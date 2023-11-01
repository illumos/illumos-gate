/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <procfs.h>
#include <sys/auxv.h>
#include <libelf.h>
#include <sys/param.h>
#include <stdarg.h>

#include "rdb.h"
#include "disasm.h"

/*
 * I don't like this global but it's a work-around for the
 * poor disassemble interface for now.
 */
static struct ps_prochandle	*cur_ph;

/*
 * This routine converts 'address' into it's closest symbol
 * representation.
 *
 * The following flags are used to effect the output:
 *
 *	FLG_PAP_SONAME
 *		embed the SONAME in the symbol name
 *	FLG_PAP_NOHEXNAME
 *		if no symbol found return a null string
 *		If this flag is not set return a string displaying
 *		the 'hex' value of address.
 *	FLG_PAP_PLTDECOM
 *		decompose the PLT symbol if possible
 */
char *
print_address_ps(struct ps_prochandle *ph, ulong_t address, unsigned flags)
{
	static char	buf[256];
	GElf_Sym	sym;
	char		*str;
	ulong_t		val;
	size_t		len;

	if (addr_to_sym(ph, address, &sym, &str) == RET_OK) {
		map_info_t	*mip;
		ulong_t		pltbase;

		if (flags & FLG_PAP_SONAME) {
			/*
			 * Embed SOName in symbol name
			 */
			if ((mip = addr_to_map(ph, address)) != 0) {
				(void) strcpy(buf, mip->mi_name);
				(void) strcat(buf, ":");
			} else
				(void) sprintf(buf, "0x%08lx:", address);
		} else
			buf[0] = '\0';

		if ((flags & FLG_PAP_PLTDECOM) &&
		    (pltbase = is_plt(ph, address)) != 0) {
			rd_plt_info_t	rp;
			pstatus_t	pstatus;

			if (pread(ph->pp_statusfd, &pstatus,
			    sizeof (pstatus), 0) == -1)
				perr("pap: reading pstatus");

			if (rd_plt_resolution(ph->pp_rap, address,
			    pstatus.pr_lwp.pr_lwpid, pltbase,
			    &rp) == RD_OK) {
				if (rp.pi_flags & RD_FLG_PI_PLTBOUND) {
					GElf_Sym	_sym;
					char		*_str;

					if (addr_to_sym(ph, rp.pi_baddr,
					    &_sym, &_str) == RET_OK) {
						len = strlen(buf);
						(void) snprintf(buf + len,
						    256 - len,
						    "0x%lx:plt(%s)",
						    address, _str);
						return (buf);
					}
				}
			}
			val = sym.st_value;
			len = strlen(buf);
			(void) snprintf(buf + len, 256 - len,
			    "0x%lx:plt(unbound)+0x%lx",
			    address, address - val);
			return (buf);
		} else {

			val = sym.st_value;

			len = strlen(buf);
			if (val < address) {
				(void) snprintf(buf + len, 256 - len,
				    "%s+0x%lx", str, address - val);
			} else {
				(void) strlcat(buf, str, 256);
			}
			return (buf);
		}
	} else {
		if (flags & FLG_PAP_NOHEXNAME)
			buf[0] = '\0';
		else
			(void) sprintf(buf, "0x%lx", address);
		return (buf);
	}
}

char *
print_address(unsigned long address)
{
	return (print_address_ps(cur_ph, address,
	    FLG_PAP_SONAME| FLG_PAP_PLTDECOM));
}

retc_t
disasm_addr(struct ps_prochandle *ph, ulong_t addr, int num_inst)
{
	ulong_t		offset, end;
	int		vers = V8_MODE;

	if (ph->pp_dmodel == PR_MODEL_LP64)
		vers = V9_MODE | V9_SGI_MODE;

	for (offset = addr, end = addr + num_inst * 4; offset < end;
	    offset += 4) {
		char		*instr_str;
		unsigned int	instr;

		if (ps_pread(ph, offset, (char *)&instr,
		    sizeof (unsigned)) != PS_OK)
			perror("da: ps_pread");

		cur_ph = ph;
		instr_str = disassemble(instr, offset, print_address, 0, 0,
		    vers);

		(void) printf("%-30s: %s\n", print_address(offset), instr_str);
	}
	return (RET_OK);
}

void
disasm(struct ps_prochandle *ph, int num_inst)
{
	pstatus_t	pstat;

	if (pread(ph->pp_statusfd, &pstat, sizeof (pstat), 0) == -1)
		perr("disasm: PIOCSTATUS");

	(void) disasm_addr(ph, (ulong_t)pstat.pr_lwp.pr_reg[R_PC], num_inst);
}
