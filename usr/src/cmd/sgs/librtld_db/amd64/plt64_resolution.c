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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<libelf.h>
#include	<sys/reg.h>
#include	<rtld_db.h>
#include	"_rtld_db.h"
#include	"msg.h"


/*
 * On amd64, basically, a PLT entry looks like this:
 *
 *	0x00  ff 25 00 00 00 00  jmpq   *func@got(%rip)  ; jmp GOT[N]
 *	0x06  68 01 00 00 00     pushq  $0x1	       ; push index
 *	0x0b  e9 00 00 00 00     jmpq   .plt0	       ; jmp plt[0]
 *	0x10  ...
 *
 *  The first time around GOT[N] contains address of pushq; this forces
 *	first time resolution to go thru PLT's first entry (which is a call)
 *  The nth time around, the GOT[N] actually contains the resolved
 *	address of the symbol(name), so the jmp is direct
 */
/* ARGSUSED 3 */
rd_err_e
plt64_resolution(rd_agent_t *rap, psaddr_t pc, lwpid_t lwpid,
	psaddr_t pltbase, rd_plt_info_t *rpi)
{
	uint32_t	pcrel;
	psaddr_t	destaddr;
	psaddr_t	pltoff, pltaddr;


	if (rtld_db_version >= RD_VERSION3) {
		rpi->pi_flags = 0;
		rpi->pi_baddr = 0;
	}

	pltoff = pc - pltbase;
	pltaddr = pltbase +
		((pltoff / M_PLT_ENTSIZE) * M_PLT_ENTSIZE);
	/*
	 * This is the target of the jmp instruction
	 */
	if (ps_pread(rap->rd_psp, pltaddr + 2, (char *)&pcrel,
	    sizeof (pcrel)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(pltaddr + 2)));
		return (RD_ERR);
	}

	/*
	 * the offset to the GOT table entry is
	 * PC-relative.
	 */
	destaddr = pcrel + pltaddr + 6;

	/*
	 * Find out what's pointed to by @OFFSET_INTO_GOT
	 */
	if (ps_pread(rap->rd_psp, destaddr, (char *)&destaddr,
	    sizeof (destaddr)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(destaddr)));
		return (RD_ERR);
	}
	if (destaddr == (pltaddr + 6)) {
		rd_err_e	rerr;
		/*
		 * If GOT[ind] points to PLT+6 then this is the first
		 * time through this PLT.
		 */
		if ((rerr = rd_binder_exit_addr(rap, MSG_ORIG(MSG_SYM_RTBIND),
		    &(rpi->pi_target))) != RD_OK) {
			return (rerr);
		}
		rpi->pi_skip_method = RD_RESOLVE_TARGET_STEP;
		rpi->pi_nstep = 1;
	} else {
		/*
		 * This is the n'th time through and GOT[ind] points
		 * to the final destination.
		 */
		rpi->pi_skip_method = RD_RESOLVE_STEP;
		rpi->pi_nstep = 1;
		rpi->pi_target = 0;
		if (rtld_db_version >= RD_VERSION3) {
			rpi->pi_flags |= RD_FLG_PI_PLTBOUND;
			rpi->pi_baddr = destaddr;
		}
	}

	return (RD_OK);
}
