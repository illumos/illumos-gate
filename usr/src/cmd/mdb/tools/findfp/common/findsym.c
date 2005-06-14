/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>

#include <findfp.h>
#include <util.h>

int
findelfsym(Elf *elf, uintptr_t addr, char **symnamep, offset_t *offp)
{
	Elf_Data *symtab;
	GElf_Shdr shdr;
	Elf_Scn *scn;
	int symtabidx, nent, i;

	if ((symtabidx = findelfsecidx(elf, ".symtab")) < 0)
		elfdie("failed to find .symtab\n");

	if ((scn = elf_getscn(elf, symtabidx)) == NULL ||
	    gelf_getshdr(scn, &shdr) == NULL ||
	    (symtab = elf_getdata(scn, NULL)) == NULL)
		elfdie("failed to read .symtab");

	nent = shdr.sh_size / shdr.sh_entsize;

	for (i = 0; i < nent; i++) {
		GElf_Sym sym;

		if (gelf_getsym(symtab, i, &sym) == NULL)
			elfdie("failed to get symbol at idx %d", i);

		if ((GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
		    GELF_ST_TYPE(sym.st_info) != STT_OBJECT) ||
		    sym.st_shndx == SHN_UNDEF)
			continue;

		if (addr - sym.st_value < sym.st_size) {
			/* matched */
			if ((*symnamep = elf_strptr(elf, shdr.sh_link,
			    sym.st_name)) == NULL)
				elfdie("failed to get name for sym %d", i);
			*offp = addr - sym.st_value;
			return (1);
		}
	}

	return (0);
}
