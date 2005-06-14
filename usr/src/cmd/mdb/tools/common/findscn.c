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

#include <string.h>
#include <libelf.h>
#include <gelf.h>

#include <util.h>

int
findelfsecidx(Elf *elf, char *tofind)
{
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		elfdie("failed to get ELF header");

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		char *name;

		if (gelf_getshdr(scn, &shdr) == NULL ||
		    (name = elf_strptr(elf, ehdr.e_shstrndx,
		    (size_t)shdr.sh_name)) == NULL)
			elfdie("failed to get section header");

		if (strcmp(name, tofind) == 0)
			return (elf_ndxscn(scn));
	}

	return (-1);
}
