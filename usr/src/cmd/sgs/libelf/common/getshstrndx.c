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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include <gelf.h>
#include <decl.h>
#include <msg.h>

/*
 * Return section header array string table index, taking
 * extended headers into account.
 *
 * elf_getshstrndx() returns 0 for failure, and 1 for success.
 *
 * elf_getshdrstrndx() supercedes elf_getshstrndx(), which is now considered
 * obsolete. It returns -1 for failure and 0 for success, bringing us into
 * alignment with the interface agreed to in the 2002 gABI meeting.
 *
 * See the comment in getshnum.c for additional information.
 */

int
elf_getshdrstrndx(Elf *elf, size_t *shstrndx)
{
	GElf_Ehdr	ehdr;
	Elf_Scn		*scn;
	GElf_Shdr	shdr0;

	if (gelf_getehdr(elf, &ehdr) == 0)
		return (-1);
	if (ehdr.e_shstrndx != SHN_XINDEX) {
		*shstrndx = ehdr.e_shstrndx;
		return (0);
	}
	if ((scn = elf_getscn(elf, 0)) == 0)
		return (-1);
	if (gelf_getshdr(scn, &shdr0) == 0)
		return (-1);
	*shstrndx = shdr0.sh_link;
	return (0);
}

int
elf_getshstrndx(Elf *elf, size_t *shstrndx)
{
	return (elf_getshdrstrndx(elf, shstrndx) == 0);
}
