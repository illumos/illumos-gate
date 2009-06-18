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
 * Return number of entries in the section header array, taking
 * extended headers into account.
 *
 * elf_getshnum() and elf_getshstrndx() were defined during the 2002 gABI
 * meetings. They were supposed to return -1 for failure, and 0 for success.
 * Our manpage documented them as such, but we then implemented them to
 * return 0 for failure and 1 for success. This makes elf_getshnum() and
 * elf_getshstrnum() non-portable to systems that implement the 2002 gABI
 * definition.
 *
 * In 2005, the manpage was modified to match the code.
 * In 2009, the discrepency was identified. elf_getshdrnum() and
 * elf_getshdrstrndx() were created to provide a portable implementation.
 * The older two functions are considered to be obsolete, and are retained
 * for backward compatability.
 */

int
elf_getshdrnum(Elf *elf, size_t *shnum)
{
	GElf_Ehdr	ehdr;
	Elf_Scn		*scn;
	GElf_Shdr	shdr0;

	if (gelf_getehdr(elf, &ehdr) == 0)
		return (-1);
	if (ehdr.e_shnum > 0) {
		*shnum = ehdr.e_shnum;
		return (0);
	}
	if ((ehdr.e_shnum == 0) && (ehdr.e_shoff == 0)) {
		*shnum = 0;
		return (0);
	}
	if ((scn = elf_getscn(elf, 0)) == 0)
		return (-1);
	if (gelf_getshdr(scn, &shdr0) == 0)
		return (-1);
	*shnum = shdr0.sh_size;
	return (0);
}

int
elf_getshnum(Elf *elf, size_t *shnum)
{
	return (elf_getshdrnum(elf, shnum) == 0);
}
