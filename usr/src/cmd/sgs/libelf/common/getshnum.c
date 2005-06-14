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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <gelf.h>
#include <decl.h>
#include <msg.h>


int
elf_getshnum(Elf *elf, size_t *shnum)
{
	GElf_Ehdr	ehdr;
	Elf_Scn		*scn;
	GElf_Shdr	shdr0;

	if (gelf_getehdr(elf, &ehdr) == 0)
		return (0);
	if (ehdr.e_shnum > 0) {
		*shnum = ehdr.e_shnum;
		return (1);
	}
	if ((ehdr.e_shnum == 0) && (ehdr.e_shoff == 0)) {
		*shnum = 0;
		return (1);
	}
	if ((scn = elf_getscn(elf, 0)) == 0)
		return (0);
	if (gelf_getshdr(scn, &shdr0) == 0)
		return (0);
	*shnum = shdr0.sh_size;
	return (1);
}
