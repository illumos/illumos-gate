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
 *	Copyright (c) 1998 by Sun Microsystems, Inc.
 *	All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"


#if !(defined(_ELF64) && defined(lint))


/*
 * Print out a single `program header' entry.
 */
void
Elf_phdr_entry(Half mach, Elf32_Phdr * phdr)
{
	dbg_print(MSG_ORIG(MSG_PHD_VADDR), EC_ADDR(phdr->p_vaddr),
	    conv_phdrflg_str(phdr->p_flags));
	dbg_print(MSG_ORIG(MSG_PHD_PADDR), EC_ADDR(phdr->p_paddr),
	    conv_phdrtyp_str(mach, phdr->p_type));
	dbg_print(MSG_ORIG(MSG_PHD_FILESZ), EC_XWORD(phdr->p_filesz),
	    EC_XWORD(phdr->p_memsz));
	dbg_print(MSG_ORIG(MSG_PHD_OFFSET), EC_OFF(phdr->p_offset),
	    EC_XWORD(phdr->p_align));
}

void
Gelf_phdr_entry(Half mach, GElf_Phdr * phdr)
{
	dbg_print(MSG_ORIG(MSG_PHD_VADDR), EC_ADDR(phdr->p_vaddr),
	    conv_phdrflg_str(phdr->p_flags));
	dbg_print(MSG_ORIG(MSG_PHD_PADDR), EC_ADDR(phdr->p_paddr),
	    conv_phdrtyp_str(mach, phdr->p_type));
	dbg_print(MSG_ORIG(MSG_PHD_FILESZ), EC_XWORD(phdr->p_filesz),
	    EC_XWORD(phdr->p_memsz));
	dbg_print(MSG_ORIG(MSG_PHD_OFFSET), EC_OFF(phdr->p_offset),
	    EC_XWORD(phdr->p_align));
}

#endif /* !(defined(_ELF64) && defined(lint)) */
