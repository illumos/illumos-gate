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
 *	Copyright (c) 2000 by Sun Microsystems, Inc.
 *	All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"


#if !(defined(_ELF64) && defined(lint))


/*
 * Print out a single `section header' entry.
 */
void
Elf_shdr_entry(Half mach, Elf32_Shdr * shdr)
{
	dbg_print(MSG_ORIG(MSG_SHD_ADDR), EC_ADDR(shdr->sh_addr),
	    conv_secflg_str(mach, shdr->sh_flags));
	dbg_print(MSG_ORIG(MSG_SHD_SIZE), EC_XWORD(shdr->sh_size),
	    conv_sectyp_str(mach, shdr->sh_type));
	dbg_print(MSG_ORIG(MSG_SHD_OFFSET), EC_OFF(shdr->sh_offset),
	    EC_XWORD(shdr->sh_entsize));
	dbg_print(MSG_ORIG(MSG_SHD_LINK), EC_WORD(shdr->sh_link),
	    conv_secinfo_str(shdr->sh_info, shdr->sh_flags));
	dbg_print(MSG_ORIG(MSG_SHD_ALIGN), EC_XWORD(shdr->sh_addralign));
}

void
Gelf_shdr_entry(Half mach, GElf_Shdr * shdr)
{
	dbg_print(MSG_ORIG(MSG_SHD_ADDR), EC_ADDR(shdr->sh_addr),
	    conv_secflg_str(mach, (Word)shdr->sh_flags));
	dbg_print(MSG_ORIG(MSG_SHD_SIZE), EC_XWORD(shdr->sh_size),
	    conv_sectyp_str(mach, shdr->sh_type));
	dbg_print(MSG_ORIG(MSG_SHD_OFFSET), EC_OFF(shdr->sh_offset),
	    EC_XWORD(shdr->sh_entsize));
	dbg_print(MSG_ORIG(MSG_SHD_LINK), EC_WORD(shdr->sh_link),
	    conv_secinfo_str(shdr->sh_info, (Word)shdr->sh_flags));
	dbg_print(MSG_ORIG(MSG_SHD_ALIGN), EC_XWORD(shdr->sh_addralign));
}

#endif /* !(defined(_ELF64) && defined(lint)) */
