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

#include	<sgs.h>
#include	<_debug.h>
#include	<conv.h>
#include	<msg.h>

void
Elf_shdr(Lm_list *lml, Half mach, Shdr * shdr)
{
	dbg_print(lml, MSG_ORIG(MSG_SHD_ADDR), EC_ADDR(shdr->sh_addr),
	    conv_sec_flags(shdr->sh_flags));
	dbg_print(lml, MSG_ORIG(MSG_SHD_SIZE), EC_XWORD(shdr->sh_size),
	    conv_sec_type(mach, shdr->sh_type));
	dbg_print(lml, MSG_ORIG(MSG_SHD_OFFSET), EC_OFF(shdr->sh_offset),
	    EC_XWORD(shdr->sh_entsize));
	dbg_print(lml, MSG_ORIG(MSG_SHD_LINK), EC_WORD(shdr->sh_link),
	    conv_sec_info(shdr->sh_info, shdr->sh_flags));
	dbg_print(lml, MSG_ORIG(MSG_SHD_ALIGN), EC_XWORD(shdr->sh_addralign));
}
