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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sgs.h>
#include	<_debug.h>
#include	<conv.h>
#include	<msg.h>

void
Elf_shdr(Lm_list *lml, Half mach, Shdr *shdr)
{
	Conv_inv_buf_t		inv_buf1, inv_buf2;
	Conv_sec_flags_buf_t	sec_flags_buf;

	dbg_print(lml, MSG_ORIG(MSG_SHD_ADDR), EC_ADDR(shdr->sh_addr),
	    conv_sec_flags(shdr->sh_flags, 0, &sec_flags_buf));
	dbg_print(lml, MSG_ORIG(MSG_SHD_SIZE), EC_XWORD(shdr->sh_size),
	    conv_sec_type(mach, shdr->sh_type, 0, &inv_buf1));
	if (shdr->sh_entsize == 0) {
		dbg_print(lml, MSG_ORIG(MSG_SHD_OFFSET),
		    EC_OFF(shdr->sh_offset), EC_XWORD(shdr->sh_entsize));
	} else {		/* Provide an entry count */
		Xword nelts = shdr->sh_size / shdr->sh_entsize;
		const char *entstr = (nelts == 1) ? MSG_INTL(MSG_SHD_ENTRY_1) :
		    MSG_INTL(MSG_SHD_ENTRY_N);

		dbg_print(lml, MSG_ORIG(MSG_SHD_OFFSET_ENT),
		    EC_OFF(shdr->sh_offset), EC_XWORD(shdr->sh_entsize),
		    EC_XWORD(nelts), entstr);
	}
	dbg_print(lml, MSG_ORIG(MSG_SHD_LINK),
	    conv_sec_linkinfo(shdr->sh_link, shdr->sh_flags, &inv_buf1),
	    conv_sec_linkinfo(shdr->sh_info, shdr->sh_flags, &inv_buf2));
	dbg_print(lml, MSG_ORIG(MSG_SHD_ALIGN), EC_XWORD(shdr->sh_addralign));
}

void
Dbg_shdr_modified(Lm_list *lml, const char *obj, Half mach, Shdr *oshdr,
    Shdr *nshdr, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SECTIONS | DBG_C_SUPPORT))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SHD_MODIFIED), name, obj);

	dbg_print(lml, MSG_INTL(MSG_SHD_ORIG));
	Elf_shdr(lml, mach, oshdr);

	dbg_print(lml, MSG_INTL(MSG_SHD_NEW));
	Elf_shdr(lml, mach, nshdr);

	Dbg_util_nl(lml, DBG_NL_STD);
}
