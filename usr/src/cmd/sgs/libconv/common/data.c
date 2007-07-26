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

/*
 * String conversion routine for Elf data buffer types.
 */
#include	"_conv.h"
#include	"data_msg.h"

const char *
conv_elfdata_type(Elf_Type type, Conv_inv_buf_t *inv_buf)
{
	static const Msg	types[] = {
		MSG_DATA_BYTE,		MSG_DATA_ADDR,
		MSG_DATA_DYN,		MSG_DATA_EHDR,
		MSG_DATA_HALF,		MSG_DATA_OFF,
		MSG_DATA_PHDR,		MSG_DATA_RELA,
		MSG_DATA_REL,		MSG_DATA_SHDR,
		MSG_DATA_SWORD,		MSG_DATA_SYM,
		MSG_DATA_WORD,		MSG_DATA_VDEF,
		MSG_DATA_VNEED,		MSG_DATA_SXWORD,
		MSG_DATA_XWORD,		MSG_DATA_SYMINFO,
		MSG_DATA_NOTE,		MSG_DATA_MOVE,
		MSG_DATA_MOVEP,		MSG_DATA_CAP
	};

	if (type >= ELF_T_NUM)
		return (conv_invalid_val(inv_buf, type, 0));
	else
		return (MSG_ORIG(types[type]));
}
