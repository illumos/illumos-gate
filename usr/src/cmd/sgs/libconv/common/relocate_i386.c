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

/*
 * String conversion routine for relocation types.
 */
#include	<stdio.h>
#include	<sys/elf_386.h>
#include	"_conv.h"
#include	"relocate_i386_msg.h"

/*
 * 386 specific relocations.
 */
static const Msg rels[R_386_NUM] = {
	[R_386_NONE]		= MSG_R_386_NONE,
	[R_386_32]		= MSG_R_386_32,
	[R_386_PC32]		= MSG_R_386_PC32,
	[R_386_GOT32]		= MSG_R_386_GOT32,
	[R_386_PLT32]		= MSG_R_386_PLT32,
	[R_386_COPY]		= MSG_R_386_COPY,
	[R_386_GLOB_DAT]	= MSG_R_386_GLOB_DAT,
	[R_386_JMP_SLOT]	= MSG_R_386_JMP_SLOT,
	[R_386_RELATIVE]	= MSG_R_386_RELATIVE,
	[R_386_GOTOFF]		= MSG_R_386_GOTOFF,
	[R_386_GOTPC]		= MSG_R_386_GOTPC,
	[R_386_32PLT]		= MSG_R_386_32PLT,
	[R_386_TLS_GD_PLT]	= MSG_R_386_TLS_GD_PLT,
	[R_386_TLS_LDM_PLT]	= MSG_R_386_TLS_LDM_PLT,
	[R_386_TLS_TPOFF]	= MSG_R_386_TLS_TPOFF,
	[R_386_TLS_IE]		= MSG_R_386_TLS_IE,
	[R_386_TLS_GOTIE]	= MSG_R_386_TLS_GOTIE,
	[R_386_TLS_LE]		= MSG_R_386_TLS_LE,
	[R_386_TLS_GD]		= MSG_R_386_TLS_GD,
	[R_386_TLS_LDM]		= MSG_R_386_TLS_LDM,
	[R_386_16]		= MSG_R_386_16,
	[R_386_PC16]		= MSG_R_386_PC16,
	[R_386_8]		= MSG_R_386_8,
	[R_386_PC8]		= MSG_R_386_PC8,
	[R_386_TLS_GD_32]	= MSG_R_386_TLS_GD_32,
	[R_386_TLS_GD_PUSH]	= MSG_R_386_TLS_GD_PUSH,
	[R_386_TLS_GD_CALL]	= MSG_R_386_TLS_GD_CALL,
	[R_386_TLS_GD_POP]	= MSG_R_386_TLS_GD_POP,
	[R_386_TLS_LDM_32]	= MSG_R_386_TLS_LDM_32,
	[R_386_TLS_LDM_PUSH]	= MSG_R_386_TLS_LDM_PUSH,
	[R_386_TLS_LDM_CALL]	= MSG_R_386_TLS_LDM_CALL,
	[R_386_TLS_LDM_POP]	= MSG_R_386_TLS_LDM_POP,
	[R_386_TLS_LDO_32]	= MSG_R_386_TLS_LDO_32,
	[R_386_TLS_IE_32]	= MSG_R_386_TLS_IE_32,
	[R_386_TLS_LE_32]	= MSG_R_386_TLS_LE_32,
	[R_386_TLS_DTPMOD32]	= MSG_R_386_TLS_DTPMOD32,
	[R_386_TLS_DTPOFF32]	= MSG_R_386_TLS_DTPOFF32,
	[R_386_TLS_TPOFF32]	= MSG_R_386_TLS_TPOFF32,
	[R_386_SIZE32]		= MSG_R_386_SIZE32,
	[R_386_TLS_GOTDESC]	= MSG_R_386_TLS_GOTDESC,
	[R_386_TLS_DESC_CALL]	= MSG_R_386_TLS_DESC_CALL,
	[R_386_TLS_DESC]	= MSG_R_386_TLS_DESC,
	[R_386_IRELATIVE]	= MSG_R_386_RELATIVE,
	[R_386_GOT32X]		= MSG_R_386_GOT32X
};

#if	(R_386_NUM != (R_386_GOT32X + 1))
#error	"R_386_NUM has grown"
#endif

const char *
conv_reloc_386_type(Word type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	if (type >= R_386_NUM)
		return (conv_invalid_val(inv_buf, type, fmt_flags));
	return (MSG_ORIG(rels[type]));
}
