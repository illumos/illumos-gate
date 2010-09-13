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
 * String conversion routine for relocation types.
 */
#include	<stdio.h>
#include	<sys/elf_SPARC.h>
#include	"_conv.h"
#include	"relocate_sparc_msg.h"

/*
 * SPARC specific relocations.
 */
static const Msg rels[R_SPARC_NUM] = {
	MSG_R_SPARC_NONE,		MSG_R_SPARC_8,
	MSG_R_SPARC_16,			MSG_R_SPARC_32,
	MSG_R_SPARC_DISP8,		MSG_R_SPARC_DISP16,
	MSG_R_SPARC_DISP32,		MSG_R_SPARC_WDISP30,
	MSG_R_SPARC_WDISP22,		MSG_R_SPARC_HI22,
	MSG_R_SPARC_22,			MSG_R_SPARC_13,
	MSG_R_SPARC_LO10,		MSG_R_SPARC_GOT10,
	MSG_R_SPARC_GOT13,		MSG_R_SPARC_GOT22,
	MSG_R_SPARC_PC10,		MSG_R_SPARC_PC22,
	MSG_R_SPARC_WPLT30,		MSG_R_SPARC_COPY,
	MSG_R_SPARC_GLOB_DAT,		MSG_R_SPARC_JMP_SLOT,
	MSG_R_SPARC_RELATIVE,		MSG_R_SPARC_UA32,
	MSG_R_SPARC_PLT32,		MSG_R_SPARC_HIPLT22,
	MSG_R_SPARC_LOPLT10,		MSG_R_SPARC_PCPLT32,
	MSG_R_SPARC_PCPLT22,		MSG_R_SPARC_PCPLT10,
	MSG_R_SPARC_10,			MSG_R_SPARC_11,
	MSG_R_SPARC_64,			MSG_R_SPARC_OLO10,
	MSG_R_SPARC_HH22,		MSG_R_SPARC_HM10,
	MSG_R_SPARC_LM22,		MSG_R_SPARC_PC_HH22,
	MSG_R_SPARC_PC_HM10,		MSG_R_SPARC_PC_LM22,
	MSG_R_SPARC_WDISP16,		MSG_R_SPARC_WDISP19,
	MSG_R_SPARC_GLOB_JMP,		MSG_R_SPARC_7,
	MSG_R_SPARC_5,			MSG_R_SPARC_6,
	MSG_R_SPARC_DISP64,		MSG_R_SPARC_PLT64,
	MSG_R_SPARC_HIX22,		MSG_R_SPARC_LOX10,
	MSG_R_SPARC_H44,		MSG_R_SPARC_M44,
	MSG_R_SPARC_L44,		MSG_R_SPARC_REGISTER,
	MSG_R_SPARC_UA64,		MSG_R_SPARC_UA16,
	MSG_R_SPARC_TLS_GD_HI22,	MSG_R_SPARC_TLS_GD_LO10,
	MSG_R_SPARC_TLS_GD_ADD,		MSG_R_SPARC_TLS_GD_CALL,
	MSG_R_SPARC_TLS_LDM_HI22,	MSG_R_SPARC_TLS_LDM_LO10,
	MSG_R_SPARC_TLS_LDM_ADD,	MSG_R_SPARC_TLS_LDM_CALL,
	MSG_R_SPARC_TLS_LDO_HIX22,	MSG_R_SPARC_TLS_LDO_LOX10,
	MSG_R_SPARC_TLS_LDO_ADD,	MSG_R_SPARC_TLS_IE_HI22,
	MSG_R_SPARC_TLS_IE_LO10,	MSG_R_SPARC_TLS_IE_LD,
	MSG_R_SPARC_TLS_IE_LDX,		MSG_R_SPARC_TLS_IE_ADD,
	MSG_R_SPARC_TLS_LE_HIX22,	MSG_R_SPARC_TLS_LE_LOX10,
	MSG_R_SPARC_TLS_DTPMOD32,	MSG_R_SPARC_TLS_DTPMOD64,
	MSG_R_SPARC_TLS_DTPOFF32,	MSG_R_SPARC_TLS_DTPOFF64,
	MSG_R_SPARC_TLS_TPOFF32,	MSG_R_SPARC_TLS_TPOFF64,
	MSG_R_SPARC_GOTDATA_HIX22,	MSG_R_SPARC_GOTDATA_LOX10,
	MSG_R_SPARC_GOTDATA_OP_HIX22,	MSG_R_SPARC_GOTDATA_OP_LOX10,
	MSG_R_SPARC_GOTDATA_OP,		MSG_R_SPARC_H34,
	MSG_R_SPARC_SIZE32,		MSG_R_SPARC_SIZE64
};

#if	(R_SPARC_NUM != (R_SPARC_SIZE64 + 1))
#error	"R_SPARC_NUM has grown"
#endif

const char *
conv_reloc_SPARC_type(Word type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	if (type >= R_SPARC_NUM)
		return (conv_invalid_val(inv_buf, type, fmt_flags));
	return (MSG_ORIG(rels[type]));
}
