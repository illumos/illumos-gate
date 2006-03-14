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

#include	<strings.h>
#include	<dwarf.h>
#include	<dwarf_ehe_msg.h>
#include	"_conv.h"

#define	FLAGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_DWEHE_SLEB128_SIZE + \
		MSG_DWEHE_INDIRECT_SIZE + \
		CONV_INV_STRSIZE + MSG_GBL_CSQBRKT_SIZE

const char *
conv_dwarf_ehe(uint_t flags)
{
	static char	string[FLAGSZ];
	size_t		ret = 0;

	(void) strncpy(string, MSG_ORIG(MSG_GBL_OSQBRKT), FLAGSZ);

	if (flags == DW_EH_PE_omit)
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_OMIT), FLAGSZ);
	else if (flags == DW_EH_PE_absptr)
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_ABSPTR), FLAGSZ);

	if (ret >= FLAGSZ)
		return (conv_invalid_val(string, FLAGSZ, flags, 0));

	if ((flags == DW_EH_PE_omit) || (flags == DW_EH_PE_absptr)) {
		(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT), FLAGSZ);
		return (string);
	}

	switch (flags & 0x0f) {
	case DW_EH_PE_uleb128:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_ULEB128), FLAGSZ);
		break;
	case DW_EH_PE_udata2:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_UDATA2), FLAGSZ);
		break;
	case DW_EH_PE_udata4:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_UDATA4), FLAGSZ);
		break;
	case DW_EH_PE_udata8:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_UDATA8), FLAGSZ);
		break;
	case DW_EH_PE_sleb128:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_SLEB128), FLAGSZ);
		break;
	case DW_EH_PE_sdata2:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_SDATA2), FLAGSZ);
		break;
	case DW_EH_PE_sdata4:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_SDATA4), FLAGSZ);
		break;
	case DW_EH_PE_sdata8:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_SDATA8), FLAGSZ);
		break;
	}
	if (ret >= FLAGSZ)
		return (conv_invalid_val(string, FLAGSZ, flags, 0));

	switch (flags & 0xf0) {
	case DW_EH_PE_pcrel:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_PCREL), FLAGSZ);
		break;
	case DW_EH_PE_textrel:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_TEXTREL), FLAGSZ);
		break;
	case DW_EH_PE_datarel:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_DATAREL), FLAGSZ);
		break;
	case DW_EH_PE_funcrel:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_FUNCREL), FLAGSZ);
		break;
	case DW_EH_PE_aligned:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_ALIGNED), FLAGSZ);
		break;
	case DW_EH_PE_indirect:
		ret = strlcat(string, MSG_ORIG(MSG_DWEHE_INDIRECT), FLAGSZ);
		break;
	}
	if (ret >= FLAGSZ)
		return (conv_invalid_val(string, FLAGSZ, flags, 0));

	(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT), FLAGSZ);
	return (string);
}
