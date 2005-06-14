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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<strings.h>
#include	<stdio.h>
#include	<limits.h>
#include	<dwarf.h>
#include	<dwarf_ehe_msg.h>

#define	STRBUFSIZE	128
const char *
conv_dwarf_ehe_str(uint_t flags)
{
	static char	string[STRBUFSIZE];

	(void) strncpy(string, MSG_ORIG(MSG_GBL_OSQBRKT), STRBUFSIZE);

	if (flags == DW_EH_PE_omit) {
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_OMIT), STRBUFSIZE);
		(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT), STRBUFSIZE);
		return (string);
	}
	if (flags == DW_EH_PE_absptr) {
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_ABSPTR), STRBUFSIZE);
		(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT), STRBUFSIZE);
		return (string);
	}

	switch (flags & 0x0f) {
	case DW_EH_PE_absptr:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_ABSPTR), STRBUFSIZE);
		break;
	case DW_EH_PE_uleb128:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_ULEB128), STRBUFSIZE);
		break;
	case DW_EH_PE_udata2:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_UDATA2), STRBUFSIZE);
		break;
	case DW_EH_PE_udata4:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_UDATA4), STRBUFSIZE);
		break;
	case DW_EH_PE_udata8:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_UDATA8), STRBUFSIZE);
		break;
	case DW_EH_PE_sleb128:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_SLEB128), STRBUFSIZE);
		break;
	case DW_EH_PE_sdata2:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_SDATA2), STRBUFSIZE);
		break;
	case DW_EH_PE_sdata4:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_SDATA4), STRBUFSIZE);
		break;
	case DW_EH_PE_sdata8:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_SDATA8), STRBUFSIZE);
		break;
	}

	switch (flags & 0xf0) {
	case DW_EH_PE_pcrel:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_PCREL), STRBUFSIZE);
		break;
	case DW_EH_PE_textrel:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_TEXTREL), STRBUFSIZE);
		break;
	case DW_EH_PE_datarel:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_DATAREL), STRBUFSIZE);
		break;
	case DW_EH_PE_funcrel:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_FUNCREL), STRBUFSIZE);
		break;
	case DW_EH_PE_aligned:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_ALIGNED), STRBUFSIZE);
		break;
	case DW_EH_PE_indirect:
		(void) strlcat(string, MSG_ORIG(MSG_DWEHE_INDIRECT),
			STRBUFSIZE);
		break;
	}

	(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT), STRBUFSIZE);
	return (string);
}
