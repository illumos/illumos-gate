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

#include	<sys/types.h>
#include	"krtld/reloc.h"

static const char	*rels[R_SPARC_NUM] = {
	"R_SPARC_NONE",			"R_SPARC_8",
	"R_SPARC_16",			"R_SPARC_32",
	"R_SPARC_DISP8",		"R_SPARC_DISP16",
	"R_SPARC_DISP32",		"R_SPARC_WDISP30",
	"R_SPARC_WDISP22",		"R_SPARC_HI22",
	"R_SPARC_22",			"R_SPARC_13",
	"R_SPARC_LO10",			"R_SPARC_GOT10",
	"R_SPARC_GOT13",		"R_SPARC_GOT22",
	"R_SPARC_PC10",			"R_SPARC_PC22",
	"R_SPARC_WPLT30",		"R_SPARC_COPY",
	"R_SPARC_GLOB_DAT",		"R_SPARC_JMP_SLOT",
	"R_SPARC_RELATIVE",		"R_SPARC_UA32",
	"R_SPARC_PLT32",		"R_SPARC_HIPLT22",
	"R_SPARC_LOPLT10",		"R_SPARC_PCPLT32",
	"R_SPARC_PCPLT22",		"R_SPARC_PCPLT10",
	"R_SPARC_10",			"R_SPARC_11",
	"R_SPARC_64",			"R_SPARC_OLO10",
	"R_SPARC_HH22",			"R_SPARC_HM10",
	"R_SPARC_LM22",			"R_SPARC_PC_HH22",
	"R_SPARC_PC_HM10",		"R_SPARC_PC_LM22",
	"R_SPARC_WDISP16",		"R_SPARC_WDISP19",
	"R_SPARC_GLOB_JMP",		"R_SPARC_7",
	"R_SPARC_5",			"R_SPARC_6",
	"R_SPARC_DISP64",		"R_SPARC_PLT64",
	"R_SPARC_HIX22",		"R_SPARC_LOX10",
	"R_SPARC_H44",			"R_SPARC_M44",
	"R_SPARC_L44",			"R_SPARC_REGISTER",
	"R_SPARC_UA64",			"R_SPARC_UA16",
	"R_SPARC_TLS_GD_HI22",		"R_SPARC_TLS_GD_LO10",
	"R_SPARC_TLS_GD_ADD",		"R_SPARC_TLS_GD_CALL",
	"R_SPARC_TLS_LDM_HI22",		"R_SPARC_TLS_LDM_LO10",
	"R_SPARC_TLS_LDM_ADD",		"R_SPARC_TLS_LDM_CALL",
	"R_SPARC_TLS_LDO_HIX22",	"R_SPARC_TLS_LDO_LOX10",
	"R_SPARC_TLS_LDO_ADD",		"R_SPARC_TLS_IE_HI22",
	"R_SPARC_TLS_IE_LO10",		"R_SPARC_TLS_IE_LD",
	"R_SPARC_TLS_IE_LDX",		"R_SPARC_TLS_IE_ADD",
	"R_SPARC_TLS_LE_HIX22",		"R_SPARC_TLS_LE_LOX10",
	"R_SPARC_TLS_DTPMOD32",		"R_SPARC_TLS_DTPMOD64",
	"R_SPARC_TLS_DTPOFF32",		"R_SPARC_TLS_DTPOFF64",
	"R_SPARC_TLS_TPOFF32",		"R_SPARC_TLS_TPOFF64",
	"R_SPARC_GOTDATA_HIX22",	"R_SPARC_GOTDATA_LOX10",
	"R_SPARC_GOTDATA_OP_HIX22",	"R_SPARC_GOTDATA_OP_LOX10",
	"R_SPARC_GOTDATA_OP",		"R_SPARC_H34",
	"R_SPARC_SIZE32",		"R_SPARC_SIZE64"
};

#if	(R_SPARC_NUM != (R_SPARC_SIZE64 + 1))
#error	"R_SPARC_NUM has grown"
#endif

/*
 * This is a 'stub' of the orignal version defined in liblddbg.so.  This stub
 * returns the 'int string' of the relocation in question instead of converting
 * the relocation to it's full syntax.
 */
const char *
conv_reloc_SPARC_type(Word type)
{
	static char 	strbuf[32];
	int		ndx = 31;

	if (type < R_SPARC_NUM)
		return (rels[type]);

	strbuf[ndx--] = '\0';
	do {
		strbuf[ndx--] = '0' + (type % 10);
		type = type / 10;
	} while ((ndx >= (int)0) && (type > (Word)0));

	return (&strbuf[ndx + 1]);
}
