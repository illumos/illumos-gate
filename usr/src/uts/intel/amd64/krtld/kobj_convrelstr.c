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

#include	<sys/types.h>
#include	"reloc.h"


#ifdef	KOBJ_DEBUG
static const char	*rels[] = {
	"R_AMD64_NONE",
	"R_AMD64_64",
	"R_AMD64_PC32",
	"R_AMD64_GOT32",
	"R_AMD64_PLT32",
	"R_AMD64_COPY",
	"R_AMD64_GLOB_DATA",
	"R_AMD64_JUMP_SLOT",
	"R_AMD64_RELATIVE",
	"R_AMD64_GOTPCREL",
	"R_AMD64_32",
	"R_AMD64_32S",
	"R_AMD64_16",
	"R_AMD64_PC16",
	"R_AMD64_8",
	"R_AMD64_PC8",
	"R_AMD64_DPTMOD64",
	"R_AMD64_DTPOFF64",
	"R_AMD64_TPOFF64",
	"R_AMD64_TLSGD",
	"R_AMD64_TLSLD",
	"R_AMD64_DTPOFF32",
	"R_AMD64_GOTTPOFF",
	"R_AMD64_TPOFF32",
	"R_AMD64_PC64",
	"R_AMD64_GOTOFF64",
	"R_AMD64_GOTPC32"
};
#endif


/*
 * This is a 'stub' of the orignal version defined in liblddbg.so
 * This stub just returns the 'int string' of the relocation in question
 * instead of converting it to it's full syntax.
 */
const char *
conv_reloc_amd64_type_str(Word rtype)
{
#ifdef	KOBJ_DEBUG
#if	(R_AMD64_NUM != (R_AMD64_GOTPC32 + 1))
#error	"R_AMD64_NUM has grown"
#endif
	if (rtype < R_AMD64_NUM)
		return (rels[rtype]);
	else {
#endif
		static char 	strbuf[32];
		int		ndx = 31;
		strbuf[ndx--] = '\0';
		do {
			strbuf[ndx--] = '0' + (rtype % 10);
			rtype = rtype / 10;
		} while ((ndx >= (int)0) && (rtype > (Word)0));
		return (&strbuf[ndx + 1]);
#ifdef	KOBJ_DEBUG
	}
#endif
}
