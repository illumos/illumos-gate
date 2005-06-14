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
 * Copyright (c) 1996-1997,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include	"reloc.h"


#ifdef	KOBJ_DEBUG
static const char	*rels[] = {
	"R_386_NONE",
	"R_386_32",
	"R_386_PC32",
	"R_386_GOT32",
	"R_386_PLT32",
	"R_386_COPY",
	"R_386_GLOB_DAT",
	"R_386_JMP_SLOT",
	"R_386_RELATIVE",
	"R_386_GOTOFF",
	"R_386_GOTPC",
	"R_386_32PLT",
};
#endif


/*
 * This is a 'stub' of the orignal version defined in liblddbg.so
 * This stub just returns the 'int string' of the relocation in question
 * instead of converting it to it's full syntax.
 */
const char *
conv_reloc_386_type_str(Word rtype)
{
#ifdef	KOBJ_DEBUG
	if (rtype < R_386_NUM)
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
