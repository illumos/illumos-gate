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
 * Copyright (c) 1996-1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include	"reloc.h"


#ifdef	KOBJ_DEBUG
static const char	*rels[] = {
	"R_SPARC_NONE    ",
	"R_SPARC_8       ",
	"R_SPARC_16      ",
	"R_SPARC_32      ",
	"R_SPARC_DISP8   ",
	"R_SPARC_DISP16  ",
	"R_SPARC_DISP32  ",
	"R_SPARC_WDISP30 ",
	"R_SPARC_WDISP22 ",
	"R_SPARC_HI22    ",
	"R_SPARC_22      ",
	"R_SPARC_13      ",
	"R_SPARC_LO10    ",
	"R_SPARC_GOT10   ",
	"R_SPARC_GOT13   ",
	"R_SPARC_GOT22   ",
	"R_SPARC_PC10    ",
	"R_SPARC_PC22    ",
	"R_SPARC_WPLT30  ",
	"R_SPARC_COPY    ",
	"R_SPARC_GLOB_DAT",
	"R_SPARC_JMP_SLOT",
	"R_SPARC_RELATIVE",
	"R_SPARC_UA32    ",
	"R_SPARC_PLT32   ",
	"R_SPARC_HIPLT22 ",
	"R_SPARC_LOPLT10 ",
	"R_SPARC_PCPLT32 ",
	"R_SPARC_PCPLT22 ",
	"R_SPARC_PCPLT10 ",
	"R_SPARC_10      ",
	"R_SPARC_11      ",
	"R_SPARC_64      ",
	"R_SPARC_OLO10   ",
	"R_SPARC_HH22    ",
	"R_SPARC_HM10    ",
	"R_SPARC_LM22    ",
	"R_SPARC_PC_HH22 ",
	"R_SPARC_PC_HM10 ",
	"R_SPARC_PC_LM22 ",
	"R_SPARC_WDISP16 ",
	"R_SPARC_WDISP19 ",
	"R_SPARC_GLOB_JMP",
	"R_SPARC_7       ",
	"R_SPARC_5       ",
	"R_SPARC_6       "
};
#endif

/*
 * This is a 'stub' of the orignal version defined in liblddbg.so
 * This stub just returns the 'int string' of the relocation in question
 * instead of converting it to it's full syntax.
 */
const char *
conv_reloc_SPARC_type_str(Word rtype)
{
#ifdef	KOBJ_DEBUG
	if (rtype < R_SPARC_NUM)
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
