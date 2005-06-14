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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if	defined(_KERNEL)
#include	<sys/types.h>
#include	"reloc.h"
#else
#include	<stdio.h>
#include	"sgs.h"
#include	"machdep.h"
#include	"libld.h"
#include	"reloc.h"
#include	"conv.h"
#include	"msg.h"
#endif

/*
 * This table represents the current relocations that do_reloc()
 * is able to process.  The relocations below that are marked
 * 'SPECIAL' in the comments are relocations that take special
 * processing and shouldn't actually ever be passed to do_reloc().
 */
const Rel_entry	reloc_table[R_AMD64_NUM] = {
/* R_AMD64_NONE */	{0, 0},
/* R_AMD64_64 */	{FLG_RE_NOTREL, 8},
/* R_AMD64_PC32 */	{FLG_RE_PCREL, 4},
/* R_AMD64_GOT32 */	{FLG_RE_NOTSUP, 0},
/* R_AMD64_PLT32 */	{FLG_RE_PCREL | FLG_RE_PLTREL |
				FLG_RE_VERIFY | FLG_RE_SIGN, 4},
/* R_AMD64_COPY */	{FLG_RE_NOTSUP, 0},
/* R_AMD64_GLOB_DAT */	{FLG_RE_NOTREL, 8},
/* R_AMD64_JUMP_SLOT */	{FLG_RE_NOTSUP, 0},
/* R_AMD64_RELATIVE */	{FLG_RE_NOTREL, 8},
/* R_AMD64_GOTPCREL */	{FLG_RE_GOTPC | FLG_RE_GOTADD, 4},
/* R_AMD64_32 */	{FLG_RE_NOTREL, 4},
/* R_AMD64_32S */	{FLG_RE_NOTREL, 4},
/* R_AMD64_16 */	{FLG_RE_NOTSUP, 0},
/* R_AMD64_PC16 */	{FLG_RE_NOTSUP, 0},
/* R_AMD64_8 */		{FLG_RE_NOTSUP, 0},
/* R_AMD64_PC8 */	{FLG_RE_NOTSUP, 0},
/* R_AMD64_DTPMOD64 */	{FLG_RE_NOTREL, 8},
/* R_AMD64_DTPOFF64 */	{FLG_RE_NOTREL, 8},
/* R_AMD64_TPOFF64 */	{FLG_RE_NOTREL, 8},
/* R_AMD64_TLSGD */	{FLG_RE_GOTPC | FLG_RE_GOTADD |
			    FLG_RE_TLSINS | FLG_RE_TLSGD, 4},
/* R_AMD64_TLSLD */	{FLG_RE_GOTPC | FLG_RE_GOTADD |
			    FLG_RE_TLSINS | FLG_RE_TLSLD, 4},
/* R_AMD64_DTPOFF32 */	{FLG_RE_TLSINS | FLG_RE_NOTREL | FLG_RE_TLSLD, 4},
/* R_AMD64_GOTTPOFF */	{FLG_RE_GOTPC | FLG_RE_GOTADD |
			    FLG_RE_TLSINS | FLG_RE_TLSIE, 4},
/* R_AMD64_TPOFF32 */	{FLG_RE_TLSINS | FLG_RE_NOTREL | FLG_RE_TLSLE, 4},
/* R_AMD64_PC64 */	{FLG_RE_PCREL, 8},
/* R_AMD64_GOTOFF64 */	{FLG_RE_GOTREL, 8},
/* R_AMD64_GOTPC32 */	{FLG_RE_PCREL | FLG_RE_GOTPC | FLG_RE_LOCLBND, 4}
};
#if	(R_AMD64_NUM != (R_AMD64_GOTPC32 + 1))
#error	"R_AMD64_NUM has grown"
#endif

/*
 * Write a single relocated value to its reference location.
 * We assume we wish to add the relocatoin amount, value, to the
 * value of the address already present at the offset.
 *
 * NAME			VALUE	FIELD		CALCULATION
 *
 * R_AMD64_NONE		 0	none		none
 * R_AMD64_64		 1	word64		S + A
 * R_AMD64_PC32		 2	word64		S + A
 * R_AMD64_GOT32	 3	word32		G + A
 * R_AMD64_PLT32	 4	word32		L + A - P
 * R_AMD64_COPY		 5	none		none
 * R_AMD64_GLOB_DAT	 6	word64		S
 * R_AMD64_JUMP_SLOT	 7	word64		S
 * R_AMD64_RELATIVE	 8	word64		B + A
 * R_AMD64_GOTPCREL	 9	word32		G + GOT + A - P
 * R_AMD64_32		10	word32		S + A
 * R_AMD64_32S		11	word32		S + A
 * R_AMD64_16		12	word16		S + A
 * R_AMD64_PC16		13	word16		S + A - P
 * R_AMD64_8		14	word8		S + A
 * R_AMD64_PC8		15	word8		S + A - P
 * R_AMD64_DTPMOD64	16	word64
 * R_AMD64_DTPOFF64	17	word64
 * R_AMD64_TPOFF64	18	word64
 * R_AMD64_TLSGD	19	word32
 * R_AMD64_TLSLD	20	word32
 * R_AMD64_DTPOFF32	21	word32
 * R_AMD64_GOTTPOFF	22	word32
 * R_AMD64_TPOFF32	23	word32
 * R_AMD64_PC64		24	word32		S + A - P
 * R_AMD64_GOTOFF64	25	word32		S + A - GOT
 * R_AMD64_GOTPC32	26	word32		GOT + A - P
 *
 * Relocation calculations:
 *	A	Represents the addend used to compute the value of the
 *		relocatable field.
 *
 *	B	Represents the base address at which a shared objects has
 *		been loaded into memory during executaion.  Generally, a
 *		shared objects is built with a 0 base virtual address,
 *		but the execution address will be different.
 *
 *	G	Represents the offset into the global offset table
 *		at which the relocation entry's symbol will reside
 *		during execution.
 *
 *	GOT	Rrepresents the address of the global offset table.
 *
 *	L	Represents the place (section offset or address) of
 *		the Procedure Linkage Table entry for a symbol.
 *
 *	P	Represents the place (section offset or address) of the
 *		storage unit being relocated (computed using r_offset).
 *
 *	S	Represents the value of the symbol whose index resides
 *		in the relocation entry.
 *
 */

#define	HIBITS	0xffffffff80000000

int
do_reloc(unsigned char rtype, unsigned char *off, Xword *value,
	const char *sym, const char *file)
{
	const Rel_entry	*rep;

	rep = &reloc_table[rtype];

	if (rep->re_fsize == 4) {
		/*
		 * The amd64 psABI requires that we perform
		 * the following verifications:
		 *
		 *    The R_AMD64_32 and R_AMD64_32S relocations
		 *    truncate the computed value to 32bits.  The linker
		 *    must verify that the generated value for the
		 *    R_AMD64_32(R_AMD64_32S) relocation zero-extends
		 *    (sign extends) to the original 64-bit value.
		 *
		 * Also - the following relocations are all 32 bit PC relative
		 * references, so we must validate that the value being
		 * written will fit in the field provided.
		 *
		 *  R_AMD64_PC32, R_AMD64_GOTPC32, R_AMD64_GOTPCREL
		 */
		if (rtype == R_AMD64_32) {
			/*
			 * We must verify that this value will 'zero-extend',
			 * this requires that the upper 33bits all be
			 * 'zero'.
			 */
			if ((*value & HIBITS) != 0) {
				/*
				 * to keep chkmsg() happy:
				 *  MSG_INTL(MSG_REL_NOFIT)
				 */
				REL_ERR_NOFIT(file, sym, rtype, *value);
				return (0);
			}
		} else if ((rtype == R_AMD64_32S) ||
			(rtype == R_AMD64_PC32) ||
			(rtype == R_AMD64_GOTPCREL) ||
			(rtype == R_AMD64_GOTPC32)) {
			/*
			 * We must verify that this value will properly
			 * sign extend.  This is true of the upper
			 * 33bits are all either 'zero' or
			 * all 'one'.
			 */
			if (((*value & HIBITS) != HIBITS) &&
			    ((*value & HIBITS) != 0)) {
				/*
				 * to keep chkmsg() happy:
				 *  MSG_INTL(MSG_REL_NOFIT)
				 */
				REL_ERR_NOFIT(file, sym, rtype, *value);
				return (0);
			}
		}
		/* LINTED */
		*((Word *)off) += *value;
	} else if (rep->re_fsize == 8) {
		*((Xword *)off) += *value;
	} else {
		eprintf(ERR_FATAL, MSG_INTL(MSG_REL_UNSUPSZ),
		    conv_reloc_amd64_type_str(rtype), file,
		    (sym ? sym : MSG_INTL(MSG_STR_UNKNOWN)),
		    EC_WORD(rep->re_fsize));
		return (0);
	}
	return (1);
}
