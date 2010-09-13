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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#if	defined(_KERNEL)
#include	<sys/types.h>
#include	"reloc.h"
#else
#define	ELF_TARGET_AMD64
#if defined(DO_RELOC_LIBLD)
#undef DO_RELOC_LIBLD
#define	DO_RELOC_LIBLD_X86
#endif
#include	<stdio.h>
#include	"sgs.h"
#include	"machdep.h"
#include	"libld.h"
#include	"reloc.h"
#include	"conv.h"
#include	"msg.h"
#endif

/*
 * We need to build this code differently when it is used for
 * cross linking:
 *	- Data alignment requirements can differ from those
 *		of the running system, so we can't access data
 *		in units larger than a byte
 *	- We have to include code to do byte swapping when the
 *		target and linker host use different byte ordering,
 *		but such code is a waste when running natively.
 */
#if !defined(DO_RELOC_LIBLD) || defined(__i386) || defined(__amd64)
#define	DORELOC_NATIVE
#endif

/*
 * This table represents the current relocations that do_reloc() is able to
 * process.  The relocations below that are marked SPECIAL are relocations that
 * take special processing and shouldn't actually ever be passed to do_reloc().
 */
const Rel_entry	reloc_table[R_AMD64_NUM] = {
/* R_AMD64_NONE */	{0, FLG_RE_NOTREL, 0, 0, 0},
/* R_AMD64_64 */	{0, FLG_RE_NOTREL, 8, 0, 0},
/* R_AMD64_PC32 */	{0, FLG_RE_PCREL, 4, 0, 0},
/* R_AMD64_GOT32 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_AMD64_PLT32 */	{0, FLG_RE_PCREL | FLG_RE_PLTREL |
			    FLG_RE_VERIFY | FLG_RE_SIGN, 4, 0, 0},
/* R_AMD64_COPY */	{0, FLG_RE_NOTSUP, 0, 0, 0},	/* SPECIAL */
/* R_AMD64_GLOB_DAT */	{0, FLG_RE_NOTREL, 8, 0, 0},
/* R_AMD64_JUMP_SLOT */	{0, FLG_RE_NOTSUP, 0, 0, 0},	/* SPECIAL */
/* R_AMD64_RELATIVE */	{0, FLG_RE_NOTREL, 8, 0, 0},
/* R_AMD64_GOTPCREL */	{0, FLG_RE_GOTPC | FLG_RE_GOTADD, 4, 0, 0},
/* R_AMD64_32 */	{0, FLG_RE_NOTREL, 4, 0, 0},
/* R_AMD64_32S */	{0, FLG_RE_NOTREL, 4, 0, 0},
/* R_AMD64_16 */	{0, FLG_RE_NOTREL, 2, 0, 0},
/* R_AMD64_PC16 */	{0, FLG_RE_PCREL, 2, 0, 0},
/* R_AMD64_8 */		{0, FLG_RE_NOTREL, 1, 0, 0},
/* R_AMD64_PC8 */	{0, FLG_RE_PCREL, 1, 0, 0},
/* R_AMD64_DTPMOD64 */	{0, FLG_RE_NOTREL, 8, 0, 0},
/* R_AMD64_DTPOFF64 */	{0, FLG_RE_NOTREL, 8, 0, 0},
/* R_AMD64_TPOFF64 */	{0, FLG_RE_NOTREL, 8, 0, 0},
/* R_AMD64_TLSGD */	{0, FLG_RE_GOTPC | FLG_RE_GOTADD | FLG_RE_TLSGD,
			    4, 0, 0},
/* R_AMD64_TLSLD */	{0, FLG_RE_GOTPC | FLG_RE_GOTADD | FLG_RE_TLSLD,
			    4, 0, 0},
/* R_AMD64_DTPOFF32 */	{0, FLG_RE_TLSLD, 4},
/* R_AMD64_GOTTPOFF */	{0, FLG_RE_GOTPC | FLG_RE_GOTADD | FLG_RE_TLSIE,
			    4, 0, 0},
/* R_AMD64_TPOFF32 */	{0, FLG_RE_TLSLE, 4, 0, 0},
/* R_AMD64_PC64 */	{0, FLG_RE_PCREL, 8, 0, 0},
/* R_AMD64_GOTOFF64 */	{0, FLG_RE_GOTREL, 8, 0, 0},
/* R_AMD64_GOTPC32 */	{0, FLG_RE_PCREL | FLG_RE_GOTPC | FLG_RE_LOCLBND,
			    4, 0, 0},
/* R_AMD64_GOT64 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_AMD64_GOTPCREL64 */	{FLG_RE_NOTSUP, 0, 0, 0},
/* R_AMD64_GOTPC6 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_AMD64_GOTPLT64 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_AMD64_PLTOFF64 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_AMD64_SIZE32 */	{0, FLG_RE_SIZE, 4, 0, 0},
/* R_AMD64_SIZE64 */	{0, FLG_RE_SIZE, 8, 0, 0}
};
#if	(R_AMD64_NUM != (R_AMD64_SIZE64 + 1))
#error	"R_AMD64_NUM has grown"
#endif

/*
 * Write a single relocated value to its reference location.
 * We assume we wish to add the relocation amount, value, to the
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
 * R_AMD64_GOT64	27			reserved for future expansion
 * R_AMD64_GOTPCREL64	28			reserved for future expansion
 * R_AMD64_GOTPC64	29			reserved for future expansion
 * R_AMD64_GOTPLT64	30			reserved for future expansion
 * R_AMD64_PLTOFF64	31			reserved for future expansion
 * R_AMD64_SIZE32	32	word32		Z + A
 * R_AMD64_SIZE64	33	word64		Z + A
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
 *	Z	the size of the symbol whose index resides in the relocation
 *		entry
 */

#define	HIBITS	0xffffffff80000000ULL

#if defined(_KERNEL)
#define	lml	0		/* Needed by arglist of REL_ERR_* macros */
int
do_reloc_krtld(uchar_t rtype, uchar_t *off, Xword *value, const char *sym,
    const char *file)
#elif defined(DO_RELOC_LIBLD)
/*ARGSUSED5*/
int
do_reloc_ld(Rel_desc *rdesc, uchar_t *off, Xword *value,
    rel_desc_sname_func_t rel_desc_sname_func,
    const char *file, int bswap, void *lml)
#else
int
do_reloc_rtld(uchar_t rtype, uchar_t *off, Xword *value, const char *sym,
    const char *file, void *lml)
#endif
{
#ifdef DO_RELOC_LIBLD
#define	sym (* rel_desc_sname_func)(rdesc)
	uchar_t	rtype = rdesc->rel_rtype;
#endif
	const Rel_entry	*rep;

	rep = &reloc_table[rtype];

	switch (rep->re_fsize) {
	case 1:
		/* LINTED */
		*((uchar_t *)off) = (uchar_t)(*value);
		break;

	case 2:
#if defined(DORELOC_NATIVE)
		/* LINTED */
		*((Half *)off) = (Half)(*value);
#else
		{
			Half	v = (Half)(*value);
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (bswap) {
				UL_ASSIGN_BSWAP_HALF(off, v_bytes);
			} else {
				UL_ASSIGN_HALF(off, v_bytes);
			}
		}
#endif
		break;

	case 4:
		/*
		 * The amd64 psABI requires that we perform the following
		 * verifications:
		 *
		 *    The R_AMD64_32 and R_AMD64_32S relocations truncate the
		 *    computed value to 32bits.  Verify that the generated value
		 *    for the R_AMD64_32/32S relocation zero-extends (sign
		 *    extends) to the original 64-bit value.
		 *
		 * Also, the following relocations are all 32 bit PC relative
		 * references.  Validate that the value being written will fit
		 * in the field provided.
		 *
		 *    R_AMD64_PC32, R_AMD64_GOTPC32, R_AMD64_GOTPCREL
		 */
		if (rtype == R_AMD64_32) {
			/*
			 * Verify that this value will 'zero-extend', this
			 * requires that the upper 33bits all be 'zero'.
			 */
			if ((*value & HIBITS) != 0) {
				/*
				 * To keep chkmsg() happy:
				 *  MSG_INTL(MSG_REL_NOFIT)
				 */
				REL_ERR_NOFIT(lml, file, sym, rtype, *value);
				return (0);
			}
		} else if ((rtype == R_AMD64_32S) || (rtype == R_AMD64_PC32) ||
		    (rtype == R_AMD64_GOTPCREL) || (rtype == R_AMD64_GOTPC32)) {
			/*
			 * Verify that this value will properly sign extend.
			 * This is true of the upper 33bits are all either
			 * 'zero' or all 'one'.
			 */
			if (((*value & HIBITS) != HIBITS) &&
			    ((*value & HIBITS) != 0)) {
				/*
				 * To keep chkmsg() happy:
				 *  MSG_INTL(MSG_REL_NOFIT)
				 */
				REL_ERR_NOFIT(lml, file, sym, rtype, *value);
				return (0);
			}
		}

#if defined(DORELOC_NATIVE)
		/* LINTED */
		*((Word *)off) += *value;
#else
		{
			Word	v;
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (bswap) {
				UL_ASSIGN_BSWAP_WORD(v_bytes, off);
				v += *value;
				UL_ASSIGN_BSWAP_WORD(off, v_bytes);
			} else {
				UL_ASSIGN_WORD(v_bytes, off);
				v += *value;
				UL_ASSIGN_WORD(off, v_bytes);
			}
		}
#endif
		break;

	case 8:
#if defined(DORELOC_NATIVE)
		/* LINTED */
		*((Xword *)off) += *value;
#else
		{
			Xword	v;
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (bswap) {
				UL_ASSIGN_BSWAP_XWORD(v_bytes, off);
				v += *value;
				UL_ASSIGN_BSWAP_XWORD(off, v_bytes);
			} else {
				UL_ASSIGN_XWORD(v_bytes, off);
				v += *value;
				UL_ASSIGN_XWORD(off, v_bytes);
			}
		}
#endif
		break;
	default:
		/*
		 * To keep chkmsg() happy: MSG_INTL(MSG_REL_UNSUPSZ)
		 */
		REL_ERR_UNSUPSZ(lml, file, sym, rtype, rep->re_fsize);
		return (0);
	}
	return (1);

#ifdef DO_RELOC_LIBLD
#undef sym
#endif
}
