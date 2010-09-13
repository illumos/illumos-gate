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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#if	defined(_KERNEL)
#include	<sys/types.h>
#include	"krtld/reloc.h"
#else
#define	ELF_TARGET_SPARC
#if defined(DO_RELOC_LIBLD)
#undef DO_RELOC_LIBLD
#define	DO_RELOC_LIBLD_SPARC
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
#if !defined(DO_RELOC_LIBLD) || defined(__sparc)
#define	DORELOC_NATIVE
#endif

/*
 * This table represents the current relocations that do_reloc() is able to
 * process.  The relocations below that are marked SPECIAL are relocations that
 * take special processing and shouldn't actually ever be passed to do_reloc().
 */
const Rel_entry reloc_table[R_SPARC_NUM] = {
/* R_SPARC_NONE */	{0x0, FLG_RE_NOTREL, 0, 0, 0},
/* R_SPARC_8 */		{0x0, FLG_RE_VERIFY, 1, 0, 0},
/* R_SPARC_16 */	{0x0, FLG_RE_VERIFY, 2, 0, 0},
/* R_SPARC_32 */	{0x0, FLG_RE_VERIFY, 4, 0, 0},
/* R_SPARC_DISP8 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY | FLG_RE_SIGN,
				1, 0, 0},
/* R_SPARC_DISP16 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY | FLG_RE_SIGN,
				2, 0, 0},
/* R_SPARC_DISP32 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY | FLG_RE_SIGN,
				4, 0, 0},
/* R_SPARC_WDISP30 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY | FLG_RE_SIGN,
				4, 2, 30},
/* R_SPARC_WDISP22 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY | FLG_RE_SIGN,
				4, 2, 22},
#if	defined(_ELF64)
/* R_SPARC_HI22 */	{0x0, FLG_RE_VERIFY, 4, 10, 22},
#else
/* R_SPARC_HI22 */	{0x0, FLG_RE_NOTREL, 4, 10, 22},
#endif
/* R_SPARC_22 */	{0x0, FLG_RE_VERIFY, 4, 0, 22},
/* R_SPARC_13 */	{0x0, FLG_RE_VERIFY | FLG_RE_SIGN, 4, 0, 13},
/* R_SPARC_LO10 */	{0x3ff, FLG_RE_SIGN, 4, 0, 13},
/* R_SPARC_GOT10 */	{0x3ff, FLG_RE_GOTADD | FLG_RE_SIGN, 4, 0, 13},
/* R_SPARC_GOT13 */	{0x0, FLG_RE_GOTADD | FLG_RE_VERIFY | FLG_RE_SIGN,
				4, 0, 13},
/* R_SPARC_GOT22 */	{0x0, FLG_RE_GOTADD, 4, 10, 22},
/* R_SPARC_PC10 */	{0x3ff, FLG_RE_PCREL | FLG_RE_SIGN | FLG_RE_LOCLBND,
				4, 0, 13},
/* R_SPARC_PC22 */	{0x0, FLG_RE_PCREL | FLG_RE_SIGN | FLG_RE_VERIFY |
				FLG_RE_LOCLBND, 4, 10, 22},
/* R_SPARC_WPLT30 */	{0x0, FLG_RE_PCREL | FLG_RE_PLTREL |
				FLG_RE_VERIFY | FLG_RE_SIGN,
				4, 2, 30},
/* R_SPARC_COPY */	{0x0, 0, 0, 0, 0},		/* SPECIAL */
#if	defined(_ELF64)
/* R_SPARC_GLOB_DAT */	{0x0, FLG_RE_NOTREL, 8, 0, 0},
#else
/* R_SPARC_GLOB_DAT */	{0x0, FLG_RE_NOTREL, 4, 0, 0},
#endif
/* R_SPARC_JMP_SLOT */	{0x0, 0, 0, 0, 0},		/* SPECIAL */
#if	defined(_ELF64)
/* R_SPARC_RELATIVE */	{0x0, FLG_RE_NOTREL, 8, 0, 0},
#else
/* R_SPARC_RELATIVE */	{0x0, FLG_RE_NOTREL, 4, 0, 0},
#endif
/* R_SPARC_UA32 */	{0x0, FLG_RE_UNALIGN, 4, 0, 0},
/* R_SPARC_PLT32 */	{0x0, FLG_RE_PLTREL | FLG_RE_VERIFY |
				FLG_RE_ADDRELATIVE, 4, 0, 0},
/* R_SPARC_HIPLT22 */	{0x0, FLG_RE_PLTREL, 4, 10, 22},
/* R_SPARC_LOPLT10 */	{0x3ff, FLG_RE_PLTREL, 4, 0, 13},
/* R_SPARC_PCPLT32 */	{0x0, FLG_RE_PLTREL | FLG_RE_PCREL | FLG_RE_VERIFY,
				4, 0, 0},
/* R_SPARC_PCPLT22 */	{0x0, FLG_RE_PLTREL | FLG_RE_PCREL | FLG_RE_VERIFY,
				4, 10, 22},
/* R_SPARC_PCPLT10 */	{0x3ff, FLG_RE_PLTREL | FLG_RE_PCREL | FLG_RE_VERIFY,
				4, 0, 13},
/* R_SPARC_10 */	{0x0, FLG_RE_VERIFY | FLG_RE_SIGN, 4, 0, 10},
/* R_SPARC_11 */	{0x0, FLG_RE_VERIFY | FLG_RE_SIGN, 4, 0, 11},
/* R_SPARC_64 */	{0x0, FLG_RE_VERIFY, 8, 0, 0},		/* V9 */
/* R_SPARC_OLO10 */	{0x3ff, FLG_RE_EXTOFFSET | FLG_RE_SIGN,
				4, 0, 13},			/* V9 */
/* R_SPARC_HH22 */	{0x0, FLG_RE_VERIFY, 4, 42, 22},	/* V9 */
/* R_SPARC_HM10 */	{0x3ff, FLG_RE_SIGN, 4, 32, 13},	/* V9 */
/* R_SPARC_LM22 */	{0x0, FLG_RE_NOTREL, 4, 10, 22},	/* V9 */
/* R_SPARC_PC_HH22 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY,
				4, 42, 22},			/* V9 */
/* R_SPARC_PC_HM10 */	{0x3ff, FLG_RE_PCREL | FLG_RE_SIGN,
				4, 32, 13},			/* V9 */
/* R_SPARC_PC_LM22 */	{0x0, FLG_RE_PCREL,
				4, 10, 22},			/* V9 */
/* R_SPARC_WDISP16 */	{0x0, FLG_RE_PCREL | FLG_RE_WDISP16 |
				FLG_RE_VERIFY | FLG_RE_SIGN,
				4, 2, 16},
/* R_SPARC_WDISP19 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY | FLG_RE_SIGN,
				4, 2, 19},
/* R_SPARC_GLOB_JMP */	{0x0, 0, 0, 0, 0},	/* V9 - not implemented */
						/* removed from v9 ABI */
/* R_SPARC_7 */		{0x0, FLG_RE_NOTREL, 4, 0, 7},
/* R_SPARC_5 */		{0x0, FLG_RE_NOTREL, 4, 0, 5},
/* R_SPARC_6 */		{0x0, FLG_RE_NOTREL, 4, 0, 6},
/* R_SPARC_DISP64 */	{0x0, FLG_RE_PCREL | FLG_RE_VERIFY | FLG_RE_SIGN,
				8, 0, 0},
/* R_SPARC_PLT64 */	{0x0, FLG_RE_PLTREL | FLG_RE_VERIFY |
				FLG_RE_ADDRELATIVE, 8, 0, 0},
/* R_SPARC_HIX22 */	{(Xword)(-1LL), FLG_RE_VERIFY,
				4, 10, 22},			/* V9 - HaL */
/* R_SPARC_LOX10 */	{0x3ff, FLG_RE_SIGN, 4, 0, 13},		/* V9 - HaL */
/* R_SPARC_H44 */	{0x0, FLG_RE_VERIFY, 4, 22, 22},	/* V9 */
/* R_SPARC_M44 */	{0x3ff, FLG_RE_NOTREL, 4, 12, 10},	/* V9 */
/* R_SPARC_L44 */	{0xfff, FLG_RE_NOTREL, 4, 0, 13},	/* V9 */
/* R_SPARC_REGISTER */	{0x0, FLG_RE_REGISTER, 0, 0, 0},	/* SPECIAL */
/* R_SPARC_UA64 */	{0x0, FLG_RE_VERIFY | FLG_RE_UNALIGN,
				8, 0, 0},			/* V9 */
/* R_SPARC_UA16 */	{0x0, FLG_RE_VERIFY | FLG_RE_UNALIGN,
				2, 0, 0},
/* R_SPARC_TLS_GD_HI22 */   {0x0, FLG_RE_GOTADD | FLG_RE_TLSGD, 4, 10, 22},
/* R_SPARC_TLS_GD_LO10 */   {0x3ff, FLG_RE_GOTADD | FLG_RE_TLSGD |
				FLG_RE_SIGN, 4, 0, 13},
/* R_SPARC_TLS_GD_ADD */    {0x0, FLG_RE_TLSGD, 0, 0, 0},
/* R_SPARC_TLS_GD_CALL */   {0x0, FLG_RE_TLSGD, 0, 0, 0},
/* R_SPARC_TLS_LDM_HI22 */  {0x0, FLG_RE_GOTADD | FLG_RE_TLSLD, 4, 10, 22},
/* R_SPARC_TLS_LDM_LO10 */  {0x3ff, FLG_RE_GOTADD | FLG_RE_TLSLD |
				FLG_RE_SIGN, 4, 0, 13},
/* R_SPARC_TLS_LDM_ADD */   {0x0, FLG_RE_TLSLD, 0, 0, 0},
/* R_SPARC_TLS_LDM_CALL */  {0x0, FLG_RE_TLSLD, 0, 0, 0},
/* R_SPARC_TLS_LDO_HIX22 */ {0x0, FLG_RE_VERIFY | FLG_RE_TLSLD, 4, 10, 22},
/* R_SPARC_TLS_LDO_LOX10 */ {0x3ff, FLG_RE_SIGN | FLG_RE_TLSLD, 4, 0, 13},
/* R_SPARC_TLS_LDO_ADD */   {0x0, FLG_RE_TLSLD, 0, 0, 0},
/* R_SPARC_TLS_IE_HI22 */   {0x0, FLG_RE_GOTADD | FLG_RE_TLSIE, 4, 10, 22},
/* R_SPARC_TLS_IE_LO10 */   {0x3ff, FLG_RE_GOTADD | FLG_RE_TLSIE |
				FLG_RE_SIGN, 4, 0, 13},
/* R_SPARC_TLS_IE_LD */	    {0x0, FLG_RE_TLSIE, 0, 0, 0},
/* R_SPARC_TLS_IE_LDX */    {0x0, FLG_RE_TLSIE, 0, 0, 0},
/* R_SPARC_TLS_IE_ADD */    {0x0, FLG_RE_TLSIE, 0, 0, 0},
/* R_SPARC_TLS_LE_HIX22 */  {(Xword)(-1LL),
				FLG_RE_VERIFY | FLG_RE_TLSLE, 4, 10, 22},
/* R_SPARC_TLS_LE_LOX10 */  {0x3ff, FLG_RE_SIGN | FLG_RE_TLSLE, 4, 0, 13},
/* R_SPARC_TLS_DTPMOD32 */  {0x0, FLG_RE_NOTREL, 4, 0, 0},
/* R_SPARC_TLS_DTPMOD64 */  {0x0, FLG_RE_NOTREL, 8, 0, 0},
/* R_SPARC_TLS_DTPOFF32 */  {0x0, FLG_RE_NOTREL, 4, 0, 0},
/* R_SPARC_TLS_DTPOFF64 */  {0x0, FLG_RE_NOTREL, 8, 0, 0},
/* R_SPARC_TLS_TPOFF32 */   {0x0, FLG_RE_NOTREL, 4, 0, 0},
/* R_SPARC_TLS_TPOFF64 */   {0x0, FLG_RE_NOTREL, 8, 0, 0},
/* R_SPARC_GOTDATA_HIX22 */	{0, FLG_RE_SIGN | FLG_RE_GOTREL |
					FLG_RE_VERIFY, 4, 10, 22},
/* R_SPARC_GOTDATA_LOX10 */	{ 0x3ff, FLG_RE_GOTREL | FLG_RE_SIGN, 4, 0, 13},
/* R_SPARC_GOTDATA_OP_HIX22 */	{ 0x0, FLG_RE_GOTOPINS | FLG_RE_GOTADD,
					4, 10, 22},
/* R_SPARC_GOTDATA_OP_LOX10 */	{ 0x3ff, FLG_RE_SIGN | FLG_RE_GOTOPINS |
					FLG_RE_GOTADD, 4, 0, 13},
/* R_SPARC_GOTDATA_OP */	{ 0x0, FLG_RE_GOTOPINS, 0, 0, 0},
/* R_SPARC_H34 */	{0x0, FLG_RE_VERIFY, 4, 12, 22},	/* V9 */
/* R_SPARC_SIZE32 */	{0x0, FLG_RE_SIZE | FLG_RE_VERIFY, 4, 0, 0},
/* R_SPARC_SIZE64 */	{0x0, FLG_RE_SIZE | FLG_RE_VERIFY, 8, 0, 0},
};


/*
 * Write a single relocated value to its reference location.
 * We assume we wish to add the relocation amount, value, to the
 * value of the address already present in the instruction.
 *
 * NAME			 VALUE	FIELD		CALCULATION
 *
 * R_SPARC_NONE		     0	none		none
 * R_SPARC_8		     1	V-byte8		S + A
 * R_SPARC_16		     2	V-half16	S + A
 * R_SPARC_32		     3	V-word32	S + A
 * R_SPARC_DISP8	     4	V-byte8		S + A - P
 * R_SPARC_DISP16	     5	V-half16	S + A - P
 * R_SPARC_DISP32	     6	V-word32	S + A - P
 * R_SPARC_WDISP30	     7	V-disp30	(S + A - P) >> 2
 * R_SPARC_WDISP22	     8	V-disp22	(S + A - P) >> 2
 * R_SPARC_HI22		     9	T-imm22		(S + A) >> 10
 * R_SPARC_22		    10	V-imm22		S + A
 * R_SPARC_13		    11	V-simm13	S + A
 * R_SPARC_LO10		    12	T-simm13	(S + A) & 0x3ff
 * R_SPARC_GOT10	    13	T-simm13	G & 0x3ff
 * R_SPARC_GOT13	    14	V-simm13	G
 * R_SPARC_GOT22	    15	T-imm22		G >> 10
 * R_SPARC_PC10		    16	T-simm13	(S + A - P) & 0x3ff
 * R_SPARC_PC22		    17	V-disp22	(S + A - P) >> 10
 * R_SPARC_WPLT30	    18	V-disp30	(L + A - P) >> 2
 * R_SPARC_COPY		    19	none		none
 * R_SPARC_GLOB_DAT	    20	V-word32	S + A
 * R_SPARC_JMP_SLOT	    21	V-plt22		S + A
 * R_SPARC_RELATIVE	    22	V-word32	S + A
 * R_SPARC_UA32		    23	V-word32	S + A
 * R_SPARC_PLT32	    24	V-word32        L + A
 * R_SPARC_HIPLT22	    25	T-imm22         (L + A) >> 10
 * R_SPARC_LOPLT10	    26	T-simm13        (L + A) & 0x3ff
 * R_SPARC_PCPLT32	    27	V-word32        L + A - P
 * R_SPARC_PCPLT22	    28	V-disp22        (L + A - P) >> 10
 * R_SPARC_PCPLT10	    29	V-simm13        (L + A - P) & 0x3ff
 * R_SPARC_10		    30	V-simm10	S + A
 * R_SPARC_11		    31	V-simm11	S + A
 * R_SPARC_64		    32	V-xword64	S + A
 * R_SPARC_OLO10	    33	V-simm13	((S + A) & 0x3ff) + O
 * R_SPARC_HH22		    34	V-imm22		(S + A) >> 42
 * R_SPARC_HM10		    35	T-simm13	((S + A) >> 32) & 0x3ff
 * R_SPARC_LM22		    36	T-imm22		(S + A) >> 10
 * R_SPARC_PC_HH22	    37	V-imm22		(S + A - P) >> 42
 * R_SPARC_PC_HM10	    38	T-simm13	((S + A - P) >> 32) & 0x3ff
 * R_SPARC_PC_LM22	    39	T-imm22		(S + A - P) >> 10
 * R_SPARC_WDISP16	    40	V-d2/disp14	(S + A - P) >> 2
 * R_SPARC_WDISP19	    41	V-disp19	(S + A - P) >> 2
 * R_SPARC_GLOB_JMP	    42	V-xword64	S + A
 * R_SPARC_7		    43	V-imm7		S + A
 * R_SPARC_5		    44	V-imm5		S + A
 * R_SPARC_6		    45	V-imm6		S + A
 * R_SPARC_DISP64	    46	V-xword64	S + A - P
 * R_SPARC_PLT64	    47	V-xword64	L + A
 * R_SPARC_HIX22	    48	V-imm22		((S + A) ^
 *						    0xffffffffffffffff) >> 10
 * R_SPARC_LOX10	    49	T-simm13	((S + A) & 0x3ff) | 0x1c00
 * R_SPARC_H44		    50	V-imm22		(S + A) >> 22
 * R_SPARC_M44		    51	T-imm10		((S + A) >> 12) & 0x3ff
 * R_SPARC_L44		    52	T-imm13		(S + A) & 0xfff
 * R_SPARC_REGISTER	    53	V-xword64	S + A
 * R_SPARC_UA64		    54	V-xword64	S + A
 * R_SPARC_UA16		    55	V-half16	S + A
 * R_SPARC_TLS_GD_HI22	    56	T-simm22	@dtlndx(S + A) >> 10
 * R_SPARC_TLS_GD_LO10	    57	T-simm13	@dtlndx(S + A) & 0x3ff
 * R_SPARC_TLS_GD_ADD	    58	none		SPECIAL
 * R_SPARC_TLS_GD_CALL	    59	V-disp30	SPECIAL
 * R_SPARC_TLS_LDM_HI22	    60	T-simm22	@tmndx(S + A) >> 10
 * R_SPARC_TLS_LDM_LO10	    61	T-simm13	@tmndx(S + A) & 0x3ff
 * R_SPARC_TLS_LDM_ADD	    62	none		SPECIAL
 * R_SPARC_TLS_LDM_CALL	    63	V-disp30	SPECIAL
 * R_SPARC_TLS_LDO_HIX22    64	V-simm22	@dtpoff(S + A) >> 10
 * R_SPARC_TLS_LDO_LOX10    65	T-simm13	@dtpoff(S + A) & 0x3ff
 * R_SPARC_TLS_LDO_ADD	    66	none		SPECIAL
 * R_SPARC_TLS_IE_HI22	    67	T-simm22	@got(@tpoff(S + A)) >> 10
 * R_SPARC_TLS_IE_LO10	    68	T-simm13	@got(@tpoff(S + A)) & 0x3ff
 * R_SPARC_TLS_IE_LD	    69	none		SPECIAL
 * R_SPARC_TLS_IE_LDX	    70	none		SPECIAL
 * R_SPARC_TLS_IE_ADD	    71	none		SPECIAL
 * R_SPARC_TLS_LE_HIX22	    72	V-simm22	(@tpoff(S + A) ^
 *						    0xffffffff) >> 10
 * R_SPARC_TLS_LE_LOX10	    73	T-simm13	(@tpoff(S + A) & 0x3ff) | 0x1c00
 * R_SPARC_TLS_DTPMOD32	    74	V-word32	@dtmod(S + A)
 * R_SPARC_TLS_DTPMOD64	    75	V-word64	@dtmod(S + A)
 * R_SPARC_TLS_DTPOFF32	    76	V-word32	@dtpoff(S + A)
 * R_SPARC_TLS_DTPOFF64	    77	V-word64	@dtpoff(S + A)
 * R_SPARC_TLS_TPOFF32	    78	V-word32	@tpoff(S + A)
 * R_SPARC_TLS_TPOFF64	    79	V-word64	@tpoff(S + A)
 * R_SPARC_GOTDATA_HIX22    80	V-imm22		((S + A - GOT) >> 10) ^
 *						  ((S + A - GOT) >> 31)
 * R_SPARC_GOTDATA_LOX10    81	T-simm13	((S + A - GOT) & 0x3ff) |
 *						  (((S + A - GOT) >> 31) &
 *						  0x1c00)
 * R_SPARC_GOTDATA_OP_HIX22 82	T-imm22		(G >> 10) & (G >> 31)
 * R_SPARC_GOTDATA_OP_LOX10 83	T-simm13	(G & 0x3ff) |
 *						  ((G >> 31) & 0x1c00)
 * R_SPARC_GOTDATA_OP	    84  Word32		SPECIAL
 * R_SPARC_H34		    85	V-imm22		(S + A) >> 12
 * R_SPARC_SIZE32	    86	V-word32	Z + A
 * R_SPARC_SIZE64	    87	V-xword64	Z + A
 *
 *	This is Figure 4-20: Relocation Types from the Draft Copy of
 * the ABI, Printed on 11/29/88.
 *
 * NOTE1: relocations 24->45 are newly registered relocations to support
 *	 C++ ABI & SPARC V8+ and SPARC V9 architectures (1/9/94), and
 *	 64-bit relocations 46-55 were added for SPARC V9.
 *
 * NOTE2: relocations 56->79 are added to support Thread-Local storage
 *	  as recorded in PSARC/2001/509
 *
 * NOTE3: The value to be passed for relocations R_SPARC_HIX22 and
 *	  R_SPARC_TLS_HIX22 are negative values. So the upper 10 or 40 bits
 *	  are 1. (So when the exclusive OR is applied, the upper bits
 *	  will be 0.)
 *
 * Relocation calculations:
 *
 * The FIELD names indicate whether the relocation type checks for overflow.
 * A calculated relocation value may be larger than the intended field, and
 * the relocation type may verify (V) that the value fits, or truncate (T)
 * the result.
 *
 * CALCULATION uses the following notation:
 *      A       the addend used
 *      B       the base address of the shared object in memory
 *      G       the offset into the global offset table
 *      L       the procedure linkage entry
 *      P       the place of the storage unit being relocated
 *      S       the value of the symbol
 *	O	secondary addend (extra offset) in v9 r_info field
 *	Z	the size of the symbol whose index resides in the relocation
 *		entry
 *
 *	@dtlndx(x): Allocate two contiguous entries in the GOT table to hold
 *	   a Tls_index structure (for passing to __tls_get_addr()). The
 *	   instructions referencing this entry will be bound to the first
 *	   of the two GOT entries.
 *
 *	@tmndx(x): Allocate two contiguous entries in the GOT table to hold
 *	   a Tls_index structure (for passing to __tls_get_addr()). The
 *	   ti_offset field of the Tls_index will be set to 0 (zero) and the
 *	   ti_module will be filled in at run-time. The call to
 *	   __tls_get_addr() will return the starting offset of the dynamic
 *	   TLS block.
 *
 *	@dtpoff(x): calculate the tlsoffset relative to the TLS block.
 *
 *	@tpoff(x): calculate the negative tlsoffset relative to the static
 *	   TLS block. This value can be added to the thread-pointer to
 *	   calculate the tls address.
 *
 *	@dtpmod(x): calculate the module id of the object containing symbol x.
 *
 * The calculations in the CALCULATION column are assumed to have been performed
 * before calling this function except for the addition of the addresses in the
 * instructions.
 *
 * Upon successful completion of do_reloc() *value will be set to the
 * 'bit-shifted' value that will be or'ed into memory.
 */
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
	Xword	uvalue = 0;
	Xword	basevalue, sigbit_mask, sigfit_mask;
	Xword	corevalue = *value;
	uchar_t	bshift;
	int	field_size, re_flags;
	const	Rel_entry	*rep;

	rep = &reloc_table[rtype];
	bshift = rep->re_bshift;
	field_size = rep->re_fsize;
	re_flags = rep->re_flags;
	sigbit_mask = S_MASK(rep->re_sigbits);

	if ((re_flags & FLG_RE_SIGN) && sigbit_mask) {
		/*
		 * sigfit_mask takes into account that a value
		 * might be signed and discards the signbit for
		 * comparison.
		 */
		sigfit_mask = S_MASK(rep->re_sigbits - 1);
	} else
		sigfit_mask = sigbit_mask;

	if (field_size == 0) {
		REL_ERR_UNIMPL(lml, file, sym, rtype);
		return (0);
	}

	/*
	 * We have two ways to retrieve the base value, a general one
	 * that will work with data of any alignment, and another that is
	 * fast, but which requires the data to be aligned according to
	 * sparc alignment rules.
	 *
	 * For non-native linking, we always use the general path. For
	 * native linking, the FLG_RE_UNALIGN determines it.
	 */
#if defined(DORELOC_NATIVE)
	if (re_flags & FLG_RE_UNALIGN)
#endif
	{
		int	i;
		uchar_t	*dest = (uchar_t *)&basevalue;

		basevalue = 0;
#if !defined(DORELOC_NATIVE)
		if (bswap) {
			int j = field_size - 1;

			for (i = 0; i < field_size; i++, j--)
				dest[i] = off[j];

		} else
#endif
		{
			/*
			 * Adjust the offset
			 */
			/* LINTED */
			i = (int)(sizeof (Xword) - field_size);
			if (i > 0)
				dest += i;
			for (i = field_size - 1; i >= 0; i--)
				dest[i] = off[i];
		}
	}

	/*
	 * Non-native linker: We have already fetched the value above,
	 *	but if the relocation does not have the FLG_RE_UNALIGN
	 *	flag set, we still need to do the same error checking we
	 *	would do on a native linker.
	 * Native-linker: If this is an aligned relocation, we need to
	 *	fetch the value and also do the error checking.
	 *
	 * The FETCH macro is used to conditionalize the fetching so that
	 * it only happens in the native case.
	 */
#if defined(DORELOC_NATIVE)
#define	FETCH(_type) basevalue = (Xword)*((_type *)off);
#else
#define	FETCH(_type)
#endif
	if ((re_flags & FLG_RE_UNALIGN) == 0) {
		if (((field_size == 2) && ((uintptr_t)off & 0x1)) ||
		    ((field_size == 4) && ((uintptr_t)off & 0x3)) ||
		    ((field_size == 8) && ((uintptr_t)off & 0x7))) {
			REL_ERR_NONALIGN(lml, file, sym, rtype, (uintptr_t)off);
			return (0);
		}
		switch (field_size) {
		case 1:
			/* LINTED */
			FETCH(uchar_t);
			break;
		case 2:
			/* LINTED */
			FETCH(Half);
			break;
		case 4:
			/* LINTED */
			FETCH(Word);
			break;
		case 8:
			/* LINTED */
			FETCH(Xword);
			break;
		default:
			REL_ERR_UNNOBITS(lml, file, sym, rtype,
			    (rep->re_fsize * 8));
			return (0);
		}
	}
#undef FETCH

	if (sigbit_mask) {
		/*
		 * The WDISP16 relocation is an unusual one in that it's bits
		 * are not all contiguous.  We have to selectivly pull them out.
		 */
		if (re_flags & FLG_RE_WDISP16) {
			uvalue = ((basevalue & 0x300000) >> 6) |
			    (basevalue & 0x3fff);
			basevalue &= ~0x303fff;
		} else {
			uvalue = sigbit_mask & basevalue;
			basevalue &= ~sigbit_mask;
		}
		/*
		 * If value is signed make sure that we signextend the uvalue.
		 */
		if (re_flags & FLG_RE_SIGN) {
			if (uvalue & (~sigbit_mask & sigfit_mask))
				uvalue |= ~sigbit_mask;
		}
	} else
		uvalue = basevalue;

	if (bshift)
		uvalue <<= bshift;

	uvalue += *value;

	if (rep->re_mask &&
	    ((rtype == R_SPARC_HIX22) || (rtype == R_SPARC_TLS_LE_HIX22)))
		uvalue ^= rep->re_mask;

	if (bshift) {
		/*
		 * This is to check that we are not attempting to
		 * jump to a non-4 byte aligned address.
		 */
		if ((bshift == 2) && (uvalue & 0x3)) {
			REL_ERR_LOSEBITS(lml, file, sym, rtype, uvalue, 2, off);
			return (0);
		}

		if (re_flags & FLG_RE_SIGN) {
			uvalue = (Sxword)uvalue >> bshift;
		} else {
			uvalue >>= bshift;
		}
		corevalue >>= bshift;
	}

	if ((rtype == R_SPARC_GOTDATA_HIX22) ||
	    (rtype == R_SPARC_GOTDATA_OP_HIX22)) {
		uvalue ^= ((Sxword)(*value) >> 31);
		corevalue ^= ((Sxword)(*value) >> 31);
	}

	if (rep->re_mask &&
	    (rtype != R_SPARC_HIX22) && (rtype != R_SPARC_TLS_LE_HIX22) &&
	    (rtype != R_SPARC_GOTDATA_HIX22))
		uvalue &= rep->re_mask;

	if ((rtype == R_SPARC_LOX10) || (rtype == R_SPARC_TLS_LE_LOX10)) {
		uvalue |= 0x1c00;
		corevalue |= 0x1c00;
	}

	if ((rtype == R_SPARC_GOTDATA_LOX10) ||
	    (rtype == R_SPARC_GOTDATA_OP_LOX10)) {
		uvalue |= ((Sxword)(*value) >> 31) & 0x1c00;
		corevalue |= ((Sxword)(*value) >> 31) & 0x1c00;
	}


	if ((re_flags & FLG_RE_VERIFY) && sigbit_mask) {
		if (((re_flags & FLG_RE_SIGN) &&
		    (S_INRANGE((Sxword)uvalue, rep->re_sigbits - 1) == 0)) ||
		    (!(re_flags & FLG_RE_SIGN) &&
		    ((sigbit_mask & uvalue) != uvalue))) {
			REL_ERR_NOFIT(lml, file, sym, rtype, uvalue);
			return (0);
		}
	}

	if (sigbit_mask) {
		/*
		 * Again the R_SPARC_WDISP16 relocation takes special
		 * processing because of its non-continguous bits.
		 */
		if (re_flags & FLG_RE_WDISP16)
			uvalue = ((uvalue & 0xc000) << 6) |
			    (uvalue & 0x3fff);
		else
			uvalue &= sigbit_mask;
		/*
		 * Combine value back with original word
		 */
		uvalue |= basevalue;
	}
	*value = corevalue;

	/*
	 * Now, we store uvalue back at the location given by off.
	 * This is similar to the fetch case above:
	 *	- We have general (unaligned) and fast (aligned) cases
	 *	- Cross linkers need to use the unaligned case even
	 *		when the relocation does not specify FLG_RE_UNALIGN.
	 *	- A cross linker that processes a relocation that does not
	 *		have FLG_RE_UNALIGN set has to do the same error
	 *		checking that a native linker would do, while avoiding
	 *		the aligned store (accomplished with the STORE macro).
	 */
#if defined(DORELOC_NATIVE)
	if (re_flags & FLG_RE_UNALIGN)
#endif
	{
		int	i;
		uchar_t	*src = (uchar_t *)&uvalue;

#if !defined(DORELOC_NATIVE)
		if (bswap) {
			int j = field_size - 1;

			for (i = 0; i < field_size; i++, j--)
				off[i] = src[j];

		} else
#endif
		{
			/*
			 * Adjust the offset.
			 */
			/* LINTED */
			i = (int)(sizeof (Xword) - field_size);
			if (i > 0)
				src += i;
			for (i = field_size - 1; i >= 0; i--)
				off[i] = src[i];
		}
	}

#if defined(DORELOC_NATIVE)
#define	STORE(_type) *((_type *)off) = (_type)uvalue
#else
#define	STORE(_type)
#endif
	if ((re_flags & FLG_RE_UNALIGN) == 0) {
		switch (rep->re_fsize) {
		case 1:
			/* LINTED */
			STORE(uchar_t);
			break;
		case 2:
			/* LINTED */
			STORE(Half);
			break;
		case 4:
			/* LINTED */
			STORE(Word);
			break;
		case 8:
			/* LINTED */
			STORE(Xword);
			break;
		default:
			/*
			 * To keep chkmsg() happy: MSG_INTL(MSG_REL_UNSUPSZ)
			 */
			REL_ERR_UNSUPSZ(lml, file, sym, rtype, rep->re_fsize);
			return (0);
		}
	}
#undef STORE

	return (1);

#ifdef DO_RELOC_LIBLD
#undef sym
#endif
}
