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
#include	"reloc.h"
#else
#define	ELF_TARGET_386
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
const Rel_entry	reloc_table[R_386_NUM] = {
/* R_386_NONE */	{0, FLG_RE_NOTREL, 0, 0, 0},
/* R_386_32 */		{0, FLG_RE_NOTREL, 4, 0, 0},
/* R_386_PC32 */	{0, FLG_RE_PCREL, 4, 0, 0},
/* R_386_GOT32 */	{0, FLG_RE_GOTADD, 4, 0, 0},
/* R_386_PLT32 */	{0, FLG_RE_PLTREL | FLG_RE_PCREL, 4, 0, 0},
/* R_386_COPY */	{0, FLG_RE_NOTREL, 0, 0, 0},		/* SPECIAL */
/* R_386_GLOB_DAT */	{0, FLG_RE_NOTREL, 4, 0, 0},
/* R_386_JMP_SLOT */	{0, FLG_RE_NOTREL, 4, 0, 0},		/* SPECIAL */
/* R_386_RELATIVE */	{0, FLG_RE_NOTREL, 4, 0, 0},
/* R_386_GOTOFF */	{0, FLG_RE_GOTREL, 4, 0, 0},
/* R_386_GOTPC */	{0, FLG_RE_PCREL | FLG_RE_GOTPC | FLG_RE_LOCLBND, 4,
			    0, 0},
/* R_386_32PLT */	{0, FLG_RE_PLTREL, 4, 0, 0},
/* R_386_TLS_GD_PLT */	{0, FLG_RE_PLTREL | FLG_RE_PCREL | FLG_RE_TLSGD, 4,
			    0, 0},
/* R_386_TLS_LDM_PLT */	{0, FLG_RE_PLTREL | FLG_RE_PCREL | FLG_RE_TLSLD, 4,
			    0, 0},
/* R_386_TLS_TPOFF */	{0, FLG_RE_NOTREL, 4, 0, 0},
/* R_386_TLS_IE */	{0, FLG_RE_GOTADD | FLG_RE_TLSIE, 4, 0, 0},
/* R_386_TLS_GOTIE */	{0, FLG_RE_GOTADD | FLG_RE_TLSIE, 4, 0, 0},
/* R_386_TLS_LE */	{0, FLG_RE_TLSLE, 4, 0, 0},
/* R_386_TLS_GD */	{0, FLG_RE_GOTADD | FLG_RE_TLSGD, 4, 0, 0},
/* R_386_TLS_LDM */	{0, FLG_RE_GOTADD | FLG_RE_TLSLD, 4, 0, 0},
/* R_386_16 */		{0, FLG_RE_NOTREL, 2, 0, 0},
/* R_386_PC16 */	{0, FLG_RE_PCREL, 2, 0, 0},
/* R_386_8 */		{0, FLG_RE_NOTREL, 1, 0, 0},
/* R_386_PC8 */		{0, FLG_RE_PCREL, 1, 0, 0},
/* R_386_UNKNOWN24 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN25 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN26 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN27 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN28 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN29 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN30 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN31 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_TLS_LDO_32 */	{0, FLG_RE_TLSLD, 4, 0, 0},
/* R_386_UNKNOWN33 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_UNKNOWN34 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_TLS_DTPMOD32 */ {0, FLG_RE_NOTREL, 4, 0, 0},
/* R_386_TLS_DTPOFF32 */ {0, FLG_RE_NOTREL, 4, 0, 0},
/* R_386_UNKONWN37 */	{0, FLG_RE_NOTSUP, 0, 0, 0},
/* R_386_SIZE32 */	{0, FLG_RE_SIZE | FLG_RE_VERIFY, 4, 0, 0}
};

/*
 * Write a single relocated value to its reference location.
 * We assume we wish to add the relocation amount, value, to the
 * value of the address already present at the offset.
 *
 * NAME			VALUE	FIELD		CALCULATION
 *
 * R_386_NONE		 0	none		none
 * R_386_32		 1	word32		S + A
 * R_386_PC32		 2	word32		S + A - P
 * R_386_GOT32		 3	word32		G + A - P
 * R_386_PLT32		 4	word32		L + A - P
 * R_386_COPY		 5	none		none
 * R_386_GLOB_DAT	 6	word32		S
 * R_386_JMP_SLOT	 7	word32		S
 * R_386_RELATIVE	 8	word32		B + A
 * R_386_GOTOFF		 9	word32		S + A - GOT
 * R_386_GOTPC		10	word32		GOT + A - P
 * R_386_32PLT		11	word32		L + A
 * R_386_TLS_GD_PLT	12	word32		@tlsgdplt
 * R_386_TLS_LDM_PLT	13	word32		@tlsldmplt
 * R_386_TLS_TPOFF	14	word32		@ntpoff(S)
 * R_386_TLS_IE		15	word32		@indntpoff(S)
 * R_386_TLS_GD		18	word32		@tlsgd(S)
 * R_386_TLS_LDM	19	word32		@tlsldm(S)
 * R_386_16		20	word16		S + A
 * R_386_PC16		21	word16		S + A - P
 * R_386_8		22	word8		S + A
 * R_386_PC8		23	word8		S + A - P
 * R_386_TLS_LDO_32	32	word32		@dtpoff(S)
 * R_386_TLS_DTPMOD32	35	word32		@dtpmod(S)
 * R_386_TLS_DTPOFF32	36	word32		@dtpoff(S)
 * R_386_SIZE32		38	word32		Z + A
 *
 * Relocations 0-10 are from Figure 4-4: Relocation Types from the
 * intel ABI.  Relocation 11 (R_386_32PLT) is from the C++ intel abi
 * and is in the process of being registered with intel ABI (1/13/94).
 *
 * Relocations R_386_TLS_* are added to support Thread-Local storage
 *	as recorded in PSARC/2001/509
 *
 * Relocation calculations:
 *
 * CALCULATION uses the following notation:
 *	A	the addend used
 *	B	the base address of the shared object in memory
 *	G	the offset into the global offset table
 *	GOT	the address of teh global offset table
 *	L	the procedure linkage entry
 *	P	the place of the storage unit being relocated
 *	S	the value of the symbol
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
 *	@tpoff(x): calculate the tlsoffset relative to the TLS block.
 *
 *	@dtpmod(x): calculate the module id of the object containing symbol x.
 *
 * The calculations in the CALCULATION column are assumed to have
 * been performed before calling this function except for the addition of
 * the addresses in the instructions.
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
	const Rel_entry	*rep;

	rep = &reloc_table[rtype];

	switch (rep->re_fsize) {
	case 1:
		/* LINTED */
		*((uchar_t *)off) += (uchar_t)(*value);
		break;

	case 2:
#if defined(DORELOC_NATIVE)
		/* LINTED */
		*((Half *)off) += (Half)(*value);
#else
		{
			Half	v;
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (bswap) {
				UL_ASSIGN_BSWAP_HALF(v_bytes, off);
				v += *value;
				UL_ASSIGN_BSWAP_HALF(off, v_bytes);
			} else {
				UL_ASSIGN_HALF(v_bytes, off);
				v += *value;
				UL_ASSIGN_HALF(off, v_bytes);
			}
		}
#endif
		break;

	case 4:
#if defined(DORELOC_NATIVE)
		/* LINTED */
		*((Xword *)off) += *value;
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
