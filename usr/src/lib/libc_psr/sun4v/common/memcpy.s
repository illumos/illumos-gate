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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"memcpy.s"

/*
 * memcpy(s1, s2, len)
 *
 * Copy s2 to s1, always copy n bytes.
 * Note: this C code does not work for overlapped copies.
 *       Memmove() and bcopy() do.
 *
 * Added entry __align_cpy_1 is generally for use of the compilers.
 *
 * Fast assembler language version of the following C-program for memcpy
 * which represents the `standard' for the C-library.
 *
 *	void *
 *	memcpy(void *s, const void *s0, size_t n)
 *	{
 *		if (n != 0) {
 *		    char *s1 = s;
 *		    const char *s2 = s0;
 *		    do {
 *			*s1++ = *s2++;
 *		    } while (--n != 0);
 *		}
 *		return (s);
 *	}
 *
 *
 * N1 Flow :
 *
 * if (count < 17) {
 *	Do the byte copy
 *	Return destination address
 * }
 * if (count < 128) {
 *	Is source aligned on word boundary
 *	If no then align source on word boundary then goto .ald
 *	If yes goto .ald
 *	.ald:
 *		Is destination aligned on word boundary
 *		Depending on destination offset (last 2 bits of destination)
 *		copy data by shifting and merging.
 *		Copy residue bytes as byte copy
 *		Return destination address
 * } else {
 *	Align destination on block boundary
 *	Depending on the source offset (last 4 bits of source address) align
 *	the data and store to destination. Both the load and store are done
 *	using ASI_BLK_INIT_ST_QUAD_LDD_P.
 *	For remaining count copy as much data in 8-byte chunk from source to
 *	destination.
 *	Followed by trailing copy using byte copy.
 *	Return saved destination address
 * }
 *
 *
 * N2 Flow :
 * Flow :
 *
 * if (count < 128) {
 *   if count < 3
 *	copy bytes; exit with dst addr
 *   if src & dst aligned on word boundary but not long word boundary,
 *     copy with ldw/stw; branch to finish_up
 *   if src & dst aligned on long word boundary
 *     copy with ldx/stx; branch to finish_up
 *   if src & dst not aligned and length <= 14
 *     copy bytes; exit with dst addr
 *   move enough bytes to get src to word boundary
 *   if dst now on word boundary
 * move_words:
 *     copy words; branch to finish_up
 *   if dst now on half word boundary
 *     load words, shift half words, store words; branch to finish_up
 *   if dst on byte 1
 *     load words, shift 3 bytes, store words; branch to finish_up
 *   if dst on byte 3
 *     load words, shift 1 byte, store words; branch to finish_up
 * finish_up:
 *     copy bytes; exit with dst addr
 * } else {                                         More than 128 bytes
 *   move bytes until dst is on long word boundary
 *   if( src is on long word boundary ) {
 *     if (count < 512) {
 * finish_long:				           src/dst aligned on 8 bytes
 *       copy with ldx/stx in 8-way unrolled loop;
 *       copy final 0-63 bytes; exit with dst addr
 *     } else {                                 src/dst aligned; count > 512
 *       align dst on 64 byte boundary; use 8-way test for each of 8 possible
 *       src alignments relative to a 64 byte boundary to select the
 *       16-way unrolled loop to use for
 *       block load, fmovd, block-init-store, block-store, fmovd operations
 *       then go to finish_long.
 *     }
 *   } else {                                   src/dst not aligned on 8 bytes
 *     if src is word aligned and count < 512
 *       move words in 8-way unrolled loop
 *       move final 0-31 bytes; exit with dst addr
 *     if count < 512
 *       use alignaddr/faligndata combined with ldd/std in 8-way
 *       unrolled loop to move data.
 *       go to unalign_done
 *     else
 *       setup alignaddr for faligndata instructions
 *       align dst on 64 byte boundary; use 8-way test for each of 8 possible
 *       src alignments to nearest long word relative to 64 byte boundary to
 *       select the 8-way unrolled loop to use for
 *       block load, falign, fmovd, block-init-store, block-store loop
 *	 (only use block-init-store when src/dst on 8 byte boundaries.)
 * unalign_done:
 *       move remaining bytes for unaligned cases. exit with dst addr.
 * }
 *
 * Comment on N2 memmove and memcpy common code and block-store-init:
 *   In the man page for memmove, it specifies that copying will take place
 *   correctly between objects that overlap.  For memcpy, behavior is
 *   undefined for objects that overlap.
 *
 *   In rare cases, some multi-threaded applications may attempt to examine
 *   the copy destination buffer during the copy. Using the block-store-init
 *   instruction allows those applications to observe zeros in some
 *   cache lines of the destination buffer for narrow windows. But the
 *   the block-store-init provides memory throughput advantages for many
 *   common applications. To meet both needs, those applications which need
 *   the destination buffer to retain meaning during the copy should use
 *   memmove instead of memcpy.  The memmove version duplicates the memcpy
 *   algorithms except the memmove version does not use block-store-init
 *   in those cases where memcpy does use block-store-init. Otherwise, when
 *   memmove can determine the source and destination do not overlap,
 *   memmove shares the memcpy code.
 */

#include <sys/asm_linkage.h>
#include <sys/niagaraasi.h>
#include <sys/asi.h>
#include <sys/trap.h>

/* documented name for primary block initializing store */
#define	ASI_STBI_P	ASI_BLK_INIT_ST_QUAD_LDD_P

#define	BLOCK_SIZE	64
#define	FPRS_FEF	0x4

#define	SHORTCOPY	3
#define	SHORTCHECK	14
#define	SHORT_LONG	64	/* max copy for short longword-aligned case */
				/* must be at least 32 */
#define	SMALL_MAX	128
#define	MED_UMAX	512	/* max copy for medium un-aligned case */
#define	MED_WMAX	512	/* max copy for medium word-aligned case */
#define	MED_MAX		512	/* max copy for medium longword-aligned case */

#ifdef NIAGARA2_IMPL
#include <sys/sun4asi.h>

#else	/* NIAGARA2_IMPL */
/*
 * This define is to align data for the unaligned source cases.
 * The data1, data2 and data3 is merged into data1 and data2.
 * The data3 is preserved for next merge.
 */
#define	ALIGN_DATA(data1, data2, data3, lshift, rshift, tmp)	\
	sllx	data1, lshift, data1				;\
	srlx	data2, rshift, tmp				;\
	or	data1, tmp, data1				;\
	sllx	data2, lshift, data2				;\
	srlx	data3, rshift, tmp				;\
	or	data2, tmp, data2
/*
 * Align the data. Merge the data1 and data2 into data1.
 */
#define	ALIGN_DATA_EW(data1, data2, lshift, rshift, tmp)	\
	sllx	data1, lshift, data1				;\
	srlx	data2, rshift, tmp				;\
	or	data1, tmp, data1
#endif	/* NIAGARA2_IMPL */


	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

	ENTRY(memmove)
	cmp	%o1, %o0	! if from address is >= to use forward copy
	bgeu,pn	%ncc, .forcpy	! else use backward if ...
	sub	%o0, %o1, %o4	! get difference of two addresses
	cmp	%o2, %o4	! compare size and difference of addresses
	bleu,pn	%ncc, .forcpy	! if size is bigger, do overlapped copy
	add	%o1, %o2, %o5	! get to end of source space

	!
	! an overlapped copy that must be done "backwards"
	!
.chksize:
	cmp	%o2, 8			! less than 8 byte do byte copy
	blu,pt %ncc, 2f			! else continue

	! Now size is bigger than 8
.dbalign:
	add	%o0, %o2, %g1		! get to end of dest space
	andcc	%g1, 7, %o3		! %o3 has bytes till dst 8 bytes aligned
	bz,a,pn	%ncc, .dbbck		! if dst is not 8 byte aligned: align it
	andn	%o2, 7, %o3		! %o3 count is multiple of 8 bytes size
	sub	%o2, %o3, %o2		! update o2 with new count

1:	dec	%o5			! decrement source
	ldub	[%o5], %g1		! load one byte
	deccc	%o3			! decrement count
	bgu,pt	%ncc, 1b		! if not done keep copying
	stb	%g1, [%o5+%o4]		! store one byte into dest
	andncc	%o2, 7, %o3		! %o3 count is multiple of 8 bytes size
	bz,pn	%ncc, 2f		! if size < 8, move to byte copy

	! Now Destination is 8 byte aligned
.dbbck:
	andcc	%o5, 7, %o0		! %o0 has src offset
	bz,a,pn	%ncc, .dbcopybc		! if src is aligned to fast mem move
	sub	%o2, %o3, %o2		! Residue bytes in %o2

.cpy_dbwdbc:				! alignment of src is needed
	sub	%o2, 8, %o2		! set size one loop ahead
	sll	%o0, 3, %g1		! %g1 is left shift
	mov	64, %g5			! init %g5 to be 64
	sub	%g5, %g1, %g5		! %g5 right shift = (64 - left shift)
	sub	%o5, %o0, %o5		! align the src at 8 bytes.
	add	%o4, %o0, %o4		! increase difference between src & dst
	ldx	[%o5], %o1		! load first 8 bytes
	srlx	%o1, %g5, %o1
1:	sub	%o5, 8, %o5		! subtract 8 from src
	ldx	[%o5], %o0		! load 8 byte
	sllx	%o0, %g1, %o3		! shift loaded 8 bytes left into tmp reg
	or	%o1, %o3, %o3		! align data
	stx	%o3, [%o5+%o4]		! store 8 byte
	subcc	%o2, 8, %o2		! subtract 8 byte from size
	bg,pt	%ncc, 1b		! if size > 0 continue
	srlx	%o0, %g5, %o1		! move extra byte for the next use

	srl	%g1, 3, %o0		! retsote %o0 value for alignment
	add	%o5, %o0, %o5		! restore src alignment
	sub	%o4, %o0, %o4		! restore difference between src & dest

	ba	2f			! branch to the trailing byte copy
	add	%o2, 8, %o2		! restore size value

.dbcopybc:				! alignment of src is not needed
1:	sub	%o5, 8, %o5		! subtract from src
	ldx	[%o5], %g1		! load 8 bytes
	subcc	%o3, 8, %o3		! subtract from size
	bgu,pt	%ncc, 1b		! if size is bigger 0 continue
	stx	%g1, [%o5+%o4]		! store 8 bytes to destination

	ba	2f
	nop

.bcbyte:
1:	ldub	[%o5], %g1		! load one byte
	stb	%g1, [%o5+%o4]		! store one byte
2:	deccc	%o2			! decrement size
	bgeu,a,pt %ncc, 1b		! if size is >= 0 continue
	dec	%o5			! decrement from address

.exitbc:				! exit from backward copy
	retl
	add	%o5, %o4, %o0		! restore dest addr

#ifdef NIAGARA2_IMPL
	!
	! Check to see if memmove is large aligned copy
	! If so, use special version of copy that avoids
	! use of block store init
	!
.forcpy:
	cmp	%o2, SMALL_MAX		! check for not small case
	blt,pn	%ncc, .mv_short		! merge with memcpy
	mov	%o0, %g1		! save %o0
	neg	%o0, %o5
	andcc	%o5, 7, %o5		! bytes till DST 8 byte aligned
	brz,pt	%o5, .mv_dst_aligned_on_8

	! %o5 has the bytes to be written in partial store.
	sub	%o2, %o5, %o2
	sub	%o1, %o0, %o1		! %o1 gets the difference
7:					! dst aligning loop
	ldub	[%o1+%o0], %o4		! load one byte
	subcc	%o5, 1, %o5
	stb	%o4, [%o0]
	bgu,pt	%ncc, 7b
	add	%o0, 1, %o0		! advance dst
	add	%o1, %o0, %o1		! restore %o1
.mv_dst_aligned_on_8:
	andcc	%o1, 7, %o5
	brnz,pt	%o5, .src_dst_unaligned_on_8
	prefetch [%o1 + (1 * BLOCK_SIZE)], #one_read

.mv_src_dst_aligned_on_8:
	! check if we are copying MED_MAX or more bytes
	cmp	%o2, MED_MAX		! limit to store buffer size
	bleu,pt	%ncc, .medlong
	prefetch [%o1 + (2 * BLOCK_SIZE)], #one_read

/*
 * The following memmove code mimics the memcpy code for large aligned copies,
 * but does not use the ASI_STBI_P (block initializing store) performance
 * optimization. See memmove rationale section in documentation
 */
.mv_large_align8_copy:			! Src and dst share 8 byte alignment
	rd	%fprs, %g5		! check for unused fp
	! if fprs.fef == 0, set it.
	! Setting it when already set costs more than checking
	andcc	%g5, FPRS_FEF, %g5	! test FEF, fprs.du = fprs.dl = 0
	bz,a	%ncc, 1f
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
1:
	! align dst to 64 byte boundary
	andcc	%o0, 0x3f, %o3		! %o3 == 0 means dst is 64 byte aligned
	brz,pn	%o3, .mv_aligned_on_64
	sub	%o3, 64, %o3		! %o3 has negative bytes to move
	add	%o2, %o3, %o2		! adjust remaining count
.mv_align_to_64:
	ldx	[%o1], %o4
	add	%o1, 8, %o1		! increment src ptr
	addcc	%o3, 8, %o3
	stx	%o4, [%o0]
	brnz,pt	%o3, .mv_align_to_64
	add	%o0, 8, %o0		! increment dst ptr

.mv_aligned_on_64:
	prefetch [%o1 + (3 * BLOCK_SIZE)], #one_read
	mov	%asi,%o4		! save %asi
	! Determine source alignment
	! to correct 8 byte offset
	andcc	%o1, 0x20, %o3
	brnz,pn	%o3, .mv_align_1
	mov	ASI_BLK_P, %asi		! setup %asi for block load/store
	andcc	%o1, 0x10, %o3
	brnz,pn	%o3, .mv_align_01
	nop
	andcc	%o1, 0x08, %o3
	brz,pn	%o3, .mv_align_000
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	ba	.mv_align_001
	nop
.mv_align_01:
	andcc	%o1, 0x08, %o3
	brnz,pn	%o3, .mv_align_011
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	ba	.mv_align_010
	nop
.mv_align_1:
	andcc	%o1, 0x10, %o3
	brnz,pn	%o3, .mv_align_11
	nop
	andcc	%o1, 0x08, %o3
	brnz,pn	%o3, .mv_align_101
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	ba	.mv_align_100
	nop
.mv_align_11:
	andcc	%o1, 0x08, %o3
	brz,pn	%o3, .mv_align_110
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

.mv_align_111:
! Alignment off by 8 bytes
	ldd	[%o1], %d0
	add	%o1, 8, %o1
	sub	%o2, 8, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_111_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */
	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d2
	fmovd	%d18, %d4
	fmovd	%d20, %d6
	fmovd	%d22, %d8
	fmovd	%d24, %d10
	fmovd	%d26, %d12
	fmovd	%d28, %d14
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d0

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d2
	fmovd	%d18, %d4
	fmovd	%d20, %d6
	fmovd	%d22, %d8
	fmovd	%d24, %d10
	fmovd	%d26, %d12
	fmovd	%d28, %d14
	add	%o1, 128, %o1		! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d30, %d0
	bgt,pt	%ncc, .mv_align_111_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	ba	.remain_stuff
	add	%o0, 8, %o0
	! END OF mv_align_111

.mv_align_110:
! Alignment off by 16 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	add	%o1, 16, %o1
	sub	%o2, 16, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_110_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d4
	fmovd	%d18, %d6
	fmovd	%d20, %d8
	fmovd	%d22, %d10
	fmovd	%d24, %d12
	fmovd	%d26, %d14
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d28, %d0
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d2

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d4
	fmovd	%d18, %d6
	fmovd	%d20, %d8
	fmovd	%d22, %d10
	fmovd	%d24, %d12
	fmovd	%d26, %d14
	add	%o1, 128, %o1		! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d28, %d0
	fmovd	%d30, %d2
	bgt,pt	%ncc, .mv_align_110_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	ba	.remain_stuff
	add	%o0, 16, %o0
	! END OF mv_align_110

.mv_align_101:
! Alignment off by 24 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	add	%o1, 24, %o1
	sub	%o2, 24, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_101_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d6
	fmovd	%d18, %d8
	fmovd	%d20, %d10
	fmovd	%d22, %d12
	fmovd	%d24, %d14
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d26, %d0
	fmovd	%d28, %d2
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d4

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d6
	fmovd	%d18, %d8
	fmovd	%d20, %d10
	fmovd	%d22, %d12
	fmovd	%d24, %d14
	add	%o1, 128, %o1		! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d26, %d0
	fmovd	%d28, %d2
	fmovd	%d30, %d4
	bgt,pt	%ncc, .mv_align_101_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	ba	.remain_stuff
	add	%o0, 24, %o0
	! END OF mv_align_101

.mv_align_100:
! Alignment off by 32 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16],%d4
	ldd	[%o1+24],%d6
	add	%o1, 32, %o1
	sub	%o2, 32, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_100_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */
	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d8
	fmovd	%d18, %d10
	fmovd	%d20, %d12
	fmovd	%d22, %d14
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d24, %d0
	fmovd	%d26, %d2
	fmovd	%d28, %d4
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d6

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d8
	fmovd	%d18, %d10
	fmovd	%d20, %d12
	fmovd	%d22, %d14
	add	%o1, 128, %o1		! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d24, %d0
	fmovd	%d26, %d2
	fmovd	%d28, %d4
	fmovd	%d30, %d6
	bgt,pt	%ncc, .mv_align_100_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	ba	.remain_stuff
	add	%o0, 32, %o0
	! END OF mv_align_100

.mv_align_011:
! Alignment off by 40 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	ldd	[%o1+24], %d6
	ldd	[%o1+32], %d8
	add	%o1, 40, %o1
	sub	%o2, 40, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_011_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d10
	fmovd	%d18, %d12
	fmovd	%d20, %d14
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d22, %d0
	fmovd	%d24, %d2
	fmovd	%d26, %d4
	fmovd	%d28, %d6
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d8

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d10
	fmovd	%d18, %d12
	fmovd	%d20, %d14
	add	%o1, 128, %o1		! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d22, %d0
	fmovd	%d24, %d2
	fmovd	%d26, %d4
	fmovd	%d28, %d6
	fmovd	%d30, %d8
	bgt,pt	%ncc, .mv_align_011_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	std	%d8, [%o0+32]
	ba	.remain_stuff
	add	%o0, 40, %o0
	! END OF mv_align_011

.mv_align_010:
! Alignment off by 48 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	ldd	[%o1+24], %d6
	ldd	[%o1+32], %d8
	ldd	[%o1+40], %d10
	add	%o1, 48, %o1
	sub	%o2, 48, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_010_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d12
	fmovd	%d18, %d14
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d20, %d0
	fmovd	%d22, %d2
	fmovd	%d24, %d4
	fmovd	%d26, %d6
	fmovd	%d28, %d8
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d10

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d12
	fmovd	%d18, %d14
	add	%o1, 128, %o1	! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d20, %d0
	fmovd	%d22, %d2
	fmovd	%d24, %d4
	fmovd	%d26, %d6
	fmovd	%d28, %d8
	fmovd	%d30, %d10
	bgt,pt	%ncc, .mv_align_010_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	std	%d8, [%o0+32]
	std	%d10, [%o0+40]
	ba	.remain_stuff
	add	%o0, 48, %o0
	! END OF mv_align_010

.mv_align_001:
! Alignment off by 56 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	ldd	[%o1+24], %d6
	ldd	[%o1+32], %d8
	ldd	[%o1+40], %d10
	ldd	[%o1+48], %d12
	add	%o1, 56, %o1
	sub	%o2, 56, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_001_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d14
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d18, %d0
	fmovd	%d20, %d2
	fmovd	%d22, %d4
	fmovd	%d24, %d6
	fmovd	%d26, %d8
	fmovd	%d28, %d10
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d12

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d14
	add	%o1, 128, %o1		! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d18, %d0
	fmovd	%d20, %d2
	fmovd	%d22, %d4
	fmovd	%d24, %d6
	fmovd	%d26, %d8
	fmovd	%d28, %d10
	fmovd	%d30, %d12
	bgt,pt	%ncc, .mv_align_001_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	std	%d8, [%o0+32]
	std	%d10, [%o0+40]
	std	%d12, [%o0+48]
	ba	.remain_stuff
	add	%o0, 56, %o0
	! END OF mv_align_001

.mv_align_000:
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.mv_align_000_loop:
	/* ---- copy line 1 of 2. ---- */
	subcc	%o5, 128, %o5
	ldda	[%o1]%asi,%d0
	stda	%d0,[%o0]%asi
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read

	/* ---- copy line 2 of 2. ---- */
	add	%o0, 64, %o0
	ldda	[%o1+64]%asi,%d0
	add	%o1, 128, %o1		! increment src
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! increment dst
	bgt,pt	%ncc, .mv_align_000_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	ba	.remain_stuff
	nop

	! END OF mv_align_000
#else	/* NIAGARA2_IMPL */
#endif	/* NIAGARA2_IMPL */

	SET_SIZE(memmove)

	ENTRY(memcpy)
	ENTRY(__align_cpy_1)
#ifdef NIAGARA2_IMPL
	cmp	%o2, SMALL_MAX		! check for not small case
	bgeu,pn	%ncc, .medium		! go to larger cases
	mov	%o0, %g1		! save %o0
.mv_short:
	cmp	%o2, SHORTCOPY		! check for really short case
	ble,pt	%ncc, .smallfin
	or	%o0, %o1, %o4		! prepare alignment check
	andcc	%o4, 0x3, %o5		! test for alignment
	bz,pt	%ncc, .smallword	! branch to word aligned case
	cmp	%o2, SHORTCHECK
	ble,pt	%ncc, .smallrest
	andcc	%o1, 0x3, %o5		! is src word aligned
	bz,pn	%ncc, .aldst
	cmp	%o5, 2			! is src half-word aligned
	be,pt	%ncc, .s2algn
	cmp	%o5, 3			! src is byte aligned
.s1algn:ldub	[%o1], %o3		! move 1 or 3 bytes to align it
	inc	1, %o1
	stb	%o3, [%o0]		! move a byte to align src
	inc	1, %o0
	bne,pt	%ncc, .s2algn
	dec	%o2
	b	.ald			! now go align dest
	andcc	%o0, 0x3, %o5

.s2algn:lduh	[%o1], %o3		! know src is 2 byte aligned
	inc	2, %o1
	srl	%o3, 8, %o4
	stb	%o4, [%o0]		! have to do bytes,
	stb	%o3, [%o0 + 1]		! don't know dst alignment
	inc	2, %o0
	dec	2, %o2

.aldst:	andcc	%o0, 0x3, %o5		! align the destination address
.ald:	bz,pn	%ncc, .w4cp
	cmp	%o5, 2
	be,pn	%ncc, .w2cp
	cmp	%o5, 3
.w3cp:	lduw	[%o1], %o4
	inc	4, %o1
	srl	%o4, 24, %o5
	stb	%o5, [%o0]
	bne,pt	%ncc, .w1cp
	inc	%o0
	dec	1, %o2
	andn	%o2, 3, %o3		! %o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! %o1 gets the difference

1:	sll	%o4, 8, %g5		! save residual bytes
	lduw	[%o1+%o0], %o4
	deccc	4, %o3
	srl	%o4, 24, %o5		! merge with residual
	or	%o5, %g5, %g5
	st	%g5, [%o0]
	bnz,pt	%ncc, 1b
	inc	4, %o0
	sub	%o1, 3, %o1		! used one byte of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w1cp:	srl	%o4, 8, %o5
	sth	%o5, [%o0]
	inc	2, %o0
	dec	3, %o2
	andn	%o2, 3, %o3		! %o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! %o1 gets the difference

2:	sll	%o4, 24, %g5		! save residual bytes
	lduw	[%o1+%o0], %o4
	deccc	4, %o3
	srl	%o4, 8, %o5		! merge with residual
	or	%o5, %g5, %g5
	st	%g5, [%o0]
	bnz,pt	%ncc, 2b
	inc	4, %o0
	sub	%o1, 1, %o1		! used three bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w2cp:	lduw	[%o1], %o4
	inc	4, %o1
	srl	%o4, 16, %o5
	sth	%o5, [%o0]
	inc	2, %o0
	dec	2, %o2
	andn	%o2, 3, %o3		! %o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! %o1 gets the difference

3:	sll	%o4, 16, %g5		! save residual bytes
	lduw	[%o1+%o0], %o4
	deccc	4, %o3
	srl	%o4, 16, %o5		! merge with residual
	or	%o5, %g5, %g5
	st	%g5, [%o0]
	bnz,pt	%ncc, 3b
	inc	4, %o0
	sub	%o1, 2, %o1		! used two bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w4cp:	andn	%o2, 3, %o3		! %o3 is aligned word count
	sub	%o1, %o0, %o1		! %o1 gets the difference

1:	lduw	[%o1+%o0], %o4		! read from address
	deccc	4, %o3			! decrement count
	st	%o4, [%o0]		! write at destination address
	bgu,pt	%ncc, 1b
	inc	4, %o0			! increment to address
	and	%o2, 3, %o2		! number of leftover bytes, if any

	! simple finish up byte copy, works with any alignment
7:
	add	%o1, %o0, %o1		! restore %o1
.smallrest:
	tst	%o2
	bz,pt	%ncc, .smallx
	cmp	%o2, 4
	blt,pt	%ncc, .smallleft3
	nop
	sub	%o2, 3, %o2
.smallnotalign4:
	ldub	[%o1], %o3		! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	stb	%o3, [%o0]		! write byte
	ldub	[%o1+1], %o3		! repeat for total of 4 bytes
	add	%o1, 4, %o1		! advance SRC by 4
	stb	%o3, [%o0+1]
	ldub	[%o1-2], %o3
	add	%o0, 4, %o0		! advance DST by 4
	stb	%o3, [%o0-2]
	ldub	[%o1-1], %o3
	bgu,pt	%ncc, .smallnotalign4	! loop til 3 or fewer bytes remain
	stb	%o3, [%o0-1]
	addcc	%o2, 3, %o2		! restore count
	bz,pt	%ncc, .smallx
.smallleft3:				! 1, 2, or 3 bytes remain
	subcc	%o2, 1, %o2
	ldub	[%o1], %o3		! load one byte
	bz,pt	%ncc, .smallx
	stb	%o3, [%o0]		! store one byte
	ldub	[%o1+1], %o3		! load second byte
	subcc	%o2, 1, %o2
	bz,pt	%ncc, .smallx
	stb	%o3, [%o0+1]		! store second byte
	ldub	[%o1+2], %o3		! load third byte
	stb	%o3, [%o0+2]		! store third byte
.smallx:
	retl
	mov	%g1, %o0		! restore %o0

.smallfin:
	tst	%o2
	bnz,pt	%ncc, .smallleft3
	nop
	retl
	mov	%g1, %o0		! restore %o0

	.align 16
.smallwords:
	lduw	[%o1], %o3		! read word
.smallwordx:
	subcc	%o2, 8, %o2		! update count
	stw	%o3, [%o0]		! write word
	add	%o1, 8, %o1		! update SRC
	lduw	[%o1-4], %o3		! read word
	add	%o0, 8, %o0		! update DST
	bgu,pt	%ncc, .smallwords	! loop until done
	stw	%o3, [%o0-4]		! write word
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .smallexit	! check for completion
	cmp	%o2, 4			! check for 4 or more bytes left
	blt	%ncc, .smallleft3	! if not, go to finish up
	nop
	lduw	[%o1], %o3
	add	%o1, 4, %o1
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	bnz,pt	%ncc, .smallleft3
	stw	%o3, [%o0-4]
	retl
	mov	%g1, %o0		! restore %o0

! 8 or more bytes, src and dest start on word boundary
! %o4 contains or %o0, %o1; %o3 contains first four bytes of src
.smalllong:
	andcc	%o4, 0x7, %o5		! test for long alignment
	bnz,pt	%ncc, .smallwordx	! branch to word aligned case
	cmp	%o2, SHORT_LONG-7
	bge,a	%ncc, .medl64		! if we branch
	sub	%o2,56,%o2		! adjust %o2 to -31 off count
	sub	%o1, %o0, %o1		! %o1 gets the difference
.small_long_l:
	ldx	[%o1+%o0], %o3
	subcc	%o2, 8, %o2
	add	%o0, 8, %o0
	bgu,pt	%ncc, .small_long_l	! loop until done
	stx	%o3, [%o0-8]		! write word
	add	%o1, %o0, %o1		! restore %o1
	addcc	%o2, 7, %o2		! restore %o2 to correct count
	bz,pt	%ncc, .smallexit	! check for completion
	cmp	%o2, 4			! check for 4 or more bytes left
	blt,pt	%ncc, .smallleft3	! if not, go to finish up
	nop
	lduw	[%o1], %o3
	add	%o1, 4, %o1
	subcc	%o2, 4, %o2
	stw	%o3, [%o0]
	add	%o0, 4, %o0
	bnz,pt	%ncc, .smallleft3
	nop
	retl
	mov	%g1, %o0		! restore %o0

	.align 16
! src and dest start on word boundary
.smallword:
	subcc	%o2, 7, %o2		! adjust count
	bgu,pt	%ncc, .smalllong
	lduw	[%o1], %o3		! read word
	addcc	%o2, 3, %o2		! restore count
	bz,pt	%ncc, .smallexit
	stw	%o3, [%o0]		! write word
	deccc	%o2			! reduce count for cc test
	ldub	[%o1+4], %o3		! load one byte
	bz,pt	%ncc, .smallexit
	stb	%o3, [%o0+4]		! store one byte
	ldub	[%o1+5], %o3		! load second byte
	deccc	%o2
	bz,pt	%ncc, .smallexit
	stb	%o3, [%o0+5]		! store second byte
	ldub	[%o1+6], %o3		! load third byte
	stb	%o3, [%o0+6]		! store third byte
.smallexit:
	retl
	mov	%g1, %o0		! restore %o0

	.align 16
.medium:
	neg	%o0, %o5
	andcc	%o5, 7, %o5		! bytes till DST 8 byte aligned
	brz,pt	%o5, .dst_aligned_on_8

	! %o5 has the bytes to be written in partial store.
	sub	%o2, %o5, %o2
	sub	%o1, %o0, %o1		! %o1 gets the difference
7:					! dst aligning loop
	ldub	[%o1+%o0], %o4		! load one byte
	subcc	%o5, 1, %o5
	stb	%o4, [%o0]
	bgu,pt	%ncc, 7b
	add	%o0, 1, %o0		! advance dst
	add	%o1, %o0, %o1		! restore %o1
.dst_aligned_on_8:
	andcc	%o1, 7, %o5
	brnz,pt	%o5, .src_dst_unaligned_on_8
	prefetch [%o1 + (1 * BLOCK_SIZE)], #one_read

.src_dst_aligned_on_8:
	! check if we are copying MED_MAX or more bytes
	cmp	%o2, MED_MAX		! limit to store buffer size
	bgu,pt	%ncc, .large_align8_copy
	prefetch [%o1 + (2 * BLOCK_SIZE)], #one_read
/*
 * Special case for handling when src and dest are both long word aligned
 * and total data to move is less than MED_MAX bytes
 */
.medlong:
	subcc	%o2, 63, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .medl63		! skip big loop if less than 64 bytes
.medl64:
	prefetch [%o1 + (3 * BLOCK_SIZE)], #one_read ! into the l2 cache
	ldx	[%o1], %o4		! load
	subcc	%o2, 64, %o2		! decrement length count
	stx	%o4, [%o0]		! and store
	ldx	[%o1+8], %o3		! a block of 64 bytes
	stx	%o3, [%o0+8]
	ldx	[%o1+16], %o4
	stx	%o4, [%o0+16]
	ldx	[%o1+24], %o3
	stx	%o3, [%o0+24]
	ldx	[%o1+32], %o4		! load
	stx	%o4, [%o0+32]		! and store
	ldx	[%o1+40], %o3		! a block of 64 bytes
	add	%o1, 64, %o1		! increase src ptr by 64
	stx	%o3, [%o0+40]
	ldx	[%o1-16], %o4
	add	%o0, 64, %o0		! increase dst ptr by 64
	stx	%o4, [%o0-16]
	ldx	[%o1-8], %o3
	bgu,pt	%ncc, .medl64		! repeat if at least 64 bytes left
	stx	%o3, [%o0-8]
.medl63:
	addcc	%o2, 32, %o2		! adjust remaining count
	ble,pt	%ncc, .medl31		! to skip if 31 or fewer bytes left
	nop
	ldx	[%o1], %o4		! load
	sub	%o2, 32, %o2		! decrement length count
	stx	%o4, [%o0]		! and store
	ldx	[%o1+8], %o3		! a block of 32 bytes
	add	%o1, 32, %o1		! increase src ptr by 32
	stx	%o3, [%o0+8]
	ldx	[%o1-16], %o4
	add	%o0, 32, %o0		! increase dst ptr by 32
	stx	%o4, [%o0-16]
	ldx	[%o1-8], %o3
	stx	%o3, [%o0-8]
.medl31:
	addcc	%o2, 16, %o2		! adjust remaining count
	ble,pt	%ncc, .medl15		! skip if 15 or fewer bytes left
	nop				!
	ldx	[%o1], %o4		! load and store 16 bytes
	add	%o1, 16, %o1		! increase src ptr by 16
	stx	%o4, [%o0]		!
	sub	%o2, 16, %o2		! decrease count by 16
	ldx	[%o1-8], %o3		!
	add	%o0, 16, %o0		! increase dst ptr by 16
	stx	%o3, [%o0-8]
.medl15:
	addcc	%o2, 15, %o2		! restore count
	bz,pt	%ncc, .smallexit	! exit if finished
	cmp	%o2, 8
	blt,pt	%ncc, .medw7		! skip if 7 or fewer bytes left
	tst	%o2
	ldx	[%o1], %o4		! load 8 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	add	%o0, 8, %o0		! increase dst ptr by 8
	subcc	%o2, 8, %o2		! decrease count by 8
	bnz,pt	%ncc, .medw7
	stx	%o4, [%o0-8]		! and store 8 bytes
	retl
	mov	%g1, %o0		! restore %o0

	.align 16
.src_dst_unaligned_on_8:
	! DST is 8-byte aligned, src is not
2:
	andcc	%o1, 0x3, %o5		! test word alignment
	bnz,pt	%ncc, .unalignsetup	! branch to skip if not word aligned
	prefetch [%o1 + (2 * BLOCK_SIZE)], #one_read

/*
 * Handle all cases where src and dest are aligned on word
 * boundaries. Use unrolled loops for better performance.
 * This option wins over standard large data move when
 * source and destination is in cache for medium
 * to short data moves.
 */
	cmp	%o2, MED_WMAX		! limit to store buffer size
	bge,pt	%ncc, .unalignrejoin	! otherwise rejoin main loop
	prefetch [%o1 + (3 * BLOCK_SIZE)], #one_read

	subcc	%o2, 31, %o2		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .medw31		! skip big loop if less than 16
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
.medw32:
	ld	[%o1], %o4		! move a block of 32 bytes
	stw	%o4, [%o0]
	ld	[%o1+4], %o3
	stw	%o3, [%o0+4]
	ld	[%o1+8], %o4
	stw	%o4, [%o0+8]
	ld	[%o1+12], %o3
	stw	%o3, [%o0+12]
	ld	[%o1+16], %o4
	subcc	%o2, 32, %o2		! decrement length count
	stw	%o4, [%o0+16]
	ld	[%o1+20], %o3
	add	%o1, 32, %o1		! increase src ptr by 32
	stw	%o3, [%o0+20]
	ld	[%o1-8], %o4
	add	%o0, 32, %o0		! increase dst ptr by 32
	stw	%o4, [%o0-8]
	ld	[%o1-4], %o3
	bgu,pt	%ncc, .medw32		! repeat if at least 32 bytes left
	stw	%o3, [%o0-4]
.medw31:
	addcc	%o2, 31, %o2		! restore count

	bz,pt	%ncc, .smallexit	! exit if finished
	nop
	cmp	%o2, 16
	blt,pt	%ncc, .medw15
	nop
	ld	[%o1], %o4		! move a block of 16 bytes
	subcc	%o2, 16, %o2		! decrement length count
	stw	%o4, [%o0]
	ld	[%o1+4], %o3
	add	%o1, 16, %o1		! increase src ptr by 16
	stw	%o3, [%o0+4]
	ld	[%o1-8], %o4
	add	%o0, 16, %o0		! increase dst ptr by 16
	stw	%o4, [%o0-8]
	ld	[%o1-4], %o3
	stw	%o3, [%o0-4]
.medw15:
	bz,pt	%ncc, .smallexit	! exit if finished
	cmp	%o2, 8
	blt,pt	%ncc, .medw7		! skip if 7 or fewer bytes left
	tst	%o2
	ld	[%o1], %o4		! load 4 bytes
	subcc	%o2, 8, %o2		! decrease count by 8
	stw	%o4, [%o0]		! and store 4 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	ld	[%o1-4], %o3		! load 4 bytes
	add	%o0, 8, %o0		! increase dst ptr by 8
	stw	%o3, [%o0-4]		! and store 4 bytes
	bz,pt	%ncc, .smallexit	! exit if finished
.medw7:					! count is ge 1, less than 8
	cmp	%o2, 4			! check for 4 bytes left
	blt,pt	%ncc, .smallleft3	! skip if 3 or fewer bytes left
	nop				!
	ld	[%o1], %o4		! load 4 bytes
	add	%o1, 4, %o1		! increase src ptr by 4
	add	%o0, 4, %o0		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bnz	.smallleft3
	stw	%o4, [%o0-4]		! and store 4 bytes
	retl
	mov	%g1, %o0		! restore %o0

	.align	16
.large_align8_copy:			! Src and dst share 8 byte alignment
	rd	%fprs, %g5		! check for unused fp
	! if fprs.fef == 0, set it.
	! Setting it when already set costs more than checking
	andcc	%g5, FPRS_FEF, %g5	! test FEF, fprs.du = fprs.dl = 0
	bz,a	%ncc, 1f
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
1:
	! align dst to 64 byte boundary
	andcc	%o0, 0x3f, %o3		! %o3 == 0 means dst is 64 byte aligned
	brz,pn	%o3, .aligned_to_64
	andcc	%o0, 8, %o3		! odd long words to move?
	brz,pt	%o3, .aligned_to_16
	nop
	ldx	[%o1], %o4
	sub	%o2, 8, %o2
	add	%o1, 8, %o1		! increment src ptr
	add	%o0, 8, %o0		! increment dst ptr
	stx	%o4, [%o0-8]
.aligned_to_16:
	andcc	%o0, 16, %o3		! pair of long words to move?
	brz,pt	%o3, .aligned_to_32
	nop
	ldx	[%o1], %o4
	sub	%o2, 16, %o2
	stx	%o4, [%o0]
	add	%o1, 16, %o1		! increment src ptr
	ldx	[%o1-8], %o4
	add	%o0, 16, %o0		! increment dst ptr
	stx	%o4, [%o0-8]
.aligned_to_32:
	andcc	%o0, 32, %o3		! four long words to move?
	brz,pt	%o3, .aligned_to_64
	nop
	ldx	[%o1], %o4
	sub	%o2, 32, %o2
	stx	%o4, [%o0]
	ldx	[%o1+8], %o4
	stx	%o4, [%o0+8]
	ldx	[%o1+16], %o4
	stx	%o4, [%o0+16]
	add	%o1, 32, %o1		! increment src ptr
	ldx	[%o1-8], %o4
	add	%o0, 32, %o0		! increment dst ptr
	stx	%o4, [%o0-8]
.aligned_to_64:
	prefetch [%o1 + (3 * BLOCK_SIZE)], #one_read
	mov	%asi,%o4		! save %asi
	! Determine source alignment
	! to correct 8 byte offset
	andcc	%o1, 0x20, %o3
	brnz,pn	%o3, .align_1
	mov	ASI_BLK_P, %asi		! setup %asi for block load/store
	andcc	%o1, 0x10, %o3
	brnz,pn	%o3, .align_01
	nop
	andcc	%o1, 0x08, %o3
	brz,pn	%o3, .align_000
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	ba	.align_001
	nop
.align_01:
	andcc	%o1, 0x08, %o3
	brnz,pn	%o3, .align_011
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	ba	.align_010
	nop
.align_1:
	andcc	%o1, 0x10, %o3
	brnz,pn	%o3, .align_11
	nop
	andcc	%o1, 0x08, %o3
	brnz,pn	%o3, .align_101
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	ba	.align_100
	nop
.align_11:
	andcc	%o1, 0x08, %o3
	brz,pn	%o3, .align_110
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

.align_111:
! Alignment off by 8 bytes
	ldd	[%o1], %d0
	add	%o1, 8, %o1
	sub	%o2, 8, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_111_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */
	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d2
	fmovd	%d18, %d4
	fmovd	%d20, %d6
	fmovd	%d22, %d8
	fmovd	%d24, %d10
	fmovd	%d26, %d12
	fmovd	%d28, %d14
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d0

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d2
	fmovd	%d18, %d4
	fmovd	%d20, %d6
	fmovd	%d22, %d8
	fmovd	%d24, %d10
	fmovd	%d26, %d12
	fmovd	%d28, %d14
	add	%o1, 128, %o1		! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d30, %d0
	bgt,pt	%ncc, .align_111_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	ba	.remain_stuff
	add	%o0, 8, %o0
	! END OF align_111

.align_110:
! Alignment off by 16 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	add	%o1, 16, %o1
	sub	%o2, 16, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_110_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d4
	fmovd	%d18, %d6
	fmovd	%d20, %d8
	fmovd	%d22, %d10
	fmovd	%d24, %d12
	fmovd	%d26, %d14
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d28, %d0
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d2

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d4
	fmovd	%d18, %d6
	fmovd	%d20, %d8
	fmovd	%d22, %d10
	fmovd	%d24, %d12
	fmovd	%d26, %d14
	add	%o1, 128, %o1		! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d28, %d0
	fmovd	%d30, %d2
	bgt,pt	%ncc, .align_110_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	ba	.remain_stuff
	add	%o0, 16, %o0
	! END OF align_110

.align_101:
! Alignment off by 24 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	add	%o1, 24, %o1
	sub	%o2, 24, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_101_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d6
	fmovd	%d18, %d8
	fmovd	%d20, %d10
	fmovd	%d22, %d12
	fmovd	%d24, %d14
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d26, %d0
	fmovd	%d28, %d2
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d4

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d6
	fmovd	%d18, %d8
	fmovd	%d20, %d10
	fmovd	%d22, %d12
	fmovd	%d24, %d14
	add	%o1, 128, %o1		! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d26, %d0
	fmovd	%d28, %d2
	fmovd	%d30, %d4
	bgt,pt	%ncc, .align_101_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	ba	.remain_stuff
	add	%o0, 24, %o0
	! END OF align_101

.align_100:
! Alignment off by 32 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16],%d4
	ldd	[%o1+24],%d6
	add	%o1, 32, %o1
	sub	%o2, 32, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_100_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */
	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d8
	fmovd	%d18, %d10
	fmovd	%d20, %d12
	fmovd	%d22, %d14
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d24, %d0
	fmovd	%d26, %d2
	fmovd	%d28, %d4
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d6

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d8
	fmovd	%d18, %d10
	fmovd	%d20, %d12
	fmovd	%d22, %d14
	add	%o1, 128, %o1		! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d24, %d0
	fmovd	%d26, %d2
	fmovd	%d28, %d4
	fmovd	%d30, %d6
	bgt,pt	%ncc, .align_100_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	ba	.remain_stuff
	add	%o0, 32, %o0
	! END OF align_100

.align_011:
! Alignment off by 40 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	ldd	[%o1+24], %d6
	ldd	[%o1+32], %d8
	add	%o1, 40, %o1
	sub	%o2, 40, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_011_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d10
	fmovd	%d18, %d12
	fmovd	%d20, %d14
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d22, %d0
	fmovd	%d24, %d2
	fmovd	%d26, %d4
	fmovd	%d28, %d6
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d8

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d10
	fmovd	%d18, %d12
	fmovd	%d20, %d14
	add	%o1, 128, %o1		! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d22, %d0
	fmovd	%d24, %d2
	fmovd	%d26, %d4
	fmovd	%d28, %d6
	fmovd	%d30, %d8
	bgt,pt	%ncc, .align_011_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	std	%d8, [%o0+32]
	ba	.remain_stuff
	add	%o0, 40, %o0
	! END OF align_011

.align_010:
! Alignment off by 48 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	ldd	[%o1+24], %d6
	ldd	[%o1+32], %d8
	ldd	[%o1+40], %d10
	add	%o1, 48, %o1
	sub	%o2, 48, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_010_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d12
	fmovd	%d18, %d14
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d20, %d0
	fmovd	%d22, %d2
	fmovd	%d24, %d4
	fmovd	%d26, %d6
	fmovd	%d28, %d8
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d10

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d12
	fmovd	%d18, %d14
	add	%o1, 128, %o1	! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d20, %d0
	fmovd	%d22, %d2
	fmovd	%d24, %d4
	fmovd	%d26, %d6
	fmovd	%d28, %d8
	fmovd	%d30, %d10
	bgt,pt	%ncc, .align_010_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	std	%d8, [%o0+32]
	std	%d10, [%o0+40]
	ba	.remain_stuff
	add	%o0, 48, %o0
	! END OF align_010

.align_001:
! Alignment off by 56 bytes
	ldd	[%o1], %d0
	ldd	[%o1+8], %d2
	ldd	[%o1+16], %d4
	ldd	[%o1+24], %d6
	ldd	[%o1+32], %d8
	ldd	[%o1+40], %d10
	ldd	[%o1+48], %d12
	add	%o1, 56, %o1
	sub	%o2, 56, %o2
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_001_loop:
	subcc	%o5, 128, %o5
	/* ---- copy line 1 of 2. ---- */

	ldda	[%o1]%asi,%d16		! block load
	fmovd	%d16, %d14
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d18, %d0
	fmovd	%d20, %d2
	fmovd	%d22, %d4
	fmovd	%d24, %d6
	fmovd	%d26, %d8
	fmovd	%d28, %d10
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	fmovd	%d30, %d12

	/* ---- copy line 2 of 2. ---- */
	ldda	[%o1+64]%asi,%d16
	fmovd	%d16, %d14
	add	%o1, 128, %o1		! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! advance dst
	fmovd	%d18, %d0
	fmovd	%d20, %d2
	fmovd	%d22, %d4
	fmovd	%d24, %d6
	fmovd	%d26, %d8
	fmovd	%d28, %d10
	fmovd	%d30, %d12
	bgt,pt	%ncc, .align_001_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	std	%d0, [%o0]
	std	%d2, [%o0+8]
	std	%d4, [%o0+16]
	std	%d6, [%o0+24]
	std	%d8, [%o0+32]
	std	%d10, [%o0+40]
	std	%d12, [%o0+48]
	ba	.remain_stuff
	add	%o0, 56, %o0
	! END OF align_001

.align_000:
	andn	%o2, 0x7f, %o5		! %o5 is multiple of 2*block size
	and	%o2, 0x7f, %o2		! residue bytes in %o2
.align_000_loop:
	/* ---- copy line 1 of 2. ---- */
	subcc	%o5, 128, %o5
	ldda	[%o1]%asi,%d0
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read

	/* ---- copy line 2 of 2. ---- */
	add	%o0, 64, %o0
	ldda	[%o1+64]%asi,%d0
	add	%o1, 128, %o1		! increment src
	stxa	%g0,[%o0]ASI_STBI_P	! block initializing store
	stda	%d0,[%o0]%asi
	add	%o0, 64, %o0		! increment dst
	bgt,pt	%ncc, .align_000_loop
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read

	! END OF align_000

.remain_stuff:
	mov	%o4, %asi		! restore %asi
	brnz	%g5, .medlong
	membar	#Sync
	ba	.medlong
	wr	%g5, %g0, %fprs

	.align 16
	! Dst is on 8 byte boundary; src is not; remaining count > SMALL_MAX
.unalignsetup:
	prefetch [%o1 + (3 * BLOCK_SIZE)], #one_read
.unalignrejoin:
	rd	%fprs, %g5		! check for unused fp
	! if fprs.fef == 0, set it.
	! Setting it when already set costs more than checking
	andcc	%g5, FPRS_FEF, %g5	! test FEF, fprs.du = fprs.dl = 0
	bz,a	%ncc, 1f
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
1:
	cmp	%o2, MED_UMAX		! check for medium unaligned limit
	bge,pt	%ncc,.unalign_large
	nop
	andn	%o2, 0x3f, %o5		! %o5 is multiple of block size
	and	%o2, 0x3f, %o2		! residue bytes in %o2
	cmp	%o2, 8			! Insure we don't load beyond
	bgt	.unalign_adjust		! end of source buffer
	andn	%o1, 0x7, %o4		! %o4 has long word aligned src address
	add	%o2, 64, %o2		! adjust to leave loop
	sub	%o5, 64, %o5		! early if necessary
.unalign_adjust:
	alignaddr %o1, %g0, %g0		! generate %gsr
	add	%o1, %o5, %o1		! advance %o1 to after blocks
	ldd	[%o4], %d0
.unalign_loop:
	ldd	[%o4+8], %d2
	faligndata %d0, %d2, %d16
	ldd	[%o4+16], %d4
	std	%d16, [%o0]
	faligndata %d2, %d4, %d18
	ldd	[%o4+24], %d6
	std	%d18, [%o0+8]
	faligndata %d4, %d6, %d20
	ldd	[%o4+32], %d8
	std	%d20, [%o0+16]
	faligndata %d6, %d8, %d22
	ldd	[%o4+40], %d10
	std	%d22, [%o0+24]
	faligndata %d8, %d10, %d24
	ldd	[%o4+48], %d12
	std	%d24, [%o0+32]
	faligndata %d10, %d12, %d26
	ldd	[%o4+56], %d14
	std	%d26, [%o0+40]
	faligndata %d12, %d14, %d28
	ldd	[%o4+64], %d0
	std	%d28, [%o0+48]
	faligndata %d14, %d0, %d30
	add	%o4, BLOCK_SIZE, %o4
	std	%d30, [%o0+56]
	add	%o0, BLOCK_SIZE, %o0
	subcc	%o5, BLOCK_SIZE, %o5
	bgu,pt	%ncc, .unalign_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	nop

.unalign_large:
	andcc	%o0, 0x3f, %o3		! is dst 64-byte block aligned?
	bz	%ncc, .unalignsrc
	sub	%o3, 64, %o3		! %o3 will be multiple of 8
	neg	%o3			! bytes until dest is 64 byte aligned
	sub	%o2, %o3, %o2		! update cnt with bytes to be moved
	! Move bytes according to source alignment
	andcc	%o1, 0x1, %o5
	bnz	%ncc, .unalignbyte	! check for byte alignment
	nop
	andcc	%o1, 2, %o5		! check for half word alignment
	bnz	%ncc, .unalignhalf
	nop
	! Src is word aligned
.unalignword:
	ld	[%o1], %o4		! load 4 bytes
	stw	%o4, [%o0]		! and store 4 bytes
	ld	[%o1+4], %o4		! load 4 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	stw	%o4, [%o0+4]		! and store 4 bytes
	subcc	%o3, 8, %o3		! decrease count by 8
	bnz	%ncc, .unalignword
	add	%o0, 8, %o0		! increase dst ptr by 8
	ba	.unalignsrc
	nop

	! Src is half-word aligned
.unalignhalf:
	lduh	[%o1], %o4		! load 2 bytes
	sllx	%o4, 32, %o5		! shift left
	lduw	[%o1+2], %o4
	or	%o4, %o5, %o5
	sllx	%o5, 16, %o5
	lduh	[%o1+6], %o4
	or	%o4, %o5, %o5
	stx	%o5, [%o0]
	add	%o1, 8, %o1
	subcc	%o3, 8, %o3
	bnz	%ncc, .unalignhalf
	add	%o0, 8, %o0
	ba	.unalignsrc
	nop

	! Src is Byte aligned
.unalignbyte:
	sub	%o0, %o1, %o0		! share pointer advance
.unalignbyte_loop:
	ldub	[%o1], %o4
	sllx	%o4, 56, %o5
	lduh	[%o1+1], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o5, %o5
	lduh	[%o1+3], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o5, %o5
	lduh	[%o1+5], %o4
	sllx	%o4,  8, %o4
	or	%o4, %o5, %o5
	ldub	[%o1+7], %o4
	or	%o4, %o5, %o5
	stx	%o5, [%o0+%o1]
	subcc	%o3, 8, %o3
	bnz	%ncc, .unalignbyte_loop
	add	%o1, 8, %o1
	add	%o0,%o1, %o0 		! restore pointer

	! Destination is now block (64 byte aligned)
.unalignsrc:
	andn	%o2, 0x3f, %o5		! %o5 is multiple of block size
	and	%o2, 0x3f, %o2		! residue bytes in %o2
	add	%o2, 64, %o2		! Insure we don't load beyond
	sub	%o5, 64, %o5		! end of source buffer

	andn	%o1, 0x3f, %o4		! %o4 has block aligned src address
	prefetch [%o4 + (3 * BLOCK_SIZE)], #one_read
	alignaddr %o1, %g0, %g0		! generate %gsr
	add	%o1, %o5, %o1		! advance %o1 to after blocks
	!
	! Determine source alignment to correct 8 byte offset
	andcc	%o1, 0x20, %o3
	brnz,pn	%o3, .unalign_1
	nop
	andcc	%o1, 0x10, %o3
	brnz,pn	%o3, .unalign_01
	nop
	andcc	%o1, 0x08, %o3
	brz,a	%o3, .unalign_000
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_001
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
.unalign_01:
	andcc	%o1, 0x08, %o3
	brnz,a	%o3, .unalign_011
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_010
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
.unalign_1:
	andcc	%o1, 0x10, %o3
	brnz,pn	%o3, .unalign_11
	nop
	andcc	%o1, 0x08, %o3
	brnz,a	%o3, .unalign_101
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_100
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
.unalign_11:
	andcc	%o1, 0x08, %o3
	brz,pn	%o3, .unalign_110
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read

.unalign_111:
	ldd	[%o4+56], %d14
.unalign_111_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d14, %d16, %d48
	faligndata %d16, %d18, %d50
	faligndata %d18, %d20, %d52
	faligndata %d20, %d22, %d54
	faligndata %d22, %d24, %d56
	faligndata %d24, %d26, %d58
	faligndata %d26, %d28, %d60
	faligndata %d28, %d30, %d62
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_111_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	membar	#Sync

.unalign_110:
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.unalign_110_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d12, %d14, %d48
	faligndata %d14, %d16, %d50
	faligndata %d16, %d18, %d52
	faligndata %d18, %d20, %d54
	faligndata %d20, %d22, %d56
	faligndata %d22, %d24, %d58
	faligndata %d24, %d26, %d60
	faligndata %d26, %d28, %d62
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_110_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	membar	#Sync

.unalign_101:
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.unalign_101_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d10, %d12, %d48
	faligndata %d12, %d14, %d50
	faligndata %d14, %d16, %d52
	faligndata %d16, %d18, %d54
	faligndata %d18, %d20, %d56
	faligndata %d20, %d22, %d58
	faligndata %d22, %d24, %d60
	faligndata %d24, %d26, %d62
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_101_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	membar	#Sync

.unalign_100:
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.unalign_100_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d8, %d10, %d48
	faligndata %d10, %d12, %d50
	faligndata %d12, %d14, %d52
	faligndata %d14, %d16, %d54
	faligndata %d16, %d18, %d56
	faligndata %d18, %d20, %d58
	faligndata %d20, %d22, %d60
	faligndata %d22, %d24, %d62
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_100_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	membar	#Sync

.unalign_011:
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.unalign_011_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d6, %d8, %d48
	faligndata %d8, %d10, %d50
	faligndata %d10, %d12, %d52
	faligndata %d12, %d14, %d54
	faligndata %d14, %d16, %d56
	faligndata %d16, %d18, %d58
	faligndata %d18, %d20, %d60
	faligndata %d20, %d22, %d62
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_011_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	membar	#Sync

.unalign_010:
	ldd	[%o4+16], %d4
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.unalign_010_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d4, %d6, %d48
	faligndata %d6, %d8, %d50
	faligndata %d8, %d10, %d52
	faligndata %d10, %d12, %d54
	faligndata %d12, %d14, %d56
	faligndata %d14, %d16, %d58
	faligndata %d16, %d18, %d60
	faligndata %d18, %d20, %d62
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_010_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	membar	#Sync

.unalign_001:
	ldd	[%o4+8], %d2
	ldd	[%o4+16], %d4
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.unalign_001_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d2, %d4, %d48
	faligndata %d4, %d6, %d50
	faligndata %d6, %d8, %d52
	faligndata %d8, %d10, %d54
	faligndata %d10, %d12, %d56
	faligndata %d12, %d14, %d58
	faligndata %d14, %d16, %d60
	faligndata %d16, %d18, %d62
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_001_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	ba	.unalign_done
	membar	#Sync

.unalign_000:
	ldda	[%o4]ASI_BLK_P, %d0
.unalign_000_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d0, %d2, %d48
	faligndata %d2, %d4, %d50
	faligndata %d4, %d6, %d52
	faligndata %d6, %d8, %d54
	faligndata %d8, %d10, %d56
	faligndata %d10, %d12, %d58
	faligndata %d12, %d14, %d60
	faligndata %d14, %d16, %d62
	fmovd	%d16, %d0
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%o0]ASI_BLK_P
	subcc	%o5, 64, %o5
	add	%o0, 64, %o0
	bgu,pt	%ncc, .unalign_000_loop
	prefetch [%o4 + (4 * BLOCK_SIZE)], #one_read
	membar	#Sync

.unalign_done:
	! Handle trailing bytes, 64 to 127
	! Dest long word aligned, Src not long word aligned
	cmp	%o2, 15
	bleu	%ncc, .unalign_short

	andn	%o2, 0x7, %o5		! %o5 is multiple of 8
	and	%o2, 0x7, %o2		! residue bytes in %o2
	add	%o2, 8, %o2
	sub	%o5, 8, %o5		! insure we don't load past end of src
	andn	%o1, 0x7, %o4		! %o4 has long word aligned src address
	add	%o1, %o5, %o1		! advance %o1 to after multiple of 8
	ldd	[%o4], %d0		! fetch partial word
.unalign_by8:
	ldd	[%o4+8], %d2
	add	%o4, 8, %o4
	faligndata %d0, %d2, %d16
	subcc	%o5, 8, %o5
	std	%d16, [%o0]
	fmovd	%d2, %d0
	bgu,pt	%ncc, .unalign_by8
	add	%o0, 8, %o0

.unalign_short:
	brnz	%g5, .smallrest
	nop
	ba	.smallrest
	wr	%g5, %g0, %fprs
#else	/* NIAGARA2_IMPL */
.forcpy:
	mov	%o0, %g5		! save des address for return val
	cmp	%o2, 17			! for small counts copy bytes
	bleu,pt	%ncc, .dbytecp
	nop

	cmp	%o2, 0x80		! For lengths less than 128 bytes no
	bleu,pn	%ncc, .no_blkcpy	! copy using ASI_BLK_INIT_ST_QUAD_LDD_P

	/*
	 * Make sure that source and destination buffers are 64 bytes apart.
	 * If they are not, do not use ASI_BLK_INIT_ST_QUAD_LDD_P asi to copy
	 * the data.
	 */
	subcc	%o1, %o0, %o3
	blu	%ncc, .blkalgndst
	cmp	%o3, 0x40		! if src - dst >= 0x40
	bgeu,pt	%ncc, .blkalgndst	! then use ASI_BLK_INIT_ST_QUAD_LDD_P
.no_blkcpy:
	andcc	%o1, 3, %o5		! is src word aligned
	bz,pn	%ncc, .aldst
	cmp	%o5, 2			! is src half-word aligned
	be,pt	%ncc, .s2algn
	cmp	%o5, 3			! src is byte aligned
.s1algn:ldub	[%o1], %o3		! move 1 or 3 bytes to align it
	inc	1, %o1
	stb	%o3, [%g5]		! move a byte to align src
	inc	1, %g5
	bne,pt	%ncc, .s2algn
	dec	%o2
	b	.ald			! now go align dest
	andcc	%g5, 3, %o5

.s2algn:lduh	[%o1], %o3		! know src is 2 byte alinged
	inc	2, %o1
	srl	%o3, 8, %o4
	stb	%o4, [%g5]		! have to do bytes,
	stb	%o3, [%g5 + 1]		! don't know dst alingment
	inc	2, %g5
	dec	2, %o2

.aldst:	andcc	%g5, 3, %o5		! align the destination address
.ald:	bz,pn	%ncc, .w4cp
	cmp	%o5, 2
	bz,pn	%ncc, .w2cp
	cmp	%o5, 3
.w3cp:	lduw	[%o1], %o4
	inc	4, %o1
	srl	%o4, 24, %o5
	stb	%o5, [%g5]
	bne,pt	%ncc, .w1cp
	inc	%g5
	dec	1, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %g5, %o1		! o1 gets the difference

1:	sll	%o4, 8, %g1		! save residual bytes
	lduw	[%o1+%g5], %o4
	deccc	4, %o3
	srl	%o4, 24, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%g5]
	bnz,pt	%ncc, 1b
	inc	4, %g5
	sub	%o1, 3, %o1		! used one byte of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w1cp:	srl	%o4, 8, %o5
	sth	%o5, [%g5]
	inc	2, %g5
	dec	3, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %g5, %o1		! o1 gets the difference

2:	sll	%o4, 24, %g1		! save residual bytes
	lduw	[%o1+%g5], %o4
	deccc	4, %o3
	srl	%o4, 8, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%g5]
	bnz,pt	%ncc, 2b
	inc	4, %g5
	sub	%o1, 1, %o1		! used three bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w2cp:	lduw	[%o1], %o4
	inc	4, %o1
	srl	%o4, 16, %o5
	sth	%o5, [%g5]
	inc	2, %g5
	dec	2, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %g5, %o1		! o1 gets the difference

3:	sll	%o4, 16, %g1		! save residual bytes
	lduw	[%o1+%g5], %o4
	deccc	4, %o3
	srl	%o4, 16, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%g5]
	bnz,pt	%ncc, 3b
	inc	4, %g5
	sub	%o1, 2, %o1		! used two bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w4cp:	andn	%o2, 3, %o3		! o3 is aligned word count
	sub	%o1, %g5, %o1		! o1 gets the difference

1:	lduw	[%o1+%g5], %o4		! read from address
	deccc	4, %o3			! decrement count
	st	%o4, [%g5]		! write at destination address
	bgu,pt	%ncc, 1b
	inc	4, %g5			! increment to address
	b	7f
	and	%o2, 3, %o2		! number of leftover bytes, if any

	!
	! differenced byte copy, works with any alignment
	!
.dbytecp:
	b	7f
	sub	%o1, %g5, %o1		! o1 gets the difference

4:	stb	%o4, [%g5]		! write to address
	inc	%g5			! inc to address
7:	deccc	%o2			! decrement count
	bgeu,a,pt %ncc,4b		! loop till done
	ldub	[%o1+%g5], %o4		! read from address
	retl				! %o0 was preserved
	nop

.blkalgndst:
	save	%sp, -SA(MINFRAME), %sp

	! Block (64 bytes) align the destination.
	andcc	%i0, 0x3f, %i3		! is dst block aligned
	bz	%ncc, .chksrc		! dst already block aligned
	sub	%i3, 0x40, %i3
	neg	%i3			! bytes till dst 64 bytes aligned
	sub	%i2, %i3, %i2		! update i2 with new count

	! Based on source and destination alignment do
	! either 8 bytes, 4 bytes, 2 bytes or byte copy.

	! Is dst & src 8B aligned
	or	%i0, %i1, %o2
	andcc	%o2, 0x7, %g0
	bz	%ncc, .alewdcp
	nop

	! Is dst & src 4B aligned
	andcc	%o2, 0x3, %g0
	bz	%ncc, .alwdcp
	nop

	! Is dst & src 2B aligned
	andcc	%o2, 0x1, %g0
	bz	%ncc, .alhlfwdcp
	nop

	! 1B aligned
1:	ldub	[%i1], %o2
	stb	%o2, [%i0]
	inc	%i1
	deccc	%i3
	bgu,pt	%ncc, 1b
	inc	%i0

	ba	.chksrc
	nop

	! dst & src 4B aligned
.alwdcp:
	ld	[%i1], %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	subcc	%i3, 0x4, %i3
	bgu,pt	%ncc, .alwdcp
	add	%i0, 0x4, %i0

	ba	.chksrc
	nop

	! dst & src 2B aligned
.alhlfwdcp:
	lduh	[%i1], %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	subcc	%i3, 0x2, %i3
	bgu,pt	%ncc, .alhlfwdcp
	add	%i0, 0x2, %i0

	ba	.chksrc
	nop

	! dst & src 8B aligned
.alewdcp:
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, .alewdcp
	add	%i0, 0x8, %i0

	! Now Destination is block (64 bytes) aligned
.chksrc:
	andn	%i2, 0x3f, %i3		! %i3 count is multiple of block size
	sub	%i2, %i3, %i2		! Residue bytes in %i2
	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi
	andcc	%i1, 0xf, %l1		! is src quadword aligned
	bz,pn	%ncc, .blkcpy		! src offset in %l1
	nop
	cmp	%l1, 0x8
	bgu	%ncc, .cpy_upper_double
	nop
	blu	%ncc, .cpy_lower_double
	nop

	! Falls through when source offset is equal to 8 i.e.
	! source is double word aligned.
	! In this case no shift/merge of data is required
	sub	%i1, %l1, %i1		! align the src at 16 bytes.
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %o2
loop0:
	ldda	[%i1+0x10]%asi, %o4
	prefetch [%o0+0x40], #one_read

	stxa	%o3, [%i0+0x0]%asi
	stxa	%o4, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %o2
	stxa	%o5, [%i0+0x10]%asi
	stxa	%o2, [%i0+0x18]%asi

	ldda	[%i1+0x30]%asi, %o4
	stxa	%o3, [%i0+0x20]%asi
	stxa	%o4, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %o2
	stxa	%o5, [%i0+0x30]%asi
	stxa	%o2, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, loop0
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %l1, %i1		! increment the source by src offset

.cpy_lower_double:
	sub	%i1, %l1, %i1		! align the src at 16 bytes.
	sll	%l1, 3, %l2		! %l2 left shift
	mov	0x40, %l3
	sub	%l3, %l2, %l3		! %l3 right shift = (64 - left shift)
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %o2	! partial data in %o2 and %o3 has
					! complete data
loop1:
	ldda	[%i1+0x10]%asi, %o4	! %o4 has partial data for this read.
	ALIGN_DATA(%o2, %o3, %o4, %l2, %l3, %g1)	! merge %o2, %o3 and %o4
							! into %o2 and %o3
	prefetch [%o0+0x40], #one_read
	stxa	%o2, [%i0+0x0]%asi
	stxa	%o3, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %o2
	ALIGN_DATA(%o4, %o5, %o2, %l2, %l3, %g1)	! merge %o2 with %o5 and
	stxa	%o4, [%i0+0x10]%asi			! %o4 from previous read
	stxa	%o5, [%i0+0x18]%asi			! into %o4 and %o5

	! Repeat the same for next 32 bytes.

	ldda	[%i1+0x30]%asi, %o4
	ALIGN_DATA(%o2, %o3, %o4, %l2, %l3, %g1)
	stxa	%o2, [%i0+0x20]%asi
	stxa	%o3, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %o2
	ALIGN_DATA(%o4, %o5, %o2, %l2, %l3, %g1)
	stxa	%o4, [%i0+0x30]%asi
	stxa	%o5, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, loop1
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %l1, %i1		! increment the source by src offset

.cpy_upper_double:
	sub	%i1, %l1, %i1		! align the src at 16 bytes.
	mov	0x8, %l2
	sub	%l1, %l2, %l2
	sll	%l2, 3, %l2		! %l2 left shift
	mov	0x40, %l3
	sub	%l3, %l2, %l3		! %l3 right shift = (64 - left shift)
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %o2	! partial data in %o3 for this read and
					! no data in %o2
loop2:
	ldda	[%i1+0x10]%asi, %o4	! %o4 has complete data and %o5 has
					! partial
	ALIGN_DATA(%o3, %o4, %o5, %l2, %l3, %g1)	! merge %o3, %o4 and %o5
							! into %o3 and %o4
	prefetch [%o0+0x40], #one_read
	stxa	%o3, [%i0+0x0]%asi
	stxa	%o4, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %o2
	ALIGN_DATA(%o5, %o2, %o3, %l2, %l3, %g1)	! merge %o2 and %o3 with
	stxa	%o5, [%i0+0x10]%asi			! %o5 from previous read
	stxa	%o2, [%i0+0x18]%asi			! into %o5 and %o2

	! Repeat the same for next 32 bytes.

	ldda	[%i1+0x30]%asi, %o4
	ALIGN_DATA(%o3, %o4, %o5, %l2, %l3, %g1)
	stxa	%o3, [%i0+0x20]%asi
	stxa	%o4, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %o2
	ALIGN_DATA(%o5, %o2, %o3, %l2, %l3, %g1)
	stxa	%o5, [%i0+0x30]%asi
	stxa	%o2, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, loop2
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %l1, %i1		! increment the source by src offset

	! Do fast copy using ASI_BLK_INIT_ST_QUAD_LDD_P
.blkcpy:
	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
1:
	prefetch [%o0+0x40], #one_read

	ldda	[%i1+0x0]%asi, %o2
	ldda	[%i1+0x10]%asi, %o4

	stxa	%o2, [%i0+0x0]%asi
	stxa	%o3, [%i0+0x8]%asi
	stxa	%o4, [%i0+0x10]%asi
	stxa	%o5, [%i0+0x18]%asi

	ldda	[%i1+0x20]%asi, %o2
	ldda	[%i1+0x30]%asi, %o4

	stxa	%o2, [%i0+0x20]%asi
	stxa	%o3, [%i0+0x28]%asi
	stxa	%o4, [%i0+0x30]%asi
	stxa	%o5, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%ncc, 1b
	add	%i0, 0x40, %i0

.blkdone:
	membar	#Sync

	mov	ASI_PNF, %asi		! restore %asi to default
					! ASI_PRIMARY_NOFAULT value
	tst	%i2
	bz,pt	%ncc, .blkexit
	nop

	! Handle trailing bytes
	cmp	%i2, 0x8
	blu,pt	%ncc, .residue
	nop

	! Can we do some 8B ops
	or	%i1, %i0, %o2
	andcc	%o2, 0x7, %g0
	bnz	%ncc, .last4
	nop

	! Do 8byte ops as long as possible
.last8:
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	sub	%i2, 0x8, %i2
	cmp	%i2, 0x8
	bgu,pt	%ncc, .last8
	add	%i0, 0x8, %i0

	tst	%i2
	bz,pt	%ncc, .blkexit
	nop

	ba	.residue
	nop

.last4:
	! Can we do 4B ops
	andcc	%o2, 0x3, %g0
	bnz	%ncc, .last2
	nop
1:
	ld	[%i1], %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	sub	%i2, 0x4, %i2
	cmp	%i2, 0x4
	bgu,pt	%ncc, 1b
	add	%i0, 0x4, %i0

	cmp	%i2, 0
	bz,pt	%ncc, .blkexit
	nop

	ba	.residue
	nop

.last2:
	! Can we do 2B ops
	andcc	%o2, 0x1, %g0
	bnz	%ncc, .residue
	nop

1:
	lduh	[%i1], %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	sub	%i2, 0x2, %i2
	cmp	%i2, 0x2
	bgu,pt	%ncc, 1b
	add	%i0, 0x2, %i0

	cmp	%i2, 0
	bz,pt	%ncc, .blkexit
	nop

.residue:
	ldub	[%i1], %o2
	stb	%o2, [%i0]
	inc	%i1
	deccc	%i2
	bgu,pt	%ncc, .residue
	inc	%i0

.blkexit:

	ret
	restore	%g5, %g0, %o0

#endif	/* NIAGARA2_IMPL */
	SET_SIZE(memcpy)
	SET_SIZE(__align_cpy_1)
