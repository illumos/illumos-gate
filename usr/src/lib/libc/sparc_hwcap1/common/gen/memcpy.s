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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
 *	   	    char *s1 = s;
 *		    const char *s2 = s0;
 *		    do {
 *			*s1++ = *s2++;
 *		    } while (--n != 0);
 *		}
 *		return (s);
 *	}
 */

#include <sys/asm_linkage.h>
#include <sys/sun4asi.h>
#include <sys/trap.h>

#ifdef	__sparcv9
#define	SAVESIZE	(8 * 1)
#define	STACK_OFFSET	(STACK_BIAS + MINFRAME)
#else
#define	SAVESIZE	(8 * 3)
#define	STACK_OFFSET	(STACK_BIAS + MINFRAME + 4)
#endif

#define	scratch_offset	0
#define	g4_offset	8
#define	g5_offset	16

#define	ICACHE_LINE_SIZE	64
#define	BLOCK_SIZE	64
#define	FPRS_FEF	0x4
#define	PF_FAR		2048
#define	PF_NEAR		1024

#define SHORTCOPY	3
#define	SMALL_MAX	39
#define	MEDIUM_MAX	255
#define MED_WMAX	256	/* max copy for medium word-aligned case */
#define MED_MAX		256	/* max copy for medium longword-aligned case */

#ifndef BSTORE_SIZE
#define BSTORE_SIZE	256	/* min copy size for block store */
#endif

/*
 * The LDDs will use the below ASI for performance
 * This ASI minimizes cache pollution.
 */
#define	ASI_CACHE_SPARING	0xf4
#define	ASI_CACHE_SPARING_PRIMARY	0xf4

	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

	ENTRY(memmove)
	cmp	%o1, %o0	! if from address is >= to use forward copy
	bgeu	%ncc, .forcpy	! else use backward if ...
	sub	%o0, %o1, %o4	! get difference of two addresses
	cmp	%o2, %o4	! compare size and difference of addresses
	bleu	%ncc, .forcpy	! if size is bigger, do overlapped copy
	nop

	!
	! an overlapped copy that must be done "backwards"
	!
.ovbc:
	mov	%o0, %g1		! save dest address for return val
	add     %o1, %o2, %o1	   ! get to end of source space
	add     %o0, %o2, %o0	   ! get to end of destination space

	cmp	%o2, 24
	bgeu,pn	%ncc, .dbalign
	nop
	cmp	%o2, 4
	blt,pn	%ncc, .byte
	sub	%o2, 3, %o2
.byte4loop:
	ldub	[%o1-1], %o3		! load last byte
	stb	%o3, [%o0-1]		! store last byte
	sub	%o1, 4, %o1
	ldub	[%o1+2], %o3		! load 2nd from last byte
	stb	%o3, [%o0-2]		! store 2nd from last byte
	sub	%o0, 4, %o0
	ldub	[%o1+1], %o3		! load 3rd from last byte
	stb	%o3, [%o0+1]		! store 3rd from last byte
	subcc	%o2, 4, %o2
	ldub	[%o1], %o3		! load 4th from last byte
	bgu,pt	%ncc, .byte4loop
	stb	%o3, [%o0]		! store 4th from last byte
.byte:
	addcc	%o2, 3, %o2
	bz,pt	%ncc, .exit
.byteloop:
	dec	%o1			! decrement src address
	ldub	[%o1], %o3		! read a byte
	dec	%o0			! decrement dst address
	deccc	%o2			! decrement count
	bgu,pt	%ncc, .byteloop		! loop until done
	stb	%o3, [%o0]		! write byte
.exit:
	retl
	mov	%g1, %o0

	.align	16
.dbalign:
	andcc   %o0, 7, %o5		! bytes till DST 8 byte aligned
	bz,pt	%ncc, .dbmed
	sub	%o2, %o5, %o2		! update count
.dbalign1:
	dec	%o1			! decrement src address
	ldub	[%o1], %o3		! read a byte
	dec	%o0			! decrement dst address
	deccc	%o5			! decrement count
	bgu,pt	%ncc, .dbalign1		! loop until done
	stb	%o3, [%o0]		! store a byte

! check for src long word alignment
.dbmed:
	mov	%asi, %g5		! save curr %asi
	wr	%g0, ASI_CACHE_SPARING, %asi
	andcc	%o1, 7, %g0		! chk src long word alignment
	bnz,pn	%ncc, .dbbck
	nop
!
! Following code is for overlapping copies where src and dest
! are long word aligned
!
	cmp	%o2, 4095
	blt,pn	%ncc, .dbmedl32enter	! go to no prefetch code
	nop
	prefetch [%o1 - (1 * BLOCK_SIZE)], #n_reads
	sub	%o2, 63, %o2		! adjust length to allow cc test
					! for end of loop
	prefetch [%o1 - (2 * BLOCK_SIZE)], #n_reads
	prefetch [%o1 - (3 * BLOCK_SIZE)], #n_reads
	prefetch [%o1 - (4 * BLOCK_SIZE)], #n_reads
.dbmedl64:
	prefetch [%o1 - (5 * BLOCK_SIZE)], #n_reads
	ldxa	[%o1-8]%asi, %o3	! load
	subcc	%o2, 64, %o2		! decrement length count
	stx	%o3, [%o0-8]		! and store
	ldxa	[%o1-16]%asi, %o3	! a block of 64 bytes
	sub	%o1, 64, %o1		! decrease src ptr by 64
	stx	%o3, [%o0-16]
	sub	%o0, 64, %o0		! decrease dst ptr by 64
	ldxa	[%o1+40]%asi, %o3
	ldxa	[%o1+32]%asi, %o4
	ldxa	[%o1+24]%asi, %o5
	stx	%o3, [%o0+40]
	stx	%o4, [%o0+32]
	stx	%o5, [%o0+24]
	ldxa	[%o1+16]%asi, %o3
	ldxa	[%o1+8]%asi, %o4
	stx	%o3, [%o0+16]
	stx	%o4, [%o0+8]
	ldxa	[%o1]%asi, %o5
	bgu,pt	%ncc, .dbmedl64		! repeat if at least 64 bytes left
	stx	%o5, [%o0]
	add	%o2, 63, %o2		! restore offset adjustment
.dbmedl32enter:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
					! for end of loop
	ble,pt  %ncc, .dbmedl31		! skip big loop if less than 32
	nop
.dbmedl32:
	ldx	[%o1-8], %o4		! load
	subcc	%o2, 32, %o2		! decrement length count
	stx	%o4, [%o0-8]		! and store
	ldx	[%o1-16], %o3		! a block of 32 bytes
	sub	%o1, 32, %o1		! decrease src ptr by 32
	stx	%o3, [%o0-16]
	ldx	[%o1+8], %o4
	sub	%o0, 32, %o0		! decrease dst ptr by 32
	stx	%o4, [%o0+8]
	ldx	[%o1], %o3
	bgu,pt	%ncc, .dbmedl32		! repeat if at least 32 bytes left
	stx	%o3, [%o0]
.dbmedl31:
	addcc	%o2, 16, %o2		! adjust remaining count
	ble,pt	%ncc, .dbmedl15		! skip if 15 or fewer bytes left
	nop				!
	ldx	[%o1-8], %o4		! load and store 16 bytes
	sub	%o1, 16, %o1		! decrease src ptr by 16
	stx	%o4, [%o0-8]		!
	sub	%o2, 16, %o2		! decrease count by 16
	ldx	[%o1], %o3		!
	sub	%o0, 16, %o0		! decrease dst ptr by 16
	stx	%o3, [%o0]
.dbmedl15:
	addcc	%o2, 15, %o2		! restore count
	bz,pt	%ncc, .dbexit		! exit if finished
	nop
	cmp	%o2, 8
	blt,pt	%ncc, .dbremain		! skip if 7 or fewer bytes left
	nop
	ldx	[%o1-8], %o4		! load 8 bytes
	sub	%o1, 8, %o1		! decrease src ptr by 8
	stx	%o4, [%o0-8]		! and store 8 bytes
	subcc	%o2, 8, %o2		! decrease count by 8
	bnz	%ncc, .dbremain		! exit if finished
	sub	%o0, 8, %o0		! decrease dst ptr by 8
	mov	%g5, %asi		! restore %asi
	retl
	mov	%g1, %o0

!
! Following code is for overlapping copies where src and dest
! are not long word aligned
!
	.align	16
.dbbck:
	rd	%fprs, %o3		! o3 = fprs
 
	! if fprs.fef == 0, set it. Checking it, requires 2 instructions.
	! So set it anyway, without checking.
	wr      %g0, FPRS_FEF, %fprs	 ! fprs.fef = 1

	alignaddr %o1, %g0, %o5		! align src
	ldda	[%o5]%asi, %d0		! get first 8 byte block
	andn	%o2, 7, %o4		! prepare src ptr for finishup code
	cmp	%o2, 32
	blt,pn	%ncc, .dbmv8
	sub	%o1, %o4, %o1		!
	cmp	%o2, 4095		! check for short memmoves
	blt,pn	%ncc, .dbmv32enter	! go to no prefetch code
.dbmv64:
	ldda	[%o5-8]%asi, %d2	! load 8 bytes
	ldda	[%o5-16]%asi, %d4	! load 8 bytes
	sub	%o5, 64, %o5		!
	ldda	[%o5+40]%asi, %d6	! load 8 bytes
	sub	%o0, 64, %o0		!
	ldda	[%o5+32]%asi, %d8	! load 8 bytes
	sub	%o2, 64, %o2		! 64 less bytes to copy
	ldda	[%o5+24]%asi, %d18	! load 8 bytes
	cmp	%o2, 64			! do we have < 64 bytes remaining
	ldda	[%o5+16]%asi, %d28	! load 8 bytes
	ldda	[%o5+8]%asi, %d30	! load 8 bytes
	prefetch [%o5 - (5 * BLOCK_SIZE)], #n_reads
	faligndata %d2, %d0, %d10	! extract 8 bytes out
	ldda	[%o5]%asi, %d0		! load 8 bytes
	std	%d10, [%o0+56]		! store the current 8 bytes
	faligndata %d4, %d2, %d12	! extract 8 bytes out
	std	%d12, [%o0+48]		! store the current 8 bytes
	faligndata %d6, %d4, %d14	! extract 8 bytes out
	std	%d14, [%o0+40]		! store the current 8 bytes
	faligndata %d8, %d6, %d16	! extract 8 bytes out
	std	%d16, [%o0+32]		! store the current 8 bytes
	faligndata %d18, %d8, %d20	! extract 8 bytes out
	std	%d20, [%o0+24]		! store the current 8 bytes
	faligndata %d28, %d18, %d22	! extract 8 bytes out
	std	%d22, [%o0+16]		! store the current 8 bytes
	faligndata %d30, %d28, %d24	! extract 8 bytes out
	std	%d24, [%o0+8]		! store the current 8 bytes
	faligndata %d0, %d30, %d26	! extract 8 bytes out
	bgeu,pt	%ncc, .dbmv64
	std	%d26, [%o0]		! store the current 8 bytes

	cmp	%o2, 32
	blt,pn	%ncc, .dbmvx
	nop
.dbmv32:
	ldda	[%o5-8]%asi, %d2	! load 8 bytes
.dbmv32enter:
	ldda	[%o5-16]%asi, %d4	! load 8 bytes
	sub	%o5, 32, %o5		!
	ldda	[%o5+8]%asi, %d6	! load 8 bytes
	sub	%o0, 32, %o0		! 
	faligndata %d2, %d0, %d10	! extract 8 bytes out
	ldda	[%o5]%asi, %d0		! load 8 bytes
	sub     %o2,32, %o2		! 32 less bytes to copy
	std	%d10, [%o0+24]		! store the current 8 bytes
	cmp	%o2, 32			! do we have < 32 bytes remaining
	faligndata %d4, %d2, %d12	! extract 8 bytes out
	std	%d12, [%o0+16]		! store the current 8 bytes
	faligndata %d6, %d4, %d14	! extract 8 bytes out
	std	%d14, [%o0+8]		! store the current 8 bytes
	faligndata %d0, %d6, %d16	! extract 8 bytes out
	bgeu,pt	%ncc, .dbmv32
	std	%d16, [%o0]		! store the current 8 bytes
.dbmvx:
	cmp	%o2, 8			! do we have < 8 bytes remaining
	blt,pt	%ncc, .dbmvfinish	! if yes, skip to finish up code
	nop
.dbmv8:
	ldda	[%o5-8]%asi, %d2
	sub	%o0, 8, %o0		! since we are at the end
					! when we first enter the loop
	sub     %o2, 8, %o2		! 8 less bytes to copy
	sub	%o5, 8, %o5
	cmp	%o2, 8			! do we have < 8 bytes remaining
	faligndata %d2, %d0, %d8	! extract 8 bytes out
	std	%d8, [%o0]		! store the current 8 bytes
	bgeu,pt	%ncc, .dbmv8
	fmovd	%d2, %d0
.dbmvfinish:
	and	%o3, 0x4, %o3	   ! fprs.du = fprs.dl = 0
	tst	%o2
	bz,pt	%ncc, .dbexit
	wr	%o3, %g0, %fprs	 ! fprs = o3   restore fprs

.dbremain:
	cmp	%o2, 4
	blt,pn	%ncc, .dbbyte
	nop
	ldub	[%o1-1], %o3		! load last byte
	stb	%o3, [%o0-1]		! store last byte
	sub	%o1, 4, %o1
	ldub	[%o1+2], %o3		! load 2nd from last byte
	stb	%o3, [%o0-2]		! store 2nd from last byte
	sub	%o0, 4, %o0
	ldub	[%o1+1], %o3		! load 3rd from last byte
	stb	%o3, [%o0+1]		! store 3rd from last byte
	subcc	%o2, 4, %o2
	ldub	[%o1], %o3		! load 4th from last byte
	stb	%o3, [%o0]		! store 4th from last byte	
	bz,pt	%ncc, .dbexit
.dbbyte:
	dec	%o1			! decrement src address
	ldub	[%o1], %o3		! read a byte
	dec	%o0			! decrement dst address
	deccc	%o2			! decrement count
	bgu,pt	%ncc, .dbbyte		! loop until done
	stb	%o3, [%o0]		! write byte
.dbexit:
	mov	%g5, %asi		! restore %asi
	retl
	mov     %g1, %o0
	SET_SIZE(memmove)

	.align ICACHE_LINE_SIZE
	ENTRY(memcpy)
	ENTRY(__align_cpy_1)
					! adjust instruction alignment
	nop				! Do not remove, these nops affect
	nop				! icache alignment and performance
.forcpy:
	cmp	%o2, SMALL_MAX		! check for not small case
	bgu,pn	%ncc, .medium		! go to larger cases
	mov	%o0, %g1		! save %o0
	cmp	%o2, SHORTCOPY		! check for really short case
	ble,pt	%ncc, .smallleft	!
	or	%o0, %o1, %o3		! prepare alignment check
	andcc	%o3, 0x3, %g0		! test for alignment
	bz,pt	%ncc, .smallword	! branch to word aligned case
	sub	%o2, 3, %o2		! adjust count to allow cc zero test
.smallnotalign4:
	ldub	[%o1], %o3		! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	stb	%o3, [%o0]		! write byte
	ldub	[%o1+1], %o3		! repeat for a total of 4 bytes
	add	%o1, 4, %o1		! advance SRC by 4
	stb	%o3, [%o0+1]
	ldub	[%o1-2], %o3
	add	%o0, 4, %o0		! advance DST by 4
	stb	%o3, [%o0-2]
	ldub	[%o1-1], %o3
	bgu,pt	%ncc, .smallnotalign4	! loop til 3 or fewer bytes remain
	stb	%o3, [%o0-1]
	add	%o2, 3, %o2		! restore count
.smallleft:
	tst	%o2
	bz,pt	%ncc, .smallexit
	nop
.smallleft3:				! 1, 2, or 3 bytes remain
	ldub	[%o1], %o3		! load one byte
	deccc	%o2			! reduce count for cc test
	bz,pt	%ncc, .smallexit
	stb	%o3, [%o0]		! store one byte
	ldub	[%o1+1], %o3		! load second byte
	deccc	%o2
	bz,pt	%ncc, .smallexit
	stb	%o3, [%o0+1]		! store second byte
	ldub	[%o1+2], %o3		! load third byte
	stb	%o3, [%o0+2]		! store third byte
	retl
	mov	%g1, %o0		! restore %o0

	.align	16
	nop				! affects loop icache alignment
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
	nop
	cmp	%o2, 4			! check for 4 or more bytes left
	blt	.smallleft3		! if not, go to finish up
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

.smallword:
	subcc	%o2, 4, %o2		! update count
	bgu,pt	%ncc, .smallwordx
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
	neg	%o1, %o3	
	andcc	%o5, 7, %o5	! bytes till DST 8 byte aligned
	and	%o3, 7, %o3	! bytes till SRC 8 byte aligned
	cmp	%o5, %o3
	bne	%ncc, continue
	sub	%o5, %o3, %o3	! -(bytes till SRC aligned after DST aligned)
				! o3={-7, -6, ... 7}  o3>0 => SRC overaligned
	! src and dst are aligned.
	mov	%o3, %g5		! save %o3
	andcc	%o1, 7, %o3		! is src buf  aligned on a 8 byte bound
	brz,pt	%o3, src_dst_aligned_on_8		
	mov	%o3, %o5
	mov	8, %o4
	sub 	%o4, %o3, %o3
	cmp	%o3, %o2
	bg,a,pn	%ncc, 1f
	mov	%o2, %o3	
1:
	! %o3 has the bytes to be written in partial store.
	sub	%o2, %o3, %o2
	prefetch	[%o1],2

7:
	deccc	%o3			! byte clearing loop
	ldub	[%o1], %o4		! load one byte
	stb	%o4, [%o0]
	inc	%o1			! increment src
	bgu,pt	%ncc, 7b
	inc	%o0			! increment dst

	mov	%g5, %o3		! restore %o3
src_dst_aligned_on_8:
	! check  if we are copying 1k or more bytes
	cmp	%o2, 511
	bgu,pt	%ncc, copying_ge_512
	nop
	ba	.medlword
	nop

continue:
	andcc	%o5, 7, %o5	! bytes till DST 8 byte aligned
	bz	%ncc, 2f
	nop

	sub	%o2, %o5, %o2	! update count

1:
	ldub	[%o1], %o4
	deccc	%o5
	inc	%o1
	stb	%o4, [%o0]
	bgu,pt	%ncc, 1b
	inc	%o0

	! Now DST is 8-byte aligned.  o0, o1, o2 are current.

2:
	andcc	%o1, 0x3, %g0		! test alignment
	bnz,pt	%ncc, .mediumsetup	! branch to skip aligned cases
					! if src, dst not aligned
	prefetch [%o1 + (1 * BLOCK_SIZE)], #n_reads

/*
 * Handle all cases where src and dest are aligned on word
 * or long word boundaries.  Use unrolled loops for better
 * performance.  This option wins over standard large data
 * move when source and destination is in cache for medium
 * to short data moves.
 */
	andcc	%o1, 0x7, %g0		! test word alignment
	bz,pt	%ncc, src_dst_lword_aligned	! branch to long word aligned case
	prefetch [%o1 + (2 * BLOCK_SIZE)], #n_reads
	cmp	%o2, MED_WMAX		! limit to store buffer size
	bgu,pt	%ncc, .mediumrejoin	! otherwise rejoin main loop
	nop
	subcc	%o2, 15, %o2		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .medw15		! skip big loop if less than 16
	prefetch [%o1 + (3 * BLOCK_SIZE)], #n_reads
/*
 * no need to put prefetch in loop as prefetches have
 * already been issued for maximum loop size
 */
.medw16:
	ld	[%o1], %o4		! load
	subcc	%o2, 16, %o2		! decrement length count
	stw	%o4, [%o0]		! and store
	ld	[%o1+4], %o3		! a block of 16 bytes
	add	%o1, 16, %o1		! increase src ptr by 16
	stw	%o3, [%o0+4]
	ld	[%o1-8], %o4
	add	%o0, 16, %o0		! increase dst ptr by 16
	stw	%o4, [%o0-8]
	ld	[%o1-4], %o3
	bgu,pt	%ncc, .medw16		! repeat if at least 16 bytes left
	stw	%o3, [%o0-4]
.medw15:
	addcc	%o2, 15, %o2		! restore count
	bz,pt	%ncc, .medwexit		! exit if finished
	nop
	cmp	%o2, 8
	blt,pt	%ncc, .medw7		! skip if 7 or fewer bytes left
	nop				!
	ld	[%o1], %o4		! load 4 bytes
	subcc	%o2, 8, %o2		! decrease count by 8
	stw	%o4, [%o0]		! and store 4 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	ld	[%o1-4], %o3		! load 4 bytes
	add	%o0, 8, %o0		! increase dst ptr by 8
	stw	%o3, [%o0-4]		! and store 4 bytes
	bz	%ncc, .medwexit		! exit if finished
	nop
.medw7:					! count is ge 1, less than 8
	cmp	%o2, 3			! check for 4 bytes left
	ble,pt	%ncc, .medw3		! skip if 3 or fewer bytes left
	nop				!
	ld	[%o1], %o4		! load 4 bytes
	sub	%o2, 4, %o2		! decrease count by 4
	add	%o1, 4, %o1		! increase src ptr by 4
	stw	%o4, [%o0]		! and store 4 bytes
	add	%o0, 4, %o0		! increase dst ptr by 4
	tst	%o2			! check for zero bytes left
	bz	%ncc, .medwexit		! exit if finished
	nop
.medw3:					! count is known to be 1, 2, or 3
	deccc	%o2			! reduce count by one
	ldub	[%o1], %o3		! load one byte
	bz,pt	%ncc, .medwexit		! exit if last byte
	stb	%o3, [%o0]		! store one byte
	ldub	[%o1+1], %o3		! load second byte
	deccc	%o2			! reduce count by one
	bz,pt	%ncc, .medwexit		! exit if last byte
	stb	%o3, [%o0+1]		! store second byte
	ldub	[%o1+2], %o3		! load third byte
	stb	%o3, [%o0+2]		! store third byte
.medwexit:
	retl
	mov	%g1, %o0		! restore %o0
	
/*
 * Special case for handling when src and dest are both long word aligned
 * and total data to move is between SMALL_MAX and MED_MAX bytes
 */

	.align 16
	nop
src_dst_lword_aligned:
.medlword:				! long word aligned
	cmp	%o2, MED_MAX		! limit to store buffer size
	bgu,pt	%ncc, .mediumrejoin	! otherwise rejoin main loop
	nop
	subcc	%o2, 31, %o2		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .medl31		! skip big loop if less than 32
	prefetch [%o1 + (3 * BLOCK_SIZE)], #n_reads ! into the l2 cache
/*
 * no need to put prefetch in loop as prefetches have
 * already been issued for maximum loop size
 */
.medl32:
	ldx	[%o1], %o4		! load
	subcc	%o2, 32, %o2		! decrement length count
	stx	%o4, [%o0]		! and store
	ldx	[%o1+8], %o3		! a block of 32 bytes
	add	%o1, 32, %o1		! increase src ptr by 32
	stx	%o3, [%o0+8]
	ldx	[%o1-16], %o4
	add	%o0, 32, %o0		! increase dst ptr by 32
	stx	%o4, [%o0-16]
	ldx	[%o1-8], %o3
	bgu,pt	%ncc, .medl32		! repeat if at least 32 bytes left
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
	bz,pt	%ncc, .medwexit		! exit if finished
	nop
	cmp	%o2, 8
	blt,pt	%ncc, .medw7		! skip if 7 or fewer bytes left
	nop
	ldx	[%o1], %o4		! load 8 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	stx	%o4, [%o0]		! and store 8 bytes
	subcc	%o2, 8, %o2		! decrease count by 8
	bz	%ncc, .medwexit		! exit if finished
	add	%o0, 8, %o0		! increase dst ptr by 8
	ba	.medw7
	nop

	.align 16
	nop
	nop
	nop
unaligned_src_dst:

.mediumsetup:
	prefetch [%o1 + (2 * BLOCK_SIZE)], #one_read
.mediumrejoin:
	rd	%fprs, %o4		! check for unused fp

	add	%o1, 8, %o1		! prepare to round SRC upward

	sethi	%hi(0x1234567f), %o5	! For GSR.MASK 
	or	%o5, 0x67f, %o5
	andcc	%o4, FPRS_FEF, %o4	! test FEF, fprs.du = fprs.dl = 0
	bz,a	%ncc, 3f
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
3:
	cmp	%o2, MEDIUM_MAX
	bmask	%o5, %g0, %g0

	! Compute o5 (number of bytes that need copying using the main loop).
	! First, compute for the medium case.
	! Then, if large case, o5 is replaced by count for block alignment.
	! Be careful not to read past end of SRC
	! Currently, o2 is the actual count remaining
	!	    o3 is how much sooner we'll cross the alignment boundary
	!		in SRC compared to in DST
	!
	! Examples:  Let # denote bytes that should not be accessed
	!	    Let x denote a byte already copied to align DST
	!	    Let . and - denote bytes not yet copied
	!	    Let | denote double alignment boundaries
	!
	!	    DST:  ######xx|........|--------|..######   o2 = 18
	!			  o0
	!
	!  o3 = -3:  SRC:  ###xx...|.....---|-----..#|########   o5 = 8
	!			  o1
	!
	!  o3 =  0:  SRC:  ######xx|........|--------|..######   o5 = 16-8 = 8
	!				   o1
	!
	!  o3 = +1:  SRC:  #######x|x.......|.-------|-..#####   o5 = 16-8 = 8
	!				   o1

	mov	%asi, %g5		! save curr %asi
	wr	%g0, ASI_CACHE_SPARING, %asi

	or	%g0, -8, %o5
	alignaddr %o1, %g0, %o1		! set GSR.ALIGN and align o1

	movrlz	%o3, %g0, %o5		! subtract 8 from o2+o3 only if o3>=0
	add	%o5, %o2, %o5
	add	%o5, %o3, %o5

	bleu	%ncc, 4f
	andn	%o5, 7, %o5		! 8 byte aligned count
	neg	%o0, %o5		! 'large' case
	and	%o5, BLOCK_SIZE-1, %o5  ! bytes till DST block aligned
4:	
	brgez,a	%o3, .beginmedloop
	ldda	[%o1-8]%asi, %d0

	add	%o1, %o3, %o1		! back up o1
5:
	ldda	[%o1]ASI_FL8_P, %d2
	inc	%o1
	andcc	%o1, 7, %g0
	bnz	%ncc, 5b
	bshuffle %d0, %d2, %d0		! shifts d0 left 1 byte and or's in d2

.beginmedloop:
	tst	%o5
	bz	%ncc, .endmedloop
	sub	%o2, %o5, %o2		! update count for later

	! Main loop to write out doubles.  Note: o5 & 7 == 0
	
	ldd	[%o1], %d2
	subcc	%o5, 8, %o5		! update local count
	bz,pn	%ncc, 1f
	add	%o1, 8, %o1		! update SRC

.medloop:
	faligndata %d0, %d2, %d4
	ldda	[%o1]%asi, %d0
	subcc	%o5, 8, %o5		! update local count
	add	%o1, 16, %o1		! update SRC
	std	%d4, [%o0]
	bz,pn	%ncc, 2f
	faligndata %d2, %d0, %d6
	ldda	[%o1 - 8]%asi, %d2
	subcc	%o5, 8, %o5		! update local count
	std	%d6, [%o0 + 8]
	bnz,pt	%ncc, .medloop
	add	%o0, 16, %o0		! update DST

1:	
	faligndata %d0, %d2, %d4
	fmovd	%d2, %d0
	std	%d4, [%o0]
	ba	.endmedloop
	add	%o0, 8, %o0
	
2:
	std	%d6, [%o0 + 8]
	sub	%o1, 8, %o1
	add	%o0, 16, %o0
	

.endmedloop:
	! Currently, o1 is pointing to the next double-aligned byte in SRC
	! The 8 bytes starting at [o1-8] are available in d0
	! At least one, and possibly all, of these need to be written.

	cmp	%o2, BLOCK_SIZE	
	bgu	%ncc, .large		! otherwise, less than 16 bytes left
	
#if 1

	/* This code will use partial stores.  */

	mov	%g0, %o5
	and	%o3, 7, %o3		! Number of bytes needed to completely
					! fill %d0 with good (unwritten) data.

	subcc	%o2, 8, %o2		! update count (maybe too much)
	movl	%ncc, %o2, %o5		
	addcc	%o3, %o5, %o5		! extra bytes we can stuff into %d0
	sub	%o3, %o5, %o3		! update o3 (# bad bytes in %d0)

	bz	%ncc, 2f
	alignaddr %o3, %g0, %g0		! set GSR.ALIGN
	
1:
	deccc	%o5
	ldda	[%o1]ASI_FL8_P, %d2
	inc	%o1
	bgu	%ncc, 1b
	bshuffle %d0, %d2, %d0		! shifts d0 left 1 byte and or's in d2

2:
	not     %o3
	faligndata %d0, %d0, %d0	! shift bytes to the left
	and	%o3, 7, %o3		! last byte to be stored in [%o0+%o3]
	edge8n	%g0, %o3, %o5
	stda	%d0, [%o0]%o5, ASI_PST8_P
	brlez	%o2, .exit_memcpy
	add	%o0, %o3, %o0		! update DST to last stored byte
3:	
	inc	%o0
	deccc	%o2
	ldub	[%o1], %o3
	stb	%o3, [%o0]
	bgu	%ncc, 3b
	inc	%o1

#else

	andcc	%o3, 7, %o5		! Number of bytes needed to completely
					! fill %d0 with good (unwritten) data.
	bz	%ncc, 2f
	sub	%o5, 8, %o3		! -(number of good bytes in %d0)
	cmp	%o2, 8
	bl,a	%ncc, 3f		! Not enough bytes to fill %d0
	add	%o1, %o3, %o1 		! Back up %o1

1:
	deccc	%o5
	ldda	[%o1]ASI_FL8_P, %d2
	inc	%o1
	bgu	%ncc, 1b
	bshuffle %d0, %d2, %d0		! shifts d0 left 1 byte and or's in d2

2:	
	subcc	%o2, 8, %o2
	std	%d0, [%o0]
	bz	%ncc, .exit_memcpy
	add	%o0, 8, %o0
3:	
	ldub	[%o1], %o3
	deccc	%o2
	inc	%o1
	stb	%o3, [%o0]
	bgu	%ncc, 3b
	inc	%o0
#endif	

.exit_memcpy:
        wr      %o4, %g0, %fprs		! fprs = o4   restore fprs
	mov	%g5, %asi		! restore %asi
	retl
        mov     %g1, %o0

	.align ICACHE_LINE_SIZE
.large:
	! The following test for BSTORE_SIZE is used to decide whether
	! to store data with a block store or with individual stores.
	! The block store wins when the amount of data is so large
	! that it is causes other application data to be moved out
	! of the L1 or L2 cache.
	! On a Panther, block store can lose more often because block
	! store forces the stored data to be removed from the L3 cache.
	!
	sethi	%hi(BSTORE_SIZE),%o5
	or	%o5,%lo(BSTORE_SIZE),%o5
	cmp	%o2, %o5
	bgu	%ncc, .xlarge		

	! %o0 I/O DST is 64-byte aligned
	! %o1 I/O 8-byte aligned (and we've set GSR.ALIGN)
	! %d0 I/O already loaded with SRC data from [%o1-8]
	! %o2 I/O count (number of bytes that need to be written)
	! %o3 I   Not written.  If zero, then SRC is double aligned.
	! %o4 I   Not written.  Holds fprs.
	! %o5   O The number of doubles that remain to be written.

	! Load the rest of the current block 
	! Recall that %o1 is further into SRC than %o0 is into DST

	prefetch [%o0 + (0 * BLOCK_SIZE)], #n_writes
	prefetch [%o0 + (1 * BLOCK_SIZE)], #n_writes
	prefetch [%o0 + (2 * BLOCK_SIZE)], #n_writes
	ldda	[%o1]%asi, %d2
	prefetch [%o1 + (3 * BLOCK_SIZE)], #one_read
	ldda	[%o1 + 0x8]%asi, %d4
	faligndata %d0, %d2, %d16
	ldda	[%o1 + 0x10]%asi, %d6
	faligndata %d2, %d4, %d18
	ldda	[%o1 + 0x18]%asi, %d8
	faligndata %d4, %d6, %d20
	ldda	[%o1 + 0x20]%asi, %d10
	or	%g0, -8, %o5		! if %o3 >= 0, %o5 = -8
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	faligndata %d6, %d8, %d22
	ldda	[%o1 + 0x28]%asi, %d12
	movrlz	%o3, %g0, %o5		! if %o3 < 0, %o5 = 0  (needed lter)
	faligndata %d8, %d10, %d24
	ldda	[%o1 + 0x30]%asi, %d14
	faligndata %d10, %d12, %d26
	ldda	[%o1 + 0x38]%asi, %d0
	sub	%o2, BLOCK_SIZE, %o2	! update count
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	add	%o1, BLOCK_SIZE, %o1		! update SRC

	! Main loop.  Write previous block.  Load rest of current block.
	! Some bytes will be loaded that won't yet be written.
1:	
	ldda	[%o1]%asi, %d2
	faligndata %d12, %d14, %d28
	ldda	[%o1 + 0x8]%asi, %d4
	faligndata %d14, %d0, %d30
	std	%d16, [%o0]
	std	%d18, [%o0+8]
	std	%d20, [%o0+16]
	std	%d22, [%o0+24]
	std	%d24, [%o0+32]
	std	%d26, [%o0+40]
	std	%d28, [%o0+48]
	std	%d30, [%o0+56]
	sub	%o2, BLOCK_SIZE, %o2		! update count
	prefetch [%o0 + (6 * BLOCK_SIZE)], #n_writes
	prefetch [%o0 + (3 * BLOCK_SIZE)], #n_writes
	add	%o0, BLOCK_SIZE, %o0		! update DST
	ldda	[%o1 + 0x10]%asi, %d6
	faligndata %d0, %d2, %d16
	ldda	[%o1 + 0x18]%asi, %d8
	faligndata %d2, %d4, %d18
	ldda	[%o1 + 0x20]%asi, %d10
	faligndata %d4, %d6, %d20
	ldda	[%o1 + 0x28]%asi, %d12
	faligndata %d6, %d8, %d22
	ldda	[%o1 + 0x30]%asi, %d14
	faligndata %d8, %d10, %d24
	ldda	[%o1 + 0x38]%asi, %d0
	faligndata %d10, %d12, %d26
	cmp	%o2, BLOCK_SIZE + 8
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	bgu,pt	%ncc, 1b
	add	%o1, BLOCK_SIZE, %o1	! update SRC
	faligndata %d12, %d14, %d28
	faligndata %d14, %d0, %d30
	stda	%d16, [%o0]ASI_BLK_P	! store 64 bytes, bypass cache
	cmp	%o2, BLOCK_SIZE
	bne	%ncc, 2f		! exactly 1 block remaining?
	add	%o0, BLOCK_SIZE, %o0	! update DST
	brz,a	%o3, 3f			! is SRC double aligned?
	ldd	[%o1], %d2

2:	
	add	%o5, %o2, %o5		! %o5 was already set to 0 or -8 
	add	%o5, %o3, %o5

	ba	.beginmedloop
	andn	%o5, 7, %o5		! 8 byte aligned count

	! This is when there is exactly 1 block remaining and SRC is aligned
3:
	!  %d0 was loaded in the last iteration of the loop above, and
	!  %d2 was loaded in the branch delay slot that got us here.
	ldd	[%o1 + 0x08], %d4
	ldd	[%o1 + 0x10], %d6
	ldd	[%o1 + 0x18], %d8
	ldd	[%o1 + 0x20], %d10
	ldd	[%o1 + 0x28], %d12
	ldd	[%o1 + 0x30], %d14
	stda	%d0, [%o0]ASI_BLK_P

	ba	.exit_memcpy
	 nop


	.align 16
	! two nops here causes loop starting at 1f below to be
	! on a cache line boundary, improving performance
	nop
	nop
xlarge:
.xlarge:
	/*
	set	4096, %l2
	subcc	%o2, %l2, %g0
	bge	%ncc, size_ge_4k
	nop
	*/
	! %o0 I/O DST is 64-byte aligned
	! %o1 I/O 8-byte aligned (and we've set GSR.ALIGN)
	! %d0 I/O already loaded with SRC data from [%o1-8]
	! %o2 I/O count (number of bytes that need to be written)
	! %o3 I   Not written.  If zero, then SRC is double aligned.
	! %o4 I   Not written.  Holds fprs.
	! %o5   O The number of doubles that remain to be written.

	! Load the rest of the current block 
	! Recall that %o1 is further into SRC than %o0 is into DST

	! prefetch [%o1 + (3 * BLOCK_SIZE)], #one_read
	! executed in delay slot for branch to .xlarge
	prefetch [%o1 + (4 * BLOCK_SIZE)], #one_read
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	ldda	[%o1]%asi, %d2
	prefetch [%o1 + (6 * BLOCK_SIZE)], #one_read
	ldda	[%o1 + 0x8]%asi, %d4
	faligndata %d0, %d2, %d16
	ldda	[%o1 + 0x10]%asi, %d6
	faligndata %d2, %d4, %d18
	ldda	[%o1 + 0x18]%asi, %d8
	faligndata %d4, %d6, %d20
	ldda	[%o1 + 0x20]%asi, %d10
	or	%g0, -8, %o5		! if %o3 >= 0, %o5 = -8
	faligndata %d6, %d8, %d22
	ldda	[%o1 + 0x28]%asi, %d12
	movrlz	%o3, %g0, %o5		! if %o3 < 0, %o5 = 0  (needed later)
	faligndata %d8, %d10, %d24
	ldda	[%o1 + 0x30]%asi, %d14
	faligndata %d10, %d12, %d26
	ldda	[%o1 + 0x38]%asi, %d0
	sub	%o2, BLOCK_SIZE, %o2	! update count
	prefetch [%o1 + (7 * BLOCK_SIZE)], #one_read
	add	%o1, BLOCK_SIZE, %o1	! update SRC

	! This point is 32-byte aligned since 24 instructions appear since
	! the previous alignment directive.
	

	! Main loop.  Write previous block.  Load rest of current block.
	! Some bytes will be loaded that won't yet be written.
1:
	ldda	[%o1]%asi, %d2
	faligndata %d12, %d14, %d28
	ldda	[%o1 + 0x8]%asi, %d4
	faligndata %d14, %d0, %d30
	stda	%d16, [%o0]ASI_BLK_P
	sub	%o2, BLOCK_SIZE, %o2		! update count
	ldda	[%o1 + 0x10]%asi, %d6
	faligndata %d0, %d2, %d16
	ldda	[%o1 + 0x18]%asi, %d8
	faligndata %d2, %d4, %d18
	ldda	[%o1 + 0x20]%asi, %d10
	faligndata %d4, %d6, %d20
	ldda	[%o1 + 0x28]%asi, %d12
	faligndata %d6, %d8, %d22
	ldda	[%o1 + 0x30]%asi, %d14
	faligndata %d8, %d10, %d24
	ldda	[%o1 + 0x38]%asi, %d0
	faligndata %d10, %d12, %d26
	! offset of 8*BLK+8 bytes works best over range of (src-dst) mod 1K
	prefetch [%o1 + (8 * BLOCK_SIZE) + 8], #one_read
	add	%o0, BLOCK_SIZE, %o0		! update DST
	cmp	%o2, BLOCK_SIZE + 8
	! second prefetch important to correct for occasional dropped
	! initial prefetches, 5*BLK works best over range of (src-dst) mod 1K
	! strong prefetch prevents drops on Panther, but Jaguar and earlier
	! US-III models treat strong prefetches as weak prefetchs
	! to avoid regressions on customer hardware, we retain the prefetch
	prefetch [%o1 + (5 * BLOCK_SIZE)], #one_read
	bgu,pt	%ncc, 1b
	add	%o1, BLOCK_SIZE, %o1	! update SRC

	faligndata %d12, %d14, %d28
	faligndata %d14, %d0, %d30
	stda	%d16, [%o0]ASI_BLK_P	! store 64 bytes, bypass cache
	cmp	%o2, BLOCK_SIZE		
	bne	%ncc, 2f		! exactly 1 block remaining?
	add	%o0, BLOCK_SIZE, %o0	! update DST
	brz,a	%o3, 3f			! is SRC double aligned?
	ldd	[%o1], %d2

2:	
	add	%o5, %o2, %o5		! %o5 was already set to 0 or -8 
	add	%o5, %o3, %o5


	ba	.beginmedloop
	andn	%o5, 7, %o5		! 8 byte aligned count


	! This is when there is exactly 1 block remaining and SRC is aligned
3:
	!  %d0 was loaded in the last iteration of the loop above, and
	!  %d2 was loaded in the branch delay slot that got us here.
	ldd	[%o1 + 0x08], %d4
	ldd	[%o1 + 0x10], %d6
	ldd	[%o1 + 0x18], %d8
	ldd	[%o1 + 0x20], %d10
	ldd	[%o1 + 0x28], %d12
	ldd	[%o1 + 0x30], %d14
	stda	%d0, [%o0]ASI_BLK_P

	ba	.exit_memcpy
	 nop

copying_ge_512:
	mov	%o0, %o5	! save dst address for return value.
	! both src and dst are aligned to 8 byte boundary.
	save	%sp, -SA(STACK_OFFSET + SAVESIZE), %sp
	mov	%i0, %o0
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i5, %o5
#ifndef	__sparcv9
	stx	%g4, [%sp + STACK_OFFSET + g4_offset]
	stx	%g5, [%sp + STACK_OFFSET + g5_offset]
#endif
	rd	%fprs, %g5		! check for unused fp
	andcc	%g5, FPRS_FEF, %g5	! test FEF, fprs.du = fprs.dl = 0
	bz,a	%ncc, 1f
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
1:
	!predfetch src buf
	sub     %o1,1,%o3
	andn    %o3,0x7f,%l1
	add     %l1,128,%l1
	prefetch [%l1],2		!prefetch next 128b
	prefetch [%l1+64],2
	prefetch [%l1+(2*64)],2		!cont from above
	prefetch [%l1+(3*64)],2
	!predfetch dst buf
	sub     %o5,1,%o3
	andn    %o3,0x7f,%l1
	add     %l1,128,%l1
	prefetch [%l1],2		!prefetch next 128b
	prefetch [%l1+64],2
	prefetch [%l1+(2*64)],2		!cont from above
	prefetch [%l1+(3*64)],2

	andcc   %o5,0x7f,%o3	    !o3=0 , means it is already 128 align
	brz,pn  %o3,aligned_on_128
	sub     %o3,128,%o3

	add     %o2,%o3,%o2
align_to_128:
	ldxa	[%o1]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o1,8,%o1		! increment src pointer
	stxa    %o4,[%o5]ASI_CACHE_SPARING_PRIMARY
	addcc   %o3,8,%o3
	bl,pt   %ncc,align_to_128
	add     %o5,8,%o5		! increment dst pointer

aligned_on_128:
	andcc	%o5,0x1ff,%o3	!%o3=0 when it is 512 b aligned.
	brnz,pn	%o3, 4f
	mov	%o2,%l4		!l4=count from 512 align
	set	4096, %l2
	subcc	%o2, %l2, %g0
	bge,pn	%ncc, stingray_optimized_copy
	nop
4:

	sub	%o5,8,%l6	!should be in current 512 chunk
	andn 	%l6,0x1ff,%o3	!%o3=aligned 512b addr
	add 	%o3,0x200,%o3	!%o3=next aligned 512b addr to start
				! stingray_optimized_copy
	sub 	%o3,%o5,%o3	!o3=how many byte in the current remaining chunk
	sub	%o2,%o3,%l4	!l4=count from 512 align
	/*
	 * if l4 is < 4096 do interleave_128_copy only.
	 */
	set	4096, %l2
	subcc	%l4, %l2, %g0
	bge,pn	%ncc,6f
	nop
	mov	%g0, %l4
	add	%o5, %o2, %l1
	ba	interleave_128_copy
	nop
6:
	mov	%o3, %o2
	subcc 	%o3,256,%g0	! if it is > 256 bytes , could use the
				! interleave_128_copy
	bl,pn	%ncc,copy_word	! o.w use copy_word to finish the 512 byte
				! alignment.
	!%o1=64 bytes data
	!%o5=next 8 byte addr to write
	!%o2=new count i.e how many bytes to write
	add     %o5,%o2,%l1	!cal the last byte to write %l1
	ba	interleave_128_copy
	nop

	.align	64
interleave_128_copy:
	! %l1 has the addr of the dest. buffer at or beyond which no write
	! is to be done.
	! %l4 has the number of bytes to zero using stingray_optimized_bzero
	!prefetch src
	!prefetch src 

	add	%o1, 256, %o3
	prefetch [%o3], 2	!1st 64 byte line of next 256 byte block
	add	%o1, 384, %o3
	prefetch [%o3], 2	!3rd 64 byte line of next 256 byte block
	add	%o1, 320, %o3
	prefetch [%o3], 2	!2nd 64 byte line of next 256 byte block
	add	%o1, 448, %o3
	prefetch [%o3], 2	!4th 64 byte line of next 256 byte block

	!prefetch dst 

	add	%o5, 256, %o3
	prefetch [%o3], 2	!1st 64 byte line of next 256 byte block
	add	%o5, 384, %o3
	prefetch [%o3], 2	!3rd 64 byte line of next 256 byte block
	add	%o5, 320, %o3
	prefetch [%o3], 2	!2nd 64 byte line of next 256 byte block
	add	%o5, 448, %o3
	prefetch [%o3], 2	!4th 64 byte line of next 256 byte block

	ldxa	[%o1]ASI_CACHE_SPARING_PRIMARY, %o4
	stxa     %o4,[%o5]ASI_CACHE_SPARING_PRIMARY	!1st 64 byte line
	add	%o1, 128, %o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, 128, %o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY	!3rd 64 byte line
	add     %o1, (1 * 8), %o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add	%o5, (1 * 8), %o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (1 * 8 + 128), %o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (1 * 8 + 128), %o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (2 * 8),%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (2 * 8),%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (2 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (2 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (3 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (3 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (3 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (3 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (4 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (4 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (4 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (4 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (5 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (5 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (5 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (5 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (6 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (6 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (6 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (6 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (7 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (7 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (7 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (7 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (8 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (8 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (8 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (8 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (9 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (9 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (9 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (9 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (10 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (10 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (10 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (10 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (11 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (11 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (11 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (11 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (12 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (12 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (12 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (12 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (13 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (13 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (13 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (13 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (14 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (14 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (14 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (14 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (15 * 8) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (15 * 8) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add     %o1, (15 * 8 + 128) ,%o3
	ldxa	[%o3]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o5, (15 * 8 + 128) ,%o3
	stxa     %o4,[%o3]ASI_CACHE_SPARING_PRIMARY
	add	%o1, 256, %o1
	! check if the next 256 byte copy will not exceed the number of
	! bytes remaining to be copied.
	! %l2 points to the dest buffer after copying 256 bytes more.
	! %l1 points to dest. buffer at or beyond which no writes should be done.
	add     %o5,512,%l2
			
	subcc   %l1,%l2,%g0
	bge,pt  %ncc,interleave_128_copy
	add     %o5,256,%o5

copy_word:
	and     %o2,255,%o3
	and     %o3,7,%o2

	! Set the remaining doubles
	subcc   %o3, 8, %o3		! Can we store any doubles?
	bl,pn  %ncc, 6f
	and	%o2, 7, %o2		! calc bytes left after doubles

	!prefetch src 

	mov	%o1, %o4
	prefetch [%o4], 2	!1st 64 byte line of next 256 byte block
	add	%o1, 128, %o4
	prefetch [%o4], 2	!3rd 64 byte line of next 256 byte block
	add	%o1, 64, %o4
	prefetch [%o4], 2	!2nd 64 byte line of next 256 byte block
	add	%o1, 192, %o4
	prefetch [%o4], 2	!4th 64 byte line of next 256 byte block

	!prefetch dst 

	mov	%o5, %o4
	prefetch [%o4], 2	!1st 64 byte line of next 256 byte block
	add	%o5, 128, %o4
	prefetch [%o4], 2	!3rd 64 byte line of next 256 byte block
	add	%o5, 64, %o4
	prefetch [%o4], 2	!2nd 64 byte line of next 256 byte block
	add	%o5, 192, %o4
	prefetch [%o4], 2	!4th 64 byte line of next 256 byte block

5:	
	ldxa	[%o1]ASI_CACHE_SPARING_PRIMARY, %o4
	add     %o1, 8, %o1      
	stxa	%o4, [%o5]ASI_CACHE_SPARING_PRIMARY
	subcc   %o3, 8, %o3
	bge,pt	%ncc, 5b
	add     %o5, 8, %o5      
6:
	! Set the remaining bytes
	brz	%o2,  can_we_do_stingray_optimized_copy
	nop
	
	! Terminate the copy with a partial store.
	! The data should be at d0
	ldxa	[%o1]ASI_CACHE_SPARING_PRIMARY, %o4
	stx	%o4, [%sp + STACK_OFFSET + scratch_offset]
	ldd	[%sp + STACK_OFFSET + scratch_offset], %d0
	
	dec     %o2		     ! needed to get the mask right
	edge8n	%g0, %o2, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P
can_we_do_stingray_optimized_copy:
	mov	%l4, %o2
	brnz,pn	%o2, stingray_optimized_copy
	nop
	
exit:	
	brnz	%g5, 1f
	nop
	wr	%g5, %g0, %fprs
1:
#ifndef	__sparcv9
	ldx	[%sp + STACK_OFFSET + g4_offset], %g4
	ldx	[%sp + STACK_OFFSET + g5_offset], %g5
#endif
	ret				! %o0 was preserved
	restore


stingray_optimized_copy:
!%o5 = next memory addr which is 512 b align
!%l4 = remaining byte from 512 align.

	add	%o5, %l4, %o2

	prefetch [%o1+0],2
	prefetch [%o1+(64*1)],2
	prefetch [%o1+(64*2)],2
	prefetch [%o1+(64*3)],2
	prefetch [%o1+(64*4)],2
	prefetch [%o1+(64*5)],2
	prefetch [%o1+(64*6)],2
	prefetch [%o1+(64*7)],2
	prefetch [%o1+(64*8)],2
	prefetch [%o1+(64*9)],2
	prefetch [%o1+(64*10)],2
	prefetch [%o1+(64*11)],2
	prefetch [%o1+(64*12)],2
	prefetch [%o1+(64*13)],2
	prefetch [%o1+(64*14)],2
	prefetch [%o1+(64*15)],2

	prefetch [%o5+0],2
	prefetch [%o5+(64*1)],2
	prefetch [%o5+(64*2)],2
	prefetch [%o5+(64*3)],2
	prefetch [%o5+(64*4)],2
	prefetch [%o5+(64*5)],2
	prefetch [%o5+(64*6)],2
	prefetch [%o5+(64*7)],2
	prefetch [%o5+(64*8)],2
	prefetch [%o5+(64*9)],2
	prefetch [%o5+(64*10)],2
	prefetch [%o5+(64*11)],2
	prefetch [%o5+(64*12)],2
	prefetch [%o5+(64*13)],2
	prefetch [%o5+(64*14)],2
	prefetch [%o5+(64*15)],2
	
	ba      myloop2
	srl	%l4, 12, %l4
	
	! Local register usage:
	!
	! %l1 address at short distance ahead of current %o1 for prefetching
	!     into L1 cache. 
	! %l2 address at far ahead of current %o1 for prefetching into L2 cache.
	! %l3 save %o5 at start of inner loop. 
	! %l4 Number of 4k blocks to copy
	! %g1 save %o1 at start of inner loop. 
	! %l5 iteration counter to make buddy loop execute 2 times. 
	! %l6 iteration counter to make inner loop execute 32 times. 
	! %l7 address at far ahead of current %o5 for prefetching destination
	!     into L2 cache.
	       
.align 64
myloop2:
	set      2,%l5	! %l5 is the loop count for the buddy loop, for 2 buddy lines.
	add      %o5, 0, %l3 
	add      %o1, 0, %g1 
buddyloop:
	set      PF_FAR, %g4	! Prefetch far ahead. CHANGE FAR PREFETCH HERE.
	add      %o1, %g4, %l2	! For prefetching far ahead, set %l2 far ahead
				! of %o1
	add      %o1, PF_NEAR, %l1	! For prefetching into L1 D$, set %l1 a
					! little ahead of %o1
	add      %o5, %g4, %l7	! For prefetching far ahead, set %l7 far ahead
				! of %o5

	add      %l2, %g4, %g4	! %g4 is now double far ahead of the source
				! address in %o1.
	prefetch [%g4+%g0],2	! Prefetch ahead by several pages to get TLB
				! entry in advance.
	set      2*PF_FAR, %g4	! Prefetch double far ahead.  SET DOUBLE FAR
				! PREFETCH HERE.
	add      %o5, %g4, %g4	! %g4 is now double far ahead of the dest
				! address in %o5.
	prefetch [%g4+%g0],2	! Prefetch ahead by 2 pages to get TLB entry
				! in advance.

	set      4,%l6		! %l6 = loop count for the inner loop,
				! for 4 x 8 = 32 lines.
	set      0, %g4
	
	! Each iteration of the inner loop below copies 8 sequential lines.
	! This loop is iterated 4 times, to move a total of 32 lines,
	! all of which have the same value of PA[9], so we increment the base
	! address by 1024 bytes in each iteration, which varies PA[10].				     */ 
innerloop:	  
	/* ---- copy line 1 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P
	add     %g4, 64, %g4
	add     %o5, 64, %o5
	add     %o1, 64, %o1       /* increment %o1 for the next source line.   */

	/* ---- copy line 2 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P
	add     %g4, 64, %g4
	add     %o5, 64, %o5
	add     %o1, 64, %o1       /* increment %o1 for the next source line.   */

	/* ---- copy line 3 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P
	add     %g4, 64, %g4
	add     %o5, 64, %o5
	add     %o1, 64, %o1       /* increment %o1 for the next source line.   */

	/* ---- copy line 4 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P
	add     %g4, 64, %g4
	add     %o5, 64, %o5
	add     %o1, 64, %o1       /* increment %o1 for the next source line.   */

	/* ---- copy line 5 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P
	add     %g4, 64, %g4
	add     %o5, 64, %o5
	add     %o1, 64, %o1       /* increment %o1 for the next source line.   */

	/* ---- copy line 6 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P
	add     %g4, 64, %g4
	add     %o5, 64, %o5
	add     %o1, 64, %o1       /* increment %o1 for the next source line.   */

	/* ---- copy line 7 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P
	add     %g4, 64, %g4
	add     %o5, 64, %o5
	add     %o1, 64, %o1       /* increment %o1 for the next source line.   */

	/* ---- copy line 8 of 8. ---- */
	prefetch [%l2+%g4],2
	prefetch [%l7+%g4],2
	prefetch [%l1+%g4],1

	ldd     [%o1],%d0
	ldd     [%o1+8],%d2
	ldd     [%o1+16],%d4
	ldd     [%o1+24],%d6
	ldd     [%o1+32],%d8
	ldd     [%o1+40],%d10
	ldd     [%o1+48],%d12
	ldd     [%o1+56],%d14
	stda    %d0,[%o5]ASI_BLK_P

	subcc   %l6,1,%l6	  /* Decrement the inner loop counter.	 */
	
	! Now increment by 64 + 512 so we don't toggle PA[9]
	add     %g4, 576, %g4
	add     %o5, 576, %o5

	bg,pt   %icc,innerloop
	add     %o1, 576, %o1	! increment %o1 for the next source line.
	! END OF INNER LOOP


	subcc   %l5,1,%l5
	add     %l3, 512, %o5	! increment %o5 to first buddy line of dest.
	bg,pt   %icc,buddyloop
	add     %g1, 512 ,%o1	! Set %o1 to the first of the odd buddy lines.

	subcc   %l4, 1, %l4
	add     %o5, 3584, %o5	! Advance both base addresses to 4k above where
				! they started.
	add     %o1, 3584, %o1	! They were already incremented by 512,
				! so just add 3584.

	bg,pt   %icc,myloop2
	nop

	/****larryalg_end_here*************/

	sub	%o2,%o5,%o2	!how many byte left
	brz,pn	%o2,complete_write
	mov	%g0,%l4
	add     %o5,%o2,%l1	     !cal the last byte to write %l1
	subcc	%o2,256,%g0
	bge,pt	%ncc,interleave_128_copy
	mov	%g0,%l4
	
	ba	copy_word
	nop


complete_write: 
	ba      exit
	nop


	
	SET_SIZE(memcpy)
	SET_SIZE(__align_cpy_1)
