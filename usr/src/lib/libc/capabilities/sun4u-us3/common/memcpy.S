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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

	.file	"memcpy.s"

/*
 * memcpy(s1, s2, len)
 *
 * Copy s2 to s1, always copy n bytes.
 * Note: this C code does not work for overlapped copies.
 *       Memmove() and bcopy() do.
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

#define	ICACHE_LINE_SIZE	64
#define	BLOCK_SIZE	64
#define	FPRS_FEF	0x4

#define SHORTCOPY	3
#define	SMALL_MAX	39
#define	MEDIUM_MAX	255
#define MED_WMAX	256	/* max copy for medium word-aligned case */
#define MED_MAX		256	/* max copy for medium longword-aligned case */

#ifndef BSTORE_SIZE
#define BSTORE_SIZE	256	/* min copy size for block store */
#endif

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
	add     %o1, %o2, %o1           ! get to end of source space
        add     %o0, %o2, %o0           ! get to end of destination space

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
	prefetch [%o1 - (1 * BLOCK_SIZE)], 20	! into the prefetch cache
	sub	%o2, 63, %o2		! adjust length to allow cc test
					! for end of loop
	prefetch [%o1 - (2 * BLOCK_SIZE)], 20	! into the prefetch cache
	rd	%fprs, %o3		! o3 = fprs
	! if fprs.fef == 0, set it. Checking it, requires 2 instructions.
	! So set it anyway, without checking.
	prefetch [%o1 - (3 * BLOCK_SIZE)], 20	! into the prefetch cache
	wr      %g0, 0x4, %fprs         ! fprs.fef = 1
	prefetch [%o1 - (4 * BLOCK_SIZE)], 20	! into the prefetch cache
.dbmedl64:
	prefetch [%o1 - (5 * BLOCK_SIZE)], 20	! into the prefetch cache
	ldd	[%o1-8], %d4		! load
	subcc	%o2, 64, %o2		! decrement length count
	std	%d4, [%o0-8]		! and store
	ldd	[%o1-16], %d2		! a block of 64 bytes
	sub	%o1, 64, %o1		! decrease src ptr by 64
	std	%d2, [%o0-16]
	sub	%o0, 64, %o0		! decrease dst ptr by 64
	ldd	[%o1+40], %d4
	std	%d4, [%o0+40]
	ldd	[%o1+32], %d2
	std	%d2, [%o0+32]
	ldd	[%o1+24], %d4
	std	%d4, [%o0+24]
	ldd	[%o1+16], %d2
	std	%d2, [%o0+16]
	ldd	[%o1+8], %d4
	std	%d4, [%o0+8]
	ldd	[%o1], %d2
	bgu,pt	%ncc, .dbmedl64		! repeat if at least 64 bytes left
	std	%d2, [%o0]
	add	%o2, 63, %o2		! restore offset adjustment
	and	%o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
	wr	%o3, %g0, %fprs         ! fprs = o3   restore fprs
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
	wr      %g0, 0x4, %fprs         ! fprs.fef = 1

	alignaddr %o1, %g0, %o5		! align src
	ldd	[%o5], %d0		! get first 8 byte block
	andn	%o2, 7, %o4		! prepare src ptr for finishup code
	cmp	%o2, 32
	blt,pn	%ncc, .dbmv8
	sub	%o1, %o4, %o1		!
	cmp	%o2, 4095		! check for short memmoves
	blt,pn	%ncc, .dbmv32enter	! go to no prefetch code
.dbmv64:
	ldd	[%o5-8], %d2		! load 8 bytes
	ldd	[%o5-16], %d4		! load 8 bytes
	sub	%o5, 64, %o5		!
	ldd	[%o5+40], %d6		! load 8 bytes
	sub	%o0, 64, %o0		!
	ldd	[%o5+32], %d8		! load 8 bytes
	sub	%o2, 64, %o2		! 64 less bytes to copy
	ldd	[%o5+24], %d18		! load 8 bytes
	cmp	%o2, 64			! do we have < 64 bytes remaining
	ldd	[%o5+16], %d28		! load 8 bytes
	ldd	[%o5+8], %d30		! load 8 bytes
	prefetch [%o5 - (5 * BLOCK_SIZE)], 20	! into the prefetch cache
	faligndata %d2, %d0, %d10	! extract 8 bytes out
	ldd	[%o5], %d0		! load 8 bytes
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
	ldd	[%o5-8], %d2		! load 8 bytes
.dbmv32enter:
	ldd	[%o5-16], %d4		! load 8 bytes
	sub	%o5, 32, %o5		!
	ldd	[%o5+8], %d6		! load 8 bytes
	sub	%o0, 32, %o0		!
	faligndata %d2, %d0, %d10	! extract 8 bytes out
	ldd	[%o5], %d0		! load 8 bytes
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
	ldd	[%o5-8], %d2
	sub	%o0, 8, %o0		! since we are at the end
					! when we first enter the loop
	sub     %o2, 8, %o2		! 8 less bytes to copy
	sub	%o5, 8, %o5
	cmp	%o2, 8			! do we have < 8 bytes remaining
	faligndata %d2, %d0, %d8        ! extract 8 bytes out
	std	%d8, [%o0]		! store the current 8 bytes
	bgeu,pt	%ncc, .dbmv8
	fmovd	%d2, %d0
.dbmvfinish:
	and	%o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
	tst	%o2
	bz,pt	%ncc, .dbexit
	wr	%o3, %g0, %fprs         ! fprs = o3   restore fprs

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
	retl
        mov     %g1, %o0
	SET_SIZE(memmove)


	.align ICACHE_LINE_SIZE
	ENTRY(memcpy)
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

	bz	%ncc, 2f
	sub	%o5, %o3, %o3	! -(bytes till SRC aligned after DST aligned)
				! o3={-7, -6, ... 7}  o3>0 => SRC overaligned

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
	prefetch [%o1 + (1 * BLOCK_SIZE)], 20

/*
 * Handle all cases where src and dest are aligned on word
 * or long word boundaries.  Use unrolled loops for better
 * performance.  This option wins over standard large data
 * move when source and destination is in cache for medium
 * to short data moves.
 */
	andcc	%o1, 0x7, %g0		! test word alignment
	bz,pt	%ncc, .medlword		! branch to long word aligned case
	prefetch [%o1 + (2 * BLOCK_SIZE)], 20
	cmp	%o2, MED_WMAX		! limit to store buffer size
	bgu,pt	%ncc, .mediumrejoin	! otherwise rejoin main loop
	nop
	subcc	%o2, 15, %o2		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .medw15		! skip big loop if less than 16
	prefetch [%o1 + (3 * BLOCK_SIZE)], 20
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
.medlword:				! long word aligned
					! length > SMALL_MAX
	cmp	%o2, MED_MAX		! limit to store buffer size
	bgu,pt	%ncc, .mediumrejoin	! otherwise rejoin main loop
	nop
	subcc	%o2, 31, %o2		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .medl31		! skip big loop if less than 32
	prefetch [%o1 + (3 * BLOCK_SIZE)], 20	! into the l2 cache
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
.mediumsetup:
	prefetch [%o1 + (2 * BLOCK_SIZE)], 21
.mediumrejoin:
	rd	%fprs, %o4		! check for unused FPU

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
	!            o3 is how much sooner we'll cross the alignment boundary
	!                in SRC compared to in DST
	!
	! Examples:  Let # denote bytes that should not be accessed
	!            Let x denote a byte already copied to align DST
	!            Let . and - denote bytes not yet copied
	!            Let | denote double alignment boundaries
	!
	!            DST:  ######xx|........|--------|..######   o2 = 18
	!                          o0
	!
	!  o3 = -3:  SRC:  ###xx...|.....---|-----..#|########   o5 = 8
	!                          o1
	!
	!  o3 =  0:  SRC:  ######xx|........|--------|..######   o5 = 16-8 = 8
	!                                   o1
	!
	!  o3 = +1:  SRC:  #######x|x.......|.-------|-..#####   o5 = 16-8 = 8
	!                                   o1

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
	ldd	[%o1-8], %d0

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
	ldd	[%o1], %d0
	subcc	%o5, 8, %o5		! update local count
	add	%o1, 16, %o1		! update SRC
	std	%d4, [%o0]
	bz,pn	%ncc, 2f
	faligndata %d2, %d0, %d6
	ldd	[%o1 - 8], %d2
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

#if 0

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
	brlez	%o2, .mediumexit
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
	bz	%ncc, .mediumexit
	add	%o0, 8, %o0
3:
	ldub	[%o1], %o3
	deccc	%o2
	inc	%o1
	stb	%o3, [%o0]
	bgu	%ncc, 3b
	inc	%o0
#endif

.mediumexit:
        wr      %o4, %g0, %fprs		! fprs = o4   restore fprs
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

	prefetch [%o0 + (0 * BLOCK_SIZE)], 22
	prefetch [%o0 + (1 * BLOCK_SIZE)], 22
	prefetch [%o0 + (2 * BLOCK_SIZE)], 22
	ldd	[%o1], %f2
	prefetch [%o1 + (3 * BLOCK_SIZE)], 21
	ldd	[%o1 + 0x8], %f4
	faligndata %f0, %f2, %f32
	ldd	[%o1 + 0x10], %f6
	faligndata %f2, %f4, %f34
	ldd	[%o1 + 0x18], %f8
	faligndata %f4, %f6, %f36
	ldd	[%o1 + 0x20], %f10
        or	%g0, -8, %o5		! if %o3 >= 0, %o5 = -8
	prefetch [%o1 + (4 * BLOCK_SIZE)], 21
	faligndata %f6, %f8, %f38
	ldd	[%o1 + 0x28], %f12
	movrlz	%o3, %g0, %o5		! if %o3 < 0, %o5 = 0  (needed lter)
	faligndata %f8, %f10, %f40
	ldd	[%o1 + 0x30], %f14
	faligndata %f10, %f12, %f42
	ldd	[%o1 + 0x38], %f0
	sub	%o2, BLOCK_SIZE, %o2	! update count
	prefetch [%o1 + (5 * BLOCK_SIZE)], 21
	add	%o1, BLOCK_SIZE, %o1		! update SRC

	! Main loop.  Write previous block.  Load rest of current block.
	! Some bytes will be loaded that won't yet be written.
1:
	ldd	[%o1], %f2
	faligndata %f12, %f14, %f44
	ldd	[%o1 + 0x8], %f4
	faligndata %f14, %f0, %f46
	std	%f32, [%o0]
	std	%f34, [%o0+8]
	std	%f36, [%o0+16]
	std	%f38, [%o0+24]
	std	%f40, [%o0+32]
	std	%f42, [%o0+40]
	std	%f44, [%o0+48]
	std	%f46, [%o0+56]
	sub	%o2, BLOCK_SIZE, %o2		! update count
	prefetch [%o0 + (6 * BLOCK_SIZE)], 22
	prefetch [%o0 + (3 * BLOCK_SIZE)], 22
	add	%o0, BLOCK_SIZE, %o0		! update DST
	ldd	[%o1 + 0x10], %f6
	faligndata %f0, %f2, %f32
	ldd	[%o1 + 0x18], %f8
	faligndata %f2, %f4, %f34
	ldd	[%o1 + 0x20], %f10
	faligndata %f4, %f6, %f36
	ldd	[%o1 + 0x28], %f12
	faligndata %f6, %f8, %f38
	ldd	[%o1 + 0x30], %f14
	faligndata %f8, %f10, %f40
	ldd	[%o1 + 0x38], %f0
	faligndata %f10, %f12, %f42
	cmp	%o2, BLOCK_SIZE + 8
	prefetch [%o1 + (5 * BLOCK_SIZE)], 21
	bgu,pt	%ncc, 1b
	add	%o1, BLOCK_SIZE, %o1	! update SRC
	faligndata %f12, %f14, %f44
	faligndata %f14, %f0, %f46
	stda	%f32, [%o0]ASI_BLK_P		! store 64 bytes, bypass cache
	cmp	%o2, BLOCK_SIZE
	bne	%ncc, 2f		! exactly 1 block remaining?
	add	%o0, BLOCK_SIZE, %o0	! update DST
	brz,a	%o3, 3f			! is SRC double aligned?
	ldd	[%o1], %f2

2:
	add	%o5, %o2, %o5		! %o5 was already set to 0 or -8
	add	%o5, %o3, %o5

	membar	#StoreLoad|#StoreStore

	ba	.beginmedloop
	andn	%o5, 7, %o5		! 8 byte aligned count


	! This is when there is exactly 1 block remaining and SRC is aligned
3:
	ldd	[%o1 + 0x8], %f4
	ldd	[%o1 + 0x10], %f6
	fsrc1	%f0, %f32
	ldd	[%o1 + 0x18], %f8
	fsrc1	%f2, %f34
	ldd	[%o1 + 0x20], %f10
	fsrc1	%f4, %f36
	ldd	[%o1 + 0x28], %f12
	fsrc1	%f6, %f38
	ldd	[%o1 + 0x30], %f14
	fsrc1	%f8, %f40
	fsrc1	%f10, %f42
	fsrc1	%f12, %f44
	fsrc1	%f14, %f46
	stda	%f32, [%o0]ASI_BLK_P
	membar	#StoreLoad|#StoreStore
	wr	%o4, 0, %fprs
	retl
	mov	%g1, %o0


	.align 16
	! two nops here causes loop starting at 1f below to be
	! on a cache line boundary, improving performance
	nop
	nop
.xlarge:
	! %o0 I/O DST is 64-byte aligned
	! %o1 I/O 8-byte aligned (and we've set GSR.ALIGN)
	! %d0 I/O already loaded with SRC data from [%o1-8]
	! %o2 I/O count (number of bytes that need to be written)
	! %o3 I   Not written.  If zero, then SRC is double aligned.
	! %o4 I   Not written.  Holds fprs.
	! %o5   O The number of doubles that remain to be written.

	! Load the rest of the current block
	! Recall that %o1 is further into SRC than %o0 is into DST

	! prefetch [%o1 + (3 * BLOCK_SIZE)], 21
	! executed in delay slot for branch to .xlarge
	prefetch [%o1 + (4 * BLOCK_SIZE)], 21
	prefetch [%o1 + (5 * BLOCK_SIZE)], 21
	ldd	[%o1], %f2
	prefetch [%o1 + (6 * BLOCK_SIZE)], 21
	ldd	[%o1 + 0x8], %f4
	faligndata %f0, %f2, %f32
	ldd	[%o1 + 0x10], %f6
	faligndata %f2, %f4, %f34
	ldd	[%o1 + 0x18], %f8
	faligndata %f4, %f6, %f36
	ldd	[%o1 + 0x20], %f10
        or	%g0, -8, %o5		! if %o3 >= 0, %o5 = -8
	faligndata %f6, %f8, %f38
	ldd	[%o1 + 0x28], %f12
	movrlz	%o3, %g0, %o5		! if %o3 < 0, %o5 = 0  (needed later)
	faligndata %f8, %f10, %f40
	ldd	[%o1 + 0x30], %f14
	faligndata %f10, %f12, %f42
	ldd	[%o1 + 0x38], %f0
	sub	%o2, BLOCK_SIZE, %o2	! update count
	prefetch [%o1 + (7 * BLOCK_SIZE)], 21
	add	%o1, BLOCK_SIZE, %o1	! update SRC

	! This point is 32-byte aligned since 24 instructions appear since
	! the previous alignment directive.


	! Main loop.  Write previous block.  Load rest of current block.
	! Some bytes will be loaded that won't yet be written.
1:
	ldd	[%o1], %f2
	faligndata %f12, %f14, %f44
	ldd	[%o1 + 0x8], %f4
	faligndata %f14, %f0, %f46
	stda	%f32, [%o0]ASI_BLK_P
	sub	%o2, BLOCK_SIZE, %o2		! update count
	ldd	[%o1 + 0x10], %f6
	faligndata %f0, %f2, %f32
	ldd	[%o1 + 0x18], %f8
	faligndata %f2, %f4, %f34
	ldd	[%o1 + 0x20], %f10
	faligndata %f4, %f6, %f36
	ldd	[%o1 + 0x28], %f12
	faligndata %f6, %f8, %f38
	ldd	[%o1 + 0x30], %f14
	faligndata %f8, %f10, %f40
	ldd	[%o1 + 0x38], %f0
	faligndata %f10, %f12, %f42
	! offset of 8*BLK+8 bytes works best over range of (src-dst) mod 1K
	prefetch [%o1 + (8 * BLOCK_SIZE) + 8], 21
	add	%o0, BLOCK_SIZE, %o0		! update DST
	cmp	%o2, BLOCK_SIZE + 8
	! second prefetch important to correct for occasional dropped
	! initial prefetches, 5*BLK works best over range of (src-dst) mod 1K
	! strong prefetch prevents drops on Panther, but Jaguar and earlier
	! US-III models treat strong prefetches as weak prefetchs
	! to avoid regressions on customer hardware, we retain the prefetch
	prefetch [%o1 + (5 * BLOCK_SIZE)], 21
	bgu,pt	%ncc, 1b
	add	%o1, BLOCK_SIZE, %o1		! update SRC

	faligndata %f12, %f14, %f44
	faligndata %f14, %f0, %f46
	stda	%f32, [%o0]ASI_BLK_P		! store 64 bytes, bypass cache
	cmp	%o2, BLOCK_SIZE
	bne	%ncc, 2f		! exactly 1 block remaining?
	add	%o0, BLOCK_SIZE, %o0	! update DST
	brz,a	%o3, 3f			! is SRC double aligned?
	ldd	[%o1], %f2

2:
	add	%o5, %o2, %o5		! %o5 was already set to 0 or -8
	add	%o5, %o3, %o5

	membar	#StoreLoad|#StoreStore

	ba	.beginmedloop
	andn	%o5, 7, %o5		! 8 byte aligned count


	! This is when there is exactly 1 block remaining and SRC is aligned
3:
	ldd	[%o1 + 0x8], %f4
	ldd	[%o1 + 0x10], %f6
	fsrc1	%f0, %f32
	ldd	[%o1 + 0x18], %f8
	fsrc1	%f2, %f34
	ldd	[%o1 + 0x20], %f10
	fsrc1	%f4, %f36
	ldd	[%o1 + 0x28], %f12
	fsrc1	%f6, %f38
	ldd	[%o1 + 0x30], %f14
	fsrc1	%f8, %f40
	fsrc1	%f10, %f42
	fsrc1	%f12, %f44
	fsrc1	%f14, %f46
	stda	%f32, [%o0]ASI_BLK_P
	membar	#StoreLoad|#StoreStore
	wr	%o4, 0, %fprs
	retl
	mov	%g1, %o0

	SET_SIZE(memcpy)
