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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

	.file	"memcpy.s"

/*
 * memcpy(s1, s2, len)
 *
 * Copy s2 to s1, always copy n bytes.
 * Note: this does not work for overlapped copies, bcopy() does
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
 *		return ( s );
 *	}
 */

#include <sys/asm_linkage.h>
#include <sys/sun4asi.h>
#include <sys/trap.h>

	ANSI_PRAGMA_WEAK(memmove,function)
	ANSI_PRAGMA_WEAK(memcpy,function)

	ENTRY(memmove)
	cmp	%o1, %o0	! if from address is >= to use forward copy
	bgeu	%ncc, forcpy	! else use backward if ...
	sub	%o0, %o1, %o4	! get difference of two addresses
	cmp	%o2, %o4	! compare size and difference of addresses
	bleu	%ncc, forcpy	! if size is bigger, do overlapped copy
	nop

        !
        ! an overlapped copy that must be done "backwards"
        !
.ovbc:
	mov	%o0, %o5		! save des address for return val
	add     %o1, %o2, %o1           ! get to end of source space
        add     %o0, %o2, %o0           ! get to end of destination space

.chksize:
	cmp	%o2, 8
	bgeu,pn	%ncc, .dbalign
	nop


.byte:
1:	deccc	%o2			! decrement count
	blu,pn	%ncc, exit		! loop until done
	dec	%o0			! decrement to address
	dec	%o1			! decrement from address
        ldub	[%o1], %o3		! read a byte
        ba	1b			! loop until done
	stb	%o3, [%o0]		! write byte

.dbalign:
	andcc	%o0, 7, %o3
	bz	%ncc, .dbbck
	nop
	dec	%o1
	dec	%o0
	dec	%o2
	ldub	[%o1], %o3
	ba	.chksize
	stb	%o3, [%o0]

.dbbck:

        rd      %fprs, %o3              ! o3 = fprs


        ! if fprs.fef == 0, set it. Checking it, reqires 2 instructions.
        ! So set it anyway, without checking.
        wr      %g0, 0x4, %fprs         ! fprs.fef = 1

        alignaddr	%o1, %g0, %g1		! align src
        ldd	[%g1], %d0		! get first 8 byte block
	sub	%g1, 8, %g1
	andn	%o2, 7, %o4
	sub	%o1, %o4, %o1

2:
	sub	%o0, 8, %o0		! since we are at the end
					! when we first enter the loop
        ldd	[%g1], %d2
        faligndata %d2, %d0, %d8	! extract 8 bytes out
        std	%d8, [%o0]		! store it

	sub	%g1, 8, %g1
        sub	%o2, 8, %o2		! 8 less bytes to copy
	cmp	%o2, 8			! or do we have < 8 bytes
        bgeu,pt	%ncc, 2b
	fmovd	%d2, %d0

        and     %o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
        ba      .byte
        wr      %o3, %g0, %fprs         ! fprs = o3 - restore fprs

	SET_SIZE(memmove)


	ENTRY(memcpy)
	ENTRY(__align_cpy_1)
forcpy:
	mov	%o0, %o5		! save des address for return val

	cmp	%o2, 32			! for small counts copy bytes
	bgu,a	%ncc, .alignsrc
	andcc   %o1, 7, %o3             ! is src aligned on a 8 byte bound

.bytecp:
	! Do byte copy
	tst	%o2
	bleu,a,pn %ncc, exit
	nop

1:	ldub	[%o1], %o4
	inc 	%o1
	inc	%o0
	deccc	%o2
	bgu	%ncc, 1b
	stb	%o4, [%o0 - 1]

exit:
	retl
	mov	%o5, %o0

.alignsrc:
        bz      %ncc, .bigcpy		! src already double aligned
	sub     %o3, 8, %o3
        neg     %o3                     ! bytes till src double aligned

        sub     %o2, %o3, %o2           ! update o2 with new count

	! Copy %o3 bytes till double aligned

2:      ldub    [%o1], %o4
        inc     %o1
        inc     %o0
        deccc   %o3
        bgu	%ncc, 2b
        stb     %o4, [%o0 - 1]

	! Now Source (%o1) is double word aligned

.bigcpy: 				! >= 17 bytes to copy
	andcc	%o0, 7, %o3		! is dst aligned on a 8 byte bound
        bz      %ncc, .blkchk		! already double aligned
	sub     %o3, 8, %o3
        neg     %o3                     ! bytes till double aligned

        sub     %o2, %o3, %o2           ! update o2 with new count

	! Copy %o3 bytes till double aligned

3:      ldub    [%o1], %o4
        inc     %o1
        inc     %o0
        deccc   %o3
        bgu	%ncc, 3b
        stb     %o4, [%o0 - 1]

	! Now Destination (%o0) is double word aligned
.blkchk:
	cmp     %o2, 384		! if cnt < 256 + 128 -  no Block ld/st
	bgeu,a	%ncc, blkcpy		!    do double word copy
	subcc	%o0, %o1, %o4		! %o4 = dest - src

	! double word copy - using ldd and faligndata. Copies upto
	! 8 byte multiple count and does byte copy for the residual.
.dwcpy:
	rd	%fprs, %o3		! o3 = fprs

	! if fprs.fef == 0, set it. Checking it, reqires 2 instructions.
	! So set it anyway, without checking.
	wr	%g0, 0x4, %fprs 	! fprs.fef = 1
	andn    %o2, 7, %o4     	! o4 has 8 byte aligned cnt
	sub	%o4, 8, %o4
        alignaddr %o1, %g0, %g1
        ldd     [%g1], %d0
        add     %g1, 8, %g1
4:
        ldd     [%g1], %d2
        add     %g1, 8, %g1
        sub     %o2, 8, %o2
        subcc   %o4, 8, %o4
        faligndata %d0, %d2, %d8
        std     %d8, [%o0]
        add     %o1, 8, %o1
        bz,pn   %ncc, .residcp
        add     %o0, 8, %o0
        ldd     [%g1], %d0
        add     %g1, 8, %g1
        sub     %o2, 8, %o2
        subcc   %o4, 8, %o4
        faligndata %d2, %d0, %d8
        std     %d8, [%o0]
        add     %o1, 8, %o1
        bgu,pn	%ncc, 4b
        add     %o0, 8, %o0

.residcp:				! Do byte copy
	tst	%o2
	bz,a,pn %ncc, dwexit
	nop

5:	ldub	[%o1], %o4
	inc 	%o1
	inc	%o0
	deccc	%o2
	bgu	%ncc, 5b
	stb	%o4, [%o0 - 1]

dwexit:
        and     %o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
        wr      %o3, %g0, %fprs         ! fprs = o3 - restore fprs
	retl
	mov	%o5, %o0

blkcpy:
	! subcc	%o0, %o1, %o4		! in delay slot of branch
	bneg,a,pn %ncc, 1f		! %o4 = abs(%o4)
	neg	%o4
1:
	/*
	 * Compare against 256 since we should be checking block addresses
	 * and (dest & ~63) - (src & ~63) can be 3 blocks even if
	 * src = dest + (64 * 3) + 63.
	 */
	cmp	%o4, 256		! if smaller than 3 blocks skip
	blu,pn	%ncc, .dwcpy		! and do it the slower way
	andcc	%o0, 63, %o3

	save    %sp, -SA(MINFRAME), %sp
        rd      %fprs, %l3              ! l3 = fprs

        ! if fprs.fef == 0, set it. Checking it, reqires 2 instructions.
        ! So set it anyway, without checking.
        wr      %g0, 0x4, %fprs         ! fprs.fef = 1

        bz,pn   %ncc, blalign           ! now block aligned
        sub     %i3, 64, %i3
        neg     %i3                     ! bytes till block aligned
	sub	%i2, %i3, %i2		! update %i2 with new count

	! Copy %i3 bytes till dst is block (64 byte) aligned. use
	! double word copies.

        alignaddr %i1, %g0, %g1
        ldd     [%g1], %d0
        add     %g1, 8, %g1
6:
        ldd     [%g1], %d2
        add     %g1, 8, %g1
        subcc   %i3, 8, %i3
        faligndata %d0, %d2, %d8
        std     %d8, [%i0]
        add     %i1, 8, %i1
        bz,pn   %ncc, blalign
        add     %i0, 8, %i0
        ldd     [%g1], %d0
        add     %g1, 8, %g1
        subcc   %i3, 8, %i3
        faligndata %d2, %d0, %d8
        std     %d8, [%i0]
        add     %i1, 8, %i1
        bgu,pn	%ncc, 6b
        add     %i0, 8, %i0

blalign:
	membar  #StoreLoad
	! %i2 = total length
	! %i3 = blocks  (length - 64) / 64
	! %i4 = doubles remaining  (length - blocks)
	sub	%i2, 64, %i3
	andn	%i3, 63, %i3
	sub	%i2, %i3, %i4
	andn	%i4, 7, %i4
	sub	%i4, 16, %i4
	sub	%i2, %i4, %i2
	sub	%i2, %i3, %i2

	andn	%i1, 0x3F, %l7		! blk aligned address
	alignaddr %i1, %g0, %g0		! gen %gsr

	srl	%i1, 3, %l5		! bits 3,4,5 are now least sig in  %l5
	andcc  	%l5, 7, %l6		! mask everything except bits 1,2 3
	add	%i1, %i4, %i1
	add	%i1, %i3, %i1

	be,a	%ncc, 1f	! branch taken if src is 64-byte aligned
	ldda	[%l7]ASI_BLK_P, %d0

	call	.+8		! get the address of this instruction in %o7
	sll	%l6, 2, %l4
	add	%o7, %l4, %o7
	jmp	%o7 + 16	! jump to the starting ldd instruction
	nop
	ldd	[%l7+8], %d2
	ldd	[%l7+16], %d4
	ldd	[%l7+24], %d6
	ldd	[%l7+32], %d8
	ldd	[%l7+40], %d10
	ldd	[%l7+48], %d12
	ldd	[%l7+56], %d14
1:
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_P, %d16
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_P, %d32
	add	%l7, 64, %l7
	sub	%i3, 128, %i3


        ! switch statement to get us to the right 8 byte blk within a
        ! 64 byte block

	cmp	 %l6, 4
	bgeu,a	 hlf
	cmp	 %l6, 6
	cmp	 %l6, 2
	bgeu,a	 sqtr
	nop
	cmp	 %l6, 1
	be,a	 seg1
	nop
	ba	 seg0
	nop
sqtr:
	be,a	 seg2
	nop
	ba,a	 seg3
	nop

hlf:
	bgeu,a	 fqtr
	nop
	cmp	 %l6, 5
	be,a	 seg5
	nop
	ba	 seg4
	nop
fqtr:
	be,a	 seg6
	nop
	ba	 seg7
	nop

#define	FALIGN_D0			\
	faligndata %d0, %d2, %d48	;\
	faligndata %d2, %d4, %d50	;\
	faligndata %d4, %d6, %d52	;\
	faligndata %d6, %d8, %d54	;\
	faligndata %d8, %d10, %d56	;\
	faligndata %d10, %d12, %d58	;\
	faligndata %d12, %d14, %d60	;\
	faligndata %d14, %d16, %d62

#define	FALIGN_D16			\
	faligndata %d16, %d18, %d48	;\
	faligndata %d18, %d20, %d50	;\
	faligndata %d20, %d22, %d52	;\
	faligndata %d22, %d24, %d54	;\
	faligndata %d24, %d26, %d56	;\
	faligndata %d26, %d28, %d58	;\
	faligndata %d28, %d30, %d60	;\
	faligndata %d30, %d32, %d62

#define	FALIGN_D32			\
	faligndata %d32, %d34, %d48	;\
	faligndata %d34, %d36, %d50	;\
	faligndata %d36, %d38, %d52	;\
	faligndata %d38, %d40, %d54	;\
	faligndata %d40, %d42, %d56	;\
	faligndata %d42, %d44, %d58	;\
	faligndata %d44, %d46, %d60	;\
	faligndata %d46, %d0, %d62

seg0:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D0
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D16
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D32
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg0

0:
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd0
	add	%i0, 64, %i0

1:
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd16
	add	%i0, 64, %i0

2:
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd32
	add	%i0, 64, %i0


#define	FALIGN_D2			\
	faligndata %d2, %d4, %d48	;\
	faligndata %d4, %d6, %d50	;\
	faligndata %d6, %d8, %d52	;\
	faligndata %d8, %d10, %d54	;\
	faligndata %d10, %d12, %d56	;\
	faligndata %d12, %d14, %d58	;\
	faligndata %d14, %d16, %d60	;\
	faligndata %d16, %d18, %d62

#define	FALIGN_D18			\
	faligndata %d18, %d20, %d48	;\
	faligndata %d20, %d22, %d50	;\
	faligndata %d22, %d24, %d52	;\
	faligndata %d24, %d26, %d54	;\
	faligndata %d26, %d28, %d56	;\
	faligndata %d28, %d30, %d58	;\
	faligndata %d30, %d32, %d60	;\
	faligndata %d32, %d34, %d62

#define	FALIGN_D34			\
	faligndata %d34, %d36, %d48	;\
	faligndata %d36, %d38, %d50	;\
	faligndata %d38, %d40, %d52	;\
	faligndata %d40, %d42, %d54	;\
	faligndata %d42, %d44, %d56	;\
	faligndata %d44, %d46, %d58	;\
	faligndata %d46, %d0, %d60	;\
	faligndata %d0, %d2, %d62

seg1:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D2
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D18
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D34
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg1
0:
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd2
	add	%i0, 64, %i0

1:
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd18
	add	%i0, 64, %i0

2:
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd34
	add	%i0, 64, %i0

#define	FALIGN_D4			\
	faligndata %d4, %d6, %d48	;\
	faligndata %d6, %d8, %d50	;\
	faligndata %d8, %d10, %d52	;\
	faligndata %d10, %d12, %d54	;\
	faligndata %d12, %d14, %d56	;\
	faligndata %d14, %d16, %d58	;\
	faligndata %d16, %d18, %d60	;\
	faligndata %d18, %d20, %d62

#define	FALIGN_D20			\
	faligndata %d20, %d22, %d48	;\
	faligndata %d22, %d24, %d50	;\
	faligndata %d24, %d26, %d52	;\
	faligndata %d26, %d28, %d54	;\
	faligndata %d28, %d30, %d56	;\
	faligndata %d30, %d32, %d58	;\
	faligndata %d32, %d34, %d60	;\
	faligndata %d34, %d36, %d62

#define	FALIGN_D36			\
	faligndata %d36, %d38, %d48	;\
	faligndata %d38, %d40, %d50	;\
	faligndata %d40, %d42, %d52	;\
	faligndata %d42, %d44, %d54	;\
	faligndata %d44, %d46, %d56	;\
	faligndata %d46, %d0, %d58	;\
	faligndata %d0, %d2, %d60	;\
	faligndata %d2, %d4, %d62

seg2:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D4
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D20
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D36
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg2

0:
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd4
	add	%i0, 64, %i0

1:
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd20
	add	%i0, 64, %i0

2:
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd36
	add	%i0, 64, %i0


#define	FALIGN_D6			\
	faligndata %d6, %d8, %d48	;\
	faligndata %d8, %d10, %d50	;\
	faligndata %d10, %d12, %d52	;\
	faligndata %d12, %d14, %d54	;\
	faligndata %d14, %d16, %d56	;\
	faligndata %d16, %d18, %d58	;\
	faligndata %d18, %d20, %d60	;\
	faligndata %d20, %d22, %d62

#define	FALIGN_D22			\
	faligndata %d22, %d24, %d48	;\
	faligndata %d24, %d26, %d50	;\
	faligndata %d26, %d28, %d52	;\
	faligndata %d28, %d30, %d54	;\
	faligndata %d30, %d32, %d56	;\
	faligndata %d32, %d34, %d58	;\
	faligndata %d34, %d36, %d60	;\
	faligndata %d36, %d38, %d62

#define	FALIGN_D38			\
	faligndata %d38, %d40, %d48	;\
	faligndata %d40, %d42, %d50	;\
	faligndata %d42, %d44, %d52	;\
	faligndata %d44, %d46, %d54	;\
	faligndata %d46, %d0, %d56	;\
	faligndata %d0, %d2, %d58	;\
	faligndata %d2, %d4, %d60	;\
	faligndata %d4, %d6, %d62

seg3:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D6
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D22
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D38
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg3

0:
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd6
	add	%i0, 64, %i0

1:
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd22
	add	%i0, 64, %i0

2:
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd38
	add	%i0, 64, %i0


#define	FALIGN_D8			\
	faligndata %d8, %d10, %d48	;\
	faligndata %d10, %d12, %d50	;\
	faligndata %d12, %d14, %d52	;\
	faligndata %d14, %d16, %d54	;\
	faligndata %d16, %d18, %d56	;\
	faligndata %d18, %d20, %d58	;\
	faligndata %d20, %d22, %d60	;\
	faligndata %d22, %d24, %d62

#define	FALIGN_D24			\
	faligndata %d24, %d26, %d48	;\
	faligndata %d26, %d28, %d50	;\
	faligndata %d28, %d30, %d52	;\
	faligndata %d30, %d32, %d54	;\
	faligndata %d32, %d34, %d56	;\
	faligndata %d34, %d36, %d58	;\
	faligndata %d36, %d38, %d60	;\
	faligndata %d38, %d40, %d62

#define	FALIGN_D40			\
	faligndata %d40, %d42, %d48	;\
	faligndata %d42, %d44, %d50	;\
	faligndata %d44, %d46, %d52	;\
	faligndata %d46, %d0, %d54	;\
	faligndata %d0, %d2, %d56	;\
	faligndata %d2, %d4, %d58	;\
	faligndata %d4, %d6, %d60	;\
	faligndata %d6, %d8, %d62

seg4:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D8
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D24
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D40
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg4

0:
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd8
	add	%i0, 64, %i0

1:
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd24
	add	%i0, 64, %i0

2:
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd40
	add	%i0, 64, %i0


#define	FALIGN_D10			\
	faligndata %d10, %d12, %d48	;\
	faligndata %d12, %d14, %d50	;\
	faligndata %d14, %d16, %d52	;\
	faligndata %d16, %d18, %d54	;\
	faligndata %d18, %d20, %d56	;\
	faligndata %d20, %d22, %d58	;\
	faligndata %d22, %d24, %d60	;\
	faligndata %d24, %d26, %d62

#define	FALIGN_D26			\
	faligndata %d26, %d28, %d48	;\
	faligndata %d28, %d30, %d50	;\
	faligndata %d30, %d32, %d52	;\
	faligndata %d32, %d34, %d54	;\
	faligndata %d34, %d36, %d56	;\
	faligndata %d36, %d38, %d58	;\
	faligndata %d38, %d40, %d60	;\
	faligndata %d40, %d42, %d62

#define	FALIGN_D42			\
	faligndata %d42, %d44, %d48	;\
	faligndata %d44, %d46, %d50	;\
	faligndata %d46, %d0, %d52	;\
	faligndata %d0, %d2, %d54	;\
	faligndata %d2, %d4, %d56	;\
	faligndata %d4, %d6, %d58	;\
	faligndata %d6, %d8, %d60	;\
	faligndata %d8, %d10, %d62

seg5:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D10
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D26
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D42
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg5

0:
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd10
	add	%i0, 64, %i0

1:
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd26
	add	%i0, 64, %i0

2:
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd42
	add	%i0, 64, %i0


#define	FALIGN_D12			\
	faligndata %d12, %d14, %d48	;\
	faligndata %d14, %d16, %d50	;\
	faligndata %d16, %d18, %d52	;\
	faligndata %d18, %d20, %d54	;\
	faligndata %d20, %d22, %d56	;\
	faligndata %d22, %d24, %d58	;\
	faligndata %d24, %d26, %d60	;\
	faligndata %d26, %d28, %d62

#define	FALIGN_D28			\
	faligndata %d28, %d30, %d48	;\
	faligndata %d30, %d32, %d50	;\
	faligndata %d32, %d34, %d52	;\
	faligndata %d34, %d36, %d54	;\
	faligndata %d36, %d38, %d56	;\
	faligndata %d38, %d40, %d58	;\
	faligndata %d40, %d42, %d60	;\
	faligndata %d42, %d44, %d62

#define	FALIGN_D44			\
	faligndata %d44, %d46, %d48	;\
	faligndata %d46, %d0, %d50	;\
	faligndata %d0, %d2, %d52	;\
	faligndata %d2, %d4, %d54	;\
	faligndata %d4, %d6, %d56	;\
	faligndata %d6, %d8, %d58	;\
	faligndata %d8, %d10, %d60	;\
	faligndata %d10, %d12, %d62

seg6:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D12
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D28
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D44
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg6

0:
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd12
	add	%i0, 64, %i0

1:
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd28
	add	%i0, 64, %i0

2:
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd44
	add	%i0, 64, %i0


#define	FALIGN_D14			\
	faligndata %d14, %d16, %d48	;\
	faligndata %d16, %d18, %d50	;\
	faligndata %d18, %d20, %d52	;\
	faligndata %d20, %d22, %d54	;\
	faligndata %d22, %d24, %d56	;\
	faligndata %d24, %d26, %d58	;\
	faligndata %d26, %d28, %d60	;\
	faligndata %d28, %d30, %d62

#define	FALIGN_D30			\
	faligndata %d30, %d32, %d48	;\
	faligndata %d32, %d34, %d50	;\
	faligndata %d34, %d36, %d52	;\
	faligndata %d36, %d38, %d54	;\
	faligndata %d38, %d40, %d56	;\
	faligndata %d40, %d42, %d58	;\
	faligndata %d42, %d44, %d60	;\
	faligndata %d44, %d46, %d62

#define	FALIGN_D46			\
	faligndata %d46, %d0, %d48	;\
	faligndata %d0, %d2, %d50	;\
	faligndata %d2, %d4, %d52	;\
	faligndata %d4, %d6, %d54	;\
	faligndata %d6, %d8, %d56	;\
	faligndata %d8, %d10, %d58	;\
	faligndata %d10, %d12, %d60	;\
	faligndata %d12, %d14, %d62

seg7:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D14
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D30
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D46
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg7

0:
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd14
	add	%i0, 64, %i0

1:
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd30
	add	%i0, 64, %i0

2:
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd46
	add	%i0, 64, %i0


	!
	! dribble out the last partial block
	!
blkd0:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d0, %d2, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd2:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d2, %d4, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd4:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d4, %d6, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd6:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d6, %d8, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd8:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d8, %d10, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd10:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d10, %d12, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd12:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d12, %d14, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd14:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	fsrc1	%d14, %d0
	ba,a,pt	%ncc, blkleft

blkd16:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d16, %d18, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd18:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d18, %d20, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd20:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d20, %d22, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd22:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d22, %d24, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd24:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d24, %d26, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd26:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d26, %d28, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd28:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d28, %d30, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd30:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	fsrc1	%d30, %d0
	ba,a,pt	%ncc, blkleft
blkd32:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d32, %d34, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd34:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d34, %d36, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd36:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d36, %d38, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd38:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d38, %d40, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd40:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d40, %d42, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd42:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d42, %d44, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd44:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d44, %d46, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd46:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	fsrc1	%d46, %d0

blkleft:
	ldd	[%l7], %d2
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d0, %d2, %d8
	std	%d8, [%i0]
	blu,pn	%ncc, blkdone
	add	%i0, 8, %i0
	ldd	[%l7], %d0
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d2, %d0, %d8
	std	%d8, [%i0]
	bgeu,pt	%ncc, blkleft
	add	%i0, 8, %i0

blkdone:
	tst	%i2
	bz,pt 	%ncc, blkexit
	and	%l3, 0x4, %l3		! fprs.du = fprs.dl = 0

7:      ldub    [%i1], %i4
        inc     %i1
        inc     %i0
        deccc   %i2
        bgu  	%ncc, 7b
        stb     %i4, [%i0 - 1]

blkexit:
        and     %l3, 0x4, %l3           ! fprs.du = fprs.dl = 0
	wr      %l3, %g0, %fprs         ! fprs = l3 - restore fprs.fef
	membar  #StoreLoad|#StoreStore
	ret
	restore %i5, %g0, %o0

	SET_SIZE(memcpy)
	SET_SIZE(__align_cpy_1)
