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

	.file	"memcmp.s"

/*
 * memcmp(s1, s2, len)
 *
 * Compare n bytes:  s1>s2: >0  s1==s2: 0  s1<s2: <0
 *
 * Fast assembler language version of the following C-program for memcmp
 * which represents the `standard' for the C-library.
 *
 *	int
 *	memcmp(const void *s1, const void *s2, size_t n)
 *	{
 *		if (s1 != s2 && n != 0) {
 *			const char *ps1 = s1;
 *			const char *ps2 = s2;
 *			do {
 *				if (*ps1++ != *ps2++)
 *					return(ps1[-1] - ps2[-1]);
 *			} while (--n != 0);
 *		}
 *		return (0);
 *	}
 */

#include <sys/asm_linkage.h>
#include <sys/sun4asi.h>

	ANSI_PRAGMA_WEAK(memcmp,function)

	ENTRY(memcmp)
	cmp	%o0, %o1		! s1 == s2?
	be	%ncc, .cmpeq

	! for small counts byte compare immediately
	cmp	%o2, 48
	bleu,a 	%ncc, .bytcmp
	mov	%o2, %o3		! o3 <= 48

	! Count > 48. We will byte compare (8 + num of bytes to dbl align)
	! bytes. We assume that most miscompares will occur in the 1st 8 bytes

.chkdbl:
        and     %o0, 7, %o4             ! is s1 aligned on a 8 byte bound
	mov	8, %o3			! o2 > 48;  o3 = 8
        sub     %o4, 8, %o4		! o4 = -(num of bytes to dbl align)
	ba	%ncc, .bytcmp
        sub     %o3, %o4, %o3           ! o3 = 8 + (num of bytes to dbl align)


1:      ldub    [%o1], %o5        	! byte compare loop
        inc     %o1
        inc     %o0
	dec	%o2
        cmp     %o4, %o5
	bne	%ncc, .noteq
.bytcmp:
	deccc   %o3
	bgeu,a   %ncc, 1b
        ldub    [%o0], %o4

	! Check to see if there are more bytes to compare
	cmp	%o2, 0			! is o2 > 0
	bgu,a	%ncc, .blkchk		! we should already be dbl aligned
	cmp     %o2, 320                ! if cnt < 256 + 64 -  no Block ld/st
.cmpeq:
        retl                             ! strings compare equal
	sub	%g0, %g0, %o0

.noteq:
	retl				! strings aren't equal
	sub	%o4, %o5, %o0		! return(*s1 - *s2)


        ! Now src1 is Double word aligned
.blkchk:
        bgeu,a   %ncc, blkcmp                  ! do block cmp
        andcc   %o0, 63, %o3            ! is src1 block aligned

        ! double word compare - using ldd and faligndata. Compares upto
        ! 8 byte multiple count and does byte compare for the residual.

.dwcmp:

        rd      %fprs, %o3              ! o3 = fprs

        ! if fprs.fef == 0, set it. Checking it, reqires 2 instructions.
        ! So set it anyway, without checking.
        wr      %g0, 0x4, %fprs         ! fprs.fef = 1

        andn    %o2, 7, %o4             ! o4 has 8 byte aligned cnt
	sub     %o4, 8, %o4
        alignaddr %o1, %g0, %g1
        ldd     [%g1], %d0
4:
        add     %g1, 8, %g1
        ldd     [%g1], %d2
	ldd	[%o0], %d6
        faligndata %d0, %d2, %d8
	fcmpne32 %d6, %d8, %o5
	fsrc1	%d6, %d6		! 2 fsrc1's added since o5 cannot
	fsrc1	%d8, %d8		! be used for 3 cycles else we
	fmovd	%d2, %d0		! create 9 bubbles in the pipeline
	brnz,a,pn %o5, 6f
	sub     %o1, %o0, %o1           ! o1 gets the difference
        subcc   %o4, 8, %o4
        add     %o0, 8, %o0
        add     %o1, 8, %o1
        bgu,pt	%ncc, 4b
        sub     %o2, 8, %o2

.residcmp:
        ba      6f
	sub     %o1, %o0, %o1           ! o1 gets the difference

5:      ldub    [%o0 + %o1], %o5        ! byte compare loop
        inc     %o0
        cmp     %o4, %o5
        bne     %ncc, .dnoteq
6:
        deccc   %o2
        bgeu,a	%ncc, 5b
        ldub    [%o0], %o4

	and     %o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
	wr      %o3, %g0, %fprs         ! fprs = o3 - restore fprs
	retl
	sub	%g0, %g0, %o0		! strings compare equal

.dnoteq:
	and     %o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
	wr      %o3, %g0, %fprs         ! fprs = o3 - restore fprs
	retl
	sub	%o4, %o5, %o0		! return(*s1 - *s2)


blkcmp:
	save    %sp, -SA(MINFRAME), %sp
        rd      %fprs, %l5              ! l5 = fprs

        ! if fprs.fef == 0, set it. Checking it, reqires 2 instructions.
        ! So set it anyway, without checking.
        wr      %g0, 0x4, %fprs         ! fprs.fef = 1

	bz,pn   %ncc, .blalign          ! now block aligned
        sub     %i3, 64, %i3
        neg     %i3                     ! bytes till block aligned

        ! Compare %i3 bytes till dst is block (64 byte) aligned. use
        ! double word compares.

        alignaddr %i1, %g0, %g1
        ldd     [%g1], %d0
7:
        add     %g1, 8, %g1
        ldd     [%g1], %d2
        ldd     [%i0], %d6
        faligndata %d0, %d2, %d8
        fcmpne32 %d6, %d8, %i5
	fsrc1	%d6, %d6		! 2 fsrc1's added since i5 cannot
	fsrc1	%d8, %d8		! be used for 3 cycles else we
	fmovd	%d2, %d0		! create 9 bubbles in the pipeline
        brnz,a,pn  %i5, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        subcc   %i3, 8, %i3
        add     %i0, 8, %i0
        add     %i1, 8, %i1
        bgu,pt	%ncc, 7b
        sub     %i2, 8, %i2

.blalign:

	! src1 is block aligned
        membar  #StoreLoad
        srl     %i1, 3, %l6             ! bits 3,4,5 are now least sig in  %l6
        andcc   %l6, 7, %l6             ! mask everything except bits 1,2 3
        andn    %i2, 63, %i3            ! calc number of blocks
        alignaddr %i1, %g0, %g0         ! gen %gsr
        andn    %i1, 0x3F, %l7          ! blk aligned address
        sub     %i2, %i3, %l2
        andn    %l2, 7, %i4             ! calc doubles left after blkcpy

	be,a	%ncc, 1f	! branch taken if src2 is 64-byte aligned
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
        add     %l7, 64, %l7
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	ldda	[%i0]ASI_BLK_P, %d32
	sub     %i3, 128, %i3

        ! switch statement to get us to the right 8 byte blk within a
        ! 64 byte block

        cmp      %l6, 4
        bgeu,a	hlf
        cmp      %l6, 6
        cmp      %l6, 2
        bgeu,a	sqtr
        nop
        cmp      %l6, 1
        be,a     seg1
        nop
        ba       seg0
        nop
sqtr:
        be,a     seg2
        nop

        ba,a     seg3
        nop

hlf:
        bgeu,a	fqtr
        nop
        cmp      %l6, 5
        be,a     seg5
        nop
        ba       seg4
        nop
fqtr:
        be,a     seg6
        nop
        ba       seg7
        nop

! The fsrc1 instructions are to make sure that the results of the fcmpne32
! are used 3 cycles later - else spitfire adds 9 bubbles.

#define	FCMPNE32_D32_D48			\
	fcmpne32	%d48, %d32, %l0		;\
	fcmpne32	%d50, %d34, %l1		;\
	fcmpne32	%d52, %d36, %l2		;\
	fcmpne32	%d54, %d38, %l3		;\
	brnz,a		%l0, add		;\
	mov		0, %l4			;\
	fcmpne32	%d56, %d40, %l0		;\
	brnz,a		%l1, add		;\
	mov		8, %l4			;\
	fcmpne32	%d58, %d42, %l1		;\
	brnz,a		%l2, add		;\
	mov		16, %l4			;\
	fcmpne32	%d60, %d44, %l2		;\
	brnz,a		%l3, add		;\
	mov		24, %l4			;\
	fcmpne32	%d62, %d46, %l3		;\
	brnz,a		%l0, add		;\
	mov		32, %l4			;\
        fsrc1           %d48, %d48              ;\
	brnz,a		%l1, add		;\
	mov		40, %l4			;\
        fsrc1           %d48, %d48              ;\
	brnz,a		%l2, add		;\
	mov		48, %l4			;\
        fsrc1           %d48, %d48              ;\
	brnz,a		%l3, add		;\
	mov		56, %l4

add:
	add	%l4, %i0, %i0
	add	%l4, %i1, %i1
	ba	.remcmp
	sub	%i1, %i0, %i1

#define FALIGN_D0                       \
        faligndata %d0, %d2, %d48       ;\
        faligndata %d2, %d4, %d50       ;\
        faligndata %d4, %d6, %d52       ;\
        faligndata %d6, %d8, %d54       ;\
        faligndata %d8, %d10, %d56      ;\
        faligndata %d10, %d12, %d58     ;\
        faligndata %d12, %d14, %d60     ;\
        faligndata %d14, %d16, %d62

#define FALIGN_D16                      \
        faligndata %d16, %d18, %d48     ;\
        faligndata %d18, %d20, %d50     ;\
        faligndata %d20, %d22, %d52     ;\
        faligndata %d22, %d24, %d54     ;\
        faligndata %d24, %d26, %d56     ;\
        faligndata %d26, %d28, %d58     ;\
        faligndata %d28, %d30, %d60     ;\
        faligndata %d30, %d0, %d62

seg0:
        FALIGN_D0
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D16
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg0
	ldda	[%i0]ASI_BLK_P, %d32

0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D0
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd16
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D16
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd0
        sub     %i2, 64, %i2

#define FALIGN_D2                       \
        faligndata %d2, %d4, %d48       ;\
        faligndata %d4, %d6, %d50       ;\
        faligndata %d6, %d8, %d52       ;\
        faligndata %d8, %d10, %d54      ;\
        faligndata %d10, %d12, %d56     ;\
        faligndata %d12, %d14, %d58     ;\
        faligndata %d14, %d16, %d60     ;\
        faligndata %d16, %d18, %d62

#define FALIGN_D18                      \
        faligndata %d18, %d20, %d48     ;\
        faligndata %d20, %d22, %d50     ;\
        faligndata %d22, %d24, %d52     ;\
        faligndata %d24, %d26, %d54     ;\
        faligndata %d26, %d28, %d56     ;\
        faligndata %d28, %d30, %d58     ;\
        faligndata %d30, %d0, %d60      ;\
        faligndata %d0, %d2, %d62


seg1:
        FALIGN_D2
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D18
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg1
	ldda	[%i0]ASI_BLK_P, %d32

0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D2
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd18
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D18
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd2
        sub     %i2, 64, %i2

#define FALIGN_D4                       \
        faligndata %d4, %d6, %d48       ;\
        faligndata %d6, %d8, %d50       ;\
        faligndata %d8, %d10, %d52      ;\
        faligndata %d10, %d12, %d54     ;\
        faligndata %d12, %d14, %d56     ;\
        faligndata %d14, %d16, %d58     ;\
        faligndata %d16, %d18, %d60     ;\
        faligndata %d18, %d20, %d62

#define FALIGN_D20                      \
        faligndata %d20, %d22, %d48     ;\
        faligndata %d22, %d24, %d50     ;\
        faligndata %d24, %d26, %d52     ;\
        faligndata %d26, %d28, %d54     ;\
        faligndata %d28, %d30, %d56     ;\
        faligndata %d30, %d0, %d58      ;\
        faligndata %d0, %d2, %d60       ;\
        faligndata %d2, %d4, %d62

seg2:
	FALIGN_D4
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D20
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg2
	ldda	[%i0]ASI_BLK_P, %d32

0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D4
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd20
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D20
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd4
        sub     %i2, 64, %i2

#define FALIGN_D6                       \
        faligndata %d6, %d8, %d48       ;\
        faligndata %d8, %d10, %d50      ;\
        faligndata %d10, %d12, %d52     ;\
        faligndata %d12, %d14, %d54     ;\
        faligndata %d14, %d16, %d56     ;\
        faligndata %d16, %d18, %d58     ;\
        faligndata %d18, %d20, %d60     ;\
        faligndata %d20, %d22, %d62

#define FALIGN_D22                      \
        faligndata %d22, %d24, %d48     ;\
        faligndata %d24, %d26, %d50     ;\
        faligndata %d26, %d28, %d52     ;\
        faligndata %d28, %d30, %d54     ;\
        faligndata %d30, %d0, %d56      ;\
        faligndata %d0, %d2, %d58       ;\
        faligndata %d2, %d4, %d60       ;\
        faligndata %d4, %d6, %d62


seg3:
        FALIGN_D6
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D22
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg3
	ldda	[%i0]ASI_BLK_P, %d32


0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D6
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd22
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D22
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd6
        sub     %i2, 64, %i2

#define FALIGN_D8                       \
        faligndata %d8, %d10, %d48      ;\
        faligndata %d10, %d12, %d50     ;\
        faligndata %d12, %d14, %d52     ;\
        faligndata %d14, %d16, %d54     ;\
        faligndata %d16, %d18, %d56     ;\
        faligndata %d18, %d20, %d58     ;\
        faligndata %d20, %d22, %d60     ;\
        faligndata %d22, %d24, %d62

#define FALIGN_D24                      \
        faligndata %d24, %d26, %d48     ;\
        faligndata %d26, %d28, %d50     ;\
        faligndata %d28, %d30, %d52     ;\
        faligndata %d30, %d0, %d54      ;\
        faligndata %d0, %d2, %d56       ;\
        faligndata %d2, %d4, %d58       ;\
        faligndata %d4, %d6, %d60       ;\
        faligndata %d6, %d8, %d62


seg4:
        FALIGN_D8
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D24
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg4
	ldda	[%i0]ASI_BLK_P, %d32


0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D8
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd24
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D24
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd8
        sub     %i2, 64, %i2

#define FALIGN_D10                      \
        faligndata %d10, %d12, %d48     ;\
        faligndata %d12, %d14, %d50     ;\
        faligndata %d14, %d16, %d52     ;\
        faligndata %d16, %d18, %d54     ;\
        faligndata %d18, %d20, %d56     ;\
        faligndata %d20, %d22, %d58     ;\
        faligndata %d22, %d24, %d60     ;\
        faligndata %d24, %d26, %d62

#define FALIGN_D26                      \
        faligndata %d26, %d28, %d48     ;\
        faligndata %d28, %d30, %d50     ;\
        faligndata %d30, %d0, %d52      ;\
        faligndata %d0, %d2, %d54       ;\
        faligndata %d2, %d4, %d56       ;\
        faligndata %d4, %d6, %d58       ;\
        faligndata %d6, %d8, %d60       ;\
        faligndata %d8, %d10, %d62


seg5:
        FALIGN_D10
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D26
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg5
	ldda	[%i0]ASI_BLK_P, %d32


0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D10
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd26
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D26
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd10
        sub     %i2, 64, %i2

#define FALIGN_D12                      \
        faligndata %d12, %d14, %d48     ;\
        faligndata %d14, %d16, %d50     ;\
        faligndata %d16, %d18, %d52     ;\
        faligndata %d18, %d20, %d54     ;\
        faligndata %d20, %d22, %d56     ;\
        faligndata %d22, %d24, %d58     ;\
        faligndata %d24, %d26, %d60     ;\
        faligndata %d26, %d28, %d62

#define FALIGN_D28                      \
        faligndata %d28, %d30, %d48     ;\
        faligndata %d30, %d0, %d50      ;\
        faligndata %d0, %d2, %d52       ;\
        faligndata %d2, %d4, %d54       ;\
        faligndata %d4, %d6, %d56       ;\
        faligndata %d6, %d8, %d58       ;\
        faligndata %d8, %d10, %d60      ;\
        faligndata %d10, %d12, %d62


seg6:
        FALIGN_D12
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D28
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg6
	ldda	[%i0]ASI_BLK_P, %d32


0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D12
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd28
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D28
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd12
        sub     %i2, 64, %i2

#define FALIGN_D14                      \
        faligndata %d14, %d16, %d48     ;\
        faligndata %d16, %d18, %d50     ;\
        faligndata %d18, %d20, %d52     ;\
        faligndata %d20, %d22, %d54     ;\
        faligndata %d22, %d24, %d56     ;\
        faligndata %d24, %d26, %d58     ;\
        faligndata %d26, %d28, %d60     ;\
        faligndata %d28, %d30, %d62

#define FALIGN_D30                      \
        faligndata %d30, %d0, %d48     ;\
        faligndata %d0, %d2, %d50      ;\
        faligndata %d2, %d4, %d52      ;\
        faligndata %d4, %d6, %d54      ;\
        faligndata %d6, %d8, %d56      ;\
        faligndata %d8, %d10, %d58     ;\
        faligndata %d10, %d12, %d60    ;\
        faligndata %d12, %d14, %d62

seg7:
        FALIGN_D14
        ldda    [%l7]ASI_BLK_P, %d0
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 1f
        sub     %i2, 64, %i2
        ldda    [%i0]ASI_BLK_P, %d32

        FALIGN_D30
        ldda    [%l7]ASI_BLK_P, %d16
        add     %l7, 64, %l7
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
        subcc   %i3, 64, %i3
        bz,pn   %ncc, 0f
        sub     %i2, 64, %i2

        ba	%ncc, seg7
	ldda	[%i0]ASI_BLK_P, %d32

0:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D14
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd30
        sub     %i2, 64, %i2

1:
	ldda	[%i0]ASI_BLK_P, %d32
	membar  #Sync
	FALIGN_D30
	FCMPNE32_D32_D48
        add     %i0, 64, %i0
        add     %i1, 64, %i1
	ba	%ncc, blkd14
        sub     %i2, 64, %i2


blkd0:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d0, %d2, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd2:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d2, %d4, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd4:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d4, %d6, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd6:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d6, %d8, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd8:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d8, %d10, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd10:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d10, %d12, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd12:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d12, %d14, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd14:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        ba,pt 	%ncc, blkleft
	fmovd   %d14, %d0

blkd16:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d16, %d18, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd18:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d18, %d20, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd20:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d20, %d22, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd22:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d22, %d24, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd24:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d24, %d26, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd26:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d26, %d28, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd28:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        faligndata %d28, %d30, %d48
	ldd	[%i0], %d32
	fcmpne32 %d32, %d48, %l1
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	fsrc1	%d32, %d32
	brnz,a	 %l1, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
	sub	%i2, 8, %i2

blkd30:
        subcc   %i4, 8, %i4
        blu,a,pn %ncc, .remcmp
        sub     %i1, %i0, %i1           ! i1 gets the difference
        fmovd   %d30, %d0

	! This loop handles doubles remaining that were not loaded(ldda`ed)
	! in the Block Compare loop
blkleft:
        ldd     [%l7], %d2
        add     %l7, 8, %l7
        faligndata %d0, %d2, %d8
	ldd     [%i0], %d32
        fcmpne32 %d32, %d8, %l1
	fsrc1	%d2, %d0
	fsrc1	%d2, %d0
	fsrc1	%d2, %d0
	brnz,a	%l1, .remcmp
	sub     %i1, %i0, %i1           ! i1 gets the difference
        add     %i0, 8, %i0
        add     %i1, 8, %i1
        subcc   %i4, 8, %i4
        bgeu,pt  %ncc, blkleft
        sub     %i2, 8, %i2

	ba	%ncc, .remcmp
	sub     %i1, %i0, %i1           ! i1 gets the difference

6:      ldub    [%i0 + %i1], %i5        ! byte compare loop
        inc     %i0
        cmp     %i4, %i5
        bne     %ncc, .bnoteq
.remcmp:
        deccc   %i2
        bgeu,a   %ncc, 6b
        ldub    [%i0], %i4

exit:
	and     %l5, 0x4, %l5           ! fprs.du = fprs.dl = 0
	wr      %l5, %g0, %fprs         ! fprs = l5 - restore fprs
	membar  #StoreLoad|#StoreStore
        ret
        restore %g0, %g0, %o0


.bnoteq:
	and     %l5, 0x4, %l5           ! fprs.du = fprs.dl = 0
	wr      %l5, %g0, %fprs         ! fprs = l5 - restore fprs
	membar  #StoreLoad|#StoreStore
	sub	%i4, %i5, %i0		! return(*s1 - *s2)
	ret				! strings aren't equal
	restore %i0, %g0, %o0



	SET_SIZE(memcmp)
