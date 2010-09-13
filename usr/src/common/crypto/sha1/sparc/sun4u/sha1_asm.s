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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/stack.h>

#ifdef _KERNEL

#include <sys/privregs.h>
#include <sys/regset.h>
#include <sys/vis.h>
#include <sys/machthread.h>

#endif /* _KERNEL */

#if defined(lint)

#ifdef _KERNEL

/* ARGSUSED */
int
sha1_savefp(kfpu_t *fpu, int svfp_ok)
{ return(0); }

/* ARGSUSED */
void
sha1_restorefp(kfpu_t *fpu)
{}

#endif /* _KERNEL */

/* ARGSUSED */
void
SHA1TransformVIS(uint64_t *X0, uint64_t *blk, uint32_t *cstate, uint64_t *VIS)
{}

#else /* defined(lint) */

#ifdef _KERNEL

#define	FZERO				\
	fzero	%f0			;\
	fzero	%f2			;\
	faddd	%f0, %f2, %f4		;\
	fmuld	%f0, %f2, %f6		;\
	faddd	%f0, %f2, %f8		;\
	fmuld	%f0, %f2, %f10		;\
	faddd	%f0, %f2, %f12		;\
	fmuld	%f0, %f2, %f14		;\
	faddd	%f0, %f2, %f16		;\
	fmuld	%f0, %f2, %f18		;\
	faddd	%f0, %f2, %f20		;\
	fmuld	%f0, %f2, %f22		;\
	faddd	%f0, %f2, %f24		;\
	fmuld	%f0, %f2, %f26		;\
	faddd	%f0, %f2, %f28		;\
	fmuld	%f0, %f2, %f30		;\
	faddd	%f0, %f2, %f32		;\
	fmuld	%f0, %f2, %f34		;\
	faddd	%f0, %f2, %f36		;\
	fmuld	%f0, %f2, %f38		;\
	faddd	%f0, %f2, %f40		;\
	fmuld	%f0, %f2, %f42		;\
	faddd	%f0, %f2, %f44		;\
	fmuld	%f0, %f2, %f46		;\
	faddd	%f0, %f2, %f48		;\
	fmuld	%f0, %f2, %f50		;\
	faddd	%f0, %f2, %f52		;\
	fmuld	%f0, %f2, %f54		;\
	faddd	%f0, %f2, %f56		;\
	fmuld	%f0, %f2, %f58		;\
	faddd	%f0, %f2, %f60		;\
	fmuld	%f0, %f2, %f62

#include "assym.h"

	ENTRY(sha1_savefp)
	rd	%fprs, %o2
	st	%o2, [%o0 + FPU_FPRS]
	andcc	%o2, FPRS_FEF, %g0
	bz,a,pt	%icc, 1f
	wr	%g0, FPRS_FEF, %fprs
	brz,pt	%o1, 2f
	nop
	rd	%gsr, %o3
	stx	%o3, [%o0 + FPU_GSR]
	stx	%fsr, [%o0 + FPU_FSR]
	BSTORE_FPREGS(%o0, %o4)
1:
	retl
	or	%g0, 1, %o0
2:
	retl
	clr	%o0
	SET_SIZE(sha1_savefp)

	ENTRY(sha1_restorefp)
	ld	[%o0 + FPU_FPRS], %o1
	andcc	%o1, FPRS_FEF, %g0
	bz,pt	%icc, 1f
	nop
	BLOAD_FPREGS(%o0, %o2)
	wr	%o1, 0, %fprs
	ldx	[%o0 + FPU_FSR], %fsr
	ldx	[%o0 + FPU_GSR], %o3
	retl
	wr	%o3, 0, %gsr
1:
	FZERO
	retl
	wr	%o1, 0, %fprs
	SET_SIZE(sha1_restorefp)

#endif /* _KERNEL */

	ENTRY(SHA1TransformVIS)
	save		%sp, -SA(MINFRAME), %sp

	ld		[%i2 + 0], %o0
	mov		5, %g1

	ld		[%i2 + 4], %o1
	alignaddr	%g0, %g1, %g0

	ld		[%i2 + 8], %o2

	ld		[%i2 + 12], %o3

	ld		[%i2 + 16], %o4

	ld		[%i3 + 0 + 16], %g1

! Starting round 0
	sll		%o0, 5, %l0
	and		%o1, %o2, %l1
	ld		[%i1 + (0 * 4)], %l2

	srl		%o0, 27, %l3
	andn		%o3, %o1, %l4
	ld		[%i1 + 0], %f16

	sll		%o1, 30, %l5
	xor		%l1, %l4, %l1
	ld		[%i1 + 4], %f17

	srl		%o1,  2, %l7
	or		%l0, %l3, %l0
	ld		[%i1 + 8], %f30

	add		%l0, %l1, %l0
	add		%o4, %g1, %l1
	ld		[%i1 + 12], %f31

	or		%l5, %l7, %o1
	add		%l0, %l1, %l0
	ld		[%i1 + 16], %f28

	add		%l0, %l2, %o5
	ld		[%i1 + 20], %f29

! Starting round 1
	sll		%o5, 5, %l0
	and		%o0, %o1, %l1
	ld		[%i1 + (1 * 4)], %l2

	srl		%o5, 27, %l3
	andn		%o2, %o0, %l4
	ld		[%i1 + 24], %f26

	sll		%o0, 30, %l5
	xor		%l1, %l4, %l1
	ld		[%i1 + 28], %f27
	fzero		%f52

	srl		%o0,  2, %l7
	or		%l0, %l3, %l0
	ld		[%i1 + 32], %f24

	add		%l0, %l1, %l0
	add		%o3, %g1, %l1
	ld		[%i1 + 36], %f25

	or		%l5, %l7, %o0
	add		%l0, %l1, %l0
	ld		[%i1 + 40], %f22

	add		%l0, %l2, %o4
	ld		[%i1 + 44], %f23

! Starting round 2
	sll		%o4, 5, %l0
	and		%o5, %o0, %l1
	ld		[%i1 + (2 * 4)], %l2

	srl		%o4, 27, %l3
	andn		%o1, %o5, %l4
	ld		[%i1 + 48], %f20

	sll		%o5, 30, %l5
	xor		%l1, %l4, %l1
	ld		[%i1 + 52], %f21

	srl		%o5,  2, %l7
	or		%l0, %l3, %l0
	fxor		%f16, %f30, %f38
	ld		[%i1 + 56], %f18

	add		%l0, %l1, %l0
	add		%o2, %g1, %l1
	fxor		%f28, %f30, %f14
	ld		[%i1 + 60], %f19

	or		%l5, %l7, %o5
	add		%l0, %l1, %l0
	ld		[%i1 + 52], %f0

	add		%l0, %l2, %o3

! Starting round 3
	sll		%o3, 5, %l0
	and		%o4, %o5, %l1
	ld		[%i1 + (3 * 4)], %l2

	srl		%o3, 27, %l3
	andn		%o0, %o4, %l4
	ld		[%i1 + 56], %f1

	sll		%o4, 30, %l5
	xor		%l1, %l4, %l1
	ldd		[%i3 + 8], %f54
	fxor		%f38, %f24, %f38

	srl		%o4,  2, %l7
	or		%l0, %l3, %l0
	ldd		[%i3 + 0], %f50
	fxor		%f14, %f22, %f14

	add		%l0, %l1, %l0
	add		%o1, %g1, %l1
	ld		[%i1 + 60], %f8

	or		%l5, %l7, %o4
	add		%l0, %l1, %l0

	add		%l0, %l2, %o2

! Starting round 4
	and		%o3, %o4, %l1
	sll		%o2, 5, %l0
	ld		[%i1 + (4 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	andn		%o5, %o3, %l4
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	xor		%l1, %l4, %l1
	fxor		%f28, %f30, %f14

	srl		%o3,  2, %l7
	or		%l0, %l3, %l0
	fand		%f50, %f36, %f2

	add		%l0, %l1, %l0
	add		%o0, %g1, %l1
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o3
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	add		%l0, %l2, %o1
! Starting round 5
	and		%o2, %o3, %l1
	sll		%o1, 5, %l0
	ld		[%i1 + (5 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	andn		%o4, %o2, %l4
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	xor		%l1, %l4, %l1
	fpadd32s	%f12, %f12, %f12

	srl		%o2,  2, %l7
	or		%l0, %l3, %l0
	fxor		%f26, %f28, %f38
	fmul8x16	%f2, %f54, %f6

	add		%l0, %l1, %l0
	add		%o5, %g1, %l1
	fxor		%f14, %f22, %f14
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o2
	add		%l0, %l1, %l0
	fmul8x16	%f10, %f54, %f10

	add		%l0, %l2, %o0

! Starting round 6
	and		%o1, %o2, %l1
	sll		%o0, 5, %l0
	ld		[%i1 + (6 * 4)], %l2
	fxor		%f38, %f20, %f38

	srl		%o0, 27, %l3
	andn		%o3, %o1, %l4
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (16*4) + (0)]

	sll		%o1, 30, %l5
	xor		%l1, %l4, %l1
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (16*4) + (4)]

	srl		%o1,  2, %l7
	or		%l0, %l3, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (16*4) + (8)]

	add		%l0, %l1, %l0
	add		%o4, %g1, %l1
	fors		%f4, %f7, %f16

	or		%l5, %l7, %o1
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f17

	add		%l0, %l2, %o5
	fors		%f12, %f11, %f9

! Starting round 7
	and		%o0, %o1, %l1
	sll		%o5, 5, %l0
	ld		[%i1 + (7 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	andn		%o2, %o0, %l4
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	xor		%l1, %l4, %l1
	fxor		%f24, %f26, %f38

	srl		%o0,  2, %l7
	or		%l0, %l3, %l0
	fand		%f50, %f36, %f2

	add		%l0, %l1, %l0
	add		%o3, %g1, %l1
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	add		%l0, %l2, %o4
! Starting round 8
	and		%o5, %o0, %l1
	sll		%o4, 5, %l0
	ld		[%i1 + (8 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	andn		%o1, %o5, %l4
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	xor		%l1, %l4, %l1
	fpadd32s	%f12, %f12, %f12

	srl		%o5,  2, %l7
	or		%l0, %l3, %l0
	fxor		%f22, %f24, %f14
	fmul8x16	%f2, %f54, %f6

	add		%l0, %l1, %l0
	add		%o2, %g1, %l1
	fxor		%f38, %f18, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l1, %l0
	fmovs		%f9, %f30
	fmul8x16	%f10, %f54, %f10

	add		%l0, %l2, %o3

! Starting round 9
	and		%o4, %o5, %l1
	sll		%o3, 5, %l0
	ld		[%i1 + (9 * 4)], %l2
	fxor		%f14, %f16, %f14

	srl		%o3, 27, %l3
	andn		%o0, %o4, %l4
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (19*4) + (4)]

	sll		%o4, 30, %l5
	xor		%l1, %l4, %l1
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (19*4) + (8)]

	srl		%o4,  2, %l7
	or		%l0, %l3, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (19*4) + (0)]

	add		%l0, %l1, %l0
	add		%o1, %g1, %l1
	fors		%f4, %f7, %f28

	or		%l5, %l7, %o4
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f29

	add		%l0, %l2, %o2
	fors		%f12, %f11, %f31

! Starting round 10
	and		%o3, %o4, %l1
	sll		%o2, 5, %l0
	ld		[%i1 + (10 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	andn		%o5, %o3, %l4
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	xor		%l1, %l4, %l1
	fxor		%f22, %f24, %f14

	srl		%o3,  2, %l7
	or		%l0, %l3, %l0
	fand		%f50, %f36, %f2

	add		%l0, %l1, %l0
	add		%o0, %g1, %l1
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o3
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	add		%l0, %l2, %o1

! Starting round 11
	and		%o2, %o3, %l1
	sll		%o1, 5, %l0
	ld		[%i1 + (11 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	andn		%o4, %o2, %l4
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	xor		%l1, %l4, %l1
	fpadd32s	%f12, %f12, %f12

	srl		%o2,  2, %l7
	or		%l0, %l3, %l0
	fxor		%f20, %f22, %f38
	fmul8x16	%f2, %f54, %f6

	add		%l0, %l1, %l0
	add		%o5, %g1, %l1
	fxor		%f14, %f16, %f14
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o2
	add		%l0, %l1, %l0
	fmul8x16	%f10, %f54, %f10

	add		%l0, %l2, %o0

! Starting round 12
	and		%o1, %o2, %l1
	sll		%o0, 5, %l0
	ld		[%i1 + (12 * 4)], %l2
	fxor		%f38, %f30, %f38

	srl		%o0, 27, %l3
	andn		%o3, %o1, %l4
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (22*4) + (0)]

	sll		%o1, 30, %l5
	xor		%l1, %l4, %l1
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (22*4) + (4)]

	srl		%o1,  2, %l7
	or		%l0, %l3, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (22*4) + (8)]

	add		%l0, %l1, %l0
	add		%o4, %g1, %l1
	fors		%f4, %f7, %f26

	or		%l5, %l7, %o1
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f27

	add		%l0, %l2, %o5
	fors		%f12, %f11, %f9

! Starting round 13
	and		%o0, %o1, %l1
	sll		%o5, 5, %l0
	ld		[%i1 + (13 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	andn		%o2, %o0, %l4
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	xor		%l1, %l4, %l1
	fxor		%f18, %f20, %f38

	srl		%o0,  2, %l7
	or		%l0, %l3, %l0
	fand		%f50, %f36, %f2

	add		%l0, %l1, %l0
	add		%o3, %g1, %l1
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	add		%l0, %l2, %o4
! Starting round 14
	and		%o5, %o0, %l1
	sll		%o4, 5, %l0
	ld		[%i1 + (14 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	andn		%o1, %o5, %l4
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	xor		%l1, %l4, %l1
	fpadd32s	%f12, %f12, %f12

	srl		%o5,  2, %l7
	or		%l0, %l3, %l0
	fxor		%f16, %f18, %f14
	fmul8x16	%f2, %f54, %f6

	add		%l0, %l1, %l0
	add		%o2, %g1, %l1
	fxor		%f38, %f28, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l1, %l0
	fmovs		%f9, %f24
	fmul8x16	%f10, %f54, %f10

	add		%l0, %l2, %o3

! Starting round 15
	and		%o4, %o5, %l1
	sll		%o3, 5, %l0
	ld		[%i1 + (15 * 4)], %l2
	fxor		%f14, %f26, %f14

	srl		%o3, 27, %l3
	andn		%o0, %o4, %l4
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (25*4) + (4)]

	sll		%o4, 30, %l5
	xor		%l1, %l4, %l1
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (25*4) + (8)]

	srl		%o4,  2, %l7
	or		%l0, %l3, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (25*4) + (0)]

	add		%l0, %l1, %l0
	add		%o1, %g1, %l1
	fors		%f4, %f7, %f22

	or		%l5, %l7, %o4
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f23

	add		%l0, %l2, %o2
	fors		%f12, %f11, %f25

! Starting round 16
	and		%o3, %o4, %l1
	sll		%o2, 5, %l0
	ld		[%i0 + (16 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	andn		%o5, %o3, %l4
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	xor		%l1, %l4, %l1
	fxor		%f16, %f18, %f14

	srl		%o3,  2, %l7
	or		%l0, %l3, %l0
	fand		%f50, %f36, %f2

	add		%l0, %l1, %l0
	add		%o0, %g1, %l1
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o3
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	add		%l0, %l2, %o1

! Starting round 17
	and		%o2, %o3, %l1
	sll		%o1, 5, %l0
	ld		[%i0 + (17 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	andn		%o4, %o2, %l4
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	xor		%l1, %l4, %l1
	fpadd32s	%f12, %f12, %f12

	srl		%o2,  2, %l7
	or		%l0, %l3, %l0
	fxor		%f30, %f16, %f38
	fmul8x16	%f2, %f54, %f6

	add		%l0, %l1, %l0
	add		%o5, %g1, %l1
	fxor		%f14, %f26, %f14
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o2
	add		%l0, %l1, %l0
	fmul8x16	%f10, %f54, %f10

	add		%l0, %l2, %o0

! Starting round 18
	and		%o1, %o2, %l1
	sll		%o0, 5, %l0
	ld		[%i0 + (18 * 4)], %l2
	fxor		%f38, %f24, %f38

	srl		%o0, 27, %l3
	andn		%o3, %o1, %l4
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (28*4) + (0)]

	sll		%o1, 30, %l5
	xor		%l1, %l4, %l1
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (28*4) + (4)]

	srl		%o1,  2, %l7
	or		%l0, %l3, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (28*4) + (8)]

	add		%l0, %l1, %l0
	add		%o4, %g1, %l1
	fors		%f4, %f7, %f20

	or		%l5, %l7, %o1
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f21

	add		%l0, %l2, %o5
	fors		%f12, %f11, %f9

! Starting round 19
	and		%o0, %o1, %l1
	sll		%o5, 5, %l0
	ld		[%i0 + (19 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	andn		%o2, %o0, %l4
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	xor		%l1, %l4, %l1
	fxor		%f28, %f30, %f38

	srl		%o0,  2, %l7
	or		%l0, %l3, %l0
	fand		%f50, %f36, %f2

	add		%l0, %l1, %l0
	add		%o3, %g1, %l1
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	add		%l0, %l2, %o4

	ld 		[%i3 + 4 + 16], %g1

! Starting round 20
	sll		%o4, 5, %l0
	xor		%o5, %o0, %l1
	ld		[%i0 + (20 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	xor		%l1, %o1, %l1
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f26, %f28, %f14
	fmul8x16	%f2, %f54, %f6

	srl		%o5,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f38, %f22, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3
	fmovs		%f9, %f18
	fmul8x16	%f10, %f54, %f10

! Starting round 21
	sll		%o3, 5, %l0
	xor		%o4, %o5, %l1
	ld		[%i0 + (21 * 4)], %l2

	fxor		%f14, %f20, %f14
	srl		%o3, 27, %l3
	xor		%l1, %o0, %l1
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (31*4) + (4)]

	sll		%o4, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (31*4) + (8)]

	add		%o1, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (31*4) + (0)]

	srl		%o4,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f16

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f5, %f3, %f17

	fors		%f12, %f11, %f19

! Starting round 22
	sll		%o2, 5, %l0
	xor		%o3, %o4, %l1
	ld		[%i0 + (22 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	xor		%l1, %o5, %l1
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f26, %f28, %f14

	add		%o0, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o3,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1

	fpadd32		%f36, %f36, %f4

! Starting round 23
	sll		%o1, 5, %l0
	xor		%o2, %o3, %l1
	ld		[%i0 + (23 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	xor		%l1, %o4, %l1

	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f24, %f26, %f38
	fmul8x16	%f2, %f54, %f6

	srl		%o2,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f14, %f20, %f14
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0
	fmul8x16	%f10, %f54, %f10

! Starting round 24
	sll		%o0, 5, %l0
	xor		%o1, %o2, %l1
	ld		[%i0 + (24 * 4)], %l2

	fxor		%f38, %f18, %f38
	srl		%o0, 27, %l3
	xor		%l1, %o3, %l1
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (34*4) + (0)]

	sll		%o1, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (34*4) + (4)]

	add		%o4, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (34*4) + (8)]

	srl		%o1,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f30

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f5, %f3, %f31

	fors		%f12, %f11, %f9

! Starting round 25
	sll		%o5, 5, %l0
	xor		%o0, %o1, %l1
	ld		[%i0 + (25 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	xor		%l1, %o2, %l1
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f22, %f24, %f38

	add		%o3, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o0,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4

	fpadd32		%f36, %f36, %f4

! Starting round 26
	sll		%o4, 5, %l0
	xor		%o5, %o0, %l1
	ld		[%i0 + (26 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	xor		%l1, %o1, %l1

	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f20, %f22, %f14
	fmul8x16	%f2, %f54, %f6

	srl		%o5,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f38, %f16, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3
	fmovs		%f9, %f28
	fmul8x16	%f10, %f54, %f10

! Starting round 27
	sll		%o3, 5, %l0
	xor		%o4, %o5, %l1
	ld		[%i0 + (27 * 4)], %l2

	fxor		%f14, %f30, %f14
	srl		%o3, 27, %l3
	xor		%l1, %o0, %l1
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (37*4) + (4)]

	sll		%o4, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (37*4) + (8)]

	add		%o1, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (37*4) + (0)]

	srl		%o4,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f26

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f5, %f3, %f27

	fors		%f12, %f11, %f29

! Starting round 28
	sll		%o2, 5, %l0
	xor		%o3, %o4, %l1
	ld		[%i0 + (28 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	xor		%l1, %o5, %l1
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f20, %f22, %f14

	add		%o0, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o3,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1

	fpadd32		%f36, %f36, %f4

! Starting round 29
	sll		%o1, 5, %l0
	xor		%o2, %o3, %l1
	ld		[%i0 + (29 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	xor		%l1, %o4, %l1

	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f18, %f20, %f38
	fmul8x16	%f2, %f54, %f6

	srl		%o2,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f14, %f30, %f14
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0
	fmul8x16	%f10, %f54, %f10

! Starting round 30
	sll		%o0, 5, %l0
	xor		%o1, %o2, %l1
	ld		[%i0 + (30 * 4)], %l2

	fxor		%f38, %f28, %f38
	srl		%o0, 27, %l3
	xor		%l1, %o3, %l1
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (40*4) + (0)]

	sll		%o1, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (40*4) + (4)]

	add		%o4, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (40*4) + (8)]

	srl		%o1,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f24

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f5, %f3, %f25

	fors		%f12, %f11, %f9

! Starting round 31
	sll		%o5, 5, %l0
	xor		%o0, %o1, %l1
	ld		[%i0 + (31 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	xor		%l1, %o2, %l1
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f16, %f18, %f38

	add		%o3, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o0,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4
	fpadd32		%f36, %f36, %f4

! Starting round 32
	sll		%o4, 5, %l0
	xor		%o5, %o0, %l1
	ld		[%i0 + (32 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	xor		%l1, %o1, %l1
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f30, %f16, %f14
	fmul8x16	%f2, %f54, %f6

	srl		%o5,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f38, %f26, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3
	fmovs		%f9, %f22
	fmul8x16	%f10, %f54, %f10

! Starting round 33
	sll		%o3, 5, %l0
	xor		%o4, %o5, %l1
	ld		[%i0 + (33 * 4)], %l2
	fxor		%f14, %f24, %f14

	srl		%o3, 27, %l3
	xor		%l1, %o0, %l1
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (43*4) + (4)]

	sll		%o4, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (43*4) + (8)]

	add		%o1, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (43*4) + (0)]

	srl		%o4,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f20

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f5, %f3, %f21

	fors		%f12, %f11, %f23

! Starting round 34
	sll		%o2, 5, %l0
	xor		%o3, %o4, %l1
	ld		[%i0 + (34 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	xor		%l1, %o5, %l1
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f30, %f16, %f14

	add		%o0, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o3,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1
	fpadd32		%f36, %f36, %f4

! Starting round 35
	sll		%o1, 5, %l0
	xor		%o2, %o3, %l1
	ld		[%i0 + (35 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	xor		%l1, %o4, %l1
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f28, %f30, %f38
	fmul8x16	%f2, %f54, %f6

	srl		%o2,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f14, %f24, %f14
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0
	fmul8x16	%f10, %f54, %f10

! Starting round 36
	sll		%o0, 5, %l0
	xor		%o1, %o2, %l1
	ld		[%i0 + (36 * 4)], %l2
	fxor		%f38, %f22, %f38

	srl		%o0, 27, %l3
	xor		%l1, %o3, %l1
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (46*4) + (0)]

	sll		%o1, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (46*4) + (4)]

	add		%o4, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (46*4) + (8)]

	srl		%o1,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f18

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f5, %f3, %f19

	fors		%f12, %f11, %f9

! Starting round 37
	sll		%o5, 5, %l0
	xor		%o0, %o1, %l1
	ld		[%i0 + (37 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	xor		%l1, %o2, %l1
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f26, %f28, %f38

	add		%o3, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o0,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4
	fpadd32		%f36, %f36, %f4

! Starting round 38
	sll		%o4, 5, %l0
	xor		%o5, %o0, %l1
	ld		[%i0 + (38 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	xor		%l1, %o1, %l1
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f24, %f26, %f14
	fmul8x16	%f2, %f54, %f6

	srl		%o5,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f38, %f20, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3
	fmovs		%f9, %f16
	fmul8x16	%f10, %f54, %f10

! Starting round 39
	sll		%o3, 5, %l0
	xor		%o4, %o5, %l1
	ld		[%i0 + (39 * 4)], %l2
	fxor		%f14, %f18, %f14

	srl		%o3, 27, %l3
	xor		%l1, %o0, %l1
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (49*4) + (4)]

	sll		%o4, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (49*4) + (8)]

	add		%o1, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (49*4) + (0)]

	srl		%o4,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f30

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f5, %f3, %f31

	fors		%f12, %f11, %f17
	ld 		[%i3 + 8 + 16], %g1

! Starting round 40
	sll		%o2, 5, %l0
	and		%o3, %o4, %l1
	ld		[%i0 + (40 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	or		%o3, %o4, %l4
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	and		%l4, %o5, %l4
	fxor		%f24, %f26, %f14

	add		%o0, %g1, %l6
	or		%l1, %l4, %l1
	fand		%f50, %f36, %f2

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fand		%f50, %f12, %f10

	srl		%o3,  2, %l7
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1

! Starting round 41
	sll		%o1, 5, %l0
	and		%o2, %o3, %l1
	ld		[%i0 + (41 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	or		%o2, %o3, %l4
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	and		%l4, %o4, %l4
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l6
	or		%l1, %l4, %l1
	fxor		%f22, %f24, %f38
	fmul8x16	%f2, %f54, %f6

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fxor		%f14, %f18, %f14
	fmul8x16	%f3, %f54, %f2

	srl		%o2,  2, %l7
	add		%l0, %l1, %l0
	fmul8x16	%f10, %f54, %f10

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0

! Starting round 42
	sll		%o0, 5, %l0
	and		%o1, %o2, %l1
	ld		[%i0 + (42 * 4)], %l2
	fxor		%f38, %f16, %f38

	srl		%o0, 27, %l3
	or		%o1, %o2, %l4
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (52*4) +(0)]

	sll		%o1, 30, %l5
	and		%l4, %o3, %l4
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (52*4) + (4)]

	add		%o4, %g1, %l6
	or		%l1, %l4, %l1
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (52*4) + (8)]

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fors		%f4, %f7, %f28

	srl		%o1,  2, %l7
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f29

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f12, %f11, %f9

! Starting round 43
	sll		%o5, 5, %l0
	and		%o0, %o1, %l1
	ld		[%i0 + (43 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	or		%o0, %o1, %l4
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	and		%l4, %o2, %l4
	fxor		%f20, %f22, %f38

	add		%o3, %g1, %l6
	or		%l1, %l4, %l1
	fand		%f50, %f36, %f2

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fand		%f50, %f12, %f10

	srl		%o0,  2, %l7
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4

! Starting round 44
	sll		%o4, 5, %l0
	and		%o5, %o0, %l1
	ld		[%i0 + (44 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	or		%o5, %o0, %l4
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	and		%l4, %o1, %l4
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l6
	or		%l1, %l4, %l1
	fxor		%f18, %f20, %f14
	fmul8x16	%f2, %f54, %f6

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fxor		%f38, %f30, %f38
	fmul8x16	%f3, %f54, %f2

	srl		%o5,  2, %l7
	add		%l0, %l1, %l0
	fmovs		%f9, %f26
	fmul8x16	%f10, %f54, %f10

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3

! Starting round 45
	sll		%o3, 5, %l0
	and		%o4, %o5, %l1
	ld		[%i0 + (45 * 4)], %l2
	fxor		%f14, %f28, %f14

	srl		%o3, 27, %l3
	or		%o4, %o5, %l4
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (55*4) +(4)]

	sll		%o4, 30, %l5
	and		%l4, %o0, %l4
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (55*4) + (8)]

	add		%o1, %g1, %l6
	or		%l1, %l4, %l1
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (55*4) + (0)]

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fors		%f4, %f7, %f24

	srl		%o4,  2, %l7
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f25

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f12, %f11, %f27

! Starting round 46
	sll		%o2, 5, %l0
	and		%o3, %o4, %l1
	ld		[%i0 + (46 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	or		%o3, %o4, %l4
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	and		%l4, %o5, %l4
	fxor		%f18, %f20, %f14

	add		%o0, %g1, %l6
	or		%l1, %l4, %l1
	fand		%f50, %f36, %f2

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fand		%f50, %f12, %f10

	srl		%o3,  2, %l7
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1

! Starting round 47
	sll		%o1, 5, %l0
	and		%o2, %o3, %l1
	ld		[%i0 + (47 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	or		%o2, %o3, %l4
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	and		%l4, %o4, %l4
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l6
	or		%l1, %l4, %l1
	fxor		%f16, %f18, %f38
	fmul8x16	%f2, %f54, %f6

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fxor		%f14, %f28, %f14
	fmul8x16	%f3, %f54, %f2

	srl		%o2,  2, %l7
	add		%l0, %l1, %l0
	fmul8x16	%f10, %f54, %f10

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0

! Starting round 48
	sll		%o0, 5, %l0
	and		%o1, %o2, %l1
	ld		[%i0 + (48 * 4)], %l2
	fxor		%f38, %f26, %f38

	srl		%o0, 27, %l3
	or		%o1, %o2, %l4
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (58*4) +(0)]

	sll		%o1, 30, %l5
	and		%l4, %o3, %l4
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (58*4) + (4)]

	add		%o4, %g1, %l6
	or		%l1, %l4, %l1
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (58*4) + (8)]

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fors		%f4, %f7, %f22

	srl		%o1,  2, %l7
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f23

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f12, %f11, %f9

! Starting round 49
	sll		%o5, 5, %l0
	and		%o0, %o1, %l1
	ld		[%i0 + (49 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	or		%o0, %o1, %l4
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	and		%l4, %o2, %l4
	fxor		%f30, %f16, %f38

	add		%o3, %g1, %l6
	or		%l1, %l4, %l1
	fand		%f50, %f36, %f2

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fand		%f50, %f12, %f10

	srl		%o0,  2, %l7
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4

! Starting round 50
	sll		%o4, 5, %l0
	and		%o5, %o0, %l1
	ld		[%i0 + (50 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	or		%o5, %o0, %l4
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	and		%l4, %o1, %l4
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l6
	or		%l1, %l4, %l1
	fxor		%f28, %f30, %f14
	fmul8x16	%f2, %f54, %f6

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fxor		%f38, %f24, %f38
	fmul8x16	%f3, %f54, %f2

	srl		%o5,  2, %l7
	add		%l0, %l1, %l0
	fmovs		%f9, %f20
	fmul8x16	%f10, %f54, %f10

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3

! Starting round 51
	sll		%o3, 5, %l0
	and		%o4, %o5, %l1
	ld		[%i0 + (51 * 4)], %l2
	fxor		%f14, %f22, %f14

	srl		%o3, 27, %l3
	or		%o4, %o5, %l4
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (61*4) +(4)]

	sll		%o4, 30, %l5
	and		%l4, %o0, %l4
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (61*4) + (8)]

	add		%o1, %g1, %l6
	or		%l1, %l4, %l1
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (61*4) + (0)]

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fors		%f4, %f7, %f18

	srl		%o4,  2, %l7
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f19

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f12, %f11, %f21

! Starting round 52
	sll		%o2, 5, %l0
	and		%o3, %o4, %l1
	ld		[%i0 + (52 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	or		%o3, %o4, %l4
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	and		%l4, %o5, %l4
	fxor		%f28, %f30, %f14

	add		%o0, %g1, %l6
	or		%l1, %l4, %l1
	fand		%f50, %f36, %f2

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fand		%f50, %f12, %f10

	srl		%o3,  2, %l7
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1

! Starting round 53
	sll		%o1, 5, %l0
	and		%o2, %o3, %l1
	ld		[%i0 + (53 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	or		%o2, %o3, %l4
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	and		%l4, %o4, %l4
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l6
	or		%l1, %l4, %l1
	fxor		%f26, %f28, %f38
	fmul8x16	%f2, %f54, %f6

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fxor		%f14, %f22, %f14
	fmul8x16	%f3, %f54, %f2

	srl		%o2,  2, %l7
	add		%l0, %l1, %l0
	fmul8x16	%f10, %f54, %f10

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0

! Starting round 54
	sll		%o0, 5, %l0
	and		%o1, %o2, %l1
	ld		[%i0 + (54 * 4)], %l2
	fxor		%f38, %f20, %f38

	srl		%o0, 27, %l3
	or		%o1, %o2, %l4
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (64*4) +(0)]

	sll		%o1, 30, %l5
	and		%l4, %o3, %l4
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (64*4) + (4)]

	add		%o4, %g1, %l6
	or		%l1, %l4, %l1
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (64*4) + (8)]

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fors		%f4, %f7, %f16

	srl		%o1,  2, %l7
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f17

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f12, %f11, %f9

! Starting round 55
	sll		%o5, 5, %l0
	and		%o0, %o1, %l1
	ld		[%i0 + (55 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	or		%o0, %o1, %l4
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	and		%l4, %o2, %l4
	fxor		%f24, %f26, %f38

	add		%o3, %g1, %l6
	or		%l1, %l4, %l1
	fand		%f50, %f36, %f2

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fand		%f50, %f12, %f10

	srl		%o0,  2, %l7
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4

! Starting round 56
	sll		%o4, 5, %l0
	and		%o5, %o0, %l1
	ld		[%i0 + (56 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	or		%o5, %o0, %l4
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	and		%l4, %o1, %l4
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l6
	or		%l1, %l4, %l1
	fxor		%f22, %f24, %f14
	fmul8x16	%f2, %f54, %f6

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fxor		%f38, %f18, %f38
	fmul8x16	%f3, %f54, %f2

	srl		%o5,  2, %l7
	add		%l0, %l1, %l0
	fmovs		%f9, %f30
	fmul8x16	%f10, %f54, %f10

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3

! Starting round 57
	sll		%o3, 5, %l0
	and		%o4, %o5, %l1
	ld		[%i0 + (57 * 4)], %l2
	fxor		%f14, %f16, %f14

	srl		%o3, 27, %l3
	or		%o4, %o5, %l4
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (67*4) +(4)]

	sll		%o4, 30, %l5
	and		%l4, %o0, %l4
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (67*4) + (8)]

	add		%o1, %g1, %l6
	or		%l1, %l4, %l1
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (67*4) + (0)]

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fors		%f4, %f7, %f28

	srl		%o4,  2, %l7
	add		%l0, %l1, %l0
	fors		%f5, %f3, %f29

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f12, %f11, %f31

! Starting round 58
	sll		%o2, 5, %l0
	and		%o3, %o4, %l1
	ld		[%i0 + (58 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	or		%o3, %o4, %l4
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	and		%l4, %o5, %l4
	fxor		%f22, %f24, %f14

	add		%o0, %g1, %l6
	or		%l1, %l4, %l1
	fand		%f50, %f36, %f2

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fand		%f50, %f12, %f10

	srl		%o3,  2, %l7
	add		%l0, %l1, %l0
	fpadd32		%f36, %f36, %f4

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1

! Starting round 59
	sll		%o1, 5, %l0
	and		%o2, %o3, %l1
	ld		[%i0 + (59 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	or		%o2, %o3, %l4
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	and		%l4, %o4, %l4
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l6
	or		%l1, %l4, %l1
	fxor		%f20, %f22, %f38
	fmul8x16	%f2, %f54, %f6

	or		%l0, %l3, %l0
	add		%l6, %l1, %l1
	fxor		%f14, %f16, %f14
	fmul8x16	%f3, %f54, %f2

	srl		%o2,  2, %l7
	add		%l0, %l1, %l0
	fmul8x16	%f10, %f54, %f10

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0
	ld 		[%i3 + 12 + 16], %g1

! Starting round 60
	sll		%o0, 5, %l0
	xor		%o1, %o2, %l1
	ld		[%i0 + (60 * 4)], %l2

	fxor		%f38, %f30, %f38
	srl		%o0, 27, %l3
	xor		%l1, %o3, %l1
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (70*4) + (0)]

	sll		%o1, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (70*4) + (4)]

	add		%o4, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (70*4) + (8)]

	srl		%o1,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f26

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f5, %f3, %f27

	fors		%f12, %f11, %f9

! Starting round 61
	sll		%o5, 5, %l0
	xor		%o0, %o1, %l1
	ld		[%i0 + (61 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	xor		%l1, %o2, %l1
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f18, %f20, %f38

	add		%o3, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o0,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4
	fpadd32		%f36, %f36, %f4

! Starting round 62
	sll		%o4, 5, %l0
	xor		%o5, %o0, %l1
	ld		[%i0 + (62 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	xor		%l1, %o1, %l1
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f16, %f18, %f14
	fmul8x16	%f2, %f54, %f6

	srl		%o5,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f38, %f28, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3
	fmovs		%f9, %f24
	fmul8x16	%f10, %f54, %f10

! Starting round 63
	sll		%o3, 5, %l0
	xor		%o4, %o5, %l1
	ld		[%i0 + (63 * 4)], %l2
	fxor		%f14, %f26, %f14

	srl		%o3, 27, %l3
	xor		%l1, %o0, %l1
	fors		%f4, %f7, %f1
	st		%f1, [%i0 + (73*4) + (4)]

	sll		%o4, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f8
	st		%f8, [%i0 + (73*4) + (8)]

	add		%o1, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (73*4) + (0)]

	srl		%o4,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f22

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2
	fors		%f5, %f3, %f23

	fors		%f12, %f11, %f25

! Starting round 64
	sll		%o2, 5, %l0
	xor		%o3, %o4, %l1
	ld		[%i0 + (64 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o2, 27, %l3
	xor		%l1, %o5, %l1
	fxors		%f14, %f8, %f12

	sll		%o3, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f16, %f18, %f14

	add		%o0, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o3,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o3
	add		%l0, %l2, %o1
	fpadd32		%f36, %f36, %f4

! Starting round 65
	sll		%o1, 5, %l0
	xor		%o2, %o3, %l1
	ld		[%i0 + (65 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o1, 27, %l3
	xor		%l1, %o4, %l1
	faligndata	%f52, %f10, %f10

	sll		%o2, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o5, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f30, %f16, %f38
	fmul8x16	%f2, %f54, %f6

	srl		%o2,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f14, %f26, %f14
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o2
	add		%l0, %l2, %o0
	fmul8x16	%f10, %f54, %f10

! Starting round 66
	sll		%o0, 5, %l0
	xor		%o1, %o2, %l1
	ld		[%i0 + (66 * 4)], %l2
	fxor		%f38, %f24, %f38

	srl		%o0, 27, %l3
	xor		%l1, %o3, %l1
	fors		%f4, %f7, %f8
	st		%f8, [%i0 + (76*4) + (0)]

	sll		%o1, 30, %l5
	or		%l0, %l3, %l0
	fors		%f5, %f3, %f0
	st		%f0, [%i0 + (76*4) + (4)]

	add		%o4, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f1
	st		%f1, [%i0 + (76*4) + (8)]

	srl		%o1,  2, %l7
	add		%l0, %l4, %l0
	fors		%f4, %f7, %f20

	or		%l5, %l7, %o1
	add		%l0, %l2, %o5
	fors		%f5, %f3, %f21

	fors		%f12, %f11, %f9

! Starting round 67
	sll		%o5, 5, %l0
	xor		%o0, %o1, %l1
	ld		[%i0 + (67 * 4)], %l2
	fxor		%f38, %f0, %f36

	srl		%o5, 27, %l3
	xor		%l1, %o2, %l1
	fxors		%f15, %f8, %f12

	sll		%o0, 30, %l5
	or		%l0, %l3, %l0
	fxor		%f28, %f30, %f38

	add		%o3, %g1, %l4
	add		%l0, %l1, %l0
	fand		%f50, %f36, %f2

	srl		%o0,  2, %l7
	add		%l0, %l4, %l0
	fand		%f50, %f12, %f10

	or		%l5, %l7, %o0
	add		%l0, %l2, %o4
	fpadd32		%f36, %f36, %f4

! Starting round 68
	sll		%o4, 5, %l0
	xor		%o5, %o0, %l1
	ld		[%i0 + (68 * 4)], %l2
	faligndata	%f52, %f2, %f2

	srl		%o4, 27, %l3
	xor		%l1, %o1, %l1
	faligndata	%f52, %f10, %f10

	sll		%o5, 30, %l5
	or		%l0, %l3, %l0
	fpadd32s	%f12, %f12, %f12

	add		%o2, %g1, %l4
	add		%l0, %l1, %l0
	fxor		%f26, %f28, %f14
	fmul8x16	%f2, %f54, %f6

	srl		%o5,  2, %l7
	add		%l0, %l4, %l0
	fxor		%f38, %f22, %f38
	fmul8x16	%f3, %f54, %f2

	or		%l5, %l7, %o5
	add		%l0, %l2, %o3
	fmovs		%f9, %f18
	fmul8x16	%f10, %f54, %f10

! Starting round 69
	sll		%o3, 5, %l0
	xor		%o4, %o5, %l1
	ld		[%i0 + (69 * 4)], %l2

	fxor		%f14, %f20, %f14
	srl		%o3, 27, %l3
	xor		%l1, %o0, %l1

	sll		%o4, 30, %l5
	or		%l0, %l3, %l0

	add		%o1, %g1, %l4
	add		%l0, %l1, %l0
	fors		%f12, %f11, %f0
	st		%f0, [%i0 + (79*4) + (0)]

	srl		%o4,  2, %l7
	add		%l0, %l4, %l0

	or		%l5, %l7, %o4
	add		%l0, %l2, %o2

! Starting round 70
	sll		%o2, 5, %l0
	xor		%o3, %o4, %l1
	ld		[%i0 + (70 * 4)], %l2

	srl		%o2, 27, %l3
	xor		%l1, %o5, %l1

	sll		%o3, 30, %l5
	or		%l0, %l3, %l0

	srl		%o3,  2, %l7
	add		%l0, %l1, %l0

	add		%o0, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o1
	or		%l5, %l7, %o3

! Starting round 71
	sll		%o1, 5, %l0
	xor		%o2, %o3, %l1
	ld		[%i0 + (71 * 4)], %l2

	srl		%o1, 27, %l3
	xor		%l1, %o4, %l1

	sll		%o2, 30, %l5
	or		%l0, %l3, %l0

	srl		%o2,  2, %l7
	add		%l0, %l1, %l0

	add		%o5, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o0
	or		%l5, %l7, %o2

! Starting round 72
	sll		%o0, 5, %l0
	xor		%o1, %o2, %l1
	ld		[%i0 + (72 * 4)], %l2

	srl		%o0, 27, %l3
	xor		%l1, %o3, %l1

	sll		%o1, 30, %l5
	or		%l0, %l3, %l0

	srl		%o1,  2, %l7
	add		%l0, %l1, %l0

	add		%o4, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o5
	or		%l5, %l7, %o1

! Starting round 73
	sll		%o5, 5, %l0
	xor		%o0, %o1, %l1
	ld		[%i0 + (73 * 4)], %l2

	srl		%o5, 27, %l3
	xor		%l1, %o2, %l1

	sll		%o0, 30, %l5
	or		%l0, %l3, %l0

	srl		%o0,  2, %l7
	add		%l0, %l1, %l0

	add		%o3, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o4
	or		%l5, %l7, %o0

! Starting round 74
	sll		%o4, 5, %l0
	xor		%o5, %o0, %l1
	ld		[%i0 + (74 * 4)], %l2

	srl		%o4, 27, %l3
	xor		%l1, %o1, %l1

	sll		%o5, 30, %l5
	or		%l0, %l3, %l0

	srl		%o5,  2, %l7
	add		%l0, %l1, %l0

	add		%o2, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o3
	or		%l5, %l7, %o5

! Starting round 75
	sll		%o3, 5, %l0
	xor		%o4, %o5, %l1
	ld		[%i0 + (75 * 4)], %l2

	srl		%o3, 27, %l3
	xor		%l1, %o0, %l1

	sll		%o4, 30, %l5
	or		%l0, %l3, %l0

	srl		%o4,  2, %l7
	add		%l0, %l1, %l0

	add		%o1, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o2
	or		%l5, %l7, %o4

! Starting round 76
	sll		%o2, 5, %l0
	xor		%o3, %o4, %l1
	ld		[%i0 + (76 * 4)], %l2

	srl		%o2, 27, %l3
	xor		%l1, %o5, %l1

	sll		%o3, 30, %l5
	or		%l0, %l3, %l0

	srl		%o3,  2, %l7
	add		%l0, %l1, %l0

	add		%o0, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o1
	or		%l5, %l7, %o3

! Starting round 77
	sll		%o1, 5, %l0
	xor		%o2, %o3, %l1
	ld		[%i0 + (77 * 4)], %l2

	srl		%o1, 27, %l3
	xor		%l1, %o4, %l1

	sll		%o2, 30, %l5
	or		%l0, %l3, %l0

	srl		%o2,  2, %l7
	add		%l0, %l1, %l0

	add		%o5, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o0
	or		%l5, %l7, %o2

! Starting round 78
	sll		%o0, 5, %l0
	xor		%o1, %o2, %l1
	ld		[%i0 + (78 * 4)], %l2

	srl		%o0, 27, %l3
	xor		%l1, %o3, %l1

	sll		%o1, 30, %l5
	or		%l0, %l3, %l0

	srl		%o1,  2, %l7
	add		%l0, %l1, %l0

	add		%o4, %g1, %l1
	add		%l0, %l2, %l0

	add		%l0, %l1, %o5
	or		%l5, %l7, %o1

! Starting round 79
	sll		%o5, 5, %l0
	xor		%o0, %o1, %l1
	ld		[%i0 + (79 * 4)], %l2

	srl		%o5, 27, %l3
	xor		%l1, %o2, %l1
	ld		[%i2 + 0], %i0

	sll		%o0, 30, %l5
	or		%l0, %l3, %l0
	ld		[%i2 + 4], %i1

	srl		%o0,  2, %l7
	add		%l0, %l1, %l0
	ld		[%i2 + 8], %i3

	add		%o3, %g1, %l1
	add		%l0, %l2, %l0
	ld		[%i2 + 12], %i4

	add		%l0, %l1, %o4
	or		%l5, %l7, %o0
	ld		[%i2 + 16], %i5

! Compute final hash values for this block and store back to SHA1_CTX
	add 		%i0, %o4, %o4
	st 		%o4, [%i2 + 0]

	add 		%i1, %o5, %o5
	st 		%o5, [%i2 + 4]

	add 		%i3, %o0, %o0
	st 		%o0, [%i2 + 8]

	add 		%i4, %o1, %o1
	st 		%o1, [%i2 + 12]

	add 		%i5, %o2, %o2
	st 		%o2, [%i2 + 16]

	ret
	restore
	SET_SIZE(SHA1TransformVIS)

#endif	/* defined(lint) */
