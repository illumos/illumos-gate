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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"__vsin.S"

#include "libm.h"

	RO_DATA
	.align	64
constants:
	.word	0x3ec718e3,0xa6972785
	.word	0x3ef9fd39,0x94293940
	.word	0xbf2a019f,0x75ee4be1
	.word	0xbf56c16b,0xba552569
	.word	0x3f811111,0x1108c703
	.word	0x3fa55555,0x554f5b35
	.word	0xbfc55555,0x555554d0
	.word	0xbfdfffff,0xffffff85
	.word	0x3ff00000,0x00000000
	.word	0xbfc55555,0x5551fc28
	.word	0x3f811107,0x62eacc9d
	.word	0xbfdfffff,0xffff6328
	.word	0x3fa55551,0x5f7acf0c
	.word	0x3fe45f30,0x6dc9c883
	.word	0x43380000,0x00000000
	.word	0x3ff921fb,0x54400000
	.word	0x3dd0b461,0x1a600000
	.word	0x3ba3198a,0x2e000000
	.word	0x397b839a,0x252049c1
	.word	0x80000000,0x00004000
	.word	0xffff8000,0x00000000	! N.B.: low-order words used
	.word	0x3fc90000,0x80000000	! for sign bit hacking; see
	.word	0x3fc40000,0x00000000	! references to "thresh" below

#define p4		0x0
#define q4		0x08
#define p3		0x10
#define q3		0x18
#define p2		0x20
#define q2		0x28
#define p1		0x30
#define q1		0x38
#define one		0x40
#define pp1		0x48
#define pp2		0x50
#define qq1		0x58
#define qq2		0x60
#define invpio2		0x68
#define round		0x70
#define pio2_1		0x78
#define pio2_2		0x80
#define pio2_3		0x88
#define pio2_3t		0x90
#define f30val		0x98
#define mask		0xa0
#define thresh		0xa8

! local storage indices

#define xsave		STACK_BIAS-0x8
#define ysave		STACK_BIAS-0x10
#define nsave		STACK_BIAS-0x14
#define sxsave		STACK_BIAS-0x18
#define sysave		STACK_BIAS-0x1c
#define biguns		STACK_BIAS-0x20
#define n2		STACK_BIAS-0x24
#define n1		STACK_BIAS-0x28
#define n0		STACK_BIAS-0x2c
#define x2_1		STACK_BIAS-0x40
#define x1_1		STACK_BIAS-0x50
#define x0_1		STACK_BIAS-0x60
#define y2_0		STACK_BIAS-0x70
#define y1_0		STACK_BIAS-0x80
#define y0_0		STACK_BIAS-0x90
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x90

!--------------------------------------------------------------
!	Some defines to keep code more readable
#define LIM_l6		%l6
!	in primary range, contains |x| upper limit when cos(x)=1.
!	in transferring to medium range, denotes what loop was active.
!--------------------------------------------------------------

	ENTRY(__vsin)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(g5)
	PIC_SET(g5,__vlibm_TBL_sincos_hi,l3)
	PIC_SET(g5,__vlibm_TBL_sincos_lo,l4)
	PIC_SET(g5,constants,l5)
	mov	%l5,%g1
	wr	%g0,0x82,%asi		! set %asi for non-faulting loads

! ========== primary range ==========

! register use

! i0  n
! i1  x
! i2  stridex
! i3  y
! i4  stridey
! i5  0x80000000

! l0  hx0
! l1  hx1
! l2  hx2
! l3  __vlibm_TBL_sincos_hi
! l4  __vlibm_TBL_sincos_lo
! l5  0x3fc90000
! l6  0x3e400000
! l7  0x3fe921fb

! the following are 64-bit registers in both V8+ and V9

! g1  scratch
! g5  

! o0  py0
! o1  py1
! o2  py2
! o3  oy0
! o4  oy1
! o5  oy2
! o7  scratch

! f0  x0
! f2  
! f4  
! f6  
! f8  scratch for table base
! f9  signbit0
! f10 x1
! f12 
! f14 
! f16 
! f18 scratch for table base
! f19 signbit1
! f20 x2
! f22 
! f24 
! f26 
! f28 scratch for table base
! f29 signbit2
! f30 0x80000000
! f31 0x4000
! f32 
! f34 
! f36 
! f38 
! f40 
! f42 
! f44 0xffff800000000000
! f46 p1
! f48 p2
! f50 p3
! f52 p4
! f54 one
! f56 pp1
! f58 pp2
! f60 qq1
! f62 qq2

#ifdef __sparcv9
	stx	%i1,[%fp+xsave]		! save arguments
	stx	%i3,[%fp+ysave]
#else
	st	%i1,[%fp+xsave]		! save arguments
	st	%i3,[%fp+ysave]
#endif
	st	%i0,[%fp+nsave]
	st	%i2,[%fp+sxsave]
	st	%i4,[%fp+sysave]
	sethi	%hi(0x80000000),%i5	! load/set up constants
	sethi	%hi(0x3fc90000),%l5
	sethi	%hi(0x3e400000),LIM_l6
	sethi	%hi(0x3fe921fb),%l7
	or	%l7,%lo(0x3fe921fb),%l7
	ldd	[%g1+f30val],%f30
	ldd	[%g1+mask],%f44
	ldd	[%g1+p1],%f46
	ldd	[%g1+p2],%f48
	ldd	[%g1+p3],%f50
	ldd	[%g1+p4],%f52
	ldd	[%g1+one],%f54
	ldd	[%g1+pp1],%f56
	ldd	[%g1+pp2],%f58
	ldd	[%g1+qq1],%f60
	ldd	[%g1+qq2],%f62
	sll	%i2,3,%i2		! scale strides
	sll	%i4,3,%i4
	add	%fp,x0_1,%o3		! precondition loop
	add	%fp,x0_1,%o4
	add	%fp,x0_1,%o5
	ld	[%i1],%l0		! hx = *x
	ld	[%i1],%f0
	ld	[%i1+4],%f1
	andn	%l0,%i5,%l0		! hx &= ~0x80000000
	add	%i1,%i2,%i1		! x += stridex

	ba,pt	%icc,.loop0
! delay slot
	nop

	.align 32
.loop0:
	lda	[%i1]%asi,%l1		! preload next argument
	sub	%l0,LIM_l6,%g1
	sub	%l7,%l0,%o7
	fands	%f0,%f30,%f9		! save signbit

	lda	[%i1]%asi,%f10
	orcc	%o7,%g1,%g0
	mov	%i3,%o0			! py0 = y
	bl,pn	%icc,.range0		! if hx < 0x3e400000 or > 0x3fe921fb

! delay slot
	lda	[%i1+4]%asi,%f11
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.endloop1

! delay slot
	andn	%l1,%i5,%l1
	add	%i1,%i2,%i1		! x += stridex
	fabsd	%f0,%f0
	fmuld	%f54,%f54,%f54		! one*one; a nop for alignment only

.loop1:
	lda	[%i1]%asi,%l2		! preload next argument
	sub	%l1,LIM_l6,%g1
	sub	%l7,%l1,%o7
	fands	%f10,%f30,%f19		! save signbit

	lda	[%i1]%asi,%f20
	orcc	%o7,%g1,%g0
	mov	%i3,%o1			! py1 = y
	bl,pn	%icc,.range1		! if hx < 0x3e400000 or > 0x3fe921fb

! delay slot
	lda	[%i1+4]%asi,%f21
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.endloop2

! delay slot
	andn	%l2,%i5,%l2
	add	%i1,%i2,%i1		! x += stridex
	fabsd	%f10,%f10
	fmuld	%f54,%f54,%f54		! one*one; a nop for alignment only

.loop2:
	st	%f6,[%o3]
	sub	%l2,LIM_l6,%g1
	sub	%l7,%l2,%o7
	fands	%f20,%f30,%f29		! save signbit

	st	%f7,[%o3+4]
	orcc	%g1,%o7,%g0
	mov	%i3,%o2			! py2 = y
	bl,pn	%icc,.range2		! if hx < 0x3e400000 or > 0x3fe921fb

! delay slot
	add	%i3,%i4,%i3		! y += stridey
	cmp	%l0,%l5
	fabsd	%f20,%f20
	bl,pn	%icc,.case4

! delay slot
	st	%f16,[%o4]
	cmp	%l1,%l5
	fpadd32s %f0,%f31,%f8
	bl,pn	%icc,.case2

! delay slot
	st	%f17,[%o4+4]
	cmp	%l2,%l5
	fpadd32s %f10,%f31,%f18
	bl,pn	%icc,.case1

! delay slot
	st	%f26,[%o5]
	mov	%o0,%o3
	sethi	%hi(0x3fc3c000),%o7
	fpadd32s %f20,%f31,%f28

	st	%f27,[%o5+4]
	fand	%f8,%f44,%f2
	mov	%o1,%o4

	fand	%f18,%f44,%f12
	mov	%o2,%o5
	sub	%l0,%o7,%l0

	fand	%f28,%f44,%f22
	sub	%l1,%o7,%l1
	sub	%l2,%o7,%l2

	fsubd	%f0,%f2,%f0
	srl	%l0,10,%l0
	add	%l3,8,%g1

	fsubd	%f10,%f12,%f10
	srl	%l1,10,%l1

	fsubd	%f20,%f22,%f20
	srl	%l2,10,%l2

	fmuld	%f0,%f0,%f2
	andn	%l0,0x1f,%l0

	fmuld	%f10,%f10,%f12
	andn	%l1,0x1f,%l1

	fmuld	%f20,%f20,%f22
	andn	%l2,0x1f,%l2

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f36

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f40

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4
	ldd	[%g1+%l0],%f34

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14
	ldd	[%g1+%l1],%f38

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24
	ldd	[%g1+%l2],%f42

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24

	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f2

	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f12

	fmuld	%f20,%f26,%f26
	ldd	[%l4+%l2],%f22

	fmuld	%f4,%f32,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f14,%f36,%f14
	lda	[%i1]%asi,%f0

	fmuld	%f24,%f40,%f24
	lda	[%i1+4]%asi,%f1

	fmuld	%f6,%f34,%f6
	add	%i1,%i2,%i1		! x += stridex

	fmuld	%f16,%f38,%f16

	fmuld	%f26,%f42,%f26

	faddd	%f6,%f4,%f6

	faddd	%f16,%f14,%f16

	faddd	%f26,%f24,%f26

	faddd	%f6,%f2,%f6

	faddd	%f16,%f12,%f16

	faddd	%f26,%f22,%f26

	faddd	%f6,%f32,%f6

	faddd	%f16,%f36,%f16

	faddd	%f26,%f40,%f26
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	fors	%f6,%f9,%f6
	addcc	%i0,-1,%i0

	fors	%f16,%f19,%f16
	bg,pt	%icc,.loop0

! delay slot
	fors	%f26,%f29,%f26

	ba,pt	%icc,.endloop0
! delay slot
	nop

	.align	32
.case1:
	st	%f27,[%o5+4]
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fand	%f8,%f44,%f2

	sub	%l0,%o7,%l0
	sub	%l1,%o7,%l1
	fand	%f18,%f44,%f12
	fmuld	%f20,%f20,%f22

	fsubd	%f0,%f2,%f0
	srl	%l0,10,%l0
	mov	%o0,%o3

	fsubd	%f10,%f12,%f10
	srl	%l1,10,%l1
	mov	%o1,%o4

	fmuld	%f22,%f52,%f24
	mov	%o2,%o5

	fmuld	%f0,%f0,%f2
	andn	%l0,0x1f,%l0

	fmuld	%f10,%f10,%f12
	andn	%l1,0x1f,%l1

	faddd	%f24,%f50,%f24

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f36

	fmuld	%f22,%f24,%f24

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4
	ldd	[%g1+%l0],%f34

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14
	ldd	[%g1+%l1],%f38

	faddd	%f24,%f48,%f24

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f22,%f24,%f24

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14

	faddd	%f24,%f46,%f24

	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f2

	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f12

	fmuld	%f4,%f32,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f14,%f36,%f14
	lda	[%i1]%asi,%f0

	fmuld	%f6,%f34,%f6
	lda	[%i1+4]%asi,%f1

	fmuld	%f16,%f38,%f16
	add	%i1,%i2,%i1		! x += stridex

	fmuld	%f22,%f24,%f24

	faddd	%f6,%f4,%f6

	faddd	%f16,%f14,%f16

	fmuld	%f20,%f24,%f24

	faddd	%f6,%f2,%f6

	faddd	%f16,%f12,%f16

	faddd	%f20,%f24,%f26

	faddd	%f6,%f32,%f6

	faddd	%f16,%f36,%f16
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	fors	%f26,%f29,%f26
	addcc	%i0,-1,%i0

	fors	%f6,%f9,%f6
	bg,pt	%icc,.loop0

! delay slot
	fors	%f16,%f19,%f16

	ba,pt	%icc,.endloop0
! delay slot
	nop

	.align	32
.case2:
	st	%f26,[%o5]
	cmp	%l2,%l5
	fpadd32s %f20,%f31,%f28
	bl,pn	%icc,.case3

! delay slot
	st	%f27,[%o5+4]
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fand	%f8,%f44,%f2

	sub	%l0,%o7,%l0
	sub	%l2,%o7,%l2
	fand	%f28,%f44,%f22
	fmuld	%f10,%f10,%f12

	fsubd	%f0,%f2,%f0
	srl	%l0,10,%l0
	mov	%o0,%o3

	fsubd	%f20,%f22,%f20
	srl	%l2,10,%l2
	mov	%o2,%o5

	fmuld	%f12,%f52,%f14
	mov	%o1,%o4

	fmuld	%f0,%f0,%f2
	andn	%l0,0x1f,%l0

	fmuld	%f20,%f20,%f22
	andn	%l2,0x1f,%l2

	faddd	%f14,%f50,%f14

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f40

	fmuld	%f12,%f14,%f14

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4
	ldd	[%g1+%l0],%f34

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24
	ldd	[%g1+%l2],%f42

	faddd	%f14,%f48,%f14

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	fmuld	%f12,%f14,%f14

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24

	faddd	%f14,%f46,%f14

	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f2

	fmuld	%f20,%f26,%f26
	ldd	[%l4+%l2],%f22

	fmuld	%f4,%f32,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f24,%f40,%f24
	lda	[%i1]%asi,%f0

	fmuld	%f6,%f34,%f6
	lda	[%i1+4]%asi,%f1

	fmuld	%f26,%f42,%f26
	add	%i1,%i2,%i1		! x += stridex

	fmuld	%f12,%f14,%f14

	faddd	%f6,%f4,%f6

	faddd	%f26,%f24,%f26

	fmuld	%f10,%f14,%f14

	faddd	%f6,%f2,%f6

	faddd	%f26,%f22,%f26

	faddd	%f10,%f14,%f16

	faddd	%f6,%f32,%f6

	faddd	%f26,%f40,%f26
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	fors	%f16,%f19,%f16
	addcc	%i0,-1,%i0

	fors	%f6,%f9,%f6
	bg,pt	%icc,.loop0

! delay slot
	fors	%f26,%f29,%f26

	ba,pt	%icc,.endloop0
! delay slot
	nop

	.align	32
.case3:
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fand	%f8,%f44,%f2
	fmuld	%f10,%f10,%f12

	sub	%l0,%o7,%l0
	fmuld	%f20,%f20,%f22

	fsubd	%f0,%f2,%f0
	srl	%l0,10,%l0
	mov	%o0,%o3

	fmuld	%f12,%f52,%f14
	mov	%o1,%o4

	fmuld	%f22,%f52,%f24
	mov	%o2,%o5

	fmuld	%f0,%f0,%f2
	andn	%l0,0x1f,%l0

	faddd	%f14,%f50,%f14

	faddd	%f24,%f50,%f24

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f12,%f14,%f14

	fmuld	%f22,%f24,%f24

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4
	ldd	[%g1+%l0],%f34

	faddd	%f14,%f48,%f14

	faddd	%f24,%f48,%f24

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f12,%f14,%f14

	fmuld	%f22,%f24,%f24

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4

	faddd	%f14,%f46,%f14

	faddd	%f24,%f46,%f24

	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f2

	fmuld	%f4,%f32,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f12,%f14,%f14
	lda	[%i1]%asi,%f0

	fmuld	%f6,%f34,%f6
	lda	[%i1+4]%asi,%f1

	fmuld	%f22,%f24,%f24
	add	%i1,%i2,%i1		! x += stridex

	fmuld	%f10,%f14,%f14

	faddd	%f6,%f4,%f6

	fmuld	%f20,%f24,%f24

	faddd	%f10,%f14,%f16

	faddd	%f6,%f2,%f6

	faddd	%f20,%f24,%f26

	fors	%f16,%f19,%f16
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	faddd	%f6,%f32,%f6
	addcc	%i0,-1,%i0

	fors	%f26,%f29,%f26
	bg,pt	%icc,.loop0

! delay slot
	fors	%f6,%f9,%f6

	ba,pt	%icc,.endloop0
! delay slot
	nop

	.align	32
.case4:
	st	%f17,[%o4+4]
	cmp	%l1,%l5
	fpadd32s %f10,%f31,%f18
	bl,pn	%icc,.case6

! delay slot
	st	%f26,[%o5]
	cmp	%l2,%l5
	fpadd32s %f20,%f31,%f28
	bl,pn	%icc,.case5

! delay slot
	st	%f27,[%o5+4]
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fand	%f18,%f44,%f12

	sub	%l1,%o7,%l1
	sub	%l2,%o7,%l2
	fand	%f28,%f44,%f22
	fmuld	%f0,%f0,%f2

	fsubd	%f10,%f12,%f10
	srl	%l1,10,%l1
	mov	%o1,%o4

	fsubd	%f20,%f22,%f20
	srl	%l2,10,%l2
	mov	%o2,%o5

	fmovd	%f0,%f6
	fmuld	%f2,%f52,%f4
	mov	%o0,%o3

	fmuld	%f10,%f10,%f12
	andn	%l1,0x1f,%l1

	fmuld	%f20,%f20,%f22
	andn	%l2,0x1f,%l2

	faddd	%f4,%f50,%f4

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f36

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f40

	fmuld	%f2,%f4,%f4

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14
	ldd	[%g1+%l1],%f38

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24
	ldd	[%g1+%l2],%f42

	faddd	%f4,%f48,%f4

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	fmuld	%f2,%f4,%f4

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24

	faddd	%f4,%f46,%f4

	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f12

	fmuld	%f20,%f26,%f26
	ldd	[%l4+%l2],%f22

	fmuld	%f14,%f36,%f14
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f24,%f40,%f24
	lda	[%i1]%asi,%f0

	fmuld	%f16,%f38,%f16
	lda	[%i1+4]%asi,%f1

	fmuld	%f26,%f42,%f26
	add	%i1,%i2,%i1		! x += stridex

	fmuld	%f2,%f4,%f4

	faddd	%f16,%f14,%f16

	faddd	%f26,%f24,%f26

	fmuld	%f6,%f4,%f4

	faddd	%f16,%f12,%f16

	faddd	%f26,%f22,%f26

	faddd	%f6,%f4,%f6

	faddd	%f16,%f36,%f16

	faddd	%f26,%f40,%f26
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	fors	%f6,%f9,%f6
	addcc	%i0,-1,%i0

	fors	%f16,%f19,%f16
	bg,pt	%icc,.loop0

! delay slot
	fors	%f26,%f29,%f26

	ba,pt	%icc,.endloop0
! delay slot
	nop

	.align	32
.case5:
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fand	%f18,%f44,%f12
	fmuld	%f0,%f0,%f2

	sub	%l1,%o7,%l1
	fmuld	%f20,%f20,%f22

	fsubd	%f10,%f12,%f10
	srl	%l1,10,%l1
	mov	%o1,%o4

	fmovd	%f0,%f6
	fmuld	%f2,%f52,%f4
	mov	%o0,%o3

	fmuld	%f22,%f52,%f24
	mov	%o2,%o5

	fmuld	%f10,%f10,%f12
	andn	%l1,0x1f,%l1

	faddd	%f4,%f50,%f4

	faddd	%f24,%f50,%f24

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f36

	fmuld	%f2,%f4,%f4

	fmuld	%f22,%f24,%f24

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14
	ldd	[%g1+%l1],%f38

	faddd	%f4,%f48,%f4

	faddd	%f24,%f48,%f24

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f2,%f4,%f4

	fmuld	%f22,%f24,%f24

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14

	faddd	%f4,%f46,%f4

	faddd	%f24,%f46,%f24

	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f12

	fmuld	%f14,%f36,%f14
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f2,%f4,%f4
	lda	[%i1]%asi,%f0

	fmuld	%f16,%f38,%f16
	lda	[%i1+4]%asi,%f1

	fmuld	%f22,%f24,%f24
	add	%i1,%i2,%i1		! x += stridex

	fmuld	%f6,%f4,%f4

	faddd	%f16,%f14,%f16

	fmuld	%f20,%f24,%f24

	faddd	%f6,%f4,%f6

	faddd	%f16,%f12,%f16

	faddd	%f20,%f24,%f26

	fors	%f6,%f9,%f6
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	faddd	%f16,%f36,%f16
	addcc	%i0,-1,%i0

	fors	%f26,%f29,%f26
	bg,pt	%icc,.loop0

! delay slot
	fors	%f16,%f19,%f16

	ba,pt	%icc,.endloop0
! delay slot
	nop

	.align	32
.case6:
	st	%f27,[%o5+4]
	cmp	%l2,%l5
	fpadd32s %f20,%f31,%f28
	bl,pn	%icc,.case7

! delay slot
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fand	%f28,%f44,%f22
	fmuld	%f0,%f0,%f2

	sub	%l2,%o7,%l2
	fmuld	%f10,%f10,%f12

	fsubd	%f20,%f22,%f20
	srl	%l2,10,%l2
	mov	%o2,%o5

	fmovd	%f0,%f6
	fmuld	%f2,%f52,%f4
	mov	%o0,%o3

	fmuld	%f12,%f52,%f14
	mov	%o1,%o4

	fmuld	%f20,%f20,%f22
	andn	%l2,0x1f,%l2

	faddd	%f4,%f50,%f4

	faddd	%f14,%f50,%f14

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f40

	fmuld	%f2,%f4,%f4

	fmuld	%f12,%f14,%f14

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24
	ldd	[%g1+%l2],%f42

	faddd	%f4,%f48,%f4

	faddd	%f14,%f48,%f14

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	fmuld	%f2,%f4,%f4

	fmuld	%f12,%f14,%f14

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24

	faddd	%f4,%f46,%f4

	faddd	%f14,%f46,%f14

	fmuld	%f20,%f26,%f26
	ldd	[%l4+%l2],%f22

	fmuld	%f24,%f40,%f24
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f2,%f4,%f4
	lda	[%i1]%asi,%f0

	fmuld	%f26,%f42,%f26
	lda	[%i1+4]%asi,%f1

	fmuld	%f12,%f14,%f14
	add	%i1,%i2,%i1		! x += stridex

	fmuld	%f6,%f4,%f4

	faddd	%f26,%f24,%f26

	fmuld	%f10,%f14,%f14

	faddd	%f6,%f4,%f6

	faddd	%f26,%f22,%f26

	faddd	%f10,%f14,%f16

	fors	%f6,%f9,%f6
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	faddd	%f26,%f40,%f26
	addcc	%i0,-1,%i0

	fors	%f16,%f19,%f16
	bg,pt	%icc,.loop0

! delay slot
	fors	%f26,%f29,%f26

	ba,pt	%icc,.endloop0
! delay slot
	nop

	.align	32
.case7:
	fmuld	%f0,%f0,%f2
	fmovd	%f0,%f6
	mov	%o0,%o3

	fmuld	%f10,%f10,%f12
	mov	%o1,%o4

	fmuld	%f20,%f20,%f22
	mov	%o2,%o5

	fmuld	%f2,%f52,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fmuld	%f12,%f52,%f14
	lda	[%i1]%asi,%f0

	fmuld	%f22,%f52,%f24
	lda	[%i1+4]%asi,%f1

	faddd	%f4,%f50,%f4
	add	%i1,%i2,%i1		! x += stridex

	faddd	%f14,%f50,%f14

	faddd	%f24,%f50,%f24

	fmuld	%f2,%f4,%f4

	fmuld	%f12,%f14,%f14

	fmuld	%f22,%f24,%f24

	faddd	%f4,%f48,%f4

	faddd	%f14,%f48,%f14

	faddd	%f24,%f48,%f24

	fmuld	%f2,%f4,%f4

	fmuld	%f12,%f14,%f14

	fmuld	%f22,%f24,%f24

	faddd	%f4,%f46,%f4

	faddd	%f14,%f46,%f14

	faddd	%f24,%f46,%f24

	fmuld	%f2,%f4,%f4

	fmuld	%f12,%f14,%f14

	fmuld	%f22,%f24,%f24

	fmuld	%f6,%f4,%f4

	fmuld	%f10,%f14,%f14

	fmuld	%f20,%f24,%f24

	faddd	%f6,%f4,%f6

	faddd	%f10,%f14,%f16

	faddd	%f20,%f24,%f26
	andn	%l0,%i5,%l0		! hx &= ~0x80000000

	fors	%f6,%f9,%f6
	addcc	%i0,-1,%i0

	fors	%f16,%f19,%f16
	bg,pt	%icc,.loop0

! delay slot
	fors	%f26,%f29,%f26

	ba,pt	%icc,.endloop0
! delay slot
	nop


	.align	32
.endloop2:
	cmp	%l1,%l5
	bl,pn	%icc,1f
! delay slot
	fabsd	%f10,%f10
	sethi	%hi(0x3fc3c000),%o7
	fpadd32s %f10,%f31,%f18
	add	%l3,8,%g1
	fand	%f18,%f44,%f12
	sub	%l1,%o7,%l1
	fsubd	%f10,%f12,%f10
	srl	%l1,10,%l1
	fmuld	%f10,%f10,%f12
	andn	%l1,0x1f,%l1
	fmuld	%f12,%f58,%f20
	ldd	[%l3+%l1],%f36
	faddd	%f20,%f56,%f20
	fmuld	%f12,%f62,%f14
	ldd	[%g1+%l1],%f38
	fmuld	%f12,%f20,%f20
	faddd	%f14,%f60,%f14
	faddd	%f20,%f54,%f20
	fmuld	%f12,%f14,%f14
	fmuld	%f10,%f20,%f20
	ldd	[%l4+%l1],%f12
	fmuld	%f14,%f36,%f14
	fmuld	%f20,%f38,%f20
	faddd	%f20,%f14,%f20
	faddd	%f20,%f12,%f20
	ba,pt	%icc,2f
! delay slot
	faddd	%f20,%f36,%f20
1:
	fmuld	%f10,%f10,%f12
	fmuld	%f12,%f52,%f14
	faddd	%f14,%f50,%f14
	fmuld	%f12,%f14,%f14
	faddd	%f14,%f48,%f14
	fmuld	%f12,%f14,%f14
	faddd	%f14,%f46,%f14
	fmuld	%f12,%f14,%f14
	fmuld	%f10,%f14,%f14
	faddd	%f10,%f14,%f20
2:
	fors	%f20,%f19,%f20
	st	%f20,[%o1]
	st	%f21,[%o1+4]

.endloop1:
	cmp	%l0,%l5
	bl,pn	%icc,1f
! delay slot
	fabsd	%f0,%f0
	sethi	%hi(0x3fc3c000),%o7
	fpadd32s %f0,%f31,%f8
	add	%l3,8,%g1
	fand	%f8,%f44,%f2
	sub	%l0,%o7,%l0
	fsubd	%f0,%f2,%f0
	srl	%l0,10,%l0
	fmuld	%f0,%f0,%f2
	andn	%l0,0x1f,%l0
	fmuld	%f2,%f58,%f20
	ldd	[%l3+%l0],%f32
	faddd	%f20,%f56,%f20
	fmuld	%f2,%f62,%f4
	ldd	[%g1+%l0],%f34
	fmuld	%f2,%f20,%f20
	faddd	%f4,%f60,%f4
	faddd	%f20,%f54,%f20
	fmuld	%f2,%f4,%f4
	fmuld	%f0,%f20,%f20
	ldd	[%l4+%l0],%f2
	fmuld	%f4,%f32,%f4
	fmuld	%f20,%f34,%f20
	faddd	%f20,%f4,%f20
	faddd	%f20,%f2,%f20
	ba,pt	%icc,2f
! delay slot
	faddd	%f20,%f32,%f20
1:
	fmuld	%f0,%f0,%f2
	fmuld	%f2,%f52,%f4
	faddd	%f4,%f50,%f4
	fmuld	%f2,%f4,%f4
	faddd	%f4,%f48,%f4
	fmuld	%f2,%f4,%f4
	faddd	%f4,%f46,%f4
	fmuld	%f2,%f4,%f4
	fmuld	%f0,%f4,%f4
	faddd	%f0,%f4,%f20
2:
	fors	%f20,%f9,%f20
	st	%f20,[%o0]
	st	%f21,[%o0+4]

.endloop0:
	st	%f6,[%o3]
	st	%f7,[%o3+4]
	st	%f16,[%o4]
	st	%f17,[%o4+4]
	st	%f26,[%o5]
	st	%f27,[%o5+4]

! return.  finished off with only primary range arguments.

	ret
	restore


	.align	32
.range0:
	cmp	%l0,LIM_l6
	bg,a,pt	%icc,.MEDIUM		! branch if x is not tiny
! delay slot, annulled if branch not taken
	mov	0x1,LIM_l6		! set "processing loop0"
	st	%f0,[%o0]		! *y = *x with inexact if x nonzero
	st	%f1,[%o0+4]
	fdtoi	%f0,%f2
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop0
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	andn	%l1,%i5,%l0		! hx &= ~0x80000000
	fmovd	%f10,%f0
	ba,pt	%icc,.loop0
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.range1:
	cmp	%l1,LIM_l6
	bg,a,pt	%icc,.MEDIUM		! branch if x is not tiny
! delay slot, annulled if branch not taken
	mov	0x2,LIM_l6		! set "processing loop1"
	st	%f10,[%o1]		! *y = *x with inexact if x nonzero
	st	%f11,[%o1+4]
	fdtoi	%f10,%f12
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop1
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	andn	%l2,%i5,%l1		! hx &= ~0x80000000
	fmovd	%f20,%f10
	ba,pt	%icc,.loop1
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.range2:
	cmp	%l2,LIM_l6
	bg,a,pt	%icc,.MEDIUM		! branch if x is not tiny
! delay slot, annulled if branch not taken
	mov	0x3,LIM_l6		! set "processing loop2"
	st	%f20,[%o2]		! *y = *x with inexact if x nonzero
	st	%f21,[%o2+4]
	fdtoi	%f20,%f22
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop2
! delay slot
	nop
	ld	[%i1],%l2
	ld	[%i1],%f20
	ld	[%i1+4],%f21
	andn	%l2,%i5,%l2		! hx &= ~0x80000000
	ba,pt	%icc,.loop2
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.MEDIUM:

! ========== medium range ==========

! register use

! i0  n
! i1  x
! i2  stridex
! i3  y
! i4  stridey
! i5  0x80000000

! l0  hx0
! l1  hx1
! l2  hx2
! l3  __vlibm_TBL_sincos_hi
! l4  __vlibm_TBL_sincos_lo
! l5  constants
! l6  in transition from pri-range and here, use for biguns
! l7  0x413921fb

! the following are 64-bit registers in both V8+ and V9

! g1  scratch
! g5  

! o0  py0
! o1  py1
! o2  py2
! o3  n0
! o4  n1
! o5  n2
! o7  scratch

! f0  x0
! f2  n0,y0
! f4  
! f6  
! f8  scratch for table base
! f9  signbit0
! f10 x1
! f12 n1,y1
! f14 
! f16 
! f18 scratch for table base
! f19 signbit1
! f20 x2
! f22 n2,y2
! f24 
! f26 
! f28 scratch for table base
! f29 signbit2
! f30 0x80000000
! f31 0x4000
! f32 
! f34 
! f36 
! f38 
! f40 invpio2
! f42 round
! f44 0xffff800000000000
! f46 pio2_1
! f48 pio2_2
! f50 pio2_3
! f52 pio2_3t
! f54 one
! f56 pp1
! f58 pp2
! f60 qq1
! f62 qq2

	PIC_SET(g5,constants,l5)

	! %o3,%o4,%o5 need to be stored
	st	%f6,[%o3]
	sethi	%hi(0x413921fb),%l7
	st	%f7,[%o3+4]
	or	%l7,%lo(0x413921fb),%l7
	st	%f16,[%o4]
	st	%f17,[%o4+4]
	st	%f26,[%o5]
	st	%f27,[%o5+4]
	ldd	[%l5+invpio2],%f40
	ldd	[%l5+round],%f42
	ldd	[%l5+pio2_1],%f46
	ldd	[%l5+pio2_2],%f48
	ldd	[%l5+pio2_3],%f50
	ldd	[%l5+pio2_3t],%f52
	std	%f54,[%fp+x0_1+8]	! set up stack data
	std	%f54,[%fp+x1_1+8]
	std	%f54,[%fp+x2_1+8]
	stx	%g0,[%fp+y0_0+8]
	stx	%g0,[%fp+y1_0+8]
	stx	%g0,[%fp+y2_0+8]

!	branched here in the middle of the array.  Need to adjust 
!	for the members of the triple that were selected in the primary
!	loop.

!	no adjustment since all three selected here
	subcc	LIM_l6,0x1,%g0		! continue in LOOP0?
	bz,a	%icc,.LOOP0
	mov	0x0,LIM_l6		! delay slot set biguns=0

!	ajust 1st triple since 2d and 3d done here
	subcc	LIM_l6,0x2,%g0		! continue in LOOP1?
	fors	%f0,%f9,%f0		! restore sign bit
	fmuld	%f0,%f40,%f2		! adj LOOP0
	bz,a	%icc,.LOOP1
	mov	0x0,LIM_l6		! delay slot set biguns=0

!	ajust 1st and 2d triple since 3d done here
	subcc	LIM_l6,0x3,%g0		! continue in LOOP2?
	!done fmuld	%f0,%f40,%f2		! adj LOOP0
	sub	%i3,%i4,%i3		! adjust to not double increment
	fors	%f10,%f19,%f10		! restore sign bit
	fmuld	%f10,%f40,%f12		! adj LOOP1
	faddd	%f2,%f42,%f2		! adj LOOP1
	bz,a	%icc,.LOOP2
	mov	0x0,LIM_l6		! delay slot set biguns=0

	.align 32
.LOOP0:
	lda	[%i1]%asi,%l1		! preload next argument
	mov	%i3,%o0			! py0 = y
	lda	[%i1]%asi,%f10
	cmp	%l0,%l7
	add	%i3,%i4,%i3		! y += stridey
	bg,pn	%icc,.BIG0		! if hx > 0x413921fb

! delay slot
	lda	[%i1+4]%asi,%f11
	addcc	%i0,-1,%i0
	add	%i1,%i2,%i1		! x += stridex
	ble,pn	%icc,.ENDLOOP1

! delay slot
	andn	%l1,%i5,%l1
	nop
	fmuld	%f0,%f40,%f2
	fabsd	%f54,%f54		! a nop for alignment only

.LOOP1:
	lda	[%i1]%asi,%l2		! preload next argument
	mov	%i3,%o1			! py1 = y

	lda	[%i1]%asi,%f20
	cmp	%l1,%l7
	add	%i3,%i4,%i3		! y += stridey
	bg,pn	%icc,.BIG1		! if hx > 0x413921fb

! delay slot
	lda	[%i1+4]%asi,%f21
	addcc	%i0,-1,%i0
	add	%i1,%i2,%i1		! x += stridex
	ble,pn	%icc,.ENDLOOP2

! delay slot
	andn	%l2,%i5,%l2
	nop
	fmuld	%f10,%f40,%f12
	faddd	%f2,%f42,%f2

.LOOP2:
	st	%f3,[%fp+n0]
	mov	%i3,%o2			! py2 = y

	cmp	%l2,%l7
	add	%i3,%i4,%i3		! y += stridey
	fmuld	%f20,%f40,%f22
	bg,pn	%icc,.BIG2		! if hx > 0x413921fb

! delay slot
	add	%l5,thresh+4,%o7
	faddd	%f12,%f42,%f12
	st	%f13,[%fp+n1]

! -

	add	%l5,thresh,%g1
	faddd	%f22,%f42,%f22
	st	%f23,[%fp+n2]

	fsubd	%f2,%f42,%f2		! n

	fsubd	%f12,%f42,%f12		! n

	fsubd	%f22,%f42,%f22		! n

	fmuld	%f2,%f46,%f4

	fmuld	%f12,%f46,%f14

	fmuld	%f22,%f46,%f24

	fsubd	%f0,%f4,%f4
	fmuld	%f2,%f48,%f6

	fsubd	%f10,%f14,%f14
	fmuld	%f12,%f48,%f16

	fsubd	%f20,%f24,%f24
	fmuld	%f22,%f48,%f26

	fsubd	%f4,%f6,%f0
	ld	[%fp+n0],%o3

	fsubd	%f14,%f16,%f10
	ld	[%fp+n1],%o4

	fsubd	%f24,%f26,%f20
	ld	[%fp+n2],%o5

	fsubd	%f4,%f0,%f32
	and	%o3,1,%o3

	fsubd	%f14,%f10,%f34
	and	%o4,1,%o4

	fsubd	%f24,%f20,%f36
	and	%o5,1,%o5

	fsubd	%f32,%f6,%f32
	fmuld	%f2,%f50,%f8
	sll	%o3,3,%o3

	fsubd	%f34,%f16,%f34
	fmuld	%f12,%f50,%f18
	sll	%o4,3,%o4

	fsubd	%f36,%f26,%f36
	fmuld	%f22,%f50,%f28
	sll	%o5,3,%o5

	fsubd	%f8,%f32,%f8
	ld	[%g1+%o3],%f6

	fsubd	%f18,%f34,%f18
	ld	[%g1+%o4],%f16

	fsubd	%f28,%f36,%f28
	ld	[%g1+%o5],%f26

	fsubd	%f0,%f8,%f4

	fsubd	%f10,%f18,%f14

	fsubd	%f20,%f28,%f24

	fsubd	%f0,%f4,%f32

	fsubd	%f10,%f14,%f34

	fsubd	%f20,%f24,%f36

	fsubd	%f32,%f8,%f32
	fmuld	%f2,%f52,%f2

	fsubd	%f34,%f18,%f34
	fmuld	%f12,%f52,%f12

	fsubd	%f36,%f28,%f36
	fmuld	%f22,%f52,%f22

	fsubd	%f2,%f32,%f2
	ld	[%o7+%o3],%f8

	fsubd	%f12,%f34,%f12
	ld	[%o7+%o4],%f18

	fsubd	%f22,%f36,%f22
	ld	[%o7+%o5],%f28

	fsubd	%f4,%f2,%f0		! x

	fsubd	%f14,%f12,%f10		! x

	fsubd	%f24,%f22,%f20		! x

	fsubd	%f4,%f0,%f4

	fsubd	%f14,%f10,%f14

	fsubd	%f24,%f20,%f24

	fands	%f0,%f30,%f9		! save signbit

	fands	%f10,%f30,%f19		! save signbit

	fands	%f20,%f30,%f29		! save signbit

	fabsd	%f0,%f0
	std	%f0,[%fp+x0_1]

	fabsd	%f10,%f10
	std	%f10,[%fp+x1_1]

	fabsd	%f20,%f20
	std	%f20,[%fp+x2_1]

	fsubd	%f4,%f2,%f2		! y

	fsubd	%f14,%f12,%f12		! y

	fsubd	%f24,%f22,%f22		! y

	fcmpgt32 %f6,%f0,%l0

	fcmpgt32 %f16,%f10,%l1

	fcmpgt32 %f26,%f20,%l2

! -- 16 byte aligned
	fxors	%f2,%f9,%f2

	fxors	%f12,%f19,%f12

	fxors	%f22,%f29,%f22

	fands	%f9,%f8,%f9		! if (n & 1) clear sign bit
	andcc	%l0,2,%g0
	bne,pn	%icc,.CASE4

! delay slot
	fands	%f19,%f18,%f19		! if (n & 1) clear sign bit
	andcc	%l1,2,%g0
	bne,pn	%icc,.CASE2

! delay slot
	fands	%f29,%f28,%f29		! if (n & 1) clear sign bit
	andcc	%l2,2,%g0
	bne,pn	%icc,.CASE1

! delay slot
	fpadd32s %f0,%f31,%f8
	sethi	%hi(0x3fc3c000),%o7
	ld	[%fp+x0_1],%l0

	fpadd32s %f10,%f31,%f18
	add	%l3,8,%g1
	ld	[%fp+x1_1],%l1

	fpadd32s %f20,%f31,%f28
	ld	[%fp+x2_1],%l2

	fand	%f8,%f44,%f4
	sub	%l0,%o7,%l0

	fand	%f18,%f44,%f14
	sub	%l1,%o7,%l1

	fand	%f28,%f44,%f24
	sub	%l2,%o7,%l2

	fsubd	%f0,%f4,%f0
	srl	%l0,10,%l0

	fsubd	%f10,%f14,%f10
	srl	%l1,10,%l1

	fsubd	%f20,%f24,%f20
	srl	%l2,10,%l2

	faddd	%f0,%f2,%f0
	andn	%l0,0x1f,%l0

	faddd	%f10,%f12,%f10
	andn	%l1,0x1f,%l1

	faddd	%f20,%f22,%f20
	andn	%l2,0x1f,%l2

	fmuld	%f0,%f0,%f2
	add	%l0,%o3,%l0

	fmuld	%f10,%f10,%f12
	add	%l1,%o4,%l1

	fmuld	%f20,%f20,%f22
	add	%l2,%o5,%l2

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f34

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f36

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24

	fmuld	%f0,%f6,%f6
	ldd	[%g1+%l0],%f2

	fmuld	%f10,%f16,%f16
	ldd	[%g1+%l1],%f12

	fmuld	%f20,%f26,%f26
	ldd	[%g1+%l2],%f22

	fmuld	%f4,%f32,%f4
	ldd	[%l4+%l0],%f0

	fmuld	%f14,%f34,%f14
	ldd	[%l4+%l1],%f10

	fmuld	%f24,%f36,%f24
	ldd	[%l4+%l2],%f20

	fmuld	%f6,%f2,%f6

	fmuld	%f16,%f12,%f16

	fmuld	%f26,%f22,%f26

	faddd	%f6,%f4,%f6

	faddd	%f16,%f14,%f16

	faddd	%f26,%f24,%f26

	faddd	%f6,%f0,%f6

	faddd	%f16,%f10,%f16

	faddd	%f26,%f20,%f26

	faddd	%f6,%f32,%f6

	faddd	%f16,%f34,%f16

	faddd	%f26,%f36,%f26

.FIXSIGN:
	ld	[%fp+n0],%o3
	add	%l5,thresh-4,%g1

	ld	[%fp+n1],%o4

	ld	[%fp+n2],%o5
	and	%o3,2,%o3

	sll	%o3,2,%o3
	and	%o4,2,%o4
	lda	[%i1]%asi,%l0		! preload next argument

	sll	%o4,2,%o4
	and	%o5,2,%o5
	ld	[%g1+%o3],%f8

	sll	%o5,2,%o5
	ld	[%g1+%o4],%f18

	ld	[%g1+%o5],%f28
	fxors	%f9,%f8,%f9

	lda	[%i1]%asi,%f0
	fxors	%f29,%f28,%f29

	lda	[%i1+4]%asi,%f1
	fxors	%f19,%f18,%f19

	fors	%f6,%f9,%f6		! tack on sign
	add	%i1,%i2,%i1		! x += stridex
	st	%f6,[%o0]

	fors	%f26,%f29,%f26		! tack on sign
	st	%f7,[%o0+4]

	fors	%f16,%f19,%f16		! tack on sign
	st	%f26,[%o2]

	st	%f27,[%o2+4]
	addcc	%i0,-1,%i0

	st	%f16,[%o1]
	andn	%l0,%i5,%l0		! hx &= ~0x80000000
	bg,pt	%icc,.LOOP0

! delay slot
	st	%f17,[%o1+4]

	ba,pt	%icc,.ENDLOOP0
! delay slot
	nop

	.align	32
.CASE1:
	fpadd32s %f10,%f31,%f18
	sethi	%hi(0x3fc3c000),%o7
	ld	[%fp+x0_1],%l0

	fand	%f8,%f44,%f4
	add	%l3,8,%g1
	ld	[%fp+x1_1],%l1

	fand	%f18,%f44,%f14
	sub	%l0,%o7,%l0

	fsubd	%f0,%f4,%f0
	srl	%l0,10,%l0
	sub	%l1,%o7,%l1

	fsubd	%f10,%f14,%f10
	srl	%l1,10,%l1

	fmuld	%f20,%f20,%f20
	ldd	[%l5+%o5],%f36
	add	%l5,%o5,%l2

	faddd	%f0,%f2,%f0
	andn	%l0,0x1f,%l0

	faddd	%f10,%f12,%f10
	andn	%l1,0x1f,%l1

	fmuld	%f20,%f36,%f24
	ldd	[%l2+0x10],%f26
	add	%fp,%o5,%o5

	fmuld	%f0,%f0,%f2
	add	%l0,%o3,%l0

	fmuld	%f10,%f10,%f12
	add	%l1,%o4,%l1

	faddd	%f24,%f26,%f24
	ldd	[%l2+0x20],%f36

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f34

	fmuld	%f20,%f24,%f24
	ldd	[%l2+0x30],%f26

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14

	faddd	%f24,%f36,%f24
	ldd	[%o5+x2_1],%f36

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f20,%f24,%f24

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4
	ldd	[%g1+%l0],%f2

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14
	ldd	[%g1+%l1],%f12

	faddd	%f24,%f26,%f24

	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f0

	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f10

	fmuld	%f4,%f32,%f4
	std	%f22,[%fp+y2_0]

	fmuld	%f14,%f34,%f14

	fmuld	%f6,%f2,%f6

	fmuld	%f16,%f12,%f16

	fmuld	%f20,%f24,%f24

	faddd	%f6,%f4,%f6

	faddd	%f16,%f14,%f16

	fmuld	%f36,%f24,%f24
	ldd	[%o5+y2_0],%f22

	faddd	%f6,%f0,%f6

	faddd	%f16,%f10,%f16

	faddd	%f24,%f22,%f24

	faddd	%f6,%f32,%f6

	faddd	%f16,%f34,%f16
	ba,pt	%icc,.FIXSIGN

! delay slot
	faddd	%f36,%f24,%f26

	.align	32
.CASE2:
	fpadd32s %f0,%f31,%f8
	ld	[%fp+x0_1],%l0
	andcc	%l2,2,%g0
	bne,pn	%icc,.CASE3

! delay slot
	sethi	%hi(0x3fc3c000),%o7
	fpadd32s %f20,%f31,%f28
	ld	[%fp+x2_1],%l2

	fand	%f8,%f44,%f4
	sub	%l0,%o7,%l0
	add	%l3,8,%g1

	fand	%f28,%f44,%f24
	sub	%l2,%o7,%l2

	fsubd	%f0,%f4,%f0
	srl	%l0,10,%l0

	fsubd	%f20,%f24,%f20
	srl	%l2,10,%l2

	fmuld	%f10,%f10,%f10
	ldd	[%l5+%o4],%f34
	add	%l5,%o4,%l1

	faddd	%f0,%f2,%f0
	andn	%l0,0x1f,%l0

	faddd	%f20,%f22,%f20
	andn	%l2,0x1f,%l2

	fmuld	%f10,%f34,%f14
	ldd	[%l1+0x10],%f16
	add	%fp,%o4,%o4

	fmuld	%f0,%f0,%f2
	add	%l0,%o3,%l0

	fmuld	%f20,%f20,%f22
	add	%l2,%o5,%l2

	faddd	%f14,%f16,%f14
	ldd	[%l1+0x20],%f34

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f36

	fmuld	%f10,%f14,%f14
	ldd	[%l1+0x30],%f16

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24

	faddd	%f14,%f34,%f14
	ldd	[%o4+x1_1],%f34

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	fmuld	%f10,%f14,%f14

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4
	ldd	[%g1+%l0],%f2

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24
	ldd	[%g1+%l2],%f22

	faddd	%f14,%f16,%f14

	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f0

	fmuld	%f20,%f26,%f26
	ldd	[%l4+%l2],%f20

	fmuld	%f4,%f32,%f4
	std	%f12,[%fp+y1_0]

	fmuld	%f24,%f36,%f24

	fmuld	%f6,%f2,%f6

	fmuld	%f26,%f22,%f26

	fmuld	%f10,%f14,%f14

	faddd	%f6,%f4,%f6

	faddd	%f26,%f24,%f26

	fmuld	%f34,%f14,%f14
	ldd	[%o4+y1_0],%f12

	faddd	%f6,%f0,%f6

	faddd	%f26,%f20,%f26

	faddd	%f14,%f12,%f14

	faddd	%f6,%f32,%f6

	faddd	%f26,%f36,%f26
	ba,pt	%icc,.FIXSIGN

! delay slot
	faddd	%f34,%f14,%f16

	.align	32
.CASE3:
	fand	%f8,%f44,%f4
	add	%l3,8,%g1
	sub	%l0,%o7,%l0

	fmuld	%f10,%f10,%f10
	ldd	[%l5+%o4],%f34
	add	%l5,%o4,%l1

	fsubd	%f0,%f4,%f0
	srl	%l0,10,%l0

	fmuld	%f20,%f20,%f20
	ldd	[%l5+%o5],%f36
	add	%l5,%o5,%l2

	fmuld	%f10,%f34,%f14
	ldd	[%l1+0x10],%f16
	add	%fp,%o4,%o4

	faddd	%f0,%f2,%f0
	andn	%l0,0x1f,%l0

	fmuld	%f20,%f36,%f24
	ldd	[%l2+0x10],%f26
	add	%fp,%o5,%o5

	faddd	%f14,%f16,%f14
	ldd	[%l1+0x20],%f34

	fmuld	%f0,%f0,%f2
	add	%l0,%o3,%l0

	faddd	%f24,%f26,%f24
	ldd	[%l2+0x20],%f36

	fmuld	%f10,%f14,%f14
	ldd	[%l1+0x30],%f16

	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32

	fmuld	%f20,%f24,%f24
	ldd	[%l2+0x30],%f26

	faddd	%f14,%f34,%f14
	ldd	[%o4+x1_1],%f34

	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4

	faddd	%f24,%f36,%f24
	ldd	[%o5+x2_1],%f36

	fmuld	%f10,%f14,%f14
	std	%f12,[%fp+y1_0]

	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4

	fmuld	%f20,%f24,%f24
	std	%f22,[%fp+y2_0]

	faddd	%f14,%f16,%f14

	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4
	ldd	[%g1+%l0],%f2

	faddd	%f24,%f26,%f24

	fmuld	%f10,%f14,%f14

	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f0

	fmuld	%f4,%f32,%f4

	fmuld	%f20,%f24,%f24

	fmuld	%f6,%f2,%f6

	fmuld	%f34,%f14,%f14
	ldd	[%o4+y1_0],%f12

	fmuld	%f36,%f24,%f24
	ldd	[%o5+y2_0],%f22

	faddd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	faddd	%f24,%f22,%f24

	faddd	%f6,%f0,%f6

	faddd	%f34,%f14,%f16

	faddd	%f36,%f24,%f26
	ba,pt	%icc,.FIXSIGN

! delay slot
	faddd	%f6,%f32,%f6

	.align	32
.CASE4:
	fands	%f29,%f28,%f29		! if (n & 1) clear sign bit
	sethi	%hi(0x3fc3c000),%o7
	andcc	%l1,2,%g0
	bne,pn	%icc,.CASE6

! delay slot
	andcc	%l2,2,%g0
	fpadd32s %f10,%f31,%f18
	ld	[%fp+x1_1],%l1
	bne,pn	%icc,.CASE5

! delay slot
	add	%l3,8,%g1
	ld	[%fp+x2_1],%l2
	fpadd32s %f20,%f31,%f28

	fand	%f18,%f44,%f14
	sub	%l1,%o7,%l1

	fand	%f28,%f44,%f24
	sub	%l2,%o7,%l2

	fsubd	%f10,%f14,%f10
	srl	%l1,10,%l1

	fsubd	%f20,%f24,%f20
	srl	%l2,10,%l2

	fmuld	%f0,%f0,%f0
	ldd	[%l5+%o3],%f32
	add	%l5,%o3,%l0

	faddd	%f10,%f12,%f10
	andn	%l1,0x1f,%l1

	faddd	%f20,%f22,%f20
	andn	%l2,0x1f,%l2

	fmuld	%f0,%f32,%f4
	ldd	[%l0+0x10],%f6
	add	%fp,%o3,%o3

	fmuld	%f10,%f10,%f12
	add	%l1,%o4,%l1

	fmuld	%f20,%f20,%f22
	add	%l2,%o5,%l2

	faddd	%f4,%f6,%f4
	ldd	[%l0+0x20],%f32

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f34

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f36

	fmuld	%f0,%f4,%f4
	ldd	[%l0+0x30],%f6

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24

	faddd	%f4,%f32,%f4
	ldd	[%o3+x0_1],%f32

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	fmuld	%f0,%f4,%f4

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14
	ldd	[%g1+%l1],%f12

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24
	ldd	[%g1+%l2],%f22

	faddd	%f4,%f6,%f4

	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f10

	fmuld	%f20,%f26,%f26
	ldd	[%l4+%l2],%f20

	fmuld	%f14,%f34,%f14
	std	%f2,[%fp+y0_0]

	fmuld	%f24,%f36,%f24

	fmuld	%f0,%f4,%f4

	fmuld	%f16,%f12,%f16

	fmuld	%f26,%f22,%f26

	fmuld	%f32,%f4,%f4
	ldd	[%o3+y0_0],%f2

	faddd	%f16,%f14,%f16

	faddd	%f26,%f24,%f26

	faddd	%f4,%f2,%f4

	faddd	%f16,%f10,%f16

	faddd	%f26,%f20,%f26

	faddd	%f32,%f4,%f6

	faddd	%f16,%f34,%f16
	ba,pt	%icc,.FIXSIGN

! delay slot
	faddd	%f26,%f36,%f26

	.align	32
.CASE5:
	fand	%f18,%f44,%f14
	sub	%l1,%o7,%l1

	fmuld	%f0,%f0,%f0
	ldd	[%l5+%o3],%f32
	add	%l5,%o3,%l0

	fsubd	%f10,%f14,%f10
	srl	%l1,10,%l1

	fmuld	%f20,%f20,%f20
	ldd	[%l5+%o5],%f36
	add	%l5,%o5,%l2

	fmuld	%f0,%f32,%f4
	ldd	[%l0+0x10],%f6
	add	%fp,%o3,%o3

	faddd	%f10,%f12,%f10
	andn	%l1,0x1f,%l1

	fmuld	%f20,%f36,%f24
	ldd	[%l2+0x10],%f26
	add	%fp,%o5,%o5

	faddd	%f4,%f6,%f4
	ldd	[%l0+0x20],%f32

	fmuld	%f10,%f10,%f12
	add	%l1,%o4,%l1

	faddd	%f24,%f26,%f24
	ldd	[%l2+0x20],%f36

	fmuld	%f0,%f4,%f4
	ldd	[%l0+0x30],%f6

	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f34

	fmuld	%f20,%f24,%f24
	ldd	[%l2+0x30],%f26

	faddd	%f4,%f32,%f4
	ldd	[%o3+x0_1],%f32

	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14

	faddd	%f24,%f36,%f24
	ldd	[%o5+x2_1],%f36

	fmuld	%f0,%f4,%f4
	std	%f2,[%fp+y0_0]

	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14

	fmuld	%f20,%f24,%f24
	std	%f22,[%fp+y2_0]

	faddd	%f4,%f6,%f4

	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14
	ldd	[%g1+%l1],%f12

	faddd	%f24,%f26,%f24

	fmuld	%f0,%f4,%f4

	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f10

	fmuld	%f14,%f34,%f14

	fmuld	%f20,%f24,%f24

	fmuld	%f16,%f12,%f16

	fmuld	%f32,%f4,%f4
	ldd	[%o3+y0_0],%f2

	fmuld	%f36,%f24,%f24
	ldd	[%o5+y2_0],%f22

	faddd	%f16,%f14,%f16

	faddd	%f4,%f2,%f4

	faddd	%f24,%f22,%f24

	faddd	%f16,%f10,%f16

	faddd	%f32,%f4,%f6

	faddd	%f36,%f24,%f26
	ba,pt	%icc,.FIXSIGN

! delay slot
	faddd	%f16,%f34,%f16

	.align	32
.CASE6:
	ld	[%fp+x2_1],%l2
	add	%l3,8,%g1
	bne,pn	%icc,.CASE7
! delay slot
	fpadd32s %f20,%f31,%f28

	fand	%f28,%f44,%f24
	ldd	[%l5+%o3],%f32
	add	%l5,%o3,%l0

	fmuld	%f0,%f0,%f0
	sub	%l2,%o7,%l2

	fsubd	%f20,%f24,%f20
	srl	%l2,10,%l2

	fmuld	%f10,%f10,%f10
	ldd	[%l5+%o4],%f34
	add	%l5,%o4,%l1

	fmuld	%f0,%f32,%f4
	ldd	[%l0+0x10],%f6
	add	%fp,%o3,%o3

	faddd	%f20,%f22,%f20
	andn	%l2,0x1f,%l2

	fmuld	%f10,%f34,%f14
	ldd	[%l1+0x10],%f16
	add	%fp,%o4,%o4

	faddd	%f4,%f6,%f4
	ldd	[%l0+0x20],%f32

	fmuld	%f20,%f20,%f22
	add	%l2,%o5,%l2

	faddd	%f14,%f16,%f14
	ldd	[%l1+0x20],%f34

	fmuld	%f0,%f4,%f4
	ldd	[%l0+0x30],%f6

	fmuld	%f22,%f58,%f26
	ldd	[%l3+%l2],%f36

	fmuld	%f10,%f14,%f14
	ldd	[%l1+0x30],%f16

	faddd	%f4,%f32,%f4
	ldd	[%o3+x0_1],%f32

	faddd	%f26,%f56,%f26
	fmuld	%f22,%f62,%f24

	faddd	%f14,%f34,%f14
	ldd	[%o4+x1_1],%f34

	fmuld	%f0,%f4,%f4
	std	%f2,[%fp+y0_0]

	fmuld	%f22,%f26,%f26
	faddd	%f24,%f60,%f24

	fmuld	%f10,%f14,%f14
	std	%f12,[%fp+y1_0]

	faddd	%f4,%f6,%f4

	faddd	%f26,%f54,%f26
	fmuld	%f22,%f24,%f24
	ldd	[%g1+%l2],%f22

	faddd	%f14,%f16,%f14

	fmuld	%f0,%f4,%f4

	fmuld	%f20,%f26,%f26
	ldd	[%l4+%l2],%f20

	fmuld	%f24,%f36,%f24

	fmuld	%f10,%f14,%f14

	fmuld	%f26,%f22,%f26

	fmuld	%f32,%f4,%f4
	ldd	[%o3+y0_0],%f2

	fmuld	%f34,%f14,%f14
	ldd	[%o4+y1_0],%f12

	faddd	%f26,%f24,%f26

	faddd	%f4,%f2,%f4

	faddd	%f14,%f12,%f14

	faddd	%f26,%f20,%f26

	faddd	%f32,%f4,%f6

	faddd	%f34,%f14,%f16
	ba,pt	%icc,.FIXSIGN

! delay slot
	faddd	%f26,%f36,%f26

	.align	32
.CASE7:
	fmuld	%f0,%f0,%f0
	ldd	[%l5+%o3],%f32
	add	%l5,%o3,%l0

	fmuld	%f10,%f10,%f10
	ldd	[%l5+%o4],%f34
	add	%l5,%o4,%l1

	fmuld	%f20,%f20,%f20
	ldd	[%l5+%o5],%f36
	add	%l5,%o5,%l2

	fmuld	%f0,%f32,%f4
	ldd	[%l0+0x10],%f6
	add	%fp,%o3,%o3

	fmuld	%f10,%f34,%f14
	ldd	[%l1+0x10],%f16
	add	%fp,%o4,%o4

	fmuld	%f20,%f36,%f24
	ldd	[%l2+0x10],%f26
	add	%fp,%o5,%o5

	faddd	%f4,%f6,%f4
	ldd	[%l0+0x20],%f32

	faddd	%f14,%f16,%f14
	ldd	[%l1+0x20],%f34

	faddd	%f24,%f26,%f24
	ldd	[%l2+0x20],%f36

	fmuld	%f0,%f4,%f4
	ldd	[%l0+0x30],%f6

	fmuld	%f10,%f14,%f14
	ldd	[%l1+0x30],%f16

	fmuld	%f20,%f24,%f24
	ldd	[%l2+0x30],%f26

	faddd	%f4,%f32,%f4
	ldd	[%o3+x0_1],%f32

	faddd	%f14,%f34,%f14
	ldd	[%o4+x1_1],%f34

	faddd	%f24,%f36,%f24
	ldd	[%o5+x2_1],%f36

	fmuld	%f0,%f4,%f4
	std	%f2,[%fp+y0_0]

	fmuld	%f10,%f14,%f14
	std	%f12,[%fp+y1_0]

	fmuld	%f20,%f24,%f24
	std	%f22,[%fp+y2_0]

	faddd	%f4,%f6,%f4

	faddd	%f14,%f16,%f14

	faddd	%f24,%f26,%f24

	fmuld	%f0,%f4,%f4

	fmuld	%f10,%f14,%f14

	fmuld	%f20,%f24,%f24

	fmuld	%f32,%f4,%f4
	ldd	[%o3+y0_0],%f2

	fmuld	%f34,%f14,%f14
	ldd	[%o4+y1_0],%f12

	fmuld	%f36,%f24,%f24
	ldd	[%o5+y2_0],%f22

	faddd	%f4,%f2,%f4

	faddd	%f14,%f12,%f14

	faddd	%f24,%f22,%f24

	faddd	%f32,%f4,%f6

	faddd	%f34,%f14,%f16
	ba,pt	%icc,.FIXSIGN

! delay slot
	faddd	%f36,%f24,%f26


	.align	32
.ENDLOOP2:
	fmuld	%f10,%f40,%f12
	add	%l5,thresh,%g1
	faddd	%f12,%f42,%f12
	st	%f13,[%fp+n1]
	fsubd	%f12,%f42,%f12		! n
	fmuld	%f12,%f46,%f14
	fsubd	%f10,%f14,%f14
	fmuld	%f12,%f48,%f16
	fsubd	%f14,%f16,%f10
	ld	[%fp+n1],%o4
	fsubd	%f14,%f10,%f34
	and	%o4,1,%o4
	fsubd	%f34,%f16,%f34
	fmuld	%f12,%f50,%f18
	sll	%o4,3,%o4
	fsubd	%f18,%f34,%f18
	ld	[%g1+%o4],%f16
	fsubd	%f10,%f18,%f14
	fsubd	%f10,%f14,%f34
	add	%l5,thresh+4,%o7
	fsubd	%f34,%f18,%f34
	fmuld	%f12,%f52,%f12
	fsubd	%f12,%f34,%f12
	ld	[%o7+%o4],%f18
	fsubd	%f14,%f12,%f10		! x
	fsubd	%f14,%f10,%f14
	fands	%f10,%f30,%f19		! save signbit
	fabsd	%f10,%f10
	std	%f10,[%fp+x1_1]
	fsubd	%f14,%f12,%f12		! y
	fcmpgt32 %f16,%f10,%l1
	fxors	%f12,%f19,%f12
	fands	%f19,%f18,%f19		! if (n & 1) clear sign bit
	andcc	%l1,2,%g0
	bne,pn	%icc,1f
! delay slot
	nop
	fpadd32s %f10,%f31,%f18
	ld	[%fp+x1_1],%l1
	fand	%f18,%f44,%f14
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fsubd	%f10,%f14,%f10
	sub	%l1,%o7,%l1
	srl	%l1,10,%l1
	faddd	%f10,%f12,%f10
	andn	%l1,0x1f,%l1
	fmuld	%f10,%f10,%f12
	add	%l1,%o4,%l1
	fmuld	%f12,%f58,%f16
	ldd	[%l3+%l1],%f34
	faddd	%f16,%f56,%f16
	fmuld	%f12,%f62,%f14
	fmuld	%f12,%f16,%f16
	faddd	%f14,%f60,%f14
	faddd	%f16,%f54,%f16
	fmuld	%f12,%f14,%f14
	ldd	[%g1+%l1],%f12
	fmuld	%f10,%f16,%f16
	ldd	[%l4+%l1],%f10
	fmuld	%f14,%f34,%f14
	fmuld	%f16,%f12,%f16
	faddd	%f16,%f14,%f16
	faddd	%f16,%f10,%f16
	ba,pt	%icc,2f
	faddd	%f16,%f34,%f16
1:
	fmuld	%f10,%f10,%f10
	ldd	[%l5+%o4],%f34
	add	%l5,%o4,%l1
	fmuld	%f10,%f34,%f14
	ldd	[%l1+0x10],%f16
	add	%fp,%o4,%o4
	faddd	%f14,%f16,%f14
	ldd	[%l1+0x20],%f34
	fmuld	%f10,%f14,%f14
	ldd	[%l1+0x30],%f16
	faddd	%f14,%f34,%f14
	ldd	[%o4+x1_1],%f34
	fmuld	%f10,%f14,%f14
	std	%f12,[%fp+y1_0]
	faddd	%f14,%f16,%f14
	fmuld	%f10,%f14,%f14
	fmuld	%f34,%f14,%f14
	ldd	[%o4+y1_0],%f12
	faddd	%f14,%f12,%f14
	faddd	%f34,%f14,%f16
2:
	add	%l5,thresh-4,%g1
	ld	[%fp+n1],%o4
	and	%o4,2,%o4
	sll	%o4,2,%o4
	ld	[%g1+%o4],%f18
	fxors	%f19,%f18,%f19
	fors	%f16,%f19,%f16		! tack on sign
	st	%f16,[%o1]
	st	%f17,[%o1+4]

.ENDLOOP1:
	fmuld	%f0,%f40,%f2
	add	%l5,thresh,%g1
	faddd	%f2,%f42,%f2
	st	%f3,[%fp+n0]
	fsubd	%f2,%f42,%f2		! n
	fmuld	%f2,%f46,%f4
	fsubd	%f0,%f4,%f4
	fmuld	%f2,%f48,%f6
	fsubd	%f4,%f6,%f0
	ld	[%fp+n0],%o3
	fsubd	%f4,%f0,%f32
	and	%o3,1,%o3
	fsubd	%f32,%f6,%f32
	fmuld	%f2,%f50,%f8
	sll	%o3,3,%o3
	fsubd	%f8,%f32,%f8
	ld	[%g1+%o3],%f6
	fsubd	%f0,%f8,%f4
	fsubd	%f0,%f4,%f32
	add	%l5,thresh+4,%o7
	fsubd	%f32,%f8,%f32
	fmuld	%f2,%f52,%f2
	fsubd	%f2,%f32,%f2
	ld	[%o7+%o3],%f8
	fsubd	%f4,%f2,%f0		! x
	fsubd	%f4,%f0,%f4
	fands	%f0,%f30,%f9		! save signbit
	fabsd	%f0,%f0
	std	%f0,[%fp+x0_1]
	fsubd	%f4,%f2,%f2		! y
	fcmpgt32 %f6,%f0,%l0
	fxors	%f2,%f9,%f2
	fands	%f9,%f8,%f9		! if (n & 1) clear sign bit
	andcc	%l0,2,%g0
	bne,pn	%icc,1f
! delay slot
	nop
	fpadd32s %f0,%f31,%f8
	ld	[%fp+x0_1],%l0
	fand	%f8,%f44,%f4
	sethi	%hi(0x3fc3c000),%o7
	add	%l3,8,%g1
	fsubd	%f0,%f4,%f0
	sub	%l0,%o7,%l0
	srl	%l0,10,%l0
	faddd	%f0,%f2,%f0
	andn	%l0,0x1f,%l0
	fmuld	%f0,%f0,%f2
	add	%l0,%o3,%l0
	fmuld	%f2,%f58,%f6
	ldd	[%l3+%l0],%f32
	faddd	%f6,%f56,%f6
	fmuld	%f2,%f62,%f4
	fmuld	%f2,%f6,%f6
	faddd	%f4,%f60,%f4
	faddd	%f6,%f54,%f6
	fmuld	%f2,%f4,%f4
	ldd	[%g1+%l0],%f2
	fmuld	%f0,%f6,%f6
	ldd	[%l4+%l0],%f0
	fmuld	%f4,%f32,%f4
	fmuld	%f6,%f2,%f6
	faddd	%f6,%f4,%f6
	faddd	%f6,%f0,%f6
	ba,pt	%icc,2f
	faddd	%f6,%f32,%f6
1:
	fmuld	%f0,%f0,%f0
	ldd	[%l5+%o3],%f32
	add	%l5,%o3,%l0
	fmuld	%f0,%f32,%f4
	ldd	[%l0+0x10],%f6
	add	%fp,%o3,%o3
	faddd	%f4,%f6,%f4
	ldd	[%l0+0x20],%f32
	fmuld	%f0,%f4,%f4
	ldd	[%l0+0x30],%f6
	faddd	%f4,%f32,%f4
	ldd	[%o3+x0_1],%f32
	fmuld	%f0,%f4,%f4
	std	%f2,[%fp+y0_0]
	faddd	%f4,%f6,%f4
	fmuld	%f0,%f4,%f4
	fmuld	%f32,%f4,%f4
	ldd	[%o3+y0_0],%f2
	faddd	%f4,%f2,%f4
	faddd	%f32,%f4,%f6
2:
	add	%l5,thresh-4,%g1
	ld	[%fp+n0],%o3
	and	%o3,2,%o3
	sll	%o3,2,%o3
	ld	[%g1+%o3],%f8
	fxors	%f9,%f8,%f9
	fors	%f6,%f9,%f6		! tack on sign
	st	%f6,[%o0]
	st	%f7,[%o0+4]

.ENDLOOP0:

! check for huge arguments remaining

	tst	LIM_l6
	be,pt	%icc,.exit
! delay slot
	nop

! ========== huge range (use C code) ==========

#ifdef __sparcv9
	ldx	[%fp+xsave],%o1
	ldx	[%fp+ysave],%o3
#else
	ld	[%fp+xsave],%o1
	ld	[%fp+ysave],%o3
#endif
	ld	[%fp+nsave],%o0
	ld	[%fp+sxsave],%o2
	ld	[%fp+sysave],%o4
	sra	%o2,0,%o2		! sign-extend for V9
	sra	%o4,0,%o4
	call	__vlibm_vsin_big
	mov	%l7,%o5			! delay slot

.exit:
	ret
	restore


	.align	32
.SKIP0:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.ENDLOOP0
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	andn	%l1,%i5,%l0		! hx &= ~0x80000000
	fmovs	%f10,%f0
	ld	[%i1+4],%f1
	ba,pt	%icc,.LOOP0
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.SKIP1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.ENDLOOP1
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	andn	%l2,%i5,%l1		! hx &= ~0x80000000
	fmovs	%f20,%f10
	ld	[%i1+4],%f11
	ba,pt	%icc,.LOOP1
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.SKIP2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.ENDLOOP2
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	ld	[%i1],%l2
	ld	[%i1],%f20
	ld	[%i1+4],%f21
	andn	%l2,%i5,%l2		! hx &= ~0x80000000
	ba,pt	%icc,.LOOP2
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.BIG0:
	sethi	%hi(0x7ff00000),%o7
	cmp	%l0,%o7
	bl,a,pt	%icc,1f			! if hx < 0x7ff00000
! delay slot, annulled if branch not taken
	mov	%l7,LIM_l6		! set biguns flag or
	fsubd	%f0,%f0,%f0		! y = x - x
	st	%f0,[%o0]
	st	%f1,[%o0+4]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.ENDLOOP0
! delay slot, harmless if branch taken
	andn	%l1,%i5,%l0		! hx &= ~0x80000000
	fmovd	%f10,%f0
	ba,pt	%icc,.LOOP0
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.BIG1:
	sethi	%hi(0x7ff00000),%o7
	cmp	%l1,%o7
	bl,a,pt	%icc,1f			! if hx < 0x7ff00000
! delay slot, annulled if branch not taken
	mov	%l7,LIM_l6		! set biguns flag or
	fsubd	%f10,%f10,%f10		! y = x - x
	st	%f10,[%o1]
	st	%f11,[%o1+4]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.ENDLOOP1
! delay slot, harmless if branch taken
	andn	%l2,%i5,%l1		! hx &= ~0x80000000
	fmovd	%f20,%f10
	ba,pt	%icc,.LOOP1
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	32
.BIG2:
	sethi	%hi(0x7ff00000),%o7
	cmp	%l2,%o7
	bl,a,pt	%icc,1f			! if hx < 0x7ff00000
! delay slot, annulled if branch not taken
	mov	%l7,LIM_l6		! set biguns flag or
	fsubd	%f20,%f20,%f20		! y = x - x
	st	%f20,[%o2]
	st	%f21,[%o2+4]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.ENDLOOP2
! delay slot
	nop
	ld	[%i1],%l2
	ld	[%i1],%f20
	ld	[%i1+4],%f21
	andn	%l2,%i5,%l2		! hx &= ~0x80000000
	ba,pt	%icc,.LOOP2
! delay slot
	add	%i1,%i2,%i1		! x += stridex

	SET_SIZE(__vsin)

