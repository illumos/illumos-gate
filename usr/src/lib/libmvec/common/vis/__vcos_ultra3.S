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

	.file	"__vcos_ultra3.S"

#include "libm.h"
#if defined(LIBMVEC_SO_BUILD)
	.weak	__vcos
	.type	__vcos,#function
	__vcos = __vcos_ultra3
#endif

	RO_DATA
	.align	64
constants:
	.word	0x42c80000,0x00000000	! 3 * 2^44
	.word	0x43380000,0x00000000	! 3 * 2^51
	.word	0x3fe45f30,0x6dc9c883	! invpio2
	.word	0x3ff921fb,0x54442c00	! pio2_1
	.word	0x3d318469,0x898cc400	! pio2_2
	.word	0x3a71701b,0x839a2520	! pio2_3
	.word	0xbfc55555,0x55555533	! pp1
	.word	0x3f811111,0x10e7d53b	! pp2
	.word	0xbf2a0167,0xe6b3cf9b	! pp3
	.word	0xbfdfffff,0xffffff65	! qq1
	.word	0x3fa55555,0x54f88ed0	! qq2
	.word	0xbf56c12c,0xdd185f60	! qq3

! local storage indices

#define xsave		STACK_BIAS-0x8
#define ysave		STACK_BIAS-0x10
#define nsave		STACK_BIAS-0x14
#define sxsave		STACK_BIAS-0x18
#define sysave		STACK_BIAS-0x1c
#define biguns		STACK_BIAS-0x20
#define nk3		STACK_BIAS-0x24
#define nk2		STACK_BIAS-0x28
#define nk1		STACK_BIAS-0x2c
#define nk0		STACK_BIAS-0x30
#define junk		STACK_BIAS-0x38
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x40

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
! l3  hx3
! l4  k0
! l5  k1
! l6  k2
! l7  k3

! the following are 64-bit registers in both V8+ and V9

! g1  __vlibm_TBL_sincos2
! g5  scratch

! o0  py0
! o1  py1
! o2  py2
! o3  py3
! o4  0x3e400000
! o5  0x3fe921fb,0x4099251e
! o7  scratch

! f0  hx0
! f2  
! f4  
! f6  
! f8  hx1
! f10 
! f12 
! f14 
! f16 hx2
! f18 
! f20 
! f22 
! f24 hx3
! f26 
! f28 
! f30 
! f32 
! f34 
! f36
! f38

#define c3two44	%f40
#define c3two51	%f42
#define invpio2	%f44
#define pio2_1	%f46
#define pio2_2	%f48
#define pio2_3	%f50
#define pp1	%f52
#define pp2	%f54
#define pp3	%f56
#define qq1	%f58
#define qq2	%f60
#define qq3	%f62

	ENTRY(__vcos_ultra3)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,constants,o0)
	PIC_SET(l7,__vlibm_TBL_sincos2,o1)
	mov	%o1,%g1
	wr	%g0,0x82,%asi		! set %asi for non-faulting loads
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
	st	%g0,[%fp+biguns]	! biguns = 0
	ldd	[%o0+0x00],c3two44	! load/set up constants
	ldd	[%o0+0x08],c3two51
	ldd	[%o0+0x10],invpio2
	ldd	[%o0+0x18],pio2_1
	ldd	[%o0+0x20],pio2_2
	ldd	[%o0+0x28],pio2_3
	ldd	[%o0+0x30],pp1
	ldd	[%o0+0x38],pp2
	ldd	[%o0+0x40],pp3
	ldd	[%o0+0x48],qq1
	ldd	[%o0+0x50],qq2
	ldd	[%o0+0x58],qq3
	sethi	%hi(0x80000000),%i5
	sethi	%hi(0x3e400000),%o4
	sethi	%hi(0x3fe921fb),%o5
	or	%o5,%lo(0x3fe921fb),%o5
	sllx	%o5,32,%o5
	sethi	%hi(0x4099251e),%o7
	or	%o7,%lo(0x4099251e),%o7
	or	%o5,%o7,%o5
	sll	%i2,3,%i2		! scale strides
	sll	%i4,3,%i4
	add	%fp,junk,%o1		! loop prologue
	add	%fp,junk,%o2
	add	%fp,junk,%o3
	ld	[%i1],%l0		! *x
	ld	[%i1],%f0
	ld	[%i1+4],%f3
	andn	%l0,%i5,%l0		! mask off sign
	add	%i1,%i2,%i1		! x += stridex
	ba	.loop0
	nop

! 16-byte aligned
	.align	16
.loop0:
	lda	[%i1]%asi,%l1		! preload next argument
	sub	%l0,%o4,%g5
	sub	%o5,%l0,%o7
	fabss	%f0,%f2

	lda	[%i1]%asi,%f8
	orcc	%o7,%g5,%g0
	mov	%i3,%o0			! py0 = y
	bl,pn	%icc,.range0		! hx < 0x3e400000 or hx > 0x4099251e

! delay slot
	lda	[%i1+4]%asi,%f11
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.last1

! delay slot
	andn	%l1,%i5,%l1
	add	%i1,%i2,%i1		! x += stridex
	faddd	%f2,c3two44,%f4
	st	%f15,[%o1+4]

.loop1:
	lda	[%i1]%asi,%l2		! preload next argument
	sub	%l1,%o4,%g5
	sub	%o5,%l1,%o7
	fabss	%f8,%f10

	lda	[%i1]%asi,%f16
	orcc	%o7,%g5,%g0
	mov	%i3,%o1			! py1 = y
	bl,pn	%icc,.range1		! hx < 0x3e400000 or hx > 0x4099251e

! delay slot
	lda	[%i1+4]%asi,%f19
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.last2

! delay slot
	andn	%l2,%i5,%l2
	add	%i1,%i2,%i1		! x += stridex
	faddd	%f10,c3two44,%f12
	st	%f23,[%o2+4]

.loop2:
	lda	[%i1]%asi,%l3		! preload next argument
	sub	%l2,%o4,%g5
	sub	%o5,%l2,%o7
	fabss	%f16,%f18

	lda	[%i1]%asi,%f24
	orcc	%o7,%g5,%g0
	mov	%i3,%o2			! py2 = y
	bl,pn	%icc,.range2		! hx < 0x3e400000 or hx > 0x4099251e

! delay slot
	lda	[%i1+4]%asi,%f27
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.last3

! delay slot
	andn	%l3,%i5,%l3
	add	%i1,%i2,%i1		! x += stridex
	faddd	%f18,c3two44,%f20
	st	%f31,[%o3+4]

.loop3:
	sub	%l3,%o4,%g5
	sub	%o5,%l3,%o7
	fabss	%f24,%f26
	st	%f5,[%fp+nk0]

	orcc	%o7,%g5,%g0
	mov	%i3,%o3			! py3 = y
	bl,pn	%icc,.range3		! hx < 0x3e400000 or > hx 0x4099251e
! delay slot
	st	%f13,[%fp+nk1]

!!! DONE?
.cont:
	srlx	%o5,32,%o7
	add	%i3,%i4,%i3		! y += stridey
	fmovs	%f3,%f1
	st	%f21,[%fp+nk2]

	sub	%o7,%l0,%l0
	sub	%o7,%l1,%l1
	faddd	%f26,c3two44,%f28
	st	%f29,[%fp+nk3]

	sub	%o7,%l2,%l2
	sub	%o7,%l3,%l3
	fmovs	%f11,%f9

	or	%l0,%l1,%l0
	or	%l2,%l3,%l2
	fmovs	%f19,%f17

	fmovs	%f27,%f25
	fmuld	%f0,invpio2,%f6		! x * invpio2, for medium range

	fmuld	%f8,invpio2,%f14
	ld	[%fp+nk0],%l4

	fmuld	%f16,invpio2,%f22
	ld	[%fp+nk1],%l5

	orcc	%l0,%l2,%g0
	bl,pn	%icc,.medium
! delay slot
	fmuld	%f24,invpio2,%f30
	ld	[%fp+nk2],%l6

	ld	[%fp+nk3],%l7
	sll	%l4,5,%l4		! k
	fcmpd	%fcc0,%f0,pio2_3	! x < pio2_3 iff x < 0

	sll	%l5,5,%l5
	ldd	[%l4+%g1],%f4
	fcmpd	%fcc1,%f8,pio2_3

	sll	%l6,5,%l6
	ldd	[%l5+%g1],%f12
	fcmpd	%fcc2,%f16,pio2_3

	sll	%l7,5,%l7
	ldd	[%l6+%g1],%f20
	fcmpd	%fcc3,%f24,pio2_3

	ldd	[%l7+%g1],%f28
	fsubd	%f2,%f4,%f2		! x -= __vlibm_TBL_sincos2[k]

	fsubd	%f10,%f12,%f10

	fsubd	%f18,%f20,%f18

	fsubd	%f26,%f28,%f26

	fmuld	%f2,%f2,%f0		! z = x * x

	fmuld	%f10,%f10,%f8

	fmuld	%f18,%f18,%f16

	fmuld	%f26,%f26,%f24

	fmuld	%f0,qq3,%f6

	fmuld	%f8,qq3,%f14

	fmuld	%f16,qq3,%f22

	fmuld	%f24,qq3,%f30

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+16],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+16],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+16],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+16],%f38

	fmuld	%f32,%f6,%f6
	ldd	[%l4+8],%f2

	fmuld	%f34,%f14,%f14
	ldd	[%l5+8],%f10

	fmuld	%f36,%f22,%f22
	ldd	[%l6+8],%f18

	fmuld	%f38,%f30,%f30
	ldd	[%l7+8],%f26

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f28,%f28

	fsubd	%f6,%f4,%f6
	lda	[%i1]%asi,%l0		! preload next argument

	fsubd	%f14,%f12,%f14
	lda	[%i1]%asi,%f0

	fsubd	%f22,%f20,%f22
	lda	[%i1+4]%asi,%f3

	fsubd	%f30,%f28,%f30
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	faddd	%f6,%f32,%f6
	st	%f6,[%o0]

	faddd	%f14,%f34,%f14
	st	%f14,[%o1]

	faddd	%f22,%f36,%f22
	st	%f22,[%o2]

	faddd	%f30,%f38,%f30
	st	%f30,[%o3]
	addcc	%i0,-1,%i0

	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop


	.align	16
.medium:
	faddd	%f6,c3two51,%f4
	st	%f5,[%fp+nk0]

	faddd	%f14,c3two51,%f12
	st	%f13,[%fp+nk1]

	faddd	%f22,c3two51,%f20
	st	%f21,[%fp+nk2]

	faddd	%f30,c3two51,%f28
	st	%f29,[%fp+nk3]

	fsubd	%f4,c3two51,%f6

	fsubd	%f12,c3two51,%f14

	fsubd	%f20,c3two51,%f22

	fsubd	%f28,c3two51,%f30

	fmuld	%f6,pio2_1,%f2
	ld	[%fp+nk0],%l0		! n

	fmuld	%f14,pio2_1,%f10
	ld	[%fp+nk1],%l1

	fmuld	%f22,pio2_1,%f18
	ld	[%fp+nk2],%l2

	fmuld	%f30,pio2_1,%f26
	ld	[%fp+nk3],%l3

	fsubd	%f0,%f2,%f0
	fmuld	%f6,pio2_2,%f4
	add	%l0,1,%l0

	fsubd	%f8,%f10,%f8
	fmuld	%f14,pio2_2,%f12
	add	%l1,1,%l1

	fsubd	%f16,%f18,%f16
	fmuld	%f22,pio2_2,%f20
	add	%l2,1,%l2

	fsubd	%f24,%f26,%f24
	fmuld	%f30,pio2_2,%f28
	add	%l3,1,%l3

	fsubd	%f0,%f4,%f32

	fsubd	%f8,%f12,%f34

	fsubd	%f16,%f20,%f36

	fsubd	%f24,%f28,%f38

	fsubd	%f0,%f32,%f0
	fcmple32 %f32,pio2_3,%l4	! x <= pio2_3 iff x < 0

	fsubd	%f8,%f34,%f8
	fcmple32 %f34,pio2_3,%l5

	fsubd	%f16,%f36,%f16
	fcmple32 %f36,pio2_3,%l6

	fsubd	%f24,%f38,%f24
	fcmple32 %f38,pio2_3,%l7

	fsubd	%f0,%f4,%f0
	fmuld	%f6,pio2_3,%f6
	sll	%l4,30,%l4		! if (x < 0) n = -n ^ 2

	fsubd	%f8,%f12,%f8
	fmuld	%f14,pio2_3,%f14
	sll	%l5,30,%l5

	fsubd	%f16,%f20,%f16
	fmuld	%f22,pio2_3,%f22
	sll	%l6,30,%l6

	fsubd	%f24,%f28,%f24
	fmuld	%f30,pio2_3,%f30
	sll	%l7,30,%l7

	fsubd	%f6,%f0,%f6
	sra	%l4,31,%l4

	fsubd	%f14,%f8,%f14
	sra	%l5,31,%l5

	fsubd	%f22,%f16,%f22
	sra	%l6,31,%l6

	fsubd	%f30,%f24,%f30
	sra	%l7,31,%l7

	fsubd	%f32,%f6,%f0		! reduced x
	xor	%l0,%l4,%l0

	fsubd	%f34,%f14,%f8
	xor	%l1,%l5,%l1

	fsubd	%f36,%f22,%f16
	xor	%l2,%l6,%l2

	fsubd	%f38,%f30,%f24
	xor	%l3,%l7,%l3

	fabsd	%f0,%f2
	sub	%l0,%l4,%l0

	fabsd	%f8,%f10
	sub	%l1,%l5,%l1

	fabsd	%f16,%f18
	sub	%l2,%l6,%l2

	fabsd	%f24,%f26
	sub	%l3,%l7,%l3

	faddd	%f2,c3two44,%f4
	st	%f5,[%fp+nk0]
	and	%l4,2,%l4

	faddd	%f10,c3two44,%f12
	st	%f13,[%fp+nk1]
	and	%l5,2,%l5

	faddd	%f18,c3two44,%f20
	st	%f21,[%fp+nk2]
	and	%l6,2,%l6

	faddd	%f26,c3two44,%f28
	st	%f29,[%fp+nk3]
	and	%l7,2,%l7

	fsubd	%f32,%f0,%f4
	xor	%l0,%l4,%l0

	fsubd	%f34,%f8,%f12
	xor	%l1,%l5,%l1

	fsubd	%f36,%f16,%f20
	xor	%l2,%l6,%l2

	fsubd	%f38,%f24,%f28
	xor	%l3,%l7,%l3

	fzero	%f38
	ld	[%fp+nk0],%l4

	fsubd	%f4,%f6,%f6		! w
	ld	[%fp+nk1],%l5

	fsubd	%f12,%f14,%f14
	ld	[%fp+nk2],%l6

	fnegd	%f38,%f38
	ld	[%fp+nk3],%l7
	sll	%l4,5,%l4		! k

	fsubd	%f20,%f22,%f22
	sll	%l5,5,%l5

	fsubd	%f28,%f30,%f30
	sll	%l6,5,%l6

	fand	%f0,%f38,%f32		! sign bit of x
	ldd	[%l4+%g1],%f4
	sll	%l7,5,%l7

	fand	%f8,%f38,%f34
	ldd	[%l5+%g1],%f12

	fand	%f16,%f38,%f36
	ldd	[%l6+%g1],%f20

	fand	%f24,%f38,%f38
	ldd	[%l7+%g1],%f28

	fsubd	%f2,%f4,%f2		! x -= __vlibm_TBL_sincos2[k]

	fsubd	%f10,%f12,%f10

	fsubd	%f18,%f20,%f18
	nop

	fsubd	%f26,%f28,%f26
	nop

! 16-byte aligned
	fmuld	%f2,%f2,%f0		! z = x * x
	andcc	%l0,1,%g0
	bz,pn	%icc,.case8
! delay slot
	fxor	%f6,%f32,%f32

	fmuld	%f10,%f10,%f8
	andcc	%l1,1,%g0
	bz,pn	%icc,.case4
! delay slot
	fxor	%f14,%f34,%f34

	fmuld	%f18,%f18,%f16
	andcc	%l2,1,%g0
	bz,pn	%icc,.case2
! delay slot
	fxor	%f22,%f36,%f36

	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case1
! delay slot
	fxor	%f30,%f38,%f38

!.case0:
	fmuld	%f0,qq3,%f6		! cos(x0)

	fmuld	%f8,qq3,%f14		! cos(x1)

	fmuld	%f16,qq3,%f22		! cos(x2)

	fmuld	%f24,qq3,%f30		! cos(x3)

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f28,%f28

	fsubd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case1:
	fmuld	%f24,pp3,%f30		! sin(x3)

	fmuld	%f0,qq3,%f6		! cos(x0)

	fmuld	%f8,qq3,%f14		! cos(x1)

	fmuld	%f16,qq3,%f22		! cos(x2)

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f30,%f30

	fsubd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case2:
	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case3
! delay slot
	fxor	%f30,%f38,%f38

	fmuld	%f16,pp3,%f22		! sin(x2)

	fmuld	%f0,qq3,%f6		! cos(x0)

	fmuld	%f8,qq3,%f14		! cos(x1)

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	fmuld	%f24,qq3,%f30		! cos(x3)

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f28,%f28

	fsubd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case3:
	fmuld	%f16,pp3,%f22		! sin(x2)

	fmuld	%f24,pp3,%f30		! sin(x3)

	fmuld	%f0,qq3,%f6		! cos(x0)

	fmuld	%f8,qq3,%f14		! cos(x1)

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f30,%f30

	fsubd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case4:
	fmuld	%f18,%f18,%f16
	andcc	%l2,1,%g0
	bz,pn	%icc,.case6
! delay slot
	fxor	%f22,%f36,%f36

	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case5
! delay slot
	fxor	%f30,%f38,%f38

	fmuld	%f8,pp3,%f14		! sin(x1)

	fmuld	%f0,qq3,%f6		! cos(x0)

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	fmuld	%f16,qq3,%f22		! cos(x2)

	fmuld	%f24,qq3,%f30		! cos(x3)

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f28,%f28

	fsubd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case5:
	fmuld	%f8,pp3,%f14		! sin(x1)

	fmuld	%f24,pp3,%f30		! sin(x3)

	fmuld	%f0,qq3,%f6		! cos(x0)

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	fmuld	%f16,qq3,%f22		! cos(x2)

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f30,%f30

	fsubd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case6:
	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case7
! delay slot
	fxor	%f30,%f38,%f38

	fmuld	%f8,pp3,%f14		! sin(x1)

	fmuld	%f16,pp3,%f22		! sin(x2)

	fmuld	%f0,qq3,%f6		! cos(x0)

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	fmuld	%f24,qq3,%f30		! cos(x3)

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14

	fmuld	%f16,%f22,%f22

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f28,%f28

	fsubd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case7:
	fmuld	%f8,pp3,%f14		! sin(x1)

	fmuld	%f16,pp3,%f22		! sin(x2)

	fmuld	%f24,pp3,%f30		! sin(x3)

	fmuld	%f0,qq3,%f6		! cos(x0)

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	faddd	%f6,qq2,%f6
	fmuld	%f0,pp2,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,pp1,%f4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	faddd	%f6,qq1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14

	fmuld	%f16,%f22,%f22

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f4,%f4

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f32,%f4
	ldd	[%l4+16],%f0

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	fmuld	%f0,%f6,%f6
	faddd	%f4,%f2,%f4
	ldd	[%l4+8],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f4,%f4

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f30,%f30

	fsubd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case8:
	fmuld	%f10,%f10,%f8
	andcc	%l1,1,%g0
	bz,pn	%icc,.case12
! delay slot
	fxor	%f14,%f34,%f34

	fmuld	%f18,%f18,%f16
	andcc	%l2,1,%g0
	bz,pn	%icc,.case10
! delay slot
	fxor	%f22,%f36,%f36

	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case9
! delay slot
	fxor	%f30,%f38,%f38

	fmuld	%f0,pp3,%f6		! sin(x0)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	fmuld	%f8,qq3,%f14		! cos(x1)

	fmuld	%f16,qq3,%f22		! cos(x2)

	fmuld	%f24,qq3,%f30		! cos(x3)

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	fmuld	%f0,%f6,%f6

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f28,%f28

	faddd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case9:
	fmuld	%f0,pp3,%f6		! sin(x0)

	fmuld	%f24,pp3,%f30		! sin(x3)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	fmuld	%f8,qq3,%f14		! cos(x1)

	fmuld	%f16,qq3,%f22		! cos(x2)

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f0,%f6,%f6

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f30,%f30

	faddd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case10:
	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case11
! delay slot
	fxor	%f30,%f38,%f38

	fmuld	%f0,pp3,%f6		! sin(x0)

	fmuld	%f16,pp3,%f22		! sin(x2)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	fmuld	%f8,qq3,%f14		! cos(x1)

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	fmuld	%f24,qq3,%f30		! cos(x3)

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	fmuld	%f0,%f6,%f6

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f28,%f28

	faddd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case11:
	fmuld	%f0,pp3,%f6		! sin(x0)

	fmuld	%f16,pp3,%f22		! sin(x2)

	fmuld	%f24,pp3,%f30		! sin(x3)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	fmuld	%f8,qq3,%f14		! cos(x1)

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	faddd	%f14,qq2,%f14
	fmuld	%f8,pp2,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	fmuld	%f8,%f14,%f14
	faddd	%f12,pp1,%f12

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f0,%f6,%f6

	faddd	%f14,qq1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f12,%f12

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f34,%f12
	ldd	[%l5+16],%f8

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	fmuld	%f8,%f14,%f14
	faddd	%f12,%f10,%f12
	ldd	[%l5+8],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f12,%f12

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f30,%f30

	faddd	%f6,%f4,%f6

	fsubd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case12:
	fmuld	%f18,%f18,%f16
	andcc	%l2,1,%g0
	bz,pn	%icc,.case14
! delay slot
	fxor	%f22,%f36,%f36

	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case13
! delay slot
	fxor	%f30,%f38,%f38

	fmuld	%f0,pp3,%f6		! sin(x0)

	fmuld	%f8,pp3,%f14		! sin(x1)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	fmuld	%f16,qq3,%f22		! cos(x2)

	fmuld	%f24,qq3,%f30		! cos(x3)

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	fmuld	%f0,%f6,%f6

	fmuld	%f8,%f14,%f14

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f28,%f28

	faddd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case13:
	fmuld	%f0,pp3,%f6		! sin(x0)

	fmuld	%f8,pp3,%f14		! sin(x1)

	fmuld	%f24,pp3,%f30		! sin(x3)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	fmuld	%f16,qq3,%f22		! cos(x2)

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	faddd	%f22,qq2,%f22
	fmuld	%f16,pp2,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	fmuld	%f16,%f22,%f22
	faddd	%f20,pp1,%f20

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f0,%f6,%f6

	fmuld	%f8,%f14,%f14

	faddd	%f22,qq1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f20,%f20

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f36,%f20
	ldd	[%l6+16],%f16

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	fmuld	%f16,%f22,%f22
	faddd	%f20,%f18,%f20
	ldd	[%l6+8],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f20,%f20

	fmuld	%f38,%f30,%f30

	faddd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	fsubd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case14:
	fmuld	%f26,%f26,%f24
	andcc	%l3,1,%g0
	bz,pn	%icc,.case15
! delay slot
	fxor	%f30,%f38,%f38

	fmuld	%f0,pp3,%f6		! sin(x0)

	fmuld	%f8,pp3,%f14		! sin(x1)

	fmuld	%f16,pp3,%f22		! sin(x2)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	fmuld	%f24,qq3,%f30		! cos(x3)

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	faddd	%f30,qq2,%f30
	fmuld	%f24,pp2,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	fmuld	%f24,%f30,%f30
	faddd	%f28,pp1,%f28

	fmuld	%f0,%f6,%f6

	fmuld	%f8,%f14,%f14

	fmuld	%f16,%f22,%f22

	faddd	%f30,qq1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f28,%f28

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f38,%f28
	ldd	[%l7+16],%f24

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	fmuld	%f24,%f30,%f30
	faddd	%f28,%f26,%f28
	ldd	[%l7+8],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f28,%f28

	faddd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	fsubd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case15:
	fmuld	%f0,pp3,%f6		! sin(x0)

	fmuld	%f8,pp3,%f14		! sin(x1)

	fmuld	%f16,pp3,%f22		! sin(x2)

	fmuld	%f24,pp3,%f30		! sin(x3)

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq2,%f4

	faddd	%f14,pp2,%f14
	fmuld	%f8,qq2,%f12

	faddd	%f22,pp2,%f22
	fmuld	%f16,qq2,%f20

	faddd	%f30,pp2,%f30
	fmuld	%f24,qq2,%f28

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	fmuld	%f8,%f14,%f14
	faddd	%f12,qq1,%f12

	fmuld	%f16,%f22,%f22
	faddd	%f20,qq1,%f20

	fmuld	%f24,%f30,%f30
	faddd	%f28,qq1,%f28

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l4,%g1,%l4

	faddd	%f14,pp1,%f14
	fmuld	%f8,%f12,%f12
	add	%l5,%g1,%l5

	faddd	%f22,pp1,%f22
	fmuld	%f16,%f20,%f20
	add	%l6,%g1,%l6

	faddd	%f30,pp1,%f30
	fmuld	%f24,%f28,%f28
	add	%l7,%g1,%l7

	fmuld	%f0,%f6,%f6

	fmuld	%f8,%f14,%f14

	fmuld	%f16,%f22,%f22

	fmuld	%f24,%f30,%f30

	fmuld	%f2,%f6,%f6
	ldd	[%l4+8],%f0

	fmuld	%f10,%f14,%f14
	ldd	[%l5+8],%f8

	fmuld	%f18,%f22,%f22
	ldd	[%l6+8],%f16

	fmuld	%f26,%f30,%f30
	ldd	[%l7+8],%f24

	fmuld	%f0,%f4,%f4
	faddd	%f32,%f6,%f6

	fmuld	%f8,%f12,%f12
	faddd	%f34,%f14,%f14

	fmuld	%f16,%f20,%f20
	faddd	%f36,%f22,%f22

	fmuld	%f24,%f28,%f28
	faddd	%f38,%f30,%f30

	faddd	%f2,%f6,%f6
	ldd	[%l4+16],%f32

	faddd	%f10,%f14,%f14
	ldd	[%l5+16],%f34

	faddd	%f18,%f22,%f22
	ldd	[%l6+16],%f36

	faddd	%f26,%f30,%f30
	ldd	[%l7+16],%f38

	fmuld	%f32,%f6,%f6

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f22,%f22

	fmuld	%f38,%f30,%f30

	faddd	%f6,%f4,%f6

	faddd	%f14,%f12,%f14

	faddd	%f22,%f20,%f22

	faddd	%f30,%f28,%f30

	faddd	%f6,%f0,%f6

	faddd	%f14,%f8,%f14

	faddd	%f22,%f16,%f22

	faddd	%f30,%f24,%f30
	mov	%l0,%l4

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f14,%f12
	lda	[%i1]%asi,%f0

	fnegd	%f22,%f20
	lda	[%i1+4]%asi,%f3

	fnegd	%f30,%f28
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	andcc	%l4,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f12,%f14
	st	%f14,[%o1]

	andcc	%l2,2,%g0
	fmovdnz	%icc,%f20,%f22
	st	%f22,[%o2]

	andcc	%l3,2,%g0
	fmovdnz	%icc,%f28,%f30
	st	%f30,[%o3]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop


	.align	16
.end:
	st	%f15,[%o1+4]
	st	%f23,[%o2+4]
	st	%f31,[%o3+4]
	ld	[%fp+biguns],%i5
	tst	%i5			! check for huge arguments remaining
	be,pt	%icc,.exit
! delay slot
	nop
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
	call	__vlibm_vcos_big_ultra3
	sra	%o5,0,%o5		! delay slot

.exit:
	ret
	restore


	.align	16
.last1:
	faddd	%f2,c3two44,%f4
	st	%f15,[%o1+4]
.last1_from_range1:
	mov	0,%l1
	fzeros	%f8
	fzero	%f10
	add	%fp,junk,%o1
.last2:
	faddd	%f10,c3two44,%f12
	st	%f23,[%o2+4]
.last2_from_range2:
	mov	0,%l2
	fzeros	%f16
	fzero	%f18
	add	%fp,junk,%o2
.last3:
	faddd	%f18,c3two44,%f20
	st	%f31,[%o3+4]
	st	%f5,[%fp+nk0]
	st	%f13,[%fp+nk1]
.last3_from_range3:
	mov	0,%l3
	fzeros	%f24
	fzero	%f26
	ba,pt	%icc,.cont
! delay slot
	add	%fp,junk,%o3


	.align	16
.range0:
	cmp	%l0,%o4
	bl,pt	%icc,1f			! hx < 0x3e400000
! delay slot, harmless if branch taken
	sethi	%hi(0x7ff00000),%o7
	cmp	%l0,%o7
	bl,a,pt	%icc,2f			! branch if finite
! delay slot, squashed if branch not taken
	st	%o4,[%fp+biguns]	! set biguns
	fzero	%f0
	fmuld	%f2,%f0,%f2
	st	%f2,[%o0]
	ba,pt	%icc,2f
! delay slot
	st	%f3,[%o0+4]
1:
	fdtoi	%f2,%f4			! raise inexact if not zero
	sethi	%hi(0x3ff00000),%o7
	st	%o7,[%o0]
	st	%g0,[%o0+4]
2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.end
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	andn	%l1,%i5,%l0		! hx &= ~0x80000000
	fmovs	%f8,%f0
	fmovs	%f11,%f3
	ba,pt	%icc,.loop0
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	16
.range1:
	cmp	%l1,%o4
	bl,pt	%icc,1f			! hx < 0x3e400000
! delay slot, harmless if branch taken
	sethi	%hi(0x7ff00000),%o7
	cmp	%l1,%o7
	bl,a,pt	%icc,2f			! branch if finite
! delay slot, squashed if branch not taken
	st	%o4,[%fp+biguns]	! set biguns
	fzero	%f8
	fmuld	%f10,%f8,%f10
	st	%f10,[%o1]
	ba,pt	%icc,2f
! delay slot
	st	%f11,[%o1+4]
1:
	fdtoi	%f10,%f12		! raise inexact if not zero
	sethi	%hi(0x3ff00000),%o7
	st	%o7,[%o1]
	st	%g0,[%o1+4]
2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last1_from_range1
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	andn	%l2,%i5,%l1		! hx &= ~0x80000000
	fmovs	%f16,%f8
	fmovs	%f19,%f11
	ba,pt	%icc,.loop1
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	16
.range2:
	cmp	%l2,%o4
	bl,pt	%icc,1f			! hx < 0x3e400000
! delay slot, harmless if branch taken
	sethi	%hi(0x7ff00000),%o7
	cmp	%l2,%o7
	bl,a,pt	%icc,2f			! branch if finite
! delay slot, squashed if branch not taken
	st	%o4,[%fp+biguns]	! set biguns
	fzero	%f16
	fmuld	%f18,%f16,%f18
	st	%f18,[%o2]
	ba,pt	%icc,2f
! delay slot
	st	%f19,[%o2+4]
1:
	fdtoi	%f18,%f20		! raise inexact if not zero
	sethi	%hi(0x3ff00000),%o7
	st	%o7,[%o2]
	st	%g0,[%o2+4]
2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last2_from_range2
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	andn	%l3,%i5,%l2		! hx &= ~0x80000000
	fmovs	%f24,%f16
	fmovs	%f27,%f19
	ba,pt	%icc,.loop2
! delay slot
	add	%i1,%i2,%i1		! x += stridex


	.align	16
.range3:
	cmp	%l3,%o4
	bl,pt	%icc,1f			! hx < 0x3e400000
! delay slot, harmless if branch taken
	sethi	%hi(0x7ff00000),%o7
	cmp	%l3,%o7
	bl,a,pt	%icc,2f			! branch if finite
! delay slot, squashed if branch not taken
	st	%o4,[%fp+biguns]	! set biguns
	fzero	%f24
	fmuld	%f26,%f24,%f26
	st	%f26,[%o3]
	ba,pt	%icc,2f
! delay slot
	st	%f27,[%o3+4]
1:
	fdtoi	%f26,%f28		! raise inexact if not zero
	sethi	%hi(0x3ff00000),%o7
	st	%o7,[%o3]
	st	%g0,[%o3+4]
2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last3_from_range3
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! y += stridey
	ld	[%i1],%l3
	ld	[%i1],%f24
	ld	[%i1+4],%f27
	andn	%l3,%i5,%l3		! hx &= ~0x80000000
	ba,pt	%icc,.loop3
! delay slot
	add	%i1,%i2,%i1		! x += stridex

	SET_SIZE(__vcos_ultra3)

