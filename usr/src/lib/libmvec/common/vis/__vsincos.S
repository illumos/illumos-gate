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

	.file	"__vsincos.S"

#include "libm.h"

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
#define ssave		STACK_BIAS-0x10
#define csave		STACK_BIAS-0x18
#define nsave		STACK_BIAS-0x1c
#define sxsave		STACK_BIAS-0x20
#define sssave		STACK_BIAS-0x24
#define biguns		STACK_BIAS-0x28
#define junk		STACK_BIAS-0x30
#define nk2		STACK_BIAS-0x38
#define nk1		STACK_BIAS-0x3c
#define nk0		STACK_BIAS-0x40
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x40

! register use

! i0  n
! i1  x
! i2  stridex
! i3  s
! i4  strides
! i5  0x80000000,n0

! l0  hx0,k0
! l1  hx1,k1
! l2  hx2,k2
! l3  c
! l4  pc0
! l5  pc1
! l6  pc2
! l7  stridec

! the following are 64-bit registers in both V8+ and V9

! g1  __vlibm_TBL_sincos2
! g5  scratch,n1

! o0  ps0
! o1  ps1
! o2  ps2
! o3  0x3fe921fb
! o4  0x3e400000
! o5  0x4099251e
! o7  scratch,n2

! f0  x0,z0
! f2  abs(x0)
! f4  
! f6  
! f8  
! f10 x1,z1
! f12 abs(x1)
! f14 
! f16 
! f18 
! f20 x2,z2
! f22 abs(x2)
! f24 
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

	ENTRY(__vsincos)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,constants,o0)
	PIC_SET(l7,__vlibm_TBL_sincos2,o1)
	mov	%o1,%g1
	wr	%g0,0x82,%asi		! set %asi for non-faulting loads
#ifdef __sparcv9
	stx	%i1,[%fp+xsave]		! save arguments
	stx	%i3,[%fp+ssave]
	stx	%i5,[%fp+csave]
	ldx	[%fp+STACK_BIAS+0xb0],%l7
#else
	st	%i1,[%fp+xsave]		! save arguments
	st	%i3,[%fp+ssave]
	st	%i5,[%fp+csave]
	ld	[%fp+0x5c],%l7
#endif
	st	%i0,[%fp+nsave]
	st	%i2,[%fp+sxsave]
	st	%i4,[%fp+sssave]
	mov	%i5,%l3
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
	sethi	%hi(0x3fe921fb),%o3
	or	%o3,%lo(0x3fe921fb),%o3
	sethi	%hi(0x4099251e),%o5
	or	%o5,%lo(0x4099251e),%o5
	sll	%i2,3,%i2		! scale strides
	sll	%i4,3,%i4
	sll	%l7,3,%l7
	add	%fp,junk,%o0		! loop prologue
	add	%fp,junk,%o1
	add	%fp,junk,%o2
	ld	[%i1],%l0		! *x
	ld	[%i1],%f0
	ld	[%i1+4],%f3
	andn	%l0,%i5,%l0		! mask off sign
	ba	.loop0
	add	%i1,%i2,%i1		! x += stridex

! 16-byte aligned
	.align	16
.loop0:
	lda	[%i1]%asi,%l1		! preload next argument
	sub	%l0,%o4,%g5
	sub	%o5,%l0,%o7
	fabss	%f0,%f2

	lda	[%i1]%asi,%f10
	orcc	%o7,%g5,%g0
	mov	%i3,%o0			! ps0 = s
	bl,pn	%icc,.range0		! hx < 0x3e400000 or hx > 0x4099251e

! delay slot
	lda	[%i1+4]%asi,%f13
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! s += strides

	mov	%l3,%l4			! pc0 = c
	add	%l3,%l7,%l3		! c += stridec
	ble,pn	%icc,.last1

! delay slot
	andn	%l1,%i5,%l1
	add	%i1,%i2,%i1		! x += stridex
	faddd	%f2,c3two44,%f4
	st	%f17,[%o1+4]

.loop1:
	lda	[%i1]%asi,%l2		! preload next argument
	sub	%l1,%o4,%g5
	sub	%o5,%l1,%o7
	fabss	%f10,%f12

	lda	[%i1]%asi,%f20
	orcc	%o7,%g5,%g0
	mov	%i3,%o1			! ps1 = s
	bl,pn	%icc,.range1		! hx < 0x3e400000 or hx > 0x4099251e

! delay slot
	lda	[%i1+4]%asi,%f23
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! s += strides

	mov	%l3,%l5			! pc1 = c
	add	%l3,%l7,%l3		! c += stridec
	ble,pn	%icc,.last2

! delay slot
	andn	%l2,%i5,%l2
	add	%i1,%i2,%i1		! x += stridex
	faddd	%f12,c3two44,%f14
	st	%f27,[%o2+4]

.loop2:
	sub	%l2,%o4,%g5
	sub	%o5,%l2,%o7
	fabss	%f20,%f22
	st	%f5,[%fp+nk0]

	orcc	%o7,%g5,%g0
	mov	%i3,%o2			! ps2 = s
	bl,pn	%icc,.range2		! hx < 0x3e400000 or hx > 0x4099251e
! delay slot
	st	%f15,[%fp+nk1]

	mov	%l3,%l6			! pc2 = c

.cont:
	add	%i3,%i4,%i3		! s += strides
	add	%l3,%l7,%l3		! c += stridec
	faddd	%f22,c3two44,%f24
	st	%f25,[%fp+nk2]

	sub	%o3,%l0,%l0
	sub	%o3,%l1,%l1
	fmovs	%f3,%f1

	sub	%o3,%l2,%l2
	fmovs	%f13,%f11

	or	%l0,%l1,%l0
	orcc	%l0,%l2,%g0
	fmovs	%f23,%f21

	fmuld	%f0,invpio2,%f6		! x * invpio2, for medium range

	fmuld	%f10,invpio2,%f16
	ld	[%fp+nk0],%l0

	fmuld	%f20,invpio2,%f26
	ld	[%fp+nk1],%l1

	bl,pn	%icc,.medium
! delay slot
	ld	[%fp+nk2],%l2

	sll	%l0,5,%l0		! k
	fcmpd	%fcc0,%f0,pio2_3	! x < pio2_3 iff x < 0

	sll	%l1,5,%l1
	ldd	[%l0+%g1],%f4
	fcmpd	%fcc1,%f10,pio2_3

	sll	%l2,5,%l2
	ldd	[%l1+%g1],%f14
	fcmpd	%fcc2,%f20,pio2_3

	ldd	[%l2+%g1],%f24

	fsubd	%f2,%f4,%f2		! x -= __vlibm_TBL_sincos2[k]

	fsubd	%f12,%f14,%f12

	fsubd	%f22,%f24,%f22

	fmuld	%f2,%f2,%f0		! z = x * x

	fmuld	%f12,%f12,%f10

	fmuld	%f22,%f22,%f20

	fmuld	%f0,pp3,%f6

	fmuld	%f10,pp3,%f16

	fmuld	%f20,pp3,%f26

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq3,%f4

	faddd	%f16,pp2,%f16
	fmuld	%f10,qq3,%f14

	faddd	%f26,pp2,%f26
	fmuld	%f20,qq3,%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq2,%f4

	fmuld	%f10,%f16,%f16
	faddd	%f14,qq2,%f14

	fmuld	%f20,%f26,%f26
	faddd	%f24,qq2,%f24

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l0,%g1,%l0

	faddd	%f16,pp1,%f16
	fmuld	%f10,%f14,%f14
	add	%l1,%g1,%l1

	faddd	%f26,pp1,%f26
	fmuld	%f20,%f24,%f24
	add	%l2,%g1,%l2

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	fmuld	%f10,%f16,%f16
	faddd	%f14,qq1,%f14

	fmuld	%f20,%f26,%f26
	faddd	%f24,qq1,%f24

	fmuld	%f2,%f6,%f6
	ldd	[%l0+8],%f8

	fmuld	%f12,%f16,%f16
	ldd	[%l1+8],%f18

	fmuld	%f22,%f26,%f26
	ldd	[%l2+8],%f28

	faddd	%f6,%f2,%f6
	fmuld	%f0,%f4,%f4
	ldd	[%l0+16],%f30

	faddd	%f16,%f12,%f16
	fmuld	%f10,%f14,%f14
	ldd	[%l1+16],%f32

	faddd	%f26,%f22,%f26
	fmuld	%f20,%f24,%f24
	ldd	[%l2+16],%f34

	fmuld	%f8,%f6,%f0		! s * spoly

	fmuld	%f18,%f16,%f10

	fmuld	%f28,%f26,%f20

	fmuld	%f30,%f4,%f2		! c * cpoly

	fmuld	%f32,%f14,%f12

	fmuld	%f34,%f24,%f22

	fmuld	%f30,%f6,%f6		! c * spoly
	fsubd	%f2,%f0,%f2

	fmuld	%f32,%f16,%f16
	fsubd	%f12,%f10,%f12

	fmuld	%f34,%f26,%f26
	fsubd	%f22,%f20,%f22

	fmuld	%f8,%f4,%f4		! s * cpoly
	faddd	%f2,%f30,%f2
	st	%f2,[%l4]

	fmuld	%f18,%f14,%f14
	faddd	%f12,%f32,%f12
	st	%f3,[%l4+4]

	fmuld	%f28,%f24,%f24
	faddd	%f22,%f34,%f22
	st	%f12,[%l5]

	faddd	%f6,%f4,%f6
	st	%f13,[%l5+4]

	faddd	%f16,%f14,%f16
	st	%f22,[%l6]

	faddd	%f26,%f24,%f26
	st	%f23,[%l6+4]

	faddd	%f6,%f8,%f6

	faddd	%f16,%f18,%f16

	faddd	%f26,%f28,%f26

	fnegd	%f6,%f4
	lda	[%i1]%asi,%l0		! preload next argument

	fnegd	%f16,%f14
	lda	[%i1]%asi,%f0

	fnegd	%f26,%f24
	lda	[%i1+4]%asi,%f3
	andn	%l0,%i5,%l0
	add	%i1,%i2,%i1

	fmovdl	%fcc0,%f4,%f6		! (hx < -0)? -s : s
	st	%f6,[%o0]

	fmovdl	%fcc1,%f14,%f16
	st	%f16,[%o1]

	fmovdl	%fcc2,%f24,%f26
	st	%f26,[%o2]
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

	faddd	%f16,c3two51,%f14
	st	%f15,[%fp+nk1]

	faddd	%f26,c3two51,%f24
	st	%f25,[%fp+nk2]

	fsubd	%f4,c3two51,%f6

	fsubd	%f14,c3two51,%f16

	fsubd	%f24,c3two51,%f26

	fmuld	%f6,pio2_1,%f2
	ld	[%fp+nk0],%i5		! n

	fmuld	%f16,pio2_1,%f12
	ld	[%fp+nk1],%g5

	fmuld	%f26,pio2_1,%f22
	ld	[%fp+nk2],%o7

	fsubd	%f0,%f2,%f0
	fmuld	%f6,pio2_2,%f4
	mov	%o0,%o4			! if (n & 1) swap ps, pc
	andcc	%i5,1,%g0

	fsubd	%f10,%f12,%f10
	fmuld	%f16,pio2_2,%f14
	movnz	%icc,%l4,%o0
	and	%i5,3,%i5

	fsubd	%f20,%f22,%f20
	fmuld	%f26,pio2_2,%f24
	movnz	%icc,%o4,%l4

	fsubd	%f0,%f4,%f30
	mov	%o1,%o4
	andcc	%g5,1,%g0

	fsubd	%f10,%f14,%f32
	movnz	%icc,%l5,%o1
	and	%g5,3,%g5

	fsubd	%f20,%f24,%f34
	movnz	%icc,%o4,%l5

	fsubd	%f0,%f30,%f0
	fcmple32 %f30,pio2_3,%l0	! x <= pio2_3 iff x < 0
	mov	%o2,%o4
	andcc	%o7,1,%g0

	fsubd	%f10,%f32,%f10
	fcmple32 %f32,pio2_3,%l1
	movnz	%icc,%l6,%o2
	and	%o7,3,%o7

	fsubd	%f20,%f34,%f20
	fcmple32 %f34,pio2_3,%l2
	movnz	%icc,%o4,%l6

	fsubd	%f0,%f4,%f0
	fmuld	%f6,pio2_3,%f6
	add	%i5,1,%o4		! n = (n >> 1) | (((n + 1) ^ l) & 2)
	srl	%i5,1,%i5

	fsubd	%f10,%f14,%f10
	fmuld	%f16,pio2_3,%f16
	xor	%o4,%l0,%o4

	fsubd	%f20,%f24,%f20
	fmuld	%f26,pio2_3,%f26
	and	%o4,2,%o4

	fsubd	%f6,%f0,%f6
	or	%i5,%o4,%i5

	fsubd	%f16,%f10,%f16
	add	%g5,1,%o4
	srl	%g5,1,%g5

	fsubd	%f26,%f20,%f26
	xor	%o4,%l1,%o4

	fsubd	%f30,%f6,%f0		! reduced x
	and	%o4,2,%o4

	fsubd	%f32,%f16,%f10
	or	%g5,%o4,%g5

	fsubd	%f34,%f26,%f20
	add	%o7,1,%o4
	srl	%o7,1,%o7

	fzero	%f38
	xor	%o4,%l2,%o4

	fabsd	%f0,%f2
	and	%o4,2,%o4

	fabsd	%f10,%f12
	or	%o7,%o4,%o7

	fabsd	%f20,%f22
	sethi	%hi(0x3e400000),%o4

	fnegd	%f38,%f38

	faddd	%f2,c3two44,%f4
	st	%f5,[%fp+nk0]

	faddd	%f12,c3two44,%f14
	st	%f15,[%fp+nk1]

	faddd	%f22,c3two44,%f24
	st	%f25,[%fp+nk2]

	fsubd	%f30,%f0,%f4

	fsubd	%f32,%f10,%f14

	fsubd	%f34,%f20,%f24

	fsubd	%f4,%f6,%f6		! w
	ld	[%fp+nk0],%l0

	fsubd	%f14,%f16,%f16
	ld	[%fp+nk1],%l1

	fsubd	%f24,%f26,%f26
	ld	[%fp+nk2],%l2
	sll	%l0,5,%l0		! k

	fand	%f0,%f38,%f30		! sign bit of x
	ldd	[%l0+%g1],%f4
	sll	%l1,5,%l1

	fand	%f10,%f38,%f32
	ldd	[%l1+%g1],%f14
	sll	%l2,5,%l2

	fand	%f20,%f38,%f34
	ldd	[%l2+%g1],%f24

	fsubd	%f2,%f4,%f2		! x -= __vlibm_TBL_sincos2[k]

	fsubd	%f12,%f14,%f12

	fsubd	%f22,%f24,%f22

	fmuld	%f2,%f2,%f0		! z = x * x
	fxor	%f6,%f30,%f30

	fmuld	%f12,%f12,%f10
	fxor	%f16,%f32,%f32

	fmuld	%f22,%f22,%f20
	fxor	%f26,%f34,%f34

	fmuld	%f0,pp3,%f6

	fmuld	%f10,pp3,%f16

	fmuld	%f20,pp3,%f26

	faddd	%f6,pp2,%f6
	fmuld	%f0,qq3,%f4

	faddd	%f16,pp2,%f16
	fmuld	%f10,qq3,%f14

	faddd	%f26,pp2,%f26
	fmuld	%f20,qq3,%f24

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq2,%f4

	fmuld	%f10,%f16,%f16
	faddd	%f14,qq2,%f14

	fmuld	%f20,%f26,%f26
	faddd	%f24,qq2,%f24

	faddd	%f6,pp1,%f6
	fmuld	%f0,%f4,%f4
	add	%l0,%g1,%l0

	faddd	%f16,pp1,%f16
	fmuld	%f10,%f14,%f14
	add	%l1,%g1,%l1

	faddd	%f26,pp1,%f26
	fmuld	%f20,%f24,%f24
	add	%l2,%g1,%l2

	fmuld	%f0,%f6,%f6
	faddd	%f4,qq1,%f4

	fmuld	%f10,%f16,%f16
	faddd	%f14,qq1,%f14

	fmuld	%f20,%f26,%f26
	faddd	%f24,qq1,%f24

	fmuld	%f2,%f6,%f6
	ldd	[%l0+16],%f8

	fmuld	%f12,%f16,%f16
	ldd	[%l1+16],%f18

	fmuld	%f22,%f26,%f26
	ldd	[%l2+16],%f28

	faddd	%f6,%f30,%f6
	fmuld	%f0,%f4,%f4
	ldd	[%l0+8],%f30

	faddd	%f16,%f32,%f16
	fmuld	%f10,%f14,%f14
	ldd	[%l1+8],%f32

	faddd	%f26,%f34,%f26
	fmuld	%f20,%f24,%f24
	ldd	[%l2+8],%f34

	fmuld	%f8,%f4,%f0		! c * cpoly
	faddd	%f6,%f2,%f6

	fmuld	%f18,%f14,%f10
	faddd	%f16,%f12,%f16

	fmuld	%f28,%f24,%f20
	faddd	%f26,%f22,%f26

	fmuld	%f30,%f6,%f2		! s * spoly

	fmuld	%f32,%f16,%f12

	fmuld	%f34,%f26,%f22

	fmuld	%f8,%f6,%f6		! c * spoly
	fsubd	%f0,%f2,%f2

	fmuld	%f18,%f16,%f16
	fsubd	%f10,%f12,%f12

	fmuld	%f28,%f26,%f26
	fsubd	%f20,%f22,%f22

	fmuld	%f30,%f4,%f4		! s * cpoly
	faddd	%f8,%f2,%f8

	fmuld	%f32,%f14,%f14
	faddd	%f18,%f12,%f18

	fmuld	%f34,%f24,%f24
	faddd	%f28,%f22,%f28

	faddd	%f4,%f6,%f6

	faddd	%f14,%f16,%f16

	faddd	%f24,%f26,%f26

	faddd	%f30,%f6,%f6		! now %f6 = sin |x|, %f8 = cos |x|

	faddd	%f32,%f16,%f16

	faddd	%f34,%f26,%f26

	fnegd	%f8,%f4			! if (n & 1) c = -c
	lda	[%i1]%asi,%l0		! preload next argument
	mov	%i5,%l1

	fnegd	%f18,%f14
	lda	[%i1]%asi,%f0
	sethi	%hi(0x80000000),%i5

	fnegd	%f28,%f24
	lda	[%i1+4]%asi,%f3

	andcc	%l1,1,%g0
	fmovdnz	%icc,%f4,%f8
	st	%f8,[%l4]

	andcc	%g5,1,%g0
	fmovdnz	%icc,%f14,%f18
	st	%f9,[%l4+4]

	andcc	%o7,1,%g0
	fmovdnz	%icc,%f24,%f28
	st	%f18,[%l5]

	fnegd	%f6,%f4			! if (n & 2) s = -s
	st	%f19,[%l5+4]
	andn	%l0,%i5,%l0

	fnegd	%f16,%f14
	st	%f28,[%l6]
	add	%i1,%i2,%i1

	fnegd	%f26,%f24
	st	%f29,[%l6+4]

	andcc	%l1,2,%g0
	fmovdnz	%icc,%f4,%f6
	st	%f6,[%o0]

	andcc	%g5,2,%g0
	fmovdnz	%icc,%f14,%f16
	st	%f16,[%o1]

	andcc	%o7,2,%g0
	fmovdnz	%icc,%f24,%f26
	st	%f26,[%o2]

	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	st	%f7,[%o0+4]

	ba,pt	%icc,.end
! delay slot
	nop


	.align	16
.end:
	st	%f17,[%o1+4]
	st	%f27,[%o2+4]
	ld	[%fp+biguns],%i5
	tst	%i5			! check for huge arguments remaining
	be,pt	%icc,.exit
! delay slot
	nop
#ifdef __sparcv9
	stx	%o5,[%sp+STACK_BIAS+0xb8]
	ldx	[%fp+xsave],%o1
	ldx	[%fp+ssave],%o3
	ldx	[%fp+csave],%o5
	ldx	[%fp+STACK_BIAS+0xb0],%i5
	stx	%i5,[%sp+STACK_BIAS+0xb0]
#else
	st	%o5,[%sp+0x60]
	ld	[%fp+xsave],%o1
	ld	[%fp+ssave],%o3
	ld	[%fp+csave],%o5
	ld	[%fp+0x5c],%i5
	st	%i5,[%sp+0x5c]
#endif
	ld	[%fp+nsave],%o0
	ld	[%fp+sxsave],%o2
	ld	[%fp+sssave],%o4
	sra	%o2,0,%o2		! sign-extend for V9
	call	__vlibm_vsincos_big
	sra	%o4,0,%o4		! delay slot

.exit:
	ret
	restore


	.align	16
.last1:
	faddd	%f2,c3two44,%f4
	st	%f17,[%o1+4]
.last1_from_range1:
	mov	0,%l1
	fzeros	%f10
	fzero	%f12
	add	%fp,junk,%o1
	add	%fp,junk,%l5
.last2:
	faddd	%f12,c3two44,%f14
	st	%f27,[%o2+4]
	st	%f5,[%fp+nk0]
	st	%f15,[%fp+nk1]
.last2_from_range2:
	mov	0,%l2
	fzeros	%f20
	fzero	%f22
	add	%fp,junk,%o2
	ba,pt	%icc,.cont
! delay slot
	add	%fp,junk,%l6


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
	st	%f3,[%o0+4]
	st	%f2,[%l3]
	ba,pt	%icc,2f
! delay slot
	st	%f3,[%l3+4]
1:
	fdtoi	%f2,%f4			! raise inexact if not zero
	st	%f0,[%o0]
	st	%f3,[%o0+4]
	sethi	%hi(0x3ff00000),%g5
	st	%g5,[%l3]
	st	%g0,[%l3+4]
2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.end
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! s += strides
	add	%l3,%l7,%l3		! c += stridec
	andn	%l1,%i5,%l0		! hx &= ~0x80000000
	fmovs	%f10,%f0
	fmovs	%f13,%f3
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
	fzero	%f10
	fmuld	%f12,%f10,%f12
	st	%f12,[%o1]
	st	%f13,[%o1+4]
	st	%f12,[%l3]
	ba,pt	%icc,2f
! delay slot
	st	%f13,[%l3+4]
1:
	fdtoi	%f12,%f14		! raise inexact if not zero
	st	%f10,[%o1]
	st	%f13,[%o1+4]
	sethi	%hi(0x3ff00000),%g5
	st	%g5,[%l3]
	st	%g0,[%l3+4]
2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last1_from_range1
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! s += strides
	add	%l3,%l7,%l3		! c += stridec
	andn	%l2,%i5,%l1		! hx &= ~0x80000000
	fmovs	%f20,%f10
	fmovs	%f23,%f13
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
	fzero	%f20
	fmuld	%f22,%f20,%f22
	st	%f22,[%o2]
	st	%f23,[%o2+4]
	st	%f22,[%l3]
	ba,pt	%icc,2f
! delay slot
	st	%f23,[%l3+4]
1:
	fdtoi	%f22,%f24		! raise inexact if not zero
	st	%f20,[%o2]
	st	%f23,[%o2+4]
	sethi	%hi(0x3ff00000),%g5
	st	%g5,[%l3]
	st	%g0,[%l3+4]
2:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last2_from_range2
! delay slot, harmless if branch taken
	add	%i3,%i4,%i3		! s += strides
	add	%l3,%l7,%l3		! c += stridec
	ld	[%i1],%l2
	ld	[%i1],%f20
	ld	[%i1+4],%f23
	andn	%l2,%i5,%l2		! hx &= ~0x80000000
	ba,pt	%icc,.loop2
! delay slot
	add	%i1,%i2,%i1		! x += stridex

	SET_SIZE(__vsincos)

