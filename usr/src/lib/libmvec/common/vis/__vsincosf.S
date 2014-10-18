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

	.file	"__vsincosf.S"

#include "libm.h"

	RO_DATA
	.align	64
constants:
	.word	0xbfc55554,0x60000000
	.word	0x3f811077,0xe0000000
	.word	0xbf29956b,0x60000000
	.word	0x3ff00000,0x00000000
	.word	0xbfe00000,0x00000000
	.word	0x3fa55554,0xa0000000
	.word	0xbf56c0c1,0xe0000000
	.word	0x3ef99e24,0xe0000000
	.word	0x3fe45f30,0x6dc9c883
	.word	0x43380000,0x00000000
	.word	0x3ff921fb,0x54400000
	.word	0x3dd0b461,0x1a626331
	.word	0x3f490fdb,0
	.word	0x49c90fdb,0
	.word	0x7f800000,0
	.word	0x80000000,0

#define S0		0x0
#define S1		0x08
#define S2		0x10
#define one		0x18
#define mhalf		0x20
#define C0		0x28
#define C1		0x30
#define C2		0x38
#define invpio2		0x40
#define round		0x48
#define pio2_1		0x50
#define pio2_t		0x58
#define thresh1		0x60
#define thresh2		0x68
#define inf		0x70
#define signbit		0x78

! local storage indices

#define xsave		STACK_BIAS-0x8
#define ssave		STACK_BIAS-0x10
#define csave		STACK_BIAS-0x18
#define nsave		STACK_BIAS-0x1c
#define sxsave		STACK_BIAS-0x20
#define sssave		STACK_BIAS-0x24
#define junk		STACK_BIAS-0x28
#define n3		STACK_BIAS-0x38
#define n2		STACK_BIAS-0x40
#define n1		STACK_BIAS-0x48
#define n0		STACK_BIAS-0x50
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x50

! register use

! i0  n
! i1  x
! i2  stridex
! i3  s
! i4  strides
! i5  biguns

! l0  ps0
! l1  ps1
! l2  ps2
! l3  ps3
! l4  pc0
! l5  pc1
! l6  pc2
! l7  pc3

! the following are 64-bit registers in both V8+ and V9

! g1  
! g5  

! o0  n0
! o1  n1
! o2  n2
! o3  n3
! o4  c
! o5  stridec
! o7  

! f0  x0
! f2  x1
! f4  x2
! f6  x3
! f8  thresh1 (pi/4)
! f10 s0
! f12 s1
! f14 s2
! f16 s3
! f18 thresh2 (2^19 pi)
! f20 c0
! f22 c1
! f24 c2
! f26 c3
! f28 signbit
! f30 
! f32 
! f34 
! f36 
! f38 inf
! f40 S0
! f42 S1
! f44 S2
! f46 one
! f48 mhalf
! f50 C0
! f52 C1
! f54 C2
! f56 invpio2
! f58 round
! f60 pio2_1
! f62 pio2_t

	ENTRY(__vsincosf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,constants,o0)
	mov	%o0,%g1

#ifdef __sparcv9
	stx	%i1,[%fp+xsave]		! save arguments
	stx	%i3,[%fp+ssave]
	stx	%i5,[%fp+csave]
	ldx	[%fp+STACK_BIAS+0xb0],%o5
#else
	st	%i1,[%fp+xsave]		! save arguments
	st	%i3,[%fp+ssave]
	st	%i5,[%fp+csave]
	ld	[%fp+0x5c],%o5
#endif
	st	%i0,[%fp+nsave]
	st	%i2,[%fp+sxsave]
	st	%i4,[%fp+sssave]
	mov	%i5,%o4
	mov	0,%i5			! biguns = 0
	ldd	[%g1+S0],%f40		! load constants
	ldd	[%g1+S1],%f42
	ldd	[%g1+S2],%f44
	ldd	[%g1+one],%f46
	ldd	[%g1+mhalf],%f48
	ldd	[%g1+C0],%f50
	ldd	[%g1+C1],%f52
	ldd	[%g1+C2],%f54
	ldd	[%g1+invpio2],%f56
	ldd	[%g1+round],%f58
	ldd	[%g1+pio2_1],%f60
	ldd	[%g1+pio2_t],%f62
	ldd	[%g1+thresh1],%f8
	ldd	[%g1+thresh2],%f18
	ldd	[%g1+inf],%f38
	ldd	[%g1+signbit],%f28
	sll	%i2,2,%i2		! scale strides
	sll	%i4,2,%i4
	sll	%o5,2,%o5
	nop
	fzero	%f10			! loop prologue
	add	%fp,junk,%l0
	fzero	%f20
	add	%fp,junk,%l4
	fzero	%f12
	add	%fp,junk,%l1
	fzero	%f22
	add	%fp,junk,%l5
	fzero	%f14
	add	%fp,junk,%l2
	fzero	%f24
	add	%fp,junk,%l6
	fzero	%f16
	add	%fp,junk,%l3
	fzero	%f26
	ba	.start
	add	%fp,junk,%l7

! 16-byte aligned
	.align	16
.start:
	ld	[%i1],%f0		! *x
	add	%i1,%i2,%i1		! x += stridex
	addcc	%i0,-1,%i0
	fdtos	%f10,%f10

	st	%f10,[%l0]
	mov	%i3,%l0			! ps0 = s
	add	%i3,%i4,%i3		! s += strides
	fdtos	%f20,%f20

	st	%f20,[%l4]
	mov	%o4,%l4			! pc0 = c
	ble,pn	%icc,.last1
! delay slot
	add	%o4,%o5,%o4		! c += stridec

	ld	[%i1],%f2		! *x
	add	%i1,%i2,%i1		! x += stridex
	addcc	%i0,-1,%i0
	fdtos	%f12,%f12

	st	%f12,[%l1]
	mov	%i3,%l1			! ps1 = s
	add	%i3,%i4,%i3		! s += strides
	fdtos	%f22,%f22

	st	%f22,[%l5]
	mov	%o4,%l5			! pc1 = c
	ble,pn	%icc,.last2
! delay slot
	add	%o4,%o5,%o4		! c += stridec

	ld	[%i1],%f4		! *x
	add	%i1,%i2,%i1		! x += stridex
	addcc	%i0,-1,%i0
	fdtos	%f14,%f14

	st	%f14,[%l2]
	mov	%i3,%l2			! ps2 = s
	add	%i3,%i4,%i3		! s += strides
	fdtos	%f24,%f24

	st	%f24,[%l6]
	mov	%o4,%l6			! pc2 = c
	ble,pn	%icc,.last3
! delay slot
	add	%o4,%o5,%o4		! c += stridec

	ld	[%i1],%f6		! *x
	add	%i1,%i2,%i1		! x += stridex
	nop
	fdtos	%f16,%f16

	st	%f16,[%l3]
	mov	%i3,%l3			! ps3 = s
	add	%i3,%i4,%i3		! s += strides
	fdtos	%f26,%f26

	st	%f26,[%l7]
	mov	%o4,%l7			! pc3 = c
	add	%o4,%o5,%o4		! c += stridec
.cont:
	fabsd	%f0,%f30

	fabsd	%f2,%f32

	fabsd	%f4,%f34

	fabsd	%f6,%f36
	fcmple32 %f30,%f18,%o0

	fcmple32 %f32,%f18,%o1

	fcmple32 %f34,%f18,%o2

	fcmple32 %f36,%f18,%o3
	nop

! 16-byte aligned
	andcc	%o0,2,%g0
	bz,pn	%icc,.range0		! branch if > 2^19 pi
! delay slot
	fcmple32 %f30,%f8,%o0

.check1:
	andcc	%o1,2,%g0
	bz,pn	%icc,.range1		! branch if > 2^19 pi
! delay slot
	fcmple32 %f32,%f8,%o1

.check2:
	andcc	%o2,2,%g0
	bz,pn	%icc,.range2		! branch if > 2^19 pi
! delay slot
	fcmple32 %f34,%f8,%o2

.check3:
	andcc	%o3,2,%g0
	bz,pn	%icc,.range3		! branch if > 2^19 pi
! delay slot
	fcmple32 %f36,%f8,%o3

.checkprimary:
	fsmuld	%f0,%f0,%f30
	fstod	%f0,%f0

	fsmuld	%f2,%f2,%f32
	fstod	%f2,%f2
	and	%o0,%o1,%o7

	fsmuld	%f4,%f4,%f34
	fstod	%f4,%f4
	and	%o2,%o7,%o7

	fsmuld	%f6,%f6,%f36
	fstod	%f6,%f6
	and	%o3,%o7,%o7

	fmuld	%f30,%f54,%f20
	andcc	%o7,2,%g0
	bz,pn	%icc,.medium		! branch if any argument is > pi/4
! delay slot
	nop

	fmuld	%f32,%f54,%f22

	fmuld	%f34,%f54,%f24

	fmuld	%f36,%f54,%f26

	faddd	%f20,%f52,%f20
	fmuld	%f30,%f44,%f10

	faddd	%f22,%f52,%f22
	fmuld	%f32,%f44,%f12

	faddd	%f24,%f52,%f24
	fmuld	%f34,%f44,%f14

	faddd	%f26,%f52,%f26
	fmuld	%f36,%f44,%f16

	fmuld	%f30,%f20,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f22,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f24,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f26,%f26
	faddd	%f16,%f42,%f16

	faddd	%f20,%f50,%f20
	fmuld	%f30,%f10,%f10

	faddd	%f22,%f50,%f22
	fmuld	%f32,%f12,%f12

	faddd	%f24,%f50,%f24
	fmuld	%f34,%f14,%f14

	faddd	%f26,%f50,%f26
	fmuld	%f36,%f16,%f16

	fmuld	%f30,%f20,%f20
	faddd	%f10,%f40,%f10

	fmuld	%f32,%f22,%f22
	faddd	%f12,%f40,%f12

	fmuld	%f34,%f24,%f24
	faddd	%f14,%f40,%f14

	fmuld	%f36,%f26,%f26
	faddd	%f16,%f40,%f16

	faddd	%f20,%f48,%f20
	fmuld	%f30,%f10,%f10

	faddd	%f22,%f48,%f22
	fmuld	%f32,%f12,%f12

	faddd	%f24,%f48,%f24
	fmuld	%f34,%f14,%f14

	faddd	%f26,%f48,%f26
	fmuld	%f36,%f16,%f16

	fmuld	%f30,%f20,%f20
	faddd	%f10,%f46,%f10

	fmuld	%f32,%f22,%f22
	faddd	%f12,%f46,%f12

	fmuld	%f34,%f24,%f24
	faddd	%f14,%f46,%f14

	fmuld	%f36,%f26,%f26
	faddd	%f16,%f46,%f16

	faddd	%f20,%f46,%f20
	fmuld	%f0,%f10,%f10

	faddd	%f22,%f46,%f22
	fmuld	%f2,%f12,%f12

	faddd	%f24,%f46,%f24
	fmuld	%f4,%f14,%f14
	addcc	%i0,-1,%i0

	faddd	%f26,%f46,%f26
	bg,pt	%icc,.start
! delay slot
	fmuld	%f6,%f16,%f16

	ba,pt	%icc,.end
! delay slot
	nop


	.align	16
.medium:
	fmuld	%f0,%f56,%f10

	fmuld	%f2,%f56,%f12

	fmuld	%f4,%f56,%f14

	fmuld	%f6,%f56,%f16

	faddd	%f10,%f58,%f10
	st	%f11,[%fp+n0]

	faddd	%f12,%f58,%f12
	st	%f13,[%fp+n1]

	faddd	%f14,%f58,%f14
	st	%f15,[%fp+n2]

	faddd	%f16,%f58,%f16
	st	%f17,[%fp+n3]

	fsubd	%f10,%f58,%f10

	fsubd	%f12,%f58,%f12

	fsubd	%f14,%f58,%f14

	fsubd	%f16,%f58,%f16

	fmuld	%f10,%f60,%f20
	ld	[%fp+n0],%o0

	fmuld	%f12,%f60,%f22
	ld	[%fp+n1],%o1

	fmuld	%f14,%f60,%f24
	ld	[%fp+n2],%o2

	fmuld	%f16,%f60,%f26
	ld	[%fp+n3],%o3

	fsubd	%f0,%f20,%f0
	fmuld	%f10,%f62,%f30
	and	%o0,1,%o0
	mov	%l0,%g1

	fsubd	%f2,%f22,%f2
	fmuld	%f12,%f62,%f32
	and	%o1,1,%o1
	movrnz	%o0,%l4,%l0		! if (n & 1) exchange ps and pc

	fsubd	%f4,%f24,%f4
	fmuld	%f14,%f62,%f34
	and	%o2,1,%o2
	movrnz	%o0,%g1,%l4

	fsubd	%f6,%f26,%f6
	fmuld	%f16,%f62,%f36
	and	%o3,1,%o3
	mov	%l1,%g1

	fsubd	%f0,%f30,%f0
	movrnz	%o1,%l5,%l1

	fsubd	%f2,%f32,%f2
	movrnz	%o1,%g1,%l5

	fsubd	%f4,%f34,%f4
	mov	%l2,%g1

	fsubd	%f6,%f36,%f6
	movrnz	%o2,%l6,%l2

	fmuld	%f0,%f0,%f30
	fnegd	%f0,%f10
	movrnz	%o2,%g1,%l6

	fmuld	%f2,%f2,%f32
	fnegd	%f2,%f12
	mov	%l3,%g1

	fmuld	%f4,%f4,%f34
	fnegd	%f4,%f14
	movrnz	%o3,%l7,%l3

	fmuld	%f6,%f6,%f36
	fnegd	%f6,%f16
	movrnz	%o3,%g1,%l7

	fmuld	%f30,%f54,%f20
	fmovrdnz %o0,%f10,%f0		! if (n & 1) x = -x

	fmuld	%f32,%f54,%f22
	fmovrdnz %o1,%f12,%f2

	fmuld	%f34,%f54,%f24
	fmovrdnz %o2,%f14,%f4

	fmuld	%f36,%f54,%f26
	fmovrdnz %o3,%f16,%f6

	faddd	%f20,%f52,%f20
	fmuld	%f30,%f44,%f10
	ld	[%fp+n0],%o0

	faddd	%f22,%f52,%f22
	fmuld	%f32,%f44,%f12
	and	%o0,2,%o0

	faddd	%f24,%f52,%f24
	fmuld	%f34,%f44,%f14
	sllx	%o0,62,%g1
	stx	%g1,[%fp+n0]

	faddd	%f26,%f52,%f26
	fmuld	%f36,%f44,%f16
	ld	[%fp+n1],%o1

	fmuld	%f30,%f20,%f20
	faddd	%f10,%f42,%f10
	and	%o1,2,%o1

	fmuld	%f32,%f22,%f22
	faddd	%f12,%f42,%f12
	sllx	%o1,62,%g1
	stx	%g1,[%fp+n1]

	fmuld	%f34,%f24,%f24
	faddd	%f14,%f42,%f14
	ld	[%fp+n2],%o2

	fmuld	%f36,%f26,%f26
	faddd	%f16,%f42,%f16
	and	%o2,2,%o2

	faddd	%f20,%f50,%f20
	fmuld	%f30,%f10,%f10
	sllx	%o2,62,%g1
	stx	%g1,[%fp+n2]

	faddd	%f22,%f50,%f22
	fmuld	%f32,%f12,%f12
	ld	[%fp+n3],%o3

	faddd	%f24,%f50,%f24
	fmuld	%f34,%f14,%f14
	and	%o3,2,%o3

	faddd	%f26,%f50,%f26
	fmuld	%f36,%f16,%f16
	sllx	%o3,62,%g1
	stx	%g1,[%fp+n3]

	fmuld	%f30,%f20,%f20
	faddd	%f10,%f40,%f10

	fmuld	%f32,%f22,%f22
	faddd	%f12,%f40,%f12

	fmuld	%f34,%f24,%f24
	faddd	%f14,%f40,%f14

	fmuld	%f36,%f26,%f26
	faddd	%f16,%f40,%f16

	faddd	%f20,%f48,%f20
	fmuld	%f30,%f10,%f10

	faddd	%f22,%f48,%f22
	fmuld	%f32,%f12,%f12

	faddd	%f24,%f48,%f24
	fmuld	%f34,%f14,%f14

	faddd	%f26,%f48,%f26
	fmuld	%f36,%f16,%f16

	fmuld	%f30,%f20,%f20
	faddd	%f10,%f46,%f10

	fmuld	%f32,%f22,%f22
	faddd	%f12,%f46,%f12

	fmuld	%f34,%f24,%f24
	faddd	%f14,%f46,%f14

	fmuld	%f36,%f26,%f26
	faddd	%f16,%f46,%f16

	faddd	%f20,%f46,%f20
	fmuld	%f0,%f10,%f10
	ldd	[%fp+n0],%f30

	faddd	%f22,%f46,%f22
	fmuld	%f2,%f12,%f12
	ldd	[%fp+n1],%f32

	faddd	%f24,%f46,%f24
	fmuld	%f4,%f14,%f14
	ldd	[%fp+n2],%f34

	faddd	%f26,%f46,%f26
	fmuld	%f6,%f16,%f16
	ldd	[%fp+n3],%f36

	fxor	%f10,%f30,%f10		! if (n & 2) negate s, c

	fxor	%f12,%f32,%f12

	fxor	%f14,%f34,%f14

	fxor	%f16,%f36,%f16

	fxor	%f20,%f30,%f20

	fxor	%f22,%f32,%f22

	fxor	%f24,%f34,%f24

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f26,%f36,%f26

	ba,pt	%icc,.end
! delay slot
	nop


	.align	32
.end:
	fdtos	%f10,%f10
	st	%f10,[%l0]
	fdtos	%f20,%f20
	st	%f20,[%l4]
	fdtos	%f12,%f12
	st	%f12,[%l1]
	fdtos	%f22,%f22
	st	%f22,[%l5]
	fdtos	%f14,%f14
	st	%f14,[%l2]
	fdtos	%f24,%f24
	st	%f24,[%l6]
	fdtos	%f16,%f16
	st	%f16,[%l3]
	fdtos	%f26,%f26
	tst	%i5			! check for huge arguments remaining
	be,pt	%icc,.exit
! delay slot
	st	%f26,[%l7]
#ifdef __sparcv9
	ldx	[%fp+xsave],%o1
	ldx	[%fp+ssave],%o3
	ldx	[%fp+csave],%o5
	ldx	[%fp+STACK_BIAS+0xb0],%i5
	stx	%i5,[%sp+STACK_BIAS+0xb0]
#else
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
	call	__vlibm_vsincos_bigf
	sra	%o4,0,%o4		! delay slot

.exit:
	ret
	restore


	.align	32
.last1:
	fdtos	%f12,%f12
	st	%f12,[%l1]
	nop
	fdtos	%f22,%f22
	st	%f22,[%l5]
	fzeros	%f2
	add	%fp,junk,%l5
	add	%fp,junk,%l1
.last2:
	fdtos	%f14,%f14
	st	%f14,[%l2]
	nop
	fdtos	%f24,%f24
	st	%f24,[%l6]
	fzeros	%f4
	add	%fp,junk,%l2
	add	%fp,junk,%l6
.last3:
	fdtos	%f16,%f16
	st	%f16,[%l3]
	fdtos	%f26,%f26
	st	%f26,[%l7]
	fzeros	%f6
	add	%fp,junk,%l3
	ba,pt	%icc,.cont
! delay slot
	add	%fp,junk,%l7


	.align	16
.range0:
	fcmpgt32 %f38,%f30,%o0
	andcc	%o0,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f1
	fmuls	%f0,%f1,%f0
	st	%f0,[%l0]
	st	%f0,[%l4]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f0
	add	%i1,%i2,%i1
	mov	%i3,%l0
	add	%i3,%i4,%i3
	fabsd	%f0,%f30
	mov	%o4,%l4
	add	%o4,%o5,%o4
	fcmple32 %f30,%f18,%o0
	andcc	%o0,2,%g0
	bz,pn	%icc,.range0
! delay slot
	nop
	ba,pt	%icc,.check1
! delay slot
	fcmple32 %f30,%f8,%o0
1:
	fzero	%f0			! set up dummy argument
	add	%fp,junk,%l0
	add	%fp,junk,%l4
	mov	2,%o0
	ba,pt	%icc,.check1
! delay slot
	fzero	%f30


	.align	16
.range1:
	fcmpgt32 %f38,%f32,%o1
	andcc	%o1,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f3
	fmuls	%f2,%f3,%f2
	st	%f2,[%l1]
	st	%f2,[%l5]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f2
	add	%i1,%i2,%i1
	mov	%i3,%l1
	add	%i3,%i4,%i3
	fabsd	%f2,%f32
	mov	%o4,%l5
	add	%o4,%o5,%o4
	fcmple32 %f32,%f18,%o1
	andcc	%o1,2,%g0
	bz,pn	%icc,.range1
! delay slot
	nop
	ba,pt	%icc,.check2
! delay slot
	fcmple32 %f32,%f8,%o1
1:
	fzero	%f2			! set up dummy argument
	add	%fp,junk,%l1
	add	%fp,junk,%l5
	mov	2,%o1
	ba,pt	%icc,.check2
! delay slot
	fzero	%f32


	.align	16
.range2:
	fcmpgt32 %f38,%f34,%o2
	andcc	%o2,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f5
	fmuls	%f4,%f5,%f4
	st	%f4,[%l2]
	st	%f4,[%l6]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f4
	add	%i1,%i2,%i1
	mov	%i3,%l2
	add	%i3,%i4,%i3
	fabsd	%f4,%f34
	mov	%o4,%l6
	add	%o4,%o5,%o4
	fcmple32 %f34,%f18,%o2
	andcc	%o2,2,%g0
	bz,pn	%icc,.range2
! delay slot
	nop
	ba,pt	%icc,.check3
! delay slot
	fcmple32 %f34,%f8,%o2
1:
	fzero	%f4			! set up dummy argument
	add	%fp,junk,%l2
	add	%fp,junk,%l6
	mov	2,%o2
	ba,pt	%icc,.check3
! delay slot
	fzero	%f34


	.align	16
.range3:
	fcmpgt32 %f38,%f36,%o3
	andcc	%o3,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f7
	fmuls	%f6,%f7,%f6
	st	%f6,[%l3]
	st	%f6,[%l7]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f6
	add	%i1,%i2,%i1
	mov	%i3,%l3
	add	%i3,%i4,%i3
	fabsd	%f6,%f36
	mov	%o4,%l7
	add	%o4,%o5,%o4
	fcmple32 %f36,%f18,%o3
	andcc	%o3,2,%g0
	bz,pn	%icc,.range3
! delay slot
	nop
	ba,pt	%icc,.checkprimary
! delay slot
	fcmple32 %f36,%f8,%o3
1:
	fzero	%f6			! set up dummy argument
	add	%fp,junk,%l3
	add	%fp,junk,%l7
	mov	2,%o3
	ba,pt	%icc,.checkprimary
! delay slot
	fzero	%f36

	SET_SIZE(__vsincosf)

