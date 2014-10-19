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

	.file	"__vsinf.S"

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
#define ysave		STACK_BIAS-0x10
#define nsave		STACK_BIAS-0x14
#define sxsave		STACK_BIAS-0x18
#define sysave		STACK_BIAS-0x1c
#define junk		STACK_BIAS-0x20
#define n3		STACK_BIAS-0x24
#define n2		STACK_BIAS-0x28
#define n1		STACK_BIAS-0x2c
#define n0		STACK_BIAS-0x30
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x30

! register use

! i0  n
! i1  x
! i2  stridex
! i3  y
! i4  stridey
! i5  biguns

! l0  n0
! l1  n1
! l2  n2
! l3  n3
! l4  
! l5  
! l6  
! l7  

! the following are 64-bit registers in both V8+ and V9

! g1  
! g5  

! o0  py0
! o1  py1
! o2  py2
! o3  py3
! o4  
! o5  
! o7  

! f0  x0
! f2  x1
! f4  x2
! f6  x3
! f8  thresh1 (pi/4)
! f10 y0
! f12 y1
! f14 y2
! f16 y3
! f18 thresh2 (2^19 pi)
! f20 
! f22 
! f24 
! f26 
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

	ENTRY(__vsinf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,constants,l1)
	mov	%l1,%g1
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
	fzero	%f10			! loop prologue
	add	%fp,junk,%o0
	fzero	%f12
	add	%fp,junk,%o1
	fzero	%f14
	add	%fp,junk,%o2
	fzero	%f16
	ba	.start
	add	%fp,junk,%o3

! 16-byte aligned
	.align	16
.start:
	ld	[%i1],%f0		! *x
	add	%i1,%i2,%i1		! x += stridex
	addcc	%i0,-1,%i0
	fdtos	%f10,%f10

	st	%f10,[%o0]
	mov	%i3,%o0			! py0 = y
	ble,pn	%icc,.last1
! delay slot
	add	%i3,%i4,%i3		! y += stridey

	ld	[%i1],%f2		! *x
	add	%i1,%i2,%i1		! x += stridex
	addcc	%i0,-1,%i0
	fdtos	%f12,%f12

	st	%f12,[%o1]
	mov	%i3,%o1			! py1 = y
	ble,pn	%icc,.last2
! delay slot
	add	%i3,%i4,%i3		! y += stridey

	ld	[%i1],%f4		! *x
	add	%i1,%i2,%i1		! x += stridex
	addcc	%i0,-1,%i0
	fdtos	%f14,%f14

	st	%f14,[%o2]
	mov	%i3,%o2			! py2 = y
	ble,pn	%icc,.last3
! delay slot
	add	%i3,%i4,%i3		! y += stridey

	ld	[%i1],%f6		! *x
	add	%i1,%i2,%i1		! x += stridex
	nop
	fdtos	%f16,%f16

	st	%f16,[%o3]
	mov	%i3,%o3			! py3 = y
	add	%i3,%i4,%i3		! y += stridey
.cont:
	fabsd	%f0,%f30

	fabsd	%f2,%f32

	fabsd	%f4,%f34

	fabsd	%f6,%f36
	fcmple32 %f30,%f18,%l0

	fcmple32 %f32,%f18,%l1

	fcmple32 %f34,%f18,%l2

	fcmple32 %f36,%f18,%l3
	nop

! 16-byte aligned
	andcc	%l0,2,%g0
	bz,pn	%icc,.range0		! branch if > 2^19 pi
! delay slot
	fcmple32 %f30,%f8,%l0

.check1:
	andcc	%l1,2,%g0
	bz,pn	%icc,.range1		! branch if > 2^19 pi
! delay slot
	fcmple32 %f32,%f8,%l1

.check2:
	andcc	%l2,2,%g0
	bz,pn	%icc,.range2		! branch if > 2^19 pi
! delay slot
	fcmple32 %f34,%f8,%l2

.check3:
	andcc	%l3,2,%g0
	bz,pn	%icc,.range3		! branch if > 2^19 pi
! delay slot
	fcmple32 %f36,%f8,%l3

.checkprimary:
	fsmuld	%f0,%f0,%f30
	fstod	%f0,%f0

	fsmuld	%f2,%f2,%f32
	fstod	%f2,%f2
	and	%l0,%l1,%o4

	fsmuld	%f4,%f4,%f34
	fstod	%f4,%f4

	fsmuld	%f6,%f6,%f36
	fstod	%f6,%f6
	and	%l2,%l3,%o5

	fmuld	%f30,%f44,%f10
	and	%o4,%o5,%o5

	fmuld	%f32,%f44,%f12
	andcc	%o5,2,%g0
	bz,pn	%icc,.medium		! branch if any argument is > pi/4
! delay slot
	nop

	fmuld	%f34,%f44,%f14

	fmuld	%f36,%f44,%f16

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10

	fmuld	%f32,%f12,%f12

	fmuld	%f34,%f14,%f14

	fmuld	%f36,%f16,%f16

	faddd	%f10,%f20,%f10

	faddd	%f12,%f22,%f12

	faddd	%f14,%f24,%f14

	faddd	%f16,%f26,%f16

	fmuld	%f0,%f10,%f10

	fmuld	%f2,%f12,%f12

	fmuld	%f4,%f14,%f14

	addcc	%i0,-1,%i0
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
	ld	[%fp+n0],%l0

	fmuld	%f12,%f60,%f22
	ld	[%fp+n1],%l1

	fmuld	%f14,%f60,%f24
	ld	[%fp+n2],%l2

	fmuld	%f16,%f60,%f26
	ld	[%fp+n3],%l3

	fsubd	%f0,%f20,%f0
	fmuld	%f10,%f62,%f30

	fsubd	%f2,%f22,%f2
	fmuld	%f12,%f62,%f32

	fsubd	%f4,%f24,%f4
	fmuld	%f14,%f62,%f34

	fsubd	%f6,%f26,%f6
	fmuld	%f16,%f62,%f36

	fsubd	%f0,%f30,%f0

	fsubd	%f2,%f32,%f2

	fsubd	%f4,%f34,%f4

	fsubd	%f6,%f36,%f6
	andcc	%l0,1,%g0

	fmuld	%f0,%f0,%f30
	bz,pn	%icc,.case8
! delay slot
	andcc	%l1,1,%g0

	fmuld	%f2,%f2,%f32
	bz,pn	%icc,.case4
! delay slot
	andcc	%l2,1,%g0

	fmuld	%f4,%f4,%f34
	bz,pn	%icc,.case2
! delay slot
	andcc	%l3,1,%g0

	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case1
! delay slot
	nop

!.case0:
	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	faddd	%f10,%f20,%f10

	faddd	%f12,%f22,%f12

	faddd	%f14,%f24,%f14

	faddd	%f16,%f26,%f16

	fxor	%f10,%f0,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case1:
	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fzero	%f36

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10

	faddd	%f12,%f22,%f12

	faddd	%f14,%f24,%f14

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f0,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case2:
	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case3
! delay slot
	nop

	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	faddd	%f10,%f20,%f10

	faddd	%f12,%f22,%f12

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	faddd	%f16,%f26,%f16

	fxor	%f10,%f0,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case3:
	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f16,%f16
	fzero	%f36

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10

	faddd	%f12,%f22,%f12

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f0,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case4:
	fmuld	%f4,%f4,%f34
	bz,pn	%icc,.case6
! delay slot
	andcc	%l3,1,%g0

	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case5
! delay slot
	nop

	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	faddd	%f10,%f20,%f10

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	faddd	%f14,%f24,%f14

	faddd	%f16,%f26,%f16

	fxor	%f10,%f0,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case5:
	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fzero	%f36

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	faddd	%f14,%f24,%f14

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f0,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case6:
	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case7
! delay slot
	nop

	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	faddd	%f10,%f20,%f10

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	faddd	%f16,%f26,%f16

	fxor	%f10,%f0,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case7:
	fmuld	%f30,%f54,%f10		! cos(x0)
	fzero	%f0		

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f48,%f20
	faddd	%f10,%f52,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f10,%f10
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f30,%f30
	faddd	%f10,%f50,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f16,%f16
	fzero	%f36

	fmuld	%f30,%f10,%f10
	fmovrdnz %g1,%f28,%f0

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f0,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop


	.align	16
.case8:
	fmuld	%f2,%f2,%f32
	bz,pn	%icc,.case12
! delay slot
	andcc	%l2,1,%g0

	fmuld	%f4,%f4,%f34
	bz,pn	%icc,.case10
! delay slot
	andcc	%l3,1,%g0

	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case9
! delay slot
	nop

	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	faddd	%f12,%f22,%f12

	faddd	%f14,%f24,%f14

	faddd	%f16,%f26,%f16

	fxor	%f10,%f30,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case9:
	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fzero	%f36

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	faddd	%f12,%f22,%f12

	faddd	%f14,%f24,%f14

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f30,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case10:
	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case11
! delay slot
	nop

	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	faddd	%f12,%f22,%f12

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	faddd	%f16,%f26,%f16

	fxor	%f10,%f30,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case11:
	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f54,%f12		! cos(x1)
	fzero	%f2		

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f48,%f22
	faddd	%f12,%f52,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f12,%f12
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f32,%f32
	faddd	%f12,%f50,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f16,%f16
	fzero	%f36

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	fmuld	%f32,%f12,%f12
	fmovrdnz %g5,%f28,%f2

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	faddd	%f12,%f22,%f12

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f30,%f10

	fxor	%f12,%f2,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case12:
	fmuld	%f4,%f4,%f34
	bz,pn	%icc,.case14
! delay slot
	andcc	%l3,1,%g0

	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case13
! delay slot
	nop

	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	faddd	%f14,%f24,%f14

	faddd	%f16,%f26,%f16

	fxor	%f10,%f30,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case13:
	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f54,%f14		! cos(x2)
	fzero	%f4		

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f48,%f24
	faddd	%f14,%f52,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f14,%f14
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f34,%f34
	faddd	%f14,%f50,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fzero	%f36

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	fmuld	%f34,%f14,%f14
	fmovrdnz %o4,%f28,%f4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	faddd	%f14,%f24,%f14

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f30,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f4,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case14:
	fmuld	%f6,%f6,%f36
	bz,pn	%icc,.case15
! delay slot
	nop

	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f54,%f16		! cos(x3)
	fzero	%f6		

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f48,%f26
	faddd	%f16,%f52,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f16,%f16
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f36,%f36
	faddd	%f16,%f50,%f16
	and	%l3,2,%o5

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	fmuld	%f36,%f16,%f16
	fmovrdnz %o5,%f28,%f6

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	faddd	%f16,%f26,%f16

	fxor	%f10,%f30,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f6,%f16

	ba,pt	%icc,.end
! delay slot
	nop

	.align	16
.case15:
	fmuld	%f30,%f44,%f10		! sin(x0)

	fmuld	%f32,%f44,%f12		! sin(x1)

	fmuld	%f34,%f44,%f14		! sin(x2)

	fmuld	%f36,%f44,%f16		! sin(x3)

	fmuld	%f30,%f40,%f20
	faddd	%f10,%f42,%f10

	fmuld	%f32,%f40,%f22
	faddd	%f12,%f42,%f12

	fmuld	%f34,%f40,%f24
	faddd	%f14,%f42,%f14

	fmuld	%f36,%f40,%f26
	faddd	%f16,%f42,%f16

	fmuld	%f30,%f30,%f30
	faddd	%f20,%f46,%f20

	fmuld	%f32,%f32,%f32
	faddd	%f22,%f46,%f22

	fmuld	%f34,%f34,%f34
	faddd	%f24,%f46,%f24

	fmuld	%f36,%f36,%f36
	faddd	%f26,%f46,%f26

	fmuld	%f30,%f10,%f10
	fzero	%f30

	fmuld	%f32,%f12,%f12
	fzero	%f32

	fmuld	%f34,%f14,%f14
	fzero	%f34

	fmuld	%f36,%f16,%f16
	fzero	%f36

	faddd	%f10,%f20,%f10
	and	%l0,2,%g1

	faddd	%f12,%f22,%f12
	and	%l1,2,%g5

	faddd	%f14,%f24,%f14
	and	%l2,2,%o4

	faddd	%f16,%f26,%f16
	and	%l3,2,%o5

	fmuld	%f0,%f10,%f10
	fmovrdnz %g1,%f28,%f30

	fmuld	%f2,%f12,%f12
	fmovrdnz %g5,%f28,%f32

	fmuld	%f4,%f14,%f14
	fmovrdnz %o4,%f28,%f34

	fmuld	%f6,%f16,%f16
	fmovrdnz %o5,%f28,%f36

	fxor	%f10,%f30,%f10

	fxor	%f12,%f32,%f12

	fxor	%f14,%f34,%f14

	addcc	%i0,-1,%i0
	bg,pt	%icc,.start
! delay slot
	fxor	%f16,%f36,%f16

	ba,pt	%icc,.end
! delay slot
	nop


	.align	32
.end:
	fdtos	%f10,%f10
	st	%f10,[%o0]
	fdtos	%f12,%f12
	st	%f12,[%o1]
	fdtos	%f14,%f14
	st	%f14,[%o2]
	fdtos	%f16,%f16
	tst	%i5			! check for huge arguments remaining
	be,pt	%icc,.exit
! delay slot
	st	%f16,[%o3]
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
	call	__vlibm_vsin_bigf
	sra	%o4,0,%o4		! delay slot

.exit:
	ret
	restore


	.align	32
.last1:
	fdtos	%f12,%f12
	st	%f12,[%o1]
	fzeros	%f2
	add	%fp,junk,%o1
.last2:
	fdtos	%f14,%f14
	st	%f14,[%o2]
	fzeros	%f4
	add	%fp,junk,%o2
.last3:
	fdtos	%f16,%f16
	st	%f16,[%o3]
	fzeros	%f6
	ba,pt	%icc,.cont
! delay slot
	add	%fp,junk,%o3


	.align	16
.range0:
	fcmpgt32 %f38,%f30,%l0
	andcc	%l0,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f1
	fmuls	%f0,%f1,%f0
	st	%f0,[%o0]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f0
	add	%i1,%i2,%i1
	mov	%i3,%o0
	add	%i3,%i4,%i3
	fabsd	%f0,%f30
	fcmple32 %f30,%f18,%l0
	andcc	%l0,2,%g0
	bz,pn	%icc,.range0
! delay slot
	nop
	ba,pt	%icc,.check1
! delay slot
	fcmple32 %f30,%f8,%l0
1:
	fzero	%f0			! set up dummy argument
	add	%fp,junk,%o0
	mov	2,%l0
	ba,pt	%icc,.check1
! delay slot
	fzero	%f30


	.align	16
.range1:
	fcmpgt32 %f38,%f32,%l1
	andcc	%l1,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f3
	fmuls	%f2,%f3,%f2
	st	%f2,[%o1]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f2
	add	%i1,%i2,%i1
	mov	%i3,%o1
	add	%i3,%i4,%i3
	fabsd	%f2,%f32
	fcmple32 %f32,%f18,%l1
	andcc	%l1,2,%g0
	bz,pn	%icc,.range1
! delay slot
	nop
	ba,pt	%icc,.check2
! delay slot
	fcmple32 %f32,%f8,%l1
1:
	fzero	%f2			! set up dummy argument
	add	%fp,junk,%o1
	mov	2,%l1
	ba,pt	%icc,.check2
! delay slot
	fzero	%f32


	.align	16
.range2:
	fcmpgt32 %f38,%f34,%l2
	andcc	%l2,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f5
	fmuls	%f4,%f5,%f4
	st	%f4,[%o2]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f4
	add	%i1,%i2,%i1
	mov	%i3,%o2
	add	%i3,%i4,%i3
	fabsd	%f4,%f34
	fcmple32 %f34,%f18,%l2
	andcc	%l2,2,%g0
	bz,pn	%icc,.range2
! delay slot
	nop
	ba,pt	%icc,.check3
! delay slot
	fcmple32 %f34,%f8,%l2
1:
	fzero	%f4			! set up dummy argument
	add	%fp,junk,%o2
	mov	2,%l2
	ba,pt	%icc,.check3
! delay slot
	fzero	%f34


	.align	16
.range3:
	fcmpgt32 %f38,%f36,%l3
	andcc	%l3,2,%g0
	bnz,a,pt %icc,1f		! branch if finite
! delay slot, squashed if branch not taken
	mov	1,%i5			! set biguns
	fzeros	%f7
	fmuls	%f6,%f7,%f6
	st	%f6,[%o3]
1:
	addcc	%i0,-1,%i0
	ble,pn	%icc,1f
! delay slot
	nop
	ld	[%i1],%f6
	add	%i1,%i2,%i1
	mov	%i3,%o3
	add	%i3,%i4,%i3
	fabsd	%f6,%f36
	fcmple32 %f36,%f18,%l3
	andcc	%l3,2,%g0
	bz,pn	%icc,.range3
! delay slot
	nop
	ba,pt	%icc,.checkprimary
! delay slot
	fcmple32 %f36,%f8,%l3
1:
	fzero	%f6			! set up dummy argument
	add	%fp,junk,%o3
	mov	2,%l3
	ba,pt	%icc,.checkprimary
! delay slot
	fzero	%f36

	SET_SIZE(__vsinf)

