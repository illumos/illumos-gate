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

	.file	"__vatan2.S"

#include "libm.h"

	RO_DATA
	.align	64
constants:
	.word	0x3ff921fb,0x54442d18	! pio2
	.word	0x3c91a626,0x33145c07	! pio2_lo
	.word	0xbfd55555,0x555554ee	! p1
	.word	0x3fc99999,0x997a1559	! p2
	.word	0xbfc24923,0x158dfe02	! p3
	.word	0x3fbc639d,0x0ed1347b	! p4
	.word	0xffffffff,0x00000000	! mask
	.word	0x3fc00000,0x00000000	! twom3
	.word	0x46d00000,0x00000000	! two110
	.word	0x3fe921fb,0x54442d18	! pio4

! local storage indices

#define xscl		STACK_BIAS-0x8
#define yscl		STACK_BIAS-0x10
#define twom3		STACK_BIAS-0x18
#define two110		STACK_BIAS-0x20
#define pio4		STACK_BIAS-0x28
#define junk		STACK_BIAS-0x30
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x30

! register use

! i0  n
! i1  y
! i2  stridey
! i3  x
! i4  stridex
! i5  z

! l0  k0
! l1  k1
! l2  k2
! l3  hx
! l4  pz0
! l5  pz1
! l6  pz2
! l7  stridez

! the following are 64-bit registers in both V8+ and V9

! g1  __vlibm_TBL_atan2
! g5  

! o0  hy
! o1  0x00004000
! o2  0x1420
! o3  0x7fe00000
! o4  0x03600000
! o5  0x00100000
! o7  

! f0  y0
! f2  x0
! f4  t0
! f6  ah0
! f8  al0
! f10 y1
! f12 x1
! f14 t1
! f16 ah1
! f18 al1
! f20 y2
! f22 x2
! f24 t2
! f26 ah2
! f28 al2
! f30 
! f32 
! f34 
! f36 sx0
! f38 sx1
! f40 sx2
! f42 sy0
! f44 sy1
! f46 sy2

#define mask	%f48
#define signbit	%f50
#define pio2	%f52
#define pio2_lo	%f54
#define p1	%f56
#define p2	%f58
#define p3	%f60
#define p4	%f62

	ENTRY(__vatan2)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,constants,o0)
	PIC_SET(l7,__vlibm_TBL_atan2,o1)
	wr	%g0,0x82,%asi		! set %asi for non-faulting loads
	mov	%o1, %g1
#ifdef __sparcv9
	ldx	[%fp+STACK_BIAS+0xb0],%l7
#else
	ld	[%fp+0x5c],%l7
#endif
	ldd	[%o0+0x00],pio2		! load/set up constants
	ldd	[%o0+0x08],pio2_lo
	ldd	[%o0+0x10],p1
	ldd	[%o0+0x18],p2
	ldd	[%o0+0x20],p3
	ldd	[%o0+0x28],p4
	ldd	[%o0+0x30],mask
	fzero	signbit
	fnegd	signbit,signbit
	sethi	%hi(0x00004000),%o1
	sethi	%hi(0x1420),%o2
	or	%o2,%lo(0x1420),%o2
	sethi	%hi(0x7fe00000),%o3
	sethi	%hi(0x03600000),%o4
	sethi	%hi(0x00100000),%o5
	ldd	[%o0+0x38],%f0		! copy rarely used constants to stack
	ldd	[%o0+0x40],%f2
	ldd	[%o0+0x48],%f4
	std	%f0,[%fp+twom3]
	std	%f2,[%fp+two110]
	std	%f4,[%fp+pio4]
	sll	%i2,3,%i2		! scale strides
	sll	%i4,3,%i4
	sll	%l7,3,%l7
	fzero	%f20			! loop prologue
	fzero	%f22
	fzero	%f24
	fzero	%f26
	fzero	%f46
	add	%fp,junk,%l6	
	ld	[%i1],%f0		! *y
	ld	[%i1+4],%f1
	ld	[%i3],%f8		! *x
	ld	[%i3+4],%f9
	ld	[%i1],%o0		! hy
	ba	.loop
	ld	[%i3],%l3		! hx

! 16-byte aligned
	.align	16
.loop:
	fabsd	%f0,%f4
	mov	%i5,%l4
	add	%i1,%i2,%i1		! y += stridey

	fabsd	%f8,%f2
	add	%i3,%i4,%i3		! x += stridex
	add	%i5,%l7,%i5		! z += stridez

	fand	%f0,signbit,%f42
	sethi	%hi(0x80000000),%g5

	fand	%f8,signbit,%f36
	andn	%o0,%g5,%o0
	andn	%l3,%g5,%l3

	fcmpd	%fcc0,%f4,%f2

	fmovd	%f4,%f0

	fmovdg	%fcc0,%f2,%f0		! swap if |y| > |x|

	fmovdg	%fcc0,%f4,%f2
	mov	%o0,%o7
	 lda	[%i1]%asi,%f10		! preload next argument

	  faddd	%f26,%f20,%f26
	 lda	[%i1+4]%asi,%f11

	  faddd	%f22,%f24,%f22
	movg	%fcc0,%l3,%o0

	movg	%fcc0,%o7,%l3

	fbu,pn	%fcc0,.nan0		! if x or y is nan
! delay slot
	 lda	[%i3]%asi,%f18

	sub	%l3,%o0,%l0		! hx - hy
	sub	%l3,%o3,%g5
	 fabsd	%f10,%f14
	 lda	[%i3+4]%asi,%f19

	sub	%l0,%o4,%o7
	  faddd	%f22,%f26,%f26

	andcc	%g5,%o7,%g0
	bge,pn	%icc,.big0		! if |x| or |x/y| is big
! delay slot
	nop

	 fabsd	%f18,%f12
	cmp	%o0,%o5
	bl,pn	%icc,.small0		! if |y| is small
! delay slot
	 lda	[%i1]%asi,%o0

	add	%l0,%o1,%l0		! k
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last1
! delay slot
	 lda	[%i3]%asi,%l3

.cont1:
	srl	%l0,10,%l0
	 mov	%i5,%l5
	  fxor	%f26,%f46,%f26
	  st	%f26,[%l6]

	 fand	%f10,signbit,%f44
	andn	%l0,0x1f,%l0
	 add	%i1,%i2,%i1
	  st	%f27,[%l6+4]

	 fand	%f18,signbit,%f38
	cmp	%l0,%o2
	movg	%icc,%o2,%l0

	 fcmpd	%fcc1,%f14,%f12
	 add	%i3,%i4,%i3
	 add	%i5,%l7,%i5

	 fmovd	%f14,%f10
	add	%l0,%g1,%l0
	 sethi	%hi(0x80000000),%g5

	ldd	[%l0+0x10],%f4
	fand	%f2,mask,%f6
	 andn	%o0,%g5,%o0
	 andn	%l3,%g5,%l3

	 fmovdg	%fcc1,%f12,%f10

	 fmovdg	%fcc1,%f14,%f12
	 mov	%o0,%o7
	  lda	[%i1]%asi,%f20

	fsubd	%f2,%f6,%f30
	fmuld	%f6,%f4,%f6
	 movg	%fcc1,%l3,%o0

	fmuld	%f0,%f4,%f8
	 movg	%fcc1,%o7,%l3

	  lda	[%i1+4]%asi,%f21
	 fbu,pn	%fcc1,.nan1
! delay slot
	 nop

	  lda	[%i3]%asi,%f28
	 sub	%l3,%o0,%l1
	 sub	%l3,%o3,%g5

	  lda	[%i3+4]%asi,%f29
	fmuld	%f30,%f4,%f30
	fsubd	%f0,%f6,%f4
	 sub	%l1,%o4,%o7

	  fabsd	%f20,%f24
	 andcc	%g5,%o7,%g0
	 bge,pn	%icc,.big1
! delay slot
	 nop

	faddd	%f2,%f8,%f8
	 cmp	%o0,%o5
	 bl,pn	%icc,.small1
! delay slot
	  lda	[%i1]%asi,%o0

	  fabsd	%f28,%f22
	 add	%l1,%o1,%l1
	 addcc	%i0,-1,%i0
	  lda	[%i3]%asi,%l3

	fsubd	%f4,%f30,%f4
	 srl	%l1,10,%l1
	 ble,pn	%icc,.last2
! delay slot
	  mov	%i5,%l6

.cont2:
	  fand	%f20,signbit,%f46
	 andn	%l1,0x1f,%l1
	  add	%i1,%i2,%i1

	  fand	%f28,signbit,%f40
	 cmp	%l1,%o2
	 movg	%icc,%o2,%l1

	  fcmpd	%fcc2,%f24,%f22
	  add	%i3,%i4,%i3
	  add	%i5,%l7,%i5

	fdivd	%f4,%f8,%f4
	  fmovd	%f24,%f20
	 add	%l1,%g1,%l1
	  sethi	%hi(0x80000000),%g5

	 ldd	[%l1+0x10],%f14
	 fand	%f12,mask,%f16
	  andn	%o0,%g5,%o0
	  andn	%l3,%g5,%l3

	  fmovdg %fcc2,%f22,%f20

	  fmovdg %fcc2,%f24,%f22
	  mov	%o0,%o7

	 fsubd	%f12,%f16,%f32
	 fmuld	%f16,%f14,%f16
	  movg	%fcc2,%l3,%o0

	fnegd	pio2_lo,%f8		! al
	 fmuld	%f10,%f14,%f18
	  movg	%fcc2,%o7,%l3

	fzero	%f0
	  fbu,pn %fcc2,.nan2
! delay slot
	  nop

	fmovdg	%fcc0,signbit,%f0
	  sub	%l3,%o0,%l2
	  sub	%l3,%o3,%g5

	 fmuld	%f32,%f14,%f32
	 fsubd	%f10,%f16,%f14
	  sub	%l2,%o4,%o7

	 faddd	%f12,%f18,%f18
	  andcc	%g5,%o7,%g0
	  bge,pn %icc,.big2
! delay slot
	  nop

	fxor	%f36,%f0,%f36
	  cmp	%o0,%o5
	  bl,pn	%icc,.small2
! delay slot
	  nop

.cont3:
	fmovdg	%fcc0,signbit,%f8
	  add	%l2,%o1,%l2

	 fsubd	%f14,%f32,%f14
	  srl	%l2,10,%l2

	fxor	%f36,pio2_lo,%f30	! al
	  andn	%l2,0x1f,%l2

	fxor	%f36,pio2,%f0		! ah
	  cmp	%l2,%o2
	  movg	%icc,%o2,%l2

	fxor	%f42,%f36,%f42		! sy

	faddd	%f8,%f30,%f8
	ldd	[%l0+0x8],%f30
	  add	%l2,%g1,%l2

	 fdivd	%f14,%f18,%f14
	 fzero	%f10

	  ldd	[%l2+0x10],%f24
	  fand	%f22,mask,%f26

	 fmovdg	%fcc1,signbit,%f10

	fmuld	%f4,%f4,%f36
	faddd	%f8,%f30,%f8

	  fsubd	%f22,%f26,%f34
	  fmuld	%f26,%f24,%f26

	  fmuld	%f20,%f24,%f28
	 fxor	%f38,%f10,%f38

	fmuld	%f4,p3,%f6
	 fnegd	pio2_lo,%f18

	fmuld	%f36,p2,%f2
	 fmovdg	%fcc1,signbit,%f18

	fmuld	%f36,%f4,%f36
	 fxor	%f38,pio2,%f10

	  fmuld	%f34,%f24,%f34
	  fsubd	%f20,%f26,%f24

	  faddd	%f22,%f28,%f28

	faddd	%f2,p1,%f2

	fmuld	%f36,p4,%f30
	 fxor	%f38,pio2_lo,%f32

	  fsubd	%f24,%f34,%f24

	 fxor	%f44,%f38,%f44

	fmuld	%f36,%f2,%f2
	 faddd	%f18,%f32,%f18
	 ldd	[%l1+0x8],%f32

	fmuld	%f36,%f36,%f36
	faddd	%f6,%f30,%f30

	  fdivd	%f24,%f28,%f24
	  fzero	%f20

	  fmovdg %fcc2,signbit,%f20

	faddd	%f2,%f8,%f2

	 fmuld	%f14,%f14,%f38
	 faddd	%f18,%f32,%f18

	fmuld	%f36,%f30,%f36
	  fxor	%f40,%f20,%f40

	fnegd	pio2,%f6		! ah
	 fmuld	%f14,p3,%f16

	fmovdg	%fcc0,signbit,%f6

	 fmuld	%f38,p2,%f12
	  fnegd	pio2_lo,%f28

	faddd	%f2,%f36,%f2
	 fmuld	%f38,%f14,%f38

	faddd	%f6,%f0,%f6
	ldd	[%l0],%f0

	  fmovdg %fcc2,signbit,%f28

	 faddd	%f12,p1,%f12

	 fmuld	%f38,p4,%f32
	  fxor	%f40,pio2_lo,%f34

	  fxor	%f40,pio2,%f20

	faddd	%f2,%f4,%f2

	 fmuld	%f38,%f12,%f12
	  fxor	%f46,%f40,%f46

	 fmuld	%f38,%f38,%f38
	 faddd	%f16,%f32,%f32

	  faddd	%f28,%f34,%f28
	  ldd	[%l2+0x8],%f34

	faddd	%f6,%f0,%f6
	lda	[%i1]%asi,%f0		! preload next argument

	 faddd	%f12,%f18,%f12
	lda	[%i1+4]%asi,%f1

	  fmuld	%f24,%f24,%f40
	lda	[%i3]%asi,%f8

	 fmuld	%f38,%f32,%f38
	  faddd	%f28,%f34,%f28
	lda	[%i3+4]%asi,%f9

	 fnegd	pio2,%f16
	  fmuld	%f24,p3,%f26
	lda	[%i1]%asi,%o0

	 fmovdg	%fcc1,signbit,%f16
	lda	[%i3]%asi,%l3

	  fmuld	%f40,p2,%f22

	 faddd	%f12,%f38,%f12
	  fmuld	%f40,%f24,%f40

	faddd	%f2,%f6,%f6

	 faddd	%f16,%f10,%f16
	 ldd	[%l1],%f10

	  faddd	%f22,p1,%f22

	 faddd	%f12,%f14,%f12
	  fmuld	%f40,p4,%f34

	fxor	%f6,%f42,%f6
	st	%f6,[%l4]

	 faddd	%f16,%f10,%f16
	st	%f7,[%l4+4]

	  fmuld	%f40,%f22,%f22

	  fmuld	%f40,%f40,%f40
	  faddd	%f26,%f34,%f34

	  fnegd	pio2,%f26

	 faddd	%f12,%f16,%f16

	  faddd	%f22,%f28,%f22

	  fmuld	%f40,%f34,%f40
	  fmovdg %fcc2,signbit,%f26

! -

	 fxor	%f16,%f44,%f16
	 st	%f16,[%l5]

	  faddd	%f26,%f20,%f26
	 st	%f17,[%l5+4]
	addcc	%i0,-1,%i0

	  faddd	%f22,%f40,%f22
	bg,pt	%icc,.loop
! delay slot
	  ldd	[%l2],%f20


	  faddd	%f26,%f20,%f26
	  faddd	%f22,%f24,%f22
	  faddd	%f22,%f26,%f26
.done_from_special0:
	  fxor	%f26,%f46,%f26
	  st	%f26,[%l6]
	  st	%f27,[%l6+4]
	  ret
	  restore



	.align	16
.last1:
	fmovd	pio2,%f10		! set up dummy arguments
	fmovd	pio2,%f18
	fabsd	%f10,%f14
	fabsd	%f18,%f12
	sethi	%hi(0x3ff921fb),%o0
	or	%o0,%lo(0x3ff921fb),%o0
	mov	%o0,%l3
	ba,pt	%icc,.cont1
! delay slot
	add	%fp,junk,%i5



	.align	16
.last2:
	fmovd	pio2,%f20
	fmovd	pio2,%f28
	fabsd	%f20,%f24
	fabsd	%f28,%f22
	sethi	%hi(0x3ff921fb),%o0
	or	%o0,%lo(0x3ff921fb),%o0
	mov	%o0,%l3
	ba,pt	%icc,.cont2
! delay slot
	add	%fp,junk,%l6



	.align	16
.nan0:
	  faddd	%f22,%f26,%f26
.nan0_from_special0:
	 fabsd	%f10,%f14
	 lda	[%i3+4]%asi,%f19
	 fabsd	%f18,%f12
	 lda	[%i1]%asi,%o0
	 lda	[%i3]%asi,%l3
	ba,pt	%icc,.special0
! delay slot
	fmuld	%f0,%f2,%f6


	.align	16
.big0:
	 fabsd	%f18,%f12
	 lda	[%i1]%asi,%o0
	 lda	[%i3]%asi,%l3
	cmp	%g5,%o5	
	bge,pn	%icc,.return_ah0	! if hx >= 0x7ff00000
! delay slot
	nop
	cmp	%l0,%o4
	bge,pn	%icc,1f			! if hx - hy >= 0x03600000
! delay slot
	nop
	ldd	[%fp+twom3],%f6
	fmuld	%f0,%f6,%f0
	fmuld	%f2,%f6,%f2
	add	%l0,%o1,%l0
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last1
! delay slot
	nop
	ba,pt	%icc,.cont1
! delay slot
	nop
1:
	fbg,pn	%fcc0,.return_ah0
! delay slot
	nop
	fcmpd	%fcc3,%f8,signbit
	fbl,pn	%fcc3,.return_ah0
! delay slot
	nop
	ba,pt	%icc,.special0
! delay slot
	fdivd	%f0,%f2,%f6


	.align	16
.small0:
	 lda	[%i3]%asi,%l3
	fcmpd	%fcc3,%f0,signbit
	fbe,pt	%fcc3,.return_ah0
! delay slot
	nop
	ldd	[%fp+two110],%f6
	fmuld	%f0,%f6,%f0
	fmuld	%f2,%f6,%f2
	st	%f0,[%fp+yscl]
	ld	[%fp+yscl],%o7
	st	%f2,[%fp+xscl]
	ld	[%fp+xscl],%l0
	sub	%l0,%o7,%l0
	add	%l0,%o1,%l0
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last1
! delay slot
	nop
	ba,pt	%icc,.cont1
! delay slot
	nop


	.align	16
.return_ah0:
	fzero	%f0
	fmovdg	%fcc0,signbit,%f0
	fxor	%f36,%f0,%f36
	fxor	%f36,pio2,%f0
	fxor	%f42,%f36,%f42
	fnegd	pio2,%f6
	fmovdg	%fcc0,signbit,%f6
	faddd	%f6,%f0,%f6
	sub	%g5,%l0,%o7
	cmp	%o7,%o5
	bl,pt	%icc,1f			! if hy < 0x7ff00000
! delay slot
	nop
	ldd	[%fp+pio4],%f0
	faddd	%f6,%f0,%f6
1:
	fdtoi	%f6,%f4
.special0:
	fxor	%f6,%f42,%f6
	st	%f6,[%l4]
	st	%f7,[%l4+4]
	addcc	%i0,-1,%i0
	ble,pn	%icc,.done_from_special0
! delay slot
	nop
	fmovd	%f10,%f0
	fmovd	%f18,%f8
	fmovd	%f14,%f4
	fmovd	%f12,%f2
	mov	%i5,%l4
	add	%i1,%i2,%i1
	add	%i3,%i4,%i3
	add	%i5,%l7,%i5
	fand	%f0,signbit,%f42
	sethi	%hi(0x80000000),%g5
	fand	%f8,signbit,%f36
	andn	%o0,%g5,%o0
	andn	%l3,%g5,%l3
	fcmpd	%fcc0,%f4,%f2
	fmovd	%f4,%f0
	fmovdg	%fcc0,%f2,%f0
	fmovdg	%fcc0,%f4,%f2
	mov	%o0,%o7
	movg	%fcc0,%l3,%o0
	movg	%fcc0,%o7,%l3
	 lda	[%i1]%asi,%f10
	 lda	[%i1+4]%asi,%f11
	fbu,pn	%fcc0,.nan0_from_special0
! delay slot
	 lda	[%i3]%asi,%f18
	 fabsd	%f10,%f14
	 lda	[%i3+4]%asi,%f19
	sub	%l3,%o0,%l0
	sub	%l3,%o3,%g5
	sub	%l0,%o4,%o7
	andcc	%g5,%o7,%g0
	bge,pn	%icc,.big0
! delay slot
	nop
	 fabsd	%f18,%f12
	cmp	%o0,%o5
	bl,pn	%icc,.small0
! delay slot
	 lda	[%i1]%asi,%o0
	add	%l0,%o1,%l0
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last1
! delay slot
	 lda	[%i3]%asi,%l3
	ba,pt	%icc,.cont1
! delay slot
	nop



	.align	16
.nan1:
	fmuld	%f30,%f4,%f30
	fsubd	%f0,%f6,%f4
	faddd	%f2,%f8,%f8
	fsubd	%f4,%f30,%f4
.nan1_from_special1:
	 lda	[%i3]%asi,%f28
	 lda	[%i3+4]%asi,%f29
	 fabsd	%f20,%f24
	 lda	[%i1]%asi,%o0
	 fabsd	%f28,%f22
	 lda	[%i3]%asi,%l3
	 mov	%i5,%l6
	ba,pt	%icc,.special1
! delay slot
	fmuld	%f10,%f12,%f16


	.align	16
.big1:
	faddd	%f2,%f8,%f8
	fsubd	%f4,%f30,%f4
.big1_from_special1:
	 lda	[%i1]%asi,%o0
	 fabsd	%f28,%f22
	 lda	[%i3]%asi,%l3
	 mov	%i5,%l6
	cmp	%g5,%o5	
	bge,pn	%icc,.return_ah1
! delay slot
	nop
	cmp	%l1,%o4
	bge,pn	%icc,1f
! delay slot
	nop
	ldd	[%fp+twom3],%f16
	fmuld	%f10,%f16,%f10
	fmuld	%f12,%f16,%f12
	add	%l1,%o1,%l1
	srl	%l1,10,%l1
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last2
! delay slot
	nop
	ba,pt	%icc,.cont2
! delay slot
	nop
1:
	fbg,pn	%fcc1,.return_ah1
! delay slot
	nop
	fcmpd	%fcc3,%f18,signbit
	fbl,pn	%fcc3,.return_ah1
! delay slot
	nop
	ba,pt	%icc,.special1
! delay slot
	fdivd	%f10,%f12,%f16


	.align	16
.small1:
	fsubd	%f4,%f30,%f4
.small1_from_special1:
	 fabsd	%f28,%f22
	 lda	[%i3]%asi,%l3
	 mov	%i5,%l6
	fcmpd	%fcc3,%f10,signbit
	fbe,pt	%fcc3,.return_ah1
! delay slot
	nop
	ldd	[%fp+two110],%f16
	fmuld	%f10,%f16,%f10
	fmuld	%f12,%f16,%f12
	st	%f10,[%fp+yscl]
	ld	[%fp+yscl],%o7
	st	%f12,[%fp+xscl]
	ld	[%fp+xscl],%l1
	sub	%l1,%o7,%l1
	add	%l1,%o1,%l1
	srl	%l1,10,%l1
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last2
! delay slot
	nop
	ba,pt	%icc,.cont2
! delay slot
	nop


	.align	16
.return_ah1:
	fzero	%f10
	fmovdg	%fcc1,signbit,%f10
	fxor	%f38,%f10,%f38
	fxor	%f38,pio2,%f10
	fxor	%f44,%f38,%f44
	fnegd	pio2,%f16
	fmovdg	%fcc1,signbit,%f16
	faddd	%f16,%f10,%f16
	sub	%g5,%l1,%o7
	cmp	%o7,%o5
	bl,pt	%icc,1f	
! delay slot
	nop
	ldd	[%fp+pio4],%f10
	faddd	%f16,%f10,%f16
1:
	fdtoi	%f16,%f14
.special1:
	fxor	%f16,%f44,%f16
	st	%f16,[%l5]
	st	%f17,[%l5+4]
	addcc	%i0,-1,%i0
	bg,pn	%icc,1f
! delay slot
	nop
	fmovd	pio2,%f20		! set up dummy argument
	fmovd	pio2,%f28
	fabsd	%f20,%f24
	fabsd	%f28,%f22
	sethi	%hi(0x3ff921fb),%o0
	or	%o0,%lo(0x3ff921fb),%o0
	mov	%o0,%l3
	add	%fp,junk,%i5
1:
	fmovd	%f20,%f10
	fmovd	%f28,%f18
	fmovd	%f24,%f14
	fmovd	%f22,%f12
	mov	%i5,%l5
	add	%i1,%i2,%i1
	add	%i3,%i4,%i3
	add	%i5,%l7,%i5
	fand	%f10,signbit,%f44
	sethi	%hi(0x80000000),%g5
	fand	%f18,signbit,%f38
	andn	%o0,%g5,%o0
	andn	%l3,%g5,%l3
	fcmpd	%fcc1,%f14,%f12
	fmovd	%f14,%f10
	fmovdg	%fcc1,%f12,%f10
	fmovdg	%fcc1,%f14,%f12
	mov	%o0,%o7
	movg	%fcc1,%l3,%o0
	movg	%fcc1,%o7,%l3
	 lda	[%i1]%asi,%f20
	 lda	[%i1+4]%asi,%f21
	fbu,pn	%fcc1,.nan1_from_special1
! delay slot
	nop
	 lda	[%i3]%asi,%f28
	 lda	[%i3+4]%asi,%f29
	 fabsd	%f20,%f24
	sub	%l3,%o0,%l1
	sub	%l3,%o3,%g5
	sub	%l1,%o4,%o7
	andcc	%g5,%o7,%g0
	bge,pn	%icc,.big1_from_special1
! delay slot
	nop
	cmp	%o0,%o5
	bl,pn	%icc,.small1_from_special1
! delay slot
	 lda	[%i1]%asi,%o0
	 fabsd	%f28,%f22
	 lda	[%i3]%asi,%l3
	add	%l1,%o1,%l1
	srl	%l1,10,%l1
	addcc	%i0,-1,%i0
	ble,pn	%icc,.last2
! delay slot
	 mov	%i5,%l6
	ba,pt	%icc,.cont2
! delay slot
	nop



	.align	16
.nan2:
	fmovdg	%fcc0,signbit,%f0
	 fmuld	%f32,%f14,%f32
	 fsubd	%f10,%f16,%f14
	 faddd	%f12,%f18,%f18
	fxor	%f36,%f0,%f36
.nan2_from_special2:
	ba,pt	%icc,.special2
! delay slot
	fmuld	%f20,%f22,%f26


	.align	16
.big2:
	fxor	%f36,%f0,%f36
.big2_from_special2:
	cmp	%g5,%o5	
	bge,pn	%icc,.return_ah2
! delay slot
	nop
	cmp	%l2,%o4
	bge,pn	%icc,1f
! delay slot
	nop
	ldd	[%fp+twom3],%f26
	fmuld	%f20,%f26,%f20
	fmuld	%f22,%f26,%f22
	ba,pt	%icc,.cont3
! delay slot
	nop
1:
	fbg,pn	%fcc2,.return_ah2
! delay slot
	nop
	fcmpd	%fcc3,%f28,signbit
	fbl,pn	%fcc3,.return_ah2
! delay slot
	nop
	ba,pt	%icc,.special2
! delay slot
	fdivd	%f20,%f22,%f26


	.align	16
.small2:
	fcmpd	%fcc3,%f20,signbit
	fbe,pt	%fcc3,.return_ah2
! delay slot
	nop
	ldd	[%fp+two110],%f26
	fmuld	%f20,%f26,%f20
	fmuld	%f22,%f26,%f22
	st	%f20,[%fp+yscl]
	ld	[%fp+yscl],%o7
	st	%f22,[%fp+xscl]
	ld	[%fp+xscl],%l2
	sub	%l2,%o7,%l2
	ba,pt	%icc,.cont3
! delay slot
	nop


	.align	16
.return_ah2:
	fzero	%f20
	fmovdg	%fcc2,signbit,%f20
	fxor	%f40,%f20,%f40
	fxor	%f40,pio2,%f20
	fxor	%f46,%f40,%f46
	fnegd	pio2,%f26
	fmovdg	%fcc2,signbit,%f26
	faddd	%f26,%f20,%f26
	sub	%g5,%l2,%o7
	cmp	%o7,%o5
	bl,pt	%icc,1f	
! delay slot
	nop
	ldd	[%fp+pio4],%f20
	faddd	%f26,%f20,%f26
1:
	fdtoi	%f26,%f24
.special2:
	fxor	%f26,%f46,%f26
	st	%f26,[%l6]
	st	%f27,[%l6+4]
	addcc	%i0,-1,%i0
	bg,pn	%icc,1f
! delay slot
	nop
	fmovd	pio2,%f20		! set up dummy argument
	fmovd	pio2,%f22
	fzero	%f40
	fzero	%f46
	mov	0,%l2
	ba,pt	%icc,.cont3
! delay slot
	add	%fp,junk,%l6
1:
	lda	[%i1]%asi,%f20
	lda	[%i1+4]%asi,%f21
	lda	[%i3]%asi,%f28
	lda	[%i3+4]%asi,%f29
	fabsd	%f20,%f24
	lda	[%i1]%asi,%o0
	fabsd	%f28,%f22
	lda	[%i3]%asi,%l3
	mov	%i5,%l6
	fand	%f20,signbit,%f46
	add	%i1,%i2,%i1
	fand	%f28,signbit,%f40
	fcmpd	%fcc2,%f24,%f22
	add	%i3,%i4,%i3
	add	%i5,%l7,%i5
	fmovd	%f24,%f20
	sethi	%hi(0x80000000),%g5
	andn	%o0,%g5,%o0
	andn	%l3,%g5,%l3
	fmovdg	%fcc2,%f22,%f20
	fmovdg	%fcc2,%f24,%f22
	mov	%o0,%o7
	movg	%fcc2,%l3,%o0
	movg	%fcc2,%o7,%l3
	fbu,pn	%fcc2,.nan2_from_special2
! delay slot
	nop
	sub	%l3,%o0,%l2
	sub	%l3,%o3,%g5
	sub	%l2,%o4,%o7
	andcc	%g5,%o7,%g0
	bge,pn	%icc,.big2_from_special2
! delay slot
	nop
	cmp	%o0,%o5
	bl,pn	%icc,.small2
! delay slot
	nop
	ba,pt	%icc,.cont3
! delay slot
	nop

	SET_SIZE(__vatan2)

