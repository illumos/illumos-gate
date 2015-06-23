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

	.file	"__vlog.S"

#include "libm.h"

	RO_DATA
	.align	32
TBL:
	.word	0xbfd522ae, 0x0738a000
	.word	0xbd2ebe70, 0x8164c759
	.word	0xbfd3c252, 0x77333000
	.word	0xbd183b54, 0xb606bd5c
	.word	0xbfd26962, 0x1134e000
	.word	0x3d31b61f, 0x10522625
	.word	0xbfd1178e, 0x8227e000
	.word	0xbd31ef78, 0xce2d07f2
	.word	0xbfcf991c, 0x6cb3c000
	.word	0x3d390d04, 0xcd7cc834
	.word	0xbfcd1037, 0xf2656000
	.word	0x3d084a7e, 0x75b6f6e4
	.word	0xbfca93ed, 0x3c8ae000
	.word	0x3d287243, 0x50562169
	.word	0xbfc823c1, 0x6551a000
	.word	0xbd1e0ddb, 0x9a631e83
	.word	0xbfc5bf40, 0x6b544000
	.word	0x3d127023, 0xeb68981c
	.word	0xbfc365fc, 0xb015a000
	.word	0x3d3fd3a0, 0xafb9691b
	.word	0xbfc1178e, 0x8227e000
	.word	0xbd21ef78, 0xce2d07f2
	.word	0xbfbda727, 0x63844000
	.word	0xbd1a8940, 0x1fa71733
	.word	0xbfb9335e, 0x5d594000
	.word	0xbd23115c, 0x3abd47da
	.word	0xbfb4d311, 0x5d208000
	.word	0x3cf53a25, 0x82f4e1ef
	.word	0xbfb08598, 0xb59e4000
	.word	0x3d17e5dd, 0x7009902c
	.word	0xbfa894aa, 0x149f8000
	.word	0xbd39a19a, 0x8be97661
	.word	0xbfa0415d, 0x89e78000
	.word	0x3d3dddc7, 0xf461c516
	.word	0xbf902056, 0x58930000
	.word	0xbd3611d2, 0x7c8e8417
	.word	0x00000000, 0x00000000
	.word	0x00000000, 0x00000000
	.word	0x3f9f829b, 0x0e780000
	.word	0x3d298026, 0x7c7e09e4
	.word	0x3faf0a30, 0xc0110000
	.word	0x3d48a998, 0x5f325c5c
	.word	0x3fb6f0d2, 0x8ae58000
	.word	0xbd34b464, 0x1b664613
	.word	0x3fbe2707, 0x6e2b0000
	.word	0xbd2a342c, 0x2af0003c
	.word	0x3fc29552, 0xf8200000
	.word	0xbd35b967, 0xf4471dfc
	.word	0x3fc5ff30, 0x70a78000
	.word	0x3d43d3c8, 0x73e20a07
	.word	0x3fc9525a, 0x9cf44000
	.word	0x3d46b476, 0x41307539
	.word	0x3fcc8ff7, 0xc79a8000
	.word	0x3d4a21ac, 0x25d81ef3
	.word	0x3fcfb918, 0x6d5e4000
	.word	0xbd0d572a, 0xab993c87
	.word	0x3fd1675c, 0xababa000
	.word	0x3d38380e, 0x731f55c4
	.word	0x3fd2e8e2, 0xbae12000
	.word	0xbd267b1e, 0x99b72bd8
	.word	0x3fd4618b, 0xc21c6000
	.word	0xbd13d82f, 0x484c84cc
	.word	0x3fd5d1bd, 0xbf580000
	.word	0x3d4394a1, 0x1b1c1ee4
! constants:
	.word	0x40000000,0x00000000
	.word	0x3fe55555,0x555571da
	.word	0x3fd99999,0x8702be3a
	.word	0x3fd24af7,0x3f4569b1
	.word	0x3ea62e42,0xfee00000	! scaled by 2**-20
	.word	0x3caa39ef,0x35793c76	! scaled by 2**-20
	.word	0xffff8000,0x00000000
	.word	0x43200000
	.word	0xfff00000
	.word	0xc0194000
	.word	0x4000

#define two		0x200
#define A1		0x208
#define A2		0x210
#define A3		0x218
#define ln2hi		0x220
#define ln2lo		0x228
#define mask		0x230
#define ox43200000	0x238
#define oxfff00000	0x23c
#define oxc0194000	0x240
#define ox4000		0x244

! local storage indices

#define jnk		STACK_BIAS-0x8
#define tmp2		STACK_BIAS-0x10
#define tmp1		STACK_BIAS-0x18
#define tmp0		STACK_BIAS-0x20
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x20

! register use

! i0  n
! i1  x
! i2  stridex
! i3  y
! i4  stridey
! i5  

! g1  TBL

! l0  j0
! l1  j1
! l2  j2
! l3  
! l4  0x94000
! l5  
! l6  0x000fffff
! l7  0x7ff00000

! o0  py0
! o1  py1
! o2  py2
! o3  
! o4  
! o5  
! o7  

! f0  u0,q0
! f2  v0,(two-v0)-u0,z0
! f4  n0,f0,q0
! f6  s0
! f8  q
! f10 u1,q1
! f12 v1,(two-v1)-u1,z1
! f14 n1,f1,q1
! f16 s1
! f18 t
! f20 u2,q2
! f22 v2,(two-v2)-u2,q2
! f24 n2,f2,q2
! f26 s2
! f28 0xfff00000
! f29 0x43200000
! f30 0x4000
! f31 0xc0194000
! f32 t0
! f34 h0,f0-(c0-h0)
! f36 c0
! f38 A1
! f40 two
! f42 t1
! f44 h1,f1-(c1-h1)
! f46 c1
! f48 A2
! f50 0xffff8000...
! f52 t2
! f54 h2,f2-(c2-h2)
! f56 c2
! f58 A3
! f60 ln2hi
! f62 ln2lo

	ENTRY(__vlog)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,TBL,o0)
	mov	%o0,%g1
	wr	%g0,0x82,%asi		! set %asi for non-faulting loads
	sethi	%hi(0x94000),%l4
	sethi	%hi(0x000fffff),%l6
	or	%l6,%lo(0x000fffff),%l6
	sethi	%hi(0x7ff00000),%l7
	ldd	[%g1+two],%f40
	ldd	[%g1+A1],%f38
	ldd	[%g1+A2],%f48
	ldd	[%g1+A3],%f58
	ldd	[%g1+ln2hi],%f60
	ldd	[%g1+ln2lo],%f62
	ldd	[%g1+mask],%f50
	ld	[%g1+ox43200000],%f29
	ld	[%g1+oxfff00000],%f28
	ld	[%g1+oxc0194000],%f31
	ld	[%g1+ox4000],%f30
	sll	%i2,3,%i2		! scale strides
	sll	%i4,3,%i4
	add	%fp,jnk,%o0		! precondition loop
	add	%fp,jnk,%o1
	add	%fp,jnk,%o2
	fzero	%f2
	fzero	%f6
	fzero	%f18
	fzero	%f36
	fzero	%f12
	fzero	%f14
	fzero	%f16
	fzero	%f42
	fzero	%f44
	fzero	%f46
	std	%f46,[%fp+tmp1]
	fzero	%f24
	fzero	%f26
	fzero	%f52
	fzero	%f54
	std	%f54,[%fp+tmp2]
	sub	%i3,%i4,%i3
	ld	[%i1],%l0		! ix
	ld	[%i1],%f0		! u.l[0] = *x
	ba	.loop0
	ld	[%i1+4],%f1		! u.l[1] = *(1+x)

	.align	16
! -- 16 byte aligned
.loop0:
	sub	%l0,%l7,%o3
	sub	%l6,%l0,%o4
	fpadd32s %f0,%f31,%f4		! n = (ix + 0xc0194000) & 0xfff00000
	fmuld	%f6,%f2,%f8		! (previous iteration)

	andcc	%o3,%o4,%o4
	bge,pn	%icc,.range0		! ix <= 0x000fffff or >= 0x7ff00000
! delay slot
	fands	%f4,%f28,%f4

	add	%i1,%i2,%i1		! x += stridex
	add	%i3,%i4,%i3		! y += stridey
	fpsub32s %f0,%f4,%f0		! u.l[0] -= n

.cont0:
	lda	[%i1]%asi,%l1		! preload next argument
	add	%l0,%l4,%l0		! j = ix + 0x94000
	fpadd32s %f0,%f30,%f2		! v.l[0] = u.l[0] + 0x4000

	lda	[%i1]%asi,%f10
	srl	%l0,11,%l0		! j = (j >> 11) & 0x1f0
	fand	%f2,%f50,%f2		! v.l &= 0xffff8000...

	lda	[%i1+4]%asi,%f11
	and	%l0,0x1f0,%l0
	fitod	%f4,%f32		! (double) n

	add	%l0,8,%l3
	fsubd	%f0,%f2,%f4		! f = u.d - v.d

	faddd	%f0,%f2,%f6		! s = f / (u.d + v.d)

	fsubd	%f40,%f2,%f2		! two - v.d
	fmuld	%f32,%f60,%f34		! h = n * ln2hi + TBL[j]

	faddd	%f8,%f18,%f8		! y = c + (t + q)
	fmuld	%f32,%f62,%f32		! t = n * ln2lo + TBL[j+1]

	fdivd	%f4,%f6,%f6

	faddd	%f54,%f24,%f56		! c = h + f
	fmuld	%f26,%f26,%f22		! z = s * s

	faddd	%f8,%f36,%f8
	st	%f8,[%o0]

	st	%f9,[%o0+4]
	mov	%i3,%o0
	faddd	%f14,%f38,%f14

	fsubd	%f56,%f54,%f54		! t += f - (c - h)
	fmuld	%f22,%f58,%f20		! q = ...

	fsubd	%f2,%f0,%f2		! (two - v.d) - u.d
	ldd	[%g1+%l0],%f36

	faddd	%f42,%f44,%f18
	fmuld	%f12,%f14,%f14
	ldd	[%fp+tmp1],%f12

	faddd	%f20,%f48,%f20
	nop

	faddd	%f34,%f36,%f34
	ldd	[%g1+%l3],%f0

	faddd	%f14,%f12,%f12

	fsubd	%f24,%f54,%f54
	fmuld	%f22,%f20,%f24

	std	%f2,[%fp+tmp0]
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop0
! delay slot
	faddd	%f32,%f0,%f32

! -- 16 byte aligned
.loop1:
	sub	%l1,%l7,%o3
	sub	%l6,%l1,%o4
	fpadd32s %f10,%f31,%f14		! n = (ix + 0xc0194000) & 0xfff00000
	fmuld	%f16,%f12,%f8		! (previous iteration)

	andcc	%o3,%o4,%o4
	bge,pn	%icc,.range1		! ix <= 0x000fffff or >= 0x7ff00000
! delay slot
	fands	%f14,%f28,%f14

	add	%i1,%i2,%i1		! x += stridex
	add	%i3,%i4,%i3		! y += stridey
	fpsub32s %f10,%f14,%f10		! u.l[0] -= n

.cont1:
	lda	[%i1]%asi,%l2		! preload next argument
	add	%l1,%l4,%l1		! j = ix + 0x94000
	fpadd32s %f10,%f30,%f12		! v.l[0] = u.l[0] + 0x4000

	lda	[%i1]%asi,%f20
	srl	%l1,11,%l1		! j = (j >> 11) & 0x1f0
	fand	%f12,%f50,%f12		! v.l &= 0xffff8000...

	lda	[%i1+4]%asi,%f21
	and	%l1,0x1f0,%l1
	fitod	%f14,%f42		! (double) n

	add	%l1,8,%l3
	fsubd	%f10,%f12,%f14		! f = u.d - v.d

	faddd	%f10,%f12,%f16		! s = f / (u.d + v.d)

	fsubd	%f40,%f12,%f12		! two - v.d
	fmuld	%f42,%f60,%f44		! h = n * ln2hi + TBL[j]

	faddd	%f8,%f18,%f8		! y = c + (t + q)
	fmuld	%f42,%f62,%f42		! t = n * ln2lo + TBL[j+1]

	fdivd	%f14,%f16,%f16

	faddd	%f34,%f4,%f36		! c = h + f
	fmuld	%f6,%f6,%f2		! z = s * s

	faddd	%f8,%f46,%f8
	st	%f8,[%o1]

	st	%f9,[%o1+4]
	mov	%i3,%o1
	faddd	%f24,%f38,%f24

	fsubd	%f36,%f34,%f34		! t += f - (c - h)
	fmuld	%f2,%f58,%f0		! q = ...

	fsubd	%f12,%f10,%f12		! (two - v.d) - u.d
	ldd	[%g1+%l1],%f46

	faddd	%f52,%f54,%f18
	fmuld	%f22,%f24,%f24
	ldd	[%fp+tmp2],%f22

	faddd	%f0,%f48,%f0
	nop

	faddd	%f44,%f46,%f44
	ldd	[%g1+%l3],%f10

	faddd	%f24,%f22,%f22

	fsubd	%f4,%f34,%f34
	fmuld	%f2,%f0,%f4

	std	%f12,[%fp+tmp1]
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop1
! delay slot
	faddd	%f42,%f10,%f42

! -- 16 byte aligned
.loop2:
	sub	%l2,%l7,%o3
	sub	%l6,%l2,%o4
	fpadd32s %f20,%f31,%f24		! n = (ix + 0xc0194000) & 0xfff00000
	fmuld	%f26,%f22,%f8		! (previous iteration)

	andcc	%o3,%o4,%o4
	bge,pn	%icc,.range2		! ix <= 0x000fffff or >= 0x7ff00000
! delay slot
	fands	%f24,%f28,%f24

	add	%i1,%i2,%i1		! x += stridex
	add	%i3,%i4,%i3		! y += stridey
	fpsub32s %f20,%f24,%f20		! u.l[0] -= n

.cont2:
	lda	[%i1]%asi,%l0		! preload next argument
	add	%l2,%l4,%l2		! j = ix + 0x94000
	fpadd32s %f20,%f30,%f22		! v.l[0] = u.l[0] + 0x4000

	lda	[%i1]%asi,%f0
	srl	%l2,11,%l2		! j = (j >> 11) & 0x1f0
	fand	%f22,%f50,%f22		! v.l &= 0xffff8000...

	lda	[%i1+4]%asi,%f1
	and	%l2,0x1f0,%l2
	fitod	%f24,%f52		! (double) n

	add	%l2,8,%l3
	fsubd	%f20,%f22,%f24		! f = u.d - v.d

	faddd	%f20,%f22,%f26		! s = f / (u.d + v.d)

	fsubd	%f40,%f22,%f22		! two - v.d
	fmuld	%f52,%f60,%f54		! h = n * ln2hi + TBL[j]

	faddd	%f8,%f18,%f8		! y = c + (t + q)
	fmuld	%f52,%f62,%f52		! t = n * ln2lo + TBL[j+1]

	fdivd	%f24,%f26,%f26

	faddd	%f44,%f14,%f46		! c = h + f
	fmuld	%f16,%f16,%f12		! z = s * s

	faddd	%f8,%f56,%f8
	st	%f8,[%o2]

	st	%f9,[%o2+4]
	mov	%i3,%o2
	faddd	%f4,%f38,%f4

	fsubd	%f46,%f44,%f44		! t += f - (c - h)
	fmuld	%f12,%f58,%f10		! q = ...

	fsubd	%f22,%f20,%f22		! (two - v.d) - u.d
	ldd	[%g1+%l2],%f56

	faddd	%f32,%f34,%f18
	fmuld	%f2,%f4,%f4
	ldd	[%fp+tmp0],%f2

	faddd	%f10,%f48,%f10
	nop

	faddd	%f54,%f56,%f54
	ldd	[%g1+%l3],%f20

	faddd	%f4,%f2,%f2

	fsubd	%f14,%f44,%f44
	fmuld	%f12,%f10,%f14

	std	%f22,[%fp+tmp2]
	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	faddd	%f52,%f20,%f52


! Once we get to the last element, we loop three more times to finish
! the computations in progress.  This means we will load past the end
! of the argument vector, but since we use non-faulting loads and never
! use the data, the only potential problem is cache miss.  (Note that
! when the argument is 2, the only exception that occurs in the compu-
! tation is an inexact result in the final addition, and we break out
! of the "extra" iterations before then.)
.endloop2:
	sethi	%hi(0x40000000),%l0	! "next argument" = two
	cmp	%i0,-3
	bg,a,pt	%icc,.loop0
! delay slot
	fmovd	%f40,%f0
	ret
	restore

	.align	16
.endloop0:
	sethi	%hi(0x40000000),%l1	! "next argument" = two
	cmp	%i0,-3
	bg,a,pt	%icc,.loop1
! delay slot
	fmovd	%f40,%f10
	ret
	restore

	.align	16
.endloop1:
	sethi	%hi(0x40000000),%l2	! "next argument" = two
	cmp	%i0,-3
	bg,a,pt	%icc,.loop2
! delay slot
	fmovd	%f40,%f20
	ret
	restore


	.align	16
.range0:
	cmp	%l0,%l7
	bgeu,pn	%icc,2f			! if (unsigned) ix >= 0x7ff00000
! delay slot
	ld	[%i1+4],%o5
	fxtod	%f0,%f0			! scale by 2**1074 w/o trapping
	st	%f0,[%fp+tmp0]
	add	%i1,%i2,%i1		! x += stridex
	orcc	%l0,%o5,%g0
	be,pn	%icc,1f			! if x == 0
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	fpadd32s %f0,%f31,%f4		! n = (ix + 0xc0194000) & 0xfff00000
	fands	%f4,%f28,%f4
	fpsub32s %f0,%f4,%f0		! u.l[0] -= n
	ld	[%fp+tmp0],%l0
	ba,pt	%icc,.cont0
! delay slot
	fpsub32s %f4,%f29,%f4		! n -= 0x43200000
1:
	fdivs	%f29,%f1,%f4		! raise div-by-zero
	ba,pt	%icc,3f
! delay slot
	st	%f28,[%i3]		! store -inf
2:
	sll	%l0,1,%l0		! lop off sign bit
	add	%i1,%i2,%i1		! x += stridex
	orcc	%l0,%o5,%g0
	be,pn	%icc,1b			! if x == -0
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	fabsd	%f0,%f4			! *y = (x + |x|) * inf
	faddd	%f0,%f4,%f0
	fand	%f28,%f50,%f4
	fnegd	%f4,%f4
	fmuld	%f0,%f4,%f0
	st	%f0,[%i3]
3:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop2
! delay slot
	st	%f1,[%i3+4]
	ld	[%i1],%l0		! get next argument
	ld	[%i1],%f0
	ba,pt	%icc,.loop0
! delay slot
	ld	[%i1+4],%f1


	.align	16
.range1:
	cmp	%l1,%l7
	bgeu,pn	%icc,2f			! if (unsigned) ix >= 0x7ff00000
! delay slot
	ld	[%i1+4],%o5
	fxtod	%f10,%f10		! scale by 2**1074 w/o trapping
	st	%f10,[%fp+tmp1]
	add	%i1,%i2,%i1		! x += stridex
	orcc	%l1,%o5,%g0
	be,pn	%icc,1f			! if x == 0
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	fpadd32s %f10,%f31,%f14		! n = (ix + 0xc0194000) & 0xfff00000
	fands	%f14,%f28,%f14
	fpsub32s %f10,%f14,%f10		! u.l[0] -= n
	ld	[%fp+tmp1],%l1
	ba,pt	%icc,.cont1
! delay slot
	fpsub32s %f14,%f29,%f14		! n -= 0x43200000
1:
	fdivs	%f29,%f11,%f14		! raise div-by-zero
	ba,pt	%icc,3f
! delay slot
	st	%f28,[%i3]		! store -inf
2:
	sll	%l1,1,%l1		! lop off sign bit
	add	%i1,%i2,%i1		! x += stridex
	orcc	%l1,%o5,%g0
	be,pn	%icc,1b			! if x == -0
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	fabsd	%f10,%f14		! *y = (x + |x|) * inf
	faddd	%f10,%f14,%f10
	fand	%f28,%f50,%f14
	fnegd	%f14,%f14
	fmuld	%f10,%f14,%f10
	st	%f10,[%i3]
3:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop0
! delay slot
	st	%f11,[%i3+4]
	ld	[%i1],%l1		! get next argument
	ld	[%i1],%f10
	ba,pt	%icc,.loop1
! delay slot
	ld	[%i1+4],%f11


	.align	16
.range2:
	cmp	%l2,%l7
	bgeu,pn	%icc,2f			! if (unsigned) ix >= 0x7ff00000
! delay slot
	ld	[%i1+4],%o5
	fxtod	%f20,%f20		! scale by 2**1074 w/o trapping
	st	%f20,[%fp+tmp2]
	add	%i1,%i2,%i1		! x += stridex
	orcc	%l2,%o5,%g0
	be,pn	%icc,1f			! if x == 0
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	fpadd32s %f20,%f31,%f24		! n = (ix + 0xc0194000) & 0xfff00000
	fands	%f24,%f28,%f24
	fpsub32s %f20,%f24,%f20		! u.l[0] -= n
	ld	[%fp+tmp2],%l2
	ba,pt	%icc,.cont2
! delay slot
	fpsub32s %f24,%f29,%f24		! n -= 0x43200000
1:
	fdivs	%f29,%f21,%f24		! raise div-by-zero
	ba,pt	%icc,3f
! delay slot
	st	%f28,[%i3]		! store -inf
2:
	sll	%l2,1,%l2		! lop off sign bit
	add	%i1,%i2,%i1		! x += stridex
	orcc	%l2,%o5,%g0
	be,pn	%icc,1b			! if x == -0
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	fabsd	%f20,%f24		! *y = (x + |x|) * inf
	faddd	%f20,%f24,%f20
	fand	%f28,%f50,%f24
	fnegd	%f24,%f24
	fmuld	%f20,%f24,%f20
	st	%f20,[%i3]
3:
	addcc	%i0,-1,%i0
	ble,pn	%icc,.endloop1
! delay slot
	st	%f21,[%i3+4]
	ld	[%i1],%l2		! get next argument
	ld	[%i1],%f20
	ba,pt	%icc,.loop2
! delay slot
	ld	[%i1+4],%f21
	
	SET_SIZE(__vlog)

