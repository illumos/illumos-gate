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

	.file	"__vrhypot.S"

#include "libm.h"

	RO_DATA
	.align	64

.CONST_TBL:
	.word	0x7fe00000, 0x7fdfc07f, 0x7fdf81f8, 0x7fdf4465,
	.word	0x7fdf07c1, 0x7fdecc07, 0x7fde9131, 0x7fde573a,
	.word	0x7fde1e1e, 0x7fdde5d6, 0x7fddae60, 0x7fdd77b6,
	.word	0x7fdd41d4, 0x7fdd0cb5, 0x7fdcd856, 0x7fdca4b3,
	.word	0x7fdc71c7, 0x7fdc3f8f, 0x7fdc0e07, 0x7fdbdd2b,
	.word	0x7fdbacf9, 0x7fdb7d6c, 0x7fdb4e81, 0x7fdb2036,
	.word	0x7fdaf286, 0x7fdac570, 0x7fda98ef, 0x7fda6d01,
	.word	0x7fda41a4, 0x7fda16d3, 0x7fd9ec8e, 0x7fd9c2d1,
	.word	0x7fd99999, 0x7fd970e4, 0x7fd948b0, 0x7fd920fb,
	.word	0x7fd8f9c1, 0x7fd8d301, 0x7fd8acb9, 0x7fd886e5,
	.word	0x7fd86186, 0x7fd83c97, 0x7fd81818, 0x7fd7f405,
	.word	0x7fd7d05f, 0x7fd7ad22, 0x7fd78a4c, 0x7fd767dc,
	.word	0x7fd745d1, 0x7fd72428, 0x7fd702e0, 0x7fd6e1f7,
	.word	0x7fd6c16c, 0x7fd6a13c, 0x7fd68168, 0x7fd661ec,
	.word	0x7fd642c8, 0x7fd623fa, 0x7fd60581, 0x7fd5e75b,
	.word	0x7fd5c988, 0x7fd5ac05, 0x7fd58ed2, 0x7fd571ed,
	.word	0x7fd55555, 0x7fd53909, 0x7fd51d07, 0x7fd50150,
	.word	0x7fd4e5e0, 0x7fd4cab8, 0x7fd4afd6, 0x7fd49539,
	.word	0x7fd47ae1, 0x7fd460cb, 0x7fd446f8, 0x7fd42d66,
	.word	0x7fd41414, 0x7fd3fb01, 0x7fd3e22c, 0x7fd3c995,
	.word	0x7fd3b13b, 0x7fd3991c, 0x7fd38138, 0x7fd3698d,
	.word	0x7fd3521c, 0x7fd33ae4, 0x7fd323e3, 0x7fd30d19,
	.word	0x7fd2f684, 0x7fd2e025, 0x7fd2c9fb, 0x7fd2b404,
	.word	0x7fd29e41, 0x7fd288b0, 0x7fd27350, 0x7fd25e22,
	.word	0x7fd24924, 0x7fd23456, 0x7fd21fb7, 0x7fd20b47,
	.word	0x7fd1f704, 0x7fd1e2ef, 0x7fd1cf06, 0x7fd1bb4a,
	.word	0x7fd1a7b9, 0x7fd19453, 0x7fd18118, 0x7fd16e06,
	.word	0x7fd15b1e, 0x7fd1485f, 0x7fd135c8, 0x7fd12358,
	.word	0x7fd11111, 0x7fd0fef0, 0x7fd0ecf5, 0x7fd0db20,
	.word	0x7fd0c971, 0x7fd0b7e6, 0x7fd0a681, 0x7fd0953f,
	.word	0x7fd08421, 0x7fd07326, 0x7fd0624d, 0x7fd05197,
	.word	0x7fd04104, 0x7fd03091, 0x7fd02040, 0x7fd01010,

	.word	0x42300000, 0		! D2ON36 = 2**36
	.word	0xffffff00, 0		! DA0
	.word	0xfff00000, 0		! DA1
	.word	0x3ff00000, 0		! DONE = 1.0
	.word	0x40000000, 0		! DTWO = 2.0
	.word	0x7fd00000, 0		! D2ON1022
	.word	0x3cb00000, 0		! D2ONM52
	.word	0x43200000, 0		! D2ON51
	.word	0x0007ffff, 0xffffffff	! 0x0007ffffffffffff

#define stridex		%l2
#define stridey		%l3
#define stridez		%l5

#define TBL_SHIFT	512

#define TBL		%l1
#define counter		%l4

#define _0x7ff00000	%l0
#define _0x00100000	%o5
#define _0x7fffffff	%l6

#define D2ON36		%f4
#define DTWO		%f6
#define DONE		%f8
#define DA0		%f58
#define DA1		%f56

#define dtmp0		STACK_BIAS-0x80
#define dtmp1		STACK_BIAS-0x78
#define dtmp2		STACK_BIAS-0x70
#define dtmp3		STACK_BIAS-0x68
#define dtmp4		STACK_BIAS-0x60
#define dtmp5		STACK_BIAS-0x58
#define dtmp6		STACK_BIAS-0x50
#define dtmp7		STACK_BIAS-0x48
#define dtmp8		STACK_BIAS-0x40
#define dtmp9		STACK_BIAS-0x38
#define dtmp10		STACK_BIAS-0x30
#define dtmp11		STACK_BIAS-0x28
#define dtmp12		STACK_BIAS-0x20
#define dtmp13		STACK_BIAS-0x18
#define dtmp14		STACK_BIAS-0x10
#define dtmp15		STACK_BIAS-0x08

#define ftmp0		STACK_BIAS-0x100
#define tmp_px		STACK_BIAS-0x98
#define tmp_py		STACK_BIAS-0x90
#define tmp_counter	STACK_BIAS-0x88

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x100

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!  hx0 = *(int*)px;
!  hy0 = *(int*)py;
!
!  ((float*)&x0)[0] = ((float*)px)[0];
!  ((float*)&x0)[1] = ((float*)px)[1];
!  ((float*)&y0)[0] = ((float*)py)[0];
!  ((float*)&y0)[1] = ((float*)py)[1];
!
!  hx0 &= 0x7fffffff;
!  hy0 &= 0x7fffffff;
!
!  diff0 = hy0 - hx0;
!  j0 = diff0 >> 31;
!  j0 &= diff0;
!  j0 = hy0 - j0;
!  j0 &= 0x7ff00000;
!
!  j0 = 0x7ff00000 - j0;
!  ll = (long long)j0 << 32;
!  *(long long*)&scl0 = ll;
!
!  if ( hx0 >= 0x7ff00000 || hy0 >= 0x7ff00000 )
!  {
!    lx = ((int*)px)[1];
!    ly = ((int*)py)[1];
!
!    if ( hx0 == 0x7ff00000 && lx == 0 ) res0 = 0.0;
!    else if ( hy0 == 0x7ff00000 && ly == 0 ) res0 = 0.0;
!    else res0 = fabs(x0) * fabs(y0);
!
!    ((float*)pz)[0] = ((float*)&res0)[0];
!    ((float*)pz)[1] = ((float*)&res0)[1];
!
!    px += stridex;
!    py += stridey;
!    pz += stridez;
!    continue;
!  }
!  if ( hx0 <  0x00100000 && hy0 <  0x00100000 )
!  {
!    lx = ((int*)px)[1];
!    ly = ((int*)py)[1];
!    ii = hx0 | hy0;
!    ii |= lx;
!    ii |= ly;
!    if ( ii == 0 )
!    {
!      res0 = 1.0 / 0.0;
!      ((float*)pz)[0] = ((float*)&res0)[0];
!      ((float*)pz)[1] = ((float*)&res0)[1];
!
!      px += stridex;
!      py += stridey;
!      pz += stridez;
!      continue;
!    }
!    x0 = fabs(x0);
!    y0 = fabs(y0);
!    if ( hx0 < 0x00080000 )
!    {
!      x0 = *(long long*)&x0;
!    }
!    else
!    {
!      ((long long*)&dtmp0)[0] = 0x0007ffffffffffffULL;
!      x0 = vis_fand(x0, dtmp0);
!      x0 = *(long long*)&x0;
!      x0 += D2ON51;
!    }
!    x0 *= D2ONM52;
!    if ( hy0 < 0x00080000 )
!    {
!      y0 = *(long long*)&y0;
!    }
!    else
!    {
!      ((long long*)&dtmp0)[0] = 0x0007ffffffffffffULL;
!      y0 = vis_fand(y0, dtmp0);
!      y0 = *(long long*)&y0;
!      y0 += D2ON51;
!    }
!    y0 *= D2ONM52;
!    *(long long*)&scl0 = 0x7fd0000000000000ULL;
!  }
!  else
!  {
!    x0 *= scl0;
!    y0 *= scl0;
!  }
!
!  x_hi0 = x0 + D2ON36;
!  y_hi0 = y0 + D2ON36;
!  x_hi0 -= D2ON36;
!  y_hi0 -= D2ON36;
!  x_lo0 = x0 - x_hi0;
!  y_lo0 = y0 - y_hi0;
!  res0_hi = x_hi0 * x_hi0;
!  dtmp0 = y_hi0 * y_hi0;
!  res0_hi += dtmp0;
!  res0_lo = x0 + x_hi0;
!  res0_lo *= x_lo0;
!  dtmp1 = y0 + y_hi0;
!  dtmp1 *= y_lo0;
!  res0_lo += dtmp1;
!
!  dres = res0_hi + res0_lo;
!  dexp0 = vis_fand(dres,DA1);
!  iarr = ((int*)&dres)[0];
!
!  iarr >>= 11;
!  iarr &= 0x1fc;
!  dtmp0 = ((double*)((char*)dll1 + iarr))[0];
!  dd = vis_fpsub32(dtmp0, dexp0);
!
!  dtmp0 = dd * dres;
!  dtmp0 = DTWO - dtmp0;
!  dd *= dtmp0;
!  dtmp1 = dd * dres;
!  dtmp1 = DTWO - dtmp1;
!  dd *= dtmp1;
!  dtmp2 = dd * dres;
!  dtmp2 = DTWO - dtmp2;
!  dres = dd * dtmp2;
!
!  res0 = vis_fand(dres,DA0);
!
!  dtmp0 = res0_hi * res0;
!  dtmp0 = DONE - dtmp0;
!  dtmp1 = res0_lo * res0;
!  dtmp0 -= dtmp1;
!  dtmp0 *= dres;
!  res0 += dtmp0;
!
!  res0 = sqrt ( res0 );
!
!  res0 = scl0 * res0;
!
!  ((float*)pz)[0] = ((float*)&res0)[0];
!  ((float*)pz)[1] = ((float*)&res0)[1];
!
!  px += stridex;
!  py += stridey;
!  pz += stridez;
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vrhypot)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,l1)
	wr	%g0,0x82,%asi

#ifdef __sparcv9
	ldx	[%fp+STACK_BIAS+176],stridez
#else
	ld	[%fp+STACK_BIAS+92],stridez
#endif

	sll	%i2,3,stridex
	sethi	%hi(0x7ff00000),_0x7ff00000
	st	%i0,[%fp+tmp_counter]

	sll	%i4,3,stridey
	sethi	%hi(0x00100000),_0x00100000
	stx	%i1,[%fp+tmp_px]

	sll	stridez,3,stridez
	sethi	%hi(0x7ffffc00),_0x7fffffff
	stx	%i3,[%fp+tmp_py]

	ldd	[TBL+TBL_SHIFT],D2ON36
	add	_0x7fffffff,1023,_0x7fffffff

	ldd	[TBL+TBL_SHIFT+8],DA0

	ldd	[TBL+TBL_SHIFT+16],DA1

	ldd	[TBL+TBL_SHIFT+24],DONE

	ldd	[TBL+TBL_SHIFT+32],DTWO

.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%i4
	ldx	[%fp+tmp_py],%i3
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit

	lda	[%i4]0x82,%o1		! (7_0) hx0 = *(int*)px;
	add	%i4,stridex,%i1

	lda	[%i3]0x82,%o4		! (7_0) hy0 = *(int*)py;
	add	%i3,stridey,%i0		! py += stridey

	and	%o1,_0x7fffffff,%o7	! (7_0) hx0 &= 0x7fffffff;

	cmp	%o7,_0x7ff00000		! (7_0) hx0 ? 0x7ff00000
	bge,pn	%icc,.spec0		! (7_0) if ( hx0 >= 0x7ff00000 )
	and	%o4,_0x7fffffff,%l7	! (7_0) hy0 &= 0x7fffffff;

	cmp	%l7,_0x7ff00000		! (7_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.spec0		! (7_0) if ( hy0 >= 0x7ff00000 )
	sub	%l7,%o7,%o1		! (7_0) diff0 = hy0 - hx0;

	sra	%o1,31,%o3		! (7_0) j0 = diff0 >> 31;
	cmp	%o7,_0x00100000		! (7_0) hx0 ? 0x00100000
	bl,pn	%icc,.spec1		! (7_0) if ( hx0 < 0x00100000 )

	and	%o1,%o3,%o1		! (7_0) j0 &= diff0;
.cont_spec0:
	sub	%l7,%o1,%o4		! (7_0) j0 = hy0 - j0;

	and	%o4,%l0,%o4		! (7_0) j0 &= 0x7ff00000;

	sub	%l0,%o4,%g1		! (7_0) j0 = 0x7ff00000 - j0;

	sllx	%g1,32,%g1		! (7_0) ll = (long long)j0 << 32;

	stx	%g1,[%fp+dtmp15]	! (7_0) *(long long*)&scl0 = ll;

	stx	%g1,[%fp+dtmp0]		! (7_1) *(long long*)&scl0 = ll;
.cont_spec1:
	lda	[%i1]0x82,%o1		! (0_0) hx0 = *(int*)px;
	mov	%i1,%i2

	lda	[%i0]0x82,%o4		! (0_0) hy0 = *(int*)py;

	and	%o1,_0x7fffffff,%o7	! (0_0) hx0 &= 0x7fffffff;
	mov	%i0,%o0

	cmp	%o7,_0x7ff00000		! (0_0) hx0 ? 0x7ff00000
	bge,pn	%icc,.update0		! (0_0) if ( hx0 >= 0x7ff00000 )
	and	%o4,_0x7fffffff,%l7	! (0_0) hy0 &= 0x7fffffff;

	cmp	%l7,_0x7ff00000		! (0_0) hy0 ? 0x7ff00000
	sub	%l7,%o7,%o1		! (0_0) diff0 = hy0 - hx0;
	bge,pn	%icc,.update0		! (0_0) if ( hy0 >= 0x7ff00000 )
	sra	%o1,31,%o3		! (0_0) j0 = diff0 >> 31;

	cmp	%o7,_0x00100000		! (0_0) hx0 ? 0x00100000

	and	%o1,%o3,%o1		! (0_0) j0 &= diff0;
	bl,pn	%icc,.update1		! (0_0) if ( hx0 < 0x00100000 )
	sub	%l7,%o1,%o4		! (0_0) j0 = hy0 - j0;
.cont0:
	and	%o4,%l0,%o4		! (0_0) j0 &= 0x7ff00000;

	sub	%l0,%o4,%o4		! (0_0) j0 = 0x7ff00000 - j0;
.cont1:
	sllx	%o4,32,%o4		! (0_0) ll = (long long)j0 << 32;
	stx	%o4,[%fp+dtmp1]		! (0_0) *(long long*)&scl0 = ll;

	ldd	[%fp+dtmp15],%f62	! (7_1) *(long long*)&scl0 = ll;

	lda	[%i4]%asi,%f10		! (7_1) ((float*)&x0)[0] = ((float*)px)[0];

	lda	[%i4+4]%asi,%f11	! (7_1) ((float*)&x0)[1] = ((float*)px)[1];

	lda	[%i3]%asi,%f12		! (7_1) ((float*)&y0)[0] = ((float*)py)[0];

	add	%i1,stridex,%i4		! px += stridex
	lda	[%i3+4]%asi,%f13	! (7_1) ((float*)&y0)[1] = ((float*)py)[1];

	fmuld	%f10,%f62,%f10		! (7_1) x0 *= scl0;
	add	%i4,stridex,%i1		! px += stridex

	fmuld	%f12,%f62,%f60		! (7_1) y0 *= scl0;

	lda	[%i4]0x82,%o1		! (1_0) hx0 = *(int*)px;

	add	%i0,stridey,%i3		! py += stridey
	faddd	%f10,D2ON36,%f46	! (7_1) x_hi0 = x0 + D2ON36;

	lda	[%i3]0x82,%g1		! (1_0) hy0 = *(int*)py;
	add	%i3,stridey,%i0		! py += stridey
	faddd	%f60,D2ON36,%f50	! (7_1) y_hi0 = y0 + D2ON36;

	and	%o1,_0x7fffffff,%o7	! (1_0) hx0 &= 0x7fffffff;

	cmp	%o7,_0x7ff00000		! (1_0) hx0 ? 0x7ff00000
	stx	%o4,[%fp+dtmp2]		! (0_0) *(long long*)&scl0 = ll;

	and	%g1,_0x7fffffff,%l7	! (1_0) hy0 &= 0x7fffffff;
	bge,pn	%icc,.update2		! (1_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f20	! (7_1) x_hi0 -= D2ON36;

	cmp	%l7,_0x7ff00000		! (1_0) hy0 ? 0x7ff00000
	sub	%l7,%o7,%o1		! (1_0) diff0 = hy0 - hx0;
	bge,pn	%icc,.update3		! (1_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f54	! (7_1) y_hi0 -= D2ON36;

	sra	%o1,31,%o3		! (1_0) j0 = diff0 >> 31;

	and	%o1,%o3,%o1		! (1_0) j0 &= diff0;

	fmuld	%f20,%f20,%f2		! (7_1) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (1_0) j0 = hy0 - j0;
	cmp	%o7,_0x00100000		! (1_0) hx0 ? 0x00100000
	fsubd	%f10,%f20,%f0		! (7_1) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (7_1) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (1_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update4		! (1_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (7_1) res0_lo = x0 + x_hi0;

	sub	%l0,%o4,%o4		! (1_0) j0 = 0x7ff00000 - j0;
.cont4:
	sllx	%o4,32,%o4		! (1_0) ll = (long long)j0 << 32;
	stx	%o4,[%fp+dtmp3]		! (1_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (7_1) dtmp1 = y0 + y_hi0;

	fsubd	%f60,%f54,%f12		! (7_1) y_lo0 = y0 - y_hi0;

	fmuld	%f62,%f0,%f0		! (7_1) res0_lo *= x_lo0;
	ldd	[%fp+dtmp1],%f62	! (0_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f44		! (7_1) res0_hi += dtmp0;

	lda	[%i2]%asi,%f10		! (0_0) ((float*)&x0)[0] = ((float*)px)[0];

	lda	[%i2+4]%asi,%f11	! (0_0) ((float*)&x0)[1] = ((float*)px)[1];

	fmuld	%f50,%f12,%f26		! (7_1) dtmp1 *= y_lo0;
	lda	[%o0]%asi,%f12		! (0_0) ((float*)&y0)[0] = ((float*)py)[0];

	lda	[%o0+4]%asi,%f13	! (0_0) ((float*)&y0)[1] = ((float*)py)[1];

	fmuld	%f10,%f62,%f10		! (0_0) x0 *= scl0;

	fmuld	%f12,%f62,%f60		! (0_0) y0 *= scl0;
	faddd	%f0,%f26,%f38		! (7_1) res0_lo += dtmp1;

	lda	[%i1]0x82,%o1		! (2_0) hx0 = *(int*)px;
	mov	%i1,%i2

	faddd	%f10,D2ON36,%f46	! (0_0) x_hi0 = x0 + D2ON36;

	lda	[%i0]0x82,%g1		! (2_0) hy0 = *(int*)py;
	mov	%i0,%o0
	faddd	%f60,D2ON36,%f12	! (0_0) y_hi0 = y0 + D2ON36;

	faddd	%f44,%f38,%f14		! (7_1) dres = res0_hi + res0_lo;
	and	%o1,_0x7fffffff,%o7	! (2_0) hx0 &= 0x7fffffff;

	cmp	%o7,_0x7ff00000		! (2_0) hx0 ? 0x7ff00000
	bge,pn	%icc,.update5		! (2_0) if ( hx0 >= 0x7ff00000 )
	stx	%o4,[%fp+dtmp4]		! (1_0) *(long long*)&scl0 = ll;

	and	%g1,_0x7fffffff,%l7	! (2_0) hx0 &= 0x7fffffff;
	st	%f14,[%fp+ftmp0]	! (7_1) iarr = ((int*)&dres)[0];
	fsubd	%f46,D2ON36,%f20	! (0_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (2_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (2_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update6		! (2_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f12,D2ON36,%f54	! (0_0) y_hi0 -= D2ON36;

	sra	%o1,31,%o3		! (2_0) j0 = diff0 >> 31;

	and	%o1,%o3,%o1		! (2_0) j0 &= diff0;

	fmuld	%f20,%f20,%f2		! (0_0) res0_hi = x_hi0 * x_hi0;
	cmp	%o7,_0x00100000		! (2_0) hx0 ? 0x00100000
	sub	%l7,%o1,%o4		! (2_0) j0 = hy0 - j0;
	fsubd	%f10,%f20,%f0		! (0_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (0_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (2_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update7		! (2_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (0_0) res0_lo = x0 + x_hi0;
.cont7:
	sub	%l0,%o4,%g1		! (2_0) j0 = 0x7ff00000 - j0;

	sllx	%g1,32,%g1		! (2_0) ll = (long long)j0 << 32;
.cont8:
	stx	%g1,[%fp+dtmp5]		! (2_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (0_0) dtmp1 = y0 + y_hi0;

	fsubd	%f60,%f54,%f12		! (0_0) y_lo0 = y0 - y_hi0;

	fmuld	%f62,%f0,%f0		! (0_0) res0_lo *= x_lo0;
	ldd	[%fp+dtmp3],%f62	! (1_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f32		! (0_0) res0_hi += dtmp0;

	lda	[%i4]%asi,%f10		! (1_0) ((float*)&x0)[0] = ((float*)px)[0];

	lda	[%i4+4]%asi,%f11	! (1_0) ((float*)&x0)[1] = ((float*)px)[1];

	fmuld	%f50,%f12,%f28		! (0_0) dtmp1 *= y_lo0;
	lda	[%i3]%asi,%f12		! (1_0) ((float*)&y0)[0] = ((float*)py)[0];

	add	%i1,stridex,%i4		! px += stridex
	lda	[%i3+4]%asi,%f13	! (1_0) ((float*)&y0)[1] = ((float*)py)[1];

	ld	[%fp+ftmp0],%o2		! (7_1) iarr = ((int*)&dres)[0];
	add	%i4,stridex,%i1		! px += stridex
	fand	%f14,DA1,%f2		! (7_1) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (1_0) x0 *= scl0;

	fmuld	%f12,%f62,%f60		! (1_0) y0 *= scl0;
	sra	%o2,11,%i3		! (7_1) iarr >>= 11;
	faddd	%f0,%f28,%f36		! (0_0) res0_lo += dtmp1;

	and	%i3,0x1fc,%i3		! (7_1) iarr &= 0x1fc;

	add	%i3,TBL,%o4		! (7_1) (char*)dll1 + iarr
	lda	[%i4]0x82,%o1		! (3_0) hx0 = *(int*)px;

	add	%i0,stridey,%i3		! py += stridey
	ld	[%o4],%f26		! (7_1) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (1_0) x_hi0 = x0 + D2ON36;

	lda	[%i3]0x82,%o4		! (3_0) hy0 = *(int*)py;
	add	%i3,stridey,%i0		! py += stridey
	faddd	%f60,D2ON36,%f12	! (1_0) y_hi0 = y0 + D2ON36;

	faddd	%f32,%f36,%f22		! (0_0) dres = res0_hi + res0_lo;
	and	%o1,_0x7fffffff,%o7	! (3_0) hx0 &= 0x7fffffff;

	cmp	%o7,_0x7ff00000		! (3_0) hx0 ? 0x7ff00000
	stx	%g1,[%fp+dtmp6]		! (2_0) *(long long*)&scl0 = ll;
	bge,pn	%icc,.update9		! (3_0) if ( hx0 >= 0x7ff00000 )
	fpsub32	%f26,%f2,%f26		! (7_1) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (3_0) hy0 &= 0x7fffffff;
	st	%f22,[%fp+ftmp0]	! (0_0) iarr = ((int*)&dres)[0];
	fsubd	%f46,D2ON36,%f20	! (1_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (3_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (3_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update10		! (3_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f12,D2ON36,%f54	! (1_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f14,%f50		! (7_1) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (3_0) j0 = diff0 >> 31;

	and	%o1,%o3,%o1		! (3_0) j0 &= diff0;

	fmuld	%f20,%f20,%f2		! (1_0) res0_hi = x_hi0 * x_hi0;
	cmp	%o7,_0x00100000		! (3_0) hx0 ? 0x00100000
	sub	%l7,%o1,%o4		! (3_0) j0 = hy0 - j0;
	fsubd	%f10,%f20,%f0		! (1_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (1_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (3_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update11		! (3_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (1_0) res0_lo = x0 + x_hi0;
.cont11:
	sub	%l0,%o4,%g1		! (3_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;
.cont12:
	sllx	%g1,32,%g1		! (3_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp7]		! (3_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (1_0) dtmp1 = y0 + y_hi0;

	fsubd	%f60,%f54,%f12		! (1_0) y_lo0 = y0 - y_hi0

	fmuld	%f62,%f0,%f0		! (1_0) res0_lo *= x_lo0;
	ldd	[%fp+dtmp5],%f62	! (2_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f42		! (1_0) res0_hi += dtmp0;

	lda	[%i2]%asi,%f10		! (2_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f26,%f20,%f54		! (7_1) dd *= dtmp0;

	lda	[%i2+4]%asi,%f11	! (2_0) ((float*)&x0)[1] = ((float*)px)[1];

	fmuld	%f50,%f12,%f26		! (1_0) dtmp1 *= y_lo0;
	lda	[%o0]%asi,%f12		! (2_0) ((float*)&y0)[0] = ((float*)py)[0];

	lda	[%o0+4]%asi,%f13	! (2_0) ((float*)&y0)[1] = ((float*)py)[1];

	fmuld	%f54,%f14,%f50		! (7_1) dtmp1 = dd * dres;
	ld	[%fp+ftmp0],%o2		! (0_0) iarr = ((int*)&dres)[0];
	fand	%f22,DA1,%f2		! (0_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (2_0) x0 *= scl0;

	fmuld	%f12,%f62,%f60		! (2_0) y0 *= scl0;
	sra	%o2,11,%o4		! (0_0) iarr >>= 11;
	faddd	%f0,%f26,%f34		! (1_0) res0_lo += dtmp1;

	and	%o4,0x1fc,%o4		! (0_0) iarr &= 0x1fc;

	add	%o4,TBL,%o4		! (0_0) (char*)dll1 + iarr
	mov	%i1,%i2
	lda	[%i1]0x82,%o1		! (4_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f20		! (7_1) dtmp1 = DTWO - dtmp1;

	ld	[%o4],%f28		! (0_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (2_0) x_hi0 = x0 + D2ON36;

	lda	[%i0]0x82,%o4		! (4_0) hy0 = *(int*)py;
	mov	%i0,%o0
	faddd	%f60,D2ON36,%f50	! (2_0) y_hi0 = y0 + D2ON36;

	and	%o1,_0x7fffffff,%o7	! (4_0) hx0 &= 0x7fffffff;
	faddd	%f42,%f34,%f18		! (1_0) dres = res0_hi + res0_lo;

	fmuld	%f54,%f20,%f16		! (7_1) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (4_0) hx0 ? 0x7ff00000
	stx	%g1,[%fp+dtmp8]		! (3_0) *(long long*)&scl0 = ll;
	fpsub32	%f28,%f2,%f28		! (0_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (4_0) hy0 &= 0x7fffffff;
	bge,pn	%icc,.update13		! (4_0) if ( hx0 >= 0x7ff00000 )
	st	%f18,[%fp+ftmp0]	! (1_0) iarr = ((int*)&dres)[0];
	fsubd	%f46,D2ON36,%f20	! (2_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (4_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (4_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update14		! (4_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f54	! (2_0) y_hi0 -= D2ON36;

	fmuld	%f28,%f22,%f50		! (0_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (4_0) j0 = diff0 >> 31;

	and	%o1,%o3,%o1		! (4_0) j0 &= diff0;

	fmuld	%f20,%f20,%f2		! (2_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (4_0) j0 = hy0 - j0;
	cmp	%o7,_0x00100000		! (4_0) hx0 ? 0x00100000
	fsubd	%f10,%f20,%f0		! (2_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (2_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (4_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update15		! (4_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (2_0) res0_lo = x0 + x_hi0;
.cont15:
	sub	%l0,%o4,%g1		! (4_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;
.cont16:
	fmuld	%f16,%f14,%f14		! (7_1) dtmp2 = dd * dres;
	sllx	%g1,32,%g1		! (4_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp9]		! (4_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (2_0) dtmp1 = y0 + y_hi0;

	fsubd	%f60,%f54,%f12		! (2_0) y_lo0 = y0 - y_hi0;

	fmuld	%f62,%f0,%f0		! (2_0) res0_lo *= x_lo0;
	ldd	[%fp+dtmp7],%f62	! (3_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f30		! (2_0) res0_hi += dtmp0;

	lda	[%i4]%asi,%f10		! (3_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f28,%f20,%f54		! (0_0) dd *= dtmp0;

	lda	[%i4+4]%asi,%f11	! (3_0) ((float*)&x0)[1] = ((float*)px)[1];

	fmuld	%f50,%f12,%f28		! (2_0) dtmp1 *= y_lo0;
	lda	[%i3]%asi,%f12		! (3_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f14,%f20		! (7_1) dtmp2 = DTWO - dtmp2;

	lda	[%i3+4]%asi,%f13	! (3_0) ((float*)&y0)[1] = ((float*)py)[1];
	add	%i1,stridex,%i4		! px += stridex

	fmuld	%f54,%f22,%f50		! (0_0) dtmp1 = dd * dres;
	ld	[%fp+ftmp0],%o2		! (1_0) iarr = ((int*)&dres)[0];
	add	%i4,stridex,%i1		! px += stridex
	fand	%f18,DA1,%f2		! (1_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (3_0) x0 *= scl0;

	fmuld	%f12,%f62,%f60		! (3_0) y0 *= scl0;
	sra	%o2,11,%i3		! (1_0) iarr >>= 11;
	faddd	%f0,%f28,%f40		! (2_0) res0_lo += dtmp1;

	and	%i3,0x1fc,%i3		! (1_0) iarr &= 0x1fc;
	fmuld	%f16,%f20,%f28		! (7_1) dres = dd * dtmp2;

	add	%i3,TBL,%o4		! (1_0) (char*)dll1 + iarr
	lda	[%i4]0x82,%o1		! (5_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f20		! (0_0) dtmp1 = DTWO - dtmp1;

	add	%i0,stridey,%i3		! py += stridey
	ld	[%o4],%f26		! (1_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (3_0) x_hi0 = x0 + D2ON36;

	lda	[%i3]0x82,%o4		! (5_0) hy0 = *(int*)py;
	add	%i3,stridey,%i0		! py += stridey
	faddd	%f60,D2ON36,%f50	! (3_0) y_hi0 = y0 + D2ON36;

	and	%o1,_0x7fffffff,%o7	! (5_0) hx0 &= 0x7fffffff;
	faddd	%f30,%f40,%f14		! (2_0) dres = res0_hi + res0_lo;

	fmuld	%f54,%f20,%f24		! (0_0) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (5_0) hx0 ? 0x7ff00000
	stx	%g1,[%fp+dtmp10]	! (4_0) *(long long*)&scl0 = ll;
	fpsub32	%f26,%f2,%f26		! (1_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (5_0) hy0 &= 0x7fffffff;
	st	%f14,[%fp+ftmp0]	! (2_0) iarr = ((int*)&dres)[0];
	bge,pn	%icc,.update17		! (5_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f20	! (3_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (5_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (5_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update18		! (5_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f54	! (3_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f18,%f50		! (1_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (5_0) j0 = diff0 >> 31;

	and	%o1,%o3,%o1		! (5_0) j0 &= diff0;
	fand	%f28,DA0,%f48		! (7_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (3_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (5_0) j0 = hy0 - j0;
	cmp	%o7,_0x00100000		! (5_0) hx0 ? 0x00100000
	fsubd	%f10,%f20,%f0		! (3_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (3_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (5_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update19		! (5_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (3_0) res0_lo = x0 + x_hi0;
.cont19a:
	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	sub	%l0,%o4,%g1		! (5_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;
.cont19b:
	fmuld	%f24,%f22,%f22		! (0_0) dtmp2 = dd * dres;
	sllx	%g1,32,%g1		! (5_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp11]	! (5_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (3_0) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (7_1) dtmp1 = res0_lo * res0;
	fsubd	%f60,%f54,%f12		! (3_0) y_lo0 = y0 - y_hi0;
.cont20:
	fmuld	%f62,%f0,%f0		! (3_0) res0_lo *= x_lo0;
	ldd	[%fp+dtmp9],%f62	! (4_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f44		! (3_0) res0_hi += dtmp0;

	fsubd	DONE,%f10,%f60		! (7_1) dtmp0 = DONE - dtmp0;
	lda	[%i2]%asi,%f10		! (4_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f26,%f20,%f54		! (1_0) dd *= dtmp0;

	lda	[%i2+4]%asi,%f11	! (4_0) ((float*)&x0)[1] = ((float*)px)[1];

	fmuld	%f50,%f12,%f26		! (3_0) dtmp1 *= y_lo0;
	lda	[%o0]%asi,%f12		! (4_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f22,%f20		! (0_0) dtmp2 = DTWO - dtmp2;

	lda	[%o0+4]%asi,%f13	! (4_0) ((float*)&y0)[1] = ((float*)py)[1];

	fmuld	%f54,%f18,%f50		! (1_0) dtmp1 = dd * dres;
	ld	[%fp+ftmp0],%o2		! (2_0) iarr = ((int*)&dres)[0];
	fand	%f14,DA1,%f2		! (2_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (4_0) x0 *= scl0;
	fsubd	%f60,%f38,%f46		! (7_1) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (4_0) y0 *= scl0;
	sra	%o2,11,%o4		! (2_0) iarr >>= 11;
	faddd	%f0,%f26,%f38		! (3_0) res0_lo += dtmp1;

	and	%o4,0x1fc,%o4		! (2_0) iarr &= 0x1fc;
	fmuld	%f24,%f20,%f26		! (0_0) dres = dd * dtmp2;

	add	%o4,TBL,%o4		! (2_0) (char*)dll1 + iarr
	mov	%i1,%i2
	lda	[%i1]0x82,%o1		! (6_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f52		! (1_0) dtmp1 = DTWO - dtmp1;

	fmuld	%f46,%f28,%f28		! (7_1) dtmp0 *= dres;
	ld	[%o4],%f20		! (2_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (4_0) x_hi0 = x0 + D2ON36;

	lda	[%i0]0x82,%o4		! (6_0) hy0 = *(int*)py;
	mov	%i0,%o0
	faddd	%f60,D2ON36,%f50	! (4_0) y_hi0 = y0 + D2ON36;

	and	%o1,_0x7fffffff,%o7	! (6_0) hx0 &= 0x7fffffff;
	faddd	%f44,%f38,%f22		! (3_0) dres = res0_hi + res0_lo;

	fmuld	%f54,%f52,%f16		! (1_0) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (6_0) hx0 ? 0x7ff00000
	stx	%g1,[%fp+dtmp12]	! (5_0) *(long long*)&scl0 = ll;
	fpsub32	%f20,%f2,%f52		! (2_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (6_0) hy0 &= 0x7fffffff;
	st	%f22,[%fp+ftmp0]	! (3_0) iarr = ((int*)&dres)[0];
	bge,pn	%icc,.update21		! (6_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f46	! (4_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (6_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (6_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update22		! (6_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f54	! (4_0) y_hi0 -= D2ON36;

	fmuld	%f52,%f14,%f50		! (2_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (6_0) j0 = diff0 >> 31;
	faddd	%f48,%f28,%f48		! (7_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (6_0) j0 &= diff0;
	fand	%f26,DA0,%f28		! (0_0) res0 = vis_fand(dres,DA0);

	fmuld	%f46,%f46,%f0		! (4_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (6_0) j0 = hy0 - j0;
	cmp	%o7,_0x00100000		! (6_0) hx0 ? 0x00100000
	fsubd	%f10,%f46,%f2		! (4_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f20		! (4_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (6_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update23		! (6_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f46,%f62		! (4_0) res0_lo = x0 + x_hi0;
.cont23a:
	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	sub	%l0,%o4,%g1		! (6_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;
.cont23b:
	fmuld	%f32,%f28,%f50		! (0_0) dtmp0 = res0_hi * res0;
	sllx	%g1,32,%g1		! (6_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp13]	! (6_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f46		! (4_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f28,%f36		! (0_0) dtmp1 = res0_lo * res0;
	fsubd	%f60,%f54,%f60		! (4_0) y_lo0 = y0 - y_hi0;
.cont24:
	fmuld	%f62,%f2,%f2		! (4_0) res0_lo *= x_lo0;
	ldd	[%fp+dtmp11],%f62	! (5_0) *(long long*)&scl0 = ll;
	faddd	%f0,%f20,%f32		! (4_0) res0_hi += dtmp0;

	lda	[%i4]%asi,%f0		! (5_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f52,%f10,%f10		! (2_0) dd *= dtmp0;

	lda	[%i4+4]%asi,%f1		! (5_0) ((float*)&x0)[1] = ((float*)px)[1];
	fsubd	DONE,%f50,%f52		! (0_0) dtmp0 = DONE - dtmp0;

	fmuld	%f46,%f60,%f46		! (4_0) dtmp1 *= y_lo0;
	lda	[%i3]%asi,%f12		! (5_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f18,%f18		! (1_0) dtmp2 = DTWO - dtmp2;

	add	%i1,stridex,%i4		! px += stridex
	lda	[%i3+4]%asi,%f13	! (5_0) ((float*)&y0)[1] = ((float*)py)[1];

	fmuld	%f10,%f14,%f50		! (2_0) dtmp1 = dd * dres;
	add	%i4,stridex,%i1		! px += stridex
	ld	[%fp+ftmp0],%o2		! (3_0) iarr = ((int*)&dres)[0];
	fand	%f22,DA1,%f54		! (3_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f0,%f62,%f60		! (5_0) x0 *= scl0;
	fsubd	%f52,%f36,%f20		! (0_0) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f52		! (5_0) y0 *= scl0;
	sra	%o2,11,%i3		! (3_0) iarr >>= 11;
	faddd	%f2,%f46,%f36		! (4_0) res0_lo += dtmp1;

	and	%i3,0x1fc,%i3		! (3_0) iarr &= 0x1fc;
	fmuld	%f16,%f18,%f16		! (1_0) dres = dd * dtmp2;

	fsqrtd	%f48,%f18		! (7_1) res0 = sqrt ( res0 );
	add	%i3,TBL,%o4		! (3_0) (char*)dll1 + iarr
	lda	[%i4]0x82,%o1		! (7_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f46		! (2_0) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f26,%f48		! (0_0) dtmp0 *= dres;
	add	%i0,stridey,%i3		! py += stridey
	ld	[%o4],%f20		! (3_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f60,D2ON36,%f50	! (5_0) x_hi0 = x0 + D2ON36;

	lda	[%i3]0x82,%o4		! (7_0) hy0 = *(int*)py;
	add	%i3,stridey,%i0		! py += stridey
	faddd	%f52,D2ON36,%f12	! (5_0) y_hi0 = y0 + D2ON36;

	and	%o1,_0x7fffffff,%o7	! (7_0) hx0 &= 0x7fffffff;
	faddd	%f32,%f36,%f24		! (4_0) dres = res0_hi + res0_lo;

	fmuld	%f10,%f46,%f26		! (2_0) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (7_0) hx0 ? 0x7ff00000
	stx	%g1,[%fp+dtmp14]	! (6_0) *(long long*)&scl0 = ll;
	fpsub32	%f20,%f54,%f10		! (3_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (7_0) hy0 &= 0x7fffffff;
	st	%f24,[%fp+ftmp0]	! (4_0) iarr = ((int*)&dres)[0];
	bge,pn	%icc,.update25		! (7_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f20	! (5_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (7_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (7_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update26		! (7_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f12,D2ON36,%f54	! (5_0) y_hi0 -= D2ON36;

	fmuld	%f10,%f22,%f50		! (3_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (7_0) j0 = diff0 >> 31;
	faddd	%f28,%f48,%f48		! (0_0) res0 += dtmp0;

	and	%o1,%o3,%o1		! (7_0) j0 &= diff0;
	fand	%f16,DA0,%f28		! (1_0) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f0		! (5_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (7_0) j0 = hy0 - j0;
	cmp	%o7,_0x00100000		! (7_0) hx0 ? 0x00100000
	fsubd	%f60,%f20,%f2		! (5_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (5_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (7_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update27		! (7_0) if ( hx0 < 0x00100000 )
	faddd	%f60,%f20,%f62		! (5_0) res0_lo = x0 + x_hi0;
.cont27a:
	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	sub	%l0,%o4,%g1		! (7_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;
.cont27b:
	fmuld	%f42,%f28,%f60		! (1_0) dtmp0 = res0_hi * res0;
	sllx	%g1,32,%g1		! (7_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp15]	! (7_0) *(long long*)&scl0 = ll;
	faddd	%f52,%f54,%f50		! (5_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f28,%f34		! (1_0) dtmp1 = res0_lo * res0;
	fsubd	%f52,%f54,%f54		! (5_0) y_lo0 = y0 - y_hi0;
.cont28:
	fmuld	%f62,%f2,%f2		! (5_0) res0_lo *= x_lo0;
	ldd	[%fp+dtmp13],%f62	! (6_0) *(long long*)&scl0 = ll;
	faddd	%f0,%f46,%f42		! (5_0) res0_hi += dtmp0;

	fmuld	%f10,%f20,%f52		! (3_0) dd *= dtmp0;
	lda	[%i2]%asi,%f10		! (6_0) ((float*)&x0)[0] = ((float*)px)[0];

	lda	[%i2+4]%asi,%f11	! (6_0) ((float*)&x0)[1] = ((float*)px)[1];
	fsubd	DONE,%f60,%f60		! (1_0) dtmp0 = DONE - dtmp0;

	fmuld	%f50,%f54,%f46		! (5_0) dtmp1 *= y_lo0;
	lda	[%o0]%asi,%f12		! (6_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f14,%f14		! (2_0) dtmp2 = DTWO - dtmp2;

	lda	[%o0+4]%asi,%f13	! (6_0) ((float*)&y0)[1] = ((float*)py)[1];

	fmuld	%f52,%f22,%f50		! (3_0) dtmp1 = dd * dres;
	ld	[%fp+ftmp0],%o2		! (4_0) iarr = ((int*)&dres)[0];
	fand	%f24,DA1,%f54		! (4_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (6_0) x0 *= scl0;
	ldd	[%fp+dtmp0],%f0		! (7_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f34,%f20		! (1_0) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (6_0) y0 *= scl0;
	sra	%o2,11,%o4		! (4_0) iarr >>= 11;
	faddd	%f2,%f46,%f34		! (5_0) res0_lo += dtmp1;

	and	%o4,0x1fc,%o4		! (4_0) iarr &= 0x1fc;
	fmuld	%f26,%f14,%f26		! (2_0) dres = dd * dtmp2;

	cmp	counter,8
	bl,pn	%icc,.tail
	nop

	ba	.main_loop
	sub	counter,8,counter

	.align	16
.main_loop:
	fsqrtd	%f48,%f14		! (0_1) res0 = sqrt ( res0 );
	add	%o4,TBL,%o4		! (4_1) (char*)dll1 + iarr
	lda	[%i1]0x82,%o1		! (0_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f46		! (3_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f16,%f48		! (1_1) dtmp0 *= dres;
	mov	%i1,%i2
	ld	[%o4],%f20		! (4_1) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f50	! (6_1) x_hi0 = x0 + D2ON36;

	nop
	mov	%i0,%o0
	lda	[%i0]0x82,%o4		! (0_0) hy0 = *(int*)py;
	faddd	%f60,D2ON36,%f2		! (6_1) y_hi0 = y0 + D2ON36;

	faddd	%f42,%f34,%f16		! (5_1) dres = res0_hi + res0_lo;
	and	%o1,_0x7fffffff,%o7	! (0_0) hx0 &= 0x7fffffff;
	st	%f16,[%fp+ftmp0]	! (5_1) iarr = ((int*)&dres)[0];
	fmuld	%f0,%f18,%f0		! (7_2) res0 = scl0 * res0;

	fmuld	%f52,%f46,%f18		! (3_1) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (0_0) hx0 ? 0x7ff00000
	st	%f0,[%i5]		! (7_2) ((float*)pz)[0] = ((float*)&res0)[0];
	fpsub32	%f20,%f54,%f54		! (4_1) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (0_0) hy0 &= 0x7fffffff;
	st	%f1,[%i5+4]		! (7_2) ((float*)pz)[1] = ((float*)&res0)[1];
	bge,pn	%icc,.update29		! (0_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f20	! (6_1) x_hi0 -= D2ON36;

	cmp	%l7,_0x7ff00000		! (0_0) hy0 ? 0x7ff00000
	sub	%l7,%o7,%o1		! (0_0) diff0 = hy0 - hx0;
	bge,pn	%icc,.update30		! (0_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f2,D2ON36,%f2		! (6_1) y_hi0 -= D2ON36;

	fmuld	%f54,%f24,%f50		! (4_1) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (0_0) j0 = diff0 >> 31;
	stx	%g1,[%fp+dtmp0]		! (7_1) *(long long*)&scl0 = ll;
	faddd	%f28,%f48,%f52		! (1_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (0_0) j0 &= diff0;
	cmp	%o7,_0x00100000		! (0_0) hx0 ? 0x00100000
	bl,pn	%icc,.update31		! (0_0) if ( hx0 < 0x00100000 )
	fand	%f26,DA0,%f48		! (2_1) res0 = vis_fand(dres,DA0);
.cont31:
	fmuld	%f20,%f20,%f0		! (6_1) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (0_0) j0 = hy0 - j0;
	nop
	fsubd	%f10,%f20,%f28		! (6_1) x_lo0 = x0 - x_hi0;

	fmuld	%f2,%f2,%f46		! (6_1) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	and	%o4,%l0,%o4		! (0_0) j0 &= 0x7ff00000;
	faddd	%f10,%f20,%f62		! (6_1) res0_lo = x0 + x_hi0;

	fmuld	%f18,%f22,%f22		! (3_1) dtmp2 = dd * dres;
	sub	%l0,%o4,%o4		! (0_0) j0 = 0x7ff00000 - j0;
	nop
	fsubd	DTWO,%f50,%f20		! (4_1) dtmp0 = DTWO - dtmp0;
.cont32:
	fmuld	%f30,%f48,%f12		! (2_1) dtmp0 = res0_hi * res0;
	sllx	%o4,32,%o4		! (0_0) ll = (long long)j0 << 32;
	stx	%o4,[%fp+dtmp1]		! (0_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f2,%f50		! (6_1) dtmp1 = y0 + y_hi0;

	fmuld	%f40,%f48,%f40		! (2_1) dtmp1 = res0_lo * res0;
	nop
	bn,pn	%icc,.exit
	fsubd	%f60,%f2,%f2		! (6_1) y_lo0 = y0 - y_hi0;

	fmuld	%f62,%f28,%f28		! (6_1) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp15],%f62	! (7_1) *(long long*)&scl0 = ll;
	faddd	%f0,%f46,%f30		! (6_1) res0_hi += dtmp0;

	nop
	nop
	lda	[%i4]%asi,%f10		! (7_1) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f54,%f20,%f54		! (4_1) dd *= dtmp0;

	nop
	nop
	lda	[%i4+4]%asi,%f11	! (7_1) ((float*)&x0)[1] = ((float*)px)[1];
	fsubd	DONE,%f12,%f60		! (2_1) dtmp0 = DONE - dtmp0;

	fmuld	%f50,%f2,%f46		! (6_1) dtmp1 *= y_lo0;
	nop
	lda	[%i3]%asi,%f12		! (7_1) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f22,%f22		! (3_1) dtmp2 = DTWO - dtmp2;

	add	%i1,stridex,%i4		! px += stridex
	nop
	lda	[%i3+4]%asi,%f13	! (7_1) ((float*)&y0)[1] = ((float*)py)[1];
	bn,pn	%icc,.exit

	fmuld	%f54,%f24,%f50		! (4_1) dtmp1 = dd * dres;
	add	%i4,stridex,%i1		! px += stridex
	ld	[%fp+ftmp0],%o2		! (5_1) iarr = ((int*)&dres)[0];
	fand	%f16,DA1,%f2		! (5_1) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (7_1) x0 *= scl0;
	nop
	ldd	[%fp+dtmp2],%f0		! (0_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f40,%f20		! (2_1) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (7_1) y0 *= scl0;
	sra	%o2,11,%i3		! (5_1) iarr >>= 11;
	nop
	faddd	%f28,%f46,%f40		! (6_1) res0_lo += dtmp1;

	and	%i3,0x1fc,%i3		! (5_1) iarr &= 0x1fc;
	nop
	bn,pn	%icc,.exit
	fmuld	%f18,%f22,%f28		! (3_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f22		! (1_1) res0 = sqrt ( res0 );
	lda	[%i4]0x82,%o1		! (1_0) hx0 = *(int*)px;
	add	%i3,TBL,%g1		! (5_1) (char*)dll1 + iarr
	fsubd	DTWO,%f50,%f62		! (4_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f26,%f52		! (2_1) dtmp0 *= dres;
	add	%i0,stridey,%i3		! py += stridey
	ld	[%g1],%f26		! (5_1) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (7_1) x_hi0 = x0 + D2ON36;

	nop
	add	%i3,stridey,%i0		! py += stridey
	lda	[%i3]0x82,%g1		! (1_0) hy0 = *(int*)py;
	faddd	%f60,D2ON36,%f50	! (7_1) y_hi0 = y0 + D2ON36;

	faddd	%f30,%f40,%f18		! (6_1) dres = res0_hi + res0_lo;
	and	%o1,_0x7fffffff,%o7	! (1_0) hx0 &= 0x7fffffff;
	st	%f18,[%fp+ftmp0]	! (6_1) iarr = ((int*)&dres)[0];
	fmuld	%f0,%f14,%f0		! (0_1) res0 = scl0 * res0;

	fmuld	%f54,%f62,%f14		! (4_1) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (1_0) hx0 ? 0x7ff00000
	st	%f0,[%i5]		! (0_1) ((float*)pz)[0] = ((float*)&res0)[0];
	fpsub32	%f26,%f2,%f26		! (5_1) dd = vis_fpsub32(dtmp0, dexp0);

	and	%g1,_0x7fffffff,%l7	! (1_0) hy0 &= 0x7fffffff;
	nop
	bge,pn	%icc,.update33		! (1_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f20	! (7_1) x_hi0 -= D2ON36;

	cmp	%l7,_0x7ff00000		! (1_0) hy0 ? 0x7ff00000
	sub	%l7,%o7,%o1		! (1_0) diff0 = hy0 - hx0;
	st	%f1,[%i5+4]		! (0_1) ((float*)pz)[1] = ((float*)&res0)[1];
	fsubd	%f50,D2ON36,%f54	! (7_1) y_hi0 -= D2ON36;

	fmuld	%f26,%f16,%f50		! (5_1) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (1_0) j0 = diff0 >> 31;
	bge,pn	%icc,.update34		! (1_0) if ( hy0 >= 0x7ff00000 )
	faddd	%f48,%f52,%f52		! (2_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (1_0) j0 &= diff0;
	add	%i5,stridez,%i5		! pz += stridez
	stx	%o4,[%fp+dtmp2]		! (0_0) *(long long*)&scl0 = ll;
	fand	%f28,DA0,%f48		! (3_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (7_1) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (1_0) j0 = hy0 - j0;
	cmp	%o7,_0x00100000		! (1_0) hx0 ? 0x00100000
	fsubd	%f10,%f20,%f0		! (7_1) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (7_1) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (1_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update35		! (1_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (7_1) res0_lo = x0 + x_hi0;
.cont35a:
	fmuld	%f44,%f48,%f10		! (3_1) dtmp0 = res0_hi * res0;
	nop
	sub	%l0,%o4,%o4		! (1_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f20		! (5_1) dtmp0 = DTWO - dtmp0;
.cont35b:
	fmuld	%f14,%f24,%f24		! (4_1) dtmp2 = dd * dres;
	sllx	%o4,32,%o4		! (1_0) ll = (long long)j0 << 32;
	stx	%o4,[%fp+dtmp3]		! (1_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (7_1) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (3_1) dtmp1 = res0_lo * res0;
	nop
	nop
	fsubd	%f60,%f54,%f12		! (7_1) y_lo0 = y0 - y_hi0;
.cont36:
	fmuld	%f62,%f0,%f0		! (7_1) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp1],%f62	! (0_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f44		! (7_1) res0_hi += dtmp0;

	fsubd	DONE,%f10,%f60		! (3_1) dtmp0 = DONE - dtmp0;
	nop
	lda	[%i2]%asi,%f10		! (0_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f26,%f20,%f54		! (5_1) dd *= dtmp0;

	nop
	nop
	lda	[%i2+4]%asi,%f11	! (0_0) ((float*)&x0)[1] = ((float*)px)[1];
	bn,pn	%icc,.exit

	fmuld	%f50,%f12,%f26		! (7_1) dtmp1 *= y_lo0;
	nop
	lda	[%o0]%asi,%f12		! (0_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f24,%f24		! (4_1) dtmp2 = DTWO - dtmp2;

	nop
	nop
	lda	[%o0+4]%asi,%f13	! (0_0) ((float*)&y0)[1] = ((float*)py)[1];
	bn,pn	%icc,.exit

	fmuld	%f54,%f16,%f46		! (5_1) dtmp1 = dd * dres;
	nop
	ld	[%fp+ftmp0],%o2		! (6_1) iarr = ((int*)&dres)[0];
	fand	%f18,DA1,%f2		! (6_1) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (0_0) x0 *= scl0;
	nop
	ldd	[%fp+dtmp4],%f50	! (1_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f38,%f20		! (3_1) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (0_0) y0 *= scl0;
	sra	%o2,11,%g1		! (6_1) iarr >>= 11;
	nop
	faddd	%f0,%f26,%f38		! (7_1) res0_lo += dtmp1;

	nop
	and	%g1,0x1fc,%g1		! (6_1) iarr &= 0x1fc;
	bn,pn	%icc,.exit
	fmuld	%f14,%f24,%f26		! (4_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f24		! (2_1) res0 = sqrt ( res0 );
	lda	[%i1]0x82,%o1		! (2_0) hx0 = *(int*)px;
	add	%g1,TBL,%g1		! (6_1) (char*)dll1 + iarr
	fsubd	DTWO,%f46,%f62		! (5_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f28,%f52		! (3_1) dtmp0 *= dres;
	mov	%i1,%i2
	ld	[%g1],%f28		! (6_1) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (0_0) x_hi0 = x0 + D2ON36;

	nop
	mov	%i0,%o0
	lda	[%i0]0x82,%g1		! (2_0) hy0 = *(int*)py;
	faddd	%f60,D2ON36,%f12	! (0_0) y_hi0 = y0 + D2ON36;

	faddd	%f44,%f38,%f14		! (7_1) dres = res0_hi + res0_lo;
	and	%o1,_0x7fffffff,%o7	! (2_0) hx0 &= 0x7fffffff;
	st	%f14,[%fp+ftmp0]	! (7_1) iarr = ((int*)&dres)[0];
	fmuld	%f50,%f22,%f0		! (1_1) res0 = scl0 * res0;

	fmuld	%f54,%f62,%f22		! (5_1) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (2_0) hx0 ? 0x7ff00000
	st	%f0,[%i5]		! (1_1) ((float*)pz)[0] = ((float*)&res0)[0];
	fpsub32	%f28,%f2,%f28		! (6_1) dd = vis_fpsub32(dtmp0, dexp0);

	and	%g1,_0x7fffffff,%l7	! (2_0) hx0 &= 0x7fffffff;
	nop
	bge,pn	%icc,.update37		! (2_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f20	! (0_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (2_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (2_0) hy0 ? 0x7ff00000
	st	%f1,[%i5+4]		! (1_1) ((float*)pz)[1] = ((float*)&res0)[1];
	fsubd	%f12,D2ON36,%f54	! (0_0) y_hi0 -= D2ON36;

	fmuld	%f28,%f18,%f50		! (6_1) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (2_0) j0 = diff0 >> 31;
	bge,pn	%icc,.update38		! (2_0) if ( hy0 >= 0x7ff00000 )
	faddd	%f48,%f52,%f52		! (3_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (2_0) j0 &= diff0;
	add	%i5,stridez,%i5		! pz += stridez
	stx	%o4,[%fp+dtmp4]		! (1_0) *(long long*)&scl0 = ll;
	fand	%f26,DA0,%f48		! (4_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (0_0) res0_hi = x_hi0 * x_hi0;
	cmp	%o7,_0x00100000		! (2_0) hx0 ? 0x00100000
	sub	%l7,%o1,%o4		! (2_0) j0 = hy0 - j0;
	fsubd	%f10,%f20,%f0		! (0_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (0_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (2_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update39		! (2_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (0_0) res0_lo = x0 + x_hi0;
.cont39a:
	fmuld	%f32,%f48,%f10		! (4_1) dtmp0 = res0_hi * res0;
	sub	%l0,%o4,%g1		! (2_0) j0 = 0x7ff00000 - j0;
	nop
	fsubd	DTWO,%f50,%f20		! (6_1) dtmp0 = DTWO - dtmp0;
.cont39b:
	fmuld	%f22,%f16,%f16		! (5_1) dtmp2 = dd * dres;
	sllx	%g1,32,%g1		! (2_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp5]		! (2_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (0_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f48,%f36		! (4_1) dtmp1 = res0_lo * res0;
	nop
	nop
	fsubd	%f60,%f54,%f12		! (0_0) y_lo0 = y0 - y_hi0;
.cont40:
	fmuld	%f62,%f0,%f0		! (0_0) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp3],%f62	! (1_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f32		! (0_0) res0_hi += dtmp0;

	fsubd	DONE,%f10,%f60		! (4_1) dtmp0 = DONE - dtmp0;
	nop
	lda	[%i4]%asi,%f10		! (1_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f28,%f20,%f54		! (6_1) dd *= dtmp0;

	nop
	nop
	lda	[%i4+4]%asi,%f11	! (1_0) ((float*)&x0)[1] = ((float*)px)[1];
	bn,pn	%icc,.exit

	fmuld	%f50,%f12,%f28		! (0_0) dtmp1 *= y_lo0;
	nop
	lda	[%i3]%asi,%f12		! (1_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f16,%f16		! (5_1) dtmp2 = DTWO - dtmp2;

	add	%i1,stridex,%i4		! px += stridex
	nop
	lda	[%i3+4]%asi,%f13	! (1_0) ((float*)&y0)[1] = ((float*)py)[1];
	bn,pn	%icc,.exit

	fmuld	%f54,%f18,%f46		! (6_1) dtmp1 = dd * dres;
	add	%i4,stridex,%i1		! px += stridex
	ld	[%fp+ftmp0],%o2		! (7_1) iarr = ((int*)&dres)[0];
	fand	%f14,DA1,%f2		! (7_1) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (1_0) x0 *= scl0;
	nop
	ldd	[%fp+dtmp6],%f50	! (2_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f36,%f20		! (4_1) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (1_0) y0 *= scl0;
	sra	%o2,11,%i3		! (7_1) iarr >>= 11;
	nop
	faddd	%f0,%f28,%f36		! (0_0) res0_lo += dtmp1;

	and	%i3,0x1fc,%i3		! (7_1) iarr &= 0x1fc;
	nop
	bn,pn	%icc,.exit
	fmuld	%f22,%f16,%f28		! (5_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f16		! (3_1) res0 = sqrt ( res0 );
	add	%i3,TBL,%o4		! (7_1) (char*)dll1 + iarr
	lda	[%i4]0x82,%o1		! (3_0) hx0 = *(int*)px;
	fsubd	DTWO,%f46,%f62		! (6_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f26,%f52		! (4_1) dtmp0 *= dres;
	add	%i0,stridey,%i3		! py += stridey
	ld	[%o4],%f26		! (7_1) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (1_0) x_hi0 = x0 + D2ON36;

	nop
	add	%i3,stridey,%i0		! py += stridey
	lda	[%i3]0x82,%o4		! (3_0) hy0 = *(int*)py;
	faddd	%f60,D2ON36,%f12	! (1_0) y_hi0 = y0 + D2ON36;

	faddd	%f32,%f36,%f22		! (0_0) dres = res0_hi + res0_lo;
	and	%o1,_0x7fffffff,%o7	! (3_0) hx0 &= 0x7fffffff;
	st	%f22,[%fp+ftmp0]	! (0_0) iarr = ((int*)&dres)[0];
	fmuld	%f50,%f24,%f0		! (2_1) res0 = scl0 * res0;

	fmuld	%f54,%f62,%f24		! (6_1) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (3_0) hx0 ? 0x7ff00000
	st	%f0,[%i5]		! (2_1) ((float*)pz)[0] = ((float*)&res0)[0];
	fpsub32	%f26,%f2,%f26		! (7_1) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (3_0) hy0 &= 0x7fffffff;
	nop
	bge,pn	%icc,.update41		! (3_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f20	! (1_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (3_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (3_0) hy0 ? 0x7ff00000
	st	%f1,[%i5+4]		! (2_1) ((float*)pz)[1] = ((float*)&res0)[1];
	fsubd	%f12,D2ON36,%f54	! (1_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f14,%f50		! (7_1) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (3_0) j0 = diff0 >> 31;
	bge,pn	%icc,.update42		! (3_0) if ( hy0 >= 0x7ff00000 )
	faddd	%f48,%f52,%f52		! (4_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (3_0) j0 &= diff0;
	add	%i5,stridez,%i5		! pz += stridez
	stx	%g1,[%fp+dtmp6]		! (2_0) *(long long*)&scl0 = ll;
	fand	%f28,DA0,%f48		! (5_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (1_0) res0_hi = x_hi0 * x_hi0;
	cmp	%o7,_0x00100000		! (3_0) hx0 ? 0x00100000
	sub	%l7,%o1,%o4		! (3_0) j0 = hy0 - j0;
	fsubd	%f10,%f20,%f0		! (1_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (1_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (3_0) j0 &= 0x7ff00000;
	bl,pn	%icc,.update43		! (3_0) if ( hx0 < 0x00100000 )
	faddd	%f10,%f20,%f62		! (1_0) res0_lo = x0 + x_hi0;
.cont43a:
	fmuld	%f42,%f48,%f10		! (5_1) dtmp0 = res0_hi * res0;
	nop
	sub	%l0,%o4,%g1		! (3_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;
.cont43b:
	fmuld	%f24,%f18,%f18		! (6_1) dtmp2 = dd * dres;
	sllx	%g1,32,%g1		! (3_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp7]		! (3_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (1_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f48,%f34		! (5_1) dtmp1 = res0_lo * res0;
	nop
	nop
	fsubd	%f60,%f54,%f12		! (1_0) y_lo0 = y0 - y_hi0
.cont44:
	fmuld	%f62,%f0,%f0		! (1_0) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp5],%f62	! (2_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f42		! (1_0) res0_hi += dtmp0;

	fsubd	DONE,%f10,%f60		! (5_1) dtmp0 = DONE - dtmp0;
	nop
	lda	[%i2]%asi,%f10		! (2_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f26,%f20,%f54		! (7_1) dd *= dtmp0;

	nop
	nop
	lda	[%i2+4]%asi,%f11	! (2_0) ((float*)&x0)[1] = ((float*)px)[1];
	bn,pn	%icc,.exit

	fmuld	%f50,%f12,%f26		! (1_0) dtmp1 *= y_lo0;
	nop
	lda	[%o0]%asi,%f12		! (2_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f18,%f20		! (6_1) dtmp2 = DTWO - dtmp2;

	nop
	nop
	lda	[%o0+4]%asi,%f13	! (2_0) ((float*)&y0)[1] = ((float*)py)[1];
	bn,pn	%icc,.exit

	fmuld	%f54,%f14,%f50		! (7_1) dtmp1 = dd * dres;
	nop
	ld	[%fp+ftmp0],%o2		! (0_0) iarr = ((int*)&dres)[0];
	fand	%f22,DA1,%f2		! (0_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (2_0) x0 *= scl0;
	nop
	ldd	[%fp+dtmp8],%f18	! (3_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f34,%f46		! (5_1) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (2_0) y0 *= scl0;
	sra	%o2,11,%o4		! (0_0) iarr >>= 11;
	nop
	faddd	%f0,%f26,%f34		! (1_0) res0_lo += dtmp1;

	and	%o4,0x1fc,%o4		! (0_0) iarr &= 0x1fc;
	nop
	bn,pn	%icc,.exit
	fmuld	%f24,%f20,%f26		! (6_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f24		! (4_1) res0 = sqrt ( res0 );
	add	%o4,TBL,%o4		! (0_0) (char*)dll1 + iarr
	lda	[%i1]0x82,%o1		! (4_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f20		! (7_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f46,%f28,%f52		! (5_1) dtmp0 -= dtmp1;
	mov	%i1,%i2
	ld	[%o4],%f28		! (0_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (2_0) x_hi0 = x0 + D2ON36;

	nop
	mov	%i0,%o0
	lda	[%i0]0x82,%o4		! (4_0) hy0 = *(int*)py;
	faddd	%f60,D2ON36,%f50	! (2_0) y_hi0 = y0 + D2ON36;

	fmuld	%f18,%f16,%f0		! (3_1) res0 = scl0 * res0;
	nop
	and	%o1,_0x7fffffff,%o7	! (4_0) hx0 &= 0x7fffffff;
	faddd	%f42,%f34,%f18		! (1_0) dres = res0_hi + res0_lo;

	fmuld	%f54,%f20,%f16		! (7_1) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (4_0) hx0 ? 0x7ff00000
	st	%f18,[%fp+ftmp0]	! (1_0) iarr = ((int*)&dres)[0];
	fpsub32	%f28,%f2,%f28		! (0_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (4_0) hy0 &= 0x7fffffff;
	st	%f0,[%i5]		! (3_1) ((float*)pz)[0] = ((float*)&res0)[0];
	bge,pn	%icc,.update45		! (4_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f20	! (2_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (4_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (4_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update46		! (4_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f54	! (2_0) y_hi0 -= D2ON36;

	fmuld	%f28,%f22,%f50		! (0_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (4_0) j0 = diff0 >> 31;
	st	%f1,[%i5+4]		! (3_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (5_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (4_0) j0 &= diff0;
	cmp	%o7,_0x00100000		! (4_0) hx0 ? 0x00100000
	bl,pn	%icc,.update47		! (4_0) if ( hx0 < 0x00100000 )
	fand	%f26,DA0,%f48		! (6_1) res0 = vis_fand(dres,DA0);
.cont47a:
	fmuld	%f20,%f20,%f2		! (2_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (4_0) j0 = hy0 - j0;
	stx	%g1,[%fp+dtmp8]		! (3_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (2_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (2_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (4_0) j0 &= 0x7ff00000;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (2_0) res0_lo = x0 + x_hi0;

	fmuld	%f30,%f48,%f10		! (6_1) dtmp0 = res0_hi * res0;
	nop
	sub	%l0,%o4,%g1		! (4_0) j0 = 0x7ff00000 - j0;
	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;
.cont47b:
	fmuld	%f16,%f14,%f14		! (7_1) dtmp2 = dd * dres;
	sllx	%g1,32,%g1		! (4_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp9]		! (4_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (2_0) dtmp1 = y0 + y_hi0;

	fmuld	%f40,%f48,%f40		! (6_1) dtmp1 = res0_lo * res0;
	nop
	nop
	fsubd	%f60,%f54,%f12		! (2_0) y_lo0 = y0 - y_hi0;
.cont48:
	fmuld	%f62,%f0,%f0		! (2_0) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp7],%f62	! (3_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f30		! (2_0) res0_hi += dtmp0;

	fsubd	DONE,%f10,%f60		! (6_1) dtmp0 = DONE - dtmp0;
	nop
	lda	[%i4]%asi,%f10		! (3_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f28,%f20,%f54		! (0_0) dd *= dtmp0;

	nop
	nop
	lda	[%i4+4]%asi,%f11	! (3_0) ((float*)&x0)[1] = ((float*)px)[1];
	bn,pn	%icc,.exit

	fmuld	%f50,%f12,%f28		! (2_0) dtmp1 *= y_lo0;
	nop
	lda	[%i3]%asi,%f12		! (3_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f14,%f20		! (7_1) dtmp2 = DTWO - dtmp2;

	lda	[%i3+4]%asi,%f13	! (3_0) ((float*)&y0)[1] = ((float*)py)[1];
	add	%i1,stridex,%i4		! px += stridex
	nop
	bn,pn	%icc,.exit

	fmuld	%f54,%f22,%f50		! (0_0) dtmp1 = dd * dres;
	add	%i4,stridex,%i1		! px += stridex
	ld	[%fp+ftmp0],%o2		! (1_0) iarr = ((int*)&dres)[0];
	fand	%f18,DA1,%f2		! (1_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (3_0) x0 *= scl0;
	nop
	ldd	[%fp+dtmp10],%f14	! (4_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f40,%f46		! (6_1) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (3_0) y0 *= scl0;
	sra	%o2,11,%i3		! (1_0) iarr >>= 11;
	nop
	faddd	%f0,%f28,%f40		! (2_0) res0_lo += dtmp1;

	and	%i3,0x1fc,%i3		! (1_0) iarr &= 0x1fc;
	nop
	bn,pn	%icc,.exit
	fmuld	%f16,%f20,%f28		! (7_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f16		! (5_1) res0 = sqrt ( res0 );
	add	%i3,TBL,%o4		! (1_0) (char*)dll1 + iarr
	lda	[%i4]0x82,%o1		! (5_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f20		! (0_0) dtmp1 = DTWO - dtmp1;

	fmuld	%f46,%f26,%f52		! (6_1) dtmp0 *= dres;
	add	%i0,stridey,%i3		! py += stridey
	ld	[%o4],%f26		! (1_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (3_0) x_hi0 = x0 + D2ON36;

	nop
	add	%i3,stridey,%i0		! py += stridey
	lda	[%i3]0x82,%o4		! (5_0) hy0 = *(int*)py;
	faddd	%f60,D2ON36,%f50	! (3_0) y_hi0 = y0 + D2ON36;

	fmuld	%f14,%f24,%f0		! (4_1) res0 = scl0 * res0;
	and	%o1,_0x7fffffff,%o7	! (5_0) hx0 &= 0x7fffffff;
	nop
	faddd	%f30,%f40,%f14		! (2_0) dres = res0_hi + res0_lo;

	fmuld	%f54,%f20,%f24		! (0_0) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (5_0) hx0 ? 0x7ff00000
	st	%f14,[%fp+ftmp0]	! (2_0) iarr = ((int*)&dres)[0];
	fpsub32	%f26,%f2,%f26		! (1_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (5_0) hy0 &= 0x7fffffff;
	st	%f0,[%i5]		! (4_1) ((float*)pz)[0] = ((float*)&res0)[0];
	bge,pn	%icc,.update49		! (5_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f20	! (3_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (5_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (5_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update50		! (5_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f54	! (3_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f18,%f50		! (1_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (5_0) j0 = diff0 >> 31;
	st	%f1,[%i5+4]		! (4_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (6_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (5_0) j0 &= diff0;
	cmp	%o7,_0x00100000		! (5_0) hx0 ? 0x00100000
	bl,pn	%icc,.update51		! (5_0) if ( hx0 < 0x00100000 )
	fand	%f28,DA0,%f48		! (7_1) res0 = vis_fand(dres,DA0);
.cont51a:
	fmuld	%f20,%f20,%f2		! (3_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (5_0) j0 = hy0 - j0;
	stx	%g1,[%fp+dtmp10]	! (4_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (3_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (3_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (5_0) j0 &= 0x7ff00000;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (3_0) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	sub	%l0,%o4,%g1		! (5_0) j0 = 0x7ff00000 - j0;
	nop
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;
.cont51b:
	fmuld	%f24,%f22,%f22		! (0_0) dtmp2 = dd * dres;
	sllx	%g1,32,%g1		! (5_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp11]	! (5_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f50		! (3_0) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (7_1) dtmp1 = res0_lo * res0;
	nop
	nop
	fsubd	%f60,%f54,%f12		! (3_0) y_lo0 = y0 - y_hi0;
.cont52:
	fmuld	%f62,%f0,%f0		! (3_0) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp9],%f62	! (4_0) *(long long*)&scl0 = ll;
	faddd	%f2,%f46,%f44		! (3_0) res0_hi += dtmp0;

	fsubd	DONE,%f10,%f60		! (7_1) dtmp0 = DONE - dtmp0;
	nop
	lda	[%i2]%asi,%f10		! (4_0) ((float*)&x0)[0] = ((float*)px)[0];
	fmuld	%f26,%f20,%f54		! (1_0) dd *= dtmp0;

	nop
	nop
	lda	[%i2+4]%asi,%f11	! (4_0) ((float*)&x0)[1] = ((float*)px)[1];
	bn,pn	%icc,.exit

	fmuld	%f50,%f12,%f26		! (3_0) dtmp1 *= y_lo0;
	nop
	lda	[%o0]%asi,%f12		! (4_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f22,%f20		! (0_0) dtmp2 = DTWO - dtmp2;

	nop
	nop
	lda	[%o0+4]%asi,%f13	! (4_0) ((float*)&y0)[1] = ((float*)py)[1];
	bn,pn	%icc,.exit

	fmuld	%f54,%f18,%f50		! (1_0) dtmp1 = dd * dres;
	nop
	ld	[%fp+ftmp0],%o2		! (2_0) iarr = ((int*)&dres)[0];
	fand	%f14,DA1,%f2		! (2_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (4_0) x0 *= scl0;
	nop
	ldd	[%fp+dtmp12],%f22	! (5_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f38,%f46		! (7_1) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (4_0) y0 *= scl0;
	sra	%o2,11,%o4		! (2_0) iarr >>= 11;
	nop
	faddd	%f0,%f26,%f38		! (3_0) res0_lo += dtmp1;

	and	%o4,0x1fc,%o4		! (2_0) iarr &= 0x1fc;
	nop
	bn,pn	%icc,.exit
	fmuld	%f24,%f20,%f26		! (0_0) dres = dd * dtmp2;

	fsqrtd	%f52,%f24		! (6_1) res0 = sqrt ( res0 );
	add	%o4,TBL,%o4		! (2_0) (char*)dll1 + iarr
	lda	[%i1]0x82,%o1		! (6_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f52		! (1_0) dtmp1 = DTWO - dtmp1;

	fmuld	%f46,%f28,%f28		! (7_1) dtmp0 *= dres;
	mov	%i1,%i2
	ld	[%o4],%f20		! (2_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f10,D2ON36,%f46	! (4_0) x_hi0 = x0 + D2ON36;

	nop
	mov	%i0,%o0
	lda	[%i0]0x82,%o4		! (6_0) hy0 = *(int*)py;
	faddd	%f60,D2ON36,%f50	! (4_0) y_hi0 = y0 + D2ON36;

	fmuld	%f22,%f16,%f0		! (5_1) res0 = scl0 * res0;
	and	%o1,_0x7fffffff,%o7	! (6_0) hx0 &= 0x7fffffff;
	nop
	faddd	%f44,%f38,%f22		! (3_0) dres = res0_hi + res0_lo;

	fmuld	%f54,%f52,%f16		! (1_0) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (6_0) hx0 ? 0x7ff00000
	st	%f22,[%fp+ftmp0]	! (3_0) iarr = ((int*)&dres)[0];
	fpsub32	%f20,%f2,%f52		! (2_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (6_0) hy0 &= 0x7fffffff;
	st	%f0,[%i5]		! (5_1) ((float*)pz)[0] = ((float*)&res0)[0];
	bge,pn	%icc,.update53		! (6_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f46,D2ON36,%f46	! (4_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (6_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (6_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update54		! (6_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f54	! (4_0) y_hi0 -= D2ON36;

	fmuld	%f52,%f14,%f50		! (2_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (6_0) j0 = diff0 >> 31;
	st	%f1,[%i5+4]		! (5_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f28,%f48		! (7_1) res0 += dtmp0;

	and	%o1,%o3,%o1		! (6_0) j0 &= diff0;
	cmp	%o7,_0x00100000		! (6_0) hx0 ? 0x00100000
	bl,pn	%icc,.update55		! (6_0) if ( hx0 < 0x00100000 )
	fand	%f26,DA0,%f28		! (0_0) res0 = vis_fand(dres,DA0);
.cont55a:
	fmuld	%f46,%f46,%f0		! (4_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (6_0) j0 = hy0 - j0;
	stx	%g1,[%fp+dtmp12]	! (5_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f46,%f2		! (4_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f20		! (4_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (6_0) j0 &= 0x7ff00000;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f46,%f62		! (4_0) res0_lo = x0 + x_hi0;

	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	sub	%l0,%o4,%g1		! (6_0) j0 = 0x7ff00000 - j0;
	nop
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;
.cont55b:
	fmuld	%f32,%f28,%f50		! (0_0) dtmp0 = res0_hi * res0;
	sllx	%g1,32,%g1		! (6_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp13]	! (6_0) *(long long*)&scl0 = ll;
	faddd	%f60,%f54,%f46		! (4_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f28,%f36		! (0_0) dtmp1 = res0_lo * res0;
	nop
	nop
	fsubd	%f60,%f54,%f60		! (4_0) y_lo0 = y0 - y_hi0;
.cont56:
	fmuld	%f62,%f2,%f2		! (4_0) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp11],%f62	! (5_0) *(long long*)&scl0 = ll;
	faddd	%f0,%f20,%f32		! (4_0) res0_hi += dtmp0;

	lda	[%i4]%asi,%f0		! (5_0) ((float*)&x0)[0] = ((float*)px)[0];
	nop
	nop
	fmuld	%f52,%f10,%f10		! (2_0) dd *= dtmp0;

	lda	[%i4+4]%asi,%f1		! (5_0) ((float*)&x0)[1] = ((float*)px)[1];
	nop
	nop
	fsubd	DONE,%f50,%f52		! (0_0) dtmp0 = DONE - dtmp0;

	fmuld	%f46,%f60,%f46		! (4_0) dtmp1 *= y_lo0;
	nop
	lda	[%i3]%asi,%f12		! (5_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f18,%f18		! (1_0) dtmp2 = DTWO - dtmp2;

	nop
	add	%i1,stridex,%i4		! px += stridex
	lda	[%i3+4]%asi,%f13	! (5_0) ((float*)&y0)[1] = ((float*)py)[1];
	bn,pn	%icc,.exit

	fmuld	%f10,%f14,%f50		! (2_0) dtmp1 = dd * dres;
	add	%i4,stridex,%i1		! px += stridex
	ld	[%fp+ftmp0],%o2		! (3_0) iarr = ((int*)&dres)[0];
	fand	%f22,DA1,%f54		! (3_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f0,%f62,%f60		! (5_0) x0 *= scl0;
	nop
	ldd	[%fp+dtmp14],%f0	! (6_1) *(long long*)&scl0 = ll;
	fsubd	%f52,%f36,%f20		! (0_0) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f52		! (5_0) y0 *= scl0;
	sra	%o2,11,%i3		! (3_0) iarr >>= 11;
	nop
	faddd	%f2,%f46,%f36		! (4_0) res0_lo += dtmp1;

	and	%i3,0x1fc,%i3		! (3_0) iarr &= 0x1fc;
	nop
	bn,pn	%icc,.exit
	fmuld	%f16,%f18,%f16		! (1_0) dres = dd * dtmp2;

	fsqrtd	%f48,%f18		! (7_1) res0 = sqrt ( res0 );
	add	%i3,TBL,%o4		! (3_0) (char*)dll1 + iarr
	lda	[%i4]0x82,%o1		! (7_0) hx0 = *(int*)px;
	fsubd	DTWO,%f50,%f46		! (2_0) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f26,%f48		! (0_0) dtmp0 *= dres;
	add	%i0,stridey,%i3		! py += stridey
	ld	[%o4],%f20		! (3_0) dtmp0 = ((double*)((char*)dll1 + iarr))[0];
	faddd	%f60,D2ON36,%f50	! (5_0) x_hi0 = x0 + D2ON36;

	nop
	add	%i3,stridey,%i0		! py += stridey
	lda	[%i3]0x82,%o4		! (7_0) hy0 = *(int*)py;
	faddd	%f52,D2ON36,%f12	! (5_0) y_hi0 = y0 + D2ON36;

	fmuld	%f0,%f24,%f2		! (6_1) res0 = scl0 * res0;
	and	%o1,_0x7fffffff,%o7	! (7_0) hx0 &= 0x7fffffff;
	nop
	faddd	%f32,%f36,%f24		! (4_0) dres = res0_hi + res0_lo;

	fmuld	%f10,%f46,%f26		! (2_0) dd *= dtmp1;
	cmp	%o7,_0x7ff00000		! (7_0) hx0 ? 0x7ff00000
	st	%f24,[%fp+ftmp0]	! (4_0) iarr = ((int*)&dres)[0];
	fpsub32	%f20,%f54,%f10		! (3_0) dd = vis_fpsub32(dtmp0, dexp0);

	and	%o4,_0x7fffffff,%l7	! (7_0) hy0 &= 0x7fffffff;
	st	%f2,[%i5]		! (6_1) ((float*)pz)[0] = ((float*)&res0)[0];
	bge,pn	%icc,.update57		! (7_0) if ( hx0 >= 0x7ff00000 )
	fsubd	%f50,D2ON36,%f20	! (5_0) x_hi0 -= D2ON36;

	sub	%l7,%o7,%o1		! (7_0) diff0 = hy0 - hx0;
	cmp	%l7,_0x7ff00000		! (7_0) hy0 ? 0x7ff00000
	bge,pn	%icc,.update58		! (7_0) if ( hy0 >= 0x7ff00000 )
	fsubd	%f12,D2ON36,%f54	! (5_0) y_hi0 -= D2ON36;

	fmuld	%f10,%f22,%f50		! (3_0) dtmp0 = dd * dres;
	sra	%o1,31,%o3		! (7_0) j0 = diff0 >> 31;
	st	%f3,[%i5+4]		! (6_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f28,%f48,%f48		! (0_0) res0 += dtmp0;

	and	%o1,%o3,%o1		! (7_0) j0 &= diff0;
	cmp	%o7,_0x00100000		! (7_0) hx0 ? 0x00100000
	bl,pn	%icc,.update59		! (7_0) if ( hx0 < 0x00100000 )
	fand	%f16,DA0,%f28		! (1_0) res0 = vis_fand(dres,DA0);
.cont59a:
	fmuld	%f20,%f20,%f0		! (5_0) res0_hi = x_hi0 * x_hi0;
	sub	%l7,%o1,%o4		! (7_0) j0 = hy0 - j0;
	stx	%g1,[%fp+dtmp14]	! (6_0) *(long long*)&scl0 = ll;
	fsubd	%f60,%f20,%f2		! (5_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (5_0) dtmp0 = y_hi0 * y_hi0;
	and	%o4,%l0,%o4		! (7_0) j0 &= 0x7ff00000;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f60,%f20,%f62		! (5_0) res0_lo = x0 + x_hi0;

	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	sub	%l0,%o4,%g1		! (7_0) j0 = 0x7ff00000 - j0;
	nop
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;
.cont59b:
	fmuld	%f42,%f28,%f60		! (1_0) dtmp0 = res0_hi * res0;
	sllx	%g1,32,%g1		! (7_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp15]	! (7_0) *(long long*)&scl0 = ll;
	faddd	%f52,%f54,%f50		! (5_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f28,%f34		! (1_0) dtmp1 = res0_lo * res0;
	nop
	nop
	fsubd	%f52,%f54,%f54		! (5_0) y_lo0 = y0 - y_hi0;
.cont60:
	fmuld	%f62,%f2,%f2		! (5_0) res0_lo *= x_lo0;
	nop
	ldd	[%fp+dtmp13],%f62	! (6_0) *(long long*)&scl0 = ll;
	faddd	%f0,%f46,%f42		! (5_0) res0_hi += dtmp0;

	fmuld	%f10,%f20,%f52		! (3_0) dd *= dtmp0;
	nop
	lda	[%i2]%asi,%f10		! (6_0) ((float*)&x0)[0] = ((float*)px)[0];
	bn,pn	%icc,.exit

	lda	[%i2+4]%asi,%f11	! (6_0) ((float*)&x0)[1] = ((float*)px)[1];
	nop
	nop
	fsubd	DONE,%f60,%f60		! (1_0) dtmp0 = DONE - dtmp0;

	fmuld	%f50,%f54,%f46		! (5_0) dtmp1 *= y_lo0;
	nop
	lda	[%o0]%asi,%f12		! (6_0) ((float*)&y0)[0] = ((float*)py)[0];
	fsubd	DTWO,%f14,%f14		! (2_0) dtmp2 = DTWO - dtmp2;

	nop
	nop
	lda	[%o0+4]%asi,%f13	! (6_0) ((float*)&y0)[1] = ((float*)py)[1];
	bn,pn	%icc,.exit

	fmuld	%f52,%f22,%f50		! (3_0) dtmp1 = dd * dres;
	nop
	ld	[%fp+ftmp0],%o2		! (4_0) iarr = ((int*)&dres)[0];
	fand	%f24,DA1,%f54		! (4_0) dexp0 = vis_fand(dres,DA1);

	fmuld	%f10,%f62,%f10		! (6_0) x0 *= scl0;
	nop
	ldd	[%fp+dtmp0],%f0		! (7_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f34,%f20		! (1_0) dtmp0 -= dtmp1;

	fmuld	%f12,%f62,%f60		! (6_0) y0 *= scl0;
	sra	%o2,11,%o4		! (4_0) iarr >>= 11;
	nop
	faddd	%f2,%f46,%f34		! (5_0) res0_lo += dtmp1;

	and	%o4,0x1fc,%o4		! (4_0) iarr &= 0x1fc;
	subcc	counter,8,counter	! counter -= 8;
	bpos,pt	%icc,.main_loop
	fmuld	%f26,%f14,%f26		! (2_0) dres = dd * dtmp2;

	add	counter,8,counter

.tail:
	subcc	counter,1,counter
	bneg	.begin
	nop

	fsqrtd	%f48,%f14		! (0_1) res0 = sqrt ( res0 );
	add	%o4,TBL,%o4		! (4_1) (char*)dll1 + iarr
	fsubd	DTWO,%f50,%f46		! (3_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f16,%f48		! (1_1) dtmp0 *= dres;
	ld	[%o4],%f20		! (4_1) dtmp0 = ((double*)((char*)dll1 + iarr))[0];

	fmuld	%f0,%f18,%f0		! (7_2) res0 = scl0 * res0;
	st	%f0,[%i5]		! (7_2) ((float*)pz)[0] = ((float*)&res0)[0];
	faddd	%f42,%f34,%f16		! (5_1) dres = res0_hi + res0_lo;

	subcc	counter,1,counter
	st	%f1,[%i5+4]		! (7_2) ((float*)pz)[1] = ((float*)&res0)[1];
	bneg	.begin
	add	%i5,stridez,%i5		! pz += stridez

	fmuld	%f52,%f46,%f18		! (3_1) dd *= dtmp1;
	st	%f16,[%fp+ftmp0]	! (5_1) iarr = ((int*)&dres)[0];
	fpsub32	%f20,%f54,%f54		! (4_1) dd = vis_fpsub32(dtmp0, dexp0);

	fmuld	%f54,%f24,%f50		! (4_1) dtmp0 = dd * dres;
	faddd	%f28,%f48,%f52		! (1_1) res0 += dtmp0;


	fand	%f26,DA0,%f48		! (2_1) res0 = vis_fand(dres,DA0);

	fmuld	%f18,%f22,%f22		! (3_1) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f20		! (4_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f30,%f48,%f12		! (2_1) dtmp0 = res0_hi * res0;

	fmuld	%f40,%f48,%f40		! (2_1) dtmp1 = res0_lo * res0;

	fmuld	%f54,%f20,%f54		! (4_1) dd *= dtmp0;

	fsubd	DONE,%f12,%f60		! (2_1) dtmp0 = DONE - dtmp0;

	fsubd	DTWO,%f22,%f22		! (3_1) dtmp2 = DTWO - dtmp2;

	fmuld	%f54,%f24,%f50		! (4_1) dtmp1 = dd * dres;
	ld	[%fp+ftmp0],%o2		! (5_1) iarr = ((int*)&dres)[0];
	fand	%f16,DA1,%f2		! (5_1) dexp0 = vis_fand(dres,DA1);

	ldd	[%fp+dtmp2],%f0		! (0_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f40,%f20		! (2_1) dtmp0 -= dtmp1;

	sra	%o2,11,%i3		! (5_1) iarr >>= 11;

	and	%i3,0x1fc,%i3		! (5_1) iarr &= 0x1fc;
	fmuld	%f18,%f22,%f28		! (3_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f22		! (1_1) res0 = sqrt ( res0 );
	add	%i3,TBL,%g1		! (5_1) (char*)dll1 + iarr
	fsubd	DTWO,%f50,%f62		! (4_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f26,%f52		! (2_1) dtmp0 *= dres;
	ld	[%g1],%f26		! (5_1) dtmp0 = ((double*)((char*)dll1 + iarr))[0];

	fmuld	%f0,%f14,%f0		! (0_1) res0 = scl0 * res0;

	fmuld	%f54,%f62,%f14		! (4_1) dd *= dtmp1;
	fpsub32	%f26,%f2,%f26		! (5_1) dd = vis_fpsub32(dtmp0, dexp0);

	st	%f0,[%i5]		! (0_1) ((float*)pz)[0] = ((float*)&res0)[0];

	fmuld	%f26,%f16,%f50		! (5_1) dtmp0 = dd * dres;
	st	%f1,[%i5+4]		! (0_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (2_1) res0 += dtmp0;

	subcc	counter,1,counter
	bneg	.begin
	add	%i5,stridez,%i5		! pz += stridez

	fand	%f28,DA0,%f48		! (3_1) res0 = vis_fand(dres,DA0);

	fmuld	%f44,%f48,%f10		! (3_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (5_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f14,%f24,%f24		! (4_1) dtmp2 = dd * dres;

	fmuld	%f38,%f48,%f38		! (3_1) dtmp1 = res0_lo * res0;

	fsubd	DONE,%f10,%f60		! (3_1) dtmp0 = DONE - dtmp0;
	fmuld	%f26,%f20,%f54		! (5_1) dd *= dtmp0;

	fsubd	DTWO,%f24,%f24		! (4_1) dtmp2 = DTWO - dtmp2;

	fmuld	%f54,%f16,%f46		! (5_1) dtmp1 = dd * dres;

	ldd	[%fp+dtmp4],%f50	! (1_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f38,%f20		! (3_1) dtmp0 -= dtmp1;

	fmuld	%f14,%f24,%f26		! (4_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f24		! (2_1) res0 = sqrt ( res0 );
	fsubd	DTWO,%f46,%f62		! (5_1) dtmp1 = DTWO - dtmp1;

	fmuld	%f20,%f28,%f52		! (3_1) dtmp0 *= dres;

	fmuld	%f50,%f22,%f0		! (1_1) res0 = scl0 * res0;

	fmuld	%f54,%f62,%f22		! (5_1) dd *= dtmp1;

	st	%f0,[%i5]		! (1_1) ((float*)pz)[0] = ((float*)&res0)[0];

	subcc	counter,1,counter
	st	%f1,[%i5+4]		! (1_1) ((float*)pz)[1] = ((float*)&res0)[1];
	bneg	.begin
	add	%i5,stridez,%i5		! pz += stridez

	faddd	%f48,%f52,%f52		! (3_1) res0 += dtmp0;

	fand	%f26,DA0,%f48		! (4_1) res0 = vis_fand(dres,DA0);

	fmuld	%f32,%f48,%f10		! (4_1) dtmp0 = res0_hi * res0;

	fmuld	%f22,%f16,%f16		! (5_1) dtmp2 = dd * dres;

	fmuld	%f36,%f48,%f36		! (4_1) dtmp1 = res0_lo * res0;

	fsubd	DONE,%f10,%f60		! (4_1) dtmp0 = DONE - dtmp0;

	fsubd	DTWO,%f16,%f16		! (5_1) dtmp2 = DTWO - dtmp2;

	ldd	[%fp+dtmp6],%f50	! (2_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f36,%f20		! (4_1) dtmp0 -= dtmp1;

	fmuld	%f22,%f16,%f28		! (5_1) dres = dd * dtmp2;

	fsqrtd	%f52,%f16		! (3_1) res0 = sqrt ( res0 );

	fmuld	%f20,%f26,%f52		! (4_1) dtmp0 *= dres;

	fmuld	%f50,%f24,%f0		! (2_1) res0 = scl0 * res0;

	st	%f0,[%i5]		! (2_1) ((float*)pz)[0] = ((float*)&res0)[0];

	st	%f1,[%i5+4]		! (2_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (4_1) res0 += dtmp0;

	subcc	counter,1,counter
	bneg	.begin
	add	%i5,stridez,%i5		! pz += stridez

	fand	%f28,DA0,%f48		! (5_1) res0 = vis_fand(dres,DA0);

	fmuld	%f42,%f48,%f10		! (5_1) dtmp0 = res0_hi * res0;

	fmuld	%f34,%f48,%f34		! (5_1) dtmp1 = res0_lo * res0;

	fsubd	DONE,%f10,%f60		! (5_1) dtmp0 = DONE - dtmp0;

	ldd	[%fp+dtmp8],%f18	! (3_1) *(long long*)&scl0 = ll;
	fsubd	%f60,%f34,%f46		! (5_1) dtmp0 -= dtmp1;

	fsqrtd	%f52,%f24		! (4_1) res0 = sqrt ( res0 );

	fmuld	%f46,%f28,%f52		! (5_1) dtmp0 -= dtmp1;

	fmuld	%f18,%f16,%f0		! (3_1) res0 = scl0 * res0;
	st	%f0,[%i5]		! (3_1) ((float*)pz)[0] = ((float*)&res0)[0];
	st	%f1,[%i5+4]		! (3_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (5_1) res0 += dtmp0;

	subcc	counter,1,counter
	bneg	.begin
	add	%i5,stridez,%i5		! pz += stridez

	ldd	[%fp+dtmp10],%f14	! (4_1) *(long long*)&scl0 = ll;

	fsqrtd	%f52,%f16		! (5_1) res0 = sqrt ( res0 );

	fmuld	%f14,%f24,%f0		! (4_1) res0 = scl0 * res0
	st	%f0,[%i5]		! (4_1) ((float*)pz)[0] = ((float*)&res0)[0];
	st	%f1,[%i5+4]		! (4_1) ((float*)pz)[1] = ((float*)&res0)[1];

	subcc	counter,1,counter
	bneg	.begin
	add	%i5,stridez,%i5		! pz += stridez

	ldd	[%fp+dtmp12],%f22	! (5_1) *(long long*)&scl0 = ll;

	fmuld	%f22,%f16,%f0		! (5_1) res0 = scl0 * res0;
	st	%f0,[%i5]		! (5_1) ((float*)pz)[0] = ((float*)&res0)[0];
	st	%f1,[%i5+4]		! (5_1) ((float*)pz)[1] = ((float*)&res0)[1];

	ba	.begin
	add	%i5,stridez,%i5

	.align	16
.spec0:
	cmp	%o7,_0x7ff00000		! hx0 ? 0x7ff00000
	bne	1f			! if ( hx0 != 0x7ff00000 )
	ld	[%i4+4],%i2		! lx = ((int*)px)[1];

	cmp	%i2,0			! lx ? 0
	be	3f			! if ( lx == 0 )
	nop
1:
	cmp	%l7,_0x7ff00000		! hy0 ? 0x7ff00000
	bne	2f			! if ( hy0 != 0x7ff00000 )
	ld	[%i3+4],%o2		! ly = ((int*)py)[1];

	cmp	%o2,0			! ly ? 0
	be	3f			! if ( ly == 0 )
2:
	ld	[%i4],%f0		! ((float*)&x0)[0] = ((float*)px)[0];
	ld	[%i4+4],%f1		! ((float*)&x0)[1] = ((float*)px)[1];

	ld	[%i3],%f2		! ((float*)&y0)[0] = ((float*)py)[0];
	add	%i4,stridex,%i4		! px += stridex
	ld	[%i3+4],%f3		! ((float*)&y0)[1] = ((float*)py)[1];

	fabsd	%f0,%f0

	fabsd	%f2,%f2

	fmuld	%f0,%f2,%f0		! res0 = fabs(x0) * fabs(y0);
	add	%i3,stridey,%i3		! py += stridey;
	st	%f0,[%i5]		! ((float*)pz)[0] = ((float*)&res0)[0];

	st	%f1,[%i5+4]		! ((float*)pz)[1] = ((float*)&res0)[1];
	add	%i5,stridez,%i5		! pz += stridez
	ba	.begin1
	sub	counter,1,counter
3:
	add	%i4,stridex,%i4		! px += stridex
	add	%i3,stridey,%i3		! py += stridey
	st	%g0,[%i5]		! ((int*)pz)[0] = 0;

	add	%i5,stridez,%i5		! pz += stridez;
	st	%g0,[%i5+4]		! ((int*)pz)[1] = 0;
	ba	.begin1
	sub	counter,1,counter

	.align	16
.spec1:
	and	%o1,%o3,%o1		! (7_0) j0 &= diff0;

	cmp	%l7,_0x00100000		! (7_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont_spec0	! (7_0) if ( hy0 < 0x00100000 )

	ld	[%i4+4],%i2		! lx = ((int*)px)[1];
	or	%o7,%l7,%g5		! ii = hx0 | hy0;
	fzero	%f0

	ld	[%i3+4],%o2		! ly = ((int*)py)[1];
	or	%i2,%g5,%g5		! ii |= lx;

	orcc	%o2,%g5,%g5		! ii |= ly;
	bnz,a,pn	%icc,1f		! if ( ii != 0 )
	sethi	%hi(0x00080000),%i2

	fdivd	DONE,%f0,%f0		! res0 = 1.0 / 0.0;

	st	%f0,[%i5]		! ((float*)pz)[0] = ((float*)&res0)[0];

	add	%i4,stridex,%i4		! px += stridex;
	add	%i3,stridey,%i3		! py += stridey;
	st	%f1,[%i5+4]		! ((float*)pz)[1] = ((float*)&res0)[1];

	add	%i5,stridez,%i5		! pz += stridez;
	ba	.begin1
	sub	counter,1,counter
1:
	ld	[%i4],%f0		! ((float*)&x0)[0] = ((float*)px)[0];

	ld	[%i4+4],%f1		! ((float*)&x0)[1] = ((float*)px)[1];

	ld	[%i3],%f2		! ((float*)&y0)[0] = ((float*)py)[0];

	fabsd	%f0,%f0			! x0 = fabs(x0);
	ld	[%i3+4],%f3		! ((float*)&y0)[1] = ((float*)py)[1];

	ldd	[TBL+TBL_SHIFT+64],%f12	! ((long long*)&dtmp0)[0] = 0x0007ffffffffffffULL;
	add	%fp,dtmp2,%i4
	add	%fp,dtmp3,%i3

	fabsd	%f2,%f2			! y0 = fabs(y0);
	ldd	[TBL+TBL_SHIFT+56],%f10	! D2ON51

	ldx	[TBL+TBL_SHIFT+48],%g5	! D2ONM52
	cmp	%o7,%i2			! hx0 ? 0x00080000
	bl,a	1f			! if ( hx0 < 0x00080000 )
	fxtod	%f0,%f0			! x0 = *(long long*)&x0;

	fand	%f0,%f12,%f0		! x0 = vis_fand(x0, dtmp0);
	fxtod	%f0,%f0			! x0 = *(long long*)&x0;
	faddd	%f0,%f10,%f0		! x0 += D2ON51;
1:
	std	%f0,[%i4]

	ldx	[TBL+TBL_SHIFT+40],%g1	! D2ON1022
	cmp	%l7,%i2			! hy0 ? 0x00080000
	bl,a	1f			! if ( hy0 < 0x00080000 )
	fxtod	%f2,%f2			! y0 = *(long long*)&y0;

	fand	%f2,%f12,%f2		! y0 = vis_fand(y0, dtmp0);
	fxtod	%f2,%f2			! y0 = *(long long*)&y0;
	faddd	%f2,%f10,%f2		! y0 += D2ON51;
1:
	std	%f2,[%i3]

	stx	%g5,[%fp+dtmp15]	! D2ONM52

	ba	.cont_spec1
	stx	%g1,[%fp+dtmp0]		! D2ON1022

	.align	16
.update0:
	cmp	counter,1
	ble	1f
	nop

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	1,counter
1:
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i2
	ba	.cont1
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update1:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont0		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,1
	ble,a	1f
	nop

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	1,counter
	stx	%o0,[%fp+tmp_py]
1:
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i2
	ba	.cont1
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update2:
	cmp	counter,2
	ble	1f
	nop

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	2,counter
1:
	fsubd	%f50,D2ON36,%f54	! (7_1) y_hi0 -= D2ON36;

	fmuld	%f20,%f20,%f2		! (7_1) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (7_1) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (7_1) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (7_1) res0_lo = x0 + x_hi0;

	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i4
	ba	.cont4
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update3:
	cmp	counter,2
	ble	1f
	nop

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	2,counter
1:
	fmuld	%f20,%f20,%f2		! (7_1) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (7_1) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (7_1) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (7_1) res0_lo = x0 + x_hi0;

	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i4
	ba	.cont4
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update4:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,a,pn	%icc,.cont4	! (0_0) if ( hy0 < 0x00100000 )
	sub	%l0,%o4,%o4		! (1_0) j0 = 0x7ff00000 - j0;

	cmp	counter,2
	ble,a	1f
	nop

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	2,counter
	stx	%i3,[%fp+tmp_py]
1:
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i4
	ba	.cont4
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update5:
	cmp	counter,3
	ble	1f
	nop

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	3,counter
1:
	st	%f14,[%fp+ftmp0]	! (7_1) iarr = ((int*)&dres)[0];
	fsubd	%f46,D2ON36,%f20	! (0_0) x_hi0 -= D2ON36;

	fsubd	%f12,D2ON36,%f54	! (0_0) y_hi0 -= D2ON36;

	fmuld	%f20,%f20,%f2		! (0_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (0_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (0_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (0_0) res0_lo = x0 + x_hi0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2

	sllx	%g1,32,%g1
	ba	.cont8
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update6:
	cmp	counter,3
	ble	1f
	nop

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	3,counter
1:
	fmuld	%f20,%f20,%f2		! (0_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (0_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (0_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (0_0) res0_lo = x0 + x_hi0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2

	sllx	%g1,32,%g1
	ba	.cont8
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update7:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont7		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,3
	ble,a	1f
	nop

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	3,counter
	stx	%o0,[%fp+tmp_py]
1:
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2

	sllx	%g1,32,%g1
	ba	.cont8
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update9:
	cmp	counter,4
	ble	1f
	nop

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	4,counter
1:
	st	%f22,[%fp+ftmp0]	! (0_0) iarr = ((int*)&dres)[0];
	fsubd	%f46,D2ON36,%f20	! (1_0) x_hi0 -= D2ON36;

	fsubd	%f12,D2ON36,%f54	! (1_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f14,%f50		! (7_1) dtmp0 = dd * dres;


	fmuld	%f20,%f20,%f2		! (1_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (1_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (1_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (1_0) res0_lo = x0 + x_hi0;

	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	ba	.cont12
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update10:
	cmp	counter,4
	ble	1f
	nop

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	4,counter
1:
	fmuld	%f26,%f14,%f50		! (7_1) dtmp0 = dd * dres;


	fmuld	%f20,%f20,%f2		! (1_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (1_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (1_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (1_0) res0_lo = x0 + x_hi0;

	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	ba	.cont12
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update11:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont11		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,4
	ble,a	1f
	nop

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	4,counter
	stx	%i3,[%fp+tmp_py]
1:
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4

	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;
	ba	.cont12
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update13:
	cmp	counter,5
	ble	1f
	nop

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	5,counter
1:
	fsubd	%f46,D2ON36,%f20	! (2_0) x_hi0 -= D2ON36;

	fsubd	%f50,D2ON36,%f54	! (2_0) y_hi0 -= D2ON36;

	fmuld	%f28,%f22,%f50		! (0_0) dtmp0 = dd * dres;

	fmuld	%f20,%f20,%f2		! (2_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (2_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (2_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (2_0) res0_lo = x0 + x_hi0;

	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	ba	.cont16
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update14:
	cmp	counter,5
	ble	1f
	nop

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	5,counter
1:
	fmuld	%f28,%f22,%f50		! (0_0) dtmp0 = dd * dres;

	fmuld	%f20,%f20,%f2		! (2_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (2_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (2_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (2_0) res0_lo = x0 + x_hi0;

	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	ba	.cont16
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update15:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont15		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,5
	ble,a	1f
	nop

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	5,counter
	stx	%o0,[%fp+tmp_py]
1:
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2

	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;
	ba	.cont16
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update17:
	cmp	counter,6
	ble	1f
	nop

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	6,counter
1:
	fsubd	%f50,D2ON36,%f54	! (3_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f18,%f50		! (1_0) dtmp0 = dd * dres;

	fand	%f28,DA0,%f48		! (7_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (3_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (3_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (3_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (3_0) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f24,%f22,%f22		! (0_0) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (3_0) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (7_1) dtmp1 = res0_lo * res0;
	fsubd	%f60,%f54,%f12		! (3_0) y_lo0 = y0 - y_hi0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4

	sllx	%g1,32,%g1		! (5_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp11]	! (5_0) *(long long*)&scl0 = ll;
	ba	.cont20
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update18:
	cmp	counter,6
	ble	1f
	nop

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	6,counter
1:
	fmuld	%f26,%f18,%f50		! (1_0) dtmp0 = dd * dres;

	fand	%f28,DA0,%f48		! (7_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (3_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (3_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (3_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (3_0) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f24,%f22,%f22		! (0_0) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (3_0) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (7_1) dtmp1 = res0_lo * res0;
	fsubd	%f60,%f54,%f12		! (3_0) y_lo0 = y0 - y_hi0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4

	sllx	%g1,32,%g1		! (5_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp11]	! (5_0) *(long long*)&scl0 = ll;
	ba	.cont20
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update19:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont19a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,6
	ble,a	1f
	nop

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	6,counter
	stx	%i3,[%fp+tmp_py]
1:
	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;

	ba	.cont19b
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update21:
	cmp	counter,7
	ble	1f
	nop

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	7,counter
1:
	fsubd	%f50,D2ON36,%f54	! (4_0) y_hi0 -= D2ON36;

	fmuld	%f52,%f14,%f50		! (2_0) dtmp0 = dd * dres;
	faddd	%f48,%f28,%f48		! (7_1) res0 += dtmp0;

	fand	%f26,DA0,%f28		! (0_0) res0 = vis_fand(dres,DA0);

	fmuld	%f46,%f46,%f0		! (4_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f46,%f2		! (4_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f20		! (4_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f46,%f62		! (4_0) res0_lo = x0 + x_hi0;

	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f32,%f28,%f50		! (0_0) dtmp0 = res0_hi * res0;
	faddd	%f60,%f54,%f46		! (4_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f28,%f36		! (0_0) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f60		! (4_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (6_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp13]	! (6_0) *(long long*)&scl0 = ll;
	ba	.cont24
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update22:
	cmp	counter,7
	ble	1f
	nop

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	7,counter
1:
	fmuld	%f52,%f14,%f50		! (2_0) dtmp0 = dd * dres;
	faddd	%f48,%f28,%f48		! (7_1) res0 += dtmp0;

	fand	%f26,DA0,%f28		! (0_0) res0 = vis_fand(dres,DA0);

	fmuld	%f46,%f46,%f0		! (4_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f46,%f2		! (4_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f20		! (4_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f46,%f62		! (4_0) res0_lo = x0 + x_hi0;

	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f32,%f28,%f50		! (0_0) dtmp0 = res0_hi * res0;
	faddd	%f60,%f54,%f46		! (4_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f28,%f36		! (0_0) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f60		! (4_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (6_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp13]	! (6_0) *(long long*)&scl0 = ll;
	ba	.cont24
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update23:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont23a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,7
	ble,a	1f
	nop

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	7,counter
	stx	%o0,[%fp+tmp_py]
1:
	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;

	ba	.cont23b
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update25:
	cmp	counter,8
	ble	1f
	nop

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	8,counter
1:
	fsubd	%f12,D2ON36,%f54	! (5_0) y_hi0 -= D2ON36;

	fmuld	%f10,%f22,%f50		! (3_0) dtmp0 = dd * dres;
	faddd	%f28,%f48,%f48		! (0_0) res0 += dtmp0;

	fand	%f16,DA0,%f28		! (1_0) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f0		! (5_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f60,%f20,%f2		! (5_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (5_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f60,%f20,%f62		! (5_0) res0_lo = x0 + x_hi0;

	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f42,%f28,%f60		! (1_0) dtmp0 = res0_hi * res0;
	faddd	%f52,%f54,%f50		! (5_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f28,%f34		! (1_0) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f52,%f54,%f54		! (5_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (7_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp15]	! (7_0) *(long long*)&scl0 = ll;
	ba	.cont28
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update26:
	cmp	counter,8
	ble	1f
	nop

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	8,counter
1:
	fmuld	%f10,%f22,%f50		! (3_0) dtmp0 = dd * dres;
	faddd	%f28,%f48,%f48		! (0_0) res0 += dtmp0;

	fand	%f16,DA0,%f28		! (1_0) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f0		! (5_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f60,%f20,%f2		! (5_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (5_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f60,%f20,%f62		! (5_0) res0_lo = x0 + x_hi0;

	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f42,%f28,%f60		! (1_0) dtmp0 = res0_hi * res0;
	faddd	%f52,%f54,%f50		! (5_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f28,%f34		! (1_0) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f52,%f54,%f54		! (5_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (7_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp15]	! (7_0) *(long long*)&scl0 = ll;
	ba	.cont28
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update27:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont27a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,8
	ble,a	1f
	nop

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	8,counter
	stx	%i3,[%fp+tmp_py]
1:
	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;

	ba	.cont27b
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update29:
	cmp	counter,1
	ble	1f
	nop

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	1,counter
1:
	fsubd	%f2,D2ON36,%f2		! (6_1) y_hi0 -= D2ON36;

	fmuld	%f54,%f24,%f50		! (4_1) dtmp0 = dd * dres;
	stx	%g1,[%fp+dtmp0]		! (7_1) *(long long*)&scl0 = ll;
	faddd	%f28,%f48,%f52		! (1_1) res0 += dtmp0;

	fand	%f26,DA0,%f48		! (2_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f0		! (6_1) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f28		! (6_1) x_lo0 = x0 - x_hi0;

	fmuld	%f2,%f2,%f46		! (6_1) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (6_1) res0_lo = x0 + x_hi0;

	fmuld	%f18,%f22,%f22		! (3_1) dtmp2 = dd * dres;
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	DTWO,%f50,%f20		! (4_1) dtmp0 = DTWO - dtmp0;

	ba	.cont32
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update30:
	cmp	counter,1
	ble	1f
	nop

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	1,counter
1:
	fmuld	%f54,%f24,%f50		! (4_1) dtmp0 = dd * dres;
	stx	%g1,[%fp+dtmp0]		! (7_1) *(long long*)&scl0 = ll;
	faddd	%f28,%f48,%f52		! (1_1) res0 += dtmp0;

	fand	%f26,DA0,%f48		! (2_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f0		! (6_1) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f28		! (6_1) x_lo0 = x0 - x_hi0;

	fmuld	%f2,%f2,%f46		! (6_1) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (6_1) res0_lo = x0 + x_hi0;

	fmuld	%f18,%f22,%f22		! (3_1) dtmp2 = dd * dres;
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	DTWO,%f50,%f20		! (4_1) dtmp0 = DTWO - dtmp0;

	ba	.cont32
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update31:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont31		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,1
	ble,a	1f
	nop

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	1,counter
	stx	%o0,[%fp+tmp_py]
1:
	fmuld	%f20,%f20,%f0		! (6_1) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f28		! (6_1) x_lo0 = x0 - x_hi0;

	fmuld	%f2,%f2,%f46		! (6_1) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (6_1) res0_lo = x0 + x_hi0;

	fmuld	%f18,%f22,%f22		! (3_1) dtmp2 = dd * dres;
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	DTWO,%f50,%f20		! (4_1) dtmp0 = DTWO - dtmp0;

	ba	.cont32
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update33:
	cmp	counter,2
	ble	1f
	nop

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	2,counter
1:
	st	%f1,[%i5+4]		! (0_1) ((float*)pz)[1] = ((float*)&res0)[1];
	fsubd	%f50,D2ON36,%f54	! (7_1) y_hi0 -= D2ON36;

	fmuld	%f26,%f16,%f50		! (5_1) dtmp0 = dd * dres;
	faddd	%f48,%f52,%f52		! (2_1) res0 += dtmp0;

	add	%i5,stridez,%i5		! pz += stridez
	stx	%o4,[%fp+dtmp2]		! (0_0) *(long long*)&scl0 = ll;
	fand	%f28,DA0,%f48		! (3_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (7_1) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (7_1) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (7_1) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (7_1) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (3_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (5_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f14,%f24,%f24		! (4_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (7_1) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (3_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f60,%f54,%f12		! (7_1) y_lo0 = y0 - y_hi0;

	sllx	%o4,32,%o4		! (1_0) ll = (long long)j0 << 32;
	stx	%o4,[%fp+dtmp3]		! (1_0) *(long long*)&scl0 = ll;
	ba	.cont36
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update34:
	cmp	counter,2
	ble	1f
	nop

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	2,counter
1:
	add	%i5,stridez,%i5		! pz += stridez
	stx	%o4,[%fp+dtmp2]		! (0_0) *(long long*)&scl0 = ll;
	fand	%f28,DA0,%f48		! (3_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (7_1) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (7_1) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (7_1) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (7_1) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (3_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (5_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f14,%f24,%f24		! (4_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (7_1) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (3_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f60,%f54,%f12		! (7_1) y_lo0 = y0 - y_hi0;

	sllx	%o4,32,%o4		! (1_0) ll = (long long)j0 << 32;
	stx	%o4,[%fp+dtmp3]		! (1_0) *(long long*)&scl0 = ll;
	ba	.cont36
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update35:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont35a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,2
	ble,a	1f
	nop

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	2,counter
	stx	%i3,[%fp+tmp_py]
1:
	fmuld	%f44,%f48,%f10		! (3_1) dtmp0 = res0_hi * res0;
	sethi	%hi(0x3ff00000),%o4
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	DTWO,%f50,%f20		! (5_1) dtmp0 = DTWO - dtmp0;

	ba	.cont35b
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update37:
	cmp	counter,3
	ble	1f
	nop

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	3,counter
1:
	st	%f1,[%i5+4]		! (1_1) ((float*)pz)[1] = ((float*)&res0)[1];
	fsubd	%f12,D2ON36,%f54	! (0_0) y_hi0 -= D2ON36;

	fmuld	%f28,%f18,%f50		! (6_1) dtmp0 = dd * dres;
	faddd	%f48,%f52,%f52		! (3_1) res0 += dtmp0;

	add	%i5,stridez,%i5		! pz += stridez
	stx	%o4,[%fp+dtmp4]		! (1_0) *(long long*)&scl0 = ll;
	fand	%f26,DA0,%f48		! (4_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (0_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (0_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (0_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (0_0) res0_lo = x0 + x_hi0;

	fmuld	%f32,%f48,%f10		! (4_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (6_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f22,%f16,%f16		! (5_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (0_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f48,%f36		! (4_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f12		! (0_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (2_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp5]		! (2_0) *(long long*)&scl0 = ll;
	ba	.cont40
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update38:
	cmp	counter,3
	ble	1f
	nop

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	3,counter
1:
	add	%i5,stridez,%i5		! pz += stridez
	stx	%o4,[%fp+dtmp4]		! (1_0) *(long long*)&scl0 = ll;
	fand	%f26,DA0,%f48		! (4_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (0_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (0_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (0_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (0_0) res0_lo = x0 + x_hi0;

	fmuld	%f32,%f48,%f10		! (4_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (6_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f22,%f16,%f16		! (5_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (0_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f48,%f36		! (4_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f12		! (0_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (2_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp5]		! (2_0) *(long long*)&scl0 = ll;
	ba	.cont40
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update39:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont39a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,3
	ble,a	1f
	nop

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	3,counter
	stx	%o0,[%fp+tmp_py]
1:
	fmuld	%f32,%f48,%f10		! (4_1) dtmp0 = res0_hi * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	DTWO,%f50,%f20		! (6_1) dtmp0 = DTWO - dtmp0;

	ba	.cont39b
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update41:
	cmp	counter,4
	ble	1f
	nop

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	4,counter
1:
	st	%f1,[%i5+4]		! (2_1) ((float*)pz)[1] = ((float*)&res0)[1];
	fsubd	%f12,D2ON36,%f54	! (1_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f14,%f50		! (7_1) dtmp0 = dd * dres;
	faddd	%f48,%f52,%f52		! (4_1) res0 += dtmp0;

	add	%i5,stridez,%i5		! pz += stridez
	stx	%g1,[%fp+dtmp6]		! (2_0) *(long long*)&scl0 = ll;
	fand	%f28,DA0,%f48		! (5_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (1_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (1_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (1_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (1_0) res0_lo = x0 + x_hi0;

	fmuld	%f42,%f48,%f10		! (5_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f24,%f18,%f18		! (6_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (1_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f48,%f34		! (5_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f60,%f54,%f12		! (1_0) y_lo0 = y0 - y_hi0

	sllx	%g1,32,%g1		! (3_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp7]		! (3_0) *(long long*)&scl0 = ll;
	ba	.cont44
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update42:
	cmp	counter,4
	ble	1f
	nop

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	4,counter
1:
	add	%i5,stridez,%i5		! pz += stridez
	stx	%g1,[%fp+dtmp6]		! (2_0) *(long long*)&scl0 = ll;
	fand	%f28,DA0,%f48		! (5_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (1_0) res0_hi = x_hi0 * x_hi0;
	fsubd	%f10,%f20,%f0		! (1_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (1_0) dtmp0 = y_hi0 * y_hi0;
	faddd	%f10,%f20,%f62		! (1_0) res0_lo = x0 + x_hi0;

	fmuld	%f42,%f48,%f10		! (5_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;

	fmuld	%f24,%f18,%f18		! (6_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (1_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f48,%f34		! (5_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f60,%f54,%f12		! (1_0) y_lo0 = y0 - y_hi0

	sllx	%g1,32,%g1		! (3_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp7]		! (3_0) *(long long*)&scl0 = ll;
	ba	.cont44
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update43:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont43a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,4
	ble,a	1f
	nop

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	4,counter
	stx	%i3,[%fp+tmp_py]
1:
	fmuld	%f42,%f48,%f10		! (5_1) dtmp0 = res0_hi * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	DTWO,%f50,%f20		! (7_1) dtmp0 = DTWO - dtmp0;

	ba	.cont43b
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update45:
	cmp	counter,5
	ble	1f
	nop

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	5,counter
1:
	fsubd	%f50,D2ON36,%f54	! (2_0) y_hi0 -= D2ON36;

	fmuld	%f28,%f22,%f50		! (0_0) dtmp0 = dd * dres;
	st	%f1,[%i5+4]		! (3_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (5_1) res0 += dtmp0;

	fand	%f26,DA0,%f48		! (6_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (2_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp8]		! (3_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (2_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (2_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (2_0) res0_lo = x0 + x_hi0;

	fmuld	%f30,%f48,%f10		! (6_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f16,%f14,%f14		! (7_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (2_0) dtmp1 = y0 + y_hi0;

	fmuld	%f40,%f48,%f40		! (6_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f12		! (2_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (4_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp9]		! (4_0) *(long long*)&scl0 = ll;
	ba	.cont48
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update46:
	cmp	counter,5
	ble	1f
	nop

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	5,counter
1:
	fmuld	%f28,%f22,%f50		! (0_0) dtmp0 = dd * dres;
	st	%f1,[%i5+4]		! (3_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (5_1) res0 += dtmp0;

	fand	%f26,DA0,%f48		! (6_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (2_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp8]		! (3_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (2_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (2_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (2_0) res0_lo = x0 + x_hi0;

	fmuld	%f30,%f48,%f10		! (6_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f16,%f14,%f14		! (7_1) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (2_0) dtmp1 = y0 + y_hi0;

	fmuld	%f40,%f48,%f40		! (6_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f12		! (2_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (4_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp9]		! (4_0) *(long long*)&scl0 = ll;
	ba	.cont48
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update47:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont47a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,5
	ble,a	1f
	nop

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	5,counter
	stx	%o0,[%fp+tmp_py]
1:
	fmuld	%f20,%f20,%f2		! (2_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp8]		! (3_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (2_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (2_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (2_0) res0_lo = x0 + x_hi0;

	fmuld	%f30,%f48,%f10		! (6_1) dtmp0 = res0_hi * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	DTWO,%f50,%f20		! (0_0) dtmp0 = DTWO - dtmp0;

	ba	.cont47b
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update49:
	cmp	counter,6
	ble	1f
	nop

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	6,counter
1:
	fsubd	%f50,D2ON36,%f54	! (3_0) y_hi0 -= D2ON36;

	fmuld	%f26,%f18,%f50		! (1_0) dtmp0 = dd * dres;
	st	%f1,[%i5+4]		! (4_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (6_1) res0 += dtmp0;

	fand	%f28,DA0,%f48		! (7_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (3_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp10]	! (4_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (3_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (3_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (3_0) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f24,%f22,%f22		! (0_0) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (3_0) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (7_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f60,%f54,%f12		! (3_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (5_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp11]	! (5_0) *(long long*)&scl0 = ll;
	ba	.cont52
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update50:
	cmp	counter,6
	ble	1f
	nop

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	6,counter
1:
	fmuld	%f26,%f18,%f50		! (1_0) dtmp0 = dd * dres;
	st	%f1,[%i5+4]		! (4_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f52,%f52		! (6_1) res0 += dtmp0;

	fand	%f28,DA0,%f48		! (7_1) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f2		! (3_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp10]	! (4_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (3_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (3_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (3_0) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f24,%f22,%f22		! (0_0) dtmp2 = dd * dres;
	faddd	%f60,%f54,%f50		! (3_0) dtmp1 = y0 + y_hi0;

	fmuld	%f38,%f48,%f38		! (7_1) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	%f60,%f54,%f12		! (3_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (5_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp11]	! (5_0) *(long long*)&scl0 = ll;
	ba	.cont52
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update51:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont51a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,6
	ble,a	1f
	nop

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	6,counter
	stx	%i3,[%fp+tmp_py]
1:
	fmuld	%f20,%f20,%f2		! (3_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp10]	! (4_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f20,%f0		! (3_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (3_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f20,%f62		! (3_0) res0_lo = x0 + x_hi0;

	fmuld	%f44,%f48,%f10		! (7_1) dtmp0 = res0_hi * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	DTWO,%f50,%f20		! (1_0) dtmp0 = DTWO - dtmp0;

	ba	.cont51b
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update53:
	cmp	counter,7
	ble	1f
	nop

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	7,counter
1:
	fsubd	%f50,D2ON36,%f54	! (4_0) y_hi0 -= D2ON36;

	fmuld	%f52,%f14,%f50		! (2_0) dtmp0 = dd * dres;
	st	%f1,[%i5+4]		! (5_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f28,%f48		! (7_1) res0 += dtmp0;

	fand	%f26,DA0,%f28		! (0_0) res0 = vis_fand(dres,DA0);

	fmuld	%f46,%f46,%f0		! (4_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp12]	! (5_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f46,%f2		! (4_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f20		! (4_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f46,%f62		! (4_0) res0_lo = x0 + x_hi0;

	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f32,%f28,%f50		! (0_0) dtmp0 = res0_hi * res0;
	faddd	%f60,%f54,%f46		! (4_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f28,%f36		! (0_0) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f60		! (4_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (6_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp13]	! (6_0) *(long long*)&scl0 = ll;
	ba	.cont56
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update54:
	cmp	counter,7
	ble	1f
	nop

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	stx	%o0,[%fp+tmp_py]

	mov	7,counter
1:
	fmuld	%f52,%f14,%f50		! (2_0) dtmp0 = dd * dres;
	st	%f1,[%i5+4]		! (5_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f48,%f28,%f48		! (7_1) res0 += dtmp0;

	fand	%f26,DA0,%f28		! (0_0) res0 = vis_fand(dres,DA0);

	fmuld	%f46,%f46,%f0		! (4_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp12]	! (5_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f46,%f2		! (4_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f20		! (4_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f46,%f62		! (4_0) res0_lo = x0 + x_hi0;

	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f32,%f28,%f50		! (0_0) dtmp0 = res0_hi * res0;
	faddd	%f60,%f54,%f46		! (4_0) dtmp1 = y0 + y_hi0;

	fmuld	%f36,%f28,%f36		! (0_0) dtmp1 = res0_lo * res0;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	%f60,%f54,%f60		! (4_0) y_lo0 = y0 - y_hi0;

	sllx	%g1,32,%g1		! (6_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp13]	! (6_0) *(long long*)&scl0 = ll;
	ba	.cont56
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update55:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont55a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,7
	ble,a	1f
	nop

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]

	mov	7,counter
	stx	%o0,[%fp+tmp_py]
1:
	fmuld	%f46,%f46,%f0		! (4_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp12]	! (5_0) *(long long*)&scl0 = ll;
	fsubd	%f10,%f46,%f2		! (4_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f20		! (4_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f10,%f46,%f62		! (4_0) res0_lo = x0 + x_hi0;

	fmuld	%f16,%f18,%f18		! (1_0) dtmp2 = dd * dres;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i2
	fsubd	DTWO,%f50,%f10		! (2_0) dtmp0 = DTWO - dtmp0;

	ba	.cont55b
	add	TBL,TBL_SHIFT+24,%o0

	.align	16
.update57:
	cmp	counter,8
	ble	1f
	nop

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	8,counter
1:
	fsubd	%f12,D2ON36,%f54	! (5_0) y_hi0 -= D2ON36;

	fmuld	%f10,%f22,%f50		! (3_0) dtmp0 = dd * dres;
	st	%f3,[%i5+4]		! (6_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f28,%f48,%f48		! (0_0) res0 += dtmp0;

	fand	%f16,DA0,%f28		! (1_0) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f0		! (5_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp14]	! (6_0) *(long long*)&scl0 = ll;
	fsubd	%f60,%f20,%f2		! (5_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (5_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f60,%f20,%f62		! (5_0) res0_lo = x0 + x_hi0;

	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f42,%f28,%f60		! (1_0) dtmp0 = res0_hi * res0;
	faddd	%f52,%f54,%f50		! (5_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f28,%f34		! (1_0) dtmp1 = res0_lo * res0;
	fsubd	%f52,%f54,%f54		! (5_0) y_lo0 = y0 - y_hi0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4

	sllx	%g1,32,%g1		! (7_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp15]	! (7_0) *(long long*)&scl0 = ll;
	ba	.cont60
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update58:
	cmp	counter,8
	ble	1f
	nop

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	mov	8,counter
1:
	fmuld	%f10,%f22,%f50		! (3_0) dtmp0 = dd * dres;
	st	%f3,[%i5+4]		! (6_1) ((float*)pz)[1] = ((float*)&res0)[1];
	faddd	%f28,%f48,%f48		! (0_0) res0 += dtmp0;

	fand	%f16,DA0,%f28		! (1_0) res0 = vis_fand(dres,DA0);

	fmuld	%f20,%f20,%f0		! (5_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp14]	! (6_0) *(long long*)&scl0 = ll;
	fsubd	%f60,%f20,%f2		! (5_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (5_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f60,%f20,%f62		! (5_0) res0_lo = x0 + x_hi0;

	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;

	fmuld	%f42,%f28,%f60		! (1_0) dtmp0 = res0_hi * res0;
	faddd	%f52,%f54,%f50		! (5_0) dtmp1 = y0 + y_hi0;

	fmuld	%f34,%f28,%f34		! (1_0) dtmp1 = res0_lo * res0;
	fsubd	%f52,%f54,%f54		! (5_0) y_lo0 = y0 - y_hi0;

	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4

	sllx	%g1,32,%g1		! (7_0) ll = (long long)j0 << 32;
	stx	%g1,[%fp+dtmp15]	! (7_0) *(long long*)&scl0 = ll;
	ba	.cont60
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.update59:
	cmp	%l7,_0x00100000		! (0_0) hy0 ? 0x00100000
	bge,pn	%icc,.cont59a		! (0_0) if ( hy0 < 0x00100000 )

	cmp	counter,8
	ble,a	1f
	nop

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	mov	8,counter
	stx	%i3,[%fp+tmp_py]
1:
	fmuld	%f20,%f20,%f0		! (5_0) res0_hi = x_hi0 * x_hi0;
	stx	%g1,[%fp+dtmp14]	! (6_0) *(long long*)&scl0 = ll;
	fsubd	%f60,%f20,%f2		! (5_0) x_lo0 = x0 - x_hi0;

	fmuld	%f54,%f54,%f46		! (5_0) dtmp0 = y_hi0 * y_hi0;
	add	%i5,stridez,%i5		! pz += stridez
	faddd	%f60,%f20,%f62		! (5_0) res0_lo = x0 + x_hi0;

	fmuld	%f26,%f14,%f14		! (2_0) dtmp2 = dd * dres;
	sethi	%hi(0x3ff00000),%g1
	add	TBL,TBL_SHIFT+24,%i4
	fsubd	DTWO,%f50,%f20		! (3_0) dtmp0 = DTWO - dtmp0;

	ba	.cont59b
	add	TBL,TBL_SHIFT+24,%i3

	.align	16
.exit:
	ret
	restore
	SET_SIZE(__vrhypot)

