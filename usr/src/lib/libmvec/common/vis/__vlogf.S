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

	.file	"__vlogf.S"

#include "libm.h"

	RO_DATA
	.align	64
!! CONST_TBL[2*i]   = 127*log(2) - log(1+i/32), i = [0, 32]
!! CONST_TBL[2*i+1] = 2**(-23)/(1+i/32),        i = [0, 32]

.CONST_TBL:
	.word  	0x405601e6, 	0x78fc457b, 	0x3e800000, 	0x00000000,
	.word  	0x4055ffee, 	0x4f4b5df8,	0x3e7f07c1,	0xf07c1f08,
	.word	0x4055fe05,	0x32e4434f,	0x3e7e1e1e,	0x1e1e1e1e,
	.word	0x4055fc2a,	0x44598c21,	0x3e7d41d4,	0x1d41d41d,
	.word	0x4055fa5c,	0xb720babf,	0x3e7c71c7,	0x1c71c71c,
	.word	0x4055f89b,	0xcf803581,	0x3e7bacf9,	0x14c1bad0,
	.word	0x4055f6e6,	0xe0c3f1b1,	0x3e7af286,	0xbca1af28,
	.word	0x4055f53d,	0x4badcb50,	0x3e7a41a4,	0x1a41a41a,
	.word	0x4055f39e,	0x7d18782e,	0x3e799999,	0x9999999a,
	.word	0x4055f209,	0xecc5965c,	0x3e78f9c1,	0x8f9c18fa,
	.word	0x4055f07f,	0x1c5099d5,	0x3e786186,	0x18618618,
	.word	0x4055eefd,	0x9641645e,	0x3e77d05f,	0x417d05f4,
	.word	0x4055ed84,	0xed3a291d,	0x3e7745d1,	0x745d1746,
	.word	0x4055ec14,	0xbb3ced72,	0x3e76c16c,	0x16c16c17,
	.word	0x4055eaac,	0xa10589ab,	0x3e7642c8,	0x590b2164,
	.word	0x4055e94c,	0x45758439,	0x3e75c988,	0x2b931057,
	.word	0x4055e7f3,	0x550f85e3,	0x3e755555,	0x55555555,
	.word	0x4055e6a1,	0x818078ec,	0x3e74e5e0,	0xa72f0539,
	.word	0x4055e556,	0x8134aae1,	0x3e747ae1,	0x47ae147b,
	.word	0x4055e412,	0x0ef783b7,	0x3e741414,	0x14141414,
	.word	0x4055e2d3,	0xe99c9674,	0x3e73b13b,	0x13b13b14,
	.word	0x4055e19b,	0xd3b0f9d9,	0x3e73521c,	0xfb2b78c1,
	.word	0x4055e069,	0x9333fb26,	0x3e72f684,	0xbda12f68,
	.word	0x4055df3c,	0xf1565bd0,	0x3e729e41,	0x29e4129e,
	.word	0x4055de15,	0xba3f64fa,	0x3e724924,	0x92492492,
	.word	0x4055dcf3,	0xbcd73219,	0x3e71f704,	0x7dc11f70,
	.word	0x4055dbd6,	0xca95a75a,	0x3e71a7b9,	0x611a7b96,
	.word	0x4055dabe,	0xb7559927,	0x3e715b1e,	0x5f75270d,
	.word	0x4055d9ab,	0x592bb896,	0x3e711111,	0x11111111,
	.word	0x4055d89c,	0x8840e4fe,	0x3e70c971,	0x4fbcda3b,
	.word	0x4055d792,	0x1eaf8df0,	0x3e708421,	0x08421084,
	.word	0x4055d68b,	0xf863da3d,	0x3e704104,	0x10410410,
	.word	0x4055d589,	0xf2fe5107,	0x3e700000,	0x00000000,
	.word	0xbfcffb16,	0xbfa3db6e,	! K3 = -2.49850123953105416108e-01
	.word	0x3fd5561b,	0xa4b3110b,	! K2 =  3.33380614127478394992e-01
	.word	0xbfe00000,	0x0b666d0b,	! K1 = -5.00000021234343492201e-01
	.word	0x3fefffff,	0xff3fd118,	! K0 =  9.99999998601683029714e-01
	.word	0x3fe62e42,	0xfefa39ef,	! LN2 = 6.931471805599452862e-01
	.word	0xbf800000,	0x7f800000,	! MONE = -1.0f ;    INF

! local storage indices
#define tmp0		STACK_BIAS-0x8
#define tmp1		STACK_BIAS-0x10
#define tmp2		STACK_BIAS-0x18
#define tmp3		STACK_BIAS-0x20
#define tmp4		STACK_BIAS-0x28
#define tmp5		STACK_BIAS-0x30
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x30

#define ZERO		%f28
#define K3		%f30
#define K2		%f32
#define K1		%f34
#define K0		%f36
#define LN2		%f38

#define stridex		%o0
#define stridex2	%o1
#define stridey		%o2
#define x0		%o3
#define x1		%o4
#define y		%o5

#define ind0		%i0
#define ind1		%i1
#define ind2		%i2
#define ind3		%i3
#define MASK_0x007fffff	%i4
#define MASK_0xfffc0000	%i5
#define CONST_0x20000	%o7
#define MASK_0x7f800000	%l3

#define ival0		%l0
#define iy0		%l1
#define ival1		%l2
#define iy1		%l1
#define ival2		%l4
#define iy2		%l5
#define ival3		%l6
#define iy3		%l2
#define counter		%l7

#define LOGFTBL		%g5
#define LOGFTBL_P8	%g1

! register use

! i0  ind0
! i1  ind1
! i2  ind2
! i3  ind3
! i4  0x007fffff
! i5  0xfffc0000

! l0  ival0
! l1  iy0, iy1
! l2  ival1, iy3
! l3  0x7f800000
! l4  ival2
! l5  iy2
! l6  ival3
! l7  cycle counter

! o0  stridex
! o1  stridex * 2
! o2  stridey
! o3  x
! o4  x
! o5  y
! o7  0x20000

! g1  CONST_TBL
! g5  CONST_TBL + 8

! f2
! f4
! f6
! f8
! f9
! f10
! f12
! f14
! f16
! f18
! f19
! f20
! f22
! f24
! f26
! f28 ZERO = 0
! f30 K3 = -2.49850123953105416108e-01
! f32 K2 =  3.33380614127478394992e-01
! f34 K1 = -5.00000021234343492201e-01
! f36 K0 =  9.99999998601683029714e-01
! f38 LN2 = 6.931471805599452862e-01
! f40
! f42
! f44
! f46
! f48
! f50
! f52
! f54
! f56
! f58
! f60
! f62


!  !!!!!  Algorithm   !!!!!
!
!  double exp, ty, yy, ldtmp0, ldtmp1;
!  double dtmp0, dtmp1, dtmp2, dtmp3, dtmp4, dtmp5;
!  float  value;
!  int    ival, iy, i, ind, iexp;
!  double K3   = -2.49850123953105416108e-01;
!  double K2   =  3.33380614127478394992e-01;
!  double K1   = -5.00000021234343492201e-01;
!  double K0   =  9.99999998601683029714e-01;
!  double LN2  =  6.931471805599452862e-01;
!  double ZERO =  0;
!  float  INF;
!
!  ival = *(int*)(x);
!  if (ival >= 0x7f800000) goto spec;
!  if (ival <= 0x7fffff) goto spec;
!  *(float*)&*(float*)&exp = *(float*)(x);
!  exp = vis_fpack32(ZERO, exp);
!  iy = ival & 0x007fffff;
!  ival = iy + 0x20000;
!  ival = ival & 0xfffc0000;
!  i  = ival >> 14;
!  ind  = i & (-8);
!  iy = iy - ival;
!  ty = LN2 * (double)(*(int*)&exp);
!  ldtmp0 = *(double*)((char*)CONST_TBL+ind);
!  ldtmp1 = *(double*)((char*)CONST_TBL+ind+8);
!  ty = ty - ldtmp0;
!  yy = (double) iy;
!  yy = yy * ldtmp1;
!  dtmp0 = K3 * yy;
!  dtmp1 = dtmp0 + K2;
!  dtmp2 = dtmp1 * yy;
!  dtmp3 = dtmp2 + K1;
!  dtmp4 = dtmp3 * yy;
!  dtmp5 = dtmp4 + K0;
!  yy    = dtmp5 * yy;
!  yy    = yy + ty;
!  y[0] = (float)(yy);
!  return;
!
!spec:
!  if ((ival & 0x7fffffff) >= 0x7f800000) { /* X = NaN or Inf */
!    value = *(float*) &ival;
!    y[0] = (value < 0.0f? 0.0f : value) * value;
!    return;
!  } else if (ival <= 0) {
!    y[0] = ((ival & 0x7fffffff) == 0) ?
!      -1.0f / 0f. : 0f. /0f.;      /* X = +-0 : X < 0 */
!    return;
!  } else { /* Denom. number */
!    value = (float) ival;
!    ival = *(int*) &value;
!    iexp = (ival >> 23) - 149;
!    iy = ival & 0x007fffff;
!    ival = iy + 0x20000;
!    ival = ival & 0xfffc0000;
!    i  = ival >> 14;
!    ind  = i & (-8);
!    iy = iy - ival;
!    ty = LN2 * (double)iexp;
!    ldtmp0 = *(double*)((char*)CONST_TBL+ind);
!    ldtmp1 = *(double*)((char*)CONST_TBL+ind+8);
!    ty = ty - ldtmp0;
!    yy = (double) iy;
!    yy = yy * ldtmp1;
!    dtmp0 = K3 * yy;
!    dtmp1 = dtmp0 + K2;
!    dtmp2 = dtmp1 * yy;
!    dtmp3 = dtmp2 + K1;
!    dtmp4 = dtmp3 * yy;
!    dtmp5 = dtmp4 + K0;
!    yy    = dtmp5 * yy;
!    yy    = yy + ty;
!    y[0] = (float)(yy);
!    return;
!  }
!--------------------------------------------------------------------

	ENTRY(__vlogf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,g5)
	wr	%g0,0,%gsr

	st	%i0,[%fp+tmp0]
	stx	%i1,[%fp+tmp5]

	sra	%i2,0,%l4
	ldd	[LOGFTBL+528],K3
	add	%i3,0,y
	sllx	%l4,2,stridex
	sllx	%l4,3,stridex2
	ldd	[LOGFTBL+536],K2
	sra	%i4,0,%l3
	ldd	[LOGFTBL+544],K1
	sllx	%l3,2,stridey
	sethi	%hi(0x7ffc00),MASK_0x007fffff
	add	MASK_0x007fffff,1023,MASK_0x007fffff
	ldd	[LOGFTBL+552],K0
	sethi	%hi(0xfffc0000),MASK_0xfffc0000
	ldd	[LOGFTBL+560],LN2
	sethi	%hi(0x20000),CONST_0x20000
	fzero	ZERO
	sethi	%hi(0x7f800000),MASK_0x7f800000
	sub	y,stridey,y

.begin:
	ld	[%fp+tmp0],counter
	ldx	[%fp+tmp5],x0
	st	%g0,[%fp+tmp0]
.begin1:
	add	x0,stridex2,x1! x += 2*stridex
	subcc	counter,1,counter
	bneg,pn	%icc,.end
	lda	[x0]0x82,ival0			! (Y0_0) ival = *(int*)(x)

	add	LOGFTBL,8,LOGFTBL_P8
	lda	[stridex+x0]0x82,ival1		! (Y1_0) ival = *(int*)(x)

	cmp	ival0,MASK_0x7f800000		! (Y0_0) if (ival >= 0x7f800000)
	lda	[x1]0x82,ival2			! (Y2_0) ival = *(int*)(x);

	bge,pn	%icc,.spec			! (Y0_0) if (ival >= 0x7f800000)
	nop

	cmp	ival0,MASK_0x007fffff		! (Y0_0) if (ival <= 0x7fffff)
	ble,pn	%icc,.spec			! (Y0_0) if (ival <= 0x7fffff)
	nop

	cmp	ival1,MASK_0x7f800000		! (Y1_0) if (ival >= 0x7f800000)
	and	ival0,MASK_0x007fffff,iy0	! (Y0_0) iy = ival & 0x007fffff


	add	iy0,CONST_0x20000,ival0		! (Y0_0) ival = iy + 0x20000

	and	ival0,MASK_0xfffc0000,ival0	! (Y0_0) ival = ival & 0xfffc0000
	bge,pn	%icc,.update2			! (Y1_0) if (ival >= 0x7f800000)
	nop
.cont2:
	sub	iy0,ival0,iy0			! (Y0_0) iy = iy - ival
	cmp	ival1,MASK_0x007fffff		! (Y1_0) if (ival <= 0x7fffff)
	lda	[stridex+x1]0x82,ival3		! (Y3_0) ival = *(int*)(x)

	st	iy0,[%fp+tmp1]			! (Y0_0) (double) iy
	ble,pn	%icc,.update3			! (Y1_0) if (ival <= 0x7fffff)
	nop
.cont3:
	cmp	ival2,MASK_0x7f800000		! (Y2_0) if (ival >= 0x7f800000)
	and	ival1,MASK_0x007fffff,iy1	! (Y1_0) iy = ival & 0x007fffff
	bge,pn	%icc,.update4			! (Y2_0) if (ival >= 0x7f800000)
	nop
.cont4:
	cmp	ival2,MASK_0x007fffff		! (Y2_0) if (ival <= 0x7fffff)
	ble,pn	%icc,.update5			! (Y2_0) if (ival <= 0x7fffff)
	nop
.cont5:
	add	iy1,CONST_0x20000,ival1		! (Y1_0) ival = iy + 0x20000
	and	ival2,MASK_0x007fffff,iy2	! (Y2_0) iy = ival & 0x007fffff

	and	ival1,MASK_0xfffc0000,ival1	! (Y1_0) ival = ival & 0xfffc0000
	add	iy2,CONST_0x20000,ival2		! (Y2_0) ival = iy + 0x20000

	sub	iy1,ival1,iy1			! (Y1_0) iy = iy - ival
	and	ival2,MASK_0xfffc0000,ival2	! (Y2_0) ival = ival & 0xfffc0000

	cmp	ival3,MASK_0x7f800000		! (Y3_0) (ival >= 0x7f800000)
	sub	iy2,ival2,iy2			! (Y2_0) iy = iy - ival
	st 	iy1,[%fp+tmp3]			! (Y1_0) (double) iy

	st	iy2,[%fp+tmp2]			! (Y2_0) (double) iy
	bge,pn	%icc,.update6			! (Y3_0) (ival >= 0x7f800000)
	nop
.cont6:
	cmp	ival3,MASK_0x007fffff		! (Y3_0) if (ival <= 0x7fffff)
	ld	[%fp+tmp1],%f2			! (Y0_0) (double) iy
	ble,pn	%icc,.update7			! (Y3_0) if (ival <= 0x7fffff)
	sra	ival0,14,ival0			! (Y0_0) i  = ival >> 14;
.cont7:
	sra	ival1,14,ind1			! (Y1_0) i  = ival >> 14;
	ld	[%fp+tmp3],%f4			! (Y1_0) (double) iy

	sra	ival2,14,ival2			! (Y2_0) i  = ival >> 14;
	and	ival0,-8,ind0			! (Y0_0) ind  = i & (-8)
	lda	[x0]0x82,%f6			! (Y0_0) *(float*)&exp = *(float*)(x)

	and	ind1,-8,ind1			! (Y1_0) ind  = i & (-8)
	ldd	[LOGFTBL_P8+ind0],%f14		! (Y0_0) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fitod	%f2,%f48			! (Y0_0) yy = (double) iy

	and	ival3,MASK_0x007fffff,iy3	! (Y3_0) iy = ival & 0x007fffff
	lda	[stridex+x0]0x82,%f8		! (Y1_0) *(float*)&exp = *(float*)(x)

	add	iy3,CONST_0x20000,ival3		! (Y3_0) iy + 0x20000
	ldd	[LOGFTBL_P8+ind1],%f16		! (Y1_0) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fitod	%f4,%f26			! (Y1_0) yy = (double) iy

	sub	y,stridey,y			! y += stridey
	and	ival3,MASK_0xfffc0000,ival3	! (Y3_0) ival = ival & 0xfffc0000
	lda	[x1]0x82,%f10			! (Y2_0) *(float*)&exp = *(float*)(x)

	add	x1,stridex2,x0			! x += 2*stridex
	sub	iy3,ival3,iy3			! (Y3_0) iy = iy - ival
	ld	[%fp+tmp2],%f2			! (Y2_0) (double) iy
	fmuld	%f48,%f14,%f46			! (Y0_0) yy = yy * ldtmp1

	lda	[stridex+x1]0x82,%f12		! (Y3_0) *(float*)&exp = *(float*)(x)
	fmuld	%f26,%f16,%f62			! (Y1_0) yy = yy * ldtmp1

	sra	ival3,14,ival3			! (Y3_0) i  = ival >> 14;
	lda	[x0]0x82,ival0			! (Y0_1) ival = *(int*)(x)

	add	x0,stridex2,x1			! x += 2*stridex
	st	iy3,[%fp+tmp3]			! (Y3_0) (double) iy
	fmuld	K3,%f46,%f22			! (Y0_0) dtmp0 = K3 * yy

	and	ival2,-8,ind2			! (Y2_0) ind  = i & (-8)
	lda	[stridex+x0]0x82,ival1		! (Y1_1) ival = *(int*)(x)

	cmp	ival0,MASK_0x7f800000		! (Y0_1) if (ival >= 0x7f800000)
	lda	[x1]0x82,ival2			! (Y2_1) ival = *(int*)(x);
	fmuld	K3,%f62,%f50			! (Y1_0) dtmp0 = K3 * yy

	bge,pn  %icc,.update8			! (Y0_1) if (ival >= 0x7f800000)
	nop
.cont8:
	cmp	ival0,MASK_0x007fffff		! (Y0_1) if (ival <= 0x7fffff)
	ble,pn	%icc,.update9			! (Y0_1) if (ival <= 0x7fffff)
	faddd	%f22,K2,%f48			! (Y0_0) dtmp1 = dtmp0 + K2

.cont9:
	cmp	ival1,MASK_0x7f800000		! (Y1_1) if (ival >= 0x7f800000)
	and	ival0,MASK_0x007fffff,iy0	! (Y0_1) iy = ival & 0x007fffff

	add	iy0,CONST_0x20000,ival0		! (Y0_1) ival = iy + 0x20000
	ldd	[LOGFTBL_P8+ind2],%f14		! (Y2_0) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8);
	fpack32	ZERO,%f6,%f6			! (Y0_0) exp = vis_fpack32(ZERO, exp)

	and	ival0,MASK_0xfffc0000,ival0	! (Y0_1) ival = ival & 0xfffc0000
	faddd	%f50,K2,%f26			! (Y1_0) dtmp1 = dtmp0 + K2
	bge,pn	%icc,.update10			! (Y1_1) if (ival >= 0x7f800000)
	nop
.cont10:
	sub	iy0,ival0,iy0			! (Y0_1) iy = iy - ival
	and	ival3,-8,ind3			! (Y3_0) ind  = i & (-8)
	ld	[%fp+tmp3],%f4			! (Y3_0) (double) iy

	cmp	ival1,MASK_0x007fffff		! (Y1_1) if (ival <= 0x7fffff)
	lda	[stridex+x1]0x82,ival3		! (Y3_1) ival = *(int*)(x)
	fmuld	%f48,%f46,%f50			! (Y0_0) dtmp2 = dtmp1 * yy
	fitod	%f2,%f48			! (Y2_0) yy = (double) iy

	st	iy0,[%fp+tmp1]			! (Y0_1) (double) iy
	ble,pn	%icc,.update11			! (Y1_1) if (ival <= 0x7fffff)
	nop
.cont11:
	cmp	ival2,MASK_0x7f800000		! (Y2_1) if (ival >= 0x7f800000)
	and	ival1,MASK_0x007fffff,iy1	! (Y1_1) iy = ival & 0x007fffff
	bge,pn	%icc,.update12			! (Y2_1) if (ival >= 0x7f800000)
	fmuld	%f26,%f62,%f42			! (Y1_0) dtmp2 = dtmp1 * yy
.cont12:
	cmp	ival2,MASK_0x007fffff		! (Y2_1) if (ival <= 0x7fffff)
	ldd	[LOGFTBL_P8+ind3],%f16		! (Y3_0) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	ble,pn 	%icc,.update13			! (Y2_1) if (ival <= 0x7fffff)
	fitod	%f4,%f26			! (Y3_0) yy = (double) iy
.cont13:
	add	iy1,CONST_0x20000,ival1		! (Y1_1) ival = iy + 0x20000
	and	ival2,MASK_0x007fffff,iy2	! (Y2_1) iy = ival & 0x007fffff

	and	ival1,MASK_0xfffc0000,ival1	! (Y1_1) ival = ival & 0xfffc0000
	add	iy2,CONST_0x20000,ival2		! (Y2_1) ival = iy + 0x20000
	fmuld	%f48,%f14,%f44			! (Y2_0) yy = yy * ldtmp1
	faddd	%f50,K1,%f50			! (Y0_0) dtmp3 = dtmp2 + K1

	cmp	ival3,MASK_0x7f800000		! (Y3_1) if (ival >= 0x7f800000)
	sub	iy1,ival1,iy1			! (Y1_1) iy = iy - ival
	and	ival2,MASK_0xfffc0000,ival2	! (Y2_1) ival = ival & 0xfffc0000
	fpack32	ZERO,%f8,%f8			! (Y1_0) exp = vis_fpack32(ZERO, exp)

	sub	iy2,ival2,iy2			! (Y2_1) iy = iy - ival
	st	iy1,[%fp+tmp3]			! (Y1_1) (double) iy
	fmuld	%f26,%f16,%f60			! (Y3_0) yy = yy * ldtmp1
	faddd	%f42,K1,%f54			! (Y1_0) dtmp3 = dtmp2 + K1

	st	iy2,[%fp+tmp2]			! (Y2_1) (double) iy
	fmuld	K3,%f44,%f22			! (Y2_0) dtmp0 = K3 * yy
	bge,pn	%icc,.update14			! (Y3_1) if (ival >= 0x7f800000)
	fitod	%f6,%f40			! (Y0_0) (double)(*(int*)&exp)
.cont14:
	cmp	ival3,MASK_0x007fffff		! (Y3_1) if (ival <= 0x7fffff)
	ldd	[LOGFTBL+ind1],%f58		! (Y1_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	%f50,%f46,%f52			! (Y0_0) dtmp4 = dtmp3 * yy
	fitod	%f8,%f56			! (Y1_0) (double)(*(int*)&exp)

	ld	[%fp+tmp1],%f2			! (Y0_1) (double) iy
	fmuld	K3,%f60,%f50			! (Y3_0) dtmp0 = K3 * yy
	ble,pn	%icc,.update15			! (Y3_1) if (ival <= 0x7fffff)
	nop
.cont15:
	subcc	counter,7,counter
	fmuld	%f54,%f62,%f54			! (Y1_0) dtmp4 = dtmp3 * yy

	sra	ival0,14,ival0			! (Y0_1) i  = ival >> 14;
	bneg,pn	%icc,.tail
	faddd	%f22,K2,%f48			! (Y2_0) dtmp1 = dtmp0 + K2
	
	ba	.main_loop
	nop

	.align	16
.main_loop:
	sra	ival2,14,ival2			! (Y2_1) i  = ival >> 14;
	ldd	[LOGFTBL+ind0],%f42		! (Y0_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	LN2,%f40,%f40			! (Y0_0) ty = LN2 * (double)(*(int*)&exp)
	faddd	%f52,K0,%f22			! (Y0_0) dtmp5 = dtmp4 + K0

	sra	ival1,14,ind1			! (Y1_1) i  = ival >> 14;
	ld	[%fp+tmp3],%f4			! (Y1_1) (double) iy
	fpack32	ZERO,%f10,%f18			! (Y2_0) exp = vis_fpack32(ZERO, exp)
	faddd	%f50,K2,%f26			! (Y3_0) dtmp1 = dtmp0 + K2

	and	ival0,-8,ind0			! (Y0_1) ind  = i & (-8)
	lda	[x0]0x82,%f6			! (Y0_1) *(float*)&exp = *(float*)(x)
	fmuld	LN2,%f56,%f56			! (Y1_0) LN2 * (double)(*(int*)&exp)
	faddd	%f54,K0,%f24			! (Y1_0) dtmp5 = dtmp4 + K0

	and	ind1,-8,ind1			! (Y1_1) ind  = i & (-8)
	ldd	[LOGFTBL_P8+ind0],%f14		! (Y0_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fmuld	%f48,%f44,%f50			! (Y2_0) dtmp2 = dtmp1 * yy
	fitod	%f2,%f48			! (Y0_1) yy = (double) iy

	and	ival3,MASK_0x007fffff,iy3	! (Y3_1) iy = ival & 0x007fffff
	lda	[stridex+x0]0x82,%f8		! (Y1_1) *(float*)&exp = *(float*)(x)
	fmuld	%f22,%f46,%f22			! (Y0_0) yy = dtmp5 * yy
	fsubd	%f40,%f42,%f40			! (Y0_0) ty = ty - ldtmp0

	add	iy3,CONST_0x20000,ival3		! (Y3_1) iy + 0x20000
	ldd	[LOGFTBL_P8+ind1],%f16		! (Y1_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fmuld	%f26,%f60,%f42			! (Y3_0) dtmp2 = dtmp1 * yy
	fitod	%f4,%f26			! (Y1_1) yy = (double) iy

	and	ival3,MASK_0xfffc0000,ival3	! (Y3_1) ival = ival & 0xfffc0000
	lda	[x1]0x82,%f10			! (Y2_1) *(float*)&exp = *(float*)(x)
	fmuld	%f24,%f62,%f24			! (Y1_0) yy = dtmp5 * yy
	fsubd	%f56,%f58,%f58			! (Y1_0) ty = ty - ldtmp0

	sub	iy3,ival3,iy3			! (Y3_1) iy = iy - ival
	ld	[%fp+tmp2],%f2			! (Y2_1) (double) iy
	fmuld	%f48,%f14,%f46			! (Y0_1) yy = yy * ldtmp1
	faddd	%f50,K1,%f50			! (Y2_0) dtmp3 = dtmp2 + K1

	add	x1,stridex2,x0			! x += 2*stridex
	st	iy3,[%fp+tmp3]			! (Y3_1) (double) iy
	fpack32	ZERO,%f12,%f20			! (Y3_0) exp = vis_fpack32(ZERO, exp)
	faddd	%f22,%f40,%f48			! (Y0_0) yy = yy + ty

	add	y,stridey,y			! y += stridey
	lda	[stridex+x1]0x82,%f12		! (Y3_1) *(float*)&exp = *(float*)(x)
	fmuld	%f26,%f16,%f62			! (Y1_1) yy = yy * ldtmp1
	faddd	%f42,K1,%f54			! (Y3_0) dtmp3 = dtmp2 + K1

	sra	ival3,14,ival3			! (Y3_1) i  = ival >> 14;
	add	y,stridey,y			! y += stridey
	lda	[x0]0x82,ival0			! (Y0_2) ival = *(int*)(x)
	faddd	%f24,%f58,%f24			! (Y1_0) yy = yy + ty

	add	x0,stridex2,x1			! x += 2*stridex
	ldd	[LOGFTBL+ind2],%f42		! (Y2_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	K3,%f46,%f22			! (Y0_1) dtmp0 = K3 * yy
	fitod	%f18,%f40			! (Y2_0) (double)(*(int*)&exp)

	and	ival2,-8,ind2			! (Y2_1) ind  = i & (-8)
	lda	[stridex+x0]0x82,ival1		! (Y1_2) ival = *(int*)(x)
	fmuld	%f50,%f44,%f52			! (Y2_0) dtmp4 = dtmp3 * yy
	fitod	%f20,%f56			! (Y3_0) (double)(*(int*)&exp)

	cmp	ival0,MASK_0x7f800000		! (Y0_2) if (ival >= 0x7f800000)
	lda	[x1]0x82,ival2			! (Y2_2) ival = *(int*)(x);
	fmuld	K3,%f62,%f50			! (Y1_1) dtmp0 = K3 * yy
	fdtos	%f48,%f4			! (Y0_0) (float)(yy)

	st	%f4,[y]				! (Y0_0) write into memory
	fmuld	%f54,%f60,%f54			! (Y3_0) dtmp4 = dtmp3 * yy
	bge,pn 	%icc,.update16			! (Y0_2) if (ival >= 0x7f800000)
	fdtos	%f24,%f4			! (Y1_0) (float)(yy)
.cont16:
	cmp	ival0,MASK_0x007fffff		! (Y0_2) if (ival <= 0x7fffff
	ldd	[LOGFTBL+ind3],%f58		! (Y3_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	ble,pn	%icc,.update17			! (Y0_2) if (ival <= 0x7fffff
	faddd	%f22,K2,%f48			! (Y0_1) dtmp1 = dtmp0 + K2
.cont17:
	cmp	ival1,MASK_0x7f800000		! (Y1_2) if (ival >= 0x7f800000)
	and	ival0,MASK_0x007fffff,iy0	! (Y0_2) iy = ival & 0x007fffff
	st	%f4,[stridey+y]			! (Y1_0) write into memory
	fmuld	LN2,%f40,%f40			! (Y2_0) ty = LN2 * (double)(*(int*)&exp)

	add	iy0,CONST_0x20000,ival0		! (Y0_2) ival = iy + 0x20000
	ldd	[LOGFTBL_P8+ind2],%f14		! (Y2_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8);
	faddd	%f52,K0,%f22			! (Y2_0) dtmp5 = dtmp4 + K0
	fpack32	ZERO,%f6,%f6			! (Y0_1) exp = vis_fpack32(ZERO, exp)

	and	ival0,MASK_0xfffc0000,ival0	! (Y0_2) ival = ival & 0xfffc0000
	faddd	%f50,K2,%f26			! (Y1_1) dtmp1 = dtmp0 + K2
	bge,pn	%icc,.update18			! (Y1_2) if (ival >= 0x7f800000)
	fmuld	LN2,%f56,%f56			! (Y3_0) ty = LN2 * (double)(*(int*)&exp)
.cont18:
	sub	iy0,ival0,iy0			! (Y0_2) iy = iy - ival
	and	ival3,-8,ind3			! (Y3_1) ind  = i & (-8)
	ld	[%fp+tmp3],%f4			! (Y3_1) (double) iy
	faddd	%f54,K0,%f24			! (Y3_0) dtmp5 = dtmp4 + K0

	cmp	ival1,MASK_0x007fffff		! (Y1_2) if (ival <= 0x7fffff)
	lda	[stridex+x1]0x82,ival3		! (Y3_2) ival = *(int*)(x)
	fmuld	%f48,%f46,%f50			! (Y0_1) dtmp2 = dtmp1 * yy
	fitod	%f2,%f48			! (Y2_1) yy = (double) iy

	st	iy0,[%fp+tmp1]			! (Y0_2) (double) iy
	fmuld	%f22,%f44,%f22			! (Y2_0) yy = dtmp5 * yy
	ble,pn	%icc,.update19			! (Y1_2) if (ival <= 0x7fffff)
	fsubd	%f40,%f42,%f40			! (Y2_0) ty = ty - ldtmp0
.cont19:
	cmp	ival2,MASK_0x7f800000		! (Y2_2) if (ival >= 0x7f800000)
	and	ival1,MASK_0x007fffff,iy1	! (Y1_2) iy = ival & 0x007fffff
	bge,pn	%icc,.update20			! (Y2_2) if (ival >= 0x7f800000)
	fmuld	%f26,%f62,%f42			! (Y1_1) dtmp2 = dtmp1 * yy
.cont20:
	cmp	ival2,MASK_0x007fffff		! (Y2_2) if (ival <= 0x7fffff)
	ldd	[LOGFTBL_P8+ind3],%f16		! (Y3_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	ble,pn	%icc,.update21			! (Y2_2) if (ival <= 0x7fffff)
	fitod	%f4,%f26			! (Y3_1) yy = (double) iy
.cont21:
	add	iy1,CONST_0x20000,ival1		! (Y1_2) ival = iy + 0x20000
	and	ival2,MASK_0x007fffff,iy2	! (Y2_2) iy = ival & 0x007fffff
	fmuld	%f24,%f60,%f24			! (Y3_0) yy = dtmp5 * yy
	fsubd	%f56,%f58,%f58			! (Y3_0) ty = ty - ldtmp0

	and	ival1,MASK_0xfffc0000,ival1	! (Y1_2) ival = ival & 0xfffc0000
	add	iy2,CONST_0x20000,ival2		! (Y2_2) ival = iy + 0x20000
	fmuld	%f48,%f14,%f44			! (Y2_1) yy = yy * ldtmp1
	faddd	%f50,K1,%f50			! (Y0_1) dtmp3 = dtmp2 + K1

	sub	iy1,ival1,iy1			! (Y1_2) iy = iy - ival
	and	ival2,MASK_0xfffc0000,ival2	! (Y2_2) ival = ival & 0xfffc0000
	fpack32	ZERO,%f8,%f8			! (Y1_1) exp = vis_fpack32(ZERO, exp)
	faddd	%f22,%f40,%f48			! (Y2_0) yy = yy + ty

	sub	iy2,ival2,iy2			! (Y2_2) iy = iy - ival
	st	iy1,[%fp+tmp3]			! (Y1_2) (double) iy
	fmuld	%f26,%f16,%f60			! (Y3_1) yy = yy * ldtmp1
	faddd	%f42,K1,%f54			! (Y1_1) dtmp3 = dtmp2 + K1

	cmp	ival3,MASK_0x7f800000		! (Y3_2) if (ival >= 0x7f800000)
	add	y,stridey,y			! y += stridey
	st	iy2,[%fp+tmp2]			! (Y2_2) (double) iy
	faddd	%f24,%f58,%f24			! (Y3_0) yy = yy + ty

	add	y,stridey,y			! y += stridey
	fmuld	K3,%f44,%f22			! (Y2_1) dtmp0 = K3 * yy
	bge,pn	%icc,.update22			! (Y3_2) if (ival >= 0x7f800000)
	fitod	%f6,%f40			! (Y0_1)(double)(*(int*)&exp)
.cont22:
	cmp	ival3,MASK_0x007fffff		! (Y3_2) if (ival <= 0x7fffff)
	ldd	[LOGFTBL+ind1],%f58		! (Y1_1) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	%f50,%f46,%f52			! (Y0_1) dtmp4 = dtmp3 * yy
	fitod	%f8,%f56			! (Y1_1) (double)(*(int*)&exp)

	ld	[%fp+tmp1],%f2			! (Y0_2) (double) iy
	fmuld	K3,%f60,%f50			! (Y3_1) dtmp0 = K3 * yy
	ble,pn	%icc,.update23			! (Y3_2) if (ival <= 0x7fffff)
	fdtos	%f48,%f4			! (Y2_0) (float)(yy)
.cont23:
	subcc	counter,4,counter		! update cycle counter
	st	%f4,[y]				! (Y2_0) write into memory
	fmuld	%f54,%f62,%f54			! (Y1_1) dtmp4 = dtmp3 * yy
	fdtos	%f24,%f4			! (Y3_0)(float)(yy)

	sra	ival0,14,ival0			! (Y0_2) i  = ival >> 14;
	st	%f4,[stridey+y]			! (Y3_0) write into memory
	bpos,pt	%icc,.main_loop
	faddd	%f22,K2,%f48			! (Y2_1) dtmp1 = dtmp0 + K2

.tail:
	addcc	counter,7,counter
	add	y,stridey,y			! y += stridey
	bneg,pn	%icc,.end_loop

	sra	ival2,14,ival2			! (Y2_1) i  = ival >> 14;
	ldd	[LOGFTBL+ind0],%f42		! (Y0_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	LN2,%f40,%f40			! (Y0_0) ty = LN2 * (double)(*(int*)&exp)
	faddd	%f52,K0,%f22			! (Y0_0) dtmp5 = dtmp4 + K0

	sra	ival1,14,ind1			! (Y1_1) i  = ival >> 14;
	ld	[%fp+tmp3],%f4			! (Y1_1) (double) iy
	fpack32	ZERO,%f10,%f18			! (Y2_0) exp = vis_fpack32(ZERO, exp)
	faddd	%f50,K2,%f26			! (Y3_0) dtmp1 = dtmp0 + K2

	and	ival0,-8,ind0			! (Y0_1) ind  = i & (-8)
	lda	[x0]0x82,%f6			! (Y0_1) *(float*)&exp = *(float*)(x)
	fmuld	LN2,%f56,%f56			! (Y1_0) LN2 * (double)(*(int*)&exp)
	faddd	%f54,K0,%f24			! (Y1_0) dtmp5 = dtmp4 + K0

	and	ind1,-8,ind1			! (Y1_1) ind  = i & (-8)
	ldd	[LOGFTBL_P8+ind0],%f14		! (Y0_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fmuld	%f48,%f44,%f50			! (Y2_0) dtmp2 = dtmp1 * yy
	fitod	%f2,%f48			! (Y0_1) yy = (double) iy

	and	ival3,MASK_0x007fffff,ival1	! (Y3_1) iy = ival & 0x007fffff
	lda	[stridex+x0]0x82,%f8		! (Y1_1) *(float*)&exp = *(float*)(x)
	fmuld	%f22,%f46,%f22			! (Y0_0) yy = dtmp5 * yy
	fsubd	%f40,%f42,%f40			! (Y0_0) ty = ty - ldtmp0

	add	iy3,CONST_0x20000,ival3		! (Y3_1) iy + 0x20000
	ldd	[LOGFTBL_P8+ind1],%f16		! (Y1_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fmuld	%f26,%f60,%f42			! (Y3_0) dtmp2 = dtmp1 * yy
	fitod	%f4,%f26			! (Y1_1) yy = (double) iy

	and	ival3,MASK_0xfffc0000,ival3	! (Y3_1) ival = ival & 0xfffc0000
	lda	[x1]0x82,%f10			! (Y2_1) *(float*)&exp = *(float*)(x)
	fmuld	%f24,%f62,%f24			! (Y1_0) yy = dtmp5 * yy
	fsubd	%f56,%f58,%f58			! (Y1_0) ty = ty - ldtmp0

	sub	iy3,ival3,iy3			! (Y3_1) iy = iy - ival
	ld	[%fp+tmp2],%f2			! (Y2_1) (double) iy
	fmuld	%f48,%f14,%f46			! (Y0_1) yy = yy * ldtmp1
	faddd	%f50,K1,%f50			! (Y2_0) dtmp3 = dtmp2 + K1

	add	x1,stridex2,x0			! x += 2*stridex
	st	iy3,[%fp+tmp3]			! (Y3_1) (double) iy
	fpack32	ZERO,%f12,%f20			! (Y3_0) exp = vis_fpack32(ZERO, exp)
	faddd	%f22,%f40,%f48			! (Y0_0) yy = yy + ty

	lda	[stridex+x1]0x82,%f12		! (Y3_1) *(float*)&exp = *(float*)(x)
	fmuld	%f26,%f16,%f62			! (Y1_1) yy = yy * ldtmp1
	faddd	%f42,K1,%f54			! (Y3_0) dtmp3 = dtmp2 + K1

	sra	ival3,14,ival3			! (Y3_1) i  = ival >> 14;
	add	y,stridey,y			! y += stridey
	faddd	%f24,%f58,%f24			! (Y1_0) yy = yy + ty

	subcc	counter,1,counter
	ldd	[LOGFTBL+ind2],%f42		! (Y2_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	K3,%f46,%f22			! (Y0_1) dtmp0 = K3 * yy
	fitod	%f18,%f40			! (Y2_0) (double)(*(int*)&exp)

	and	ival2,-8,ind2			! (Y2_1) ind  = i & (-8)
	fmuld	%f50,%f44,%f52			! (Y2_0) dtmp4 = dtmp3 * yy
	fitod	%f20,%f56			! (Y3_0) (double)(*(int*)&exp)

	fmuld	K3,%f62,%f50			! (Y1_1) dtmp0 = K3 * yy
	fdtos	%f48,%f4			! (Y0_0) (float)(yy)

	st	%f4,[y]				! (Y0_0) write into memory
	fmuld	%f54,%f60,%f54			! (Y3_0) dtmp4 = dtmp3 * yy
	bneg,pn	%icc,.end_loop
	fdtos	%f24,%f4			! (Y1_0) (float)(yy)

	add	y,stridey,y			! y += stridey
	subcc	counter,1,counter
	ldd	[LOGFTBL+ind3],%f58		! (Y3_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	faddd	%f22,K2,%f48			! (Y0_1) dtmp1 = dtmp0 + K2

	st	%f4,[y]				! (Y1_0) write into memory
	bneg,pn	%icc,.end_loop
	fmuld	LN2,%f40,%f40			! (Y2_0) ty = LN2 * (double)(*(int*)&exp)

	ldd	[LOGFTBL_P8+ind2],%f14		! (Y2_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8);
	faddd	%f52,K0,%f22			! (Y2_0) dtmp5 = dtmp4 + K0
	fpack32	ZERO,%f6,%f6			! (Y0_1) exp = vis_fpack32(ZERO, exp)

	faddd	%f50,K2,%f26			! (Y1_1) dtmp1 = dtmp0 + K2
	fmuld	LN2,%f56,%f56			! (Y3_0) ty = LN2 * (double)(*(int*)&exp)

	and	ival3,-8,ind3			! (Y3_1) ind  = i & (-8)
	ld	[%fp+tmp3],%f4			! (Y3_1) (double) iy
	faddd	%f54,K0,%f24			! (Y3_0) dtmp5 = dtmp4 + K0

	fmuld	%f48,%f46,%f50			! (Y0_1) dtmp2 = dtmp1 * yy
	fitod	%f2,%f48			! (Y2_1) yy = (double) iy

	fmuld	%f22,%f44,%f22			! (Y2_0) yy = dtmp5 * yy
	fsubd	%f40,%f42,%f40			! (Y2_0) ty = ty - ldtmp0

	fmuld	%f26,%f62,%f42			! (Y1_1) dtmp2 = dtmp1 * yy

	ldd	[LOGFTBL_P8+ind3],%f16		! (Y3_1) ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fitod	%f4,%f26			! (Y3_1) yy = (double) iy

	fmuld	%f24,%f60,%f24			! (Y3_0) yy = dtmp5 * yy
	fsubd	%f56,%f58,%f58			! (Y3_0) ty = ty - ldtmp0

	fmuld	%f48,%f14,%f44			! (Y2_1) yy = yy * ldtmp1
	faddd	%f50,K1,%f50			! (Y0_1) dtmp3 = dtmp2 + K1

	fpack32	ZERO,%f8,%f8			! (Y1_1) exp = vis_fpack32(ZERO, exp)
	faddd	%f22,%f40,%f48			! (Y2_0) yy = yy + ty

	fmuld	%f26,%f16,%f60			! (Y3_1) yy = yy * ldtmp1
	faddd	%f42,K1,%f54			! (Y1_1) dtmp3 = dtmp2 + K1

	add	y,stridey,y			! y += stridey
	faddd	%f24,%f58,%f24			! (Y3_0) yy = yy + ty

	subcc	counter,1,counter
	fmuld	K3,%f44,%f22			! (Y2_1) dtmp0 = K3 * yy
	fitod	%f6,%f40			! (Y0_1)(double)(*(int*)&exp)

	ldd	[LOGFTBL+ind1],%f58		! (Y1_1) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	%f50,%f46,%f52			! (Y0_1) dtmp4 = dtmp3 * yy
	fitod	%f8,%f56			! (Y1_1) (double)(*(int*)&exp)

	fmuld	K3,%f60,%f50			! (Y3_1) dtmp0 = K3 * yy
	fdtos	%f48,%f4			! (Y2_0) (float)(yy)

	st	%f4,[y]				! (Y2_0) write into memory
	fmuld	%f54,%f62,%f54			! (Y1_1) dtmp4 = dtmp3 * yy
	bneg,pn	%icc,.end_loop
	fdtos	%f24,%f4			! (Y3_0)(float)(yy)

	subcc	counter,1,counter		! update cycle counter
	add	y,stridey,y

	st	%f4,[y]				! (Y3_0) write into memory
	bneg,pn	%icc,.end_loop
	faddd	%f22,K2,%f48			! (Y2_1) dtmp1 = dtmp0 + K2

	ldd	[LOGFTBL+ind0],%f42		! (Y0_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fmuld	LN2,%f40,%f40			! (Y0_0) ty = LN2 * (double)(*(int*)&exp)
	faddd	%f52,K0,%f22			! (Y0_0) dtmp5 = dtmp4 + K0

	fpack32	ZERO,%f10,%f18			! (Y2_0) exp = vis_fpack32(ZERO, exp)

	fmuld	LN2,%f56,%f56			! (Y1_0) LN2 * (double)(*(int*)&exp)
	faddd	%f54,K0,%f24			! (Y1_0) dtmp5 = dtmp4 + K0

	fmuld	%f48,%f44,%f50			! (Y2_0) dtmp2 = dtmp1 * yy

	fmuld	%f22,%f46,%f22			! (Y0_0) yy = dtmp5 * yy
	fsubd	%f40,%f42,%f40			! (Y0_0) ty = ty - ldtmp0

	fmuld	%f24,%f62,%f24			! (Y1_0) yy = dtmp5 * yy
	fsubd	%f56,%f58,%f58			! (Y1_0) ty = ty - ldtmp0

	subcc	counter,1,counter
	faddd	%f50,K1,%f50			! (Y2_0) dtmp3 = dtmp2 + K1

	faddd	%f22,%f40,%f48			! (Y0_0) yy = yy + ty

	add	y,stridey,y			! y += stridey
	faddd	%f24,%f58,%f24			! (Y1_0) yy = yy + ty

	ldd	[LOGFTBL+ind2],%f42		! (Y2_0) ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	fitod	%f18,%f40			! (Y2_0) (double)(*(int*)&exp)

	fmuld	%f50,%f44,%f52			! (Y2_0) dtmp4 = dtmp3 * yy

	fdtos	%f48,%f4			! (Y0_0) (float)(yy)

	st	%f4,[y]				! (Y0_0) write into memory
	bneg,pn	%icc,.end_loop
	fdtos	%f24,%f4			! (Y1_0) (float)(yy)

	add	y,stridey,y			! y += stridey
	subcc	counter,1,counter
	st	%f4,[y]				! (Y1_0) write into memory
	bneg,pn	%icc,.end_loop
	fmuld	LN2,%f40,%f40			! (Y2_0) ty = LN2 * (double)(*(int*)&exp)

	faddd	%f52,K0,%f22			! (Y2_0) dtmp5 = dtmp4 + K0

	fmuld	%f22,%f44,%f22			! (Y2_0) yy = dtmp5 * yy
	fsubd	%f40,%f42,%f40			! (Y2_0) ty = ty - ldtmp0

	add	y,stridey,y			! y += stridey
	faddd	%f22,%f40,%f48			! (Y2_0) yy = yy + ty

	fdtos	%f48,%f4			! (Y2_0) (float)(yy)

	st	%f4,[y]				! (Y2_0) write into memory
.end_loop:
	ba	.begin
	nop

.end:
	ret
	restore	%g0,0,%o0

	.align	16
.update2:
	cmp	counter,0
	ble	.cont2
	nop

	add	x0,stridex,x0
	stx	x0,[%fp+tmp5]
	sub	x0,stridex,x0
	st	counter,[%fp+tmp0]
	or	%g0,0,counter
	ba	.cont2
	nop
        
	.align	16
.update3:
	cmp	counter,0
	ble	.cont3
	nop
 
	add	x0,stridex,x0
	stx	x0,[%fp+tmp5]
	sub	x0,stridex,x0
	st	counter,[%fp+tmp0]
	or	%g0,0,counter
	ba	.cont3
	nop
                
	.align	16
.update4:
	cmp	counter,1
	ble	.cont4
	nop
 
	stx	x1,[%fp+tmp5]
	sub	counter,1,counter
	st	counter,[%fp+tmp0]
	or	%g0,1,counter
	ba	.cont4
	nop
                
	.align	16
.update5:
	cmp	counter,1
	ble	.cont5
	nop
 
	stx	x1,[%fp+tmp5]
	sub	counter,1,counter
	st	counter,[%fp+tmp0]
	or	%g0,1,counter
	ba	.cont5
	nop
                
	.align	16
.update6:
	cmp	counter,2
	ble	.cont6
	nop
 
	add	x1,stridex,x1
	stx	x1,[%fp+tmp5]
	sub	x1,stridex,x1
	sub	counter,2,counter
	st	counter,[%fp+tmp0]
	or	%g0,2,counter
	ba	.cont6
	nop
                
	.align	16
.update7:
	cmp	counter,2
	ble	.cont7
	nop
 
	add	x1,stridex,x1
	stx	x1,[%fp+tmp5]
	sub	x1,stridex,x1
	sub	counter,2,counter
	st	counter,[%fp+tmp0]
	or	%g0,2,counter
	ba	.cont7
	nop
                
	.align	16
.update8:
	cmp	counter,3
	ble	.cont8
	nop

	stx	x0,[%fp+tmp5]
	sub	counter,3,counter
	st	counter,[%fp+tmp0]
	or	%g0,3,counter
	ba	.cont8
	nop
        
	.align	16
.update9:
	cmp	counter,3
	ble	.cont9
	nop

	stx	x0,[%fp+tmp5]
	sub	counter,3,counter
	st	counter,[%fp+tmp0]
	or	%g0,3,counter
	ba	.cont9
	nop
        
	.align	16
.update10:
	cmp	counter,4
	ble	.cont10
	nop

	add	x0,stridex,x0
	stx	x0,[%fp+tmp5]
	sub	x0, stridex, x0
	sub	counter,4,counter
	st	counter,[%fp+tmp0]
	or	%g0,4,counter
	ba	.cont10
	nop
        
	.align	16
.update11:
	cmp	counter,4
	ble	.cont11
	nop
 
	add	x0,stridex,x0
	stx	x0,[%fp+tmp5]
	sub	x0,stridex,x0
	sub	counter,4,counter
	st	counter,[%fp+tmp0]
	or	%g0,4,counter
	ba	.cont11
	nop
                
	.align	16
.update12:
	cmp	counter,5
	ble	.cont12
	nop
 
	stx	x1,[%fp+tmp5]
	sub	counter,5,counter
	st	counter,[%fp+tmp0]
	or	%g0,5,counter
	ba	.cont12
	nop
                
	.align	16
.update13:
	cmp	counter,5
	ble	.cont13
	nop
 
	stx	x1,[%fp+tmp5]
	sub	counter,5,counter
	st	counter,[%fp+tmp0]
	or	%g0,5,counter
	ba	.cont13
	nop
                
	.align	16
.update14:
	cmp	counter,6
	ble	.cont14
	nop
 
	add	x1,stridex,x1
	stx	x1,[%fp+tmp5]
	sub	x1, stridex, x1
	sub	counter,6,counter
	st	counter,[%fp+tmp0]
	or	%g0,6,counter
	ba 	.cont14
	nop
                
	.align	16
.update15:
	cmp	counter,6
	ble	.cont15
	nop
 
	add	x1,stridex,x1
	stx	x1,[%fp+tmp5]
	sub	x1, stridex, x1
	sub	counter,6,counter
	st	counter,[%fp+tmp0]
	or	%g0,6,counter
	ba	.cont15
	nop
                
	.align	16
.update16:
	cmp	counter,0
	ble,pt	%icc, .cont16
	nop

	stx	x0,[%fp+tmp5]
	st	counter,[%fp+tmp0]
	or	%g0,0,counter
	ba	.cont16
	nop
        
	.align	16
.update17:
	cmp	counter,0
	ble,pt	%icc, .cont17
	nop
 
	stx	x0,[%fp+tmp5]
	st	counter,[%fp+tmp0]
	or	%g0,0,counter
	ba	.cont17
	nop
                
	.align	16
.update18:
	cmp	counter,1
	ble,pt	%icc, .cont18
	nop

	add	x0,stridex,x0
	stx	x0,[%fp+tmp5]
	sub	x0,stridex,x0
	sub	counter,1,counter
	st	counter,[%fp+tmp0]
	or	%g0,1,counter
	ba	.cont18
	nop
        
	.align	16
.update19:
	cmp	counter,1
	ble,pt	%icc, .cont19
	nop
 
	add	x0,stridex,x0
	sub	counter,1,counter
	stx	x0,[%fp+tmp5]
	sub	x0, stridex, x0
	st	counter,[%fp+tmp0]
	or	%g0,1,counter
	ba	.cont19
	nop
                
	.align	16
.update20:
	cmp	counter,2
	ble,pt	%icc, .cont20
	nop
 
	stx	x1,[%fp+tmp5]
	sub	counter,2,counter
	st	counter,[%fp+tmp0]
	or	%g0,2,counter
	ba	.cont20
	nop
                
	.align	16
.update21:
	cmp	counter,2
	ble,pt	%icc, .cont21
	nop
 
	stx x1,[%fp+tmp5]
	sub	counter, 2, counter
	st	counter,[%fp+tmp0]
	or	%g0,2,counter
	ba	.cont21
	nop
                
	.align	16
.update22:
	cmp	counter,3
	ble,pt	%icc, .cont22
	nop
 
	add	x1,stridex,x1
	stx	x1,[%fp+tmp5]
	sub	x1,stridex,x1
	sub	counter,3,counter
	st	counter,[%fp+tmp0]
	or	%g0,3,counter
	ba	.cont22
	nop
                
	.align	16
.update23:
	cmp	counter,3
	ble,pt	%icc, .cont23
	nop
 
	add	x1,stridex,x1
	stx	x1,[%fp+tmp5]
	sub	x1,stridex,x1
	sub	counter,3,counter
	st	counter,[%fp+tmp0]
	or	%g0,3,counter
	ba	.cont23
	nop
                
	.align	16
.spec:
	or	%g0,1,ind3			! ind3 = 1
	sll	ind3,31,ind3			! ind3 = 0x8000000
	add	x0,stridex,x0			! x += stridex
	sub	ind3,1,ind3			! ind3 = 0x7ffffff
	add	y,stridey,y			! y += stridey
	and	ival0,ind3,iy0			! ival & 0x7fffffff
	cmp	iy0,MASK_0x7f800000		! if ((ival & 0x7fffffff) >= 0x7f800000)
	bge,pn	%icc, .spec0			! if ((ival & 0x7fffffff) >= 0x7f800000)
	st	ival0,[%fp+tmp1]
	cmp	ival0,0				! if (ival <= 0)
	ble,pn	%icc,.spec1			! if (ival <= 0)
	nop

	ld	[%fp+tmp1],%f12
	fitos	%f12,%f14			! value = (float) ival
	st	%f14,[%fp+tmp2]			! ival = *(int*) &value
	ld	[%fp+tmp2],ival0		! ival = *(int*) &value

	and	ival0,MASK_0x007fffff,iy0	!  iy = ival & 0x007fffff
	sra	ival0,23,ival2			!  iexp = ival >> 23

	add	iy0,CONST_0x20000,ival0		!  ival = iy + 0x20000
	sub	ival2,149,ival2			!  iexp = iexp - 149

	and	ival0,MASK_0xfffc0000,ival0	!  ival = ival & 0xfffc0000
	st 	ival2,[%fp+tmp2]		!  (double) iexp

	sub	iy0,ival0,iy0			!  iy = iy - ival

	sra	ival0,14,ival0			!  i  = ival >> 14;
	st	iy0,[%fp+tmp1]			!  (double) iy

	and	ival0,-8,ind0			!  ind  = i & (-8)
	ld	[%fp+tmp1],%f2			!  (double) iy

	ldd	[LOGFTBL_P8+ind0],%f14		!  ldtmp1 = *(double*)((char*)CONST_TBL+ind+8)
	fitod	%f2,%f48			!  yy = (double) iy

	fmuld	%f48,%f14,%f46			!  yy = yy * ldtmp1

	ld	[%fp+tmp2],%f6			!  (double) iexp
	fmuld	K3,%f46,%f22			!  dtmp0 = K3 * yy

	ldd	[LOGFTBL+ind0],%f42		!  ldtmp0 = *(double*)((char*)CONST_TBL+ind)
	faddd	%f22,K2,%f48			!  dtmp1 = dtmp0 + K2

	fmuld	%f48,%f46,%f50			!  dtmp2 = dtmp1 * yy

	faddd	%f50,K1,%f50			!  dtmp3 = dtmp2 + K1

	fitod	%f6,%f40			!  (double) iexp
	fmuld	%f50,%f46,%f52			!  dtmp4 = dtmp3 * yy

	fmuld	LN2,%f40,%f40			!  ty = LN2 * (double) iexp
	faddd	%f52,K0,%f22			!  dtmp5 = dtmp4 + K0

	fmuld	%f22,%f46,%f22			!  yy = dtmp5 * yy
	fsubd	%f40,%f42,%f40			!  ty = ty - ldtmp0

	faddd	%f22,%f40,%f48			!  yy = yy + ty

	fdtos	%f48,%f4			!  (float)(yy)

	ba	.begin1
	st	%f4,[y]				! write into memory
        
	.align	16
.spec0:
	ld	[%fp+tmp1],%f12			! value = *(float*) &ival
	fzeros	%f2				! y[0] = (value < 0.0f?
	fcmps	%fcc0,%f12,%f2			!   0.0f : value) * value
	fmovsug	%fcc0,%f12,%f2
	fmuls	%f12,%f2,%f2
	ba	.begin1
	st	%f2,[y]				! write into memory
                
	.align	16                
.spec1:
	cmp	iy0,0				! if ((ival & 0x7fffffff) == 0)
	bne,pn	%icc,.spec2			! if ((ival & 0x7fffffff) == 0)
	nop
	ld	[LOGFTBL+568],%f4
	fdivs	%f4,ZERO,%f6			! y[0] = -1.0f / 0f
	ba	.begin1
	st	%f6,[y]				! write into memory
                
	.align	16
.spec2:
	fdivs	ZERO,ZERO,%f6			! y[0] = 0f / 0f
	ba	.begin1
	st	%f6,[y]				! write into memory

	SET_SIZE(__vlogf)

