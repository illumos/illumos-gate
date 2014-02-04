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

	.file	"__vrsqrt.S"

#include "libm.h"

	RO_DATA
	.align	64

.CONST_TBL:
	.word	0xbfe00000, 0x0000002f	! K1 =-5.00000000000005209867e-01;
	.word	0x3fd80000, 0x00000058	! K2 = 3.75000000000004884257e-01;
	.word	0xbfd3ffff, 0xff444bc8	! K3 =-3.12499999317136886551e-01;
	.word	0x3fd17fff, 0xff5006fe	! K4 = 2.73437499359815081532e-01;
	.word	0xbfcf80bb, 0xb33ef574	! K5 =-2.46116125605037803130e-01;
	.word	0x3fcce0af, 0xf8156949	! K6 = 2.25606914648617522896e-01;

	.word	0x001fffff, 0xffffffff	! DC0
	.word	0x3fe00000, 0x00000000	! DC1
	.word	0x00002000, 0x00000000	! DC2
	.word	0x7fffc000, 0x00000000	! DC3
	.word	0x0007ffff, 0xffffffff	! DC4

	.word	0x43200000, 0x00000000	! D2ON51  = pow(2,51)
	.word	0x3ff00000, 0x00000000	! DONE   = 1.0

#define stridex		%l5
#define stridey		%l7
#define counter		%l0
#define TBL		%l3
#define _0x7ff00000	%o0
#define _0x00100000	%o1

#define DC0		%f56
#define DC1		%f54
#define DC2		%f48
#define DC3		%f46
#define K6		%f42
#define K5		%f20
#define K4		%f52
#define K3		%f50
#define K2		%f14
#define K1		%f12
#define DONE		%f4

#define tmp_counter	%g5
#define tmp_px		%o5

#define tmp0		STACK_BIAS-0x40
#define tmp1		STACK_BIAS-0x38
#define tmp2		STACK_BIAS-0x30
#define tmp3		STACK_BIAS-0x28
#define tmp4		STACK_BIAS-0x20
#define tmp5		STACK_BIAS-0x18
#define tmp6		STACK_BIAS-0x10
#define tmp7		STACK_BIAS-0x08

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x40

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!  ((float*)&res)[0] = ((float*)px)[0];
!  ((float*)&res)[1] = ((float*)px)[1];
!  hx = *(int*)px;
!  if ( hx >= 0x7ff00000 )
!  {
!    res = DONE / res;
!    ((float*)py)[0] = ((float*)&res)[0];
!    ((float*)py)[1] = ((float*)&res)[1];
!    px += stridex;
!    py += stridey;
!    continue;
!  }
!  if ( hx < 0x00100000 )
!  {
!    ax = hx & 0x7fffffff;
!    lx = ((int*)px)[1];
!
!    if ( (ax | lx) == 0 )
!    {
!      res = DONE / res;
!      ((float*)py)[0] = ((float*)&res)[0];
!      ((float*)py)[1] = ((float*)&res)[1];
!      px += stridex;
!      py += stridey;
!      continue;
!    }
!    else if ( hx >= 0 )
!    {
!      if ( hx < 0x00080000 )
!      {
!        res = *(long long*)&res;
!        hx = *(int*)&res - (537 << 21);
!      }
!      else
!      {
!        res = vis_fand(res,DC4);
!        res = *(long long*)&res;
!        res += D2ON51;
!        hx = *(int*)&res - (537 << 21);
!      }
!    }
!    else
!    {
!      res = sqrt(res);
!      ((float*)py)[0] = ((float*)&res)[0];
!      ((float*)py)[1] = ((float*)&res)[1];
!      px += stridex;
!      py += stridey;
!      continue;
!    }
!  }
!
!  iexp = hx >> 21;
!  iexp = -iexp;
!  iexp += 0x5fe;
!  lexp = iexp << 52;
!  dlexp = *(double*)&lexp;
!  hx >>= 10;
!  hx &= 0x7f8;
!  hx += 8;
!  hx &= -16;
!
!  res = vis_fand(res,DC0);
!  res = vis_for(res,DC1);
!  res_c = vis_fpadd32(res,DC2);
!  res_c = vis_fand(res_c,DC3);
!
!  addr = (char*)arr + hx;
!  dexp_hi = ((double*)addr)[0];
!  dexp_lo = ((double*)addr)[1];
!  dtmp0 = dexp_hi * dexp_hi;
!  xx = res - res_c;
!  xx *= dtmp0;
!  res = K6 * xx;
!  res += K5;
!  res *= xx;
!  res += K4;
!  res *= xx;
!  res += K3;
!  res *= xx;
!  res += K2;
!  res *= xx;
!  res += K1;
!  res *= xx;
!  res = dexp_hi * res;
!  res += dexp_lo;
!  res += dexp_hi;
!
!  res *= dlexp;
!
!  ((float*)py)[0] = ((float*)&res)[0];
!  ((float*)py)[1] = ((float*)&res)[1];
!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vrsqrt)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,o3)
	PIC_SET(l7,__vlibm_TBL_rsqrt,l3)
	wr	%g0,0x82,%asi

	ldd	[%o3],K1
	sethi	%hi(0x7ff00000),%o0
	mov	%i3,%o4

	ldd	[%o3+0x08],K2
	sethi	%hi(0x00100000),%o1
	mov	%i1,tmp_px

	ldd	[%o3+0x10],K3
	sll	%i2,3,stridex
	mov	%i0,tmp_counter

	ldd	[%o3+0x18],K4
	sll	%i4,3,stridey

	ldd	[%o3+0x20],K5
	ldd	[%o3+0x28],K6
	ldd	[%o3+0x30],DC0
	ldd	[%o3+0x38],DC1
	ldd	[%o3+0x40],DC2
	ldd	[%o3+0x48],DC3

.begin:
	mov	tmp_counter,counter
	mov	tmp_px,%i1
	clr	tmp_counter
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit
	ldd	[%o3+0x60],DONE

	lda	[%i1]%asi,%f0		! (6_0) ((float*)res)[0] = ((float*)px)[0];
	sethi	%hi(0x7ffffc00),%i0

	lda	[%i1+4]%asi,%f1		! (6_0) ((float*)res)[1] = ((float*)px)[1];
	add	%i0,1023,%i0

	fand	%f0,DC0,%f16		! (6_0) res = vis_fand(res,DC0);

	lda	[%i1]%asi,%g1		! (6_1) hx = *(int*)px;
	sethi	%hi(0x00080000),%i4

	lda	[%i1+4]%asi,%l4
	add	%i1,stridex,%l6		! px += stridex

	sra	%g1,21,%o7		! (6_1) iexp = hx >> 21;
	lda	[%l6]%asi,%f8		! (0_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f44		! (6_1) res = vis_for(res,DC1);

	lda	[%l6+4]%asi,%f9		! (0_0) ((float*)res)[1] = ((float*)px)[1];
	sra	%g1,10,%o2		! (6_1) hx >>= 10;
	and	%g1,%i0,%i2

	cmp	%g1,_0x7ff00000		! (6_1) hx ? 0x7ff00000
	bge,pn	%icc,.spec0		! (6_1) if ( hx >= 0x7ff00000 )
	and	%o2,2040,%o2		! (6_1) hx &= 0x7f8;

	cmp	%g1,_0x00100000		! (6_1) hx ? 0x00100000
	bl,pn	%icc,.spec1		! (6_1) if ( hx < 0x00100000 )
	sub	%g0,%o7,%o7		! (6_1) iexp = -iexp;
.cont_spec:
	fand	%f8,DC0,%f16		! (0_0) res = vis_fand(res,DC0);

	fpadd32	%f44,DC2,%f18		! (6_1) res_c = vis_fpadd32(res,DC2);

	add	%o2,8,%l4		! (6_1) hx += 8;

	add	%o7,1534,%o7		! (6_1) iexp += 0x5fe;

	lda	[%l6]%asi,%g1		! (0_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (6_1) iexp << 52;
	and	%l4,-16,%l4		! (6_1) hx = -16;

	add	%l4,TBL,%l4		! (6_1) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp1]		! (6_1) dlexp = *(double*)lexp;

	add	%l6,stridex,%l6		! px += stridex
	ldd	[%l4],%f30		! (6_1) dtmp0 = ((double*)addr)[0];

	sra	%g1,21,%o7		! (0_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f0		! (1_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f28		! (0_0) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (0_0) hx >>= 10;
	sub	%g0,%o7,%o7		! (0_0) iexp = -iexp;
	lda	[%l6+4]%asi,%f1		! (1_0) ((float*)res)[1] = ((float*)px)[1];

	cmp	%g1,_0x7ff00000		! (0_0) hx ? 0x7ff00000
	bge,pn	%icc,.update0		! (0_0) if ( hx >= 0x7ff00000 )
	fand	%f18,DC3,%f6		! (6_1) res_c = vis_fand(res_c,DC3);
.cont0:
	and	%o2,2040,%o2		! (0_0) hx &= 0x7f8;
	fmuld	%f30,%f30,%f10		! (6_1) dtmp0 = dexp_hi * dexp_hi;

	cmp	%g1,_0x00100000		! (0_0) hx ? 0x00100000
	bl,pn	%icc,.update1		! (0_0) if ( hx < 0x00100000 )
	add	%o7,1534,%o7		! (0_0) iexp += 0x5fe;
.cont1:
	fand	%f0,DC0,%f16		! (1_0) res = vis_fand(res,DC0);

	fpadd32	%f28,DC2,%f18		! (0_0) res_c = vis_fpadd32(res,DC2);

	add	%o2,8,%l2		! (0_0) hx += 8;
	fsubd	%f44,%f6,%f6		! (6_1) xx = res - res_c;

	lda	[%l6]%asi,%g1		! (1_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (0_0) iexp << 52;
	and	%l2,-16,%l2		! (0_0) hx = -16;

	add	%l2,TBL,%l2		! (0_0) addr = (char*)arr + hx;
	add	%l6,stridex,%l6		! px += stridex
	stx	%o7,[%fp+tmp2]		! (0_0) dlexp = *(double*)lexp;

	fmuld	%f6,%f10,%f26		! (6_1) xx *= dtmp0;
	ldd	[%l2],%f10		! (0_0) dtmp0 = ((double*)addr)[0];

	sra	%g1,21,%o7		! (1_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f6		! (2_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f44		! (1_0) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (1_0) hx >>= 10;
	cmp	%g1,_0x7ff00000		! (1_0) hx ? 0x7ff00000
	bge,pn	%icc,.update2		! (1_0) if ( hx >= 0x7ff00000 )
	lda	[%l6+4]%asi,%f7		! (2_0) ((float*)res)[1] = ((float*)px)[1];
.cont2:
	fand	%f18,DC3,%f8		! (0_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f10,%f10,%f10		! (0_0) dtmp0 = dexp_hi * dexp_hi;
	cmp	%g1,_0x00100000		! (1_0) hx ? 0x00100000
	bl,pn	%icc,.update3		! (1_0) if ( hx < 0x00100000 )
	and	%o2,2040,%o2		! (1_0) hx &= 0x7f8;
.cont3:
	sub	%g0,%o7,%o7		! (1_0) iexp = -iexp;
	fand	%f6,DC0,%f16		! (2_0) res = vis_fand(res,DC0);

	add	%o7,1534,%o7		! (1_0) iexp += 0x5fe;
	fpadd32	%f44,DC2,%f18		! (1_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f26,%f62		! (6_1) res = K6 * xx;
	add	%o2,8,%i2		! (1_0) hx += 8;
	fsubd	%f28,%f8,%f32		! (0_0) xx = res - res_c;

	lda	[%l6]%asi,%g1		! (2_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (1_0) iexp << 52;
	and	%i2,-16,%i2		! (1_0) hx = -16;

	add	%i2,TBL,%i2		! (1_0) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp3]		! (1_0) dlexp = *(double*)lexp;

	fmuld	%f32,%f10,%f32		! (0_0) xx *= dtmp0;
	add	%l6,stridex,%l6		! px += stridex
	ldd	[%i2],%f10		! (1_0) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (6_1) res += K5;

	sra	%g1,21,%o7		! (2_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f0		! (3_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f28		! (2_0) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (2_0) hx >>= 10;
	cmp	%g1,_0x7ff00000		! (2_0) hx ? 0x7ff00000
	bge,pn	%icc,.update4		! (2_0) if ( hx >= 0x7ff00000 )
	lda	[%l6+4]%asi,%f1		! (3_0) ((float*)res)[1] = ((float*)px)[1];
.cont4:
	fmuld	%f62,%f26,%f40		! (6_1) res *= xx;
	fand	%f18,DC3,%f8		! (1_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f10,%f10,%f10		! (1_0) dtmp0 = dexp_hi * dexp_hi;
	cmp	%g1,_0x00100000		! (2_0) hx ? 0x00100000
	bl,pn	%icc,.update5		! (2_0) if ( hx < 0x00100000 )
	and	%o2,2040,%o2		! (2_0) hx &= 0x7f8;
.cont5:
	sub	%g0,%o7,%o7		! (2_0) iexp = -iexp;
	fand	%f0,DC0,%f16		! (3_0) res = vis_fand(res,DC0);

	add	%o7,1534,%o7		! (2_0) iexp += 0x5fe;
	fpadd32	%f28,DC2,%f18		! (2_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f32,%f62		! (0_0) res = K6 * xx;
	add	%o2,8,%i4		! (2_0) hx += 8;
	fsubd	%f44,%f8,%f6		! (1_0) xx = res - res_c;

	faddd	%f40,K4,%f40		! (6_1) res += K4;

	lda	[%l6]%asi,%g1		! (3_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (2_0) iexp << 52;
	and	%i4,-16,%i4		! (2_0) hx = -16;

	add	%i4,TBL,%i4		! (2_0) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp4]		! (2_0) dlexp = *(double*)lexp;

	fmuld	%f6,%f10,%f38		! (1_0) xx *= dtmp0;
	ldd	[%i4],%f24		! (2_0) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (0_0) res += K5;

	fmuld	%f40,%f26,%f34		! (6_1) res *= xx;
	add	%l6,stridex,%l6		! px += stridex

	sra	%g1,21,%o7		! (3_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f8		! (4_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f44		! (3_0) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (3_0) hx >>= 10;
	cmp	%g1,_0x7ff00000		! (3_0) hx ? 0x7ff00000
	bge,pn	%icc,.update6		! (3_0) if ( hx >= 0x7ff00000 )
	lda	[%l6+4]%asi,%f9		! (4_0) ((float*)res)[1] = ((float*)px)[1];
.cont6:
	fmuld	%f62,%f32,%f60		! (0_0) res *= xx;
	cmp	%g1,_0x00100000		! (3_0) hx ? 0x00100000
	fand	%f18,DC3,%f22		! (2_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f24,%f24,%f24		! (2_0) dtmp0 = dexp_hi * dexp_hi;
	bl,pn	%icc,.update7		! (3_0) if ( hx < 0x00100000 )
	and	%o2,2040,%o2		! (3_0) hx &= 0x7f8;
	faddd	%f34,K3,%f6		! (6_1) res += K3;
.cont7:
	sub	%g0,%o7,%o7		! (3_0) iexp = -iexp;
	fand	%f8,DC0,%f16		! (4_0) res = vis_fand(res,DC0);

	add	%o7,1534,%o7		! (3_0) iexp += 0x5fe;
	fpadd32	%f44,DC2,%f18		! (3_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f38,%f62		! (1_0) res = K6 * xx;
	add	%o2,8,%i5		! (3_0) hx += 8;
	fsubd	%f28,%f22,%f28		! (2_0) xx = res - res_c;

	fmuld	%f6,%f26,%f22		! (6_1) res *= xx;
	faddd	%f60,K4,%f60		! (0_0) res += K4;

	lda	[%l6]%asi,%g1		! (4_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (3_0) iexp << 52;
	and	%i5,-16,%i5		! (3_0) hx = -16;

	add	%i5,TBL,%i5		! (3_0) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp5]		! (3_0) dlexp = *(double*)lexp;

	fmuld	%f28,%f24,%f36		! (2_0) xx *= dtmp0;
	add	%l6,stridex,%i0		! px += stridex
	ldd	[%i5],%f28		! (3_0) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (1_0) res += K5;

	faddd	%f22,K2,%f10		! (6_1) res += K2;
	fmuld	%f60,%f32,%f34		! (0_0) res *= xx;

	sra	%g1,21,%o7		! (4_0) iexp = hx >> 21;
	lda	[%i0]%asi,%f0		! (5_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f24		! (4_0) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (4_0) hx >>= 10;
	cmp	%g1,_0x7ff00000		! (4_0) hx ? 0x7ff00000
	bge,pn	%icc,.update8		! (4_0) if ( hx >= 0x7ff00000 )
	lda	[%i0+4]%asi,%f1		! (5_0) ((float*)res)[1] = ((float*)px)[1];
.cont8:
	fand	%f18,DC3,%f40		! (3_0) res_c = vis_fand(res_c,DC3);
	fmuld	%f62,%f38,%f62		! (1_0) res *= xx;

	fmuld	%f10,%f26,%f58		! (6_1) res *= xx;
	cmp	%g1,_0x00100000		! (4_0) hx ? 0x00100000
	and	%o2,2040,%o2		! (4_0) hx &= 0x7f8;
	faddd	%f34,K3,%f60		! (0_0) res += K3;

	fmuld	%f28,%f28,%f28		! (3_0) dtmp0 = dexp_hi * dexp_hi;
	bl,pn	%icc,.update9		! (4_0) if ( hx < 0x00100000 )
	sub	%g0,%o7,%o7		! (4_0) iexp = -iexp;
	fand	%f0,DC0,%f16		! (5_0) res = vis_fand(res,DC0);
.cont9:
	add	%o7,1534,%o7		! (4_0) iexp += 0x5fe;
	fpadd32	%f24,DC2,%f18		! (4_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f36,%f10		! (2_0) res = K6 * xx;
	add	%o2,8,%l1		! (4_0) hx += 8;
	fsubd	%f44,%f40,%f44		! (3_0) xx = res - res_c;

	fmuld	%f60,%f32,%f60		! (0_0) res *= xx;
	faddd	%f62,K4,%f6		! (1_0) res += K4;

	lda	[%i0]%asi,%g1		! (5_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (4_0) iexp << 52;
	and	%l1,-16,%l1		! (4_0) hx = -16;
	faddd	%f58,K1,%f58		! (6_1) res += K1;

	add	%i0,stridex,%i1		! px += stridex
	add	%l1,TBL,%l1		! (4_0) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp6]		! (4_0) dlexp = *(double*)lexp;

	fmuld	%f44,%f28,%f40		! (3_0) xx *= dtmp0;
	ldd	[%l1],%f44		! (4_0) dtmp0 = ((double*)addr)[0];
	faddd	%f10,K5,%f62		! (2_0) res += K5;

	fmuld	%f6,%f38,%f34		! (1_0) res *= xx;
	sra	%g1,21,%o7		! (5_0) iexp = hx >> 21;
	nop
	faddd	%f60,K2,%f60		! (0_0) res += K2;

	for	%f16,DC1,%f28		! (5_0) res = vis_for(res,DC1);
	sub	%g0,%o7,%o7		! (5_0) iexp = -iexp;
	lda	[%i1]%asi,%f6		! (6_0) ((float*)res)[0] = ((float*)px)[0];
	fmuld	%f58,%f26,%f26		! (6_1) res *= xx;

	sra	%g1,10,%o2		! (5_0) hx >>= 10;
	cmp	%g1,_0x7ff00000		! (5_0) hx ? 0x7ff00000
	bge,pn	%icc,.update10		! (5_0) if ( hx >= 0x7ff00000 )
	lda	[%i1+4]%asi,%f7		! (6_0) ((float*)res)[1] = ((float*)px)[1];
.cont10:
	fand	%f18,DC3,%f8		! (4_0) res_c = vis_fand(res_c,DC3);
	fmuld	%f62,%f36,%f62		! (2_0) res *= xx;

	fmuld	%f60,%f32,%f58		! (0_0) res *= xx;
	cmp	%g1,_0x00100000		! (5_0) hx ? 0x00100000
	and	%o2,2040,%o2		! (5_0) hx &= 0x7f8;
	faddd	%f34,K3,%f34		! (1_0) res += K3;

	fmuld	%f30,%f26,%f26		! (6_1) res = dexp_hi * res;
	bl,pn	%icc,.update11		! (5_0) if ( hx < 0x00100000 )
	nop
	fand	%f6,DC0,%f16		! (6_0) res = vis_fand(res,DC0);
.cont11:
	ldd	[%l4+8],%f60		! (6_1) dexp_lo = ((double*)addr)[1];
	fmuld	%f44,%f44,%f44		! (4_0) dtmp0 = dexp_hi * dexp_hi;
	fpadd32	%f28,DC2,%f18		! (5_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f40,%f22		! (3_0) res = K6 * xx;
	add	%o2,8,%i3		! (5_0) hx += 8;
	fsubd	%f24,%f8,%f10		! (4_0) xx = res - res_c;

	fmuld	%f34,%f38,%f24		! (1_0) res *= xx;
	or	%g0,%o4,%i0

	cmp	counter,7
	bl,pn	%icc,.tail
	faddd	%f62,K4,%f34		! (2_0) res += K4;

	ba	.main_loop
	sub	counter,7,counter	! counter

	.align	16
.main_loop:
	add	%o7,1534,%o7		! (5_0) iexp += 0x5fe;
	and	%i3,-16,%i3		! (5_1) hx = -16;
	lda	[%i1]%asi,%g1		! (6_1) hx = *(int*)px;
	faddd	%f58,K1,%f58		! (0_1) res += K1;

	add	%i3,TBL,%i3		! (5_1) addr = (char*)arr + hx;
	sllx	%o7,52,%o7		! (5_1) iexp << 52;
	stx	%o7,[%fp+tmp0]		! (5_1) dlexp = *(double*)lexp;
	faddd	%f26,%f60,%f8		! (6_2) res += dexp_lo;

	faddd	%f22,K5,%f62		! (3_1) res += K5;
	add	%i1,stridex,%l6		! px += stridex
	ldd	[%i3],%f22		! (5_1) dtmp0 = ((double*)addr)[0];
	fmuld	%f10,%f44,%f60		! (4_1) xx *= dtmp0;

	faddd	%f24,K2,%f26		! (1_1) res += K2;
	add	%i0,stridey,%i1		! px += stridey
	ldd	[%l2],%f24		! (0_1) dexp_hi = ((double*)addr)[0];
	fmuld	%f34,%f36,%f34		! (2_1) res *= xx;

	fmuld	%f58,%f32,%f58		! (0_1) res *= xx;
	sra	%g1,21,%o7		! (6_1) iexp = hx >> 21;
	lda	[%l6]%asi,%f0		! (0_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f44		! (6_1) res = vis_for(res,DC1);

	lda	[%l6+4]%asi,%f1		! (0_0) ((float*)res)[1] = ((float*)px)[1];
	sra	%g1,10,%o2		! (6_1) hx >>= 10;
	fmuld	%f22,%f22,%f10		! (5_1) dtmp0 = dexp_hi * dexp_hi;
	faddd	%f8,%f30,%f30		! (6_2) res += dexp_hi;

	fmuld	%f62,%f40,%f32		! (3_1) res *= xx;
	cmp	%g1,_0x7ff00000		! (6_1) hx ? 0x7ff00000
	ldd	[%fp+tmp1],%f62		! (6_2) dlexp = *(double*)lexp;
	fand	%f18,DC3,%f8		! (5_1) res_c = vis_fand(res_c,DC3);

	fmuld	%f26,%f38,%f26		! (1_1) res *= xx;
	bge,pn	%icc,.update12		! (6_1) if ( hx >= 0x7ff00000 )
	and	%o2,2040,%o2		! (6_1) hx &= 0x7f8;
	faddd	%f34,K3,%f34		! (2_1) res += K3;
.cont12:
	fmuld	%f24,%f58,%f58		! (0_1) res = dexp_hi * res;
	cmp	%g1,_0x00100000		! (6_1) hx ? 0x00100000
	sub	%g0,%o7,%o7		! (6_1) iexp = -iexp;
	fand	%f0,DC0,%f16		! (0_0) res = vis_fand(res,DC0);

	fmuld	%f30,%f62,%f2		! (6_2) res *= dlexp;
	bl,pn	%icc,.update13		! (6_1) if ( hx < 0x00100000 )
	ldd	[%l2+8],%f30		! (0_1) dexp_lo = ((double*)addr)[1];
	fpadd32	%f44,DC2,%f18		! (6_1) res_c = vis_fpadd32(res,DC2);
.cont13:
	fmuld	K6,%f60,%f62		! (4_1) res = K6 * xx;
	add	%o2,8,%l4		! (6_1) hx += 8;
	st	%f2,[%i0]		! (6_2) ((float*)py)[0] = ((float*)res)[0];
	fsubd	%f28,%f8,%f6		! (5_1) xx = res - res_c;

	fmuld	%f34,%f36,%f28		! (2_1) res *= xx;
	add	%o7,1534,%o7		! (6_1) iexp += 0x5fe;
	st	%f3,[%i0+4]		! (6_2) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f32,K4,%f32		! (3_1) res += K4;

	lda	[%l6]%asi,%g1		! (0_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (6_1) iexp << 52;
	and	%l4,-16,%l4		! (6_1) hx = -16;
	faddd	%f26,K1,%f26		! (1_1) res += K1;

	add	%i1,stridey,%i0		! px += stridey
	add	%l4,TBL,%l4		! (6_1) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp1]		! (6_1) dlexp = *(double*)lexp;
	faddd	%f58,%f30,%f8		! (0_1) res += dexp_lo;

	fmuld	%f6,%f10,%f58		! (5_1) xx *= dtmp0;
	add	%l6,stridex,%l6		! px += stridex
	ldd	[%l4],%f30		! (6_1) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (4_1) res += K5;

	fmuld	%f32,%f40,%f34		! (3_1) res *= xx;
	sra	%g1,10,%o2		! (0_0) hx >>= 10;
	ldd	[%i2],%f4		! (1_1) dexp_hi = ((double*)addr)[0];
	faddd	%f28,K2,%f32		! (2_1) res += K2;

	fmuld	%f26,%f38,%f26		! (1_1) res *= xx;
	sra	%g1,21,%o7		! (0_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f6		! (1_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f28		! (0_0) res = vis_for(res,DC1);

	fmuld	%f30,%f30,%f30		! (6_1) dtmp0 = dexp_hi * dexp_hi;
	sub	%g0,%o7,%o7		! (0_0) iexp = -iexp;
	lda	[%l6+4]%asi,%f7		! (1_0) ((float*)res)[1] = ((float*)px)[1];
	faddd	%f8,%f24,%f24		! (0_1) res += dexp_hi;

	fmuld	%f62,%f60,%f38		! (4_1) res *= xx;
	cmp	%g1,_0x7ff00000		! (0_0) hx ? 0x7ff00000
	ldd	[%fp+tmp2],%f62		! (0_1) dlexp = *(double*)lexp;
	fand	%f18,DC3,%f8		! (6_1) res_c = vis_fand(res_c,DC3);

	fmuld	%f32,%f36,%f32		! (2_1) res *= xx;
	bge,pn	%icc,.update14		! (0_0) if ( hx >= 0x7ff00000 )
	and	%o2,2040,%o2		! (0_0) hx &= 0x7f8;
	faddd	%f34,K3,%f34		! (3_1) res += K3;
.cont14:
	fmuld	%f4,%f26,%f26		! (1_1) res = dexp_hi * res;
	cmp	%g1,_0x00100000		! (0_0) hx ? 0x00100000
	add	%o7,1534,%o7		! (0_0) iexp += 0x5fe;
	fand	%f6,DC0,%f16		! (1_0) res = vis_fand(res,DC0);

	fmuld	%f24,%f62,%f2		! (0_1) res *= dlexp;
	bl,pn	%icc,.update15		! (0_0) if ( hx < 0x00100000 )
	ldd	[%i2+8],%f24		! (1_1) dexp_lo = ((double*)addr)[1];
	fpadd32	%f28,DC2,%f18		! (0_0) res_c = vis_fpadd32(res,DC2);
.cont15:
	fmuld	K6,%f58,%f62		! (5_1) res = K6 * xx;
	add	%o2,8,%l2		! (0_0) hx += 8;
	st	%f2,[%i1]		! (0_1) ((float*)py)[0] = ((float*)res)[0];
	fsubd	%f44,%f8,%f10		! (6_1) xx = res - res_c;

	fmuld	%f34,%f40,%f44		! (3_1) res *= xx;
	nop
	st	%f3,[%i1+4]		! (0_1) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f38,K4,%f38		! (4_1) res += K4;

	lda	[%l6]%asi,%g1		! (1_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (0_0) iexp << 52;
	and	%l2,-16,%l2		! (0_0) hx = -16;
	faddd	%f32,K1,%f32		! (2_1) res += K1;

	add	%l2,TBL,%l2		! (0_0) addr = (char*)arr + hx;
	add	%l6,stridex,%l6		! px += stridex
	stx	%o7,[%fp+tmp2]		! (0_0) dlexp = *(double*)lexp;
	faddd	%f26,%f24,%f8		! (1_1) res += dexp_lo;

	fmuld	%f10,%f30,%f26		! (6_1) xx *= dtmp0;
	add	%i0,stridey,%i1		! px += stridey
	ldd	[%l2],%f30		! (0_0) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (5_1) res += K5;

	fmuld	%f38,%f60,%f34		! (4_1) res *= xx;
	sra	%g1,10,%o2		! (1_0) hx >>= 10;
	ldd	[%i4],%f24		! (2_1) dexp_hi = ((double*)addr)[0];
	faddd	%f44,K2,%f38		! (3_1) res += K2;

	fmuld	%f32,%f36,%f32		! (2_1) res *= xx;
	sra	%g1,21,%o7		! (1_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f0		! (2_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f44		! (1_0) res = vis_for(res,DC1);

	fmuld	%f30,%f30,%f30		! (0_0) dtmp0 = dexp_hi * dexp_hi;
	cmp	%g1,_0x7ff00000		! (1_0) hx ? 0x7ff00000
	lda	[%l6+4]%asi,%f1		! (2_0) ((float*)res)[1] = ((float*)px)[1];
	faddd	%f8,%f4,%f4		! (1_1) res += dexp_hi;

	fmuld	%f62,%f58,%f36		! (5_1) res *= xx;
	bge,pn	%icc,.update16		! (1_0) if ( hx >= 0x7ff00000 )
	ldd	[%fp+tmp3],%f62		! (1_1) dlexp = *(double*)lexp;
	fand	%f18,DC3,%f8		! (0_0) res_c = vis_fand(res_c,DC3);
.cont16:
	fmuld	%f38,%f40,%f38		! (3_1) res *= xx;
	cmp	%g1,_0x00100000		! (1_0) hx ? 0x00100000
	and	%o2,2040,%o2		! (1_0) hx &= 0x7f8;
	faddd	%f34,K3,%f34		! (4_1) res += K3;

	fmuld	%f24,%f32,%f32		! (2_1) res = dexp_hi * res;
	bl,pn	%icc,.update17		! (1_0) if ( hx < 0x00100000 )
	sub	%g0,%o7,%o7		! (1_0) iexp = -iexp;
	fand	%f0,DC0,%f16		! (2_0) res = vis_fand(res,DC0);
.cont17:
	fmuld	%f4,%f62,%f2		! (1_1) res *= dlexp;
	add	%o7,1534,%o7		! (1_0) iexp += 0x5fe;
	ldd	[%i4+8],%f4		! (2_1) dexp_lo = ((double*)addr)[1];
	fpadd32	%f44,DC2,%f18		! (1_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f26,%f62		! (6_1) res = K6 * xx;
	add	%o2,8,%i2		! (1_0) hx += 8;
	st	%f2,[%i0]		! (1_1) ((float*)py)[0] = ((float*)res)[0];
	fsubd	%f28,%f8,%f6		! (0_0) xx = res - res_c;

	fmuld	%f34,%f60,%f28		! (4_1) res *= xx;
	nop
	st	%f3,[%i0+4]		! (1_1) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f36,K4,%f36		! (5_1) res += K4;

	lda	[%l6]%asi,%g1		! (2_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (1_0) iexp << 52;
	and	%i2,-16,%i2		! (1_0) hx = -16;
	faddd	%f38,K1,%f38		! (3_1) res += K1;

	add	%i1,stridey,%i0		! px += stridey
	add	%i2,TBL,%i2		! (1_0) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp3]		! (1_0) dlexp = *(double*)lexp;
	faddd	%f32,%f4,%f8		! (2_1) res += dexp_lo;

	fmuld	%f6,%f30,%f32		! (0_0) xx *= dtmp0;
	add	%l6,stridex,%l6		! px += stridex
	ldd	[%i2],%f30		! (1_0) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (6_1) res += K5;

	fmuld	%f36,%f58,%f34		! (5_1) res *= xx;
	sra	%g1,10,%o2		! (2_0) hx >>= 10;
	ldd	[%i5],%f4		! (3_1) dexp_hi = ((double*)addr)[0];
	faddd	%f28,K2,%f36		! (4_1) res += K2;

	fmuld	%f38,%f40,%f38		! (3_1) res *= xx;
	sra	%g1,21,%o7		! (2_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f6		! (3_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f28		! (2_0) res = vis_for(res,DC1);

	fmuld	%f30,%f30,%f30		! (1_0) dtmp0 = dexp_hi * dexp_hi;
	cmp	%g1,_0x7ff00000		! (2_0) hx ? 0x7ff00000
	lda	[%l6+4]%asi,%f7		! (3_0) ((float*)res)[1] = ((float*)px)[1];
	faddd	%f8,%f24,%f24		! (2_1) res += dexp_hi;

	fmuld	%f62,%f26,%f40		! (6_1) res *= xx;
	bge,pn	%icc,.update18		! (2_0) if ( hx >= 0x7ff00000 )
	ldd	[%fp+tmp4],%f62		! (2_1) dlexp = *(double*)lexp;
	fand	%f18,DC3,%f8		! (1_0) res_c = vis_fand(res_c,DC3);
.cont18:
	fmuld	%f36,%f60,%f36		! (4_1) res *= xx;
	cmp	%g1,_0x00100000		! (2_0) hx ? 0x00100000
	and	%o2,2040,%o2		! (2_0) hx &= 0x7f8;
	faddd	%f34,K3,%f34		! (5_1) res += K3;

	fmuld	%f4,%f38,%f38		! (3_1) res = dexp_hi * res;
	bl,pn	%icc,.update19		! (2_0) if ( hx < 0x00100000 )
	sub	%g0,%o7,%o7		! (2_0) iexp = -iexp;
	fand	%f6,DC0,%f16		! (3_0) res = vis_fand(res,DC0);
.cont19:
	fmuld	%f24,%f62,%f2		! (2_1) res *= dlexp;
	add	%o7,1534,%o7		! (2_0) iexp += 0x5fe;
	ldd	[%i5+8],%f24		! (3_1) dexp_lo = ((double*)addr)[1];
	fpadd32	%f28,DC2,%f18		! (2_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f32,%f62		! (0_0) res = K6 * xx;
	add	%o2,8,%i4		! (2_0) hx += 8;
	st	%f2,[%i1]		! (2_1) ((float*)py)[0] = ((float*)res)[0];
	fsubd	%f44,%f8,%f10		! (1_0) xx = res - res_c;

	fmuld	%f34,%f58,%f44		! (5_1) res *= xx;
	nop
	st	%f3,[%i1+4]		! (2_1) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f40,K4,%f40		! (6_1) res += K4;

	lda	[%l6]%asi,%g1		! (3_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (2_0) iexp << 52;
	and	%i4,-16,%i4		! (2_0) hx = -16;
	faddd	%f36,K1,%f36		! (4_1) res += K1;

	add	%l6,stridex,%l6		! px += stridex
	add	%i4,TBL,%i4		! (2_0) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp4]		! (2_0) dlexp = *(double*)lexp;
	faddd	%f38,%f24,%f8		! (3_1) res += dexp_lo;

	fmuld	%f10,%f30,%f38		! (1_0) xx *= dtmp0;
	add	%i0,stridey,%i1		! px += stridey
	ldd	[%i4],%f24		! (2_0) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (0_0) res += K5;

	fmuld	%f40,%f26,%f34		! (6_1) res *= xx;
	sra	%g1,10,%o2		! (3_0) hx >>= 10;
	ldd	[%l1],%f30		! (4_1) dexp_hi = ((double*)addr)[0];
	faddd	%f44,K2,%f40		! (5_1) res += K2;

	fmuld	%f36,%f60,%f36		! (4_1) res *= xx;
	sra	%g1,21,%o7		! (3_0) iexp = hx >> 21;
	lda	[%l6]%asi,%f0		! (4_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f44		! (3_0) res = vis_for(res,DC1);

	fmuld	%f24,%f24,%f24		! (2_0) dtmp0 = dexp_hi * dexp_hi;
	cmp	%g1,_0x7ff00000		! (3_0) hx ? 0x7ff00000
	lda	[%l6+4]%asi,%f1		! (4_0) ((float*)res)[1] = ((float*)px)[1];
	faddd	%f8,%f4,%f8		! (3_1) res += dexp_hi;

	fmuld	%f62,%f32,%f60		! (0_0) res *= xx;
	bge,pn	%icc,.update20		! (3_0) if ( hx >= 0x7ff00000 )
	ldd	[%fp+tmp5],%f62		! (3_1) dlexp = *(double*)lexp;
	fand	%f18,DC3,%f4		! (2_0) res_c = vis_fand(res_c,DC3);
.cont20:
	fmuld	%f40,%f58,%f40		! (5_1) res *= xx;
	cmp	%g1,_0x00100000		! (3_0) hx ? 0x00100000
	and	%o2,2040,%o2		! (3_0) hx &= 0x7f8;
	faddd	%f34,K3,%f10		! (6_1) res += K3;

	fmuld	%f30,%f36,%f36		! (4_1) res = dexp_hi * res;
	bl,pn	%icc,.update21		! (3_0) if ( hx < 0x00100000 )
	sub	%g0,%o7,%o7		! (3_0) iexp = -iexp;
	fand	%f0,DC0,%f16		! (4_0) res = vis_fand(res,DC0);
.cont21:
	fmuld	%f8,%f62,%f8		! (3_1) res *= dlexp;
	add	%o7,1534,%o7		! (3_0) iexp += 0x5fe;
	ldd	[%l1+8],%f34		! (4_1) dexp_lo = ((double*)addr)[1];
	fpadd32	%f44,DC2,%f18		! (3_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f38,%f62		! (1_0) res = K6 * xx;
	add	%o2,8,%i5		! (3_0) hx += 8;
	st	%f8,[%i0]		! (3_1) ((float*)py)[0] = ((float*)res)[0];
	fsubd	%f28,%f4,%f28		! (2_0) xx = res - res_c;

	fmuld	%f10,%f26,%f4		! (6_1) res *= xx;
	nop
	st	%f9,[%i0+4]		! (3_1) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f60,K4,%f60		! (0_0) res += K4;

	lda	[%l6]%asi,%g1		! (4_0) hx = *(int*)px;
	sllx	%o7,52,%o7		! (3_0) iexp << 52;
	and	%i5,-16,%i5		! (3_0) hx = -16;
	faddd	%f40,K1,%f40		! (5_1) res += K1;

	add	%l6,stridex,%i0		! px += stridex
	add	%i5,TBL,%i5		! (3_0) addr = (char*)arr + hx;
	stx	%o7,[%fp+tmp5]		! (3_0) dlexp = *(double*)lexp;
	faddd	%f36,%f34,%f8		! (4_1) res += dexp_lo;

	fmuld	%f28,%f24,%f36		! (2_0) xx *= dtmp0;
	add	%i1,stridey,%l6		! px += stridey
	ldd	[%i5],%f28		! (3_0) dtmp0 = ((double*)addr)[0];
	faddd	%f62,K5,%f62		! (1_0) res += K5;

	faddd	%f4,K2,%f10		! (6_1) res += K2;
	sra	%g1,10,%o2		! (4_0) hx >>= 10;
	nop
	fmuld	%f60,%f32,%f34		! (0_0) res *= xx;

	fmuld	%f40,%f58,%f40		! (5_1) res *= xx;
	sra	%g1,21,%o7		! (4_0) iexp = hx >> 21;
	lda	[%i0]%asi,%f6		! (5_0) ((float*)res)[0] = ((float*)px)[0];
	for	%f16,DC1,%f24		! (4_0) res = vis_for(res,DC1);

	fmuld	%f28,%f28,%f28		! (3_0) dtmp0 = dexp_hi * dexp_hi;
	cmp	%g1,_0x7ff00000		! (4_0) hx ? 0x7ff00000
	lda	[%i0+4]%asi,%f7		! (5_0) ((float*)res)[1] = ((float*)px)[1];
	faddd	%f8,%f30,%f30		! (4_1) res += dexp_hi;

	fand	%f18,DC3,%f8		! (3_0) res_c = vis_fand(res_c,DC3);
	bge,pn	%icc,.update22		! (4_0) if ( hx >= 0x7ff00000 )
	ldd	[%fp+tmp6],%f18		! (4_1) dlexp = *(double*)lexp;
	fmuld	%f62,%f38,%f62		! (1_0) res *= xx;
.cont22:
	fmuld	%f10,%f26,%f58		! (6_1) res *= xx;
	cmp	%g1,_0x00100000		! (4_0) hx ? 0x00100000
	and	%o2,2040,%o2		! (4_0) hx &= 0x7f8;
	faddd	%f34,K3,%f60		! (0_0) res += K3;

	fmuld	%f22,%f40,%f40		! (5_1) res = dexp_hi * res;
	bl,pn	%icc,.update23		! (4_0) if ( hx < 0x00100000 )
	sub	%g0,%o7,%o7		! (4_0) iexp = -iexp;
	fand	%f6,DC0,%f16		! (5_0) res = vis_fand(res,DC0);
.cont23:
	fmuld	%f30,%f18,%f6		! (4_1) res *= dlexp;
	add	%o7,1534,%o7		! (4_0) iexp += 0x5fe;
	ldd	[%i3+8],%f34		! (5_1) dexp_lo = ((double*)addr)[1];
	fpadd32	%f24,DC2,%f18		! (4_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f36,%f30		! (2_0) res = K6 * xx;
	add	%o2,8,%l1		! (4_0) hx += 8;
	st	%f6,[%i1]		! (4_1) ((float*)py)[0] = ((float*)res)[0];
	fsubd	%f44,%f8,%f44		! (3_0) xx = res - res_c;

	fmuld	%f60,%f32,%f60		! (0_0) res *= xx;
	sllx	%o7,52,%o7		! (4_0) iexp << 52;
	st	%f7,[%i1+4]		! (4_1) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f62,K4,%f6		! (1_0) res += K4;

	lda	[%i0]%asi,%g1		! (5_0) hx = *(int*)px;
	add	%i0,stridex,%i1		! px += stridex
	and	%l1,-16,%l1		! (4_0) hx = -16;
	faddd	%f58,K1,%f58		! (6_1) res += K1;

	add	%l1,TBL,%l1		! (4_0) addr = (char*)arr + hx;
	add	%l6,stridey,%i0		! px += stridey
	stx	%o7,[%fp+tmp6]		! (4_0) dlexp = *(double*)lexp;
	faddd	%f40,%f34,%f8		! (5_1) res += dexp_lo;

	fmuld	%f44,%f28,%f40		! (3_0) xx *= dtmp0;
	nop
	ldd	[%l1],%f44		! (4_0) dtmp0 = ((double*)addr)[0];
	faddd	%f30,K5,%f62		! (2_0) res += K5;

	fmuld	%f6,%f38,%f34		! (1_0) res *= xx;
	sra	%g1,21,%o7		! (5_0) iexp = hx >> 21;
	ldd	[%l4],%f30		! (6_1) dexp_hi = ((double*)addr)[0];
	faddd	%f60,K2,%f60		! (0_0) res += K2;

	for	%f16,DC1,%f28		! (5_0) res = vis_for(res,DC1);
	sub	%g0,%o7,%o7		! (5_0) iexp = -iexp;
	lda	[%i1]%asi,%f6		! (6_0) ((float*)res)[0] = ((float*)px)[0];
	fmuld	%f58,%f26,%f26		! (6_1) res *= xx;

	fmuld	%f44,%f44,%f44		! (4_0) dtmp0 = dexp_hi * dexp_hi;
	cmp	%g1,_0x7ff00000		! (5_0) hx ? 0x7ff00000
	lda	[%i1+4]%asi,%f7		! (6_0) ((float*)res)[1] = ((float*)px)[1];
	faddd	%f8,%f22,%f22		! (5_1) res += dexp_hi;

	fand	%f18,DC3,%f8		! (4_0) res_c = vis_fand(res_c,DC3);
	bge,pn	%icc,.update24		! (5_0) if ( hx >= 0x7ff00000 )
	ldd	[%fp+tmp0],%f18		! (5_1) dlexp = *(double*)lexp;
	fmuld	%f62,%f36,%f62		! (2_0) res *= xx;
.cont24:
	fmuld	%f60,%f32,%f58		! (0_0) res *= xx;
	sra	%g1,10,%o2		! (5_0) hx >>= 10;
	cmp	%g1,_0x00100000		! (5_0) hx ? 0x00100000
	faddd	%f34,K3,%f34		! (1_0) res += K3;

	fmuld	%f30,%f26,%f26		! (6_1) res = dexp_hi * res;
	bl,pn	%icc,.update25		! (5_0) if ( hx < 0x00100000 )
	and	%o2,2040,%o2		! (5_0) hx &= 0x7f8;
	fand	%f6,DC0,%f16		! (6_0) res = vis_fand(res,DC0);
.cont25:
	fmuld	%f22,%f18,%f2		! (5_1) res *= dlexp;
	subcc	counter,7,counter	! counter -= 7;
	ldd	[%l4+8],%f60		! (6_1) dexp_lo = ((double*)addr)[1];
	fpadd32	%f28,DC2,%f18		! (5_0) res_c = vis_fpadd32(res,DC2);

	fmuld	K6,%f40,%f22		! (3_0) res = K6 * xx;
	add	%o2,8,%i3		! (5_0) hx += 8;
	st	%f2,[%l6]		! (5_1) ((float*)py)[0] = ((float*)res)[0];
	fsubd	%f24,%f8,%f10		! (4_0) xx = res - res_c;

	fmuld	%f34,%f38,%f24		! (1_0) res *= xx;
	st	%f3,[%l6+4]		! (5_1) ((float*)py)[1] = ((float*)res)[1];
	bpos,pt	%icc,.main_loop
	faddd	%f62,K4,%f34		! (2_0) res += K4;

	add	counter,7,counter
.tail:
	add	%o7,1534,%o7		! (5_0) iexp += 0x5fe;
	subcc	counter,1,counter
	bneg,a	.begin
	mov	%i0,%o4

	faddd	%f58,K1,%f58		! (0_1) res += K1;

	faddd	%f26,%f60,%f8		! (6_2) res += dexp_lo;

	faddd	%f22,K5,%f62		! (3_1) res += K5;
	fmuld	%f10,%f44,%f60		! (4_1) xx *= dtmp0;

	faddd	%f24,K2,%f26		! (1_1) res += K2;
	add	%i1,stridex,%l6		! px += stridex
	ldd	[%l2],%f24		! (0_1) dexp_hi = ((double*)addr)[0];
	fmuld	%f34,%f36,%f34		! (2_1) res *= xx;

	fmuld	%f58,%f32,%f58		! (0_1) res *= xx;

	add	%i0,stridey,%i1		! px += stridey
	faddd	%f8,%f30,%f30		! (6_2) res += dexp_hi;

	fmuld	%f62,%f40,%f32		! (3_1) res *= xx;
	ldd	[%fp+tmp1],%f62		! (6_2) dlexp = *(double*)lexp;

	fmuld	%f26,%f38,%f26		! (1_1) res *= xx;
	faddd	%f34,K3,%f34		! (2_1) res += K3;

	fmuld	%f24,%f58,%f58		! (0_1) res = dexp_hi * res;

	fmuld	%f30,%f62,%f2		! (6_2) res *= dlexp;
	ldd	[%l2+8],%f30		! (0_1) dexp_lo = ((double*)addr)[1];

	fmuld	K6,%f60,%f62		! (4_1) res = K6 * xx;
	st	%f2,[%i0]		! (6_2) ((float*)py)[0] = ((float*)res)[0];

	fmuld	%f34,%f36,%f28		! (2_1) res *= xx;
	st	%f3,[%i0+4]		! (6_2) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f32,K4,%f32		! (3_1) res += K4;

	subcc	counter,1,counter
	bneg,a	.begin
	mov	%i1,%o4

	faddd	%f26,K1,%f26		! (1_1) res += K1;

	faddd	%f58,%f30,%f8		! (0_1) res += dexp_lo;

	add	%l6,stridex,%l6		! px += stridex
	faddd	%f62,K5,%f62		! (4_1) res += K5;

	fmuld	%f32,%f40,%f34		! (3_1) res *= xx;
	add	%i1,stridey,%i0		! px += stridey
	ldd	[%i2],%f22		! (1_1) dexp_hi = ((double*)addr)[0];
	faddd	%f28,K2,%f32		! (2_1) res += K2;

	fmuld	%f26,%f38,%f26		! (1_1) res *= xx;

	faddd	%f8,%f24,%f24		! (0_1) res += dexp_hi;

	fmuld	%f62,%f60,%f38		! (4_1) res *= xx;
	ldd	[%fp+tmp2],%f62		! (0_1) dlexp = *(double*)lexp;

	fmuld	%f32,%f36,%f32		! (2_1) res *= xx;
	faddd	%f34,K3,%f34		! (3_1) res += K3;

	fmuld	%f22,%f26,%f26		! (1_1) res = dexp_hi * res;

	fmuld	%f24,%f62,%f2		! (0_1) res *= dlexp;
	ldd	[%i2+8],%f24		! (1_1) dexp_lo = ((double*)addr)[1];

	st	%f2,[%i1]		! (0_1) ((float*)py)[0] = ((float*)res)[0];

	fmuld	%f34,%f40,%f44		! (3_1) res *= xx;
	st	%f3,[%i1+4]		! (0_1) ((float*)py)[1] = ((float*)res)[1];
	faddd	%f38,K4,%f38		! (4_1) res += K4;

	subcc	counter,1,counter
	bneg,a	.begin
	mov	%i0,%o4

	faddd	%f32,K1,%f32		! (2_1) res += K1;

	add	%l6,stridex,%l6		! px += stridex
	faddd	%f26,%f24,%f8		! (1_1) res += dexp_lo;

	add	%i0,stridey,%i1		! px += stridey

	fmuld	%f38,%f60,%f34		! (4_1) res *= xx;
	ldd	[%i4],%f24		! (2_1) dexp_hi = ((double*)addr)[0];
	faddd	%f44,K2,%f38		! (3_1) res += K2;

	fmuld	%f32,%f36,%f32		! (2_1) res *= xx;

	faddd	%f8,%f22,%f22		! (1_1) res += dexp_hi;

	ldd	[%fp+tmp3],%f62		! (1_1) dlexp = *(double*)lexp;

	fmuld	%f38,%f40,%f38		! (3_1) res *= xx;
	faddd	%f34,K3,%f34		! (4_1) res += K3;

	fmuld	%f24,%f32,%f32		! (2_1) res = dexp_hi * res;

	fmuld	%f22,%f62,%f2		! (1_1) res *= dlexp;
	ldd	[%i4+8],%f22		! (2_1) dexp_lo = ((double*)addr)[1];

	st	%f2,[%i0]		! (1_1) ((float*)py)[0] = ((float*)res)[0];

	fmuld	%f34,%f60,%f28		! (4_1) res *= xx;
	st	%f3,[%i0+4]		! (1_1) ((float*)py)[1] = ((float*)res)[1];

	subcc	counter,1,counter
	bneg,a	.begin
	mov	%i1,%o4

	faddd	%f38,K1,%f38		! (3_1) res += K1;

	faddd	%f32,%f22,%f8		! (2_1) res += dexp_lo;

	add	%l6,stridex,%l6		! px += stridex

	add	%i1,stridey,%i0		! px += stridey
	ldd	[%i5],%f22		! (3_1) dexp_hi = ((double*)addr)[0];
	faddd	%f28,K2,%f36		! (4_1) res += K2;

	fmuld	%f38,%f40,%f38		! (3_1) res *= xx;

	faddd	%f8,%f24,%f24		! (2_1) res += dexp_hi;

	ldd	[%fp+tmp4],%f62		! (2_1) dlexp = *(double*)lexp;

	fmuld	%f36,%f60,%f36		! (4_1) res *= xx;

	fmuld	%f22,%f38,%f38		! (3_1) res = dexp_hi * res;

	fmuld	%f24,%f62,%f2		! (2_1) res *= dlexp;
	ldd	[%i5+8],%f24		! (3_1) dexp_lo = ((double*)addr)[1];

	st	%f2,[%i1]		! (2_1) ((float*)py)[0] = ((float*)res)[0];

	st	%f3,[%i1+4]		! (2_1) ((float*)py)[1] = ((float*)res)[1];

	subcc	counter,1,counter
	bneg,a	.begin
	mov	%i0,%o4

	faddd	%f36,K1,%f36		! (4_1) res += K1;

	faddd	%f38,%f24,%f8		! (3_1) res += dexp_lo;

	add	%i0,stridey,%i1		! px += stridey

	add	%l6,stridex,%l6		! px += stridex
	ldd	[%l1],%f30		! (4_1) dexp_hi = ((double*)addr)[0];

	fmuld	%f36,%f60,%f36		! (4_1) res *= xx;

	faddd	%f8,%f22,%f8		! (3_1) res += dexp_hi;

	ldd	[%fp+tmp5],%f62		! (3_1) dlexp = *(double*)lexp;

	fmuld	%f30,%f36,%f36		! (4_1) res = dexp_hi * res;

	fmuld	%f8,%f62,%f8		! (3_1) res *= dlexp;
	ldd	[%l1+8],%f34		! (4_1) dexp_lo = ((double*)addr)[1];

	st	%f8,[%i0]		! (3_1) ((float*)py)[0] = ((float*)res)[0];

	st	%f9,[%i0+4]		! (3_1) ((float*)py)[1] = ((float*)res)[1];

	subcc	counter,1,counter
	bneg,a	.begin
	mov	%i1,%o4

	faddd	%f36,%f34,%f8		! (4_1) res += dexp_lo;

	add	%l6,stridex,%i0		! px += stridex

	add	%i1,stridey,%l6		! px += stridey

	faddd	%f8,%f30,%f30		! (4_1) res += dexp_hi;

	ldd	[%fp+tmp6],%f18		! (4_1) dlexp = *(double*)lexp;

	fmuld	%f30,%f18,%f6		! (4_1) res *= dlexp;

	st	%f6,[%i1]		! (4_1) ((float*)py)[0] = ((float*)res)[0];

	st	%f7,[%i1+4]		! (4_1) ((float*)py)[1] = ((float*)res)[1];

	ba	.begin
	add	%i1,stridey,%o4

	.align	16
.spec0:
	fdivd	DONE,%f0,%f0		! res = DONE / res;
	add	%i1,stridex,%i1		! px += stridex
	st	%f0,[%o4]		! ((float*)py)[0] = ((float*)&res)[0];
	st	%f1,[%o4+4]		! ((float*)py)[1] = ((float*)&res)[1];
	add	%o4,stridey,%o4		! py += stridey
	ba	.begin1
	sub	counter,1,counter

	.align	16
.spec1:
	orcc	%i2,%l4,%g0
	bz,a	2f
	fdivd	DONE,%f0,%f0		! res = DONE / res;

	cmp	%g1,0
	bl,a	2f
	fsqrtd	%f0,%f0			! res = sqrt(res);

	cmp	%g1,%i4
	bge,a	1f
	ldd	[%o3+0x50],%f18

	fxtod	%f0,%f0			! res = *(long long*)&res;
	st	%f0,[%fp+tmp0]

	fand	%f0,DC0,%f16		! (6_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp0],%g1

	sra	%g1,21,%o7		! (6_1) iexp = hx >> 21;
	for	%f16,DC1,%f44		! (6_1) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (6_1) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (6_1) hx &= 0x7f8;
	ba	.cont_spec
	sub	%g0,%o7,%o7		! (6_1) iexp = -iexp;

1:
	fand	%f0,%f18,%f0		! res = vis_fand(res,DC4);

	ldd	[%o3+0x58],%f28
	fxtod	%f0,%f0			! res = *(long long*)&res;

	faddd	%f0,%f28,%f0		! res += D2ON51;
	st	%f0,[%fp+tmp0]

	fand	%f0,DC0,%f16		! (6_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp0],%g1

	sra	%g1,21,%o7		! (6_1) iexp = hx >> 21;
	for	%f16,DC1,%f44		! (6_1) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (6_1) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (6_1) hx &= 0x7f8;
	ba	.cont_spec
	sub	%g0,%o7,%o7		! (6_1) iexp = -iexp;

2:
	add	%i1,stridex,%i1		! px += stridex
	st	%f0,[%o4]		! ((float*)py)[0] = ((float*)&res)[0];
	st	%f1,[%o4+4]		! ((float*)py)[1] = ((float*)&res)[1];
	add	%o4,stridey,%o4		! py += stridey
	ba	.begin1
	sub	counter,1,counter

	.align	16
.update0:
	cmp	counter,1
	ble	.cont0
	nop

	sub	%l6,stridex,tmp_px
	sub	counter,1,tmp_counter

	ba	.cont0
	mov	1,counter

	.align	16
.update1:
	cmp	counter,1
	ble	.cont1
	sub	%l6,stridex,%i1

	ld	[%i1+4],%i2
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i2,%g0
	bz	1f
	sethi	%hi(0x00080000),%i3

	cmp	%g1,%i3
	bge,a	2f
	ldd	[%o3+0x50],%f18

	fxtod	%f8,%f8			! res = *(long long*)&res;
	st	%f8,[%fp+tmp7]

	fand	%f8,DC0,%f16		! (0_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (0_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (0_0) hx >>= 10;
	for	%f16,DC1,%f28		! (0_0) res = vis_for(res,DC1);

	sub	%o7,537,%o7

	sub	%g0,%o7,%o7		! (0_0) iexp = -iexp;

	and	%o2,2040,%o2		! (0_0) hx &= 0x7f8;
	ba	.cont1
	add	%o7,1534,%o7		! (0_0) iexp += 0x5fe;
2:
	fand	%f8,%f18,%f8
	fxtod	%f8,%f8			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f18
	faddd	%f8,%f18,%f8
	st	%f8,[%fp+tmp7]

	fand	%f8,DC0,%f16		! (0_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (0_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (0_0) hx >>= 10;
	for	%f16,DC1,%f28		! (0_0) res = vis_for(res,DC1);

	sub	%o7,537,%o7

	sub	%g0,%o7,%o7		! (0_0) iexp = -iexp;

	and	%o2,2040,%o2		! (0_0) hx &= 0x7f8;
	ba	.cont1
	add	%o7,1534,%o7		! (0_0) iexp += 0x5fe;
1:
	sub	%l6,stridex,tmp_px
	sub	counter,1,tmp_counter

	ba	.cont1
	mov	1,counter

	.align	16
.update2:
	cmp	counter,2
	ble	.cont2
	nop

	sub	%l6,stridex,tmp_px
	sub	counter,2,tmp_counter

	ba	.cont2
	mov	2,counter

	.align	16
.update3:
	cmp	counter,2
	ble	.cont3
	sub	%l6,stridex,%i1

	ld	[%i1+4],%i2
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i2,%g0
	bz	1f
	sethi	%hi(0x00080000),%i3

	cmp	%g1,%i3
	bge,a	2f
	ldd	[%o3+0x50],%f18

	fxtod	%f0,%f0			! res = *(long long*)&res;
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f16		! (1_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (1_0) iexp = hx >> 21;
	for	%f16,DC1,%f44		! (1_0) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (1_0) hx >>= 10;
	sub	%o7,537,%o7
	ba	.cont3
	and	%o2,2040,%o2		! (1_0) hx &= 0x7f8;
2:
	fand	%f0,%f18,%f0
	fxtod	%f0,%f0			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f18
	faddd	%f0,%f18,%f0
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f16		! (1_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (1_0) iexp = hx >> 21;
	for	%f16,DC1,%f44		! (1_0) res = vis_for(res,DC1);

	sra	%g1,10,%o2		! (1_0) hx >>= 10;
	sub	%o7,537,%o7
	ba	.cont3
	and	%o2,2040,%o2		! (1_0) hx &= 0x7f8;
1:
	sub	%l6,stridex,tmp_px
	sub	counter,2,tmp_counter

	ba	.cont3
	mov	2,counter

	.align	16
.update4:
	cmp	counter,3
	ble	.cont4
	nop

	sub	%l6,stridex,tmp_px
	sub	counter,3,tmp_counter

	ba	.cont4
	mov	3,counter

	.align	16
.update5:
	cmp	counter,3
	ble	.cont5
	sub	%l6,stridex,%i1

	ld	[%i1+4],%i3
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i3,%g0
	bz	1f
	sethi	%hi(0x00080000),%i4

	cmp	%g1,%i4
	bge,a	2f
	ldd	[%o3+0x50],%f18

	fxtod	%f6,%f6			! res = *(long long*)&res;
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f16		! (2_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (2_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (2_0) hx >>= 10;

	sub	%o7,537,%o7
	and	%o2,2040,%o2		! (2_0) hx &= 0x7f8;
	ba	.cont5
	for	%f16,DC1,%f28		! (2_0) res = vis_for(res,DC1);
2:
	fand	%f6,%f18,%f6
	fxtod	%f6,%f6			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f18
	faddd	%f6,%f18,%f6
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f16		! (2_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (2_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (2_0) hx >>= 10;

	sub	%o7,537,%o7
	and	%o2,2040,%o2		! (2_0) hx &= 0x7f8;
	ba	.cont5
	for	%f16,DC1,%f28		! (2_0) res = vis_for(res,DC1);
1:
	sub	%l6,stridex,tmp_px
	sub	counter,3,tmp_counter

	ba	.cont5
	mov	3,counter

	.align	16
.update6:
	cmp	counter,4
	ble	.cont6
	nop

	sub	%l6,stridex,tmp_px
	sub	counter,4,tmp_counter

	ba	.cont6
	mov	4,counter

	.align	16
.update7:
	sub	%l6,stridex,%i1
	cmp	counter,4
	ble	.cont7
	faddd	%f34,K3,%f6		! (6_1) res += K3;

	ld	[%i1+4],%i3
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i3,%g0
	bz	1f
	sethi	%hi(0x00080000),%i5

	cmp	%g1,%i5
	bge,a	2f
	ldd	[%o3+0x50],%f18

	fxtod	%f0,%f0			! res = *(long long*)&res;
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f16		! (3_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (3_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (3_0) hx >>= 10;

	sub	%o7,537,%o7
	and	%o2,2040,%o2		! (3_0) hx &= 0x7f8;
	ba	.cont7
	for	%f16,DC1,%f44		! (3_0) res = vis_for(res,DC1);
2:
	fand	%f0,%f18,%f0
	fxtod	%f0,%f0			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f18
	faddd	%f0,%f18,%f0
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f16		! (3_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (3_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (3_0) hx >>= 10;

	sub	%o7,537,%o7
	and	%o2,2040,%o2		! (3_0) hx &= 0x7f8;
	ba	.cont7
	for	%f16,DC1,%f44		! (3_0) res = vis_for(res,DC1);
1:
	sub	%l6,stridex,tmp_px
	sub	counter,4,tmp_counter

	ba	.cont7
	mov	4,counter

	.align	16
.update8:
	cmp	counter,5
	ble	.cont8
	nop

	mov	%l6,tmp_px
	sub	counter,5,tmp_counter

	ba	.cont8
	mov	5,counter

	.align	16
.update9:
	ld	[%l6+4],%i3
	cmp	counter,5
	ble	.cont9
	fand	%f0,DC0,%f16		! (5_0) res = vis_fand(res,DC0);

	cmp	%g1,0
	bl	1f

	orcc	%g1,%i3,%g0
	bz	1f
	sethi	%hi(0x00080000),%i1

	cmp	%g1,%i1
	bge,a	2f
	ldd	[%o3+0x50],%f18

	fxtod	%f8,%f8			! res = *(long long*)&res;
	st	%f8,[%fp+tmp7]

	fand	%f8,DC0,%f24		! (4_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (4_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (4_0) hx >>= 10;

	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (4_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (4_0) iexp = -iexp;
	ba	.cont9
	for	%f24,DC1,%f24		! (4_0) res = vis_for(res,DC1);
2:
	fand	%f8,%f18,%f8
	fxtod	%f8,%f8			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f18
	faddd	%f8,%f18,%f8
	st	%f8,[%fp+tmp7]

	fand	%f8,DC0,%f24		! (4_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (4_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (4_0) hx >>= 10;

	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (4_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (4_0) iexp = -iexp;
	ba	.cont9
	for	%f24,DC1,%f24		! (4_0) res = vis_for(res,DC1);
1:
	mov	%l6,tmp_px
	sub	counter,5,tmp_counter

	ba	.cont9
	mov	5,counter

	.align	16
.update10:
	cmp	counter,6
	ble	.cont10
	nop

	mov	%i0,tmp_px
	sub	counter,6,tmp_counter

	ba	.cont10
	mov	6,counter

	.align	16
.update11:
	ld	[%i0+4],%i3
	cmp	counter,6
	ble	.cont11
	fand	%f6,DC0,%f16		! (6_0) res = vis_fand(res,DC0);

	cmp	%g1,0
	bl	1f

	orcc	%g1,%i3,%g0
	bz	1f
	sethi	%hi(0x00080000),%i3

	cmp	%g1,%i3
	bge,a	2f
	ldd	[%o3+0x50],%f18

	fxtod	%f0,%f0			! res = *(long long*)&res;
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f28		! (5_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (5_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (5_0) hx >>= 10;

	sub	%o7,537,%o7

	sub	%g0,%o7,%o7		! (5_0) iexp = -iexp;

	and	%o2,2040,%o2		! (5_0) hx &= 0x7f8;
	ba	.cont11
	for	%f28,DC1,%f28		! (5_0) res = vis_for(res,DC1);
2:
	fand	%f0,%f18,%f0
	fxtod	%f0,%f0			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f18
	faddd	%f0,%f18,%f0
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f28		! (5_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (5_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (5_0) hx >>= 10;

	sub	%o7,537,%o7

	sub	%g0,%o7,%o7		! (5_0) iexp = -iexp;

	and	%o2,2040,%o2		! (5_0) hx &= 0x7f8;
	ba	.cont11
	for	%f28,DC1,%f28		! (5_0) res = vis_for(res,DC1);
1:
	mov	%i0,tmp_px
	sub	counter,6,tmp_counter

	ba	.cont11
	mov	6,counter

	.align	16
.update12:
	cmp	counter,0
	ble	.cont12
	faddd	%f34,K3,%f34		! (2_1) res += K3;

	sub	%l6,stridex,tmp_px
	sub	counter,0,tmp_counter

	ba	.cont12
	mov	0,counter

	.align	16
.update13:
	sub	%l6,stridex,%l4
	cmp	counter,0
	ble	.cont13
	fpadd32	%f44,DC2,%f18		! (6_1) res_c = vis_fpadd32(res,DC2);

	ld	[%l4+4],%l4
	cmp	%g1,0
	bl	1f

	orcc	%g1,%l4,%g0
	bz	1f
	sethi	%hi(0x00080000),%l4

	cmp	%g1,%l4
	bge,a	2f
	ldd	[%o3+0x50],%f62

	fxtod	%f6,%f6			! res = *(long long*)&res;
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f44		! (6_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (6_1) iexp = hx >> 21;
	sra	%g1,10,%o2		! (6_1) hx >>= 10;

	sub	%o7,537,%o7
	and	%o2,2040,%o2		! (6_1) hx &= 0x7f8;
	for	%f44,DC1,%f44		! (6_1) res = vis_for(res,DC1);

	sub	%g0,%o7,%o7		! (6_1) iexp = -iexp;
	ba	.cont13
	fpadd32	%f44,DC2,%f18		! (6_1) res_c = vis_fpadd32(res,DC2);
2:
	fand	%f6,%f62,%f6
	fxtod	%f6,%f6			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f62
	faddd	%f6,%f62,%f6
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f44		! (6_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (6_1) iexp = hx >> 21;
	sra	%g1,10,%o2		! (6_1) hx >>= 10;
	for	%f44,DC1,%f44		! (6_1) res = vis_for(res,DC1);

	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (6_1) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (6_1) iexp = -iexp;
	ba	.cont13
	fpadd32	%f44,DC2,%f18		! (6_1) res_c = vis_fpadd32(res,DC2);
1:
	sub	%l6,stridex,tmp_px
	sub	counter,0,tmp_counter

	ba	.cont13
	mov	0,counter

	.align	16
.update14:
	cmp	counter,1
	ble	.cont14
	faddd	%f34,K3,%f34		! (3_1) res += K3;

	sub	%l6,stridex,tmp_px
	sub	counter,1,tmp_counter

	ba	.cont14
	mov	1,counter

	.align	16
.update15:
	sub	%l6,stridex,%l2
	cmp	counter,1
	ble	.cont15
	fpadd32	%f28,DC2,%f18		! (0_0) res_c = vis_fpadd32(res,DC2);

	ld	[%l2+4],%l2
	cmp	%g1,0
	bl	1f

	orcc	%g1,%l2,%g0
	bz	1f
	sethi	%hi(0x00080000),%l2

	cmp	%g1,%l2
	bge,a	2f
	ldd	[%o3+0x50],%f62

	fxtod	%f0,%f0			! res = *(long long*)&res;
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f18		! (0_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (0_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (0_0) hx >>= 10;

	sub	%o7,537,%o7
	for	%f18,DC1,%f28		! (0_0) res = vis_for(res,DC1);

	sub	%g0,%o7,%o7		! (0_0) iexp = -iexp;

	and	%o2,2040,%o2		! (0_0) hx &= 0x7f8;
	add	%o7,1534,%o7		! (0_0) iexp += 0x5fe;
	ba	.cont15
	fpadd32	%f28,DC2,%f18		! (0_0) res_c = vis_fpadd32(res,DC2);
2:
	fand	%f0,%f62,%f0
	fxtod	%f0,%f0			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f62
	faddd	%f0,%f62,%f0
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f18		! (0_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (0_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (0_0) hx >>= 10;
	for	%f18,DC1,%f28		! (0_0) res = vis_for(res,DC1);

	sub	%o7,537,%o7

	sub	%g0,%o7,%o7		! (0_0) iexp = -iexp;

	and	%o2,2040,%o2		! (0_0) hx &= 0x7f8;
	add	%o7,1534,%o7		! (0_0) iexp += 0x5fe;
	ba	.cont15
	fpadd32	%f28,DC2,%f18		! (0_0) res_c = vis_fpadd32(res,DC2);
1:
	sub	%l6,stridex,tmp_px
	sub	counter,1,tmp_counter

	ba	.cont15
	mov	1,counter

	.align	16
.update16:
	cmp	counter,2
	ble	.cont16
	fand	%f18,DC3,%f8		! (0_0) res_c = vis_fand(res_c,DC3);

	sub	%l6,stridex,tmp_px
	sub	counter,2,tmp_counter

	ba	.cont16
	mov	2,counter

	.align	16
.update17:
	sub	%l6,stridex,%i2
	cmp	counter,2
	ble	.cont17
	fand	%f0,DC0,%f16		! (2_0) res = vis_fand(res,DC0);

	ld	[%i2+4],%i2
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i2,%g0
	bz	1f
	sethi	%hi(0x00080000),%i2

	cmp	%g1,%i2
	bge,a	2f
	ldd	[%o3+0x50],%f2

	fxtod	%f6,%f6			! res = *(long long*)&res;
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f44		! (1_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (1_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (1_0) hx >>= 10;

	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (1_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (1_0) iexp = -iexp;
	ba	.cont17
	for	%f44,DC1,%f44		! (1_0) res = vis_for(res,DC1);
2:
	fand	%f6,%f2,%f6
	fxtod	%f6,%f6			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f2
	faddd	%f6,%f2,%f6
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f44		! (1_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (1_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (1_0) hx >>= 10;

	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (1_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (1_0) iexp = -iexp;
	ba	.cont17
	for	%f44,DC1,%f44		! (1_0) res = vis_for(res,DC1);
1:
	sub	%l6,stridex,tmp_px
	sub	counter,2,tmp_counter

	ba	.cont17
	mov	2,counter

	.align	16
.update18:
	cmp	counter,3
	ble	.cont18
	fand	%f18,DC3,%f8		! (1_0) res_c = vis_fand(res_c,DC3);

	sub	%l6,stridex,tmp_px
	sub	counter,3,tmp_counter

	ba	.cont18
	mov	3,counter

	.align	16
.update19:
	sub	%l6,stridex,%i4
	cmp	counter,3
	ble	.cont19
	fand	%f6,DC0,%f16		! (3_0) res = vis_fand(res,DC0);

	ld	[%i4+4],%i4
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i4,%g0
	bz	1f
	sethi	%hi(0x00080000),%i4

	cmp	%g1,%i4
	bge,a	2f
	ldd	[%o3+0x50],%f2

	fxtod	%f0,%f0			! res = *(long long*)&res;
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f28		! (2_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (2_0) iexp = hx >> 21;

	sra	%g1,10,%o2		! (2_0) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (2_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (2_0) iexp = -iexp;
	ba	.cont19
	for	%f28,DC1,%f28		! (2_0) res = vis_for(res,DC1);
2:
	fand	%f0,%f2,%f0
	fxtod	%f0,%f0			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f2
	faddd	%f0,%f2,%f0
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f28		! (2_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (2_0) iexp = hx >> 21;

	sra	%g1,10,%o2		! (2_0) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (2_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (2_0) iexp = -iexp;
	ba	.cont19
	for	%f28,DC1,%f28		! (2_0) res = vis_for(res,DC1);
1:
	sub	%l6,stridex,tmp_px
	sub	counter,3,tmp_counter

	ba	.cont19
	mov	3,counter

	.align	16
.update20:
	cmp	counter,4
	ble	.cont20
	fand	%f18,DC3,%f4		! (2_0) res_c = vis_fand(res_c,DC3);

	sub	%l6,stridex,tmp_px
	sub	counter,4,tmp_counter

	ba	.cont20
	mov	4,counter

	.align	16
.update21:
	sub	%l6,stridex,%i5
	cmp	counter,4
	ble	.cont21
	fand	%f0,DC0,%f16		! (4_0) res = vis_fand(res,DC0);

	ld	[%i5+4],%i5
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i5,%g0
	bz	1f
	sethi	%hi(0x00080000),%i5

	cmp	%g1,%i5
	bge,a	2f
	ldd	[%o3+0x50],%f34

	fxtod	%f6,%f6			! res = *(long long*)&res;
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f44		! (3_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (3_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (3_0) hx >>= 10;

	sub	%o7,537,%o7
	and	%o2,2040,%o2		! (3_0) hx &= 0x7f8;

	sub	%g0,%o7,%o7		! (3_0) iexp = -iexp;
	ba	.cont21
	for	%f44,DC1,%f44		! (3_0) res = vis_for(res,DC1);
2:
	fand	%f6,%f34,%f6
	fxtod	%f6,%f6			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f34
	faddd	%f6,%f34,%f6
	st	%f6,[%fp+tmp7]

	fand	%f6,DC0,%f44		! (3_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (3_0) iexp = hx >> 21;
	sra	%g1,10,%o2		! (3_0) hx >>= 10;

	sub	%o7,537,%o7
	and	%o2,2040,%o2		! (3_0) hx &= 0x7f8;

	sub	%g0,%o7,%o7		! (3_0) iexp = -iexp;
	ba	.cont21
	for	%f44,DC1,%f44		! (3_0) res = vis_for(res,DC1);
1:
	sub	%l6,stridex,tmp_px
	sub	counter,4,tmp_counter

	ba	.cont21
	mov	4,counter

	.align	16
.update22:
	cmp	counter,5
	ble	.cont22
	fmuld	%f62,%f38,%f62		! (1_0) res *= xx;

	sub	%i0,stridex,tmp_px
	sub	counter,5,tmp_counter

	ba	.cont22
	mov	5,counter

	.align	16
.update23:
	sub	%i0,stridex,%l1
	cmp	counter,5
	ble	.cont23
	fand	%f6,DC0,%f16		! (5_0) res = vis_fand(res,DC0);

	ld	[%l1+4],%l1
	cmp	%g1,0
	bl	1f

	orcc	%g1,%l1,%g0
	bz	1f
	sethi	%hi(0x00080000),%l1

	cmp	%g1,%l1
	bge,a	2f
	ldd	[%o3+0x50],%f34

	fxtod	%f0,%f0			! res = *(long long*)&res;
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f24		! (4_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (4_0) iexp = hx >> 21;

	sra	%g1,10,%o2		! (4_0) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (4_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (4_0) iexp = -iexp;
	ba	.cont23
	for	%f24,DC1,%f24		! (4_0) res = vis_for(res,DC1);
2:
	fand	%f0,%f34,%f0
	fxtod	%f0,%f0			! res = *(long long*)&res;
	ldd	[%o3+0x58],%f34
	faddd	%f0,%f34,%f0
	st	%f0,[%fp+tmp7]

	fand	%f0,DC0,%f24		! (4_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (4_0) iexp = hx >> 21;

	sra	%g1,10,%o2		! (4_0) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (4_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (4_0) iexp = -iexp;
	ba	.cont23
	for	%f24,DC1,%f24		! (4_0) res = vis_for(res,DC1);
1:
	sub	%i0,stridex,tmp_px
	sub	counter,5,tmp_counter

	ba	.cont23
	mov	5,counter

	.align	16
.update24:
	cmp	counter,6
	ble	.cont24
	fmuld	%f62,%f36,%f62		! (2_0) res *= xx;

	sub	%i1,stridex,tmp_px
	sub	counter,6,tmp_counter

	ba	.cont24
	mov	6,counter

	.align	16
.update25:
	sub	%i1,stridex,%i3
	cmp	counter,6
	ble	.cont25
	fand	%f6,DC0,%f16		! (6_0) res = vis_fand(res,DC0);

	ld	[%i3+4],%i3
	cmp	%g1,0
	bl	1f

	orcc	%g1,%i3,%g0
	bz	1f
	nop

	sub	%i1,stridex,%i3
	ld	[%i3],%f10
	ld	[%i3+4],%f11

	sethi	%hi(0x00080000),%i3

	cmp	%g1,%i3
	bge,a	2f
	ldd	[%o3+0x50],%f60

	fxtod	%f10,%f10		! res = *(long long*)&res;
	st	%f10,[%fp+tmp7]

	fand	%f10,DC0,%f28		! (5_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (5_0) iexp = hx >> 21;

	sra	%g1,10,%o2		! (5_0) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (5_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (5_0) iexp = -iexp;

	ba	.cont25
	for	%f28,DC1,%f28		! (5_0) res = vis_for(res,DC1);
2:
	fand	%f10,%f60,%f10
	fxtod	%f10,%f10		! res = *(long long*)&res;
	ldd	[%o3+0x58],%f60
	faddd	%f10,%f60,%f10
	st	%f10,[%fp+tmp7]

	fand	%f10,DC0,%f28		! (5_0) res = vis_fand(res,DC0);
	ld	[%fp+tmp7],%g1

	sra	%g1,21,%o7		! (5_0) iexp = hx >> 21;

	sra	%g1,10,%o2		! (5_0) hx >>= 10;
	sub	%o7,537,%o7

	and	%o2,2040,%o2		! (5_0) hx &= 0x7f8;
	sub	%g0,%o7,%o7		! (5_0) iexp = -iexp;

	ba	.cont25
	for	%f28,DC1,%f28		! (5_0) res = vis_for(res,DC1);
1:
	sub	%i1,stridex,tmp_px
	sub	counter,6,tmp_counter

	ba	.cont25
	mov	6,counter

.exit:
	ret
	restore
	SET_SIZE(__vrsqrt)

