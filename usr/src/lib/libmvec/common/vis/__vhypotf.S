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

	.file	"__vhypotf.S"

#include "libm.h"

	RO_DATA
	.align	64

.CONST_TBL:
	.word	0x3fe00001, 0x80007e00	! K1  =  5.00000715259318464227e-01
	.word	0xbfc00003, 0xc0017a01	! K2  = -1.25000447037521686593e-01
	.word	0x000fffff, 0xffffffff	! DC0 = 0x000fffffffffffff
	.word	0x3ff00000, 0x00000000	! DC1 = 0x3ff0000000000000
	.word	0x7ffff000, 0x00000000	! DC2 = 0x7ffff00000000000
	.word	0x7fe00000, 0x00000000	! DA0 = 0x7fe0000000000000
	.word	0x47efffff, 0xe0000000	! DFMAX = 3.402823e+38
	.word	0x7f7fffff, 0x80808080	! FMAX = 3.402823e+38 , SCALE = 0x80808080
	.word	0x20000000, 0x00000000	! DA1 = 0x2000000000000000

#define DC0		%f12
#define DC1		%f10
#define DC2		%f42
#define DA0		%f6
#define DA1		%f4
#define K2		%f26
#define K1		%f28
#define SCALE		%f3
#define FMAX		%f2
#define DFMAX		%f50

#define stridex		%l6
#define stridey		%i4
#define stridez		%l5
#define _0x7fffffff	%o1
#define _0x7f3504f3	%o2
#define _0x1ff0		%l2
#define TBL		%l1

#define counter		%l0

#define tmp_px		STACK_BIAS-0x30
#define tmp_py		STACK_BIAS-0x28
#define tmp_counter	STACK_BIAS-0x20
#define tmp0		STACK_BIAS-0x18
#define tmp1		STACK_BIAS-0x10
#define tmp2		STACK_BIAS-0x0c
#define tmp3		STACK_BIAS-0x08
#define tmp4		STACK_BIAS-0x04

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x30

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!  hx0 = *(int*)px;
!  x0 = *px;
!  px += stridex;
!
!  hy0 = *(int*)py;
!  y0 = *py;
!  py += stridey;
!
!  hx0 &= 0x7fffffff;
!  hy0 &= 0x7fffffff;
!
!  if ( hx >= 0x7f3504f3 || hy >= 0x7f3504f3 )
!  {
!    if ( hx >= 0x7f800000 || hy >= 0x7f800000 )
!    {
!      if ( hx == 0x7f800000 || hy == 0x7f800000 )
!        *(int*)pz = 0x7f800000;
!      else *pz = x * y;
!    }
!    else
!    {
!      hyp = sqrt(x * (double)x + y * (double)y);
!      if ( hyp <= DMAX ) ftmp0 = (float)hyp;
!      else ftmp0 = FMAX * FMAX;
!      *pz = ftmp0;
!    }
!    pz += stridez;
!    continue;
!  }
!  if ( (hx | hy) == 0 )
!  {
!    *pz = 0;
!    pz += stridez;
!    continue;
!  }
!  dx0 = x0 * (double)x0;
!  dy0 = y0 * (double)y0;
!  db0 = dx0 + dy0;
!
!  iexp0 = ((int*)&db0)[0];
!
!  h0 = vis_fand(db0,DC0);
!  h0 = vis_for(h0,DC1);
!  h_hi0 = vis_fand(h0,DC2);
!
!  db0 = vis_fand(db0,DA0);
!  db0 = vis_fmul8x16(SCALE, db0);
!  db0 = vis_fpadd32(db0,DA1);
!
!  iexp0 >>= 8;
!  di0 = iexp0 & 0x1ff0;
!  si0 = (char*)sqrt_arr + di0;
!
!  dtmp0 = ((double*)((char*)div_arr + di0))[0];
!  xx0 = h0 - h_hi0;
!  xx0 *= dmp0;
!
!  dtmp0 = ((double*)si0)[1];
!  res0 = K2 * xx0;
!  res0 += K1;
!  res0 *= xx0;
!  res0 += DC1;
!  res0 = dtmp0 * res0;
!  res0 *= db0;
!  ftmp0 = (float)res0;
!  *pz = ftmp0;
!  pz += stridez;
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vhypotf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,o3)
	PIC_SET(l7,__vlibm_TBL_sqrtf,l1)

#ifdef __sparcv9
	ldx	[%fp+STACK_BIAS+176],stridez
#else
	ld	[%fp+STACK_BIAS+92],stridez
#endif
	st	%i0,[%fp+tmp_counter]

	stx	%i1,[%fp+tmp_px]

	stx	%i3,[%fp+tmp_py]

	ldd	[%o3],K1
	sethi	%hi(0x7ffffc00),%o1

	ldd	[%o3+8],K2
	sethi	%hi(0x7f350400),%o2

	ldd	[%o3+16],DC0
	add	%o1,1023,_0x7fffffff
	add	%o2,0xf3,_0x7f3504f3

	ldd	[%o3+24],DC1
	sll	%i2,2,stridex

	ld	[%o3+56],FMAX

	ldd	[%o3+32],DC2
	sll	%i4,2,stridey

	ldd	[%o3+40],DA0
	sll	stridez,2,stridez

	ldd	[%o3+48],DFMAX

	ld	[%o3+60],SCALE
	or	%g0,0xff8,%l2

	ldd	[%o3+64],DA1
	sll	%l2,1,_0x1ff0
	or	%g0,%i5,%l7

.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%i1
	ldx	[%fp+tmp_py],%i2
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit
	lda	[%i1]0x82,%l3		! (3_0) hx0 = *(int*)px;

	lda	[%i2]0x82,%l4		! (3_0) hy0 = *(int*)py;

	lda	[%i1]0x82,%f17		! (3_0) x0 = *px;
	and	%l3,_0x7fffffff,%l3	! (3_0) hx0 &= 0x7fffffff;

	cmp	%l3,_0x7f3504f3		! (3_0) hx ? 0x7f3504f3
	bge,pn	%icc,.spec		! (3_0) if ( hx >= 0x7f3504f3 )
	and	%l4,_0x7fffffff,%l4	! (3_0) hy0 &= 0x7fffffff;

	cmp	%l4,_0x7f3504f3		! (3_0) hy ? 0x7f3504f3
	bge,pn	%icc,.spec		! (3_0) if ( hy >= 0x7f3504f3 )
	or	%g0,%i2,%o7

	orcc	%l3,%l4,%g0
	bz,pn	%icc,.spec1

	add	%i1,stridex,%i1		! px += stridex
	fsmuld	%f17,%f17,%f44		! (3_0) dx0 = x0 * (double)x0;
	lda	[%i2]0x82,%f17		! (3_0) y0 = *py;

	lda	[%i1]0x82,%l3		! (4_0) hx0 = *(int*)px;

	lda	[stridey+%o7]0x82,%l4	! (4_0) hy0 = *(int*)py;

	and	%l3,_0x7fffffff,%l3	! (4_0) hx0 &= 0x7fffffff;

	fsmuld	%f17,%f17,%f24		! (3_0) dy0 = y0 * (double)y0;
	cmp	%l3,_0x7f3504f3		! (4_0) hx ? 0x7f3504f3
	bge,pn	%icc,.update0		! (4_0) if ( hx >= 0x7f3504f3 )
	and	%l4,_0x7fffffff,%l4	! (4_0) hy0 &= 0x7fffffff;

	orcc	%l3,%l4,%g0
	bz,pn	%icc,.update0
	lda	[%i1]0x82,%f17		! (4_0) x0 = *px;
.cont0:
	faddd	%f44,%f24,%f24		! (3_0) db0 = dx0 + dy0;

	fsmuld	%f17,%f17,%f40		! (4_1) dy0 = x0 * (double)x0;
	cmp	%l4,_0x7f3504f3		! (4_1) hy ? 0x7f3504f3
	lda	[stridey+%o7]0x82,%f17	! (4_1) hy0 = *py;

	add	%o7,stridey,%i5		! py += stridey
	lda	[%i1+stridex]0x82,%l3	! (0_0) hx0 = *(int*)px;

	bge,pn	%icc,.update1		! (4_1) if ( hy >= 0x7f3504f3 )
	st	%f24,[%fp+tmp0]		! (3_1) iexp0 = ((int*)&db0)[0];
.cont1:
	and	%l3,_0x7fffffff,%l3	! (0_0) hx0 &= 0x7fffffff;

	fsmuld	%f17,%f17,%f48		! (4_1) dy0 = y0 * (double)y0;
	lda	[%i1+stridex]0x82,%f8	! (0_0) x0 = *px;

	add	%i1,stridex,%i1		! px += stridex

	lda	[%i5+stridey]0x82,%l4	! (0_0) hy0 = *(int*)py;
	cmp	%l3,_0x7f3504f3		! (0_0) hx ? 0x7f3504f3
	bge,pn	%icc,.update2		! (0_0) if ( hx >= 0x7f3504f3 )
	add	%i5,stridey,%o4		! py += stridey
.cont2:
	faddd	%f40,%f48,%f20		! (4_1) db0 = dx0 + dy0;

	fsmuld	%f8,%f8,%f40		! (0_0) dx0 = x0 * (double)x0;
	and	%l4,_0x7fffffff,%l4	! (0_0) hy0 &= 0x7fffffff;
	lda	[%i5+stridey]0x82,%f17	! (0_0) hy0 = *py;

	cmp	%l4,_0x7f3504f3		! (0_0) hy ? 0x7f3504f3
	bge,pn	%icc,.update3		! (0_0) if ( hy >= 0x7f3504f3 )
	st	%f20,[%fp+tmp1]		! (4_1) iexp0 = ((int*)&db0)[0];

	orcc	%l3,%l4,%g0
	bz,pn	%icc,.update3
.cont3:
	lda	[%i1+stridex]0x82,%l3	! (1_0) hx0 = *(int*)px;

	fand	%f24,DC0,%f60		! (3_1) h0 = vis_fand(db0,DC0);

	and	%l3,_0x7fffffff,%l3	! (1_0) hx0 &= 0x7fffffff;

	fsmuld	%f17,%f17,%f34		! (0_0) dy0 = y0 * (double)y0;
	cmp	%l3,_0x7f3504f3		! (1_0) hx ? 0x7f3504f3
	lda	[%o4+stridey]0x82,%l4	! (1_0) hy0 = *(int*)py;

	add	%i1,stridex,%i1		! px += stridex

	lda	[%i1]0x82,%f17		! (1_0) x0 = *px;
	bge,pn	%icc,.update4		! (1_0) if ( hx >= 0x7f3504f3 )
	add	%o4,stridey,%i5		! py += stridey
.cont4:
	and	%l4,_0x7fffffff,%l4	! (1_0) hy0 &= 0x7fffffff;
	for	%f60,DC1,%f46		! (3_1) h0 = vis_for(h0,DC1);

	cmp	%l4,_0x7f3504f3		! (1_0) hy ? 0x7f3504f3
	ld	[%fp+tmp0],%o0		! (3_1) iexp0 = ((int*)&db0)[0];
	faddd	%f40,%f34,%f0		! (0_0) db0 = dx0 + dy0;

	fsmuld	%f17,%f17,%f40		! (1_0) dx0 = x0 * (double)x0;
	add	%i1,stridex,%i1		! px += stridex
	lda	[%o4+stridey]0x82,%f17	! (1_0) y0 = *py;

	srax	%o0,8,%o0		! (3_1) iexp0 >>= 8;
	bge,pn	%icc,.update5		! (1_0) if ( hy >= 0x7f3504f3 )
	fand	%f46,DC2,%f38		! (3_1) h_hi0 = vis_fand(h0,DC2);

	orcc	%l3,%l4,%g0
	bz,pn	%icc,.update5
.cont5:
	lda	[%i1]0x82,%l3		! (2_0) hx0 = *(int*)px;

	and	%o0,_0x1ff0,%o0		! (3_1) di0 = iexp0 & 0x1ff0;
	st	%f0,[%fp+tmp2]		! (0_0) iexp0 = ((int*)&db0)[0];
	fand	%f20,DC0,%f60		! (4_1) h0 = vis_fand(db0,DC0);

	ldd	[TBL+%o0],%f22		! (3_1) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	fsubd	%f46,%f38,%f38		! (3_1) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f32		! (1_0) dy0 = y0 * (double)y0;
	add	%i5,stridey,%i2		! py += stridey
	lda	[stridey+%i5]0x82,%l4	! (2_0) hy0 = *(int*)py;

	and	%l3,_0x7fffffff,%l3	! (2_0) hx0 &= 0x7fffffff;

	lda	[%i1]0x82,%f17		! (2_0) x0 = *px;
	cmp	%l3,_0x7f3504f3		! (2_0) hx ? 0x7f3504f3

	fmuld	%f38,%f22,%f38		! (3_1) xx0 *= dmp0;
	and	%l4,_0x7fffffff,%l4	! (2_0) hy0 &= 0x7fffffff;
	for	%f60,DC1,%f46		! (4_1) h0 = vis_for(h0,DC1);

	bge,pn	%icc,.update6		! (2_0) if ( hx >= 0x7f3504f3 )
	ld	[%fp+tmp1],%o3		! (4_1) iexp0 = ((int*)&db0)[0];
.cont6:
	faddd	%f40,%f32,%f18		! (1_0) db0 = dx0 + dy0;

	fsmuld	%f17,%f17,%f44		! (2_0) dx0 = x0 * (double)x0;
	cmp	%l4,_0x7f3504f3		! (2_0) hy ? 0x7f3504f3
	lda	[stridey+%i5]0x82,%f17	! (2_0) y0 = *py;

	add	%i1,stridex,%i1		! px += stridex
	bge,pn	%icc,.update7		! (2_0) if ( hy >= 0x7f3504f3 )
	fand	%f46,DC2,%f58		! (4_1) h_hi0 = vis_fand(h0,DC2);

	orcc	%l3,%l4,%g0
	bz,pn	%icc,.update7
	nop
.cont7:
	fmuld	K2,%f38,%f56		! (3_1) res0 = K2 * xx0;
	srax	%o3,8,%o3		! (4_1) iexp0 >>= 8;
	lda	[%i1]0x82,%l3		! (3_0) hx0 = *(int*)px;

	and	%o3,_0x1ff0,%o3		! (4_1) di0 = iexp0 & 0x1ff0;
	st	%f18,[%fp+tmp3]		! (1_0) iexp0 = ((int*)&db0)[0];
	fand	%f0,DC0,%f60		! (0_0) h0 = vis_fand(db0,DC0);

	ldd	[TBL+%o3],%f22		! (4_1) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%i2,stridey,%o7		! py += stridey
	fsubd	%f46,%f58,%f58		! (4_1) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f30		! (2_0) dy0 = y0 * (double)y0;
	lda	[stridey+%i2]0x82,%l4	! (3_0) hy0 = *(int*)py;
	and	%l3,_0x7fffffff,%l3	! (3_0) hx0 &= 0x7fffffff;

	faddd	%f56,K1,%f54		! (3_1) res0 += K1;
	cmp	%l3,_0x7f3504f3		! (3_0) hx ? 0x7f3504f3

	lda	[%i1]0x82,%f17		! (3_0) x0 = *px;
	add	%i1,stridex,%i1		! px += stridex
	bge,pn	%icc,.update8		! (3_0) if ( hx >= 0x7f3504f3 )

	fmuld	%f58,%f22,%f58		! (4_1) xx0 *= dmp0;
.cont8:
	and	%l4,_0x7fffffff,%l4	! (3_0) hy0 &= 0x7fffffff;
	for	%f60,DC1,%f46		! (0_0) h0 = vis_for(h0,DC1);

	cmp	%l4,_0x7f3504f3		! (3_0) hy ? 0x7f3504f3
	ld	[%fp+tmp2],%g1		! (0_0) iexp0 = ((int*)&db0)[0];
	faddd	%f44,%f30,%f30		! (2_0) db0 = dx0 + dy0;

	fsmuld	%f17,%f17,%f44		! (3_0) dx0 = x0 * (double)x0;
	bge,pn	%icc,.update9		! (3_0) if ( hy >= 0x7f3504f3 )
	lda	[stridey+%i2]0x82,%f17	! (3_0) y0 = *py;

	orcc	%l3,%l4,%g0
	bz,pn	%icc,.update9
	nop
.cont9:
	fmuld	%f54,%f38,%f40		! (3_1) res0 *= xx0;
	lda	[%i1]0x82,%l3		! (4_0) hx0 = *(int*)px;
	fand	%f46,DC2,%f38		! (0_0) h_hi0 = vis_fand(h0,DC2);

	fmuld	K2,%f58,%f54		! (4_1) res0 = K2 * xx0;
	srax	%g1,8,%o5		! (0_0) iexp0 >>= 8;
	lda	[stridey+%o7]0x82,%l4	! (4_0) hy0 = *(int*)py;
	fand	%f24,DA0,%f56		! (3_1) db0 = vis_fand(db0,DA0);

	and	%o5,_0x1ff0,%o5		! (0_0) di0 = iexp0 & 0x1ff0;
	st	%f30,[%fp+tmp4]		! (2_0) iexp0 = ((int*)&db0)[0];
	fand	%f18,DC0,%f60		! (1_0) h0 = vis_fand(db0,DC0);

	ldd	[TBL+%o5],%f22		! (0_0) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%o0,TBL,%g1		! (3_1) si0 = (char*)sqrt_arr + di0;
	and	%l3,_0x7fffffff,%l3	! (4_0) hx0 &= 0x7fffffff;
	fsubd	%f46,%f38,%f38		! (0_0) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f24		! (3_0) dy0 = y0 * (double)y0;
	cmp	%l3,_0x7f3504f3		! (4_0) hx ? 0x7f3504f3
	bge,pn	%icc,.update10		! (4_0) if ( hx >= 0x7f3504f3 )
	faddd	%f40,DC1,%f40		! (3_1) res0 += DC1;

	fmul8x16	SCALE,%f56,%f36	! (3_1) db0 = vis_fmul8x16(SCALE, db0);
	and	%l4,_0x7fffffff,%l4	! (4_0) hy0 &= 0x7fffffff;
	ldd	[%g1+8],%f56		! (3_1) dtmp0 = ((double*)si0)[1];
	faddd	%f54,K1,%f54		! (4_1) res0 += K1;

	lda	[%i1]0x82,%f17		! (4_0) x0 = *px;
.cont10:
	fmuld	%f38,%f22,%f38		! (0_0) xx0 *= dmp0;
	cmp	counter,5
	for	%f60,DC1,%f46		! (1_0) h0 = vis_for(h0,DC1);

	ld	[%fp+tmp3],%g1		! (1_0) iexp0 = ((int*)&db0)[0];
	fmuld	%f56,%f40,%f62		! (3_1) res0 = dtmp0 * res0;
	faddd	%f44,%f24,%f24		! (3_0) db0 = dx0 + dy0;

	bl,pn	%icc,.tail
	nop

	ba	.main_loop
	sub	counter,5,counter

	.align	16
.main_loop:
	fsmuld	%f17,%f17,%f40		! (4_1) dy0 = x0 * (double)x0;
	cmp	%l4,_0x7f3504f3		! (4_1) hy ? 0x7f3504f3
	lda	[stridey+%o7]0x82,%f17	! (4_1) hy0 = *py;
	fpadd32	%f36,DA1,%f36		! (3_2) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f54,%f58,%f58		! (4_2) res0 *= xx0;
	add	%o7,stridey,%i5		! py += stridey
	st	%f24,[%fp+tmp0]		! (3_1) iexp0 = ((int*)&db0)[0];
	fand	%f46,DC2,%f44		! (1_1) h_hi0 = vis_fand(h0,DC2);

	fmuld	K2,%f38,%f56		! (0_1) res0 = K2 * xx0;
	srax	%g1,8,%g5		! (1_1) iexp0 >>= 8;
	bge,pn	%icc,.update11		! (4_1) if ( hy >= 0x7f3504f3 )
	fand	%f20,DA0,%f54		! (4_2) db0 = vis_fand(db0,DA0);

	orcc	%l3,%l4,%g0
	nop
	bz,pn	%icc,.update11
	fzero	%f52
.cont11:
	fmuld	%f62,%f36,%f62		! (3_2) res0 *= db0;
	and	%g5,_0x1ff0,%g5		! (1_1) di0 = iexp0 & 0x1ff0;
	lda	[%i1+stridex]0x82,%l3	! (0_0) hx0 = *(int*)px;
	fand	%f30,DC0,%f60		! (2_1) h0 = vis_fand(db0,DC0);

	ldd	[%g5+TBL],%f22		! (1_1) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%o3,TBL,%g1		! (4_2) si0 = (char*)sqrt_arr + di0;
	add	%i1,stridex,%i0		! px += stridex
	fsubd	%f46,%f44,%f44		! (1_1) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f48		! (4_1) dy0 = y0 * (double)y0;
	nop
	lda	[%i1+stridex]0x82,%f8	! (0_0) x0 = *px;
	faddd	%f58,DC1,%f36		! (4_2) res0 += DC1;

	faddd	%f56,K1,%f58		! (0_1) res0 += K1;
	and	%l3,_0x7fffffff,%l3	! (0_0) hx0 &= 0x7fffffff;
	ldd	[%g1+8],%f56		! (4_2) dtmp0 = ((double*)si0)[1];
	fmul8x16	SCALE,%f54,%f54	! (4_2) db0 = vis_fmul8x16(SCALE, db0);

	lda	[%i5+stridey]0x82,%l4	! (0_0) hy0 = *(int*)py;
	cmp	%l3,_0x7f3504f3		! (0_0) hx ? 0x7f3504f3
	bge,pn	%icc,.update12		! (0_0) if ( hx >= 0x7f3504f3 )
	fdtos	%f62,%f14		! (3_2) ftmp0 = (float)res0;
.cont12:
	fmuld	%f44,%f22,%f44		! (1_1) xx0 *= dmp0;
	add	%l7,stridez,%o7		! pz += stridez
	st	%f14,[%l7]		! (3_2) *pz = ftmp0;
	for	%f60,DC1,%f46		! (2_1) h0 = vis_for(h0,DC1);

	fmuld	%f56,%f36,%f36		! (4_2) res0 = dtmp0 * res0;
	add	%i5,stridey,%o4		! py += stridey
	ld	[%fp+tmp4],%g1		! (2_1) iexp0 = ((int*)&db0)[0];
	faddd	%f40,%f48,%f20		! (4_1) db0 = dx0 + dy0;

	fsmuld	%f8,%f8,%f40		! (0_0) dx0 = x0 * (double)x0;
	and	%l4,_0x7fffffff,%l4	! (0_0) hy0 &= 0x7fffffff;
	lda	[%i5+stridey]0x82,%f17	! (0_0) hy0 = *py;
	fpadd32	%f54,DA1,%f62		! (4_2) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f58,%f38,%f38		! (0_1) res0 *= xx0;
	cmp	%l4,_0x7f3504f3		! (0_0) hy ? 0x7f3504f3
	st	%f20,[%fp+tmp1]		! (4_1) iexp0 = ((int*)&db0)[0];
	fand	%f46,DC2,%f58		! (2_1) h_hi0 = vis_fand(h0,DC2);

	fmuld	K2,%f44,%f56		! (1_1) res0 = K2 * xx0;
	srax	%g1,8,%g1		! (2_1) iexp0 >>= 8;
	bge,pn	%icc,.update13		! (0_0) if ( hy >= 0x7f3504f3 )
	fand	%f0,DA0,%f54		! (0_1) db0 = vis_fand(db0,DA0);

	orcc	%l3,%l4,%g0
	nop
	bz,pn	%icc,.update13
	fzero	%f52
.cont13:
	fmuld	%f36,%f62,%f62		! (4_2) res0 *= db0;
	and	%g1,_0x1ff0,%g1		! (2_1) di0 = iexp0 & 0x1ff0;
	lda	[%i0+stridex]0x82,%l3	! (1_0) hx0 = *(int*)px;
	fand	%f24,DC0,%f60		! (3_1) h0 = vis_fand(db0,DC0);

	ldd	[TBL+%g1],%f22		! (2_1) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%o5,TBL,%o0		! (0_1) si0 = (char*)sqrt_arr + di0;
	add	%i0,stridex,%i1		! px += stridex
	fsubd	%f46,%f58,%f58		! (2_1) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f34		! (0_0) dy0 = y0 * (double)y0;
	add	%o7,stridez,%i0		! pz += stridez
	lda	[%o4+stridey]0x82,%l4	! (1_0) hy0 = *(int*)py;
	faddd	%f38,DC1,%f36		! (0_1) res0 += DC1;

	faddd	%f56,K1,%f38		! (1_1) res0 += K1;
	and	%l3,_0x7fffffff,%l3	! (1_0) hx0 &= 0x7fffffff;
	ldd	[%o0+8],%f56		! (0_1) dtmp0 = ((double*)si0)[1];
	fmul8x16	SCALE,%f54,%f54	! (0_1) db0 = vis_fmul8x16(SCALE, db0);

	lda	[%i1]0x82,%f17		! (1_0) x0 = *px;
	cmp	%l3,_0x7f3504f3		! (1_0) hx ? 0x7f3504f3
	bge,pn	%icc,.update14		! (1_0) if ( hx >= 0x7f3504f3 )
	fdtos	%f62,%f14		! (4_2) ftmp0 = (float)res0;
.cont14:
	fmuld	%f58,%f22,%f58		! (2_1) xx0 *= dmp0;
	and	%l4,_0x7fffffff,%l4	! (1_0) hy0 &= 0x7fffffff;
	add	%o4,stridey,%i5		! py += stridey
	for	%f60,DC1,%f46		! (3_1) h0 = vis_for(h0,DC1);

	fmuld	%f56,%f36,%f36		! (0_1) res0 = dtmp0 * res0;
	cmp	%l4,_0x7f3504f3		! (1_0) hy ? 0x7f3504f3
	ld	[%fp+tmp0],%o0		! (3_1) iexp0 = ((int*)&db0)[0];
	faddd	%f40,%f34,%f0		! (0_0) db0 = dx0 + dy0;

	fsmuld	%f17,%f17,%f40		! (1_0) dx0 = x0 * (double)x0;
	add	%i1,stridex,%i1		! px += stridex
	lda	[%o4+stridey]0x82,%f17	! (1_0) y0 = *py;
	fpadd32	%f54,DA1,%f62		! (0_1) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f38,%f44,%f44		! (1_1) res0 *= xx0;
	st	%f14,[%o7]		! (4_2) *pz = ftmp0;
	bge,pn	%icc,.update15		! (1_0) if ( hy >= 0x7f3504f3 )
	fand	%f46,DC2,%f38		! (3_1) h_hi0 = vis_fand(h0,DC2);

	orcc	%l3,%l4,%g0
	bz,pn	%icc,.update15
	nop
.cont15:
	fmuld	K2,%f58,%f54		! (2_1) res0 = K2 * xx0;
	srax	%o0,8,%o0		! (3_1) iexp0 >>= 8;
	st	%f0,[%fp+tmp2]		! (0_0) iexp0 = ((int*)&db0)[0];
	fand	%f18,DA0,%f56		! (1_1) db0 = vis_fand(db0,DA0);

	fmuld	%f36,%f62,%f62		! (0_1) res0 *= db0;
	and	%o0,_0x1ff0,%o0		! (3_1) di0 = iexp0 & 0x1ff0;
	lda	[%i1]0x82,%l3		! (2_0) hx0 = *(int*)px;
	fand	%f20,DC0,%f60		! (4_1) h0 = vis_fand(db0,DC0);

	ldd	[TBL+%o0],%f22		! (3_1) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%g5,TBL,%o3		! (1_1) si0 = (char*)sqrt_arr + di0;
	add	%i0,stridez,%i3		! pz += stridez
	fsubd	%f46,%f38,%f38		! (3_1) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f32		! (1_0) dy0 = y0 * (double)y0;
	add	%i5,stridey,%i2		! py += stridey
	lda	[stridey+%i5]0x82,%l4	! (2_0) hy0 = *(int*)py;
	faddd	%f44,DC1,%f44		! (1_1) res0 += DC1;

	fmul8x16	SCALE,%f56,%f36	! (1_1) db0 = vis_fmul8x16(SCALE, db0);
	and	%l3,_0x7fffffff,%l3	! (2_0) hx0 &= 0x7fffffff;
	ldd	[%o3+8],%f56		! (1_1) dtmp0 = ((double*)si0)[1];
	faddd	%f54,K1,%f54		! (2_1) res0 += K1;

	lda	[%i1]0x82,%f17		! (2_0) x0 = *px;
	cmp	%l3,_0x7f3504f3		! (2_0) hx ? 0x7f3504f3
	add	%i3,stridez,%o4		! pz += stridez
	fdtos	%f62,%f14		! (0_1) ftmp0 = (float)res0;

	fmuld	%f38,%f22,%f38		! (3_1) xx0 *= dmp0;
	and	%l4,_0x7fffffff,%l4	! (2_0) hy0 &= 0x7fffffff;
	st	%f14,[%i0]		! (0_1) *pz = ftmp0;
	for	%f60,DC1,%f46		! (4_1) h0 = vis_for(h0,DC1);

	fmuld	%f56,%f44,%f62		! (1_1) res0 = dtmp0 * res0;
	bge,pn	%icc,.update16		! (2_0) if ( hx >= 0x7f3504f3 )
	ld	[%fp+tmp1],%o3		! (4_1) iexp0 = ((int*)&db0)[0];
	faddd	%f40,%f32,%f18		! (1_0) db0 = dx0 + dy0;
.cont16:
	fsmuld	%f17,%f17,%f44		! (2_0) dx0 = x0 * (double)x0;
	cmp	%l4,_0x7f3504f3		! (2_0) hy ? 0x7f3504f3
	lda	[stridey+%i5]0x82,%f17	! (2_0) y0 = *py;
	fpadd32	%f36,DA1,%f36		! (1_1) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f54,%f58,%f54		! (2_1) res0 *= xx0;
	add	%i1,stridex,%l7		! px += stridex
	bge,pn	%icc,.update17		! (2_0) if ( hy >= 0x7f3504f3 )
	fand	%f46,DC2,%f58		! (4_1) h_hi0 = vis_fand(h0,DC2);

	orcc	%l3,%l4,%g0
	nop
	bz,pn	%icc,.update17
	fzero	%f52
.cont17:
	fmuld	K2,%f38,%f56		! (3_1) res0 = K2 * xx0;
	srax	%o3,8,%o3		! (4_1) iexp0 >>= 8;
	st	%f18,[%fp+tmp3]		! (1_0) iexp0 = ((int*)&db0)[0];
	fand	%f30,DA0,%f40		! (2_1) db0 = vis_fand(db0,DA0);

	fmuld	%f62,%f36,%f62		! (1_1) res0 *= db0;
	and	%o3,_0x1ff0,%o3		! (4_1) di0 = iexp0 & 0x1ff0;
	lda	[%l7]0x82,%l3		! (3_0) hx0 = *(int*)px;
	fand	%f0,DC0,%f60		! (0_0) h0 = vis_fand(db0,DC0);

	ldd	[TBL+%o3],%f22		! (4_1) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%g1,TBL,%g1		! (2_1) si0 = (char*)sqrt_arr + di0;
	add	%i2,stridey,%o7		! py += stridey
	fsubd	%f46,%f58,%f58		! (4_1) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f30		! (2_0) dy0 = y0 * (double)y0;
	lda	[stridey+%i2]0x82,%l4	! (3_0) hy0 = *(int*)py;
	add	%l7,stridex,%i1		! px += stridex
	faddd	%f54,DC1,%f36		! (2_1) res0 += DC1;

	faddd	%f56,K1,%f54		! (3_1) res0 += K1;
	and	%l3,_0x7fffffff,%l3	! (3_0) hx0 &= 0x7fffffff;
	ldd	[%g1+8],%f56		! (2_1) dtmp0 = ((double*)si0)[1];
	fmul8x16	SCALE,%f40,%f40	! (2_1) db0 = vis_fmul8x16(SCALE, db0);

	lda	[%l7]0x82,%f17		! (3_0) x0 = *px;
	cmp	%l3,_0x7f3504f3		! (3_0) hx ? 0x7f3504f3
	bge,pn	%icc,.update18		! (3_0) if ( hx >= 0x7f3504f3 )
	fdtos	%f62,%f14		! (1_1) ftmp0 = (float)res0;
.cont18:
	fmuld	%f58,%f22,%f58		! (4_1) xx0 *= dmp0;
	and	%l4,_0x7fffffff,%l4	! (3_0) hy0 &= 0x7fffffff;
	st	%f14,[%i3]		! (1_1) *pz = ftmp0;
	for	%f60,DC1,%f46		! (0_0) h0 = vis_for(h0,DC1);

	fmuld	%f56,%f36,%f36		! (2_1) res0 = dtmp0 * res0;
	cmp	%l4,_0x7f3504f3		! (3_0) hy ? 0x7f3504f3
	ld	[%fp+tmp2],%g1		! (0_0) iexp0 = ((int*)&db0)[0];
	faddd	%f44,%f30,%f30		! (2_0) db0 = dx0 + dy0;

	fsmuld	%f17,%f17,%f44		! (3_0) dx0 = x0 * (double)x0;
	bge,pn	%icc,.update19		! (3_0) if ( hy >= 0x7f3504f3 )
	lda	[stridey+%i2]0x82,%f17	! (3_0) y0 = *py;
	fpadd32	%f40,DA1,%f62		! (2_1) db0 = vis_fpadd32(db0,DA1);

.cont19:
	fmuld	%f54,%f38,%f40		! (3_1) res0 *= xx0;
	orcc	%l3,%l4,%g0
	st	%f30,[%fp+tmp4]		! (2_0) iexp0 = ((int*)&db0)[0];
	fand	%f46,DC2,%f38		! (0_0) h_hi0 = vis_fand(h0,DC2);

	fmuld	K2,%f58,%f54		! (4_1) res0 = K2 * xx0;
	srax	%g1,8,%o5		! (0_0) iexp0 >>= 8;
	lda	[%i1]0x82,%l3		! (4_0) hx0 = *(int*)px;
	fand	%f24,DA0,%f56		! (3_1) db0 = vis_fand(db0,DA0);

	fmuld	%f36,%f62,%f62		! (2_1) res0 *= db0;
	and	%o5,_0x1ff0,%o5		! (0_0) di0 = iexp0 & 0x1ff0;
	bz,pn	%icc,.update19a
	fand	%f18,DC0,%f60		! (1_0) h0 = vis_fand(db0,DC0);
.cont19a:
	ldd	[TBL+%o5],%f22		! (0_0) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%o0,TBL,%g1		! (3_1) si0 = (char*)sqrt_arr + di0;
	and	%l3,_0x7fffffff,%l3	! (4_0) hx0 &= 0x7fffffff;
	fsubd	%f46,%f38,%f38		! (0_0) xx0 = h0 - h_hi0;

	fsmuld	%f17,%f17,%f24		! (3_0) dy0 = y0 * (double)y0;
	cmp	%l3,_0x7f3504f3		! (4_0) hx ? 0x7f3504f3
	lda	[stridey+%o7]0x82,%l4	! (4_0) hy0 = *(int*)py;
	faddd	%f40,DC1,%f40		! (3_1) res0 += DC1;

	fmul8x16	SCALE,%f56,%f36	! (3_1) db0 = vis_fmul8x16(SCALE, db0);
	bge,pn	%icc,.update20		! (4_0) if ( hx >= 0x7f3504f3 )
	ldd	[%g1+8],%f56		! (3_1) dtmp0 = ((double*)si0)[1];
	faddd	%f54,K1,%f54		! (4_1) res0 += K1;

	lda	[%i1]0x82,%f17		! (4_0) x0 = *px;
.cont20:
	subcc	counter,5,counter	! counter -= 5
	add	%o4,stridez,%l7		! pz += stridez
	fdtos	%f62,%f14		! (2_1) ftmp0 = (float)res0;

	fmuld	%f38,%f22,%f38		! (0_0) xx0 *= dmp0;
	and	%l4,_0x7fffffff,%l4	! (4_0) hy0 &= 0x7fffffff;
	st	%f14,[%o4]		! (2_1) *pz = ftmp0;
	for	%f60,DC1,%f46		! (1_0) h0 = vis_for(h0,DC1);

	ld	[%fp+tmp3],%g1		! (1_0) iexp0 = ((int*)&db0)[0];
	fmuld	%f56,%f40,%f62		! (3_1) res0 = dtmp0 * res0;
	bpos,pt	%icc,.main_loop
	faddd	%f44,%f24,%f24		! (3_0) db0 = dx0 + dy0;

	add	counter,5,counter

.tail:
	subcc	counter,1,counter
	bneg	.begin
	nop

	fpadd32	%f36,DA1,%f36		! (3_2) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f54,%f58,%f58		! (4_2) res0 *= xx0;
	fand	%f46,DC2,%f44		! (1_1) h_hi0 = vis_fand(h0,DC2);

	fmuld	K2,%f38,%f56		! (0_1) res0 = K2 * xx0;
	srax	%g1,8,%g5		! (1_1) iexp0 >>= 8;
	fand	%f20,DA0,%f54		! (4_2) db0 = vis_fand(db0,DA0);

	fmuld	%f62,%f36,%f62		! (3_2) res0 *= db0;
	and	%g5,_0x1ff0,%g5		! (1_1) di0 = iexp0 & 0x1ff0;

	ldd	[%g5+TBL],%f22		! (1_1) dtmp0 = ((double*)((char*)div_arr + di0))[0];
	add	%o3,TBL,%g1		! (4_2) si0 = (char*)sqrt_arr + di0;
	fsubd	%f46,%f44,%f44		! (1_1) xx0 = h0 - h_hi0;

	faddd	%f58,DC1,%f36		! (4_2) res0 += DC1;

	faddd	%f56,K1,%f58		! (0_1) res0 += K1;
	ldd	[%g1+8],%f56		! (4_2) dtmp0 = ((double*)si0)[1];
	fmul8x16	SCALE,%f54,%f54	! (4_2) db0 = vis_fmul8x16(SCALE, db0);

	fdtos	%f62,%f14		! (3_2) ftmp0 = (float)res0;

	fmuld	%f44,%f22,%f44		! (1_1) xx0 *= dmp0;
	add	%l7,stridez,%o7		! pz += stridez
	st	%f14,[%l7]		! (3_2) *pz = ftmp0;

	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%o7,%l7

	fmuld	%f56,%f36,%f36		! (4_2) res0 = dtmp0 * res0;

	fpadd32	%f54,DA1,%f62		! (4_2) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f58,%f38,%f38		! (0_1) res0 *= xx0;

	fmuld	K2,%f44,%f56		! (1_1) res0 = K2 * xx0;
	fand	%f0,DA0,%f54		! (0_1) db0 = vis_fand(db0,DA0);

	fmuld	%f36,%f62,%f62		! (4_2) res0 *= db0;

	add	%o5,TBL,%o0		! (0_1) si0 = (char*)sqrt_arr + di0;

	faddd	%f38,DC1,%f36		! (0_1) res0 += DC1;

	faddd	%f56,K1,%f38		! (1_1) res0 += K1;
	ldd	[%o0+8],%f56		! (0_1) dtmp0 = ((double*)si0)[1];
	fmul8x16	SCALE,%f54,%f54	! (0_1) db0 = vis_fmul8x16(SCALE, db0);

	add	%o7,stridez,%i0		! pz += stridez
	fdtos	%f62,%f14		! (4_2) ftmp0 = (float)res0;

	fmuld	%f56,%f36,%f36		! (0_1) res0 = dtmp0 * res0;

	fpadd32	%f54,DA1,%f62		! (0_1) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f38,%f44,%f44		! (1_1) res0 *= xx0;
	add	%i0,stridez,%i3		! pz += stridez
	st	%f14,[%o7]		! (4_2) *pz = ftmp0;

	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%i0,%l7

	fand	%f18,DA0,%f56		! (1_1) db0 = vis_fand(db0,DA0);

	fmuld	%f36,%f62,%f62		! (0_1) res0 *= db0;

	add	%g5,TBL,%o3		! (1_1) si0 = (char*)sqrt_arr + di0;

	faddd	%f44,DC1,%f44		! (1_1) res0 += DC1;

	fmul8x16	SCALE,%f56,%f36	! (1_1) db0 = vis_fmul8x16(SCALE, db0);
	ldd	[%o3+8],%f56		! (1_1) dtmp0 = ((double*)si0)[1];

	add	%i3,stridez,%o4		! pz += stridez
	fdtos	%f62,%f14		! (0_1) ftmp0 = (float)res0;

	st	%f14,[%i0]		! (0_1) *pz = ftmp0;

	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%i3,%l7

	fmuld	%f56,%f44,%f62		! (1_1) res0 = dtmp0 * res0;

	fpadd32	%f36,DA1,%f36		! (1_1) db0 = vis_fpadd32(db0,DA1);

	fmuld	%f62,%f36,%f62		! (1_1) res0 *= db0;

	fdtos	%f62,%f14		! (1_1) ftmp0 = (float)res0;

	st	%f14,[%i3]		! (1_1) *pz = ftmp0;

	ba	.begin
	or	%g0,%o4,%l7

	.align	16
.spec1:
	st	%g0,[%l7]		! *pz = 0;
	add	%l7,stridez,%l7		! pz += stridez

	add	%i2,stridey,%i2		! py += stridey
	ba	.begin1
	sub	counter,1,counter	! counter--

	.align	16
.spec:
	sethi	%hi(0x7f800000),%i0
	cmp	%l3,%i0			! hx ? 0x7f800000
	bge,pt	%icc,2f			! if ( hx >= 0x7f800000 )
	ld	[%i2],%f8

	cmp	%l4,%i0			! hy ? 0x7f800000
	bge,pt	%icc,2f			! if ( hy >= 0x7f800000 )
	nop

	fsmuld	%f17,%f17,%f44		! x * (double)x
	fsmuld	%f8,%f8,%f24		! y * (double)y
	faddd	%f44,%f24,%f24		! x * (double)x + y * (double)y
	fsqrtd	%f24,%f24		! hyp = sqrt(x * (double)x + y * (double)y);
	fcmped	%f24,DFMAX		! hyp ? DMAX
	fbug,a	1f			! if ( hyp > DMAX )
	fmuls	FMAX,FMAX,%f20		! ftmp0 = FMAX * FMAX;

	fdtos	%f24,%f20		! ftmp0 = (float)hyp;
1:
	st	%f20,[%l7]		! *pz = ftmp0;
	add	%l7,stridez,%l7		! pz += stridez
	add	%i1,stridex,%i1		! px += stridex

	add	%i2,stridey,%i2		! py += stridey
	ba	.begin1
	sub	counter,1,counter	! counter--
2:
	fcmps	%f17,%f8		! exceptions
	cmp	%l3,%i0			! hx ? 0x7f800000
	be,a	%icc,1f			! if ( hx == 0x7f800000 )
	st	%i0,[%l7]		! *(int*)pz = 0x7f800000;

	cmp	%l4,%i0			! hy ? 0x7f800000
	be,a	%icc,1f			! if ( hy == 0x7f800000
	st	%i0,[%l7]		! *(int*)pz = 0x7f800000;

	fmuls	%f17,%f8,%f8		! x * y
	st	%f8,[%l7]		! *pz = x * y;

1:
	add	%l7,stridez,%l7		! pz += stridez
	add	%i1,stridex,%i1		! px += stridex

	add	%i2,stridey,%i2		! py += stridey
	ba	.begin1
	sub	counter,1,counter	! counter--

	.align	16
.update0:
	cmp	counter,1
	ble	.cont0
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]

	add	%o7,stridey,%i5
	stx	%i5,[%fp+tmp_py]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont0
	or	%g0,1,counter

	.align	16
.update1:
	cmp	counter,1
	ble	.cont1
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	stx	%i5,[%fp+tmp_py]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont1
	or	%g0,1,counter

	.align	16
.update2:
	cmp	counter,2
	ble	.cont2
	fzeros	%f8

	stx	%i1,[%fp+tmp_px]
	stx	%o4,[%fp+tmp_py]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont2
	or	%g0,2,counter

	.align	16
.update3:
	cmp	counter,2
	ble	.cont3
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	stx	%o4,[%fp+tmp_py]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont3
	or	%g0,2,counter

	.align	16
.update4:
	cmp	counter,3
	ble	.cont4
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	stx	%i5,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont4
	or	%g0,3,counter

	.align	16
.update5:
	cmp	counter,3
	ble	.cont5
	fzeros	%f17

	sub	%i1,stridex,%i2
	stx	%i2,[%fp+tmp_px]
	stx	%i5,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont5
	or	%g0,3,counter

	.align	16
.update6:
	cmp	counter,4
	ble	.cont6
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	stx	%i2,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont6
	or	%g0,4,counter

	.align	16
.update7:
	cmp	counter,4
	ble	.cont7
	fzeros	%f17

	sub	%i1,stridex,%o7
	stx	%o7,[%fp+tmp_px]
	stx	%i2,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont7
	or	%g0,4,counter

	.align	16
.update8:
	cmp	counter,5
	ble	.cont8
	fzeros	%f17

	sub	%i1,stridex,%o5
	stx	%o5,[%fp+tmp_px]
	stx	%o7,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont8
	or	%g0,5,counter

	.align	16
.update9:
	cmp	counter,5
	ble	.cont9
	fzeros	%f17

	sub	%i1,stridex,%o5
	stx	%o5,[%fp+tmp_px]
	stx	%o7,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont9
	or	%g0,5,counter

	.align	16
.update10:
	fmul8x16	SCALE,%f56,%f36	! (3_1) db0 = vis_fmul8x16(SCALE, db0);
	and	%l4,_0x7fffffff,%l4	! (4_0) hy0 &= 0x7fffffff;
	ldd	[%g1+8],%f56		! (3_1) dtmp0 = ((double*)si0)[1];
	faddd	%f54,K1,%f54		! (4_1) res0 += K1;

	cmp	counter,6
	ble	.cont10
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	add	%o7,stridey,%i5
	stx	%i5,[%fp+tmp_py]

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont10
	or	%g0,6,counter

	.align	16
.update11:
	cmp	counter,1
	ble	.cont11
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	stx	%i5,[%fp+tmp_py]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont11
	or	%g0,1,counter

	.align	16
.update12:
	cmp	counter,2
	ble	.cont12
	fzeros	%f8

	stx	%i0,[%fp+tmp_px]
	add	%i5,stridey,%o4
	stx	%o4,[%fp+tmp_py]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont12
	or	%g0,2,counter

	.align	16
.update13:
	cmp	counter,2
	ble	.cont13
	fzeros	%f17

	stx	%i0,[%fp+tmp_px]
	stx	%o4,[%fp+tmp_py]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont13
	or	%g0,2,counter

	.align	16
.update14:
	cmp	counter,3
	ble	.cont14
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	add	%o4,stridey,%i5
	stx	%i5,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont14
	or	%g0,3,counter

	.align	16
.update15:
	cmp	counter,3
	ble	.cont15
	fzeros	%f17

	sub	%i1,stridex,%i2
	stx	%i2,[%fp+tmp_px]
	stx	%i5,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont15
	or	%g0,3,counter

	.align	16
.update16:
	faddd	%f40,%f32,%f18		! (1_0) db0 = dx0 + dy0;
	cmp	counter,4
	ble	.cont16
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	stx	%i2,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont16
	or	%g0,4,counter

	.align	16
.update17:
	cmp	counter,4
	ble	.cont17
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	stx	%i2,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont17
	or	%g0,4,counter

	.align	16
.update18:
	cmp	counter,5
	ble	.cont18
	fzeros	%f17

	stx	%l7,[%fp+tmp_px]
	stx	%o7,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont18
	or	%g0,5,counter

	.align	16
.update19:
	fpadd32	%f40,DA1,%f62		! (2_1) db0 = vis_fpadd32(db0,DA1);
	cmp	counter,5
	ble	.cont19
	fzeros	%f17

	stx	%l7,[%fp+tmp_px]
	stx	%o7,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont19
	or	%g0,5,counter

	.align	16
.update19a:
	cmp	counter,5
	ble	.cont19a
	fzeros	%f17

	stx	%l7,[%fp+tmp_px]
	stx	%o7,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont19a
	or	%g0,5,counter

	.align	16
.update20:
	faddd	%f54,K1,%f54		! (4_1) res0 += K1;
	cmp	counter,6
	ble	.cont20
	fzeros	%f17

	stx	%i1,[%fp+tmp_px]
	add	%o7,stridey,%g1
	stx	%g1,[%fp+tmp_py]

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont20
	or	%g0,6,counter

.exit:
	ret
	restore
	SET_SIZE(__vhypotf)

