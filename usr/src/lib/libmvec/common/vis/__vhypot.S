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

	.file	"__vhypot.S"

#include "libm.h"

	RO_DATA
	.align	64

.CONST_TBL:
	.word	0x7ff00000, 0	! DC0
	.word	0x7fe00000, 0	! DC1
	.word	0x00100000, 0	! DC2
	.word	0x41b00000, 0	! D2ON28 = 268435456.0
	.word	0x7fd00000, 0	! DC3

#define counter		%i0
#define tmp_counter	%l3
#define tmp_px		%l5
#define tmp_py		%o7
#define stridex		%i2
#define stridey		%i4
#define stridez		%l0

#define DC0		%f8
#define DC0_HI		%f8
#define DC0_LO		%f9
#define DC1		%f46
#define DC2		%f48
#define DC3		%f0
#define D2ON28		%f62

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!  ((float*)&x)[0] = ((float*)px)[0];
!  ((float*)&x)[1] = ((float*)px)[1];
!
!  ((float*)&y)[0] = ((float*)py)[0];
!  ((float*)&y)[1] = ((float*)py)[1];
!
!  x = fabs(x);
!  y = fabs(y);
!
!  c0 = vis_fcmple32(DC1,x);
!  c2 = vis_fcmple32(DC1,y);
!  c1 = vis_fcmpgt32(DC2,x);
!  c3 = vis_fcmpgt32(DC2,y);
!
!  c0 |= c2;
!  c1 &= c3;
!  if ( (c0 & 2) != 0 )
!  {
!    lx = ((int*)px)[1];
!    ly = ((int*)py)[1];
!    hx = *(int*)px;
!    hy = *(int*)py;
!
!    hx &= 0x7fffffff;
!    hy &= 0x7fffffff;
!
!    j0 = hx;
!    if ( j0 < hy ) j0 = hy;
!    j0 &= 0x7ff00000;
!    if ( j0 >= 0x7ff00000 )
!    {
!      if ( hx == 0x7ff00000 && lx == 0 ) res = x == y ? y : x;
!      else if ( hy == 0x7ff00000 && ly == 0 ) res = x == y ? x : y;
!      else res = x * y;
!
!      ((float*)pz)[0] = ((float*)&res)[0];
!      ((float*)pz)[1] = ((float*)&res)[1];
!    }
!    else
!    {
!      diff = hy - hx;
!      j0 = diff >> 31;
!      if ( ((diff ^ j0) - j0) < 0x03600000 )
!      {!
!        x *= D2ONM1022;
!        y *= D2ONM1022;
!
!        x_hi = ( x + two28 ) - two28;
!        x_lo = x - x_hi;
!        y_hi = ( y + two28 ) - two28;
!        y_lo = y - y_hi;
!        res = (x_hi * x_hi + y_hi * y_hi);
!        res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);
!
!        res = sqrt(res);
!
!        res = D2ONP1022 * res;
!        ((float*)pz)[0] = ((float*)&res)[0];
!        ((float*)pz)[1] = ((float*)&res)[1];
!      }
!      else
!      {
!        res = x + y;
!        ((float*)pz)[0] = ((float*)&res)[0];
!        ((float*)pz)[1] = ((float*)&res)[1];
!      }
!    }
!    px += stridex;
!    py += stridey;
!    pz += stridez;
!    continue;
!  }
!  if ( (c1 & 2) != 0 )
!  {
!    x *= D2ONP1022;
!    y *= D2ONP1022;
!
!    x_hi = ( x + two28 ) - two28;
!    x_lo = x - x_hi;
!    y_hi = ( y + two28 ) - two28;
!    y_lo = y - y_hi;
!    res = (x_hi * x_hi + y_hi * y_hi);
!    res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);
!
!    res = sqrt(res);
!
!    res = D2ONM1022 * res;
!    ((float*)pz)[0] = ((float*)&res)[0];
!    ((float*)pz)[1] = ((float*)&res)[1];
!    px += stridex;
!    py += stridey;
!    pz += stridez;
!    continue;
!  }
!
!  dmax = x;
!  if ( dmax < y ) dmax = y;
!
!  dmax = vis_fand(dmax,DC0);
!  dnorm = vis_fpsub32(DC1,dmax);
!
!  x *= dnorm;
!  y *= dnorm;
!
!  x_hi = x + D2ON28;
!  x_hi -= D2ON28;
!  x_lo = x - x_hi;
!
!  y_hi = y + D2ON28;
!  y_hi -= D2ON28;
!  y_lo = y - y_hi;
!
!  res = x_hi * x_hi;
!  dtmp1 = x + x_hi;
!  dtmp0 = y_hi * y_hi;
!  dtmp2 = y + y_hi;
!
!  res += dtmp0;
!  dtmp1 *= x_lo;
!  dtmp2 *= y_lo;
!  dtmp1 += dtmp2;
!  res += dtmp1;
!
!  res = sqrt(res);
!
!  res = dmax * res;
!  ((float*)pz)[0] = ((float*)&res)[0];
!  ((float*)pz)[1] = ((float*)&res)[1];
!
!  px += stridex;
!  py += stridey;
!  pz += stridez;
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vhypot)
	save	%sp,-SA(MINFRAME),%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,o3)
	wr	%g0,0x82,%asi

#ifdef __sparcv9
	ldx	[%fp+STACK_BIAS+176],%l0
#else
	ld	[%fp+STACK_BIAS+92],%l0
#endif
	ldd	[%o3],DC0
	sll	%i2,3,stridex
	mov	%i0,tmp_counter

	ldd	[%o3+8],DC1
	sll	%i4,3,stridey
	mov	%i1,tmp_px

	ldd	[%o3+16],DC2
	sll	%l0,3,stridez
	mov	%i3,tmp_py

	ldd	[%o3+24],D2ON28

	ldd	[%o3+32],DC3

.begin:
	mov	tmp_counter,counter
	mov	tmp_px,%i1
	mov	tmp_py,%i3
	clr	tmp_counter
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit
	nop

	lda	[%i1]%asi,%o0
	sethi	%hi(0x7ffffc00),%o5

	lda	[%i3]%asi,%o2
	add	%o5,1023,%o5

	lda	[%i1]%asi,%f26		! (1_0) ((float*)&x)[0] = ((float*)px)[0];

	lda	[%i1+4]%asi,%f27	! (1_0) ((float*)&x)[1] = ((float*)px)[1];
	add	%i1,stridex,%o1		! px += stridex

	lda	[%i3]%asi,%f24		! (1_0) ((float*)&y)[0] = ((float*)py)[0];
	sethi	%hi(0x00100000),%l7
	and	%o0,%o5,%o0

	lda	[%i3+4]%asi,%f25	! (1_0) ((float*)&y)[1] = ((float*)py)[1];
	and	%o2,%o5,%o2
	sethi	%hi(0x7fe00000),%l6

	fabsd	%f26,%f36		! (1_0) x = fabs(x);
	cmp	%o0,%o2
	mov	%o2,%l4

	fabsd	%f24,%f54		! (1_0) y = fabs(y);
	add	%i3,stridey,%o5		! py += stridey
	movg	%icc,%o0,%o2
	lda	[%o5]%asi,%f28		! (2_0) ((float*)&y)[0] = ((float*)py)[0];

	cmp	%o2,%l6
	sethi	%hi(0x7ff00000),%o4
	bge,pn	%icc,.spec0
	lda	[%o5+4]%asi,%f29	! (2_0) ((float*)&y)[1] = ((float*)py)[1];

	cmp	%o2,%l7
	bl,pn	%icc,.spec1
	nop
	lda	[%o1]%asi,%f26		! (2_0) ((float*)&x)[0] = ((float*)px)[0];

	lda	[%o1+4]%asi,%f27	! (2_0) ((float*)&x)[1] = ((float*)px)[1];
	add	%i3,stridey,%i3		! py += stridey

	fabsd	%f28,%f34		! (2_0) y = fabs(y);

	fabsd	%f26,%f50		! (2_0) x = fabs(x);

	fcmple32	DC1,%f50,%o3	! (2_0) c0 = vis_fcmple32(DC1,x);

	fcmple32	DC1,%f34,%o0	! (2_0) c2 = vis_fcmple32(DC1,y);

	fcmpgt32	DC2,%f50,%o4	! (2_0) c1 = vis_fcmpgt32(DC2,x);

	fcmpgt32	DC2,%f34,%o5	! (2_0) c3 = vis_fcmpgt32(DC2,y);

	or	%o3,%o0,%o3		! (2_0) c0 |= c2;

	andcc	%o3,2,%g0		! (2_0) c0 & 2
	bnz,pn	%icc,.update0		! (2_0) if ( (c0 & 2) != 0 )
	and	%o4,%o5,%o4		! (2_0) c1 &= c3;
.cont0:
	add	%i3,stridey,%l4		! py += stridey
	andcc	%o4,2,%g0		! (2_0) c1 & 2
	bnz,pn	%icc,.update1		! (2_0) if ( (c1 & 2) != 0 )
	fmovd	%f36,%f56		! (1_0) dmax = x;
.cont1:
	lda	[%l4]%asi,%f30		! (3_0) ((float*)&y)[0] = ((float*)py)[0];
	add	%o1,stridex,%l2		! px += stridex

	lda	[%l4+4]%asi,%f31	! (3_0) ((float*)&y)[1] = ((float*)py)[1];

	lda	[%l2]%asi,%f18		! (3_1) ((float*)&x)[0] = ((float*)px)[0];

	lda	[%l2+4]%asi,%f19	! (3_1) ((float*)&x)[1] = ((float*)px)[1];

	fabsd	%f30,%f30		! (3_1) y = fabs(y);

	fabsd	%f18,%f18		! (3_1) x = fabs(x);

	fcmped	%fcc2,%f54,%f56		! (1_1) dmax ? y

	fmovdg	%fcc2,%f54,%f56		! (1_1) if ( dmax < y ) dmax = y;

	fcmple32	DC1,%f18,%o3	! (3_1) c0 = vis_fcmple32(DC1,x);

	fcmple32	DC1,%f30,%o0	! (3_1) c2 = vis_fcmple32(DC1,y);

	fcmpgt32	DC2,%f18,%o4	! (3_1) c1 = vis_fcmpgt32(DC2,x);

	fcmpgt32	DC2,%f30,%o1	! (3_1) c3 = vis_fcmpgt32(DC2,y);

	fand	%f56,DC0,%f38		! (1_1) dmax = vis_fand(dmax,DC0);

	or	%o3,%o0,%o3		! (3_1) c0 |= c2;

	andcc	%o3,2,%g0		! (3_1) c0 & 2
	bnz,pn	%icc,.update2		! (3_1) if ( (c0 & 2) != 0 )
	and	%o4,%o1,%o4		! (3_1) c1 &= c3;
.cont2:
	add	%l4,stridey,%i3		! py += stridey
	andcc	%o4,2,%g0		! (3_1) c1 & 2
	bnz,pn	%icc,.update3		! (3_1) if ( (c1 & 2) != 0 )
	fmovd	%f50,%f32		! (2_1) dmax = x;
.cont3:
	fpsub32	DC1,%f38,%f10		! (1_1) dnorm = vis_fpsub32(DC1,dmax);
	lda	[%i3]%asi,%f20		! (0_0) ((float*)&y)[0] = ((float*)py)[0];

	lda	[%i3+4]%asi,%f21	! (0_0) ((float*)&y)[1] = ((float*)py)[1];

	add	%l2,stridex,%l1		! px += stridex

	fmuld	%f36,%f10,%f36		! (1_1) x *= dnorm;
	lda	[%l1]%asi,%f22		! (0_0) ((float*)&x)[0] = ((float*)px)[0]

	lda	[%l1+4]%asi,%f23	! (0_0) ((float*)&x)[1] = ((float*)px)[1];

	fmuld	%f54,%f10,%f56		! (1_1) y *= dnorm;
	fabsd	%f20,%f40		! (0_0) y = fabs(y);

	fabsd	%f22,%f20		! (0_0) x = fabs(x);

	fcmped	%fcc3,%f34,%f32		! (2_1) dmax ? y


	fmovdg	%fcc3,%f34,%f32		! (2_1) if ( dmax < y ) dmax = y;

	faddd	%f36,D2ON28,%f58	! (1_1) x_hi = x + D2ON28;
	fcmple32	DC1,%f20,%g5	! (0_0) c0 = vis_fcmple32(DC1,x);

	faddd	%f56,D2ON28,%f22	! (1_1) y_hi = y + D2ON28;
	fcmple32	DC1,%f40,%o2	! (0_0) c2 = vis_fcmple32(DC1,y);

	fcmpgt32	DC2,%f20,%g1	! (0_0) c1 = vis_fcmpgt32(DC2,x);

	fcmpgt32	DC2,%f40,%o4	! (0_0) c3 = vis_fcmpgt32(DC2,y);

	fand	%f32,DC0,%f52		! (2_1) dmax = vis_fand(dmax,DC0);

	or	%g5,%o2,%g5		! (0_0) c0 |= c2;
	fsubd	%f58,D2ON28,%f58	! (1_1) x_hi -= D2ON28;

	andcc	%g5,2,%g0		! (0_0) c0 & 2
	bnz,pn	%icc,.update4		! (0_0) if ( (c0 & 2) != 0 )
	fsubd	%f22,D2ON28,%f22	! (1_1) y_hi -= D2ON28;
.cont4:
	and	%g1,%o4,%g1		! (0_0) c1 &= c3;

	add	%i3,stridey,%l2		! py += stridey
	andcc	%g1,2,%g0		! (0_0) c1 & 2
	bnz,pn	%icc,.update5		! (0_0) if ( (c1 & 2) != 0 )
	fmovd	%f18,%f44		! (3_1) dmax = x;
.cont5:
	fpsub32	DC1,%f52,%f10		! (2_1) dnorm = vis_fpsub32(DC1,dmax);
	lda	[%l2]%asi,%f24		! (1_0) ((float*)&y)[0] = ((float*)py)[0];

	fmuld	%f58,%f58,%f60		! (1_1) res = x_hi * x_hi;
	lda	[%l2+4]%asi,%f25	! (1_0) ((float*)&y)[1] = ((float*)py)[1];
	add	%l1,stridex,%l7		! px += stridex
	faddd	%f56,%f22,%f28		! (1_1) dtmp2 = y + y_hi;

	faddd	%f36,%f58,%f6		! (1_1) dtmp1 = x + x_hi;
	lda	[%l7]%asi,%f26		! (1_0) ((float*)&x)[0] = ((float*)px)[0];

	fmuld	%f50,%f10,%f50		! (2_1) x *= dnorm;
	fsubd	%f36,%f58,%f58		! (1_1) x_lo = x - x_hi;
	lda	[%l7+4]%asi,%f27	! (1_0) ((float*)&x)[1] = ((float*)px)[1];

	fmuld	%f22,%f22,%f2		! (1_1) dtmp0 = y_hi * y_hi;
	fsubd	%f56,%f22,%f56		! (1_1) y_lo = y - y_hi;

	fmuld	%f34,%f10,%f34		! (2_1) y *= dnorm;
	fabsd	%f24,%f54		! (1_0) y = fabs(y);

	fabsd	%f26,%f36		! (1_0) x = fabs(x);

	fmuld	%f6,%f58,%f10		! (1_1) dtmp1 *= x_lo;
	fcmped	%fcc0,%f30,%f44		! (3_1) dmax ? y

	fmuld	%f28,%f56,%f26		! (1_1) dtmp2 *= y_lo;

	fmovdg	%fcc0,%f30,%f44		! (3_1) if ( dmax < y ) dmax = y;

	faddd	%f50,D2ON28,%f58	! (2_1) x_hi = x + D2ON28;
	fcmple32	DC1,%f36,%g1	! (1_0) c0 = vis_fcmple32(DC1,x);

	faddd	%f34,D2ON28,%f22	! (2_1) y_hi = y + D2ON28;
	fcmple32	DC1,%f54,%g5	! (1_0) c2 = vis_fcmple32(DC1,y);

	faddd	%f60,%f2,%f24		! (1_1) res += dtmp0;
	fcmpgt32	DC2,%f36,%o5	! (1_0) c1 = vis_fcmpgt32(DC2,x);

	faddd	%f10,%f26,%f28		! (1_1) dtmp1 += dtmp2;
	fcmpgt32	DC2,%f54,%o1	! (1_0) c3 = vis_fcmpgt32(DC2,y);

	fand	%f44,DC0,%f14		! (3_1) dmax = vis_fand(dmax,DC0);

	or	%g1,%g5,%g1		! (1_0) c0 |= c2;
	fsubd	%f58,D2ON28,%f44	! (2_1) x_hi -= D2ON28;

	andcc	%g1,2,%g0		! (1_0) c0 & 2
	bnz,pn	%icc,.update6		! (1_0) if ( (c0 & 2) != 0 )
	fsubd	%f22,D2ON28,%f58	! (2_1) y_hi -= D2ON28;
.cont6:
	and	%o5,%o1,%o5		! (1_0) c1 &= c3;
	faddd	%f24,%f28,%f26		! (1_1) res += dtmp1;

	add	%l2,stridey,%i3		! py += stridey
	andcc	%o5,2,%g0		! (1_0) c1 & 2
	bnz,pn	%icc,.update7		! (1_0) if ( (c1 & 2) != 0 )
	fmovd	%f20,%f4		! (0_0) dmax = x;
.cont7:
	fpsub32	DC1,%f14,%f10		! (3_1) dnorm = vis_fpsub32(DC1,dmax);
	lda	[%i3]%asi,%f28		! (2_0) ((float*)&y)[0] = ((float*)py)[0];

	fmuld	%f44,%f44,%f2		! (2_1) res = x_hi * x_hi;
	lda	[%i3+4]%asi,%f29	! (2_0) ((float*)&y)[1] = ((float*)py)[1];
	add	%l7,stridex,%o1		! px += stridex
	faddd	%f34,%f58,%f60		! (2_1) dtmp2 = y + y_hi;

	fsqrtd	%f26,%f24		! (1_1) res = sqrt(res);
	lda	[%o1]%asi,%f26		! (2_0) ((float*)&x)[0] = ((float*)px)[0];
	faddd	%f50,%f44,%f56		! (2_1) dtmp1 = x + x_hi;

	fmuld	%f18,%f10,%f6		! (3_1) x *= dnorm;
	fsubd	%f50,%f44,%f18		! (2_1) x_lo = x - x_hi;
	lda	[%o1+4]%asi,%f27	! (2_0) ((float*)&x)[1] = ((float*)px)[1];

	fmuld	%f58,%f58,%f44		! (2_1) dtmp0 = y_hi * y_hi;
	fsubd	%f34,%f58,%f22		! (2_1) y_lo = y - y_hi;

	fmuld	%f30,%f10,%f58		! (3_1) y *= dnorm;
	fabsd	%f28,%f34		! (2_0) y = fabs(y);

	fabsd	%f26,%f50		! (2_0) x = fabs(x);

	fmuld	%f56,%f18,%f10		! (2_1) dtmp1 *= x_lo;
	fcmped	%fcc1,%f40,%f4		! (0_0) dmax ? y

	fmuld	%f60,%f22,%f12		! (2_1) dtmp2 *= y_lo;

	fmovdg	%fcc1,%f40,%f4		! (0_0) if ( dmax < y ) dmax = y;

	faddd	%f6,D2ON28,%f56		! (3_1) x_hi = x + D2ON28;
	fcmple32	DC1,%f50,%o3	! (2_0) c0 = vis_fcmple32(DC1,x);

	faddd	%f58,D2ON28,%f28	! (3_1) y_hi = y + D2ON28;
	fcmple32	DC1,%f34,%o0	! (2_0) c2 = vis_fcmple32(DC1,y);

	faddd	%f2,%f44,%f30		! (2_1) res += dtmp0;
	fcmpgt32	DC2,%f50,%o4	! (2_0) c1 = vis_fcmpgt32(DC2,x);

	faddd	%f10,%f12,%f26		! (2_1) dtmp1 += dtmp2;
	fcmpgt32	DC2,%f34,%o5	! (2_0) c3 = vis_fcmpgt32(DC2,y);

	fand	%f4,DC0,%f16		! (0_0) dmax = vis_fand(dmax,DC0);

	or	%o3,%o0,%o3		! (2_0) c0 |= c2;
	fsubd	%f56,D2ON28,%f18	! (3_1) x_hi -= D2ON28;

	andcc	%o3,2,%g0		! (2_0) c0 & 2
	bnz,pn	%icc,.update8		! (2_0) if ( (c0 & 2) != 0 )
	fsubd	%f28,D2ON28,%f4		! (3_1) y_hi -= D2ON28;
.cont8:
	and	%o4,%o5,%o4		! (2_0) c1 &= c3;
	faddd	%f30,%f26,%f12		! (2_1) res += dtmp1;

	add	%i3,stridey,%l4		! py += stridey
	andcc	%o4,2,%g0		! (2_0) c1 & 2
	bnz,pn	%icc,.update9		! (2_0) if ( (c1 & 2) != 0 )
	fmovd	%f36,%f56		! (1_0) dmax = x;
.cont9:
	lda	[%l4]%asi,%f30		! (3_0) ((float*)&y)[0] = ((float*)py)[0];
	add	%o1,stridex,%l2		! px += stridex
	fpsub32	DC1,%f16,%f44		! (0_0) dnorm = vis_fpsub32(DC1,dmax);

	fmuld	%f18,%f18,%f60		! (3_1) res = x_hi * x_hi;
	lda	[%l4+4]%asi,%f31	! (3_0) ((float*)&y)[1] = ((float*)py)[1];
	faddd	%f58,%f4,%f32		! (3_1) dtmp2 = y + y_hi;

	fsqrtd	%f12,%f12		! (2_1) res = sqrt(res);
	faddd	%f6,%f18,%f28		! (3_1) dtmp1 = x + x_hi;

	cmp	counter,4
	bl,pn	%icc,.tail
	nop

	ba	.main_loop
	sub	counter,4,counter

	.align	16
.main_loop:
	fmuld	%f20,%f44,%f2		! (0_1) x *= dnorm;
	fsubd	%f6,%f18,%f20		! (3_2) x_lo = x - x_hi;
	lda	[%l2]%asi,%f18		! (3_1) ((float*)&x)[0] = ((float*)px)[0];

	fmuld	%f4,%f4,%f22		! (3_2) dtmp0 = y_hi * y_hi;
	lda	[%l2+4]%asi,%f19	! (3_1) ((float*)&x)[1] = ((float*)px)[1];
	fsubd	%f58,%f4,%f58		! (3_2) y_lo = y - y_hi;

	fmuld	%f40,%f44,%f44		! (0_1) y *= dnorm;
	fabsd	%f30,%f30		! (3_1) y = fabs(y);

	fmuld	%f38,%f24,%f10		! (1_2) res = dmax * res;
	fabsd	%f18,%f18		! (3_1) x = fabs(x);
	st	%f10,[%i5]		! (1_2) ((float*)pz)[0] = ((float*)&res)[0];

	fmuld	%f28,%f20,%f28		! (3_2) dtmp1 *= x_lo;
	st	%f11,[%i5+4]		! (1_2) ((float*)pz)[1] = ((float*)&res)[1];
	fcmped	%fcc2,%f54,%f56		! (1_1) dmax ? y

	fmuld	%f32,%f58,%f24		! (3_2) dtmp2 *= y_lo;

	fmovdg	%fcc2,%f54,%f56		! (1_1) if ( dmax < y ) dmax = y;

	faddd	%f2,D2ON28,%f10		! (0_1) x_hi = x + D2ON28;
	fcmple32	DC1,%f18,%o3	! (3_1) c0 = vis_fcmple32(DC1,x);

	faddd	%f44,D2ON28,%f20	! (0_1) y_hi = y + D2ON28;
	fcmple32	DC1,%f30,%o0	! (3_1) c2 = vis_fcmple32(DC1,y);

	faddd	%f60,%f22,%f22		! (3_2) res += dtmp0;
	fcmpgt32	DC2,%f18,%o4	! (3_1) c1 = vis_fcmpgt32(DC2,x);

	faddd	%f28,%f24,%f26		! (3_2) dtmp1 += dtmp2;
	fcmpgt32	DC2,%f30,%o1	! (3_1) c3 = vis_fcmpgt32(DC2,y);

	fand	%f56,DC0,%f38		! (1_1) dmax = vis_fand(dmax,DC0);

	or	%o3,%o0,%o3		! (3_1) c0 |= c2;
	fsubd	%f10,D2ON28,%f58	! (0_1) x_hi -= D2ON28;

	andcc	%o3,2,%g0		! (3_1) c0 & 2
	bnz,pn	%icc,.update10		! (3_1) if ( (c0 & 2) != 0 )
	fsubd	%f20,D2ON28,%f56	! (0_1) y_hi -= D2ON28;
.cont10:
	faddd	%f22,%f26,%f28		! (3_2) res += dtmp1;
	and	%o4,%o1,%o4		! (3_1) c1 &= c3;

	add	%l4,stridey,%i3		! py += stridey
	andcc	%o4,2,%g0		! (3_1) c1 & 2
	bnz,pn	%icc,.update11		! (3_1) if ( (c1 & 2) != 0 )
	fmovd	%f50,%f32		! (2_1) dmax = x;
.cont11:
	fpsub32	DC1,%f38,%f10		! (1_1) dnorm = vis_fpsub32(DC1,dmax);
	add	%l2,stridex,%l1		! px += stridex
	lda	[%i3]%asi,%f20		! (0_0) ((float*)&y)[0] = ((float*)py)[0];

	fmuld	%f58,%f58,%f6		! (0_1) res = x_hi * x_hi;
	lda	[%i3+4]%asi,%f21	! (0_0) ((float*)&y)[1] = ((float*)py)[1];
	add	%i5,stridez,%l6		! pz += stridez
	faddd	%f44,%f56,%f60		! (0_1) dtmp2 = y + y_hi;

	fsqrtd	%f28,%f4		! (3_2) res = sqrt(res);
	lda	[%l1]%asi,%f22		! (0_0) ((float*)&x)[0] = ((float*)px)[0];
	faddd	%f2,%f58,%f24		! (0_1) dtmp1 = x + x_hi;

	fmuld	%f36,%f10,%f36		! (1_1) x *= dnorm;
	fsubd	%f2,%f58,%f26		! (0_1) x_lo = x - x_hi;
	lda	[%l1+4]%asi,%f23	! (0_0) ((float*)&x)[1] = ((float*)px)[1];

	fmuld	%f56,%f56,%f28		! (0_1) dtmp0 = y_hi * y_hi;
	fsubd	%f44,%f56,%f44		! (0_1) y_lo = y - y_hi;

	fmuld	%f54,%f10,%f56		! (1_1) y *= dnorm;
	fabsd	%f20,%f40		! (0_0) y = fabs(y);

	fmuld	%f52,%f12,%f12		! (2_2) res = dmax * res;
	fabsd	%f22,%f20		! (0_0) x = fabs(x);
	st	%f12,[%l6]		! (2_2) ((float*)pz)[0] = ((float*)&res)[0];

	fmuld	%f24,%f26,%f10		! (0_1) dtmp1 *= x_lo;
	st	%f13,[%l6+4]		! (2_2) ((float*)pz)[1] = ((float*)&res)[1];
	fcmped	%fcc3,%f34,%f32		! (2_1) dmax ? y

	fmuld	%f60,%f44,%f12		! (0_1) dtmp2 *= y_lo;

	fmovdg	%fcc3,%f34,%f32		! (2_1) if ( dmax < y ) dmax = y;

	faddd	%f36,D2ON28,%f58	! (1_1) x_hi = x + D2ON28;
	fcmple32	DC1,%f20,%g5	! (0_0) c0 = vis_fcmple32(DC1,x);

	faddd	%f56,D2ON28,%f22	! (1_1) y_hi = y + D2ON28;
	fcmple32	DC1,%f40,%o2	! (0_0) c2 = vis_fcmple32(DC1,y);

	faddd	%f6,%f28,%f24		! (0_1) res += dtmp0;
	fcmpgt32	DC2,%f20,%g1	! (0_0) c1 = vis_fcmpgt32(DC2,x);

	faddd	%f10,%f12,%f26		! (0_1) dtmp1 += dtmp2;
	fcmpgt32	DC2,%f40,%o4	! (0_0) c3 = vis_fcmpgt32(DC2,y);

	fand	%f32,DC0,%f52		! (2_1) dmax = vis_fand(dmax,DC0);

	or	%g5,%o2,%g5		! (0_0) c0 |= c2;
	fsubd	%f58,D2ON28,%f58	! (1_1) x_hi -= D2ON28;

	andcc	%g5,2,%g0		! (0_0) c0 & 2
	bnz,pn	%icc,.update12		! (0_0) if ( (c0 & 2) != 0 )
	fsubd	%f22,D2ON28,%f22	! (1_1) y_hi -= D2ON28;
.cont12:
	and	%g1,%o4,%g1		! (0_0) c1 &= c3;
	faddd	%f24,%f26,%f12		! (0_1) res += dtmp1;

	add	%i3,stridey,%l2		! py += stridey
	andcc	%g1,2,%g0		! (0_0) c1 & 2
	bnz,pn	%icc,.update13		! (0_0) if ( (c1 & 2) != 0 )
	fmovd	%f18,%f44		! (3_1) dmax = x;
.cont13:
	fpsub32	DC1,%f52,%f10		! (2_1) dnorm = vis_fpsub32(DC1,dmax);
	add	%l1,stridex,%l7		! px += stridex
	lda	[%l2]%asi,%f24		! (1_0) ((float*)&y)[0] = ((float*)py)[0];

	fmuld	%f58,%f58,%f60		! (1_1) res = x_hi * x_hi;
	add	%l6,stridez,%i5		! pz += stridez
	lda	[%l2+4]%asi,%f25	! (1_0) ((float*)&y)[1] = ((float*)py)[1];
	faddd	%f56,%f22,%f28		! (1_1) dtmp2 = y + y_hi;

	fsqrtd	%f12,%f12		! (0_1) res = sqrt(res);
	lda	[%l7]%asi,%f26		! (1_0) ((float*)&x)[0] = ((float*)px)[0];
	faddd	%f36,%f58,%f6		! (1_1) dtmp1 = x + x_hi;

	fmuld	%f50,%f10,%f50		! (2_1) x *= dnorm;
	fsubd	%f36,%f58,%f58		! (1_1) x_lo = x - x_hi;
	lda	[%l7+4]%asi,%f27	! (1_0) ((float*)&x)[1] = ((float*)px)[1];

	fmuld	%f22,%f22,%f2		! (1_1) dtmp0 = y_hi * y_hi;
	fsubd	%f56,%f22,%f56		! (1_1) y_lo = y - y_hi;

	fmuld	%f34,%f10,%f34		! (2_1) y *= dnorm;
	fabsd	%f24,%f54		! (1_0) y = fabs(y);

	fmuld	%f14,%f4,%f14		! (3_2) res = dmax * res;
	fabsd	%f26,%f36		! (1_0) x = fabs(x);
	st	%f14,[%i5]		! (3_2) ((float*)pz)[0] = ((float*)&res)[0];

	fmuld	%f6,%f58,%f10		! (1_1) dtmp1 *= x_lo;
	st	%f15,[%i5+4]		! (3_2) ((float*)pz)[1] = ((float*)&res)[1];
	fcmped	%fcc0,%f30,%f44		! (3_1) dmax ? y

	fmuld	%f28,%f56,%f26		! (1_1) dtmp2 *= y_lo;

	fmovdg	%fcc0,%f30,%f44		! (3_1) if ( dmax < y ) dmax = y;

	faddd	%f50,D2ON28,%f58	! (2_1) x_hi = x + D2ON28;
	fcmple32	DC1,%f36,%g1	! (1_0) c0 = vis_fcmple32(DC1,x);

	faddd	%f34,D2ON28,%f22	! (2_1) y_hi = y + D2ON28;
	fcmple32	DC1,%f54,%g5	! (1_0) c2 = vis_fcmple32(DC1,y);

	faddd	%f60,%f2,%f24		! (1_1) res += dtmp0;
	fcmpgt32	DC2,%f36,%o5	! (1_0) c1 = vis_fcmpgt32(DC2,x);

	faddd	%f10,%f26,%f28		! (1_1) dtmp1 += dtmp2;
	fcmpgt32	DC2,%f54,%o1	! (1_0) c3 = vis_fcmpgt32(DC2,y);

	fand	%f44,DC0,%f14		! (3_1) dmax = vis_fand(dmax,DC0);

	or	%g1,%g5,%g1		! (1_0) c0 |= c2;
	fsubd	%f58,D2ON28,%f44	! (2_1) x_hi -= D2ON28;

	andcc	%g1,2,%g0		! (1_0) c0 & 2
	bnz,pn	%icc,.update14		! (1_0) if ( (c0 & 2) != 0 )
	fsubd	%f22,D2ON28,%f58	! (2_1) y_hi -= D2ON28;
.cont14:
	and	%o5,%o1,%o5		! (1_0) c1 &= c3;
	faddd	%f24,%f28,%f26		! (1_1) res += dtmp1;

	add	%l2,stridey,%i3		! py += stridey
	andcc	%o5,2,%g0		! (1_0) c1 & 2
	bnz,pn	%icc,.update15		! (1_0) if ( (c1 & 2) != 0 )
	fmovd	%f20,%f4		! (0_0) dmax = x;
.cont15:
	fpsub32	DC1,%f14,%f10		! (3_1) dnorm = vis_fpsub32(DC1,dmax);
	add	%l7,stridex,%o1		! px += stridex
	lda	[%i3]%asi,%f28		! (2_0) ((float*)&y)[0] = ((float*)py)[0];

	fmuld	%f44,%f44,%f2		! (2_1) res = x_hi * x_hi;
	add	%i5,stridez,%g5		! pz += stridez
	lda	[%i3+4]%asi,%f29	! (2_0) ((float*)&y)[1] = ((float*)py)[1];
	faddd	%f34,%f58,%f60		! (2_1) dtmp2 = y + y_hi;

	fsqrtd	%f26,%f24		! (1_1) res = sqrt(res);
	lda	[%o1]%asi,%f26		! (2_0) ((float*)&x)[0] = ((float*)px)[0];
	faddd	%f50,%f44,%f56		! (2_1) dtmp1 = x + x_hi;

	fmuld	%f18,%f10,%f6		! (3_1) x *= dnorm;
	fsubd	%f50,%f44,%f18		! (2_1) x_lo = x - x_hi;
	lda	[%o1+4]%asi,%f27	! (2_0) ((float*)&x)[1] = ((float*)px)[1];

	fmuld	%f58,%f58,%f44		! (2_1) dtmp0 = y_hi * y_hi;
	fsubd	%f34,%f58,%f22		! (2_1) y_lo = y - y_hi;

	fmuld	%f30,%f10,%f58		! (3_1) y *= dnorm;
	fabsd	%f28,%f34		! (2_0) y = fabs(y);

	fmuld	%f16,%f12,%f16		! (0_1) res = dmax * res;
	fabsd	%f26,%f50		! (2_0) x = fabs(x);
	st	%f16,[%g5]		! (0_1) ((float*)pz)[0] = ((float*)&res)[0];

	fmuld	%f56,%f18,%f10		! (2_1) dtmp1 *= x_lo;
	st	%f17,[%g5+4]		! (0_1) ((float*)pz)[1] = ((float*)&res)[1];
	fcmped	%fcc1,%f40,%f4		! (0_0) dmax ? y

	fmuld	%f60,%f22,%f12		! (2_1) dtmp2 *= y_lo;

	fmovdg	%fcc1,%f40,%f4		! (0_0) if ( dmax < y ) dmax = y;

	faddd	%f6,D2ON28,%f56		! (3_1) x_hi = x + D2ON28;
	fcmple32	DC1,%f50,%o3	! (2_0) c0 = vis_fcmple32(DC1,x);

	faddd	%f58,D2ON28,%f28	! (3_1) y_hi = y + D2ON28;
	fcmple32	DC1,%f34,%o0	! (2_0) c2 = vis_fcmple32(DC1,y);

	faddd	%f2,%f44,%f30		! (2_1) res += dtmp0;
	fcmpgt32	DC2,%f50,%o4	! (2_0) c1 = vis_fcmpgt32(DC2,x);

	faddd	%f10,%f12,%f26		! (2_1) dtmp1 += dtmp2;
	fcmpgt32	DC2,%f34,%o5	! (2_0) c3 = vis_fcmpgt32(DC2,y);

	fand	%f4,DC0,%f16		! (0_0) dmax = vis_fand(dmax,DC0);

	or	%o3,%o0,%o3		! (2_0) c0 |= c2;
	fsubd	%f56,D2ON28,%f18	! (3_1) x_hi -= D2ON28;

	andcc	%o3,2,%g0		! (2_0) c0 & 2
	bnz,pn	%icc,.update16		! (2_0) if ( (c0 & 2) != 0 )
	fsubd	%f28,D2ON28,%f4		! (3_1) y_hi -= D2ON28;
.cont16:
	and	%o4,%o5,%o4		! (2_0) c1 &= c3;
	faddd	%f30,%f26,%f12		! (2_1) res += dtmp1;

	add	%i3,stridey,%l4		! py += stridey
	andcc	%o4,2,%g0		! (2_0) c1 & 2
	bnz,pn	%icc,.update17		! (2_0) if ( (c1 & 2) != 0 )
	fmovd	%f36,%f56		! (1_0) dmax = x;
.cont17:
	lda	[%l4]%asi,%f30		! (3_0) ((float*)&y)[0] = ((float*)py)[0];
	add	%o1,stridex,%l2		! px += stridex
	fpsub32	DC1,%f16,%f44		! (0_0) dnorm = vis_fpsub32(DC1,dmax);

	fmuld	%f18,%f18,%f60		! (3_1) res = x_hi * x_hi;
	add	%g5,stridez,%i5		! pz += stridez
	lda	[%l4+4]%asi,%f31	! (3_0) ((float*)&y)[1] = ((float*)py)[1];
	faddd	%f58,%f4,%f32		! (3_1) dtmp2 = y + y_hi;

	fsqrtd	%f12,%f12		! (2_1) res = sqrt(res);
	subcc	counter,4,counter	! counter -= 4;
	bpos,pt	%icc,.main_loop
	faddd	%f6,%f18,%f28		! (3_1) dtmp1 = x + x_hi;

	add	counter,4,counter

.tail:
	subcc	counter,1,counter
	bneg,a	.begin
	nop

	fsubd	%f6,%f18,%f20		! (3_2) x_lo = x - x_hi;

	fmuld	%f4,%f4,%f22		! (3_2) dtmp0 = y_hi * y_hi;
	fsubd	%f58,%f4,%f58		! (3_2) y_lo = y - y_hi;

	fmuld	%f38,%f24,%f10		! (1_2) res = dmax * res;
	st	%f10,[%i5]		! (1_2) ((float*)pz)[0] = ((float*)&res)[0];

	st	%f11,[%i5+4]		! (1_2) ((float*)pz)[1] = ((float*)&res)[1];

	subcc	counter,1,counter
	bneg,a	.begin
	add	%i5,stridez,%i5

	fmuld	%f28,%f20,%f28		! (3_2) dtmp1 *= x_lo;

	fmuld	%f32,%f58,%f24		! (3_2) dtmp2 *= y_lo;

	faddd	%f60,%f22,%f22		! (3_2) res += dtmp0;

	faddd	%f28,%f24,%f26		! (3_2) dtmp1 += dtmp2;

	faddd	%f22,%f26,%f28		! (3_2) res += dtmp1;

	add	%i5,stridez,%l6		! pz += stridez

	fsqrtd	%f28,%f4		! (3_2) res = sqrt(res);
	add	%l2,stridex,%l1		! px += stridex

	fmuld	%f52,%f12,%f12		! (2_2) res = dmax * res;
	st	%f12,[%l6]		! (2_2) ((float*)pz)[0] = ((float*)&res)[0];

	st	%f13,[%l6+4]		! (2_2) ((float*)pz)[1] = ((float*)&res)[1];

	subcc	counter,1,counter
	bneg	.begin
	add	%l6,stridez,%i5

	fmuld	%f14,%f4,%f14		! (3_2) res = dmax * res;
	st	%f14,[%i5]		! (3_2) ((float*)pz)[0] = ((float*)&res)[0];

	st	%f15,[%i5+4]		! (3_2) ((float*)pz)[1] = ((float*)&res)[1];

	ba	.begin
	add	%i5,stridez,%i5

	.align	16
.spec0:
	ld	[%i1+4],%l1		! lx = ((int*)px)[1];
	cmp	%o2,%o4			! j0 ? 0x7ff00000
	bge,pn	%icc,1f			! if ( j0 >= 0x7ff00000 )
	fabsd	%f26,%f26		! x = fabs(x);

	sub	%o0,%l4,%o0		! diff = hy - hx;
	fabsd	%f24,%f24		! y = fabs(y);

	sra	%o0,31,%l4		! j0 = diff >> 31;

	xor	%o0,%l4,%o0		! diff ^ j0

	sethi	%hi(0x03600000),%l1
	sub	%o0,%l4,%o0		! (diff ^ j0) - j0

	cmp	%o0,%l1			! ((diff ^ j0) - j0) ? 0x03600000
	bge,a,pn	%icc,2f		! if ( ((diff ^ j0) - j0) >= 0x03600000 )
	faddd	%f26,%f24,%f24		! *pz = x + y

	fmuld	%f26,DC2,%f36		! (1_1) x *= dnorm;

	fmuld	%f24,DC2,%f56		! (1_1) y *= dnorm;

	faddd	%f36,D2ON28,%f58	! (1_1) x_hi = x + D2ON28;

	faddd	%f56,D2ON28,%f22	! (1_1) y_hi = y + D2ON28;

	fsubd	%f58,D2ON28,%f58	! (1_1) x_hi -= D2ON28;

	fsubd	%f22,D2ON28,%f22	! (1_1) y_hi -= D2ON28;

	fmuld	%f58,%f58,%f60		! (1_1) res = x_hi * x_hi;
	faddd	%f56,%f22,%f28		! (1_1) dtmp2 = y + y_hi;

	faddd	%f36,%f58,%f6		! (1_1) dtmp1 = x + x_hi;

	fsubd	%f36,%f58,%f58		! (1_1) x_lo = x - x_hi;

	fmuld	%f22,%f22,%f2		! (1_1) dtmp0 = y_hi * y_hi;
	fsubd	%f56,%f22,%f56		! (1_1) y_lo = y - y_hi;

	fmuld	%f6,%f58,%f10		! (1_1) dtmp1 *= x_lo;

	fmuld	%f28,%f56,%f26		! (1_1) dtmp2 *= y_lo;

	faddd	%f60,%f2,%f24		! (1_1) res += dtmp0;

	faddd	%f10,%f26,%f28		! (1_1) dtmp1 += dtmp2;

	faddd	%f24,%f28,%f26		! (1_1) res += dtmp1;

	fsqrtd	%f26,%f24		! (1_1) res = sqrt(res);

	fmuld	DC3,%f24,%f24		! (1_2) res = dmax * res;
2:
	add	%i3,stridey,%i3
	add	%i1,stridex,%i1
	st	%f24,[%i5]		! ((float*)pz)[0] = ((float*)&res)[0];
	st	%f25,[%i5+4]		! ((float*)pz)[1] = ((float*)&res)[1];

	add	%i5,stridez,%i5
	ba	.begin1
	sub	counter,1,counter

1:
	ld	[%i3+4],%l2		! ly = ((int*)py)[1];
	cmp	%o0,%o4			! hx ? 0x7ff00000
	bne,pn	%icc,1f			! if ( hx != 0x7ff00000 )
	fabsd	%f24,%f24		! y = fabs(y);

	cmp	%l1,0			! lx ? 0
	be,pn	%icc,2f			! if ( lx == 0 )
	nop
1:
	cmp	%l4,%o4			! hy ? 0x7ff00000
	bne,pn	%icc,1f			! if ( hy != 0x7ff00000 )
	nop

	cmp	%l2,0			! ly ? 0
	be,pn	%icc,2f			! if ( ly == 0 )
	nop
1:
	add	%i3,stridey,%i3
	add	%i1,stridex,%i1
	fmuld	%f26,%f24,%f24		! res = x * y;
	st	%f24,[%i5]		! ((float*)pz)[0] = ((float*)&res)[0];

	st	%f25,[%i5+4]		! ((float*)pz)[1] = ((float*)&res)[1];

	add	%i5,stridez,%i5
	ba	.begin1
	sub	counter,1,counter

2:
	add	%i1,stridex,%i1
	add	%i3,stridey,%i3
	st	DC0_HI,[%i5]		! ((int*)pz)[0] = 0x7ff00000;
	st	DC0_LO,[%i5+4]		! ((int*)pz)[1] = 0;
	fcmpd	%f26,%f24		! x ? y

	add	%i5,stridez,%i5
	ba	.begin1
	sub	counter,1,counter

	.align	16
.spec1:
	fmuld	%f26,DC3,%f36		! (1_1) x *= dnorm;

	fmuld	%f24,DC3,%f56		! (1_1) y *= dnorm;

	faddd	%f36,D2ON28,%f58	! (1_1) x_hi = x + D2ON28;

	faddd	%f56,D2ON28,%f22	! (1_1) y_hi = y + D2ON28;

	fsubd	%f58,D2ON28,%f58	! (1_1) x_hi -= D2ON28;

	fsubd	%f22,D2ON28,%f22	! (1_1) y_hi -= D2ON28;

	fmuld	%f58,%f58,%f60		! (1_1) res = x_hi * x_hi;
	faddd	%f56,%f22,%f28		! (1_1) dtmp2 = y + y_hi;

	faddd	%f36,%f58,%f6		! (1_1) dtmp1 = x + x_hi;

	fsubd	%f36,%f58,%f58		! (1_1) x_lo = x - x_hi;

	fmuld	%f22,%f22,%f2		! (1_1) dtmp0 = y_hi * y_hi;
	fsubd	%f56,%f22,%f56		! (1_1) y_lo = y - y_hi;

	fmuld	%f6,%f58,%f10		! (1_1) dtmp1 *= x_lo;

	fmuld	%f28,%f56,%f26		! (1_1) dtmp2 *= y_lo;

	faddd	%f60,%f2,%f24		! (1_1) res += dtmp0;

	faddd	%f10,%f26,%f28		! (1_1) dtmp1 += dtmp2;

	faddd	%f24,%f28,%f26		! (1_1) res += dtmp1;

	fsqrtd	%f26,%f24		! (1_1) res = sqrt(res);

	fmuld	DC2,%f24,%f24		! (1_2) res = dmax * res;

	add	%i3,stridey,%i3
	add	%i1,stridex,%i1
	st	%f24,[%i5]		! ((float*)pz)[0] = ((float*)&res)[0];

	st	%f25,[%i5+4]		! ((float*)pz)[1] = ((float*)&res)[1];
	add	%i5,stridez,%i5
	ba	.begin1
	sub	counter,1,counter

	.align	16
.update0:
	fzero	%f50
	cmp	counter,1
	ble	.cont0
	fzero	%f34

	mov	%o1,tmp_px
	mov	%i3,tmp_py

	sub	counter,1,tmp_counter
	ba	.cont0
	mov	1,counter

	.align	16
.update1:
	fzero	%f50
	cmp	counter,1
	ble	.cont1
	fzero	%f34

	mov	%o1,tmp_px
	mov	%i3,tmp_py

	sub	counter,1,tmp_counter
	ba	.cont1
	mov	1,counter

	.align	16
.update2:
	fzero	%f18
	cmp	counter,2
	ble	.cont2
	fzero	%f30

	mov	%l2,tmp_px
	mov	%l4,tmp_py

	sub	counter,2,tmp_counter
	ba	.cont1
	mov	2,counter

	.align	16
.update3:
	fzero	%f18
	cmp	counter,2
	ble	.cont3
	fzero	%f30

	mov	%l2,tmp_px
	mov	%l4,tmp_py

	sub	counter,2,tmp_counter
	ba	.cont3
	mov	2,counter

	.align	16
.update4:
	fzero	%f20
	cmp	counter,3
	ble	.cont4
	fzero	%f40

	mov	%l1,tmp_px
	mov	%i3,tmp_py

	sub	counter,3,tmp_counter
	ba	.cont4
	mov	3,counter

	.align	16
.update5:
	fzero	%f20
	cmp	counter,3
	ble	.cont5
	fzero	%f40

	mov	%l1,tmp_px
	mov	%i3,tmp_py

	sub	counter,3,tmp_counter
	ba	.cont5
	mov	3,counter

	.align	16
.update6:
	fzero	%f36
	cmp	counter,4
	ble	.cont6
	fzero	%f54

	mov	%l7,tmp_px
	mov	%l2,tmp_py

	sub	counter,4,tmp_counter
	ba	.cont6
	mov	4,counter

	.align	16
.update7:
	fzero	%f36
	cmp	counter,4
	ble	.cont7
	fzero	%f54

	mov	%l7,tmp_px
	mov	%l2,tmp_py

	sub	counter,4,tmp_counter
	ba	.cont7
	mov	4,counter

	.align	16
.update8:
	fzero	%f50
	cmp	counter,5
	ble	.cont8
	fzero	%f34

	mov	%o1,tmp_px
	mov	%i3,tmp_py

	sub	counter,5,tmp_counter
	ba	.cont8
	mov	5,counter

	.align	16
.update9:
	fzero	%f50
	cmp	counter,5
	ble	.cont9
	fzero	%f34

	mov	%o1,tmp_px
	mov	%i3,tmp_py

	sub	counter,5,tmp_counter
	ba	.cont9
	mov	5,counter


	.align	16
.update10:
	fzero	%f18
	cmp	counter,2
	ble	.cont10
	fzero	%f30

	mov	%l2,tmp_px
	mov	%l4,tmp_py

	sub	counter,2,tmp_counter
	ba	.cont10
	mov	2,counter

	.align	16
.update11:
	fzero	%f18
	cmp	counter,2
	ble	.cont11
	fzero	%f30

	mov	%l2,tmp_px
	mov	%l4,tmp_py

	sub	counter,2,tmp_counter
	ba	.cont11
	mov	2,counter

	.align	16
.update12:
	fzero	%f20
	cmp	counter,3
	ble	.cont12
	fzero	%f40

	mov	%l1,tmp_px
	mov	%i3,tmp_py

	sub	counter,3,tmp_counter
	ba	.cont12
	mov	3,counter

	.align	16
.update13:
	fzero	%f20
	cmp	counter,3
	ble	.cont13
	fzero	%f40

	mov	%l1,tmp_px
	mov	%i3,tmp_py

	sub	counter,3,tmp_counter
	ba	.cont13
	mov	3,counter

	.align	16
.update14:
	fzero	%f54
	cmp	counter,4
	ble	.cont14
	fzero	%f36

	mov	%l7,tmp_px
	mov	%l2,tmp_py

	sub	counter,4,tmp_counter
	ba	.cont14
	mov	4,counter

	.align	16
.update15:
	fzero	%f54
	cmp	counter,4
	ble	.cont15
	fzero	%f36

	mov	%l7,tmp_px
	mov	%l2,tmp_py

	sub	counter,4,tmp_counter
	ba	.cont15
	mov	4,counter

	.align	16
.update16:
	fzero	%f50
	cmp	counter,5
	ble	.cont16
	fzero	%f34

	mov	%o1,tmp_px
	mov	%i3,tmp_py

	sub	counter,5,tmp_counter
	ba	.cont16
	mov	5,counter

	.align	16
.update17:
	fzero	%f50
	cmp	counter,5
	ble	.cont17
	fzero	%f34

	mov	%o1,tmp_px
	mov	%i3,tmp_py

	sub	counter,5,tmp_counter
	ba	.cont17
	mov	5,counter

	.align	16
.exit:
	ret
	restore
	SET_SIZE(__vhypot)

