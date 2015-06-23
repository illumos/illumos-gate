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

	.file	"__vatan2f.S"

#include "libm.h"

	RO_DATA
	.align	64
.CONST_TBL:
	.word	0xbff921fb, 0x54442d18	! -M_PI_2
	.word	0x3ff921fb, 0x54442d18	!  M_PI_2
	.word	0xbff921fb, 0x54442d18	! -M_PI_2
	.word	0x3ff921fb, 0x54442d18	!  M_PI_2
	.word	0xc00921fb, 0x54442d18	! -M_PI
	.word	0x400921fb, 0x54442d18	!  M_PI
	.word	0x80000000, 0x00000000	! -0.0
	.word	0x00000000, 0x00000000	!  0.0

	.word	0xbff00000, 0x00000000	! -1.0
	.word	0x3ff00000, 0x00000000	!  1.0

	.word	0x3fefffff, 0xfe79bf93	! K0 =  9.99999997160545464888e-01
	.word	0xbfd55552, 0xf0db4320	! K1 = -3.33332762919825514315e-01
	.word	0x3fc998f8, 0x2493d066	! K2 =  1.99980752811487135558e-01
	.word	0xbfc240b8, 0xd994abf9	! K3 = -1.42600160828209047720e-01
	.word	0x3fbbfc9e, 0x8c2b0243	! K4 =  1.09323415013030928421e-01
	.word	0xbfb56013, 0x64b1cac3	! K5 = -8.34972496830160174704e-02
	.word	0x3fad3ad7, 0x9f53e142	! K6 =  5.70895559303061900411e-02
	.word	0xbf9f148f, 0x2a829af1	! K7 = -3.03518647857811706139e-02
	.word	0x3f857a8c, 0x747ed314	! K8 =  1.04876492549493055747e-02
	.word	0xbf5bdf39, 0x729124b6	! K9 = -1.70117006406859722727e-03

	.word	0x3fe921fb, 0x54442d18	! M_PI_4
	.word	0x36a00000, 0x00000000	! 2^(-149)

#define counter		%o3
#define stridex		%i4
#define stridey		%i5
#define stridez		%l1
#define cmul_arr	%i0
#define cadd_arr	%i2
#define _0x7fffffff	%l0
#define _0x7f800000	%l2

#define K0		%f42
#define K1		%f44
#define K2		%f46
#define K3		%f48
#define K4		%f50
#define K5		%f52
#define K6		%f54
#define K7		%f56
#define K8		%f58
#define K9		%f60

#define tmp_counter	STACK_BIAS-32
#define tmp_py		STACK_BIAS-24
#define tmp_px		STACK_BIAS-16
#define tmp_pz		STACK_BIAS-8

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x20

!--------------------------------------------------------------------
!		!!!!!	vatan2f algorithm	!!!!!
!	uy0 = *(int*)py;
!	ux0 = *(int*)px;
!	ay0 = uy0 & 0x7fffffff;
!	ax0 = ux0 & 0x7fffffff;
!	if ( ax0 >= 0x7f800000 || ay0 >= 0x7f800000 )
!	{
!		/* |X| or |Y| = Nan */
!		if ( ax0 > 0x7f800000 || ay0 > 0x7f800000 )
!		{
!			ftmp0 = *(float*)&ax0 * *(float*)&ay0;
!			*pz = ftmp0;
!		}
!		signx0 = (unsigned)ux0 >> 30;
!		signx0 &= 2;
!		signy0 = uy0 >> 31;
!		if (ay0 == 0x7f800000)
!			signx0 = (ax0 == 0x7f800000) ? signx0 + 1 : 2;
!		else
!			signx0 += signx0;
!		res = signx0 * M_PI_4;
!		signy0 <<= 3;
!		dtmp0 = *(double*)((char*)(cmul_arr + 1) + signy0);
!		res *= dtmp0;
!		ftmp0 = (float) res;
!		*pz = ftmp0;
!		goto next;
!	}
!	if ( ax0 == 0 && ay0 == 0 )
!	{
!		signy0 = uy0 >> 28;
!		signx0 = ux0 >> 27;
!		ldiff0 = ax0 - ay0;
!		ldiff0 >>= 31;
!		signx0 &= -16;
!		signy0 &= -8;
!		ldiff0 <<= 5;
!		signx0 += signy0;
!		res = *(double*)((char*)(cadd_arr + 7) + ldiff0 + signx0 + signy0);
!		ftmp0 = (float) res;
!		*pz = ftmp0;
!		goto next;
!	}
!	ldiff0 = ax0 - ay0;
!	ldiff0 >>= 31;
!	addrc0 = (char*)px - (char*)py;
!	addrc0 &= ldiff0;
!	fy0 = *(float*)((char*)py + addrc0);
!	fx0 = *(float*)((char*)px - addrc0);
!	itmp0 = *(int*)&fy0;
!	if((itmp0 & 0x7fffffff) < 0x00800000)
!	{
!		itmp0 >>= 28;
!		itmp0 &= -8;
!		fy0 = fabsf(fy0);
!		dtmp0 = (double) *(int*)&fy0;
!		dtmp0 *= C2ONM149;
!		dsign = *(double*)((char*)cmul_arr + itmp0);
!		dtmp0 *= dsign;
!		y0 = dtm0;
!	}
!	else
!		y0 = (double)fy0;
!	itmp0 = *(int*)&fx0;
!	if((itmp0 & 0x7fffffff) < 0x00800000)
!	{
!		itmp0 >>= 28;
!		itmp0 &= -8;
!		fx0 = fabsf(fx0);
!		dtmp0 = (double) *(int*)&fx0;
!		dtmp0 *= C2ONM149;
!		dsign = *(double*)((char*)cmul_arr + itmp0);
!		dtmp0 *= dsign;
!		x0 = dtmp0;
!	}
!	else
!		x0 = (double)fx0;
!	px += stridex;
!	py += stridey;
!	x0 = y0 / x0;
!	x20 = x0 * x0;
!	dtmp0 = K9 * x20;
!	dtmp0 += K8;
!	dtmp0 *= x20;
!	dtmp0 += K7;
!	dtmp0 *= x20;
!	dtmp0 += K6;
!	dtmp0 *= x20;
!	dtmp0 += K5;
!	dtmp0 *= x20;
!	dtmp0 += K4;
!	dtmp0 *= x20;
!	dtmp0 += K3;
!	dtmp0 *= x20;
!	dtmp0 += K2;
!	dtmp0 *= x20;
!	dtmp0 += K1;
!	dtmp0 *= x20;
!	dtmp0 += K0;
!	x0 = dtmp0 * x0;
!	signy0 = uy0 >> 28;
!	signy0 &= -8;
!	signx0 = ux0 >> 27;
!	signx0 &= -16;
!	ltmp0 = ldiff0 << 5;
!	ltmp0 += (char*)cadd_arr;
!	ltmp0 += signx0;
!	cadd0 = *(double*)(ltmp0 + signy0);
!	cmul0_ind = ldiff0 << 3;
!	cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
!	dtmp0 = cmul0 * x0;
!	dtmp0 = cadd0 + dtmp0;
!	ftmp0 = (float)dtmp0;
!	*pz = ftmp0;
!	pz += stridez;
!
!--------------------------------------------------------------------

	ENTRY(__vatan2f)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,g5)

#ifdef __sparcv9
	ldx	[%fp+STACK_BIAS+176],%l7
#else
	ld	[%fp+STACK_BIAS+92],%l7
#endif

	st	%i0,[%fp+tmp_counter]
	sethi	%hi(0x7ffffc00),_0x7fffffff
	add	_0x7fffffff,1023,_0x7fffffff
	or	%g0,%i2,%o2
	sll	%l7,2,stridez

	sethi	%hi(0x7f800000),_0x7f800000
	mov	%g5,%g1

	or	%g0,stridey,%o4
	add	%g1,56,cadd_arr

	sll	%o2,2,stridey
	add	%g1,72,cmul_arr

	ldd	[%g1+80],K0
	ldd	[%g1+80+8],K1
	ldd	[%g1+80+16],K2
	ldd	[%g1+80+24],K3
	ldd	[%g1+80+32],K4
	ldd	[%g1+80+40],K5
	ldd	[%g1+80+48],K6
	ldd	[%g1+80+56],K7
	ldd	[%g1+80+64],K8
	ldd	[%g1+80+72],K9

	sll	stridex,2,stridex

	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]
.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_py],%i1
	ldx	[%fp+tmp_px],%i3
	st	%g0,[%fp+tmp_counter]
.begin1:
	subcc	counter,1,counter
	bneg,pn	%icc,.exit
	nop

	lda	[%i1]0x82,%l4		! (0_0) uy0 = *(int*)py;

	lda	[%i3]0x82,%l3		! (0_0) ux0 = *(int*)px;

	and	%l4,_0x7fffffff,%l7	! (0_0) ay0 = uy0 & 0x7fffffff;

	cmp	%l7,_0x7f800000
	bge,pn	%icc,.spec0
	and	%l3,_0x7fffffff,%l6	! (0_0) ax0 = ux0 & 0x7fffffff;

	cmp	%l6,_0x7f800000
	bge,pn	%icc,.spec0
	sethi	%hi(0x00800000),%o5

	cmp	%l6,%o5
	bl,pn	%icc,.spec1
	sub	%l6,%l7,%o2		! (0_0) ldiff0 = ax0 - ay0;

	cmp	%l7,%o5
	bl,pn	%icc,.spec1
	nop

	stx	%o4,[%fp+tmp_pz]
	sra	%o2,31,%l7		! (0_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (0_0) addrc0 = (char*)px - (char*)py;

	and	%l6,%l7,%o2		! (0_0) addrc0 &= ldiff0;

	lda	[%i1+%o2]0x82,%f0	! (0_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (0_0) (char*)px - addrc0

	lda	[%o4]0x82,%f2		! (0_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%l7,5,%l6		! (0_0) ltmp0 = ldiff0 << 5;

	sra	%l3,27,%o5		! (0_0) signx0 = ux0 >> 27;
	add	%i1,stridey,%i1		! py += stridey

	add	%i3,stridex,%i3		! px += stridex

	lda	[%i1]0x82,%l3		! (1_0) uy0 = *(int*)py;
	sra	%l4,28,%o4		! (0_0) signy0 = uy0 >> 28;

	add	%l6,cadd_arr,%l6	! (0_0) ltmp0 += (char*)cadd_arr;

	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	fstod	%f2,%f2			! (0_0) x0 = (double)fx0;

.spec1_cont:
	lda	[%i3]0x82,%l4		! (1_0) ux0 = *(int*)px;
	and	%o5,-16,%o5		! (0_0) signx0 &= -16;

	and	%o4,-8,%o4		! (0_0) signy0 &= -8;

	fdivd	%f40,%f2,%f12		! (0_0) x0 = y0 / x0;

	add	%l6,%o5,%o1		! (0_0) ltmp0 += signx0;

	and	%l4,_0x7fffffff,%l6	! (1_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5

	cmp	%l6,%o5
	bl,pn	%icc,.u0
	and	%l3,_0x7fffffff,%g1	! (1_0) ay0 = uy0 & 0x7fffffff;
.c0:
	cmp	%g1,%o5
	bl,pn	%icc,.u1
	ldd	[%o1+%o4],%f34		! (0_0) cadd0 = *(double*)(ltmp0 + signy0);
.c1:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u2
	sub	%l6,%g1,%o1		! (1_0) ldiff0 = ax0 - ay0;
.c2:
	cmp	%g1,_0x7f800000
	bge,pn	%icc,.u3
	nop
.c3:
	sra	%o1,31,%g1		! (1_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (1_0) addrc0 = (char*)px - (char*)py;

	and	%l6,%g1,%o1		! (1_0) addrc0 &= ldiff0;

	lda	[%i1+%o1]0x82,%f0	! (1_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o1,%o4		! (1_0) (char*)px - addrc0;

	lda	[%o4]0x82,%f2		! (1_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%g1,5,%l6		! (1_0) ltmp0 = ldiff0 << 5;

	cmp	%o5,_0x7f800000		! (1_0) b0 ? 0x7f800000
	bge,pn	%icc,.update0		! (1_0) if ( b0 > 0x7f800000 )
	nop
.cont0:
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (1_0) y0 = (double)fy0;

	sra	%l4,27,%o5		! (1_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex

	sra	%l3,28,%o4		! (1_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (1_0) ltmp0 += (char*)cadd_arr;
	fstod	%f2,%f2			! (1_0) x0 = (double)fx0;
.d0:
	and	%o5,-16,%o5		! (1_0) signx0 &= -16;
	and	%o4,-8,%o4		! (1_0) signy0 &= -8;

	lda	[%i1]0x82,%l4		! (2_0) uy0 = *(int*)py;

	lda	[%i3]0x82,%l3		! (2_0) ux0 = *(int*)px;
	fdivd	%f40,%f2,%f10		! (1_0) x0 = y0 / x0;

	fmuld	%f12,%f12,%f20		! (0_0) x20 = x0 * x0;

	add	%l6,%o5,%o2		! (1_0) ltmp0 += signx0;

	and	%l3,_0x7fffffff,%l6	! (2_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5

	cmp	%l6,%o5
	bl,pn	%icc,.u4
	and	%l4,_0x7fffffff,%g5	! (2_0) ay0 = uy0 & 0x7fffffff;
.c4:
	cmp	%g5,%o5
	bl,pn	%icc,.u5
	fmuld	K9,%f20,%f40		! (0_0) dtmp0 = K9 * x20;
.c5:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u6
	ldd	[%o2+%o4],%f32		! (1_0) cadd0 = *(double*)(ltmp0 + signy0);
.c6:
	cmp	%g5,_0x7f800000
	bge,pn	%icc,.u7
	sub	%l6,%g5,%o2		! (2_0) ldiff0 = ax0 - ay0;
.c7:
	sra	%o2,31,%g5		! (2_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (2_0) addrc0 = (char*)px - (char*)py;

	faddd	%f40,K8,%f40		! (0_0) dtmp0 += K8;
	and	%l6,%g5,%o2		! (2_0) addrc0 &= ldiff0;

	lda	[%i1+%o2]0x82,%f0	! (2_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (2_0) (char*)px - addrc0;

	lda	[%o4]0x82,%f2		! (2_0) fx0 = *(float*)((char*)px - addrc0);

	cmp	%o5,_0x7f800000		! (2_0) b0 ? 0x7f800000
	bge,pn	%icc,.update1		! (2_0) if ( b0 > 0x7f800000 )
	nop
.cont1:
	fmuld	%f40,%f20,%f30		! (0_0) dtmp0 *= x20;
	sll	%g5,5,%l6		! (2_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (2_0) y0 = (double)fy0;

	sra	%l3,27,%o5		! (2_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex

	fstod	%f2,%f2			! (2_0) x0 = (double)fx0;
	sra	%l4,28,%o4		! (2_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (2_0) ltmp0 += (char*)cadd_arr;
.d1:
	lda	[%i1]0x82,%l3		! (3_0) uy0 = *(int*)py;
	and	%o5,-16,%o5		! (2_0) signx0 &= -16;
	faddd	%f30,K7,%f30		! (0_0) dtmp0 += K7;

	lda	[%i3]0x82,%l4		! (3_0) ux0 = *(int*)px;

	fdivd	%f40,%f2,%f8		! (2_0) x0 = y0 / x0;

	fmuld	%f10,%f10,%f18		! (1_0) x20 = x0 * x0;

	add	%l6,%o5,%o1		! (2_0) ltmp0 += signx0;
	and	%o4,-8,%o4		! (2_0) signy0 &= -8;
	fmuld	%f30,%f20,%f30		! (0_0) dtmp0 *= x20;

	and	%l4,_0x7fffffff,%l6	! (3_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5

	cmp	%l6,%o5
	bl,pn	%icc,.u8
	and	%l3,_0x7fffffff,%o0	! (3_0) ay0 = uy0 & 0x7fffffff;
.c8:
	cmp	%o0,%o5
	bl,pn	%icc,.u9
	fmuld	K9,%f18,%f40		! (1_0) dtmp0 = K9 * x20;
.c9:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u10
	faddd	%f30,K6,%f16		! (0_0) dtmp0 += K6;
.c10:
	cmp	%o0,_0x7f800000
	bge,pn	%icc,.u11
	ldd	[%o1+%o4],%f30		! (2_0) cadd0 = *(double*)(ltmp0 + signy0);
.c11:
	sub	%l6,%o0,%o1		! (3_0) ldiff0 = ax0 - ay0;

	sra	%o1,31,%o0		! (3_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (3_0) addrc0 = (char*)px - (char*)py;

	faddd	%f40,K8,%f40		! (1_0) dtmp0 += K8;
	and	%l6,%o0,%o1		! (3_0) addrc0 &= ldiff0;
	fmuld	%f16,%f20,%f16		! (0_0) dtmp0 *= x20;

	lda	[%i1+%o1]0x82,%f0	! (3_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o1,%o4		! (3_0) (char*)px - addrc0;

	lda	[%o4]0x82,%f1		! (3_0) fx0 = *(float*)((char*)px - addrc0);

	cmp	%o5,_0x7f800000		! (3_0) b0 ? 0x7f800000
	bge,pn	%icc,.update2		! (3_0) if ( b0 > 0x7f800000 )
	nop
.cont2:
	fmuld	%f40,%f18,%f28		! (1_0) dtmp0 *= x20;
	sll	%o0,5,%l6		! (3_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (3_0) y0 = (double)fy0;

	faddd	%f16,K5,%f2		! (0_0) dtmp0 += K5;
	sra	%l4,27,%o5		! (3_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex

	sra	%l3,28,%o4		! (3_0) signy0 = uy0 >> 28;
	fstod	%f1,%f16		! (3_0) x0 = (double)fx0;
.d2:
	faddd	%f28,K7,%f28		! (1_0) dtmp0 += K7;
	add	%l6,cadd_arr,%l6	! (3_0) ltmp0 += (char*)cadd_arr;
	and	%o5,-16,%o5		! (3_0) signx0 &= -16;

	lda	[%i1]0x82,%l4		! (4_0) uy0 = *(int*)py;
	fmuld	%f2,%f20,%f2		! (0_0) dtmp0 *= x20;

	lda	[%i3]0x82,%l3		! (4_0) ux0 = *(int*)px;
	fdivd	%f40,%f16,%f6		! (3_0) x0 = y0 / x0;

	and	%o4,-8,%o4		! (3_0) signy0 &= -8;
	fmuld	%f8,%f8,%f16		! (2_0) x20 = x0 * x0;

	add	%l6,%o5,%o2		! (3_0) ltmp0 += signx0;
	fmuld	%f28,%f18,%f28		! (1_0) dtmp0 *= x20;

	and	%l3,_0x7fffffff,%l6	! (4_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f2,K4,%f2		! (0_0) dtmp0 += K4;

	cmp	%l6,%o5
	bl,pn	%icc,.u12
	and	%l4,_0x7fffffff,%l5	! (4_0) ay0 = uy0 & 0x7fffffff;
.c12:
	cmp	%l5,%o5
	bl,pn	%icc,.u13
	fmuld	K9,%f16,%f40		! (2_0) dtmp0 = K9 * x20;
.c13:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u14
	faddd	%f28,K6,%f4		! (1_0) dtmp0 += K6;
.c14:
	ldd	[%o2+%o4],%f28		! (3_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l5,_0x7f800000
	bge,pn	%icc,.u15
	fmuld	%f2,%f20,%f24		! (0_0) dtmp0 *= x20;
.c15:
	sub	%l6,%l5,%o2		! (4_0) ldiff0 = ax0 - ay0;

	sra	%o2,31,%l5		! (4_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (4_0) addrc0 = (char*)px - (char*)py;

	faddd	%f40,K8,%f40		! (2_0) dtmp0 += K8;
	and	%l6,%l5,%o2		! (4_0) addrc0 &= ldiff0;
	fmuld	%f4,%f18,%f4		! (1_0) dtmp0 *= x20;

	lda	[%i1+%o2]0x82,%f0	! (4_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (4_0) (char*)px - addrc0;
	faddd	%f24,K3,%f24		! (0_0) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (4_0) fx0 = *(float*)((char*)px - addrc0);

	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bge,pn	%icc,.update3		! (4_0) if ( b0 > 0x7f800000 )
	nop
.cont3:
	fmuld	%f40,%f16,%f26		! (2_0) dtmp0 *= x20;
	sll	%l5,5,%l6		! (4_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (4_0) y0 = (double)fy0;

	faddd	%f4,K5,%f62		! (1_0) dtmp0 += K5;
	add	%i3,stridex,%i3		! px += stridex
	fmuld	%f24,%f20,%f24		! (0_0) dtmp0 *= x20;

	fstod	%f2,%f2			! (4_0) x0 = (double)fx0;
	sra	%l3,27,%o5		! (4_0) signx0 = ux0 >> 27;
	sra	%l4,28,%o4		! (4_0) signy0 = uy0 >> 28;
.d3:
	lda	[%i1]0x82,%l3		! (5_0) uy0 = *(int*)py;
	add	%l6,cadd_arr,%l6	! (4_0) ltmp0 += (char*)cadd_arr;
	faddd	%f26,K7,%f26		! (2_0) dtmp0 += K7;

	fmuld	%f62,%f18,%f4		! (1_0) dtmp0 *= x20;
	and	%o5,-16,%o5		! (4_0) signx0 &= -16;

	lda	[%i3]0x82,%l4		! (5_1) ux0 = *(int*)px;
	fdivd	%f40,%f2,%f62		! (4_1) x0 = y0 / x0;
	faddd	%f24,K2,%f40		! (0_1) dtmp0 += K2;

	and	%o4,-8,%o4		! (4_1) signy0 &= -8;
	fmuld	%f6,%f6,%f24		! (3_1) x20 = x0 * x0;

	add	%l6,%o5,%o1		! (4_1) ltmp0 += signx0;
	fmuld	%f26,%f16,%f26		! (2_1) dtmp0 *= x20;

	and	%l4,_0x7fffffff,%l6	! (5_1) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f4,K4,%f4		! (1_1) dtmp0 += K4;

	cmp	%l6,%o5
	bl,pn	%icc,.u16
	and	%l3,_0x7fffffff,%o7	! (5_1) ay0 = uy0 & 0x7fffffff;
.c16:
	cmp	%o7,%o5
	bl,pn	%icc,.u17
	fmuld	%f40,%f20,%f38		! (0_1) dtmp0 *= x20;
.c17:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u18
	fmuld	K9,%f24,%f40		! (3_1) dtmp0 = K9 * x20;
.c18:
	cmp	%o7,_0x7f800000
	bge,pn	%icc,.u19
	faddd	%f26,K6,%f22		! (2_1) dtmp0 += K6;
.c19:
	ldd	[%o1+%o4],%f26		! (4_1) cadd0 = *(double*)(ltmp0 + signy0);
	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;

	sub	%l6,%o7,%o1		! (5_1) ldiff0 = ax0 - ay0;

	sra	%o1,31,%o7		! (5_1) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (5_1) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (0_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (3_1) dtmp0 += K8;
	and	%l6,%o7,%o1		! (5_1) addrc0 &= ldiff0;
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	lda	[%i1+%o1]0x82,%f0	! (5_1) fy0 = *(float*)((char*)py + addrc0);
	sll	%o7,5,%l6		! (5_1) ltmp0 = ldiff0 << 5;
	sub	%i3,%o1,%o4		! (5_1) (char*)px - addrc0;
	faddd	%f4,K3,%f4		! (1_1) dtmp0 += K3;

	lda	[%o4]0x82,%f1		! (5_1) fx0 = *(float*)((char*)px - addrc0);

	fmuld	%f38,%f20,%f38		! (0_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (5_1) b0 ? 0x7f800000
	bge,pn	%icc,.update4		! (5_1) if ( b0 > 0x7f800000 )
	nop
.cont4:
	fmuld	%f40,%f24,%f36		! (3_1) dtmp0 *= x20;
	fstod	%f0,%f40		! (5_1) y0 = (double)fy0;

	faddd	%f22,K5,%f14		! (2_1) dtmp0 += K5;
	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;

	add	%i3,stridex,%i3		! px += stridex
	sll	%l7,3,%l7		! (0_1) cmul0_ind = ldiff0 << 3;
	fstod	%f1,%f2			! (5_1) x0 = (double)fx0;
.d4:
	sra	%l3,28,%o4		! (5_1) signy0 = uy0 >> 28;
	add	%i1,stridey,%i1		! py += stridey

	faddd	%f36,K7,%f36		! (3_1) dtmp0 += K7;
	sra	%l4,27,%o5		! (5_1) signx0 = ux0 >> 27;

	lda	[%i1]0x82,%l4		! (0_0) uy0 = *(int*)py;
	add	%l6,cadd_arr,%l6	! (5_1) ltmp0 += (char*)cadd_arr;
	fmuld	%f14,%f16,%f22		! (2_1) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (0_1) dtmp0 += K0;

	lda	[%i3]0x82,%l3		! (0_0) ux0 = *(int*)px;
	and	%o5,-16,%o5		! (5_1) signx0 &= -16;
	fdivd	%f40,%f2,%f14		! (5_1) x0 = y0 / x0;
	faddd	%f4,K2,%f40		! (1_1) dtmp0 += K2;

	fmuld	%f62,%f62,%f4		! (4_1) x20 = x0 * x0;

	ldd	[cmul_arr+%l7],%f0	! (0_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o2		! (5_1) ltmp0 += signx0;
	and	%o4,-8,%o4		! (5_1) signy0 &= -8;
	fmuld	%f36,%f24,%f36		! (3_1) dtmp0 *= x20;

	fmuld	%f38,%f12,%f12		! (0_1) x0 = dtmp0 * x0;
	and	%l4,_0x7fffffff,%l7	! (0_0) ay0 = uy0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f22,K4,%f22		! (2_1) dtmp0 += K4;

	and	%l3,_0x7fffffff,%l6	! (0_0) ax0 = ux0 & 0x7fffffff;
	cmp	%l7,%o5
	bl,pn	%icc,.u20
	fmuld	%f40,%f18,%f38		! (1_1) dtmp0 *= x20;
.c20:
	cmp	%l6,%o5
	bl,pn	%icc,.u21
	fmuld	K9,%f4,%f40		! (4_1) dtmp0 = K9 * x20;
.c21:
	cmp	%l7,_0x7f800000
	bge,pn	%icc,.u22
	faddd	%f36,K6,%f20		! (3_1) dtmp0 += K6;
.c22:
	ldd	[%o2+%o4],%f36		! (5_1) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u23
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;
.c23:
	sub	%l6,%l7,%o2		! (0_0) ldiff0 = ax0 - ay0;

	fmuld	%f0,%f12,%f12		! (0_1) dtmp0 = cmul0 * x0;
	sra	%o2,31,%l7		! (0_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (0_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (1_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (4_1) dtmp0 += K8;
	and	%l6,%l7,%o2		! (0_0) addrc0 &= ldiff0;
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;

	lda	[%i1+%o2]0x82,%f0	! (0_0) fy0 = *(float*)((char*)py + addrc0);
	sll	%g1,3,%g1		! (1_1) cmul0_ind = ldiff0 << 3;
	sub	%i3,%o2,%o4		! (0_0) (char*)px - addrc0
	faddd	%f22,K3,%f22		! (2_1) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (0_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%l7,5,%l6		! (0_0) ltmp0 = ldiff0 << 5;

	fmuld	%f38,%f18,%f38		! (1_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (0_0) b0 ? 0x7f800000
	bge,pn	%icc,.update5		! (0_0) if ( b0 > 0x7f800000 )
	faddd	%f34,%f12,%f18		! (0_1) dtmp0 = cadd0 + dtmp0;
.cont5:
	fmuld	%f40,%f4,%f34		! (4_1) dtmp0 *= x20;
	sra	%l3,27,%o5		! (0_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	faddd	%f20,K5,%f12		! (3_1) dtmp0 += K5;
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	lda	[%i1]0x82,%l3		! (1_0) uy0 = *(int*)py;
	sra	%l4,28,%o4		! (0_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (0_0) ltmp0 += (char*)cadd_arr;
	fstod	%f2,%f2			! (0_0) x0 = (double)fx0;
.d5:
	lda	[%i3]0x82,%l4		! (1_0) ux0 = *(int*)px;
	and	%o5,-16,%o5		! (0_0) signx0 &= -16;
	faddd	%f34,K7,%f34		! (4_1) dtmp0 += K7;

	ldx	[%fp+tmp_pz],%o1
	fmuld	%f12,%f24,%f20		! (3_1) dtmp0 *= x20;
	and	%o4,-8,%o4		! (0_0) signy0 &= -8;
	faddd	%f38,K0,%f38		! (1_1) dtmp0 += K0;

	fdivd	%f40,%f2,%f12		! (0_0) x0 = y0 / x0;
	faddd	%f22,K2,%f40		! (2_1) dtmp0 += K2;

	fdtos	%f18,%f2		! (0_1) ftmp0 = (float)dtmp0;
	st	%f2,[%o1]		! (0_1) *pz = ftmp0
	add	%o1,stridez,%o2
	fmuld	%f14,%f14,%f22		! (5_1) x20 = x0 * x0;

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o2,%o4

	ldd	[cmul_arr+%g1],%f0	! (1_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o1		! (0_0) ltmp0 += signx0;
	fmuld	%f34,%f4,%f34		! (4_1) dtmp0 *= x20;

	fmuld	%f38,%f10,%f10		! (1_1) x0 = dtmp0 * x0;
	and	%l4,_0x7fffffff,%l6	! (1_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f20,K4,%f20		! (3_1) dtmp0 += K4;

	and	%l3,_0x7fffffff,%g1	! (1_0) ay0 = uy0 & 0x7fffffff;
	cmp	%l6,%o5
	bl,pn	%icc,.u24
	fmuld	%f40,%f16,%f38		! (2_1) dtmp0 *= x20;
.c24:
	cmp	%g1,%o5
	bl,pn	%icc,.u25
	fmuld	K9,%f22,%f40		! (5_1) dtmp0 = K9 * x20;
.c25:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u26
	faddd	%f34,K6,%f18		! (4_1) dtmp0 += K6;
.c26:
	ldd	[%o1+%o4],%f34		! (0_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%g1,_0x7f800000
	bge,pn	%icc,.u27
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;
.c27:
	sub	%l6,%g1,%o1		! (1_0) ldiff0 = ax0 - ay0;

	fmuld	%f0,%f10,%f10		! (1_1) dtmp0 = cmul0 * x0;
	sra	%o1,31,%g1		! (1_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (1_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (2_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (5_1) dtmp0 += K8;
	and	%l6,%g1,%o1		! (1_0) addrc0 &= ldiff0;
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;

	lda	[%i1+%o1]0x82,%f0	! (1_0) fy0 = *(float*)((char*)py + addrc0);
	sll	%g5,3,%g5		! (2_1) cmul0_ind = ldiff0 << 3;
	sub	%i3,%o1,%o4		! (1_0) (char*)px - addrc0;
	faddd	%f20,K3,%f20		! (3_1) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (1_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%g1,5,%l6		! (1_0) ltmp0 = ldiff0 << 5;
	add	%o2,stridez,%o1		! pz += stridez

	fmuld	%f38,%f16,%f38		! (2_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (1_0) b0 ? 0x7f800000
	bge,pn	%icc,.update6		! (1_0) if ( b0 > 0x7f800000 )
	faddd	%f32,%f10,%f16		! (1_1) dtmp0 = cadd0 + dtmp0;
.cont6:
	fmuld	%f40,%f22,%f32		! (5_1) dtmp0 *= x20;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (1_0) y0 = (double)fy0;

	faddd	%f18,K5,%f10		! (4_1) dtmp0 += K5;
	sra	%l4,27,%o5		! (1_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;

	sra	%l3,28,%o4		! (1_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (1_0) ltmp0 += (char*)cadd_arr;
	fstod	%f2,%f2			! (1_0) x0 = (double)fx0;
.d6:
	faddd	%f32,K7,%f32		! (5_1) dtmp0 += K7;
	and	%o5,-16,%o5		! (1_0) signx0 &= -16;
	and	%o4,-8,%o4		! (1_0) signy0 &= -8;

	lda	[%i1]0x82,%l4		! (2_0) uy0 = *(int*)py;
	fmuld	%f10,%f4,%f18		! (4_1) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (2_1) dtmp0 += K0;

	lda	[%i3]0x82,%l3		! (2_0) ux0 = *(int*)px;
	fdivd	%f40,%f2,%f10		! (1_0) x0 = y0 / x0;
	faddd	%f20,K2,%f40		! (3_1) dtmp0 += K2;

	fmuld	%f12,%f12,%f20		! (0_0) x20 = x0 * x0;
	fdtos	%f16,%f2		! (1_1) ftmp0 = (float)dtmp0;
	st	%f2,[%o2]		! (1_1) *pz = ftmp0;

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o1,%o4

	ldd	[cmul_arr+%g5],%f0	! (2_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o2		! (1_0) ltmp0 += signx0;
	fmuld	%f32,%f22,%f32		! (5_1) dtmp0 *= x20;

	fmuld	%f38,%f8,%f8		! (2_1) x0 = dtmp0 * x0;
	and	%l3,_0x7fffffff,%l6	! (2_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f18,K4,%f18		! (4_1) dtmp0 += K4;

	and	%l4,_0x7fffffff,%g5	! (2_0) ay0 = uy0 & 0x7fffffff;
	cmp	%l6,%o5
	bl,pn	%icc,.u28
	fmuld	%f40,%f24,%f38		! (3_1) dtmp0 *= x20;
.c28:
	cmp	%g5,%o5
	bl,pn	%icc,.u29
	fmuld	K9,%f20,%f40		! (0_0) dtmp0 = K9 * x20;
.c29:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u30
	faddd	%f32,K6,%f16		! (5_1) dtmp0 += K6;
.c30:
	ldd	[%o2+%o4],%f32		! (1_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%g5,_0x7f800000
	bge,pn	%icc,.u31
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;
.c31:
	sub	%l6,%g5,%o2		! (2_0) ldiff0 = ax0 - ay0;

	fmuld	%f0,%f8,%f8		! (2_1) dtmp0 = cmul0 * x0;
	sra	%o2,31,%g5		! (2_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (2_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (3_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (0_0) dtmp0 += K8;
	and	%l6,%g5,%o2		! (2_0) addrc0 &= ldiff0;
	fmuld	%f16,%f22,%f16		! (5_1) dtmp0 *= x20;

	lda	[%i1+%o2]0x82,%f0	! (2_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (2_0) (char*)px - addrc0;
	add	%o1,stridez,%o2		! pz += stridez
	faddd	%f18,K3,%f18		! (4_1) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (2_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%o0,3,%o0		! (3_1) cmul0_ind = ldiff0 << 3;

	fmuld	%f38,%f24,%f38		! (3_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (2_0) b0 ? 0x7f800000
	bge,pn	%icc,.update7		! (2_0) if ( b0 > 0x7f800000 )
	faddd	%f30,%f8,%f24		! (2_1) dtmp0 = cadd0 + dtmp0;
.cont7:
	fmuld	%f40,%f20,%f30		! (0_0) dtmp0 *= x20;
	sll	%g5,5,%l6		! (2_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (2_0) y0 = (double)fy0;

	faddd	%f16,K5,%f8		! (5_1) dtmp0 += K5;
	sra	%l3,27,%o5		! (2_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;

	fstod	%f2,%f2			! (2_0) x0 = (double)fx0;
	sra	%l4,28,%o4		! (2_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (2_0) ltmp0 += (char*)cadd_arr;
.d7:
	lda	[%i1]0x82,%l3		! (3_0) uy0 = *(int*)py;
	and	%o5,-16,%o5		! (2_0) signx0 &= -16;
	faddd	%f30,K7,%f30		! (0_0) dtmp0 += K7;

	lda	[%i3]0x82,%l4		! (3_0) ux0 = *(int*)px;
	fmuld	%f8,%f22,%f16		! (5_1) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (3_1) dtmp0 += K0;

	fdivd	%f40,%f2,%f8		! (2_0) x0 = y0 / x0;
	faddd	%f18,K2,%f40		! (4_1) dtmp0 += K2;

	fmuld	%f10,%f10,%f18		! (1_0) x20 = x0 * x0;
	fdtos	%f24,%f1		! (2_1) ftmp0 = (float)dtmp0;
	st	%f1,[%o1]		! (2_1) *pz = ftmp0;

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o2,%o4

	ldd	[cmul_arr+%o0],%f2	! (3_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o1		! (2_0) ltmp0 += signx0;
	and	%o4,-8,%o4		! (2_0) signy0 &= -8;
	fmuld	%f30,%f20,%f30		! (0_0) dtmp0 *= x20;

	fmuld	%f38,%f6,%f6		! (3_1) x0 = dtmp0 * x0;
	and	%l4,_0x7fffffff,%l6	! (3_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f16,K4,%f24		! (5_1) dtmp0 += K4;

	and	%l3,_0x7fffffff,%o0	! (3_0) ay0 = uy0 & 0x7fffffff;
	cmp	%l6,%o5
	bl,pn	%icc,.u32
	fmuld	%f40,%f4,%f38		! (4_1) dtmp0 *= x20;
.c32:
	cmp	%o0,%o5
	bl,pn	%icc,.u33
	fmuld	K9,%f18,%f40		! (1_0) dtmp0 = K9 * x20;
.c33:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u34
	faddd	%f30,K6,%f16		! (0_0) dtmp0 += K6;
.c34:
	ldd	[%o1+%o4],%f30		! (2_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%o0,_0x7f800000
	bge,pn	%icc,.u35
	fmuld	%f24,%f22,%f24		! (5_1) dtmp0 *= x20;
.c35:
	sub	%l6,%o0,%o1		! (3_0) ldiff0 = ax0 - ay0;

	fmuld	%f2,%f6,%f6		! (3_1) dtmp0 = cmul0 * x0;
	sra	%o1,31,%o0		! (3_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (3_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (4_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (1_0) dtmp0 += K8;
	and	%l6,%o0,%o1		! (3_0) addrc0 &= ldiff0;
	fmuld	%f16,%f20,%f16		! (0_0) dtmp0 *= x20;

	lda	[%i1+%o1]0x82,%f0	! (3_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o1,%o4		! (3_0) (char*)px - addrc0;
	add	%o2,stridez,%o1		! pz += stridez
	faddd	%f24,K3,%f24		! (5_1) dtmp0 += K3;

	lda	[%o4]0x82,%f1		! (3_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%l5,3,%l5		! (4_1) cmul0_ind = ldiff0 << 3;

	fmuld	%f38,%f4,%f38		! (4_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (3_0) b0 ? 0x7f800000
	bge,pn	%icc,.update8		! (3_0) if ( b0 > 0x7f800000 )
	faddd	%f28,%f6,%f4		! (3_1) dtmp0 = cadd0 + dtmp0;
.cont8:
	fmuld	%f40,%f18,%f28		! (1_0) dtmp0 *= x20;
	sll	%o0,5,%l6		! (3_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (3_0) y0 = (double)fy0;

	faddd	%f16,K5,%f2		! (0_0) dtmp0 += K5;
	sra	%l4,27,%o5		! (3_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex
	fmuld	%f24,%f22,%f24		! (5_1) dtmp0 *= x20;

	sra	%l3,28,%o4		! (3_0) signy0 = uy0 >> 28;
	fstod	%f1,%f16		! (3_0) x0 = (double)fx0;
.d8:
	faddd	%f28,K7,%f28		! (1_0) dtmp0 += K7;
	add	%l6,cadd_arr,%l6	! (3_0) ltmp0 += (char*)cadd_arr;
	and	%o5,-16,%o5		! (3_0) signx0 &= -16;

	lda	[%i1]0x82,%l4		! (4_0) uy0 = *(int*)py;
	fmuld	%f2,%f20,%f2		! (0_0) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (4_1) dtmp0 += K0;

	lda	[%i3]0x82,%l3		! (4_0) ux0 = *(int*)px;
	fdivd	%f40,%f16,%f6		! (3_0) x0 = y0 / x0;
	faddd	%f24,K2,%f24		! (5_1) dtmp0 += K2;

	fdtos	%f4,%f1			! (3_1) ftmp0 = (float)dtmp0;
	and	%o4,-8,%o4		! (3_0) signy0 &= -8;
	st	%f1,[%o2]		! (3_1) *pz = ftmp0;
	fmuld	%f8,%f8,%f16		! (2_0) x20 = x0 * x0;

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o1,%o4

	ldd	[cmul_arr+%l5],%f0	! (4_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o2		! (3_0) ltmp0 += signx0;
	fmuld	%f28,%f18,%f28		! (1_0) dtmp0 *= x20;

	fmuld	%f38,%f62,%f62		! (4_1) x0 = dtmp0 * x0;
	and	%l3,_0x7fffffff,%l6	! (4_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f2,K4,%f2		! (0_0) dtmp0 += K4;

	and	%l4,_0x7fffffff,%l5	! (4_0) ay0 = uy0 & 0x7fffffff;
	cmp	%l6,%o5
	bl,pn	%icc,.u36
	fmuld	%f24,%f22,%f38		! (5_1) dtmp0 *= x20;
.c36:
	cmp	%l5,%o5
	bl,pn	%icc,.u37
	fmuld	K9,%f16,%f40		! (2_0) dtmp0 = K9 * x20;
.c37:
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.u38
	faddd	%f28,K6,%f4		! (1_0) dtmp0 += K6;
.c38:
	ldd	[%o2+%o4],%f28		! (3_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l5,_0x7f800000
	bge,pn	%icc,.u39
	fmuld	%f2,%f20,%f24		! (0_0) dtmp0 *= x20;
.c39:
	sub	%l6,%l5,%o2		! (4_0) ldiff0 = ax0 - ay0;

	fmuld	%f0,%f62,%f62		! (4_1) dtmp0 = cmul0 * x0;
	sra	%o2,31,%l5		! (4_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (4_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (5_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (2_0) dtmp0 += K8;
	and	%l6,%l5,%o2		! (4_0) addrc0 &= ldiff0;
	fmuld	%f4,%f18,%f4		! (1_0) dtmp0 *= x20;

	lda	[%i1+%o2]0x82,%f0	! (4_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (4_0) (char*)px - addrc0;
	add	%o1,stridez,%o2		! pz += stridez
	faddd	%f24,K3,%f24		! (0_0) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (4_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%o7,3,%o7		! (5_1) cmul0_ind = ldiff0 << 3;

	fmuld	%f38,%f22,%f38		! (5_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bge,pn	%icc,.update9		! (4_0) if ( b0 > 0x7f800000 )
	faddd	%f26,%f62,%f22		! (4_1) dtmp0 = cadd0 + dtmp0;
.cont9:
	fmuld	%f40,%f16,%f26		! (2_0) dtmp0 *= x20;
	sll	%l5,5,%l6		! (4_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (4_0) y0 = (double)fy0;

	faddd	%f4,K5,%f62		! (1_0) dtmp0 += K5;
	sra	%l3,27,%o5		! (4_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex
	fmuld	%f24,%f20,%f24		! (0_0) dtmp0 *= x20;

	fstod	%f2,%f2			! (4_0) x0 = (double)fx0;
	sra	%l4,28,%o4		! (4_0) signy0 = uy0 >> 28;
.d9:
	lda	[%i1]0x82,%l3		! (5_0) uy0 = *(int*)py;
	add	%l6,cadd_arr,%l6	! (4_0) ltmp0 += (char*)cadd_arr;
	faddd	%f26,K7,%f26		! (2_0) dtmp0 += K7;

	fmuld	%f62,%f18,%f4		! (1_0) dtmp0 *= x20;
	and	%o5,-16,%o5		! (4_0) signx0 &= -16;
	faddd	%f38,K0,%f38		! (5_1) dtmp0 += K0;

	subcc	counter,5,counter
	bneg,pn	%icc,.tail
	nop

	ba	.main_loop
	nop

	.align	16
.main_loop:
	lda	[%i3]0x82,%l4		! (5_1) ux0 = *(int*)px;
	nop
	fdivd	%f40,%f2,%f62		! (4_1) x0 = y0 / x0;
	faddd	%f24,K2,%f40		! (0_1) dtmp0 += K2;

	fdtos	%f22,%f22		! (4_2) ftmp0 = (float)dtmp0;
	and	%o4,-8,%o4		! (4_1) signy0 &= -8;
	st	%f22,[%o1]		! (4_2) *pz = ftmp0;
	fmuld	%f6,%f6,%f24		! (3_1) x20 = x0 * x0;

	ldd	[cmul_arr+%o7],%f0	! (5_2) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o1		! (4_1) ltmp0 += signx0;
	fmuld	%f26,%f16,%f26		! (2_1) dtmp0 *= x20;

	fmuld	%f38,%f14,%f14		! (5_2) x0 = dtmp0 * x0;
	and	%l4,_0x7fffffff,%l6	! (5_1) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f4,K4,%f4		! (1_1) dtmp0 += K4;

	and	%l3,_0x7fffffff,%o7	! (5_1) ay0 = uy0 & 0x7fffffff;
	fmuld	%f40,%f20,%f38		! (0_1) dtmp0 *= x20;

	cmp	%l6,%o5
	bl,pn	%icc,.up0
	fmuld	K9,%f24,%f40		! (3_1) dtmp0 = K9 * x20;
.co0:
	nop
	cmp	%o7,%o5
	bl,pn	%icc,.up1
	faddd	%f26,K6,%f22		! (2_1) dtmp0 += K6;
.co1:
	ldd	[%o1+%o4],%f26		! (4_1) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.up2
	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;
.co2:
	sub	%l6,%o7,%o1		! (5_1) ldiff0 = ax0 - ay0;
	cmp	%o7,_0x7f800000
	bge,pn	%icc,.up3

	fmuld	%f0,%f14,%f14		! (5_2) dtmp0 = cmul0 * x0;
.co3:
	sra	%o1,31,%o7		! (5_1) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (5_1) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (0_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (3_1) dtmp0 += K8;
	and	%l6,%o7,%o1		! (5_1) addrc0 &= ldiff0;
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	lda	[%i1+%o1]0x82,%f0	! (5_1) fy0 = *(float*)((char*)py + addrc0);
	sll	%o7,5,%l6		! (5_1) ltmp0 = ldiff0 << 5;
	sub	%i3,%o1,%o4		! (5_1) (char*)px - addrc0;
	faddd	%f4,K3,%f4		! (1_1) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (5_1) fx0 = *(float*)((char*)px - addrc0);

	fmuld	%f38,%f20,%f38		! (0_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (5_1) b0 ? 0x7f800000
	bge,pn	%icc,.update10		! (5_1) if ( b0 > 0x7f800000 )
	faddd	%f36,%f14,%f20		! (5_2) dtmp0 = cadd0 + dtmp0;
.cont10:
	fmuld	%f40,%f24,%f36		! (3_1) dtmp0 *= x20;
	nop
	fstod	%f0,%f40		! (5_1) y0 = (double)fy0;

	faddd	%f22,K5,%f14		! (2_1) dtmp0 += K5;
	add	%o2,stridez,%o1		! pz += stridez
	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;

	sll	%l7,3,%l7		! (0_1) cmul0_ind = ldiff0 << 3;
	add	%i3,stridex,%i3		! px += stridex
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;
.den0:
	sra	%l3,28,%o4		! (5_1) signy0 = uy0 >> 28;
	add	%i1,stridey,%i1		! py += stridey

	faddd	%f36,K7,%f36		! (3_1) dtmp0 += K7;
	sra	%l4,27,%o5		! (5_1) signx0 = ux0 >> 27;

	lda	[%i1]0x82,%l4		! (0_0) uy0 = *(int*)py;
	add	%l6,cadd_arr,%l6	! (5_1) ltmp0 += (char*)cadd_arr;
	fmuld	%f14,%f16,%f22		! (2_1) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (0_1) dtmp0 += K0;

	lda	[%i3]0x82,%l3		! (0_0) ux0 = *(int*)px;
	and	%o5,-16,%o5		! (5_1) signx0 &= -16;
	fdivd	%f40,%f2,%f14		! (5_1) x0 = y0 / x0;
	faddd	%f4,K2,%f40		! (1_1) dtmp0 += K2;

	fdtos	%f20,%f2		! (5_2) ftmp0 = (float)dtmp0;
	st	%f2,[%o2]		! (5_2) *pz = ftmp0;
	fmuld	%f62,%f62,%f4		! (4_1) x20 = x0 * x0;

	ldd	[cmul_arr+%l7],%f0	! (0_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o2		! (5_1) ltmp0 += signx0;
	and	%o4,-8,%o4		! (5_1) signy0 &= -8;
	fmuld	%f36,%f24,%f36		! (3_1) dtmp0 *= x20;

	fmuld	%f38,%f12,%f12		! (0_1) x0 = dtmp0 * x0;
	and	%l4,_0x7fffffff,%l7	! (0_0) ay0 = uy0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f22,K4,%f22		! (2_1) dtmp0 += K4;

	and	%l3,_0x7fffffff,%l6	! (0_0) ax0 = ux0 & 0x7fffffff;
	fmuld	%f40,%f18,%f38		! (1_1) dtmp0 *= x20;

	cmp	%l7,%o5
	bl,pn	%icc,.up4
	fmuld	K9,%f4,%f40		! (4_1) dtmp0 = K9 * x20;
.co4:
	nop
	cmp	%l6,%o5
	bl,pn	%icc,.up5
	faddd	%f36,K6,%f20		! (3_1) dtmp0 += K6;
.co5:
	ldd	[%o2+%o4],%f36		! (5_1) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l7,_0x7f800000
	bge,pn	%icc,.up6
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;
.co6:
	sub	%l6,%l7,%o2		! (0_0) ldiff0 = ax0 - ay0;
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.up7

	fmuld	%f0,%f12,%f12		! (0_1) dtmp0 = cmul0 * x0;
.co7:
	sra	%o2,31,%l7		! (0_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (0_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (1_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (4_1) dtmp0 += K8;
	and	%l6,%l7,%o2		! (0_0) addrc0 &= ldiff0;
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;

	lda	[%i1+%o2]0x82,%f0	! (0_0) fy0 = *(float*)((char*)py + addrc0);
	sll	%g1,3,%g1		! (1_1) cmul0_ind = ldiff0 << 3;
	sub	%i3,%o2,%o4		! (0_0) (char*)px - addrc0
	faddd	%f22,K3,%f22		! (2_1) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (0_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%l7,5,%l6		! (0_0) ltmp0 = ldiff0 << 5;
	add	%o1,stridez,%o2		! pz += stridez

	fmuld	%f38,%f18,%f38		! (1_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (0_0) b0 ? 0x7f800000
	bge,pn	%icc,.update11		! (0_0) if ( b0 > 0x7f800000 )
	faddd	%f34,%f12,%f18		! (0_1) dtmp0 = cadd0 + dtmp0;
.cont11:
	fmuld	%f40,%f4,%f34		! (4_1) dtmp0 *= x20;
	sra	%l3,27,%o5		! (0_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	faddd	%f20,K5,%f12		! (3_1) dtmp0 += K5;
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	lda	[%i1]0x82,%l3		! (1_0) uy0 = *(int*)py;
	sra	%l4,28,%o4		! (0_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (0_0) ltmp0 += (char*)cadd_arr;
	fstod	%f2,%f2			! (0_0) x0 = (double)fx0;
.den1:
	lda	[%i3]0x82,%l4		! (1_0) ux0 = *(int*)px;
	and	%o5,-16,%o5		! (0_0) signx0 &= -16;
	faddd	%f34,K7,%f34		! (4_1) dtmp0 += K7;

	fmuld	%f12,%f24,%f20		! (3_1) dtmp0 *= x20;
	and	%o4,-8,%o4		! (0_0) signy0 &= -8;
	faddd	%f38,K0,%f38		! (1_1) dtmp0 += K0;

	fdivd	%f40,%f2,%f12		! (0_0) x0 = y0 / x0;
	faddd	%f22,K2,%f40		! (2_1) dtmp0 += K2;

	fdtos	%f18,%f2		! (0_1) ftmp0 = (float)dtmp0;
	nop
	st	%f2,[%o1]		! (0_1) *pz = ftmp0
	fmuld	%f14,%f14,%f22		! (5_1) x20 = x0 * x0;

	ldd	[cmul_arr+%g1],%f0	! (1_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o1		! (0_0) ltmp0 += signx0;
	fmuld	%f34,%f4,%f34		! (4_1) dtmp0 *= x20;

	fmuld	%f38,%f10,%f10		! (1_1) x0 = dtmp0 * x0;
	and	%l4,_0x7fffffff,%l6	! (1_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f20,K4,%f20		! (3_1) dtmp0 += K4;

	and	%l3,_0x7fffffff,%g1	! (1_0) ay0 = uy0 & 0x7fffffff;
	fmuld	%f40,%f16,%f38		! (2_1) dtmp0 *= x20;

	cmp	%l6,%o5
	bl,pn	%icc,.up8
	fmuld	K9,%f22,%f40		! (5_1) dtmp0 = K9 * x20;
.co8:
	nop
	cmp	%g1,%o5
	bl,pn	%icc,.up9
	faddd	%f34,K6,%f18		! (4_1) dtmp0 += K6;
.co9:
	ldd	[%o1+%o4],%f34		! (0_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.up10
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;
.co10:
	sub	%l6,%g1,%o1		! (1_0) ldiff0 = ax0 - ay0;
	cmp	%g1,_0x7f800000
	bge,pn	%icc,.up11

	fmuld	%f0,%f10,%f10		! (1_1) dtmp0 = cmul0 * x0;
.co11:
	sra	%o1,31,%g1		! (1_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (1_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (2_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (5_1) dtmp0 += K8;
	and	%l6,%g1,%o1		! (1_0) addrc0 &= ldiff0;
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;

	lda	[%i1+%o1]0x82,%f0	! (1_0) fy0 = *(float*)((char*)py + addrc0);
	sll	%g5,3,%g5		! (2_1) cmul0_ind = ldiff0 << 3;
	sub	%i3,%o1,%o4		! (1_0) (char*)px - addrc0;
	faddd	%f20,K3,%f20		! (3_1) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (1_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%g1,5,%l6		! (1_0) ltmp0 = ldiff0 << 5;
	add	%o2,stridez,%o1		! pz += stridez

	fmuld	%f38,%f16,%f38		! (2_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (1_0) b0 ? 0x7f800000
	bge,pn	%icc,.update12		! (1_0) if ( b0 > 0x7f800000 )
	faddd	%f32,%f10,%f16		! (1_1) dtmp0 = cadd0 + dtmp0;
.cont12:
	fmuld	%f40,%f22,%f32		! (5_1) dtmp0 *= x20;
	add	%i1,stridey,%i1		! py += stridey
	nop
	fstod	%f0,%f40		! (1_0) y0 = (double)fy0;

	faddd	%f18,K5,%f10		! (4_1) dtmp0 += K5;
	sra	%l4,27,%o5		! (1_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;

	sra	%l3,28,%o4		! (1_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (1_0) ltmp0 += (char*)cadd_arr;
	fstod	%f2,%f2			! (1_0) x0 = (double)fx0;
.den2:
	faddd	%f32,K7,%f32		! (5_1) dtmp0 += K7;
	and	%o5,-16,%o5		! (1_0) signx0 &= -16;
	and	%o4,-8,%o4		! (1_0) signy0 &= -8;

	lda	[%i1]0x82,%l4		! (2_0) uy0 = *(int*)py;
	fmuld	%f10,%f4,%f18		! (4_1) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (2_1) dtmp0 += K0;

	lda	[%i3]0x82,%l3		! (2_0) ux0 = *(int*)px;
	fdivd	%f40,%f2,%f10		! (1_0) x0 = y0 / x0;
	faddd	%f20,K2,%f40		! (3_1) dtmp0 += K2;

	fdtos	%f16,%f2		! (1_1) ftmp0 = (float)dtmp0;
	nop
	st	%f2,[%o2]		! (1_1) *pz = ftmp0;
	fmuld	%f12,%f12,%f20		! (0_0) x20 = x0 * x0;

	ldd	[cmul_arr+%g5],%f0	! (2_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o2		! (1_0) ltmp0 += signx0;
	fmuld	%f32,%f22,%f32		! (5_1) dtmp0 *= x20;

	fmuld	%f38,%f8,%f8		! (2_1) x0 = dtmp0 * x0;
	and	%l3,_0x7fffffff,%l6	! (2_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f18,K4,%f18		! (4_1) dtmp0 += K4;

	and	%l4,_0x7fffffff,%g5	! (2_0) ay0 = uy0 & 0x7fffffff;
	fmuld	%f40,%f24,%f38		! (3_1) dtmp0 *= x20;

	cmp	%l6,%o5
	bl,pn	%icc,.up12
	fmuld	K9,%f20,%f40		! (0_0) dtmp0 = K9 * x20;
.co12:
	nop
	cmp	%g5,%o5
	bl,pn	%icc,.up13
	faddd	%f32,K6,%f16		! (5_1) dtmp0 += K6;
.co13:
	ldd	[%o2+%o4],%f32		! (1_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.up14
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;
.co14:
	sub	%l6,%g5,%o2		! (2_0) ldiff0 = ax0 - ay0;
	cmp	%g5,_0x7f800000
	bge,pn	%icc,.up15

	fmuld	%f0,%f8,%f8		! (2_1) dtmp0 = cmul0 * x0;
.co15:
	sra	%o2,31,%g5		! (2_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (2_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (3_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (0_0) dtmp0 += K8;
	and	%l6,%g5,%o2		! (2_0) addrc0 &= ldiff0;
	fmuld	%f16,%f22,%f16		! (5_1) dtmp0 *= x20;

	lda	[%i1+%o2]0x82,%f0	! (2_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (2_0) (char*)px - addrc0;
	add	%o1,stridez,%o2		! pz += stridez
	faddd	%f18,K3,%f18		! (4_1) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (2_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%o0,3,%o0		! (3_1) cmul0_ind = ldiff0 << 3;
	add	%i3,stridex,%i3		! px += stridex

	fmuld	%f38,%f24,%f38		! (3_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (2_0) b0 ? 0x7f800000
	bge,pn	%icc,.update13		! (2_0) if ( b0 > 0x7f800000 )
	faddd	%f30,%f8,%f24		! (2_1) dtmp0 = cadd0 + dtmp0;
.cont13:
	fmuld	%f40,%f20,%f30		! (0_0) dtmp0 *= x20;
	sll	%g5,5,%l6		! (2_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (2_0) y0 = (double)fy0;

	faddd	%f16,K5,%f8		! (5_1) dtmp0 += K5;
	sra	%l3,27,%o5		! (2_0) signx0 = ux0 >> 27;
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;

	fstod	%f2,%f2			! (2_0) x0 = (double)fx0;
	sra	%l4,28,%o4		! (2_0) signy0 = uy0 >> 28;
	add	%l6,cadd_arr,%l6	! (2_0) ltmp0 += (char*)cadd_arr;
.den3:
	lda	[%i1]0x82,%l3		! (3_0) uy0 = *(int*)py;
	and	%o5,-16,%o5		! (2_0) signx0 &= -16;
	faddd	%f30,K7,%f30		! (0_0) dtmp0 += K7;

	lda	[%i3]0x82,%l4		! (3_0) ux0 = *(int*)px;
	fmuld	%f8,%f22,%f16		! (5_1) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (3_1) dtmp0 += K0;

	fdivd	%f40,%f2,%f8		! (2_0) x0 = y0 / x0;
	faddd	%f18,K2,%f40		! (4_1) dtmp0 += K2;

	fdtos	%f24,%f1		! (2_1) ftmp0 = (float)dtmp0;
	st	%f1,[%o1]		! (2_1) *pz = ftmp0;
	fmuld	%f10,%f10,%f18		! (1_0) x20 = x0 * x0;

	ldd	[cmul_arr+%o0],%f2	! (3_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o1		! (2_0) ltmp0 += signx0;
	and	%o4,-8,%o4		! (2_0) signy0 &= -8;
	fmuld	%f30,%f20,%f30		! (0_0) dtmp0 *= x20;

	fmuld	%f38,%f6,%f6		! (3_1) x0 = dtmp0 * x0;
	and	%l4,_0x7fffffff,%l6	! (3_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f16,K4,%f24		! (5_1) dtmp0 += K4;

	and	%l3,_0x7fffffff,%o0	! (3_0) ay0 = uy0 & 0x7fffffff;
	fmuld	%f40,%f4,%f38		! (4_1) dtmp0 *= x20;

	cmp	%l6,%o5
	bl,pn	%icc,.up16
	fmuld	K9,%f18,%f40		! (1_0) dtmp0 = K9 * x20;
.co16:
	nop
	cmp	%o0,%o5
	bl,pn	%icc,.up17
	faddd	%f30,K6,%f16		! (0_0) dtmp0 += K6;
.co17:
	ldd	[%o1+%o4],%f30		! (2_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.up18
	fmuld	%f24,%f22,%f24		! (5_1) dtmp0 *= x20;
.co18:
	sub	%l6,%o0,%o1		! (3_0) ldiff0 = ax0 - ay0;
	cmp	%o0,_0x7f800000
	bge,pn	%icc,.up19

	fmuld	%f2,%f6,%f6		! (3_1) dtmp0 = cmul0 * x0;
.co19:
	sra	%o1,31,%o0		! (3_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (3_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (4_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (1_0) dtmp0 += K8;
	and	%l6,%o0,%o1		! (3_0) addrc0 &= ldiff0;
	fmuld	%f16,%f20,%f16		! (0_0) dtmp0 *= x20;

	lda	[%i1+%o1]0x82,%f0	! (3_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o1,%o4		! (3_0) (char*)px - addrc0;
	add	%o2,stridez,%o1		! pz += stridez
	faddd	%f24,K3,%f24		! (5_1) dtmp0 += K3;

	lda	[%o4]0x82,%f1		! (3_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%l5,3,%l5		! (4_1) cmul0_ind = ldiff0 << 3;
	add	%i3,stridex,%i3		! px += stridex

	fmuld	%f38,%f4,%f38		! (4_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (3_0) b0 ? 0x7f800000
	bge,pn	%icc,.update14		! (3_0) if ( b0 > 0x7f800000 )
	faddd	%f28,%f6,%f4		! (3_1) dtmp0 = cadd0 + dtmp0;
.cont14:
	fmuld	%f40,%f18,%f28		! (1_0) dtmp0 *= x20;
	sll	%o0,5,%l6		! (3_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (3_0) y0 = (double)fy0;

	faddd	%f16,K5,%f2		! (0_0) dtmp0 += K5;
	sra	%l4,27,%o5		! (3_0) signx0 = ux0 >> 27;
	fmuld	%f24,%f22,%f24		! (5_1) dtmp0 *= x20;

	sra	%l3,28,%o4		! (3_0) signy0 = uy0 >> 28;
	fstod	%f1,%f16		! (3_0) x0 = (double)fx0;
.den4:
	faddd	%f28,K7,%f28		! (1_0) dtmp0 += K7;
	add	%l6,cadd_arr,%l6	! (3_0) ltmp0 += (char*)cadd_arr;
	and	%o5,-16,%o5		! (3_0) signx0 &= -16;

	lda	[%i1]0x82,%l4		! (4_0) uy0 = *(int*)py;
	fmuld	%f2,%f20,%f2		! (0_0) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (4_1) dtmp0 += K0;

	lda	[%i3]0x82,%l3		! (4_0) ux0 = *(int*)px;
	fdivd	%f40,%f16,%f6		! (3_0) x0 = y0 / x0;
	faddd	%f24,K2,%f24		! (5_1) dtmp0 += K2;

	fdtos	%f4,%f1			! (3_1) ftmp0 = (float)dtmp0;
	and	%o4,-8,%o4		! (3_0) signy0 &= -8;
	st	%f1,[%o2]		! (3_1) *pz = ftmp0;
	fmuld	%f8,%f8,%f16		! (2_0) x20 = x0 * x0;

	ldd	[cmul_arr+%l5],%f0	! (4_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	add	%l6,%o5,%o2		! (3_0) ltmp0 += signx0;
	fmuld	%f28,%f18,%f28		! (1_0) dtmp0 *= x20;

	fmuld	%f38,%f62,%f62		! (4_1) x0 = dtmp0 * x0;
	and	%l3,_0x7fffffff,%l6	! (4_0) ax0 = ux0 & 0x7fffffff;
	sethi	%hi(0x00800000),%o5
	faddd	%f2,K4,%f2		! (0_0) dtmp0 += K4;

	and	%l4,_0x7fffffff,%l5	! (4_0) ay0 = uy0 & 0x7fffffff;
	fmuld	%f24,%f22,%f38		! (5_1) dtmp0 *= x20;

	cmp	%l6,%o5
	bl,pn	%icc,.up20
	fmuld	K9,%f16,%f40		! (2_0) dtmp0 = K9 * x20;
.co20:
	nop
	cmp	%l5,%o5
	bl,pn	%icc,.up21
	faddd	%f28,K6,%f4		! (1_0) dtmp0 += K6;
.co21:
	ldd	[%o2+%o4],%f28		! (3_0) cadd0 = *(double*)(ltmp0 + signy0);
	cmp	%l6,_0x7f800000
	bge,pn	%icc,.up22
	fmuld	%f2,%f20,%f24		! (0_0) dtmp0 *= x20;
.co22:
	sub	%l6,%l5,%o2		! (4_0) ldiff0 = ax0 - ay0;
	cmp	%l5,_0x7f800000
	bge,pn	%icc,.up23

	fmuld	%f0,%f62,%f62		! (4_1) dtmp0 = cmul0 * x0;
.co23:
	sra	%o2,31,%l5		! (4_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (4_0) addrc0 = (char*)px - (char*)py;
	faddd	%f38,K1,%f38		! (5_1) dtmp0 += K1;

	faddd	%f40,K8,%f40		! (2_0) dtmp0 += K8;
	and	%l6,%l5,%o2		! (4_0) addrc0 &= ldiff0;
	fmuld	%f4,%f18,%f4		! (1_0) dtmp0 *= x20;

	lda	[%i1+%o2]0x82,%f0	! (4_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (4_0) (char*)px - addrc0;
	add	%o1,stridez,%o2		! pz += stridez
	faddd	%f24,K3,%f24		! (0_0) dtmp0 += K3;

	lda	[%o4]0x82,%f2		! (4_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%o7,3,%o7		! (5_1) cmul0_ind = ldiff0 << 3;
	add	%i3,stridex,%i3		! px += stridex

	fmuld	%f38,%f22,%f38		! (5_1) dtmp0 *= x20;
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bge,pn	%icc,.update15		! (4_0) if ( b0 > 0x7f800000 )
	faddd	%f26,%f62,%f22		! (4_1) dtmp0 = cadd0 + dtmp0;
.cont15:
	fmuld	%f40,%f16,%f26		! (2_0) dtmp0 *= x20;
	sll	%l5,5,%l6		! (4_0) ltmp0 = ldiff0 << 5;
	add	%i1,stridey,%i1		! py += stridey
	fstod	%f0,%f40		! (4_0) y0 = (double)fy0;

	faddd	%f4,K5,%f62		! (1_0) dtmp0 += K5;
	sra	%l3,27,%o5		! (4_0) signx0 = ux0 >> 27;
	fmuld	%f24,%f20,%f24		! (0_0) dtmp0 *= x20;

	fstod	%f2,%f2			! (4_0) x0 = (double)fx0;
	sra	%l4,28,%o4		! (4_0) signy0 = uy0 >> 28;
.den5:
	lda	[%i1]0x82,%l3		! (5_0) uy0 = *(int*)py;
	subcc	counter,6,counter	! counter?
	add	%l6,cadd_arr,%l6	! (4_0) ltmp0 += (char*)cadd_arr;
	faddd	%f26,K7,%f26		! (2_0) dtmp0 += K7;

	fmuld	%f62,%f18,%f4		! (1_0) dtmp0 *= x20;
	and	%o5,-16,%o5		! (4_0) signx0 &= -16;
	bpos,pt	%icc,.main_loop
	faddd	%f38,K0,%f38		! (5_1) dtmp0 += K0;

.tail:
	addcc	counter,5,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o1,%o4

	faddd	%f24,K2,%f40		! (0_1) dtmp0 += K2;

	fdtos	%f22,%f22		! (4_2) ftmp0 = (float)dtmp0;
	st	%f22,[%o1]		! (4_2) *pz = ftmp0;

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o2,%o4

	ldd	[cmul_arr+%o7],%f0	! (5_2) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);
	fmuld	%f26,%f16,%f26		! (2_1) dtmp0 *= x20;

	fmuld	%f38,%f14,%f14		! (5_2) x0 = dtmp0 * x0;
	faddd	%f4,K4,%f4		! (1_1) dtmp0 += K4;

	fmuld	%f40,%f20,%f38		! (0_1) dtmp0 *= x20;


	faddd	%f26,K6,%f22		! (2_1) dtmp0 += K6;

	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;

	fmuld	%f0,%f14,%f14		! (5_2) dtmp0 = cmul0 * x0;
	faddd	%f38,K1,%f38		! (0_1) dtmp0 += K1;

	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	faddd	%f4,K3,%f4		! (1_1) dtmp0 += K3;

	fmuld	%f38,%f20,%f38		! (0_1) dtmp0 *= x20;
	faddd	%f36,%f14,%f20		! (5_2) dtmp0 = cadd0 + dtmp0;

	faddd	%f22,K5,%f14		! (2_1) dtmp0 += K5;
	add	%o2,stridez,%o1		! pz += stridez
	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;

	sll	%l7,3,%l7		! (0_1) cmul0_ind = ldiff0 << 3;

	fmuld	%f14,%f16,%f22		! (2_1) dtmp0 *= x20;
	faddd	%f38,K0,%f38		! (0_1) dtmp0 += K0;

	faddd	%f4,K2,%f40		! (1_1) dtmp0 += K2;

	fdtos	%f20,%f2		! (5_2) ftmp0 = (float)dtmp0;
	st	%f2,[%o2]		! (5_2) *pz = ftmp0;

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o1,%o4

	ldd	[cmul_arr+%l7],%f0	! (0_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);

	fmuld	%f38,%f12,%f12		! (0_1) x0 = dtmp0 * x0;
	faddd	%f22,K4,%f22		! (2_1) dtmp0 += K4;

	fmuld	%f40,%f18,%f38		! (1_1) dtmp0 *= x20;

	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	fmuld	%f0,%f12,%f12		! (0_1) dtmp0 = cmul0 * x0;
	faddd	%f38,K1,%f38		! (1_1) dtmp0 += K1;

	sll	%g1,3,%g1		! (1_1) cmul0_ind = ldiff0 << 3;
	faddd	%f22,K3,%f22		! (2_1) dtmp0 += K3;

	add	%o1,stridez,%o2		! pz += stridez

	fmuld	%f38,%f18,%f38		! (1_1) dtmp0 *= x20;
	faddd	%f34,%f12,%f18		! (0_1) dtmp0 = cadd0 + dtmp0;

	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	faddd	%f38,K0,%f38		! (1_1) dtmp0 += K0;

	faddd	%f22,K2,%f40		! (2_1) dtmp0 += K2;

	fdtos	%f18,%f2		! (0_1) ftmp0 = (float)dtmp0;
	st	%f2,[%o1]		! (0_1) *pz = ftmp0

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o2,%o4

	ldd	[cmul_arr+%g1],%f0	! (1_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);

	fmuld	%f38,%f10,%f10		! (1_1) x0 = dtmp0 * x0;

	fmuld	%f40,%f16,%f38		! (2_1) dtmp0 *= x20;

	fmuld	%f0,%f10,%f10		! (1_1) dtmp0 = cmul0 * x0;
	faddd	%f38,K1,%f38		! (2_1) dtmp0 += K1;

	sll	%g5,3,%g5		! (2_1) cmul0_ind = ldiff0 << 3;

	add	%o2,stridez,%o1		! pz += stridez

	fmuld	%f38,%f16,%f38		! (2_1) dtmp0 *= x20;
	faddd	%f32,%f10,%f16		! (1_1) dtmp0 = cadd0 + dtmp0;

	faddd	%f38,K0,%f38		! (2_1) dtmp0 += K0;

	fdtos	%f16,%f2		! (1_1) ftmp0 = (float)dtmp0;
	st	%f2,[%o2]		! (1_1) *pz = ftmp0;

	subcc	counter,1,counter
	bneg,a,pn	%icc,.begin
	or	%g0,%o1,%o4

	ldd	[cmul_arr+%g5],%f0	! (2_1) cmul0 = *(double*)((char*)cmul_arr + cmul0_ind);

	fmuld	%f38,%f8,%f8		! (2_1) x0 = dtmp0 * x0;

	fmuld	%f0,%f8,%f8		! (2_1) dtmp0 = cmul0 * x0;

	add	%o1,stridez,%o2		! pz += stridez

	faddd	%f30,%f8,%f24		! (2_1) dtmp0 = cadd0 + dtmp0;

	fdtos	%f24,%f1		! (2_1) ftmp0 = (float)dtmp0;
	st	%f1,[%o1]		! (2_1) *pz = ftmp0;

	ba	.begin
	or	%g0,%o2,%o4

	.align	16
.spec0:
	cmp	%l6,_0x7f800000		! ax0 ? 0x7f800000
	bg	2f			! if ( ax0 >= 0x7f800000 )
	srl	%l3,30,%l3		! signx0 = (unsigned)ux0 >> 30;

	cmp	%l7,_0x7f800000		! ay0 ? 0x7f800000
	bg	2f			! if ( ay0 >= 0x7f800000 )
	and	%l3,2,%l3		! signx0 &= 2;

	sra	%l4,31,%l4		! signy0 = uy0 >> 31;
	bne,a	1f			! if (ay0 != 0x7f800000)
	add	%l3,%l3,%l3		! signx0 += signx0;

	cmp	%l6,_0x7f800000		! ax0 ? 0x7f800000
	bne,a	1f			! if ( ax0 != 0x7f800000 )
	add	%g0,2,%l3		! signx0 = 2

	add	%l3,1,%l3		! signx0 ++;
1:
	sll	%l4,3,%l4		! signy0 <<= 3;
	st	%l3,[%fp+tmp_pz]	! STORE signx0

	ldd	[cmul_arr+88],%f0	! LOAD M_PI_4

	ld	[%fp+tmp_pz],%f2	! LOAD signx0

	ldd	[cmul_arr+%l4],%f4	! dtmp0 = *(double*)((char*)(cmul_arr + 1) + signy0);

	add	%i1,stridey,%i1		! py += stridey;
	fitod	%f2,%f2			! dtmp1 = (double)signx0;

	add	%i3,stridex,%i3		! px += stridex;

	fmuld	%f2,%f0,%f0		! res = signx0 * M_PI_4;

	fmuld	%f0,%f4,%f0		! res *= dtmp0;
	fdtos	%f0,%f0			! ftmp0 = (float) res;
	st	%f0,[%o4]		! *pz = ftmp0;

	ba	.begin1
	add	%o4,stridez,%o4		! pz += stridez;
2:
	std	%l6,[%fp+tmp_pz]	! *(float*)&ax0, *(float*)&ay0
	ldd	[%fp+tmp_pz],%f0	! *(float*)&ax0, *(float*)&ay0

	add	%i1,stridey,%i1		! py += stridey;

	fmuls	%f0,%f1,%f0		! ftmp0 = *(float*)&ax0 * *(float*)&ay0;
	add	%i3,stridex,%i3		! pz += stridex;
	st	%f0,[%o4]		! *pz = ftmp0;

	ba	.begin1
	add	%o4,stridez,%o4		! pz += stridez;

	.align	16
.spec1:
	cmp	%l6,0
	bne,pn	%icc,1f
	nop

	cmp	%l7,0
	bne,pn	%icc,1f
	nop

	sra	%l4,28,%l4		! signy0 = uy0 >> 28;

	sra	%l3,27,%l3		! signx0 = ux0 >> 27;
	and	%l4,-8,%l4		! signy0 &= -8;

	sra	%o2,31,%o2		! ldiff0 >>= 31;
	and	%l3,-16,%l3		! signx0 &= -16;

	sll	%o2,5,%o2		! ldiff0 <<= 5;
	add	%l4,%l3,%l3		! signx0 += signy0;

	add	%o2,%l3,%l3		! signx0 += ldiff0;
	add	%i1,stridey,%i1		! py += stridey;

	ldd	[cadd_arr+%l3],%f0	! res = *(double*)((char*)(cadd_arr + 7) + signx0);
	add	%i3,stridex,%i3		! px += stridex;

	fdtos	%f0,%f0			! ftmp0 = (float) res;
	st	%f0,[%o4]		! *pz = ftmp0;

	ba	.begin1
	add	%o4,stridez,%o4		! pz += stridez;
1:
	stx	%o4,[%fp+tmp_pz]
	sra	%o2,31,%l7		! (0_0) ldiff0 >>= 31;
	sub	%i3,%i1,%l6		! (0_0) addrc0 = (char*)px - (char*)py;

	and	%l6,%l7,%o2		! (0_0) addrc0 &= ldiff0;

	lda	[%i1+%o2]0x82,%f0	! (0_0) fy0 = *(float*)((char*)py + addrc0);
	sub	%i3,%o2,%o4		! (0_0) (char*)px - addrc0

	lda	[%i1+%o2]0x82,%l5	! (0_0) fy0 = *(float*)((char*)py + addrc0);

	lda	[%o4]0x82,%f2		! (0_0) fx0 = *(float*)((char*)px - addrc0);
	sll	%l7,5,%l6		! (0_0) ltmp0 = ldiff0 << 5;

	lda	[%o4]0x82,%g5		! (0_0) fx0 = *(float*)((char*)px - addrc0);

	sra	%l3,27,%o5		! (0_0) signx0 = ux0 >> 27;
	add	%i1,stridey,%i1		! py += stridey

	add	%i3,stridex,%i3		! px += stridex

	lda	[%i1]0x82,%l3		! (1_0) uy0 = *(int*)py;
	sra	%l4,28,%o4		! (0_0) signy0 = uy0 >> 28;

	add	%l6,cadd_arr,%l6	! (0_0) ltmp0 += (char*)cadd_arr;

	and	%l5,_0x7fffffff,%l4
	sethi	%hi(0x00800000),%g1

	cmp	%l4,%g1
	bge,a	%icc,1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	fabss	%f0,%f0			! fy0 = fabsf(fy0);
	ldd	[cmul_arr+96],%f40
	sra	%l5,28,%l4		! itmp0 >>= 28;

	and	%l4,-8,%l4
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f40,%f0,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%l4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f40,%f0,%f40		! dtmp0 *= dsign;
1:
	and	%g5,_0x7fffffff,%l4
	cmp	%l4,%g1
	bge,a	%icc,.spec1_cont
	fstod	%f2,%f2			! (0_0) x0 = (double)fx0;

	fabss	%f2,%f2			! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%g5,28,%l4		! itmp0 >>= 28;

	and	%l4,-8,%l4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%l4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	ba	.spec1_cont
	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;

	.align	16
.update0:
	cmp	counter,0
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont0
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,0,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,0,counter
	ba	.cont0
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_px]
	st	%f2,[%fp+tmp_px+4]
	ld	[%fp+tmp_px],%o4

	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	add	%i3,stridex,%i3		! px += stridex
	add	%i1,stridey,%i1		! py += stridey

	ld	[%fp+tmp_px+4],%o4
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	sra	%l4,27,%o5		! (1_0) signx0 = ux0 >> 27;

	sra	%l3,28,%o4		! (1_0) signy0 = uy0 >> 28;
	ba	.d0
	add	%l6,cadd_arr,%l6	! (1_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update1:
	cmp	counter,1
	bg,pn	%icc,1f
	nop

	fzero	%f0
	ba	.cont1
	ld	[cmul_arr],%f2
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,1,counter
	ba	.cont1
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_px]
	st	%f2,[%fp+tmp_px+4]
	ld	[%fp+tmp_px],%o4
	fmuld	%f40,%f20,%f30		! (0_0) dtmp0 *= x20;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:

	add	%i1,stridey,%i1		! py += stridey

	ld	[%fp+tmp_px+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	sll	%g5,5,%l6		! (2_0) ltmp0 = ldiff0 << 5;
	sra	%l3,27,%o5		! (2_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex

	sra	%l4,28,%o4		! (2_0) signy0 = uy0 >> 28;
	ba	.d1
	add	%l6,cadd_arr,%l6	! (2_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update2:
	cmp	counter,2
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f1
	ba	.cont2
	fzeros	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f1
	or	%g0,2,counter
	ba	.cont2
	fzeros	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	std	%f0,[%fp+tmp_px]
	ld	[%fp+tmp_px],%o4
	fmuld	%f40,%f18,%f28		! (1_0) dtmp0 *= x20;

	faddd	%f16,K5,%f2		! (0_0) dtmp0 += K5;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f16		! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f16,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f16	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f16,%f40,%f40		! dtmp0 *= dsign;
1:
	add	%i1,stridey,%i1		! py += stridey

	ld	[%fp+tmp_px+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f1,%f16		! (5_1) x0 = (double)fx0;

	fabss	%f1,%f16		! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f16,%f16		! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f16,%f0,%f16		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f16,%f0,%f16		! dtmp0 *= dsign;
1:
	sll	%o0,5,%l6		! (3_0) ltmp0 = ldiff0 << 5;
	sra	%l4,27,%o5		! (3_0) signx0 = ux0 >> 27;

	add	%i3,stridex,%i3		! px += stridex
	ba	.d2
	sra	%l3,28,%o4		! (3_0) signy0 = uy0 >> 28;

	.align	16
.update3:
	cmp	counter,3
	bg,pn	%icc,1f
	nop

	fzero	%f0
	ba	.cont3
	ld	[cmul_arr],%f2
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,3,counter
	ba	.cont3
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_px]
	st	%f2,[%fp+tmp_px+4]
	ld	[%fp+tmp_px],%o4
	fmuld	%f40,%f16,%f26		! (2_0) dtmp0 *= x20;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	add	%i1,stridey,%i1		! py += stridey
	faddd	%f4,K5,%f62		! (1_0) dtmp0 += K5;
	fmuld	%f24,%f20,%f24		! (0_0) dtmp0 *= x20;

	ld	[%fp+tmp_px+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	fabss	%f2,%f2			! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	sll	%l5,5,%l6		! (4_0) ltmp0 = ldiff0 << 5;
	sra	%l3,27,%o5		! (4_0) signx0 = ux0 >> 27;

	add	%i3,stridex,%i3		! px += stridex
	ba	.d3
	sra	%l4,28,%o4		! (4_0) signy0 = uy0 >> 28;

	.align	16
.update4:
	cmp	counter,4
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f1
	ba	.cont4
	fzeros	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f1
	or	%g0,4,counter
	ba	.cont4
	fzeros	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	std	%f0,[%fp+tmp_px]
	ld	[%fp+tmp_px],%o4
	fmuld	%f40,%f24,%f36		! (3_1) dtmp0 *= x20;

	and	%o4,_0x7fffffff,%o1	! itmp0 & 0x7fffffff
	cmp	%o1,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f14		! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f14,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f14	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f14,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f22,K5,%f14		! (2_1) dtmp0 += K5;
	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;

	ld	[%fp+tmp_px+4],%o4
	and	%o4,_0x7fffffff,%o1	! itmp0 & 0x7fffffff
	cmp	%o1,%o5
	bge,a	1f
	fstod	%f1,%f2			! (5_1) x0 = (double)fx0;

	fabss	%f1,%f22		! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f22,%f22		! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f22,%f0,%f22		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f22,%f0,%f2		! dtmp0 *= dsign;
1:
	sll	%l7,3,%l7		! (0_1) cmul0_ind = ldiff0 << 3;
	ba	.d4
	add	%i3,stridex,%i3		! px += stridex

	.align	16
.update5:
	cmp	counter,5
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont5
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,5,counter
	ba	.cont5
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_px]
	st	%f2,[%fp+tmp_px+4]
	ld	[%fp+tmp_px],%o4
	fmuld	%f40,%f4,%f34		! (4_1) dtmp0 *= x20;

	stx	%l5,[%fp+tmp_py]
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f20,K5,%f12		! (3_1) dtmp0 += K5;
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	ld	[%fp+tmp_px+4],%o4
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	ldx	[%fp+tmp_py],%l5
	sra	%l3,27,%o5		! (0_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex

	lda	[%i1]0x82,%l3		! (1_0) uy0 = *(int*)py;
	sra	%l4,28,%o4		! (0_0) signy0 = uy0 >> 28;
	ba	.d5
	add	%l6,cadd_arr,%l6	! (0_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update6:
	cmp	counter,5
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont6
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,5,counter
	ba	.cont6
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f22,%f32		! (5_1) dtmp0 *= x20;

	stx	%l5,[%fp+tmp_px]
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f18,K5,%f10		! (4_1) dtmp0 += K5;
	add	%i3,stridex,%i3		! px += stridex
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	ldx	[%fp+tmp_px],%l5

	sra	%l4,27,%o5		! (1_0) signx0 = ux0 >> 27;

	sra	%l3,28,%o4		! (1_0) signy0 = uy0 >> 28;
	ba	.d6
	add	%l6,cadd_arr,%l6	! (1_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update7:
	cmp	counter,5
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont7
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,5,counter
	ba	.cont7
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f20,%f30		! (0_0) dtmp0 *= x20;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f16,K5,%f8		! (5_1) dtmp0 += K5;
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	sll	%g5,5,%l6		! (2_0) ltmp0 = ldiff0 << 5;
	sra	%l3,27,%o5		! (2_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex

	sra	%l4,28,%o4		! (2_0) signy0 = uy0 >> 28;
	ba	.d7
	add	%l6,cadd_arr,%l6	! (2_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update8:
	cmp	counter,5
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f1
	ba	.cont8
	fzeros	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f1
	or	%g0,5,counter
	ba	.cont8
	fzeros	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	std	%f0,[%fp+tmp_pz]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f18,%f28		! (1_0) dtmp0 *= x20;

	faddd	%f16,K5,%f2		! (0_0) dtmp0 += K5;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f16		! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f16,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f16	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f16,%f40,%f40		! dtmp0 *= dsign;
1:
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f24,%f22,%f24		! (5_1) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f1,%f16		! (5_1) x0 = (double)fx0;

	fabss	%f1,%f16		! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f16,%f16		! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f16,%f0,%f16		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f16,%f0,%f16		! dtmp0 *= dsign;
1:
	sll	%o0,5,%l6		! (3_0) ltmp0 = ldiff0 << 5;
	sra	%l4,27,%o5		! (3_0) signx0 = ux0 >> 27;

	add	%i3,stridex,%i3		! px += stridex
	ba	.d8
	sra	%l3,28,%o4		! (3_0) signy0 = uy0 >> 28;

	.align	16
.update9:
	cmp	counter,5
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont9
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,5,counter
	ba	.cont9
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f16,%f26		! (2_0) dtmp0 *= x20;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	add	%i1,stridey,%i1		! py += stridey
	faddd	%f4,K5,%f62		! (1_0) dtmp0 += K5;
	fmuld	%f24,%f20,%f24		! (0_0) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	fabss	%f2,%f2			! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	sll	%l5,5,%l6		! (4_0) ltmp0 = ldiff0 << 5;
	sra	%l3,27,%o5		! (4_0) signx0 = ux0 >> 27;

	add	%i3,stridex,%i3		! px += stridex
	ba	.d9
	sra	%l4,28,%o4		! (4_0) signy0 = uy0 >> 28;

	.align	16
.update10:
	cmp	counter,1
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont10
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,1,counter
	ba	.cont10
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o1
	fmuld	%f40,%f24,%f36		! (3_1) dtmp0 *= x20;

	and	%o1,_0x7fffffff,%o4	! itmp0 & 0x7fffffff
	cmp	%o4,%o5
	bge,a	1f
	fstod	%f0,%f40		! (5_1) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o1,28,%o1		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o1,-8,%o1		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o1],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f22,K5,%f14		! (2_1) dtmp0 += K5;
	fmuld	%f4,%f18,%f4		! (1_1) dtmp0 *= x20;

	sll	%l7,3,%l7		! (0_1) cmul0_ind = ldiff0 << 3;
	add	%i3,stridex,%i3		! px += stridex

	ld	[%fp+tmp_pz+4],%o1
	and	%o1,_0x7fffffff,%o4	! itmp0 & 0x7fffffff
	cmp	%o4,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o1,28,%o1		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o1,-8,%o1		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o1],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	ba	.den0
	add	%o2,stridez,%o1		! pz += stridez

	.align	16
.update11:
	cmp	counter,2
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont11
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,2,counter
	ba	.cont11
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f4,%f34		! (4_1) dtmp0 *= x20;

	stx	%l5,[%fp+tmp_px]
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f20,K5,%f12		! (3_1) dtmp0 += K5;
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f22,%f16,%f22		! (2_1) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	ldx	[%fp+tmp_px],%l5
	sra	%l3,27,%o5		! (0_0) signx0 = ux0 >> 27;
	add	%i3,stridex,%i3		! px += stridex

	lda	[%i1]0x82,%l3		! (1_0) uy0 = *(int*)py;
	sra	%l4,28,%o4		! (0_0) signy0 = uy0 >> 28;
	ba	.den1
	add	%l6,cadd_arr,%l6	! (0_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update12:
	cmp	counter,3
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont12
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	stx	%i3,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,3,counter
	ba	.cont12
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f22,%f32		! (5_1) dtmp0 *= x20;

	stx	%l5,[%fp+tmp_px]
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f18,K5,%f10		! (4_1) dtmp0 += K5;
	add	%i3,stridex,%i3		! px += stridex
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f20,%f24,%f20		! (3_1) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l5	! itmp0 & 0x7fffffff
	cmp	%l5,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	ldx	[%fp+tmp_px],%l5

	sra	%l4,27,%o5		! (1_0) signx0 = ux0 >> 27;

	sra	%l3,28,%o4		! (1_0) signy0 = uy0 >> 28;
	ba	.den2
	add	%l6,cadd_arr,%l6	! (1_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update13:
	cmp	counter,4
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont13
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	sub	%i3,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,4,counter
	ba	.cont13
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f20,%f30		! (0_0) dtmp0 *= x20;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	faddd	%f16,K5,%f8		! (5_1) dtmp0 += K5;
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f18,%f4,%f18		! (4_1) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f2,%f2			! fx0 = fabsf(fx0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	sll	%g5,5,%l6		! (2_0) ltmp0 = ldiff0 << 5;
	sra	%l3,27,%o5		! (2_0) signx0 = ux0 >> 27;

	sra	%l4,28,%o4		! (2_0) signy0 = uy0 >> 28;
	ba	.den3
	add	%l6,cadd_arr,%l6	! (2_0) ltmp0 += (char*)cadd_arr;

	.align	16
.update14:
	cmp	counter,5
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f1
	ba	.cont14
	fzeros	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	sub	%i3,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	ld	[cmul_arr],%f1
	or	%g0,5,counter
	ba	.cont14
	fzeros	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	std	%f0,[%fp+tmp_pz]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f18,%f28		! (1_0) dtmp0 *= x20;

	faddd	%f16,K5,%f2		! (0_0) dtmp0 += K5;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f16		! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f16,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f16	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f16,%f40,%f40		! dtmp0 *= dsign;
1:
	add	%i1,stridey,%i1		! py += stridey
	fmuld	%f24,%f22,%f24		! (5_1) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f1,%f16		! (5_1) x0 = (double)fx0;

	fabss	%f1,%f16		! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f16,%f16		! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f16,%f0,%f16		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f16,%f0,%f16		! dtmp0 *= dsign;
1:
	sll	%o0,5,%l6		! (3_0) ltmp0 = ldiff0 << 5;
	sra	%l4,27,%o5		! (3_0) signx0 = ux0 >> 27;

	ba	.den4
	sra	%l3,28,%o4		! (3_0) signy0 = uy0 >> 28;

	.align	16
.update15:
	cmp	counter,6
	bg,pn	%icc,1f
	nop

	ld	[cmul_arr],%f2
	ba	.cont15
	fzero	%f0
1:
	cmp	%o5,_0x7f800000		! (4_0) b0 ? 0x7f800000
	bg,pt	%icc,1f
	nop
2:
	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_py]
	sub	%i3,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	ld	[cmul_arr],%f2
	or	%g0,6,counter
	ba	.cont15
	fzero	%f0
1:
	andcc	%l3,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	bne,pn	%icc,1f
	sethi	%hi(0x00800000),%o5

	andcc	%l4,_0x7fffffff,%g0	! itmp0 & 0x7fffffff
	be,pn	%icc,2b
	nop
1:
	st	%f0,[%fp+tmp_pz]
	st	%f2,[%fp+tmp_pz+4]
	ld	[%fp+tmp_pz],%o4
	fmuld	%f40,%f16,%f26		! (2_0) dtmp0 *= x20;

	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f0,%f40		! (0_0) y0 = (double)fy0;

	ldd	[cmul_arr+96],%f40	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;
	fabss	%f0,%f0			! fy0 = fabsf(fy0);

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f0,%f0			! dtmp0 = (double) *(int*)&fy0;

	fmuld	%f0,%f40,%f40		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f0,%f40,%f40		! dtmp0 *= dsign;
1:
	add	%i1,stridey,%i1		! py += stridey
	faddd	%f4,K5,%f62		! (1_0) dtmp0 += K5;
	fmuld	%f24,%f20,%f24		! (0_0) dtmp0 *= x20;

	ld	[%fp+tmp_pz+4],%o4
	and	%o4,_0x7fffffff,%l6	! itmp0 & 0x7fffffff
	cmp	%l6,%o5
	bge,a	1f
	fstod	%f2,%f2			! (5_1) x0 = (double)fx0;

	fabss	%f2,%f2			! fx0 = fabsf(fx0);
	ldd	[cmul_arr+96],%f0	! LOAD C2ONM149
	sra	%o4,28,%o4		! itmp0 >>= 28;

	and	%o4,-8,%o4		! itmp0 = -8;
	fitod	%f2,%f2			! dtmp0 = (double) *(int*)&fx0;

	fmuld	%f2,%f0,%f2		! dtmp0 *= C2ONM149;
	ldd	[cmul_arr+%o4],%f0	! dsign = *(double*)((char*)cmul_arr + itmp0);

	fmuld	%f2,%f0,%f2		! dtmp0 *= dsign;
1:
	sll	%l5,5,%l6		! (4_0) ltmp0 = ldiff0 << 5;
	sra	%l3,27,%o5		! (4_0) signx0 = ux0 >> 27;

	ba	.den5
	sra	%l4,28,%o4		! (4_0) signy0 = uy0 >> 28;

	.align	16
.u0:
	ba	.c0
	or	%g0,_0x7fffffff,%o5
.u1:
	ba	.c1
	or	%g0,_0x7fffffff,%o5
.u2:
	ba	.c2
	or	%g0,_0x7f800000,%o5
.u3:
	ba	.c3
	or	%g0,_0x7f800000,%o5
.u4:
	ba	.c4
	or	%g0,_0x7fffffff,%o5
.u5:
	ba	.c5
	or	%g0,_0x7fffffff,%o5
.u6:
	ba	.c6
	or	%g0,_0x7f800000,%o5
.u7:
	ba	.c7
	or	%g0,_0x7f800000,%o5
.u8:
	ba	.c8
	or	%g0,_0x7fffffff,%o5
.u9:
	ba	.c9
	or	%g0,_0x7fffffff,%o5
.u10:
	ba	.c10
	or	%g0,_0x7f800000,%o5
.u11:
	ba	.c11
	or	%g0,_0x7f800000,%o5
.u12:
	ba	.c12
	or	%g0,_0x7fffffff,%o5
.u13:
	ba	.c13
	or	%g0,_0x7fffffff,%o5
.u14:
	ba	.c14
	or	%g0,_0x7f800000,%o5
.u15:
	ba	.c15
	or	%g0,_0x7f800000,%o5
.u16:
	ba	.c16
	or	%g0,_0x7fffffff,%o5
.u17:
	ba	.c17
	or	%g0,_0x7fffffff,%o5
.u18:
	ba	.c18
	or	%g0,_0x7f800000,%o5
.u19:
	ba	.c19
	or	%g0,_0x7f800000,%o5
.u20:
	ba	.c20
	or	%g0,_0x7fffffff,%o5
.u21:
	ba	.c21
	or	%g0,_0x7fffffff,%o5
.u22:
	ba	.c22
	or	%g0,_0x7f800000,%o5
.u23:
	ba	.c23
	or	%g0,_0x7f800000,%o5
.u24:
	ba	.c24
	or	%g0,_0x7fffffff,%o5
.u25:
	ba	.c25
	or	%g0,_0x7fffffff,%o5
.u26:
	ba	.c26
	or	%g0,_0x7f800000,%o5
.u27:
	ba	.c27
	or	%g0,_0x7f800000,%o5
.u28:
	ba	.c28
	or	%g0,_0x7fffffff,%o5
.u29:
	ba	.c29
	or	%g0,_0x7fffffff,%o5
.u30:
	ba	.c30
	or	%g0,_0x7f800000,%o5
.u31:
	ba	.c31
	or	%g0,_0x7f800000,%o5
.u32:
	ba	.c32
	or	%g0,_0x7fffffff,%o5
.u33:
	ba	.c33
	or	%g0,_0x7fffffff,%o5
.u34:
	ba	.c34
	or	%g0,_0x7f800000,%o5
.u35:
	ba	.c35
	or	%g0,_0x7f800000,%o5
.u36:
	ba	.c36
	or	%g0,_0x7fffffff,%o5
.u37:
	ba	.c37
	or	%g0,_0x7fffffff,%o5
.u38:
	ba	.c38
	or	%g0,_0x7f800000,%o5
.u39:
	ba	.c39
	or	%g0,_0x7f800000,%o5
.up0:
	ba	.co0
	or	%g0,_0x7fffffff,%o5
.up1:
	ba	.co1
	or	%g0,_0x7fffffff,%o5
.up2:
	ba	.co2
	or	%g0,_0x7f800000,%o5
.up3:
	ba	.co3
	or	%g0,_0x7f800000,%o5
.up4:
	ba	.co4
	or	%g0,_0x7fffffff,%o5
.up5:
	ba	.co5
	or	%g0,_0x7fffffff,%o5
.up6:
	ba	.co6
	or	%g0,_0x7f800000,%o5
.up7:
	ba	.co7
	or	%g0,_0x7f800000,%o5
.up8:
	ba	.co8
	or	%g0,_0x7fffffff,%o5
.up9:
	ba	.co9
	or	%g0,_0x7fffffff,%o5
.up10:
	ba	.co10
	or	%g0,_0x7f800000,%o5
.up11:
	ba	.co11
	or	%g0,_0x7f800000,%o5
.up12:
	ba	.co12
	or	%g0,_0x7fffffff,%o5
.up13:
	ba	.co13
	or	%g0,_0x7fffffff,%o5
.up14:
	ba	.co14
	or	%g0,_0x7f800000,%o5
.up15:
	ba	.co15
	or	%g0,_0x7f800000,%o5
.up16:
	ba	.co16
	or	%g0,_0x7fffffff,%o5
.up17:
	ba	.co17
	or	%g0,_0x7fffffff,%o5
.up18:
	ba	.co18
	or	%g0,_0x7f800000,%o5
.up19:
	ba	.co19
	or	%g0,_0x7f800000,%o5
.up20:
	ba	.co20
	or	%g0,_0x7fffffff,%o5
.up21:
	ba	.co21
	or	%g0,_0x7fffffff,%o5
.up22:
	ba	.co22
	or	%g0,_0x7f800000,%o5
.up23:
	ba	.co23
	or	%g0,_0x7f800000,%o5
.exit:
	ret
	restore
	SET_SIZE(__vatan2f)

