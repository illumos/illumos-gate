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

	.file	"__vsqrtf_ultra3.S"

#include "libm.h"
#if defined(LIBMVEC_SO_BUILD)
	.weak	__vsqrtf
	.type	__vsqrtf,#function
	__vsqrtf = __vsqrtf_ultra3
#endif

	RO_DATA
	.align	64

.CONST_TBL:
	.word	0x3fe00001, 0x80007e00	! K1  =  5.00000715259318464227e-01
	.word	0xbfc00003, 0xc0017a01	! K2  = -1.25000447037521686593e-01
	.word	0x000fffff, 0xffffffff	! DC0 = 0x000fffffffffffff
	.word	0x3ff00000, 0x00000000	! DC1 = 0x3ff0000000000000
	.word	0x7ffff000, 0x00000000	! DC2 = 0x7ffff00000000000

#define DC0		%f6
#define DC1		%f4
#define DC2		%f2
#define K2		%f38
#define K1		%f36
#define TBL		%l2
#define stridex		%l3
#define stridey		%l4
#define _0x1ff0		%l5
#define counter		%l6
#define _0x00800000	%l7
#define _0x7f800000	%o0

#define tmp_px		STACK_BIAS-0x40
#define tmp_counter	STACK_BIAS-0x38
#define tmp0		STACK_BIAS-0x30
#define tmp1		STACK_BIAS-0x28
#define tmp2		STACK_BIAS-0x20
#define tmp3		STACK_BIAS-0x18
#define tmp4		STACK_BIAS-0x10

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x40

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!
!  x0 = *px;
!  ax = *(int*)px;
!  px += stridex;
!
!  if( ax >= 0x7f800000 )
!  {
!    *py = sqrtf(x0);
!    py += stridey;
!    continue;
!  }
!  if( ax < 0x00800000 )
!  {
!    *py = sqrtf(x0);
!    py += stridey;
!    continue;
!  }
!
!  db0 = (double)x0;
!  iexp0 = ax >> 24;
!  iexp0 += 0x3c0;
!  lexp0 = (long long)iexp0 << 52;
!
!  db0 = vis_fand(db0,DC0);
!  db0 = vis_for(db0,DC1);
!  hi0 = vis_fand(db0,DC2);
!
!  ax >>= 11;
!  si0 = ax & 0x1ff0;
!  dtmp0 = ((double*)((char*)TBL + si0))[0];
!  xx0 = (db0 - hi0);
!  xx0 *= dtmp0;
!  dtmp0 = ((double*)((char*)TBL + si0))[1]
!  res0 = K2 * xx0;
!  res0 += K1;
!  res0 *= xx0;
!  res0 += DC1;
!  res0 = dtmp0 * res0;
!  dtmp1 = *((double*)&lexp0);
!  res0 *= dtmp1;
!  fres0 = (float)res0;
!  *py = fres0;
!  py += stridey;
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vsqrtf_ultra3)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,o2)
	PIC_SET(l7,__vlibm_TBL_sqrtf,l2)

	st	%i0,[%fp+tmp_counter]
	sll	%i2,2,stridex
	or	%g0,0xff8,%l5

	stx	%i1,[%fp+tmp_px]
	sll	%l5,1,_0x1ff0

	ldd	[%o2],K1
	sll	%i4,2,stridey

	ldd	[%o2+8],K2
	or	%g0,%i3,%g5

	ldd	[%o2+16],DC0
	sethi	%hi(0x7f800000),%o0

	ldd	[%o2+24],DC1
	sethi	%hi(0x00800000),%l7

	ldd	[%o2+32],DC2

.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%i1
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit

	lda	[%i1]0x82,%o2		! (2_0) ax = *(int*)px;

	or	%g0,%i1,%o7
	lda	[%i1]0x82,%f25		! (2_0) x0 = *px;

	cmp	%o2,_0x7f800000		! (2_0) ax ? 0x7f800000
	bge,pn	%icc,.spec		! (2_0) if( ax >= 0x7f800000 )
	nop

	cmp	%o2,_0x00800000		! (2_0) ax ? 0x00800000
	bl,pn	%icc,.spec		! (2_0) if( ax < 0x00800000 )
	nop

	fstod	%f25,%f56		! (2_0) db0 = (double)x0;

	lda	[stridex+%o7]0x82,%o1	! (3_0) ax = *(int*)px;

	sra	%o2,24,%l1		! (2_0) iexp0 = ax >> 24;

	add	%o7,stridex,%i1		! px += stridex
	add	%l1,960,%l0		! (2_0) iexp0 += 0x3c0;
	lda	[stridex+%o7]0x82,%f0	! (3_0) x0 = *px;
	fand	%f56,DC0,%f60		! (2_0) db0 = vis_fand(db0,DC0);

	cmp	%o1,_0x7f800000		! (3_0) ax ? 0x7f800000
	bge,pn	%icc,.update0		! (3_0) if( ax >= 0x7f800000 )
	nop
.cont0:
	sllx	%l0,52,%o3		! (2_0) lexp0 = (long long)iexp0 << 52;

	sra	%o2,11,%i2		! (2_0) ax >>= 11;
	stx	%o3,[%fp+tmp0]		! (2_0) dtmp1 = *((double*)&lexp0);
	for	%f60,DC1,%f40		! (2_0) db0 = vis_for(db0,DC1);

	cmp	%o1,_0x00800000		! (3_0) ax ? 0x00800000
	bl,pn	%icc,.update1		! (3_0) if( ax < 0x00800000 )
	nop
.cont1:
	fstod	%f0,%f48		! (3_0) db0 = (double)x0;

	and	%i2,_0x1ff0,%o3		! (2_0) si0 = ax & 0x1ff0;
	lda	[%i1+stridex]0x82,%o2	! (4_0) ax = *(int*)px;

	add	%i1,stridex,%i1		! px += stridex
	add	%o3,TBL,%i2		! (2_0) (char*)TBL + si0
	fand	%f40,DC2,%f46		! (2_0) hi0 = vis_fand(db0,DC2);

	sra	%o1,24,%o4		! (3_0) iexp0 = ax >> 24;

	lda	[%i1]0x82,%f13		! (4_0) x0 = *px;
	fand	%f48,DC0,%f58		! (3_0) db0 = vis_fand(db0,DC0);

	add	%o4,960,%i0		! (3_0) iexp0 += 0x3c0;

	cmp	%o2,_0x7f800000		! (4_1) ax ? 0x7f800000
	bge,pn	%icc,.update2		! (4_1) if( ax >= 0x7f800000 )
	nop
.cont2:
	fsubd	%f40,%f46,%f44		! (2_1) xx0 = (db0 - hi0);
	sllx	%i0,52,%g1		! (3_1) lexp0 = (long long)iexp0 << 52;
	ldd	[%i2],%f40		! (2_1) dtmp0 = ((double*)((char*)TBL + si0))[0];

	sra	%o1,11,%l0		! (3_1) ax >>= 11;
	stx	%g1,[%fp+tmp1]		! (3_1) dtmp1 = *((double*)&lexp0);
	for	%f58,DC1,%f48		! (3_1) db0 = vis_for(db0,DC1);

	cmp	%o2,_0x00800000		! (4_1) ax ? 0x00800000
	bl,pn	%icc,.update3		! (4_1) if( ax < 0x00800000 )
	nop
.cont3:
	fstod	%f13,%f50		! (4_1) db0 = (double)x0;

	fmuld	%f44,%f40,%f46		! (2_1) xx0 *= dtmp0;
	and	%l0,_0x1ff0,%i0		! (3_1) si0 = ax & 0x1ff0;
	lda	[%i1+stridex]0x82,%l1	! (0_0) ax = *(int*)px;

	add	%i0,TBL,%l0		! (3_1) (char*)TBL + si0
	fand	%f48,DC2,%f62		! (3_1) hi0 = vis_fand(db0,DC2);

	sra	%o2,24,%o7		! (4_1) iexp0 = ax >> 24;

	add	%i1,stridex,%o4		! px += stridex
	add	%o7,960,%o7		! (4_1) iexp0 += 0x3c0;
	lda	[%i1+stridex]0x82,%f17	! (0_0) x0 = *px;
	fand	%f50,DC0,%f54		! (4_1) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f46,%f52		! (2_1) res0 = K2 * xx0;
	cmp	%l1,_0x7f800000		! (0_0) ax ? 0x7f800000
	bge,pn	%icc,.update4		! (0_0) if( ax >= 0x7f800000 )
	fsubd	%f48,%f62,%f42		! (3_1) xx0 = (db0 - hi0);
.cont4:
	sllx	%o7,52,%o1		! (4_1) lexp0 = (long long)iexp0 << 52;
	ldd	[%i0+TBL],%f40		! (3_1) dtmp0 = ((double*)((char*)TBL + si0))[0];

	sra	%o2,11,%i5		! (4_1) ax >>= 11;
	stx	%o1,[%fp+tmp2]		! (4_1) dtmp1 = *((double*)&lexp0);
	for	%f54,DC1,%f34		! (4_1) db0 = vis_for(db0,DC1);

	cmp	%l1,_0x00800000		! (0_0) ax ? 0x00800000
	bl,pn	%icc,.update5		! (0_0) if( ax < 0x00800000 )
	nop
.cont5:
	fstod	%f17,%f56		! (0_0) db0 = (double)x0;

	fmuld	%f42,%f40,%f42		! (3_1) xx0 *= dtmp0;
	lda	[stridex+%o4]0x82,%i0	! (1_0) ax = *(int*)px;
	faddd	%f52,K1,%f52		! (2_1) res0 += K1;

	sra	%l1,24,%g1		! (0_0) iexp0 = ax >> 24;
	and	%i5,_0x1ff0,%i5		! (4_1) si0 = ax & 0x1ff0;
	fand	%f34,DC2,%f62		! (4_1) hi0 = vis_fand(db0,DC2);

	add	%o4,stridex,%i1		! px += stridex

	add	%g1,960,%o5		! (0_0) iexp0 += 0x3c0;
	add	%i5,TBL,%i3		! (4_1) (char*)TBL + si0
	lda	[stridex+%o4]0x82,%f21	! (1_0) x0 = *px;
	fand	%f56,DC0,%f32		! (0_0) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f42,%f50		! (3_1) res0 = K2 * xx0;
	cmp	%i0,_0x7f800000		! (1_0) ax ? 0x7f800000
	bge,pn	%icc,.update6		! (1_0) if( ax >= 0x7f800000 )
	fsubd	%f34,%f62,%f54		! (4_1) xx0 = (db0 - hi0);
.cont6:
	fmuld	%f52,%f46,%f52		! (2_1) res0 *= xx0;
	sllx	%o5,52,%o7		! (0_0) lexp0 = (long long)iexp0 << 52;
	ldd	[TBL+%i5],%f62		! (4_1) dtmp0 = ((double*)((char*)TBL + si0))[0];

	sra	%l1,11,%i4		! (0_0) ax >>= 11;
	stx	%o7,[%fp+tmp3]		! (0_0) dtmp1 = *((double*)&lexp0);
	for	%f32,DC1,%f48		! (0_0) db0 = vis_for(db0,DC1);

	cmp	%i0,_0x00800000		! (1_0) ax ? 0x00800000
	bl,pn	%icc,.update7		! (1_0) if( ax < 0x00800000 )
	nop
.cont7:
	fstod	%f21,%f56		! (1_0) db0 = (double)x0;

	fmuld	%f54,%f62,%f46		! (4_1) xx0 *= dtmp0;
	and	%i4,_0x1ff0,%g1		! (0_0) si0 = ax & 0x1ff0;
	lda	[%i1+stridex]0x82,%o2	! (2_0) ax = *(int*)px;
	faddd	%f50,K1,%f62		! (3_1) res0 += K1;

	add	%g1,TBL,%i5		! (0_0) (double*)((char*)TBL + si0
	fand	%f48,DC2,%f32		! (0_0) hi0 = vis_fand(db0,DC2);

	sra	%i0,24,%o4		! (1_0) iexp0 = ax >> 24;
	ldd	[%i2+8],%f60		! (2_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f52,DC1,%f58		! (2_1) res0 += DC1;

	add	%i1,stridex,%o7		! px += stridex
	add	%o4,960,%i2		! (1_0) iexp0 += 0x3c0;
	lda	[%i1+stridex]0x82,%f25	! (2_0) x0 = *px;
	fand	%f56,DC0,%f34		! (1_0) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f46,%f50		! (4_1) res0 = K2 * xx0;
	cmp	%o2,_0x7f800000		! (2_0) ax ? 0x7f800000
	bge,pn	%icc,.update8		! (2_0) if( ax >= 0x7f800000 )
	fsubd	%f48,%f32,%f52		! (0_0) xx0 = (db0 - hi0);
.cont8:
	fmuld	%f62,%f42,%f54		! (3_1) res0 *= xx0;
	sllx	%i2,52,%o4		! (1_0) lexp0 = (long long)iexp0 << 52;
	ldd	[TBL+%g1],%f32		! (0_0) dtmp0 = ((double*)((char*)TBL + si0))[0];

	fmuld	%f60,%f58,%f60		! (2_1) res0 = dtmp0 * res0;
	sra	%i0,11,%g1		! (1_0) ax >>= 11;
	stx	%o4,[%fp+tmp4]		! (1_0) dtmp1 = *((double*)&lexp0);
	for	%f34,DC1,%f48		! (1_0) db0 = vis_for(db0,DC1);

	cmp	%o2,_0x00800000		! (2_0) ax ? 0x00800000
	bl,pn	%icc,.update9		! (2_0) if( ax < 0x00800000 )
	ldd	[%fp+tmp0],%f40		! (2_1) dtmp1 = *((double*)&lexp0);
	fstod	%f25,%f56		! (2_0) db0 = (double)x0;
.cont9:
	fmuld	%f52,%f32,%f42		! (0_0) xx0 *= dtmp0;
	and	%g1,_0x1ff0,%o5		! (1_0) si0 = ax & 0x1ff0;
	lda	[stridex+%o7]0x82,%o1	! (3_0) ax = *(int*)px;
	faddd	%f50,K1,%f34		! (4_1) res0 += K1;

	add	%o5,TBL,%i4		! (1_0) (char*)TBL + si0
	fand	%f48,DC2,%f62		! (1_0) hi0 = vis_fand(db0,DC2);

	fmuld	%f60,%f40,%f32		! (2_1) res0 *= dtmp1;
	sra	%o2,24,%l1		! (2_0) iexp0 = ax >> 24;
	ldd	[%l0+8],%f40		! (3_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f54,DC1,%f58		! (3_1) res0 += DC1;

	add	%o7,stridex,%i1		! px += stridex
	add	%l1,960,%l0		! (2_0) iexp0 += 0x3c0;
	lda	[stridex+%o7]0x82,%f0	! (3_0) x0 = *px;
	fand	%f56,DC0,%f60		! (2_0) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f42,%f50		! (0_0) res0 = K2 * xx0;
	cmp	%o1,_0x7f800000		! (3_0) ax ? 0x7f800000
	bge,pn	%icc,.update10		! (3_0) if( ax >= 0x7f800000 )
	fsubd	%f48,%f62,%f54		! (1_0) xx0 = (db0 - hi0);
.cont10:
	fmuld	%f34,%f46,%f52		! (4_1) res0 *= xx0;
	sllx	%l0,52,%o3		! (2_0) lexp0 = (long long)iexp0 << 52;
	ldd	[TBL+%o5],%f56		! (1_0) dtmp0 = ((double*)((char*)TBL + si0))[0];

	fmuld	%f40,%f58,%f34		! (3_1) res0 = dtmp0 * res0;
	sra	%o2,11,%i2		! (2_0) ax >>= 11;
	stx	%o3,[%fp+tmp0]		! (2_0) dtmp1 = *((double*)&lexp0);
	for	%f60,DC1,%f40		! (2_0) db0 = vis_for(db0,DC1);

	cmp	%o1,_0x00800000		! (3_0) ax ? 0x00800000
	bl,pn	%icc,.update11		! (3_0) if( ax < 0x00800000 )
	ldd	[%fp+tmp1],%f62		! (3_1) dtmp1 = *((double*)&lexp0);
	fstod	%f0,%f48		! (3_0) db0 = (double)x0;
.cont11:
	fmuld	%f54,%f56,%f30		! (1_0) xx0 *= dtmp0;
	and	%i2,_0x1ff0,%o3		! (2_0) si0 = ax & 0x1ff0;
	lda	[%i1+stridex]0x82,%o2	! (4_0) ax = *(int*)px;
	faddd	%f50,K1,%f56		! (0_0) res0 += K1;

	add	%i1,stridex,%i1		! px += stridex
	add	%o3,TBL,%i2		! (2_0) (char*)TBL + si0
	fand	%f40,DC2,%f46		! (2_0) hi0 = vis_fand(db0,DC2);

	fmuld	%f34,%f62,%f28		! (3_1) res0 *= dtmp1;
	sra	%o1,24,%o4		! (3_0) iexp0 = ax >> 24;
	ldd	[%i3+8],%f50		! (4_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f52,DC1,%f54		! (4_1) res0 += DC1;

	lda	[%i1]0x82,%f13		! (4_0) x0 = *px;
	fand	%f48,DC0,%f58		! (3_0) db0 = vis_fand(db0,DC0);

	or	%g0,%g5,%i3
	cmp	counter,5
	bl,pn	%icc,.tail
	add	%o4,960,%g5		! (3_0) iexp0 += 0x3c0;

	ba	.main_loop
	sub	counter,5,counter	! counter

	.align	16
.main_loop:
	fmuld	K2,%f30,%f60		! (1_1) res0 = K2 * xx0;
	cmp	%o2,_0x7f800000		! (4_1) ax ? 0x7f800000
	bge,pn	%icc,.update12		! (4_1) if( ax >= 0x7f800000 )
	fsubd	%f40,%f46,%f44		! (2_1) xx0 = (db0 - hi0);
.cont12:
	fmuld	%f56,%f42,%f52		! (0_1) res0 *= xx0;
	sllx	%g5,52,%g5		! (3_1) lexp0 = (long long)iexp0 << 52;
	ldd	[%i2],%f40		! (2_1) dtmp0 = ((double*)((char*)TBL + si0))[0];
	fdtos	%f32,%f15		! (2_2) fres0 = (float)res0;

	fmuld	%f50,%f54,%f42		! (4_2) res0 = dtmp0 * res0;
	sra	%o1,11,%l0		! (3_1) ax >>= 11;
	stx	%g5,[%fp+tmp1]		! (3_1) dtmp1 = *((double*)&lexp0);
	for	%f58,DC1,%f48		! (3_1) db0 = vis_for(db0,DC1);

	cmp	%o2,_0x00800000		! (4_1) ax ? 0x00800000
	bl,pn	%icc,.update13		! (4_1) if( ax < 0x00800000 )
	ldd	[%fp+tmp2],%f56		! (4_2) dtmp1 = *((double*)&lexp0);
	fstod	%f13,%f50		! (4_1) db0 = (double)x0;
.cont13:
	fmuld	%f44,%f40,%f46		! (2_1) xx0 *= dtmp0;
	and	%l0,_0x1ff0,%i0		! (3_1) si0 = ax & 0x1ff0;
	lda	[%i1+stridex]0x82,%l1	! (0_0) ax = *(int*)px;
	faddd	%f60,K1,%f32		! (1_1) res0 += K1;

	add	%i0,TBL,%l0		! (3_1) (char*)TBL + si0
	add	%i3,stridey,%o3		! py += stridey
	st	%f15,[%i3]		! (2_2) *py = fres0;
	fand	%f48,DC2,%f62		! (3_1) hi0 = vis_fand(db0,DC2);

	fmuld	%f42,%f56,%f44		! (4_2) res0 *= dtmp1;
	sra	%o2,24,%o7		! (4_1) iexp0 = ax >> 24;
	ldd	[%i5+8],%f58		! (0_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f52,DC1,%f34		! (0_1) res0 += DC1;

	add	%i1,stridex,%o4		! px += stridex
	add	%o7,960,%o7		! (4_1) iexp0 += 0x3c0;
	lda	[%i1+stridex]0x82,%f17	! (0_0) x0 = *px;
	fand	%f50,DC0,%f54		! (4_1) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f46,%f52		! (2_1) res0 = K2 * xx0;
	cmp	%l1,_0x7f800000		! (0_0) ax ? 0x7f800000
	bge,pn	%icc,.update14		! (0_0) if( ax >= 0x7f800000 )
	fsubd	%f48,%f62,%f42		! (3_1) xx0 = (db0 - hi0);
.cont14:
	fmuld	%f32,%f30,%f48		! (1_1) res0 *= xx0;
	sllx	%o7,52,%o1		! (4_1) lexp0 = (long long)iexp0 << 52;
	ldd	[%i0+TBL],%f40		! (3_1) dtmp0 = ((double*)((char*)TBL + si0))[0];
	fdtos	%f28,%f19		! (3_2) fres0 = (float)res0;

	fmuld	%f58,%f34,%f32		! (0_1) res0 = dtmp0 * res0;
	sra	%o2,11,%i5		! (4_1) ax >>= 11;
	stx	%o1,[%fp+tmp2]		! (4_1) dtmp1 = *((double*)&lexp0);
	for	%f54,DC1,%f34		! (4_1) db0 = vis_for(db0,DC1);

	cmp	%l1,_0x00800000		! (0_0) ax ? 0x00800000
	bl,pn	%icc,.update15		! (0_0) if( ax < 0x00800000 )
	ldd	[%fp+tmp3],%f60		! (0_1) dtmp1 = *((double*)&lexp0);
	fstod	%f17,%f56		! (0_0) db0 = (double)x0;
.cont15:
	fmuld	%f42,%f40,%f42		! (3_1) xx0 *= dtmp0;
	add	%o3,stridey,%g5		! py += stridey
	lda	[stridex+%o4]0x82,%i0	! (1_0) ax = *(int*)px;
	faddd	%f52,K1,%f52		! (2_1) res0 += K1;

	sra	%l1,24,%g1		! (0_0) iexp0 = ax >> 24;
	and	%i5,_0x1ff0,%i5		! (4_1) si0 = ax & 0x1ff0;
	st	%f19,[%o3]		! (3_2) *py = fres0;
	fand	%f34,DC2,%f62		! (4_1) hi0 = vis_fand(db0,DC2);

	fmuld	%f32,%f60,%f40		! (0_1) res0 *= dtmp1;
	add	%o4,stridex,%i1		! px += stridex
	ldd	[%i4+8],%f60		! (1_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f48,DC1,%f58		! (1_1) res0 += DC1;

	add	%g1,960,%o5		! (0_0) iexp0 += 0x3c0;
	add	%i5,TBL,%i3		! (4_1) (char*)TBL + si0
	lda	[stridex+%o4]0x82,%f21	! (1_0) x0 = *px;
	fand	%f56,DC0,%f32		! (0_0) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f42,%f50		! (3_1) res0 = K2 * xx0;
	cmp	%i0,_0x7f800000		! (1_0) ax ? 0x7f800000
	bge,pn	%icc,.update16		! (1_0) if( ax >= 0x7f800000 )
	fsubd	%f34,%f62,%f54		! (4_1) xx0 = (db0 - hi0);
.cont16:
	fmuld	%f52,%f46,%f52		! (2_1) res0 *= xx0;
	sllx	%o5,52,%o7		! (0_0) lexp0 = (long long)iexp0 << 52;
	ldd	[TBL+%i5],%f62		! (4_1) dtmp0 = ((double*)((char*)TBL + si0))[0];
	fdtos	%f44,%f23		! (4_2) fres0 = (float)res0;

	fmuld	%f60,%f58,%f44		! (1_1) res0 = dtmp0 * res0;
	sra	%l1,11,%i4		! (0_0) ax >>= 11;
	stx	%o7,[%fp+tmp3]		! (0_0) dtmp1 = *((double*)&lexp0);
	for	%f32,DC1,%f48		! (0_0) db0 = vis_for(db0,DC1);

	cmp	%i0,_0x00800000		! (1_0) ax ? 0x00800000
	bl,pn	%icc,.update17		! (1_0) if( ax < 0x00800000 )
	ldd	[%fp+tmp4],%f34		! (1_1) dtmp1 = *((double*)&lexp0);
	fstod	%f21,%f56		! (1_0) db0 = (double)x0;
.cont17:
	fmuld	%f54,%f62,%f46		! (4_1) xx0 *= dtmp0;
	and	%i4,_0x1ff0,%g1		! (0_0) si0 = ax & 0x1ff0;
	lda	[%i1+stridex]0x82,%o2	! (2_0) ax = *(int*)px;
	faddd	%f50,K1,%f62		! (3_1) res0 += K1;

	add	%g1,TBL,%i5		! (0_0) (double*)((char*)TBL + si0
	add	%g5,stridey,%g5		! py += stridey
	st	%f23,[stridey+%o3]	! (4_2) *py = fres0;
	fand	%f48,DC2,%f32		! (0_0) hi0 = vis_fand(db0,DC2);

	fmuld	%f44,%f34,%f44		! (1_1) res0 *= dtmp1;
	sra	%i0,24,%o4		! (1_0) iexp0 = ax >> 24;
	ldd	[%i2+8],%f60		! (2_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f52,DC1,%f58		! (2_1) res0 += DC1;

	add	%i1,stridex,%o7		! px += stridex
	add	%o4,960,%i2		! (1_0) iexp0 += 0x3c0;
	lda	[%i1+stridex]0x82,%f25	! (2_0) x0 = *px;
	fand	%f56,DC0,%f34		! (1_0) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f46,%f50		! (4_1) res0 = K2 * xx0;
	cmp	%o2,_0x7f800000		! (2_0) ax ? 0x7f800000
	bge,pn	%icc,.update18		! (2_0) if( ax >= 0x7f800000 )
	fsubd	%f48,%f32,%f52		! (0_0) xx0 = (db0 - hi0);
.cont18:
	fmuld	%f62,%f42,%f54		! (3_1) res0 *= xx0;
	sllx	%i2,52,%o4		! (1_0) lexp0 = (long long)iexp0 << 52;
	ldd	[TBL+%g1],%f32		! (0_0) dtmp0 = ((double*)((char*)TBL + si0))[0];
	fdtos	%f40,%f27		! (0_1) fres0 = (float)res0;

	fmuld	%f60,%f58,%f60		! (2_1) res0 = dtmp0 * res0;
	sra	%i0,11,%g1		! (1_0) ax >>= 11;
	stx	%o4,[%fp+tmp4]		! (1_0) dtmp1 = *((double*)&lexp0);
	for	%f34,DC1,%f48		! (1_0) db0 = vis_for(db0,DC1);

	cmp	%o2,_0x00800000		! (2_0) ax ? 0x00800000
	bl,pn	%icc,.update19		! (2_0) if( ax < 0x00800000 )
	ldd	[%fp+tmp0],%f40		! (2_1) dtmp1 = *((double*)&lexp0);
	fstod	%f25,%f56		! (2_0) db0 = (double)x0;
.cont19:
	fmuld	%f52,%f32,%f42		! (0_0) xx0 *= dtmp0;
	and	%g1,_0x1ff0,%o5		! (1_0) si0 = ax & 0x1ff0;
	lda	[stridex+%o7]0x82,%o1	! (3_0) ax = *(int*)px;
	faddd	%f50,K1,%f34		! (4_1) res0 += K1;

	add	%o5,TBL,%i4		! (1_0) (char*)TBL + si0
	add	%g5,stridey,%g1		! py += stridey
	st	%f27,[%g5]		! (0_1) *py = fres0;
	fand	%f48,DC2,%f62		! (1_0) hi0 = vis_fand(db0,DC2);

	fmuld	%f60,%f40,%f32		! (2_1) res0 *= dtmp1;
	sra	%o2,24,%l1		! (2_0) iexp0 = ax >> 24;
	ldd	[%l0+8],%f40		! (3_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f54,DC1,%f58		! (3_1) res0 += DC1;

	add	%o7,stridex,%i1		! px += stridex
	add	%l1,960,%l0		! (2_0) iexp0 += 0x3c0;
	lda	[stridex+%o7]0x82,%f0	! (3_0) x0 = *px;
	fand	%f56,DC0,%f60		! (2_0) db0 = vis_fand(db0,DC0);

	fmuld	K2,%f42,%f50		! (0_0) res0 = K2 * xx0;
	cmp	%o1,_0x7f800000		! (3_0) ax ? 0x7f800000
	bge,pn	%icc,.update20		! (3_0) if( ax >= 0x7f800000 )
	fsubd	%f48,%f62,%f54		! (1_0) xx0 = (db0 - hi0);
.cont20:
	fmuld	%f34,%f46,%f52		! (4_1) res0 *= xx0;
	sllx	%l0,52,%o3		! (2_0) lexp0 = (long long)iexp0 << 52;
	ldd	[TBL+%o5],%f56		! (1_0) dtmp0 = ((double*)((char*)TBL + si0))[0];
	fdtos	%f44,%f8		! (1_1) fres0 = (float)res0;

	fmuld	%f40,%f58,%f34		! (3_1) res0 = dtmp0 * res0;
	sra	%o2,11,%i2		! (2_0) ax >>= 11;
	stx	%o3,[%fp+tmp0]		! (2_0) dtmp1 = *((double*)&lexp0);
	for	%f60,DC1,%f40		! (2_0) db0 = vis_for(db0,DC1);

	cmp	%o1,_0x00800000		! (3_0) ax ? 0x00800000
	bl,pn	%icc,.update21		! (3_0) if( ax < 0x00800000 )
	ldd	[%fp+tmp1],%f62		! (3_1) dtmp1 = *((double*)&lexp0);
	fstod	%f0,%f48		! (3_0) db0 = (double)x0;
.cont21:
	fmuld	%f54,%f56,%f30		! (1_0) xx0 *= dtmp0;
	and	%i2,_0x1ff0,%o3		! (2_0) si0 = ax & 0x1ff0;
	lda	[%i1+stridex]0x82,%o2	! (4_0) ax = *(int*)px;
	faddd	%f50,K1,%f56		! (0_0) res0 += K1;

	add	%i1,stridex,%i1		! px += stridex
	add	%o3,TBL,%i2		! (2_0) (char*)TBL + si0
	st	%f8,[stridey+%g5]	! (1_1) *py = fres0;
	fand	%f40,DC2,%f46		! (2_0) hi0 = vis_fand(db0,DC2);

	fmuld	%f34,%f62,%f28		! (3_1) res0 *= dtmp1;
	sra	%o1,24,%o4		! (3_0) iexp0 = ax >> 24;
	ldd	[%i3+8],%f50		! (4_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f52,DC1,%f54		! (4_1) res0 += DC1;

	add	%g1,stridey,%i3		! py += stridey
	subcc	counter,5,counter	! counter
	lda	[%i1]0x82,%f13		! (4_0) x0 = *px;
	fand	%f48,DC0,%f58		! (3_0) db0 = vis_fand(db0,DC0);

	bpos,pt	%icc,.main_loop
	add	%o4,960,%g5		! (3_0) iexp0 += 0x3c0;

	add	counter,5,counter
.tail:
	subcc	counter,1,counter
	bneg,a	.begin
	or	%g0,%i3,%g5

	fmuld	%f56,%f42,%f52		! (0_1) res0 *= xx0;
	fdtos	%f32,%f15		! (2_2) fres0 = (float)res0;

	fmuld	%f50,%f54,%f42		! (4_2) res0 = dtmp0 * res0;

	ldd	[%fp+tmp2],%f56		! (4_2) dtmp1 = *((double*)&lexp0);

	add	%i3,stridey,%o3		! py += stridey
	st	%f15,[%i3]		! (2_2) *py = fres0;

	subcc	counter,1,counter
	bneg,a	.begin
	or	%g0,%o3,%g5

	fmuld	%f42,%f56,%f44		! (4_2) res0 *= dtmp1;
	ldd	[%i5+8],%f58		! (0_1) dtmp0 = ((double*)((char*)TBL + si0))[1]
	faddd	%f52,DC1,%f34		! (0_1) res0 += DC1;

	fdtos	%f28,%f19		! (3_2) fres0 = (float)res0;

	fmuld	%f58,%f34,%f32		! (0_1) res0 = dtmp0 * res0;

	ldd	[%fp+tmp3],%f60		! (0_1) dtmp1 = *((double*)&lexp0);

	add	%o3,stridey,%g5		! py += stridey

	st	%f19,[%o3]		! (3_2) *py = fres0;

	subcc	counter,1,counter
	bneg,a	.begin
	nop

	fmuld	%f32,%f60,%f40		! (0_1) res0 *= dtmp1;

	fdtos	%f44,%f23		! (4_2) fres0 = (float)res0;

	add	%g5,stridey,%g5		! py += stridey
	st	%f23,[stridey+%o3]	! (4_2) *py = fres0;

	subcc	counter,1,counter
	bneg,a	.begin
	nop

	fdtos	%f40,%f27		! (0_1) fres0 = (float)res0;

	st	%f27,[%g5]		! (0_1) *py = fres0;

	ba	.begin
	add	%g5,stridey,%g5

	.align	16
.spec:
	fsqrts	%f25,%f25
	sub	counter,1,counter
	add	%i1,stridex,%i1
	st	%f25,[%g5]
	ba	.begin1
	add	%g5,stridey,%g5

	.align	16
.update0:
	cmp	counter,1
	ble	.cont0
	fzeros	%f0

	stx	%i1,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%o1

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont0
	or	%g0,1,counter

	.align	16
.update1:
	cmp	counter,1
	ble	.cont1
	fzeros	%f0

	stx	%i1,[%fp+tmp_px]
	clr	%o1

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont1
	or	%g0,1,counter

	.align	16
.update2:
	cmp	counter,2
	ble	.cont2
	fzeros	%f13

	stx	%i1,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%o2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont2
	or	%g0,2,counter

	.align	16
.update3:
	cmp	counter,2
	ble	.cont3
	fzeros	%f13

	stx	%i1,[%fp+tmp_px]
	clr	%o2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont3
	or	%g0,2,counter

	.align	16
.update4:
	cmp	counter,3
	ble	.cont4
	fzeros	%f17

	stx	%o4,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%l1

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont4
	or	%g0,3,counter

	.align	16
.update5:
	cmp	counter,3
	ble	.cont5
	fzeros	%f17

	stx	%o4,[%fp+tmp_px]
	clr	%l1

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont5
	or	%g0,3,counter

	.align	16
.update6:
	cmp	counter,4
	ble	.cont6
	fzeros	%f21

	stx	%i1,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%i0

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont6
	or	%g0,4,counter

	.align	16
.update7:
	cmp	counter,4
	ble	.cont7
	fzeros	%f21

	stx	%i1,[%fp+tmp_px]
	clr	%i0

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont7
	or	%g0,4,counter

	.align	16
.update8:
	cmp	counter,5
	ble	.cont8
	fzeros	%f25

	stx	%o7,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%o2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont8
	or	%g0,5,counter

	.align	16
.update9:
	cmp	counter,5
	ble	.cont9
	fzeros	%f25

	stx	%o7,[%fp+tmp_px]
	clr	%o2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont9
	or	%g0,5,counter

	.align	16
.update10:
	cmp	counter,6
	ble	.cont10
	fzeros	%f0

	stx	%i1,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%o1

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont10
	or	%g0,6,counter

	.align	16
.update11:
	cmp	counter,6
	ble	.cont11
	fzeros	%f0

	stx	%i1,[%fp+tmp_px]
	clr	%o1

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont11
	or	%g0,6,counter

	.align	16
.update12:
	cmp	counter,2
	ble	.cont12
	fzeros	%f13

	stx	%i1,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%o2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont12
	or	%g0,2,counter

	.align	16
.update13:
	cmp	counter,2
	ble	.cont13
	fzeros	%f13

	stx	%i1,[%fp+tmp_px]
	clr	%o2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont13
	or	%g0,2,counter

	.align	16
.update14:
	cmp	counter,3
	ble	.cont14
	fzeros	%f17

	stx	%o4,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%l1

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont14
	or	%g0,3,counter

	.align	16
.update15:
	cmp	counter,3
	ble	.cont15
	fzeros	%f17

	stx	%o4,[%fp+tmp_px]
	clr	%l1

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont15
	or	%g0,3,counter

	.align	16
.update16:
	cmp	counter,4
	ble	.cont16
	fzeros	%f21

	stx	%i1,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%i0

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont16
	or	%g0,4,counter

	.align	16
.update17:
	cmp	counter,4
	ble	.cont17
	fzeros	%f21

	stx	%i1,[%fp+tmp_px]
	clr	%i0

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont17
	or	%g0,4,counter

	.align	16
.update18:
	cmp	counter,5
	ble	.cont18
	fzeros	%f25

	stx	%o7,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%o2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont18
	or	%g0,5,counter

	.align	16
.update19:
	cmp	counter,5
	ble	.cont19
	fzeros	%f25

	stx	%o7,[%fp+tmp_px]
	clr	%o2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont19
	or	%g0,5,counter

	.align	16
.update20:
	cmp	counter,6
	ble	.cont20
	fzeros	%f0

	stx	%i1,[%fp+tmp_px]
	sethi	%hi(0x7f800000),%o1

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont20
	or	%g0,6,counter

	.align	16
.update21:
	cmp	counter,6
	ble	.cont21
	fzeros	%f0

	stx	%i1,[%fp+tmp_px]
	clr	%o1

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont21
	or	%g0,6,counter

.exit:
	ret
	restore
	SET_SIZE(__vsqrtf_ultra3)

