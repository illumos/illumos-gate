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

	.file	"__vrhypotf.S"

#include "libm.h"

	RO_DATA
	.align	64
.CONST_TBL:
! i = [0,63]
! TBL[2*i+0] = 1.0 / (*(double*)&(0x3ff0000000000000LL + (i << 46)));
! TBL[2*i+1] = (double)(0.5/sqrtl(2) / sqrtl(*(double*)&(0x3ff0000000000000LL + (i << 46))));
! TBL[128+2*i+0] = 1.0 / (*(double*)&(0x3ff0000000000000LL + (i << 46)));
! TBL[128+2*i+1] = (double)(0.25 / sqrtl(*(double*)&(0x3ff0000000000000LL + (i << 46))));

	.word	0x3ff00000, 0x00000000, 0x3fd6a09e, 0x667f3bcd,
	.word	0x3fef81f8, 0x1f81f820, 0x3fd673e3, 0x2ef63a03,
	.word	0x3fef07c1, 0xf07c1f08, 0x3fd6482d, 0x37a5a3d2,
	.word	0x3fee9131, 0xabf0b767, 0x3fd61d72, 0xb7978671,
	.word	0x3fee1e1e, 0x1e1e1e1e, 0x3fd5f3aa, 0x673fa911,
	.word	0x3fedae60, 0x76b981db, 0x3fd5cacb, 0x7802f342,
	.word	0x3fed41d4, 0x1d41d41d, 0x3fd5a2cd, 0x8c69d61a,
	.word	0x3fecd856, 0x89039b0b, 0x3fd57ba8, 0xb0ee01b9,
	.word	0x3fec71c7, 0x1c71c71c, 0x3fd55555, 0x55555555,
	.word	0x3fec0e07, 0x0381c0e0, 0x3fd52fcc, 0x468d6b54,
	.word	0x3febacf9, 0x14c1bad0, 0x3fd50b06, 0xa8fc6b70,
	.word	0x3feb4e81, 0xb4e81b4f, 0x3fd4e6fd, 0xf33cf032,
	.word	0x3feaf286, 0xbca1af28, 0x3fd4c3ab, 0xe93bcf74,
	.word	0x3fea98ef, 0x606a63be, 0x3fd4a10a, 0x97af7b92,
	.word	0x3fea41a4, 0x1a41a41a, 0x3fd47f14, 0x4fe17f9f,
	.word	0x3fe9ec8e, 0x951033d9, 0x3fd45dc3, 0xa3c34fa3,
	.word	0x3fe99999, 0x9999999a, 0x3fd43d13, 0x6248490f,
	.word	0x3fe948b0, 0xfcd6e9e0, 0x3fd41cfe, 0x93ff5199,
	.word	0x3fe8f9c1, 0x8f9c18fa, 0x3fd3fd80, 0x77e70577,
	.word	0x3fe8acb9, 0x0f6bf3aa, 0x3fd3de94, 0x8077db58,
	.word	0x3fe86186, 0x18618618, 0x3fd3c036, 0x50e00e03,
	.word	0x3fe81818, 0x18181818, 0x3fd3a261, 0xba6d7a37,
	.word	0x3fe7d05f, 0x417d05f4, 0x3fd38512, 0xba21f51e,
	.word	0x3fe78a4c, 0x8178a4c8, 0x3fd36845, 0x766eec92,
	.word	0x3fe745d1, 0x745d1746, 0x3fd34bf6, 0x3d156826,
	.word	0x3fe702e0, 0x5c0b8170, 0x3fd33021, 0x8127c0e0,
	.word	0x3fe6c16c, 0x16c16c17, 0x3fd314c3, 0xd92a9e91,
	.word	0x3fe68168, 0x16816817, 0x3fd2f9d9, 0xfd52fd50,
	.word	0x3fe642c8, 0x590b2164, 0x3fd2df60, 0xc5df2c9e,
	.word	0x3fe60581, 0x60581606, 0x3fd2c555, 0x2988e428,
	.word	0x3fe5c988, 0x2b931057, 0x3fd2abb4, 0x3c0eb0f4,
	.word	0x3fe58ed2, 0x308158ed, 0x3fd2927b, 0x2cd320f5,
	.word	0x3fe55555, 0x55555555, 0x3fd279a7, 0x4590331c,
	.word	0x3fe51d07, 0xeae2f815, 0x3fd26135, 0xe91daf55,
	.word	0x3fe4e5e0, 0xa72f0539, 0x3fd24924, 0x92492492,
	.word	0x3fe4afd6, 0xa052bf5b, 0x3fd23170, 0xd2be638a,
	.word	0x3fe47ae1, 0x47ae147b, 0x3fd21a18, 0x51ff630a,
	.word	0x3fe446f8, 0x6562d9fb, 0x3fd20318, 0xcc6a8f5d,
	.word	0x3fe41414, 0x14141414, 0x3fd1ec70, 0x124e98f9,
	.word	0x3fe3e22c, 0xbce4a902, 0x3fd1d61c, 0x070ae7d3,
	.word	0x3fe3b13b, 0x13b13b14, 0x3fd1c01a, 0xa03be896,
	.word	0x3fe38138, 0x13813814, 0x3fd1aa69, 0xe4f2777f,
	.word	0x3fe3521c, 0xfb2b78c1, 0x3fd19507, 0xecf5b9e9,
	.word	0x3fe323e3, 0x4a2b10bf, 0x3fd17ff2, 0xe00ec3ee,
	.word	0x3fe2f684, 0xbda12f68, 0x3fd16b28, 0xf55d72d4,
	.word	0x3fe2c9fb, 0x4d812ca0, 0x3fd156a8, 0x72b5ef62,
	.word	0x3fe29e41, 0x29e4129e, 0x3fd1426f, 0xac0654db,
	.word	0x3fe27350, 0xb8812735, 0x3fd12e7d, 0x02c40253,
	.word	0x3fe24924, 0x92492492, 0x3fd11ace, 0xe560242a,
	.word	0x3fe21fb7, 0x8121fb78, 0x3fd10763, 0xcec30b26,
	.word	0x3fe1f704, 0x7dc11f70, 0x3fd0f43a, 0x45cdedad,
	.word	0x3fe1cf06, 0xada2811d, 0x3fd0e150, 0xdce2b60c,
	.word	0x3fe1a7b9, 0x611a7b96, 0x3fd0cea6, 0x317186dc,
	.word	0x3fe18118, 0x11811812, 0x3fd0bc38, 0xeb8ba412,
	.word	0x3fe15b1e, 0x5f75270d, 0x3fd0aa07, 0xbd7b7488,
	.word	0x3fe135c8, 0x1135c811, 0x3fd09811, 0x63615499,
	.word	0x3fe11111, 0x11111111, 0x3fd08654, 0xa2d4f6db,
	.word	0x3fe0ecf5, 0x6be69c90, 0x3fd074d0, 0x4a8b1438,
	.word	0x3fe0c971, 0x4fbcda3b, 0x3fd06383, 0x31ff307a,
	.word	0x3fe0a681, 0x0a6810a7, 0x3fd0526c, 0x39213bfa,
	.word	0x3fe08421, 0x08421084, 0x3fd0418a, 0x4806de7d,
	.word	0x3fe0624d, 0xd2f1a9fc, 0x3fd030dc, 0x4ea03a72,
	.word	0x3fe04104, 0x10410410, 0x3fd02061, 0x446ffa9a,
	.word	0x3fe02040, 0x81020408, 0x3fd01018, 0x28467ee9,
	.word	0x3ff00000, 0x00000000, 0x3fd00000, 0x00000000,
	.word	0x3fef81f8, 0x1f81f820, 0x3fcfc0bd, 0x88a0f1d9,
	.word	0x3fef07c1, 0xf07c1f08, 0x3fcf82ec, 0x882c0f9b,
	.word	0x3fee9131, 0xabf0b767, 0x3fcf467f, 0x2814b0cc,
	.word	0x3fee1e1e, 0x1e1e1e1e, 0x3fcf0b68, 0x48d2af1c,
	.word	0x3fedae60, 0x76b981db, 0x3fced19b, 0x75e78957,
	.word	0x3fed41d4, 0x1d41d41d, 0x3fce990c, 0xdad55ed2,
	.word	0x3fecd856, 0x89039b0b, 0x3fce61b1, 0x38f18adc,
	.word	0x3fec71c7, 0x1c71c71c, 0x3fce2b7d, 0xddfefa66,
	.word	0x3fec0e07, 0x0381c0e0, 0x3fcdf668, 0x9b7e6350,
	.word	0x3febacf9, 0x14c1bad0, 0x3fcdc267, 0xbea45549,
	.word	0x3feb4e81, 0xb4e81b4f, 0x3fcd8f72, 0x08e6b82d,
	.word	0x3feaf286, 0xbca1af28, 0x3fcd5d7e, 0xa914b937,
	.word	0x3fea98ef, 0x606a63be, 0x3fcd2c85, 0x34ed6d86,
	.word	0x3fea41a4, 0x1a41a41a, 0x3fccfc7d, 0xa32a9213,
	.word	0x3fe9ec8e, 0x951033d9, 0x3fcccd60, 0x45f5d358,
	.word	0x3fe99999, 0x9999999a, 0x3fcc9f25, 0xc5bfedd9,
	.word	0x3fe948b0, 0xfcd6e9e0, 0x3fcc71c7, 0x1c71c71c,
	.word	0x3fe8f9c1, 0x8f9c18fa, 0x3fcc453d, 0x90f057a2,
	.word	0x3fe8acb9, 0x0f6bf3aa, 0x3fcc1982, 0xb2ece47b,
	.word	0x3fe86186, 0x18618618, 0x3fcbee90, 0x56fb9c39,
	.word	0x3fe81818, 0x18181818, 0x3fcbc460, 0x92eb3118,
	.word	0x3fe7d05f, 0x417d05f4, 0x3fcb9aed, 0xba588347,
	.word	0x3fe78a4c, 0x8178a4c8, 0x3fcb7232, 0x5b79db11,
	.word	0x3fe745d1, 0x745d1746, 0x3fcb4a29, 0x3c1d9550,
	.word	0x3fe702e0, 0x5c0b8170, 0x3fcb22cd, 0x56d87d7e,
	.word	0x3fe6c16c, 0x16c16c17, 0x3fcafc19, 0xd8606169,
	.word	0x3fe68168, 0x16816817, 0x3fcad60a, 0x1d0fb394,
	.word	0x3fe642c8, 0x590b2164, 0x3fcab099, 0xae8f539a,
	.word	0x3fe60581, 0x60581606, 0x3fca8bc4, 0x41a3d02c,
	.word	0x3fe5c988, 0x2b931057, 0x3fca6785, 0xb41bacf7,
	.word	0x3fe58ed2, 0x308158ed, 0x3fca43da, 0x0adc6899,
	.word	0x3fe55555, 0x55555555, 0x3fca20bd, 0x700c2c3e,
	.word	0x3fe51d07, 0xeae2f815, 0x3fc9fe2c, 0x315637ee,
	.word	0x3fe4e5e0, 0xa72f0539, 0x3fc9dc22, 0xbe484458,
	.word	0x3fe4afd6, 0xa052bf5b, 0x3fc9ba9d, 0xa6c73588,
	.word	0x3fe47ae1, 0x47ae147b, 0x3fc99999, 0x9999999a,
	.word	0x3fe446f8, 0x6562d9fb, 0x3fc97913, 0x63068b54,
	.word	0x3fe41414, 0x14141414, 0x3fc95907, 0xeb87ab44,
	.word	0x3fe3e22c, 0xbce4a902, 0x3fc93974, 0x368cfa31,
	.word	0x3fe3b13b, 0x13b13b14, 0x3fc91a55, 0x6151761c,
	.word	0x3fe38138, 0x13813814, 0x3fc8fba8, 0xa1bf6f96,
	.word	0x3fe3521c, 0xfb2b78c1, 0x3fc8dd6b, 0x4563a009,
	.word	0x3fe323e3, 0x4a2b10bf, 0x3fc8bf9a, 0xb06e1af3,
	.word	0x3fe2f684, 0xbda12f68, 0x3fc8a234, 0x5cc04426,
	.word	0x3fe2c9fb, 0x4d812ca0, 0x3fc88535, 0xd90703c6,
	.word	0x3fe29e41, 0x29e4129e, 0x3fc8689c, 0xc7e07e7d,
	.word	0x3fe27350, 0xb8812735, 0x3fc84c66, 0xdf0ca4c2,
	.word	0x3fe24924, 0x92492492, 0x3fc83091, 0xe6a7f7e7,
	.word	0x3fe21fb7, 0x8121fb78, 0x3fc8151b, 0xb86fee1d,
	.word	0x3fe1f704, 0x7dc11f70, 0x3fc7fa02, 0x3f1068d1,
	.word	0x3fe1cf06, 0xada2811d, 0x3fc7df43, 0x7579b9b5,
	.word	0x3fe1a7b9, 0x611a7b96, 0x3fc7c4dd, 0x663ebb88,
	.word	0x3fe18118, 0x11811812, 0x3fc7aace, 0x2afa8b72,
	.word	0x3fe15b1e, 0x5f75270d, 0x3fc79113, 0xebbd7729,
	.word	0x3fe135c8, 0x1135c811, 0x3fc777ac, 0xde80baea,
	.word	0x3fe11111, 0x11111111, 0x3fc75e97, 0x46a0b098,
	.word	0x3fe0ecf5, 0x6be69c90, 0x3fc745d1, 0x745d1746,
	.word	0x3fe0c971, 0x4fbcda3b, 0x3fc72d59, 0xc45f1fc5,
	.word	0x3fe0a681, 0x0a6810a7, 0x3fc7152e, 0x9f44f01f,
	.word	0x3fe08421, 0x08421084, 0x3fc6fd4e, 0x79325467,
	.word	0x3fe0624d, 0xd2f1a9fc, 0x3fc6e5b7, 0xd16657e1,
	.word	0x3fe04104, 0x10410410, 0x3fc6ce69, 0x31d5858d,
	.word	0x3fe02040, 0x81020408, 0x3fc6b761, 0x2ec892f6,

	.word	0x000fffff, 0xffffffff	! DC0
	.word	0x3ff00000, 0		! DC1
	.word	0x7fffc000, 0		! DC2
	.word	0x7fe00000, 0		! DA0
	.word	0x60000000, 0		! DA1
	.word	0x80808080, 0x3f800000	! SCALE , FONE = 1.0f
	.word	0x3fefffff, 0xfee7f18f	! KA0 =  9.99999997962321453275e-01
	.word	0xbfdfffff, 0xfe07e52f	! KA1 = -4.99999998166077580600e-01
	.word	0x3fd80118, 0x0ca296d9	! KA2 = 3.75066768969515586277e-01
	.word	0xbfd400fc, 0x0bbb8e78	! KA3 = -3.12560092408808548438e-01

#define _0x7f800000	%o0
#define _0x7fffffff	%o7
#define TBL		%l2

#define TBL_SHIFT	2048

#define stridex		%l3
#define stridey		%l4
#define stridez		%l5
#define counter		%i0

#define DA0		%f52
#define DA1		%f44
#define SCALE		%f6

#define DC0		%f46
#define DC1		%f8
#define FZERO		%f9
#define DC2		%f50

#define KA3		%f56
#define KA2		%f58
#define KA1		%f60
#define KA0		%f54

#define tmp_counter	STACK_BIAS-0x04
#define tmp_px		STACK_BIAS-0x20
#define tmp_py		STACK_BIAS-0x18

#define ftmp0		STACK_BIAS-0x10
#define ftmp1		STACK_BIAS-0x0c
#define ftmp2		STACK_BIAS-0x10
#define ftmp3		STACK_BIAS-0x0c
#define ftmp4		STACK_BIAS-0x08

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x20

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!  x0 = *px;
!  ax = *(int*)px;
!
!  y0 = *py;
!  ay = *(int*)py;
!
!  ax &= 0x7fffffff;
!  ay &= 0x7fffffff;
!
!  px += stridex;
!  py += stridey;
!
!  if ( ax >= 0x7f800000 || ay >= 0x7f800000 )
!  {
!    *pz = fabsf(x0) * fabsf(y0);
!    if( ax == 0x7f800000 ) *pz = 0.0f;
!    else if( ay == 0x7f800000 ) *pz = 0.0f;
!    pz += stridez;
!    continue;
!  }
!
!  if ( ay == 0 )
!  {
!    if ( ax == 0 )
!    {
!      *pz = 1.0f / 0.0f;
!      pz += stridez;
!      continue;
!    }
!  }
!
!  hyp0 = x0 * (double)x0;
!  dtmp0 = y0 * (double)y0;
!  hyp0 += dtmp0;
!
!  ibase0 = ((int*)&hyp0)[0];
!
!  dbase0 = vis_fand(hyp0,DA0);
!  dbase0 = vis_fmul8x16(SCALE, dbase0);
!  dbase0 = vis_fpsub32(DA1,dbase0);
!
!  hyp0 = vis_fand(hyp0,DC0);
!  hyp0 = vis_for(hyp0,DC1);
!  h_hi0 = vis_fand(hyp0,DC2);
!
!  ibase0 >>= 10;
!  si0 = ibase0 & 0x7f0;
!  xx0 = ((double*)((char*)TBL + si0))[0];
!
!  dtmp1 = hyp0 - h_hi0;
!  xx0 = dtmp1 * xx0;
!  res0 = ((double*)((char*)arr + si0))[1];
!  dtmp2 = KA3 * xx0;
!  dtmp2 += KA2;
!  dtmp2 *= xx0;
!  dtmp2 += KA1;
!  dtmp2 *= xx0;
!  dtmp2 += KA0;
!  res0 *= dtmp2;
!  res0 *= dbase0;
!  ftmp0 = (float)res0;
!  *pz = ftmp0;
!  pz += stridez;
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vrhypotf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,l2)
	wr	%g0,0x82,%asi

#ifdef __sparcv9
	ldx	[%fp+STACK_BIAS+176],stridez
#else
	ld	[%fp+STACK_BIAS+92],stridez
#endif

	stx	%i1,[%fp+tmp_px]
	sll	%i2,2,stridex

	stx	%i3,[%fp+tmp_py]
	sll	%i4,2,stridey

	st	%i0,[%fp+tmp_counter]
	sll	stridez,2,stridez
	mov	%i5,%o1

	ldd	[TBL+TBL_SHIFT],DC0
	ldd	[TBL+TBL_SHIFT+8],DC1
	ldd	[TBL+TBL_SHIFT+16],DC2
	ldd	[TBL+TBL_SHIFT+24],DA0
	ldd	[TBL+TBL_SHIFT+32],DA1
	ldd	[TBL+TBL_SHIFT+40],SCALE
	ldd	[TBL+TBL_SHIFT+48],KA0

	ldd	[TBL+TBL_SHIFT+56],KA1
	sethi	%hi(0x7f800000),%o0

	ldd	[TBL+TBL_SHIFT+64],KA2
	sethi	%hi(0x7ffffc00),%o7

	ldd	[TBL+TBL_SHIFT+72],KA3
	add	%o7,1023,%o7

.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%o4
	ldx	[%fp+tmp_py],%i2
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit
	nop

	lda	[%i2]0x82,%l6		! (3_0) ay = *(int*)py;

	lda	[%o4]0x82,%i5		! (3_0) ax = *(int*)px;

	lda	[%i2]0x82,%f2		! (3_0) y0 = *py;
	and	%l6,_0x7fffffff,%l6	! (3_0) ay &= 0x7fffffff;

	and	%i5,_0x7fffffff,%i5	! (3_0) ax &= 0x7fffffff;
	cmp	%l6,_0x7f800000		! (3_0) ay ? 0x7f800000
	bge,pn	%icc,.spec0		! (3_0) if ( ay >= 0x7f800000 )
	lda	[%o4]0x82,%f4		! (3_0) x0 = *px;

	cmp	%i5,_0x7f800000		! (3_0) ax ? 0x7f800000
	bge,pn	%icc,.spec0		! (3_0) if ( ax >= 0x7f800000 )
	nop

	cmp	%l6,0			! (3_0)
	be,pn	%icc,.spec1		! (3_0) if ( ay == 0 )
	fsmuld	%f4,%f4,%f36		! (3_0) hyp0 = x0 * (double)x0;
.cont_spec1:
	lda	[%i2+stridey]0x82,%l6	! (4_0) ay = *(int*)py;

	fsmuld	%f2,%f2,%f62		! (3_0) dtmp0 = y0 * (double)y0;
	lda	[stridex+%o4]0x82,%i5	! (4_0) ax = *(int*)px;

	add	%o4,stridex,%l0		! px += stridex

	add	%i2,stridey,%i2		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (4_0) ay &= 0x7fffffff;

	and	%i5,_0x7fffffff,%i5	! (4_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (4_0) y0 = *py;

	faddd	%f36,%f62,%f20		! (3_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (4_0) ay ? 0x7f800000

	bge,pn	%icc,.update0		! (4_0) if ( ay >= 0x7f800000 )
	lda	[stridex+%o4]0x82,%f4	! (4_0) x0 = *px;
.cont0:
	cmp	%i5,_0x7f800000		! (4_0) ax ? 0x7f800000
	bge,pn	%icc,.update1		! (4_0) if ( ax >= 0x7f800000 )
	st	%f20,[%fp+ftmp4]	! (3_0) ibase0 = ((int*)&hyp0)[0];
.cont1:
	cmp	%l6,0			! (4_1) ay ? 0
	be,pn	%icc,.update2		! (4_1) if ( ay == 0 )
	fsmuld	%f4,%f4,%f38		! (4_1) hyp0 = x0 * (double)x0;
.cont2:
	lda	[%i2+stridey]0x82,%l6	! (0_0) ay = *(int*)py;

	fsmuld	%f2,%f2,%f62		! (4_1) dtmp0 = y0 * (double)y0;
	lda	[%l0+stridex]0x82,%i5	! (0_0) ax = *(int*)px;

	add	%l0,stridex,%i1		! px += stridex

	add	%i2,stridey,%i2		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (0_0) ay &= 0x7fffffff;

	and	%i5,_0x7fffffff,%i5	! (0_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (0_0) y0 = *py;

	cmp	%l6,_0x7f800000		! (0_0) ay ? 0x7f800000
	bge,pn	%icc,.update3		! (0_0) if ( ay >= 0x7f800000 )
	faddd	%f38,%f62,%f12		! (4_1) hyp0 += dtmp0;
.cont3:
	lda	[%i1]0x82,%f4		! (0_0) x0 = *px;

	cmp	%i5,_0x7f800000		! (0_0) ax ? 0x7f800000
	bge,pn	%icc,.update4		! (0_0) if ( ax >= 0x7f800000 )
	st	%f12,[%fp+ftmp0]	! (4_1) ibase0 = ((int*)&hyp0)[0];
.cont4:
	cmp	%l6,0			! (0_0) ay ? 0
	be,pn	%icc,.update5		! (0_0) if ( ay == 0 )
	fsmuld	%f4,%f4,%f38		! (0_0) hyp0 = x0 * (double)x0;
.cont5:
	lda	[%i2+stridey]0x82,%l6	! (1_0) ay = *(int*)py;

	fsmuld	%f2,%f2,%f62		! (0_0) dtmp0 = y0 * (double)y0;
	lda	[%i1+stridex]0x82,%i5	! (1_0) ax = *(int*)px;

	add	%i1,stridex,%g5		! px += stridex

	add	%i2,stridey,%o3		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (1_0) ay &= 0x7fffffff;
	fand	%f20,DC0,%f30		! (3_1) hyp0 = vis_fand(hyp0,DC0);

	and	%i5,_0x7fffffff,%i5	! (1_0) ax &= 0x7fffffff;
	lda	[%o3]0x82,%f2		! (1_0) y0 = *py;

	faddd	%f38,%f62,%f14		! (0_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (1_0) ay ? 0x7f800000

	lda	[%g5]0x82,%f4		! (1_0) x0 = *px;
	bge,pn	%icc,.update6		! (1_0) if ( ay >= 0x7f800000 )
	for	%f30,DC1,%f28		! (3_1) hyp0 = vis_for(hyp0,DC1);
.cont6:
	cmp	%i5,_0x7f800000		! (1_0) ax ? 0x7f800000
	bge,pn	%icc,.update7		! (1_0) if ( ax >= 0x7f800000 )
	ld	[%fp+ftmp4],%l1		! (3_1) ibase0 = ((int*)&hyp0)[0];
.cont7:
	st	%f14,[%fp+ftmp1]	! (0_0) ibase0 = ((int*)&hyp0)[0];

	cmp	%l6,0			! (1_0) ay ? 0
	be,pn	%icc,.update8		! (1_0) if ( ay == 0 )
	fand	%f28,DC2,%f30		! (3_1) h_hi0 = vis_fand(hyp0,DC2);
.cont8:
	fsmuld	%f4,%f4,%f38		! (1_0) hyp0 = x0 * (double)x0;
	sra	%l1,10,%o5		! (3_1) ibase0 >>= 10;

	and	%o5,2032,%o4		! (3_1) si0 = ibase0 & 0x7f0;
	lda	[%o3+stridey]0x82,%l6	! (2_0) ay = *(int*)py;

	fsmuld	%f2,%f2,%f62		! (1_0) dtmp0 = y0 * (double)y0;
	add	%o4,TBL,%l7		! (3_1) (char*)TBL + si0
	lda	[stridex+%g5]0x82,%i5	! (2_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (3_1) dtmp1 = hyp0 - h_hi0;

	add	%g5,stridex,%i4		! px += stridex
	ldd	[TBL+%o4],%f42		! (3_1) xx0 = ((double*)((char*)TBL + si0))[0];

	and	%l6,_0x7fffffff,%l6	! (2_0) ay &= 0x7fffffff;
	add	%o3,stridey,%i2		! py += stridey
	fand	%f12,DC0,%f30		! (4_1) hyp0 = vis_fand(hyp0,DC0);

	and	%i5,_0x7fffffff,%i5	! (2_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (2_0) y0 = *py;

	faddd	%f38,%f62,%f16		! (1_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (2_0) ay ? 0x7f800000
	fmuld	%f28,%f42,%f26		! (3_1) xx0 = dtmp1 * xx0;

	lda	[stridex+%g5]0x82,%f4	! (2_0) x0 = *px;
	bge,pn	%icc,.update9		! (2_0) if ( ay >= 0x7f800000
	for	%f30,DC1,%f28		! (4_1) hyp0 = vis_for(hyp0,DC1);
.cont9:
	cmp	%i5,_0x7f800000		! (2_0) ax ? 0x7f800000
	bge,pn	%icc,.update10		! (2_0) if ( ax >= 0x7f800000 )
	ld	[%fp+ftmp0],%i3		! (4_1) ibase0 = ((int*)&hyp0)[0];
.cont10:
	st	%f16,[%fp+ftmp2]	! (1_0) ibase0 = ((int*)&hyp0)[0];

	fmuld	KA3,%f26,%f34		! (3_1) dtmp2 = KA3 * xx0;
	cmp	%l6,0			! (2_0) ay ? 0
	be,pn	%icc,.update11		! (2_0) if ( ay == 0 )
	fand	%f28,DC2,%f30		! (4_1) h_hi0 = vis_fand(hyp0,DC2);
.cont11:
	fsmuld	%f4,%f4,%f36		! (2_0) hyp0 = x0 * (double)x0;
	sra	%i3,10,%i3		! (4_1) ibase0 >>= 10;

	and	%i3,2032,%i3		! (4_1) si0 = ibase0 & 0x7f0;
	lda	[%i2+stridey]0x82,%l6	! (3_0) ay = *(int*)py;

	fsmuld	%f2,%f2,%f62		! (2_0) dtmp0 = y0 * (double)y0;
	add	%i3,TBL,%i3		! (4_1) (char*)TBL + si0
	lda	[%i4+stridex]0x82,%i5	! (3_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (4_1) dtmp1 = hyp0 - h_hi0;

	add	%i4,stridex,%o4		! px += stridex
	ldd	[%i3],%f42		! (4_1) xx0 = ((double*)((char*)TBL + si0))[0];
	faddd	%f34,KA2,%f10		! (3_1) dtmp2 += KA2;

	add	%i2,stridey,%i2		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (3_0) ay &= 0x7fffffff;
	fand	%f14,DC0,%f30		! (0_0) hyp0 = vis_fand(hyp0,DC0);

	and	%i5,_0x7fffffff,%i5	! (3_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (3_0) y0 = *py;

	faddd	%f36,%f62,%f18		! (2_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (3_0) ay ? 0x7f800000
	fmuld	%f28,%f42,%f32		! (4_1) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f26,%f10		! (3_1) dtmp2 *= xx0;
	lda	[%o4]0x82,%f4		! (3_0) x0 = *px;
	bge,pn	%icc,.update12		! (3_0) if ( ay >= 0x7f800000 )
	for	%f30,DC1,%f28		! (0_0) hyp0 = vis_for(hyp0,DC1);
.cont12:
	cmp	%i5,_0x7f800000		! (3_0) ax ? 0x7f800000
	bge,pn	%icc,.update13		! (3_0) if ( ax >= 0x7f800000 )
	ld	[%fp+ftmp1],%i1		! (0_0) ibase0 = ((int*)&hyp0)[0];
.cont13:
	st	%f18,[%fp+ftmp3]	! (2_0) ibase0 = ((int*)&hyp0)[0];

	fmuld	KA3,%f32,%f34		! (4_1) dtmp2 = KA3 * xx0;
	cmp	%l6,0			! (3_0)
	be,pn	%icc,.update14		! (3_0) if ( ay == 0 )
	fand	%f28,DC2,%f30		! (0_0) h_hi0 = vis_fand(hyp0,DC2);
.cont14:
	fsmuld	%f4,%f4,%f36		! (3_0) hyp0 = x0 * (double)x0;
	sra	%i1,10,%l1		! (0_0) ibase0 >>= 10;
	faddd	%f10,KA1,%f40		! (3_1) dtmp2 += KA1;

	and	%l1,2032,%o5		! (0_0) si0 = ibase0 & 0x7f0;
	lda	[%i2+stridey]0x82,%l6	! (4_0) ay = *(int*)py;

	fsmuld	%f2,%f2,%f62		! (3_0) dtmp0 = y0 * (double)y0;
	add	%o5,TBL,%l1		! (0_0) (char*)TBL + si0
	lda	[stridex+%o4]0x82,%i5	! (4_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (0_0) dtmp1 = hyp0 - h_hi0;

	add	%o4,stridex,%l0		! px += stridex
	ldd	[TBL+%o5],%f42		! (0_0) xx0 = ((double*)((char*)TBL + si0))[0];
	faddd	%f34,KA2,%f10		! (4_1) dtmp2 += KA2;

	fmuld	%f40,%f26,%f40		! (3_1) dtmp2 *= xx0;
	add	%i2,stridey,%i2		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (4_0) ay &= 0x7fffffff;
	fand	%f16,DC0,%f30		! (1_0) hyp0 = vis_fand(hyp0,DC0);

	and	%i5,_0x7fffffff,%i5	! (4_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (4_0) y0 = *py;
	fand	%f20,DA0,%f24		! (3_1) dbase0 = vis_fand(hyp0,DA0);

	faddd	%f36,%f62,%f20		! (3_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (4_0) ay ? 0x7f800000
	ldd	[%l7+8],%f36		! (3_1) res0 = ((double*)((char*)arr + si0))[1];
	fmuld	%f28,%f42,%f26		! (0_0) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f32,%f10		! (4_1) dtmp2 *= xx0;
	lda	[stridex+%o4]0x82,%f4	! (4_0) x0 = *px;
	bge,pn	%icc,.update15		! (4_0) if ( ay >= 0x7f800000 )
	for	%f30,DC1,%f28		! (1_0) hyp0 = vis_for(hyp0,DC1);
.cont15:
	fmul8x16	SCALE,%f24,%f24	! (3_1) dbase0 = vis_fmul8x16(SCALE, dbase0);
	cmp	%i5,_0x7f800000		! (4_0) ax ? 0x7f800000
	ld	[%fp+ftmp2],%i1		! (1_0) ibase0 = ((int*)&hyp0)[0];
	faddd	%f40,KA0,%f62		! (3_1) dtmp2 += KA0;

	bge,pn	%icc,.update16		! (4_0) if ( ax >= 0x7f800000 )
	st	%f20,[%fp+ftmp4]	! (3_0) ibase0 = ((int*)&hyp0)[0];
.cont16:
	fmuld	KA3,%f26,%f34		! (0_0) dtmp2 = KA3 * xx0;
	fand	%f28,DC2,%f30		! (1_0) h_hi0 = vis_fand(hyp0,DC2);

	mov	%o1,%i4
	cmp	counter,5
	bl,pn	%icc,.tail
	nop

	ba	.main_loop
	sub	counter,5,counter

	.align	16
.main_loop:
	fsmuld	%f4,%f4,%f38		! (4_1) hyp0 = x0 * (double)x0;
	sra	%i1,10,%o2		! (1_1) ibase0 >>= 10;
	cmp	%l6,0			! (4_1) ay ? 0
	faddd	%f10,KA1,%f40		! (4_2) dtmp2 += KA1;

	fmuld	%f36,%f62,%f36		! (3_2) res0 *= dtmp2;
	and	%o2,2032,%o2		! (1_1) si0 = ibase0 & 0x7f0;
	lda	[%i2+stridey]0x82,%l6	! (0_0) ay = *(int*)py;
	fpsub32	DA1,%f24,%f24		! (3_2) dbase0 = vis_fpsub32(DA1,dbase0);

	fsmuld	%f2,%f2,%f62		! (4_1) dtmp0 = y0 * (double)y0;
	add	%o2,TBL,%o2		! (1_1) (char*)TBL + si0
	lda	[%l0+stridex]0x82,%o1	! (0_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (1_1) dtmp1 = hyp0 - h_hi0;

	add	%l0,stridex,%i1		! px += stridex
	ldd	[%o2],%f42		! (1_1) xx0 = ((double*)((char*)TBL + si0))[0];
	be,pn	%icc,.update17		! (4_1) if ( ay == 0 )
	faddd	%f34,KA2,%f10		! (0_1) dtmp2 += KA2;
.cont17:
	fmuld	%f40,%f32,%f40		! (4_2) dtmp2 *= xx0;
	add	%i2,stridey,%i2		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (0_0) ay &= 0x7fffffff;
	fand	%f18,DC0,%f30		! (2_1) hyp0 = vis_fand(hyp0,DC0);

	fmuld	%f36,%f24,%f32		! (3_2) res0 *= dbase0;
	and	%o1,_0x7fffffff,%o1	! (0_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (0_0) y0 = *py;
	fand	%f12,DA0,%f24		! (4_2) dbase0 = vis_fand(hyp0,DA0);

	faddd	%f38,%f62,%f12		! (4_1) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (0_0) ay ? 0x7f800000
	ldd	[%i3+8],%f62		! (4_2) res0 = ((double*)((char*)arr + si0))[1];
	fmuld	%f28,%f42,%f36		! (1_1) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f26,%f10		! (0_1) dtmp2 *= xx0;
	lda	[%i1]0x82,%f4		! (0_0) x0 = *px;
	bge,pn	%icc,.update18		! (0_0) if ( ay >= 0x7f800000 )
	for	%f30,DC1,%f28		! (2_1) hyp0 = vis_for(hyp0,DC1);
.cont18:
	fmul8x16	SCALE,%f24,%f24	! (4_2) dbase0 = vis_fmul8x16(SCALE, dbase0);
	cmp	%o1,_0x7f800000		! (0_0) ax ? 0x7f800000
	ld	[%fp+ftmp3],%l0		! (2_1) ibase0 = ((int*)&hyp0)[0];
	faddd	%f40,KA0,%f42		! (4_2) dtmp2 += KA0;

	add	%i4,stridez,%i3		! pz += stridez
	st	%f12,[%fp+ftmp0]	! (4_1) ibase0 = ((int*)&hyp0)[0];
	bge,pn	%icc,.update19		! (0_0) if ( ax >= 0x7f800000 )
	fdtos	%f32,%f1		! (3_2) ftmp0 = (float)res0;
.cont19:
	fmuld	KA3,%f36,%f34		! (1_1) dtmp2 = KA3 * xx0;
	cmp	%l6,0			! (0_0) ay ? 0
	st	%f1,[%i4]		! (3_2) *pz = ftmp0;
	fand	%f28,DC2,%f30		! (2_1) h_hi0 = vis_fand(hyp0,DC2);

	fsmuld	%f4,%f4,%f38		! (0_0) hyp0 = x0 * (double)x0;
	sra	%l0,10,%i4		! (2_1) ibase0 >>= 10;
	be,pn	%icc,.update20		! (0_0) if ( ay == 0 )
	faddd	%f10,KA1,%f40		! (0_1) dtmp2 += KA1;
.cont20:
	fmuld	%f62,%f42,%f32		! (4_2) res0 *= dtmp2;
	and	%i4,2032,%g1		! (2_1) si0 = ibase0 & 0x7f0;
	lda	[%i2+stridey]0x82,%l6	! (1_0) ay = *(int*)py;
	fpsub32	DA1,%f24,%f24		! (4_2) dbase0 = vis_fpsub32(DA1,dbase0);

	fsmuld	%f2,%f2,%f62		! (0_0) dtmp0 = y0 * (double)y0;
	add	%g1,TBL,%l0		! (2_1) (char*)TBL + si0
	lda	[%i1+stridex]0x82,%i5	! (1_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (2_1) dtmp1 = hyp0 - h_hi0;

	nop
	add	%i1,stridex,%g5		! px += stridex
	ldd	[TBL+%g1],%f42		! (2_1) xx0 = ((double*)((char*)TBL + si0))[0];
	faddd	%f34,KA2,%f10		! (1_1) dtmp2 += KA2;

	fmuld	%f40,%f26,%f40		! (0_1) dtmp2 *= xx0;
	add	%i2,stridey,%o3		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (1_0) ay &= 0x7fffffff;
	fand	%f20,DC0,%f30		! (3_1) hyp0 = vis_fand(hyp0,DC0);

	fmuld	%f32,%f24,%f26		! (4_2) res0 *= dbase0;
	and	%i5,_0x7fffffff,%i5	! (1_0) ax &= 0x7fffffff;
	lda	[%o3]0x82,%f2		! (1_0) y0 = *py;
	fand	%f14,DA0,%f24		! (0_1) dbase0 = vis_fand(hyp0,DA0);

	faddd	%f38,%f62,%f14		! (0_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (1_0) ay ? 0x7f800000
	ldd	[%l1+8],%f62		! (0_1) res0 = ((double*)((char*)arr + si0))[1];
	fmuld	%f28,%f42,%f32		! (2_1) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f36,%f10		! (1_1) dtmp2 *= xx0;
	lda	[%g5]0x82,%f4		! (1_0) x0 = *px;
	bge,pn	%icc,.update21		! (1_0) if ( ay >= 0x7f800000 )
	for	%f30,DC1,%f28		! (3_1) hyp0 = vis_for(hyp0,DC1);
.cont21:
	fmul8x16	SCALE,%f24,%f24	! (0_1) dbase0 = vis_fmul8x16(SCALE, dbase0);
	cmp	%i5,_0x7f800000		! (1_0) ax ? 0x7f800000
	ld	[%fp+ftmp4],%l1		! (3_1) ibase0 = ((int*)&hyp0)[0];
	faddd	%f40,KA0,%f42		! (0_1) dtmp2 += KA0

	add	%i3,stridez,%o1		! pz += stridez
	st	%f14,[%fp+ftmp1]	! (0_0) ibase0 = ((int*)&hyp0)[0];
	bge,pn	%icc,.update22		! (1_0) if ( ax >= 0x7f800000 )
	fdtos	%f26,%f1		! (4_2) ftmp0 = (float)res0;
.cont22:
	fmuld	KA3,%f32,%f34		! (2_1) dtmp2 = KA3 * xx0;
	cmp	%l6,0			! (1_0) ay ? 0
	st	%f1,[%i3]		! (4_2) *pz = ftmp0;
	fand	%f28,DC2,%f30		! (3_1) h_hi0 = vis_fand(hyp0,DC2);

	fsmuld	%f4,%f4,%f38		! (1_0) hyp0 = x0 * (double)x0;
	sra	%l1,10,%o5		! (3_1) ibase0 >>= 10;
	be,pn	%icc,.update23		! (1_0) if ( ay == 0 )
	faddd	%f10,KA1,%f40		! (1_1) dtmp2 += KA1;
.cont23:
	fmuld	%f62,%f42,%f26		! (0_1) res0 *= dtmp2;
	and	%o5,2032,%o4		! (3_1) si0 = ibase0 & 0x7f0;
	lda	[%o3+stridey]0x82,%l6	! (2_0) ay = *(int*)py;
	fpsub32	DA1,%f24,%f24		! (0_1) dbase0 = vis_fpsub32(DA1,dbase0);

	fsmuld	%f2,%f2,%f62		! (1_0) dtmp0 = y0 * (double)y0;
	add	%o4,TBL,%l7		! (3_1) (char*)TBL + si0
	lda	[stridex+%g5]0x82,%i5	! (2_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (3_1) dtmp1 = hyp0 - h_hi0;

	nop
	add	%g5,stridex,%i4		! px += stridex
	ldd	[TBL+%o4],%f42		! (3_1) xx0 = ((double*)((char*)TBL + si0))[0];
	faddd	%f34,KA2,%f10		! (2_1) dtmp2 += KA2;

	fmuld	%f40,%f36,%f40		! (1_1) dtmp2 *= xx0;
	and	%l6,_0x7fffffff,%l6	! (2_0) ay &= 0x7fffffff;
	add	%o3,stridey,%i2		! py += stridey
	fand	%f12,DC0,%f30		! (4_1) hyp0 = vis_fand(hyp0,DC0);

	fmuld	%f26,%f24,%f36		! (0_1) res0 *= dbase0;
	and	%i5,_0x7fffffff,%i5	! (2_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (2_0) y0 = *py;
	fand	%f16,DA0,%f24		! (1_1) dbase0 = vis_fand(hyp0,DA0);

	faddd	%f38,%f62,%f16		! (1_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (2_0) ay ? 0x7f800000
	ldd	[%o2+8],%f38		! (1_1) res0 = ((double*)((char*)arr + si0))[1];
	fmuld	%f28,%f42,%f26		! (3_1) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f32,%f10		! (2_1) dtmp2 *= xx0;
	lda	[stridex+%g5]0x82,%f4	! (2_0) x0 = *px;
	bge,pn	%icc,.update24		! (2_0) if ( ay >= 0x7f800000
	for	%f30,DC1,%f28		! (4_1) hyp0 = vis_for(hyp0,DC1);
.cont24:
	fmul8x16	SCALE,%f24,%f24	! (1_1) dbase0 = vis_fmul8x16(SCALE, dbase0);
	cmp	%i5,_0x7f800000		! (2_0) ax ? 0x7f800000
	ld	[%fp+ftmp0],%i3		! (4_1) ibase0 = ((int*)&hyp0)[0];
	faddd	%f40,KA0,%f62		! (1_1) dtmp2 += KA0;

	add	%o1,stridez,%g1		! pz += stridez
	st	%f16,[%fp+ftmp2]	! (1_0) ibase0 = ((int*)&hyp0)[0];
	bge,pn	%icc,.update25		! (2_0) if ( ax >= 0x7f800000 )
	fdtos	%f36,%f1		! (0_1) ftmp0 = (float)res0;
.cont25:
	fmuld	KA3,%f26,%f34		! (3_1) dtmp2 = KA3 * xx0;
	cmp	%l6,0			! (2_0) ay ? 0
	st	%f1,[%o1]		! (0_1) *pz = ftmp0;
	fand	%f28,DC2,%f30		! (4_1) h_hi0 = vis_fand(hyp0,DC2);

	fsmuld	%f4,%f4,%f36		! (2_0) hyp0 = x0 * (double)x0;
	sra	%i3,10,%i3		! (4_1) ibase0 >>= 10;
	be,pn	%icc,.update26		! (2_0) if ( ay == 0 )
	faddd	%f10,KA1,%f40		! (2_1) dtmp2 += KA1;
.cont26:
	fmuld	%f38,%f62,%f38		! (1_1) res0 *= dtmp2;
	and	%i3,2032,%i3		! (4_1) si0 = ibase0 & 0x7f0;
	lda	[%i2+stridey]0x82,%l6	! (3_0) ay = *(int*)py;
	fpsub32	DA1,%f24,%f24		! (1_1) dbase0 = vis_fpsub32(DA1,dbase0);

	fsmuld	%f2,%f2,%f62		! (2_0) dtmp0 = y0 * (double)y0;
	add	%i3,TBL,%i3		! (4_1) (char*)TBL + si0
	lda	[%i4+stridex]0x82,%i5	! (3_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (4_1) dtmp1 = hyp0 - h_hi0;

	nop
	add	%i4,stridex,%o4		! px += stridex
	ldd	[%i3],%f42		! (4_1) xx0 = ((double*)((char*)TBL + si0))[0];
	faddd	%f34,KA2,%f10		! (3_1) dtmp2 += KA2;

	fmuld	%f40,%f32,%f40		! (2_1) dtmp2 *= xx0;
	add	%i2,stridey,%i2		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (3_0) ay &= 0x7fffffff;
	fand	%f14,DC0,%f30		! (0_0) hyp0 = vis_fand(hyp0,DC0);

	fmuld	%f38,%f24,%f38		! (1_1) res0 *= dbase0;
	and	%i5,_0x7fffffff,%i5	! (3_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (3_0) y0 = *py;
	fand	%f18,DA0,%f24		! (2_1) dbase0 = vis_fand(hyp0,DA0);

	faddd	%f36,%f62,%f18		! (2_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (3_0) ay ? 0x7f800000
	ldd	[%l0+8],%f62		! (2_1) res0 = ((double*)((char*)arr + si0))[1];
	fmuld	%f28,%f42,%f32		! (4_1) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f26,%f10		! (3_1) dtmp2 *= xx0;
	lda	[%o4]0x82,%f4		! (3_0) x0 = *px;
	bge,pn	%icc,.update27		! (3_0) if ( ay >= 0x7f800000 )
	for	%f30,DC1,%f28		! (0_0) hyp0 = vis_for(hyp0,DC1);
.cont27:
	fmul8x16	SCALE,%f24,%f24	! (2_1) dbase0 = vis_fmul8x16(SCALE, dbase0);
	cmp	%i5,_0x7f800000		! (3_0) ax ? 0x7f800000
	ld	[%fp+ftmp1],%i1		! (0_0) ibase0 = ((int*)&hyp0)[0];
	faddd	%f40,KA0,%f42		! (2_1) dtmp2 += KA0;

	add	%g1,stridez,%o3		! pz += stridez
	st	%f18,[%fp+ftmp3]	! (2_0) ibase0 = ((int*)&hyp0)[0];
	bge,pn	%icc,.update28		! (3_0) if ( ax >= 0x7f800000 )
	fdtos	%f38,%f1		! (1_1) ftmp0 = (float)res0;
.cont28:
	fmuld	KA3,%f32,%f34		! (4_1) dtmp2 = KA3 * xx0;
	cmp	%l6,0			! (3_0)
	st	%f1,[%g1]		! (1_1) *pz = ftmp0;
	fand	%f28,DC2,%f30		! (0_0) h_hi0 = vis_fand(hyp0,DC2);

	fsmuld	%f4,%f4,%f36		! (3_0) hyp0 = x0 * (double)x0;
	sra	%i1,10,%l1		! (0_0) ibase0 >>= 10;
	be,pn	%icc,.update29		! (3_0) if ( ay == 0 )
	faddd	%f10,KA1,%f40		! (3_1) dtmp2 += KA1;
.cont29:
	fmuld	%f62,%f42,%f38		! (2_1) res0 *= dtmp2;
	and	%l1,2032,%o5		! (0_0) si0 = ibase0 & 0x7f0;
	lda	[%i2+stridey]0x82,%l6	! (4_0) ay = *(int*)py;
	fpsub32	DA1,%f24,%f24		! (2_1) dbase0 = vis_fpsub32(DA1,dbase0);

	fsmuld	%f2,%f2,%f62		! (3_0) dtmp0 = y0 * (double)y0;
	add	%o5,TBL,%l1		! (0_0) (char*)TBL + si0
	lda	[stridex+%o4]0x82,%i5	! (4_0) ax = *(int*)px;
	fsubd	%f28,%f30,%f28		! (0_0) dtmp1 = hyp0 - h_hi0;

	add	%o3,stridez,%i4		! pz += stridez
	add	%o4,stridex,%l0		! px += stridex
	ldd	[TBL+%o5],%f42		! (0_0) xx0 = ((double*)((char*)TBL + si0))[0];
	faddd	%f34,KA2,%f10		! (4_1) dtmp2 += KA2;

	fmuld	%f40,%f26,%f40		! (3_1) dtmp2 *= xx0;
	add	%i2,stridey,%i2		! py += stridey
	and	%l6,_0x7fffffff,%l6	! (4_0) ay &= 0x7fffffff;
	fand	%f16,DC0,%f30		! (1_0) hyp0 = vis_fand(hyp0,DC0);

	fmuld	%f38,%f24,%f38		! (2_1) res0 *= dbase0;
	and	%i5,_0x7fffffff,%i5	! (4_0) ax &= 0x7fffffff;
	lda	[%i2]0x82,%f2		! (4_0) y0 = *py;
	fand	%f20,DA0,%f24		! (3_1) dbase0 = vis_fand(hyp0,DA0);

	faddd	%f36,%f62,%f20		! (3_0) hyp0 += dtmp0;
	cmp	%l6,_0x7f800000		! (4_0) ay ? 0x7f800000
	ldd	[%l7+8],%f36		! (3_1) res0 = ((double*)((char*)arr + si0))[1];
	fmuld	%f28,%f42,%f26		! (0_0) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f32,%f10		! (4_1) dtmp2 *= xx0;
	lda	[stridex+%o4]0x82,%f4	! (4_0) x0 = *px;
	bge,pn	%icc,.update30		! (4_0) if ( ay >= 0x7f800000 )
	for	%f30,DC1,%f28		! (1_0) hyp0 = vis_for(hyp0,DC1);
.cont30:
	fmul8x16	SCALE,%f24,%f24	! (3_1) dbase0 = vis_fmul8x16(SCALE, dbase0);
	cmp	%i5,_0x7f800000		! (4_0) ax ? 0x7f800000
	ld	[%fp+ftmp2],%i1		! (1_0) ibase0 = ((int*)&hyp0)[0];
	faddd	%f40,KA0,%f62		! (3_1) dtmp2 += KA0;

	bge,pn	%icc,.update31		! (4_0) if ( ax >= 0x7f800000 )
	st	%f20,[%fp+ftmp4]	! (3_0) ibase0 = ((int*)&hyp0)[0];
.cont31:
	subcc	counter,5,counter	! counter -= 5;
	fdtos	%f38,%f1		! (2_1) ftmp0 = (float)res0;

	fmuld	KA3,%f26,%f34		! (0_0) dtmp2 = KA3 * xx0;
	st	%f1,[%o3]		! (2_1) *pz = ftmp0;
	bpos,pt	%icc,.main_loop
	fand	%f28,DC2,%f30		! (1_0) h_hi0 = vis_fand(hyp0,DC2);

	add	counter,5,counter

.tail:
	subcc	counter,1,counter
	bneg	.begin
	mov	%i4,%o1

	sra	%i1,10,%o2		! (1_1) ibase0 >>= 10;
	faddd	%f10,KA1,%f40		! (4_2) dtmp2 += KA1;

	fmuld	%f36,%f62,%f36		! (3_2) res0 *= dtmp2;
	and	%o2,2032,%o2		! (1_1) si0 = ibase0 & 0x7f0;
	fpsub32	DA1,%f24,%f24		! (3_2) dbase0 = vis_fpsub32(DA1,dbase0);

	add	%o2,TBL,%o2		! (1_1) (char*)TBL + si0
	fsubd	%f28,%f30,%f28		! (1_1) dtmp1 = hyp0 - h_hi0;

	ldd	[%o2],%f42		! (1_1) xx0 = ((double*)((char*)TBL + si0))[0];
	faddd	%f34,KA2,%f10		! (0_1) dtmp2 += KA2;

	fmuld	%f40,%f32,%f40		! (4_2) dtmp2 *= xx0;

	fmuld	%f36,%f24,%f32		! (3_2) res0 *= dbase0;
	fand	%f12,DA0,%f24		! (4_2) dbase0 = vis_fand(hyp0,DA0);

	ldd	[%i3+8],%f62		! (4_2) res0 = ((double*)((char*)arr + si0))[1];
	fmuld	%f28,%f42,%f36		! (1_1) xx0 = dtmp1 * xx0;

	fmuld	%f10,%f26,%f10		! (0_1) dtmp2 *= xx0;

	fmul8x16	SCALE,%f24,%f24	! (4_2) dbase0 = vis_fmul8x16(SCALE, dbase0);
	faddd	%f40,KA0,%f42		! (4_2) dtmp2 += KA0;

	add	%i4,stridez,%i3		! pz += stridez
	fdtos	%f32,%f1		! (3_2) ftmp0 = (float)res0;

	fmuld	KA3,%f36,%f34		! (1_1) dtmp2 = KA3 * xx0;
	st	%f1,[%i4]		! (3_2) *pz = ftmp0;

	subcc	counter,1,counter
	bneg	.begin
	mov	%i3,%o1

	faddd	%f10,KA1,%f40		! (0_1) dtmp2 += KA1;

	fmuld	%f62,%f42,%f32		! (4_2) res0 *= dtmp2;
	fpsub32	DA1,%f24,%f24		! (4_2) dbase0 = vis_fpsub32(DA1,dbase0);


	faddd	%f34,KA2,%f10		! (1_1) dtmp2 += KA2;

	fmuld	%f40,%f26,%f40		! (0_1) dtmp2 *= xx0;

	fmuld	%f32,%f24,%f26		! (4_2) res0 *= dbase0;
	fand	%f14,DA0,%f24		! (0_1) dbase0 = vis_fand(hyp0,DA0);

	ldd	[%l1+8],%f62		! (0_1) res0 = ((double*)((char*)arr + si0))[1];

	fmuld	%f10,%f36,%f10		! (1_1) dtmp2 *= xx0;

	fmul8x16	SCALE,%f24,%f24	! (0_1) dbase0 = vis_fmul8x16(SCALE, dbase0);
	faddd	%f40,KA0,%f42		! (0_1) dtmp2 += KA0

	add	%i3,stridez,%o1		! pz += stridez
	fdtos	%f26,%f1		! (4_2) ftmp0 = (float)res0;

	st	%f1,[%i3]		! (4_2) *pz = ftmp0;

	subcc	counter,1,counter
	bneg	.begin
	nop

	faddd	%f10,KA1,%f40		! (1_1) dtmp2 += KA1;

	fmuld	%f62,%f42,%f26		! (0_1) res0 *= dtmp2;
	fpsub32	DA1,%f24,%f24		! (0_1) dbase0 = vis_fpsub32(DA1,dbase0);

	fmuld	%f40,%f36,%f40		! (1_1) dtmp2 *= xx0;

	fmuld	%f26,%f24,%f36		! (0_1) res0 *= dbase0;
	fand	%f16,DA0,%f24		! (1_1) dbase0 = vis_fand(hyp0,DA0);

	ldd	[%o2+8],%f38		! (1_1) res0 = ((double*)((char*)arr + si0))[1];

	fmul8x16	SCALE,%f24,%f24	! (1_1) dbase0 = vis_fmul8x16(SCALE, dbase0);
	faddd	%f40,KA0,%f62		! (1_1) dtmp2 += KA0;

	add	%o1,stridez,%g1		! pz += stridez
	fdtos	%f36,%f1		! (0_1) ftmp0 = (float)res0;

	st	%f1,[%o1]		! (0_1) *pz = ftmp0;

	subcc	counter,1,counter
	bneg	.begin
	mov	%g1,%o1

	fmuld	%f38,%f62,%f38		! (1_1) res0 *= dtmp2;
	fpsub32	DA1,%f24,%f24		! (1_1) dbase0 = vis_fpsub32(DA1,dbase0);

	fmuld	%f38,%f24,%f38		! (1_1) res0 *= dbase0;

	fdtos	%f38,%f1		! (1_1) ftmp0 = (float)res0;
	st	%f1,[%g1]		! (1_1) *pz = ftmp0;

	ba	.begin
	add	%g1,stridez,%o1		! pz += stridez

	.align	16
.spec0:
	fabss	%f2,%f2			! fabsf(y0);

	fabss	%f4,%f4			! fabsf(x0);

	fcmps	%f2,%f4

	cmp	%l6,_0x7f800000		! ay ? 0x7f800000
	be,a	1f			! if( ay == 0x7f800000 )
	st	%g0,[%o1]		! *pz = 0.0f;

	cmp	%i5,_0x7f800000		! ax ? 0x7f800000
	be,a	1f			! if( ax == 0x7f800000 )
	st	%g0,[%o1]		! *pz = 0.0f;

	fmuls	%f2,%f4,%f2		! fabsf(x0) * fabsf(y0);
	st	%f2,[%o1]		! *pz = fabsf(x0) + fabsf(y0);
1:
	add	%o4,stridex,%o4		! px += stridex;
	add	%i2,stridey,%i2		! py += stridey;

	add	%o1,stridez,%o1		! pz += stridez;
	ba	.begin1
	sub	counter,1,counter	! counter--;

	.align	16
.spec1:
	cmp	%i5,0			! ax ? 0
	bne,pt	%icc,.cont_spec1	! if ( ax != 0 )
	nop

	add	%o4,stridex,%o4		! px += stridex;
	add	%i2,stridey,%i2		! py += stridey;

	fdivs	%f7,%f9,%f2		! 1.0f / 0.0f
	st	%f2,[%o1]		! *pz = 1.0f / 0.0f;

	add	%o1,stridez,%o1		! pz += stridez;
	ba	.begin1
	sub	counter,1,counter	! counter--;

	.align	16
.update0:
	cmp	counter,1
	ble	.cont0
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont0
	mov	1,counter

	.align	16
.update1:
	cmp	counter,1
	ble	.cont1
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont1
	mov	1,counter

	.align	16
.update2:
	cmp	%i5,0
	bne	.cont2

	cmp	counter,1
	ble	.cont2
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont2
	mov	1,counter

	.align	16
.update3:
	cmp	counter,2
	ble	.cont3
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i1,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont3
	mov	2,counter

	.align	16
.update4:
	cmp	counter,2
	ble	.cont4
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i1,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont4
	mov	2,counter

	.align	16
.update5:
	cmp	%i5,0
	bne	.cont5

	cmp	counter,2
	ble	.cont5
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i1,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont5
	mov	2,counter

	.align	16
.update6:
	cmp	counter,3
	ble	.cont6
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]

	stx	%o3,[%fp+tmp_py]
	ba	.cont6
	mov	3,counter

	.align	16
.update7:
	cmp	counter,3
	ble	.cont7
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]

	stx	%o3,[%fp+tmp_py]
	ba	.cont7
	mov	3,counter

	.align	16
.update8:
	cmp	%i5,0
	bne	.cont8

	cmp	counter,3
	ble	.cont8
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]

	stx	%o3,[%fp+tmp_py]
	ba	.cont8
	mov	3,counter

	.align	16
.update9:
	cmp	counter,4
	ble	.cont9
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont9
	mov	4,counter

	.align	16
.update10:
	cmp	counter,4
	ble	.cont10
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont10
	mov	4,counter

	.align	16
.update11:
	cmp	%i5,0
	bne	.cont11

	cmp	counter,4
	ble	.cont11
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont11
	mov	4,counter

	.align	16
.update12:
	cmp	counter,5
	ble	.cont12
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%o4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont12
	mov	5,counter

	.align	16
.update13:
	cmp	counter,5
	ble	.cont13
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%o4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont13
	mov	5,counter

	.align	16
.update14:
	cmp	%i5,0
	bne	.cont14

	cmp	counter,5
	ble	.cont14
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%o4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont14
	mov	5,counter

	.align	16
.update15:
	cmp	counter,6
	ble	.cont15
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont15
	mov	6,counter

	.align	16
.update16:
	cmp	counter,6
	ble	.cont16
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont16
	mov	6,counter

	.align	16
.update17:
	cmp	%i5,0
	bne	.cont17

	cmp	counter,1
	ble	.cont17
	fmovd	DC1,%f62

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont17
	mov	1,counter

	.align	16
.update18:
	cmp	counter,2
	ble	.cont18
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i1,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont18
	mov	2,counter

	.align	16
.update19:
	cmp	counter,2
	ble	.cont19
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i1,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont19
	mov	2,counter

	.align	16
.update20:
	cmp	%o1,0
	bne	.cont20

	cmp	counter,2
	ble	.cont20
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%i1,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont20
	mov	2,counter

	.align	16
.update21:
	cmp	counter,3
	ble	.cont21
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]

	stx	%o3,[%fp+tmp_py]
	ba	.cont21
	mov	3,counter

	.align	16
.update22:
	cmp	counter,3
	ble	.cont22
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]

	stx	%o3,[%fp+tmp_py]
	ba	.cont22
	mov	3,counter

	.align	16
.update23:
	cmp	%i5,0
	bne	.cont23

	cmp	counter,3
	ble	.cont23
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]

	stx	%o3,[%fp+tmp_py]
	ba	.cont23
	mov	3,counter

	.align	16
.update24:
	cmp	counter,4
	ble	.cont24
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont24
	mov	4,counter

	.align	16
.update25:
	cmp	counter,4
	ble	.cont25
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont25
	mov	4,counter

	.align	16
.update26:
	cmp	%i5,0
	bne	.cont26

	cmp	counter,4
	ble	.cont26
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont26
	mov	4,counter

	.align	16
.update27:
	cmp	counter,5
	ble	.cont27
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%o4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont27
	mov	5,counter

	.align	16
.update28:
	cmp	counter,5
	ble	.cont28
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%o4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont28
	mov	5,counter

	.align	16
.update29:
	cmp	%i5,0
	bne	.cont29

	cmp	counter,5
	ble	.cont29
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%o4,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont29
	mov	5,counter

	.align	16
.update30:
	cmp	counter,6
	ble	.cont30
	ld	[TBL+TBL_SHIFT+44],%f2

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont30
	mov	6,counter

	.align	16
.update31:
	cmp	counter,6
	ble	.cont31
	ld	[TBL+TBL_SHIFT+44],%f4

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l0,[%fp+tmp_px]

	stx	%i2,[%fp+tmp_py]
	ba	.cont31
	mov	6,counter

	.align	16
.exit:
	ret
	restore
	SET_SIZE(__vrhypotf)

