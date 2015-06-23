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

	.file	"__vatanf.S"

#include "libm.h"

	RO_DATA
	.align	64

.CONST_TBL:
	.word	0x3fefffff, 0xfffccbbc	! K0 =  9.99999999976686608841e-01
	.word	0xbfd55554, 0x51c6b90f	! K1 = -3.33333091601972730504e-01
	.word	0x3fc98d6d, 0x926596cc	! K2 =  1.99628540499523379702e-01
	.word	0x00020000, 0x00000000	! DC1
	.word	0xfffc0000, 0x00000000	! DC2
	.word	0x7ff00000, 0x00000000	! DC3
	.word	0x3ff00000, 0x00000000	! DONE = 1.0
	.word	0x40000000, 0x00000000	! DTWO = 2.0

! parr0 = *(int*)&(1.0 / *(double*)&(((long long)i << 45) | 0x3ff0100000000000ULL)) + 0x3ff00000, i = [0, 127]

	.word	0x7fdfe01f, 0x7fdfa11c, 0x7fdf6310, 0x7fdf25f6
	.word	0x7fdee9c7, 0x7fdeae80, 0x7fde741a, 0x7fde3a91
	.word	0x7fde01e0, 0x7fddca01, 0x7fdd92f2, 0x7fdd5cac
	.word	0x7fdd272c, 0x7fdcf26e, 0x7fdcbe6d, 0x7fdc8b26
	.word	0x7fdc5894, 0x7fdc26b5, 0x7fdbf583, 0x7fdbc4fd
	.word	0x7fdb951e, 0x7fdb65e2, 0x7fdb3748, 0x7fdb094b
	.word	0x7fdadbe8, 0x7fdaaf1d, 0x7fda82e6, 0x7fda5741
	.word	0x7fda2c2a, 0x7fda01a0, 0x7fd9d79f, 0x7fd9ae24
	.word	0x7fd9852f, 0x7fd95cbb, 0x7fd934c6, 0x7fd90d4f
	.word	0x7fd8e652, 0x7fd8bfce, 0x7fd899c0, 0x7fd87427
	.word	0x7fd84f00, 0x7fd82a4a, 0x7fd80601, 0x7fd7e225
	.word	0x7fd7beb3, 0x7fd79baa, 0x7fd77908, 0x7fd756ca
	.word	0x7fd734f0, 0x7fd71378, 0x7fd6f260, 0x7fd6d1a6
	.word	0x7fd6b149, 0x7fd69147, 0x7fd6719f, 0x7fd6524f
	.word	0x7fd63356, 0x7fd614b3, 0x7fd5f664, 0x7fd5d867
	.word	0x7fd5babc, 0x7fd59d61, 0x7fd58056, 0x7fd56397
	.word	0x7fd54725, 0x7fd52aff, 0x7fd50f22, 0x7fd4f38f
	.word	0x7fd4d843, 0x7fd4bd3e, 0x7fd4a27f, 0x7fd48805
	.word	0x7fd46dce, 0x7fd453d9, 0x7fd43a27, 0x7fd420b5
	.word	0x7fd40782, 0x7fd3ee8f, 0x7fd3d5d9, 0x7fd3bd60
	.word	0x7fd3a524, 0x7fd38d22, 0x7fd3755b, 0x7fd35dce
	.word	0x7fd34679, 0x7fd32f5c, 0x7fd31877, 0x7fd301c8
	.word	0x7fd2eb4e, 0x7fd2d50a, 0x7fd2bef9, 0x7fd2a91c
	.word	0x7fd29372, 0x7fd27dfa, 0x7fd268b3, 0x7fd2539d
	.word	0x7fd23eb7, 0x7fd22a01, 0x7fd21579, 0x7fd20120
	.word	0x7fd1ecf4, 0x7fd1d8f5, 0x7fd1c522, 0x7fd1b17c
	.word	0x7fd19e01, 0x7fd18ab0, 0x7fd1778a, 0x7fd1648d
	.word	0x7fd151b9, 0x7fd13f0e, 0x7fd12c8b, 0x7fd11a30
	.word	0x7fd107fb, 0x7fd0f5ed, 0x7fd0e406, 0x7fd0d244
	.word	0x7fd0c0a7, 0x7fd0af2f, 0x7fd09ddb, 0x7fd08cab
	.word	0x7fd07b9f, 0x7fd06ab5, 0x7fd059ee, 0x7fd04949
	.word	0x7fd038c6, 0x7fd02864, 0x7fd01824, 0x7fd00804

	.word	0x3ff00000, 0x00000000	!  1.0
	.word	0xbff00000, 0x00000000	! -1.0

! parr1[i] = atan((double)*(float*)&((i + 460) << 21)), i = [0, 155]

	.word	0x3f2fffff, 0xf555555c, 0x3f33ffff, 0xf595555f
	.word	0x3f37ffff, 0xee000018, 0x3f3bffff, 0xe36aaadf
	.word	0x3f3fffff, 0xd55555bc, 0x3f43ffff, 0xd65555f2
	.word	0x3f47ffff, 0xb8000185, 0x3f4bffff, 0x8daaadf3
	.word	0x3f4fffff, 0x55555bbc, 0x3f53ffff, 0x59555f19
	.word	0x3f57fffe, 0xe000184d, 0x3f5bfffe, 0x36aadf30
	.word	0x3f5ffffd, 0x5555bbbc, 0x3f63fffd, 0x6555f195
	.word	0x3f67fffb, 0x800184cc, 0x3f6bfff8, 0xdaadf302
	.word	0x3f6ffff5, 0x555bbbb7, 0x3f73fff5, 0x955f194a
	.word	0x3f77ffee, 0x00184ca6, 0x3f7bffe3, 0x6adf2fd1
	.word	0x3f7fffd5, 0x55bbba97, 0x3f83ffd6, 0x55f1929c
	.word	0x3f87ffb8, 0x0184c30a, 0x3f8bff8d, 0xadf2e78c
	.word	0x3f8fff55, 0x5bbb729b, 0x3f93ff59, 0x5f18a700
	.word	0x3f97fee0, 0x184a5c36, 0x3f9bfe36, 0xdf291712
	.word	0x3f9ffd55, 0xbba97625, 0x3fa3fd65, 0xf169c9d9
	.word	0x3fa7fb81, 0x8430da2a, 0x3fabf8dd, 0xf139c444
	.word	0x3faff55b, 0xb72cfdea, 0x3fb3f59f, 0x0e7c559d
	.word	0x3fb7ee18, 0x2602f10f, 0x3fbbe39e, 0xbe6f07c4
	.word	0x3fbfd5ba, 0x9aac2f6e, 0x3fc3d6ee, 0xe8c6626c
	.word	0x3fc7b97b, 0x4bce5b02, 0x3fcb90d7, 0x529260a2
	.word	0x3fcf5b75, 0xf92c80dd, 0x3fd36277, 0x3707ebcc
	.word	0x3fd6f619, 0x41e4def1, 0x3fda64ee, 0xc3cc23fd
	.word	0x3fddac67, 0x0561bb4f, 0x3fe1e00b, 0xabdefeb4
	.word	0x3fe4978f, 0xa3269ee1, 0x3fe700a7, 0xc5784634
	.word	0x3fe921fb, 0x54442d18, 0x3fecac7c, 0x57846f9e
	.word	0x3fef730b, 0xd281f69b, 0x3ff0d38f, 0x2c5ba09f
	.word	0x3ff1b6e1, 0x92ebbe44, 0x3ff30b6d, 0x796a4da8
	.word	0x3ff3fc17, 0x6b7a8560, 0x3ff4ae10, 0xfc6589a5
	.word	0x3ff5368c, 0x951e9cfd, 0x3ff5f973, 0x15254857
	.word	0x3ff67d88, 0x63bc99bd, 0x3ff6dcc5, 0x7bb565fd
	.word	0x3ff7249f, 0xaa996a21, 0x3ff789bd, 0x2c160054
	.word	0x3ff7cd6f, 0x6dc59db4, 0x3ff7fde8, 0x0870c2a0
	.word	0x3ff82250, 0x768ac529, 0x3ff8555a, 0x2787981f
	.word	0x3ff87769, 0xeb8e956b, 0x3ff88fc2, 0x18ace9dc
	.word	0x3ff8a205, 0xfd558740, 0x3ff8bb9a, 0x63718f45
	.word	0x3ff8cca9, 0x27cf0b3d, 0x3ff8d8d8, 0xbf65316f
	.word	0x3ff8e1fc, 0xa98cb633, 0x3ff8eec8, 0xcfd00665
	.word	0x3ff8f751, 0x0eba96e6, 0x3ff8fd69, 0x4acf36b0
	.word	0x3ff901fb, 0x7eee715e, 0x3ff90861, 0xd082d9b5
	.word	0x3ff90ca6, 0x0b9322c5, 0x3ff90fb2, 0x37a7ea27
	.word	0x3ff911fb, 0x59997f3a, 0x3ff9152e, 0x8a326c38
	.word	0x3ff91750, 0xab2e0d12, 0x3ff918d6, 0xc2f9c9e2
	.word	0x3ff919fb, 0x54eed7a9, 0x3ff91b94, 0xee352849
	.word	0x3ff91ca5, 0xff216922, 0x3ff91d69, 0x0b3f72ff
	.word	0x3ff91dfb, 0x5459826d, 0x3ff91ec8, 0x211be619
	.word	0x3ff91f50, 0xa99fd49a, 0x3ff91fb2, 0x2fb5defa
	.word	0x3ff91ffb, 0x5446d7c3, 0x3ff92061, 0xbaabf105
	.word	0x3ff920a5, 0xfeefa208, 0x3ff920d6, 0xc1fb87e7
	.word	0x3ff920fb, 0x5444826e, 0x3ff9212e, 0x87778bfc
	.word	0x3ff92150, 0xa9999bb6, 0x3ff92169, 0x0b1faabb
	.word	0x3ff9217b, 0x544437c3, 0x3ff92194, 0xedddcc28
	.word	0x3ff921a5, 0xfeeedaec, 0x3ff921b2, 0x2fb1e5f1
	.word	0x3ff921bb, 0x54442e6e, 0x3ff921c8, 0x2110fa94
	.word	0x3ff921d0, 0xa99982d3, 0x3ff921d6, 0xc1fb08c6
	.word	0x3ff921db, 0x54442d43, 0x3ff921e1, 0xbaaa9395
	.word	0x3ff921e5, 0xfeeed7d0, 0x3ff921e9, 0x0b1f9ad7
	.word	0x3ff921eb, 0x54442d1e, 0x3ff921ee, 0x8777604e
	.word	0x3ff921f0, 0xa999826f, 0x3ff921f2, 0x2fb1e3f5
	.word	0x3ff921f3, 0x54442d19, 0x3ff921f4, 0xedddc6b2
	.word	0x3ff921f5, 0xfeeed7c3, 0x3ff921f6, 0xc1fb0886
	.word	0x3ff921f7, 0x54442d18, 0x3ff921f8, 0x2110f9e5
	.word	0x3ff921f8, 0xa999826e, 0x3ff921f9, 0x0b1f9acf
	.word	0x3ff921f9, 0x54442d18, 0x3ff921f9, 0xbaaa937f
	.word	0x3ff921f9, 0xfeeed7c3, 0x3ff921fa, 0x2fb1e3f4
	.word	0x3ff921fa, 0x54442d18, 0x3ff921fa, 0x8777604b
	.word	0x3ff921fa, 0xa999826e, 0x3ff921fa, 0xc1fb0886
	.word	0x3ff921fa, 0xd4442d18, 0x3ff921fa, 0xedddc6b2
	.word	0x3ff921fa, 0xfeeed7c3, 0x3ff921fb, 0x0b1f9acf
	.word	0x3ff921fb, 0x14442d18, 0x3ff921fb, 0x2110f9e5
	.word	0x3ff921fb, 0x2999826e, 0x3ff921fb, 0x2fb1e3f4
	.word	0x3ff921fb, 0x34442d18, 0x3ff921fb, 0x3aaa937f
	.word	0x3ff921fb, 0x3eeed7c3, 0x3ff921fb, 0x41fb0886
	.word	0x3ff921fb, 0x44442d18, 0x3ff921fb, 0x4777604b
	.word	0x3ff921fb, 0x4999826e, 0x3ff921fb, 0x4b1f9acf
	.word	0x3ff921fb, 0x4c442d18, 0x3ff921fb, 0x4dddc6b2
	.word	0x3ff921fb, 0x4eeed7c3, 0x3ff921fb, 0x4fb1e3f4
	.word	0x3ff921fb, 0x50442d18, 0x3ff921fb, 0x5110f9e5
	.word	0x3ff921fb, 0x5199826e, 0x3ff921fb, 0x51fb0886

#define DC2		%f2
#define DTWO		%f6
#define DONE		%f52
#define K0		%f54
#define K1		%f56
#define K2		%f58
#define DC1		%f60
#define DC3		%f62

#define stridex		%o2
#define stridey		%o3
#define MASK_0x7fffffff	%i1
#define MASK_0x100000	%i5

#define tmp_px		STACK_BIAS-32
#define tmp_counter	STACK_BIAS-24
#define tmp0		STACK_BIAS-16
#define tmp1		STACK_BIAS-8

#define counter		%l1

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x20

!--------------------------------------------------------------------
!		!!!!!	vatanf algorithm	!!!!!
!  ux = ((int*)px)[0];
!  ax = ux & 0x7fffffff;
!
!  if ( ax < 0x39b89c55 )
!  {
!    *(int*)py = ux;
!    goto next;
!  }
!
!  if ( ax > 0x4c700518 )
!  {
!    if ( ax > 0x7f800000 )
!    {
!      float fpx = fabsf(*px);
!      fpx *= fpx;
!      *py = fpx;
!      goto next;
!    }
!
!    sign = ux & 0x80000000;
!    sign |= pi_2;
!    *(int*)py = sign;
!    goto next;
!  }
!
!  ftmp0 = *px;
!  x = (double)ftmp0;
!  px += stridex;
!  y = vis_fpadd32(x,DC1);
!  y = vis_fand(y,DC2);
!  div = x * y;
!  xx = x - y;
!  div += DONE;
!  i = ((unsigned long long*)&div)[0];
!  y0 = vis_fand(div,DC3);
!  i >>= 43;
!  i &= 508;
!  *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
!  y0 = vis_fpsub32(dtmp0, y0);
!  dtmp0 = div0 * y0;
!  dtmp0 = DTWO - dtmp0;
!  y0 *= dtmp0;
!  dtmp1 = div0 * y0;
!  dtmp1 = DTWO - dtmp1;
!  y0 *= dtmp1;
!  ax = ux & 0x7fffffff;
!  ax += 0x00100000;
!  ax >>= 18;
!  ax &= -8;
!  res = *(double*)((char*)parr1 + ax);
!  ux >>= 28;
!  ux &= -8;
!  dtmp0 = *(double*)((char*)sign_arr + ux);
!  res *= dtmp0;
!  xx *= y0;
!  x2 = xx * xx;
!  dtmp0 = K2 * x2;
!  dtmp0 += K1;
!  dtmp0 *= x2;
!  dtmp0 += K0;
!  dtmp0 *= xx;
!  res += dtmp0;
!  ftmp0 = (float)res;
!  py[0] = ftmp0;
!  py += stridey;
!--------------------------------------------------------------------

	ENTRY(__vatanf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,l2)

	st	%i0,[%fp+tmp_counter]

	sllx	%i2,2,stridex
	sllx	%i4,2,stridey

	or	%g0,%i3,%o1
	stx	%i1,[%fp+tmp_px]

	ldd	[%l2],K0
	ldd	[%l2+8],K1
	ldd	[%l2+16],K2
	ldd	[%l2+24],DC1
	ldd	[%l2+32],DC2
	ldd	[%l2+40],DC3
	ldd	[%l2+48],DONE
	ldd	[%l2+56],DTWO

	add	%l2,64,%i4
	add	%l2,64+512,%l0
	add	%l2,64+512+16-0x1cc*8,%l7

	sethi	%hi(0x100000),MASK_0x100000
	sethi	%hi(0x7ffffc00),MASK_0x7fffffff
	add	MASK_0x7fffffff,1023,MASK_0x7fffffff

	sethi	%hi(0x39b89c00),%o4
	add	%o4,0x55,%o4
	sethi	%hi(0x4c700400),%o5
	add	%o5,0x118,%o5

.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%i3
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit
	nop

	lda	[%i3]0x82,%l6		! (0_0) ux = ((int*)px)[0];

	and	%l6,MASK_0x7fffffff,%l5	! (0_0) ax = ux & 0x7fffffff;
	lda	[%i3]0x82,%f0		! (0_0) ftmp0 = *px;

	cmp	%l5,%o4			! (0_0) ax ? 0x39b89c55
	bl,pn	%icc,.spec0		! (0_0) if ( ax < 0x39b89c55 )
	nop

	cmp	%l5,%o5			! (0_0) ax ? 0x4c700518
	bg,pn	%icc,.spec1		! (0_0) if ( ax > 0x4c700518 )
	nop

	add	%i3,stridex,%l5		! px += stridex;
	fstod	%f0,%f22		! (0_0) ftmp0 = *px;
	mov	%l6,%i3

	lda	[%l5]0x82,%l6		! (1_0) ux = ((int*)px)[0];

	and	%l6,MASK_0x7fffffff,%o7	! (1_0) ax = ux & 0x7fffffff;
	lda	[%l5]0x82,%f0		! (1_0) ftmp0 = *px;
	add	%l5,stridex,%l4		! px += stridex;
	fpadd32	%f22,DC1,%f24		! (0_0) y = vis_fpadd32(x,dconst1);

	cmp	%o7,%o4			! (1_0) ax ? 0x39b89c55
	bl,pn	%icc,.update0		! (1_0) if ( ax < 0x39b89c55 )
	nop
.cont0:
	cmp	%o7,%o5			! (1_0) ax ? 0x4c700518
	bg,pn	%icc,.update1		! (1_0) if ( ax > 0x4c700518 )
	nop
.cont1:
	fstod	%f0,%f20		! (1_0) x = (double)ftmp0;
	mov	%l6,%l5

	fand	%f24,DC2,%f26		! (0_0) y = vis_fand(y,dconst2);

	fmuld	%f22,%f26,%f32		! (0_0) div = x * y;

	lda	[%l4]0x82,%l6		! (2_0) ux = ((int*)px)[0];
	fsubd	%f22,%f26,%f22		! (0_0) xx = x - y;

	and	%l6,MASK_0x7fffffff,%o7	! (2_0) ax = ux & 0x7fffffff;
	lda	[%l4]0x82,%f0		! (2_0) ftmp0 = *px;
	add	%l4,stridex,%l3		! px += stridex;
	fpadd32	%f20,DC1,%f24		! (1_0) y = vis_fpadd32(x,dconst1);

	cmp	%o7,%o4			! (2_0) ax ? 0x39b89c55
	bl,pn	%icc,.update2		! (2_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f32,%f32		! (0_0) div += done;
.cont2:
	cmp	%o7,%o5			! (2_0) ax ? 0x4c700518
	bg,pn	%icc,.update3		! (2_0) if ( ax > 0x4c700518 )
	nop
.cont3:
	std	%f32,[%fp+tmp0]		! (0_0) i = ((unsigned long long*)&div)[0];
	mov	%l6,%l4
	fstod	%f0,%f18		! (2_0) x = (double)ftmp0;

	fand	%f24,DC2,%f26		! (1_0) y = vis_fand(y,dconst2);

	fmuld	%f20,%f26,%f30		! (1_0) div = x * y;

	lda	[%l3]0x82,%l6		! (3_0) ux = ((int*)px)[0];
	fsubd	%f20,%f26,%f20		! (1_0) xx = x - y;

	and	%l6,MASK_0x7fffffff,%o7	! (3_0) ax = ux & 0x7fffffff;
	lda	[%l3]0x82,%f0		! (3_0) ftmp0 = *px;
	add	%l3,stridex,%i0		! px += stridex;
	fpadd32	%f18,DC1,%f24		! (2_0) y = vis_fpadd32(x,dconst1);

	cmp	%o7,%o4			! (3_0) ax ? 0x39b89c55
	bl,pn	%icc,.update4		! (3_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f30,%f30		! (1_0) div += done;
.cont4:
	cmp	%o7,%o5			! (3_0) ax ? 0x4c700518
	bg,pn	%icc,.update5		! (3_0) if ( ax > 0x4c700518 )
	nop
.cont5:
	std	%f30,[%fp+tmp1]		! (1_0) i = ((unsigned long long*)&div)[0];
	mov	%l6,%l3
	fstod	%f0,%f16		! (3_0) x = (double)ftmp0;

	ldx	[%fp+tmp0],%o0		! (0_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (2_0) y = vis_fand(y,dconst2);

	fand	%f32,DC3,%f24		! (0_0) y0 = vis_fand(div,dconst3);

	srlx	%o0,43,%o0		! (0_0) i >>= 43;

	and	%o0,508,%l6		! (0_0) i &= 508;

	ld	[%i4+%l6],%f0		! (0_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);

	fmuld	%f18,%f26,%f28		! (2_0) div = x * y;

	lda	[%i0]0x82,%l6		! (4_0) ux = ((int*)px)[0];
	fsubd	%f18,%f26,%f18		! (2_0) xx = x - y;

	fpsub32	%f0,%f24,%f40		! (0_0) y0 = vis_fpsub32(dtmp0, y0);

	and	%l6,MASK_0x7fffffff,%o7	! (4_0) ax = ux & 0x7fffffff;
	lda	[%i0]0x82,%f0		! (4_0) ftmp0 = *px;
	add	%i0,stridex,%i2		! px += stridex;
	fpadd32	%f16,DC1,%f24		! (3_0) y = vis_fpadd32(x,dconst1);

	cmp	%o7,%o4			! (4_0) ax ? 0x39b89c55
	bl,pn	%icc,.update6		! (4_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f28,%f28		! (2_0) div += done;
.cont6:
	fmuld	%f32,%f40,%f42		! (0_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (4_0) ax ? 0x4c700518
	bg,pn	%icc,.update7		! (4_0) if ( ax > 0x4c700518 )
	nop
.cont7:
	std	%f28,[%fp+tmp0]		! (2_0) i = ((unsigned long long*)&div)[0];
	mov	%l6,%i0
	fstod	%f0,%f14		! (4_0) x = (double)ftmp0;

	ldx	[%fp+tmp1],%g1		! (1_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (3_0) y = vis_fand(y,dconst2);

	fand	%f30,DC3,%f24		! (1_0) y0 = vis_fand(div,dconst3);

	fsubd	DTWO,%f42,%f44		! (0_0) dtmp0 = dtwo - dtmp0;
	srlx	%g1,43,%g1		! (1_0) i >>= 43;

	and	%g1,508,%l6		! (1_0) i &= 508;

	ld	[%i4+%l6],%f0		! (1_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);

	fmuld	%f16,%f26,%f34		! (3_0) div = x * y;

	lda	[%i2]0x82,%l6		! (5_0) ux = ((int*)px)[0];
	fsubd	%f16,%f26,%f16		! (3_0) xx = x - y;

	fpsub32	%f0,%f24,%f38		! (1_0) y0 = vis_fpsub32(dtmp0, y0);
	add	%i2,stridex,%l2		! px += stridex;

	fmuld	%f40,%f44,%f40		! (0_0) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (5_0) ax = ux & 0x7fffffff;
	lda	[%i2]0x82,%f0		! (5_0) ftmp0 = *px;
	fpadd32	%f14,DC1,%f24		! (4_0) y = vis_fpadd32(x,dconst1);

	cmp	%o7,%o4			! (5_0) ax ? 0x39b89c55
	bl,pn	%icc,.update8		! (5_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f34,%f34		! (3_0) div += done;
.cont8:
	fmuld	%f30,%f38,%f42		! (1_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (5_0) ax ? 0x4c700518
	bg,pn	%icc,.update9		! (5_0) if ( ax > 0x4c700518 )
	nop
.cont9:
	std	%f34,[%fp+tmp1]		! (3_0) i = ((unsigned long long*)&div)[0];
	mov	%l6,%i2
	fstod	%f0,%f36		! (5_0) x = (double)ftmp0;

	fmuld	%f32,%f40,%f32		! (0_0) dtmp1 = div0 * y0;
	ldx	[%fp+tmp0],%o0		! (2_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (4_0) y = vis_fand(y,dconst2);

	fand	%f28,DC3,%f24		! (2_0) y0 = vis_fand(div,dconst3);

	fsubd	DTWO,%f42,%f44		! (1_0) dtmp0 = dtwo - dtmp0;
	srlx	%o0,43,%o0		! (2_0) i >>= 43;

	and	%o0,508,%l6		! (2_0) i &= 508;
	fsubd	DTWO,%f32,%f46		! (0_0) dtmp1 = dtwo - dtmp1;

	ld	[%i4+%l6],%f0		! (2_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);

	fmuld	%f14,%f26,%f32		! (4_0) div = x * y;

	lda	[%l2]0x82,%l6		! (6_0) ux = ((int*)px)[0];
	fsubd	%f14,%f26,%f14		! (4_0) xx = x - y;

	fmuld	%f40,%f46,%f26		! (0_0) y0 *= dtmp1;
	add	%l2,stridex,%g5		! px += stridex;
	fpsub32	%f0,%f24,%f40		! (2_0) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f38,%f44,%f38		! (1_0) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (6_0) ax = ux & 0x7fffffff;
	lda	[%l2]0x82,%f0		! (6_0) ftmp0 = *px;
	fpadd32	%f36,DC1,%f24		! (5_0) y = vis_fpadd32(x,dconst1);

	cmp	%o7,%o4			! (6_0) ax ? 0x39b89c55
	bl,pn	%icc,.update10		! (6_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f32,%f32		! (4_0) div += done;
.cont10:
	fmuld	%f28,%f40,%f42		! (2_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (6_0) ax ? 0x4c700518
	bg,pn	%icc,.update11		! (6_0) if ( ax > 0x4c700518 )
	nop
.cont11:
	fmuld	%f22,%f26,%f22		! (0_0) xx *= y0;
	mov	%l6,%l2
	std	%f32,[%fp+tmp0]		! (4_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f10		! (6_0) x = (double)ftmp0;

	fmuld	%f30,%f38,%f30		! (1_0) dtmp1 = div0 * y0;
	ldx	[%fp+tmp1],%g1		! (3_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (5_0) y = vis_fand(y,dconst2);

	fand	%f34,DC3,%f24		! (3_0) y0 = vis_fand(div,dconst3);

	fmuld	%f22,%f22,%f50		! (0_0) x2 = xx * xx;
	srlx	%g1,43,%g1		! (3_0) i >>= 43;
	fsubd	DTWO,%f42,%f44		! (2_0) dtmp0 = dtwo - dtmp0;

	and	%g1,508,%l6		! (3_0) i &= 508;
	mov	%i3,%o7
	fsubd	DTWO,%f30,%f46		! (1_0) dtmp1 = dtwo - dtmp1;

	ld	[%i4+%l6],%f0		! (3_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);

	fmuld	%f36,%f26,%f30		! (5_0) div = x * y;
	srl	%o7,28,%g1		! (0_0) ux >>= 28;
	add	%g5,stridex,%i3		! px += stridex;

	fmuld	K2,%f50,%f4		! (0_0) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o0	! (0_0) ax = ux & 0x7fffffff;
	lda	[%g5]0x82,%l6		! (7_0) ux = ((int*)px)[0];
	fsubd	%f36,%f26,%f36		! (5_0) xx = x - y;

	fmuld	%f38,%f46,%f26		! (1_0) y0 *= dtmp1;
	add	%o0,MASK_0x100000,%o0	! (0_0) ax += 0x00100000;
	and	%g1,-8,%g1		! (0_0) ux &= -8;
	fpsub32	%f0,%f24,%f38		! (3_0) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f40,%f44,%f40		! (2_0) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (7_0) ax = ux & 0x7fffffff;
	lda	[%g5]0x82,%f0		! (7_0) ftmp0 = *px;
	fpadd32	%f10,DC1,%f24		! (6_0) y = vis_fpadd32(x,dconst1);

	cmp	%o7,%o4			! (7_0) ax ? 0x39b89c55
	bl,pn	%icc,.update12		! (7_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f30,%f30		! (5_0) div += done;
.cont12:
	fmuld	%f34,%f38,%f42		! (3_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (7_0) ax ? 0x4c700518
	bg,pn	%icc,.update13		! (7_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (0_0) dtmp0 += K1;
.cont13:
	fmuld	%f20,%f26,%f20		! (1_0) xx *= y0;
	srl	%o0,18,%o7		! (0_0) ax >>= 18;
	std	%f30,[%fp+tmp1]		! (5_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f8			! (7_0) x = (double)ftmp0;

	fmuld	%f28,%f40,%f28		! (2_0) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (0_0) ux &= -8;
	ldx	[%fp+tmp0],%o0		! (4_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (6_0) y = vis_fand(y,dconst2);

	add	%o7,%l7,%o7		! (0_0) (char*)parr1 + ax;
	mov	%l6,%g5
	ldd	[%l0+%g1],%f48		! (0_0) dtmp0 = *(double*)((char*)sign_arr + ux);

	fmuld	%f4,%f50,%f4		! (0_0) dtmp0 *= x2;
	srlx	%o0,43,%o0		! (4_0) i >>= 43;
	ldd	[%o7],%f0		! (0_0) res = *(double*)((char*)parr1 + ax);
	fand	%f32,DC3,%f24		! (4_0) y0 = vis_fand(div,dconst3);

	fmuld	%f20,%f20,%f50		! (1_0) x2 = xx * xx;
	and	%o0,508,%l6		! (4_0) i &= 508;
	mov	%l5,%o7
	fsubd	DTWO,%f42,%f44		! (3_0) dtmp0 = dtwo - dtmp0;

	fsubd	DTWO,%f28,%f46		! (2_0) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (0_0) res *= dtmp0;
	srl	%o7,28,%l5		! (1_0) ux >>= 28;
	ld	[%i4+%l6],%f0		! (4_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);

	fmuld	%f10,%f26,%f28		! (6_0) div = x * y;
	faddd	%f4,K0,%f42		! (0_0) dtmp0 += K0;

	subcc	counter,8,counter
	bneg,pn	%icc,.tail
	or	%g0,%o1,%o0

	add	%fp,tmp0,%g1
	lda	[%i3]0x82,%l6		! (0_0) ux = ((int*)px)[0];

	ba	.main_loop
	add	%i3,stridex,%l5		! px += stridex;

	.align	16
.main_loop:
	fsubd	%f10,%f26,%f10		! (6_1) xx = x - y;
	and	%o7,MASK_0x7fffffff,%o1	! (1_1) ax = ux & 0x7fffffff;
	st	%f12,[%g1]		! (7_1) py[0] = ftmp0;
	fmuld	K2,%f50,%f4		! (1_1) dtmp0 = K2 * x2;

	fmuld	%f40,%f46,%f26		! (2_1) y0 *= dtmp1;
	srl	%o7,28,%o7		! (1_0) ux >>= 28;
	add	%o1,MASK_0x100000,%g1	! (1_1) ax += 0x00100000;
	fpsub32	%f0,%f24,%f40		! (4_1) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f38,%f44,%f38		! (3_1) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o1	! (0_0) ax = ux & 0x7fffffff;
	lda	[%i3]0x82,%f0		! (0_0) ftmp0 = *px;
	fpadd32	%f8,DC1,%f24		! (7_1) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f22,%f44		! (0_1) dtmp0 *= xx;
	cmp	%o1,%o4			! (0_0) ax ? 0x39b89c55
	bl,pn	%icc,.update14		! (0_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f28,%f28		! (6_1) div += done;
.cont14:
	fmuld	%f32,%f40,%f42		! (4_1) dtmp0 = div0 * y0;
	cmp	%o1,%o5			! (0_0) ax ? 0x4c700518
	bg,pn	%icc,.update15		! (0_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (1_1) dtmp0 += K1;
.cont15:
	fmuld	%f18,%f26,%f18		! (2_1) xx *= y0;
	srl	%g1,18,%o1		! (1_1) ax >>= 18;
	std	%f28,[%fp+tmp0]		! (6_1) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f22		! (0_0) ftmp0 = *px;

	fmuld	%f34,%f38,%f34		! (3_1) dtmp1 = div0 * y0;
	and	%o1,-8,%o1		! (1_1) ax &= -8;
	ldx	[%fp+tmp1],%g1		! (5_1) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (7_1) y = vis_fand(y,dconst2);

	ldd	[%o1+%l7],%f0		! (1_1) res = *(double*)((char*)parr1 + ax);
	and	%o7,-8,%o7		! (1_1) ux &= -8;
	mov	%l6,%i3
	faddd	%f48,%f44,%f12		! (0_1) res += dtmp0;

	fmuld	%f4,%f50,%f4		! (1_1) dtmp0 *= x2;
	nop
	ldd	[%l0+%o7],%f48		! (1_1) dtmp0 = *(double*)((char*)sign_arr + ux);
	fand	%f30,DC3,%f24		! (5_1) y0 = vis_fand(div,dconst3);

	fmuld	%f18,%f18,%f50		! (2_1) x2 = xx * xx;
	srlx	%g1,43,%g1		! (5_1) i >>= 43;
	mov	%l4,%o7
	fsubd	DTWO,%f42,%f44		! (4_1) dtmp0 = dtwo - dtmp0;

	and	%g1,508,%l6		! (5_1) i &= 508;
	nop
	bn,pn	%icc,.exit
	fsubd	DTWO,%f34,%f46		! (3_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (1_1) res *= dtmp0;
	add	%o0,stridey,%g1		! py += stridey;
	ld	[%i4+%l6],%f0		! (5_1) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (0_1) ftmp0 = (float)res;

	fmuld	%f8,%f26,%f34		! (7_1) div = x * y;
	srl	%o7,28,%o1		! (2_1) ux >>= 28;
	lda	[%l5]0x82,%l6		! (1_0) ux = ((int*)px)[0];
	faddd	%f4,K0,%f42		! (1_1) dtmp0 += K0;

	fmuld	K2,%f50,%f4		! (2_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o7	! (2_1) ax = ux & 0x7fffffff;
	st	%f12,[%o0]		! (0_1) py[0] = ftmp0;
	fsubd	%f8,%f26,%f8		! (7_1) xx = x - y;

	fmuld	%f38,%f46,%f26		! (3_1) y0 *= dtmp1;
	add	%l5,stridex,%l4		! px += stridex;
	add	%o7,MASK_0x100000,%o0	! (2_1) ax += 0x00100000;
	fpsub32	%f0,%f24,%f38		! (5_1) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f40,%f44,%f40		! (4_1) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (1_0) ax = ux & 0x7fffffff;
	lda	[%l5]0x82,%f0		! (1_0) ftmp0 = *px;
	fpadd32	%f22,DC1,%f24		! (0_0) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f20,%f44		! (1_1) dtmp0 *= xx;
	cmp	%o7,%o4			! (1_0) ax ? 0x39b89c55
	bl,pn	%icc,.update16		! (1_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f34,%f34		! (7_1) div += done;
.cont16:
	fmuld	%f30,%f38,%f42		! (5_1) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (1_0) ax ? 0x4c700518
	bg,pn	%icc,.update17		! (1_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (2_1) dtmp0 += K1;
.cont17:
	fmuld	%f16,%f26,%f16		! (3_1) xx *= y0;
	srl	%o0,18,%o7		! (2_1) ax >>= 18;
	std	%f34,[%fp+tmp1]		! (7_1) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f20		! (1_0) x = (double)ftmp0;

	fmuld	%f32,%f40,%f32		! (4_1) dtmp1 = div0 * y0;
	ldx	[%fp+tmp0],%o0		! (6_1) i = ((unsigned long long*)&div)[0];
	and	%o1,-8,%o1		! (2_1) ux &= -8;
	fand	%f24,DC2,%f26		! (0_0) y = vis_fand(y,dconst2);

	faddd	%f48,%f44,%f12		! (1_1) res += dtmp0;
	and	%o7,-8,%o7		! (2_1) ax &= -8;
	ldd	[%l0+%o1],%f48		! (2_1) dtmp0 = *(double*)((char*)sign_arr + ux);
	bn,pn	%icc,.exit

	ldd	[%o7+%l7],%f0		! (2_1) res = *(double*)((char*)parr1 + ax);
	mov	%l6,%l5
	fmuld	%f4,%f50,%f4		! (2_1) dtmp0 *= x2;
	fand	%f28,DC3,%f24		! (6_1) y0 = vis_fand(div,dconst3);

	fmuld	%f16,%f16,%f50		! (3_1) x2 = xx * xx;
	srlx	%o0,43,%o0		! (6_1) i >>= 43;
	mov	%l3,%o7
	fsubd	DTWO,%f42,%f44		! (5_1) dtmp0 = dtwo - dtmp0;

	and	%o0,508,%l6		! (6_1) i &= 508;
	add	%l4,stridex,%l3		! px += stridex;
	bn,pn	%icc,.exit
	fsubd	DTWO,%f32,%f46		! (4_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (2_1) res *= dtmp0;
	add	%g1,stridey,%o0		! py += stridey;
	ld	[%i4+%l6],%f0		! (6_1) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (1_1) ftmp0 = (float)res;

	fmuld	%f22,%f26,%f32		! (0_0) div = x * y;
	srl	%o7,28,%o1		! (3_1) ux >>= 28;
	lda	[%l4]0x82,%l6		! (2_0) ux = ((int*)px)[0];
	faddd	%f4,K0,%f42		! (2_1) dtmp0 += K0;

	fmuld	K2,%f50,%f4		! (3_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o7	! (3_1) ax = ux & 0x7fffffff;
	st	%f12,[%g1]		! (1_1) py[0] = ftmp0;
	fsubd	%f22,%f26,%f22		! (0_0) xx = x - y;

	fmuld	%f40,%f46,%f26		! (4_1) y0 *= dtmp1;
	add	%o7,MASK_0x100000,%g1	! (3_1) ax += 0x00100000;
	and	%o1,-8,%o1		! (3_1) ux &= -8;
	fpsub32	%f0,%f24,%f40		! (6_1) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f38,%f44,%f38		! (5_1) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (2_0) ax = ux & 0x7fffffff;
	lda	[%l4]0x82,%f0		! (2_0) ftmp0 = *px;
	fpadd32	%f20,DC1,%f24		! (1_0) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f18,%f44		! (2_1) dtmp0 *= xx;
	cmp	%o7,%o4			! (2_0) ax ? 0x39b89c55
	bl,pn	%icc,.update18		! (2_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f32,%f32		! (0_0) div += done;
.cont18:
	fmuld	%f28,%f40,%f42		! (6_1) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (2_0) ax ? 0x4c700518
	bg,pn	%icc,.update19		! (2_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (3_1) dtmp0 += K1;
.cont19:
	fmuld	%f14,%f26,%f14		! (4_1) xx *= y0;
	srl	%g1,18,%o7		! (3_1) ax >>= 18;
	std	%f32,[%fp+tmp0]		! (0_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f18		! (2_0) x = (double)ftmp0;

	fmuld	%f30,%f38,%f30		! (5_1) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (3_1) ax &= -8;
	ldx	[%fp+tmp1],%g1		! (7_1) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (1_0) y = vis_fand(y,dconst2);

	faddd	%f48,%f44,%f12		! (2_1) res += dtmp0;
	mov	%l6,%l4
	ldd	[%l0+%o1],%f48		! (3_1) dtmp0 = *(double*)((char*)sign_arr + ux);
	bn,pn	%icc,.exit

	fmuld	%f4,%f50,%f4		! (3_1) dtmp0 *= x2;
	ldd	[%o7+%l7],%f0		! (3_1) res = *(double*)((char*)parr1 + ax)
	nop
	fand	%f34,DC3,%f24		! (7_1) y0 = vis_fand(div,dconst3);

	fmuld	%f14,%f14,%f50		! (4_1) x2 = xx * xx;
	srlx	%g1,43,%g1		! (7_1) i >>= 43;
	mov	%i0,%o7
	fsubd	DTWO,%f42,%f44		! (6_1) dtmp0 = dtwo - dtmp0;

	and	%g1,508,%l6		! (7_1) i &= 508;
	add	%l3,stridex,%i0		! px += stridex;
	bn,pn	%icc,.exit
	fsubd	DTWO,%f30,%f46		! (5_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (3_1) res *= dtmp0;
	add	%o0,stridey,%g1		! py += stridey;
	ld	[%i4+%l6],%f0		! (7_1) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (2_1) ftmp0 = (float)res;

	fmuld	%f20,%f26,%f30		! (1_0) div = x * y;
	srl	%o7,28,%o1		! (4_1) ux >>= 28;
	lda	[%l3]0x82,%l6		! (3_0) ux = ((int*)px)[0];
	faddd	%f4,K0,%f42		! (3_1) dtmp0 += K0;

	fmuld	K2,%f50,%f4		! (4_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o7	! (4_1) ax = ux & 0x7fffffff;
	st	%f12,[%o0]		! (2_1) py[0] = ftmp0;
	fsubd	%f20,%f26,%f20		! (1_0) xx = x - y;

	fmuld	%f38,%f46,%f26		! (5_1) y0 *= dtmp1;
	add	%o7,MASK_0x100000,%o0	! (4_1) ax += 0x00100000;
	and	%o1,-8,%o1		! (4_1) ux &= -8;
	fpsub32	%f0,%f24,%f38		! (7_1) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f40,%f44,%f40		! (6_1) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (3_0) ax = ux & 0x7fffffff;
	lda	[%l3]0x82,%f0		! (3_0) ftmp0 = *px;
	fpadd32	%f18,DC1,%f24		! (2_0) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f16,%f44		! (3_1) dtmp0 *= xx;
	cmp	%o7,%o4			! (3_0) ax ? 0x39b89c55
	bl,pn	%icc,.update20		! (3_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f30,%f30		! (1_0) div += done;
.cont20:
	fmuld	%f34,%f38,%f42		! (7_1) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (3_0) ax ? 0x4c700518
	bg,pn	%icc,.update21		! (3_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (4_1) dtmp0 += K1;
.cont21:
	fmuld	%f36,%f26,%f36		! (5_1) xx *= y0;
	srl	%o0,18,%o7		! (4_1) ax >>= 18;
	std	%f30,[%fp+tmp1]		! (1_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f16		! (3_0) x = (double)ftmp0;

	fmuld	%f28,%f40,%f28		! (6_1) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (4_1) ax &= -8;
	ldx	[%fp+tmp0],%o0		! (0_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (2_0) y = vis_fand(y,dconst2);

	faddd	%f48,%f44,%f12		! (3_1) res += dtmp0;
	nop
	ldd	[%l0+%o1],%f48		! (4_1) dtmp0 = *(double*)((char*)sign_arr + ux);
	bn,pn	%icc,.exit

	ldd	[%o7+%l7],%f0		! (4_1) res = *(double*)((char*)parr1 + ax);
	mov	%l6,%l3
	fmuld	%f4,%f50,%f4		! (4_1) dtmp0 *= x2;
	fand	%f32,DC3,%f24		! (0_0) y0 = vis_fand(div,dconst3);

	fmuld	%f36,%f36,%f50		! (5_1) x2 = xx * xx;
	srlx	%o0,43,%o0		! (0_0) i >>= 43;
	mov	%i2,%o7
	fsubd	DTWO,%f42,%f44		! (7_1) dtmp0 = dtwo - dtmp0;

	and	%o0,508,%l6		! (0_0) i &= 508;
	add	%i0,stridex,%i2		! px += stridex;
	bn,pn	%icc,.exit
	fsubd	DTWO,%f28,%f46		! (6_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (4_1) res *= dtmp0;
	add	%g1,stridey,%o0		! py += stridey;
	ld	[%i4+%l6],%f0		! (0_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (3_1) ftmp0 = (float)res;

	fmuld	%f18,%f26,%f28		! (2_0) div = x * y;
	srl	%o7,28,%o1		! (5_1) ux >>= 28;
	lda	[%i0]0x82,%l6		! (4_0) ux = ((int*)px)[0];
	faddd	%f4,K0,%f42		! (4_1) dtmp0 += K0;

	fmuld	K2,%f50,%f4		! (5_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o7	! (5_1) ax = ux & 0x7fffffff;
	st	%f12,[%g1]		! (3_1) py[0] = ftmp0;
	fsubd	%f18,%f26,%f18		! (2_0) xx = x - y;

	fmuld	%f40,%f46,%f26		! (6_1) y0 *= dtmp1;
	add	%o7,MASK_0x100000,%g1	! (5_1) ax += 0x00100000;
	and	%o1,-8,%o1		! (5_1) ux &= -8;
	fpsub32	%f0,%f24,%f40		! (0_0) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f38,%f44,%f38		! (7_1) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (4_0) ax = ux & 0x7fffffff;
	lda	[%i0]0x82,%f0		! (4_0) ftmp0 = *px;
	fpadd32	%f16,DC1,%f24		! (3_0) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f14,%f44		! (4_1) dtmp0 *= xx;
	cmp	%o7,%o4			! (4_0) ax ? 0x39b89c55
	bl,pn	%icc,.update22		! (4_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f28,%f28		! (2_0) div += done;
.cont22:
	fmuld	%f32,%f40,%f42		! (0_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (4_0) ax ? 0x4c700518
	bg,pn	%icc,.update23		! (4_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (5_1) dtmp0 += K1;
.cont23:
	fmuld	%f10,%f26,%f10		! (6_1) xx *= y0;
	srl	%g1,18,%o7		! (5_1) ax >>= 18;
	std	%f28,[%fp+tmp0]		! (2_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f14		! (4_0) x = (double)ftmp0;

	fmuld	%f34,%f38,%f34		! (7_1) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (5_1) ax &= -8;
	ldx	[%fp+tmp1],%g1		! (1_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (3_0) y = vis_fand(y,dconst2);

	faddd	%f48,%f44,%f12		! (4_1) res += dtmp0;
	mov	%l6,%i0
	ldd	[%l0+%o1],%f48		! (5_1) dtmp0 = *(double*)((char*)sign_arr + ux);
	bn,pn	%icc,.exit

	ldd	[%o7+%l7],%f0		! (5_1) res = *(double*)((char*)parr1 + ax);
	nop
	fmuld	%f4,%f50,%f4		! (5_1) dtmp0 *= x2;
	fand	%f30,DC3,%f24		! (1_0) y0 = vis_fand(div,dconst3);

	fmuld	%f10,%f10,%f50		! (6_1) x2 = xx * xx;
	srlx	%g1,43,%g1		! (1_0) i >>= 43;
	mov	%l2,%o7
	fsubd	DTWO,%f42,%f44		! (0_0) dtmp0 = dtwo - dtmp0;

	and	%g1,508,%l6		! (1_0) i &= 508;
	add	%i2,stridex,%l2		! px += stridex;
	bn,pn	%icc,.exit
	fsubd	DTWO,%f34,%f46		! (7_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (5_1) res *= dtmp0;
	add	%o0,stridey,%g1		! py += stridey;
	ld	[%i4+%l6],%f0		! (1_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (4_1) ftmp0 = (float)res;

	fmuld	%f16,%f26,%f34		! (3_0) div = x * y;
	srl	%o7,28,%o1		! (6_1) ux >>= 28;
	lda	[%i2]0x82,%l6		! (5_0) ux = ((int*)px)[0];
	faddd	%f4,K0,%f42		! (5_1) dtmp0 += K0;

	fmuld	K2,%f50,%f4		! (6_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o7	! (6_1) ax = ux & 0x7fffffff;
	st	%f12,[%o0]		! (4_1) py[0] = ftmp0;
	fsubd	%f16,%f26,%f16		! (3_0) xx = x - y;

	fmuld	%f38,%f46,%f26		! (7_1) y0 *= dtmp1;
	add	%o7,MASK_0x100000,%o0	! (6_1) ax += 0x00100000;
	and	%o1,-8,%o1		! (6_1) ux &= -8;
	fpsub32	%f0,%f24,%f38		! (1_0) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f40,%f44,%f40		! (0_0) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (5_0) ax = ux & 0x7fffffff;
	lda	[%i2]0x82,%f0		! (5_0) ftmp0 = *px;
	fpadd32	%f14,DC1,%f24		! (4_0) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f36,%f44		! (5_1) dtmp0 *= xx;
	cmp	%o7,%o4			! (5_0) ax ? 0x39b89c55
	bl,pn	%icc,.update24		! (5_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f34,%f34		! (3_0) div += done;
.cont24:
	fmuld	%f30,%f38,%f42		! (1_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (5_0) ax ? 0x4c700518
	bg,pn	%icc,.update25		! (5_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (6_1) dtmp0 += K1;
.cont25:
	fmuld	%f8,%f26,%f8		! (7_1) xx *= y0;
	srl	%o0,18,%o7		! (6_1) ax >>= 18;
	std	%f34,[%fp+tmp1]		! (3_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f36		! (5_0) x = (double)ftmp0;

	fmuld	%f32,%f40,%f32		! (0_0) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (6_1) ax &= -8;
	ldx	[%fp+tmp0],%o0		! (2_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (4_0) y = vis_fand(y,dconst2);

	faddd	%f48,%f44,%f12		! (5_1) res += dtmp0;
	mov	%l6,%i2
	ldd	[%l0+%o1],%f48		! (6_1) dtmp0 = *(double*)((char*)sign_arr + ux);
	bn,pn	%icc,.exit

	ldd	[%o7+%l7],%f0		! (6_1) res = *(double*)((char*)parr1 + ax);
	nop
	fmuld	%f4,%f50,%f4		! (6_1) dtmp0 *= x2;
	fand	%f28,DC3,%f24		! (2_0) y0 = vis_fand(div,dconst3);

	fmuld	%f8,%f8,%f50		! (7_1) x2 = xx * xx;
	srlx	%o0,43,%o0		! (2_0) i >>= 43;
	mov	%g5,%o7
	fsubd	DTWO,%f42,%f44		! (1_0) dtmp0 = dtwo - dtmp0;

	and	%o0,508,%l6		! (2_0) i &= 508;
	add	%l2,stridex,%g5		! px += stridex;
	bn,pn	%icc,.exit
	fsubd	DTWO,%f32,%f46		! (0_0) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (6_1) res *= dtmp0;
	add	%g1,stridey,%o0		! py += stridey;
	ld	[%i4+%l6],%f0		! (2_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (5_1) ftmp0 = (float)res;

	fmuld	%f14,%f26,%f32		! (4_0) div = x * y;
	srl	%o7,28,%o1		! (7_1) ux >>= 28;
	lda	[%l2]0x82,%l6		! (6_0) ux = ((int*)px)[0];
	faddd	%f4,K0,%f42		! (6_1) dtmp0 += K0;

	fmuld	K2,%f50,%f4		! (7_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o7	! (7_1) ax = ux & 0x7fffffff;
	st	%f12,[%g1]		! (5_1) py[0] = ftmp0;
	fsubd	%f14,%f26,%f14		! (4_0) xx = x - y;

	fmuld	%f40,%f46,%f26		! (0_0) y0 *= dtmp1;
	add	%o7,MASK_0x100000,%g1	! (7_1) ax += 0x00100000;
	and	%o1,-8,%o1		! (7_1) ux &= -8;
	fpsub32	%f0,%f24,%f40		! (2_0) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f38,%f44,%f38		! (1_0) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (6_0) ax = ux & 0x7fffffff;
	lda	[%l2]0x82,%f0		! (6_0) ftmp0 = *px;
	fpadd32	%f36,DC1,%f24		! (5_0) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f10,%f44		! (6_1) dtmp0 *= xx;
	cmp	%o7,%o4			! (6_0) ax ? 0x39b89c55
	bl,pn	%icc,.update26		! (6_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f32,%f32		! (4_0) div += done;
.cont26:
	fmuld	%f28,%f40,%f42		! (2_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (6_0) ax ? 0x4c700518
	bg,pn	%icc,.update27		! (6_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (7_1) dtmp0 += K1;
.cont27:
	fmuld	%f22,%f26,%f22		! (0_0) xx *= y0;
	srl	%g1,18,%o7		! (7_1) ax >>= 18;
	std	%f32,[%fp+tmp0]		! (4_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f10		! (6_0) x = (double)ftmp0;

	fmuld	%f30,%f38,%f30		! (1_0) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (7_1) ax &= -8;
	ldx	[%fp+tmp1],%g1		! (3_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (5_0) y = vis_fand(y,dconst2);

	faddd	%f48,%f44,%f12		! (6_1) res += dtmp0;
	mov	%l6,%l2
	ldd	[%l0+%o1],%f48		! (7_1) dtmp0 = *(double*)((char*)sign_arr + ux);
	bn,pn	%icc,.exit

	ldd	[%o7+%l7],%f0		! (7_1) res = *(double*)((char*)parr1 + ax);
	nop
	fmuld	%f4,%f50,%f4		! (7_1) dtmp0 *= x2;
	fand	%f34,DC3,%f24		! (3_0) y0 = vis_fand(div,dconst3);

	fmuld	%f22,%f22,%f50		! (0_0) x2 = xx * xx;
	srlx	%g1,43,%g1		! (3_0) i >>= 43;
	mov	%i3,%o7
	fsubd	DTWO,%f42,%f44		! (2_0) dtmp0 = dtwo - dtmp0;

	and	%g1,508,%l6		! (3_0) i &= 508;
	add	%g5,stridex,%i3		! px += stridex;
	bn,pn	%icc,.exit
	fsubd	DTWO,%f30,%f46		! (1_0) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (7_1) res *= dtmp0;
	add	%o0,stridey,%g1		! py += stridey;
	ld	[%i4+%l6],%f0		! (3_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (6_1) ftmp0 = (float)res;

	fmuld	%f36,%f26,%f30		! (5_0) div = x * y;
	srl	%o7,28,%o1		! (0_0) ux >>= 28;
	lda	[%g5]0x82,%l6		! (7_0) ux = ((int*)px)[0];
	faddd	%f4,K0,%f42		! (7_1) dtmp0 += K0;

	fmuld	K2,%f50,%f4		! (0_0) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o7	! (0_0) ax = ux & 0x7fffffff;
	st	%f12,[%o0]		! (6_1) py[0] = ftmp0;
	fsubd	%f36,%f26,%f36		! (5_0) xx = x - y;

	fmuld	%f38,%f46,%f26		! (1_0) y0 *= dtmp1;
	add	%o7,MASK_0x100000,%o0	! (0_0) ax += 0x00100000;
	and	%o1,-8,%o1		! (0_0) ux &= -8;
	fpsub32	%f0,%f24,%f38		! (3_0) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f40,%f44,%f40		! (2_0) y0 *= dtmp0;
	and	%l6,MASK_0x7fffffff,%o7	! (7_0) ax = ux & 0x7fffffff;
	lda	[%g5]0x82,%f0		! (7_0) ftmp0 = *px;
	fpadd32	%f10,DC1,%f24		! (6_0) y = vis_fpadd32(x,dconst1);

	fmuld	%f42,%f8,%f44		! (7_1) dtmp0 *= xx;
	cmp	%o7,%o4			! (7_0) ax ? 0x39b89c55
	bl,pn	%icc,.update28		! (7_0) if ( ax < 0x39b89c55 )
	faddd	DONE,%f30,%f30		! (5_0) div += done;
.cont28:
	fmuld	%f34,%f38,%f42		! (3_0) dtmp0 = div0 * y0;
	cmp	%o7,%o5			! (7_0) ax ? 0x4c700518
	bg,pn	%icc,.update29		! (7_0) if ( ax > 0x4c700518 )
	faddd	%f4,K1,%f4		! (0_0) dtmp0 += K1;
.cont29:
	fmuld	%f20,%f26,%f20		! (1_0) xx *= y0;
	srl	%o0,18,%o7		! (0_0) ax >>= 18;
	std	%f30,[%fp+tmp1]		! (5_0) i = ((unsigned long long*)&div)[0];
	fstod	%f0,%f8			! (7_0) x = (double)ftmp0;

	fmuld	%f28,%f40,%f28		! (2_0) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (0_0) ux &= -8;
	ldx	[%fp+tmp0],%o0		! (4_0) i = ((unsigned long long*)&div)[0];
	fand	%f24,DC2,%f26		! (6_0) y = vis_fand(y,dconst2);

	faddd	%f48,%f44,%f12		! (7_1) res += dtmp0;
	subcc	counter,8,counter
	ldd	[%l0+%o1],%f48		! (0_0) dtmp0 = *(double*)((char*)sign_arr + ux);
	bn,pn	%icc,.exit

	fmuld	%f4,%f50,%f4		! (0_0) dtmp0 *= x2;
	mov	%l6,%g5
	ldd	[%o7+%l7],%f0		! (0_0) res = *(double*)((char*)parr1 + ax);
	fand	%f32,DC3,%f24		! (4_0) y0 = vis_fand(div,dconst3);

	fmuld	%f20,%f20,%f50		! (1_0) x2 = xx * xx;
	srlx	%o0,43,%l6		! (4_0) i >>= 43;
	mov	%l5,%o7
	fsubd	DTWO,%f42,%f44		! (3_0) dtmp0 = dtwo - dtmp0;

	add	%g1,stridey,%o0		! py += stridey;
	and	%l6,508,%l6		! (4_0) i &= 508;
	bn,pn	%icc,.exit
	fsubd	DTWO,%f28,%f46		! (2_0) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (0_0) res *= dtmp0;
	ld	[%i4+%l6],%f0		! (4_0) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	add	%i3,stridex,%l5		! px += stridex;
	fdtos	%f12,%f12		! (7_1) ftmp0 = (float)res;

	lda	[%i3]0x82,%l6		! (0_0) ux = ((int*)px)[0];
	fmuld	%f10,%f26,%f28		! (6_0) div = x * y;
	bpos,pt	%icc,.main_loop
	faddd	%f4,K0,%f42		! (0_0) dtmp0 += K0;

	srl	%o7,28,%l5		! (1_0) ux >>= 28;
	st	%f12,[%g1]		! (7_1) py[0] = ftmp0;

.tail:
	addcc	counter,7,counter
	bneg,pn	%icc,.begin
	or	%g0,%o0,%o1

	fsubd	%f10,%f26,%f10		! (6_1) xx = x - y;
	and	%o7,MASK_0x7fffffff,%g1	! (1_1) ax = ux & 0x7fffffff;
	fmuld	K2,%f50,%f4		! (1_1) dtmp0 = K2 * x2;

	fmuld	%f40,%f46,%f26		! (2_1) y0 *= dtmp1;
	add	%g1,MASK_0x100000,%g1	! (1_1) ax += 0x00100000;
	and	%l5,-8,%l5		! (1_1) ux &= -8;
	fpsub32	%f0,%f24,%f40		! (4_1) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f38,%f44,%f38		! (3_1) y0 *= dtmp0;

	fmuld	%f42,%f22,%f44		! (0_1) dtmp0 *= xx;
	faddd	DONE,%f28,%f28		! (6_1) div += done;

	fmuld	%f32,%f40,%f42		! (4_1) dtmp0 = div0 * y0;
	faddd	%f4,K1,%f4		! (1_1) dtmp0 += K1;

	fmuld	%f18,%f26,%f18		! (2_1) xx *= y0;
	srl	%g1,18,%o7		! (1_1) ax >>= 18;
	std	%f28,[%fp+tmp0]		! (6_1) i = ((unsigned long long*)&div)[0];

	fmuld	%f34,%f38,%f34		! (3_1) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (1_1) ax &= -8;
	ldx	[%fp+tmp1],%g1		! (5_1) i = ((unsigned long long*)&div)[0];

	faddd	%f48,%f44,%f12		! (0_1) res += dtmp0;
	add	%o7,%l7,%o7		! (1_1) (char*)parr1 + ax;
	ldd	[%l0+%l5],%f48		! (1_1) dtmp0 = *(double*)((char*)sign_arr + ux);

	fmuld	%f4,%f50,%f4		! (1_1) dtmp0 *= x2;
	fand	%f30,DC3,%f24		! (5_1) y0 = vis_fand(div,dconst3);
	ldd	[%o7],%f0		! (1_1) res = *(double*)((char*)parr1 + ax);

	fmuld	%f18,%f18,%f50		! (2_1) x2 = xx * xx;
	fsubd	DTWO,%f42,%f44		! (4_1) dtmp0 = dtwo - dtmp0;
	srlx	%g1,43,%g1		! (5_1) i >>= 43;

	and	%g1,508,%l6		! (5_1) i &= 508;
	mov	%l4,%o7
	fsubd	DTWO,%f34,%f46		! (3_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (1_1) res *= dtmp0;
	add	%o0,stridey,%g1		! py += stridey;
	ld	[%i4+%l6],%f0		! (5_1) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (0_1) ftmp0 = (float)res;

	srl	%o7,28,%l4		! (2_1) ux >>= 28;
	st	%f12,[%o0]		! (0_1) py[0] = ftmp0;
	faddd	%f4,K0,%f42		! (1_1) dtmp0 += K0;

	subcc	counter,1,counter
	bneg,pn	%icc,.begin
	or	%g0,%g1,%o1

	fmuld	K2,%f50,%f4		! (2_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o0	! (2_1) ax = ux & 0x7fffffff;

	fmuld	%f38,%f46,%f26		! (3_1) y0 *= dtmp1;
	add	%o0,MASK_0x100000,%o0	! (2_1) ax += 0x00100000;
	and	%l4,-8,%l4		! (2_1) ux &= -8;
	fpsub32	%f0,%f24,%f38		! (5_1) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f40,%f44,%f40		! (4_1) y0 *= dtmp0;

	fmuld	%f42,%f20,%f44		! (1_1) dtmp0 *= xx;

	fmuld	%f30,%f38,%f42		! (5_1) dtmp0 = div0 * y0;
	faddd	%f4,K1,%f4		! (2_1) dtmp0 += K1;

	fmuld	%f16,%f26,%f16		! (3_1) xx *= y0;
	srl	%o0,18,%o7		! (2_1) ax >>= 18;

	fmuld	%f32,%f40,%f32		! (4_1) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (2_1) ax &= -8;
	ldx	[%fp+tmp0],%o0		! (6_1) i = ((unsigned long long*)&div)[0];

	faddd	%f48,%f44,%f12		! (1_1) res += dtmp0;
	add	%o7,%l7,%o7		! (2_1) (char*)parr1 + ax;
	ldd	[%l0+%l4],%f48		! (2_1) dtmp0 = *(double*)((char*)sign_arr + ux);

	fmuld	%f4,%f50,%f4		! (2_1) dtmp0 *= x2;
	fand	%f28,DC3,%f24		! (6_1) y0 = vis_fand(div,dconst3);
	ldd	[%o7],%f0		! (2_1) res = *(double*)((char*)parr1 + ax);

	fmuld	%f16,%f16,%f50		! (3_1) x2 = xx * xx;
	fsubd	DTWO,%f42,%f44		! (5_1) dtmp0 = dtwo - dtmp0;
	srlx	%o0,43,%o0		! (6_1) i >>= 43;

	and	%o0,508,%l6		! (6_1) i &= 508;
	mov	%l3,%o7
	fsubd	DTWO,%f32,%f46		! (4_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (2_1) res *= dtmp0;
	add	%g1,stridey,%o0		! py += stridey;
	ld	[%i4+%l6],%f0		! (6_1) *(float*)&dtmp0 = *(float*)((char*)parr0 + i);
	fdtos	%f12,%f12		! (1_1) ftmp0 = (float)res;

	srl	%o7,28,%l3		! (3_1) ux >>= 28;
	st	%f12,[%g1]		! (1_1) py[0] = ftmp0;
	faddd	%f4,K0,%f42		! (2_1) dtmp0 += K0;

	subcc	counter,1,counter
	bneg,pn	%icc,.begin
	or	%g0,%o0,%o1

	fmuld	K2,%f50,%f4		! (3_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%g1	! (3_1) ax = ux & 0x7fffffff;

	fmuld	%f40,%f46,%f26		! (4_1) y0 *= dtmp1;
	add	%g1,MASK_0x100000,%g1	! (3_1) ax += 0x00100000;
	and	%l3,-8,%l3		! (3_1) ux &= -8;
	fpsub32	%f0,%f24,%f40		! (6_1) y0 = vis_fpsub32(dtmp0, y0);

	fmuld	%f38,%f44,%f38		! (5_1) y0 *= dtmp0;

	fmuld	%f42,%f18,%f44		! (2_1) dtmp0 *= xx;

	fmuld	%f28,%f40,%f42		! (6_1) dtmp0 = div0 * y0;
	faddd	%f4,K1,%f4		! (3_1) dtmp0 += K1;

	fmuld	%f14,%f26,%f14		! (4_1) xx *= y0;
	srl	%g1,18,%o7		! (3_1) ax >>= 18;

	fmuld	%f30,%f38,%f30		! (5_1) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (3_1) ax &= -8;

	faddd	%f48,%f44,%f12		! (2_1) res += dtmp0;
	add	%o7,%l7,%o7		! (3_1) (char*)parr1 + ax;
	ldd	[%l0+%l3],%f48		! (3_1) dtmp0 = *(double*)((char*)sign_arr + ux);

	fmuld	%f4,%f50,%f4		! (3_1) dtmp0 *= x2;
	ldd	[%o7],%f0		! (3_1) res = *(double*)((char*)parr1 + ax)

	fmuld	%f14,%f14,%f50		! (4_1) x2 = xx * xx;
	fsubd	DTWO,%f42,%f44		! (6_1) dtmp0 = dtwo - dtmp0;

	mov	%i0,%o7
	fsubd	DTWO,%f30,%f46		! (5_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (3_1) res *= dtmp0;
	add	%o0,stridey,%g1		! py += stridey;
	fdtos	%f12,%f12		! (2_1) ftmp0 = (float)res;

	srl	%o7,28,%i0		! (4_1) ux >>= 28;
	st	%f12,[%o0]		! (2_1) py[0] = ftmp0;
	faddd	%f4,K0,%f42		! (3_1) dtmp0 += K0;

	subcc	counter,1,counter
	bneg,pn	%icc,.begin
	or	%g0,%g1,%o1

	fmuld	K2,%f50,%f4		! (4_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o0	! (4_1) ax = ux & 0x7fffffff;

	fmuld	%f38,%f46,%f26		! (5_1) y0 *= dtmp1;
	add	%o0,MASK_0x100000,%o0	! (4_1) ax += 0x00100000;
	and	%i0,-8,%i0		! (4_1) ux &= -8;

	fmuld	%f40,%f44,%f40		! (6_1) y0 *= dtmp0;

	fmuld	%f42,%f16,%f44		! (3_1) dtmp0 *= xx;

	faddd	%f4,K1,%f4		! (4_1) dtmp0 += K1;

	fmuld	%f36,%f26,%f36		! (5_1) xx *= y0;
	srl	%o0,18,%o7		! (4_1) ax >>= 18;

	fmuld	%f28,%f40,%f28		! (6_1) dtmp1 = div0 * y0;
	and	%o7,-8,%o7		! (4_1) ax &= -8;

	faddd	%f48,%f44,%f12		! (3_1) res += dtmp0;
	add	%o7,%l7,%o7		! (4_1) (char*)parr1 + ax;
	ldd	[%l0+%i0],%f48		! (4_1) dtmp0 = *(double*)((char*)sign_arr + ux);

	fmuld	%f4,%f50,%f4		! (4_1) dtmp0 *= x2;
	ldd	[%o7],%f0		! (4_1) res = *(double*)((char*)parr1 + ax);

	fmuld	%f36,%f36,%f50		! (5_1) x2 = xx * xx;

	mov	%i2,%o7
	fsubd	DTWO,%f28,%f46		! (6_1) dtmp1 = dtwo - dtmp1;

	fmuld	%f0,%f48,%f48		! (4_1) res *= dtmp0;
	add	%g1,stridey,%o0		! py += stridey;
	fdtos	%f12,%f12		! (3_1) ftmp0 = (float)res;

	srl	%o7,28,%i2		! (5_1) ux >>= 28;
	st	%f12,[%g1]		! (3_1) py[0] = ftmp0;
	faddd	%f4,K0,%f42		! (4_1) dtmp0 += K0;

	subcc	counter,1,counter
	bneg,pn	%icc,.begin
	or	%g0,%o0,%o1

	fmuld	K2,%f50,%f4		! (5_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%g1	! (5_1) ax = ux & 0x7fffffff;

	fmuld	%f40,%f46,%f26		! (6_1) y0 *= dtmp1;
	add	%g1,MASK_0x100000,%g1	! (5_1) ax += 0x00100000;
	and	%i2,-8,%i2		! (5_1) ux &= -8;

	fmuld	%f42,%f14,%f44		! (4_1) dtmp0 *= xx;

	faddd	%f4,K1,%f4		! (5_1) dtmp0 += K1;

	fmuld	%f10,%f26,%f10		! (6_1) xx *= y0;
	srl	%g1,18,%o7		! (5_1) ax >>= 18;

	and	%o7,-8,%o7		! (5_1) ax &= -8;

	faddd	%f48,%f44,%f12		! (4_1) res += dtmp0;
	add	%o7,%l7,%o7		! (5_1) (char*)parr1 + ax;
	ldd	[%l0+%i2],%f48		! (5_1) dtmp0 = *(double*)((char*)sign_arr + ux);

	fmuld	%f4,%f50,%f4		! (5_1) dtmp0 *= x2;
	ldd	[%o7],%f0		! (5_1) res = *(double*)((char*)parr1 + ax);

	fmuld	%f10,%f10,%f50		! (6_1) x2 = xx * xx;

	mov	%l2,%o7

	fmuld	%f0,%f48,%f48		! (5_1) res *= dtmp0;
	add	%o0,stridey,%g1		! py += stridey;
	fdtos	%f12,%f12		! (4_1) ftmp0 = (float)res;

	srl	%o7,28,%l2		! (6_1) ux >>= 28;
	st	%f12,[%o0]		! (4_1) py[0] = ftmp0;
	faddd	%f4,K0,%f42		! (5_1) dtmp0 += K0;

	subcc	counter,1,counter
	bneg,pn	%icc,.begin
	or	%g0,%g1,%o1

	fmuld	K2,%f50,%f4		! (6_1) dtmp0 = K2 * x2;
	and	%o7,MASK_0x7fffffff,%o0	! (6_1) ax = ux & 0x7fffffff;

	add	%o0,MASK_0x100000,%o0	! (6_1) ax += 0x00100000;
	and	%l2,-8,%l2		! (6_1) ux &= -8;

	fmuld	%f42,%f36,%f44		! (5_1) dtmp0 *= xx;

	faddd	%f4,K1,%f4		! (6_1) dtmp0 += K1;

	srl	%o0,18,%o7		! (6_1) ax >>= 18;

	and	%o7,-8,%o7		! (6_1) ax &= -8;

	faddd	%f48,%f44,%f12		! (5_1) res += dtmp0;
	add	%o7,%l7,%o7		! (6_1) (char*)parr1 + ax;
	ldd	[%l0+%l2],%f48		! (6_1) dtmp0 = *(double*)((char*)sign_arr + ux);

	fmuld	%f4,%f50,%f4		! (6_1) dtmp0 *= x2;
	ldd	[%o7],%f0		! (6_1) res = *(double*)((char*)parr1 + ax);

	fmuld	%f0,%f48,%f48		! (6_1) res *= dtmp0;
	add	%g1,stridey,%o0		! py += stridey;
	fdtos	%f12,%f12		! (5_1) ftmp0 = (float)res;

	st	%f12,[%g1]		! (5_1) py[0] = ftmp0;
	faddd	%f4,K0,%f42		! (6_1) dtmp0 += K0;

	subcc	counter,1,counter
	bneg,pn	%icc,.begin
	or	%g0,%o0,%o1

	fmuld	%f42,%f10,%f44		! (6_1) dtmp0 *= xx;

	faddd	%f48,%f44,%f12		! (6_1) res += dtmp0;

	add	%o0,stridey,%g1		! py += stridey;
	fdtos	%f12,%f12		! (6_1) ftmp0 = (float)res;

	st	%f12,[%o0]		! (6_1) py[0] = ftmp0;

	ba	.begin
	or	%g0,%g1,%o1		! py += stridey;

.exit:
	ret
	restore	%g0,%g0,%g0

	.align	16
.spec0:
	add	%i3,stridex,%i3		! px += stridex;
	sub	counter,1,counter
	st	%l6,[%o1]		! *(int*)py = ux;

	ba	.begin1
	add	%o1,stridey,%o1		! py += stridey;

	.align	16
.spec1:
	sethi	%hi(0x7f800000),%l3
	sethi	%hi(0x3fc90c00),%l4	! pi_2

	sethi	%hi(0x80000000),%o0
	add	%l4,0x3db,%l4		! pi_2

	cmp	%l5,%l3			! if ( ax > 0x7f800000 )
	bg,a,pn	%icc,1f
	fabss	%f0,%f0			! fpx = fabsf(*px);

	and	%l6,%o0,%l6		! sign = ux & 0x80000000;

	or	%l6,%l4,%l6		! sign |= pi_2;

	add	%i3,stridex,%i3		! px += stridex;
	sub	counter,1,counter
	st	%l6,[%o1]		! *(int*)py = sign;

	ba	.begin1
	add	%o1,stridey,%o1		! py += stridey;

1:
	fmuls	%f0,%f0,%f0		! fpx *= fpx;

	add	%i3,stridex,%i3		! px += stridex
	sub	counter,1,counter
	st	%f0,[%o1]		! *py = fpx;

	ba	.begin1
	add	%o1,stridey,%o1		! py += stridey;

	.align	16
.update0:
	cmp	counter,1
	fzeros	%f0
	ble,a	.cont0
	sethi	%hi(0x3fffffff),%l6

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont0
	or	%g0,1,counter

	.align	16
.update1:
	cmp	counter,1
	fzeros	%f0
	ble,a	.cont1
	sethi	%hi(0x3fffffff),%l6

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont1
	or	%g0,1,counter

	.align	16
.update2:
	cmp	counter,2
	fzeros	%f0
	ble,a	.cont2
	sethi	%hi(0x3fffffff),%l6

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%l4,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont2
	or	%g0,2,counter

	.align	16
.update3:
	cmp	counter,2
	fzeros	%f0
	ble,a	.cont3
	sethi	%hi(0x3fffffff),%l6

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%l4,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont3
	or	%g0,2,counter

	.align	16
.update4:
	cmp	counter,3
	fzeros	%f0
	ble,a	.cont4
	sethi	%hi(0x3fffffff),%l6

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%l3,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont4
	or	%g0,3,counter

	.align	16
.update5:
	cmp	counter,3
	fzeros	%f0
	ble,a	.cont5
	sethi	%hi(0x3fffffff),%l6

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%l3,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont5
	or	%g0,3,counter

	.align	16
.update6:
	cmp	counter,4
	fzeros	%f0
	ble,a	.cont6
	sethi	%hi(0x3fffffff),%l6

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i0,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont6
	or	%g0,4,counter

	.align	16
.update7:
	cmp	counter,4
	fzeros	%f0
	ble,a	.cont7
	sethi	%hi(0x3fffffff),%l6

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i0,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont7
	or	%g0,4,counter

	.align	16
.update8:
	cmp	counter,5
	fzeros	%f0
	ble,a	.cont8
	sethi	%hi(0x3fffffff),%l6

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont8
	or	%g0,5,counter

	.align	16
.update9:
	cmp	counter,5
	fzeros	%f0
	ble,a	.cont9
	sethi	%hi(0x3fffffff),%l6

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont9
	or	%g0,5,counter

	.align	16
.update10:
	cmp	counter,6
	fzeros	%f0
	ble,a	.cont10
	sethi	%hi(0x3fffffff),%l6

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont10
	or	%g0,6,counter

	.align	16
.update11:
	cmp	counter,6
	fzeros	%f0
	ble,a	.cont11
	sethi	%hi(0x3fffffff),%l6

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont11
	or	%g0,6,counter

	.align	16
.update12:
	cmp	counter,7
	fzeros	%f0
	ble,a	.cont12
	sethi	%hi(0x3fffffff),%l6

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont12
	or	%g0,7,counter

	.align	16
.update13:
	cmp	counter,7
	fzeros	%f0
	ble,a	.cont13
	sethi	%hi(0x3fffffff),%l6

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont13
	or	%g0,7,counter

	.align	16
.update14:
	cmp	counter,0
	fzeros	%f0
	ble,a	.cont14
	sethi	%hi(0x3fffffff),%l6

	sub	counter,0,counter
	st	counter,[%fp+tmp_counter]

	stx	%i3,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont14
	or	%g0,0,counter

	.align	16
.update15:
	cmp	counter,0
	fzeros	%f0
	ble,a	.cont15
	sethi	%hi(0x3fffffff),%l6

	sub	counter,0,counter
	st	counter,[%fp+tmp_counter]

	stx	%i3,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont15
	or	%g0,0,counter

	.align	16
.update16:
	cmp	counter,1
	fzeros	%f0
	ble,a	.cont16
	sethi	%hi(0x3fffffff),%l6

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont16
	or	%g0,1,counter

	.align	16
.update17:
	cmp	counter,1
	fzeros	%f0
	ble,a	.cont17
	sethi	%hi(0x3fffffff),%l6

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	stx	%l5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont17
	or	%g0,1,counter

	.align	16
.update18:
	cmp	counter,2
	fzeros	%f0
	ble,a	.cont18
	sethi	%hi(0x3fffffff),%l6

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%l4,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont18
	or	%g0,2,counter

	.align	16
.update19:
	cmp	counter,2
	fzeros	%f0
	ble,a	.cont19
	sethi	%hi(0x3fffffff),%l6

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	stx	%l4,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont19
	or	%g0,2,counter

	.align	16
.update20:
	cmp	counter,3
	fzeros	%f0
	ble,a	.cont20
	sethi	%hi(0x3fffffff),%l6

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%l3,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont20
	or	%g0,3,counter

	.align	16
.update21:
	cmp	counter,3
	fzeros	%f0
	ble,a	.cont21
	sethi	%hi(0x3fffffff),%l6

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	stx	%l3,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont21
	or	%g0,3,counter

	.align	16
.update22:
	cmp	counter,4
	fzeros	%f0
	ble,a	.cont22
	sethi	%hi(0x3fffffff),%l6

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i0,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont22
	or	%g0,4,counter

	.align	16
.update23:
	cmp	counter,4
	fzeros	%f0
	ble,a	.cont23
	sethi	%hi(0x3fffffff),%l6

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	stx	%i0,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont23
	or	%g0,4,counter

	.align	16
.update24:
	cmp	counter,5
	fzeros	%f0
	ble,a	.cont24
	sethi	%hi(0x3fffffff),%l6

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont24
	or	%g0,5,counter

	.align	16
.update25:
	cmp	counter,5
	fzeros	%f0
	ble,a	.cont25
	sethi	%hi(0x3fffffff),%l6

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	stx	%i2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont25
	or	%g0,5,counter

	.align	16
.update26:
	cmp	counter,6
	fzeros	%f0
	ble,a	.cont26
	sethi	%hi(0x3fffffff),%l6

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont26
	or	%g0,6,counter

	.align	16
.update27:
	cmp	counter,6
	fzeros	%f0
	ble,a	.cont27
	sethi	%hi(0x3fffffff),%l6

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	stx	%l2,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont27
	or	%g0,6,counter

	.align	16
.update28:
	cmp	counter,7
	fzeros	%f0
	ble,a	.cont28
	sethi	%hi(0x3fffffff),%l6

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont28
	or	%g0,7,counter

	.align	16
.update29:
	cmp	counter,7
	fzeros	%f0
	ble,a	.cont29
	sethi	%hi(0x3fffffff),%l6

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	stx	%g5,[%fp+tmp_px]
	sethi	%hi(0x3fffffff),%l6
	ba	.cont29
	or	%g0,7,counter

	SET_SIZE(__vatanf)

