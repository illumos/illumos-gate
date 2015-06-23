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

	.file	"__vexpf.S"

#include "libm.h"

	RO_DATA
	.align	64
!!  2^(i/256) - ((i & 0xf0) << 44), i = [0, 255]
.CONST_TBL:
	.word	0x3ff00000, 0x00000000, 0x3ff00b1a, 0xfa5abcbf
	.word	0x3ff0163d, 0xa9fb3335, 0x3ff02168, 0x143b0281
	.word	0x3ff02c9a, 0x3e778061, 0x3ff037d4, 0x2e11bbcc
	.word	0x3ff04315, 0xe86e7f85, 0x3ff04e5f, 0x72f654b1
	.word	0x3ff059b0, 0xd3158574, 0x3ff0650a, 0x0e3c1f89
	.word	0x3ff0706b, 0x29ddf6de, 0x3ff07bd4, 0x2b72a836
	.word	0x3ff08745, 0x18759bc8, 0x3ff092bd, 0xf66607e0
	.word	0x3ff09e3e, 0xcac6f383, 0x3ff0a9c7, 0x9b1f3919
	.word	0x3fefb558, 0x6cf9890f, 0x3fefc0f1, 0x45e46c85
	.word	0x3fefcc92, 0x2b7247f7, 0x3fefd83b, 0x23395dec
	.word	0x3fefe3ec, 0x32d3d1a2, 0x3fefefa5, 0x5fdfa9c5
	.word	0x3feffb66, 0xaffed31b, 0x3ff00730, 0x28d7233e
	.word	0x3ff01301, 0xd0125b51, 0x3ff01edb, 0xab5e2ab6
	.word	0x3ff02abd, 0xc06c31cc, 0x3ff036a8, 0x14f204ab
	.word	0x3ff0429a, 0xaea92de0, 0x3ff04e95, 0x934f312e
	.word	0x3ff05a98, 0xc8a58e51, 0x3ff066a4, 0x5471c3c2
	.word	0x3fef72b8, 0x3c7d517b, 0x3fef7ed4, 0x8695bbc0
	.word	0x3fef8af9, 0x388c8dea, 0x3fef9726, 0x58375d2f
	.word	0x3fefa35b, 0xeb6fcb75, 0x3fefaf99, 0xf8138a1c
	.word	0x3fefbbe0, 0x84045cd4, 0x3fefc82f, 0x95281c6b
	.word	0x3fefd487, 0x3168b9aa, 0x3fefe0e7, 0x5eb44027
	.word	0x3fefed50, 0x22fcd91d, 0x3feff9c1, 0x8438ce4d
	.word	0x3ff0063b, 0x88628cd6, 0x3ff012be, 0x3578a819
	.word	0x3ff01f49, 0x917ddc96, 0x3ff02bdd, 0xa27912d1
	.word	0x3fef387a, 0x6e756238, 0x3fef451f, 0xfb82140a
	.word	0x3fef51ce, 0x4fb2a63f, 0x3fef5e85, 0x711ece75
	.word	0x3fef6b45, 0x65e27cdd, 0x3fef780e, 0x341ddf29
	.word	0x3fef84df, 0xe1f56381, 0x3fef91ba, 0x7591bb70
	.word	0x3fef9e9d, 0xf51fdee1, 0x3fefab8a, 0x66d10f13
	.word	0x3fefb87f, 0xd0dad990, 0x3fefc57e, 0x39771b2f
	.word	0x3fefd285, 0xa6e4030b, 0x3fefdf96, 0x1f641589
	.word	0x3fefecaf, 0xa93e2f56, 0x3feff9d2, 0x4abd886b
	.word	0x3fef06fe, 0x0a31b715, 0x3fef1432, 0xedeeb2fd
	.word	0x3fef2170, 0xfc4cd831, 0x3fef2eb8, 0x3ba8ea32
	.word	0x3fef3c08, 0xb26416ff, 0x3fef4962, 0x66e3fa2d
	.word	0x3fef56c5, 0x5f929ff1, 0x3fef6431, 0xa2de883b
	.word	0x3fef71a7, 0x373aa9cb, 0x3fef7f26, 0x231e754a
	.word	0x3fef8cae, 0x6d05d866, 0x3fef9a40, 0x1b7140ef
	.word	0x3fefa7db, 0x34e59ff7, 0x3fefb57f, 0xbfec6cf4
	.word	0x3fefc32d, 0xc313a8e5, 0x3fefd0e5, 0x44ede173
	.word	0x3feedea6, 0x4c123422, 0x3feeec70, 0xdf1c5175
	.word	0x3feefa45, 0x04ac801c, 0x3fef0822, 0xc367a024
	.word	0x3fef160a, 0x21f72e2a, 0x3fef23fb, 0x2709468a
	.word	0x3fef31f5, 0xd950a897, 0x3fef3ffa, 0x3f84b9d4
	.word	0x3fef4e08, 0x6061892d, 0x3fef5c20, 0x42a7d232
	.word	0x3fef6a41, 0xed1d0057, 0x3fef786d, 0x668b3237
	.word	0x3fef86a2, 0xb5c13cd0, 0x3fef94e1, 0xe192aed2
	.word	0x3fefa32a, 0xf0d7d3de, 0x3fefb17d, 0xea6db7d7
	.word	0x3feebfda, 0xd5362a27, 0x3feece41, 0xb817c114
	.word	0x3feedcb2, 0x99fddd0d, 0x3feeeb2d, 0x81d8abff
	.word	0x3feef9b2, 0x769d2ca7, 0x3fef0841, 0x7f4531ee
	.word	0x3fef16da, 0xa2cf6642, 0x3fef257d, 0xe83f4eef
	.word	0x3fef342b, 0x569d4f82, 0x3fef42e2, 0xf4f6ad27
	.word	0x3fef51a4, 0xca5d920f, 0x3fef6070, 0xdde910d2
	.word	0x3fef6f47, 0x36b527da, 0x3fef7e27, 0xdbe2c4cf
	.word	0x3fef8d12, 0xd497c7fd, 0x3fef9c08, 0x27ff07cc
	.word	0x3feeab07, 0xdd485429, 0x3feeba11, 0xfba87a03
	.word	0x3feec926, 0x8a5946b7, 0x3feed845, 0x90998b93
	.word	0x3feee76f, 0x15ad2148, 0x3feef6a3, 0x20dceb71
	.word	0x3fef05e1, 0xb976dc09, 0x3fef152a, 0xe6cdf6f4
	.word	0x3fef247e, 0xb03a5585, 0x3fef33dd, 0x1d1929fd
	.word	0x3fef4346, 0x34ccc320, 0x3fef52b9, 0xfebc8fb7
	.word	0x3fef6238, 0x82552225, 0x3fef71c1, 0xc70833f6
	.word	0x3fef8155, 0xd44ca973, 0x3fef90f4, 0xb19e9538
	.word	0x3feea09e, 0x667f3bcd, 0x3feeb052, 0xfa75173e
	.word	0x3feec012, 0x750bdabf, 0x3feecfdc, 0xddd47645
	.word	0x3feedfb2, 0x3c651a2f, 0x3feeef92, 0x98593ae5
	.word	0x3feeff7d, 0xf9519484, 0x3fef0f74, 0x66f42e87
	.word	0x3fef1f75, 0xe8ec5f74, 0x3fef2f82, 0x86ead08a
	.word	0x3fef3f9a, 0x48a58174, 0x3fef4fbd, 0x35d7cbfd
	.word	0x3fef5feb, 0x564267c9, 0x3fef7024, 0xb1ab6e09
	.word	0x3fef8069, 0x4fde5d3f, 0x3fef90b9, 0x38ac1cf6
	.word	0x3feea114, 0x73eb0187, 0x3feeb17b, 0x0976cfdb
	.word	0x3feec1ed, 0x0130c132, 0x3feed26a, 0x62ff86f0
	.word	0x3feee2f3, 0x36cf4e62, 0x3feef387, 0x8491c491
	.word	0x3fef0427, 0x543e1a12, 0x3fef14d2, 0xadd106d9
	.word	0x3fef2589, 0x994cce13, 0x3fef364c, 0x1eb941f7
	.word	0x3fef471a, 0x4623c7ad, 0x3fef57f4, 0x179f5b21
	.word	0x3fef68d9, 0x9b4492ed, 0x3fef79ca, 0xd931a436
	.word	0x3fef8ac7, 0xd98a6699, 0x3fef9bd0, 0xa478580f
	.word	0x3feeace5, 0x422aa0db, 0x3feebe05, 0xbad61778
	.word	0x3feecf32, 0x16b5448c, 0x3feee06a, 0x5e0866d9
	.word	0x3feef1ae, 0x99157736, 0x3fef02fe, 0xd0282c8a
	.word	0x3fef145b, 0x0b91ffc6, 0x3fef25c3, 0x53aa2fe2
	.word	0x3fef3737, 0xb0cdc5e5, 0x3fef48b8, 0x2b5f98e5
	.word	0x3fef5a44, 0xcbc8520f, 0x3fef6bdd, 0x9a7670b3
	.word	0x3fef7d82, 0x9fde4e50, 0x3fef8f33, 0xe47a22a2
	.word	0x3fefa0f1, 0x70ca07ba, 0x3fefb2bb, 0x4d53fe0d
	.word	0x3feec491, 0x82a3f090, 0x3feed674, 0x194bb8d5
	.word	0x3feee863, 0x19e32323, 0x3feefa5e, 0x8d07f29e
	.word	0x3fef0c66, 0x7b5de565, 0x3fef1e7a, 0xed8eb8bb
	.word	0x3fef309b, 0xec4a2d33, 0x3fef42c9, 0x80460ad8
	.word	0x3fef5503, 0xb23e255d, 0x3fef674a, 0x8af46052
	.word	0x3fef799e, 0x1330b358, 0x3fef8bfe, 0x53c12e59
	.word	0x3fef9e6b, 0x5579fdbf, 0x3fefb0e5, 0x21356eba
	.word	0x3fefc36b, 0xbfd3f37a, 0x3fefd5ff, 0x3a3c2774
	.word	0x3feee89f, 0x995ad3ad, 0x3feefb4c, 0xe622f2ff
	.word	0x3fef0e07, 0x298db666, 0x3fef20ce, 0x6c9a8952
	.word	0x3fef33a2, 0xb84f15fb, 0x3fef4684, 0x15b749b1
	.word	0x3fef5972, 0x8de5593a, 0x3fef6c6e, 0x29f1c52a
	.word	0x3fef7f76, 0xf2fb5e47, 0x3fef928c, 0xf22749e4
	.word	0x3fefa5b0, 0x30a1064a, 0x3fefb8e0, 0xb79a6f1f
	.word	0x3fefcc1e, 0x904bc1d2, 0x3fefdf69, 0xc3f3a207
	.word	0x3feff2c2, 0x5bd71e09, 0x3ff00628, 0x6141b33d
	.word	0x3fef199b, 0xdd85529c, 0x3fef2d1c, 0xd9fa652c
	.word	0x3fef40ab, 0x5fffd07a, 0x3fef5447, 0x78fafb22
	.word	0x3fef67f1, 0x2e57d14b, 0x3fef7ba8, 0x8988c933
	.word	0x3fef8f6d, 0x9406e7b5, 0x3fefa340, 0x5751c4db
	.word	0x3fefb720, 0xdcef9069, 0x3fefcb0f, 0x2e6d1675
	.word	0x3fefdf0b, 0x555dc3fa, 0x3feff315, 0x5b5bab74
	.word	0x3ff0072d, 0x4a07897c, 0x3ff01b53, 0x2b08c968
	.word	0x3ff02f87, 0x080d89f2, 0x3ff043c8, 0xeacaa1d6
	.word	0x3fef5818, 0xdcfba487, 0x3fef6c76, 0xe862e6d3
	.word	0x3fef80e3, 0x16c98398, 0x3fef955d, 0x71ff6075
	.word	0x3fefa9e6, 0x03db3285, 0x3fefbe7c, 0xd63a8315
	.word	0x3fefd321, 0xf301b460, 0x3fefe7d5, 0x641c0658
	.word	0x3feffc97, 0x337b9b5f, 0x3ff01167, 0x6b197d17
	.word	0x3ff02646, 0x14f5a129, 0x3ff03b33, 0x3b16ee12
	.word	0x3ff0502e, 0xe78b3ff6, 0x3ff06539, 0x24676d76
	.word	0x3ff07a51, 0xfbc74c83, 0x3ff08f79, 0x77cdb740
	.word	0x3fefa4af, 0xa2a490da, 0x3fefb9f4, 0x867cca6e
	.word	0x3fefcf48, 0x2d8e67f1, 0x3fefe4aa, 0xa2188510
	.word	0x3feffa1b, 0xee615a27, 0x3ff00f9c, 0x1cb6412a
	.word	0x3ff0252b, 0x376bba97, 0x3ff03ac9, 0x48dd7274
	.word	0x3ff05076, 0x5b6e4540, 0x3ff06632, 0x798844f8
	.word	0x3ff07bfd, 0xad9cbe14, 0x3ff091d8, 0x02243c89
	.word	0x3ff0a7c1, 0x819e90d8, 0x3ff0bdba, 0x3692d514
	.word	0x3ff0d3c2, 0x2b8f71f1, 0x3ff0e9d9, 0x6b2a23d9

	.word	0x7149f2ca, 0x0da24260	! 1.0e30f, 1.0e-30f
	.word	0x3ecebfbe, 0x9d182250	! KA2 = 3.66556671660783833261e-06
	.word	0x3f662e43, 0xe2528362	! KA1 = 2.70760782821392980564e-03
	.word	0x40771547, 0x652b82fe	! K256ONLN2 = 369.3299304675746271
	.word	0x42aeac4f, 0x42b17218	! THRESHOLD = 87.3365402f
					! THRESHOLDL = 88.7228394f
! local storage indices

#define tmp0		STACK_BIAS-32
#define tmp1		STACK_BIAS-28
#define tmp2		STACK_BIAS-24
#define tmp3		STACK_BIAS-20
#define tmp4		STACK_BIAS-16
#define tmp5		STACK_BIAS-12
#define tmp6		STACK_BIAS-8
#define tmp7		STACK_BIAS-4

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps 		0x20

#define I5_THRESHOLD	%i5
#define G1_CONST_TBL	%g5
#define G5_CONST	%g1

#define F62_K256ONLN2	%f62
#define F60_KA2		%f60
#define F58_KA1		%f58

#define THRESHOLDL	%f0

! register use
! i0  n
! i1  x
! i2  stridex
! i3  y
! i4  stridey

! i5  0x42aeac4f (87.3365402f)

! g1  CONST_TBL
! g5  0x7fffffff

! f62 K256ONLN2 = 369.3299304675746271
! f60 KA2 = 3.66556671660783833261e-06
! f58 KA1 = 2.70760782821392980564e-03


!		!!!!!  Algorithm  !!!!!
!
!  double y, dtmp, drez;
!  int k, sign, Xi;
!  float X, Y;
!  int THRESHOLD = 0x42aeac4f; /* 87.3365402f */
!  float THRESHOLDL = 88.7228394f;
!  double KA2 = 3.66556671660783833261e-06;
!  double KA1 = 2.70760782821392980564e-03;
!  double K256ONLN2 = 369.3299304675746271;
!  char *CONST_TBL;
!
!  X  = px[0];
!  Xi = ((int*)px)[0];
!  ax = Xi & 0x7fffffff;
!
!  if (ax > THRESHOLD) {
!    sign = ((unsigned)Xi >> 29) & 4;
!    if (ax >= 0x7f800000) {      /* Inf or NaN */
!      if (ax > 0x7f800000) {     /* NaN */
!        Y = X * X;               /* NaN -> NaN */
!        return Y;
!      }
!      Y = (sign) ? zero : X;     /* +Inf -> +Inf , -Inf -> zero */
!      return Y;
!    }
!
!    if ( X < 0.0f || X >= THRESHOLDL ) {
!      Y = ((float*)(CONST_TBL + 2048 + sign))[0];
!         /* Xi >= THRESHOLDL : Y = 1.0e+30f */
!         /* Xi < -THRESHOLD  : Y = 1.0e-30f */
!      Y =  Y * Y;
!         /* Xi >= THRESHOLDL : +Inf + overflow  */
!         /* Xi < -THRESHOLD  : +0 + underflow */
!      return Y;
!    }
!  }
!  vis_write_gsr(12 << 3);
!  y = (double) X;
!  y = K256ONLN2 * y;
!  k = (int) y;
!  dtmp = (double) k;
!  y -= dtmp;
!  dtmp = y * KA2;
!  dtmp += KA1;
!  y *= dtmp;
!  y = (y * KA2 + KA1) * y;
!  ((int*)&drez)[0] = k;
!  ((int*)&drez)[1] = 0;
!  ((float*)&drez)[0] = vis_fpackfix(drez);
!  k &= 255;
!  k <<= 3;
!  dtmp = ((double*)(CONST_TBL + k))[0];
!  drez = vis_fpadd32(drez,dtmp);
!  y *= drez;
!  y += drez;
!  Y = (float) y;
!
!
!  fstod %f16,%f40			! y = (double) X
!  fmuld F62_K256ONLN2,%f40,%f40	! y *= K256ONLN2
!  fdtoi %f40,%f16			! k = (int) y
!  st  %f16,[%fp+tmp0]			! store k
!  fitod %f16,%f34			! dtmp = (double) k
!  fpackfix  %f16,%f16			! ((float*)&drez)[0] = vis_fpackfix(drez)
!  fsubd %f40,%f34,%f40			! y -= dtmp
!  fmuld F60_KA2,%f40,%f34		! dtmp = y * KA2
!  faddd F58_KA1,%f34,%f34		! dtmp += KA1
!  ld  [%fp+tmp0],%o0			! load k
!  fmuld %f34,%f40,%f40			! y *= dtmp
!  and %o0,255,%o0			! k &= 255
!  sll  %o0,3,%o0			! k <<= 3
!  ldd [G1_CONST_TBL+%o0],%f34		! dtmp = ((double*)(CONST_TBL + k))[0]
!  fpadd32 %f16,%f34,%f34		! drez = vis_fpadd32(drez,dtmp)
!  fmuld %f34,%f40,%f40			! y *= drez
!  faddd %f34,%f40,%f40			! y += drez
!  fdtos %f40,%f26			! (float) y
!--------------------------------------------------------------------

	ENTRY(__vexpf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,g5)

	wr	%g0,0x82,%asi		! set %asi for non-faulting loads
	wr	%g0,0x60,%gsr

	sll	%i2,2,%i2
	sll	%i4,2,%i4

	ldd	[G1_CONST_TBL+2056],F60_KA2
	sethi	%hi(0x7ffffc00),G5_CONST
	ldd	[G1_CONST_TBL+2064],F58_KA1
	add	G5_CONST,1023,G5_CONST
	ldd	[G1_CONST_TBL+2072],F62_K256ONLN2
	ld	[G1_CONST_TBL+2080],I5_THRESHOLD
	ld	[G1_CONST_TBL+2084],THRESHOLDL

	subcc	%i0,8,%i0
	bneg,pn	%icc,.tail
	fzeros	%f3

.main_loop_preload:

! preload 8 elements and get absolute values
	ld	[%i1],%l0		! (0) Xi = ((int*)px)[0]
	fzeros	%f5
	ld	[%i1],%f16		! (0) X = px[0]
	fzeros	%f7
	add	%i1,%i2,%o5		! px += stridex
	ld	[%o5],%l1		! (1) Xi = ((int*)px)[0]
	and	%l0,G5_CONST,%l0	! (0) ax = Xi & 0x7fffffff
	fzeros	%f9
	ld	[%o5],%f2		! (1) X = px[0]
	fzeros	%f11
	add	%o5,%i2,%i1		! px += stridex
	ld	[%i1],%l2		! (2) Xi = ((int*)px)[0]
	and	%l1,G5_CONST,%l1	! (1) ax = Xi & 0x7fffffff
	fzeros	%f13
	ld	[%i1],%f4		! (2) X = px[0]
	fzeros	%f15
	add	%i1,%i2,%o5		! px += stridex
	ld	[%o5],%l3		! (3) Xi = ((int*)px)[0]
	and	%l2,G5_CONST,%l2	! (2) ax = Xi & 0x7fffffff
	fzeros	%f17
	ld	[%o5],%f6		! (3) X = px[0]
	add	%o5,%i2,%o0		! px += stridex
	ld	[%o0],%l4		! (4) Xi = ((int*)px)[0]
	and	%l3,G5_CONST,%l3	! (3) ax = Xi & 0x7fffffff
	add	%o0,%i2,%o1		! px += stridex
	ld	[%o1],%l5		! (5) Xi = ((int*)px)[0]
	add	%o1,%i2,%o2		! px += stridex
	ld	[%o2],%l6		! (6) Xi = ((int*)px)[0]
	and	%l4,G5_CONST,%l4	! (4) ax = Xi & 0x7fffffff
	add	%o2,%i2,%o3		! px += stridex
	ld	[%o3],%l7		! (7) Xi = ((int*)px)[0]
	add	%o3,%i2,%i1		! px += stridex
	and	%l5,G5_CONST,%l5	! (5) ax = Xi & 0x7fffffff
	and	%l6,G5_CONST,%l6	! (6) ax = Xi & 0x7fffffff
	ba	.main_loop
	and	%l7,G5_CONST,%l7	! (7) ax = Xi & 0x7fffffff

	.align	16
.main_loop:
	cmp	%l0,I5_THRESHOLD
	bg,pn	%icc,.spec0		! (0) if (ax > THRESHOLD)
	lda	[%o0]%asi,%f8		! (4) X = px[0]
	fstod	%f16,%f40		! (0) y = (double) X
.spec0_cont:
	cmp	%l1,I5_THRESHOLD
	bg,pn	%icc,.spec1		! (1) if (ax > THRESHOLD)
	lda	[%o1]%asi,%f10		! (5) X = px[0]
	fstod	%f2,%f42		! (1) y = (double) X
.spec1_cont:
	cmp	%l2,I5_THRESHOLD
	bg,pn	%icc,.spec2		! (2) if (ax > THRESHOLD)
	lda	[%o2]%asi,%f12		! (6) X = px[0]
	fstod	%f4,%f44		! (2) y = (double) X
.spec2_cont:
	cmp	%l3,I5_THRESHOLD
	bg,pn	%icc,.spec3		! (3) if (ax > THRESHOLD)
	lda	[%o3]%asi,%f14		! (7) X = px[0]
	fstod	%f6,%f46		! (3) y = (double) X
.spec3_cont:
	cmp	%l4,I5_THRESHOLD
	bg,pn	%icc,.spec4		! (4) if (ax > THRESHOLD)
	fmuld	F62_K256ONLN2,%f40,%f40	! (0) y *= K256ONLN2
	fstod	%f8,%f48		! (4) y = (double) X
.spec4_cont:
	cmp	%l5,I5_THRESHOLD
	bg,pn	%icc,.spec5		! (5) if (ax > THRESHOLD)
	fmuld	F62_K256ONLN2,%f42,%f42	! (1) y *= K256ONLN2
	fstod	%f10,%f50		! (5) y = (double) X
.spec5_cont:
	cmp	%l6,I5_THRESHOLD
	bg,pn	%icc,.spec6		! (6) if (ax > THRESHOLD)
	fmuld	F62_K256ONLN2,%f44,%f44	! (2) y *= K256ONLN2
	fstod	%f12,%f52		! (6) y = (double) X
.spec6_cont:
	cmp	%l7,I5_THRESHOLD
	bg,pn	%icc,.spec7		! (7) if (ax > THRESHOLD)
	fmuld	F62_K256ONLN2,%f46,%f46	! (3) y *= K256ONLN2
	fstod	%f14,%f54		! (7) y = (double) X
.spec7_cont:
	fdtoi	%f40,%f16		! (0) k = (int) y
	st	%f16,[%fp+tmp0]
	fmuld	F62_K256ONLN2,%f48,%f48	! (4) y *= K256ONLN2

	fdtoi	%f42,%f2		! (1) k = (int) y
	st	%f2,[%fp+tmp1]
	fmuld	F62_K256ONLN2,%f50,%f50	! (5) y *= K256ONLN2

	fdtoi	%f44,%f4		! (2) k = (int) y
	st	%f4,[%fp+tmp2]
	fmuld	F62_K256ONLN2,%f52,%f52	! (6) y *= K256ONLN2

	fdtoi	%f46,%f6		! (3) k = (int) y
	st	%f6,[%fp+tmp3]
	fmuld	F62_K256ONLN2,%f54,%f54	! (7) y *= K256ONLN2

	fdtoi	%f48,%f8		! (4) k = (int) y
	st	%f8,[%fp+tmp4]

	fdtoi	%f50,%f10		! (5) k = (int) y
	st	%f10,[%fp+tmp5]

	fitod	%f16,%f34		! (0) dtmp = (double) k
	fpackfix	%f16,%f16	! (0) ((float*)&drez)[0] = vis_fpackfix(drez)
	nop
	nop

	fdtoi	%f52,%f12		! (6) k = (int) y
	st	%f12,[%fp+tmp6]

	fdtoi	%f54,%f14		! (7) k = (int) y
	st	%f14,[%fp+tmp7]

	lda	[%i1]%asi,%l0		! (8) Xi = ((int*)px)[0]
	add	%i1,%i2,%o5		! px += stridex
	fitod	%f2,%f18		! (1) dtmp = (double) k
	fpackfix	%f2,%f2		! (1) ((float*)&drez)[0] = vis_fpackfix(drez)

	lda	[%o5]%asi,%l1		! (9) Xi = ((int*)px)[0]
	add	%o5,%i2,%i1		! px += stridex
	fitod	%f4,%f20		! (2) dtmp = (double) k
	fpackfix	%f4,%f4		! (2) ((float*)&drez)[0] = vis_fpackfix(drez)

	lda	[%i1]%asi,%l2		! (10) Xi = ((int*)px)[0]
	add	%i1,%i2,%o5		! px += stridex
	fitod	%f6,%f22		! (3) dtmp = (double) k
	fpackfix	%f6,%f6		! (3) ((float*)&drez)[0] = vis_fpackfix(drez)

	lda	[%o5]%asi,%l3		! (11) Xi = ((int*)px)[0]
	add	%o5,%i2,%i1		! px += stridex
	fitod	%f8,%f24		! (4) dtmp = (double) k
	fpackfix	%f8,%f8		! (4) ((float*)&drez)[0] = vis_fpackfix(drez)

	fitod	%f10,%f26		! (5) dtmp = (double) k
	fpackfix	%f10,%f10	! (5) ((float*)&drez)[0] = vis_fpackfix(drez)

	fitod	%f12,%f28		! (6) dtmp = (double) k
	fpackfix	%f12,%f12	! (6) ((float*)&drez)[0] = vis_fpackfix(drez)

	fitod	%f14,%f30		! (7) dtmp = (double) k
	fpackfix	%f14,%f14	! (7) ((float*)&drez)[0] = vis_fpackfix(drez)

	ld	[%fp+tmp0],%o0		! (0) load k
	and	%l0,G5_CONST,%l0	! (8) ax = Xi & 0x7fffffff
	fsubd	%f40,%f34,%f40		! (0) y -= dtmp

	ld	[%fp+tmp1],%o1		! (1) load k
	and	%l1,G5_CONST,%l1	! (9) ax = Xi & 0x7fffffff
	fsubd	%f42,%f18,%f42		! (1) y -= dtmp

	ld	[%fp+tmp2],%o2		! (2) load k
	and	%l2,G5_CONST,%l2	! (10) ax = Xi & 0x7fffffff
	and	%o0,255,%o0		! (0) k &= 255
	fsubd	%f44,%f20,%f44		! (2) y -= dtmp

	ld	[%fp+tmp3],%o3		! (3) load k
	and	%o1,255,%o1		! (1) k &= 255
	fsubd	%f46,%f22,%f46		! (3) y -= dtmp

	sll	%o0,3,%o0		! (0) k <<= 3
	sll	%o1,3,%o1		! (1) k <<= 3
	fmuld	F60_KA2,%f40,%f34	! (0) dtmp = y * KA2
	fsubd	%f48,%f24,%f48		! (4) y -= dtmp

	and	%l3,G5_CONST,%l3	! (11) ax = Xi & 0x7fffffff
	and	%o2,255,%o2		! (2) k &= 255
	fmuld	F60_KA2,%f42,%f18	! (1) dtmp = y * KA2
	fsubd	%f50,%f26,%f50		! (5) y -= dtmp

	sll	%o2,3,%o2		! (2) k <<= 3
	fmuld	F60_KA2,%f44,%f20	! (2) dtmp = y * KA2
	fsubd	%f52,%f28,%f52		! (6) y -= dtmp

	ld	[%fp+tmp4],%o4		! (4) load k
	and	%o3,255,%o3		! (3) k &= 255
	fmuld	F60_KA2,%f46,%f22	! (3) dtmp = y * KA2
	fsubd	%f54,%f30,%f54		! (7) y -= dtmp

	ld	[%fp+tmp5],%o5		! (5) load k
	sll	%o3,3,%o3		! (3) k <<= 3
	fmuld	F60_KA2,%f48,%f24	! (4) dtmp = y * KA2
	faddd	F58_KA1,%f34,%f34	! (0) dtmp += KA1

	ld	[%fp+tmp6],%o7		! (6) load k
	and	%o4,255,%o4		! (4) k &= 255
	fmuld	F60_KA2,%f50,%f26	! (5) dtmp = y * KA2
	faddd	F58_KA1,%f18,%f18	! (1) dtmp += KA1

	ld	[%fp+tmp7],%l4		! (7) load k
	and	%o5,255,%o5		! (5) k &= 255
	fmuld	F60_KA2,%f52,%f28	! (6) dtmp = y * KA2
	faddd	F58_KA1,%f20,%f20	! (2) dtmp += KA1

	sll	%o5,3,%o5		! (5) k <<= 3
	fmuld	F60_KA2,%f54,%f30	! (7) dtmp = y * KA2
	faddd	F58_KA1,%f22,%f22	! (3) dtmp += KA1

	fmuld	%f34,%f40,%f40		! (0) y *= dtmp
	ldd	[G1_CONST_TBL+%o0],%f34	! (0) dtmp = ((double*)(CONST_TBL + k))[0]
	and	%l4,255,%l4		! (7) k &= 255
	faddd	F58_KA1,%f24,%f24	! (4) dtmp += KA1

	fmuld	%f18,%f42,%f42		! (1) y *= dtmp
	ldd	[G1_CONST_TBL+%o1],%f18	! (1) dtmp = ((double*)(CONST_TBL + k))[0]
	sll	%l4,3,%l4		! (7) k <<= 3
	faddd	F58_KA1,%f26,%f26	! (5) dtmp += KA1

	fmuld	%f20,%f44,%f44		! (2) y *= dtmp
	ldd	[G1_CONST_TBL+%o2],%f20	! (2) dtmp = ((double*)(CONST_TBL + k))[0]
	faddd	F58_KA1,%f28,%f28	! (6) dtmp += KA1

	fmuld	%f22,%f46,%f46		! (3) y *= dtmp
	ldd	[G1_CONST_TBL+%o3],%f22	! (3) dtmp = ((double*)(CONST_TBL + k))[0]
	sll	%o4,3,%o4		! (4) k <<= 3
	faddd	F58_KA1,%f30,%f30	! (7) dtmp += KA1

	fmuld	%f24,%f48,%f48		! (4) y *= dtmp
	ldd	[G1_CONST_TBL+%o4],%f24	! (4) dtmp = ((double*)(CONST_TBL + k))[0]
	and	%o7,255,%o7		! (6) k &= 255
	fpadd32 %f16,%f34,%f34		! (0) drez = vis_fpadd32(drez,dtmp)

	fmuld	%f26,%f50,%f50		! (5) y *= dtmp
	ldd	[G1_CONST_TBL+%o5],%f26	! (5) dtmp = ((double*)(CONST_TBL + k))[0]
	sll	%o7,3,%o7		! (6) k <<= 3
	fpadd32 %f2,%f18,%f18		! (1) drez = vis_fpadd32(drez,dtmp)

	fmuld	%f28,%f52,%f52		! (6) y *= dtmp
	ldd	[G1_CONST_TBL+%o7],%f28	! (6) dtmp = ((double*)(CONST_TBL + k))[0]
	sll	%i2,2,%o0
	fpadd32 %f4,%f20,%f20		! (2) drez = vis_fpadd32(drez,dtmp)

	fmuld	%f30,%f54,%f54		! (7) y *= dtmp
	ldd	[G1_CONST_TBL+%l4],%f30	! (7) dtmp = ((double*)(CONST_TBL + k))[0]
	sub	%i1,%o0,%o0
	fpadd32 %f6,%f22,%f22		! (3) drez = vis_fpadd32(drez,dtmp)

	lda	[%i1]%asi,%l4		! (12) Xi = ((int*)px)[0]
	add	%i1,%i2,%o1		! px += stridex
	fpadd32 %f8,%f24,%f24		! (4) drez = vis_fpadd32(drez,dtmp)
	fmuld	%f34,%f40,%f40		! (0) y *= drez

	lda	[%o1]%asi,%l5		! (13) Xi = ((int*)px)[0]
	add	%o1,%i2,%o2		! px += stridex
	fpadd32 %f10,%f26,%f26		! (5)  drez = vis_fpadd32(drez,dtmp)
	fmuld	%f18,%f42,%f42		! (1)  y *= drez

	lda	[%o2]%asi,%l6		! (14) Xi = ((int*)px)[0]
	add	%o2,%i2,%o3		! px += stridex
	fpadd32 %f12,%f28,%f28		! (6)  drez = vis_fpadd32(drez,dtmp)
	fmuld	%f20,%f44,%f44		! (2)  y *= drez

	lda	[%o3]%asi,%l7		! (15) Xi = ((int*)px)[0]
	add	%o3,%i2,%i1		! px += stridex
	fpadd32 %f14,%f30,%f30		! (7)  drez = vis_fpadd32(drez,dtmp)
	fmuld	%f22,%f46,%f46		! (3)  y *= drez

	lda	[%o0]%asi,%f16		! (8)  X = px[0]
	add	%o0,%i2,%o5
	fmuld	%f24,%f48,%f48		! (4)  y *= drez
	faddd	%f34,%f40,%f40		! (0)  y += drez

	lda	[%o5]%asi,%f2		! (9)  X = px[0]
	add	%o5,%i2,%o0
	fmuld	%f26,%f50,%f50		! (5)  y *= drez
	faddd	%f18,%f42,%f42		! (1)  y += drez

	lda	[%o0]%asi,%f4		! (10) X = px[0]
	add	%o0,%i2,%o5
	fmuld	%f28,%f52,%f52		! (6)  y *= drez
	faddd	%f20,%f44,%f44		! (2)  y += drez

	lda	[%o5]%asi,%f6		! (11) X = px[0]
	add	%o5,%i2,%o0
	fmuld	%f30,%f54,%f54		! (7)  y *= drez
	faddd	%f22,%f46,%f46		! (3)  y += drez

	and	%l4,G5_CONST,%l4	! (12) ax = Xi & 0x7fffffff
	faddd	%f24,%f48,%f48		! (4)  y += drez

	and	%l5,G5_CONST,%l5	! (13) ax = Xi & 0x7fffffff
	faddd	%f26,%f50,%f50		! (5)  y += drez

	and	%l6,G5_CONST,%l6	! (14) ax = Xi & 0x7fffffff
	faddd	%f28,%f52,%f52		! (6)  y += drez

	and	%l7,G5_CONST,%l7	! (15) ax = Xi & 0x7fffffff
	faddd	%f30,%f54,%f54		! (7)  y += drez

	fdtos	%f40,%f26		! (0) (float) y
	st	%f26,[%i3]
	add	%i3,%i4,%o4		! py += stridey

	fdtos	%f42,%f18		! (1) (float) y
	st	%f18,[%o4]
	add	%o4,%i4,%i3		! py += stridey

	fdtos	%f44,%f20		! (2) (float) y
	st	%f20,[%i3]
	add	%i3,%i4,%o4		! py += stridey

	fdtos	%f46,%f22		! (3) (float) y
	st	%f22,[%o4]
	add	%o4,%i4,%i3		! py += stridey

	fdtos	%f48,%f24		! (4) (float) y
	st	%f24,[%i3]
	subcc	%i0,8,%i0
	add	%i3,%i4,%o4		! py += stridey

	fdtos	%f50,%f26		! (5) (float) y
	st	%f26,[%o4]
	add	%o4,%i4,%o5		! py += stridey
	add	%i4,%i4,%o7

	fdtos	%f52,%f28		! (6) (float) y
	st	%f28,[%o5]
	add	%o5,%i4,%o4		! py += stridey
	add	%o5,%o7,%i3		! py += stridey

	fdtos	%f54,%f30		! (7) (float) y
	st	%f30,[%o4]
	bpos,pt	%icc,.main_loop
	nop
.after_main_loop:
	sll	%i2,3,%o2
	sub	%i1,%o2,%i1

.tail:
	add	%i0,8,%i0
	subcc	%i0,1,%i0
	bneg,pn	%icc,.exit

	ld	[%i1],%l0
	ld	[%i1],%f2
	add	%i1,%i2,%i1

.tail_loop:
	and	%l0,G5_CONST,%l1
	cmp	%l1,I5_THRESHOLD
	bg,pn	%icc,.tail_spec
	nop
.tail_spec_cont:
	fstod	%f2,%f40
	fmuld	F62_K256ONLN2,%f40,%f40
	fdtoi	%f40,%f2
	st	%f2,[%fp+tmp0]
	fitod	%f2,%f16
	fpackfix	%f2,%f2
	fsubd	%f40,%f16,%f40
	fmuld	F60_KA2,%f40,%f16
	faddd	F58_KA1,%f16,%f16
	ld	[%fp+tmp0],%o0
	fmuld	%f16,%f40,%f40
	and	%o0,255,%o0
	sll	%o0,3,%o0
	ldd	[G1_CONST_TBL+%o0],%f16
	fpadd32 %f2,%f16,%f16
	lda	[%i1]%asi,%l0
	fmuld	%f16,%f40,%f40
	lda	[%i1]%asi,%f2
	faddd	%f16,%f40,%f40
	add	%i1,%i2,%i1
	fdtos	%f40,%f16
	st	%f16,[%i3]
	add	%i3,%i4,%i3
	subcc	%i0,1,%i0
	bpos,pt	%icc,.tail_loop
	nop

.exit:
	ret
	restore

.tail_spec:
	sethi	%hi(0x7f800000),%o4
	cmp	%l1,%o4
	bl,pt	%icc,.tail_spec_out_of_range
	nop

	srl	%l0,29,%l0
	ble,pn	%icc,.tail_spec_inf
	andcc	%l0,4,%g0

! NaN -> NaN

	fmuls	%f2,%f2,%f2
	ba	.tail_spec_exit
	st	%f2,[%i3]

.tail_spec_inf:
	be,a,pn	%icc,.tail_spec_exit
	st	%f2,[%i3]

	ba	.tail_spec_exit
	st	%f3,[%i3]

.tail_spec_out_of_range:
	fcmpes	%fcc0,%f2,%f3
	fcmpes	%fcc1,%f2,THRESHOLDL
	fbl,pn	%fcc0,1f		! if ( X < 0.0f )
	nop
	fbl,pt	%fcc1,.tail_spec_cont	! if ( X < THRESHOLDL )
	nop
1:
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.tail_spec_exit:
	lda	[%i1]%asi,%l0
	lda	[%i1]%asi,%f2
	add	%i1,%i2,%i1

	subcc	%i0,1,%i0
	bpos,pt	%icc,.tail_loop
	add	%i3,%i4,%i3
	ba	.exit
	nop

	.align	16
.spec0:
	sethi	%hi(0x7f800000),%o5
	cmp	%l0,%o5
	bl,pt	%icc,.spec0_out_of_range
	sll	%i2,3,%o4

	ble,pn	%icc,.spec0_inf
	sub	%i1,%o4,%o4

! NaN -> NaN

	fmuls	%f16,%f16,%f16
	ba	.spec0_exit
	st	%f16,[%i3]

.spec0_inf:
	ld	[%o4],%l0
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec0_exit
	st	%f16,[%i3]

	ba	.spec0_exit
	st	%f3,[%i3]

.spec0_out_of_range:
	fcmpes	%fcc0,%f16,%f3
	fcmpes	%fcc1,%f16,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f16,%f40			! (0) y = (double) X
	fbl,a,pt	%fcc1,.spec0_cont	! if ( X < THRESHOLDL )
	fstod	%f16,%f40			! (0) y = (double) X
1:
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f16
	fmuls	%f16,%f16,%f16
	st	%f16,[%i3]

.spec0_exit:
	fmovs	%f2,%f16
	mov	%l1,%l0
	fmovs	%f4,%f2
	mov	%l2,%l1
	fmovs	%f6,%f4
	mov	%l3,%l2
	fmovs	%f8,%f6
	mov	%l4,%l3
	mov	%l5,%l4
	mov	%l6,%l5
	mov	%l7,%l6
	lda	[%i1]%asi,%l7
	add	%i1,%i2,%i1
	mov	%o1,%o0
	mov	%o2,%o1
	mov	%o3,%o2
	and	%l7,G5_CONST,%l7
	add	%o2,%i2,%o3

	subcc	%i0,1,%i0
	bpos,pt	%icc,.main_loop
	add	%i3,%i4,%i3
	ba	.after_main_loop
	nop

	.align	16
.spec1:
	sethi	%hi(0x7f800000),%o5
	cmp	%l1,%o5
	bge,pn	%icc,1f
	nop
	fcmpes	%fcc0,%f2,%f3
	fcmpes	%fcc1,%f2,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f2,%f42			! (1) y = (double) X
	fbl,a,pt	%fcc1,.spec1_cont	! if ( X < THRESHOLDL )
	fstod	%f2,%f42			! (1) y = (double) X
1:
	fmuld	F62_K256ONLN2,%f40,%f40
	fdtoi	%f40,%f16
	st	%f16,[%fp+tmp0]
	fitod	%f16,%f34
	fpackfix	%f16,%f16
	fsubd	%f40,%f34,%f40
	fmuld	F60_KA2,%f40,%f34
	faddd	F58_KA1,%f34,%f34
	ld	[%fp+tmp0],%o0
	fmuld	%f34,%f40,%f40
	and	%o0,255,%o0
	sll	%o0,3,%o0
	ldd	[G1_CONST_TBL+%o0],%f34
	fpadd32 %f16,%f34,%f34
	fmuld	%f34,%f40,%f40
	faddd	%f34,%f40,%f40
	fdtos	%f40,%f26
	st	%f26,[%i3]
	add	%i3,%i4,%i3

	cmp	%l1,%o5
	bl,pt	%icc,.spec1_out_of_range
	sll	%i2,3,%o4

	ble,pn	%icc,.spec1_inf
	sub	%i1,%o4,%o4

! NaN -> NaN

	fmuls	%f2,%f2,%f2
	ba	.spec1_exit
	st	%f2,[%i3]

.spec1_inf:
	add	%o4,%i2,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec1_exit
	st	%f2,[%i3]

	ba	.spec1_exit
	st	%f3,[%i3]

.spec1_out_of_range:
	sub	%i1,%o4,%o4
	add	%o4,%i2,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.spec1_exit:
	fmovs	%f4,%f16
	mov	%l2,%l0
	fmovs	%f6,%f2
	mov	%l3,%l1
	fmovs	%f8,%f4
	mov	%l4,%l2
	fmovs	%f10,%f6
	mov	%l5,%l3
	mov	%l6,%l4
	mov	%l7,%l5
	lda	[%i1]%asi,%l6
	add	%i1,%i2,%i1
	lda	[%i1]%asi,%l7
	add	%i1,%i2,%i1
	and	%l6,G5_CONST,%l6
	and	%l7,G5_CONST,%l7
	mov	%o2,%o0
	mov	%o3,%o1
	add	%o1,%i2,%o2
	add	%o2,%i2,%o3

	subcc	%i0,2,%i0
	bpos,pt	%icc,.main_loop
	add	%i3,%i4,%i3
	ba	.after_main_loop
	nop

	.align	16
.spec2:
	sethi	%hi(0x7f800000),%o5
	cmp	%l2,%o5
	bge,pn	%icc,1f
	nop
	fcmpes	%fcc0,%f4,%f3
	fcmpes	%fcc1,%f4,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f4,%f44			! (2) y = (double) X
	fbl,a,pt	%fcc1,.spec2_cont	! if ( X < THRESHOLDL )
	fstod	%f4,%f44			! (2) y = (double) X
1:
	fmuld	F62_K256ONLN2,%f40,%f40

	fmuld	F62_K256ONLN2,%f42,%f42

	fdtoi	%f40,%f16
	st	%f16,[%fp+tmp0]

	fdtoi	%f42,%f2
	st	%f2,[%fp+tmp1]

	fitod	%f16,%f34
	fpackfix	%f16,%f16

	fitod	%f2,%f18
	fpackfix	%f2,%f2

	fsubd	%f40,%f34,%f40

	fsubd	%f42,%f18,%f42

	fmuld	F60_KA2,%f40,%f34

	fmuld	F60_KA2,%f42,%f18

	faddd	F58_KA1,%f34,%f34

	faddd	F58_KA1,%f18,%f18

	ld	[%fp+tmp0],%o0
	fmuld	%f34,%f40,%f40

	ld	[%fp+tmp1],%o1
	fmuld	%f18,%f42,%f42

	and	%o0,255,%o0

	and	%o1,255,%o1

	sll	%o0,3,%o0

	sll	%o1,3,%o1

	ldd	[G1_CONST_TBL+%o0],%f34

	ldd	[G1_CONST_TBL+%o1],%f18

	fpadd32 %f16,%f34,%f34

	fpadd32 %f2,%f18,%f18

	fmuld	%f34,%f40,%f40

	fmuld	%f18,%f42,%f42

	faddd	%f34,%f40,%f40

	faddd	%f18,%f42,%f42

	fdtos	%f40,%f26
	st	%f26,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f42,%f18
	st	%f18,[%o4]
	add	%o4,%i4,%i3

	cmp	%l2,%o5
	sll	%i2,1,%o5
	bl,pt	%icc,.spec2_out_of_range
	sll	%i2,2,%o4

	ble,pn	%icc,.spec2_inf
	add	%o4,%o5,%o4

! NaN -> NaN

	fmuls	%f4,%f4,%f4
	ba	.spec2_exit
	st	%f4,[%i3]

.spec2_inf:
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec2_exit
	st	%f4,[%i3]

	ba	.spec2_exit
	st	%f3,[%i3]

.spec2_out_of_range:
	add	%o4,%o5,%o4
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.spec2_exit:
	fmovs	%f6,%f16
	mov	%l3,%l0
	mov	%o3,%o0
	fmovs	%f8,%f2
	mov	%l4,%l1
	add	%o0,%i2,%o1
	fmovs	%f10,%f4
	mov	%l5,%l2
	add	%o1,%i2,%o2
	fmovs	%f12,%f6
	mov	%l6,%l3
	mov	%l7,%l4
	lda	[%i1]%asi,%l5
	add	%i1,%i2,%i1
	add	%o2,%i2,%o3
	lda	[%i1]%asi,%l6
	add	%i1,%i2,%i1
	lda	[%i1]%asi,%l7
	add	%i1,%i2,%i1
	and	%l5,G5_CONST,%l5
	and	%l6,G5_CONST,%l6
	and	%l7,G5_CONST,%l7

	subcc	%i0,3,%i0
	bpos,pt	%icc,.main_loop
	add	%i3,%i4,%i3
	ba	.after_main_loop
	nop
.spec3:
	sethi	%hi(0x7f800000),%o5
	cmp	%l3,%o5
	bge,pn	%icc,1f
	nop
	fcmpes	%fcc0,%f6,%f3
	fcmpes	%fcc1,%f6,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f6,%f46			! (3) y = (double) X
	fbl,a,pt	%fcc1,.spec3_cont	! if ( X < THRESHOLDL )
	fstod	%f6,%f46			! (3) y = (double) X
1:
	fmuld	F62_K256ONLN2,%f40,%f40

	fmuld	F62_K256ONLN2,%f42,%f42

	fmuld	F62_K256ONLN2,%f44,%f44

	fdtoi	%f40,%f16
	st	%f16,[%fp+tmp0]

	fdtoi	%f42,%f2
	st	%f2,[%fp+tmp1]

	fdtoi	%f44,%f4
	st	%f4,[%fp+tmp2]

	fitod	%f16,%f34
	fpackfix	%f16,%f16

	fitod	%f2,%f18
	fpackfix	%f2,%f2

	fitod	%f4,%f20
	fpackfix	%f4,%f4

	fsubd	%f40,%f34,%f40

	fsubd	%f42,%f18,%f42

	fsubd	%f44,%f20,%f44

	fmuld	F60_KA2,%f40,%f34

	fmuld	F60_KA2,%f42,%f18

	fmuld	F60_KA2,%f44,%f20

	faddd	F58_KA1,%f34,%f34

	faddd	F58_KA1,%f18,%f18

	faddd	F58_KA1,%f20,%f20

	ld	[%fp+tmp0],%o0
	fmuld	%f34,%f40,%f40

	ld	[%fp+tmp1],%o1
	fmuld	%f18,%f42,%f42

	ld	[%fp+tmp2],%o2
	fmuld	%f20,%f44,%f44

	and	%o0,255,%o0
	and	%o1,255,%o1

	and	%o2,255,%o2
	sll	%o0,3,%o0

	sll	%o1,3,%o1
	sll	%o2,3,%o2

	ldd	[G1_CONST_TBL+%o0],%f34

	ldd	[G1_CONST_TBL+%o1],%f18

	ldd	[G1_CONST_TBL+%o2],%f20

	fpadd32 %f16,%f34,%f34

	fpadd32 %f2,%f18,%f18

	fpadd32 %f4,%f20,%f20

	fmuld	%f34,%f40,%f40

	fmuld	%f18,%f42,%f42

	fmuld	%f20,%f44,%f44

	faddd	%f34,%f40,%f40

	faddd	%f18,%f42,%f42

	faddd	%f20,%f44,%f44

	fdtos	%f40,%f26
	st	%f26,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f42,%f18
	st	%f18,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f44,%f20
	st	%f20,[%i3]
	add	%i3,%i4,%i3

	cmp	%l3,%o5
	bl,pt	%icc,.spec3_out_of_range
	sll	%i2,2,%o4

	ble,pn	%icc,.spec3_inf
	add	%o4,%i2,%o4

! NaN -> NaN

	fmuls	%f6,%f6,%f6
	ba	.spec3_exit
	st	%f6,[%i3]

.spec3_inf:
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec3_exit
	st	%f6,[%i3]

	ba	.spec3_exit
	st	%f3,[%i3]

.spec3_out_of_range:
	add	%o4,%i2,%o4
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.spec3_exit:
	fmovs	%f8,%f16
	mov	%l4,%l0
	fmovs	%f10,%f2
	mov	%l5,%l1
	fmovs	%f12,%f4
	mov	%l6,%l2
	fmovs	%f14,%f6
	mov	%l7,%l3
	mov	%i1,%o0
	lda	[%o0]%asi,%l4
	add	%o0,%i2,%o1
	lda	[%o1]%asi,%l5
	add	%o1,%i2,%o2
	lda	[%o2]%asi,%l6
	add	%o2,%i2,%o3
	lda	[%o3]%asi,%l7
	add	%o3,%i2,%i1
	and	%l4,G5_CONST,%l4
	and	%l5,G5_CONST,%l5
	and	%l6,G5_CONST,%l6
	and	%l7,G5_CONST,%l7

	subcc	%i0,4,%i0
	bpos,pt	%icc,.main_loop
	add	%i3,%i4,%i3
	ba	.after_main_loop
	nop

	.align	16
.spec4:
	sethi	%hi(0x7f800000),%o5
	cmp	%l4,%o5
	bge,pn	%icc,1f
	nop
	fcmpes	%fcc0,%f8,%f3
	fcmpes	%fcc1,%f8,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f8,%f48			! (4) y = (double) X
	fbl,a,pt	%fcc1,.spec4_cont	! if ( X < THRESHOLDL )
	fstod	%f8,%f48			! (4) y = (double) X
1:
	fmuld	F62_K256ONLN2,%f42,%f42

	fmuld	F62_K256ONLN2,%f44,%f44

	fmuld	F62_K256ONLN2,%f46,%f46

	fdtoi	%f40,%f16
	st	%f16,[%fp+tmp0]

	fdtoi	%f42,%f2
	st	%f2,[%fp+tmp1]

	fdtoi	%f44,%f4
	st	%f4,[%fp+tmp2]

	fdtoi	%f46,%f6
	st	%f6,[%fp+tmp3]

	fitod	%f16,%f34
	fpackfix	%f16,%f16

	fitod	%f2,%f18
	fpackfix	%f2,%f2

	fitod	%f4,%f20
	fpackfix	%f4,%f4

	fitod	%f6,%f22
	fpackfix	%f6,%f6

	fsubd	%f40,%f34,%f40

	fsubd	%f42,%f18,%f42

	fsubd	%f44,%f20,%f44

	fsubd	%f46,%f22,%f46

	fmuld	F60_KA2,%f40,%f34

	fmuld	F60_KA2,%f42,%f18

	fmuld	F60_KA2,%f44,%f20

	fmuld	F60_KA2,%f46,%f22

	faddd	F58_KA1,%f34,%f34

	faddd	F58_KA1,%f18,%f18

	faddd	F58_KA1,%f20,%f20

	faddd	F58_KA1,%f22,%f22

	ld	[%fp+tmp0],%o0
	fmuld	%f34,%f40,%f40

	ld	[%fp+tmp1],%o1
	fmuld	%f18,%f42,%f42

	ld	[%fp+tmp2],%o2
	fmuld	%f20,%f44,%f44

	ld	[%fp+tmp3],%o3
	fmuld	%f22,%f46,%f46

	and	%o0,255,%o0
	and	%o1,255,%o1

	and	%o2,255,%o2
	and	%o3,255,%o3

	sll	%o0,3,%o0
	sll	%o1,3,%o1

	sll	%o2,3,%o2
	sll	%o3,3,%o3

	ldd	[G1_CONST_TBL+%o0],%f34

	ldd	[G1_CONST_TBL+%o1],%f18

	ldd	[G1_CONST_TBL+%o2],%f20

	ldd	[G1_CONST_TBL+%o3],%f22

	fpadd32 %f16,%f34,%f34

	fpadd32 %f2,%f18,%f18

	fpadd32 %f4,%f20,%f20

	fpadd32 %f6,%f22,%f22

	fmuld	%f34,%f40,%f40

	fmuld	%f18,%f42,%f42

	fmuld	%f20,%f44,%f44

	fmuld	%f22,%f46,%f46

	faddd	%f34,%f40,%f40

	faddd	%f18,%f42,%f42

	faddd	%f20,%f44,%f44

	faddd	%f22,%f46,%f46

	fdtos	%f40,%f26
	st	%f26,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f42,%f18
	st	%f18,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f44,%f20
	st	%f20,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f46,%f22
	st	%f22,[%o4]
	add	%o4,%i4,%i3

	cmp	%l4,%o5
	bl,pt	%icc,.spec4_out_of_range
	sll	%i2,2,%o4

	ble,pn	%icc,.spec4_inf
	sub	%i1,%o4,%o4

! NaN -> NaN

	fmuls	%f8,%f8,%f8
	ba	.spec4_exit
	st	%f8,[%i3]

.spec4_inf:
	ld	[%o4],%l0
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec4_exit
	st	%f8,[%i3]

	ba	.spec4_exit
	st	%f3,[%i3]

.spec4_out_of_range:
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.spec4_exit:
	fmovs	%f10,%f16
	mov	%l5,%l0
	fmovs	%f12,%f2
	mov	%l6,%l1
	fmovs	%f14,%f4
	mov	%l7,%l2
	lda	[%i1]%asi,%l3
	lda	[%i1]%asi,%f6
	add	%i1,%i2,%o0
	lda	[%o0]%asi,%l4
	add	%o0,%i2,%o1
	lda	[%o1]%asi,%l5
	add	%o1,%i2,%o2
	lda	[%o2]%asi,%l6
	add	%o2,%i2,%o3
	lda	[%o3]%asi,%l7
	add	%o3,%i2,%i1
	and	%l3,G5_CONST,%l3
	and	%l4,G5_CONST,%l4
	and	%l5,G5_CONST,%l5
	and	%l6,G5_CONST,%l6
	and	%l7,G5_CONST,%l7

	subcc	%i0,5,%i0
	bpos,pt	%icc,.main_loop
	add	%i3,%i4,%i3
	ba	.after_main_loop
	nop

	.align 16
.spec5:
	sethi	%hi(0x7f800000),%o5
	cmp	%l5,%o5
	bge,pn	%icc,1f
	nop
	fcmpes	%fcc0,%f10,%f3
	fcmpes	%fcc1,%f10,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f10,%f50			! (5) y = (double) X
	fbl,a,pt	%fcc1,.spec5_cont	! if ( X < THRESHOLDL )
	fstod	%f10,%f50			! (5) y = (double) X
1:
	fmuld	F62_K256ONLN2,%f44,%f44

	fmuld	F62_K256ONLN2,%f46,%f46

	fdtoi	%f40,%f16
	st	%f16,[%fp+tmp0]
	fmuld	F62_K256ONLN2,%f48,%f48

	fdtoi	%f42,%f2
	st	%f2,[%fp+tmp1]

	fdtoi	%f44,%f4
	st	%f4,[%fp+tmp2]

	fdtoi	%f46,%f6
	st	%f6,[%fp+tmp3]

	fdtoi	%f48,%f8
	st	%f8,[%fp+tmp4]

	fitod	%f16,%f34
	fpackfix	%f16,%f16

	fitod	%f2,%f18
	fpackfix	%f2,%f2

	fitod	%f4,%f20
	fpackfix	%f4,%f4

	fitod	%f6,%f22
	fpackfix	%f6,%f6

	fitod	%f8,%f24
	fpackfix	%f8,%f8

	ld	[%fp+tmp0],%o0
	fsubd	%f40,%f34,%f40

	ld	[%fp+tmp1],%o1
	fsubd	%f42,%f18,%f42

	ld	[%fp+tmp2],%o2
	and	%o0,255,%o0
	fsubd	%f44,%f20,%f44

	ld	[%fp+tmp3],%o3
	and	%o1,255,%o1
	fsubd	%f46,%f22,%f46

	sll	%o0,3,%o0
	sll	%o1,3,%o1
	fmuld	F60_KA2,%f40,%f34
	fsubd	%f48,%f24,%f48

	and	%o2,255,%o2
	fmuld	F60_KA2,%f42,%f18

	sll	%o2,3,%o2
	fmuld	F60_KA2,%f44,%f20

	ld	[%fp+tmp4],%o4
	and	%o3,255,%o3
	fmuld	F60_KA2,%f46,%f22

	sll	%o3,3,%o3
	fmuld	F60_KA2,%f48,%f24
	faddd	F58_KA1,%f34,%f34

	and	%o4,255,%o4
	faddd	F58_KA1,%f18,%f18

	faddd	F58_KA1,%f20,%f20

	faddd	F58_KA1,%f22,%f22

	fmuld	%f34,%f40,%f40
	ldd	[G1_CONST_TBL+%o0],%f34
	faddd	F58_KA1,%f24,%f24

	fmuld	%f18,%f42,%f42
	ldd	[G1_CONST_TBL+%o1],%f18

	fmuld	%f20,%f44,%f44
	ldd	[G1_CONST_TBL+%o2],%f20

	fmuld	%f22,%f46,%f46
	ldd	[G1_CONST_TBL+%o3],%f22
	sll	%o4,3,%o4

	fmuld	%f24,%f48,%f48
	ldd	[G1_CONST_TBL+%o4],%f24
	fpadd32 %f16,%f34,%f34

	fpadd32 %f2,%f18,%f18

	fpadd32 %f4,%f20,%f20

	fpadd32 %f6,%f22,%f22

	fpadd32 %f8,%f24,%f24
	fmuld	%f34,%f40,%f40

	fmuld	%f18,%f42,%f42

	fmuld	%f20,%f44,%f44

	fmuld	%f22,%f46,%f46

	fmuld	%f24,%f48,%f48
	faddd	%f34,%f40,%f40

	faddd	%f18,%f42,%f42

	faddd	%f20,%f44,%f44

	faddd	%f22,%f46,%f46

	faddd	%f24,%f48,%f48

	fdtos	%f40,%f26
	st	%f26,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f42,%f18
	st	%f18,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f44,%f20
	st	%f20,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f46,%f22
	st	%f22,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f48,%f24
	st	%f24,[%i3]
	add	%i3,%i4,%i3

	cmp	%l5,%o5
	bl,pt	%icc,.spec5_out_of_range
	sll	%i2,2,%o4

	ble,pn	%icc,.spec5_inf
	sub	%o4,%i2,%o4

! NaN -> NaN

	fmuls	%f10,%f10,%f10
	ba	.spec5_exit
	st	%f10,[%i3]

.spec5_inf:
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec5_exit
	st	%f10,[%i3]

	ba	.spec5_exit
	st	%f3,[%i3]

.spec5_out_of_range:
	sub	%o4,%i2,%o4
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.spec5_exit:
	fmovs	%f12,%f16
	mov	%l6,%l0
	fmovs	%f14,%f2
	mov	%l7,%l1
	lda	[%i1]%asi,%l2
	lda	[%i1]%asi,%f4
	add	%i1,%i2,%i1
	lda	[%i1]%asi,%l3
	lda	[%i1]%asi,%f6
	add	%i1,%i2,%o0
	lda	[%o0]%asi,%l4
	add	%o0,%i2,%o1
	lda	[%o1]%asi,%l5
	add	%o1,%i2,%o2
	lda	[%o2]%asi,%l6
	add	%o2,%i2,%o3
	lda	[%o3]%asi,%l7
	add	%o3,%i2,%i1
	and	%l2,G5_CONST,%l2
	and	%l3,G5_CONST,%l3
	and	%l4,G5_CONST,%l4
	and	%l5,G5_CONST,%l5
	and	%l6,G5_CONST,%l6
	and	%l7,G5_CONST,%l7

	subcc	%i0,6,%i0
	bpos,pt	%icc,.main_loop
	add	%i3,%i4,%i3
	ba	.after_main_loop
	nop
.spec6:
	sethi	%hi(0x7f800000),%o5
	cmp	%l6,%o5
	bge,pn	%icc,1f
	nop
	fcmpes	%fcc0,%f12,%f3
	fcmpes	%fcc1,%f12,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f12,%f52			! (6) y = (double) X
	fbl,a,pt	%fcc1,.spec6_cont	! if ( X < THRESHOLDL )
	fstod	%f12,%f52			! (6) y = (double) X
1:
	fmuld	F62_K256ONLN2,%f46,%f46

	fdtoi	%f40,%f16
	st	%f16,[%fp+tmp0]
	fmuld	F62_K256ONLN2,%f48,%f48

	fdtoi	%f42,%f2
	st	%f2,[%fp+tmp1]
	fmuld	F62_K256ONLN2,%f50,%f50

	fdtoi	%f44,%f4
	st	%f4,[%fp+tmp2]

	fdtoi	%f46,%f6
	st	%f6,[%fp+tmp3]

	fdtoi	%f48,%f8
	st	%f8,[%fp+tmp4]

	fdtoi	%f50,%f10
	st	%f10,[%fp+tmp5]

	fitod	%f16,%f34
	fpackfix	%f16,%f16

	fitod	%f2,%f18
	fpackfix	%f2,%f2

	fitod	%f4,%f20
	fpackfix	%f4,%f4

	fitod	%f6,%f22
	fpackfix	%f6,%f6

	fitod	%f8,%f24
	fpackfix	%f8,%f8

	fitod	%f10,%f26
	fpackfix	%f10,%f10

	ld	[%fp+tmp0],%o0
	fsubd	%f40,%f34,%f40

	ld	[%fp+tmp1],%o1
	fsubd	%f42,%f18,%f42

	ld	[%fp+tmp2],%o2
	and	%o0,255,%o0
	fsubd	%f44,%f20,%f44

	ld	[%fp+tmp3],%o3
	and	%o1,255,%o1
	fsubd	%f46,%f22,%f46

	sll	%o0,3,%o0
	sll	%o1,3,%o1
	fmuld	F60_KA2,%f40,%f34
	fsubd	%f48,%f24,%f48

	and	%o2,255,%o2
	fmuld	F60_KA2,%f42,%f18
	fsubd	%f50,%f26,%f50

	sll	%o2,3,%o2
	fmuld	F60_KA2,%f44,%f20

	ld	[%fp+tmp4],%o4
	and	%o3,255,%o3
	fmuld	F60_KA2,%f46,%f22

	ld	[%fp+tmp5],%o5
	sll	%o3,3,%o3
	fmuld	F60_KA2,%f48,%f24
	faddd	F58_KA1,%f34,%f34

	and	%o4,255,%o4
	fmuld	F60_KA2,%f50,%f26
	faddd	F58_KA1,%f18,%f18

	and	%o5,255,%o5
	faddd	F58_KA1,%f20,%f20

	sll	%o5,3,%o5
	faddd	F58_KA1,%f22,%f22

	fmuld	%f34,%f40,%f40
	ldd	[G1_CONST_TBL+%o0],%f34
	faddd	F58_KA1,%f24,%f24

	fmuld	%f18,%f42,%f42
	ldd	[G1_CONST_TBL+%o1],%f18
	faddd	F58_KA1,%f26,%f26

	fmuld	%f20,%f44,%f44
	ldd	[G1_CONST_TBL+%o2],%f20

	fmuld	%f22,%f46,%f46
	ldd	[G1_CONST_TBL+%o3],%f22
	sll	%o4,3,%o4

	fmuld	%f24,%f48,%f48
	ldd	[G1_CONST_TBL+%o4],%f24
	fpadd32 %f16,%f34,%f34

	fmuld	%f26,%f50,%f50
	ldd	[G1_CONST_TBL+%o5],%f26
	fpadd32 %f2,%f18,%f18

	fpadd32 %f4,%f20,%f20

	fpadd32 %f6,%f22,%f22

	fpadd32 %f8,%f24,%f24
	fmuld	%f34,%f40,%f40

	fpadd32 %f10,%f26,%f26
	fmuld	%f18,%f42,%f42

	fmuld	%f20,%f44,%f44

	fmuld	%f22,%f46,%f46

	fmuld	%f24,%f48,%f48
	faddd	%f34,%f40,%f40

	fmuld	%f26,%f50,%f50
	faddd	%f18,%f42,%f42

	faddd	%f20,%f44,%f44

	faddd	%f22,%f46,%f46

	faddd	%f24,%f48,%f48

	faddd	%f26,%f50,%f50

	fdtos	%f40,%f26
	st	%f26,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f42,%f18
	st	%f18,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f44,%f20
	st	%f20,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f46,%f22
	st	%f22,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f48,%f24
	st	%f24,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f50,%f26
	st	%f26,[%o4]
	add	%o4,%i4,%i3

	sethi	%hi(0x7f800000),%o5
	cmp	%l6,%o5
	bl,pt	%icc,.spec6_out_of_range
	sll	%i2,1,%o4

	ble,pn	%icc,.spec6_inf
	sub	%i1,%o4,%o4

! NaN -> NaN

	fmuls	%f12,%f12,%f12
	ba	.spec6_exit
	st	%f12,[%i3]

.spec6_inf:
	ld	[%o4],%l0
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec6_exit
	st	%f12,[%i3]

	ba	.spec6_exit
	st	%f3,[%i3]

.spec6_out_of_range:
	sub	%i1,%o4,%o4
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.spec6_exit:
	fmovs	%f14,%f16
	mov	%l7,%l0
	lda	[%i1]%asi,%l1
	lda	[%i1]%asi,%f2
	add	%i1,%i2,%i1
	lda	[%i1]%asi,%l2
	lda	[%i1]%asi,%f4
	add	%i1,%i2,%i1
	lda	[%i1]%asi,%l3
	lda	[%i1]%asi,%f6
	add	%i1,%i2,%o0
	lda	[%o0]%asi,%l4
	add	%o0,%i2,%o1
	lda	[%o1]%asi,%l5
	add	%o1,%i2,%o2
	lda	[%o2]%asi,%l6
	add	%o2,%i2,%o3
	lda	[%o3]%asi,%l7
	add	%o3,%i2,%i1
	and	%l1,G5_CONST,%l1
	and	%l2,G5_CONST,%l2
	and	%l3,G5_CONST,%l3
	and	%l4,G5_CONST,%l4
	and	%l5,G5_CONST,%l5
	and	%l6,G5_CONST,%l6
	and	%l7,G5_CONST,%l7

	subcc	%i0,7,%i0
	bpos,pt	%icc,.main_loop
	add	%i3,%i4,%i3
	ba	.after_main_loop
	nop

	.align	16
.spec7:
	sethi	%hi(0x7f800000),%o5
	cmp	%l7,%o5
	bge,pn	%icc,1f
	nop
	fcmpes	%fcc0,%f14,%f3
	fcmpes	%fcc1,%f14,THRESHOLDL
	fbl,a,pn	%fcc0,1f		! if ( X < 0.0f )
	fstod	%f14,%f54			! (7) y = (double) X
	fbl,a,pt	%fcc1,.spec7_cont	! if ( X < THRESHOLDL )
	fstod	%f14,%f54			! (7) y = (double) X
1:
	fdtoi	%f40,%f16
	st	%f16,[%fp+tmp0]
	fmuld	F62_K256ONLN2,%f48,%f48

	fdtoi	%f42,%f2
	st	%f2,[%fp+tmp1]
	fmuld	F62_K256ONLN2,%f50,%f50

	fdtoi	%f44,%f4
	st	%f4,[%fp+tmp2]
	fmuld	F62_K256ONLN2,%f52,%f52

	fdtoi	%f46,%f6
	st	%f6,[%fp+tmp3]

	fdtoi	%f48,%f8
	st	%f8,[%fp+tmp4]

	fdtoi	%f50,%f10
	st	%f10,[%fp+tmp5]

	fdtoi	%f52,%f12
	st	%f12,[%fp+tmp6]

	fitod	%f16,%f34
	fpackfix	%f16,%f16

	fitod	%f2,%f18
	fpackfix	%f2,%f2

	fitod	%f4,%f20
	fpackfix	%f4,%f4

	fitod	%f6,%f22
	fpackfix	%f6,%f6

	fitod	%f8,%f24
	fpackfix	%f8,%f8

	fitod	%f10,%f26
	fpackfix	%f10,%f10

	fitod	%f12,%f28
	fpackfix	%f12,%f12

	ld	[%fp+tmp0],%o0
	fsubd	%f40,%f34,%f40

	ld	[%fp+tmp1],%o1
	fsubd	%f42,%f18,%f42

	ld	[%fp+tmp2],%o2
	and	%o0,255,%o0
	fsubd	%f44,%f20,%f44

	ld	[%fp+tmp3],%o3
	and	%o1,255,%o1
	fsubd	%f46,%f22,%f46

	sll	%o0,3,%o0
	sll	%o1,3,%o1
	fmuld	F60_KA2,%f40,%f34
	fsubd	%f48,%f24,%f48

	and	%o2,255,%o2
	fmuld	F60_KA2,%f42,%f18
	fsubd	%f50,%f26,%f50

	sll	%o2,3,%o2
	fmuld	F60_KA2,%f44,%f20
	fsubd	%f52,%f28,%f52

	ld	[%fp+tmp4],%o4
	and	%o3,255,%o3
	fmuld	F60_KA2,%f46,%f22

	ld	[%fp+tmp5],%o5
	sll	%o3,3,%o3
	fmuld	F60_KA2,%f48,%f24
	faddd	F58_KA1,%f34,%f34

	ld	[%fp+tmp6],%o7
	and	%o4,255,%o4
	fmuld	F60_KA2,%f50,%f26
	faddd	F58_KA1,%f18,%f18

	and	%o5,255,%o5
	fmuld	F60_KA2,%f52,%f28
	faddd	F58_KA1,%f20,%f20

	sll	%o5,3,%o5
	faddd	F58_KA1,%f22,%f22

	fmuld	%f34,%f40,%f40
	ldd	[G1_CONST_TBL+%o0],%f34
	faddd	F58_KA1,%f24,%f24

	fmuld	%f18,%f42,%f42
	ldd	[G1_CONST_TBL+%o1],%f18
	faddd	F58_KA1,%f26,%f26

	fmuld	%f20,%f44,%f44
	ldd	[G1_CONST_TBL+%o2],%f20
	faddd	F58_KA1,%f28,%f28

	fmuld	%f22,%f46,%f46
	ldd	[G1_CONST_TBL+%o3],%f22
	sll	%o4,3,%o4

	fmuld	%f24,%f48,%f48
	ldd	[G1_CONST_TBL+%o4],%f24
	and	%o7,255,%o7
	fpadd32 %f16,%f34,%f34

	fmuld	%f26,%f50,%f50
	ldd	[G1_CONST_TBL+%o5],%f26
	sll	%o7,3,%o7
	fpadd32 %f2,%f18,%f18

	fmuld	%f28,%f52,%f52
	ldd	[G1_CONST_TBL+%o7],%f28
	fpadd32 %f4,%f20,%f20

	fpadd32 %f6,%f22,%f22

	fpadd32 %f8,%f24,%f24
	fmuld	%f34,%f40,%f40

	fpadd32 %f10,%f26,%f26
	fmuld	%f18,%f42,%f42

	fpadd32 %f12,%f28,%f28
	fmuld	%f20,%f44,%f44

	fmuld	%f22,%f46,%f46

	fmuld	%f24,%f48,%f48
	faddd	%f34,%f40,%f40

	fmuld	%f26,%f50,%f50
	faddd	%f18,%f42,%f42

	fmuld	%f28,%f52,%f52
	faddd	%f20,%f44,%f44

	faddd	%f22,%f46,%f46

	faddd	%f24,%f48,%f48

	faddd	%f26,%f50,%f50

	faddd	%f28,%f52,%f52

	fdtos	%f40,%f26
	st	%f26,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f42,%f18
	st	%f18,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f44,%f20
	st	%f20,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f46,%f22
	st	%f22,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f48,%f24
	st	%f24,[%i3]
	add	%i3,%i4,%o4

	fdtos	%f50,%f26
	st	%f26,[%o4]
	add	%o4,%i4,%i3

	fdtos	%f52,%f28
	st	%f28,[%i3]
	add	%i3,%i4,%i3

	sethi	%hi(0x7f800000),%o5
	cmp	%l7,%o5
	bl,pt	%icc,.spec7_out_of_range
	sub	%i1,%i2,%o4

	ble,pn	%icc,.spec7_inf
	ld	[%o4],%l0

! NaN -> NaN

	fmuls	%f14,%f14,%f14
	ba	.spec7_exit
	st	%f14,[%i3]

.spec7_inf:
	srl	%l0,29,%l0
	andcc	%l0,4,%l0
	be,a,pn	%icc,.spec7_exit
	st	%f14,[%i3]

	ba	.spec7_exit
	st	%f3,[%i3]

.spec7_out_of_range:
	ld	[%o4],%l0
	srl	%l0,29,%l0
	and	%l0,4,%l0
	add	%l0,2048,%l0
	ld	[G1_CONST_TBL+%l0],%f2
	fmuls	%f2,%f2,%f2
	st	%f2,[%i3]

.spec7_exit:
	subcc	%i0,8,%i0
	bpos,pt	%icc,.main_loop_preload
	add	%i3,%i4,%i3

	ba	.tail
	nop
	SET_SIZE(__vexpf)

