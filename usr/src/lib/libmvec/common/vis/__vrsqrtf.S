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

	.file	"__vrsqrtf.S"

#include "libm.h"

	RO_DATA
	.align	64

! i = [0,63]
! TBL[2*i  ] = 1 / (*(double*)&(0x3fe0000000000000ULL + (i << 46))) * 2**-24;
! TBL[2*i+1] = 1 / sqrtl(*(double*)&(0x3fe0000000000000ULL + (i << 46)));
! i = [64,127]
! TBL[2*i  ] = 1 / (*(double*)&(0x3fe0000000000000ULL + (i << 46))) * 2**-23;
! TBL[2*i+1] = 1 / sqrtl(*(double*)&(0x3fe0000000000000ULL + (i << 46)));

.CONST_TBL:
	.word	0x3e800000, 0x00000000, 0x3ff6a09e, 0x667f3bcd,
	.word	0x3e7f81f8, 0x1f81f820, 0x3ff673e3, 0x2ef63a03,
	.word	0x3e7f07c1, 0xf07c1f08, 0x3ff6482d, 0x37a5a3d2,
	.word	0x3e7e9131, 0xabf0b767, 0x3ff61d72, 0xb7978671,
	.word	0x3e7e1e1e, 0x1e1e1e1e, 0x3ff5f3aa, 0x673fa911,
	.word	0x3e7dae60, 0x76b981db, 0x3ff5cacb, 0x7802f342,
	.word	0x3e7d41d4, 0x1d41d41d, 0x3ff5a2cd, 0x8c69d61a,
	.word	0x3e7cd856, 0x89039b0b, 0x3ff57ba8, 0xb0ee01b9,
	.word	0x3e7c71c7, 0x1c71c71c, 0x3ff55555, 0x55555555,
	.word	0x3e7c0e07, 0x0381c0e0, 0x3ff52fcc, 0x468d6b54,
	.word	0x3e7bacf9, 0x14c1bad0, 0x3ff50b06, 0xa8fc6b70,
	.word	0x3e7b4e81, 0xb4e81b4f, 0x3ff4e6fd, 0xf33cf032,
	.word	0x3e7af286, 0xbca1af28, 0x3ff4c3ab, 0xe93bcf74,
	.word	0x3e7a98ef, 0x606a63be, 0x3ff4a10a, 0x97af7b92,
	.word	0x3e7a41a4, 0x1a41a41a, 0x3ff47f14, 0x4fe17f9f,
	.word	0x3e79ec8e, 0x951033d9, 0x3ff45dc3, 0xa3c34fa3,
	.word	0x3e799999, 0x9999999a, 0x3ff43d13, 0x6248490f,
	.word	0x3e7948b0, 0xfcd6e9e0, 0x3ff41cfe, 0x93ff5199,
	.word	0x3e78f9c1, 0x8f9c18fa, 0x3ff3fd80, 0x77e70577,
	.word	0x3e78acb9, 0x0f6bf3aa, 0x3ff3de94, 0x8077db58,
	.word	0x3e786186, 0x18618618, 0x3ff3c036, 0x50e00e03,
	.word	0x3e781818, 0x18181818, 0x3ff3a261, 0xba6d7a37,
	.word	0x3e77d05f, 0x417d05f4, 0x3ff38512, 0xba21f51e,
	.word	0x3e778a4c, 0x8178a4c8, 0x3ff36845, 0x766eec92,
	.word	0x3e7745d1, 0x745d1746, 0x3ff34bf6, 0x3d156826,
	.word	0x3e7702e0, 0x5c0b8170, 0x3ff33021, 0x8127c0e0,
	.word	0x3e76c16c, 0x16c16c17, 0x3ff314c3, 0xd92a9e91,
	.word	0x3e768168, 0x16816817, 0x3ff2f9d9, 0xfd52fd50,
	.word	0x3e7642c8, 0x590b2164, 0x3ff2df60, 0xc5df2c9e,
	.word	0x3e760581, 0x60581606, 0x3ff2c555, 0x2988e428,
	.word	0x3e75c988, 0x2b931057, 0x3ff2abb4, 0x3c0eb0f4,
	.word	0x3e758ed2, 0x308158ed, 0x3ff2927b, 0x2cd320f5,
	.word	0x3e755555, 0x55555555, 0x3ff279a7, 0x4590331c,
	.word	0x3e751d07, 0xeae2f815, 0x3ff26135, 0xe91daf55,
	.word	0x3e74e5e0, 0xa72f0539, 0x3ff24924, 0x92492492,
	.word	0x3e74afd6, 0xa052bf5b, 0x3ff23170, 0xd2be638a,
	.word	0x3e747ae1, 0x47ae147b, 0x3ff21a18, 0x51ff630a,
	.word	0x3e7446f8, 0x6562d9fb, 0x3ff20318, 0xcc6a8f5d,
	.word	0x3e741414, 0x14141414, 0x3ff1ec70, 0x124e98f9,
	.word	0x3e73e22c, 0xbce4a902, 0x3ff1d61c, 0x070ae7d3,
	.word	0x3e73b13b, 0x13b13b14, 0x3ff1c01a, 0xa03be896,
	.word	0x3e738138, 0x13813814, 0x3ff1aa69, 0xe4f2777f,
	.word	0x3e73521c, 0xfb2b78c1, 0x3ff19507, 0xecf5b9e9,
	.word	0x3e7323e3, 0x4a2b10bf, 0x3ff17ff2, 0xe00ec3ee,
	.word	0x3e72f684, 0xbda12f68, 0x3ff16b28, 0xf55d72d4,
	.word	0x3e72c9fb, 0x4d812ca0, 0x3ff156a8, 0x72b5ef62,
	.word	0x3e729e41, 0x29e4129e, 0x3ff1426f, 0xac0654db,
	.word	0x3e727350, 0xb8812735, 0x3ff12e7d, 0x02c40253,
	.word	0x3e724924, 0x92492492, 0x3ff11ace, 0xe560242a,
	.word	0x3e721fb7, 0x8121fb78, 0x3ff10763, 0xcec30b26,
	.word	0x3e71f704, 0x7dc11f70, 0x3ff0f43a, 0x45cdedad,
	.word	0x3e71cf06, 0xada2811d, 0x3ff0e150, 0xdce2b60c,
	.word	0x3e71a7b9, 0x611a7b96, 0x3ff0cea6, 0x317186dc,
	.word	0x3e718118, 0x11811812, 0x3ff0bc38, 0xeb8ba412,
	.word	0x3e715b1e, 0x5f75270d, 0x3ff0aa07, 0xbd7b7488,
	.word	0x3e7135c8, 0x1135c811, 0x3ff09811, 0x63615499,
	.word	0x3e711111, 0x11111111, 0x3ff08654, 0xa2d4f6db,
	.word	0x3e70ecf5, 0x6be69c90, 0x3ff074d0, 0x4a8b1438,
	.word	0x3e70c971, 0x4fbcda3b, 0x3ff06383, 0x31ff307a,
	.word	0x3e70a681, 0x0a6810a7, 0x3ff0526c, 0x39213bfa,
	.word	0x3e708421, 0x08421084, 0x3ff0418a, 0x4806de7d,
	.word	0x3e70624d, 0xd2f1a9fc, 0x3ff030dc, 0x4ea03a72,
	.word	0x3e704104, 0x10410410, 0x3ff02061, 0x446ffa9a,
	.word	0x3e702040, 0x81020408, 0x3ff01018, 0x28467ee9,
	.word	0x3e800000, 0x00000000, 0x3ff00000, 0x00000000,
	.word	0x3e7f81f8, 0x1f81f820, 0x3fefc0bd, 0x88a0f1d9,
	.word	0x3e7f07c1, 0xf07c1f08, 0x3fef82ec, 0x882c0f9b,
	.word	0x3e7e9131, 0xabf0b767, 0x3fef467f, 0x2814b0cc,
	.word	0x3e7e1e1e, 0x1e1e1e1e, 0x3fef0b68, 0x48d2af1c,
	.word	0x3e7dae60, 0x76b981db, 0x3feed19b, 0x75e78957,
	.word	0x3e7d41d4, 0x1d41d41d, 0x3fee990c, 0xdad55ed2,
	.word	0x3e7cd856, 0x89039b0b, 0x3fee61b1, 0x38f18adc,
	.word	0x3e7c71c7, 0x1c71c71c, 0x3fee2b7d, 0xddfefa66,
	.word	0x3e7c0e07, 0x0381c0e0, 0x3fedf668, 0x9b7e6350,
	.word	0x3e7bacf9, 0x14c1bad0, 0x3fedc267, 0xbea45549,
	.word	0x3e7b4e81, 0xb4e81b4f, 0x3fed8f72, 0x08e6b82d,
	.word	0x3e7af286, 0xbca1af28, 0x3fed5d7e, 0xa914b937,
	.word	0x3e7a98ef, 0x606a63be, 0x3fed2c85, 0x34ed6d86,
	.word	0x3e7a41a4, 0x1a41a41a, 0x3fecfc7d, 0xa32a9213,
	.word	0x3e79ec8e, 0x951033d9, 0x3feccd60, 0x45f5d358,
	.word	0x3e799999, 0x9999999a, 0x3fec9f25, 0xc5bfedd9,
	.word	0x3e7948b0, 0xfcd6e9e0, 0x3fec71c7, 0x1c71c71c,
	.word	0x3e78f9c1, 0x8f9c18fa, 0x3fec453d, 0x90f057a2,
	.word	0x3e78acb9, 0x0f6bf3aa, 0x3fec1982, 0xb2ece47b,
	.word	0x3e786186, 0x18618618, 0x3febee90, 0x56fb9c39,
	.word	0x3e781818, 0x18181818, 0x3febc460, 0x92eb3118,
	.word	0x3e77d05f, 0x417d05f4, 0x3feb9aed, 0xba588347,
	.word	0x3e778a4c, 0x8178a4c8, 0x3feb7232, 0x5b79db11,
	.word	0x3e7745d1, 0x745d1746, 0x3feb4a29, 0x3c1d9550,
	.word	0x3e7702e0, 0x5c0b8170, 0x3feb22cd, 0x56d87d7e,
	.word	0x3e76c16c, 0x16c16c17, 0x3feafc19, 0xd8606169,
	.word	0x3e768168, 0x16816817, 0x3fead60a, 0x1d0fb394,
	.word	0x3e7642c8, 0x590b2164, 0x3feab099, 0xae8f539a,
	.word	0x3e760581, 0x60581606, 0x3fea8bc4, 0x41a3d02c,
	.word	0x3e75c988, 0x2b931057, 0x3fea6785, 0xb41bacf7,
	.word	0x3e758ed2, 0x308158ed, 0x3fea43da, 0x0adc6899,
	.word	0x3e755555, 0x55555555, 0x3fea20bd, 0x700c2c3e,
	.word	0x3e751d07, 0xeae2f815, 0x3fe9fe2c, 0x315637ee,
	.word	0x3e74e5e0, 0xa72f0539, 0x3fe9dc22, 0xbe484458,
	.word	0x3e74afd6, 0xa052bf5b, 0x3fe9ba9d, 0xa6c73588,
	.word	0x3e747ae1, 0x47ae147b, 0x3fe99999, 0x9999999a,
	.word	0x3e7446f8, 0x6562d9fb, 0x3fe97913, 0x63068b54,
	.word	0x3e741414, 0x14141414, 0x3fe95907, 0xeb87ab44,
	.word	0x3e73e22c, 0xbce4a902, 0x3fe93974, 0x368cfa31,
	.word	0x3e73b13b, 0x13b13b14, 0x3fe91a55, 0x6151761c,
	.word	0x3e738138, 0x13813814, 0x3fe8fba8, 0xa1bf6f96,
	.word	0x3e73521c, 0xfb2b78c1, 0x3fe8dd6b, 0x4563a009,
	.word	0x3e7323e3, 0x4a2b10bf, 0x3fe8bf9a, 0xb06e1af3,
	.word	0x3e72f684, 0xbda12f68, 0x3fe8a234, 0x5cc04426,
	.word	0x3e72c9fb, 0x4d812ca0, 0x3fe88535, 0xd90703c6,
	.word	0x3e729e41, 0x29e4129e, 0x3fe8689c, 0xc7e07e7d,
	.word	0x3e727350, 0xb8812735, 0x3fe84c66, 0xdf0ca4c2,
	.word	0x3e724924, 0x92492492, 0x3fe83091, 0xe6a7f7e7,
	.word	0x3e721fb7, 0x8121fb78, 0x3fe8151b, 0xb86fee1d,
	.word	0x3e71f704, 0x7dc11f70, 0x3fe7fa02, 0x3f1068d1,
	.word	0x3e71cf06, 0xada2811d, 0x3fe7df43, 0x7579b9b5,
	.word	0x3e71a7b9, 0x611a7b96, 0x3fe7c4dd, 0x663ebb88,
	.word	0x3e718118, 0x11811812, 0x3fe7aace, 0x2afa8b72,
	.word	0x3e715b1e, 0x5f75270d, 0x3fe79113, 0xebbd7729,
	.word	0x3e7135c8, 0x1135c811, 0x3fe777ac, 0xde80baea,
	.word	0x3e711111, 0x11111111, 0x3fe75e97, 0x46a0b098,
	.word	0x3e70ecf5, 0x6be69c90, 0x3fe745d1, 0x745d1746,
	.word	0x3e70c971, 0x4fbcda3b, 0x3fe72d59, 0xc45f1fc5,
	.word	0x3e70a681, 0x0a6810a7, 0x3fe7152e, 0x9f44f01f,
	.word	0x3e708421, 0x08421084, 0x3fe6fd4e, 0x79325467,
	.word	0x3e70624d, 0xd2f1a9fc, 0x3fe6e5b7, 0xd16657e1,
	.word	0x3e704104, 0x10410410, 0x3fe6ce69, 0x31d5858d,
	.word	0x3e702040, 0x81020408, 0x3fe6b761, 0x2ec892f6,

	.word	0x3fefffff, 0xfee7f18f	! K0 =  9.99999997962321453275e-01
	.word	0xbfdfffff, 0xfe07e52f	! K1 = -4.99999998166077580600e-01
	.word	0x3fd80118, 0x0ca296d9	! K2 =  3.75066768969515586277e-01
	.word	0xbfd400fc, 0x0bbb8e78	! K3 = -3.12560092408808548438e-01
	.word	0x7ffe0000, 0x7ffe0000	! DC0
	.word	0x3f800000, 0x40000000	! FTWO

#define stridex		%l4
#define stridex2	%l1
#define stridey		%l3
#define stridey2	%i2
#define TBL		%l2
#define counter		%i5

#define K3		%f38
#define K2		%f36
#define K1		%f34
#define K0		%f32
#define DC0		%f4
#define FONE		%f2
#define FTWO		%f3

#define _0x00800000	%o2
#define _0x7f800000	%o4

#define tmp0		STACK_BIAS-0x30
#define tmp1		STACK_BIAS-0x28
#define tmp2		STACK_BIAS-0x20
#define tmp3		STACK_BIAS-0x18
#define tmp_counter	STACK_BIAS-0x10
#define tmp_px		STACK_BIAS-0x08

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x30

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!  ((float*)&ddx0)[0] = *px;
!  ax0 = *(int*)px;
!
!  ((float*)&ddx0)[1] = *(px + stridex);
!  ax1 = *(int*)(px + stridex);
!
!  px += stridex2;
!
!  if ( ax0 >= 0x7f800000 )
!  {
!    RETURN ( FONE / ((float*)&dres0)[0] );
!  }
!  if ( ax0 < 0x00800000 )
!  {
!    float res = ((float*)&dres0)[0];
!
!    if ( (ax0 & 0x7fffffff) == 0 )  /* |X| = zero  */
!    {
!      RETURN ( FONE / res )
!    }
!    else if ( ax0 >= 0 )  /* X = denormal  */
!    {
!      double    res0, xx0, tbl_div0, tbl_sqrt0;
!      float    fres0;
!      int    iax0, si0, iexp0;
!
!      res = *(int*)&res;
!      res *= FTWO;
!      ax0 = *(int*)&res;
!      iexp0 = ax0 >> 24;
!      iexp0 = 0x3f + 0x4b - iexp0;
!      iexp0 = iexp0 << 23;
!
!      si0 = (ax0 >> 13) & 0x7f0;
!
!      tbl_div0 = ((double*)((char*)__TBL_rsqrtf + si0))[0];
!      tbl_sqrt0 = ((double*)((char*)__TBL_rsqrtf + si0))[1];
!      iax0 = ax0 & 0x7ffe0000;
!      iax0 = ax0 - iax0;
!      xx0 = iax0 * tbl_div0;
!      res0 = tbl_sqrt0 * (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);
!
!      fres0 = res0;
!      iexp0 += *(int*)&fres0;
!      RETURN(*(float*)&iexp0)
!    }
!    else  /* X = negative  */
!    {
!      RETURN ( sqrtf(res) )
!    }
!  }
!  if ( ax1 >= 0x7f800000 )
!  {
!    RETURN ( FONE / ((float*)&dres0)[1] )
!  }
!  if ( ax1 < 0x00800000 )
!  {
!    float res = ((float*)&dres0)[1];
!    if ( (ax0 & 0x7fffffff) == 0 )  /* |X| = zero  */
!    {
!      RETURN ( FONE / res )
!    }
!    else if ( ax0 >= 0 )  /* X = denormal  */
!    {
!      double    res0, xx0, tbl_div0, tbl_sqrt0;
!      float    fres0;
!      int    iax1, si0, iexp0;
!
!      res = *(int*)&res;
!      res *= FTWO;
!      ax1 = *(int*)&res;
!      iexp0 = ax1 >> 24;
!      iexp0 = 0x3f + 0x4b - iexp0;
!      iexp0 = iexp0 << 23;
!
!      si0 = (ax1 >> 13) & 0x7f0;
!
!      tbl_div0 = ((double*)((char*)__TBL_rsqrtf + si0))[0];
!      tbl_sqrt0 = ((double*)((char*)__TBL_rsqrtf + si0))[1];
!      iax1 = ax1 & 0x7ffe0000;
!      iax1 = ax1 - iax1;
!      xx0 = iax1 * tbl_div0;
!      res0 = tbl_sqrt0 * (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);
!
!      fres0 = res0;
!      iexp0 += *(int*)&fres0;
!      RETURN(*(float*)&iexp0)
!    }
!    else  /* X = negative  */
!    {
!      RETURN ( sqrtf(res) )
!    }
!  }
!
!  iexp0 = ax0 >> 24;
!  iexp1 = ax1 >> 24;
!  iexp0 = 0x3f - iexp0;
!  iexp1 = 0x3f - iexp1;
!  iexp1 &= 0x1ff;
!  lexp0 = iexp0 << 55;
!  lexp1 = iexp1 << 23;
!
!  lexp0 |= lexp1;
!
!  fdx0 = *((double*)&lexp0);
!
!  si0 = ax0 >> 13;
!  si1 = ax1 >> 13;
!  si0 &= 0x7f0;
!  si1 &= 0x7f0;
!
!  addr0 = (char*)TBL + si0;
!  addr1 = (char*)TBL + si1;
!  tbl_div0 = ((double*)((char*)TBL + si0))[0];
!  tbl_div1 = ((double*)((char*)TBL + si1))[0];
!  tbl_sqrt0 = ((double*)addr0)[1];
!  tbl_sqrt1 = ((double*)addr1)[1];
!  dfx0 = vis_fand(ddx0,DC0);
!  dfx0 = vis_fpsub32(ddx0,dfx0);
!  dtmp0 = (double)(((int*)&dfx0)[0]);
!  dtmp1 = (double)(((int*)&dfx0)[1]);
!  xx0 = dtmp0 * tbl_div0;
!  xx1 = dtmp1 * tbl_div1;
!  res0 = K3 * xx0;
!  res1 = K3 * xx1;
!  res0 += K2;
!  res1 += K2;
!  res0 *= xx0;
!  res1 *= xx1;
!  res0 += K1;
!  res1 += K1;
!  res0 *= xx0;
!  res1 *= xx1;
!  res0 += K0;
!  res1 += K0;
!  res0 = tbl_sqrt0 * res0;
!  res1 = tbl_sqrt1 * res1;
!  ((float*)&dres0)[0] = (float)res0;
!  ((float*)&dres0)[1] = (float)res1;
!  dres0 = vis_fpadd32(dres0,fdx0);
!  *py = ((float*)&dres0)[0];
!  *(py + stridey) = ((float*)&dres0)[1];
!  py += stridey2;
!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vrsqrtf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,l2)

	st	%i0,[%fp+tmp_counter]
	stx	%i1,[%fp+tmp_px]

	ldd	[TBL+2048],K0
	sll	%i2,2,stridex

	ldd	[TBL+2048+8],K1
	sll	%i4,2,stridey
	mov	%i3,%i2

	ldd	[TBL+2048+16],K2
	sethi	%hi(0x7f800000),_0x7f800000
	sll	stridex,1,stridex2

	ldd	[TBL+2048+24],K3
	sethi	%hi(0x00800000),_0x00800000

	ldd	[TBL+2048+32],DC0
	add	%g0,0x3f,%l0

	ldd	[TBL+2048+40],FONE
!	ld	[TBL+2048+44],FTWO
.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%l7
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit

	lda	[%l7]0x82,%f14		! (4_0) ((float*)&ddx0)[0] = *px;

	lda	[stridex+%l7]0x82,%f15	! (5_0) ((float*)&ddx0)[1] = *(px + stridex);
	sethi	%hi(0x7ffffc00),%o0

	lda	[%l7]0x82,%g1		! (4_0) ax0 = *(int*)px;
	add	%l7,stridex2,%i1	! px += stridex2
	add	%o0,0x3ff,%o0

	lda	[stridex+%l7]0x82,%g5	! (5_0) ax1 = *(int*)(px + stridex);
	fand	%f14,DC0,%f16		! (4_0) dfx0 = vis_fand(ddx0,DC0);

	sra	%g1,13,%l5		! (4_0) si0 = ax0 >> 13;
	add	%i1,stridex2,%o5	! px += stridex2

	cmp	%g1,_0x7f800000		! (4_1) ax0 ? 0x7f800000
	bge,pn	%icc,.spec0		! (4_1) if ( ax0 >= 0x7f800000 )
	nop

	cmp	%g1,_0x00800000		! (4_1) ax0 ? 0x00800000
	bl,pn	%icc,.spec1		! (4_1) if ( ax0 < 0x00800000 )
	sra	%g5,13,%l6		! (5_0) si1 = ax1 >> 13;
.cont_spec:
	and	%l5,2032,%l5		! (4_0) si0 &= 0x7f0;

	ldd	[%l5+TBL],%f54		! (4_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	sra	%g5,24,%l7		! (5_0) iexp1 = ax1 >> 24;
	and	%l6,2032,%l6		! (5_0) si1 &= 0x7f0;
	fpsub32	%f14,%f16,%f16		! (4_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%l6+TBL],%f46		! (5_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sra	%g1,24,%i3		! (4_0) iexp0 = ax0 >> 24;
	sub	%l0,%l7,%l7		! (5_0) iexp1 = 0x3f - iexp1;

	and	%l7,511,%l1		! (5_0) iexp1 = 0x1ff;
	add	%l6,TBL,%l6		! (5_0) addr1 = (char*)TBL + si1;

	sllx	%l1,23,%l1		! (5_0) lexp1 = iexp1 << 23;
	sub	%l0,%i3,%o0		! (4_0) iexp0 = 0x3f - iexp0;
	fitod	%f16,%f56		! (4_0) dtmp0 = (double)(((int*)dfx0)[0]);

	sllx	%o0,55,%o0		! (4_0) lexp0 = iexp0 << 55;
	fitod	%f17,%f44		! (5_0) dtmp1 = (double)(((int*)dfx0)[1]);

	or	%o0,%l1,%o0		! (4_0) lexp0 |= lexp1;

	stx	%o0,[%fp+tmp0]		! (4_0) fdx0 = *((double*)lexp0);

	fmuld	%f56,%f54,%f40		! (4_0) xx0 = dtmp0 * tbl_div0;

	lda	[%i1]0x82,%f18		! (0_0) ((float*)&ddx0)[0] = *px;
	fmuld	%f44,%f46,%f46		! (5_1) xx1 = dtmp1 * tbl_div1;

	lda	[stridex+%i1]0x82,%f19	! (1_0) ((float*)&ddx0)[1] = *(px + stridex);

	lda	[%i1]0x82,%g1		! (0_0) ax0 = *(int*)px;

	lda	[stridex+%i1]0x82,%i4	! (1_0) ax1 = *(int*)(px + stridex);
	cmp	%g5,_0x7f800000		! (5_1) ax1 ? 0x7f800000
	bge,pn	%icc,.update0		! (5_1) if ( ax1 >= 0x7f800000 )
	fmuld	K3,%f40,%f52		! (4_1) res0 = K3 * xx0;
.cont0:
	fmuld	K3,%f46,%f50		! (5_1) res1 = K3 * xx1;
	cmp	%g5,_0x00800000		! (5_1) ax1 ? 0x00800000
	bl,pn	%icc,.update1		! (5_1) if ( ax1 < 0x00800000 )
	fand	%f18,DC0,%f56		! (0_0) dfx0 = vis_fand(ddx0,DC0);
.cont1:
	sra	%g1,13,%o0		! (0_0) si0 = ax0 >> 13;
	cmp	%g1,_0x7f800000		! (0_0) ax0 ? 0x7f800000

	sra	%i4,13,%g5		! (1_0) si1 = ax1 >> 13;
	and	%o0,2032,%o0		! (0_0) si0 &= 0x7f0;

	ldd	[%o0+TBL],%f54		! (0_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	sra	%i4,24,%i1		! (1_0) iexp1 = ax1 >> 24;
	and	%g5,2032,%o7		! (1_0) si1 &= 0x7f0;
	fpsub32	%f18,%f56,%f30		! (0_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o7+TBL],%f44		! (1_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sra	%g1,24,%i3		! (0_0) iexp0 = ax0 >> 24;
	sub	%l0,%i1,%i1		! (1_0) iexp1 = 0x3f - iexp1;
	faddd	%f52,K2,%f62		! (4_1) res0 += K2;

	sub	%l0,%i3,%g5		! (0_0) iexp0 = 0x3f - iexp0;
	bge,pn	%icc,.update2		! (0_0) if ( ax0 >= 0x7f800000 )
	faddd	%f50,K2,%f60		! (5_1) res1 += K2;
.cont2:
	cmp	%g1,_0x00800000		! (0_0) ax0 ? 0x00800000
	and	%i1,511,%i0		! (1_0) iexp1 = 0x1ff;
	fitod	%f30,%f56		! (0_0) dtmp0 = (double)(((int*)dfx0)[0]);

	sllx	%i0,23,%i0		! (1_0) lexp1 = iexp1 << 23;
	bl,pn	%icc,.update3		! (0_0) if ( ax0 < 0x00800000 )
	fitod	%f31,%f50		! (1_0) dtmp0 = (double)(((int*)dfx0)[0]);
.cont3:
	fmuld	%f62,%f40,%f30		! (4_1) res0 *= xx0;
	sllx	%g5,55,%g5		! (0_0) lexp0 = iexp0 << 55;

	fmuld	%f60,%f46,%f48		! (5_1) res1 *= xx1;
	or	%g5,%i0,%g5		! (0_0) lexp0 |= lexp1;
	stx	%g5,[%fp+tmp1]		! (0_0) fdx0 = *((double*)lexp0);

	fmuld	%f56,%f54,%f26		! (0_0) xx0 = dtmp0 * tbl_div0;
	sll	stridex,1,stridex2	! stridex2 = stridex * 2;

	lda	[%o5]0x82,%f24		! (2_0) ((float*)&ddx0)[0] = *px;
	add	%o7,TBL,%o7		! (1_0) addr0 = (char*)TBL + si0;
	fmuld	%f50,%f44,%f44		! (1_0) xx0 = dtmp0 * tbl_div0;

	lda	[stridex+%o5]0x82,%f25	! (3_0) ((float*)&ddx0)[1] = *(px + stridex);
	add	%l5,TBL,%l5		! (4_1) addr0 = (char*)TBL + si0;
	faddd	%f30,K1,%f62		! (4_1) res0 += K1;

	lda	[%o5]0x82,%g1		! (2_0) ax0 = *(int*)px;
	add	%o5,stridex2,%l7	! px += stridex2
	faddd	%f48,K1,%f42		! (5_1) res1 += K1;

	lda	[stridex+%o5]0x82,%o5	! (3_0) ax1 = *(int*)(px + stridex);
	cmp	%i4,_0x7f800000		! (1_0) ax1 ? 0x7f800000
	bge,pn	%icc,.update4		! (1_0) if ( ax1 >= 0x7f800000 )
	fmuld	K3,%f26,%f52		! (0_0) res0 = K3 * xx0;
.cont4:
	fmuld	K3,%f44,%f50		! (1_0) res1 = K3 * xx1;
	cmp	%i4,_0x00800000		! (1_0) ax1 ? 0x00800000
	bl,pn	%icc,.update5		! (1_0) if ( ax1 < 0x00800000 )
	fand	%f24,DC0,%f54		! (2_0) dfx0 = vis_fand(ddx0,DC0);
.cont5:
	fmuld	%f62,%f40,%f48		! (4_1) res0 *= xx0;
	sra	%g1,13,%i0		! (2_0) si0 = ax0 >> 13;
	cmp	%g1,_0x7f800000		! (2_0) ax0 ? 0x7f800000

	fmuld	%f42,%f46,%f58		! (5_1) res1 *= xx1;
	sra	%o5,13,%o1		! (3_0) si1 = ax1 >> 13;
	and	%i0,2032,%i0		! (2_0) si0 &= 0x7f0;

	ldd	[%i0+TBL],%f30		! (2_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	sra	%o5,24,%o3		! (3_0) iexp1 = ax1 >> 24;
	and	%o1,2032,%o1		! (3_0) si1 &= 0x7f0;
	fpsub32	%f24,%f54,%f12		! (2_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o1+TBL],%f46		! (3_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sra	%g1,24,%i3		! (2_0) iexp0 = ax0 >> 24;
	sub	%l0,%o3,%o3		! (3_0) iexp1 = 0x3f - iexp1;
	faddd	%f52,K2,%f40		! (0_0) res0 += K2;

	ldd	[%l5+8],%f42		! (4_1) tbl_sqrt0 = ((double*)addr0)[1];
	sub	%l0,%i3,%g5		! (2_0) iexp0 = 0x3f - iexp0;
	and	%o3,511,%i3		! (3_0) iexp1 &= 0x1ff;
	faddd	%f50,K2,%f60		! (1_0) res0 += K2;

	ldd	[%l6+8],%f28		! (5_1) tbl_sqrt1 = ((double*)addr1)[1];
	sllx	%g5,55,%g5		! (2_0) lexp0 = iexp0 << 55;
	add	%i0,TBL,%i0		! (2_0) addr0 = (char*)TBL + si0;
	fitod	%f12,%f56		! (2_0) dtmp0 = (double)(((int*)dfx0)[0]);

	sllx	%i3,23,%i3		! (3_0) lexp1 = iexp1 << 23;
	fitod	%f13,%f50		! (3_0) dtmp1 = (double)(((int*)dfx0)[1]);

	fmuld	%f40,%f26,%f40		! (0_0) res0 *= xx0;
	or	%g5,%i3,%g5		! (2_0) lexp0 |= lexp1;
	faddd	%f48,K0,%f62		! (4_1) res0 += K0;

	fmuld	%f60,%f44,%f48		! (1_0) res1 *= xx1;
	add	%o1,TBL,%o1		! (3_0) addr1 = (char*)TBL + si1;
	stx	%g5,[%fp+tmp2]		! (2_0) fdx0 = *((double*)lexp0);
	faddd	%f58,K0,%f60		! (5_1) res1 += K0;

	fmuld	%f56,%f30,%f30		! (2_0) xx0 = dtmp0 * tbl_div0;
	bge,pn	%icc,.update6		! (2_0) if ( ax0 >= 0x7f800000 )
	lda	[%l7]0x82,%f14		! (4_0) ((float*)&ddx0)[0] = *px;
.cont6:
	cmp	%g1,_0x00800000		! (2_0) ax0 ? 0x00800000
	bl,pn	%icc,.update7		! (2_0) if ( ax0 < 0x00800000 )
	nop
.cont7:
	fmuld	%f50,%f46,%f24		! (3_0) xx1 = dtmp1 * tbl_div1;

	lda	[stridex+%l7]0x82,%f15	! (5_0) ((float*)&ddx0)[1] = *(px + stridex);
	cmp	%o5,_0x7f800000		! (3_0) ax1 ? 0x7f800000
	fmuld	%f42,%f62,%f58		! (4_1) res0 = tbl_sqrt0 * res0;
	faddd	%f40,K1,%f46		! (0_0) res0 += K1;

	lda	[%l7]0x82,%g1		! (4_0) ax0 = *(int*)px;
	add	%l7,stridex2,%i1	! px += stridex2
	fmuld	%f28,%f60,%f56		! (5_1) res1 = tbl_sqrt1 * res1;
	faddd	%f48,K1,%f62		! (1_0) res1 += K1;

	lda	[stridex+%l7]0x82,%g5	! (5_0) ax1 = *(int*)(px + stridex);
	add	%o0,TBL,%o0		! (0_0) addr0 = (char*)TBL + si0;
	bge,pn	%icc,.update8		! (3_0) if ( ax1 >= 0x7f800000 )
	fmuld	K3,%f30,%f52		! (2_0) res0 = K3 * xx0;
.cont8:
	fmuld	K3,%f24,%f50		! (3_0) res1 = K3 * xx1;
	cmp	%o5,_0x00800000		! (3_0) ax1 ? 0x00800000
	bl,pn	%icc,.update9		! (3_0) if ( ax1 < 0x00800000 )
	fand	%f14,DC0,%f16		! (4_0) dfx0 = vis_fand(ddx0,DC0);
.cont9:
	fmuld	%f46,%f26,%f48		! (0_0) res0 *= xx0;
	sra	%g1,13,%l5		! (4_0) si0 = ax0 >> 13;
	add	%i1,stridex2,%o5	! px += stridex2
	fdtos	%f58,%f6		! (4_1) ((float*)&dres0)[0] = (float)res0;

	fmuld	%f62,%f44,%f40		! (1_0) res1 *= xx1;
	sra	%g5,13,%l6		! (5_0) si1 = ax1 >> 13;
	and	%l5,2032,%l5		! (4_0) si0 &= 0x7f0;
	fdtos	%f56,%f7		! (5_1) ((float*)&dres0)[1] = (float)res1;

	ldd	[%l5+TBL],%f54		! (4_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	sra	%g5,24,%l7		! (5_0) iexp1 = ax1 >> 24;
	and	%l6,2032,%l6		! (5_0) si1 &= 0x7f0;
	fpsub32	%f14,%f16,%f16		! (4_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%l6+TBL],%f46		! (5_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sra	%g1,24,%i3		! (4_0) iexp0 = ax0 >> 24;
	sub	%l0,%l7,%l7		! (5_0) iexp1 = 0x3f - iexp1;
	faddd	%f52,K2,%f58		! (2_0) res0 += K2;

	ldd	[%o0+8],%f42		! (0_0) tbl_sqrt0 = ((double*)addr0)[1];
	and	%l7,511,%l1		! (5_0) iexp1 = 0x1ff;
	add	%l6,TBL,%l6		! (5_0) addr1 = (char*)TBL + si1;
	faddd	%f50,K2,%f60		! (3_0) res1 += K2;

	ldd	[%o7+8],%f28		! (1_0) tbl_sqrt1 = ((double*)addr1)[1];
	sllx	%l1,23,%l1		! (5_0) lexp1 = iexp1 << 23;
	sub	%l0,%i3,%o0		! (4_0) iexp0 = 0x3f - iexp0;
	fitod	%f16,%f56		! (4_0) dtmp0 = (double)(((int*)dfx0)[0]);

	ldd	[%fp+tmp0],%f52		! (4_1) fdx0 = *((double*)lexp0);
	sllx	%o0,55,%o0		! (4_0) lexp0 = iexp0 << 55;
	fitod	%f17,%f44		! (5_0) dtmp1 = (double)(((int*)dfx0)[1]);

	fmuld	%f58,%f30,%f62		! (2_0) res0 *= xx0;
	or	%o0,%l1,%o0		! (4_0) lexp0 |= lexp1;
	faddd	%f48,K0,%f22		! (0_0) res0 += K0;

	fmuld	%f60,%f24,%f58		! (3_0) res1 *= xx1;
	stx	%o0,[%fp+tmp0]		! (4_0) fdx0 = *((double*)lexp0);
	faddd	%f40,K0,%f26		! (1_0) res1 += K0;

	fmuld	%f56,%f54,%f40		! (4_0) xx0 = dtmp0 * tbl_div0;
	fpadd32	%f6,%f52,%f10		! (4_1) dres0 = vis_fpadd32(dres0,fdx0);

	or	%g0,%i2,%l7
	add	stridey,stridey,stridey2

	cmp	counter,6
	bl,pn	%icc,.tail
	nop

	ba	.main_loop
	sub	counter,6,counter	! counter

	.align	16
.main_loop:
	lda	[%i1]0x82,%f18		! (0_0) ((float*)&ddx0)[0] = *px;
	cmp	%g1,_0x7f800000		! (4_1) ax0 ? 0x7f800000
	bge,pn	%icc,.update10		! (4_1) if ( ax0 >= 0x7f800000 )
	fmuld	%f44,%f46,%f46		! (5_1) xx1 = dtmp1 * tbl_div1;
.cont10:
	lda	[stridex+%i1]0x82,%f19	! (1_0) ((float*)&ddx0)[1] = *(px + stridex);
	cmp	%g1,_0x00800000		! (4_1) ax0 ? 0x00800000
	fmuld	%f42,%f22,%f44		! (0_1) res0 = tbl_sqrt0 * res0;
	faddd	%f62,K1,%f42		! (2_1) res0 += K1;

	lda	[%i1]0x82,%g1		! (0_0) ax0 = *(int*)px;
	fmuld	%f28,%f26,%f60		! (1_1) res1 = tbl_sqrt1 * res1;
	bl,pn	%icc,.update11		! (4_1) if ( ax0 < 0x00800000 )
	faddd	%f58,K1,%f62		! (3_1) res1 += K1;
.cont11:
	lda	[stridex+%i1]0x82,%i4	! (1_0) ax1 = *(int*)(px + stridex);
	cmp	%g5,_0x7f800000		! (5_1) ax1 ? 0x7f800000
	bge,pn	%icc,.update12		! (5_1) if ( ax1 >= 0x7f800000 )
	fmuld	K3,%f40,%f52		! (4_1) res0 = K3 * xx0;
.cont12:
	fmuld	K3,%f46,%f50		! (5_1) res1 = K3 * xx1;
	cmp	%g5,_0x00800000		! (5_1) ax1 ? 0x00800000
	bl,pn	%icc,.update13		! (5_1) if ( ax1 < 0x00800000 )
	fand	%f18,DC0,%f56		! (0_0) dfx0 = vis_fand(ddx0,DC0);
.cont13:
	fmuld	%f42,%f30,%f48		! (2_1) res0 *= xx0;
	sra	%g1,13,%o0		! (0_0) si0 = ax0 >> 13;
	cmp	%g1,_0x7f800000		! (0_0) ax0 ? 0x7f800000
	fdtos	%f44,%f8		! (0_1) ((float*)&dres0)[0] = (float)res0;

	fmuld	%f62,%f24,%f58		! (3_1) res1 *= xx1;
	sra	%i4,13,%g5		! (1_0) si1 = ax1 >> 13;
	and	%o0,2032,%o0		! (0_0) si0 &= 0x7f0;
	fdtos	%f60,%f9		! (1_1) ((float*)&dres0)[1] = (float)res1;

	ldd	[%o0+TBL],%f54		! (0_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	sra	%i4,24,%i1		! (1_0) iexp1 = ax1 >> 24;
	and	%g5,2032,%o7		! (1_0) si1 &= 0x7f0;
	fpsub32	%f18,%f56,%f30		! (0_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o7+TBL],%f44		! (1_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sra	%g1,24,%i3		! (0_0) iexp0 = ax0 >> 24;
	sub	%l0,%i1,%i1		! (1_0) iexp1 = 0x3f - iexp1;
	faddd	%f52,K2,%f62		! (4_1) res0 += K2;

	ldd	[%i0+8],%f42		! (2_1) tbl_sqrt0 = ((double*)addr0)[1];
	sub	%l0,%i3,%g5		! (0_0) iexp0 = 0x3f - iexp0;
	bge,pn	%icc,.update14		! (0_0) if ( ax0 >= 0x7f800000 )
	faddd	%f50,K2,%f60		! (5_1) res1 += K2;
.cont14:
	ldd	[%o1+8],%f28		! (3_1) tbl_sqrt1 = ((double*)addr0)[1];
	cmp	%g1,_0x00800000		! (0_0) ax0 ? 0x00800000
	and	%i1,511,%i0		! (1_0) iexp1 = 0x1ff;
	fitod	%f30,%f56		! (0_0) dtmp0 = (double)(((int*)dfx0)[0]);

	ldd	[%fp+tmp1],%f52		! (0_1) fdx0 = *((double*)lexp0);
	sllx	%i0,23,%i0		! (1_0) lexp1 = iexp1 << 23;
	bl,pn	%icc,.update15		! (0_0) if ( ax0 < 0x00800000 )
	fitod	%f31,%f50		! (1_0) dtmp0 = (double)(((int*)dfx0)[0]);
.cont15:
	fmuld	%f62,%f40,%f30		! (4_1) res0 *= xx0;
	sllx	%g5,55,%g5		! (0_0) lexp0 = iexp0 << 55;
	st	%f10,[%l7]		! (4_2) *py = ((float*)&dres0)[0];
	faddd	%f48,K0,%f62		! (2_1) res0 += K0;

	fmuld	%f60,%f46,%f48		! (5_1) res1 *= xx1;
	or	%g5,%i0,%g5		! (0_0) lexp0 |= lexp1;
	stx	%g5,[%fp+tmp1]		! (0_0) fdx0 = *((double*)lexp0);
	faddd	%f58,K0,%f60		! (3_1) res1 += K0;

	fmuld	%f56,%f54,%f26		! (0_0) xx0 = dtmp0 * tbl_div0;
	sll	stridex,1,stridex2	! stridex2 = stridex * 2;
	st	%f11,[stridey+%l7]	! (5_2) *(py + stridey) = ((float*)&dres0)[1];
	fpadd32	%f8,%f52,%f10		! (0_1) dres0 = vis_fpadd32(dres0,fdx0);

	lda	[%o5]0x82,%f24		! (2_0) ((float*)&ddx0)[0] = *px;
	add	%l7,stridey2,%i1	! py += stridey2
	add	%o7,TBL,%o7		! (1_0) addr0 = (char*)TBL + si0;
	fmuld	%f50,%f44,%f44		! (1_0) xx0 = dtmp0 * tbl_div0;

	lda	[stridex+%o5]0x82,%f25	! (3_0) ((float*)&ddx0)[1] = *(px + stridex);
	add	%l5,TBL,%l5		! (4_1) addr0 = (char*)TBL + si0;
	fmuld	%f42,%f62,%f58		! (2_1) res0 = tbl_sqrt0 * res0;
	faddd	%f30,K1,%f62		! (4_1) res0 += K1;

	lda	[%o5]0x82,%g1		! (2_0) ax0 = *(int*)px;
	add	%o5,stridex2,%l7	! px += stridex2
	fmuld	%f28,%f60,%f56		! (3_1) res1 = tbl_sqrt1 * res1;
	faddd	%f48,K1,%f42		! (5_1) res1 += K1;

	lda	[stridex+%o5]0x82,%o5	! (3_0) ax1 = *(int*)(px + stridex);
	cmp	%i4,_0x7f800000		! (1_0) ax1 ? 0x7f800000
	bge,pn	%icc,.update16		! (1_0) if ( ax1 >= 0x7f800000 )
	fmuld	K3,%f26,%f52		! (0_0) res0 = K3 * xx0;
.cont16:
	fmuld	K3,%f44,%f50		! (1_0) res1 = K3 * xx1;
	cmp	%i4,_0x00800000		! (1_0) ax1 ? 0x00800000
	bl,pn	%icc,.update17		! (1_0) if ( ax1 < 0x00800000 )
	fand	%f24,DC0,%f54		! (2_0) dfx0 = vis_fand(ddx0,DC0);
.cont17:
	fmuld	%f62,%f40,%f48		! (4_1) res0 *= xx0;
	sra	%g1,13,%i0		! (2_0) si0 = ax0 >> 13;
	cmp	%g1,_0x7f800000		! (2_0) ax0 ? 0x7f800000
	fdtos	%f58,%f20		! (2_1) ((float*)&dres0)[0] = (float)res0;

	fmuld	%f42,%f46,%f58		! (5_1) res1 *= xx1;
	sra	%o5,13,%o1		! (3_0) si1 = ax1 >> 13;
	and	%i0,2032,%i0		! (2_0) si0 &= 0x7f0;
	fdtos	%f56,%f21		! (3_1) ((float*)&dres0)[0] = (float)res0;

	ldd	[%i0+TBL],%f30		! (2_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	sra	%o5,24,%o3		! (3_0) iexp1 = ax1 >> 24;
	and	%o1,2032,%o1		! (3_0) si1 &= 0x7f0;
	fpsub32	%f24,%f54,%f12		! (2_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o1+TBL],%f46		! (3_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sra	%g1,24,%i3		! (2_0) iexp0 = ax0 >> 24;
	sub	%l0,%o3,%o3		! (3_0) iexp1 = 0x3f - iexp1;
	faddd	%f52,K2,%f40		! (0_0) res0 += K2;

	ldd	[%l5+8],%f42		! (4_1) tbl_sqrt0 = ((double*)addr0)[1];
	sub	%l0,%i3,%g5		! (2_0) iexp0 = 0x3f - iexp0;
	and	%o3,511,%i3		! (3_0) iexp1 &= 0x1ff;
	faddd	%f50,K2,%f60		! (1_0) res0 += K2;

	ldd	[%l6+8],%f28		! (5_1) tbl_sqrt1 = ((double*)addr1)[1];
	sllx	%g5,55,%g5		! (2_0) lexp0 = iexp0 << 55;
	add	%i0,TBL,%i0		! (2_0) addr0 = (char*)TBL + si0;
	fitod	%f12,%f56		! (2_0) dtmp0 = (double)(((int*)dfx0)[0]);

	ldd	[%fp+tmp2],%f52		! (2_1) fdx0 = *((double*)lexp0);
	sllx	%i3,23,%i3		! (3_0) lexp1 = iexp1 << 23;
	add	%i1,stridey2,%o3	! py += stridey2
	fitod	%f13,%f50		! (3_0) dtmp1 = (double)(((int*)dfx0)[1]);

	fmuld	%f40,%f26,%f40		! (0_0) res0 *= xx0;
	or	%g5,%i3,%g5		! (2_0) lexp0 |= lexp1;
	st	%f10,[%i1]		! (0_1) *py = ((float*)&dres0)[0];
	faddd	%f48,K0,%f62		! (4_1) res0 += K0;

	fmuld	%f60,%f44,%f48		! (1_0) res1 *= xx1;
	add	%o1,TBL,%o1		! (3_0) addr1 = (char*)TBL + si1;
	stx	%g5,[%fp+tmp2]		! (2_0) fdx0 = *((double*)lexp0);
	faddd	%f58,K0,%f60		! (5_1) res1 += K0;

	fmuld	%f56,%f30,%f30		! (2_0) xx0 = dtmp0 * tbl_div0;
	bge,pn	%icc,.update18		! (2_0) if ( ax0 >= 0x7f800000 )
	st	%f11,[stridey+%i1]	! (1_1) *(py + stridey) = ((float*)&dres0)[1];
	fpadd32	%f20,%f52,%f0		! (2_1) dres0 = vis_fpadd32(dres0,fdx0);
.cont18:
	cmp	%g1,_0x00800000		! (2_0) ax0 ? 0x00800000
	bl,pn	%icc,.update19		! (2_0) if ( ax0 < 0x00800000 )
	lda	[%l7]0x82,%f14		! (4_0) ((float*)&ddx0)[0] = *px;
	fmuld	%f50,%f46,%f24		! (3_0) xx1 = dtmp1 * tbl_div1;
.cont19:
	lda	[stridex+%l7]0x82,%f15	! (5_0) ((float*)&ddx0)[1] = *(px + stridex);
	cmp	%o5,_0x7f800000		! (3_0) ax1 ? 0x7f800000
	fmuld	%f42,%f62,%f58		! (4_1) res0 = tbl_sqrt0 * res0;
	faddd	%f40,K1,%f46		! (0_0) res0 += K1;

	lda	[%l7]0x82,%g1		! (4_0) ax0 = *(int*)px;
	add	%l7,stridex2,%i1	! px += stridex2
	fmuld	%f28,%f60,%f56		! (5_1) res1 = tbl_sqrt1 * res1;
	faddd	%f48,K1,%f62		! (1_0) res1 += K1;

	lda	[stridex+%l7]0x82,%g5	! (5_0) ax1 = *(int*)(px + stridex);
	add	%o0,TBL,%o0		! (0_0) addr0 = (char*)TBL + si0;
	bge,pn	%icc,.update20		! (3_0) if ( ax1 >= 0x7f800000 )
	fmuld	K3,%f30,%f52		! (2_0) res0 = K3 * xx0;
.cont20:
	fmuld	K3,%f24,%f50		! (3_0) res1 = K3 * xx1;
	cmp	%o5,_0x00800000		! (3_0) ax1 ? 0x00800000
	bl,pn	%icc,.update21		! (3_0) if ( ax1 < 0x00800000 )
	fand	%f14,DC0,%f16		! (4_0) dfx0 = vis_fand(ddx0,DC0);
.cont21:
	fmuld	%f46,%f26,%f48		! (0_0) res0 *= xx0;
	sra	%g1,13,%l5		! (4_0) si0 = ax0 >> 13;
	add	%i1,stridex2,%o5	! px += stridex2
	fdtos	%f58,%f6		! (4_1) ((float*)&dres0)[0] = (float)res0;

	fmuld	%f62,%f44,%f40		! (1_0) res1 *= xx1;
	sra	%g5,13,%l6		! (5_0) si1 = ax1 >> 13;
	and	%l5,2032,%l5		! (4_0) si0 &= 0x7f0;
	fdtos	%f56,%f7		! (5_1) ((float*)&dres0)[1] = (float)res1;

	ldd	[%l5+TBL],%f54		! (4_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	sra	%g5,24,%l7		! (5_0) iexp1 = ax1 >> 24;
	and	%l6,2032,%l6		! (5_0) si1 &= 0x7f0;
	fpsub32	%f14,%f16,%f16		! (4_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%l6+TBL],%f46		! (5_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sra	%g1,24,%i3		! (4_0) iexp0 = ax0 >> 24;
	sub	%l0,%l7,%l7		! (5_0) iexp1 = 0x3f - iexp1;
	faddd	%f52,K2,%f58		! (2_0) res0 += K2;

	ldd	[%o0+8],%f42		! (0_0) tbl_sqrt0 = ((double*)addr0)[1];
	and	%l7,511,%l1		! (5_0) iexp1 = 0x1ff;
	add	%l6,TBL,%l6		! (5_0) addr1 = (char*)TBL + si1;
	faddd	%f50,K2,%f60		! (3_0) res1 += K2;

	ldd	[%o7+8],%f28		! (1_0) tbl_sqrt1 = ((double*)addr1)[1];
	sllx	%l1,23,%l1		! (5_0) lexp1 = iexp1 << 23;
	sub	%l0,%i3,%o0		! (4_0) iexp0 = 0x3f - iexp0;
	fitod	%f16,%f56		! (4_0) dtmp0 = (double)(((int*)dfx0)[0]);

	ldd	[%fp+tmp0],%f52		! (4_1) fdx0 = *((double*)lexp0);
	sllx	%o0,55,%o0		! (4_0) lexp0 = iexp0 << 55;
	add	%o3,stridey2,%l7	! py += stridey2
	fitod	%f17,%f44		! (5_0) dtmp1 = (double)(((int*)dfx0)[1]);

	fmuld	%f58,%f30,%f62		! (2_0) res0 *= xx0;
	or	%o0,%l1,%o0		! (4_0) lexp0 |= lexp1;
	st	%f0,[%o3]		! (2_1) *py = ((float*)&dres0)[0];
	faddd	%f48,K0,%f22		! (0_0) res0 += K0;

	fmuld	%f60,%f24,%f58		! (3_0) res1 *= xx1;
	subcc	counter,6,counter	! counter -= 6;
	stx	%o0,[%fp+tmp0]		! (4_0) fdx0 = *((double*)lexp0);
	faddd	%f40,K0,%f26		! (1_0) res1 += K0;

	fmuld	%f56,%f54,%f40		! (4_0) xx0 = dtmp0 * tbl_div0;
	st	%f1,[stridey+%o3]	! (3_1) *(py + stridey) = ((float*)&dres0)[1];
	bpos,pt	%icc,.main_loop
	fpadd32	%f6,%f52,%f10		! (4_1) dres0 = vis_fpadd32(dres0,fdx0);

	add	counter,6,counter
.tail:
	sll	stridex,1,stridex2
	subcc	counter,1,counter
	bneg,a	.begin
	mov	%l7,%i2

	fmuld	%f42,%f22,%f44		! (0_1) res0 = tbl_sqrt0 * res0;
	faddd	%f62,K1,%f42		! (2_1) res0 += K1;

	fmuld	%f28,%f26,%f60		! (1_1) res1 = tbl_sqrt1 * res1;

	fmuld	%f42,%f30,%f48		! (2_1) res0 *= xx0;
	fdtos	%f44,%f8		! (0_1) ((float*)&dres0)[0] = (float)res0;

	fdtos	%f60,%f9		! (1_1) ((float*)&dres0)[1] = (float)res1;

	ldd	[%i0+8],%f42		! (2_1) tbl_sqrt0 = ((double*)addr0)[1];

	ldd	[%fp+tmp1],%f52		! (0_1) fdx0 = *((double*)lexp0);

	st	%f10,[%l7]		! (4_2) *py = ((float*)&dres0)[0];
	subcc	counter,1,counter
	bneg,a	.begin
	add	%l7,stridey,%i2

	faddd	%f48,K0,%f62		! (2_1) res0 += K0;
	st	%f11,[stridey+%l7]	! (5_2) *(py + stridey) = ((float*)&dres0)[1];
	subcc	counter,1,counter
	bneg,a	.begin
	add	%l7,stridey2,%i2
	fpadd32	%f8,%f52,%f10		! (0_1) dres0 = vis_fpadd32(dres0,fdx0);

	add	%l7,stridey2,%i1	! py += stridey2

	fmuld	%f42,%f62,%f58		! (2_1) res0 = tbl_sqrt0 * res0;

	fdtos	%f58,%f20		! (2_1) ((float*)&dres0)[0] = (float)res0;

	ldd	[%fp+tmp2],%f52		! (2_1) fdx0 = *((double*)lexp0);
	add	%i1,stridey2,%o3	! py += stridey2

	st	%f10,[%i1]		! (0_1) *py = ((float*)&dres0)[0];
	subcc	counter,1,counter
	bneg,a	.begin
	add	%i1,stridey,%i2

	st	%f11,[stridey+%i1]	! (1_1) *(py + stridey) = ((float*)&dres0)[1];
	subcc	counter,1,counter
	bneg,a	.begin
	mov	%o3,%i2
	fpadd32	%f20,%f52,%f0		! (2_1) dres0 = vis_fpadd32(dres0,fdx0);

	st	%f0,[%o3]		! (2_1) *py = ((float*)&dres0)[0];
	ba	.begin
	add	%o3,stridey,%i2

	.align	16
.spec0:
	fdivs	FONE,%f14,%f14		! x0 = FONE / x0;
	add	%l7,stridex,%l7		! px += stridex
	st	%f14,[%i2]		! *py = x0;
	sub	counter,1,counter
	ba	.begin1
	add	%i2,stridey,%i2		! py += stridey

	.align	16
.spec1:
	andcc	%g1,%o0,%g0
	bz,a	1f
	fdivs	FONE,%f14,%f14		! x0 = DONE / x0;

	cmp	%g1,0
	bl,a	1f
	fsqrts	%f14,%f14		! x0 = sqrtf(x0);

	fitod	%f14,%f0
	fdtos	%f0,%f14
	fmuls	%f14,FTWO,%f14
	st	%f14,[%fp+tmp3]
	ld	[%fp+tmp3],%g1
	sethi	%hi(0x4b000000),%o0
	sra	%g1,13,%l5		! (4_0) si0 = ax0 >> 13;
	fands	%f14,DC0,%f16		! (4_0) dfx0 = vis_fand(ddx0,DC0);
	ba	.cont_spec
	sub	%g1,%o0,%g1
1:
	add	%l7,stridex,%l7		! px += stridex
	sub	counter,1,counter
	st	%f14,[%i2]		! *py = x0;
	ba	.begin1
	add	%i2,stridey,%i2		! py += stridey

	.align	16
.update0:
	cmp	counter,1
	ble	.cont0
	nop

	sub	%i1,stridex,%o1
	stx	%o1,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont0
	mov	1,counter

	.align	16
.update1:
	sethi	%hi(0x7ffffc00),%o0
	cmp	counter,1
	ble	.cont1

	add	%o0,0x3ff,%o0

	andcc	%g5,%o0,%g0
	bz,a	1f
	nop

	cmp	%g5,0
	bl,a	1f
	nop

	fitod	%f15,%f0
	fdtos	%f0,%f15
	fmuls	%f15,FTWO,%f15
	st	%f15,[%fp+tmp3]
	ld	[%fp+tmp3],%g5
	sethi	%hi(0x4b000000),%o0
	sub	%g5,%o0,%g5

	fands	%f15,DC0,%f17		! (4_0) dfx0 = vis_fand(ddx0,DC0);

	sra	%g5,13,%l6		! (5_0) si1 = ax1 >> 13;

	sra	%g5,24,%l7		! (5_0) iexp1 = ax1 >> 24;
	and	%l6,2032,%l6		! (5_0) si1 &= 0x7f0;

	fpsub32s	%f15,%f17,%f17	! (4_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%l6+TBL],%f46		! (5_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sub	%l0,%l7,%l1		! (5_0) iexp1 = 0x3f - iexp1;

	sll	%l1,23,%l1		! (5_0) lexp1 = iexp1 << 23;
	add	%l6,TBL,%l6		! (5_0) addr1 = (char*)TBL + si1;
	st	%l1,[%fp+tmp0+4]	! (4_0) fdx0 = *((double*)lexp0);
	fitod	%f17,%f44		! (5_0) dtmp1 = (double)(((int*)dfx0)[1]);

	fmuld	%f44,%f46,%f46		! (5_1) xx1 = dtmp1 * tbl_div1;

	ba	.cont1
	fmuld	K3,%f46,%f50		! (5_1) res1 = K3 * xx1;
1:
	sub	%i1,stridex,%o1
	stx	%o1,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont1
	mov	1,counter

	.align	16
.update2:
	cmp	counter,2
	ble	.cont2
	sub	%o5,stridex,%o1

	sub	%o1,stridex,%o1
	stx	%o1,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont2
	mov	2,counter

	.align	16
.update3:
	sethi	%hi(0x7ffffc00),%o1
	cmp	counter,2
	ble	.cont3

	add	%o1,0x3ff,%o1

	andcc	%g1,%o1,%g0
	bz,a	1f
	sub	%o5,stridex,%o1

	cmp	%g1,0
	bl,a	1f
	sub	%o5,stridex,%o1

	fitod	%f18,%f0
	fdtos	%f0,%f18
	fmuls	%f18,FTWO,%f18
	st	%f18,[%fp+tmp3]
	ld	[%fp+tmp3],%g1
	sethi	%hi(0x4b000000),%o1
	sub	%g1,%o1,%g1

	fand	%f18,DC0,%f56		! (0_0) dfx0 = vis_fand(ddx0,DC0);
	sra	%g1,13,%o0		! (0_0) si0 = ax0 >> 13;

	and	%o0,2032,%o0		! (0_0) si0 &= 0x7f0;

	ldd	[%o0+TBL],%f54		! (0_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	fpsub32	%f18,%f56,%f30		! (0_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	sra	%g1,24,%i3		! (0_0) iexp0 = ax0 >> 24;
	sub	%l0,%i3,%g5		! (0_0) iexp0 = 0x3f - iexp0;
	ba	.cont3
	fitod	%f30,%f56		! (0_0) dtmp0 = (double)(((int*)dfx0)[0]);
1:
	sub	%o1,stridex,%o1
	stx	%o1,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont3
	mov	2,counter

	.align	16
.update4:
	cmp	counter,3
	ble	.cont4
	sub	%l7,stridex2,%o1

	sub	%o1,stridex,%o1
	stx	%o1,[%fp+tmp_px]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont4
	mov	3,counter

	.align	16
.update5:
	sethi	%hi(0x7ffffc00),%o1
	cmp	counter,3
	ble	.cont5

	add	%o1,0x3ff,%o1

	andcc	%i4,%o1,%g0
	bz,a	1f
	sub	%l7,stridex2,%o1

	cmp	%i4,0
	bl,a	1f
	sub	%l7,stridex2,%o1

	fitod	%f19,%f0
	fdtos	%f0,%f19
	fmuls	%f19,FTWO,%f19
	st	%f19,[%fp+tmp3]
	ld	[%fp+tmp3],%i4
	sethi	%hi(0x4b000000),%o1
	sub	%i4,%o1,%i4

	fands	%f19,DC0,%f0		! (0_0) dfx0 = vis_fand(ddx0,DC0);

	sra	%i4,13,%g5		! (1_0) si1 = ax1 >> 13;

	sra	%i4,24,%i1		! (1_0) iexp1 = ax1 >> 24;
	and	%g5,2032,%o7		! (1_0) si1 &= 0x7f0;
	fpsub32s	%f19,%f0,%f31	! (0_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o7+TBL],%f44		! (1_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sub	%l0,%i1,%i0		! (1_0) iexp1 = 0x3f - iexp1;

	sll	%i0,23,%i0		! (1_0) lexp1 = iexp1 << 23;
	fitod	%f31,%f50		! (1_0) dtmp0 = (double)(((int*)dfx0)[0]);

	st	%i0,[%fp+tmp1+4]	! (0_0) fdx0 = *((double*)lexp0);

	add	%o7,TBL,%o7		! (1_0) addr0 = (char*)TBL + si0;
	fmuld	%f50,%f44,%f44		! (1_0) xx0 = dtmp0 * tbl_div0;

	ba	.cont5
	fmuld	K3,%f44,%f50		! (1_0) res1 = K3 * xx1;
1:
	sub	%o1,stridex,%o1
	stx	%o1,[%fp+tmp_px]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont5
	mov	3,counter

	.align	16
.update6:
	cmp	counter,4
	ble	.cont6
	sub	%l7,stridex,%o3

	sub	%o3,stridex,%o3
	stx	%o3,[%fp+tmp_px]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont6
	mov	4,counter

	.align	16
.update7:
	sethi	%hi(0x7ffffc00),%o3
	cmp	counter,4
	ble	.cont7

	add	%o3,0x3ff,%o3

	andcc	%g1,%o3,%g0
	bz,a	1f
	sub	%l7,stridex,%o3

	cmp	%g1,0
	bl,a	1f
	sub	%l7,stridex,%o3

	fitod	%f24,%f0
	fdtos	%f0,%f24
	fmuls	%f24,FTWO,%f24
	st	%f24,[%fp+tmp3]
	ld	[%fp+tmp3],%g1
	sethi	%hi(0x4b000000),%o3
	sub	%g1,%o3,%g1

	fands	%f24,DC0,%f0		! (2_0) dfx0 = vis_fand(ddx0,DC0);
	sra	%g1,13,%i0		! (2_0) si0 = ax0 >> 13;

	and	%i0,2032,%i0		! (2_0) si0 &= 0x7f0;

	ldd	[%i0+TBL],%f30		! (2_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	fpsub32s	%f24,%f0,%f12	! (2_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	sra	%g1,24,%i3		! (2_0) iexp0 = ax0 >> 24;

	sub	%l0,%i3,%g5		! (2_0) iexp0 = 0x3f - iexp0;

	sll	%g5,23,%g5		! (2_0) lexp0 = iexp0 << 55;
	add	%i0,TBL,%i0		! (2_0) addr0 = (char*)TBL + si0;
	fitod	%f12,%f56		! (2_0) dtmp0 = (double)(((int*)dfx0)[0]);

	st	%g5,[%fp+tmp2]		! (2_0) fdx0 = *((double*)lexp0);
	ba	.cont7
	fmuld	%f56,%f30,%f30		! (2_0) xx0 = dtmp0 * tbl_div0;
1:
	sub	%o3,stridex,%o3
	stx	%o3,[%fp+tmp_px]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont7
	mov	4,counter

	.align	16
.update8:
	cmp	counter,5
	ble	.cont8
	nop

	sub	%l7,stridex,%o3
	stx	%o3,[%fp+tmp_px]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont8
	mov	5,counter

	.align	16
.update9:
	sethi	%hi(0x7ffffc00),%o3
	cmp	counter,5
	ble	.cont9
	sub	%l7,stridex,%i3

	add	%o3,0x3ff,%o3

	andcc	%o5,%o3,%g0
	bz	1f
	ld	[%i3],%f0

	cmp	%o5,0
	bl,a	1f
	nop

	fitod	%f0,%f0
	fdtos	%f0,%f0
	fmuls	%f0,FTWO,%f0
	st	%f0,[%fp+tmp3]
	ld	[%fp+tmp3],%o5
	sethi	%hi(0x4b000000),%o3
	sub	%o5,%o3,%o5

	fands	%f0,DC0,%f8		! (2_0) dfx0 = vis_fand(ddx0,DC0);

	sra	%o5,13,%o1		! (3_0) si1 = ax1 >> 13;

	sra	%o5,24,%o3		! (3_0) iexp1 = ax1 >> 24;
	and	%o1,2032,%o1		! (3_0) si1 &= 0x7f0;
	fpsub32s	%f0,%f8,%f0	! (2_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o1+TBL],%f8		! (3_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sub	%l0,%o3,%i3		! (3_0) iexp1 = 0x3f - iexp1;

	sllx	%i3,23,%i3		! (3_0) lexp1 = iexp1 << 23;
	fitod	%f0,%f50		! (3_0) dtmp1 = (double)(((int*)dfx0)[1]);

	add	%o1,TBL,%o1		! (3_0) addr1 = (char*)TBL + si1;
	st	%i3,[%fp+tmp2+4]	! (2_0) fdx0 = *((double*)lexp0);

	fmuld	%f50,%f8,%f24		! (3_0) xx1 = dtmp1 * tbl_div1;

	ba	.cont9
	fmuld	K3,%f24,%f50		! (3_0) res1 = K3 * xx1;
1:
	stx	%i3,[%fp+tmp_px]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont9
	mov	5,counter

	.align	16
.update10:
	cmp	counter,0
	ble	.cont10
	sub	%i1,stridex,%o3

	sub	%o3,stridex,%o3
	stx	%o3,[%fp+tmp_px]

	st	counter,[%fp+tmp_counter]

	ba	.cont10
	mov	0,counter

	.align	16
.update11:
	sethi	%hi(0x7ffffc00),%i4
	cmp	counter,0
	ble	.cont11
	sub	%i1,stridex,%o3

	sub	%o3,stridex,%o3
	add	%i4,0x3ff,%i4
	ld	[%o3],%i3

	andcc	%i3,%i4,%g0
	bz	1f

	cmp	%i3,0
	bl,a	1f
	nop

	fitod	%f14,%f0
	fdtos	%f0,%f14
	fmuls	%f14,FTWO,%f14
	st	%f14,[%fp+tmp3]
	ld	[%fp+tmp3],%i3
	sethi	%hi(0x4b000000),%o3
	sub	%i3,%o3,%i3

	fands	%f14,DC0,%f16		! (4_0) dfx0 = vis_fand(ddx0,DC0);
	sra	%i3,13,%l5		! (4_0) si0 = ax0 >> 13;

	and	%l5,2032,%l5		! (4_0) si0 &= 0x7f0;

	ldd	[%l5+TBL],%f54		! (4_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	fpsub32s	%f14,%f16,%f16	! (4_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	sra	%i3,24,%i3		! (4_0) iexp0 = ax0 >> 24;

	sub	%l0,%i3,%o0		! (4_0) iexp0 = 0x3f - iexp0;
	fitod	%f16,%f56		! (4_0) dtmp0 = (double)(((int*)dfx0)[0]);

	sllx	%o0,23,%o0		! (4_0) lexp0 = iexp0 << 55;

	st	%o0,[%fp+tmp0]		! (4_0) fdx0 = *((double*)lexp0);

	ba	.cont11
	fmuld	%f56,%f54,%f40		! (4_0) xx0 = dtmp0 * tbl_div0;
1:
	stx	%o3,[%fp+tmp_px]

	st	counter,[%fp+tmp_counter]

	ba	.cont11
	mov	0,counter

	.align	16
.update12:
	cmp	counter,1
	ble	.cont12
	nop

	sub	%i1,stridex,%i1
	stx	%i1,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont12
	mov	1,counter

	.align	16
.update13:
	sethi	%hi(0x7ffffc00),%o3
	cmp	counter,1
	ble	.cont13

	add	%o3,0x3ff,%o3

	andcc	%g5,%o3,%g0
	bz	1f

	cmp	%g5,0
	bl,a	1f
	nop

	fitod	%f15,%f0
	fdtos	%f0,%f15
	fmuls	%f15,FTWO,%f15
	st	%f15,[%fp+tmp3]
	ld	[%fp+tmp3],%g5
	sethi	%hi(0x4b000000),%o3
	sub	%g5,%o3,%g5

	fands	%f15,DC0,%f17		! (4_0) dfx0 = vis_fand(ddx0,DC0);

	sra	%g5,13,%l6		! (5_0) si1 = ax1 >> 13;
	sra	%g5,24,%o3		! (5_0) iexp1 = ax1 >> 24;
	and	%l6,2032,%l6		! (5_0) si1 &= 0x7f0;
	fpsub32s	%f15,%f17,%f17	! (4_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%l6+TBL],%f46		! (5_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sub	%l0,%o3,%l1		! (5_0) iexp1 = 0x3f - iexp1;

	add	%l6,TBL,%l6		! (5_0) addr1 = (char*)TBL + si1;

	sllx	%l1,23,%l1		! (5_0) lexp1 = iexp1 << 23;
	st	%l1,[%fp+tmp0+4]	! (4_0) fdx0 = *((double*)lexp0);

	fitod	%f17,%f0		! (5_0) dtmp1 = (double)(((int*)dfx0)[1]);

	fmuld	%f0,%f46,%f46		! (5_1) xx1 = dtmp1 * tbl_div1;
	ba	.cont13
	fmuld	K3,%f46,%f50		! (5_1) res1 = K3 * xx1;
1:
	sub	%i1,stridex,%i1
	stx	%i1,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont13
	mov	1,counter

	.align	16
.update14:
	cmp	counter,2
	ble	.cont14
	sub	%o5,stridex,%o3

	sub	%o3,stridex,%o3
	stx	%o3,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont14
	mov	2,counter

	.align	16
.update15:
	sethi	%hi(0x7ffffc00),%i3
	cmp	counter,2
	ble	.cont15
	sub	%o5,stridex,%o3

	add	%i3,0x3ff,%i3

	andcc	%g1,%i3,%g0
	bz	1f
	sub	%o3,stridex,%o3

	cmp	%g1,0
	bl,a	1f
	nop

	fitod	%f18,%f0
	fdtos	%f0,%f18
	fmuls	%f18,FTWO,%f18
	st	%f18,[%fp+tmp3]
	ld	[%fp+tmp3],%g1
	sethi	%hi(0x4b000000),%o3
	sub	%g1,%o3,%g1

	fands	%f18,DC0,%f0		! (0_0) dfx0 = vis_fand(ddx0,DC0);
	sra	%g1,13,%o0		! (0_0) si0 = ax0 >> 13;
	and	%o0,2032,%o0		! (0_0) si0 &= 0x7f0;

	ldd	[%o0+TBL],%f54		! (0_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	fpsub32s	%f18,%f0,%f30	! (0_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	sra	%g1,24,%i3		! (0_0) iexp0 = ax0 >> 24;

	sub	%l0,%i3,%g5		! (0_0) iexp0 = 0x3f - iexp0;

	ba	.cont15
	fitod	%f30,%f56		! (0_0) dtmp0 = (double)(((int*)dfx0)[0]);
1:
	stx	%o3,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont15
	mov	2,counter

	.align	16
.update16:
	cmp	counter,3
	ble	.cont16
	sub	%l7,stridex2,%o3

	sub	%o3,stridex,%o3
	stx	%o3,[%fp+tmp_px]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont16
	mov	3,counter

	.align	16
.update17:
	sethi	%hi(0x7ffffc00),%i3
	cmp	counter,3
	ble	.cont17
	sub	%l7,stridex2,%o3

	add	%i3,0x3ff,%i3

	andcc	%i4,%i3,%g0
	bz	1f
	sub	%o3,stridex,%o3

	cmp	%i4,0
	bl,a	1f
	nop

	fitod	%f19,%f0
	fdtos	%f0,%f19
	fmuls	%f19,FTWO,%f19
	st	%f19,[%fp+tmp3]
	ld	[%fp+tmp3],%i4
	sethi	%hi(0x4b000000),%o3
	sub	%i4,%o3,%i4

	fands	%f19,DC0,%f0		! (0_0) dfx0 = vis_fand(ddx0,DC0);

	sra	%i4,13,%g5		! (1_0) si1 = ax1 >> 13;

	sra	%i4,24,%i0		! (1_0) iexp1 = ax1 >> 24;
	and	%g5,2032,%o7		! (1_0) si1 &= 0x7f0;
	fpsub32s	%f19,%f0,%f31	! (0_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o7+TBL],%f44		! (1_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sub	%l0,%i0,%i0		! (1_0) iexp1 = 0x3f - iexp1;

	sllx	%i0,23,%i0		! (1_0) lexp1 = iexp1 << 23;
	fitod	%f31,%f50		! (1_0) dtmp0 = (double)(((int*)dfx0)[0]);

	st	%i0,[%fp+tmp1+4]	! (0_0) fdx0 = *((double*)lexp0);

	add	%o7,TBL,%o7		! (1_0) addr0 = (char*)TBL + si0;
	fmuld	%f50,%f44,%f44		! (1_0) xx0 = dtmp0 * tbl_div0;

	ba	.cont17
	fmuld	K3,%f44,%f50		! (1_0) res1 = K3 * xx1;
1:
	stx	%o3,[%fp+tmp_px]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont17
	mov	3,counter

	.align	16
.update18:
	cmp	counter,4
	ble	.cont18
	fpadd32	%f20,%f52,%f0		! (2_1) dres0 = vis_fpadd32(dres0,fdx0);

	sub	%l7,stridex2,%i3
	stx	%i3,[%fp+tmp_px]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont18
	mov	4,counter

	.align	16
.update19:
	sethi	%hi(0x7ffffc00),%i3
	cmp	counter,4
	ble,a	.cont19
	fmuld	%f50,%f46,%f24		! (3_0) xx1 = dtmp1 * tbl_div1;

	add	%i3,0x3ff,%i3

	andcc	%g1,%i3,%g0
	bz	1f
	nop

	cmp	%g1,0
	bl,a	1f
	nop

	fitod	%f24,%f24
	fdtos	%f24,%f24
	fmuls	%f24,FTWO,%f24
	st	%f24,[%fp+tmp3]
	ld	[%fp+tmp3],%g1
	sethi	%hi(0x4b000000),%i3
	sub	%g1,%i3,%g1

	fands	%f24,DC0,%f8		! (2_0) dfx0 = vis_fand(ddx0,DC0);
	sra	%g1,13,%i0		! (2_0) si0 = ax0 >> 13;

	and	%i0,2032,%i0		! (2_0) si0 &= 0x7f0;

	ldd	[%i0+TBL],%f30		! (2_0) tbl_div0 = ((double*)((char*)TBL + si0))[0];
	fpsub32s	%f24,%f8,%f12	! (2_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	sra	%g1,24,%i3		! (2_0) iexp0 = ax0 >> 24;

	sub	%l0,%i3,%g5		! (2_0) iexp0 = 0x3f - iexp0;

	sllx	%g5,23,%g5		! (2_0) lexp0 = iexp0 << 55;
	add	%i0,TBL,%i0		! (2_0) addr0 = (char*)TBL + si0;
	fitod	%f12,%f56		! (2_0) dtmp0 = (double)(((int*)dfx0)[0]);

	st	%g5,[%fp+tmp2]		! (2_0) fdx0 = *((double*)lexp0);
	fmuld	%f56,%f30,%f30		! (2_0) xx0 = dtmp0 * tbl_div0;

	ba	.cont19
	fmuld	%f50,%f46,%f24		! (3_0) xx1 = dtmp1 * tbl_div1;
1:
	sub	%l7,stridex2,%i3
	stx	%i3,[%fp+tmp_px]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	mov	4,counter
	ba	.cont19
	fmuld	%f50,%f46,%f24		! (3_0) xx1 = dtmp1 * tbl_div1;

	.align	16
.update20:
	cmp	counter,5
	ble	.cont20
	nop

	sub	%l7,stridex,%i3
	stx	%i3,[%fp+tmp_px]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont20
	mov	5,counter

	.align	16
.update21:
	sethi	%hi(0x7ffffc00),%i3
	cmp	counter,5
	ble,a	.cont21
	nop

	sub	%l7,stridex,%i4
	add	%i3,0x3ff,%i3

	andcc	%o5,%i3,%g0
	bz	1f
	ld	[%i4],%f8

	cmp	%o5,0
	bl,a	1f
	nop

	fitod	%f8,%f8
	fdtos	%f8,%f8
	fmuls	%f8,FTWO,%f8
	st	%f8,[%fp+tmp3]
	ld	[%fp+tmp3],%o5
	sethi	%hi(0x4b000000),%i3
	sub	%o5,%i3,%o5

	fands	%f8,DC0,%f24		! (2_0) dfx0 = vis_fand(ddx0,DC0);

	sra	%o5,13,%o1		! (3_0) si1 = ax1 >> 13;

	sra	%o5,24,%i3		! (3_0) iexp1 = ax1 >> 24;
	and	%o1,2032,%o1		! (3_0) si1 &= 0x7f0;
	fpsub32s	%f8,%f24,%f24	! (2_0) dfx0 = vis_fpsub32(ddx0,dfx0);

	ldd	[%o1+TBL],%f8		! (3_0) tbl_div1 = ((double*)((char*)TBL + si1))[0];
	sub	%l0,%i3,%i3		! (3_0) iexp1 = 0x3f - iexp1;

	sllx	%i3,23,%i3		! (3_0) lexp1 = iexp1 << 23;
	fitod	%f24,%f50		! (3_0) dtmp1 = (double)(((int*)dfx0)[1]);

	add	%o1,TBL,%o1		! (3_0) addr1 = (char*)TBL + si1;
	st	%i3,[%fp+tmp2+4]	! (2_0) fdx0 = *((double*)lexp0);

	fmuld	%f50,%f8,%f24		! (3_0) xx1 = dtmp1 * tbl_div1;

	ba	.cont21
	fmuld	K3,%f24,%f50		! (3_0) res1 = K3 * xx1;
1:
	sub	%l7,stridex,%i3
	stx	%i3,[%fp+tmp_px]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont21
	mov	5,counter

	.align	16
.exit:
	ret
	restore

	SET_SIZE(__vrsqrtf)

