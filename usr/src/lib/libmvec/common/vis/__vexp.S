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

	.file	"__vexp.S"

#include "libm.h"

	RO_DATA

/********************************************************************
 * vexp() algorithm is from mopt:f_exp.c.  Basics are included here
 * to supplement comments within this file.  vexp() has been unrolled
 * to a depth of 3.  Only element 0 is documented.
 *
 * Note 1: INVLN2_256, LN2_256H, and LN2_256L were originally scaled by
 *	2^44 to allow *2^k w/o shifting within the FP registers.  These
 *	had to be removed for CHEETAH to avoid the fdtox of a very large
 *	number, which would trap to kernel (2^52).
 *
 * Let 	x = (k + j/256)ln2 + r
 * then	exp(x) = exp(ln2^(k+j/256)) * exp(r)
 *	       = 2^k * 2^(j/256) * exp(r)
 * where r is polynomial approximation
 *	exp(r) = 1 + r + r^2*B1 + r^3*B2 + r^4*B3
 *	       = 1 + r*(1+r*(B1+r*(B2+r*B3)))
 *	let
 *	p = r*(1+r*(B1+r*(B2+r*B3)))	! notice, not quite exp(r)
 *	q = 2^(j/256) (high 64 bits)
 *	t = 2^(j/256) (extra precision)	! both from _TBL_exp_z[]
 *	then
 *	2^(j/256) * exp(r) = (q+t)(1+p) ~ q + ( t + q*p )
 *	then actual computation is 2^k * ( q + ( t + q*p ) )
 * 
 ********************************************************************/

	.align	16
TBL:
	.word	0x3ff00000,0x00000000
	.word	0x00000000,0x00000000
	.word	0x3ff00b1a,0xfa5abcbf
	.word	0xbc84f6b2,0xa7609f71
	.word	0x3ff0163d,0xa9fb3335
	.word	0x3c9b6129,0x9ab8cdb7
	.word	0x3ff02168,0x143b0281
	.word	0xbc82bf31,0x0fc54eb6
	.word	0x3ff02c9a,0x3e778061
	.word	0xbc719083,0x535b085d
	.word	0x3ff037d4,0x2e11bbcc
	.word	0x3c656811,0xeeade11a
	.word	0x3ff04315,0xe86e7f85
	.word	0xbc90a31c,0x1977c96e
	.word	0x3ff04e5f,0x72f654b1
	.word	0x3c84c379,0x3aa0d08c
	.word	0x3ff059b0,0xd3158574
	.word	0x3c8d73e2,0xa475b465
	.word	0x3ff0650a,0x0e3c1f89
	.word	0xbc95cb7b,0x5799c396
	.word	0x3ff0706b,0x29ddf6de
	.word	0xbc8c91df,0xe2b13c26
	.word	0x3ff07bd4,0x2b72a836
	.word	0x3c832334,0x54458700
	.word	0x3ff08745,0x18759bc8
	.word	0x3c6186be,0x4bb284ff
	.word	0x3ff092bd,0xf66607e0
	.word	0xbc968063,0x800a3fd1
	.word	0x3ff09e3e,0xcac6f383
	.word	0x3c914878,0x18316136
	.word	0x3ff0a9c7,0x9b1f3919
	.word	0x3c85d16c,0x873d1d38
	.word	0x3ff0b558,0x6cf9890f
	.word	0x3c98a62e,0x4adc610a
	.word	0x3ff0c0f1,0x45e46c85
	.word	0x3c94f989,0x06d21cef
	.word	0x3ff0cc92,0x2b7247f7
	.word	0x3c901edc,0x16e24f71
	.word	0x3ff0d83b,0x23395dec
	.word	0xbc9bc14d,0xe43f316a
	.word	0x3ff0e3ec,0x32d3d1a2
	.word	0x3c403a17,0x27c57b53
	.word	0x3ff0efa5,0x5fdfa9c5
	.word	0xbc949db9,0xbc54021b
	.word	0x3ff0fb66,0xaffed31b
	.word	0xbc6b9bed,0xc44ebd7b
	.word	0x3ff10730,0x28d7233e
	.word	0x3c8d46eb,0x1692fdd5
	.word	0x3ff11301,0xd0125b51
	.word	0xbc96c510,0x39449b3a
	.word	0x3ff11edb,0xab5e2ab6
	.word	0xbc9ca454,0xf703fb72
	.word	0x3ff12abd,0xc06c31cc
	.word	0xbc51b514,0xb36ca5c7
	.word	0x3ff136a8,0x14f204ab
	.word	0xbc67108f,0xba48dcf0
	.word	0x3ff1429a,0xaea92de0
	.word	0xbc932fbf,0x9af1369e
	.word	0x3ff14e95,0x934f312e
	.word	0xbc8b91e8,0x39bf44ab
	.word	0x3ff15a98,0xc8a58e51
	.word	0x3c82406a,0xb9eeab0a
	.word	0x3ff166a4,0x5471c3c2
	.word	0x3c58f23b,0x82ea1a32
	.word	0x3ff172b8,0x3c7d517b
	.word	0xbc819041,0xb9d78a76
	.word	0x3ff17ed4,0x8695bbc0
	.word	0x3c709e3f,0xe2ac5a64
	.word	0x3ff18af9,0x388c8dea
	.word	0xbc911023,0xd1970f6c
	.word	0x3ff19726,0x58375d2f
	.word	0x3c94aadd,0x85f17e08
	.word	0x3ff1a35b,0xeb6fcb75
	.word	0x3c8e5b4c,0x7b4968e4
	.word	0x3ff1af99,0xf8138a1c
	.word	0x3c97bf85,0xa4b69280
	.word	0x3ff1bbe0,0x84045cd4
	.word	0xbc995386,0x352ef607
	.word	0x3ff1c82f,0x95281c6b
	.word	0x3c900977,0x8010f8c9
	.word	0x3ff1d487,0x3168b9aa
	.word	0x3c9e016e,0x00a2643c
	.word	0x3ff1e0e7,0x5eb44027
	.word	0xbc96fdd8,0x088cb6de
	.word	0x3ff1ed50,0x22fcd91d
	.word	0xbc91df98,0x027bb78c
	.word	0x3ff1f9c1,0x8438ce4d
	.word	0xbc9bf524,0xa097af5c
	.word	0x3ff2063b,0x88628cd6
	.word	0x3c8dc775,0x814a8494
	.word	0x3ff212be,0x3578a819
	.word	0x3c93592d,0x2cfcaac9
	.word	0x3ff21f49,0x917ddc96
	.word	0x3c82a97e,0x9494a5ee
	.word	0x3ff22bdd,0xa27912d1
	.word	0x3c8d34fb,0x5577d69e
	.word	0x3ff2387a,0x6e756238
	.word	0x3c99b07e,0xb6c70573
	.word	0x3ff2451f,0xfb82140a
	.word	0x3c8acfcc,0x911ca996
	.word	0x3ff251ce,0x4fb2a63f
	.word	0x3c8ac155,0xbef4f4a4
	.word	0x3ff25e85,0x711ece75
	.word	0x3c93e1a2,0x4ac31b2c
	.word	0x3ff26b45,0x65e27cdd
	.word	0x3c82bd33,0x9940e9d9
	.word	0x3ff2780e,0x341ddf29
	.word	0x3c9e067c,0x05f9e76c
	.word	0x3ff284df,0xe1f56381
	.word	0xbc9a4c3a,0x8c3f0d7e
	.word	0x3ff291ba,0x7591bb70
	.word	0xbc82cc72,0x28401cbc
	.word	0x3ff29e9d,0xf51fdee1
	.word	0x3c8612e8,0xafad1255
	.word	0x3ff2ab8a,0x66d10f13
	.word	0xbc995743,0x191690a7
	.word	0x3ff2b87f,0xd0dad990
	.word	0xbc410adc,0xd6381aa4
	.word	0x3ff2c57e,0x39771b2f
	.word	0xbc950145,0xa6eb5124
	.word	0x3ff2d285,0xa6e4030b
	.word	0x3c900247,0x54db41d5
	.word	0x3ff2df96,0x1f641589
	.word	0x3c9d16cf,0xfbbce198
	.word	0x3ff2ecaf,0xa93e2f56
	.word	0x3c71ca0f,0x45d52383
	.word	0x3ff2f9d2,0x4abd886b
	.word	0xbc653c55,0x532bda93
	.word	0x3ff306fe,0x0a31b715
	.word	0x3c86f46a,0xd23182e4
	.word	0x3ff31432,0xedeeb2fd
	.word	0x3c8959a3,0xf3f3fcd0
	.word	0x3ff32170,0xfc4cd831
	.word	0x3c8a9ce7,0x8e18047c
	.word	0x3ff32eb8,0x3ba8ea32
	.word	0xbc9c45e8,0x3cb4f318
	.word	0x3ff33c08,0xb26416ff
	.word	0x3c932721,0x843659a6
	.word	0x3ff34962,0x66e3fa2d
	.word	0xbc835a75,0x930881a4
	.word	0x3ff356c5,0x5f929ff1
	.word	0xbc8b5cee,0x5c4e4628
	.word	0x3ff36431,0xa2de883b
	.word	0xbc8c3144,0xa06cb85e
	.word	0x3ff371a7,0x373aa9cb
	.word	0xbc963aea,0xbf42eae2
	.word	0x3ff37f26,0x231e754a
	.word	0xbc99f5ca,0x9eceb23c
	.word	0x3ff38cae,0x6d05d866
	.word	0xbc9e958d,0x3c9904bd
	.word	0x3ff39a40,0x1b7140ef
	.word	0xbc99a9a5,0xfc8e2934
	.word	0x3ff3a7db,0x34e59ff7
	.word	0xbc75e436,0xd661f5e3
	.word	0x3ff3b57f,0xbfec6cf4
	.word	0x3c954c66,0xe26fff18
	.word	0x3ff3c32d,0xc313a8e5
	.word	0xbc9efff8,0x375d29c3
	.word	0x3ff3d0e5,0x44ede173
	.word	0x3c7fe8d0,0x8c284c71
	.word	0x3ff3dea6,0x4c123422
	.word	0x3c8ada09,0x11f09ebc
	.word	0x3ff3ec70,0xdf1c5175
	.word	0xbc8af663,0x7b8c9bca
	.word	0x3ff3fa45,0x04ac801c
	.word	0xbc97d023,0xf956f9f3
	.word	0x3ff40822,0xc367a024
	.word	0x3c8bddf8,0xb6f4d048
	.word	0x3ff4160a,0x21f72e2a
	.word	0xbc5ef369,0x1c309278
	.word	0x3ff423fb,0x2709468a
	.word	0xbc98462d,0xc0b314dd
	.word	0x3ff431f5,0xd950a897
	.word	0xbc81c7dd,0xe35f7998
	.word	0x3ff43ffa,0x3f84b9d4
	.word	0x3c8880be,0x9704c002
	.word	0x3ff44e08,0x6061892d
	.word	0x3c489b7a,0x04ef80d0
	.word	0x3ff45c20,0x42a7d232
	.word	0xbc686419,0x82fb1f8e
	.word	0x3ff46a41,0xed1d0057
	.word	0x3c9c944b,0xd1648a76
	.word	0x3ff4786d,0x668b3237
	.word	0xbc9c20f0,0xed445733
	.word	0x3ff486a2,0xb5c13cd0
	.word	0x3c73c1a3,0xb69062f0
	.word	0x3ff494e1,0xe192aed2
	.word	0xbc83b289,0x5e499ea0
	.word	0x3ff4a32a,0xf0d7d3de
	.word	0x3c99cb62,0xf3d1be56
	.word	0x3ff4b17d,0xea6db7d7
	.word	0xbc8125b8,0x7f2897f0
	.word	0x3ff4bfda,0xd5362a27
	.word	0x3c7d4397,0xafec42e2
	.word	0x3ff4ce41,0xb817c114
	.word	0x3c905e29,0x690abd5d
	.word	0x3ff4dcb2,0x99fddd0d
	.word	0x3c98ecdb,0xbc6a7833
	.word	0x3ff4eb2d,0x81d8abff
	.word	0xbc95257d,0x2e5d7a52
	.word	0x3ff4f9b2,0x769d2ca7
	.word	0xbc94b309,0xd25957e3
	.word	0x3ff50841,0x7f4531ee
	.word	0x3c7a249b,0x49b7465f
	.word	0x3ff516da,0xa2cf6642
	.word	0xbc8f7685,0x69bd93ee
	.word	0x3ff5257d,0xe83f4eef
	.word	0xbc7c998d,0x43efef71
	.word	0x3ff5342b,0x569d4f82
	.word	0xbc807abe,0x1db13cac
	.word	0x3ff542e2,0xf4f6ad27
	.word	0x3c87926d,0x192d5f7e
	.word	0x3ff551a4,0xca5d920f
	.word	0xbc8d689c,0xefede59a
	.word	0x3ff56070,0xdde910d2
	.word	0xbc90fb6e,0x168eebf0
	.word	0x3ff56f47,0x36b527da
	.word	0x3c99bb2c,0x011d93ad
	.word	0x3ff57e27,0xdbe2c4cf
	.word	0xbc90b98c,0x8a57b9c4
	.word	0x3ff58d12,0xd497c7fd
	.word	0x3c8295e1,0x5b9a1de8
	.word	0x3ff59c08,0x27ff07cc
	.word	0xbc97e2ce,0xe467e60f
	.word	0x3ff5ab07,0xdd485429
	.word	0x3c96324c,0x054647ad
	.word	0x3ff5ba11,0xfba87a03
	.word	0xbc9b77a1,0x4c233e1a
	.word	0x3ff5c926,0x8a5946b7
	.word	0x3c3c4b1b,0x816986a2
	.word	0x3ff5d845,0x90998b93
	.word	0xbc9cd6a7,0xa8b45642
	.word	0x3ff5e76f,0x15ad2148
	.word	0x3c9ba6f9,0x3080e65e
	.word	0x3ff5f6a3,0x20dceb71
	.word	0xbc89eadd,0xe3cdcf92
	.word	0x3ff605e1,0xb976dc09
	.word	0xbc93e242,0x9b56de47
	.word	0x3ff6152a,0xe6cdf6f4
	.word	0x3c9e4b3e,0x4ab84c27
	.word	0x3ff6247e,0xb03a5585
	.word	0xbc9383c1,0x7e40b497
	.word	0x3ff633dd,0x1d1929fd
	.word	0x3c984710,0xbeb964e5
	.word	0x3ff64346,0x34ccc320
	.word	0xbc8c483c,0x759d8932
	.word	0x3ff652b9,0xfebc8fb7
	.word	0xbc9ae3d5,0xc9a73e08
	.word	0x3ff66238,0x82552225
	.word	0xbc9bb609,0x87591c34
	.word	0x3ff671c1,0xc70833f6
	.word	0xbc8e8732,0x586c6134
	.word	0x3ff68155,0xd44ca973
	.word	0x3c6038ae,0x44f73e65
	.word	0x3ff690f4,0xb19e9538
	.word	0x3c8804bd,0x9aeb445c
	.word	0x3ff6a09e,0x667f3bcd
	.word	0xbc9bdd34,0x13b26456
	.word	0x3ff6b052,0xfa75173e
	.word	0x3c7a38f5,0x2c9a9d0e
	.word	0x3ff6c012,0x750bdabf
	.word	0xbc728956,0x67ff0b0d
	.word	0x3ff6cfdc,0xddd47645
	.word	0x3c9c7aa9,0xb6f17309
	.word	0x3ff6dfb2,0x3c651a2f
	.word	0xbc6bbe3a,0x683c88ab
	.word	0x3ff6ef92,0x98593ae5
	.word	0xbc90b974,0x9e1ac8b2
	.word	0x3ff6ff7d,0xf9519484
	.word	0xbc883c0f,0x25860ef6
	.word	0x3ff70f74,0x66f42e87
	.word	0x3c59d644,0xd45aa65f
	.word	0x3ff71f75,0xe8ec5f74
	.word	0xbc816e47,0x86887a99
	.word	0x3ff72f82,0x86ead08a
	.word	0xbc920aa0,0x2cd62c72
	.word	0x3ff73f9a,0x48a58174
	.word	0xbc90a8d9,0x6c65d53c
	.word	0x3ff74fbd,0x35d7cbfd
	.word	0x3c9047fd,0x618a6e1c
	.word	0x3ff75feb,0x564267c9
	.word	0xbc902459,0x57316dd3
	.word	0x3ff77024,0xb1ab6e09
	.word	0x3c9b7877,0x169147f8
	.word	0x3ff78069,0x4fde5d3f
	.word	0x3c9866b8,0x0a02162c
	.word	0x3ff790b9,0x38ac1cf6
	.word	0x3c9349a8,0x62aadd3e
	.word	0x3ff7a114,0x73eb0187
	.word	0xbc841577,0xee04992f
	.word	0x3ff7b17b,0x0976cfdb
	.word	0xbc9bebb5,0x8468dc88
	.word	0x3ff7c1ed,0x0130c132
	.word	0x3c9f124c,0xd1164dd6
	.word	0x3ff7d26a,0x62ff86f0
	.word	0x3c91bddb,0xfb72b8b4
	.word	0x3ff7e2f3,0x36cf4e62
	.word	0x3c705d02,0xba15797e
	.word	0x3ff7f387,0x8491c491
	.word	0xbc807f11,0xcf9311ae
	.word	0x3ff80427,0x543e1a12
	.word	0xbc927c86,0x626d972b
	.word	0x3ff814d2,0xadd106d9
	.word	0x3c946437,0x0d151d4d
	.word	0x3ff82589,0x994cce13
	.word	0xbc9d4c1d,0xd41532d8
	.word	0x3ff8364c,0x1eb941f7
	.word	0x3c999b9a,0x31df2bd5
	.word	0x3ff8471a,0x4623c7ad
	.word	0xbc88d684,0xa341cdfb
	.word	0x3ff857f4,0x179f5b21
	.word	0xbc5ba748,0xf8b216d0
	.word	0x3ff868d9,0x9b4492ec
	.word	0x3ca01c83,0xb21584a3
	.word	0x3ff879ca,0xd931a436
	.word	0x3c85d2d7,0xd2db47bc
	.word	0x3ff88ac7,0xd98a6699
	.word	0x3c9994c2,0xf37cb53a
	.word	0x3ff89bd0,0xa478580f
	.word	0x3c9d5395,0x4475202a
	.word	0x3ff8ace5,0x422aa0db
	.word	0x3c96e9f1,0x56864b27
	.word	0x3ff8be05,0xbad61778
	.word	0x3c9ecb5e,0xfc43446e
	.word	0x3ff8cf32,0x16b5448c
	.word	0xbc70d55e,0x32e9e3aa
	.word	0x3ff8e06a,0x5e0866d9
	.word	0xbc97114a,0x6fc9b2e6
	.word	0x3ff8f1ae,0x99157736
	.word	0x3c85cc13,0xa2e3976c
	.word	0x3ff902fe,0xd0282c8a
	.word	0x3c9592ca,0x85fe3fd2
	.word	0x3ff9145b,0x0b91ffc6
	.word	0xbc9dd679,0x2e582524
	.word	0x3ff925c3,0x53aa2fe2
	.word	0xbc83455f,0xa639db7f
	.word	0x3ff93737,0xb0cdc5e5
	.word	0xbc675fc7,0x81b57ebc
	.word	0x3ff948b8,0x2b5f98e5
	.word	0xbc8dc3d6,0x797d2d99
	.word	0x3ff95a44,0xcbc8520f
	.word	0xbc764b7c,0x96a5f039
	.word	0x3ff96bdd,0x9a7670b3
	.word	0xbc5ba596,0x7f19c896
	.word	0x3ff97d82,0x9fde4e50
	.word	0xbc9d185b,0x7c1b85d0
	.word	0x3ff98f33,0xe47a22a2
	.word	0x3c7cabda,0xa24c78ed
	.word	0x3ff9a0f1,0x70ca07ba
	.word	0xbc9173bd,0x91cee632
	.word	0x3ff9b2bb,0x4d53fe0d
	.word	0xbc9dd84e,0x4df6d518
	.word	0x3ff9c491,0x82a3f090
	.word	0x3c7c7c46,0xb071f2be
	.word	0x3ff9d674,0x194bb8d5
	.word	0xbc9516be,0xa3dd8233
	.word	0x3ff9e863,0x19e32323
	.word	0x3c7824ca,0x78e64c6e
	.word	0x3ff9fa5e,0x8d07f29e
	.word	0xbc84a9ce,0xaaf1face
	.word	0x3ffa0c66,0x7b5de565
	.word	0xbc935949,0x5d1cd533
	.word	0x3ffa1e7a,0xed8eb8bb
	.word	0x3c9c6618,0xee8be70e
	.word	0x3ffa309b,0xec4a2d33
	.word	0x3c96305c,0x7ddc36ab
	.word	0x3ffa42c9,0x80460ad8
	.word	0xbc9aa780,0x589fb120
	.word	0x3ffa5503,0xb23e255d
	.word	0xbc9d2f6e,0xdb8d41e1
	.word	0x3ffa674a,0x8af46052
	.word	0x3c650f56,0x30670366
	.word	0x3ffa799e,0x1330b358
	.word	0x3c9bcb7e,0xcac563c6
	.word	0x3ffa8bfe,0x53c12e59
	.word	0xbc94f867,0xb2ba15a8
	.word	0x3ffa9e6b,0x5579fdbf
	.word	0x3c90fac9,0x0ef7fd31
	.word	0x3ffab0e5,0x21356eba
	.word	0x3c889c31,0xdae94544
	.word	0x3ffac36b,0xbfd3f37a
	.word	0xbc8f9234,0xcae76cd0
	.word	0x3ffad5ff,0x3a3c2774
	.word	0x3c97ef3b,0xb6b1b8e4
	.word	0x3ffae89f,0x995ad3ad
	.word	0x3c97a1cd,0x345dcc81
	.word	0x3ffafb4c,0xe622f2ff
	.word	0xbc94b2fc,0x0f315ecc
	.word	0x3ffb0e07,0x298db666
	.word	0xbc9bdef5,0x4c80e425
	.word	0x3ffb20ce,0x6c9a8952
	.word	0x3c94dd02,0x4a0756cc
	.word	0x3ffb33a2,0xb84f15fb
	.word	0xbc62805e,0x3084d708
	.word	0x3ffb4684,0x15b749b1
	.word	0xbc7f763d,0xe9df7c90
	.word	0x3ffb5972,0x8de5593a
	.word	0xbc9c71df,0xbbba6de3
	.word	0x3ffb6c6e,0x29f1c52a
	.word	0x3c92a8f3,0x52883f6e
	.word	0x3ffb7f76,0xf2fb5e47
	.word	0xbc75584f,0x7e54ac3b
	.word	0x3ffb928c,0xf22749e4
	.word	0xbc9b7216,0x54cb65c6
	.word	0x3ffba5b0,0x30a1064a
	.word	0xbc9efcd3,0x0e54292e
	.word	0x3ffbb8e0,0xb79a6f1f
	.word	0xbc3f52d1,0xc9696205
	.word	0x3ffbcc1e,0x904bc1d2
	.word	0x3c823dd0,0x7a2d9e84
	.word	0x3ffbdf69,0xc3f3a207
	.word	0xbc3c2623,0x60ea5b52
	.word	0x3ffbf2c2,0x5bd71e09
	.word	0xbc9efdca,0x3f6b9c73
	.word	0x3ffc0628,0x6141b33d
	.word	0xbc8d8a5a,0xa1fbca34
	.word	0x3ffc199b,0xdd85529c
	.word	0x3c811065,0x895048dd
	.word	0x3ffc2d1c,0xd9fa652c
	.word	0xbc96e516,0x17c8a5d7
	.word	0x3ffc40ab,0x5fffd07a
	.word	0x3c9b4537,0xe083c60a
	.word	0x3ffc5447,0x78fafb22
	.word	0x3c912f07,0x2493b5af
	.word	0x3ffc67f1,0x2e57d14b
	.word	0x3c92884d,0xff483cad
	.word	0x3ffc7ba8,0x8988c933
	.word	0xbc8e76bb,0xbe255559
	.word	0x3ffc8f6d,0x9406e7b5
	.word	0x3c71acbc,0x48805c44
	.word	0x3ffca340,0x5751c4db
	.word	0xbc87f2be,0xd10d08f4
	.word	0x3ffcb720,0xdcef9069
	.word	0x3c7503cb,0xd1e949db
	.word	0x3ffccb0f,0x2e6d1675
	.word	0xbc7d220f,0x86009093
	.word	0x3ffcdf0b,0x555dc3fa
	.word	0xbc8dd83b,0x53829d72
	.word	0x3ffcf315,0x5b5bab74
	.word	0xbc9a08e9,0xb86dff57
	.word	0x3ffd072d,0x4a07897c
	.word	0xbc9cbc37,0x43797a9c
	.word	0x3ffd1b53,0x2b08c968
	.word	0x3c955636,0x219a36ee
	.word	0x3ffd2f87,0x080d89f2
	.word	0xbc9d487b,0x719d8578
	.word	0x3ffd43c8,0xeacaa1d6
	.word	0x3c93db53,0xbf5a1614
	.word	0x3ffd5818,0xdcfba487
	.word	0x3c82ed02,0xd75b3706
	.word	0x3ffd6c76,0xe862e6d3
	.word	0x3c5fe87a,0x4a8165a0
	.word	0x3ffd80e3,0x16c98398
	.word	0xbc911ec1,0x8beddfe8
	.word	0x3ffd955d,0x71ff6075
	.word	0x3c9a052d,0xbb9af6be
	.word	0x3ffda9e6,0x03db3285
	.word	0x3c9c2300,0x696db532
	.word	0x3ffdbe7c,0xd63a8315
	.word	0xbc9b76f1,0x926b8be4
	.word	0x3ffdd321,0xf301b460
	.word	0x3c92da57,0x78f018c2
	.word	0x3ffde7d5,0x641c0658
	.word	0xbc9ca552,0x8e79ba8f
	.word	0x3ffdfc97,0x337b9b5f
	.word	0xbc91a5cd,0x4f184b5c
	.word	0x3ffe1167,0x6b197d17
	.word	0xbc72b529,0xbd5c7f44
	.word	0x3ffe2646,0x14f5a129
	.word	0xbc97b627,0x817a1496
	.word	0x3ffe3b33,0x3b16ee12
	.word	0xbc99f4a4,0x31fdc68a
	.word	0x3ffe502e,0xe78b3ff6
	.word	0x3c839e89,0x80a9cc8f
	.word	0x3ffe6539,0x24676d76
	.word	0xbc863ff8,0x7522b734
	.word	0x3ffe7a51,0xfbc74c83
	.word	0x3c92d522,0xca0c8de2
	.word	0x3ffe8f79,0x77cdb740
	.word	0xbc910894,0x80b054b1
	.word	0x3ffea4af,0xa2a490da
	.word	0xbc9e9c23,0x179c2893
	.word	0x3ffeb9f4,0x867cca6e
	.word	0x3c94832f,0x2293e4f2
	.word	0x3ffecf48,0x2d8e67f1
	.word	0xbc9c93f3,0xb411ad8c
	.word	0x3ffee4aa,0xa2188510
	.word	0x3c91c68d,0xa487568d
	.word	0x3ffefa1b,0xee615a27
	.word	0x3c9dc7f4,0x86a4b6b0
	.word	0x3fff0f9c,0x1cb6412a
	.word	0xbc932200,0x65181d45
	.word	0x3fff252b,0x376bba97
	.word	0x3c93a1a5,0xbf0d8e43
	.word	0x3fff3ac9,0x48dd7274
	.word	0xbc795a5a,0x3ed837de
	.word	0x3fff5076,0x5b6e4540
	.word	0x3c99d3e1,0x2dd8a18b
	.word	0x3fff6632,0x798844f8
	.word	0x3c9fa37b,0x3539343e
	.word	0x3fff7bfd,0xad9cbe14
	.word	0xbc9dbb12,0xd006350a
	.word	0x3fff91d8,0x02243c89
	.word	0xbc612ea8,0xa779f689
	.word	0x3fffa7c1,0x819e90d8
	.word	0x3c874853,0xf3a5931e
	.word	0x3fffbdba,0x3692d514
	.word	0xbc796773,0x15098eb6
	.word	0x3fffd3c2,0x2b8f71f1
	.word	0x3c62eb74,0x966579e7
	.word	0x3fffe9d9,0x6b2a23d9
	.word	0x3c74a603,0x7442fde3

	.align	16
constants:
	.word	0x3ef00000,0x00000000
	.word	0x40862e42,0xfefa39ef
	.word	0x01000000,0x00000000
	.word	0x7f000000,0x00000000
	.word	0x80000000,0x00000000
	.word	0x43f00000,0x00000000 ! scaling 2^12 two96
	.word	0xfff00000,0x00000000
	.word	0x3ff00000,0x00000000
	.word	0x3fdfffff,0xfffffff6
	.word	0x3fc55555,0x721a1d14
	.word	0x3fa55555,0x6e0896af
	.word	0x41371547,0x652b82fe ! scaling 2^12 invln2_256
	.word	0x3ea62e42,0xfee00000 ! scaling 2^(-12) ln2_256h
	.word	0x3caa39ef,0x35793c76 ! scaling 2^(-12) ln2_256l

	! base set w/o scaling
	! .word	0x43300000,0x00000000 ! scaling  two96
	! .word	0x40771547,0x652b82fe ! scaling  invln2_256
	! .word	0x3f662e42,0xfee00000 ! scaling  ln2_256h
	! .word	0x3d6a39ef,0x35793c76 ! scaling  ln2_256l

#define ox3ef		0x0
#define thresh		0x8
#define tiny		0x10
#define huge		0x18
#define signbit		0x20
#define two96		0x28
#define neginf		0x30
#define one		0x38
#define B1OFF		0x40
#define B2OFF		0x48
#define B3OFF		0x50
#define invln2_256	0x58
#define ln2_256h	0x60
#define ln2_256l	0x68

! local storage indices

#define m2		STACK_BIAS-0x4
#define m1		STACK_BIAS-0x8
#define m0		STACK_BIAS-0xc
#define jnk		STACK_BIAS-0x20
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x20

! register use

! i0  n
! i1  x
! i2  stridex
! i3  y
! i4  stridey
! i5  0x80000000

! g1  TBL

! l0  m0
! l1  m1
! l2  m2
! l3  j0,oy0
! l4  j1,oy1
! l5  j2,oy2
! l6  0x3e300000
! l7  0x40862e41

! o0  py0
! o1  py1
! o2  py2
! o3  scratch
! o4  scratch
! o5  0x40874910
! o7  0x7ff00000

! f0  x0
! f2  
! f4  
! f6  
! f8  
! f10 x1
! f12 
! f14 
! f16 
! f18 
! f20 x2
! f22 
! f24 
! f26 
! f28 
! f30 
! f32 
! f34 
! f36 0x3ef0...
! f38 thresh
! f40 tiny
! f42 huge
! f44 signbit
! f46 two96
! f48 neginf
! f50 one
! f52 B1
! f54 B2
! f56 B3
! f58 invln2_256
! f60 ln2_256h
! f62 ln2_256l
#define BOUNDRY %f36
#define THRESH %f38
#define TINY %f40
#define HUGE %f42
#define SIGNBIT %f44
#define TWO96 %f46
#define NEGINF %f48
#define ONE %f50
#define B1 %f52
#define B2 %f54
#define B3 %f56
#define INVLN2_256 %f58
#define LN2_256H %f60
#define LN2_256L %f62

	ENTRY(__vexp)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,constants,o3)
	PIC_SET(l7,TBL,o0)
	mov	%o0,%g1
	wr	%g0,0x82,%asi		! set %asi for non-faulting loads

	sethi	%hi(0x80000000),%i5
	sethi	%hi(0x3e300000),%l6
	sethi	%hi(0x40862e41),%l7
	or	%l7,%lo(0x40862e41),%l7
	sethi	%hi(0x40874910),%o5
	or	%o5,%lo(0x40874910),%o5
	sethi	%hi(0x7ff00000),%o7
	ldd	[%o3+ox3ef],BOUNDRY
	ldd	[%o3+thresh],THRESH
	ldd	[%o3+tiny],TINY
	ldd	[%o3+huge],HUGE
	ldd	[%o3+signbit],SIGNBIT
	ldd	[%o3+two96],TWO96
	ldd	[%o3+neginf],NEGINF
	ldd	[%o3+one],ONE
	ldd	[%o3+B1OFF],B1
	ldd	[%o3+B2OFF],B2
	ldd	[%o3+B3OFF],B3
	ldd	[%o3+invln2_256],INVLN2_256
	ldd	[%o3+ln2_256h],LN2_256H
	ldd	[%o3+ln2_256l],LN2_256L
	sll	%i2,3,%i2		! scale strides
	sll	%i4,3,%i4
	add	%fp,jnk,%l3		! precondition loop
	add	%fp,jnk,%l4
	add	%fp,jnk,%l5
	ld	[%i1],%l0		! hx = *x
	ld	[%i1],%f0
	ld	[%i1+4],%f1
	andn	%l0,%i5,%l0		! hx &= ~0x80000000
	ba	.loop0
	add	%i1,%i2,%i1		! x += stridex

	.align	16
! -- 16 byte aligned
.loop0:
	lda	[%i1]%asi,%l1		! preload next argument
	sub	%l0,%l6,%o3
	sub	%l7,%l0,%o4
	fand	%f0,SIGNBIT,%f2		! get sign bit

	lda	[%i1]%asi,%f10
	orcc	%o3,%o4,%g0
	mov	%i3,%o0			! py0 = y
	bl,pn	%icc,.range0		! if hx < 0x3e300000 or > 0x40862e41

! delay slot
	lda	[%i1+4]%asi,%f11
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.endloop1

! delay slot
	andn	%l1,%i5,%l1
	add	%i1,%i2,%i1		! x += stridex
	for	%f2,TWO96,%f2		! used to strip least sig bits
	fmuld	%f0,INVLN2_256,%f4	! x/ (ln2/256)  , creating k

.loop1:
	lda	[%i1]%asi,%l2		! preload next argument
	sub	%l1,%l6,%o3
	sub	%l7,%l1,%o4
	fand	%f10,SIGNBIT,%f12

	lda	[%i1]%asi,%f20
	orcc	%o3,%o4,%g0
	mov	%i3,%o1			! py1 = y
	bl,pn	%icc,.range1		! if hx < 0x3e300000 or > 0x40862e41

! delay slot
	lda	[%i1+4]%asi,%f21
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.endloop2

! delay slot
	andn	%l2,%i5,%l2
	add	%i1,%i2,%i1		! x += stridex
	for	%f12,TWO96,%f12
	fmuld	%f10,INVLN2_256,%f14

.loop2:
	sub	%l2,%l6,%o3
	sub	%l7,%l2,%o4
	fand	%f20,SIGNBIT,%f22
	fmuld	%f20,INVLN2_256,%f24		! okay to put this here; for alignment

	orcc	%o3,%o4,%g0
	bl,pn	%icc,.range2		! if hx < 0x3e300000 or > 0x40862e41
! delay slot
	for	%f22,TWO96,%f22
	faddd	%f4,%f2,%f4		! creating k+j/256, sra to zero bits

.cont:
	faddd	%f14,%f12,%f14
	mov	%i3,%o2			! py2 = y

	faddd	%f24,%f22,%f24
	add	%i3,%i4,%i3		! y += stridey

	! BUBBLE USIII

	fsubd	%f4,%f2,%f8		! creating k+j/256: sll 
	st	%f6,[%l3]		! store previous loop x0

	fsubd	%f14,%f12,%f18
	st	%f7,[%l3+4]		! store previous loop x0

	fsubd	%f24,%f22,%f28
	st	%f16,[%l4]

	! BUBBLE USIII

	fmuld	%f8,LN2_256H,%f2	! closest LN2_256 to x
	st	%f17,[%l4+4]

	fmuld	%f18,LN2_256H,%f12
	st	%f26,[%l5]

	fmuld	%f28,LN2_256H,%f22
	st	%f27,[%l5+4]

	! BUBBLE USIII

	fsubd	%f0,%f2,%f0		! r = x - p*LN2_256H
	fmuld	%f8,LN2_256L,%f4	! closest LN2_256 to x , added prec

	fsubd	%f10,%f12,%f10
	fmuld	%f18,LN2_256L,%f14

	fsubd	%f20,%f22,%f20
	fmuld	%f28,LN2_256L,%f24

	! BUBBLE USIII

	fsubd	%f0,%f4,%f0		! r -= p*LN2_256L

	fsubd	%f10,%f14,%f10

	fsubd	%f20,%f24,%f20

!!!!!!!!!!!!!!!!!!! New polynomial reorder starts here

	! Alternate polynomial grouping allowing non-sequential calc of p
	! OLD : p = r * ( 1 + r * ( B1 + r * ( B2 + r * B3) ) )
	! NEW : p = r * [ (1+r*B1) + (r*r) * ( B2 + r * B3) ) ]
	!
	! let               SLi        Ri           SRi		be accumulators

	fmuld	%f0,B3,%f2	! SR1 = r1 * B3
	fdtoi	%f8,%f8				! convert k+j/256 to int
	st      %f8,[%fp+m0]			! store k, to shift return/use

	fmuld	%f10,B3,%f12	! SR2 = r2 * B3
	fdtoi	%f18,%f18			! convert k+j/256 to int
	st      %f18,[%fp+m1]			! store k, to shift return/use

	fmuld	%f20,B3,%f22	! SR3 = r3 * B3
	fdtoi	%f28,%f28			! convert k+j/256 to int
	st      %f28,[%fp+m2]			! store k, to shift return/use

	fmuld	%f0,%f0,%f4	! R1 = r1 * r1

	fmuld	%f10,%f10,%f14	! R2 = r2 * r2
	faddd	%f2,B2,%f2	! SR1 += B2

	fmuld	%f20,%f20,%f24	! R3 = r3 * r3
	faddd	%f12,B2,%f12	! SR2 += B2

	faddd	%f22,B2,%f22	! SR3 += B2
	fmuld	%f0,B1,%f6	! SL1 = r1 * B1

	fmuld	%f10,B1,%f32	! SL2 = r2 * B1
	fand	%f8,NEGINF,%f8
	! best here for RAW BYPASS
	ld	[%fp+m0],%l0			! get nonshifted k into intreg

	fmuld	%f20,B1,%f34	! SL3 = r3 * B1
	fand	%f18,NEGINF,%f18
	ld	[%fp+m1],%l1			! get nonshifted k into intreg

	fmuld	%f4,%f2,%f4	! R1 = R1 * SR1
	fand	%f28,NEGINF,%f28
	ld	[%fp+m2],%l2			! get nonshifted k into intreg

	fmuld	%f14,%f12,%f14	! R2 = R2 * SR2
	faddd	%f6,ONE,%f6	! SL1 += 1

	fmuld	%f24,%f22,%f24	! R3 = R3 * SR3
	faddd	%f32,ONE,%f32	! SL2 += 1
	sra	%l0,8,%l3			! shift k tobe offset 256-8byte

	faddd	%f34,ONE,%f34	! SL3 += 1
	sra	%l1,8,%l4			! shift k tobe offset 256-8byte
	sra	%l2,8,%l5			! shift k tobe offset 256-8byte

	! BUBBLE in USIII
	and	%l3,0xff0,%l3
	and	%l4,0xff0,%l4



	faddd	%f6,%f4,%f6	! R1 = SL1 + R1
	ldd     [%g1+%l3],%f4			! tbl[j]
	add     %l3,8,%l3			! inc j
	and	%l5,0xff0,%l5


	faddd	%f32,%f14,%f32	! R2 = SL2 + R2
	ldd     [%g1+%l4],%f14			! tbl[j]
	add     %l4,8,%l4			! inc j
	sra	%l0,20,%o3

	faddd	%f34,%f24,%f34	! R3 = SL3 + R3
	ldd     [%g1+%l5],%f24			! tbl[j]
	add     %l5,8,%l5			! inc j
	sra	%l1,20,%l1

	! BUBBLE in USIII
	ldd     [%g1+%l4],%f16		! tbl[j+1]
	add     %o3,1021,%o3		! inc j

	fmuld	%f0,%f6,%f0	! p1 = r1 * R1
	ldd     [%g1+%l3],%f6           ! tbl[j+1]
	add     %l1,1021,%l1		! inc j
	sra	%l2,20,%l2

	fmuld	%f10,%f32,%f10	! p2 = r2 * R2
	ldd     [%g1+%l5],%f26		! tbl[j+1]
	add     %l2,1021,%l2		! inc j

	fmuld	%f20,%f34,%f20	! p3 = r3 * R3

 
 


!!!!!!!!!!!!!!!!!!! poly-reorder - ends here

	fmuld	%f0,%f4,%f0		! start exp(x) = exp(r) * tbl[j]
	mov	%o0,%l3

	fmuld	%f10,%f14,%f10
	mov	%o1,%l4

	fmuld	%f20,%f24,%f20
	mov	%o2,%l5

	faddd	%f0,%f6,%f6		! cont exp(x) : apply tbl[j] high bits
	lda	[%i1]%asi,%l0		! preload next argument

	faddd	%f10,%f16,%f16
	lda	[%i1]%asi,%f0

	faddd	%f20,%f26,%f26
	lda	[%i1+4]%asi,%f1

	faddd	%f6,%f4,%f6		! cont exp(x) : apply tbl[j+1] low bits
	add	%i1,%i2,%i1		! x += stridex

	faddd	%f16,%f14,%f16
	andn	%l0,%i5,%l0
	or	%o3,%l1,%o4

! -- 16 byte aligned
	orcc	%o4,%l2,%o4
	bl,pn	%icc,.small
! delay slot
	faddd	%f26,%f24,%f26

	fpadd32	%f6,%f8,%f6		! done exp(x) : apply 2^k
	fpadd32	%f16,%f18,%f16


	addcc	%i0,-1,%i0
	bg,pn	%icc,.loop0
! delay slot
	fpadd32	%f26,%f28,%f26

	ba,pt	%icc,.endloop0
! delay slot
	nop


	.align	16
.small:
	tst	%o3
	bge,pt	%icc,1f
! delay slot
	fpadd32	%f6,%f8,%f6
	fpadd32	%f6,BOUNDRY,%f6
	fmuld	%f6,TINY,%f6
1:
	tst	%l1
	bge,pt	%icc,1f
! delay slot
	fpadd32	%f16,%f18,%f16
	fpadd32	%f16,BOUNDRY,%f16
	fmuld	%f16,TINY,%f16
1:
	tst	%l2
	bge,pt	%icc,1f
! delay slot
	fpadd32	%f26,%f28,%f26
	fpadd32	%f26,BOUNDRY,%f26
	fmuld	%f26,TINY,%f26
1:
	addcc	%i0,-1,%i0
	bg,pn	%icc,.loop0
! delay slot
	nop
	ba,pt	%icc,.endloop0
! delay slot
	nop


.endloop2:
	for	%f12,TWO96,%f12
	fmuld	%f10,INVLN2_256,%f14
	faddd	%f14,%f12,%f14
	fsubd	%f14,%f12,%f18
	fmuld	%f18,LN2_256H,%f12
	fsubd	%f10,%f12,%f10
	fmuld	%f18,LN2_256L,%f14
	fsubd	%f10,%f14,%f10
	fmuld	%f10,B3,%f12
	fdtoi	%f18,%f18
	st      %f18,[%fp+m1]
	fmuld	%f10,%f10,%f14
	faddd	%f12,B2,%f12
	fmuld	%f10,B1,%f32
	fand	%f18,NEGINF,%f18
	ld	[%fp+m1],%l1
	fmuld	%f14,%f12,%f14
	faddd	%f32,ONE,%f32
	sra	%l1,8,%o4	
	and	%o4,0xff0,%o4
	faddd	%f32,%f14,%f32
	ldd     [%g1+%o4],%f14
	add     %o4,8,%o4
	sra	%l1,20,%l1
	ldd     [%g1+%o4],%f30
	addcc	%l1,1021,%l1
	fmuld	%f10,%f32,%f10
	fmuld	%f10,%f14,%f10
	faddd	%f10,%f30,%f30
	faddd	%f30,%f14,%f30
	bge,pt	%icc,1f
! delay slot
	fpadd32	%f30,%f18,%f30
	fpadd32	%f30,BOUNDRY,%f30
	fmuld	%f30,TINY,%f30
1:
	st	%f30,[%o1]
	st	%f31,[%o1+4]

.endloop1:
	for	%f2,TWO96,%f2
	fmuld	%f0,INVLN2_256,%f4
	faddd	%f4,%f2,%f4
	fsubd	%f4,%f2,%f8
	fmuld	%f8,LN2_256H,%f2
	fsubd	%f0,%f2,%f0
	fmuld	%f8,LN2_256L,%f4
	fsubd	%f0,%f4,%f0
	fmuld	%f0,B3,%f2
	fdtoi	%f8,%f8
	st	%f8,[%fp+m0]
	fmuld	%f0,%f0,%f4
	faddd	%f2,B2,%f2
	fmuld	%f0,B1,%f32
	fand	%f8,NEGINF,%f8
	ld	[%fp+m0],%l0
	fmuld	%f4,%f2,%f4
	faddd	%f32,ONE,%f32
	sra	%l0,8,%o4	
	and	%o4,0xff0,%o4
	faddd	%f32,%f4,%f32
	ldd     [%g1+%o4],%f4
	add     %o4,8,%o4
	sra	%l0,20,%o3
	ldd     [%g1+%o4],%f30
	addcc	%o3,1021,%o3
	fmuld	%f0,%f32,%f0
	fmuld	%f0,%f4,%f0
	faddd	%f0,%f30,%f30
	faddd	%f30,%f4,%f30
	bge,pt	%icc,1f
! delay slot
	fpadd32	%f30,%f8,%f30
	fpadd32	%f30,BOUNDRY,%f30
	fmuld	%f30,TINY,%f30
1:
	st	%f30,[%o0]
	st	%f31,[%o0+4]

.endloop0:
	st	%f6,[%l3]
	st	%f7,[%l3+4]
	st	%f16,[%l4]
	st	%f17,[%l4+4]
	st	%f26,[%l5]
	st	%f27,[%l5+4]
	ret
	restore


.range0:
	cmp	%l0,%l6
	bl,a,pt	%icc,3f			! if x is tiny
! delay slot, annulled if branch not taken
	faddd	%f0,ONE,%f4

	cmp	%l0,%o5
	bg,pt	%icc,1f			! if x is huge, inf, nan
! delay slot
	nop

	fcmpd	%fcc0,%f0,THRESH
	fbg,a,pt %fcc0,3f		! if x is huge and positive
! delay slot, annulled if branch not taken
	fmuld	HUGE,HUGE,%f4

! x is near the extremes but within range; return to the loop
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.endloop1
! delay slot
	andn	%l1,%i5,%l1
	add	%i1,%i2,%i1		! x += stridex
	for	%f2,TWO96,%f2
	ba,pt	%icc,.loop1
! delay slot
	fmuld	%f0,INVLN2_256,%f4

1:
	cmp	%l0,%o7
	bl,pn	%icc,2f			! if x is finite
! delay slot
	nop
	fzero	%f4
	fcmpd	%fcc0,%f0,NEGINF
	fmovdne	%fcc0,%f0,%f4
	ba,pt	%icc,3f
	fmuld	%f4,%f4,%f4		! x*x or zero*zero
2:
	fmovd	HUGE,%f4
	fcmpd	%fcc0,%f0,ONE
	fmovdl	%fcc0,TINY,%f4
	fmuld	%f4,%f4,%f4		! huge*huge or tiny*tiny
3:
	st	%f4,[%o0]
	andn	%l1,%i5,%l0
	add	%i1,%i2,%i1		! x += stridex
	fmovd	%f10,%f0
	st	%f5,[%o0+4]
	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop0
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	ba,pt	%icc,.endloop0
! delay slot
	nop


.range1:
	cmp	%l1,%l6
	bl,a,pt	%icc,3f			! if x is tiny
! delay slot, annulled if branch not taken
	faddd	%f10,ONE,%f14

	cmp	%l1,%o5
	bg,pt	%icc,1f			! if x is huge, inf, nan
! delay slot
	nop

	fcmpd	%fcc0,%f10,THRESH
	fbg,a,pt %fcc0,3f		! if x is huge and positive
! delay slot, annulled if branch not taken
	fmuld	HUGE,HUGE,%f14

! x is near the extremes but within range; return to the loop
	addcc	%i0,-1,%i0
	add	%i3,%i4,%i3		! y += stridey
	ble,pn	%icc,.endloop2
! delay slot
	andn	%l2,%i5,%l2
	add	%i1,%i2,%i1		! x += stridex
	for	%f12,TWO96,%f12
	ba,pt	%icc,.loop2
! delay slot
	fmuld	%f10,INVLN2_256,%f14

1:
	cmp	%l1,%o7
	bl,pn	%icc,2f			! if x is finite
! delay slot
	nop
	fzero	%f14
	fcmpd	%fcc0,%f10,NEGINF
	fmovdne	%fcc0,%f10,%f14
	ba,pt	%icc,3f
	fmuld	%f14,%f14,%f14		! x*x or zero*zero
2:
	fmovd	HUGE,%f14
	fcmpd	%fcc0,%f10,ONE
	fmovdl	%fcc0,TINY,%f14
	fmuld	%f14,%f14,%f14		! huge*huge or tiny*tiny
3:
	st	%f14,[%o1]
	andn	%l2,%i5,%l1
	add	%i1,%i2,%i1		! x += stridex
	fmovd	%f20,%f10
	st	%f15,[%o1+4]
	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop1
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	ba,pt	%icc,.endloop1
! delay slot
	nop


.range2:
	cmp	%l2,%l6
	bl,a,pt	%icc,3f			! if x is tiny
! delay slot, annulled if branch not taken
	faddd	%f20,ONE,%f24

	cmp	%l2,%o5
	bg,pt	%icc,1f			! if x is huge, inf, nan
! delay slot
	nop

	fcmpd	%fcc0,%f20,THRESH
	fbg,a,pt %fcc0,3f		! if x is huge and positive
! delay slot, annulled if branch not taken
	fmuld	HUGE,HUGE,%f24

! x is near the extremes but within range; return to the loop
	ba,pt	%icc,.cont
! delay slot
	faddd	%f4,%f2,%f4

1:
	cmp	%l2,%o7
	bl,pn	%icc,2f			! if x is finite
! delay slot
	nop
	fzero	%f24
	fcmpd	%fcc0,%f20,NEGINF
	fmovdne	%fcc0,%f20,%f24
	ba,pt	%icc,3f
	fmuld	%f24,%f24,%f24		! x*x or zero*zero
2:
	fmovd	HUGE,%f24
	fcmpd	%fcc0,%f20,ONE
	fmovdl	%fcc0,TINY,%f24
	fmuld	%f24,%f24,%f24		! huge*huge or tiny*tiny
3:
	st	%f24,[%i3]
	st	%f25,[%i3+4]
	lda	[%i1]%asi,%l2		! preload next argument
	lda	[%i1]%asi,%f20
	lda	[%i1+4]%asi,%f21
	andn	%l2,%i5,%l2
	add	%i1,%i2,%i1		! x += stridex
	addcc	%i0,-1,%i0
	bg,pt	%icc,.loop2
! delay slot
	add	%i3,%i4,%i3		! y += stridey
	ba,pt	%icc,.endloop2
! delay slot
	nop

	SET_SIZE(__vexp)

