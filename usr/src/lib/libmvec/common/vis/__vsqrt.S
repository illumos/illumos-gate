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

	.file	"__vsqrt.S"

#include "libm.h"

	RO_DATA
	.align	64

.CONST_TBL:
	.word	0x3fe00000, 0x00000000	! A1  =  5.00000000000000001789e-01
	.word	0xbfbfffff, 0xfffd0bfd	! A2  = -1.24999999997314110667e-01
	.word	0x3fafffff, 0xfffb5bfb	! A3  =  6.24999999978896565817e-02
	.word	0xbfa4000f, 0xc00b4fc8	! A4  = -3.90629693917215481458e-02
	.word	0x3f9c0018, 0xc012da4e	! A5  =  2.73441188080261677282e-02
	.word	0x000fffff, 0xffffffff	! DC0 =  0x000fffffffffffff
	.word	0x00001000, 0x00000000	! DC2 =  0x0000100000000000
	.word	0x7fffe000, 0x00000000	! DC3 =  0x7fffe00000000000

! i = [0,128]
! TBL[8*i+0] = 1.0 / (*(double*)&(0x3fe0000000000000LL + (i << 45)));
! TBL[8*i+1] = (double)(2.0 * sqrtl(*(double*)&(0x3fe0000000000000LL + (i << 45))));
! TBL[8*i+2] = (double)(2.0 * sqrtl(*(double*)&(0x3fe0000000000000LL + (i << 45))) - TBL[8*i+1]);
! TBL[8*i+3] = 0
! TBL[8*i+4] = 1.0 / (*(double*)&(0x3fe0000000000000LL + (i << 45)));
! TBL[8*i+5] = (double)(2.0 * sqrtl(2.0) * sqrtl(*(double*)&(0x3fe0000000000000LL + (i << 45))));
! TBL[8*i+6] = (double)(2.0 * sqrtl(2.0) * sqrtl(*(double*)&(0x3fe0000000000000LL + (i << 45))) - TBL[8*i+5]);
! TBL[8*i+7] = 0

	.word	0x40000000, 0x00000000, 0x3ff6a09e, 0x667f3bcd
	.word	0xbc9bdd34, 0x13b26456, 0x00000000, 0x00000000
	.word	0x40000000, 0x00000000, 0x40000000, 0x00000000
	.word	0xb8f00000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3fffc07f, 0x01fc07f0, 0x3ff6b733, 0xbfd8c648
	.word	0x3c53b629, 0x05629048, 0x00000000, 0x00000000
	.word	0x3fffc07f, 0x01fc07f0, 0x40000ff8, 0x07f60deb
	.word	0x3c90655c, 0x648a53f1, 0x00000000, 0x00000000
	.word	0x3fff81f8, 0x1f81f820, 0x3ff6cdb2, 0xbbb212eb
	.word	0x3c960332, 0xcdbaba2d, 0x00000000, 0x00000000
	.word	0x3fff81f8, 0x1f81f820, 0x40001fe0, 0x3f61bad0
	.word	0x3ca2c41a, 0x15cbfaf2, 0x00000000, 0x00000000
	.word	0x3fff4465, 0x9e4a4271, 0x3ff6e41b, 0x9bfb3b75
	.word	0xbc925d8c, 0xfd6d5c87, 0x00000000, 0x00000000
	.word	0x3fff4465, 0x9e4a4271, 0x40002fb8, 0xd4e30f48
	.word	0xbca64203, 0xab1ba910, 0x00000000, 0x00000000
	.word	0x3fff07c1, 0xf07c1f08, 0x3ff6fa6e, 0xa162d0f0
	.word	0x3c691a24, 0x3d6297e9, 0x00000000, 0x00000000
	.word	0x3fff07c1, 0xf07c1f08, 0x40003f81, 0xf636b80c
	.word	0xbca0efc8, 0xba812a8c, 0x00000000, 0x00000000
	.word	0x3ffecc07, 0xb301ecc0, 0x3ff710ac, 0x0b5e5e32
	.word	0xbc991218, 0xb8d2850d, 0x00000000, 0x00000000
	.word	0x3ffecc07, 0xb301ecc0, 0x40004f3b, 0xd03c0a64
	.word	0x3c9ee2cf, 0x2d8ae22b, 0x00000000, 0x00000000
	.word	0x3ffe9131, 0xabf0b767, 0x3ff726d4, 0x1832a0be
	.word	0xbc2d9b1a, 0xa8ecb058, 0x00000000, 0x00000000
	.word	0x3ffe9131, 0xabf0b767, 0x40005ee6, 0x8efad48b
	.word	0xbc9c35f4, 0x8f4b89f7, 0x00000000, 0x00000000
	.word	0x3ffe573a, 0xc901e574, 0x3ff73ce7, 0x04fb7b23
	.word	0x3c91470b, 0x816b17a6, 0x00000000, 0x00000000
	.word	0x3ffe573a, 0xc901e574, 0x40006e82, 0x5da8fc2b
	.word	0x3c9a315a, 0x8bd8a03b, 0x00000000, 0x00000000
	.word	0x3ffe1e1e, 0x1e1e1e1e, 0x3ff752e5, 0x0db3a3a2
	.word	0xbc939331, 0x3eea4381, 0x00000000, 0x00000000
	.word	0x3ffe1e1e, 0x1e1e1e1e, 0x40007e0f, 0x66afed07
	.word	0xbc74a6e1, 0xdcd59eaf, 0x00000000, 0x00000000
	.word	0x3ffde5d6, 0xe3f8868a, 0x3ff768ce, 0x6d3c11e0
	.word	0xbc9478b8, 0xab33074d, 0x00000000, 0x00000000
	.word	0x3ffde5d6, 0xe3f8868a, 0x40008d8d, 0xd3b1d9aa
	.word	0x3c81d533, 0x85fe2b96, 0x00000000, 0x00000000
	.word	0x3ffdae60, 0x76b981db, 0x3ff77ea3, 0x5d632e43
	.word	0x3c92f714, 0x9a22fa4f, 0x00000000, 0x00000000
	.word	0x3ffdae60, 0x76b981db, 0x40009cfd, 0xcd8ed009
	.word	0xbc4862a9, 0xbcf7f372, 0x00000000, 0x00000000
	.word	0x3ffd77b6, 0x54b82c34, 0x3ff79464, 0x16ebc56c
	.word	0x3c9a7cd5, 0x224c7375, 0x00000000, 0x00000000
	.word	0x3ffd77b6, 0x54b82c34, 0x4000ac5f, 0x7c69a3c8
	.word	0x3ca94dff, 0x7bfa2757, 0x00000000, 0x00000000
	.word	0x3ffd41d4, 0x1d41d41d, 0x3ff7aa10, 0xd193c22d
	.word	0xbc790ed9, 0x403afe85, 0x00000000, 0x00000000
	.word	0x3ffd41d4, 0x1d41d41d, 0x4000bbb3, 0x07acafdb
	.word	0xbc852a97, 0x686f9d2e, 0x00000000, 0x00000000
	.word	0x3ffd0cb5, 0x8f6ec074, 0x3ff7bfa9, 0xc41ab040
	.word	0x3c8d6bc3, 0x02ae758f, 0x00000000, 0x00000000
	.word	0x3ffd0cb5, 0x8f6ec074, 0x4000caf8, 0x960e710d
	.word	0x3c9caa6b, 0xe2366171, 0x00000000, 0x00000000
	.word	0x3ffcd856, 0x89039b0b, 0x3ff7d52f, 0x244809e9
	.word	0x3c9081f6, 0xf3b99d5f, 0x00000000, 0x00000000
	.word	0x3ffcd856, 0x89039b0b, 0x4000da30, 0x4d95fb06
	.word	0xbc9e1269, 0x76855586, 0x00000000, 0x00000000
	.word	0x3ffca4b3, 0x055ee191, 0x3ff7eaa1, 0x26f15284
	.word	0xbc846ce4, 0x68c1882b, 0x00000000, 0x00000000
	.word	0x3ffca4b3, 0x055ee191, 0x4000e95a, 0x539f492c
	.word	0xbc80c73f, 0xc38a2184, 0x00000000, 0x00000000
	.word	0x3ffc71c7, 0x1c71c71c, 0x3ff80000, 0x00000000
	.word	0x00000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ffc71c7, 0x1c71c71c, 0x4000f876, 0xccdf6cd9
	.word	0x3cab1a18, 0xf13a34c0, 0x00000000, 0x00000000
	.word	0x3ffc3f8f, 0x01c3f8f0, 0x3ff8154b, 0xe2773526
	.word	0xbc857147, 0xe067d0ee, 0x00000000, 0x00000000
	.word	0x3ffc3f8f, 0x01c3f8f0, 0x40010785, 0xdd689a29
	.word	0xbcaaabbe, 0x9e4d810a, 0x00000000, 0x00000000
	.word	0x3ffc0e07, 0x0381c0e0, 0x3ff82a85, 0x00794e6c
	.word	0xbc82edaa, 0x75e6ac5f, 0x00000000, 0x00000000
	.word	0x3ffc0e07, 0x0381c0e0, 0x40011687, 0xa8ae14a3
	.word	0x3cac9b43, 0xbcf06106, 0x00000000, 0x00000000
	.word	0x3ffbdd2b, 0x899406f7, 0x3ff83fab, 0x8b4d4315
	.word	0x3c829e06, 0x2d3e134d, 0x00000000, 0x00000000
	.word	0x3ffbdd2b, 0x899406f7, 0x4001257c, 0x5187fd09
	.word	0xbca4a750, 0xa83950a4, 0x00000000, 0x00000000
	.word	0x3ffbacf9, 0x14c1bad0, 0x3ff854bf, 0xb363dc39
	.word	0x3c99399f, 0xca38787e, 0x00000000, 0x00000000
	.word	0x3ffbacf9, 0x14c1bad0, 0x40013463, 0xfa37014e
	.word	0x3c7b295b, 0xaa698cd3, 0x00000000, 0x00000000
	.word	0x3ffb7d6c, 0x3dda338b, 0x3ff869c1, 0xa85cc346
	.word	0x3c9fcc99, 0xde11b1d1, 0x00000000, 0x00000000
	.word	0x3ffb7d6c, 0x3dda338b, 0x4001433e, 0xc467effb
	.word	0x3c92c031, 0x3b7278c8, 0x00000000, 0x00000000
	.word	0x3ffb4e81, 0xb4e81b4f, 0x3ff87eb1, 0x990b697a
	.word	0x3c7c43e9, 0xf593ea0f, 0x00000000, 0x00000000
	.word	0x3ffb4e81, 0xb4e81b4f, 0x4001520c, 0xd1372feb
	.word	0xbcadec22, 0x5d8e66d2, 0x00000000, 0x00000000
	.word	0x3ffb2036, 0x406c80d9, 0x3ff8938f, 0xb37bc9c1
	.word	0xbc7c115f, 0x9f5c8d6f, 0x00000000, 0x00000000
	.word	0x3ffb2036, 0x406c80d9, 0x400160ce, 0x41341d74
	.word	0x3c967036, 0x863a1bb2, 0x00000000, 0x00000000
	.word	0x3ffaf286, 0xbca1af28, 0x3ff8a85c, 0x24f70659
	.word	0x3c9f6e07, 0x6b588a50, 0x00000000, 0x00000000
	.word	0x3ffaf286, 0xbca1af28, 0x40016f83, 0x34644df9
	.word	0xbcae8679, 0x80a1c48e, 0x00000000, 0x00000000
	.word	0x3ffac570, 0x1ac5701b, 0x3ff8bd17, 0x1a07e38a
	.word	0x3c9c20b5, 0xa697f23f, 0x00000000, 0x00000000
	.word	0x3ffac570, 0x1ac5701b, 0x40017e2b, 0xca46bab9
	.word	0x3ca1519b, 0x10d04d5f, 0x00000000, 0x00000000
	.word	0x3ffa98ef, 0x606a63be, 0x3ff8d1c0, 0xbe7f20ac
	.word	0xbc8bdb8a, 0x6df021f3, 0x00000000, 0x00000000
	.word	0x3ffa98ef, 0x606a63be, 0x40018cc8, 0x21d6d3e3
	.word	0xbca30af1, 0xd725cc5b, 0x00000000, 0x00000000
	.word	0x3ffa6d01, 0xa6d01a6d, 0x3ff8e659, 0x3d77b0b8
	.word	0xbc7d99d7, 0x64769954, 0x00000000, 0x00000000
	.word	0x3ffa6d01, 0xa6d01a6d, 0x40019b58, 0x598f7c9f
	.word	0xbc72e0d8, 0x51c0e011, 0x00000000, 0x00000000
	.word	0x3ffa41a4, 0x1a41a41a, 0x3ff8fae0, 0xc15ad38a
	.word	0xbc7db7ad, 0xb6817f6d, 0x00000000, 0x00000000
	.word	0x3ffa41a4, 0x1a41a41a, 0x4001a9dc, 0x8f6df104
	.word	0xbcafc519, 0xc18dc1d5, 0x00000000, 0x00000000
	.word	0x3ffa16d3, 0xf97a4b02, 0x3ff90f57, 0x73e410e4
	.word	0x3c6fb605, 0xcee75482, 0x00000000, 0x00000000
	.word	0x3ffa16d3, 0xf97a4b02, 0x4001b854, 0xe0f496a0
	.word	0x3ca27006, 0x899b7c3a, 0x00000000, 0x00000000
	.word	0x3ff9ec8e, 0x951033d9, 0x3ff923bd, 0x7e25164d
	.word	0xbc9278d1, 0x901d3b40, 0x00000000, 0x00000000
	.word	0x3ff9ec8e, 0x951033d9, 0x4001c6c1, 0x6b2db870
	.word	0x3c887e1d, 0x8335fb28, 0x00000000, 0x00000000
	.word	0x3ff9c2d1, 0x4ee4a102, 0x3ff93813, 0x088978c5
	.word	0xbc54312c, 0x627e5c52, 0x00000000, 0x00000000
	.word	0x3ff9c2d1, 0x4ee4a102, 0x4001d522, 0x4aae2ee1
	.word	0x3ca91222, 0xf6aebdc9, 0x00000000, 0x00000000
	.word	0x3ff99999, 0x9999999a, 0x3ff94c58, 0x3ada5b53
	.word	0xbc9b7ed7, 0x50df3cca, 0x00000000, 0x00000000
	.word	0x3ff99999, 0x9999999a, 0x4001e377, 0x9b97f4a8
	.word	0xbc9f5063, 0x19fcfd19, 0x00000000, 0x00000000
	.word	0x3ff970e4, 0xf80cb872, 0x3ff9608d, 0x3c41fb4b
	.word	0x3c73df32, 0xeaa86b83, 0x00000000, 0x00000000
	.word	0x3ff970e4, 0xf80cb872, 0x4001f1c1, 0x799ca8ff
	.word	0xbca28b52, 0xeb725e0a, 0x00000000, 0x00000000
	.word	0x3ff948b0, 0xfcd6e9e0, 0x3ff974b2, 0x334f2346
	.word	0x3c814e4a, 0xd3ae9e3f, 0x00000000, 0x00000000
	.word	0x3ff948b0, 0xfcd6e9e0, 0x40020000, 0x00000000
	.word	0xb9000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ff920fb, 0x49d0e229, 0x3ff988c7, 0x45f88592
	.word	0x3c95af70, 0x1a56047b, 0x00000000, 0x00000000
	.word	0x3ff920fb, 0x49d0e229, 0x40020e33, 0x499a21a9
	.word	0xbc924ba2, 0x74fea9a1, 0x00000000, 0x00000000
	.word	0x3ff8f9c1, 0x8f9c18fa, 0x3ff99ccc, 0x999fff00
	.word	0x3c866234, 0x063b88ee, 0x00000000, 0x00000000
	.word	0x3ff8f9c1, 0x8f9c18fa, 0x40021c5b, 0x70d9f824
	.word	0xbca844f9, 0x9eee6fc3, 0x00000000, 0x00000000
	.word	0x3ff8d301, 0x8d3018d3, 0x3ff9b0c2, 0x5315c2ce
	.word	0xbc87f64a, 0x65cc6887, 0x00000000, 0x00000000
	.word	0x3ff8d301, 0x8d3018d3, 0x40022a78, 0x8fc76de5
	.word	0x3c931e32, 0xd4e07a48, 0x00000000, 0x00000000
	.word	0x3ff8acb9, 0x0f6bf3aa, 0x3ff9c4a8, 0x969b7077
	.word	0xbc96ca9e, 0x5cd4517a, 0x00000000, 0x00000000
	.word	0x3ff8acb9, 0x0f6bf3aa, 0x4002388a, 0xc0059c28
	.word	0xbc96072f, 0xbe0e5da3, 0x00000000, 0x00000000
	.word	0x3ff886e5, 0xf0abb04a, 0x3ff9d87f, 0x87e71422
	.word	0xbc85fdd8, 0xb11b7b1d, 0x00000000, 0x00000000
	.word	0x3ff886e5, 0xf0abb04a, 0x40024692, 0x1ad4ea49
	.word	0xbcaa6d9b, 0x268ef62d, 0x00000000, 0x00000000
	.word	0x3ff86186, 0x18618618, 0x3ff9ec47, 0x4a261264
	.word	0xbc8540c4, 0x89ba5074, 0x00000000, 0x00000000
	.word	0x3ff86186, 0x18618618, 0x4002548e, 0xb9151e85
	.word	0x3c999820, 0x0a774879, 0x00000000, 0x00000000
	.word	0x3ff83c97, 0x7ab2bedd, 0x3ffa0000, 0x00000000
	.word	0x00000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ff83c97, 0x7ab2bedd, 0x40026280, 0xb3476096
	.word	0x3c9ab88b, 0x5ffe1cf5, 0x00000000, 0x00000000
	.word	0x3ff81818, 0x18181818, 0x3ffa13a9, 0xcb996651
	.word	0xbc9f9ab9, 0x0e4e85c3, 0x00000000, 0x00000000
	.word	0x3ff81818, 0x18181818, 0x40027068, 0x21902e9a
	.word	0x3c90ff4c, 0x20f541f6, 0x00000000, 0x00000000
	.word	0x3ff7f405, 0xfd017f40, 0x3ffa2744, 0xce9674f5
	.word	0xbc8b936c, 0x81e54daa, 0x00000000, 0x00000000
	.word	0x3ff7f405, 0xfd017f40, 0x40027e45, 0x1bb944c3
	.word	0x3c8e4a16, 0x42099ef0, 0x00000000, 0x00000000
	.word	0x3ff7d05f, 0x417d05f4, 0x3ffa3ad1, 0x2a1da160
	.word	0x3c951168, 0xf4be5984, 0x00000000, 0x00000000
	.word	0x3ff7d05f, 0x417d05f4, 0x40028c17, 0xb9337834
	.word	0xbc8af150, 0xa0e88972, 0x00000000, 0x00000000
	.word	0x3ff7ad22, 0x08e0ecc3, 0x3ffa4e4e, 0xfeda34de
	.word	0x3c6afbb4, 0xdbdadd0d, 0x00000000, 0x00000000
	.word	0x3ff7ad22, 0x08e0ecc3, 0x400299e0, 0x11188575
	.word	0xbc9a6169, 0x3fb250e5, 0x00000000, 0x00000000
	.word	0x3ff78a4c, 0x8178a4c8, 0x3ffa61be, 0x6cfec997
	.word	0xbc8c37ea, 0xb2bb5ca0, 0x00000000, 0x00000000
	.word	0x3ff78a4c, 0x8178a4c8, 0x4002a79e, 0x3a2cd2e6
	.word	0xbca5ddd4, 0x9cc9ad59, 0x00000000, 0x00000000
	.word	0x3ff767dc, 0xe434a9b1, 0x3ffa751f, 0x9447b724
	.word	0x3c82b909, 0x477e9ed1, 0x00000000, 0x00000000
	.word	0x3ff767dc, 0xe434a9b1, 0x4002b552, 0x4ae1278e
	.word	0xbca2f2a9, 0x8841b934, 0x00000000, 0x00000000
	.word	0x3ff745d1, 0x745d1746, 0x3ffa8872, 0x93fd6f34
	.word	0x3c768ef2, 0x4f198721, 0x00000000, 0x00000000
	.word	0x3ff745d1, 0x745d1746, 0x4002c2fc, 0x595456a7
	.word	0xbc996f60, 0xb0fc7e96, 0x00000000, 0x00000000
	.word	0x3ff72428, 0x7f46debc, 0x3ffa9bb7, 0x8af6cabc
	.word	0x3c8ba60d, 0xc999aba7, 0x00000000, 0x00000000
	.word	0x3ff72428, 0x7f46debc, 0x4002d09c, 0x7b54e03e
	.word	0x3c98c747, 0xfdeda6de, 0x00000000, 0x00000000
	.word	0x3ff702e0, 0x5c0b8170, 0x3ffaaeee, 0x979b4838
	.word	0xbc91f08a, 0xef9ef6c0, 0x00000000, 0x00000000
	.word	0x3ff702e0, 0x5c0b8170, 0x4002de32, 0xc6628741
	.word	0x3ca78746, 0xc499a4f7, 0x00000000, 0x00000000
	.word	0x3ff6e1f7, 0x6b4337c7, 0x3ffac217, 0xd7e53b66
	.word	0xbc64282a, 0xaa967e4f, 0x00000000, 0x00000000
	.word	0x3ff6e1f7, 0x6b4337c7, 0x4002ebbf, 0x4fafdd4b
	.word	0xbca78a73, 0xb72d5c41, 0x00000000, 0x00000000
	.word	0x3ff6c16c, 0x16c16c17, 0x3ffad533, 0x6963eefc
	.word	0xbc977c4a, 0x537dbdd2, 0x00000000, 0x00000000
	.word	0x3ff6c16c, 0x16c16c17, 0x4002f942, 0x2c23c47e
	.word	0xbc827c85, 0xf29db65d, 0x00000000, 0x00000000
	.word	0x3ff6a13c, 0xd1537290, 0x3ffae841, 0x693db8b4
	.word	0x3c90f773, 0xcd7a0713, 0x00000000, 0x00000000
	.word	0x3ff6a13c, 0xd1537290, 0x400306bb, 0x705ae7c3
	.word	0x3caf4933, 0x907af47a, 0x00000000, 0x00000000
	.word	0x3ff68168, 0x16816817, 0x3ffafb41, 0xf432002e
	.word	0xbc7ac94a, 0xfdfe8c5b, 0x00000000, 0x00000000
	.word	0x3ff68168, 0x16816817, 0x4003142b, 0x30a929ab
	.word	0x3c98dc01, 0x081a6c5c, 0x00000000, 0x00000000
	.word	0x3ff661ec, 0x6a5122f9, 0x3ffb0e35, 0x269b38f5
	.word	0xbc4f69a8, 0x05c3271a, 0x00000000, 0x00000000
	.word	0x3ff661ec, 0x6a5122f9, 0x40032191, 0x811b0a41
	.word	0xbc9ce3f0, 0xb38c0bf7, 0x00000000, 0x00000000
	.word	0x3ff642c8, 0x590b2164, 0x3ffb211b, 0x1c70d023
	.word	0x3c2e4c5e, 0x66eae2f0, 0x00000000, 0x00000000
	.word	0x3ff642c8, 0x590b2164, 0x40032eee, 0x75770416
	.word	0x3caed8e7, 0x730eaff2, 0x00000000, 0x00000000
	.word	0x3ff623fa, 0x77016240, 0x3ffb33f3, 0xf1490def
	.word	0xbc95894b, 0xcb02373b, 0x00000000, 0x00000000
	.word	0x3ff623fa, 0x77016240, 0x40033c42, 0x213ee0c9
	.word	0x3ca84c24, 0x4ba98124, 0x00000000, 0x00000000
	.word	0x3ff60581, 0x60581606, 0x3ffb46bf, 0xc05aeb89
	.word	0x3c9b1c7c, 0xc39adc9f, 0x00000000, 0x00000000
	.word	0x3ff60581, 0x60581606, 0x4003498c, 0x97b10540
	.word	0x3c734193, 0xbc8543b4, 0x00000000, 0x00000000
	.word	0x3ff5e75b, 0xb8d015e7, 0x3ffb597e, 0xa47fdda3
	.word	0xbc923cc8, 0x9d1e4635, 0x00000000, 0x00000000
	.word	0x3ff5e75b, 0xb8d015e7, 0x400356cd, 0xebc9b5e2
	.word	0x3c96dee1, 0x46bb1571, 0x00000000, 0x00000000
	.word	0x3ff5c988, 0x2b931057, 0x3ffb6c30, 0xb83593e6
	.word	0x3c8f4e3f, 0xd28d84bc, 0x00000000, 0x00000000
	.word	0x3ff5c988, 0x2b931057, 0x40036406, 0x30445306
	.word	0xbca78d86, 0x2327430a, 0x00000000, 0x00000000
	.word	0x3ff5ac05, 0x6b015ac0, 0x3ffb7ed6, 0x159fadc8
	.word	0xbc899bcf, 0xf04d134b, 0x00000000, 0x00000000
	.word	0x3ff5ac05, 0x6b015ac0, 0x40037135, 0x779c8dcb
	.word	0xbc8fe126, 0xce9778ae, 0x00000000, 0x00000000
	.word	0x3ff58ed2, 0x308158ed, 0x3ffb916e, 0xd68964ec
	.word	0x3c826a5d, 0x5dbaae29, 0x00000000, 0x00000000
	.word	0x3ff58ed2, 0x308158ed, 0x40037e5b, 0xd40f95a1
	.word	0x3cac6ff5, 0xeca5d122, 0x00000000, 0x00000000
	.word	0x3ff571ed, 0x3c506b3a, 0x3ffba3fb, 0x14672d7c
	.word	0xbc8117d3, 0x97dcefc9, 0x00000000, 0x00000000
	.word	0x3ff571ed, 0x3c506b3a, 0x40038b79, 0x579d3eab
	.word	0xbcac254f, 0xc0db598e, 0x00000000, 0x00000000
	.word	0x3ff55555, 0x55555555, 0x3ffbb67a, 0xe8584caa
	.word	0x3c9cec95, 0xd0b5c1e3, 0x00000000, 0x00000000
	.word	0x3ff55555, 0x55555555, 0x4003988e, 0x1409212e
	.word	0x3caf40c8, 0x6450c869, 0x00000000, 0x00000000
	.word	0x3ff53909, 0x48f40feb, 0x3ffbc8ee, 0x6b2865b9
	.word	0x3c9394eb, 0x90f645c8, 0x00000000, 0x00000000
	.word	0x3ff53909, 0x48f40feb, 0x4003a59a, 0x1adbb257
	.word	0x3ca6adce, 0x020a308d, 0x00000000, 0x00000000
	.word	0x3ff51d07, 0xeae2f815, 0x3ffbdb55, 0xb550fdbc
	.word	0x3c7365e9, 0x6aa5fae3, 0x00000000, 0x00000000
	.word	0x3ff51d07, 0xeae2f815, 0x4003b29d, 0x7d635662
	.word	0x3cac99b0, 0x5e282129, 0x00000000, 0x00000000
	.word	0x3ff50150, 0x15015015, 0x3ffbedb0, 0xdefaf661
	.word	0x3c91a627, 0xb279170d, 0x00000000, 0x00000000
	.word	0x3ff50150, 0x15015015, 0x4003bf98, 0x4cb56c77
	.word	0x3ca8f653, 0xbcc0c4a1, 0x00000000, 0x00000000
	.word	0x3ff4e5e0, 0xa72f0539, 0x3ffc0000, 0x00000000
	.word	0x00000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ff4e5e0, 0xa72f0539, 0x4003cc8a, 0x99af5453
	.word	0xbc486364, 0x4f05f2be, 0x00000000, 0x00000000
	.word	0x3ff4cab8, 0x8725af6e, 0x3ffc1243, 0x2fec0329
	.word	0x3c96e0d7, 0x8dd23a7d, 0x00000000, 0x00000000
	.word	0x3ff4cab8, 0x8725af6e, 0x4003d974, 0x74f76df2
	.word	0x3c82e3c9, 0xfdbbbdc2, 0x00000000, 0x00000000
	.word	0x3ff4afd6, 0xa052bf5b, 0x3ffc247a, 0x85fe81fa
	.word	0x3c89d8ee, 0xf6854220, 0x00000000, 0x00000000
	.word	0x3ff4afd6, 0xa052bf5b, 0x4003e655, 0xeefe1367
	.word	0x3c80eb35, 0xbb532559, 0x00000000, 0x00000000
	.word	0x3ff49539, 0xe3b2d067, 0x3ffc36a6, 0x192bf168
	.word	0xbc9083d8, 0x1a423b11, 0x00000000, 0x00000000
	.word	0x3ff49539, 0xe3b2d067, 0x4003f32f, 0x17fe8d04
	.word	0xbc905d6c, 0x1c437de0, 0x00000000, 0x00000000
	.word	0x3ff47ae1, 0x47ae147b, 0x3ffc48c6, 0x001f0ac0
	.word	0xbc92d481, 0x189efd6b, 0x00000000, 0x00000000
	.word	0x3ff47ae1, 0x47ae147b, 0x40040000, 0x00000000
	.word	0x00000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ff460cb, 0xc7f5cf9a, 0x3ffc5ada, 0x513a1593
	.word	0xbc7aaedd, 0x014f5f03, 0x00000000, 0x00000000
	.word	0x3ff460cb, 0xc7f5cf9a, 0x40040cc8, 0xb6d657c2
	.word	0xbc9c05ab, 0xf480ce19, 0x00000000, 0x00000000
	.word	0x3ff446f8, 0x6562d9fb, 0x3ffc6ce3, 0x22982a3f
	.word	0x3c891b2d, 0xf3e15f29, 0x00000000, 0x00000000
	.word	0x3ff446f8, 0x6562d9fb, 0x40041989, 0x4c2329f0
	.word	0x3c976037, 0x46da0ea6, 0x00000000, 0x00000000
	.word	0x3ff42d66, 0x25d51f87, 0x3ffc7ee0, 0x8a0e6d4c
	.word	0x3c991c54, 0xc53e75c8, 0x00000000, 0x00000000
	.word	0x3ff42d66, 0x25d51f87, 0x40042641, 0xcf569572
	.word	0xbcadf80b, 0x1442c029, 0x00000000, 0x00000000
	.word	0x3ff41414, 0x14141414, 0x3ffc90d2, 0x9d2d43ce
	.word	0xbc9edadb, 0x07f1137a, 0x00000000, 0x00000000
	.word	0x3ff41414, 0x14141414, 0x400432f2, 0x4fb01c7a
	.word	0x3ca38bfe, 0x0e012c1c, 0x00000000, 0x00000000
	.word	0x3ff3fb01, 0x3fb013fb, 0x3ffca2b9, 0x714180f7
	.word	0xbc81a63d, 0x6750c57c, 0x00000000, 0x00000000
	.word	0x3ff3fb01, 0x3fb013fb, 0x40043f9a, 0xdc3f79ce
	.word	0x3c66d2b1, 0x767ae30a, 0x00000000, 0x00000000
	.word	0x3ff3e22c, 0xbce4a902, 0x3ffcb495, 0x1b558d17
	.word	0x3c8fcbcb, 0x357f2308, 0x00000000, 0x00000000
	.word	0x3ff3e22c, 0xbce4a902, 0x40044c3b, 0x83e57153
	.word	0x3c98c853, 0xc6be5ee1, 0x00000000, 0x00000000
	.word	0x3ff3c995, 0xa47babe7, 0x3ffcc665, 0xb0328622
	.word	0xbc91baa4, 0xd369f814, 0x00000000, 0x00000000
	.word	0x3ff3c995, 0xa47babe7, 0x400458d4, 0x55549c1a
	.word	0x3ca02d72, 0x8d9a6054, 0x00000000, 0x00000000
	.word	0x3ff3b13b, 0x13b13b14, 0x3ffcd82b, 0x446159f3
	.word	0x3c983fb7, 0xb33cdfe8, 0x00000000, 0x00000000
	.word	0x3ff3b13b, 0x13b13b14, 0x40046565, 0x5f122ff6
	.word	0x3ca862c5, 0xd2f0ca4c, 0x00000000, 0x00000000
	.word	0x3ff3991c, 0x2c187f63, 0x3ffce9e5, 0xec2bda80
	.word	0xbc94ccf3, 0xd8e249ab, 0x00000000, 0x00000000
	.word	0x3ff3991c, 0x2c187f63, 0x400471ee, 0xaf76c2c6
	.word	0x3c975c62, 0xeff26e8e, 0x00000000, 0x00000000
	.word	0x3ff38138, 0x13813814, 0x3ffcfb95, 0xbb9dcc0c
	.word	0x3c92cea2, 0x0857ae03, 0x00000000, 0x00000000
	.word	0x3ff38138, 0x13813814, 0x40047e70, 0x54af0989
	.word	0x3c9d8c33, 0xc0054830, 0x00000000, 0x00000000
	.word	0x3ff3698d, 0xf3de0748, 0x3ffd0d3a, 0xc685eda4
	.word	0x3c94115a, 0x0ff4cf9e, 0x00000000, 0x00000000
	.word	0x3ff3698d, 0xf3de0748, 0x40048aea, 0x5cbc935f
	.word	0xbca8cb00, 0x12d14ff5, 0x00000000, 0x00000000
	.word	0x3ff3521c, 0xfb2b78c1, 0x3ffd1ed5, 0x2076fbe9
	.word	0x3c8f48a8, 0x6b72875f, 0x00000000, 0x00000000
	.word	0x3ff3521c, 0xfb2b78c1, 0x4004975c, 0xd5768088
	.word	0xbca1731e, 0xbc02f748, 0x00000000, 0x00000000
	.word	0x3ff33ae4, 0x5b57bcb2, 0x3ffd3064, 0xdcc8ae67
	.word	0x3c93480e, 0x805158ba, 0x00000000, 0x00000000
	.word	0x3ff33ae4, 0x5b57bcb2, 0x4004a3c7, 0xcc8a358a
	.word	0xbc9d8f7f, 0xd2726ffa, 0x00000000, 0x00000000
	.word	0x3ff323e3, 0x4a2b10bf, 0x3ffd41ea, 0x0e98af91
	.word	0x3c824640, 0x0309962f, 0x00000000, 0x00000000
	.word	0x3ff323e3, 0x4a2b10bf, 0x4004b02b, 0x4f7c0a88
	.word	0xbcaf71e1, 0xf6cafde2, 0x00000000, 0x00000000
	.word	0x3ff30d19, 0x0130d190, 0x3ffd5364, 0xc8cb8f86
	.word	0x3c8ad003, 0xc00630e1, 0x00000000, 0x00000000
	.word	0x3ff30d19, 0x0130d190, 0x4004bc87, 0x6ba7f6ec
	.word	0x3c9c1edb, 0x2be943b8, 0x00000000, 0x00000000
	.word	0x3ff2f684, 0xbda12f68, 0x3ffd64d5, 0x1e0db1c6
	.word	0xbc911ed3, 0x6986d362, 0x00000000, 0x00000000
	.word	0x3ff2f684, 0xbda12f68, 0x4004c8dc, 0x2e423980
	.word	0xbc949d1f, 0x46ef5d2c, 0x00000000, 0x00000000
	.word	0x3ff2e025, 0xc04b8097, 0x3ffd763b, 0x20d435ef
	.word	0x3c9d6780, 0xf76cb258, 0x00000000, 0x00000000
	.word	0x3ff2e025, 0xc04b8097, 0x4004d529, 0xa457fcfc
	.word	0xbca1404a, 0x46484e3d, 0x00000000, 0x00000000
	.word	0x3ff2c9fb, 0x4d812ca0, 0x3ffd8796, 0xe35ddbb2
	.word	0x3c83fdd9, 0x1aeb637a, 0x00000000, 0x00000000
	.word	0x3ff2c9fb, 0x4d812ca0, 0x4004e16f, 0xdacff937
	.word	0xbca1deb9, 0xd3815ad2, 0x00000000, 0x00000000
	.word	0x3ff2b404, 0xad012b40, 0x3ffd98e8, 0x77b3e207
	.word	0xbc48c301, 0xee02dee8, 0x00000000, 0x00000000
	.word	0x3ff2b404, 0xad012b40, 0x4004edae, 0xde6b10fe
	.word	0x3ca99709, 0x4a91a780, 0x00000000, 0x00000000
	.word	0x3ff29e41, 0x29e4129e, 0x3ffdaa2f, 0xefaae1d8
	.word	0xbc63fe0e, 0x03f44594, 0x00000000, 0x00000000
	.word	0x3ff29e41, 0x29e4129e, 0x4004f9e6, 0xbbc4ecb3
	.word	0x3c6ce5a6, 0x018493f1, 0x00000000, 0x00000000
	.word	0x3ff288b0, 0x1288b013, 0x3ffdbb6d, 0x5ce3a42f
	.word	0xbc922c27, 0xf71c8337, 0x00000000, 0x00000000
	.word	0x3ff288b0, 0x1288b013, 0x40050617, 0x7f5491bb
	.word	0xbc9e591e, 0x7b2a6d1a, 0x00000000, 0x00000000
	.word	0x3ff27350, 0xb8812735, 0x3ffdcca0, 0xd0cbf408
	.word	0x3c7a6d16, 0x2310db57, 0x00000000, 0x00000000
	.word	0x3ff27350, 0xb8812735, 0x40051241, 0x356cf6e0
	.word	0x3ca37dc2, 0x60e8bc2d, 0x00000000, 0x00000000
	.word	0x3ff25e22, 0x708092f1, 0x3ffdddca, 0x5c9f6be8
	.word	0x3c818520, 0xf0a3f809, 0x00000000, 0x00000000
	.word	0x3ff25e22, 0x708092f1, 0x40051e63, 0xea3d95b0
	.word	0x3caecf78, 0x2e88d5ce, 0x00000000, 0x00000000
	.word	0x3ff24924, 0x92492492, 0x3ffdeeea, 0x11683f49
	.word	0x3c802aae, 0x4bfa7c27, 0x00000000, 0x00000000
	.word	0x3ff24924, 0x92492492, 0x40052a7f, 0xa9d2f8ea
	.word	0xbca21c62, 0xb033c079, 0x00000000, 0x00000000
	.word	0x3ff23456, 0x789abcdf, 0x3ffe0000, 0x00000000
	.word	0x00000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ff23456, 0x789abcdf, 0x40053694, 0x80174810
	.word	0xbc9c3ec1, 0xa4ee7c21, 0x00000000, 0x00000000
	.word	0x3ff21fb7, 0x8121fb78, 0x3ffe110c, 0x39105faf
	.word	0x3c776161, 0x4c513964, 0x00000000, 0x00000000
	.word	0x3ff21fb7, 0x8121fb78, 0x400542a2, 0x78d2d036
	.word	0xbca495c2, 0x45254df4, 0x00000000, 0x00000000
	.word	0x3ff20b47, 0x0c67c0d9, 0x3ffe220e, 0xcd13ed60
	.word	0xbc729f01, 0xf18c9dc9, 0x00000000, 0x00000000
	.word	0x3ff20b47, 0x0c67c0d9, 0x40054ea9, 0x9fac8a0f
	.word	0x3c80cfbb, 0x19353b3d, 0x00000000, 0x00000000
	.word	0x3ff1f704, 0x7dc11f70, 0x3ffe3307, 0xcc56cf5c
	.word	0xbc81f04e, 0xc3189131, 0x00000000, 0x00000000
	.word	0x3ff1f704, 0x7dc11f70, 0x40055aaa, 0x002a9d5a
	.word	0xbc4bf504, 0x76241f94, 0x00000000, 0x00000000
	.word	0x3ff1e2ef, 0x3b3fb874, 0x3ffe43f7, 0x46f7795b
	.word	0xbc931e7f, 0x8af68f8c, 0x00000000, 0x00000000
	.word	0x3ff1e2ef, 0x3b3fb874, 0x400566a3, 0xa5b2e1b1
	.word	0x3caa1fd2, 0x8cc92e33, 0x00000000, 0x00000000
	.word	0x3ff1cf06, 0xada2811d, 0x3ffe54dd, 0x4ce75f1e
	.word	0xbc811b19, 0x5dfc62e5, 0x00000000, 0x00000000
	.word	0x3ff1cf06, 0xada2811d, 0x40057296, 0x9b8b5cd8
	.word	0x3ca30cbf, 0x1c53312e, 0x00000000, 0x00000000
	.word	0x3ff1bb4a, 0x4046ed29, 0x3ffe65b9, 0xedeba38e
	.word	0xbc7bb732, 0x51e8c364, 0x00000000, 0x00000000
	.word	0x3ff1bb4a, 0x4046ed29, 0x40057e82, 0xecdabe8d
	.word	0xbc7c2aed, 0xf3c4c4bd, 0x00000000, 0x00000000
	.word	0x3ff1a7b9, 0x611a7b96, 0x3ffe768d, 0x399dc470
	.word	0xbc9a8c81, 0x3405c01c, 0x00000000, 0x00000000
	.word	0x3ff1a7b9, 0x611a7b96, 0x40058a68, 0xa4a8d9f3
	.word	0x3ca50798, 0xe67012d9, 0x00000000, 0x00000000
	.word	0x3ff19453, 0x808ca29c, 0x3ffe8757, 0x3f6c42c5
	.word	0x3c9dbf9c, 0xf7bbcda3, 0x00000000, 0x00000000
	.word	0x3ff19453, 0x808ca29c, 0x40059647, 0xcddf1ca5
	.word	0x3ca14a95, 0xf35dea0b, 0x00000000, 0x00000000
	.word	0x3ff18118, 0x11811812, 0x3ffe9818, 0x0e9b47f2
	.word	0xbc9b6bd7, 0x4396d08e, 0x00000000, 0x00000000
	.word	0x3ff18118, 0x11811812, 0x4005a220, 0x73490377
	.word	0xbcadd036, 0x39925812, 0x00000000, 0x00000000
	.word	0x3ff16e06, 0x89427379, 0x3ffea8cf, 0xb64547ab
	.word	0x3c8721b2, 0x6374e19f, 0x00000000, 0x00000000
	.word	0x3ff16e06, 0x89427379, 0x4005adf2, 0x9f948cfb
	.word	0xbca42520, 0xf7716fa6, 0x00000000, 0x00000000
	.word	0x3ff15b1e, 0x5f75270d, 0x3ffeb97e, 0x455b9edb
	.word	0x3c999b45, 0x40857883, 0x00000000, 0x00000000
	.word	0x3ff15b1e, 0x5f75270d, 0x4005b9be, 0x5d52a9da
	.word	0x3c9098cd, 0x1b3af777, 0x00000000, 0x00000000
	.word	0x3ff1485f, 0x0e0acd3b, 0x3ffeca23, 0xcaa72f73
	.word	0x3c7e3ed5, 0x29679959, 0x00000000, 0x00000000
	.word	0x3ff1485f, 0x0e0acd3b, 0x4005c583, 0xb6f7ab03
	.word	0x3ca963bc, 0x9d795b51, 0x00000000, 0x00000000
	.word	0x3ff135c8, 0x1135c811, 0x3ffedac0, 0x54c8f94c
	.word	0x3c90b5c1, 0x15a56207, 0x00000000, 0x00000000
	.word	0x3ff135c8, 0x1135c811, 0x4005d142, 0xb6dbadc5
	.word	0x3ca6f1f5, 0x5323d116, 0x00000000, 0x00000000
	.word	0x3ff12358, 0xe75d3033, 0x3ffeeb53, 0xf23ab028
	.word	0xbc8617e4, 0xb5384f5d, 0x00000000, 0x00000000
	.word	0x3ff12358, 0xe75d3033, 0x4005dcfb, 0x673b05df
	.word	0xbca099df, 0xc321634f, 0x00000000, 0x00000000
	.word	0x3ff11111, 0x11111111, 0x3ffefbde, 0xb14f4eda
	.word	0xbc93a145, 0xfe1be078, 0x00000000, 0x00000000
	.word	0x3ff11111, 0x11111111, 0x4005e8ad, 0xd236a58f
	.word	0xbc7ef8c7, 0xc0d1fec6, 0x00000000, 0x00000000
	.word	0x3ff0fef0, 0x10fef011, 0x3fff0c60, 0xa033a7b3
	.word	0xbc91b0fc, 0x15cd89c6, 0x00000000, 0x00000000
	.word	0x3ff0fef0, 0x10fef011, 0x4005f45a, 0x01d483b4
	.word	0xbc94a237, 0xdc0fa105, 0x00000000, 0x00000000
	.word	0x3ff0ecf5, 0x6be69c90, 0x3fff1cd9, 0xcceef239
	.word	0x3c91afd8, 0x64eab60a, 0x00000000, 0x00000000
	.word	0x3ff0ecf5, 0x6be69c90, 0x40060000, 0x00000000
	.word	0x00000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ff0db20, 0xa88f4696, 0x3fff2d4a, 0x45635640
	.word	0xbc8eebae, 0xea670bc2, 0x00000000, 0x00000000
	.word	0x3ff0db20, 0xa88f4696, 0x40060b9f, 0xd68a4554
	.word	0x3ca328e1, 0x70dae176, 0x00000000, 0x00000000
	.word	0x3ff0c971, 0x4fbcda3b, 0x3fff3db2, 0x174e7468
	.word	0x3c9e1513, 0x2d6ac52a, 0x00000000, 0x00000000
	.word	0x3ff0c971, 0x4fbcda3b, 0x40061739, 0x8f2aaa48
	.word	0xbc9b672b, 0xba260735, 0x00000000, 0x00000000
	.word	0x3ff0b7e6, 0xec259dc8, 0x3fff4e11, 0x5049ec26
	.word	0xbc9b6656, 0xb6bd5d76, 0x00000000, 0x00000000
	.word	0x3ff0b7e6, 0xec259dc8, 0x400622cd, 0x337f0fe8
	.word	0x3c9fe207, 0x3279559f, 0x00000000, 0x00000000
	.word	0x3ff0a681, 0x0a6810a7, 0x3fff5e67, 0xfdcbdf44
	.word	0xbc98af06, 0x1849d6fc, 0x00000000, 0x00000000
	.word	0x3ff0a681, 0x0a6810a7, 0x40062e5a, 0xcd0c3ebe
	.word	0xbca2c50e, 0x2092203a, 0x00000000, 0x00000000
	.word	0x3ff0953f, 0x39010954, 0x3fff6eb6, 0x2d27730d
	.word	0xbc9401d9, 0x5ca1ce34, 0x00000000, 0x00000000
	.word	0x3ff0953f, 0x39010954, 0x400639e2, 0x653e421b
	.word	0xbc9f75e0, 0x5835e4b9, 0x00000000, 0x00000000
	.word	0x3ff08421, 0x08421084, 0x3fff7efb, 0xeb8d4f12
	.word	0xbc7e84e8, 0xa6ff3256, 0x00000000, 0x00000000
	.word	0x3ff08421, 0x08421084, 0x40064564, 0x0568c1c3
	.word	0x3cad1778, 0x7e4c8970, 0x00000000, 0x00000000
	.word	0x3ff07326, 0x0a47f7c6, 0x3fff8f39, 0x460c19a8
	.word	0x3c989b4e, 0x16ee9aaf, 0x00000000, 0x00000000
	.word	0x3ff07326, 0x0a47f7c6, 0x400650df, 0xb6c759f4
	.word	0x3c99063c, 0x91db4c77, 0x00000000, 0x00000000
	.word	0x3ff0624d, 0xd2f1a9fc, 0x3fff9f6e, 0x4990f227
	.word	0x3c8b42e5, 0xb5d1e808, 0x00000000, 0x00000000
	.word	0x3ff0624d, 0xd2f1a9fc, 0x40065c55, 0x827df1d2
	.word	0xbca3923d, 0xf03e1e2f, 0x00000000, 0x00000000
	.word	0x3ff05197, 0xf7d73404, 0x3fffaf9b, 0x02e7e8f2
	.word	0x3c897a76, 0x8f34e1c2, 0x00000000, 0x00000000
	.word	0x3ff05197, 0xf7d73404, 0x400667c5, 0x7199104b
	.word	0x3c875b89, 0x6f332e70, 0x00000000, 0x00000000
	.word	0x3ff04104, 0x10410410, 0x3fffbfbf, 0x7ebc755f
	.word	0xbc9b2a94, 0x084da0b6, 0x00000000, 0x00000000
	.word	0x3ff04104, 0x10410410, 0x4006732f, 0x8d0e2f77
	.word	0xbc93dffd, 0x470422e3, 0x00000000, 0x00000000
	.word	0x3ff03091, 0xb51f5e1a, 0x3fffcfdb, 0xc999e97d
	.word	0x3c82be17, 0xecdd3bbc, 0x00000000, 0x00000000
	.word	0x3ff03091, 0xb51f5e1a, 0x40067e93, 0xddbc0e73
	.word	0xbc86eb9f, 0x32ac1a5c, 0x00000000, 0x00000000
	.word	0x3ff02040, 0x81020408, 0x3fffdfef, 0xefebe3d6
	.word	0xbc909afc, 0xfc7c1f3b, 0x00000000, 0x00000000
	.word	0x3ff02040, 0x81020408, 0x400689f2, 0x6c6b01d0
	.word	0x3cae816f, 0x9d2a1032, 0x00000000, 0x00000000
	.word	0x3ff01010, 0x10101010, 0x3fffeffb, 0xfdfebf1f
	.word	0x3c95dee5, 0x1994f18b, 0x00000000, 0x00000000
	.word	0x3ff01010, 0x10101010, 0x4006954b, 0x41cd4293
	.word	0x3ca3d5bc, 0xcc443076, 0x00000000, 0x00000000
	.word	0x3ff00000, 0x00000000, 0x40000000, 0x00000000
	.word	0x00000000, 0x00000000, 0x00000000, 0x00000000
	.word	0x3ff00000, 0x00000000, 0x4006a09e, 0x667f3bcd
	.word	0xbcabdd34, 0x13b26456, 0x00000000, 0x00000000

#define A5		%f32
#define A4		%f30
#define A3		%f28
#define A2		%f26
#define A1		%f56

#define DC0		%f8
#define DC2		%f6
#define DC3		%f4

#define counter		%l3
#define TBL		%l5
#define stridex		%l6
#define stridey		%l7

#define _0x00001ff8	%i0
#define _0x7ff00000	%o0
#define _0x00100000	%o2

#define tmp_counter	STACK_BIAS-0x40
#define tmp_px		STACK_BIAS-0x38
#define tmp0		STACK_BIAS-0x30
#define tmp1		STACK_BIAS-0x28
#define tmp2		STACK_BIAS-0x20
#define tmp3		STACK_BIAS-0x18
#define tmp4		STACK_BIAS-0x10
#define tmp5		STACK_BIAS-0x08

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x40

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!      !!!!!   algorithm   !!!!!
!  ((float*)&res)[0] = ((float*)px)[0];
!  ((float*)&res)[1] = ((float*)px)[1];
!  hx = *(int*)px;
!  px += stridex;
!
!  if ( hx >= 0x7ff00000 )
!  {
!    res = sqrt(res);
!    ((float*)py)[0] = ((float*)&res)[0];
!    ((float*)py)[1] = ((float*)&res)[1];
!    py += stridey;
!    goto next;
!  }
!  if ( hx < 0x00100000 )
!  {
!    res = sqrt(res);
!    ((float*)py)[0] = ((float*)&res)[0];
!    ((float*)py)[1] = ((float*)&res)[1];
!    py += stridey;
!    goto next;
!  }
!
!  sqrt_exp = hx >> 21;
!  sqrt_exp -= 512;
!  sqrt_exp <<= 52;
!  dsqrt_exp = *(double*)&sqrt_exp;
!  bit = hx >> 15;
!  bit &= 32;
!  ind0 = hx >> 7;
!  ind0 &= 0x1ff8;
!  ind0 += 32;
!  ind0 &= -64;
!  ind1 = ind0;
!  ind1 += bit;
!
!  res = vis_fand(res,DC0);      /* DC0 = vis_to_double(0x000fffff, 0xffffffff); */
!  res = vis_for(res,A1);        /* A1  = vis_to_double(0x3fe00000, 0x00000000); */
!  res_c = vis_fpadd32(res,DC2); /* DC2 = vis_to_double(0x00001000, 0x00000000); */
!  res_c = vis_fand(res_c,DC3);  /* DC3 = vis_to_double(0x7fffe000, 0x00000000); */
!
!  pind = (char*)TBL + ind1;
!  dexp_hi = ((double*)pind)[1];
!  dexp_lo = ((double*)pind)[2];
!
!  dtmp0 = ((double*)pind)[0];
!  xx = (res - res_c);
!  xx *= dtmp0;
!
!  res = A5 * xx;
!  res += A4;
!  res *= xx;
!  res += A3;
!  res *= xx;
!  res += A2;
!  res *= xx;
!  res += A1;
!  res *= xx;
!
!  res = dexp_hi * res;
!  res += dexp_lo;
!  res += dexp_hi;
!
!  dtmp0 = vis_fpadd32(dsqrt_exp,res);
!  ((float*)py)[0] = ((float*)&dtmp0)[0];
!  ((float*)py)[1] = ((float*)&dtmp0)[1];
!  py += stridey;
!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	ENTRY(__vsqrt)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,l5)
	wr	%g0,0x82,%asi

	ldd	[TBL],A1
	sll	%i2,3,stridex
	or	%g0,%i3,%o4

	ldd	[TBL+8],A2
	sll	%i4,3,stridey
	or	%g0,0x7ff,%o0

	ldd	[TBL+16],A3
	sll	%o0,20,_0x7ff00000
	or	%g0,0x001,%o2

	ldd	[TBL+24],A4
	sll	%o2,20,_0x00100000

	ldd	[TBL+32],A5
	ldd	[TBL+40],DC0
	ldd	[TBL+48],DC2
	ldd	[TBL+56],DC3

	add	TBL,64,TBL
	add	%g0,1023,%o5
	st	%i0,[%fp+tmp_counter]

	sll	%o5,3,_0x00001ff8
	stx	%i1,[%fp+tmp_px]

.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%l2
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit
	lda	[%l2]%asi,%o5		! (5_1) hx = *(int*)px;

	lda	[%l2]%asi,%f10		! (5_0) ((float*)&res)[0] = ((float*)px)[0];

	lda	[%l2+4]%asi,%f11	! (5_0) ((float*)&res)[1] = ((float*)px)[1];

	cmp	%o5,_0x7ff00000		! (5_1) hx ? 0x7ff00000
	bge,pn	%icc,.spec		! (5_1) if ( hx >= 0x7ff00000 )
	nop

	cmp	%o5,_0x00100000		! (5_1) hx ? 0x00100000
	bl,pn	%icc,.spec		! (5_1) if ( hx < 0x00100000 )
	nop

	add	%l2,stridex,%l2		! px += stridex
	fand	%f10,DC0,%f50		! (5_1) res = vis_fand(res,DC0);

	for	%f50,A1,%f40		! (5_1) res = vis_for(res,A1);
	sra	%o5,21,%l1		! (5_1) sqrt_exp = hx >> 21;
	sra	%o5,15,%i1		! (5_1) bit = hx >> 15;

	sra	%o5,7,%o1		! (5_1) ind0 = hx >> 7;
	sub	%l1,512,%o3		! (5_1) sqrt_exp -= 512;

	and	%o1,_0x00001ff8,%o1	! (5_1) ind0 &= 0x1ff8;
	lda	[%l2]%asi,%f10		! (0_0) ((float*)&res)[0] = ((float*)px)[0];

	add	%o1,32,%o1		! (5_1) ind0 += 32;
	lda	[%l2+4]%asi,%f11	! (0_0) ((float*)&res)[1] = ((float*)px)[1];

	and	%i1,32,%i4		! (5_1) bit &= 32;
	and	%o1,-64,%o1		! (5_1) ind0 &= -8;

	sll	%o1,0,%o7		! (5_1) ind1 = ind0;

	sllx	%o3,52,%o3		! (5_1) sqrt_exp <<= 52;
	add	%o7,%i4,%l0		! (5_1) ind1 += bit;
	lda	[%l2]%asi,%o5		! (0_0) hx = *(int*)px;

	stx	%o3,[%fp+tmp0]		! (5_1) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (0_0) res = vis_fand(res,DC0);

	add	%l2,stridex,%l2		! px += stridex
	fpadd32	%f40,DC2,%f54		! (5_1) res_c = vis_fpadd32(res,DC2);

	add	%l0,TBL,%o1		! (5_1) pind = (char*)TBL + ind1

	cmp	%o5,_0x7ff00000		! (0_0) hx ? 0x7ff00000
	bge,pn	%icc,.update0		! (0_0) if ( hx >= 0x7ff00000 )
	for	%f50,A1,%f42		! (0_0) res = vis_for(res,A1);
.cont0:
	sra	%o5,21,%l1		! (0_0) sqrt_exp = hx >> 21;
	sra	%o5,15,%i2		! (0_0) bit = hx >> 15;
	ldd	[%o1],%f50		! (5_1) dtmp0 = ((double*)pind)[0];

	sra	%o5,7,%o1		! (0_0) ind0 = hx >> 7;
	sub	%l1,512,%o3		! (0_0) sqrt_exp -= 512;
	fand	%f54,DC3,%f54		! (5_1) res_c = vis_fand(res_c,DC3);

	and	%o1,_0x00001ff8,%o1	! (0_0) ind0 &= 0x1ff8;
	lda	[%l2]%asi,%f10		! (1_0) ((float*)&res)[0] = ((float*)px)[0];

	add	%o1,32,%o1		! (0_0) ind0 += 32;
	lda	[%l2+4]%asi,%f11	! (1_0) ((float*)&res)[1] = ((float*)px)[1];

	and	%i2,32,%i4		! (0_0) bit &= 32;
	and	%o1,-64,%o1		! (0_0) ind0 &= -8;
	fsubd	%f40,%f54,%f40		! (5_1) xx = (res - res_c);

	sll	%o1,0,%o7		! (0_0) ind1 = ind0;

	cmp	%o5,_0x00100000		! (0_0) hx ? 0x00100000
	bl,pn	%icc,.update1		! (0_0) if ( hx < 0x00100000 )
	lda	[%l2]%asi,%o5		! (1_0) hx = *(int*)px;
.cont1:
	sllx	%o3,52,%o3		! (0_0) sqrt_exp <<= 52;
	add	%o7,%i4,%i1		! (0_0) ind1 += bit;

	fmuld	%f40,%f50,%f40		! (5_1) xx *= dtmp0;
	stx	%o3,[%fp+tmp1]		! (0_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (1_0) res = vis_fand(res,DC0);

	add	%l2,stridex,%l2		! px += stridex
	fpadd32	%f42,DC2,%f54		! (0_0) res_c = vis_fpadd32(res,DC2);

	add	%i1,TBL,%o1		! (0_0) pind = (char*)TBL + ind1

	cmp	%o5,_0x7ff00000		! (1_0) hx ? 0x7ff00000
	bge,pn	%icc,.update2		! (1_0) if ( hx >= 0x7ff00000 )
	for	%f50,A1,%f14		! (1_0) res = vis_for(res,A1);
.cont2:
	sra	%o5,21,%l1		! (1_0) sqrt_exp = hx >> 21;
	sra	%o5,15,%g5		! (1_0) bit = hx >> 15;
	ldd	[%o1],%f50		! (0_0) dtmp0 = ((double*)pind)[0];

	fmuld	A5,%f40,%f52		! (5_1) res = A5 * xx;
	sra	%o5,7,%o1		! (1_0) ind0 = hx >> 7;
	sub	%l1,512,%o3		! (1_0) sqrt_exp -= 512;
	fand	%f54,DC3,%f54		! (0_0) res_c = vis_fand(res_c,DC3);

	and	%o1,_0x00001ff8,%o1	! (1_0) ind0 &= 0x1ff8;
	lda	[%l2]%asi,%f10		! (2_0) ((float*)&res)[0] = ((float*)px)[0];

	add	%o1,32,%o1		! (1_0) ind0 += 32;
	lda	[%l2+4]%asi,%f11	! (2_0) ((float*)&res)[1] = ((float*)px)[1];

	and	%g5,32,%i4		! (1_0) bit &= 32;
	and	%o1,-64,%o1		! (1_0) ind0 &= -8;
	fsubd	%f42,%f54,%f42		! (0_0) xx = (res - res_c);

	sll	%o1,0,%o7		! (1_0) ind1 = ind0;
	faddd	%f52,A4,%f54		! (5_1) res += A4;

	cmp	%o5,_0x00100000		! (1_0) hx ? 0x00100000
	bl,pn	%icc,.update3		! (1_0) if ( hx < 0x00100000 )
	lda	[%l2]%asi,%o5		! (2_0) hx = *(int*)px;
.cont3:
	sllx	%o3,52,%o3		! (1_0) sqrt_exp <<= 52;
	add	%o7,%i4,%i2		! (1_0) ind1 += bit;

	fmuld	%f42,%f50,%f42		! (0_0) xx *= dtmp0;
	stx	%o3,[%fp+tmp2]		! (1_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (2_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f40,%f34		! (5_1) res *= xx;
	fpadd32	%f14,DC2,%f54		! (1_0) res_c = vis_fpadd32(res,DC2);
	add	%l2,stridex,%l2		! px += stridex

	add	%i2,TBL,%o1		! (1_0) pind = (char*)TBL + ind1

	cmp	%o5,_0x7ff00000		! (2_0) hx ? 0x7ff00000
	bge,pn	%icc,.update4		! (2_0) if ( hx >= 0x7ff00000 )
	for	%f50,A1,%f18		! (2_0) res = vis_for(res,A1);
.cont4:
	sra	%o5,21,%l1		! (2_0) sqrt_exp = hx >> 21;
	sra	%o5,15,%g1		! (2_0) bit = hx >> 15;
	ldd	[%o1],%f50		! (1_0) dtmp0 = ((double*)pind)[0];

	fmuld	A5,%f42,%f52		! (0_0) res = A5 * xx;
	sra	%o5,7,%o1		! (2_0) ind0 = hx >> 7;
	sub	%l1,512,%o3		! (2_0) sqrt_exp -= 512;
	fand	%f54,DC3,%f54		! (1_0) res_c = vis_fand(res_c,DC3);

	and	%o1,_0x00001ff8,%o1	! (2_0) ind0 &= 0x1ff8;
	lda	[%l2]%asi,%f10		! (3_0) ((float*)&res)[0] = ((float*)px)[0];
	faddd	%f34,A3,%f62		! (5_1) res += A3;

	add	%o1,32,%o1		! (2_0) ind0 += 32;
	lda	[%l2+4]%asi,%f11	! (3_0) ((float*)&res)[1] = ((float*)px)[1];

	and	%g1,32,%i4		! (2_0) bit &= 32;
	and	%o1,-64,%o1		! (2_0) ind0 &= -8;
	fsubd	%f14,%f54,%f14		! (1_0) xx = (res - res_c);

	sll	%o1,0,%o7		! (2_0) ind1 = ind0;
	faddd	%f52,A4,%f54		! (0_0) res += A4;

	fmuld	%f62,%f40,%f52		! (5_1) res *= xx;
	cmp	%o5,_0x00100000		! (2_0) hx ? 0x00100000
	bl,pn	%icc,.update5		! (2_0) if ( hx < 0x00100000 )
	lda	[%l2]%asi,%o5		! (3_0) hx = *(int*)px;
.cont5:
	sllx	%o3,52,%o3		! (2_0) sqrt_exp <<= 52;
	add	%o7,%i4,%g5		! (2_0) ind1 += bit;

	fmuld	%f14,%f50,%f14		! (1_0) xx *= dtmp0;
	stx	%o3,[%fp+tmp3]		! (2_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (3_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f42,%f34		! (0_0) res *= xx;
	fpadd32	%f18,DC2,%f54		! (2_0) res_c = vis_fpadd32(res,DC2);
	add	%l2,stridex,%l2		! px += stridex

	add	%g5,TBL,%o1		! (2_0) pind = (char*)TBL + ind1
	faddd	%f52,A2,%f20		! (5_1) res += A2;

	cmp	%o5,_0x7ff00000		! (3_0) hx ? 0x7ff00000
	bge,pn	%icc,.update6		! (3_0) if ( hx >= 0x7ff00000 )
	for	%f50,A1,%f44		! (3_0) res = vis_for(res,A1);
.cont6:
	sra	%o5,21,%l1		! (3_0) sqrt_exp = hx >> 21;
	sra	%o5,15,%i3		! (3_0) bit = hx >> 15;
	ldd	[%o1],%f50		! (2_0) dtmp0 = ((double*)pind)[0];

	fmuld	A5,%f14,%f52		! (1_0) res = A5 * xx;
	sra	%o5,7,%o1		! (3_0) ind0 = hx >> 7;
	sub	%l1,512,%o3		! (3_0) sqrt_exp -= 512;
	fand	%f54,DC3,%f54		! (2_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f40,%f20		! (5_1) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (3_0) ind0 &= 0x1ff8;
	lda	[%l2]%asi,%f10		! (4_0) ((float*)&res)[0] = ((float*)px)[0];
	faddd	%f34,A3,%f62		! (0_0) res += A3;

	add	%o1,32,%o1		! (3_0) ind0 += 32;
	lda	[%l2+4]%asi,%f11	! (4_0) ((float*)&res)[1] = ((float*)px)[1];

	and	%i3,32,%i4		! (3_0) bit &= 32;
	and	%o1,-64,%o1		! (3_0) ind0 &= -8;
	fsubd	%f18,%f54,%f18		! (2_0) xx = (res - res_c);

	sll	%o1,0,%o7		! (3_0) ind1 = ind0;
	faddd	%f52,A4,%f54		! (1_0) res += A4;

	fmuld	%f62,%f42,%f52		! (0_0) res *= xx;
	cmp	%o5,_0x00100000		! (3_0) hx ? 0x00100000
	bl,pn	%icc,.update7		! (3_0) if ( hx < 0x00100000 )
	faddd	%f20,A1,%f12		! (5_1) res += A1;
.cont7:
	lda	[%l2]%asi,%o5		! (4_0) hx = *(int*)px;
	sllx	%o3,52,%o3		! (3_0) sqrt_exp <<= 52;
	add	%o7,%i4,%g1		! (3_0) ind1 += bit;

	fmuld	%f18,%f50,%f18		! (2_0) xx *= dtmp0;
	add	%l0,TBL,%l0		! (5_1) pind = (char*)TBL + ind1;
	stx	%o3,[%fp+tmp4]		! (3_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (4_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f14,%f34		! (1_0) res *= xx;
	add	%l2,stridex,%l2		! px += stridex
	ldd	[%l0+16],%f36		! (5_1) dexp_lo = ((double*)pind)[2];
	fpadd32	%f44,DC2,%f54		! (3_0) res_c = vis_fpadd32(res,DC2);

	fmuld	%f12,%f40,%f12		! (5_1) res *= xx;
	add	%g1,TBL,%o1		! (3_0) (char*)div_arr+ind0
	ldd	[%l0+8],%f40		! (5_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (0_0) res += A2;

	cmp	%o5,_0x7ff00000		! (4_0) hx ? 0x7ff00000
	bge,pn	%icc,.update8		! (4_0) if ( hx >= 0x7ff00000 )
	for	%f50,A1,%f24		! (4_0) res = vis_for(res,A1);
.cont8:
	sra	%o5,21,%l1		! (4_0) sqrt_exp = hx >> 21;
	sra	%o5,15,%l0		! (4_0) bit = hx >> 15;
	ldd	[%o1],%f22		! (3_0) dtmp0 = ((double*)pind)[0];

	fmuld	A5,%f18,%f52		! (2_0) res = A5 * xx;
	sra	%o5,7,%o1		! (4_0) ind0 = hx >> 7;
	sub	%l1,512,%o3		! (4_0) sqrt_exp -= 512;
	fand	%f54,DC3,%f54		! (3_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f42,%f20		! (0_0) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (4_0) ind0 &= 0x1ff8;
	lda	[%l2]%asi,%f10		! (5_0) ((float*)&res)[0] = ((float*)px)[0];
	faddd	%f34,A3,%f62		! (1_0) res += A3;

	fmuld	%f40,%f12,%f34		! (5_1) res = dexp_hi * res;
	add	%o1,32,%o1		! (4_0) ind0 += 32;
	lda	[%l2+4]%asi,%f11	! (5_0) ((float*)&res)[1] = ((float*)px)[1];

	and	%l0,32,%i4		! (4_0) bit &= 32;
	cmp	%o5,_0x00100000		! (4_0) hx ? 0x00100000
	bl,pn	%icc,.update9		! (4_0) if ( hx < 0x00100000 )
	fsubd	%f44,%f54,%f44		! (3_0) xx = (res - res_c);
.cont9:
	and	%o1,-64,%o1		! (4_0) ind0 &= -8;
	faddd	%f52,A4,%f54		! (2_0) res += A4;

	cmp	counter,6
	bl,pn	%icc,.tail
	or	%g0,%o4,%l0

	ba	.main_loop
	nop

	.align	16
.main_loop:
	fmuld	%f62,%f14,%f52		! (1_1) res *= xx;
	sll	%o1,0,%i3		! (4_1) ind1 = ind0;
	add	%i1,TBL,%i1		! (0_1) pind = (char*)TBL + ind1;
	faddd	%f20,A1,%f12		! (0_1) res += A1;

	lda	[%l2]%asi,%o5		! (5_1) hx = *(int*)px;
	sllx	%o3,52,%o3		! (4_1) sqrt_exp <<= 52;
	add	%i3,%i4,%i3		! (4_1) ind1 += bit;
	faddd	%f34,%f36,%f60		! (5_2) res += dexp_lo;

	fmuld	%f44,%f22,%f44		! (3_1) xx *= dtmp0;
	add	%l2,stridex,%l2		! px += stridex
	stx	%o3,[%fp+tmp5]		! (4_1) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (5_1) res = vis_fand(res,DC0);

	fmuld	%f54,%f18,%f34		! (2_1) res *= xx;
	nop
	ldd	[%i1+16],%f36		! (0_1) dexp_lo = ((double*)pind)[2];
	fpadd32	%f24,DC2,%f54		! (4_1) res_c = vis_fpadd32(res,DC2);

	fmuld	%f12,%f42,%f16		! (0_1) res *= xx;
	sra	%o5,21,%l1		! (5_1) sqrt_exp = hx >> 21;
	ldd	[%i1+8],%f42		! (0_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (1_1) res += A2;

	ldd	[%fp+tmp0],%f48		! (5_2) dsqrt_exp = *(double*)&sqrt_exp;
	cmp	%o5,_0x7ff00000		! (5_1) hx ? 0x7ff00000
	bge,pn	%icc,.update10		! (5_1) if ( hx >= 0x7ff00000 )
	faddd	%f60,%f40,%f60		! (5_2) res += dexp_hi;
.cont10:
	lda	[%l2]%asi,%f10		! (0_0) ((float*)&res)[0] = ((float*)px)[0];
	sra	%o5,15,%i1		! (5_1) bit = hx >> 15;
	add	%i3,TBL,%o7		! (4_1) pind = (char*)TBL + ind1
	for	%f50,A1,%f40		! (5_1) res = vis_for(res,A1);

	fmuld	A5,%f44,%f52		! (3_1) res = A5 * xx;
	sra	%o5,7,%o1		! (5_1) ind0 = hx >> 7;
	ldd	[%o7],%f22		! (4_1) dtmp0 = ((double*)pind)[0];
	fand	%f54,DC3,%f54		! (4_1) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f14,%f20		! (1_1) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (5_1) ind0 &= 0x1ff8;
	sub	%l1,512,%o3		! (5_1) sqrt_exp -= 512;
	faddd	%f34,A3,%f62		! (2_1) res += A3;

	fpadd32	%f48,%f60,%f12		! (5_2) dtmp0 = vis_fpadd32(dsqrt_exp,res);
	add	%o1,32,%o1		! (5_1) ind0 += 32;
	st	%f12,[%l0]		! (5_2) ((float*)py)[0] = ((float*)&dtmp0)[0];
	fmuld	%f42,%f16,%f34		! (0_1) res = dexp_hi * res;

	lda	[%l2+4]%asi,%f11	! (0_0) ((float*)&res)[1] = ((float*)px)[1];
	and	%i1,32,%i4		! (5_1) bit &= 32;
	and	%o1,-64,%o1		! (5_1) ind0 &= -8;
	fsubd	%f24,%f54,%f24		! (4_1) xx = (res - res_c);

	sll	%o1,0,%o7		! (5_1) ind1 = ind0;
	add	%l0,stridey,%i1		! py += stridey
	st	%f13,[%l0+4]		! (5_2) ((float*)py)[1] = ((float*)&dtmp0)[1];
	faddd	%f52,A4,%f54		! (3_1) res += A4;

	fmuld	%f62,%f18,%f52		! (2_1) res *= xx;
	cmp	%o5,_0x00100000		! (5_1) hx ? 0x00100000
	bl,pn	%icc,.update11		! (5_1) if ( hx < 0x00100000 )
	faddd	%f20,A1,%f12		! (1_1) res += A1;
.cont11:
	sllx	%o3,52,%o3		! (5_1) sqrt_exp <<= 52;
	add	%o7,%i4,%l0		! (5_1) ind1 += bit;
	lda	[%l2]%asi,%o5		! (0_0) hx = *(int*)px;
	faddd	%f34,%f36,%f60		! (0_1) res += dexp_lo;

	fmuld	%f24,%f22,%f24		! (4_1) xx *= dtmp0;
	add	%i2,TBL,%i2		! (1_1) pind = (char*)TBL + ind1;
	stx	%o3,[%fp+tmp0]		! (5_1) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (0_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f44,%f34		! (3_1) res *= xx;
	add	%l2,stridex,%l2		! px += stridex
	ldd	[%i2+16],%f36		! (1_1) dexp_lo = ((double*)pind)[2];
	fpadd32	%f40,DC2,%f54		! (5_1) res_c = vis_fpadd32(res,DC2);

	fmuld	%f12,%f14,%f16		! (1_1) res *= xx;
	sra	%o5,21,%l1		! (0_0) sqrt_exp = hx >> 21;
	ldd	[%i2+8],%f14		! (1_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (2_1) res += A2;

	ldd	[%fp+tmp1],%f48		! (0_1) dsqrt_exp = *(double*)&sqrt_exp;
	cmp	%o5,_0x7ff00000		! (0_0) hx ? 0x7ff00000
	bge,pn	%icc,.update12		! (0_0) if ( hx >= 0x7ff00000 )
	faddd	%f60,%f42,%f60		! (0_1) res += dexp_hi;
.cont12:
	lda	[%l2]%asi,%f10		! (1_0) ((float*)&res)[0] = ((float*)px)[0];
	sra	%o5,15,%i2		! (0_0) bit = hx >> 15;
	add	%l0,TBL,%o7		! (5_1) pind = (char*)TBL + ind1
	for	%f50,A1,%f42		! (0_0) res = vis_for(res,A1);

	fmuld	A5,%f24,%f52		! (4_1) res = A5 * xx;
	sra	%o5,7,%o1		! (0_0) ind0 = hx >> 7;
	ldd	[%o7],%f22		! (5_1) dtmp0 = ((double*)pind)[0];
	fand	%f54,DC3,%f54		! (5_1) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f18,%f20		! (2_1) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (0_0) ind0 &= 0x1ff8;
	sub	%l1,512,%o3		! (0_0) sqrt_exp -= 512;
	faddd	%f34,A3,%f62		! (3_1) res += A3;

	fpadd32	%f48,%f60,%f12		! (0_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);
	add	%o1,32,%o1		! (0_0) ind0 += 32;
	st	%f12,[%i1]		! (0_1) ((float*)py)[0] = ((float*)&dtmp0)[0];
	fmuld	%f14,%f16,%f34		! (1_1) res = dexp_hi * res;

	lda	[%l2+4]%asi,%f11	! (1_0) ((float*)&res)[1] = ((float*)px)[1];
	and	%i2,32,%i4		! (0_0) bit &= 32;
	and	%o1,-64,%o1		! (0_0) ind0 &= -8;
	fsubd	%f40,%f54,%f40		! (5_1) xx = (res - res_c);

	sll	%o1,0,%o7		! (0_0) ind1 = ind0;
	add	%i1,stridey,%i2		! py += stridey
	st	%f13,[%i1+4]		! (0_1) ((float*)py)[1] = ((float*)&dtmp0)[1];
	faddd	%f52,A4,%f54		! (4_1) res += A4;

	fmuld	%f62,%f44,%f52		! (3_1) res *= xx;
	cmp	%o5,_0x00100000		! (0_0) hx ? 0x00100000
	bl,pn	%icc,.update13		! (0_0) if ( hx < 0x00100000 )
	faddd	%f20,A1,%f12		! (2_1) res += A1;
.cont13:
	lda	[%l2]%asi,%o5		! (1_0) hx = *(int*)px;
	sllx	%o3,52,%o3		! (0_0) sqrt_exp <<= 52;
	add	%o7,%i4,%i1		! (0_0) ind1 += bit;
	faddd	%f34,%f36,%f60		! (1_1) res += dexp_lo;

	fmuld	%f40,%f22,%f40		! (5_1) xx *= dtmp0;
	add	%g5,TBL,%g5		! (2_1) pind = (char*)TBL + ind1;
	stx	%o3,[%fp+tmp1]		! (0_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (1_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f24,%f34		! (4_1) res *= xx;
	add	%l2,stridex,%l2		! px += stridex
	ldd	[%g5+16],%f36		! (2_1) dexp_lo = ((double*)pind)[2];
	fpadd32	%f42,DC2,%f54		! (0_0) res_c = vis_fpadd32(res,DC2);

	fmuld	%f12,%f18,%f16		! (2_1) res *= xx;
	sra	%o5,21,%l1		! (1_0) sqrt_exp = hx >> 21;
	ldd	[%g5+8],%f18		! (2_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (3_1) res += A2;

	ldd	[%fp+tmp2],%f48		! (1_1) dsqrt_exp = *(double*)&sqrt_exp;
	cmp	%o5,_0x7ff00000		! (1_0) hx ? 0x7ff00000
	bge,pn	%icc,.update14		! (1_0) if ( hx >= 0x7ff00000 )
	faddd	%f60,%f14,%f60		! (1_1) res += dexp_hi;
.cont14:
	lda	[%l2]%asi,%f10		! (2_0) ((float*)&res)[0] = ((float*)px)[0];
	sra	%o5,15,%g5		! (1_0) bit = hx >> 15;
	add	%i1,TBL,%o7		! (0_0) pind = (char*)TBL + ind1
	for	%f50,A1,%f14		! (1_0) res = vis_for(res,A1);

	fmuld	A5,%f40,%f52		! (5_1) res = A5 * xx;
	sra	%o5,7,%o1		! (1_0) ind0 = hx >> 7;
	ldd	[%o7],%f22		! (0_0) dtmp0 = ((double*)pind)[0];
	fand	%f54,DC3,%f54		! (0_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f44,%f20		! (3_1) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (1_0) ind0 &= 0x1ff8;
	sub	%l1,512,%o3		! (1_0) sqrt_exp -= 512;
	faddd	%f34,A3,%f62		! (4_1) res += A3;

	fpadd32	%f48,%f60,%f12		! (1_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);
	add	%o1,32,%o1		! (1_0) ind0 += 32;
	st	%f12,[%i2]		! (1_1) ((float*)py)[0] = ((float*)&dtmp0)[0];
	fmuld	%f18,%f16,%f34		! (2_1) res = dexp_hi * res;

	lda	[%l2+4]%asi,%f11	! (2_0) ((float*)&res)[1] = ((float*)px)[1];
	and	%g5,32,%i4		! (1_0) bit &= 32;
	and	%o1,-64,%o1		! (1_0) ind0 &= -8;
	fsubd	%f42,%f54,%f42		! (0_0) xx = (res - res_c);

	sll	%o1,0,%o7		! (1_0) ind1 = ind0;
	add	%i2,stridey,%g5		! py += stridey
	st	%f13,[%i2+4]		! (1_1) ((float*)py)[1] = ((float*)&dtmp0)[1];
	faddd	%f52,A4,%f54		! (5_1) res += A4;

	fmuld	%f62,%f24,%f52		! (4_1) res *= xx;
	cmp	%o5,_0x00100000		! (1_0) hx ? 0x00100000
	bl,pn	%icc,.update15		! (1_0) if ( hx < 0x00100000 )
	faddd	%f20,A1,%f12		! (3_1) res += A1;
.cont15:
	lda	[%l2]%asi,%o5		! (2_0) hx = *(int*)px;
	sllx	%o3,52,%o3		! (1_0) sqrt_exp <<= 52;
	add	%o7,%i4,%i2		! (1_0) ind1 += bit;
	faddd	%f34,%f36,%f60		! (2_1) res += dexp_lo;

	fmuld	%f42,%f22,%f42		! (0_0) xx *= dtmp0;
	add	%g1,TBL,%g1		! (3_1) pind = (char*)TBL + ind1;
	stx	%o3,[%fp+tmp2]		! (1_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (2_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f40,%f34		! (5_1) res *= xx;
	fpadd32	%f14,DC2,%f54		! (1_0) res_c = vis_fpadd32(res,DC2);
	add	%l2,stridex,%l2		! px += stridex
	ldd	[%g1+16],%f36		! (3_1) dexp_lo = ((double*)pind)[2];

	fmuld	%f12,%f44,%f16		! (3_1) res *= xx;
	sra	%o5,21,%l1		! (2_0) sqrt_exp = hx >> 21;
	ldd	[%g1+8],%f44		! (3_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (4_1) res += A2;

	ldd	[%fp+tmp3],%f48		! (2_1) dsqrt_exp = *(double*)&sqrt_exp;
	cmp	%o5,_0x7ff00000		! (2_0) hx ? 0x7ff00000
	bge,pn	%icc,.update16		! (2_0) if ( hx >= 0x7ff00000 )
	faddd	%f60,%f18,%f60		! (2_1) res += dexp_hi;
.cont16:
	lda	[%l2]%asi,%f10		! (3_0) ((float*)&res)[0] = ((float*)px)[0];
	sra	%o5,15,%g1		! (2_0) bit = hx >> 15;
	add	%i2,TBL,%o7		! (1_0) pind = (char*)TBL + ind1
	for	%f50,A1,%f18		! (2_0) res = vis_for(res,A1);

	fmuld	A5,%f42,%f52		! (0_0) res = A5 * xx;
	sra	%o5,7,%o1		! (2_0) ind0 = hx >> 7;
	ldd	[%o7],%f22		! (1_0) dtmp0 = ((double*)pind)[0];
	fand	%f54,DC3,%f54		! (1_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f24,%f20		! (4_1) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (2_0) ind0 &= 0x1ff8;
	sub	%l1,512,%o3		! (2_0) sqrt_exp -= 512;
	faddd	%f34,A3,%f62		! (5_1) res += A3;

	fpadd32	%f48,%f60,%f12		! (2_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);
	add	%o1,32,%o1		! (2_0) ind0 += 32;
	st	%f12,[%g5]		! (2_1) ((float*)py)[0] = ((float*)&dtmp0)[0];
	fmuld	%f44,%f16,%f34		! (3_1) res = dexp_hi * res;

	lda	[%l2+4]%asi,%f11	! (3_0) ((float*)&res)[1] = ((float*)px)[1];
	and	%g1,32,%i4		! (2_0) bit &= 32;
	and	%o1,-64,%o1		! (2_0) ind0 &= -8;
	fsubd	%f14,%f54,%f14		! (1_0) xx = (res - res_c);

	sll	%o1,0,%o7		! (2_0) ind1 = ind0;
	add	%g5,stridey,%g1		! py += stridey
	st	%f13,[%g5+4]		! (2_1) ((float*)py)[1] = ((float*)&dtmp0)[1];
	faddd	%f52,A4,%f54		! (0_0) res += A4;

	fmuld	%f62,%f40,%f52		! (5_1) res *= xx;
	cmp	%o5,_0x00100000		! (2_0) hx ? 0x00100000
	bl,pn	%icc,.update17		! (2_0) if ( hx < 0x00100000 )
	faddd	%f20,A1,%f12		! (4_1) res += A1;
.cont17:
	lda	[%l2]%asi,%o5		! (3_0) hx = *(int*)px;
	sllx	%o3,52,%o3		! (2_0) sqrt_exp <<= 52;
	add	%o7,%i4,%g5		! (2_0) ind1 += bit;
	faddd	%f34,%f36,%f60		! (3_1) res += dexp_lo;

	fmuld	%f14,%f22,%f14		! (1_0) xx *= dtmp0;
	add	%i3,TBL,%i3		! (4_1) pind = (char*)TBL + ind1;
	stx	%o3,[%fp+tmp3]		! (2_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (3_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f42,%f34		! (0_0) res *= xx;
	fpadd32	%f18,DC2,%f54		! (2_0) res_c = vis_fpadd32(res,DC2);
	add	%l2,stridex,%l2		! px += stridex
	ldd	[%i3+16],%f36		! (4_1) dexp_lo = ((double*)pind)[2];

	fmuld	%f12,%f24,%f16		! (4_1) res *= xx;
	sra	%o5,21,%l1		! (3_0) sqrt_exp = hx >> 21;
	ldd	[%i3+8],%f24		! (4_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (5_1) res += A2;

	ldd	[%fp+tmp4],%f48		! (3_1) dsqrt_exp = *(double*)&sqrt_exp;
	cmp	%o5,_0x7ff00000		! (3_0) hx ? 0x7ff00000
	bge,pn	%icc,.update18		! (3_0) if ( hx >= 0x7ff00000 )
	faddd	%f60,%f44,%f60		! (3_1) res += dexp_hi;
.cont18:
	lda	[%l2]%asi,%f10		! (4_0) ((float*)&res)[0] = ((float*)px)[0];
	sra	%o5,15,%i3		! (3_0) bit = hx >> 15;
	add	%g5,TBL,%o7		! (2_0) pind = (char*)TBL + ind1
	for	%f50,A1,%f44		! (3_0) res = vis_for(res,A1);

	fmuld	A5,%f14,%f52		! (1_0) res = A5 * xx;
	sra	%o5,7,%o1		! (3_0) ind0 = hx >> 7;
	ldd	[%o7],%f22		! (2_0) dtmp0 = ((double*)pind)[0];
	fand	%f54,DC3,%f54		! (2_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f40,%f20		! (5_1) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (3_0) ind0 &= 0x1ff8;
	sub	%l1,512,%o3		! (3_0) sqrt_exp -= 512;
	faddd	%f34,A3,%f62		! (0_0) res += A3;

	fpadd32	%f48,%f60,%f12		! (3_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);
	add	%o1,32,%o1		! (3_0) ind0 += 32;
	st	%f12,[%g1]		! (3_1) ((float*)py)[0] = ((float*)&dtmp0)[0];
	fmuld	%f24,%f16,%f34		! (4_1) res = dexp_hi * res;

	lda	[%l2+4]%asi,%f11	! (4_0) ((float*)&res)[1] = ((float*)px)[1];
	and	%i3,32,%i4		! (3_0) bit &= 32;
	and	%o1,-64,%o1		! (3_0) ind0 &= -8;
	fsubd	%f18,%f54,%f18		! (2_0) xx = (res - res_c);

	or	%g0,%o1,%o7		! (3_0) ind1 = ind0;
	add	%g1,stridey,%i3		! py += stridey
	st	%f13,[%g1+4]		! (3_1) ((float*)py)[1] = ((float*)&dtmp0)[1];
	faddd	%f52,A4,%f54		! (1_0) res += A4;

	fmuld	%f62,%f42,%f52		! (0_0) res *= xx;
	cmp	%o5,_0x00100000		! (3_0) hx ? 0x00100000
	bl,pn	%icc,.update19		! (3_0) if ( hx < 0x00100000 )
	faddd	%f20,A1,%f12		! (5_1) res += A1;
.cont19:
	lda	[%l2]%asi,%o5		! (4_0) hx = *(int*)px;
	sllx	%o3,52,%o3		! (3_0) sqrt_exp <<= 52;
	add	%o7,%i4,%g1		! (3_0) ind1 += bit;
	faddd	%f34,%f36,%f60		! (4_1) res += dexp_lo;

	fmuld	%f18,%f22,%f18		! (2_0) xx *= dtmp0;
	add	%l0,TBL,%l0		! (5_1) pind = (char*)TBL + ind1;
	stx	%o3,[%fp+tmp4]		! (3_0) dsqrt_exp = *(double*)&sqrt_exp;
	fand	%f10,DC0,%f50		! (4_0) res = vis_fand(res,DC0);

	fmuld	%f54,%f14,%f34		! (1_0) res *= xx;
	add	%l2,stridex,%l2		! px += stridex
	ldd	[%l0+16],%f36		! (5_1) dexp_lo = ((double*)pind)[2];
	fpadd32	%f44,DC2,%f54		! (3_0) res_c = vis_fpadd32(res,DC2);

	fmuld	%f12,%f40,%f16		! (5_1) res *= xx;
	sra	%o5,21,%l1		! (4_0) sqrt_exp = hx >> 21;
	ldd	[%l0+8],%f40		! (5_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (0_0) res += A2;

	ldd	[%fp+tmp5],%f48		! (4_1) dsqrt_exp = *(double*)&sqrt_exp;
	cmp	%o5,_0x7ff00000		! (4_0) hx ? 0x7ff00000
	bge,pn	%icc,.update20		! (4_0) if ( hx >= 0x7ff00000 )
	faddd	%f60,%f24,%f60		! (4_1) res += dexp_hi;
.cont20:
	lda	[%l2]%asi,%f10		! (5_0) ((float*)&res)[0] = ((float*)px)[0];
	sra	%o5,15,%l0		! (4_0) bit = hx >> 15;
	add	%g1,TBL,%o7		! (3_0) (char*)div_arr+ind0
	for	%f50,A1,%f24		! (4_0) res = vis_for(res,A1);

	fmuld	A5,%f18,%f52		! (2_0) res = A5 * xx;
	sra	%o5,7,%o1		! (4_0) ind0 = hx >> 7;
	ldd	[%o7],%f22		! (3_0) dtmp0 = ((double*)pind)[0];
	fand	%f54,DC3,%f54		! (3_0) res_c = vis_fand(res_c,DC3);

	fmuld	%f20,%f42,%f20		! (0_0) res *= xx;
	and	%o1,_0x00001ff8,%o1	! (4_0) ind0 &= 0x1ff8;
	sub	%l1,512,%o3		! (4_0) sqrt_exp -= 512;
	faddd	%f34,A3,%f62		! (1_0) res += A3;

	lda	[%l2+4]%asi,%f11	! (5_0) ((float*)&res)[1] = ((float*)px)[1];
	add	%o1,32,%o1		! (4_0) ind0 += 32;
	fpadd32	%f48,%f60,%f12		! (4_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);
	fmuld	%f40,%f16,%f34		! (5_1) res = dexp_hi * res;

	and	%l0,32,%i4		! (4_0) bit &= 32;
	cmp	%o5,_0x00100000		! (4_0) hx ? 0x00100000
	bl,pn	%icc,.update21		! (4_0) if ( hx < 0x00100000 )
	fsubd	%f44,%f54,%f44		! (3_0) xx = (res - res_c);
.cont21:
	and	%o1,-64,%o1		! (4_0) ind0 &= -8;
	sub	counter,6,counter	! counter
	st	%f12,[%i3]		! (4_1) ((float*)py)[0] = ((float*)&dtmp0)[0];
	faddd	%f52,A4,%f54		! (2_0) res += A4;

	st	%f13,[%i3+4]		! (4_1) ((float*)py)[1] = ((float*)&dtmp0)[1];
	cmp	counter,6
	bge,pt	%icc,.main_loop
	add	%i3,stridey,%l0		! py += stridey

.tail:
	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%l0,%o4

	fmuld	%f62,%f14,%f52		! (1_1) res *= xx;
	add	%i1,TBL,%i1		! (0_1) pind = (char*)TBL + ind1;
	faddd	%f20,A1,%f12		! (0_1) res += A1;

	faddd	%f34,%f36,%f60		! (5_2) res += dexp_lo;

	fmuld	%f44,%f22,%f44		! (3_1) xx *= dtmp0;
	add	%l2,stridex,%l2		! px += stridex

	fmuld	%f54,%f18,%f34		! (2_1) res *= xx;
	ldd	[%i1+16],%f36		! (0_1) dexp_lo = ((double*)pind)[2];

	fmuld	%f12,%f42,%f12		! (0_1) res *= xx;
	ldd	[%i1+8],%f42		! (0_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (1_1) res += A2;

	ldd	[%fp+tmp0],%f48		! (5_2) dsqrt_exp = *(double*)&sqrt_exp;
	faddd	%f60,%f40,%f60		! (5_2) res += dexp_hi;

	fmuld	A5,%f44,%f52		! (3_1) res = A5 * xx;

	fmuld	%f20,%f14,%f20		! (1_1) res *= xx;
	faddd	%f34,A3,%f62		! (2_1) res += A3;

	fmuld	%f42,%f12,%f34		! (0_1) res = dexp_hi * res;
	fpadd32	%f48,%f60,%f12		! (5_2) dtmp0 = vis_fpadd32(dsqrt_exp,res);

	st	%f12,[%l0]		! (5_2) ((float*)py)[0] = ((float*)&dtmp0)[0];

	add	%l0,stridey,%i1		! py += stridey
	st	%f13,[%l0+4]		! (5_2) ((float*)py)[1] = ((float*)&dtmp0)[1];
	faddd	%f52,A4,%f54		! (3_1) res += A4;

	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%i1,%o4

	fmuld	%f62,%f18,%f52		! (2_1) res *= xx;
	faddd	%f20,A1,%f12		! (1_1) res += A1;

	faddd	%f34,%f36,%f60		! (0_1) res += dexp_lo;

	add	%i2,TBL,%i2		! (1_1) pind = (char*)TBL + ind1;

	fmuld	%f54,%f44,%f34		! (3_1) res *= xx;
	add	%l2,stridex,%l2		! px += stridex
	ldd	[%i2+16],%f36		! (1_1) dexp_lo = ((double*)pind)[2];

	fmuld	%f12,%f14,%f12		! (1_1) res *= xx;
	ldd	[%i2+8],%f14		! (1_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (2_1) res += A2;

	ldd	[%fp+tmp1],%f48		! (0_1) dsqrt_exp = *(double*)&sqrt_exp;
	faddd	%f60,%f42,%f60		! (0_1) res += dexp_hi;

	fmuld	%f20,%f18,%f20		! (2_1) res *= xx;
	faddd	%f34,A3,%f62		! (3_1) res += A3;

	fmuld	%f14,%f12,%f34		! (1_1) res = dexp_hi * res;
	fpadd32	%f48,%f60,%f12		! (0_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);

	st	%f12,[%i1]		! (0_1) ((float*)py)[0] = ((float*)&dtmp0)[0];

	add	%i1,stridey,%i2		! py += stridey
	st	%f13,[%i1+4]		! (0_1) ((float*)py)[1] = ((float*)&dtmp0)[1];

	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%i2,%o4

	fmuld	%f62,%f44,%f52		! (3_1) res *= xx;
	faddd	%f20,A1,%f12		! (2_1) res += A1;

	faddd	%f34,%f36,%f60		! (1_1) res += dexp_lo;

	add	%g5,TBL,%g5		! (2_1) pind = (char*)TBL + ind1;

	add	%l2,stridex,%l2		! px += stridex
	ldd	[%g5+16],%f36		! (2_1) dexp_lo = ((double*)pind)[2];

	fmuld	%f12,%f18,%f12		! (2_1) res *= xx;
	ldd	[%g5+8],%f18		! (2_1) dexp_hi = ((double*)pind)[1];
	faddd	%f52,A2,%f20		! (3_1) res += A2;

	ldd	[%fp+tmp2],%f48		! (1_1) dsqrt_exp = *(double*)&sqrt_exp;
	faddd	%f60,%f14,%f60		! (1_1) res += dexp_hi;

	fmuld	%f20,%f44,%f20		! (3_1) res *= xx;

	fmuld	%f18,%f12,%f34		! (2_1) res = dexp_hi * res;
	fpadd32	%f48,%f60,%f12		! (1_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);

	st	%f12,[%i2]		! (1_1) ((float*)py)[0] = ((float*)&dtmp0)[0];

	add	%i2,stridey,%g5		! py += stridey
	st	%f13,[%i2+4]		! (1_1) ((float*)py)[1] = ((float*)&dtmp0)[1];

	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%g5,%o4

	faddd	%f20,A1,%f12		! (3_1) res += A1;

	faddd	%f34,%f36,%f60		! (2_1) res += dexp_lo;

	add	%g1,TBL,%g1		! (3_1) pind = (char*)TBL + ind1;

	add	%l2,stridex,%l2		! px += stridex
	ldd	[%g1+16],%f36		! (3_1) dexp_lo = ((double*)pind)[2];

	fmuld	%f12,%f44,%f12		! (3_1) res *= xx;
	ldd	[%g1+8],%f44		! (3_1) dexp_hi = ((double*)pind)[1];

	ldd	[%fp+tmp3],%f48		! (2_1) dsqrt_exp = *(double*)&sqrt_exp;
	faddd	%f60,%f18,%f60		! (2_1) res += dexp_hi;

	fmuld	%f44,%f12,%f34		! (3_1) res = dexp_hi * res;
	fpadd32	%f48,%f60,%f12		! (2_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);

	st	%f12,[%g5]		! (2_1) ((float*)py)[0] = ((float*)&dtmp0)[0];

	add	%g5,stridey,%g1		! py += stridey
	st	%f13,[%g5+4]		! (2_1) ((float*)py)[1] = ((float*)&dtmp0)[1];

	subcc	counter,1,counter
	bneg	.begin
	or	%g0,%g1,%o4

	faddd	%f34,%f36,%f60		! (3_1) res += dexp_lo;

	add	%l2,stridex,%l2		! px += stridex

	ldd	[%fp+tmp4],%f48		! (3_1) dsqrt_exp = *(double*)&sqrt_exp;
	faddd	%f60,%f44,%f60		! (3_1) res += dexp_hi;

	fpadd32	%f48,%f60,%f12		! (3_1) dtmp0 = vis_fpadd32(dsqrt_exp,res);

	st	%f12,[%g1]		! (3_1) ((float*)py)[0] = ((float*)&dtmp0)[0];

	add	%g1,stridey,%i3		! py += stridey
	st	%f13,[%g1+4]		! (3_1) ((float*)py)[1] = ((float*)&dtmp0)[1];

	ba	.begin
	or	%g0,%i3,%o4

	.align	16
.spec:
	fsqrtd	%f10,%f10
	add	%l2,stridex,%l2

	st	%f10,[%o4]
	st	%f11,[%o4+4]

	add	%o4,stridey,%o4
	ba	.begin1
	sub	counter,1,counter

	.align	16
.update0:
	cmp	counter,1
	ble	.cont0
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont0
	or	%g0,1,counter

	.align	16
.update1:
	cmp	counter,1
	ble	.cont1
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont1
	or	%g0,1,counter

	.align	16
.update2:
	cmp	counter,2
	ble	.cont2
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont2
	or	%g0,2,counter

	.align	16
.update3:
	cmp	counter,2
	ble	.cont3
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont3
	or	%g0,2,counter

	.align	16
.update4:
	cmp	counter,3
	ble	.cont4
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont4
	or	%g0,3,counter

	.align	16
.update5:
	cmp	counter,3
	ble	.cont5
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont5
	or	%g0,3,counter

	.align	16
.update6:
	cmp	counter,4
	ble	.cont6
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont6
	or	%g0,4,counter

	.align	16
.update7:
	cmp	counter,4
	ble	.cont7
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont7
	or	%g0,4,counter

	.align	16
.update8:
	cmp	counter,5
	ble	.cont8
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont8
	or	%g0,5,counter

	.align	16
.update9:
	cmp	counter,5
	ble	.cont9
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont9
	or	%g0,5,counter

	.align	16
.update10:
	cmp	counter,6
	ble	.cont10
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont10
	or	%g0,6,counter

	.align	16
.update11:
	cmp	counter,6
	ble	.cont11
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,6,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont11
	or	%g0,6,counter

	.align	16
.update12:
	cmp	counter,7
	ble	.cont12
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont12
	or	%g0,7,counter

	.align	16
.update13:
	cmp	counter,7
	ble	.cont13
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,7,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont13
	or	%g0,7,counter

	.align	16
.update14:
	cmp	counter,8
	ble	.cont14
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont14
	or	%g0,8,counter

	.align	16
.update15:
	cmp	counter,8
	ble	.cont15
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,8,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont15
	or	%g0,8,counter

	.align	16
.update16:
	cmp	counter,9
	ble	.cont16
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,9,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont16
	or	%g0,9,counter

	.align	16
.update17:
	cmp	counter,9
	ble	.cont17
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,9,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont17
	or	%g0,9,counter

	.align	16
.update18:
	cmp	counter,10
	ble	.cont18
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,10,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont18
	or	%g0,10,counter

	.align	16
.update19:
	cmp	counter,10
	ble	.cont19
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,10,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont19
	or	%g0,10,counter

	.align	16
.update20:
	cmp	counter,11
	ble	.cont20
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,11,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont20
	or	%g0,11,counter

	.align	16
.update21:
	cmp	counter,11
	ble	.cont21
	nop

	sub	%l2,stridex,%i5
	stx	%i5,[%fp+tmp_px]

	sub	counter,11,counter
	st	counter,[%fp+tmp_counter]

	ba	.cont21
	or	%g0,11,counter

.exit:
	ret
	restore

	SET_SIZE(__vsqrt)

