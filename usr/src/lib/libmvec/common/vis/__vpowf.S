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

	.file	"__vpowf.S"

#include "libm.h"

	RO_DATA
	.align	64

! __mt_constexp2fa:
	.word	0x3ff00000, 0x00000000, 0x3ff00b1a, 0xfa5abcbf
	.word	0x3ff0163d, 0xa9fb3335, 0x3ff02168, 0x143b0281
	.word	0x3ff02c9a, 0x3e778061, 0x3ff037d4, 0x2e11bbcc
	.word	0x3ff04315, 0xe86e7f85, 0x3ff04e5f, 0x72f654b1
	.word	0x3ff059b0, 0xd3158574, 0x3ff0650a, 0x0e3c1f89
	.word	0x3ff0706b, 0x29ddf6de, 0x3ff07bd4, 0x2b72a836
	.word	0x3ff08745, 0x18759bc8, 0x3ff092bd, 0xf66607e0
	.word	0x3ff09e3e, 0xcac6f383, 0x3ff0a9c7, 0x9b1f3919
	.word	0x3ff0b558, 0x6cf9890f, 0x3ff0c0f1, 0x45e46c85
	.word	0x3ff0cc92, 0x2b7247f7, 0x3ff0d83b, 0x23395dec
	.word	0x3ff0e3ec, 0x32d3d1a2, 0x3ff0efa5, 0x5fdfa9c5
	.word	0x3ff0fb66, 0xaffed31b, 0x3ff10730, 0x28d7233e
	.word	0x3ff11301, 0xd0125b51, 0x3ff11edb, 0xab5e2ab6
	.word	0x3ff12abd, 0xc06c31cc, 0x3ff136a8, 0x14f204ab
	.word	0x3ff1429a, 0xaea92de0, 0x3ff14e95, 0x934f312e
	.word	0x3ff15a98, 0xc8a58e51, 0x3ff166a4, 0x5471c3c2
	.word	0x3ff172b8, 0x3c7d517b, 0x3ff17ed4, 0x8695bbc0
	.word	0x3ff18af9, 0x388c8dea, 0x3ff19726, 0x58375d2f
	.word	0x3ff1a35b, 0xeb6fcb75, 0x3ff1af99, 0xf8138a1c
	.word	0x3ff1bbe0, 0x84045cd4, 0x3ff1c82f, 0x95281c6b
	.word	0x3ff1d487, 0x3168b9aa, 0x3ff1e0e7, 0x5eb44027
	.word	0x3ff1ed50, 0x22fcd91d, 0x3ff1f9c1, 0x8438ce4d
	.word	0x3ff2063b, 0x88628cd6, 0x3ff212be, 0x3578a819
	.word	0x3ff21f49, 0x917ddc96, 0x3ff22bdd, 0xa27912d1
	.word	0x3ff2387a, 0x6e756238, 0x3ff2451f, 0xfb82140a
	.word	0x3ff251ce, 0x4fb2a63f, 0x3ff25e85, 0x711ece75
	.word	0x3ff26b45, 0x65e27cdd, 0x3ff2780e, 0x341ddf29
	.word	0x3ff284df, 0xe1f56381, 0x3ff291ba, 0x7591bb70
	.word	0x3ff29e9d, 0xf51fdee1, 0x3ff2ab8a, 0x66d10f13
	.word	0x3ff2b87f, 0xd0dad990, 0x3ff2c57e, 0x39771b2f
	.word	0x3ff2d285, 0xa6e4030b, 0x3ff2df96, 0x1f641589
	.word	0x3ff2ecaf, 0xa93e2f56, 0x3ff2f9d2, 0x4abd886b
	.word	0x3ff306fe, 0x0a31b715, 0x3ff31432, 0xedeeb2fd
	.word	0x3ff32170, 0xfc4cd831, 0x3ff32eb8, 0x3ba8ea32
	.word	0x3ff33c08, 0xb26416ff, 0x3ff34962, 0x66e3fa2d
	.word	0x3ff356c5, 0x5f929ff1, 0x3ff36431, 0xa2de883b
	.word	0x3ff371a7, 0x373aa9cb, 0x3ff37f26, 0x231e754a
	.word	0x3ff38cae, 0x6d05d866, 0x3ff39a40, 0x1b7140ef
	.word	0x3ff3a7db, 0x34e59ff7, 0x3ff3b57f, 0xbfec6cf4
	.word	0x3ff3c32d, 0xc313a8e5, 0x3ff3d0e5, 0x44ede173
	.word	0x3ff3dea6, 0x4c123422, 0x3ff3ec70, 0xdf1c5175
	.word	0x3ff3fa45, 0x04ac801c, 0x3ff40822, 0xc367a024
	.word	0x3ff4160a, 0x21f72e2a, 0x3ff423fb, 0x2709468a
	.word	0x3ff431f5, 0xd950a897, 0x3ff43ffa, 0x3f84b9d4
	.word	0x3ff44e08, 0x6061892d, 0x3ff45c20, 0x42a7d232
	.word	0x3ff46a41, 0xed1d0057, 0x3ff4786d, 0x668b3237
	.word	0x3ff486a2, 0xb5c13cd0, 0x3ff494e1, 0xe192aed2
	.word	0x3ff4a32a, 0xf0d7d3de, 0x3ff4b17d, 0xea6db7d7
	.word	0x3ff4bfda, 0xd5362a27, 0x3ff4ce41, 0xb817c114
	.word	0x3ff4dcb2, 0x99fddd0d, 0x3ff4eb2d, 0x81d8abff
	.word	0x3ff4f9b2, 0x769d2ca7, 0x3ff50841, 0x7f4531ee
	.word	0x3ff516da, 0xa2cf6642, 0x3ff5257d, 0xe83f4eef
	.word	0x3ff5342b, 0x569d4f82, 0x3ff542e2, 0xf4f6ad27
	.word	0x3ff551a4, 0xca5d920f, 0x3ff56070, 0xdde910d2
	.word	0x3ff56f47, 0x36b527da, 0x3ff57e27, 0xdbe2c4cf
	.word	0x3ff58d12, 0xd497c7fd, 0x3ff59c08, 0x27ff07cc
	.word	0x3ff5ab07, 0xdd485429, 0x3ff5ba11, 0xfba87a03
	.word	0x3ff5c926, 0x8a5946b7, 0x3ff5d845, 0x90998b93
	.word	0x3ff5e76f, 0x15ad2148, 0x3ff5f6a3, 0x20dceb71
	.word	0x3ff605e1, 0xb976dc09, 0x3ff6152a, 0xe6cdf6f4
	.word	0x3ff6247e, 0xb03a5585, 0x3ff633dd, 0x1d1929fd
	.word	0x3ff64346, 0x34ccc320, 0x3ff652b9, 0xfebc8fb7
	.word	0x3ff66238, 0x82552225, 0x3ff671c1, 0xc70833f6
	.word	0x3ff68155, 0xd44ca973, 0x3ff690f4, 0xb19e9538
	.word	0x3ff6a09e, 0x667f3bcd, 0x3ff6b052, 0xfa75173e
	.word	0x3ff6c012, 0x750bdabf, 0x3ff6cfdc, 0xddd47645
	.word	0x3ff6dfb2, 0x3c651a2f, 0x3ff6ef92, 0x98593ae5
	.word	0x3ff6ff7d, 0xf9519484, 0x3ff70f74, 0x66f42e87
	.word	0x3ff71f75, 0xe8ec5f74, 0x3ff72f82, 0x86ead08a
	.word	0x3ff73f9a, 0x48a58174, 0x3ff74fbd, 0x35d7cbfd
	.word	0x3ff75feb, 0x564267c9, 0x3ff77024, 0xb1ab6e09
	.word	0x3ff78069, 0x4fde5d3f, 0x3ff790b9, 0x38ac1cf6
	.word	0x3ff7a114, 0x73eb0187, 0x3ff7b17b, 0x0976cfdb
	.word	0x3ff7c1ed, 0x0130c132, 0x3ff7d26a, 0x62ff86f0
	.word	0x3ff7e2f3, 0x36cf4e62, 0x3ff7f387, 0x8491c491
	.word	0x3ff80427, 0x543e1a12, 0x3ff814d2, 0xadd106d9
	.word	0x3ff82589, 0x994cce13, 0x3ff8364c, 0x1eb941f7
	.word	0x3ff8471a, 0x4623c7ad, 0x3ff857f4, 0x179f5b21
	.word	0x3ff868d9, 0x9b4492ed, 0x3ff879ca, 0xd931a436
	.word	0x3ff88ac7, 0xd98a6699, 0x3ff89bd0, 0xa478580f
	.word	0x3ff8ace5, 0x422aa0db, 0x3ff8be05, 0xbad61778
	.word	0x3ff8cf32, 0x16b5448c, 0x3ff8e06a, 0x5e0866d9
	.word	0x3ff8f1ae, 0x99157736, 0x3ff902fe, 0xd0282c8a
	.word	0x3ff9145b, 0x0b91ffc6, 0x3ff925c3, 0x53aa2fe2
	.word	0x3ff93737, 0xb0cdc5e5, 0x3ff948b8, 0x2b5f98e5
	.word	0x3ff95a44, 0xcbc8520f, 0x3ff96bdd, 0x9a7670b3
	.word	0x3ff97d82, 0x9fde4e50, 0x3ff98f33, 0xe47a22a2
	.word	0x3ff9a0f1, 0x70ca07ba, 0x3ff9b2bb, 0x4d53fe0d
	.word	0x3ff9c491, 0x82a3f090, 0x3ff9d674, 0x194bb8d5
	.word	0x3ff9e863, 0x19e32323, 0x3ff9fa5e, 0x8d07f29e
	.word	0x3ffa0c66, 0x7b5de565, 0x3ffa1e7a, 0xed8eb8bb
	.word	0x3ffa309b, 0xec4a2d33, 0x3ffa42c9, 0x80460ad8
	.word	0x3ffa5503, 0xb23e255d, 0x3ffa674a, 0x8af46052
	.word	0x3ffa799e, 0x1330b358, 0x3ffa8bfe, 0x53c12e59
	.word	0x3ffa9e6b, 0x5579fdbf, 0x3ffab0e5, 0x21356eba
	.word	0x3ffac36b, 0xbfd3f37a, 0x3ffad5ff, 0x3a3c2774
	.word	0x3ffae89f, 0x995ad3ad, 0x3ffafb4c, 0xe622f2ff
	.word	0x3ffb0e07, 0x298db666, 0x3ffb20ce, 0x6c9a8952
	.word	0x3ffb33a2, 0xb84f15fb, 0x3ffb4684, 0x15b749b1
	.word	0x3ffb5972, 0x8de5593a, 0x3ffb6c6e, 0x29f1c52a
	.word	0x3ffb7f76, 0xf2fb5e47, 0x3ffb928c, 0xf22749e4
	.word	0x3ffba5b0, 0x30a1064a, 0x3ffbb8e0, 0xb79a6f1f
	.word	0x3ffbcc1e, 0x904bc1d2, 0x3ffbdf69, 0xc3f3a207
	.word	0x3ffbf2c2, 0x5bd71e09, 0x3ffc0628, 0x6141b33d
	.word	0x3ffc199b, 0xdd85529c, 0x3ffc2d1c, 0xd9fa652c
	.word	0x3ffc40ab, 0x5fffd07a, 0x3ffc5447, 0x78fafb22
	.word	0x3ffc67f1, 0x2e57d14b, 0x3ffc7ba8, 0x8988c933
	.word	0x3ffc8f6d, 0x9406e7b5, 0x3ffca340, 0x5751c4db
	.word	0x3ffcb720, 0xdcef9069, 0x3ffccb0f, 0x2e6d1675
	.word	0x3ffcdf0b, 0x555dc3fa, 0x3ffcf315, 0x5b5bab74
	.word	0x3ffd072d, 0x4a07897c, 0x3ffd1b53, 0x2b08c968
	.word	0x3ffd2f87, 0x080d89f2, 0x3ffd43c8, 0xeacaa1d6
	.word	0x3ffd5818, 0xdcfba487, 0x3ffd6c76, 0xe862e6d3
	.word	0x3ffd80e3, 0x16c98398, 0x3ffd955d, 0x71ff6075
	.word	0x3ffda9e6, 0x03db3285, 0x3ffdbe7c, 0xd63a8315
	.word	0x3ffdd321, 0xf301b460, 0x3ffde7d5, 0x641c0658
	.word	0x3ffdfc97, 0x337b9b5f, 0x3ffe1167, 0x6b197d17
	.word	0x3ffe2646, 0x14f5a129, 0x3ffe3b33, 0x3b16ee12
	.word	0x3ffe502e, 0xe78b3ff6, 0x3ffe6539, 0x24676d76
	.word	0x3ffe7a51, 0xfbc74c83, 0x3ffe8f79, 0x77cdb740
	.word	0x3ffea4af, 0xa2a490da, 0x3ffeb9f4, 0x867cca6e
	.word	0x3ffecf48, 0x2d8e67f1, 0x3ffee4aa, 0xa2188510
	.word	0x3ffefa1b, 0xee615a27, 0x3fff0f9c, 0x1cb6412a
	.word	0x3fff252b, 0x376bba97, 0x3fff3ac9, 0x48dd7274
	.word	0x3fff5076, 0x5b6e4540, 0x3fff6632, 0x798844f8
	.word	0x3fff7bfd, 0xad9cbe14, 0x3fff91d8, 0x02243c89
	.word	0x3fffa7c1, 0x819e90d8, 0x3fffbdba, 0x3692d514
	.word	0x3fffd3c2, 0x2b8f71f1, 0x3fffe9d9, 0x6b2a23d9

! __mt_constexp2fb:
	.word	0x36900000, 0x36a00000, 0x36b00000, 0x36c00000
	.word	0x36d00000, 0x36e00000, 0x36f00000, 0x37000000
	.word	0x37100000, 0x37200000, 0x37300000, 0x37400000
	.word	0x37500000, 0x37600000, 0x37700000, 0x37800000
	.word	0x37900000, 0x37a00000, 0x37b00000, 0x37c00000
	.word	0x37d00000, 0x37e00000, 0x37f00000, 0x38000000
	.word	0x38100000, 0x38200000, 0x38300000, 0x38400000
	.word	0x38500000, 0x38600000, 0x38700000, 0x38800000
	.word	0x38900000, 0x38a00000, 0x38b00000, 0x38c00000
	.word	0x38d00000, 0x38e00000, 0x38f00000, 0x39000000
	.word	0x39100000, 0x39200000, 0x39300000, 0x39400000
	.word	0x39500000, 0x39600000, 0x39700000, 0x39800000
	.word	0x39900000, 0x39a00000, 0x39b00000, 0x39c00000
	.word	0x39d00000, 0x39e00000, 0x39f00000, 0x3a000000
	.word	0x3a100000, 0x3a200000, 0x3a300000, 0x3a400000
	.word	0x3a500000, 0x3a600000, 0x3a700000, 0x3a800000
	.word	0x3a900000, 0x3aa00000, 0x3ab00000, 0x3ac00000
	.word	0x3ad00000, 0x3ae00000, 0x3af00000, 0x3b000000
	.word	0x3b100000, 0x3b200000, 0x3b300000, 0x3b400000
	.word	0x3b500000, 0x3b600000, 0x3b700000, 0x3b800000
	.word	0x3b900000, 0x3ba00000, 0x3bb00000, 0x3bc00000
	.word	0x3bd00000, 0x3be00000, 0x3bf00000, 0x3c000000
	.word	0x3c100000, 0x3c200000, 0x3c300000, 0x3c400000
	.word	0x3c500000, 0x3c600000, 0x3c700000, 0x3c800000
	.word	0x3c900000, 0x3ca00000, 0x3cb00000, 0x3cc00000
	.word	0x3cd00000, 0x3ce00000, 0x3cf00000, 0x3d000000
	.word	0x3d100000, 0x3d200000, 0x3d300000, 0x3d400000
	.word	0x3d500000, 0x3d600000, 0x3d700000, 0x3d800000
	.word	0x3d900000, 0x3da00000, 0x3db00000, 0x3dc00000
	.word	0x3dd00000, 0x3de00000, 0x3df00000, 0x3e000000
	.word	0x3e100000, 0x3e200000, 0x3e300000, 0x3e400000
	.word	0x3e500000, 0x3e600000, 0x3e700000, 0x3e800000
	.word	0x3e900000, 0x3ea00000, 0x3eb00000, 0x3ec00000
	.word	0x3ed00000, 0x3ee00000, 0x3ef00000, 0x3f000000
	.word	0x3f100000, 0x3f200000, 0x3f300000, 0x3f400000
	.word	0x3f500000, 0x3f600000, 0x3f700000, 0x3f800000
	.word	0x3f900000, 0x3fa00000, 0x3fb00000, 0x3fc00000
	.word	0x3fd00000, 0x3fe00000, 0x3ff00000, 0x40000000
	.word	0x40100000, 0x40200000, 0x40300000, 0x40400000
	.word	0x40500000, 0x40600000, 0x40700000, 0x40800000
	.word	0x40900000, 0x40a00000, 0x40b00000, 0x40c00000
	.word	0x40d00000, 0x40e00000, 0x40f00000, 0x41000000
	.word	0x41100000, 0x41200000, 0x41300000, 0x41400000
	.word	0x41500000, 0x41600000, 0x41700000, 0x41800000
	.word	0x41900000, 0x41a00000, 0x41b00000, 0x41c00000
	.word	0x41d00000, 0x41e00000, 0x41f00000, 0x42000000
	.word	0x42100000, 0x42200000, 0x42300000, 0x42400000
	.word	0x42500000, 0x42600000, 0x42700000, 0x42800000
	.word	0x42900000, 0x42a00000, 0x42b00000, 0x42c00000
	.word	0x42d00000, 0x42e00000, 0x42f00000, 0x43000000
	.word	0x43100000, 0x43200000, 0x43300000, 0x43400000
	.word	0x43500000, 0x43600000, 0x43700000, 0x43800000
	.word	0x43900000, 0x43a00000, 0x43b00000, 0x43c00000
	.word	0x43d00000, 0x43e00000, 0x43f00000, 0x44000000
	.word	0x44100000, 0x44200000, 0x44300000, 0x44400000
	.word	0x44500000, 0x44600000, 0x44700000, 0x44800000
	.word	0x44900000, 0x44a00000, 0x44b00000, 0x44c00000
	.word	0x44d00000, 0x44e00000, 0x44f00000, 0x45000000
	.word	0x45100000, 0x45200000, 0x45300000, 0x45400000
	.word	0x45500000, 0x45600000, 0x45700000, 0x45800000
	.word	0x45900000, 0x45a00000, 0x45b00000, 0x45c00000
	.word	0x45d00000, 0x45e00000, 0x45f00000, 0x46000000
	.word	0x46100000, 0x46200000, 0x46300000, 0x46400000
	.word	0x46500000, 0x46600000, 0x46700000, 0x46800000
	.word	0x46900000, 0x46a00000, 0x46b00000, 0x46c00000
	.word	0x46d00000, 0x46e00000, 0x46f00000, 0x47000000
	.word	0x47100000, 0x47200000, 0x47300000, 0x47400000
	.word	0x47500000, 0x47600000, 0x47700000, 0x47800000
	.word	0x47900000, 0x47a00000, 0x47b00000, 0x47c00000
	.word	0x47d00000, 0x47e00000, 0x47f00000, 0x00000000

	.word	0,0,0,0
	.word	0,0,0,0

.CONST_TBL:
! __mt_constlog4f:
	.word	0x00000000, 0x00000000, 0x3e800000, 0x00000000
	.word	0x4006fe50, 0xb6ef0851, 0x3e7fc07f, 0x01fc07f0
	.word	0x4016e796, 0x85c2d22a, 0x3e7f81f8, 0x1f81f820
	.word	0x40211cd1, 0xd5133413, 0x3e7f4465, 0x9e4a4271
	.word	0x4026bad3, 0x758efd87, 0x3e7f07c1, 0xf07c1f08
	.word	0x402c4dfa, 0xb90aab5f, 0x3e7ecc07, 0xb301ecc0
	.word	0x4030eb38, 0x9fa29f9b, 0x3e7e9131, 0xabf0b767
	.word	0x4033aa2f, 0xdd27f1c3, 0x3e7e573a, 0xc901e574
	.word	0x403663f6, 0xfac91316, 0x3e7e1e1e, 0x1e1e1e1e
	.word	0x403918a1, 0x6e46335b, 0x3e7de5d6, 0xe3f8868a
	.word	0x403bc842, 0x40adabba, 0x3e7dae60, 0x76b981db
	.word	0x403e72ec, 0x117fa5b2, 0x3e7d77b6, 0x54b82c34
	.word	0x40408c58, 0x8cda79e4, 0x3e7d41d4, 0x1d41d41d
	.word	0x4041dcd1, 0x97552b7b, 0x3e7d0cb5, 0x8f6ec074
	.word	0x40432ae9, 0xe278ae1a, 0x3e7cd856, 0x89039b0b
	.word	0x404476a9, 0xf983f74d, 0x3e7ca4b3, 0x055ee191
	.word	0x4045c01a, 0x39fbd688, 0x3e7c71c7, 0x1c71c71c
	.word	0x40470742, 0xd4ef027f, 0x3e7c3f8f, 0x01c3f8f0
	.word	0x40484c2b, 0xd02f03b3, 0x3e7c0e07, 0x0381c0e0
	.word	0x40498edd, 0x077e70df, 0x3e7bdd2b, 0x899406f7
	.word	0x404acf5e, 0x2db4ec94, 0x3e7bacf9, 0x14c1bad0
	.word	0x404c0db6, 0xcdd94dee, 0x3e7b7d6c, 0x3dda338b
	.word	0x404d49ee, 0x4c325970, 0x3e7b4e81, 0xb4e81b4f
	.word	0x404e840b, 0xe74e6a4d, 0x3e7b2036, 0x406c80d9
	.word	0x404fbc16, 0xb902680a, 0x3e7af286, 0xbca1af28
	.word	0x4050790a, 0xdbb03009, 0x3e7ac570, 0x1ac5701b
	.word	0x40511307, 0xdad30b76, 0x3e7a98ef, 0x606a63be
	.word	0x4051ac05, 0xb291f070, 0x3e7a6d01, 0xa6d01a6d
	.word	0x40524407, 0xab0e073a, 0x3e7a41a4, 0x1a41a41a
	.word	0x4052db10, 0xfc4d9aaf, 0x3e7a16d3, 0xf97a4b02
	.word	0x40537124, 0xcea4cded, 0x3e79ec8e, 0x951033d9
	.word	0x40540646, 0x3b1b0449, 0x3e79c2d1, 0x4ee4a102
	.word	0x40549a78, 0x4bcd1b8b, 0x3e799999, 0x9999999a
	.word	0x40552dbd, 0xfc4c96b3, 0x3e7970e4, 0xf80cb872
	.word	0x4055c01a, 0x39fbd688, 0x3e7948b0, 0xfcd6e9e0
	.word	0x4056518f, 0xe4677ba7, 0x3e7920fb, 0x49d0e229
	.word	0x4056e221, 0xcd9d0cde, 0x3e78f9c1, 0x8f9c18fa
	.word	0x405771d2, 0xba7efb3c, 0x3e78d301, 0x8d3018d3
	.word	0x405800a5, 0x63161c54, 0x3e78acb9, 0x0f6bf3aa
	.word	0x40588e9c, 0x72e0b226, 0x3e7886e5, 0xf0abb04a
	.word	0x40591bba, 0x891f1709, 0x3e786186, 0x18618618
	.word	0x4059a802, 0x391e232f, 0x3e783c97, 0x7ab2bedd
	.word	0x405a3376, 0x0a7f6051, 0x3e781818, 0x18181818
	.word	0x405abe18, 0x797f1f49, 0x3e77f405, 0xfd017f40
	.word	0x405b47eb, 0xf73882a1, 0x3e77d05f, 0x417d05f4
	.word	0x405bd0f2, 0xe9e79031, 0x3e77ad22, 0x08e0ecc3
	.word	0x405c592f, 0xad295b56, 0x3e778a4c, 0x8178a4c8
	.word	0x405ce0a4, 0x923a587d, 0x3e7767dc, 0xe434a9b1
	.word	0x405d6753, 0xe032ea0f, 0x3e7745d1, 0x745d1746
	.word	0x405ded3f, 0xd442364c, 0x3e772428, 0x7f46debc
	.word	0x405e726a, 0xa1e754d2, 0x3e7702e0, 0x5c0b8170
	.word	0x405ef6d6, 0x7328e220, 0x3e76e1f7, 0x6b4337c7
	.word	0x405f7a85, 0x68cb06cf, 0x3e76c16c, 0x16c16c17
	.word	0x405ffd79, 0x9a83ff9b, 0x3e76a13c, 0xd1537290
	.word	0x40603fda, 0x8b97997f, 0x3e768168, 0x16816817
	.word	0x4060809c, 0xf27f703d, 0x3e7661ec, 0x6a5122f9
	.word	0x4060c105, 0x00d63aa6, 0x3e7642c8, 0x590b2164
	.word	0x40610113, 0xb153c8ea, 0x3e7623fa, 0x77016240
	.word	0x406140c9, 0xfaa1e544, 0x3e760581, 0x60581606
	.word	0x40618028, 0xcf72976a, 0x3e75e75b, 0xb8d015e7
	.word	0x4061bf31, 0x1e95d00e, 0x3e75c988, 0x2b931057
	.word	0x4061fde3, 0xd30e8126, 0x3e75ac05, 0x6b015ac0
	.word	0x40623c41, 0xd42727c8, 0x3e758ed2, 0x308158ed
	.word	0x40627a4c, 0x0585cbf8, 0x3e7571ed, 0x3c506b3a
	.word	0x4062b803, 0x473f7ad1, 0x3e755555, 0x55555555
	.word	0x4062f568, 0x75eb3f26, 0x3e753909, 0x48f40feb
	.word	0x4063327c, 0x6ab49ca7, 0x3e751d07, 0xeae2f815
	.word	0x40636f3f, 0xfb6d9162, 0x3e750150, 0x15015015
	.word	0x4063abb3, 0xfaa02167, 0x3e74e5e0, 0xa72f0539
	.word	0x4063e7d9, 0x379f7016, 0x3e74cab8, 0x8725af6e
	.word	0x406423b0, 0x7e986aa9, 0x3e74afd6, 0xa052bf5b
	.word	0x40645f3a, 0x98a20739, 0x3e749539, 0xe3b2d067
	.word	0x40649a78, 0x4bcd1b8b, 0x3e747ae1, 0x47ae147b
	.word	0x4064d56a, 0x5b33cec4, 0x3e7460cb, 0xc7f5cf9a
	.word	0x40651011, 0x8708a8f9, 0x3e7446f8, 0x6562d9fb
	.word	0x40654a6e, 0x8ca5438e, 0x3e742d66, 0x25d51f87
	.word	0x40658482, 0x26989d34, 0x3e741414, 0x14141414
	.word	0x4065be4d, 0x0cb51435, 0x3e73fb01, 0x3fb013fb
	.word	0x4065f7cf, 0xf41e09af, 0x3e73e22c, 0xbce4a902
	.word	0x4066310b, 0x8f553048, 0x3e73c995, 0xa47babe7
	.word	0x40666a00, 0x8e4788cc, 0x3e73b13b, 0x13b13b14
	.word	0x4066a2af, 0x9e5a0f0a, 0x3e73991c, 0x2c187f63
	.word	0x4066db19, 0x6a76194a, 0x3e738138, 0x13813814
	.word	0x4067133e, 0x9b156c7c, 0x3e73698d, 0xf3de0748
	.word	0x40674b1f, 0xd64e0754, 0x3e73521c, 0xfb2b78c1
	.word	0x406782bd, 0xbfdda657, 0x3e733ae4, 0x5b57bcb2
	.word	0x4067ba18, 0xf93502e4, 0x3e7323e3, 0x4a2b10bf
	.word	0x4067f132, 0x2182cf16, 0x3e730d19, 0x0130d190
	.word	0x40682809, 0xd5be7073, 0x3e72f684, 0xbda12f68
	.word	0x40685ea0, 0xb0b27b26, 0x3e72e025, 0xc04b8097
	.word	0x406894f7, 0x4b06ef8b, 0x3e72c9fb, 0x4d812ca0
	.word	0x4068cb0e, 0x3b4b3bbe, 0x3e72b404, 0xad012b40
	.word	0x406900e6, 0x160002cd, 0x3e729e41, 0x29e4129e
	.word	0x4069367f, 0x6da0ab2f, 0x3e7288b0, 0x1288b013
	.word	0x40696bda, 0xd2acb5f6, 0x3e727350, 0xb8812735
	.word	0x4069a0f8, 0xd3b0e050, 0x3e725e22, 0x708092f1
	.word	0x4069d5d9, 0xfd5010b3, 0x3e724924, 0x92492492
	.word	0x406a0a7e, 0xda4c112d, 0x3e723456, 0x789abcdf
	.word	0x406a3ee7, 0xf38e181f, 0x3e721fb7, 0x8121fb78
	.word	0x406a7315, 0xd02f20c8, 0x3e720b47, 0x0c67c0d9
	.word	0x406aa708, 0xf58014d3, 0x3e71f704, 0x7dc11f70
	.word	0x406adac1, 0xe711c833, 0x3e71e2ef, 0x3b3fb874
	.word	0x406b0e41, 0x26bcc86c, 0x3e71cf06, 0xada2811d
	.word	0x406b4187, 0x34a9008c, 0x3e71bb4a, 0x4046ed29
	.word	0x406b7494, 0x8f5532da, 0x3e71a7b9, 0x611a7b96
	.word	0x406ba769, 0xb39e4964, 0x3e719453, 0x808ca29c
	.word	0x406bda07, 0x1cc67e6e, 0x3e718118, 0x11811812
	.word	0x406c0c6d, 0x447c5dd3, 0x3e716e06, 0x89427379
	.word	0x406c3e9c, 0xa2e1a055, 0x3e715b1e, 0x5f75270d
	.word	0x406c7095, 0xae91e1c7, 0x3e71485f, 0x0e0acd3b
	.word	0x406ca258, 0xdca93316, 0x3e7135c8, 0x1135c811
	.word	0x406cd3e6, 0xa0ca8907, 0x3e712358, 0xe75d3033
	.word	0x406d053f, 0x6d260896, 0x3e711111, 0x11111111
	.word	0x406d3663, 0xb27f31d5, 0x3e70fef0, 0x10fef011
	.word	0x406d6753, 0xe032ea0f, 0x3e70ecf5, 0x6be69c90
	.word	0x406d9810, 0x643d6615, 0x3e70db20, 0xa88f4696
	.word	0x406dc899, 0xab3ff56c, 0x3e70c971, 0x4fbcda3b
	.word	0x406df8f0, 0x2086af2c, 0x3e70b7e6, 0xec259dc8
	.word	0x406e2914, 0x2e0e0140, 0x3e70a681, 0x0a6810a7
	.word	0x406e5906, 0x3c8822ce, 0x3e70953f, 0x39010954
	.word	0x406e88c6, 0xb3626a73, 0x3e708421, 0x08421084
	.word	0x406eb855, 0xf8ca88fb, 0x3e707326, 0x0a47f7c6
	.word	0x406ee7b4, 0x71b3a950, 0x3e70624d, 0xd2f1a9fc
	.word	0x406f16e2, 0x81db7630, 0x3e705197, 0xf7d73404
	.word	0x406f45e0, 0x8bcf0655, 0x3e704104, 0x10410410
	.word	0x406f74ae, 0xf0efafae, 0x3e703091, 0xb51f5e1a
	.word	0x406fa34e, 0x1177c233, 0x3e702040, 0x81020408
	.word	0x406fd1be, 0x4c7f2af9, 0x3e701010, 0x10101010
	.word	0x40700000, 0x00000000, 0x3e700000, 0x00000000

! __mt_constexp2f:
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

	.word	0xc057150d, 0x5f6e1c54	! KA3 = -3.60659926599003171364e-01*256.0
	.word	0x405ec71c, 0x2e92efda	! KA2 =  4.80902715189356683026e-01*256.0
	.word	0xc0671547, 0x653cbec4	! KA1 = -7.21347520569871841065e-01*256.0
	.word	0x40771547, 0x652af190	! KA0 =  1.44269504088069658645e+00*256.0
	.word	0x3ecebfbe, 0x9d182250	! KB2 = 3.66556671660783833261e-06
	.word	0x3f662e43, 0xe2528362	! KB1 = 2.70760782821392980564e-03
	.word	0x40e00000, 0x00000000	! HTHRESH = 32768.0
	.word	0xc0e2c000, 0x00000000	! LTHRESH = -38400.0 ; 0.0f
	.word	0x3f800000, 0x00000000 	! 1.0f               ; free

#define tmp_px		STACK_BIAS-48
#define tmp_py		STACK_BIAS-40
#define tmp_counter	STACK_BIAS-32
#define tmp0		STACK_BIAS-28
#define tmp1		STACK_BIAS-24
#define tmp2		STACK_BIAS-20
#define tmp3		STACK_BIAS-16
#define tmp4		STACK_BIAS-12
#define tmp5		STACK_BIAS-8
#define tmp6		STACK_BIAS-4


#define KA3		%f34
#define KA2		%f36
#define KA1		%f38
#define KA0		%f40
#define KB2		%f42
#define KB1		%f44
#define HTHRESHOLD	%f30
#define LTHRESHOLD	%f32

#define counter		%o7
#define stridex		%i0
#define stridey		%i4
#define stridez		%l3

#define CONST_0x8000	%l1
#define MASK_0x007fffff	%l4
#define MASK_0x7fffffff	%l5

! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x30

!--------------------------------------------------------------------
!		!!!!!	vpowf algorithm	!!!!!
!  uy = *(unsigned int*)py;
!  ux = *(unsigned int*)px;
!  ay = uy & 0x7fffffff;
!  ax0 = ux & 0x7fffffff;
!  sx = ux >> 31;
!  yisint0 = 0;                /* Y - non-integer */
!  if (ax0 >= 0x7f800000 || ay >= 0x7f800000) { /* |X| or |Y| = Inf,Nan */
!    if (ax0 > 0x7f800000 || ay > 0x7f800000)   /* |X| or |Y| = Nan     */
!      pz[0] = *px * *py;
!      goto next;
!    if (ay == 0x7f800000) { /* |Y| = Inf */
!      float fy;
!      if (ax0 == 0x3f800000) fy = *py - *py; /* +-1 ** +-Inf = NaN */
!      else fy = ((ax0 < 0x3f800000) != (uy >> 31)) ? ZERO : *(float*) &ay;
!      pz[0] = fy;
!      goto next;
!    }
!    if (sx) {                               /* X = -Inf     */
!      exp = ay >> 23;
!      if (exp >= 0x97)                      /* |Y| >= 2^24  */
!        yisint0 = 2;                      /* Y - even     */
!      else {
!        if (exp >= 0x7f) {                  /* |Y| >= 1     */
!          i0 = ay >> ((0x7f + 23) - exp);
!          if ((i0 << ((0x7f + 23) - exp)) == ay) yisint0 = 2 - (i0 & 1);
!        }
!      }
!    }
!    if (uy >> 31) ax0 = 0;
!    ax0 += yisint0 << 31;
!    pz[0] =  *(float*)&ax0;
!    goto next;
!  }
!  exp0 = (ax0 >> 23) - 127;
!  if ((int)ux < 0x00800000) {         /* X = denormal or negative */
!    if ((int)ax0 < 0x00800000) {    /* X = denormal */
!      *((float*) &ax0) = (float) (int)ax0;
!      exp0 = (ax0 >> 23) - (127 + 149);
!    }
!    if ((int)ux <= 0) {                      /* X <= 0       */
!      exp = ay >> 23;
!      if (exp >= 0x97)                       /* |Y| >= 2^24  */
!        yisint0 = 2;                       /* Y - even     */
!      else {
!        if (exp >= 0x7f) {                   /* |Y| >= 1     */
!          i0 = ay >> ((0x7f + 23) - exp);
!          if ((i0 << ((0x7f + 23) - exp)) == ay) yisint0 = 2 - (i0 & 1);
!        }
!      }
!      if (ax0 == 0) { /* pow(0,Y) */
!        float fy;
!        fy = (uy >> 31) ? ONE / ZERO : ZERO;
!        if (sx & yisint0) fy = -fy;
!        pz[0] = fy;
!        goto next;
!      }
!      if (yisint0 == 0) { /* pow(neg,non-integer) */
!        pz[0] = ZERO / ZERO;  /* NaN */
!        goto next;
!      }
!    }
!  }
!
!  ax0 = *px;
!  exp0 = ax0 & 0x7fffffff;
!  exp0 >>= 23;
!  exp0 -= 127;
!  exp0 <<= 8;
!  ax0 &= 0x007fffff;
!  i0 = ax0 + 0x8000;
!  i0 &= 0xffff0000;
!  ind0 = i0 >> 12;
!  ind0 &= -8;
!  i0 = ax0 - i0;
!  dtmp0 = (double) i0;
!  dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
!  y0 =  dtmp0 * dtmp1;
!  dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
!  dtmp1 = (double) exp0;
!  yy0 = dtmp0 + dtmp1;
!  dtmp0 = KA3 * y0;
!  dtmp0 += KA2;
!  dtmp0 *= y0;
!  dtmp0 += KA1;
!  dtmp0 *= y0;
!  dtmp0 += KA0;
!  dtmp0 *= y0;
!  yy0 += dtmp0;
!  ftmp0 = *py0;
!  dtmp0 = (double)ftmp0;
!  yy0 *= dtmp0;
!  if (yy0 >= HTHRESH)
!    yy0 = HTHRESH;
!  if (yy0 <= LTHRESH)
!    yy0 = LTHRESH;
!  ind0 = (int) yy0;
!  ((int*)&dtmp1)[0] = ind0;
!  ((int*)&dtmp1)[1] = 0;
!  dtmp1 = vis_fpackfix(dtmp1);
!  dtmp0 = (double)ind0;
!  y0 = yy0 - dtmp0;
!  dtmp0 = KB2 * y0;
!  dtmp0 += KB1;
!  yy0 = dtmp0 * y0;
!  ind0 &= 255;
!  ind0 <<= 3;
!  di0 = *(double*)((char*)__mt_constexp2f + ind0);
!  di0 = vis_fpadd32(di0,dtmp1);
!  yy0 *= di0;
!  yy0 += di0;
!  ftmp0 = (float)yy0;
!  *pz0 = ftmp0;
!--------------------------------------------------------------------
!		!!!!!	vpowf algorithm,stridex=0	!!!!!
!
!  ax = ax0 = *px;
!  exp0 = ax0 & 0x7fffffff;
!  exp0 >>= 23;
!  exp0 -= 127;
!  exp0 <<= 8;
!  ax0 &= 0x007fffff;
!  i0 = ax0 + 0x8000;
!  i0 &= 0xffff0000;
!  ind0 = i0 >> 12;
!  ind0 &= -8;
!  i0 = ax0 - i0;
!  dtmp0 = (double) i0;
!  dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
!  y0 =  dtmp0 * dtmp1;
!  dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
!  dtmp1 = (double) exp0;
!  yy0 = dtmp0 + dtmp1;
!  dtmp0 = KA3 * y0;
!  dtmp0 += KA2;
!  dtmp0 *= y0;
!  dtmp0 += KA1;
!  dtmp0 *= y0;
!  dtmp0 += KA0;
!  dtmp0 *= y0;
!  yy = yy0 + dtmp0;
!
!  uy = ((int*)py)[0];
!  ay = uy & 0x7fffffff;
!  if (ay >= 0x7f800000) {       /* |Y| = Inf or Nan */
!    float fy;
!   if (ay > 0x7f800000) fy = *py + *py;  /* |Y| = Nan     */
!    else fy = ((ax < 0x3f800000) != (uy >> 31)) ? ZERO : *(float*)&ay;
!    pz[0] = fy;
!    goto next;
!  }
!
!
!  ftmp0 = py[0];
!  dtmp0 = (double)ftmp0;
!  yy0 = dtmp0 * yy;
!  if (yy0 >= HTHRESH)
!  if (yy0 <= LTHRESH)
!  yy0 = HTHRESH;
!  yy0 = LTHRESH;
!  ii0 = (int) yy0;
!  dtmp0 = (double)ii0;
!  i0 = ii0 >> 5;
!  i0 &= -8;
!  di0 = ((double*)((char*)(__mt_constexp2fb + 150) + i0))[0];
!  y0 = yy0 - dtmp0;
!  dtmp0 = KB2 * y0;
!  dtmp0 += KB1;
!  yy0 = dtmp0 * y0;
!  ii0 &= 255;
!  ii0 <<= 3;
!  dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];
!  di0 *= dtmp0;
!  dtmp0 = yy0 * di0;
!  dtmp0 += di0;
!  ftmp0 = (float)dtmp0;
!  pz[0] = ftmp0;
!--------------------------------------------------------------------
	ENTRY(__vpowf)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,l2)
	wr	%g0,0x60,%gsr

#ifdef __sparcv9
	ldx	[%fp+STACK_BIAS+176],stridez
#else
	ld	[%fp+STACK_BIAS+92],stridez
#endif

	ld	[%i1],%o3
	add	%l2,2064,%l0
	st	%i0,[%fp+tmp_counter]
	add	%l0,2048,%l6
	ldd	[%l6],KA3
	ldd	[%l6+8],KA2
	sll	stridey,2,stridey
	ldd	[%l6+16],KA1
	sll	stridez,2,stridez
	ldd	[%l6+24],KA0
	sll	%i2,2,stridex
	ldd	[%l6+32],KB2
	sethi	%hi(0x7ffffc00),MASK_0x7fffffff
	fzero	%f2
	ldd	[%l6+40],KB1
	add	MASK_0x7fffffff,1023,MASK_0x7fffffff
	fzero	%f10
	ldd	[%l6+48],HTHRESHOLD
	sethi	%hi(0x7ffc00),MASK_0x007fffff
	fzero	%f20
	ldd	[%l6+56],LTHRESHOLD
	sethi	%hi(0x8000),CONST_0x8000
	add	MASK_0x007fffff,1023,MASK_0x007fffff

	cmp	stridex,0
	bne,pt	%icc,.common_case
	sethi	%hi(0x00800000),%l6

	cmp	%o3,%l6
	bl,pn	%icc,.common_case
	sethi	%hi(0x7f800000),%o1

	cmp	%o3,%o1
	bge,pn	%icc,.common_case
	sethi	%hi(0x3f800000),%l6

	cmp	%o3,%l6
	bne,pt	%icc,.stridex_zero
	nop

.common_case:
	stx	%i1,[%fp+tmp_px]
	stx	%i3,[%fp+tmp_py]
.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],%o2
	ldx	[%fp+tmp_py],%i2
	st	%g0,[%fp+tmp_counter]
.begin1:
	cmp	counter,0
	ble,pn	%icc,.exit
	lda	[%o2]0x82,%i1		! (Y0_2) ax0 = *px;

	lda	[%i2]0x82,%l7
	sethi	%hi(0xffff0000),%l6
	sethi	%hi(0x7f800000),%o5

	and	%i1,MASK_0x7fffffff,%i3	! (Y0_2) exp0 = ax0 & 0x7fffffff;
	and	%i1,MASK_0x007fffff,%g5	! (Y0_2) ax0 &= 0x007fffff;

	cmp	%i3,%o5			! (Y0_2) ax0 ? 0x7f800000
	bge,pn	%icc,.spec1		! (Y0_2) if( ax0 >= 0x7f800000 )
	and	%l7,MASK_0x7fffffff,%o4

	cmp	%o4,%o5			! (Y0_2) ay0 ? 0x7f800000
	bge,pn	%icc,.spec1		! (Y0_2) if( ay0 >= 0x7f800000 )
	nop

	cmp	%i1,MASK_0x007fffff	! (Y0_2) ux0 ? 0x800000
	ble,pn	%icc,.spec2		! (Y0_2) if(ux0 < 0x800000)
	srl	%i3,23,%o3		! (Y0_2) exp0 >>= 23;

	sub	%o3,127,%o3		! (Y0_2) exp0 -= 127;

	add	%g5,CONST_0x8000,%i3	! (Y0_2) i0 = ax0 + 0x8000;

	sll	%o3,8,%o4		! (Y0_2) exp0 <<= 8;
	and	%i3,%l6,%i3		! (Y0_2) i0 &= 0xffff0000;
	st	%o4,[%fp+tmp3]		! (Y0_2) STORE exp0

	sub	%g5,%i3,%o4		! (Y0_2) i0 = ax0 - i0;
	st	%o4,[%fp+tmp2]		! (Y0_2) STORE i0
	add	%o2,stridex,%o2		! px += stridex

	sra	%i3,12,%o0		! (Y0_2) ind0 = i0 >> 12;
	lda	[%o2]0x82,%o3		! (Y1_2) ax0 = *px;

	and	%o0,-8,%g5		! (Y0_2) ind0 &= -8;
	ld	[%fp+tmp2],%f14		! (Y0_2) dtmp0 = (double) i0;

	and	%o3,MASK_0x7fffffff,%i3	! (Y1_2) exp0 = ax0 & 0x7fffffff;
	and	%o3,MASK_0x007fffff,%o0	! (Y1_2) ax0 &= 0x007fffff;

	cmp	%i3,%o5			! (Y1_2) ax0 ? 0x7f800000
	add	%l2,%g5,%g1		! (Y0_2) (char*)__mt_constlog4f + ind0

	srl	%i3,23,%i3		! (Y1_2) exp0 >>= 23;
	add	%o0,CONST_0x8000,%i1	! (Y1_2) i0 = ax0 + 0x8000;

	ldd	[%g1+8],%f48		! (Y0_2) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	sub	%i3,127,%i3		! (Y1_2) exp0 -= 127;
	fitod	%f14,%f60		! (Y0_2) dtmp0 = (double) i0;

	sll	%i3,8,%i3		! (Y1_2) exp0 <<= 8;
	and	%i1,%l6,%i1		! (Y1_2) i0 &= 0xffff0000;
	st	%i3,[%fp+tmp4]		! (Y1_2) STORE exp0

	sub	%o0,%i1,%o0		! (Y1_2) i0 = ax0 - i0;
	st	%o0,[%fp+tmp5]		! (Y1_2) STORE i0
	bge,pn 	%icc,.update0		! (Y1_2) if(ax0 >= 0x7f800000)
	nop
.cont0:
	cmp	%o3,MASK_0x007fffff	! (Y1_2) ux0 ? 0x800000

	fmuld	%f60,%f48,%f48		! (Y0_2) y0 =  dtmp0 * dtmp1;
	ble,pn 	%icc,.update1		! (Y1_2) if(ux0 < 0x800000)
	nop
.cont1:
	fmuld	KA3,%f48,%f62		! (Y0_2) dtmp0 = KA3 * y0;

	faddd	%f62,KA2,%f22		! (Y0_2) dtmp0 += KA2;

	sra	%i1,12,%o1		! (Y1_2) ind0 = i0 >> 12;
	add	%o2,stridex,%i3		! px += stridex
	lda	[stridex+%o2]0x82,%g1	! (Y2_2) ax0 = *px;

	and	%o1,-8,%o0		! (Y1_2) ind0 &= -8;
	ld	[%fp+tmp5],%f12		! (Y1_2) LOAD i0

	and	%g1,MASK_0x7fffffff,%i1	! (Y2_2) exp0 = ax0 & 0x7fffffff;
	and	%g1,MASK_0x007fffff,%o2	! (Y2_2) ax0 &= 0x007fffff;
	lda	[%i2]0x82,%f0		! (Y0_2) ftmp0 = *py0;

	srl	%i1,23,%o3		! (Y2_2) exp0 >>= 23;
	cmp	%i1,%o5			! (Y2_2) ax0 ? 0x7f800000

	fmuld	%f22,%f48,%f26 		! (Y0_2) dtmp0 *= y0;
	add	%l2,%o0,%i1		! (Y1_2) (char*)__mt_constlog4f + ind0
	sub	%o3,127,%l7		! (Y2_2) exp0 -= 127;

	add	%o2,CONST_0x8000,%o1	! (Y2_2) i0 = ax0 + 0x8000;
	ldd	[%i1+8],%f50		! (Y1_2) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	fitod	%f12,%f28		! (Y1_2) dtmp0 = (double) i0;

	sll	%l7,8,%l7		! (Y2_2) exp0 <<= 8;
	and	%o1,%l6,%o1		! (Y2_2) i0 &= 0xffff0000;
	st	%l7,[%fp+tmp6]		! (Y2_2) STORE exp0

	sub	%o2,%o1,%i1		! (Y2_2) i0 = ax0 - i0;
	st	%i1,[%fp+tmp2]		! (Y2_2) STORE i0
	bge,pn	%icc,.update2		! (Y2_2) if(ax0 >= 0x7f800000)
	nop
.cont2:
	cmp	%g1,MASK_0x007fffff	! (Y2_2) ux0 ? 0x800000

	fmuld	%f28,%f50,%f46		! (Y1_2) y0 =  dtmp0 * dtmp1;
	ble,pn	%icc,.update3		! (Y2_2) if(ux0 < 0x800000)
	faddd	%f26,KA1,%f50		! (Y0_2) dtmp0 += KA1;
.cont3:
	ld	[%fp+tmp3],%f4		! (Y0_2) dtmp1 = (double) exp0;

	fstod	%f0,%f24		! (Y0_2) dtmp0 = (double)ftmp0;

	fmuld	KA3,%f46,%f28		! (Y1_1) dtmp0 = KA3 * y0;

	fitod	%f4,%f26		! (Y0_1) dtmp1 = (double) exp0;

	fmuld	%f50,%f48,%f50		! (Y0_1) dtmp0 *= y0;

	faddd	%f28,KA2,%f28		! (Y1_1) dtmp0 += KA2;

	ldd	[%l2+%g5],%f60		! (Y0_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
	add	%i3,stridex,%o2		! px += stridex

	lda	[%o2]0x82,%i1		! (Y0_2) ax0 = *px;
	sra	%o1,12,%g5		! (Y2_1) ind0 = i0 >> 12;

	faddd	%f50,KA0,%f58		! (Y0_1) dtmp0 += KA0;
	and	%g5,-8,%o1		! (Y2_1) ind0 &= -8;
	ld	[%fp+tmp2],%f6		! (Y2_1) dtmp0 = (double) i0;

	and	%i1,MASK_0x7fffffff,%i3	! (Y0_2) exp0 = ax0 & 0x7fffffff;
	and	%i1,MASK_0x007fffff,%g5	! (Y0_2) ax0 &= 0x007fffff;

	srl	%i3,23,%o3		! (Y0_2) exp0 >>= 23;
	add	%l2,%o1,%g1		! (Y2_1) (char*)__mt_constlog4f + ind0
	faddd	%f60,%f26,%f26		! (Y0_1) yy0 = dtmp0 + dtmp1;

	fmuld	%f28,%f46,%f50		! (Y1_1) dtmp0 *= y0;
	sub	%o3,127,%o3		! (Y0_2) exp0 -= 127;
	cmp	%i3,%o5			! (Y0_2) ax0 ? 0x7f800000

	fmuld	%f58,%f48,%f48		! (Y0_1) dtmp0 *= y0;
	add	%g5,CONST_0x8000,%i3	! (Y0_2) i0 = ax0 + 0x8000;
	ldd	[%g1+8],%f58		! (Y2_1) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	fitod	%f6,%f54		! (Y2_1) dtmp0 = (double) i0;

	sll	%o3,8,%o4		! (Y0_2) exp0 <<= 8;
	and	%i3,%l6,%i3		! (Y0_2) i0 &= 0xffff0000;
	st	%o4,[%fp+tmp3]		! (Y0_2) STORE exp0

	sub	%g5,%i3,%o4		! (Y0_2) i0 = ax0 - i0;
	st	%o4,[%fp+tmp2]		! (Y0_2) STORE i0
	bge,pn 	%icc,.update4		! (Y0_2) if( ax0 >= 0x7f800000 )
	nop
.cont4:
	lda	[stridey+%i2]0x82,%g1	! (Y1_1) ay0 = *(unsigned*)py0
	add	%i2,stridey,%o4		! py += stridey
	cmp	%i1,MASK_0x007fffff	! (Y0_2) ux0 ? 0x800000

	fmuld	%f54,%f58,%f28		! (Y2_1) y0 =  dtmp0 * dtmp1;
	lda	[stridey+%i2]0x82,%f2	! (Y1_1) ftmp0 = *py0;
	ble,pn 	%icc,.update5		! (Y0_2) if(ux0 < 0x800000)
	faddd	%f50,KA1,%f54		! (Y1_1) dtmp0 += KA1;
.cont5:
	and	%g1,MASK_0x7fffffff,%g1	! (Y1_1) ay0 &= 0x7fffffff;
	ld	[%fp+tmp4],%f1		! (Y1_1) LOAD exp0
	faddd	%f26,%f48,%f58		! (Y0_1) yy0 += dtmp0;

	cmp	%g1,%o5			! (Y1_1) ay0 ? 0x7f800000
	bge,pn 	%icc,.update6		! (Y1_1) if(ay0 >= 0x7f800000)
	nop
.cont6:
	fmuld	KA3,%f28,%f62		! (Y2_1) dtmp0 = KA3 * y0;
	fstod	%f2,%f22		! (Y1_1) dtmp0 = (double)ftmp0;

	fmuld	%f24,%f58,%f58		! (Y0_1) yy0 *= dtmp0;

	fitod	%f1,%f48		! (Y1_1) dtmp1 = (double) exp0;

	fmuld	%f54,%f46,%f54		! (Y1_1) dtmp0 *= y0;

	faddd	%f62,KA2,%f26		! (Y2_1) dtmp0 += KA2;

	add	%o2,stridex,%o2		! px += stridex
	ldd	[%l2+%o0],%f60		! (Y1_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
	fcmped	%fcc0,HTHRESHOLD,%f58	! (Y0_1) if (yy0 >= HTHRESH)

	sra	%i3,12,%o0		! (Y0_2) ind0 = i0 >> 12;
	lda	[%o2]0x82,%o3		! (Y1_2) ax0 = *px;

	faddd	%f54,KA0,%f56		! (Y1_1) dtmp0 += KA0;
	and	%o0,-8,%g5		! (Y0_2) ind0 &= -8;
	ld	[%fp+tmp2],%f14		! (Y0_2) dtmp0 = (double) i0;

	and	%o3,MASK_0x7fffffff,%i3	! (Y1_2) exp0 = ax0 & 0x7fffffff;
	and	%o3,MASK_0x007fffff,%o0	! (Y1_2) ax0 &= 0x007fffff;

	cmp	%i3,%o5			! (Y1_2) ax0 ? 0x7f800000
	add	%l2,%g5,%g1		! (Y0_2) (char*)__mt_constlog4f + ind0
	faddd	%f60,%f48,%f12		! (Y1_1) yy0 = dtmp0 + dtmp1;

	fmuld	%f26,%f28,%f50		! (Y2_1) dtmp0 *= y0;
	srl	%i3,23,%i3		! (Y1_2) exp0 >>= 23;
	add	%o0,CONST_0x8000,%i1	! (Y1_2) i0 = ax0 + 0x8000;
	fcmped	%fcc1,LTHRESHOLD,%f58	! (Y0_1) if (yy0 <= LTHRESH)

	fmuld	%f56,%f46,%f46		! (Y1_1) dtmp0 *= y0;
	ldd	[%g1+8],%f48		! (Y0_2) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	sub	%i3,127,%i3		! (Y1_2) exp0 -= 127;
	fitod	%f14,%f60		! (Y0_2) dtmp0 = (double) i0;

	sll	%i3,8,%i2		! (Y1_2) exp0 <<= 8;
	and	%i1,%l6,%i1		! (Y1_2) i0 &= 0xffff0000;
	st	%i2,[%fp+tmp4]		! (Y1_2) STORE exp0

	sub	%o0,%i1,%o0		! (Y1_2) i0 = ax0 - i0;
	st	%o0,[%fp+tmp5]		! (Y1_2) STORE i0
	bge,pn 	%icc,.update7		! (Y1_2) if(ax0 >= 0x7f800000)
	nop
.cont7:
	lda	[stridey+%o4]0x82,%i3 	! Y(2_1) ay0 = *py0
	cmp	%o3,MASK_0x007fffff	! (Y1_2) ux0 ? 0x800000
	add	%o4,stridey,%i2		! py += stridey;
	fmovdl	%fcc0,HTHRESHOLD,%f58	! (Y0_1) yy0 = HTHRESH;

	fmuld	%f60,%f48,%f48		! (Y0_2) y0 =  dtmp0 * dtmp1;
	lda	[stridey+%o4]0x82,%f16	! (Y2_1) ftmp0 = *py0;
	ble,pn 	%icc,.update8		! (Y1_2) if(ux0 < 0x800000)
	faddd	%f50,KA1,%f52		! (Y2_1) dtmp0 += KA1;
.cont8:
	and	%i3,MASK_0x7fffffff,%i3	! (Y2_1) ay0 &= 0x7fffffff
	ld	[%fp+tmp6],%f17		! (Y2_1) dtmp1 = (double) exp0;
	faddd	%f12,%f46,%f60		! (Y1_1) yy0 += dtmp0;

	cmp	%i3,%o5			! (Y2_1) ay0 ? 0x7f800000
	bge,pn 	%icc,.update9		! (Y2_1) if(ay0 >= 0x7f800000)
	nop

.cont9:
	fmovdg	%fcc1,LTHRESHOLD,%f58	! (Y0_1) yy0 = LTHRESH;

	fmuld	KA3,%f48,%f62		! (Y0_2) dtmp0 = KA3 * y0;
	fstod	%f16,%f54		! (Y2_1) dtmp0 = (double)ftmp0;

	fmuld	%f22,%f60,%f56		! (Y1_1) yy0 *= dtmp0;

	fitod	%f17,%f24		! (Y2_1) dtmp1 = (double) exp0;

	fmuld	%f52,%f28,%f52		! (Y2_1) dtmp0 *= y0;
	fdtoi	%f58,%f10		! (Y0_1) ind0 = (int) yy0;

	st	%f10,[%fp+tmp0]		! (Y0_1) STORE ind0
	faddd	%f62,KA2,%f22		! (Y0_2) dtmp0 += KA2;

	fcmped	%fcc0,HTHRESHOLD,%f56	! (Y1_1) if (yy0 >= HTHRESH)
	ldd	[%l2+%o1],%f60		! (Y2_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);

	sra	%i1,12,%o1		! (Y1_2) ind0 = i0 >> 12;
	add	%o2,stridex,%i3		! px += stridex
	lda	[stridex+%o2]0x82,%g1	! (Y2_2) ax0 = *px;

	and	%o1,-8,%o0		! (Y1_2) ind0 &= -8;
	add	%i2,stridey,%i2		! py += stridey
	ld	[%fp+tmp5],%f12		! (Y1_2) LOAD i0
	faddd	%f52,KA0,%f4		! (Y2_1) dtmp0 += KA0;

	and	%g1,MASK_0x7fffffff,%i1	! (Y2_2) exp0 = ax0 & 0x7fffffff;
	and	%g1,MASK_0x007fffff,%o2	! (Y2_2) ax0 &= 0x007fffff;
	lda	[%i2]0x82,%f0		! (Y0_2) ftmp0 = *py0;
	fitod	%f10,%f52		! (Y0_1) dtmp0 = (double)ind0;

	srl	%i1,23,%o3		! (Y2_2) exp0 >>= 23;
	cmp	%i1,%o5			! (Y2_2) ax0 ? 0x7f800000
	faddd	%f60,%f24,%f18		! (Y2_1) yy0 = dtmp0 + dtmp1;

	fmuld	%f22,%f48,%f26		! (Y0_2) dtmp0 *= y0;
	add	%l2,%o0,%i1		! (Y1_2) (char*)__mt_constlog4f + ind0
	sub	%o3,127,%l7		! (Y2_2) exp0 -= 127;
	fcmped	%fcc1,LTHRESHOLD,%f56	! (Y1_1) if (yy0 <= LTHRESH)

	fmuld	%f4,%f28,%f24		! (Y2_1) dtmp0 *= y0;
	add	%o2,CONST_0x8000,%o1	! (Y2_2) i0 = ax0 + 0x8000;
	ldd	[%i1+8],%f50		! (Y1_2) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	fitod	%f12,%f28		! (Y1_2) dtmp0 = (double) i0;

	sll	%l7,8,%l7		! (Y2_2) exp0 <<= 8;
	and	%o1,%l6,%o1		! (Y2_2) i0 &= 0xffff0000;
	st	%l7,[%fp+tmp6]		! (Y2_2) STORE exp0
	fsubd	%f58,%f52,%f60		! (Y0_1) y0 = yy0 - dtmp0;


	sub	%o2,%o1,%i1		! (Y2_2) i0 = ax0 - i0;
	st	%i1,[%fp+tmp2]		! (Y2_2) STORE i0
	bge,pn	%icc,.update10		! (Y2_2) if(ax0 >= 0x7f800000)
	nop
.cont10:
	lda	[%i2]0x82,%o2		! (Y0_2) ay0 = *(int*)py0;
	cmp	%g1,MASK_0x007fffff	! (Y2_2) ux0 ? 0x800000
	fmovdl	%fcc0,HTHRESHOLD,%f56	! (Y1_1) yy0 = HTHRESH;

	fmuld	%f28,%f50,%f46		! (Y1_2) y0 =  dtmp0 * dtmp1;
	ble,pn	%icc,.update11		! (Y2_2) if(ux0 < 0x800000)
	faddd	%f26,KA1,%f50		! (Y0_2) dtmp0 += KA1;
.cont11:
	fmuld	KB2,%f60,%f62		! (Y0_1) dtmp0 = KB2 * y0;
	and	%o2,MASK_0x7fffffff,%o2	! (Y0_2) ay0 &= 0x7fffffff
	ld	[%fp+tmp3],%f4		! (Y0_2) dtmp1 = (double) exp0;
	faddd	%f18,%f24,%f52		! (Y2_1) yy0 += dtmp0;

	ld	[%fp+tmp0],%g1		! (Y0_1) LAOD ind0
	cmp	%o2,%o5			! (Y0_2) ay0 ? 0x7f800000
	bge,pn	%icc,.update12		! (Y0_2) if( ay0 >= 0x7f800000)
	nop
.cont12:
	fstod	%f0,%f24		! (Y0_2) dtmp0 = (double)ftmp0;

	cmp	counter,6		! counter
	bl,pn	%icc,.tail
	sub	%i5,stridez,%o4

	ba	.main_loop
	nop

	.align	16
.main_loop:
	fmuld	KA3,%f46,%f28		! (Y1_1) dtmp0 = KA3 * y0;
	and	%g1,255,%o2		! (Y0_0) ind0 &= 255;
	sub	counter,3,counter	! counter
	fmovdg	%fcc1,LTHRESHOLD,%f56	! (Y1_0) yy0 = LTHRESH;

	fmuld	%f54,%f52,%f18		! (Y2_0) yy0 *= dtmp0;
	sll	%o2,3,%i1		! (Y0_0) ind0 <<= 3;
	add	%o4,stridez,%l7     	! pz += stridez
	faddd	%f62,KB1,%f62		! (Y0_0) dtmp0 += KB1;

	fpackfix	%f10,%f10	! (Y0_0) dtmp1 = vis_fpackfix(dtmp1);
	fitod	%f4,%f26		! (Y0_1) dtmp1 = (double) exp0;
	ldd	[%l0+%i1],%f58		! (Y0_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fmuld	%f50,%f48,%f50		! (Y0_1) dtmp0 *= y0;
	fdtoi	%f56,%f20		! (Y1_0) ind0 = (int) yy0;
	st	%f20,[%fp+tmp1]		! (Y1_0) STORE ind0

	faddd	%f28,KA2,%f28		! (Y1_1) dtmp0 += KA2;

	fmuld	%f62,%f60,%f62		! (Y0_0) yy0 = dtmp0 * y0;
	ldd	[%l2+%g5],%f60		! (Y0_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
	add	%i3,stridex,%o2		! px += stridex
	fcmped	%fcc0,HTHRESHOLD,%f18	! (Y2_0) if (yy0 >= HTHRESH)

	lda	[%o2]0x82,%i1		! (Y0_2) ax0 = *px;
	sra	%o1,12,%g5		! (Y2_1) ind0 = i0 >> 12;
	fpadd32	%f10,%f58,%f22		! (Y0_0) di0 = vis_fpadd32(di0,dtmp1);

	faddd	%f50,KA0,%f58		! (Y0_1) dtmp0 += KA0;
	and	%g5,-8,%o1		! (Y2_1) ind0 &= -8;
	ld	[%fp+tmp2],%f6		! (Y2_1) dtmp0 = (double) i0;

	fitod	%f20,%f52		! (Y1_0) dtmp0 = (double)ind0;
	and	%i1,MASK_0x7fffffff,%i3	! (Y0_2) exp0 = ax0 & 0x7fffffff;
	and	%i1,MASK_0x007fffff,%g5	! (Y0_2) ax0 &= 0x007fffff;

	fmuld	%f62,%f22,%f62		! (Y0_0) yy0 *= di0;
	srl	%i3,23,%o3		! (Y0_2) exp0 >>= 23;
	add	%l2,%o1,%g1		! (Y2_1) (char*)__mt_constlog4f + ind0
	faddd	%f60,%f26,%f26		! (Y0_1) yy0 = dtmp0 + dtmp1;

	fmuld	%f28,%f46,%f50		! (Y1_1) dtmp0 *= y0;
	sub	%o3,127,%o3		! (Y0_2) exp0 -= 127;
	cmp	%i3,%o5			! (Y0_2) ax0 ? 0x7f800000
	fcmped	%fcc1,LTHRESHOLD,%f18	! (Y2_0) if (yy0 <= LTHRESH)

	fmuld	%f58,%f48,%f48		! (Y0_1) dtmp0 *= y0;
	add	%g5,CONST_0x8000,%i3	! (Y0_2) i0 = ax0 + 0x8000;
	ldd	[%g1+8],%f58		! (Y2_1) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	fitod	%f6,%f54		! (Y2_1) dtmp0 = (double) i0;

	sll	%o3,8,%o4		! (Y0_2) exp0 <<= 8;
	and	%i3,%l6,%i3		! (Y0_2) i0 &= 0xffff0000;
	st	%o4,[%fp+tmp3]		! (Y0_2) STORE exp0
	fsubd	%f56,%f52,%f52		! (Y1_0) y0 = yy0 - dtmp0;

	sub	%g5,%i3,%o4		! (Y0_2) i0 = ax0 - i0;
	st	%o4,[%fp+tmp2]		! (Y0_2) STORE i0
	bge,pn 	%icc,.update13		! (Y0_2) if( ax0 >= 0x7f800000 )
	faddd	%f62,%f22,%f62		! (Y0_0) yy0 += di0;
.cont13:
	lda	[stridey+%i2]0x82,%g1	! (Y1_1) ay0 = *(unsigned*)py0
	add	%i2,stridey,%o4		! py += stridey
	cmp	%i1,MASK_0x007fffff	! (Y0_2) ux0 ? 0x800000
	fmovdl	%fcc0,HTHRESHOLD,%f18	! (Y2_0) yy0 = HTHRESH;

	fmuld	%f54,%f58,%f28		! (Y2_1) y0 =  dtmp0 * dtmp1;
	lda	[stridey+%i2]0x82,%f2	! (Y1_1) ftmp0 = *py0;
	ble,pn 	%icc,.update14		! (Y0_2) if(ux0 < 0x800000)
	faddd	%f50,KA1,%f54		! (Y1_1) dtmp0 += KA1;
.cont14:
	fmuld	KB2,%f52,%f56		! (Y1_0) dtmp0 = KB2 * y0;
	and	%g1,MASK_0x7fffffff,%g1	! (Y1_1) ay0 &= 0x7fffffff;
	ld	[%fp+tmp4],%f1		! (Y1_1) LOAD exp0
	faddd	%f26,%f48,%f58		! (Y0_1) yy0 += dtmp0;

	ld	[%fp+tmp1],%g5		! (Y1_0) ind0 = (int) yy0;
	cmp	%g1,%o5			! (Y1_1) ay0 ? 0x7f800000
	bge,pn 	%icc,.update15		! (Y1_1) if(ay0 >= 0x7f800000)
	fdtos	%f62,%f8		! (Y0_0) ftmp0 = (float)yy0;
.cont15:
	st	%f8,[%l7]		! (Y0_0) *pz0 = ftmp0;
	fmovdg	%fcc1,LTHRESHOLD,%f18	! (Y2_0) yy0 = LTHRESH;

	add	%l7,stridez,%l7		! pz += stridez
	fmuld	KA3,%f28,%f62		! (Y2_1) dtmp0 = KA3 * y0;
	and	%g5,255,%g5		! (Y1_0) ind0 &= 255;
	fstod	%f2,%f22		! (Y1_1) dtmp0 = (double)ftmp0;

	fmuld	%f24,%f58,%f58		! (Y0_1) yy0 *= dtmp0;
	sll	%g5,3,%i2		! (Y1_0) ind0 <<= 3;
	faddd	%f56,KB1,%f60		! (Y1_0) dtmp0 += KB1;

	fpackfix	%f20,%f20	! (Y1_0) dtmp1 = vis_fpackfix(dtmp1);
	fitod	%f1,%f48		! (Y1_1) dtmp1 = (double) exp0;
	ldd	[%l0+%i2],%f56		! (Y1_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fmuld	%f54,%f46,%f54		! (Y1_1) dtmp0 *= y0;
	fdtoi	%f18,%f2		! (Y2_0) ind0 = (int) yy0;
	st	%f2,[%fp+tmp1]		! (Y2_0) STORE ind0

	faddd	%f62,KA2,%f26		! (Y2_1) dtmp0 += KA2;

	fmuld	%f60,%f52,%f62		! (Y1_0) yy0 = dtmp0 * y0;
	add	%o2,stridex,%o2		! px += stridex
	ldd	[%l2+%o0],%f60		! (Y1_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
	fcmped	%fcc0,HTHRESHOLD,%f58	! (Y0_1) if (yy0 >= HTHRESH)

	fpadd32	%f20,%f56,%f52		! (Y1_0) di0 = vis_fpadd32(di0,dtmp1);
	sra	%i3,12,%o0		! (Y0_2) ind0 = i0 >> 12;
	lda	[%o2]0x82,%o3		! (Y1_2) ax0 = *px;

	faddd	%f54,KA0,%f56		! (Y1_1) dtmp0 += KA0;
	and	%o0,-8,%g5		! (Y0_2) ind0 &= -8;
	ld	[%fp+tmp2],%f14		! (Y0_2) dtmp0 = (double) i0;

	fitod	%f2,%f54		! (Y2_0) dtmp0 = (double)ind0;
	and	%o3,MASK_0x7fffffff,%i3	! (Y1_2) exp0 = ax0 & 0x7fffffff;
	and	%o3,MASK_0x007fffff,%o0	! (Y1_2) ax0 &= 0x007fffff;

	fmuld	%f62,%f52,%f62		! (Y1_0) yy0 *= di0;
	cmp	%i3,%o5			! (Y1_2) ax0 ? 0x7f800000
	add	%l2,%g5,%g1		! (Y0_2) (char*)__mt_constlog4f + ind0
	faddd	%f60,%f48,%f12		! (Y1_1) yy0 = dtmp0 + dtmp1;

	fmuld	%f26,%f28,%f50		! (Y2_1) dtmp0 *= y0;
	srl	%i3,23,%i3		! (Y1_2) exp0 >>= 23;
	add	%o0,CONST_0x8000,%i1	! (Y1_2) i0 = ax0 + 0x8000;
	fcmped	%fcc1,LTHRESHOLD,%f58	! (Y0_1) if (yy0 <= LTHRESH)

	fmuld	%f56,%f46,%f46		! (Y1_1) dtmp0 *= y0;
	ldd	[%g1+8],%f48		! (Y0_2) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	sub	%i3,127,%i3		! (Y1_2) exp0 -= 127;
	fitod	%f14,%f60		! (Y0_2) dtmp0 = (double) i0;

	sll	%i3,8,%i2		! (Y1_2) exp0 <<= 8;
	and	%i1,%l6,%i1		! (Y1_2) i0 &= 0xffff0000;
	st	%i2,[%fp+tmp4]		! (Y1_2) STORE exp0
	fsubd	%f18,%f54,%f26		! (Y2_0) y0 = yy0 - dtmp0;

	sub	%o0,%i1,%o0		! (Y1_2) i0 = ax0 - i0;
	st	%o0,[%fp+tmp5]		! (Y1_2) STORE i0
	bge,pn 	%icc,.update16		! (Y1_2) if(ax0 >= 0x7f800000)
	faddd	%f62,%f52,%f54		! (Y1_0) yy0 += di0;
.cont16:
	lda	[stridey+%o4]0x82,%i3 	! Y(2_1) ay0 = *py0
	cmp	%o3,MASK_0x007fffff	! (Y1_2) ux0 ? 0x800000
	add	%o4,stridey,%i2		! py += stridey;
	fmovdl	%fcc0,HTHRESHOLD,%f58	! (Y0_1) yy0 = HTHRESH;

	fmuld	%f60,%f48,%f48		! (Y0_2) y0 =  dtmp0 * dtmp1;
	lda	[stridey+%o4]0x82,%f16	! (Y2_1) ftmp0 = *py0;
	ble,pn 	%icc,.update17		! (Y1_2) if(ux0 < 0x800000)
	faddd	%f50,KA1,%f52		! (Y2_1) dtmp0 += KA1;
.cont17:
	fmuld	KB2,%f26,%f4		! (Y2_0) dtmp0 = KB2 * y0;
	and	%i3,MASK_0x7fffffff,%i3	! (Y2_1) ay0 &= 0x7fffffff
	ld	[%fp+tmp6],%f17		! (Y2_1) dtmp1 = (double) exp0;
	faddd	%f12,%f46,%f60		! (Y1_1) yy0 += dtmp0;

	ld	[%fp+tmp1],%o0
	cmp	%i3,%o5			! (Y2_1) ay0 ? 0x7f800000
	bge,pn 	%icc,.update18		! (Y2_1) if(ay0 >= 0x7f800000)
	fdtos	%f54,%f15		! (Y1_0) ftmp0 = (float)yy0;
.cont18:
	st	%f15,[%l7]		! (Y1_0) *pz0 = ftmp0;
	add	%l7,stridez,%o4		! pz += stridez
	fmovdg	%fcc1,LTHRESHOLD,%f58	! (Y0_1) yy0 = LTHRESH;

	fmuld	KA3,%f48,%f62		! (Y0_2) dtmp0 = KA3 * y0;
	and	%o0,255,%o0		! (Y2_0) ind0 &= 255;
	fstod	%f16,%f54		! (Y2_1) dtmp0 = (double)ftmp0;

	fmuld	%f22,%f60,%f56		! (Y1_1) yy0 *= dtmp0;
	sll	%o0,3,%l7		! (Y2_0) ind0 <<= 3;
	faddd	%f4,KB1,%f60		! (Y2_0) dtmp0 += KB1;

	fpackfix	%f2,%f2		! (Y2_0) dtmp1 = vis_fpackfix(dtmp1);
	fitod	%f17,%f24		! (Y2_1) dtmp1 = (double) exp0;
	ldd	[%l0+%l7],%f4		! (Y2_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fmuld	%f52,%f28,%f52		! (Y2_1) dtmp0 *= y0;
	fdtoi	%f58,%f10		! (Y0_1) ind0 = (int) yy0;

	st	%f10,[%fp+tmp0]		! (Y0_1) STORE ind0
	faddd	%f62,KA2,%f22		! (Y0_2) dtmp0 += KA2;

	fmuld	%f60,%f26,%f62		! (Y2_0) yy0 = dtmp0 * y0;
	fcmped	%fcc0,HTHRESHOLD,%f56	! (Y1_1) if (yy0 >= HTHRESH)
	ldd	[%l2+%o1],%f60		! (Y2_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);

	sra	%i1,12,%o1		! (Y1_2) ind0 = i0 >> 12;
	add	%o2,stridex,%i3		! px += stridex
	lda	[stridex+%o2]0x82,%g1	! (Y2_2) ax0 = *px;
	fpadd32	%f2,%f4,%f46		! (Y2_0) di0 = vis_fpadd32(di0,dtmp1);

	and	%o1,-8,%o0		! (Y1_2) ind0 &= -8;
	add	%i2,stridey,%i2		! py += stridey
	ld	[%fp+tmp5],%f12		! (Y1_2) LOAD i0
	faddd	%f52,KA0,%f4		! (Y2_1) dtmp0 += KA0;

	and	%g1,MASK_0x7fffffff,%i1	! (Y2_2) exp0 = ax0 & 0x7fffffff;
	and	%g1,MASK_0x007fffff,%o2	! (Y2_2) ax0 &= 0x007fffff;
	lda	[%i2]0x82,%f0		! (Y0_2) ftmp0 = *py0;
	fitod	%f10,%f52		! (Y0_1) dtmp0 = (double)ind0;

	fmuld	%f62,%f46,%f62		! (Y2_0) yy0 *= di0;
	srl	%i1,23,%o3		! (Y2_2) exp0 >>= 23;
	cmp	%i1,%o5			! (Y2_2) ax0 ? 0x7f800000
	faddd	%f60,%f24,%f18		! (Y2_1) yy0 = dtmp0 + dtmp1;

	fmuld	%f22,%f48,%f26		! (Y0_2) dtmp0 *= y0;
	add	%l2,%o0,%i1		! (Y1_2) (char*)__mt_constlog4f + ind0
	sub	%o3,127,%l7		! (Y2_2) exp0 -= 127;
	fcmped	%fcc1,LTHRESHOLD,%f56	! (Y1_1) if (yy0 <= LTHRESH)

	fmuld	%f4,%f28,%f24		! (Y2_1) dtmp0 *= y0;
	add	%o2,CONST_0x8000,%o1	! (Y2_2) i0 = ax0 + 0x8000;
	ldd	[%i1+8],%f50		! (Y1_2) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	fitod	%f12,%f28		! (Y1_2) dtmp0 = (double) i0;

	sll	%l7,8,%l7		! (Y2_2) exp0 <<= 8;
	and	%o1,%l6,%o1		! (Y2_2) i0 &= 0xffff0000;
	st	%l7,[%fp+tmp6]		! (Y2_2) STORE exp0
	fsubd	%f58,%f52,%f60		! (Y0_1) y0 = yy0 - dtmp0;

	sub	%o2,%o1,%i1		! (Y2_2) i0 = ax0 - i0;
	st	%i1,[%fp+tmp2]		! (Y2_2) STORE i0
	bge,pn	%icc,.update19		! (Y2_2) if(ax0 >= 0x7f800000)
	faddd	%f62,%f46,%f22		! (Y2_0) yy0 += di0;
.cont19:
	lda	[%i2]0x82,%o2		! (Y0_2) ay0 = *(int*)py0;
	cmp	%g1,MASK_0x007fffff	! (Y2_2) ux0 ? 0x800000
	fmovdl	%fcc0,HTHRESHOLD,%f56	! (Y1_1) yy0 = HTHRESH;

	fmuld	%f28,%f50,%f46		! (Y1_2) y0 =  dtmp0 * dtmp1;
	ble,pn	%icc,.update20		! (Y2_2) if(ux0 < 0x800000)
	faddd	%f26,KA1,%f50		! (Y0_2) dtmp0 += KA1;
.cont20:
	fmuld	KB2,%f60,%f62		! (Y0_1) dtmp0 = KB2 * y0;
	and	%o2,MASK_0x7fffffff,%o2	! (Y0_2) ay0 &= 0x7fffffff
	ld	[%fp+tmp3],%f4		! (Y0_2) dtmp1 = (double) exp0;
	faddd	%f18,%f24,%f52		! (Y2_1) yy0 += dtmp0;

	ld	[%fp+tmp0],%g1		! (Y0_1) LAOD ind0
	cmp	%o2,%o5			! (Y0_2) ay0 ? 0x7f800000
	bge,pn	%icc,.update21		! (Y0_2) if( ay0 >= 0x7f800000)
	fdtos	%f22,%f12		! (Y2_0) ftmp0 = (float)yy0;
.cont21:
	st	%f12,[%o4]		! (Y2_0) *pz0 = ftmp0;
	cmp	counter,6		! counter
	bge,pt	%icc,.main_loop
	fstod	%f0,%f24		! (Y0_2) dtmp0 = (double)ftmp0;

.tail:
	subcc	counter,1,counter
	bneg,pn	%icc,.begin
	add	%o4,stridez,%i5

	fmuld	KA3,%f46,%f28		! (Y1_1) dtmp0 = KA3 * y0;
	and	%g1,255,%o2		! (Y0_0) ind0 &= 255;
	fmovdg	%fcc1,LTHRESHOLD,%f56	! (Y1_0) yy0 = LTHRESH;

	fmuld	%f54,%f52,%f18		! (Y2_0) yy0 *= dtmp0;
	sll	%o2,3,%i1		! (Y0_0) ind0 <<= 3;
	add	%o4,stridez,%l7    	! pz += stridez
	faddd	%f62,KB1,%f62		! (Y0_0) dtmp0 += KB1;

	fpackfix	%f10,%f10	! (Y0_0) dtmp1 = vis_fpackfix(dtmp1);
	fitod	%f4,%f26		! (Y0_1) dtmp1 = (double) exp0;
	ldd	[%l0+%i1],%f58		! (Y0_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fmuld	%f50,%f48,%f50		! (Y0_1) dtmp0 *= y0;
	fdtoi	%f56,%f20		! (Y1_0) ind0 = (int) yy0;
	st	%f20,[%fp+tmp1]		! (Y1_0) STORE ind0

	faddd	%f28,KA2,%f28		! (Y1_1) dtmp0 += KA2;

	fmuld	%f62,%f60,%f62		! (Y0_0) yy0 = dtmp0 * y0;
	ldd	[%l2+%g5],%f60		! (Y0_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
	fcmped	%fcc0,HTHRESHOLD,%f18	! (Y2_0) if (yy0 >= HTHRESH)

	fpadd32	%f10,%f58,%f22		! (Y0_0) di0 = vis_fpadd32(di0,dtmp1);

	faddd	%f50,KA0,%f58		! (Y0_1) dtmp0 += KA0;

	fitod	%f20,%f52		! (Y1_0) dtmp0 = (double)ind0;

	fmuld	%f62,%f22,%f62		! (Y0_0) yy0 *= di0;
	faddd	%f60,%f26,%f26		! (Y0_1) yy0 = dtmp0 + dtmp1;

	fmuld	%f28,%f46,%f50		! (Y1_1) dtmp0 *= y0;
	fcmped	%fcc1,LTHRESHOLD,%f18	! (Y2_0) if (yy0 <= LTHRESH)

	fmuld	%f58,%f48,%f48		! (Y0_1) dtmp0 *= y0;

	fsubd	%f56,%f52,%f52		! (Y1_0) y0 = yy0 - dtmp0;

	faddd	%f62,%f22,%f62		! (Y0_0) yy0 += di0;

	lda	[stridey+%i2]0x82,%g1	! (Y1_1) ay0 = *(unsigned*)py0
	add	%i2,stridey,%o4		! py += stridey
	fmovdl	%fcc0,HTHRESHOLD,%f18	! (Y2_0) yy0 = HTHRESH;

	lda	[stridey+%i2]0x82,%f2	! (Y1_1) ftmp0 = *py0;
	faddd	%f50,KA1,%f54		! (Y1_1) dtmp0 += KA1;

	fmuld	KB2,%f52,%f56		! (Y1_0) dtmp0 = KB2 * y0;
	and	%g1,MASK_0x7fffffff,%g1	! (Y1_1) ay0 &= 0x7fffffff;
	ld	[%fp+tmp4],%f1		! (Y1_1) LOAD exp0
	faddd	%f26,%f48,%f58		! (Y0_1) yy0 += dtmp0;

	ld	[%fp+tmp1],%g5		! (Y1_0) ind0 = (int) yy0;
	cmp	%g1,%o5			! (Y1_1) ay0 ? 0x7f800000
	bge,pn 	%icc,.update22		! (Y1_1) if(ay0 >= 0x7f800000)
	fdtos	%f62,%f8		! (Y0_0) ftmp0 = (float)yy0;
.cont22:
	st	%f8,[%l7]		! (Y0_0) *pz0 = ftmp0;
	fmovdg	%fcc1,LTHRESHOLD,%f18	! (Y2_0) yy0 = LTHRESH;

	subcc	counter,1,counter
	bneg,pn %icc,.begin
	add	%l7,stridez,%i5

	add	%l7,stridez,%l7		! pz += stridez
	and	%g5,255,%g5		! (Y1_0) ind0 &= 255;
	fstod	%f2,%f22		! (Y1_1) dtmp0 = (double)ftmp0;

	fmuld	%f24,%f58,%f58		! (Y0_1) yy0 *= dtmp0;
	sll	%g5,3,%i2		! (Y1_0) ind0 <<= 3;
	faddd	%f56,KB1,%f60		! (Y1_0) dtmp0 += KB1;

	fpackfix	%f20,%f20	! (Y1_0) dtmp1 = vis_fpackfix(dtmp1);
	fitod	%f1,%f48		! (Y1_1) dtmp1 = (double) exp0;
	ldd	[%l0+%i2],%f56		! (Y1_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fmuld	%f54,%f46,%f54		! (Y1_1) dtmp0 *= y0;
	fdtoi	%f18,%f2		! (Y2_0) ind0 = (int) yy0;
	st	%f2,[%fp+tmp1]		! (Y2_0) STORE ind0


	fmuld	%f60,%f52,%f62		! (Y1_0) yy0 = dtmp0 * y0;
	ldd	[%l2+%o0],%f60		! (Y1_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
	fcmped	%fcc0,HTHRESHOLD,%f58	! (Y0_1) if (yy0 >= HTHRESH)

	fpadd32	%f20,%f56,%f52		! (Y1_0) di0 = vis_fpadd32(di0,dtmp1);

	faddd	%f54,KA0,%f56		! (Y1_1) dtmp0 += KA0;

	fitod	%f2,%f54		! (Y2_0) dtmp0 = (double)ind0;

	fmuld	%f62,%f52,%f62		! (Y1_0) yy0 *= di0;
	faddd	%f60,%f48,%f12		! (Y1_1) yy0 = dtmp0 + dtmp1;

	fcmped	%fcc1,LTHRESHOLD,%f58	! (Y0_1) if (yy0 <= LTHRESH)

	fmuld	%f56,%f46,%f46		! (Y1_1) dtmp0 *= y0;

	fsubd	%f18,%f54,%f26		! (Y2_0) y0 = yy0 - dtmp0;

	faddd	%f62,%f52,%f54		! (Y1_0) yy0 += di0;

	fmovdl	%fcc0,HTHRESHOLD,%f58	! (Y0_1) yy0 = HTHRESH;


	fmuld	KB2,%f26,%f4		! (Y2_0) dtmp0 = KB2 * y0;
	faddd	%f12,%f46,%f60		! (Y1_1) yy0 += dtmp0;

	ld	[%fp+tmp1],%o0
	fdtos	%f54,%f15		! (Y1_0) ftmp0 = (float)yy0;

	st	%f15,[%l7]		! (Y1_0) *pz0 = ftmp0;
	add	%l7,stridez,%o4		! pz += stridez
	fmovdg	%fcc1,LTHRESHOLD,%f58	! (Y0_1) yy0 = LTHRESH;

	subcc	counter,1,counter
	bneg,pn %icc,.begin
	or	%g0,%o4,%i5

	and	%o0,255,%o0		! (Y2_0) ind0 &= 255;

	fmuld	%f22,%f60,%f56		! (Y1_1) yy0 *= dtmp0;
	sll	%o0,3,%l7		! (Y2_0) ind0 <<= 3;
	faddd	%f4,KB1,%f60		! (Y2_0) dtmp0 += KB1;

	fpackfix	%f2,%f2		! (Y2_0) dtmp1 = vis_fpackfix(dtmp1);
	ldd	[%l0+%l7],%f4		! (Y2_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fdtoi	%f58,%f10		! (Y0_1) ind0 = (int) yy0;

	st	%f10,[%fp+tmp0]		! (Y0_1) STORE ind0

	fmuld	%f60,%f26,%f62		! (Y2_0) yy0 = dtmp0 * y0;
	fcmped	%fcc0,HTHRESHOLD,%f56	! (Y1_1) if (yy0 >= HTHRESH)

	fpadd32	%f2,%f4,%f46		! (Y2_0) di0 = vis_fpadd32(di0,dtmp1);

	add	%i2,stridey,%i2		! py += stridey

	fitod	%f10,%f52		! (Y0_1) dtmp0 = (double)ind0;

	fmuld	%f62,%f46,%f62		! (Y2_0) yy0 *= di0;

	fcmped	%fcc1,LTHRESHOLD,%f56	! (Y1_1) if (yy0 <= LTHRESH)


	fsubd	%f58,%f52,%f60		! (Y0_1) y0 = yy0 - dtmp0;

	faddd	%f62,%f46,%f22		! (Y2_0) yy0 += di0;

	fmovdl	%fcc0,HTHRESHOLD,%f56	! (Y1_1) yy0 = HTHRESH;

	fmuld	KB2,%f60,%f62		! (Y0_1) dtmp0 = KB2 * y0;

	ld	[%fp+tmp0],%g1		! (Y0_1) LAOD ind0
	fdtos	%f22,%f12		! (Y2_0) ftmp0 = (float)yy0;

	st	%f12,[%o4]		! (Y2_0) *pz0 = ftmp0;

	subcc	counter,1,counter
	bneg,pn %icc,.begin
	add	%o4,stridez,%i5

	and	%g1,255,%o2		! (Y0_0) ind0 &= 255;
	fmovdg	%fcc1,LTHRESHOLD,%f56	! (Y1_0) yy0 = LTHRESH;

	sll	%o2,3,%i1		! (Y0_0) ind0 <<= 3;
	add	%o4,stridez,%l7    	! pz += stridez
	faddd	%f62,KB1,%f62		! (Y0_0) dtmp0 += KB1;

	fpackfix	%f10,%f10	! (Y0_0) dtmp1 = vis_fpackfix(dtmp1);
	ldd	[%l0+%i1],%f58		! (Y0_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fdtoi	%f56,%f20		! (Y1_0) ind0 = (int) yy0;
	st	%f20,[%fp+tmp1]		! (Y1_0) STORE ind0

	fmuld	%f62,%f60,%f62		! (Y0_0) yy0 = dtmp0 * y0;

	fpadd32	%f10,%f58,%f22		! (Y0_0) di0 = vis_fpadd32(di0,dtmp1);

	fitod	%f20,%f52		! (Y1_0) dtmp0 = (double)ind0;

	fmuld	%f62,%f22,%f62		! (Y0_0) yy0 *= di0;

	fsubd	%f56,%f52,%f52		! (Y1_0) y0 = yy0 - dtmp0;

	faddd	%f62,%f22,%f62		! (Y0_0) yy0 += di0;

	fmuld	KB2,%f52,%f56		! (Y1_0) dtmp0 = KB2 * y0;

	ld	[%fp+tmp1],%g5		! (Y1_0) ind0 = (int) yy0;
	fdtos	%f62,%f8		! (Y0_0) ftmp0 = (float)yy0;
	st	%f8,[%l7]		! (Y0_0) *pz0 = ftmp0;

	subcc	counter,1,counter
	bneg	.begin
	add	%l7,stridez,%i5

	add	%l7,stridez,%l7		! pz += stridez
	and	%g5,255,%g5		! (Y1_0) ind0 &= 255;

	sll	%g5,3,%i2		! (Y1_0) ind0 <<= 3;
	faddd	%f56,KB1,%f60		! (Y1_0) dtmp0 += KB1;

	fpackfix	%f20,%f20	! (Y1_0) dtmp1 = vis_fpackfix(dtmp1);
	ldd	[%l0+%i2],%f56		! (Y1_0) di0 = *(double*)((char*)__mt_constexp2f + ind0);

	fmuld	%f60,%f52,%f62		! (Y1_0) yy0 = dtmp0 * y0;

	fpadd32	%f20,%f56,%f52		! (Y1_0) di0 = vis_fpadd32(di0,dtmp1);

	fmuld	%f62,%f52,%f62		! (Y1_0) yy0 *= di0;

	faddd	%f62,%f52,%f54		! (Y1_0) yy0 += di0;

	fdtos	%f54,%f15		! (Y1_0) ftmp0 = (float)yy0;

	st	%f15,[%l7]		! (Y1_0) *pz0 = ftmp0;
	ba	.begin
	add	%l7,stridez,%i5		! pz += stridez

.exit:
	ret
	restore

	.align	16
.specs_exit:
	add	%i1,stridex,%o2
	add	%i3,stridey,%i2
	st	%f4,[%i5]

	sub	counter,1,counter
	ba	.begin1
	add	%i5,stridez,%i5

.spec1:
	ld	[%l0+2048+64],%f0	! LOAD 1.0f
	or	%g0,%i1,%o1
	or	%g0,%i3,%o3

	ld	[%o2],%f4		! *px
	or	%g0,%o2,%i1
	or	%g0,%i2,%i3

	ld	[%i3],%f6		! *py
	or	%g0,%l7,%o2
	fsubs	%f0,%f0,%f5		! 0.0f

	sethi	%hi(0x7f800000),%l6
	cmp	%o4,0			! ay ? 0
	be,a,pn	%icc,.specs_exit	! if(ay == 0)
	fmovs	%f0,%f4			! return 1.0f

	cmp	%o3,%l6			! ax0 ? 0x7f800000
	bgu,a	%icc,.specs_exit	! ax0 > 0x7f800000
	fmuls	%f4,%f6,%f4		! return *px * *py; /* |X| or |Y| = Nan */

	cmp	%o4,%l6			! ay ? 0x7f800000
	bgu,a	.specs_exit		! ay > 0x7f800000
	fmuls	%f4,%f6,%f4		! return *px * *py; /* |X| or |Y| = Nan */

	sethi	%hi(0x3f800000),%o5
	bne,a	%icc,1f			! if (ay != 0x7f800000) { /* |Y| = Inf */
	srl	%o1,31,%o1		! sx = ux >> 31

	cmp	%o3,%o5			! ax0 ? 0x3f800000
	be,a	.specs_exit		! if (ax0 == 0x3f800000)
	fmuls	%f6,%f5,%f4		! return *py * 0.0f; /* +-1 ** +-Inf = NaN */

	sub	%o3,%o5,%o3		! ax0 - 0x3f800000
	srl	%o2,31,%o2		! uy >> 31

	srlx	%o3,63,%o3		! (ax0 - 0x3f800000) << 63

	cmp	%o3,%o2			! ((ax0 - 0x3f800000) << 63) ? (uy >> 31)
	bne,a	.specs_exit
	fzeros	%f4			! return 0.f;

	ba	.specs_exit
	fabss	%f6,%f4			! return fabss(*py)
1:
	cmp	%o1,0			! sx ? 0
	be,pn	%icc,.spec1_exit	! if (sx == 0)
	or	%g0,%g0,%o5		! yisint0 = 0;

	srl	%o4,23,%l7		! exp = ay >> 23;
	cmp	%l7,0x97		! exp ? 0x97
	bge,a,pn %icc,.spec1_exit	! if (exp >= 0x97) /* |Y| >= 2^24  */
	add	%g0,2,%o5		! yisint = 2;

	cmp	%l7,0x7f		! exp ? 0x7f
	bl,pn	%icc,.spec1_exit	! if (exp < 0x7f)
	sub	%g0,%l7,%l7		! exp = -exp;

	add	%l7,(0x7f + 23),%l7	! exp += (0x07f + 23);
	srl	%o4,%l7,%l6		! i0 = ay >> exp
	sll	%l6,%l7,%l7		! i0 << exp

	cmp	%l7,%o4			! (i0 << exp) ? ay
	bne,pn	%icc,.spec1_exit	! if((i0 << exp) != ay)
	and	%l6,1,%l6		! i0 &= 1

	sub	%g0,%l6,%l6		! i0 = -i0;
	add	%l6,2,%o5		! yisint0 = 2 + i0;

.spec1_exit:
	srl	%o2,31,%o2		! uy >> 31
	cmp	%o2,0			! (uy >> 31) ? 0
	movne	%icc,%g0,%o3		! if (uy >> 31) ax0 = 0;

	sll	%o5,31,%o5		! yisint0 <<= 31;
	add	%o5,%o3,%o5		! ax0 += yisint0;

	add	%i1,stridex,%o2		! px += stridex;
	add	%i3,stridey,%i2		! py += stridey;
	st	%o5,[%i5]		! return *(float*)&ax0;

	sub	counter,1,counter	! counter--;
	ba	.begin1
	add	%i5,stridez,%i5		! pz += stridez;

.spec2:
	or	%g0,%i1,%o1
	or	%g0,%i3,%o3
	ld	[%l0+2048+64],%f0	! LOAD 1.0f
	or	%g0,%o2,%i1
	or	%g0,%i2,%i3

	or	%g0,%l7,%o2
	cmp	%o4,0			! ay ? 0
	be,a,pn	%icc,.specs_exit	! if(ay == 0)
	fmovs	%f0,%f4			! return 1.0f

	srl	%o3,23,%l7		! exp0 = (ax0 >> 23);
	sub	%l7,127,%l7		! exp = exp0 = exp0 - 127;

	or	%g0,%g0,%o5		! yisint = 0;
	cmp	%o3,MASK_0x007fffff	! (int)ax0 ? 0x00800000
	bg,pn	%icc,1f			! if ((int)ax0 >= 0x00800000)
	nop

					! X = denormal or negative
	st	%o3,[%fp+tmp0]		! *((float*) &ax0) = (float) (int)ax0;
	ld	[%fp+tmp0],%f4
	fitos	%f4,%f4
	st	%f4,[%fp+tmp0]
	ld	[%fp+tmp0],%o3

	srl	%o3,23,%l7		! exp = (ax0 >> 23)
	sub	%l7,127+149,%l7		! exp -= (127+149)
1:
	cmp	%o1,0			! ux ? 0
	bg,a	%icc,.spec_proc		! if((int)ux > 0)
	sethi	%hi(0xffff0000),%l6

	srl	%o4,23,%o0		! exp = ay >> 23;
	cmp	%o0,0x97		! exp ? 0x97
	bge,a,pn %icc,2f		! if (exp >= 0x97) /* |Y| >= 2^24  */
	add	%g0,2,%o5		! yisint0 = 2;     /* Y - even */

	cmp	%o0,0x7f		! exp ? 0x7f
	bl,pn	%icc,2f			! if(exp < 0x7f)
	nop

	sub	%g0,%o0,%o0		! exp = -exp;
	add	%o0,(0x7f + 23),%o0	! exp += (0x7f + 23)
	srl	%o4,%o0,%l6		! i0 = ay >> ((0x7f + 23) - exp);
	sll	%l6,%o0,%o0		! i0 << ((0x7f + 23) - exp
	cmp	%o0,%o4			! (i0 << ((0x7f + 23) - exp)) ? ay
	bne,pn	%icc,2f			! if(i0 << ((0x7f + 23) - exp)) != ay)
	nop

	and	%l6,1,%l6		! i0 &= 1;
	sub	%g0,%l6,%l6		! i0 = -i0;
	add	%l6,2,%o5		! yisint = i0 + 2;
2:
	cmp	%o3,0			! ax0 ? 0
	bne,pn	%icc,4f			! if(ax0 != 0)
	nop

	srl	%o1,31,%o1		! sx = ux >> 31
	srl	%o2,31,%o2		! uy >> 31

	cmp	%o2,0			! (uy >> 31) ? 0
	be,a,pn	%icc,3f			! if((uy >> 31) == 0)
	fzeros	%f4			! return ZERO

	fdivs	%f0,%f3,%f4		! fy = ONE/ZERO
3:
	andcc	%o1,%o5,%g0		! sx & yisint0
	be,pn	%icc,.specs_exit	! if( (sx & yisint0) == 0 )
	nop

	ba	.specs_exit
	fnegs	%f4,%f4			! fy = -fy;
4:
	cmp	%o5,0			! ysisint0 ? 0
	be,a	%icc,.specs_exit	! if(yisint0 == 0)
	fdivs	%f3,%f3,%f4		! return ZERO/ZERO

	sethi	%hi(0xffff0000),%l6

.spec_proc:
	sll	%l7,8,%l7		! exp0 = exp0 << 8;
	st	%l7,[%fp+tmp1]		! STORE exp0
	and	%o3,MASK_0x007fffff,%g5	! ax0 &= 0x007fffff;
	ld	[%i3],%f14		! ftmp0 = py[0]
	sllx	%o5,63,%o5		! ysisint0 <<= 63;
	add	%g5,CONST_0x8000,%o3	! i0 = ax0 + 0x8000;
	stx	%o5,[%fp+tmp5]		! STORE yisint0
	and	%o3,%l6,%l7		! i0 &= 0xffff0000;
	sub	%g5,%l7,%o1		! i0 = ax0 - i0;
	sra	%l7,12,%g5		! ind0 = i0 >> 12;
	st	%o1,[%fp+tmp2]		! STORE i0
	fstod	%f14,%f54		! dtmp1 = (double)ftmp0
	and	%g5,-8,%g5		! ind0 &= -8;
	add	%l2,%g5,%l7		! (char*)__mt_constlog4f + ind0
	ld	[%fp+tmp1],%f18		! LOAD exp0
	ld	[%fp+tmp2],%f16		! LOAD i0
	ldd	[%l7+8],%f62		! dtmp2 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	ldd	[%l2+%g5],%f56		! dtmp3 = *(double *)((char*)__mt_constlog4f + ind0);
	fitod	%f18,%f58		! dtmp4 = (double)exp0
	fitod	%f16,%f60		! dtmp5 = (double)i0
	fmuld	%f60,%f62,%f60		! y0 =  dtmp5 * dtmp2;
	faddd	%f56,%f58,%f58		! yy0 = dtmp3 + dtmp4;
	fmuld	KA3,%f60,%f52		! dtmp0 = KA3 * y0;
	faddd	%f52,KA2,%f50		! dtmp0 += KA2;
	fmuld	%f50,%f60,%f48		! dtmp0 *= y0;
	faddd	%f48,KA1,%f46		! dtmp0 += KA1;
	fmuld	%f46,%f60,%f62		! dtmp0 *= y0;
	ldd	[%fp+tmp5],%f24		! LOAD yisint0
	faddd	%f62,KA0,%f56		! dtmp0 += KA0;
	fmuld	%f56,%f60,%f52		! dtmp0 *= y0;
	faddd	%f58,%f52,%f50		! yy0 += dtmp1;
	fmuld	%f54,%f50,%f52		! yy0 *= dtmp1;
	fcmped	%fcc0,HTHRESHOLD,%f52	! if (yy0 >= HTHRESH)
	fcmped	%fcc1,LTHRESHOLD,%f52	! yy0 = HTHRESH;
	fmovdl	%fcc0,HTHRESHOLD,%f52	! if (yy0 <= LTHRESH)
	fmovdg	%fcc1,LTHRESHOLD,%f52	! yy0 = LTHRESH;
	fdtoi	%f52,%f20		! ind0 = (int) yy0;
	st	%f20,[%fp+tmp3]		! STORE ind0
	fitod	%f20,%f58		! dtmp0 = (double) ind0;
	fpackfix	%f20,%f20	! dtmp1 = vis_fpackfix(dtmp1)
	ld	[%fp+tmp3],%g1		! LOAD ind0
	fsubd	%f52,%f58,%f46		! y0 = yy0 - dtmp0;
	fpadd32	%f20,%f24,%f56		! dtmp1 += yisint0
	and	%g1,255,%o4		! ind0 &= 255;
	sll	%o4,3,%o3		! ind0 <<= 3;
	ldd	[%l0+%o3],%f54		! di0 = *(double*)((char*)__mt_constexp2f + ind0);
	fmuld	KB2,%f46,%f48		! dtmp0 = KB2 * y0;
	fpadd32	%f56,%f54,%f56		! di0 = vis_fpadd32(di0,dtmp1);
	faddd	%f48,KB1,%f62		! dtmp0 += KB1;
	fmuld	%f62,%f46,%f60		! yy0 = dtmp0 * y0;
	fmuld	%f60,%f56,%f52		! yy0 *= di0;
	faddd	%f52,%f56,%f58		! yy0 += di0;
	ba	.specs_exit
	fdtos	%f58,%f4		! ftmp0 = (float)yy0;

	.align	16
.update0:
	cmp	counter,1
	ble	.cont0
	nop

	add	%i2,stridey,%o1
	stx	%o2,[%fp+tmp_px]

	stx	%o1,[%fp+tmp_py]
	sub	counter,1,counter

	st	counter,[%fp+tmp_counter]
	ba	.cont0
	or	%g0,1,counter

	.align	16
.update1:
	cmp	counter,1
	ble	.cont1
	nop

	add	%i2,stridey,%o1
	stx	%o2,[%fp+tmp_px]

	stx	%o1,[%fp+tmp_py]
	sub	counter,1,counter

	st	counter,[%fp+tmp_counter]
	ba	.cont1
	or	%g0,1,counter

	.align	16
.update2:
	cmp	counter,2
	ble	.cont2
	nop

	add	%i2,stridey,%o2
	stx	%i3,[%fp+tmp_px]

	add	%o2,stridey,%o2
	stx	%o2,[%fp+tmp_py]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont2
	or	%g0,2,counter

	.align	16
.update3:
	cmp	counter,2
	ble	.cont3
	nop

	add	%i2,stridey,%o2
	stx	%i3,[%fp+tmp_px]

	add	%o2,stridey,%o2
	stx	%o2,[%fp+tmp_py]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont3
	or	%g0,2,counter

	.align	16
.update4:
	cmp	counter,3
	ble	.cont4
	nop

	sll	stridey,1,%g5
	add	%i2,stridey,%o3
	stx	%o2,[%fp+tmp_px]

	add	%o3,%g5,%o3
	stx	%o3,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont4
	or	%g0,3,counter

	.align	16
.update5:
	cmp	counter,3
	ble	.cont5
	nop

	sll	stridey,1,%g5
	add	%i2,stridey,%o3
	stx	%o2,[%fp+tmp_px]

	add	%o3,%g5,%o3
	stx	%o3,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont5
	or	%g0,3,counter

	.align	16
.update6:
	fzeros	%f2
	cmp	counter,1
	ble	.cont6
	nop

	ld	[%fp+tmp_counter],%g1

	sub	%o2,stridex,%o3
	stx	%o4,[%fp+tmp_py]

	sub	%o3,stridex,%o3
	add	%g1,counter,counter
	stx	%o3,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont6
	or	%g0,1,counter

	.align	16
.update7:
	cmp	counter,4
	ble	.cont7
	nop

	sll	stridey,1,%g1
	add	%o4,stridey,%o0
	stx	%o2,[%fp+tmp_px]

	add	%o0,%g1,%o0
	stx	%o0,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont7
	or	%g0,4,counter

	.align	16
.update8:
	cmp	counter,4
	ble	.cont8
	nop

	sll	stridey,1,%g1
	add	%o4,stridey,%o0
	stx	%o2,[%fp+tmp_px]

	add	%o0,%g1,%o0
	stx	%o0,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont8
	or	%g0,4,counter

	.align	16
.update9:
	cmp	counter,2
	ble	.cont9
	fzeros	%f16

	ld	[%fp+tmp_counter],%i3

	sub	%o2,stridex,%g1
	stx	%i2,[%fp+tmp_py]

	sub	%g1,stridex,%g1
	add	%i3,counter,counter
	stx	%g1,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont9
	or	%g0,2,counter

	.align	16
.update10:
	cmp	counter,5
	ble	.cont10
	nop

	add	%i2,stridey,%i1
	stx	%i3,[%fp+tmp_px]

	add	%i1,stridey,%i1
	stx	%i1,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont10
	or	%g0,5,counter

	.align	16
.update11:
	cmp	counter,5
	ble	.cont11
	nop

	add	%i2,stridey,%i1
	stx	%i3,[%fp+tmp_px]

	add	%i1,stridey,%i1
	stx	%i1,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont11
	or	%g0,5,counter

	.align	16
.update12:
	fzeros	%f0
	cmp	counter,3
	ble	.cont12
	nop

	ld	[%fp+tmp_counter],%o2

	sub	%i3,stridex,%i1
	stx	%i2,[%fp+tmp_py]

	sub	%i1,stridex,%i1
	add	%o2,counter,counter
	stx	%i1,[%fp+tmp_px]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont12
	or	%g0,3,counter

	.align	16
.update13:
	cmp	counter,3
	ble	.cont13
	nop

	sll	stridey,1,%g5
	add	%i2,stridey,%o3
	stx	%o2,[%fp+tmp_px]

	add	%o3,%g5,%o3
	stx	%o3,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont13
	or	%g0,3,counter

	.align	16
.update14:
	cmp	counter,3
	ble	.cont14
	nop

	sll	stridey,1,%g5
	add	%i2,stridey,%o3
	stx	%o2,[%fp+tmp_px]

	add	%o3,%g5,%o3
	stx	%o3,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont14
	or	%g0,3,counter

	.align	16
.update15:
	cmp	counter,1
	ble	.cont15
	fzeros	%f2

	ld	[%fp+tmp_counter],%g1

	sub	%o2,stridex,%o3
	stx	%o4,[%fp+tmp_py]

	sub	%o3,stridex,%o3
	add	%g1,counter,counter
	stx	%o3,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont15
	or	%g0,1,counter

	.align	16
.update16:
	cmp	counter,4
	ble	.cont16
	nop

	sll	stridey,1,%g1
	add	%o4,stridey,%o0
	stx	%o2,[%fp+tmp_px]

	add	%o0,%g1,%o0
	stx	%o0,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont16
	or	%g0,4,counter

	.align	16
.update17:
	cmp	counter,4
	ble	.cont17
	nop

	sll	stridey,1,%g1
	add	%o4,stridey,%o0
	stx	%o2,[%fp+tmp_px]

	add	%o0,%g1,%o0
	stx	%o0,[%fp+tmp_py]

	sub	counter,4,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont17
	or	%g0,4,counter

	.align	16
.update18:
	fzeros	%f16
	cmp	counter,2
	ble	.cont18
	nop

	ld	[%fp+tmp_counter],%i3

	sub	%o2,stridex,%g1
	stx	%i2,[%fp+tmp_py]

	sub	%g1,stridex,%g1
	add	%i3,counter,counter
	stx	%g1,[%fp+tmp_px]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont18
	or	%g0,2,counter

	.align	16
.update19:
	cmp	counter,5
	ble	.cont19
	nop

	add	%i2,stridey,%i1
	stx	%i3,[%fp+tmp_px]

	add	%i1,stridey,%i1
	stx	%i1,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont19
	or	%g0,5,counter

	.align	16
.update20:
	cmp	counter,5
	ble	.cont20
	nop

	add	%i2,stridey,%i1
	stx	%i3,[%fp+tmp_px]

	add	%i1,stridey,%i1
	stx	%i1,[%fp+tmp_py]

	sub	counter,5,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont20
	or	%g0,5,counter

	.align	16
.update21:
	cmp	counter,3
	ble	.cont21
	fzeros	%f0

	ld	[%fp+tmp_counter],%o2

	sub	%i3,stridex,%i1
	stx	%i2,[%fp+tmp_py]

	sub	%i1,stridex,%i1
	add	%o2,counter,counter
	stx	%i1,[%fp+tmp_px]


	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont21
	or	%g0,3,counter

	.align	16
.update22:
	cmp	counter,3
	ble	.cont22
	fzeros	%f2

	ld	[%fp+tmp_counter],%g1

	sub	%i3,stridex,%i2
	stx	%i2,[%fp+tmp_px]

	add	%g1,counter,counter
	stx	%o4,[%fp+tmp_py]

	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont22
	or	%g0,3,counter

.stridex_zero:
	ld	[%fp+tmp_counter],counter

	stx	%i3,[%fp+tmp_py]

	cmp	counter,0
	ble,pn	%icc,.exit
	lda	[%i1]0x82,%i1		! (Y0_2) ax0 = *px;

	and	%i1,MASK_0x7fffffff,%i3	! (Y0_2) exp0 = ax0 & 0x7fffffff;
	sub	%i3,%l6,%l6
	and	%i1,MASK_0x007fffff,%g5	! (Y0_2) ax0 &= 0x007fffff;
	srl	%i3,23,%o3		! (Y0_2) exp0 >>= 23;
	srl	%l6,31,%l6
	st	%l6,[%fp+tmp5]
	add	%g5,CONST_0x8000,%i3	! (Y0_2) i0 = ax0 + 0x8000;
	sethi	%hi(0xffff0000),%l6
	sub	%o3,127,%o3		! (Y0_2) exp0 -= 127;
	and	%i3,%l6,%i3		! (Y0_2) i0 &= 0xffff0000;
	sll	%o3,8,%o4		! (Y0_2) exp0 <<= 8;
	st	%o4,[%fp+tmp3]		! (Y0_2) STORE exp0
	sra	%i3,12,%o0		! (Y0_2) ind0 = i0 >> 12;
	sub	%g5,%i3,%o4		! (Y0_2) i0 = ax0 - i0;
	st	%o4,[%fp+tmp2]		! (Y0_2) STORE i0
	and	%o0,-8,%g5		! (Y0_2) ind0 &= -8;
	ld	[%fp+tmp2],%f14		! (Y0_2) dtmp0 = (double) i0;
	add	%l2,%g5,%g1		! (Y0_2) (char*)__mt_constlog4f + ind0
	ldd	[%g1+8],%f48		! (Y0_2) dtmp1 = *(double *)((char*)__mt_constlog4f + ind0 + 8);
	fitod	%f14,%f60		! (Y0_2) dtmp0 = (double) i0;
	fmuld	%f60,%f48,%f48		! (Y0_2) y0 =  dtmp0 * dtmp1;
	fmuld	KA3,%f48,%f62		! (Y0_2) dtmp0 = KA3 * y0;
	faddd	%f62,KA2,%f22		! (Y0_2) dtmp0 += KA2;
	fmuld	%f22,%f48,%f26 		! (Y0_2) dtmp0 *= y0;
	faddd	%f26,KA1,%f50		! (Y0_2) dtmp0 += KA1;
	ld	[%fp+tmp3],%f4		! (Y0_2) dtmp1 = (double) exp0;
	fitod	%f4,%f26		! (Y0_1) dtmp1 = (double) exp0;
	fmuld	%f50,%f48,%f50		! (Y0_1) dtmp0 *= y0;
	ldd	[%l2+%g5],%f60		! (Y0_1) dtmp0 = *(double *)((char*)__mt_constlog4f + ind0);
	faddd	%f50,KA0,%f58		! (Y0_1) dtmp0 += KA0;
	faddd	%f60,%f26,%f26		! (Y0_1) yy0 = dtmp0 + dtmp1;
	fmuld	%f58,%f48,%f48		! (Y0_1) dtmp0 *= y0;
	sub	%l2,3200,%o4
	sub	%l2,1152-600,%o3
	faddd	%f26,%f48,%f46		! (Y0_1) yy0 += dtmp0;
	or	%g0,%i5,%g1
	sethi	%hi(0x7f800000),%o1

.xbegin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_py],%o5
	st	%g0,[%fp+tmp_counter]
.xbegin1:
	subcc	counter,1,counter
	bneg,pn	%icc,.exit
	nop

	lda	[%o5]0x82,%i5		! (Y0_0) ay = py[0];

	lda	[%o5]0x82,%f5		! (Y0_0) ftmp0 = py[0];

	and	%i5,MASK_0x7fffffff,%i3	! (Y0_0) ay &= 0x7fffffff

	cmp	%i3,%o1
	bge,pn	%icc,.xspec
	nop

	fstod	%f5,%f52		! (Y0_0) dtmp0 = (double)ftmp0;

	fmuld	%f52,%f46,%f26		! (Y0_0) yy0 = dtmp0 * yy;
	add	%o5,stridey,%o5		! py += stridey

	lda	[%o5]0x82,%i5		! (Y1_0) ay = ((int*)py)[0];

	lda	[%o5]0x82,%f7		! (Y1_0) ftmp0 = py[0];

	and	%i5,MASK_0x7fffffff,%i5	! (Y1_0) ay &= 0x7fffffff
	fcmped	%fcc0,HTHRESHOLD,%f26	! (Y0_0) if (yy0 >= HTHRESH)

	cmp	%i5,%o1
	bge,pn	%icc,.xupdate0
	nop

.xcont0:
	fstod	%f7,%f48		! (Y1_0) dtmp0 = (double)ftmp0;

	fcmped	%fcc1,LTHRESHOLD,%f26	! (Y0_1) if (yy0 <= LTHRESH)

	add	%o5,stridey,%o5		! py += stridey
	fmuld	%f48,%f46,%f28		! (Y1_1) yy0 = dtmp0 * yy;

	lda	[%o5]0x82,%i3		! (Y0_0) ay = py[0];

	lda	[%o5]0x82,%f5		! (Y0_0) ftmp0 = py[0];

	and	%i3,MASK_0x7fffffff,%i3	! (Y0_0) ay &= 0x7fffffff
	fmovdl	%fcc0,HTHRESHOLD,%f26	! (Y0_1) yy0 = HTHRESH;

	cmp	%i3,%o1
	bge,pn	%icc,.xupdate1
	fcmped	%fcc2,HTHRESHOLD,%f28	! (Y1_1) if (yy0 >= HTHRESH)
.xcont1:
	fstod	%f5,%f52		! (Y0_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc1,LTHRESHOLD,%f26	! (Y0_1) yy0 = LTHRESH;

	fcmped	%fcc3,LTHRESHOLD,%f28	! (Y1_1) if (yy0 <= LTHRESH)

	fmuld	%f52,%f46,%f22		! (Y0_0) yy0 = dtmp0 * yy;

	fdtoi	%f26,%f0		! (Y0_1) ii0 = (int) yy0;

	add	%o5,stridey,%o5		! py += stridey
	st	%f0,[%fp+tmp1]		! (Y0_1) STORE ii0

	lda	[%o5]0x82,%l7		! (Y1_0) ay = ((int*)py)[0];

	lda	[%o5]0x82,%f7		! (Y1_0) ftmp0 = py[0];
	fmovdl	%fcc2,HTHRESHOLD,%f28	! (Y1_1) yy0 = HTHRESH;

	and	%l7,MASK_0x7fffffff,%l7	! (Y1_0) ay &= 0x7fffffff
	fcmped	%fcc0,HTHRESHOLD,%f22	! (Y0_0) if (yy0 >= HTHRESH)

	cmp	%l7,%o1
	bge,pn	%icc,.xupdate2
	nop
.xcont2:
	fstod	%f7,%f48		! (Y1_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc3,LTHRESHOLD,%f28	! (Y1_2) yy0 = LTHRESH;

	fcmped	%fcc1,LTHRESHOLD,%f22	! (Y0_1) if (yy0 <= LTHRESH)

	fitod	%f0,%f52		! (Y0_2) dtmp0 = (double)ii0;

	add	%o5,stridey,%o5		! py += stridey
	fmuld	%f48,%f46,%f24		! (Y1_1) yy0 = dtmp0 * yy;

	fdtoi	%f28,%f3		! (Y1_2) ii0 = (int) yy0;
	lda	[%o5]0x82,%i3		! (Y0_0) ay = py[0];

	st	%f3,[%fp+tmp0]		! (Y1_2) STORE ii0

	fsubd	%f26,%f52,%f40		! (Y0_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%f5		! (Y0_0) ftmp0 = py[0];

	and	%i3,MASK_0x7fffffff,%i3	! (Y0_0) ay &= 0x7fffffff
	fmovdl	%fcc0,HTHRESHOLD,%f22	! (Y0_1) yy0 = HTHRESH;

	cmp	%i3,%o1
	bge,pn	%icc,.xupdate3
	fcmped	%fcc2,HTHRESHOLD,%f24	! (Y1_1) if (yy0 >= HTHRESH)
.xcont3:
	ld	[%fp+tmp1],%i2		! (Y0_2) LOAD ii0
	fmuld	KB2,%f40,%f36		! (Y0_2) dtmp0 = KB2 * y0;
	fstod	%f5,%f52		! (Y0_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc1,LTHRESHOLD,%f22	! (Y0_1) yy0 = LTHRESH;

	sra	%i2,6,%l6		! (Y0_2) i0 = ii0 >> 6;
	and	%i2,255,%l7		! (Y0_2) ii0 &= 255;
	fcmped	%fcc3,LTHRESHOLD,%f24	! (Y1_1) if (yy0 <= LTHRESH)

	fitod	%f3,%f56		! (Y1_2) dtmp0 = (double)ii0;
	sll	%l7,3,%o0		! (Y0_2) ii0 <<= 3;
	and	%l6,-4,%g5		! (Y0_2) i0 &= -4;

	faddd	%f36,KB1,%f60		! (Y0_2) dtmp0 += KB1;
	fmuld	%f52,%f46,%f26		! (Y0_0) yy0 = dtmp0 * yy;
	ld	[%g5+%o3],%f10		! (Y0_2) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0]

	fdtoi	%f22,%f0		! (Y0_1) ii0 = (int) yy0;
	ldd	[%o4+%o0],%f62		! (Y0_2) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	add	%o5,stridey,%o5		! py += stridey
	st	%f0,[%fp+tmp1]		! (Y0_1) STORE ii0

	fsubd	%f28,%f56,%f56		! (Y1_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%i5		! (Y1_0) ay = ((int*)py)[0];

	fmuld	%f60,%f40,%f60		! (Y0_2) yy0 = dtmp0 * y0;
	fmovdl	%fcc2,HTHRESHOLD,%f24	! (Y1_1) yy0 = HTHRESH;
	lda	[%o5]0x82,%f7		! (Y1_0) ftmp0 = py[0];

	fmuld	%f10,%f62,%f62		! (Y0_2) di0 *= dtmp0;
	ld	[%fp+tmp0],%g5		! (Y1_2) LOAD ii0
	and	%i5,MASK_0x7fffffff,%i5	! (Y1_0) ay &= 0x7fffffff
	fcmped	%fcc0,HTHRESHOLD,%f26	! (Y0_0) if (yy0 >= HTHRESH)

	cmp	%i5,%o1
	bge,pn	%icc,.xupdate4
.xcont4:
	fmuld	KB2,%f56,%f58		! (Y1_2) dtmp0 = KB2 * y0;
	fstod	%f7,%f48		! (Y1_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc3,LTHRESHOLD,%f24	! (Y1_2) yy0 = LTHRESH;
	sra	%g5,6,%i0		! (Y1_3) i0 = ii0 >> 6;
	and	%g5,255,%i1		! (Y1_3) ii0 &= 255;
	fmuld	%f60,%f62,%f40		! (Y0_3) dtmp0 = yy0 * di0;

	fcmped	%fcc1,LTHRESHOLD,%f26	! (Y0_1) if (yy0 <= LTHRESH)
	sll	%i1,3,%i3		! (Y1_3) ii0 <<= 3;
	and	%i0,-4,%i0		! (Y1_3) i0 &= -4;

	fitod	%f0,%f52		! (Y0_2) dtmp0 = (double)ii0;
	ld	[%i0+%o3],%f10		! (Y1_3) di0 = ((double*)((char*)(__mt_constexp2fb + 150) + i0))[0];

	faddd	%f58,KB1,%f58		! (Y1_3) dtmp0 += KB1;
	add	%o5,stridey,%o5		! py += stridey
	ldd	[%o4+%i3],%f18		! (Y1_3) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];
	fmuld	%f48,%f46,%f28		! (Y1_1) yy0 = dtmp0 * yy;

	fdtoi	%f24,%f3		! (Y1_2) ii0 = (int) yy0;
	lda	[%o5]0x82,%i3		! (Y0_0) ay = py[0];

	faddd	%f40,%f62,%f60		! (Y0_3) dtmp0 += di0;
	st	%f3,[%fp+tmp0]		! (Y1_2) STORE ii0

	fsubd	%f22,%f52,%f40		! (Y0_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%f5		! (Y0_0) ftmp0 = py[0];

	fmuld	%f58,%f56,%f56		! (Y1_3) yy0 = dtmp0 * y0;
	and	%i3,MASK_0x7fffffff,%i3	! (Y0_0) ay &= 0x7fffffff
	fmovdl	%fcc0,HTHRESHOLD,%f26	! (Y0_1) yy0 = HTHRESH;

	fmuld	%f10,%f18,%f50		! (Y1_3) di0 *= dtmp0;
	cmp	%i3,%o1
	bge,pn	%icc,.xupdate5
	fcmped	%fcc2,HTHRESHOLD,%f28	! (Y1_1) if (yy0 >= HTHRESH)
.xcont5:
	fdtos	%f60,%f1		! (Y0_3) ftmp0 = (float)dtmp0;
	add	%g1,stridez,%i3		! pz += stridez
	st	%f1,[%g1]		! (Y0_3) pz[0] = ftmp0;

	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i3,%g1

	ld	[%fp+tmp1],%i2		! (Y0_2) LOAD ii0
	fmuld	KB2,%f40,%f36		! (Y0_2) dtmp0 = KB2 * y0;
	fstod	%f5,%f52		! (Y0_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc1,LTHRESHOLD,%f26	! (Y0_1) yy0 = LTHRESH;

	fmuld	%f56,%f50,%f58		! (Y1_3) dtmp0 = yy0 * di0;
	sra	%i2,6,%l6		! (Y0_2) i0 = ii0 >> 6;
	and	%i2,255,%l7		! (Y0_2) ii0 &= 255;
	fcmped	%fcc3,LTHRESHOLD,%f28	! (Y1_1) if (yy0 <= LTHRESH)

	fitod	%f3,%f56		! (Y1_2) dtmp0 = (double)ii0;
	sll	%l7,3,%o0		! (Y0_2) ii0 <<= 3;
	and	%l6,-4,%g5		! (Y0_2) i0 &= -4;

	faddd	%f36,KB1,%f60		! (Y0_2) dtmp0 += KB1;
	fmuld	%f52,%f46,%f22		! (Y0_0) yy0 = dtmp0 * yy;
	ld	[%g5+%o3],%f10		! (Y0_2) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0]

	fdtoi	%f26,%f0		! (Y0_1) ii0 = (int) yy0;
	ldd	[%o4+%o0],%f62		! (Y0_2) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	faddd	%f58,%f50,%f58		! (Y1_3) dtmp0 += di0;
	add	%o5,stridey,%o5		! py += stridey
	st	%f0,[%fp+tmp1]		! (Y0_1) STORE ii0

	fsubd	%f24,%f56,%f56		! (Y1_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%l7		! (Y1_0) ay = ((int*)py)[0];

	fmuld	%f60,%f40,%f60		! (Y0_2) yy0 = dtmp0 * y0;
	add	%i3,stridez,%i5		! pz += stridez
	lda	[%o5]0x82,%f7		! (Y1_0) ftmp0 = py[0];
	fmovdl	%fcc2,HTHRESHOLD,%f28	! (Y1_1) yy0 = HTHRESH;

	fmuld	%f10,%f62,%f62		! (Y0_2) di0 *= dtmp0;
	and	%l7,MASK_0x7fffffff,%l7	! (Y1_0) ay &= 0x7fffffff
	ld	[%fp+tmp0],%g5		! (Y1_2) LOAD ii0
	fcmped	%fcc0,HTHRESHOLD,%f22	! (Y0_0) if (yy0 >= HTHRESH)

	fdtos	%f58,%f9		! (Y1_3) ftmp0 = (float)dtmp0;
	st	%f9,[%i3]		! (Y1_3) pz[0] = ftmp0;
	cmp	%l7,%o1
	bge,pn	%icc,.xupdate6

.xcont6:
	fmuld	KB2,%f56,%f58		! (Y1_2) dtmp0 = KB2 * y0;
	fstod	%f7,%f48		! (Y1_0) dtmp0 = (double)ftmp0;

	cmp	counter,8
	bl,pn	%icc,.xtail
	nop

	ba	.xmain_loop
	nop

	.align	16
.xmain_loop:
	fmovdg	%fcc3,LTHRESHOLD,%f28	! (Y1_2) yy0 = LTHRESH;
	sra	%g5,6,%i0		! (Y1_3) i0 = ii0 >> 6;
	and	%g5,255,%i1		! (Y1_3) ii0 &= 255;
	fmuld	%f60,%f62,%f40		! (Y0_3) dtmp0 = yy0 * di0;

	fcmped	%fcc1,LTHRESHOLD,%f22	! (Y0_1) if (yy0 <= LTHRESH)
	sll	%i1,3,%i3		! (Y1_3) ii0 <<= 3;
	and	%i0,-4,%i0		! (Y1_3) i0 &= -4;

	fitod	%f0,%f52		! (Y0_2) dtmp0 = (double)ii0;
	sub	counter,4,counter
	ld	[%i0+%o3],%f10		! (Y1_3) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0];

	faddd	%f58,KB1,%f58		! (Y1_3) dtmp0 += KB1;
	add	%o5,stridey,%o5		! py += stridey
	ldd	[%o4+%i3],%f18		! (Y1_3) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];
	fmuld	%f48,%f46,%f24		! (Y1_1) yy0 = dtmp0 * yy;

	fdtoi	%f28,%f3		! (Y1_2) ii0 = (int) yy0;
	lda	[%o5]0x82,%i3		! (Y0_0) ay = py[0];

	faddd	%f40,%f62,%f60		! (Y0_3) dtmp0 += di0;
	st	%f3,[%fp+tmp0]		! (Y1_2) STORE ii0

	fsubd	%f26,%f52,%f40		! (Y0_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%f5		! (Y0_0) ftmp0 = py[0];

	fmuld	%f58,%f56,%f56		! (Y1_3) yy0 = dtmp0 * y0;
	and	%i3,MASK_0x7fffffff,%i3	! (Y0_0) ay &= 0x7fffffff
	fmovdl	%fcc0,HTHRESHOLD,%f22	! (Y0_1) yy0 = HTHRESH;

	fmuld	%f10,%f18,%f50		! (Y1_3) di0 *= dtmp0;
	cmp	%i3,%o1
	bge,pn	%icc,.xupdate7
	fcmped	%fcc2,HTHRESHOLD,%f24	! (Y1_1) if (yy0 >= HTHRESH)
.xcont7:
	fdtos	%f60,%f1		! (Y0_3) ftmp0 = (float)dtmp0;
	add	%i5,stridez,%i3		! pz += stridez
	st	%f1,[%i5]		! (Y0_3) pz[0] = ftmp0;

	ld	[%fp+tmp1],%i2		! (Y0_2) LOAD ii0
	fmuld	KB2,%f40,%f36		! (Y0_2) dtmp0 = KB2 * y0;
	fstod	%f5,%f52		! (Y0_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc1,LTHRESHOLD,%f22	! (Y0_1) yy0 = LTHRESH;

	fmuld	%f56,%f50,%f58		! (Y1_3) dtmp0 = yy0 * di0;
	sra	%i2,6,%l6		! (Y0_2) i0 = ii0 >> 6;
	and	%i2,255,%l7		! (Y0_2) ii0 &= 255;
	fcmped	%fcc3,LTHRESHOLD,%f24	! (Y1_1) if (yy0 <= LTHRESH)

	fitod	%f3,%f56		! (Y1_2) dtmp0 = (double)ii0;
	sll	%l7,3,%o0		! (Y0_2) ii0 <<= 3;
	and	%l6,-4,%g5		! (Y0_2) i0 &= -4;

	faddd	%f36,KB1,%f60		! (Y0_2) dtmp0 += KB1;
	fmuld	%f52,%f46,%f26		! (Y0_0) yy0 = dtmp0 * yy;
	ld	[%g5+%o3],%f10		! (Y0_2) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0]

	fdtoi	%f22,%f0		! (Y0_1) ii0 = (int) yy0;
	ldd	[%o4+%o0],%f62		! (Y0_2) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	faddd	%f58,%f50,%f58		! (Y1_3) dtmp0 += di0;
	add	%o5,stridey,%o5		! py += stridey
	st	%f0,[%fp+tmp1]		! (Y0_1) STORE ii0

	fsubd	%f28,%f56,%f56		! (Y1_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%i5		! (Y1_0) ay = ((int*)py)[0];

	fmuld	%f60,%f40,%f60		! (Y0_2) yy0 = dtmp0 * y0;
	fmovdl	%fcc2,HTHRESHOLD,%f24	! (Y1_1) yy0 = HTHRESH;
	lda	[%o5]0x82,%f7		! (Y1_0) ftmp0 = py[0];

	fmuld	%f10,%f62,%f62		! (Y0_2) di0 *= dtmp0;
	ld	[%fp+tmp0],%g5		! (Y1_2) LOAD ii0
	and	%i5,MASK_0x7fffffff,%i5	! (Y1_0) ay &= 0x7fffffff
	fcmped	%fcc0,HTHRESHOLD,%f26	! (Y0_0) if (yy0 >= HTHRESH)

	fdtos	%f58,%f9		! (Y1_3) ftmp0 = (float)dtmp0;
	cmp	%i5,%o1
	bge,pn	%icc,.xupdate8

.xcont8:
	fmuld	KB2,%f56,%f58		! (Y1_2) dtmp0 = KB2 * y0;
	add	%i3,stridez,%i5		! pz += stridez
	st	%f9,[%i3]		! (Y1_3) pz[0] = ftmp0;
	fstod	%f7,%f48		! (Y1_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc3,LTHRESHOLD,%f24	! (Y1_2) yy0 = LTHRESH;
	sra	%g5,6,%i0		! (Y1_3) i0 = ii0 >> 6;
	and	%g5,255,%i1		! (Y1_3) ii0 &= 255;
	fmuld	%f60,%f62,%f40		! (Y0_3) dtmp0 = yy0 * di0;

	fcmped	%fcc1,LTHRESHOLD,%f26	! (Y0_1) if (yy0 <= LTHRESH)
	sll	%i1,3,%i3		! (Y1_3) ii0 <<= 3;
	and	%i0,-4,%i0		! (Y1_3) i0 &= -4;

	fitod	%f0,%f52		! (Y0_2) dtmp0 = (double)ii0;
	ld	[%i0+%o3],%f10		! (Y1_3) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0];

	faddd	%f58,KB1,%f58		! (Y1_3) dtmp0 += KB1;
	add	%o5,stridey,%o5		! py += stridey
	ldd	[%o4+%i3],%f18		! (Y1_3) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];
	fmuld	%f48,%f46,%f28		! (Y1_1) yy0 = dtmp0 * yy;

	fdtoi	%f24,%f3		! (Y1_2) ii0 = (int) yy0;
	lda	[%o5]0x82,%i3		! (Y0_0) ay = py[0];

	faddd	%f40,%f62,%f60		! (Y0_3) dtmp0 += di0;
	st	%f3,[%fp+tmp0]		! (Y1_2) STORE ii0

	fsubd	%f22,%f52,%f40		! (Y0_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%f5		! (Y0_0) ftmp0 = py[0];

	fmuld	%f58,%f56,%f56		! (Y1_3) yy0 = dtmp0 * y0;
	and	%i3,MASK_0x7fffffff,%i3	! (Y0_0) ay &= 0x7fffffff
	fmovdl	%fcc0,HTHRESHOLD,%f26	! (Y0_1) yy0 = HTHRESH;

	fmuld	%f10,%f18,%f50		! (Y1_3) di0 *= dtmp0;
	cmp	%i3,%o1
	bge,pn	%icc,.xupdate9
	fcmped	%fcc2,HTHRESHOLD,%f28	! (Y1_1) if (yy0 >= HTHRESH)
.xcont9:
	fdtos	%f60,%f1		! (Y0_3) ftmp0 = (float)dtmp0;
	add	%i5,stridez,%i3		! pz += stridez
	st	%f1,[%i5]		! (Y0_3) pz[0] = ftmp0;

	ld	[%fp+tmp1],%i2		! (Y0_2) LOAD ii0
	fmuld	KB2,%f40,%f36		! (Y0_2) dtmp0 = KB2 * y0;
	fstod	%f5,%f52		! (Y0_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc1,LTHRESHOLD,%f26	! (Y0_1) yy0 = LTHRESH;

	fmuld	%f56,%f50,%f58		! (Y1_3) dtmp0 = yy0 * di0;
	sra	%i2,6,%l6		! (Y0_2) i0 = ii0 >> 6;
	and	%i2,255,%l7		! (Y0_2) ii0 &= 255;
	fcmped	%fcc3,LTHRESHOLD,%f28	! (Y1_1) if (yy0 <= LTHRESH)

	fitod	%f3,%f56		! (Y1_2) dtmp0 = (double)ii0;
	sll	%l7,3,%o0		! (Y0_2) ii0 <<= 3;
	and	%l6,-4,%g5		! (Y0_2) i0 &= -4;

	faddd	%f36,KB1,%f60		! (Y0_2) dtmp0 += KB1;
	fmuld	%f52,%f46,%f22		! (Y0_0) yy0 = dtmp0 * yy;
	ld	[%g5+%o3],%f10		! (Y0_2) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0]

	fdtoi	%f26,%f0		! (Y0_1) ii0 = (int) yy0;
	ldd	[%o4+%o0],%f62		! (Y0_2) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	faddd	%f58,%f50,%f58		! (Y1_3) dtmp0 += di0;
	add	%o5,stridey,%o5		! py += stridey
	st	%f0,[%fp+tmp1]		! (Y0_1) STORE ii0

	fsubd	%f24,%f56,%f56		! (Y1_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%l7		! (Y1_0) ay = ((int*)py)[0];

	fmuld	%f60,%f40,%f60		! (Y0_2) yy0 = dtmp0 * y0;
	add	%i3,stridez,%i5		! pz += stridez
	lda	[%o5]0x82,%f7		! (Y1_0) ftmp0 = py[0];
	fmovdl	%fcc2,HTHRESHOLD,%f28	! (Y1_1) yy0 = HTHRESH;

	fmuld	%f10,%f62,%f62		! (Y0_2) di0 *= dtmp0;
	and	%l7,MASK_0x7fffffff,%l7	! (Y1_0) ay &= 0x7fffffff
	ld	[%fp+tmp0],%g5		! (Y1_2) LOAD ii0
	fcmped	%fcc0,HTHRESHOLD,%f22	! (Y0_0) if (yy0 >= HTHRESH)

	fdtos	%f58,%f9		! (Y1_3) ftmp0 = (float)dtmp0;
	st	%f9,[%i3]		! (Y1_3) pz[0] = ftmp0;
	cmp	%l7,%o1
	bge,pn	%icc,.xupdate10
.xcont10:
	fmuld	KB2,%f56,%f58		! (Y1_2) dtmp0 = KB2 * y0;
	cmp	counter,4
	bge,pt	%icc,.xmain_loop
	fstod	%f7,%f48		! (Y1_0) dtmp0 = (double)ftmp0;

.xtail:
	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i5,%g1

	fmovdg	%fcc3,LTHRESHOLD,%f28	! (Y1_2) yy0 = LTHRESH;
	sra	%g5,6,%i0		! (Y1_3) i0 = ii0 >> 6;
	and	%g5,255,%i1		! (Y1_3) ii0 &= 255;
	fmuld	%f60,%f62,%f40		! (Y0_3) dtmp0 = yy0 * di0;

	fcmped	%fcc1,LTHRESHOLD,%f22	! (Y0_1) if (yy0 <= LTHRESH)
	sll	%i1,3,%i3		! (Y1_3) ii0 <<= 3;
	and	%i0,-4,%i0		! (Y1_3) i0 &= -4;

	fitod	%f0,%f52		! (Y0_2) dtmp0 = (double)ii0;
	ld	[%i0+%o3],%f10		! (Y1_3) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0];

	faddd	%f58,KB1,%f58		! (Y1_3) dtmp0 += KB1;
	add	%o5,stridey,%o5		! py += stridey
	ldd	[%o4+%i3],%f18		! (Y1_3) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];
	fmuld	%f48,%f46,%f24		! (Y1_1) yy0 = dtmp0 * yy;

	fdtoi	%f28,%f3		! (Y1_2) ii0 = (int) yy0;
	lda	[%o5]0x82,%i3		! (Y0_0) ay = py[0];

	faddd	%f40,%f62,%f60		! (Y0_3) dtmp0 += di0;
	st	%f3,[%fp+tmp0]		! (Y1_2) STORE ii0

	fsubd	%f26,%f52,%f40		! (Y0_2) y0 = yy0 - dtmp0;
	lda	[%o5]0x82,%f5		! (Y0_0) ftmp0 = py[0];

	fmuld	%f58,%f56,%f56		! (Y1_3) yy0 = dtmp0 * y0;
	and	%i3,MASK_0x7fffffff,%i3	! (Y0_0) ay &= 0x7fffffff
	fmovdl	%fcc0,HTHRESHOLD,%f22	! (Y0_1) yy0 = HTHRESH;

	fmuld	%f10,%f18,%f50		! (Y1_3) di0 *= dtmp0;
	cmp	%i3,%o1
	bge,pn	%icc,.xupdate11
	fcmped	%fcc2,HTHRESHOLD,%f24	! (Y1_1) if (yy0 >= HTHRESH)
.xcont11:
	fdtos	%f60,%f1		! (Y0_3) ftmp0 = (float)dtmp0;
	add	%i5,stridez,%i3		! pz += stridez
	st	%f1,[%i5]		! (Y0_3) pz[0] = ftmp0;

	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i3,%g1

	ld	[%fp+tmp1],%i2		! (Y0_2) LOAD ii0
	fmuld	KB2,%f40,%f36		! (Y0_2) dtmp0 = KB2 * y0;
	fstod	%f5,%f52		! (Y0_0) dtmp0 = (double)ftmp0;

	fmovdg	%fcc1,LTHRESHOLD,%f22	! (Y0_1) yy0 = LTHRESH;

	fmuld	%f56,%f50,%f58		! (Y1_3) dtmp0 = yy0 * di0;
	sra	%i2,6,%l6		! (Y0_2) i0 = ii0 >> 6;
	and	%i2,255,%l7		! (Y0_2) ii0 &= 255;
	fcmped	%fcc3,LTHRESHOLD,%f24	! (Y1_1) if (yy0 <= LTHRESH)

	fitod	%f3,%f56		! (Y1_2) dtmp0 = (double)ii0;
	sll	%l7,3,%o0		! (Y0_2) ii0 <<= 3;
	and	%l6,-4,%g5		! (Y0_2) i0 &= -4;

	faddd	%f36,KB1,%f60		! (Y0_2) dtmp0 += KB1;
	fmuld	%f52,%f46,%f26		! (Y0_0) yy0 = dtmp0 * yy;
	ld	[%g5+%o3],%f10		! (Y0_2) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0]

	fdtoi	%f22,%f0		! (Y0_1) ii0 = (int) yy0;
	ldd	[%o4+%o0],%f62		! (Y0_2) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	faddd	%f58,%f50,%f58		! (Y1_3) dtmp0 += di0;
	st	%f0,[%fp+tmp1]		! (Y0_1) STORE ii0

	fsubd	%f28,%f56,%f56		! (Y1_2) y0 = yy0 - dtmp0;

	fmuld	%f60,%f40,%f60		! (Y0_2) yy0 = dtmp0 * y0;
	fmovdl	%fcc2,HTHRESHOLD,%f24	! (Y1_1) yy0 = HTHRESH;

	fmuld	%f10,%f62,%f62		! (Y0_2) di0 *= dtmp0;
	ld	[%fp+tmp0],%g5		! (Y1_2) LOAD ii0
	fcmped	%fcc0,HTHRESHOLD,%f26	! (Y0_0) if (yy0 >= HTHRESH)

	fdtos	%f58,%f9		! (Y1_3) ftmp0 = (float)dtmp0;

	fmuld	KB2,%f56,%f58		! (Y1_2) dtmp0 = KB2 * y0;
	add	%i3,stridez,%i5		! pz += stridez
	st	%f9,[%i3]		! (Y1_3) pz[0] = ftmp0;

	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i5,%g1

	fmovdg	%fcc3,LTHRESHOLD,%f24	! (Y1_2) yy0 = LTHRESH;
	sra	%g5,6,%i0		! (Y1_3) i0 = ii0 >> 6;
	and	%g5,255,%i1		! (Y1_3) ii0 &= 255;
	fmuld	%f60,%f62,%f40		! (Y0_3) dtmp0 = yy0 * di0;

	fcmped	%fcc1,LTHRESHOLD,%f26	! (Y0_1) if (yy0 <= LTHRESH)
	sll	%i1,3,%i3		! (Y1_3) ii0 <<= 3;
	and	%i0,-4,%i0		! (Y1_3) i0 &= -4;

	fitod	%f0,%f52		! (Y0_2) dtmp0 = (double)ii0;
	ld	[%i0+%o3],%f10		! (Y1_3) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0];

	faddd	%f58,KB1,%f58		! (Y1_3) dtmp0 += KB1;
	ldd	[%o4+%i3],%f18		! (Y1_3) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	fdtoi	%f24,%f3		! (Y1_2) ii0 = (int) yy0;

	faddd	%f40,%f62,%f60		! (Y0_3) dtmp0 += di0;
	st	%f3,[%fp+tmp0]		! (Y1_2) STORE ii0

	fsubd	%f22,%f52,%f40		! (Y0_2) y0 = yy0 - dtmp0;

	fmuld	%f58,%f56,%f56		! (Y1_3) yy0 = dtmp0 * y0;
	fmovdl	%fcc0,HTHRESHOLD,%f26	! (Y0_1) yy0 = HTHRESH;

	fmuld	%f10,%f18,%f50		! (Y1_3) di0 *= dtmp0;

	fdtos	%f60,%f1		! (Y0_3) ftmp0 = (float)dtmp0;
	add	%i5,stridez,%i3		! pz += stridez
	st	%f1,[%i5]		! (Y0_3) pz[0] = ftmp0;

	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i3,%g1

	ld	[%fp+tmp1],%i2		! (Y0_2) LOAD ii0
	fmuld	KB2,%f40,%f36		! (Y0_2) dtmp0 = KB2 * y0;

	fmovdg	%fcc1,LTHRESHOLD,%f26	! (Y0_1) yy0 = LTHRESH;

	fmuld	%f56,%f50,%f58		! (Y1_3) dtmp0 = yy0 * di0;
	sra	%i2,6,%l6		! (Y0_2) i0 = ii0 >> 6;
	and	%i2,255,%l7		! (Y0_2) ii0 &= 255;

	fitod	%f3,%f56		! (Y1_2) dtmp0 = (double)ii0;
	sll	%l7,3,%o0		! (Y0_2) ii0 <<= 3;
	and	%l6,-4,%g5		! (Y0_2) i0 &= -4;

	faddd	%f36,KB1,%f60		! (Y0_2) dtmp0 += KB1;
	ld	[%g5+%o3],%f10		! (Y0_2) di0 = ((double*)((char*)(__mt_constexp2fb + 150) + i0))[0];

	fdtoi	%f26,%f0		! (Y0_1) ii0 = (int) yy0;
	ldd	[%o4+%o0],%f62		! (Y0_2) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	faddd	%f58,%f50,%f58		! (Y1_3) dtmp0 += di0;
	st	%f0,[%fp+tmp1]		! (Y0_1) STORE ii0

	fsubd	%f24,%f56,%f56		! (Y1_2) y0 = yy0 - dtmp0;

	fmuld	%f60,%f40,%f60		! (Y0_2) yy0 = dtmp0 * y0;
	add	%i3,stridez,%i5		! pz += stridez

	fmuld	%f10,%f62,%f62		! (Y0_2) di0 *= dtmp0;
	ld	[%fp+tmp0],%g5		! (Y1_2) LOAD ii0

	fdtos	%f58,%f9		! (Y1_3) ftmp0 = (float)dtmp0;
	st	%f9,[%i3]		! (Y1_3) pz[0] = ftmp0;

	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i5,%g1

	fmuld	KB2,%f56,%f58		! (Y1_2) dtmp0 = KB2 * y0;

	sra	%g5,6,%i0		! (Y1_3) i0 = ii0 >> 6;
	and	%g5,255,%i1		! (Y1_3) ii0 &= 255;
	fmuld	%f60,%f62,%f40		! (Y0_3) dtmp0 = yy0 * di0;

	sll	%i1,3,%i3		! (Y1_3) ii0 <<= 3;
	and	%i0,-4,%i0		! (Y1_3) i0 &= -4;

	fitod	%f0,%f52		! (Y0_2) dtmp0 = (double)ii0;
	ld	[%i0+%o3],%f10		! (Y1_3) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0];

	faddd	%f58,KB1,%f58		! (Y1_3) dtmp0 += KB1;
	ldd	[%o4+%i3],%f18		! (Y1_3) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	faddd	%f40,%f62,%f60		! (Y0_3) dtmp0 += di0;

	fsubd	%f26,%f52,%f40		! (Y0_2) y0 = yy0 - dtmp0;

	fmuld	%f58,%f56,%f56		! (Y1_3) yy0 = dtmp0 * y0;

	fmuld	%f10,%f18,%f50		! (Y1_3) di0 *= dtmp0;

	fdtos	%f60,%f1		! (Y0_3) ftmp0 = (float)dtmp0;
	add	%i5,stridez,%i3		! pz += stridez
	st	%f1,[%i5]		! (Y0_3) pz[0] = ftmp0;

	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i3,%g1

	ld	[%fp+tmp1],%i2		! (Y0_2) LOAD ii0
	fmuld	KB2,%f40,%f36		! (Y0_2) dtmp0 = KB2 * y0;

	fmuld	%f56,%f50,%f58		! (Y1_3) dtmp0 = yy0 * di0;
	sra	%i2,6,%l6		! (Y0_2) i0 = ii0 >> 6;
	and	%i2,255,%l7		! (Y0_2) ii0 &= 255;

	sll	%l7,3,%o0		! (Y0_2) ii0 <<= 3;
	and	%l6,-4,%g5		! (Y0_2) i0 &= -4;

	faddd	%f36,KB1,%f60		! (Y0_2) dtmp0 += KB1;
	ld	[%g5+%o3],%f10		! (Y0_2) di0 = ((double*)((char*)(__mt_constexp2fb + 150 ) + i0))[0]

	ldd	[%o4+%o0],%f62		! (Y0_2) dtmp0 = ((double*)((char*)__mt_constexp2fa + ii0))[0];

	faddd	%f58,%f50,%f58		! (Y1_3) dtmp0 += di0;

	fmuld	%f60,%f40,%f60		! (Y0_2) yy0 = dtmp0 * y0;

	fmuld	%f10,%f62,%f62		! (Y0_2) di0 *= dtmp0;

	fdtos	%f58,%f9		! (Y1_3) ftmp0 = (float)dtmp0;
	add	%i3,stridez,%i5		! pz += stridez
	st	%f9,[%i3]		! (Y1_3) pz[0] = ftmp0;

	subcc	counter,1,counter
	bneg,pn	%icc,.xbegin
	or	%g0,%i5,%g1

	fmuld	%f60,%f62,%f40		! (Y0_3) dtmp0 = yy0 * di0;

	faddd	%f40,%f62,%f60		! (Y0_3) dtmp0 += di0;

	fdtos	%f60,%f1		! (Y0_3) ftmp0 = (float)dtmp0;
	add	%i5,stridez,%i3		! pz += stridez
	st	%f1,[%i5]		! (Y0_3) pz[0] = ftmp0;

	ba	.xbegin
	or	%g0,%i3,%g1

.xspec:
	bg,a,pn	%icc,.yisnan		! if (ay > 0x7f800000) /* |Y| = Nan */
	ld	[%o5],%f8		! fy = *py;

	ld	[%fp+tmp5],%l6		! LOAD (ax-0x3f800000)<<63
	srl	%i5,31,%i5		! uy >> 31

	cmp	%l6,%i5			! if((ax < 0x3f800000) != (uy >> 31))
	be,a,pn	%icc,.xspec_exit	! if((ax < 0x3f800000) != (uy >> 31))
	st	%i3,[%g1]		! fy = *(float*)&ay;

	st	%g0,[%g1]		! fy = ZERO
	add	%g1,stridez,%g1
	ba	.xbegin1
	add	%o5,stridey,%o5

.yisnan:
	fmuls	%f8,%f8,%f8		! fy = *py * *py;  /* |Y| = Nan */
	st	%f8,[%g1]

.xspec_exit:
	add	%g1,stridez,%g1
	ba	.xbegin1
	add	%o5,stridey,%o5

	.align	16
.xupdate0:
	cmp	counter,0
	ble	.xcont0
	fzeros	%f7

	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont0
	or	%g0,0,counter

	.align	16
.xupdate1:
	cmp	counter,1
	ble	.xcont1
	fzeros	%f5

	sub	counter,1,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont1
	or	%g0,1,counter

	.align	16
.xupdate2:
	cmp	counter,2
	ble	.xcont2
	fzeros	%f7

	sub	counter,2,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont2
	or	%g0,2,counter

	.align	16
.xupdate3:
	cmp	counter,3
	ble	.xcont3
	fzeros	%f5

	sub	counter,3,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont3
	or	%g0,3,counter

	.align	16
.xupdate4:
	cmp	counter,4
	ble	.xcont4
	fzeros	%f7

	sub	counter,4,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont4
	or	%g0,4,counter

	.align	16
.xupdate5:
	cmp	counter,5
	ble	.xcont5
	fzeros	%f5

	sub	counter,5,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont5
	or	%g0,5,counter

	.align	16
.xupdate6:
	cmp	counter,5
	ble	.xcont6
	fzeros	%f7

	sub	counter,5,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont6
	or	%g0,5,counter

	.align	16
.xupdate7:
	cmp	counter,2
	ble	.xcont7
	fzeros	%f5

	sub	counter,2,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont7
	or	%g0,2,counter

	.align	16
.xupdate8:
	cmp	counter,3
	ble	.xcont8
	fzeros	%f7

	sub	counter,3,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont8
	or	%g0,3,counter

	.align	16
.xupdate9:
	cmp	counter,4
	ble	.xcont9
	fzeros	%f5

	sub	counter,4,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont9
	or	%g0,4,counter

	.align	16
.xupdate10:
	cmp	counter,5
	ble	.xcont10
	fzeros	%f7

	sub	counter,5,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont10
	or	%g0,5,counter

	.align	16
.xupdate11:
	cmp	counter,5
	ble	.xcont11
	fzeros	%f5

	sub	counter,5,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont11
	or	%g0,5,counter

	SET_SIZE(__vpowf)

