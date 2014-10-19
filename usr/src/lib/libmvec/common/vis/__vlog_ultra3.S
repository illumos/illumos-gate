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

	.file	"__vlog_ultra3.S"

#include "libm.h"
#if defined(LIBMVEC_SO_BUILD)
	.weak	__vlog
	.type	__vlog,#function
	__vlog = __vlog_ultra3
#endif

/*
 * ELEVENBIT table and order 5 POLYNOMIAL no explicit correction t
 */

	RO_DATA
	.align	64
!! this is a new 11 bit table.
TBL:
	.word	0xbfd522ae,	0x0738a000
	.word	0xbd2ebe70,	0x8164c759
	.word	0xbfd5178d,	0x9ab55000
	.word	0xbd35c153,	0x0fe963b3
	.word	0xbfd50c6f,	0x1d11b000
	.word	0xbd42f8ca,	0x40bec1ea
	.word	0xbfd50152,	0x8da1f000
	.word	0xbd42cfac,	0x6d29f4d7
	.word	0xbfd4f637,	0xebba9000
	.word	0xbd401f53,	0x9a676da3
	.word	0xbfd4eb1f,	0x36b07000
	.word	0xbd184047,	0x46e5797b
	.word	0xbfd4e008,	0x6dd8b000
	.word	0xbd4594b6,	0xaf0ddc3c
	.word	0xbfd4d4f3,	0x90890000
	.word	0xbd19fd79,	0x3a9f1441
	.word	0xbfd4c9e0,	0x9e172000
	.word	0xbd4877dd,	0xb93d49d7
	.word	0xbfd4becf,	0x95d97000
	.word	0xbd422662,	0x6ffee2c8
	.word	0xbfd4b3c0,	0x77267000
	.word	0xbd4d3497,	0x2fdf5a8c
	.word	0xbfd4a8b3,	0x41552000
	.word	0xbd46127e,	0x3d0dc8d1
	.word	0xbfd49da7,	0xf3bcc000
	.word	0xbd307b33,	0x4daf4b9a
	.word	0xbfd4929e,	0x8db4e000
	.word	0xbd3b9056,	0x556c70de
	.word	0xbfd48797,	0x0e958000
	.word	0xbd3dc1b8,	0x465cf25f
	.word	0xbfd47c91,	0x75b6f000
	.word	0xbd05acd1,	0x7009e35b
	.word	0xbfd4718d,	0xc271c000
	.word	0xbd306c18,	0xfb4c14c5
	.word	0xbfd4668b,	0xf41ef000
	.word	0xbd432874,	0x4e9d2b85
	.word	0xbfd45b8c,	0x0a17d000
	.word	0xbd4e26ed,	0xf182f57b
	.word	0xbfd4508e,	0x03b61000
	.word	0xbd40ef1c,	0x2579199c
	.word	0xbfd44591,	0xe0539000
	.word	0xbd4e916a,	0x76d6dc28
	.word	0xbfd43a97,	0x9f4ac000
	.word	0xbd23ee07,	0x6a81f88e
	.word	0xbfd42f9f,	0x3ff62000
	.word	0xbd390644,	0x0f7d3354
	.word	0xbfd424a8,	0xc1b0c000
	.word	0xbd2dc57c,	0x99ae2a25
	.word	0xbfd419b4,	0x23d5e000
	.word	0xbd418e43,	0x6ec90e0a
	.word	0xbfd40ec1,	0x65c13000
	.word	0xbd3f59a8,	0xa01757f6
	.word	0xbfd403d0,	0x86cea000
	.word	0xbd3e6ef5,	0x74487308
	.word	0xbfd3f8e1,	0x865a8000
	.word	0xbd26f338,	0x912773e3
	.word	0xbfd3edf4,	0x63c16000
	.word	0xbd407cc1,	0xeb4069e1
	.word	0xbfd3e309,	0x1e604000
	.word	0xbd43f634,	0xa2afb68d
	.word	0xbfd3d81f,	0xb5946000
	.word	0xbd4b74e0,	0xf558b217
	.word	0xbfd3cd38,	0x28bb6000
	.word	0xbd489faf,	0xb06c8342
	.word	0xbfd3c252,	0x77333000
	.word	0xbd183b54,	0xb606bd5c
	.word	0xbfd3b76e,	0xa059f000
	.word	0xbd47b5cf,	0x9912c7cb
	.word	0xbfd3ac8c,	0xa38e5000
	.word	0xbd48bd04,	0x10ff506d
	.word	0xbfd3a1ac,	0x802f3000
	.word	0xbd398ecf,	0x399abd8d
	.word	0xbfd396ce,	0x359bb000
	.word	0xbd4ea7c6,	0x3a99c99c
	.word	0xbfd38bf1,	0xc3337000
	.word	0xbd4ce9e9,	0x41e9516d
	.word	0xbfd38117,	0x28564000
	.word	0xbd496386,	0xdb17e3f5
	.word	0xbfd3763e,	0x64645000
	.word	0xbd318b1f,	0x291dcb56
	.word	0xbfd36b67,	0x76be1000
	.word	0xbd116ecd,	0xb0f177c8
	.word	0xbfd36092,	0x5ec44000
	.word	0xbd4eb929,	0xf344bbd1
	.word	0xbfd355bf,	0x1bd82000
	.word	0xbd491599,	0x1da6c3c6
	.word	0xbfd34aed,	0xad5b1000
	.word	0xbd3a2aac,	0xf2be1fdd
	.word	0xbfd3401e,	0x12aec000
	.word	0xbd4741c6,	0x5548eb71
	.word	0xbfd33550,	0x4b355000
	.word	0xbd446efc,	0x89cefc92
	.word	0xbfd32a84,	0x56512000
	.word	0xbd04f928,	0x139af5d6
	.word	0xbfd31fba,	0x3364c000
	.word	0xbd4a08d8,	0x6ce5a16e
	.word	0xbfd314f1,	0xe1d35000
	.word	0xbd49c761,	0x4b37b0d2
	.word	0xbfd30a2b,	0x61001000
	.word	0xbd4a53e9,	0x6290ef5b
	.word	0xbfd2ff66,	0xb04ea000
	.word	0xbd43a896,	0xd5f0c8e9
	.word	0xbfd2f4a3,	0xcf22e000
	.word	0xbd4b8693,	0xf85f2705
	.word	0xbfd2e9e2,	0xbce12000
	.word	0xbd24300c,	0x128d1dc2
	.word	0xbfd2df23,	0x78edd000
	.word	0xbce292b7,	0xcd95c595
	.word	0xbfd2d466,	0x02adc000
	.word	0xbd49dcbc,	0x88caaf9b
	.word	0xbfd2c9aa,	0x59863000
	.word	0xbd4a7f90,	0xe829d4d2
	.word	0xbfd2bef0,	0x7cdc9000
	.word	0xbd2a9cfa,	0x4a5004f4
	.word	0xbfd2b438,	0x6c168000
	.word	0xbd4e1827,	0x3a343630
	.word	0xbfd2a982,	0x269a3000
	.word	0xbd4b7e9c,	0x6aa35e8c
	.word	0xbfd29ecd,	0xabcdf000
	.word	0xbd44073b,	0x3bdc2243
	.word	0xbfd2941a,	0xfb186000
	.word	0xbd46f79e,	0xa4678ebb
	.word	0xbfd2896a,	0x13e08000
	.word	0xbd3a8ed0,	0x27e16952
	.word	0xbfd27eba,	0xf58d8000
	.word	0xbd49399d,	0xffd2d096
	.word	0xbfd2740d,	0x9f870000
	.word	0xbd45f660,	0x0b9a802a
	.word	0xbfd26962,	0x1134d000
	.word	0xbd4724f0,	0x77d6ecee
	.word	0xbfd25eb8,	0x49ff2000
	.word	0xbd310c25,	0x03f76b8e
	.word	0xbfd25410,	0x494e5000
	.word	0xbd3b1d7a,	0xc0ef77f2
	.word	0xbfd2496a,	0x0e8b3000
	.word	0xbd003238,	0x687cfe2e
	.word	0xbfd23ec5,	0x991eb000
	.word	0xbd44920d,	0xdbae8d6f
	.word	0xbfd23422,	0xe8724000
	.word	0xbd40708a,	0x931c895b
	.word	0xbfd22981,	0xfbef7000
	.word	0xbd42f5ef,	0x4fb53f93
	.word	0xbfd21ee2,	0xd3003000
	.word	0xbd40382e,	0x41be00e3
	.word	0xbfd21445,	0x6d0eb000
	.word	0xbd41a87d,	0xeba46baf
	.word	0xbfd209a9,	0xc9857000
	.word	0xbd45b053,	0x3ba9c94d
	.word	0xbfd1ff0f,	0xe7cf4000
	.word	0xbd3e9d5b,	0x513ff0c1
	.word	0xbfd1f477,	0xc7573000
	.word	0xbd26d6d4,	0x010d751a
	.word	0xbfd1e9e1,	0x67889000
	.word	0xbd43e8a8,	0x961ba4d1
	.word	0xbfd1df4c,	0xc7cf2000
	.word	0xbd30b43f,	0x0455f7e4
	.word	0xbfd1d4b9,	0xe796c000
	.word	0xbd222a66,	0x7c42e56d
	.word	0xbfd1ca28,	0xc64ba000
	.word	0xbd4ca760,	0xf7a15533
	.word	0xbfd1bf99,	0x635a6000
	.word	0xbd4729bb,	0x5451ef6e
	.word	0xbfd1b50b,	0xbe2fc000
	.word	0xbd38ecd7,	0x3263201f
	.word	0xbfd1aa7f,	0xd638d000
	.word	0xbd29f60a,	0x9616f7a0
	.word	0xbfd19ff5,	0xaae2f000
	.word	0xbce69fd9,	0x9ec05ba8
	.word	0xbfd1956d,	0x3b9bc000
	.word	0xbd27d2f7,	0x3ad1aa14
	.word	0xbfd18ae6,	0x87d13000
	.word	0xbd43a034,	0x64df39ff
	.word	0xbfd18061,	0x8ef18000
	.word	0xbd45be80,	0x1bc9638d
	.word	0xbfd175de,	0x506b3000
	.word	0xbd30c07c,	0x4da5752f
	.word	0xbfd16b5c,	0xcbacf000
	.word	0xbd46e6b3,	0x7de945a0
	.word	0xbfd160dd,	0x0025e000
	.word	0xbd4ba5c1,	0xc499684a
	.word	0xbfd1565e,	0xed455000
	.word	0xbd4f8629,	0x48125517
	.word	0xbfd14be2,	0x927ae000
	.word	0xbd49a817,	0xc85685e2
	.word	0xbfd14167,	0xef367000
	.word	0xbd3e0c07,	0x824daaf5
	.word	0xbfd136ef,	0x02e82000
	.word	0xbd4217d3,	0xe78d3ed8
	.word	0xbfd12c77,	0xcd007000
	.word	0xbd13b294,	0x8a11f797
	.word	0xbfd12202,	0x4cf00000
	.word	0xbd38fdd9,	0x76fabda5
	.word	0xbfd1178e,	0x8227e000
	.word	0xbd31ef78,	0xce2d07f2
	.word	0xbfd10d1c,	0x6c194000
	.word	0xbd4cb3de,	0x00324ee4
	.word	0xbfd102ac,	0x0a35c000
	.word	0xbd483810,	0x88080a5e
	.word	0xbfd0f83d,	0x5bef2000
	.word	0xbd475fa0,	0x37a37ba8
	.word	0xbfd0edd0,	0x60b78000
	.word	0xbd0019b5,	0x2d8435f5
	.word	0xbfd0e365,	0x18012000
	.word	0xbd2a5943,	0x8bbdca93
	.word	0xbfd0d8fb,	0x813eb000
	.word	0xbd1ee8c8,	0x8753fa35
	.word	0xbfd0ce93,	0x9be30000
	.word	0xbd4e8266,	0xd788ddf1
	.word	0xbfd0c42d,	0x67616000
	.word	0xbd27188b,	0x163ceae9
	.word	0xbfd0b9c8,	0xe32d1000
	.word	0xbd42224e,	0x89208f94
	.word	0xbfd0af66,	0x0eb9e000
	.word	0xbd23c7c3,	0xf528d80a
	.word	0xbfd0a504,	0xe97bb000
	.word	0xbd303094,	0xe6690c44
	.word	0xbfd09aa5,	0x72e6c000
	.word	0xbd3b50a1,	0xe1734342
	.word	0xbfd09047,	0xaa6f9000
	.word	0xbd3f18e8,	0x3ce75c0e
	.word	0xbfd085eb,	0x8f8ae000
	.word	0xbd3e5d51,	0x3f45fe7b
	.word	0xbfd07b91,	0x21adb000
	.word	0xbd4520ba,	0x8e9b8a72
	.word	0xbfd07138,	0x604d5000
	.word	0xbd40c4e6,	0xd8b76a75
	.word	0xbfd066e1,	0x4adf4000
	.word	0xbd47f6bb,	0x351a4a71
	.word	0xbfd05c8b,	0xe0d96000
	.word	0xbd2ad0f1,	0xc77ccb58
	.word	0xbfd05238,	0x21b1a000
	.word	0xbd4ec752,	0xd39776ce
	.word	0xbfd047e6,	0x0cde8000
	.word	0xbd2dbdf1,	0x0d397f3c
	.word	0xbfd03d95,	0xa1d67000
	.word	0xbd3a1788,	0x0f236109
	.word	0xbfd03346,	0xe0106000
	.word	0xbcf89ff8,	0xa966395c
	.word	0xbfd028f9,	0xc7035000
	.word	0xbd483851,	0x858333c0
	.word	0xbfd01eae,	0x5626c000
	.word	0xbd3a43dc,	0xfade85ae
	.word	0xbfd01464,	0x8cf23000
	.word	0xbd4d082a,	0x567b45ed
	.word	0xbfd00a1c,	0x6adda000
	.word	0xbd31cd8d,	0x688b9e18
	.word	0xbfcfffab,	0xdec23000
	.word	0xbd236a1a,	0xdb4a75a4
	.word	0xbfcfeb22,	0x33ea0000
	.word	0xbd2f3418,	0xde00938b
	.word	0xbfcfd69b,	0xd4240000
	.word	0xbd3641a8,	0xff2ccc45
	.word	0xbfcfc218,	0xbe620000
	.word	0xbd34bba4,	0x6f1cf6a0
	.word	0xbfcfad98,	0xf1965000
	.word	0xbd16ee92,	0x73d7c2de
	.word	0xbfcf991c,	0x6cb3b000
	.word	0xbd1bcbec,	0xca0cdf30
	.word	0xbfcf84a3,	0x2ead7000
	.word	0xbd386af1,	0xd33d9e37
	.word	0xbfcf702d,	0x36777000
	.word	0xbd3bdf9a,	0xba663077
	.word	0xbfcf5bba,	0x83060000
	.word	0xbd341b25,	0x4a43da63
	.word	0xbfcf474b,	0x134df000
	.word	0xbd1146d8,	0x38821289
	.word	0xbfcf32de,	0xe6448000
	.word	0xbd2efb83,	0x625f1609
	.word	0xbfcf1e75,	0xfadf9000
	.word	0xbd37bcea,	0x6d13e04a
	.word	0xbfcf0a10,	0x50157000
	.word	0xbd3dad5f,	0x7347f55b
	.word	0xbfcef5ad,	0xe4dcf000
	.word	0xbd3fcbbd,	0xd53488e4
	.word	0xbfcee14e,	0xb82d6000
	.word	0xbd39d172,	0x6f4de261
	.word	0xbfceccf2,	0xc8fe9000
	.word	0xbd104e71,	0x7062a6fe
	.word	0xbfceb89a,	0x1648b000
	.word	0xbd32e26f,	0x74808b80
	.word	0xbfcea444,	0x9f04a000
	.word	0xbd35e916,	0x63732a36
	.word	0xbfce8ff2,	0x622ba000
	.word	0xbd378e13,	0xd33981e5
	.word	0xbfce7ba3,	0x5eb77000
	.word	0xbd3c5422,	0x3b90d937
	.word	0xbfce6757,	0x93a26000
	.word	0xbd01dc8e,	0xc0554762
	.word	0xbfce530e,	0xffe71000
	.word	0xbcc21227,	0x6041f430
	.word	0xbfce3ec9,	0xa280c000
	.word	0xbd14bd96,	0x3fb80bff
	.word	0xbfce2a87,	0x7a6b2000
	.word	0xbd382381,	0x7787081a
	.word	0xbfce1648,	0x86a27000
	.word	0xbd36ce95,	0xba645527
	.word	0xbfce020c,	0xc6235000
	.word	0xbd356a7f,	0xa92375ee
	.word	0xbfcdedd4,	0x37eae000
	.word	0xbd3e0125,	0x53595898
	.word	0xbfcdd99e,	0xdaf6d000
	.word	0xbd2fa273,	0x2c71522a
	.word	0xbfcdc56c,	0xae452000
	.word	0xbd3eb37a,	0xa24e1817
	.word	0xbfcdb13d,	0xb0d48000
	.word	0xbd32806a,	0x847527e6
	.word	0xbfcd9d11,	0xe1a3f000
	.word	0xbd19da04,	0xfa9fa4c6
	.word	0xbfcd88e9,	0x3fb2f000
	.word	0xbd2141af,	0xfb96815e
	.word	0xbfcd74c3,	0xca018000
	.word	0xbd393e4c,	0xfa17dce1
	.word	0xbfcd60a1,	0x7f903000
	.word	0xbd24523f,	0x207be58e
	.word	0xbfcd4c82,	0x5f5fd000
	.word	0xbd3e3f04,	0x21df291e
	.word	0xbfcd3866,	0x6871f000
	.word	0xbd21935e,	0x98ed9a88
	.word	0xbfcd244d,	0x99c85000
	.word	0xbd29cfb0,	0x0c890770
	.word	0xbfcd1037,	0xf2655000
	.word	0xbd3cf6b0,	0x31492124
	.word	0xbfccfc25,	0x714bd000
	.word	0xbd39fbd3,	0x34e03910
	.word	0xbfcce816,	0x157f1000
	.word	0xbd330faa,	0x2efb3576
	.word	0xbfccd409,	0xde02d000
	.word	0xbd132115,	0x39f1dcc5
	.word	0xbfccc000,	0xc9db3000
	.word	0xbd38a4a9,	0xe8aa1402
	.word	0xbfccabfa,	0xd80d0000
	.word	0xbd11e253,	0x70a10e3e
	.word	0xbfcc97f8,	0x079d4000
	.word	0xbd23b161,	0xa8c6e6c5
	.word	0xbfcc83f8,	0x57919000
	.word	0xbd358740,	0x00c94a0f
	.word	0xbfcc6ffb,	0xc6f00000
	.word	0xbd3ee138,	0xd3a69d43
	.word	0xbfcc5c02,	0x54bf2000
	.word	0xbd1d2f55,	0x73da163b
	.word	0xbfcc480c,	0x0005c000
	.word	0xbd39a294,	0xd5e44e76
	.word	0xbfcc3418,	0xc7cb7000
	.word	0xbd234b5d,	0xe46e0516
	.word	0xbfcc2028,	0xab17f000
	.word	0xbd3368f8,	0x8d51c29d
	.word	0xbfcc0c3b,	0xa8f3a000
	.word	0xbd3ac339,	0x48e7f56a
	.word	0xbfcbf851,	0xc0675000
	.word	0xbd257be3,	0x67ef56a7
	.word	0xbfcbe46a,	0xf07c2000
	.word	0xbd350591,	0x910f505a
	.word	0xbfcbd087,	0x383bd000
	.word	0xbd315a1d,	0xd355f6a5
	.word	0xbfcbbca6,	0x96b07000
	.word	0xbd3d0045,	0xea3f2624
	.word	0xbfcba8c9,	0x0ae4a000
	.word	0xbd3a32e7,	0xf44432da
	.word	0xbfcb94ee,	0x93e36000
	.word	0xbd2f2a06,	0xe2db48a3
	.word	0xbfcb8117,	0x30b82000
	.word	0xbd1e9068,	0x3b9cd768
	.word	0xbfcb6d42,	0xe06ec000
	.word	0xbd302afe,	0x254869ba
	.word	0xbfcb5971,	0xa213a000
	.word	0xbd39b50e,	0x83aa91df
	.word	0xbfcb45a3,	0x74b39000
	.word	0xbd3701df,	0x22138fc3
	.word	0xbfcb31d8,	0x575bc000
	.word	0xbd3c794e,	0x562a63cb
	.word	0xbfcb1e10,	0x4919e000
	.word	0xbd3fa006,	0x2597f33a
	.word	0xbfcb0a4b,	0x48fc1000
	.word	0xbd368c69,	0x51e3338a
	.word	0xbfcaf689,	0x5610d000
	.word	0xbd375beb,	0xba042b64
	.word	0xbfcae2ca,	0x6f672000
	.word	0xbd37a8d5,	0xae54f550
	.word	0xbfcacf0e,	0x940e7000
	.word	0xbd2800e3,	0xa7e64e07
	.word	0xbfcabb55,	0xc3169000
	.word	0xbd1d6694,	0xd43acc9f
	.word	0xbfcaa79f,	0xfb8fc000
	.word	0xbd3a8bf1,	0x1c0d8aaa
	.word	0xbfca93ed,	0x3c8ad000
	.word	0xbd33c6de,	0x57d4ef4c
	.word	0xbfca803d,	0x8518d000
	.word	0xbd3e09d1,	0x87f293cc
	.word	0xbfca6c90,	0xd44b7000
	.word	0xbce38901,	0xf909e74b
	.word	0xbfca58e7,	0x29348000
	.word	0xbd3e867d,	0x504551b1
	.word	0xbfca4540,	0x82e6a000
	.word	0xbd360a77,	0xc81f7171
	.word	0xbfca319c,	0xe074a000
	.word	0xbcbd7dba,	0xe650d5b3
	.word	0xbfca1dfc,	0x40f1b000
	.word	0xbd2fc3e1,	0xff6190fe
	.word	0xbfca0a5e,	0xa371a000
	.word	0xbd322191,	0x988b2e31
	.word	0xbfc9f6c4,	0x07089000
	.word	0xbd29904d,	0x6865817a
	.word	0xbfc9e32c,	0x6acb0000
	.word	0xbd3e5e8d,	0xbc0fb4ac
	.word	0xbfc9cf97,	0xcdce0000
	.word	0xbd3d862f,	0x10c414e3
	.word	0xbfc9bc06,	0x2f26f000
	.word	0xbd3874d8,	0x1809e6d5
	.word	0xbfc9a877,	0x8deba000
	.word	0xbd3470fa,	0x3efec390
	.word	0xbfc994eb,	0xe9325000
	.word	0xbd2a9c9d,	0x28bcbe25
	.word	0xbfc98163,	0x4011a000
	.word	0xbd34eadd,	0x9e9045e2
	.word	0xbfc96ddd,	0x91a0b000
	.word	0xbd32ac6b,	0x11cf6f2b
	.word	0xbfc95a5a,	0xdcf70000
	.word	0xbd07f228,	0x58a0ff6f
	.word	0xbfc946db,	0x212c6000
	.word	0xbd36cf76,	0x74ca02ba
	.word	0xbfc9335e,	0x5d594000
	.word	0xbd33115c,	0x3abd47da
	.word	0xbfc91fe4,	0x90965000
	.word	0xbd30369c,	0xf30a1c32
	.word	0xbfc90c6d,	0xb9fcb000
	.word	0xbd39b282,	0xa239ca0d
	.word	0xbfc8f8f9,	0xd8a60000
	.word	0xbd2af16c,	0x8230ceca
	.word	0xbfc8e588,	0xebac2000
	.word	0xbd3b7d5c,	0xab2d1140
	.word	0xbfc8d21a,	0xf2299000
	.word	0xbd14d652,	0x74757226
	.word	0xbfc8beaf,	0xeb38f000
	.word	0xbd3d1855,	0x6aa2da66
	.word	0xbfc8ab47,	0xd5f5a000
	.word	0xbd187eb8,	0x505d468f
	.word	0xbfc897e2,	0xb17b1000
	.word	0xbd334a64,	0x63f9a0b1
	.word	0xbfc88480,	0x7ce56000
	.word	0xbd1c77ce,	0xf4a8712c
	.word	0xbfc87121,	0x3750e000
	.word	0xbd3328eb,	0x42f9af75
	.word	0xbfc85dc4,	0xdfda7000
	.word	0xbd3785ab,	0x048301ba
	.word	0xbfc84a6b,	0x759f5000
	.word	0xbd02ebfe,	0xa903cfb8
	.word	0xbfc83714,	0xf7bd0000
	.word	0xbd2ed83a,	0xf85a2ced
	.word	0xbfc823c1,	0x6551a000
	.word	0xbd1e0ddb,	0x9a631e83
	.word	0xbfc81070,	0xbd7b9000
	.word	0xbcafe80a,	0x6682e646
	.word	0xbfc7fd22,	0xff599000
	.word	0xbd3a9d05,	0x02ea120c
	.word	0xbfc7e9d8,	0x2a0b0000
	.word	0xbd116849,	0xfa40e4f0
	.word	0xbfc7d690,	0x3caf5000
	.word	0xbd359fca,	0x741e7f15
	.word	0xbfc7c34b,	0x3666a000
	.word	0xbd3175c9,	0x81b45e10
	.word	0xbfc7b009,	0x16515000
	.word	0xbd146280,	0xd3e606a3
	.word	0xbfc79cc9,	0xdb902000
	.word	0xbd1e00d0,	0x375e70bd
	.word	0xbfc7898d,	0x85444000
	.word	0xbd38e67b,	0xe3dbaf3f
	.word	0xbfc77654,	0x128f6000
	.word	0xbd0274ba,	0xdf268e7c
	.word	0xbfc7631d,	0x82935000
	.word	0xbd350c41,	0x1c1d060f
	.word	0xbfc74fe9,	0xd4729000
	.word	0xbd249736,	0xd91da11e
	.word	0xbfc73cb9,	0x074fd000
	.word	0xbd04cab7,	0x97ffd2cc
	.word	0xbfc7298b,	0x1a4e3000
	.word	0xbd15accc,	0xe43ce383
	.word	0xbfc71660,	0x0c914000
	.word	0xbce51b15,	0x7cec3838
	.word	0xbfc70337,	0xdd3ce000
	.word	0xbd206a17,	0x8a5eab9c
	.word	0xbfc6f012,	0x8b756000
	.word	0xbd357739,	0x0d31ef0f
	.word	0xbfc6dcf0,	0x165f8000
	.word	0xbd1b9566,	0x9a33e4c6
	.word	0xbfc6c9d0,	0x7d203000
	.word	0xbd3f8e30,	0x14099349
	.word	0xbfc6b6b3,	0xbedd1000
	.word	0xbd1a8f73,	0xa64d3813
	.word	0xbfc6a399,	0xdabbd000
	.word	0xbd1c1b2c,	0x6657a967
	.word	0xbfc69082,	0xcfe2b000
	.word	0xbd2da1e7,	0x20b79662
	.word	0xbfc67d6e,	0x9d785000
	.word	0xbd2dc2ef,	0x9eb1f25a
	.word	0xbfc66a5d,	0x42a3a000
	.word	0xbd3a6893,	0x3aa00298
	.word	0xbfc6574e,	0xbe8c1000
	.word	0xbd19cf8b,	0x2c3c2e78
	.word	0xbfc64443,	0x10594000
	.word	0xbd22f605,	0xb0281916
	.word	0xbfc6313a,	0x37335000
	.word	0xbd3aec82,	0xac378565
	.word	0xbfc61e34,	0x3242d000
	.word	0xbd32bb2d,	0x97ecd861
	.word	0xbfc60b31,	0x00b09000
	.word	0xbd21d752,	0x6cee0fd8
	.word	0xbfc5f830,	0xa1a5c000
	.word	0xbd352268,	0x98ffc1bc
	.word	0xbfc5e533,	0x144c1000
	.word	0xbd2c63e8,	0x189ade2b
	.word	0xbfc5d238,	0x57cd7000
	.word	0xbd23530a,	0x5ba6e7ac
	.word	0xbfc5bf40,	0x6b543000
	.word	0xbd3b63f7,	0x0525d9f9
	.word	0xbfc5ac4b,	0x4e0b2000
	.word	0xbd351709,	0xd7275f36
	.word	0xbfc59958,	0xff1d5000
	.word	0xbd178be9,	0xa258d7eb
	.word	0xbfc58669,	0x7db62000
	.word	0xbd39e26c,	0x65e8cb44
	.word	0xbfc5737c,	0xc9018000
	.word	0xbd39baa7,	0xa6b887f6
	.word	0xbfc56092,	0xe02ba000
	.word	0xbd245850,	0x06899d98
	.word	0xbfc54dab,	0xc2610000
	.word	0xbd2746fe,	0xe5c8d0d8
	.word	0xbfc53ac7,	0x6ece9000
	.word	0xbd39ca8a,	0x2a8725d5
	.word	0xbfc527e5,	0xe4a1b000
	.word	0xbd2633e8,	0xe5697dc7
	.word	0xbfc51507,	0x2307f000
	.word	0xbd306b11,	0xecc0d77b
	.word	0xbfc5022b,	0x292f6000
	.word	0xbd348a05,	0xff36a25b
	.word	0xbfc4ef51,	0xf6466000
	.word	0xbd3bc83d,	0x21c8cd53
	.word	0xbfc4dc7b,	0x897bc000
	.word	0xbd0c79b6,	0x0ae1ff0f
	.word	0xbfc4c9a7,	0xe1fe8000
	.word	0xbcff39f7,	0x50dbbb30
	.word	0xbfc4b6d6,	0xfefe2000
	.word	0xbd1522ec,	0xf56e7952
	.word	0xbfc4a408,	0xdfaa7000
	.word	0xbd33b41f,	0x86e5dd72
	.word	0xbfc4913d,	0x8333b000
	.word	0xbd258379,	0x54fdb678
	.word	0xbfc47e74,	0xe8ca5000
	.word	0xbd3ef836,	0xa48fdfcf
	.word	0xbfc46baf,	0x0f9f5000
	.word	0xbd3b6d8c,	0xbe1bdef9
	.word	0xbfc458eb,	0xf6e3f000
	.word	0xbcf5c0fe,	0x1f2b8094
	.word	0xbfc4462b,	0x9dc9b000
	.word	0xbd1ede9d,	0x63b93e7a
	.word	0xbfc4336e,	0x03829000
	.word	0xbd3ac363,	0xa859c2af
	.word	0xbfc420b3,	0x2740f000
	.word	0xbd3ba75f,	0x4de97ddf
	.word	0xbfc40dfb,	0x08378000
	.word	0xbc9bb453,	0xc4f7b685
	.word	0xbfc3fb45,	0xa5992000
	.word	0xbd319713,	0xc0cae559
	.word	0xbfc3e892,	0xfe995000
	.word	0xbd2b6aad,	0x914d5249
	.word	0xbfc3d5e3,	0x126bc000
	.word	0xbd13fb2f,	0x85096c4b
	.word	0xbfc3c335,	0xe0447000
	.word	0xbd3ae77d,	0x114a8b5f
	.word	0xbfc3b08b,	0x6757f000
	.word	0xbd15485c,	0x35b37c15
	.word	0xbfc39de3,	0xa6dae000
	.word	0xbd284fc7,	0x32ce95f1
	.word	0xbfc38b3e,	0x9e027000
	.word	0xbd21e21f,	0x5747d00e
	.word	0xbfc3789c,	0x4c041000
	.word	0xbd19b4f4,	0x44d31e60
	.word	0xbfc365fc,	0xb0159000
	.word	0xbcc62fa8,	0x234b7289
	.word	0xbfc3535f,	0xc96d1000
	.word	0xbd013f1c,	0x3b1fab68
	.word	0xbfc340c5,	0x97411000
	.word	0xbd20b846,	0x104c58f3
	.word	0xbfc32e2e,	0x18c86000
	.word	0xbd3e6220,	0x6c327115
	.word	0xbfc31b99,	0x4d3a4000
	.word	0xbd3f098e,	0xe3a50810
	.word	0xbfc30907,	0x33ce3000
	.word	0xbd33f323,	0x7c4d853e
	.word	0xbfc2f677,	0xcbbc0000
	.word	0xbd352b30,	0x2160f40d
	.word	0xbfc2e3eb,	0x143bf000
	.word	0xbd218910,	0x2710016e
	.word	0xbfc2d161,	0x0c868000
	.word	0xbd039d6c,	0xcb81b4a1
	.word	0xbfc2bed9,	0xb3d49000
	.word	0xbd095245,	0x4a40d26b
	.word	0xbfc2ac55,	0x095f5000
	.word	0xbd38b2e6,	0x4bce4dd6
	.word	0xbfc299d3,	0x0c606000
	.word	0xbd3d4d00,	0x79dc08d9
	.word	0xbfc28753,	0xbc11a000
	.word	0xbd37494e,	0x359302e6
	.word	0xbfc274d7,	0x17ad4000
	.word	0xbd38a65b,	0xa0967592
	.word	0xbfc2625d,	0x1e6dd000
	.word	0xbd3ead69,	0xd0f61c28
	.word	0xbfc24fe5,	0xcf8e4000
	.word	0xbd318f96,	0x26b10d30
	.word	0xbfc23d71,	0x2a49c000
	.word	0xbd100d23,	0x8fd3df5c
	.word	0xbfc22aff,	0x2ddbd000
	.word	0xbd32e1ea,	0xca7cb4f0
	.word	0xbfc2188f,	0xd9807000
	.word	0xbd131786,	0x02bce3fb
	.word	0xbfc20623,	0x2c73c000
	.word	0xbd2351a5,	0x02bb95f5
	.word	0xbfc1f3b9,	0x25f25000
	.word	0xbd3a822c,	0x593df273
	.word	0xbfc1e151,	0xc5391000
	.word	0xbd38e5f5,	0xf578d80e
	.word	0xbfc1ceed,	0x09853000
	.word	0xbd2d47c7,	0x8dcdaa0e
	.word	0xbfc1bc8a,	0xf2143000
	.word	0xbd2acd64,	0xfb955458
	.word	0xbfc1aa2b,	0x7e23f000
	.word	0xbd2ca78e,	0x44389934
	.word	0xbfc197ce,	0xacf2a000
	.word	0xbd31ab14,	0x4caf6736
	.word	0xbfc18574,	0x7dbec000
	.word	0xbd3e6744,	0x45bd9b49
	.word	0xbfc1731c,	0xefc74000
	.word	0xbcfde27c,	0xd98317fd
	.word	0xbfc160c8,	0x024b2000
	.word	0xbd2ec2d2,	0xa9009e3d
	.word	0xbfc14e75,	0xb489f000
	.word	0xbd3fdf84,	0x66dfe192
	.word	0xbfc13c26,	0x05c39000
	.word	0xbd318501,	0x13584d7c
	.word	0xbfc129d8,	0xf5381000
	.word	0xbd1d77cc,	0x415a172e
	.word	0xbfc1178e,	0x8227e000
	.word	0xbd21ef78,	0xce2d07f2
	.word	0xbfc10546,	0xabd3d000
	.word	0xbd00189b,	0x51d162e8
	.word	0xbfc0f301,	0x717cf000
	.word	0xbcff64bb,	0xe51793b4
	.word	0xbfc0e0be,	0xd264a000
	.word	0xbd3bafe2,	0x3aeb549c
	.word	0xbfc0ce7e,	0xcdccc000
	.word	0xbd14652d,	0xabff5447
	.word	0xbfc0bc41,	0x62f73000
	.word	0xbd36ca04,	0x73bd9c29
	.word	0xbfc0aa06,	0x91267000
	.word	0xbd2755cc,	0x51f9bdae
	.word	0xbfc097ce,	0x579d2000
	.word	0xbce33742,	0xda652881
	.word	0xbfc08598,	0xb59e3000
	.word	0xbd340d11,	0x47fb37ea
	.word	0xbfc07365,	0xaa6d1000
	.word	0xbd16e172,	0x43f1226a
	.word	0xbfc06135,	0x354d4000
	.word	0xbd363046,	0x28340ee9
	.word	0xbfc04f07,	0x5582d000
	.word	0xbd1a3d31,	0x4c780403
	.word	0xbfc03cdc,	0x0a51e000
	.word	0xbd381a9c,	0xf169fc5c
	.word	0xbfc02ab3,	0x52ff2000
	.word	0xbd27ce63,	0x5d569b2b
	.word	0xbfc0188d,	0x2ecf6000
	.word	0xbd03f965,	0x1cff9dfe
	.word	0xbfc00669,	0x9d07c000
	.word	0xbd3b8775,	0x304686e1
	.word	0xbfbfe891,	0x39dbd000
	.word	0xbd159653,	0x60bdea07
	.word	0xbfbfc454,	0x5b8f0000
	.word	0xbd29cba7,	0xd5591204
	.word	0xbfbfa01c,	0x9db57000
	.word	0xbd29c32b,	0x816dd634
	.word	0xbfbf7be9,	0xfedbf000
	.word	0xbd2bcbe8,	0xb535310e
	.word	0xbfbf57bc,	0x7d900000
	.word	0xbd176a6c,	0x9ea8b04e
	.word	0xbfbf3394,	0x185fa000
	.word	0xbd1ea383,	0x09d097b7
	.word	0xbfbf0f70,	0xcdd99000
	.word	0xbd0718fb,	0x613960ee
	.word	0xbfbeeb52,	0x9c8d1000
	.word	0xbd0b6260,	0x903c8f99
	.word	0xbfbec739,	0x830a1000
	.word	0xbcf1fcba,	0x80cdd0fe
	.word	0xbfbea325,	0x7fe10000
	.word	0xbd2ef30d,	0x47e4627a
	.word	0xbfbe7f16,	0x91a32000
	.word	0xbd2a7c74,	0xc871080d
	.word	0xbfbe5b0c,	0xb6e22000
	.word	0xbd109021,	0x3b34d95f
	.word	0xbfbe3707,	0xee304000
	.word	0xbd20f684,	0xe6766abd
	.word	0xbfbe1308,	0x36208000
	.word	0xbd21aeea,	0xf90019f9
	.word	0xbfbdef0d,	0x8d466000
	.word	0xbd2b715f,	0x7da2cb17
	.word	0xbfbdcb17,	0xf2361000
	.word	0xbd226a0a,	0x5ba47956
	.word	0xbfbda727,	0x63844000
	.word	0xbd1a8940,	0x1fa71733
	.word	0xbfbd833b,	0xdfc64000
	.word	0xbd24805c,	0x07408695
	.word	0xbfbd5f55,	0x65921000
	.word	0xbcec4739,	0x830a8d2a
	.word	0xbfbd3b73,	0xf37e1000
	.word	0xbd2f3501,	0x33da5007
	.word	0xbfbd1797,	0x88219000
	.word	0xbd0b219d,	0xaf7df76b
	.word	0xbfbcf3c0,	0x22142000
	.word	0xbce9d2b6,	0x6ddd996f
	.word	0xbfbccfed,	0xbfee1000
	.word	0xbd0d4119,	0x7f3892ad
	.word	0xbfbcac20,	0x60484000
	.word	0xbd2d53ed,	0xcc4f420b
	.word	0xbfbc8858,	0x01bc4000
	.word	0xbd2646d1,	0xc65aacd3
	.word	0xbfbc6494,	0xa2e41000
	.word	0xbd214bd1,	0x564189cb
	.word	0xbfbc40d6,	0x425a5000
	.word	0xbd296224,	0x3a3261b9
	.word	0xbfbc1d1c,	0xdeba5000
	.word	0xbd02f7e7,	0x23a02373
	.word	0xbfbbf968,	0x769fc000
	.word	0xbd24218c,	0x8d824283
	.word	0xbfbbd5b9,	0x08a72000
	.word	0xbd2236aa,	0x3ae84f31
	.word	0xbfbbb20e,	0x936d6000
	.word	0xbd22e8af,	0x9574c8e4
	.word	0xbfbb8e69,	0x15901000
	.word	0xbd22bef7,	0xf208fbd9
	.word	0xbfbb6ac8,	0x8dad5000
	.word	0xbd2637bf,	0xea044b8d
	.word	0xbfbb472c,	0xfa63e000
	.word	0xbd1246f5,	0xc7f4588b
	.word	0xbfbb2396,	0x5a52f000
	.word	0xbd2e009b,	0x115ec8f8
	.word	0xbfbb0004,	0xac1a8000
	.word	0xbd1aaf97,	0x037f2b35
	.word	0xbfbadc77,	0xee5ae000
	.word	0xbd25189b,	0xec79cdf7
	.word	0xbfbab8f0,	0x1fb52000
	.word	0xbd27f69d,	0xd23d3ac2
	.word	0xbfba956d,	0x3ecad000
	.word	0xbd2cc6f2,	0x9805895f
	.word	0xbfba71ef,	0x4a3e2000
	.word	0xbd1bbc94,	0x7b201fbf
	.word	0xbfba4e76,	0x40b1b000
	.word	0xbd286f52,	0x51aefe0e
	.word	0xbfba2b02,	0x20c8e000
	.word	0xbd17d329,	0x8e6b7dbf
	.word	0xbfba0792,	0xe9277000
	.word	0xbd2958c6,	0x4d94ab90
	.word	0xbfb9e428,	0x9871e000
	.word	0xbd22c483,	0xd0942b9c
	.word	0xbfb9c0c3,	0x2d4d2000
	.word	0xbd1520fd,	0x85f1e661
	.word	0xbfb99d62,	0xa65eb000
	.word	0xbd22dd17,	0xd834450a
	.word	0xbfb97a07,	0x024cb000
	.word	0xbd2ce867,	0xd19bed86
	.word	0xbfb956b0,	0x3fbdd000
	.word	0xbd286fb6,	0x03fe1b67
	.word	0xbfb9335e,	0x5d594000
	.word	0xbd23115c,	0x3abd47da
	.word	0xbfb91011,	0x59c6c000
	.word	0xbd27af17,	0x9df80b59
	.word	0xbfb8ecc9,	0x33aeb000
	.word	0xbd1ba18c,	0x833010ab
	.word	0xbfb8c985,	0xe9b9e000
	.word	0xbd290791,	0x0379ff94
	.word	0xbfb8a647,	0x7a91d000
	.word	0xbd285181,	0x5f37adbf
	.word	0xbfb8830d,	0xe4e08000
	.word	0xbd05f60b,	0x79c8f66a
	.word	0xbfb85fd9,	0x27506000
	.word	0xbd248fcf,	0xccd1e7c7
	.word	0xbfb83ca9,	0x408ca000
	.word	0xbd2326c8,	0xd744c7d1
	.word	0xbfb8197e,	0x2f40e000
	.word	0xbd0f80dc,	0xf96ffdf7
	.word	0xbfb7f657,	0xf2194000
	.word	0xbd21bef9,	0x43faf4d2
	.word	0xbfb7d336,	0x87c29000
	.word	0xbd0e4461,	0xf3833832
	.word	0xbfb7b019,	0xeeea0000
	.word	0xbd275649,	0xaee848d4
	.word	0xbfb78d02,	0x263d8000
	.word	0xbd069b57,	0x94b69fb7
	.word	0xbfb769ef,	0x2c6b5000
	.word	0xbd1a35d8,	0xc73b6a55
	.word	0xbfb746e1,	0x00226000
	.word	0xbd2db25d,	0x23c3bc5b
	.word	0xbfb723d7,	0xa0123000
	.word	0xbd2c3cbb,	0x84fef08e
	.word	0xbfb700d3,	0x0aeac000
	.word	0xbcec1e8d,	0xa99ded32
	.word	0xbfb6ddd3,	0x3f5c7000
	.word	0xbd2aeb06,	0x82906a06
	.word	0xbfb6bad8,	0x3c188000
	.word	0xbd0daf3c,	0xc08926ae
	.word	0xbfb697e1,	0xffd06000
	.word	0xbd296c57,	0x15a12bb6
	.word	0xbfb674f0,	0x89365000
	.word	0xbd24f332,	0x993a6604
	.word	0xbfb65203,	0xd6fcf000
	.word	0xbd1ea006,	0x8199326b
	.word	0xbfb62f1b,	0xe7d77000
	.word	0xbd1d0cd5,	0x02538764
	.word	0xbfb60c38,	0xba799000
	.word	0xbd1172c4,	0x3aec1296
	.word	0xbfb5e95a,	0x4d979000
	.word	0xbcfcb7ce,	0x1d171711
	.word	0xbfb5c680,	0x9fe63000
	.word	0xbd23c479,	0x935581b6
	.word	0xbfb5a3ab,	0xb01ad000
	.word	0xbd2c4ae9,	0x3cd5f430
	.word	0xbfb580db,	0x7ceb5000
	.word	0xbd1c07f6,	0xcbe60d53
	.word	0xbfb55e10,	0x050e0000
	.word	0xbd0c1d74,	0x0c53c72e
	.word	0xbfb53b49,	0x4739c000
	.word	0xbd221868,	0x5306aaa5
	.word	0xbfb51887,	0x42261000
	.word	0xbd0850ec,	0xb12c59ec
	.word	0xbfb4f5c9,	0xf48ad000
	.word	0xbd0580c1,	0x2c81f8fd
	.word	0xbfb4d311,	0x5d207000
	.word	0xbd2d58bb,	0x4fa163c2
	.word	0xbfb4b05d,	0x7aa01000
	.word	0xbd07029c,	0x6ef93715
	.word	0xbfb48dae,	0x4bc31000
	.word	0xbcb85b20,	0x8c200bea
	.word	0xbfb46b03,	0xcf437000
	.word	0xbd2787a5,	0x2f0f6296
	.word	0xbfb4485e,	0x03dbd000
	.word	0xbd2f5a8d,	0xd1a4d56e
	.word	0xbfb425bc,	0xe8474000
	.word	0xbd2365ac,	0x5219daef
	.word	0xbfb40320,	0x7b414000
	.word	0xbd26fd84,	0xaa8157c0
	.word	0xbfb3e088,	0xbb85f000
	.word	0xbd248068,	0xbdc331fa
	.word	0xbfb3bdf5,	0xa7d1e000
	.word	0xbd2cc85e,	0xa5db4ed7
	.word	0xbfb39b67,	0x3ee24000
	.word	0xbd0a759b,	0xa99f5667
	.word	0xbfb378dd,	0x7f749000
	.word	0xbd1c5044,	0xa3c7eb28
	.word	0xbfb35658,	0x68470000
	.word	0xbd2464d7,	0x0035b508
	.word	0xbfb333d7,	0xf8183000
	.word	0xbd2e96d4,	0x957e477c
	.word	0xbfb3115c,	0x2da75000
	.word	0xbd25bc37,	0x00651448
	.word	0xbfb2eee5,	0x07b40000
	.word	0xbd08081e,	0xdd77c860
	.word	0xbfb2cc72,	0x84fe5000
	.word	0xbd2e38bd,	0x0cb32a28
	.word	0xbfb2aa04,	0xa4471000
	.word	0xbd1e922e,	0xa2c72d06
	.word	0xbfb2879b,	0x644f5000
	.word	0xbd1752b6,	0xf65943ec
	.word	0xbfb26536,	0xc3d8c000
	.word	0xbd0b4bac,	0x097c5ba3
	.word	0xbfb242d6,	0xc1a58000
	.word	0xbd24b838,	0xac648481
	.word	0xbfb2207b,	0x5c785000
	.word	0xbd127633,	0xf0431efb
	.word	0xbfb1fe24,	0x93144000
	.word	0xbd27a374,	0xe1a7c696
	.word	0xbfb1dbd2,	0x643d1000
	.word	0xbd221649,	0xb2ef8928
	.word	0xbfb1b984,	0xceb6e000
	.word	0xbd121a31,	0x2f307601
	.word	0xbfb1973b,	0xd1465000
	.word	0xbd159b45,	0x53e4c2cb
	.word	0xbfb174f7,	0x6ab09000
	.word	0xbcf71031,	0x7ee2e483
	.word	0xbfb152b7,	0x99bb3000
	.word	0xbd299135,	0xbe3f3df6
	.word	0xbfb1307c,	0x5d2c7000
	.word	0xbd2357c9,	0xfa3dbf1f
	.word	0xbfb10e45,	0xb3cae000
	.word	0xbd20612d,	0xaf6b9737
	.word	0xbfb0ec13,	0x9c5da000
	.word	0xbd180247,	0xe54ebd73
	.word	0xbfb0c9e6,	0x15ac4000
	.word	0xbd2c2da8,	0x0974d976
	.word	0xbfb0a7bd,	0x1e7ef000
	.word	0xbd20f926,	0xcdf8dfb4
	.word	0xbfb08598,	0xb59e3000
	.word	0xbd240d11,	0x47fb37ea
	.word	0xbfb06378,	0xd9d32000
	.word	0xbd104990,	0x672b0729
	.word	0xbfb0415d,	0x89e74000
	.word	0xbd1111c0,	0x5cf1d753
	.word	0xbfb01f46,	0xc4a4a000
	.word	0xbd11157c,	0x89ecf845
	.word	0xbfaffa69,	0x11ab9000
	.word	0xbcf80464,	0xc1c0d47a
	.word	0xbfafb64d,	0xaa8b6000
	.word	0xbd13830d,	0xaeb373e0
	.word	0xbfaf723b,	0x517fc000
	.word	0xbd048a79,	0x154f796a
	.word	0xbfaf2e32,	0x04209000
	.word	0xbcfb9ba8,	0x2f4d6e7f
	.word	0xbfaeea31,	0xc006b000
	.word	0xbd10f760,	0xd81b6242
	.word	0xbfaea63a,	0x82cc0000
	.word	0xbd19f144,	0x08e210e7
	.word	0xbfae624c,	0x4a0b5000
	.word	0xbd1c368e,	0x2e6265dd
	.word	0xbfae1e67,	0x13606000
	.word	0xbd1a0d3c,	0xb7b141db
	.word	0xbfadda8a,	0xdc67e000
	.word	0xbd1c9ca7,	0x364c37a2
	.word	0xbfad96b7,	0xa2bf8000
	.word	0xbd12eb81,	0xf49d3d78
	.word	0xbfad52ed,	0x6405d000
	.word	0xbd10de8b,	0x575910a6
	.word	0xbfad0f2c,	0x1dda6000
	.word	0xbd0c6fc7,	0x04385ddf
	.word	0xbfaccb73,	0xcdddb000
	.word	0xbcf65c36,	0xe09f5fe2
	.word	0xbfac87c4,	0x71b12000
	.word	0xbd13799a,	0xf29d923d
	.word	0xbfac441e,	0x06f72000
	.word	0xbd153c7d,	0x26143455
	.word	0xbfac0080,	0x8b530000
	.word	0xbd003c05,	0x63baea2e
	.word	0xbfabbceb,	0xfc68f000
	.word	0xbd0080f2,	0xe79d07ab
	.word	0xbfab7960,	0x57de2000
	.word	0xbd0f5af1,	0xf7b24d0f
	.word	0xbfab35dd,	0x9b58b000
	.word	0xbd1559d3,	0x5b3d5639
	.word	0xbfaaf263,	0xc47fb000
	.word	0xbd085458,	0x172a97ad
	.word	0xbfaaaef2,	0xd0fb1000
	.word	0xbcdf8346,	0xa77685c1
	.word	0xbfaa6b8a,	0xbe73a000
	.word	0xbd1e988d,	0x46e25c90
	.word	0xbfaa282b,	0x8a936000
	.word	0xbce70a67,	0xf10371d7
	.word	0xbfa9e4d5,	0x3304e000
	.word	0xbcfec4a6,	0x991acef2
	.word	0xbfa9a187,	0xb573d000
	.word	0xbd1cf746,	0xc4ec9bca
	.word	0xbfa95e43,	0x0f8ce000
	.word	0xbd01774c,	0x225e2c8d
	.word	0xbfa91b07,	0x3efd7000
	.word	0xbcf8a0eb,	0x0224d5a9
	.word	0xbfa8d7d4,	0x4173f000
	.word	0xbcf24a7b,	0x7a089116
	.word	0xbfa894aa,	0x149fb000
	.word	0xbcfa19a8,	0xbe97660a
	.word	0xbfa85188,	0xb630f000
	.word	0xbcca0544,	0x165f80aa
	.word	0xbfa80e70,	0x23d8c000
	.word	0xbd1988fa,	0x435d02ec
	.word	0xbfa7cb60,	0x5b495000
	.word	0xbcfc8af3,	0x69d6d0f4
	.word	0xbfa78859,	0x5a357000
	.word	0xbd0ee9e5,	0xef898b68
	.word	0xbfa7455b,	0x1e511000
	.word	0xbcfb28ce,	0xb91e296d
	.word	0xbfa70265,	0xa550e000
	.word	0xbd0ddc83,	0xb80a8c63
	.word	0xbfa6bf78,	0xecea9000
	.word	0xbd163cc0,	0x0f16f7e9
	.word	0xbfa67c94,	0xf2d4b000
	.word	0xbd16b082,	0x09f3282f
	.word	0xbfa639b9,	0xb4c6b000
	.word	0xbd14f37b,	0x6b7f9673
	.word	0xbfa5f6e7,	0x3078e000
	.word	0xbd1f6f4a,	0xffdb6d69
	.word	0xbfa5b41d,	0x63a49000
	.word	0xbd0abcc4,	0x7e8a0c20
	.word	0xbfa5715c,	0x4c03c000
	.word	0xbd1dddc8,	0x80ee2760
	.word	0xbfa52ea3,	0xe7519000
	.word	0xbd16ff79,	0x68012363
	.word	0xbfa4ebf4,	0x3349e000
	.word	0xbcf37578,	0x4620c465
	.word	0xbfa4a94d,	0x2da96000
	.word	0xbd18ace0,	0x8a56ed78
	.word	0xbfa466ae,	0xd42de000
	.word	0xbcff4c64,	0x521016be
	.word	0xbfa42419,	0x2495d000
	.word	0xbd05f329,	0x88dd64a6
	.word	0xbfa3e18c,	0x1ca0a000
	.word	0xbd1d23b4,	0xfdb8de39
	.word	0xbfa39f07,	0xba0eb000
	.word	0xbd1ac4a7,	0x590b95de
	.word	0xbfa35c8b,	0xfaa13000
	.word	0xbccabeaf,	0x7cf59aac
	.word	0xbfa31a18,	0xdc1a1000
	.word	0xbd07dd58,	0xd860ceab
	.word	0xbfa2d7ae,	0x5c3c5000
	.word	0xbd175b1a,	0xe989664c
	.word	0xbfa2954c,	0x78cbc000
	.word	0xbd1c3526,	0x570c1572
	.word	0xbfa252f3,	0x2f8d1000
	.word	0xbd107d35,	0xc0436cf5
	.word	0xbfa210a2,	0x7e45c000
	.word	0xbcf8ceca,	0x131bef9c
	.word	0xbfa1ce5a,	0x62bc3000
	.word	0xbd04e63c,	0x6c6fccc5
	.word	0xbfa18c1a,	0xdab7b000
	.word	0xbcf22af4,	0xd32f2ac0
	.word	0xbfa149e3,	0xe4005000
	.word	0xbd1519d5,	0x96fa5c0c
	.word	0xbfa107b5,	0x7c5f2000
	.word	0xbd152b81,	0xe94af0a6
	.word	0xbfa0c58f,	0xa19df000
	.word	0xbd155317,	0x53a74377
	.word	0xbfa08372,	0x51877000
	.word	0xbd1cc91e,	0xb2004222
	.word	0xbfa0415d,	0x89e74000
	.word	0xbd0111c0,	0x5cf1d753
	.word	0xbf9ffea2,	0x91136000
	.word	0xbd04dd01,	0xd7640dc2
	.word	0xbf9f7a9b,	0x16782000
	.word	0xbd00ab64,	0x9c6f9f5c
	.word	0xbf9ef6a4,	0x9f98f000
	.word	0xbd0671e4,	0xe8f151a3
	.word	0xbf9e72bf,	0x2813c000
	.word	0xbd0ca2ba,	0xda22cae5
	.word	0xbf9deeea,	0xab883000
	.word	0xbd0c6e1d,	0x7741b591
	.word	0xbf9d6b27,	0x25979000
	.word	0xbd000425,	0x79723e3d
	.word	0xbf9ce774,	0x91e4d000
	.word	0xbd00d7ce,	0xf3d25198
	.word	0xbf9c63d2,	0xec14a000
	.word	0xbd05e318,	0xfe7acbca
	.word	0xbf9be042,	0x2fcd6000
	.word	0xbd01ec42,	0x87f2c9ca
	.word	0xbf9b5cc2,	0x58b71000
	.word	0xbd01cc23,	0x715f7fd0
	.word	0xbf9ad953,	0x627b6000
	.word	0xbd0ab5a1,	0x1a805efd
	.word	0xbf9a55f5,	0x48c5c000
	.word	0xbcf0fc7b,	0x0697e1b5
	.word	0xbf99d2a8,	0x07432000
	.word	0xbcf7cf80,	0x538b441e
	.word	0xbf994f6b,	0x99a24000
	.word	0xbcf1d5ef,	0x96cf7f51
	.word	0xbf98cc3f,	0xfb937000
	.word	0xbd050394,	0x323f2c7a
	.word	0xbf984925,	0x28c8c000
	.word	0xbd057d17,	0x3697cf30
	.word	0xbf97c61b,	0x1cf5d000
	.word	0xbd0dc0dc,	0x1ed96ee4
	.word	0xbf974321,	0xd3d00000
	.word	0xbcfb4a69,	0x0fe94778
	.word	0xbf96c039,	0x490e3000
	.word	0xbcff7b34,	0x02fd59ca
	.word	0xbf963d61,	0x78690000
	.word	0xbd07abf3,	0x89596542
	.word	0xbf95ba9a,	0x5d9ac000
	.word	0xbcacbb84,	0xe08d78ac
	.word	0xbf9537e3,	0xf45f3000
	.word	0xbcf592ce,	0x96bf9299
	.word	0xbf94b53e,	0x3873e000
	.word	0xbd0b6ee9,	0xbca265c1
	.word	0xbf9432a9,	0x25980000
	.word	0xbd098139,	0x928637fe
	.word	0xbf93b024,	0xb78c5000
	.word	0xbcf9a5e2,	0x3a02f82a
	.word	0xbf932db0,	0xea132000
	.word	0xbd0c432c,	0x4c2257ef
	.word	0xbf92ab4d,	0xb8f09000
	.word	0xbcf82c84,	0xa532c74c
	.word	0xbf9228fb,	0x1fea2000
	.word	0xbd0c4f8c,	0xa12647f9
	.word	0xbf91a6b9,	0x1ac73000
	.word	0xbcec30e9,	0xb54e2dd6
	.word	0xbf912487,	0xa5507000
	.word	0xbd0edf2f,	0xf6a59c94
	.word	0xbf90a266,	0xbb508000
	.word	0xbcfa5be1,	0x7c2ec500
	.word	0xbf902056,	0x58935000
	.word	0xbd008e93,	0xe47420b7
	.word	0xbf8f3cac,	0xf1cd3000
	.word	0xbcf64d83,	0xc9a6875d
	.word	0xbf8e38ce,	0x30333000
	.word	0xbcc0bbae,	0x12ebf308
	.word	0xbf8d3510,	0x63fa4000
	.word	0xbcea8d92,	0xdf000beb
	.word	0xbf8c3173,	0x84c75000
	.word	0xbcfe0cc0,	0x31046026
	.word	0xbf8b2df7,	0x8a428000
	.word	0xbcf4c647,	0xa5d4542f
	.word	0xbf8a2a9c,	0x6c170000
	.word	0xbce18876,	0x525971be
	.word	0xbf892762,	0x21f33000
	.word	0xbcd456ba,	0x9344a27f
	.word	0xbf882448,	0xa388a000
	.word	0xbcd55104,	0xb16137f1
	.word	0xbf87214f,	0xe88c0000
	.word	0xbcf27275,	0xd7338080
	.word	0xbf861e77,	0xe8b53000
	.word	0xbcff8c11,	0x507150cb
	.word	0xbf851bc0,	0x9bbf4000
	.word	0xbcdae1ea,	0x5258a3c6
	.word	0xbf841929,	0xf9683000
	.word	0xbcd77c75,	0x5d013688
	.word	0xbf8316b3,	0xf9714000
	.word	0xbcfb8dcc,	0x8ba5563d
	.word	0xbf82145e,	0x939ef000
	.word	0xbcce891c,	0x6274ffda
	.word	0xbf811229,	0xbfb89000
	.word	0xbcf50ee4,	0x5fd053b1
	.word	0xbf801015,	0x7588d000
	.word	0xbcfce251,	0x998b505f
	.word	0xbf7e1c43,	0x59bad000
	.word	0xbce9f504,	0xadbb6021
	.word	0xbf7c189c,	0xbb0e2000
	.word	0xbcdfeabb,	0x69dea7ed
	.word	0xbf7a1536,	0xfeb35000
	.word	0xbcecb8e8,	0x91b69c25
	.word	0xbf781212,	0x14586000
	.word	0xbce6a81c,	0x14b9f937
	.word	0xbf760f2d,	0xebb16000
	.word	0xbcbb6835,	0x84891753
	.word	0xbf740c8a,	0x74787000
	.word	0xbce1c38e,	0xf838000c
	.word	0xbf720a27,	0x9e6e0000
	.word	0xbce34d96,	0x922727aa
	.word	0xbf700805,	0x59588000
	.word	0xbce66afc,	0xb31c67b2
	.word	0xbf6c0c47,	0x2a092000
	.word	0xbc657d36,	0x31cacba0
	.word	0xbf680904,	0x82898000
	.word	0xbcc701a5,	0xa9c30314
	.word	0xbf640642,	0x9be3c000
	.word	0xbcccf0de,	0xc26e96f3
	.word	0xbf600401,	0x55d58000
	.word	0xbcd13bce,	0x0ce3ddd8
	.word	0xbf580481,	0x20511000
	.word	0xbcc0a8ce,	0x7ceb0de6
	.word	0xbf500200,	0x55655000
	.word	0xbcc11266,	0xaf9afc3f
	.word	0xbf400100,	0x15575000
	.word	0xbca62237,	0x79c0dc11
	.word	0x00000000,	0x00000000
	.word	0x00000000,	0x00000000
	.word	0x3f4ffc00,	0xaa8ab000
	.word	0x3c80fbc0,	0x4d051925
	.word	0x3f5ff802,	0xa9ab1000
	.word	0x3c8ccf14,	0xf1d0a9f2
	.word	0x3f67f704,	0x7d798000
	.word	0x3cbed344,	0xeb43240a
	.word	0x3f6ff00a,	0xa2b10000
	.word	0x3cd78094,	0x10d6ad37
	.word	0x3f73f38a,	0x60f06000
	.word	0x3cd22569,	0x3c937494
	.word	0x3f77ee11,	0xebd82000
	.word	0x3ced274f,	0x0b48e81d
	.word	0x3f7be79c,	0x70058000
	.word	0x3ced91f3,	0x4d808088
	.word	0x3f7fe02a,	0x6b106000
	.word	0x3cde23f0,	0xdda40e47
	.word	0x3f81ebde,	0x2d199000
	.word	0x3cef97c0,	0x0b723c9a
	.word	0x3f83e729,	0x5d25a000
	.word	0x3cef63e0,	0x0d65eebc
	.word	0x3f85e1f7,	0x03ecb000
	.word	0x3cfca09f,	0x585da1b5
	.word	0x3f87dc47,	0x5f810000
	.word	0x3cf4edba,	0x4a25e0b1
	.word	0x3f89d61a,	0xadc6b000
	.word	0x3cfb1963,	0x27b4256d
	.word	0x3f8bcf71,	0x2c743000
	.word	0x3cf09782,	0x5ef65dc3
	.word	0x3f8dc84b,	0x19123000
	.word	0x3cf02950,	0x78e96cc1
	.word	0x3f8fc0a8,	0xb0fc0000
	.word	0x3cdf1e7c,	0xf6d3a69c
	.word	0x3f90dc45,	0x18afc000
	.word	0x3d090f43,	0x1ff3b010
	.word	0x3f91d7f7,	0xeb9ee000
	.word	0x3d07cd8a,	0xf80670b5
	.word	0x3f92d36c,	0xefb55000
	.word	0x3cff0bb3,	0x41706c38
	.word	0x3f93cea4,	0x4346a000
	.word	0x3cf5d3bc,	0xd295bf53
	.word	0x3f94c99e,	0x04901000
	.word	0x3d0bd98c,	0xbbebe949
	.word	0x3f95c45a,	0x51b8d000
	.word	0x3cec449d,	0xe927827c
	.word	0x3f96bed9,	0x48d1b000
	.word	0x3cff43be,	0x9f5bc086
	.word	0x3f97b91b,	0x07d5b000
	.word	0x3cd1aa92,	0x7f54c717
	.word	0x3f98b31f,	0xaca9b000
	.word	0x3c8c3ab4,	0x8db4decf
	.word	0x3f99ace7,	0x551cc000
	.word	0x3cf45134,	0x09c1df81
	.word	0x3f9aa672,	0x1ee83000
	.word	0x3cf6a75a,	0xe2d7a49d
	.word	0x3f9b9fc0,	0x27af9000
	.word	0x3cd97fbd,	0x465b7589
	.word	0x3f9c98d1,	0x8d00c000
	.word	0x3d0027ab,	0xe9d883c3
	.word	0x3f9d91a6,	0x6c543000
	.word	0x3d0987c5,	0x9633ee68
	.word	0x3f9e8a3e,	0xe30cd000
	.word	0x3d095817,	0x086b1c01
	.word	0x3f9f829b,	0x0e783000
	.word	0x3ce80267,	0xc7e09e3e
	.word	0x3fa03d5d,	0x85e73000
	.word	0x3d1dde25,	0x83b4a73b
	.word	0x3fa0b94f,	0x7c196000
	.word	0x3ce76769,	0x0fdd87d3
	.word	0x3fa13523,	0x78597000
	.word	0x3cef29e2,	0x4702d328
	.word	0x3fa1b0d9,	0x8923d000
	.word	0x3d12ff85,	0x945dd915
	.word	0x3fa22c71,	0xbcea8000
	.word	0x3cfd2818,	0xf87f888f
	.word	0x3fa2a7ec,	0x2214e000
	.word	0x3d10e631,	0x0add3804
	.word	0x3fa32348,	0xc7001000
	.word	0x3d0a5b6e,	0x42c7927d
	.word	0x3fa39e87,	0xb9feb000
	.word	0x3d1abf52,	0x02b64055
	.word	0x3fa419a9,	0x09593000
	.word	0x3d0ae6e3,	0x3ea4753a
	.word	0x3fa494ac,	0xc34d9000
	.word	0x3ce1c78a,	0x56fd2473
	.word	0x3fa50f92,	0xf60f9000
	.word	0x3d12d9f6,	0x1523ffc6
	.word	0x3fa58a5b,	0xafc8e000
	.word	0x3d035231,	0xaa3d4b1d
	.word	0x3fa60506,	0xfe98d000
	.word	0x3d1516fd,	0xf9ac7f28
	.word	0x3fa67f94,	0xf094b000
	.word	0x3d1b307c,	0xf9f93b5b
	.word	0x3fa6fa05,	0x93c7b000
	.word	0x3d0a0af2,	0x0eb1a504
	.word	0x3fa77458,	0xf632d000
	.word	0x3d19f88c,	0x69e543dd
	.word	0x3fa7ee8f,	0x25cd4000
	.word	0x3ce7bd3d,	0xcb47c2e4
	.word	0x3fa868a8,	0x3083f000
	.word	0x3d0b3b8b,	0xd96a72db
	.word	0x3fa8e2a4,	0x243a1000
	.word	0x3d173dd6,	0x0284c920
	.word	0x3fa95c83,	0x0ec8e000
	.word	0x3cff5beb,	0x41d00a41
	.word	0x3fa9d644,	0xfdffa000
	.word	0x3cf3c905,	0x39a473b6
	.word	0x3faa4fe9,	0xffa3d000
	.word	0x3cf1a7b5,	0xfbfd6db2
	.word	0x3faac972,	0x21711000
	.word	0x3d1f1a7d,	0xe0264459
	.word	0x3fab42dd,	0x71197000
	.word	0x3cebec28,	0xd14c7d9f
	.word	0x3fabbc2b,	0xfc44f000
	.word	0x3d005cf2,	0xdd7d04a2
	.word	0x3fac355d,	0xd0921000
	.word	0x3d1e5999,	0x357f0710
	.word	0x3facae72,	0xfb95c000
	.word	0x3cf0540d,	0xfda4e418
	.word	0x3fad276b,	0x8adb0000
	.word	0x3d16a423,	0xc78a64b0
	.word	0x3fada047,	0x8be39000
	.word	0x3cf2963d,	0x8fb7f02b
	.word	0x3fae1907,	0x0c276000
	.word	0x3ca5b99b,	0x9d617a09
	.word	0x3fae91aa,	0x1914f000
	.word	0x3d10beaf,	0xf119cac5
	.word	0x3faf0a30,	0xc0116000
	.word	0x3cf5330b,	0xe64b8b77
	.word	0x3faf829b,	0x0e783000
	.word	0x3cf80267,	0xc7e09e3e
	.word	0x3faffae9,	0x119b9000
	.word	0x3cf819ba,	0x13162a9c
	.word	0x3fb0398d,	0x6b622000
	.word	0x3d153ac8,	0x0d00cc01
	.word	0x3fb07598,	0x3598e000
	.word	0x3d11c4c0,	0x6d2999e2
	.word	0x3fb0b194,	0xee0d1000
	.word	0x3d199ba9,	0x3da7b72e
	.word	0x3fb0ed83,	0x9b552000
	.word	0x3d1bf82e,	0x4add5131
	.word	0x3fb12964,	0x4402e000
	.word	0x3d056224,	0x572ac464
	.word	0x3fb16536,	0xeea37000
	.word	0x3d25c1d0,	0xc4b82e7c
	.word	0x3fb1a0fb,	0xa1bf8000
	.word	0x3d24a3fc,	0xc319d6dc
	.word	0x3fb1dcb2,	0x63db1000
	.word	0x3d22889e,	0xbd3d1303
	.word	0x3fb2185b,	0x3b75a000
	.word	0x3cfce760,	0x70cdcfc5
	.word	0x3fb253f6,	0x2f0a1000
	.word	0x3d105be3,	0xeda69c04
	.word	0x3fb28f83,	0x450ed000
	.word	0x3d251aeb,	0x54232ed1
	.word	0x3fb2cb02,	0x83f5d000
	.word	0x3d2c3dc5,	0x94cae043
	.word	0x3fb30673,	0xf22c8000
	.word	0x3d24c9e2,	0x9dcf0ba5
	.word	0x3fb341d7,	0x961bd000
	.word	0x3cfd0929,	0x98376105
	.word	0x3fb37d2d,	0x76283000
	.word	0x3cfcfaab,	0x2400751e
	.word	0x3fb3b875,	0x98b1b000
	.word	0x3d1bb7d4,	0xd6a6b9db
	.word	0x3fb3f3b0,	0x04140000
	.word	0x3cee2474,	0xacdfcec5
	.word	0x3fb42edc,	0xbea64000
	.word	0x3d1bc0ee,	0xea7c9acd
	.word	0x3fb469fb,	0xcebb5000
	.word	0x3d26cc78,	0x9e4ae327
	.word	0x3fb4a50d,	0x3aa1b000
	.word	0x3cd003d9,	0xeed183bb
	.word	0x3fb4e011,	0x08a35000
	.word	0x3d25cb9f,	0xbe58b5c9
	.word	0x3fb51b07,	0x3f061000
	.word	0x3d207ed2,	0x4f1cd0d4
	.word	0x3fb555ef,	0xe40b5000
	.word	0x3ce692f1,	0x90d1c46b
	.word	0x3fb590ca,	0xfdf01000
	.word	0x3d28509e,	0xae455754
	.word	0x3fb5cb98,	0x92ed4000
	.word	0x3d17be44,	0xa64fc52f
	.word	0x3fb60658,	0xa9375000
	.word	0x3ce8763b,	0xdd389ef2
	.word	0x3fb6410b,	0x46fe7000
	.word	0x3d256038,	0x61a13976
	.word	0x3fb67bb0,	0x726ec000
	.word	0x3cef724b,	0x69ef5912
	.word	0x3fb6b648,	0x31afe000
	.word	0x3d1033d7,	0xb22085b8
	.word	0x3fb6f0d2,	0x8ae56000
	.word	0x3d269737,	0xc93373da
	.word	0x3fb72b4f,	0x842ea000
	.word	0x3d21f666,	0x7fe6c45a
	.word	0x3fb765bf,	0x23a6b000
	.word	0x3d2c2687,	0xf9477b53
	.word	0x3fb7a021,	0x6f649000
	.word	0x3d2c2499,	0x430831ff
	.word	0x3fb7da76,	0x6d7b1000
	.word	0x3d066422,	0x240644d8
	.word	0x3fb814be,	0x23f8c000
	.word	0x3ccb2381,	0xda82fdfd
	.word	0x3fb84ef8,	0x98e82000
	.word	0x3d205465,	0xb72d106e
	.word	0x3fb88925,	0xd24fa000
	.word	0x3d2c55f5,	0x76088ff3
	.word	0x3fb8c345,	0xd6319000
	.word	0x3d2641eb,	0x596854cc
	.word	0x3fb8fd58,	0xaa8c2000
	.word	0x3cf136fe,	0x4348da4e
	.word	0x3fb9375e,	0x55595000
	.word	0x3d2dbb86,	0xe70186c9
	.word	0x3fb97156,	0xdc8f6000
	.word	0x3d0f01f3,	0x28123425
	.word	0x3fb9ab42,	0x46203000
	.word	0x3d0d66df,	0x661e3e7b
	.word	0x3fb9e520,	0x97f9c000
	.word	0x3d235fac,	0xb52dd050
	.word	0x3fba1ef1,	0xd8061000
	.word	0x3d29a82e,	0xdbf2f796
	.word	0x3fba58b6,	0x0c2b2000
	.word	0x3d091c65,	0x1d1b06b1
	.word	0x3fba926d,	0x3a4ad000
	.word	0x3d158d94,	0x2f48aa71
	.word	0x3fbacc17,	0x68433000
	.word	0x3d0561f1,	0x7d2016d1
	.word	0x3fbb05b4,	0x9bee4000
	.word	0x3d0ff22c,	0x18f84a5e
	.word	0x3fbb3f44,	0xdb221000
	.word	0x3d2fa2a7,	0xb1bc135d
	.word	0x3fbb78c8,	0x2bb0e000
	.word	0x3d2b4210,	0x878cf032
	.word	0x3fbbb23e,	0x9368e000
	.word	0x3d22e9cf,	0x954c48ea
	.word	0x3fbbeba8,	0x18146000
	.word	0x3d1d921d,	0x248382a6
	.word	0x3fbc2504,	0xbf79d000
	.word	0x3d1c5f13,	0x43bd2b70
	.word	0x3fbc5e54,	0x8f5bc000
	.word	0x3d1d0c57,	0x585fbe06
	.word	0x3fbc9797,	0x8d78e000
	.word	0x3d223fde,	0xd105cef9
	.word	0x3fbcd0cd,	0xbf8c1000
	.word	0x3d0f0a6d,	0xa86eba18
	.word	0x3fbd09f7,	0x2b4c4000
	.word	0x3d2048c0,	0x00354e33
	.word	0x3fbd4313,	0xd66cb000
	.word	0x3d0aeaf2,	0x1bb2a3b2
	.word	0x3fbd7c23,	0xc69cb000
	.word	0x3d0a046c,	0x8b35e23e
	.word	0x3fbdb527,	0x0187d000
	.word	0x3d224ef0,	0xad5c303f
	.word	0x3fbdee1d,	0x8cd5e000
	.word	0x3d2ae4bf,	0x1ac200ee
	.word	0x3fbe2707,	0x6e2af000
	.word	0x3d072f4f,	0x543fff10
	.word	0x3fbe5fe4,	0xab272000
	.word	0x3d240a2c,	0x11600366
	.word	0x3fbe98b5,	0x49671000
	.word	0x3d119dd2,	0x27143a5b
	.word	0x3fbed179,	0x4e837000
	.word	0x3d20175e,	0x45b17dbe
	.word	0x3fbf0a30,	0xc0116000
	.word	0x3d05330b,	0xe64b8b77
	.word	0x3fbf42db,	0xa3a22000
	.word	0x3d29da91,	0x9a4127e6
	.word	0x3fbf7b79,	0xfec37000
	.word	0x3d2bbd9e,	0x05da04c0
	.word	0x3fbfb40b,	0xd6ff4000
	.word	0x3d2c0bec,	0xb7b53b5b
	.word	0x3fbfec91,	0x31dbe000
	.word	0x3d257554,	0x5ca333f2
	.word	0x3fc01285,	0x0a6df000
	.word	0x3d395e79,	0xadfe901b
	.word	0x3fc02ebb,	0x42bf3000
	.word	0x3d3a95c1,	0x68c7fc69
	.word	0x3fc04aeb,	0x449f6000
	.word	0x3d2afa90,	0x65ccd35c
	.word	0x3fc06715,	0x12ca5000
	.word	0x3d32dc54,	0x3191fae2
	.word	0x3fc08338,	0xaffa2000
	.word	0x3d30533c,	0xac823e27
	.word	0x3fc09f56,	0x1ee71000
	.word	0x3d33867d,	0x4754172c
	.word	0x3fc0bb6d,	0x6247a000
	.word	0x3d35464f,	0x3ccd04b3
	.word	0x3fc0d77e,	0x7cd08000
	.word	0x3d3cb2cd,	0x2ee2f482
	.word	0x3fc0f389,	0x7134b000
	.word	0x3d02e530,	0xbb6149cf
	.word	0x3fc10f8e,	0x42253000
	.word	0x3d336263,	0xde634e7c
	.word	0x3fc12b8c,	0xf2518000
	.word	0x3d348a4a,	0x13c0a0fc
	.word	0x3fc14785,	0x84674000
	.word	0x3d156345,	0x1027c750
	.word	0x3fc16377,	0xfb124000
	.word	0x3d091e1a,	0xbf41763e
	.word	0x3fc17f64,	0x58fca000
	.word	0x3d2843fa,	0xd093c8dc
	.word	0x3fc19b4a,	0xa0ced000
	.word	0x3d03bedb,	0x4ef663a7
	.word	0x3fc1b72a,	0xd52f6000
	.word	0x3d2e80a4,	0x1811a396
	.word	0x3fc1d304,	0xf8c35000
	.word	0x3d164aec,	0x82ebbef7
	.word	0x3fc1eed9,	0x0e2dc000
	.word	0x3d161563,	0x7097648f
	.word	0x3fc20aa7,	0x18102000
	.word	0x3d3f2c94,	0x348552fe
	.word	0x3fc2266f,	0x190a5000
	.word	0x3d3596fa,	0xa3df8c05
	.word	0x3fc24231,	0x13ba5000
	.word	0x3cfc5ff8,	0x71162641
	.word	0x3fc25ded,	0x0abc6000
	.word	0x3d35a385,	0x4f176449
	.word	0x3fc279a3,	0x00ab4000
	.word	0x3d3ef432,	0xb3235108
	.word	0x3fc29552,	0xf81ff000
	.word	0x3d248d30,	0x1771c408
	.word	0x3fc2b0fc,	0xf3b1a000
	.word	0x3d177ca3,	0xe30a59ea
	.word	0x3fc2cca0,	0xf5f5f000
	.word	0x3d128439,	0xb9403b82
	.word	0x3fc2e83f,	0x0180d000
	.word	0x3cee7aa7,	0xaf63c632
	.word	0x3fc303d7,	0x18e47000
	.word	0x3d3fa5fd,	0x28c704d4
	.word	0x3fc31f69,	0x3eb19000
	.word	0x3d32cc6c,	0x8d2e3482
	.word	0x3fc33af5,	0x75770000
	.word	0x3d3c9ecc,	0xa2fe72a5
	.word	0x3fc3567b,	0xbfc22000
	.word	0x3d3250d2,	0x53991a1f
	.word	0x3fc371fc,	0x201e8000
	.word	0x3d3ee877,	0x9b2d8abc
	.word	0x3fc38d76,	0x99164000
	.word	0x3d1844a5,	0x9e39bb70
	.word	0x3fc3a8eb,	0x2d31a000
	.word	0x3d1bafb7,	0x7d5d503e
	.word	0x3fc3c459,	0xdef76000
	.word	0x3d3edc86,	0xf6b70d33
	.word	0x3fc3dfc2,	0xb0ecc000
	.word	0x3d28a72a,	0x62b8c13f
	.word	0x3fc3fb25,	0xa5952000
	.word	0x3d3195be,	0x6b358ff7
	.word	0x3fc41682,	0xbf727000
	.word	0x3d377fdc,	0x7bf03db2
	.word	0x3fc431da,	0x01050000
	.word	0x3d304837,	0x836e0391
	.word	0x3fc44d2b,	0x6ccb7000
	.word	0x3d3a3ccf,	0xa7b2a1f1
	.word	0x3fc46877,	0x0542f000
	.word	0x3d03f5d0,	0x3957bc10
	.word	0x3fc483bc,	0xcce6e000
	.word	0x3d1eea52,	0x723f6369
	.word	0x3fc49efc,	0xc6313000
	.word	0x3d3cde14,	0xcc15551b
	.word	0x3fc4ba36,	0xf39a5000
	.word	0x3d279568,	0x981bcc36
	.word	0x3fc4d56b,	0x5798e000
	.word	0x3d380580,	0x15a96555
	.word	0x3fc4f099,	0xf4a23000
	.word	0x3cf640d0,	0x50150d92
	.word	0x3fc50bc2,	0xcd29c000
	.word	0x3d1ada57,	0x28db8d4f
	.word	0x3fc526e5,	0xe3a1b000
	.word	0x3d20de8b,	0x90075b8f
	.word	0x3fc54203,	0x3a7a8000
	.word	0x3d268d68,	0xed855f0e
	.word	0x3fc55d1a,	0xd4232000
	.word	0x3d3add94,	0xdda647e8
	.word	0x3fc5782c,	0xb3091000
	.word	0x3d28b739,	0x5d0d777d
	.word	0x3fc59338,	0xd9982000
	.word	0x3cf0ba68,	0xb7555d4a
	.word	0x3fc5ae3f,	0x4a3aa000
	.word	0x3d21ea25,	0xf012a8b9
	.word	0x3fc5c940,	0x07597000
	.word	0x3d15c9ad,	0xccb7337a
	.word	0x3fc5e43b,	0x135bd000
	.word	0x3d278a96,	0x6224c79e
	.word	0x3fc5ff30,	0x70a79000
	.word	0x3d1e9e43,	0x9f105039
	.word	0x3fc61a20,	0x21a0e000
	.word	0x3d3dd9dd,	0x1bdf3cdd
	.word	0x3fc6350a,	0x28aaa000
	.word	0x3d2d5ec0,	0xab8163af
	.word	0x3fc64fee,	0x8825f000
	.word	0x3d3896fc,	0xa298884b
	.word	0x3fc66acd,	0x4272a000
	.word	0x3d3aa1bd,	0xbfc6c785
	.word	0x3fc685a6,	0x59eef000
	.word	0x3d3706ab,	0x49f7e6f6
	.word	0x3fc6a079,	0xd0f7a000
	.word	0x3d35a3f8,	0x448d14f5
	.word	0x3fc6bb47,	0xa9e80000
	.word	0x3d19f64d,	0x23ea3296
	.word	0x3fc6d60f,	0xe719d000
	.word	0x3d10e46a,	0xa3b2e266
	.word	0x3fc6f0d2,	0x8ae56000
	.word	0x3d369737,	0xc93373da
	.word	0x3fc70b8f,	0x97a1a000
	.word	0x3d34ea64,	0xf6a95bef
	.word	0x3fc72647,	0x0fa3f000
	.word	0x3d211641,	0xe3178b76
	.word	0x3fc740f8,	0xf5403000
	.word	0x3d2e9326,	0xcdfceabe
	.word	0x3fc75ba5,	0x4ac8e000
	.word	0x3d3ddca5,	0x8bc4a7c0
	.word	0x3fc7764c,	0x128f2000
	.word	0x3d027490,	0x3479e3d1
	.word	0x3fc790ed,	0x4ee26000
	.word	0x3d199bbd,	0x4e7746f6
	.word	0x3fc7ab89,	0x0210d000
	.word	0x3d321237,	0xc6d65ad4
	.word	0x3fc7c61f,	0x2e673000
	.word	0x3d2b8da4,	0x99c82e40
	.word	0x3fc7e0af,	0xd630c000
	.word	0x3d139e7c,	0x1d8f1034
	.word	0x3fc7fb3a,	0xfbb75000
	.word	0x3d204815,	0xb73ec551
	.word	0x3fc815c0,	0xa1435000
	.word	0x3d2fab5a,	0x0dbfc630
	.word	0x3fc83040,	0xc91bc000
	.word	0x3d3e5b71,	0xc6e66f32
	.word	0x3fc84abb,	0x75865000
	.word	0x3d0392a9,	0x058ea173
	.word	0x3fc86530,	0xa8c70000
	.word	0x3d398bb0,	0xcb4ea3e3
	.word	0x3fc87fa0,	0x6520c000
	.word	0x3d322120,	0x401202fc
	.word	0x3fc89a0a,	0xacd4e000
	.word	0x3d2c0bfb,	0xda8f5a72
	.word	0x3fc8b46f,	0x82236000
	.word	0x3d12d9f2,	0x102dd7c9
	.word	0x3fc8cece,	0xe74ad000
	.word	0x3d16917d,	0x56f5912d
	.word	0x3fc8e928,	0xde886000
	.word	0x3d3a8154,	0xb13d72d5
	.word	0x3fc9037d,	0x6a180000
	.word	0x3d230dea,	0x57c1c8d9
	.word	0x3fc91dcc,	0x8c340000
	.word	0x3d37bc6a,	0xbddeff46
	.word	0x3fc93816,	0x47159000
	.word	0x3d267385,	0x2b8b8c4f
	.word	0x3fc9525a,	0x9cf45000
	.word	0x3d2ad1d9,	0x04c1d4e3
	.word	0x3fc96c99,	0x9006a000
	.word	0x3d2a88d5,	0x9cbb452c
	.word	0x3fc986d3,	0x22818000
	.word	0x3cf93b56,	0x4dd44000
	.word	0x3fc9a107,	0x56988000
	.word	0x3d264aa6,	0x242cd098
	.word	0x3fc9bb36,	0x2e7df000
	.word	0x3d3706ab,	0xaf18f802
	.word	0x3fc9d55f,	0xac62d000
	.word	0x3ce732c0,	0x789487af
	.word	0x3fc9ef83,	0xd2769000
	.word	0x3d3467a4,	0x26031900
	.word	0x3fca09a2,	0xa2e79000
	.word	0x3d311331,	0x195f76e6
	.word	0x3fca23bc,	0x1fe2b000
	.word	0x3d258c64,	0xdc46c1ea
	.word	0x3fca3dd0,	0x4b938000
	.word	0x3d297da1,	0x366e2c5a
	.word	0x3fca57df,	0x28244000
	.word	0x3d3b99c8,	0xca1d9abb
	.word	0x3fca71e8,	0xb7bdf000
	.word	0x3d377a9a,	0xc887d66f
	.word	0x3fca8bec,	0xfc882000
	.word	0x3d3e3185,	0xcf21b9cf
	.word	0x3fcaa5eb,	0xf8a93000
	.word	0x3d2abead,	0x92d5cae2
	.word	0x3fcabfe5,	0xae461000
	.word	0x3d125c2b,	0x1a83b18e
	.word	0x3fcad9da,	0x1f827000
	.word	0x3d1df520,	0xdff03ebe
	.word	0x3fcaf3c9,	0x4e80b000
	.word	0x3d3fe5b1,	0x9cc03270
	.word	0x3fcb0db3,	0x3d620000
	.word	0x3d3fee14,	0x38eab906
	.word	0x3fcb2797,	0xee463000
	.word	0x3d105dd5,	0xbe4bfd5c
	.word	0x3fcb4177,	0x634ba000
	.word	0x3d355d01,	0x5666069f
	.word	0x3fcb5b51,	0x9e8fb000
	.word	0x3d2691ba,	0x27fdc19e
	.word	0x3fcb7526,	0xa22e4000
	.word	0x3d2c0dbf,	0x2e785490
	.word	0x3fcb8ef6,	0x70420000
	.word	0x3d387533,	0x321788e0
	.word	0x3fcba8c1,	0x0ae46000
	.word	0x3d3a32e2,	0x9eee9d85
	.word	0x3fcbc286,	0x742d8000
	.word	0x3d39ac53,	0xf39d121c
	.word	0x3fcbdc46,	0xae344000
	.word	0x3d3625b4,	0x023d6505
	.word	0x3fcbf601,	0xbb0e4000
	.word	0x3d2386a9,	0x47c378b5
	.word	0x3fcc0fb7,	0x9ccfd000
	.word	0x3d272000,	0xcc2eb551
	.word	0x3fcc2968,	0x558c1000
	.word	0x3d318146,	0x108e3ae0
	.word	0x3fcc4313,	0xe754e000
	.word	0x3d3279be,	0x74cad7d6
	.word	0x3fcc5cba,	0x543ae000
	.word	0x3d20929d,	0xecb454fc
	.word	0x3fcc765b,	0x9e4d6000
	.word	0x3d31ab6b,	0x36976f6c
	.word	0x3fcc8ff7,	0xc79a9000
	.word	0x3d344358,	0x4bb03de6
	.word	0x3fcca98e,	0xd22f5000
	.word	0x3d3e9673,	0xe735df63
	.word	0x3fccc320,	0xc0176000
	.word	0x3d240903,	0x9a653794
	.word	0x3fccdcad,	0x935d1000
	.word	0x3d3cbe01,	0xf966cb77
	.word	0x3fccf635,	0x4e09c000
	.word	0x3d277123,	0x9a07d55b
	.word	0x3fcd0fb7,	0xf2255000
	.word	0x3d3ca15a,	0x9bf3989b
	.word	0x3fcd2935,	0x81b6b000
	.word	0x3d1f363f,	0xb5d55685
	.word	0x3fcd42ad,	0xfec35000
	.word	0x3d3a28ff,	0xc09fef63
	.word	0x3fcd5c21,	0x6b4fb000
	.word	0x3d3722b7,	0x221acbf2
	.word	0x3fcd758f,	0xc95ef000
	.word	0x3d3a97bd,	0x5d2fa755
	.word	0x3fcd8ef9,	0x1af31000
	.word	0x3d3abbe8,	0x0f26ce1f
	.word	0x3fcda85d,	0x620ce000
	.word	0x3d240194,	0xc16cc7ec
	.word	0x3fcdc1bc,	0xa0abe000
	.word	0x3d38fac1,	0xa628ccc6
	.word	0x3fcddb16,	0xd8ce9000
	.word	0x3d384421,	0xa3bed1d1
	.word	0x3fcdf46c,	0x0c722000
	.word	0x3d3a5e82,	0xb0b79039
	.word	0x3fce0dbc,	0x3d92a000
	.word	0x3d359233,	0xf0529bf1
	.word	0x3fce2707,	0x6e2af000
	.word	0x3d172f4f,	0x543fff10
	.word	0x3fce404d,	0xa034b000
	.word	0x3d2cf022,	0x3ecbb0ce
	.word	0x3fce598e,	0xd5a87000
	.word	0x3d3c5d96,	0x861c2cec
	.word	0x3fce72cb,	0x107da000
	.word	0x3d1dd48c,	0xcdf5471c
	.word	0x3fce8c02,	0x52aa5000
	.word	0x3d34bfd2,	0x3f8b8c80
	.word	0x3fcea534,	0x9e23a000
	.word	0x3d381b93,	0x4c73ccb5
	.word	0x3fcebe61,	0xf4dd7000
	.word	0x3d3615d6,	0x67811ada
	.word	0x3fced78a,	0x58ca8000
	.word	0x3d16f1b5,	0x3793387e
	.word	0x3fcef0ad,	0xcbdc5000
	.word	0x3d326ca4,	0x31bca86e
	.word	0x3fcf09cc,	0x50036000
	.word	0x3d3da094,	0x18d999db
	.word	0x3fcf22e5,	0xe72f1000
	.word	0x3ce7561d,	0x7d037c19
	.word	0x3fcf3bfa,	0x934d6000
	.word	0x3d2d9f2a,	0x937b903b
	.word	0x3fcf550a,	0x564b7000
	.word	0x3d366e0e,	0x2fb6fe81
	.word	0x3fcf6e15,	0x32153000
	.word	0x3d0b2b44,	0x29d89c5c
	.word	0x3fcf871b,	0x28955000
	.word	0x3ce14052,	0xb5b2204b
	.word	0x3fcfa01c,	0x3bb57000
	.word	0x3d397823,	0x81478a1f
	.word	0x3fcfb918,	0x6d5e3000
	.word	0x3d3c551a,	0xaa8cd86f
	.word	0x3fcfd20f,	0xbf76f000
	.word	0x3d3b8ea9,	0x234e4064
	.word	0x3fcfeb02,	0x33e60000
	.word	0x3d2f316e,	0x32d5e8c7
	.word	0x3fd001f7,	0xe6484000
	.word	0x3d38a957,	0x40c9abbc
	.word	0x3fd00e6c,	0x45ad5000
	.word	0x3cdcc68d,	0x52e01203
	.word	0x3fd01ade,	0x39139000
	.word	0x3d4deed9,	0xe6647d5c
	.word	0x3fd0274d,	0xc16c2000
	.word	0x3d2979e8,	0x9cf835c2
	.word	0x3fd033ba,	0xdfa74000
	.word	0x3d0c30bc,	0x1485bdff
	.word	0x3fd04025,	0x94b4d000
	.word	0x3cf036b8,	0x9ef42d7f
	.word	0x3fd04c8d,	0xe1841000
	.word	0x3d4c0328,	0xb5da628f
	.word	0x3fd058f3,	0xc703e000
	.word	0x3d478bcc,	0xa196e4a9
	.word	0x3fd06557,	0x46227000
	.word	0x3d0131df,	0xb4868d6a
	.word	0x3fd071b8,	0x5fcd5000
	.word	0x3d421a3a,	0x2e0ff2f8
	.word	0x3fd07e17,	0x14f1c000
	.word	0x3d40819c,	0xd863da16
	.word	0x3fd08a73,	0x667c5000
	.word	0x3d3ebc1d,	0x40c5a329
	.word	0x3fd096cd,	0x55591000
	.word	0x3d3f998d,	0x20550a31
	.word	0x3fd0a324,	0xe2739000
	.word	0x3d0c6bee,	0x7ef4030e
	.word	0x3fd0af7a,	0x0eb6c000
	.word	0x3d23ccf9,	0x4945adad
	.word	0x3fd0bbcc,	0xdb0d2000
	.word	0x3d32f32c,	0xcc5dcdfb
	.word	0x3fd0c81d,	0x4860a000
	.word	0x3d40d218,	0x5ff17467
	.word	0x3fd0d46b,	0x579ab000
	.word	0x3d3d2c81,	0xf640e1e6
	.word	0x3fd0e0b7,	0x09a43000
	.word	0x3d32a038,	0xa7862f2a
	.word	0x3fd0ed00,	0x5f657000
	.word	0x3d4b48e2,	0xb5e955ff
	.word	0x3fd0f947,	0x59c66000
	.word	0x3d4356cf,	0x407bf3a5
	.word	0x3fd1058b,	0xf9ae4000
	.word	0x3d45aa31,	0x3f415699
	.word	0x3fd111ce,	0x4003e000
	.word	0x3d4c99b9,	0x1ed29693
	.word	0x3fd11e0e,	0x2dad9000
	.word	0x3d496e01,	0xdc0cc691
	.word	0x3fd12a4b,	0xc3911000
	.word	0x3d452c57,	0xcf5c66d4
	.word	0x3fd13687,	0x0293a000
	.word	0x3d4160bd,	0xb314c76f
	.word	0x3fd142bf,	0xeb9a0000
	.word	0x3d31ce61,	0x85b58a9e
	.word	0x3fd14ef6,	0x7f886000
	.word	0x3d40b42c,	0xd101b436
	.word	0x3fd15b2a,	0xbf428000
	.word	0x3d489c71,	0x2d927594
	.word	0x3fd1675c,	0xababa000
	.word	0x3d38380e,	0x731f55c4
	.word	0x3fd1738c,	0x45a66000
	.word	0x3d431c8b,	0x7fe69f45
	.word	0x3fd17fb9,	0x8e150000
	.word	0x3d42baba,	0x2c5aecbe
	.word	0x3fd18be4,	0x85d93000
	.word	0x3d3c167f,	0x6f3604ab
	.word	0x3fd1980d,	0x2dd42000
	.word	0x3d2b7b3a,	0x7a361c9a
	.word	0x3fd1a433,	0x86e67000
	.word	0x3d4e857a,	0xf9cb1f55
	.word	0x3fd1b057,	0x91f07000
	.word	0x3d46915c,	0xc91d50e9
	.word	0x3fd1bc79,	0x4fd1c000
	.word	0x3d419879,	0xc5c22c21
	.word	0x3fd1c898,	0xc1699000
	.word	0x3d43f5f7,	0x8d1cea80
	.word	0x3fd1d4b5,	0xe796a000
	.word	0x3d222a5b,	0xd197bac2
	.word	0x3fd1e0d0,	0xc3371000
	.word	0x3d3af8f2,	0xa9b0d4a0
	.word	0x3fd1ece9,	0x5528a000
	.word	0x3d4cf630,	0x9ec96b89
	.word	0x3fd1f8ff,	0x9e48a000
	.word	0x3d27946c,	0x040cbe77
	.word	0x3fd20513,	0x9f73b000
	.word	0x3cf6e15e,	0x1609e0a4
	.word	0x3fd21125,	0x59861000
	.word	0x3d382e78,	0xba2950c4
	.word	0x3fd21d34,	0xcd5b9000
	.word	0x3d3b552f,	0xb28badaa
	.word	0x3fd22941,	0xfbcf7000
	.word	0x3d42cb44,	0x850a7b4f
	.word	0x3fd2354c,	0xe5bc8000
	.word	0x3d414389,	0x7cfeacce
	.word	0x3fd24155,	0x8bfd1000
	.word	0x3d300fff,	0x3228fcad
	.word	0x3fd24d5b,	0xef6ae000
	.word	0x3d4ff114,	0x3f81b02a
	.word	0x3fd25960,	0x10df7000
	.word	0x3d38e7bc,	0x224ea3e3
	.word	0x3fd26561,	0xf1338000
	.word	0x3d38b488,	0x66faa45f
	.word	0x3fd27161,	0x913f8000
	.word	0x3d34f4f1,	0xf61564b4
	.word	0x3fd27d5e,	0xf1db5000
	.word	0x3d4e6dc8,	0xb8735361
	.word	0x3fd2895a,	0x13de8000
	.word	0x3d3a8d7a,	0xd24c13f0
	.word	0x3fd29552,	0xf81ff000
	.word	0x3d348d30,	0x1771c408
	.word	0x3fd2a149,	0x9f762000
	.word	0x3d479220,	0x57062a92
	.word	0x3fd2ad3e,	0x0ab73000
	.word	0x3d2b972e,	0x488c359f
	.word	0x3fd2b930,	0x3ab89000
	.word	0x3d4a493b,	0x4a5013d7
	.word	0x3fd2c520,	0x304f8000
	.word	0x3d230852,	0x8c342f39
	.word	0x3fd2d10d,	0xec508000
	.word	0x3d360c61,	0xf7088353
	.word	0x3fd2dcf9,	0x6f8fd000
	.word	0x3d20b4a2,	0x8e33c9ce
	.word	0x3fd2e8e2,	0xbae11000
	.word	0x3d4a6138,	0x5992350a
	.word	0x3fd2f4c9,	0xcf17a000
	.word	0x3d371f04,	0x9374b87b
	.word	0x3fd300ae,	0xad063000
	.word	0x3d342f56,	0x8b75fcac
	.word	0x3fd30c91,	0x557f1000
	.word	0x3d4d7ad4,	0xebd75d15
	.word	0x3fd31871,	0xc9544000
	.word	0x3d184fab,	0x94cecfd9
	.word	0x3fd32450,	0x09570000
	.word	0x3d3d271b,	0x9bdae59d
	.word	0x3fd3302c,	0x16586000
	.word	0x3d36217d,	0xc2a3e08b
	.word	0x3fd33c05,	0xf128d000
	.word	0x3d4b51be,	0x71fc7961
	.word	0x3fd347dd,	0x9a987000
	.word	0x3d4aa9ac,	0x8ace9fdc
	.word	0x3fd353b3,	0x1376d000
	.word	0x3d4d99ca,	0x0327b24d
	.word	0x3fd35f86,	0x5c932000
	.word	0x3d427c10,	0xd8af2d5b
	.word	0x3fd36b57,	0x76bc1000
	.word	0x3d116978,	0x5a9c223f
	.word	0x3fd37726,	0x62bfd000
	.word	0x3d40b5e4,	0xa9d627ef
	.word	0x3fd382f3,	0x216c4000
	.word	0x3d4df3c5,	0xbc5cb012
	.word	0x3fd38ebd,	0xb38ed000
	.word	0x3d290582,	0xe67d4ca0
	.word	0x3fd39a86,	0x19f45000
	.word	0x3d18ee51,	0x937354f5
	.word	0x3fd3a64c,	0x55694000
	.word	0x3d37a71c,	0xbcd735d0
	.word	0x3fd3b210,	0x66b9b000
	.word	0x3d461f09,	0x33f754f9
	.word	0x3fd3bdd2,	0x4eb14000
	.word	0x3d46d425,	0xb478c893
	.word	0x3fd3c992,	0x0e1b2000
	.word	0x3d141c28,	0xaa680b76
	.word	0x3fd3d54f,	0xa5c1f000
	.word	0x3d3c3e1c,	0xd9a395e3
	.word	0x3fd3e10b,	0x16701000
	.word	0x3d3f3bcf,	0x145429c7
	.word	0x3fd3ecc4,	0x60ef5000
	.word	0x3d4e9fd7,	0x9d83ecff
	.word	0x3fd3f87b,	0x86093000
	.word	0x3d451014,	0x55d3b3bc
	.word	0x3fd40430,	0x8686a000
	.word	0x3d3f8ef4,	0x3049f7d3
	.word	0x3fd40fe3,	0x63303000
	.word	0x3d3e5c5f,	0xe79f05c6
	.word	0x3fd41b94,	0x1cce0000
	.word	0x3d47dcb7,	0xf60de01c
	.word	0x3fd42742,	0xb427d000
	.word	0x3d433c6c,	0x7ea3ecc5
	.word	0x3fd432ef,	0x2a04e000
	.word	0x3d40276b,	0x3674752a
	.word	0x3fd43e99,	0x7f2c1000
	.word	0x3d1c3f72,	0x40c41a04
	.word	0x3fd44a41,	0xb463c000
	.word	0x3d31ee28,	0xf37cf612
	.word	0x3fd455e7,	0xca720000
	.word	0x3d1ad8c6,	0x36629aed
	.word	0x3fd4618b,	0xc21c5000
	.word	0x3d4d84fa,	0x16f66f66
	.word	0x3fd46d2d,	0x9c280000
	.word	0x3d359b27,	0x5f67f75a
	.word	0x3fd478cd,	0x5959b000
	.word	0x3d2ec89b,	0xf0c8d098
	.word	0x3fd4846a,	0xfa75b000
	.word	0x3d4a7057,	0x47219c8d
	.word	0x3fd49006,	0x80400000
	.word	0x3d43a198,	0x00f2f83a
	.word	0x3fd49b9f,	0xeb7c1000
	.word	0x3d3dac1c,	0x58ab60d7
	.word	0x3fd4a737,	0x3cecf000
	.word	0x3d432ee5,	0x8a0655db
	.word	0x3fd4b2cc,	0x75555000
	.word	0x3d43f81a,	0x1c3a02db
	.word	0x3fd4be5f,	0x95777000
	.word	0x3d4141b6,	0x993293ee
	.word	0x3fd4c9f0,	0x9e152000
	.word	0x3d487888,	0x63c7f488
	.word	0x3fd4d57f,	0x8fefe000
	.word	0x3d23f926,	0x7fd06868
	.word	0x3fd4e10c,	0x6bc8a000
	.word	0x3cf8283f,	0x1636f061
	.word	0x3fd4ec97,	0x32600000
	.word	0x3d234d7a,	0xaf04d104
	.word	0x3fd4f81f,	0xe4763000
	.word	0x3d4a00c2,	0x6f2c03dd
	.word	0x3fd503a6,	0x82cb1000
	.word	0x3d4965cd,	0xc3a41929
	.word	0x3fd50f2b,	0x0e1e0000
	.word	0x3d3a0940,	0x8c47b8d8
	.word	0x3fd51aad,	0x872df000
	.word	0x3d405a13,	0x927ac19f
	.word	0x3fd5262d,	0xeeb98000
	.word	0x3d40f230,	0x47bb5b00
	.word	0x3fd531ac,	0x457ee000
	.word	0x3d3df83b,	0x7d931501
	.word	0x3fd53d28,	0x8c3bd000
	.word	0x3d4ddd8d,	0x029240a7
	.word	0x3fd548a2,	0xc3add000
	.word	0x3d23167e,	0x63081cf7
	.word	0x3fd5541a,	0xec91b000
	.word	0x3d4f3f4a,	0xa91c688a
	.word	0x3fd55f91,	0x07a43000
	.word	0x3d4dc337,	0x10e416b4
	.word	0x3fd56b05,	0x15a18000
	.word	0x3d29247b,	0xbc4a23fc
	.word	0x3fd57677,	0x17455000
	.word	0x3d44d8a9,	0x356d941b
	.word	0x3fd581e7,	0x0d4b2000
	.word	0x3d4c19c3,	0xc9da4e1c
	.word	0x3fd58d54,	0xf86e0000
	.word	0x3d2791f3,	0x0a795215
	.word	0x3fd598c0,	0xd9687000
	.word	0x3d43d05b,	0x4793492e
	.word	0x3fd5a42a,	0xb0f4c000
	.word	0x3d4fc338,	0xa1a4108b
	.word	0x3fd5af92,	0x7fccd000
	.word	0x3d4c7f9a,	0x01400711
	.word	0x3fd5baf8,	0x46aa1000
	.word	0x3d46328b,	0x83c602e0
	.word	0x3fd5c65c,	0x06459000
	.word	0x3d4300fc,	0xff3f88cd
	.word	0x3fd5d1bd,	0xbf580000
	.word	0x3d4394a1,	0x1b1c1ee4
	.word	0x3fd5dd1d,	0x7299b000
	.word	0x3d43a84f,	0x3bf518f5
	.word	0x3fd5e87b,	0x20c29000
	.word	0x3d3527d1,	0x8f7738fa
	.word	0x3fd5f3d6,	0xca8a2000
	.word	0x3d37af84,	0x8e19cc75
	.word	0x3fd5ff30,	0x70a79000
	.word	0x3d2e9e43,	0x9f105039
	.word	0x3fd60a88,	0x13d1a000
	.word	0x3d36e9b9,	0xc879af55
	.word	0x3fd615dd,	0xb4bec000
	.word	0x3d13c7ca,	0x90bc04b2
	.word	0x3fd62131,	0x5424e000
	.word	0x3d463e81,	0xdaacbccc
	.word	0x3fd62c82,	0xf2b9c000
	.word	0x3d3e54bd,	0xbd7c8a98
	.word	0x3fd637d2,	0x91329000
	.word	0x3d450450,	0x865165ea
	.word	0x3fd64320,	0x30444000
	.word	0x3d3efe02,	0x7a01d7df
	.word	0x3fd64e6b,	0xd0a35000
	.word	0x3d2afe80,	0x69d61295
	.word	0x3fd659b5,	0x7303e000
	.word	0x3d1f281d,	0xb0af8efc
	.word	0x3fd664fd,	0x1819b000
	.word	0x3d418e55,	0xe463b5fe
	.word	0x3fd67042,	0xc0983000
	.word	0x3d4c6148,	0xdbdcf10d
	.word	0x3fd67b86,	0x6d327000
	.word	0x3d438fd6,	0x3ea11c64
	.word	0x3fd686c8,	0x1e9b1000
	.word	0x3d32bb11,	0x0af84054
	.word	0x3fd69207,	0xd5845000
	.word	0x3d43a44f,	0x4861e4ab
	.word	0x3fd69d45,	0x92a03000
	.word	0x3d38b1bd,	0xbf97ffa6
	.word	0x3fd6a881,	0x56a03000
	.word	0x3d420e9b,	0xd9d37351
	.word	0x3fd6b3bb,	0x22359000
	.word	0x3d30f625,	0x7a933268
	.word	0x3fd6bef2,	0xf6111000
	.word	0x3d48f8fc,	0x947d5965
	.word	0x3fd6ca28,	0xd2e34000
	.word	0x3d430ad0,	0xb8c49166
	.word	0x3fd6d55c,	0xb95c3000
	.word	0x3d39b9c8,	0xae9a6ee2
	.word	0x3fd6e08e,	0xaa2ba000
	.word	0x3d1e38c1,	0x39318d71
	.word	0x3fd6ebbe,	0xa600e000
	.word	0x3d4cce14,	0xc7dd17dd
	.word	0x3fd6f6ec,	0xad8b2000
	.word	0x3d249058,	0xfdf08376
	.word	0x3fd70218,	0xc178e000
	.word	0x3d42a947,	0x0e225428
	.word	0x3fd70d42,	0xe2789000
	.word	0x3d21aead,	0x337ee287
	.word	0x3fd7186b,	0x11381000
	.word	0x3d1934e2,	0x677d272b
	.word	0x3fd72391,	0x4e650000
	.word	0x3d0c1d52,	0xbdc87d8a
	.word	0x3fd72eb5,	0x9aac9000
	.word	0x3d4dd010,	0xd08a7a15
!! TBL - end

! constants:
	.align 64
CONSTANTS:
	.word	0x40000000,0x00000000
	.word	0x3fe55555,0x555571da
	.word	0x3fd99999,0x8702be3a
	.word	0x3fd24af7,0x3f4569b1
	.word	0x3ea62e42,0xfee00000	! scaled by 2**-20
	.word	0x3caa39ef,0x35793c76	! scaled by 2**-20
	.word	0xfffffc00,0x00000000	! ELEVENBIT
	.word	0x43200000
	.word	0xfff00000
	.word	0xc0190200		! ELEVENBIT
	.word	0x0200			! ELEVENBIT

#define two		0x00
#define A1		0x08
#define A2		0x10
#define A3		0x18
#define ln2hi		0x20
#define ln2lo		0x28
#define mask		0x30
#define ox43200000	0x38
#define oxfff00000	0x3c
#define oxc0194000	0x40
#define ox4000		0x44


! local storage indices

#define jnk		STACK_BIAS-0x8
#define tmp2		STACK_BIAS-0x10
#define tmp1		STACK_BIAS-0x18
#define tmp0		STACK_BIAS-0x20
#define tmp3		STACK_BIAS-0x28
#define tmp4		STACK_BIAS-0x30
#define tmp5		STACK_BIAS-0x38
#define tmp6		STACK_BIAS-0x40
! sizeof temp storage - must be a multiple of 16 for V9
#define tmps		0x40

! register use

! i0  n
! i1  x
! i2  stridex
! i3  y
! i4  stridey
! i5  

! g1  TBL

! l0  j0
! l1  j1
! l2  j2
! l3  
! l4  0x94000
! l5  CONSTANTS
! l6  0x000fffff
! l7  0x7ff00000

! o0  py0
! o1  py1
! o2  py2
! o3  		used in primary range bounds check
! o4  		used in primary range bounds check
! o5  		used in .rangeI check section as temporary
! o7  		NOT USED

! f0  u0,q0
! f2  v0,(two-v0)-u0,z0
! f4  n0,f0,q0
! f6  s0
! f8  q
! f10 u1,q1
! f12 v1,(two-v1)-u1,z1
! f14 n1,f1,q1
! f16 s1
! f18 t	! now tmp0 storage
! f20 u2,q2
! f22 v2,(two-v2)-u2,q2
! f24 n2,f2,q2
! f26 s2
! f28 0xfff00000
! f29 0x43200000
! f30 0x4000
! f31 0xc0194000
! f32 t0
! f34 h0,f0-(c0-h0)
! f36 c0
! f38 A1
! f40 two
! f42 t1
! f44 h1,f1-(c1-h1)
! f46 c1
! f48 A2
! f50 0xffff8000... or 0xfffffc00 for 6 or 11 bit tbl resp
! f52 t2
! f54 h2,f2-(c2-h2)
! f56 c2
! f58 A3	now tmp1 storage
! f60 ln2hi
! f62 ln2lo
!--------------------------------------------------------------------
!--------------------------------------------------------------------
! PREFETCH info
#define PREFETCH_MULT_READS 0
!--------------------------------------------------------------------
!--------------------------------------------------------------------
! define pipes for easier reading

#define ICNT		%i0

#define XPTR		%i1
#define XSTR		%i2
#define YPTR		%i3
#define YSTR		%i4

#define RANGE_LO	%l6
#define RANGE_HI	%l7

#define P0_X1		%f0
#define P0_f1		%f1
#define P0_f2		%f2
#define P0_f3		%f3
#define P0_f4		%f4
#define P0_f5		%f5
#define P0_f6		%f6
#define P0_f7		%f7
!#define P0_f8		%f8
#define T0_f8		%f8
#define P0_f9		%f9

#define P1_X2		%f10
#define P1_f11		%f11
#define P1_f12		%f12
#define P1_f13		%f13
#define P1_f14		%f14
#define P1_f15		%f15
#define P1_f16		%f16
#define P1_f17		%f17

!#define P1_f18		%f18
#define T1_f18		%f18

#define P1_f19		%f19

#define P2_X3		%f20
#define P2_f21		%f21
#define P2_f22		%f22
#define P2_f23		%f23
#define P2_f24		%f24
#define P2_f25		%f25
#define P2_f26		%f26
#define P2_f27		%f27
#define INF_f28		%f28
#define CONSTE432_f29	%f29

#define CONST_f30	%f30

#define TTOPMSK		%f31

#define P0_f32		%f32
#define P0_f34		%f34
#define P0_f36		%f36

#define P1_f42		%f42
#define P1_f44		%f44
#define P1_f46		%f46

#define P2_f52		%f52
#define P2_f54		%f54
#define P2_f56		%f56

#define G1_TBL		%g1
#define L5_CONSTANTS	%l5
#define FP40_TWO	%f40
#define FP38_A1		%f38
#define FP48_A2		%f48
#define FP50_MASK	%f50
!!!#define FP58_A3		%f58
#define T2_f58		%f58
#define FP60_LN2HI	%f60
#define FP62_LN2LO	%f62


!--------------------------------------------------------------------

	ENTRY(__vlog_ultra3)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,CONSTANTS,l5)
	PIC_SET(l7,TBL,o0)
	mov	%o0,%g1
	wr	%g0,0x82,%asi		! set %asi for non-faulting loads

	ld	[XPTR],%l0		! quickly			!X1

	sethi	%hi(0x90200),%l4		! ELEVENBIT
	or	%l4,%lo(0x90200),%l4		! ELEVENBIT
	ldd	[XPTR],P0_X1		! u.l[0] = *x			!X1
	sethi	%hi(0x000fffff),RANGE_LO
	or	RANGE_LO,%lo(0x000fffff),RANGE_LO
	sethi	%hi(0x7ff00000),RANGE_HI
	ldd	[L5_CONSTANTS+two],FP40_TWO
	fzero	P1_X2
	fzero	P2_X3
	ldd	[L5_CONSTANTS+A1],FP38_A1
	ldd	[L5_CONSTANTS+A2],FP48_A2
	ldd	[L5_CONSTANTS+ln2hi],FP60_LN2HI
	ldd	[L5_CONSTANTS+ln2lo],FP62_LN2LO
	ldd	[L5_CONSTANTS+mask],FP50_MASK
	ld	[L5_CONSTANTS+ox43200000],CONSTE432_f29
	ld	[L5_CONSTANTS+oxfff00000],INF_f28
	ld	[L5_CONSTANTS+oxc0194000],TTOPMSK
	fpadd32s P0_X1,TTOPMSK,P0_f2	! X+TTOP !X1 START
	ld	[L5_CONSTANTS+ox4000],CONST_f30
	sll	XSTR,3,XSTR		! scale strides
	sll	YSTR,3,YSTR
	add	%fp,jnk,%o0		! precondition loop
	fands	P0_f2,INF_f28,P0_f2	! (X+TTOP)&INF->n		X1
!	st	P0_X1,[%fp+tmp0]	!BYPASS in
	fzero	P0_f4
	fzero	P0_f6
!	ld	[%fp+tmp0],%l0		!BYPASS out ix			X1
	add	%fp,jnk,%o1
	add	%fp,jnk,%o2
	fzero	P0_f32
	fzero	P0_f34
	fzero	P0_f36
	fzero	P1_f12
	sub	%l0,RANGE_HI,%o3		! bounds for X1
	sub	RANGE_LO,%l0,%o4		! bounds for X1
	fzero	P1_f14
	fzero	P1_f16
	sub	YPTR,YSTR,YPTR
	fzero	P1_f42
	mov	%g0,%l1				! zero out for first pass 
	mov	%g0,%l2				! zero out for first pass
	fzero	P1_f44
	fzero	P1_f46
	fzero	T0_f8
	fzero	T1_f18
	fzero	T2_f58
	fzero	P2_f24
	fzero	P2_f26
	fzero	P2_f52
	fzero	P2_f54
	fzero	P2_f56
	ba	.loop0
	std	P2_f26,[%fp+tmp2]

	.align	16
! -- 16 byte aligned
.loop0:
!############################# AREA 1 (0-19) ###################################!
!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 1.1 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 0

	fmuld	P1_f44,FP48_A2,P1_f46			! s^2,A2	!	X2-2
	andcc	%o3,%o4,%o4					!	X1
	bge,pn	%icc,.range0	! ix<=0x000fffff or >=0x7ff00000 !	X1
! delay slot
	nop
	! x , n , reduction

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 1
	fpsub32s P0_X1,P0_f2,P0_X1		! X - n -> x	!	X1
	add	XPTR,XSTR,XPTR		! x += stridex		
	add	YPTR,YSTR,YPTR		! y += stridey	!

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 2
.cont0:
	! n*l2lo , lylo
	faddd	P0_f4,P0_f34,P0_f34	!n*l2lo,lylo		!	X1-2
	! TBL calc
	add     %l0,%l4,%l0             ! j = ix + 0x94000              X1
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 3
	fsubd	FP40_TWO,P2_f24,P2_f24	! two - xT		!	X3-2


!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 1.2 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 4
	! round up redunction
	fpadd32s P0_X1,CONST_f30,P0_f4	! x round up	 		X1
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 5
	! s ( poly + ( 2-xT-x)), n*l2lo+lylo
	faddd	P0_f36,P0_f34,P0_f36	! + n*l2lo+lylo			X1-2
	! n*l2hi
	fmuld	T0_f8,FP60_LN2HI,T0_f8 ! n*l2hi			!	X1-2

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 6
	fmuld	T1_f18,FP62_LN2LO,P1_f12 ! n*l2lo			!	X2
	faddd	P1_f46,FP38_A1,P1_f46	! (s^2*A2), A1				X2-2
	! TBL calc
	srl     %l0,10,%l0              ! j=(j>>11)&0x1f0 !ELEVENBIT !  X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 7
	fsubd	P2_f24,P2_X3,P2_f24	! (two - xT) - x	!	!X3-2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 1.3 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 8
	ldda	[XPTR]%asi,P1_X2				!	X2-nextX START
	! x-roundedup & 0xffff8000  -> xT  i.e 11bit value of x
	fand	P0_f4,FP50_MASK,P0_f4	! xT			!	X1

	

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 9
	faddd	P0_f36,P0_f32,P0_f36	! + (x-xT)			X1-2
	and     %l0,0x3ff,%l0           ! ELEVENBIT             !       X1
	st	P1_X2,[%fp+tmp0]	!BYPASS in		!	X2

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 10
	fmuld   P1_f46,P1_f44,P1_f46       ! s^2*A2+A1 , s^2       		X2-2
	ldd	[G1_TBL+%l1],P1_f44		!lylo		!	X2-2
	sub	%l1,8,%l1			! get back ptr to lyhi	X2-2
	faddd	P1_f12,P1_f44,P1_f44	!n*l2lo,lylo		!	X2-2

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 11

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 1.4 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 12
	faddd	P0_f36,P0_f6,P0_f36		! + lyhi		X1-2

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 13
	! x+xT
	faddd	P0_X1,P0_f4,P0_f6	 ! x + xT		!	X1
	! TBL calc
	sll     %l0,4,%l0               ! ELEVENBIT             !       X1


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 14
	faddd	P1_f46,P1_f14,P1_f46	! (s^2*A2+A1)s^2 + (2-xT-x)		X2-2


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 15
	fpadd32s P1_X2,TTOPMSK,P1_f12 ! X + TTOP			 !	X2
	ld	[%fp+tmp0],%l3			!BYPASS out	!	X2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 1.5 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 16
	! x-xT
	fsubd	P0_X1,P0_f4,P0_f32		! x-xT		!	X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 17
	faddd	P0_f36,T0_f8,P0_f36	! + n*l2hi			X1-2
	! TBL+1
	add     %l0,8,%l0                                       !       X1


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 18
	fmuld	P1_f16,P1_f46,P1_f46		! s*(POLY)	!	X2-2

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 19
	fands	P1_f12,INF_f28,P1_f12				!	X2
	fmuld	P2_f26,P2_f26,P2_f54		! z = s * s	!	!X3-2

!############################# AREA 2 (20#39) ###################################!
!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 2.1 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 20
	! (x-xT) / (x+xT) => s
	fdivd	P0_f32,P0_f6,P0_f6	! -> s			!	X1
	faddd	P1_f46,P1_f44,P1_f46	! + n*l2lo+lylo			X2-2
	ldd	[G1_TBL+%l1],P1_f44	! ld lyhi		!	X2-2
	mov	%l3,%l1			! BYPASS temp		!	X2
	! wrap !!! done for X0
	std	P0_f36,[%o0]					!	X1-2 FINI
	mov	YPTR,%o0					!	X1-2 INC

	addcc	ICNT,-1,ICNT		!
	ble,pn	%icc,.endloop0		!
! delay slot
	nop

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 21
! -- 16 byte aligned
.loop1:
	sub	%l1,RANGE_HI,%o3		! bounds for 		X2
	sub	RANGE_LO,%l1,%o4		! bounds for 		X2
	andcc	%o3,%o4,%o4					!	X2
	bge,pn	%icc,.range1	! ix<=0x000fffff or >=0x7ff00000 !	X2
! delay slot
	nop

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 22
	fpsub32s P1_X2,P1_f12,P1_X2		! X - n -> x	!	X2
	add	XPTR,XSTR,XPTR		! x += stridex		
	add	YPTR,YSTR,YPTR		! y += stridey	!
.cont1:

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 23
	fmuld	P2_f54,FP48_A2,P2_f56			! s^2,A2!	X3-2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 2.2 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 24
	! n to double
	fitod	P0_f2,T0_f8		! (double) n		!	X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 25

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 26
	faddd	P1_f46,P1_f42,P1_f46	! + (x-xT)			X2-2

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 27
	fpadd32s P1_X2,CONST_f30,P1_f14	! x round up	 		X2
	faddd	P2_f56,FP38_A1,P2_f56	! (s^2*A2), A1			X3-2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 2.3 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 28
	! 2 , xT
	fsubd	FP40_TWO,P0_f4,P0_f4	! two - xT		!	X1
	fmuld	T1_f18,FP60_LN2HI,T1_f18 ! n*l2hi			!	X2-2
	ldda	[XPTR]%asi,P2_X3				!	X3-nextX START

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 29

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 30
	faddd	P1_f46,P1_f44,P1_f46		! + lyhi		X2-2
	st	P2_X3,[%fp+tmp0]	!BYPASS in		!	X3


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 31
	fand	P1_f14,FP50_MASK,P1_f14	! xT			!	X2
	fmuld   P2_f56,P2_f54,P2_f56       ! s^2*A2+A1 , s^2       	X3-2
	ldd	[G1_TBL+%l2],P2_f54		!lylo		!	X3
	sub     %l2,8,%l2  		! back to TBL hi        !       X3
	add     %l1,%l4,%l1             ! j = ix + 0x94000              X2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 2.4 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 32
	! 2-xT , x
	fsubd	P0_f4,P0_X1,P0_f4	! (two - xT) - x	!	!X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 33
	fpadd32s P2_X3,TTOPMSK,P2_f22 ! X + TTOP		 !	X3


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 34
	faddd	P1_f46,T1_f18,P1_f46	! + n*l2hi			X2-2

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 35
	faddd	P1_X2,P1_f14,P1_f16	 ! x + xT		!	X2
	srl     %l1,10,%l1              ! j=(j>>11)&0x1f0 !ELEVENBIT !  X2
	faddd	P2_f56,P2_f24,P2_f56	! + 2-xT-x			X3-2


!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 2.5 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 36
	fitod	P1_f12,T1_f18		! (double) n		!	X2
	fmuld	T2_f58,FP62_LN2LO,P2_f24 ! n*l2lo		!	X3-2


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 37
	fands	P2_f22,INF_f28,P2_f22				!	X3
	ld	[%fp+tmp0],%l3			!BYPASS out	!	X3

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 38
	std	P1_f46,[%o1]					!	X2-2 FINI
	mov	YPTR,%o1					!	X2-2 INC

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 39
	fsubd	P1_X2,P1_f14,P1_f42		! x-xT		!	X2
	fmuld	P2_f26,P2_f56,P2_f56		! s*(POLY)	!	X3-2
	ldd	[G1_TBL+%l2],P2_f26	! ld lyhi		!	X3
	mov	%l3,%l2			! BYPASS for X3		!	X3
	and     %l1,0x3ff,%l1           ! ELEVENBIT             !       X2

!############################# AREA 3 (40#59) ###################################!
!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 3.1 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 40
	faddd	P2_f24,P2_f54,P2_f54	!n*l2lo,lylo		!	X3-2
	! s , s
	fmuld	P0_f6,P0_f6,P0_f34		! z = s * s	!	!X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 41
	fdivd	P1_f42,P1_f16,P1_f16	! -> s			!	X2
! -- 16 byte aligned
	addcc	ICNT,-1,ICNT		!
	ble,pn	%icc,.endloop1		!
	nop
.loop2:

	sub	%l2,RANGE_HI,%o3		! bounds for 		X3
	sub	RANGE_LO,%l2,%o4		! bounds for 		X3
	andcc	%o3,%o4,%o4					!	X3
	bge,pn	%icc,.range2	! ix<=0x000fffff or >=0x7ff00000 !	X3
!	delay slot
	nop
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 42
	fpsub32s P2_X3,P2_f22,P2_X3		! X - n -> x	!	X3
	add	XPTR,XSTR,XPTR		! x += stridex		
	add	YPTR,YSTR,YPTR		! y += stridey	!
.cont2:

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 43
	sll     %l1,4,%l1               ! ELEVENBIT             !       X2
	fmuld	T2_f58,FP60_LN2HI,T2_f58 ! n*l2hi		!	X3-2
	faddd	P2_f56,P2_f54,P2_f56	! + n*l2lo+lylo			X3-2


!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 3.2 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 44
	! s^ , A2
	fmuld	P0_f34,FP48_A2,P0_f36			! s^2,A2	!	X1
	fsubd	FP40_TWO,P1_f14,P1_f14	! two - xT		!	X2
	add     %l2,%l4,%l2             ! j = ix + 0x94000              X3
	srl     %l2,10,%l2              ! j=(j>>11)&0x1f0 !ELEVENBIT !  X3
	ldda	[XPTR]%asi,P0_X1				!	X1-nextX START

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 45
	st	P0_X1,[%fp+tmp0]	!BYPASS in		!	X1-nextX

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 46
	fpadd32s P2_X3,CONST_f30,P2_f24	! x round up	 		X3

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 47
	add     %l1,8,%l1                                       !       X2
	faddd	P2_f56,P2_f52,P2_f56	! + (x-xT)			X3-2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 3.3 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 48
	! s^2*A2 , A1
	faddd	P0_f36,FP38_A1,P0_f36	! (s^2*A2), A1				X1

	and     %l2,0x3ff,%l2           ! ELEVENBIT             !       X3


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 49
	fsubd	P1_f14,P1_X2,P1_f14	! (two - xT) - x	!	!X2


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 50
	fand	P2_f24,FP50_MASK,P2_f24	! xT			!	X3

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 51
	faddd	P2_f56,P2_f26,P2_f56		! + lyhi		X3-2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 3.4 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 52
	! s^2*A2+A1 , s^2
	fmuld   P0_f36,P0_f34,P0_f36       ! s^2*A2+A1 , s^2       		X1
	fpadd32s P0_X1,TTOPMSK,P0_f2 ! X + TTOP			 !	X1-nextX
	sll     %l2,4,%l2               ! ELEVENBIT             !       X3


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 53
	! lylo
	ldd	[G1_TBL+%l0],P0_f34		!lylo		!	X1
	add	%l0,-8,%l0			!lyhi pointer	!	X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 54
	faddd	P2_X3,P2_f24,P2_f26	 ! x + xT		!	X3

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 55
	faddd	P2_f56,T2_f58,P2_f56	! + n*l2hi			X3-2

!>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 3.5 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 56
	! s^2(s^2*A1+A1) + (2-xT-x)
	faddd	P0_f36,P0_f4,P0_f36	!					X1
	add     %l2,8,%l2               ! TBL+8 is TBL lo       !       X3

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 57
	! X+TTOP & INF -> n
	fands	P0_f2,INF_f28,P0_f2				!	X1-nextX
	! n * l2lo
	fmuld	T0_f8,FP62_LN2LO,P0_f4 ! n*l2lo			!	X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 58
	fsubd	P2_X3,P2_f24,P2_f52		! x-xT		!	X3
!BEST	ld	[%fp+tmp0],%l3		!BYPASS out		!	X1-nextX
	ld	[%fp+tmp0],%l3		!BYPASS out		!	X1-nextX


!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 59
	fitod	P2_f22,T2_f58		! (double) n		!	X3
	std	P2_f56,[%o2]					!	X3 FINI
	mov	YPTR,%o2					!	X3 INC

!############################# AREA 4 (OVERFLOW) ###################################!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 60
	! s * (s^2(s^2*A1+A1) + (2-xT-x))
	fmuld	P0_f6,P0_f36,P0_f36		! s*(POLY)	!	X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 61
	fmuld	P1_f16,P1_f16,P1_f44		! z = s * s	!	!X2
	! lyhi
	ldd	[G1_TBL+%l0],P0_f6	! ld lyhi		!	X1
	mov	%l3,%l0			! BYPASS tmp for X1	!	X1
	sub	%l0,RANGE_HI,%o3		! bounds for 		X1
	sub	RANGE_LO,%l0,%o4		! bounds for 		X1

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 62
	addcc	ICNT,-1,ICNT		!
! FALL THROUGH if running out of X array here
	bg,pt	%icc,.loop0		!62
! delay slot		
	fdivd	P2_f52,P2_f26,P2_f26	! -> s			!	X3

!!!!!!!!!!!!!!!!!!!!!!!!!!!!CYCLE 63
!LOSTC





	! Once we get to the last element, we loop three more times to finish
	! the computations in progress.  This means we will load past the end
	! of the argument vector, but since we use non-faulting loads and never
	! use the data, the only potential problem is cache miss.  (Strictly
	! speaking, since we pad the argument vector with twos, we incorrectly
	! raise inexact if the actual argument vector is all ones.)
	.endloop2:
		sethi	%hi(0x40000000),%l0	! "next argument" = two
		sub	%l0,RANGE_HI,%o3		! bnds chk x1  		!54
		sub	RANGE_LO,%l0,%o4		! bounds chk x1 	!54
		fmovd	FP40_TWO,P0_X1
		cmp	ICNT,-3
		bg,a,pt	%icc,.loop0
	! delay slot
		fpadd32s P0_X1,TTOPMSK,P0_f2	! n=(ix+0xc0194000)&0xfff00000
		ret
		restore

		.align	16
	.endloop0:
		sethi	%hi(0x40000000),%l1	! "next argument" = two
		fmovd	FP40_TWO,P1_X2
		cmp	ICNT,-3
		bg,a,pt	%icc,.loop1
	! delay slot
		fpadd32s P1_X2,TTOPMSK,P1_f12	! n=(ix+0xc0194000)&0xfff00000
		ret
		restore

		.align	16
	.endloop1:
		sethi	%hi(0x40000000),%l2	! "next argument" = two
		fmovd	FP40_TWO,P2_X3
		cmp	ICNT,-3
		bg,a,pt	%icc,.loop2
	! delay slot
		fpadd32s P2_X3,TTOPMSK,P2_f22	! n=(ix+0xc0194000)&0xfff00000
		ret
		restore


		.align	16
	.range0:
		cmp	%l0,RANGE_HI
		bgeu,pn	%icc,2f			! if (unsigned) ix >= 0x7ff00000
	! delay slot
		ld	[XPTR+4],%o5
		!THERE
		fxtod	P0_X1,P0_X1		! scale by 2**1074 w/o trapping
		st	P0_X1,[%fp+tmp0]	!BYPASS in
		add	XPTR,XSTR,XPTR		! x += stridex
		orcc	%l0,%o5,%g0
		be,pn	%icc,1f			! if x == 0
	! delay slot
		add	YPTR,YSTR,YPTR		! y += stridey
		! HERE
		fpadd32s P0_X1,TTOPMSK,P0_f2		! n = (ix + 0xc0194000) & 0xfff00000
		fands	P0_f2,INF_f28,P0_f2
		fpsub32s P0_X1,P0_f2,P0_X1		! u.l[0] -= n
		ld	[%fp+tmp0],%l0		!BYPASS out
		ba,pt	%icc,.cont0
	! delay slot
		fpsub32s P0_f2,CONSTE432_f29,P0_f2		! n -= 0x43200000
	1:
		fdivs	CONSTE432_f29,P0_f1,P0_f2		! raise div-by-zero
		ba,pt	%icc,3f
	! delay slot
		st	INF_f28,[YPTR]		! store -inf
	2:
		sll	%l0,1,%l0		! lop off sign bit
		add	XPTR,XSTR,XPTR		! x += stridex
		orcc	%l0,%o5,%g0
		be,pn	%icc,1b			! if x == -0
	! delay slot
		add	YPTR,YSTR,YPTR		! y += stridey
		fzero	P0_f2			! *y = (x < 0.0? 0.0 : x) * inf
		fcmpd	%fcc0,P0_X1,P0_f2
		fmovdl	%fcc0,P0_f2,P0_X1
		fand	INF_f28,FP50_MASK,P0_f2
		fnegd	P0_f2,P0_f2
		fmuld	P0_X1,P0_f2,P0_X1
		st	P0_X1,[YPTR]
	3:
		addcc	ICNT,-1,ICNT
		ble,pn	%icc,.endloop2
	! delay slot
		st	P0_f1,[YPTR+4]
		ld	[XPTR],%l0		! get next argument
		sub	%l0,RANGE_HI,%o3		! bnds chk x1  		!54
		sub	RANGE_LO,%l0,%o4		! bounds chk x1 	!54
		ldd	[XPTR],P0_X1
		fpadd32s P0_X1,TTOPMSK,P0_f2	! n=(ix+0xc0194000)&0xfff00000
		ba,pt	%icc,.loop0
	! delay slot
		fands	P0_f2,INF_f28,P0_f2				!58


		.align	16
	.range1:
		cmp	%l1,RANGE_HI
		bgeu,pn	%icc,2f			! if (unsigned) ix >= 0x7ff00000
	! delay slot
		ld	[XPTR+4],%o5
		fxtod	P1_X2,P1_X2		! scale by 2**1074 w/o trapping
		st	P1_X2,[%fp+tmp1]
		add	XPTR,XSTR,XPTR		! x += stridex
		orcc	%l1,%o5,%g0
		be,pn	%icc,1f			! if x == 0
	! delay slot
		add	YPTR,YSTR,YPTR		! y += stridey
		fpadd32s P1_X2,TTOPMSK,P1_f12		! n = (ix + 0xc0194000) & 0xfff00000
		fands	P1_f12,INF_f28,P1_f12
		fpsub32s P1_X2,P1_f12,P1_X2		! u.l[0] -= n
		ld	[%fp+tmp1],%l1
		ba,pt	%icc,.cont1
	! delay slot
		fpsub32s P1_f12,CONSTE432_f29,P1_f12		! n -= 0x43200000
	1:
		fdivs	CONSTE432_f29,P1_f11,P1_f12		! raise div-by-zero
		ba,pt	%icc,3f
	! delay slot
		st	INF_f28,[YPTR]		! store -inf
	2:
		sll	%l1,1,%l1		! lop off sign bit
		add	XPTR,XSTR,XPTR		! x += stridex
		orcc	%l1,%o5,%g0
		be,pn	%icc,1b			! if x == -0
	! delay slot
		add	YPTR,YSTR,YPTR		! y += stridey
		fzero	P1_f12			! *y = (x < 0.0? 0.0 : x) * inf
		fcmpd	%fcc0,P1_X2,P1_f12
		fmovdl	%fcc0,P1_f12,P1_X2
		fand	INF_f28,FP50_MASK,P1_f12
		fnegd	P1_f12,P1_f12
		fmuld	P1_X2,P1_f12,P1_X2
		st	P1_X2,[YPTR]
	3:
		addcc	ICNT,-1,ICNT
		ble,pn	%icc,.endloop0
	! delay slot
		st	P1_f11,[YPTR+4]
		ld	[XPTR],%l1		! get next argument
		ldd	[XPTR],P1_X2
		fpadd32s P1_X2,TTOPMSK,P1_f12 		! X + TTOP
		ba,pt	%icc,.loop1
	! delay slot
		fands	P1_f12,INF_f28,P1_f12		! & INF


	.align	16
.range2:
	cmp	%l2,RANGE_HI
	bgeu,pn	%icc,2f			! if (unsigned) ix >= 0x7ff00000
! delay slot
	ld	[XPTR+4],%o5
	fxtod	P2_X3,P2_X3		! scale by 2**1074 w/o trapping
	st	P2_X3,[%fp+tmp2]
	add	XPTR,XSTR,XPTR		! x += stridex
	orcc	%l2,%o5,%g0
	be,pn	%icc,1f			! if x == 0
! delay slot
	add	YPTR,YSTR,YPTR		! y += stridey
	fpadd32s P2_X3,TTOPMSK,P2_f22		! n = (ix + 0xc0194000) & 0xfff00000
	fands	P2_f22,INF_f28,P2_f22
	fpsub32s P2_X3,P2_f22,P2_X3		! u.l[0] -= n
	ld	[%fp+tmp2],%l2
	ba,pt	%icc,.cont2
! delay slot
	fpsub32s P2_f22,CONSTE432_f29,P2_f22		! n -= 0x43200000
1:
	fdivs	CONSTE432_f29,P2_f21,P2_f22		! raise div-by-zero
	ba,pt	%icc,3f
! delay slot
	st	INF_f28,[YPTR]		! store -inf
2:
	sll	%l2,1,%l2		! lop off sign bit
	add	XPTR,XSTR,XPTR		! x += stridex
	orcc	%l2,%o5,%g0
	be,pn	%icc,1b			! if x == -0
! delay slot
	add	YPTR,YSTR,YPTR		! y += stridey
	fzero	P2_f22			! *y = (x < 0.0? 0.0 : x) * inf
	fcmpd	%fcc0,P2_X3,P2_f22
	fmovdl	%fcc0,P2_f22,P2_X3
	fand	INF_f28,FP50_MASK,P2_f22
	fnegd	P2_f22,P2_f22
	fmuld	P2_X3,P2_f22,P2_X3
	st	P2_X3,[YPTR]
3:
	addcc	ICNT,-1,ICNT
	ble,pn	%icc,.endloop1
! delay slot
	st	P2_f21,[YPTR+4]
	ld	[XPTR],%l2		! get next argument
	ldd	[XPTR],P2_X3
	fpadd32s P2_X3,TTOPMSK,P2_f22 ! X + TTOP
	ba,pt	%icc,.loop2
! delay slot
	fands	P2_f22,INF_f28,P2_f22				!	X3
	nop !ld	[XPTR+4],P2_f21

	SET_SIZE(__vlog_ultra3)

