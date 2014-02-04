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

	.file	"__vpow.S"

#include "libm.h"

	RO_DATA
	.align	64

.CONST_TBL:

! __mt_constlog2[2*i] = high order rounded 32 bits log2(1+i/256)*256, i = [0, 255]
! __mt_constlog2[2*i+1] = low order least bits log2(1+i/256)*256, i = [0, 255]

	.word	0x00000000,	0x00000000,	0x00000000,	0x00000000,
	.word	0x3ff709c4,	0x00000000,	0x3e9b5eab,	0x1dd2b66f,
	.word	0x4006fe51,	0x00000000,	0xbea2443d,	0xeba01c72,
	.word	0x40113631,	0x00000000,	0x3e97a97b,	0x0c4bb41a,
	.word	0x4016e797,	0x00000000,	0xbebe8f4b,	0x759d6476,
	.word	0x401c9364,	0x00000000,	0xbeb15ebc,	0x1e666460,
	.word	0x40211cd2,	0x00000000,	0xbeb57665,	0xf6893f5d,
	.word	0x4023ed31,	0x00000000,	0xbecae5e9,	0x7677f62d,
	.word	0x4026bad3,	0x00000000,	0x3ecd63bf,	0x61cc4d82,
	.word	0x402985c0,	0x00000000,	0xbebe5b57,	0x35cfaf8e,
	.word	0x402c4dfb,	0x00000000,	0xbec1bd55,	0x2842c1c2,
	.word	0x402f138a,	0x00000000,	0xbecf336b,	0x18178cbe,
	.word	0x4030eb39,	0x00000000,	0xbed81758,	0x19530c23,
	.word	0x40324b5b,	0x00000000,	0x3edf84d6,	0x8f2268b4,
	.word	0x4033aa30,	0x00000000,	0xbec16c07,	0x1e93fd97,
	.word	0x403507b8,	0x00000000,	0x3ecb019d,	0xdb6a796a,
	.word	0x403663f7,	0x00000000,	0xbe94dbb3,	0xa60cceb2,
	.word	0x4037beef,	0x00000000,	0xbeda51d7,	0x5fb0ef94,
	.word	0x403918a1,	0x00000000,	0x3edb918c,	0xd6ab9c8d,
	.word	0x403a7112,	0x00000000,	0xbec065bd,	0xb60a5dd4,
	.word	0x403bc842,	0x00000000,	0x3ed02b6a,	0xee98ecb1,
	.word	0x403d1e35,	0x00000000,	0xbebca47d,	0x25b2f4c7,
	.word	0x403e72ec,	0x00000000,	0x3eb17fa5,	0xb21cbdb6,
	.word	0x403fc66a,	0x00000000,	0x3eae1601,	0x49209a69,
	.word	0x40408c59,	0x00000000,	0xbeecc961,	0x871a7611,
	.word	0x404134e2,	0x00000000,	0xbee2ddbe,	0x74803297,
	.word	0x4041dcd2,	0x00000000,	0xbeea2ab5,	0x212856eb,
	.word	0x40428429,	0x00000000,	0x3ee2c1e9,	0x8fe35da3,
	.word	0x40432aea,	0x00000000,	0xbecd8751,	0xe5e0ae0d,
	.word	0x4043d114,	0x00000000,	0x3eeb66a2,	0x98fc02ce,
	.word	0x404476aa,	0x00000000,	0xbea9f022,	0xcb3b1c5b,
	.word	0x40451bac,	0x00000000,	0xbeebe168,	0xdd6dd3fe,
	.word	0x4045c01a,	0x00000000,	0x3edcfdeb,	0x43cfd006,
	.word	0x404663f7,	0x00000000,	0xbea4dbb3,	0xa60cceb2,
	.word	0x40470743,	0x00000000,	0xbed5887e,	0xc06b1ff2,
	.word	0x4047a9ff,	0x00000000,	0xbedc17d1,	0x108740d9,
	.word	0x40484c2c,	0x00000000,	0xbed7e87e,	0x268116ee,
	.word	0x4048edcb,	0x00000000,	0xbec7cad4,	0x944a32be,
	.word	0x40498edd,	0x00000000,	0x3eadf9c3,	0x7c0beb3a,
	.word	0x404a2f63,	0x00000000,	0x3ed1905c,	0x35651c43,
	.word	0x404acf5e,	0x00000000,	0x3ed6da76,	0x49f7f08f,
	.word	0x404b6ecf,	0x00000000,	0x3ec75f95,	0xe96bed8d,
	.word	0x404c0db7,	0x00000000,	0xbed91359,	0x08df8ec9,
	.word	0x404cac16,	0x00000000,	0x3ede3b86,	0xe44b6265,
	.word	0x404d49ee,	0x00000000,	0x3ee30c96,	0x5bf23d2d,
	.word	0x404de740,	0x00000000,	0xbecc4eb7,	0xf11e41be,
	.word	0x404e840c,	0x00000000,	0xbec8b195,	0xb338360c,
	.word	0x404f2053,	0x00000000,	0x3edc9047,	0x93a3ba95,
	.word	0x404fbc17,	0x00000000,	0xbee1bf65,	0xfd7715ca,
	.word	0x40502bac,	0x00000000,	0xbef76cbe,	0x67113a18,
	.word	0x4050790b,	0x00000000,	0xbee227e7,	0xfb487e73,
	.word	0x4050c629,	0x00000000,	0x3efd550a,	0xa3a93ec8,
	.word	0x40511308,	0x00000000,	0xbee2967a,	0x451a7b48,
	.word	0x40515fa6,	0x00000000,	0x3efdaec2,	0x3fd65f8e,
	.word	0x4051ac06,	0x00000000,	0xbef35b83,	0xe3eb5ce3,
	.word	0x4051f826,	0x00000000,	0xbec24ee3,	0xd9a82f2e,
	.word	0x40524408,	0x00000000,	0xbef53c7e,	0x319f6e92,
	.word	0x40528fab,	0x00000000,	0x3eead993,	0x41b181d1,
	.word	0x4052db11,	0x00000000,	0xbead932a,	0x8487642e,
	.word	0x40532639,	0x00000000,	0x3ef8daca,	0x0d66b8f9,
	.word	0x40537125,	0x00000000,	0xbee8ad99,	0x09933766,
	.word	0x4053bbd4,	0x00000000,	0xbef7d788,	0xc15a9f3d,
	.word	0x40540646,	0x00000000,	0x3eed8d82,	0x24bad97a,
	.word	0x4054507d,	0x00000000,	0xbe922b03,	0xc6b2a5f6,
	.word	0x40549a78,	0x00000000,	0x3ef2f346,	0xe2bf924b,
	.word	0x4054e439,	0x00000000,	0xbeffc5c1,	0x258110a4,
	.word	0x40552dbe,	0x00000000,	0xbead9b4a,	0x641184f9,
	.word	0x40557709,	0x00000000,	0x3edb3378,	0xcab10782,
	.word	0x4055c01a,	0x00000000,	0x3eecfdeb,	0x43cfd006,
	.word	0x405608f2,	0x00000000,	0xbef2f5ad,	0xd49a43fc,
	.word	0x40565190,	0x00000000,	0xbedb9884,	0x591add87,
	.word	0x405699f5,	0x00000000,	0x3ee2466a,	0x5c3462a4,
	.word	0x4056e222,	0x00000000,	0xbee93179,	0x90d43957,
	.word	0x40572a16,	0x00000000,	0x3eebe5e0,	0xc14a1a6d,
	.word	0x405771d3,	0x00000000,	0xbef16041,	0x3106e405,
	.word	0x4057b958,	0x00000000,	0xbef4eb95,	0x4eea2724,
	.word	0x405800a5,	0x00000000,	0x3ef8c587,	0x150cabae,
	.word	0x405847bc,	0x00000000,	0x3ee9ec30,	0xc6e3e04a,
	.word	0x40588e9c,	0x00000000,	0x3efcb82c,	0x89692d99,
	.word	0x4058d546,	0x00000000,	0x3efced70,	0xdc6acf42,
	.word	0x40591bbb,	0x00000000,	0xbefdb83a,	0x3dd2d353,
	.word	0x405961f9,	0x00000000,	0x3eb49d02,	0x6e33d676,
	.word	0x4059a802,	0x00000000,	0x3eec8f11,	0x979a5db7,
	.word	0x4059edd6,	0x00000000,	0x3efd66c9,	0x77e236c7,
	.word	0x405a3376,	0x00000000,	0x3ec4fec0,	0xa13af882,
	.word	0x405a78e1,	0x00000000,	0x3ef1bdef,	0xbd14a081,
	.word	0x405abe18,	0x00000000,	0x3efe5fc7,	0xd238691d,
	.word	0x405b031c,	0x00000000,	0xbed01f9b,	0xcb999fe9,
	.word	0x405b47ec,	0x00000000,	0xbec18efa,	0xbeb7d722,
	.word	0x405b8c89,	0x00000000,	0xbee203bc,	0xc3346511,
	.word	0x405bd0f3,	0x00000000,	0xbed6186f,	0xcf54bbd3,
	.word	0x405c152a,	0x00000000,	0x3efb0932,	0xb9700973,
	.word	0x405c5930,	0x00000000,	0xbef4b5a9,	0x2a606047,
	.word	0x405c9d03,	0x00000000,	0xbec26b70,	0x98590071,
	.word	0x405ce0a5,	0x00000000,	0xbefb7169,	0xe0cda8bd,
	.word	0x405d2415,	0x00000000,	0xbeebfa06,	0xc156f521,
	.word	0x405d6754,	0x00000000,	0xbedfcd15,	0xf101c142,
	.word	0x405daa62,	0x00000000,	0x3ee10327,	0xdc8093a5,
	.word	0x405ded40,	0x00000000,	0xbee5dee4,	0xd9d8a273,
	.word	0x405e2fed,	0x00000000,	0x3eee84b9,	0x4c06f913,
	.word	0x405e726b,	0x00000000,	0xbef7862a,	0xcb7ceb98,
	.word	0x405eb4b8,	0x00000000,	0x3ef1f456,	0xf394f972,
	.word	0x405ef6d6,	0x00000000,	0x3efcca38,	0x881f4780,
	.word	0x405f38c5,	0x00000000,	0x3ef9ef31,	0x50343f8e,
	.word	0x405f7a85,	0x00000000,	0x3efa32c1,	0xb3b3864c,
	.word	0x405fbc17,	0x00000000,	0xbef1bf65,	0xfd7715ca,
	.word	0x405ffd7a,	0x00000000,	0xbef95f00,	0x19518ce0,
	.word	0x40601f57,	0x00000000,	0x3ef3b932,	0x6ff91960,
	.word	0x40603fdb,	0x00000000,	0xbf0d1a19,	0xa0331af3,
	.word	0x40606047,	0x00000000,	0x3ee9f24e,	0xb23e991f,
	.word	0x4060809d,	0x00000000,	0xbedb011f,	0x855b4988,
	.word	0x4060a0dc,	0x00000000,	0x3efa7c70,	0xfde006c7,
	.word	0x4060c105,	0x00000000,	0x3e9ac754,	0xcb104aea,
	.word	0x4060e117,	0x00000000,	0x3f0d535f,	0x0444ebab,
	.word	0x40610114,	0x00000000,	0xbf03ab0d,	0xc56138c9,
	.word	0x406120fa,	0x00000000,	0xbef630f3,	0xfc695a97,
	.word	0x406140ca,	0x00000000,	0xbec5786a,	0xf187a96b,
	.word	0x40616084,	0x00000000,	0x3f012578,	0x0181e2b3,
	.word	0x40618029,	0x00000000,	0xbef846b4,	0x4ad8a38b,
	.word	0x40619fb8,	0x00000000,	0xbf01c336,	0xf7a3a78f,
	.word	0x4061bf31,	0x00000000,	0x3eee95d0,	0x0de3b514,
	.word	0x4061de95,	0x00000000,	0x3eed9cbb,	0xa6187a4d,
	.word	0x4061fde4,	0x00000000,	0xbef678bf,	0x6cdedf51,
	.word	0x40621d1d,	0x00000000,	0x3f06edb5,	0x668c543d,
	.word	0x40623c42,	0x00000000,	0xbef5ec6c,	0x1bfbf89a,
	.word	0x40625b51,	0x00000000,	0x3f062dcf,	0x4115a1a3,
	.word	0x40627a4c,	0x00000000,	0x3ec6172f,	0xe015e13c,
	.word	0x40629932,	0x00000000,	0xbed30dd5,	0x3f5c184c,
	.word	0x4062b803,	0x00000000,	0x3f01cfde,	0xb43cfd00,
	.word	0x4062d6c0,	0x00000000,	0x3ee35013,	0x8064a94e,
	.word	0x4062f568,	0x00000000,	0x3f0d7acf,	0xc98509e3,
	.word	0x406313fd,	0x00000000,	0xbf0d7932,	0x43718371,
	.word	0x4063327c,	0x00000000,	0x3f0aad27,	0x29b21ae5,
	.word	0x406350e8,	0x00000000,	0x3ef92b83,	0xec743665,
	.word	0x40636f40,	0x00000000,	0xbec249ba,	0x76fee235,
	.word	0x40638d84,	0x00000000,	0xbeefd0a2,	0xf6d7e41e,
	.word	0x4063abb4,	0x00000000,	0xbec57f7a,	0x64ccd537,
	.word	0x4063c9d0,	0x00000000,	0x3f09242b,	0x8488b305,
	.word	0x4063e7d9,	0x00000000,	0x3efbcfb8,	0x0b357154,
	.word	0x406405cf,	0x00000000,	0xbf0cb1c2,	0xd10504b4,
	.word	0x406423b0,	0x00000000,	0x3f0fa61a,	0xaa59c1d8,
	.word	0x4064417f,	0x00000000,	0x3ef26410,	0xb256d8d7,
	.word	0x40645f3b,	0x00000000,	0xbf09d77e,	0x31d6ca00,
	.word	0x40647ce3,	0x00000000,	0xbeda5fb4,	0xf23978de,
	.word	0x40649a78,	0x00000000,	0x3f02f346,	0xe2bf924b,
	.word	0x4064b7fb,	0x00000000,	0xbf0106da,	0x1aa0e9e7,
	.word	0x4064d56a,	0x00000000,	0x3f06ccf3,	0xb1129b7c,
	.word	0x4064f2c7,	0x00000000,	0x3f006a7c,	0xcf9dd420,
	.word	0x40651012,	0x00000000,	0xbf0e3dd5,	0xc1c885ae,
	.word	0x40652d49,	0x00000000,	0x3f00b91e,	0x4253bd27,
	.word	0x40654a6f,	0x00000000,	0xbf0cd6af,	0x1c9393cd,
	.word	0x40656781,	0x00000000,	0x3f0ee1ac,	0x0b1ec5ea,
	.word	0x40658482,	0x00000000,	0x3ef34c4e,	0x99e1c6c6,
	.word	0x4065a171,	0x00000000,	0xbf06d01c,	0xa8f50e5f,
	.word	0x4065be4d,	0x00000000,	0x3ed96a28,	0x6955d67e,
	.word	0x4065db17,	0x00000000,	0x3f0d4210,	0x4f127092,
	.word	0x4065f7d0,	0x00000000,	0xbed7c3ec,	0xa28e69ca,
	.word	0x40661477,	0x00000000,	0xbf07f393,	0xbdd98c47,
	.word	0x4066310c,	0x00000000,	0xbf0c2ab3,	0xedefe569,
	.word	0x40664d8f,	0x00000000,	0xbef44732,	0x0833c207,
	.word	0x40666a01,	0x00000000,	0xbf0c6e1d,	0xcd0cb449,
	.word	0x40668661,	0x00000000,	0xbefb4848,	0x3c643a24,
	.word	0x4066a2b0,	0x00000000,	0xbf08697c,	0x3d7dfd9b,
	.word	0x4066beed,	0x00000000,	0x3ef12866,	0xd705c554,
	.word	0x4066db19,	0x00000000,	0x3f0a9d86,	0x52765f7c,
	.word	0x4066f735,	0x00000000,	0xbf0d0e8e,	0x7a165e04,
	.word	0x4067133f,	0x00000000,	0xbf093aa4,	0xe106ba60,
	.word	0x40672f38,	0x00000000,	0xbf04bace,	0x940d18ba,
	.word	0x40674b20,	0x00000000,	0xbef4d8fc,	0x561c8d44,
	.word	0x406766f7,	0x00000000,	0x3ef5931e,	0xf6e6f15b,
	.word	0x406782be,	0x00000000,	0xbf000896,	0x6a210de0,
	.word	0x40679e74,	0x00000000,	0xbf05dbfe,	0x780eccdb,
	.word	0x4067ba19,	0x00000000,	0xbecb2bf4,	0x6fd85522,
	.word	0x4067d5ae,	0x00000000,	0xbefd2fc3,	0xaddfdee2,
	.word	0x4067f132,	0x00000000,	0x3ef0c167,	0x8ae89767,
	.word	0x40680ca6,	0x00000000,	0x3ef034a6,	0xfc6488d1,
	.word	0x4068280a,	0x00000000,	0xbef520c7,	0xc69211fe,
	.word	0x4068435d,	0x00000000,	0x3f05328d,	0xdcedf39e,
	.word	0x40685ea1,	0x00000000,	0xbf03d361,	0x367bde41,
	.word	0x406879d4,	0x00000000,	0xbebc2624,	0x7a0cdfbb,
	.word	0x406894f7,	0x00000000,	0x3f02c1bb,	0xe2d01ba9,
	.word	0x4068b00b,	0x00000000,	0xbf043a4a,	0xd5c7a4dd,
	.word	0x4068cb0e,	0x00000000,	0x3efda59d,	0xded9b445,
	.word	0x4068e602,	0x00000000,	0x3eb11eb3,	0x043f5602,
	.word	0x406900e6,	0x00000000,	0x3ee60002,	0xccfe43f5,
	.word	0x40691bbb,	0x00000000,	0xbf0db83a,	0x3dd2d353,
	.word	0x4069367f,	0x00000000,	0x3f0b682a,	0xcba73219,
	.word	0x40695135,	0x00000000,	0xbef53d8e,	0x8e4c59c3,
	.word	0x40696bdb,	0x00000000,	0xbef6a9a5,	0x050809db,
	.word	0x40698671,	0x00000000,	0x3f0db68e,	0x0ba15359,
	.word	0x4069a0f9,	0x00000000,	0xbef6278f,	0xd810b546,
	.word	0x4069bb71,	0x00000000,	0xbec528c6,	0xcdef4d8d,
	.word	0x4069d5da,	0x00000000,	0xbeb57f7a,	0x64ccd537,
	.word	0x4069f034,	0x00000000,	0xbee33716,	0xa9ae332f,
	.word	0x406a0a7f,	0x00000000,	0xbef2d9f7,	0x698ce769,
	.word	0x406a24bb,	0x00000000,	0xbef48c02,	0x44aa8cfc,
	.word	0x406a3ee8,	0x00000000,	0xbed8e3cf,	0xc25f0ce6,
	.word	0x406a5906,	0x00000000,	0x3f0044c5,	0x590979a0,
	.word	0x406a7316,	0x00000000,	0xbef7e86f,	0x9c2154fb,
	.word	0x406a8d17,	0x00000000,	0xbf03a076,	0x2ed351cd,
	.word	0x406aa709,	0x00000000,	0xbed4ffd6,	0x59064390,
	.word	0x406ac0ed,	0x00000000,	0xbf04d9bb,	0x3135f0b1,
	.word	0x406adac2,	0x00000000,	0xbee8ee37,	0xcd2ea9d3,
	.word	0x406af489,	0x00000000,	0xbf02ba1b,	0x4a95229c,
	.word	0x406b0e41,	0x00000000,	0x3ef35e64,	0x35ebd377,
	.word	0x406b27eb,	0x00000000,	0x3f02fe3c,	0x2291b5ad,
	.word	0x406b4187,	0x00000000,	0x3efa5480,	0x45ecbc5d,
	.word	0x406b5b15,	0x00000000,	0xbedee0d3,	0x3432f2c3,
	.word	0x406b7495,	0x00000000,	0xbf0c2ab3,	0x496d2d24,
	.word	0x406b8e06,	0x00000000,	0x3ef04439,	0x848e9d1e,
	.word	0x406ba76a,	0x00000000,	0xbf03186d,	0xa6fc41e0,
	.word	0x406bc0bf,	0x00000000,	0x3f05fc8d,	0x8164754e,
	.word	0x406bda07,	0x00000000,	0x3eecc67e,	0x6db516de,
	.word	0x406bf341,	0x00000000,	0x3ee14464,	0xa6bcdf48,
	.word	0x406c0c6d,	0x00000000,	0x3f011f17,	0x74d8b66a,
	.word	0x406c258c,	0x00000000,	0xbefd4cdb,	0xebaa4121,
	.word	0x406c3e9d,	0x00000000,	0xbf074797,	0xeab3259d,
	.word	0x406c57a0,	0x00000000,	0xbee44a49,	0xa82ed669,
	.word	0x406c7096,	0x00000000,	0xbf045b87,	0x8e27d0d9,
	.word	0x406c897e,	0x00000000,	0xbec7c929,	0xc9e33277,
	.word	0x406ca259,	0x00000000,	0xbef1ab66,	0x74e5008e,
	.word	0x406cbb26,	0x00000000,	0x3f09333f,	0x3d6bb35f,
	.word	0x406cd3e7,	0x00000000,	0xbf07cd5d,	0xbe4f6f23,
	.word	0x406cec9a,	0x00000000,	0xbf0848eb,	0x7f40a752,
	.word	0x406d053f,	0x00000000,	0x3f0b4982,	0x259cc626,
	.word	0x406d1dd8,	0x00000000,	0x3ee9b4c3,	0xf0c92723,
	.word	0x406d3664,	0x00000000,	0xbf036033,	0x8ab5a1f2,
	.word	0x406d4ee2,	0x00000000,	0x3f015971,	0x8aacb6ec,
	.word	0x406d6754,	0x00000000,	0xbeefcd15,	0xf101c142,
	.word	0x406d7fb9,	0x00000000,	0xbf0bd935,	0x64ee1bf6,
	.word	0x406d9810,	0x00000000,	0x3f090f59,	0x8530f102,
	.word	0x406db05b,	0x00000000,	0x3f0a28be,	0xd929effb,
	.word	0x406dc89a,	0x00000000,	0xbf053002,	0xa4e86631,
	.word	0x406de0cb,	0x00000000,	0x3efcb99c,	0x5233429f,
	.word	0x406df8f0,	0x00000000,	0x3ef04357,	0x9625f7a4,
	.word	0x406e1108,	0x00000000,	0x3f0b6bdd,	0x258a7b23,
	.word	0x406e2914,	0x00000000,	0x3ef70700,	0xa00fdd55,
	.word	0x406e4113,	0x00000000,	0x3f0bab95,	0x4f46b93f,
	.word	0x406e5906,	0x00000000,	0x3efe4411,	0x672b0c89,
	.word	0x406e70ed,	0x00000000,	0xbf06e041,	0xe4467502,
	.word	0x406e88c7,	0x00000000,	0xbf032765,	0x63557797,
	.word	0x406ea094,	0x00000000,	0x3f0d7b8f,	0x0e7b8e75,
	.word	0x406eb856,	0x00000000,	0xbeccd5dc,	0x13cad28e,
	.word	0x406ed00b,	0x00000000,	0x3f0222fb,	0x08d5c3f2,
	.word	0x406ee7b4,	0x00000000,	0x3f0c6cea,	0x541f5b70,
	.word	0x406eff52,	0x00000000,	0xbf0fd40b,	0x070e6c33,
	.word	0x406f16e3,	0x00000000,	0xbf0f8922,	0x73f1379b,
	.word	0x406f2e68,	0x00000000,	0xbf0fa051,	0xeebd4f74,
	.word	0x406f45e1,	0x00000000,	0xbf0d0c3e,	0x6aac6ca9,
	.word	0x406f5d4e,	0x00000000,	0xbf04c432,	0x5068bc88,
	.word	0x406f74af,	0x00000000,	0xbede20a0,	0xa450bc93,
	.word	0x406f8c04,	0x00000000,	0x3f08f3a3,	0x1a23946e,
	.word	0x406fa34e,	0x00000000,	0x3ee177c2,	0x3362928c,
	.word	0x406fba8c,	0x00000000,	0x3ec71513,	0x7cfebaa0,
	.word	0x406fd1be,	0x00000000,	0x3f031fca,	0xbe50ac88,
	.word	0x406fe8e5,	0x00000000,	0xbedd485c,	0xbfb44c3b,
!
	.word	0x01a56e1f,	0xc2f8f359,	! _TINY = 1.0e-300
	.word	0x7e37e43c,	0x8800759c,	! _HUGE = 1.0e+300
	.word	0x3f6d94ae,	0x0bf85de6,	! KA1_LO  = (1.41052154268147309568e-05*256)
	.word	0x40871540,	0x00000000,	! KA1_HI  = (2.8853759765625e+00*256)
	.word	0x3cd5d528,	0x93bc7fec,	! KB5     = 1.21195555854068860923e-15
	.word	0x3e2c6b08,	0xd71f5d1e,	! KB3     = 3.30830268126604677436e-09
	.word	0x3ecebfbd,	0xff82c4ed,	! KB2     = 3.66556559691003767877e-06
	.word	0x3f662e42,	0xfefa39ef,	! KB1     = 2.70760617406228636578e-03
!
! __mt_constexp2[2*i] = high order bits 2^(i/256), i = [0, 255]
! __mt_constexp2[2*i+1] = least bits 2^(i/256), i = [0, 255]

	.word	0x3ff00000,	0x00000000,	0x00000000,	0x00000000,
	.word	0x3ff00b1a,	0xfa5abcbf,	0xbc84f6b2,	0xa7609f71,
	.word	0x3ff0163d,	0xa9fb3335,	0x3c9b6129,	0x9ab8cdb7,
	.word	0x3ff02168,	0x143b0281,	0xbc82bf31,	0x0fc54eb6,
	.word	0x3ff02c9a,	0x3e778061,	0xbc719083,	0x535b085d,
	.word	0x3ff037d4,	0x2e11bbcc,	0x3c656811,	0xeeade11a,
	.word	0x3ff04315,	0xe86e7f85,	0xbc90a31c,	0x1977c96e,
	.word	0x3ff04e5f,	0x72f654b1,	0x3c84c379,	0x3aa0d08c,
	.word	0x3ff059b0,	0xd3158574,	0x3c8d73e2,	0xa475b465,
	.word	0x3ff0650a,	0x0e3c1f89,	0xbc95cb7b,	0x5799c397,
	.word	0x3ff0706b,	0x29ddf6de,	0xbc8c91df,	0xe2b13c27,
	.word	0x3ff07bd4,	0x2b72a836,	0x3c832334,	0x54458700,
	.word	0x3ff08745,	0x18759bc8,	0x3c6186be,	0x4bb284ff,
	.word	0x3ff092bd,	0xf66607e0,	0xbc968063,	0x800a3fd1,
	.word	0x3ff09e3e,	0xcac6f383,	0x3c914878,	0x18316136,
	.word	0x3ff0a9c7,	0x9b1f3919,	0x3c85d16c,	0x873d1d38,
	.word	0x3ff0b558,	0x6cf9890f,	0x3c98a62e,	0x4adc610b,
	.word	0x3ff0c0f1,	0x45e46c85,	0x3c94f989,	0x06d21cef,
	.word	0x3ff0cc92,	0x2b7247f7,	0x3c901edc,	0x16e24f71,
	.word	0x3ff0d83b,	0x23395dec,	0xbc9bc14d,	0xe43f316a,
	.word	0x3ff0e3ec,	0x32d3d1a2,	0x3c403a17,	0x27c57b52,
	.word	0x3ff0efa5,	0x5fdfa9c5,	0xbc949db9,	0xbc54021b,
	.word	0x3ff0fb66,	0xaffed31b,	0xbc6b9bed,	0xc44ebd7b,
	.word	0x3ff10730,	0x28d7233e,	0x3c8d46eb,	0x1692fdd5,
	.word	0x3ff11301,	0xd0125b51,	0xbc96c510,	0x39449b3a,
	.word	0x3ff11edb,	0xab5e2ab6,	0xbc9ca454,	0xf703fb72,
	.word	0x3ff12abd,	0xc06c31cc,	0xbc51b514,	0xb36ca5c7,
	.word	0x3ff136a8,	0x14f204ab,	0xbc67108f,	0xba48dcf0,
	.word	0x3ff1429a,	0xaea92de0,	0xbc932fbf,	0x9af1369e,
	.word	0x3ff14e95,	0x934f312e,	0xbc8b91e8,	0x39bf44ab,
	.word	0x3ff15a98,	0xc8a58e51,	0x3c82406a,	0xb9eeab0a,
	.word	0x3ff166a4,	0x5471c3c2,	0x3c58f23b,	0x82ea1a32,
	.word	0x3ff172b8,	0x3c7d517b,	0xbc819041,	0xb9d78a76,
	.word	0x3ff17ed4,	0x8695bbc0,	0x3c709e3f,	0xe2ac5a64,
	.word	0x3ff18af9,	0x388c8dea,	0xbc911023,	0xd1970f6c,
	.word	0x3ff19726,	0x58375d2f,	0x3c94aadd,	0x85f17e08,
	.word	0x3ff1a35b,	0xeb6fcb75,	0x3c8e5b4c,	0x7b4968e4,
	.word	0x3ff1af99,	0xf8138a1c,	0x3c97bf85,	0xa4b69280,
	.word	0x3ff1bbe0,	0x84045cd4,	0xbc995386,	0x352ef607,
	.word	0x3ff1c82f,	0x95281c6b,	0x3c900977,	0x8010f8c9,
	.word	0x3ff1d487,	0x3168b9aa,	0x3c9e016e,	0x00a2643c,
	.word	0x3ff1e0e7,	0x5eb44027,	0xbc96fdd8,	0x088cb6de,
	.word	0x3ff1ed50,	0x22fcd91d,	0xbc91df98,	0x027bb78c,
	.word	0x3ff1f9c1,	0x8438ce4d,	0xbc9bf524,	0xa097af5c,
	.word	0x3ff2063b,	0x88628cd6,	0x3c8dc775,	0x814a8495,
	.word	0x3ff212be,	0x3578a819,	0x3c93592d,	0x2cfcaac9,
	.word	0x3ff21f49,	0x917ddc96,	0x3c82a97e,	0x9494a5ee,
	.word	0x3ff22bdd,	0xa27912d1,	0x3c8d34fb,	0x5577d69f,
	.word	0x3ff2387a,	0x6e756238,	0x3c99b07e,	0xb6c70573,
	.word	0x3ff2451f,	0xfb82140a,	0x3c8acfcc,	0x911ca996,
	.word	0x3ff251ce,	0x4fb2a63f,	0x3c8ac155,	0xbef4f4a4,
	.word	0x3ff25e85,	0x711ece75,	0x3c93e1a2,	0x4ac31b2c,
	.word	0x3ff26b45,	0x65e27cdd,	0x3c82bd33,	0x9940e9d9,
	.word	0x3ff2780e,	0x341ddf29,	0x3c9e067c,	0x05f9e76c,
	.word	0x3ff284df,	0xe1f56381,	0xbc9a4c3a,	0x8c3f0d7e,
	.word	0x3ff291ba,	0x7591bb70,	0xbc82cc72,	0x28401cbd,
	.word	0x3ff29e9d,	0xf51fdee1,	0x3c8612e8,	0xafad1255,
	.word	0x3ff2ab8a,	0x66d10f13,	0xbc995743,	0x191690a7,
	.word	0x3ff2b87f,	0xd0dad990,	0xbc410adc,	0xd6381aa4,
	.word	0x3ff2c57e,	0x39771b2f,	0xbc950145,	0xa6eb5124,
	.word	0x3ff2d285,	0xa6e4030b,	0x3c900247,	0x54db41d5,
	.word	0x3ff2df96,	0x1f641589,	0x3c9d16cf,	0xfbbce198,
	.word	0x3ff2ecaf,	0xa93e2f56,	0x3c71ca0f,	0x45d52383,
	.word	0x3ff2f9d2,	0x4abd886b,	0xbc653c55,	0x532bda93,
	.word	0x3ff306fe,	0x0a31b715,	0x3c86f46a,	0xd23182e4,
	.word	0x3ff31432,	0xedeeb2fd,	0x3c8959a3,	0xf3f3fcd1,
	.word	0x3ff32170,	0xfc4cd831,	0x3c8a9ce7,	0x8e18047c,
	.word	0x3ff32eb8,	0x3ba8ea32,	0xbc9c45e8,	0x3cb4f318,
	.word	0x3ff33c08,	0xb26416ff,	0x3c932721,	0x843659a6,
	.word	0x3ff34962,	0x66e3fa2d,	0xbc835a75,	0x930881a4,
	.word	0x3ff356c5,	0x5f929ff1,	0xbc8b5cee,	0x5c4e4628,
	.word	0x3ff36431,	0xa2de883b,	0xbc8c3144,	0xa06cb85e,
	.word	0x3ff371a7,	0x373aa9cb,	0xbc963aea,	0xbf42eae2,
	.word	0x3ff37f26,	0x231e754a,	0xbc99f5ca,	0x9eceb23c,
	.word	0x3ff38cae,	0x6d05d866,	0xbc9e958d,	0x3c9904bd,
	.word	0x3ff39a40,	0x1b7140ef,	0xbc99a9a5,	0xfc8e2934,
	.word	0x3ff3a7db,	0x34e59ff7,	0xbc75e436,	0xd661f5e3,
	.word	0x3ff3b57f,	0xbfec6cf4,	0x3c954c66,	0xe26fff18,
	.word	0x3ff3c32d,	0xc313a8e5,	0xbc9efff8,	0x375d29c3,
	.word	0x3ff3d0e5,	0x44ede173,	0x3c7fe8d0,	0x8c284c71,
	.word	0x3ff3dea6,	0x4c123422,	0x3c8ada09,	0x11f09ebc,
	.word	0x3ff3ec70,	0xdf1c5175,	0xbc8af663,	0x7b8c9bca,
	.word	0x3ff3fa45,	0x04ac801c,	0xbc97d023,	0xf956f9f3,
	.word	0x3ff40822,	0xc367a024,	0x3c8bddf8,	0xb6f4d048,
	.word	0x3ff4160a,	0x21f72e2a,	0xbc5ef369,	0x1c309278,
	.word	0x3ff423fb,	0x2709468a,	0xbc98462d,	0xc0b314dd,
	.word	0x3ff431f5,	0xd950a897,	0xbc81c7dd,	0xe35f7999,
	.word	0x3ff43ffa,	0x3f84b9d4,	0x3c8880be,	0x9704c003,
	.word	0x3ff44e08,	0x6061892d,	0x3c489b7a,	0x04ef80d0,
	.word	0x3ff45c20,	0x42a7d232,	0xbc686419,	0x82fb1f8e,
	.word	0x3ff46a41,	0xed1d0057,	0x3c9c944b,	0xd1648a76,
	.word	0x3ff4786d,	0x668b3237,	0xbc9c20f0,	0xed445733,
	.word	0x3ff486a2,	0xb5c13cd0,	0x3c73c1a3,	0xb69062f0,
	.word	0x3ff494e1,	0xe192aed2,	0xbc83b289,	0x5e499ea0,
	.word	0x3ff4a32a,	0xf0d7d3de,	0x3c99cb62,	0xf3d1be56,
	.word	0x3ff4b17d,	0xea6db7d7,	0xbc8125b8,	0x7f2897f0,
	.word	0x3ff4bfda,	0xd5362a27,	0x3c7d4397,	0xafec42e2,
	.word	0x3ff4ce41,	0xb817c114,	0x3c905e29,	0x690abd5d,
	.word	0x3ff4dcb2,	0x99fddd0d,	0x3c98ecdb,	0xbc6a7833,
	.word	0x3ff4eb2d,	0x81d8abff,	0xbc95257d,	0x2e5d7a52,
	.word	0x3ff4f9b2,	0x769d2ca7,	0xbc94b309,	0xd25957e3,
	.word	0x3ff50841,	0x7f4531ee,	0x3c7a249b,	0x49b7465f,
	.word	0x3ff516da,	0xa2cf6642,	0xbc8f7685,	0x69bd93ef,
	.word	0x3ff5257d,	0xe83f4eef,	0xbc7c998d,	0x43efef71,
	.word	0x3ff5342b,	0x569d4f82,	0xbc807abe,	0x1db13cad,
	.word	0x3ff542e2,	0xf4f6ad27,	0x3c87926d,	0x192d5f7e,
	.word	0x3ff551a4,	0xca5d920f,	0xbc8d689c,	0xefede59b,
	.word	0x3ff56070,	0xdde910d2,	0xbc90fb6e,	0x168eebf0,
	.word	0x3ff56f47,	0x36b527da,	0x3c99bb2c,	0x011d93ad,
	.word	0x3ff57e27,	0xdbe2c4cf,	0xbc90b98c,	0x8a57b9c4,
	.word	0x3ff58d12,	0xd497c7fd,	0x3c8295e1,	0x5b9a1de8,
	.word	0x3ff59c08,	0x27ff07cc,	0xbc97e2ce,	0xe467e60f,
	.word	0x3ff5ab07,	0xdd485429,	0x3c96324c,	0x054647ad,
	.word	0x3ff5ba11,	0xfba87a03,	0xbc9b77a1,	0x4c233e1a,
	.word	0x3ff5c926,	0x8a5946b7,	0x3c3c4b1b,	0x816986a2,
	.word	0x3ff5d845,	0x90998b93,	0xbc9cd6a7,	0xa8b45643,
	.word	0x3ff5e76f,	0x15ad2148,	0x3c9ba6f9,	0x3080e65e,
	.word	0x3ff5f6a3,	0x20dceb71,	0xbc89eadd,	0xe3cdcf92,
	.word	0x3ff605e1,	0xb976dc09,	0xbc93e242,	0x9b56de47,
	.word	0x3ff6152a,	0xe6cdf6f4,	0x3c9e4b3e,	0x4ab84c27,
	.word	0x3ff6247e,	0xb03a5585,	0xbc9383c1,	0x7e40b497,
	.word	0x3ff633dd,	0x1d1929fd,	0x3c984710,	0xbeb964e5,
	.word	0x3ff64346,	0x34ccc320,	0xbc8c483c,	0x759d8933,
	.word	0x3ff652b9,	0xfebc8fb7,	0xbc9ae3d5,	0xc9a73e09,
	.word	0x3ff66238,	0x82552225,	0xbc9bb609,	0x87591c34,
	.word	0x3ff671c1,	0xc70833f6,	0xbc8e8732,	0x586c6134,
	.word	0x3ff68155,	0xd44ca973,	0x3c6038ae,	0x44f73e65,
	.word	0x3ff690f4,	0xb19e9538,	0x3c8804bd,	0x9aeb445d,
	.word	0x3ff6a09e,	0x667f3bcd,	0xbc9bdd34,	0x13b26456,
	.word	0x3ff6b052,	0xfa75173e,	0x3c7a38f5,	0x2c9a9d0e,
	.word	0x3ff6c012,	0x750bdabf,	0xbc728956,	0x67ff0b0d,
	.word	0x3ff6cfdc,	0xddd47645,	0x3c9c7aa9,	0xb6f17309,
	.word	0x3ff6dfb2,	0x3c651a2f,	0xbc6bbe3a,	0x683c88ab,
	.word	0x3ff6ef92,	0x98593ae5,	0xbc90b974,	0x9e1ac8b2,
	.word	0x3ff6ff7d,	0xf9519484,	0xbc883c0f,	0x25860ef6,
	.word	0x3ff70f74,	0x66f42e87,	0x3c59d644,	0xd45aa65f,
	.word	0x3ff71f75,	0xe8ec5f74,	0xbc816e47,	0x86887a99,
	.word	0x3ff72f82,	0x86ead08a,	0xbc920aa0,	0x2cd62c72,
	.word	0x3ff73f9a,	0x48a58174,	0xbc90a8d9,	0x6c65d53c,
	.word	0x3ff74fbd,	0x35d7cbfd,	0x3c9047fd,	0x618a6e1c,
	.word	0x3ff75feb,	0x564267c9,	0xbc902459,	0x57316dd3,
	.word	0x3ff77024,	0xb1ab6e09,	0x3c9b7877,	0x169147f8,
	.word	0x3ff78069,	0x4fde5d3f,	0x3c9866b8,	0x0a02162d,
	.word	0x3ff790b9,	0x38ac1cf6,	0x3c9349a8,	0x62aadd3e,
	.word	0x3ff7a114,	0x73eb0187,	0xbc841577,	0xee04992f,
	.word	0x3ff7b17b,	0x0976cfdb,	0xbc9bebb5,	0x8468dc88,
	.word	0x3ff7c1ed,	0x0130c132,	0x3c9f124c,	0xd1164dd6,
	.word	0x3ff7d26a,	0x62ff86f0,	0x3c91bddb,	0xfb72b8b4,
	.word	0x3ff7e2f3,	0x36cf4e62,	0x3c705d02,	0xba15797e,
	.word	0x3ff7f387,	0x8491c491,	0xbc807f11,	0xcf9311ae,
	.word	0x3ff80427,	0x543e1a12,	0xbc927c86,	0x626d972b,
	.word	0x3ff814d2,	0xadd106d9,	0x3c946437,	0x0d151d4d,
	.word	0x3ff82589,	0x994cce13,	0xbc9d4c1d,	0xd41532d8,
	.word	0x3ff8364c,	0x1eb941f7,	0x3c999b9a,	0x31df2bd5,
	.word	0x3ff8471a,	0x4623c7ad,	0xbc88d684,	0xa341cdfb,
	.word	0x3ff857f4,	0x179f5b21,	0xbc5ba748,	0xf8b216d0,
	.word	0x3ff868d9,	0x9b4492ed,	0xbc9fc6f8,	0x9bd4f6ba,
	.word	0x3ff879ca,	0xd931a436,	0x3c85d2d7,	0xd2db47bd,
	.word	0x3ff88ac7,	0xd98a6699,	0x3c9994c2,	0xf37cb53a,
	.word	0x3ff89bd0,	0xa478580f,	0x3c9d5395,	0x4475202a,
	.word	0x3ff8ace5,	0x422aa0db,	0x3c96e9f1,	0x56864b27,
	.word	0x3ff8be05,	0xbad61778,	0x3c9ecb5e,	0xfc43446e,
	.word	0x3ff8cf32,	0x16b5448c,	0xbc70d55e,	0x32e9e3aa,
	.word	0x3ff8e06a,	0x5e0866d9,	0xbc97114a,	0x6fc9b2e6,
	.word	0x3ff8f1ae,	0x99157736,	0x3c85cc13,	0xa2e3976c,
	.word	0x3ff902fe,	0xd0282c8a,	0x3c9592ca,	0x85fe3fd2,
	.word	0x3ff9145b,	0x0b91ffc6,	0xbc9dd679,	0x2e582524,
	.word	0x3ff925c3,	0x53aa2fe2,	0xbc83455f,	0xa639db7f,
	.word	0x3ff93737,	0xb0cdc5e5,	0xbc675fc7,	0x81b57ebc,
	.word	0x3ff948b8,	0x2b5f98e5,	0xbc8dc3d6,	0x797d2d99,
	.word	0x3ff95a44,	0xcbc8520f,	0xbc764b7c,	0x96a5f039,
	.word	0x3ff96bdd,	0x9a7670b3,	0xbc5ba596,	0x7f19c896,
	.word	0x3ff97d82,	0x9fde4e50,	0xbc9d185b,	0x7c1b85d1,
	.word	0x3ff98f33,	0xe47a22a2,	0x3c7cabda,	0xa24c78ec,
	.word	0x3ff9a0f1,	0x70ca07ba,	0xbc9173bd,	0x91cee632,
	.word	0x3ff9b2bb,	0x4d53fe0d,	0xbc9dd84e,	0x4df6d518,
	.word	0x3ff9c491,	0x82a3f090,	0x3c7c7c46,	0xb071f2be,
	.word	0x3ff9d674,	0x194bb8d5,	0xbc9516be,	0xa3dd8233,
	.word	0x3ff9e863,	0x19e32323,	0x3c7824ca,	0x78e64c6e,
	.word	0x3ff9fa5e,	0x8d07f29e,	0xbc84a9ce,	0xaaf1face,
	.word	0x3ffa0c66,	0x7b5de565,	0xbc935949,	0x5d1cd533,
	.word	0x3ffa1e7a,	0xed8eb8bb,	0x3c9c6618,	0xee8be70e,
	.word	0x3ffa309b,	0xec4a2d33,	0x3c96305c,	0x7ddc36ab,
	.word	0x3ffa42c9,	0x80460ad8,	0xbc9aa780,	0x589fb120,
	.word	0x3ffa5503,	0xb23e255d,	0xbc9d2f6e,	0xdb8d41e1,
	.word	0x3ffa674a,	0x8af46052,	0x3c650f56,	0x30670366,
	.word	0x3ffa799e,	0x1330b358,	0x3c9bcb7e,	0xcac563c7,
	.word	0x3ffa8bfe,	0x53c12e59,	0xbc94f867,	0xb2ba15a9,
	.word	0x3ffa9e6b,	0x5579fdbf,	0x3c90fac9,	0x0ef7fd31,
	.word	0x3ffab0e5,	0x21356eba,	0x3c889c31,	0xdae94545,
	.word	0x3ffac36b,	0xbfd3f37a,	0xbc8f9234,	0xcae76cd0,
	.word	0x3ffad5ff,	0x3a3c2774,	0x3c97ef3b,	0xb6b1b8e5,
	.word	0x3ffae89f,	0x995ad3ad,	0x3c97a1cd,	0x345dcc81,
	.word	0x3ffafb4c,	0xe622f2ff,	0xbc94b2fc,	0x0f315ecd,
	.word	0x3ffb0e07,	0x298db666,	0xbc9bdef5,	0x4c80e425,
	.word	0x3ffb20ce,	0x6c9a8952,	0x3c94dd02,	0x4a0756cc,
	.word	0x3ffb33a2,	0xb84f15fb,	0xbc62805e,	0x3084d708,
	.word	0x3ffb4684,	0x15b749b1,	0xbc7f763d,	0xe9df7c90,
	.word	0x3ffb5972,	0x8de5593a,	0xbc9c71df,	0xbbba6de3,
	.word	0x3ffb6c6e,	0x29f1c52a,	0x3c92a8f3,	0x52883f6e,
	.word	0x3ffb7f76,	0xf2fb5e47,	0xbc75584f,	0x7e54ac3b,
	.word	0x3ffb928c,	0xf22749e4,	0xbc9b7216,	0x54cb65c6,
	.word	0x3ffba5b0,	0x30a1064a,	0xbc9efcd3,	0x0e54292e,
	.word	0x3ffbb8e0,	0xb79a6f1f,	0xbc3f52d1,	0xc9696205,
	.word	0x3ffbcc1e,	0x904bc1d2,	0x3c823dd0,	0x7a2d9e84,
	.word	0x3ffbdf69,	0xc3f3a207,	0xbc3c2623,	0x60ea5b52,
	.word	0x3ffbf2c2,	0x5bd71e09,	0xbc9efdca,	0x3f6b9c73,
	.word	0x3ffc0628,	0x6141b33d,	0xbc8d8a5a,	0xa1fbca34,
	.word	0x3ffc199b,	0xdd85529c,	0x3c811065,	0x895048dd,
	.word	0x3ffc2d1c,	0xd9fa652c,	0xbc96e516,	0x17c8a5d7,
	.word	0x3ffc40ab,	0x5fffd07a,	0x3c9b4537,	0xe083c60a,
	.word	0x3ffc5447,	0x78fafb22,	0x3c912f07,	0x2493b5af,
	.word	0x3ffc67f1,	0x2e57d14b,	0x3c92884d,	0xff483cad,
	.word	0x3ffc7ba8,	0x8988c933,	0xbc8e76bb,	0xbe255559,
	.word	0x3ffc8f6d,	0x9406e7b5,	0x3c71acbc,	0x48805c44,
	.word	0x3ffca340,	0x5751c4db,	0xbc87f2be,	0xd10d08f5,
	.word	0x3ffcb720,	0xdcef9069,	0x3c7503cb,	0xd1e949db,
	.word	0x3ffccb0f,	0x2e6d1675,	0xbc7d220f,	0x86009092,
	.word	0x3ffcdf0b,	0x555dc3fa,	0xbc8dd83b,	0x53829d72,
	.word	0x3ffcf315,	0x5b5bab74,	0xbc9a08e9,	0xb86dff57,
	.word	0x3ffd072d,	0x4a07897c,	0xbc9cbc37,	0x43797a9c,
	.word	0x3ffd1b53,	0x2b08c968,	0x3c955636,	0x219a36ee,
	.word	0x3ffd2f87,	0x080d89f2,	0xbc9d487b,	0x719d8578,
	.word	0x3ffd43c8,	0xeacaa1d6,	0x3c93db53,	0xbf5a1614,
	.word	0x3ffd5818,	0xdcfba487,	0x3c82ed02,	0xd75b3707,
	.word	0x3ffd6c76,	0xe862e6d3,	0x3c5fe87a,	0x4a8165a0,
	.word	0x3ffd80e3,	0x16c98398,	0xbc911ec1,	0x8beddfe8,
	.word	0x3ffd955d,	0x71ff6075,	0x3c9a052d,	0xbb9af6be,
	.word	0x3ffda9e6,	0x03db3285,	0x3c9c2300,	0x696db532,
	.word	0x3ffdbe7c,	0xd63a8315,	0xbc9b76f1,	0x926b8be4,
	.word	0x3ffdd321,	0xf301b460,	0x3c92da57,	0x78f018c3,
	.word	0x3ffde7d5,	0x641c0658,	0xbc9ca552,	0x8e79ba8f,
	.word	0x3ffdfc97,	0x337b9b5f,	0xbc91a5cd,	0x4f184b5c,
	.word	0x3ffe1167,	0x6b197d17,	0xbc72b529,	0xbd5c7f44,
	.word	0x3ffe2646,	0x14f5a129,	0xbc97b627,	0x817a1496,
	.word	0x3ffe3b33,	0x3b16ee12,	0xbc99f4a4,	0x31fdc68b,
	.word	0x3ffe502e,	0xe78b3ff6,	0x3c839e89,	0x80a9cc8f,
	.word	0x3ffe6539,	0x24676d76,	0xbc863ff8,	0x7522b735,
	.word	0x3ffe7a51,	0xfbc74c83,	0x3c92d522,	0xca0c8de2,
	.word	0x3ffe8f79,	0x77cdb740,	0xbc910894,	0x80b054b1,
	.word	0x3ffea4af,	0xa2a490da,	0xbc9e9c23,	0x179c2893,
	.word	0x3ffeb9f4,	0x867cca6e,	0x3c94832f,	0x2293e4f2,
	.word	0x3ffecf48,	0x2d8e67f1,	0xbc9c93f3,	0xb411ad8c,
	.word	0x3ffee4aa,	0xa2188510,	0x3c91c68d,	0xa487568d,
	.word	0x3ffefa1b,	0xee615a27,	0x3c9dc7f4,	0x86a4b6b0,
	.word	0x3fff0f9c,	0x1cb6412a,	0xbc932200,	0x65181d45,
	.word	0x3fff252b,	0x376bba97,	0x3c93a1a5,	0xbf0d8e43,
	.word	0x3fff3ac9,	0x48dd7274,	0xbc795a5a,	0x3ed837de,
	.word	0x3fff5076,	0x5b6e4540,	0x3c99d3e1,	0x2dd8a18b,
	.word	0x3fff6632,	0x798844f8,	0x3c9fa37b,	0x3539343e,
	.word	0x3fff7bfd,	0xad9cbe14,	0xbc9dbb12,	0xd006350a,
	.word	0x3fff91d8,	0x02243c89,	0xbc612ea8,	0xa779f689,
	.word	0x3fffa7c1,	0x819e90d8,	0x3c874853,	0xf3a5931e,
	.word	0x3fffbdba,	0x3692d514,	0xbc796773,	0x15098eb6,
	.word	0x3fffd3c2,	0x2b8f71f1,	0x3c62eb74,	0x966579e7,
	.word	0x3fffe9d9,	0x6b2a23d9,	0x3c74a603,	0x7442fde3,
!
	.word	0x3c900000,	0x00000000,	! 2**(-54) = 5.551115123125782702e-17
	.word	0x3ff00000,	0x00000000,	! DONE = 1.0
	.word	0x43300000,	0x00000000,	! DVAIN52 = 2**52 = 4.503599627370496e15
	.word	0xffffffff,	0x00000000,	! MHI32   = 0xffffffff00000000
	.word	0x4062776d,	0x8ce329bd,	! KA5     = (5.77078604860893737986e-01*256)
	.word	0x406ec709,	0xdc39fc99,	! KA3     = (9.61796693925765549423e-01*256)
	.word	0x40871547,	0x652b82fe,	! KA1     = (2.885390081777926774e+00*256)
	.word	0x41100000,	0x00000000,	! HTHRESH = 262144.0
	.word	0xc110cc00,	0x00000000,	! LTHRESH = -275200.0
	.word	0x3d83b2ab,	0xc07c93d0,	! KB4     = 2.23939573811855104311e-12
	.word	0x000fffff,	0xffffffff,	! MMANT
	.word	0x00000800,	0x00000000,	! MROUND
	.word	0xfffff000,	0x00000000,	! MHI20

! local storage indices
#define	tmp0_lo		STACK_BIAS-4
#define	tmp0_hi		STACK_BIAS-8
#define	tmp1_lo		STACK_BIAS-12
#define	tmp1_hi		STACK_BIAS-16
#define	tmp2_lo		STACK_BIAS-20
#define	tmp2_hi		STACK_BIAS-24
#define	tmp3		STACK_BIAS-28
#define	tmp4		STACK_BIAS-32
#define	ind_buf		STACK_BIAS-48
#define	tmp_counter	STACK_BIAS-56
#define	tmp_px		STACK_BIAS-64
#define	tmp_py		STACK_BIAS-72
#define	tmp_mant	STACK_BIAS-80
#define	tmp5		STACK_BIAS-88
#define	tmp6		STACK_BIAS-96

! sizeof temp storage - must be a multiple of 16 for V9
#define	tmps		96

#define	LOGTBL		%g5
#define	EXPTBL		%g1
#define	EXPTBL_P8	%l4

#define	MASK_0x7fffffff	%o4
#define	MASK_0x000fffff	%o3
#define	MASK_0x3ff00000	%o1

#define	counter		%i0
#define	px		%i1
#define	stridex		%l5
#define	py		%i3
#define	stridey		%l6
#define	pz		%i5
#define	stridez		%l7

#define	HTHRESH		%f0
#define	LTHRESH		%f2

#define	MHI32		%f38
#define	KA1_LO		%f40
#define	KA1_HI		%f40

#define	KB1		%f42
#define	KB2		%f42
#define	KB3		%f42
#define	KB4		%f44
#define	KB5		%f42

#define	KA1		%f46
#define	KA3		%f28
#define	KA5		%f50

#define	DZERO		%f24
#define	DZERO_HI	%f24
#define	DZERO_LO	%f25
#define	DONE		%f18
#define	DONE_HI		%f18
#define	DONE_LO		%f19

#define	XKB1		%f42
#define	XKB2		%f40
#define	XKB3		%f32
#define	XKB4		%f36
#define	XKB5		%f34

#define	s_h		%f46
#define	yr		%f30

#define	ind_TINY	64
#define	ind_HUGE	56
#define	ind_LO		48
#define	ind_HI		40
#define	ind_KB5		32
#define	ind_KB3		24
#define	ind_KB2		16
#define	ind_KB1		8

!--------------------------------------------------------------------
!		!!!!!	vpow algorithm	!!!!!
!
!  hx = ((unsigned*)px)[0];
!  lx = ((unsigned*)px)[1];
!  hy = ((unsigned*)py)[0];
!  ly = ((unsigned*)py)[1];
!  sx = hx >> 31;
!  sy = hy >> 31;
!  hx &= 0x7fffffff;
!  hy &= 0x7fffffff;
!  y0 = *px;
!
!  if (hy < 0x3bf00000) {						/* |Y| < 2^(-64) */
!    if ((hy | ly) == 0) {						/* pow(X,0)      */
!      *pz = DONE;
!      goto next;
!    }
!    if (hx > 0x7ff00000 || (hx == 0x7ff00000 && lx != 0)) {		/* |X| = Nan     */
!      *pz = y0 * y0;
!      goto next;
!    }
!    else if ((hx | lx) == 0 || (hx == 0x7ff00000 && lx == 0)) {	/* X = 0 or Inf  */
!      ((int*)pz)[0] = hx;
!      ((int*)pz)[1] = lx;
!      if (sy) *pz = DONE / *pz;
!      goto next;
!    }
!    else *pz = (sx) ? DZERO / DZERO : DONE;
!      goto next;
!  }
!  yisint = 0; /* Y - non-integer */
!  expy = hy >> 20; /* Y exponent */
!
!  if (hx >= 0x7ff00000 || expy >= 0x43e) {			/* X=Inf,Nan or |Y|>2^63,Inf,Nan */
!    if (hx > 0x7ff00000 || (hx == 0x7ff00000 && lx != 0) ||
!        hy > 0x7ff00000 || (hy == 0x7ff00000 && ly != 0))
!      *pz = y0 * *py; /* |X| or |Y| = Nan */
!      goto next;
!    if (hy == 0x7ff00000 && (ly == 0)) { /* |Y| = Inf */
!      if (hx == 0x3ff00000 && (lx == 0))
!        *pz = *py - *py; /* +-1 ** +-Inf */
!      else if ((hx < 0x3ff00000) != sy)
!        *pz = DZERO;
!      else {
!        ((int*)pz)[0] = hy;
!        ((int*)pz)[1] = ly;
!      }
!      goto next;
!    }
!    if (expy < 0x43e) {						/* |Y| < 2^63   */
!      if (sx) {							/* X = -Inf     */
!        if (expy >= 0x434)						/* |Y| >= 2^53  */
!          yisint##I = 2; 						/* Y - even     */
!        else {
!          if (expy >= 0x3ff) {						/* |Y| >= 1     */
!            if (expy > (20 + 0x3ff)) {
!              i0 = ly >> (52 - (expy - 0x3ff));
!              if ((i0 << (52 - (expy - 0x3ff))) == ly) yisint = 2 - (i0 & 1);
!            }
!            else if (ly == 0) {
!              i0 = hy >> (20 - (expy - 0x3ff));
!              if ((i0 << (20 - (expy - 0x3ff))) == hy) yisint = 2 - (i0 & 1);
!            }
!          }
!        }
!      }
!      if (sy) hx = lx = 0;
!      hx += yisint << 31;
!      ((int*)pz)[0] = hx;
!      ((int*)pz)[1] = lx;
!      goto next;
!    }
!    else {								/* |Y| >= 2^63     */
!      if (lx == 0 &&							/* |X| = 0, 1, Inf */
!         (hx == 0 || hx == 0x3ff00000 || hx == 0x7ff00000)) {
!        ((int*)pz)[0] = hx;
!        ((int*)pz)[1] = lx;
!        if (sy) *pz = DONE / *pz;
!      }
!      else {
!        y0 = ((hx < 0x3ff00000) != sy) ? _TINY : _HUGE;
!        *pz = y0 * y0;
!      }
!      goto next;
!    }
!  }
!  if (sx || (hx | lx) == 0) {						/* X <= 0      */
!    if (expy >= 0x434)							/* |Y| >= 2^53 */
!      yisint = 2;							/* Y - even    */
!    else {
!      if (expy >= 0x3ff) {						/* |Y| >= 1    */
!        if (expy > (20 + 0x3ff)) {
!          i0 = ly >> (52 - (expy - 0x3ff));
!          if ((i0 << (52 - (expy - 0x3ff))) == ly) yisint = 2 - (i0 & 1);
!        }
!        else if (ly == 0) {
!          i0 = hy >> (20 - (expy - 0x3ff));
!          if ((i0 << (20 - (expy - 0x3ff))) == hy) yisint = 2 - (i0 & 1);
!        }
!      }
!    }
!    if ((hx | lx) == 0) {						/* X == 0  */
!      y0 = DZERO;
!      if (sy) y0 = DONE / y0;
!      if (sx & yisint) y0 = -y0;
!      *pz = y0;
!      goto next;
!    }
!    if (yisint == 0) {							/* pow(neg,non-integer) */
!      *pz = DZERO / DZERO;						/* NaN */
!      goto next;
!    }
!  }
!
!  *((int*)&x + 1) = ((unsigned*)px)[1];
!  *((int*)&ax + 1) = 0;
!  exp = hx;
!  hx &= 0xfffff;
!  hx |= 0x3ff00000;
!  *(int*)&x = hx;
!  hx += 0x800;
!  hx &= 0xfffff000;
!  *(int*)&ax = hx;
!  if (exp <= 0xfffff) {
!    y0 = vis_fand(x, MMANT);
!    ax = (double) ((long long *) & y0)[0];
!    x = vis_fand(ax, MMANT);
!    x = vis_for(x, DONE);
!    exp = ((unsigned int*) & ax)[0];
!    exp -= (1023 + 51) << 20;
!    hx = exp & 0xfffff;
!    hx |= 0x3ff00000;
!    hx += 0x800;
!    *(int*)&ax = hx;
!  }
!  exp = (exp >> 20);
!  exp = exp - 2046;
!  ux = x + ax;
!  yd = DONE / ux;
!  u = x - ax;
!  s = u * yd;
!  ux = vis_fand(ux, MHI32);
!  y = s * s;
!  s_h = vis_fand(s, MHI32);
!  dtmp8 = KA5 * y;
!  dtmp8 = dtmp8 + KA3;
!  dtmp8 = dtmp8 * y;
!  s = dtmp8 * s;
!  dtmp0 = (ux - ax);
!  s_l = (x - dtmp0);
!  dtmp0 = s_h * ux;
!  dtmp1 = s_h * s_l;
!  s_l = u - dtmp0;
!  s_l -= dtmp1;
!  dtmp0 = KA1 * yd;
!  s_l = dtmp0 * s_l;
!  i = (hx >> 8);
!  i = i & 0xff0;
!  itmp0 = (hx >> 20);
!  exp += itmp0;
!  yd = KA1_HI * s_h;
!  y = *(double *)((char*)__mt_constlog2 + i);
!  itmp0 = exp << 8;
!  y += (double)itmp0;
!  m_h = y + yd;
!  dtmp2 = m_h - y;
!  dtmp2 -= yd;
!  dtmp2 -= s_l;
!  y = s - dtmp2;
!  dtmp0 = *(double *)((char*)__mt_constlog2 + i + 8);
!  dtmp1 = KA1_LO * s_h;
!  dtmp0 += dtmp1;
!  y += dtmp0;
!  dtmp0 = y + m_h;
!  s_h = vis_fand(dtmp0, MHI32);
!  dtmp0 = (s_h - m_h);
!  y = y - dtmp0;
!  yd = *py;
!  s = vis_fand(yd, MHI32);
!  dtmp0 = (yd - s);
!  dtmp1 = yd * y;
!  dtmp0 *= s_h;
!  yd = dtmp0 + dtmp1;
!  s = s_h * s;
!  if (s > HTHRESH) {s = HTHRESH; yd = DZERO;}
!  if (s < LTHRESH) {s = LTHRESH; yd = DZERO;}
!  dtmp0 = (s + yd);
!  ind = (int)dtmp0;
!  i = ind & 0xff;
!  i = i << 4;
!  u = (double)(int)dtmp0;
!  ind >>= 8;
!  y = s - u;
!  y = y + yd;
!  u = *(double*)((char*)__mt_constexp2 + i);
!  dtmp0 = KB5 * y;
!  dtmp1 = dtmp0 + KB4;
!  dtmp2 = dtmp1 * y;
!  dtmp3 = dtmp2 + KB3;
!  dtmp4 = dtmp3 * y;
!  dtmp5 = dtmp4 + KB2;
!  dtmp6 = dtmp5 * y;
!  dtmp7 = dtmp6 + KB1;
!  y = dtmp7 * y;
!  eflag = (ind + 1021);
!  eflag = eflag >> 31;
!  gflag = (1022 - ind);
!  gflag = gflag >> 31;
!  dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
!  dtmp1 = u * y;
!  dtmp2 = dtmp0 + dtmp1;
!  u = dtmp2 + u;
!  ind = yisint + ind;
!  itmp0 = 54 & eflag;
!  itmp1 = 52 & gflag;
!  ind = ind + itmp0;
!  ind = ind - itmp1;
!  ind <<= 20;
!  *(int*)&dtmp0 = ind;
!  *((int*)&dtmp0 + 1) = 0;
!  u = vis_fpadd32(u, dtmp0);
!  ind = eflag - gflag;
!  ind += 1;
!  ind *= 8;
!  dtmp1 = (*(double*)((char*)lconst + ind);
!  dtmp1 = u * dtmp1;
!  *pz = dtmp1;
!--------------------------------------------------------------------
!		!!!!!	vpowx algorithm	!!!!! (x > 0 and x != Inf, NaN)
!
!                   /* perform s_h + yr = 256*log2(x) */
!
!  exp = ((unsigned*)px)[0];
!  y0 = px[0];
!  if (exp <= 0xfffff) {
!    y0 = (double) ((long long *) & y0)[0];
!    exp = ((unsigned int*) & y0)[0];
!    exp -= (1023 + 51) << 20;
!  }
!  x = vis_fand(y0, MMANT);
!  x = vis_for(x, DONE);
!  ax = vis_fpadd32(x, MROUND);
!  ax = vis_fand(ax, MHI20);
!  hx = *(int*)&ax;
!  exp = (exp >> 20);
!  exp = exp - 2046;
!  ux = x + ax;
!  yd = DONE / ux;
!  u = x - ax;
!  s = u * yd;
!  ux = vis_fand(ux, MHI32);
!  y = s * s;
!  s_h = vis_fand(s, MHI32);
!  dtmp8 = KA5 * y;
!  dtmp8 = dtmp8 + KA3;
!  dtmp8 = dtmp8 * y;
!  s = dtmp8 * s;
!  dtmp0 = (ux - ax);
!  s_l = (x - dtmp0);
!  dtmp0 = s_h * ux;
!  dtmp1 = s_h * s_l;
!  s_l = u - dtmp0;
!  s_l -= dtmp1;
!  dtmp0 = KA1 * yd;
!  s_l = dtmp0 * s_l;
!  i = (hx >> 8);
!  i = i & 0xff0;
!  itmp0 = (hx >> 20);
!  exp += itmp0;
!  yd = KA1_HI * s_h;
!  y = *(double *)((char*)__mt_constlog2 + i);
!  itmp0 = exp << 8;
!  y += (double)itmp0;
!  m_h = y + yd;
!  dtmp2 = m_h - y;
!  dtmp2 -= yd;
!  dtmp2 -= s_l;
!  y = s - dtmp2;
!  dtmp0 = *(double *)((char*)__mt_constlog2 + i + 8);
!  dtmp1 = KA1_LO * s_h;
!  dtmp0 += dtmp1;
!  y += dtmp0;
!  dtmp0 = y + m_h;
!  s_h = vis_fand(dtmp0, MHI32);
!  dtmp0 = (s_h - m_h);
!  yr = y - dtmp0;
!
!  hy = ((unsigned*)py)[0];
!  ly = ((unsigned*)py)[1];
!  hx = ((unsigned*)px)[0];
!  lx = ((unsigned*)px)[1];
!  sy = hy >> 31;
!  hy &= 0x7fffffff;
!
!  if (hy < 0x3bf00000) {/* |Y| < 2^(-64) */
!    *pz = DONE;
!    goto next;
!  }
!
!  if (hy >= 0x43e00000) {			/* |Y|>2^63,Inf,Nan */
!    if (hy == 0x7ff00000 && (ly == 0)) {	/* |Y| = Inf */
!      if (hx == 0x3ff00000 && (lx == 0))
!        *pz = *py - *py;			/* 1 ** +-Inf */
!      else if ((hx < 0x3ff00000) != sy)
!        *pz = DZERO;
!      else {
!        ((int*)pz)[0] = hy;
!        ((int*)pz)[1] = ly;
!      }
!      goto next;
!    }
!    if (hy >= 0x7ff00000) {
!      *pz = *px + *py;				/* |Y| = Nan */
!      goto next;
!    }
! 						/* |Y| >= 2^63   */
!    if (lx == 0 && (hx == 0x3ff00000)) {	/*  X = 1 */
!      *pz = DONE;
!    }
!    else {
!      y0 = ((hx < 0x3ff00000) != sy) ? _TINY : _HUGE;
!      *pz = y0 * y0;
!    }
!    goto next;
!  }
!
!  yd = *py;
!  s = vis_fand(yd, MHI32);
!  dtmp0 = (yd - s);
!  dtmp1 = yd * yr;
!  dtmp0 *= s_h;
!  yd = dtmp0 + dtmp1;
!  s = s_h * s;
!  if (s > HTHRESH) {s = HTHRESH; yd = DZERO;}
!  if (s < LTHRESH) {s = LTHRESH; yd = DZERO;}
!  dtmp0 = (s + yd);
!  ind = (int)dtmp0;
!  i = ind & 0xff;
!  i = i << 4;
!  u = (double)(int)dtmp0;
!  ind >>= 8;
!  y = s - u;
!  y = y + yd;
!  u = *(double*)((char*)__mt_constexp2 + i);
!  dtmp0 = XKB5 * y;
!  dtmp1 = dtmp0 + XKB4;
!  dtmp2 = dtmp1 * y;
!  dtmp3 = dtmp2 + XKB3;
!  dtmp4 = dtmp3 * y;
!  dtmp5 = dtmp4 + XKB2;
!  dtmp6 = dtmp5 * y;
!  dtmp7 = dtmp6 + XKB1;
!  y = dtmp7 * y;
!  eflag = (ind + 1021);
!  eflag = eflag >> 31;
!  gflag = (1022 - ind);
!  gflag = gflag >> 31;
!  dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
!  dtmp1 = u * y;
!  dtmp2 = dtmp0 + dtmp1;
!  u = dtmp2 + u;
!  itmp0 = 54 & eflag;
!  itmp1 = 52 & gflag;
!  ind = ind + itmp0;
!  ind = ind - itmp1;
!  ind <<= 20;
!  *(int*)&dtmp0 = ind;
!  *((int*)&dtmp0 + 1) = 0;
!  u = vis_fpadd32(u, dtmp0);
!  ind = eflag - gflag;
!  ind += 1;
!  ind *= 8;
!  dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
!  dtmp1 = u * dtmp1;
!  *pz = dtmp1;
!--------------------------------------------------------------------

	ENTRY(__vpow)
	save	%sp,-SA(MINFRAME)-tmps,%sp
	PIC_SETUP(l7)
	PIC_SET(l7,.CONST_TBL,g5)
	wr	%g0,0x82,%asi			! set %asi for non-faulting loads

	cmp	counter,0
	ble,pn	%icc,.end

#ifdef	__sparcv9
	ldx	[%fp+STACK_BIAS+176],stridez
#else
	ld	[%fp+STACK_BIAS+92],stridez
#endif

	ld	[px],%o0
	add	LOGTBL,4095,EXPTBL
	st	counter,[%fp+tmp_counter]
	add	EXPTBL,65,EXPTBL
	sra	%i2,0,stridex
	stx	px,[%fp+tmp_px]
	add	EXPTBL,4095,%l0
	fzero	DZERO
	stx	py,[%fp+tmp_py]

	cmp	stridex,0
	bne,pt	%icc,.common_case
	add	%l0,1,%l0

	cmp	%o0,0
	ble,pt	%icc,.common_case
	sethi	%hi(0x7f800000),%o1

	cmp	%o0,%o1
	bl,pn	%icc,.stridex_zero
	nop

.common_case:
	sra	stridez,0,stridez
	ldd	[%l0+8],DONE
	ldd	[%l0+24],MHI32
	sra	%i4,0,stridey
	ldd	[%l0+32],KA5
	sethi	%hi(0x7ffffc00),MASK_0x7fffffff
	ldd	[%l0+40],KA3
	sethi	%hi(0xffc00),MASK_0x000fffff
	ldd	[%l0+48],KA1
	sethi	%hi(0x3ff00000),MASK_0x3ff00000
	ldd	[%l0+56],HTHRESH
	sllx	stridex,3,stridex
	add	MASK_0x7fffffff,0x3ff,MASK_0x7fffffff
	ldd	[%l0+64],LTHRESH
	sllx	stridey,3,stridey
	add	MASK_0x000fffff,0x3ff,MASK_0x000fffff
	ldd	[%l0+72],KB4
	sllx	stridez,3,stridez
	st	%g0,[%fp+tmp1_lo]		! *((int*)&ax + 1) = 0;
	sub	%g0,1,%o2
	st	%g0,[%fp+tmp2_lo]		! (Y0_0) *((int*)&dtmp0 + 1) = 0;
	st	MASK_0x000fffff,[%fp+tmp_mant]
	sub	pz,stridez,pz
	st	%o2,[%fp+tmp_mant+4]

.begin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_px],px
	ldx	[%fp+tmp_py],py
	st	%g0,[%fp+tmp_counter]
.begin1:
	subcc	counter,1,counter
	bneg,pn	%icc,.end
	or	%g0,ind_buf,%o7

	lda	[py]%asi,%o2			! (Y0_1) hy = *py;

	and	%o2,MASK_0x7fffffff,%l1		! (Y0_3) hy &= 0x7fffffff;
	lda	[px]%asi,%l0			! (Y0_3) hx = ((unsigned*)px)[0];

	sra	%l1,20,%o0			! (Y0_3) expy = hy >> 20;
	lda	[px+4]%asi,%i2			! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];

	and	MASK_0x000fffff,%l0,%o5		! (Y0_3) hx &= 0xfffff;

	or	MASK_0x3ff00000,%o5,%o5		! (Y0_3) hx |= 0x3ff00000;

	st	%o5,[%fp+tmp0_hi]		! (Y0_3) *(int*)&x = hx;

	add	%o5,2048,%o5			! (Y0_3) hx += 0x800;

	st	%i2,[%fp+tmp0_lo]		! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];
	and	%o5,-4096,%l4			! (Y0_3) hx &= 0xfffff000;

	add	pz,stridez,pz
	st	%l4,[%fp+tmp1_hi]		! (Y0_3) *(int*)&ax = hx;

	and	%l0,MASK_0x7fffffff,%l3		! (Y0_3) hx &= 0x7fffffff;

	sra	%l3,20,%l2			! (Y0_3) exp = (exp >> 20);

	cmp	%o0,959				! (Y0_3) if (expy < 0x3fb);
	bl,pn	%icc,.spec0			! (Y0_3) if (expy < 0x3fb);
	st	%g0,[%fp+%o7]			! (Y0_3) yisint = 0;

	cmp	%o0,1086			! (Y0_3) if (expy >= 0x43e);
	bge,pn	%icc,.spec1			! (Y0_3) if (expy >= 0x43e);
	nop

	cmp	%l2,2047			! (Y0_2) if (exp >= 0x7ff)
	bge,pn	%icc,.spec1			! (Y0_2) if (exp >= 0x7ff)
	nop

	cmp	%l0,MASK_0x000fffff		! (Y0_2) if (hx <= 0xfffff)

	ldd	[%fp+tmp0_hi],%f32		! (Y0_2) *(int*)&x = hx;
	ble,pn	%icc,.update0			! (Y0_2) if (hx <= 0xfffff)
	nop
.cont0:
	sub	%o7,ind_buf,%o7			! stack buffer pointer update
	sub	pz,stridez,pz
	ldd	[%fp+tmp1_hi],%f54		! (Y0_2) *(int*)&ax = hx;

	add	%o7,4,%o7			! stack buffer pointer update
	faddd	%f32,%f54,%f12			! (Y0_2) ux = x + ax;

	and	%o7,15,%o7			! stack buffer pointer update

	add	%o7,ind_buf,%o7			! stack buffer pointer update
	add	px,stridex,px			! px += stridex;

	lda	[px]%asi,%l0			! (Y1_2) hx = ((unsigned*)px)[0];

	lda	[px+4]%asi,%i2			! (Y1_2) *((int*)&x + 1) = ((unsigned*)px)[1];
	and	MASK_0x000fffff,%l0,%i4		! (Y1_2) hx &= 0xfffff;

	st	%g0,[%fp+%o7]			! (Y1_2) yisint = 0;
	or	MASK_0x3ff00000,%i4,%i4		! (Y1_2) hx |= 0x3ff00000;

	st	%i4,[%fp+tmp0_hi]		! (Y1_2) *(int*)&x = hx;
	add	%i4,2048,%i4			! (Y1_2) hx += 0x800;

	st	%i2,[%fp+tmp0_lo]		! (Y1_2) *((int*)&x + 1) = ((unsigned*)px)[1];
	and	%i4,-4096,%i4			! (Y1_2) hx &= 0xfffff000;

	st	%i4,[%fp+tmp1_hi]		! (Y1_2) *(int*)&ax = hx;
	and	%l0,MASK_0x7fffffff,%l2		! (Y1_2) hx &= 0x7fffffff;
	cmp	%l0,MASK_0x000fffff		! (Y1_2) if (hx <= 0xfffff)

	ble,pn	%icc,.update1			! (Y1_2) if (hx <= 0xfffff)
	nop
.cont1:
	sub	%o7,ind_buf,%o7			! stack buffer pointer update

	add	%o7,4,%o7			! stack buffer pointer update
	fdivd	DONE,%f12,%f20			! (Y0_2) yd = DONE / ux;

	and	%o7,15,%o7			! stack buffer pointer update

	sra	%l3,20,%l3			! (Y0_2) exp = (exp >> 20);
	add	%o7,ind_buf,%o7			! stack buffer pointer update
	ldd	[%fp+tmp0_hi],%f8		! (Y1_2) *(int*)&x = hx;

	ldd	[%fp+tmp1_hi],%f14		! (Y1_2) *(int*)&ax = hx;
	sra	%l4,20,%l0			! (Y0_2) itmp0 = (hx >> 20);
	sub	%l3,2046,%o5			! (Y0_2) exp = exp - 2046;

	add	%o5,%l0,%o5			! (Y0_2) exp += itmp0;

	sll	%o5,8,%l0			! (Y0_2) itmp0 = exp << 8;
	st	%l0,[%fp+tmp3]			! (Y0_2) (double)itmp0;
	faddd	%f8,%f14,%f26			! (Y1_2) ux = x + ax;

	fand	%f12,MHI32,%f12			! (Y0_2) ux = vis_fand(ux, MHI32);
	add	px,stridex,px			! px += stridex;

	ldd	[EXPTBL-ind_HI],KA1_HI		! (Y0_2) load KA1_HI;
	fsubd	%f12,%f54,%f10			! (Y0_2) dtmp0 = (ux - ax);

	ld	[%fp+tmp3],%f16			! (Y0_2) (double)itmp0;
	fsubd	%f32,%f54,%f58			! (Y0_2) u = x - ax;

	sra	%l4,8,%l4			! (Y0_2) i = (hx >> 8);

	and	%l4,4080,%l4			! (Y0_2) i = i & 0xff0;

	ldd	[LOGTBL+%l4],%f62		! (Y0_2) y = *(double *)((char*)__mt_constlog2 + i);
	fmuld	%f58,%f20,%f52			! (Y0_2) s = u * yd;
	fsubd	%f32,%f10,%f10			! (Y0_2) s_l = (x - dtmp0);

	fitod	%f16,%f54			! (Y0_2) (double)itmp0;
	add	%l4,8,%o0			! (Y0_2) i += 8;

	lda	[px]%asi,%l0			! (Y0_3) hx = ((unsigned*)px)[0];
	fand	%f52,MHI32,%f4			! (Y0_2) s_h = vis_fand(s, MHI32);

	faddd	%f62,%f54,%f54			! (Y0_2) y += (double)itmp0;
	lda	[px+4]%asi,%i2			! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];
	fmuld	%f4,%f12,%f32			! (Y0_2) dtmp0 = s_h * ux;

	and	MASK_0x000fffff,%l0,%o5		! (Y0_3) hx &= 0xfffff;
	fmuld	%f52,%f52,%f12			! (Y0_2) y = s * s;

	or	MASK_0x3ff00000,%o5,%o5		! (Y0_3) hx |= 0x3ff00000;

	st	%o5,[%fp+tmp0_hi]		! (Y0_3) *(int*)&x = hx;
	fsubd	%f58,%f32,%f32			! (Y0_2) s_l = u - dtmp0;

	add	%o5,2048,%o5			! (Y0_3) hx += 0x800;

	st	%i2,[%fp+tmp0_lo]		! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];
	and	%o5,-4096,%l4			! (Y0_3) hx &= 0xfffff000;
	fmuld	KA5,%f12,%f36			! (Y0_2) dtmp8 = KA5 * y;

	st	%l4,[%fp+tmp1_hi]		! (Y0_3) *(int*)&ax = hx;
	fmuld	KA1_HI,%f4,%f48			! (Y0_2) yd = KA1_HI * s_h;

	fmuld	%f4,%f10,%f10			! (Y0_2) dtmp1 = s_h * s_l;
	ldd	[EXPTBL-ind_LO],KA1_LO		! (y0_2) load KA1_LO;
	and	%l0,MASK_0x7fffffff,%l3		! (Y0_3) hx &= 0x7fffffff;
	faddd	%f36,KA3,%f62			! (Y0_2) dtmp8 = dtmp8 + KA3;

	st	%g0,[%fp+%o7]			! (Y0_3) yisint = 0;
	faddd	%f54,%f48,%f36			! (Y0_2) m_h = y + yd;

	fdivd	DONE,%f26,%f22			! (Y1_2) yd = DONE / ux;
	fsubd	%f32,%f10,%f10			! (Y0_2) s_l -= dtmp1;

	cmp	%l0,MASK_0x000fffff		! (Y0_2) if (hx <= 0xfffff)

	sra	%l2,20,%l2			! (Y1_1) exp = (exp >> 20);
	ldd	[%fp+tmp0_hi],%f32		! (Y0_2) *(int*)&x = hx;
	ble,pn	%icc,.update2			! (Y0_2) if (hx <= 0xfffff)
	fsubd	%f36,%f54,%f30			! (Y0_1) dtmp2 = m_h - y;
.cont2:
	cmp	%l2,2047			! (Y1_1) if (exp >= 0x7ff)
	sub	%o7,ind_buf,%o7			! stack buffer pointer update
	ldd	[%fp+tmp1_hi],%f54		! (Y0_2) *(int*)&ax = hx;

	sra	%i4,20,%l0			! (Y1_1) itmp0 = (hx >> 20);
	sub	%l2,2046,%o5			! (Y1_1) exp = exp - 2046;
	fmuld	KA1,%f20,%f20			! (Y0_1) dtmp0 = KA1 * yd;

	add	%o5,%l0,%o5			! (Y1_1) exp += itmp0;
	fmuld	%f62,%f12,%f62			! (Y0_1) dtmp8 = dtmp8 * y;

	sll	%o5,8,%l0			! (Y1_1) itmp0 = exp << 8;
	add	%o7,4,%o7			! stack buffer pointer update
	st	%l0,[%fp+tmp3]			! (Y1_1) (double)itmp0;
	faddd	%f32,%f54,%f12			! (Y0_2) ux = x + ax;

	bge,pn	%icc,.update3			! (Y1_1) if (exp >= 0x7ff)
	fsubd	%f30,%f48,%f48			! (Y0_1) dtmp2 -= yd;
.cont3:
	and	%o7,15,%o7			! stack buffer pointer update
	fmuld	%f20,%f10,%f10			! (Y0_1) s_l = dtmp0 * s_l;

	add	%o7,ind_buf,%o7			! stack buffer pointer update
	fmuld	KA1_LO,%f4,%f4			! (Y0_1) dtmp1 = KA1_LO * s_h;
	fand	%f26,MHI32,%f26			! (Y1_1) ux = vis_fand(ux, MHI32);

	fmuld	%f62,%f52,%f62			! (Y0_1) s = dtmp8 * s;
	ldd	[LOGTBL+%o0],%f52		! (Y0_1) dtmp0 = *(double *)((char*)__mt_constlog2 + i + 8);
	fsubd	%f48,%f10,%f20			! (Y0_1) dtmp2 -= s_l;

	add	px,stridex,px			! px += stridex;
	fsubd	%f26,%f14,%f10			! (Y1_1) dtmp0 = (ux - ax);

	faddd	%f52,%f4,%f52			! (Y0_1) dtmp0 += dtmp1;

	ldd	[EXPTBL-ind_HI],KA1_HI		! (Y1_1) load KA1_HI;
	fsubd	%f62,%f20,%f4			! (Y0_1) y = s - dtmp2;

	ld	[%fp+tmp3],%f16			! (Y1_1) (double)itmp0;
	fsubd	%f8,%f14,%f58			! (Y1_1) u = x - ax;

	sra	%i4,8,%o0			! (Y1_1) i = (hx >> 8);

	faddd	%f4,%f52,%f48			! (Y0_1) y += dtmp0;
	and	%o0,4080,%o0			! (Y1_1) i = i & 0xff0;

	ldd	[LOGTBL+%o0],%f62		! (Y1_1) y = *(double *)((char*)__mt_constlog2 + i);
	fmuld	%f58,%f22,%f52			! (Y1_1) s = u * yd;
	fsubd	%f8,%f10,%f10			! (Y1_1) s_l = (x - dtmp0);

	lda	[py]%asi,%f30			! (Y0_1) yd = *py;
	fitod	%f16,%f14			! (Y1_1) (double)itmp0;

	lda	[py+4]%asi,%f31			! (Y0_1) yd = *py;
	faddd	%f48,%f36,%f8			! (Y0_1) dtmp0 = y + m_h;

	add	%o0,8,%o0			! (Y1_1) i += 8;
	lda	[px]%asi,%l0			! (Y1_2) hx = ((unsigned*)px)[0];
	fand	%f52,MHI32,%f4			! (Y1_1) s_h = vis_fand(s, MHI32);

	faddd	%f62,%f14,%f14			! (Y1_1) y += (double)itmp0;

	lda	[px+4]%asi,%i2			! (Y1_2) *((int*)&x + 1) = ((unsigned*)px)[1];
	fand	%f8,MHI32,%f20			! (Y0_1) s_h = vis_fand(dtmp0, MHI32);
	fmuld	%f4,%f26,%f8			! (Y1_1) dtmp0 = s_h * ux;

	fand	%f30,MHI32,%f6			! (Y0_1) s = vis_fand(yd, MHI32);
	and	MASK_0x000fffff,%l0,%i4		! (Y1_2) hx &= 0xfffff;
	fmuld	%f52,%f52,%f26			! (Y1_1) y = s * s;

	st	%g0,[%fp+%o7]			! (Y1_2) yisint = 0;
	or	MASK_0x3ff00000,%i4,%i4		! (Y1_2) hx |= 0x3ff00000;
	fsubd	%f20,%f36,%f62			! (Y0_1) dtmp0 = (s_h - m_h);

	st	%i4,[%fp+tmp0_hi]		! (Y1_2) *(int*)&x = hx;
	fsubd	%f58,%f8,%f8			! (Y1_1) s_l = u - dtmp0;

	add	%i4,2048,%i4			! (Y1_2) hx += 0x800;
	fmuld	%f20,%f6,%f34			! (Y0_1) s = s_h * s;
	fsubd	%f30,%f6,%f6			! (Y0_1) dtmp0 = (yd - s);

	st	%i2,[%fp+tmp0_lo]		! (Y1_2) *((int*)&x + 1) = ((unsigned*)px)[1];
	and	%i4,-4096,%i4			! (Y1_2) hx &= 0xfffff000;
	fmuld	KA5,%f26,%f36			! (Y1_1) dtmp8 = KA5 * y;

	st	%i4,[%fp+tmp1_hi]		! (Y1_2) *(int*)&ax = hx;
	fsubd	%f48,%f62,%f62			! (Y0_1) y = y - dtmp0;
	fmuld	KA1_HI,%f4,%f48			! (Y1_1) yd = KA1_HI * s_h;

	fmuld	%f4,%f10,%f10			! (Y1_1) dtmp1 = s_h * s_l;

	ldd	[EXPTBL-ind_LO],KA1_LO		! (Y1_1) load KA1_LO;
	and	%l0,MASK_0x7fffffff,%l2		! (Y1_2) hx &= 0x7fffffff;
	fmuld	%f6,%f20,%f6			! (Y0_1) dtmp0 *= s_h;
	fcmped	%fcc0,%f34,HTHRESH		! (Y0_1) s > HTHRESH

	cmp	%l0,MASK_0x000fffff		! (Y1_2) if (hx <= 0xfffff)
	fmuld	%f30,%f62,%f30			! (Y0_1) dtmp1 = yd * y;
	faddd	%f36,KA3,%f62			! (Y1_1) dtmp8 = dtmp8 + KA3;

	ble,pn	%icc,.update4			! (Y1_2) if (hx <= 0xfffff)
	faddd	%f14,%f48,%f36			! (Y1_1)  m_h = y + yd;
.cont4:
	sub	%o7,ind_buf,%o7			! stack buffer pointer update
	fmovdg	%fcc0,HTHRESH,%f34		! (Y0_1) s = HTHRESH

	add	%o7,4,%o7			! stack buffer pointer update
	fdivd	DONE,%f12,%f20			! (Y0_2) yd = DONE / ux;
	fsubd	%f8,%f10,%f10			! (Y1_1) s_l -= dtmp1;

	and	%o7,15,%o7			! stack buffer pointer update
	faddd	%f6,%f30,%f6			! (Y0_1) yd = dtmp0 + dtmp1;

	sra	%l3,20,%l3			! (Y0_2) exp = (exp >> 20);
	add	%o7,ind_buf,%o7			! stack buffer pointer update
	ldd	[%fp+tmp0_hi],%f8		! (Y1_2) *(int*)&x = hx;
	fsubd	%f36,%f14,%f30			! (Y1_1) dtmp2 = m_h - y;

	cmp	%l3,2047			! (Y0_2) if (exp >= 0x7ff)
	ldd	[%fp+tmp1_hi],%f14		! (Y1_2) *(int*)&ax = hx;
	fmuld	KA1,%f22,%f22			! (Y1_1) dtmp0 = KA1 * yd;

	sra	%l4,20,%l0			! (Y0_2) itmp0 = (hx >> 20);
	sub	%l3,2046,%o5			! (Y0_2) exp = exp - 2046;
	fcmped	%fcc1,%f34,LTHRESH		! (Y0_1) s < LTHRESH

	add	%o5,%l0,%o5			! (Y0_2) exp += itmp0;
	add	py,stridey,py			! py += stridey;
	fmuld	%f62,%f26,%f62			! (Y1_1) dtmp8 = dtmp8 * y;
	fmovdg	%fcc0,DZERO,%f6			! (Y0_1) yd = DZERO

	sll	%o5,8,%l0			! (Y0_2) itmp0 = exp << 8;
	st	%l0,[%fp+tmp3]			! (Y0_2) (double)itmp0;
	faddd	%f8,%f14,%f26			! (Y1_2) ux = x + ax;

	bge,pn	%icc,.update5			! (Y0_2) if (exp >= 0x7ff)
	fsubd	%f30,%f48,%f48			! (Y1_1) dtmp2 -= yd;
.cont5:
	lda	[py]%asi,%l1			! (Y1_1) hy = *py;
	fmuld	%f22,%f10,%f10			! (Y1_1) s_l = dtmp0 * s_l;
	fmovdl	%fcc1,LTHRESH,%f34		! (Y0_1) s = LTHRESH

	fmovdl	%fcc1,DZERO,%f6			! (Y0_1) yd = DZERO

	fand	%f12,MHI32,%f12			! (Y0_2) ux = vis_fand(ux, MHI32);
	fmuld	KA1_LO,%f4,%f4			! (Y1_1) dtmp1 = KA1_LO * s_h;

	fmuld	%f62,%f52,%f62			! (Y1_1) s = dtmp8 * s;
	ldd	[LOGTBL+%o0],%f52		! (Y1_1) dtmp0 = *(double *)((char*)__mt_constlog2 + i + 8);
	fsubd	%f48,%f10,%f22			! (Y1_1) dtmp2 -= s_l;

	add	px,stridex,px			! px += stridex;
	faddd	%f34,%f6,%f58			! (Y0_1) dtmp0 = (s + yd);

	and	%l1,MASK_0x7fffffff,%l1		! (Y1_1) hy &= 0x7fffffff;
	ldd	[EXPTBL-ind_HI],KA1_HI		! (Y0_2) load KA1_HI;
	fsubd	%f12,%f54,%f10			! (Y0_2) dtmp0 = (ux - ax);

	faddd	%f52,%f4,%f52			! (Y1_1) dtmp0 += dtmp1;

	fsubd	%f62,%f22,%f4			! (Y1_1) y = s - dtmp2;

	fdtoi	%f58,%f17			! (Y0_1) (int)dtmp0;

	ld	[%fp+tmp3],%f16			! (Y0_2) (double)itmp0;
	fsubd	%f32,%f54,%f58			! (Y0_2) u = x - ax;
	sra	%l4,8,%l4			! (Y0_2) i = (hx >> 8);

	sra	%l1,20,%l1			! (Y1_1) expy = hy >> 20;
	ldd	[EXPTBL-ind_KB5],KB5			! (Y0_1) load KB5;
	faddd	%f4,%f52,%f48			! (Y1_1) y += dtmp0;

	and	%l4,4080,%l4			! (Y0_2) i = i & 0xff0;
	st	%f17,[%fp+tmp4]			! (Y0_1) ind = (int)dtmp0;
	fitod	%f17,%f4			! (Y0_1) u = (double)(int)dtmp0;

	ldd	[LOGTBL+%l4],%f62		! (Y0_2) y = *(double *)((char*)__mt_constlog2 + i);
	fmuld	%f58,%f20,%f52			! (Y0_2) s = u * yd;
	fsubd	%f32,%f10,%f10			! (Y0_2) s_l = (x - dtmp0);

	lda	[py]%asi,%f30			! (Y1_1) yd = *py;
	fitod	%f16,%f54			! (Y0_2) (double)itmp0;

	lda	[py+4]%asi,%f31			! (Y1_1) yd = *py;
	faddd	%f48,%f36,%f32			! (Y1_1) dtmp0 = y + m_h;

	add	%l4,8,%o0			! (Y0_2) i += 8;
	fsubd	%f34,%f4,%f60			! (Y0_1) y = s - u;

	cmp	%l1,959				! (Y1_1) if (expy < 0x3fb);
	lda	[px]%asi,%l0			! (Y0_3) hx = ((unsigned*)px)[0];
	fand	%f52,MHI32,%f4			! (Y0_2) s_h = vis_fand(s, MHI32);

	bl,pn	%icc,.update6			! (Y1_1) if (expy < 0x3fb);
	faddd	%f62,%f54,%f54			! (Y0_2) y += (double)itmp0;
.cont6:
	cmp	%l1,1086			! (Y1_1) if (expy >= 0x43e);
	lda	[px+4]%asi,%i2			! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];
	fand	%f32,MHI32,%f22			! (Y1_1) s_h = vis_fand(dtmp0, MHI32);

	fmuld	%f4,%f12,%f32			! (Y0_2) dtmp0 = s_h * ux;
	bge,pn	%icc,.update7			! (Y1_1) if (expy >= 0x43e);
	faddd	%f60,%f6,%f60			! (Y0_1) y = y + yd;
.cont7:
	ld	[%fp+%o7],%o2			! (Y0_1) load yisint
	fand	%f30,MHI32,%f6			! (Y1_1) s = vis_fand(yd, MHI32);

	and	MASK_0x000fffff,%l0,%o5		! (Y0_3) hx &= 0xfffff;
	fmuld	%f52,%f52,%f12			! (Y0_2) y = s * s;

	or	MASK_0x3ff00000,%o5,%o5		! (Y0_3) hx |= 0x3ff00000;
	fsubd	%f22,%f36,%f62			! (Y1_1) dtmp0 = (s_h - m_h);

	st	%o5,[%fp+tmp0_hi]		! (Y0_3) *(int*)&x = hx;
	fsubd	%f58,%f32,%f32			! (Y0_2) s_l = u - dtmp0;
	fmuld	KB5,%f60,%f58			! (Y0_1) dtmp0 = KB5 * y;

	ldd	[EXPTBL-ind_KB3],KB3		! (Y0_1) load KB3;
	add	%o5,2048,%o5			! (Y0_3) hx += 0x800;
	fmuld	%f22,%f6,%f34			! (Y1_1) s = s_h * s;
	fsubd	%f30,%f6,%f6			! (Y1_1) dtmp0 = (yd - s);

	st	%i2,[%fp+tmp0_lo]		! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];
	and	%o5,-4096,%l4			! (Y0_3) hx &= 0xfffff000;
	fmuld	KA5,%f12,%f36			! (Y0_2) dtmp8 = KA5 * y;

	st	%l4,[%fp+tmp1_hi]		! (Y0_3) *(int*)&ax = hx;
	fsubd	%f48,%f62,%f62			! (Y1_1) y = y - dtmp0;
	fmuld	KA1_HI,%f4,%f48			! (Y0_2) yd = KA1_HI * s_h;

	subcc	counter,1,counter
	fmuld	%f4,%f10,%f10			! (Y0_2) dtmp1 = s_h * s_l;
	faddd	%f58,KB4,%f58			! (Y0_1) dtmp1 = dtmp0 + KB4;

	ldd	[EXPTBL-ind_LO],KA1_LO		! (y0_2) load KA1_LO;
	and	%l0,MASK_0x7fffffff,%l3		! (Y0_3) hx &= 0x7fffffff;
	fmuld	%f6,%f22,%f6			! (Y1_1) dtmp0 *= s_h;
	fcmped	%fcc0,%f34,HTHRESH		! (Y1_1) s > HTHRESH;

	fmuld	%f30,%f62,%f30			! (Y1_1) dtmp1 = yd * y;
	ba	1f
	faddd	%f36,KA3,%f62			! (Y0_2) dtmp8 = dtmp8 + KA3;

	.align	16
1:
	st	%g0,[%fp+%o7]			! (Y0_3) yisint = 0;
	fmuld	%f58,%f60,%f58			! (Y0_1) dtmp2 = dtmp1 * y;
	bneg,pn	%icc,.tail
	faddd	%f54,%f48,%f36			! (Y0_2) m_h = y + yd;

	nop
	fmovdg	%fcc0,HTHRESH,%f34		! (Y1_1) s = HTHRESH;

	fdivd	DONE,%f26,%f22			! (Y1_2) yd = DONE / ux;
	fsubd	%f32,%f10,%f10			! (Y0_2) s_l -= dtmp1;

.main_loop:
	cmp	%l0,MASK_0x000fffff		! (Y0_2) if (hx <= 0xfffff)
	add	py,stridey,py			! py += stridey;
	faddd	%f6,%f30,%f6			! (Y1_0) yd = dtmp0 + dtmp1;

	sra	%l2,20,%l2			! (Y1_1) exp = (exp >> 20);
	ldd	[%fp+tmp0_hi],%f32		! (Y0_2) *(int*)&x = hx;
	ble,pn	%icc,.update8			! (Y0_2) if (hx <= 0xfffff)
	fsubd	%f36,%f54,%f30			! (Y0_1) dtmp2 = m_h - y;
.cont8:
	cmp	%l2,2047			! (Y1_1) if (exp >= 0x7ff)
	sub	%o7,ind_buf,%o7			! stack buffer pointer update
	ldd	[%fp+tmp1_hi],%f54		! (Y0_2) *(int*)&ax = hx;
	faddd	%f58,KB3,%f58			! (Y0_0) dtmp3 = dtmp2 + KB3;

	sra	%i4,20,%l0			! (Y1_1) itmp0 = (hx >> 20);
	sub	%l2,2046,%o5			! (Y1_1) exp = exp - 2046;
	fmuld	KA1,%f20,%f20			! (Y0_1) dtmp0 = KA1 * yd;
	fcmped	%fcc1,%f34,LTHRESH		! (Y1_0) s < LTHRESH;

	ldd	[EXPTBL-ind_KB2],KB2		! (Y0_0) load KB2;
	add	%o5,%l0,%o5			! (Y1_1) exp += itmp0;
	fmuld	%f62,%f12,%f62			! (Y0_1) dtmp8 = dtmp8 * y;
	fmovdg	%fcc0,DZERO,%f6			! (Y1_0) yd = DZERO

	sll	%o5,8,%l0			! (Y1_1) itmp0 = exp << 8;
	add	%o7,4,%o7			! stack buffer pointer update
	st	%l0,[%fp+tmp3]			! (Y1_1) (double)itmp0;
	faddd	%f32,%f54,%f12			! (Y0_2) ux = x + ax;

	ld	[%fp+tmp4],%i2			! (Y0_0) ind = (int)dtmp0;
	fsubd	%f30,%f48,%f48			! (Y0_1) dtmp2 -= yd;
	bge,pn	%icc,.update9			! (Y1_1) if (exp >= 0x7ff)
        fmuld	%f58,%f60,%f58			! (Y0_0) dtmp4 = dtmp3 * y;
.cont9:
	lda	[py]%asi,%l1			! (Y0_1) hy = *py;
	and	%o7,15,%o7			! stack buffer pointer update
	fmuld	%f20,%f10,%f10			! (Y0_1) s_l = dtmp0 * s_l;
	fmovdl	%fcc1,LTHRESH,%f34		! (Y1_0) s = LTHRESH;

	add	%o7,ind_buf,%o7			! stack buffer pointer update
	fmovdl	%fcc1,DZERO,%f6			! (Y1_0) yd = DZERO

	fmuld	KA1_LO,%f4,%f4			! (Y0_1) dtmp1 = KA1_LO * s_h;
	fand	%f26,MHI32,%f26			! (Y1_1) ux = vis_fand(ux, MHI32);

	fmuld	%f62,%f52,%f62			! (Y0_1) s = dtmp8 * s;
	nop
        faddd	%f58,KB2,%f30			! (Y0_0) dtmp5 = dtmp4 + KB2;

	nop
	add	pz,stridez,pz			! pz += stridez;
	ldd	[LOGTBL+%o0],%f52		! (Y0_1) dtmp0 = *(double *)((char*)__mt_constlog2 + i + 8);
	fsubd	%f48,%f10,%f20			! (Y0_1) dtmp2 -= s_l;

	sra	%i2,8,%l0			! (Y0_0) ind >>= 8;
	ldd	[EXPTBL-ind_KB1],KB1		! (Y0_0) load KB1;
	add	px,stridex,px			! px += stridex;
	faddd	%f34,%f6,%f58			! (Y1_0) dtmp0 = (s + yd);

	add	%l0,1021,%l2			! (Y0_0) eflag = (ind + 1021);
	sub	%g0,%l0,%o5			! (Y0_0) gflag = (1022 - ind);
	fsubd	%f26,%f14,%f10			! (Y1_1) dtmp0 = (ux - ax);

	sra	%l2,31,%l2			! (Y0_0) eflag = eflag >> 31;
	add	%o5,1022,%o5			! (Y0_0) gflag = (1022 - ind);
	fmuld	%f30,%f60,%f48			! (Y0_0) dtmp6 = dtmp5 * y;
	faddd	%f52,%f4,%f52			! (Y0_1) dtmp0 += dtmp1;

	sra	%o5,31,%o5			! (Y0_0) gflag = gflag >> 31;
	and	%l2,54,%o0			! (Y0_0) itmp0 = 54 & eflag;
	ldd	[EXPTBL-ind_HI],KA1_HI		! (Y1_1) load KA1_HI;
	fsubd	%f62,%f20,%f4			! (Y0_1) y = s - dtmp2;

	lda	[py]%asi,%f30			! (Y0_1) yd = *py;
	sub	%l2,%o5,%l2			! (Y0_0) ind = eflag - gflag;
	add	%l0,%o0,%l0			! (Y0_0) ind = ind + itmp0;
	fdtoi	%f58,%f20			! (Y1_0) u = (double)(int)dtmp0;

	sra	%i4,8,%o0			! (Y1_1) i = (hx >> 8);
	and	%o5,52,%o5			! (Y0_0) itmp1 = 52 & gflag;
	ld	[%fp+tmp3],%f16			! (Y1_1) (double)itmp0;
	fsubd	%f8,%f14,%f58			! (Y1_1) u = x - ax;

	and	%o0,4080,%o0			! (Y1_1) i = i & 0xff0;
	sub	%l0,%o5,%i4			! (Y0_0) ind = ind - itmp1;
	st	%f20,[%fp+tmp4]			! (Y1_0) ind = (int)dtmp0;
	faddd	%f48,KB1,%f14			! (Y0_0) dtmp7 = dtmp6 + KB1;

	add	%o2,%i4,%i4			! (Y0_0) ind = yisint + ind;
	and	%i2,255,%o5			! (Y0_0) i = ind & 0xff;
	lda	[px]%asi,%l0			! (Y1_2) hx = ((unsigned*)px)[0];
	faddd	%f4,%f52,%f48			! (Y0_1) y += dtmp0;

	sll	%i4,20,%i4			! (Y0_0) ind <<= 20;
	ldd	[LOGTBL+%o0],%f62		! (Y1_1) y = *(double *)((char*)__mt_constlog2 + i);
	and	%l1,MASK_0x7fffffff,%l1		! (Y0_1) hy &= 0x7fffffff;
	fitod	%f20,%f4			! (Y1_0) u = (double)(int)dtmp0;

	lda	[px+4]%asi,%i2			! (Y1_2) *((int*)&x + 1) = ((unsigned*)px)[1];
	nop
	fmuld	%f58,%f22,%f52			! (Y1_1) s = u * yd;
	fsubd	%f8,%f10,%f10			! (Y1_1) s_l = (x - dtmp0);

	sll	%o5,4,%o5			! (Y0_0) i = i << 4;
	st	%i4,[%fp+tmp2_hi]		! (Y0_0) *(int*)&dtmp0 = ind;
	fmuld	%f14,%f60,%f20			! (Y0_0) y = dtmp7 * y;
	fitod	%f16,%f14			! (Y1_1) (double)itmp0;

	sra	%l1,20,%l1			! (Y0_1) expy = hy >> 20;
	nop
	ldd	[EXPTBL+%o5],%f56		! (Y0_0) u = *(double*)((char*)__mt_constexp2 + i);
	faddd	%f48,%f36,%f8			! (Y0_1) dtmp0 = y + m_h;

	add	%o5,8,%o5			! (Y0_0) i += 8;
	add	%o0,8,%o0			! (Y1_1) i += 8;
	lda	[py+4]%asi,%f31			! (Y0_1) yd = *py;
	fsubd	%f34,%f4,%f60			! (Y1_0) y = s - u;

	cmp	%l1,959				! (Y0_1) if (expy < 0x3fb);
	and	MASK_0x000fffff,%l0,%i4		! (Y1_2) hx &= 0xfffff;
	ldd	[EXPTBL-ind_KB5],KB5		! (Y1_0) load KB5;
	fand	%f52,MHI32,%f4			! (Y1_1) s_h = vis_fand(s, MHI32);

	ldd	[EXPTBL+%o5],%f16		! (Y0_0) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
	fmuld	%f56,%f20,%f34			! (Y0_0) dtmp1 = u * y;
	bl,pn	%icc,.update10			! (Y0_1) if (expy < 0x3fb);
	faddd	%f62,%f14,%f14			! (Y1_1) y += (double)itmp0;
.cont10:
	or	MASK_0x3ff00000,%i4,%i4		! (Y1_2) hx |= 0x3ff00000;
	cmp	%l1,1086			! (Y0_1) if (expy >= 0x43e);
	fand	%f8,MHI32,%f20			! (Y0_1) s_h = vis_fand(dtmp0, MHI32);

	fmuld	%f4,%f26,%f8			! (Y1_1) dtmp0 = s_h * ux;
	st	%i4,[%fp+tmp0_hi]		! (Y1_2) *(int*)&x = hx;
	bge,pn	%icc,.update11			! (Y0_1) if (expy >= 0x43e);
	faddd	%f60,%f6,%f60			! (Y1_0) y = y + yd;
.cont11:
	add	%i4,2048,%i4			! (Y1_2) hx += 0x800;
	ld	[%fp+%o7],%o2			! (Y1_0) load yisint
	fand	%f30,MHI32,%f6			! (Y0_1) s = vis_fand(yd, MHI32);

	st	%i2,[%fp+tmp0_lo]		! (Y1_2) *((int*)&x + 1) = ((unsigned*)px)[1];
	and	%i4,-4096,%i4			! (Y1_2) hx &= 0xfffff000;
	fmuld	%f52,%f52,%f26			! (Y1_1) y = s * s;
	faddd	%f16,%f34,%f16			! (Y0_0) dtmp2 = dtmp0 + dtmp1;

	st	%i4,[%fp+tmp1_hi]		! (Y1_2) *(int*)&ax = hx;
	fsubd	%f20,%f36,%f62			! (Y0_1) dtmp0 = (s_h - m_h);

	fsubd	%f58,%f8,%f8			! (Y1_1) s_l = u - dtmp0;
	fmuld	KB5,%f60,%f58			! (Y1_0) dtmp0 = KB5 * y;

	ldd	[EXPTBL-ind_KB3],KB3		! (Y1_0) load KB3;
	fmuld	%f20,%f6,%f34			! (Y0_1) s = s_h * s;
	fsubd	%f30,%f6,%f6			! (Y0_1) dtmp0 = (yd - s);

	faddd	%f16,%f56,%f56			! (Y0_0) u = dtmp2 + u;
	nop
        fmuld	KA5,%f26,%f36			! (Y1_1) dtmp8 = KA5 * y;

	nop
	add	%l2,513,%l2			! (Y0_0) ind += 513;
	fsubd	%f48,%f62,%f62			! (Y0_1) y = y - dtmp0;
	fmuld	KA1_HI,%f4,%f48			! (Y1_1) yd = KA1_HI * s_h;

	sll	%l2,3,%o5			! (Y0_0) ind *= 8;
	ldd	[%fp+tmp2_hi],%f16		! (Y0_0) ld dtmp0;
	fmuld	%f4,%f10,%f10			! (Y1_1) dtmp1 = s_h * s_l;
	faddd	%f58,KB4,%f58			! (Y1_0) dtmp1 = dtmp0 + KB4;

	ldd	[EXPTBL-ind_LO],KA1_LO		! (Y1_1) load KA1_LO;
	and	%l0,MASK_0x7fffffff,%l2		! (Y1_2) hx &= 0x7fffffff;
	fmuld	%f6,%f20,%f6			! (Y0_1) dtmp0 *= s_h;
	fcmped	%fcc0,%f34,HTHRESH		! (Y0_1) s > HTHRESH

	ldd	[EXPTBL+%o5],%f20		! (Y0_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	nop
	nop
	fpadd32	%f56,%f16,%f56			! (Y0_0) u = vis_fpadd32(u, dtmp0);

	nop
	cmp	%l0,MASK_0x000fffff		! (Y1_2) if (hx <= 0xfffff)
	fmuld	%f30,%f62,%f30			! (Y0_1) dtmp1 = yd * y;
	faddd	%f36,KA3,%f62			! (Y1_1) dtmp8 = dtmp8 + KA3;

	fmuld	%f58,%f60,%f58			! (Y1_0) dtmp2 = dtmp1 * y;
	st	%g0,[%fp+%o7]			! (Y1_2) yisint = 0;
	ble,pn	%icc,.update12			! (Y1_2) if (hx <= 0xfffff)
	faddd	%f14,%f48,%f36			! (Y1_1)  m_h = y + yd;
.cont12:
	sra	%l3,20,%l3			! (Y0_2) exp = (exp >> 20);
	sub	%o7,ind_buf,%o7			! stack buffer pointer update
	fmuld	%f56,%f20,%f16			! (Y0_0) dtmp1 = u * dtmp1;
	fmovdg	%fcc0,HTHRESH,%f34		! (Y0_1) s = HTHRESH

	cmp	%l3,2047			! (Y0_2) if (exp >= 0x7ff)
	st	%f16,[pz]			! (Y0_0) write into memory
	fdivd	DONE,%f12,%f20			! (Y0_2) yd = DONE / ux;
	fsubd	%f8,%f10,%f10			! (Y1_1) s_l -= dtmp1;

	sra	%l4,20,%l0			! (Y0_2) itmp0 = (hx >> 20);
	sub	%l3,2046,%o5			! (Y0_2) exp = exp - 2046;
	st	%f17,[pz+4]			! (Y0_0) write into memory
	faddd	%f6,%f30,%f6			! (Y0_1) yd = dtmp0 + dtmp1;

	add	%o5,%l0,%o5			! (Y0_2) exp += itmp0;
	add	py,stridey,py			! py += stridey;
	ldd	[%fp+tmp0_hi],%f8		! (Y1_2) *(int*)&x = hx;
	fsubd	%f36,%f14,%f30			! (Y1_1) dtmp2 = m_h - y;

	sll	%o5,8,%l0			! (Y0_2) itmp0 = exp << 8;
	ldd	[%fp+tmp1_hi],%f14		! (Y1_2) *(int*)&ax = hx;
	fmuld	KA1,%f22,%f22			! (Y1_1) dtmp0 = KA1 * yd;
	faddd	%f58,KB3,%f58			! (Y1_0) dtmp3 = dtmp2 + KB3;

	add	%o7,4,%o7			! stack buffer pointer update
	st	%l0,[%fp+tmp3]			! (Y0_2) (double)itmp0;
	fcmped	%fcc1,%f34,LTHRESH		! (Y0_1) s < LTHRESH

	and	%o7,15,%o7			! stack buffer pointer update
	ld	[%fp+tmp4],%l0			! (Y1_0) ind = (int)dtmp0;
	fmuld	%f62,%f26,%f62			! (Y1_1) dtmp8 = dtmp8 * y;
	fmovdg	%fcc0,DZERO,%f6			! (Y0_1) yd = DZERO

	nop
	add	%o7,ind_buf,%o7			! stack buffer pointer update
	ldd	[EXPTBL-ind_KB2],KB2		! (Y1_0) load KB2;
	faddd	%f8,%f14,%f26			! (Y1_2) ux = x + ax;

	fmuld	%f58,%f60,%f58			! (Y1_0) dtmp4 = dtmp3 * y;
	nop
	bge,pn	%icc,.update13			! (Y0_2) if (exp >= 0x7ff)
	fsubd	%f30,%f48,%f48			! (Y1_1) dtmp2 -= yd;
.cont13:
	lda	[py]%asi,%l1			! (Y1_1) hy = *py;
	nop
	fmuld	%f22,%f10,%f10			! (Y1_1) s_l = dtmp0 * s_l;
	fmovdl	%fcc1,LTHRESH,%f34		! (Y0_1) s = LTHRESH

	nop
	nop
	fmovdl	%fcc1,DZERO,%f6			! (Y0_1) yd = DZERO

	fand	%f12,MHI32,%f12			! (Y0_2) ux = vis_fand(ux, MHI32);
	nop
	nop
	fmuld	KA1_LO,%f4,%f4			! (Y1_1) dtmp1 = KA1_LO * s_h;

	nop
	add	px,stridex,px			! px += stridex;
	faddd	%f58,KB2,%f30			! (Y1_0) dtmp5 = dtmp4 + KB2;
	fmuld	%f62,%f52,%f62			! (Y1_1) s = dtmp8 * s;

	sra	%l0,8,%i2			! (Y1_0) ind >>= 8;
	add	pz,stridez,pz			! pz += stridez;
	ldd	[LOGTBL+%o0],%f52		! (Y1_1) dtmp0 = *(double *)((char*)__mt_constlog2 + i + 8);
	fsubd	%f48,%f10,%f22			! (Y1_1) dtmp2 -= s_l;

	add	%i2,1021,%l3			! (Y1_0) eflag = (ind + 1021);
	sub	%g0,%i2,%o5			! (Y1_0) gflag = (1022 - ind);
	ldd	[EXPTBL-ind_KB1],KB1		! (Y1_0) load KB1;
	faddd	%f34,%f6,%f58			! (Y0_1) dtmp0 = (s + yd);

	sra	%l3,31,%l3			! (Y1_0) eflag = eflag >> 31;
	add	%o5,1022,%o5			! (Y1_0) gflag = (1022 - ind);
	ldd	[EXPTBL-ind_HI],KA1_HI		! (Y0_2) load KA1_HI;
	fsubd	%f12,%f54,%f10			! (Y0_2) dtmp0 = (ux - ax);

	sra	%o5,31,%o5			! (Y1_0) gflag = gflag >> 31;
	and	%l3,54,%o0			! (Y1_0) itmp0 = 54 & eflag;
	fmuld	%f30,%f60,%f48			! (Y1_0) dtmp6 = dtmp5 * y;
	faddd	%f52,%f4,%f52			! (Y1_1) dtmp0 += dtmp1;

	sra	%l4,8,%l4			! (Y0_2) i = (hx >> 8);
	add	%i2,%o0,%i2			! (Y1_0) ind = ind + itmp0;
	fsubd	%f62,%f22,%f4			! (Y1_1) y = s - dtmp2;

	lda	[py]%asi,%f30			! (Y1_1) yd = *py;
	and	%l4,4080,%l4			! (Y0_2) i = i & 0xff0;
	and	%o5,52,%o0			! (Y1_0) itmp1 = 52 & gflag;
	fdtoi	%f58,%f22			! (Y0_1) (int)dtmp0;

	sub	%l3,%o5,%l3			! (Y1_0) ind = eflag - gflag;
	sub	%i2,%o0,%i2			! (Y1_0) ind = ind - itmp1;
	ld	[%fp+tmp3],%f16			! (Y0_2) (double)itmp0;
	fsubd	%f32,%f54,%f58			! (Y0_2) u = x - ax;

	add	%o2,%i2,%i2			! (Y1_0) ind = yisint + ind;
	and	%l0,255,%o5			! (Y1_0) i = ind & 0xff;
	st	%f22,[%fp+tmp4]			! (Y0_1) ind = (int)dtmp0;
	faddd	%f48,KB1,%f54			! (Y1_0) dtmp7 = dtmp6 + KB1;

	sll	%i2,20,%o0			! (Y1_0) ind <<= 20;
	nop
	lda	[px]%asi,%l0			! (Y0_3) hx = ((unsigned*)px)[0];
	faddd	%f4,%f52,%f48			! (Y1_1) y += dtmp0;

	and	%l1,MASK_0x7fffffff,%l1		! (Y1_1) hy &= 0x7fffffff;
	nop
	st	%o0,[%fp+tmp2_hi]		! (Y1_0) *(int*)&dtmp0 = ind;
	fitod	%f22,%f4			! (Y0_1) u = (double)(int)dtmp0;

	lda	[px+4]%asi,%i2			! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];
	nop
	fmuld	%f58,%f20,%f52			! (Y0_2) s = u * yd;
	fsubd	%f32,%f10,%f10			! (Y0_2) s_l = (x - dtmp0);

	sll	%o5,4,%o5			! (Y1_0) i = i << 4;
	ldd	[LOGTBL+%l4],%f62		! (Y0_2) y = *(double *)((char*)__mt_constlog2 + i);
	fmuld	%f54,%f60,%f22			! (Y1_0) y = dtmp7 * y;
	fitod	%f16,%f54			! (Y0_2) (double)itmp0;

	sra	%l1,20,%l1			! (Y1_1) expy = hy >> 20;
	nop
	ldd	[EXPTBL+%o5],%f56		! (Y1_0) u = *(double*)((char*)__mt_constexp2 + i);
	faddd	%f48,%f36,%f32			! (Y1_1) dtmp0 = y + m_h;

	add	%o5,8,%o5			! (Y1_0) i += 8;
	add	%l4,8,%o0			! (Y0_2) i += 8;
	lda	[py+4]%asi,%f31			! (Y1_1) yd = *py;
	fsubd	%f34,%f4,%f60			! (Y0_1) y = s - u;

	cmp	%l1,959				! (Y1_1) if (expy < 0x3fb);
	and	MASK_0x000fffff,%l0,%l4		! (Y0_3) hx &= 0xfffff;
	fand	%f52,MHI32,%f4			! (Y0_2) s_h = vis_fand(s, MHI32);

	ldd	[EXPTBL+%o5],%f16		! (Y1_0) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
	fmuld	%f56,%f22,%f34			! (Y1_0) dtmp1 = u * y;
	bl,pn	%icc,.update14			! (Y1_1) if (expy < 0x3fb);
	faddd	%f62,%f54,%f54			! (Y0_2) y += (double)itmp0;
.cont14:
	ldd	[EXPTBL-ind_KB5],KB5		! (Y0_1) load KB5;
	or	MASK_0x3ff00000,%l4,%o5		! (Y0_3) hx |= 0x3ff00000;
	cmp	%l1,1086			! (Y1_1) if (expy >= 0x43e);
	fand	%f32,MHI32,%f22			! (Y1_1) s_h = vis_fand(dtmp0, MHI32);

	fmuld	%f4,%f12,%f32			! (Y0_2) dtmp0 = s_h * ux;
	st	%o5,[%fp+tmp0_hi]		! (Y0_3) *(int*)&x = hx;
	bge,pn	%icc,.update15			! (Y1_1) if (expy >= 0x43e);
	faddd	%f60,%f6,%f60			! (Y0_1) y = y + yd;
.cont15:
	add	%o5,2048,%o5			! (Y0_3) hx += 0x800;
	nop
	ld	[%fp+%o7],%o2			! (Y0_1) load yisint
	fand	%f30,MHI32,%f6			! (Y1_1) s = vis_fand(yd, MHI32);

	and	%o5,-4096,%l4			! (Y0_3) hx &= 0xfffff000;
	st	%i2,[%fp+tmp0_lo]		! (Y0_3) *((int*)&x + 1) = ((unsigned*)px)[1];
	fmuld	%f52,%f52,%f12			! (Y0_2) y = s * s;
	faddd	%f16,%f34,%f16			! (Y1_0) dtmp2 = dtmp0 + dtmp1;

	nop
	nop
	st	%l4,[%fp+tmp1_hi]		! (Y0_3) *(int*)&ax = hx;
	fsubd	%f22,%f36,%f62			! (Y1_1) dtmp0 = (s_h - m_h);

	fsubd	%f58,%f32,%f32			! (Y0_2) s_l = u - dtmp0;
	nop
	nop
	fmuld	KB5,%f60,%f58			! (Y0_1) dtmp0 = KB5 * y;

	ldd	[EXPTBL-ind_KB3],KB3		! (Y0_1) load KB3;
	nop
	fmuld	%f22,%f6,%f34			! (Y1_1) s = s_h * s;
	fsubd	%f30,%f6,%f6			! (Y1_1) dtmp0 = (yd - s);

	fmuld	KA5,%f12,%f36			! (Y0_2) dtmp8 = KA5 * y;
	nop
	faddd	%f16,%f56,%f56			! (Y1_0) u = dtmp2 + u;

	add	%l3,513,%l3			! (Y1_0) ind += 1;
	fsubd	%f48,%f62,%f62			! (Y1_1) y = y - dtmp0;
	fmuld	KA1_HI,%f4,%f48			! (Y0_2) yd = KA1_HI * s_h;

	sll	%l3,3,%o5			! (Y1_0) ind *= 8;
	ldd	[%fp+tmp2_hi],%f16		! (Y1_0) *(int*)&dtmp0 = ind;
	fmuld	%f4,%f10,%f10			! (Y0_2) dtmp1 = s_h * s_l;
	faddd	%f58,KB4,%f58			! (Y0_1) dtmp1 = dtmp0 + KB4;

	ldd	[EXPTBL-ind_LO],KA1_LO		! (y0_2) load KA1_LO;
	and	%l0,MASK_0x7fffffff,%l3		! (Y0_3) hx &= 0x7fffffff;
	fmuld	%f6,%f22,%f6			! (Y1_1) dtmp0 *= s_h;
	fcmped	%fcc0,%f34,HTHRESH		! (Y1_1) s > HTHRESH;

	nop
	subcc	counter,2,counter		! update cycle counter
	ldd	[EXPTBL+%o5],%f22		! (Y1_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	fpadd32	%f56,%f16,%f56			! (Y1_0) u = vis_fpadd32(u, dtmp0);

	fmuld	%f30,%f62,%f30			! (Y1_1) dtmp1 = yd * y;
	nop
	nop
	faddd	%f36,KA3,%f62			! (Y0_2) dtmp8 = dtmp8 + KA3;

	nop
	st	%g0,[%fp+%o7]			! (Y0_3) yisint = 0;
	fmuld	%f58,%f60,%f58			! (Y0_1) dtmp2 = dtmp1 * y;
	faddd	%f54,%f48,%f36			! (Y0_2) m_h = y + yd;

	fmuld	%f56,%f22,%f16			! (Y1_0) dtmp1 = u * dtmp1;
	nop
	st	%f16,[pz]			! (Y1_0) write into memory
	fmovdg	%fcc0,HTHRESH,%f34		! (Y1_1) s = HTHRESH;

	fdivd	DONE,%f26,%f22			! (Y1_2) yd = DONE / ux;
	st	%f17,[pz+4]			! (Y1_0) write into memory
	bpos,pt	%icc,.main_loop
	fsubd	%f32,%f10,%f10			! (Y0_2) s_l -= dtmp1;

.tail:
	addcc	counter,1,counter
	bneg,pn	%icc,.end_loop

	faddd	%f58,KB3,%f58			! (Y0_0) dtmp3 = dtmp2 + KB3;
	ldd	[EXPTBL-ind_KB2],KB2		! (Y0_0) load KB2;

	ld	[%fp+tmp4],%i2			! (Y0_0) ind = (int)dtmp0;
	fmuld	%f58,%f60,%f58			! (Y0_0) dtmp4 = dtmp3 * y;
	faddd	%f58,KB2,%f30			! (Y0_0) dtmp5 = dtmp4 + KB2;

	add	pz,stridez,pz			! pz += stridez;
	ldd	[EXPTBL-ind_KB1],KB1		! (Y0_0) load KB1;
	sra	%i2,8,%l0			! (Y0_0) ind >>= 8;

	add	%l0,1021,%l2			! (Y0_0) eflag = (ind + 1021);
	sub	%g0,%l0,%o5			! (Y0_0) gflag = (1022 - ind);
	fmuld	%f30,%f60,%f48			! (Y0_0) dtmp6 = dtmp5 * y;

	sra	%l2,31,%l2			! (Y0_0) eflag = eflag >> 31;
	add	%o5,1022,%o5			! (Y0_0) gflag = (1022 - ind);

	sra	%o5,31,%o5			! (Y0_0) gflag = gflag >> 31;
	and	%l2,54,%o0			! (Y0_0) itmp0 = 54 & eflag;

	sub	%l2,%o5,%l2			! (Y0_0) ind = eflag - gflag;
	add	%l0,%o0,%l0			! (Y0_0) ind = ind + itmp0;

	and	%o5,52,%o5			! (Y0_0) itmp1 = 52 & gflag;
	faddd	%f48,KB1,%f14			! (Y0_0) dtmp7 = dtmp6 + KB1;

	sub	%l0,%o5,%l0			! (Y0_0) ind = ind - itmp1;
	and	%i2,255,%i4			! (Y0_0) i = ind & 0xff;

	sll	%i4,4,%o5			! (Y0_0) i = i << 4;

	ldd	[EXPTBL+%o5],%f56		! (Y0_0) u = *(double*)((char*)__mt_constexp2 + i);
	add	%o2,%l0,%l0			! (Y0_0) ind = yisint + ind;
	fmuld	%f14,%f60,%f20			! (Y0_0) y = dtmp7 * y;

	sll	%l0,20,%i2			! (Y0_0) ind <<= 20;

	add	%o5,8,%o5			! (Y0_0) i += 8;
	st	%i2,[%fp+tmp2_hi]		! (Y0_0) *(int*)&dtmp0 = ind;

	ldd	[EXPTBL+%o5],%f16		! (Y0_0) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
	fmuld	%f56,%f20,%f34			! (Y0_0) dtmp1 = u * y;

	faddd	%f16,%f34,%f16			! (Y0_0) dtmp2 = dtmp0 + dtmp1;

	faddd	%f16,%f56,%f56			! (Y0_0) u = dtmp2 + u;
	add	%l2,513,%l2			! (Y0_0) ind += 513;

	sll	%l2,3,%o5			! (Y0_0) ind *= 8;
	ldd	[%fp+tmp2_hi],%f16		! (Y0_0) ld dtmp0;

	ldd	[EXPTBL+%o5],%f20		! (Y0_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	fpadd32	%f56,%f16,%f56			! (Y0_0) u = vis_fpadd32(u, dtmp0);

	fmuld	%f56,%f20,%f16			! (Y0_0) dtmp1 = u * dtmp1;
	st	%f16,[pz]			! (Y0_0) write into memory
	st	%f17,[pz+4]			! (Y0_0) write into memory

.end_loop:
	ba	.begin
	nop
.end:
	ret
	restore	%g0,0,%o0

	.align	16
.update0:
	cmp	%l0,%g0				! if (x >= 0);
	fzero	%f30

	lda	[py+4]%asi,%l0			! ld ly
	bge,pt	%icc,.pos0			! if (x >= 0);
	or	%g0,%g0,%o5			! yisint = 0;

	cmp	%o0,1076			! if (expy >= 0x434);
	bge	.neg0				! if (expy >= 0x434);
	or	%g0,2,%o5			! yisint = 2;

	cmp	%o0,1023			! if (expy < 0x3ff);
	bl	.neg0				! if (expy < 0x3ff);
	or	%g0,0,%o5			! yisint = 0;

	cmp	%o0,1043			! if (expy <= (20 + 0x3ff));
	ble	.small0				! if (expy <= (20 + 0x3ff));
	sub	%o0,1023,%o0			! expy - 0x3ff;

	sub	%g0,%o0,%o0
	add	%o0,52,%o0			! sh = (52 - (expy - 0x3ff);
	srl	%l0,%o0,%i4			! i0 = (ly >> sh);

	sll	%i4,%o0,%i4			! (i0 << sh);

	srl	%l0,%o0,%o0			! i0 = (ly >> sh);
	cmp	%i4,%l0				! if ((i0 << sh) == ly);

	and	%o0,1,%o0			! i0 &= 1;

	sub	%g0,%o0,%o0
	add	%o0,2,%o0			! i0 = 2 - i0;

	move	%icc,%o0,%o5			! yisint = i0;

	ba	.neg0
	nop
.small0:
	sub	%g0,%o0,%o0
	cmp	%l0,%g0				! if (ly != 0);

	add	%o0,20,%o0			! sh = (20 - (expy - 0x3ff);
	bne	.neg0				! if (ly != 0);
	or	%g0,0,%o5			! yisint = 0;

	srl	%l1,%o0,%i4			! i0 = (hy >> sh);

	sll	%i4,%o0,%i4			! (i0 << sh);

	srl	%l1,%o0,%o0			! i0 = (hy >> sh);
	cmp	%i4,%l1				! if ((i0 << sh) == hy);

	and	%o0,1,%o0			! i0 &= 1;

	sub	%g0,%o0,%o0
	add	%o0,2,%o0			! i0 = 2 - i0;

	move	%icc,%o0,%o5			! yisint = i0;
.neg0:
	orcc	%l3,%i2,%g0			! if (x != 0);

	sra	%o2,31,%i4			! sy = (*((unsigned*)py)[0]) >> 31;
	bne,pt	%icc,3f				! if (x != 0);
	nop

	cmp	%i4,%g0				! if (sy == 0);
	be	1f				! if (sy == 0);
	and	%o5,1,%i4			! yisint &= 1;

	fdivd	DONE,%f30,%f30			! y0 = DONE / y0;
1:
	cmp	%i4,%g0				! if ((yisint & 1) == 0);
	be	2f				! if ((yisint & 1) == 0);
	nop

	fnegd	%f30,%f30			! y0 = -y0;
2:
	st	%f30,[pz]
	ba	.update_point
	st	%f31,[pz+4]
3:
	cmp	%o5,%g0				! if (yisint != 0);
	bne	.pos0				! if (yisint != 0);
	nop

	fdivd	DZERO,DZERO,%f30		! y0 = DZERO / DZERO;
	st	%f30,[pz]
	ba	.update_point
	st	%f31,[pz+4]
.pos0:
	orcc	%l3,%i2,%g0			! if (x != 0);

	sra	%o2,31,%i4			! sy = (*((unsigned*)py)[0]) >> 31;
	bne,pt	%icc,.nzero0			! if (x != 0);
	nop

	cmp	%i4,%g0				! if (sy == 0);
	be	1f				! if (sy == 0);
	nop

	fdivd	DONE,%f30,%f30			! y0 = DONE / y0;
1:
	st	%f30,[pz]
	ba	.update_point
	st	%f31,[pz+4]
.nzero0:
	sll	%o5,11,%o5
	cmp	%l3,MASK_0x000fffff		! if (exp > 0xfffff);

	bg,pt	%icc,.cont0			! if (exp > 0xfffff);
	st	%o5,[%fp+%o7]

	ldd	[%fp+tmp_mant],%f54

	or	%g0,1074,%o5
	fand	%f32,%f54,%f32			! y0 = vis_fand(x, MMANT);

	sll	%o5,20,%o5
	fxtod	%f32,%f32			! ax = (double) ((long long *) & y0)[0];

	std	%f32,[%fp+tmp0_hi]		! exp = ((unsigned int*) & ax)[0];
	fand	%f32,%f54,%f32			! x = vis_fand(ax, MMANT);

	ld	[%fp+tmp0_hi],%i2		! exp = ((unsigned int*) & ax)[0];
	for	%f32,DONE,%f32			! x = vis_for(x, DONE);

	sub	%i2,%o5,%l3			! exp -= (1023 + 51) << 20;
	and	MASK_0x000fffff,%i2,%l4		! hx = exp & 0xfffff;
	or	MASK_0x3ff00000,%l4,%l4		! hx |= 0x3ff00000;
	add	%l4,2048,%l4			! hx += 0x800;
	and	%l4,-4096,%l4			! hx &= 0xfffff000;

	ba	.cont0
	st	%l4,[%fp+tmp1_hi]		! *(int*)&ax = hx;

	.align	16
.update1:
	cmp	counter,0
	ble,pt	%icc,.cont1
	add	py,stridey,%o5

	stx	px,[%fp+tmp_px]

	orcc	%l2,%i2,%g0			! if (x == 0);
	bne,pt	%icc,.nzero1			! if (x == 0);
	stx	%o5,[%fp+tmp_py]
.u1:
	st	counter,[%fp+tmp_counter]
	ba	.cont1
	or	%g0,0,counter
.nzero1:
	lda	[%o5]%asi,%l1			! ld hy;
	cmp	%l0,%g0				! if (x >= 0);

	lda	[%o5+4]%asi,%l0			! ld ly
	bge,pt	%icc,.pos1			! if (x >= 0);
	or	%g0,%g0,%o5			! yisint = 0;

	and	%l1,MASK_0x7fffffff,%i2		! hy &= 0x7fffffff;

	sra	%i2,20,%i2			! expy = hy >> 20;

	cmp	%i2,1076			! if (expy >= 0x434);
	bge	.neg1				! if (expy >= 0x434);
	or	%g0,2,%o5			! yisint = 2;

	cmp	%i2,1023			! if (expy < 0x3ff);
	bl	.neg1				! if (expy < 0x3ff);
	or	%g0,0,%o5			! yisint = 0;

	cmp	%i2,1043			! if (expy <= (20 + 0x3ff));
	ble	.small1				! if (expy <= (20 + 0x3ff));
	sub	%i2,1023,%i2			! expy - 0x3ff;

	sub	%g0,%i2,%i2
	add	%i2,52,%i2			! sh = (52 - (expy - 0x3ff);
	srl	%l0,%i2,%l1			! i0 = (ly >> sh);

	sll	%l1,%i2,%l1			! (i0 << sh);

	srl	%l0,%i2,%i2			! i0 = (ly >> sh);
	cmp	%l1,%l0				! if ((i0 << sh) == ly);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;

	ba	.neg1
	nop
.small1:
	sub	%g0,%i2,%i2
	cmp	%l0,%g0				! if (ly != 0);

	add	%i2,20,%i2			! sh = (20 - (expy - 0x3ff);
	bne	.neg1				! if (ly != 0);
	or	%g0,0,%o5			! yisint = 0;

	srl	%l1,%i2,%l0			! i0 = (hy >> sh);

	sll	%l0,%i2,%l0			! (i0 << sh);

	srl	%l1,%i2,%i2			! i0 = (hy >> sh);
	cmp	%l0,%l1				! if ((i0 << sh) == hy);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;
.neg1:
	cmp	%o5,%g0
	be	.u1
	nop
.pos1:
	sll	%o5,11,%o5
	cmp	%l2,MASK_0x000fffff		! if (exp > 0xfffff);

	bg,pt	%icc,.cont1			! if (exp > 0xfffff);
	st	%o5,[%fp+%o7]

	std	%f32,[%fp+tmp5];
	std	%f54,[%fp+tmp6];
	ldd	[%fp+tmp0_hi],%f32
	ldd	[%fp+tmp_mant],%f54

	or	%g0,1074,%o5
	fand	%f32,%f54,%f32			! y0 = vis_fand(x, MMANT);

	sll	%o5,20,%o5
	fxtod	%f32,%f32			! ax = (double) ((long long *) & y0)[0];

	std	%f32,[%fp+tmp0_hi]		! exp = ((unsigned int*) & ax)[0];
	fand	%f32,%f54,%f32			! x = vis_fand(ax, MMANT);

	ld	[%fp+tmp0_hi],%i2		! exp = ((unsigned int*) & ax)[0];
	for	%f32,DONE,%f32			! x = vis_for(x, DONE);

	std	%f32,[%fp+tmp0_hi];
	sub	%i2,%o5,%l2			! exp -= (1023 + 51) << 20;
	and	MASK_0x000fffff,%i2,%i4		! hx = exp & 0xfffff;
	ldd	[%fp+tmp5],%f32
	or	MASK_0x3ff00000,%i4,%i4		! hx |= 0x3ff00000;
	add	%i4,2048,%i4			! hx += 0x800;
	ldd	[%fp+tmp6],%f54
	and	%i4,-4096,%i4			! hx &= 0xfffff000;

	ba	.cont1
	st	%i4,[%fp+tmp1_hi]		! *(int*)&ax = hx;

	.align	16
.update2:
	cmp	counter,1
	ble,pt	%icc,.cont2
	add	py,stridey,%o5

	add	%o5,stridey,%o5
	stx	px,[%fp+tmp_px]

	orcc	%l3,%i2,%g0			! if (x == 0);
	bne,pt	%icc,.nzero2			! if (x == 0);
	stx	%o5,[%fp+tmp_py]
.u2:
	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont2
	or	%g0,1,counter
.nzero2:
	lda	[%o5]%asi,%l1			! ld hy;
	cmp	%l0,%g0				! if (x >= 0);

	lda	[%o5+4]%asi,%l0			! ld ly
	bge,pt	%icc,.pos2			! if (x >= 0);
	or	%g0,%g0,%o5			! yisint = 0;

	and	%l1,MASK_0x7fffffff,%i2		! hy &= 0x7fffffff;

	sra	%i2,20,%i2			! expy = hy >> 20;

	cmp	%i2,1076			! if (expy >= 0x434);
	bge	.neg2				! if (expy >= 0x434);
	or	%g0,2,%o5			! yisint = 2;

	cmp	%i2,1023			! if (expy < 0x3ff);
	bl	.neg2				! if (expy < 0x3ff);
	or	%g0,0,%o5			! yisint = 0;

	cmp	%i2,1043			! if (expy <= (20 + 0x3ff));
	ble	.small2				! if (expy <= (20 + 0x3ff));
	sub	%i2,1023,%i2			! expy - 0x3ff;

	sub	%g0,%i2,%i2
	add	%i2,52,%i2			! sh = (52 - (expy - 0x3ff);
	srl	%l0,%i2,%l1			! i0 = (ly >> sh);

	sll	%l1,%i2,%l1			! (i0 << sh);

	srl	%l0,%i2,%i2			! i0 = (ly >> sh);
	cmp	%l1,%l0				! if ((i0 << sh) == ly);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;

	ba	.neg2
	nop
.small2:
	sub	%g0,%i2,%i2
	cmp	%l0,%g0				! if (ly != 0);

	add	%i2,20,%i2			! sh = (20 - (expy - 0x3ff);
	bne	.neg2				! if (ly != 0);
	or	%g0,0,%o5			! yisint = 0;

	srl	%l1,%i2,%l0			! i0 = (hy >> sh);

	sll	%l0,%i2,%l0			! (i0 << sh);

	srl	%l1,%i2,%i2			! i0 = (hy >> sh);
	cmp	%l0,%l1				! if ((i0 << sh) == hy);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;
.neg2:
	cmp	%o5,%g0
	be	.u2
	nop
.pos2:
	sll	%o5,11,%o5
	cmp	%l3,MASK_0x000fffff		! if (exp > 0xfffff);

	bg,pt	%icc,.cont2			! if (exp > 0xfffff);
	st	%o5,[%fp+%o7]

	ldd	[%fp+tmp_mant],%f54

	or	%g0,1074,%o5
	fand	%f32,%f54,%f32			! y0 = vis_fand(x, MMANT);

	sll	%o5,20,%o5
	fxtod	%f32,%f32			! ax = (double) ((long long *) & y0)[0]

	std	%f32,[%fp+tmp0_hi]		! exp = ((unsigned int*) & ax)[0];
	fand	%f32,%f54,%f32			! x = vis_fand(ax, MMANT);

	ld	[%fp+tmp0_hi],%i2		! exp = ((unsigned int*) & ax)[0];
	for	%f32,DONE,%f32			! x = vis_for(x, DONE);

	sub	%i2,%o5,%l3			! exp -= (1023 + 51) << 20;
	and	MASK_0x000fffff,%i2,%l4		! hx = exp & 0xfffff;
	or	MASK_0x3ff00000,%l4,%l4		! hx |= 0x3ff00000;
	add	%l4,2048,%l4			! hx += 0x800;
	and	%l4,-4096,%l4			! hx &= 0xfffff000;

	ba	.cont2
	st	%l4,[%fp+tmp1_hi]		! *(int*)&ax = hx;

	.align	16
.update3:
	cmp	counter,0
	ble,pt	%icc,.cont3
	sub	px,stridex,%o5

	ld	[%fp+tmp_counter],%l1

	stx	%o5,[%fp+tmp_px]
	add	py,stridey,%o5

	add	%l1,counter,counter
	stx	%o5,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.cont3
	or	%g0,0,counter

	.align	16
.update4:
	cmp	counter,2
	ble,pt	%icc,.cont4
	add	py,stridey,%o5

	add	%o5,stridey,%o5
	add	%o5,stridey,%o5
	stx	px,[%fp+tmp_px]

	orcc	%l2,%i2,%g0			! if (x == 0);
	bne,pt	%icc,.nzero4			! if (x == 0);
	stx	%o5,[%fp+tmp_py]
.u4:
	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont4
	or	%g0,2,counter
.nzero4:
	lda	[%o5]%asi,%l1			! ld hy;
	cmp	%l0,%g0				! if (x >= 0);

	lda	[%o5+4]%asi,%l0			! ld ly
	bge,pt	%icc,.pos4			! if (x >= 0);
	or	%g0,%g0,%o5			! yisint = 0;

	and	%l1,MASK_0x7fffffff,%i2		! hy &= 0x7fffffff;

	sra	%i2,20,%i2			! expy = hy >> 20;

	cmp	%i2,1076			! if (expy >= 0x434);
	bge	.neg4				! if (expy >= 0x434);
	or	%g0,2,%o5			! yisint = 2;

	cmp	%i2,1023			! if (expy < 0x3ff);
	bl	.neg4				! if (expy < 0x3ff);
	or	%g0,0,%o5			! yisint = 2;

	cmp	%i2,1043			! if (expy <= (20 + 0x3ff));
	ble	.small4				! if (expy <= (20 + 0x3ff));
	sub	%i2,1023,%i2			! expy - 0x3ff;

	sub	%g0,%i2,%i2
	add	%i2,52,%i2			! sh = (52 - (expy - 0x3ff);
	srl	%l0,%i2,%l1			! i0 = (ly >> sh);

	sll	%l1,%i2,%l1			! (i0 << sh);

	srl	%l0,%i2,%i2			! i0 = (ly >> sh);
	cmp	%l1,%l0				! if ((i0 << sh) == ly);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;

	ba	.neg4
	nop
.small4:
	sub	%g0,%i2,%i2
	cmp	%l0,%g0				! if (ly != 0);

	add	%i2,20,%i2			! sh = (20 - (expy - 0x3ff);
	bne	.neg4				! if (ly != 0);
	or	%g0,0,%o5			! yisint = 0;

	srl	%l1,%i2,%l0			! i0 = (hy >> sh);

	sll	%l0,%i2,%l0			! (i0 << sh);

	srl	%l1,%i2,%i2			! i0 = (hy >> sh);
	cmp	%l0,%l1				! if ((i0 << sh) == hy);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;
.neg4:
	cmp	%o5,%g0
	be	.u4
	nop
.pos4:
	sll	%o5,11,%o5
	cmp	%l2,MASK_0x000fffff		! if (exp > 0xfffff);

	bg,pt	%icc,.cont4			! if (exp > 0xfffff);
	st	%o5,[%fp+%o7]

	std	%f32,[%fp+tmp5];
	std	%f54,[%fp+tmp6];
	ldd	[%fp+tmp0_hi],%f32
	ldd	[%fp+tmp_mant],%f54

	or	%g0,1074,%o5
	fand	%f32,%f54,%f32			! y0 = vis_fand(x, MMANT);

	sll	%o5,20,%o5
	fxtod	%f32,%f32			! ax = (double) ((long long *) & y0)[0]

	std	%f32,[%fp+tmp0_hi]		! exp = ((unsigned int*) & ax)[0];
	fand	%f32,%f54,%f32			! x = vis_fand(ax, MMANT);

	ld	[%fp+tmp0_hi],%i2		! exp = ((unsigned int*) & ax)[0];
	for	%f32,DONE,%f32			! x = vis_for(x, DONE);

	std	%f32,[%fp+tmp0_hi];
	sub	%i2,%o5,%l2			! exp -= (1023 + 51) << 20;
	and	MASK_0x000fffff,%i2,%i4		! hx = exp & 0xfffff;
	ldd	[%fp+tmp5],%f32
	or	MASK_0x3ff00000,%i4,%i4		! hx |= 0x3ff00000;
	add	%i4,2048,%i4			! hx += 0x800;
	ldd	[%fp+tmp6],%f54
	and	%i4,-4096,%i4			! hx &= 0xfffff000;

	ba	.cont4
	st	%i4,[%fp+tmp1_hi]		! *(int*)&ax = hx;

	.align	16
.update5:
	cmp	counter,1
	ble,pt	%icc,.cont5
	sub	px,stridex,%o5

	ld	[%fp+tmp_counter],%l1

	stx	%o5,[%fp+tmp_px]
	add	py,stridey,%o5

	add	%l1,counter,counter
	stx	%o5,[%fp+tmp_py]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont5
	or	%g0,1,counter

	.align	16
.update6:
	cmp	counter,0
	ble,pt	%icc,.cont6
	fmovd	DONE,%f30

	ld	[%fp+tmp_counter],%o2
	sub	px,stridex,%o5

	sub	%o5,stridex,%o5
	stx	py,[%fp+tmp_py]

	add	%o2,counter,counter
	sub	%o5,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	st	counter,[%fp+tmp_counter]
	ba	.cont6
	or	%g0,0,counter

	.align	16
.update7:
	cmp	counter,0
	ble,pt	%icc,.cont7
	fmovd	DONE,%f30
	sub	px,stridex,%o5

	ld	[%fp+tmp_counter],%o2

	sub	%o5,stridex,%o5
	stx	py,[%fp+tmp_py]

	add	%o2,counter,counter
	sub	%o5,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	st	counter,[%fp+tmp_counter]
	ba	.cont7
	or	%g0,0,counter

	.align	16
.update8:
	cmp	counter,2
	ble,pt	%icc,.cont8
	add	py,stridey,%o5

	add	%o5,stridey,%o5
	stx	px,[%fp+tmp_px]

	orcc	%l3,%i2,%g0			! if (x == 0);
	bne,pt	%icc,.nzero8			! if (x == 0);
	stx	%o5,[%fp+tmp_py]
.u8:
	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont8
	or	%g0,2,counter
.nzero8:
	lda	[%o5]%asi,%l1			! ld hy;
	cmp	%l0,%g0				! if (x >= 0);

	lda	[%o5+4]%asi,%l0			! ld ly
	bge,pt	%icc,.pos8			! if (x >= 0);
	or	%g0,%g0,%o5			! yisint = 0;

	and	%l1,MASK_0x7fffffff,%i2		! hy &= 0x7fffffff;

	sra	%i2,20,%i2			! expy = hy >> 20;

	cmp	%i2,1076			! if (expy >= 0x434);
	bge	.pos8				! if (expy >= 0x434);
	or	%g0,2,%o5			! yisint = 2;

	cmp	%i2,1023			! if (expy < 0x3ff);
	bl	.neg8				! if (expy < 0x3ff);
	or	%g0,0,%o5			! yisint = 0;

	cmp	%i2,1043			! if (expy <= (20 + 0x3ff));
	ble	.small8				! if (expy <= (20 + 0x3ff));
	sub	%i2,1023,%i2			! expy - 0x3ff;

	sub	%g0,%i2,%i2
	add	%i2,52,%i2			! sh = (52 - (expy - 0x3ff);
	srl	%l0,%i2,%l1			! i0 = (ly >> sh);

	sll	%l1,%i2,%l1			! (i0 << sh);

	srl	%l0,%i2,%i2			! i0 = (ly >> sh);
	cmp	%l1,%l0				! if ((i0 << sh) == ly);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;

	ba	.neg8
	nop
.small8:
	sub	%g0,%i2,%i2
	cmp	%l0,%g0				! if (ly != 0);

	add	%i2,20,%i2			! sh = (20 - (expy - 0x3ff);
	bne	.neg8				! if (ly != 0);
	or	%g0,0,%o5			! yisint = 0;

	srl	%l1,%i2,%l0			! i0 = (hy >> sh);

	sll	%l0,%i2,%l0			! (i0 << sh);

	srl	%l1,%i2,%i2			! i0 = (hy >> sh);
	cmp	%l0,%l1				! if ((i0 << sh) == hy);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;
.neg8:
	cmp	%o5,%g0
	be	.u8
	nop
.pos8:
	sll	%o5,11,%o5
	cmp	%l3,MASK_0x000fffff		! if (exp > 0xfffff);

	bg,pt	%icc,.cont8			! if (exp > 0xfffff);
	st	%o5,[%fp+%o7]

	ldd	[%fp+tmp_mant],%f54

	or	%g0,1074,%o5
	fand	%f32,%f54,%f32			! y0 = vis_fand(x, MMANT);

	sll	%o5,20,%o5
	fxtod	%f32,%f32			! ax = (double) ((long long *) & y0)[0]

	std	%f32,[%fp+tmp0_hi]		! exp = ((unsigned int*) & ax)[0];
	fand	%f32,%f54,%f32			! x = vis_fand(ax, MMANT);

	ld	[%fp+tmp0_hi],%i2		! exp = ((unsigned int*) & ax)[0];
	for	%f32,DONE,%f32			! x = vis_for(x, DONE);

	sub	%i2,%o5,%l3			! exp -= (1023 + 51) << 20;
	and	MASK_0x000fffff,%i2,%l4		! hx &= 0xfffff;
	or	MASK_0x3ff00000,%l4,%l4		! hx |= 0x3ff00000;
	add	%l4,2048,%l4			! hx += 0x800;
	and	%l4,-4096,%l4			! hx &= 0xfffff000;

	ba	.cont8
	st	%l4,[%fp+tmp1_hi]		! *(int*)&ax = hx;

	.align	16
.update9:
	cmp	counter,1
	ble,pt	%icc,.cont9
	sub	px,stridex,%o5

	ld	[%fp+tmp_counter],%l1

	stx	%o5,[%fp+tmp_px]
	add	py,stridey,%o5

	add	%l1,counter,counter
	stx	%o5,[%fp+tmp_py]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont9
	or	%g0,1,counter

	.align	16
.update10:
	cmp	counter,0
	ble,pt	%icc,.cont10
	fmovd	DONE,%f30

	ld	[%fp+tmp_counter],%o2
	sub	px,stridex,%o5

	sub	%o5,stridex,%o5
	stx	py,[%fp+tmp_py]

	add	%o2,counter,counter
	sub	%o5,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	st	counter,[%fp+tmp_counter]
	ba	.cont10
	or	%g0,0,counter

	.align	16
.update11:
	cmp	counter,0
	ble,pt	%icc,.cont11
	fmovd	DONE,%f30

	ld	[%fp+tmp_counter],%o2
	sub	px,stridex,%o5

	sub	%o5,stridex,%o5
	stx	py,[%fp+tmp_py]

	add	%o2,counter,counter
	sub	%o5,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	st	counter,[%fp+tmp_counter]
	ba	.cont11
	or	%g0,0,counter

	.align	16
.update12:
	cmp	counter,3
	ble,pt	%icc,.cont12
	add	py,stridey,%o5

	add	%o5,stridey,%o5
	stx	px,[%fp+tmp_px]

	add	%o5,stridey,%o5
	orcc	%l2,%i2,%g0			! if (x == 0);

	bne,pt	%icc,.nzero12			! if (x == 0);
	stx	%o5,[%fp+tmp_py]
.u12:
	sub	counter,3,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont12
	or	%g0,3,counter
.nzero12:
	lda	[%o5]%asi,%l1			! ld hy;
	cmp	%l0,%g0				! if (x >= 0);

	lda	[%o5+4]%asi,%l0			! ld ly
	bge,pt	%icc,.pos12			! if (x >= 0);
	or	%g0,%g0,%o5			! yisint = 0;

	and	%l1,MASK_0x7fffffff,%i2		! hy &= 0x7fffffff;

	sra	%i2,20,%i2			! expy = hy >> 20;

	cmp	%i2,1076			! if (expy >= 0x434);
	bge	.neg12				! if (expy >= 0x434);
	or	%g0,2,%o5			! yisint = 2;

	cmp	%i2,1023			! if (expy < 0x3ff);
	bl	.neg12				! if (expy < 0x3ff);
	or	%g0,0,%o5			! yisint = 0;

	cmp	%i2,1043			! if (expy <= (20 + 0x3ff));
	ble	.small12			! if (expy <= (20 + 0x3ff));
	sub	%i2,1023,%i2			! expy - 0x3ff;

	sub	%g0,%i2,%i2
	add	%i2,52,%i2			! sh = (52 - (expy - 0x3ff);
	srl	%l0,%i2,%l1			! i0 = (ly >> sh);

	sll	%l1,%i2,%l1			! (i0 << sh);

	srl	%l0,%i2,%i2			! i0 = (ly >> sh);
	cmp	%l1,%l0				! if ((i0 << sh) == ly);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;

	ba	.neg12
	nop
.small12:
	sub	%g0,%i2,%i2
	cmp	%l0,%g0				! if (ly != 0);

	add	%i2,20,%i2			! sh = (20 - (expy - 0x3ff);
	bne	.neg12				! if (ly != 0);
	or	%g0,0,%o5			! yisint = 0;

	srl	%l1,%i2,%l0			! i0 = (hy >> sh);

	sll	%l0,%i2,%l0			! (i0 << sh);

	srl	%l1,%i2,%i2			! i0 = (hy >> sh);
	cmp	%l0,%l1				! if ((i0 << sh) == hy);

	and	%i2,1,%i2			! i0 &= 1;

	sub	%g0,%i2,%i2
	add	%i2,2,%i2			! i0 = 2 - i0;

	move	%icc,%i2,%o5			! yisint = i0;
.neg12:
	cmp	%o5,%g0
	be	.u12
	nop
.pos12:
	sll	%o5,11,%o5
	cmp	%l2,MASK_0x000fffff		! y0 = vis_fand(x, MMANT);

	bg,pt	%icc,.cont12			! y0 = vis_fand(x, MMANT);
	st	%o5,[%fp+%o7]

	std	%f32,[%fp+tmp5];
	std	%f54,[%fp+tmp6];
	ldd	[%fp+tmp0_hi],%f32
	ldd	[%fp+tmp_mant],%f54

	or	%g0,1074,%o5
	fand	%f32,%f54,%f32			! y0 = vis_fand(x, MMANT);

	sll	%o5,20,%o5
	fxtod	%f32,%f32			! ax = (double) ((long long *) & y0)[0]

	std	%f32,[%fp+tmp0_hi]		! exp = ((unsigned int*) & ax)[0];
	fand	%f32,%f54,%f32			! x = vis_fand(ax, MMANT);

	ld	[%fp+tmp0_hi],%i2		! exp = ((unsigned int*) & ax)[0];
	for	%f32,DONE,%f32			! x = vis_for(x, DONE);

	std	%f32,[%fp+tmp0_hi];
	sub	%i2,%o5,%l2			! exp -= (1023 + 51) << 20;
	and	MASK_0x000fffff,%i2,%i4		! hx &= 0xfffff;
	ldd	[%fp+tmp5],%f32
	or	MASK_0x3ff00000,%i4,%i4		! hx |= 0x3ff00000;
	add	%i4,2048,%i4			! hx += 0x800;
	ldd	[%fp+tmp6],%f54
	and	%i4,-4096,%i4			! hx &= 0xfffff000;

	ba	.cont12
	st	%i4,[%fp+tmp1_hi]		! *(int*)&ax = hx;

	.align	16
.update13:
	cmp	counter,2
	ble,pt	%icc,.cont13
	sub	px,stridex,%o5

	ld	[%fp+tmp_counter],%l1

	stx	%o5,[%fp+tmp_px]
	add	py,stridey,%o5

	add	%l1,counter,counter
	stx	%o5,[%fp+tmp_py]

	sub	counter,2,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont13
	or	%g0,2,counter

	.align	16
.update14:
	cmp	counter,1
	ble,pt	%icc,.cont14
	fmovd	DONE,%f30

	ld	[%fp+tmp_counter],%o2
	sub	px,stridex,%o5

	sub	%o5,stridex,%o5
	stx	py,[%fp+tmp_py]

	add	%o2,counter,counter
	sub	%o5,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont14
	or	%g0,1,counter

	.align	16
.update15:
	cmp	counter,1
	ble,pt	%icc,.cont15
	fmovd	DONE,%f30

	sub	px,stridex,%o5

	ld	[%fp+tmp_counter],%o2
	sub	%o5,stridex,%o5
	stx	py,[%fp+tmp_py]

	add	%o2,counter,counter
	sub	%o5,stridex,%o5
	stx	%o5,[%fp+tmp_px]

	sub	counter,1,counter
	st	counter,[%fp+tmp_counter]
	ba	.cont15
	or	%g0,1,counter

	.align	16
.spec0:
	lda	[py+4]%asi,%o5			! ld ly;
	lda	[px]%asi,%f16			! y0 = *px;
	lda	[px+4]%asi,%f17			! y0 = *px;
	orcc	%l1,%o5,%g0			! if (hy | ly) != 0;

	bne,pn	%icc,1f
	sethi	%hi(0x7ff00000),%o5

	st	DONE_HI,[pz]
	ba	.update_point
	st	DONE_LO,[pz+4]
1:
	cmp	%l3,%o5				! if (hx > 0x7ff00000);
	bgu,a,pn	%icc,6f			! if (hx > 0x7ff00000);
	fmuld	%f16,%f16,%f16			! *pz = y0 * y0;

	bne,pt	%icc,2f				! if (hx != 0x7ff00000);
	orcc	%l3,%i2,%g0			! if (hx | lx) != 0;

	cmp	%i2,0				! if (lx) != 0;
	bne,pn	%icc,5f				! if (lx) != 0;
	srl	%o2,31,%o5			! sy;

	st	%l3,[pz]			! ((int*)pz)[0] = hx;
	ba	3f
	cmp	%o5,0				! if (sy == 0);
2:
	bne,pt	%icc,4f				! if (hx | lx) != 0;
	srl	%l0,31,%o5			! sx;

	st	%l3,[pz]			! ((int*)pz)[0] = hx;
	srl	%o2,31,%o5			! sy;
	cmp	%o5,0				! if (sy == 0);
3:
	be,pt	%icc,.update_point		! if (sy == 0);
	st	%i2,[pz+4]			! ((int*)pz)[1] = lx;

	ld	[pz],%f16			! *pz;
	ld	[pz+4],%f17			! *pz;
	fdivd	DONE,%f16,%f16			! *pz = DONE / *pz;

	st	%f16,[pz]
	ba	.update_point
	st	%f17,[pz+4]
4:
	cmp	%o5,0				! if (sx == 0);
	bne,a,pt	%icc,1f
	nop

	st	DONE_HI,[pz]			! *pz = DONE;
	ba	.update_point
	st	DONE_LO,[pz+4]			! *pz = DONE;
1:
	fdivd	DZERO,DZERO,%f16		! *pz = DZERO / DZERO;
	st	%f16,[pz]
	ba	.update_point
	st	%f17,[pz+4]
5:
	fmuld	%f16,%f16,%f16			! *pz = y0 * y0;
6:
	st	%f16,[pz]
	ba	.update_point
	st	%f17,[pz+4]

	.align	16
.spec1:
	lda	[px]%asi,%f14			! y0 = *px;
	lda	[px+4]%asi,%f15			! y0 = *px;
	sethi	%hi(0x7ff00000),%o5
	lda	[py+4]%asi,%i4			! ld ly;
	srl	%o2,31,%o2			! sy
	cmp	%l3,%o5				! if (hx >= 0x7ff00000);
	bcc,pn	%icc,3f
	nop

	cmp	%l1,%o5				! if (hy > 0x7ff00000);
	bgu,a,pt	%icc,.spec1_nan_inf	! if (hy > 0x7ff00000);
	lda	[py]%asi,%f16			! ld y

	bne,a,pt	%icc,1f			! if (hy != 0x7ff00000);
	cmp	%i2,0				! if (lx != 0);

	ba	2f				! if (hy == 0x7ff00000);
	cmp	%i4,0				! if (ly != 0);
1:
	bne,pt	%icc,7f				! if (lx != 0);
	nop

	cmp	%l3,0				! if (hx == 0);
	be,a,pt	%icc,6f				! if (hx == 0);
	st	%l3,[pz]			! ((int*)pz)[0] = hx;

	cmp	%l3,MASK_0x3ff00000		! if (hx == 0x3ff00000);
	be,a,pn	%icc,6f				! if (hx == 0x3ff00000);
	st	%l3,[pz]			! ((int*)pz)[0] = hx;

	ba	5f
	cmp	%l3,%o5				! if (hx != 0x7ff00000);
3:
	bgu,a,pt	%icc,.spec1_nan_inf	! if (hx > 0x7ff00000);
	lda	[py]%asi,%f16			! ld y

	bne,a,pn	%icc,1f			! if (hx != 0x7ff00000);
	cmp	%l1,%o5				! if (hy > 0x7ff00000);

	cmp	%i2,0				! if (lx != 0);
	bne,a,pt	%icc,.spec1_nan_inf	! if (lx != 0);
	lda	[py]%asi,%f16			! ld y

	cmp	%l1,%o5				! if (hy > 0x7ff00000);
1:
	bgu,a,pt	%icc,.spec1_nan_inf	! if (hy > 0x7ff00000);
	lda	[py]%asi,%f16			! ld y

	bne,pn	%icc,3f				! if (hy != 0x7ff00000);
	nop

	cmp	%i4,0				! if (ly != 0);
2:
	bne,a,pn	%icc,.spec1_nan_inf	! if (ly != 0);
	lda	[py]%asi,%f16			! ld y

	cmp	%l3,MASK_0x3ff00000		! if (hx != 0x3ff00000);
	bne,pn	%icc,1f				! if (hx != 0x3ff00000);
	cmp	%i2,0				! if (lx != 0);

	bne,pn	%icc,1f				! if (lx != 0);
	nop

	ld	[py],%f16			! ld y
	ld	[py+4],%f17			! ld y
	fzero	%f14
	fmuld	%f16,%f14,%f14			! *pz = *py * 0.0;
	st	%f14,[pz]
	ba	.update_point
	st	%f15,[pz+4]
1:
	sub	%l3,MASK_0x3ff00000,%o7		! (hx - 0x3ff00000);
	srlx	%o7,63,%l2			! (hx - 0x3ff00000) >> 63;

	cmp	%l2,%o2				! if ((hx < 0x3ff00000) == sy)
	be,a,pn	%icc,1f				! if ((hx < 0x3ff00000) == sy)
	st	%l1,[pz]			! ((int*)pz)[0] = hy;

	st	DZERO_HI,[pz]			! *pz = DZERO;
	ba	.update_point
	st	DZERO_LO,[pz+4]			! *pz = DZERO;
1:
	ba	.update_point
	st	%i4,[pz+4]			! ((int*)pz)[0] = ly;
3:
	cmp	%o0,1086			! if (expy >= 0x43e);
	bge,pn	%icc,4f				! if (expy >= 0x43e)
	nop

	srl	%l0,31,%l0			! sx;
	cmp	%l0,0				! if (sx == 0);
	be,pn	%icc,2f
	or	%g0,0,%l4

	cmp	%o0,1076			! if (expy >= 0x434);

	bge,pn	%icc,2f				! if (expy >= 0x434);
	or	%g0,2,%l4			! yisint = 2;

	cmp	%o0,1023			! if (expy < 0x3ff);
	bl,a,pn	%icc,2f				! if (expy < 0x3ff);
	or	%g0,0,%l4			! yisint = 0;

	cmp	%o0,1043			! if (expy <= (20 + 0x3ff));
	ble,pn	%icc,1f
	sub	%o0,1023,%l2			! (expy - 0x3ff);

	sub	%g0,%l2,%l2			! 0 - (expy - 0x3ff);
	add	%l2,52,%l2			! sh = 52 - (expy - 0x3ff);
	srl	%i4,%l2,%o0			! i0 = ly >> sh;
	sll	%o0,%l2,%l2			! i0 << sh;
	cmp	%l2,%i4				! if ((i0 << sh) != ly);
	bne,a,pn	%icc,2f			! if ((i0 << sh) != ly);
	or	%g0,0,%l4			! yisint = 0;

	and	%o0,1,%o0			! i0 &= 1;
	sub	%g0,%o0,%o0

	ba	2f
	add	%o0,2,%l4			! yisint = 2 - (i0 & 1);
1:
	cmp	%i4,0				! if (ly != 0)
	bne,a,pn	%icc,2f			! if (ly != 0)
	or	%g0,0,%l4			! yisint = 0;

	sub	%o0,1023,%l2			! (expy - 0x3ff);
	sub	%g0,%l2,%l2			! 0 - (expy - 0x3ff);
	add	%l2,20,%l2			! sh = 20 - (expy - 0x3ff);
	srl	%l1,%l2,%o0			! i0 = hy >> sh;
	sll	%o0,%l2,%l2			! i0 << sh;
	cmp	%l2,%l1				! if ((i0 << sh) != hy);
	bne,a,pn	%icc,2f			! if ((i0 << sh) != hy);
	or	%g0,0,%l4			! yisint = 0;

	and	%o0,1,%o0			! i0 &= 1;
	sub	%g0,%o0,%o0
	add	%o0,2,%l4			! yisint = 2 - (i0 & 1);
2:
	cmp	%o2,0				! if (sy == 0);
	sll	%l4,31,%l4			! yisint << 31;
	be,pt	%icc,1f				! if (sy == 0);
	add	%l3,%l4,%l3			! hx += yisint << 31;

	or	%g0,%l4,%l3			! hx = yisint << 31;
	or	%g0,0,%i2			! lx = 0;
1:
	st	%l3,[pz]			! ((int*)pz)[0] = hx;
	ba	.update_point
	st	%i2,[pz+4]			! ((int*)pz)[1] = lx;
4:
	cmp	%i2,0				! if (lx != 0);
	bne,pn	%icc,7f				! if (lx != 0);
	nop

	cmp	%l3,%o5				! if (hx != 0x7ff00000);
5:
	bne,pn	%icc,7f				! if (hx != 0x7ff00000);
	nop

	st	%l3,[pz]			! ((int*)pz)[0] = hx;
6:
	cmp	%o2,0				! if (sy == 0);
	be,pt	%icc,.update_point
	st	%i2,[pz+4]			! ((int*)pz)[1] = lx;

	ld	[pz],%f14			! ld *pz;
	ld	[pz+4],%f15			! ld *pz;
	fdivd	DONE,%f14,%f14			! *pz = DONE / *pz;
	st	%f14,[pz]
	ba	.update_point
	st	%f15,[pz+4]
7:
	sub	%l3,MASK_0x3ff00000,%o7		! hx - 0x3ff00000;
	srlx	%o7,63,%l2			! (hx - 0x3ff00000) >> 63;
	cmp	%l2,%o2				! if (hx < 0x3ff00000) == sy);
	be,a,pn	%icc,1f				! if (hx < 0x3ff00000) == sy);
	ldd	[EXPTBL-ind_HUGE],%f14		! y0 = _HUGE;

	ldd	[EXPTBL-ind_TINY],%f14		! y0 = _TINY;
1:
	fmuld	%f14,%f14,%f14			! *pz = y0 * y0

	st	%f14,[pz]
	ba .update_point
	st	%f15,[pz+4]

	.align	16
.spec1_nan_inf:
	lda	[py+4]%asi,%f17			! ld y
	fmuld 	%f14,%f16,%f16              	! *pz = *px * *py
	st	%f16,[pz]
	ba 	.update_point
	st	%f17,[pz+4]


	.align	16
.update_point:
	add 	px,stridex,px
	ba 	.begin1
	add 	py,stridey,py

	.align  64
.stridex_zero:

	sra	stridez,0,stridez
	ld	[%i1],%f18			! y0 = px[0];
	ld	[%i1+4],%f19			! y0 = px[0];

	sra	%i4,0,stridey
	sethi	%hi(0xffc00),MASK_0x000fffff
	ldd	[%l0+80],%f12			! ld MMANT

	sllx	stridez,3,stridez
	add	MASK_0x000fffff,0x3ff,MASK_0x000fffff
	ldd	[%l0+8],%f56			! ld  DONE

	sllx	stridey,3,stridey
	ldd	[%l0+88],%f14			! ld  MROUND

	ldd	[%l0+96],%f16			! ld  MHI20
	cmp	%o0,MASK_0x000fffff		! if (exp <= 0xfffff)

	bg,pt	%icc,1f
	srl	%o0,20,%o0			! exp = (exp >> 20);

	fxtod	%f18,%f18			! y0 = (double) ((long long *) & y0)[0];
	std	%f18,[%fp+tmp0_hi]		! exp = ((unsigned int*) & y0)[0];
	or	%g0,1074,%i2
	ld	[%fp+tmp0_hi],%o0		! exp = ((unsigned int*) & y0)[0];
	srl	%o0,20,%o0			! exp = (exp >> 20);
	sub	%o0,%i2,%o0			! exp -= (1023 + 51) << 20;
1:
	ldd	[%l0+24],MHI32
	sub	%o0,2046,%l5			! exp = exp - 2046;
	fand	%f18,%f12,%f18			! x = vis_fand(y0, MMANT);

	ldd	[%l0+48],%f10			! ld KA1
	for	%f18,%f56,%f18			! x = vis_for(x, DONE);

	ldd	[EXPTBL-ind_HI],%f28		! ld KA1_HI
	fpadd32	%f18,%f14,%f44			! ax = vis_fpadd32(x, MROUND);

	ldd	[%l0+32],%f46			! ld KA5
	fand	%f44,%f16,%f60			! ax = vis_fand(ax, MHI20);

	std	%f60,[%fp+tmp0_hi]		! itmp0 = (hx >> 20);
	faddd	%f18,%f60,%f50			! ux = x + ax;

	ldd	[EXPTBL-ind_LO],%f52		! ld KA1_LO
	fsubd	%f18,%f60,%f30			! u = x - ax;

	ld	[%fp+tmp0_hi],%i2		! itmp0 = (hx >> 20);
	fdivd	%f56,%f50,%f56			! yd = DONE / ux;
	fand	%f50,MHI32,%f50			! ux = vis_fand(ux, MHI32);

	srl	%i2,20,%l3			! itmp0 = (hx >> 20);
	ldd	[%l0+40],%f26			! ld KA3

	srl	%i2,8,%i2			! i = (hx >> 8);
	add	%l5,%l3,%l5			! exp += itmp0;

	and	%i2,4080,%o3			! i = i & 0xff0;
	sll	%l5,8,%l3			! itmp0 = exp << 8;
	st	%l3,[%fp+tmp1_hi]		! (double)itmp0;
	fsubd	%f50,%f60,%f60			! dtmp0 = (ux - ax);

	add	%o3,8,%i2
	ldd	[%o3+LOGTBL],%f58		! y = *(double *)((char*)__mt_constlog2 + i);

	ldd	[%i2+LOGTBL],%f20		! dtmp0 = *(double *)((char*)__mt_constlog2 + i + 8);

	ld	[%fp+tmp1_hi],%f8		! (double)itmp0;

	fitod	%f8,%f62			! (double)itmp0;

	faddd	%f58,%f62,%f22			! y += (double)itmp0;

	fsubd	%f18,%f60,%f62			! s_l = (x - dtmp0);
	fmuld	%f30,%f56,%f16			! s = u * yd;

	fmuld	%f10,%f56,%f8			! dtmp0 = KA1 * yd;
	fand	%f16,MHI32,%f58			! s_h = vis_fand(s, MHI32);

	ldd	[%l0+56],HTHRESH
	fmuld	%f16,%f16,%f18			! y = s * s;

	ldd	[%l0+64],LTHRESH
	fmuld	%f58,%f50,%f60			! dtmp0 = s_h * ux;

	ldd	[%l0+72],XKB4
	fmuld	%f28,%f58,%f50			! yd = KA1_HI * s_h;

	ldd	[EXPTBL-ind_KB1],XKB1
	fmuld	%f46,%f18,%f56			! dtmp8 = KA5 * y;

	ldd	[EXPTBL-ind_KB2],XKB2
	fmuld	%f58,%f62,%f46			! dtmp1 = s_h * s_l;
	fsubd	%f30,%f60,%f62			! s_l = u - dtmp0;

	ldd	[EXPTBL-ind_KB3],XKB3
	fmuld	%f52,%f58,%f10			! dtmp1 = KA1_LO * s_h;
	faddd	%f22,%f50,%f28			! m_h = y + yd;

	ldd	[EXPTBL-ind_KB5],XKB5
	faddd	%f56,%f26,%f58			! dtmp8 = dtmp8 + KA3;

	add	EXPTBL,8,EXPTBL_P8
	fsubd	%f62,%f46,%f46			! s_l -= dtmp1;

	fsubd	%f28,%f22,%f60			! dtmp2 = m_h - y;

	st	%g0,[%fp+tmp0_lo]		! *((int*)&dtmp0 + 1) = 0;
	faddd	%f20,%f10,%f56			! dtmp0 += dtmp1;

	st	%g0,[%fp+tmp1_lo]		! *((int*)&dtmp0 + 1) = 0;
	fmuld	%f58,%f18,%f18			! dtmp8 = dtmp8 * y;

	st	%g0,[%fp+tmp2_lo]		! *((int*)&dtmp0 + 1) = 0;
	fmuld	%f8,%f46,%f62			! s_l = dtmp0 * s_l;

	fsubd	%f60,%f50,%f10			! dtmp2 -= yd;

	fmuld	%f18,%f16,%f58			! s = dtmp8 * s;

	fsubd	%f10,%f62,%f46			! dtmp2 -= s_l;

	fsubd	%f58,%f46,%f50			! y = s - dtmp2;

	faddd	%f50,%f56,%f60			! y += dtmp0;

	faddd	%f60,%f28,%f18			! dtmp0 = y + m_h;

	fand	%f18,MHI32,s_h			! s_h = vis_fand(dtmp0, MHI32);

	fsubd	s_h,%f28,%f62			! dtmp0 = (s_h - m_h);

	fsubd	%f60,%f62,yr			! yr = y - dtmp0;

.xbegin:
	ld	[%fp+tmp_counter],counter
	ldx	[%fp+tmp_py],py
	st	%g0,[%fp+tmp_counter]
.xbegin1:
	subcc	counter,1,counter
	bneg,pn	%icc,.end
	nop

	lda	[py]0x82,%l2			! (Y0_3) hy = *py;

	lda	[py]0x82,%f18			! (Y0_3) yd = *py;
	lda	[py+4]%asi,%f19			! (Y0_3) yd = *py;

	sra	%l2,20,%l5			! (Y0_3) expy = hy >> 20;

	and	%l5,0x7ff,%l5			! (Y0_3) expy &= 0x7ff;

	cmp	%l5,959				! (Y0_3) if (expy < 0x3fb);

	bl,pn	%icc,.xspec0			! (Y0_3) if (expy < 0x3fb);
	nop

	cmp	%l5,1086			! (Y0_2) if (expy >= 0x43e);

	bge,pn	%icc,.xspec1			! (Y0_2) if (expy >= 0x43e);
	nop

	add	py,stridey,py			! y += stridey;
	fand	%f18,MHI32,%f12			! (Y0_2) s = vis_fand(yd, MHI32);

	lda	[py]0x82,%l5			! (Y1_2) hy = *py;

	lda	[py]0x82,%f10			! (Y1_2) yd = *py;
	lda	[py+4]%asi,%f11			! (Y1_2) yd = *py;

	sra	%l5,20,%l5			! (Y1_2) expy = hy >> 20;

	and	%l5,0x7ff,%l5			! (Y1_2) expy &= 0x7ff;

	cmp	%l5,959				! (Y1_2) if (expy < 0x3fb);
	add	py,stridey,py			! y += stridey;
	fmuld	s_h,%f12,%f50			! (Y0_2) s = s_h * s;
	fsubd	%f18,%f12,%f56			! (Y0_2) dtmp0 = (yd - s);

	fmuld	%f18,yr,%f26			! (Y0_2) dtmp1 = yd * yr;
	bl,pn	%icc,.xupdate0			! (Y1_2) if (expy < 0x3fb);
	nop
.xcont0:
	cmp	%l5,1086			! (Y1_2) if (expy >= 0x43e);
	bge,pn	%icc,.xupdate1			! (Y0_2) if (expy >= 0x43e);
	nop
.xcont1:
	fmuld	%f56,s_h,%f58			! (Y0_2) dtmp0 *= s_h;
	fand	%f10,MHI32,%f12			! (Y1_2) s = vis_fand(yd, MHI32);

	fcmped	%fcc0,%f50,HTHRESH		! (Y0_2) if (s > HTHRESH);

	faddd	%f58,%f26,%f48			! (Y0_2) yd = dtmp0 + dtmp1;

	lda	[py]0x82,%l5			! (Y2_2) hy = *py;
	fmovdg	%fcc0,HTHRESH,%f50		! (Y0_2) s = HTHRESH;

	fmovdg	%fcc0,DZERO,%f48		! (Y0_2) yd = DZERO;

	fcmped	%fcc1,%f50,LTHRESH		! (Y0_2) if (s < LTHRESH);

	lda	[py]0x82,%f14			! (Y2_2) yd = *py;
	lda	[py+4]%asi,%f15			! (Y2_2) yd = *py;

	sra	%l5,20,%l5			! (Y2_2) expy = hy >> 20;

	fmovdl	%fcc1,DZERO,%f48		! (Y0_2) yd = DZERO;

	add	py,stridey,py			! y += stridey;
	and	%l5,0x7ff,%l5			! (Y2_2) expy &= 0x7ff;
	fmovdl	%fcc1,LTHRESH,%f50		! (Y0_2) s = LTHRESH;

	cmp	%l5,959				! (Y2_2) if (expy < 0x3fb);

	fmuld	s_h,%f12,%f16			! (Y1_2) s = s_h * s;
	bl,pn	%icc,.xupdate2			! (Y2_2) if (expy < 0x3fb);
	fsubd	%f10,%f12,%f56			! (Y1_2) dtmp0 = (yd - s);
.xcont2:
	cmp	%l5,1086			! (Y2_2) if (expy >= 0x43e);
	fmuld	%f10,yr,%f8			! (Y1_2) dtmp1 = yd * yr;
	faddd	%f50,%f48,%f28			! (Y0_2) dtmp0 = (s + yd);

	lda	[py]0x82,%l5			! (Y0_3) hy = *py;
	bge,pn	%icc,.xupdate3			! (Y2_2) if (expy >= 0x43e);
	nop
.xcont3:
	fmuld	%f56,s_h,%f58			! (Y1_2) dtmp0 *= s_h;
	fand	%f14,MHI32,%f44			! (Y2_2) s = vis_fand(yd, MHI32);

	fcmped	%fcc0,%f16,HTHRESH		! (Y1_2) if (s > HTHRESH);

	fdtoi	%f28,%f3			! (Y0_2) u = (double)(int)dtmp0;

	st	%f3,[%fp+tmp3]			! (Y0_2) ind = (int)dtmp0;

	faddd	%f58,%f8,%f10			! (Y1_2) yd = dtmp0 + dtmp1;

	lda	[py]0x82,%f18			! (Y0_3) yd = *py;
	lda	[py+4]%asi,%f19			! (Y0_3) yd = *py;
	fmovdg	%fcc0,HTHRESH,%f16		! (Y1_2) s = HTHRESH;

	fitod	%f3,%f58			! (Y0_2) u = (double)(int)dtmp0;

	fmovdg	%fcc0,DZERO,%f10		! (Y1_2) yd = DZERO;

	sra	%l5,20,%l5			! (Y0_3) expy = hy >> 20;
	fcmped	%fcc1,%f16,LTHRESH		! (Y1_2) if (s < LTHRESH);

	and	%l5,0x7ff,%l5			! (Y0_3) expy &= 0x7ff;
	fsubd	%f50,%f58,%f54			! (Y0_2) y = s - u;

	cmp	%l5,959				! (Y0_3) if (expy < 0x3fb);

	bl,pn	%icc,.xupdate4			! (Y0_3) if (expy < 0x3fb);
	nop
.xcont4:
	fmovdl	%fcc1,DZERO,%f10		! (Y1_2) yd = DZERO;

	fmovdl	%fcc1,LTHRESH,%f16		! (Y1_2) s = LTHRESH;

	faddd	%f54,%f48,%f54			! (Y0_2) y = y + yd;

	ld	[%fp+tmp3],%o2			! (Y0_2) ind = (int)dtmp0;


	fsubd	%f14,%f44,%f50			! (Y2_1) dtmp0 = (yd - s);

	cmp	%l5,1086			! (Y0_2) if (expy >= 0x43e);

	fmuld	s_h,%f44,%f44			! (Y2_1) s = s_h * s;
	bge,pn	%icc,.xupdate5			! (Y0_2) if (expy >= 0x43e);
	faddd	%f16,%f10,%f22			! (Y1_1) dtmp0 = (s + yd);
.xcont5:
	sra	%o2,8,%o0			! (Y0_1) ind >>= 8;
	add	py,stridey,py			! y += stridey;
	fmuld	%f14,yr,%f20			! (Y2_1) dtmp1 = yd * yr;

	add	%o0,1021,%i1			! (Y0_1) eflag = (ind + 1021);
	fmuld	XKB5,%f54,%f48			! (Y0_1) dtmp0 = XKB5 * y;

	sub	%g0,%o0,%o3			! (Y0_1) gflag = (1022 - ind);
	fmuld	%f50,s_h,%f52			! (Y2_1) dtmp0 *= s_h;
	fand	%f18,MHI32,%f12			! (Y0_2) s = vis_fand(yd, MHI32);

	sra	%i1,31,%o1			! (Y0_1) eflag = eflag >> 31;
	add	%o3,1022,%l0			! (Y0_1) gflag = (1022 - ind);
	fcmped	%fcc0,%f44,HTHRESH		! (Y2_1) if (s > HTHRESH);

	sra	%l0,31,%o4			! (Y0_1) gflag = gflag >> 31;
	and	%o1,54,%i4			! (Y0_1) itmp0 = 54 & eflag;
	fdtoi	%f22,%f4			! (Y1_1) u = (double)(int)dtmp0;

	add	%o0,%i4,%i2			! (Y0_1) ind = ind + itmp0;
	and	%o4,52,%l3			! (Y0_1) itmp1 = 52 & gflag;
	st	%f4,[%fp+tmp4]			! (Y1_1) ind = (int)dtmp0;
	faddd	%f48,XKB4,%f60			! (Y0_1) dtmp1 = dtmp0 + XKB4;

	sub	%i2,%l3,%l2			! (Y0_1) ind = ind - itmp1;
	sub	%o1,%o4,%o4			! (Y0_1) ind = eflag - gflag;
	faddd	%f52,%f20,%f62			! (Y2_1) yd = dtmp0 + dtmp1;

	sll	%l2,20,%o3			! (Y0_1) ind <<= 20;
	lda	[py]0x82,%l5			! (Y1_2) hy = *py;
	fmovdg	%fcc0,HTHRESH,%f44		! (Y2_1) s = HTHRESH;

	st	%o3,[%fp+tmp0_hi]		! (Y0_1) *(int*)&dtmp0 = ind;
	fitod	%f4,%f48			! (Y1_1) u = (double)(int)dtmp0;

	fmuld	%f60,%f54,%f60			! (Y0_1) dtmp2 = dtmp1 * y;

	lda	[py]0x82,%f20			! (Y1_2) yd = *py;
	lda	[py+4]%asi,%f21			! (Y1_2) yd = *py;
	fmovdg	%fcc0,DZERO,%f62		! (Y2_1) yd = DZERO;

	fcmped	%fcc1,%f44,LTHRESH		! (Y2_1) if (s < LTHRESH);

	fsubd	%f16,%f48,%f50			! (Y1_1) y = s - u;

	faddd	%f60,XKB3,%f60			! (Y0_1) dtmp3 = dtmp2 + XKB3;

	sra	%l5,20,%l5			! (Y1_2) expy = hy >> 20;

	fmovdl	%fcc1,DZERO,%f62		! (Y2_1) yd = DZERO;

	and	%l5,0x7ff,%l5			! (Y1_2) expy &= 0x7ff;
	fmovdl	%fcc1,LTHRESH,%f44		! (Y2_1) s = LTHRESH;

	cmp	%l5,959				! (Y1_2) if (expy < 0x3fb);
	fmuld	%f60,%f54,%f48			! (Y0_1) dtmp4 = dtmp3 * y;
	faddd	%f50,%f10,%f52			! (Y1_1) y = y + yd;

	ld	[%fp+tmp4],%o1			! (Y1_1) ind = (int)dtmp0;

	add	py,stridey,py			! y += stridey;
	fmuld	s_h,%f12,%f50			! (Y0_2) s = s_h * s;
	fsubd	%f18,%f12,%f56			! (Y0_2) dtmp0 = (yd - s);

	fmuld	%f18,yr,%f26			! (Y0_2) dtmp1 = yd * yr;
	bl,pn	%icc,.xupdate6			! (Y1_2) if (expy < 0x3fb);
	faddd	%f44,%f62,%f28			! (Y2_1) dtmp0 = (s + yd);
.xcont6:
	sra	%o1,8,%o3			! (Y1_1) ind >>= 8;
	cmp	%l5,1086			! (Y1_2) if (expy >= 0x43e);
	fmuld	XKB5,%f52,%f22			! (Y1_1) dtmp0 = XKB5 * y;
	faddd	%f48,XKB2,%f14			! (Y0_1) dtmp5 = dtmp4 + XKB2;

	add	%o3,1021,%o0			! (Y1_1) eflag = (ind + 1021);
	bge,pn	%icc,.xupdate7			! (Y0_2) if (expy >= 0x43e);
	nop
.xcont7:
	sub	%g0,%o3,%i2			! (Y1_1) gflag = (1022 - ind);
	fmuld	%f56,s_h,%f58			! (Y0_2) dtmp0 *= s_h;
	fand	%f20,MHI32,%f12			! (Y1_2) s = vis_fand(yd, MHI32);

	sra	%o0,31,%l3			! (Y1_1) eflag = eflag >> 31;
	add	%i2,1022,%l2			! (Y1_1) gflag = (1022 - ind);
	fcmped	%fcc0,%f50,HTHRESH		! (Y0_2) if (s > HTHRESH);

	sra	%l2,31,%o7			! (Y1_1) gflag = gflag >> 31;
	and	%l3,54,%i1			! (Y1_1) itmp0 = 54 & eflag;
	fdtoi	%f28,%f3			! (Y2_1) u = (double)(int)dtmp0;

	add	%o3,%i1,%l0			! (Y1_1) ind = ind + itmp0;
	and	%o7,52,%l1			! (Y1_1) itmp1 = 52 & gflag;
	st	%f3,[%fp+ind_buf]		! (Y2_1) ind = (int)dtmp0;
	faddd	%f22,XKB4,%f60			! (Y1_1) dtmp1 = dtmp0 + XKB4;

	sub	%l0,%l1,%i4			! (Y1_1) ind = ind - itmp1;
	sub	%l3,%o7,%o7			! (Y1_1) ind = eflag - gflag;
	faddd	%f58,%f26,%f48			! (Y0_2) yd = dtmp0 + dtmp1;

	sll	%i4,20,%i2			! (Y1_1) ind <<= 20;
	lda	[py]0x82,%l5			! (Y2_2) hy = *py;
	fmovdg	%fcc0,HTHRESH,%f50		! (Y0_2) s = HTHRESH;

	st	%i2,[%fp+tmp1_hi]		! (Y1_1) *(int*)&dtmp0 = ind;
	fitod	%f3,%f18			! (Y2_1) u = (double)(int)dtmp0;

	fmuld	%f60,%f52,%f60			! (Y1_1) dtmp2 = dtmp1 * y;

	fmuld	%f14,%f54,%f56			! (Y0_1) dtmp6 = dtmp5 * y;
	fmovdg	%fcc0,DZERO,%f48		! (Y0_2) yd = DZERO;

	fcmped	%fcc1,%f50,LTHRESH		! (Y0_2) if (s < LTHRESH);

	lda	[py]0x82,%f26			! (Y2_2) yd = *py;
	lda	[py+4]%asi,%f27			! (Y2_2) yd = *py;
	fsubd	%f44,%f18,%f18			! (Y2_1) y = s - u;

	faddd	%f60,XKB3,%f44			! (Y1_1) dtmp3 = dtmp2 + XKB3;

	sra	%l5,20,%l5			! (Y2_2) expy = hy >> 20;
	and	%o2,255,%o2			! (Y0_1) i = ind & 0xff;
	faddd	%f56,XKB1,%f58			! (Y0_1) dtmp7 = dtmp6 + XKB1;

	sll	%o2,4,%l2			! (Y0_1) i = i << 4;
	fmovdl	%fcc1,DZERO,%f48		! (Y0_2) yd = DZERO;

	add	py,stridey,py			! y += stridey;
	and	%l5,0x7ff,%l5			! (Y2_2) expy &= 0x7ff;
	fmovdl	%fcc1,LTHRESH,%f50		! (Y0_2) s = LTHRESH;

	cmp	%l5,959				! (Y2_2) if (expy < 0x3fb);
	ldd	[EXPTBL+%l2],%f22		! (Y0_1) u = *(double*)((char*)__mt_constexp2 + i);
	faddd	%f18,%f62,%f18			! (Y2_1) y = y + yd;
	fmuld	%f44,%f52,%f62			! (Y1_1) dtmp4 = dtmp3 * y;

	ld	[%fp+ind_buf],%l1		! (Y2_1) ind = (int)dtmp0;
	fmuld	%f58,%f54,%f54			! (Y0_1) y = dtmp7 * y;

	fmuld	s_h,%f12,%f16			! (Y1_2) s = s_h * s;
	bl,pn	%icc,.xupdate8			! (Y2_2) if (expy < 0x3fb);
	fsubd	%f20,%f12,%f56			! (Y1_2) dtmp0 = (yd - s);
.xcont8:
	cmp	%l5,1086			! (Y2_2) if (expy >= 0x43e);
	fmuld	%f20,yr,%f8			! (Y1_2) dtmp1 = yd * yr;
	faddd	%f50,%f48,%f28			! (Y0_2) dtmp0 = (s + yd);

	sra	%l1,8,%o2			! (Y2_1) ind >>= 8;
	lda	[py]0x82,%l5			! (Y0_3) hy = *py;
	fmuld	XKB5,%f18,%f20			! (Y2_1) dtmp0 = XKB5 * y;
	faddd	%f62,XKB2,%f12			! (Y1_1) dtmp5 = dtmp4 + XKB2;

	add	%o2,1021,%l0			! (Y2_1) eflag = (ind + 1021);
	bge,pn	%icc,.xupdate9			! (Y2_2) if (expy >= 0x43e);
	nop
.xcont9:
	sub	%g0,%o2,%l3			! (Y2_1) gflag = (1022 - ind);
	ldd	[EXPTBL_P8+%l2],%f14		! (Y0_1) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
	fmuld	%f56,s_h,%f58			! (Y1_2) dtmp0 *= s_h;
	fand	%f26,MHI32,%f44			! (Y2_2) s = vis_fand(yd, MHI32);

	sra	%l0,31,%o0			! (Y2_1) eflag = eflag >> 31;
	add	%l3,1022,%i4			! (Y2_1) gflag = (1022 - ind);
	fmuld	%f22,%f54,%f56			! (Y0_1) dtmp1 = u * y;
	fcmped	%fcc0,%f16,HTHRESH		! (Y1_2) if (s > HTHRESH);

	sra	%i4,31,%o5			! (Y2_1) gflag = gflag >> 31;
	and	%o0,54,%i2			! (Y2_1) itmp0 = 54 & eflag;
	fdtoi	%f28,%f3			! (Y0_2) u = (double)(int)dtmp0;

	add	%o2,%i2,%i1			! (Y2_1) ind = ind + itmp0;
	and	%o5,52,%l2			! (Y2_1) itmp1 = 52 & gflag;
	st	%f3,[%fp+tmp3]			! (Y0_2) ind = (int)dtmp0;
	faddd	%f20,XKB4,%f60			! (Y2_1) dtmp1 = dtmp0 + XKB4;

	sub	%i1,%l2,%o3			! (Y2_1) ind = ind - itmp1;
	sub	%o0,%o5,%o5			! (Y2_1) ind = eflag - gflag;
	faddd	%f58,%f8,%f10			! (Y1_2) yd = dtmp0 + dtmp1;

	sll	%o3,20,%l3			! (Y2_1) ind <<= 20;
	lda	[py]0x82,%f28			! (Y0_3) yd = *py;
	lda	[py+4]%asi,%f29			! (Y0_3) yd = *py;
	fmovdg	%fcc0,HTHRESH,%f16		! (Y1_2) s = HTHRESH;

	st	%l3,[%fp+tmp2_hi]		! (Y2_1) *(int*)&dtmp0 = ind;
	fitod	%f3,%f58			! (Y0_2) u = (double)(int)dtmp0;

	fmuld	%f60,%f18,%f60			! (Y2_1) dtmp2 = dtmp1 * y;
	faddd	%f14,%f56,%f20			! (Y0_1) dtmp2 = dtmp0 + dtmp1;

	fmuld	%f12,%f52,%f56			! (Y1_1) dtmp6 = dtmp5 * y;
	fmovdg	%fcc0,DZERO,%f10		! (Y1_2) yd = DZERO;

	sra	%l5,20,%l5			! (Y0_3) expy = hy >> 20;
	fcmped	%fcc1,%f16,LTHRESH		! (Y1_2) if (s < LTHRESH);

	and	%l5,0x7ff,%l5			! (Y0_3) expy &= 0x7ff;
	fsubd	%f50,%f58,%f54			! (Y0_2) y = s - u;

	cmp	%l5,959				! (Y0_3) if (expy < 0x3fb);
	faddd	%f60,XKB3,%f60			! (Y2_1) dtmp3 = dtmp2 + XKB3;

	and	%o1,255,%o1			! (Y1_1) i = ind & 0xff;
	bl,pn	%icc,.xupdate10			! (Y0_3) if (expy < 0x3fb);
	faddd	%f56,XKB1,%f8			! (Y1_1) dtmp7 = dtmp6 + XKB1;
.xcont10:
	sll	%o1,4,%l0			! (Y1_1) i = i << 4;
	fmovdl	%fcc1,DZERO,%f10		! (Y1_2) yd = DZERO;

	nop
	ba	1f
	fmovdl	%fcc1,LTHRESH,%f16		! (Y1_2) s = LTHRESH;

	.align	16
1:
	subcc	counter,2,counter
	ldd	[EXPTBL+%l0],%f56		! (Y1_1) u = *(double*)((char*)__mt_constexp2 + i);
	fmuld	%f60,%f18,%f58			! (Y2_1) dtmp4 = dtmp3 * y;
	faddd	%f54,%f48,%f54			! (Y0_2) y = y + yd;

	fmuld	%f8,%f52,%f60			! (Y1_1) y = dtmp7 * y;
	ld	[%fp+tmp3],%o2			! (Y0_2) ind = (int)dtmp0;
	bneg,pn	%icc,.xtail
	faddd	%f20,%f22,%f12			! (Y0_1) u = dtmp2 + u;

.xmain_loop:
	cmp	%l5,1086			! (Y0_2) if (expy >= 0x43e);
	add	%o4,513,%o4			! (Y0_0) ind += 513;
	ldd	[%fp+tmp0_hi],%f52		! (Y0_0) *(int*)&dtmp0 = ind;
	fsubd	%f26,%f44,%f50			! (Y2_1) dtmp0 = (yd - s);

	fmuld	s_h,%f44,%f44			! (Y2_1) s = s_h * s;
	sra	%o2,8,%o0			! (Y0_1) ind >>= 8;
	bge,pn	%icc,.xupdate11			! (Y0_2) if (expy >= 0x43e);
	faddd	%f16,%f10,%f22			! (Y1_1) dtmp0 = (s + yd);
.xcont11:
	sll	%o4,3,%l2			! (Y0_0) ind *= 8;
	add	py,stridey,py			! y += stridey;
	fmuld	%f26,yr,%f20			! (Y2_1) dtmp1 = yd * yr;
	faddd	%f58,XKB2,%f14			! (Y2_0) dtmp5 = dtmp4 + XKB2;

	add	%o0,1021,%i1			! (Y0_1) eflag = (ind + 1021);
	ldd	[%l2+EXPTBL],%f62		! (Y0_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	fmuld	XKB5,%f54,%f48			! (Y0_1) dtmp0 = XKB5 * y;
	fpadd32	%f12,%f52,%f58			! (Y0_0) u = vis_fpadd32(u, dtmp0);

	sub	%g0,%o0,%o3			! (Y0_1) gflag = (1022 - ind);
	ldd	[EXPTBL_P8+%l0],%f8		! (Y1_0) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
	fand	%f28,MHI32,%f12			! (Y0_2) s = vis_fand(yd, MHI32);
	fmuld	%f50,s_h,%f52			! (Y2_1) dtmp0 *= s_h;

	sra	%i1,31,%o1			! (Y0_1) eflag = eflag >> 31;
	add	%o3,1022,%l0			! (Y0_1) gflag = (1022 - ind);
	fmuld	%f56,%f60,%f26			! (Y1_0) dtmp1 = u * y;
	fcmped	%fcc0,%f44,HTHRESH		! (Y2_1) if (s > HTHRESH);

	sra	%l0,31,%o4			! (Y0_1) gflag = gflag >> 31;
	and	%o1,54,%i4			! (Y0_1) itmp0 = 54 & eflag;
	fmuld	%f58,%f62,%f6			! (Y0_0) dtmp1 = u * dtmp1;
	fdtoi	%f22,%f4			! (Y1_1) u = (double)(int)dtmp0;

	add	%o0,%i4,%i2			! (Y0_1) ind = ind + itmp0;
	and	%o4,52,%l3			! (Y0_1) itmp1 = 52 & gflag;
	st	%f4,[%fp+tmp4]			! (Y1_1) ind = (int)dtmp0;
	faddd	%f48,XKB4,%f60			! (Y0_1) dtmp1 = dtmp0 + XKB4;

	sub	%i2,%l3,%l2			! (Y0_1) ind = ind - itmp1;
	sub	%o1,%o4,%o4			! (Y0_1) ind = eflag - gflag;
	st	%f6,[pz]			! (Y0_0) write into memory
	faddd	%f52,%f20,%f62			! (Y2_1) yd = dtmp0 + dtmp1;

	sll	%l2,20,%o3			! (Y0_1) ind <<= 20;
	nop
	st	%o3,[%fp+tmp0_hi]		! (Y0_1) *(int*)&dtmp0 = ind;
	fmovdg	%fcc0,HTHRESH,%f44		! (Y2_1) s = HTHRESH;

	lda	[py]0x82,%l5			! (Y1_2) hy = *py;
	nop
	fitod	%f4,%f48			! (Y1_1) u = (double)(int)dtmp0;

	fmuld	%f60,%f54,%f60			! (Y0_1) dtmp2 = dtmp1 * y;
	nop
	st	%f7,[pz+4]			! (Y0_0) write into memory
	faddd	%f8,%f26,%f26			! (Y1_0) dtmp2 = dtmp0 + dtmp1;

	lda	[py]0x82,%f8			! (Y1_2) yd = *py;
	nop
	fmuld	%f14,%f18,%f52			! (Y2_0) dtmp6 = dtmp5 * y;
	fmovdg	%fcc0,DZERO,%f62		! (Y2_1) yd = DZERO;

	lda	[py+4]%asi,%f9			! (Y1_2) yd = *py;
	add	pz,stridez,pz			! z += stridez;
	fcmped	%fcc1,%f44,LTHRESH		! (Y2_1) if (s < LTHRESH);

	fsubd	%f16,%f48,%f50			! (Y1_1) y = s - u;

	faddd	%f60,XKB3,%f60			! (Y0_1) dtmp3 = dtmp2 + XKB3;

	sra	%l5,20,%l5			! (Y1_2) expy = hy >> 20;
	and	%l1,255,%l1			! (Y2_0) i = ind & 0xff;
	faddd	%f52,XKB1,%f58			! (Y2_0) dtmp7 = dtmp6 + XKB1;

	sll	%l1,4,%l0			! (Y2_0) i = i << 4;
	fmovdl	%fcc1,DZERO,%f62		! (Y2_1) yd = DZERO;

	and	%l5,0x7ff,%l5			! (Y1_2) expy &= 0x7ff;
	nop
	fmovdl	%fcc1,LTHRESH,%f44		! (Y2_1) s = LTHRESH;

	cmp	%l5,959				! (Y1_2) if (expy < 0x3fb);
	ldd	[EXPTBL+%l0],%f20		! (Y2_0) u = *(double*)((char*)__mt_constexp2 + i);
	fmuld	%f60,%f54,%f48			! (Y0_1) dtmp4 = dtmp3 * y;
	faddd	%f50,%f10,%f52			! (Y1_1) y = y + yd;

	add	%o7,513,%o7			! (Y1_0) ind += 513;
	ld	[%fp+tmp4],%o1			! (Y1_1) ind = (int)dtmp0;
	fmuld	%f58,%f18,%f18			! (Y2_0) y = dtmp7 * y;
	faddd	%f26,%f56,%f58			! (Y1_0) u = dtmp2 + u;

	add	py,stridey,py			! y += stridey;
	ldd	[%fp+tmp1_hi],%f60		! (Y1_0) *(int*)&dtmp0 = ind;
	fmuld	s_h,%f12,%f50			! (Y0_2) s = s_h * s;
	fsubd	%f28,%f12,%f56			! (Y0_2) dtmp0 = (yd - s);

	sll	%o7,3,%l3			! (Y1_0) ind *= 8;
	fmuld	%f28,yr,%f26			! (Y0_2) dtmp1 = yd * yr;
	bl,pn	%icc,.xupdate12			! (Y1_2) if (expy < 0x3fb);
	faddd	%f44,%f62,%f28			! (Y2_1) dtmp0 = (s + yd);
.xcont12:
	sra	%o1,8,%o3			! (Y1_1) ind >>= 8;
	cmp	%l5,1086			! (Y1_2) if (expy >= 0x43e);
	fmuld	XKB5,%f52,%f22			! (Y1_1) dtmp0 = XKB5 * y;
	faddd	%f48,XKB2,%f14			! (Y0_1) dtmp5 = dtmp4 + XKB2;

	add	%o3,1021,%o0			! (Y1_1) eflag = (ind + 1021);
	ldd	[%l3+EXPTBL],%f48		! (Y1_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	bge,pn	%icc,.xupdate13			! (Y1_2) if (expy >= 0x43e);
	fpadd32	%f58,%f60,%f60			! (Y1_0) u = vis_fpadd32(u, dtmp0);
.xcont13:
	sub	%g0,%o3,%i2			! (Y1_1) gflag = (1022 - ind);
	ldd	[EXPTBL_P8+%l0],%f16		! (Y2_0) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
	fmuld	%f56,s_h,%f58			! (Y0_2) dtmp0 *= s_h;
	fand	%f8,MHI32,%f12			! (Y1_2) s = vis_fand(yd, MHI32);

	sra	%o0,31,%l3			! (Y1_1) eflag = eflag >> 31;
	add	%i2,1022,%l2			! (Y1_1) gflag = (1022 - ind);
	fmuld	%f20,%f18,%f56			! (Y2_0) dtmp1 = u * y;
	fcmped	%fcc0,%f50,HTHRESH		! (Y0_2) if (s > HTHRESH);

	sra	%l2,31,%o7			! (Y1_1) gflag = gflag >> 31;
	and	%l3,54,%i1			! (Y1_1) itmp0 = 54 & eflag;
	fmuld	%f60,%f48,%f18			! (Y1_0) dtmp1 = u * dtmp1;
	fdtoi	%f28,%f3			! (Y2_1) u = (double)(int)dtmp0;

	add	%o3,%i1,%l0			! (Y1_1) ind = ind + itmp0;
	and	%o7,52,%l1			! (Y1_1) itmp1 = 52 & gflag;
	st	%f3,[%fp+ind_buf]		! (Y2_1) ind = (int)dtmp0;
	faddd	%f22,XKB4,%f60			! (Y1_1) dtmp1 = dtmp0 + XKB4;

	sub	%l0,%l1,%i4			! (Y1_1) ind = ind - itmp1;
	sub	%l3,%o7,%o7			! (Y1_1) ind = eflag - gflag;
	st	%f18,[pz]			! (Y1_0) write into memory
	faddd	%f58,%f26,%f48			! (Y0_2) yd = dtmp0 + dtmp1;

	sll	%i4,20,%i2			! (Y1_1) ind <<= 20;
	lda	[py]0x82,%l5			! (Y2_2) hy = *py;
	fmovdg	%fcc0,HTHRESH,%f50		! (Y0_2) s = HTHRESH;

	st	%i2,[%fp+tmp1_hi]		! (Y1_1) *(int*)&dtmp0 = ind;
	fitod	%f3,%f10			! (Y2_1) u = (double)(int)dtmp0;

	fmuld	%f60,%f52,%f60			! (Y1_1) dtmp2 = dtmp1 * y;
	st	%f19,[pz+4]			! (Y1_0) write into memory
	faddd	%f16,%f56,%f28			! (Y2_0) dtmp2 = dtmp0 + dtmp1;

	fmuld	%f14,%f54,%f56			! (Y0_1) dtmp6 = dtmp5 * y;
	fmovdg	%fcc0,DZERO,%f48		! (Y0_2) yd = DZERO;

	add	pz,stridez,pz			! z += stridez;
	fcmped	%fcc1,%f50,LTHRESH		! (Y0_2) if (s < LTHRESH);

	lda	[py]0x82,%f26			! (Y2_2) yd = *py;
	fsubd	%f44,%f10,%f18			! (Y2_1) y = s - u;

	lda	[py+4]%asi,%f27			! (Y2_2) yd = *py;
	faddd	%f60,XKB3,%f44			! (Y1_1) dtmp3 = dtmp2 + XKB3;

	sra	%l5,20,%l5			! (Y2_2) expy = hy >> 20;
	and	%o2,255,%o2			! (Y0_1) i = ind & 0xff;
	faddd	%f56,XKB1,%f58			! (Y0_1) dtmp7 = dtmp6 + XKB1;

	sll	%o2,4,%l2			! (Y0_1) i = i << 4;
	fmovdl	%fcc1,DZERO,%f48		! (Y0_2) yd = DZERO;

	add	py,stridey,py			! y += stridey;
	and	%l5,0x7ff,%l5			! (Y2_2) expy &= 0x7ff;
	fmovdl	%fcc1,LTHRESH,%f50		! (Y0_2) s = LTHRESH;

	cmp	%l5,959				! (Y2_2) if (expy < 0x3fb);
	ldd	[EXPTBL+%l2],%f22		! (Y0_1) u = *(double*)((char*)__mt_constexp2 + i);
	faddd	%f18,%f62,%f18			! (Y2_1) y = y + yd;
	fmuld	%f44,%f52,%f62			! (Y1_1) dtmp4 = dtmp3 * y;

	add	%o5,513,%o5			! (Y2_0) ind += 513;
	ld	[%fp+ind_buf],%l1		! (Y2_1) ind = (int)dtmp0;
	fmuld	%f58,%f54,%f54			! (Y0_1) y = dtmp7 * y;
	faddd	%f28,%f20,%f58			! (Y2_0) u = dtmp2 + u;

	ldd	[%fp+tmp2_hi],%f60		! (Y2_0) *(int*)&dtmp0 = ind;
	fmuld	s_h,%f12,%f16			! (Y1_2) s = s_h * s;
	bl,pn	%icc,.xupdate14			! (Y2_2) if (expy < 0x3fb);
	fsubd	%f8,%f12,%f56			! (Y1_2) dtmp0 = (yd - s);
.xcont14:
	sll	%o5,3,%i1			! (Y2_0) ind *= 8;
	cmp	%l5,1086			! (Y2_2) if (expy >= 0x43e);
	fmuld	%f8,yr,%f8			! (Y1_2) dtmp1 = yd * yr;
	faddd	%f50,%f48,%f28			! (Y0_2) dtmp0 = (s + yd);

	sra	%l1,8,%o2			! (Y2_1) ind >>= 8;
	lda	[py]0x82,%l5			! (Y0_3) hy = *py;
	fmuld	XKB5,%f18,%f20			! (Y2_1) dtmp0 = XKB5 * y;
	faddd	%f62,XKB2,%f12			! (Y1_1) dtmp5 = dtmp4 + XKB2;

	add	%o2,1021,%l0			! (Y2_1) eflag = (ind + 1021);
	ldd	[%i1+EXPTBL],%f62		! (Y2_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	bge,pn	%icc,.xupdate15			! (Y2_2) if (expy >= 0x43e);
	fpadd32	%f58,%f60,%f60			! (Y2_0) u = vis_fpadd32(u, dtmp0);
.xcont15:
	sub	%g0,%o2,%l3			! (Y2_1) gflag = (1022 - ind);
	ldd	[EXPTBL_P8+%l2],%f14		! (Y0_1) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);
	fmuld	%f56,s_h,%f58			! (Y1_2) dtmp0 *= s_h;
	fand	%f26,MHI32,%f44			! (Y2_2) s = vis_fand(yd, MHI32);

	sra	%l0,31,%o0			! (Y2_1) eflag = eflag >> 31;
	add	%l3,1022,%i4			! (Y2_1) gflag = (1022 - ind);
	fmuld	%f22,%f54,%f56			! (Y0_1) dtmp1 = u * y;
	fcmped	%fcc0,%f16,HTHRESH		! (Y1_2) if (s > HTHRESH);

	sra	%i4,31,%o5			! (Y2_1) gflag = gflag >> 31;
	and	%o0,54,%i2			! (Y2_1) itmp0 = 54 & eflag;
	fmuld	%f60,%f62,%f6			! (Y2_0) dtmp1 = u * dtmp1;
	fdtoi	%f28,%f3			! (Y0_2) u = (double)(int)dtmp0;

	add	%o2,%i2,%i1			! (Y2_1) ind = ind + itmp0;
	and	%o5,52,%l2			! (Y2_1) itmp1 = 52 & gflag;
	st	%f3,[%fp+tmp3]			! (Y0_2) ind = (int)dtmp0;
	faddd	%f20,XKB4,%f60			! (Y2_1) dtmp1 = dtmp0 + XKB4;

	sub	%i1,%l2,%o3			! (Y2_1) ind = ind - itmp1;
	sub	%o0,%o5,%o5			! (Y2_1) ind = eflag - gflag;
	st	%f6,[pz]			! (Y2_0) write into memory
	faddd	%f58,%f8,%f10			! (Y1_2) yd = dtmp0 + dtmp1;

	sll	%o3,20,%l3			! (Y2_1) ind <<= 20;
	lda	[py]0x82,%f28			! (Y0_3) yd = *py;
	fmovdg	%fcc0,HTHRESH,%f16		! (Y1_2) s = HTHRESH;

	lda	[py+4]%asi,%f29			! (Y0_3) yd = *py;
	fitod	%f3,%f58			! (Y0_2) u = (double)(int)dtmp0;

	fmuld	%f60,%f18,%f60			! (Y2_1) dtmp2 = dtmp1 * y;
	st	%l3,[%fp+tmp2_hi]		! (Y2_1) *(int*)&dtmp0 = ind;
	faddd	%f14,%f56,%f20			! (Y0_1) dtmp2 = dtmp0 + dtmp1;

	fmuld	%f12,%f52,%f56			! (Y1_1) dtmp6 = dtmp5 * y;
	st	%f7,[pz+4]			! (Y2_0) write into memory
	fmovdg	%fcc0,DZERO,%f10		! (Y1_2) yd = DZERO;

	sra	%l5,20,%l5			! (Y0_3) expy = hy >> 20;
	add	pz,stridez,pz			! z += stridez;
	fcmped	%fcc1,%f16,LTHRESH		! (Y1_2) if (s < LTHRESH);

	and	%l5,0x7ff,%l5			! (Y0_3) expy &= 0x7ff;
	fsubd	%f50,%f58,%f54			! (Y0_2) y = s - u;

	cmp	%l5,959				! (Y0_3) if (expy < 0x3fb);
	faddd	%f60,XKB3,%f60			! (Y2_1) dtmp3 = dtmp2 + XKB3;

	and	%o1,255,%o1			! (Y1_1) i = ind & 0xff;
	bl,pn	%icc,.xupdate16			! (Y0_3) if (expy < 0x3fb);
	faddd	%f56,XKB1,%f8			! (Y1_1) dtmp7 = dtmp6 + XKB1;
.xcont16:
	sll	%o1,4,%l0			! (Y1_1) i = i << 4;
	fmovdl	%fcc1,DZERO,%f10		! (Y1_2) yd = DZERO;

	subcc	counter,3,counter		! update cycle counter
	fmovdl	%fcc1,LTHRESH,%f16		! (Y1_2) s = LTHRESH;

	ldd	[EXPTBL+%l0],%f56		! (Y1_1) u = *(double*)((char*)__mt_constexp2 + i);
	fmuld	%f60,%f18,%f58			! (Y2_1) dtmp4 = dtmp3 * y;
	faddd	%f54,%f48,%f54			! (Y0_2) y = y + yd;

	fmuld	%f8,%f52,%f60			! (Y1_1) y = dtmp7 * y;
	ld	[%fp+tmp3],%o2			! (Y0_2) ind = (int)dtmp0;
	bpos,pt	%icc,.xmain_loop
	faddd	%f20,%f22,%f12			! (Y0_1) u = dtmp2 + u;

.xtail:
	addcc	counter,2,counter
	ldd	[%fp+tmp0_hi],%f52		! (Y0_0) *(int*)&dtmp0 = ind;

	add	%o4,513,%o4			! (Y0_0) ind += 513;
	bneg,pn	%icc,.xend_loop
	nop

	sll	%o4,3,%l2			! (Y0_0) ind *= 8;

	subcc	counter,1,counter
	ldd	[%l2+EXPTBL],%f62		! (Y0_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	fpadd32	%f12,%f52,%f58			! (Y0_0) u = vis_fpadd32(u, dtmp0);

	ldd	[EXPTBL_P8+%l0],%f8		! (Y1_0) dtmp0 = *(double*)((char*)__mt_constexp2 + i + 8);

	fmuld	%f56,%f60,%f26			! (Y1_0) dtmp1 = u * y;

	fmuld	%f58,%f62,%f6			! (Y0_0) dtmp1 = u * dtmp1;

	st	%f6,[pz]			! (Y0_0) write into memory
	st	%f7,[pz+4]			! (Y0_0) write into memory
	bneg,pn	%icc,.xend_loop
	add	pz,stridez,pz			! z += stridez;

	faddd	%f8,%f26,%f26			! (Y1_0) dtmp2 = dtmp0 + dtmp1;

	add	%o7,513,%o7			! (Y1_0) ind += 513;
	faddd	%f26,%f56,%f58			! (Y1_0) u = dtmp2 + u;

	ldd	[%fp+tmp1_hi],%f60		! (Y1_0) *(int*)&dtmp0 = ind;

	sll	%o7,3,%l3			! (Y1_0) ind *= 8;

	ldd	[%l3+EXPTBL],%f48		! (Y1_0) dtmp1 = (*(double*)((char*)__mt_constexp2 + ind);
	fpadd32	%f58,%f60,%f60			! (Y1_0) u = vis_fpadd32(u, dtmp0);

	fmuld	%f60,%f48,%f18			! (Y1_0) dtmp1 = u * dtmp1;

	st	%f18,[pz]			! (Y1_0) write into memory
	st	%f19,[pz+4]			! (Y1_0) write into memory
	add	pz,stridez,pz			! z += stridez;

.xend_loop:
	ba	.xbegin
	nop

	.align	16
.xupdate0:
	cmp	counter,0
	sub	py,stridey,%i2
	ble,pt	%icc,.xcont0
	fmovd	DZERO,%f10

	stx	%i2,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont0
	or	%g0,0,counter

	.align	16
.xupdate1:
	cmp	counter,0
	sub	py,stridey,%i2
	ble,pt	%icc,.xcont1
	fmovd	DZERO,%f10

	stx	%i2,[%fp+tmp_py]

	st	counter,[%fp+tmp_counter]
	ba	.xcont1
	or	%g0,0,counter

	.align	16
.xupdate2:
	cmp	counter,1
	sub	py,stridey,%l3
	ble,pt	%icc,.xcont2
	fmovd	DZERO,%f14

	stx	%l3,[%fp+tmp_py]
	sub	counter,1,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont2
	or	%g0,1,counter

	.align	16
.xupdate3:
	cmp	counter,1
	sub	py,stridey,%l3
	ble,pt	%icc,.xcont3
	fmovd	DZERO,%f14

	stx	%l3,[%fp+tmp_py]
	sub	counter,1,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont3
	or	%g0,1,counter

	.align	16
.xupdate4:
	cmp	counter,2
	ble,pt	%icc,.xcont4
	fmovd	DZERO,%f18

	stx	py,[%fp+tmp_py]
	sub	counter,2,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont4
	or	%g0,2,counter

	.align	16
.xupdate5:
	cmp	counter,2
	ble,pt	%icc,.xcont5
	fmovd	DZERO,%f18

	stx	py,[%fp+tmp_py]
	sub	counter,2,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont5
	or	%g0,2,counter

	.align	16
.xupdate6:
	cmp	counter,3
	sub	py,stridey,%i2
	ble,pt	%icc,.xcont6
	fmovd	DZERO,%f20

	stx	%i2,[%fp+tmp_py]
	sub	counter,3,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont6
	or	%g0,3,counter

	.align	16
.xupdate7:
	cmp	counter,3
	sub	py,stridey,%i2
	ble,pt	%icc,.xcont7
	fmovd	DZERO,%f20

	stx	%i2,[%fp+tmp_py]
	sub	counter,3,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont7
	or	%g0,3,counter

	.align	16
.xupdate8:
	cmp	counter,4
	sub	py,stridey,%l3
	ble,pt	%icc,.xcont8
	fmovd	DZERO,%f26

	stx	%l3,[%fp+tmp_py]
	sub	counter,4,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont8
	or	%g0,4,counter

	.align	16
.xupdate9:
	cmp	counter,4
	sub	py,stridey,%l3
	ble,pt	%icc,.xcont9
	fmovd	DZERO,%f26

	stx	%l3,[%fp+tmp_py]
	sub	counter,4,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont9
	or	%g0,4,counter

	.align	16
.xupdate10:
	cmp	counter,5
	ble,pt	%icc,.xcont10
	fmovd	DZERO,%f28

	stx	py,[%fp+tmp_py]
	sub	counter,5,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont10
	or	%g0,5,counter

	.align	16
.xupdate11:
	cmp	counter,3
	ble,pt	%icc,.xcont11
	fmovd	DZERO,%f28

	stx	py,[%fp+tmp_py]
	sub	counter,3,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont11
	or	%g0,3,counter

	.align	16
.xupdate12:
	cmp	counter,4
	sub	py,stridey,%i2
	ble,pt	%icc,.xcont12
	fmovd	DZERO,%f8

	stx	%i2,[%fp+tmp_py]
	sub	counter,4,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont12
	or	%g0,4,counter

	.align	16
.xupdate13:
	cmp	counter,4
	sub	py,stridey,%i2
	ble,pt	%icc,.xcont13
	fmovd	DZERO,%f8

	stx	%i2,[%fp+tmp_py]
	sub	counter,4,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont13
	or	%g0,4,counter

	.align	16
.xupdate14:
	cmp	counter,5
	sub	py,stridey,%l3
	ble,pt	%icc,.xcont14
	fmovd	DZERO,%f26

	stx	%l3,[%fp+tmp_py]
	sub	counter,5,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont14
	or	%g0,5,counter

	.align	16
.xupdate15:
	cmp	counter,5
	sub	py,stridey,%l3
	ble,pt	%icc,.xcont15
	fmovd	DZERO,%f26

	stx	%l3,[%fp+tmp_py]
	sub	counter,5,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont15
	or	%g0,5,counter

	.align	16
.xupdate16:
	cmp	counter,6
	ble,pt	%icc,.xcont16
	fmovd	DZERO,%f28

	stx	py,[%fp+tmp_py]
	sub	counter,6,counter

	st	counter,[%fp+tmp_counter]
	ba	.xcont16
	or	%g0,6,counter

	.align	16
.xspec0:
	add	EXPTBL,4095,%l0
	add	%l0,1,%l0
	ldd	[%l0+8],%f20			! ld  DONE
	st	%f20,[pz]			! *pz = DONE;
	ba	.xupdate_point
	st	%f21,[pz+4]			! *pz = DONE;

	.align	16
.xspec1:
	ldx	[%fp+tmp_px],%l1
	sethi	%hi(0x7ffffc00),MASK_0x7fffffff

	sethi	%hi(0x7ff00000),%o3
	add	MASK_0x7fffffff,0x3ff,MASK_0x7fffffff

	and	%l2,MASK_0x7fffffff,%o2		! if (hy &= 0x7fffffff);
	sethi	%hi(0x3ff00000),MASK_0x3ff00000

	cmp	%o2,%o3				! if (hy != 0x7ff00000);
	bne,pn	%icc,2f				! if (hy != 0x7ff00000);
	nop

	ld	[py+4],%l3			! ld ly;
	cmp	%l3,0				! if (ly != 0);
	bne,a,pt	%icc,3f			! if (ly != 0);
	nop

	ld	[%l1],%i1			! ld hx;
	cmp	%i1,MASK_0x3ff00000		! if (hx != 0x3ff00000);
	bne,a,pn	%icc,1f			! if (hx != 0x3ff00000);
	srl	%l2,31,%o7			! sy = hy >> 31;

	ld	[%l1+4],%i2			! ld lx;
	cmp	%i2,0				! if (lx != 0);
	bne,pn	%icc,1f				! if (lx != 0);
	srl	%l2,31,%o7			! sy = hy >> 31;

	fzero	%f28
	fmuld	%f18,%f28,%f28			! *pz = *py * 0.0;
	st	%f28,[pz]
	ba	.xupdate_point
	st	%f29,[pz+4]
1:
	sub	%i1,MASK_0x3ff00000,%o0		! hx - 0x3ff00000;
	srlx	%o0,63,%o0			! (hx - 0x3ff00000) >> 63;

	cmp	%o0,%o7				! if ((hx < 0x3ff00000) == sy);
	be,pn	%icc,1f				! if ((hx < 0x3ff00000) == sy);

	st	DZERO_HI,[pz]
	ba	.xupdate_point
	st	DZERO_LO,[pz+4]
1:
	st	%o2,[pz]			! ((int*)pz)[0] = hy;
	ba	.xupdate_point
	st	%l3,[pz+4]			! ((int*)pz)[1] = ly;
2:
	bl,a,pn	%icc,1f				! if (hy < 0x7ff00000);
	ld	[%l1+4],%i2			! ld lx;
3:
	ld	[%l1],%f20			! x = *px;
	ld	[%l1+4],%f21			! x = *px;
	fmuld	%f20,%f18,%f28			! *pz = *px * *py;
	st	%f28,[pz]
	ba	.xupdate_point
	st	%f29,[pz+4]
1:
	ld	[%l1],%i1			! ld hx;
	cmp	%i2,0				! if (lx != 0);
	bne,pn	%icc,1f				! if (lx != 0);
	nop

	cmp	%i1,MASK_0x3ff00000		! if (hx != 0x3ff00000);
	add	EXPTBL,4095,%l0
	bne,pn	%icc,1f				! if (hx != 0x3ff00000);
	add	%l0,1,%l0

	ldd	[%l0+8],%f20			! ld  DONE
	st	%f20,[pz]			! *pz = DONE;
	ba	.xupdate_point
	st	%f21,[pz+4]			! *pz = DONE;
1:
	srl	%l2,31,%o7			! sy = hy >> 31;
	sub	%i1,MASK_0x3ff00000,%o0		! hx - 0x3ff00000;

	srlx	%o0,63,%o0			! (hx - 0x3ff00000) >> 63;

	cmp	%o0,%o7				! if (hx < 0x3ff00000) == sy);
	be,a,pn	%icc,1f				! if (hx < 0x3ff00000) == sy);
	ldd	[EXPTBL-ind_HUGE],%f20		! y0 = _HUGE;

	ldd	[EXPTBL-ind_TINY],%f20		! y0 = _TINY;
1:
	fmuld	%f20,%f20,%f20			! *pz = y0 * y0
	st	%f20,[pz]
	ba	.xupdate_point
	st	%f21,[pz+4]

.xupdate_point:
	add	py,stridey,py
	ba	.xbegin1
	add	pz,stridez,pz

	SET_SIZE(__vpow)

