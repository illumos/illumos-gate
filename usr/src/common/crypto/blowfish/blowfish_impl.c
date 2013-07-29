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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Blowfish encryption/decryption and keyschedule code.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <sys/note.h>
#include <sys/byteorder.h>
#include <sys/crypto/spi.h>
#include <modes/modes.h>
#include <sys/crypto/common.h>
#include "blowfish_impl.h"

#ifdef _KERNEL

#define	BLOWFISH_ASSERT(x)	ASSERT(x)

#else /* !_KERNEL */

#include <strings.h>
#include <stdlib.h>
#define	BLOWFISH_ASSERT(x)
#endif /* _KERNEL */

#if defined(__i386) || defined(__amd64)
#include <sys/byteorder.h>
#define	UNALIGNED_POINTERS_PERMITTED
#endif

/*
 * Blowfish initial P box and S boxes, derived from the hex digits of PI.
 *
 * NOTE:  S boxes are placed into one large array.
 */
static const uint32_t init_P[] = {
	0x243f6a88U, 0x85a308d3U, 0x13198a2eU,
	0x03707344U, 0xa4093822U, 0x299f31d0U,
	0x082efa98U, 0xec4e6c89U, 0x452821e6U,
	0x38d01377U, 0xbe5466cfU, 0x34e90c6cU,
	0xc0ac29b7U, 0xc97c50ddU, 0x3f84d5b5U,
	0xb5470917U, 0x9216d5d9U, 0x8979fb1bU
};

static const uint32_t init_S[] = {
	/* S-Box 0. */
	0xd1310ba6U, 0x98dfb5acU, 0x2ffd72dbU, 0xd01adfb7U,
	0xb8e1afedU, 0x6a267e96U, 0xba7c9045U, 0xf12c7f99U,
	0x24a19947U, 0xb3916cf7U, 0x0801f2e2U, 0x858efc16U,
	0x636920d8U, 0x71574e69U, 0xa458fea3U, 0xf4933d7eU,
	0x0d95748fU, 0x728eb658U, 0x718bcd58U, 0x82154aeeU,
	0x7b54a41dU, 0xc25a59b5U, 0x9c30d539U, 0x2af26013U,
	0xc5d1b023U, 0x286085f0U, 0xca417918U, 0xb8db38efU,
	0x8e79dcb0U, 0x603a180eU, 0x6c9e0e8bU, 0xb01e8a3eU,
	0xd71577c1U, 0xbd314b27U, 0x78af2fdaU, 0x55605c60U,
	0xe65525f3U, 0xaa55ab94U, 0x57489862U, 0x63e81440U,
	0x55ca396aU, 0x2aab10b6U, 0xb4cc5c34U, 0x1141e8ceU,
	0xa15486afU, 0x7c72e993U, 0xb3ee1411U, 0x636fbc2aU,
	0x2ba9c55dU, 0x741831f6U, 0xce5c3e16U, 0x9b87931eU,
	0xafd6ba33U, 0x6c24cf5cU, 0x7a325381U, 0x28958677U,
	0x3b8f4898U, 0x6b4bb9afU, 0xc4bfe81bU, 0x66282193U,
	0x61d809ccU, 0xfb21a991U, 0x487cac60U, 0x5dec8032U,
	0xef845d5dU, 0xe98575b1U, 0xdc262302U, 0xeb651b88U,
	0x23893e81U, 0xd396acc5U, 0x0f6d6ff3U, 0x83f44239U,
	0x2e0b4482U, 0xa4842004U, 0x69c8f04aU, 0x9e1f9b5eU,
	0x21c66842U, 0xf6e96c9aU, 0x670c9c61U, 0xabd388f0U,
	0x6a51a0d2U, 0xd8542f68U, 0x960fa728U, 0xab5133a3U,
	0x6eef0b6cU, 0x137a3be4U, 0xba3bf050U, 0x7efb2a98U,
	0xa1f1651dU, 0x39af0176U, 0x66ca593eU, 0x82430e88U,
	0x8cee8619U, 0x456f9fb4U, 0x7d84a5c3U, 0x3b8b5ebeU,
	0xe06f75d8U, 0x85c12073U, 0x401a449fU, 0x56c16aa6U,
	0x4ed3aa62U, 0x363f7706U, 0x1bfedf72U, 0x429b023dU,
	0x37d0d724U, 0xd00a1248U, 0xdb0fead3U, 0x49f1c09bU,
	0x075372c9U, 0x80991b7bU, 0x25d479d8U, 0xf6e8def7U,
	0xe3fe501aU, 0xb6794c3bU, 0x976ce0bdU, 0x04c006baU,
	0xc1a94fb6U, 0x409f60c4U, 0x5e5c9ec2U, 0x196a2463U,
	0x68fb6fafU, 0x3e6c53b5U, 0x1339b2ebU, 0x3b52ec6fU,
	0x6dfc511fU, 0x9b30952cU, 0xcc814544U, 0xaf5ebd09U,
	0xbee3d004U, 0xde334afdU, 0x660f2807U, 0x192e4bb3U,
	0xc0cba857U, 0x45c8740fU, 0xd20b5f39U, 0xb9d3fbdbU,
	0x5579c0bdU, 0x1a60320aU, 0xd6a100c6U, 0x402c7279U,
	0x679f25feU, 0xfb1fa3ccU, 0x8ea5e9f8U, 0xdb3222f8U,
	0x3c7516dfU, 0xfd616b15U, 0x2f501ec8U, 0xad0552abU,
	0x323db5faU, 0xfd238760U, 0x53317b48U, 0x3e00df82U,
	0x9e5c57bbU, 0xca6f8ca0U, 0x1a87562eU, 0xdf1769dbU,
	0xd542a8f6U, 0x287effc3U, 0xac6732c6U, 0x8c4f5573U,
	0x695b27b0U, 0xbbca58c8U, 0xe1ffa35dU, 0xb8f011a0U,
	0x10fa3d98U, 0xfd2183b8U, 0x4afcb56cU, 0x2dd1d35bU,
	0x9a53e479U, 0xb6f84565U, 0xd28e49bcU, 0x4bfb9790U,
	0xe1ddf2daU, 0xa4cb7e33U, 0x62fb1341U, 0xcee4c6e8U,
	0xef20cadaU, 0x36774c01U, 0xd07e9efeU, 0x2bf11fb4U,
	0x95dbda4dU, 0xae909198U, 0xeaad8e71U, 0x6b93d5a0U,
	0xd08ed1d0U, 0xafc725e0U, 0x8e3c5b2fU, 0x8e7594b7U,
	0x8ff6e2fbU, 0xf2122b64U, 0x8888b812U, 0x900df01cU,
	0x4fad5ea0U, 0x688fc31cU, 0xd1cff191U, 0xb3a8c1adU,
	0x2f2f2218U, 0xbe0e1777U, 0xea752dfeU, 0x8b021fa1U,
	0xe5a0cc0fU, 0xb56f74e8U, 0x18acf3d6U, 0xce89e299U,
	0xb4a84fe0U, 0xfd13e0b7U, 0x7cc43b81U, 0xd2ada8d9U,
	0x165fa266U, 0x80957705U, 0x93cc7314U, 0x211a1477U,
	0xe6ad2065U, 0x77b5fa86U, 0xc75442f5U, 0xfb9d35cfU,
	0xebcdaf0cU, 0x7b3e89a0U, 0xd6411bd3U, 0xae1e7e49U,
	0x00250e2dU, 0x2071b35eU, 0x226800bbU, 0x57b8e0afU,
	0x2464369bU, 0xf009b91eU, 0x5563911dU, 0x59dfa6aaU,
	0x78c14389U, 0xd95a537fU, 0x207d5ba2U, 0x02e5b9c5U,
	0x83260376U, 0x6295cfa9U, 0x11c81968U, 0x4e734a41U,
	0xb3472dcaU, 0x7b14a94aU, 0x1b510052U, 0x9a532915U,
	0xd60f573fU, 0xbc9bc6e4U, 0x2b60a476U, 0x81e67400U,
	0x08ba6fb5U, 0x571be91fU, 0xf296ec6bU, 0x2a0dd915U,
	0xb6636521U, 0xe7b9f9b6U, 0xff34052eU, 0xc5855664U,
	0x53b02d5dU, 0xa99f8fa1U, 0x08ba4799U, 0x6e85076aU,

	/* S-Box 1. */
	0x4b7a70e9U, 0xb5b32944U, 0xdb75092eU, 0xc4192623U,
	0xad6ea6b0U, 0x49a7df7dU, 0x9cee60b8U, 0x8fedb266U,
	0xecaa8c71U, 0x699a17ffU, 0x5664526cU, 0xc2b19ee1U,
	0x193602a5U, 0x75094c29U, 0xa0591340U, 0xe4183a3eU,
	0x3f54989aU, 0x5b429d65U, 0x6b8fe4d6U, 0x99f73fd6U,
	0xa1d29c07U, 0xefe830f5U, 0x4d2d38e6U, 0xf0255dc1U,
	0x4cdd2086U, 0x8470eb26U, 0x6382e9c6U, 0x021ecc5eU,
	0x09686b3fU, 0x3ebaefc9U, 0x3c971814U, 0x6b6a70a1U,
	0x687f3584U, 0x52a0e286U, 0xb79c5305U, 0xaa500737U,
	0x3e07841cU, 0x7fdeae5cU, 0x8e7d44ecU, 0x5716f2b8U,
	0xb03ada37U, 0xf0500c0dU, 0xf01c1f04U, 0x0200b3ffU,
	0xae0cf51aU, 0x3cb574b2U, 0x25837a58U, 0xdc0921bdU,
	0xd19113f9U, 0x7ca92ff6U, 0x94324773U, 0x22f54701U,
	0x3ae5e581U, 0x37c2dadcU, 0xc8b57634U, 0x9af3dda7U,
	0xa9446146U, 0x0fd0030eU, 0xecc8c73eU, 0xa4751e41U,
	0xe238cd99U, 0x3bea0e2fU, 0x3280bba1U, 0x183eb331U,
	0x4e548b38U, 0x4f6db908U, 0x6f420d03U, 0xf60a04bfU,
	0x2cb81290U, 0x24977c79U, 0x5679b072U, 0xbcaf89afU,
	0xde9a771fU, 0xd9930810U, 0xb38bae12U, 0xdccf3f2eU,
	0x5512721fU, 0x2e6b7124U, 0x501adde6U, 0x9f84cd87U,
	0x7a584718U, 0x7408da17U, 0xbc9f9abcU, 0xe94b7d8cU,
	0xec7aec3aU, 0xdb851dfaU, 0x63094366U, 0xc464c3d2U,
	0xef1c1847U, 0x3215d908U, 0xdd433b37U, 0x24c2ba16U,
	0x12a14d43U, 0x2a65c451U, 0x50940002U, 0x133ae4ddU,
	0x71dff89eU, 0x10314e55U, 0x81ac77d6U, 0x5f11199bU,
	0x043556f1U, 0xd7a3c76bU, 0x3c11183bU, 0x5924a509U,
	0xf28fe6edU, 0x97f1fbfaU, 0x9ebabf2cU, 0x1e153c6eU,
	0x86e34570U, 0xeae96fb1U, 0x860e5e0aU, 0x5a3e2ab3U,
	0x771fe71cU, 0x4e3d06faU, 0x2965dcb9U, 0x99e71d0fU,
	0x803e89d6U, 0x5266c825U, 0x2e4cc978U, 0x9c10b36aU,
	0xc6150ebaU, 0x94e2ea78U, 0xa5fc3c53U, 0x1e0a2df4U,
	0xf2f74ea7U, 0x361d2b3dU, 0x1939260fU, 0x19c27960U,
	0x5223a708U, 0xf71312b6U, 0xebadfe6eU, 0xeac31f66U,
	0xe3bc4595U, 0xa67bc883U, 0xb17f37d1U, 0x018cff28U,
	0xc332ddefU, 0xbe6c5aa5U, 0x65582185U, 0x68ab9802U,
	0xeecea50fU, 0xdb2f953bU, 0x2aef7dadU, 0x5b6e2f84U,
	0x1521b628U, 0x29076170U, 0xecdd4775U, 0x619f1510U,
	0x13cca830U, 0xeb61bd96U, 0x0334fe1eU, 0xaa0363cfU,
	0xb5735c90U, 0x4c70a239U, 0xd59e9e0bU, 0xcbaade14U,
	0xeecc86bcU, 0x60622ca7U, 0x9cab5cabU, 0xb2f3846eU,
	0x648b1eafU, 0x19bdf0caU, 0xa02369b9U, 0x655abb50U,
	0x40685a32U, 0x3c2ab4b3U, 0x319ee9d5U, 0xc021b8f7U,
	0x9b540b19U, 0x875fa099U, 0x95f7997eU, 0x623d7da8U,
	0xf837889aU, 0x97e32d77U, 0x11ed935fU, 0x16681281U,
	0x0e358829U, 0xc7e61fd6U, 0x96dedfa1U, 0x7858ba99U,
	0x57f584a5U, 0x1b227263U, 0x9b83c3ffU, 0x1ac24696U,
	0xcdb30aebU, 0x532e3054U, 0x8fd948e4U, 0x6dbc3128U,
	0x58ebf2efU, 0x34c6ffeaU, 0xfe28ed61U, 0xee7c3c73U,
	0x5d4a14d9U, 0xe864b7e3U, 0x42105d14U, 0x203e13e0U,
	0x45eee2b6U, 0xa3aaabeaU, 0xdb6c4f15U, 0xfacb4fd0U,
	0xc742f442U, 0xef6abbb5U, 0x654f3b1dU, 0x41cd2105U,
	0xd81e799eU, 0x86854dc7U, 0xe44b476aU, 0x3d816250U,
	0xcf62a1f2U, 0x5b8d2646U, 0xfc8883a0U, 0xc1c7b6a3U,
	0x7f1524c3U, 0x69cb7492U, 0x47848a0bU, 0x5692b285U,
	0x095bbf00U, 0xad19489dU, 0x1462b174U, 0x23820e00U,
	0x58428d2aU, 0x0c55f5eaU, 0x1dadf43eU, 0x233f7061U,
	0x3372f092U, 0x8d937e41U, 0xd65fecf1U, 0x6c223bdbU,
	0x7cde3759U, 0xcbee7460U, 0x4085f2a7U, 0xce77326eU,
	0xa6078084U, 0x19f8509eU, 0xe8efd855U, 0x61d99735U,
	0xa969a7aaU, 0xc50c06c2U, 0x5a04abfcU, 0x800bcadcU,
	0x9e447a2eU, 0xc3453484U, 0xfdd56705U, 0x0e1e9ec9U,
	0xdb73dbd3U, 0x105588cdU, 0x675fda79U, 0xe3674340U,
	0xc5c43465U, 0x713e38d8U, 0x3d28f89eU, 0xf16dff20U,
	0x153e21e7U, 0x8fb03d4aU, 0xe6e39f2bU, 0xdb83adf7U,

	/* S-Box 2. */
	0xe93d5a68U, 0x948140f7U, 0xf64c261cU, 0x94692934U,
	0x411520f7U, 0x7602d4f7U, 0xbcf46b2eU, 0xd4a20068U,
	0xd4082471U, 0x3320f46aU, 0x43b7d4b7U, 0x500061afU,
	0x1e39f62eU, 0x97244546U, 0x14214f74U, 0xbf8b8840U,
	0x4d95fc1dU, 0x96b591afU, 0x70f4ddd3U, 0x66a02f45U,
	0xbfbc09ecU, 0x03bd9785U, 0x7fac6dd0U, 0x31cb8504U,
	0x96eb27b3U, 0x55fd3941U, 0xda2547e6U, 0xabca0a9aU,
	0x28507825U, 0x530429f4U, 0x0a2c86daU, 0xe9b66dfbU,
	0x68dc1462U, 0xd7486900U, 0x680ec0a4U, 0x27a18deeU,
	0x4f3ffea2U, 0xe887ad8cU, 0xb58ce006U, 0x7af4d6b6U,
	0xaace1e7cU, 0xd3375fecU, 0xce78a399U, 0x406b2a42U,
	0x20fe9e35U, 0xd9f385b9U, 0xee39d7abU, 0x3b124e8bU,
	0x1dc9faf7U, 0x4b6d1856U, 0x26a36631U, 0xeae397b2U,
	0x3a6efa74U, 0xdd5b4332U, 0x6841e7f7U, 0xca7820fbU,
	0xfb0af54eU, 0xd8feb397U, 0x454056acU, 0xba489527U,
	0x55533a3aU, 0x20838d87U, 0xfe6ba9b7U, 0xd096954bU,
	0x55a867bcU, 0xa1159a58U, 0xcca92963U, 0x99e1db33U,
	0xa62a4a56U, 0x3f3125f9U, 0x5ef47e1cU, 0x9029317cU,
	0xfdf8e802U, 0x04272f70U, 0x80bb155cU, 0x05282ce3U,
	0x95c11548U, 0xe4c66d22U, 0x48c1133fU, 0xc70f86dcU,
	0x07f9c9eeU, 0x41041f0fU, 0x404779a4U, 0x5d886e17U,
	0x325f51ebU, 0xd59bc0d1U, 0xf2bcc18fU, 0x41113564U,
	0x257b7834U, 0x602a9c60U, 0xdff8e8a3U, 0x1f636c1bU,
	0x0e12b4c2U, 0x02e1329eU, 0xaf664fd1U, 0xcad18115U,
	0x6b2395e0U, 0x333e92e1U, 0x3b240b62U, 0xeebeb922U,
	0x85b2a20eU, 0xe6ba0d99U, 0xde720c8cU, 0x2da2f728U,
	0xd0127845U, 0x95b794fdU, 0x647d0862U, 0xe7ccf5f0U,
	0x5449a36fU, 0x877d48faU, 0xc39dfd27U, 0xf33e8d1eU,
	0x0a476341U, 0x992eff74U, 0x3a6f6eabU, 0xf4f8fd37U,
	0xa812dc60U, 0xa1ebddf8U, 0x991be14cU, 0xdb6e6b0dU,
	0xc67b5510U, 0x6d672c37U, 0x2765d43bU, 0xdcd0e804U,
	0xf1290dc7U, 0xcc00ffa3U, 0xb5390f92U, 0x690fed0bU,
	0x667b9ffbU, 0xcedb7d9cU, 0xa091cf0bU, 0xd9155ea3U,
	0xbb132f88U, 0x515bad24U, 0x7b9479bfU, 0x763bd6ebU,
	0x37392eb3U, 0xcc115979U, 0x8026e297U, 0xf42e312dU,
	0x6842ada7U, 0xc66a2b3bU, 0x12754cccU, 0x782ef11cU,
	0x6a124237U, 0xb79251e7U, 0x06a1bbe6U, 0x4bfb6350U,
	0x1a6b1018U, 0x11caedfaU, 0x3d25bdd8U, 0xe2e1c3c9U,
	0x44421659U, 0x0a121386U, 0xd90cec6eU, 0xd5abea2aU,
	0x64af674eU, 0xda86a85fU, 0xbebfe988U, 0x64e4c3feU,
	0x9dbc8057U, 0xf0f7c086U, 0x60787bf8U, 0x6003604dU,
	0xd1fd8346U, 0xf6381fb0U, 0x7745ae04U, 0xd736fcccU,
	0x83426b33U, 0xf01eab71U, 0xb0804187U, 0x3c005e5fU,
	0x77a057beU, 0xbde8ae24U, 0x55464299U, 0xbf582e61U,
	0x4e58f48fU, 0xf2ddfda2U, 0xf474ef38U, 0x8789bdc2U,
	0x5366f9c3U, 0xc8b38e74U, 0xb475f255U, 0x46fcd9b9U,
	0x7aeb2661U, 0x8b1ddf84U, 0x846a0e79U, 0x915f95e2U,
	0x466e598eU, 0x20b45770U, 0x8cd55591U, 0xc902de4cU,
	0xb90bace1U, 0xbb8205d0U, 0x11a86248U, 0x7574a99eU,
	0xb77f19b6U, 0xe0a9dc09U, 0x662d09a1U, 0xc4324633U,
	0xe85a1f02U, 0x09f0be8cU, 0x4a99a025U, 0x1d6efe10U,
	0x1ab93d1dU, 0x0ba5a4dfU, 0xa186f20fU, 0x2868f169U,
	0xdcb7da83U, 0x573906feU, 0xa1e2ce9bU, 0x4fcd7f52U,
	0x50115e01U, 0xa70683faU, 0xa002b5c4U, 0x0de6d027U,
	0x9af88c27U, 0x773f8641U, 0xc3604c06U, 0x61a806b5U,
	0xf0177a28U, 0xc0f586e0U, 0x006058aaU, 0x30dc7d62U,
	0x11e69ed7U, 0x2338ea63U, 0x53c2dd94U, 0xc2c21634U,
	0xbbcbee56U, 0x90bcb6deU, 0xebfc7da1U, 0xce591d76U,
	0x6f05e409U, 0x4b7c0188U, 0x39720a3dU, 0x7c927c24U,
	0x86e3725fU, 0x724d9db9U, 0x1ac15bb4U, 0xd39eb8fcU,
	0xed545578U, 0x08fca5b5U, 0xd83d7cd3U, 0x4dad0fc4U,
	0x1e50ef5eU, 0xb161e6f8U, 0xa28514d9U, 0x6c51133cU,
	0x6fd5c7e7U, 0x56e14ec4U, 0x362abfceU, 0xddc6c837U,
	0xd79a3234U, 0x92638212U, 0x670efa8eU, 0x406000e0U,

	/* S-Box 3. */
	0x3a39ce37U, 0xd3faf5cfU, 0xabc27737U, 0x5ac52d1bU,
	0x5cb0679eU, 0x4fa33742U, 0xd3822740U, 0x99bc9bbeU,
	0xd5118e9dU, 0xbf0f7315U, 0xd62d1c7eU, 0xc700c47bU,
	0xb78c1b6bU, 0x21a19045U, 0xb26eb1beU, 0x6a366eb4U,
	0x5748ab2fU, 0xbc946e79U, 0xc6a376d2U, 0x6549c2c8U,
	0x530ff8eeU, 0x468dde7dU, 0xd5730a1dU, 0x4cd04dc6U,
	0x2939bbdbU, 0xa9ba4650U, 0xac9526e8U, 0xbe5ee304U,
	0xa1fad5f0U, 0x6a2d519aU, 0x63ef8ce2U, 0x9a86ee22U,
	0xc089c2b8U, 0x43242ef6U, 0xa51e03aaU, 0x9cf2d0a4U,
	0x83c061baU, 0x9be96a4dU, 0x8fe51550U, 0xba645bd6U,
	0x2826a2f9U, 0xa73a3ae1U, 0x4ba99586U, 0xef5562e9U,
	0xc72fefd3U, 0xf752f7daU, 0x3f046f69U, 0x77fa0a59U,
	0x80e4a915U, 0x87b08601U, 0x9b09e6adU, 0x3b3ee593U,
	0xe990fd5aU, 0x9e34d797U, 0x2cf0b7d9U, 0x022b8b51U,
	0x96d5ac3aU, 0x017da67dU, 0xd1cf3ed6U, 0x7c7d2d28U,
	0x1f9f25cfU, 0xadf2b89bU, 0x5ad6b472U, 0x5a88f54cU,
	0xe029ac71U, 0xe019a5e6U, 0x47b0acfdU, 0xed93fa9bU,
	0xe8d3c48dU, 0x283b57ccU, 0xf8d56629U, 0x79132e28U,
	0x785f0191U, 0xed756055U, 0xf7960e44U, 0xe3d35e8cU,
	0x15056dd4U, 0x88f46dbaU, 0x03a16125U, 0x0564f0bdU,
	0xc3eb9e15U, 0x3c9057a2U, 0x97271aecU, 0xa93a072aU,
	0x1b3f6d9bU, 0x1e6321f5U, 0xf59c66fbU, 0x26dcf319U,
	0x7533d928U, 0xb155fdf5U, 0x03563482U, 0x8aba3cbbU,
	0x28517711U, 0xc20ad9f8U, 0xabcc5167U, 0xccad925fU,
	0x4de81751U, 0x3830dc8eU, 0x379d5862U, 0x9320f991U,
	0xea7a90c2U, 0xfb3e7bceU, 0x5121ce64U, 0x774fbe32U,
	0xa8b6e37eU, 0xc3293d46U, 0x48de5369U, 0x6413e680U,
	0xa2ae0810U, 0xdd6db224U, 0x69852dfdU, 0x09072166U,
	0xb39a460aU, 0x6445c0ddU, 0x586cdecfU, 0x1c20c8aeU,
	0x5bbef7ddU, 0x1b588d40U, 0xccd2017fU, 0x6bb4e3bbU,
	0xdda26a7eU, 0x3a59ff45U, 0x3e350a44U, 0xbcb4cdd5U,
	0x72eacea8U, 0xfa6484bbU, 0x8d6612aeU, 0xbf3c6f47U,
	0xd29be463U, 0x542f5d9eU, 0xaec2771bU, 0xf64e6370U,
	0x740e0d8dU, 0xe75b1357U, 0xf8721671U, 0xaf537d5dU,
	0x4040cb08U, 0x4eb4e2ccU, 0x34d2466aU, 0x0115af84U,
	0xe1b00428U, 0x95983a1dU, 0x06b89fb4U, 0xce6ea048U,
	0x6f3f3b82U, 0x3520ab82U, 0x011a1d4bU, 0x277227f8U,
	0x611560b1U, 0xe7933fdcU, 0xbb3a792bU, 0x344525bdU,
	0xa08839e1U, 0x51ce794bU, 0x2f32c9b7U, 0xa01fbac9U,
	0xe01cc87eU, 0xbcc7d1f6U, 0xcf0111c3U, 0xa1e8aac7U,
	0x1a908749U, 0xd44fbd9aU, 0xd0dadecbU, 0xd50ada38U,
	0x0339c32aU, 0xc6913667U, 0x8df9317cU, 0xe0b12b4fU,
	0xf79e59b7U, 0x43f5bb3aU, 0xf2d519ffU, 0x27d9459cU,
	0xbf97222cU, 0x15e6fc2aU, 0x0f91fc71U, 0x9b941525U,
	0xfae59361U, 0xceb69cebU, 0xc2a86459U, 0x12baa8d1U,
	0xb6c1075eU, 0xe3056a0cU, 0x10d25065U, 0xcb03a442U,
	0xe0ec6e0eU, 0x1698db3bU, 0x4c98a0beU, 0x3278e964U,
	0x9f1f9532U, 0xe0d392dfU, 0xd3a0342bU, 0x8971f21eU,
	0x1b0a7441U, 0x4ba3348cU, 0xc5be7120U, 0xc37632d8U,
	0xdf359f8dU, 0x9b992f2eU, 0xe60b6f47U, 0x0fe3f11dU,
	0xe54cda54U, 0x1edad891U, 0xce6279cfU, 0xcd3e7e6fU,
	0x1618b166U, 0xfd2c1d05U, 0x848fd2c5U, 0xf6fb2299U,
	0xf523f357U, 0xa6327623U, 0x93a83531U, 0x56cccd02U,
	0xacf08162U, 0x5a75ebb5U, 0x6e163697U, 0x88d273ccU,
	0xde966292U, 0x81b949d0U, 0x4c50901bU, 0x71c65614U,
	0xe6c6c7bdU, 0x327a140aU, 0x45e1d006U, 0xc3f27b9aU,
	0xc9aa53fdU, 0x62a80f00U, 0xbb25bfe2U, 0x35bdd2f6U,
	0x71126905U, 0xb2040222U, 0xb6cbcf7cU, 0xcd769c2bU,
	0x53113ec0U, 0x1640e3d3U, 0x38abbd60U, 0x2547adf0U,
	0xba38209cU, 0xf746ce76U, 0x77afa1c5U, 0x20756060U,
	0x85cbfe4eU, 0x8ae88dd8U, 0x7aaaf9b0U, 0x4cf9aa7eU,
	0x1948c25cU, 0x02fb8a8cU, 0x01c36ae4U, 0xd6ebe1f9U,
	0x90d4f869U, 0xa65cdea0U, 0x3f09252dU, 0xc208e69fU,
	0xb74e6132U, 0xce77e25bU, 0x578fdfe3U, 0x3ac372e6U,
};

typedef struct keysched_s {
	uint32_t ksch_S[1024];	/* The 4 S boxes are 256 32-bit words. */
	uint32_t ksch_P[18];	/* P box is 18 32-bit words. */
} keysched_t;

/*
 * Since ROUND() is a macro, make sure that the things inside can be
 * evaluated more than once.  Especially when calling F().
 * Assume the presence of local variables:
 *
 *	uint32_t *P;
 *	uint32_t *S;
 *	uint32_t tmp;
 *
 *
 * And to Microsoft interview survivors out there, perhaps I should do the
 * XOR swap trick, or at least #ifdef (__i386) the tmp = ... = tmp; stuff.
 */

#define	F(word) \
	(((S[(word >> 24) & 0xff] + S[256 + ((word >> 16) & 0xff)]) ^ \
		S[512 + ((word >> 8) & 0xff)]) + S[768 + (word & 0xff)])

#define	ROUND(left, right, i) \
	(left) ^= P[i]; \
	(right) ^= F((left)); \
	tmp = (left); \
	(left) = (right); \
	(right) = tmp;

/*
 * Encrypt a block of data.  Because of addition operations, convert blocks
 * to their big-endian representation, even on Intel boxen.
 */
/* ARGSUSED */
int
blowfish_encrypt_block(const void *cookie, const uint8_t *block,
    uint8_t *out_block)
{
	keysched_t *ksch = (keysched_t *)cookie;

	uint32_t left, right, tmp;
	uint32_t *P = ksch->ksch_P;
	uint32_t *S = ksch->ksch_S;
#ifdef _BIG_ENDIAN
	uint32_t *b32;

	if (IS_P2ALIGNED(block, sizeof (uint32_t))) {
		/* LINTED:  pointer alignment */
		b32 = (uint32_t *)block;
		left = b32[0];
		right = b32[1];
	} else
#endif
	{
	/*
	 * Read input block and place in left/right in big-endian order.
	 */
#ifdef UNALIGNED_POINTERS_PERMITTED
	left = htonl(*(uint32_t *)(void *)&block[0]);
	right = htonl(*(uint32_t *)(void *)&block[4]);
#else
	left = ((uint32_t)block[0] << 24)
	    | ((uint32_t)block[1] << 16)
	    | ((uint32_t)block[2] << 8)
	    | (uint32_t)block[3];
	right = ((uint32_t)block[4] << 24)
	    | ((uint32_t)block[5] << 16)
	    | ((uint32_t)block[6] << 8)
	    | (uint32_t)block[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}

	ROUND(left, right, 0);
	ROUND(left, right, 1);
	ROUND(left, right, 2);
	ROUND(left, right, 3);
	ROUND(left, right, 4);
	ROUND(left, right, 5);
	ROUND(left, right, 6);
	ROUND(left, right, 7);
	ROUND(left, right, 8);
	ROUND(left, right, 9);
	ROUND(left, right, 10);
	ROUND(left, right, 11);
	ROUND(left, right, 12);
	ROUND(left, right, 13);
	ROUND(left, right, 14);
	ROUND(left, right, 15);

	tmp = left;
	left = right;
	right = tmp;
	right ^= P[16];
	left ^= P[17];

#ifdef _BIG_ENDIAN
	if (IS_P2ALIGNED(out_block, sizeof (uint32_t))) {
		/* LINTED:  pointer alignment */
		b32 = (uint32_t *)out_block;
		b32[0] = left;
		b32[1] = right;
	} else
#endif
	{
		/* Put the block back into the user's block with final swap */
#ifdef UNALIGNED_POINTERS_PERMITTED
		*(uint32_t *)(void *)&out_block[0] = htonl(left);
		*(uint32_t *)(void *)&out_block[4] = htonl(right);
#else
		out_block[0] = left >> 24;
		out_block[1] = left >> 16;
		out_block[2] = left >> 8;
		out_block[3] = left;
		out_block[4] = right >> 24;
		out_block[5] = right >> 16;
		out_block[6] = right >> 8;
		out_block[7] = right;
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}
	return (CRYPTO_SUCCESS);
}

/*
 * Decrypt a block of data.  Because of addition operations, convert blocks
 * to their big-endian representation, even on Intel boxen.
 * It should look like the blowfish_encrypt_block() operation
 * except for the order in which the S/P boxes are accessed.
 */
/* ARGSUSED */
int
blowfish_decrypt_block(const void *cookie, const uint8_t *block,
    uint8_t *out_block)
{
	keysched_t *ksch = (keysched_t *)cookie;

	uint32_t left, right, tmp;
	uint32_t *P = ksch->ksch_P;
	uint32_t *S = ksch->ksch_S;
#ifdef _BIG_ENDIAN
	uint32_t *b32;

	if (IS_P2ALIGNED(block, sizeof (uint32_t))) {
		/* LINTED:  pointer alignment */
		b32 = (uint32_t *)block;
		left = b32[0];
		right = b32[1];
	} else
#endif
	{
	/*
	 * Read input block and place in left/right in big-endian order.
	 */
#ifdef UNALIGNED_POINTERS_PERMITTED
	left = htonl(*(uint32_t *)(void *)&block[0]);
	right = htonl(*(uint32_t *)(void *)&block[4]);
#else
	left = ((uint32_t)block[0] << 24)
	    | ((uint32_t)block[1] << 16)
	    | ((uint32_t)block[2] << 8)
	    | (uint32_t)block[3];
	right = ((uint32_t)block[4] << 24)
	    | ((uint32_t)block[5] << 16)
	    | ((uint32_t)block[6] << 8)
	    | (uint32_t)block[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}

	ROUND(left, right, 17);
	ROUND(left, right, 16);
	ROUND(left, right, 15);
	ROUND(left, right, 14);
	ROUND(left, right, 13);
	ROUND(left, right, 12);
	ROUND(left, right, 11);
	ROUND(left, right, 10);
	ROUND(left, right, 9);
	ROUND(left, right, 8);
	ROUND(left, right, 7);
	ROUND(left, right, 6);
	ROUND(left, right, 5);
	ROUND(left, right, 4);
	ROUND(left, right, 3);
	ROUND(left, right, 2);

	tmp = left;
	left = right;
	right = tmp;
	right ^= P[1];
	left ^= P[0];

#ifdef _BIG_ENDIAN
	if (IS_P2ALIGNED(out_block, sizeof (uint32_t))) {
		/* LINTED:  pointer alignment */
		b32 = (uint32_t *)out_block;
		b32[0] = left;
		b32[1] = right;
	} else
#endif
	{
	/* Put the block back into the user's block with final swap */
#ifdef UNALIGNED_POINTERS_PERMITTED
		*(uint32_t *)(void *)&out_block[0] = htonl(left);
		*(uint32_t *)(void *)&out_block[4] = htonl(right);
#else
		out_block[0] = left >> 24;
		out_block[1] = left >> 16;
		out_block[2] = left >> 8;
		out_block[3] = left;
		out_block[4] = right >> 24;
		out_block[5] = right >> 16;
		out_block[6] = right >> 8;
		out_block[7] = right;
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}
	return (CRYPTO_SUCCESS);
}

static void
bitrepeat(uint8_t *pattern, uint_t len_bytes, uint_t len_bits, uint8_t *dst,
    uint_t dst_len_bytes)
{
	uint8_t *current = dst;
	uint_t bitsleft = CRYPTO_BYTES2BITS(dst_len_bytes);
	uint_t bitoffset = 0;
	uint_t currentbits;
	int i;

	BLOWFISH_ASSERT(CRYPTO_BITS2BYTES(len_bits) == len_bytes);

	bzero(dst, dst_len_bytes);

	while (bitsleft != 0) {
		if (bitsleft >= len_bits) {
			currentbits = len_bits;

			for (i = 0; i < len_bytes; i++) {
				if (currentbits >= 8) {
					*current++ |= pattern[i] >> bitoffset;
					*current |= pattern[i] << 8 - bitoffset;
					currentbits -= 8;
				} else {
					*current |= pattern[i] >> bitoffset;
					bitoffset = bitoffset + currentbits;
					bitoffset &= 0x7;
					if (bitoffset == 0)
						current++;
				}
			}
			bitsleft -= len_bits;
		} else {
			currentbits = bitsleft;

			for (i = 0; i < len_bytes && bitsleft != 0; i++) {
				if (currentbits >= 8 &&
				    current < dst + dst_len_bytes) {
					*current++ |= pattern[i] >> bitoffset;
					*current |= pattern[i] << 8 - bitoffset;
					currentbits -= 8;
					bitsleft -= 8;
				} else {
					*current |= pattern[i] >> bitoffset;
					bitsleft -= bitoffset;
					bitoffset = bitoffset + currentbits;
					bitoffset &= 0x7;
					if (bitoffset == 0)
						current++;
					currentbits = 0;
				}
			}
			bitsleft = 0;
		}
	}
}

/*
 * Initialize key schedules for Blowfish.
 */
void
blowfish_init_keysched(uint8_t *key, uint_t bits, void *keysched)
{
	keysched_t *newbie = keysched;
	uint32_t *P = newbie->ksch_P;
	uint32_t *S = newbie->ksch_S;
	uint32_t *initp;
	uint32_t tmpblock[] = {0, 0};
	uint8_t *rawkeybytes = (uint8_t *)P;
	int i, slop, copylen;
	uintptr_t bytesleft;
	uint_t len;

	len = CRYPTO_BITS2BYTES(bits);

	if ((bits & 0x7) != 0) {
		/*
		 * Really slow case, bits aren't on a byte boundary.
		 * Keep track of individual bits copied over.  :-P
		 */
		bitrepeat(key, len, bits, rawkeybytes, 72);
	} else {
		slop = 72 % len;

		/* Someone gave us a nice amount (i.e. div by 8) of bits */
		while (rawkeybytes != (uint8_t *)(P + 18)) {
			bytesleft =
			    (uintptr_t)(P + 18) - (uintptr_t)rawkeybytes;
			copylen = (bytesleft >= len) ? len : slop;
			bcopy(key, rawkeybytes, copylen);
			rawkeybytes += copylen;
		}
	}

	for (i = 0; i < 18; i++)
		P[i] = ntohl(P[i]) ^ init_P[i];

	/* Go bcopy go!  (Hope that Ultra's bcopy is faster than me!) */
	bcopy(init_S, S, sizeof (init_S));

	/*
	 * When initializing P and S boxes, store the results of a single
	 * encrypt-block operation in "host order", which on little-endian
	 * means byte-swapping.  Fortunately, the ntohl() function does this
	 * quite nicely, and it a NOP on big-endian machine.
	 */
	initp = P;
	for (i = 0; i < 9; i++) {
		(void) blowfish_encrypt_block(newbie, (uint8_t *)tmpblock,
		    (uint8_t *)tmpblock);
		*initp++ = ntohl(tmpblock[0]);
		*initp++ = ntohl(tmpblock[1]);
	}

	initp = S;
	for (i = 0; i < 512; i++) {
		(void) blowfish_encrypt_block(newbie, (uint8_t *)tmpblock,
		    (uint8_t *)tmpblock);
		*initp++ = ntohl(tmpblock[0]);
		*initp++ = ntohl(tmpblock[1]);
	}
}

/*
 * Allocate key schedule for Blowfish.
 */
/* ARGSUSED */
void *
blowfish_alloc_keysched(size_t *size, int kmflag)
{
	keysched_t *keysched;

#ifdef _KERNEL
	keysched = (keysched_t *)kmem_alloc(sizeof (keysched_t), kmflag);
#else
	keysched = (keysched_t *)malloc(sizeof (keysched_t));
#endif /* _KERNEL */
	if (keysched != NULL) {
		*size = sizeof (keysched_t);
		return (keysched);
	}

	return (NULL);
}

void
blowfish_copy_block(uint8_t *in, uint8_t *out)
{
	if (IS_P2ALIGNED(in, sizeof (uint32_t)) &&
	    IS_P2ALIGNED(out, sizeof (uint32_t))) {
		/* LINTED: pointer alignment */
		*(uint32_t *)&out[0] = *(uint32_t *)&in[0];
		/* LINTED: pointer alignment */
		*(uint32_t *)&out[4] = *(uint32_t *)&in[4];
	} else {
		BLOWFISH_COPY_BLOCK(in, out);
	}
}

/* XOR block of data into dest */
void
blowfish_xor_block(uint8_t *data, uint8_t *dst)
{
	if (IS_P2ALIGNED(dst, sizeof (uint32_t)) &&
	    IS_P2ALIGNED(data, sizeof (uint32_t))) {
		/* LINTED: pointer alignment */
		*(uint32_t *)&dst[0] ^= *(uint32_t *)&data[0];
		/* LINTED: pointer alignment */
		*(uint32_t *)&dst[4] ^= *(uint32_t *)&data[4];
	} else {
		BLOWFISH_XOR_BLOCK(data, dst);
	}
}

/*
 * Encrypt multiple blocks of data according to mode.
 */
int
blowfish_encrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	blowfish_ctx_t *blowfish_ctx = ctx;
	int rv;

	if (blowfish_ctx->bc_flags & CBC_MODE) {
		rv = cbc_encrypt_contiguous_blocks(ctx, data, length, out,
		    BLOWFISH_BLOCK_LEN, blowfish_encrypt_block,
		    blowfish_copy_block, blowfish_xor_block);
	} else {
		rv = ecb_cipher_contiguous_blocks(ctx, data, length, out,
		    BLOWFISH_BLOCK_LEN, blowfish_encrypt_block);
	}
	return (rv);
}

/*
 * Decrypt multiple blocks of data according to mode.
 */
int
blowfish_decrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	blowfish_ctx_t *blowfish_ctx = ctx;
	int rv;

	if (blowfish_ctx->bc_flags & CBC_MODE) {
		rv = cbc_decrypt_contiguous_blocks(ctx, data, length, out,
		    BLOWFISH_BLOCK_LEN, blowfish_decrypt_block,
		    blowfish_copy_block, blowfish_xor_block);
	} else {
		rv = ecb_cipher_contiguous_blocks(ctx, data, length, out,
		    BLOWFISH_BLOCK_LEN, blowfish_decrypt_block);
		if (rv == CRYPTO_DATA_LEN_RANGE)
			rv = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
	}
	return (rv);
}
