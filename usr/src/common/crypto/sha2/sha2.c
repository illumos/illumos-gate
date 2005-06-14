/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * The basic framework for this code came from the reference
 * implementation for MD5.  That implementation is Copyright (C)
 * 1991-2, RSA Data Security, Inc. Created 1991. All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 *
 * NOTE: Cleaned-up and optimized, version of SHA2, based on the FIPS 180-2
 * standard, available at http://www.itl.nist.gov/div897/pubs/fip180-2.htm
 * Not as fast as one would like -- further optimizations are encouraged
 * and appreciated.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sha2.h>
#include <sys/sha2_consts.h>

#ifdef _KERNEL

#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/strsun.h>

/*
 * The sha2 module is created with two modlinkages:
 * - a modlmisc that allows consumers to directly call the entry points
 *   SHA2Init, SHA2Update, and SHA2Final.
 * - a modlcrypto that allows the module to register with the Kernel
 *   Cryptographic Framework (KCF) as a software provider for the SHA2
 *   mechanisms.
 */

#else

#include <strings.h>
#include <stdlib.h>
#include <errno.h>


#endif	/* !_KERNEL */

static void Encode(uint8_t *, uint32_t *, size_t);
static void Encode64(uint8_t *, uint64_t *, size_t);
static void SHA256Transform(SHA2_CTX *, const uint8_t *);
static void SHA512Transform(SHA2_CTX *, const uint8_t *);

static uint8_t PADDING[128] = { 0x80, /* all zeros */ };

/* Ch and Maj are the basic SHA2 functions. */
#define	Ch(b, c, d)	(((b) & (c)) ^ ((~b) & (d)))
#define	Maj(b, c, d)	(((b) & (c)) ^ ((b) & (d)) ^ ((c) & (d)))

/* Rotates x right n bits. */
#define	ROTR(x, n)	\
	(((x) >> (n)) | ((x) << ((sizeof (x) * NBBY)-(n))))

/* Shift x right n bits */
#define	SHR(x, n)	((x) >> (n))

/* SHA256 Functions */
#define	BIGSIGMA0_256(x)	(ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define	BIGSIGMA1_256(x)	(ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define	SIGMA0_256(x)		(ROTR((x), 7) ^ ROTR((x), 18) ^ SHR((x), 3))
#define	SIGMA1_256(x)		(ROTR((x), 17) ^ ROTR((x), 19) ^ SHR((x), 10))

#define	SHA256ROUND(a, b, c, d, e, f, g, h, i, w)			\
	T1 = h + BIGSIGMA1_256(e) + Ch(e, f, g) + SHA256_CONST(i) + w;	\
	d += T1;							\
	T2 = BIGSIGMA0_256(a) + Maj(a, b, c);				\
	h = T1 + T2

/* SHA384/512 Functions */
#define	BIGSIGMA0(x)	(ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#define	BIGSIGMA1(x)	(ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#define	SIGMA0(x)	(ROTR((x), 1) ^ ROTR((x), 8) ^ SHR((x), 7))
#define	SIGMA1(x)	(ROTR((x), 19) ^ ROTR((x), 61) ^ SHR((x), 6))
#define	SHA512ROUND(a, b, c, d, e, f, g, h, i, w)			\
	T1 = h + BIGSIGMA1(e) + Ch(e, f, g) + SHA512_CONST(i) + w;	\
	d += T1;							\
	T2 = BIGSIGMA0(a) + Maj(a, b, c);				\
	h = T1 + T2

#ifdef _KERNEL

static struct modlmisc modlmisc = {
	&mod_miscops,
	"SHA2 Message-Digest Algorithm"
};

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"SHA2 Kernel SW Provider %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, &modlcrypto, NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */

#endif /* _KERNEL */

/*
 * List of support mechanisms in this module.
 *
 * It is important to note that in the module, division or modulus calculations
 * are used on the enumerated type to determine which mechanism is being used;
 * therefore, changing the order or additional mechanisms should be done
 * carefully
 */
typedef enum sha2_mech_type {
	SHA256_MECH_INFO_TYPE,		/* SUN_CKM_SHA256 */
	SHA256_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA256_HMAC */
	SHA256_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA256_HMAC_GENERAL */
	SHA384_MECH_INFO_TYPE,		/* SUN_CKM_SHA384 */
	SHA384_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA384_HMAC */
	SHA384_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA384_HMAC_GENERAL */
	SHA512_MECH_INFO_TYPE,		/* SUN_CKM_SHA512 */
	SHA512_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA512_HMAC */
	SHA512_HMAC_GEN_MECH_INFO_TYPE	/* SUN_CKM_SHA512_HMAC_GENERAL */
} sha2_mech_type_t;

#ifdef _KERNEL

#define	SHA2_HMAC_MIN_KEY_LEN	8	/* SHA2-HMAC min key length in bits */
#define	SHA2_HMAC_MAX_KEY_LEN	INT_MAX /* SHA2-HMAC max key length in bits */

#define	SHA256_DIGEST_LENGTH	32	/* SHA256 digest length in bytes */
#define	SHA384_DIGEST_LENGTH	48	/* SHA384 digest length in bytes */
#define	SHA512_DIGEST_LENGTH	64	/* SHA512 digest length in bytes */

#define	SHA256_HMAC_BLOCK_SIZE	64	/* SHA256-HMAC block size */
#define	SHA512_HMAC_BLOCK_SIZE	128	/* SHA512-HMAC block size */

/*
 * Context for SHA2 mechanism.
 */
typedef struct sha2_ctx {
	sha2_mech_type_t	sc_mech_type;	/* type of context */
	SHA2_CTX		sc_sha2_ctx;	/* SHA2 context */
} sha2_ctx_t;

/*
 * Context for SHA2 HMAC and HMAC GENERAL mechanisms.
 */
typedef struct sha2_hmac_ctx {
	sha2_mech_type_t	hc_mech_type;	/* type of context */
	uint32_t		hc_digest_len;	/* digest len in bytes */
	SHA2_CTX		hc_icontext;	/* inner SHA2 context */
	SHA2_CTX		hc_ocontext;	/* outer SHA2 context */
} sha2_hmac_ctx_t;

/*
 * Macros to access the SHA2 or SHA2-HMAC contexts from a context passed
 * by KCF to one of the entry points.
 */

#define	PROV_SHA2_CTX(ctx)	((sha2_ctx_t *)(ctx)->cc_provider_private)
#define	PROV_SHA2_HMAC_CTX(ctx)	((sha2_hmac_ctx_t *)(ctx)->cc_provider_private)

/* to extract the digest length passed as mechanism parameter */
#define	PROV_SHA2_GET_DIGEST_LEN(m, len) {				\
	if (IS_P2ALIGNED((m)->cm_param, sizeof (ulong_t)))		\
		(len) = (uint32_t)*((ulong_t *)(m)->cm_param);	\
	else {								\
		ulong_t tmp_ulong;					\
		bcopy((m)->cm_param, &tmp_ulong, sizeof (ulong_t));	\
		(len) = (uint32_t)tmp_ulong;				\
	}								\
}

#define	PROV_SHA2_DIGEST_KEY(mech, ctx, key, len, digest) {	\
	SHA2Init(mech, ctx);				\
	SHA2Update(ctx, key, len);			\
	SHA2Final(digest, ctx);				\
}

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t sha2_mech_info_tab[] = {
	/* SHA256 */
	{SUN_CKM_SHA256, SHA256_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA256-HMAC */
	{SUN_CKM_SHA256_HMAC, SHA256_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA256-HMAC GENERAL */
	{SUN_CKM_SHA256_HMAC_GENERAL, SHA256_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA384 */
	{SUN_CKM_SHA384, SHA384_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA384-HMAC */
	{SUN_CKM_SHA384_HMAC, SHA384_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA384-HMAC GENERAL */
	{SUN_CKM_SHA384_HMAC_GENERAL, SHA384_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA512 */
	{SUN_CKM_SHA512, SHA512_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA512-HMAC */
	{SUN_CKM_SHA512_HMAC, SHA512_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA512-HMAC GENERAL */
	{SUN_CKM_SHA512_HMAC_GENERAL, SHA512_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

void SHA2Init(uint64_t, SHA2_CTX *);
void SHA2Update(SHA2_CTX *, const uint8_t *, uint32_t);
void SHA2Final(uint8_t *, SHA2_CTX *);

static void sha2_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t sha2_control_ops = {
	sha2_provider_status
};

static int sha2_digest_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_req_handle_t);
static int sha2_digest(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha2_digest_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha2_digest_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha2_digest_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

static crypto_digest_ops_t sha2_digest_ops = {
	sha2_digest_init,
	sha2_digest,
	sha2_digest_update,
	NULL,
	sha2_digest_final,
	sha2_digest_atomic
};

static int sha2_mac_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sha2_mac_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha2_mac_final(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t);
static int sha2_mac_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sha2_mac_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_mac_ops_t sha2_mac_ops = {
	sha2_mac_init,
	NULL,
	sha2_mac_update,
	sha2_mac_final,
	sha2_mac_atomic,
	sha2_mac_verify_atomic
};

static int sha2_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int sha2_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t sha2_ctx_ops = {
	sha2_create_ctx_template,
	sha2_free_context
};

static crypto_ops_t sha2_crypto_ops = {
	&sha2_control_ops,
	&sha2_digest_ops,
	NULL,
	&sha2_mac_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&sha2_ctx_ops
};

static crypto_provider_info_t sha2_prov_info = {
	CRYPTO_SPI_VERSION_1,
	"SHA2 Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&sha2_crypto_ops,
	sizeof (sha2_mech_info_tab)/sizeof (crypto_mech_info_t),
	sha2_mech_info_tab
};

static crypto_kcf_provider_handle_t sha2_prov_handle = NULL;

int
_init()
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/*
	 * Register with KCF. If the registration fails, log an
	 * error but do not uninstall the module, since the functionality
	 * provided by misc/sha2 should still be available.
	 */
	if ((ret = crypto_register_provider(&sha2_prov_info,
	    &sha2_prov_handle)) != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "sha2 _init: "
		    "crypto_register_provider() failed (0x%x)", ret);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#endif /* _KERNEL */


/*
 * sparc optimization:
 *
 * on the sparc, we can load big endian 32-bit data easily.  note that
 * special care must be taken to ensure the address is 32-bit aligned.
 * in the interest of speed, we don't check to make sure, since
 * careful programming can guarantee this for us.
 */

#if	defined(_BIG_ENDIAN)

#define	LOAD_BIG_32(addr)	(*(uint32_t *)(addr))

#else	/* little endian -- will work on big endian, but slowly */

#define	LOAD_BIG_32(addr)	\
	(((addr)[0] << 24) | ((addr)[1] << 16) | ((addr)[2] << 8) | (addr)[3])
#endif


#if	defined(_BIG_ENDIAN)

#define	LOAD_BIG_64(addr)	(*(uint64_t *)(addr))

#else	/* little endian -- will work on big endian, but slowly */

#define	LOAD_BIG_64(addr)	\
	(((uint64_t)(addr)[0] << 56) | ((uint64_t)(addr)[1] << 48) |	\
	    ((uint64_t)(addr)[2] << 40) | ((uint64_t)(addr)[3] << 32) |	\
	    ((uint64_t)(addr)[4] << 24) | ((uint64_t)(addr)[5] << 16) |	\
	    ((uint64_t)(addr)[6] << 8) | (uint64_t)(addr)[7])

#endif


/* SHA256 Transform */

static void
SHA256Transform(SHA2_CTX *ctx, const uint8_t *blk)
{

	uint32_t a = ctx->state.s32[0];
	uint32_t b = ctx->state.s32[1];
	uint32_t c = ctx->state.s32[2];
	uint32_t d = ctx->state.s32[3];
	uint32_t e = ctx->state.s32[4];
	uint32_t f = ctx->state.s32[5];
	uint32_t g = ctx->state.s32[6];
	uint32_t h = ctx->state.s32[7];

	uint32_t w0, w1, w2, w3, w4, w5, w6, w7;
	uint32_t w8, w9, w10, w11, w12, w13, w14, w15;
	uint32_t T1, T2;

#if	defined(__sparc)
	static const uint32_t sha256_consts[] = {
		SHA256_CONST_0, SHA256_CONST_1, SHA256_CONST_2,
		SHA256_CONST_3, SHA256_CONST_4, SHA256_CONST_5,
		SHA256_CONST_6, SHA256_CONST_7, SHA256_CONST_8,
		SHA256_CONST_9, SHA256_CONST_10, SHA256_CONST_11,
		SHA256_CONST_12, SHA256_CONST_13, SHA256_CONST_14,
		SHA256_CONST_15, SHA256_CONST_16, SHA256_CONST_17,
		SHA256_CONST_18, SHA256_CONST_19, SHA256_CONST_20,
		SHA256_CONST_21, SHA256_CONST_22, SHA256_CONST_23,
		SHA256_CONST_24, SHA256_CONST_25, SHA256_CONST_26,
		SHA256_CONST_27, SHA256_CONST_28, SHA256_CONST_29,
		SHA256_CONST_30, SHA256_CONST_31, SHA256_CONST_32,
		SHA256_CONST_33, SHA256_CONST_34, SHA256_CONST_35,
		SHA256_CONST_36, SHA256_CONST_37, SHA256_CONST_38,
		SHA256_CONST_39, SHA256_CONST_40, SHA256_CONST_41,
		SHA256_CONST_42, SHA256_CONST_43, SHA256_CONST_44,
		SHA256_CONST_45, SHA256_CONST_46, SHA256_CONST_47,
		SHA256_CONST_48, SHA256_CONST_49, SHA256_CONST_50,
		SHA256_CONST_51, SHA256_CONST_52, SHA256_CONST_53,
		SHA256_CONST_54, SHA256_CONST_55, SHA256_CONST_56,
		SHA256_CONST_57, SHA256_CONST_58, SHA256_CONST_59,
		SHA256_CONST_60, SHA256_CONST_61, SHA256_CONST_62,
		SHA256_CONST_63
	};
#endif

	if ((uintptr_t)blk & 0x3) {		/* not 4-byte aligned? */
		bcopy(blk, ctx->buf_un.buf32,  sizeof (ctx->buf_un.buf32));
		blk = (uint8_t *)ctx->buf_un.buf32;
	}

	w0 =  LOAD_BIG_32(blk + 4 * 0);
	SHA256ROUND(a, b, c, d, e, f, g, h, 0, w0);
	w1 =  LOAD_BIG_32(blk + 4 * 1);
	SHA256ROUND(h, a, b, c, d, e, f, g, 1, w1);
	w2 =  LOAD_BIG_32(blk + 4 * 2);
	SHA256ROUND(g, h, a, b, c, d, e, f, 2, w2);
	w3 =  LOAD_BIG_32(blk + 4 * 3);
	SHA256ROUND(f, g, h, a, b, c, d, e, 3, w3);
	w4 =  LOAD_BIG_32(blk + 4 * 4);
	SHA256ROUND(e, f, g, h, a, b, c, d, 4, w4);
	w5 =  LOAD_BIG_32(blk + 4 * 5);
	SHA256ROUND(d, e, f, g, h, a, b, c, 5, w5);
	w6 =  LOAD_BIG_32(blk + 4 * 6);
	SHA256ROUND(c, d, e, f, g, h, a, b, 6, w6);
	w7 =  LOAD_BIG_32(blk + 4 * 7);
	SHA256ROUND(b, c, d, e, f, g, h, a, 7, w7);
	w8 =  LOAD_BIG_32(blk + 4 * 8);
	SHA256ROUND(a, b, c, d, e, f, g, h, 8, w8);
	w9 =  LOAD_BIG_32(blk + 4 * 9);
	SHA256ROUND(h, a, b, c, d, e, f, g, 9, w9);
	w10 =  LOAD_BIG_32(blk + 4 * 10);
	SHA256ROUND(g, h, a, b, c, d, e, f, 10, w10);
	w11 =  LOAD_BIG_32(blk + 4 * 11);
	SHA256ROUND(f, g, h, a, b, c, d, e, 11, w11);
	w12 =  LOAD_BIG_32(blk + 4 * 12);
	SHA256ROUND(e, f, g, h, a, b, c, d, 12, w12);
	w13 =  LOAD_BIG_32(blk + 4 * 13);
	SHA256ROUND(d, e, f, g, h, a, b, c, 13, w13);
	w14 =  LOAD_BIG_32(blk + 4 * 14);
	SHA256ROUND(c, d, e, f, g, h, a, b, 14, w14);
	w15 =  LOAD_BIG_32(blk + 4 * 15);
	SHA256ROUND(b, c, d, e, f, g, h, a, 15, w15);

	w0 = SIGMA1_256(w14) + w9 + SIGMA0_256(w1) + w0;
	SHA256ROUND(a, b, c, d, e, f, g, h, 16, w0);
	w1 = SIGMA1_256(w15) + w10 + SIGMA0_256(w2) + w1;
	SHA256ROUND(h, a, b, c, d, e, f, g, 17, w1);
	w2 = SIGMA1_256(w0) + w11 + SIGMA0_256(w3) + w2;
	SHA256ROUND(g, h, a, b, c, d, e, f, 18, w2);
	w3 = SIGMA1_256(w1) + w12 + SIGMA0_256(w4) + w3;
	SHA256ROUND(f, g, h, a, b, c, d, e, 19, w3);
	w4 = SIGMA1_256(w2) + w13 + SIGMA0_256(w5) + w4;
	SHA256ROUND(e, f, g, h, a, b, c, d, 20, w4);
	w5 = SIGMA1_256(w3) + w14 + SIGMA0_256(w6) + w5;
	SHA256ROUND(d, e, f, g, h, a, b, c, 21, w5);
	w6 = SIGMA1_256(w4) + w15 + SIGMA0_256(w7) + w6;
	SHA256ROUND(c, d, e, f, g, h, a, b, 22, w6);
	w7 = SIGMA1_256(w5) + w0 + SIGMA0_256(w8) + w7;
	SHA256ROUND(b, c, d, e, f, g, h, a, 23, w7);
	w8 = SIGMA1_256(w6) + w1 + SIGMA0_256(w9) + w8;
	SHA256ROUND(a, b, c, d, e, f, g, h, 24, w8);
	w9 = SIGMA1_256(w7) + w2 + SIGMA0_256(w10) + w9;
	SHA256ROUND(h, a, b, c, d, e, f, g, 25, w9);
	w10 = SIGMA1_256(w8) + w3 + SIGMA0_256(w11) + w10;
	SHA256ROUND(g, h, a, b, c, d, e, f, 26, w10);
	w11 = SIGMA1_256(w9) + w4 + SIGMA0_256(w12) + w11;
	SHA256ROUND(f, g, h, a, b, c, d, e, 27, w11);
	w12 = SIGMA1_256(w10) + w5 + SIGMA0_256(w13) + w12;
	SHA256ROUND(e, f, g, h, a, b, c, d, 28, w12);
	w13 = SIGMA1_256(w11) + w6 + SIGMA0_256(w14) + w13;
	SHA256ROUND(d, e, f, g, h, a, b, c, 29, w13);
	w14 = SIGMA1_256(w12) + w7 + SIGMA0_256(w15) + w14;
	SHA256ROUND(c, d, e, f, g, h, a, b, 30, w14);
	w15 = SIGMA1_256(w13) + w8 + SIGMA0_256(w0) + w15;
	SHA256ROUND(b, c, d, e, f, g, h, a, 31, w15);

	w0 = SIGMA1_256(w14) + w9 + SIGMA0_256(w1) + w0;
	SHA256ROUND(a, b, c, d, e, f, g, h, 32, w0);
	w1 = SIGMA1_256(w15) + w10 + SIGMA0_256(w2) + w1;
	SHA256ROUND(h, a, b, c, d, e, f, g, 33, w1);
	w2 = SIGMA1_256(w0) + w11 + SIGMA0_256(w3) + w2;
	SHA256ROUND(g, h, a, b, c, d, e, f, 34, w2);
	w3 = SIGMA1_256(w1) + w12 + SIGMA0_256(w4) + w3;
	SHA256ROUND(f, g, h, a, b, c, d, e, 35, w3);
	w4 = SIGMA1_256(w2) + w13 + SIGMA0_256(w5) + w4;
	SHA256ROUND(e, f, g, h, a, b, c, d, 36, w4);
	w5 = SIGMA1_256(w3) + w14 + SIGMA0_256(w6) + w5;
	SHA256ROUND(d, e, f, g, h, a, b, c, 37, w5);
	w6 = SIGMA1_256(w4) + w15 + SIGMA0_256(w7) + w6;
	SHA256ROUND(c, d, e, f, g, h, a, b, 38, w6);
	w7 = SIGMA1_256(w5) + w0 + SIGMA0_256(w8) + w7;
	SHA256ROUND(b, c, d, e, f, g, h, a, 39, w7);
	w8 = SIGMA1_256(w6) + w1 + SIGMA0_256(w9) + w8;
	SHA256ROUND(a, b, c, d, e, f, g, h, 40, w8);
	w9 = SIGMA1_256(w7) + w2 + SIGMA0_256(w10) + w9;
	SHA256ROUND(h, a, b, c, d, e, f, g, 41, w9);
	w10 = SIGMA1_256(w8) + w3 + SIGMA0_256(w11) + w10;
	SHA256ROUND(g, h, a, b, c, d, e, f, 42, w10);
	w11 = SIGMA1_256(w9) + w4 + SIGMA0_256(w12) + w11;
	SHA256ROUND(f, g, h, a, b, c, d, e, 43, w11);
	w12 = SIGMA1_256(w10) + w5 + SIGMA0_256(w13) + w12;
	SHA256ROUND(e, f, g, h, a, b, c, d, 44, w12);
	w13 = SIGMA1_256(w11) + w6 + SIGMA0_256(w14) + w13;
	SHA256ROUND(d, e, f, g, h, a, b, c, 45, w13);
	w14 = SIGMA1_256(w12) + w7 + SIGMA0_256(w15) + w14;
	SHA256ROUND(c, d, e, f, g, h, a, b, 46, w14);
	w15 = SIGMA1_256(w13) + w8 + SIGMA0_256(w0) + w15;
	SHA256ROUND(b, c, d, e, f, g, h, a, 47, w15);

	w0 = SIGMA1_256(w14) + w9 + SIGMA0_256(w1) + w0;
	SHA256ROUND(a, b, c, d, e, f, g, h, 48, w0);
	w1 = SIGMA1_256(w15) + w10 + SIGMA0_256(w2) + w1;
	SHA256ROUND(h, a, b, c, d, e, f, g, 49, w1);
	w2 = SIGMA1_256(w0) + w11 + SIGMA0_256(w3) + w2;
	SHA256ROUND(g, h, a, b, c, d, e, f, 50, w2);
	w3 = SIGMA1_256(w1) + w12 + SIGMA0_256(w4) + w3;
	SHA256ROUND(f, g, h, a, b, c, d, e, 51, w3);
	w4 = SIGMA1_256(w2) + w13 + SIGMA0_256(w5) + w4;
	SHA256ROUND(e, f, g, h, a, b, c, d, 52, w4);
	w5 = SIGMA1_256(w3) + w14 + SIGMA0_256(w6) + w5;
	SHA256ROUND(d, e, f, g, h, a, b, c, 53, w5);
	w6 = SIGMA1_256(w4) + w15 + SIGMA0_256(w7) + w6;
	SHA256ROUND(c, d, e, f, g, h, a, b, 54, w6);
	w7 = SIGMA1_256(w5) + w0 + SIGMA0_256(w8) + w7;
	SHA256ROUND(b, c, d, e, f, g, h, a, 55, w7);
	w8 = SIGMA1_256(w6) + w1 + SIGMA0_256(w9) + w8;
	SHA256ROUND(a, b, c, d, e, f, g, h, 56, w8);
	w9 = SIGMA1_256(w7) + w2 + SIGMA0_256(w10) + w9;
	SHA256ROUND(h, a, b, c, d, e, f, g, 57, w9);
	w10 = SIGMA1_256(w8) + w3 + SIGMA0_256(w11) + w10;
	SHA256ROUND(g, h, a, b, c, d, e, f, 58, w10);
	w11 = SIGMA1_256(w9) + w4 + SIGMA0_256(w12) + w11;
	SHA256ROUND(f, g, h, a, b, c, d, e, 59, w11);
	w12 = SIGMA1_256(w10) + w5 + SIGMA0_256(w13) + w12;
	SHA256ROUND(e, f, g, h, a, b, c, d, 60, w12);
	w13 = SIGMA1_256(w11) + w6 + SIGMA0_256(w14) + w13;
	SHA256ROUND(d, e, f, g, h, a, b, c, 61, w13);
	w14 = SIGMA1_256(w12) + w7 + SIGMA0_256(w15) + w14;
	SHA256ROUND(c, d, e, f, g, h, a, b, 62, w14);
	w15 = SIGMA1_256(w13) + w8 + SIGMA0_256(w0) + w15;
	SHA256ROUND(b, c, d, e, f, g, h, a, 63, w15);

	ctx->state.s32[0] += a;
	ctx->state.s32[1] += b;
	ctx->state.s32[2] += c;
	ctx->state.s32[3] += d;
	ctx->state.s32[4] += e;
	ctx->state.s32[5] += f;
	ctx->state.s32[6] += g;
	ctx->state.s32[7] += h;
}


/* SHA384 and SHA512 Transform */

static void
SHA512Transform(SHA2_CTX *ctx, const uint8_t *blk)
{

	uint64_t a = ctx->state.s64[0];
	uint64_t b = ctx->state.s64[1];
	uint64_t c = ctx->state.s64[2];
	uint64_t d = ctx->state.s64[3];
	uint64_t e = ctx->state.s64[4];
	uint64_t f = ctx->state.s64[5];
	uint64_t g = ctx->state.s64[6];
	uint64_t h = ctx->state.s64[7];

	uint64_t w0, w1, w2, w3, w4, w5, w6, w7;
	uint64_t w8, w9, w10, w11, w12, w13, w14, w15;
	uint64_t T1, T2;

#if	defined(__sparc)
	static const uint64_t sha512_consts[] = {
		SHA512_CONST_0, SHA512_CONST_1, SHA512_CONST_2,
		SHA512_CONST_3, SHA512_CONST_4, SHA512_CONST_5,
		SHA512_CONST_6, SHA512_CONST_7, SHA512_CONST_8,
		SHA512_CONST_9, SHA512_CONST_10, SHA512_CONST_11,
		SHA512_CONST_12, SHA512_CONST_13, SHA512_CONST_14,
		SHA512_CONST_15, SHA512_CONST_16, SHA512_CONST_17,
		SHA512_CONST_18, SHA512_CONST_19, SHA512_CONST_20,
		SHA512_CONST_21, SHA512_CONST_22, SHA512_CONST_23,
		SHA512_CONST_24, SHA512_CONST_25, SHA512_CONST_26,
		SHA512_CONST_27, SHA512_CONST_28, SHA512_CONST_29,
		SHA512_CONST_30, SHA512_CONST_31, SHA512_CONST_32,
		SHA512_CONST_33, SHA512_CONST_34, SHA512_CONST_35,
		SHA512_CONST_36, SHA512_CONST_37, SHA512_CONST_38,
		SHA512_CONST_39, SHA512_CONST_40, SHA512_CONST_41,
		SHA512_CONST_42, SHA512_CONST_43, SHA512_CONST_44,
		SHA512_CONST_45, SHA512_CONST_46, SHA512_CONST_47,
		SHA512_CONST_48, SHA512_CONST_49, SHA512_CONST_50,
		SHA512_CONST_51, SHA512_CONST_52, SHA512_CONST_53,
		SHA512_CONST_54, SHA512_CONST_55, SHA512_CONST_56,
		SHA512_CONST_57, SHA512_CONST_58, SHA512_CONST_59,
		SHA512_CONST_60, SHA512_CONST_61, SHA512_CONST_62,
		SHA512_CONST_63, SHA512_CONST_64, SHA512_CONST_65,
		SHA512_CONST_66, SHA512_CONST_67, SHA512_CONST_68,
		SHA512_CONST_69, SHA512_CONST_70, SHA512_CONST_71,
		SHA512_CONST_72, SHA512_CONST_73, SHA512_CONST_74,
		SHA512_CONST_75, SHA512_CONST_76, SHA512_CONST_77,
		SHA512_CONST_78, SHA512_CONST_79
	};
#endif


	if ((uintptr_t)blk & 0x7) {		/* not 8-byte aligned? */
		bcopy(blk, ctx->buf_un.buf64,  sizeof (ctx->buf_un.buf64));
		blk = (uint8_t *)ctx->buf_un.buf64;
	}

	w0 =  LOAD_BIG_64(blk + 8 * 0);
	SHA512ROUND(a, b, c, d, e, f, g, h, 0, w0);
	w1 =  LOAD_BIG_64(blk + 8 * 1);
	SHA512ROUND(h, a, b, c, d, e, f, g, 1, w1);
	w2 =  LOAD_BIG_64(blk + 8 * 2);
	SHA512ROUND(g, h, a, b, c, d, e, f, 2, w2);
	w3 =  LOAD_BIG_64(blk + 8 * 3);
	SHA512ROUND(f, g, h, a, b, c, d, e, 3, w3);
	w4 =  LOAD_BIG_64(blk + 8 * 4);
	SHA512ROUND(e, f, g, h, a, b, c, d, 4, w4);
	w5 =  LOAD_BIG_64(blk + 8 * 5);
	SHA512ROUND(d, e, f, g, h, a, b, c, 5, w5);
	w6 =  LOAD_BIG_64(blk + 8 * 6);
	SHA512ROUND(c, d, e, f, g, h, a, b, 6, w6);
	w7 =  LOAD_BIG_64(blk + 8 * 7);
	SHA512ROUND(b, c, d, e, f, g, h, a, 7, w7);
	w8 =  LOAD_BIG_64(blk + 8 * 8);
	SHA512ROUND(a, b, c, d, e, f, g, h, 8, w8);
	w9 =  LOAD_BIG_64(blk + 8 * 9);
	SHA512ROUND(h, a, b, c, d, e, f, g, 9, w9);
	w10 =  LOAD_BIG_64(blk + 8 * 10);
	SHA512ROUND(g, h, a, b, c, d, e, f, 10, w10);
	w11 =  LOAD_BIG_64(blk + 8 * 11);
	SHA512ROUND(f, g, h, a, b, c, d, e, 11, w11);
	w12 =  LOAD_BIG_64(blk + 8 * 12);
	SHA512ROUND(e, f, g, h, a, b, c, d, 12, w12);
	w13 =  LOAD_BIG_64(blk + 8 * 13);
	SHA512ROUND(d, e, f, g, h, a, b, c, 13, w13);
	w14 =  LOAD_BIG_64(blk + 8 * 14);
	SHA512ROUND(c, d, e, f, g, h, a, b, 14, w14);
	w15 =  LOAD_BIG_64(blk + 8 * 15);
	SHA512ROUND(b, c, d, e, f, g, h, a, 15, w15);

	w0 = SIGMA1(w14) + w9 + SIGMA0(w1) + w0;
	SHA512ROUND(a, b, c, d, e, f, g, h, 16, w0);
	w1 = SIGMA1(w15) + w10 + SIGMA0(w2) + w1;
	SHA512ROUND(h, a, b, c, d, e, f, g, 17, w1);
	w2 = SIGMA1(w0) + w11 + SIGMA0(w3) + w2;
	SHA512ROUND(g, h, a, b, c, d, e, f, 18, w2);
	w3 = SIGMA1(w1) + w12 + SIGMA0(w4) + w3;
	SHA512ROUND(f, g, h, a, b, c, d, e, 19, w3);
	w4 = SIGMA1(w2) + w13 + SIGMA0(w5) + w4;
	SHA512ROUND(e, f, g, h, a, b, c, d, 20, w4);
	w5 = SIGMA1(w3) + w14 + SIGMA0(w6) + w5;
	SHA512ROUND(d, e, f, g, h, a, b, c, 21, w5);
	w6 = SIGMA1(w4) + w15 + SIGMA0(w7) + w6;
	SHA512ROUND(c, d, e, f, g, h, a, b, 22, w6);
	w7 = SIGMA1(w5) + w0 + SIGMA0(w8) + w7;
	SHA512ROUND(b, c, d, e, f, g, h, a, 23, w7);
	w8 = SIGMA1(w6) + w1 + SIGMA0(w9) + w8;
	SHA512ROUND(a, b, c, d, e, f, g, h, 24, w8);
	w9 = SIGMA1(w7) + w2 + SIGMA0(w10) + w9;
	SHA512ROUND(h, a, b, c, d, e, f, g, 25, w9);
	w10 = SIGMA1(w8) + w3 + SIGMA0(w11) + w10;
	SHA512ROUND(g, h, a, b, c, d, e, f, 26, w10);
	w11 = SIGMA1(w9) + w4 + SIGMA0(w12) + w11;
	SHA512ROUND(f, g, h, a, b, c, d, e, 27, w11);
	w12 = SIGMA1(w10) + w5 + SIGMA0(w13) + w12;
	SHA512ROUND(e, f, g, h, a, b, c, d, 28, w12);
	w13 = SIGMA1(w11) + w6 + SIGMA0(w14) + w13;
	SHA512ROUND(d, e, f, g, h, a, b, c, 29, w13);
	w14 = SIGMA1(w12) + w7 + SIGMA0(w15) + w14;
	SHA512ROUND(c, d, e, f, g, h, a, b, 30, w14);
	w15 = SIGMA1(w13) + w8 + SIGMA0(w0) + w15;
	SHA512ROUND(b, c, d, e, f, g, h, a, 31, w15);

	w0 = SIGMA1(w14) + w9 + SIGMA0(w1) + w0;
	SHA512ROUND(a, b, c, d, e, f, g, h, 32, w0);
	w1 = SIGMA1(w15) + w10 + SIGMA0(w2) + w1;
	SHA512ROUND(h, a, b, c, d, e, f, g, 33, w1);
	w2 = SIGMA1(w0) + w11 + SIGMA0(w3) + w2;
	SHA512ROUND(g, h, a, b, c, d, e, f, 34, w2);
	w3 = SIGMA1(w1) + w12 + SIGMA0(w4) + w3;
	SHA512ROUND(f, g, h, a, b, c, d, e, 35, w3);
	w4 = SIGMA1(w2) + w13 + SIGMA0(w5) + w4;
	SHA512ROUND(e, f, g, h, a, b, c, d, 36, w4);
	w5 = SIGMA1(w3) + w14 + SIGMA0(w6) + w5;
	SHA512ROUND(d, e, f, g, h, a, b, c, 37, w5);
	w6 = SIGMA1(w4) + w15 + SIGMA0(w7) + w6;
	SHA512ROUND(c, d, e, f, g, h, a, b, 38, w6);
	w7 = SIGMA1(w5) + w0 + SIGMA0(w8) + w7;
	SHA512ROUND(b, c, d, e, f, g, h, a, 39, w7);
	w8 = SIGMA1(w6) + w1 + SIGMA0(w9) + w8;
	SHA512ROUND(a, b, c, d, e, f, g, h, 40, w8);
	w9 = SIGMA1(w7) + w2 + SIGMA0(w10) + w9;
	SHA512ROUND(h, a, b, c, d, e, f, g, 41, w9);
	w10 = SIGMA1(w8) + w3 + SIGMA0(w11) + w10;
	SHA512ROUND(g, h, a, b, c, d, e, f, 42, w10);
	w11 = SIGMA1(w9) + w4 + SIGMA0(w12) + w11;
	SHA512ROUND(f, g, h, a, b, c, d, e, 43, w11);
	w12 = SIGMA1(w10) + w5 + SIGMA0(w13) + w12;
	SHA512ROUND(e, f, g, h, a, b, c, d, 44, w12);
	w13 = SIGMA1(w11) + w6 + SIGMA0(w14) + w13;
	SHA512ROUND(d, e, f, g, h, a, b, c, 45, w13);
	w14 = SIGMA1(w12) + w7 + SIGMA0(w15) + w14;
	SHA512ROUND(c, d, e, f, g, h, a, b, 46, w14);
	w15 = SIGMA1(w13) + w8 + SIGMA0(w0) + w15;
	SHA512ROUND(b, c, d, e, f, g, h, a, 47, w15);

	w0 = SIGMA1(w14) + w9 + SIGMA0(w1) + w0;
	SHA512ROUND(a, b, c, d, e, f, g, h, 48, w0);
	w1 = SIGMA1(w15) + w10 + SIGMA0(w2) + w1;
	SHA512ROUND(h, a, b, c, d, e, f, g, 49, w1);
	w2 = SIGMA1(w0) + w11 + SIGMA0(w3) + w2;
	SHA512ROUND(g, h, a, b, c, d, e, f, 50, w2);
	w3 = SIGMA1(w1) + w12 + SIGMA0(w4) + w3;
	SHA512ROUND(f, g, h, a, b, c, d, e, 51, w3);
	w4 = SIGMA1(w2) + w13 + SIGMA0(w5) + w4;
	SHA512ROUND(e, f, g, h, a, b, c, d, 52, w4);
	w5 = SIGMA1(w3) + w14 + SIGMA0(w6) + w5;
	SHA512ROUND(d, e, f, g, h, a, b, c, 53, w5);
	w6 = SIGMA1(w4) + w15 + SIGMA0(w7) + w6;
	SHA512ROUND(c, d, e, f, g, h, a, b, 54, w6);
	w7 = SIGMA1(w5) + w0 + SIGMA0(w8) + w7;
	SHA512ROUND(b, c, d, e, f, g, h, a, 55, w7);
	w8 = SIGMA1(w6) + w1 + SIGMA0(w9) + w8;
	SHA512ROUND(a, b, c, d, e, f, g, h, 56, w8);
	w9 = SIGMA1(w7) + w2 + SIGMA0(w10) + w9;
	SHA512ROUND(h, a, b, c, d, e, f, g, 57, w9);
	w10 = SIGMA1(w8) + w3 + SIGMA0(w11) + w10;
	SHA512ROUND(g, h, a, b, c, d, e, f, 58, w10);
	w11 = SIGMA1(w9) + w4 + SIGMA0(w12) + w11;
	SHA512ROUND(f, g, h, a, b, c, d, e, 59, w11);
	w12 = SIGMA1(w10) + w5 + SIGMA0(w13) + w12;
	SHA512ROUND(e, f, g, h, a, b, c, d, 60, w12);
	w13 = SIGMA1(w11) + w6 + SIGMA0(w14) + w13;
	SHA512ROUND(d, e, f, g, h, a, b, c, 61, w13);
	w14 = SIGMA1(w12) + w7 + SIGMA0(w15) + w14;
	SHA512ROUND(c, d, e, f, g, h, a, b, 62, w14);
	w15 = SIGMA1(w13) + w8 + SIGMA0(w0) + w15;
	SHA512ROUND(b, c, d, e, f, g, h, a, 63, w15);

	w0 = SIGMA1(w14) + w9 + SIGMA0(w1) + w0;
	SHA512ROUND(a, b, c, d, e, f, g, h, 64, w0);
	w1 = SIGMA1(w15) + w10 + SIGMA0(w2) + w1;
	SHA512ROUND(h, a, b, c, d, e, f, g, 65, w1);
	w2 = SIGMA1(w0) + w11 + SIGMA0(w3) + w2;
	SHA512ROUND(g, h, a, b, c, d, e, f, 66, w2);
	w3 = SIGMA1(w1) + w12 + SIGMA0(w4) + w3;
	SHA512ROUND(f, g, h, a, b, c, d, e, 67, w3);
	w4 = SIGMA1(w2) + w13 + SIGMA0(w5) + w4;
	SHA512ROUND(e, f, g, h, a, b, c, d, 68, w4);
	w5 = SIGMA1(w3) + w14 + SIGMA0(w6) + w5;
	SHA512ROUND(d, e, f, g, h, a, b, c, 69, w5);
	w6 = SIGMA1(w4) + w15 + SIGMA0(w7) + w6;
	SHA512ROUND(c, d, e, f, g, h, a, b, 70, w6);
	w7 = SIGMA1(w5) + w0 + SIGMA0(w8) + w7;
	SHA512ROUND(b, c, d, e, f, g, h, a, 71, w7);
	w8 = SIGMA1(w6) + w1 + SIGMA0(w9) + w8;
	SHA512ROUND(a, b, c, d, e, f, g, h, 72, w8);
	w9 = SIGMA1(w7) + w2 + SIGMA0(w10) + w9;
	SHA512ROUND(h, a, b, c, d, e, f, g, 73, w9);
	w10 = SIGMA1(w8) + w3 + SIGMA0(w11) + w10;
	SHA512ROUND(g, h, a, b, c, d, e, f, 74, w10);
	w11 = SIGMA1(w9) + w4 + SIGMA0(w12) + w11;
	SHA512ROUND(f, g, h, a, b, c, d, e, 75, w11);
	w12 = SIGMA1(w10) + w5 + SIGMA0(w13) + w12;
	SHA512ROUND(e, f, g, h, a, b, c, d, 76, w12);
	w13 = SIGMA1(w11) + w6 + SIGMA0(w14) + w13;
	SHA512ROUND(d, e, f, g, h, a, b, c, 77, w13);
	w14 = SIGMA1(w12) + w7 + SIGMA0(w15) + w14;
	SHA512ROUND(c, d, e, f, g, h, a, b, 78, w14);
	w15 = SIGMA1(w13) + w8 + SIGMA0(w0) + w15;
	SHA512ROUND(b, c, d, e, f, g, h, a, 79, w15);

	ctx->state.s64[0] += a;
	ctx->state.s64[1] += b;
	ctx->state.s64[2] += c;
	ctx->state.s64[3] += d;
	ctx->state.s64[4] += e;
	ctx->state.s64[5] += f;
	ctx->state.s64[6] += g;
	ctx->state.s64[7] += h;

}


/*
 * devpro compiler optimization:
 *
 * the compiler can generate better code if it knows that `input' and
 * `output' do not point to the same source.  there is no portable
 * way to tell the compiler this, but the sun compiler recognizes the
 * `_Restrict' keyword to indicate this condition.  use it if possible.
 */

#ifdef	__RESTRICT
#define	restrict	_Restrict
#else
#define	restrict	/* nothing */
#endif

/*
 * Encode()
 *
 * purpose: to convert a list of numbers from little endian to big endian
 *   input: uint8_t *	: place to store the converted big endian numbers
 *	    uint32_t *	: place to get numbers to convert from
 *          size_t	: the length of the input in bytes
 *  output: void
 */

static void
Encode(uint8_t *restrict output, uint32_t *restrict input, size_t len)
{
	size_t		i, j;

#if	defined(__sparc)
	if (IS_P2ALIGNED(output, sizeof (uint32_t))) {
		for (i = 0, j = 0; j < len; i++, j += 4) {
			/* LINTED: pointer alignment */
			*((uint32_t *)(output + j)) = input[i];
		}
	} else {
#endif	/* little endian -- will work on big endian, but slowly */
		for (i = 0, j = 0; j < len; i++, j += 4) {
			output[j]	= (input[i] >> 24) & 0xff;
			output[j + 1]	= (input[i] >> 16) & 0xff;
			output[j + 2]	= (input[i] >>  8) & 0xff;
			output[j + 3]	= input[i] & 0xff;
		}
#if	defined(__sparc)
	}
#endif
}

static void
Encode64(uint8_t *restrict output, uint64_t *restrict input, size_t len)
{
	size_t		i, j;

#if	defined(__sparc)
	if (IS_P2ALIGNED(output, sizeof (uint64_t))) {
		for (i = 0, j = 0; j < len; i++, j += 8) {
			/* LINTED: pointer alignment */
			*((uint64_t *)(output + j)) = input[i];
		}
	} else {
#endif	/* little endian -- will work on big endian, but slowly */
		for (i = 0, j = 0; j < len; i++, j += 8) {

			output[j]	= (input[i] >> 56) & 0xff;
			output[j + 1]	= (input[i] >> 48) & 0xff;
			output[j + 2]	= (input[i] >> 40) & 0xff;
			output[j + 3]	= (input[i] >> 32) & 0xff;
			output[j + 4]	= (input[i] >> 24) & 0xff;
			output[j + 5]	= (input[i] >> 16) & 0xff;
			output[j + 6]	= (input[i] >>  8) & 0xff;
			output[j + 7]	= input[i] & 0xff;
		}
#if	defined(__sparc)
	}
#endif
}


#ifdef _KERNEL

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
sha2_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF software provider digest entry points.
 */

static int
sha2_digest_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_req_handle_t req)
{

	/*
	 * Allocate and initialize SHA2 context.
	 */
	ctx->cc_provider_private = kmem_alloc(sizeof (sha2_ctx_t),
	    crypto_kmflag(req));
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_HOST_MEMORY);

	PROV_SHA2_CTX(ctx)->sc_mech_type = mechanism->cm_type;
	SHA2Init(mechanism->cm_type, &PROV_SHA2_CTX(ctx)->sc_sha2_ctx);

	return (CRYPTO_SUCCESS);
}

/*
 * Helper SHA2 digest update function for uio data.
 */
static int
sha2_digest_update_uio(SHA2_CTX *sha2_ctx, crypto_data_t *data)
{
	off_t offset = data->cd_offset;
	size_t length = data->cd_length;
	uint_t vec_idx;
	size_t cur_len;

	/* we support only kernel buffer */
	if (data->cd_uio->uio_segflg != UIO_SYSSPACE)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Jump to the first iovec containing data to be
	 * digested.
	 */
	for (vec_idx = 0; vec_idx < data->cd_uio->uio_iovcnt &&
	    offset >= data->cd_uio->uio_iov[vec_idx].iov_len;
	    offset -= data->cd_uio->uio_iov[vec_idx++].iov_len);
	if (vec_idx == data->cd_uio->uio_iovcnt) {
		/*
		 * The caller specified an offset that is larger than the
		 * total size of the buffers it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	/*
	 * Now do the digesting on the iovecs.
	 */
	while (vec_idx < data->cd_uio->uio_iovcnt && length > 0) {
		cur_len = MIN(data->cd_uio->uio_iov[vec_idx].iov_len -
		    offset, length);

		SHA2Update(sha2_ctx, (uint8_t *)data->cd_uio->
		    uio_iov[vec_idx].iov_base + offset, cur_len);
		length -= cur_len;
		vec_idx++;
		offset = 0;
	}

	if (vec_idx == data->cd_uio->uio_iovcnt && length > 0) {
		/*
		 * The end of the specified iovec's was reached but
		 * the length requested could not be processed, i.e.
		 * The caller requested to digest more data than it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Helper SHA2 digest final function for uio data.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default SHA2 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least the algorithm's digest length bytes.
 */
static int
sha2_digest_final_uio(SHA2_CTX *sha2_ctx, crypto_data_t *digest,
    ulong_t digest_len, uchar_t *digest_scratch)
{
	off_t offset = digest->cd_offset;
	uint_t vec_idx;

	/* we support only kernel buffer */
	if (digest->cd_uio->uio_segflg != UIO_SYSSPACE)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Jump to the first iovec containing ptr to the digest to
	 * be returned.
	 */
	for (vec_idx = 0; offset >= digest->cd_uio->uio_iov[vec_idx].iov_len &&
	    vec_idx < digest->cd_uio->uio_iovcnt;
	    offset -= digest->cd_uio->uio_iov[vec_idx++].iov_len);
	if (vec_idx == digest->cd_uio->uio_iovcnt) {
		/*
		 * The caller specified an offset that is
		 * larger than the total size of the buffers
		 * it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	if (offset + digest_len <=
	    digest->cd_uio->uio_iov[vec_idx].iov_len) {
		/*
		 * The computed SHA2 digest will fit in the current
		 * iovec.
		 */
		if (((sha2_ctx->algotype <= SHA256_HMAC_GEN_MECH_INFO_TYPE) &&
		    (digest_len != SHA256_DIGEST_LENGTH)) ||
		    ((sha2_ctx->algotype > SHA256_HMAC_GEN_MECH_INFO_TYPE) &&
			(digest_len != SHA512_DIGEST_LENGTH))) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA2Final(digest_scratch, sha2_ctx);

			bcopy(digest_scratch, (uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    digest_len);
		} else {
			SHA2Final((uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    sha2_ctx);

		}
	} else {
		/*
		 * The computed digest will be crossing one or more iovec's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[SHA512_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		SHA2Final(digest_tmp, sha2_ctx);

		while (vec_idx < digest->cd_uio->uio_iovcnt && length > 0) {
			cur_len =
			    MIN(digest->cd_uio->uio_iov[vec_idx].iov_len -
				    offset, length);
			bcopy(digest_tmp + scratch_offset,
			    digest->cd_uio->uio_iov[vec_idx].iov_base + offset,
			    cur_len);

			length -= cur_len;
			vec_idx++;
			scratch_offset += cur_len;
			offset = 0;
		}

		if (vec_idx == digest->cd_uio->uio_iovcnt && length > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed, i.e.
			 * The caller requested to digest more data than it
			 * provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Helper SHA2 digest update for mblk's.
 */
static int
sha2_digest_update_mblk(SHA2_CTX *sha2_ctx, crypto_data_t *data)
{
	off_t offset = data->cd_offset;
	size_t length = data->cd_length;
	mblk_t *mp;
	size_t cur_len;

	/*
	 * Jump to the first mblk_t containing data to be digested.
	 */
	for (mp = data->cd_mp; mp != NULL && offset >= MBLKL(mp);
	    offset -= MBLKL(mp), mp = mp->b_cont);
	if (mp == NULL) {
		/*
		 * The caller specified an offset that is larger than the
		 * total size of the buffers it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	/*
	 * Now do the digesting on the mblk chain.
	 */
	while (mp != NULL && length > 0) {
		cur_len = MIN(MBLKL(mp) - offset, length);
		SHA2Update(sha2_ctx, mp->b_rptr + offset, cur_len);
		length -= cur_len;
		offset = 0;
		mp = mp->b_cont;
	}

	if (mp == NULL && length > 0) {
		/*
		 * The end of the mblk was reached but the length requested
		 * could not be processed, i.e. The caller requested
		 * to digest more data than it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Helper SHA2 digest final for mblk's.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default SHA2 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least the algorithm's digest length bytes.
 */
static int
sha2_digest_final_mblk(SHA2_CTX *sha2_ctx, crypto_data_t *digest,
    ulong_t digest_len, uchar_t *digest_scratch)
{
	off_t offset = digest->cd_offset;
	mblk_t *mp;

	/*
	 * Jump to the first mblk_t that will be used to store the digest.
	 */
	for (mp = digest->cd_mp; mp != NULL && offset >= MBLKL(mp);
	    offset -= MBLKL(mp), mp = mp->b_cont);
	if (mp == NULL) {
		/*
		 * The caller specified an offset that is larger than the
		 * total size of the buffers it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	if (offset + digest_len <= MBLKL(mp)) {
		/*
		 * The computed SHA2 digest will fit in the current mblk.
		 * Do the SHA2Final() in-place.
		 */
		if (((sha2_ctx->algotype <= SHA256_HMAC_GEN_MECH_INFO_TYPE) &&
		    (digest_len != SHA256_DIGEST_LENGTH)) ||
		    ((sha2_ctx->algotype > SHA256_HMAC_GEN_MECH_INFO_TYPE) &&
			(digest_len != SHA512_DIGEST_LENGTH))) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA2Final(digest_scratch, sha2_ctx);
			bcopy(digest_scratch, mp->b_rptr + offset, digest_len);
		} else {
			SHA2Final(mp->b_rptr + offset, sha2_ctx);
		}
	} else {
		/*
		 * The computed digest will be crossing one or more mblk's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[SHA512_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		SHA2Final(digest_tmp, sha2_ctx);

		while (mp != NULL && length > 0) {
			cur_len = MIN(MBLKL(mp) - offset, length);
			bcopy(digest_tmp + scratch_offset,
			    mp->b_rptr + offset, cur_len);

			length -= cur_len;
			mp = mp->b_cont;
			scratch_offset += cur_len;
			offset = 0;
		}

		if (mp == NULL && length > 0) {
			/*
			 * The end of the specified mblk was reached but
			 * the length requested could not be processed, i.e.
			 * The caller requested to digest more data than it
			 * provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
	}

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
sha2_digest(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uint_t sha_digest_len;

	ASSERT(ctx->cc_provider_private != NULL);

	switch (PROV_SHA2_CTX(ctx)->sc_mech_type) {
	case SHA256_MECH_INFO_TYPE:
		sha_digest_len = SHA256_DIGEST_LENGTH;
		break;
	case SHA384_MECH_INFO_TYPE:
		sha_digest_len = SHA384_DIGEST_LENGTH;
		break;
	case SHA512_MECH_INFO_TYPE:
		sha_digest_len = SHA512_DIGEST_LENGTH;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < sha_digest_len)) {
		digest->cd_length = sha_digest_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do the SHA2 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Update(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_update_uio(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_update_mblk(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret != CRYPTO_SUCCESS) {
		/* the update failed, free context and bail */
		bzero(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx, sizeof (SHA2_CTX));
		kmem_free(ctx->cc_provider_private, sizeof (sha2_ctx_t));
		ctx->cc_provider_private = NULL;
		digest->cd_length = 0;
		return (ret);
	}

	/*
	 * Do a SHA2 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_SHA2_CTX(ctx)->sc_sha2_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_final_uio(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    digest, sha_digest_len, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_final_mblk(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    digest, sha_digest_len, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = sha_digest_len;
	} else {
		/*
		 * Only bzero context on failure, since SHA2Final()
		 * does it for us.
		 */
		bzero(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx, sizeof (SHA2_CTX));
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (sha2_ctx_t));
	ctx->cc_provider_private = NULL;
	return (ret);
}

/* ARGSUSED */
static int
sha2_digest_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * Do the SHA2 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Update(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_update_uio(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_update_mblk(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/* ARGSUSED */
static int
sha2_digest_final(crypto_ctx_t *ctx, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uint_t sha_digest_len;

	ASSERT(ctx->cc_provider_private != NULL);

	switch (PROV_SHA2_CTX(ctx)->sc_mech_type) {
	case SHA256_MECH_INFO_TYPE:
		sha_digest_len = SHA256_DIGEST_LENGTH;
		break;
	case SHA384_MECH_INFO_TYPE:
		sha_digest_len = SHA384_DIGEST_LENGTH;
		break;
	case SHA512_MECH_INFO_TYPE:
		sha_digest_len = SHA512_DIGEST_LENGTH;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < sha_digest_len)) {
		digest->cd_length = sha_digest_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do a SHA2 final.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_SHA2_CTX(ctx)->sc_sha2_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_final_uio(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    digest, sha_digest_len, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_final_mblk(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx,
		    digest, sha_digest_len, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = sha_digest_len;
	} else {
		/*
		 * Only bzero context this on failure, since SHA2Final()
		 * does it for us.
		 */
		bzero(&PROV_SHA2_CTX(ctx)->sc_sha2_ctx, sizeof (SHA2_CTX));
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (sha2_ctx_t));
	ctx->cc_provider_private = NULL;

	return (ret);
}

/* ARGSUSED */
static int
sha2_digest_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	SHA2_CTX sha2_ctx;
	uint32_t sha_digest_len;

	/*
	 * Do the SHA inits.
	 */

	SHA2Init(mechanism->cm_type, &sha2_ctx);

	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Update(&sha2_ctx, (uint8_t *)data->
		    cd_raw.iov_base + data->cd_offset, data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_update_uio(&sha2_ctx, data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_update_mblk(&sha2_ctx, data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/*
	 * Do the SHA updates on the specified input data.
	 */

	if (ret != CRYPTO_SUCCESS) {
		/* the update failed, bail */
		bzero(&sha2_ctx, sizeof (SHA2_CTX));
		digest->cd_length = 0;
		return (ret);

	}

	if (mechanism->cm_type <= SHA256_HMAC_GEN_MECH_INFO_TYPE)
		sha_digest_len = SHA256_DIGEST_LENGTH;
	else
		sha_digest_len = SHA512_DIGEST_LENGTH;

	/*
	 * Do a SHA2 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &sha2_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_final_uio(&sha2_ctx, digest,
		    sha_digest_len, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_final_mblk(&sha2_ctx, digest,
		    sha_digest_len, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = sha_digest_len;
	} else {
		/*
		 * Only bzero context on failure, since SHA2Final()
		 * does it for us.
		 */
		bzero(&sha2_ctx, sizeof (SHA2_CTX));
		digest->cd_length = 0;
	}

	return (ret);
}

/*
 * KCF software provider mac entry points.
 *
 * SHA2 HMAC is: SHA2(key XOR opad, SHA2(key XOR ipad, text))
 *
 * Init:
 * The initialization routine initializes what we denote
 * as the inner and outer contexts by doing
 * - for inner context: SHA2(key XOR ipad)
 * - for outer context: SHA2(key XOR opad)
 *
 * Update:
 * Each subsequent SHA2 HMAC update will result in an
 * update of the inner context with the specified data.
 *
 * Final:
 * The SHA2 HMAC final will do a SHA2 final operation on the
 * inner context, and the resulting digest will be used
 * as the data for an update on the outer context. Last
 * but not least, a SHA2 final on the outer context will
 * be performed to obtain the SHA2 HMAC digest to return
 * to the user.
 */

/*
 * Initialize a SHA2-HMAC context.
 */
static void
sha2_mac_init_ctx(sha2_hmac_ctx_t *ctx, void *keyval, uint_t length_in_bytes)
{
	uint64_t ipad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)];
	uint64_t opad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)];
	int i, block_size, blocks_per_int64;

	/* Determine the block size */
	if (ctx->hc_mech_type <= SHA256_HMAC_GEN_MECH_INFO_TYPE) {
		block_size = SHA256_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA256_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	} else {
		block_size = SHA512_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	}

	(void) bzero(ipad, block_size);
	(void) bzero(opad, block_size);
	(void) bcopy(keyval, ipad, length_in_bytes);
	(void) bcopy(keyval, opad, length_in_bytes);

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < blocks_per_int64; i ++) {
		ipad[i] ^= 0x3636363636363636;
		opad[i] ^= 0x5c5c5c5c5c5c5c5c;
	}

	/* perform SHA2 on ipad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_icontext);
	SHA2Update(&ctx->hc_icontext, (uint8_t *)ipad, block_size);

	/* perform SHA2 on opad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_ocontext);
	SHA2Update(&ctx->hc_ocontext, (uint8_t *)opad, block_size);

}

/*
 */
static int
sha2_mac_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);
	uint_t sha_digest_len, sha_hmac_block_size;

	/*
	 * Set the digest length and block size to values approriate to the
	 * mechanism
	 */
	switch (mechanism->cm_type) {
	case SHA256_HMAC_MECH_INFO_TYPE:
	case SHA256_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = SHA256_DIGEST_LENGTH;
		sha_hmac_block_size = SHA256_HMAC_BLOCK_SIZE;
		break;
	case SHA384_HMAC_MECH_INFO_TYPE:
	case SHA384_HMAC_GEN_MECH_INFO_TYPE:
	case SHA512_HMAC_MECH_INFO_TYPE:
	case SHA512_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = SHA512_DIGEST_LENGTH;
		sha_hmac_block_size = SHA512_HMAC_BLOCK_SIZE;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	ctx->cc_provider_private = kmem_alloc(sizeof (sha2_hmac_ctx_t),
	    crypto_kmflag(req));
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_HOST_MEMORY);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, PROV_SHA2_HMAC_CTX(ctx),
		    sizeof (sha2_hmac_ctx_t));
	} else {
		/* no context template, compute context */
		if (keylen_in_bytes > sha_hmac_block_size) {
			uchar_t digested_key[SHA512_DIGEST_LENGTH];
			sha2_hmac_ctx_t *hmac_ctx = ctx->cc_provider_private;

			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_SHA2_DIGEST_KEY(mechanism->cm_type / 3,
			    &hmac_ctx->hc_icontext,
			    key->ck_data, keylen_in_bytes, digested_key);
			sha2_mac_init_ctx(PROV_SHA2_HMAC_CTX(ctx),
			    digested_key, sha_digest_len);
		} else {
			sha2_mac_init_ctx(PROV_SHA2_HMAC_CTX(ctx),
			    key->ck_data, keylen_in_bytes);
		}
	}

	/*
	 * Get the mechanism parameters, if applicable.
	 */
	PROV_SHA2_HMAC_CTX(ctx)->hc_mech_type = mechanism->cm_type;
	if (mechanism->cm_type % 3 == 2) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t))
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
		PROV_SHA2_GET_DIGEST_LEN(mechanism,
		    PROV_SHA2_HMAC_CTX(ctx)->hc_digest_len);
		if (PROV_SHA2_HMAC_CTX(ctx)->hc_digest_len > sha_digest_len)
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
	}

	if (ret != CRYPTO_SUCCESS) {
		bzero(ctx->cc_provider_private, sizeof (sha2_hmac_ctx_t));
		kmem_free(ctx->cc_provider_private, sizeof (sha2_hmac_ctx_t));
		ctx->cc_provider_private = NULL;
	}

	return (ret);
}

/* ARGSUSED */
static int
sha2_mac_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * Do a SHA2 update of the inner context using the specified
	 * data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA2Update(&PROV_SHA2_HMAC_CTX(ctx)->hc_icontext,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_update_uio(
		    &PROV_SHA2_HMAC_CTX(ctx)->hc_icontext, data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_update_mblk(
		    &PROV_SHA2_HMAC_CTX(ctx)->hc_icontext, data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/* ARGSUSED */
static int
sha2_mac_final(crypto_ctx_t *ctx, crypto_data_t *mac, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[SHA512_DIGEST_LENGTH];
	uint32_t digest_len, sha_digest_len;

	ASSERT(ctx->cc_provider_private != NULL);

	/* Set the digest lengths to values approriate to the mechanism */
	switch (PROV_SHA2_HMAC_CTX(ctx)->hc_mech_type) {
	case SHA256_HMAC_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA256_DIGEST_LENGTH;
		break;
	case SHA384_HMAC_MECH_INFO_TYPE:
	case SHA512_HMAC_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA512_DIGEST_LENGTH;
		break;
	case SHA256_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = SHA256_DIGEST_LENGTH;
		digest_len = PROV_SHA2_HMAC_CTX(ctx)->hc_digest_len;
		break;
	case SHA384_HMAC_GEN_MECH_INFO_TYPE:
	case SHA512_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = SHA512_DIGEST_LENGTH;
		digest_len = PROV_SHA2_HMAC_CTX(ctx)->hc_digest_len;
		break;
	}

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((mac->cd_length == 0) || (mac->cd_length < digest_len)) {
		mac->cd_length = digest_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do a SHA2 final on the inner context.
	 */
	SHA2Final(digest, &PROV_SHA2_HMAC_CTX(ctx)->hc_icontext);

	/*
	 * Do a SHA2 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA2Update(&PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext, digest,
	    sha_digest_len);

	/*
	 * Do a SHA2 final on the outer context, storing the computing
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != sha_digest_len) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA2Final(digest,
			    &PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			SHA2Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset,
			    &PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_final_uio(
		    &PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext, mac,
		    digest_len, digest);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_final_mblk(
		    &PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext, mac,
		    digest_len, digest);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		mac->cd_length = digest_len;
	} else {
		/*
		 * Only bzero outer context on failure, since SHA2Final()
		 * does it for us.
		 * We don't have to bzero the inner context since we
		 * always invoke a SHA2Final() on it.
		 */
		bzero(&PROV_SHA2_HMAC_CTX(ctx)->hc_ocontext,
		    sizeof (SHA2_CTX));
		mac->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (sha2_hmac_ctx_t));
	ctx->cc_provider_private = NULL;

	return (ret);
}

#define	SHA2_MAC_UPDATE(data, ctx, ret) {				\
	switch (data->cd_format) {					\
	case CRYPTO_DATA_RAW:						\
		SHA2Update(&(ctx).hc_icontext,				\
		    (uint8_t *)data->cd_raw.iov_base +			\
		    data->cd_offset, data->cd_length);			\
		break;							\
	case CRYPTO_DATA_UIO:						\
		ret = sha2_digest_update_uio(&(ctx).hc_icontext, data);	\
		break;							\
	case CRYPTO_DATA_MBLK:						\
		ret = sha2_digest_update_mblk(&(ctx).hc_icontext,	\
		    data);						\
		break;							\
	default:							\
		ret = CRYPTO_ARGUMENTS_BAD;				\
	}								\
}

/* ARGSUSED */
static int
sha2_mac_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[SHA512_DIGEST_LENGTH];
	sha2_hmac_ctx_t sha2_hmac_ctx;
	uint32_t sha_digest_len, digest_len, sha_hmac_block_size;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	/*
	 * Set the digest length and block size to values approriate to the
	 * mechanism
	 */
	switch (mechanism->cm_type) {
	case SHA256_HMAC_MECH_INFO_TYPE:
	case SHA256_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA256_DIGEST_LENGTH;
		sha_hmac_block_size = SHA256_HMAC_BLOCK_SIZE;
		break;
	case SHA384_HMAC_MECH_INFO_TYPE:
	case SHA384_HMAC_GEN_MECH_INFO_TYPE:
	case SHA512_HMAC_MECH_INFO_TYPE:
	case SHA512_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA512_DIGEST_LENGTH;
		sha_hmac_block_size = SHA512_HMAC_BLOCK_SIZE;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, &sha2_hmac_ctx, sizeof (sha2_hmac_ctx_t));
	} else {
		sha2_hmac_ctx.hc_mech_type = mechanism->cm_type;
		/* no context template, initialize context */
		if (keylen_in_bytes > sha_hmac_block_size) {
			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_SHA2_DIGEST_KEY(mechanism->cm_type / 3,
			    &sha2_hmac_ctx.hc_icontext,
			    key->ck_data, keylen_in_bytes, digest);
			sha2_mac_init_ctx(&sha2_hmac_ctx, digest,
			    sha_digest_len);
		} else {
			sha2_mac_init_ctx(&sha2_hmac_ctx, key->ck_data,
			    keylen_in_bytes);
		}
	}

	/* get the mechanism parameters, if applicable */
	if ((mechanism->cm_type % 3) == 2) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t)) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
		PROV_SHA2_GET_DIGEST_LEN(mechanism, digest_len);
		if (digest_len > sha_digest_len) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
	}

	/* do a SHA2 update of the inner context using the specified data */
	SHA2_MAC_UPDATE(data, sha2_hmac_ctx, ret);
	if (ret != CRYPTO_SUCCESS)
		/* the update failed, free context and bail */
		goto bail;

	/*
	 * Do a SHA2 final on the inner context.
	 */
	SHA2Final(digest, &sha2_hmac_ctx.hc_icontext);

	/*
	 * Do an SHA2 update on the outer context, feeding the inner
	 * digest as data.
	 *
	 * Make sure that SHA384 is handled special because
	 * it cannot feed a 60-byte inner hash to the outer
	 */
	if (mechanism->cm_type == SHA384_HMAC_MECH_INFO_TYPE ||
	    mechanism->cm_type == SHA384_HMAC_GEN_MECH_INFO_TYPE)
		SHA2Update(&sha2_hmac_ctx.hc_ocontext, digest,
		    SHA384_DIGEST_LENGTH);
	else
		SHA2Update(&sha2_hmac_ctx.hc_ocontext, digest, sha_digest_len);

	/*
	 * Do a SHA2 final on the outer context, storing the computed
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != sha_digest_len) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA2Final(digest, &sha2_hmac_ctx.hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			SHA2Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, &sha2_hmac_ctx.hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = sha2_digest_final_uio(&sha2_hmac_ctx.hc_ocontext, mac,
		    digest_len, digest);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha2_digest_final_mblk(&sha2_hmac_ctx.hc_ocontext, mac,
		    digest_len, digest);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		mac->cd_length = digest_len;
	} else {
		/*
		 * Only bzero outer context on failure, since SHA2Final()
		 * does it for us.
		 * We don't have to bzero the inner context since we
		 * always invoke a SHA2Final() on it.
		 */
		bzero(&sha2_hmac_ctx.hc_ocontext, sizeof (SHA2_CTX));
		mac->cd_length = 0;
	}

	return (ret);
bail:
	bzero(&sha2_hmac_ctx, sizeof (sha2_hmac_ctx_t));
	mac->cd_length = 0;
	return (ret);
}

/* ARGSUSED */
static int
sha2_mac_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[SHA512_DIGEST_LENGTH];
	sha2_hmac_ctx_t sha2_hmac_ctx;
	uint32_t sha_digest_len, digest_len, sha_hmac_block_size;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	/*
	 * Set the digest length and block size to values approriate to the
	 * mechanism
	 */
	switch (mechanism->cm_type) {
	case SHA256_HMAC_MECH_INFO_TYPE:
	case SHA256_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA256_DIGEST_LENGTH;
		sha_hmac_block_size = SHA256_HMAC_BLOCK_SIZE;
		break;
	case SHA384_HMAC_MECH_INFO_TYPE:
	case SHA384_HMAC_GEN_MECH_INFO_TYPE:
	case SHA512_HMAC_MECH_INFO_TYPE:
	case SHA512_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = digest_len = SHA512_DIGEST_LENGTH;
		sha_hmac_block_size = SHA512_HMAC_BLOCK_SIZE;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, &sha2_hmac_ctx, sizeof (sha2_hmac_ctx_t));
	} else {
		/* no context template, initialize context */
		if (keylen_in_bytes > sha_hmac_block_size) {
			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_SHA2_DIGEST_KEY(mechanism->cm_type / 3,
			    &sha2_hmac_ctx.hc_icontext,
			    key->ck_data, keylen_in_bytes, digest);
			sha2_mac_init_ctx(&sha2_hmac_ctx, digest,
			    sha_digest_len);
		} else {
			sha2_mac_init_ctx(&sha2_hmac_ctx, key->ck_data,
			    keylen_in_bytes);
		}
	}

	/* get the mechanism parameters, if applicable */
	if (mechanism->cm_type % 3 == 2) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t)) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
		PROV_SHA2_GET_DIGEST_LEN(mechanism, digest_len);
		if (digest_len > sha_digest_len) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
	}

	if (mac->cd_length != digest_len) {
		ret = CRYPTO_INVALID_MAC;
		goto bail;
	}

	/* do a SHA2 update of the inner context using the specified data */
	SHA2_MAC_UPDATE(data, sha2_hmac_ctx, ret);
	if (ret != CRYPTO_SUCCESS)
		/* the update failed, free context and bail */
		goto bail;

	/* do a SHA2 final on the inner context */
	SHA2Final(digest, &sha2_hmac_ctx.hc_icontext);

	/*
	 * Do an SHA2 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA2Update(&sha2_hmac_ctx.hc_ocontext, digest, sha_digest_len);

	/*
	 * Do a SHA2 final on the outer context, storing the computed
	 * digest in the users buffer.
	 */
	SHA2Final(digest, &sha2_hmac_ctx.hc_ocontext);

	/*
	 * Compare the computed digest against the expected digest passed
	 * as argument.
	 */

	switch (mac->cd_format) {

	case CRYPTO_DATA_RAW:
		if (bcmp(digest, (unsigned char *)mac->cd_raw.iov_base +
		    mac->cd_offset, digest_len) != 0)
			ret = CRYPTO_INVALID_MAC;
		break;

	case CRYPTO_DATA_UIO: {
		off_t offset = mac->cd_offset;
		uint_t vec_idx;
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		/* we support only kernel buffer */
		if (mac->cd_uio->uio_segflg != UIO_SYSSPACE)
			return (CRYPTO_ARGUMENTS_BAD);

		/* jump to the first iovec containing the expected digest */
		for (vec_idx = 0;
		    offset >= mac->cd_uio->uio_iov[vec_idx].iov_len &&
		    vec_idx < mac->cd_uio->uio_iovcnt;
		    offset -= mac->cd_uio->uio_iov[vec_idx++].iov_len);
		if (vec_idx == mac->cd_uio->uio_iovcnt) {
			/*
			 * The caller specified an offset that is
			 * larger than the total size of the buffers
			 * it provided.
			 */
			ret = CRYPTO_DATA_LEN_RANGE;
			break;
		}

		/* do the comparison of computed digest vs specified one */
		while (vec_idx < mac->cd_uio->uio_iovcnt && length > 0) {
			cur_len = MIN(mac->cd_uio->uio_iov[vec_idx].iov_len -
			    offset, length);

			if (bcmp(digest + scratch_offset,
			    mac->cd_uio->uio_iov[vec_idx].iov_base + offset,
			    cur_len) != 0) {
				ret = CRYPTO_INVALID_MAC;
				break;
			}

			length -= cur_len;
			vec_idx++;
			scratch_offset += cur_len;
			offset = 0;
		}
		break;
	}

	case CRYPTO_DATA_MBLK: {
		off_t offset = mac->cd_offset;
		mblk_t *mp;
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		/* jump to the first mblk_t containing the expected digest */
		for (mp = mac->cd_mp; mp != NULL && offset >= MBLKL(mp);
		    offset -= MBLKL(mp), mp = mp->b_cont);
		if (mp == NULL) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			ret = CRYPTO_DATA_LEN_RANGE;
			break;
		}

		while (mp != NULL && length > 0) {
			cur_len = MIN(MBLKL(mp) - offset, length);
			if (bcmp(digest + scratch_offset,
			    mp->b_rptr + offset, cur_len) != 0) {
				ret = CRYPTO_INVALID_MAC;
				break;
			}

			length -= cur_len;
			mp = mp->b_cont;
			scratch_offset += cur_len;
			offset = 0;
		}
		break;
	}

	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
bail:
	bzero(&sha2_hmac_ctx, sizeof (sha2_hmac_ctx_t));
	mac->cd_length = 0;
	return (ret);
}

/*
 * KCF software provider context management entry points.
 */

/* ARGSUSED */
static int
sha2_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *ctx_template, size_t *ctx_template_size,
    crypto_req_handle_t req)
{
	sha2_hmac_ctx_t *sha2_hmac_ctx_tmpl;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);
	uint32_t sha_digest_len, sha_hmac_block_size;

	/*
	 * Set the digest length and block size to values approriate to the
	 * mechanism
	 */
	switch (mechanism->cm_type) {
	case SHA256_HMAC_MECH_INFO_TYPE:
	case SHA256_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = SHA256_DIGEST_LENGTH;
		sha_hmac_block_size = SHA256_HMAC_BLOCK_SIZE;
		break;
	case SHA384_HMAC_MECH_INFO_TYPE:
	case SHA384_HMAC_GEN_MECH_INFO_TYPE:
	case SHA512_HMAC_MECH_INFO_TYPE:
	case SHA512_HMAC_GEN_MECH_INFO_TYPE:
		sha_digest_len = SHA512_DIGEST_LENGTH;
		sha_hmac_block_size = SHA512_HMAC_BLOCK_SIZE;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Allocate and initialize SHA2 context.
	 */
	sha2_hmac_ctx_tmpl = kmem_alloc(sizeof (sha2_hmac_ctx_t),
	    crypto_kmflag(req));
	if (sha2_hmac_ctx_tmpl == NULL)
		return (CRYPTO_HOST_MEMORY);

	sha2_hmac_ctx_tmpl->hc_mech_type = mechanism->cm_type;

	if (keylen_in_bytes > sha_hmac_block_size) {
		uchar_t digested_key[SHA512_DIGEST_LENGTH];

		/*
		 * Hash the passed-in key to get a smaller key.
		 * The inner context is used since it hasn't been
		 * initialized yet.
		 */
		PROV_SHA2_DIGEST_KEY(mechanism->cm_type / 3,
		    &sha2_hmac_ctx_tmpl->hc_icontext,
		    key->ck_data, keylen_in_bytes, digested_key);
		sha2_mac_init_ctx(sha2_hmac_ctx_tmpl, digested_key,
		    sha_digest_len);
	} else {
		sha2_mac_init_ctx(sha2_hmac_ctx_tmpl, key->ck_data,
		    keylen_in_bytes);
	}

	*ctx_template = (crypto_spi_ctx_template_t)sha2_hmac_ctx_tmpl;
	*ctx_template_size = sizeof (sha2_hmac_ctx_t);

	return (CRYPTO_SUCCESS);
}

static int
sha2_free_context(crypto_ctx_t *ctx)
{
	uint_t ctx_len;

	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_SUCCESS);

	/*
	 * We have to free either SHA2 or SHA2-HMAC contexts, which
	 * have different lengths.
	 *
	 * Note: Below is dependent on the mechanism ordering.
	 */

	if (PROV_SHA2_CTX(ctx)->sc_mech_type % 3 == 0)
		ctx_len = sizeof (sha2_ctx_t);
	else
		ctx_len = sizeof (sha2_hmac_ctx_t);

	bzero(ctx->cc_provider_private, ctx_len);
	kmem_free(ctx->cc_provider_private, ctx_len);
	ctx->cc_provider_private = NULL;

	return (CRYPTO_SUCCESS);
}

#endif /* _KERNEL */

void
SHA2Init(uint64_t mech, SHA2_CTX *ctx)
{

	switch (mech) {
	case SHA256_MECH_INFO_TYPE:
	case SHA256_HMAC_MECH_INFO_TYPE:
	case SHA256_HMAC_GEN_MECH_INFO_TYPE:
		ctx->state.s32[0] = 0x6a09e667U;
		ctx->state.s32[1] = 0xbb67ae85U;
		ctx->state.s32[2] = 0x3c6ef372U;
		ctx->state.s32[3] = 0xa54ff53aU;
		ctx->state.s32[4] = 0x510e527fU;
		ctx->state.s32[5] = 0x9b05688cU;
		ctx->state.s32[6] = 0x1f83d9abU;
		ctx->state.s32[7] = 0x5be0cd19U;
		break;
	case SHA384_MECH_INFO_TYPE:
	case SHA384_HMAC_MECH_INFO_TYPE:
	case SHA384_HMAC_GEN_MECH_INFO_TYPE:
		ctx->state.s64[0] = 0xcbbb9d5dc1059ed8ULL;
		ctx->state.s64[1] = 0x629a292a367cd507ULL;
		ctx->state.s64[2] = 0x9159015a3070dd17ULL;
		ctx->state.s64[3] = 0x152fecd8f70e5939ULL;
		ctx->state.s64[4] = 0x67332667ffc00b31ULL;
		ctx->state.s64[5] = 0x8eb44a8768581511ULL;
		ctx->state.s64[6] = 0xdb0c2e0d64f98fa7ULL;
		ctx->state.s64[7] = 0x47b5481dbefa4fa4ULL;
		break;
	case SHA512_MECH_INFO_TYPE:
	case SHA512_HMAC_MECH_INFO_TYPE:
	case SHA512_HMAC_GEN_MECH_INFO_TYPE:
		ctx->state.s64[0] = 0x6a09e667f3bcc908ULL;
		ctx->state.s64[1] = 0xbb67ae8584caa73bULL;
		ctx->state.s64[2] = 0x3c6ef372fe94f82bULL;
		ctx->state.s64[3] = 0xa54ff53a5f1d36f1ULL;
		ctx->state.s64[4] = 0x510e527fade682d1ULL;
		ctx->state.s64[5] = 0x9b05688c2b3e6c1fULL;
		ctx->state.s64[6] = 0x1f83d9abfb41bd6bULL;
		ctx->state.s64[7] = 0x5be0cd19137e2179ULL;
		break;
#ifdef _KERNEL
	default:
		cmn_err(CE_WARN, "sha2_init: "
		    "failed to find a supported algorithm: 0x%x",
		    (uint32_t)mech);

#endif /* _KERNEL */
	}

	ctx->algotype = mech;
	ctx->count.c64[0] = ctx->count.c64[1] = 0;
}

/*
 * SHA2Update()
 *
 * purpose: continues an sha2 digest operation, using the message block
 *          to update the context.
 *   input: SHA2_CTX *	: the context to update
 *          uint8_t *	: the message block
 *          uint32_t    : the length of the message block in bytes
 *  output: void
 */

void
SHA2Update(SHA2_CTX *ctx, const uint8_t *input, uint32_t input_len)
{
	uint32_t i, buf_index, buf_len, buf_limit;

	/* check for noop */
	if (input_len == 0)
		return;

	if (ctx->algotype <= SHA256_HMAC_GEN_MECH_INFO_TYPE) {
		buf_limit = 64;

		/* compute number of bytes mod 64 */
		buf_index = (ctx->count.c32[1] >> 3) & 0x3F;

		/* update number of bits */
		if ((ctx->count.c32[1] += (input_len << 3)) < (input_len << 3))
			ctx->count.c32[0]++;

		ctx->count.c32[0] += (input_len >> 29);

	} else {
		buf_limit = 128;

		/* compute number of bytes mod 128 */
		buf_index = (ctx->count.c64[1] >> 3) & 0x7F;

		/* update number of bits */
		if ((ctx->count.c64[1] += (input_len << 3)) < (input_len << 3))
			ctx->count.c64[0]++;

		ctx->count.c64[0] += (input_len >> 29);
	}

	buf_len = buf_limit - buf_index;

	/* transform as many times as possible */
	i = 0;
	if (input_len >= buf_len) {

		/*
		 * general optimization:
		 *
		 * only do initial bcopy() and SHA2Transform() if
		 * buf_index != 0.  if buf_index == 0, we're just
		 * wasting our time doing the bcopy() since there
		 * wasn't any data left over from a previous call to
		 * SHA2Update().
		 */
		if (buf_index) {
			bcopy(input, &ctx->buf_un.buf8[buf_index], buf_len);
			if (ctx->algotype <= SHA256_HMAC_GEN_MECH_INFO_TYPE)
				SHA256Transform(ctx, ctx->buf_un.buf8);
			else
				SHA512Transform(ctx, ctx->buf_un.buf8);

			i = buf_len;
		}


		for (; i + buf_limit - 1 < input_len; i += buf_limit) {
			if (ctx->algotype <= SHA256_HMAC_GEN_MECH_INFO_TYPE)
				SHA256Transform(ctx, &input[i]);
			else
				SHA512Transform(ctx, &input[i]);
		}

		/*
		 * general optimization:
		 *
		 * if i and input_len are the same, return now instead
		 * of calling bcopy(), since the bcopy() in this case
		 * will be an expensive nop.
		 */

		if (input_len == i)
			return;

		buf_index = 0;
	}

	/* buffer remaining input */
	bcopy(&input[i], &ctx->buf_un.buf8[buf_index], input_len - i);
}


/*
 * SHA2Final()
 *
 * purpose: ends an sha2 digest operation, finalizing the message digest and
 *          zeroing the context.
 *   input: uint8_t *	: a buffer to store the digest in
 *          SHA2_CTX *  : the context to finalize, save, and zero
 *  output: void
 */


void
SHA2Final(uint8_t *digest, SHA2_CTX *ctx)
{
	uint8_t		bitcount_be[sizeof (ctx->count.c32)];
	uint8_t		bitcount_be64[sizeof (ctx->count.c64)];
	uint32_t	index;


	if (ctx->algotype <= SHA256_HMAC_GEN_MECH_INFO_TYPE) {
		index  = (ctx->count.c32[1] >> 3) & 0x3f;
		Encode(bitcount_be, ctx->count.c32, sizeof (bitcount_be));
		SHA2Update(ctx, PADDING, ((index < 56) ? 56 : 120) - index);
		SHA2Update(ctx, bitcount_be, sizeof (bitcount_be));
		Encode(digest, ctx->state.s32, sizeof (ctx->state.s32));

	} else {
		index  = (ctx->count.c64[1] >> 3) & 0x7f;
		Encode64(bitcount_be64, ctx->count.c64,
		    sizeof (bitcount_be64));
		SHA2Update(ctx, PADDING, ((index < 112) ? 112 : 240) - index);
		SHA2Update(ctx, bitcount_be64, sizeof (bitcount_be64));
		if (ctx->algotype <= SHA384_HMAC_GEN_MECH_INFO_TYPE) {
			ctx->state.s64[6] = ctx->state.s64[7] = 0;
			Encode64(digest, ctx->state.s64,
			    sizeof (uint64_t) * 6);
		} else
			Encode64(digest, ctx->state.s64,
			    sizeof (ctx->state.s64));
	}
}
