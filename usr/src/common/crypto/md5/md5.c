/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Cleaned-up and optimized version of MD5, based on the reference
 * implementation provided in RFC 1321.  See RSA Copyright information
 * below.
 *
 * NOTE:  All compiler data was gathered with SC4.2, and verified with SC5.x,
 *	  as used to build Solaris 2.7.  Hopefully the compiler behavior won't
 *	  change for the worse in subsequent Solaris builds.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/*
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
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
 */

#include <sys/types.h>
#include <sys/md5.h>
#include <sys/md5_consts.h>	/* MD5_CONST() optimization */
#include "md5_byteswap.h"
#if	!defined(_KERNEL) || defined(_BOOT)
#include <strings.h>
#endif /* !_KERNEL || _BOOT */

#if	defined(_KERNEL) && !defined(_BOOT)

/*
 * In kernel module, the md5 module is created with two modlinkages:
 * - a modlmisc that allows consumers to directly call the entry points
 *   MD5Init, MD5Update, and MD5Final.
 * - a modlcrypto that allows the module to register with the Kernel
 *   Cryptographic Framework (KCF) as a software provider for the MD5
 *   mechanisms.
 */

#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <sys/note.h>

extern struct mod_ops mod_miscops;
extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */

static struct modlmisc modlmisc = {
	&mod_miscops,
	"MD5 Message-Digest Algorithm"
};

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"MD5 Kernel SW Provider 1.23"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */

typedef enum md5_mech_type {
	MD5_MECH_INFO_TYPE,		/* SUN_CKM_MD5 */
	MD5_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_MD5_HMAC */
	MD5_HMAC_GEN_MECH_INFO_TYPE	/* SUN_CKM_MD5_HMAC_GENERAL */
} md5_mech_type_t;

#define	MD5_DIGEST_LENGTH	16	/* MD5 digest length in bytes */
#define	MD5_HMAC_BLOCK_SIZE	64	/* MD5 block size */
#define	MD5_HMAC_MIN_KEY_LEN	8	/* MD5-HMAC min key length in bits */
#define	MD5_HMAC_MAX_KEY_LEN	INT_MAX	/* MD5-HMAC max key length in bits */
#define	MD5_HMAC_INTS_PER_BLOCK	(MD5_HMAC_BLOCK_SIZE/sizeof (uint32_t))

/*
 * Context for MD5 mechanism.
 */
typedef struct md5_ctx {
	md5_mech_type_t		mc_mech_type;	/* type of context */
	MD5_CTX			mc_md5_ctx;	/* MD5 context */
} md5_ctx_t;

/*
 * Context for MD5-HMAC and MD5-HMAC-GENERAL mechanisms.
 */
typedef struct md5_hmac_ctx {
	md5_mech_type_t		hc_mech_type;	/* type of context */
	uint32_t		hc_digest_len;	/* digest len in bytes */
	MD5_CTX			hc_icontext;	/* inner MD5 context */
	MD5_CTX			hc_ocontext;	/* outer MD5 context */
} md5_hmac_ctx_t;

/*
 * Macros to access the MD5 or MD5-HMAC contexts from a context passed
 * by KCF to one of the entry points.
 */

#define	PROV_MD5_CTX(ctx)	((md5_ctx_t *)(ctx)->cc_provider_private)
#define	PROV_MD5_HMAC_CTX(ctx)	((md5_hmac_ctx_t *)(ctx)->cc_provider_private)
/* to extract the digest length passed as mechanism parameter */

#define	PROV_MD5_GET_DIGEST_LEN(m, len) {				\
	if (IS_P2ALIGNED((m)->cm_param, sizeof (ulong_t)))		\
		(len) = (uint32_t)*((ulong_t *)mechanism->cm_param);	\
	else {								\
		ulong_t tmp_ulong;					\
		bcopy((m)->cm_param, &tmp_ulong, sizeof (ulong_t));	\
		(len) = (uint32_t)tmp_ulong;				\
	}								\
}

#define	PROV_MD5_DIGEST_KEY(ctx, key, len, digest) {	\
	MD5Init(ctx);					\
	MD5Update(ctx, key, len);			\
	MD5Final(digest, ctx);				\
}

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t md5_mech_info_tab[] = {
	/* MD5 */
	{SUN_CKM_MD5, MD5_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* MD5-HMAC */
	{SUN_CKM_MD5_HMAC, MD5_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    MD5_HMAC_MIN_KEY_LEN, MD5_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* MD5-HMAC GENERAL */
	{SUN_CKM_MD5_HMAC_GENERAL, MD5_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    MD5_HMAC_MIN_KEY_LEN, MD5_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

static void md5_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t md5_control_ops = {
	md5_provider_status
};

static int md5_digest_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_req_handle_t);
static int md5_digest(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int md5_digest_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int md5_digest_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int md5_digest_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

static crypto_digest_ops_t md5_digest_ops = {
	md5_digest_init,
	md5_digest,
	md5_digest_update,
	NULL,
	md5_digest_final,
	md5_digest_atomic
};

static int md5_mac_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int md5_mac_update(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t);
static int md5_mac_final(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t);
static int md5_mac_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int md5_mac_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_mac_ops_t md5_mac_ops = {
	md5_mac_init,
	NULL,
	md5_mac_update,
	md5_mac_final,
	md5_mac_atomic,
	md5_mac_verify_atomic
};

static int md5_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int md5_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t md5_ctx_ops = {
	md5_create_ctx_template,
	md5_free_context
};

static crypto_ops_t md5_crypto_ops = {
	&md5_control_ops,
	&md5_digest_ops,
	NULL,
	&md5_mac_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&md5_ctx_ops
};

static crypto_provider_info_t md5_prov_info = {
	CRYPTO_SPI_VERSION_1,
	"MD5 Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&md5_crypto_ops,
	sizeof (md5_mech_info_tab)/sizeof (crypto_mech_info_t),
	md5_mech_info_tab
};

static crypto_kcf_provider_handle_t md5_prov_handle = NULL;

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/*
	 * Register with KCF. If the registration fails, log an
	 * error but do not uninstall the module, since the functionality
	 * provided by misc/md5 should still be available.
	 */
	if ((ret = crypto_register_provider(&md5_prov_info,
	    &md5_prov_handle)) != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "md5 _init: "
		    "crypto_register_provider() failed (0x%x)", ret);

	return (0);
}

int
_fini(void)
{
	int ret;

	/*
	 * Unregister from KCF if previous registration succeeded.
	 */
	if (md5_prov_handle != NULL) {
		if ((ret = crypto_unregister_provider(md5_prov_handle)) !=
		    CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "md5 _fini: "
			    "crypto_unregister_provider() failed (0x%x)", ret);
			return (EBUSY);
		}
		md5_prov_handle = NULL;
	}

	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
#endif	/* _KERNEL && !_BOOT */

static void Encode(uint8_t *, uint32_t *, size_t);
static void MD5Transform(uint32_t, uint32_t, uint32_t, uint32_t, MD5_CTX *,
    const uint8_t [64]);

static uint8_t PADDING[64] = { 0x80, /* all zeros */ };

/*
 * F, G, H and I are the basic MD5 functions.
 */
#define	F(b, c, d)	(((b) & (c)) | ((~b) & (d)))
#define	G(b, c, d)	(((b) & (d)) | ((c) & (~d)))
#define	H(b, c, d)	((b) ^ (c) ^ (d))
#define	I(b, c, d)	((c) ^ ((b) | (~d)))

/*
 * ROTATE_LEFT rotates x left n bits.
 */
#define	ROTATE_LEFT(x, n)	\
	(((x) << (n)) | ((x) >> ((sizeof (x) << 3) - (n))))

/*
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */

#define	FF(a, b, c, d, x, s, ac) { \
	(a) += F((b), (c), (d)) + (x) + ((unsigned long long)(ac)); \
	(a) = ROTATE_LEFT((a), (s)); \
	(a) += (b); \
	}

#define	GG(a, b, c, d, x, s, ac) { \
	(a) += G((b), (c), (d)) + (x) + ((unsigned long long)(ac)); \
	(a) = ROTATE_LEFT((a), (s)); \
	(a) += (b); \
	}

#define	HH(a, b, c, d, x, s, ac) { \
	(a) += H((b), (c), (d)) + (x) + ((unsigned long long)(ac)); \
	(a) = ROTATE_LEFT((a), (s)); \
	(a) += (b); \
	}

#define	II(a, b, c, d, x, s, ac) { \
	(a) += I((b), (c), (d)) + (x) + ((unsigned long long)(ac)); \
	(a) = ROTATE_LEFT((a), (s)); \
	(a) += (b); \
	}

/*
 * Loading 32-bit constants on a RISC is expensive since it involves both a
 * `sethi' and an `or'.  thus, we instead have the compiler generate `ld's to
 * load the constants from an array called `md5_consts'.  however, on intel
 * (and other CISC processors), it is cheaper to load the constant
 * directly.  thus, the c code in MD5Transform() uses the macro MD5_CONST()
 * which either expands to a constant or an array reference, depending on the
 * architecture the code is being compiled for.
 *
 * Right now, i386 and amd64 are the CISC exceptions.
 * If we get another CISC ISA, we'll have to change the ifdef.
 */

#if defined(__i386) || defined(__amd64)

#define	MD5_CONST(x)		(MD5_CONST_ ## x)
#define	MD5_CONST_e(x)		MD5_CONST(x)
#define	MD5_CONST_o(x)		MD5_CONST(x)

#else
/*
 * sparc/RISC optimization:
 *
 * while it is somewhat counter-intuitive, on sparc (and presumably other RISC
 * machines), it is more efficient to place all the constants used in this
 * function in an array and load the values out of the array than to manually
 * load the constants.  this is because setting a register to a 32-bit value
 * takes two ops in most cases: a `sethi' and an `or', but loading a 32-bit
 * value from memory only takes one `ld' (or `lduw' on v9).  while this
 * increases memory usage, the compiler can find enough other things to do
 * while waiting to keep the pipeline does not stall.  additionally, it is
 * likely that many of these constants are cached so that later accesses do
 * not even go out to the bus.
 *
 * this array is declared `static' to keep the compiler from having to
 * bcopy() this array onto the stack frame of MD5Transform() each time it is
 * called -- which is unacceptably expensive.
 *
 * the `const' is to ensure that callers are good citizens and do not try to
 * munge the array.  since these routines are going to be called from inside
 * multithreaded kernelland, this is a good safety check. -- `constants' will
 * end up in .rodata.
 *
 * unfortunately, loading from an array in this manner hurts performance under
 * intel (and presumably other CISC machines).  so, there is a macro,
 * MD5_CONST(), used in MD5Transform(), that either expands to a reference to
 * this array, or to the actual constant, depending on what platform this code
 * is compiled for.
 */

#ifdef sun4v

/*
 * Going to load these consts in 8B chunks, so need to enforce 8B alignment
 */

/* CSTYLED */
#pragma align 64 (md5_consts)

#endif /* sun4v */

static const uint32_t md5_consts[] = {
	MD5_CONST_0,	MD5_CONST_1,	MD5_CONST_2,	MD5_CONST_3,
	MD5_CONST_4,	MD5_CONST_5,	MD5_CONST_6,	MD5_CONST_7,
	MD5_CONST_8,	MD5_CONST_9,	MD5_CONST_10,	MD5_CONST_11,
	MD5_CONST_12,	MD5_CONST_13,	MD5_CONST_14,	MD5_CONST_15,
	MD5_CONST_16,	MD5_CONST_17,	MD5_CONST_18,	MD5_CONST_19,
	MD5_CONST_20,	MD5_CONST_21,	MD5_CONST_22,	MD5_CONST_23,
	MD5_CONST_24,	MD5_CONST_25,	MD5_CONST_26,	MD5_CONST_27,
	MD5_CONST_28,	MD5_CONST_29,	MD5_CONST_30,	MD5_CONST_31,
	MD5_CONST_32,	MD5_CONST_33,	MD5_CONST_34,	MD5_CONST_35,
	MD5_CONST_36,	MD5_CONST_37,	MD5_CONST_38,	MD5_CONST_39,
	MD5_CONST_40,	MD5_CONST_41,	MD5_CONST_42,	MD5_CONST_43,
	MD5_CONST_44,	MD5_CONST_45,	MD5_CONST_46,	MD5_CONST_47,
	MD5_CONST_48,	MD5_CONST_49,	MD5_CONST_50,	MD5_CONST_51,
	MD5_CONST_52,	MD5_CONST_53,	MD5_CONST_54,	MD5_CONST_55,
	MD5_CONST_56,	MD5_CONST_57,	MD5_CONST_58,	MD5_CONST_59,
	MD5_CONST_60,	MD5_CONST_61,	MD5_CONST_62,	MD5_CONST_63
};


#ifdef sun4v
/*
 * To reduce the number of loads, load consts in 64-bit
 * chunks and then split.
 *
 * No need to mask upper 32-bits, as just interested in
 * low 32-bits (saves an & operation and means that this
 * optimization doesn't increases the icount.
 */
#define	MD5_CONST_e(x)		(md5_consts64[x/2] >> 32)
#define	MD5_CONST_o(x)		(md5_consts64[x/2])

#else

#define	MD5_CONST_e(x)		(md5_consts[x])
#define	MD5_CONST_o(x)		(md5_consts[x])

#endif /* sun4v */

#endif

/*
 * MD5Init()
 *
 * purpose: initializes the md5 context and begins and md5 digest operation
 *   input: MD5_CTX *	: the context to initialize.
 *  output: void
 */

void
MD5Init(MD5_CTX *ctx)
{
	ctx->count[0] = ctx->count[1] = 0;

	/* load magic initialization constants */
	ctx->state[0] = MD5_INIT_CONST_1;
	ctx->state[1] = MD5_INIT_CONST_2;
	ctx->state[2] = MD5_INIT_CONST_3;
	ctx->state[3] = MD5_INIT_CONST_4;
}

/*
 * MD5Update()
 *
 * purpose: continues an md5 digest operation, using the message block
 *          to update the context.
 *   input: MD5_CTX *	: the context to update
 *          uint8_t *	: the message block
 *          uint32_t    : the length of the message block in bytes
 *  output: void
 *
 * MD5 crunches in 64-byte blocks.  All numeric constants here are related to
 * that property of MD5.
 */

void
MD5Update(MD5_CTX *ctx, const void *inpp, unsigned int input_len)
{
	uint32_t		i, buf_index, buf_len;
#ifdef	sun4v
	uint32_t		old_asi;
#endif	/* sun4v */
	const unsigned char 	*input = (const unsigned char *)inpp;

	/* compute (number of bytes computed so far) mod 64 */
	buf_index = (ctx->count[0] >> 3) & 0x3F;

	/* update number of bits hashed into this MD5 computation so far */
	if ((ctx->count[0] += (input_len << 3)) < (input_len << 3))
	    ctx->count[1]++;
	ctx->count[1] += (input_len >> 29);

	buf_len = 64 - buf_index;

	/* transform as many times as possible */
	i = 0;
	if (input_len >= buf_len) {

		/*
		 * general optimization:
		 *
		 * only do initial bcopy() and MD5Transform() if
		 * buf_index != 0.  if buf_index == 0, we're just
		 * wasting our time doing the bcopy() since there
		 * wasn't any data left over from a previous call to
		 * MD5Update().
		 */

#ifdef sun4v
		/*
		 * For N1 use %asi register. However, costly to repeatedly set
		 * in MD5Transform. Therefore, set once here.
		 * Should probably restore the old value afterwards...
		 */
		old_asi = get_little();
		set_little(0x88);
#endif /* sun4v */

		if (buf_index) {
			bcopy(input, &ctx->buf_un.buf8[buf_index], buf_len);

			MD5Transform(ctx->state[0], ctx->state[1],
			    ctx->state[2], ctx->state[3], ctx,
			    ctx->buf_un.buf8);

			i = buf_len;
		}

		for (; i + 63 < input_len; i += 64)
			MD5Transform(ctx->state[0], ctx->state[1],
			    ctx->state[2], ctx->state[3], ctx, &input[i]);


#ifdef sun4v
		/*
		 * Restore old %ASI value
		 */
		set_little(old_asi);
#endif /* sun4v */

		/*
		 * general optimization:
		 *
		 * if i and input_len are the same, return now instead
		 * of calling bcopy(), since the bcopy() in this
		 * case will be an expensive nop.
		 */

		if (input_len == i)
			return;

		buf_index = 0;
	}

	/* buffer remaining input */
	bcopy(&input[i], &ctx->buf_un.buf8[buf_index], input_len - i);
}

/*
 * MD5Final()
 *
 * purpose: ends an md5 digest operation, finalizing the message digest and
 *          zeroing the context.
 *   input: uint8_t *	: a buffer to store the digest in
 *          MD5_CTX *   : the context to finalize, save, and zero
 *  output: void
 */

void
MD5Final(unsigned char *digest, MD5_CTX *ctx)
{
	uint8_t		bitcount_le[sizeof (ctx->count)];
	uint32_t	index = (ctx->count[0] >> 3) & 0x3f;

	/* store bit count, little endian */
	Encode(bitcount_le, ctx->count, sizeof (bitcount_le));

	/* pad out to 56 mod 64 */
	MD5Update(ctx, PADDING, ((index < 56) ? 56 : 120) - index);

	/* append length (before padding) */
	MD5Update(ctx, bitcount_le, sizeof (bitcount_le));

	/* store state in digest */
	Encode(digest, ctx->state, sizeof (ctx->state));
}

#ifndef	_KERNEL

void
md5_calc(unsigned char *output, unsigned char *input, unsigned int inlen)
{
	MD5_CTX context;

	MD5Init(&context);
	MD5Update(&context, input, inlen);
	MD5Final(output, &context);
}

#endif	/* !_KERNEL */

/*
 * sparc register window optimization:
 *
 * `a', `b', `c', and `d' are passed into MD5Transform explicitly
 * since it increases the number of registers available to the
 * compiler.  under this scheme, these variables can be held in
 * %i0 - %i3, which leaves more local and out registers available.
 */

/*
 * MD5Transform()
 *
 * purpose: md5 transformation -- updates the digest based on `block'
 *   input: uint32_t	: bytes  1 -  4 of the digest
 *          uint32_t	: bytes  5 -  8 of the digest
 *          uint32_t	: bytes  9 - 12 of the digest
 *          uint32_t	: bytes 12 - 16 of the digest
 *          MD5_CTX *   : the context to update
 *          uint8_t [64]: the block to use to update the digest
 *  output: void
 */

static void
MD5Transform(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
    MD5_CTX *ctx, const uint8_t block[64])
{
	/*
	 * general optimization:
	 *
	 * use individual integers instead of using an array.  this is a
	 * win, although the amount it wins by seems to vary quite a bit.
	 */

	register uint32_t	x_0, x_1, x_2,  x_3,  x_4,  x_5,  x_6,  x_7;
	register uint32_t	x_8, x_9, x_10, x_11, x_12, x_13, x_14, x_15;
#ifdef sun4v
	unsigned long long 	*md5_consts64;

	md5_consts64 = (unsigned long long *) md5_consts;
#endif	/* sun4v */

	/*
	 * general optimization:
	 *
	 * the compiler (at least SC4.2/5.x) generates better code if
	 * variable use is localized.  in this case, swapping the integers in
	 * this order allows `x_0 'to be swapped nearest to its first use in
	 * FF(), and likewise for `x_1' and up.  note that the compiler
	 * prefers this to doing each swap right before the FF() that
	 * uses it.
	 */

	/*
	 * sparc v9/v8plus optimization:
	 *
	 * if `block' is already aligned on a 4-byte boundary, use the
	 * optimized load_little_32() directly.  otherwise, bcopy()
	 * into a buffer that *is* aligned on a 4-byte boundary and
	 * then do the load_little_32() on that buffer.  benchmarks
	 * have shown that using the bcopy() is better than loading
	 * the bytes individually and doing the endian-swap by hand.
	 *
	 * even though it's quite tempting to assign to do:
	 *
	 * blk = bcopy(blk, ctx->buf_un.buf32, sizeof (ctx->buf_un.buf32));
	 *
	 * and only have one set of LOAD_LITTLE_32()'s, the compiler (at least
	 * SC4.2/5.x) *does not* like that, so please resist the urge.
	 */

#ifdef _MD5_CHECK_ALIGNMENT
	if ((uintptr_t)block & 0x3) {		/* not 4-byte aligned? */
		bcopy(block, ctx->buf_un.buf32, sizeof (ctx->buf_un.buf32));

#ifdef sun4v
		x_15 = LOAD_LITTLE_32_f(ctx->buf_un.buf32);
		x_14 = LOAD_LITTLE_32_e(ctx->buf_un.buf32);
		x_13 = LOAD_LITTLE_32_d(ctx->buf_un.buf32);
		x_12 = LOAD_LITTLE_32_c(ctx->buf_un.buf32);
		x_11 = LOAD_LITTLE_32_b(ctx->buf_un.buf32);
		x_10 = LOAD_LITTLE_32_a(ctx->buf_un.buf32);
		x_9  = LOAD_LITTLE_32_9(ctx->buf_un.buf32);
		x_8  = LOAD_LITTLE_32_8(ctx->buf_un.buf32);
		x_7  = LOAD_LITTLE_32_7(ctx->buf_un.buf32);
		x_6  = LOAD_LITTLE_32_6(ctx->buf_un.buf32);
		x_5  = LOAD_LITTLE_32_5(ctx->buf_un.buf32);
		x_4  = LOAD_LITTLE_32_4(ctx->buf_un.buf32);
		x_3  = LOAD_LITTLE_32_3(ctx->buf_un.buf32);
		x_2  = LOAD_LITTLE_32_2(ctx->buf_un.buf32);
		x_1  = LOAD_LITTLE_32_1(ctx->buf_un.buf32);
		x_0  = LOAD_LITTLE_32_0(ctx->buf_un.buf32);
#else
		x_15 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 15);
		x_14 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 14);
		x_13 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 13);
		x_12 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 12);
		x_11 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 11);
		x_10 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 10);
		x_9  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  9);
		x_8  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  8);
		x_7  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  7);
		x_6  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  6);
		x_5  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  5);
		x_4  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  4);
		x_3  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  3);
		x_2  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  2);
		x_1  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  1);
		x_0  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  0);
#endif /* sun4v */
	} else
#endif
	{

#ifdef sun4v
		x_15 = LOAD_LITTLE_32_f(block);
		x_14 = LOAD_LITTLE_32_e(block);
		x_13 = LOAD_LITTLE_32_d(block);
		x_12 = LOAD_LITTLE_32_c(block);
		x_11 = LOAD_LITTLE_32_b(block);
		x_10 = LOAD_LITTLE_32_a(block);
		x_9  = LOAD_LITTLE_32_9(block);
		x_8  = LOAD_LITTLE_32_8(block);
		x_7  = LOAD_LITTLE_32_7(block);
		x_6  = LOAD_LITTLE_32_6(block);
		x_5  = LOAD_LITTLE_32_5(block);
		x_4  = LOAD_LITTLE_32_4(block);
		x_3  = LOAD_LITTLE_32_3(block);
		x_2  = LOAD_LITTLE_32_2(block);
		x_1  = LOAD_LITTLE_32_1(block);
		x_0  = LOAD_LITTLE_32_0(block);
#else
		x_15 = LOAD_LITTLE_32(block + 60);
		x_14 = LOAD_LITTLE_32(block + 56);
		x_13 = LOAD_LITTLE_32(block + 52);
		x_12 = LOAD_LITTLE_32(block + 48);
		x_11 = LOAD_LITTLE_32(block + 44);
		x_10 = LOAD_LITTLE_32(block + 40);
		x_9  = LOAD_LITTLE_32(block + 36);
		x_8  = LOAD_LITTLE_32(block + 32);
		x_7  = LOAD_LITTLE_32(block + 28);
		x_6  = LOAD_LITTLE_32(block + 24);
		x_5  = LOAD_LITTLE_32(block + 20);
		x_4  = LOAD_LITTLE_32(block + 16);
		x_3  = LOAD_LITTLE_32(block + 12);
		x_2  = LOAD_LITTLE_32(block +  8);
		x_1  = LOAD_LITTLE_32(block +  4);
		x_0  = LOAD_LITTLE_32(block +  0);
#endif /* sun4v */
	}

	/* round 1 */
	FF(a, b, c, d, 	x_0, MD5_SHIFT_11, MD5_CONST_e(0));  /* 1 */
	FF(d, a, b, c, 	x_1, MD5_SHIFT_12, MD5_CONST_o(1));  /* 2 */
	FF(c, d, a, b, 	x_2, MD5_SHIFT_13, MD5_CONST_e(2));  /* 3 */
	FF(b, c, d, a, 	x_3, MD5_SHIFT_14, MD5_CONST_o(3));  /* 4 */
	FF(a, b, c, d, 	x_4, MD5_SHIFT_11, MD5_CONST_e(4));  /* 5 */
	FF(d, a, b, c, 	x_5, MD5_SHIFT_12, MD5_CONST_o(5));  /* 6 */
	FF(c, d, a, b, 	x_6, MD5_SHIFT_13, MD5_CONST_e(6));  /* 7 */
	FF(b, c, d, a, 	x_7, MD5_SHIFT_14, MD5_CONST_o(7));  /* 8 */
	FF(a, b, c, d, 	x_8, MD5_SHIFT_11, MD5_CONST_e(8));  /* 9 */
	FF(d, a, b, c, 	x_9, MD5_SHIFT_12, MD5_CONST_o(9));  /* 10 */
	FF(c, d, a, b, x_10, MD5_SHIFT_13, MD5_CONST_e(10)); /* 11 */
	FF(b, c, d, a, x_11, MD5_SHIFT_14, MD5_CONST_o(11)); /* 12 */
	FF(a, b, c, d, x_12, MD5_SHIFT_11, MD5_CONST_e(12)); /* 13 */
	FF(d, a, b, c, x_13, MD5_SHIFT_12, MD5_CONST_o(13)); /* 14 */
	FF(c, d, a, b, x_14, MD5_SHIFT_13, MD5_CONST_e(14)); /* 15 */
	FF(b, c, d, a, x_15, MD5_SHIFT_14, MD5_CONST_o(15)); /* 16 */

	/* round 2 */
	GG(a, b, c, d,  x_1, MD5_SHIFT_21, MD5_CONST_e(16)); /* 17 */
	GG(d, a, b, c,  x_6, MD5_SHIFT_22, MD5_CONST_o(17)); /* 18 */
	GG(c, d, a, b, x_11, MD5_SHIFT_23, MD5_CONST_e(18)); /* 19 */
	GG(b, c, d, a,  x_0, MD5_SHIFT_24, MD5_CONST_o(19)); /* 20 */
	GG(a, b, c, d,  x_5, MD5_SHIFT_21, MD5_CONST_e(20)); /* 21 */
	GG(d, a, b, c, x_10, MD5_SHIFT_22, MD5_CONST_o(21)); /* 22 */
	GG(c, d, a, b, x_15, MD5_SHIFT_23, MD5_CONST_e(22)); /* 23 */
	GG(b, c, d, a,  x_4, MD5_SHIFT_24, MD5_CONST_o(23)); /* 24 */
	GG(a, b, c, d,  x_9, MD5_SHIFT_21, MD5_CONST_e(24)); /* 25 */
	GG(d, a, b, c, x_14, MD5_SHIFT_22, MD5_CONST_o(25)); /* 26 */
	GG(c, d, a, b,  x_3, MD5_SHIFT_23, MD5_CONST_e(26)); /* 27 */
	GG(b, c, d, a,  x_8, MD5_SHIFT_24, MD5_CONST_o(27)); /* 28 */
	GG(a, b, c, d, x_13, MD5_SHIFT_21, MD5_CONST_e(28)); /* 29 */
	GG(d, a, b, c,  x_2, MD5_SHIFT_22, MD5_CONST_o(29)); /* 30 */
	GG(c, d, a, b,  x_7, MD5_SHIFT_23, MD5_CONST_e(30)); /* 31 */
	GG(b, c, d, a, x_12, MD5_SHIFT_24, MD5_CONST_o(31)); /* 32 */

	/* round 3 */
	HH(a, b, c, d,  x_5, MD5_SHIFT_31, MD5_CONST_e(32)); /* 33 */
	HH(d, a, b, c,  x_8, MD5_SHIFT_32, MD5_CONST_o(33)); /* 34 */
	HH(c, d, a, b, x_11, MD5_SHIFT_33, MD5_CONST_e(34)); /* 35 */
	HH(b, c, d, a, x_14, MD5_SHIFT_34, MD5_CONST_o(35)); /* 36 */
	HH(a, b, c, d,  x_1, MD5_SHIFT_31, MD5_CONST_e(36)); /* 37 */
	HH(d, a, b, c,  x_4, MD5_SHIFT_32, MD5_CONST_o(37)); /* 38 */
	HH(c, d, a, b,  x_7, MD5_SHIFT_33, MD5_CONST_e(38)); /* 39 */
	HH(b, c, d, a, x_10, MD5_SHIFT_34, MD5_CONST_o(39)); /* 40 */
	HH(a, b, c, d, x_13, MD5_SHIFT_31, MD5_CONST_e(40)); /* 41 */
	HH(d, a, b, c,  x_0, MD5_SHIFT_32, MD5_CONST_o(41)); /* 42 */
	HH(c, d, a, b,  x_3, MD5_SHIFT_33, MD5_CONST_e(42)); /* 43 */
	HH(b, c, d, a,  x_6, MD5_SHIFT_34, MD5_CONST_o(43)); /* 44 */
	HH(a, b, c, d,  x_9, MD5_SHIFT_31, MD5_CONST_e(44)); /* 45 */
	HH(d, a, b, c, x_12, MD5_SHIFT_32, MD5_CONST_o(45)); /* 46 */
	HH(c, d, a, b, x_15, MD5_SHIFT_33, MD5_CONST_e(46)); /* 47 */
	HH(b, c, d, a,  x_2, MD5_SHIFT_34, MD5_CONST_o(47)); /* 48 */

	/* round 4 */
	II(a, b, c, d,  x_0, MD5_SHIFT_41, MD5_CONST_e(48)); /* 49 */
	II(d, a, b, c,  x_7, MD5_SHIFT_42, MD5_CONST_o(49)); /* 50 */
	II(c, d, a, b, x_14, MD5_SHIFT_43, MD5_CONST_e(50)); /* 51 */
	II(b, c, d, a,  x_5, MD5_SHIFT_44, MD5_CONST_o(51)); /* 52 */
	II(a, b, c, d, x_12, MD5_SHIFT_41, MD5_CONST_e(52)); /* 53 */
	II(d, a, b, c,  x_3, MD5_SHIFT_42, MD5_CONST_o(53)); /* 54 */
	II(c, d, a, b, x_10, MD5_SHIFT_43, MD5_CONST_e(54)); /* 55 */
	II(b, c, d, a,  x_1, MD5_SHIFT_44, MD5_CONST_o(55)); /* 56 */
	II(a, b, c, d,  x_8, MD5_SHIFT_41, MD5_CONST_e(56)); /* 57 */
	II(d, a, b, c, x_15, MD5_SHIFT_42, MD5_CONST_o(57)); /* 58 */
	II(c, d, a, b,  x_6, MD5_SHIFT_43, MD5_CONST_e(58)); /* 59 */
	II(b, c, d, a, x_13, MD5_SHIFT_44, MD5_CONST_o(59)); /* 60 */
	II(a, b, c, d,  x_4, MD5_SHIFT_41, MD5_CONST_e(60)); /* 61 */
	II(d, a, b, c, x_11, MD5_SHIFT_42, MD5_CONST_o(61)); /* 62 */
	II(c, d, a, b,  x_2, MD5_SHIFT_43, MD5_CONST_e(62)); /* 63 */
	II(b, c, d, a,  x_9, MD5_SHIFT_44, MD5_CONST_o(63)); /* 64 */

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;

	/*
	 * zeroize sensitive information -- compiler will optimize
	 * this out if everything is kept in registers
	 */

	x_0 = x_1  = x_2  = x_3  = x_4  = x_5  = x_6  = x_7 = x_8 = 0;
	x_9 = x_10 = x_11 = x_12 = x_13 = x_14 = x_15 = 0;
}

/*
 * devpro compiler optimization:
 *
 * the compiler can generate better code if it knows that `input' and
 * `output' do not point to the same source.  there is no portable
 * way to tell the compiler this, but the devpro compiler recognizes the
 * `_Restrict' keyword to indicate this condition.  use it if possible.
 */

#if defined(__RESTRICT) && !defined(__GNUC__)
#define	restrict	_Restrict
#else
#define	restrict	/* nothing */
#endif

/*
 * Encode()
 *
 * purpose: to convert a list of numbers from big endian to little endian
 *   input: uint8_t *	: place to store the converted little endian numbers
 *	    uint32_t *	: place to get numbers to convert from
 *          size_t	: the length of the input in bytes
 *  output: void
 */

static void
Encode(uint8_t *restrict output, uint32_t *restrict input, size_t input_len)
{
	size_t		i, j;

	for (i = 0, j = 0; j < input_len; i++, j += sizeof (uint32_t)) {

#ifdef _LITTLE_ENDIAN

#ifdef _MD5_CHECK_ALIGNMENT
		if ((uintptr_t)output & 0x3)	/* Not 4-byte aligned */
			bcopy(input + i, output + j, 4);
		else *(uint32_t *)(output + j) = input[i];
#else
		*(uint32_t *)(output + j) = input[i];
#endif /* _MD5_CHECK_ALIGNMENT */

#else	/* big endian -- will work on little endian, but slowly */

		output[j] = input[i] & 0xff;
		output[j + 1] = (input[i] >> 8)  & 0xff;
		output[j + 2] = (input[i] >> 16) & 0xff;
		output[j + 3] = (input[i] >> 24) & 0xff;
#endif
	}
}

#if	defined(_KERNEL) && !defined(_BOOT)

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
md5_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF software provider digest entry points.
 */

static int
md5_digest_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_req_handle_t req)
{
	if (mechanism->cm_type != MD5_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/*
	 * Allocate and initialize MD5 context.
	 */
	ctx->cc_provider_private = kmem_alloc(sizeof (md5_ctx_t),
	    crypto_kmflag(req));
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_HOST_MEMORY);

	PROV_MD5_CTX(ctx)->mc_mech_type = MD5_MECH_INFO_TYPE;
	MD5Init(&PROV_MD5_CTX(ctx)->mc_md5_ctx);

	return (CRYPTO_SUCCESS);
}

/*
 * Helper MD5 digest update function for uio data.
 */
static int
md5_digest_update_uio(MD5_CTX *md5_ctx, crypto_data_t *data)
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

		MD5Update(md5_ctx, data->cd_uio->uio_iov[vec_idx].iov_base +
		    offset, cur_len);

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
 * Helper MD5 digest final function for uio data.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default MD5 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least MD5_DIGEST_LENGTH bytes.
 */
static int
md5_digest_final_uio(MD5_CTX *md5_ctx, crypto_data_t *digest,
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
		 * The computed MD5 digest will fit in the current
		 * iovec.
		 */
		if (digest_len != MD5_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			MD5Final(digest_scratch, md5_ctx);
			bcopy(digest_scratch, (uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    digest_len);
		} else {
			MD5Final((uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    md5_ctx);
		}
	} else {
		/*
		 * The computed digest will be crossing one or more iovec's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[MD5_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		MD5Final(digest_tmp, md5_ctx);

		while (vec_idx < digest->cd_uio->uio_iovcnt && length > 0) {
			cur_len = MIN(digest->cd_uio->uio_iov[vec_idx].iov_len -
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
 * Helper MD5 digest update for mblk's.
 */
static int
md5_digest_update_mblk(MD5_CTX *md5_ctx, crypto_data_t *data)
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
		MD5Update(md5_ctx, mp->b_rptr + offset, cur_len);
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
 * Helper MD5 digest final for mblk's.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default MD5 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least MD5_DIGEST_LENGTH bytes.
 */
static int
md5_digest_final_mblk(MD5_CTX *md5_ctx, crypto_data_t *digest,
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
		 * The computed MD5 digest will fit in the current mblk.
		 * Do the MD5Final() in-place.
		 */
		if (digest_len != MD5_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			MD5Final(digest_scratch, md5_ctx);
			bcopy(digest_scratch, mp->b_rptr + offset, digest_len);
		} else {
			MD5Final(mp->b_rptr + offset, md5_ctx);
		}
	} else {
		/*
		 * The computed digest will be crossing one or more mblk's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[MD5_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		MD5Final(digest_tmp, md5_ctx);

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
md5_digest(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < MD5_DIGEST_LENGTH)) {
		digest->cd_length = MD5_DIGEST_LENGTH;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do the MD5 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		MD5Update(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_update_uio(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_update_mblk(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret != CRYPTO_SUCCESS) {
		/* the update failed, free context and bail */
		kmem_free(ctx->cc_provider_private, sizeof (md5_ctx_t));
		ctx->cc_provider_private = NULL;
		digest->cd_length = 0;
		return (ret);
	}

	/*
	 * Do an MD5 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		MD5Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_MD5_CTX(ctx)->mc_md5_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_final_uio(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    digest, MD5_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_final_mblk(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    digest, MD5_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = MD5_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (md5_ctx_t));
	ctx->cc_provider_private = NULL;
	return (ret);
}

/* ARGSUSED */
static int
md5_digest_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * Do the MD5 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		MD5Update(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_update_uio(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_update_mblk(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/* ARGSUSED */
static int
md5_digest_final(crypto_ctx_t *ctx, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < MD5_DIGEST_LENGTH)) {
		digest->cd_length = MD5_DIGEST_LENGTH;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an MD5 final.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		MD5Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_MD5_CTX(ctx)->mc_md5_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_final_uio(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    digest, MD5_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_final_mblk(&PROV_MD5_CTX(ctx)->mc_md5_ctx,
		    digest, MD5_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = MD5_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (md5_ctx_t));
	ctx->cc_provider_private = NULL;

	return (ret);
}

/* ARGSUSED */
static int
md5_digest_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	MD5_CTX md5_ctx;

	if (mechanism->cm_type != MD5_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/*
	 * Do the MD5 init.
	 */
	MD5Init(&md5_ctx);

	/*
	 * Do the MD5 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		MD5Update(&md5_ctx, data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_update_uio(&md5_ctx, data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_update_mblk(&md5_ctx, data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret != CRYPTO_SUCCESS) {
		/* the update failed, bail */
		digest->cd_length = 0;
		return (ret);
	}

	/*
	 * Do an MD5 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		MD5Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &md5_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_final_uio(&md5_ctx, digest,
		    MD5_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_final_mblk(&md5_ctx, digest,
		    MD5_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = MD5_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	return (ret);
}

/*
 * KCF software provider mac entry points.
 *
 * MD5 HMAC is: MD5(key XOR opad, MD5(key XOR ipad, text))
 *
 * Init:
 * The initialization routine initializes what we denote
 * as the inner and outer contexts by doing
 * - for inner context: MD5(key XOR ipad)
 * - for outer context: MD5(key XOR opad)
 *
 * Update:
 * Each subsequent MD5 HMAC update will result in an
 * update of the inner context with the specified data.
 *
 * Final:
 * The MD5 HMAC final will do a MD5 final operation on the
 * inner context, and the resulting digest will be used
 * as the data for an update on the outer context. Last
 * but not least, an MD5 final on the outer context will
 * be performed to obtain the MD5 HMAC digest to return
 * to the user.
 */

/*
 * Initialize a MD5-HMAC context.
 */
static void
md5_mac_init_ctx(md5_hmac_ctx_t *ctx, void *keyval, uint_t length_in_bytes)
{
	uint32_t ipad[MD5_HMAC_INTS_PER_BLOCK];
	uint32_t opad[MD5_HMAC_INTS_PER_BLOCK];
	uint_t i;

	bzero(ipad, MD5_HMAC_BLOCK_SIZE);
	bzero(opad, MD5_HMAC_BLOCK_SIZE);

	bcopy(keyval, ipad, length_in_bytes);
	bcopy(keyval, opad, length_in_bytes);

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < MD5_HMAC_INTS_PER_BLOCK; i++) {
		ipad[i] ^= 0x36363636;
		opad[i] ^= 0x5c5c5c5c;
	}

	/* perform MD5 on ipad */
	MD5Init(&ctx->hc_icontext);
	MD5Update(&ctx->hc_icontext, ipad, MD5_HMAC_BLOCK_SIZE);

	/* perform MD5 on opad */
	MD5Init(&ctx->hc_ocontext);
	MD5Update(&ctx->hc_ocontext, opad, MD5_HMAC_BLOCK_SIZE);
}

/*
 * Initializes a multi-part MAC operation.
 */
static int
md5_mac_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if (mechanism->cm_type != MD5_HMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != MD5_HMAC_GEN_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	ctx->cc_provider_private = kmem_alloc(sizeof (md5_hmac_ctx_t),
	    crypto_kmflag(req));
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_HOST_MEMORY);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, PROV_MD5_HMAC_CTX(ctx),
		    sizeof (md5_hmac_ctx_t));
	} else {
		/* no context template, compute context */
		if (keylen_in_bytes > MD5_HMAC_BLOCK_SIZE) {
			uchar_t digested_key[MD5_DIGEST_LENGTH];
			md5_hmac_ctx_t *hmac_ctx = ctx->cc_provider_private;

			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_MD5_DIGEST_KEY(&hmac_ctx->hc_icontext,
			    key->ck_data, keylen_in_bytes, digested_key);
			md5_mac_init_ctx(PROV_MD5_HMAC_CTX(ctx),
			    digested_key, MD5_DIGEST_LENGTH);
		} else {
			md5_mac_init_ctx(PROV_MD5_HMAC_CTX(ctx),
			    key->ck_data, keylen_in_bytes);
		}
	}

	/*
	 * Get the mechanism parameters, if applicable.
	 */
	PROV_MD5_HMAC_CTX(ctx)->hc_mech_type = mechanism->cm_type;
	if (mechanism->cm_type == MD5_HMAC_GEN_MECH_INFO_TYPE) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t))
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
		PROV_MD5_GET_DIGEST_LEN(mechanism,
		    PROV_MD5_HMAC_CTX(ctx)->hc_digest_len);
		if (PROV_MD5_HMAC_CTX(ctx)->hc_digest_len >
		    MD5_DIGEST_LENGTH)
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
	}

	if (ret != CRYPTO_SUCCESS) {
		bzero(ctx->cc_provider_private, sizeof (md5_hmac_ctx_t));
		kmem_free(ctx->cc_provider_private, sizeof (md5_hmac_ctx_t));
		ctx->cc_provider_private = NULL;
	}

	return (ret);
}


/* ARGSUSED */
static int
md5_mac_update(crypto_ctx_t *ctx, crypto_data_t *data, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * Do an MD5 update of the inner context using the specified
	 * data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		MD5Update(&PROV_MD5_HMAC_CTX(ctx)->hc_icontext,
		    data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_update_uio(
		    &PROV_MD5_HMAC_CTX(ctx)->hc_icontext, data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_update_mblk(
		    &PROV_MD5_HMAC_CTX(ctx)->hc_icontext, data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/* ARGSUSED */
static int
md5_mac_final(crypto_ctx_t *ctx, crypto_data_t *mac, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[MD5_DIGEST_LENGTH];
	uint32_t digest_len = MD5_DIGEST_LENGTH;

	ASSERT(ctx->cc_provider_private != NULL);

	if (PROV_MD5_HMAC_CTX(ctx)->hc_mech_type == MD5_HMAC_GEN_MECH_INFO_TYPE)
	    digest_len = PROV_MD5_HMAC_CTX(ctx)->hc_digest_len;

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((mac->cd_length == 0) || (mac->cd_length < digest_len)) {
		mac->cd_length = digest_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an MD5 final on the inner context.
	 */
	MD5Final(digest, &PROV_MD5_HMAC_CTX(ctx)->hc_icontext);

	/*
	 * Do an MD5 update on the outer context, feeding the inner
	 * digest as data.
	 */
	MD5Update(&PROV_MD5_HMAC_CTX(ctx)->hc_ocontext, digest,
	    MD5_DIGEST_LENGTH);

	/*
	 * Do an MD5 final on the outer context, storing the computing
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != MD5_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			MD5Final(digest,
			    &PROV_MD5_HMAC_CTX(ctx)->hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			MD5Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset,
			    &PROV_MD5_HMAC_CTX(ctx)->hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_final_uio(
		    &PROV_MD5_HMAC_CTX(ctx)->hc_ocontext, mac,
		    digest_len, digest);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_final_mblk(
		    &PROV_MD5_HMAC_CTX(ctx)->hc_ocontext, mac,
		    digest_len, digest);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		mac->cd_length = digest_len;
	} else {
		mac->cd_length = 0;
	}

	bzero(ctx->cc_provider_private, sizeof (md5_hmac_ctx_t));
	kmem_free(ctx->cc_provider_private, sizeof (md5_hmac_ctx_t));
	ctx->cc_provider_private = NULL;

	return (ret);
}

#define	MD5_MAC_UPDATE(data, ctx, ret) {				\
	switch (data->cd_format) {					\
	case CRYPTO_DATA_RAW:						\
		MD5Update(&(ctx).hc_icontext,				\
		    data->cd_raw.iov_base + data->cd_offset,		\
		    data->cd_length);					\
		break;							\
	case CRYPTO_DATA_UIO:						\
		ret = md5_digest_update_uio(&(ctx).hc_icontext,	data);	\
		break;							\
	case CRYPTO_DATA_MBLK:						\
		ret = md5_digest_update_mblk(&(ctx).hc_icontext,	\
		    data);						\
		break;							\
	default:							\
		ret = CRYPTO_ARGUMENTS_BAD;				\
	}								\
}


/* ARGSUSED */
static int
md5_mac_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[MD5_DIGEST_LENGTH];
	md5_hmac_ctx_t md5_hmac_ctx;
	uint32_t digest_len = MD5_DIGEST_LENGTH;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if (mechanism->cm_type != MD5_HMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != MD5_HMAC_GEN_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, &md5_hmac_ctx, sizeof (md5_hmac_ctx_t));
	} else {
		/* no context template, compute context */
		if (keylen_in_bytes > MD5_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_MD5_DIGEST_KEY(&md5_hmac_ctx.hc_icontext,
			    key->ck_data, keylen_in_bytes, digest);
			md5_mac_init_ctx(&md5_hmac_ctx, digest,
			    MD5_DIGEST_LENGTH);
		} else {
			md5_mac_init_ctx(&md5_hmac_ctx, key->ck_data,
			    keylen_in_bytes);
		}
	}

	/*
	 * Get the mechanism parameters, if applicable.
	 */
	if (mechanism->cm_type == MD5_HMAC_GEN_MECH_INFO_TYPE) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t)) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
		PROV_MD5_GET_DIGEST_LEN(mechanism, digest_len);
		if (digest_len > MD5_DIGEST_LENGTH) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
	}

	/* do an MD5 update of the inner context using the specified data */
	MD5_MAC_UPDATE(data, md5_hmac_ctx, ret);
	if (ret != CRYPTO_SUCCESS)
		/* the update failed, free context and bail */
		goto bail;

	/* do an MD5 final on the inner context */
	MD5Final(digest, &md5_hmac_ctx.hc_icontext);

	/*
	 * Do an MD5 update on the outer context, feeding the inner
	 * digest as data.
	 */
	MD5Update(&md5_hmac_ctx.hc_ocontext, digest, MD5_DIGEST_LENGTH);

	/*
	 * Do an MD5 final on the outer context, storing the computed
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != MD5_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			MD5Final(digest, &md5_hmac_ctx.hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			MD5Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, &md5_hmac_ctx.hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = md5_digest_final_uio(&md5_hmac_ctx.hc_ocontext, mac,
		    digest_len, digest);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md5_digest_final_mblk(&md5_hmac_ctx.hc_ocontext, mac,
		    digest_len, digest);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		mac->cd_length = digest_len;
	} else {
		mac->cd_length = 0;
	}
	/* Extra paranoia: zeroizing the local context on the stack */
	bzero(&md5_hmac_ctx, sizeof (md5_hmac_ctx_t));

	return (ret);
bail:
	bzero(&md5_hmac_ctx, sizeof (md5_hmac_ctx_t));
	mac->cd_length = 0;
	return (ret);
}

/* ARGSUSED */
static int
md5_mac_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[MD5_DIGEST_LENGTH];
	md5_hmac_ctx_t md5_hmac_ctx;
	uint32_t digest_len = MD5_DIGEST_LENGTH;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if (mechanism->cm_type != MD5_HMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != MD5_HMAC_GEN_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, &md5_hmac_ctx, sizeof (md5_hmac_ctx_t));
	} else {
		/* no context template, compute context */
		if (keylen_in_bytes > MD5_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_MD5_DIGEST_KEY(&md5_hmac_ctx.hc_icontext,
			    key->ck_data, keylen_in_bytes, digest);
			md5_mac_init_ctx(&md5_hmac_ctx, digest,
			    MD5_DIGEST_LENGTH);
		} else {
			md5_mac_init_ctx(&md5_hmac_ctx, key->ck_data,
			    keylen_in_bytes);
		}
	}

	/*
	 * Get the mechanism parameters, if applicable.
	 */
	if (mechanism->cm_type == MD5_HMAC_GEN_MECH_INFO_TYPE) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t)) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
		PROV_MD5_GET_DIGEST_LEN(mechanism, digest_len);
		if (digest_len > MD5_DIGEST_LENGTH) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
	}

	if (mac->cd_length != digest_len) {
		ret = CRYPTO_INVALID_MAC;
		goto bail;
	}

	/* do an MD5 update of the inner context using the specified data */
	MD5_MAC_UPDATE(data, md5_hmac_ctx, ret);
	if (ret != CRYPTO_SUCCESS)
		/* the update failed, free context and bail */
		goto bail;

	/* do an MD5 final on the inner context */
	MD5Final(digest, &md5_hmac_ctx.hc_icontext);

	/*
	 * Do an MD5 update on the outer context, feeding the inner
	 * digest as data.
	 */
	MD5Update(&md5_hmac_ctx.hc_ocontext, digest, MD5_DIGEST_LENGTH);

	/*
	 * Do an MD5 final on the outer context, storing the computed
	 * digest in the local digest buffer.
	 */
	MD5Final(digest, &md5_hmac_ctx.hc_ocontext);

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

	bzero(&md5_hmac_ctx, sizeof (md5_hmac_ctx_t));
	return (ret);
bail:
	bzero(&md5_hmac_ctx, sizeof (md5_hmac_ctx_t));
	mac->cd_length = 0;
	return (ret);
}

/*
 * KCF software provider context management entry points.
 */

/* ARGSUSED */
static int
md5_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *ctx_template, size_t *ctx_template_size,
    crypto_req_handle_t req)
{
	md5_hmac_ctx_t *md5_hmac_ctx_tmpl;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if ((mechanism->cm_type != MD5_HMAC_MECH_INFO_TYPE) &&
	    (mechanism->cm_type != MD5_HMAC_GEN_MECH_INFO_TYPE))
		return (CRYPTO_MECHANISM_INVALID);

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Allocate and initialize MD5 context.
	 */
	md5_hmac_ctx_tmpl = kmem_alloc(sizeof (md5_hmac_ctx_t),
	    crypto_kmflag(req));
	if (md5_hmac_ctx_tmpl == NULL)
		return (CRYPTO_HOST_MEMORY);

	if (keylen_in_bytes > MD5_HMAC_BLOCK_SIZE) {
		uchar_t digested_key[MD5_DIGEST_LENGTH];

		/*
		 * Hash the passed-in key to get a smaller key.
		 * The inner context is used since it hasn't been
		 * initialized yet.
		 */
		PROV_MD5_DIGEST_KEY(&md5_hmac_ctx_tmpl->hc_icontext,
		    key->ck_data, keylen_in_bytes, digested_key);
		md5_mac_init_ctx(md5_hmac_ctx_tmpl, digested_key,
		    MD5_DIGEST_LENGTH);
	} else {
		md5_mac_init_ctx(md5_hmac_ctx_tmpl, key->ck_data,
		    keylen_in_bytes);
	}

	md5_hmac_ctx_tmpl->hc_mech_type = mechanism->cm_type;
	*ctx_template = (crypto_spi_ctx_template_t)md5_hmac_ctx_tmpl;
	*ctx_template_size = sizeof (md5_hmac_ctx_t);

	return (CRYPTO_SUCCESS);
}

static int
md5_free_context(crypto_ctx_t *ctx)
{
	uint_t ctx_len;
	md5_mech_type_t mech_type;

	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_SUCCESS);

	/*
	 * We have to free either MD5 or MD5-HMAC contexts, which
	 * have different lengths.
	 */

	mech_type = PROV_MD5_CTX(ctx)->mc_mech_type;
	if (mech_type == MD5_MECH_INFO_TYPE)
		ctx_len = sizeof (md5_ctx_t);
	else {
		ASSERT(mech_type == MD5_HMAC_MECH_INFO_TYPE ||
		    mech_type == MD5_HMAC_GEN_MECH_INFO_TYPE);
		ctx_len = sizeof (md5_hmac_ctx_t);
	}

	bzero(ctx->cc_provider_private, ctx_len);
	kmem_free(ctx->cc_provider_private, ctx_len);
	ctx->cc_provider_private = NULL;

	return (CRYPTO_SUCCESS);
}

#endif	/* _KERNEL && !_BOOT */
