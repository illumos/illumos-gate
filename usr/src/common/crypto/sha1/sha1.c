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
 * NOTE: Cleaned-up and optimized, version of SHA1, based on the FIPS 180-1
 * standard, available at http://www.itl.nist.gov/div897/pubs/fip180-1.htm
 * Not as fast as one would like -- further optimizations are encouraged
 * and appreciated.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sha1.h>
#include <sys/sha1_consts.h>

#ifdef _KERNEL

#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/strsun.h>

/*
 * The sha1 module is created with two modlinkages:
 * - a modlmisc that allows consumers to directly call the entry points
 *   SHA1Init, SHA1Update, and SHA1Final.
 * - a modlcrypto that allows the module to register with the Kernel
 *   Cryptographic Framework (KCF) as a software provider for the SHA1
 *   mechanisms.
 */

#endif /* _KERNEL */
#ifndef	_KERNEL
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/systeminfo.h>
#endif	/* !_KERNEL */

static void Encode(uint8_t *, uint32_t *, size_t);
static void SHA1Transform(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
    SHA1_CTX *, const uint8_t *);

static uint8_t PADDING[64] = { 0x80, /* all zeros */ };

/*
 * F, G, and H are the basic SHA1 functions.
 */
#define	F(b, c, d)	(((b) & (c)) | ((~b) & (d)))
#define	G(b, c, d)	((b) ^ (c) ^ (d))
#define	H(b, c, d)	(((b) & (c)) | ((b) & (d)) | ((c) & (d)))

/*
 * ROTATE_LEFT rotates x left n bits.
 */
#define	ROTATE_LEFT(x, n)	\
	(((x) << (n)) | ((x) >> ((sizeof (x) * NBBY)-(n))))

#ifdef _KERNEL

static struct modlmisc modlmisc = {
	&mod_miscops,
	"SHA1 Message-Digest Algorithm"
};

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"SHA1 Kernel SW Provider %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, &modlcrypto, NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */

typedef enum sha1_mech_type {
	SHA1_MECH_INFO_TYPE,		/* SUN_CKM_SHA1 */
	SHA1_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA1_HMAC */
	SHA1_HMAC_GEN_MECH_INFO_TYPE	/* SUN_CKM_SHA1_HMAC_GENERAL */
} sha1_mech_type_t;

#define	SHA1_DIGEST_LENGTH	20	/* SHA1 digest length in bytes */
#define	SHA1_HMAC_BLOCK_SIZE	64	/* SHA1-HMAC block size */
#define	SHA1_HMAC_MIN_KEY_LEN	8	/* SHA1-HMAC min key length in bits */
#define	SHA1_HMAC_MAX_KEY_LEN	INT_MAX /* SHA1-HMAC max key length in bits */
#define	SHA1_HMAC_INTS_PER_BLOCK	(SHA1_HMAC_BLOCK_SIZE/sizeof (uint32_t))

/*
 * Context for SHA1 mechanism.
 */
typedef struct sha1_ctx {
	sha1_mech_type_t	sc_mech_type;	/* type of context */
	SHA1_CTX		sc_sha1_ctx;	/* SHA1 context */
} sha1_ctx_t;

/*
 * Context for SHA1-HMAC and SHA1-HMAC-GENERAL mechanisms.
 */
typedef struct sha1_hmac_ctx {
	sha1_mech_type_t	hc_mech_type;	/* type of context */
	uint32_t		hc_digest_len;	/* digest len in bytes */
	SHA1_CTX		hc_icontext;	/* inner SHA1 context */
	SHA1_CTX		hc_ocontext;	/* outer SHA1 context */
} sha1_hmac_ctx_t;

/*
 * Macros to access the SHA1 or SHA1-HMAC contexts from a context passed
 * by KCF to one of the entry points.
 */

#define	PROV_SHA1_CTX(ctx)	((sha1_ctx_t *)(ctx)->cc_provider_private)
#define	PROV_SHA1_HMAC_CTX(ctx)	((sha1_hmac_ctx_t *)(ctx)->cc_provider_private)

/* to extract the digest length passed as mechanism parameter */
#define	PROV_SHA1_GET_DIGEST_LEN(m, len) {				\
	if (IS_P2ALIGNED((m)->cm_param, sizeof (ulong_t)))		\
		(len) = (uint32_t)*((ulong_t *)mechanism->cm_param);	\
	else {								\
		ulong_t tmp_ulong;					\
		bcopy((m)->cm_param, &tmp_ulong, sizeof (ulong_t));	\
		(len) = (uint32_t)tmp_ulong;				\
	}								\
}

#define	PROV_SHA1_DIGEST_KEY(ctx, key, len, digest) {	\
	SHA1Init(ctx);					\
	SHA1Update(ctx, key, len);			\
	SHA1Final(digest, ctx);				\
}

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t sha1_mech_info_tab[] = {
	/* SHA1 */
	{SUN_CKM_SHA1, SHA1_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA1-HMAC */
	{SUN_CKM_SHA1_HMAC, SHA1_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA1_HMAC_MIN_KEY_LEN, SHA1_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA1-HMAC GENERAL */
	{SUN_CKM_SHA1_HMAC_GENERAL, SHA1_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SHA1_HMAC_MIN_KEY_LEN, SHA1_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

static void sha1_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t sha1_control_ops = {
	sha1_provider_status
};

static int sha1_digest_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_req_handle_t);
static int sha1_digest(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha1_digest_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha1_digest_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha1_digest_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

static crypto_digest_ops_t sha1_digest_ops = {
	sha1_digest_init,
	sha1_digest,
	sha1_digest_update,
	NULL,
	sha1_digest_final,
	sha1_digest_atomic
};

static int sha1_mac_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sha1_mac_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sha1_mac_final(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t);
static int sha1_mac_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sha1_mac_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_mac_ops_t sha1_mac_ops = {
	sha1_mac_init,
	NULL,
	sha1_mac_update,
	sha1_mac_final,
	sha1_mac_atomic,
	sha1_mac_verify_atomic
};

static int sha1_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int sha1_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t sha1_ctx_ops = {
	sha1_create_ctx_template,
	sha1_free_context
};

static crypto_ops_t sha1_crypto_ops = {
	&sha1_control_ops,
	&sha1_digest_ops,
	NULL,
	&sha1_mac_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&sha1_ctx_ops
};

static crypto_provider_info_t sha1_prov_info = {
	CRYPTO_SPI_VERSION_1,
	"SHA1 Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&sha1_crypto_ops,
	sizeof (sha1_mech_info_tab)/sizeof (crypto_mech_info_t),
	sha1_mech_info_tab
};

static crypto_kcf_provider_handle_t sha1_prov_handle = NULL;

int
_init()
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/*
	 * Register with KCF. If the registration fails, log an
	 * error but do not uninstall the module, since the functionality
	 * provided by misc/sha1 should still be available.
	 */
	if ((ret = crypto_register_provider(&sha1_prov_info,
	    &sha1_prov_handle)) != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "sha1 _init: "
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
 * SHA1Init()
 *
 * purpose: initializes the sha1 context and begins and sha1 digest operation
 *   input: SHA1_CTX *	: the context to initializes.
 *  output: void
 */

void
SHA1Init(SHA1_CTX *ctx)
{
	ctx->count[0] = ctx->count[1] = 0;

	/*
	 * load magic initialization constants. Tell lint
	 * that these constants are unsigned by using U.
	 */

	ctx->state[0] = 0x67452301U;
	ctx->state[1] = 0xefcdab89U;
	ctx->state[2] = 0x98badcfeU;
	ctx->state[3] = 0x10325476U;
	ctx->state[4] = 0xc3d2e1f0U;
}

#ifdef VIS_SHA1


#ifdef _KERNEL

#include <sys/regset.h>
#include <sys/vis.h>
#include <sys/fpu/fpusystm.h>

/* the alignment for block stores to save fp registers */
#define	VIS_ALIGN	(64)

extern int sha1_savefp(kfpu_t *, int);
extern void sha1_restorefp(kfpu_t *);

uint32_t	vis_sha1_svfp_threshold = 128;

#else /* !_KERNEL */

static boolean_t checked_vis = B_FALSE;
static int usevis = 0;

static int
havevis()
{
	char *buf = NULL;
	char *isa_token;
	char *lasts;
	int ret = 0;
	size_t bufsize = 255; /* UltraSPARC III needs 115 chars */
	int v9_isa_token, vis_isa_token, isa_token_num;

	if (checked_vis) {
		return (usevis);
	}

	if ((buf = malloc(bufsize)) == NULL) {
		return (0);
	}

	if ((ret = sysinfo(SI_ISALIST, buf, bufsize)) == -1) {
		free(buf);
		return (0);
	} else if (ret > bufsize) {
		/* We lost some because our buffer was too small  */
		if ((buf = realloc(buf, bufsize = ret)) == NULL) {
			return (0);
		}
		if ((ret = sysinfo(SI_ISALIST, buf, bufsize)) == -1) {
			free(buf);
			return (0);
		}
	}

	/*
	 * Check the relative posistions of sparcv9 & sparcv9+vis
	 * because they are listed in (best) performance order.
	 * For example: The Niagara chip reports it has VIS but the
	 * SHA1 code runs faster without this optimisation.
	 */
	isa_token = strtok_r(buf, " ", &lasts);
	v9_isa_token = vis_isa_token = -1;
	isa_token_num = 0;
	do {
		if (strcmp(isa_token, "sparcv9") == 0) {
			v9_isa_token = isa_token_num;
		} else if (strcmp(isa_token, "sparcv9+vis") == 0) {
			vis_isa_token = isa_token_num;
		}
		isa_token_num++;
	} while (isa_token = strtok_r(NULL, " ", &lasts));

	if (vis_isa_token != -1 && vis_isa_token < v9_isa_token)
		usevis = 1;
	free(buf);

	checked_vis = B_TRUE;
	return (usevis);
}

#endif /* _KERNEL */

/*
 * VIS SHA-1 consts.
 */
static uint64_t VIS[] = {
	0x8000000080000000ULL,
	0x0002000200020002ULL,
	0x5a8279996ed9eba1ULL,
	0x8f1bbcdcca62c1d6ULL,
	0x012389ab456789abULL};

extern void SHA1TransformVIS(uint64_t *, uint64_t *, uint32_t *, uint64_t *);


/*
 * SHA1Update()
 *
 * purpose: continues an sha1 digest operation, using the message block
 *          to update the context.
 *   input: SHA1_CTX *	: the context to update
 *          uint8_t *	: the message block
 *          uint32_t    : the length of the message block in bytes
 *  output: void
 */

void
SHA1Update(SHA1_CTX *ctx, const uint8_t *input, uint32_t input_len)
{
	uint32_t i, buf_index, buf_len;
	uint64_t X0[40], input64[8];
#ifdef _KERNEL
	int usevis = 0;
#endif /* _KERNEL */

	/* check for noop */
	if (input_len == 0)
		return;

	/* compute number of bytes mod 64 */
	buf_index = (ctx->count[1] >> 3) & 0x3F;

	/* update number of bits */
	if ((ctx->count[1] += (input_len << 3)) < (input_len << 3))
		ctx->count[0]++;

	ctx->count[0] += (input_len >> 29);

	buf_len = 64 - buf_index;

	/* transform as many times as possible */
	i = 0;
	if (input_len >= buf_len) {
#ifdef _KERNEL
		uint8_t fpua[sizeof (kfpu_t) + GSR_SIZE + VIS_ALIGN];
		kfpu_t *fpu;

		uint32_t len = (input_len + buf_index) & ~0x3f;
		int svfp_ok;

		fpu = (kfpu_t *)P2ROUNDUP((uintptr_t)fpua, 64);
		svfp_ok = ((len >= vis_sha1_svfp_threshold) ? 1 : 0);
		usevis = fpu_exists && sha1_savefp(fpu, svfp_ok);
#else
		if (!checked_vis)
			usevis = havevis();
#endif /* _KERNEL */

		/*
		 * general optimization:
		 *
		 * only do initial bcopy() and SHA1Transform() if
		 * buf_index != 0.  if buf_index == 0, we're just
		 * wasting our time doing the bcopy() since there
		 * wasn't any data left over from a previous call to
		 * SHA1Update().
		 */

		if (buf_index) {
			bcopy(input, &ctx->buf_un.buf8[buf_index], buf_len);
			if (usevis) {
				SHA1TransformVIS(X0,
				    (uint64_t *)ctx->buf_un.buf8,
				    &ctx->state[0], VIS);
			} else {
				SHA1Transform(ctx->state[0], ctx->state[1],
				    ctx->state[2], ctx->state[3],
				    ctx->state[4], ctx, ctx->buf_un.buf8);
			}
			i = buf_len;
		}

		/*
		 * VIS SHA-1: uses the VIS 1.0 instructions to accelerate
		 * SHA-1 processing. This is achieved by "offloading" the
		 * computation of the message schedule (MS) to the VIS units.
		 * This allows the VIS computation of the message schedule
		 * to be performed in parallel with the standard integer
		 * processing of the remainder of the SHA-1 computation.
		 * performance by up to around 1.37X, compared to an optimized
		 * integer-only implementation.
		 *
		 * The VIS implementation of SHA1Transform has a different API
		 * to the standard integer version:
		 *
		 * void SHA1TransformVIS(
		 *	 uint64_t *, // Pointer to MS for ith block
		 *	 uint64_t *, // Pointer to ith block of message data
		 *	 uint32_t *, // Pointer to SHA state i.e ctx->state
		 *	 uint64_t *, // Pointer to various VIS constants
		 * )
		 *
		 * Note: the message data must by 4-byte aligned.
		 *
		 * Function requires VIS 1.0 support.
		 *
		 * Handling is provided to deal with arbitrary byte alingment
		 * of the input data but the performance gains are reduced
		 * for alignments other than 4-bytes.
		 */
		if (usevis) {
			if (((uint64_t)(uintptr_t)(&input[i]) & 0x3)) {
				/*
				 * Main processing loop - input misaligned
				 */
				for (; i + 63 < input_len; i += 64) {
				    bcopy(&input[i], input64, 64);
				    SHA1TransformVIS(X0, input64,
					&ctx->state[0], VIS);
				}
			} else {
				/*
				 * Main processing loop - input 8-byte aligned
				 */
				for (; i + 63 < input_len; i += 64) {
					SHA1TransformVIS(X0,
					    (uint64_t *)&input[i],
					    &ctx->state[0], VIS);
				}

			}
#ifdef _KERNEL
			sha1_restorefp(fpu);
#endif /* _KERNEL */
		} else {
			for (; i + 63 < input_len; i += 64) {
			    SHA1Transform(ctx->state[0], ctx->state[1],
				ctx->state[2], ctx->state[3], ctx->state[4],
				ctx, &input[i]);
			}
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

#else /* VIS_SHA1 */

void
SHA1Update(SHA1_CTX *ctx, const uint8_t *input, uint32_t input_len)
{
	uint32_t i, buf_index, buf_len;

	/* check for noop */
	if (input_len == 0)
		return;

	/* compute number of bytes mod 64 */
	buf_index = (ctx->count[1] >> 3) & 0x3F;

	/* update number of bits */
	if ((ctx->count[1] += (input_len << 3)) < (input_len << 3))
		ctx->count[0]++;

	ctx->count[0] += (input_len >> 29);

	buf_len = 64 - buf_index;

	/* transform as many times as possible */
	i = 0;
	if (input_len >= buf_len) {

		/*
		 * general optimization:
		 *
		 * only do initial bcopy() and SHA1Transform() if
		 * buf_index != 0.  if buf_index == 0, we're just
		 * wasting our time doing the bcopy() since there
		 * wasn't any data left over from a previous call to
		 * SHA1Update().
		 */

		if (buf_index) {
			bcopy(input, &ctx->buf_un.buf8[buf_index], buf_len);


			SHA1Transform(ctx->state[0], ctx->state[1],
			    ctx->state[2], ctx->state[3], ctx->state[4], ctx,
			    ctx->buf_un.buf8);

			i = buf_len;
		}

		for (; i + 63 < input_len; i += 64)
			SHA1Transform(ctx->state[0], ctx->state[1],
			    ctx->state[2], ctx->state[3], ctx->state[4],
			    ctx, &input[i]);

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

#endif /* VIS_SHA1 */

/*
 * SHA1Final()
 *
 * purpose: ends an sha1 digest operation, finalizing the message digest and
 *          zeroing the context.
 *   input: uint8_t *	: a buffer to store the digest in
 *          SHA1_CTX *  : the context to finalize, save, and zero
 *  output: void
 */

void
SHA1Final(uint8_t *digest, SHA1_CTX *ctx)
{
	uint8_t		bitcount_be[sizeof (ctx->count)];
	uint32_t	index = (ctx->count[1] >> 3) & 0x3f;

	/* store bit count, big endian */
	Encode(bitcount_be, ctx->count, sizeof (bitcount_be));

	/* pad out to 56 mod 64 */
	SHA1Update(ctx, PADDING, ((index < 56) ? 56 : 120) - index);

	/* append length (before padding) */
	SHA1Update(ctx, bitcount_be, sizeof (bitcount_be));

	/* store state in digest */
	Encode(digest, ctx->state, sizeof (ctx->state));
}

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

/*
 * sparc register window optimization:
 *
 * `a', `b', `c', `d', and `e' are passed into SHA1Transform
 * explicitly since it increases the number of registers available to
 * the compiler.  under this scheme, these variables can be held in
 * %i0 - %i4, which leaves more local and out registers available.
 */

/*
 * SHA1Transform()
 *
 * purpose: sha1 transformation -- updates the digest based on `block'
 *   input: uint32_t	: bytes  1 -  4 of the digest
 *          uint32_t	: bytes  5 -  8 of the digest
 *          uint32_t	: bytes  9 - 12 of the digest
 *          uint32_t	: bytes 12 - 16 of the digest
 *          uint32_t	: bytes 16 - 20 of the digest
 *          SHA1_CTX *	: the context to update
 *          uint8_t [64]: the block to use to update the digest
 *  output: void
 */

void
SHA1Transform(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e,
    SHA1_CTX *ctx, const uint8_t blk[64])
{
	/*
	 * sparc optimization:
	 *
	 * while it is somewhat counter-intuitive, on sparc, it is
	 * more efficient to place all the constants used in this
	 * function in an array and load the values out of the array
	 * than to manually load the constants.  this is because
	 * setting a register to a 32-bit value takes two ops in most
	 * cases: a `sethi' and an `or', but loading a 32-bit value
	 * from memory only takes one `ld' (or `lduw' on v9).  while
	 * this increases memory usage, the compiler can find enough
	 * other things to do while waiting to keep the pipeline does
	 * not stall.  additionally, it is likely that many of these
	 * constants are cached so that later accesses do not even go
	 * out to the bus.
	 *
	 * this array is declared `static' to keep the compiler from
	 * having to bcopy() this array onto the stack frame of
	 * SHA1Transform() each time it is called -- which is
	 * unacceptably expensive.
	 *
	 * the `const' is to ensure that callers are good citizens and
	 * do not try to munge the array.  since these routines are
	 * going to be called from inside multithreaded kernelland,
	 * this is a good safety check. -- `sha1_consts' will end up in
	 * .rodata.
	 *
	 * unfortunately, loading from an array in this manner hurts
	 * performance under intel.  so, there is a macro,
	 * SHA1_CONST(), used in SHA1Transform(), that either expands to
	 * a reference to this array, or to the actual constant,
	 * depending on what platform this code is compiled for.
	 */

#if	defined(__sparc)
	static const uint32_t sha1_consts[] = {
		SHA1_CONST_0,	SHA1_CONST_1,	SHA1_CONST_2,	SHA1_CONST_3,
	};
#endif

	/*
	 * general optimization:
	 *
	 * use individual integers instead of using an array.  this is a
	 * win, although the amount it wins by seems to vary quite a bit.
	 */

	uint32_t	w_0, w_1, w_2,  w_3,  w_4,  w_5,  w_6,  w_7;
	uint32_t	w_8, w_9, w_10, w_11, w_12, w_13, w_14, w_15;

	/*
	 * sparc optimization:
	 *
	 * if `block' is already aligned on a 4-byte boundary, use
	 * LOAD_BIG_32() directly.  otherwise, bcopy() into a
	 * buffer that *is* aligned on a 4-byte boundary and then do
	 * the LOAD_BIG_32() on that buffer.  benchmarks have shown
	 * that using the bcopy() is better than loading the bytes
	 * individually and doing the endian-swap by hand.
	 *
	 * even though it's quite tempting to assign to do:
	 *
	 * blk = bcopy(ctx->buf_un.buf32, blk, sizeof (ctx->buf_un.buf32));
	 *
	 * and only have one set of LOAD_BIG_32()'s, the compiler
	 * *does not* like that, so please resist the urge.
	 */

#if	defined(__sparc)
	if ((uintptr_t)blk & 0x3) {		/* not 4-byte aligned? */
		bcopy(blk, ctx->buf_un.buf32,  sizeof (ctx->buf_un.buf32));
		w_15 = LOAD_BIG_32(ctx->buf_un.buf32 + 15);
		w_14 = LOAD_BIG_32(ctx->buf_un.buf32 + 14);
		w_13 = LOAD_BIG_32(ctx->buf_un.buf32 + 13);
		w_12 = LOAD_BIG_32(ctx->buf_un.buf32 + 12);
		w_11 = LOAD_BIG_32(ctx->buf_un.buf32 + 11);
		w_10 = LOAD_BIG_32(ctx->buf_un.buf32 + 10);
		w_9  = LOAD_BIG_32(ctx->buf_un.buf32 +  9);
		w_8  = LOAD_BIG_32(ctx->buf_un.buf32 +  8);
		w_7  = LOAD_BIG_32(ctx->buf_un.buf32 +  7);
		w_6  = LOAD_BIG_32(ctx->buf_un.buf32 +  6);
		w_5  = LOAD_BIG_32(ctx->buf_un.buf32 +  5);
		w_4  = LOAD_BIG_32(ctx->buf_un.buf32 +  4);
		w_3  = LOAD_BIG_32(ctx->buf_un.buf32 +  3);
		w_2  = LOAD_BIG_32(ctx->buf_un.buf32 +  2);
		w_1  = LOAD_BIG_32(ctx->buf_un.buf32 +  1);
		w_0  = LOAD_BIG_32(ctx->buf_un.buf32 +  0);
	} else {
		/*LINTED*/
		w_15 = LOAD_BIG_32(blk + 60);
		/*LINTED*/
		w_14 = LOAD_BIG_32(blk + 56);
		/*LINTED*/
		w_13 = LOAD_BIG_32(blk + 52);
		/*LINTED*/
		w_12 = LOAD_BIG_32(blk + 48);
		/*LINTED*/
		w_11 = LOAD_BIG_32(blk + 44);
		/*LINTED*/
		w_10 = LOAD_BIG_32(blk + 40);
		/*LINTED*/
		w_9  = LOAD_BIG_32(blk + 36);
		/*LINTED*/
		w_8  = LOAD_BIG_32(blk + 32);
		/*LINTED*/
		w_7  = LOAD_BIG_32(blk + 28);
		/*LINTED*/
		w_6  = LOAD_BIG_32(blk + 24);
		/*LINTED*/
		w_5  = LOAD_BIG_32(blk + 20);
		/*LINTED*/
		w_4  = LOAD_BIG_32(blk + 16);
		/*LINTED*/
		w_3  = LOAD_BIG_32(blk + 12);
		/*LINTED*/
		w_2  = LOAD_BIG_32(blk +  8);
		/*LINTED*/
		w_1  = LOAD_BIG_32(blk +  4);
		/*LINTED*/
		w_0  = LOAD_BIG_32(blk +  0);
	}
#else
	w_15 = LOAD_BIG_32(blk + 60);
	w_14 = LOAD_BIG_32(blk + 56);
	w_13 = LOAD_BIG_32(blk + 52);
	w_12 = LOAD_BIG_32(blk + 48);
	w_11 = LOAD_BIG_32(blk + 44);
	w_10 = LOAD_BIG_32(blk + 40);
	w_9  = LOAD_BIG_32(blk + 36);
	w_8  = LOAD_BIG_32(blk + 32);
	w_7  = LOAD_BIG_32(blk + 28);
	w_6  = LOAD_BIG_32(blk + 24);
	w_5  = LOAD_BIG_32(blk + 20);
	w_4  = LOAD_BIG_32(blk + 16);
	w_3  = LOAD_BIG_32(blk + 12);
	w_2  = LOAD_BIG_32(blk +  8);
	w_1  = LOAD_BIG_32(blk +  4);
	w_0  = LOAD_BIG_32(blk +  0);
#endif
	/*
	 * general optimization:
	 *
	 * even though this approach is described in the standard as
	 * being slower algorithmically, it is 30-40% faster than the
	 * "faster" version under SPARC, because this version has more
	 * of the constraints specified at compile-time and uses fewer
	 * variables (and therefore has better register utilization)
	 * than its "speedier" brother.  (i've tried both, trust me)
	 *
	 * for either method given in the spec, there is an "assignment"
	 * phase where the following takes place:
	 *
	 *	tmp = (main_computation);
	 *	e = d; d = c; c = rotate_left(b, 30); b = a; a = tmp;
	 *
	 * we can make the algorithm go faster by not doing this work,
	 * but just pretending that `d' is now `e', etc. this works
	 * really well and obviates the need for a temporary variable.
	 * however, we still explictly perform the rotate action,
	 * since it is cheaper on SPARC to do it once than to have to
	 * do it over and over again.
	 */

	/* round 1 */
	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_0 + SHA1_CONST(0); /* 0 */
	b = ROTATE_LEFT(b, 30);

	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_1 + SHA1_CONST(0); /* 1 */
	a = ROTATE_LEFT(a, 30);

	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_2 + SHA1_CONST(0); /* 2 */
	e = ROTATE_LEFT(e, 30);

	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_3 + SHA1_CONST(0); /* 3 */
	d = ROTATE_LEFT(d, 30);

	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_4 + SHA1_CONST(0); /* 4 */
	c = ROTATE_LEFT(c, 30);

	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_5 + SHA1_CONST(0); /* 5 */
	b = ROTATE_LEFT(b, 30);

	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_6 + SHA1_CONST(0); /* 6 */
	a = ROTATE_LEFT(a, 30);

	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_7 + SHA1_CONST(0); /* 7 */
	e = ROTATE_LEFT(e, 30);

	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_8 + SHA1_CONST(0); /* 8 */
	d = ROTATE_LEFT(d, 30);

	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_9 + SHA1_CONST(0); /* 9 */
	c = ROTATE_LEFT(c, 30);

	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_10 + SHA1_CONST(0); /* 10 */
	b = ROTATE_LEFT(b, 30);

	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_11 + SHA1_CONST(0); /* 11 */
	a = ROTATE_LEFT(a, 30);

	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_12 + SHA1_CONST(0); /* 12 */
	e = ROTATE_LEFT(e, 30);

	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_13 + SHA1_CONST(0); /* 13 */
	d = ROTATE_LEFT(d, 30);

	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_14 + SHA1_CONST(0); /* 14 */
	c = ROTATE_LEFT(c, 30);

	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_15 + SHA1_CONST(0); /* 15 */
	b = ROTATE_LEFT(b, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 16 */
	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_0 + SHA1_CONST(0);
	a = ROTATE_LEFT(a, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 17 */
	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_1 + SHA1_CONST(0);
	e = ROTATE_LEFT(e, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 18 */
	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_2 + SHA1_CONST(0);
	d = ROTATE_LEFT(d, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 19 */
	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_3 + SHA1_CONST(0);
	c = ROTATE_LEFT(c, 30);

	/* round 2 */
	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 20 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_4 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 21 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_5 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 22 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_6 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 23 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_7 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 24 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_8 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 25 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_9 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 26 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_10 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 27 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_11 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 28 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_12 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 29 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_13 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 30 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_14 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 31 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_15 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 32 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_0 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 33 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_1 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 34 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_2 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 35 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_3 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 36 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_4 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 37 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_5 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 38 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_6 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 39 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_7 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	/* round 3 */
	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 40 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_8 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 41 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_9 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 42 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_10 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 43 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_11 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 44 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_12 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 45 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_13 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 46 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_14 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 47 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_15 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 48 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_0 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 49 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_1 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 50 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_2 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 51 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_3 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 52 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_4 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 53 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_5 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 54 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_6 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 55 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_7 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 56 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_8 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 57 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_9 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 58 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_10 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 59 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_11 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	/* round 4 */
	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 60 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_12 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 61 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_13 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 62 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_14 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 63 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_15 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 64 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_0 + SHA1_CONST(3);
	c = ROTATE_LEFT(c, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 65 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_1 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 66 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_2 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 67 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_3 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 68 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_4 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 69 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_5 + SHA1_CONST(3);
	c = ROTATE_LEFT(c, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 70 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_6 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 71 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_7 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 72 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_8 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 73 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_9 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 74 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_10 + SHA1_CONST(3);
	c = ROTATE_LEFT(c, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 75 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_11 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 76 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_12 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 77 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_13 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 78 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_14 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 79 */

	ctx->state[0] += ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_15 +
	    SHA1_CONST(3);
	ctx->state[1] += b;
	ctx->state[2] += ROTATE_LEFT(c, 30);
	ctx->state[3] += d;
	ctx->state[4] += e;

	/* zeroize sensitive information */
	w_0 = w_1 = w_2 = w_3 = w_4 = w_5 = w_6 = w_7 = w_8 = 0;
	w_9 = w_10 = w_11 = w_12 = w_13 = w_14 = w_15 = 0;
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


#ifdef _KERNEL

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
sha1_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF software provider digest entry points.
 */

static int
sha1_digest_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_req_handle_t req)
{
	if (mechanism->cm_type != SHA1_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/*
	 * Allocate and initialize SHA1 context.
	 */
	ctx->cc_provider_private = kmem_alloc(sizeof (sha1_ctx_t),
	    crypto_kmflag(req));
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_HOST_MEMORY);

	PROV_SHA1_CTX(ctx)->sc_mech_type = SHA1_MECH_INFO_TYPE;
	SHA1Init(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx);

	return (CRYPTO_SUCCESS);
}

/*
 * Helper SHA1 digest update function for uio data.
 */
static int
sha1_digest_update_uio(SHA1_CTX *sha1_ctx, crypto_data_t *data)
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

		SHA1Update(sha1_ctx,
		    (uint8_t *)data->cd_uio->uio_iov[vec_idx].iov_base + offset,
		    cur_len);

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
 * Helper SHA1 digest final function for uio data.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default SHA1 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least SHA1_DIGEST_LENGTH bytes.
 */
static int
sha1_digest_final_uio(SHA1_CTX *sha1_ctx, crypto_data_t *digest,
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
		 * The computed SHA1 digest will fit in the current
		 * iovec.
		 */
		if (digest_len != SHA1_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA1Final(digest_scratch, sha1_ctx);
			bcopy(digest_scratch, (uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    digest_len);
		} else {
			SHA1Final((uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    sha1_ctx);
		}
	} else {
		/*
		 * The computed digest will be crossing one or more iovec's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[SHA1_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		SHA1Final(digest_tmp, sha1_ctx);

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
 * Helper SHA1 digest update for mblk's.
 */
static int
sha1_digest_update_mblk(SHA1_CTX *sha1_ctx, crypto_data_t *data)
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
		SHA1Update(sha1_ctx, mp->b_rptr + offset, cur_len);
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
 * Helper SHA1 digest final for mblk's.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default SHA1 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least SHA1_DIGEST_LENGTH bytes.
 */
static int
sha1_digest_final_mblk(SHA1_CTX *sha1_ctx, crypto_data_t *digest,
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
		 * The computed SHA1 digest will fit in the current mblk.
		 * Do the SHA1Final() in-place.
		 */
		if (digest_len != SHA1_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA1Final(digest_scratch, sha1_ctx);
			bcopy(digest_scratch, mp->b_rptr + offset, digest_len);
		} else {
			SHA1Final(mp->b_rptr + offset, sha1_ctx);
		}
	} else {
		/*
		 * The computed digest will be crossing one or more mblk's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[SHA1_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		SHA1Final(digest_tmp, sha1_ctx);

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
sha1_digest(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < SHA1_DIGEST_LENGTH)) {
		digest->cd_length = SHA1_DIGEST_LENGTH;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do the SHA1 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA1Update(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_update_uio(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_update_mblk(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret != CRYPTO_SUCCESS) {
		/* the update failed, free context and bail */
		kmem_free(ctx->cc_provider_private, sizeof (sha1_ctx_t));
		ctx->cc_provider_private = NULL;
		digest->cd_length = 0;
		return (ret);
	}

	/*
	 * Do a SHA1 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA1Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_SHA1_CTX(ctx)->sc_sha1_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_final_uio(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    digest, SHA1_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_final_mblk(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    digest, SHA1_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = SHA1_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (sha1_ctx_t));
	ctx->cc_provider_private = NULL;
	return (ret);
}

/* ARGSUSED */
static int
sha1_digest_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * Do the SHA1 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA1Update(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_update_uio(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_update_mblk(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/* ARGSUSED */
static int
sha1_digest_final(crypto_ctx_t *ctx, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < SHA1_DIGEST_LENGTH)) {
		digest->cd_length = SHA1_DIGEST_LENGTH;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do a SHA1 final.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA1Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_SHA1_CTX(ctx)->sc_sha1_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_final_uio(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    digest, SHA1_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_final_mblk(&PROV_SHA1_CTX(ctx)->sc_sha1_ctx,
		    digest, SHA1_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = SHA1_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (sha1_ctx_t));
	ctx->cc_provider_private = NULL;

	return (ret);
}

/* ARGSUSED */
static int
sha1_digest_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	SHA1_CTX sha1_ctx;

	if (mechanism->cm_type != SHA1_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/*
	 * Do the SHA1 init.
	 */
	SHA1Init(&sha1_ctx);

	/*
	 * Do the SHA1 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA1Update(&sha1_ctx,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_update_uio(&sha1_ctx, data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_update_mblk(&sha1_ctx, data);
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
	 * Do a SHA1 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA1Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &sha1_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_final_uio(&sha1_ctx, digest,
		    SHA1_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_final_mblk(&sha1_ctx, digest,
		    SHA1_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = SHA1_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	return (ret);
}

/*
 * KCF software provider mac entry points.
 *
 * SHA1 HMAC is: SHA1(key XOR opad, SHA1(key XOR ipad, text))
 *
 * Init:
 * The initialization routine initializes what we denote
 * as the inner and outer contexts by doing
 * - for inner context: SHA1(key XOR ipad)
 * - for outer context: SHA1(key XOR opad)
 *
 * Update:
 * Each subsequent SHA1 HMAC update will result in an
 * update of the inner context with the specified data.
 *
 * Final:
 * The SHA1 HMAC final will do a SHA1 final operation on the
 * inner context, and the resulting digest will be used
 * as the data for an update on the outer context. Last
 * but not least, a SHA1 final on the outer context will
 * be performed to obtain the SHA1 HMAC digest to return
 * to the user.
 */

/*
 * Initialize a SHA1-HMAC context.
 */
static void
sha1_mac_init_ctx(sha1_hmac_ctx_t *ctx, void *keyval, uint_t length_in_bytes)
{
	uint32_t ipad[SHA1_HMAC_INTS_PER_BLOCK];
	uint32_t opad[SHA1_HMAC_INTS_PER_BLOCK];
	uint_t i;

	bzero(ipad, SHA1_HMAC_BLOCK_SIZE);
	bzero(opad, SHA1_HMAC_BLOCK_SIZE);

	bcopy(keyval, ipad, length_in_bytes);
	bcopy(keyval, opad, length_in_bytes);

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < SHA1_HMAC_INTS_PER_BLOCK; i++) {
		ipad[i] ^= 0x36363636;
		opad[i] ^= 0x5c5c5c5c;
	}

	/* perform SHA1 on ipad */
	SHA1Init(&ctx->hc_icontext);
	SHA1Update(&ctx->hc_icontext, (uint8_t *)ipad, SHA1_HMAC_BLOCK_SIZE);

	/* perform SHA1 on opad */
	SHA1Init(&ctx->hc_ocontext);
	SHA1Update(&ctx->hc_ocontext, (uint8_t *)opad, SHA1_HMAC_BLOCK_SIZE);
}

/*
 */
static int
sha1_mac_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if (mechanism->cm_type != SHA1_HMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA1_HMAC_GEN_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	ctx->cc_provider_private = kmem_alloc(sizeof (sha1_hmac_ctx_t),
	    crypto_kmflag(req));
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_HOST_MEMORY);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, PROV_SHA1_HMAC_CTX(ctx),
		    sizeof (sha1_hmac_ctx_t));
	} else {
		/* no context template, compute context */
		if (keylen_in_bytes > SHA1_HMAC_BLOCK_SIZE) {
			uchar_t digested_key[SHA1_DIGEST_LENGTH];
			sha1_hmac_ctx_t *hmac_ctx = ctx->cc_provider_private;

			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_SHA1_DIGEST_KEY(&hmac_ctx->hc_icontext,
			    key->ck_data, keylen_in_bytes, digested_key);
			sha1_mac_init_ctx(PROV_SHA1_HMAC_CTX(ctx),
			    digested_key, SHA1_DIGEST_LENGTH);
		} else {
			sha1_mac_init_ctx(PROV_SHA1_HMAC_CTX(ctx),
			    key->ck_data, keylen_in_bytes);
		}
	}

	/*
	 * Get the mechanism parameters, if applicable.
	 */
	PROV_SHA1_HMAC_CTX(ctx)->hc_mech_type = mechanism->cm_type;
	if (mechanism->cm_type == SHA1_HMAC_GEN_MECH_INFO_TYPE) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t))
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
		PROV_SHA1_GET_DIGEST_LEN(mechanism,
		    PROV_SHA1_HMAC_CTX(ctx)->hc_digest_len);
		if (PROV_SHA1_HMAC_CTX(ctx)->hc_digest_len >
		    SHA1_DIGEST_LENGTH)
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
	}

	if (ret != CRYPTO_SUCCESS) {
		bzero(ctx->cc_provider_private, sizeof (sha1_hmac_ctx_t));
		kmem_free(ctx->cc_provider_private, sizeof (sha1_hmac_ctx_t));
		ctx->cc_provider_private = NULL;
	}

	return (ret);
}

/* ARGSUSED */
static int
sha1_mac_update(crypto_ctx_t *ctx, crypto_data_t *data, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * Do a SHA1 update of the inner context using the specified
	 * data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		SHA1Update(&PROV_SHA1_HMAC_CTX(ctx)->hc_icontext,
		    (uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_update_uio(
		    &PROV_SHA1_HMAC_CTX(ctx)->hc_icontext, data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_update_mblk(
		    &PROV_SHA1_HMAC_CTX(ctx)->hc_icontext, data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/* ARGSUSED */
static int
sha1_mac_final(crypto_ctx_t *ctx, crypto_data_t *mac, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[SHA1_DIGEST_LENGTH];
	uint32_t digest_len = SHA1_DIGEST_LENGTH;

	ASSERT(ctx->cc_provider_private != NULL);

	if (PROV_SHA1_HMAC_CTX(ctx)->hc_mech_type ==
	    SHA1_HMAC_GEN_MECH_INFO_TYPE)
		digest_len = PROV_SHA1_HMAC_CTX(ctx)->hc_digest_len;

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((mac->cd_length == 0) || (mac->cd_length < digest_len)) {
		mac->cd_length = digest_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do a SHA1 final on the inner context.
	 */
	SHA1Final(digest, &PROV_SHA1_HMAC_CTX(ctx)->hc_icontext);

	/*
	 * Do a SHA1 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA1Update(&PROV_SHA1_HMAC_CTX(ctx)->hc_ocontext, digest,
	    SHA1_DIGEST_LENGTH);

	/*
	 * Do a SHA1 final on the outer context, storing the computing
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != SHA1_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA1Final(digest,
			    &PROV_SHA1_HMAC_CTX(ctx)->hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			SHA1Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset,
			    &PROV_SHA1_HMAC_CTX(ctx)->hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_final_uio(
		    &PROV_SHA1_HMAC_CTX(ctx)->hc_ocontext, mac,
		    digest_len, digest);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_final_mblk(
		    &PROV_SHA1_HMAC_CTX(ctx)->hc_ocontext, mac,
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

	bzero(ctx->cc_provider_private, sizeof (sha1_hmac_ctx_t));
	kmem_free(ctx->cc_provider_private, sizeof (sha1_hmac_ctx_t));
	ctx->cc_provider_private = NULL;

	return (ret);
}

#define	SHA1_MAC_UPDATE(data, ctx, ret) {				\
	switch (data->cd_format) {					\
	case CRYPTO_DATA_RAW:						\
		SHA1Update(&(ctx).hc_icontext,				\
		    (uint8_t *)data->cd_raw.iov_base +			\
		    data->cd_offset, data->cd_length);			\
		break;							\
	case CRYPTO_DATA_UIO:						\
		ret = sha1_digest_update_uio(&(ctx).hc_icontext, data); \
		break;							\
	case CRYPTO_DATA_MBLK:						\
		ret = sha1_digest_update_mblk(&(ctx).hc_icontext,	\
		    data);						\
		break;							\
	default:							\
		ret = CRYPTO_ARGUMENTS_BAD;				\
	}								\
}

/* ARGSUSED */
static int
sha1_mac_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[SHA1_DIGEST_LENGTH];
	sha1_hmac_ctx_t sha1_hmac_ctx;
	uint32_t digest_len = SHA1_DIGEST_LENGTH;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if (mechanism->cm_type != SHA1_HMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA1_HMAC_GEN_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, &sha1_hmac_ctx, sizeof (sha1_hmac_ctx_t));
	} else {
		/* no context template, initialize context */
		if (keylen_in_bytes > SHA1_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_SHA1_DIGEST_KEY(&sha1_hmac_ctx.hc_icontext,
			    key->ck_data, keylen_in_bytes, digest);
			sha1_mac_init_ctx(&sha1_hmac_ctx, digest,
			    SHA1_DIGEST_LENGTH);
		} else {
			sha1_mac_init_ctx(&sha1_hmac_ctx, key->ck_data,
			    keylen_in_bytes);
		}
	}

	/* get the mechanism parameters, if applicable */
	if (mechanism->cm_type == SHA1_HMAC_GEN_MECH_INFO_TYPE) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t)) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
		PROV_SHA1_GET_DIGEST_LEN(mechanism, digest_len);
		if (digest_len > SHA1_DIGEST_LENGTH) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
	}

	/* do a SHA1 update of the inner context using the specified data */
	SHA1_MAC_UPDATE(data, sha1_hmac_ctx, ret);
	if (ret != CRYPTO_SUCCESS)
		/* the update failed, free context and bail */
		goto bail;

	/*
	 * Do a SHA1 final on the inner context.
	 */
	SHA1Final(digest, &sha1_hmac_ctx.hc_icontext);

	/*
	 * Do an SHA1 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA1Update(&sha1_hmac_ctx.hc_ocontext, digest, SHA1_DIGEST_LENGTH);

	/*
	 * Do a SHA1 final on the outer context, storing the computed
	 * digest in the users buffer.
	 */
	switch (mac->cd_format) {
	case CRYPTO_DATA_RAW:
		if (digest_len != SHA1_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			SHA1Final(digest, &sha1_hmac_ctx.hc_ocontext);
			bcopy(digest, (unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, digest_len);
		} else {
			SHA1Final((unsigned char *)mac->cd_raw.iov_base +
			    mac->cd_offset, &sha1_hmac_ctx.hc_ocontext);
		}
		break;
	case CRYPTO_DATA_UIO:
		ret = sha1_digest_final_uio(&sha1_hmac_ctx.hc_ocontext, mac,
		    digest_len, digest);
		break;
	case CRYPTO_DATA_MBLK:
		ret = sha1_digest_final_mblk(&sha1_hmac_ctx.hc_ocontext, mac,
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
	/* Extra paranoia: zeroize the context on the stack */
	bzero(&sha1_hmac_ctx, sizeof (sha1_hmac_ctx_t));

	return (ret);
bail:
	bzero(&sha1_hmac_ctx, sizeof (sha1_hmac_ctx_t));
	mac->cd_length = 0;
	return (ret);
}

/* ARGSUSED */
static int
sha1_mac_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	uchar_t digest[SHA1_DIGEST_LENGTH];
	sha1_hmac_ctx_t sha1_hmac_ctx;
	uint32_t digest_len = SHA1_DIGEST_LENGTH;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if (mechanism->cm_type != SHA1_HMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA1_HMAC_GEN_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	if (ctx_template != NULL) {
		/* reuse context template */
		bcopy(ctx_template, &sha1_hmac_ctx, sizeof (sha1_hmac_ctx_t));
	} else {
		/* no context template, initialize context */
		if (keylen_in_bytes > SHA1_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the passed-in key to get a smaller key.
			 * The inner context is used since it hasn't been
			 * initialized yet.
			 */
			PROV_SHA1_DIGEST_KEY(&sha1_hmac_ctx.hc_icontext,
			    key->ck_data, keylen_in_bytes, digest);
			sha1_mac_init_ctx(&sha1_hmac_ctx, digest,
			    SHA1_DIGEST_LENGTH);
		} else {
			sha1_mac_init_ctx(&sha1_hmac_ctx, key->ck_data,
			    keylen_in_bytes);
		}
	}

	/* get the mechanism parameters, if applicable */
	if (mechanism->cm_type == SHA1_HMAC_GEN_MECH_INFO_TYPE) {
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (ulong_t)) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
		PROV_SHA1_GET_DIGEST_LEN(mechanism, digest_len);
		if (digest_len > SHA1_DIGEST_LENGTH) {
			ret = CRYPTO_MECHANISM_PARAM_INVALID;
			goto bail;
		}
	}

	if (mac->cd_length != digest_len) {
		ret = CRYPTO_INVALID_MAC;
		goto bail;
	}

	/* do a SHA1 update of the inner context using the specified data */
	SHA1_MAC_UPDATE(data, sha1_hmac_ctx, ret);
	if (ret != CRYPTO_SUCCESS)
		/* the update failed, free context and bail */
		goto bail;

	/* do a SHA1 final on the inner context */
	SHA1Final(digest, &sha1_hmac_ctx.hc_icontext);

	/*
	 * Do an SHA1 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA1Update(&sha1_hmac_ctx.hc_ocontext, digest, SHA1_DIGEST_LENGTH);

	/*
	 * Do a SHA1 final on the outer context, storing the computed
	 * digest in the users buffer.
	 */
	SHA1Final(digest, &sha1_hmac_ctx.hc_ocontext);

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

	bzero(&sha1_hmac_ctx, sizeof (sha1_hmac_ctx_t));
	return (ret);
bail:
	bzero(&sha1_hmac_ctx, sizeof (sha1_hmac_ctx_t));
	mac->cd_length = 0;
	return (ret);
}

/*
 * KCF software provider context management entry points.
 */

/* ARGSUSED */
static int
sha1_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *ctx_template, size_t *ctx_template_size,
    crypto_req_handle_t req)
{
	sha1_hmac_ctx_t *sha1_hmac_ctx_tmpl;
	uint_t keylen_in_bytes = CRYPTO_BITS2BYTES(key->ck_length);

	if ((mechanism->cm_type != SHA1_HMAC_MECH_INFO_TYPE) &&
	    (mechanism->cm_type != SHA1_HMAC_GEN_MECH_INFO_TYPE)) {
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* Add support for key by attributes (RFE 4706552) */
	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Allocate and initialize SHA1 context.
	 */
	sha1_hmac_ctx_tmpl = kmem_alloc(sizeof (sha1_hmac_ctx_t),
	    crypto_kmflag(req));
	if (sha1_hmac_ctx_tmpl == NULL)
		return (CRYPTO_HOST_MEMORY);

	if (keylen_in_bytes > SHA1_HMAC_BLOCK_SIZE) {
		uchar_t digested_key[SHA1_DIGEST_LENGTH];

		/*
		 * Hash the passed-in key to get a smaller key.
		 * The inner context is used since it hasn't been
		 * initialized yet.
		 */
		PROV_SHA1_DIGEST_KEY(&sha1_hmac_ctx_tmpl->hc_icontext,
		    key->ck_data, keylen_in_bytes, digested_key);
		sha1_mac_init_ctx(sha1_hmac_ctx_tmpl, digested_key,
		    SHA1_DIGEST_LENGTH);
	} else {
		sha1_mac_init_ctx(sha1_hmac_ctx_tmpl, key->ck_data,
		    keylen_in_bytes);
	}

	sha1_hmac_ctx_tmpl->hc_mech_type = mechanism->cm_type;
	*ctx_template = (crypto_spi_ctx_template_t)sha1_hmac_ctx_tmpl;
	*ctx_template_size = sizeof (sha1_hmac_ctx_t);


	return (CRYPTO_SUCCESS);
}

static int
sha1_free_context(crypto_ctx_t *ctx)
{
	uint_t ctx_len;
	sha1_mech_type_t mech_type;

	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_SUCCESS);

	/*
	 * We have to free either SHA1 or SHA1-HMAC contexts, which
	 * have different lengths.
	 */

	mech_type = PROV_SHA1_CTX(ctx)->sc_mech_type;
	if (mech_type == SHA1_MECH_INFO_TYPE)
		ctx_len = sizeof (sha1_ctx_t);
	else {
		ASSERT(mech_type == SHA1_HMAC_MECH_INFO_TYPE ||
		    mech_type == SHA1_HMAC_GEN_MECH_INFO_TYPE);
		ctx_len = sizeof (sha1_hmac_ctx_t);
	}

	bzero(ctx->cc_provider_private, ctx_len);
	kmem_free(ctx->cc_provider_private, ctx_len);
	ctx->cc_provider_private = NULL;

	return (CRYPTO_SUCCESS);
}

#endif /* _KERNEL */
