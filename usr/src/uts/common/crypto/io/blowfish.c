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
 * Blowfish provider for the Kernel Cryptographic Framework (KCF)
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <sys/note.h>
#include <modes/modes.h>
#include <blowfish/blowfish_impl.h>

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"Blowfish Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */
typedef enum blowfish_mech_type {
	BLOWFISH_ECB_MECH_INFO_TYPE,		/* SUN_CKM_BLOWFISH_ECB */
	BLOWFISH_CBC_MECH_INFO_TYPE		/* SUN_CKM_BLOWFISH_CBC */
} blowfish_mech_type_t;


#define	BLOWFISH_COPY_BLOCK(src, dst) \
	(dst)[0] = (src)[0]; \
	(dst)[1] = (src)[1]; \
	(dst)[2] = (src)[2]; \
	(dst)[3] = (src)[3]; \
	(dst)[4] = (src)[4]; \
	(dst)[5] = (src)[5]; \
	(dst)[6] = (src)[6]; \
	(dst)[7] = (src)[7]

#define	BLOWFISH_XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]

/*
 * Mechanism info structure passed to KCF during registration.
 */

static crypto_mech_info_t blowfish_mech_info_tab[] = {
	/* BLOWFISH_ECB */
	{SUN_CKM_BLOWFISH_ECB, BLOWFISH_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    BLOWFISH_MINBITS, BLOWFISH_MAXBITS, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* BLOWFISH_CBC */
	{SUN_CKM_BLOWFISH_CBC, BLOWFISH_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    BLOWFISH_MINBITS, BLOWFISH_MAXBITS, CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

#define	BLOWFISH_VALID_MECH(mech)				\
	(((mech)->cm_type == BLOWFISH_ECB_MECH_INFO_TYPE ||		\
	(mech)->cm_type == BLOWFISH_CBC_MECH_INFO_TYPE) ? 1 : 0)

/* operations are in-place if the output buffer is NULL */
#define	BLOWFISH_ARG_INPLACE(input, output)			\
	if ((output) == NULL)					\
		(output) = (input);

static void blowfish_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t blowfish_control_ops = {
	blowfish_provider_status
};

static int blowfish_common_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int blowfish_common_init_ctx(blowfish_ctx_t *,
    crypto_spi_ctx_template_t *, crypto_mechanism_t *, crypto_key_t *, int);
static int blowfish_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int blowfish_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);

static int blowfish_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int blowfish_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int blowfish_encrypt_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int blowfish_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int blowfish_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int blowfish_decrypt_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_cipher_ops_t blowfish_cipher_ops = {
	blowfish_common_init,
	blowfish_encrypt,
	blowfish_encrypt_update,
	blowfish_encrypt_final,
	blowfish_encrypt_atomic,
	blowfish_common_init,
	blowfish_decrypt,
	blowfish_decrypt_update,
	blowfish_decrypt_final,
	blowfish_decrypt_atomic
};

static int blowfish_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int blowfish_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t blowfish_ctx_ops = {
	blowfish_create_ctx_template,
	blowfish_free_context
};

static crypto_ops_t blowfish_crypto_ops = {
	&blowfish_control_ops,
	NULL,
	&blowfish_cipher_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&blowfish_ctx_ops
};

static crypto_provider_info_t blowfish_prov_info = {
	CRYPTO_SPI_VERSION_1,
	"Blowfish Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&blowfish_crypto_ops,
	sizeof (blowfish_mech_info_tab)/sizeof (crypto_mech_info_t),
	blowfish_mech_info_tab
};


static crypto_kcf_provider_handle_t blowfish_prov_handle = 0;

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/* Register with KCF.  If the registration fails, remove the module. */
	if (crypto_register_provider(&blowfish_prov_info,
	    &blowfish_prov_handle)) {
		(void) mod_remove(&modlinkage);
		return (EACCES);
	}

	return (0);
}

int
_fini(void)
{
	/* Unregister from KCF if module is registered */
	if (blowfish_prov_handle != 0) {
		if (crypto_unregister_provider(blowfish_prov_handle))
			return (EBUSY);

		blowfish_prov_handle = 0;
	}

	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Initialize key schedules for blowfish
 */
static int
init_keysched(crypto_key_t *key, void *keysched)
{
	/*
	 * Only keys by value are supported by this module.
	 */
	switch (key->ck_format) {
	case CRYPTO_KEY_RAW:
		if (key->ck_length < BLOWFISH_MINBITS ||
		    key->ck_length > BLOWFISH_MAXBITS) {
			return (CRYPTO_KEY_SIZE_RANGE);
		}
		break;
	default:
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	blowfish_init_keysched(key->ck_data, key->ck_length, keysched);
	return (CRYPTO_SUCCESS);
}

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
blowfish_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF software provider encrypt entry points.
 */
static int
blowfish_common_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{
	blowfish_ctx_t *blowfish_ctx;
	int rv;
	int kmflag;

	/*
	 * Only keys by value are supported by this module.
	 */
	if (key->ck_format != CRYPTO_KEY_RAW) {
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	if (!BLOWFISH_VALID_MECH(mechanism))
		return (CRYPTO_MECHANISM_INVALID);

	if (mechanism->cm_param != NULL &&
	    mechanism->cm_param_len != BLOWFISH_BLOCK_LEN)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	kmflag = crypto_kmflag(req);
	switch (mechanism->cm_type) {
	case BLOWFISH_ECB_MECH_INFO_TYPE:
		blowfish_ctx = ecb_alloc_ctx(kmflag);
		break;
	case BLOWFISH_CBC_MECH_INFO_TYPE:
		blowfish_ctx = cbc_alloc_ctx(kmflag);
		break;
	}
	if (blowfish_ctx == NULL)
		return (CRYPTO_HOST_MEMORY);

	rv = blowfish_common_init_ctx(blowfish_ctx, template, mechanism,
	    key, kmflag);
	if (rv != CRYPTO_SUCCESS) {
		crypto_free_mode_ctx(blowfish_ctx);
		return (rv);
	}

	ctx->cc_provider_private = blowfish_ctx;

	return (CRYPTO_SUCCESS);
}

static void
blowfish_copy_block64(uint8_t *in, uint64_t *out)
{
	if (IS_P2ALIGNED(in, sizeof (uint64_t))) {
		/* LINTED: pointer alignment */
		out[0] = *(uint64_t *)&in[0];
	} else {
		uint8_t *iv8 = (uint8_t *)&out[0];

		BLOWFISH_COPY_BLOCK(in, iv8);
	}
}

/* ARGSUSED */
static int
blowfish_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int ret;

	blowfish_ctx_t *blowfish_ctx;

	/*
	 * Plaintext must be a multiple of blowfish block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((plaintext->cd_length & (BLOWFISH_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	ASSERT(ctx->cc_provider_private != NULL);
	blowfish_ctx = ctx->cc_provider_private;

	BLOWFISH_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	if (ciphertext->cd_length < plaintext->cd_length) {
		ciphertext->cd_length = plaintext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an update on the specified input data.
	 */
	ret = blowfish_encrypt_update(ctx, plaintext, ciphertext, req);
	ASSERT(blowfish_ctx->bc_remainder_len  == 0);
	(void) blowfish_free_context(ctx);

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
blowfish_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int ret;

	blowfish_ctx_t *blowfish_ctx;

	/*
	 * Ciphertext must be a multiple of blowfish block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((ciphertext->cd_length & (BLOWFISH_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);

	ASSERT(ctx->cc_provider_private != NULL);
	blowfish_ctx = ctx->cc_provider_private;

	BLOWFISH_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	if (plaintext->cd_length < ciphertext->cd_length) {
		plaintext->cd_length = ciphertext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an update on the specified input data.
	 */
	ret = blowfish_decrypt_update(ctx, ciphertext, plaintext, req);
	ASSERT(blowfish_ctx->bc_remainder_len == 0);
	(void) blowfish_free_context(ctx);

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
blowfish_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	BLOWFISH_ARG_INPLACE(plaintext, ciphertext);

	/* compute number of bytes that will hold the ciphertext */
	out_len =
	    ((blowfish_ctx_t *)ctx->cc_provider_private)->bc_remainder_len;
	out_len += plaintext->cd_length;
	out_len &= ~(BLOWFISH_BLOCK_LEN - 1);

	/* return length needed to store the output */
	if (ciphertext->cd_length < out_len) {
		ciphertext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do the blowfish update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (plaintext != ciphertext)
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

	return (ret);
}

/* ARGSUSED */
static int
blowfish_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	BLOWFISH_ARG_INPLACE(ciphertext, plaintext);

	/* compute number of bytes that will hold the plaintext */
	out_len =
	    ((blowfish_ctx_t *)ctx->cc_provider_private)->bc_remainder_len;
	out_len += ciphertext->cd_length;
	out_len &= ~(BLOWFISH_BLOCK_LEN - 1);

	/* return length needed to store the output */
	if (plaintext->cd_length < out_len) {
		plaintext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do the blowfish update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (ciphertext != plaintext)
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

	return (ret);
}

/* ARGSUSED */
static int
blowfish_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	blowfish_ctx_t *blowfish_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	blowfish_ctx = ctx->cc_provider_private;

	/*
	 * There must be no unprocessed data.
	 * This happens if the length of the last data is
	 * not a multiple of the BLOWFISH block length.
	 */
	if (blowfish_ctx->bc_remainder_len > 0)
		return (CRYPTO_DATA_LEN_RANGE);

	(void) blowfish_free_context(ctx);
	data->cd_length = 0;

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
blowfish_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	blowfish_ctx_t *blowfish_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	blowfish_ctx = ctx->cc_provider_private;

	/*
	 * There must be no unprocessed ciphertext.
	 * This happens if the length of the last ciphertext is
	 * not a multiple of the BLOWFISH block length.
	 */
	if (blowfish_ctx->bc_remainder_len > 0)
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);

	(void) blowfish_free_context(ctx);
	data->cd_length = 0;

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
blowfish_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	blowfish_ctx_t blowfish_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	int ret;

	BLOWFISH_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * Plaintext must be a multiple of blowfish block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((plaintext->cd_length & (BLOWFISH_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	/* return length needed to store the output */
	if (ciphertext->cd_length < plaintext->cd_length) {
		ciphertext->cd_length = plaintext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if (!BLOWFISH_VALID_MECH(mechanism))
		return (CRYPTO_MECHANISM_INVALID);

	if (mechanism->cm_param_len != 0 &&
	    mechanism->cm_param_len != BLOWFISH_BLOCK_LEN)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	bzero(&blowfish_ctx, sizeof (blowfish_ctx_t));

	ret = blowfish_common_init_ctx(&blowfish_ctx, template, mechanism,
	    key, crypto_kmflag(req));
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do an update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&blowfish_ctx,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&blowfish_ctx,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp((void *)&blowfish_ctx,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (blowfish_ctx.bc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(blowfish_ctx.bc_keysched, blowfish_ctx.bc_keysched_len);
		kmem_free(blowfish_ctx.bc_keysched,
		    blowfish_ctx.bc_keysched_len);
	}

	if (ret == CRYPTO_SUCCESS) {
		ASSERT(blowfish_ctx.bc_remainder_len == 0);
		if (plaintext != ciphertext)
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

	return (ret);
}

/* ARGSUSED */
static int
blowfish_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	blowfish_ctx_t blowfish_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	int ret;

	BLOWFISH_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * Ciphertext must be a multiple of blowfish block size.
	 * This test only works for non-padded mechanisms
	 * when blocksize is 2^N.
	 */
	if ((ciphertext->cd_length & (BLOWFISH_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	/* return length needed to store the output */
	if (plaintext->cd_length < ciphertext->cd_length) {
		plaintext->cd_length = ciphertext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if (!BLOWFISH_VALID_MECH(mechanism))
		return (CRYPTO_MECHANISM_INVALID);

	if (mechanism->cm_param_len != 0 &&
	    mechanism->cm_param_len != BLOWFISH_BLOCK_LEN)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	bzero(&blowfish_ctx, sizeof (blowfish_ctx_t));

	ret = blowfish_common_init_ctx(&blowfish_ctx, template, mechanism,
	    key, crypto_kmflag(req));
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do an update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&blowfish_ctx,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&blowfish_ctx,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(&blowfish_ctx,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks,
		    blowfish_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (blowfish_ctx.bc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(blowfish_ctx.bc_keysched, blowfish_ctx.bc_keysched_len);
		kmem_free(blowfish_ctx.bc_keysched,
		    blowfish_ctx.bc_keysched_len);
	}

	if (ret == CRYPTO_SUCCESS) {
		ASSERT(blowfish_ctx.bc_remainder_len == 0);
		if (ciphertext != plaintext)
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

	return (ret);
}

/*
 * KCF software provider context template entry points.
 */
/* ARGSUSED */
static int
blowfish_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *tmpl, size_t *tmpl_size, crypto_req_handle_t req)
{
	void *keysched;
	size_t size;
	int rv;

	if (!BLOWFISH_VALID_MECH(mechanism))
		return (CRYPTO_MECHANISM_INVALID);

	if ((keysched = blowfish_alloc_keysched(&size,
	    crypto_kmflag(req))) == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	/*
	 * Initialize key schedule.  Key length information is stored
	 * in the key.
	 */
	if ((rv = init_keysched(key, keysched)) != CRYPTO_SUCCESS) {
		bzero(keysched, size);
		kmem_free(keysched, size);
		return (rv);
	}

	*tmpl = keysched;
	*tmpl_size = size;

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
blowfish_free_context(crypto_ctx_t *ctx)
{
	blowfish_ctx_t *blowfish_ctx = ctx->cc_provider_private;

	if (blowfish_ctx != NULL) {
		if (blowfish_ctx->bc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(blowfish_ctx->bc_keysched_len != 0);
			bzero(blowfish_ctx->bc_keysched,
			    blowfish_ctx->bc_keysched_len);
			kmem_free(blowfish_ctx->bc_keysched,
			    blowfish_ctx->bc_keysched_len);
		}
		crypto_free_mode_ctx(blowfish_ctx);
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
blowfish_common_init_ctx(blowfish_ctx_t *blowfish_ctx,
    crypto_spi_ctx_template_t *template, crypto_mechanism_t *mechanism,
    crypto_key_t *key, int kmflag)
{
	int rv = CRYPTO_SUCCESS;

	void *keysched;
	size_t size;

	if (template == NULL) {
		if ((keysched = blowfish_alloc_keysched(&size, kmflag)) == NULL)
			return (CRYPTO_HOST_MEMORY);
		/*
		 * Initialize key schedule.
		 * Key length is stored in the key.
		 */
		if ((rv = init_keysched(key, keysched)) != CRYPTO_SUCCESS)
			kmem_free(keysched, size);

		blowfish_ctx->bc_flags |= PROVIDER_OWNS_KEY_SCHEDULE;
		blowfish_ctx->bc_keysched_len = size;
	} else {
		keysched = template;
	}
	blowfish_ctx->bc_keysched = keysched;

	switch (mechanism->cm_type) {
	case BLOWFISH_CBC_MECH_INFO_TYPE:
		rv = cbc_init_ctx((cbc_ctx_t *)blowfish_ctx,
		    mechanism->cm_param, mechanism->cm_param_len,
		    BLOWFISH_BLOCK_LEN, blowfish_copy_block64);
		break;
	case BLOWFISH_ECB_MECH_INFO_TYPE:
		blowfish_ctx->bc_flags |= ECB_MODE;
	}

	if (rv != CRYPTO_SUCCESS) {
		if (blowfish_ctx->bc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			bzero(keysched, size);
			kmem_free(keysched, size);
		}
	}

	return (rv);
}
