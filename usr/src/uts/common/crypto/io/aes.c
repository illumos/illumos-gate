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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * AES provider for the Kernel Cryptographic Framework (KCF)
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/spi.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <modes/modes.h>
#include <aes/aes_impl.h>

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"AES Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */
typedef enum aes_mech_type {
	AES_ECB_MECH_INFO_TYPE,		/* SUN_CKM_AES_ECB */
	AES_CBC_MECH_INFO_TYPE,		/* SUN_CKM_AES_CBC */
	AES_CBC_PAD_MECH_INFO_TYPE,	/* SUN_CKM_AES_CBC_PAD */
	AES_CTR_MECH_INFO_TYPE,		/* SUN_CKM_AES_CTR */
	AES_CCM_MECH_INFO_TYPE		/* SUN_CKM_AES_CCM */
} aes_mech_type_t;

/*
 * The following definitions are to keep EXPORT_SRC happy.
 */
#ifndef AES_MIN_KEY_BYTES
#define	AES_MIN_KEY_BYTES		0
#endif

#ifndef AES_MAX_KEY_BYTES
#define	AES_MAX_KEY_BYTES		0
#endif

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t aes_mech_info_tab[] = {
	/* AES_ECB */
	{SUN_CKM_AES_ECB, AES_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_CBC */
	{SUN_CKM_AES_CBC, AES_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_CTR */
	{SUN_CKM_AES_CTR, AES_CTR_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_CCM */
	{SUN_CKM_AES_CCM, AES_CCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES}
};

/* operations are in-place if the output buffer is NULL */
#define	AES_ARG_INPLACE(input, output)				\
	if ((output) == NULL)					\
		(output) = (input);

static void aes_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t aes_control_ops = {
	aes_provider_status
};

static int aes_encrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int aes_decrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int aes_common_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t, boolean_t);
static int aes_common_init_ctx(aes_ctx_t *, crypto_spi_ctx_template_t *,
    crypto_mechanism_t *, crypto_key_t *, int, boolean_t);
static int aes_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int aes_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);

static int aes_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int aes_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int aes_encrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int aes_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int aes_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int aes_decrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_cipher_ops_t aes_cipher_ops = {
	aes_encrypt_init,
	aes_encrypt,
	aes_encrypt_update,
	aes_encrypt_final,
	aes_encrypt_atomic,
	aes_decrypt_init,
	aes_decrypt,
	aes_decrypt_update,
	aes_decrypt_final,
	aes_decrypt_atomic
};

static int aes_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int aes_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t aes_ctx_ops = {
	aes_create_ctx_template,
	aes_free_context
};

static crypto_ops_t aes_crypto_ops = {
	&aes_control_ops,
	NULL,
	&aes_cipher_ops,
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
	&aes_ctx_ops
};

static crypto_provider_info_t aes_prov_info = {
	CRYPTO_SPI_VERSION_1,
	"AES Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&aes_crypto_ops,
	sizeof (aes_mech_info_tab)/sizeof (crypto_mech_info_t),
	aes_mech_info_tab
};

static crypto_kcf_provider_handle_t aes_prov_handle = NULL;

int
_init(void)
{
	int ret;

	/*
	 * Register with KCF. If the registration fails, return error.
	 */
	if ((ret = crypto_register_provider(&aes_prov_info,
	    &aes_prov_handle)) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "%s _init: crypto_register_provider()"
		    "failed (0x%x)", CRYPTO_PROVIDER_NAME, ret);
		return (EACCES);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		int rv;

		ASSERT(aes_prov_handle != NULL);
		/* We should not return if the unregister returns busy. */
		while ((rv = crypto_unregister_provider(aes_prov_handle))
		    == CRYPTO_BUSY) {
			cmn_err(CE_WARN,
			    "%s _init: crypto_unregister_provider() "
			    "failed (0x%x). Retrying.",
			    CRYPTO_PROVIDER_NAME, rv);
			/* wait 10 seconds and try again. */
			delay(10 * drv_usectohz(1000000));
		}
	}

	return (ret);
}

int
_fini(void)
{
	int ret;

	/*
	 * Unregister from KCF if previous registration succeeded.
	 */
	if (aes_prov_handle != NULL) {
		if ((ret = crypto_unregister_provider(aes_prov_handle)) !=
		    CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s _fini: crypto_unregister_provider() "
			    "failed (0x%x)", CRYPTO_PROVIDER_NAME, ret);
			return (EBUSY);
		}
		aes_prov_handle = NULL;
	}

	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
aes_check_mech_param(crypto_mechanism_t *mechanism, aes_ctx_t **ctx, int kmflag)
{
	void *p = NULL;
	int rv = CRYPTO_SUCCESS;

	switch (mechanism->cm_type) {
	case AES_ECB_MECH_INFO_TYPE:
		/* no parameter */
		if (ctx != NULL)
			p = ecb_alloc_ctx(kmflag);
		break;
	case AES_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != AES_BLOCK_LEN) {
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
			break;
		}
		if (ctx != NULL)
			p = cbc_alloc_ctx(kmflag);
		break;
	case AES_CTR_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != sizeof (CK_AES_CTR_PARAMS)) {
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
			break;
		}
		if (ctx != NULL)
			p = ctr_alloc_ctx(kmflag);
		break;
	case AES_CCM_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != sizeof (CK_AES_CCM_PARAMS)) {
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
			break;
		}
		if (ctx != NULL)
			p = ccm_alloc_ctx(kmflag);
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
	}
	if (ctx != NULL)
		*ctx = p;

	return (rv);
}

/* EXPORT DELETE START */

/*
 * Initialize key schedules for AES
 */
static int
init_keysched(crypto_key_t *key, void *newbie)
{
	/*
	 * Only keys by value are supported by this module.
	 */
	switch (key->ck_format) {
	case CRYPTO_KEY_RAW:
		if (key->ck_length < AES_MINBITS ||
		    key->ck_length > AES_MAXBITS) {
			return (CRYPTO_KEY_SIZE_RANGE);
		}

		/* key length must be either 128, 192, or 256 */
		if ((key->ck_length & 63) != 0)
			return (CRYPTO_KEY_SIZE_RANGE);
		break;
	default:
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	aes_init_keysched(key->ck_data, key->ck_length, newbie);
	return (CRYPTO_SUCCESS);
}

/* EXPORT DELETE END */

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
aes_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

static int
aes_encrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req) {
	return (aes_common_init(ctx, mechanism, key, template, req, B_TRUE));
}

static int
aes_decrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req) {
	return (aes_common_init(ctx, mechanism, key, template, req, B_FALSE));
}



/*
 * KCF software provider encrypt entry points.
 */
static int
aes_common_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req, boolean_t is_encrypt_init)
{

/* EXPORT DELETE START */

	aes_ctx_t *aes_ctx;
	int rv;
	int kmflag;

	/*
	 * Only keys by value are supported by this module.
	 */
	if (key->ck_format != CRYPTO_KEY_RAW) {
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	kmflag = crypto_kmflag(req);
	if ((rv = aes_check_mech_param(mechanism, &aes_ctx, kmflag))
	    != CRYPTO_SUCCESS)
		return (rv);

	rv = aes_common_init_ctx(aes_ctx, template, mechanism, key, kmflag,
	    is_encrypt_init);
	if (rv != CRYPTO_SUCCESS) {
		crypto_free_mode_ctx(aes_ctx);
		return (rv);
	}

	ctx->cc_provider_private = aes_ctx;

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

static void
aes_copy_block64(uint8_t *in, uint64_t *out)
{
	if (IS_P2ALIGNED(in, sizeof (uint64_t))) {
		/* LINTED: pointer alignment */
		out[0] = *(uint64_t *)&in[0];
		/* LINTED: pointer alignment */
		out[1] = *(uint64_t *)&in[8];
	} else {
		uint8_t *iv8 = (uint8_t *)&out[0];

		AES_COPY_BLOCK(in, iv8);
	}
}

/* ARGSUSED */
static int
aes_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int ret = CRYPTO_FAILED;

/* EXPORT DELETE START */

	aes_ctx_t *aes_ctx;
	size_t saved_length, saved_offset, length_needed;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	/*
	 * For block ciphers, plaintext must be a multiple of AES block size.
	 * This test is only valid for ciphers whose blocksize is a power of 2.
	 * Even though AES CCM mode is a block cipher, it does not
	 * require the plaintext to be a multiple of AES block size.
	 * The length requirement for AES CCM mode has already been checked
	 * at init time
	 */
	if (((aes_ctx->ac_flags & CTR_MODE) == 0) &&
	    ((aes_ctx->ac_flags & CCM_MODE) == 0) &&
	    (plaintext->cd_length & (AES_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	AES_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	if (aes_ctx->ac_flags & CCM_MODE) {
		length_needed = plaintext->cd_length + aes_ctx->ac_mac_len;
	} else {
		length_needed = plaintext->cd_length;
	}

	if (ciphertext->cd_length < length_needed) {
		ciphertext->cd_length = length_needed;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_length = ciphertext->cd_length;
	saved_offset = ciphertext->cd_offset;

	/*
	 * Do an update on the specified input data.
	 */
	ret = aes_encrypt_update(ctx, plaintext, ciphertext, req);
	if (ret != CRYPTO_SUCCESS) {
		return (ret);
	}

	/*
	 * For CCM mode, aes_ccm_encrypt_final() will take care of any
	 * left-over unprocessed data, and compute the MAC
	 */
	if (aes_ctx->ac_flags & CCM_MODE) {
		/*
		 * aes_ccm_encrypt_final() will compute the MAC and append
		 * it to existing ciphertext. So, need to adjust the left over
		 * length value accordingly
		 */

		/* order of following 2 lines MUST not be reversed */
		ciphertext->cd_offset = ciphertext->cd_length;
		ciphertext->cd_length = saved_length - ciphertext->cd_length;
		ret = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, ciphertext,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}

		if (plaintext != ciphertext) {
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
		ciphertext->cd_offset = saved_offset;
	}

	ASSERT(aes_ctx->ac_remainder_len == 0);
	(void) aes_free_context(ctx);

/* EXPORT DELETE END */

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
aes_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int ret = CRYPTO_FAILED;

/* EXPORT DELETE START */

	aes_ctx_t *aes_ctx;
	off_t saved_offset;
	size_t saved_length;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	/*
	 * For block ciphers, plaintext must be a multiple of AES block size.
	 * This test is only valid for ciphers whose blocksize is a power of 2.
	 * Even though AES CCM mode is a block cipher, it does not
	 * require the plaintext to be a multiple of AES block size.
	 * The length requirement for AES CCM mode has already been checked
	 * at init time
	 */
	if (((aes_ctx->ac_flags & CTR_MODE) == 0) &&
	    ((aes_ctx->ac_flags & CCM_MODE) == 0) &&
	    (ciphertext->cd_length & (AES_BLOCK_LEN - 1)) != 0) {
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
	}

	AES_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 *
	 * For AES CCM mode, size of the plaintext will be MAC_SIZE
	 * smaller than size of the cipher text.
	 */
	if (aes_ctx->ac_flags & CCM_MODE) {
		if (plaintext->cd_length < aes_ctx->ac_data_len) {
			plaintext->cd_length = aes_ctx->ac_data_len;
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
		saved_offset = plaintext->cd_offset;
		saved_length = plaintext->cd_length;
	} else if (plaintext->cd_length < ciphertext->cd_length) {
		plaintext->cd_length = ciphertext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an update on the specified input data.
	 */
	ret = aes_decrypt_update(ctx, ciphertext, plaintext, req);
	if (ret != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	if (aes_ctx->ac_flags & CCM_MODE) {
		ASSERT(aes_ctx->ac_processed_data_len == aes_ctx->ac_data_len);
		ASSERT(aes_ctx->ac_processed_mac_len == aes_ctx->ac_mac_len);

		/* order of following 2 lines MUST not be reversed */
		plaintext->cd_offset = plaintext->cd_length;
		plaintext->cd_length = saved_length - plaintext->cd_length;

		ret = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, plaintext,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		if (ret == CRYPTO_SUCCESS) {
			if (plaintext != ciphertext) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			}
		} else {
			plaintext->cd_length = saved_length;
		}

		plaintext->cd_offset = saved_offset;
	}

	ASSERT(aes_ctx->ac_remainder_len == 0);

cleanup:
	(void) aes_free_context(ctx);

/* EXPORT DELETE END */

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
aes_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;
	aes_ctx_t *aes_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	AES_ARG_INPLACE(plaintext, ciphertext);

	/* compute number of bytes that will hold the ciphertext */
	out_len = aes_ctx->ac_remainder_len;
	out_len += plaintext->cd_length;
	out_len &= ~(AES_BLOCK_LEN - 1);

	/* return length needed to store the output */
	if (ciphertext->cd_length < out_len) {
		ciphertext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;


	/*
	 * Do the AES update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    plaintext, ciphertext, aes_encrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    plaintext, ciphertext, aes_encrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    plaintext, ciphertext, aes_encrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/*
	 * Since AES counter mode is a stream cipher, we call
	 * ctr_mode_final() to pick up any remaining bytes.
	 * It is an internal function that does not destroy
	 * the context like *normal* final routines.
	 */
	if ((aes_ctx->ac_flags & CTR_MODE) && (aes_ctx->ac_remainder_len > 0)) {
		ret = ctr_mode_final((ctr_ctx_t *)aes_ctx,
		    ciphertext, aes_encrypt_block);
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
aes_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;
	aes_ctx_t *aes_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	AES_ARG_INPLACE(ciphertext, plaintext);

	/* compute number of bytes that will hold the plaintext */
	out_len = aes_ctx->ac_remainder_len;
	out_len += ciphertext->cd_length;
	out_len &= ~(AES_BLOCK_LEN - 1);

	/* return length needed to store the output */
	if (plaintext->cd_length < out_len) {
		plaintext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do the AES update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/*
	 * Since AES counter mode is a stream cipher, we call
	 * ctr_mode_final() to pick up any remaining bytes.
	 * It is an internal function that does not destroy
	 * the context like *normal* final routines.
	 */
	if ((aes_ctx->ac_flags & CTR_MODE) && (aes_ctx->ac_remainder_len > 0)) {
		ret = ctr_mode_final((ctr_ctx_t *)aes_ctx, plaintext,
		    aes_encrypt_block);
		if (ret == CRYPTO_DATA_LEN_RANGE)
			ret = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
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
aes_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{

/* EXPORT DELETE START */

	aes_ctx_t *aes_ctx;
	int ret;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	if (data->cd_format != CRYPTO_DATA_RAW &&
	    data->cd_format != CRYPTO_DATA_UIO &&
	    data->cd_format != CRYPTO_DATA_MBLK) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if (aes_ctx->ac_flags & CTR_MODE) {
		if (aes_ctx->ac_remainder_len > 0) {
			ret = ctr_mode_final((ctr_ctx_t *)aes_ctx, data,
			    aes_encrypt_block);
			if (ret != CRYPTO_SUCCESS)
				return (ret);
		}
	} else if (aes_ctx->ac_flags & CCM_MODE) {
		ret = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}
	} else {
		/*
		 * There must be no unprocessed plaintext.
		 * This happens if the length of the last data is
		 * not a multiple of the AES block length.
		 */
		if (aes_ctx->ac_remainder_len > 0) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		data->cd_length = 0;
	}

	(void) aes_free_context(ctx);

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
aes_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{

/* EXPORT DELETE START */

	aes_ctx_t *aes_ctx;
	int ret;
	off_t saved_offset;
	size_t saved_length;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	if (data->cd_format != CRYPTO_DATA_RAW &&
	    data->cd_format != CRYPTO_DATA_UIO &&
	    data->cd_format != CRYPTO_DATA_MBLK) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * There must be no unprocessed ciphertext.
	 * This happens if the length of the last ciphertext is
	 * not a multiple of the AES block length.
	 */
	if (aes_ctx->ac_remainder_len > 0) {
		if ((aes_ctx->ac_flags & CTR_MODE) == 0)
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		else {
			ret = ctr_mode_final((ctr_ctx_t *)aes_ctx, data,
			    aes_encrypt_block);
			if (ret == CRYPTO_DATA_LEN_RANGE)
				ret = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
			if (ret != CRYPTO_SUCCESS)
				return (ret);
		}
	}

	if (aes_ctx->ac_flags & CCM_MODE) {
		/*
		 * This is where all the plaintext is returned, make sure
		 * the plaintext buffer is big enough
		 */
		size_t pt_len = aes_ctx->ac_data_len;
		if (data->cd_length < pt_len) {
			data->cd_length = pt_len;
			return (CRYPTO_BUFFER_TOO_SMALL);
		}

		ASSERT(aes_ctx->ac_processed_data_len == pt_len);
		ASSERT(aes_ctx->ac_processed_mac_len == aes_ctx->ac_mac_len);
		saved_offset = data->cd_offset;
		saved_length = data->cd_length;
		ret = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		if (ret == CRYPTO_SUCCESS) {
			data->cd_length = data->cd_offset - saved_offset;
		} else {
			data->cd_length = saved_length;
		}

		data->cd_offset = saved_offset;
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}
	}


	if (((aes_ctx->ac_flags & CTR_MODE) == 0) &&
	    ((aes_ctx->ac_flags & CCM_MODE) == 0)) {
		data->cd_length = 0;
	}

	(void) aes_free_context(ctx);

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
aes_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	aes_ctx_t aes_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	int ret;

	AES_ARG_INPLACE(plaintext, ciphertext);

	if ((mechanism->cm_type != AES_CTR_MECH_INFO_TYPE) &&
	    (mechanism->cm_type != AES_CCM_MECH_INFO_TYPE)) {
		/*
		 * Plaintext must be a multiple of AES block size.
		 * This test only works for non-padded mechanisms
		 * when blocksize is 2^N.
		 */
		if ((plaintext->cd_length & (AES_BLOCK_LEN - 1)) != 0)
			return (CRYPTO_DATA_LEN_RANGE);
	}

	/* return length needed to store the output */
	if (ciphertext->cd_length < plaintext->cd_length) {
		ciphertext->cd_length = plaintext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if ((ret = aes_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&aes_ctx, sizeof (aes_ctx_t));

	ret = aes_common_init_ctx(&aes_ctx, template, mechanism, key,
	    crypto_kmflag(req), B_TRUE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
		size_t length_needed
		    = plaintext->cd_length + aes_ctx.ac_mac_len;
		if (ciphertext->cd_length < length_needed) {
			ciphertext->cd_length = length_needed;
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}


	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do an update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks, aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks, aes_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks, aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
			ret = ccm_encrypt_final((ccm_ctx_t *)&aes_ctx,
			    ciphertext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_xor_block);
			if (ret != CRYPTO_SUCCESS)
				goto out;
			ASSERT(aes_ctx.ac_remainder_len == 0);
		} else if (mechanism->cm_type == AES_CTR_MECH_INFO_TYPE) {
			if (aes_ctx.ac_remainder_len > 0) {
				ret = ctr_mode_final((ctr_ctx_t *)&aes_ctx,
				    ciphertext, aes_encrypt_block);
				if (ret != CRYPTO_SUCCESS)
					goto out;
			}
		} else {
			ASSERT(aes_ctx.ac_remainder_len == 0);
		}

		if (plaintext != ciphertext) {
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

out:
	if (aes_ctx.ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
		kmem_free(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
	}

	return (ret);
}

/* ARGSUSED */
static int
aes_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	aes_ctx_t aes_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	int ret;

	AES_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * For block ciphers, ciphertext must be a multiple of AES block size.
	 * This test is only valid for non-padded mechanisms
	 * when blocksize is 2^N
	 * Even though AES CCM mode is a block cipher, it does not
	 * require the plaintext to be a multiple of AES block size.
	 * The length requirement for AES CCM mode will be checked
	 * at init time
	 */
	if ((mechanism->cm_type != AES_CTR_MECH_INFO_TYPE) &&
	    (mechanism->cm_type != AES_CCM_MECH_INFO_TYPE) &&
	    ((ciphertext->cd_length & (AES_BLOCK_LEN - 1)) != 0))
		return (CRYPTO_DATA_LEN_RANGE);

	/*
	 * return length needed to store the output, length requirement
	 * for AES CCM mode can not be determined until later
	 */
	if ((plaintext->cd_length < ciphertext->cd_length) &&
	    (mechanism->cm_type != AES_CCM_MECH_INFO_TYPE)) {
		plaintext->cd_length = ciphertext->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}


	if ((ret = aes_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&aes_ctx, sizeof (aes_ctx_t));

	ret = aes_common_init_ctx(&aes_ctx, template, mechanism, key,
	    crypto_kmflag(req), B_FALSE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	/* check length requirement for AES CCM mode now */
	if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
		if (plaintext->cd_length < aes_ctx.ac_data_len) {
			plaintext->cd_length = aes_ctx.ac_data_len;
			ret = CRYPTO_BUFFER_TOO_SMALL;
			goto out;
		}
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do an update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks, aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks, aes_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks, aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
			ASSERT(aes_ctx.ac_processed_data_len
			    == aes_ctx.ac_data_len);
			ASSERT(aes_ctx.ac_processed_mac_len
			    == aes_ctx.ac_mac_len);
			ret = ccm_decrypt_final((ccm_ctx_t *)&aes_ctx,
			    plaintext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_copy_block, aes_xor_block);
			ASSERT(aes_ctx.ac_remainder_len == 0);
			if ((ret == CRYPTO_SUCCESS) &&
			    (ciphertext != plaintext)) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			} else {
				plaintext->cd_length = saved_length;
			}
		} else if (mechanism->cm_type != AES_CTR_MECH_INFO_TYPE) {
			ASSERT(aes_ctx.ac_remainder_len == 0);
			if (ciphertext != plaintext)
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
		} else {
			if (aes_ctx.ac_remainder_len > 0) {
				ret = ctr_mode_final((ctr_ctx_t *)&aes_ctx,
				    plaintext, aes_encrypt_block);
				if (ret == CRYPTO_DATA_LEN_RANGE)
					ret = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
				if (ret != CRYPTO_SUCCESS)
					goto out;
			}
			if (ciphertext != plaintext)
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
		}
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

out:
	if (aes_ctx.ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
		kmem_free(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
	}

	if (aes_ctx.ac_flags & CCM_MODE) {
		if (aes_ctx.ac_pt_buf != NULL) {
			kmem_free(aes_ctx.ac_pt_buf, aes_ctx.ac_data_len);
		}
	}

	return (ret);
}

/*
 * KCF software provider context template entry points.
 */
/* ARGSUSED */
static int
aes_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *tmpl, size_t *tmpl_size, crypto_req_handle_t req)
{

/* EXPORT DELETE START */

	void *keysched;
	size_t size;
	int rv;

	if (mechanism->cm_type != AES_ECB_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_CBC_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_CTR_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_CCM_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if ((keysched = aes_alloc_keysched(&size,
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

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
aes_free_context(crypto_ctx_t *ctx)
{

/* EXPORT DELETE START */

	aes_ctx_t *aes_ctx = ctx->cc_provider_private;

	if (aes_ctx != NULL) {
		if (aes_ctx->ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(aes_ctx->ac_keysched_len != 0);
			bzero(aes_ctx->ac_keysched, aes_ctx->ac_keysched_len);
			kmem_free(aes_ctx->ac_keysched,
			    aes_ctx->ac_keysched_len);
		}
		crypto_free_mode_ctx(aes_ctx);
		ctx->cc_provider_private = NULL;
	}

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
aes_common_init_ctx(aes_ctx_t *aes_ctx, crypto_spi_ctx_template_t *template,
    crypto_mechanism_t *mechanism, crypto_key_t *key, int kmflag,
    boolean_t is_encrypt_init)
{
	int rv = CRYPTO_SUCCESS;

/* EXPORT DELETE START */

	void *keysched;
	size_t size;

	if (template == NULL) {
		if ((keysched = aes_alloc_keysched(&size, kmflag)) == NULL)
			return (CRYPTO_HOST_MEMORY);
		/*
		 * Initialize key schedule.
		 * Key length is stored in the key.
		 */
		if ((rv = init_keysched(key, keysched)) != CRYPTO_SUCCESS) {
			kmem_free(keysched, size);
			return (rv);
		}

		aes_ctx->ac_flags |= PROVIDER_OWNS_KEY_SCHEDULE;
		aes_ctx->ac_keysched_len = size;
	} else {
		keysched = template;
	}
	aes_ctx->ac_keysched = keysched;

	switch (mechanism->cm_type) {
	case AES_CBC_MECH_INFO_TYPE:
		rv = cbc_init_ctx((cbc_ctx_t *)aes_ctx, mechanism->cm_param,
		    mechanism->cm_param_len, AES_BLOCK_LEN, aes_copy_block64);
		break;
	case AES_CTR_MECH_INFO_TYPE: {
		CK_AES_CTR_PARAMS *pp;

		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_CTR_PARAMS)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		pp = (CK_AES_CTR_PARAMS *)mechanism->cm_param;
		rv = ctr_init_ctx((ctr_ctx_t *)aes_ctx, pp->ulCounterBits,
		    pp->cb, aes_copy_block);
		break;
	}
	case AES_CCM_MECH_INFO_TYPE:
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_CCM_PARAMS)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		rv = ccm_init_ctx((ccm_ctx_t *)aes_ctx, mechanism->cm_param,
		    kmflag, is_encrypt_init, AES_BLOCK_LEN, aes_encrypt_block,
		    aes_xor_block);
		break;
	case AES_ECB_MECH_INFO_TYPE:
		aes_ctx->ac_flags |= ECB_MODE;
	}

	if (rv != CRYPTO_SUCCESS) {
		if (aes_ctx->ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			bzero(keysched, size);
			kmem_free(keysched, size);
		}
	}

/* EXPORT DELETE END */

	return (rv);
}
