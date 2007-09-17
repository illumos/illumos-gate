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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/crypto/spi.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <aes_impl.h>
#include <aes_cbc_crypt.h>

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
aes_check_mech_param(crypto_mechanism_t *mechanism)
{
	int rv = CRYPTO_SUCCESS;

	switch (mechanism->cm_type) {
	case AES_ECB_MECH_INFO_TYPE:
		/* no parameter */
		break;
	case AES_CBC_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != AES_BLOCK_LEN)
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
		break;
	case AES_CTR_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != sizeof (CK_AES_CTR_PARAMS))
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
		break;
	case AES_CCM_MECH_INFO_TYPE:
		if (mechanism->cm_param != NULL &&
		    mechanism->cm_param_len != sizeof (CK_AES_CCM_PARAMS))
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
	}
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

	if ((rv = aes_check_mech_param(mechanism)) != CRYPTO_SUCCESS)
		return (rv);

	/*
	 * Allocate an AES context.
	 */
	kmflag = crypto_kmflag(req);
	if ((aes_ctx = kmem_zalloc(sizeof (aes_ctx_t), kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	rv = aes_common_init_ctx(aes_ctx, template, mechanism, key, kmflag,
	    is_encrypt_init);
	if (rv != CRYPTO_SUCCESS) {
		kmem_free(aes_ctx, sizeof (aes_ctx_t));
		return (rv);
	}

	ctx->cc_provider_private = aes_ctx;

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/*
 * Helper AES encrypt update function for iov input data.
 */
static int
aes_cipher_update_iov(aes_ctx_t *aes_ctx, crypto_data_t *input,
    crypto_data_t *output, int (*cipher)(aes_ctx_t *, caddr_t, size_t,
    crypto_data_t *))
{
	int rv;
/* EXPORT DELETE START */

	if (input->cd_miscdata != NULL) {
		if (IS_P2ALIGNED(input->cd_miscdata, sizeof (uint64_t))) {
			/* LINTED: pointer alignment */
			aes_ctx->ac_iv[0] = *(uint64_t *)input->cd_miscdata;
			/* LINTED: pointer alignment */
			aes_ctx->ac_iv[1] = *(uint64_t *)&input->cd_miscdata[8];
		} else {
			uint8_t *miscdata8 = (uint8_t *)&input->cd_miscdata[0];
			uint8_t *iv8 = (uint8_t *)&aes_ctx->ac_iv[0];

			AES_COPY_BLOCK(miscdata8, iv8);
		}
	}

	if (input->cd_raw.iov_len < input->cd_length)
		return (CRYPTO_ARGUMENTS_BAD);

	rv = (cipher)(aes_ctx, input->cd_raw.iov_base + input->cd_offset,
	    input->cd_length, (input == output) ? NULL : output);

/* EXPORT DELETE END */

	return (rv);
}

/*
 * Helper AES encrypt update function for uio input data.
 */
static int
aes_cipher_update_uio(aes_ctx_t *aes_ctx, crypto_data_t *input,
    crypto_data_t *output, int (*cipher)(aes_ctx_t *, caddr_t, size_t,
    crypto_data_t *))
{
/* EXPORT DELETE START */
	uio_t *uiop = input->cd_uio;
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	uint_t vec_idx;
	size_t cur_len;

	if (input->cd_miscdata != NULL) {
		if (IS_P2ALIGNED(input->cd_miscdata, sizeof (uint64_t))) {
			/* LINTED: pointer alignment */
			aes_ctx->ac_iv[0] = *(uint64_t *)input->cd_miscdata;
			/* LINTED: pointer alignment */
			aes_ctx->ac_iv[1] = *(uint64_t *)&input->cd_miscdata[8];
		} else {
			uint8_t *miscdata8 = (uint8_t *)&input->cd_miscdata[0];
			uint8_t *iv8 = (uint8_t *)&aes_ctx->ac_iv[0];

			AES_COPY_BLOCK(miscdata8, iv8);
		}
	}

	if (input->cd_uio->uio_segflg != UIO_SYSSPACE) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * Jump to the first iovec containing data to be
	 * processed.
	 */
	for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
	    offset >= uiop->uio_iov[vec_idx].iov_len;
	    offset -= uiop->uio_iov[vec_idx++].iov_len)
		;
	if (vec_idx == uiop->uio_iovcnt) {
		/*
		 * The caller specified an offset that is larger than the
		 * total size of the buffers it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	/*
	 * Now process the iovecs.
	 */
	while (vec_idx < uiop->uio_iovcnt && length > 0) {
		cur_len = MIN(uiop->uio_iov[vec_idx].iov_len -
		    offset, length);

		(cipher)(aes_ctx, uiop->uio_iov[vec_idx].iov_base + offset,
		    cur_len, (input == output) ? NULL : output);

		length -= cur_len;
		vec_idx++;
		offset = 0;
	}

	if (vec_idx == uiop->uio_iovcnt && length > 0) {
		/*
		 * The end of the specified iovec's was reached but
		 * the length requested could not be processed, i.e.
		 * The caller requested to digest more data than it provided.
		 */

		return (CRYPTO_DATA_LEN_RANGE);
	}

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/*
 * Helper AES encrypt update function for mblk input data.
 */
static int
aes_cipher_update_mp(aes_ctx_t *aes_ctx, crypto_data_t *input,
    crypto_data_t *output, int (*cipher)(aes_ctx_t *, caddr_t, size_t,
    crypto_data_t *))
{
/* EXPORT DELETE START */
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	mblk_t *mp;
	size_t cur_len;

	if (input->cd_miscdata != NULL) {
		if (IS_P2ALIGNED(input->cd_miscdata, sizeof (uint64_t))) {
			/* LINTED: pointer alignment */
			aes_ctx->ac_iv[0] = *(uint64_t *)input->cd_miscdata;
			/* LINTED: pointer alignment */
			aes_ctx->ac_iv[1] = *(uint64_t *)&input->cd_miscdata[8];
		} else {
			uint8_t *miscdata8 = (uint8_t *)&input->cd_miscdata[0];
			uint8_t *iv8 = (uint8_t *)&aes_ctx->ac_iv[0];

			AES_COPY_BLOCK(miscdata8, iv8);
		}
	}

	/*
	 * Jump to the first mblk_t containing data to be processed.
	 */
	for (mp = input->cd_mp; mp != NULL && offset >= MBLKL(mp);
	    offset -= MBLKL(mp), mp = mp->b_cont)
		;
	if (mp == NULL) {
		/*
		 * The caller specified an offset that is larger than the
		 * total size of the buffers it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	/*
	 * Now do the processing on the mblk chain.
	 */
	while (mp != NULL && length > 0) {
		cur_len = MIN(MBLKL(mp) - offset, length);
		(cipher)(aes_ctx, (char *)(mp->b_rptr + offset), cur_len,
		    (input == output) ? NULL : output);

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

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
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
	if (((aes_ctx->ac_flags & AES_CTR_MODE) == 0) &&
	    ((aes_ctx->ac_flags & AES_CCM_MODE) == 0) &&
	    (plaintext->cd_length & (AES_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	AES_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	if (aes_ctx->ac_flags & AES_CCM_MODE) {
		length_needed = plaintext->cd_length + aes_ctx->ac_ccm_mac_len;
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
	if (aes_ctx->ac_flags & AES_CCM_MODE) {
		/*
		 * aes_ccm_encrypt_final() will compute the MAC and append
		 * it to existing ciphertext. So, need to adjust the left over
		 * length value accordingly
		 */

		/* order of following 2 lines MUST not be reversed */
		ciphertext->cd_offset = ciphertext->cd_length;
		ciphertext->cd_length = saved_length - ciphertext->cd_length;
		ret = aes_ccm_encrypt_final(aes_ctx, ciphertext);
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
	if (((aes_ctx->ac_flags & AES_CTR_MODE) == 0) &&
	    ((aes_ctx->ac_flags & AES_CCM_MODE) == 0) &&
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
	if (aes_ctx->ac_flags & AES_CCM_MODE) {
		if (plaintext->cd_length < aes_ctx->ac_ccm_data_len) {
			plaintext->cd_length = aes_ctx->ac_ccm_data_len;
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

	if (aes_ctx->ac_flags & AES_CCM_MODE) {
		ASSERT(aes_ctx->ac_ccm_processed_data_len
		    == aes_ctx->ac_ccm_data_len);
		ASSERT(aes_ctx->ac_ccm_processed_mac_len
		    == aes_ctx->ac_ccm_mac_len);

		/* order of following 2 lines MUST not be reversed */
		plaintext->cd_offset = plaintext->cd_length;
		plaintext->cd_length = saved_length - plaintext->cd_length;

		ret = aes_ccm_decrypt_final(aes_ctx, plaintext);
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
	if (aes_ctx->ac_ccm_pt_buf) {
		kmem_free(aes_ctx->ac_ccm_pt_buf, aes_ctx->ac_ccm_data_len);
	}
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

	AES_ARG_INPLACE(plaintext, ciphertext);

	/* compute number of bytes that will hold the ciphertext */
	out_len = ((aes_ctx_t *)ctx->cc_provider_private)->ac_remainder_len;
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
		ret = aes_cipher_update_iov(ctx->cc_provider_private,
		    plaintext, ciphertext, aes_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = aes_cipher_update_uio(ctx->cc_provider_private,
		    plaintext, ciphertext, aes_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = aes_cipher_update_mp(ctx->cc_provider_private,
		    plaintext, ciphertext, aes_encrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/*
	 * Since AES counter mode is a stream cipher, we call
	 * aes_counter_final() to pick up any remaining bytes.
	 * It is an internal function that does not destroy
	 * the context like *normal* final routines.
	 */
	aes_ctx = ctx->cc_provider_private;
	if ((aes_ctx->ac_flags & AES_CTR_MODE) &&
	    (aes_ctx->ac_remainder_len > 0)) {
		ret = aes_counter_final(aes_ctx, ciphertext);
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

	AES_ARG_INPLACE(ciphertext, plaintext);

	/* compute number of bytes that will hold the plaintext */
	out_len = ((aes_ctx_t *)ctx->cc_provider_private)->ac_remainder_len;
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
		ret = aes_cipher_update_iov(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = aes_cipher_update_uio(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = aes_cipher_update_mp(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/*
	 * Since AES counter mode is a stream cipher, we call
	 * aes_counter_final() to pick up any remaining bytes.
	 * It is an internal function that does not destroy
	 * the context like *normal* final routines.
	 */
	aes_ctx = ctx->cc_provider_private;
	if ((aes_ctx->ac_flags & AES_CTR_MODE) &&
	    (aes_ctx->ac_remainder_len > 0)) {
		ret = aes_counter_final(aes_ctx, plaintext);
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

	if (aes_ctx->ac_flags & AES_CTR_MODE) {
		if (aes_ctx->ac_remainder_len > 0) {
			ret = aes_counter_final(aes_ctx, data);
			if (ret != CRYPTO_SUCCESS)
				return (ret);
		}
	} else if (aes_ctx->ac_flags & AES_CCM_MODE) {
		ret = aes_ccm_encrypt_final(aes_ctx, data);
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
		if ((aes_ctx->ac_flags & AES_CTR_MODE) == 0)
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		else {
			ret = aes_counter_final(aes_ctx, data);
			if (ret != CRYPTO_SUCCESS)
				return (ret);
		}
	}

	if (aes_ctx->ac_flags & AES_CCM_MODE) {
		/*
		 * This is where all the plaintext is returned, make sure
		 * the plaintext buffer is big enough
		 */
		size_t pt_len = aes_ctx->ac_ccm_data_len;
		if (data->cd_length < pt_len) {
			data->cd_length = pt_len;
			return (CRYPTO_BUFFER_TOO_SMALL);
		}

		ASSERT(aes_ctx->ac_ccm_processed_data_len == pt_len);
		ASSERT(aes_ctx->ac_ccm_processed_mac_len
		    == aes_ctx->ac_ccm_mac_len);
		saved_offset = data->cd_offset;
		saved_length = data->cd_length;
		ret = aes_ccm_decrypt_final(aes_ctx, data);
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


	if (((aes_ctx->ac_flags & AES_CTR_MODE) == 0) &&
	    ((aes_ctx->ac_flags & AES_CCM_MODE) == 0)) {
		data->cd_length = 0;
	}

	if (aes_ctx->ac_ccm_pt_buf != NULL) {
		kmem_free(aes_ctx->ac_ccm_pt_buf, aes_ctx->ac_ccm_data_len);
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

	if ((ret = aes_check_mech_param(mechanism)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&aes_ctx, sizeof (aes_ctx_t));

	ret = aes_common_init_ctx(&aes_ctx, template, mechanism, key,
	    crypto_kmflag(req), B_TRUE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
		size_t length_needed
		    = plaintext->cd_length + aes_ctx.ac_ccm_mac_len;
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
		ret = aes_cipher_update_iov(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = aes_cipher_update_uio(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = aes_cipher_update_mp(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
			ret = aes_ccm_encrypt_final(&aes_ctx, ciphertext);
			if (ret != CRYPTO_SUCCESS)
				goto out;
			ASSERT(aes_ctx.ac_remainder_len == 0);
		} else if (mechanism->cm_type == AES_CTR_MECH_INFO_TYPE) {
			if (aes_ctx.ac_remainder_len > 0) {
				ret = aes_counter_final(&aes_ctx, ciphertext);
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
	if (aes_ctx.ac_flags & AES_PROVIDER_OWNS_KEY_SCHEDULE) {
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


	if ((ret = aes_check_mech_param(mechanism)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&aes_ctx, sizeof (aes_ctx_t));

	ret = aes_common_init_ctx(&aes_ctx, template, mechanism, key,
	    crypto_kmflag(req), B_FALSE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	/* check length requirement for AES CCM mode now */
	if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
		if (plaintext->cd_length < aes_ctx.ac_ccm_data_len) {
			plaintext->cd_length = aes_ctx.ac_ccm_data_len;
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
		ret = aes_cipher_update_iov(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = aes_cipher_update_uio(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = aes_cipher_update_mp(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
			ASSERT(aes_ctx.ac_ccm_processed_data_len
			    == aes_ctx.ac_ccm_data_len);
			ASSERT(aes_ctx.ac_ccm_processed_mac_len
			    == aes_ctx.ac_ccm_mac_len);
			ret = aes_ccm_decrypt_final(&aes_ctx, plaintext);
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
				ret = aes_counter_final(&aes_ctx, plaintext);
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
	if (aes_ctx.ac_flags & AES_PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
		kmem_free(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
	}

	if (aes_ctx.ac_ccm_pt_buf != NULL) {
		kmem_free(aes_ctx.ac_ccm_pt_buf, aes_ctx.ac_ccm_data_len);
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
		if (aes_ctx->ac_flags & AES_PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(aes_ctx->ac_keysched_len != 0);
			bzero(aes_ctx->ac_keysched, aes_ctx->ac_keysched_len);
			kmem_free(aes_ctx->ac_keysched,
			    aes_ctx->ac_keysched_len);
		}
		kmem_free(aes_ctx, sizeof (aes_ctx_t));
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
	CK_AES_CCM_PARAMS *ccm_param = NULL;

	aes_ctx->ac_flags = 0;

	if (mechanism->cm_type == AES_CBC_MECH_INFO_TYPE) {
		/*
		 * Copy 128-bit IV into context.
		 *
		 * If cm_param == NULL then the IV comes from the
		 * cd_miscdata field in the crypto_data structure.
		 */
		if (mechanism->cm_param != NULL) {
			ASSERT(mechanism->cm_param_len == AES_BLOCK_LEN);
			if (IS_P2ALIGNED(mechanism->cm_param,
			    sizeof (uint64_t))) {
				uint64_t *param64;
				param64 = (uint64_t *)mechanism->cm_param;

				aes_ctx->ac_iv[0] = *param64++;
				aes_ctx->ac_iv[1] = *param64;
			} else {
				uint8_t *iv8;
				uint8_t *p8;
				iv8 = (uint8_t *)&aes_ctx->ac_iv;
				p8 = (uint8_t *)&mechanism->cm_param[0];

				iv8[0] = p8[0];
				iv8[1] = p8[1];
				iv8[2] = p8[2];
				iv8[3] = p8[3];
				iv8[4] = p8[4];
				iv8[5] = p8[5];
				iv8[6] = p8[6];
				iv8[7] = p8[7];
				iv8[8] = p8[8];
				iv8[9] = p8[9];
				iv8[10] = p8[10];
				iv8[11] = p8[11];
				iv8[12] = p8[12];
				iv8[13] = p8[13];
				iv8[14] = p8[14];
				iv8[15] = p8[15];
			}
		}

		aes_ctx->ac_lastp = (uint8_t *)&aes_ctx->ac_iv[0];
		aes_ctx->ac_flags |= AES_CBC_MODE;

	} else if (mechanism->cm_type == AES_CTR_MECH_INFO_TYPE) {
		if (mechanism->cm_param != NULL) {
			CK_AES_CTR_PARAMS *pp;
			uint64_t mask = 0;
			ulong_t count;
			uint8_t *iv8;
			uint8_t *p8;

			/* XXX what to do about miscdata */
			pp = (CK_AES_CTR_PARAMS *)mechanism->cm_param;
			count = pp->ulCounterBits;
			if (count == 0 || count > 64) {
				return (CRYPTO_MECHANISM_PARAM_INVALID);
			}
			while (count-- > 0)
				mask |= (1ULL << count);
#ifdef _LITTLE_ENDIAN
			p8 = (uint8_t *)&mask;
			mask = (((uint64_t)p8[0] << 56) |
			    ((uint64_t)p8[1] << 48) |
			    ((uint64_t)p8[2] << 40) |
			    ((uint64_t)p8[3] << 32) |
			    ((uint64_t)p8[4] << 24) |
			    ((uint64_t)p8[5] << 16) |
			    ((uint64_t)p8[6] << 8) |
			    (uint64_t)p8[7]);
#endif
			aes_ctx->ac_counter_mask = mask;

			iv8 = (uint8_t *)&aes_ctx->ac_iv;
			p8 = (uint8_t *)&pp->cb[0];

			iv8[0] = p8[0];
			iv8[1] = p8[1];
			iv8[2] = p8[2];
			iv8[3] = p8[3];
			iv8[4] = p8[4];
			iv8[5] = p8[5];
			iv8[6] = p8[6];
			iv8[7] = p8[7];
			iv8[8] = p8[8];
			iv8[9] = p8[9];
			iv8[10] = p8[10];
			iv8[11] = p8[11];
			iv8[12] = p8[12];
			iv8[13] = p8[13];
			iv8[14] = p8[14];
			iv8[15] = p8[15];
		} else {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}

		aes_ctx->ac_lastp = (uint8_t *)&aes_ctx->ac_iv[0];
		aes_ctx->ac_flags |= AES_CTR_MODE;
	} else if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
		if (mechanism->cm_param != NULL) {
			int rc;

			ccm_param = (CK_AES_CCM_PARAMS *)mechanism->cm_param;

			if ((rc = aes_ccm_validate_args(ccm_param,
			    is_encrypt_init)) != 0) {
				return (rc);
			}

			aes_ctx->ac_ccm_mac_len = ccm_param->ulMACSize;
			if (is_encrypt_init) {
				aes_ctx->ac_ccm_data_len
				    = ccm_param->ulDataSize;
			} else {
				aes_ctx->ac_ccm_data_len =
				    ccm_param->ulDataSize
				    - aes_ctx->ac_ccm_mac_len;
				aes_ctx->ac_ccm_processed_mac_len = 0;
			}
			aes_ctx->ac_ccm_processed_data_len = 0;

			aes_ctx->ac_flags |= AES_CCM_MODE;
		} else {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
	} else {
		aes_ctx->ac_flags |= AES_ECB_MODE;
	}

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

		aes_ctx->ac_flags |= AES_PROVIDER_OWNS_KEY_SCHEDULE;
		aes_ctx->ac_keysched_len = size;
	} else {
		keysched = template;
	}
	aes_ctx->ac_keysched = keysched;

	/* process the nonce and associated data if it is AES CCM mode */
	if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
		if (aes_ccm_init(aes_ctx, ccm_param->nonce,
		    ccm_param->ulNonceSize, ccm_param->authData,
		    ccm_param->ulAuthDataSize) != 0) {
			bzero(keysched, size);
			kmem_free(keysched, size);
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		if (!is_encrypt_init) {
			/* allocate buffer for storing decrypted plaintext */
			aes_ctx->ac_ccm_pt_buf =
			    kmem_alloc(aes_ctx->ac_ccm_data_len, kmflag);
			if (aes_ctx->ac_ccm_pt_buf == NULL) {
				bzero(keysched, size);
				kmem_free(keysched, size);
				return (CRYPTO_HOST_MEMORY);
			}
		}
	}

/* EXPORT DELETE END */

	return (rv);
}
