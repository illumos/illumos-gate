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
#include <blowfish_impl.h>

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"Blowfish Kernel SW Provider %I%"
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
	BF_ECB_MECH_INFO_TYPE,		/* SUN_CKM_BF_ECB */
	BF_CBC_MECH_INFO_TYPE		/* SUN_CKM_BF_CBC */
} blowfish_mech_type_t;

/*
 * bc_keysched:		Pointer to key schedule.
 *
 * bc_keysched_len:	Length of the key schedule.
 *
 * bc_remainder:	This is for residual data, i.e. data that can't
 *			be processed because there are too few bytes.
 *			Must wait until more data arrives.
 *
 * bc_remainder_len:	Number of bytes in bc_remainder.
 *
 * bc_iv:		Scratch buffer that sometimes contains the IV.
 *
 * bc_lastblock:	Scratch buffer.
 *
 * bc_lastp:		Pointer to previous block of ciphertext.
 *
 * bc_copy_to:		Pointer to where encrypted residual data needs
 *			to be copied.
 *
 * bc_flags:		BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE
 *			When a context is freed, it is necessary
 *			to know whether the key schedule was allocated
 *			by the caller, or by blowfish_common_init().
 *			If allocated by the latter, then it needs to be freed.
 *
 *			BLOWFISH_CBC_MODE
 *			If flag is not set, the mode is BLOWFISH_ECB_MODE.
 *
 */
typedef struct blowfish_ctx {
	void *bc_keysched;
	size_t bc_keysched_len;
	uint64_t bc_iv;
	uint64_t bc_lastblock;
	uint64_t bc_remainder;
	size_t bc_remainder_len;
	uint8_t *bc_lastp;
	uint8_t *bc_copy_to;
	uint32_t bc_flags;
} blowfish_ctx_t;

#define	BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE	0x00000001
#define	BLOWFISH_CBC_MODE			0x00000002

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
	{SUN_CKM_BF_ECB, BF_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    BLOWFISH_MINBITS, BLOWFISH_MAXBITS, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* BLOWFISH_CBC */
	{SUN_CKM_BF_CBC, BF_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    BLOWFISH_MINBITS, BLOWFISH_MAXBITS, CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

#define	BLOWFISH_VALID_MECH(mech)				\
	(((mech)->cm_type == BF_ECB_MECH_INFO_TYPE ||		\
	(mech)->cm_type == BF_CBC_MECH_INFO_TYPE) ? 1 : 0)

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

static int blowfish_encrypt_contiguous_blocks(blowfish_ctx_t *, char *, size_t,
    crypto_data_t *);
static int blowfish_decrypt_contiguous_blocks(blowfish_ctx_t *, char *, size_t,
    crypto_data_t *);

static crypto_kcf_provider_handle_t blowfish_prov_handle = NULL;

int
_init(void)
{
	int ret;

	/*
	 * Register with KCF. If the registration fails, return error.
	 */
	if ((ret = crypto_register_provider(&blowfish_prov_info,
	    &blowfish_prov_handle)) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "%s _init: crypto_register_provider() "
		    "failed (0x%x)", CRYPTO_PROVIDER_NAME, ret);
		return (EACCES);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		int rv;

		ASSERT(blowfish_prov_handle != NULL);
		/* We should not return if the unregister returns busy. */
		while ((rv = crypto_unregister_provider(blowfish_prov_handle))
		    == CRYPTO_BUSY) {
			cmn_err(CE_WARN,
			    "%s _init: crypto_unregister_provider() "
			    "failed (0x%x). Retrying.",
			    CRYPTO_PROVIDER_NAME, rv);
			/* wait 10 seconds and try again */
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
	if (blowfish_prov_handle != NULL) {
		if ((ret = crypto_unregister_provider(blowfish_prov_handle)) !=
		    CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s _fini: crypto_unregister_provider() "
			    "failed (0x%x)", CRYPTO_PROVIDER_NAME, ret);
			return (EBUSY);
		}
		blowfish_prov_handle = NULL;
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
/* EXPORT DELETE START */
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
/* EXPORT DELETE END */
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

/* EXPORT DELETE START */

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

	/*
	 * Allocate a blowfish context.
	 */
	kmflag = crypto_kmflag(req);
	blowfish_ctx = kmem_zalloc(sizeof (blowfish_ctx_t), kmflag);
	if (blowfish_ctx == NULL)
		return (CRYPTO_HOST_MEMORY);

	rv = blowfish_common_init_ctx(blowfish_ctx, template, mechanism,
	    key, kmflag);
	if (rv != CRYPTO_SUCCESS) {
		kmem_free(blowfish_ctx, sizeof (blowfish_ctx_t));
		return (rv);
	}

	ctx->cc_provider_private = blowfish_ctx;

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/*
 * Helper blowfish encrypt update function for iov input data.
 */
static int
blowfish_cipher_update_iov(blowfish_ctx_t *blowfish_ctx, crypto_data_t *input,
    crypto_data_t *output, int (*cipher)(blowfish_ctx_t *, caddr_t, size_t,
    crypto_data_t *))
{
	if (input->cd_miscdata != NULL) {
		if (IS_P2ALIGNED(input->cd_miscdata, sizeof (uint64_t))) {
			/* LINTED: pointer alignment */
			blowfish_ctx->bc_iv = *(uint64_t *)input->cd_miscdata;
		} else {
			uint8_t *miscdata8 = (uint8_t *)&input->cd_miscdata[0];
			uint8_t *iv8 = (uint8_t *)&blowfish_ctx->bc_iv;

			BLOWFISH_COPY_BLOCK(miscdata8, iv8);
		}
	}

	if (input->cd_raw.iov_len < input->cd_length)
		return (CRYPTO_ARGUMENTS_BAD);

	return (cipher)(blowfish_ctx, input->cd_raw.iov_base + input->cd_offset,
	    input->cd_length, (input == output) ? NULL : output);
}

/*
 * Helper blowfish encrypt update function for uio input data.
 */
static int
blowfish_cipher_update_uio(blowfish_ctx_t *blowfish_ctx, crypto_data_t *input,
    crypto_data_t *output, int (*cipher)(blowfish_ctx_t *, caddr_t, size_t,
    crypto_data_t *))
{
	uio_t *uiop = input->cd_uio;
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	uint_t vec_idx;
	size_t cur_len;

	if (input->cd_miscdata != NULL) {
		if (IS_P2ALIGNED(input->cd_miscdata, sizeof (uint64_t))) {
			/*LINTED: pointer alignment */
			blowfish_ctx->bc_iv = *(uint64_t *)input->cd_miscdata;
		} else {
			uint8_t *miscdata8 = (uint8_t *)&input->cd_miscdata[0];
			uint8_t *iv8 = (uint8_t *)&blowfish_ctx->bc_iv;

			BLOWFISH_COPY_BLOCK(miscdata8, iv8);
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
	    offset -= uiop->uio_iov[vec_idx++].iov_len);
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

		(cipher)(blowfish_ctx, uiop->uio_iov[vec_idx].iov_base +
		    offset, cur_len, (input == output) ? NULL : output);

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

	return (CRYPTO_SUCCESS);
}

/*
 * Helper blowfish encrypt update function for mblk input data.
 */
static int
blowfish_cipher_update_mp(blowfish_ctx_t *blowfish_ctx, crypto_data_t *input,
    crypto_data_t *output, int (*cipher)(blowfish_ctx_t *, caddr_t, size_t,
    crypto_data_t *))
{
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	mblk_t *mp;
	size_t cur_len;

	if (input->cd_miscdata != NULL) {
		if (IS_P2ALIGNED(input->cd_miscdata, sizeof (uint64_t))) {
			/*LINTED: pointer alignment */
			blowfish_ctx->bc_iv = *(uint64_t *)input->cd_miscdata;
		} else {
			uint8_t *miscdata8 = (uint8_t *)&input->cd_miscdata[0];
			uint8_t *iv8 = (uint8_t *)&blowfish_ctx->bc_iv;

			BLOWFISH_COPY_BLOCK(miscdata8, iv8);
		}
	}

	/*
	 * Jump to the first mblk_t containing data to be processed.
	 */
	for (mp = input->cd_mp; mp != NULL && offset >= MBLKL(mp);
	    offset -= MBLKL(mp), mp = mp->b_cont);
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
		(cipher)(blowfish_ctx, (char *)(mp->b_rptr + offset), cur_len,
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

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
blowfish_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int ret;

/* EXPORT DELETE START */

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

/* EXPORT DELETE END */

	/* LINTED */
	return (ret);
}

/* ARGSUSED */
static int
blowfish_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int ret;

/* EXPORT DELETE START */

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

/* EXPORT DELETE END */

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
		ret = blowfish_cipher_update_iov(ctx->cc_provider_private,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = blowfish_cipher_update_uio(ctx->cc_provider_private,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = blowfish_cipher_update_mp(ctx->cc_provider_private,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks);
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
		ret = blowfish_cipher_update_iov(ctx->cc_provider_private,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = blowfish_cipher_update_uio(ctx->cc_provider_private,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = blowfish_cipher_update_mp(ctx->cc_provider_private,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks);
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

/* EXPORT DELETE START */

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

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
blowfish_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{

/* EXPORT DELETE START */

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

/* EXPORT DELETE END */

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
		ret = blowfish_cipher_update_iov(&blowfish_ctx,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = blowfish_cipher_update_uio(&blowfish_ctx,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = blowfish_cipher_update_mp(&blowfish_ctx,
		    plaintext, ciphertext, blowfish_encrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (blowfish_ctx.bc_flags & BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE) {
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
		ret = blowfish_cipher_update_iov(&blowfish_ctx,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = blowfish_cipher_update_uio(&blowfish_ctx,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_MBLK:
		ret = blowfish_cipher_update_mp(&blowfish_ctx,
		    ciphertext, plaintext, blowfish_decrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (blowfish_ctx.bc_flags & BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE) {
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

/* EXPORT DELETE START */

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

/* EXPORT DELETE END */

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
blowfish_free_context(crypto_ctx_t *ctx)
{
	blowfish_ctx_t *blowfish_ctx = ctx->cc_provider_private;

	if (blowfish_ctx != NULL) {
		if (blowfish_ctx->bc_flags &
		    BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(blowfish_ctx->bc_keysched_len != 0);
			bzero(blowfish_ctx->bc_keysched,
			    blowfish_ctx->bc_keysched_len);
			kmem_free(blowfish_ctx->bc_keysched,
			    blowfish_ctx->bc_keysched_len);
		}
		kmem_free(blowfish_ctx, sizeof (blowfish_ctx_t));
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Initialize by setting iov_or_mp to point to the current iovec or mp,
 * and by setting current_offset to an offset within the current iovec or mp .
 */
static void
blowfish_init_ptrs(crypto_data_t *out, void **iov_or_mp,
    offset_t *current_offset)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW:
		*current_offset = out->cd_offset;
		break;

	case CRYPTO_DATA_UIO: {
		uio_t *uiop = out->cd_uio;
		uint_t vec_idx;

		offset = out->cd_offset;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    offset >= uiop->uio_iov[vec_idx].iov_len;
		    offset -= uiop->uio_iov[vec_idx++].iov_len);

		*current_offset = offset;
		*iov_or_mp = (void *)(uintptr_t)vec_idx;
		break;
	}

	case CRYPTO_DATA_MBLK: {
		mblk_t *mp;

		offset = out->cd_offset;
		for (mp = out->cd_mp; mp != NULL && offset >= MBLKL(mp);
			offset -= MBLKL(mp), mp = mp->b_cont);

		*current_offset = offset;
		*iov_or_mp = mp;
		break;

	}
	} /* end switch */
}

/*
 * Get pointers for where in the output to copy a block of encrypted or
 * decrypted data.  The iov_or_mp argument stores a pointer to the current
 * iovec or mp, and offset stores an offset into the current iovec or mp.
 */
static void
blowfish_get_ptrs(crypto_data_t *out, void **iov_or_mp,
    offset_t *current_offset, uint8_t **out_data_1, size_t *out_data_1_len,
    uint8_t **out_data_2)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW: {
		iovec_t *iov;

		offset = *current_offset;
		iov = &out->cd_raw;
		if ((offset + BLOWFISH_BLOCK_LEN) <= iov->iov_len) {
			/* one BLOWFISH block fits */
			*out_data_1 = (uint8_t *)iov->iov_base + offset;
			*out_data_1_len = BLOWFISH_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + BLOWFISH_BLOCK_LEN;
		}
		break;
	}

	case CRYPTO_DATA_UIO: {
		uio_t *uio = out->cd_uio;
		iovec_t *iov;
		offset_t offset;
		uint_t vec_idx;
		uint8_t *p;

		offset = *current_offset;
		vec_idx = (uint_t)(uintptr_t)(*iov_or_mp);
		iov = &uio->uio_iov[vec_idx];
		p = (uint8_t *)iov->iov_base + offset;
		*out_data_1 = p;

		if (offset + BLOWFISH_BLOCK_LEN <= iov->iov_len) {
			/* can fit one BLOWFISH block into this iov */
			*out_data_1_len = BLOWFISH_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + BLOWFISH_BLOCK_LEN;
		} else {
			/* one BLOWFISH block spans two iovecs */
			*out_data_1_len = iov->iov_len - offset;
			if (vec_idx == uio->uio_iovcnt)
				return;
			vec_idx++;
			iov = &uio->uio_iov[vec_idx];
			*out_data_2 = (uint8_t *)iov->iov_base;
			*current_offset = BLOWFISH_BLOCK_LEN - *out_data_1_len;
		}
		*iov_or_mp = (void *)(uintptr_t)vec_idx;
		break;
	}

	case CRYPTO_DATA_MBLK: {
		mblk_t *mp;
		uint8_t *p;

		offset = *current_offset;
		mp = (mblk_t *)*iov_or_mp;
		p = mp->b_rptr + offset;
		*out_data_1 = p;
		if ((p + BLOWFISH_BLOCK_LEN) <= mp->b_wptr) {
			/* can fit one BLOWFISH block into this mblk */
			*out_data_1_len = BLOWFISH_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + BLOWFISH_BLOCK_LEN;
		} else {
			/* one BLOWFISH block spans two mblks */
			*out_data_1_len = mp->b_wptr - p;
			if ((mp = mp->b_cont) == NULL)
				return;
			*out_data_2 = mp->b_rptr;
			*current_offset = BLOWFISH_BLOCK_LEN - *out_data_1_len;
		}
		*iov_or_mp = mp;
		break;
	}
	} /* end switch */
}

/*
 * Encrypt multiple blocks of data.
 */
static int
blowfish_encrypt_contiguous_blocks(blowfish_ctx_t *ctx, char *data,
    size_t length, crypto_data_t *out)
{
/* EXPORT DELETE START */
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	uint32_t tmp[2];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->bc_remainder_len < BLOWFISH_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)&ctx->bc_remainder + ctx->bc_remainder_len,
		    length);
		ctx->bc_remainder_len += length;
		ctx->bc_copy_to = datap;
		return (0);
	}

	lastp = (uint8_t *)&ctx->bc_iv;
	if (out != NULL)
		blowfish_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->bc_remainder_len > 0) {
			need = BLOWFISH_BLOCK_LEN - ctx->bc_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)&ctx->bc_remainder)
			    [ctx->bc_remainder_len], need);

			blockp = (uint8_t *)&ctx->bc_remainder;
		} else {
			blockp = datap;
		}

		/* don't write on the plaintext */
		if (out != NULL) {
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				tmp[0] = *(uint32_t *)blockp;
				/* LINTED: pointer alignment */
				tmp[1] = *(uint32_t *)&blockp[4];
			} else {
#ifdef _BIG_ENDIAN
				tmp[0] = (((uint32_t)blockp[0] << 24) |
				    ((uint32_t)blockp[1] << 16) |
				    ((uint32_t)blockp[2] << 8) |
				    (uint32_t)blockp[3]);

				tmp[1] = (((uint32_t)blockp[4] << 24) |
				    ((uint32_t)blockp[5] << 16) |
				    ((uint32_t)blockp[6] << 8) |
				    (uint32_t)blockp[7]);
#else
				tmp[0] = (((uint32_t)blockp[7] << 24) |
				    ((uint32_t)blockp[6] << 16) |
				    ((uint32_t)blockp[5] << 8) |
				    (uint32_t)blockp[4]);

				tmp[1] = (((uint32_t)blockp[3] << 24) |
				    ((uint32_t)blockp[2] << 16) |
				    ((uint32_t)blockp[1] << 8) |
				    (uint32_t)blockp[0]);
#endif /* _BIG_ENDIAN */
			}
			blockp = (uint8_t *)tmp;
		}

		if (ctx->bc_flags & BLOWFISH_CBC_MODE) {
			/*
			 * XOR the previous cipher block or IV with the
			 * current clear block. Check for alignment.
			 */
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
			    IS_P2ALIGNED(lastp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[0] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[0];
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[4] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[4];
			} else {
				BLOWFISH_XOR_BLOCK(lastp, blockp);
			}
		}

		if (out == NULL) {
			blowfish_encrypt_block(ctx->bc_keysched, blockp,
			    blockp);

			ctx->bc_lastp = blockp;
			lastp = blockp;

			if (ctx->bc_remainder_len > 0) {
				bcopy(blockp, ctx->bc_copy_to,
				    ctx->bc_remainder_len);
				bcopy(blockp + ctx->bc_remainder_len, datap,
				    need);
			}
		} else {
			blowfish_encrypt_block(ctx->bc_keysched, blockp, lastp);
			blowfish_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2);

			/* copy block to where it belongs */
			bcopy(lastp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(lastp + out_data_1_len, out_data_2,
				    BLOWFISH_BLOCK_LEN - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += BLOWFISH_BLOCK_LEN;
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->bc_remainder_len != 0) {
			datap += need;
			ctx->bc_remainder_len = 0;
		} else {
			datap += BLOWFISH_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < BLOWFISH_BLOCK_LEN) {
			bcopy(datap, &ctx->bc_remainder, remainder);
			ctx->bc_remainder_len = remainder;
			ctx->bc_copy_to = datap;
			goto out;
		}
		ctx->bc_copy_to = NULL;

	} while (remainder > 0);

out:
	if (ctx->bc_lastp != NULL) {
		if (IS_P2ALIGNED(ctx->bc_lastp, sizeof (uint32_t))) {
			uint8_t *iv8 = (uint8_t *)&ctx->bc_iv;
			uint8_t *last8 = (uint8_t *)ctx->bc_lastp;

			/* LINTED: pointer alignment */
			*(uint32_t *)iv8 = *(uint32_t *)last8;
			/* LINTED: pointer alignment */
			*(uint32_t *)&iv8[4] = *(uint32_t *)&last8[4];
		} else {
			uint8_t *iv8 = (uint8_t *)&ctx->bc_iv;
			uint8_t *last8 = ctx->bc_lastp;

			BLOWFISH_COPY_BLOCK(last8, iv8);
		}
		ctx->bc_lastp = (uint8_t *)&ctx->bc_iv;
	}
/* EXPORT DELETE END */

	return (0);
}

#define	OTHER(a, ctx) \
	(((a) == &(ctx)->bc_lastblock) ? &(ctx)->bc_iv : &(ctx)->bc_lastblock)

static int
blowfish_decrypt_contiguous_blocks(blowfish_ctx_t *ctx, char *data,
    size_t length, crypto_data_t *out)
{
/* EXPORT DELETE START */
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	uint32_t tmp[2];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->bc_remainder_len < BLOWFISH_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)&ctx->bc_remainder + ctx->bc_remainder_len,
		    length);
		ctx->bc_remainder_len += length;
		ctx->bc_copy_to = datap;
		return (0);
	}

	lastp = ctx->bc_lastp;
	if (out != NULL)
		blowfish_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->bc_remainder_len > 0) {
			need = BLOWFISH_BLOCK_LEN - ctx->bc_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)&ctx->bc_remainder)
			    [ctx->bc_remainder_len], need);

			blockp = (uint8_t *)&ctx->bc_remainder;
		} else {
			blockp = datap;
		}

		if (ctx->bc_flags & BLOWFISH_CBC_MODE) {

			/* Save current ciphertext block */
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t))) {
				uint32_t *tmp32;

				/* LINTED: pointer alignment */
				tmp32 = (uint32_t *)OTHER((uint64_t *)lastp,
				    ctx);

				/* LINTED: pointer alignment */
				*tmp32++ = *(uint32_t *)blockp;
				/* LINTED: pointer alignment */
				*tmp32++ = *(uint32_t *)&blockp[4];
			} else {
				uint8_t *tmp8;
				tmp8 = (uint8_t *)OTHER((uint64_t *)lastp, ctx);

				BLOWFISH_COPY_BLOCK(blockp, tmp8);
			}
		}

		if (out != NULL) {
			blowfish_decrypt_block(ctx->bc_keysched, blockp,
			    (uint8_t *)tmp);
			blockp = (uint8_t *)tmp;
		} else {
			blowfish_decrypt_block(ctx->bc_keysched, blockp,
			    blockp);
		}

		if (ctx->bc_flags & BLOWFISH_CBC_MODE) {
			/*
			 * XOR the previous cipher block or IV with the
			 * currently decrypted block.  Check for alignment.
			 */
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
			    IS_P2ALIGNED(lastp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				*(uint32_t *)blockp ^= *(uint32_t *)lastp;
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[4] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[4];
			} else {
				BLOWFISH_XOR_BLOCK(lastp, blockp);
			}

			/* LINTED: pointer alignment */
			lastp = (uint8_t *)OTHER((uint64_t *)lastp, ctx);
		}

		if (out != NULL) {
			blowfish_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2);
			/* copy temporary block to where it belongs */
			bcopy(&tmp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy((uint8_t *)&tmp + out_data_1_len,
				    out_data_2,
				    BLOWFISH_BLOCK_LEN - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += BLOWFISH_BLOCK_LEN;
		} else if (ctx->bc_remainder_len > 0) {
			/* copy temporary block to where it belongs */
			bcopy(blockp, ctx->bc_copy_to, ctx->bc_remainder_len);
			bcopy(blockp + ctx->bc_remainder_len, datap, need);
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->bc_remainder_len != 0) {
			datap += need;
			ctx->bc_remainder_len = 0;
		} else {
			datap += BLOWFISH_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < BLOWFISH_BLOCK_LEN) {
			bcopy(datap, (uchar_t *)&ctx->bc_remainder, remainder);
			ctx->bc_remainder_len = remainder;
			ctx->bc_lastp = lastp;
			ctx->bc_copy_to = datap;
			return (0);
		}
		ctx->bc_copy_to = NULL;

	} while (remainder > 0);

	ctx->bc_lastp = lastp;
/* EXPORT DELETE END */
	return (0);
}

/* ARGSUSED */
static int
blowfish_common_init_ctx(blowfish_ctx_t *blowfish_ctx,
    crypto_spi_ctx_template_t *template, crypto_mechanism_t *mechanism,
    crypto_key_t *key, int kmflag)
{
	int rv = CRYPTO_SUCCESS;

/* EXPORT DELETE START */

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

		blowfish_ctx->bc_flags = BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE;
		blowfish_ctx->bc_keysched_len = size;
	} else {
		keysched = template;
	}

	if (mechanism->cm_type == BF_CBC_MECH_INFO_TYPE) {
		/*
		 * Copy IV into BLOWFISH context.
		 *
		 * If cm_param == NULL then the IV comes from the
		 * cd_miscdata field in the crypto_data structure.
		 */
		if (mechanism->cm_param != NULL) {
			ASSERT(mechanism->cm_param_len == BLOWFISH_BLOCK_LEN);
			if (IS_P2ALIGNED(mechanism->cm_param,
			    sizeof (uint64_t))) {
				/* LINTED: pointer alignment */
				blowfish_ctx->bc_iv =
				    *(uint64_t *)mechanism->cm_param;
			} else {
				uint8_t *iv8;
				uint8_t *p8;
				iv8 = (uint8_t *)&blowfish_ctx->bc_iv;
				p8 = (uint8_t *)&mechanism->cm_param[0];

				BLOWFISH_COPY_BLOCK(p8, iv8);
			}
		}

		blowfish_ctx->bc_lastp = (uint8_t *)&blowfish_ctx->bc_iv;
		blowfish_ctx->bc_flags |= BLOWFISH_CBC_MODE;
	}
	blowfish_ctx->bc_keysched = keysched;

/* EXPORT DELETE END */

	return (rv);
}
