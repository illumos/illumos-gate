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
 * RC4 provider for the Kernel Cryptographic Framework (KCF)
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
#include <arcfour.h>

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"RC4 Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */

#define	RC4_MECH_INFO_TYPE	0
/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t rc4_mech_info_tab[] = {
	{SUN_CKM_RC4, RC4_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    ARCFOUR_MIN_KEY_BITS, ARCFOUR_MAX_KEY_BITS,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS | CRYPTO_CAN_SHARE_OPSTATE}
};

static void rc4_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t rc4_control_ops = {
	rc4_provider_status
};

static int rc4_common_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int rc4_crypt_update(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

static int rc4_crypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);

static int rc4_crypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

static int rc4_crypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);


static crypto_cipher_ops_t rc4_cipher_ops = {
	rc4_common_init,
	rc4_crypt,
	rc4_crypt_update,
	rc4_crypt_final,
	rc4_crypt_atomic,
	rc4_common_init,
	rc4_crypt,
	rc4_crypt_update,
	rc4_crypt_final,
	rc4_crypt_atomic
};

static int rc4_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t rc4_ctx_ops = {
	NULL,
	rc4_free_context
};

static crypto_ops_t rc4_crypto_ops = {
	&rc4_control_ops,
	NULL,
	&rc4_cipher_ops,
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
	&rc4_ctx_ops
};

static crypto_provider_info_t rc4_prov_info = {
	CRYPTO_SPI_VERSION_1,
	"RC4 Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&rc4_crypto_ops,
	sizeof (rc4_mech_info_tab)/sizeof (crypto_mech_info_t),
	rc4_mech_info_tab
};

static crypto_kcf_provider_handle_t rc4_prov_handle = 0;

static mblk_t *advance_position(mblk_t *, off_t, uchar_t **);
static int crypto_arcfour_crypt(ARCFour_key *, uchar_t *, crypto_data_t *,
    int);

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/* Register with KCF.  If the registration fails, remove the module. */
	if (crypto_register_provider(&rc4_prov_info, &rc4_prov_handle)) {
		(void) mod_remove(&modlinkage);
		return (EACCES);
	}

	return (0);
}

int
_fini(void)
{
	/* Unregister from KCF if module is registered */
	if (rc4_prov_handle != 0) {
		if (crypto_unregister_provider(rc4_prov_handle))
			return (EBUSY);

		rc4_prov_handle = 0;
	}

	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
rc4_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/* ARGSUSED */
static int
rc4_common_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{
	ARCFour_key *keystream;

	if ((mechanism)->cm_type != RC4_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if (key->ck_format != CRYPTO_KEY_RAW)
		return (CRYPTO_KEY_TYPE_INCONSISTENT);

	if (key->ck_length < ARCFOUR_MIN_KEY_BITS ||
	    key->ck_length > ARCFOUR_MAX_KEY_BITS) {
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/*
	 * Allocate an RC4 key stream.
	 */
	if ((keystream = kmem_alloc(sizeof (ARCFour_key),
	    crypto_kmflag(req))) == NULL)
		return (CRYPTO_HOST_MEMORY);

	arcfour_key_init(keystream, key->ck_data,
	    CRYPTO_BITS2BYTES(key->ck_length));

	ctx->cc_provider_private = keystream;

	return (CRYPTO_SUCCESS);
}

static int
rc4_crypt(crypto_ctx_t *ctx, crypto_data_t *input, crypto_data_t *output,
    crypto_req_handle_t req)
{
	int ret;

	ret = rc4_crypt_update(ctx, input, output, req);

	if (ret != CRYPTO_BUFFER_TOO_SMALL)
		(void) rc4_free_context(ctx);

	return (ret);
}

/* ARGSUSED */
static int
rc4_crypt_update(crypto_ctx_t *ctx, crypto_data_t *input, crypto_data_t *output,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ARCFour_key *key;
	off_t saveoffset;

	ASSERT(ctx->cc_provider_private != NULL);

	if ((ctx->cc_flags & CRYPTO_USE_OPSTATE) && ctx->cc_opstate != NULL)
		key = ctx->cc_opstate;
	else
		key = ctx->cc_provider_private;

	/* Simple case: in-line encipherment */

	if (output == NULL) {
		switch (input->cd_format) {
		case CRYPTO_DATA_RAW: {
			char *start, *end;
			start = input->cd_raw.iov_base + input->cd_offset;

			end =  input->cd_raw.iov_base + input->cd_raw.iov_len;

			if (start + input->cd_length > end)
				return (CRYPTO_DATA_INVALID);

			arcfour_crypt(key, (uchar_t *)start, (uchar_t *)start,
			    input->cd_length);
			break;
		}
		case CRYPTO_DATA_MBLK: {
			uchar_t *start, *end;
			size_t len, left;
			mblk_t *mp = input->cd_mp, *mp1, *mp2;

			ASSERT(mp != NULL);

			mp1 = advance_position(mp, input->cd_offset, &start);

			if (mp1 == NULL)
				return (CRYPTO_DATA_LEN_RANGE);

			mp2 = advance_position(mp, input->cd_offset +
			    input->cd_length, &end);

			if (mp2 == NULL)
				return (CRYPTO_DATA_LEN_RANGE);

			left = input->cd_length;
			while (mp1 != NULL) {
				if (_PTRDIFF(mp1->b_wptr, start) > left) {
					len = left;
					arcfour_crypt(key, start, start, len);
					mp1 = NULL;
				} else {
					len = _PTRDIFF(mp1->b_wptr, start);
					arcfour_crypt(key, start, start, len);
					mp1 = mp1->b_cont;
					start = mp1->b_rptr;
					left -= len;
				}
			}
			break;
		}
		case CRYPTO_DATA_UIO: {
			uio_t *uiop = input->cd_uio;
			off_t offset = input->cd_offset;
			size_t length = input->cd_length;
			uint_t vec_idx;
			size_t cur_len;

			/*
			 * Jump to the first iovec containing data to be
			 * processed.
			 */
			for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
			    offset >= uiop->uio_iov[vec_idx].iov_len;
			    offset -= uiop->uio_iov[vec_idx++].iov_len)
				;
			if (vec_idx == uiop->uio_iovcnt) {
				return (CRYPTO_DATA_LEN_RANGE);
			}

			/*
			 * Now process the iovecs.
			 */
			while (vec_idx < uiop->uio_iovcnt && length > 0) {
				uchar_t *start;
				iovec_t *iovp = &(uiop->uio_iov[vec_idx]);

				cur_len = MIN(iovp->iov_len - offset, length);

				start = (uchar_t *)(iovp->iov_base + offset);
				arcfour_crypt(key, start + offset,
				    start + offset, cur_len);

				length -= cur_len;
				vec_idx++;
				offset = 0;
			}

			if (vec_idx == uiop->uio_iovcnt && length > 0) {

				return (CRYPTO_DATA_LEN_RANGE);
			}
			break;
		}
		}
		return (CRYPTO_SUCCESS);
	}

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */

	if (input->cd_length > output->cd_length) {
		output->cd_length = input->cd_length;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saveoffset = output->cd_offset;

	switch (input->cd_format) {
	case CRYPTO_DATA_RAW: {
		char *start, *end;
		start = input->cd_raw.iov_base + input->cd_offset;

		end =  input->cd_raw.iov_base + input->cd_raw.iov_len;

		if (start + input->cd_length > end)
			return (CRYPTO_DATA_LEN_RANGE);

		ret = crypto_arcfour_crypt(key, (uchar_t *)start, output,
		    input->cd_length);

		if (ret != CRYPTO_SUCCESS)
			return (ret);
		break;
	}
	case CRYPTO_DATA_MBLK: {
		uchar_t *start, *end;
		size_t len, left;
		mblk_t *mp = input->cd_mp, *mp1, *mp2;

		ASSERT(mp != NULL);

		mp1 = advance_position(mp, input->cd_offset, &start);

		if (mp1 == NULL)
			return (CRYPTO_DATA_LEN_RANGE);

		mp2 = advance_position(mp, input->cd_offset + input->cd_length,
		    &end);

		if (mp2 == NULL)
			return (CRYPTO_DATA_LEN_RANGE);

		left = input->cd_length;
		while (mp1 != NULL) {
			if (_PTRDIFF(mp1->b_wptr, start) > left) {
				len = left;
				ret = crypto_arcfour_crypt(key, start, output,
				    len);
				if (ret != CRYPTO_SUCCESS)
					return (ret);
				mp1 = NULL;
			} else {
				len = _PTRDIFF(mp1->b_wptr, start);
				ret = crypto_arcfour_crypt(key, start, output,
				    len);
				if (ret != CRYPTO_SUCCESS)
					return (ret);
				mp1 = mp1->b_cont;
				start = mp1->b_rptr;
				left -= len;
				output->cd_offset += len;
			}
		}
		break;
	}
	case CRYPTO_DATA_UIO: {
		uio_t *uiop = input->cd_uio;
		off_t offset = input->cd_offset;
		size_t length = input->cd_length;
		uint_t vec_idx;
		size_t cur_len;

		/*
		 * Jump to the first iovec containing data to be
		 * processed.
		 */
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    offset >= uiop->uio_iov[vec_idx].iov_len;
		    offset -= uiop->uio_iov[vec_idx++].iov_len)
			;
		if (vec_idx == uiop->uio_iovcnt) {
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && length > 0) {
			uchar_t *start;
			iovec_t *iovp = &(uiop->uio_iov[vec_idx]);
			cur_len = MIN(iovp->iov_len - offset, length);

			start = (uchar_t *)(iovp->iov_base + offset);
			ret = crypto_arcfour_crypt(key, start + offset,
			    output, cur_len);
			if (ret != CRYPTO_SUCCESS)
				return (ret);

			length -= cur_len;
			vec_idx++;
			offset = 0;
			output->cd_offset += cur_len;
		}

		if (vec_idx == uiop->uio_iovcnt && length > 0) {

			return (CRYPTO_DATA_LEN_RANGE);
		}
	}
	}

	output->cd_offset = saveoffset;
	output->cd_length = input->cd_length;

	return (ret);
}

/* ARGSUSED */
static int rc4_crypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	/* No final part for streams ciphers. Just free the context */
	if (data != NULL)
		data->cd_length = 0;

	return (rc4_free_context(ctx));
}

/* ARGSUSED */
static int
rc4_crypt_atomic(crypto_provider_handle_t handle, crypto_session_id_t session,
    crypto_mechanism_t *mechanism, crypto_key_t *key, crypto_data_t *input,
    crypto_data_t *output, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{
	crypto_ctx_t ctx;
	int ret;

	bzero(&ctx, sizeof (crypto_ctx_t));
	ret = rc4_common_init(&ctx, mechanism, key, template, req);

	if (ret != CRYPTO_SUCCESS)
		return (ret);

	ret = rc4_crypt_update(&ctx, input, output, req);

	(void) rc4_free_context(&ctx);

	return (ret);
}

/* ARGSUSED */
static int
rc4_free_context(crypto_ctx_t *ctx)
{
	ARCFour_key *keystream = ctx->cc_provider_private;

	if (keystream != NULL) {
		bzero(keystream, sizeof (ARCFour_key));
		kmem_free(keystream, sizeof (ARCFour_key));
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

/* Encrypts a contiguous input 'in' into the 'out' crypto_data_t */

static int
crypto_arcfour_crypt(ARCFour_key *key, uchar_t *in, crypto_data_t *out,
    int length)
{
	switch (out->cd_format) {
		case CRYPTO_DATA_RAW: {
			uchar_t *start, *end;
			start = (uchar_t *)(out->cd_raw.iov_base +
			    out->cd_offset);

			end = (uchar_t *)(out->cd_raw.iov_base +
			    out->cd_raw.iov_len);

			if (start + out->cd_length > end)
				return (CRYPTO_DATA_LEN_RANGE);

			arcfour_crypt(key, in, start, length);

			return (CRYPTO_SUCCESS);
		}
		case CRYPTO_DATA_MBLK: {
			uchar_t *start, *end;
			size_t len, left;
			mblk_t *mp = out->cd_mp, *mp1, *mp2;

			ASSERT(mp != NULL);

			mp1 = advance_position(mp, out->cd_offset, &start);

			if (mp1 == NULL)
				return (CRYPTO_DATA_LEN_RANGE);

			mp2 = advance_position(mp, out->cd_offset +
			    out->cd_length, &end);

			if (mp2 == NULL)
				return (CRYPTO_DATA_LEN_RANGE);

			left = length;
			while (mp1 != NULL) {
				if (_PTRDIFF(mp1->b_wptr, start) > left) {
					len = left;
					arcfour_crypt(key, in, start, len);
					mp1 = NULL;
				} else {
					len = _PTRDIFF(mp1->b_wptr, start);
					arcfour_crypt(key, in, start, len);
					mp1 = mp1->b_cont;
					start = mp1->b_rptr;
					left -= len;
				}
			}
			break;
		}
		case CRYPTO_DATA_UIO: {
			uio_t *uiop = out->cd_uio;
			off_t offset = out->cd_offset;
			size_t len = length;
			uint_t vec_idx;
			size_t cur_len;

			/*
			 * Jump to the first iovec containing data to be
			 * processed.
			 */
			for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
			    offset >= uiop->uio_iov[vec_idx].iov_len;
			    offset -= uiop->uio_iov[vec_idx++].iov_len)
				;
			if (vec_idx == uiop->uio_iovcnt) {
				return (CRYPTO_DATA_LEN_RANGE);
			}

			/*
			 * Now process the iovecs.
			 */
			while (vec_idx < uiop->uio_iovcnt && len > 0) {
				uchar_t *start;
				iovec_t *iovp = &(uiop->uio_iov[vec_idx]);
				cur_len = MIN(iovp->iov_len - offset, len);

				start = (uchar_t *)(iovp->iov_base + offset);
				arcfour_crypt(key, start + offset,
				    start + offset, cur_len);

				len -= cur_len;
				vec_idx++;
				offset = 0;
			}

			if (vec_idx == uiop->uio_iovcnt && len > 0) {
				return (CRYPTO_DATA_LEN_RANGE);
			}
			break;
		}
		default:
			return (CRYPTO_DATA_INVALID);
	}
	return (CRYPTO_SUCCESS);
}

/*
 * Advances 'offset' bytes from the beginning of the first block in 'mp',
 * possibly jumping across b_cont boundary
 * '*cpp' is set to the position of the byte we want, and the block where
 * 'cpp' is returned.
 */
static mblk_t *
advance_position(mblk_t *mp, off_t offset, uchar_t **cpp)
{
	mblk_t *mp1 = mp;
	size_t l;
	off_t o = offset;

	while (mp1 != NULL) {
		l = MBLKL(mp1);

		if (l <= o) {
			o -= l;
			mp1 = mp1->b_cont;
		} else {
			*cpp = (uchar_t *)(mp1->b_rptr + o);
			break;
		}
	}
	return (mp1);
}
