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
 * In kernel module, the md5 module is created with two modlinkages:
 * - a modlmisc that allows consumers to directly call the entry points
 *   MD5Init, MD5Update, and MD5Final.
 * - a modlcrypto that allows the module to register with the Kernel
 *   Cryptographic Framework (KCF) as a software provider for the MD5
 *   mechanisms.
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
#include <sys/md5.h>

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
	"MD5 Kernel SW Provider"
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
#define	MD5_HMAC_MIN_KEY_LEN	1	/* MD5-HMAC min key length in bytes */
#define	MD5_HMAC_MAX_KEY_LEN	INT_MAX	/* MD5-HMAC max key length in bytes */
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
		(len) = (uint32_t)*((ulong_t *)(void *)mechanism->cm_param); \
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
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* MD5-HMAC GENERAL */
	{SUN_CKM_MD5_HMAC_GENERAL, MD5_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    MD5_HMAC_MIN_KEY_LEN, MD5_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES}
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

static crypto_kcf_provider_handle_t md5_prov_handle = 0;

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/*
	 * Register with KCF.  If the registration fails, do not uninstall the
	 * module, since the functionality provided by misc/md5 should still be
	 * available.
	 */
	(void) crypto_register_provider(&md5_prov_info, &md5_prov_handle);

	return (0);
}

int
_fini(void)
{
	int ret;

	/*
	 * Unregister from KCF if previous registration succeeded.
	 */
	if (md5_prov_handle != 0) {
		if ((ret = crypto_unregister_provider(md5_prov_handle)) !=
		    CRYPTO_SUCCESS)
			return (ret);

		md5_prov_handle = 0;
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
	    offset -= data->cd_uio->uio_iov[vec_idx++].iov_len)
		;
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
	    offset -= digest->cd_uio->uio_iov[vec_idx++].iov_len)
		;
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
	    offset -= MBLKL(mp), mp = mp->b_cont)
		;
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
		    offset -= mac->cd_uio->uio_iov[vec_idx++].iov_len)
			;
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
		    offset -= MBLKL(mp), mp = mp->b_cont)
			;
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
