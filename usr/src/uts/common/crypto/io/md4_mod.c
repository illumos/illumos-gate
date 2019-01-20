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
 * In kernel module, the md4 module is created with one modlinkage,
 * this is different to md5 and sha1 modules which have a legacy misc
 * variant for direct calls to the Init/Update/Final routines.
 *
 * - a modlcrypto that allows the module to register with the Kernel
 *   Cryptographic Framework (KCF) as a software provider for the MD4
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
#include <sys/md4.h>

extern struct mod_ops mod_miscops;
extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"MD4 Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */

typedef enum md4_mech_type {
	MD4_MECH_INFO_TYPE,		/* SUN_CKM_MD4 */
} md4_mech_type_t;

#define	MD4_DIGEST_LENGTH	16	/* MD4 digest length in bytes */

/*
 * Context for MD4 mechanism.
 */
typedef struct md4_ctx {
	md4_mech_type_t		mc_mech_type;	/* type of context */
	MD4_CTX			mc_md4_ctx;	/* MD4 context */
} md4_ctx_t;

/*
 * Macros to access the MD4 contexts from a context passed
 * by KCF to one of the entry points.
 */

#define	PROV_MD4_CTX(ctx)	((md4_ctx_t *)(ctx)->cc_provider_private)

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t md4_mech_info_tab[] = {
	/* MD4 */
	{SUN_CKM_MD4, MD4_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
};

static void md4_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t md4_control_ops = {
	md4_provider_status
};

static int md4_digest_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_req_handle_t);
static int md4_digest(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int md4_digest_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int md4_digest_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int md4_digest_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

static crypto_digest_ops_t md4_digest_ops = {
	md4_digest_init,
	md4_digest,
	md4_digest_update,
	NULL,
	md4_digest_final,
	md4_digest_atomic
};

static crypto_ops_t md4_crypto_ops = {
	&md4_control_ops,
	&md4_digest_ops,
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
	NULL,
	NULL,
};

static crypto_provider_info_t md4_prov_info = {
	CRYPTO_SPI_VERSION_1,
	"MD4 Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&md4_crypto_ops,
	sizeof (md4_mech_info_tab)/sizeof (crypto_mech_info_t),
	md4_mech_info_tab
};

static crypto_kcf_provider_handle_t md4_prov_handle = 0;

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/* Register with KCF.  If the registration fails, remove the module. */
	if (crypto_register_provider(&md4_prov_info, &md4_prov_handle)) {
		(void) mod_remove(&modlinkage);
		return (EACCES);
	}

	return (0);
}

int
_fini(void)
{
	/* Unregister from KCF if module is registered */
	if (md4_prov_handle != 0) {
		if (crypto_unregister_provider(md4_prov_handle))
			return (EBUSY);

		md4_prov_handle = 0;
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
md4_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF software provider digest entry points.
 */

static int
md4_digest_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_req_handle_t req)
{
	if (mechanism->cm_type != MD4_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/*
	 * Allocate and initialize MD4 context.
	 */
	ctx->cc_provider_private = kmem_alloc(sizeof (md4_ctx_t),
	    crypto_kmflag(req));
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_HOST_MEMORY);

	PROV_MD4_CTX(ctx)->mc_mech_type = MD4_MECH_INFO_TYPE;
	MD4Init(&PROV_MD4_CTX(ctx)->mc_md4_ctx);

	return (CRYPTO_SUCCESS);
}

/*
 * Helper MD4 digest update function for uio data.
 */
static int
md4_digest_update_uio(MD4_CTX *md4_ctx, crypto_data_t *data)
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

		MD4Update(md4_ctx, data->cd_uio->uio_iov[vec_idx].iov_base +
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
 * Helper MD4 digest final function for uio data.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default MD4 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least MD4_DIGEST_LENGTH bytes.
 */
static int
md4_digest_final_uio(MD4_CTX *md4_ctx, crypto_data_t *digest,
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
		 * The computed MD4 digest will fit in the current
		 * iovec.
		 */
		if (digest_len != MD4_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			MD4Final(digest_scratch, md4_ctx);
			bcopy(digest_scratch, (uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    digest_len);
		} else {
			MD4Final((uchar_t *)digest->
			    cd_uio->uio_iov[vec_idx].iov_base + offset,
			    md4_ctx);
		}
	} else {
		/*
		 * The computed digest will be crossing one or more iovec's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[MD4_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		MD4Final(digest_tmp, md4_ctx);

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
 * Helper MD4 digest update for mblk's.
 */
static int
md4_digest_update_mblk(MD4_CTX *md4_ctx, crypto_data_t *data)
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
		MD4Update(md4_ctx, mp->b_rptr + offset, cur_len);
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
 * Helper MD4 digest final for mblk's.
 * digest_len is the length of the desired digest. If digest_len
 * is smaller than the default MD4 digest length, the caller
 * must pass a scratch buffer, digest_scratch, which must
 * be at least MD4_DIGEST_LENGTH bytes.
 */
static int
md4_digest_final_mblk(MD4_CTX *md4_ctx, crypto_data_t *digest,
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
		 * The computed MD4 digest will fit in the current mblk.
		 * Do the MD4Final() in-place.
		 */
		if (digest_len != MD4_DIGEST_LENGTH) {
			/*
			 * The caller requested a short digest. Digest
			 * into a scratch buffer and return to
			 * the user only what was requested.
			 */
			MD4Final(digest_scratch, md4_ctx);
			bcopy(digest_scratch, mp->b_rptr + offset, digest_len);
		} else {
			MD4Final(mp->b_rptr + offset, md4_ctx);
		}
	} else {
		/*
		 * The computed digest will be crossing one or more mblk's.
		 * This is bad performance-wise but we need to support it.
		 * Allocate a small scratch buffer on the stack and
		 * copy it piece meal to the specified digest iovec's.
		 */
		uchar_t digest_tmp[MD4_DIGEST_LENGTH];
		off_t scratch_offset = 0;
		size_t length = digest_len;
		size_t cur_len;

		MD4Final(digest_tmp, md4_ctx);

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
md4_digest(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < MD4_DIGEST_LENGTH)) {
		digest->cd_length = MD4_DIGEST_LENGTH;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do the MD4 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		MD4Update(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = md4_digest_update_uio(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md4_digest_update_mblk(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret != CRYPTO_SUCCESS) {
		/* the update failed, free context and bail */
		kmem_free(ctx->cc_provider_private, sizeof (md4_ctx_t));
		ctx->cc_provider_private = NULL;
		digest->cd_length = 0;
		return (ret);
	}

	/*
	 * Do an MD4 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		MD4Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_MD4_CTX(ctx)->mc_md4_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = md4_digest_final_uio(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    digest, MD4_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md4_digest_final_mblk(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    digest, MD4_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = MD4_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (md4_ctx_t));
	ctx->cc_provider_private = NULL;
	return (ret);
}

/* ARGSUSED */
static int
md4_digest_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * Do the MD4 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		MD4Update(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = md4_digest_update_uio(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md4_digest_update_mblk(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    data);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/* ARGSUSED */
static int
md4_digest_final(crypto_ctx_t *ctx, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following cases.
	 */
	if ((digest->cd_length == 0) ||
	    (digest->cd_length < MD4_DIGEST_LENGTH)) {
		digest->cd_length = MD4_DIGEST_LENGTH;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	/*
	 * Do an MD4 final.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		MD4Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &PROV_MD4_CTX(ctx)->mc_md4_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = md4_digest_final_uio(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    digest, MD4_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md4_digest_final_mblk(&PROV_MD4_CTX(ctx)->mc_md4_ctx,
		    digest, MD4_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/* all done, free context and return */

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = MD4_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	kmem_free(ctx->cc_provider_private, sizeof (md4_ctx_t));
	ctx->cc_provider_private = NULL;

	return (ret);
}

/* ARGSUSED */
static int
md4_digest_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int ret = CRYPTO_SUCCESS;
	MD4_CTX md4_ctx;

	if (mechanism->cm_type != MD4_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	/*
	 * Do the MD4 init.
	 */
	MD4Init(&md4_ctx);

	/*
	 * Do the MD4 update on the specified input data.
	 */
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		MD4Update(&md4_ctx, data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length);
		break;
	case CRYPTO_DATA_UIO:
		ret = md4_digest_update_uio(&md4_ctx, data);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md4_digest_update_mblk(&md4_ctx, data);
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
	 * Do an MD4 final, must be done separately since the digest
	 * type can be different than the input data type.
	 */
	switch (digest->cd_format) {
	case CRYPTO_DATA_RAW:
		MD4Final((unsigned char *)digest->cd_raw.iov_base +
		    digest->cd_offset, &md4_ctx);
		break;
	case CRYPTO_DATA_UIO:
		ret = md4_digest_final_uio(&md4_ctx, digest,
		    MD4_DIGEST_LENGTH, NULL);
		break;
	case CRYPTO_DATA_MBLK:
		ret = md4_digest_final_mblk(&md4_ctx, digest,
		    MD4_DIGEST_LENGTH, NULL);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		digest->cd_length = MD4_DIGEST_LENGTH;
	} else {
		digest->cd_length = 0;
	}

	return (ret);
}
