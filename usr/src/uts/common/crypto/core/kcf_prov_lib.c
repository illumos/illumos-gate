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
 *
 * Copyright 2023-2026 RackTop Systems, Inc.
 */

#include <sys/strsun.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/sha2.h>
#include <modes/modes.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>

/*
 * Utility routine to get data from a crypto_data structure.
 *
 * '*dptr' contains a pointer to a buffer on return. 'buf'
 * is allocated by the caller and is ignored for CRYPTO_DATA_RAW case.
 */
int
crypto_get_input_data(crypto_data_t *input, uchar_t **dptr, uchar_t *buf)
{
	int rv;

	switch (input->cd_format) {
	case CRYPTO_DATA_RAW:
		if (input->cd_raw.iov_len < input->cd_length)
			return (CRYPTO_ARGUMENTS_BAD);
		*dptr = (uchar_t *)(input->cd_raw.iov_base +
		    input->cd_offset);
		break;

	case CRYPTO_DATA_UIO:
		if ((rv = crypto_uio_data(input, buf, input->cd_length,
		    COPY_FROM_DATA, NULL, NULL)) != CRYPTO_SUCCESS)
			return (rv);
		*dptr = buf;
		break;

	case CRYPTO_DATA_MBLK:
		if ((rv = crypto_mblk_data(input, buf, input->cd_length,
		    COPY_FROM_DATA, NULL, NULL)) != CRYPTO_SUCCESS)
			return (rv);
		*dptr = buf;
		break;

	default:
		return (CRYPTO_ARGUMENTS_BAD);
	}

	return (CRYPTO_SUCCESS);
}

int
crypto_compare_data(crypto_data_t *data, uchar_t *buf, size_t len)
{
	uchar_t *dptr;

	if (len > INT32_MAX)
		return (CRYPTO_DATA_LEN_RANGE);

	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		dptr = (uchar_t *)(data->cd_raw.iov_base +
		    data->cd_offset);

		if (data->cd_raw.iov_len < data->cd_length ||
		    data->cd_length < len)
			return (CRYPTO_DATA_LEN_RANGE);

		return (bcmp(dptr, buf, len));

	case CRYPTO_DATA_UIO:
		return (crypto_uio_data(data, buf, len,
		    COMPARE_TO_DATA, NULL, NULL));

	case CRYPTO_DATA_MBLK:
		return (crypto_mblk_data(data, buf, len,
		    COMPARE_TO_DATA, NULL, NULL));
	}

	return (CRYPTO_FAILED);
}

int
crypto_copy_key_to_ctx(crypto_key_t *in_key, crypto_key_t **out_key,
    size_t *out_size, int kmflag)
{
	int i, count;
	size_t len;
	caddr_t attr_val;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_key_t *key;

	ASSERT(in_key->ck_format == CRYPTO_KEY_ATTR_LIST);

	count = in_key->ck_count;
	/* figure out how much memory to allocate for everything */
	len = sizeof (crypto_key_t) +
	    count * sizeof (crypto_object_attribute_t);
	for (i = 0; i < count; i++) {
		len += roundup(in_key->ck_attrs[i].oa_value_len,
		    sizeof (caddr_t));
	}

	/* one big allocation for everything */
	key = kmem_alloc(len, kmflag);
	if (key == NULL)
		return (CRYPTO_HOST_MEMORY);
	k_attrs = (crypto_object_attribute_t *)(void *)((caddr_t)key +
	    sizeof (crypto_key_t));

	attr_val = (caddr_t)k_attrs +
	    count * sizeof (crypto_object_attribute_t);
	for (i = 0; i < count; i++) {
		k_attrs[i].oa_type = in_key->ck_attrs[i].oa_type;
		bcopy(in_key->ck_attrs[i].oa_value, attr_val,
		    in_key->ck_attrs[i].oa_value_len);
		k_attrs[i].oa_value = attr_val;
		k_attrs[i].oa_value_len = in_key->ck_attrs[i].oa_value_len;
		attr_val += roundup(k_attrs[i].oa_value_len, sizeof (caddr_t));
	}

	key->ck_format = CRYPTO_KEY_ATTR_LIST;
	key->ck_count = count;
	key->ck_attrs = k_attrs;
	*out_key = key;
	*out_size = len;		/* save the size to be freed */

	return (CRYPTO_SUCCESS);
}

int
crypto_digest_data(crypto_data_t *data, void *dctx, uchar_t *digest,
    void (*update)(), void (*final)(), uchar_t flag)
{
	int rv, dlen;
	uchar_t *dptr;

	ASSERT(flag & CRYPTO_DO_MD5 || flag & CRYPTO_DO_SHA1 ||
	    flag & CRYPTO_DO_SHA2);
	if (data == NULL) {
		ASSERT((flag & CRYPTO_DO_UPDATE) == 0);
		goto dofinal;
	}

	dlen = data->cd_length;

	if (flag & CRYPTO_DO_UPDATE) {

		switch (data->cd_format) {
		case CRYPTO_DATA_RAW:
			dptr = (uchar_t *)(data->cd_raw.iov_base +
			    data->cd_offset);

			update(dctx, dptr, dlen);

		break;

		case CRYPTO_DATA_UIO:
			if (flag & CRYPTO_DO_MD5)
				rv = crypto_uio_data(data, NULL, dlen,
				    MD5_DIGEST_DATA, dctx, update);

			else if (flag & CRYPTO_DO_SHA1)
				rv = crypto_uio_data(data, NULL, dlen,
				    SHA1_DIGEST_DATA, dctx, update);

			else
				rv = crypto_uio_data(data, NULL, dlen,
				    SHA2_DIGEST_DATA, dctx, update);

			if (rv != CRYPTO_SUCCESS)
				return (rv);

			break;

		case CRYPTO_DATA_MBLK:
			if (flag & CRYPTO_DO_MD5)
				rv = crypto_mblk_data(data, NULL, dlen,
				    MD5_DIGEST_DATA, dctx, update);

			else if (flag & CRYPTO_DO_SHA1)
				rv = crypto_mblk_data(data, NULL, dlen,
				    SHA1_DIGEST_DATA, dctx, update);

			else
				rv = crypto_mblk_data(data, NULL, dlen,
				    SHA2_DIGEST_DATA, dctx, update);

			if (rv != CRYPTO_SUCCESS)
				return (rv);

			break;
		}
	}

dofinal:
	if (flag & CRYPTO_DO_FINAL) {
		final(digest, dctx);
	}

	return (CRYPTO_SUCCESS);
}

int
crypto_update_iov(void *ctx, crypto_data_t *input, crypto_data_t *output,
    int (*cipher)(void *, caddr_t, size_t, crypto_data_t *),
    void (*copy_block)(uint8_t *, uint64_t *))
{
	common_ctx_t *common_ctx = ctx;
	int rv;

	if (input->cd_miscdata != NULL) {
		copy_block((uint8_t *)input->cd_miscdata,
		    &common_ctx->cc_iv[0]);
	}

	if (input->cd_raw.iov_len < input->cd_length)
		return (CRYPTO_ARGUMENTS_BAD);

	rv = (cipher)(ctx, input->cd_raw.iov_base + input->cd_offset,
	    input->cd_length, (input == output) ? NULL : output);

	return (rv);
}

int
crypto_update_uio(void *ctx, crypto_data_t *input, crypto_data_t *output,
    int (*cipher)(void *, caddr_t, size_t, crypto_data_t *),
    void (*copy_block)(uint8_t *, uint64_t *))
{
	common_ctx_t *common_ctx = ctx;
	uio_t *uiop = input->cd_uio;
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	uint_t vec_idx;
	size_t cur_len;

	if (input->cd_miscdata != NULL) {
		copy_block((uint8_t *)input->cd_miscdata,
		    &common_ctx->cc_iv[0]);
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
	if (vec_idx == uiop->uio_iovcnt && length > 0) {
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

		(cipher)(ctx, uiop->uio_iov[vec_idx].iov_base + offset,
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

	return (CRYPTO_SUCCESS);
}

int
crypto_update_mp(void *ctx, crypto_data_t *input, crypto_data_t *output,
    int (*cipher)(void *, caddr_t, size_t, crypto_data_t *),
    void (*copy_block)(uint8_t *, uint64_t *))
{
	common_ctx_t *common_ctx = ctx;
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	mblk_t *mp;
	size_t cur_len;

	if (input->cd_miscdata != NULL) {
		copy_block((uint8_t *)input->cd_miscdata,
		    &common_ctx->cc_iv[0]);
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
		(cipher)(ctx, (char *)(mp->b_rptr + offset), cur_len,
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

/*
 * Utility routine to look up a attribute of type, 'type',
 * in the key.
 */
int
crypto_get_key_attr(crypto_key_t *key, crypto_attr_type_t type,
    uchar_t **value, ssize_t *value_len)
{
	int i;

	ASSERT(key->ck_format == CRYPTO_KEY_ATTR_LIST);
	for (i = 0; i < key->ck_count; i++) {
		if (key->ck_attrs[i].oa_type == type) {
			*value = (uchar_t *)key->ck_attrs[i].oa_value;
			*value_len = key->ck_attrs[i].oa_value_len;
			return (CRYPTO_SUCCESS);
		}
	}

	return (CRYPTO_FAILED);
}

/*
 * Sanity limit for param copyin size.
 * Actual sizes are typically tens or maybe a hundred.
 */
size_t kcf_param_copyin_max = 0x4000; /* 16K */

/*
 * Generic functions to copyin/free mechanisms whose parameters need more work
 * than a simple flat copyin. Similar to dprov_copyin_mechanism().
 * This is designed to protect against hardware providers that implement these
 * mechanisms, but do not implement the copyin_mechanism operation, which would
 * let user pointers be accessed by providers that have no way to detect them.
 *
 * The internal form of parameters is always "flattened" here so if the
 * top level param struct has pointers, they point to later parts of the
 * same (single) allocation for the entire parameters object.  This sets
 * out_mech->cm_param_len to the size of that entire (flattened) object
 * so the later kmem_free(mech->cm_param, mech->cm_param_len) is correct.
 * All params are limited in size (kcf_param_copyin_max) and since param
 * copyin happens early in a crypto session lifetime, it's unlikely this
 * ever runs into resource constraints while doing copyin of parameters.
 * There are still resource checks, but in the caller after this returns.
 */
int
kcf_copyin_aes_ccm_param(caddr_t in_addr, size_t param_len,
    crypto_mechanism_t *mech, int mode, int kmflags)
{
	STRUCT_DECL(CK_AES_CCM_PARAMS, in_param);
	CK_AES_CCM_PARAMS *out_param;
	size_t out_len;
	ulong_t mac_len;
	ulong_t nonce_len;
	ulong_t authd_len;
	size_t s0, s1, s2;
	uchar_t *p, *nonce, *authd;
	void *uptr;

	STRUCT_INIT(in_param, mode);
	if (param_len != STRUCT_SIZE(in_param))
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Copyin top-level param struct
	 */
	if (copyin(in_addr, STRUCT_BUF(in_param), param_len) != 0)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	mac_len   = STRUCT_FGET(in_param, ulMACSize);
	nonce_len = STRUCT_FGET(in_param, ulNonceSize);
	authd_len = STRUCT_FGET(in_param, ulAuthDataSize);

	/*
	 * Sanity check sizes. See ccm.c:ccm_validate_args
	 */
	if (mac_len > 16 || nonce_len > 13 ||
	    authd_len > kcf_param_copyin_max) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * Compute size of flattened internal object
	 */
	s0 = roundup(sizeof (*out_param), sizeof (caddr_t));
	s1 = roundup(nonce_len, sizeof (caddr_t));
	s2 = roundup(authd_len, sizeof (caddr_t));

	/*
	 * Allocate and set pointers (out_pram, nonce, authd)
	 */
	out_len = s0 + s1 + s2;
	p = kmem_alloc(out_len, kmflags);
	if (p == NULL)
		return (CRYPTO_HOST_MEMORY);
	out_param = (CK_AES_CCM_PARAMS *)p;
	p += s0;
	nonce = p;
	p += s1;
	authd = p;

	/*
	 * Copyin "inner" param stuff: nonce, authd
	 * (pointed to by top-level struct)
	 */
	uptr = STRUCT_FGETP(in_param, nonce);
	if (copyin(uptr, nonce, nonce_len) != 0)
		goto badparams;

	uptr = STRUCT_FGETP(in_param, authData);
	if (copyin(uptr, authd, authd_len) != 0)
		goto badparams;

	/*
	 * Fill out the top-level struct
	 */
	out_param->ulMACSize = mac_len;
	out_param->ulNonceSize = nonce_len;
	out_param->ulAuthDataSize = authd_len;
	out_param->ulDataSize = STRUCT_FGET(in_param, ulDataSize);
	out_param->nonce = nonce;
	out_param->authData = authd;

	/*
	 * Return it.  Free is in crypto_free_mech()
	 */
	mech->cm_param = (caddr_t)out_param;
	mech->cm_param_len = out_len;
	return (CRYPTO_SUCCESS);

badparams:
	kmem_free(out_param, out_len);
	return (CRYPTO_MECHANISM_PARAM_INVALID);
}

int
kcf_copyin_aes_gcm_param(caddr_t in_addr, size_t param_len,
    crypto_mechanism_t *mech, int mode, int kmflags)
{
	STRUCT_DECL(CK_AES_GCM_PARAMS, in_param);
	CK_AES_GCM_PARAMS *out_param;
	size_t out_len;
	ulong_t iv_len;
	ulong_t ad_len;
	size_t s0, s1, s2;
	uchar_t *p, *ivp, *adp;
	void *uptr;

	STRUCT_INIT(in_param, mode);
	if (param_len != STRUCT_SIZE(in_param))
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Copyin top-level param struct
	 */
	if (copyin(in_addr, STRUCT_BUF(in_param), param_len) != 0)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	iv_len = STRUCT_FGET(in_param, ulIvLen);
	ad_len = STRUCT_FGET(in_param, ulAADLen);

	/*
	 * Sanity check sizes. See gcm.c:gcm_validate_args
	 */
	if (iv_len > kcf_param_copyin_max ||
	    ad_len > kcf_param_copyin_max) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * Compute size of flattened internal object
	 */
	s0 = roundup(sizeof (*out_param), sizeof (caddr_t));
	s1 = roundup(iv_len, sizeof (caddr_t));
	s2 = roundup(ad_len, sizeof (caddr_t));

	/*
	 * Allocate and set pointers (out_param, IV, AAD)
	 */
	out_len = s0 + s1 + s2;
	p = kmem_alloc(out_len, kmflags);
	if (p == NULL)
		return (CRYPTO_HOST_MEMORY);
	out_param = (CK_AES_GCM_PARAMS *)p;
	p += s0;
	ivp = p;
	p += s1;
	adp = p;

	/*
	 * Copyin "inner" param stuff: IV, AAD
	 * (pointed to by top-level struct)
	 */
	uptr = STRUCT_FGETP(in_param, pIv);
	if (copyin(uptr, ivp, iv_len) != 0)
		goto badparams;

	uptr = STRUCT_FGETP(in_param, pAAD);
	if (copyin(uptr, adp, ad_len) != 0)
		goto badparams;

	/*
	 * Fill out the top-level struct
	 */
	out_param->pIv = ivp;
	out_param->ulIvLen = iv_len;
	out_param->ulIvBits = STRUCT_FGET(in_param, ulIvBits);
	out_param->pAAD = adp;
	out_param->ulAADLen = ad_len;
	out_param->ulTagBits = STRUCT_FGET(in_param, ulTagBits);

	/*
	 * Return it.  Free is in crypto_free_mech()
	 */
	mech->cm_param = (caddr_t)out_param;
	mech->cm_param_len = out_len;
	return (CRYPTO_SUCCESS);

badparams:
	kmem_free(out_param, out_len);
	return (CRYPTO_MECHANISM_PARAM_INVALID);
}

int
kcf_copyin_aes_gmac_param(caddr_t in_addr, size_t param_len,
    crypto_mechanism_t *mech, int mode, int kmflags)
{
	STRUCT_DECL(CK_AES_GMAC_PARAMS, in_param);
	CK_AES_GMAC_PARAMS *out_param;
	size_t out_len;
	ulong_t iv_len;
	ulong_t ad_len;
	size_t s0, s1, s2;
	uchar_t *p, *ivp, *adp;
	void *uptr;

	STRUCT_INIT(in_param, mode);
	if (param_len != STRUCT_SIZE(in_param))
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Copyin top-level param struct
	 */
	if (copyin(in_addr, STRUCT_BUF(in_param), param_len) != 0)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	iv_len = AES_GMAC_IV_LEN;
	ad_len = STRUCT_FGET(in_param, ulAADLen);

	/*
	 * Sanity check sizes. See gcm.c:gmac_init_ctx
	 */
	if (ad_len > kcf_param_copyin_max) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * Compute size of flattened internal object
	 */
	s0 = roundup(sizeof (*out_param), sizeof (caddr_t));
	s1 = roundup(iv_len, sizeof (caddr_t));
	s2 = roundup(ad_len, sizeof (caddr_t));

	/*
	 * Allocate and set pointers (out_param, IV, AAD)
	 */
	out_len = s0 + s1 + s2;
	p = kmem_alloc(out_len, kmflags);
	if (p == NULL)
		return (CRYPTO_HOST_MEMORY);
	out_param = (CK_AES_GMAC_PARAMS *)p;
	p += s0;
	ivp = p;
	p += s1;
	adp = p;

	/*
	 * Copyin "inner" param stuff: IV, AAD
	 * (pointed to by top-level struct)
	 */
	uptr = STRUCT_FGETP(in_param, pIv);
	if (copyin(uptr, ivp, iv_len) != 0)
		goto badparams;

	uptr = STRUCT_FGETP(in_param, pAAD);
	if (copyin(uptr, adp, ad_len) != 0)
		goto badparams;

	/*
	 * Fill out the top-level struct
	 */
	out_param->pIv = ivp;
	out_param->pAAD = adp;
	out_param->ulAADLen = ad_len;

	/*
	 * Return it.  Free is in crypto_free_mech()
	 */
	mech->cm_param = (caddr_t)out_param;
	mech->cm_param_len = out_len;
	return (CRYPTO_SUCCESS);

badparams:
	kmem_free(out_param, out_len);
	return (CRYPTO_MECHANISM_PARAM_INVALID);
}

int
kcf_copyin_ecdh1_param(caddr_t in_addr, size_t param_len,
    crypto_mechanism_t *mech, int mode, int kmflags)
{
	STRUCT_DECL(CK_ECDH1_DERIVE_PARAMS, in_param);
	CK_ECDH1_DERIVE_PARAMS *out_param;
	size_t out_len;
	ulong_t sd_len;
	ulong_t pd_len;
	size_t s0, s1, s2;
	uchar_t *p, *sdp, *pdp;
	void *uptr;

	STRUCT_INIT(in_param, mode);
	if (param_len != STRUCT_SIZE(in_param))
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Copyin top-level param struct
	 */
	if (copyin(in_addr, STRUCT_BUF(in_param), param_len) != 0)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	sd_len = STRUCT_FGET(in_param, ulSharedDataLen);
	pd_len = STRUCT_FGET(in_param, ulPublicDataLen);

	/*
	 * Sanity check sizes.
	 */
	if (sd_len > kcf_param_copyin_max ||
	    pd_len > kcf_param_copyin_max) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * Compute size of flattened internal object
	 */
	s0 = roundup(sizeof (*out_param), sizeof (caddr_t));
	s1 = roundup(sd_len, sizeof (caddr_t));
	s2 = roundup(pd_len, sizeof (caddr_t));

	/*
	 * Allocate and set pointers (out_param, SD, PD)
	 */
	out_len = s0 + s1 + s2;
	p = kmem_alloc(out_len, kmflags);
	if (p == NULL)
		return (CRYPTO_HOST_MEMORY);
	out_param = (CK_ECDH1_DERIVE_PARAMS *)p;
	p += s0;
	sdp = p;
	p += s1;
	pdp = p;

	/*
	 * Copyin "inner" param stuff: SD, PD
	 * (pointed to by top-level struct)
	 */
	uptr = STRUCT_FGETP(in_param, pSharedData);
	if (copyin(uptr, sdp, sd_len) != 0)
		goto badparams;

	uptr = STRUCT_FGETP(in_param, pPublicData);
	if (copyin(uptr, pdp, pd_len) != 0)
		goto badparams;

	/*
	 * Fill out the top-level struct
	 */
	out_param->kdf = STRUCT_FGET(in_param, kdf);
	out_param->ulSharedDataLen = sd_len;
	out_param->pSharedData = sdp;
	out_param->ulPublicDataLen = pd_len;
	out_param->pPublicData = pdp;

	/*
	 * Return it.  Free is in crypto_free_mech()
	 */
	mech->cm_param = (caddr_t)out_param;
	mech->cm_param_len = out_len;
	return (CRYPTO_SUCCESS);

badparams:
	kmem_free(out_param, out_len);
	return (CRYPTO_MECHANISM_PARAM_INVALID);
}
