/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <k5-int.h>
#include <enc_provider.h>

#define BLOCK_SIZE 16

static void
aes_block_size(size_t *blocksize)
{
    *blocksize = 16;
}

static void
aes128_keysize(size_t *keybytes, size_t *keylength)
{
    *keybytes = *keylength = 16;
}

static void
aes256_keysize(size_t *keybytes, size_t *keylength)
{
    *keybytes = *keylength = 32;
}

#define XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]; \
	(dst)[8] ^= (src)[8]; \
	(dst)[9] ^= (src)[9]; \
	(dst)[10] ^= (src)[10]; \
	(dst)[11] ^= (src)[11]; \
	(dst)[12] ^= (src)[12]; \
	(dst)[13] ^= (src)[13]; \
	(dst)[14] ^= (src)[14]; \
	(dst)[15] ^= (src)[15]

#define xorblock(x,y) XOR_BLOCK(y, x)

/*ARGSUSED*/
krb5_error_code
krb5int_aes_encrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *ivec,
	const krb5_data *input, krb5_data *output)
{
    krb5_error_code ret = 0;
    unsigned char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE], tmp3[BLOCK_SIZE];
    int nblocks = 0, blockno;
#ifdef _KERNEL
    crypto_context_t kef_ctx;
    crypto_mechanism_t mech;
    int result = 0;
#else
    CK_RV rv;
    KRB5_MECH_TO_PKCS algos;
    CK_MECHANISM mechanism;
    CK_ULONG outlen;
#endif /* _KERNEL */

    if (ivec && ivec->data != NULL && ivec->length >= BLOCK_SIZE)
	(void) memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	(void) memset(tmp, 0, BLOCK_SIZE);

    nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;

#ifndef _KERNEL
    rv = get_algo(key->enctype, &algos);
    if (rv != CKR_OK)
	goto cleanup;

    rv = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key);
    if (rv != CKR_OK)
	goto cleanup;

    mechanism.mechanism = algos.enc_algo;
    mechanism.pParameter = (ivec != NULL ? ivec->data : NULL);
    mechanism.ulParameterLen = (ivec != NULL ? ivec->length : 0);

    rv = C_EncryptInit(krb_ctx_hSession(context), &mechanism, key->hKey);

    if (rv != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_EncryptInit failed in "
		"krb5int_aes_encrypt: rv = 0x%x", rv);
	goto cleanup;
    }
#endif /* !_KERNEL */

    if (nblocks == 1) {
#ifndef _KERNEL
	/* XXX Used for DK function.  */
	outlen = (CK_ULONG)output->length;
	rv = C_Encrypt(krb_ctx_hSession(context),
		(CK_BYTE_PTR)input->data,
		(CK_ULONG)input->length,
		(CK_BYTE_PTR)output->data,
		(CK_ULONG_PTR)&outlen);
	output->length = (unsigned int)outlen;
#else
	ret = k5_ef_crypto((const char *)input->data,
		(char *)output->data,
		input->length, (krb5_keyblock *)key, 
		(krb5_data *)ivec, FALSE);
#endif /* _KERNEL */
    } else {
	int nleft;
#ifdef _KERNEL
	crypto_data_t ct, pt;

	mech.cm_type = key->kef_mt;
	mech.cm_param = (ivec != NULL ? ivec->data : NULL);
	mech.cm_param_len = (ivec != NULL ? ivec->length : 0);

	result = crypto_encrypt_init(&mech,
			(crypto_key_t *)&key->kef_key,
			key->key_tmpl, &kef_ctx, NULL);
	if (result != CRYPTO_SUCCESS)
		goto cleanup;
	ct.cd_format = CRYPTO_DATA_RAW;
	ct.cd_offset = 0;
	ct.cd_length = BLOCK_SIZE;
	ct.cd_miscdata = NULL;

	pt.cd_format = CRYPTO_DATA_RAW;
	pt.cd_offset = 0;
	pt.cd_length = BLOCK_SIZE;
	pt.cd_miscdata = NULL;
#else
	CK_ULONG outlen = BLOCK_SIZE;
#endif /* _KERNEL */

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
	    xorblock(tmp, (uchar_t *)input->data + blockno * BLOCK_SIZE);
#ifdef _KERNEL
	    pt.cd_raw.iov_base = (char *)tmp;
	    pt.cd_raw.iov_len = BLOCK_SIZE;
	    ct.cd_raw.iov_base = (char *)output->data + blockno * BLOCK_SIZE;
	    ct.cd_raw.iov_len = BLOCK_SIZE;

	    result = crypto_encrypt_update(kef_ctx, &pt, &ct, NULL);
	    if (result != CRYPTO_SUCCESS) {
		KRB5_LOG(KRB5_ERR,
			"crypto_encrypt_update: error: rv = 0x%08x",
			result);
		goto cleanup;
	    }
	    bcopy(output->data + blockno * BLOCK_SIZE, tmp, BLOCK_SIZE);
#else
	    rv = C_EncryptUpdate(krb_ctx_hSession(context),
		(CK_BYTE_PTR)tmp,
		(CK_ULONG)BLOCK_SIZE,
		(CK_BYTE_PTR)output->data + blockno * BLOCK_SIZE,
		(CK_ULONG_PTR)&outlen);
	
	    if (rv != CKR_OK)
		goto cleanup;
	    (void) memcpy(tmp, output->data + blockno * BLOCK_SIZE,
		outlen);
#endif
	}
	/* Do final CTS step for last two blocks (the second of which
	   may or may not be incomplete).  */

	xorblock(tmp, (uchar_t *)input->data + (nblocks - 2) * BLOCK_SIZE);

#ifdef _KERNEL
	pt.cd_raw.iov_base = (char *)tmp;
	pt.cd_raw.iov_len = BLOCK_SIZE;

	ct.cd_raw.iov_base = (char *)tmp2;
	ct.cd_raw.iov_len = BLOCK_SIZE;

	result = crypto_encrypt_update(kef_ctx, &pt, &ct, NULL);
	if (result != CRYPTO_SUCCESS) {
	    KRB5_LOG(KRB5_ERR,
		"crypto_encrypt_update: error: rv = 0x%08x", result);
	    goto cleanup;
	}
#else
	rv = C_EncryptUpdate(krb_ctx_hSession(context),
		(CK_BYTE_PTR)tmp,
		(CK_ULONG)BLOCK_SIZE,
		(CK_BYTE_PTR)tmp2,
		(CK_ULONG_PTR)&outlen);
	
	if (rv != CKR_OK)
	    goto cleanup;
#endif /* _KERNEL */

	nleft = input->length - (nblocks - 1) * BLOCK_SIZE;
	(void) memcpy(output->data + (nblocks - 1) * BLOCK_SIZE,
		tmp2, nleft);
	(void) memcpy(tmp, tmp2, BLOCK_SIZE);

	/*
	 * This effectively adds 0's as pad bytes if the last
	 * block is not exactly BLOCK_SIZE.
	 */
	(void) memset(tmp3, 0, sizeof(tmp3));

	(void) memcpy(tmp3, input->data + (nblocks - 1) * BLOCK_SIZE, nleft);
	xorblock(tmp, tmp3);
#ifdef _KERNEL
	pt.cd_raw.iov_base = (char *)tmp;
	pt.cd_raw.iov_len = BLOCK_SIZE;

	ct.cd_raw.iov_base = (char *)tmp2;
	ct.cd_raw.iov_len = BLOCK_SIZE;

	result = crypto_encrypt_update(kef_ctx, &pt, &ct, NULL);
	if (result != CRYPTO_SUCCESS) {
	    KRB5_LOG(KRB5_ERR,
		"crypto_encrypt_update: error: rv = 0x%08x", result);
	    goto cleanup;
	}
#else
	rv = C_EncryptUpdate(krb_ctx_hSession(context),
		(CK_BYTE_PTR)tmp,
		(CK_ULONG)BLOCK_SIZE,
		(CK_BYTE_PTR)tmp2,
		(CK_ULONG_PTR)&outlen);
	
	if (rv != CKR_OK)
	    goto cleanup;
#endif /* _KERNEL */

	(void) memcpy(output->data + (nblocks - 2) * BLOCK_SIZE,
		tmp2, BLOCK_SIZE);

	if (ivec && ivec->data != NULL && ivec->length >= BLOCK_SIZE) {
		(void) memcpy(ivec->data, tmp2, BLOCK_SIZE);
	}

#ifdef _KERNEL
	ct.cd_raw.iov_base = (char *)tmp2;
	ct.cd_raw.iov_len = BLOCK_SIZE;

	result = crypto_encrypt_final(kef_ctx, &ct, NULL);
#else
	/* Close the crypto session, ignore the output */
	rv = C_EncryptFinal(krb_ctx_hSession(context),
		(CK_BYTE_PTR)tmp2, (CK_ULONG_PTR)&outlen);

	if (rv != CKR_OK)
	    goto cleanup;
#endif /* _KERNEL */
    }

cleanup:

#ifdef _KERNEL
    ret = result;
#else
    if (rv != CKR_OK)
	ret = PKCS_ERR;
#endif /* _KERNEL */

    if (ret)
	bzero(output->data, input->length);

    return (ret);
}

/*ARGSUSED*/
krb5_error_code
krb5int_aes_decrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *ivec,
	const krb5_data *input, krb5_data *output)
{
    krb5_error_code ret = 0;
    unsigned char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE], tmp3[BLOCK_SIZE];
    int nblocks = 0, blockno;
#ifdef _KERNEL
    crypto_context_t kef_ctx;
    crypto_mechanism_t mech;
    int result = 0;
#else
    CK_RV rv;
    KRB5_MECH_TO_PKCS algos;
    CK_MECHANISM mechanism;
    CK_ULONG outlen;
#endif /* _KERNEL */

    if (ivec && ivec->data != NULL && ivec->length >= BLOCK_SIZE)
	(void) memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	(void) memset(tmp, 0, BLOCK_SIZE);

    nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;

#ifndef _KERNEL
    rv = get_algo(key->enctype, &algos);
    if (rv != CKR_OK)
	goto cleanup;

    rv = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key);
    if (rv != CKR_OK) {
	goto cleanup;
    }

    mechanism.mechanism = algos.enc_algo;
    mechanism.pParameter = (ivec != NULL ? ivec->data : NULL);
    mechanism.ulParameterLen = (ivec != NULL ? ivec->length : 0);

    rv = C_DecryptInit(krb_ctx_hSession(context), &mechanism, key->hKey);

    if (rv != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DecryptInit failed in "
		"krb5int_aes_decrypt: rv = 0x%x", rv);
	goto cleanup;
    }
#endif

    if (nblocks == 1) {
	if (input->length < BLOCK_SIZE)
	    return (KRB5_CRYPTO_INTERNAL);
#ifndef _KERNEL
	rv = C_Decrypt(krb_ctx_hSession(context),
		(CK_BYTE_PTR)input->data,
		(CK_ULONG)input->length,
		(CK_BYTE_PTR)output->data,
		(CK_ULONG_PTR)&output->length);
#else
	ret = k5_ef_crypto((const char *)input->data, (char *)output->data,
		input->length, (krb5_keyblock *)key, 
		(krb5_data *)ivec, FALSE);
#endif /* _KERNEL */

    } else {
#ifdef _KERNEL
	crypto_data_t ct, pt;

	(void) memset(&ct, 0, sizeof(ct));
	(void) memset(&pt, 0, sizeof(pt));

	mech.cm_type = key->kef_mt;
	mech.cm_param = (ivec != NULL ? ivec->data : NULL);
	mech.cm_param_len = (ivec != NULL ? ivec->length : 0);

	result = crypto_decrypt_init(&mech,
			(crypto_key_t *)&key->kef_key,
			key->key_tmpl, &kef_ctx, NULL);
	if (result != CRYPTO_SUCCESS)
		goto cleanup;
	ct.cd_format = CRYPTO_DATA_RAW;
	ct.cd_offset = 0;
	ct.cd_length = BLOCK_SIZE;
	ct.cd_raw.iov_len = BLOCK_SIZE;

	pt.cd_format = CRYPTO_DATA_RAW;
	pt.cd_offset = 0;
	pt.cd_length = BLOCK_SIZE;
	pt.cd_raw.iov_len = BLOCK_SIZE;
#endif /* _KERNEL */

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
#ifdef _KERNEL
	    KRB5_LOG(KRB5_INFO, "krb5int_aes_decrypt: blockno = %d",
		blockno);
	    ct.cd_raw.iov_base = (char *)input->data + blockno * BLOCK_SIZE;
	    pt.cd_raw.iov_base = (char *)tmp2;

	    result = crypto_decrypt_update(kef_ctx, &ct, &pt, NULL);
	    if (result != CRYPTO_SUCCESS) {
		KRB5_LOG(KRB5_ERR,
			"crypto_decrypt_update: error: rv = 0x%08x",
			result);
		goto cleanup;
	    }
#else
	    outlen = sizeof(tmp2);
	    rv = C_DecryptUpdate(krb_ctx_hSession(context),
		(CK_BYTE_PTR)input->data + blockno * BLOCK_SIZE,
		(CK_ULONG)BLOCK_SIZE,
		(CK_BYTE_PTR)tmp2,
		(CK_ULONG_PTR)&outlen);

	    if (rv != CKR_OK)
		goto cleanup;

#endif /* _KERNEL */
	    xorblock(tmp2, tmp);
	    (void) memcpy(output->data + blockno * BLOCK_SIZE,
			tmp2, BLOCK_SIZE);
	    (void) memcpy(tmp, input->data + blockno * BLOCK_SIZE,
			BLOCK_SIZE);
	}
	/* Do last two blocks, the second of which (next-to-last block
	   of plaintext) may be incomplete.  */
#ifdef _KERNEL
	ct.cd_raw.iov_base = (char *)input->data + (nblocks - 2) * BLOCK_SIZE;
	ct.cd_raw.iov_len = BLOCK_SIZE;
	pt.cd_raw.iov_base = (char *)tmp2;
	pt.cd_raw.iov_len = BLOCK_SIZE;

	result = crypto_decrypt_update(kef_ctx, &ct, &pt, NULL);
	if (result != CRYPTO_SUCCESS) {
	    KRB5_LOG(KRB5_ERR,
		"crypto_decrypt_update: error: rv = 0x%08x",
		result);
		goto cleanup;
	}
#else
	outlen = sizeof(tmp2);
	rv = C_DecryptUpdate(krb_ctx_hSession(context),
		(CK_BYTE_PTR)input->data + (nblocks - 2) * BLOCK_SIZE,
		(CK_ULONG)BLOCK_SIZE,
		(CK_BYTE_PTR)tmp2,
		(CK_ULONG_PTR)&outlen);

	if (rv != CKR_OK)
	    goto cleanup;
#endif /* _KERNEL */

	/* Set tmp3 to last ciphertext block, padded.  */
	(void) memset(tmp3, 0, sizeof(tmp3));
	(void) memcpy(tmp3, input->data + (nblocks - 1) * BLOCK_SIZE,
	       input->length - (nblocks - 1) * BLOCK_SIZE);

	/* Set tmp2 to last (possibly partial) plaintext block, and save it.  */
	xorblock(tmp2, tmp3);
	(void) memcpy(output->data + (nblocks - 1) * BLOCK_SIZE, tmp2,
	       input->length - (nblocks - 1) * BLOCK_SIZE);

	/*
	 * Maybe keep the trailing part, and copy in the
	 * last ciphertext block.
	 */
	(void) memcpy(tmp2, tmp3, input->length - (nblocks - 1) * BLOCK_SIZE);

	/*
	 * Decrypt, to get next to last plaintext block xor
	 * previous ciphertext.
	 */
#ifdef _KERNEL
	ct.cd_raw.iov_base = (char *)tmp2;
	ct.cd_raw.iov_len = BLOCK_SIZE;
	pt.cd_raw.iov_base = (char *)tmp3;
	pt.cd_raw.iov_len = BLOCK_SIZE;

	result = crypto_decrypt_update(kef_ctx, &ct, &pt, NULL);
	if (result != CRYPTO_SUCCESS) {
	    KRB5_LOG(KRB5_ERR,
		"crypto_decrypt_update: error: rv = 0x%08x",
		result);
		goto cleanup;
	}
#else
	outlen = sizeof(tmp3);
	rv = C_DecryptUpdate(krb_ctx_hSession(context),
	    (CK_BYTE_PTR)tmp2,
	    (CK_ULONG)BLOCK_SIZE,
	    (CK_BYTE_PTR)tmp3,
	    (CK_ULONG_PTR)&outlen);

	if (rv != CKR_OK)
	    goto cleanup;
#endif /* _KERNEL */

	xorblock(tmp3, tmp);
	(void) memcpy(output->data + (nblocks - 2) * BLOCK_SIZE,
		tmp3, BLOCK_SIZE);

	if (ivec)
		(void) memcpy(ivec->data,
			input->data + (nblocks - 2) * BLOCK_SIZE, BLOCK_SIZE);

#ifdef _KERNEL
	pt.cd_raw.iov_base = (char *)tmp2;
	pt.cd_raw.iov_len = BLOCK_SIZE;
	result = crypto_decrypt_final(kef_ctx, &pt, NULL);
#else
	outlen = sizeof(tmp2);
	rv = C_DecryptFinal(krb_ctx_hSession(context),
		(CK_BYTE_PTR)tmp2, (CK_ULONG_PTR)&outlen);

	if (rv != CKR_OK)
	    goto cleanup;
#endif /* _KERNEL */
    }
cleanup:
#ifdef _KERNEL
    ret = result;
#else
    if (rv != CKR_OK)
	ret = PKCS_ERR;
#endif /* _KERNEL */

    if (ret)
	bzero(output->data, input->length);

    return (ret);
}

static krb5_error_code
k5_aes_make_key(krb5_context context,
	const krb5_data *randombits, krb5_keyblock *key)
{
    krb5_error_code ret = 0;
    if (key->length != 16 && key->length != 32)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != key->length)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;
    key->dk_list = NULL;

#ifdef _KERNEL
    key->kef_key.ck_data = NULL;
    key->key_tmpl = NULL;
    (void) memcpy(key->contents, randombits->data, randombits->length);
    ret = init_key_kef(context->kef_cipher_mt, key);
#else
    key->hKey = CK_INVALID_HANDLE;
    (void) memcpy(key->contents, randombits->data, randombits->length);
    ret = init_key_uef(krb_ctx_hSession(context), key);
#endif /* _KERNEL */

    KRB5_LOG0(KRB5_INFO, "k5_aes_make_key() end\n");
    return (ret);
}

/*ARGSUSED*/
static krb5_error_code
krb5int_aes_init_state (krb5_context context, const krb5_keyblock *key,
	krb5_keyusage usage, krb5_data *state)
{
    if (!state)
	return (0);

    if (state && state->data)
	FREE(state->data, state->length);

    state->length = BLOCK_SIZE;
    state->data = (void *) MALLOC(BLOCK_SIZE);

    if (state->data == NULL)
	return ENOMEM;

    (void) memset(state->data, 0, state->length);
    return (0);
}

const struct krb5_enc_provider krb5int_enc_aes128 = {
    aes_block_size,
    aes128_keysize,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    aes_block_size,
    aes256_keysize,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state
};
