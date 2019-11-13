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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2017 Jason King.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <aes_impl.h>
#include <cryptoutil.h>
#include "softSession.h"
#include "softObject.h"
#include "softCrypt.h"
#include "softOps.h"

/*
 * Check that the mechanism parameter is present and the correct size if
 * required and allocate an AES context.
 */
static CK_RV
soft_aes_check_mech_param(CK_MECHANISM_PTR mech, aes_ctx_t **ctxp)
{
	void *(*allocf)(int) = NULL;
	size_t param_len = 0;
	boolean_t param_req = B_TRUE;

	switch (mech->mechanism) {
	case CKM_AES_ECB:
		param_req = B_FALSE;
		allocf = ecb_alloc_ctx;
		break;
	case CKM_AES_CMAC:
		param_req = B_FALSE;
		allocf = cmac_alloc_ctx;
		break;
	case CKM_AES_CMAC_GENERAL:
		param_len = sizeof (CK_MAC_GENERAL_PARAMS);
		allocf = cmac_alloc_ctx;
		break;
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		param_len = AES_BLOCK_LEN;
		allocf = cbc_alloc_ctx;
		break;
	case CKM_AES_CTR:
		param_len = sizeof (CK_AES_CTR_PARAMS);
		allocf = ctr_alloc_ctx;
		break;
	case CKM_AES_CCM:
		param_len = sizeof (CK_CCM_PARAMS);
		allocf = ccm_alloc_ctx;
		break;
	case CKM_AES_GCM:
		param_len = sizeof (CK_GCM_PARAMS);
		allocf = gcm_alloc_ctx;
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	if (param_req && (mech->pParameter == NULL ||
	    mech->ulParameterLen != param_len)) {
		return (CKR_MECHANISM_PARAM_INVALID);
	}

	*ctxp = allocf(0);
	if (*ctxp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	return (CKR_OK);
}

/*
 * Create an AES key schedule for the given AES context from the given key.
 * If the key is not sensitive, cache a copy of the key schedule in the
 * key object and/or use the cached copy of the key schedule.
 *
 * Must be called before the init function for a given mode is called.
 */
static CK_RV
soft_aes_init_key(aes_ctx_t *aes_ctx, soft_object_t *key_p)
{
	void *ks = NULL;
	size_t size = 0;
	CK_RV rv = CKR_OK;

	(void) pthread_mutex_lock(&key_p->object_mutex);

	/*
	 * AES keys should be either 128, 192, or 256 bits long.
	 * soft_object_t stores the key size in bytes, so we check those sizes
	 * in bytes.
	 *
	 * While soft_build_secret_key_object() does these same validations for
	 * keys created by the user, it may be possible that a key loaded from
	 * disk could be invalid or corrupt.  We err on the side of caution
	 * and check again that it's the correct size before performing any
	 * AES operations.
	 */
	switch (OBJ_SEC_VALUE_LEN(key_p)) {
	case AES_MIN_KEY_BYTES:
	case AES_MAX_KEY_BYTES:
	case AES_192_KEY_BYTES:
		break;
	default:
		rv = CKR_KEY_SIZE_RANGE;
		goto done;
	}

	ks = aes_alloc_keysched(&size, 0);
	if (ks == NULL) {
		rv = CKR_HOST_MEMORY;
		goto done;
	}

	/* If this is a sensitive key, always expand the key schedule */
	if (key_p->bool_attr_mask & SENSITIVE_BOOL_ON) {
		/* aes_init_keysched() requires key length in bits.  */
#ifdef	__sparcv9
		/* LINTED */
		aes_init_keysched(OBJ_SEC_VALUE(key_p), (uint_t)
		    (OBJ_SEC_VALUE_LEN(key_p) * NBBY), ks);
#else	/* !__sparcv9 */
		aes_init_keysched(OBJ_SEC_VALUE(key_p),
		    (OBJ_SEC_VALUE_LEN(key_p) * NBBY), ks);
#endif	/* __sparcv9 */

		goto done;
	}

	/* If a non-sensitive key and doesn't have a key schedule, create it */
	if (OBJ_KEY_SCHED(key_p) == NULL) {
		void *obj_ks = NULL;

		obj_ks = aes_alloc_keysched(&size, 0);
		if (obj_ks == NULL) {
			rv = CKR_HOST_MEMORY;
			goto done;
		}

#ifdef	__sparcv9
		/* LINTED */
		aes_init_keysched(OBJ_SEC_VALUE(key_p),
		    (uint_t)(OBJ_SEC_VALUE_LEN(key_p) * 8), obj_ks);
#else	/* !__sparcv9 */
		aes_init_keysched(OBJ_SEC_VALUE(key_p),
		    (OBJ_SEC_VALUE_LEN(key_p) * 8), obj_ks);
#endif	/* __sparcv9 */

		OBJ_KEY_SCHED_LEN(key_p) = size;
		OBJ_KEY_SCHED(key_p) = obj_ks;
	}

	(void) memcpy(ks, OBJ_KEY_SCHED(key_p), OBJ_KEY_SCHED_LEN(key_p));

done:
	(void) pthread_mutex_unlock(&key_p->object_mutex);

	if (rv == CKR_OK) {
		aes_ctx->ac_keysched = ks;
		aes_ctx->ac_keysched_len = size;
	} else {
		freezero(ks, size);
	}

	return (rv);
}

/*
 * Initialize the AES context for the given mode, including allocating and
 * expanding the key schedule if required.
 */
static CK_RV
soft_aes_init_ctx(aes_ctx_t *aes_ctx, CK_MECHANISM_PTR mech_p,
    boolean_t encrypt)
{
	int rc = CRYPTO_SUCCESS;

	switch (mech_p->mechanism) {
	case CKM_AES_ECB:
		aes_ctx->ac_flags |= ECB_MODE;
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		rc = cmac_init_ctx((cbc_ctx_t *)aes_ctx, AES_BLOCK_LEN);
		break;
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		rc = cbc_init_ctx((cbc_ctx_t *)aes_ctx, mech_p->pParameter,
		    mech_p->ulParameterLen, AES_BLOCK_LEN, aes_copy_block64);
		break;
	case CKM_AES_CTR:
	{
		/*
		 * soft_aes_check_param() verifies this is !NULL and is the
		 * correct size.
		 */
		CK_AES_CTR_PARAMS *pp = (CK_AES_CTR_PARAMS *)mech_p->pParameter;

		rc = ctr_init_ctx((ctr_ctx_t *)aes_ctx, pp->ulCounterBits,
		    pp->cb, aes_encrypt_block, aes_copy_block);
		break;
	}
	case CKM_AES_CCM: {
		CK_CCM_PARAMS *pp = (CK_CCM_PARAMS *)mech_p->pParameter;

		/*
		 * The illumos ccm mode implementation predates the PKCS#11
		 * version that specifies CK_CCM_PARAMS.  As a result, the order
		 * and names of the struct members are different, so we must
		 * translate.  ccm_init_ctx() does not store a ref ccm_params,
		 * so it is safe to allocate on the stack.
		 */
		CK_AES_CCM_PARAMS ccm_params = {
			.ulMACSize = pp->ulMACLen,
			.ulNonceSize = pp->ulNonceLen,
			.ulAuthDataSize = pp->ulAADLen,
			.ulDataSize = pp->ulDataLen,
			.nonce = pp->pNonce,
			.authData = pp->pAAD
		};

		rc = ccm_init_ctx((ccm_ctx_t *)aes_ctx, (char *)&ccm_params, 0,
		    encrypt, AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;
	}
	case CKM_AES_GCM:
		/*
		 * Similar to the ccm mode implementation, the gcm mode also
		 * predates PKCS#11 2.40, however in this instance
		 * CK_AES_GCM_PARAMS and CK_GCM_PARAMS are identical except
		 * for the member names, so we can just pass it along.
		 */
		rc = gcm_init_ctx((gcm_ctx_t *)aes_ctx, mech_p->pParameter,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	}

	return (crypto2pkcs11_error_number(rc));
}

/*
 * Allocate context for the active encryption or decryption operation, and
 * generate AES key schedule to speed up the operation.
 */
CK_RV
soft_aes_crypt_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p,
    boolean_t encrypt)
{
	aes_ctx_t *aes_ctx = NULL;
	CK_RV rv = CKR_OK;

	if (key_p->key_type != CKK_AES)
		return (CKR_KEY_TYPE_INCONSISTENT);

	/* C_{Encrypt,Decrypt}Init() validate pMechanism != NULL */
	rv = soft_aes_check_mech_param(pMechanism, &aes_ctx);
	if (rv != CKR_OK) {
		goto done;
	}

	rv = soft_aes_init_key(aes_ctx, key_p);
	if (rv != CKR_OK) {
		goto done;
	}

	rv = soft_aes_init_ctx(aes_ctx, pMechanism, encrypt);
	if (rv != CKR_OK) {
		goto done;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	if (encrypt) {
		/* Called by C_EncryptInit. */
		session_p->encrypt.context = aes_ctx;
		session_p->encrypt.mech.mechanism = pMechanism->mechanism;
	} else {
		/* Called by C_DecryptInit. */
		session_p->decrypt.context = aes_ctx;
		session_p->decrypt.mech.mechanism = pMechanism->mechanism;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);

done:
	if (rv != CKR_OK) {
		soft_aes_free_ctx(aes_ctx);
	}

	return (rv);
}


CK_RV
soft_aes_encrypt(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
	aes_ctx_t *aes_ctx = session_p->encrypt.context;
	CK_MECHANISM_TYPE mech = session_p->encrypt.mech.mechanism;
	size_t length_needed;
	size_t remainder;
	int rc = CRYPTO_SUCCESS;
	CK_RV rv = CKR_OK;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulEncryptedDataLen,
		.cd_raw.iov_base = (char *)pEncryptedData,
		.cd_raw.iov_len = *pulEncryptedDataLen
	};

	/*
	 * A bit unusual, but it's permissible for ccm and gcm modes to not
	 * encrypt any data.  This ends up being equivalent to CKM_AES_CMAC
	 * or CKM_AES_GMAC of the additional authenticated data (AAD).
	 */
	if ((pData == NULL || ulDataLen == 0) &&
	    !(aes_ctx->ac_flags & (CCM_MODE|GCM_MODE|CMAC_MODE))) {
		return (CKR_ARGUMENTS_BAD);
	}

	remainder = ulDataLen % AES_BLOCK_LEN;

	/*
	 * CTR, CCM, CMAC, and GCM modes do not require the plaintext
	 * to be a multiple of the AES block size. CKM_AES_CBC_PAD as the
	 * name suggests pads it's output, so it can also accept any
	 * size plaintext.
	 */
	switch (mech) {
	case CKM_AES_CBC_PAD:
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CTR:
	case CKM_AES_CCM:
	case CKM_AES_GCM:
		break;
	default:
		if (remainder != 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto cleanup;
		}
	}

	switch (mech) {
	case CKM_AES_CCM:
		length_needed = ulDataLen + aes_ctx->ac_mac_len;
		break;
	case CKM_AES_GCM:
		length_needed = ulDataLen + aes_ctx->ac_tag_len;
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		length_needed = AES_BLOCK_LEN;
		break;
	case CKM_AES_CBC_PAD:
		/* CKM_AES_CBC_PAD always adds 1..AES_BLOCK_LEN of padding */
		length_needed = ulDataLen + AES_BLOCK_LEN - remainder;
		break;
	default:
		length_needed = ulDataLen;
		break;
	}

	if (pEncryptedData == NULL) {
		/*
		 * The application can ask for the size of the output buffer
		 * with a NULL output buffer (pEncryptedData).
		 * C_Encrypt() guarantees pulEncryptedDataLen != NULL.
		 */
		*pulEncryptedDataLen = length_needed;
		return (CKR_OK);
	}

	if (*pulEncryptedDataLen < length_needed) {
		*pulEncryptedDataLen = length_needed;
		return (CKR_BUFFER_TOO_SMALL);
	}

	if (ulDataLen > 0) {
		rv = soft_aes_encrypt_update(session_p, pData, ulDataLen,
		    pEncryptedData, pulEncryptedDataLen);

		if (rv != CKR_OK) {
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		/*
		 * Some modes (e.g. CCM and GCM) will append data such as a MAC
		 * to the ciphertext after the plaintext has been encrypted.
		 * Update out to reflect the amount of data in pEncryptedData
		 * after encryption.
		 */
		out.cd_offset = *pulEncryptedDataLen;
	}

	switch (mech) {
	case CKM_AES_CBC_PAD: {
		/*
		 * aes_encrypt_contiguous_blocks() accumulates plaintext
		 * in aes_ctx until it has at least one full block of
		 * plaintext.  Any partial blocks of data remaining after
		 * encrypting are left for subsequent calls to
		 * aes_encrypt_contiguous_blocks().  If the input happened
		 * to be an exact multiple of AES_BLOCK_LEN, we must still
		 * append a block of padding (a full block in that case) so
		 * that the correct amount of padding to remove is known
		 * during decryption.
		 *
		 * soft_add_pkcs7_padding() is a bit overkill -- we just
		 * create a block filled with the pad amount using memset(),
		 * and encrypt 'amt' bytes of the block to pad out the input.
		 */
		char block[AES_BLOCK_LEN];
		size_t amt = AES_BLOCK_LEN - remainder;

		VERIFY3U(remainder, ==, aes_ctx->ac_remainder_len);

		(void) memset(block, amt & 0xff, sizeof (block));
		rc = aes_encrypt_contiguous_blocks(aes_ctx, block, amt, &out);
		rv = crypto2pkcs11_error_number(rc);
		explicit_bzero(block, sizeof (block));
		break;
	}
	case CKM_AES_CCM:
		rc = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
		break;
	case CKM_AES_GCM:
		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		rc = cmac_mode_final((cbc_ctx_t *)aes_ctx, &out,
		    aes_encrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
		aes_ctx->ac_remainder_len = 0;
		break;
	case CKM_AES_CTR:
		/*
		 * As CKM_AES_CTR is a stream cipher, ctr_mode_final is always
		 * invoked in the xx_update() functions, so we do not need to
		 * call it again here.
		 */
		break;
	case CKM_AES_ECB:
	case CKM_AES_CBC:
		/*
		 * These mechanisms do not have nor require a xx_final function.
		 */
		break;
	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

cleanup:
	switch (rv) {
	case CKR_OK:
		*pulEncryptedDataLen = out.cd_offset;
		break;
	case CKR_BUFFER_TOO_SMALL:
		/* *pulEncryptedDataLen was set earlier */
		break;
	default:
		/* something else failed */
		*pulEncryptedDataLen = 0;
		break;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	soft_aes_free_ctx(aes_ctx);
	session_p->encrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

static CK_RV
soft_aes_cbc_pad_decrypt(aes_ctx_t *aes_ctx, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, crypto_data_t *out_orig)
{
	aes_ctx_t *ctx = aes_ctx;
	uint8_t *buf = NULL;
	uint8_t *outbuf = (uint8_t *)out_orig->cd_raw.iov_base;
	crypto_data_t out = *out_orig;
	size_t i;
	int rc;
	CK_RV rv = CKR_OK;
	uint8_t pad_len;
	boolean_t speculate = B_FALSE;

	/*
	 * Just a query for the output size.  When the output buffer is
	 * NULL, we are allowed to return a size slightly larger than
	 * necessary.  We know the output will never be larger than the
	 * input ciphertext, so we use that as an estimate.
	 */
	if (out_orig->cd_raw.iov_base == NULL) {
		out_orig->cd_length = ulEncryptedDataLen;
		return (CKR_OK);
	}

	/*
	 * The output plaintext size will be 1..AES_BLOCK_LEN bytes
	 * smaller than the input ciphertext.  However we cannot know
	 * exactly how much smaller until we decrypt the entire
	 * input ciphertext.  If we are unsure we have enough output buffer
	 * space, we have to allocate our own memory to hold the output,
	 * then see if we have enough room to hold the result.
	 *
	 * Unfortunately, having an output buffer that's too small does
	 * not terminate the operation, nor are we allowed to return
	 * partial results.  Therefore we must also duplicate the initial
	 * aes_ctx so that this can potentially be run again.
	 */
	if (out_orig->cd_length < ulEncryptedDataLen) {
		void *ks = malloc(aes_ctx->ac_keysched_len);

		ctx = malloc(sizeof (*aes_ctx));
		buf = malloc(ulEncryptedDataLen);
		if (ks == NULL || ctx == NULL || buf == NULL) {
			free(ks);
			free(ctx);
			free(buf);
			return (CKR_HOST_MEMORY);
		}

		bcopy(aes_ctx, ctx, sizeof (*ctx));
		bcopy(aes_ctx->ac_keysched, ks, aes_ctx->ac_keysched_len);
		ctx->ac_keysched = ks;

		out.cd_length = ulEncryptedDataLen;
		out.cd_raw.iov_base = (char *)buf;
		out.cd_raw.iov_len = ulEncryptedDataLen;
		outbuf = buf;

		speculate = B_TRUE;
	}

	rc = aes_decrypt_contiguous_blocks(ctx, (char *)pEncryptedData,
	    ulEncryptedDataLen, &out);
	if (rc != CRYPTO_SUCCESS) {
		out_orig->cd_offset = 0;
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}

	/*
	 * RFC5652 6.3 The amount of padding must be
	 * block_sz - (len mod block_size).  This means
	 * the amount of padding must always be in the
	 * range [1..block_size].
	 */
	pad_len = outbuf[ulEncryptedDataLen - 1];
	if (pad_len == 0 || pad_len > AES_BLOCK_LEN) {
		rv = CKR_ENCRYPTED_DATA_INVALID;
		goto done;
	}
	out.cd_offset -= pad_len;

	/*
	 * Verify pad values, trying to do so in as close to constant
	 * time as possible.
	 */
	for (i = ulEncryptedDataLen - pad_len; i < ulEncryptedDataLen; i++) {
		if (outbuf[i] != pad_len) {
			rv = CKR_ENCRYPTED_DATA_INVALID;
		}
	}
	if (rv != CKR_OK) {
		goto done;
	}

	if (speculate) {
		if (out.cd_offset <= out_orig->cd_length) {
			bcopy(out.cd_raw.iov_base, out_orig->cd_raw.iov_base,
			    out.cd_offset);
		} else {
			rv = CKR_BUFFER_TOO_SMALL;
		}
	}

	/*
	 * No matter what, we report the exact size required.
	 */
	out_orig->cd_offset = out.cd_offset;

done:
	freezero(buf, ulEncryptedDataLen);
	if (ctx != aes_ctx) {
		VERIFY(speculate);
		soft_aes_free_ctx(ctx);
	}

	return (rv);
}

CK_RV
soft_aes_decrypt(soft_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	aes_ctx_t *aes_ctx = session_p->decrypt.context;
	CK_MECHANISM_TYPE mech = session_p->decrypt.mech.mechanism;
	size_t length_needed;
	size_t remainder;
	int rc = CRYPTO_SUCCESS;
	CK_RV rv = CKR_OK;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulDataLen,
		.cd_raw.iov_base = (char *)pData,
		.cd_raw.iov_len = *pulDataLen
	};

	/*
	 * A bit unusual, but it's permissible for ccm and gcm modes to not
	 * decrypt any data.  This ends up being equivalent to CKM_AES_CMAC
	 * or CKM_AES_GMAC of the additional authenticated data (AAD).
	 */
	if ((pEncryptedData == NULL || ulEncryptedDataLen == 0) &&
	    !(aes_ctx->ac_flags & (CCM_MODE|GCM_MODE))) {
		return (CKR_ARGUMENTS_BAD);
	}

	remainder = ulEncryptedDataLen % AES_BLOCK_LEN;

	/*
	 * CTR, CCM, CMAC, and GCM modes do not require the ciphertext
	 * to be a multiple of the AES block size.  Note that while
	 * CKM_AES_CBC_PAD accepts an arbitrary sized plaintext, the
	 * ciphertext is always a multiple of the AES block size
	 */
	switch (mech) {
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CTR:
	case CKM_AES_CCM:
	case CKM_AES_GCM:
		break;
	default:
		if (remainder != 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto cleanup;
		}
	}

	if (mech == CKM_AES_CBC_PAD) {
		rv = soft_aes_cbc_pad_decrypt(aes_ctx, pEncryptedData,
		    ulEncryptedDataLen, &out);
		if (pData == NULL || rv == CKR_BUFFER_TOO_SMALL) {
			*pulDataLen = out.cd_offset;
			return (rv);
		}
		goto cleanup;
	}

	switch (aes_ctx->ac_flags & (CCM_MODE|GCM_MODE)) {
	case CCM_MODE:
		length_needed = aes_ctx->ac_processed_data_len;
		break;
	case GCM_MODE:
		length_needed = ulEncryptedDataLen - aes_ctx->ac_tag_len;
		break;
	default:
		/*
		 * Note: for CKM_AES_CBC_PAD, we cannot know exactly how much
		 * space is needed for the plaintext until after we decrypt it.
		 * However, it is permissible to return a value 'somewhat'
		 * larger than necessary (PKCS#11 Base Specification, sec 5.2).
		 *
		 * Since CKM_AES_CBC_PAD adds at most AES_BLOCK_LEN bytes to
		 * the plaintext, we report the ciphertext length as the
		 * required plaintext length.  This means we specify at most
		 * AES_BLOCK_LEN additional bytes of memory for the plaintext.
		 *
		 * This behavior is slightly different from the earlier
		 * version of this code which returned the value of
		 * (ulEncryptedDataLen - AES_BLOCK_LEN), which was only ever
		 * correct when the original plaintext was already a multiple
		 * of AES_BLOCK_LEN (i.e. when AES_BLOCK_LEN of padding was
		 * added).  This should not be a concern for existing
		 * consumers -- if they were previously using the value of
		 * *pulDataLen to size the outbut buffer, the resulting
		 * plaintext would be truncated anytime the original plaintext
		 * wasn't a multiple of AES_BLOCK_LEN.  No consumer should
		 * be relying on such wrong behavior.  More likely they are
		 * using the size of the ciphertext or larger for the
		 * buffer to hold the decrypted plaintext (which is always
		 * acceptable).
		 */
		length_needed = ulEncryptedDataLen;
	}

	if (pData == NULL) {
		/*
		 * The application can ask for the size of the output buffer
		 * with a NULL output buffer (pData).
		 * C_Decrypt() guarantees pulDataLen != NULL.
		 */
		*pulDataLen = length_needed;
		return (CKR_OK);
	}

	if (*pulDataLen < length_needed) {
		*pulDataLen = length_needed;
		return (CKR_BUFFER_TOO_SMALL);
	}

	if (ulEncryptedDataLen > 0) {
		rv = soft_aes_decrypt_update(session_p, pEncryptedData,
		    ulEncryptedDataLen, pData, pulDataLen);
	}

	if (rv != CKR_OK) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	/*
	 * Some modes (e.g. CCM and GCM) will output additional data
	 * after the plaintext (such as the MAC).  Update out to
	 * reflect the amount of data in pData for the _final() functions.
	 */
	out.cd_offset = *pulDataLen;

	/*
	 * As CKM_AES_CTR is a stream cipher, ctr_mode_final is always
	 * invoked in the _update() functions, so we do not need to call it
	 * here.
	 */
	if (aes_ctx->ac_flags & CCM_MODE) {
		ASSERT3U(aes_ctx->ac_processed_data_len, ==,
		    aes_ctx->ac_data_len);
		ASSERT3U(aes_ctx->ac_processed_mac_len, ==,
		    aes_ctx->ac_mac_len);

		rc = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
	} else if (aes_ctx->ac_flags & GCM_MODE) {
		rc = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
	}

cleanup:
	if (rv == CKR_OK) {
		*pulDataLen = out.cd_offset;
	} else {
		*pulDataLen = 0;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	soft_aes_free_ctx(aes_ctx);
	session_p->decrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

CK_RV
soft_aes_encrypt_update(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
	aes_ctx_t *aes_ctx = session_p->encrypt.context;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulEncryptedDataLen,
		.cd_raw.iov_base = (char *)pEncryptedData,
		.cd_raw.iov_len = *pulEncryptedDataLen
	};
	CK_MECHANISM_TYPE mech = session_p->encrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	size_t out_len;
	int rc;

	/* Check size of the output buffer */
	switch (mech) {
	case CKM_AES_CMAC:
		/*
		 * The underlying CMAC implementation handles the storing of
		 * extra bytes and does not output any data until *_final,
		 * so do not bother looking at the size of the output
		 * buffer at this time.
		 */
		out_len = 0;
		break;
	case CKM_AES_CTR:
		/*
		 * CTR mode is a stream cipher, so we always output exactly as
		 * much ciphertext as input plaintext
		 */
		out_len = ulDataLen;
		break;
	default:
		out_len = aes_ctx->ac_remainder_len + ulDataLen;

		/*
		 * The number of complete blocks we can encrypt right now.
		 * The underlying implementation will buffer any remaining data
		 * until the next *_update call.
		 */
		out_len &= ~(AES_BLOCK_LEN - 1);
		break;
	}

	if (pEncryptedData == NULL) {
		*pulEncryptedDataLen = out_len;
		return (CKR_OK);
	}

	if (*pulEncryptedDataLen < out_len) {
		*pulEncryptedDataLen = out_len;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rc = aes_encrypt_contiguous_blocks(aes_ctx, (char *)pData, ulDataLen,
	    &out);

	/*
	 * Since out.cd_offset is set to 0 initially and the underlying
	 * implementation increments out.cd_offset by the amount of output
	 * written, so we can just use the value as the amount written.
	 */
	*pulEncryptedDataLen = out.cd_offset;

	if (rc != CRYPTO_SUCCESS) {
		return (CKR_FUNCTION_FAILED);
	}

	rv = crypto2pkcs11_error_number(rc);

	return (rv);
}

CK_RV
soft_aes_decrypt_update(soft_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	aes_ctx_t *aes_ctx = session_p->decrypt.context;
	uint8_t *buffer_block = NULL;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulDataLen,
		.cd_raw.iov_base = (char *)pData,
		.cd_raw.iov_len = *pulDataLen
	};
	CK_MECHANISM_TYPE mech = session_p->decrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	size_t in_len = ulEncryptedDataLen;
	size_t out_len;
	int rc = CRYPTO_SUCCESS;

	switch (mech) {
	case CKM_AES_CCM:
	case CKM_AES_GCM:
		out_len = 0;
		break;
	case CKM_AES_CBC_PAD:
		/*
		 * For CKM_AES_CBC_PAD, we use the existing code for CBC
		 * mode in libsoftcrypto (which itself uses the code in
		 * usr/src/common/crypto/modes for CBC mode).  For
		 * non-padding AES CBC mode, aes_decrypt_contiguous_blocks()
		 * will accumulate ciphertext in aes_ctx->ac_remainder until
		 * there is at least AES_BLOCK_LEN bytes of ciphertext available
		 * to decrypt.  At that point, as many blocks of AES_BLOCK_LEN
		 * sized ciphertext blocks are decrypted.  Any remainder is
		 * copied into aes_ctx->ac_remainder for decryption in
		 * subsequent calls to aes_decrypt_contiguous_blocks().
		 *
		 * When PKCS#7 padding is used, the buffering
		 * aes_decrypt_contigous_blocks() performs is insufficient.
		 * PKCS#7 padding always adds [1..AES_BLOCK_LEN] bytes of
		 * padding to plaintext, so the resulting ciphertext is always
		 * larger than the input plaintext.  However we cannot know
		 * which block is the final block (and needs its padding
		 * stripped) until C_DecryptFinal() is called.  Additionally,
		 * it is permissible for a caller to use buffers sized to the
		 * output plaintext -- i.e. smaller than the input ciphertext.
		 * This leads to a more complicated buffering/accumulation
		 * strategy than what aes_decrypt_contiguous_blocks() provides
		 * us.
		 *
		 * Our buffering strategy works as follows:
		 *  For each call to C_DecryptUpdate, we calculate the
		 *  total amount of ciphertext available (buffered plus what's
		 *  passed in) as the initial output size (out_len). Based
		 *  on the value of out_len, there are three possibilties:
		 *
		 *  1. We have less than AES_BLOCK_LEN + 1 bytes of
		 *  ciphertext available. Accumulate the ciphertext in
		 *  aes_ctx->ac_remainder. Note that while we could let
		 *  aes_decrypt_contiguous_blocks() buffer the input for us
		 *  when we have less than AES_BLOCK_LEN bytes, we would still
		 *  need to buffer when we have exactly AES_BLOCK_LEN
		 *  bytes available, so we just handle both situations with
		 *  one if clause.
		 *
		 *  2. We have at least AES_BLOCK_LEN + 1 bytes of
		 *  ciphertext, and the total amount available is also an
		 *  exact multiple of AES_BLOCK_LEN. We cannot know if the
		 *  last block of input is the final block (yet), but we
		 *  are an exact multiple of AES_BLOCK_LEN, and we have
		 *  at least AES_BLOCK_LEN + 1 bytes available, therefore
		 *  there must be at least 2 * AES_BLOCK_LEN bytes of input
		 *  ciphertext available. It also means there's at least one
		 *  full block of input ciphertext that can be decrypted. We
		 *  reduce the size of the input (in_len) given to
		 *  aes_decrypt_contiguous_bytes() by AES_BLOCK_LEN to prevent
		 *  it from decrypting the last full block of data.
		 *  aes_decrypt_contiguous_blocks() will when decrypt any
		 *  buffered data in aex_ctx->ac_remainder, and then any
		 *  input data passed. Since we have an exact multiple of
		 *  AES_BLOCK_LEN, aes_ctx->ac_remainder will be empty
		 *  (aes_ctx->ac_remainder_len == 0), once
		 *  aes_decrypt_contiguout_block() completes, and we can
		 *  copy the last block of data into aes_ctx->ac_remainder.
		 *
		 *  3. We have at least AES_BLOCK_LEN + 1 bytes of
		 *  ciphertext, but the total amount available is not an
		 *  exact multiple of AES_BLOCK_LEN. We decrypt all of
		 *  full blocks of data we have. The remainder will be
		 *  less than AES_BLOCK_LEN bytes. We let
		 *  aes_decrypt_contiguous_blocks() buffer the remainder
		 *  for us since it would normally do this anyway. Since there
		 *  is a remainder, the full blocks that are present cannot
		 *  be the last block, so we can safey decrypt all of them.
		 *
		 * Some things to note:
		 *  - The above semantics will cause aes_ctx->ac_remainder to
		 *  never accumulate more than AES_BLOCK_LEN bytes of
		 *  ciphertext. Once we reach at least AES_BLOCK_LEN + 1 bytes,
		 *  we will decrypt the contents of aes_ctx->ac_remainder by one
		 *  of the last two scenarios described above.
		 *
		 *  - We must always end up with AES_BLOCK_LEN bytes of data
		 *  in aes_ctx->ac_remainder when C_DecryptFinal() is called.
		 *  The first and third scenarios above may leave
		 *  aes_ctx->ac_remainder with less than AES_BLOCK_LEN bytes,
		 *  however the total size of the input ciphertext that's
		 *  been decrypted must end up a multiple of AES_BLOCK_LEN.
		 *  Therefore, we can always assume when there is a
		 *  remainder that more data is coming.  If we do end up
		 *  with a remainder that's not AES_BLOCK_LEN bytes long
		 *  when C_DecryptFinal() is called, the input is assumed
		 *  invalid and we return CKR_DATA_LEN_RANGE (see
		 *  soft_aes_decrypt_final()).
		 */

		VERIFY3U(aes_ctx->ac_remainder_len, <=, AES_BLOCK_LEN);
		if (in_len >= SIZE_MAX - AES_BLOCK_LEN)
			return (CKR_ENCRYPTED_DATA_LEN_RANGE);

		out_len = aes_ctx->ac_remainder_len + in_len;

		if (out_len <= AES_BLOCK_LEN) {
			/*
			 * The first scenario detailed above, accumulate
			 * ciphertext in ac_remainder_len and return.
			 */
			uint8_t *dest = (uint8_t *)aes_ctx->ac_remainder +
			    aes_ctx->ac_remainder_len;

			bcopy(pEncryptedData, dest, in_len);
			aes_ctx->ac_remainder_len += in_len;
			*pulDataLen = 0;

			/*
			 * Since we aren't writing an output, and are returning
			 * here, we don't need to adjust out_len -- we never
			 * reach the output buffer size checks after the
			 * switch statement.
			 */
			return (CKR_OK);
		} else if (out_len % AES_BLOCK_LEN == 0) {
			/*
			 * The second scenario decribed above. The total amount
			 * available is a multiple of AES_BLOCK_LEN, and
			 * we have more than one block.  We reduce the
			 * input size (in_len) by AES_BLOCK_LEN. We also
			 * reduce the output size (out_len) by AES_BLOCK_LEN
			 * for the output buffer size checks that follow
			 * the switch statement. In certain situations,
			 * PKCS#11 requires this to be an exact value, so
			 * the size check cannot occur for CKM_AES_CBC_PAD
			 * until after we've determine which scenario we
			 * have.
			 *
			 * Because we never accumulate more than AES_BLOCK_LEN
			 * bytes in aes_ctx->ac_remainder, when we are in
			 * this scenario, the following VERIFYs should always
			 * be true (and serve as a final safeguard against
			 * underflow).
			 */
			VERIFY3U(in_len, >=, AES_BLOCK_LEN);

			buffer_block = pEncryptedData + in_len - AES_BLOCK_LEN;

			in_len -= AES_BLOCK_LEN;

			/*
			 * This else clause explicity checks
			 * out_len > AES_BLOCK_LEN, so this is also safe.
			 */
			out_len -= AES_BLOCK_LEN;
		} else {
			/*
			 * The third scenario above.  We have at least
			 * AES_BLOCK_LEN + 1 bytes, but the total amount of
			 * input ciphertext available is not an exact
			 * multiple of AES_BLOCK_LEN.  Let
			 * aes_decrypt_contiguous_blocks() handle the
			 * buffering of the remainder.  Update the
			 * output size to reflect the actual amount of output
			 * we want to emit for the checks after the switch
			 * statement.
			 */
			out_len &= ~(AES_BLOCK_LEN - 1);
		}
		break;
	case CKM_AES_CTR:
		/*
		 * CKM_AES_CTR is a stream cipher, so we always output
		 * exactly as much output plaintext as input ciphertext
		 */
		out_len = in_len;
		break;
	default:
		out_len = aes_ctx->ac_remainder_len + in_len;
		out_len &= ~(AES_BLOCK_LEN - 1);
		break;
	}

	/*
	 * C_DecryptUpdate() verifies that pulDataLen is not NULL prior
	 * to calling soft_decrypt_common() (which calls us).
	 */

	if (pData == NULL) {
		/*
		 * If the output buffer (pData) is NULL, that means the
		 * caller is inquiring about the size buffer needed to
		 * complete the C_DecryptUpdate() request.  While we are
		 * permitted to set *pulDataLen to an estimated value that can
		 * be 'slightly' larger than the actual value required,
		 * since we know the exact size we need, we stick with the
		 * exact size.
		 */
		*pulDataLen = out_len;
		return (CKR_OK);
	}

	if (*pulDataLen < out_len) {
		/*
		 * Not an inquiry, but the output buffer isn't large enough.
		 * PKCS#11 requires that this scenario not fail fatally (as
		 * well as return a different error value). This situation
		 * also requires us to set *pulDataLen to the _exact_ size
		 * required.
		 */
		*pulDataLen = out_len;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rc = aes_decrypt_contiguous_blocks(aes_ctx, (char *)pEncryptedData,
	    in_len, &out);

	if (rc != CRYPTO_SUCCESS) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}

	*pulDataLen = out.cd_offset;

	switch (mech) {
	case CKM_AES_CBC_PAD:
		if (buffer_block == NULL) {
			break;
		}

		VERIFY0(aes_ctx->ac_remainder_len);

		/*
		 * We had multiple blocks of data to decrypt with nothing
		 * left over and deferred decrypting the last block of data.
		 * Copy it into aes_ctx->ac_remainder to decrypt on the
		 * next update call (or final).
		 */
		bcopy(buffer_block, aes_ctx->ac_remainder, AES_BLOCK_LEN);
		aes_ctx->ac_remainder_len = AES_BLOCK_LEN;
		break;
	}

done:
	return (rv);
}

CK_RV
soft_aes_encrypt_final(soft_session_t *session_p,
    CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	aes_ctx_t *aes_ctx = session_p->encrypt.context;
	crypto_data_t data = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulLastEncryptedPartLen,
		.cd_raw.iov_base = (char *)pLastEncryptedPart,
		.cd_raw.iov_len = *pulLastEncryptedPartLen
	};
	CK_MECHANISM_TYPE mech = session_p->encrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	size_t out_len;
	int rc = CRYPTO_SUCCESS;

	switch (mech) {
	case CKM_AES_CBC_PAD:
		/*
		 * We always add 1..AES_BLOCK_LEN of padding to the input
		 * plaintext to round up to a multiple of AES_BLOCK_LEN.
		 * During encryption, we never output a partially encrypted
		 * block (that is the amount encrypted by each call of
		 * C_EncryptUpdate() is always either 0 or n * AES_BLOCK_LEN).
		 * As a result, at the end of the encryption operation, we
		 * output AES_BLOCK_LEN bytes of data -- this could be a full
		 * block of padding, or a combination of data + padding.
		 */
		out_len = AES_BLOCK_LEN;
		break;
	case CKM_AES_CTR:
		/*
		 * Since CKM_AES_CTR is a stream cipher, we never buffer any
		 * input, so we always have 0 remaining bytes of output.
		 */
		out_len = 0;
		break;
	case CKM_AES_CCM:
		out_len = aes_ctx->ac_remainder_len +
		    aes_ctx->acu.acu_ccm.ccm_mac_len;
		break;
	case CKM_AES_GCM:
		out_len = aes_ctx->ac_remainder_len +
		    aes_ctx->acu.acu_gcm.gcm_tag_len;
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		out_len = AES_BLOCK_LEN;
		break;
	default:
		/*
		 * Everything other AES mechansism requires full blocks of
		 * input.  If the input was not an exact multiple of
		 * AES_BLOCK_LEN, it is a fatal error.
		 */
		if (aes_ctx->ac_remainder_len > 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto done;
		}
		out_len = 0;
	}

	if (*pulLastEncryptedPartLen < out_len || pLastEncryptedPart == NULL) {
		*pulLastEncryptedPartLen = out_len;
		return ((pLastEncryptedPart == NULL) ?
		    CKR_OK : CKR_BUFFER_TOO_SMALL);
	}

	switch (mech) {
	case CKM_AES_CBC_PAD: {
		char block[AES_BLOCK_LEN] = { 0 };
		size_t padlen = AES_BLOCK_LEN - aes_ctx->ac_remainder_len;

		if (padlen == 0) {
			padlen = AES_BLOCK_LEN;
		}

		(void) memset(block, padlen & 0xff, sizeof (block));
		rc = aes_encrypt_contiguous_blocks(aes_ctx, block,
		    padlen, &data);
		explicit_bzero(block, sizeof (block));
		break;
	}
	case CKM_AES_CTR:
		/*
		 * Since CKM_AES_CTR is a stream cipher, we never
		 * buffer any data, and thus have no remaining data
		 * to output at the end
		 */
		break;
	case CKM_AES_CCM:
		rc = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, &data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;
	case CKM_AES_GCM:
		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		rc = cmac_mode_final((cbc_ctx_t *)aes_ctx, &data,
		    aes_encrypt_block, aes_xor_block);
		break;
	default:
		break;
	}
	rv = crypto2pkcs11_error_number(rc);

done:
	if (rv == CKR_OK) {
		*pulLastEncryptedPartLen = data.cd_offset;
	}

	soft_aes_free_ctx(aes_ctx);
	session_p->encrypt.context = NULL;
	return (rv);
}

CK_RV
soft_aes_decrypt_final(soft_session_t *session_p, CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
{
	aes_ctx_t *aes_ctx = session_p->decrypt.context;
	CK_MECHANISM_TYPE mech = session_p->decrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	int rc = CRYPTO_SUCCESS;
	size_t out_len;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulLastPartLen,
		.cd_raw.iov_base = (char *)pLastPart,
		.cd_raw.iov_len = *pulLastPartLen
	};

	switch (mech) {
	case CKM_AES_CBC_PAD:
		/*
		 * PKCS#11 requires that a caller can discover the size of
		 * the output buffer required by calling
		 * C_DecryptFinal(hSession, NULL, &len) which sets
		 * *pulLastPartLen to the size required.  However, it also
		 * allows if one calls C_DecryptFinal with a buffer (i.e.
		 * pLastPart != NULL) that is too small, to return
		 * CKR_BUFFER_TOO_SMALL with *pulLastPartLen set to the
		 * _exact_ size required (when pLastPart is NULL, the
		 * implementation is allowed to set a 'sightly' larger
		 * value than is strictly necessary.  In either case, the
		 * caller is allowed to retry the operation (the operation
		 * is not terminated).
		 *
		 * With PKCS#7 padding, we cannot determine the exact size of
		 * the output until we decrypt the final block.  As such, the
		 * first time for a given decrypt operation we are called,
		 * we decrypt the final block and stash it in the aes_ctx
		 * remainder block.  On any subsequent calls in the
		 * current decrypt operation, we then can use the decrypted
		 * block as necessary to provide the correct semantics.
		 *
		 * The cleanup of aes_ctx when the operation terminates
		 * will take care of clearing out aes_ctx->ac_remainder_len.
		 */
		if ((aes_ctx->ac_flags & P11_DECRYPTED) == 0) {
			uint8_t block[AES_BLOCK_LEN] = { 0 };
			crypto_data_t block_out = {
				.cd_format = CRYPTO_DATA_RAW,
				.cd_offset = 0,
				.cd_length = sizeof (block),
				.cd_raw.iov_base = (char *)block,
				.cd_raw.iov_len = sizeof (block)
			};
			size_t amt, i;
			uint8_t pad_len;

			if (aes_ctx->ac_remainder_len != AES_BLOCK_LEN) {
				return (CKR_DATA_LEN_RANGE);
			}

			rc = aes_decrypt_contiguous_blocks(aes_ctx,
			    (char *)block, 0, &block_out);
			if (rc != CRYPTO_SUCCESS) {
				explicit_bzero(block, sizeof (block));
				return (CKR_FUNCTION_FAILED);
			}

			pad_len = block[AES_BLOCK_LEN - 1];

			/*
			 * RFC5652 6.3 The amount of padding must be
			 * block_sz - (len mod block_size).  This means
			 * the amount of padding must always be in the
			 * range [1..block_size].
			 */
			if (pad_len == 0 || pad_len > AES_BLOCK_LEN) {
				rv = CKR_ENCRYPTED_DATA_INVALID;
				explicit_bzero(block, sizeof (block));
				goto done;
			}
			amt = AES_BLOCK_LEN - pad_len;

			/*
			 * Verify the padding is correct.  Try to do so
			 * in as constant a time as possible.
			 */
			for (i = amt; i < AES_BLOCK_LEN; i++) {
				if (block[i] != pad_len) {
					rv = CKR_ENCRYPTED_DATA_INVALID;
				}
			}
			if (rv != CKR_OK) {
				explicit_bzero(block, sizeof (block));
				goto done;
			}

			bcopy(block, aes_ctx->ac_remainder, amt);
			explicit_bzero(block, sizeof (block));

			aes_ctx->ac_flags |= P11_DECRYPTED;
			aes_ctx->ac_remainder_len = amt;
		}

		out_len = aes_ctx->ac_remainder_len;
		break;
	case CKM_AES_CTR:
		/*
		 * Since CKM_AES_CTR is a stream cipher, we never have
		 * any remaining bytes to output.
		 */
		out_len = 0;
		break;
	case CKM_AES_CCM:
		out_len = aes_ctx->ac_data_len;
		break;
	case CKM_AES_GCM:
		out_len = aes_ctx->acu.acu_gcm.gcm_processed_data_len -
		    aes_ctx->acu.acu_gcm.gcm_tag_len;
		break;
	default:
		/*
		 * The remaining mechanims require an exact multiple of
		 * AES_BLOCK_LEN of ciphertext.  Any other value is an error.
		 */
		if (aes_ctx->ac_remainder_len > 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto done;
		}
		out_len = 0;
		break;
	}

	if (*pulLastPartLen < out_len || pLastPart == NULL) {
		*pulLastPartLen = out_len;
		return ((pLastPart == NULL) ? CKR_OK : CKR_BUFFER_TOO_SMALL);
	}

	switch (mech) {
	case CKM_AES_CBC_PAD:
		*pulLastPartLen = out_len;
		if (out_len == 0) {
			break;
		}
		bcopy(aes_ctx->ac_remainder, pLastPart, out_len);
		out.cd_offset += out_len;
		break;
	case CKM_AES_CCM:
		ASSERT3U(aes_ctx->ac_processed_data_len, ==, out_len);
		ASSERT3U(aes_ctx->ac_processed_mac_len, ==,
		    aes_ctx->ac_mac_len);

		rc = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	case CKM_AES_GCM:
		rc = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;
	default:
		break;
	}

	VERIFY3U(out.cd_offset, ==, out_len);
	rv = crypto2pkcs11_error_number(rc);

done:
	if (rv == CKR_OK) {
		*pulLastPartLen = out.cd_offset;
	}

	soft_aes_free_ctx(aes_ctx);
	session_p->decrypt.context = NULL;

	return (rv);
}

/*
 * Allocate and initialize AES contexts for sign and verify operations
 * (including the underlying encryption context needed to sign or verify) --
 * called by C_SignInit() and C_VerifyInit() to perform the CKM_AES_* MAC
 * mechanisms. For general-length AES MAC, also validate the MAC length.
 */
CK_RV
soft_aes_sign_verify_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p, boolean_t sign_op)
{
	soft_aes_sign_ctx_t	*ctx = NULL;
	/* For AES CMAC (the only AES MAC currently), iv is always 0 */
	CK_BYTE		iv[AES_BLOCK_LEN] = { 0 };
	CK_MECHANISM	encrypt_mech = {
		.mechanism = CKM_AES_CMAC,
		.pParameter = iv,
		.ulParameterLen = sizeof (iv)
	};
	CK_RV		rv;
	size_t		mac_len = AES_BLOCK_LEN;

	if (key_p->key_type != CKK_AES)
		return (CKR_KEY_TYPE_INCONSISTENT);

	/* C_{Sign,Verify}Init() validate pMechanism != NULL */
	if (pMechanism->mechanism == CKM_AES_CMAC_GENERAL) {
		if (pMechanism->pParameter == NULL) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		mac_len = *(CK_MAC_GENERAL_PARAMS *)pMechanism->pParameter;

		if (mac_len > AES_BLOCK_LEN) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}
	}

	ctx = calloc(1, sizeof (*ctx));
	if (ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = soft_aes_check_mech_param(pMechanism, &ctx->aes_ctx);
	if (rv != CKR_OK) {
		soft_aes_free_ctx(ctx->aes_ctx);
		goto done;
	}

	if ((rv = soft_encrypt_init_internal(session_p, &encrypt_mech,
	    key_p)) != CKR_OK) {
		soft_aes_free_ctx(ctx->aes_ctx);
		goto done;
	}

	ctx->mac_len = mac_len;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (sign_op) {
		session_p->sign.context = ctx;
		session_p->sign.mech.mechanism = pMechanism->mechanism;
	} else {
		session_p->verify.context = ctx;
		session_p->verify.mech.mechanism = pMechanism->mechanism;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

done:
	if (rv != CKR_OK) {
		soft_aes_free_ctx(ctx->aes_ctx);
		free(ctx);
	}

	return (rv);
}

CK_RV
soft_aes_sign_verify_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned, CK_ULONG_PTR pulSignedLen,
    boolean_t sign_op, boolean_t Final)
{
	soft_aes_sign_ctx_t	*soft_aes_ctx_sign_verify;
	CK_RV			rv;
	CK_BYTE			*pEncrypted = NULL;
	CK_ULONG		ulEncryptedLen = AES_BLOCK_LEN;
	CK_BYTE			last_block[AES_BLOCK_LEN];

	if (sign_op) {
		soft_aes_ctx_sign_verify =
		    (soft_aes_sign_ctx_t *)session_p->sign.context;

		if (soft_aes_ctx_sign_verify->mac_len == 0) {
			*pulSignedLen = 0;
			goto clean_exit;
		}

		/* Application asks for the length of the output buffer. */
		if (pSigned == NULL) {
			*pulSignedLen = soft_aes_ctx_sign_verify->mac_len;
			return (CKR_OK);
		}

		/* Is the application-supplied buffer large enough? */
		if (*pulSignedLen < soft_aes_ctx_sign_verify->mac_len) {
			*pulSignedLen = soft_aes_ctx_sign_verify->mac_len;
			return (CKR_BUFFER_TOO_SMALL);
		}
	} else {
		soft_aes_ctx_sign_verify =
		    (soft_aes_sign_ctx_t *)session_p->verify.context;
	}

	if (Final) {
		rv = soft_encrypt_final(session_p, last_block,
		    &ulEncryptedLen);
	} else {
		rv = soft_encrypt(session_p, pData, ulDataLen,
		    last_block, &ulEncryptedLen);
	}

	if (rv == CKR_OK) {
		*pulSignedLen = soft_aes_ctx_sign_verify->mac_len;

		/* the leftmost mac_len bytes of last_block is our MAC */
		(void) memcpy(pSigned, last_block, *pulSignedLen);
	}

clean_exit:

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* soft_encrypt_common() has freed the encrypt context */
	if (sign_op) {
		free(session_p->sign.context);
		session_p->sign.context = NULL;
	} else {
		free(session_p->verify.context);
		session_p->verify.context = NULL;
	}
	session_p->encrypt.flags = 0;

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	if (pEncrypted) {
		free(pEncrypted);
	}

	return (rv);
}

/*
 * Called by soft_sign_update()
 */
CK_RV
soft_aes_mac_sign_verify_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_BYTE		buf[AES_BLOCK_LEN];
	CK_ULONG	ulEncryptedLen = AES_BLOCK_LEN;
	CK_RV		rv;

	rv = soft_encrypt_update(session_p, pPart, ulPartLen,
	    buf, &ulEncryptedLen);
	explicit_bzero(buf, sizeof (buf));

	return (rv);
}

void
soft_aes_free_ctx(aes_ctx_t *ctx)
{
	size_t len = 0;

	if (ctx == NULL)
		return;

	if (ctx->ac_flags & ECB_MODE) {
		len = sizeof (ecb_ctx_t);
	} else if (ctx->ac_flags & (CBC_MODE|CMAC_MODE)) {
		len = sizeof (cbc_ctx_t);
	} else if (ctx->ac_flags & CTR_MODE) {
		len = sizeof (ctr_ctx_t);
	} else if (ctx->ac_flags & CCM_MODE) {
		len = sizeof (ccm_ctx_t);
	} else if (ctx->ac_flags & GCM_MODE) {
		len = sizeof (gcm_ctx_t);
	}

	freezero(ctx->ac_keysched, ctx->ac_keysched_len);
	freezero(ctx, len);
}
