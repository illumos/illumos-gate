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
 * Copyright (c) 2018, Joyent, Inc.
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
		    pp->cb, aes_copy_block);
		break;
	}
	case CKM_AES_CCM: {
		/* LINTED: pointer alignment */
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
		return (rv);
	}

	rv = soft_aes_init_ctx(aes_ctx, pMechanism, encrypt);
	if (rv != CKR_OK) {
		goto done;
		return (rv);
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

	remainder = ulDataLen & (AES_BLOCK_LEN - 1);

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

	switch (aes_ctx->ac_flags & (CMAC_MODE|CCM_MODE|GCM_MODE)) {
	case CCM_MODE:
		length_needed = ulDataLen + aes_ctx->ac_mac_len;
		break;
	case GCM_MODE:
		length_needed = ulDataLen + aes_ctx->ac_tag_len;
		break;
	case CMAC_MODE:
		length_needed = AES_BLOCK_LEN;
		break;
	default:
		length_needed = ulDataLen;

		/* CKM_AES_CBC_PAD out pads to a multiple of AES_BLOCK_LEN */
		if (mech == CKM_AES_CBC_PAD) {
			length_needed += AES_BLOCK_LEN - remainder;
		}
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

	/*
	 * As CKM_AES_CTR is a stream cipher, ctr_mode_final is always
	 * invoked in the _update() functions, so we do not need to call it
	 * here.
	 */
	if (mech == CKM_AES_CBC_PAD) {
		/*
		 * aes_encrypt_contiguous_blocks() accumulates plaintext
		 * in aes_ctx and then encrypts once it has accumulated
		 * a multiple of AES_BLOCK_LEN bytes of plaintext (through one
		 * or more calls).  Any leftover plaintext is left in aes_ctx
		 * for subsequent calls.  If there is any remaining plaintext
		 * at the end, we pad it out to to AES_BLOCK_LEN using the
		 * amount of padding to add as the value of the pad bytes
		 * (i.e. PKCS#7 padding) and call
		 * aes_encrypt_contiguous_blocks() one last time.
		 *
		 * Even when the input is already a multiple of AES_BLOCK_LEN,
		 * we must add an additional full block so that we can determine
		 * the amount of padding to remove during decryption (by
		 * examining the last byte of the decrypted ciphertext).
		 */
		size_t amt = AES_BLOCK_LEN - remainder;
		char block[AES_BLOCK_LEN];

		ASSERT3U(remainder, ==, aes_ctx->ac_remainder_len);
		ASSERT3U(amt + remainder, ==, AES_BLOCK_LEN);

		/*
		 * The existing soft_add_pkcs7_padding() interface is
		 * overkill for what is effectively a memset().  A better
		 * RFE would be to create a CBC_PAD mode.
		 */
		(void) memset(block, amt & 0xff, sizeof (block));
		rc = aes_encrypt_contiguous_blocks(aes_ctx, block, amt, &out);
	} else if (aes_ctx->ac_flags & CCM_MODE) {
		rc = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
	} else if (aes_ctx->ac_flags & GCM_MODE) {
		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
	} else if (aes_ctx->ac_flags & CMAC_MODE) {
		rc = cmac_mode_final((cbc_ctx_t *)aes_ctx, &out,
		    aes_encrypt_block, aes_xor_block);
		aes_ctx->ac_remainder_len = 0;
	}

cleanup:
	if (rc != CRYPTO_SUCCESS && rv == CKR_OK) {
		*pulEncryptedDataLen = 0;
		rv = crypto2pkcs11_error_number(rc);
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	soft_aes_free_ctx(aes_ctx);
	session_p->encrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	if (rv == CKR_OK) {
		*pulEncryptedDataLen = out.cd_offset;
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

	remainder = ulEncryptedDataLen & (AES_BLOCK_LEN - 1);

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
	if (mech == CKM_AES_CBC_PAD) {
		rv = soft_remove_pkcs7_padding(pData, *pulDataLen, pulDataLen);
	} else if (aes_ctx->ac_flags & CCM_MODE) {
		ASSERT3U(aes_ctx->ac_processed_data_len, ==,
		    aes_ctx->ac_data_len);
		ASSERT3U(aes_ctx->ac_processed_mac_len, ==,
		    aes_ctx->ac_mac_len);

		rc = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
	} else if (aes_ctx->ac_flags & GCM_MODE) {
		rc = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
	}

cleanup:
	if (rc != CRYPTO_SUCCESS && rv == CKR_OK) {
		rv = crypto2pkcs11_error_number(rc);
		*pulDataLen = 0;
	}

	if (rv == CKR_OK) {
		*pulDataLen = out.cd_offset;
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
	size_t out_len = aes_ctx->ac_remainder_len + ulDataLen;
	int rc;

	/* Check size of the output buffer */
	if (mech == CKM_AES_CBC_PAD && (out_len <= AES_BLOCK_LEN)) {
		/*
		 * Since there is currently no CBC_PAD mode, we must stash any
		 * remainder ourselves.  For all other modes,
		 * aes_encrypt_contiguous_blocks() will call the mode specific
		 * encrypt function and will stash any reminder if required.
		 */
		if (pData != NULL) {
			uint8_t *dest = (uint8_t *)aes_ctx->ac_remainder +
			    aes_ctx->ac_remainder_len;

			bcopy(pData, dest, ulDataLen);
			aes_ctx->ac_remainder_len += ulDataLen;
		}

		*pulEncryptedDataLen = 0;
		return (CKR_OK);
	} else if (aes_ctx->ac_flags & CMAC_MODE) {
		/*
		 * The underlying CMAC implementation handles the storing of
		 * extra bytes and does not output any data until *_final,
		 * so do not bother looking at the size of the output
		 * buffer at this time.
		 */
		if (pData == NULL) {
			*pulEncryptedDataLen = 0;
			return (CKR_OK);
		}
	} else {
		/*
		 * The number of complete blocks we can encrypt right now.
		 * The underlying implementation will buffer any remaining data
		 * until the next *_update call.
		 */
		out_len &= ~(AES_BLOCK_LEN - 1);

		if (pEncryptedData == NULL) {
			*pulEncryptedDataLen = out_len;
			return (CKR_OK);
		}

		if (*pulEncryptedDataLen < out_len) {
			*pulEncryptedDataLen = out_len;
			return (CKR_BUFFER_TOO_SMALL);
		}
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
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}

	/*
	 * Since AES counter mode is a stream cipher, we call ctr_mode_final()
	 * to pick up any remaining bytes.  It is an internal function that
	 * does not destroy the context like *normal* final routines.
	 */
	if ((aes_ctx->ac_flags & CTR_MODE) && (aes_ctx->ac_remainder_len > 0)) {
		rc = ctr_mode_final((ctr_ctx_t *)aes_ctx, &out,
		    aes_encrypt_block);
	}

done:
	if (rc != CRYPTO_SUCCESS && rv == CKR_OK) {
		rv = crypto2pkcs11_error_number(rc);
	}

	return (rv);
}

CK_RV
soft_aes_decrypt_update(soft_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	aes_ctx_t *aes_ctx = session_p->decrypt.context;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulDataLen,
		.cd_raw.iov_base = (char *)pData,
		.cd_raw.iov_len = *pulDataLen
	};
	CK_MECHANISM_TYPE mech = session_p->decrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	size_t out_len = 0;
	int rc = CRYPTO_SUCCESS;

	if ((aes_ctx->ac_flags & (CCM_MODE|GCM_MODE)) == 0) {
		out_len = aes_ctx->ac_remainder_len + ulEncryptedDataLen;

		if (mech == CKM_AES_CBC_PAD && out_len <= AES_BLOCK_LEN) {
			uint8_t *dest = (uint8_t *)aes_ctx->ac_remainder +
				aes_ctx->ac_remainder_len;

			bcopy(pEncryptedData, dest, ulEncryptedDataLen);
			aes_ctx->ac_remainder_len += ulEncryptedDataLen;
			return (CKR_OK);
		}
		out_len &= ~(AES_BLOCK_LEN - 1);
	}

	if (pData == NULL) {
		*pulDataLen = out_len;
		return (CKR_OK);
	}

	if (*pulDataLen < out_len) {
		*pulDataLen = out_len;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rc = aes_decrypt_contiguous_blocks(aes_ctx, (char *)pEncryptedData,
	    ulEncryptedDataLen, &out);

	if (rc != CRYPTO_SUCCESS) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}

	*pulDataLen = out.cd_offset;

	if ((aes_ctx->ac_flags & CTR_MODE) && (aes_ctx->ac_remainder_len > 0)) {
		rc = ctr_mode_final((ctr_ctx_t *)aes_ctx, &out,
		    aes_encrypt_block);
	}

done:
	if (rc != CRYPTO_SUCCESS && rv == CKR_OK) {
		rv = crypto2pkcs11_error_number(rc);
	}

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
	int rc = CRYPTO_SUCCESS;
	CK_RV rv = CKR_OK;

	if (session_p->encrypt.mech.mechanism == CKM_AES_CBC_PAD) {
		char block[AES_BLOCK_LEN] = { 0 };
		size_t padlen = AES_BLOCK_LEN - aes_ctx->ac_remainder_len;

		(void) memset(block, padlen & 0xff, sizeof (block));
		if (padlen > 0) {
			rc = aes_encrypt_contiguous_blocks(aes_ctx, block,
			    padlen, &data);
		}
	} else if (aes_ctx->ac_flags & CTR_MODE) {
		if (pLastEncryptedPart == NULL) {
			*pulLastEncryptedPartLen = aes_ctx->ac_remainder_len;
			return (CKR_OK);
		}

		if (aes_ctx->ac_remainder_len > 0) {
			rc = ctr_mode_final((ctr_ctx_t *)aes_ctx, &data,
			    aes_encrypt_block);
			if (rc == CRYPTO_BUFFER_TOO_SMALL) {
				rv = CKR_BUFFER_TOO_SMALL;
			}
		}
	} else if (aes_ctx->ac_flags & CCM_MODE) {
		rc = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, &data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
	} else if (aes_ctx->ac_flags & GCM_MODE) {
		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
	} else if (aes_ctx->ac_flags & CMAC_MODE) {
		if (pLastEncryptedPart == NULL) {
			*pulLastEncryptedPartLen = AES_BLOCK_LEN;
			return (CKR_OK);
		}

		rc = cmac_mode_final((cbc_ctx_t *)aes_ctx, &data,
		    aes_encrypt_block, aes_xor_block);
	} else {
		/*
		 * There must be no unprocessed plaintext.
		 * This happens if the length of the last data is not a
		 * multiple of the AES block length.
		 */
		*pulLastEncryptedPartLen = 0;
		if (aes_ctx->ac_remainder_len > 0) {
			rv = CKR_DATA_LEN_RANGE;
		}
	}

	if (rc != CRYPTO_SUCCESS && rv == CKR_OK) {
		rv = crypto2pkcs11_error_number(rc);
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
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulLastPartLen,
		.cd_raw.iov_base = (char *)pLastPart,
		.cd_raw.iov_len = *pulLastPartLen
	};

	if (aes_ctx->ac_remainder_len > 0) {
		switch (mech) {
		case CKM_AES_CBC_PAD:
			/*
			 * Since we cannot know the amount of padding present
			 * until after we decrypt the final block, and since
			 * we don't know which block is the last block until
			 * C_DecryptFinal() is called, we must always defer
			 * decrypting the most recent block of ciphertext
			 * until C_DecryptFinal() is called.  As a consequence,
			 * we should always have a remainder, and it should
			 * always be equal to AES_BLOCK_LEN.
			 */
			if (aes_ctx->ac_remainder_len != AES_BLOCK_LEN) {
				return (CKR_ENCRYPTED_DATA_LEN_RANGE);
			}

			if (*pulLastPartLen < AES_BLOCK_LEN) {
				*pulLastPartLen = AES_BLOCK_LEN;
				return (CKR_BUFFER_TOO_SMALL);
			}

			rc = aes_decrypt_contiguous_blocks(aes_ctx,
			    (char *)pLastPart, AES_BLOCK_LEN, &out);

			if (rc != CRYPTO_SUCCESS) {
				break;
			}

			rv = soft_remove_pkcs7_padding(pLastPart, AES_BLOCK_LEN,
			    pulLastPartLen);
			break;
		case CKM_AES_CTR:
			rc = ctr_mode_final((ctr_ctx_t *)aes_ctx, &out,
			    aes_encrypt_block);
			break;
		default:
			/* There must be no unprocessed ciphertext */
			return (CKR_ENCRYPTED_DATA_LEN_RANGE);
		}
	} else {
		/*
		 * We should never have no remainder for AES_CBC_PAD -- see
		 * above.
		 */
		ASSERT3U(mech, !=, CKM_AES_CBC_PAD);
	}

	if (aes_ctx->ac_flags & CCM_MODE) {
		size_t pt_len = aes_ctx->ac_data_len;

		if (*pulLastPartLen < pt_len) {
			*pulLastPartLen = pt_len;
			return (CKR_BUFFER_TOO_SMALL);
		}

		ASSERT3U(aes_ctx->ac_processed_data_len, ==, pt_len);
		ASSERT3U(aes_ctx->ac_processed_mac_len, ==,
		    aes_ctx->ac_mac_len);

		rc = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulLastPartLen = out.cd_offset;
		}
	} else if (aes_ctx->ac_flags & GCM_MODE) {
		gcm_ctx_t *gcm_ctx = (gcm_ctx_t *)aes_ctx;
		size_t pt_len = gcm_ctx->gcm_processed_data_len -
		    gcm_ctx->gcm_tag_len;

		if (*pulLastPartLen < pt_len) {
			*pulLastPartLen = pt_len;
			return (CKR_BUFFER_TOO_SMALL);
		}

		rc = gcm_decrypt_final(gcm_ctx, &out, AES_BLOCK_LEN,
		    aes_encrypt_block, aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulLastPartLen = out.cd_offset;
		}
	}

	if (rv == CKR_OK && rc != CRYPTO_SUCCESS) {
		rv = crypto2pkcs11_error_number(rc);
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
