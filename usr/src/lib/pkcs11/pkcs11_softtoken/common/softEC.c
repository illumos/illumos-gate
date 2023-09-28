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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/crypto/common.h>
#include <security/cryptoki.h>
#include <bignum.h>
#include <des_impl.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softEC.h"
#include "softCrypt.h"
#include "softOps.h"
#include "softMAC.h"

void
soft_free_ecparams(ECParams *params, boolean_t freeit)
{
	SECITEM_FreeItem(&params->fieldID.u.prime, B_FALSE);
	SECITEM_FreeItem(&params->curve.a, B_FALSE);
	SECITEM_FreeItem(&params->curve.b, B_FALSE);
	SECITEM_FreeItem(&params->curve.seed, B_FALSE);
	SECITEM_FreeItem(&params->base, B_FALSE);
	SECITEM_FreeItem(&params->order, B_FALSE);
	SECITEM_FreeItem(&params->DEREncoding, B_FALSE);
	SECITEM_FreeItem(&params->curveOID, B_FALSE);
	if (freeit)
		free(params);
}

static void
soft_free_ecc_context(soft_ecc_ctx_t *ecc_ctx)
{
	if (ecc_ctx != NULL) {
		if (ecc_ctx->key != NULL) {
			soft_cleanup_object(ecc_ctx->key);
			free(ecc_ctx->key);
		}

		soft_free_ecparams(&ecc_ctx->ecparams, B_FALSE);
		free(ecc_ctx);
	}
}

void
soft_free_ecprivkey(ECPrivateKey *key)
{
	soft_free_ecparams(&key->ecParams, B_FALSE);
	/*
	 * Don't free publicValue or privateValue
	 * as these values are copied into objects.
	 */
	SECITEM_FreeItem(&key->version, B_FALSE);
	free(key);
}

/*
 * Called from init routines to do basic sanity checks. Init routines,
 * e.g. sign_init should fail rather than subsequent operations.
 */
static int
check_key(soft_object_t *key_p, boolean_t sign)
{
	biginteger_t *p;
	ulong_t len;

	if (sign) {
		if ((key_p->class != CKO_PRIVATE_KEY) ||
		    (key_p->key_type != CKK_EC))
			return (CKR_KEY_TYPE_INCONSISTENT);

		p = OBJ_PRI_EC_VALUE(key_p);
		len = p->big_value_len;
		if (p->big_value == NULL)
			len = 0;

		if (len < CRYPTO_BITS2BYTES(EC_MIN_KEY_LEN) ||
		    len > CRYPTO_BITS2BYTES(EC_MAX_KEY_LEN))
			return (CKR_KEY_SIZE_RANGE);
	} else {
		if ((key_p->class != CKO_PUBLIC_KEY) ||
		    (key_p->key_type != CKK_EC))
			return (CKR_KEY_TYPE_INCONSISTENT);

		p = OBJ_PUB_EC_POINT(key_p);
		len = p->big_value_len;
		if (p->big_value == NULL)
			len = 0;

		if (len < CRYPTO_BITS2BYTES(EC_MIN_KEY_LEN) * 2 + 1 ||
		    len > CRYPTO_BITS2BYTES(EC_MAX_KEY_LEN) * 2 + 1)
			return (CKR_KEY_SIZE_RANGE);
	}

	return (CKR_OK);
}

/*
 * This function places the octet string of the specified attribute
 * into the corresponding key object.
 */
static void
soft_genECkey_set_attribute(soft_object_t *key, biginteger_t *bi,
    CK_ATTRIBUTE_TYPE type)
{
	biginteger_t *dst;

	switch (type) {
	case CKA_VALUE:
		dst = OBJ_PRI_EC_VALUE(key);
		break;

	case CKA_EC_POINT:
		dst = OBJ_PUB_EC_POINT(key);
		break;
	}
	copy_bigint_attr(bi, dst);
}

CK_RV
soft_ec_genkey_pair(soft_object_t *pubkey, soft_object_t *prikey)
{
	CK_RV rv;
	CK_ATTRIBUTE template;
	ECPrivateKey *privKey;	/* contains both public and private values */
	ECParams *ecparams;
	SECKEYECParams params_item;
	biginteger_t bi;
	uchar_t param_buffer[EC_MAX_OID_LEN];
	uint_t paramlen;

	if ((pubkey->class != CKO_PUBLIC_KEY) ||
	    (pubkey->key_type != CKK_EC))
		return (CKR_KEY_TYPE_INCONSISTENT);

	if ((prikey->class != CKO_PRIVATE_KEY) ||
	    (prikey->key_type != CKK_EC))
		return (CKR_KEY_TYPE_INCONSISTENT);

	template.type = CKA_EC_PARAMS;
	template.pValue = param_buffer;
	template.ulValueLen = sizeof (param_buffer);
	rv = soft_get_public_key_attribute(pubkey, &template);
	if (rv != CKR_OK) {
		return (rv);
	}
	paramlen = template.ulValueLen;

	/* private key also has CKA_EC_PARAMS attribute */
	rv = set_extra_attr_to_object(prikey, CKA_EC_PARAMS, &template);
	if (rv != CKR_OK) {
		return (rv);
	}

	/* ASN1 check */
	if (param_buffer[0] != 0x06 ||
	    param_buffer[1] != paramlen - 2) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}
	params_item.len = paramlen;
	params_item.data = param_buffer;
	if (EC_DecodeParams(&params_item, &ecparams, 0) != SECSuccess) {
		/* bad curve OID */
		return (CKR_ARGUMENTS_BAD);
	}

	if (EC_NewKey(ecparams, &privKey, 0) != SECSuccess) {
		soft_free_ecparams(ecparams, B_TRUE);
		return (CKR_FUNCTION_FAILED);
	}

	bi.big_value = privKey->privateValue.data;
	bi.big_value_len = privKey->privateValue.len;
	soft_genECkey_set_attribute(prikey, &bi, CKA_VALUE);

	bi.big_value = privKey->publicValue.data;
	bi.big_value_len = privKey->publicValue.len;
	soft_genECkey_set_attribute(pubkey, &bi, CKA_EC_POINT);

	soft_free_ecprivkey(privKey);
	soft_free_ecparams(ecparams, B_TRUE);

	return (CKR_OK);
}

CK_RV
soft_ec_key_derive(soft_object_t *basekey, soft_object_t *secretkey,
    void *mech_params, size_t mech_params_len)
{
	CK_RV		rv;
	CK_ATTRIBUTE	template;
	CK_ECDH1_DERIVE_PARAMS *ecdh1_derive_params = mech_params;
	uchar_t		value[EC_MAX_VALUE_LEN];
	uint32_t	value_len = sizeof (value);
	uchar_t		params[EC_MAX_OID_LEN];
	uint32_t	params_len = sizeof (params);
	uint32_t	keylen;
	ECParams	*ecparams;
	SECKEYECParams	params_item;
	SECItem		public_value_item, private_value_item, secret_item;
	uchar_t		*buf;

	if (mech_params_len != sizeof (CK_ECDH1_DERIVE_PARAMS) ||
	    ecdh1_derive_params->kdf != CKD_NULL) {
		return (CKR_MECHANISM_PARAM_INVALID);
	}

	template.type = CKA_VALUE;
	template.pValue = value;
	template.ulValueLen = value_len;
	rv = soft_get_private_key_attribute(basekey, &template);
	if (rv != CKR_OK) {
		return (rv);
	}
	value_len = template.ulValueLen;
	private_value_item.data = value;
	private_value_item.len = value_len;

	template.type = CKA_EC_PARAMS;
	template.pValue = params;
	template.ulValueLen = params_len;
	rv = soft_get_private_key_attribute(basekey, &template);
	if (rv != CKR_OK) {
		return (rv);
	}
	params_len = template.ulValueLen;

	switch (secretkey->key_type) {
	case CKK_DES:
		keylen = DES_KEYSIZE;
		break;
	case CKK_DES2:
		keylen = DES2_KEYSIZE;
		break;
	case CKK_DES3:
		keylen = DES3_KEYSIZE;
		break;
	case CKK_RC4:
	case CKK_AES:
	case CKK_GENERIC_SECRET:
#ifdef	__sparcv9
		/* LINTED */
		keylen = (uint32_t)OBJ_SEC_VALUE_LEN(secretkey);
#else	/* !__sparcv9 */
		keylen = OBJ_SEC_VALUE_LEN(secretkey);
#endif	/* __sparcv9 */
		break;
	}

	/* ASN1 check */
	if (params[0] != 0x06 ||
	    params[1] != params_len - 2) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}
	params_item.data = params;
	params_item.len = params_len;
	if (EC_DecodeParams(&params_item, &ecparams, 0) != SECSuccess) {
		/* bad curve OID */
		return (CKR_ARGUMENTS_BAD);
	}

	public_value_item.data = ecdh1_derive_params->pPublicData;
	public_value_item.len = ecdh1_derive_params->ulPublicDataLen;

	secret_item.data = NULL;
	secret_item.len = 0;

	if (ECDH_Derive(&public_value_item, ecparams, &private_value_item,
	    B_FALSE, &secret_item, 0) != SECSuccess) {
		soft_free_ecparams(ecparams, B_TRUE);
		return (CKR_FUNCTION_FAILED);
	} else {
		rv = CKR_OK;
	}

	if (keylen == 0)
		keylen = secret_item.len;

	if (keylen > secret_item.len) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto out;
	}
	buf = malloc(keylen);
	if (buf == NULL) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}
	bcopy(secret_item.data + secret_item.len - keylen, buf, keylen);
	OBJ_SEC_VALUE_LEN(secretkey) = keylen;
	OBJ_SEC_VALUE(secretkey) = buf;

out:
	soft_free_ecparams(ecparams, B_TRUE);
	SECITEM_FreeItem(&secret_item, B_FALSE);

	return (rv);
}

/*
 * Allocate a ECC context for the active sign or verify operation.
 * This function is called without the session lock held.
 */
CK_RV
soft_ecc_sign_verify_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p,
    boolean_t sign)
{
	CK_RV rv;
	CK_ATTRIBUTE template;
	CK_MECHANISM digest_mech;
	soft_ecc_ctx_t *ecc_ctx;
	soft_object_t *tmp_key = NULL;
	uchar_t params[EC_MAX_OID_LEN];
	ECParams *ecparams;
	SECKEYECParams params_item;

	if ((rv = check_key(key_p, sign)) != CKR_OK)
		return (rv);

	if (pMechanism->mechanism == CKM_ECDSA_SHA1) {
		digest_mech.mechanism = CKM_SHA_1;
		rv = soft_digest_init_internal(session_p, &digest_mech);
		if (rv != CKR_OK)
			return (rv);
	}

	ecc_ctx = malloc(sizeof (soft_ecc_ctx_t));
	if (ecc_ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/*
	 * Make a copy of the signature or verification key, and save it
	 * in the ECC crypto context since it will be used later for
	 * signing/verification. We don't want to hold any object reference
	 * on this original key while doing signing/verification.
	 */
	(void) pthread_mutex_lock(&key_p->object_mutex);
	rv = soft_copy_object(key_p, &tmp_key, SOFT_COPY_OBJ_ORIG_SH, NULL);
	if ((rv != CKR_OK) || (tmp_key == NULL)) {
		/* Most likely we ran out of space. */
		(void) pthread_mutex_unlock(&key_p->object_mutex);
		free(ecc_ctx);
		return (rv);
	}


	template.type = CKA_EC_PARAMS;
	template.pValue = params;
	template.ulValueLen = sizeof (params);
	rv = soft_get_private_key_attribute(key_p, &template);
	(void) pthread_mutex_unlock(&key_p->object_mutex);
	if (rv != CKR_OK) {
		goto out;
	}

	/* ASN1 check */
	if (params[0] != 0x06 ||
	    params[1] != template.ulValueLen - 2) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto out;
	}
	params_item.data = params;
	params_item.len = template.ulValueLen;

	ecc_ctx->key = tmp_key;

	if (EC_DecodeParams(&params_item, &ecparams, 0) != SECSuccess) {
		/* bad curve OID */
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	ecc_ctx->ecparams = *ecparams;
	free(ecparams);

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (sign) {
		session_p->sign.context = ecc_ctx;
		session_p->sign.mech.mechanism = pMechanism->mechanism;
	} else {
		session_p->verify.context = ecc_ctx;
		session_p->verify.mech.mechanism = pMechanism->mechanism;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	return (CKR_OK);

out:
	soft_cleanup_object(tmp_key);
	free(tmp_key);
	free(ecc_ctx);

	return (rv);
}

CK_RV
soft_ecc_digest_sign_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned,
    CK_ULONG_PTR pulSignedLen, boolean_t Final)
{
	CK_RV rv = CKR_OK;
	CK_BYTE hash[SHA1_HASH_SIZE];
	CK_ULONG hash_len = SHA1_HASH_SIZE;

	if (pSigned != NULL) {
		if (Final) {
			rv = soft_digest_final(session_p, hash, &hash_len);
		} else {
			rv = soft_digest(session_p, pData, ulDataLen, hash,
			    &hash_len);
		}

		if (rv != CKR_OK) {
			(void) pthread_mutex_lock(&session_p->session_mutex);
			soft_free_ecc_context(session_p->sign.context);
			session_p->sign.context = NULL;
			session_p->digest.flags = 0;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (rv);
		}
	}

	rv = soft_ecc_sign(session_p, hash, hash_len, pSigned, pulSignedLen);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	/* soft_digest_common() has freed the digest context */
	session_p->digest.flags = 0;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

CK_RV
soft_ecc_sign(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned,
    CK_ULONG_PTR pulSignedLen)
{
	CK_RV rv = CKR_OK;
	SECStatus ss;
	soft_ecc_ctx_t *ecc_ctx = session_p->sign.context;
	soft_object_t *key = ecc_ctx->key;
	uchar_t value[EC_MAX_VALUE_LEN];
	ECPrivateKey ECkey;
	SECItem signature_item;
	SECItem digest_item;
	uint_t value_len;

	if ((key->class != CKO_PRIVATE_KEY) || (key->key_type != CKK_EC)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	if (ulDataLen > EC_MAX_DIGEST_LEN) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean_exit;
	}

	/* structure assignment */
	ECkey.ecParams = ecc_ctx->ecparams;

	value_len = EC_MAX_VALUE_LEN;
	rv = soft_get_private_value(key, CKA_VALUE, value, &value_len);
	if (rv != CKR_OK) {
		goto clean_exit;
	}

	ECkey.privateValue.data = value;
	ECkey.privateValue.len = value_len;

	signature_item.data = pSigned;
	signature_item.len = *pulSignedLen;

	digest_item.data = pData;
	digest_item.len = ulDataLen;

	if ((ss = ECDSA_SignDigest(&ECkey, &signature_item, &digest_item, 0))
	    != SECSuccess) {
		if (ss == SECBufferTooSmall)
			return (CKR_BUFFER_TOO_SMALL);

		rv = CKR_FUNCTION_FAILED;
		goto clean_exit;
	}

	if (rv == CKR_OK) {
		*pulSignedLen = signature_item.len;
		if (pSigned == NULL)
			return (rv);
	}

clean_exit:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	soft_free_ecc_context(session_p->sign.context);
	session_p->sign.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	return (rv);
}

CK_RV
soft_ecc_verify(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
	CK_RV rv = CKR_OK;
	soft_ecc_ctx_t *ecc_ctx = session_p->verify.context;
	soft_object_t *key = ecc_ctx->key;
	uchar_t point[EC_MAX_POINT_LEN];
	CK_ATTRIBUTE template;
	ECPublicKey ECkey;
	SECItem signature_item;
	SECItem digest_item;

	if ((key->class != CKO_PUBLIC_KEY) ||(key->key_type != CKK_EC)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	if (ulSignatureLen > EC_MAX_SIG_LEN) {
		rv = CKR_SIGNATURE_LEN_RANGE;
		goto clean_exit;
	}

	if (ulDataLen > EC_MAX_DIGEST_LEN) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean_exit;
	}

	/* structure assignment */
	ECkey.ecParams = ecc_ctx->ecparams;

	template.type = CKA_EC_POINT;
	template.pValue = point;
	template.ulValueLen = sizeof (point);
	rv = soft_get_public_key_attribute(key, &template);
	if (rv != CKR_OK) {
		goto clean_exit;
	}

	ECkey.publicValue.data = point;
	ECkey.publicValue.len = template.ulValueLen;

	signature_item.data = pSignature;
	signature_item.len = ulSignatureLen;

	digest_item.data = pData;
	digest_item.len = ulDataLen;

	if (ECDSA_VerifyDigest(&ECkey, &signature_item, &digest_item, 0)
	    != SECSuccess) {
		rv = CKR_SIGNATURE_INVALID;
	} else {
		rv = CKR_OK;
	}

clean_exit:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	soft_free_ecc_context(session_p->verify.context);
	session_p->verify.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	return (rv);
}


CK_RV
soft_ecc_digest_verify_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned,
    CK_ULONG ulSignedLen, boolean_t Final)
{
	CK_RV rv;
	CK_BYTE hash[SHA1_HASH_SIZE];
	CK_ULONG hash_len = SHA1_HASH_SIZE;

	if (Final) {
		rv = soft_digest_final(session_p, hash, &hash_len);
	} else {
		rv = soft_digest(session_p, pData, ulDataLen, hash, &hash_len);
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		soft_free_ecc_context(session_p->verify.context);
		session_p->verify.context = NULL;
		session_p->digest.flags = 0;
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return (rv);
	}

	/*
	 * Now, we are ready to verify the data using signature.
	 * soft_ecc_verify() will free the verification key.
	 */
	rv = soft_ecc_verify(session_p, hash, hash_len,
	    pSigned, ulSignedLen);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	/* soft_digest_common() has freed the digest context */
	session_p->digest.flags = 0;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	return (rv);
}
