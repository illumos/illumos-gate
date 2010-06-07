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
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softDSA.h"
#include "softOps.h"
#include "softMAC.h"
#include "softCrypt.h"

/*
 * Allocate a DSA context for the active sign or verify operation.
 * This function is called without the session lock held.
 */
CK_RV
soft_dsa_sign_verify_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p,
    boolean_t sign)
{

	soft_dsa_ctx_t *dsa_ctx;
	CK_MECHANISM digest_mech;
	soft_object_t *tmp_key = NULL;
	CK_RV rv;

	if (sign) {
		if ((key_p->class != CKO_PRIVATE_KEY) ||
		    (key_p->key_type != CKK_DSA))
			return (CKR_KEY_TYPE_INCONSISTENT);
	} else {
		if ((key_p->class != CKO_PUBLIC_KEY) ||
		    (key_p->key_type != CKK_DSA))
			return (CKR_KEY_TYPE_INCONSISTENT);
	}

	if (pMechanism->mechanism == CKM_DSA_SHA1) {
		digest_mech.mechanism = CKM_SHA_1;
		rv = soft_digest_init_internal(session_p, &digest_mech);
		if (rv != CKR_OK)
			return (rv);
	}

	dsa_ctx = malloc(sizeof (soft_dsa_ctx_t));

	if (dsa_ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/*
	 * Make a copy of the signature or verification key, and save it
	 * in the DSA crypto context since it will be used later for
	 * signing/verification. We don't want to hold any object reference
	 * on this original key while doing signing/verification.
	 */
	(void) pthread_mutex_lock(&key_p->object_mutex);
	rv = soft_copy_object(key_p, &tmp_key, SOFT_COPY_OBJ_ORIG_SH,
	    NULL);

	if ((rv != CKR_OK) || (tmp_key == NULL)) {
		/* Most likely we ran out of space. */
		(void) pthread_mutex_unlock(&key_p->object_mutex);
		free(dsa_ctx);
		return (rv);
	}

	/* No need to hold the lock on the old object. */
	(void) pthread_mutex_unlock(&key_p->object_mutex);
	dsa_ctx->key = tmp_key;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (sign) {
		session_p->sign.context = dsa_ctx;
		session_p->sign.mech.mechanism = pMechanism->mechanism;
	} else {
		session_p->verify.context = dsa_ctx;
		session_p->verify.mech.mechanism = pMechanism->mechanism;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);
}


static CK_RV
local_dsa_sign(soft_object_t *key, CK_BYTE_PTR in, CK_ULONG inlen,
    CK_BYTE_PTR out)
{
	CK_RV rv;
	uchar_t q[MAX_KEY_ATTR_BUFLEN];
	uchar_t p[MAX_KEY_ATTR_BUFLEN];
	uchar_t g[MAX_KEY_ATTR_BUFLEN];
	uchar_t x[MAX_KEY_ATTR_BUFLEN];
	uint_t qlen = sizeof (q);
	uint_t plen = sizeof (p);
	uint_t glen = sizeof (g);
	uint_t xlen = sizeof (x);
	DSAbytekey k;

	rv = soft_get_private_value(key, CKA_PRIME, p, &plen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_private_value(key, CKA_SUBPRIME, q, &qlen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_private_value(key, CKA_BASE, g, &glen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_private_value(key, CKA_VALUE, x, &xlen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	k.prime = p;
	k.prime_bits = CRYPTO_BYTES2BITS(plen);
	k.subprime = q;
	k.subprime_bits = CRYPTO_BYTES2BITS(qlen);
	k.base = g;
	k.base_bytes = glen;
	k.private_x_bits = CRYPTO_BYTES2BITS(xlen);
	k.private_x = x;
	k.rfunc = NULL;

	rv = dsa_sign(&k, in, inlen, out);

clean1:
	return (rv);
}

static CK_RV
local_dsa_verify(soft_object_t *key, CK_BYTE_PTR data, CK_BYTE_PTR sig)
{
	CK_RV rv;
	uchar_t g[MAX_KEY_ATTR_BUFLEN];
	uchar_t y[MAX_KEY_ATTR_BUFLEN];
	uchar_t p[MAX_KEY_ATTR_BUFLEN];
	uchar_t q[MAX_KEY_ATTR_BUFLEN];
	uint_t glen = sizeof (g);
	uint_t ylen = sizeof (y);
	uint_t plen = sizeof (p);
	uint_t qlen = sizeof (q);
	DSAbytekey k;

	rv = soft_get_public_value(key, CKA_PRIME, p, &plen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_public_value(key, CKA_SUBPRIME, q, &qlen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_public_value(key, CKA_BASE, g, &glen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_public_value(key, CKA_VALUE, y, &ylen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	k.prime = p;
	k.prime_bits = CRYPTO_BYTES2BITS(plen);
	k.subprime = q;
	k.subprime_bits = CRYPTO_BYTES2BITS(qlen);
	k.base = g;
	k.base_bytes = glen;
	k.public_y_bits = CRYPTO_BYTES2BITS(ylen);
	k.public_y = y;
	k.rfunc = NULL;

	rv = dsa_verify(&k, data, sig);

clean1:
	return (rv);
}


CK_RV
soft_dsa_digest_sign_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned,
    CK_ULONG_PTR pulSignedLen, boolean_t Final)
{

	CK_RV rv = CKR_OK;
	CK_BYTE hash[SHA1_HASH_SIZE];  /* space enough for SHA1 and MD5 */
	CK_ULONG hash_len = SHA1_HASH_SIZE;
	soft_dsa_ctx_t *dsa_ctx = session_p->sign.context;
	soft_object_t *key = dsa_ctx->key;

	/* Check arguments before performing message digest. */
	if (pSigned == NULL) {
		/* Application asks for the length of the output buffer. */
		*pulSignedLen = DSA_SIGNATURE_LENGTH;
		goto clean1;
	}

	/* Is the application-supplied buffer large enough? */
	if (*pulSignedLen < DSA_SIGNATURE_LENGTH) {
		*pulSignedLen = DSA_SIGNATURE_LENGTH;
		rv = CKR_BUFFER_TOO_SMALL;
		goto clean1;
	}

	if (Final) {
		rv = soft_digest_final(session_p, hash, &hash_len);
	} else {
		rv = soft_digest(session_p, pData, ulDataLen, hash, &hash_len);
	}

	if (rv != CKR_OK) {
		/* free the signature key */
		soft_cleanup_object(key);
		free(key);
		goto clean_exit;
	}

	/*
	 * Now, we are ready to sign the data
	 * soft_dsa_sign() will free the signature key.
	 */
	rv = soft_dsa_sign(session_p, hash, hash_len, pSigned, pulSignedLen);

clean_exit:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	/* soft_digest_common() has freed the digest context */
	session_p->digest.flags = 0;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

clean1:
	return (rv);
}


CK_RV
soft_dsa_sign(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned,
    CK_ULONG_PTR pulSignedLen)
{

	CK_RV rv = CKR_OK;
	soft_dsa_ctx_t *dsa_ctx = session_p->sign.context;
	soft_object_t *key = dsa_ctx->key;

	if ((key->class != CKO_PRIVATE_KEY) || (key->key_type != CKK_DSA)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	/* Output length is always 40 bytes. */
	if (pSigned == NULL) {
		/* Application asks for the length of the output buffer. */
		*pulSignedLen = DSA_SIGNATURE_LENGTH;
		return (CKR_OK);
	}

	/* Input data length needs to be 20 bytes. */
	if (ulDataLen != DSA_SUBPRIME_BYTES) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean_exit;
	}

	if (*pulSignedLen < DSA_SIGNATURE_LENGTH) {
		*pulSignedLen = DSA_SIGNATURE_LENGTH;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rv = local_dsa_sign(key, pData, ulDataLen, pSigned);
	if (rv == CKR_OK) {
		*pulSignedLen = DSA_SIGNATURE_LENGTH;
	}

clean_exit:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	free(session_p->sign.context);
	session_p->sign.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	soft_cleanup_object(key);
	free(key);
	return (rv);
}


CK_RV
soft_dsa_verify(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{

	CK_RV rv = CKR_OK;
	soft_dsa_ctx_t *dsa_ctx = session_p->verify.context;
	soft_object_t *key = dsa_ctx->key;

	if ((key->class != CKO_PUBLIC_KEY) ||(key->key_type != CKK_DSA)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	/* Input data length needs to be 20 bytes. */
	if (ulDataLen != DSA_SUBPRIME_BYTES) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean_exit;
	}

	/* The signature length is always 40 bytes. */
	if (ulSignatureLen != DSA_SIGNATURE_LENGTH) {
		rv = CKR_SIGNATURE_LEN_RANGE;
		goto clean_exit;
	}

	rv = local_dsa_verify(key, pData, pSignature);

clean_exit:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	free(session_p->verify.context);
	session_p->verify.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	soft_cleanup_object(key);
	free(key);
	return (rv);
}


CK_RV
soft_dsa_digest_verify_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned,
    CK_ULONG ulSignedLen, boolean_t Final)
{

	CK_RV rv;
	CK_BYTE hash[SHA1_HASH_SIZE];  /* space enough for SHA1 and MD5 */
	CK_ULONG hash_len = SHA1_HASH_SIZE;
	soft_dsa_ctx_t *dsa_ctx = session_p->verify.context;
	soft_object_t *key = dsa_ctx->key;

	if (Final) {
		rv = soft_digest_final(session_p, hash, &hash_len);
	} else {
		rv = soft_digest(session_p, pData, ulDataLen, hash, &hash_len);
	}

	if (rv != CKR_OK) {
		/* free the verification key */
		soft_cleanup_object(key);
		free(key);
		goto clean_exit;
	}

	/*
	 * Now, we are ready to verify the data using signature.
	 * soft_dsa_verify() will free the verification key.
	 */
	rv = soft_dsa_verify(session_p, hash, hash_len,
	    pSigned, ulSignedLen);

clean_exit:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	/* soft_digest_common() has freed the digest context */
	session_p->digest.flags = 0;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	return (rv);
}


static CK_RV
soft_genDSAkey_set_attribute(soft_object_t *key, CK_ATTRIBUTE_TYPE type,
    uchar_t *value, uint32_t value_len, boolean_t public)
{

	CK_RV rv = CKR_OK;
	biginteger_t *dst = NULL;
	biginteger_t src;

	switch (type) {

	case CKA_VALUE:
		if (public)
			dst = OBJ_PUB_DSA_VALUE(key);
		else
			dst = OBJ_PRI_DSA_VALUE(key);
		break;

	case CKA_PRIME:
		if (public)
			dst = OBJ_PUB_DSA_PRIME(key);
		else
			dst = OBJ_PRI_DSA_PRIME(key);
		break;

	case CKA_SUBPRIME:
		if (public)
			dst = OBJ_PUB_DSA_SUBPRIME(key);
		else
			dst = OBJ_PRI_DSA_SUBPRIME(key);
		break;

	case CKA_BASE:
		if (public)
			dst = OBJ_PUB_DSA_BASE(key);
		else
			dst = OBJ_PRI_DSA_BASE(key);
		break;
	}

	/* Note: removal of preceding 0x00 imitates similar code in RSA */
	while (value[0] == 0) {		/* remove preceding 0x00 */
		value++;
		value_len--;
	}

	if ((rv = dup_bigint_attr(&src, value, value_len)) != CKR_OK)
		goto cleanexit;

	/* Copy the attribute in the key object. */
	copy_bigint_attr(&src, dst);

cleanexit:
	/* No need to free big_value because dst holds it now after copy. */
	return (rv);

}


CK_RV
soft_dsa_genkey_pair(soft_object_t *pubkey, soft_object_t *prikey)
{
	CK_RV rv;
	uchar_t prime[MAX_KEY_ATTR_BUFLEN];
	uint32_t prime_len = sizeof (prime);
	uchar_t	subprime[MAX_KEY_ATTR_BUFLEN];
	uint32_t subprime_len = sizeof (subprime);
	uchar_t	base[MAX_KEY_ATTR_BUFLEN];
	uint32_t base_len = sizeof (base);
	uchar_t	pubvalue[MAX_KEY_ATTR_BUFLEN];
	uint32_t pubvalue_len = sizeof (pubvalue);
	uchar_t	privalue[DSA_SUBPRIME_BYTES];
	uint32_t privalue_len = sizeof (privalue);
	DSAbytekey k;

	if ((pubkey == NULL) || (prikey == NULL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* lookup prime, subprime and base */
	rv = soft_get_public_value(pubkey, CKA_PRIME, prime, &prime_len);
	if (rv != CKR_OK) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto cleanexit;
	}

	rv = soft_get_public_value(pubkey, CKA_SUBPRIME, subprime,
	    &subprime_len);
	if (rv != CKR_OK) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto cleanexit;
	}

	rv = soft_get_public_value(pubkey, CKA_BASE, base, &base_len);
	if (rv != CKR_OK) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto cleanexit;
	}

	/* Inputs to DSA key pair generation. */
	k.prime = prime;
	k.prime_bits = CRYPTO_BYTES2BITS(prime_len);
	k.subprime = subprime;
	k.subprime_bits = CRYPTO_BYTES2BITS(subprime_len);
	k.base = base;
	k.base_bytes = base_len;
	k.rfunc = (IS_TOKEN_OBJECT(pubkey) || IS_TOKEN_OBJECT(prikey)) ?
	    pkcs11_get_random : pkcs11_get_urandom;

	/* Outputs from DSA key pair generation. */
	k.public_y = pubvalue;
	k.public_y_bits = CRYPTO_BYTES2BITS(pubvalue_len);
	k.private_x = privalue;
	k.private_x_bits = CRYPTO_BYTES2BITS(privalue_len);

	rv = dsa_genkey_pair(&k);

	if (rv != CKR_OK) {
		goto cleanexit;
	}

	/* Update attribute in public key. */
	if ((rv = soft_genDSAkey_set_attribute(pubkey, CKA_VALUE,
	    pubvalue, CRYPTO_BITS2BYTES(k.public_y_bits), B_TRUE)) != CKR_OK) {
		goto cleanexit;
	}
	/* Update attributes in private key. */
	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_PRIME,
	    prime, CRYPTO_BITS2BYTES(k.prime_bits), B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_SUBPRIME, subprime,
	    CRYPTO_BITS2BYTES(k.subprime_bits), B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_BASE,
	    base, k.base_bytes, B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_VALUE, privalue,
	    CRYPTO_BITS2BYTES(k.private_x_bits), B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

cleanexit:
	return (rv);
}
