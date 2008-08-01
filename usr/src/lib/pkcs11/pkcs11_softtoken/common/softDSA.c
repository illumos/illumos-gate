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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <bignum.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softDSA.h"
#include "softRandom.h"
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


/* size is in bits */
BIG_ERR_CODE
DSA_key_init(DSAkey *key, int size)
{
	BIG_ERR_CODE err;
	int len, len160;

	len = BITLEN2BIGNUMLEN(size);
	len160 = BIG_CHUNKS_FOR_160BITS;
	key->size = size;
	if ((err = big_init1(&(key->q), len160, NULL, 0)) != BIG_OK)
		return (err);
	if ((err = big_init1(&(key->p), len, NULL, 0)) != BIG_OK)
		goto ret1;
	if ((err = big_init1(&(key->g), len, NULL, 0)) != BIG_OK)
		goto ret2;
	if ((err = big_init1(&(key->x), len160, NULL, 0)) != BIG_OK)
		goto ret3;
	if ((err = big_init1(&(key->y), len, NULL, 0)) != BIG_OK)
		goto ret4;
	if ((err = big_init1(&(key->k), len160, NULL, 0)) != BIG_OK)
		goto ret5;
	if ((err = big_init1(&(key->r), len160, NULL, 0)) != BIG_OK)
		goto ret6;
	if ((err = big_init1(&(key->s), len160, NULL, 0)) != BIG_OK)
		goto ret7;
	if ((err = big_init1(&(key->v), len160, NULL, 0)) != BIG_OK)
		goto ret8;

	return (BIG_OK);

ret8:
	big_finish(&(key->s));
ret7:
	big_finish(&(key->r));
ret6:
	big_finish(&(key->k));
ret5:
	big_finish(&(key->y));
ret4:
	big_finish(&(key->x));
ret3:
	big_finish(&(key->g));
ret2:
	big_finish(&(key->p));
ret1:
	big_finish(&(key->q));
	return (err);
}


void
DSA_key_finish(DSAkey *key)
{
	big_finish(&(key->v));
	big_finish(&(key->s));
	big_finish(&(key->r));
	big_finish(&(key->k));
	big_finish(&(key->y));
	big_finish(&(key->x));
	big_finish(&(key->g));
	big_finish(&(key->p));
	big_finish(&(key->q));
}


CK_RV
dsa_sign(soft_object_t *key, CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out)
{

	uchar_t q[MAX_KEY_ATTR_BUFLEN];
	uchar_t p[MAX_KEY_ATTR_BUFLEN];
	uchar_t g[MAX_KEY_ATTR_BUFLEN];
	uchar_t x[MAX_KEY_ATTR_BUFLEN];
	uint_t qlen = sizeof (q);
	uint_t plen = sizeof (p);
	uint_t glen = sizeof (g);
	uint_t xlen = sizeof (x);
	DSAkey dsakey;
	BIGNUM msg, tmp, tmp1, tmp2;
	BIG_ERR_CODE err;
	CK_RV rv;

	rv = soft_get_private_value(key, CKA_SUBPRIME, q, &qlen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	if (20 != qlen) {
		rv = CKR_KEY_SIZE_RANGE;
		goto clean1;
	}

	rv = soft_get_private_value(key, CKA_PRIME, p, &plen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_private_value(key, CKA_BASE, g, &glen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	if (glen != plen) {
		rv = CKR_KEY_SIZE_RANGE;
		goto clean1;
	}

	rv = soft_get_private_value(key, CKA_VALUE, x, &xlen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	if (20 < xlen) {
		rv = CKR_KEY_SIZE_RANGE;
		goto clean1;
	}

	if ((err = DSA_key_init(&dsakey, plen * 8)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	if ((err = big_init(&msg, BIG_CHUNKS_FOR_160BITS)) != BIG_OK) {
		goto clean6;
	}
	if ((err = big_init(&tmp, CHARLEN2BIGNUMLEN(plen) +
	    2 * BIG_CHUNKS_FOR_160BITS + 1)) != BIG_OK) {
		goto clean7;
	}
	if ((err = big_init(&tmp1, 2 * BIG_CHUNKS_FOR_160BITS + 1)) != BIG_OK) {
		goto clean8;
	}
	if ((err = big_init(&tmp2, BIG_CHUNKS_FOR_160BITS)) != BIG_OK) {
		goto clean9;
	}

	bytestring2bignum(&(dsakey.g), g, plen);
	bytestring2bignum(&(dsakey.x), x, 20);
	bytestring2bignum(&(dsakey.p), p, plen);
	bytestring2bignum(&(dsakey.q), q, 20);
	bytestring2bignum(&msg, (uchar_t *)in, inlen);

	if ((err = random_bignum(&(dsakey.k), DSA_SUBPRIME_BITS,
	    B_FALSE)) != BIG_OK)
		goto clean10;

	if ((err = big_div_pos(NULL, &(dsakey.k), &(dsakey.k),
	    &(dsakey.q))) != BIG_OK)
		goto clean10;

	if ((err = big_modexp(&tmp, &(dsakey.g), &(dsakey.k), &(dsakey.p),
	    NULL)) != BIG_OK)
		goto clean10;

	if ((err = big_div_pos(NULL, &(dsakey.r), &tmp, &(dsakey.q))) !=
	    BIG_OK)
		goto clean10;

	if ((err = big_ext_gcd_pos(NULL, NULL, &tmp, &(dsakey.q),
	    &(dsakey.k))) != BIG_OK)
		goto clean10;

	if (tmp.sign == -1)
		if ((err = big_add(&tmp, &tmp, &(dsakey.q))) != BIG_OK)
			goto clean10;			/* tmp <- k^-1 */

	if ((err = big_mul(&tmp1, &(dsakey.x), &(dsakey.r))) != BIG_OK)
		goto clean10;

	if ((err = big_add(&tmp1, &tmp1, &msg)) != BIG_OK)
		goto clean10;

	if ((err = big_mul(&tmp, &tmp1, &tmp)) != BIG_OK)
		goto clean10;

	if ((err = big_div_pos(NULL, &(dsakey.s), &tmp, &(dsakey.q))) !=
	    BIG_OK)
		goto clean10;

	bignum2bytestring((uchar_t *)out, &(dsakey.r), 20);
	bignum2bytestring((uchar_t *)out + 20, &(dsakey.s), 20);

	err = BIG_OK;

clean10:
	big_finish(&tmp2);
clean9:
	big_finish(&tmp1);
clean8:
	big_finish(&tmp);
clean7:
	big_finish(&msg);
clean6:
	DSA_key_finish(&dsakey);
	if (err == BIG_OK)
		rv = CKR_OK;
	else if (err == BIG_NO_MEM)
		rv = CKR_HOST_MEMORY;
	else
		rv = CKR_FUNCTION_FAILED;
clean1:
	return (rv);
}

CK_RV
dsa_verify(soft_object_t *key, CK_BYTE_PTR data, CK_BYTE_PTR sig)
{

	uchar_t g[MAX_KEY_ATTR_BUFLEN];
	uchar_t y[MAX_KEY_ATTR_BUFLEN];
	uchar_t p[MAX_KEY_ATTR_BUFLEN];
	uchar_t q[MAX_KEY_ATTR_BUFLEN];
	uint_t glen = sizeof (g);
	uint_t ylen = sizeof (y);
	uint_t plen = sizeof (p);
	uint_t qlen = sizeof (q);
	DSAkey dsakey;
	BIGNUM msg, tmp1, tmp2, tmp3;
	CK_RV rv;

	rv = soft_get_public_value(key, CKA_SUBPRIME, q, &qlen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	if (20 != qlen) {
		rv = CKR_KEY_SIZE_RANGE;
		goto clean1;
	}

	rv = soft_get_public_value(key, CKA_PRIME, p, &plen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	rv = soft_get_public_value(key, CKA_BASE, g, &glen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	if (plen < glen) {
		rv = CKR_KEY_SIZE_RANGE;
		goto clean1;
	}

	rv = soft_get_public_value(key, CKA_VALUE, y, &ylen);
	if (rv != CKR_OK) {
		goto clean1;
	}

	if (plen < ylen) {
		rv = CKR_KEY_SIZE_RANGE;
		goto clean1;
	}

	if (DSA_key_init(&dsakey, plen * 8) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	rv = CKR_HOST_MEMORY;
	if (big_init(&msg, BIG_CHUNKS_FOR_160BITS) != BIG_OK) {
		goto clean6;
	}
	if (big_init(&tmp1, 2 * CHARLEN2BIGNUMLEN(plen)) != BIG_OK) {
		goto clean7;
	}
	if (big_init(&tmp2, CHARLEN2BIGNUMLEN(plen)) != BIG_OK) {
		goto clean8;
	}
	if (big_init(&tmp3, 2 * BIG_CHUNKS_FOR_160BITS) != BIG_OK) {
		goto clean9;
	}

	bytestring2bignum(&(dsakey.g), g, glen);
	bytestring2bignum(&(dsakey.y), y, ylen);
	bytestring2bignum(&(dsakey.p), p, plen);
	bytestring2bignum(&(dsakey.q), q, 20);
	bytestring2bignum(&(dsakey.r), (uchar_t *)sig, 20);
	bytestring2bignum(&(dsakey.s), ((uchar_t *)sig) + 20, 20);
	bytestring2bignum(&msg, (uchar_t *)data, 20);

	if (big_ext_gcd_pos(NULL, &tmp2, NULL, &(dsakey.s), &(dsakey.q)) !=
	    BIG_OK)
		goto clean10;

	if (tmp2.sign == -1)
		if (big_add(&tmp2, &tmp2, &(dsakey.q)) != BIG_OK)
			goto clean10;			/* tmp2 <- w */

	if (big_mul(&tmp1, &msg, &tmp2) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.q)) != BIG_OK)
		goto clean10;				/* tmp1 <- u_1 */

	if (big_mul(&tmp2, &tmp2, &(dsakey.r)) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp2, &tmp2, &(dsakey.q)) != BIG_OK)
		goto clean10;				/* tmp2 <- u_2 */

	if (big_modexp(&tmp1, &(dsakey.g), &tmp1, &(dsakey.p), NULL) != BIG_OK)
		goto clean10;

	if (big_modexp(&tmp2, &(dsakey.y), &tmp2, &(dsakey.p), NULL) != BIG_OK)
		goto clean10;

	if (big_mul(&tmp1, &tmp1, &tmp2) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.p)) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.q)) != BIG_OK)
		goto clean10;

	if (big_cmp_abs(&tmp1, &(dsakey.r)) == 0)
		rv = CKR_OK;
	else
		rv = CKR_SIGNATURE_INVALID;

clean10:
	big_finish(&tmp3);
clean9:
	big_finish(&tmp2);
clean8:
	big_finish(&tmp1);
clean7:
	big_finish(&msg);
clean6:
	DSA_key_finish(&dsakey);
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
	if (ulDataLen != 20) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean_exit;
	}

	if (*pulSignedLen < DSA_SIGNATURE_LENGTH) {
		*pulSignedLen = DSA_SIGNATURE_LENGTH;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rv = dsa_sign(key, pData, ulDataLen, pSigned);
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

	/* The signature length is always 40 bytes. */
	if (ulSignatureLen != DSA_SIGNATURE_LENGTH) {
		rv = CKR_SIGNATURE_LEN_RANGE;
		goto clean_exit;
	}

	/* Input data length needs to be 20 bytes. */
	if (ulDataLen != 20) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean_exit;
	}

	rv = dsa_verify(key, pData, pSignature);

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


CK_RV
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

	src.big_value_len = value_len;

	if ((src.big_value = malloc(value_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanexit;
	}
	(void) memcpy(src.big_value, value, value_len);

	/* Copy the attribute in the key object. */
	copy_bigint_attr(&src, dst);

cleanexit:
	/* No need to free big_value because dst holds it now after copy. */
	return (rv);

}


CK_RV
generate_dsa_key(DSAkey *key, boolean_t token_obj)
{
	BIG_ERR_CODE err;

	do {
		if ((err = random_bignum(&(key->x), DSA_SUBPRIME_BITS,
		    token_obj)) != BIG_OK) {
			return (convert_rv(err));
		}
	} while (big_cmp_abs(&(key->x), &(key->q)) > 0);

	if ((err = big_modexp(&(key->y), &(key->g), (&key->x),
	    (&key->p), NULL)) != BIG_OK)
		return (convert_rv(err));

	return (CKR_OK);
}


CK_RV
soft_dsa_genkey_pair(soft_object_t *pubkey, soft_object_t *prikey)
{
	BIG_ERR_CODE brv;
	CK_RV rv;
	uchar_t	prime[MAX_KEY_ATTR_BUFLEN];
	uint32_t prime_len = sizeof (prime);
	uchar_t	subprime[MAX_KEY_ATTR_BUFLEN];
	uint32_t subprime_len = sizeof (subprime);
	uchar_t	base[MAX_KEY_ATTR_BUFLEN];
	uint32_t base_len = sizeof (base);
	uchar_t	*pubvalue;
	uint32_t pubvalue_len;
	uchar_t	*privalue;
	uint32_t privalue_len;
	DSAkey	dsakey = {0};

	pubvalue = NULL;
	privalue = NULL;

	if ((pubkey == NULL) || (prikey == NULL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* lookup prime, subprime and base */
	rv = soft_get_public_value(pubkey, CKA_PRIME, prime, &prime_len);
	if (rv != CKR_OK) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto cleanexit;
	}

	if ((prime_len < MIN_DSA_KEY_LEN) ||
	    (prime_len > MAX_DSA_KEY_LEN)) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanexit;
	}

	rv = soft_get_public_value(pubkey, CKA_SUBPRIME, subprime,
	    &subprime_len);
	if (rv != CKR_OK) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto cleanexit;
	}

	if (subprime_len != DSA_SUBPRIME_BYTES) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanexit;
	}

	rv = soft_get_public_value(pubkey, CKA_BASE, base, &base_len);
	if (rv != CKR_OK) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto cleanexit;
	}

	/*
	 * initialize the dsa key
	 * Note: big_extend takes length in words
	 */
	if ((brv = DSA_key_init(&dsakey, prime_len * 8)) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	if ((brv = big_extend(&dsakey.p,
	    CHARLEN2BIGNUMLEN(prime_len))) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	bytestring2bignum(&dsakey.p, prime, prime_len);

	if ((brv = big_extend(&dsakey.q, CHARLEN2BIGNUMLEN(subprime_len))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	bytestring2bignum(&dsakey.q, subprime, subprime_len);

	if ((brv = big_extend(&dsakey.g, CHARLEN2BIGNUMLEN(base_len))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	bytestring2bignum(&dsakey.g, base, base_len);

	/*
	 * generate DSA key pair
	 * Note: bignum.len is length of value in words
	 */
	if ((rv = generate_dsa_key(&dsakey, (IS_TOKEN_OBJECT(pubkey) ||
	    IS_TOKEN_OBJECT(prikey)))) != CKR_OK) {
		goto cleanexit;
	}

	pubvalue_len = prime_len;
	if ((pubvalue = malloc(pubvalue_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanexit;
	}
	bignum2bytestring(pubvalue, &dsakey.y, pubvalue_len);

	privalue_len = DSA_SUBPRIME_BYTES;
	if ((privalue = malloc(privalue_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanexit;
	}
	bignum2bytestring(privalue, &dsakey.x, privalue_len);

	/* Update attribute in public key. */
	if ((rv = soft_genDSAkey_set_attribute(pubkey, CKA_VALUE,
	    pubvalue, pubvalue_len, B_TRUE)) != CKR_OK) {
		goto cleanexit;
	}
	/* Update attributes in private key. */
	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_PRIME,
	    prime, prime_len, B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_SUBPRIME,
	    subprime, subprime_len, B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_BASE,
	    base, base_len, B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

	if ((rv = soft_genDSAkey_set_attribute(prikey, CKA_VALUE,
	    privalue, privalue_len, B_FALSE)) != CKR_OK) {
		goto cleanexit;
	}

cleanexit:
	DSA_key_finish(&dsakey);

	if (pubvalue != NULL) {
		free(pubvalue);
	}

	if (privalue != NULL) {
		free(privalue);
	}

	return (rv);
}
