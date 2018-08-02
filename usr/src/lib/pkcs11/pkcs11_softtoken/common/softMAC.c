/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/sha2.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include "softObject.h"
#include "softOps.h"
#include "softSession.h"
#include "softMAC.h"

/*
 * IPAD = 0x36 repeated 48 times for ssl md5, repeated 40 times for ssl sha1
 * OPAD = 0x5C repeated 48 times for SSL md5, repeated 40 times for ssl sha1
 */
const uint32_t md5_ssl_ipad[] = {
	0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636};
const uint32_t sha1_ssl_ipad[] = {
	0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636};
const uint32_t md5_ssl_opad[] = {
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c};
const uint32_t sha1_ssl_opad[] = {
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c};

/*
 * Allocate and initialize a HMAC context, and save the context pointer in
 * the session struct. For General-length HMAC, checks the length in the
 * parameter to see if it is in the right range.
 */
CK_RV
soft_hmac_sign_verify_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p, boolean_t sign_op)
{

	soft_hmac_ctx_t *hmac_ctx;
	CK_RV rv = CKR_OK;

	if ((key_p->class != CKO_SECRET_KEY) ||
	    (key_p->key_type != CKK_GENERIC_SECRET)) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	hmac_ctx = malloc(sizeof (soft_hmac_ctx_t));

	if (hmac_ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	switch (pMechanism->mechanism) {
	case CKM_MD5_HMAC:
		hmac_ctx->hmac_len = MD5_HASH_SIZE;
		break;

	case CKM_SHA_1_HMAC:
		hmac_ctx->hmac_len = SHA1_HASH_SIZE;
		break;

	case CKM_SHA256_HMAC:
		hmac_ctx->hmac_len = SHA256_DIGEST_LENGTH;
		break;

	case CKM_SHA384_HMAC:
		hmac_ctx->hmac_len = SHA384_DIGEST_LENGTH;
		break;

	case CKM_SHA512_HMAC:
		hmac_ctx->hmac_len = SHA512_DIGEST_LENGTH;
		break;

	case CKM_MD5_HMAC_GENERAL:
	case CKM_SSL3_MD5_MAC:
		if ((pMechanism->ulParameterLen !=
		    sizeof (CK_MAC_GENERAL_PARAMS)) &&
		    (*(CK_MAC_GENERAL_PARAMS *)pMechanism->pParameter >
		    MD5_HASH_SIZE)) {
				free(hmac_ctx);
				return (CKR_MECHANISM_PARAM_INVALID);
			}
		hmac_ctx->hmac_len = *((CK_MAC_GENERAL_PARAMS_PTR)
		    pMechanism->pParameter);
		break;

	case CKM_SSL3_SHA1_MAC:
	case CKM_SHA_1_HMAC_GENERAL:
		if ((pMechanism->ulParameterLen !=
		    sizeof (CK_MAC_GENERAL_PARAMS)) &&
		    (*(CK_MAC_GENERAL_PARAMS *)pMechanism->pParameter >
		    SHA1_HASH_SIZE)) {
			free(hmac_ctx);
			return (CKR_MECHANISM_PARAM_INVALID);
		}
		hmac_ctx->hmac_len = *((CK_MAC_GENERAL_PARAMS_PTR)
		    pMechanism->pParameter);
		break;

	case CKM_SHA256_HMAC_GENERAL:
		if ((pMechanism->ulParameterLen !=
		    sizeof (CK_MAC_GENERAL_PARAMS)) &&
		    (*(CK_MAC_GENERAL_PARAMS *)pMechanism->pParameter >
		    SHA256_DIGEST_LENGTH)) {
			free(hmac_ctx);
			return (CKR_MECHANISM_PARAM_INVALID);
		}
		hmac_ctx->hmac_len = *((CK_MAC_GENERAL_PARAMS_PTR)
		    pMechanism->pParameter);
		break;

	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC_GENERAL:
		if ((pMechanism->ulParameterLen !=
		    sizeof (CK_MAC_GENERAL_PARAMS)) &&
		    (*(CK_MAC_GENERAL_PARAMS *)pMechanism->pParameter >
		    SHA512_DIGEST_LENGTH)) {
			free(hmac_ctx);
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		hmac_ctx->hmac_len = *((CK_MAC_GENERAL_PARAMS_PTR)
		    pMechanism->pParameter);
		break;

	}


	/* Initialize a MAC context. */
	rv = mac_init_ctx(session_p, key_p, hmac_ctx, pMechanism->mechanism);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (sign_op) {
		session_p->sign.mech.mechanism = pMechanism->mechanism;
		session_p->sign.context = hmac_ctx;
	} else {
		session_p->verify.mech.mechanism = pMechanism->mechanism;
		session_p->verify.context = hmac_ctx;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);
}


/*
 * Initialize a HMAC context.
 */
CK_RV
mac_init_ctx(soft_session_t *session_p, soft_object_t *key,
    soft_hmac_ctx_t *ctx, CK_MECHANISM_TYPE mech)
{
	CK_RV rv = CKR_OK;

	switch (mech) {
	case CKM_SSL3_MD5_MAC:
	{
		CK_BYTE md5_ipad[MD5_SSL_PAD_AND_KEY_SIZE];
		CK_BYTE md5_opad[MD5_SSL_PAD_AND_KEY_SIZE];

		if (OBJ_SEC(key)->sk_value_len > MD5_SSL_PAD_AND_KEY_SIZE) {
			return (CKR_KEY_SIZE_RANGE);
		}

		bzero(md5_ipad, MD5_SSL_PAD_AND_KEY_SIZE);
		bzero(md5_opad, MD5_SSL_PAD_AND_KEY_SIZE);

		/* SSL MAC is HASH(key + opad + HASH(key + ipad + data)) */
		(void) memcpy(md5_ipad, OBJ_SEC(key)->sk_value,
		    OBJ_SEC(key)->sk_value_len);
		(void) memcpy(&md5_ipad[OBJ_SEC(key)->sk_value_len],
		    md5_ssl_ipad, MD5_SSL_PAD_SIZE);
		(void) memcpy(md5_opad, OBJ_SEC(key)->sk_value,
		    OBJ_SEC(key)->sk_value_len);
		(void) memcpy(&md5_opad[OBJ_SEC(key)->sk_value_len],
		    md5_ssl_opad, MD5_SSL_PAD_SIZE);

		SOFT_MAC_INIT_CTX(MD5, &(ctx->hc_ctx_u.md5_ctx),
		    md5_ipad, md5_opad, MD5_SSL_PAD_AND_KEY_SIZE);

		break;
	}
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:
	{
		uint32_t md5_ipad[MD5_HMAC_INTS_PER_BLOCK];
		uint32_t md5_opad[MD5_HMAC_INTS_PER_BLOCK];
		CK_MECHANISM digest_mech;
		CK_ULONG hash_len = MD5_HASH_SIZE;

		bzero(md5_ipad, MD5_HMAC_BLOCK_SIZE);
		bzero(md5_opad, MD5_HMAC_BLOCK_SIZE);

		if (OBJ_SEC(key)->sk_value_len > MD5_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the key when it is longer than 64 bytes.
			 */
			digest_mech.mechanism = CKM_MD5;
			digest_mech.pParameter = NULL_PTR;
			digest_mech.ulParameterLen = 0;
			rv = soft_digest_init_internal(session_p, &digest_mech);
			if (rv != CKR_OK)
				return (rv);
			rv = soft_digest(session_p, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len, (CK_BYTE_PTR)md5_ipad,
			    &hash_len);
			session_p->digest.flags = 0;
			if (rv != CKR_OK)
				return (rv);
			(void) memcpy(md5_opad, md5_ipad, hash_len);
		} else {
			(void) memcpy(md5_ipad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
			(void) memcpy(md5_opad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
		}

		md5_hmac_ctx_init(&ctx->hc_ctx_u.md5_ctx, md5_ipad, md5_opad);
		break;
	}

	case CKM_SSL3_SHA1_MAC:
	{
		CK_BYTE sha1_ipad[SHA1_SSL_PAD_AND_KEY_SIZE];
		CK_BYTE sha1_opad[SHA1_SSL_PAD_AND_KEY_SIZE];

		if (OBJ_SEC(key)->sk_value_len > SHA1_HMAC_BLOCK_SIZE) {
			return (CKR_KEY_SIZE_RANGE);
		}

		bzero(sha1_ipad, SHA1_SSL_PAD_AND_KEY_SIZE);
		bzero(sha1_opad, SHA1_SSL_PAD_AND_KEY_SIZE);

		/* SSL MAC is HASH(key + opad + HASH(key + ipad + data)) */
		(void) memcpy(sha1_ipad, OBJ_SEC(key)->sk_value,
		    OBJ_SEC(key)->sk_value_len);
		(void) memcpy(&sha1_ipad[OBJ_SEC(key)->sk_value_len],
		    sha1_ssl_ipad, SHA1_SSL_PAD_SIZE);
		(void) memcpy(sha1_opad, OBJ_SEC(key)->sk_value,
		    OBJ_SEC(key)->sk_value_len);
		(void) memcpy(&sha1_opad[OBJ_SEC(key)->sk_value_len],
		    sha1_ssl_opad, SHA1_SSL_PAD_SIZE);

		SOFT_MAC_INIT_CTX(SHA1, &(ctx->hc_ctx_u.sha1_ctx),
		    sha1_ipad, sha1_opad, SHA1_SSL_PAD_AND_KEY_SIZE);

		break;
	}
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	{
		uint32_t sha1_ipad[SHA1_HMAC_INTS_PER_BLOCK];
		uint32_t sha1_opad[SHA1_HMAC_INTS_PER_BLOCK];
		CK_MECHANISM digest_mech;
		CK_ULONG hash_len = SHA1_HASH_SIZE;

		bzero(sha1_ipad, SHA1_HMAC_BLOCK_SIZE);
		bzero(sha1_opad, SHA1_HMAC_BLOCK_SIZE);

		if (OBJ_SEC(key)->sk_value_len > SHA1_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the key when it is longer than 64 bytes.
			 */
			digest_mech.mechanism = CKM_SHA_1;
			digest_mech.pParameter = NULL_PTR;
			digest_mech.ulParameterLen = 0;
			rv = soft_digest_init_internal(session_p, &digest_mech);
			if (rv != CKR_OK)
				return (rv);
			rv = soft_digest(session_p, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len, (CK_BYTE_PTR)sha1_ipad,
			    &hash_len);
			session_p->digest.flags = 0;
			if (rv != CKR_OK)
				return (rv);
			(void) memcpy(sha1_opad, sha1_ipad, hash_len);
		} else {
			(void) memcpy(sha1_ipad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
			(void) memcpy(sha1_opad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
		}

		sha1_hmac_ctx_init(&ctx->hc_ctx_u.sha1_ctx, sha1_ipad,
		    sha1_opad);

		break;
	}
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	{
		uint64_t sha_ipad[SHA256_HMAC_INTS_PER_BLOCK];
		uint64_t sha_opad[SHA256_HMAC_INTS_PER_BLOCK];
		CK_MECHANISM digest_mech;
		CK_ULONG hash_len = SHA256_DIGEST_LENGTH;

		bzero(sha_ipad, SHA256_HMAC_BLOCK_SIZE);
		bzero(sha_opad, SHA256_HMAC_BLOCK_SIZE);

		if (OBJ_SEC(key)->sk_value_len > SHA256_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the key when it is longer than 64 bytes.
			 */
			digest_mech.mechanism = CKM_SHA256;
			digest_mech.pParameter = NULL_PTR;
			digest_mech.ulParameterLen = 0;
			rv = soft_digest_init_internal(session_p, &digest_mech);
			if (rv != CKR_OK)
				return (rv);
			rv = soft_digest(session_p, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len, (CK_BYTE_PTR)sha_ipad,
			    &hash_len);
			session_p->digest.flags = 0;
			if (rv != CKR_OK)
				return (rv);
			(void) memcpy(sha_opad, sha_ipad, hash_len);
		} else {
			(void) memcpy(sha_ipad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
			(void) memcpy(sha_opad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
		}

		sha2_hmac_ctx_init(CKM_TO_SHA2(mech), &ctx->hc_ctx_u.sha2_ctx,
		    sha_ipad, sha_opad, SHA256_HMAC_INTS_PER_BLOCK,
		    SHA256_HMAC_BLOCK_SIZE);

		break;
	}
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	{
		uint64_t sha_ipad[SHA512_HMAC_INTS_PER_BLOCK];
		uint64_t sha_opad[SHA512_HMAC_INTS_PER_BLOCK];
		CK_MECHANISM digest_mech;
		CK_ULONG hash_len = SHA384_DIGEST_LENGTH;

		bzero(sha_ipad, SHA512_HMAC_BLOCK_SIZE);
		bzero(sha_opad, SHA512_HMAC_BLOCK_SIZE);

		if (OBJ_SEC(key)->sk_value_len > SHA512_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the key when it is longer than 64 bytes.
			 */
			digest_mech.mechanism = CKM_SHA384;
			digest_mech.pParameter = NULL_PTR;
			digest_mech.ulParameterLen = 0;
			rv = soft_digest_init_internal(session_p, &digest_mech);
			if (rv != CKR_OK)
				return (rv);
			rv = soft_digest(session_p, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len, (CK_BYTE_PTR)sha_ipad,
			    &hash_len);
			session_p->digest.flags = 0;
			if (rv != CKR_OK)
				return (rv);
			(void) memcpy(sha_opad, sha_ipad, hash_len);
		} else {
			(void) memcpy(sha_ipad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
			(void) memcpy(sha_opad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
		}

		sha2_hmac_ctx_init(CKM_TO_SHA2(mech), &ctx->hc_ctx_u.sha2_ctx,
		    sha_ipad, sha_opad, SHA512_HMAC_INTS_PER_BLOCK,
		    SHA512_HMAC_BLOCK_SIZE);

		break;
	}
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	{
		uint64_t sha_ipad[SHA512_HMAC_INTS_PER_BLOCK];
		uint64_t sha_opad[SHA512_HMAC_INTS_PER_BLOCK];
		CK_MECHANISM digest_mech;
		CK_ULONG hash_len = SHA512_DIGEST_LENGTH;

		bzero(sha_ipad, SHA512_HMAC_BLOCK_SIZE);
		bzero(sha_opad, SHA512_HMAC_BLOCK_SIZE);

		if (OBJ_SEC(key)->sk_value_len > SHA512_HMAC_BLOCK_SIZE) {
			/*
			 * Hash the key when it is longer than 64 bytes.
			 */
			digest_mech.mechanism = CKM_SHA512;
			digest_mech.pParameter = NULL_PTR;
			digest_mech.ulParameterLen = 0;
			rv = soft_digest_init_internal(session_p, &digest_mech);
			if (rv != CKR_OK)
				return (rv);
			rv = soft_digest(session_p, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len, (CK_BYTE_PTR)sha_ipad,
			    &hash_len);
			session_p->digest.flags = 0;
			if (rv != CKR_OK)
				return (rv);
			(void) memcpy(sha_opad, sha_ipad, hash_len);
		} else {
			(void) memcpy(sha_ipad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
			(void) memcpy(sha_opad, OBJ_SEC(key)->sk_value,
			    OBJ_SEC(key)->sk_value_len);
		}

		sha2_hmac_ctx_init(CKM_TO_SHA2(mech), &ctx->hc_ctx_u.sha2_ctx,
		    sha_ipad, sha_opad, SHA512_HMAC_INTS_PER_BLOCK,
		    SHA512_HMAC_BLOCK_SIZE);

		break;
	}
	}
	return (rv);
}


/*
 * Called by soft_sign(), soft_sign_final(), soft_verify() or
 * soft_verify_final().
 */
CK_RV
soft_hmac_sign_verify_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned, CK_ULONG_PTR pulSignedLen,
    boolean_t sign_op)
{

	soft_hmac_ctx_t	*hmac_ctx;
	CK_MECHANISM_TYPE	mechanism;
#ifdef	__sparcv9
	/* LINTED */
	uint_t datalen = (uint_t)ulDataLen;
#else	/* __sparcv9 */
	uint_t datalen = ulDataLen;
#endif	/* __sparcv9 */

	if (sign_op) {
		hmac_ctx = (soft_hmac_ctx_t *)session_p->sign.context;
		mechanism = session_p->sign.mech.mechanism;

		/*
		 * If application asks for the length of the output buffer
		 * to hold the signature?
		 */
		if (pSigned == NULL) {
			*pulSignedLen = hmac_ctx->hmac_len;
			return (CKR_OK);
		}

		/* Is the application-supplied buffer large enough? */
		if (*pulSignedLen < hmac_ctx->hmac_len) {
			*pulSignedLen = hmac_ctx->hmac_len;
			return (CKR_BUFFER_TOO_SMALL);
		}
	} else {
		hmac_ctx = (soft_hmac_ctx_t *)session_p->verify.context;
		mechanism = session_p->verify.mech.mechanism;
	}

	switch (mechanism) {

	case CKM_SSL3_MD5_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:

		if (pData != NULL) {
			/* Called by soft_sign() or soft_verify(). */
			SOFT_MAC_UPDATE(MD5, &(hmac_ctx->hc_ctx_u.md5_ctx),
			    pData, datalen);
		}
		SOFT_MAC_FINAL(MD5, &(hmac_ctx->hc_ctx_u.md5_ctx), pSigned);
		break;

	case CKM_SSL3_SHA1_MAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:

		if (pData != NULL) {
			/* Called by soft_sign() or soft_verify(). */
			SOFT_MAC_UPDATE(SHA1, &(hmac_ctx->hc_ctx_u.sha1_ctx),
			    pData, datalen);
		}
		SOFT_MAC_FINAL(SHA1, &(hmac_ctx->hc_ctx_u.sha1_ctx), pSigned);
		break;

	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
		if (pData != NULL)
			/* Called by soft_sign() or soft_verify(). */
			SHA2Update(&(hmac_ctx->hc_ctx_u.sha2_ctx.hc_icontext),
			    pData, datalen);

		SOFT_MAC_FINAL_2(SHA256, &(hmac_ctx->hc_ctx_u.sha2_ctx),
		    pSigned);
		break;

	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
		if (pData != NULL)
			/* Called by soft_sign() or soft_verify(). */
			SHA2Update(&(hmac_ctx->hc_ctx_u.sha2_ctx.hc_icontext),
			    pData, datalen);

		SOFT_MAC_FINAL_2(SHA384, &(hmac_ctx->hc_ctx_u.sha2_ctx),
		    pSigned);
		hmac_ctx->hmac_len = SHA384_DIGEST_LENGTH;
		break;

	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:

		if (pData != NULL)
			/* Called by soft_sign() or soft_verify(). */
			SHA2Update(&(hmac_ctx->hc_ctx_u.sha2_ctx.hc_icontext),
			    pData, datalen);

		SOFT_MAC_FINAL_2(SHA512, &(hmac_ctx->hc_ctx_u.sha2_ctx),
		    pSigned);
	};

	*pulSignedLen = hmac_ctx->hmac_len;


clean_exit:

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (sign_op) {
		freezero(session_p->sign.context, sizeof (soft_hmac_ctx_t));
		session_p->sign.context = NULL;
	} else {
		freezero(session_p->verify.context, sizeof (soft_hmac_ctx_t));
		session_p->verify.context = NULL;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);
}


/*
 * Called by soft_sign_update() or soft_verify_update().
 */
CK_RV
soft_hmac_sign_verify_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, boolean_t sign_op)
{

	soft_hmac_ctx_t	*hmac_ctx;
	CK_MECHANISM_TYPE	mechanism;
#ifdef	__sparcv9
	/* LINTED */
	uint_t partlen = (uint_t)ulPartLen;
#else	/* __sparcv9 */
	uint_t partlen = ulPartLen;
#endif	/* __sparcv9 */

	if (sign_op) {
		hmac_ctx = (soft_hmac_ctx_t *)session_p->sign.context;
		mechanism = session_p->sign.mech.mechanism;
	} else {
		hmac_ctx = (soft_hmac_ctx_t *)session_p->verify.context;
		mechanism = session_p->verify.mech.mechanism;
	}

	switch (mechanism) {

	case CKM_SSL3_MD5_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:

		SOFT_MAC_UPDATE(MD5, &(hmac_ctx->hc_ctx_u.md5_ctx), pPart,
		    partlen);
		break;

	case CKM_SSL3_SHA1_MAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:

		SOFT_MAC_UPDATE(SHA1, &(hmac_ctx->hc_ctx_u.sha1_ctx), pPart,
		    partlen);

		break;

	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:

		SOFT_MAC_UPDATE(SHA2, &(hmac_ctx->hc_ctx_u.sha2_ctx), pPart,
		    partlen);
		break;

	}
	return (CKR_OK);
}

/*
 * The following 2 functions expect the MAC key to be alreay copied in
 * the ipad and opad
 */
void
md5_hmac_ctx_init(md5_hc_ctx_t *md5_hmac_ctx, uint32_t *ipad, uint32_t *opad)
{
	int i;
	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < MD5_HMAC_INTS_PER_BLOCK; i++) {
		ipad[i] ^= 0x36363636;
		opad[i] ^= 0x5c5c5c5c;
	}
	SOFT_MAC_INIT_CTX(MD5, md5_hmac_ctx, ipad, opad, MD5_HMAC_BLOCK_SIZE);
}

void
sha1_hmac_ctx_init(sha1_hc_ctx_t *sha1_hmac_ctx, uint32_t *ipad, uint32_t *opad)
{
	int i;
	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < SHA1_HMAC_INTS_PER_BLOCK; i++) {
		ipad[i] ^= 0x36363636;
		opad[i] ^= 0x5c5c5c5c;
	}
	SOFT_MAC_INIT_CTX(SHA1, sha1_hmac_ctx, (const uchar_t *)ipad,
	    (const uchar_t *)opad, SHA1_HMAC_BLOCK_SIZE);
}


void
sha2_hmac_ctx_init(uint_t mech, sha2_hc_ctx_t *ctx, uint64_t *ipad,
    uint64_t *opad, uint_t blocks_per_int64, uint_t block_size)
{
	int i;

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < blocks_per_int64; i ++) {
		ipad[i] ^= 0x3636363636363636ULL;
		opad[i] ^= 0x5c5c5c5c5c5c5c5cULL;
	}

	/* perform SHA2 on ipad */
	SHA2Init(mech, &ctx->hc_icontext);
	SHA2Update(&ctx->hc_icontext, (uint8_t *)ipad, block_size);

	/* perform SHA2 on opad */
	SHA2Init(mech, &ctx->hc_ocontext);
	SHA2Update(&ctx->hc_ocontext, (uint8_t *)opad, block_size);

}
