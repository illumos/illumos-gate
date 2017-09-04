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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include "softObject.h"
#include "softOps.h"
#include "softSession.h"
#include "softMAC.h"
#include "softRSA.h"
#include "softDSA.h"
#include "softEC.h"
#include "softCrypt.h"

/*
 * soft_sign_init()
 *
 * Arguments:
 *	session_p:	pointer to soft_session_t struct
 *	pMechanism:	pointer to CK_MECHANISM struct provided by application
 *	key_p:		pointer to key soft_object_t struct
 *
 * Description:
 *	called by C_SignInit(). This function calls the corresponding
 *	sign init routine based on the mechanism.
 *
 */
CK_RV
soft_sign_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *key_p)
{

	switch (pMechanism->mechanism) {

	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:

		return (soft_hmac_sign_verify_init_common(session_p,
		    pMechanism, key_p, B_TRUE));

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:

		return (soft_rsa_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	case CKM_DSA:
	case CKM_DSA_SHA1:

		return (soft_dsa_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:

		return (soft_ecc_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:

		return (soft_des_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:

		return (soft_aes_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	default:
		return (CKR_MECHANISM_INVALID);
	}

}


/*
 * soft_sign()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pData:		pointer to the input data to be signed
 *	ulDataLen:	length of the input data
 *	pSignature:	pointer to the signature after signing
 *	pulSignatureLen: pointer to the length of the signature
 *
 * Description:
 *      called by C_Sign(). This function calls the corresponding
 *	sign routine based on the mechanism.
 *
 */
CK_RV
soft_sign(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->sign.mech.mechanism;
	CK_RV rv = CKR_OK;

	switch (mechanism) {

	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
	{
		CK_BYTE hmac[SHA512_DIGEST_LENGTH]; /* use the maximum size */

		if (pSignature != NULL) {
			/* Pass local buffer to avoid overflow. */
			rv = soft_hmac_sign_verify_common(session_p, pData,
			    ulDataLen, hmac, pulSignatureLen, B_TRUE);
		} else {
			/* Pass original pSignature, let callee to handle it. */
			rv = soft_hmac_sign_verify_common(session_p, pData,
			    ulDataLen, pSignature, pulSignatureLen, B_TRUE);
		}

		if ((rv == CKR_OK) && (pSignature != NULL))
			(void) memcpy(pSignature, hmac, *pulSignatureLen);

		return (rv);
	}
	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:
	{
		CK_BYTE signature[DES_BLOCK_LEN]; /* use the maximum size */

		if (pSignature != NULL) {
			/* Pass local buffer to avoid overflow. */
			rv = soft_des_sign_verify_common(session_p, pData,
			    ulDataLen, signature, pulSignatureLen, B_TRUE,
			    B_FALSE);
		} else {
			/* Pass NULL, let callee to handle it. */
			rv = soft_des_sign_verify_common(session_p, pData,
			    ulDataLen, NULL, pulSignatureLen, B_TRUE, B_FALSE);
		}

		if ((rv == CKR_OK) && (pSignature != NULL))
			(void) memcpy(pSignature, signature, *pulSignatureLen);

		return (rv);
	}
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:
	{
		CK_BYTE signature[AES_BLOCK_LEN];

		if (pSignature != NULL) {
			/* Pass local buffer to avoid overflow. */
			rv = soft_aes_sign_verify_common(session_p, pData,
			    ulDataLen, signature, pulSignatureLen, B_TRUE,
			    B_FALSE);
		} else {
			/* Pass NULL, let callee handle it. */
			rv = soft_aes_sign_verify_common(session_p, pData,
			    ulDataLen, NULL, pulSignatureLen, B_TRUE, B_FALSE);
		}

		if ((rv == CKR_OK) && (pSignature != NULL))
			(void) memcpy(pSignature, signature, *pulSignatureLen);

		return (rv);
	}
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_sign_common(session_p, pData, ulDataLen,
		    pSignature, pulSignatureLen, mechanism));

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:

		return (soft_rsa_digest_sign_common(session_p, pData, ulDataLen,
		    pSignature, pulSignatureLen, mechanism, B_FALSE));

	case CKM_DSA:

		return (soft_dsa_sign(session_p, pData, ulDataLen,
		    pSignature, pulSignatureLen));

	case CKM_DSA_SHA1:

		return (soft_dsa_digest_sign_common(session_p, pData, ulDataLen,
		    pSignature, pulSignatureLen, B_FALSE));

	case CKM_ECDSA:

		return (soft_ecc_sign(session_p, pData, ulDataLen,
		    pSignature, pulSignatureLen));

	case CKM_ECDSA_SHA1:

		return (soft_ecc_digest_sign_common(session_p, pData, ulDataLen,
		    pSignature, pulSignatureLen, B_FALSE));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}


/*
 * soft_sign_update()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pPart:		pointer to the input data to be signed
 *      ulPartLen:	length of the input data
 *
 * Description:
 *      called by C_SignUpdate(). This function calls the corresponding
 *	sign update routine based on the mechanism.
 *
 */
CK_RV
soft_sign_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_MECHANISM_TYPE	mechanism = session_p->sign.mech.mechanism;

	switch (mechanism) {

	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:

		return (soft_hmac_sign_verify_update(session_p, pPart,
		    ulPartLen, B_TRUE));

	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:

		return (soft_des_mac_sign_verify_update(session_p, pPart,
		    ulPartLen));

	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:

		return (soft_aes_mac_sign_verify_update(session_p, pPart,
		    ulPartLen));

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		/*
		 * The MD5/SHA1 digest value is accumulated in the context
		 * of the multiple-part digesting operation. In the final
		 * operation, the digest is encoded and then perform RSA
		 * signing.
		 */
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:

		return (soft_digest_update(session_p, pPart, ulPartLen));

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		return (CKR_MECHANISM_INVALID);
	}
}


/*
 * soft_sign_final()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pSignature:	pointer to the signature after signing
 *      pulSignatureLen: pointer to the	length of the signature
 *
 * Description:
 *      called by C_SignFinal(). This function calls the corresponding
 *	sign final routine based on the mechanism.
 *
 */
CK_RV
soft_sign_final(soft_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->sign.mech.mechanism;
	CK_RV rv = CKR_OK;

	switch (mechanism) {

	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
	{
		CK_BYTE hmac[SHA512_DIGEST_LENGTH]; /* use the maximum size */

		if (pSignature != NULL) {
			/* Pass local buffer to avoid overflow */
			rv = soft_hmac_sign_verify_common(session_p, NULL,
			    0, hmac, pulSignatureLen, B_TRUE);
		} else {
			/* Pass original pSignature, let callee to handle it. */
			rv = soft_hmac_sign_verify_common(session_p, NULL,
			    0, pSignature, pulSignatureLen, B_TRUE);
		}

		if ((rv == CKR_OK) && (pSignature != NULL))
			(void) memcpy(pSignature, hmac, *pulSignatureLen);

		return (rv);
	}
	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:
	{
		CK_BYTE signature[DES_BLOCK_LEN]; /* use the maximum size */

		if (pSignature != NULL) {
			/* Pass local buffer to avoid overflow. */
			rv = soft_des_sign_verify_common(session_p, NULL, 0,
			    signature, pulSignatureLen, B_TRUE, B_TRUE);
		} else {
			/* Pass NULL, let callee to handle it. */
			rv = soft_des_sign_verify_common(session_p, NULL, 0,
			    NULL, pulSignatureLen, B_TRUE, B_TRUE);
		}

		if ((rv == CKR_OK) && (pSignature != NULL))
			(void) memcpy(pSignature, signature, *pulSignatureLen);

		return (rv);
	}
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:
	{
		CK_BYTE signature[AES_BLOCK_LEN]; /* use the maximum size */

		if (pSignature != NULL) {
			/* Pass local buffer to avoid overflow. */
			rv = soft_aes_sign_verify_common(session_p, NULL, 0,
			    signature, pulSignatureLen, B_TRUE, B_TRUE);
		} else {
			/* Pass NULL, let callee handle it. */
			rv = soft_aes_sign_verify_common(session_p, NULL, 0,
			    NULL, pulSignatureLen, B_TRUE, B_TRUE);
		}

		if ((rv == CKR_OK) && (pSignature != NULL))
			(void) memcpy(pSignature, signature, *pulSignatureLen);

		return (rv);
	}
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:

		return (soft_rsa_digest_sign_common(session_p, NULL, 0,
		    pSignature, pulSignatureLen, mechanism, B_TRUE));

	case CKM_DSA_SHA1:

		return (soft_dsa_digest_sign_common(session_p, NULL, 0,
		    pSignature, pulSignatureLen, B_TRUE));

	case CKM_ECDSA_SHA1:

		return (soft_ecc_digest_sign_common(session_p, NULL, 0,
		    pSignature, pulSignatureLen, B_TRUE));

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		return (CKR_MECHANISM_INVALID);
	}
}


CK_RV
soft_sign_recover_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *key_p)
{

	switch (pMechanism->mechanism) {

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}


CK_RV
soft_sign_recover(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->sign.mech.mechanism;

	switch (mechanism) {

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_sign_common(session_p, pData, ulDataLen,
		    pSignature, pulSignatureLen, mechanism));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}

/*
 * This function frees the allocated active crypto context.
 * It is only called by the first tier of sign/verify routines
 * and the caller of this function may or may not hold the session mutex.
 */
void
soft_sign_verify_cleanup(soft_session_t *session_p, boolean_t sign,
    boolean_t lock_held)
{

	crypto_active_op_t *active_op;
	boolean_t lock_true = B_TRUE;

	if (!lock_held)
		(void) pthread_mutex_lock(&session_p->session_mutex);

	active_op = (sign) ? &(session_p->sign) : &(session_p->verify);

	switch (active_op->mech.mechanism) {

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		if (session_p->digest.context != NULL) {
			free(session_p->digest.context);
			session_p->digest.context = NULL;
			session_p->digest.flags = 0;
		}
		/* FALLTHRU */

	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
	{
		soft_rsa_ctx_t *rsa_ctx =
		    (soft_rsa_ctx_t *)active_op->context;

		if (rsa_ctx != NULL && rsa_ctx->key != NULL) {
			soft_cleanup_object(rsa_ctx->key);
			free(rsa_ctx->key);
		}
		break;

	}
	case CKM_DSA_SHA1:
		if (session_p->digest.context != NULL) {
			free(session_p->digest.context);
			session_p->digest.context = NULL;
			session_p->digest.flags = 0;
		}

		/* FALLTHRU */
	case CKM_DSA:
	{
		soft_dsa_ctx_t *dsa_ctx =
		    (soft_dsa_ctx_t *)active_op->context;

		if (dsa_ctx != NULL && dsa_ctx->key != NULL) {
			soft_cleanup_object(dsa_ctx->key);
			free(dsa_ctx->key);
		}
		break;

	}
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
		if (active_op->context != NULL)
			bzero(active_op->context, sizeof (soft_hmac_ctx_t));
		break;
	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:
		if (session_p->encrypt.context != NULL) {
			free(session_p->encrypt.context);
			session_p->encrypt.context = NULL;
			session_p->encrypt.flags = 0;
		}
		if (active_op->context != NULL)
			bzero(active_op->context, sizeof (soft_des_ctx_t));
		break;

	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:
		if (session_p->encrypt.context != NULL) {
			free(session_p->encrypt.context);
			session_p->encrypt.context = NULL;
			session_p->encrypt.flags = 0;
		}
		if (active_op->context != NULL)
			bzero(active_op->context, sizeof (soft_aes_ctx_t));
		break;

	}

	if (active_op->context != NULL) {
		free(active_op->context);
		active_op->context = NULL;
	}

	active_op->flags = 0;

	if (!lock_held)
		SES_REFRELE(session_p, lock_true);
}
