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
#include <string.h>
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
 * soft_verify_init()
 *
 * Arguments:
 *	session_p:	pointer to soft_session_t struct
 *	pMechanism:	pointer to CK_MECHANISM struct provided by application
 *	key_p:		pointer to key soft_object_t struct
 *
 * Description:
 *	called by C_VerifyInit(). This function calls the corresponding
 *	verify init routine based on the mechanism.
 *
 */
CK_RV
soft_verify_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
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
		    pMechanism, key_p, B_FALSE));

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:

		return (soft_rsa_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	case CKM_DSA:
	case CKM_DSA_SHA1:

		return (soft_dsa_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:

		return (soft_ecc_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:

		return (soft_des_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:

		return (soft_aes_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	default:
		return (CKR_MECHANISM_INVALID);
	}

}


/*
 * soft_verify()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pData:		pointer to the input data
 *	ulDataLen:	length of the input data
 *	pSignature:	pointer to the signature
 *	ulSignatureLen:	length of the signature
 *
 * Description:
 *      called by C_Verify(). This function calls the corresponding
 *	verify routine based on the mechanism.
 *
 */
CK_RV
soft_verify(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->verify.mech.mechanism;
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
		CK_ULONG len;
		CK_BYTE hmac[SHA512_DIGEST_LENGTH]; /* use the maximum size */
		soft_hmac_ctx_t *hmac_ctx;

		hmac_ctx = (soft_hmac_ctx_t *)session_p->verify.context;
		len = hmac_ctx->hmac_len;

		rv = soft_hmac_sign_verify_common(session_p, pData,
		    ulDataLen, hmac, &len, B_FALSE);

		if (rv == CKR_OK) {
			if (len != ulSignatureLen) {
				rv = CKR_SIGNATURE_LEN_RANGE;
			}

			if (memcmp(hmac, pSignature, len) != 0) {
				rv = CKR_SIGNATURE_INVALID;
			}
		}

		return (rv);
	}
	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:
	{
		CK_ULONG len;
		CK_BYTE signature[DES_BLOCK_LEN]; /* use the maximum size */
		soft_des_ctx_t *des_ctx;

		des_ctx = (soft_des_ctx_t *)session_p->verify.context;
		len = des_ctx->mac_len;

		/* Pass local buffer to avoid overflow. */
		rv = soft_des_sign_verify_common(session_p, pData,
		    ulDataLen, signature, &len, B_FALSE, B_FALSE);

		if (rv == CKR_OK) {
			if (len != ulSignatureLen) {
				rv = CKR_SIGNATURE_LEN_RANGE;
			}

			if (memcmp(signature, pSignature, len) != 0) {
				rv = CKR_SIGNATURE_INVALID;
			}
		}

		return (rv);
	}
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:
	{
		CK_ULONG len;
		CK_BYTE signature[AES_BLOCK_LEN];
		soft_aes_ctx_t *aes_ctx;

		aes_ctx = (soft_aes_ctx_t *)session_p->verify.context;
		len = aes_ctx->mac_len;

		/* Pass local buffer to avoid overflow. */
		rv = soft_aes_sign_verify_common(session_p, pData,
		    ulDataLen, signature, &len, B_FALSE, B_FALSE);

		if (rv == CKR_OK) {
			if (len != ulSignatureLen) {
				rv = CKR_SIGNATURE_LEN_RANGE;
			}

			if (memcmp(signature, pSignature, len) != 0) {
				rv = CKR_SIGNATURE_INVALID;
			}
		}

		return (rv);
	}
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_verify_common(session_p, pData, ulDataLen,
		    pSignature, ulSignatureLen, mechanism));

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:

		return (soft_rsa_digest_verify_common(session_p, pData,
		    ulDataLen, pSignature, ulSignatureLen, mechanism, B_FALSE));

	case CKM_DSA:

		return (soft_dsa_verify(session_p, pData, ulDataLen,
		    pSignature, ulSignatureLen));

	case CKM_DSA_SHA1:

		return (soft_dsa_digest_verify_common(session_p, pData,
		    ulDataLen, pSignature, ulSignatureLen, B_FALSE));

	case CKM_ECDSA:

		return (soft_ecc_verify(session_p, pData, ulDataLen,
		    pSignature, ulSignatureLen));

	case CKM_ECDSA_SHA1:

		return (soft_ecc_digest_verify_common(session_p, pData,
		    ulDataLen, pSignature, ulSignatureLen, B_FALSE));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}


/*
 * soft_verify_update()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pPart:		pointer to the input data
 *      ulPartLen:	length of the input data
 *
 * Description:
 *      called by C_VerifyUpdate(). This function calls the corresponding
 *	verify update routine based on the mechanism.
 *
 */
CK_RV
soft_verify_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_MECHANISM_TYPE	mechanism = session_p->verify.mech.mechanism;

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
		    ulPartLen, B_FALSE));

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
		 * verification.
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
 * soft_verify_final()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pSignature:	pointer to the signature
 *      ulSignatureLen:	length of the signature
 *
 * Description:
 *      called by C_VerifyFinal().  This function calls the corresponding
 *	verify final routine based on the mechanism.
 *
 */
CK_RV
soft_verify_final(soft_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->verify.mech.mechanism;
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
		CK_ULONG len;
		CK_BYTE hmac[SHA512_DIGEST_LENGTH];
		soft_hmac_ctx_t *hmac_ctx;

		hmac_ctx = (soft_hmac_ctx_t *)session_p->verify.context;
		len = hmac_ctx->hmac_len;

		rv = soft_hmac_sign_verify_common(session_p, NULL, 0,
		    hmac, &len, B_FALSE);

		if (rv == CKR_OK) {
			if (len != ulSignatureLen) {
				rv = CKR_SIGNATURE_LEN_RANGE;
			}

			if (memcmp(hmac, pSignature, len) != 0) {
				rv = CKR_SIGNATURE_INVALID;
			}
		}

		return (rv);
	}
	case CKM_DES_MAC_GENERAL:
	case CKM_DES_MAC:
	{
		CK_ULONG len;
		CK_BYTE signature[DES_BLOCK_LEN]; /* use the maximum size */
		soft_des_ctx_t *des_ctx;

		des_ctx = (soft_des_ctx_t *)session_p->verify.context;
		len = des_ctx->mac_len;

		/* Pass local buffer to avoid overflow. */
		rv = soft_des_sign_verify_common(session_p, NULL, 0,
		    signature, &len, B_FALSE, B_TRUE);

		if (rv == CKR_OK) {
			if (len != ulSignatureLen) {
				rv = CKR_SIGNATURE_LEN_RANGE;
			}

			if (memcmp(signature, pSignature, len) != 0) {
				rv = CKR_SIGNATURE_INVALID;
			}
		}

		return (rv);
	}
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CMAC:
	{
		CK_ULONG len;
		CK_BYTE signature[AES_BLOCK_LEN];
		soft_aes_ctx_t *aes_ctx;

		aes_ctx = (soft_aes_ctx_t *)session_p->verify.context;
		len = aes_ctx->mac_len;

		/* Pass local buffer to avoid overflow. */
		rv = soft_aes_sign_verify_common(session_p, NULL, 0,
		    signature, &len, B_FALSE, B_TRUE);

		if (rv == CKR_OK) {
			if (len != ulSignatureLen) {
				rv = CKR_SIGNATURE_LEN_RANGE;
			}

			if (memcmp(signature, pSignature, len) != 0) {
				rv = CKR_SIGNATURE_INVALID;
			}
		}

		return (rv);
	}
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:

		return (soft_rsa_digest_verify_common(session_p, NULL, 0,
		    pSignature, ulSignatureLen, mechanism, B_TRUE));

	case CKM_DSA_SHA1:

		return (soft_dsa_digest_verify_common(session_p, NULL, 0,
		    pSignature, ulSignatureLen, B_TRUE));

	case CKM_ECDSA_SHA1:

		return (soft_ecc_digest_verify_common(session_p, NULL, 0,
		    pSignature, ulSignatureLen, B_TRUE));

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		return (CKR_MECHANISM_INVALID);

	}
}


CK_RV
soft_verify_recover_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *key_p)
{

	switch (pMechanism->mechanism) {

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_sign_verify_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}


CK_RV
soft_verify_recover(soft_session_t *session_p, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->verify.mech.mechanism;

	switch (mechanism) {

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_verify_recover(session_p, pSignature,
		    ulSignatureLen, pData, pulDataLen));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}
