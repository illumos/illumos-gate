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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softKeys.h"
#include "softOps.h"


CK_RV
C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pMechanism == NULL) || (phKey == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if ((pTemplate == NULL) && (ulCount != 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	rv = soft_genkey(session_p, pMechanism, pTemplate,
	    ulCount, phKey);

clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);

}


CK_RV
C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pMechanism == NULL) || (phPublicKey == NULL) ||
	    (phPrivateKey == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if ((pPublicKeyTemplate == NULL) ||
	    (ulPublicKeyAttributeCount == 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if ((pPrivateKeyTemplate == NULL) &&
	    (ulPrivateKeyAttributeCount != 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	rv = soft_genkey_pair(session_p, pMechanism, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);

clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV		rv;
	soft_session_t	*session_p;
	soft_object_t	*wrappingkey_p;
	soft_object_t	*hkey_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if (pulWrappedKeyLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Obtain the wrapping key object pointer. */
	HANDLE2OBJECT(hWrappingKey, wrappingkey_p, rv);
	if (rv != CKR_OK) {
		rv = CKR_WRAPPING_KEY_HANDLE_INVALID;
		goto clean_exit;
	}

	/* Obtain the to-be-wrapped key object pointer. */
	HANDLE2OBJECT(hKey, hkey_p, rv);
	if (rv != CKR_OK)
		goto clean_exit1;

	/* Check if given wrapping key may be used for wrapping. */
	if (!(wrappingkey_p->bool_attr_mask & WRAP_BOOL_ON)) {
		rv = CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
		goto clean_exit2;
	}

	/* Check if given wrapping key may be used for encryption. */
	if (!(wrappingkey_p->bool_attr_mask & ENCRYPT_BOOL_ON)) {
		rv = CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
		goto clean_exit2;
	}

	/*
	 * Check to see if key to be wrapped is extractable.
	 * Note: this should always be true for softtoken keys.
	 */
	if (!(hkey_p->bool_attr_mask & EXTRACTABLE_BOOL_ON)) {
		rv = CKR_KEY_UNEXTRACTABLE;
		goto clean_exit2;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Wrapping key objects requires calling encrypt operations.
	 * Check to see if encrypt operation is already active.
	 */
	if (session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE) {
		/* free the memory to avoid memory leak */
		soft_crypt_cleanup(session_p, B_TRUE, lock_held);
	}

	/* This active flag will remain ON while wrapping the key. */
	session_p->encrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_wrapkey(session_p, pMechanism, wrappingkey_p,
	    hkey_p, pWrappedKey, pulWrappedKeyLen);

	(void) pthread_mutex_lock(&session_p->session_mutex);

	lock_held = B_TRUE;
	session_p->encrypt.flags = 0;

	if ((rv == CKR_OK && pWrappedKey == NULL) ||
	    rv == CKR_BUFFER_TOO_SMALL)
		soft_crypt_cleanup(session_p, B_TRUE, lock_held);

clean_exit2:
	OBJ_REFRELE(hkey_p);
clean_exit1:
	OBJ_REFRELE(wrappingkey_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV		rv;
	soft_session_t	*session_p;
	soft_object_t	*unwrappingkey_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if ((pTemplate == NULL) || (ulAttributeCount == 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if ((pWrappedKey == NULL) || (ulWrappedKeyLen == 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if (phKey == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Obtain the unwrapping key object pointer. */
	HANDLE2OBJECT(hUnwrappingKey, unwrappingkey_p, rv);
	if (rv != CKR_OK) {
		rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
		goto clean_exit;
	}

	/* Check if given unwrapping key may be used for unwrapping. */
	if (!(unwrappingkey_p->bool_attr_mask & UNWRAP_BOOL_ON)) {
		rv = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
		goto clean_exit1;
	}

	/* Check if given unwrapping key may be used to decrypt. */
	if (!(unwrappingkey_p->bool_attr_mask & DECRYPT_BOOL_ON)) {
		rv = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
		goto clean_exit1;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Unwrapping key objects requires calling decrypt operations.
	 * Check to see if decrypt operation is already active.
	 */
	if (session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE) {
		/* free the memory to avoid memory leak */
		soft_crypt_cleanup(session_p, B_FALSE, lock_held);
	}

	/*
	 * This active flag will remain ON until application
	 * is done unwrapping the key.
	 */
	session_p->decrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_unwrapkey(session_p, pMechanism, unwrappingkey_p,
	    pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount,
	    phKey);

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if ((rv == CKR_OK && pWrappedKey == NULL) ||
	    rv == CKR_BUFFER_TOO_SMALL)
		soft_crypt_cleanup(session_p, B_TRUE, lock_held);

	session_p->decrypt.flags = 0;
	lock_held = B_TRUE;

clean_exit1:
	OBJ_REFRELE(unwrappingkey_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	soft_object_t	*basekey_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	if (((pTemplate != NULL) && (ulAttributeCount == 0)) ||
	    ((pTemplate == NULL) && (ulAttributeCount != 0))) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Obtain the private key object pointer. */
	HANDLE2OBJECT(hBaseKey, basekey_p, rv);
	if (rv != CKR_OK)
		goto clean_exit;

	/* Check to see if key object allows for derivation. */
	if (!(basekey_p->bool_attr_mask & DERIVE_BOOL_ON)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit1;
	}

	rv = soft_derivekey(session_p, pMechanism, basekey_p,
	    pTemplate, ulAttributeCount, phKey);

clean_exit1:
	OBJ_REFRELE(basekey_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}
