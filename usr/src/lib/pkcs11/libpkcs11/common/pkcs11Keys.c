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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Conf.h"
#include "pkcs11Session.h"
#include "pkcs11Slot.h"

/*
 * C_GenerateKey will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.
 */
CK_RV
C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	pkcs11_session_t *sessp;
	CK_SLOT_ID slotid;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		if (policyfastpath &&
		    pkcs11_is_dismech(fast_slot, pMechanism->mechanism)) {
			return (CKR_MECHANISM_INVALID);
		}
		return (fast_funcs->C_GenerateKey(hSession, pMechanism,
			    pTemplate, ulCount, phKey));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	slotid = sessp->se_slotid;

	/* Make sure this is not a disabled mechanism */
	if (pkcs11_is_dismech(slotid, pMechanism->mechanism)) {
		return (CKR_MECHANISM_INVALID);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(slotid)->C_GenerateKey(sessp->se_handle,
	    pMechanism, pTemplate, ulCount, phKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_GenerateKeyPair will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.
 */
CK_RV
C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv;
	pkcs11_session_t *sessp;
	CK_SLOT_ID slotid;


	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		if (policyfastpath &&
		    pkcs11_is_dismech(fast_slot, pMechanism->mechanism)) {
			return (CKR_MECHANISM_INVALID);
		}
		return (fast_funcs->C_GenerateKeyPair(hSession, pMechanism,
			    pPublicKeyTemplate, ulPublicKeyAttributeCount,
			    pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			    phPublicKey, phPrivateKey));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	slotid = sessp->se_slotid;

	/* Make sure this is not a disabled mechanism */
	if (pkcs11_is_dismech(slotid, pMechanism->mechanism)) {
		return (CKR_MECHANISM_INVALID);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(slotid)->C_GenerateKeyPair(sessp->se_handle,
	    pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount,
	    pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
	    phPublicKey, phPrivateKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_WrapKey will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.
 */
CK_RV
C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;
	CK_SLOT_ID slotid;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		if (policyfastpath &&
		    pkcs11_is_dismech(fast_slot, pMechanism->mechanism)) {
			return (CKR_MECHANISM_INVALID);
		}
		return (fast_funcs->C_WrapKey(hSession, pMechanism,
			    hWrappingKey, hKey, pWrappedKey,
			    pulWrappedKeyLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	slotid = sessp->se_slotid;

	/* Make sure this is not a disabled mechanism */
	if (pkcs11_is_dismech(slotid, pMechanism->mechanism)) {
		return (CKR_MECHANISM_INVALID);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(slotid)->C_WrapKey(sessp->se_handle,
	    pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_UnwrapKey will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.
 */
CK_RV
C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	pkcs11_session_t *sessp;
	CK_SLOT_ID slotid;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		if (policyfastpath &&
		    pkcs11_is_dismech(fast_slot, pMechanism->mechanism)) {
			return (CKR_MECHANISM_INVALID);
		}
		return (fast_funcs->C_UnwrapKey(hSession, pMechanism,
			    hUnwrappingKey, pWrappedKey, ulWrappedKeyLen,
			    pTemplate, ulAttributeCount, phKey));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	slotid = sessp->se_slotid;

	/* Make sure this is not a disabled mechanism */
	if (pkcs11_is_dismech(slotid, pMechanism->mechanism)) {
		return (CKR_MECHANISM_INVALID);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(slotid)->C_UnwrapKey(sessp->se_handle,
	    pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen,
	    pTemplate, ulAttributeCount, phKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_DeriveKey will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.
 */
CK_RV
C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	pkcs11_session_t *sessp;
	CK_SLOT_ID slotid;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		if (policyfastpath &&
		    pkcs11_is_dismech(fast_slot, pMechanism->mechanism)) {
			return (CKR_MECHANISM_INVALID);
		}
		return (fast_funcs->C_DeriveKey(hSession, pMechanism,
			    hBaseKey, pTemplate, ulAttributeCount, phKey));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	slotid = sessp->se_slotid;

	/* Make sure this is not a disabled mechanism */
	if (pkcs11_is_dismech(slotid, pMechanism->mechanism)) {
		return (CKR_MECHANISM_INVALID);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(slotid)->C_DeriveKey(sessp->se_handle,
	    pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
