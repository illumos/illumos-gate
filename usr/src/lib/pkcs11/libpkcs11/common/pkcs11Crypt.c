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
 * C_EncryptInit will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.  Policy is checked for C_EncryptInit, and not C_Encrypt
 * or C_EncryptUpdate, since C_EncryptInit is required to be called
 * before C_Encrypt and C_EncryptUpdate.
 */
CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
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
		return (fast_funcs->C_EncryptInit(hSession, pMechanism, hKey));
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
	rv = FUNCLIST(slotid)->C_EncryptInit(sessp->se_handle,
	    pMechanism, hKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_Encrypt is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_Encrypt(hSession, pData, ulDataLen,
			    pEncryptedData, pulEncryptedDataLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(sessp->se_slotid)->C_Encrypt(sessp->se_handle, pData,
	    ulDataLen, pEncryptedData, pulEncryptedDataLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_EncryptUpdate is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_EncryptUpdate(hSession, pPart, ulPartLen,
			    pEncryptedPart, pulEncryptedPartLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(sessp->se_slotid)->C_EncryptUpdate(sessp->se_handle,
	    pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_EncryptFinal is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_EncryptFinal(hSession,
			    pLastEncryptedPart, pulLastEncryptedPartLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(sessp->se_slotid)->C_EncryptFinal(sessp->se_handle,
	    pLastEncryptedPart, pulLastEncryptedPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_DecryptInit will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.  Policy is checked for C_DecryptInit, and not C_Decrypt
 * or C_DecryptUpdate, since C_DecryptInit is required to be called
 * before C_Decrypt and C_DecryptUpdate.
 */
CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
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
		return (fast_funcs->C_DecryptInit(hSession, pMechanism, hKey));
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
	rv = FUNCLIST(slotid)->C_DecryptInit(sessp->se_handle,
	    pMechanism, hKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_Decrypt is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_Decrypt(hSession, pEncryptedData,
		    ulEncryptedDataLen, pData, pulDataLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(sessp->se_slotid)->C_Decrypt(sessp->se_handle,
	    pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_DecryptUpdate is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_DecryptUpdate(hSession, pEncryptedPart,
		    ulEncryptedPartLen, pPart, pulPartLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(sessp->se_slotid)->C_DecryptUpdate(sessp->se_handle,
	    pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_DecryptFinal is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_DecryptFinal(hSession, pLastPart,
		    pulLastPartLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Initialize the digest with the underlying provider */
	rv = FUNCLIST(sessp->se_slotid)->C_DecryptFinal(sessp->se_handle,
	    pLastPart, pulLastPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
