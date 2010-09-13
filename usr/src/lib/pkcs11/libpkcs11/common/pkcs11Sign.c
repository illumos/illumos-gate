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
 * C_SignInit will verify that the session handle is valid within the
 * framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.  Policy is only checked for C_SignInit, since it is
 * required to be called before C_Sign and C_SignUpdate.
 */
CK_RV
C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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
		return (fast_funcs->C_SignInit(hSession, pMechanism, hKey));
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
	rv = FUNCLIST(slotid)->C_SignInit(sessp->se_handle,
	    pMechanism, hKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_Sign is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_Sign(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_Sign(hSession, pData, ulDataLen,
			    pSignature, pulSignatureLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Pass data to the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_Sign(sessp->se_handle, pData,
	    ulDataLen, pSignature, pulSignatureLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_SignUpdate is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_SignUpdate(hSession, pPart, ulPartLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Pass data to the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_SignUpdate(sessp->se_handle, pPart,
	    ulPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_SignFinal is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_SignFinal(hSession, pSignature,
			    pulSignatureLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Pass data to the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_SignFinal(sessp->se_handle,
	    pSignature, pulSignatureLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_SignRecoverInit will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.  Policy is only checked for C_SignRecoverInit, since it is
 * required to be called before C_SignRecover.
 */
CK_RV
C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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
		return (fast_funcs->C_SignRecoverInit(hSession, pMechanism,
			    hKey));
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
	rv = FUNCLIST(slotid)->C_SignRecoverInit(sessp->se_handle,
	    pMechanism, hKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_SignRecover is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_SignRecover(hSession, pData, ulDataLen,
			    pSignature, pulSignatureLen));
	}
	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Pass data to the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_SignRecover(sessp->se_handle, pData,
	    ulDataLen, pSignature, pulSignatureLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
