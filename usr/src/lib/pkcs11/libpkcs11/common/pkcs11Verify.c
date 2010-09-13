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
 * C_VerifyInit will verify that the session handle is valid within the
 * framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.  Policy is only checked for C_VerifyInit, since it is
 * required to be called before C_Verify and C_VerifyUpdate.
 */
CK_RV
C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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
		return (fast_funcs->C_VerifyInit(hSession, pMechanism, hKey));
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
	rv = FUNCLIST(slotid)->C_VerifyInit(sessp->se_handle,
	    pMechanism, hKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_Verify is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_Verify(hSession, pData, ulDataLen,
			    pSignature, ulSignatureLen));
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
	rv = FUNCLIST(sessp->se_slotid)->C_Verify(sessp->se_handle, pData,
	    ulDataLen, pSignature, ulSignatureLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_VerifyUpdate is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_VerifyUpdate(hSession, pPart,
			    ulPartLen));
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
	rv = FUNCLIST(sessp->se_slotid)->C_VerifyUpdate(sessp->se_handle,
	    pPart, ulPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_VerifyFinal is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_VerifyFinal(hSession, pSignature,
			    ulSignatureLen));
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
	rv = FUNCLIST(sessp->se_slotid)->C_VerifyFinal(sessp->se_handle,
	    pSignature, ulSignatureLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_VerifyRecoverInit will verify that the session handle is valid within
 * the framework, that the mechanism is not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.  Policy is only checked for C_VerifyRecoverInit, since it is
 * required to be called before C_VerifyRecover.
 */
CK_RV
C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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
		return (fast_funcs->C_VerifyRecoverInit(hSession, pMechanism,
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
	rv = FUNCLIST(slotid)->C_VerifyRecoverInit(sessp->se_handle,
	    pMechanism, hKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);


}

/*
 * C_VerifyRecover is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_VerifyRecover(hSession, pSignature,
			    ulSignatureLen, pData, pulDataLen));
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
	rv = FUNCLIST(sessp->se_slotid)->C_VerifyRecover(sessp->se_handle,
	    pSignature, ulSignatureLen, pData, pulDataLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
