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
#include "pkcs11Session.h"
#include "pkcs11Slot.h"

/*
 * C_DigestEncryptUpdate is a pure wrapper to the underlying provider.
 * Policy enforcement was done earlier by the mandatory calls to
 * C_DigestInit and C_EncryptInit.
 *
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_DigestEncryptUpdate(hSession, pPart,
			    ulPartLen, pEncryptedPart, pulEncryptedPartLen));
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
	rv = FUNCLIST(sessp->se_slotid)->
	    C_DigestEncryptUpdate(sessp->se_handle, pPart, ulPartLen,
		pEncryptedPart, pulEncryptedPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_DecryptDigestUpdate is a pure wrapper to the underlying provider.
 * Policy enforcement was done earlier by the mandatory calls to
 * C_DigestInit and C_DecryptInit.
 *
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_DecryptDigestUpdate(hSession,
			    pEncryptedPart, ulEncryptedPartLen, pPart,
			    pulPartLen));
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
	rv = FUNCLIST(sessp->se_slotid)->
	    C_DecryptDigestUpdate(sessp->se_handle, pEncryptedPart,
		ulEncryptedPartLen, pPart, pulPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_SignEncryptUpdate is a pure wrapper to the underlying provider.
 * Policy enforcement was done earlier by the mandatory calls to
 * C_SignInit and C_EncryptInit.
 *
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_SignEncryptUpdate(hSession, pPart,
			    ulPartLen,  pEncryptedPart, pulEncryptedPartLen));
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
	rv = FUNCLIST(sessp->se_slotid)->
	    C_SignEncryptUpdate(sessp->se_handle, pPart, ulPartLen,
		pEncryptedPart, pulEncryptedPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_DecryptVerifyUpdate is a pure wrapper to the underlying provider.
 * Policy enforcement was done earlier by the mandatory calls to
 * C_SignInit and C_EncryptInit.
 *
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_DecryptVerifyUpdate(hSession,
			    pEncryptedPart, ulEncryptedPartLen, pPart,
			    pulPartLen));
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
	rv = FUNCLIST(sessp->se_slotid)->
	    C_DecryptVerifyUpdate(sessp->se_handle, pEncryptedPart,
		ulEncryptedPartLen, pPart, pulPartLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
