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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Functions for Verifying Signatures and MACS
 * (as defined in PKCS#11 spec section 11.13)
 */

#include "metaGlobal.h"


/*
 * meta_VerifyInit
 *
 */
CK_RV
meta_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *key;

	if (pMechanism == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hKey, &key);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_operation_init(CKF_VERIFY, session, pMechanism, key);

	OBJRELEASE(key);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_Verify
 *
 */
CK_RV
meta_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	/* Note: unlike other ops, both buffers are inputs, and required. */
	if (pData == NULL || pSignature == NULL) {
		meta_operation_cleanup(session, CKF_VERIFY, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_VERIFY, MODE_SINGLE, session, NULL,
	    pData, ulDataLen, pSignature, &ulSignatureLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_VerifyUpdate
 *
 */
CK_RV
meta_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pPart == NULL) {
		meta_operation_cleanup(session, CKF_VERIFY, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_VERIFY, MODE_UPDATE, session, NULL,
	    pPart, ulPartLen, NULL, NULL);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_VerifyFinal
 *
 */
CK_RV
meta_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Unlike other ops the buffer is an input. Allow NULL if there's
	 * no more input.
	 */
	if (pSignature == NULL && ulSignatureLen != 0) {
		meta_operation_cleanup(session, CKF_VERIFY, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_VERIFY, MODE_FINAL, session, NULL,
	    pSignature, ulSignatureLen, NULL, NULL);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_VerifyRecoverInit
 *
 */
CK_RV
meta_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *key;

	if (pMechanism == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hKey, &key);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_operation_init(CKF_VERIFY_RECOVER, session, pMechanism, key);

	OBJRELEASE(key);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_VerifyRecover
 *
 */
CK_RV
meta_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pSignature == NULL || pulDataLen == NULL) {
		meta_operation_cleanup(session, CKF_VERIFY_RECOVER, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_VERIFY_RECOVER, MODE_SINGLE, session, NULL,
	    pSignature, ulSignatureLen, pData, pulDataLen);

	REFRELEASE(session);

	return (rv);
}
