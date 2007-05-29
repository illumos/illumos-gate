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
 * Signing and MACing Functions
 * (as defined in PKCs#11 spec section 11.11)
 */

#include "metaGlobal.h"


/*
 * meta_SignInit
 *
 */
CK_RV
meta_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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

	rv = meta_operation_init(CKF_SIGN, session, pMechanism, key);

	OBJRELEASE(key);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_Sign
 *
 */
CK_RV
meta_Sign(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pData == NULL || pulSignatureLen == NULL) {
		meta_operation_cleanup(session, CKF_SIGN, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_SIGN, MODE_SINGLE, session, NULL,
	    pData, ulDataLen, pSignature, pulSignatureLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_SignUpdate
 *
 */
CK_RV
meta_SignUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pPart == NULL) {
		meta_operation_cleanup(session, CKF_SIGN, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_SIGN, MODE_UPDATE, session, NULL,
	    pPart, ulPartLen, NULL, NULL);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_SignFinal
 *
 */
CK_RV
meta_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pulSignatureLen == NULL) {
		meta_operation_cleanup(session, CKF_SIGN, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_SIGN, MODE_FINAL, session, NULL,
	    NULL, 0, pSignature, pulSignatureLen);

	REFRELEASE(session);

	return (rv);
}

/*
 * meta_SignRecoverInit
 *
 */
CK_RV
meta_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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

	rv = meta_operation_init(CKF_SIGN_RECOVER, session, pMechanism, key);

	OBJRELEASE(key);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_SignRecover
 *
 */
CK_RV
meta_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pData == NULL || pulSignatureLen == NULL) {
		meta_operation_cleanup(session, CKF_SIGN_RECOVER, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_SIGN_RECOVER, MODE_SINGLE, session, NULL,
	    pData, ulDataLen, pSignature, pulSignatureLen);

	REFRELEASE(session);

	return (rv);
}
