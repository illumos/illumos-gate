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
 * Copyright 2018, Joyent, Inc.
 */

/*
 * Message Digesting Functions
 * (as defined in PKCS#11 spec section 11.10)
 */

#include "metaGlobal.h"


/*
 * meta_DigestInit
 *
 */
CK_RV
meta_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	CK_RV rv;
	meta_session_t *session;

	if (pMechanism == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_operation_init_defer(CKF_DIGEST, session, pMechanism, NULL);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_Digest
 *
 */
CK_RV
meta_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	meta_session_t *session;


	if ((pData == NULL && ulDataLen != 0) || pulDigestLen == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_do_operation(CKF_DIGEST, MODE_SINGLE, session, NULL,
	    pData, ulDataLen, pDigest, pulDigestLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DigestUpdate
 *
 */
CK_RV
meta_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_RV rv;
	meta_session_t *session;


	if (pPart == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_do_operation(CKF_DIGEST, MODE_UPDATE, session, NULL,
	    pPart, ulPartLen, NULL, NULL);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DigestKey
 *
 * NOTE: This function can fail under certain circumstances!
 * Unlike the other crypto functions, we didn't get the key object
 * when the operation was initialized with C_DigestInit().
 * Thus, the slot we're using for the digest operation may
 * not be the slot containing the key -- if the key is extractible we can
 * deal with it, but if it's not the operation will FAIL.
 */
CK_RV
meta_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *key;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hKey, &key);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	/* meta_do_operation() will clone the key, if needed. */
	rv = meta_do_operation(CKF_DIGEST, MODE_UPDATE_WITHKEY, session, key,
	    NULL, 0, NULL, NULL);

	OBJRELEASE(key);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DigestFinal
 *
 */
CK_RV
meta_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	meta_session_t *session;

	if (pulDigestLen == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_do_operation(CKF_DIGEST, MODE_FINAL, session, NULL,
	    NULL, 0, pDigest, pulDigestLen);

	REFRELEASE(session);

	return (rv);
}
