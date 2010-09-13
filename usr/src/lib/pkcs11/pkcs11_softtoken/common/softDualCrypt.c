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
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softOps.h"

CK_RV
C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{

	CK_RV	rv;

	/*
	 * All the front-end checkings will be done in the
	 * C_EncryptUpdate and C_DigestUpdate.
	 */
	rv = C_EncryptUpdate(hSession, pPart, ulPartLen,
	    pEncryptedPart, pulEncryptedPartLen);

	if (rv != CKR_OK)
		return (rv);

	/*
	 * If the application just wants to know the length of output
	 * buffer, then we do not digest the data.
	 */
	if (pEncryptedPart == NULL)
		return (CKR_OK);

	return (C_DigestUpdate(hSession, pPart, ulPartLen));
}


CK_RV
C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{

	CK_RV	rv;

	/*
	 * All the front-end checkings will be done in the
	 * C_DecryptUpdate and C_DigestUpdate.
	 */
	rv = C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen,
	    pPart, pulPartLen);

	if (rv != CKR_OK)
		return (rv);

	/*
	 * If the application just wants to know the length of output
	 * buffer, then we do not digest the data.
	 */
	if (pPart == NULL)
		return (CKR_OK);

	return (C_DigestUpdate(hSession, pPart, *pulPartLen));
}


CK_RV
C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{

	CK_RV	rv;

	/*
	 * All the front-end checkings will be done in the
	 * C_EncryptUpdate and C_SignUpdate.
	 */
	rv = C_EncryptUpdate(hSession, pPart, ulPartLen,
	    pEncryptedPart, pulEncryptedPartLen);

	if (rv != CKR_OK)
		return (rv);

	/*
	 * If the application just wants to know the length of output
	 * buffer, then we do not sign the data.
	 */
	if (pEncryptedPart == NULL)
		return (CKR_OK);

	return (C_SignUpdate(hSession, pPart, ulPartLen));
}


CK_RV
C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{

	CK_RV	rv;

	/*
	 * All the front-end checkings will be done in the
	 * C_DecryptUpdate and C_VerifyUpdate.
	 */
	rv = C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen,
	    pPart, pulPartLen);

	if (rv != CKR_OK)
		return (rv);

	/*
	 * If the application just wants to know the length of output
	 * buffer, then we do not verify the data.
	 */
	if (pPart == NULL)
		return (CKR_OK);

	return (C_VerifyUpdate(hSession, pPart, *pulPartLen));
}
