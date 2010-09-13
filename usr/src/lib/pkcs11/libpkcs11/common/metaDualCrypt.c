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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Dual-Function Cryptographic Functions
 * (as defined in PKCS#11 spec section 11.13)
 *
 * These functions will not be supported in the this release.
 * A call to these functions returns CKR_FUNCTION_NOT_SUPPORTED.
 *
 * Providing the support for dual-function crypto functions is
 * not trivial.  C_FooInit() need to be called for the 2 crypto
 * operations before any of these function can be called.
 * When C_FooInit() is called, metaslot doesn't know if it is going
 * to do dual-function crypto or single crypto operation.
 * So, it has no way to pick the slot that supports both the mechanism
 * it specified and supports dual-functions.
 *
 * In order for these dual functions to be supported in the future,
 * metaslot need to simulate the dual-function crypto operations
 * when both operations are not lucky enough be to initialized in
 * the same slots that supports dual-functions.
 */

#include "metaGlobal.h"

/*
 * meta_DigestEncryptUpdate
 *
 */
/*ARGSUSED*/
CK_RV
meta_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*
 * meta_DecryptDigestUpdate
 *
 */
/*ARGSUSED*/
CK_RV
meta_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*
 * meta_SignEncryptUpdate
 *
 */
/*ARGSUSED*/
CK_RV
meta_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*
 * meta_DecryptVerifyUpdate
 *
 */
/*ARGSUSED*/
CK_RV
meta_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}
