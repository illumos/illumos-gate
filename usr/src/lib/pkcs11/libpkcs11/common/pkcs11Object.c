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
 * C_CreateObject is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
{

	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_CreateObject(hSession, pTemplate,
			    ulCount, phObject));
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
	rv = FUNCLIST(sessp->se_slotid)->C_CreateObject(sessp->se_handle,
	    pTemplate, ulCount, phObject);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_CopyObject is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_CopyObject(hSession, hObject,
			    pTemplate, ulCount, phNewObject));
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
	rv = FUNCLIST(sessp->se_slotid)->C_CopyObject(sessp->se_handle,
	    hObject, pTemplate, ulCount, phNewObject);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_DestroyObject is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_DestroyObject(hSession, hObject));
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
	rv = FUNCLIST(sessp->se_slotid)->C_DestroyObject(sessp->se_handle,
	    hObject);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_GetAttributeValue is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_GetAttributeValue(hSession, hObject,
			    pTemplate, ulCount));
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
	rv = FUNCLIST(sessp->se_slotid)->C_GetAttributeValue(sessp->se_handle,
	    hObject, pTemplate, ulCount);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * C_SetAttributeValue is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_SetAttributeValue(hSession, hObject,
			    pTemplate, ulCount));
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
	rv = FUNCLIST(sessp->se_slotid)->C_SetAttributeValue(sessp->se_handle,
	    hObject, pTemplate, ulCount);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_GetObjectSize is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_GetObjectSize(hSession, hObject,
			    pulSize));
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
	rv = FUNCLIST(sessp->se_slotid)->C_GetObjectSize(sessp->se_handle,
	    hObject, pulSize);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_FindObjectsInit is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_FindObjectsInit(hSession, pTemplate,
			    ulCount));
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
	rv = FUNCLIST(sessp->se_slotid)->C_FindObjectsInit(sessp->se_handle,
	    pTemplate, ulCount);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_FindObjects is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_FindObjects(hSession, phObject,
			    ulMaxObjectCount, pulObjectCount));
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
	rv = FUNCLIST(sessp->se_slotid)->C_FindObjects(sessp->se_handle,
	    phObject, ulMaxObjectCount, pulObjectCount);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_FindObjectsFinal is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_FindObjectsFinal(hSession));
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
	rv = FUNCLIST(sessp->se_slotid)->C_FindObjectsFinal(sessp->se_handle);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
