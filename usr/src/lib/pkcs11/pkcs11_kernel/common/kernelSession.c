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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <errno.h>
#include <security/cryptoki.h>
#include <sys/crypto/ioctl.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelSlot.h"

CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv = CKR_OK;
	kernel_slot_t	*pslot;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * For legacy reasons, the CKF_SERIAL_SESSION bit must always
	 * be set.
	 */
	if (!(flags & CKF_SERIAL_SESSION))
		return (CKR_SESSION_PARALLEL_NOT_SUPPORTED);

	if (phSession == NULL)
		return (CKR_ARGUMENTS_BAD);

	if (slotID >= slot_count) {
		return (CKR_SLOT_ID_INVALID);
	}

	/*
	 * Acquire the slot lock to protect sl_state and sl_sess_list.
	 * These two fields need to be protected atomically, even though
	 * "sl_sess_list" is updated in kernel_add_session().
	 */
	pslot = slot_table[slotID];
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	/* If SO is logged in the slot, only the RW session is allowed. */
	if ((pslot->sl_state == CKU_SO) && !(flags & CKF_RW_SESSION)) {
		(void) pthread_mutex_unlock(&pslot->sl_mutex);
		return (CKR_SESSION_READ_WRITE_SO_EXISTS);
	}

	/* Create a new session */
	rv = kernel_add_session(slotID, flags, pApplication, Notify,
	    phSession);
	(void) pthread_mutex_unlock(&pslot->sl_mutex);
	return (rv);
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * Set SESSION_IS_CLOSING flag so any access to this
	 * session will be rejected.
	 */
	session_p->ses_close_sync |= SESSION_IS_CLOSING;

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and REFRELE()
	 * will release the session lock for us.
	 */
	REFRELE(session_p, ses_lock_held);

	/*
	 * Delete a session by calling kernel_delete_session() with
	 * a session pointer and two boolean arguments. The 3rd argument
	 * boolean value FALSE indicates that the caller does not
	 * hold the slot lock.  The 4th argument boolean value B_FALSE
	 * indicates that we want to delete all the objects completely.
	 *
	 * kernel_delete_session() will reset SESSION_IS_CLOSING
	 * flag after it is done.
	 */
	rv = kernel_delete_session(session_p->ses_slotid, session_p, B_FALSE,
	    B_FALSE);
	return (rv);
}


CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV rv = CKR_OK;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Delete all the sessions and release the allocated resources */
	rv = kernel_delete_all_sessions(slotID, B_FALSE);

	return (rv);
}

CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	kernel_session_t *session_p;
	CK_RV rv;
	boolean_t ses_lock_held = B_FALSE;
	kernel_slot_t	*pslot;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Provide information for the specified session */
	pInfo->slotID = session_p->ses_slotid;
	pInfo->flags = session_p->flags;
	pInfo->ulDeviceError = 0;

	pslot = slot_table[session_p->ses_slotid];
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	if (pslot->sl_state == CKU_PUBLIC) {
		pInfo->state = (session_p->ses_RO) ?
		    CKS_RO_PUBLIC_SESSION : CKS_RW_PUBLIC_SESSION;
	} else if (pslot->sl_state == CKU_USER) {
		pInfo->state = (session_p->ses_RO) ?
		    CKS_RO_USER_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
	} else if (pslot->sl_state == CKU_SO) {
		pInfo->state = CKS_RW_SO_FUNCTIONS;
	}

	(void) pthread_mutex_unlock(&pslot->sl_mutex);

	/*
	 * Decrement the session reference count.
	 */
	REFRELE(session_p, ses_lock_held);

	return (CKR_OK);
}


/*ARGSUSED*/
CK_RV
C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG_PTR pulOperationStateLen)
{
	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


/*ARGSUSED*/
CK_RV
C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV	rv = CKR_OK;
	kernel_session_t *session_p;
	kernel_slot_t	*pslot;
	boolean_t ses_lock_held = B_FALSE;
	crypto_login_t  c_login;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if ((userType != CKU_SO) && (userType != CKU_USER)) {
		return (CKR_USER_TYPE_INVALID);
	}

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Acquire the slot lock */
	pslot = slot_table[session_p->ses_slotid];
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	/* Check if the slot is logged in already */
	if ((pslot->sl_state == CKU_USER) || (pslot->sl_state == CKU_SO)) {
		rv = CKR_USER_ALREADY_LOGGED_IN;
		goto clean_exit;
	}

	/* To login as SO, every session in this slot needs to be R/W */
	if (userType == CKU_SO) {
		kernel_session_t  *sp;
		boolean_t	found;

		found = B_FALSE;
		sp = pslot->sl_sess_list;
		while (sp) {
			/*
			 * Need not to lock individual sessions before
			 * accessing their "ses_RO" and "next" fields,
			 * because they are always accessed under the
			 * slot's mutex protection.
			 */
			if (sp->ses_RO) {
				found = B_TRUE;
				break;
			}
			sp = sp->next;
		}

		if (found) {
			rv = CKR_SESSION_READ_ONLY_EXISTS;
			goto clean_exit;
		}
	}

	/* Now make the ioctl call; no need to acquire the session lock. */
	c_login.co_session = session_p->k_session;
	c_login.co_user_type = userType;
	c_login.co_pin_len = ulPinLen;
	c_login.co_pin = (char *)pPin;

	while ((r = ioctl(kernel_fd, CRYPTO_LOGIN, &c_login)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(c_login.co_return_value);
	}

	if (rv == CKR_OK) {
		/* Set the slot's session state. */
		pslot->sl_state = userType;
	}

clean_exit:

	REFRELE(session_p, ses_lock_held);
	(void) pthread_mutex_unlock(&pslot->sl_mutex);
	return (rv);
}


CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV	rv = CKR_OK;
	kernel_session_t *session_p;
	kernel_slot_t	*pslot;
	boolean_t ses_lock_held = B_FALSE;
	crypto_logout_t  c_logout;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Acquire the slot lock. */
	pslot = slot_table[session_p->ses_slotid];
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	/* Check if the user or SO was logged in  */
	if (pslot->sl_state == CKU_PUBLIC) {
		rv = CKR_USER_NOT_LOGGED_IN;
		goto clean_exit;
	}

	/* Now make the ioctl call. No need to acquire the session lock. */
	c_logout.cl_session = session_p->k_session;
	while ((r = ioctl(kernel_fd, CRYPTO_LOGOUT, &c_logout)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(c_logout.cl_return_value);
	}

	if (rv != CKR_OK) {
		goto clean_exit;
	}

	/*
	 * If this slot was logged in as USER previously, we need to clean up
	 * all private object wrappers in library for this slot.
	 */
	kernel_cleanup_pri_objects_in_slot(pslot, session_p);

	if (rv == CKR_OK) {
		/* Reset the slot's session state. */
		pslot->sl_state = CKU_PUBLIC;
	}

clean_exit:
	REFRELE(session_p, ses_lock_held);
	(void) pthread_mutex_unlock(&pslot->sl_mutex);
	return (rv);
}
