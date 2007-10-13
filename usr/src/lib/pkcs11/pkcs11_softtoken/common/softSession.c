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

#include <pthread.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softKeystore.h"
#include "softKeystoreUtil.h"


CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{

	CK_RV rv = CKR_OK;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * For legacy reasons, the CKF_SERIAL_SESSION bit must always
	 * be set.
	 */
	if (!(flags & CKF_SERIAL_SESSION))
		return (CKR_SESSION_PARALLEL_NOT_SUPPORTED);

	if (slotID != SOFTTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	if (phSession == NULL)
		return (CKR_ARGUMENTS_BAD);

	/*
	 * softtoken has no limit on the number of concurrent sessions
	 * that the token allows. No need to check to see if the
	 * token has too many sessions already open.
	 */

	/* Create a new session */
	rv = soft_add_session(flags, pApplication, Notify, phSession);

	return (rv);

}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{

	CK_RV rv;

	soft_session_t *session_p;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	/*
	 * Set SESSION_IS_CLOSING flag so any access to this
	 * session will be rejected.
	 */
	if (session_p->ses_close_sync & SESSION_IS_CLOSING) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_SESSION_CLOSED);
	}
	session_p->ses_close_sync |= SESSION_IS_CLOSING;

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and SES_REFRELE()
	 * will release the session lock for us.
	 */
	SES_REFRELE(session_p, lock_held);

	/*
	 * Delete a session by calling soft_delete_session() with
	 * a session pointer and a boolean arguments. Boolean
	 * value FALSE is used to indicate that the caller does not
	 * hold the lock on the global session list and also that
	 * this is not a forced session close but an explicit request.
	 *
	 * soft_delete_session() will reset SESSION_IS_CLOSING
	 * flag after it is done.
	 */
	rv = soft_delete_session(session_p, B_FALSE, B_FALSE);

	if (soft_session_cnt == 0) {
		/* Clean up private token objects from the token object list */
		soft_delete_all_in_core_token_objects(PRIVATE_TOKEN);
		/*
		 * Invalidate public token object handles instead of
		 * deleting them.
		 */
		soft_validate_token_objects(B_FALSE);
		(void) pthread_mutex_lock(&soft_giant_mutex);
		soft_slot.authenticated = 0;
		soft_slot.userpin_change_needed = 0;
		(void) pthread_mutex_unlock(&soft_giant_mutex);
	}

	return (rv);
}


CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{

	CK_RV rv = CKR_OK;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != SOFTTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	/* Acquire the global session list lock */
	(void) pthread_mutex_lock(&soft_sessionlist_mutex);
	/*
	 * Set all_sessions_closing flag so any access to any
	 * existing sessions will be rejected.
	 */
	all_sessions_closing = 1;
	(void) pthread_mutex_unlock(&soft_sessionlist_mutex);

	/* Delete all the sessions and release the allocated resources */
	rv = soft_delete_all_sessions(B_FALSE);

	/* Clean up private token objects from the token object list */
	soft_delete_all_in_core_token_objects(PRIVATE_TOKEN);

	/* Invalidate public token object handles instead of deleting them */
	soft_validate_token_objects(B_FALSE);

	(void) pthread_mutex_lock(&soft_giant_mutex);
	soft_slot.authenticated = 0;
	soft_slot.userpin_change_needed = 0;
	(void) pthread_mutex_unlock(&soft_giant_mutex);

	(void) pthread_mutex_lock(&soft_sessionlist_mutex);
	/* Reset all_sessions_closing flag. */
	all_sessions_closing = 0;
	(void) pthread_mutex_unlock(&soft_sessionlist_mutex);

	return (rv);
}

CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{

	soft_session_t *session_p;
	CK_RV rv;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pInfo == NULL) {
		lock_held = B_FALSE;
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Provide information for the specified session */
	pInfo->slotID = SOFTTOKEN_SLOTID;
	pInfo->state = session_p->state;
	pInfo->flags = session_p->flags;
	pInfo->ulDeviceError = 0;

clean_exit:
	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and SES_REFRELE()
	 * will release the session lock for us.
	 */
	SES_REFRELE(session_p, lock_held);

	return (rv);
}


CK_RV
C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG_PTR pulOperationStateLen)
{
	soft_session_t *session_p;
	CK_RV rv;
	boolean_t lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Only check if pulOperationStateLen is NULL_PTR.
	 * No need to check if pOperationState is NULL_PTR because
	 * application might just ask for the length of buffer to hold
	 * the OperationState.
	 */
	if (pulOperationStateLen == NULL_PTR) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	rv = soft_get_operationstate(session_p, pOperationState,
	    pulOperationStateLen);

clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);

}


CK_RV
C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
	soft_session_t *session_p;
	CK_RV rv;
	boolean_t lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pOperationState == NULL_PTR) ||
	    (ulOperationStateLen == 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	rv = soft_set_operationstate(session_p, pOperationState,
	    ulOperationStateLen, hEncryptionKey, hAuthenticationKey);

clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{

	soft_session_t *session_p, *sp;
	CK_RV rv;
	boolean_t lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Check the load status of keystore */
	if (!soft_keystore_status(KEYSTORE_VERSION_OK)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_DEVICE_REMOVED);
	}

	if (userType != CKU_USER) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_USER_TYPE_INVALID);
	}

	if ((ulPinLen < MIN_PIN_LEN) || (ulPinLen > MAX_PIN_LEN)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_PIN_LEN_RANGE);
	}

	if (pPin == NULL_PTR) {
		/*
		 * We don't support CKF_PROTECTED_AUTHENTICATION_PATH
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	(void) pthread_mutex_lock(&soft_giant_mutex);
	if (soft_slot.authenticated) {
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		SES_REFRELE(session_p, lock_held);
		return (CKR_USER_ALREADY_LOGGED_IN);
	}

	rv = soft_login(pPin, ulPinLen);
	if (rv == CKR_OK) {
		if (soft_slot.userpin_change_needed) {
			/*
			 * This is the special case when the PIN is never
			 * initialized in the keystore, which will always
			 * return CKR_OK with "userpin_change_needed" set.
			 */
			(void) pthread_mutex_unlock(&soft_giant_mutex);
			SES_REFRELE(session_p, lock_held);
			return (rv);
		}

		soft_slot.authenticated = 1;
		(void) pthread_mutex_unlock(&soft_giant_mutex);
	} else {
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

	/*
	 * Load all the private token objects from keystore.
	 */
	rv = soft_get_token_objects_from_keystore(PRI_TOKENOBJS);
	if (rv != CKR_OK) {
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

	/* Acquire the global session list lock */
	(void) pthread_mutex_lock(&soft_sessionlist_mutex);

	sp = soft_session_list;

	while (sp) {
		(void) pthread_mutex_lock(&sp->session_mutex);

		if (sp->flags & CKF_RW_SESSION) {
			sp->state = CKS_RW_USER_FUNCTIONS;
		} else {
			sp->state = CKS_RO_USER_FUNCTIONS;
		}
		(void) pthread_mutex_unlock(&sp->session_mutex);
		sp = sp->next;
	}

	(void) pthread_mutex_unlock(&soft_sessionlist_mutex);

	SES_REFRELE(session_p, lock_held);
	return (rv);

}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{

	soft_session_t *session_p, *sp;
	CK_RV rv;
	boolean_t lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&soft_giant_mutex);
	if (!soft_slot.authenticated) {
		if (!soft_slot.userpin_change_needed) {
			/*
			 * Only if the PIN has been initialized in the keystore.
			 */
			(void) pthread_mutex_unlock(&soft_giant_mutex);
			SES_REFRELE(session_p, lock_held);
			return (CKR_USER_NOT_LOGGED_IN);
		} else {
			soft_slot.userpin_change_needed = 0;
			(void) pthread_mutex_unlock(&soft_giant_mutex);
			SES_REFRELE(session_p, lock_held);
			return (CKR_OK);
		}
	}

	soft_logout();
	soft_slot.authenticated = 0;
	(void) pthread_mutex_unlock(&soft_giant_mutex);

	/* Acquire the global session list lock */
	(void) pthread_mutex_lock(&soft_sessionlist_mutex);

	sp = soft_session_list;

	while (sp) {
		(void) pthread_mutex_lock(&sp->session_mutex);

		if (sp->flags & CKF_RW_SESSION) {
			sp->state = CKS_RW_PUBLIC_SESSION;
		} else {
			sp->state = CKS_RO_PUBLIC_SESSION;
		}
		(void) pthread_mutex_unlock(&sp->session_mutex);
		sp = sp->next;
	}

	(void) pthread_mutex_unlock(&soft_sessionlist_mutex);

	SES_REFRELE(session_p, lock_held);
	return (rv);

}
