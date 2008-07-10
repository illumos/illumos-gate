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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include "kernelEmulate.h"

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
	if (session_p->ses_close_sync & SESSION_IS_CLOSING) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_SESSION_CLOSED);
	}
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
	kernel_delete_session(session_p->ses_slotid, session_p, B_FALSE,
	    B_FALSE);
	return (rv);
}


CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Delete all the sessions and release the allocated resources */
	kernel_delete_all_sessions(slotID, B_FALSE);

	return (CKR_OK);
}

/*
 * Utility routine to get CK_STATE value for a session.
 * The caller should not be holding the session lock.
 */
static CK_STATE
get_ses_state(kernel_session_t *session_p)
{
	CK_STATE state;
	kernel_slot_t *pslot;

	pslot = slot_table[session_p->ses_slotid];
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	if (pslot->sl_state == CKU_PUBLIC) {
		state = (session_p->ses_RO) ?
		    CKS_RO_PUBLIC_SESSION : CKS_RW_PUBLIC_SESSION;
	} else if (pslot->sl_state == CKU_USER) {
		state = (session_p->ses_RO) ?
		    CKS_RO_USER_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
	} else if (pslot->sl_state == CKU_SO) {
		state = CKS_RW_SO_FUNCTIONS;
	}

	(void) pthread_mutex_unlock(&pslot->sl_mutex);

	return (state);
}


CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	kernel_session_t *session_p;
	CK_RV rv;
	boolean_t ses_lock_held = B_FALSE;

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
	pInfo->state = get_ses_state(session_p);

	/*
	 * Decrement the session reference count.
	 */
	REFRELE(session_p, ses_lock_held);

	return (CKR_OK);
}

/*
 * Save the state in pOperationState. The data format is:
 * 1. Total length (including this field)
 * 2. session state
 * 3. crypto_active_op_t structure
 * 4. digest_buf_t's data buffer contents
 */
static CK_RV
kernel_get_operationstate(kernel_session_t *session_p, CK_STATE ses_state,
    CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	int op_data_len = 0;
	CK_BYTE_PTR dst;
	digest_buf_t *bufp;

	if (!(session_p->digest.flags & CRYPTO_EMULATE)) {
		/*
		 * Return CKR_OPERATION_NOT_INITIALIZED if the slot
		 * is capable of C_GetOperationState(). Return
		 * CKR_FUNCTION_NOT_SUPPORTED otherwise.
		 *
		 * We return these codes because some clients
		 * check the return code to determine if C_GetOperationState()
		 * is supported.
		 */
		if (slot_table[session_p->ses_slotid]->sl_flags &
		    CRYPTO_LIMITED_HASH_SUPPORT)
			return (CKR_OPERATION_NOT_INITIALIZED);
		else
			return (CKR_FUNCTION_NOT_SUPPORTED);
	}

	/*
	 * XXX Need to support this case in future.
	 * This is the case where we exceeded SLOT_MAX_INDATA_LEN and
	 * hence started using libmd. SLOT_MAX_INDATA_LEN is at least
	 * 64K for current crypto framework providers and web servers
	 * do not need to clone digests that big for SSL operations.
	 */
	if (session_p->digest.flags & CRYPTO_EMULATE_USING_SW) {
		return (CKR_STATE_UNSAVEABLE);
	}

	/* Check to see if this is an unsupported operation. */
	if (session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE ||
	    session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE ||
	    session_p->sign.flags & CRYPTO_OPERATION_ACTIVE ||
	    session_p->verify.flags & CRYPTO_OPERATION_ACTIVE) {
		return (CKR_STATE_UNSAVEABLE);
	}

	/* Check to see if digest operation is active. */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	bufp = session_p->digest.context;

	op_data_len =  sizeof (int);
	op_data_len +=  sizeof (CK_STATE);
	op_data_len += sizeof (crypto_active_op_t);
	op_data_len += bufp->indata_len;

	if (pOperationState == NULL_PTR) {
		*pulOperationStateLen = op_data_len;
		return (CKR_OK);
	} else {
		if (*pulOperationStateLen < op_data_len) {
			*pulOperationStateLen = op_data_len;
			return (CKR_BUFFER_TOO_SMALL);
		}
	}

	dst = pOperationState;

	/* Save total length */
	bcopy(&op_data_len, dst, sizeof (int));
	dst += sizeof (int);

	/* Save session state */
	bcopy(&ses_state, dst, sizeof (CK_STATE));
	dst += sizeof (CK_STATE);

	/* Save crypto_active_op_t */
	bcopy(&session_p->digest, dst, sizeof (crypto_active_op_t));
	dst += sizeof (crypto_active_op_t);

	/* Save the data buffer */
	bcopy(bufp->buf, dst, bufp->indata_len);

	*pulOperationStateLen = op_data_len;
	return (CKR_OK);
}

CK_RV
C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG_PTR pulOperationStateLen)
{
	CK_RV rv;
	CK_STATE ses_state;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_TRUE;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pulOperationStateLen == NULL_PTR)
		return (CKR_ARGUMENTS_BAD);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	ses_state = get_ses_state(session_p);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	rv = kernel_get_operationstate(session_p, ses_state,
	    pOperationState, pulOperationStateLen);

	REFRELE(session_p, ses_lock_held);
	return (rv);
}

/*
 * Restore the state from pOperationState. The data format is:
 * 1. Total length (including this field)
 * 2. session state
 * 3. crypto_active_op_t structure
 * 4. digest_buf_t's data buffer contents
 */
static CK_RV
kernel_set_operationstate(kernel_session_t *session_p, CK_STATE ses_state,
    CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	CK_RV rv;
	CK_BYTE_PTR src;
	CK_STATE src_ses_state;
	int expected_len, indata_len;
	digest_buf_t *bufp;
	crypto_active_op_t tmp_op;

	if ((hAuthenticationKey != 0) || (hEncryptionKey != 0))
		return (CKR_KEY_NOT_NEEDED);

	src = pOperationState;

	/* Get total length field */
	bcopy(src, &expected_len, sizeof (int));
	if (ulOperationStateLen < expected_len)
		return (CKR_SAVED_STATE_INVALID);

	/* compute the data buffer length */
	indata_len = expected_len - sizeof (int) -
	    sizeof (CK_STATE) - sizeof (crypto_active_op_t);
	if (indata_len > SLOT_MAX_INDATA_LEN(session_p))
		return (CKR_SAVED_STATE_INVALID);
	src += sizeof (int);

	/* Get session state */
	bcopy(src, &src_ses_state, sizeof (CK_STATE));
	if (ses_state != src_ses_state)
		return (CKR_SAVED_STATE_INVALID);
	src += sizeof (CK_STATE);

	/*
	 * Restore crypto_active_op_t. We need to use a temporary
	 * buffer to avoid modifying the source session's buffer.
	 */
	bcopy(src, &tmp_op, sizeof (crypto_active_op_t));
	if (tmp_op.flags & CRYPTO_EMULATE_USING_SW)
		return (CKR_SAVED_STATE_INVALID);
	session_p->digest.mech = tmp_op.mech;
	session_p->digest.flags = tmp_op.flags;
	src += sizeof (crypto_active_op_t);

	/* This routine reuses the session's existing buffer if possible */
	rv = emulate_buf_init(session_p, indata_len, OP_DIGEST);
	if (rv != CKR_OK)
		return (rv);
	bufp = session_p->digest.context;
	bufp->indata_len = indata_len;

	/* Restore the data buffer */
	bcopy(src, bufp->buf, bufp->indata_len);

	return (CKR_OK);
}


CK_RV
C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
	CK_RV rv;
	CK_STATE ses_state;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_TRUE;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if ((pOperationState == NULL_PTR) ||
	    (ulOperationStateLen == 0))
		return (CKR_ARGUMENTS_BAD);

	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	ses_state = get_ses_state(session_p);

	(void) pthread_mutex_lock(&session_p->session_mutex);

	rv = kernel_set_operationstate(session_p, ses_state,
	    pOperationState, ulOperationStateLen,
	    hEncryptionKey, hAuthenticationKey);

	REFRELE(session_p, ses_lock_held);
	return (rv);
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
