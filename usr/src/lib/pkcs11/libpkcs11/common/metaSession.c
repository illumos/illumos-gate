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
 * Session Management Functions
 * (as defined in PKCS#11 spec spection 11.6)
 */

#include <string.h>
#include "metaGlobal.h"

extern meta_session_t *meta_sessionlist_head;
extern pthread_rwlock_t meta_sessionlist_lock;
extern CK_ULONG num_meta_sessions;
extern CK_ULONG num_rw_meta_sessions;

/*
 * meta_OpenSession
 *
 * NOTES:
 * 1) The pApplication and Notify args are not used, as the metaslot does not
 *    support application callbacks.
 * 2) the slotID argument is not checked or used because this function
 *    is only called from the framework.
 */
/* ARGSUSED */
CK_RV
meta_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	meta_session_t *new_session;
	CK_RV rv;

	if (!metaslot_enabled) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (phSession == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Check for any unknown flags. */
	if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION)) {
		return (CKR_ARGUMENTS_BAD);
	}

	if (!(flags & CKF_SERIAL_SESSION)) {
		return (CKR_SESSION_PARALLEL_NOT_SUPPORTED);
	}

	if (meta_slotManager_token_write_protected() &&
	    (flags & CKF_RW_SESSION)) {
		return (CKR_TOKEN_WRITE_PROTECTED);
	}

	rv = meta_session_alloc(&new_session);
	if (rv != CKR_OK)
		return (rv);

	new_session->session_flags = flags;

	rv = meta_session_activate(new_session);
	if (rv != CKR_OK) {
		meta_session_dealloc(new_session);
		return (rv);
	}

	*phSession = (CK_SESSION_HANDLE) new_session;

	num_meta_sessions++;
	if (flags & CKF_RW_SESSION) {
		num_rw_meta_sessions++;
	}

	return (CKR_OK);
}


/*
 * meta_CloseSession
 *
 */
CK_RV
meta_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	meta_session_t *session;
	CK_FLAGS flags;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	/* save info about session flags before they are destroyed */
	flags = session->session_flags;

	rv = meta_session_deactivate(session, B_FALSE);

	if (rv == CKR_OK)
		meta_session_dealloc(session);

	num_meta_sessions--;
	if (flags & CKF_RW_SESSION) {
		num_rw_meta_sessions--;
	}

	return (rv);
}


/*
 * meta_CloseAllSessions
 *
 * This is a simple loop that closes the sessionlist head (resulting in a
 * new list head) until the list is empty.
 *
 */
CK_RV
meta_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV rv;
	meta_session_t *session;

	if (!metaslot_enabled) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (slotID != METASLOT_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	(void) pthread_rwlock_wrlock(&meta_sessionlist_lock);
	while ((session = meta_sessionlist_head) != NULL) {
		rv = meta_handle2session((CK_SESSION_HANDLE)session, &session);
		if (rv != CKR_OK) {
			/*NOTREACHED*/
			(void) pthread_rwlock_unlock(&meta_sessionlist_lock);
			return (CKR_FUNCTION_FAILED);
		}

		(void) meta_session_deactivate(session, B_TRUE);
		meta_session_dealloc(session);
	}
	(void) pthread_rwlock_unlock(&meta_sessionlist_lock);

	/* All open sessions should be closed, just reset the variables */
	num_meta_sessions = 0;
	num_rw_meta_sessions = 0;

	return (CKR_OK);
}


/*
 * meta_GetSessionInfo
 *
 */
CK_RV
meta_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv;
	meta_session_t *session;

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	pInfo->slotID = METASLOT_SLOTID;
	pInfo->flags = session->session_flags;

	if (metaslot_logged_in()) {
		if (IS_READ_ONLY_SESSION(session->session_flags)) {
			pInfo->state = CKS_RO_USER_FUNCTIONS;
		} else {
			pInfo->state = CKS_RW_USER_FUNCTIONS;
		}
	} else {
		if (IS_READ_ONLY_SESSION(session->session_flags)) {
			pInfo->state = CKS_RO_PUBLIC_SESSION;
		} else {
			pInfo->state = CKS_RW_PUBLIC_SESSION;
		}
	}

	pInfo->ulDeviceError = 0;

	REFRELEASE(session);

	return (CKR_OK);
}

CK_RV
meta_getopstatelen(meta_session_t *session, CK_ULONG *out_length)
{
	CK_RV rv = CKR_OK;
	slot_session_t *slot_session;
	CK_ULONG length;

	*out_length = sizeof (meta_opstate_t);
	if (session->op1.type != 0) {
		slot_session = session->op1.session;
		rv = FUNCLIST(slot_session->fw_st_id)->C_GetOperationState(
		    slot_session->hSession, NULL, &length);
		if (rv == CKR_OK)
			*out_length += length;
	}
	return (rv);
}

/*
 * meta_GetOperationState
 *
 */
CK_RV
meta_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG_PTR pulOperationStateLen)
{
	CK_RV rv;
	meta_session_t *session;
	slot_session_t *slot_session = NULL;
	meta_opstate_t opstate;

	if (pulOperationStateLen == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * If no operation is active, then bail out.
	 */
	if (session->op1.type == 0) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
		goto endgetopstate;
	}

	/*
	 * If the caller did not give an OpState buffer,
	 * shortcut and just return the size needed to hold
	 * a metaslot OpState record later.
	 * The actual size of the returned state will be the
	 * sizeof(meta_opstate_t) + SIZE (op1 state),
	 * so we have to get the size of
	 * the operation states now.
	 */
	if (pOperationState == NULL) {
		rv = meta_getopstatelen(session, pulOperationStateLen);
		REFRELEASE(session);
		return (rv);
	}

	/*
	 * To be here, the caller must have supplied an
	 * already initialized meta_opstate_t pointer.
	 * Use it to get the real state info from the operation(s).
	 *
	 * The format of the Metaslot Opstate record:
	 * {
	 *    struct metaopstate
	 *    [ op1 state data ]
	 * }
	 */

	/*
	 * If the buffer is not even big enough for the metaslot
	 * opstate data, return error and set the returned
	 * state length to indicate the minimum needed.
	 */
	if (*pulOperationStateLen < sizeof (meta_opstate_t)) {
		rv = meta_getopstatelen(session, pulOperationStateLen);
		/*
		 * Remap the error so the caller knows that they
		 * used an invalid buffer size in the first place.
		 */
		if (rv == CKR_OK)
			rv = CKR_BUFFER_TOO_SMALL;
		goto endgetopstate;
	}

	(void) memset(&opstate, 0, sizeof (meta_opstate_t));
	opstate.magic_marker = METASLOT_OPSTATE_MAGIC;

	if (session->op1.type != 0) {
		slot_session = session->op1.session;
		opstate.state[0].op_type = session->op1.type;
		opstate.state[0].op_slotnum = slot_session->slotnum;
		opstate.state[0].op_state_len = *pulOperationStateLen -
		    sizeof (meta_opstate_t);
		opstate.state[0].op_init_app = session->init.app;
		opstate.state[0].op_init_done = session->init.done;
		rv = FUNCLIST(slot_session->fw_st_id)->C_GetOperationState(
		    slot_session->hSession,
		    pOperationState + sizeof (meta_opstate_t),
		    &(opstate.state[0].op_state_len));

		if (rv == CKR_BUFFER_TOO_SMALL) {
			/*
			 * This should not happen, but if it does,
			 * recalculate the entire size needed
			 * and return the error.
			 */
			rv = meta_getopstatelen(session, pulOperationStateLen);
			if (rv == CKR_OK)
				rv = CKR_BUFFER_TOO_SMALL;
		}

		if (rv != CKR_OK)
			goto endgetopstate;
	}

endgetopstate:
	if (rv == CKR_OK && pOperationState != NULL) {
		(void) memcpy(pOperationState, (void *)&opstate,
		    sizeof (meta_opstate_t));

		*pulOperationStateLen = sizeof (meta_opstate_t) +
		    opstate.state[0].op_state_len;
	}

	REFRELEASE(session);
	return (rv);
}

static CK_RV
meta_set_opstate(slot_session_t *slot_session,
		meta_object_t *meta_enc_key,
		meta_object_t *meta_auth_key,
		struct opstate_data *state,
		CK_BYTE *databuf)
{
	CK_RV rv;
	static CK_ULONG encrypt_optypes = (CKF_ENCRYPT | CKF_DECRYPT);
	static CK_ULONG sign_optypes = (CKF_SIGN | CKF_VERIFY |
	    CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER);
	slot_object_t *enc_key_obj = NULL, *auth_key_obj = NULL;

	if (state->op_type & encrypt_optypes) {
		rv = meta_object_get_clone(meta_enc_key, slot_session->slotnum,
		    slot_session, &enc_key_obj);
		if (rv != CKR_OK) {
			return (rv);
		}
	}
	if (state->op_type & sign_optypes) {
		rv = meta_object_get_clone(meta_auth_key, slot_session->slotnum,
		    slot_session, &auth_key_obj);
		if (rv != CKR_OK) {
			return (rv);
		}
	}

	/*
	 * Check to see if the keys are needed to restore the
	 * state on the first operation.
	 */
	rv = FUNCLIST(slot_session->fw_st_id)->C_SetOperationState(
	    slot_session->hSession, databuf, state->op_state_len,
	    enc_key_obj ? enc_key_obj->hObject : CK_INVALID_HANDLE,
	    auth_key_obj ? auth_key_obj->hObject : CK_INVALID_HANDLE);
	/*
	 * If the operation did not need a key, try again.
	 */
	if (rv == CKR_KEY_NOT_NEEDED) {
		rv = FUNCLIST(slot_session->fw_st_id)->C_SetOperationState(
		    slot_session->hSession, databuf, state->op_state_len,
		    CK_INVALID_HANDLE, CK_INVALID_HANDLE);
		/*
		 * Strange case... If the first try returned
		 * KEY_NOT_NEEDED, and this one returns KEY_NEEDED,
		 * we want to remap the return so the caller sees
		 * the original "CKR_KEY_NOT_NEEDED" return value.
		 * This ensures that a correct caller will retry
		 * without the unnecessary key argument and this
		 * 2nd attempt will not happen again.
		 */
		if (rv == CKR_KEY_NEEDED) {
			rv  = CKR_KEY_NOT_NEEDED;
		}
	}

	return (rv);
}

/*
 * meta_SetOperationState
 *
 */
CK_RV
meta_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
	CK_RV rv = CKR_OK;
	meta_session_t *session;
	slot_session_t *slot_session = NULL;
	meta_opstate_t opstate;
	meta_object_t *meta_enc_key = NULL, *meta_auth_key = NULL;

	/*
	 * Make sure the opstate info buffer is big enough to be valid.
	 */
	if (ulOperationStateLen < sizeof (meta_opstate_t) ||
	    pOperationState == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Copy the opstate info into the structure */
	(void) memcpy(&opstate, pOperationState, sizeof (meta_opstate_t));

	/* verify that a metaslot operation state was supplied */
	if (opstate.magic_marker != METASLOT_OPSTATE_MAGIC)
		return (CKR_SAVED_STATE_INVALID);

	/*
	 * Now, check the size again to make sure the "real" state
	 * data is present.  Length of state provided must be exact.
	 */
	if (ulOperationStateLen != (sizeof (meta_opstate_t) +
	    opstate.state[0].op_state_len))
		return (CKR_SAVED_STATE_INVALID);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (hEncryptionKey != CK_INVALID_HANDLE) {
		rv = meta_handle2object(hEncryptionKey, &meta_enc_key);
		if (rv != CKR_OK)
			goto cleanup;
	}
	if (hAuthenticationKey != CK_INVALID_HANDLE) {
		rv = meta_handle2object(hAuthenticationKey, &meta_auth_key);
		if (rv != CKR_OK)
			goto cleanup;
	}

	if (opstate.state[0].op_type != 0) {
		if (session->op1.type != 0)
			meta_operation_cleanup(session, session->op1.type,
			    B_FALSE);

		rv = meta_get_slot_session(opstate.state[0].op_slotnum,
		    &slot_session, session->session_flags);
		if (rv != CKR_OK)
			goto cleanup;

		session->op1.type = opstate.state[0].op_type;
		session->op1.session = slot_session;
		session->init.app = opstate.state[0].op_init_app;
		session->init.done = opstate.state[0].op_init_done;

		rv = meta_set_opstate(slot_session, meta_enc_key,
		    meta_auth_key, &(opstate.state[0]),
		    pOperationState + sizeof (meta_opstate_t));

		if (rv != CKR_OK) {
			meta_operation_cleanup(session, session->op1.type,
			    FALSE);
			goto cleanup;
		}
	}

cleanup:
	if (meta_enc_key != NULL)
		OBJRELEASE(meta_enc_key);
	if (meta_auth_key != NULL)
		OBJRELEASE(meta_auth_key);
	REFRELEASE(session);
	return (rv);
}

/*
 * meta_Login
 *
 * This allows the user to login to the object token. The metaslot itself
 * does not have any kind of PIN.
 *
 */
CK_RV
meta_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv;
	meta_session_t *session;
	slot_session_t *login_session = NULL;
	CK_TOKEN_INFO token_info;
	CK_SLOT_ID true_id, fw_st_id;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (metaslot_logged_in()) {
		rv = CKR_USER_ALREADY_LOGGED_IN;
		goto finish;
	}

	/* Note: CKU_SO is not supported. */
	if (userType != CKU_USER) {
		rv = CKR_USER_TYPE_INVALID;
		goto finish;
	}

	rv = meta_get_slot_session(get_keystore_slotnum(), &login_session,
	    session->session_flags);
	if (rv != CKR_OK)
		goto finish;


	fw_st_id = login_session->fw_st_id;
	rv = FUNCLIST(fw_st_id)->C_Login(login_session->hSession, userType,
	    pPin, ulPinLen);

	if (rv != CKR_OK) {
		goto finish;
	}

	/*
	 * Note:
	 *
	 * For some slots (eg: the pkcs11_softtoken.so), C_Login()
	 * returning OK don't mean that the login is truely
	 * successful.  For pkcs11_softtoken.so, the CKF_USER_PIN_TO_BE_CHANGED
	 * is set to indicate that the pin needs to be changed, and
	 * the login is not really successful.  We will check
	 * that flag for this special condition.  Checking for
	 * this flag shouldn't be harmful for other slots that doesn't
	 * behave like pkcs11_softtoken.so.
	 */

	true_id = TRUEID(fw_st_id);
	rv = FUNCLIST(fw_st_id)->C_GetTokenInfo(true_id, &token_info);
	if (rv != CKR_OK) {
		goto finish;
	}

	metaslot_set_logged_in_flag(B_TRUE);
	if (token_info.flags & CKF_USER_PIN_TO_BE_CHANGED) {
		metaslot_set_logged_in_flag(B_FALSE);
	}
finish:
	if (login_session)
		meta_release_slot_session(login_session);

	REFRELEASE(session);

	return (rv);
}

/*
 * meta_Logout
 *
 */
CK_RV
meta_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	meta_session_t *session;
	slot_session_t *logout_session = NULL;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (!metaslot_logged_in()) {
		rv = CKR_USER_NOT_LOGGED_IN;
		goto finish;
	}

	rv = meta_get_slot_session(get_keystore_slotnum(), &logout_session,
	    session->session_flags);
	if (rv != CKR_OK)
		goto finish;

	rv = FUNCLIST(logout_session->fw_st_id)->C_Logout(
	    logout_session->hSession);

	/* If the C_Logout fails, just ignore the error. */
	metaslot_set_logged_in_flag(B_FALSE);

finish:
	if (logout_session)
		meta_release_slot_session(logout_session);

	REFRELEASE(session);

	return (rv);
}
