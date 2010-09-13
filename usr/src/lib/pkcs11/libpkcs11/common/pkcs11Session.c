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

#include <pthread.h>
#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Session.h"
#include "pkcs11Slot.h"
#include "metaGlobal.h"

/*
 * C_OpenSession will need to create a pseudo session associated
 * with the session created by the plugged in provider.  Only
 * minimal argument checking is done here, as we rely on the
 * underlying provider to catch most errors.
 */
CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{

	CK_RV rv;
	CK_SLOT_ID true_id;
	CK_SLOT_ID fw_st_id; /* id for accessing framework's slottable */
	CK_SESSION_HANDLE prov_sess;

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		if (metaslot_enabled) {
			/*
			 * if metaslot is enabled and we are in fastpath
			 * mode, only one other slot is in the framework
			 * so, need to go to that slot's entry
			 * to look up the true slot ID for the slot
			 */
			return (fast_funcs->C_OpenSession(TRUEID(slotID+1),
			    flags, pApplication, Notify, phSession));
		} else {
			return (fast_funcs->C_OpenSession(slotID, flags,
			    pApplication, Notify, phSession));
		}
	}


	if (slotID == METASLOT_FRAMEWORK_ID) {
		rv = meta_OpenSession(METASLOT_SLOTID, flags,
		    pApplication, Notify, &prov_sess);
	} else {
		/* Check that slotID is valid */
		if (pkcs11_validate_and_convert_slotid(slotID, &fw_st_id)
		    != CKR_OK) {
			return (CKR_SLOT_ID_INVALID);
		}
		true_id = TRUEID(fw_st_id);
		rv = FUNCLIST(fw_st_id)->C_OpenSession(true_id, flags,
		    pApplication, Notify, &prov_sess);
	}

	/* Present consistent interface for framework */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	} else if (rv != CKR_OK) {
		/* could not create session with provider, return now */
		return (rv);
	}

	/* Provider was successful, now create session in framework */
	if (slotID == METASLOT_FRAMEWORK_ID) {
		rv = pkcs11_session_add(
		    slottable->st_slots[METASLOT_FRAMEWORK_ID],
		    METASLOT_FRAMEWORK_ID, phSession, prov_sess);
	} else {
		rv = pkcs11_session_add(slottable->st_slots[fw_st_id],
		    fw_st_id, phSession, prov_sess);
	}

	if (rv != CKR_OK) {
		/* Trouble in the framework, clean up provider session */
		FUNCLIST(slotID)->C_CloseSession(prov_sess);
	}
	return (rv);
}

/*
 * C_CloseSession will close a session with the underlying provider,
 * and if that's successful will close it in the framework.
 */
CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_CloseSession(hSession));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Delete the session with the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_CloseSession(sessp->se_handle);

	/* Present consistent interface for framework */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	} else if (rv != CKR_OK) {
		/* could not delete session with provider, return now */
		return (rv);
	}

	/* Delete session from the framework */
	pkcs11_session_delete(slottable->st_slots[sessp->se_slotid], sessp);

	return (rv);
}

/*
 * C_CloseAllSessions will close all sessions associated with this
 * slot with the underlying provider.  If that is successful, will
 * close the associated sessions in the framework.  If the provider
 * has not implemented C_CloseAllSessions, then we will loop through
 * the list of sessions and individually call C_CloseSession.
 */
CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{

	CK_RV rv, rv1;

	CK_SLOT_ID true_id;
	CK_SLOT_ID fw_st_id; /* id for accessing framework's slottable */
	pkcs11_session_t *sessp, *sess_nextp;
	pkcs11_slot_t *slotp;

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		if (metaslot_enabled) {
			/*
			 * if metaslot is enabled and we are in fastpath
			 * mode, only one other slot is in the framework
			 * so, need to go to that slot's entry
			 * to look up the true slot ID for the slot
			 */
			return (fast_funcs->C_CloseAllSessions(
			    TRUEID(slotID+1)));
		} else {
			return (fast_funcs->C_CloseAllSessions(slotID));
		}
	}

	/* Check that slotID is valid */
	if (pkcs11_validate_and_convert_slotid(slotID, &fw_st_id) != CKR_OK) {
		return (CKR_SLOT_ID_INVALID);
	}

	slotp = slottable->st_slots[fw_st_id];
	true_id = TRUEID(fw_st_id);

	rv = FUNCLIST(fw_st_id)->C_CloseAllSessions(true_id);

	/* Present consistent interface for framework */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		/* Need to attempt to individually delete sessions */

		/* reset rv */
		rv = CKR_OK;

		(void) pthread_mutex_lock(&slotp->sl_mutex);
		sessp = slotp->sl_sess_list;

		while (sessp) {
			sess_nextp = sessp->se_next;

			rv1 = FUNCLIST(fw_st_id)->
			    C_CloseSession(sessp->se_handle);

			/* Record the first error encountered */
			if ((rv == CKR_OK) && (rv1 != CKR_OK)) {
				rv = rv1;
			}

			sessp = sess_nextp;
		}

		(void) pthread_mutex_unlock(&slotp->sl_mutex);
	}

	if (rv != CKR_OK) {
		/* could not delete sessionlist with provider, return now */
		return (rv);
	}

	/* Delete sessions from the framework */
	pkcs11_sessionlist_delete(slotp);

	return (rv);
}

/*
 * C_GetSessionInfo is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{

	CK_RV rv;
	CK_SLOT_ID slot_id;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		rv = fast_funcs->C_GetSessionInfo(hSession, pInfo);

		/*
		 * If metaslot is enabled, and we are here, that
		 * that means there's only 1 other slot in the
		 * framework, and that slot should be hidden.
		 * so, override value of slot id to be metaslot's
		 * slot id.
		 */
		if (metaslot_enabled) {
			pInfo->slotID = METASLOT_FRAMEWORK_ID;
		}
		return (rv);
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Find the slot id for the framework */
	slot_id = sessp->se_slotid;

	/* Get session info from the provider */
	rv = FUNCLIST(slot_id)->
	    C_GetSessionInfo(sessp->se_handle, pInfo);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	/* Override value of slot id to framework's */
	pInfo->slotID = slot_id;

	return (rv);
}

/*
 * C_GetOperationState is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG_PTR pulOperationStateLen)
{

	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_GetOperationState(hSession,
			    pOperationState, pulOperationStateLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Get the operation state with the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_GetOperationState(sessp->se_handle,
		pOperationState, pulOperationStateLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}


/*
 * C_SetOperationState is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_SetOperationState(hSession,
			    pOperationState, ulOperationStateLen,
			    hEncryptionKey, hAuthenticationKey));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Set the operation state with the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_SetOperationState(sessp->se_handle,
		pOperationState, ulOperationStateLen, hEncryptionKey,
		hAuthenticationKey);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}


/*
 * C_Login is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_Login(hSession, userType, pPin,
			    ulPinLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Login with the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_Login(sessp->se_handle,
	    userType, pPin, ulPinLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_Logout is a pure wrapper to the underlying provider.
 * The only argument checked is whether or not hSession is valid.
 */
CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_Logout(hSession));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	rv = FUNCLIST(sessp->se_slotid)->C_Logout(sessp->se_handle);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
