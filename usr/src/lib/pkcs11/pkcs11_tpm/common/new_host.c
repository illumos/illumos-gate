/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <pwd.h>
#include <grp.h>

#include "tpmtok_int.h"
#include "tpmtok_defs.h"

extern pthread_rwlock_t obj_list_rw_mutex;

void SC_SetFunctionList(void);

struct ST_FCN_LIST function_list;

int  debugfile = 0;

pid_t  initedpid = 0;  // for initialized pid

CK_C_INITIALIZE_ARGS cinit_args = {NULL, NULL, NULL, NULL, 0, NULL};

extern void stlogterm();
extern void stloginit();
extern void stlogit2(int type, char *fmt, ...);
extern void stlogit(char *fmt, ...);

CK_BBOOL
st_Initialized()
{
	return (initedpid == getpid());
}

void
Fork_Initializer(void)
{
	stlogterm();
	stloginit(); // Initialize Logging so we can capture EVERYTHING

	// Force logout.  This cleans out the private session and list
	// and cleans out the private object map
	(void) session_mgr_logout_all();

	// Clean out the public object map
	// First parm is no longer used..
	(void) object_mgr_purge_map((SESSION *)0xFFFF, PUBLIC);
	(void) object_mgr_purge_map((SESSION *)0xFFFF, PRIVATE);

	// This should clear the entire session list out
	(void) session_mgr_close_all_sessions();

	next_session_handle = 1;
	next_object_handle = 1;

	while (priv_token_obj_list) {
		priv_token_obj_list = dlist_remove_node(priv_token_obj_list,
		    priv_token_obj_list);
	}

	while (publ_token_obj_list) {
		publ_token_obj_list = dlist_remove_node(publ_token_obj_list,
		    publ_token_obj_list);
	}
}

#define	SESSION_HANDLE   sSession.sessionh

#define	SESS_SET \
	CK_SESSION_HANDLE  hSession = sSession.sessionh;

static CK_RV
validate_mechanism(CK_MECHANISM_PTR  pMechanism)
{
	CK_ULONG i;

	for (i = 0; i < mech_list_len; i++) {
		if (pMechanism->mechanism == mech_list[i].mech_type) {
			return (CKR_OK);
		}
	}
	return (CKR_MECHANISM_INVALID);
}

#define	VALID_MECH(p) \
	if (validate_mechanism(p) != CKR_OK) { \
		rc = CKR_MECHANISM_INVALID; \
		goto done; \
	}

CK_RV
ST_Initialize(void *FunctionList,
	CK_SLOT_ID SlotNumber,
	unsigned char *Correlator)
{
	CK_RV  rc = CKR_OK;
	struct ST_FCN_LIST *flist = (struct ST_FCN_LIST *)FunctionList;
	TSS_HCONTEXT hContext = 0;

	stlogterm();
	stloginit();

	if (st_Initialized() == TRUE) {
		return (CKR_OK);
	}
	// assume that the upper API prevents multiple calls of initialize
	// since that only happens on C_Initialize and that is the
	// resonsibility of the upper layer..
	initialized = FALSE;

	// check for other completing this before creating mutexes...
	// make sure that the same process tried to to the init...
	// thread issues should be caught up above...
	if (st_Initialized() == TRUE) {
		goto done;
	}

	Fork_Initializer();

	(void) pthread_mutex_init(&pkcs_mutex, NULL);
	(void) pthread_mutex_init(&obj_list_mutex, NULL);
	(void) pthread_rwlock_init(&obj_list_rw_mutex, NULL);

	(void) pthread_mutex_init(&sess_list_mutex, NULL);
	(void) pthread_mutex_init(&login_mutex, NULL);

	if (st_Initialized() == FALSE) {
		if ((rc = attach_shm()) != CKR_OK)
			goto done;

		nv_token_data = &global_shm->nv_token_data;

		initialized = TRUE;
		initedpid = getpid();
		SC_SetFunctionList();

		if (flist != NULL)
			(*flist) = function_list;

		/* Always call the token_specific_init function.... */
		rc = token_specific.t_init((char *)Correlator, SlotNumber,
		    &hContext);
		if (rc != 0) {
			/*
			 * The token could not be initialized, return OK, but
			 * present no slots.
			 */
			rc = CKR_OK;
			goto done;
		} else {
			/* Mark the token as available */
			global_shm->token_available = TRUE;
		}
	}

	rc = load_token_data(hContext, nv_token_data);

	if (rc != CKR_OK) {
		goto done;
	}

	rc = load_public_token_objects();
	if (rc != CKR_OK)
		goto done;

	(void) XProcLock(xproclock);
	global_shm->publ_loaded = TRUE;
	(void) XProcUnLock(xproclock);

	init_slot_info(nv_token_data);

done:
	if (hContext)
		Tspi_Context_Close(hContext);
	return (rc);
}

/*ARGSUSED*/
CK_RV
SC_Finalize(void *argptr)
{
	CK_RV	  rc;
	TSS_HCONTEXT hContext;

	if (st_Initialized() == FALSE) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	rc = pthread_mutex_lock(&pkcs_mutex);
	if (rc != CKR_OK) {
		return (rc);
	}
	//
	// If somebody else has taken care of things, leave...
	//
	if (st_Initialized() == FALSE) {
		(void) pthread_mutex_unlock(&pkcs_mutex);
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}
	if (open_tss_context(&hContext)) {
		(void) pthread_mutex_unlock(&pkcs_mutex);
		return (CKR_FUNCTION_FAILED);
	}

	initialized = FALSE;

	if (token_specific.t_final != NULL) {
		token_specific.t_final(hContext);
	}

	(void) session_mgr_close_all_sessions();
	(void) object_mgr_purge_token_objects(hContext);

	(void) Tspi_Context_Close(hContext);

	(void) detach_shm();

	rc = pthread_mutex_unlock(&pkcs_mutex);
	if (rc != CKR_OK) {
		return (rc);
	}
	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
SC_GetTokenInfo(CK_SLOT_ID sid, CK_TOKEN_INFO_PTR  pInfo)
{
	CK_RV rc = CKR_OK;
	time_t now;

	if (st_Initialized() == FALSE)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL)
		return (CKR_FUNCTION_FAILED);

	if (sid != TPM_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	(void) memcpy(pInfo, &nv_token_data->token_info,
	    sizeof (CK_TOKEN_INFO));

	now = time((time_t *)NULL);
	(void) strftime((char *)pInfo->utcTime, 16, "%X", localtime(&now));

	return (rc);
}

/*ARGSUSED*/
CK_RV
SC_GetMechanismList(
	CK_SLOT_ID	sid,
	CK_MECHANISM_TYPE_PTR  pMechList,
	CK_ULONG_PTR	count)
{
	CK_ULONG   i;
	CK_RV	rc = CKR_OK;

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (count == NULL) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (sid != TPM_SLOTID) {
		rc = CKR_SLOT_ID_INVALID;
		goto done;
	}

	if (pMechList == NULL) {
		*count = mech_list_len;
		rc = CKR_OK;
		goto done;
	}

	if (*count < mech_list_len) {
		*count = mech_list_len;
		rc = CKR_BUFFER_TOO_SMALL;
		goto done;
	}

	for (i = 0; i < mech_list_len; i++)
		pMechList[i] = mech_list[i].mech_type;

	*count = mech_list_len;
	rc = CKR_OK;

done:
	if (debugfile) {
		stlogit2(debugfile,
		    "% - 25s:  rc = 0x%08x, # mechanisms:  %d\n",
		    "C_GetMechanismList", rc, *count);
	}
	return (rc);
}

/*ARGSUSED*/
CK_RV
SC_GetMechanismInfo(
	CK_SLOT_ID		sid,
	CK_MECHANISM_TYPE	type,
	CK_MECHANISM_INFO_PTR  pInfo)
{
	CK_ULONG  i;
	CK_RV	rc = CKR_OK;

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (pInfo == NULL) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (sid != TPM_SLOTID) {
		rc = CKR_SLOT_ID_INVALID;
		goto done;
	}

	for (i = 0; i < mech_list_len; i++) {
		if (mech_list[i].mech_type == type) {
			(void) memcpy(pInfo, &mech_list[i].mech_info,
			    sizeof (CK_MECHANISM_INFO));
			rc = CKR_OK;
			goto done;
		}
	}
	rc = CKR_MECHANISM_INVALID;

done:
	if (debugfile) {
		stlogit2(debugfile, "% - 25s:  "
		    "rc = 0x%08x, mech type = 0x%08x\n",
		    "C_GetMechanismInfo", rc, type);
	}

	return (rc);
}

/*ARGSUSED*/
CK_RV
SC_InitToken(
	CK_SLOT_ID  sid,
	CK_CHAR_PTR pPin,
	CK_ULONG    ulPinLen,
	CK_CHAR_PTR pLabel)
{
	CK_RV	rc = CKR_OK;
	CK_BYTE    hash_sha[SHA1_DIGEST_LENGTH];
	TOKEN_DATA	newtoken;
	TSS_HCONTEXT	hContext = 0;

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (sid != TPM_SLOTID) {
		rc = CKR_SLOT_ID_INVALID;
		goto done;
	}

	if (! pPin || ! pLabel) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	if (open_tss_context(&hContext)) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = load_token_data(hContext, &newtoken);
	if (rc != CKR_OK) {
		goto done;
	}

	if (newtoken.token_info.flags & CKF_SO_PIN_LOCKED) {
		rc = CKR_PIN_LOCKED;
		goto done;
	}

	rc = token_specific.t_verify_so_pin(hContext, pPin, ulPinLen);
	if (rc != CKR_OK) {
		rc = CKR_PIN_INCORRECT;
		goto done;
	}

	/*
	 * Before we reconstruct all the data, we should delete the
	 * token objects from the filesystem.
	 *
	 * Construct a string to delete the token objects.
	 */
	(void) object_mgr_destroy_token_objects(hContext);

	(void) init_token_data(hContext, &newtoken);
	(void) init_slot_info(&newtoken);

	/* change the label */
	(void) strncpy((char *)newtoken.token_info.label, (char *)pLabel,
	    sizeof (newtoken.token_info.label));

	(void) memcpy(newtoken.so_pin_sha, hash_sha,
	    SHA1_DIGEST_LENGTH);

	newtoken.token_info.flags |= CKF_TOKEN_INITIALIZED;

	rc = save_token_data(&newtoken);
done:
	if (hContext)
		(void) Tspi_Context_Close(hContext);

	return (rc);
}

CK_RV
SC_InitPIN(
	ST_SESSION_HANDLE  sSession,
	CK_CHAR_PTR	pPin,
	CK_ULONG	   ulPinLen)
{
	SESSION	 * sess = NULL;
	CK_RV		rc = CKR_OK;
	CK_FLAGS	* flags = NULL;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pPin) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_locked(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_LOCKED;
		goto done;
	}

	if (sess->session_info.state != CKS_RW_SO_FUNCTIONS) {
		rc = CKR_USER_NOT_LOGGED_IN;
		goto done;
	}

	rc = token_specific.t_init_pin(sess->hContext, pPin, ulPinLen);
	if (rc == CKR_OK) {
		flags = &nv_token_data->token_info.flags;

		*flags &= ~(CKF_USER_PIN_LOCKED |
		    CKF_USER_PIN_FINAL_TRY |
		    CKF_USER_PIN_COUNT_LOW);

		rc = save_token_data(nv_token_data);
		if (rc != CKR_OK) {
			goto done;
		}
	}

done:

	if (debugfile) {
		stlogit2(debugfile, "% - 25s:  session = %08x\n",
		    "C_InitPin", rc, hSession);
	}

	return (rc);
}

CK_RV
SC_SetPIN(ST_SESSION_HANDLE  sSession,
	CK_CHAR_PTR	pOldPin,
	CK_ULONG	   ulOldLen,
	CK_CHAR_PTR	pNewPin,
	CK_ULONG	   ulNewLen)
{
	SESSION	 * sess = NULL;
	CK_RV		rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_locked(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_LOCKED;
		goto done;
	}

	rc = token_specific.t_set_pin(sSession, pOldPin,
	    ulOldLen, pNewPin, ulNewLen);

done:
	if (debugfile) {
		stlogit2(debugfile, "% - 25s:  session = %08x\n",
		    "C_SetPin", rc, hSession);
	}

	return (rc);
}

CK_RV
SC_OpenSession(
	CK_SLOT_ID		sid,
	CK_FLAGS		flags,
	CK_SESSION_HANDLE_PTR  phSession)
{
	SESSION		*sess;
	CK_RV		  rc = CKR_OK;
	TSS_HCONTEXT	hContext;

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if ((flags & CKF_RW_SESSION) == 0) {
		if (session_mgr_so_session_exists()) {
			return (CKR_SESSION_READ_WRITE_SO_EXISTS);
		}
	}
	if (sid != TPM_SLOTID) {
		rc = CKR_SLOT_ID_INVALID;
		goto done;
	}
	if (open_tss_context(&hContext)) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = pthread_mutex_lock(&pkcs_mutex);
	if (rc != CKR_OK) {
		(void) pthread_mutex_unlock(&pkcs_mutex);
		Tspi_Context_Close(hContext);
		goto done;
	}
	token_specific.t_session(sid);

	(void) pthread_mutex_unlock(&pkcs_mutex);

	rc = session_mgr_new(flags, &sess);
	if (rc != CKR_OK) {
		Tspi_Context_Close(hContext);
		goto done;
	}
	*phSession = sess->handle;
	sess->session_info.slotID = sid;

	/* Open a new context for each session */
	sess->hContext = hContext;
done:
	return (rc);
}

CK_RV
SC_CloseSession(ST_SESSION_HANDLE  sSession)
{
	SESSION  *sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (token_specific.t_final != NULL) {
		token_specific.t_final(sess->hContext);
	}

	rc = session_mgr_close_session(sess);

done:

	return (rc);
}

/*ARGSUSED*/
CK_RV
SC_CloseAllSessions(CK_SLOT_ID  sid)
{
	CK_RV rc = CKR_OK;

	if (st_Initialized() == FALSE)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (sid != TPM_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	rc = session_mgr_close_all_sessions();

	return (rc);
}

CK_RV
SC_GetSessionInfo(ST_SESSION_HANDLE   sSession,
	CK_SESSION_INFO_PTR pInfo)
{
	SESSION  * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pInfo) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	(void) memcpy(pInfo, &sess->session_info, sizeof (CK_SESSION_INFO));

done:
	return (rc);
}

CK_RV SC_GetOperationState(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pOperationState,
	CK_ULONG_PTR	pulOperationStateLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pulOperationStateLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	if (! pOperationState)
		length_only = TRUE;

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = session_mgr_get_op_state(sess, length_only,
	    pOperationState, pulOperationStateLen);
done:
	return (rc);
}

CK_RV
SC_SetOperationState(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pOperationState,
	CK_ULONG	   ulOperationStateLen,
	CK_OBJECT_HANDLE   hEncryptionKey,
	CK_OBJECT_HANDLE   hAuthenticationKey)
{
	SESSION  * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (!pOperationState || (ulOperationStateLen == 0)) {
		return (CKR_ARGUMENTS_BAD);
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	rc = session_mgr_set_op_state(sess,
	    hEncryptionKey,  hAuthenticationKey,
	    pOperationState);

	return (rc);
}

CK_RV
SC_Login(ST_SESSION_HANDLE   sSession,
	CK_USER_TYPE	userType,
	CK_CHAR_PTR	pPin,
	CK_ULONG	ulPinLen)
{
	SESSION	* sess = NULL;
	CK_FLAGS    * flags = NULL, flagcheck, flagmask;
	CK_RV	 rc = CKR_OK;

	SESS_SET
	// In v2.11, logins should be exclusive, since token
	// specific flags may need to be set for a bad login. - KEY
	rc = pthread_mutex_lock(&login_mutex);
	if (rc != CKR_OK) {
		return (CKR_FUNCTION_FAILED);
	}

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	flags = &nv_token_data->token_info.flags;

	if (pPin == NULL) {
		set_login_flags(userType, flags);
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) {
		set_login_flags(userType, flags);
		rc = CKR_PIN_LEN_RANGE;
		goto done;
	}

	/*
	 * PKCS #11 v2.01 requires that all sessions have the same login status:
	 * --> all sessions are public, all are SO or all are USER
	 */
	if (userType == CKU_USER) {
		if (session_mgr_so_session_exists()) {
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_user_session_exists()) {
			rc = CKR_USER_ALREADY_LOGGED_IN;
		}
	} else if (userType == CKU_SO) {
		if (session_mgr_user_session_exists()) {
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_so_session_exists()) {
			rc = CKR_USER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_readonly_exists()) {
			rc = CKR_SESSION_READ_ONLY_EXISTS;
		}
	} else {
		rc = CKR_USER_TYPE_INVALID;
	}
	if (rc != CKR_OK)
		goto done;

	if (userType == CKU_USER) {
		flagcheck = CKF_USER_PIN_LOCKED;
		flagmask = (CKF_USER_PIN_LOCKED | CKF_USER_PIN_FINAL_TRY |
		    CKF_USER_PIN_COUNT_LOW);
	} else {
		flagcheck = CKF_SO_PIN_LOCKED;
		flagmask = (CKF_SO_PIN_LOCKED |
		    CKF_SO_PIN_FINAL_TRY |
		    CKF_SO_PIN_COUNT_LOW);
	}
	if (*flags & flagcheck) {
		rc = CKR_PIN_LOCKED;
		goto done;
	}

	/* call the pluggable login function here */
	rc = token_specific.t_login(sess->hContext, userType, pPin, ulPinLen);
	if (rc == CKR_OK) {
		*flags &= ~(flagmask);
	} else if (rc == CKR_PIN_INCORRECT) {
		set_login_flags(userType, flags);
		goto done;
	} else {
		goto done;
	}

	rc = session_mgr_login_all(userType);

done:
	if (rc == CKR_OK)
		rc = save_token_data(nv_token_data);
	(void) pthread_mutex_unlock(&login_mutex);
	return (rc);
}

CK_RV
SC_Logout(ST_SESSION_HANDLE  sSession)
{
	SESSION  * sess = NULL;
	CK_RV	rc = CKR_OK;

	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	// all sessions have the same state so we just have to check one
	//
	if (session_mgr_public_session_exists()) {
		rc = CKR_USER_NOT_LOGGED_IN;
		goto done;
	}

	(void) session_mgr_logout_all();

	rc = token_specific.t_logout(sess->hContext);

done:
	return (rc);
}

CK_RV
SC_CreateObject(ST_SESSION_HANDLE    sSession,
	CK_ATTRIBUTE_PTR	pTemplate,
	CK_ULONG		ulCount,
	CK_OBJECT_HANDLE_PTR phObject)
{
	SESSION		* sess = NULL;
	CK_RV		   rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}
	rc = object_mgr_add(sess, pTemplate, ulCount, phObject);

done:
	return (rc);

}

CK_RV
SC_CopyObject(
	ST_SESSION_HANDLE    sSession,
	CK_OBJECT_HANDLE	hObject,
	CK_ATTRIBUTE_PTR	pTemplate,
	CK_ULONG		ulCount,
	CK_OBJECT_HANDLE_PTR phNewObject)
{
	SESSION		* sess = NULL;
	CK_RV		  rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = object_mgr_copy(sess, pTemplate, ulCount,
	    hObject, phNewObject);

done:
	return (rc);
}

CK_RV
SC_DestroyObject(ST_SESSION_HANDLE  sSession,
	CK_OBJECT_HANDLE   hObject)
{
	SESSION		* sess = NULL;
	CK_RV		   rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = object_mgr_destroy_object(sess, hObject);
done:
	return (rc);
}

CK_RV
SC_GetObjectSize(
	ST_SESSION_HANDLE  sSession,
	CK_OBJECT_HANDLE   hObject,
	CK_ULONG_PTR	pulSize)
{
	SESSION		* sess = NULL;
	CK_RV		   rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = object_mgr_get_object_size(sess->hContext, hObject, pulSize);

done:
	return (rc);
}

CK_RV
SC_GetAttributeValue(ST_SESSION_HANDLE  sSession,
	CK_OBJECT_HANDLE   hObject,
	CK_ATTRIBUTE_PTR   pTemplate,
	CK_ULONG	   ulCount)
{
	SESSION	* sess = NULL;
	CK_RV	    rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = object_mgr_get_attribute_values(sess, hObject, pTemplate, ulCount);

done:
	return (rc);
}

CK_RV
SC_SetAttributeValue(ST_SESSION_HANDLE    sSession,
	CK_OBJECT_HANDLE	hObject,
	CK_ATTRIBUTE_PTR	pTemplate,
	CK_ULONG		ulCount)
{
	SESSION	* sess = NULL;
	CK_RV	   rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = object_mgr_set_attribute_values(sess, hObject, pTemplate, ulCount);

done:
	return (rc);
}

CK_RV
SC_FindObjectsInit(ST_SESSION_HANDLE   sSession,
	CK_ATTRIBUTE_PTR    pTemplate,
	CK_ULONG	    ulCount)
{
	SESSION	* sess  = NULL;
	CK_RV	    rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->find_active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = object_mgr_find_init(sess, pTemplate, ulCount);

done:
	return (rc);
}

CK_RV
SC_FindObjects(ST_SESSION_HANDLE	sSession,
	CK_OBJECT_HANDLE_PTR  phObject,
	CK_ULONG		ulMaxObjectCount,
	CK_ULONG_PTR	  pulObjectCount)
{
	SESSION    * sess  = NULL;
	CK_ULONG	count = 0;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! phObject || ! pulObjectCount) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->find_active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! sess->find_list) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	count = MIN(ulMaxObjectCount, (sess->find_count - sess->find_idx));

	(void) memcpy(phObject, sess->find_list + sess->find_idx,
	    count * sizeof (CK_OBJECT_HANDLE));
	*pulObjectCount = count;

	sess->find_idx += count;
	rc = CKR_OK;

done:
	return (rc);
}

CK_RV
SC_FindObjectsFinal(ST_SESSION_HANDLE  sSession)
{
	SESSION	* sess = NULL;
	CK_RV	 rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->find_active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (sess->find_list)
		free(sess->find_list);

	sess->find_list   = NULL;
	sess->find_len    = 0;
	sess->find_idx    = 0;
	sess->find_active = FALSE;

	rc = CKR_OK;

done:
	return (rc);
}

CK_RV
SC_EncryptInit(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism,
	CK_OBJECT_HANDLE   hKey)
{
	SESSION		* sess = NULL;
	CK_RV		   rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pMechanism) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->encr_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = encr_mgr_init(sess, &sess->encr_ctx, OP_ENCRYPT_INIT,
	    pMechanism, hKey);
done:
	return (rc);
}

CK_RV
SC_Encrypt(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pData,
	CK_ULONG	   ulDataLen,
	CK_BYTE_PTR	pEncryptedData,
	CK_ULONG_PTR	pulEncryptedDataLen)
{
	SESSION	* sess = NULL;
	CK_BBOOL	 length_only = FALSE;
	CK_RV	    rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (! pData || ! pulEncryptedDataLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	if (sess->encr_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pEncryptedData)
		length_only = TRUE;

	rc = encr_mgr_encrypt(sess, length_only,
	    &sess->encr_ctx, pData, ulDataLen,
	    pEncryptedData, pulEncryptedDataLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) encr_mgr_cleanup(&sess->encr_ctx);

	return (rc);
}

#if 0
CK_RV
SC_EncryptUpdate(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pPart,
	CK_ULONG	   ulPartLen,
	CK_BYTE_PTR	pEncryptedPart,
	CK_ULONG_PTR	pulEncryptedPartLen)
{
	SESSION	* sess = NULL;
	CK_BBOOL	 length_only = FALSE;
	CK_RV	    rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pPart || ! pulEncryptedPartLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->encr_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pEncryptedPart)
		length_only = TRUE;

	rc = encr_mgr_encrypt_update(sess,	   length_only,
	    &sess->encr_ctx, pPart,	  ulPartLen,
	    pEncryptedPart, pulEncryptedPartLen);

done:
	if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
		(void) encr_mgr_cleanup(&sess->encr_ctx);

	return (rc);
}

CK_RV
SC_EncryptFinal(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pLastEncryptedPart,
	CK_ULONG_PTR	pulLastEncryptedPartLen)
{
	SESSION	* sess = NULL;
	CK_BBOOL	length_only = FALSE;
	CK_RV	 rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pulLastEncryptedPartLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->encr_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pLastEncryptedPart)
		length_only = TRUE;

	rc = encr_mgr_encrypt_final(sess, length_only, &sess->encr_ctx,
	    pLastEncryptedPart, pulLastEncryptedPartLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) encr_mgr_cleanup(&sess->encr_ctx);

	return (rc);
}
#endif

CK_RV
SC_DecryptInit(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism,
	CK_OBJECT_HANDLE   hKey)
{
	SESSION   * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pMechanism) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->decr_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = decr_mgr_init(sess, &sess->decr_ctx,
	    OP_DECRYPT_INIT, pMechanism, hKey);

done:
	return (rc);
}

CK_RV
SC_Decrypt(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pEncryptedData,
	CK_ULONG	   ulEncryptedDataLen,
	CK_BYTE_PTR	pData,
	CK_ULONG_PTR	pulDataLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	if (! pEncryptedData || ! pulDataLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	if (sess->decr_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pData)
		length_only = TRUE;

	rc = decr_mgr_decrypt(sess,
	    length_only,
	    &sess->decr_ctx,
	    pEncryptedData,
	    ulEncryptedDataLen,
	    pData,
	    pulDataLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) decr_mgr_cleanup(&sess->decr_ctx);

	return (rc);
}

CK_RV
SC_DigestInit(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism)
{
	SESSION   * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (! pMechanism) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->digest_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = digest_mgr_init(sess, &sess->digest_ctx, pMechanism);

done:
	return (rc);
}

CK_RV
SC_Digest(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pData,
	CK_ULONG	   ulDataLen,
	CK_BYTE_PTR	pDigest,
	CK_ULONG_PTR	pulDigestLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (! pData || ! pulDigestLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pDigest)
		length_only = TRUE;

	rc = digest_mgr_digest(sess,    length_only,
	    &sess->digest_ctx, pData,   ulDataLen,
	    pDigest, pulDigestLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) digest_mgr_cleanup(&sess->digest_ctx);

	return (rc);
}

CK_RV
SC_DigestUpdate(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pPart,
	CK_ULONG	   ulPartLen)
{
	SESSION  * sess = NULL;
	CK_RV	rc   = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pPart && ulPartLen != 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (pPart) {
		rc = digest_mgr_digest_update(sess, &sess->digest_ctx,
		    pPart, ulPartLen);
	}
done:
	if (rc != CKR_OK)
		(void) digest_mgr_cleanup(&sess->digest_ctx);

	return (rc);
}

CK_RV
SC_DigestKey(ST_SESSION_HANDLE  sSession,
	CK_OBJECT_HANDLE   hKey)
{
	SESSION  * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = digest_mgr_digest_key(sess, &sess->digest_ctx, hKey);

done:
	if (rc != CKR_OK)
		(void) digest_mgr_cleanup(&sess->digest_ctx);

	return (rc);
}

CK_RV
SC_DigestFinal(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pDigest,
	CK_ULONG_PTR	pulDigestLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pulDigestLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pDigest)
		length_only = TRUE;

	rc = digest_mgr_digest_final(sess,
	    &sess->digest_ctx, pDigest, pulDigestLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) digest_mgr_cleanup(&sess->digest_ctx);

	return (rc);
}

CK_RV
SC_SignInit(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism,
	CK_OBJECT_HANDLE   hKey)
{
	SESSION   * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pMechanism) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	VALID_MECH(pMechanism);

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->sign_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = sign_mgr_init(sess, &sess->sign_ctx, pMechanism, FALSE, hKey);

done:
	return (rc);
}

CK_RV
SC_Sign(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pData,
	CK_ULONG	   ulDataLen,
	CK_BYTE_PTR	pSignature,
	CK_ULONG_PTR	pulSignatureLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	if (!pData || !pulSignatureLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	if (sess->sign_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pSignature)
		length_only = TRUE;

	rc = sign_mgr_sign(sess,	length_only,
	    &sess->sign_ctx, pData,	ulDataLen,
	    pSignature, pulSignatureLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) sign_mgr_cleanup(&sess->sign_ctx);

	return (rc);
}

CK_RV
SC_SignUpdate(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pPart,
	CK_ULONG	   ulPartLen)
{
	SESSION  * sess = NULL;
	CK_RV	rc   = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pPart) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->sign_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = sign_mgr_sign_update(sess, &sess->sign_ctx, pPart, ulPartLen);

done:
	if (rc != CKR_OK)
		(void) sign_mgr_cleanup(&sess->sign_ctx);

	return (rc);
}

CK_RV
SC_SignFinal(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pSignature,
	CK_ULONG_PTR	pulSignatureLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pulSignatureLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->sign_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pSignature)
		length_only = TRUE;

	rc = sign_mgr_sign_final(sess,	length_only,
	    &sess->sign_ctx, pSignature, pulSignatureLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) sign_mgr_cleanup(&sess->sign_ctx);

	return (rc);
}

CK_RV
SC_SignRecoverInit(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism,
	CK_OBJECT_HANDLE   hKey)
{
	SESSION   * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (! pMechanism) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->sign_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = sign_mgr_init(sess, &sess->sign_ctx, pMechanism, TRUE, hKey);

done:
	return (rc);
}

CK_RV
SC_SignRecover(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pData,
	CK_ULONG	   ulDataLen,
	CK_BYTE_PTR	pSignature,
	CK_ULONG_PTR	pulSignatureLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	if (!pData || !pulSignatureLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	if ((sess->sign_ctx.active == FALSE) ||
	    (sess->sign_ctx.recover == FALSE)) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (! pSignature)
		length_only = TRUE;

	rc = sign_mgr_sign_recover(sess,	length_only,
	    &sess->sign_ctx, pData,	ulDataLen,
	    pSignature, pulSignatureLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) sign_mgr_cleanup(&sess->sign_ctx);

	return (rc);
}

CK_RV
SC_VerifyInit(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism,
	CK_OBJECT_HANDLE   hKey)
{
	SESSION   * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (! pMechanism) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->verify_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = verify_mgr_init(sess, &sess->verify_ctx, pMechanism, FALSE, hKey);

done:
	return (rc);
}

CK_RV
SC_Verify(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pData,
	CK_ULONG	   ulDataLen,
	CK_BYTE_PTR	pSignature,
	CK_ULONG	   ulSignatureLen)
{
	SESSION  * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (! pData || ! pSignature) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	if (sess->verify_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = verify_mgr_verify(sess,
	    &sess->verify_ctx, pData,	ulDataLen,
	    pSignature, ulSignatureLen);

done:
	(void) verify_mgr_cleanup(&sess->verify_ctx);

	return (rc);
}

CK_RV
SC_VerifyUpdate(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pPart,
	CK_ULONG	   ulPartLen)
{
	SESSION  * sess = NULL;
	CK_RV	rc   = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pPart) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->verify_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = verify_mgr_verify_update(sess, &sess->verify_ctx,
	    pPart, ulPartLen);
done:
	if (rc != CKR_OK)
		(void) verify_mgr_cleanup(&sess->verify_ctx);

	return (rc);
}

CK_RV
SC_VerifyFinal(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pSignature,
	CK_ULONG	   ulSignatureLen)
{
	SESSION  * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pSignature) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->verify_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = verify_mgr_verify_final(sess, &sess->verify_ctx,
	    pSignature, ulSignatureLen);

done:
	(void) verify_mgr_cleanup(&sess->verify_ctx);

	return (rc);
}

CK_RV
SC_VerifyRecoverInit(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism,
	CK_OBJECT_HANDLE   hKey)
{
	SESSION   * sess = NULL;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (! pMechanism) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->verify_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = verify_mgr_init(sess, &sess->verify_ctx, pMechanism, TRUE, hKey);

done:
	return (rc);
}

CK_RV
SC_VerifyRecover(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pSignature,
	CK_ULONG	   ulSignatureLen,
	CK_BYTE_PTR	pData,
	CK_ULONG_PTR	pulDataLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	if (!pSignature || !pulDataLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	if ((sess->verify_ctx.active == FALSE) ||
	    (sess->verify_ctx.recover == FALSE)) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}
	if (! pData)
		length_only = TRUE;

	rc = verify_mgr_verify_recover(sess,	length_only,
	    &sess->verify_ctx, pSignature, ulSignatureLen,
	    pData,	pulDataLen);

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		(void) verify_mgr_cleanup(&sess->verify_ctx);

	return (rc);
}

CK_RV
SC_GenerateKeyPair(ST_SESSION_HANDLE	sSession,
	CK_MECHANISM_PTR	pMechanism,
	CK_ATTRIBUTE_PTR	pPublicKeyTemplate,
	CK_ULONG		ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR	pPrivateKeyTemplate,
	CK_ULONG		ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR  phPublicKey,
	CK_OBJECT_HANDLE_PTR  phPrivateKey)
{
	SESSION	* sess = NULL;
	CK_RV	   rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pMechanism || ! phPublicKey || ! phPrivateKey ||
	    (! pPublicKeyTemplate && (ulPublicKeyAttributeCount != 0)) ||
	    (! pPrivateKeyTemplate && (ulPrivateKeyAttributeCount != 0))) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = key_mgr_generate_key_pair(sess, pMechanism,
	    pPublicKeyTemplate,  ulPublicKeyAttributeCount,
	    pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
	    phPublicKey,	 phPrivateKey);
done:
	return (rc);
}

CK_RV
SC_WrapKey(ST_SESSION_HANDLE  sSession,
	CK_MECHANISM_PTR   pMechanism,
	CK_OBJECT_HANDLE   hWrappingKey,
	CK_OBJECT_HANDLE   hKey,
	CK_BYTE_PTR	pWrappedKey,
	CK_ULONG_PTR	pulWrappedKeyLen)
{
	SESSION  * sess = NULL;
	CK_BBOOL   length_only = FALSE;
	CK_RV	rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pMechanism || ! pulWrappedKeyLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	VALID_MECH(pMechanism);

	if (! pWrappedKey)
		length_only = TRUE;

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = key_mgr_wrap_key(sess, length_only,
	    pMechanism, hWrappingKey, hKey,
	    pWrappedKey,  pulWrappedKeyLen);

done:
	return (rc);
}

CK_RV
SC_UnwrapKey(ST_SESSION_HANDLE	sSession,
	CK_MECHANISM_PTR	pMechanism,
	CK_OBJECT_HANDLE	hUnwrappingKey,
	CK_BYTE_PTR	   pWrappedKey,
	CK_ULONG		ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR	pTemplate,
	CK_ULONG		ulCount,
	CK_OBJECT_HANDLE_PTR  phKey)
{
	SESSION	* sess = NULL;
	CK_RV	    rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pMechanism || ! pWrappedKey ||
	    (! pTemplate && ulCount != 0) || ! phKey) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	VALID_MECH(pMechanism);

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
	    nv_token_data->token_info.flags) == TRUE) {
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = key_mgr_unwrap_key(sess,	   pMechanism,
	    pTemplate,	ulCount,
	    pWrappedKey,    ulWrappedKeyLen,
	    hUnwrappingKey, phKey);

done:
	return (rc);
}

/*ARGSUSED*/
CK_RV
SC_SeedRandom(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pSeed,
	CK_ULONG	   ulSeedLen)
{
	if (st_Initialized() == FALSE) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}
	if (pSeed == NULL || ulSeedLen == 0)
		return (CKR_ARGUMENTS_BAD);

	return (CKR_OK);
}

CK_RV
SC_GenerateRandom(ST_SESSION_HANDLE  sSession,
	CK_BYTE_PTR	pRandomData,
	CK_ULONG	   ulRandomLen)
{
	SESSION *sess = NULL;
	CK_RV    rc = CKR_OK;
	SESS_SET

	if (st_Initialized() == FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (! pRandomData && ulRandomLen != 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(hSession);
	if (! sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = token_rng(sess->hContext, pRandomData, ulRandomLen);

done:
	return (rc);
}

void
SC_SetFunctionList(void) {
	function_list.ST_Initialize	= ST_Initialize;
	function_list.ST_Finalize	= SC_Finalize;
	function_list.ST_GetTokenInfo	= SC_GetTokenInfo;
	function_list.ST_GetMechanismList    = SC_GetMechanismList;
	function_list.ST_GetMechanismInfo    = SC_GetMechanismInfo;
	function_list.ST_InitToken	   = SC_InitToken;
	function_list.ST_InitPIN		= SC_InitPIN;
	function_list.ST_SetPIN		= SC_SetPIN;
	function_list.ST_OpenSession	 = SC_OpenSession;
	function_list.ST_CloseSession	= SC_CloseSession;
	function_list.ST_GetSessionInfo	= SC_GetSessionInfo;
	function_list.ST_GetOperationState   = SC_GetOperationState;
	function_list.ST_SetOperationState   = SC_SetOperationState;
	function_list.ST_Login		= SC_Login;
	function_list.ST_Logout		= SC_Logout;
	function_list.ST_CreateObject	= SC_CreateObject;
	function_list.ST_CopyObject	  = SC_CopyObject;
	function_list.ST_DestroyObject	= SC_DestroyObject;
	function_list.ST_GetObjectSize	= SC_GetObjectSize;
	function_list.ST_GetAttributeValue   = SC_GetAttributeValue;
	function_list.ST_SetAttributeValue   = SC_SetAttributeValue;
	function_list.ST_FindObjectsInit	= SC_FindObjectsInit;
	function_list.ST_FindObjects	 = SC_FindObjects;
	function_list.ST_FindObjectsFinal    = SC_FindObjectsFinal;
	function_list.ST_EncryptInit	 = SC_EncryptInit;
	function_list.ST_Encrypt		= SC_Encrypt;
	function_list.ST_EncryptUpdate	= NULL /* SC_EncryptUpdate */;
	function_list.ST_EncryptFinal	= NULL /* SC_EncryptFinal */;
	function_list.ST_DecryptInit	 = SC_DecryptInit;
	function_list.ST_Decrypt		= SC_Decrypt;
	function_list.ST_DecryptUpdate	= NULL /* SC_DecryptUpdate */;
	function_list.ST_DecryptFinal	= NULL /* SC_DecryptFinal */;
	function_list.ST_DigestInit	  = SC_DigestInit;
	function_list.ST_Digest		= SC_Digest;
	function_list.ST_DigestUpdate	= SC_DigestUpdate;
	function_list.ST_DigestKey	   = SC_DigestKey;
	function_list.ST_DigestFinal	 = SC_DigestFinal;
	function_list.ST_SignInit	    = SC_SignInit;
	function_list.ST_Sign		= SC_Sign;
	function_list.ST_SignUpdate	  = SC_SignUpdate;
	function_list.ST_SignFinal	   = SC_SignFinal;
	function_list.ST_SignRecoverInit	= SC_SignRecoverInit;
	function_list.ST_SignRecover	 = SC_SignRecover;
	function_list.ST_VerifyInit	  = SC_VerifyInit;
	function_list.ST_Verify		= SC_Verify;
	function_list.ST_VerifyUpdate	= SC_VerifyUpdate;
	function_list.ST_VerifyFinal	 = SC_VerifyFinal;
	function_list.ST_VerifyRecoverInit   = SC_VerifyRecoverInit;
	function_list.ST_VerifyRecover	= SC_VerifyRecover;
	function_list.ST_DigestEncryptUpdate = NULL;
	function_list.ST_DecryptDigestUpdate = NULL;
	function_list.ST_SignEncryptUpdate   = NULL;
	function_list.ST_DecryptVerifyUpdate = NULL;
	function_list.ST_GenerateKey	 = NULL;
	function_list.ST_GenerateKeyPair	= SC_GenerateKeyPair;
	function_list.ST_WrapKey		= SC_WrapKey;
	function_list.ST_UnwrapKey	   = SC_UnwrapKey;
	function_list.ST_DeriveKey	   = NULL;
	function_list.ST_SeedRandom	= SC_SeedRandom;
	function_list.ST_GenerateRandom	= SC_GenerateRandom;
	function_list.ST_GetFunctionStatus   = NULL;
	function_list.ST_CancelFunction	= NULL;
}
