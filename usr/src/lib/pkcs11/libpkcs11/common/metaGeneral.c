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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */
/*
 * General-Purpose Functions
 * (as defined in PKCS#11 spec section 11.4)
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "metaGlobal.h"

extern meta_session_t *meta_sessionlist_head;

struct CK_FUNCTION_LIST metaslot_functionList = {
	{ 2, 20 },	/* version */
	meta_Initialize,
	meta_Finalize,
	meta_GetInfo,
	meta_GetFunctionList,
	meta_GetSlotList,
	meta_GetSlotInfo,
	meta_GetTokenInfo,
	meta_GetMechanismList,
	meta_GetMechanismInfo,
	meta_InitToken,
	meta_InitPIN,
	meta_SetPIN,
	meta_OpenSession,
	meta_CloseSession,
	meta_CloseAllSessions,
	meta_GetSessionInfo,
	meta_GetOperationState,
	meta_SetOperationState,
	meta_Login,
	meta_Logout,
	meta_CreateObject,
	meta_CopyObject,
	meta_DestroyObject,
	meta_GetObjectSize,
	meta_GetAttributeValue,
	meta_SetAttributeValue,
	meta_FindObjectsInit,
	meta_FindObjects,
	meta_FindObjectsFinal,
	meta_EncryptInit,
	meta_Encrypt,
	meta_EncryptUpdate,
	meta_EncryptFinal,
	meta_DecryptInit,
	meta_Decrypt,
	meta_DecryptUpdate,
	meta_DecryptFinal,
	meta_DigestInit,
	meta_Digest,
	meta_DigestUpdate,
	meta_DigestKey,
	meta_DigestFinal,
	meta_SignInit,
	meta_Sign,
	meta_SignUpdate,
	meta_SignFinal,
	meta_SignRecoverInit,
	meta_SignRecover,
	meta_VerifyInit,
	meta_Verify,
	meta_VerifyUpdate,
	meta_VerifyFinal,
	meta_VerifyRecoverInit,
	meta_VerifyRecover,
	meta_DigestEncryptUpdate,
	meta_DecryptDigestUpdate,
	meta_SignEncryptUpdate,
	meta_DecryptVerifyUpdate,
	meta_GenerateKey,
	meta_GenerateKeyPair,
	meta_WrapKey,
	meta_UnwrapKey,
	meta_DeriveKey,
	meta_SeedRandom,
	meta_GenerateRandom,
	meta_GetFunctionStatus,
	meta_CancelFunction,
	meta_WaitForSlotEvent
};

pthread_mutex_t initmutex = PTHREAD_MUTEX_INITIALIZER;

ses_to_be_freed_list_t ses_delay_freed;
object_to_be_freed_list_t obj_delay_freed;

/*
 * meta_Initialize
 *
 * This function is never called by the application.  It is only
 * called by uCF to initialize metaslot.  The pInitArgs argument is ignored.
 *
 */
/*ARGSUSED*/
CK_RV
meta_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_RV rv;

	/* Make sure function hasn't been called twice */
	(void) pthread_mutex_lock(&initmutex);

	rv = meta_slotManager_initialize();
	if (rv != CKR_OK) {
		(void) pthread_mutex_unlock(&initmutex);
		return (rv);
	}

	rv = meta_mechManager_initialize();
	if (rv != CKR_OK) {
		(void) meta_slotManager_finalize();
		(void) pthread_mutex_unlock(&initmutex);
		return (rv);
	}

	rv = meta_objectManager_initialize();
	if (rv != CKR_OK) {
		(void) meta_slotManager_finalize();
		(void) meta_mechManager_finalize();
		(void) pthread_mutex_unlock(&initmutex);
		return (rv);
	}

	rv = meta_sessionManager_initialize();
	if (rv != CKR_OK) {
		(void) meta_slotManager_finalize();
		(void) meta_mechManager_finalize();
		(void) meta_objectManager_finalize();
		(void) pthread_mutex_unlock(&initmutex);
		return (rv);
	}

	meta_slotManager_find_object_token();

	/* Initialize the object_to_be_freed list */
	(void) pthread_mutex_init(&obj_delay_freed.obj_to_be_free_mutex, NULL);
	obj_delay_freed.count = 0;
	obj_delay_freed.first = NULL;
	obj_delay_freed.last = NULL;

	/* Initialize the session_to_be_freed list */
	(void) pthread_mutex_init(&ses_delay_freed.ses_to_be_free_mutex, NULL);
	ses_delay_freed.count = 0;
	ses_delay_freed.first = NULL;
	ses_delay_freed.last = NULL;

	(void) pthread_mutex_unlock(&initmutex);

	return (CKR_OK);
}


/*
 * meta_Finalize
 *
 * Called by uCF only, "pReserved" argument is ignored.
 */
/*ARGSUSED*/
CK_RV
meta_Finalize(CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;
	meta_object_t *delay_free_obj, *tmpo;
	meta_session_t *delay_free_ses, *tmps;

	if (pReserved != NULL)
		return (CKR_ARGUMENTS_BAD);

	(void) pthread_mutex_lock(&initmutex);

	/*
	 * There used to be calls to cleanup libcryptoutil here.  Given that
	 * libcryptoutil can be linked and invoked independently of PKCS#11,
	 * cleaning up libcryptoutil here makes no sense.  Decoupling these
	 * two also prevent deadlocks and other artificial dependencies.
	 */

	meta_objectManager_finalize();

	meta_sessionManager_finalize();

	meta_mechManager_finalize();

	meta_slotManager_finalize();

	/*
	 * free all entries in the delay_freed list
	 */
	delay_free_obj = obj_delay_freed.first;
	while (delay_free_obj != NULL) {
		tmpo = delay_free_obj->next;
		free(delay_free_obj);
		delay_free_obj = tmpo;
	}
	(void) pthread_mutex_destroy(&obj_delay_freed.obj_to_be_free_mutex);

	delay_free_ses = ses_delay_freed.first;
	while (delay_free_ses != NULL) {
		tmps = delay_free_ses->next;
		free(delay_free_ses);
		delay_free_ses = tmps;
	}
	(void) pthread_mutex_destroy(&ses_delay_freed.ses_to_be_free_mutex);

	(void) pthread_mutex_unlock(&initmutex);

	return (rv);
}

/*
 * meta_GetInfo
 *
 * NOTE: This function will never be called by applications because it's
 * hidden behind the uCF C_GetInfo. So, it is not implemented.
 */
/*ARGSUSED*/
CK_RV
meta_GetInfo(CK_INFO_PTR pInfo)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}


/*
 * meta_GetFunctionList
 *
 * This function is not implemented because metaslot is part of the framework,
 * so, the framework can just do a static assignment to metaslot's
 * function list instead of calling this function.
 */
/*ARGSUSED*/
CK_RV
meta_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}


/*
 * Parallel Function Management Function
 * (as defined in PKCS#11 spec section 11.16)
 */

/*
 * This function is no longer supported in this revision of the PKCS#11
 * standard.  It is maintained for backwards compatibility only.
 */
/* ARGSUSED */
CK_RV
meta_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}


/*
 * This function is no longer supported in this revision of the PKCS#11
 * standard.  It is maintained for backwards compatibility only.
 */
/* ARGSUSED */
CK_RV
meta_CancelFunction(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}
