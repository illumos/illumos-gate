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

#include <unistd.h>
#include <string.h>
#include <cryptoutil.h>
#include <pthread.h>

#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Slot.h"
#include "pkcs11Conf.h"
#include "pkcs11Session.h"

#pragma fini(pkcs11_fini)

static struct CK_FUNCTION_LIST functionList = {
	{ 2, 20 },	/* version */
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

boolean_t pkcs11_initialized = B_FALSE;
boolean_t pkcs11_cant_create_threads = B_FALSE;
boolean_t fini_called = B_FALSE;
static boolean_t pkcs11_atfork_initialized = B_FALSE;
static pid_t pkcs11_pid = 0;

/* protects pkcs11_[initialized|pid], and fastpath */
static pthread_mutex_t globalmutex = PTHREAD_MUTEX_INITIALIZER;

static CK_RV finalize_common(CK_VOID_PTR pReserved);
static void pkcs11_fini();

/*
 * Ensure that before a fork, all mutexes are taken.
 * Order:
 * 1. globalmutex
 * 2. slottable->st_mutex
 * 3. all slottable->st_slots' mutexes
 */
static void
pkcs11_fork_prepare(void)
{
	int i;
	(void) pthread_mutex_lock(&globalmutex);
	if (slottable != NULL) {
		(void) pthread_mutex_lock(&slottable->st_mutex);

		/* Take the sl_mutex of all slots */
		for (i = slottable->st_first; i <= slottable->st_last; i++) {
			if (slottable->st_slots[i] != NULL) {
				(void) pthread_mutex_lock(
				    &slottable->st_slots[i]->sl_mutex);
			}
		}
	}
}


/*
 * Ensure that after a fork, in the parent, all mutexes are released in opposite
 * order to pkcs11_fork_prepare().
 */
static void
pkcs11_fork_parent(void)
{
	int i;
	if (slottable != NULL) {
		/* Release the sl_mutex of all slots */
		for (i = slottable->st_first; i <= slottable->st_last; i++) {
			if (slottable->st_slots[i] != NULL) {
				(void) pthread_mutex_unlock(
				    &slottable->st_slots[i]->sl_mutex);
			}
		}
		(void) pthread_mutex_unlock(&slottable->st_mutex);
	}
	(void) pthread_mutex_unlock(&globalmutex);
}


/*
 * Ensure that after a fork, in the child, all mutexes are released in opposite
 * order to pkcs11_fork_prepare() and cleanup is done.
 */
static void
pkcs11_fork_child(void)
{
	int i;
	if (slottable != NULL) {
		/* Release the sl_mutex of all slots */
		for (i = slottable->st_first; i <= slottable->st_last; i++) {
			if (slottable->st_slots[i] != NULL) {
				(void) pthread_mutex_unlock(
				    &slottable->st_slots[i]->sl_mutex);
			}
		}
		(void) pthread_mutex_unlock(&slottable->st_mutex);
	}
	(void) pthread_mutex_unlock(&globalmutex);
	pkcs11_fini();
}

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_RV rv;
	uentrylist_t *pliblist = NULL;
	int initialize_pid;

	/*
	 * Grab lock to insure only one thread enters
	 * this function at a time.
	 */
	(void) pthread_mutex_lock(&globalmutex);

	initialize_pid = getpid();

	/* Make sure function hasn't been called twice */
	if (pkcs11_initialized) {
		if (initialize_pid == pkcs11_pid) {
			(void) pthread_mutex_unlock(&globalmutex);
			return (CKR_CRYPTOKI_ALREADY_INITIALIZED);
		} else {
			/*
			 * A fork has happened and the child is
			 * reinitializing.  Do a finalize_common() to close
			 * out any state from the parent, and then
			 * continue on.
			 */
			(void) finalize_common(NULL);
		}
	}

	/* Check if application has provided mutex-handling functions */
	if (pInitArgs != NULL) {
		CK_C_INITIALIZE_ARGS_PTR initargs =
			(CK_C_INITIALIZE_ARGS_PTR) pInitArgs;

		/* pReserved should not be set */
		if (initargs->pReserved != NULL) {
			rv = CKR_ARGUMENTS_BAD;
			goto errorexit;
		}

		/*
		 * Make sure function pointers are either all NULL or
		 * all set.
		 */
		if (!(((initargs->CreateMutex   != NULL) &&
			(initargs->LockMutex    != NULL) &&
			(initargs->UnlockMutex  != NULL) &&
			(initargs->DestroyMutex != NULL)) ||
			((initargs->CreateMutex == NULL) &&
			(initargs->LockMutex    == NULL) &&
			(initargs->UnlockMutex  == NULL) &&
			(initargs->DestroyMutex == NULL)))) {
			rv = CKR_ARGUMENTS_BAD;
			goto errorexit;
		}

		if (!(initargs->flags & CKF_OS_LOCKING_OK)) {
			if (initargs->CreateMutex != NULL) {
				/*
				 * Do not accept application supplied
				 * locking primitives.
				 */
				rv = CKR_CANT_LOCK;
				goto errorexit;
			}

		}
		if (initargs->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) {
			/*
			 * Calling application does not want the library
			 * to create threads.  This will effect
			 * C_WaitForSlotEvent().
			 */
			pkcs11_cant_create_threads = B_TRUE;
		}
	}

	/* Initialize slot table */
	rv = pkcs11_slottable_initialize();

	if (rv != CKR_OK)
		goto errorexit;

	/* Get the list of providers */
	if (get_pkcs11conf_info(&pliblist) != SUCCESS) {
		rv = CKR_FUNCTION_FAILED;
		goto errorexit;
	}

	/*
	 * Load each provider, check for accessible slots,
	 * and populate slottable.  If metaslot is enabled,
	 * it will be initialized as well.
	 */
	rv = pkcs11_slot_mapping(pliblist, pInitArgs);

	if (rv != CKR_OK)
		goto errorexit;

	pkcs11_initialized = B_TRUE;
	pkcs11_pid = initialize_pid;
	/* Children inherit parent's atfork handlers */
	if (!pkcs11_atfork_initialized) {
		(void) pthread_atfork(pkcs11_fork_prepare,
		    pkcs11_fork_parent, pkcs11_fork_child);
		pkcs11_atfork_initialized = B_TRUE;
	}
	(void) pthread_mutex_unlock(&globalmutex);

	/* Cleanup data structures no longer needed */
	free_uentrylist(pliblist);

	return (CKR_OK);

errorexit:
	/* Cleanup any data structures that have already been allocated */
	if (slottable)
		(void) pkcs11_slottable_delete();
	if (pliblist)
		(void) free_uentrylist(pliblist);

	(void) pthread_mutex_unlock(&globalmutex);
	return (rv);

}

/*
 * C_Finalize is a wrapper around finalize_common. The
 * globalmutex should be locked by C_Finalize().
 *
 * When an explicit C_Finalize() call is received, all
 * plugins currently in the slottable will also be
 * finalized.  This must occur, even if libpkcs11(3lib)
 * was not the first one to initialize the plugins, since it
 * is the only way in PKCS#11 to force a refresh of the
 * slot listings (ie to get new hardware devices).
 */
CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{

	CK_RV rv;

	(void) pthread_mutex_lock(&globalmutex);

	rv = finalize_common(pReserved);

	(void) pthread_mutex_unlock(&globalmutex);

	return (rv);
}

/*
 * finalize_common() does the work for C_Finalize.  globalmutex
 * must be held before calling this function.
 */
static CK_RV
finalize_common(CK_VOID_PTR pReserved)
{

	CK_RV rv;

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pReserved != NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	purefastpath = B_FALSE;
	policyfastpath = B_FALSE;
	fast_funcs = NULL;
	fast_slot = 0;
	pkcs11_initialized = B_FALSE;
	pkcs11_cant_create_threads = B_FALSE;
	pkcs11_pid = 0;

	/* Check if C_WaitForSlotEvent() is currently active */
	(void) pthread_mutex_lock(&slottable->st_mutex);
	if (slottable->st_wfse_active) {
		/*
		 * Wait for this thread to proceed far enough to block or
		 * end on its own.  Otherwise, teardown of slottable may
		 * occurr before this active function completes.
		 */
		while (slottable->st_wfse_active) {
			/*
			 * If C_WaitForSlotEvent is blocking, wake it up and
			 * return error to calling application.
			 */
			if (slottable->st_blocking) {
				slottable->st_list_signaled = B_TRUE;
				(void) pthread_cond_signal(
					&slottable->st_wait_cond);
				(void) pthread_mutex_unlock(
					&slottable->st_mutex);
				(void) pthread_join(slottable->st_tid, NULL);
			}
		}
	} else {
		(void) pthread_mutex_unlock(&slottable->st_mutex);
	}

	rv = pkcs11_slottable_delete();

	return (rv);
}

/*
 * pkcs11_fini() function required to make sure complete cleanup
 * is done of plugins if the framework is ever unloaded without
 * a C_Finalize() call.  This would be common when applications
 * load and unload other libraries that use libpkcs11(3lib), since
 * shared libraries should not call C_Finalize().
 *
 * If pkcs11_fini() is used, we set fini_called to B_TRUE so that
 * pkcs11_slottable_delete() will not call C_Finalize() on the plugins.
 *
 * This is to protect in cases where the application has dlopened
 * an object (for example, dlobj) that links to libpkcs11(3lib), but
 * the application is unaware that the object is doing PKCS#11 calls
 * underneath.  This application may later directly dlopen one of the
 * plugins (like pkcs11_softtoken.so, or any other 3rd party provided
 * plugin) in order to directly perform PKCS#11 operations.
 *
 * While it is still actively using the PKCS#11 plugin directly,
 * the application may finish with dlobj and dlclose it.  As the
 * reference count for libpkcs11(3lib) has become 0, pkcs11_fini()
 * will be run by the linker.  Even though libpkcs11(3lib) was the
 * first to initialize the plugin in this case, it is not safe for
 * libpkcs11(3lib) to finalize the plugin, as the application would
 * lose state.
 */
static void
pkcs11_fini()
{
	(void) pthread_mutex_lock(&globalmutex);

	/* if we're not initilized, do not attempt to finalize */
	if (!pkcs11_initialized) {
		(void) pthread_mutex_unlock(&globalmutex);
		return;
	}

	fini_called = B_TRUE;

	(void) finalize_common(NULL_PTR);

	(void) pthread_mutex_unlock(&globalmutex);

}

CK_RV
C_GetInfo(CK_INFO_PTR pInfo)
{

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_GetInfo(pInfo));
	}

	if (!pkcs11_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Copy data into the provided buffer, use strncpy() instead
	 * of strlcpy() so that the strings are NOT NULL terminated,
	 * as required by the PKCS#11 standard
	 */
	(void) strncpy((char *)pInfo->manufacturerID, MANUFACTURER_ID,
	    PKCS11_STRING_LENGTH);
	(void) strncpy((char *)pInfo->libraryDescription,
	    LIBRARY_DESCRIPTION, PKCS11_STRING_LENGTH);

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	pInfo->flags = 0;
	pInfo->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = LIBRARY_VERSION_MINOR;

	return (CKR_OK);
}

/*
 * This function is unaffected by the fast-path, since it is likely
 * called before C_Initialize is, so we will not yet know the status
 * of the fast-path.  Additionally, policy will still need to be
 * enforced if applicable.
 */
CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	*ppFunctionList = &functionList;

	return (CKR_OK);
}


/*
 * This function is no longer supported in this revision of the PKCS#11
 * standard.  It is maintained for backwards compatibility only.
 */
/*ARGSUSED*/
CK_RV
C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}


/*
 * This function is no longer supported in this revision of the PKCS#11
 * standard.  It is maintained for backwards compatibility only.
 */
/*ARGSUSED*/
CK_RV
C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}
