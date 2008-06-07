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

#include <fcntl.h>
#include <pthread.h>
#include <strings.h>
#include <unistd.h> /* for pid */
#include <errno.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelSlot.h"

#pragma fini(kernel_fini)

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

boolean_t kernel_initialized = B_FALSE;
static boolean_t kernel_atfork_initialized = B_FALSE;
static pid_t kernel_pid = 0;

int kernel_fd = -1;


/* protects kernel_initialized and entrance to C_Initialize/Finalize */
static pthread_mutex_t globalmutex = PTHREAD_MUTEX_INITIALIZER;

ses_to_be_freed_list_t ses_delay_freed;
object_to_be_freed_list_t obj_delay_freed;
kmh_elem_t **kernel_mechhash;	/* Hash table for kCF mech numbers */

static void finalize_common();
static void cleanup_library();
static void kernel_fini();
static void kernel_fork_prepare();
static void kernel_fork_parent();
static void kernel_fork_child();

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
	int initialize_pid;
	boolean_t supplied_ok;
	CK_RV rv = CKR_OK;

	/*
	 * Grab lock to insure that only one thread enters this
	 * function at a time.
	 */
	(void) pthread_mutex_lock(&globalmutex);
	initialize_pid = getpid();

	if (kernel_initialized) {
		if (initialize_pid == kernel_pid) {
			/*
			 * This process has called C_Initialize already
			 */
			(void) pthread_mutex_unlock(&globalmutex);
			return (CKR_CRYPTOKI_ALREADY_INITIALIZED);
		} else {
			/*
			 * A fork has happened and the child is
			 * reinitializing.  Do a cleanup_library to close
			 * out any state from the parent, and then
			 * continue on.
			 */
			cleanup_library();
		}
	}

	if (pInitArgs != NULL) {
		CK_C_INITIALIZE_ARGS *initargs1 =
		    (CK_C_INITIALIZE_ARGS *) pInitArgs;

		/* pReserved must be NULL */
		if (initargs1->pReserved != NULL) {
			(void) pthread_mutex_unlock(&globalmutex);
			return (CKR_ARGUMENTS_BAD);
		}

		/*
		 * ALL supplied function pointers need to have the value
		 * either NULL or non-NULL.
		 */
		supplied_ok = (initargs1->CreateMutex == NULL &&
		    initargs1->DestroyMutex == NULL &&
		    initargs1->LockMutex == NULL &&
		    initargs1->UnlockMutex == NULL) ||
		    (initargs1->CreateMutex != NULL &&
		    initargs1->DestroyMutex != NULL &&
		    initargs1->LockMutex != NULL &&
		    initargs1->UnlockMutex != NULL);

		if (!supplied_ok) {
			(void) pthread_mutex_unlock(&globalmutex);
			return (CKR_ARGUMENTS_BAD);
		}

		/*
		 * When the CKF_OS_LOCKING_OK flag isn't set and mutex
		 * function pointers are supplied by an application,
		 * return an error.  We must be able to use our own locks.
		 */
		if (!(initargs1->flags & CKF_OS_LOCKING_OK) &&
		    (initargs1->CreateMutex != NULL)) {
			(void) pthread_mutex_unlock(&globalmutex);
			return (CKR_CANT_LOCK);
		}
	}

	while ((kernel_fd = open(CRYPTO_DEVICE, O_RDWR)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (kernel_fd < 0) {
		(void) pthread_mutex_unlock(&globalmutex);
		return (CKR_FUNCTION_FAILED);
	}

	/* Mark kernel_fd "close on exec" */
	(void) fcntl(kernel_fd, F_SETFD, FD_CLOEXEC);

	/* Create the hash table */
	kernel_mechhash = calloc(KMECH_HASHTABLE_SIZE, sizeof (void *));
	if (kernel_mechhash == NULL) {
		(void) close(kernel_fd);
		(void) pthread_mutex_unlock(&globalmutex);
		return (CKR_HOST_MEMORY);
	}

	/* Initialize the slot table */
	rv = kernel_slottable_init();
	if (rv != CKR_OK) {
		free(kernel_mechhash);
		(void) close(kernel_fd);
		(void) pthread_mutex_unlock(&globalmutex);
		return (rv);
	}

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

	kernel_initialized = B_TRUE;
	kernel_pid = initialize_pid;

	/* Children inherit parent's atfork handlers */
	if (!kernel_atfork_initialized) {
		(void) pthread_atfork(kernel_fork_prepare, kernel_fork_parent,
		    kernel_fork_child);
		kernel_atfork_initialized = B_TRUE;
	}

	(void) pthread_mutex_unlock(&globalmutex);

	return (CKR_OK);

}


/*
 * C_Finalize is a wrapper around finalize_common. The
 * globalmutex should be locked by C_Finalize().
 */
CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
	int i;

	(void) pthread_mutex_lock(&globalmutex);

	if (!kernel_initialized) {
		(void) pthread_mutex_unlock(&globalmutex);
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Check to see if pReseved is NULL */
	if (pReserved != NULL) {
		(void) pthread_mutex_unlock(&globalmutex);
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Delete all the sessions for each slot and release the allocated
	 * resources
	 */
	for (i = 0; i < slot_count; i++) {
		kernel_delete_all_sessions(i, B_FALSE);
	}

	finalize_common();

	(void) pthread_mutex_unlock(&globalmutex);

	return (CKR_OK);
}

/*
 * finalize_common() does the work for C_Finalize.  globalmutex
 * must be held before calling this function.
 */
static void
finalize_common() {

	int i;
	kmh_elem_t *elem, *next;
	kernel_object_t *delay_free_obj, *tmpo;
	kernel_session_t *delay_free_ses, *tmps;

	/*
	 * Free the resources allocated for the slot table and reset
	 * slot_count to 0.
	 */
	if (slot_count > 0) {
		for (i = 0; i < slot_count; i++) {
			(void) pthread_mutex_destroy(&slot_table[i]->sl_mutex);
			(void) free(slot_table[i]);
		}
		(void) free(slot_table);
		slot_count = 0;
	}

	/* Close CRYPTO_DEVICE */
	if (kernel_fd >= 0) {
		(void) close(kernel_fd);
	}

	/* Walk the hash table and free all entries */
	for (i = 0; i < KMECH_HASHTABLE_SIZE; i++) {
		elem = kernel_mechhash[i];
		while (elem != NULL) {
			next = elem->knext;
			free(elem);
			elem = next;
		}
	}

	free(kernel_mechhash);

	kernel_fd = -1;
	kernel_initialized = B_FALSE;
	kernel_pid = 0;

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
}

/*
 * This function cleans up all the resources in the library (user space only)
 */
static void
cleanup_library()
{
	int i;

	/*
	 * Delete all the sessions for each slot and release the allocated
	 * resources from the library.  The boolean argument TRUE indicates
	 * that we only wants to clean up the resource in the library only.
	 * We don't want to clean up the corresponding kernel part of
	 * resources, because they are used by the parent process still.
	 */

	for (i = 0; i < slot_count; i++) {
		kernel_delete_all_sessions(i, B_TRUE);
	}

	finalize_common();
}

/*
 * kernel_fini() function required to make sure complete cleanup
 * is done if pkcs11_kernel is ever unloaded without
 * a C_Finalize() call.
 */
static void
kernel_fini()
{

	(void) pthread_mutex_lock(&globalmutex);

	/* if we're not initilized, do not attempt to finalize */
	if (!kernel_initialized) {
		(void) pthread_mutex_unlock(&globalmutex);
		return;
	}

	cleanup_library();

	(void) pthread_mutex_unlock(&globalmutex);
}

CK_RV
C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Check if the cryptoki was initialized */

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	(void) strncpy((char *)pInfo->manufacturerID,
	    MANUFACTURER_ID, 32);
	pInfo->flags = 0;
	(void) strncpy((char *)pInfo->libraryDescription,
	    LIBRARY_DESCRIPTION, 32);
	pInfo->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = LIBRARY_VERSION_MINOR;

	return (CKR_OK);
}

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
 * PKCS#11 states that C_GetFunctionStatus should always return
 * CKR_FUNCTION_NOT_PARALLEL
 */
/*ARGSUSED*/
CK_RV
C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}

/*
 * Take out all mutexes before fork.
 * Order:
 * 1. globalmutex
 * 2. all slots mutexes (and all their sessions) via
 *    kernel_acquire_all_slots_mutexes()
 * 3. obj_delay_freed.obj_to_be_free_mutex;
 * 4. ses_delay_freed.ses_to_be_free_mutex
 */
void
kernel_fork_prepare()
{
	(void) pthread_mutex_lock(&globalmutex);
	kernel_acquire_all_slots_mutexes();
	(void) pthread_mutex_lock(
	    &obj_delay_freed.obj_to_be_free_mutex);
	(void) pthread_mutex_lock(
	    &ses_delay_freed.ses_to_be_free_mutex);
}

/* Release in opposite order to kernel_fork_prepare(). */
void
kernel_fork_parent()
{
	(void) pthread_mutex_unlock(
	    &ses_delay_freed.ses_to_be_free_mutex);
	(void) pthread_mutex_unlock(
	    &obj_delay_freed.obj_to_be_free_mutex);
	kernel_release_all_slots_mutexes();
	(void) pthread_mutex_unlock(&globalmutex);
}

/* Release in opposite order to kernel_fork_prepare(). */
void
kernel_fork_child()
{
	(void) pthread_mutex_unlock(
	    &ses_delay_freed.ses_to_be_free_mutex);
	(void) pthread_mutex_unlock(
	    &obj_delay_freed.obj_to_be_free_mutex);
	kernel_release_all_slots_mutexes();
	(void) pthread_mutex_unlock(&globalmutex);
}

/*
 * PKCS#11 states that C_CancelFunction should always return
 * CKR_FUNCTION_NOT_PARALLEL
 */
/*ARGSUSED*/
CK_RV
C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	return (CKR_FUNCTION_NOT_PARALLEL);
}
