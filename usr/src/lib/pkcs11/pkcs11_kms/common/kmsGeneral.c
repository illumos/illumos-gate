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
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <fcntl.h>
#include <pthread.h>
#include <strings.h>
#include <unistd.h> /* for pid */
#include <errno.h>
#include <security/cryptoki.h>

#include "kmsKeystoreUtil.h"
#include "kmsGlobal.h"
#include "kmsSession.h"
#include "kmsSlot.h"

/*
 * PKCS#11 KMS Crypto provider module.
 *
 * This module provides access to a Key Management System (v 2.0)
 * through the Solaris Cryptographic Framework interfaces  (PKCS#11).
 *
 * PREREQUISITES
 * =============
 * 1. You must have access to a KMS on the network and you must
 * know the IP address and name of the "Agent" assigned to
 * you and the passphrase needed to access the Agent information.
 *
 * 2. The token configuration must be completed prior
 * to using this provider using the kmscfg(1m) utility.
 *
 * This provider provides support for 3 AES mechanisms:
 * CKM_AES_KEY_GEN (for 256 bit keys only)
 * CKM_AES_CBC (encrypt/decrypt)
 * CKM_AES_CBC_PAD (encrypt/decrypt)
 *
 * DETAILS
 * =======
 * Each user has their own local configuration for the KMS.
 * The local configuration information is typically located
 * in a private token directory - /var/tmp/kms/$USERNAME
 * The location may be overridden using an environment variable
 * $KMSTOKEN_DIR.  The user's private token namespace is configured
 * using kmscfg(1M) which establishes the directory and populates
 * it with a simple configuration file that this module later uses
 * to access the KMS.
 *
 * INITIALIZING
 * ============
 * Once the token configuration is established, C_InitToken
 * is used to initialize the first contact with the KMS.  This
 * will cause the provider to contact the KMS and download
 * the profile configuration data, a server certificate, and a
 * private entity key and certificate (in a PKCS#12 file).
 * Once the above data is collected it is stored under $KMSTOKEN_DIR.
 * The user may then proceed with normal PKCS#11 activity.
 *
 * LOGIN
 * =====
 * The concept of a "Login" is established when the user provides
 * a PIN that will successfully unwrap the private data in the
 * PKCS#12 file downloaded earlier when C_InitToken was called.
 * If the PKCS#12 file is successfully opened, then the user
 * is considered "logged in" and may use the private key and
 * certificate to initiate secure communications with the KMS.
 *
 * CHANGE PIN
 * ==========
 * The C_SetPIN interface may be used to change the passphrase
 * on the PKCS#12 file and thus effectively change the passphrase
 * for the token itself (even though the wrapped private key and
 * certificate do not change).
 *
 * KEY STORAGE
 * ===========
 * Keys generated in the KMS are always kept securely in the KMS.
 * The local token area contains only a list of CKA_LABEL values
 * for all successfully created keys, no sensitive key data
 * is stored on the client system.  When a key is "destroyed", the
 * local references to that key's label is removed and it is no
 * longer visible to the token provider.
 *
 * NOTE: The KMS itself does not have an interface for destroying
 * keys, it only allows for the keys to be disassociated from
 * a particular "DataUnit". Key labels should not be re-used.
 */
#pragma init(kms_init)
#pragma fini(kms_fini)

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

boolean_t kms_initialized = B_FALSE;
static pid_t kms_pid = 0;


/* protects kms_initialized and entrance to C_Initialize/Finalize */
static pthread_mutex_t globalmutex = PTHREAD_MUTEX_INITIALIZER;

ses_to_be_freed_list_t ses_delay_freed;
object_to_be_freed_list_t obj_delay_freed;
kms_elem_t **kms_mechhash;	/* Hash table for kCF mech numbers */

static void kms_finalize_common();
static void kms_cleanup_library();
static void kms_init();
static void kms_fini();
static void kms_fork_prepare();
static void kms_fork_after();

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

	if (kms_initialized) {
		if (initialize_pid == kms_pid) {
			/*
			 * This process has called C_Initialize already
			 */
			(void) pthread_mutex_unlock(&globalmutex);
			return (CKR_CRYPTOKI_ALREADY_INITIALIZED);
		} else {
			/*
			 * A fork has happened and the child is
			 * reinitializing.  Do a kms_cleanup_library to close
			 * out any state from the parent, and then
			 * continue on.
			 */
			kms_cleanup_library();
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

	/* Create the hash table */
	kms_mechhash = calloc(KMECH_HASHTABLE_SIZE, sizeof (void *));
	if (kms_mechhash == NULL) {
		(void) pthread_mutex_unlock(&globalmutex);
		return (CKR_HOST_MEMORY);
	}

	/* Initialize the slot table */
	rv = kms_slottable_init();
	if (rv != CKR_OK) {
		free(kms_mechhash);
		goto end;
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

	rv = KMS_Initialize();
	if (rv != CKR_OK) {
		free(kms_mechhash);
		goto end;
	}

	kms_initialized = B_TRUE;
	kms_pid = initialize_pid;

end:
	(void) pthread_mutex_unlock(&globalmutex);

	return (CKR_OK);
}

/*
 * C_Finalize is a wrapper around kms_finalize_common. The
 * globalmutex should be locked by C_Finalize().
 */
CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
	(void) pthread_mutex_lock(&globalmutex);

	if (!kms_initialized) {
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
	kms_delete_all_sessions(B_FALSE);

	kms_finalize_common();

	(void) pthread_mutex_unlock(&globalmutex);

	return (CKR_OK);
}

/*
 * kms_finalize_common() does the work for C_Finalize.  globalmutex
 * must be held before calling this function.
 */
static void
kms_finalize_common() {

	int i;
	kms_elem_t *elem, *next;
	kms_object_t *delay_free_obj, *tmpo;
	kms_session_t *delay_free_ses, *tmps;

	cleanup_slottable();
	/* Walk the hash table and free all entries */
	for (i = 0; i < KMECH_HASHTABLE_SIZE; i++) {
		elem = kms_mechhash[i];
		while (elem != NULL) {
			next = elem->knext;
			free(elem);
			elem = next;
		}
	}

	free(kms_mechhash);

	kms_mechhash = NULL;
	kms_initialized = B_FALSE;
	kms_pid = 0;

	/*
	 * free all entries in the delay_freed list
	 */
	delay_free_obj = obj_delay_freed.first;
	while (delay_free_obj != NULL) {
		tmpo = delay_free_obj->next;
		free(delay_free_obj);
		delay_free_obj = tmpo;
	}
	obj_delay_freed.count = 0;
	obj_delay_freed.first = NULL;
	obj_delay_freed.last = NULL;
	(void) pthread_mutex_destroy(&obj_delay_freed.obj_to_be_free_mutex);

	delay_free_ses = ses_delay_freed.first;
	while (delay_free_ses != NULL) {
		tmps = delay_free_ses->next;
		free(delay_free_ses);
		delay_free_ses = tmps;
	}
	ses_delay_freed.count = 0;
	ses_delay_freed.first = NULL;
	ses_delay_freed.last = NULL;
	(void) pthread_mutex_destroy(&ses_delay_freed.ses_to_be_free_mutex);
}

/*
 * This function cleans up all the resources in the library (user space only)
 */
static void
kms_cleanup_library()
{
	kms_slot_t *pslot = get_slotinfo();

	if (pslot)
		kms_cleanup_pri_objects_in_slot(pslot, NULL);

	/*
	 * Delete all the sessions for each slot and release the allocated
	 * resources from the library.  The boolean argument TRUE indicates
	 * that we only wants to clean up the resource in the library only.
	 * We don't want to clean up the corresponding kernel part of
	 * resources, because they are used by the parent process still.
	 */
	kms_delete_all_sessions(B_TRUE);

	kms_finalize_common();
}

static void
kms_init()
{
	(void) pthread_atfork(kms_fork_prepare, kms_fork_after,
	    kms_fork_after);
}

/*
 * kms_fini() function required to make sure complete cleanup
 * is done if pkcs11_kms is ever unloaded without
 * a C_Finalize() call.
 */
static void
kms_fini()
{
	(void) pthread_mutex_lock(&globalmutex);

	(void) KMS_Finalize();

	/* if we're not initilized, do not attempt to finalize */
	if (!kms_initialized) {
		(void) pthread_mutex_unlock(&globalmutex);
		return;
	}

	kms_cleanup_library();

	(void) pthread_mutex_unlock(&globalmutex);
}

CK_RV
C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!kms_initialized)
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
 *    kms_acquire_all_slots_mutexes()
 * 3. obj_delay_freed.obj_to_be_free_mutex;
 * 4. ses_delay_freed.ses_to_be_free_mutex
 */
void
kms_fork_prepare()
{
	(void) pthread_mutex_lock(&globalmutex);
	if (kms_initialized) {
		kms_acquire_all_slots_mutexes();
		(void) pthread_mutex_lock(
		    &obj_delay_freed.obj_to_be_free_mutex);
		(void) pthread_mutex_lock(
		    &ses_delay_freed.ses_to_be_free_mutex);
	}
}

/*
 * Release in opposite order to kms_fork_prepare().
 * Function is used for parent and child.
 */
void
kms_fork_after()
{
	if (kms_initialized) {
		(void) pthread_mutex_unlock(
		    &ses_delay_freed.ses_to_be_free_mutex);
		(void) pthread_mutex_unlock(
		    &obj_delay_freed.obj_to_be_free_mutex);
		kms_release_all_slots_mutexes();
	}
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
