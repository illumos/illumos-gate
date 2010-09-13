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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <errno.h>
#include <string.h>
#include <security/cryptoki.h>
#include "kmsGlobal.h"
#include "kmsObject.h"
#include "kmsSession.h"

CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
{

	CK_RV rv;
	kms_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if ((pTemplate == NULL) || (ulCount == 0) ||
	    (phObject == NULL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Create a new object. */
	rv = kms_add_object(pTemplate, ulCount, phObject, session_p);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

CK_RV
C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject)
{

	CK_RV rv;
	kms_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	kms_object_t *old_object;
	kms_object_t *new_object = NULL;
	int i;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Check arguments */
	if (((ulCount > 0) && (pTemplate == NULL)) ||
	    (phNewObject == NULL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hObject, old_object, rv);
	if (rv != CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	(void) pthread_mutex_lock(&old_object->object_mutex);

	if (old_object->is_lib_obj) {
		/*
		 * Copy the old object to a new object.
		 * The 3rd argument with TRUE value indicates that
		 * everything in the object will be duplicated.
		 */
		rv = kms_copy_object(old_object, &new_object, B_TRUE,
		    session_p);
		(void) pthread_mutex_unlock(&old_object->object_mutex);
		if ((rv != CKR_OK) || (new_object == NULL)) {
			/*
			 * Most likely we ran out of space.
			 * Decrement the session reference count.
			 * We do not hold the session lock.
			 */
			OBJ_REFRELE(old_object);
			REFRELE(session_p, ses_lock_held);
			return (rv);
		}

		new_object->is_lib_obj = B_TRUE;

		/* Modify the object attribute if requested */
		for (i = 0; i < ulCount; i++) {
			/* Set the requested attribute into the new object. */
			rv = kms_set_attribute(new_object, &pTemplate[i],
			    B_TRUE);

			if (rv != CKR_OK) {
				kms_cleanup_object(new_object);
				OBJ_REFRELE(old_object);
				REFRELE(session_p, ses_lock_held);
				return (rv);
			}
		}

		/* Insert the new object into this session's object list. */
		kms_add_object_to_session(new_object, session_p);

		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		OBJ_REFRELE(old_object);
		REFRELE(session_p, ses_lock_held);

		/* set handle of the new object */
		*phNewObject = (CK_ULONG)new_object;

	}

	return (rv);

failed_cleanup:
	if (new_object != NULL) {
		(void) kms_free_object(new_object);
	}

	OBJ_REFRELE(old_object);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}

CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;
	kms_object_t *object_p;
	kms_session_t *session_p = (kms_session_t *)(hSession);
	kms_slot_t	*pslot;
	boolean_t ses_lock_held = B_FALSE;
	CK_SESSION_HANDLE creating_session;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * The reason that we don't call handle2session is because
	 * the argument hSession may not be the creating_session of
	 * the object to be destroyed, and we want to avoid the lock
	 * contention. The handle2session will be called later for
	 * the creating_session.
	 */
	if ((session_p == NULL) ||
	    (session_p->magic_marker != KMSTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}
	/* Obtain the object pointer without incrementing reference count. */
	HANDLE2OBJECT_DESTROY(hObject, object_p, rv);
	if (rv != CKR_OK) {
		return (rv);
	}

	/* Only session objects can be destroyed at a read-only session. */
	if ((session_p->ses_RO) &&
	    (object_p->bool_attr_mask & TOKEN_BOOL_ON)) {
		return (CKR_SESSION_READ_ONLY);
	}


	/*
	 * If the object is a session object, obtain the session handle
	 * which object belongs to.  For a token object, we will use the
	 * session handle from the caller, because the session used to
	 * create the token object may no longer exist.
	 */
	if (!(object_p->bool_attr_mask & TOKEN_BOOL_ON))
		creating_session = object_p->session_handle;
	else
		creating_session = hSession;

	rv = handle2session(creating_session, &session_p);
	if (rv != CKR_OK) {
		return (rv);
	}

	/*
	 * Set OBJECT_IS_DELETING flag so any access to this
	 * object will be rejected.
	 */
	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->obj_delete_sync & OBJECT_IS_DELETING) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		REFRELE(session_p, ses_lock_held);
		return (CKR_OBJECT_HANDLE_INVALID);
	}
	object_p->obj_delete_sync |= OBJECT_IS_DELETING;
	(void) pthread_mutex_unlock(&object_p->object_mutex);

	if (object_p->bool_attr_mask & TOKEN_BOOL_ON) {
		/*
		 * The first FALSE boolean argument indicates that the caller
		 * does not hold the slot lock.  The second FALSE boolean
		 * argument indicates that the caller wants to clean up the
		 * object in the HW provider also.
		 */
		pslot = get_slotinfo();
		rv = kms_delete_token_object(pslot, session_p, object_p,
		    B_FALSE, B_FALSE);
	} else {
		/*
		 * The first FALSE boolean argument indicates that the caller
		 * does not hold the session lock.  The second FALSE boolean
		 * argument indicates that the caller wants to clean the object
		 * in the HW provider also.
		 */
		rv = kms_delete_object(session_p, object_p, B_FALSE,
		    B_FALSE);
	}
	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	REFRELE(session_p, ses_lock_held);
	return (rv);
}

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{

	CK_RV rv = CKR_OK, rv1 = CKR_OK;
	kms_object_t *object_p;
	kms_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	int i;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if ((pTemplate == NULL) || (ulCount == 0))
		return (CKR_ARGUMENTS_BAD);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hObject, object_p, rv);
	if (rv != CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Acquire the lock on the object. */
	(void) pthread_mutex_lock(&object_p->object_mutex);

	/*
	 * The object was created in the library. The library
	 * contains the value information of each attribute.
	 */
	for (i = 0; i < ulCount; i++) {
		/*
		 * Get the value of each attribute in the template.
		 * (We must process EVERY attribute in the template.)
		 */
		rv = kms_get_attribute(object_p, &pTemplate[i]);
		if (rv != CKR_OK)
			rv1 = rv;
	}
	(void) pthread_mutex_unlock(&object_p->object_mutex);

clean_exit:
	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(object_p);
	REFRELE(session_p, ses_lock_held);
	rv = rv1;
	return (rv);
}

CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	kms_object_t *object_p;
	kms_object_t *new_object = NULL;
	kms_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	int i;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if ((pTemplate == NULL) || (ulCount == 0))
		return (CKR_ARGUMENTS_BAD);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hObject, object_p, rv);
	if (rv != CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* lock the object */
	(void) pthread_mutex_lock(&object_p->object_mutex);

	/*
	 * If the object was created in the HW provider, changing its
	 * attributes' values need to be done in the provider too.
	 */
	if (!object_p->is_lib_obj) {

		/* Cannot modify a token object with a READ-ONLY session */
		if (session_p->ses_RO &&
		    (object_p->bool_attr_mask & TOKEN_BOOL_ON)) {
			(void) pthread_mutex_unlock(&object_p->object_mutex);
			rv = CKR_SESSION_READ_ONLY;
			goto clean_exit;
		}
	}

	/*
	 * if we come here, the object must have been created in the
	 * library.  The work will be done completely in the library.
	 *
	 * Copy the old object to a new object. We work on the copied
	 * version because in case of error we still keep the old one
	 * intact.
	 */
	rv = kms_copy_object(object_p, &new_object, B_FALSE, NULL);
	(void) pthread_mutex_unlock(&object_p->object_mutex);
	if ((rv != CKR_OK) || (new_object == NULL)) {
		/*
		 * Most likely we ran out of space.
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		goto clean_exit;
	}

	for (i = 0; i < ulCount; i++) {
		/* Set the requested attribute into the new object. */
		rv = kms_set_attribute(new_object, &pTemplate[i], B_FALSE);

		if (rv != CKR_OK) {
			kms_cleanup_object(new_object);
			goto clean_exit;
		}
	}

	/*
	 * We've successfully set all the requested attributes.
	 * Merge the new object with the old object, then destory
	 * the new one. The reason to do the merging is because we
	 * have to keep the original object handle (address of object).
	 */
	(void) pthread_mutex_lock(&object_p->object_mutex);
	kms_merge_object(object_p, new_object);
	(void) pthread_mutex_unlock(&object_p->object_mutex);

clean_exit:
	if (new_object != NULL)
		(void) kms_free_object(new_object);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(object_p);
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize)
{

	CK_RV rv = CKR_OK;
	kms_object_t *object_p;
	kms_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Check if pulSize is valid */
	if (pulSize == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hObject, object_p, rv);
	if (rv != CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Acquire the lock on the object. */
	(void) pthread_mutex_lock(&object_p->object_mutex);

	rv = kms_get_object_size(object_p, pulSize);

	(void) pthread_mutex_unlock(&object_p->object_mutex);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(object_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE sh, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	CK_RV		rv;
	kms_session_t	*session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Check the arguments */
	if ((ulCount > 0) && (pTemplate == NULL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(sh, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Check to see if find operation is already active */
	if (session_p->find_objects.flags & CRYPTO_OPERATION_ACTIVE) {
		/* decrement the session count, and unlock the mutex */
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_ACTIVE);
	} else {
		/*
		 * This active flag will remain ON until application calls
		 * C_FindObjectsFinal.
		 */
		session_p->find_objects.flags = CRYPTO_OPERATION_ACTIVE;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	/*
	 * If the KMS provider supports object creation, we call the
	 * CRYPTO_OBJECT_FIND_INIT to initialize object finding.
	 * Otherwise, all the objects are created in the library and we
	 * do the find objects solely in the library.
	 */
	rv = kms_find_objects_init(session_p, pTemplate, ulCount);
	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->find_objects.flags = 0;
		(void) pthread_mutex_unlock(&session_p->session_mutex);
	}
	/* decrement the session count, and unlock the mutex */
	REFRELE(session_p, ses_lock_held);
	return (rv);
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv = CKR_OK;
	kms_slot_t		*pslot = NULL;
	kms_session_t	*session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* check for invalid arguments */
	if (((phObject == NULL) && (ulMaxObjectCount != 0)) ||
	    (pulObjectCount == NULL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	if (ulMaxObjectCount == 0) {
		/* don't need to do anything, just return */
		*pulObjectCount = 0;
		return (CKR_OK);
	}

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(sh, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Acquire the slot lock */
	pslot = get_slotinfo();
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Check to see if find operation is active */
	if (!(session_p->find_objects.flags & CRYPTO_OPERATION_ACTIVE)) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
		goto clean_exit;
	}

	/*
	 * Similar to C_FindObjectInit(), if the KMS provider supports object
	 * creation, we need to find objects.
	 * Otherwise, all the objects are created in the library and we do
	 * the find objects solely in the library.
	 */

	rv = kms_find_objects(session_p, phObject,
	    ulMaxObjectCount, pulObjectCount);

clean_exit:
	/* decrement the session count, and release the session lock */
	REFRELE(session_p, ses_lock_held);

	/* release the slot lock */
	if (pslot)
		(void) pthread_mutex_unlock(&pslot->sl_mutex);

	return (rv);
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE sh)
{
	kms_session_t	*session_p;
	CK_RV rv;
	boolean_t ses_lock_held = B_FALSE;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(sh, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Check to see if find operation is active */
	if (!(session_p->find_objects.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * Similar to C_FindObjectInit(), if the KMS provider supports object
	 * creation, we need to finalize the search on the KMS side.
	 */
	kms_find_objects_final(session_p);

	/* decrement the session count, and release the lock */
	REFRELE(session_p, ses_lock_held);
	return (rv);
}
