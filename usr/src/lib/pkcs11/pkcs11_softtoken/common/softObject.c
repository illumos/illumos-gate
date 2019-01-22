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
 */

#include <pthread.h>
#include <stdlib.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softObject.h"
#include "softSession.h"
#include "softKeystore.h"
#include "softKeystoreUtil.h"


CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
{

	CK_RV rv;
	soft_session_t *session_p;
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

	if ((pTemplate == NULL) || (ulCount == 0) ||
	    (phObject == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Create a new object. */
	rv = soft_add_object(pTemplate, ulCount, phObject, session_p);

clean_exit:
	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	SES_REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject)
{

	CK_RV rv;
	soft_session_t *session_p;
	boolean_t lock_held = B_FALSE;
	soft_object_t *old_object, *new_object = NULL;
	ulong_t i;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Check arguments */
	if (((ulCount > 0) && (pTemplate == NULL)) ||
	    (phNewObject == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hObject, old_object, rv);
	if (rv != CKR_OK) {
		goto clean_exit;
	}

	/*
	 * Copy the old object to a new object.
	 * The 3rd argument with SOFT_COPY_OBJ value indicates that
	 * everything in the object will be duplicated for C_CopyObject.
	 * The 4th argument has the session pointer that will be
	 * saved in the new copy of the session object.
	 */
	(void) pthread_mutex_lock(&old_object->object_mutex);
	rv = soft_copy_object(old_object, &new_object, SOFT_COPY_OBJECT,
	    session_p);

	if ((rv != CKR_OK) || (new_object == NULL)) {
		/* Most likely we ran out of space. */
		(void) pthread_mutex_unlock(&old_object->object_mutex);
		goto clean_exit1;
	}

	/* No need to hold the lock on the old object. */
	(void) pthread_mutex_unlock(&old_object->object_mutex);

	/* Modifiy the objects if requested */
	for (i = 0; i < ulCount; i++) {
		/* Set the requested attribute into the new object. */
		rv = soft_set_attribute(new_object, &pTemplate[i], B_TRUE);
		if (rv != CKR_OK) {
			goto fail;
		}
	}

	rv = soft_pin_expired_check(new_object);
	if (rv != CKR_OK) {
		goto fail;
	}

	/*
	 * Does the new object violate the creation rule or access rule?
	 */
	rv = soft_object_write_access_check(session_p, new_object);
	if (rv != CKR_OK) {
		goto fail;
	}

	/*
	 * If the new object is a token object, it will be added
	 * to token object list and write to disk.
	 */
	if (IS_TOKEN_OBJECT(new_object)) {
		new_object->version = 1;
		/*
		 * Write to the keystore file.
		 */
		rv = soft_put_object_to_keystore(new_object);
		if (rv != CKR_OK) {
			goto fail;
		}

		new_object->session_handle = (CK_SESSION_HANDLE)NULL;
		/*
		 * Add the newly created token object to the global
		 * token object list in the slot struct.
		 */
		soft_add_token_object_to_slot(new_object);
		OBJ_REFRELE(old_object);
		SES_REFRELE(session_p, lock_held);
		*phNewObject = (CK_ULONG)new_object;

		return (CKR_OK);
	}

	/* Insert new object into this session's object list */
	soft_add_object_to_session(new_object, session_p);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(old_object);
	SES_REFRELE(session_p, lock_held);

	/* set handle of the new object */
	*phNewObject = (CK_ULONG)new_object;

	return (rv);

fail:
	soft_cleanup_object(new_object);
	free(new_object);

clean_exit1:
	OBJ_REFRELE(old_object);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{

	CK_RV rv;
	soft_object_t *object_p;
	soft_session_t *session_p = (soft_session_t *)(hSession);
	boolean_t lock_held = B_FALSE;
	CK_SESSION_HANDLE creating_session;


	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * The reason that we don't call handle2session is because
	 * the argument hSession may not be the creating_session of
	 * the object to be destroyed, and we want to avoid the lock
	 * contention. The handle2session will be called later for
	 * the creating_session.
	 */
	if ((session_p == NULL) ||
	    (session_p->magic_marker != SOFTTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	/* Obtain the object pointer. */
	HANDLE2OBJECT_DESTROY(hObject, object_p, rv);
	if (rv != CKR_OK) {
		return (rv);
	}

	/* Obtain the session handle which object belongs to. */
	creating_session = object_p->session_handle;

	if (creating_session == 0) {
		/*
		 * This is a token object to be deleted.
		 * For token object, there is no creating session concept,
		 * therefore, creating_session is always NULL.
		 */
		rv = soft_pin_expired_check(object_p);
		if (rv != CKR_OK) {
			return (rv);
		}

		/* Obtain the session pointer just for validity check. */
		rv = handle2session(hSession, &session_p);
		if (rv != CKR_OK) {
			return (rv);
		}

		rv = soft_object_write_access_check(session_p, object_p);
		if (rv != CKR_OK) {
			SES_REFRELE(session_p, lock_held);
			return (rv);
		}

		/*
		 * Set OBJECT_IS_DELETING flag so any access to this
		 * object will be rejected.
		 */
		(void) pthread_mutex_lock(&object_p->object_mutex);
		if (object_p->obj_delete_sync & OBJECT_IS_DELETING) {
			(void) pthread_mutex_unlock(&object_p->object_mutex);
			SES_REFRELE(session_p, lock_held);
			return (CKR_OBJECT_HANDLE_INVALID);
		}
		object_p->obj_delete_sync |= OBJECT_IS_DELETING;
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		SES_REFRELE(session_p, lock_held);

		/*
		 * Delete a token object by calling soft_delete_token_object()
		 * with the second argument B_TRUE indicating to delete the
		 * object from keystore and the third argument B_FALSE
		 * indicating that the caller does not hold the slot mutex.
		 */
		soft_delete_token_object(object_p, B_TRUE, B_FALSE);
		return (CKR_OK);
	}

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
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
		SES_REFRELE(session_p, lock_held);
		return (CKR_OBJECT_HANDLE_INVALID);
	}
	object_p->obj_delete_sync |= OBJECT_IS_DELETING;
	(void) pthread_mutex_unlock(&object_p->object_mutex);

	/*
	 * Delete an object by calling soft_delete_object()
	 * with a FALSE boolean argument indicating that
	 * the caller does not hold the session lock.
	 */
	soft_delete_object(session_p, object_p, B_FALSE, B_FALSE);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	SES_REFRELE(session_p, lock_held);

	return (rv);
}


CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{

	CK_RV rv = CKR_OK, rv1 = CKR_OK;
	soft_object_t *object_p;
	soft_session_t *session_p;
	boolean_t lock_held = B_FALSE;
	ulong_t i;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pTemplate == NULL) || (ulCount == 0)) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hObject, object_p, rv);
	if (rv != CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

	if (IS_TOKEN_OBJECT(object_p)) {

		rv = soft_keystore_load_latest_object(object_p);
		if (rv != CKR_OK) {
			OBJ_REFRELE(object_p);
			SES_REFRELE(session_p, lock_held);
			return (rv);
		}
	}

	/* Acquire the lock on the object. */
	(void) pthread_mutex_lock(&object_p->object_mutex);

	for (i = 0; i < ulCount; i++) {
		/*
		 * Get the value of each attribute in the template.
		 * (We must process EVERY attribute in the template.)
		 */
		rv = soft_get_attribute(object_p, &pTemplate[i]);
		if (rv != CKR_OK)
			/* At least we catch some type of error. */
			rv1 = rv;
	}

	/* Release the object lock */
	(void) pthread_mutex_unlock(&object_p->object_mutex);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(object_p);
	SES_REFRELE(session_p, lock_held);

	rv = rv1;
	return (rv);
}


CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	soft_object_t *object_p;
	soft_object_t *new_object = NULL;
	soft_session_t *session_p;
	boolean_t lock_held = B_FALSE;
	ulong_t i;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pTemplate == NULL) || (ulCount == 0)) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hObject, object_p, rv);
	if (rv != CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

	if (object_p->bool_attr_mask & NOT_MODIFIABLE_BOOL_ON) {
		rv = CKR_ATTRIBUTE_READ_ONLY;
		goto fail_1;
	}

	/*
	 * Start working on the object, so we need to set the write lock so that
	 * no one can write to it but still can read it.
	 */
	if (IS_TOKEN_OBJECT(object_p)) {
		rv = soft_keystore_load_latest_object(object_p);
		if (rv != CKR_OK) {
			goto fail_1;
		}
	}

	/*
	 * Copy the old object to a new object. We work on the copied
	 * version because in case of error we still keep the old one
	 * intact.
	 * The 3rd argument with SOFT_SET_ATTR_VALUE value indicates that
	 * not everything will be duplicated for C_SetAttributeValue.
	 * Information not duplicated are those attributes that are not
	 * modifiable.
	 */
	(void) pthread_mutex_lock(&object_p->object_mutex);
	rv = soft_copy_object(object_p, &new_object, SOFT_SET_ATTR_VALUE, NULL);

	if ((rv != CKR_OK) || (new_object == NULL)) {
		/* Most likely we ran out of space. */
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		goto fail_1;
	}

	/*
	 * No need to hold the lock on the old object, because we
	 * will be working on the new scratch object.
	 */
	(void) pthread_mutex_unlock(&object_p->object_mutex);

	rv = soft_object_write_access_check(session_p, new_object);
	if (rv != CKR_OK) {
		goto fail;
	}

	for (i = 0; i < ulCount; i++) {
		/* Set the requested attribute into the new object. */
		rv = soft_set_attribute(new_object, &pTemplate[i], B_FALSE);

		if (rv != CKR_OK) {
			goto fail;
		}
	}

	/*
	 * We've successfully set all the requested attributes.
	 * Merge the new object with the old object, then destory
	 * the new one. The reason to do the merging is because we
	 * have to keep the original object handle (address of object).
	 */
	(void) pthread_mutex_lock(&object_p->object_mutex);

	soft_merge_object(object_p, new_object);

	/*
	 * The object has been modified, so we write it back to keystore.
	 */
	if (IS_TOKEN_OBJECT(object_p)) {
		object_p->version++;
		rv = soft_modify_object_to_keystore(object_p);
	}

	(void) pthread_mutex_unlock(&object_p->object_mutex);
	free(new_object);

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(object_p);
	SES_REFRELE(session_p, lock_held);
	return (rv);

fail:
	soft_cleanup_object(new_object);
	free(new_object);

fail_1:
	OBJ_REFRELE(object_p);
	SES_REFRELE(session_p, lock_held);

	return (rv);
}

/*ARGSUSED*/
CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize)
{
	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE sh, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(sh, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Check the arguments */
	if ((ulCount > 0) && (pTemplate == NULL)) {
		/* decrement the session count, we do not hold the lock */
		lock_held = B_FALSE;
		SES_REFRELE(session_p, lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Check to see if find operation is already active */
	if (session_p->find_objects.flags & CRYPTO_OPERATION_ACTIVE) {
		/* decrement the session count, and unlock the mutex */
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_ACTIVE);
	} else {
		/*
		 * This active flag will remain ON until application calls
		 * C_FindObjectsFinal.
		 */
		session_p->find_objects.flags = CRYPTO_OPERATION_ACTIVE;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_find_objects_init(session_p,  pTemplate, ulCount);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->find_objects.flags = 0;
		(void) pthread_mutex_unlock(&session_p->session_mutex);
	}

	/* decrement the session count, and unlock the mutex */
	lock_held = B_FALSE;
	SES_REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE sh,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount)
{
	soft_session_t	*session_p;
	CK_RV rv = CKR_OK;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(sh, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* check for invalid arguments */
	if (((phObject == NULL) && (ulMaxObjectCount != 0)) ||
	    (pulObjectCount == NULL)) {
		/* decrement the session count, we do not hold the lock */
		lock_held = B_FALSE;
		SES_REFRELE(session_p, lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	if (ulMaxObjectCount == 0) {
		/* don't need to do anything, just return */
		*pulObjectCount = 0;
		/* decrement the session count, we do not hold the lock */
		lock_held = B_FALSE;
		SES_REFRELE(session_p, lock_held);
		return (CKR_OK);
	}

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Check to see if find operation is active */
	if (!(session_p->find_objects.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	soft_find_objects(session_p, phObject, ulMaxObjectCount,
	    pulObjectCount);

	/* decrement the session count, and release the lock */
	SES_REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE sh)
{
	soft_session_t	*session_p;
	CK_RV rv;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
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

	/* Check to see if find operation is active */
	if (!(session_p->find_objects.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	soft_find_objects_final(session_p);

	/* decrement the session count, and release the lock */
	SES_REFRELE(session_p, lock_held);
	return (rv);
}
