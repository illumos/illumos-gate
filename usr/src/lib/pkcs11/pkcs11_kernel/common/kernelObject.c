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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelObject.h"
#include "kernelSession.h"
#include <errno.h>
#include <string.h>
#include <cryptoutil.h>

CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kernel_initialized)
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
	rv = kernel_add_object(pTemplate, ulCount, phObject, session_p);

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
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	kernel_object_t *old_object;
	kernel_object_t *new_object = NULL;
	crypto_object_copy_t  object_copy;
	CK_BBOOL is_pri_obj = FALSE;
	CK_BBOOL is_token_obj = FALSE;
	kernel_slot_t	*pslot;
	int i, r;

	if (!kernel_initialized)
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
		rv = kernel_copy_object(old_object, &new_object, B_TRUE,
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
			rv = kernel_set_attribute(new_object, &pTemplate[i],
			    B_TRUE, session_p);

			if (rv != CKR_OK) {
				kernel_cleanup_object(new_object);

				/*
				 * Decrement the session reference count.
				 * We do not hold the session lock.
				 */
				OBJ_REFRELE(old_object);
				REFRELE(session_p, ses_lock_held);
				return (rv);
			}
		}

		/* Insert the new object into this session's object list. */
		kernel_add_object_to_session(new_object, session_p);

		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		OBJ_REFRELE(old_object);
		REFRELE(session_p, ses_lock_held);

		/* set handle of the new object */
		*phNewObject = (CK_ULONG)new_object;

	} else {
		/*
		 * The old object was created in the HW provider.
		 * First, create an object wrapper in library.
		 */
		new_object = calloc(1, sizeof (kernel_object_t));
		if (new_object == NULL) {
			(void) pthread_mutex_unlock(&old_object->object_mutex);
			OBJ_REFRELE(old_object);
			REFRELE(session_p, ses_lock_held);
			return (CKR_HOST_MEMORY);
		}

		/* Call CRYPTO_OBJECT_COPY ioctl to get a new object. */
		object_copy.oc_session = session_p->k_session;
		object_copy.oc_handle = old_object->k_handle;
		(void) pthread_mutex_unlock(&old_object->object_mutex);
		object_copy.oc_count = ulCount;
		object_copy.oc_new_attributes = NULL;
		if (ulCount > 0) {
			rv = process_object_attributes(pTemplate, ulCount,
			    &object_copy.oc_new_attributes, &is_token_obj);
			if (rv != CKR_OK) {
				goto failed_cleanup;
			}
		}

		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_COPY,
		    &object_copy)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    object_copy.oc_return_value);
		}

		/* Free the attributes' space allocated for ioctl */
		free_object_attributes(object_copy.oc_new_attributes, ulCount);

		if (rv != CKR_OK) {
			goto failed_cleanup;
		}

		/*
		 * Store the kernel object handle in the object wrapper and
		 * get the CKA_PRIVATE value of the new object.
		 */
		new_object->k_handle = object_copy.oc_new_handle;
		rv = get_cka_private_value(session_p, new_object->k_handle,
		    &is_pri_obj);
		if (rv != CKR_OK) {
			goto failed_cleanup;
		}

		/*
		 * Initialize other field of the object wrapper.
		 */
		new_object->is_lib_obj = B_FALSE;
		new_object->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
		new_object->session_handle = (CK_SESSION_HANDLE)session_p;
		(void) pthread_mutex_init(&new_object->object_mutex, NULL);

		if (is_pri_obj)
			new_object->bool_attr_mask |= PRIVATE_BOOL_ON;
		else
			new_object->bool_attr_mask &= ~PRIVATE_BOOL_ON;

		if (is_token_obj)
			new_object->bool_attr_mask |= TOKEN_BOOL_ON;
		else
			new_object->bool_attr_mask &= ~TOKEN_BOOL_ON;

		/*
		 * Add the new copied object into the slot's token list
		 * or the session list.  We don't hold the slot lock.
		 */
		if (is_token_obj) {
			pslot = slot_table[session_p->ses_slotid];

			/*
			 * Decrement the session reference count.
			 * We do not hold the session lock.
			 */
			OBJ_REFRELE(old_object);
			REFRELE(session_p, ses_lock_held);

			/* Add into the slot token object list. */
			kernel_add_token_object_to_slot(new_object, pslot);
		} else {
			kernel_add_object_to_session(new_object, session_p);

			/*
			 * Decrement the session reference count.
			 * We do not hold the session lock.
			 */
			OBJ_REFRELE(old_object);
			REFRELE(session_p, ses_lock_held);
		}

		/* set handle of the new object */
		*phNewObject = (CK_ULONG)new_object;
	}

	return (rv);

failed_cleanup:
	if (new_object != NULL) {
		(void) free(new_object);
	}

	OBJ_REFRELE(old_object);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;
	kernel_object_t *object_p;
	kernel_session_t *session_p = (kernel_session_t *)(hSession);
	kernel_slot_t	*pslot;
	boolean_t ses_lock_held = B_FALSE;
	CK_SESSION_HANDLE creating_session;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * The reason that we don't call handle2session is because
	 * the argument hSession may not be the creating_session of
	 * the object to be destroyed, and we want to avoid the lock
	 * contention. The handle2session will be called later for
	 * the creating_session.
	 */
	if ((session_p == NULL) ||
	    (session_p->magic_marker != KERNELTOKEN_SESSION_MAGIC)) {
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
		pslot = slot_table[session_p->ses_slotid];
		rv = kernel_delete_token_object(pslot, session_p, object_p,
		    B_FALSE, B_FALSE);
	} else {
		/*
		 * The first FALSE boolean argument indicates that the caller
		 * does not hold the session lock.  The second FALSE boolean
		 * argument indicates that the caller wants to clean the object
		 * in the HW provider also.
		 */
		rv = kernel_delete_session_object(session_p, object_p, B_FALSE,
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
	kernel_object_t *object_p;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_object_get_attribute_value_t obj_get_attr;
	int i, r;

	if (!kernel_initialized)
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

	if (object_p->is_lib_obj) {
		/*
		 * The object was created in the library. The library
		 * contains the value information of each attribute.
		 */
		for (i = 0; i < ulCount; i++) {
			/*
			 * Get the value of each attribute in the template.
			 * (We must process EVERY attribute in the template.)
			 */
			rv = kernel_get_attribute(object_p, &pTemplate[i]);
			if (rv != CKR_OK)
				/* At least we catch some type of error. */
				rv1 = rv;
		}
		rv = rv1;
		(void) pthread_mutex_unlock(&object_p->object_mutex);
	} else {
		/*
		 * The object was created in HW provider, call ioctl to get
		 * the values of attributes.
		 */
		obj_get_attr.og_session = session_p->k_session;
		obj_get_attr.og_handle = object_p->k_handle;
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		obj_get_attr.og_count = ulCount;

		rv = process_object_attributes(pTemplate, ulCount,
		    &obj_get_attr.og_attributes, NULL);
		if (rv != CKR_OK) {
			goto clean_exit;
		}

		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE,
		    &obj_get_attr)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    obj_get_attr.og_return_value);
		}

		/*
		 * The error codes CKR_ATTRIBUTE_SENSITIVE,
		 * CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL
		 * do not denote true errors for this function. If a call
		 * returns any of these three values, then the call must
		 * nonetheless have processed every attribute in the
		 * template.  Every attribute in the template whose value
		 * can be returned will be returned.
		 */
		if ((rv == CKR_OK) ||
		    (rv == CKR_ATTRIBUTE_SENSITIVE) ||
		    (rv == CKR_ATTRIBUTE_TYPE_INVALID) ||
		    (rv == CKR_BUFFER_TOO_SMALL)) {
			rv1 = get_object_attributes(pTemplate, ulCount,
			    obj_get_attr.og_attributes);
			if (rv1 != CKR_OK) {
				rv = rv1;
			}
		}

		/* Free the attributes' allocated for the ioctl call. */
		free_object_attributes(obj_get_attr.og_attributes, ulCount);
	}

clean_exit:
	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	OBJ_REFRELE(object_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	kernel_object_t *object_p;
	kernel_object_t *new_object = NULL;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_object_set_attribute_value_t obj_set_attr;
	int i, r;

	if (!kernel_initialized)
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

		obj_set_attr.sa_session = session_p->k_session;
		obj_set_attr.sa_handle = object_p->k_handle;
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		obj_set_attr.sa_count = ulCount;
		rv = process_object_attributes(pTemplate, ulCount,
		    &obj_set_attr.sa_attributes, NULL);
		if (rv != CKR_OK) {
			goto clean_exit;
		}

		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_SET_ATTRIBUTE_VALUE,
		    &obj_set_attr)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    obj_set_attr.sa_return_value);
		}

		/* Free the attributes' space allocated for the ioctl call. */
		free_object_attributes(obj_set_attr.sa_attributes, ulCount);
		goto clean_exit;
	}

	/*
	 * if we come here, the object must have been created in the
	 * library.  The work will be done completely in the library.
	 *
	 * Copy the old object to a new object. We work on the copied
	 * version because in case of error we still keep the old one
	 * intact.
	 */
	rv = kernel_copy_object(object_p, &new_object, B_FALSE, NULL);
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
		rv = kernel_set_attribute(new_object, &pTemplate[i], B_FALSE,
		    session_p);

		if (rv != CKR_OK) {
			kernel_cleanup_object(new_object);
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
	kernel_merge_object(object_p, new_object);
	(void) pthread_mutex_unlock(&object_p->object_mutex);

clean_exit:
	if (new_object != NULL)
		(void) free(new_object);

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
	kernel_object_t *object_p;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_object_get_size_t obj_gs;
	int r;

	if (!kernel_initialized)
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

	if (!object_p->is_lib_obj) {
		/*
		 * The object was created in HW provider, call the
		 * CRYPTO_OBJECT_GET_SIZE ioctl.
		 */
		obj_gs.gs_session = session_p->k_session;
		obj_gs.gs_handle = object_p->k_handle;
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_GET_SIZE,
		    &obj_gs)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    obj_gs.gs_return_value);
		}

		if (rv == CKR_OK) {
			*pulSize = obj_gs.gs_size;
		}

	} else {
		rv = kernel_get_object_size(object_p, pulSize);
		(void) pthread_mutex_unlock(&object_p->object_mutex);
	}

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
	kernel_session_t	*session_p;
	boolean_t ses_lock_held = B_FALSE;
	kernel_slot_t *pslot;
	crypto_object_find_init_t obj_fi;
	int r;

	if (!kernel_initialized)
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


	/*
	 * If the HW provider supports object creation, we call the
	 * CRYPTO_OBJECT_FIND_INIT ioctl to initialize object finding.
	 * Otherwise, all the objects are created in the library and we
	 * do the find objects solely in the library.
	 */
	pslot = slot_table[session_p->ses_slotid];
	if (pslot->sl_func_list.fl_object_create) {
		obj_fi.fi_session = session_p->k_session;
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		ses_lock_held = B_FALSE;
		obj_fi.fi_count = ulCount;
		rv = process_object_attributes(pTemplate, ulCount,
		    &obj_fi.fi_attributes, NULL);
		if (rv == CKR_OK) {
			while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_FIND_INIT,
			    &obj_fi)) < 0) {
				if (errno != EINTR)
					break;
			}
			if (r < 0) {
				rv = CKR_FUNCTION_FAILED;
			} else {
				rv = crypto2pkcs11_error_number(
				    obj_fi.fi_return_value);
			}
		}

		/* Free the attributes' space allocated for the ioctl call. */
		free_object_attributes(obj_fi.fi_attributes, ulCount);

	} else {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		ses_lock_held = B_FALSE;
		rv = kernel_find_objects_init(session_p,  pTemplate, ulCount);
	}

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
	kernel_slot_t		*pslot;
	kernel_session_t	*session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_object_find_update_t obj_fu;
	int r;

	if (!kernel_initialized)
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
	pslot = slot_table[session_p->ses_slotid];
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
	 * Similar to C_FindObjectInit(), if the HW provider supports object
	 * creation, we call the respective ioctl to find objects.
	 * Otherwise, all the objects are created in the library and we do
	 * the find objects solely in the library.
	 */
	if (pslot->sl_func_list.fl_object_create) {
		obj_fu.fu_session = session_p->k_session;
		obj_fu.fu_max_count = ulMaxObjectCount;
		obj_fu.fu_handles = (char *)calloc(1,
		    ulMaxObjectCount * sizeof (crypto_object_id_t));
		if (obj_fu.fu_handles == NULL) {
			rv = CKR_HOST_MEMORY;
			goto clean_exit;
		}

		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_FIND_UPDATE,
		    &obj_fu)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    obj_fu.fu_return_value);
		}

		if (rv == CKR_OK) {
			rv = process_found_objects(session_p, phObject,
			    pulObjectCount, obj_fu);
		}
		free(obj_fu.fu_handles);

	} else {

		kernel_find_objects(session_p, phObject, ulMaxObjectCount,
		    pulObjectCount);
		rv = CKR_OK;
	}

clean_exit:
	/* decrement the session count, and release the session lock */
	REFRELE(session_p, ses_lock_held);

	/* release the slot lock */
	(void) pthread_mutex_unlock(&pslot->sl_mutex);

	return (rv);
}


CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE sh)
{

	kernel_session_t	*session_p;
	CK_RV rv;
	boolean_t ses_lock_held = B_FALSE;
	kernel_slot_t *pslot;
	crypto_object_find_final_t obj_ff;
	int r;

	if (!kernel_initialized)
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
	 * Similar to C_FindObjectInit(), if the HW provider supports object
	 * creation, we need to call the CRYPTO_OBJECT_FIND_FINAL ioctl.
	 */
	pslot = slot_table[session_p->ses_slotid];
	if (pslot->sl_func_list.fl_object_create) {
		obj_ff.ff_session = session_p->k_session;
		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_FIND_FINAL,
		    &obj_ff)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    obj_ff.ff_return_value);
		}

		/* only need to reset find_objects.flags */
		if (rv == CKR_OK) {
			session_p->find_objects.flags = 0;
		}

	} else {
		/*
		 * The find object operations were done in the library, we
		 * need to cleanup find_objects context.
		 */
		kernel_find_objects_final(session_p);
		rv = CKR_OK;
	}

	/* decrement the session count, and release the lock */
	REFRELE(session_p, ses_lock_held);
	return (rv);
}
