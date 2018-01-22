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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "kernelGlobal.h"
#include "kernelObject.h"
#include "kernelSession.h"
#include "kernelSlot.h"

/*
 * Add an object to the session's object list.
 *
 * This function will acquire the lock on the session, and release
 * that lock after adding the object to the session's object list.
 */
void
kernel_add_object_to_session(kernel_object_t *objp, kernel_session_t *sp)
{
	/* Acquire the session lock. */
	(void) pthread_mutex_lock(&sp->session_mutex);

	/* Insert the new object in front of session's object list. */
	if (sp->object_list == NULL) {
		sp->object_list = objp;
		objp->next = NULL;
		objp->prev = NULL;
	} else {
		sp->object_list->prev = objp;
		objp->next = sp->object_list;
		objp->prev = NULL;
		sp->object_list = objp;
	}

	/* Release the session lock. */
	(void) pthread_mutex_unlock(&sp->session_mutex);
}

/*
 * Clean up and release the storage allocated to the object.
 *
 * The function is called either with the object lock being held
 * (by caller kernel_delete_object()), or there is no object lock
 * yet (by kernel_build_XXX_object() during creating an object).
 */
void
kernel_cleanup_object(kernel_object_t *objp)
{
	/*
	 * Free the storage allocated to a secret key object.
	 */
	if (objp->class == CKO_SECRET_KEY) {
		if (OBJ_SEC(objp) != NULL && OBJ_SEC_VALUE(objp) != NULL) {
			freezero(OBJ_SEC_VALUE(objp), OBJ_SEC_VALUE_LEN(objp));
			OBJ_SEC_VALUE(objp) = NULL;
			OBJ_SEC_VALUE_LEN(objp) = 0;
		}
		free(OBJ_SEC(objp));
		OBJ_SEC(objp) = NULL;
	} else {
		kernel_cleanup_object_bigint_attrs(objp);
	}

	/*
	 * Free the storage allocated to the extra attribute list.
	 */
	kernel_cleanup_extra_attr(objp);
}

/*
 * Create a new object. Copy the attributes that can be modified
 * (in the boolean attribute mask field and extra attribute list)
 * from the old object to the new object.
 *
 * The caller of this function holds the lock on the old object.
 */
CK_RV
kernel_copy_object(kernel_object_t *old_object, kernel_object_t **new_object,
    boolean_t copy_everything, kernel_session_t *sp)
{
	CK_RV rv = CKR_OK;
	kernel_object_t *new_objp = NULL;
	CK_ATTRIBUTE_INFO_PTR attrp;

	/* Allocate new object. */
	new_objp = calloc(1, sizeof (kernel_object_t));
	if (new_objp == NULL)
		return (CKR_HOST_MEMORY);

	new_objp->class = old_object->class;
	new_objp->bool_attr_mask = old_object->bool_attr_mask;

	attrp = old_object->extra_attrlistp;
	while (attrp) {
		/*
		 * Copy the attribute_info struct from the old
		 * object to a new attribute_info struct, and add
		 * that new struct to the extra attribute list
		 * of the new object.
		 */
		rv = kernel_copy_extra_attr(attrp, new_objp);
		if (rv != CKR_OK) {
			kernel_cleanup_extra_attr(new_objp);
			free(new_objp);
			return (rv);
		}
		attrp = attrp->next;
	}

	*new_object = new_objp;

	if (!copy_everything) {
		/* done with copying all information that can be modified */
		return (CKR_OK);
	}

	/*
	 * Copy the rest of the object.
	 * Certain fields that are not appropriate for coping will be
	 * initialized.
	 */
	new_objp->key_type = old_object->key_type;
	new_objp->magic_marker = old_object->magic_marker;
	new_objp->mechanism = old_object->mechanism;
	new_objp->session_handle = (CK_SESSION_HANDLE)sp;
	(void) pthread_mutex_init(&(new_objp->object_mutex), NULL);
	/* copy key related information */
	switch (new_objp->class) {
		case CKO_PUBLIC_KEY:
			rv = kernel_copy_public_key_attr(OBJ_PUB(old_object),
			    &(OBJ_PUB(new_objp)), new_objp->key_type);
			break;
		case CKO_PRIVATE_KEY:
			rv = kernel_copy_private_key_attr(OBJ_PRI(old_object),
			    &(OBJ_PRI(new_objp)), new_objp->key_type);
			break;
		case CKO_SECRET_KEY:
			rv = kernel_copy_secret_key_attr(OBJ_SEC(old_object),
			    &(OBJ_SEC(new_objp)));
			break;
		default:
			/* should never be this case */
			break;
	}
	if (rv != CKR_OK) {
		/*
		 * don't need to cleanup the memory from failure of copying
		 * any key related stuff.  Each individual function for
		 * copying key attr will free the memory if it fails
		 */
		kernel_cleanup_extra_attr(new_objp);
		free(new_objp);
	}
	return (rv);
}

/*
 * Copy the attributes (in the boolean attribute mask field and
 * extra attribute list) from the new object back to the original
 * object. Also, clean up and release all the storage in the extra
 * attribute list of the original object.
 *
 * The caller of this function holds the lock on the old object.
 */
void
kernel_merge_object(kernel_object_t *old_object, kernel_object_t *new_object)
{

	old_object->bool_attr_mask = new_object->bool_attr_mask;
	kernel_cleanup_extra_attr(old_object);
	old_object->extra_attrlistp = new_object->extra_attrlistp;

}

/*
 * Create a new object struct.  If it is a session object, add the object to
 * the session's object list.  If it is a token object, add it to the slot's
 * token object list.  The caller does not hold the slot lock.
 */
CK_RV
kernel_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
    CK_ULONG *objecthandle_p, kernel_session_t *sp)
{
	CK_RV rv = CKR_OK;
	kernel_object_t *new_objp = NULL;
	kernel_slot_t	*pslot;
	crypto_object_create_t	objc;
	CK_BBOOL is_pri_obj;
	CK_BBOOL is_token_obj = B_FALSE;
	int r;

	new_objp = calloc(1, sizeof (kernel_object_t));
	if (new_objp == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail_cleanup;
	}

	new_objp->extra_attrlistp = NULL;
	new_objp->is_lib_obj = B_TRUE;

	/*
	 * If the HW provider supports object creation, create the object
	 * in the HW provider by calling the CRYPTO_OBJECT_CREATE ioctl.
	 * Otherwise, create the object in the library.
	 */
	pslot = slot_table[sp->ses_slotid];
	if (pslot->sl_func_list.fl_object_create) {
		new_objp->is_lib_obj = B_FALSE;
		objc.oc_session = sp->k_session;
		objc.oc_count = ulCount;
		rv = process_object_attributes(pTemplate, ulCount,
		    &objc.oc_attributes, &is_token_obj);
		if (rv != CKR_OK) {
			goto fail_cleanup;
		}

		/* Cannot create a token object with a READ-ONLY session */
		if (is_token_obj && sp->ses_RO) {
			free_object_attributes(objc.oc_attributes, ulCount);
			rv = CKR_SESSION_READ_ONLY;
			goto fail_cleanup;
		}

		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_CREATE,
		    &objc)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(objc.oc_return_value);
		}

		free_object_attributes(objc.oc_attributes, ulCount);

		if (rv != CKR_OK) {
			goto fail_cleanup;
		}

		/* Get the CKA_PRIVATE value of this object. */
		new_objp->k_handle = objc.oc_handle;
		rv = get_cka_private_value(sp, new_objp->k_handle,
		    &is_pri_obj);
		if (rv != CKR_OK) {
			goto fail_cleanup;
		}

		/* Set the PRIVATE_BOOL_ON and TOKEN_BOOL_ON attributes */
		if (is_pri_obj)
			new_objp->bool_attr_mask |= PRIVATE_BOOL_ON;
		else
			new_objp->bool_attr_mask &= ~PRIVATE_BOOL_ON;

		if (is_token_obj)
			new_objp->bool_attr_mask |= TOKEN_BOOL_ON;
		else
			new_objp->bool_attr_mask &= ~TOKEN_BOOL_ON;

	} else {
		/*
		 * Create the object in the library.
		 * Validate attribute template and fill in the attributes
		 * in the kernel_object_t.
		 */
		rv = kernel_build_object(pTemplate, ulCount, new_objp, sp,
		    KERNEL_CREATE_OBJ);
		if (rv != CKR_OK) {
			goto fail_cleanup;
		}
	}

	/* Initialize the rest of stuffs in kernel_object_t. */
	(void) pthread_mutex_init(&new_objp->object_mutex, NULL);
	new_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	new_objp->session_handle = (CK_SESSION_HANDLE)sp;

	if (is_token_obj) {
		/* Add the new object to the slot's token object list. */
		pslot = slot_table[sp->ses_slotid];
		kernel_add_token_object_to_slot(new_objp, pslot);
	} else {
		/* Add the new object to the session's object list. */
		kernel_add_object_to_session(new_objp, sp);
	}

	/* Type casting the address of an object struct to an object handle. */
	*objecthandle_p = (CK_ULONG)new_objp;

	return (CKR_OK);

fail_cleanup:
	if (new_objp) {
		/*
		 * If the object is created in the HW provider, the storage
		 * allocated for the ioctl call is always cleaned up after
		 * the call.  If the object is created in the library,
		 * the storage allocated inside of this object should
		 * have been cleaned up in the kernel_build_object()
		 * after an error occurred. Therefore, we can safely
		 * free the object.
		 */
		free(new_objp);
	}

	return (rv);
}

/*
 * Remove an object from the session's object list.
 *
 * The caller of this function holds the session lock.
 */
CK_RV
kernel_remove_object_from_session(kernel_object_t *objp, kernel_session_t *sp)
{
	kernel_object_t *tmp_objp;
	boolean_t found = B_FALSE;

	/*
	 * Remove the object from the session's object list.
	 */
	if ((sp == NULL) ||
	    (sp->magic_marker != KERNELTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	if ((sp->object_list == NULL) || (objp == NULL) ||
	    (objp->magic_marker != KERNELTOKEN_OBJECT_MAGIC)) {
		return (CKR_OBJECT_HANDLE_INVALID);
	}

	tmp_objp = sp->object_list;
	while (tmp_objp) {
		if (tmp_objp == objp) {
			found = B_TRUE;
			break;
		}
		tmp_objp = tmp_objp->next;
	}
	if (!found)
		return (CKR_OBJECT_HANDLE_INVALID);

	if (sp->object_list == objp) {
		/* Object is the first one in the list. */
		if (objp->next) {
			sp->object_list = objp->next;
			objp->next->prev = NULL;
		} else {
			/* Object is the only one in the list. */
			sp->object_list = NULL;
		}
	} else {
		/* Object is not the first one in the list. */
		if (objp->next) {
			/* Object is in the middle of the list. */
			objp->prev->next = objp->next;
			objp->next->prev = objp->prev;
		} else {
			/* Object is the last one in the list. */
			objp->prev->next = NULL;
		}
	}
	return (CKR_OK);
}

static void
kernel_delete_object_cleanup(kernel_object_t *objp, boolean_t wrapper_only)
{
	/* Acquire the lock on the object. */
	(void) pthread_mutex_lock(&objp->object_mutex);

	/*
	 * Make sure another thread hasn't freed the object.
	 */
	if (objp->magic_marker != KERNELTOKEN_OBJECT_MAGIC) {
		(void) pthread_mutex_unlock(&objp->object_mutex);
		return;
	}

	/*
	 * The deletion of an object must be blocked when the object
	 * reference count is not zero. This means if any object related
	 * operation starts prior to the delete object operation gets in,
	 * the object deleting thread must wait for the non-deleting
	 * operation to be completed before it can proceed the delete
	 * operation.
	 *
	 * Unless we are being forced to shut everything down, this only
	 * happens if the library's _fini() is running not if someone
	 * explicitly called C_Finalize().
	 */
	if (wrapper_only) {
		objp->obj_refcnt = 0;
	}

	while (objp->obj_refcnt != 0) {
		/*
		 * We set the OBJECT_REFCNT_WAITING flag before we put
		 * this deleting thread in a wait state, so other non-deleting
		 * operation thread will signal to wake it up only when
		 * the object reference count becomes zero and this flag
		 * is set.
		 */
		objp->obj_delete_sync |= OBJECT_REFCNT_WAITING;
		(void) pthread_cond_wait(&objp->obj_free_cond,
		    &objp->object_mutex);
	}

	objp->obj_delete_sync &= ~OBJECT_REFCNT_WAITING;

	/* Mark object as no longer valid. */
	objp->magic_marker = 0;

	(void) pthread_cond_destroy(&objp->obj_free_cond);
}

/*
 * Delete a session object:
 * - Remove the object from the session's object list.
 * - Release the storage allocated to the object.
 *
 * The boolean argument ses_lock_held is used to indicate that whether
 * the caller holds the session lock or not.
 * - When called by kernel_delete_all_objects_in_session() or
 *   kernel_delete_pri_objects_in_slot() -- ses_lock_held = TRUE.
 *
 * The boolean argument wrapper_only is used to indicate that whether
 * the caller only wants to clean up the object wrapper from the library and
 * needs not to make an ioctl call.
 * - This argument only applies to the object created in the provider level.
 * - When called by kernel_cleanup_pri_objects_in_slot(), wrapper_only is TRUE.
 * - When called by C_DestroyObject(), wrapper_only is FALSE.
 * - When called by kernel_delete_all_objects_in_session(), the value of
 *   wrapper_only depends on its caller.
 */
CK_RV
kernel_delete_session_object(kernel_session_t *sp, kernel_object_t *objp,
    boolean_t ses_lock_held, boolean_t wrapper_only)
{
	CK_RV rv = CKR_OK;
	crypto_object_destroy_t	obj_destroy;

	/*
	 * Check to see if the caller holds the lock on the session.
	 * If not, we need to acquire that lock in order to proceed.
	 */
	if (!ses_lock_held) {
		/* Acquire the session lock. */
		(void) pthread_mutex_lock(&sp->session_mutex);
	}

	/* Remove the object from the session's object list first. */
	rv = kernel_remove_object_from_session(objp, sp);
	if (!ses_lock_held) {
		/*
		 * If the session lock is obtained by this function,
		 * then release that lock after removing the object
		 * from session's object list.
		 * We want the releasing of the object storage to
		 * be done without holding the session lock.
		 */
		(void) pthread_mutex_unlock(&sp->session_mutex);
	}

	if (rv != CKR_OK)
		return (rv);

	kernel_delete_object_cleanup(objp, wrapper_only);

	/* Destroy the object. */
	if (objp->is_lib_obj) {
		/*
		 * If this object is created in the library, cleanup the
		 * contents of this object such as free all the storage
		 * allocated for this object.
		 */
		kernel_cleanup_object(objp);
	} else {
		/*
		 * This object is created in the HW provider. If wrapper_only
		 * is FALSE, make an ioctl call to destroy it in kernel.
		 */
		if (!wrapper_only) {
			obj_destroy.od_session = sp->k_session;
			obj_destroy.od_handle = objp->k_handle;

			while (ioctl(kernel_fd, CRYPTO_OBJECT_DESTROY,
			    &obj_destroy) < 0) {
				if (errno != EINTR)
					break;
			}

			/*
			 * Ignore ioctl return codes for a session object.
			 * If the kernel can not delete a session object, it
			 * is likely caused by the HW provider. There's not
			 * much that can be done.  The library will still
			 * cleanup the object wrapper in the library. The HW
			 * provider will destroy all session objects when
			 * the application exits.
			 */
		}
	}

	/* Reset OBJECT_IS_DELETING flag. */
	objp->obj_delete_sync &= ~OBJECT_IS_DELETING;

	(void) pthread_mutex_unlock(&objp->object_mutex);
	/* Destroy the object lock */
	(void) pthread_mutex_destroy(&objp->object_mutex);
	/* Free the object itself */
	kernel_object_delay_free(objp);

	return (CKR_OK);
}

/*
 * Delete all the objects in a session. The caller holds the lock
 * on the session.   If the wrapper_only argument is TRUE, the caller only
 * want to clean up object wrappers in the library.
 */
void
kernel_delete_all_objects_in_session(kernel_session_t *sp,
    boolean_t wrapper_only)
{
	kernel_object_t *objp = sp->object_list;
	kernel_object_t *objp1;

	/* Delete all the objects in the session. */
	while (objp) {
		objp1 = objp->next;

		/*
		 * Delete an session object by calling
		 * kernel_delete_session_object():
		 * - The 3rd TRUE boolean argument indicates that the caller
		 *   holds the session lock.
		 * - The 4th boolean argument indicates whether we only want
		 *   clean up object wrappers in the library.
		 */
		(void) kernel_delete_session_object(sp, objp, B_TRUE,
		    wrapper_only);

		objp = objp1;
	}
}

static CK_RV
add_to_search_result(kernel_object_t *obj, find_context_t *fcontext,
    CK_ULONG *num_result_alloc)
{
	/*
	 * allocate space for storing results if the currently
	 * allocated space is not enough
	 */
	if (*num_result_alloc <= fcontext->num_results) {
		fcontext->objs_found = realloc(fcontext->objs_found,
		    sizeof (kernel_object_t *) * (*num_result_alloc + BUFSIZ));
		if (fcontext->objs_found == NULL) {
			return (CKR_HOST_MEMORY);
		}
		*num_result_alloc += BUFSIZ;
	}

	(fcontext->objs_found)[(fcontext->num_results)++] = obj;
	return (CKR_OK);
}

static CK_RV
search_for_objects(kernel_session_t *sp, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, find_context_t *fcontext)
{
	kernel_session_t *session_p;
	kernel_object_t *obj;
	CK_OBJECT_CLASS pclasses[6]; /* classes attrs possibly exist */
	CK_ULONG num_pclasses;	/* number of possible classes */
	CK_ULONG num_result_alloc = 0; /* spaces allocated for results */
	CK_RV rv = CKR_OK;
	kernel_slot_t	*pslot;

	if (ulCount > 0) {
		/* there are some search requirement */
		kernel_process_find_attr(pclasses, &num_pclasses,
		    pTemplate, ulCount);
	}

	/* Acquire the slot lock */
	pslot = slot_table[sp->ses_slotid];
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	/*
	 * Go through all objects in each session.
	 * Acquire individual session lock for the session
	 * we are searching.
	 */
	session_p = pslot->sl_sess_list;
	while (session_p) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		obj = session_p->object_list;
		while (obj) {
			(void) pthread_mutex_lock(&obj->object_mutex);
			if (ulCount > 0) {
				if (kernel_find_match_attrs(obj, pclasses,
				    num_pclasses, pTemplate, ulCount)) {
					rv = add_to_search_result(
					    obj, fcontext, &num_result_alloc);
				}
			} else {
				/* no search criteria, just record the object */
				rv = add_to_search_result(obj, fcontext,
				    &num_result_alloc);
			}
			(void) pthread_mutex_unlock(&obj->object_mutex);
			if (rv != CKR_OK) {
				(void) pthread_mutex_unlock(
				    &session_p->session_mutex);
				goto cleanup;
			}
			obj = obj->next;
		}
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		session_p = session_p->next;
	}

cleanup:
	/* Release the slot lock */
	(void) pthread_mutex_unlock(&pslot->sl_mutex);
	return (rv);
}

/*
 * Initialize the context for C_FindObjects() calls
 */
CK_RV
kernel_find_objects_init(kernel_session_t *sp, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_CLASS class; /* for kernel_validate_attr(). Value unused */
	find_context_t *fcontext;

	if (ulCount) {
		rv = kernel_validate_attr(pTemplate, ulCount, &class);
		/* Make sure all attributes in template are valid */
		if (rv != CKR_OK) {
			return (rv);
		}
	}

	/* prepare the find context */
	fcontext = calloc(1, sizeof (find_context_t));
	if (fcontext == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = search_for_objects(sp, pTemplate, ulCount, fcontext);
	if (rv != CKR_OK) {
		free(fcontext);
		return (rv);
	}

	/* store the find_context in the session */
	sp->find_objects.context = (CK_VOID_PTR)fcontext;

	return (rv);
}

void
kernel_find_objects_final(kernel_session_t *sp)
{
	find_context_t *fcontext;

	fcontext = sp->find_objects.context;
	sp->find_objects.context = NULL;
	sp->find_objects.flags = 0;
	if (fcontext->objs_found != NULL) {
		free(fcontext->objs_found);
	}

	free(fcontext);
}

void
kernel_find_objects(kernel_session_t *sp, CK_OBJECT_HANDLE *obj_found,
    CK_ULONG max_obj_requested, CK_ULONG *found_obj_count)
{
	find_context_t *fcontext;
	CK_ULONG num_obj_found = 0;
	CK_ULONG i;
	kernel_object_t *obj;

	fcontext = sp->find_objects.context;

	for (i = fcontext->next_result_index;
	    ((num_obj_found < max_obj_requested) &&
	    (i < fcontext->num_results));
	    i++) {
		obj = fcontext->objs_found[i];
		if (obj != NULL) {
			(void) pthread_mutex_lock(&obj->object_mutex);
			/* a sanity check to make sure the obj is still valid */
			if (obj->magic_marker == KERNELTOKEN_OBJECT_MAGIC) {
				obj_found[num_obj_found] =
				    (CK_OBJECT_HANDLE)obj;
				num_obj_found++;
			}
			(void) pthread_mutex_unlock(&obj->object_mutex);
		}
	}
	fcontext->next_result_index = i;
	*found_obj_count = num_obj_found;
}

/*
 * Add an token object to the token object list in slot.
 *
 * This function will acquire the lock on the slot, and release
 * that lock after adding the object to the slot's token object list.
 */
void
kernel_add_token_object_to_slot(kernel_object_t *objp, kernel_slot_t *pslot)
{
	/* Acquire the slot lock. */
	(void) pthread_mutex_lock(&pslot->sl_mutex);

	/* Insert the new object in front of slot's token object list. */
	if (pslot->sl_tobj_list == NULL) {
		pslot->sl_tobj_list = objp;
		objp->next = NULL;
		objp->prev = NULL;
	} else {
		pslot->sl_tobj_list->prev = objp;
		objp->next = pslot->sl_tobj_list;
		objp->prev = NULL;
		pslot->sl_tobj_list = objp;
	}

	/* Release the slot lock. */
	(void) pthread_mutex_unlock(&pslot->sl_mutex);
}

/*
 * Remove an token object from the slot's token object list.
 * This routine is called by kernel_delete_token_object().
 * The caller of this function hold the slot lock.
 */
void
kernel_remove_token_object_from_slot(kernel_slot_t *pslot,
    kernel_object_t *objp)
{

	if (pslot->sl_tobj_list == objp) {
		/* Object is the first one in the list */
		if (objp->next) {
			pslot->sl_tobj_list = objp->next;
			objp->next->prev = NULL;
		} else {
			/* Object is the only one in the list. */
			pslot->sl_tobj_list = NULL;
		}
	} else {
		/* Object is not the first one in the list. */
		if (objp->next) {
			/* Object is in the middle of the list. */
			objp->prev->next = objp->next;
			objp->next->prev = objp->prev;
		} else {
			/* Object is the last one in the list. */
			objp->prev->next = NULL;
		}
	}
}

/*
 * Delete a token object:
 * - Remove the object from the slot's token object list.
 * - Release the storage allocated to the object.
 *
 * The boolean argument slot_lock_held is used to indicate that whether
 * the caller holds the slot lock or not. When the caller does not hold
 * the slot lock, this function will acquire that lock in order to proceed,
 * and also release that lock before returning to caller.
 *
 * The boolean argument wrapper_only is used to indicate that whether
 * the caller only wants to the object wrapper from library.
 */
CK_RV
kernel_delete_token_object(kernel_slot_t *pslot, kernel_session_t *sp,
    kernel_object_t *objp, boolean_t slot_lock_held, boolean_t wrapper_only)
{
	CK_RV rv;
	crypto_object_destroy_t	obj_destroy;
	int r;

	/*
	 * Check to see if the caller holds the lock on the slot.
	 * If not, we need to acquire that lock in order to proceed.
	 */
	if (!slot_lock_held) {
		(void) pthread_mutex_lock(&pslot->sl_mutex);
	}

	/* Remove the object from the slot's token object list first. */
	kernel_remove_token_object_from_slot(pslot, objp);

	/* Release the slot lock if the call doesn't hold the lock. */
	if (!slot_lock_held) {
		(void) pthread_mutex_unlock(&pslot->sl_mutex);
	}

	kernel_delete_object_cleanup(objp, wrapper_only);

	if (!wrapper_only) {
		obj_destroy.od_session = sp->k_session;
		obj_destroy.od_handle = objp->k_handle;

		while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_DESTROY,
		    &obj_destroy)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    obj_destroy.od_return_value);
		}

		/*
		 * Could not destroy an object from kernel. Write a warning
		 * in syslog, but we still clean up the object wrapper in
		 * the library.
		 */
		if (rv != CKR_OK) {
			cryptoerror(LOG_ERR, "pkcs11_kernel: Could not "
			    "destroy an object in kernel.");
		}
	}

	(void) pthread_mutex_unlock(&objp->object_mutex);
	/* Destroy the object lock */
	(void) pthread_mutex_destroy(&objp->object_mutex);
	/* Free the object itself */
	kernel_object_delay_free(objp);

	return (CKR_OK);
}

/*
 * Clean up private object wrappers in this slot. The caller holds the slot
 * lock.
 */
void
kernel_cleanup_pri_objects_in_slot(kernel_slot_t *pslot,
    kernel_session_t *cur_sp)
{
	kernel_session_t *session_p;
	kernel_object_t *objp;
	kernel_object_t *objp1;

	/*
	 * Delete every private token object from the slot' token object list
	 */
	objp = pslot->sl_tobj_list;
	while (objp) {
		objp1 = objp->next;
		/*
		 * The first TRUE boolean argument indicates that the caller
		 * hold the slot lock.  The second TRUE boolean argument
		 * indicates that the caller just wants to clean up the object
		 * wrapper from the library only.
		 */
		if (objp->bool_attr_mask & PRIVATE_BOOL_ON) {
			(void) kernel_delete_token_object(pslot, cur_sp, objp,
			    B_TRUE, B_TRUE);
		}
		objp = objp1;
	}

	/*
	 * Walk through all the sessions in this slot and delete every
	 * private object.
	 */
	session_p = pslot->sl_sess_list;
	while (session_p) {

		/* Delete all the objects in the session. */
		objp = session_p->object_list;
		while (objp) {
			objp1 = objp->next;
			/*
			 * The FALSE boolean argument indicates that the
			 * caller does not hold the session lock.  The TRUE
			 * boolean argument indicates that the caller just
			 * want to clean upt the object wrapper from the
			 * library only.
			 */
			if (objp->bool_attr_mask & PRIVATE_BOOL_ON) {
				(void) kernel_delete_session_object(session_p,
				    objp, B_FALSE, B_TRUE);
			}

			objp = objp1;
		}

		session_p = session_p->next;
	}
}

/*
 * Get the object size in bytes for the objects created in the library.
 */
CK_RV
kernel_get_object_size(kernel_object_t *obj, CK_ULONG_PTR pulSize)
{
	CK_RV rv = CKR_OK;
	CK_ULONG obj_size;
	biginteger_t *big;

	obj_size = sizeof (kernel_object_t);

	switch (obj->class) {
	case CKO_PUBLIC_KEY:
		if (obj->key_type == CKK_RSA) {
			big = OBJ_PUB_RSA_PUBEXPO(obj);
			obj_size += big->big_value_len;
			big = OBJ_PUB_RSA_MOD(obj);
			obj_size += big->big_value_len;

		} else if (obj->key_type == CKK_DSA) {
			big = OBJ_PUB_DSA_PRIME(obj);
			obj_size += big->big_value_len;
			big = OBJ_PUB_DSA_SUBPRIME(obj);
			obj_size += big->big_value_len;
			big = OBJ_PUB_DSA_BASE(obj);
			obj_size += big->big_value_len;
			big = OBJ_PUB_DSA_VALUE(obj);
			obj_size += big->big_value_len;

		} else if (obj->key_type == CKK_EC) {
			big = OBJ_PUB_EC_POINT(obj);
			obj_size += big->big_value_len;

		} else {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}
		break;

	case CKO_PRIVATE_KEY:
		if (obj->key_type == CKK_RSA) {
			big = OBJ_PRI_RSA_MOD(obj);
			obj_size += big->big_value_len;

			big = OBJ_PRI_RSA_PUBEXPO(obj); /* optional */
			if (big != NULL) {
				obj_size += big->big_value_len;
			}

			big = OBJ_PRI_RSA_PRIEXPO(obj);
			obj_size += big->big_value_len;

			big = OBJ_PRI_RSA_PRIME1(obj); /* optional */
			if (big != NULL) {
				obj_size += big->big_value_len;
			}

			big = OBJ_PRI_RSA_PRIME2(obj); /* optional */
			if (big != NULL) {
				obj_size += big->big_value_len;
			}

			big = OBJ_PRI_RSA_EXPO1(obj); /* optional */
			if (big != NULL) {
				obj_size += big->big_value_len;
			}

			big = OBJ_PRI_RSA_EXPO2(obj); /* optional */
			if (big != NULL) {
				obj_size += big->big_value_len;
			}

			big = OBJ_PRI_RSA_COEF(obj); /* optional */
			if (big != NULL) {
				obj_size += big->big_value_len;
			}

		} else if (obj->key_type == CKK_DSA) {
			big = OBJ_PRI_DSA_PRIME(obj);
			obj_size += big->big_value_len;
			big = OBJ_PRI_DSA_SUBPRIME(obj);
			obj_size += big->big_value_len;
			big = OBJ_PRI_DSA_BASE(obj);
			obj_size += big->big_value_len;
			big = OBJ_PRI_DSA_VALUE(obj);
			obj_size += big->big_value_len;

		} else if (obj->key_type == CKK_EC) {
			big = OBJ_PRI_EC_VALUE(obj);
			obj_size += big->big_value_len;

		} else {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}
		break;

	case CKO_SECRET_KEY:
		obj_size += OBJ_SEC_VALUE_LEN(obj);
		break;

	default:
		rv = CKR_OBJECT_HANDLE_INVALID;
	}

	if (rv == CKR_OK) {
		*pulSize = obj_size;
	}

	return (rv);
}

/*
 * This function adds the to-be-freed session object to a linked list.
 * When the number of objects queued in the linked list reaches the
 * maximum threshold MAX_OBJ_TO_BE_FREED, it will free the first
 * object (FIFO) in the list.
 */
void
kernel_object_delay_free(kernel_object_t *objp)
{
	kernel_object_t *tmp;

	(void) pthread_mutex_lock(&obj_delay_freed.obj_to_be_free_mutex);

	/* Add the newly deleted object at the end of the list */
	objp->next = NULL;
	if (obj_delay_freed.first == NULL) {
		obj_delay_freed.last = objp;
		obj_delay_freed.first = objp;
	} else {
		obj_delay_freed.last->next = objp;
		obj_delay_freed.last = objp;
	}

	if (++obj_delay_freed.count >= MAX_OBJ_TO_BE_FREED) {
		/*
		 * Free the first object in the list only if
		 * the total count reaches maximum threshold.
		 */
		obj_delay_freed.count--;
		tmp = obj_delay_freed.first->next;
		free(obj_delay_freed.first);
		obj_delay_freed.first = tmp;
	}
	(void) pthread_mutex_unlock(&obj_delay_freed.obj_to_be_free_mutex);
}
