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

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>

#include "kmsGlobal.h"
#include "kmsObject.h"
#include "kmsSession.h"
#include "kmsSlot.h"
#include "kmsKeystoreUtil.h"

kms_object_t *
kms_new_object()
{
	kms_object_t *obj;

	obj = calloc(1, sizeof (kms_object_t));
	if (obj == NULL)
		return (NULL);

	(void) pthread_cond_init(&obj->obj_free_cond, NULL);
	(void) pthread_mutex_init(&obj->object_mutex, NULL);
	obj->magic_marker = KMSTOKEN_OBJECT_MAGIC;

	return (obj);
}

/*
 * Add an object to the session's object list.
 *
 * This function will acquire the lock on the session, and release
 * that lock after adding the object to the session's object list.
 */
void
kms_add_object_to_session(kms_object_t *objp, kms_session_t *sp)
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
 * (by caller kms_delete_object()), or there is no object lock
 * yet (by kms_build_XXX_object() during creating an object).
 */
void
kms_cleanup_object(kms_object_t *objp)
{
	/*
	 * Free the storage allocated to a secret key object.
	 */
	if (objp->class == CKO_SECRET_KEY) {
		if (OBJ_SEC(objp) != NULL && OBJ_SEC_VALUE(objp) != NULL) {
			bzero(OBJ_SEC_VALUE(objp), OBJ_SEC_VALUE_LEN(objp));
			free(OBJ_SEC_VALUE(objp));
			OBJ_SEC_VALUE(objp) = NULL;
			OBJ_SEC_VALUE_LEN(objp) = 0;
		}
		if (OBJ_SEC(objp) != NULL)
			free(OBJ_SEC(objp));

		OBJ_SEC(objp) = NULL;
	}

	/*
	 * Free the storage allocated to the extra attribute list.
	 */
	kms_cleanup_extra_attr(objp);
}

void
kms_free_object(kms_object_t *obj)
{
	(void) pthread_cond_destroy(&obj->obj_free_cond);
	(void) pthread_mutex_destroy(&obj->object_mutex);

	kms_cleanup_object(obj);

	free(obj);
}

/*
 * Create a new object. Copy the attributes that can be modified
 * (in the boolean attribute mask field and extra attribute list)
 * from the old object to the new object.
 *
 * The caller of this function holds the lock on the old object.
 */
CK_RV
kms_copy_object(kms_object_t *old_object, kms_object_t **new_object,
    boolean_t copy_everything, kms_session_t *sp)
{
	CK_RV rv = CKR_OK;
	kms_object_t *new_objp = NULL;
	CK_ATTRIBUTE_INFO_PTR attrp;

	/* Allocate new object. */
	new_objp = kms_new_object();
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
		rv = kms_copy_extra_attr(attrp, new_objp);
		if (rv != CKR_OK) {
			kms_free_object(new_objp);
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

	/* copy key related information */
	switch (new_objp->class) {
		case CKO_SECRET_KEY:
			rv = kms_copy_secret_key_attr(OBJ_SEC(old_object),
			    &(OBJ_SEC(new_objp)));
			break;
		default:
			/* should never be this case */
			break;
	}
	if (rv != CKR_OK) {
		kms_free_object(new_objp);
		*new_object = NULL;
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
kms_merge_object(kms_object_t *old_object, kms_object_t *new_object)
{
	old_object->bool_attr_mask = new_object->bool_attr_mask;
	kms_cleanup_extra_attr(old_object);
	old_object->extra_attrlistp = new_object->extra_attrlistp;
}

/*
 * Create a new object struct.  If it is a session object, add the object to
 * the session's object list.  If it is a token object, add it to the slot's
 * token object list.  The caller does not hold the slot lock.
 */
CK_RV
kms_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
	CK_ULONG *objecthandle_p, kms_session_t *sp)
{
	CK_RV rv = CKR_OK;
	kms_object_t *new_objp = NULL;
	kms_slot_t	*pslot;
	CK_ATTRIBUTE	pritmpl;
	CK_BBOOL	is_pri_obj, is_token_obj;

	new_objp = kms_new_object();
	if (new_objp == NULL)
		return (CKR_HOST_MEMORY);

	rv = kms_build_object(pTemplate, ulCount, new_objp);
	if (rv != CKR_OK)
		goto fail_cleanup;

	/* Cannot create a token object with a READ-ONLY session */
	pritmpl.type = CKA_TOKEN;
	pritmpl.pValue = &is_token_obj;
	pritmpl.ulValueLen = sizeof (is_token_obj);
	rv = kms_get_attribute(new_objp, &pritmpl);
	if (rv != CKR_OK)
		goto fail_cleanup;

	if (is_token_obj && sp->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		goto fail_cleanup;
	}

	/*
	 * If the KMS supports object creation, create the object
	 * in the KMS.  Otherwise, create the object in the library.
	 */

	/* Get the CKA_PRIVATE value of this object. */
	pritmpl.type = CKA_PRIVATE;
	pritmpl.pValue = &is_pri_obj;
	pritmpl.ulValueLen = sizeof (is_pri_obj);

	rv = kms_get_attribute(new_objp, &pritmpl);
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

	new_objp->session_handle = (CK_SESSION_HANDLE)sp;

	if (is_token_obj) {
		/* Add the new object to the slot's token object list. */
		pslot = get_slotinfo();
		kms_add_token_object_to_slot(new_objp, pslot);
	} else {
		/* Add the new object to the session's object list. */
		kms_add_object_to_session(new_objp, sp);
	}

	/* Type casting the address of an object struct to an object handle. */
	if (rv == CKR_OK)
		*objecthandle_p = (CK_ULONG)new_objp;

fail_cleanup:
	if (rv != CKR_OK) {
		kms_free_object(new_objp);
	}
	return (rv);
}

/*
 * Remove an object from the session's object list.
 *
 * The caller of this function holds the session lock.
 */
CK_RV
kms_remove_object_from_session(kms_object_t *objp, kms_session_t *sp)
{
	kms_object_t *tmp_objp;
	boolean_t found = B_FALSE;

	/*
	 * Remove the object from the session's object list.
	 */
	if ((sp == NULL) ||
	    (sp->magic_marker != KMSTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	if ((sp->object_list == NULL) || (objp == NULL) ||
	    (objp->magic_marker != KMSTOKEN_OBJECT_MAGIC)) {
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

/*
 * This function adds the to-be-freed session object to a linked list.
 * When the number of objects queued in the linked list reaches the
 * maximum threshold MAX_OBJ_TO_BE_FREED, it will free the first
 * object (FIFO) in the list.
 */
void
kms_object_delay_free(kms_object_t *objp)
{
	kms_object_t *tmp;

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
		kms_free_object(obj_delay_freed.first);
		obj_delay_freed.first = tmp;
	}
	(void) pthread_mutex_unlock(&obj_delay_freed.obj_to_be_free_mutex);
}

static void
kms_delete_object_cleanup(kms_object_t *objp, boolean_t force)
{
	/* Acquire the lock on the object. */
	(void) pthread_mutex_lock(&objp->object_mutex);

	/*
	 * Make sure another thread hasn't freed the object.
	 */
	if (objp->magic_marker != KMSTOKEN_OBJECT_MAGIC) {
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
	if (force) {
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
	kms_cleanup_object(objp);

	objp->obj_delete_sync &= ~OBJECT_IS_DELETING;
	(void) pthread_mutex_unlock(&objp->object_mutex);

	if (objp->bool_attr_mask & TOKEN_BOOL_ON)
		free(objp);
	else
		kms_object_delay_free(objp);
}

/*
 * Delete a session object:
 * - Remove the object from the session's object list.
 * - Release the storage allocated to the object.
 *
 * The boolean argument ses_lock_held is used to indicate that whether
 * the caller holds the session lock or not.
 * - When called by kms_delete_all_objects_in_session() or
 *   kms_delete_pri_objects_in_slot() -- ses_lock_held = TRUE.
 *
 * The boolean argument wrapper_only is used to indicate that whether
 * the caller only wants to clean up the object wrapper from the library and
 * needs not to make an call to KMS.
 * - This argument only applies to the object created in the provider level.
 * - When called by kms_cleanup_pri_objects_in_slot(), wrapper_only is TRUE.
 * - When called by C_DestroyObject(), wrapper_only is FALSE.
 * - When called by kms_delete_all_objects_in_session(), the value of
 *   wrapper_only depends on its caller.
 */
CK_RV
kms_delete_object(kms_session_t *sp, kms_object_t *objp,
    boolean_t ses_lock_held, boolean_t wrapper_only)
{
	CK_RV rv = CKR_OK;

	/*
	 * Check to see if the caller holds the lock on the session.
	 * If not, we need to acquire that lock in order to proceed.
	 */
	if (!ses_lock_held) {
		/* Acquire the session lock. */
		(void) pthread_mutex_lock(&sp->session_mutex);
	}

	/* Remove the object from the session's object list first. */
	if ((rv = kms_remove_object_from_session(objp, sp))) {
		if (!ses_lock_held)
			(void) pthread_mutex_unlock(&sp->session_mutex);
		return (rv);
	}

	if (!wrapper_only)
		(void) pthread_mutex_unlock(&sp->session_mutex);

	kms_delete_object_cleanup(objp, wrapper_only);

	return (rv);
}

/*
 * Delete all the objects in a session. The caller holds the lock
 * on the session.   If the wrapper_only argument is TRUE, the caller only
 * want to clean up object wrappers in the library.
 */
void
kms_delete_all_objects_in_session(kms_session_t *sp,
    boolean_t wrapper_only)
{
	kms_object_t *objp = sp->object_list;
	kms_object_t *objp1;

	/* Delete all the objects in the session. */
	while (objp) {
		objp1 = objp->next;
		(void) kms_delete_object(sp, objp, B_TRUE,
		    wrapper_only);

		objp = objp1;
	}
}

static CK_RV
add_to_search_result(kms_object_t *obj, find_context_t *fcontext,
    CK_ULONG *num_result_alloc)
{
	/*
	 * allocate space for storing results if the currently
	 * allocated space is not enough
	 */
	if (*num_result_alloc <= fcontext->num_results) {
		fcontext->objs_found = realloc(fcontext->objs_found,
		    sizeof (kms_object_t *) * (*num_result_alloc + BUFSIZ));
		if (fcontext->objs_found == NULL) {
			return (CKR_HOST_MEMORY);
		}
		*num_result_alloc += BUFSIZ;
	}

	(fcontext->objs_found)[(fcontext->num_results)++] = obj;
	return (CKR_OK);
}

static CK_RV
search_for_objects(kms_session_t *sp, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, find_context_t *fcontext)
{
	kms_session_t *session_p;
	kms_object_t *obj;
	CK_OBJECT_CLASS pclasses[6]; /* classes attrs possibly exist */
	CK_ULONG num_pclasses;	/* number of possible classes */
	CK_ULONG num_result_alloc = 0; /* spaces allocated for results */
	CK_RV rv = CKR_OK;
	kms_slot_t	*pslot = NULL;
	boolean_t token_specified = B_FALSE;
	boolean_t token_flag_val = B_FALSE;
	int i;

	if (ulCount > 0) {
		/* there are some search requirement */
		kms_process_find_attr(pclasses, &num_pclasses,
		    pTemplate, ulCount);
	}

	/*
	 * look through template and see if it explicitly specifies
	 * whether we need to look for token objects or not
	 */
	for (i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == CKA_TOKEN) {
			token_specified = B_TRUE;
			token_flag_val = *((CK_BBOOL *)pTemplate[i].pValue);
			break;
		}
	}

	pslot = get_slotinfo();

	/* Acquire the slot lock */
	if (token_flag_val || !token_specified) {
		(void) pthread_mutex_lock(&pslot->sl_mutex);
		/*
		 * Make sure the object list is current.
		 */
		rv = KMS_RefreshObjectList(sp, pslot);
		if (rv != CKR_OK) {
			(void) pthread_mutex_unlock(&pslot->sl_mutex);
			return (rv);
		}

		obj = pslot->sl_tobj_list;
		while (obj) {
			(void) pthread_mutex_lock(&obj->object_mutex);
			if (((token_specified) && (ulCount > 1)) ||
			    ((!token_specified) && (ulCount > 0))) {
				if (kms_find_match_attrs(obj, pclasses,
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
				goto cleanup;
			}
			obj = obj->next;
		}
		(void) pthread_mutex_unlock(&pslot->sl_mutex);
	}

	if (token_flag_val) {
		return (rv);
	}

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
				if (kms_find_match_attrs(obj, pclasses,
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
kms_find_objects_init(kms_session_t *sp, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_CLASS class; /* for kms_validate_attr(). Value unused */
	find_context_t *fcontext;

	if (ulCount) {
		rv = kms_validate_attr(pTemplate, ulCount, &class);
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
kms_find_objects_final(kms_session_t *sp)
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

CK_RV
kms_find_objects(kms_session_t *sp, CK_OBJECT_HANDLE *obj_found,
    CK_ULONG max_obj_requested, CK_ULONG *found_obj_count)
{
	find_context_t *fcontext;
	CK_ULONG num_obj_found = 0;
	CK_ULONG i;
	kms_object_t *obj;

	fcontext = sp->find_objects.context;

	for (i = fcontext->next_result_index;
	    ((num_obj_found < max_obj_requested) &&
	    (i < fcontext->num_results));
	    i++) {
		obj = fcontext->objs_found[i];
		if (obj != NULL) {
			(void) pthread_mutex_lock(&obj->object_mutex);
			/* a sanity check to make sure the obj is still valid */
			if (obj->magic_marker == KMSTOKEN_OBJECT_MAGIC) {
				obj_found[num_obj_found] =
				    (CK_OBJECT_HANDLE)obj;
				num_obj_found++;
			}
			(void) pthread_mutex_unlock(&obj->object_mutex);
		}
	}
	fcontext->next_result_index = i;
	*found_obj_count = num_obj_found;
	return (CKR_OK);
}

/*
 * Add an token object to the token object list in slot.
 *
 * This function will acquire the lock on the slot, and release
 * that lock after adding the object to the slot's token object list.
 */
void
kms_add_token_object_to_slot(kms_object_t *objp, kms_slot_t *pslot)
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
 * This routine is called by kms_delete_token_object().
 * The caller of this function hold the slot lock.
 */
void
kms_remove_token_object_from_slot(kms_slot_t *pslot,
    kms_object_t *objp)
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
			if (objp->prev)
				objp->prev->next = objp->next;
			objp->next->prev = objp->prev;
		} else if (objp->prev) {
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
kms_delete_token_object(kms_slot_t *pslot, kms_session_t *sp,
    kms_object_t *objp, boolean_t slot_lock_held, boolean_t wrapper_only)
{
	CK_RV rv = CKR_OK;

	if (!slot_lock_held) {
		(void) pthread_mutex_lock(&pslot->sl_mutex);
	}
	if (!wrapper_only && objp->class == CKO_SECRET_KEY) {
		/* Delete from KMS */
		rv = KMS_DestroyKey(sp, objp);
	}

	/* Remove the object from the slot's token object list first. */
	kms_remove_token_object_from_slot(pslot, objp);

	/* Release the slot lock if the call doesn't hold the lock. */
	if (!slot_lock_held) {
		(void) pthread_mutex_unlock(&pslot->sl_mutex);
	}

	kms_delete_object_cleanup(objp, wrapper_only);

	return (rv);
}

/*
 * Clean up private object wrappers in this slot. The caller holds the slot
 * lock.
 */
void
kms_cleanup_pri_objects_in_slot(kms_slot_t *pslot,
    kms_session_t *cur_sp)
{
	kms_session_t *session_p;
	kms_object_t *objp;
	kms_object_t *objp1;

	/*
	 * Delete every private token object from
	 * the slot token object list.
	 */
	(void) pthread_mutex_lock(&pslot->sl_mutex);
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
			(void) kms_delete_token_object(pslot, cur_sp, objp,
			    B_TRUE, B_TRUE);
		}
		objp = objp1;
	}

	(void) pthread_mutex_unlock(&pslot->sl_mutex);
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
				(void) kms_delete_object(session_p,
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
kms_get_object_size(kms_object_t *obj, CK_ULONG_PTR pulSize)
{
	CK_RV rv = CKR_OK;
	CK_ULONG obj_size;

	obj_size = sizeof (kms_object_t);

	switch (obj->class) {
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
