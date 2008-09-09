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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softObject.h"
#include "softSession.h"
#include "softKeystore.h"
#include "softKeystoreUtil.h"

/*
 * Add an object to the session's object list.
 *
 * This function will acquire the lock on the session, and release
 * that lock after adding the object to the session's object list.
 */
void
soft_add_object_to_session(soft_object_t *objp, soft_session_t *sp)
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
 * (by caller soft_delete_object()), or there is no object lock
 * yet (by soft_build_XXX_object() during creating an object).
 */
void
soft_cleanup_object(soft_object_t *objp)
{
	/*
	 * Free the storage allocated to big integer attributes.
	 */
	soft_cleanup_object_bigint_attrs(objp);

	/*
	 * Free the storage allocated to the extra attribute list.
	 */
	soft_cleanup_extra_attr(objp);

	/*
	 * Free the storage allocated to certificate attributes.
	 */
	soft_cleanup_cert_object(objp);
}


/*
 * Create a new object. Copy the attributes that can be modified
 * (in the boolean attribute mask field and extra attribute list)
 * from the old object to the new object.
 *
 * The caller of this function holds the lock on the old object.
 */
CK_RV
soft_copy_object(soft_object_t *old_object, soft_object_t **new_object,
    CK_ULONG object_func, soft_session_t *sp)
{

	CK_RV rv = CKR_OK;
	soft_object_t *new_objp = NULL;
	CK_ATTRIBUTE_INFO_PTR attrp;

	/* Allocate new object. */
	new_objp = calloc(1, sizeof (soft_object_t));
	if (new_objp == NULL)
		return (CKR_HOST_MEMORY);

	new_objp->class = old_object->class;
	new_objp->bool_attr_mask = old_object->bool_attr_mask;
	new_objp->cert_type = old_object->cert_type;
	new_objp->object_type = old_object->object_type;

	attrp = old_object->extra_attrlistp;
	while (attrp) {
		/*
		 * Copy the attribute_info struct from the old
		 * object to a new attribute_info struct, and add
		 * that new struct to the extra attribute list
		 * of the new object.
		 */
		rv = soft_copy_extra_attr(attrp, new_objp);
		if (rv != CKR_OK) {
			soft_cleanup_extra_attr(new_objp);
			free(new_objp);
			return (rv);
		}
		attrp = attrp->next;
	}

	*new_object = new_objp;

	if (object_func == SOFT_SET_ATTR_VALUE) {
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

	switch (object_func) {
	case SOFT_COPY_OBJ_ORIG_SH:
		new_objp->session_handle = old_object->session_handle;
		break;
	case SOFT_COPY_OBJECT:
		/*
		 * Save the session handle of the C_CopyObject function
		 * in the new copy of the session object.
		 */
		new_objp->session_handle = (CK_SESSION_HANDLE)sp;
		break;
	}

	(void) pthread_cond_init(&(new_objp->obj_free_cond), NULL);
	(void) pthread_mutex_init(&(new_objp->object_mutex), NULL);
	/* copy key related information */
	switch (new_objp->class) {
		case CKO_PUBLIC_KEY:
			rv = soft_copy_public_key_attr(OBJ_PUB(old_object),
			    &(OBJ_PUB(new_objp)), new_objp->key_type);
			break;
		case CKO_PRIVATE_KEY:
			rv = soft_copy_private_key_attr(OBJ_PRI(old_object),
			    &(OBJ_PRI(new_objp)), new_objp->key_type);
			break;
		case CKO_SECRET_KEY:
			rv = soft_copy_secret_key_attr(OBJ_SEC(old_object),
			    &(OBJ_SEC(new_objp)));
			break;
		case CKO_DOMAIN_PARAMETERS:
			rv = soft_copy_domain_attr(OBJ_DOM(old_object),
			    &(OBJ_DOM(new_objp)), new_objp->key_type);
			break;
		case CKO_CERTIFICATE:
			rv = soft_copy_certificate(OBJ_CERT(old_object),
			    &(OBJ_CERT(new_objp)), new_objp->cert_type);
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
		soft_cleanup_extra_attr(new_objp);
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
soft_merge_object(soft_object_t *old_object, soft_object_t *new_object)
{
	old_object->bool_attr_mask = new_object->bool_attr_mask;
	soft_cleanup_extra_attr(old_object);
	old_object->extra_attrlistp = new_object->extra_attrlistp;
}


/*
 * Create a new object struct, and add it to the session's object list.
 */
CK_RV
soft_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
	CK_ULONG *objecthandle_p, soft_session_t *sp)
{

	CK_RV rv = CKR_OK;
	soft_object_t *new_objp = NULL;

	new_objp = calloc(1, sizeof (soft_object_t));
	if (new_objp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	new_objp->extra_attrlistp = NULL;

	/*
	 * Validate attribute template and fill in the attributes
	 * in the soft_object_t.
	 */
	rv = soft_build_object(pTemplate, ulCount, new_objp);
	if (rv != CKR_OK) {
		goto fail_cleanup1;
	}

	rv = soft_pin_expired_check(new_objp);
	if (rv != CKR_OK) {
		goto fail_cleanup2;
	}

	rv = soft_object_write_access_check(sp, new_objp);
	if (rv != CKR_OK) {
		goto fail_cleanup2;
	}

	/* Initialize the rest of stuffs in soft_object_t. */
	(void) pthread_cond_init(&new_objp->obj_free_cond, NULL);
	(void) pthread_mutex_init(&new_objp->object_mutex, NULL);
	new_objp->magic_marker = SOFTTOKEN_OBJECT_MAGIC;
	new_objp->obj_refcnt = 0;
	new_objp->obj_delete_sync = 0;

	/* Write the new token object to the keystore */
	if (IS_TOKEN_OBJECT(new_objp)) {
		if (!soft_keystore_status(KEYSTORE_INITIALIZED)) {
			rv = CKR_DEVICE_REMOVED;
			goto fail_cleanup2;
		}
		new_objp->version = 1;
		rv = soft_put_object_to_keystore(new_objp);
		if (rv != CKR_OK) {
			(void) pthread_cond_destroy(&new_objp->obj_free_cond);
			(void) pthread_mutex_destroy(&new_objp->object_mutex);
			goto fail_cleanup2;
		}
		new_objp->session_handle = (CK_SESSION_HANDLE)NULL;
		soft_add_token_object_to_slot(new_objp);
		/*
		 * Type casting the address of an object struct to
		 * an object handle.
		 */
		*objecthandle_p = (CK_ULONG)new_objp;

		return (CKR_OK);
	}

	new_objp->session_handle = (CK_SESSION_HANDLE)sp;

	/* Add the new object to the session's object list. */
	soft_add_object_to_session(new_objp, sp);

	/* Type casting the address of an object struct to an object handle. */
	*objecthandle_p =  (CK_ULONG)new_objp;

	return (CKR_OK);

fail_cleanup2:
	/*
	 * When any error occurs after soft_build_object(), we will need to
	 * clean up the memory allocated by the soft_build_object().
	 */
	soft_cleanup_object(new_objp);

fail_cleanup1:
	if (new_objp) {
		/*
		 * The storage allocated inside of this object should have
		 * been cleaned up by the soft_build_object() if it failed.
		 * Therefore, we can safely free the object.
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
soft_remove_object_from_session(soft_object_t *objp, soft_session_t *sp)
{
	soft_object_t *tmp_objp;
	boolean_t found = B_FALSE;

	/*
	 * Remove the object from the session's object list.
	 */
	if ((sp == NULL) ||
	    (sp->magic_marker != SOFTTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	if ((sp->object_list == NULL) || (objp == NULL) ||
	    (objp->magic_marker != SOFTTOKEN_OBJECT_MAGIC)) {
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
object_delay_free(soft_object_t *objp)
{
	soft_object_t *tmp;

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

static void
soft_delete_object_cleanup(soft_object_t *objp)
{
	/* Acquire the lock on the object. */
	(void) pthread_mutex_lock(&objp->object_mutex);

	/*
	 * Make sure another thread hasn't freed the object.
	 */
	if (objp->magic_marker != SOFTTOKEN_OBJECT_MAGIC) {
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
	 */
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

	/*
	 * Cleanup the contents of this object such as free all the
	 * storage allocated for this object.
	 */
	soft_cleanup_object(objp);

	/* Reset OBJECT_IS_DELETING flag. */
	objp->obj_delete_sync &= ~OBJECT_IS_DELETING;

	(void) pthread_mutex_unlock(&objp->object_mutex);
	/* Destroy the object lock */
	(void) pthread_mutex_destroy(&objp->object_mutex);

	/* Free the object itself */
	if (IS_TOKEN_OBJECT(objp))
		free(objp);
	else
		/*
		 * Delay freeing the session object as S1WS/NSS uses session
		 * objects for its SSL Handshake.
		 */
		(void) object_delay_free(objp);
}

/*
 * Delete an object:
 * - Remove the object from the session's object list.
 *   Holding the lock on the session which the object was created at
 *   is needed to do this.
 * - Release the storage allocated to the object.
 *
 * The boolean argument lock_held is used to indicate that whether
 * the caller holds the session lock or not.
 * - When called by soft_delete_all_objects_in_session() -- the
 *   lock_held = TRUE.
 *
 * When the caller does not hold the session lock, this function
 * will acquire that lock in order to proceed, and also release
 * that lock before returning to caller.
 */
void
soft_delete_object(soft_session_t *sp, soft_object_t *objp, boolean_t lock_held)
{

	/*
	 * Check to see if the caller holds the lock on the session.
	 * If not, we need to acquire that lock in order to proceed.
	 */
	if (!lock_held) {
		/* Acquire the session lock. */
		(void) pthread_mutex_lock(&sp->session_mutex);
	}

	/* Remove the object from the session's object list first. */
	if (soft_remove_object_from_session(objp, sp) != CKR_OK) {
		if (!lock_held) {
			(void) pthread_mutex_unlock(&sp->session_mutex);
		}
		return;
	}

	if (!lock_held) {
		/*
		 * If the session lock is obtained by this function,
		 * then release that lock after removing the object
		 * from session's object list.
		 * We want the releasing of the object storage to
		 * be done without holding the session lock.
		 */
		(void) pthread_mutex_unlock(&sp->session_mutex);
	}

	soft_delete_object_cleanup(objp);
}


/*
 * Delete all the objects in a session. The caller holds the lock
 * on the session.
 */
void
soft_delete_all_objects_in_session(soft_session_t *sp)
{
	soft_object_t *objp = sp->object_list;
	soft_object_t *objp1;

	/* Delete all the objects in the session. */
	while (objp) {
		objp1 = objp->next;

		/*
		 * Delete an object by calling soft_delete_object()
		 * with a TRUE boolean argument indicating that
		 * the caller holds the lock on the session.
		 */
		soft_delete_object(sp, objp, B_TRUE);

		objp = objp1;
	}
}

static CK_RV
add_to_search_result(soft_object_t *obj, find_context_t *fcontext,
    CK_ULONG *num_result_alloc)
{
	/*
	 * allocate space for storing results if the currently
	 * allocated space is not enough
	 */
	if (*num_result_alloc <= fcontext->num_results) {
		fcontext->objs_found = realloc(fcontext->objs_found,
		    sizeof (soft_object_t *) * (*num_result_alloc + BUFSIZ));
		if (fcontext->objs_found == NULL) {
			return (CKR_HOST_MEMORY);
		}
		*num_result_alloc += BUFSIZ;
	}

	(fcontext->objs_found)[(fcontext->num_results)++] = obj;
	return (CKR_OK);
}

static CK_RV
search_for_objects(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    find_context_t *fcontext)
{
	soft_session_t *session_p;
	soft_object_t *obj;
	CK_OBJECT_CLASS pclasses[6]; /* classes attrs possibly exist */
	CK_ULONG num_pclasses;	/* number of possible classes */
	CK_ULONG num_result_alloc = 0; /* spaces allocated for results */
	CK_RV rv = CKR_OK;
	/* whether CKA_TOKEN flag specified or not */
	boolean_t token_specified = B_FALSE;
	/* value of CKA_TOKEN flag, if specified */
	boolean_t token_flag_val = B_FALSE;
	CK_ULONG i;

	if (ulCount > 0) {
		/* there are some search requirement */
		soft_process_find_attr(pclasses, &num_pclasses,
		    pTemplate, ulCount);
	}

	for (i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == CKA_PRIVATE) {
			(void) pthread_mutex_lock(&soft_giant_mutex);
			if (soft_slot.userpin_change_needed) {
				(void) pthread_mutex_unlock(&soft_giant_mutex);
				return (CKR_PIN_EXPIRED);
			}
			(void) pthread_mutex_unlock(&soft_giant_mutex);
		}
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

	/*
	 * Need go through token objects if it explicitly say so, or
	 * it is not mentioned in the template.  And this will ONLY be
	 * done when the keystore exists. Otherwise, we will skip re-loading
	 * the token objects.
	 *
	 * If a session has not logged into the token, only public
	 * objects, if any, will be searched.  If a session is logged
	 * into the token, all public and private objects in the keystore
	 * are searched.
	 */
	if (((token_flag_val) || (!token_specified)) &&
	    soft_keystore_status(KEYSTORE_INITIALIZED)) {
		/* acquire token session lock */
		(void) pthread_mutex_lock(&soft_slot.slot_mutex);
		rv = refresh_token_objects();
		if (rv != CKR_OK) {
			(void) pthread_mutex_unlock(&soft_slot.slot_mutex);
			return (rv);
		}
		obj = soft_slot.token_object_list;
		while (obj) {
			(void) pthread_mutex_lock(&obj->object_mutex);
			if (((token_specified) && (ulCount > 1)) ||
			    ((!token_specified) && (ulCount > 0))) {
				if (soft_find_match_attrs(obj, pclasses,
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
				(void) pthread_mutex_unlock
				    (&soft_slot.slot_mutex);
				return (rv);
			}
			obj = obj->next;
		}
		(void) pthread_mutex_unlock(&soft_slot.slot_mutex);
	}

	if (token_flag_val) {
		/* no need to look through session objects */
		return (rv);
	}

	/* Acquire the global session list lock */
	(void) pthread_mutex_lock(&soft_sessionlist_mutex);

	/*
	 * Go through all objects in each session.
	 * Acquire individual session lock for the session
	 * we are searching.
	 */
	session_p = soft_session_list;
	while (session_p) {
		(void) pthread_mutex_lock(&session_p->session_mutex);

		obj = session_p->object_list;
		while (obj) {
			(void) pthread_mutex_lock(&obj->object_mutex);
			if (ulCount > 0) {
				if (soft_find_match_attrs(obj, pclasses,
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
	/* Release the global session list lock */
	(void) pthread_mutex_unlock(&soft_sessionlist_mutex);
	return (rv);
}

/*
 * Initialize the context for C_FindObjects() calls
 */
CK_RV
soft_find_objects_init(soft_session_t *sp, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{

	CK_RV rv = CKR_OK;
	CK_OBJECT_CLASS class; /* for soft_validate_attr(). Value unused */
	find_context_t *fcontext;

	if (ulCount) {
		rv = soft_validate_attr(pTemplate, ulCount, &class);
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

	rv = search_for_objects(pTemplate, ulCount, fcontext);
	if (rv != CKR_OK) {
		free(fcontext);
		return (rv);
	}

	/* store the find_context in the session */
	sp->find_objects.context = (CK_VOID_PTR)fcontext;

	return (rv);
}

void
soft_find_objects_final(soft_session_t *sp)
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
soft_find_objects(soft_session_t *sp, CK_OBJECT_HANDLE *obj_found,
    CK_ULONG max_obj_requested, CK_ULONG *found_obj_count)
{
	find_context_t *fcontext;
	CK_ULONG num_obj_found = 0;
	CK_ULONG i;
	soft_object_t *obj;

	fcontext = sp->find_objects.context;

	for (i = fcontext->next_result_index;
	    ((num_obj_found < max_obj_requested) &&
	    (i < fcontext->num_results));
	    i++) {
		obj = fcontext->objs_found[i];
		if (obj != NULL) {
			(void) pthread_mutex_lock(&obj->object_mutex);
			/* a sanity check to make sure the obj is still valid */
			if (obj->magic_marker == SOFTTOKEN_OBJECT_MAGIC) {
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
 * Below are the token object related functions
 */
void
soft_add_token_object_to_slot(soft_object_t *objp)
{

	(void) pthread_mutex_lock(&soft_slot.slot_mutex);

	/* Insert the new object in front of slot's token object list. */
	if (soft_slot.token_object_list == NULL) {
		soft_slot.token_object_list = objp;
		objp->next = NULL;
		objp->prev = NULL;
	} else {
		soft_slot.token_object_list->prev = objp;
		objp->next = soft_slot.token_object_list;
		objp->prev = NULL;
		soft_slot.token_object_list = objp;
	}

	(void) pthread_mutex_unlock(&soft_slot.slot_mutex);

}

void
soft_remove_token_object_from_slot(soft_object_t *objp, boolean_t lock_held)
{

	if (!lock_held)
		(void) pthread_mutex_lock(&soft_slot.slot_mutex);

	/*
	 * Remove the object from the slot's token object list.
	 */
	if (soft_slot.token_object_list == objp) {
		/* Object is the first one in the list. */
		if (objp->next) {
			soft_slot.token_object_list = objp->next;
			objp->next->prev = NULL;
		} else {
			/* Object is the only one in the list. */
			soft_slot.token_object_list = NULL;
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

	if (!lock_held)
		(void) pthread_mutex_unlock(&soft_slot.slot_mutex);
}

void
soft_delete_token_object(soft_object_t *objp, boolean_t persistent,
    boolean_t lock_held)
{

	if (!lock_held)
		(void) pthread_mutex_lock(&soft_slot.slot_mutex);
	if (persistent)
		/* Delete the object from the keystore. */
		(void) soft_keystore_del_obj(&objp->ks_handle, B_FALSE);

	/* Remove the object from the slot's token object list. */
	soft_remove_token_object_from_slot(objp, B_TRUE);
	if (!lock_held)
		(void) pthread_mutex_unlock(&soft_slot.slot_mutex);

	soft_delete_object_cleanup(objp);
}

void
soft_delete_all_in_core_token_objects(token_obj_type_t type)
{

	soft_object_t *objp;
	soft_object_t *objp1;

	(void) pthread_mutex_lock(&soft_slot.slot_mutex);
	objp = soft_slot.token_object_list;

	switch (type) {
	case PRIVATE_TOKEN:
		while (objp) {
			objp1 = objp->next;
			if (objp->object_type == TOKEN_PRIVATE) {
				soft_delete_token_object(objp, B_FALSE, B_TRUE);
			}
			objp = objp1;
		}
		break;

	case PUBLIC_TOKEN:
		while (objp) {
			objp1 = objp->next;
			if (objp->object_type == TOKEN_PUBLIC) {
				soft_delete_token_object(objp, B_FALSE, B_TRUE);
			}
			objp = objp1;
		}
		break;

	case ALL_TOKEN:
		while (objp) {
			objp1 = objp->next;
			soft_delete_token_object(objp, B_FALSE, B_TRUE);
			objp = objp1;
		}
		break;
	}

	(void) pthread_mutex_unlock(&soft_slot.slot_mutex);

}

/*
 * Mark all the token objects in the global list to be valid.
 */
void
soft_validate_token_objects(boolean_t validate)
{

	soft_object_t *objp;

	(void) pthread_mutex_lock(&soft_slot.slot_mutex);

	objp = soft_slot.token_object_list;

	while (objp) {
		if (validate)
			objp->magic_marker = SOFTTOKEN_OBJECT_MAGIC;
		else
			objp->magic_marker = 0;

		objp = objp->next;
	}

	(void) pthread_mutex_unlock(&soft_slot.slot_mutex);

}

/*
 * Verify user's write access rule to the token object.
 */
CK_RV
soft_object_write_access_check(soft_session_t *sp, soft_object_t *objp)
{

	/*
	 * This function is called by C_CreateObject, C_CopyObject,
	 * C_DestroyObject, C_SetAttributeValue, C_GenerateKey,
	 * C_GenerateKeyPairs, C_DeriveKey. All of them will write
	 * the token object to the keystore.
	 */
	(void) pthread_mutex_lock(&soft_giant_mutex);
	if (!soft_slot.authenticated) {
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		/* User is not logged in */
		if (sp->flags & CKF_RW_SESSION) {
			/*
			 * For R/W Public Session:
			 * we allow write access to public session or token
			 * object, but not for private token/session object.
			 */
			if ((objp->object_type == TOKEN_PRIVATE) ||
			    (objp->object_type == SESSION_PRIVATE)) {
				return (CKR_USER_NOT_LOGGED_IN);
			}
		} else {
			/*
			 * For R/O Public Session:
			 * we allow write access to public session object.
			 */
			if (objp->object_type != SESSION_PUBLIC)
				return (CKR_SESSION_READ_ONLY);
		}
	} else {
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		/* User is logged in */
		if (!(sp->flags & CKF_RW_SESSION)) {
			/*
			 * For R/O User Function Session:
			 * we allow write access to public or private
			 * session object, but not for public or private
			 * token object.
			 */
			if ((objp->object_type == TOKEN_PUBLIC) ||
			    (objp->object_type == TOKEN_PRIVATE)) {
				return (CKR_SESSION_READ_ONLY);
			}
		}
	}

	return (CKR_OK);
}

/*
 * Verify if user is required to setpin when accessing the
 * private token/session object.
 */
CK_RV
soft_pin_expired_check(soft_object_t *objp)
{

	/*
	 * This function is called by C_CreateObject, C_CopyObject,
	 * C_DestroyObject, C_GenerateKey,
	 * C_GenerateKeyPairs, C_DeriveKey.
	 * All of them will return CKR_PIN_EXPIRED if the
	 * "userpin_change_needed" is set.
	 *
	 * The following functions will not be necessary to call
	 * this routine even though CKR_PIN_EXPIRED is one of the
	 * valid error code they might return. These functions are:
	 * C_EncryptInit, C_DecryptInit, C_DigestInit, C_SignInit,
	 * C_SignRecoverInit, C_VerifyInit, C_VerifyRecoverInit.
	 * This is because they will not get the object handle
	 * before the above functions are called.
	 */

	(void) pthread_mutex_lock(&soft_giant_mutex);
	if (soft_slot.userpin_change_needed) {
		/*
		 * Access private token/session object but user's
		 * PIN is expired or never set.
		 */
		if ((objp->object_type == TOKEN_PRIVATE) ||
		    (objp->object_type == SESSION_PRIVATE)) {
			(void) pthread_mutex_unlock(&soft_giant_mutex);
			return (CKR_PIN_EXPIRED);
		}
	}

	(void) pthread_mutex_unlock(&soft_giant_mutex);
	return (CKR_OK);
}

/*
 * Copy the selected fields from new token object to old
 * token object.
 */
CK_RV
soft_copy_to_old_object(soft_object_t *new, soft_object_t *old)
{

	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE_INFO_PTR attrp;

	old->class = new->class;
	old->bool_attr_mask = new->bool_attr_mask;
	soft_cleanup_extra_attr(old);
	attrp = new->extra_attrlistp;
	while (attrp) {
		rv = soft_copy_extra_attr(attrp, old);
		if (rv != CKR_OK) {
			soft_cleanup_extra_attr(old);
			return (rv);
		}
		attrp = attrp->next;
	}

	/* Done with copying all information that can be modified */
	return (CKR_OK);
}

/*
 * Update an existing object with new data from keystore.
 */
CK_RV
soft_update_object(ks_obj_t *ks_obj, soft_object_t *old_obj)
{

	soft_object_t *new_object;
	CK_RV rv;

	new_object = calloc(1, sizeof (soft_object_t));
	if (new_object == NULL)
		return (CKR_HOST_MEMORY);

	rv = soft_keystore_unpack_obj(new_object, ks_obj);
	if (rv != CKR_OK) {
		soft_cleanup_object(new_object);
		free(new_object);
		return (rv);
	}
	rv = soft_copy_to_old_object(new_object, old_obj);

	soft_cleanup_object(new_object);
	free(new_object);
	return (CKR_OK);
}


CK_RV
soft_keystore_load_latest_object(soft_object_t *old_obj)
{

	uint_t version;
	ks_obj_t *ks_obj = NULL;
	CK_RV rv = CKR_OK;

	/*
	 * Get the current version number from the keystore for
	 * the specified token object.
	 */
	if (soft_keystore_get_object_version(&old_obj->ks_handle, &version,
	    B_FALSE) == 1)
		return (CKR_FUNCTION_FAILED);

	/*
	 * If the keystore version is newer than the in-core version,
	 * re-read the token object from the keystore.
	 */
	if (old_obj->version != version) {
		rv = soft_keystore_get_single_obj(&old_obj->ks_handle,
		    &ks_obj, B_FALSE);
		if (rv != CKR_OK)
			return (rv);
		old_obj->version = version;

		/*
		 * Update an existing object with new data from keystore.
		 */
		rv = soft_update_object(ks_obj, old_obj);
		free(ks_obj->buf);
		free(ks_obj);
	}

	return (rv);
}

/*
 * Insert an object into a list of soft_object_t objects.  It is assumed
 * that the object to be inserted doesn't previously belong to any list
 */
static void
insert_into_list(soft_object_t **list, soft_object_t **end_of_list,
    soft_object_t *objp)
{
	if (*list == NULL) {
		*list = objp;
		objp->next = NULL;
		objp->prev = NULL;
		*end_of_list = objp;
	} else {
		(*list)->prev = objp;
		objp->next = *list;
		objp->prev = NULL;
		*list = objp;
	}
}

/*
 * Move an object from an existing list into a new list of
 * soft_object_t objects.
 */
static void
move_into_list(soft_object_t **existing_list, soft_object_t **new_list,
    soft_object_t **end_of_list, soft_object_t *objp)
{

	/* first, remove object from existing list */
	if (objp == *existing_list) {
		/* first item in list */
		if (objp->next) {
			*existing_list = objp->next;
			objp->next->prev = NULL;
		} else {
			*existing_list = NULL;
		}
	} else {
		if (objp->next) {
			objp->prev->next = objp->next;
			objp->next->prev = objp->prev;
		} else {
			objp->prev->next = NULL;
		}
	}

	/* then, add into new list */
	insert_into_list(new_list, end_of_list, objp);
}

/*
 * Insert "new_list" into "existing_list", new list will always be inserted
 * into the front of existing list
 */
static void
insert_list_into_list(soft_object_t **existing_list,
    soft_object_t *new_list, soft_object_t *end_new_list)
{

	if (new_list == NULL) {
		return;
	}

	if (*existing_list == NULL) {
		*existing_list = new_list;
	} else {
		(*existing_list)->prev = end_new_list;
		end_new_list->next = *existing_list;
		*existing_list = new_list;
	}
}

static void
delete_all_objs_in_list(soft_object_t *list)
{
	soft_object_t *objp, *objp_next;

	if (list == NULL) {
		return;
	}

	objp = list;
	while (objp) {
		objp_next = objp->next;
		soft_delete_object_cleanup(objp);
		objp = objp_next;
	}
}

/*
 * Makes sure that the list of in-core token objects are up to date
 * with respect to the on disk keystore.  Other process/applications
 * might have modified the keystore since the objects are last loaded
 *
 * If there's any error from refreshing the token object list (eg: unable
 * to read, unable to unpack and object...etc), the in-core list
 * will be restored back to the state before the refresh.  An error
 * will be returned to indicate the failure.
 *
 * It is assumed that the caller holds the lock for the token slot
 */
CK_RV
refresh_token_objects()
{
	uint_t on_disk_ks_version;
	ks_obj_t *on_disk_list = NULL, *tmp_on_disk, *next_on_disk;
	soft_object_t *in_core_obj, *tmp_incore_obj, *new_objp = NULL;
	CK_RV rv = CKR_OK;

	/* deleted in-core objects */
	soft_object_t *del_objs_list = NULL;
	soft_object_t *end_del_objs_list = NULL;

	/* modified in-core objects */
	soft_object_t *mod_objs_list = NULL;
	soft_object_t *end_mod_objs_list = NULL;

	/*
	 * copy of modified in-core objects, in case we need
	 * undo the change
	 */
	soft_object_t *copy_of_mod_objs_list = NULL;
	soft_object_t *end_copy_of_mod_objs_list = NULL;

	/* objects to be added to the in-core list */
	soft_object_t *added_objs_list = NULL;
	soft_object_t *end_added_objs_list = NULL;

	if (soft_keystore_get_version(&on_disk_ks_version, B_FALSE) != 0) {
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_lock(&soft_giant_mutex);
	if (on_disk_ks_version == soft_slot.ks_version) {
		/* no change */
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		return (CKR_OK);
	}

	if (soft_slot.authenticated) {
		/* get both public and private objects */
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		rv = soft_keystore_get_objs(ALL_TOKENOBJS, &on_disk_list,
		    B_FALSE);
	} else {
		/* get both public objects only */
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		rv = soft_keystore_get_objs(PUB_TOKENOBJS, &on_disk_list,
		    B_FALSE);
	}
	if (rv != CKR_OK) {
		return (rv);
	}

	/*
	 * The in-core tokens list will be updated as follows:
	 *
	 * Go through each item in the in-core tokens list.
	 * Try to match the in-core object with one of the
	 * objects from the on-disk list.  If a match is made,
	 * check the version number, and update in-core object
	 * as necessary.
	 *
	 * If there's no match between in-core object with on-disk
	 * object, that means the object is deleted since
	 * last loaded.  Will remove object from in-core list.
	 *
	 * When doing the matching of on-disk object list above,
	 * Delete every matched on-disk object from the on-disk list
	 * regardless the in-core object need to be deleted or not
	 *
	 * At the end of matching the in-core tokens list, if
	 * any object is still left on the on-disk object list,
	 * those are all new objects added since last load,
	 * include all of them to the in-core list
	 *
	 * Since we need to be able to revert the in-core list
	 * back to original state if there's any error with the refresh,
	 * we need to do the following.
	 * When an in-core object is "deleted", it is not immediately
	 * deleted.  It is moved to the list of "deleted_objects".
	 * When an in-core object is "modified", a copy of the
	 * unmodified object is made.  After the object is modified,
	 * it is temporarily moved to the "mod_objects" list
	 * from the in-core list.
	 * When the refresh is completed without any error,
	 * the actual deleted objects and unmodified objects is deleted.
	 */
	in_core_obj = soft_slot.token_object_list;
	while (in_core_obj) {
		/* try to match object with on_disk_list */
		ks_obj_t *ondisk_obj, *prev_ondisk_obj;
		boolean_t found = B_FALSE;
		soft_object_t *obj_copy;

		ondisk_obj = on_disk_list;
		prev_ondisk_obj = NULL;

		/* larval object that has not been written to disk */
		if (in_core_obj->ks_handle.name[0] == '\0') {
			in_core_obj = in_core_obj->next;
			continue;
		}

		while ((!found) && (ondisk_obj != NULL)) {

			if (strcmp((char *)((ondisk_obj->ks_handle).name),
			    (char *)((in_core_obj->ks_handle).name)) == 0) {

				/* found a match */
				found = B_TRUE;

				/* update in-core obj if necessary */
				if (ondisk_obj->obj_version !=
				    in_core_obj->version) {
					/* make a copy of before updating */
					rv = soft_copy_object(in_core_obj,
					    &obj_copy, SOFT_COPY_OBJ_ORIG_SH,
					    NULL);
					if (rv != CKR_OK) {
						goto cleanup;
					}
					insert_into_list(
					    &copy_of_mod_objs_list,
					    &end_copy_of_mod_objs_list,
					    obj_copy);

					rv = soft_update_object(ondisk_obj,
					    in_core_obj);
					if (rv != CKR_OK) {
						goto cleanup;
					}
					move_into_list(
					    &(soft_slot.token_object_list),
					    &mod_objs_list, &end_mod_objs_list,
					    in_core_obj);
				}

				/* remove processed obj from on disk list */
				if (ondisk_obj == on_disk_list) {
					/* first item */
					on_disk_list = ondisk_obj->next;
				} else {
					prev_ondisk_obj->next =
					    ondisk_obj->next;
				}
				free(ondisk_obj->buf);
				free(ondisk_obj);
			} else {
				prev_ondisk_obj = ondisk_obj;
				ondisk_obj = ondisk_obj->next;
			}
		}

		if (!found) {
			tmp_incore_obj = in_core_obj->next;
			move_into_list(&(soft_slot.token_object_list),
			    &del_objs_list, &end_del_objs_list, in_core_obj);
			in_core_obj = tmp_incore_obj;
		} else {
			in_core_obj = in_core_obj->next;
		}
	}

	/*
	 * At this point, if there's still anything on the on_disk_list, they
	 * are all newly added objects since in-core list last loaded.
	 * include all of them into the in-core list
	 */
	next_on_disk = on_disk_list;
	while (next_on_disk) {
		new_objp = calloc(1, sizeof (soft_object_t));
		if (new_objp == NULL) {
			rv = CKR_HOST_MEMORY;
			goto cleanup;
		}

		/* Convert the keystore format to memory format */
		rv = soft_keystore_unpack_obj(new_objp, next_on_disk);
		if (rv != CKR_OK) {
			soft_cleanup_object(new_objp);
			free(new_objp);
			goto cleanup;
		}

		insert_into_list(&added_objs_list, &end_added_objs_list,
		    new_objp);

		/* free the on_disk object */
		tmp_on_disk = next_on_disk;
		next_on_disk = tmp_on_disk->next;
		free(tmp_on_disk->buf);
		free(tmp_on_disk);
	}

	if (rv == CKR_OK) {
		(void) pthread_mutex_lock(&soft_giant_mutex);
		soft_slot.ks_version = on_disk_ks_version;
		(void) pthread_mutex_unlock(&soft_giant_mutex);

		/* add the new objects into in-core list */
		insert_list_into_list(&(soft_slot.token_object_list),
		    added_objs_list, end_added_objs_list);

		/* add modified objects back into the in-core list */
		insert_list_into_list(&(soft_slot.token_object_list),
		    mod_objs_list, end_mod_objs_list);

		/* actually remove deleted objs, and copy of modified objs */
		delete_all_objs_in_list(copy_of_mod_objs_list);
		delete_all_objs_in_list(del_objs_list);
	}

	return (rv);

cleanup:
	next_on_disk = on_disk_list;
	while (next_on_disk) {
		tmp_on_disk = next_on_disk;
		next_on_disk = tmp_on_disk->next;
		free(tmp_on_disk->buf);
		free(tmp_on_disk);
	}

	/*
	 * restore the in-core list back to the original state by adding
	 * copy of original objects and deleted objects back to list
	 */
	insert_list_into_list(&(soft_slot.token_object_list),
	    del_objs_list, end_del_objs_list);
	insert_list_into_list(&(soft_slot.token_object_list),
	    copy_of_mod_objs_list, end_copy_of_mod_objs_list);

	/*
	 * remove the modified objects, and newly objects list
	 */
	delete_all_objs_in_list(mod_objs_list);
	delete_all_objs_in_list(added_objs_list);
	return (rv);
}
