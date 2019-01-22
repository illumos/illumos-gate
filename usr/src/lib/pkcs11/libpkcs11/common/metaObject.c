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

/*
 * Object Management Functions
 * (as defined in PKCS#11 spec section 11.7)
 */

#include <strings.h>
#include "metaGlobal.h"
#include <stdio.h>

#define	FIND_OBJ_BUF_SIZE	512	/* size of buf used for C_FindObjects */

/*
 * Argument related return codes. Will return to the caller immediately,
 * and not try the operation on another slot.
 */
static CK_RV stop_rv[] = {
	CKR_ARGUMENTS_BAD,
	CKR_ATTRIBUTE_TYPE_INVALID,
	CKR_DOMAIN_PARAMS_INVALID,
	CKR_TEMPLATE_INCOMPLETE
};
static int num_stop_rv = sizeof (stop_rv) / sizeof (CK_RV);

/*
 * Return codes that are related to a specific slot.
 * Will try to perform the operation in the next available slot.
 * If all attempts failed, will return the error code from the first slot.
 *
 * This list is here for reference only, it is commented out because
 * it doesn't need to be used by the code at this point.
 *
 * static CK_RV try_again_rv[] = {
 *	CKR_DEVICE_ERROR,
 *	CKR_DEVICE_MEMORY,
 *	CKR_DEVICE_REMOVED,
 *	CKR_FUNCTION_FAILED,
 *	CKR_GENERAL_ERROR,
 *	CKR_HOST_MEMORY,
 *	CKR_TEMPLATE_INCONSISTENT,
 *	CKR_ATTRIBUTE_READ_ONLY,
 *	CKR_ATTRIBUTE_VALUE_INVALID
 * };
 * static int num_try_again_rv = sizeof (try_again_rv) / sizeof (CK_RV);
 */

/*
 * We should never get these return codes because
 * MetaSlot is the one that actually created the
 * sessions.  When we get these errors in C_CreateObject,
 * will try to create the object in the next available slot.
 * If all attempts failed, will return CKR_FUNCTION_FAILED
 * to the caller.
 */
static CK_RV other_rv[] = {
	CKR_CRYPTOKI_NOT_INITIALIZED,
	CKR_SESSION_CLOSED,
	CKR_SESSION_HANDLE_INVALID,
	CKR_SESSION_READ_ONLY
};
static int num_other_rv = sizeof (other_rv) / sizeof (CK_RV);

/*
 * This function is only used by the C_CreateObject and C_CopyObject.
 *
 * It is used to determine if the operation should be tried on another slot
 * based on the return code
 */
static boolean_t
try_again(CK_RV rv)
{
	int i;

	for (i = 0; i < num_stop_rv; i++) {
		if (rv == stop_rv[i]) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}


/*
 * meta_CreateObject
 *
 */
CK_RV
meta_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv;
	meta_session_t *session;
	slot_session_t *slot_session = NULL;
	meta_object_t *object = NULL;
	slot_object_t *slot_object = NULL;
	CK_OBJECT_HANDLE hNewObject;
	CK_ULONG slot_num, keystore_slotnum;
	CK_RV first_rv;

	if (pTemplate == NULL || ulCount < 1 || phObject == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_object_alloc(session, &object);
	if (rv != CKR_OK)
		goto cleanup;

	/*
	 * Create a clone of the object
	 */
	rv = meta_slot_object_alloc(&slot_object);
	if (rv != CKR_OK)
		goto cleanup;

	/*
	 * Set to true (token object) if template has CKA_TOKEN=true;
	 * otherwise, it is false (session object).
	 */
	(void) get_template_boolean(CKA_TOKEN, pTemplate, ulCount,
	    &(object->isToken));

	/* Can't create token objects in a read-only session. */
	if ((IS_READ_ONLY_SESSION(session->session_flags)) && object->isToken) {
		rv = CKR_SESSION_READ_ONLY;
		goto cleanup;
	}

	/*
	 * Set to true (private object) if template has CKA_PRIVATE=true;
	 * otherwise, it is false (public object).
	 */
	(void) get_template_boolean(CKA_PRIVATE, pTemplate, ulCount,
	    &(object->isPrivate));

	/* Assume object is extractable unless template has otherwise */
	object->isExtractable = B_TRUE;
	(void) get_template_boolean(CKA_EXTRACTABLE, pTemplate, ulCount,
	    &(object->isExtractable));

	/*
	 * Set to true (sensitive object) if template has CKA_SENSITIVE=true;
	 * otherwise, it is false.
	 */
	(void) get_template_boolean(CKA_SENSITIVE, pTemplate, ulCount,
	    &(object->isSensitive));

	/*
	 * Check if this can be a FreeObject.
	 *
	 * For creating objects, this check is mostly for preventing
	 * non-keystore hardware from creating CKA_PRIVATE objects without
	 * logging in.
	 */

	if (meta_freeobject_check(session, object, NULL, pTemplate, ulCount,
	    0)) {
		/*
		 * Make sure we are logged into the keystore if this is a
		 * private freetoken object.
		 */
		if (object->isPrivate && !metaslot_logged_in())
			return (CKR_USER_NOT_LOGGED_IN);

		if (!meta_freeobject_set(object, pTemplate, ulCount, B_TRUE))
			goto cleanup;
	}


	keystore_slotnum = get_keystore_slotnum();

	if (object->isToken || object->isFreeToken == FREE_ENABLED) {

		/*
		 * If this is a token object or a FreeToken then create it
		 * on the keystore slot.
		 */

		slot_num = keystore_slotnum;
		rv = meta_get_slot_session(slot_num, &slot_session,
		    session->session_flags);
		if (rv != CKR_OK)
			goto cleanup;

		object->tried_create_clone[slot_num] = B_TRUE;
		rv = FUNCLIST(slot_session->fw_st_id)->C_CreateObject(
		    slot_session->hSession, pTemplate, ulCount, &hNewObject);

		if (rv != CKR_OK)
			goto cleanup;

	} else {

		/*
		 * Create a clone of the object in the first available slot.
		 *
		 * If creating a clone in a specific slot failed, it will
		 * either stop and return the error to the user, or try
		 * again in the next available slot until it succeeds.  The
		 * decision to stop or continue is made based on the return
		 * code.
		 */
		CK_ULONG num_slots = meta_slotManager_get_slotcount();

		for (slot_num = 0; slot_num < num_slots; slot_num++) {
			/*
			 * If this is a free token and we are on the keystore
			 * slot, bypass this because it was already created
			 */

			rv = meta_get_slot_session(slot_num, &slot_session,
			    session->session_flags);
			if (rv != CKR_OK)
				goto cleanup;

			object->tried_create_clone[slot_num] = B_TRUE;
			rv = FUNCLIST(slot_session->fw_st_id)->C_CreateObject(
			    slot_session->hSession, pTemplate, ulCount,
			    &hNewObject);
			if (rv == CKR_OK)
				break;

			if (!try_again(rv))
				goto cleanup;

			/* save first rv for other errors */
			if (slot_num == 0)
				first_rv = rv;

			meta_release_slot_session(slot_session);
			slot_session = NULL;

		}
	}

	if (rv == CKR_OK) {
		slot_object->hObject = hNewObject;
		object->clones[slot_num] = slot_object;
		object->master_clone_slotnum = slot_num;

		/* Allow FreeToken to activate onto token obj list */
		if (object->isFreeToken == FREE_ENABLED)
			object->isToken = B_TRUE;

		meta_slot_object_activate(slot_object, slot_session,
		    object->isToken);

		slot_object = NULL;
		meta_release_slot_session(slot_session);
		slot_session = NULL;

	} else {
		/*
		 * return either first error code or
		 * CKR_FUNCTION_FAILED depending on the failure
		 */
		int i;
		for (i = 0; i < num_other_rv; i++) {
			if (rv == other_rv[i]) {
				rv = CKR_FUNCTION_FAILED;
				goto cleanup;
			}
		}
		/* need to return first rv */
		rv = first_rv;
		goto cleanup;
	}


	/*
	 * always keep a copy of the template for C_CreateObject,
	 * so clones can be created on other slots if necessary.
	 * This is done even when the CKA_EXTRACTABLE=FALSE flag
	 * is set for the object.  The supplied template is
	 * "owned" by metaslot.  The application should not be
	 * penalized just because metaslot choose to try creating
	 * the object in a slot that's not capable of performing
	 * any future operation.
	 */
	rv = get_master_attributes_by_template(pTemplate, ulCount,
	    &object->attributes, &object->num_attributes);
	if (rv == CKR_OK) {
		CK_ULONG i;
		for (i = 0; i < ulCount; i++) {
			rv = attribute_set_value(&(pTemplate[i]),
			    object->attributes, object->num_attributes);
		}
	}

	meta_object_activate(object);
	*phObject = (CK_OBJECT_HANDLE) object;

	REFRELEASE(session);

	return (CKR_OK);

cleanup:
	if (slot_object)
		meta_slot_object_dealloc(slot_object);
	if (slot_session)
		meta_release_slot_session(slot_session);
	if (object)
		(void) meta_object_dealloc(session, object, B_TRUE);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_CopyObject
 *
 */
CK_RV
meta_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_RV rv, first_rv;
	meta_session_t *session;
	meta_object_t *src_object, *dst_object = NULL;
	slot_session_t *slot_session = NULL;
	slot_object_t *dst_slot_object = NULL;
	CK_ULONG i;
	slot_object_t *src_slot_object;
	CK_ULONG slotnum, num_slots;
	boolean_t found;

	if (pTemplate == NULL && ulCount != 0)
		return (CKR_ARGUMENTS_BAD);
	if (phNewObject == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hObject, &src_object);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_object_alloc(session, &dst_object);
	if (rv != CKR_OK)
		goto finish;

	found = get_template_boolean(CKA_TOKEN,
	    pTemplate, ulCount, &(dst_object->isToken));
	if (!found) {
		dst_object->isToken = src_object->isToken;
		if (src_object->isFreeToken == FREE_ENABLED)
			dst_object->isToken = TRUE;
		else
			dst_object->isToken = src_object->isToken;
	}

	/* Can't create token objects in a read-only session. */
	if ((IS_READ_ONLY_SESSION(session->session_flags)) &&
	    (dst_object->isToken)) {
		rv = CKR_SESSION_READ_ONLY;
		goto finish;
	}

	if (dst_object->isToken) {

		/*
		 * if the dst object is a token object, and the source
		 * object is not, the source object needs to be extractable.
		 * Otherwise, the source object needs to reside in the
		 * token object slot
		 */
		if ((!src_object->isExtractable) &&
		    (src_object->master_clone_slotnum
		    != get_keystore_slotnum())) {
			rv = CKR_FUNCTION_FAILED;
			goto finish;
		}

		/* determine if dst is going to be private object or not */
		found = get_template_boolean(CKA_PRIVATE,
		    pTemplate, ulCount, &(dst_object->isPrivate));
		if (!found) {
			/* will be the same as the source object */
			dst_object->isPrivate = src_object->isPrivate;
		}

		slotnum = get_keystore_slotnum();
	} else {

		/* try create the obj in the same slot as the source obj */
		slotnum = src_object->master_clone_slotnum;
	}

	rv = meta_slot_object_alloc(&dst_slot_object);
	if (rv != CKR_OK)
		goto finish;

	rv = meta_get_slot_session(slotnum, &slot_session,
	    session->session_flags);
	if (rv != CKR_OK)
		goto finish;

	rv = meta_object_get_clone(src_object, slotnum,
	    slot_session, &src_slot_object);
	if (rv != CKR_OK)
		goto finish;

	dst_object->tried_create_clone[slotnum] = B_TRUE;
	rv = FUNCLIST(slot_session->fw_st_id)->C_CopyObject(
	    slot_session->hSession, src_slot_object->hObject, pTemplate,
	    ulCount, &(dst_slot_object->hObject));

	if (rv != CKR_OK) {
		if (dst_object->isToken) {
			/*
			 * token obj can only be created in the
			 * token slot.  No need to try anywhere else
			 */
			goto finish;
		}
		if ((!src_object->isExtractable) ||
		    ((src_object->isSensitive) && (src_object->isToken) &&
		    (!metaslot_auto_key_migrate))) {
			/* source object isn't clonable in another slot */
			goto finish;
		}

		if (!try_again(rv)) {
			goto finish;
		}

		first_rv = rv;

		meta_release_slot_session(slot_session);
		slot_session = NULL;

		num_slots = meta_slotManager_get_slotcount();

		/* Try operation on other slots if the object is clonable */
		for (slotnum = 0; slotnum < num_slots; slotnum++) {

			if (slotnum == src_object->master_clone_slotnum) {
				/* already tried, don't need to try again */
				continue;
			}

			rv = meta_get_slot_session(slotnum, &slot_session,
			    session->session_flags);
			if (rv != CKR_OK) {
				goto finish;
			}

			rv = meta_object_get_clone(src_object, slotnum,
			    slot_session, &src_slot_object);
			if (rv != CKR_OK)
				goto finish;

			dst_object->tried_create_clone[slotnum] = B_TRUE;

			rv = FUNCLIST(slot_session->fw_st_id)->C_CopyObject(
			    slot_session->hSession, src_slot_object->hObject,
			    pTemplate, ulCount, &dst_slot_object->hObject);

			if (rv == CKR_OK) {
				break;
			}

			if (!try_again(rv)) {
				goto finish;
			}
			meta_release_slot_session(slot_session);
			slot_session = NULL;
		}
	}

	if (rv == CKR_OK) {

		rv = meta_object_get_attr(slot_session,
		    dst_slot_object->hObject, dst_object);
		if (rv != CKR_OK) {
			goto finish;
		}

		if (src_object->attributes != NULL) {

			/* Keep a copy of the template for the future */

			/*
			 * Don't allow attributes to change while
			 * we look at them.
			 */
			(void) pthread_rwlock_rdlock(
			    &src_object->attribute_lock);

			rv = get_master_attributes_by_duplication(
			    src_object->attributes,
			    src_object->num_attributes,
			    &dst_object->attributes,
			    &dst_object->num_attributes);

			(void) pthread_rwlock_unlock(
			    &src_object->attribute_lock);

			if (rv != CKR_OK)
				goto finish;

			for (i = 0; i < ulCount; i++) {
				rv = attribute_set_value(pTemplate + i,
				    dst_object->attributes,
				    dst_object->num_attributes);

				if (rv != CKR_OK)
					goto finish;
			}
		}

		/* Allow FreeToken to activate onto token obj list */
		if (dst_object->isFreeToken == FREE_ENABLED)
			dst_object->isToken = TRUE;

		meta_slot_object_activate(dst_slot_object,
		    slot_session, dst_object->isToken);

		dst_object->clones[slotnum] = dst_slot_object;
		dst_object->master_clone_slotnum = slotnum;
		dst_slot_object = NULL; /* for error cleanup */

		meta_release_slot_session(slot_session);
		slot_session = NULL; /* for error cleanup */

	} else {
		/*
		 * return either first error code or
		 * CKR_FUNCTION_FAILED depending on the failure
		 */
		int j;
		for (j = 0; j < num_other_rv; j++) {
			if (rv == other_rv[j]) {
				rv = CKR_FUNCTION_FAILED;
				goto finish;
			}
		}
		/* need to return first rv */
		rv = first_rv;
		goto finish;
	}
	meta_object_activate(dst_object);
	*phNewObject = (CK_OBJECT_HANDLE) dst_object;

finish:
	if (rv != CKR_OK) {
		if (dst_slot_object)
			meta_slot_object_dealloc(dst_slot_object);

		if (dst_object)
			(void) meta_object_dealloc(session, dst_object,
			    B_TRUE);

		if (slot_session)
			meta_release_slot_session(slot_session);
	}

	OBJRELEASE(src_object);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DestroyObject
 *
 * This function destroys an object by first removing it from the
 * list of valid objects for a given session (if session object) or
 * the global token object list.  And then, calling C_DestroyObject
 * on all the slots on which we have created a clone of this object.
 */
CK_RV
meta_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *object;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hObject, &object);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	/* Can't delete token objects from a read-only session. */
	if ((IS_READ_ONLY_SESSION(session->session_flags)) &&
	    (object->isToken || object->isFreeToken == FREE_ENABLED)) {
		OBJRELEASE(object);
		REFRELEASE(session);
		return (CKR_SESSION_READ_ONLY);
	}

	/* Remove object from list of valid meta_objects */
	rv = meta_object_deactivate(object, B_FALSE, B_TRUE);

	/*
	 * Actually call C_DestroyObject on all the slots on which we have
	 * created a clone of this object.
	 */
	if (rv == CKR_OK)
		rv = meta_object_dealloc(session, object, B_TRUE);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_GetObjectSize
 *
 * NOTES:
 * 1) Because the "size" is so poorly defined in the spec, we have deemed
 *    it useless and won't support it. This is especially true for the
 *    metaslot, because the mulitple providers it uses may each interpret
 *    the size differently.
 */
/* ARGSUSED */
CK_RV
meta_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}


/*
 * meta_GetAttributeValue
 *
 */
CK_RV
meta_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *object;
	CK_ULONG slotnum;
	slot_session_t *slot_session;

	if (pTemplate == NULL || ulCount < 1)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hObject, &object);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	slotnum = object->master_clone_slotnum;

	rv = meta_get_slot_session(slotnum, &slot_session,
	    session->session_flags);
	if (rv == CKR_OK) {
		rv = FUNCLIST(slot_session->fw_st_id)->C_GetAttributeValue(
		    slot_session->hSession, object->clones[slotnum]->hObject,
		    pTemplate, ulCount);

		meta_release_slot_session(slot_session);
	}

	OBJRELEASE(object);
	REFRELEASE(session);

	return (rv);

}


/*
 * meta_SetAttributeValue
 *
 * Call C_SetAttributeValue on all the clones.  If the operation fails on
 * all clones, return the failure.
 *
 * If the operation fails on some clones and not the others, delete all the
 * clones that have failed the operation.  If any of the deleted clone is the
 * master clone, use one of the remaining clone as the master clone.
 *
 * If the operation is successful and the master template already exists,
 * update the master template with new values.
 */
CK_RV
meta_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK, save_rv = CKR_OK;
	meta_session_t *session;
	meta_object_t *object;
	CK_ULONG slotnum, num_slots;
	/* Keep track of which slot's SetAttributeValue failed */
	boolean_t *clone_failed_op = NULL;
	int num_clones = 0, num_clones_failed = 0;
	slot_session_t *slot_session;
	slot_object_t *slot_object;
	boolean_t need_update_master_clone = B_FALSE;

	if (pTemplate == NULL || ulCount < 1)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hObject, &object);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	if ((IS_READ_ONLY_SESSION(session->session_flags)) &&
	    (object->isToken || object->isFreeToken == FREE_ENABLED)) {
		rv = CKR_SESSION_READ_ONLY;
		goto finish;
	}

	if ((!object->isExtractable) && (object->attributes == NULL)) {
		/*
		 * object has no clone, just need to do the operation
		 * in the master clone slot
		 */
		slot_session_t *slot_session;
		slotnum = object->master_clone_slotnum;

		rv = meta_get_slot_session(slotnum, &slot_session,
		    session->session_flags);
		if (rv == CKR_OK) {
			rv = FUNCLIST(slot_session->fw_st_id)->\
			    C_SetAttributeValue(slot_session->hSession,
			    object->clones[slotnum]->hObject, pTemplate,
			    ulCount);

			meta_release_slot_session(slot_session);
		}
		goto finish;
	}


	num_slots = meta_slotManager_get_slotcount();

	/*
	 * object might have clones, need to do operation in all clones
	 *
	 * If the C_SetAttributeValue() call fails in a clone, the
	 * clone that failed the operation can not be deleted right
	 * away.  The clone with the failed operation is recorded, and
	 * the deletion will happen in a separate loop.
	 *
	 * This is necessary because if ALL the clones failed
	 * C_SetAttributeVAlue(), then, the app's call to C_SetAttributeValue()
	 * is considered failed, and there shouldn't be any changes to the
	 * object, none of the clones should be deleted.
	 * On the other hand, if C_SetAttributeValue() fails in some clones
	 * and succeeds in other clones, the C_SetAttributeValue() operation
	 * is considered successful, and those clones that failed the
	 * operation is deleted.
	 */
	clone_failed_op = calloc(num_slots, sizeof (boolean_t));
	if (clone_failed_op == NULL) {
		rv = CKR_HOST_MEMORY;
		goto finish;
	}
	for (slotnum = 0; slotnum < num_slots; slotnum++) {
		if (object->clones[slotnum] != NULL) {
			num_clones++;
			rv = meta_get_slot_session(slotnum, &slot_session,
			    session->session_flags);
			if (rv != CKR_OK) {
				goto finish;
			}

			rv = FUNCLIST(slot_session->fw_st_id)->\
			    C_SetAttributeValue(slot_session->hSession,
			    object->clones[slotnum]->hObject, pTemplate,
			    ulCount);

			if (rv != CKR_OK) {
				num_clones_failed++;
				clone_failed_op[slotnum] = B_TRUE;
				if (save_rv == CKR_OK) {
					save_rv = rv;
				}
			}
			meta_release_slot_session(slot_session);
		}
	}

	if (num_clones_failed == num_clones) {
		/* all operations failed */
		rv = save_rv;
		goto finish;
	}

	if (num_clones_failed > 0) {
		/*
		 * C_SetAttributeValue in some of the clones failed.
		 * Find out which ones failed, and delete the clones
		 * in those failed slots
		 */
		for (slotnum = 0; slotnum < num_slots; slotnum++) {
			if (clone_failed_op[slotnum]) {

				slot_object_t *clone = object->clones[slotnum];

				rv = meta_get_slot_session(slotnum,
				    &slot_session, session->session_flags);
				if (rv == CKR_OK) {
					(void) FUNCLIST(
					    slot_session->fw_st_id)->
					    C_DestroyObject(
					    slot_session->hSession,
					    clone->hObject);

					meta_release_slot_session(slot_session);

				}

				meta_slot_object_deactivate(clone);
				meta_slot_object_dealloc(clone);
				object->clones[slotnum] = NULL;

				if (slotnum == object->master_clone_slotnum) {
					need_update_master_clone = B_TRUE;
				}
			}
		}

		if (need_update_master_clone) {
			/* make first available clone the master */
			for (slotnum = 0; slotnum < num_slots; slotnum++) {
				if (object->clones[slotnum]) {
					object->master_clone_slotnum = slotnum;
					need_update_master_clone = B_FALSE;
					break;
				}
			}

		}
		if (need_update_master_clone) {
			/*
			 * something is very wrong, can't continue
			 * it should never be this case.
			 */
			rv = CKR_FUNCTION_FAILED;
			goto finish;
		}
		rv = CKR_OK;
	}

	/*
	 * Update the attribute information we keep in our metaslot object
	 */
	slot_object = object->clones[object->master_clone_slotnum];
	rv = meta_get_slot_session(object->master_clone_slotnum,
	    &slot_session, session->session_flags);
	if (rv == CKR_OK) {
		(void) meta_object_get_attr(slot_session,
		    slot_object->hObject, object);
		meta_release_slot_session(slot_session);
	}

	/* if there's a copy of the attributes, keep it up to date */
	if (object->attributes != NULL) {

		CK_ULONG i;

		/* Make sure no one else is looking at attributes. */
		(void) pthread_rwlock_wrlock(&object->attribute_lock);

		for (i = 0; i < ulCount; i++) {
			(void) attribute_set_value(pTemplate + i,
			    object->attributes, object->num_attributes);

		}
		(void) pthread_rwlock_unlock(&object->attribute_lock);
	}

finish:
	if (clone_failed_op) {
		free(clone_failed_op);
	}
	OBJRELEASE(object);
	REFRELEASE(session);

	return (rv);
}

static boolean_t
meta_object_in_list(meta_object_t *obj, meta_object_t **objs_list, int num_objs)
{
	int i;

	for (i = 0; i < num_objs; i++) {
		if (objs_list[i] == obj) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static CK_RV
add_to_search_result(meta_object_t *object, find_objs_info_t *info,
    int *num_results_alloc)
{
	/*
	 * allocate space for storing results if the currently
	 * allocated space is not enough
	 */
	if (*num_results_alloc <= info->num_matched_objs) {
		*num_results_alloc += FIND_OBJ_BUF_SIZE;
		info->matched_objs = realloc(info->matched_objs,
		    sizeof (meta_object_t *) * (*num_results_alloc));
		if (info->matched_objs == NULL) {
			return (CKR_HOST_MEMORY);
		}
	}
	(info->matched_objs)[(info->num_matched_objs)++] = object;
	return (CKR_OK);
}

static CK_RV
process_find_results(CK_OBJECT_HANDLE *results, CK_ULONG num_results,
    int *num_results_allocated, find_objs_info_t *info, CK_ULONG slotnum,
    boolean_t token_only, slot_session_t *slot_session,
    meta_session_t *session)
{
	CK_ULONG i;
	meta_object_t *object;
	CK_RV rv;

	for (i = 0; i < num_results; i++) {

		object = meta_object_find_by_handle(results[i], slotnum,
		    token_only);

		/*
		 * a token object is found from the keystore,
		 * need to create a meta object for it
		 */
		if (object == NULL) {
			slot_object_t *slot_object;

			rv = meta_object_alloc(session, &object);
			if (rv != CKR_OK) {
				return (rv);
			}

			rv = meta_slot_object_alloc(&slot_object);
			if (rv != CKR_OK) {
				(void) meta_object_dealloc(session, object,
				    B_TRUE);
				return (rv);
			}

			slot_object->hObject = results[i];
			object->master_clone_slotnum = slotnum;
			object->clones[slotnum] = slot_object;

			/* get in the attributes we keep in meta_object */

			rv = meta_object_get_attr(slot_session,
			    slot_object->hObject, object);
			if (rv != CKR_OK) {
				(void) meta_object_dealloc(session, object,
				    B_TRUE);
				return (rv);
			}

			meta_slot_object_activate(slot_object, slot_session,
			    B_TRUE);
			meta_object_activate(object);
			slot_object = NULL;
		}

		if (!meta_object_in_list(object, info->matched_objs,
		    info->num_matched_objs)) {
			rv = add_to_search_result(object, info,
			    num_results_allocated);
			if (rv != CKR_OK) {
				return (rv);
			}
		}
	}
	return (CKR_OK);
}

static CK_RV
meta_search_for_objects(meta_session_t *session, find_objs_info_t *info,
    slot_session_t *slot_session, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_ULONG slotnum, boolean_t token_only,
    int *num_results_alloc)
{
	CK_ULONG tmp_num_results;
	CK_OBJECT_HANDLE tmp_results[FIND_OBJ_BUF_SIZE];
	CK_SESSION_HANDLE hSession = slot_session->hSession;
	CK_RV rv;
	CK_SLOT_ID fw_st_id = slot_session->fw_st_id;

	rv = FUNCLIST(fw_st_id)->C_FindObjectsInit(hSession,
	    pTemplate, ulCount);

	if (rv != CKR_OK) {
		return (rv);
	}

	tmp_num_results = 0;
	rv = FUNCLIST(fw_st_id)->C_FindObjects(hSession, tmp_results,
	    FIND_OBJ_BUF_SIZE, &tmp_num_results);
	if (rv != CKR_OK) {
		return (rv);
	}

	rv = process_find_results(tmp_results, tmp_num_results,
	    num_results_alloc, info, slotnum, token_only,
	    slot_session, session);
	if (rv != CKR_OK) {
		return (rv);
	}

	while (tmp_num_results == FIND_OBJ_BUF_SIZE) {
		/* might be more results, need to call C_FindObjects again */
		rv = FUNCLIST(fw_st_id)->C_FindObjects(hSession, tmp_results,
		    FIND_OBJ_BUF_SIZE, &tmp_num_results);
		if (rv != CKR_OK) {
			return (rv);
		}

		rv = process_find_results(tmp_results, tmp_num_results,
		    num_results_alloc, info, slotnum, token_only,
		    slot_session, session);
		if (rv != CKR_OK) {
			return (rv);
		}
	}

	rv = FUNCLIST(fw_st_id)->C_FindObjectsFinal(hSession);
	return (rv);
}


/*
 * meta_FindObjectsInit
 *
 * This function actually will do ALL the work of searching for objects
 * that match all requirements specified in the template.
 *
 * Objects that matched the template will be stored in the
 * session's data structure.  When the subsequent C_FindObjects()
 * calls are made, results saved will be returned.
 *
 */
CK_RV
meta_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	CK_RV rv;
	meta_session_t *session;
	CK_ULONG slot_num = 0;
	boolean_t have_token_attr, tokenTrue = B_FALSE;
	slot_session_t *slot_find_session = NULL;
	int num_results_allocated = 0;
	CK_ULONG keystore_slotnum;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if ((session->find_objs_info).op_active) {
		REFRELEASE(session);
		return (CKR_OPERATION_ACTIVE);
	}

	(session->find_objs_info).op_active = B_TRUE;

	REFRELEASE(session);

	/* see if the template indicates token object only or not */
	have_token_attr = get_template_boolean(CKA_TOKEN, pTemplate, ulCount,
	    &tokenTrue);

	keystore_slotnum = get_keystore_slotnum();

	if (have_token_attr && tokenTrue) {


		/*
		 * only interested in token objects, just need to search
		 * token object slot
		 */
		rv = meta_get_slot_session(keystore_slotnum,
		    &slot_find_session, session->session_flags);
		if (rv != CKR_OK)  {
			goto finish;
		}
		rv = meta_search_for_objects(session,
		    &(session->find_objs_info), slot_find_session, pTemplate,
		    ulCount, keystore_slotnum, B_TRUE, &num_results_allocated);
		if (rv != CKR_OK) {
			goto finish;
		}
	} else {
		CK_ULONG num_slots = meta_slotManager_get_slotcount();
		for (slot_num = 0; slot_num < num_slots; slot_num++) {
			rv = meta_get_slot_session(slot_num,
			    &slot_find_session, session->session_flags);
			if (rv != CKR_OK) {
				goto finish;
			}

			/*
			 * if the slot is NOT the token object slot, and
			 * CKA_TOKEN is not specified, need to specified
			 * it to be false explicitly.  This will prevent
			 * us from using token objects that doesn't
			 * belong to the token slot in the case that
			 * more than one slot supports token objects.
			 */

			if ((slot_num != keystore_slotnum) &&
			    (!have_token_attr)) {
				CK_BBOOL false = FALSE;
				CK_ATTRIBUTE_PTR newTemplate;

				newTemplate = malloc((ulCount + 1) *
				    sizeof (CK_ATTRIBUTE));
				if (newTemplate == NULL) {
					rv = CKR_HOST_MEMORY;
					goto finish;
				}
				(void) memcpy(newTemplate + 1, pTemplate,
				    ulCount * sizeof (CK_ATTRIBUTE));
				newTemplate[0].type = CKA_TOKEN;
				newTemplate[0].pValue = &false;
				newTemplate[0].ulValueLen = sizeof (false);

				rv = meta_search_for_objects(session,
				    &(session->find_objs_info),
				    slot_find_session, newTemplate,
				    ulCount+1, slot_num, B_FALSE,
				    &num_results_allocated);
				free(newTemplate);
			} else {
				rv = meta_search_for_objects(session,
				    &(session->find_objs_info),
				    slot_find_session, pTemplate, ulCount,
				    slot_num, B_FALSE,
				    &num_results_allocated);
			}

			if (rv != CKR_OK) {
				goto finish;
			}
			meta_release_slot_session(slot_find_session);
			slot_find_session = NULL;
		}
	}

finish:
	if (slot_find_session != NULL) {
		meta_release_slot_session(slot_find_session);
	}
	if (rv != CKR_OK) {
		(void) pthread_rwlock_wrlock(&session->session_lock);
		if (((session->find_objs_info).matched_objs) != NULL) {
			free((session->find_objs_info).matched_objs);
		}
		bzero(&(session->find_objs_info), sizeof (find_objs_info_t));
		(void) pthread_rwlock_unlock(&(session->session_lock));
	}

	return (rv);
}

/*
 * meta_FindObjects
 *
 * This function actually doesn't do any real work in search for the
 * matching object.  All the work is done in FindObjectsInit().  This
 * function will only return the matching objects store in the session's
 * "find_objs_info" variable.
 *
 */
CK_RV
meta_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv;
	find_objs_info_t *info;
	CK_ULONG num_objs_found = 0;
	meta_object_t *obj;
	meta_session_t *session;
	int i;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	info = &(session->find_objs_info);

	if (!(info->op_active)) {
		REFRELEASE(session);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	for (i = info->next_result_index;
	    ((num_objs_found < ulMaxObjectCount) &&
	    (i < info->num_matched_objs));
	    i++) {
		obj = info->matched_objs[i];
		if (obj != NULL) {
			/* sanity check to see if object is still valid */
			(void) pthread_rwlock_rdlock(&obj->object_lock);
			if (obj->magic_marker == METASLOT_OBJECT_MAGIC) {
				phObject[num_objs_found++] =
				    (CK_OBJECT_HANDLE)obj;
			}
			(void) pthread_rwlock_unlock(&obj->object_lock);
		}
	}
	info->next_result_index = i;
	*pulObjectCount	= num_objs_found;
	REFRELEASE(session);
	return (rv);
}


/*
 * meta_FindObjectsFinal
 *
 */
CK_RV
meta_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	find_objs_info_t *info;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	info = &(session->find_objs_info);

	if (!info->op_active) {
		REFRELEASE(session);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	if (info->matched_objs) {
		free(info->matched_objs);
	}

	bzero(info, sizeof (find_objs_info_t));
	REFRELEASE(session);
	return (rv);
}
