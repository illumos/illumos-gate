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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */


#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "metaGlobal.h"

/* Size of the template for creating key used for wrap/unwrap */
#define	WRAP_KEY_TEMPLATE_SIZE	7

/*
 * Information necessary to create keys for C_WrapKey/C_UnwrapKey
 */
typedef struct _wrap_info {
	CK_OBJECT_CLASS		class; /* class of the key for wrap/unwrap */
	CK_KEY_TYPE		key_type; /* key type of key for wrap/unwrap */
	CK_ULONG		key_length; /* length of key */
	CK_MECHANISM_TYPE	mech_type; /* mech used for wrap/unwrap */
	CK_ULONG		iv_length; /* length of iv for mech */

	boolean_t		src_supports;
	boolean_t		dst_supports;
} wrap_info_t;

extern pthread_rwlock_t meta_sessionlist_lock;
extern meta_session_t *meta_sessionlist_head;

static wrap_info_t common_wrap_info[] = {
	{CKO_SECRET_KEY, CKK_AES, 16, CKM_AES_CBC_PAD, 16, B_FALSE, B_FALSE},
	{CKO_SECRET_KEY, CKK_DES3, 24, CKM_DES3_CBC_PAD, 8, B_FALSE, B_FALSE},
	{CKO_SECRET_KEY, CKK_DES, 8, CKM_DES_CBC_PAD, 8, B_FALSE, B_FALSE},
};

static unsigned int num_common_wrap_info =
    sizeof (common_wrap_info) / sizeof (wrap_info_t);

static wrap_info_t special_wrap_info[] = {
	{CKO_SECRET_KEY, CKK_SKIPJACK, 12,  CKM_SKIPJACK_WRAP, 0,
	    B_FALSE, B_FALSE},
	{CKO_SECRET_KEY, CKK_BATON, 40, CKM_BATON_WRAP, 0,
	    B_FALSE, B_FALSE},
	{CKO_SECRET_KEY, CKK_JUNIPER, 40, CKM_JUNIPER_WRAP, 0,
	    B_FALSE, B_FALSE},
};
static unsigned int num_special_wrap_info =
    sizeof (special_wrap_info) / sizeof (wrap_info_t);

static wrap_info_t rsa_wrap_info[] = {
	{CKO_PUBLIC_KEY, CKK_RSA, 0,  CKM_RSA_PKCS, 0,
	    B_FALSE, B_FALSE},
	{CKO_PUBLIC_KEY, CKK_RSA, 0, CKM_RSA_X_509, 0,
	    B_FALSE, B_FALSE},
};
static unsigned int num_rsa_wrap_info =
    sizeof (rsa_wrap_info) / sizeof (wrap_info_t);


static pthread_rwlock_t meta_objectclose_lock;
static pthread_rwlock_t tokenobject_list_lock;
static meta_object_t *tokenobject_list_head;

CK_BBOOL falsevalue = FALSE;
CK_BBOOL truevalue = TRUE;

/*
 * Public and private exponent, and Module value for
 * creating the RSA public/private key.
 *
 */
static CK_BYTE PubExpo[3] = {0x01, 0x00, 0x01};
CK_BYTE PriExpo[128] = {
	0x8e, 0xc9, 0x70, 0x57, 0x6b, 0xcd, 0xfb, 0xa9,
	0x19, 0xad, 0xcd, 0x91, 0x69, 0xd5, 0x52, 0xec,
	0x72, 0x1e, 0x45, 0x15, 0x06, 0xdc, 0x65, 0x2d,
	0x98, 0xc4, 0xce, 0x33, 0x54, 0x15, 0x70, 0x8d,
	0xfa, 0x65, 0xea, 0x53, 0x44, 0xf3, 0x3e, 0x3f,
	0xb4, 0x4c, 0x60, 0xd5, 0x01, 0x2d, 0xa4, 0x12,
	0x99, 0xbf, 0x3f, 0x0b, 0xcd, 0xbb, 0x24, 0x10,
	0x60, 0x30, 0x5e, 0x58, 0xf8, 0x59, 0xaa, 0xd1,
	0x63, 0x3b, 0xbc, 0xcb, 0x94, 0x58, 0x38, 0x24,
	0xfc, 0x65, 0x25, 0xc5, 0xa6, 0x51, 0xa2, 0x2e,
	0xf1, 0x5e, 0xf5, 0xc1, 0xf5, 0x46, 0xf7, 0xbd,
	0xc7, 0x62, 0xa8, 0xe2, 0x27, 0xd6, 0x94, 0x5b,
	0xd3, 0xa2, 0xb5, 0x76, 0x42, 0x67, 0x6b, 0x86,
	0x91, 0x97, 0x4d, 0x07, 0x92, 0x00, 0x4a, 0xdf,
	0x0b, 0x65, 0x64, 0x05, 0x03, 0x48, 0x27, 0xeb,
	0xce, 0x9a, 0x49, 0x7f, 0x3e, 0x10, 0xe0, 0x01};

static CK_BYTE Modulus[128] = {
	0x94, 0x32, 0xb9, 0x12, 0x1d, 0x68, 0x2c, 0xda,
	0x2b, 0xe0, 0xe4, 0x97, 0x1b, 0x4d, 0xdc, 0x43,
	0xdf, 0x38, 0x6e, 0x7b, 0x9f, 0x07, 0x58, 0xae,
	0x9d, 0x82, 0x1e, 0xc7, 0xbc, 0x92, 0xbf, 0xd3,
	0xce, 0x00, 0xbb, 0x91, 0xc9, 0x79, 0x06, 0x03,
	0x1f, 0xbc, 0x9f, 0x94, 0x75, 0x29, 0x5f, 0xd7,
	0xc5, 0xf3, 0x73, 0x8a, 0xa4, 0x35, 0x43, 0x7a,
	0x00, 0x32, 0x97, 0x3e, 0x86, 0xef, 0x70, 0x6f,
	0x18, 0x56, 0x15, 0xaa, 0x6a, 0x87, 0xe7, 0x8d,
	0x7d, 0xdd, 0x1f, 0xa4, 0xe4, 0x31, 0xd4, 0x7a,
	0x8c, 0x0e, 0x20, 0xd2, 0x23, 0xf5, 0x57, 0x3c,
	0x1b, 0xa8, 0x44, 0xa4, 0x57, 0x8f, 0x33, 0x52,
	0xad, 0x83, 0xae, 0x4a, 0x97, 0xa6, 0x1e, 0xa6,
	0x2b, 0xfa, 0xea, 0xeb, 0x6e, 0x71, 0xb8, 0xb6,
	0x0a, 0x36, 0xed, 0x83, 0xce, 0xb0, 0xdf, 0xc1,
	0xd4, 0x3a, 0xe9, 0x99, 0x6f, 0xf3, 0x96, 0xb7};

static CK_RV
meta_clone_template_setup(meta_object_t *object,
    const generic_attr_t *attributes, size_t num_attributes);

/*
 * meta_objectManager_initialize
 *
 * Called from meta_Initialize.  Initializes all the variables used
 * by the object manager.
 */
CK_RV
meta_objectManager_initialize()
{
	if (pthread_rwlock_init(&meta_objectclose_lock, NULL) != 0) {
		return (CKR_FUNCTION_FAILED);
	}

	if (pthread_rwlock_init(&tokenobject_list_lock, NULL) != 0) {
		(void) pthread_rwlock_destroy(&meta_objectclose_lock);
		return (CKR_FUNCTION_FAILED);
	}

	tokenobject_list_head = NULL;

	return (CKR_OK);
}

void
meta_objectManager_finalize()
{
	/*
	 * If there are still any token object in the list, need to
	 * deactivate all of them.
	 */
	(void) meta_token_object_deactivate(ALL_TOKEN);

	(void) pthread_rwlock_destroy(&meta_objectclose_lock);
	(void) pthread_rwlock_destroy(&tokenobject_list_lock);
}



/*
 * meta_handle2object
 *
 * Convert a CK_OBJECT_HANDLE to the corresponding metaobject. If
 * successful, a reader-lock on the object will be held to indicate
 * that it's in use. Call OBJRELEASE() when finished.
 *
 */
CK_RV
meta_handle2object(CK_OBJECT_HANDLE hObject, meta_object_t **object)
{
	meta_object_t *tmp_object = (meta_object_t *)(hObject);

	/* Check for bad args (eg CK_INVALID_HANDLE, which is 0/NULL). */
	if (tmp_object == NULL) {
		*object = NULL;
		return (CKR_OBJECT_HANDLE_INVALID);
	}


	/* Lock to ensure the magic-check + read-lock is atomic. */
	(void) pthread_rwlock_rdlock(&meta_objectclose_lock);

	if (tmp_object->magic_marker != METASLOT_OBJECT_MAGIC) {
		(void) pthread_rwlock_unlock(&meta_objectclose_lock);
		*object = NULL;
		return (CKR_OBJECT_HANDLE_INVALID);
	}
	(void) pthread_rwlock_rdlock(&tmp_object->object_lock);
	(void) pthread_rwlock_unlock(&meta_objectclose_lock);

	*object = tmp_object;
	return (CKR_OK);
}


/*
 * meta_object_alloc
 *
 * Creates a new metaobject, but does not yet add it to the object list.
 * Once the caller has finished initializing the object (by setting
 * object attributes), meta_object_add should be called. This two-step
 * process prevents others from seeing the object until fully intitialized.
 *
 */
CK_RV
meta_object_alloc(meta_session_t *session, meta_object_t **object)
{
	meta_object_t *new_object;
	CK_ULONG num_slots;

	/* Allocate memory for the object. */
	new_object = calloc(1, sizeof (meta_object_t));
	if (new_object == NULL)
		return (CKR_HOST_MEMORY);

	num_slots = meta_slotManager_get_slotcount();

	new_object->clones = calloc(num_slots, sizeof (slot_object_t *));
	if (new_object->clones == NULL) {
		free(new_object);
		return (CKR_HOST_MEMORY);
	}

	new_object->tried_create_clone = calloc(num_slots, sizeof (boolean_t));
	if (new_object->tried_create_clone == NULL) {
		free(new_object->clones);
		free(new_object);
		return (CKR_HOST_MEMORY);
	}

	/* Initialize the object fields. */
	new_object->magic_marker = METASLOT_OBJECT_MAGIC;
	(void) pthread_rwlock_init(&new_object->object_lock, NULL);
	(void) pthread_rwlock_init(&new_object->attribute_lock, NULL);
	(void) pthread_mutex_init(&new_object->clone_create_lock, NULL);
	(void) pthread_mutex_init(&new_object->isClosingObject_lock, NULL);
	new_object->creator_session = session;

	*object = new_object;

	return (CKR_OK);
}


/*
 * meta_object_get_attr
 *
 * Get attribute values to fill in attribute values
 * being kept in the metaslot object.  The following 4 attributes
 * in the meta_object_t structure will be filled in:
 * isToken, isPrivate, isSensitive, isExtractable
 *
 * It's basically an easy way to do a C_GetAttributeValue.
 * So, the hSession argument is assumed
 * to be valid, and the pointer to meta_object_t is also assumed
 * to be valid.
 */
CK_RV
meta_object_get_attr(slot_session_t *slot_session, CK_OBJECT_HANDLE hObject,
    meta_object_t *object)
{
	CK_BBOOL is_sensitive = object->isSensitive;
	CK_BBOOL is_extractable = object->isExtractable;
	CK_BBOOL is_token = B_FALSE, is_private = B_FALSE;
	CK_KEY_TYPE keytype;
	CK_OBJECT_CLASS class;
	CK_ATTRIBUTE attrs[3];
	CK_RV rv;
	CK_SESSION_HANDLE hSession = slot_session->hSession;
	CK_SLOT_ID fw_st_id = slot_session->fw_st_id;
	int count = 1;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &class;
	attrs[0].ulValueLen = sizeof (class);

	if (object->isFreeObject != FREE_ENABLED) {
		attrs[1].type = CKA_TOKEN;
		attrs[1].pValue = &is_token;
		attrs[1].ulValueLen = sizeof (is_token);
		count++;
	}

	/*
	 * If this is a freeobject, we already know the Private value
	 * and we don't want to overwrite it with the wrong value
	 */
	if (object->isFreeObject <= FREE_DISABLED) {
		attrs[count].type = CKA_PRIVATE;
		attrs[count].pValue = &is_private;
		attrs[count].ulValueLen = sizeof (is_private);
		count++;
	} else
		is_private = object->isPrivate;

	rv = FUNCLIST(fw_st_id)->C_GetAttributeValue(hSession, hObject,
	    attrs, count);
	if (rv != CKR_OK) {
		return (rv);
	}

	count = 0;
	switch (class) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
		/* Only need to check these for private & secret keys */
		attrs[0].type = CKA_EXTRACTABLE;
		attrs[0].pValue = &is_extractable;
		attrs[0].ulValueLen = sizeof (is_extractable);
		count = 1;

		/*
		 * If this is a freeobject, we already know the Sensitive
		 * value and we don't want to overwrite it with the wrong
		 * value.
		 */

		if (object->isFreeObject <= FREE_DISABLED) {
			attrs[1].type = CKA_SENSITIVE;
			attrs[1].pValue = &is_sensitive;
			attrs[1].ulValueLen = sizeof (is_sensitive);
			count = 2;

			/*
			 * We only need the key type if this is the first
			 * time we've looked at the object
			 */
			if (object->isFreeObject == FREE_UNCHECKED) {
				attrs[2].type = CKA_KEY_TYPE;
				attrs[2].pValue = &keytype;
				attrs[2].ulValueLen = sizeof (keytype);
				count = 3;
			}
		}

		break;

	case CKO_PUBLIC_KEY:
		if (object->isFreeObject == FREE_UNCHECKED) {
			attrs[count].type = CKA_KEY_TYPE;
			attrs[count].pValue = &keytype;
			attrs[count].ulValueLen = sizeof (keytype);
			count++;
		}
		is_sensitive = CK_FALSE;
		is_extractable = CK_TRUE;
		break;

	default:
		object->isFreeObject = FREE_DISABLED;
		is_sensitive = CK_FALSE;
		is_extractable = CK_TRUE;
	};

	if (count > 0) {
		rv = FUNCLIST(fw_st_id)->C_GetAttributeValue(hSession, hObject,
		    attrs, count);
		if (rv != CKR_OK) {
			return (rv);
		}

		if (object->isFreeObject == FREE_UNCHECKED) {
			if (keytype == CKK_EC || keytype == CKK_RSA ||
			    keytype == CKK_DH) {
				if (metaslot_config.auto_key_migrate) {
					object->isFreeObject = FREE_DISABLED;
					object->isFreeToken = FREE_DISABLED;
				}

				object->isFreeObject = FREE_ENABLED;
				if (is_token)
					object->isFreeToken = FREE_ENABLED;
			} else
				object->isFreeObject = FREE_DISABLED;

		}

	}

	object->isToken = is_token;
	object->isPrivate = is_private;
	object->isSensitive = is_sensitive;
	object->isExtractable = is_extractable;

	return (CKR_OK);
}


/*
 * meta_object_activate
 *
 * Add a new metaobject to the list of objects. See also meta_object_create,
 * which would be called to create an object before it is added.
 */
void
meta_object_activate(meta_object_t *new_object)
{
	pthread_rwlock_t *list_lock;
	meta_object_t **list_head;

	/*
	 * For session objects, we keep the list in the session that created
	 * this object, because this object will be destroyed when that session
	 * is closed.
	 *
	 * For token objects, the list is global (ie, not associated with any
	 * particular session).
	 */
	if (new_object->isToken) {
		list_lock = &tokenobject_list_lock;
		list_head = &tokenobject_list_head;
	} else {
		list_lock = &new_object->creator_session->object_list_lock;
		list_head = &new_object->creator_session->object_list_head;
	}

	/* Add object to the list of objects. */
	(void) pthread_rwlock_wrlock(list_lock);
	INSERT_INTO_LIST(*list_head, new_object);
	(void) pthread_rwlock_unlock(list_lock);
}


/*
 * meta_object_deactivate
 *
 * Removes the object from the list of valid meta objects.  Note
 * that this function does not clean up any allocated
 * resources (memory, object clones, etc).   Cleaning up of
 * allocated resources is done by calling the meta_object_dealloc()
 *
 */
CK_RV
meta_object_deactivate(meta_object_t *object, boolean_t have_list_lock,
    boolean_t have_object_lock)
{
	pthread_rwlock_t *list_lock;
	meta_object_t **list_head;

	if (!have_object_lock) {
		(void) pthread_rwlock_rdlock(&object->object_lock);
	}

	(void) pthread_mutex_lock(&object->isClosingObject_lock);
	if (object->isClosingObject) {
		/* Lost a delete race. */
		(void) pthread_mutex_unlock(&object->isClosingObject_lock);
		OBJRELEASE(object);
		return (CKR_OBJECT_HANDLE_INVALID);
	}
	object->isClosingObject = B_TRUE;
	(void) pthread_mutex_unlock(&object->isClosingObject_lock);

	if (object->isToken || (object->isFreeToken == FREE_ENABLED)) {
		list_lock = &tokenobject_list_lock;
		list_head = &tokenobject_list_head;
	} else {
		list_lock = &object->creator_session->object_list_lock;
		list_head = &object->creator_session->object_list_head;
	}

	/*
	 * Remove object from the object list. Once removed, it will not
	 * be possible for another thread to begin using the object.
	 */
	(void) pthread_rwlock_wrlock(&meta_objectclose_lock);
	if (!have_list_lock) {
		(void) pthread_rwlock_wrlock(list_lock);
	}


	object->magic_marker = METASLOT_OBJECT_BADMAGIC;
	/*
	 * Can't use the regular REMOVE_FROM_LIST() function because
	 * that will miss the "error cleanup" situation where object is not yet
	 * in the list (object->next == NULL && object->prev == NULL)
	 */
	if (*list_head == object) {
		/* Object is the first one in the list */
		if (object->next) {
			*list_head = object->next;
			object->next->prev = NULL;
		} else {
			/* Object is the only one in the list */
			*list_head = NULL;
		}
	} else if (object->next != NULL || object->prev != NULL) {
		if (object->next) {
			object->prev->next = object->next;
			object->next->prev = object->prev;
		} else {
			/* Object is the last one in the list */
			object->prev->next = NULL;
		}
	}

	if (!have_list_lock) {
		(void) pthread_rwlock_unlock(list_lock);
	}
	(void) pthread_rwlock_unlock(&meta_objectclose_lock);

	/*
	 * Wait for anyone already using object to finish, by obtaining
	 * a writer-lock (need to release our reader-lock first). Once we
	 * get the write lock, we can just release it and finish cleaning
	 * up the object.
	 */
	(void) pthread_rwlock_unlock(&object->object_lock); /* rdlock */
	(void) pthread_rwlock_wrlock(&object->object_lock);
	(void) pthread_rwlock_unlock(&object->object_lock); /* wrlock */


	return (CKR_OK);
}


/*
 * meta_object_dealloc
 *
 * Performs final object cleanup, releasing any allocated memory and
 * destroying any clones on other slots. Caller is assumed to have
 * called meta_object_deactivate() before this function.
 *
 * Caller is assumed to have only reference to object, but should have
 * released any lock.
 *
 * If "nukeSourceObj" argument is true, we will actually delete the
 * object from the underlying slot.
 */
CK_RV
meta_object_dealloc(meta_session_t *session, meta_object_t *object,
    boolean_t nukeSourceObj)
{
	CK_RV rv, save_rv = CKR_OK;
	CK_ULONG slotnum, num_slots;
	CK_ULONG i;

	/* First, delete all the clones of this object on other slots. */
	num_slots = meta_slotManager_get_slotcount();
	for (slotnum = 0; slotnum < num_slots; slotnum++) {
		slot_session_t *obj_session;
		slot_object_t *clone;

		clone = object->clones[slotnum];
		if (clone == NULL)
			continue;
		if (nukeSourceObj || (!object->isToken &&
		    !(object->isFreeToken == FREE_ENABLED &&
		    get_keystore_slotnum() == slotnum))) {

			rv = meta_get_slot_session(slotnum, &obj_session,
			    (session == NULL) ?
			    object->creator_session->session_flags :
			    session->session_flags);

			if (rv == CKR_OK) {
				rv = FUNCLIST(obj_session->fw_st_id)->\
				    C_DestroyObject(obj_session->hSession,
				    clone->hObject);

				meta_release_slot_session(obj_session);
				if ((rv != CKR_OK) && (save_rv == CKR_OK)) {
					save_rv = rv;
				}
			}

		}

		meta_slot_object_deactivate(clone);
		meta_slot_object_dealloc(clone);

		object->clones[slotnum] = NULL;
	}

	/* Now erase and delete any attributes in the metaobject. */
	dealloc_attributes(object->attributes, object->num_attributes);

	free(object->clones);
	free(object->tried_create_clone);

	if (object->clone_template) {
		for (i = 0; i < object->clone_template_size; i++) {
			freezero((object->clone_template)[i].pValue,
			    (object->clone_template)[i].ulValueLen);
		}
		free(object->clone_template);
	}

	/* Cleanup remaining object fields. */
	(void) pthread_rwlock_destroy(&object->object_lock);
	(void) pthread_rwlock_destroy(&object->attribute_lock);
	(void) pthread_mutex_destroy(&object->isClosingObject_lock);
	(void) pthread_mutex_destroy(&object->clone_create_lock);

	meta_object_delay_free(object);

	return (save_rv);
}


/*
 * meta_slot_object_alloc
 */
CK_RV
meta_slot_object_alloc(slot_object_t **object)
{
	slot_object_t *new_object;

	new_object = calloc(1, sizeof (slot_object_t));
	if (new_object == NULL)
		return (CKR_HOST_MEMORY);

	*object = new_object;
	return (CKR_OK);
}


/*
 * meta_slot_object_activate
 */
void
meta_slot_object_activate(slot_object_t *object,
    slot_session_t *creator_session, boolean_t isToken)
{
	object->creator_session = creator_session;

	if (isToken) {
		extern slot_data_t *slots;
		slot_data_t *slot;

		slot = &(slots[object->creator_session->slotnum]);

		(void) pthread_rwlock_wrlock(&slot->tokenobject_list_lock);
		INSERT_INTO_LIST(slot->tokenobject_list_head, object);
		(void) pthread_rwlock_unlock(&slot->tokenobject_list_lock);
	} else {
		slot_session_t *session = object->creator_session;

		/* Add to session's list of session objects. */
		(void) pthread_rwlock_wrlock(&session->object_list_lock);
		INSERT_INTO_LIST(session->object_list_head, object);
		(void) pthread_rwlock_unlock(&session->object_list_lock);
	}

	/*
	 * This set tells the slot object that we are in the token list,
	 * but does not cause harm with the metaobject knowing the object
	 * isn't a token, but a freetoken
	 */

	object->isToken = isToken;
}


/*
 * meta_slot_object_deactivate
 *
 * Remove the specified slot object from the appropriate object list.
 */
void
meta_slot_object_deactivate(slot_object_t *object)
{
	slot_object_t **list_head;
	pthread_rwlock_t *list_lock;

	if (object->isToken) {
		extern slot_data_t *slots;
		slot_data_t *slot;

		slot = &(slots[object->creator_session->slotnum]);

		list_head = &slot->tokenobject_list_head;
		list_lock = &slot->tokenobject_list_lock;
	} else {
		list_head = &object->creator_session->object_list_head;
		list_lock = &object->creator_session->object_list_lock;
	}

	(void) pthread_rwlock_wrlock(list_lock);
	REMOVE_FROM_LIST(*list_head, object);
	(void) pthread_rwlock_unlock(list_lock);
}


/*
 * meta_slot_object_dealloc
 */
void
meta_slot_object_dealloc(slot_object_t *object)
{
	/* Not much cleanup for slot objects, unlike meta objects... */
	free(object);
}


/*
 * meta_object_copyin
 *
 * When a key is generated/derived/unwrapped, the attribute values
 * created by the token are not immediately read into our copy of the
 * attributes. We defer this work until we actually need to know.
 */
CK_RV
meta_object_copyin(meta_object_t *object)
{
	CK_RV rv = CKR_OK;
	slot_session_t *session = NULL;
	CK_ATTRIBUTE *attrs = NULL, *attrs_with_val = NULL;
	slot_object_t *slot_object = NULL;
	CK_ULONG num_attrs = 0, i, num_attrs_with_val;
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID fw_st_id;

	/* Make sure no one else is looking at attributes. */
	(void) pthread_rwlock_wrlock(&object->attribute_lock);

	/* Did we just lose a copyin race with another thread */
	if (object->attributes != NULL) {
		goto finish;
	}

	slot_object = object->clones[object->master_clone_slotnum];

	rv = meta_get_slot_session(object->master_clone_slotnum, &session,
	    object->creator_session->session_flags);
	if (rv != CKR_OK) {
		goto finish;
	}

	/*
	 * first, get the master template of all the attributes
	 * for this object
	 */
	rv = get_master_attributes_by_object(session, slot_object,
	    &(object->attributes), &(object->num_attributes));
	if (rv != CKR_OK) {
		goto finish;
	}

	/*
	 * Get value for each attribute items.
	 *
	 * Some attributes are required by the given object type.
	 * Some are optional.  Get all the values first, and then
	 * make sure we have value for all required values,
	 */
	attrs = calloc(object->num_attributes, sizeof (CK_ATTRIBUTE));
	if (attrs == NULL) {
		rv = CKR_HOST_MEMORY;
		goto finish;
	}


	for (i = 0; i < object->num_attributes; i++) {
		attrs[i].type =
		    ((object->attributes[i]).attribute).type;
	}
	num_attrs = object->num_attributes;

	hSession = session->hSession;
	fw_st_id = session->fw_st_id;

	/* first, call C_GetAttributeValue() to get size for each attribute */
	rv = FUNCLIST(fw_st_id)->C_GetAttributeValue(hSession,
	    slot_object->hObject, attrs, num_attrs);
	/*
	 * If the return value is not CKR_OK, allow it to be
	 * CKR_ATTRIBUTE_TYPE_INVALID for now.
	 * Some attributes defined in PKCS#11 version 2.11
	 * might not be defined in earlier versions.  We will
	 * TRY to work with those providers if the attribute
	 * is optional.
	 */
	if ((rv != CKR_OK) && (rv != CKR_ATTRIBUTE_TYPE_INVALID)) {
		rv = CKR_FUNCTION_FAILED; /* make sure rv is appropriate */
		goto finish;
	}

	/*
	 * allocate space.
	 * Since we don't know how many attributes have
	 * values at this time, just assume all of them
	 * have values so we save one loop to count the number
	 * of attributes that have value.
	 */
	attrs_with_val = calloc(num_attrs, sizeof (CK_ATTRIBUTE));
	if (attrs_with_val == NULL) {
		rv = CKR_HOST_MEMORY;
		goto finish;
	}


	num_attrs_with_val = 0;
	for (i = 0; i < num_attrs; i++) {
		if (!(((CK_LONG)(attrs[i].ulValueLen)) > 0)) {
			/* if it isn't an optional attr, len should be > 0 */
			if (!object->attributes[i].canBeEmptyValue) {
				rv = CKR_FUNCTION_FAILED;
				goto finish;
			}
		} else {
			attrs_with_val[num_attrs_with_val].type = attrs[i].type;
			attrs_with_val[num_attrs_with_val].ulValueLen =
			    attrs[i].ulValueLen;
			attrs_with_val[num_attrs_with_val].pValue =
			    malloc(attrs[i].ulValueLen);
			if (attrs_with_val[num_attrs_with_val].pValue == NULL) {
				rv = CKR_HOST_MEMORY;
				goto finish;
			}
			num_attrs_with_val++;
		}
	}

	rv = FUNCLIST(fw_st_id)->C_GetAttributeValue(hSession,
	    slot_object->hObject, attrs_with_val, num_attrs_with_val);
	if (rv != CKR_OK) {
		goto finish;
	}

	/* store these values into the meta object */
	for (i = 0; i < num_attrs_with_val; i++) {
		rv = attribute_set_value(&(attrs_with_val[i]),
		    object->attributes, object->num_attributes);
		if (rv != CKR_OK) {
			goto finish;
		}
	}

finish:
	(void) pthread_rwlock_unlock(&object->attribute_lock);

	if (session)
		meta_release_slot_session(session);

	if (attrs) {
		for (i = 0; i < num_attrs; i++) {
			if (attrs[i].pValue != NULL) {
				free(attrs[i].pValue);
			}
		}
		free(attrs);
	}

	if (attrs_with_val) {
		for (i = 0; i < num_attrs; i++) {
			if (attrs_with_val[i].pValue != NULL) {
				freezero(attrs_with_val[i].pValue,
				    attrs_with_val[i].ulValueLen);
			}
		}
		free(attrs_with_val);
	}
	return (rv);
}

/*
 * Create an object to be used for wrapping and unwrapping.
 * The same template will be used for all wrapping/unwrapping keys all
 * the time
 */

static CK_RV
create_wrap_unwrap_key(slot_session_t *slot_session, CK_OBJECT_HANDLE *hObject,
    wrap_info_t *wrap_info, char *key_data, CK_ULONG key_len)
{

	CK_OBJECT_CLASS objclass;
	CK_KEY_TYPE keytype;
	CK_RV rv = CKR_OK;
	int i;
	CK_ATTRIBUTE template[WRAP_KEY_TEMPLATE_SIZE];

	i = 0;
	objclass = wrap_info->class;
	template[i].type = CKA_CLASS;
	template[i].pValue = &objclass;
	template[i].ulValueLen = sizeof (objclass);

	i++;
	keytype = wrap_info->key_type;
	template[i].type = CKA_KEY_TYPE;
	template[i].pValue = &keytype;
	template[i].ulValueLen = sizeof (keytype);

	i++;
	template[i].type = CKA_TOKEN;
	template[i].pValue = &falsevalue;
	template[i].ulValueLen = sizeof (falsevalue);


	if (objclass == CKO_SECRET_KEY) {
		i++;
		template[i].type = CKA_VALUE;
		template[i].pValue = key_data;
		template[i].ulValueLen = key_len;

		i++;
		template[i].type = CKA_WRAP;
		template[i].pValue = &truevalue;
		template[i].ulValueLen = sizeof (truevalue);

		i++;
		template[i].type = CKA_UNWRAP;
		template[i].pValue = &truevalue;
		template[i].ulValueLen = sizeof (truevalue);
	} else {
		/* Modulus is the same for rsa public and private key */
		i++;
		template[i].type = CKA_MODULUS;
		template[i].pValue = Modulus;
		template[i].ulValueLen = sizeof (Modulus);

		if (objclass == CKO_PUBLIC_KEY) {
			/* RSA public key */
			i++;
			template[i].type = CKA_PUBLIC_EXPONENT;
			template[i].pValue = PubExpo;
			template[i].ulValueLen = sizeof (PubExpo);

			i++;
			template[i].type = CKA_WRAP;
			template[i].pValue = &truevalue;
			template[i].ulValueLen = sizeof (truevalue);
		} else {
			/* RSA private key */
			i++;
			template[i].type = CKA_PRIVATE_EXPONENT;
			template[i].pValue = PriExpo;
			template[i].ulValueLen = sizeof (PriExpo);

			i++;
			template[i].type = CKA_UNWRAP;
			template[i].pValue = &truevalue;
			template[i].ulValueLen = sizeof (truevalue);
		}
	}

	rv = FUNCLIST(slot_session->fw_st_id)->C_CreateObject(
	    slot_session->hSession, template, i + 1, hObject);

	return (rv);
}


/*
 * Create a clone of a non-sensitive and extractable object.
 * If the template required for creating the clone doesn't exist,
 * it will be retrieved from the master clone.
 */
static CK_RV
clone_by_create(meta_object_t *object, slot_object_t *new_clone,
    slot_session_t *dst_slot_session)
{
	CK_RV rv;
	int free_token_index = -1;

	if (object->attributes == NULL) {
		rv = meta_object_copyin(object);
		if (rv != CKR_OK) {
			return (rv);
		}
	}

	if (object->clone_template == NULL) {
		rv = meta_clone_template_setup(object, object->attributes,
		    object->num_attributes);
		if (rv != CKR_OK) {
			return (rv);
		}
	}

	if (object->isFreeToken == FREE_ENABLED) {
		if (dst_slot_session->slotnum == get_keystore_slotnum())
			free_token_index = set_template_boolean(CKA_TOKEN,
			    object->clone_template,
			    object->clone_template_size, B_FALSE, &truevalue);
		else
			free_token_index = set_template_boolean(CKA_TOKEN,
			    object->clone_template,
			    object->clone_template_size, B_FALSE, &falsevalue);
	}

	/* Create the clone... */
	rv = FUNCLIST(dst_slot_session->fw_st_id)->C_CreateObject(
	    dst_slot_session->hSession, object->clone_template,
	    object->clone_template_size, &(new_clone->hObject));

	if (free_token_index != -1) {
			free_token_index = set_template_boolean(CKA_TOKEN,
			    object->clone_template, object->clone_template_size,
			    B_FALSE, &falsevalue);
	}

	if (rv != CKR_OK) {
		return (rv);
	}

	return (CKR_OK);
}

/*
 * Goes through the list of wraping mechanisms, and returns the first
 * one that is supported by both the source and the destination slot.
 * If none of the mechanisms are supported by both slot, return the
 * first mechanism that's supported by the source slot
 */
static CK_RV
find_best_match_wrap_mech(wrap_info_t *wrap_info, int num_info,
    CK_ULONG src_slotnum, CK_ULONG dst_slotnum, int *first_both_mech,
    int *first_src_mech)
{

	int i;
	boolean_t src_supports, dst_supports;
	CK_RV rv;
	CK_MECHANISM_INFO mech_info;

	mech_info.flags = CKF_WRAP;

	for (i = 0; i < num_info; i++) {
		src_supports = B_FALSE;
		dst_supports = B_FALSE;

		rv = meta_mechManager_slot_supports_mech(
		    (wrap_info[i]).mech_type, src_slotnum,
		    &src_supports, NULL, B_FALSE, &mech_info);
		if (rv != CKR_OK) {
			return (rv);
		}

		rv = meta_mechManager_slot_supports_mech(
		    (wrap_info[i]).mech_type, dst_slotnum,
		    &dst_supports, NULL, B_FALSE, &mech_info);
		if (rv != CKR_OK) {
			return (rv);
		}

		/* both source and destination supports the mech */
		if ((src_supports) && (dst_supports)) {
			*first_both_mech = i;
			return (CKR_OK);
		}

		if ((src_supports) && (*first_src_mech == -1)) {
			*first_src_mech = i;
		}
	}
	return (CKR_OK);
}

/*
 * Determine the wrapping/unwrapping mechanism to be used
 *
 * If possible, select a mechanism that's supported by both source
 * and destination slot.  If none of the mechanisms are supported
 * by both slot, then, select the first one supported by
 * the source slot.
 */

static CK_RV
get_wrap_mechanism(CK_OBJECT_CLASS obj_class, CK_KEY_TYPE key_type,
    CK_ULONG src_slotnum, CK_ULONG dst_slotnum, wrap_info_t *wrap_info)
{
	wrap_info_t *wrap_info_to_search = NULL;
	unsigned int num_wrap_info;
	CK_RV rv;
	int i;
	boolean_t src_supports = B_FALSE, dst_supports = B_FALSE;
	int first_src_mech, rsa_first_src_mech, first_both_mech;
	CK_MECHANISM_INFO mech_info;

	mech_info.flags = CKF_WRAP;

	if ((obj_class == CKO_PRIVATE_KEY) && (key_type == CKK_KEA)) {
		/*
		 * only SKIPJACK keys can be used for wrapping
		 * KEA private keys
		 */

		for (i = 0; i < num_special_wrap_info; i++) {
			if ((special_wrap_info[i]).mech_type
			    != CKM_SKIPJACK_WRAP) {
				continue;
			}

			src_supports = B_FALSE;
			dst_supports = B_FALSE;

			rv = meta_mechManager_slot_supports_mech(
			    (special_wrap_info[i]).mech_type, src_slotnum,
			    &src_supports, NULL, B_FALSE, &mech_info);
			if (rv != CKR_OK) {
				goto finish;
			}

			rv = meta_mechManager_slot_supports_mech(
			    (special_wrap_info[i]).mech_type, dst_slotnum,
			    &dst_supports, NULL, B_FALSE, &mech_info);
			if (rv != CKR_OK) {
				goto finish;
			}

			if (src_supports) {
				/*
				 * both src and dst supports the mech or
				 * only the src supports the mech
				 */
				(void) memcpy(wrap_info,
				    &(special_wrap_info[i]),
				    sizeof (wrap_info_t));

				wrap_info->src_supports = src_supports;
				wrap_info->dst_supports = dst_supports;
				rv = CKR_OK;
				goto finish;
			}

		}

		/*
		 * if we are here, that means neither the source slot
		 * nor the destination slots supports CKM_SKIPJACK_WRAP.
		 */
		rv = CKR_FUNCTION_FAILED;
		goto finish;
	}

	if ((key_type == CKK_SKIPJACK) || (key_type == CKK_BATON) ||
	    (key_type == CKK_JUNIPER)) {
		/* special key types */
		wrap_info_to_search = special_wrap_info;
		num_wrap_info = num_special_wrap_info;
	} else {
		/* use the regular wrapping mechanisms */
		wrap_info_to_search = common_wrap_info;
		num_wrap_info = num_common_wrap_info;
	}

	first_both_mech = -1;
	first_src_mech = -1;

	rv = find_best_match_wrap_mech(wrap_info_to_search, num_wrap_info,
	    src_slotnum, dst_slotnum, &first_both_mech, &first_src_mech);
	if (rv != CKR_OK) {
		goto finish;
	}

	if (first_both_mech != -1) {
		(void) memcpy(wrap_info,
		    &(wrap_info_to_search[first_both_mech]),
		    sizeof (wrap_info_t));

		wrap_info->src_supports = B_TRUE;
		wrap_info->dst_supports = B_TRUE;
		rv = CKR_OK;
		goto finish;
	}

	/*
	 * If we are here, we did not find a mechanism that's supported
	 * by both source and destination slot.
	 *
	 * If it is a secret key, can also try to wrap it with
	 * a RSA public key
	 */
	if (obj_class == CKO_SECRET_KEY) {
		first_both_mech = -1;
		rsa_first_src_mech = -1;

		rv = find_best_match_wrap_mech(rsa_wrap_info,
		    num_rsa_wrap_info, src_slotnum, dst_slotnum,
		    &first_both_mech, &rsa_first_src_mech);

		if (rv != CKR_OK) {
			goto finish;
		}

		if (first_both_mech > -1) {
			(void) memcpy(wrap_info,
			    &(rsa_wrap_info[first_both_mech]),
			    sizeof (wrap_info_t));

			wrap_info->src_supports = B_TRUE;
			wrap_info->dst_supports = B_TRUE;
			rv = CKR_OK;
			goto finish;
		}
	}

	/*
	 * if we are here, that means none of the mechanisms are supported
	 * by both the source and the destination
	 */
	if (first_src_mech > -1) {
		/* source slot support one of the secret key mechs */
		(void) memcpy(wrap_info,
		    &(wrap_info_to_search[first_src_mech]),
		    sizeof (wrap_info_t));
		wrap_info->src_supports = B_TRUE;
		wrap_info->dst_supports = B_FALSE;
		rv = CKR_OK;
	} else if (rsa_first_src_mech > -1) {
		/* source slot support one of the RSA mechs */
		(void) memcpy(wrap_info, &(rsa_wrap_info[rsa_first_src_mech]),
		    sizeof (wrap_info_t));

		wrap_info->src_supports = B_TRUE;
		wrap_info->dst_supports = B_FALSE;
		rv = CKR_OK;
	} else {
		/* neither source nor destination support any wrap mechs */
		rv = CKR_FUNCTION_FAILED;
	}

finish:
	return (rv);
}


/*
 * This is called if the object to be cloned is a sensitive object
 */
static CK_RV
clone_by_wrap(meta_object_t *object, slot_object_t *new_clone,
    slot_session_t *dst_slot_session)
{
	slot_session_t *src_slot_session = NULL;
	CK_OBJECT_HANDLE wrappingKey = NULL, unwrappingKey = NULL;
	CK_MECHANISM wrappingMech;
	CK_BYTE *wrappedKey = NULL;
	CK_ULONG wrappedKeyLen = 0;
	slot_object_t *slot_object = NULL;
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE unwrapped_obj;
	meta_object_t *tmp_meta_obj = NULL;
	slot_object_t *tmp_slot_obj = NULL;
	CK_OBJECT_CLASS obj_class;
	CK_KEY_TYPE key_type;
	meta_session_t *tmp_meta_session = NULL;
	CK_ATTRIBUTE unwrap_template[4];
	char key_data[1024]; /* should be big enough for any key size */
	char ivbuf[1024]; /* should be big enough for any mech */
	wrap_info_t wrap_info;
	CK_ULONG key_len, unwrap_template_size;

	slot_object = object->clones[object->master_clone_slotnum];

	rv = meta_get_slot_session(object->master_clone_slotnum,
	    &src_slot_session, object->creator_session->session_flags);
	if (rv != CKR_OK) {
		return (rv);
	}

	/*
	 * get the object class and key type for unwrap template
	 * This information will also be used for determining
	 * which wrap mechanism and which key to use for
	 * doing the wrapping
	 */
	unwrap_template[0].type = CKA_CLASS;
	unwrap_template[0].pValue = &obj_class;
	unwrap_template[0].ulValueLen = sizeof (obj_class);

	unwrap_template[1].type = CKA_KEY_TYPE;
	unwrap_template[1].pValue = &key_type;
	unwrap_template[1].ulValueLen = sizeof (key_type);

	rv = FUNCLIST(src_slot_session->fw_st_id)->C_GetAttributeValue(
	    src_slot_session->hSession, slot_object->hObject,
	    unwrap_template, 2);
	if (rv != CKR_OK) {
		goto finish;
	}

	rv = get_wrap_mechanism(obj_class, key_type, src_slot_session->slotnum,
	    dst_slot_session->slotnum, &wrap_info);
	if (rv != CKR_OK) {
		goto finish;
	}

	/*
	 * read number of bytes required from random device for
	 * creating a secret key for wrapping and unwrapping
	 */
	if (wrap_info.class == CKO_SECRET_KEY) {

		/*
		 * /dev/urandom will be used for generating the key used
		 * for doing the wrap/unwrap.  It's should be ok to
		 * use /dev/urandom because this key is used for this
		 * one time operation only.  It doesn't need to be stored.
		 */
		key_len = wrap_info.key_length;
		if (pkcs11_get_urandom(key_data, key_len) < 0) {
			rv = CKR_FUNCTION_FAILED;
			goto finish;
		}

		if (wrap_info.iv_length > 0) {
			if (pkcs11_get_urandom(
			    ivbuf, wrap_info.iv_length) < 0) {
				rv = CKR_FUNCTION_FAILED;
				goto finish;
			}
		}
	}

	/* create the wrapping key */
	rv = create_wrap_unwrap_key(src_slot_session, &wrappingKey,
	    &wrap_info, key_data, key_len);
	if (rv != CKR_OK) {
		goto finish;
	}

	wrappingMech.mechanism = wrap_info.mech_type;
	wrappingMech.pParameter = ((wrap_info.iv_length > 0) ? ivbuf : NULL);
	wrappingMech.ulParameterLen = wrap_info.iv_length;

	/* get the size of the wrapped key */
	rv = FUNCLIST(src_slot_session->fw_st_id)->C_WrapKey(
	    src_slot_session->hSession, &wrappingMech,
	    wrappingKey, slot_object->hObject, NULL, &wrappedKeyLen);

	if (rv != CKR_OK) {
		goto finish;
	}

	wrappedKey = malloc(wrappedKeyLen * sizeof (CK_BYTE));
	if (wrappedKey == NULL) {
		rv = CKR_HOST_MEMORY;
		goto finish;
	}

	/* do the actual key wrapping */
	rv = FUNCLIST(src_slot_session->fw_st_id)->C_WrapKey(
	    src_slot_session->hSession, &wrappingMech,
	    wrappingKey, slot_object->hObject, wrappedKey, &wrappedKeyLen);

	if (rv != CKR_OK) {
		goto finish;
	}

	/* explicitly force the unwrapped object to be not sensitive */
	unwrap_template[2].type = CKA_SENSITIVE;
	unwrap_template[2].pValue = &falsevalue;
	unwrap_template[2].ulValueLen = sizeof (falsevalue);

	unwrap_template[3].type = CKA_TOKEN;
	unwrap_template[3].pValue = &falsevalue;
	unwrap_template[3].ulValueLen = sizeof (falsevalue);

	unwrap_template_size =
	    sizeof (unwrap_template) / sizeof (CK_ATTRIBUTE);

	if (!wrap_info.dst_supports) {
		/*
		 * if we know for sure that the destination slot doesn't
		 * support the wrapping mechanism, no point in trying.
		 * go directly to unwrap in source slot, and create key
		 * in destination
		 */
		goto unwrap_in_source;
	}

	/* create the unwrapping key in destination slot */
	if (wrap_info.key_type == CKK_RSA) {
		/* for RSA key, the unwrapping key need to be private key */
		wrap_info.class = CKO_PRIVATE_KEY;
	}
	rv = create_wrap_unwrap_key(dst_slot_session,
	    &unwrappingKey, &wrap_info, key_data, key_len);
	if (rv != CKR_OK) {
		goto finish;
	}

	rv = FUNCLIST(dst_slot_session->fw_st_id)->C_UnwrapKey(
	    dst_slot_session->hSession, &wrappingMech,
	    unwrappingKey, wrappedKey, wrappedKeyLen, unwrap_template,
	    unwrap_template_size, &(new_clone->hObject));

	if (rv != CKR_OK) {
unwrap_in_source:

		/*
		 * There seemed to be a problem with unwrapping in the
		 * destination slot.
		 * Try to do the unwrap in the src slot so it becomes
		 * a non-sensitive object, then, get all the attributes
		 * and create the object in the destination slot
		 */


		if (wrap_info.class == CKO_SECRET_KEY) {
			/* unwrap with same key used for wrapping */
			rv = FUNCLIST(src_slot_session->fw_st_id)->C_UnwrapKey(
			    src_slot_session->hSession,
			    &wrappingMech, wrappingKey, wrappedKey,
			    wrappedKeyLen, unwrap_template,
			    unwrap_template_size, &(unwrapped_obj));
		} else {
			/*
			 * If the object is wrapping with RSA public key, need
			 * need to create RSA private key for unwrapping
			 */
			wrap_info.class = CKO_PRIVATE_KEY;
			rv = create_wrap_unwrap_key(src_slot_session,
			    &unwrappingKey, &wrap_info, key_data, key_len);
			if (rv != CKR_OK) {
				goto finish;
			}
			rv = FUNCLIST(src_slot_session->fw_st_id)->C_UnwrapKey(
			    src_slot_session->hSession,
			    &wrappingMech, unwrappingKey, wrappedKey,
			    wrappedKeyLen, unwrap_template,
			    unwrap_template_size, &(unwrapped_obj));
		}


		if (rv != CKR_OK) {
			goto finish;
		}

		rv = meta_session_alloc(&tmp_meta_session);
		if (rv != CKR_OK) {
			goto finish;
		}

		tmp_meta_session->session_flags = CKF_SERIAL_SESSION;

		rv = meta_object_alloc(tmp_meta_session, &tmp_meta_obj);
		if (rv != CKR_OK) {
			goto finish;
		}

		rv = meta_slot_object_alloc(&tmp_slot_obj);
		if (rv != CKR_OK) {
			goto finish;
		}

		tmp_meta_obj->master_clone_slotnum = src_slot_session->slotnum;
		tmp_slot_obj->hObject = unwrapped_obj;
		tmp_meta_obj->clones[tmp_meta_obj->master_clone_slotnum]
		    = tmp_slot_obj;
		meta_slot_object_activate(tmp_slot_obj, src_slot_session,
		    B_FALSE);
		tmp_slot_obj = NULL;

		rv = clone_by_create(tmp_meta_obj, new_clone,
		    dst_slot_session);
		if (rv != CKR_OK) {
			goto finish;
		}
	}

finish:
	if (unwrappingKey) {
		(void) FUNCLIST(dst_slot_session->fw_st_id)->C_DestroyObject(
		    dst_slot_session->hSession, unwrappingKey);
	}

	if (wrappingKey) {
		(void) FUNCLIST(src_slot_session->fw_st_id)->C_DestroyObject(
		    src_slot_session->hSession, wrappingKey);
	}

	if (tmp_slot_obj) {
		(void) meta_slot_object_dealloc(tmp_slot_obj);
	}

	if (tmp_meta_obj) {
		(void) meta_object_dealloc(tmp_meta_session, tmp_meta_obj,
		    B_TRUE);
	}

	if (tmp_meta_session) {
		(void) meta_session_dealloc(tmp_meta_session);
	}

	if (wrappedKey) {
		freezero(wrappedKey, wrappedKeyLen);
	}

	if (src_slot_session) {
		meta_release_slot_session(src_slot_session);
	}

	return (rv);

}


/*
 * meta_object_get_clone
 *
 * Creates a "clone" of a metaobject on the specified slot. A clone is a
 * copy of the object.
 *
 * Clones are cached, so that they can be reused with subsequent operations.
 */
CK_RV
meta_object_get_clone(meta_object_t *object,
    CK_ULONG slot_num, slot_session_t *slot_session, slot_object_t **clone)
{
	CK_RV rv = CKR_OK;
	slot_object_t *newclone = NULL;

	/* Does a clone already exist? */
	if (object->clones[slot_num] != NULL) {
		*clone = object->clones[slot_num];
		return (CKR_OK);
	}

	if ((object->isSensitive) && (object->isToken) &&
	    (!metaslot_auto_key_migrate)) {
		/*
		 * if the object is a sensitive token object, and auto
		 * key migrate is not allowed, will not create the clone
		 * in another slot
		 */
		return (CKR_FUNCTION_FAILED);
	}

	/* object attributes can't be extracted and attributes are not known */
	if ((!object->isExtractable) && (object->attributes == NULL)) {
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_lock(&object->clone_create_lock);

	/* Maybe someone just created one? */
	if (object->clones[slot_num] != NULL) {
		*clone = object->clones[slot_num];
		goto finish;
	}

	/*
	 * has an attempt already been made to create this object in
	 * slot?  If yes, and there's no clone, as indicated above,
	 * that means this object can't be created in this slot.
	 */
	if (object->tried_create_clone[slot_num]) {
		(void) pthread_mutex_unlock(&object->clone_create_lock);
		return (CKR_FUNCTION_FAILED);
	}

	rv = meta_slot_object_alloc(&newclone);
	if (rv != CKR_OK)
		goto finish;

	object->tried_create_clone[slot_num] = B_TRUE;

	/*
	 * If this object is sensitive and we do not have not copied in the
	 * attributes via FreeObject functionality, then we need to wrap it off
	 * the provider.  If we do have attributes, we can just create the
	 * clone
	 */

	if (object->isSensitive && object->attributes == NULL) {
		rv = clone_by_wrap(object, newclone, slot_session);
	} else {
		rv = clone_by_create(object, newclone, slot_session);
	}

	if (rv != CKR_OK) {
		goto finish;
	}

	object->clones[slot_num] = newclone;
	meta_slot_object_activate(newclone, slot_session, object->isToken);

	*clone = newclone;
	newclone = NULL;
finish:
	(void) pthread_mutex_unlock(&object->clone_create_lock);

	if (newclone)
		meta_slot_object_dealloc(newclone);

	return (rv);
}


/*
 * meta_setup_clone_template
 *
 * Create a clone template for the specified object.
 */
static CK_RV
meta_clone_template_setup(meta_object_t *object,
    const generic_attr_t *attributes, size_t num_attributes)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE *clone_template;
	size_t i, c = 0;

	clone_template = malloc(num_attributes * sizeof (CK_ATTRIBUTE));
	if (clone_template == NULL) {
		rv = CKR_HOST_MEMORY;
		goto finish;
	}

	/* Don't allow attributes to change while we look at them. */
	(void) pthread_rwlock_rdlock(&object->attribute_lock);

	for (i = 0; i < num_attributes; i++) {
		if (!attributes[i].isCloneAttr ||
		    (attributes[i].attribute.type == CKA_TOKEN &&
		    object->isFreeToken == FREE_DISABLED)) {
			continue;
		}
		if ((!(attributes[i].hasValueForClone)) &&
		    (attributes[i].canBeEmptyValue)) {
			continue;
		}

		clone_template[c].type = attributes[i].attribute.type;
		clone_template[c].ulValueLen =
		    attributes[i].attribute.ulValueLen;
		/* Allocate space to store the attribute value. */
		clone_template[c].pValue = malloc(clone_template[c].ulValueLen);
		if (clone_template[c].pValue == NULL) {
			free(clone_template);
			rv = CKR_HOST_MEMORY;
			(void) pthread_rwlock_unlock(&object->attribute_lock);
			goto finish;
		}

		(void) memcpy(clone_template[c].pValue,
		    object->attributes[i].attribute.pValue,
		    clone_template[c].ulValueLen);
		c++;
	}

	(void) pthread_rwlock_unlock(&object->attribute_lock);

	object->clone_template = clone_template;
	object->clone_template_size = c;

finish:
	return (rv);
}


/*
 * meta_object_find_by_handle
 *
 * Search for an existing metaobject, using the object handle of a clone
 * on a particular slot.
 *
 * Returns a matching metaobject, or NULL if no match was found.
 */
meta_object_t *
meta_object_find_by_handle(CK_OBJECT_HANDLE hObject, CK_ULONG slotnum,
    boolean_t token_only)
{
	meta_object_t *object = NULL, *tmp_obj;
	meta_session_t *session;

	if (!token_only) {
		(void) pthread_rwlock_rdlock(&meta_sessionlist_lock);
		session = meta_sessionlist_head;
		while (session != NULL) {
			/* lock the objects list while we look at it */
			(void) pthread_rwlock_rdlock(
			    &(session->object_list_lock));
			tmp_obj = session->object_list_head;
			while (tmp_obj != NULL) {
				slot_object_t *slot_object;

				(void) pthread_rwlock_rdlock(
				    &(tmp_obj->object_lock));
				slot_object = tmp_obj->clones[slotnum];
				if (slot_object != NULL) {
					if (slot_object->hObject == hObject) {
						object = tmp_obj;
					}
				}
				(void) pthread_rwlock_unlock(
				    &(tmp_obj->object_lock));
				if (object != NULL) {
					break;
				}
				tmp_obj = tmp_obj->next;
			}
			(void) pthread_rwlock_unlock(
			    &(session->object_list_lock));
			if (object != NULL) {
				break;
			}
			session = session->next;
		}
		(void) pthread_rwlock_unlock(&meta_sessionlist_lock);
	}

	if (object != NULL) {
		/* found the object, no need to look further */
		return (object);
	}

	/*
	 * Look at list of token objects
	 */
	(void) pthread_rwlock_rdlock(&tokenobject_list_lock);
	tmp_obj = tokenobject_list_head;

	while (tmp_obj != NULL) {
		slot_object_t *slot_object;

		(void) pthread_rwlock_rdlock(&(tmp_obj->object_lock));
		slot_object = tmp_obj->clones[slotnum];
		if (slot_object != NULL) {
			if (slot_object->hObject == hObject)
				object = tmp_obj;
		}
		(void) pthread_rwlock_unlock(&(tmp_obj->object_lock));
		if (object != NULL) {
			break;
		}
		tmp_obj = tmp_obj->next;
	}
	(void) pthread_rwlock_unlock(&tokenobject_list_lock);

	return (object);
}

CK_RV
meta_token_object_deactivate(token_obj_type_t token_type)
{
	meta_object_t *object, *tmp_object;
	CK_RV save_rv = CKR_OK, rv;

	/* get a write lock on the token object list */
	(void) pthread_rwlock_wrlock(&tokenobject_list_lock);

	object = tokenobject_list_head;

	/* go through each object and delete the one with matching type */
	while (object != NULL) {
		tmp_object = object->next;

		if ((token_type == ALL_TOKEN) ||
		    ((object->isPrivate) && (token_type == PRIVATE_TOKEN)) ||
		    ((!object->isPrivate) && (token_type == PUBLIC_TOKEN))) {
			rv = meta_object_deactivate(object, B_TRUE, B_FALSE);
			if ((rv != CKR_OK) && (save_rv == CKR_OK)) {
				save_rv = rv;
				goto finish;
			}
			rv = meta_object_dealloc(NULL, object, B_FALSE);
			if ((rv != CKR_OK) && (save_rv == CKR_OK)) {
				save_rv = rv;
				goto finish;
			}
		}
		object = tmp_object;
	}
finish:
	(void) pthread_rwlock_unlock(&tokenobject_list_lock);
	return (save_rv);
}

/*
 * This function adds the to-be-freed meta object to a linked list.
 * When the number of objects queued in the linked list reaches the
 * maximum threshold MAX_OBJ_TO_BE_FREED, it will free the first
 * object (FIFO) in the list.
 */
void
meta_object_delay_free(meta_object_t *objp)
{
	meta_object_t *tmp;

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


/*
 * This function checks if the object passed can be a freeobject.
 *
 * If there is more than one provider that supports the supported freeobject
 * mechanisms then allow freeobjects to be an option.
 */

boolean_t
meta_freeobject_check(meta_session_t *session, meta_object_t *object,
    CK_MECHANISM *pMech, CK_ATTRIBUTE *tmpl, CK_ULONG tmpl_len,
    CK_KEY_TYPE keytype)
{
	mech_support_info_t *info = &(session->mech_support_info);

	/*
	 * If key migration is turned off, or the object does not has any of
	 * the required flags and there is only one slot, then we don't need
	 * FreeObjects.
	 */
	if (!metaslot_auto_key_migrate ||
	    (!object->isToken && !object->isSensitive &&
	    meta_slotManager_get_slotcount() < 2))
		goto failure;

	/*
	 * If this call is for key generation, check pMech for supported
	 * FreeObject mechs
	 */
	if (pMech != NULL) {
		if (pMech->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN ||
		    pMech->mechanism == CKM_EC_KEY_PAIR_GEN ||
		    pMech->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN ||
		    pMech->mechanism == CKM_DH_PKCS_DERIVE)
			info->mech = pMech->mechanism;
		else
			goto failure;

	/*
	 * If this call is for an object creation, look inside the template
	 * for supported FreeObject mechs
	 */
	} else if (tmpl_len > 0) {
		if (!get_template_ulong(CKA_KEY_TYPE, tmpl, tmpl_len, &keytype))
			goto failure;

		switch (keytype) {
		case CKK_RSA:
			info->mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
			break;
		case CKK_EC:
			info->mech = CKM_EC_KEY_PAIR_GEN;
			break;
		case CKK_DH:
			info->mech = CKM_DH_PKCS_KEY_PAIR_GEN;
			break;
		default:
			goto failure;
		}
	} else
		goto failure;

	/* Get the slot that support this mech... */
	if (meta_mechManager_get_slots(info, B_FALSE, NULL) != CKR_OK)
		goto failure;

	/*
	 * If there is only one slot with the mech or the first slot in
	 * the list is the keystore slot, we should bail.
	 */
	if (info->num_supporting_slots < 2 &&
	    info->supporting_slots[0]->slotnum == get_keystore_slotnum())
		goto failure;

	if (object->isToken)
		object->isFreeToken = FREE_ALLOWED_KEY;
	else
		object->isFreeToken = FREE_DISABLED;

	object->isFreeObject = FREE_ALLOWED_KEY;

	return (B_TRUE);

failure:
	object->isFreeToken = FREE_DISABLED;
	object->isFreeObject = FREE_DISABLED;
	return (B_FALSE);
}

/*
 * This function assumes meta_freeobject_check() has just been called and set
 * the isFreeObject and/or isFreeToken vars to FREE_ALLOWED_KEY.
 *
 * If the template value for CKA_PRIVATE, CKA_SENSITIVE and/or CKA_TOKEN are
 * true, then isFreeObject is fully enabled.  In addition isFreeToken is
 * enabled if is CKA_TOKEN true.
 *
 * If create is true, we are doing a C_CreateObject operation and don't
 * handle CKA_PRIVATE & CKA_SENSITIVE flags, we only care about CKA_TOKEN.
 */

boolean_t
meta_freeobject_set(meta_object_t *object, CK_ATTRIBUTE *tmpl,
    CK_ULONG tmpl_len, boolean_t create)
{

	/* This check should never be true, if it is, it's a bug */
	if (object->isFreeObject < FREE_ALLOWED_KEY)
		return (B_FALSE);

	if (!create) {
		/* Turn off the Sensitive flag */
		if (object->isSensitive) {
			if (set_template_boolean(CKA_SENSITIVE, tmpl, tmpl_len,
			    B_TRUE, &falsevalue) == -1)
				goto failure;

			object->isFreeObject = FREE_ENABLED;
		}

		/* Turn off the Private flag */
		if (object->isPrivate) {
			if (set_template_boolean(CKA_PRIVATE, tmpl, tmpl_len,
			    B_TRUE, &falsevalue) == -1)
				goto failure;

			object->isFreeObject = FREE_ENABLED;
		}
	}

	if (object->isToken) {
		object->isToken = B_FALSE;
		object->isFreeToken = FREE_ENABLED;
		object->isFreeObject = FREE_ENABLED;
	} else
		object->isFreeToken = FREE_DISABLED;

	/*
	 *  If isFreeObject is not in the FREE_ENABLED state yet, it can be
	 *  turned off because the object doesn't not need to be a FreeObject.
	 */
	if (object->isFreeObject == FREE_ALLOWED_KEY)
		object->isFreeObject = FREE_DISABLED;

	return (B_TRUE);

failure:
	object->isFreeToken = FREE_DISABLED;
	object->isFreeObject = FREE_DISABLED;
	return (B_FALSE);
}

/*
 * This function sets the CKA_TOKEN flag on a given object template depending
 * if the slot being used is a keystore.
 *
 * If the object is a token, but the slot is not the system keystore or has
 * no keystore, then set the template to token = false; otherwise it's true.
 * In addition we know ahead of time what the value is, so if the value is
 * already correct, bypass the setting function
 */
CK_RV
meta_freetoken_set(CK_ULONG slot_num, CK_BBOOL *current_value,
    CK_ATTRIBUTE *tmpl, CK_ULONG tmpl_len)
{

	if (slot_num == get_keystore_slotnum()) {
		if (*current_value == TRUE)
			return (CKR_OK);

		if (set_template_boolean(CKA_TOKEN, tmpl, tmpl_len, B_TRUE,
		    &truevalue) == -1)
			return (CKR_FUNCTION_FAILED);

	} else {

		if (*current_value == FALSE)
			return (CKR_OK);

		if (set_template_boolean(CKA_TOKEN, tmpl, tmpl_len, B_TRUE,
		    &falsevalue) == -1)
			return (CKR_FUNCTION_FAILED);

		*current_value = FALSE;
	}

	return (CKR_OK);
}

/*
 * Cloning function for meta_freeobject_clone() to use.  This function
 * is streamlined because we know what the object is and this should
 * not be called as a generic cloner.
 */

static CK_RV
meta_freeobject_clone_maker(meta_session_t *session, meta_object_t *object,
    CK_ULONG slotnum)
{

	slot_object_t *slot_object = NULL;
	slot_session_t *slot_session = NULL;
	CK_RV rv;

	rv = meta_slot_object_alloc(&slot_object);
	if (rv != CKR_OK)
		goto cleanup;

	rv = meta_get_slot_session(slotnum, &slot_session,
	    session->session_flags);
	if (rv != CKR_OK)
		goto cleanup;

	rv = clone_by_create(object, slot_object, slot_session);
	if (rv == CKR_OK) {
		object->clones[slotnum] = slot_object;
		meta_slot_object_activate(slot_object, slot_session, B_TRUE);
	}

cleanup:
	meta_release_slot_session(slot_session);
	return (rv);

}

/*
 * This function is called when a object is a FreeObject.
 *
 * What we are given is an object that has been generated on a provider
 * that is not its final usage place. That maybe because:
 * 1) it's a token and needs to be stored in keystore.
 * 2) it was to be a private/sensitive object that we modified so we could know
 *    the important attributes for cloning before we make it private/sensitive.
 */

boolean_t
meta_freeobject_clone(meta_session_t *session, meta_object_t *object)
{
	CK_RV rv;
	CK_ULONG keystore_slotnum;
	CK_ATTRIBUTE attr[2];
	boolean_t failover = B_FALSE;

	if (object->attributes == NULL) {
		rv = meta_object_copyin(object);
		if (rv != CKR_OK)
			return (rv);
	}

	if (object->isPrivate) {
		CK_OBJECT_HANDLE new_clone;
		CK_ULONG slotnum = object->master_clone_slotnum;
		slot_session_t *slot_session;

		attr[0].type = CKA_PRIVATE;
		attr[0].pValue = &truevalue;
		attr[0].ulValueLen = sizeof (truevalue);

		/* Set the master attribute list */
		rv = attribute_set_value(attr, object->attributes,
		    object->num_attributes);
		if (rv > 0)
			return (CKR_FUNCTION_FAILED);

		/* Get a slot session */
		rv = meta_get_slot_session(slotnum, &slot_session,
		    session->session_flags);
		if (rv > 0)
			return (rv);

		/* Create the new CKA_PRIVATE one */
		rv = FUNCLIST(slot_session->fw_st_id)->\
		    C_CopyObject(slot_session->hSession,
		    object->clones[slotnum]->hObject, attr, 1, &new_clone);

		if (rv == CKR_USER_NOT_LOGGED_IN) {
			/*
			 * If the CopyObject fails, we may be using a provider
			 * that has a keystore that is not the default
			 * keystore set in metaslot or has object management
			 * abilities. In which case we should write this
			 * object to metaslot's keystore and let the failover.
			 * rest of the function know we've changed providers.
			 */
			failover = B_TRUE;
			keystore_slotnum = get_keystore_slotnum();
			if (object->clones[keystore_slotnum] == NULL) {
				rv = meta_freeobject_clone_maker(session,
				    object, keystore_slotnum);
				if (rv != CKR_OK) {
					goto failure;
				}
			}
			object->master_clone_slotnum = keystore_slotnum;

		} else if (rv != CKR_OK) {
			meta_release_slot_session(slot_session);
			goto failure;
		}
		/* Remove the old object */
		rv = FUNCLIST(slot_session->fw_st_id)->	\
		    C_DestroyObject(slot_session->hSession,
		    object->clones[slotnum]->hObject);
		if (rv != CKR_OK) {
			meta_release_slot_session(slot_session);
			goto failure;
		}

		if (!failover)
			object->clones[slotnum]->hObject = new_clone;
		else
			object->clones[slotnum] = NULL;

		meta_release_slot_session(slot_session);

	}

	if (object->isSensitive) {
		slot_session_t *slot_session;
		CK_ULONG slotnum = object->master_clone_slotnum;

		attr[0].type = CKA_SENSITIVE;
		attr[0].pValue = &truevalue;
		attr[0].ulValueLen = sizeof (truevalue);
		rv = attribute_set_value(attr, object->attributes,
		    object->num_attributes);
		if (rv != CKR_OK)
			goto failure;

		rv = meta_get_slot_session(slotnum, &slot_session,
		    session->session_flags);
		if (rv == CKR_OK) {
			rv = FUNCLIST(slot_session->fw_st_id)->		\
			    C_SetAttributeValue(slot_session->hSession,
			    object->clones[slotnum]->hObject, attr, 1);

			meta_release_slot_session(slot_session);
		}
	}

	if (object->isFreeToken == FREE_ENABLED || failover) {
		keystore_slotnum = get_keystore_slotnum();
		if (object->clones[keystore_slotnum] == NULL) {
			rv = meta_freeobject_clone_maker(session, object,
			    keystore_slotnum);
			if (rv != CKR_OK)
				goto failure;

			object->master_clone_slotnum = keystore_slotnum;
		}
		object->isFreeToken = FREE_ENABLED;
	}

	object->isFreeObject = FREE_ENABLED;
	return (CKR_OK);

failure:
	object->isFreeToken = FREE_DISABLED;
	object->isFreeObject = FREE_DISABLED;
	return (rv);

}
