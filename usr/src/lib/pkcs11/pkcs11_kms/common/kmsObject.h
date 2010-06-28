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

#ifndef	_KMSOBJECT_H
#define	_KMSOBJECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <security/pkcs11t.h>
#include "kmsSession.h"
#include "kmsSlot.h"

#define	KMSTOKEN_OBJECT_MAGIC 0xECF0B004

#define	KMS_CREATE_OBJ	1
#define	KMS_GEN_KEY	2

/*
 * Secret key Struct
 */
typedef struct secret_key_obj {
	CK_BYTE *sk_value;
	CK_ULONG sk_value_len;
	void *key_sched;
	size_t keysched_len;
} secret_key_obj_t;

/*
 * This structure is used to hold the attributes in the
 * Extra Attribute List.
 */
typedef struct attribute_info {
	CK_ATTRIBUTE	attr;
	struct attribute_info *next;
} attribute_info_t;

typedef attribute_info_t *CK_ATTRIBUTE_INFO_PTR;

/*
 * This is the main structure of the Objects.
 */
typedef struct object {
	boolean_t	is_lib_obj; /* default is TRUE */

	/* Generic common fields. Always present */
	CK_OBJECT_CLASS class;
	CK_KEY_TYPE key_type;
	CK_ULONG magic_marker;
	uint64_t bool_attr_mask;
	CK_MECHANISM_TYPE mechanism;

	/* Fields for access and arbitration */
	pthread_mutex_t object_mutex;
	struct object *next;
	struct object *prev;

	/* Extra non-boolean attribute list */
	CK_ATTRIBUTE_INFO_PTR extra_attrlistp;
	CK_ULONG extra_attrcount;

	/* For each object, only one object class is presented */
	union {
		secret_key_obj_t  *secret_key;
	} object_class_u;

	/* Session handle that the object belongs to */
	CK_SESSION_HANDLE	session_handle;
	uint32_t	obj_refcnt;	/* object reference count */
	pthread_cond_t	obj_free_cond;	/* cond variable for signal and wait */
	uint32_t	obj_delete_sync;	/* object delete sync flags */
} kms_object_t;

typedef struct find_context {
	kms_object_t **objs_found;
	CK_ULONG num_results;
	CK_ULONG next_result_index; /* next result object to return */
} find_context_t;

/*
 * The following structure is used to link the to-be-freed session
 * objects into a linked list. The objects on this linked list have
 * not yet been freed via free() after C_DestroyObject() call; instead
 * they are added to this list. The actual free will take place when
 * the number of objects queued reaches MAX_OBJ_TO_BE_FREED, at which
 * time the first object in the list will be freed.
 */
#define	MAX_OBJ_TO_BE_FREED		300

typedef struct obj_to_be_freed_list {
	kms_object_t	*first;	/* points to first obj in the list */
	kms_object_t	*last;	/* points to last obj in the list */
	uint32_t	count;	/* current total objs in the list */
	pthread_mutex_t obj_to_be_free_mutex;
} object_to_be_freed_list_t;

extern object_to_be_freed_list_t obj_delay_freed;

/*
 * The following definitions are the shortcuts
 */

/*
 * Secret Key Object Attributes
 */
#define	OBJ_SEC(o) \
	((o)->object_class_u.secret_key)
#define	OBJ_SEC_VALUE(o) \
	((o)->object_class_u.secret_key->sk_value)
#define	OBJ_SEC_VALUE_LEN(o) \
	((o)->object_class_u.secret_key->sk_value_len)
#define	OBJ_KEY_SCHED(o) \
	((o)->object_class_u.secret_key->key_sched)
#define	OBJ_KEY_SCHED_LEN(o) \
	((o)->object_class_u.secret_key->keysched_len)

/*
 * key related attributes with CK_BBOOL data type
 */
#define	DERIVE_BOOL_ON			0x00000001
#define	LOCAL_BOOL_ON			0x00000002
#define	SENSITIVE_BOOL_ON		0x00000004
#define	SECONDARY_AUTH_BOOL_ON		0x00000008
#define	ENCRYPT_BOOL_ON			0x00000010
#define	DECRYPT_BOOL_ON			0x00000020
#define	SIGN_BOOL_ON			0x00000040
#define	SIGN_RECOVER_BOOL_ON		0x00000080
#define	VERIFY_BOOL_ON			0x00000100
#define	VERIFY_RECOVER_BOOL_ON		0x00000200
#define	WRAP_BOOL_ON			0x00000400
#define	UNWRAP_BOOL_ON			0x00000800
#define	TRUSTED_BOOL_ON			0x00001000
#define	EXTRACTABLE_BOOL_ON		0x00002000
#define	ALWAYS_SENSITIVE_BOOL_ON	0x00004000
#define	NEVER_EXTRACTABLE_BOOL_ON	0x00008000
#define	PRIVATE_BOOL_ON			0x00010000
#define	TOKEN_BOOL_ON			0x00020000
#define	MODIFIABLE_BOOL_ON		0x00040000

#define	SECRET_KEY_DEFAULT	(ENCRYPT_BOOL_ON|\
				DECRYPT_BOOL_ON|\
				SIGN_BOOL_ON|\
				VERIFY_BOOL_ON|\
				WRAP_BOOL_ON|\
				UNWRAP_BOOL_ON|\
				EXTRACTABLE_BOOL_ON|\
				MODIFIABLE_BOOL_ON)

/*
 * Flag definitions for obj_delete_sync
 */
#define	OBJECT_IS_DELETING	1	/* Object is in a deleting state */
#define	OBJECT_REFCNT_WAITING	2	/* Waiting for object reference */
					/* count to become zero */

/*
 * This macro is used to type cast an object handle to a pointer to
 * the object struct. Also, it checks to see if the object struct
 * is tagged with an object magic number. This is to detect when an
 * application passes a bogus object pointer.
 * Also, it checks to see if the object is in the deleting state that
 * another thread is performing. If not, increment the object reference
 * count by one. This is to prevent this object from being deleted by
 * other thread.
 */
#define	HANDLE2OBJECT_COMMON(hObject, object_p, rv, REFCNT_CODE) { \
	object_p = (kms_object_t *)(hObject); \
	if ((object_p == NULL) || \
		(object_p->magic_marker != KMSTOKEN_OBJECT_MAGIC)) {\
			rv = CKR_OBJECT_HANDLE_INVALID; \
	} else { \
		(void) pthread_mutex_lock(&object_p->object_mutex); \
		if (!(object_p->obj_delete_sync & OBJECT_IS_DELETING)) { \
			REFCNT_CODE; \
			rv = CKR_OK; \
		} else { \
			rv = CKR_OBJECT_HANDLE_INVALID; \
		} \
		(void) pthread_mutex_unlock(&object_p->object_mutex); \
	} \
}

#define	HANDLE2OBJECT(hObject, object_p, rv) \
	HANDLE2OBJECT_COMMON(hObject, object_p, rv, object_p->obj_refcnt++)

#define	HANDLE2OBJECT_DESTROY(hObject, object_p, rv) \
	HANDLE2OBJECT_COMMON(hObject, object_p, rv, /* no refcnt increment */)


#define	OBJ_REFRELE(object_p) { \
	(void) pthread_mutex_lock(&object_p->object_mutex); \
	if ((--object_p->obj_refcnt) == 0 && \
	    (object_p->obj_delete_sync & OBJECT_REFCNT_WAITING)) { \
		(void) pthread_cond_signal(&object_p->obj_free_cond); \
	} \
	(void) pthread_mutex_unlock(&object_p->object_mutex); \
}


/*
 * Function Prototypes.
 */
void kms_cleanup_object(kms_object_t *objp);

CK_RV kms_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
    CK_ULONG *objecthandle_p, kms_session_t *sp);

CK_RV kms_delete_object(kms_session_t *, kms_object_t *,
    boolean_t, boolean_t);

void kms_cleanup_extra_attr(kms_object_t *object_p);

CK_RV kms_copy_extra_attr(CK_ATTRIBUTE_INFO_PTR old_attrp,
    kms_object_t *object_p);

void kms_cleanup_object_bigint_attrs(kms_object_t *object_p);

CK_RV kms_build_object(CK_ATTRIBUTE_PTR, CK_ULONG, kms_object_t *);

CK_RV kms_copy_object(kms_object_t *old_object,
    kms_object_t **new_object, boolean_t copy_everything,
    kms_session_t *sp);

void kms_merge_object(kms_object_t *old_object,
    kms_object_t *new_object);

CK_RV kms_get_attribute(kms_object_t *object_p,
    CK_ATTRIBUTE_PTR template);

CK_RV kms_set_attribute(kms_object_t *, CK_ATTRIBUTE_PTR, boolean_t);

void kms_add_object_to_session(kms_object_t *objp, kms_session_t *sp);

CK_RV kms_copy_secret_key_attr(secret_key_obj_t *old_secret_key_obj_p,
    secret_key_obj_t **new_secret_key_obj_p);

CK_RV kms_validate_attr(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
    CK_OBJECT_CLASS *class);

CK_RV kms_find_objects_init(kms_session_t *sp,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

void kms_find_objects_final(kms_session_t *sp);

CK_RV kms_find_objects(kms_session_t *sp,
    CK_OBJECT_HANDLE *obj_found, CK_ULONG max_obj_requested,
    CK_ULONG *found_obj_count);

void kms_process_find_attr(CK_OBJECT_CLASS *pclasses,
    CK_ULONG *num_result_pclasses, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount);

boolean_t kms_find_match_attrs(kms_object_t *obj,
    CK_OBJECT_CLASS *pclasses, CK_ULONG num_pclasses,
    CK_ATTRIBUTE *tmpl_attr, CK_ULONG num_attr);

CK_ATTRIBUTE_PTR get_extra_attr(CK_ATTRIBUTE_TYPE type, kms_object_t *obj);

CK_RV get_string_from_template(CK_ATTRIBUTE_PTR dest, CK_ATTRIBUTE_PTR src);

void string_attr_cleanup(CK_ATTRIBUTE_PTR template);

void kms_add_token_object_to_slot(kms_object_t *objp,
    kms_slot_t *pslot);

void kms_remove_token_object_from_slot(kms_slot_t *pslot,
    kms_object_t *objp);

CK_RV kms_delete_token_object(kms_slot_t *pslot, kms_session_t *sp,
    kms_object_t *obj, boolean_t lock_held, boolean_t wrapper_only);

void kms_cleanup_pri_objects_in_slot(kms_slot_t *pslot,
    kms_session_t *sp);

CK_RV kms_get_object_size(kms_object_t *objp, CK_ULONG_PTR pulSize);

void kms_object_delay_free(kms_object_t *);

kms_object_t *kms_new_object();
void kms_free_object(kms_object_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _KMSOBJECT_H */
