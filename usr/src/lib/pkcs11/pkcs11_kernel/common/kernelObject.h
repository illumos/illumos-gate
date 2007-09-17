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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KERNELOBJECT_H
#define	_KERNELOBJECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <security/pkcs11t.h>
#include "kernelSession.h"
#include "kernelSlot.h"

#define	KERNELTOKEN_OBJECT_MAGIC	0xECF0B003

#define	KERNEL_CREATE_OBJ	1
#define	KERNEL_GEN_KEY		2

#define	RSA_PRI_ATTR_COUNT		7
#define	RSA_PUB_ATTR_COUNT		3
#define	DSA_ATTR_COUNT			4
#define	EC_ATTR_COUNT			2

/*
 * Secret key Struct
 */
typedef struct secret_key_obj {
	CK_BYTE *sk_value;
	CK_ULONG sk_value_len;
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
 * biginteger Struct
 */
typedef struct biginteger {
	CK_BYTE *big_value;
	CK_ULONG big_value_len;
} biginteger_t;


/*
 * PKCS11: RSA Public Key Object Attributes
 */
typedef struct rsa_pub_key {
	biginteger_t modulus;
	CK_ULONG modulus_bits;
	biginteger_t pub_exponent;
} rsa_pub_key_t;


/*
 * PKCS11: DSA Public Key Object Attributes
 */
typedef struct dsa_pub_key {
	biginteger_t prime;
	biginteger_t subprime;
	biginteger_t base;
	biginteger_t value;
} dsa_pub_key_t;

/*
 * PKCS11: Diffie-Hellman Public Key Object Attributes
 */
typedef struct dh_pub_key {
	biginteger_t prime;
	biginteger_t base;
	biginteger_t value;
} dh_pub_key_t;

/*
 * PKCS11: EC Public Key Object Attributes
 */
typedef struct ec_pub_key {
	biginteger_t point;
} ec_pub_key_t;


/*
 * Public Key Main Struct
 */
typedef struct public_key_obj {
	union {
		rsa_pub_key_t rsa_pub_key; /* RSA public key */
		dsa_pub_key_t dsa_pub_key; /* DSA public key */
		dh_pub_key_t dh_pub_key; /* DH public key */
		ec_pub_key_t ec_pub_key; /* EC public key */
	} key_type_u;
} public_key_obj_t;


/*
 * PKCS11: RSA Private Key Object Attributes
 */
typedef struct rsa_pri_key {
	biginteger_t modulus;
	biginteger_t pub_exponent;
	biginteger_t pri_exponent;
	biginteger_t prime_1;
	biginteger_t prime_2;
	biginteger_t exponent_1;
	biginteger_t exponent_2;
	biginteger_t coefficient;
} rsa_pri_key_t;


/*
 * PKCS11: DSA Private Key Object Attributes
 */
typedef struct dsa_pri_key {
	biginteger_t prime;
	biginteger_t subprime;
	biginteger_t base;
	biginteger_t value;
} dsa_pri_key_t;


/*
 * PKCS11: Diffie-Hellman Private Key Object Attributes
 */
typedef struct dh_pri_key {
	biginteger_t prime;
	biginteger_t base;
	biginteger_t value;
	CK_ULONG value_bits;
} dh_pri_key_t;


/*
 * PKCS11: EC Private Key Object Attributes
 */
typedef struct ec_pri_key {
	biginteger_t value;
} ec_pri_key_t;

/*
 * Private Key Main Struct
 */
typedef struct private_key_obj {
	union {
		rsa_pri_key_t rsa_pri_key; /* RSA private key */
		dsa_pri_key_t dsa_pri_key; /* DSA private key */
		dh_pri_key_t dh_pri_key; /* DH private key */
		ec_pri_key_t ec_pri_key; /* EC private key */
	} key_type_u;
} private_key_obj_t;


/*
 * This is the main structure of the Objects.
 */
typedef struct object {
	boolean_t	is_lib_obj; /* default is TRUE */
	crypto_object_id_t	k_handle;

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
		public_key_obj_t  *public_key;
		private_key_obj_t *private_key;
	} object_class_u;

	/* Session handle that the object belongs to */
	CK_SESSION_HANDLE	session_handle;
	uint32_t	obj_refcnt;	/* object reference count */
	pthread_cond_t	obj_free_cond;	/* cond variable for signal and wait */
	uint32_t	obj_delete_sync;	/* object delete sync flags */

} kernel_object_t;


typedef struct find_context {
	kernel_object_t **objs_found;
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
	kernel_object_t	*first;	/* points to first obj in the list */
	kernel_object_t	*last;	/* points to last obj in the list */
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
	(o->object_class_u.secret_key)
#define	OBJ_SEC_VALUE(o) \
	(o->object_class_u.secret_key->sk_value)
#define	OBJ_SEC_VALUE_LEN(o) \
	(o->object_class_u.secret_key->sk_value_len)

/*
 * RSA Public Key Object Attributes
 */
#define	OBJ_PUB(o) \
	((o)->object_class_u.public_key)
#define	KEY_PUB_RSA(k) \
	&((k)->key_type_u.rsa_pub_key)
#define	OBJ_PUB_RSA_MOD(o) \
	&((o)->object_class_u.public_key->key_type_u.rsa_pub_key.modulus)
#define	KEY_PUB_RSA_MOD(k) \
	&((k)->key_type_u.rsa_pub_key.modulus)
#define	OBJ_PUB_RSA_PUBEXPO(o) \
	&((o)->object_class_u.public_key->key_type_u.rsa_pub_key.pub_exponent)
#define	KEY_PUB_RSA_PUBEXPO(k) \
	&((k)->key_type_u.rsa_pub_key.pub_exponent)
#define	OBJ_PUB_RSA_MOD_BITS(o) \
	((o)->object_class_u.public_key->key_type_u.rsa_pub_key.modulus_bits)
#define	KEY_PUB_RSA_MOD_BITS(k) \
	((k)->key_type_u.rsa_pub_key.modulus_bits)


/*
 * DSA Public Key Object Attributes
 */
#define	KEY_PUB_DSA(k) \
	&((k)->key_type_u.dsa_pub_key)
#define	OBJ_PUB_DSA_PRIME(o) \
	&((o)->object_class_u.public_key->key_type_u.dsa_pub_key.prime)
#define	KEY_PUB_DSA_PRIME(k) \
	&((k)->key_type_u.dsa_pub_key.prime)
#define	OBJ_PUB_DSA_SUBPRIME(o) \
	&((o)->object_class_u.public_key->key_type_u.dsa_pub_key.subprime)
#define	KEY_PUB_DSA_SUBPRIME(k) \
	&((k)->key_type_u.dsa_pub_key.subprime)
#define	OBJ_PUB_DSA_BASE(o) \
	&((o)->object_class_u.public_key->key_type_u.dsa_pub_key.base)
#define	KEY_PUB_DSA_BASE(k) \
	&((k)->key_type_u.dsa_pub_key.base)
#define	OBJ_PUB_DSA_VALUE(o) \
	&((o)->object_class_u.public_key->key_type_u.dsa_pub_key.value)
#define	KEY_PUB_DSA_VALUE(k) \
	&((k)->key_type_u.dsa_pub_key.value)


/*
 * Diffie-Hellman Public Key Object Attributes
 */
#define	KEY_PUB_DH(k) \
	&((k)->key_type_u.dh_pub_key)
#define	OBJ_PUB_DH_PRIME(o) \
	&((o)->object_class_u.public_key->key_type_u.dh_pub_key.prime)
#define	KEY_PUB_DH_PRIME(k) \
	&((k)->key_type_u.dh_pub_key.prime)
#define	OBJ_PUB_DH_BASE(o) \
	&((o)->object_class_u.public_key->key_type_u.dh_pub_key.base)
#define	KEY_PUB_DH_BASE(k) \
	&((k)->key_type_u.dh_pub_key.base)
#define	OBJ_PUB_DH_VALUE(o) \
	&((o)->object_class_u.public_key->key_type_u.dh_pub_key.value)
#define	KEY_PUB_DH_VALUE(k) \
	&((k)->key_type_u.dh_pub_key.value)


/*
 * EC Public Key Object Attributes
 */
#define	OBJ_PUB_EC_POINT(o) \
	&((o)->object_class_u.public_key->key_type_u.ec_pub_key.point)
#define	KEY_PUB_EC_POINT(k) \
	&((k)->key_type_u.ec_pub_key.point)


/*
 * RSA Private Key Object Attributes
 */
#define	OBJ_PRI(o) \
	((o)->object_class_u.private_key)
#define	KEY_PRI_RSA(k) \
	&((k)->key_type_u.rsa_pri_key)
#define	OBJ_PRI_RSA_MOD(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.modulus)
#define	KEY_PRI_RSA_MOD(k) \
	&((k)->key_type_u.rsa_pri_key.modulus)
#define	OBJ_PRI_RSA_PUBEXPO(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.pub_exponent)
#define	KEY_PRI_RSA_PUBEXPO(k) \
	&((k)->key_type_u.rsa_pri_key.pub_exponent)
#define	OBJ_PRI_RSA_PRIEXPO(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.pri_exponent)
#define	KEY_PRI_RSA_PRIEXPO(k) \
	&((k)->key_type_u.rsa_pri_key.pri_exponent)
#define	OBJ_PRI_RSA_PRIME1(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.prime_1)
#define	KEY_PRI_RSA_PRIME1(k) \
	&((k)->key_type_u.rsa_pri_key.prime_1)
#define	OBJ_PRI_RSA_PRIME2(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.prime_2)
#define	KEY_PRI_RSA_PRIME2(k) \
	&((k)->key_type_u.rsa_pri_key.prime_2)
#define	OBJ_PRI_RSA_EXPO1(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.exponent_1)
#define	KEY_PRI_RSA_EXPO1(k) \
	&((k)->key_type_u.rsa_pri_key.exponent_1)
#define	OBJ_PRI_RSA_EXPO2(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.exponent_2)
#define	KEY_PRI_RSA_EXPO2(k) \
	&((k)->key_type_u.rsa_pri_key.exponent_2)
#define	OBJ_PRI_RSA_COEF(o) \
	&((o)->object_class_u.private_key->key_type_u.rsa_pri_key.coefficient)
#define	KEY_PRI_RSA_COEF(k) \
	&((k)->key_type_u.rsa_pri_key.coefficient)

/*
 * DSA Private Key Object Attributes
 */
#define	KEY_PRI_DSA(k) \
	&((k)->key_type_u.dsa_pri_key)
#define	OBJ_PRI_DSA_PRIME(o) \
	&((o)->object_class_u.private_key->key_type_u.dsa_pri_key.prime)
#define	KEY_PRI_DSA_PRIME(k) \
	&((k)->key_type_u.dsa_pri_key.prime)
#define	OBJ_PRI_DSA_SUBPRIME(o) \
	&((o)->object_class_u.private_key->key_type_u.dsa_pri_key.subprime)
#define	KEY_PRI_DSA_SUBPRIME(k) \
	&((k)->key_type_u.dsa_pri_key.subprime)
#define	OBJ_PRI_DSA_BASE(o) \
	&((o)->object_class_u.private_key->key_type_u.dsa_pri_key.base)
#define	KEY_PRI_DSA_BASE(k) \
	&((k)->key_type_u.dsa_pri_key.base)
#define	OBJ_PRI_DSA_VALUE(o) \
	&((o)->object_class_u.private_key->key_type_u.dsa_pri_key.value)
#define	KEY_PRI_DSA_VALUE(k) \
	&((k)->key_type_u.dsa_pri_key.value)

/*
 * Diffie-Hellman Private Key Object Attributes
 */
#define	KEY_PRI_DH(k) \
	&((k)->key_type_u.dh_pri_key)
#define	OBJ_PRI_DH_PRIME(o) \
	&((o)->object_class_u.private_key->key_type_u.dh_pri_key.prime)
#define	KEY_PRI_DH_PRIME(k) \
	&((k)->key_type_u.dh_pri_key.prime)
#define	OBJ_PRI_DH_BASE(o) \
	&((o)->object_class_u.private_key->key_type_u.dh_pri_key.base)
#define	KEY_PRI_DH_BASE(k) \
	&((k)->key_type_u.dh_pri_key.base)
#define	OBJ_PRI_DH_VALUE(o) \
	&((o)->object_class_u.private_key->key_type_u.dh_pri_key.value)
#define	KEY_PRI_DH_VALUE(k) \
	&((k)->key_type_u.dh_pri_key.value)
#define	OBJ_PRI_DH_VAL_BITS(o) \
	((o)->object_class_u.private_key->key_type_u.dh_pri_key.value_bits)
#define	KEY_PRI_DH_VAL_BITS(k) \
	((k)->key_type_u.dh_pri_key.value_bits)

/*
 * EC Private Key Object Attributes
 */
#define	OBJ_PRI_EC_VALUE(o) \
	&((o)->object_class_u.private_key->key_type_u.ec_pri_key.value)
#define	KEY_PRI_EC_VALUE(k) \
	&((k)->key_type_u.ec_pri_key.value)

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
				EXTRACTABLE_BOOL_ON|\
				MODIFIABLE_BOOL_ON)

#define	PUBLIC_KEY_DEFAULT	(ENCRYPT_BOOL_ON|\
				VERIFY_BOOL_ON|\
				VERIFY_RECOVER_BOOL_ON|\
				MODIFIABLE_BOOL_ON)

#define	PRIVATE_KEY_DEFAULT	(DECRYPT_BOOL_ON|\
				SIGN_BOOL_ON|\
				SIGN_RECOVER_BOOL_ON|\
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
	object_p = (kernel_object_t *)(hObject); \
	if ((object_p == NULL) || \
		(object_p->magic_marker != KERNELTOKEN_OBJECT_MAGIC)) {\
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
void kernel_cleanup_object(kernel_object_t *objp);

CK_RV kernel_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
    CK_ULONG *objecthandle_p, kernel_session_t *sp);

CK_RV kernel_delete_session_object(kernel_session_t *sp, kernel_object_t *objp,
    boolean_t lock_held, boolean_t wrapper_only);

void kernel_cleanup_extra_attr(kernel_object_t *object_p);

CK_RV kernel_copy_extra_attr(CK_ATTRIBUTE_INFO_PTR old_attrp,
    kernel_object_t *object_p);

void kernel_cleanup_object_bigint_attrs(kernel_object_t *object_p);

CK_RV kernel_build_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
    kernel_object_t *new_object, kernel_session_t *sp, uint_t);

CK_RV kernel_copy_object(kernel_object_t *old_object,
    kernel_object_t **new_object, boolean_t copy_everything,
    kernel_session_t *sp);

void kernel_merge_object(kernel_object_t *old_object,
    kernel_object_t *new_object);

CK_RV kernel_get_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template);

CK_RV kernel_set_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template, boolean_t copy, kernel_session_t *sp);

void copy_bigint_attr(biginteger_t *src, biginteger_t *dst);

void kernel_add_object_to_session(kernel_object_t *objp, kernel_session_t *sp);

CK_RV kernel_copy_public_key_attr(public_key_obj_t *old_pub_key_obj_p,
    public_key_obj_t **new_pub_key_obj_p, CK_KEY_TYPE key_type);

CK_RV kernel_copy_private_key_attr(private_key_obj_t *old_pri_key_obj_p,
    private_key_obj_t **new_pri_key_obj_p, CK_KEY_TYPE key_type);

CK_RV kernel_copy_secret_key_attr(secret_key_obj_t *old_secret_key_obj_p,
    secret_key_obj_t **new_secret_key_obj_p);

CK_RV kernel_validate_attr(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
    CK_OBJECT_CLASS *class);

CK_RV kernel_find_objects_init(kernel_session_t *sp,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

void kernel_find_objects_final(kernel_session_t *sp);

void kernel_find_objects(kernel_session_t *sp,
    CK_OBJECT_HANDLE *obj_found, CK_ULONG max_obj_requested,
    CK_ULONG *found_obj_count);

void kernel_process_find_attr(CK_OBJECT_CLASS *pclasses,
    CK_ULONG *num_result_pclasses, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount);

boolean_t kernel_find_match_attrs(kernel_object_t *obj,
    CK_OBJECT_CLASS *pclasses, CK_ULONG num_pclasses,
    CK_ATTRIBUTE *tmpl_attr, CK_ULONG num_attr);

CK_ATTRIBUTE_PTR get_extra_attr(CK_ATTRIBUTE_TYPE type, kernel_object_t *obj);

CK_RV get_string_from_template(CK_ATTRIBUTE_PTR dest, CK_ATTRIBUTE_PTR src);

void string_attr_cleanup(CK_ATTRIBUTE_PTR template);

void kernel_add_token_object_to_slot(kernel_object_t *objp,
    kernel_slot_t *pslot);

void kernel_remove_token_object_from_slot(kernel_slot_t *pslot,
    kernel_object_t *objp);

CK_RV kernel_delete_token_object(kernel_slot_t *pslot, kernel_session_t *sp,
    kernel_object_t *obj, boolean_t lock_held, boolean_t wrapper_only);

void kernel_cleanup_pri_objects_in_slot(kernel_slot_t *pslot,
    kernel_session_t *sp);

CK_RV kernel_get_object_size(kernel_object_t *objp, CK_ULONG_PTR pulSize);

void kernel_object_delay_free(kernel_object_t *objp);

#ifdef	__cplusplus
}
#endif

#endif /* _KERNELOBJECT_H */
