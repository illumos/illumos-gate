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

#ifndef	_SOFTOBJECT_H
#define	_SOFTOBJECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <security/pkcs11t.h>
#include "softKeystoreUtil.h"
#include "softSession.h"


#define	SOFTTOKEN_OBJECT_MAGIC	0xECF0B002

#define	SOFT_CREATE_OBJ		1
#define	SOFT_GEN_KEY		2
#define	SOFT_DERIVE_KEY_DH	3	/* for CKM_DH_PKCS_DERIVE */
#define	SOFT_DERIVE_KEY_OTHER	4	/* for CKM_MD5_KEY_DERIVATION and */
					/* CKM_SHA1_KEY_DERIVATION */
#define	SOFT_UNWRAP_KEY		5
#define	SOFT_CREATE_OBJ_INT	6	/* internal object creation */

typedef struct biginteger {
	CK_BYTE *big_value;
	CK_ULONG big_value_len;
} biginteger_t;


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
 * PKCS11: X9.42 Diffie-Hellman Public Key Object Attributes
 */
typedef struct dh942_pub_key {
	biginteger_t prime;
	biginteger_t base;
	biginteger_t subprime;
	biginteger_t value;
} dh942_pub_key_t;


/*
 * PKCS11: Elliptic Curve Public Key Object Attributes
 */
typedef struct ec_pub_key {
	biginteger_t param;
	biginteger_t point;
} ec_pub_key_t;


/*
 * Public Key Main Struct
 */
typedef struct public_key_obj {
	union {
		rsa_pub_key_t rsa_pub_key; /* RSA public key */
		dsa_pub_key_t dsa_pub_key; /* DSA public key */
		dh_pub_key_t  dh_pub_key;  /* DH public key */
		dh942_pub_key_t dh942_pub_key;	/* DH9.42 public key */
		ec_pub_key_t ec_pub_key; /* Elliptic Curve public key */
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
 * PKCS11: X9.42 Diffie-Hellman Private Key Object Attributes
 */
typedef struct dh942_pri_key {
	biginteger_t prime;
	biginteger_t base;
	biginteger_t subprime;
	biginteger_t value;
} dh942_pri_key_t;

/*
 * PKCS11: Elliptic Curve Private Key Object Attributes
 */
typedef struct ec_pri_key {
	biginteger_t param;
	biginteger_t value;
} ec_pri_key_t;


/*
 * Private Key Main Struct
 */
typedef struct private_key_obj {
	union {
		rsa_pri_key_t rsa_pri_key; /* RSA private key */
		dsa_pri_key_t dsa_pri_key; /* DSA private key */
		dh_pri_key_t  dh_pri_key;  /* DH private key */
		dh942_pri_key_t dh942_pri_key;	/* DH9.42 private key */
		ec_pri_key_t ec_pri_key; /* Elliptic Curve private key */
	} key_type_u;
} private_key_obj_t;

/*
 * PKCS11: DSA Domain Parameters Object Attributes
 */
typedef struct dsa_dom_key {
	biginteger_t prime;
	biginteger_t subprime;
	biginteger_t base;
	CK_ULONG prime_bits;
} dsa_dom_key_t;


/*
 * PKCS11: Diffie-Hellman Domain Parameters Object Attributes
 */
typedef struct dh_dom_key {
	biginteger_t prime;
	biginteger_t base;
	CK_ULONG prime_bits;
} dh_dom_key_t;


/*
 * PKCS11: X9.42 Diffie-Hellman Domain Parameters Object Attributes
 */
typedef struct dh942_dom_key {
	biginteger_t prime;
	biginteger_t base;
	biginteger_t subprime;
	CK_ULONG prime_bits;
	CK_ULONG subprime_bits;
} dh942_dom_key_t;

/*
 * Domain Parameters Main Struct
 */
typedef struct domain_obj {
	union {
		dsa_dom_key_t dsa_dom_key; /* DSA domain parameters */
		dh_dom_key_t  dh_dom_key;  /* DH domain parameters */
		dh942_dom_key_t dh942_dom_key;  /* DH9.42 domain parameters */
	} key_type_u;
} domain_obj_t;

typedef struct cert_attr_type {
	CK_BYTE *value;
	CK_ULONG length;
} cert_attr_t;

/*
 * X.509 Public Key Certificate Structure.
 * This structure contains only the attributes that are
 * NOT modifiable after creation.
 * ID, ISSUER, and SUBJECT attributes are kept in the extra_attrlistp
 * record.
 */
typedef struct x509_cert {
	cert_attr_t *subject; /* DER encoding of certificate subject name */
	cert_attr_t *value;	/* BER encoding of the cert */
} x509_cert_t;

/*
 * X.509 Attribute Certificiate Structure
 * This structure contains only the attributes that are
 * NOT modifiable after creation.
 * AC_ISSUER, SERIAL_NUMBER, and ATTR_TYPES are kept in the
 * extra_attrlistp record so they may be modified.
 */
typedef struct x509_attr_cert {
	cert_attr_t *owner;	 /* DER encoding of attr cert subject field */
	cert_attr_t *value;	/* BER encoding of cert */
} x509_attr_cert_t;

/*
 * Certificate Object Main Struct
 */
typedef struct certificate_obj {
	CK_CERTIFICATE_TYPE certificate_type;
	union {
		x509_cert_t  	x509;
		x509_attr_cert_t x509_attr;
	} cert_type_u;
} certificate_obj_t;

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
	/* Generic common fields. Always present */
	uint_t			version;	/* for token objects only */
	CK_OBJECT_CLASS 	class;
	CK_KEY_TYPE		key_type;
	CK_CERTIFICATE_TYPE	cert_type;
	ulong_t			magic_marker;
	uint64_t		bool_attr_mask;	/* see below */
	CK_MECHANISM_TYPE	mechanism;
	uchar_t object_type;		/* see below */
	struct ks_obj_handle ks_handle;	/* keystore handle */

	/* Fields for access and arbitration */
	pthread_mutex_t	object_mutex;
	struct object *next;
	struct object *prev;

	/* Extra non-boolean attribute list */
	CK_ATTRIBUTE_INFO_PTR extra_attrlistp;

	/* For each object, only one of these object classes is presented */
	union {
		public_key_obj_t  *public_key;
		private_key_obj_t *private_key;
		secret_key_obj_t  *secret_key;
		domain_obj_t	  *domain;
		certificate_obj_t *certificate;
	} object_class_u;

	/* Session handle that the object belongs to */
	CK_SESSION_HANDLE	session_handle;
	uint32_t	obj_refcnt;	/* object reference count */
	pthread_cond_t	obj_free_cond;	/* cond variable for signal and wait */
	uint32_t	obj_delete_sync;	/* object delete sync flags */

} soft_object_t;

typedef struct find_context {
	soft_object_t **objs_found;
	CK_ULONG num_results;
	CK_ULONG next_result_index;	/* next result object to return */
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
	struct object	*first;	/* points to the first obj in the list */
	struct object	*last;	/* points to the last obj in the list */
	uint32_t	count;	/* current total objs in the list */
	pthread_mutex_t	obj_to_be_free_mutex;
} obj_to_be_freed_list_t;

/*
 * Object type
 */
#define	SESSION_PUBLIC		0	/* CKA_TOKEN = 0, CKA_PRIVATE = 0 */
#define	SESSION_PRIVATE		1	/* CKA_TOKEN = 0, CKA_PRIVATE = 1 */
#define	TOKEN_PUBLIC		2	/* CKA_TOKEN = 1, CKA_PRIVATE = 0 */
#define	TOKEN_PRIVATE		3	/* CKA_TOKEN = 1, CKA_PRIVATE = 1 */

#define	TOKEN_OBJECT		2
#define	PRIVATE_OBJECT		1

typedef enum {
		ALL_TOKEN = 0,
		PUBLIC_TOKEN = 1,
		PRIVATE_TOKEN = 2
} token_obj_type_t;

#define	IS_TOKEN_OBJECT(objp)	\
	((objp->object_type == TOKEN_PUBLIC) || \
	(objp->object_type == TOKEN_PRIVATE))

/*
 * Types associated with copying object's content
 */
#define	SOFT_SET_ATTR_VALUE	1	/* for C_SetAttributeValue */
#define	SOFT_COPY_OBJECT	2	/* for C_CopyObject */
#define	SOFT_COPY_OBJ_ORIG_SH	3	/* for copying an object but keeps */
					/* the original session handle */

/*
 * The following definitions are the shortcuts
 */

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
 * X9.42 Diffie-Hellman Public Key Object Attributes
 */
#define	KEY_PUB_DH942(k) \
	&((k)->key_type_u.dh942_pub_key)
#define	OBJ_PUB_DH942_PRIME(o) \
	&((o)->object_class_u.public_key->key_type_u.dh942_pub_key.prime)
#define	KEY_PUB_DH942_PRIME(k) \
	&((k)->key_type_u.dh942_pub_key.prime)
#define	OBJ_PUB_DH942_BASE(o) \
	&((o)->object_class_u.public_key->key_type_u.dh942_pub_key.base)
#define	KEY_PUB_DH942_BASE(k) \
	&((k)->key_type_u.dh942_pub_key.base)
#define	OBJ_PUB_DH942_SUBPRIME(o) \
	&((o)->object_class_u.public_key->key_type_u.dh942_pub_key.subprime)
#define	KEY_PUB_DH942_SUBPRIME(k) \
	&((k)->key_type_u.dh942_pub_key.subprime)
#define	OBJ_PUB_DH942_VALUE(o) \
	&((o)->object_class_u.public_key->key_type_u.dh942_pub_key.value)
#define	KEY_PUB_DH942_VALUE(k) \
	&((k)->key_type_u.dh942_pub_key.value)

/*
 * Elliptic Curve Public Key Object Attributes
 */
#define	KEY_PUB_EC(k) \
	&((k)->key_type_u.ec_pub_key)
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
 * X9.42 Diffie-Hellman Private Key Object Attributes
 */
#define	KEY_PRI_DH942(k) \
	&((k)->key_type_u.dh942_pri_key)
#define	OBJ_PRI_DH942_PRIME(o) \
	&((o)->object_class_u.private_key->key_type_u.dh942_pri_key.prime)
#define	KEY_PRI_DH942_PRIME(k) \
	&((k)->key_type_u.dh942_pri_key.prime)
#define	OBJ_PRI_DH942_BASE(o) \
	&((o)->object_class_u.private_key->key_type_u.dh942_pri_key.base)
#define	KEY_PRI_DH942_BASE(k) \
	&((k)->key_type_u.dh942_pri_key.base)
#define	OBJ_PRI_DH942_SUBPRIME(o) \
	&((o)->object_class_u.private_key->key_type_u.dh942_pri_key.subprime)
#define	KEY_PRI_DH942_SUBPRIME(k) \
	&((k)->key_type_u.dh942_pri_key.subprime)
#define	OBJ_PRI_DH942_VALUE(o) \
	&((o)->object_class_u.private_key->key_type_u.dh942_pri_key.value)
#define	KEY_PRI_DH942_VALUE(k) \
	&((k)->key_type_u.dh942_pri_key.value)

/*
 * Elliptic Curve Private Key Object Attributes
 */

#define	KEY_PRI_EC(k) \
	&((k)->key_type_u.ec_pri_key)
#define	OBJ_PRI_EC_VALUE(o) \
	&((o)->object_class_u.private_key->key_type_u.ec_pri_key.value)
#define	KEY_PRI_EC_VALUE(k) \
	&((k)->key_type_u.ec_pri_key.value)

/*
 * DSA Domain Parameters Object Attributes
 */
#define	OBJ_DOM(o) \
	((o)->object_class_u.domain)
#define	KEY_DOM_DSA(k) \
	&((k)->key_type_u.dsa_dom_key)
#define	OBJ_DOM_DSA_PRIME(o) \
	&((o)->object_class_u.domain->key_type_u.dsa_dom_key.prime)
#define	KEY_DOM_DSA_PRIME(k) \
	&((k)->key_type_u.dsa_dom_key.prime)
#define	OBJ_DOM_DSA_SUBPRIME(o) \
	&((o)->object_class_u.domain->key_type_u.dsa_dom_key.subprime)
#define	KEY_DOM_DSA_SUBPRIME(k) \
	&((k)->key_type_u.dsa_dom_key.subprime)
#define	OBJ_DOM_DSA_BASE(o) \
	&((o)->object_class_u.domain->key_type_u.dsa_dom_key.base)
#define	KEY_DOM_DSA_BASE(k) \
	&((k)->key_type_u.dsa_dom_key.base)
#define	OBJ_DOM_DSA_PRIME_BITS(o) \
	((o)->object_class_u.domain->key_type_u.dsa_dom_key.prime_bits)

/*
 * Diffie-Hellman Domain Parameters Object Attributes
 */
#define	KEY_DOM_DH(k) \
	&((k)->key_type_u.dh_dom_key)
#define	OBJ_DOM_DH_PRIME(o) \
	&((o)->object_class_u.domain->key_type_u.dh_dom_key.prime)
#define	KEY_DOM_DH_PRIME(k) \
	&((k)->key_type_u.dh_dom_key.prime)
#define	OBJ_DOM_DH_BASE(o) \
	&((o)->object_class_u.domain->key_type_u.dh_dom_key.base)
#define	KEY_DOM_DH_BASE(k) \
	&((k)->key_type_u.dh_dom_key.base)
#define	OBJ_DOM_DH_PRIME_BITS(o) \
	((o)->object_class_u.domain->key_type_u.dh_dom_key.prime_bits)

/*
 * X9.42 Diffie-Hellman Domain Parameters Object Attributes
 */
#define	KEY_DOM_DH942(k) \
	&((k)->key_type_u.dh942_dom_key)
#define	OBJ_DOM_DH942_PRIME(o) \
	&((o)->object_class_u.domain->key_type_u.dh942_dom_key.prime)
#define	KEY_DOM_DH942_PRIME(k) \
	&((k)->key_type_u.dh942_dom_key.prime)
#define	OBJ_DOM_DH942_BASE(o) \
	&((o)->object_class_u.domain->key_type_u.dh942_dom_key.base)
#define	KEY_DOM_DH942_BASE(k) \
	&((k)->key_type_u.dh942_dom_key.base)
#define	OBJ_DOM_DH942_SUBPRIME(o) \
	&((o)->object_class_u.domain->key_type_u.dh942_dom_key.subprime)
#define	KEY_DOM_DH942_SUBPRIME(k) \
	&((k)->key_type_u.dh942_dom_key.subprime)
#define	OBJ_DOM_DH942_PRIME_BITS(o) \
	((o)->object_class_u.domain->key_type_u.dh942_dom_key.prime_bits)
#define	OBJ_DOM_DH942_SUBPRIME_BITS(o) \
	((o)->object_class_u.domain->key_type_u.dh942_dom_key.subprime_bits)

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

#define	OBJ_CERT(o) \
	((o)->object_class_u.certificate)
/*
 * X.509 Key Certificate object attributes
 */
#define	X509_CERT(o) \
	((o)->object_class_u.certificate->cert_type_u.x509)
#define	X509_CERT_SUBJECT(o) \
	((o)->object_class_u.certificate->cert_type_u.x509.subject)
#define	X509_CERT_VALUE(o) \
	((o)->object_class_u.certificate->cert_type_u.x509.value)

/*
 * X.509 Attribute Certificate object attributes
 */
#define	X509_ATTR_CERT(o) \
	((o)->object_class_u.certificate->cert_type_u.x509_attr)
#define	X509_ATTR_CERT_OWNER(o) \
	((o)->object_class_u.certificate->cert_type_u.x509_attr.owner)
#define	X509_ATTR_CERT_VALUE(o) \
	((o)->object_class_u.certificate->cert_type_u.x509_attr.value)

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
#define	NOT_MODIFIABLE_BOOL_ON		0x00010000

#define	PUBLIC_KEY_DEFAULT	(ENCRYPT_BOOL_ON|\
				WRAP_BOOL_ON|\
				VERIFY_BOOL_ON|\
				VERIFY_RECOVER_BOOL_ON)

#define	PRIVATE_KEY_DEFAULT	(DECRYPT_BOOL_ON|\
				UNWRAP_BOOL_ON|\
				SIGN_BOOL_ON|\
				SIGN_RECOVER_BOOL_ON|\
				EXTRACTABLE_BOOL_ON)

#define	SECRET_KEY_DEFAULT	(ENCRYPT_BOOL_ON|\
				DECRYPT_BOOL_ON|\
				WRAP_BOOL_ON|\
				UNWRAP_BOOL_ON|\
				SIGN_BOOL_ON|\
				VERIFY_BOOL_ON|\
				EXTRACTABLE_BOOL_ON)

/*
 * MAX_KEY_ATTR_BUFLEN
 * The maximum buffer size needed for public or private key attributes
 * should be 514 bytes.  Just to be safe we give a little more space.
 */
#define	MAX_KEY_ATTR_BUFLEN 1024

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
	object_p = (soft_object_t *)(hObject); \
	if ((object_p == NULL) || \
		(object_p->magic_marker != SOFTTOKEN_OBJECT_MAGIC)) {\
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
void soft_cleanup_object(soft_object_t *objp);

CK_RV soft_add_object(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
	CK_ULONG *objecthandle_p, soft_session_t *sp);

void soft_delete_object(soft_session_t *sp, soft_object_t *objp,
	boolean_t lock_held);

void soft_cleanup_extra_attr(soft_object_t *object_p);

CK_RV soft_copy_extra_attr(CK_ATTRIBUTE_INFO_PTR old_attrp,
	soft_object_t *object_p);

void soft_cleanup_object_bigint_attrs(soft_object_t *object_p);

CK_RV soft_build_object(CK_ATTRIBUTE_PTR template,
	CK_ULONG ulAttrNum, soft_object_t *new_object);

CK_RV soft_build_secret_key_object(CK_ATTRIBUTE_PTR template,
	CK_ULONG ulAttrNum, soft_object_t *new_object, CK_ULONG mode,
	CK_ULONG key_len, CK_KEY_TYPE key_type);

CK_RV soft_copy_object(soft_object_t *old_object, soft_object_t **new_object,
	CK_ULONG object_func, soft_session_t *sp);

void soft_merge_object(soft_object_t *old_object, soft_object_t *new_object);

CK_RV soft_get_attribute(soft_object_t *object_p, CK_ATTRIBUTE_PTR template);

CK_RV soft_set_attribute(soft_object_t *object_p, CK_ATTRIBUTE_PTR template,
	boolean_t copy);

CK_RV soft_set_common_storage_attribute(soft_object_t *object_p,
	CK_ATTRIBUTE_PTR template, boolean_t copy);

CK_RV soft_get_public_value(soft_object_t *, CK_ATTRIBUTE_TYPE, uchar_t *,
	uint32_t *);

CK_RV soft_get_private_value(soft_object_t *, CK_ATTRIBUTE_TYPE, uchar_t *,
	uint32_t *);

CK_RV get_ulong_attr_from_object(CK_ULONG value, CK_ATTRIBUTE_PTR template);

void copy_bigint_attr(biginteger_t *src, biginteger_t *dst);

void soft_add_object_to_session(soft_object_t *, soft_session_t *);

CK_RV soft_build_key(CK_ATTRIBUTE_PTR, CK_ULONG, soft_object_t *,
	CK_OBJECT_CLASS, CK_KEY_TYPE, CK_ULONG, CK_ULONG);

CK_RV soft_copy_public_key_attr(public_key_obj_t *old_pub_key_obj_p,
	public_key_obj_t **new_pub_key_obj_p, CK_KEY_TYPE key_type);

CK_RV soft_copy_private_key_attr(private_key_obj_t *old_pri_key_obj_p,
	private_key_obj_t **new_pri_key_obj_p, CK_KEY_TYPE key_type);

CK_RV soft_copy_secret_key_attr(secret_key_obj_t *old_secret_key_obj_p,
	secret_key_obj_t **new_secret_key_obj_p);

CK_RV soft_copy_domain_attr(domain_obj_t *old_domain_obj_p,
	domain_obj_t **new_domain_obj_p, CK_KEY_TYPE key_type);

CK_RV soft_validate_attr(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	CK_OBJECT_CLASS *class);

CK_RV soft_find_objects_init(soft_session_t *sp, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount);

void soft_find_objects_final(soft_session_t *sp);

void soft_find_objects(soft_session_t *sp, CK_OBJECT_HANDLE *obj_found,
	CK_ULONG max_obj_requested, CK_ULONG *found_obj_count);

void soft_process_find_attr(CK_OBJECT_CLASS *pclasses,
	CK_ULONG *num_result_pclasses, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount);

boolean_t soft_find_match_attrs(soft_object_t *obj, CK_OBJECT_CLASS *pclasses,
	CK_ULONG num_pclasses, CK_ATTRIBUTE *tmpl_attr, CK_ULONG num_attr);

CK_ATTRIBUTE_PTR get_extra_attr(CK_ATTRIBUTE_TYPE type, soft_object_t *obj);

CK_RV get_string_from_template(CK_ATTRIBUTE_PTR dest, CK_ATTRIBUTE_PTR src);

void string_attr_cleanup(CK_ATTRIBUTE_PTR template);

void soft_cleanup_cert_object(soft_object_t *object_p);

CK_RV soft_get_certificate_attribute(soft_object_t *object_p,
	CK_ATTRIBUTE_PTR template);

CK_RV soft_set_certificate_attribute(soft_object_t *object_p,
	CK_ATTRIBUTE_PTR template, boolean_t copy);

CK_RV soft_copy_certificate(certificate_obj_t *old, certificate_obj_t **new,
	CK_CERTIFICATE_TYPE type);

CK_RV get_cert_attr_from_template(cert_attr_t **dest,
	CK_ATTRIBUTE_PTR src);

/* Token object related function prototypes */

void soft_add_token_object_to_slot(soft_object_t *objp);

void soft_remove_token_object_from_slot(soft_object_t *objp,
	boolean_t lock_held);

void soft_delete_token_object(soft_object_t *objp, boolean_t persistent,
	boolean_t lock_held);

void soft_delete_all_in_core_token_objects(token_obj_type_t type);

void soft_validate_token_objects(boolean_t validate);

CK_RV soft_object_write_access_check(soft_session_t *sp, soft_object_t *objp);

CK_RV soft_pin_expired_check(soft_object_t *objp);

CK_RV soft_copy_to_old_object(soft_object_t *new, soft_object_t *old);

CK_RV soft_keystore_load_latest_object(soft_object_t *old_obj);

CK_RV refresh_token_objects();

void bigint_attr_cleanup(biginteger_t *big);

CK_RV soft_add_extra_attr(CK_ATTRIBUTE_PTR template, soft_object_t *object_p);

CK_RV get_bigint_attr_from_template(biginteger_t *big,
	CK_ATTRIBUTE_PTR template);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTOBJECT_H */
