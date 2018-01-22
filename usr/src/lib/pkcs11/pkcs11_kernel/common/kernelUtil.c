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
 * Copyright 2018, Joyent, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <cryptoutil.h>
#include <errno.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <sys/crypto/ioctl.h>
#include "kernelGlobal.h"
#include "kernelObject.h"
#include "kernelSlot.h"

#define	ENCODE_ATTR(type, value, len) {		\
	cur_attr->oa_type = type;		\
	(void) memcpy(ptr, value, len);		\
	cur_attr->oa_value = ptr;		\
	cur_attr->oa_value_len = len;		\
	cur_attr++;				\
}

/*
 * In order to fit everything on one line, the 'CRYPTO_' prefix
 * has been dropped from the KCF #defines, e.g.
 * CRYPTO_SUCCESS becomes SUCCESS.
 */

static CK_RV error_number_table[CRYPTO_LAST_ERROR+1] = {
CKR_OK,					/* SUCCESS */
CKR_CANCEL,				/* CANCEL */
CKR_HOST_MEMORY,			/* HOST_MEMORY */
CKR_GENERAL_ERROR,			/* GENERAL_ERROR */
CKR_FUNCTION_FAILED,			/* FAILED */
CKR_ARGUMENTS_BAD,			/* ARGUMENTS_BAD */
CKR_ATTRIBUTE_READ_ONLY,		/* ATTRIBUTE_READ_ONLY */
CKR_ATTRIBUTE_SENSITIVE,		/* ATTRIBUTE_SENSITIVE */
CKR_ATTRIBUTE_TYPE_INVALID,		/* ATTRIBUTE_TYPE_INVALID */
CKR_ATTRIBUTE_VALUE_INVALID,		/* ATTRIBUTE_VALUE_INVALID */
CKR_FUNCTION_FAILED,			/* CANCELED */
CKR_DATA_INVALID,			/* DATA_INVALID */
CKR_DATA_LEN_RANGE,			/* DATA_LEN_RANGE */
CKR_DEVICE_ERROR,			/* DEVICE_ERROR */
CKR_DEVICE_MEMORY,			/* DEVICE_MEMORY */
CKR_DEVICE_REMOVED,			/* DEVICE_REMOVED */
CKR_ENCRYPTED_DATA_INVALID,		/* ENCRYPTED_DATA_INVALID */
CKR_ENCRYPTED_DATA_LEN_RANGE,		/* ENCRYPTED_DATA_LEN_RANGE */
CKR_KEY_HANDLE_INVALID,			/* KEY_HANDLE_INVALID */
CKR_KEY_SIZE_RANGE,			/* KEY_SIZE_RANGE */
CKR_KEY_TYPE_INCONSISTENT,		/* KEY_TYPE_INCONSISTENT */
CKR_KEY_NOT_NEEDED,			/* KEY_NOT_NEEDED */
CKR_KEY_CHANGED,			/* KEY_CHANGED */
CKR_KEY_NEEDED,				/* KEY_NEEDED */
CKR_KEY_INDIGESTIBLE,			/* KEY_INDIGESTIBLE */
CKR_KEY_FUNCTION_NOT_PERMITTED,		/* KEY_FUNCTION_NOT_PERMITTED */
CKR_KEY_NOT_WRAPPABLE,			/* KEY_NOT_WRAPPABLE */
CKR_KEY_UNEXTRACTABLE,			/* KEY_UNEXTRACTABLE */
CKR_MECHANISM_INVALID,			/* MECHANISM_INVALID */
CKR_MECHANISM_PARAM_INVALID,		/* MECHANISM_PARAM_INVALID */
CKR_OBJECT_HANDLE_INVALID,		/* OBJECT_HANDLE_INVALID */
CKR_OPERATION_ACTIVE,			/* OPERATION_ACTIVE */
CKR_OPERATION_NOT_INITIALIZED,		/* OPERATION_NOT_INITIALIZED */
CKR_PIN_INCORRECT,			/* PIN_INCORRECT */
CKR_PIN_INVALID,			/* PIN_INVALID */
CKR_PIN_LEN_RANGE,			/* PIN_LEN_RANGE */
CKR_PIN_EXPIRED,			/* PIN_EXPIRED */
CKR_PIN_LOCKED,				/* PIN_LOCKED */
CKR_SESSION_CLOSED,			/* SESSION_CLOSED */
CKR_SESSION_COUNT,			/* SESSION_COUNT */
CKR_SESSION_HANDLE_INVALID,		/* SESSION_HANDLE_INVALID */
CKR_SESSION_READ_ONLY,			/* SESSION_READ_ONLY */
CKR_SESSION_EXISTS,			/* SESSION_EXISTS */
CKR_SESSION_READ_ONLY_EXISTS,		/* SESSION_READ_ONLY_EXISTS */
CKR_SESSION_READ_WRITE_SO_EXISTS,	/* SESSION_READ_WRITE_SO_EXISTS */
CKR_SIGNATURE_INVALID,			/* SIGNATURE_INVALID */
CKR_SIGNATURE_LEN_RANGE,		/* SIGNATURE_LEN_RANGE */
CKR_TEMPLATE_INCOMPLETE,		/* TEMPLATE_INCOMPLETE */
CKR_TEMPLATE_INCONSISTENT,		/* TEMPLATE_INCONSISTENT */
CKR_UNWRAPPING_KEY_HANDLE_INVALID,	/* UNWRAPPING_KEY_HANDLE_INVALID */
CKR_UNWRAPPING_KEY_SIZE_RANGE,		/* UNWRAPPING_KEY_SIZE_RANGE */
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,	/* UNWRAPPING_KEY_TYPE_INCONSISTENT */
CKR_USER_ALREADY_LOGGED_IN,		/* USER_ALREADY_LOGGED_IN */
CKR_USER_NOT_LOGGED_IN,			/* USER_NOT_LOGGED_IN */
CKR_USER_PIN_NOT_INITIALIZED,		/* USER_PIN_NOT_INITIALIZED */
CKR_USER_TYPE_INVALID,			/* USER_TYPE_INVALID */
CKR_USER_ANOTHER_ALREADY_LOGGED_IN,	/* USER_ANOTHER_ALREADY_LOGGED_IN */
CKR_USER_TOO_MANY_TYPES,		/* USER_TOO_MANY_TYPES */
CKR_WRAPPED_KEY_INVALID,		/* WRAPPED_KEY_INVALID */
CKR_WRAPPED_KEY_LEN_RANGE,		/* WRAPPED_KEY_LEN_RANGE */
CKR_WRAPPING_KEY_HANDLE_INVALID,	/* WRAPPING_KEY_HANDLE_INVALID */
CKR_WRAPPING_KEY_SIZE_RANGE,		/* WRAPPING_KEY_SIZE_RANGE */
CKR_WRAPPING_KEY_TYPE_INCONSISTENT,	/* WRAPPING_KEY_TYPE_INCONSISTENT */
CKR_RANDOM_SEED_NOT_SUPPORTED,		/* RANDOM_SEED_NOT_SUPPORTED */
CKR_RANDOM_NO_RNG,			/* RANDOM_NO_RNG */
CKR_DOMAIN_PARAMS_INVALID,		/* DOMAIN_PARAMS_INVALID */
CKR_BUFFER_TOO_SMALL,			/* BUFFER_TOO_SMALL */
CKR_INFORMATION_SENSITIVE,		/* INFORMATION_SENSITIVE */
CKR_FUNCTION_NOT_SUPPORTED,		/* NOT_SUPPORTED */
CKR_GENERAL_ERROR,			/* QUEUED */
CKR_GENERAL_ERROR,			/* BUFFER_TOO_BIG */
CKR_OPERATION_NOT_INITIALIZED,		/* INVALID_CONTEXT */
CKR_GENERAL_ERROR,			/* INVALID_MAC */
CKR_GENERAL_ERROR,			/* MECH_NOT_SUPPORTED */
CKR_GENERAL_ERROR,			/* INCONSISTENT_ATTRIBUTE */
CKR_GENERAL_ERROR,			/* NO_PERMISSION */
CKR_SLOT_ID_INVALID,			/* INVALID_PROVIDER_ID */
CKR_GENERAL_ERROR,			/* VERSION_MISMATCH */
CKR_GENERAL_ERROR,			/* BUSY */
CKR_GENERAL_ERROR,			/* UNKNOWN_PROVIDER */
CKR_GENERAL_ERROR,			/* MODVERIFICATION_FAILED */
CKR_GENERAL_ERROR,			/* OLD_CTX_TEMPLATE */
CKR_GENERAL_ERROR,			/* WEAK_KEY */
CKR_GENERAL_ERROR			/* FIPS140_ERROR */
};

#if CRYPTO_LAST_ERROR != CRYPTO_FIPS140_ERROR
#error "Crypto to PKCS11 error mapping table needs to be updated!"
#endif

/*
 * Map KCF error codes into PKCS11 error codes.
 */
CK_RV
crypto2pkcs11_error_number(uint_t n)
{
	if (n >= sizeof (error_number_table) / sizeof (error_number_table[0]))
		return (CKR_GENERAL_ERROR);

	return (error_number_table[n]);
}

#define	MECH_HASH(type)	(((uintptr_t)type) % KMECH_HASHTABLE_SIZE)
/*
 * Serialize writes to the hash table. We don't need a per bucket lock as
 * there are only a few writes and we don't need the lock for reads.
 */
pthread_mutex_t mechhash_mutex = PTHREAD_MUTEX_INITIALIZER;

static CK_RV
kmech_hash_insert(CK_MECHANISM_TYPE type, crypto_mech_type_t kmech)
{
	uint_t h;
	kmh_elem_t *elem, *cur;

	elem = malloc(sizeof (kmh_elem_t));
	if (elem == NULL)
		return (CKR_HOST_MEMORY);

	h = MECH_HASH(type);
	elem->type = type;
	elem->kmech = kmech;

	(void) pthread_mutex_lock(&mechhash_mutex);
	for (cur = kernel_mechhash[h]; cur != NULL; cur = cur->knext) {
		if (type == cur->type) {
			/* Some other thread beat us to it. */
			(void) pthread_mutex_unlock(&mechhash_mutex);
			free(elem);
			return (CKR_OK);
		}
	}
	elem->knext = kernel_mechhash[h];
	kernel_mechhash[h] = elem;
	(void) pthread_mutex_unlock(&mechhash_mutex);

	return (CKR_OK);
}

CK_RV
kernel_mech(CK_MECHANISM_TYPE type, crypto_mech_type_t *k_number)
{
	crypto_get_mechanism_number_t get_number;
	const char *string;
	CK_RV rv;
	int r;
	kmh_elem_t *elem;
	uint_t h;
	char buf[11];   /* Num chars for representing ulong in ASCII */

	/*
	 * Search for an existing entry. No need to lock since we are
	 * just a reader and we never free the entries in the hash table.
	 */
	h = MECH_HASH(type);
	for (elem = kernel_mechhash[h]; elem != NULL; elem = elem->knext) {
		if (type == elem->type) {
			*k_number = elem->kmech;
			return (CKR_OK);
		}
	}

	if (type >= CKM_VENDOR_DEFINED) {
		(void) snprintf(buf, sizeof (buf), "%#lx", type);
		string = buf;
	} else {
		string = pkcs11_mech2str(type);
	}

	if (string == NULL)
		return (CKR_MECHANISM_INVALID);

	get_number.pn_mechanism_string = (char *)string;
	get_number.pn_mechanism_len = strlen(string) + 1;

	while ((r = ioctl(kernel_fd, CRYPTO_GET_MECHANISM_NUMBER,
	    &get_number)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_MECHANISM_INVALID;
	} else {
		if (get_number.pn_return_value != CRYPTO_SUCCESS) {
			rv = crypto2pkcs11_error_number(
			    get_number.pn_return_value);
		} else {
			rv = CKR_OK;
		}
	}

	if (rv == CKR_OK) {
		*k_number = get_number.pn_internal_number;
		/* Add this to the hash table */
		(void) kmech_hash_insert(type, *k_number);
	}

	return (rv);
}


/*
 * Return the value of a secret key object.
 * This routine allocates memory for the value.
 * A null pointer is returned on error.
 */
unsigned char *
get_symmetric_key_value(kernel_object_t *key_p)
{
	uint8_t *cipherKey;

	switch (key_p->class) {

	case CKO_SECRET_KEY:

		cipherKey = malloc(OBJ_SEC(key_p)->sk_value_len);
		if (cipherKey == NULL)
			return (NULL);

		(void) memcpy(cipherKey, OBJ_SEC(key_p)->sk_value,
		    OBJ_SEC(key_p)->sk_value_len);

		return (cipherKey);

	default:
		return (NULL);
	}
}

/*
 * Convert a RSA private key object into a crypto_key structure.
 * Memory is allocated for each attribute stored in the crypto_key
 * structure.  Memory for the crypto_key structure is not
 * allocated.  Attributes can be freed by free_key_attributes().
 */
CK_RV
get_rsa_private_key(kernel_object_t *object_p, crypto_key_t *key)
{
	biginteger_t *big;
	crypto_object_attribute_t *attrs, *cur_attr;
	char *ptr;
	CK_RV rv;

	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->key_type != CKK_RSA ||
	    object_p->class != CKO_PRIVATE_KEY) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	attrs = calloc(1,
	    RSA_PRI_ATTR_COUNT * sizeof (crypto_object_attribute_t));
	if (attrs == NULL) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_HOST_MEMORY);
	}

	key->ck_format = CRYPTO_KEY_ATTR_LIST;
	key->ck_attrs = attrs;
	cur_attr = attrs;

	/*
	 * Allocate memory for each key attribute and set up the value
	 * value length.
	 */
	key->ck_count = 0;

	/* CKA_MODULUS is required. */
	big = OBJ_PRI_RSA_MOD(object_p);
	if (big->big_value == NULL) {
		rv = CKR_ATTRIBUTE_TYPE_INVALID;
		goto fail_cleanup;
	} else {
		if ((ptr = malloc(big->big_value_len)) == NULL) {
			rv = CKR_HOST_MEMORY;
			goto fail_cleanup;
		}
		ENCODE_ATTR(CKA_MODULUS, big->big_value, big->big_value_len);
		key->ck_count++;
	}

	/* CKA_PRIVATE_EXPONENT is required. */
	big = OBJ_PRI_RSA_PRIEXPO(object_p);
	if (big->big_value == NULL) {
		rv = CKR_ATTRIBUTE_TYPE_INVALID;
		goto fail_cleanup;
	} else {
		if ((ptr = malloc(big->big_value_len)) == NULL) {
			rv = CKR_HOST_MEMORY;
			goto fail_cleanup;
		}
		ENCODE_ATTR(CKA_PRIVATE_EXPONENT, big->big_value,
		    big->big_value_len);
		key->ck_count++;
	}

	/* CKA_PRIME_1 is optional. */
	big = OBJ_PRI_RSA_PRIME1(object_p);
	if (big->big_value != NULL) {
		if ((ptr = malloc(big->big_value_len)) == NULL) {
			rv = CKR_HOST_MEMORY;
			goto fail_cleanup;
		}
		ENCODE_ATTR(CKA_PRIME_1, big->big_value, big->big_value_len);
		key->ck_count++;
	}

	/* CKA_PRIME_2 is optional. */
	big = OBJ_PRI_RSA_PRIME2(object_p);
	if (big->big_value != NULL) {
		if ((ptr = malloc(big->big_value_len)) == NULL) {
			rv = CKR_HOST_MEMORY;
			goto fail_cleanup;
		}
		ENCODE_ATTR(CKA_PRIME_2, big->big_value, big->big_value_len);
		key->ck_count++;
	}

	/* CKA_EXPONENT_1 is optional. */
	big = OBJ_PRI_RSA_EXPO1(object_p);
	if (big->big_value != NULL) {
		if ((ptr = malloc(big->big_value_len)) == NULL) {
			rv = CKR_HOST_MEMORY;
			goto fail_cleanup;
		}
		ENCODE_ATTR(CKA_EXPONENT_1, big->big_value,
		    big->big_value_len);
		key->ck_count++;
	}

	/* CKA_EXPONENT_2 is optional. */
	big = OBJ_PRI_RSA_EXPO2(object_p);
	if (big->big_value != NULL) {
		if ((ptr = malloc(big->big_value_len)) == NULL) {
			rv = CKR_HOST_MEMORY;
			goto fail_cleanup;
		}
		ENCODE_ATTR(CKA_EXPONENT_2, big->big_value,
		    big->big_value_len);
		key->ck_count++;
	}

	/* CKA_COEFFICIENT is optional. */
	big = OBJ_PRI_RSA_COEF(object_p);
	if (big->big_value != NULL) {
		if ((ptr = malloc(big->big_value_len)) == NULL) {
			rv = CKR_HOST_MEMORY;
			goto fail_cleanup;
		}
		ENCODE_ATTR(CKA_COEFFICIENT, big->big_value,
		    big->big_value_len);
		key->ck_count++;
	}

	(void) pthread_mutex_unlock(&object_p->object_mutex);
	return (CKR_OK);

fail_cleanup:
	(void) pthread_mutex_unlock(&object_p->object_mutex);
	free_key_attributes(key);
	return (rv);
}

/*
 * Convert a RSA public key object into a crypto_key structure.
 * Memory is allocated for each attribute stored in the crypto_key
 * structure.  Memory for the crypto_key structure is not
 * allocated.  Attributes can be freed by free_key_attributes().
 */
CK_RV
get_rsa_public_key(kernel_object_t *object_p, crypto_key_t *key)
{
	biginteger_t *big;
	crypto_object_attribute_t *attrs, *cur_attr;
	char *ptr;

	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->key_type != CKK_RSA ||
	    object_p->class != CKO_PUBLIC_KEY) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	attrs = calloc(1,
	    RSA_PUB_ATTR_COUNT * sizeof (crypto_object_attribute_t));
	if (attrs == NULL) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_HOST_MEMORY);
	}

	key->ck_format = CRYPTO_KEY_ATTR_LIST;
	key->ck_count = RSA_PUB_ATTR_COUNT;
	key->ck_attrs = attrs;

	cur_attr = attrs;
	big = OBJ_PUB_RSA_PUBEXPO(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_PUBLIC_EXPONENT, big->big_value, big->big_value_len);

	big = OBJ_PUB_RSA_MOD(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_MODULUS, big->big_value, big->big_value_len);

	if ((ptr = malloc(sizeof (CK_ULONG))) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_MODULUS_BITS, &OBJ_PUB_RSA_MOD_BITS(object_p),
	    sizeof (CK_ULONG));

	(void) pthread_mutex_unlock(&object_p->object_mutex);
	return (CKR_OK);

mem_failure:
	(void) pthread_mutex_unlock(&object_p->object_mutex);
	free_key_attributes(key);
	return (CKR_HOST_MEMORY);
}

/*
 * Free attribute storage in a crypto_key structure.
 */
void
free_key_attributes(crypto_key_t *key)
{
	int i;

	if (key->ck_format == CRYPTO_KEY_ATTR_LIST &&
	    (key->ck_count > 0) && key->ck_attrs != NULL) {
		for (i = 0; i < key->ck_count; i++) {
			freezero(key->ck_attrs[i].oa_value,
			    key->ck_attrs[i].oa_value_len);
		}
		free(key->ck_attrs);
	}
}


/*
 * Convert a DSA private key object into a crypto_key structure.
 * Memory is allocated for each attribute stored in the crypto_key
 * structure.  Memory for the crypto_key structure is not
 * allocated.  Attributes can be freed by free_dsa_key_attributes().
 */
CK_RV
get_dsa_private_key(kernel_object_t *object_p, crypto_key_t *key)
{
	biginteger_t *big;
	crypto_object_attribute_t *attrs, *cur_attr;
	char *ptr;

	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->key_type != CKK_DSA ||
	    object_p->class != CKO_PRIVATE_KEY) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	attrs = calloc(1,
	    DSA_ATTR_COUNT * sizeof (crypto_object_attribute_t));
	if (attrs == NULL) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_HOST_MEMORY);
	}

	key->ck_format = CRYPTO_KEY_ATTR_LIST;
	key->ck_count = DSA_ATTR_COUNT;
	key->ck_attrs = attrs;

	cur_attr = attrs;
	big = OBJ_PRI_DSA_PRIME(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_PRIME, big->big_value, big->big_value_len);

	big = OBJ_PRI_DSA_SUBPRIME(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_SUBPRIME, big->big_value, big->big_value_len);

	big = OBJ_PRI_DSA_BASE(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_BASE, big->big_value, big->big_value_len);

	big = OBJ_PRI_DSA_VALUE(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_VALUE, big->big_value, big->big_value_len);

	(void) pthread_mutex_unlock(&object_p->object_mutex);
	return (CKR_OK);

mem_failure:
	(void) pthread_mutex_unlock(&object_p->object_mutex);
	free_key_attributes(key);
	return (CKR_HOST_MEMORY);
}


/*
 * Convert a DSA public key object into a crypto_key structure.
 * Memory is allocated for each attribute stored in the crypto_key
 * structure.  Memory for the crypto_key structure is not
 * allocated.  Attributes can be freed by free_dsa_key_attributes().
 */
CK_RV
get_dsa_public_key(kernel_object_t *object_p, crypto_key_t *key)
{
	biginteger_t *big;
	crypto_object_attribute_t *attrs, *cur_attr;
	char *ptr;

	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->key_type != CKK_DSA ||
	    object_p->class != CKO_PUBLIC_KEY) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	attrs = calloc(1,
	    DSA_ATTR_COUNT * sizeof (crypto_object_attribute_t));
	if (attrs == NULL) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_HOST_MEMORY);
	}

	key->ck_format = CRYPTO_KEY_ATTR_LIST;
	key->ck_count = DSA_ATTR_COUNT;
	key->ck_attrs = attrs;

	cur_attr = attrs;
	big = OBJ_PUB_DSA_PRIME(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_PRIME, big->big_value, big->big_value_len);

	big = OBJ_PUB_DSA_SUBPRIME(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_SUBPRIME, big->big_value, big->big_value_len);

	big = OBJ_PUB_DSA_BASE(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_BASE, big->big_value, big->big_value_len);

	big = OBJ_PUB_DSA_VALUE(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL)
		goto mem_failure;
	ENCODE_ATTR(CKA_VALUE, big->big_value, big->big_value_len);

	(void) pthread_mutex_unlock(&object_p->object_mutex);
	return (CKR_OK);

mem_failure:
	(void) pthread_mutex_unlock(&object_p->object_mutex);
	free_key_attributes(key);
	return (CKR_HOST_MEMORY);
}


/*
 * Convert a EC private key object into a crypto_key structure.
 * Memory is allocated for each attribute stored in the crypto_key
 * structure.  Memory for the crypto_key structure is not
 * allocated.  Attributes can be freed by free_ec_key_attributes().
 */
CK_RV
get_ec_private_key(kernel_object_t *object_p, crypto_key_t *key)
{
	biginteger_t *big;
	crypto_object_attribute_t *attrs, *cur_attr;
	CK_ATTRIBUTE tmp;
	char *ptr;
	int rv;

	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->key_type != CKK_EC ||
	    object_p->class != CKO_PRIVATE_KEY) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	attrs = calloc(EC_ATTR_COUNT, sizeof (crypto_object_attribute_t));
	if (attrs == NULL) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_HOST_MEMORY);
	}

	key->ck_format = CRYPTO_KEY_ATTR_LIST;
	key->ck_count = EC_ATTR_COUNT;
	key->ck_attrs = attrs;

	cur_attr = attrs;
	big = OBJ_PRI_EC_VALUE(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail;
	}
	ENCODE_ATTR(CKA_VALUE, big->big_value, big->big_value_len);

	tmp.type = CKA_EC_PARAMS;
	tmp.pValue = NULL;
	rv = kernel_get_attribute(object_p, &tmp);
	if (rv != CKR_OK) {
		goto fail;
	}

	tmp.pValue = malloc(tmp.ulValueLen);
	if (tmp.pValue == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail;
	}

	rv = kernel_get_attribute(object_p, &tmp);
	if (rv != CKR_OK) {
		free(tmp.pValue);
		goto fail;
	}

	cur_attr->oa_type = tmp.type;
	cur_attr->oa_value = tmp.pValue;
	cur_attr->oa_value_len = tmp.ulValueLen;

	(void) pthread_mutex_unlock(&object_p->object_mutex);
	return (CKR_OK);

fail:
	(void) pthread_mutex_unlock(&object_p->object_mutex);
	free_key_attributes(key);
	return (rv);
}

/*
 * Convert an EC public key object into a crypto_key structure.
 * Memory is allocated for each attribute stored in the crypto_key
 * structure.  Memory for the crypto_key structure is not
 * allocated.  Attributes can be freed by free_ec_key_attributes().
 */
CK_RV
get_ec_public_key(kernel_object_t *object_p, crypto_key_t *key)
{
	biginteger_t *big;
	crypto_object_attribute_t *attrs, *cur_attr;
	CK_ATTRIBUTE tmp;
	char *ptr;
	int rv;

	(void) pthread_mutex_lock(&object_p->object_mutex);
	if (object_p->key_type != CKK_EC ||
	    object_p->class != CKO_PUBLIC_KEY) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	attrs = calloc(EC_ATTR_COUNT, sizeof (crypto_object_attribute_t));
	if (attrs == NULL) {
		(void) pthread_mutex_unlock(&object_p->object_mutex);
		return (CKR_HOST_MEMORY);
	}

	key->ck_format = CRYPTO_KEY_ATTR_LIST;
	key->ck_count = EC_ATTR_COUNT;
	key->ck_attrs = attrs;

	cur_attr = attrs;
	big = OBJ_PUB_EC_POINT(object_p);
	if ((ptr = malloc(big->big_value_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail;
	}
	ENCODE_ATTR(CKA_EC_POINT, big->big_value, big->big_value_len);

	tmp.type = CKA_EC_PARAMS;
	tmp.pValue = NULL;
	rv = kernel_get_attribute(object_p, &tmp);
	if (rv != CKR_OK) {
		goto fail;
	}

	tmp.pValue = malloc(tmp.ulValueLen);
	if (tmp.pValue == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail;
	}

	rv = kernel_get_attribute(object_p, &tmp);
	if (rv != CKR_OK) {
		free(tmp.pValue);
		goto fail;
	}

	cur_attr->oa_type = tmp.type;
	cur_attr->oa_value = tmp.pValue;
	cur_attr->oa_value_len = tmp.ulValueLen;

	(void) pthread_mutex_unlock(&object_p->object_mutex);
	return (CKR_OK);

fail:
	(void) pthread_mutex_unlock(&object_p->object_mutex);
	free_key_attributes(key);
	return (rv);
}

/*
 * Convert an attribute template into an obj_attrs array.
 * Memory is allocated for each attribute stored in the obj_attrs.
 * The memory can be freed by free_object_attributes().
 *
 * If the boolean pointer is_token_obj is not NULL, the caller wants to
 * retrieve the value of the CKA_TOKEN attribute if it is specified in the
 * template.
 * - When this routine is called thru C_CreateObject(), C_CopyObject(), or
 *   any key management function, is_token_obj should NOT be NULL.
 * - When this routine is called thru C_GetAttributeValue() or
 *   C_SetAttributeValue(), "is_token_obj" should be NULL.
 */
CK_RV
process_object_attributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    caddr_t *obj_attrs, CK_BBOOL *is_token_obj)
{
	crypto_object_attribute_t *attrs, *cur_attr;
	int i, cur_i;
	char *ptr;
	CK_RV rv;
	ssize_t value_len;

	if (ulCount == 0) {
		obj_attrs = NULL;
		return (CKR_OK);
	}

	attrs = calloc(1, ulCount * sizeof (crypto_object_attribute_t));
	if (attrs == NULL) {
		return (CKR_HOST_MEMORY);
	}

	cur_attr = attrs;
	for (i = 0; i < ulCount; i++) {
		/*
		 * The length of long attributes must be set correctly
		 * so providers can determine whether they came from 32
		 * or 64-bit applications.
		 */
		switch (pTemplate[i].type) {
		case CKA_CLASS:
		case CKA_CERTIFICATE_TYPE:
		case CKA_KEY_TYPE:
		case CKA_MODULUS_BITS:
		case CKA_HW_FEATURE_TYPE:
			value_len = sizeof (ulong_t);
			if (pTemplate[i].pValue != NULL &&
			    (pTemplate[i].ulValueLen < value_len)) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				cur_i = i;
				goto fail_cleanup;
			}
			break;
		default:
			value_len = pTemplate[i].ulValueLen;
		}

		cur_attr->oa_type = pTemplate[i].type;
		cur_attr->oa_value_len = value_len;
		cur_attr->oa_value = NULL;

		if ((pTemplate[i].pValue != NULL) &&
		    (pTemplate[i].ulValueLen > 0)) {
			ptr = malloc(pTemplate[i].ulValueLen);
			if (ptr == NULL) {
				rv = CKR_HOST_MEMORY;
				cur_i = i;
				goto fail_cleanup;
			} else {
				(void) memcpy(ptr, pTemplate[i].pValue,
				    pTemplate[i].ulValueLen);
				cur_attr->oa_value = ptr;
			}
		}

		if ((is_token_obj != NULL) &&
		    (pTemplate[i].type == CKA_TOKEN)) {
			/* Get the CKA_TOKEN attribute value. */
			if (pTemplate[i].pValue == NULL) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				cur_i = i;
				goto fail_cleanup;
			} else {
				*is_token_obj =
				    *(CK_BBOOL *)pTemplate[i].pValue;
			}
		}

		cur_attr++;
	}

	*obj_attrs = (char *)attrs;
	return (CKR_OK);

fail_cleanup:
	cur_attr = attrs;
	for (i = 0; i < cur_i; i++) {
		if (cur_attr->oa_value != NULL) {
			(void) free(cur_attr->oa_value);
		}
		cur_attr++;
	}

	(void) free(attrs);
	return (rv);
}


/*
 * Copy the attribute values from obj_attrs to pTemplate.
 * The obj_attrs is an image of the Template and is expected to have the
 * same attributes in the same order and each one of the attribute pValue
 * in obj_attr has enough space allocated for the corresponding valueLen
 * in pTemplate.
 */
CK_RV
get_object_attributes(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
    caddr_t obj_attrs)
{
	crypto_object_attribute_t *cur_attr;
	CK_RV rv = CKR_OK;
	int i;

	/* LINTED */
	cur_attr = (crypto_object_attribute_t *)obj_attrs;
	for (i = 0; i < ulCount; i++) {
		if (pTemplate[i].type != cur_attr->oa_type) {
			/* The attribute type doesn't match, this is bad. */
			rv = CKR_FUNCTION_FAILED;
			return (rv);
		}

		pTemplate[i].ulValueLen = cur_attr->oa_value_len;

		if ((pTemplate[i].pValue != NULL) &&
		    ((CK_LONG)pTemplate[i].ulValueLen != -1)) {
			(void) memcpy(pTemplate[i].pValue, cur_attr->oa_value,
			    pTemplate[i].ulValueLen);
		}
		cur_attr++;
	}

	return (rv);
}

/*
 * Free the attribute storage in a crypto_object_attribute_t structure.
 */
void
free_object_attributes(caddr_t obj_attrs, CK_ULONG ulCount)
{
	crypto_object_attribute_t *cur_attr;
	int i;

	if ((ulCount == 0) || (obj_attrs == NULL)) {
		return;
	}

	/* LINTED */
	cur_attr = (crypto_object_attribute_t *)obj_attrs;
	for (i = 0; i < ulCount; i++) {
		/* XXX check that oa_value > 0 */
		if (cur_attr->oa_value != NULL) {
			free(cur_attr->oa_value);
		}
		cur_attr++;
	}

	free(obj_attrs);
}

/*
 * This function is called by process_found_objects().  It will check the
 * CKA_PRIVATE and CKA_TOKEN attributes for the kernel object "oid", then
 * initialize all the necessary fields in the object wrapper "objp".
 */
static CK_RV
create_new_tobj_in_lib(kernel_slot_t *pslot, kernel_session_t *sp,
    kernel_object_t *objp,  crypto_object_id_t oid)
{
	CK_RV  rv = CKR_OK;
	crypto_object_get_attribute_value_t obj_ga;
	boolean_t is_pri_obj;
	boolean_t is_token_obj;
	CK_BBOOL pri_value, token_value;
	CK_ATTRIBUTE  pTemplate[2];
	int r;

	/*
	 * Make a CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE ioctl call to get this
	 * kernel object's attribute values for CKA_PRIVATE and CKA_TOKEN.
	 */
	obj_ga.og_session = sp->k_session;
	obj_ga.og_handle = oid;
	obj_ga.og_count = 2;

	pTemplate[0].type = CKA_PRIVATE;
	pTemplate[0].pValue = &pri_value;
	pTemplate[0].ulValueLen = sizeof (pri_value);
	pTemplate[1].type = CKA_TOKEN;
	pTemplate[1].pValue = &token_value;
	pTemplate[1].ulValueLen = sizeof (token_value);
	rv = process_object_attributes(pTemplate, 2, &obj_ga.og_attributes,
	    NULL);
	if (rv != CKR_OK) {
		return (rv);
	}

	while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE,
	    &obj_ga)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_ga.og_return_value);
	}

	if (rv == CKR_OK) {
		rv = get_object_attributes(pTemplate, 2, obj_ga.og_attributes);
		if (rv == CKR_OK) {
			is_pri_obj = *(CK_BBOOL *)pTemplate[0].pValue;
			is_token_obj = *(CK_BBOOL *)pTemplate[1].pValue;
		}
	}

	free_object_attributes(obj_ga.og_attributes, 2);
	if (rv != CKR_OK) {
		return (rv);
	}

	/* Make sure it is a token object. */
	if (!is_token_obj) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		return (rv);
	}

	/* If it is a private object, make sure the user has logged in. */
	if (is_pri_obj && (pslot->sl_state != CKU_USER)) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		return (rv);
	}

	objp->is_lib_obj = B_FALSE;
	objp->k_handle = oid;
	objp->bool_attr_mask |= TOKEN_BOOL_ON;
	if (is_pri_obj) {
		objp->bool_attr_mask |= PRIVATE_BOOL_ON;
	} else {
		objp->bool_attr_mask &= ~PRIVATE_BOOL_ON;
	}

	(void) pthread_mutex_init(&objp->object_mutex, NULL);
	objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	objp->session_handle = (CK_SESSION_HANDLE) sp;

	return (CKR_OK);
}

/*
 * This function processes the kernel object handles returned from the
 * CRYPTO_OBJECT_FIND_UPDATE ioctl and returns an object handle list
 * and the number of object handles to the caller - C_FindObjects().
 * The caller acquires the slot lock and the session lock.
 */
CK_RV
process_found_objects(kernel_session_t *cur_sp, CK_OBJECT_HANDLE *obj_found,
    CK_ULONG *found_obj_count, crypto_object_find_update_t obj_fu)
{
	CK_RV rv = CKR_OK;
	crypto_object_id_t  *oid_p;
	kernel_slot_t *pslot;
	kernel_object_t *objp;
	kernel_object_t *objp1;
	kernel_object_t *new_tobj_list = NULL;
	kernel_session_t  *sp;
	CK_ULONG num_obj_found = 0;
	boolean_t is_in_lib;
	int i;

	if (obj_fu.fu_count == 0) {
		*found_obj_count = 0;
		return (CKR_OK);
	}

	pslot = slot_table[cur_sp->ses_slotid];

	/* LINTED */
	oid_p = (crypto_object_id_t *)obj_fu.fu_handles;
	for (i = 0; i < obj_fu.fu_count; i++) {
		is_in_lib = B_FALSE;
		/*
		 * Check if this oid has an object wrapper in the library
		 * already.  First, search the slot's token object list.
		 */
		objp = pslot->sl_tobj_list;
		while (!is_in_lib && objp) {
			if (objp->k_handle == *oid_p) {
				is_in_lib = B_TRUE;
			} else {
				objp = objp->next;
			}
		}

		/*
		 * If it is not in the slot's token object list,
		 * search it in all the sessions.
		 */
		if (!is_in_lib) {
			sp = pslot->sl_sess_list;
			while (!is_in_lib && sp) {
				objp = sp->object_list;
				while (!is_in_lib && objp) {
					if (objp->k_handle == *oid_p) {
						is_in_lib = B_TRUE;
					} else {
						objp = objp->next;
					}
				}
				sp = sp->next;
			}
		}

		/*
		 * If this object is in the library already, add its object
		 * wrapper to the returned find object list.
		 */
		if (is_in_lib) {
			obj_found[num_obj_found++] = (CK_OBJECT_HANDLE)objp;
		}

		/*
		 * If we still do not find it in the library.  This object
		 * must be a token object pre-existed in the HW provider.
		 * We need to create an object wrapper for it in the library.
		 */
		if (!is_in_lib) {
			objp1 = calloc(1, sizeof (kernel_object_t));
			if (objp1 == NULL) {
				rv = CKR_HOST_MEMORY;
				goto failed_exit;
			}
			rv = create_new_tobj_in_lib(pslot, cur_sp, objp1,
			    *oid_p);

			if (rv == CKR_OK) {
				/* Save the new object to the new_tobj_list. */
				if (new_tobj_list == NULL) {
					new_tobj_list = objp1;
					objp1->next = NULL;
					objp1->prev = NULL;
				} else {
					new_tobj_list->prev = objp1;
					objp1->next = new_tobj_list;
					objp1->prev = NULL;
					new_tobj_list = objp1;
				}
			} else {
				/*
				 * If create_new_tobj_in_lib() doesn't fail
				 * with CKR_HOST_MEMORY, the failure should be
				 * caused by the attributes' checking. We will
				 * just ignore this object and continue on.
				 */
				free(objp1);
				if (rv == CKR_HOST_MEMORY) {
					goto failed_exit;
				}
			}
		}

		/* Process next one */
		oid_p++;
	}

	/*
	 * Add the newly created token object wrappers to the found object
	 * list and to the slot's token object list.
	 */
	if (new_tobj_list != NULL) {
		/* Add to the obj_found array. */
		objp = new_tobj_list;
		while (objp) {
			obj_found[num_obj_found++] = (CK_OBJECT_HANDLE)objp;
			if (objp->next == NULL) {
				break;
			}
			objp = objp->next;
		}

		/* Add to the beginning of the slot's token object list. */
		if (pslot->sl_tobj_list != NULL) {
			objp->next = pslot->sl_tobj_list;
			pslot->sl_tobj_list->prev = objp;
		}
		pslot->sl_tobj_list = new_tobj_list;
	}

	*found_obj_count = num_obj_found;
	return (CKR_OK);

failed_exit:

	/* Free the newly created token object wrappers. */
	objp = new_tobj_list;
	while (objp) {
		objp1 = objp->next;
		(void) pthread_mutex_destroy(&objp->object_mutex);
		free(objp);
		objp = objp1;
	}

	return (rv);
}


/*
 * Get the value of the CKA_PRIVATE attribute for the object just returned
 * from the HW provider.  This function will be called by any function
 * that creates a new object, because the CKA_PRIVATE value of an object is
 * token specific.  The CKA_PRIVATE attribute value of the new object will be
 * stored in the object structure in the library, which will be used later at
 * C_Logout to clean up all private objects.
 */
CK_RV
get_cka_private_value(kernel_session_t *sp, crypto_object_id_t oid,
    CK_BBOOL *is_pri_obj)
{
	CK_RV  rv = CKR_OK;
	crypto_object_get_attribute_value_t obj_ga;
	crypto_object_attribute_t obj_attr;
	CK_BBOOL pri_value;
	int r;

	obj_ga.og_session = sp->k_session;
	obj_ga.og_handle = oid;
	obj_ga.og_count = 1;

	obj_attr.oa_type = CKA_PRIVATE;
	obj_attr.oa_value = (char *)&pri_value;
	obj_attr.oa_value_len = sizeof (CK_BBOOL);
	obj_ga.og_attributes = (char *)&obj_attr;

	while ((r = ioctl(kernel_fd, CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE,
	    &obj_ga)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_ga.og_return_value);
	}

	if (rv == CKR_OK) {
		*is_pri_obj = *(CK_BBOOL *)obj_attr.oa_value;
	}

	return (rv);
}


CK_RV
get_mechanism_info(kernel_slot_t *pslot, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo, uint32_t *k_mi_flags)
{
	crypto_get_provider_mechanism_info_t mechanism_info;
	const char *string;
	CK_FLAGS flags, mi_flags;
	CK_RV rv;
	int r;
	char buf[11];   /* Num chars for representing ulong in ASCII */

	if (type >= CKM_VENDOR_DEFINED) {
		/* allocate/build a string containing the mechanism number */
		(void) snprintf(buf, sizeof (buf), "%#lx", type);
		string = buf;
	} else {
		string = pkcs11_mech2str(type);
	}

	if (string == NULL)
		return (CKR_MECHANISM_INVALID);

	(void) strcpy(mechanism_info.mi_mechanism_name, string);
	mechanism_info.mi_provider_id = pslot->sl_provider_id;

	while ((r = ioctl(kernel_fd, CRYPTO_GET_PROVIDER_MECHANISM_INFO,
	    &mechanism_info)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(
		    mechanism_info.mi_return_value);
	}

	if (rv != CKR_OK) {
		return (rv);
	}

	/*
	 * Atomic flags are not part of PKCS#11 so we filter
	 * them out here.
	 */
	mi_flags = mechanism_info.mi_flags;
	mi_flags &= ~(CRYPTO_FG_DIGEST_ATOMIC | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_SIGN_RECOVER_ATOMIC |
	    CRYPTO_FG_VERIFY_RECOVER_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC);

	if (mi_flags == 0) {
		return (CKR_MECHANISM_INVALID);
	}

	if (rv == CKR_OK) {
		/* set the value of k_mi_flags first */
		*k_mi_flags = mi_flags;

		/* convert KEF flags into pkcs11 flags */
		flags = CKF_HW;
		if (mi_flags & CRYPTO_FG_ENCRYPT)
			flags |= CKF_ENCRYPT;
		if (mi_flags & CRYPTO_FG_DECRYPT) {
			flags |= CKF_DECRYPT;
			/*
			 * Since we'll be emulating C_UnwrapKey() for some
			 * cases, we can go ahead and claim CKF_UNWRAP
			 */
			flags |= CKF_UNWRAP;
		}
		if (mi_flags & CRYPTO_FG_DIGEST)
			flags |= CKF_DIGEST;
		if (mi_flags & CRYPTO_FG_SIGN)
			flags |= CKF_SIGN;
		if (mi_flags & CRYPTO_FG_SIGN_RECOVER)
			flags |= CKF_SIGN_RECOVER;
		if (mi_flags & CRYPTO_FG_VERIFY)
			flags |= CKF_VERIFY;
		if (mi_flags & CRYPTO_FG_VERIFY_RECOVER)
			flags |= CKF_VERIFY_RECOVER;
		if (mi_flags & CRYPTO_FG_GENERATE)
			flags |= CKF_GENERATE;
		if (mi_flags & CRYPTO_FG_GENERATE_KEY_PAIR)
			flags |= CKF_GENERATE_KEY_PAIR;
		if (mi_flags & CRYPTO_FG_WRAP)
			flags |= CKF_WRAP;
		if (mi_flags & CRYPTO_FG_UNWRAP)
			flags |= CKF_UNWRAP;
		if (mi_flags & CRYPTO_FG_DERIVE)
			flags |= CKF_DERIVE;

		pInfo->ulMinKeySize = mechanism_info.mi_min_key_size;
		pInfo->ulMaxKeySize = mechanism_info.mi_max_key_size;
		pInfo->flags = flags;

	}

	return (rv);
}
