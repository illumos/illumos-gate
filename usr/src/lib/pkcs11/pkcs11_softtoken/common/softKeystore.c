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
 * Copyright 2018, Joyent, Inc.
 */

#include <crypt.h>
#include <cryptoutil.h>
#include <pwd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softCrypt.h"
#include "softSession.h"
#include "softObject.h"
#include "softKeys.h"
#include "softKeystore.h"
#include "softKeystoreUtil.h"
#include "softMAC.h"
#include "softOps.h"

soft_session_t token_session;

/*
 * soft_gen_hashed_pin()
 *
 * Arguments:
 *
 *	pPin:	pointer to caller provided Pin
 *	result:	output argument which contains the address of the
 *		pointer to the hashed pin
 *	salt:	input argument (if non-NULL), or
 *		output argument (if NULL):
 *		address of pointer to the "salt" of the hashed pin
 *
 * Description:
 *
 *	Generate a hashed pin using system provided crypt(3C) function.
 *
 * Returns:
 *
 *	0: no error
 *	-1: some error occurred while generating the hashed pin
 *
 */
int
soft_gen_hashed_pin(CK_UTF8CHAR_PTR pPin, char **result, char **salt)
{

	uid_t uid;
	struct passwd pwd, *pw;
	char pwdbuf[PWD_BUFFER_SIZE];
	boolean_t new_salt = B_FALSE;

	/*
	 * We need to get the passwd entry of the application, which is required
	 * by the crypt_gensalt() below.
	 */
	uid = geteuid();
	if (getpwuid_r(uid, &pwd, pwdbuf, PWD_BUFFER_SIZE, &pw) != 0) {
		return (-1);
	}

	if (*salt == NULL) {
		new_salt = B_TRUE;
		/*
		 * crypt_gensalt() will allocate memory to store the new salt.
		 * on return.  Pass "$5" here to default to crypt_sha256 since
		 * SHA256 is a FIPS 140-2 certified algorithm and we shouldn't
		 * assume the system default is that strong.
		 */
		if ((*salt = crypt_gensalt("$5", pw)) == NULL) {
			return (-1);
		}
	}

	if ((*result = crypt((char *)pPin, *salt)) == NULL) {
		if (new_salt) {
			size_t saltlen = strlen(*salt) + 1;

			freezero(*salt, saltlen);
		}
		return (-1);
	}

	return (0);
}

/*
 * Authenticate user's PIN for C_Login.
 */
CK_RV
soft_verify_pin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{

	char	*user_cryptpin = NULL;
	char	*ks_cryptpin = NULL;
	char	*salt = NULL;
	uchar_t	*tmp_pin = NULL;
	boolean_t pin_initialized = B_FALSE;
	CK_RV	rv = CKR_OK;
	size_t	len = 0;

	/*
	 * Check to see if keystore is initialized.
	 */
	rv = soft_keystore_pin_initialized(&pin_initialized, &ks_cryptpin,
	    B_FALSE);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Authenticate user's PIN for C_Login.
	 */
	if (pin_initialized) {

		if (soft_keystore_get_pin_salt(&salt) < 0) {
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		/*
		 * Generate the hashed value based on the user's supplied pin.
		 */
		tmp_pin = malloc(ulPinLen + 1);
		if (tmp_pin == NULL) {
			rv = CKR_HOST_MEMORY;
			goto cleanup;
		}

		(void) memcpy(tmp_pin, pPin, ulPinLen);
		tmp_pin[ulPinLen] = '\0';

		if (soft_gen_hashed_pin(tmp_pin, &user_cryptpin, &salt) < 0) {
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		/*
		 * Compare hash value of the user supplied PIN with
		 * hash value of the keystore PIN.
		 */
		if (strcmp(user_cryptpin, ks_cryptpin) != 0) {
			rv = CKR_PIN_INCORRECT;
			goto cleanup;
		}

		/*
		 * Provide the user's PIN to low-level keystore so that
		 * it can use it to generate encryption key as needed for
		 * encryption/decryption of the private objects in
		 * keystore.
		 */
		if (soft_keystore_authpin(tmp_pin) != 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = CKR_OK;
		}
		goto cleanup;
	} else {
		/*
		 * The PIN is not initialized in the keystore
		 * We will let it pass the authentication anyway but set the
		 * "userpin_change_needed" flag so that the application
		 * will get CKR_PIN_EXPIRED by other C_functions such as
		 * C_CreateObject, C_FindObjectInit, C_GenerateKey etc.
		 */
		soft_slot.userpin_change_needed = 1;
		rv = CKR_OK;
	}

cleanup:
	if (salt) {
		len = strlen(salt) + 1;
		freezero(salt, len);
	}
	if (tmp_pin) {
		len = strlen((char *)tmp_pin) + 1;
		freezero(tmp_pin, len);
	}
	if (ks_cryptpin) {
		len = strlen(ks_cryptpin) + 1;
		freezero(ks_cryptpin, len);
	}
	return (rv);
}

/*
 * The second level C_SetPIN function.
 */
CK_RV
soft_setpin(CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen,
    CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{

	char	*user_cryptpin = NULL;
	char	*ks_cryptpin = NULL;
	char	*salt = NULL;
	boolean_t pin_initialized = B_FALSE;
	uchar_t	*tmp_old_pin = NULL, *tmp_new_pin = NULL;
	CK_RV	rv = CKR_OK;
	size_t	len = 0;

	/*
	 * Check to see if keystore is initialized.
	 */
	rv = soft_keystore_pin_initialized(&pin_initialized, &ks_cryptpin,
	    B_FALSE);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Authenticate user's PIN for C_SetPIN.
	 */
	if (pin_initialized) {
		/*
		 * Generate the hashed value based on the user supplied PIN.
		 */
		if (soft_keystore_get_pin_salt(&salt) < 0) {
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		tmp_old_pin = malloc(ulOldPinLen + 1);
		if (tmp_old_pin == NULL) {
			rv = CKR_HOST_MEMORY;
			goto cleanup;
		}
		(void) memcpy(tmp_old_pin, pOldPin, ulOldPinLen);
		tmp_old_pin[ulOldPinLen] = '\0';

		if (soft_gen_hashed_pin(tmp_old_pin, &user_cryptpin,
		    &salt) < 0) {
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		/*
		 * Compare hashed value of the user supplied PIN with the
		 * hashed value of the keystore PIN.
		 */
		if (strcmp(user_cryptpin, ks_cryptpin) != 0) {
			rv = CKR_PIN_INCORRECT;
			goto cleanup;
		}
	} else {
		/*
		 * This is the first time to setpin, the oldpin must be
		 * "changeme".
		 */
		if (strncmp("changeme", (const char *)pOldPin,
		    ulOldPinLen) != 0) {
			rv = CKR_PIN_INCORRECT;
			goto cleanup;
		}
	}

	tmp_new_pin = malloc(ulNewPinLen + 1);
	if (tmp_new_pin == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	(void) memcpy(tmp_new_pin, pNewPin, ulNewPinLen);
	tmp_new_pin[ulNewPinLen] = '\0';

	/*
	 * Set the new pin after the old pin is authenticated.
	 */
	if (soft_keystore_setpin(tmp_old_pin, tmp_new_pin, B_FALSE)) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	} else {
		(void) pthread_mutex_lock(&soft_giant_mutex);
		soft_slot.userpin_change_needed = 0;
		(void) pthread_mutex_unlock(&soft_giant_mutex);
		rv = CKR_OK;
	}

cleanup:
	if (salt) {
		len = strlen(salt) + 1;
		freezero(salt, len);
	}
	if (ks_cryptpin) {
		len = strlen(ks_cryptpin) + 1;
		freezero(ks_cryptpin, len);
	}
	if (tmp_old_pin) {
		len = strlen((char *)tmp_old_pin) + 1;
		freezero(tmp_old_pin, len);
	}
	if (tmp_new_pin) {
		len = strlen((char *)tmp_new_pin) + 1;
		freezero(tmp_new_pin, len);
	}

	return (rv);
}

/*
 * soft_keystore_pack_obj()
 *
 * Arguments:
 *
 *	obj:	pointer to the soft_object_t of the token object to
 *		be packed
 *	ks_buf:	output argument which contains the address of the
 *		pointer to the buf of the packed token object
 *		soft_keystore_pack_obj() will allocate memory for the buf,
 *		it is caller's responsibility to free it.
 *	len:	output argument which contains the address of the
 *		buffer length of the packed token object
 *
 * Description:
 *
 *	Pack the in-core token object into the keystore format.
 *
 * Returns:
 *
 *	CKR_OK: no error
 *	Other: some error occurred while packing the object
 *
 */
CK_RV
soft_keystore_pack_obj(soft_object_t *obj, uchar_t **ks_buf, size_t *len)
{
	ks_obj_hdr_t hdr;
	ks_attr_hdr_t attr_hdr;
	CK_ATTRIBUTE_INFO_PTR extra_attr;
	int num_attrs = 0;
	ulong_t len_attrs = 0;
	size_t ks_len;
	uchar_t *buf, *buf1;
	CK_RV rv;
	int i;

	(void) memset(&hdr, 0, sizeof (ks_obj_hdr_t));

	/*
	 * The first part of the packed format contains
	 * the ks_obj_hdr_t struct.
	 */
	hdr.class = SWAP64((uint64_t)obj->class);
	hdr.key_type = SWAP64((uint64_t)obj->key_type);
	hdr.cert_type = SWAP64((uint64_t)obj->cert_type);
	hdr.bool_attr_mask = SWAP64(obj->bool_attr_mask);
	hdr.mechanism = SWAP64((uint64_t)obj->mechanism);
	hdr.object_type = obj->object_type;

	/*
	 * The second part of the packed format contains
	 * the attributes from the extra atrribute list.
	 */
	extra_attr = obj->extra_attrlistp;

	while (extra_attr) {
		num_attrs++;
		len_attrs += ROUNDUP(extra_attr->attr.ulValueLen, 8);
		extra_attr = extra_attr->next;
	}
	hdr.num_attrs = SWAP32(num_attrs);
	ks_len = soft_pack_object_size(obj);
	ks_len += sizeof (ks_obj_hdr_t) + len_attrs +
	    2 * num_attrs * sizeof (uint64_t);
	buf = calloc(1, ks_len);
	if (buf == NULL) {
		return (CKR_HOST_MEMORY);
	}
	(void) memcpy(buf, &hdr, sizeof (ks_obj_hdr_t));
	buf1 = buf + sizeof (ks_obj_hdr_t);
	extra_attr = obj->extra_attrlistp;
	for (i = 0; i < num_attrs; i++) {
		attr_hdr.type = SWAP64((uint64_t)extra_attr->attr.type);
		attr_hdr.ulValueLen =
		    SWAP64((uint64_t)extra_attr->attr.ulValueLen);
		(void) memcpy(buf1, &attr_hdr, sizeof (ks_attr_hdr_t));
		buf1 = buf1 + sizeof (ks_attr_hdr_t);
		(void) memcpy(buf1, extra_attr->attr.pValue,
		    extra_attr->attr.ulValueLen);
		buf1 = buf1 + ROUNDUP(extra_attr->attr.ulValueLen, 8);
		extra_attr = extra_attr->next;
	}

	/*
	 * The third part of the packed format contains
	 * the key itself.
	 */
	rv = soft_pack_object(obj, buf1);
	*len = ks_len;
	*ks_buf = buf;

	return (rv);

}

/*
 * soft_keystore_unpack_obj()
 *
 * Arguments:
 *
 *	obj:	pointer to the soft_object_t to store the unpacked
 *		token object
 *	ks_obj:	input argument which contains the pointer to the
 *		ks_obj_t struct of packed token object to be unpacked
 *
 * Description:
 *
 *	Unpack the token object in keystore format to in-core soft_object_t.
 *
 * Returns:
 *
 *	CKR_OK: no error
 *	Other: some error occurred while unpacking the object
 *
 */
CK_RV
soft_keystore_unpack_obj(soft_object_t *obj, ks_obj_t *ks_obj)
{

	CK_RV rv;
	ks_obj_hdr_t *hdr;
	ks_attr_hdr_t *attr_hdr;
	CK_ATTRIBUTE template;
	int i;
	uchar_t *buf;

	/*
	 * Unpack the common area.
	 */
	(void) strcpy((char *)obj->ks_handle.name,
	    (char *)ks_obj->ks_handle.name);
	obj->ks_handle.public = ks_obj->ks_handle.public;
	/* LINTED: pointer alignment */
	hdr = (ks_obj_hdr_t *)ks_obj->buf;
	obj->version = ks_obj->obj_version;
	obj->class = (CK_OBJECT_CLASS)(SWAP64(hdr->class));
	obj->key_type = (CK_KEY_TYPE)(SWAP64(hdr->key_type));
	obj->cert_type = (CK_CERTIFICATE_TYPE)(SWAP64(hdr->cert_type));
	obj->bool_attr_mask = SWAP64(hdr->bool_attr_mask);
	obj->mechanism = (CK_MECHANISM_TYPE)(SWAP64(hdr->mechanism));
	obj->object_type = hdr->object_type;

	/*
	 * Initialize other stuffs which were not from keystore.
	 */
	(void) pthread_mutex_init(&obj->object_mutex, NULL);
	obj->magic_marker = SOFTTOKEN_OBJECT_MAGIC;
	obj->session_handle = (CK_SESSION_HANDLE)NULL;

	buf = ks_obj->buf + sizeof (ks_obj_hdr_t);

	/*
	 * Unpack extra attribute list.
	 */
	for (i = 0; i < SWAP32(hdr->num_attrs); i++) {
		/* LINTED: pointer alignment */
		attr_hdr = (ks_attr_hdr_t *)buf;
		(void) memset(&template, 0, sizeof (CK_ATTRIBUTE));
		template.type = (CK_ATTRIBUTE_TYPE)(SWAP64(attr_hdr->type));
		template.ulValueLen = (CK_ULONG)(SWAP64(attr_hdr->ulValueLen));
		buf = buf + sizeof (ks_attr_hdr_t);
		/* Allocate storage for the value of the attribute. */
		if (template.ulValueLen > 0) {
			template.pValue = malloc(template.ulValueLen);
			if (template.pValue == NULL) {
				return (CKR_HOST_MEMORY);
			}
			(void) memcpy(template.pValue, buf,
			    template.ulValueLen);
		}

		rv = soft_add_extra_attr(&template, obj);
		freezero(template.pValue, template.ulValueLen);

		if (rv != CKR_OK) {
			return (rv);
		}

		buf = buf + ROUNDUP(template.ulValueLen, 8);
	}

	/*
	 * Unpack the key itself.
	 */
	rv = soft_unpack_object(obj, buf);
	return (rv);

}


/*
 * soft_unpack_obj_attribute()
 *
 * Arguments:
 *
 *	buf:	contains the packed data (attributes) from keystore
 *	key_dest: the key attribute will be unpacked and save in key_dest
 *	cert_dest: the certificate attribute will be unpacked an
 *		   in cert_dest
 *	offset: length of the current attribute occupies.
 *		The caller should use this returned "offset" to
 *		advance the buffer pointer to next attribute.
 *	cert:	TRUE for certificate (use cert_dest)
 *		FALSE for key (use key_dest)
 *
 * Description:
 *
 *	Unpack the attribute from keystore format to the big integer format.
 *
 * Returns:
 *
 *	CKR_OK: no error
 *	Other: some error occurred while unpacking the object attribute
 *
 */
CK_RV
soft_unpack_obj_attribute(uchar_t *buf, biginteger_t *key_dest,
    cert_attr_t **cert_dest, ulong_t *offset, boolean_t cert)
{

	CK_RV rv;
	CK_ATTRIBUTE template;

	/* LINTED: pointer alignment */
	template.ulValueLen = SWAP64(*(uint64_t *)buf);
	buf = buf + sizeof (uint64_t);
	template.pValue = malloc(template.ulValueLen);
	if (template.pValue == NULL) {
		return (CKR_HOST_MEMORY);
	}

	(void) memcpy(template.pValue, buf, template.ulValueLen);
	if (cert) {
		rv = get_cert_attr_from_template(cert_dest, &template);
	} else {
		rv = get_bigint_attr_from_template(key_dest, &template);
	}

	freezero(template.pValue, template.ulValueLen);
	if (rv != CKR_OK) {
		return (rv);
	}

	*offset = sizeof (uint64_t) + template.ulValueLen;
	return (CKR_OK);
}


/*
 * Calculate the total buffer length required to store the
 * object key (the third part) in a keystore format.
 */
ulong_t
soft_pack_object_size(soft_object_t *objp)
{

	CK_OBJECT_CLASS class = objp->class;
	CK_KEY_TYPE	keytype = objp->key_type;
	CK_CERTIFICATE_TYPE certtype = objp->cert_type;

	switch (class) {
	case CKO_PUBLIC_KEY:
		switch (keytype) {
		case CKK_RSA:
			/*
			 * modulus_bits + modulus_len + modulus +
			 * pubexpo_len + pubexpo
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PUB_RSA_MOD(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_RSA_PUBEXPO(objp))->big_value_len, 8) +
			    3 * sizeof (uint64_t));

		case CKK_DSA:
			/*
			 * prime_len + prime + subprime_len + subprime +
			 * base_len + base + value_len + value
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DSA_PRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DSA_SUBPRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DSA_BASE(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DSA_VALUE(objp))->big_value_len, 8) +
			    4 * sizeof (uint64_t));
		case CKK_EC:
			/*
			 * ec_point_len + ec_point
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PUB_EC_POINT(objp))->big_value_len, 8) +
			    sizeof (uint64_t));
		case CKK_DH:
			/*
			 * prime_len + prime + base_len + base +
			 * value_len + value
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH_PRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH_BASE(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH_VALUE(objp))->big_value_len, 8) +
			    3 * sizeof (uint64_t));

		case CKK_X9_42_DH:
			/*
			 * prime_len + prime + base_len + base +
			 * subprime_len + subprime + value_len + value
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH942_PRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH942_BASE(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH942_SUBPRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH942_VALUE(objp))->big_value_len, 8) +
			    4 * sizeof (uint64_t));
		} /* keytype */

		break;

	case CKO_PRIVATE_KEY:
		switch (keytype) {
		case CKK_RSA:
			/*
			 * modulus_len + modulus + pubexpo_len + pubexpo +
			 * priexpo_len + priexpo + prime1_len + prime1 +
			 * prime2_len + prime2 + expo1_len + expo1 +
			 * expo2_len + expo2 + coef_len + coef
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_MOD(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PUBEXPO(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PRIEXPO(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PRIME1(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PRIME2(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_EXPO1(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_EXPO2(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_COEF(objp))->big_value_len, 8) +
			    8 * sizeof (uint64_t));

		case CKK_DSA:
			/*
			 * prime_len + prime + subprime_len + subprime +
			 * base_len + base + value_len + value
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DSA_PRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DSA_SUBPRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DSA_BASE(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DSA_VALUE(objp))->big_value_len, 8) +
			    4 * sizeof (uint64_t));

		case CKK_DH:
			/*
			 * value_bits + prime_len + prime + base_len + base +
			 * value_len + value
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH_PRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH_BASE(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH_VALUE(objp))->big_value_len, 8) +
			    4 * sizeof (uint64_t));

		case CKK_EC:
			/*
			 * value_len + value
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PRI_EC_VALUE(objp))->big_value_len, 8) +
			    sizeof (uint64_t));

		case CKK_X9_42_DH:
			/*
			 * prime_len + prime + base_len + base +
			 * subprime_len + subprime + value_len + value
			 */
			return (ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH942_PRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH942_BASE(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH942_SUBPRIME(objp))->big_value_len, 8) +
			    ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH942_VALUE(objp))->big_value_len, 8) +
			    4 * sizeof (uint64_t));

		} /* keytype */

		break;

	case CKO_SECRET_KEY:
		/*
		 * value_len + value
		 */
		return (ROUNDUP(OBJ_SEC_VALUE_LEN(objp), 8) +
		    sizeof (uint64_t));

	case CKO_CERTIFICATE:
		switch (certtype) {
		case CKC_X_509:
			/*
			 * subject_len + subject + value_len + value
			 */
			return (ROUNDUP(((cert_attr_t *)
			    X509_CERT_SUBJECT(objp))->length, 8) +
			    ROUNDUP(((cert_attr_t *)
			    X509_CERT_VALUE(objp))->length, 8) +
			    2 * sizeof (uint64_t));

		case CKC_X_509_ATTR_CERT:
			/*
			 * owner_len + owner + value_len + value
			 */
			return (ROUNDUP(((cert_attr_t *)
			    X509_ATTR_CERT_OWNER(objp))->length, 8) +
			    ROUNDUP(((cert_attr_t *)
			    X509_ATTR_CERT_VALUE(objp))->length, 8) +
			    2 * sizeof (uint64_t));
		}
		return (0);

	case CKO_DOMAIN_PARAMETERS:

		return (0);
	}
	return (0);
}

/*
 * Pack the object key (the third part) from the soft_object_t
 * into the keystore format.
 */
CK_RV
soft_pack_object(soft_object_t *objp, uchar_t *buf)
{

	CK_OBJECT_CLASS class = objp->class;
	CK_KEY_TYPE	keytype = objp->key_type;
	CK_CERTIFICATE_TYPE certtype = objp->cert_type;
	uint64_t tmp_val;

	switch (class) {
	case CKO_PUBLIC_KEY:
		switch (keytype) {
		case CKK_RSA:
			/* modulus_bits */
			tmp_val = SWAP64((uint64_t)OBJ_PUB_RSA_MOD_BITS(objp));
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			/* modulus_len + modulus */
			tmp_val = SWAP64((uint64_t)(((biginteger_t *)
			    OBJ_PUB_RSA_MOD(objp))->big_value_len));
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)(((biginteger_t *)
			    OBJ_PUB_RSA_MOD(objp))->big_value),
			    ((biginteger_t *)
			    OBJ_PUB_RSA_MOD(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_RSA_MOD(objp))->big_value_len, 8);

			/* pubexpo_len + pubexpo */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_RSA_PUBEXPO(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)(((biginteger_t *)
			    OBJ_PUB_RSA_PUBEXPO(objp))->big_value),
			    ((biginteger_t *)
			    OBJ_PUB_RSA_PUBEXPO(objp))->big_value_len);
			break;

		case CKK_DSA:
			/* prime_len + prime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DSA_PRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DSA_PRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DSA_PRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DSA_PRIME(objp))->big_value_len, 8);

			/* subprime_len + subprime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DSA_SUBPRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DSA_SUBPRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DSA_SUBPRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DSA_SUBPRIME(objp))->big_value_len, 8);

			/* base_len + base */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DSA_BASE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DSA_BASE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DSA_BASE(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DSA_BASE(objp))->big_value_len, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DSA_VALUE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DSA_VALUE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DSA_VALUE(objp))->big_value_len);

			break;
		case CKK_EC:
			/* point_len + point */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_EC_POINT(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_EC_POINT(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_EC_POINT(objp))->big_value_len);
			break;

		case CKK_DH:
			/* prime_len + prime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DH_PRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DH_PRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DH_PRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH_PRIME(objp))->big_value_len, 8);

			/* base_len + base */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DH_BASE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DH_BASE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DH_BASE(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH_BASE(objp))->big_value_len, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DH_VALUE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DH_VALUE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DH_VALUE(objp))->big_value_len);

			break;

		case CKK_X9_42_DH:
			/* prime_len +  prime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DH942_PRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DH942_PRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DH942_PRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH942_PRIME(objp))->big_value_len, 8);

			/* base_len + base */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DH942_BASE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DH942_BASE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DH942_BASE(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH942_BASE(objp))->big_value_len, 8);

			/* subprime_len + subprime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DH942_SUBPRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DH942_SUBPRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DH942_SUBPRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PUB_DH942_SUBPRIME(objp))->big_value_len, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PUB_DH942_VALUE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PUB_DH942_VALUE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PUB_DH942_VALUE(objp))->big_value_len);

			break;
		} /* keytype */

		break;

	case CKO_PRIVATE_KEY:
		switch (keytype) {
		case CKK_RSA:
			/* modulus_len + modulus */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_MOD(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_MOD(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_MOD(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_MOD(objp))->big_value_len, 8);

			/* pubexpo_len + pubexpo */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_PUBEXPO(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_PUBEXPO(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_PUBEXPO(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PUBEXPO(objp))->big_value_len, 8);

			/* priexpo_len + priexpo */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_PRIEXPO(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_PRIEXPO(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_PRIEXPO(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PRIEXPO(objp))->big_value_len, 8);

			/* prime1_len + prime1 */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_PRIME1(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_PRIME1(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_PRIME1(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PRIME1(objp))->big_value_len, 8);

			/* prime2_len + prime2 */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_PRIME2(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_PRIME2(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_PRIME2(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_PRIME2(objp))->big_value_len, 8);

			/* expo1_len + expo1 */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_EXPO1(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_EXPO1(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_EXPO1(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_EXPO1(objp))->big_value_len, 8);

			/* expo2_len + expo2 */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_EXPO2(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_EXPO2(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_EXPO2(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_EXPO2(objp))->big_value_len, 8);

			/* coef_len + coef */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_RSA_COEF(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_RSA_COEF(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_RSA_COEF(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_RSA_COEF(objp))->big_value_len, 8);

			break;

		case CKK_DSA:
			/* prime_len + prime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DSA_PRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DSA_PRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DSA_PRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DSA_PRIME(objp))->big_value_len, 8);

			/* subprime_len + subprime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DSA_SUBPRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DSA_SUBPRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DSA_SUBPRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DSA_SUBPRIME(objp))->big_value_len, 8);

			/* base_len + base */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DSA_BASE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DSA_BASE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DSA_BASE(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DSA_BASE(objp))->big_value_len, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DSA_VALUE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DSA_VALUE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DSA_VALUE(objp))->big_value_len);

			break;
		case CKK_EC:
			/* value_len + value */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_EC_VALUE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_EC_VALUE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_EC_VALUE(objp))->big_value_len);
			break;

		case CKK_DH:
			/* value_bits */
			tmp_val = SWAP64((uint64_t)OBJ_PRI_DH_VAL_BITS(objp));
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			/* prime_len + prime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DH_PRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DH_PRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DH_PRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH_PRIME(objp))->big_value_len, 8);

			/* base_len + base */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DH_BASE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DH_BASE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DH_BASE(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH_BASE(objp))->big_value_len, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DH_VALUE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DH_VALUE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DH_VALUE(objp))->big_value_len);

			break;

		case CKK_X9_42_DH:
			/* prime_len + prime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DH942_PRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DH942_PRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DH942_PRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH942_PRIME(objp))->big_value_len, 8);

			/* base_len + base */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DH942_BASE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DH942_BASE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DH942_BASE(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH942_BASE(objp))->big_value_len, 8);

			/* subprime_len + subprime */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DH942_SUBPRIME(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DH942_SUBPRIME(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DH942_SUBPRIME(objp))->big_value_len);
			buf = buf + ROUNDUP(((biginteger_t *)
			    OBJ_PRI_DH942_SUBPRIME(objp))->big_value_len, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)((biginteger_t *)
			    OBJ_PRI_DH942_VALUE(objp))->big_value_len);
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((biginteger_t *)
			    OBJ_PRI_DH942_VALUE(objp))->big_value,
			    ((biginteger_t *)
			    OBJ_PRI_DH942_VALUE(objp))->big_value_len);

			break;

		} /* keytype */

		break;

	case CKO_SECRET_KEY:
		/* value_len  + value */
		tmp_val = SWAP64((uint64_t)OBJ_SEC_VALUE_LEN(objp));
		(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
		buf = buf + sizeof (uint64_t);

		if (OBJ_SEC_VALUE_LEN(objp) > 0) {
			(void) memcpy(buf, (char *)OBJ_SEC_VALUE(objp),
			    OBJ_SEC_VALUE_LEN(objp));
			buf = buf + ROUNDUP(OBJ_SEC_VALUE_LEN(objp), 8);
		}

		break;

	case CKO_CERTIFICATE:

		switch (certtype) {
		case CKC_X_509:
			/* subject_len + subject */
			tmp_val = SWAP64((uint64_t)(((cert_attr_t *)
			    X509_CERT_SUBJECT(objp))->length));
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((cert_attr_t *)
			    X509_CERT_SUBJECT(objp))->value,
			    ((cert_attr_t *)
			    X509_CERT_SUBJECT(objp))->length);
			buf = buf + ROUNDUP(((cert_attr_t *)
			    X509_CERT_SUBJECT(objp))->length, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)(((cert_attr_t *)
			    X509_CERT_VALUE(objp))->length));
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((cert_attr_t *)
			    X509_CERT_VALUE(objp))->value,
			    ((cert_attr_t *)
			    X509_CERT_VALUE(objp))->length);
			break;

		case CKC_X_509_ATTR_CERT:
			/* owner_len + owner */
			tmp_val = SWAP64((uint64_t)(((cert_attr_t *)
			    X509_ATTR_CERT_OWNER(objp))->length));
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((cert_attr_t *)
			    X509_ATTR_CERT_OWNER(objp))->value,
			    ((cert_attr_t *)
			    X509_ATTR_CERT_OWNER(objp))->length);
			buf = buf + ROUNDUP(((cert_attr_t *)
			    X509_ATTR_CERT_OWNER(objp))->length, 8);

			/* value_len + value */
			tmp_val = SWAP64((uint64_t)(((cert_attr_t *)
			    X509_ATTR_CERT_VALUE(objp))->length));
			(void) memcpy(buf, (char *)&tmp_val, sizeof (uint64_t));
			buf = buf + sizeof (uint64_t);

			(void) memcpy(buf, (char *)((cert_attr_t *)
			    X509_ATTR_CERT_VALUE(objp))->value,
			    ((cert_attr_t *)
			    X509_ATTR_CERT_VALUE(objp))->length);
			break;
		}
		break;

	case CKO_DOMAIN_PARAMETERS:

		return (0);
	}
	return (CKR_OK);
}

/*
 * Unpack the object key in keystore format (the third part)
 * into soft_object_t.
 */
CK_RV
soft_unpack_object(soft_object_t *objp, uchar_t *buf)
{

	public_key_obj_t  *pbk;
	private_key_obj_t *pvk;
	secret_key_obj_t  *sck;
	certificate_obj_t *cert;
	CK_OBJECT_CLASS class = objp->class;
	CK_KEY_TYPE	keytype = objp->key_type;
	CK_CERTIFICATE_TYPE certtype = objp->cert_type;

	biginteger_t	modulus;
	biginteger_t	pubexpo;
	biginteger_t	prime;
	biginteger_t	subprime;
	biginteger_t	base;
	biginteger_t	value;

	biginteger_t	priexpo;
	biginteger_t	prime1;
	biginteger_t	prime2;
	biginteger_t	expo1;
	biginteger_t	expo2;
	biginteger_t	coef;
	CK_RV		rv = CKR_OK;
	ulong_t offset = 0;
	uint64_t tmp_val;

	/* prevent bigint_attr_cleanup from freeing invalid attr value */
	(void) memset(&modulus, 0x0, sizeof (biginteger_t));
	(void) memset(&pubexpo, 0x0, sizeof (biginteger_t));
	(void) memset(&prime, 0x0, sizeof (biginteger_t));
	(void) memset(&subprime, 0x0, sizeof (biginteger_t));
	(void) memset(&base, 0x0, sizeof (biginteger_t));
	(void) memset(&value, 0x0, sizeof (biginteger_t));

	(void) memset(&priexpo, 0x0, sizeof (biginteger_t));
	(void) memset(&prime1, 0x0, sizeof (biginteger_t));
	(void) memset(&prime2, 0x0, sizeof (biginteger_t));
	(void) memset(&expo1, 0x0, sizeof (biginteger_t));
	(void) memset(&expo2, 0x0, sizeof (biginteger_t));
	(void) memset(&coef, 0x0, sizeof (biginteger_t));

	switch (class) {

	case CKO_PUBLIC_KEY:
		/* Allocate storage for Public Key Object. */
		pbk = calloc(1, sizeof (public_key_obj_t));
		if (pbk == NULL) {
			rv =  CKR_HOST_MEMORY;
			return (rv);
		}

		objp->object_class_u.public_key = pbk;

		switch (keytype) {
		case CKK_RSA:			/* modulus_bits */
			(void) memcpy(&tmp_val, buf, sizeof (uint64_t));
			KEY_PUB_RSA_MOD_BITS(pbk) = (CK_ULONG)(SWAP64(tmp_val));
			buf = buf + sizeof (uint64_t);

			/* modulus */
			if ((rv = soft_unpack_obj_attribute(buf, &modulus,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&modulus, KEY_PUB_RSA_MOD(pbk));

			buf += ROUNDUP(offset, 8);

			/* pubexpo */
			if ((rv = soft_unpack_obj_attribute(buf, &pubexpo,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&pubexpo, KEY_PUB_RSA_PUBEXPO(pbk));

			break;

		case CKK_DSA:
			/* prime */
			if ((rv = soft_unpack_obj_attribute(buf, &prime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&prime, KEY_PUB_DSA_PRIME(pbk));

			buf += ROUNDUP(offset, 8);

			/* subprime */
			if ((rv = soft_unpack_obj_attribute(buf, &subprime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&subprime, KEY_PUB_DSA_SUBPRIME(pbk));

			buf += ROUNDUP(offset, 8);

			/* base */
			if ((rv = soft_unpack_obj_attribute(buf, &base,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&base, KEY_PUB_DSA_BASE(pbk));

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&value, KEY_PUB_DSA_VALUE(pbk));

			break;

		case CKK_DH:
			/* prime */
			if ((rv = soft_unpack_obj_attribute(buf, &prime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&prime, KEY_PUB_DH_PRIME(pbk));

			buf += ROUNDUP(offset, 8);

			/* base */
			if ((rv = soft_unpack_obj_attribute(buf, &base,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&base, KEY_PUB_DH_BASE(pbk));

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&value, KEY_PUB_DH_VALUE(pbk));

			break;

		case CKK_EC:
			/* ec_point */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&value, KEY_PUB_EC_POINT(pbk));
			break;

		case CKK_X9_42_DH:
			/* prime */
			if ((rv = soft_unpack_obj_attribute(buf, &prime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&prime, KEY_PUB_DH942_PRIME(pbk));

			buf += ROUNDUP(offset, 8);

			/* base */
			if ((rv = soft_unpack_obj_attribute(buf, &base,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&base, KEY_PUB_DH942_BASE(pbk));

			buf += ROUNDUP(offset, 8);

			/* subprime */
			if ((rv = soft_unpack_obj_attribute(buf, &subprime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&subprime,
			    KEY_PUB_DH942_SUBPRIME(pbk));

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pub_cleanup;

			copy_bigint_attr(&value, KEY_PUB_DH942_VALUE(pbk));

			break;
		} /* keytype */

		break;

	case CKO_PRIVATE_KEY:
		/* Allocate storage for Private Key Object. */
		pvk = calloc(1, sizeof (private_key_obj_t));
		if (pvk == NULL) {
			rv = CKR_HOST_MEMORY;
			return (rv);
		}

		objp->object_class_u.private_key = pvk;

		switch (keytype) {
		case CKK_RSA:
			/* modulus */
			if ((rv = soft_unpack_obj_attribute(buf, &modulus,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&modulus, KEY_PRI_RSA_MOD(pvk));

			buf += ROUNDUP(offset, 8);

			/* pubexpo */
			if ((rv = soft_unpack_obj_attribute(buf, &pubexpo,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&pubexpo, KEY_PRI_RSA_PUBEXPO(pvk));

			buf += ROUNDUP(offset, 8);

			/* priexpo */
			if ((rv = soft_unpack_obj_attribute(buf, &priexpo,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&priexpo, KEY_PRI_RSA_PRIEXPO(pvk));

			buf += ROUNDUP(offset, 8);

			/* prime1 */
			if ((rv = soft_unpack_obj_attribute(buf, &prime1,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&prime1, KEY_PRI_RSA_PRIME1(pvk));

			buf += ROUNDUP(offset, 8);

			/* prime2 */
			if ((rv = soft_unpack_obj_attribute(buf, &prime2,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&prime2, KEY_PRI_RSA_PRIME2(pvk));

			buf += ROUNDUP(offset, 8);

			/* expo1 */
			if ((rv = soft_unpack_obj_attribute(buf, &expo1,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&expo1, KEY_PRI_RSA_EXPO1(pvk));

			buf += ROUNDUP(offset, 8);

			/* expo2 */
			if ((rv = soft_unpack_obj_attribute(buf, &expo2,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&expo2, KEY_PRI_RSA_EXPO2(pvk));

			buf += ROUNDUP(offset, 8);

			/* coef */
			if ((rv = soft_unpack_obj_attribute(buf, &coef,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&coef, KEY_PRI_RSA_COEF(pvk));

			break;

		case CKK_DSA:
			/* prime */
			if ((rv = soft_unpack_obj_attribute(buf, &prime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&prime, KEY_PRI_DSA_PRIME(pvk));

			buf += ROUNDUP(offset, 8);

			/* subprime */
			if ((rv = soft_unpack_obj_attribute(buf, &subprime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&subprime, KEY_PRI_DSA_SUBPRIME(pvk));

			buf += ROUNDUP(offset, 8);

			/* base */
			if ((rv = soft_unpack_obj_attribute(buf, &base,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&base, KEY_PRI_DSA_BASE(pvk));

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&value, KEY_PRI_DSA_VALUE(pvk));

			break;

		case CKK_DH:
			/* value_bits */
			(void) memcpy(&tmp_val, buf, sizeof (uint64_t));
			KEY_PRI_DH_VAL_BITS(pvk) = (CK_ULONG)(SWAP64(tmp_val));
			buf = buf + sizeof (uint64_t);

			/* prime */
			if ((rv = soft_unpack_obj_attribute(buf, &prime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&prime, KEY_PRI_DH_PRIME(pvk));

			buf += ROUNDUP(offset, 8);

			/* base */
			if ((rv = soft_unpack_obj_attribute(buf, &base,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&base, KEY_PRI_DH_BASE(pvk));

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&value, KEY_PRI_DH_VALUE(pvk));

			break;

		case CKK_EC:
			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&value, KEY_PRI_EC_VALUE(pvk));
			break;

		case CKK_X9_42_DH:
			/* prime */
			if ((rv = soft_unpack_obj_attribute(buf, &prime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&prime, KEY_PRI_DH942_PRIME(pvk));

			buf += ROUNDUP(offset, 8);

			/* base */
			if ((rv = soft_unpack_obj_attribute(buf, &base,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&base, KEY_PRI_DH942_BASE(pvk));

			buf += ROUNDUP(offset, 8);

			/* subprime */
			if ((rv = soft_unpack_obj_attribute(buf, &subprime,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&subprime, KEY_PRI_DH942_BASE(pvk));

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, &value,
			    NULL, &offset, B_FALSE)) != CKR_OK)
				goto pri_cleanup;

			copy_bigint_attr(&value, KEY_PRI_DH942_VALUE(pvk));

			break;
		} /* keytype */

		break;

	case CKO_SECRET_KEY:
		/* Allocate storage for Secret Key Object. */
		sck = calloc(1, sizeof (secret_key_obj_t));
		if (sck == NULL) {
			return (CKR_HOST_MEMORY);
		}

		objp->object_class_u.secret_key = sck;

		/* value */
		(void) memcpy((void *)&tmp_val, buf, sizeof (uint64_t));
		OBJ_SEC_VALUE_LEN(objp) = (CK_ULONG)(SWAP64(tmp_val));
		buf = buf + sizeof (uint64_t);

		if (OBJ_SEC_VALUE_LEN(objp) > 0) {
			OBJ_SEC_VALUE(objp) = malloc(OBJ_SEC_VALUE_LEN(objp));
			if (OBJ_SEC_VALUE(objp) == NULL) {
				free(sck);
				return (CKR_HOST_MEMORY);
			}
			(void) memcpy(OBJ_SEC_VALUE(objp), buf,
			    OBJ_SEC_VALUE_LEN(objp));

			buf = buf + ROUNDUP(OBJ_SEC_VALUE_LEN(objp), 8);
		}

		return (rv);

	case CKO_CERTIFICATE:
		/* Allocate storage for Certificate Object. */
		cert = calloc(1, sizeof (certificate_obj_t));
		if (cert == NULL) {
			return (CKR_HOST_MEMORY);
		}
		(void) memset((void *)cert, 0, sizeof (certificate_obj_t));

		cert->certificate_type = certtype;
		objp->object_class_u.certificate = cert;

		switch (certtype) {
		case CKC_X_509:
			/* subject */
			if ((rv = soft_unpack_obj_attribute(buf, NULL,
			    &cert->cert_type_u.x509.subject,
			    &offset, B_TRUE)) != CKR_OK) {
				free(cert);
				return (rv);
			}

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, NULL,
			    &cert->cert_type_u.x509.value,
			    &offset, B_TRUE)) != CKR_OK) {
				free(cert);
				return (rv);
			}

			break;

		case CKC_X_509_ATTR_CERT:
			/* owner */
			if ((rv = soft_unpack_obj_attribute(buf, NULL,
			    &cert->cert_type_u.x509_attr.owner,
			    &offset, B_TRUE)) != CKR_OK) {
				free(cert);
				return (rv);
			}

			buf += ROUNDUP(offset, 8);

			/* value */
			if ((rv = soft_unpack_obj_attribute(buf, NULL,
			    &cert->cert_type_u.x509_attr.value,
			    &offset, B_TRUE)) != CKR_OK) {
				free(cert);
				return (rv);
			}

			break;
		}

		return (rv);

	case CKO_DOMAIN_PARAMETERS:

		break;
	}

pub_cleanup:
	/*
	 * cleanup the storage allocated to the local variables.
	 */
	if (rv != CKR_OK)
		free(pbk);
	bigint_attr_cleanup(&modulus);
	bigint_attr_cleanup(&pubexpo);
	bigint_attr_cleanup(&prime);
	bigint_attr_cleanup(&subprime);
	bigint_attr_cleanup(&base);
	bigint_attr_cleanup(&value);
	return (rv);

pri_cleanup:
	/*
	 * cleanup the storage allocated to the local variables.
	 */
	if (rv != CKR_OK)
		free(pvk);
	bigint_attr_cleanup(&modulus);
	bigint_attr_cleanup(&priexpo);
	bigint_attr_cleanup(&prime);
	bigint_attr_cleanup(&subprime);
	bigint_attr_cleanup(&base);
	bigint_attr_cleanup(&value);
	bigint_attr_cleanup(&pubexpo);
	bigint_attr_cleanup(&prime1);
	bigint_attr_cleanup(&prime2);
	bigint_attr_cleanup(&expo1);
	bigint_attr_cleanup(&expo2);
	bigint_attr_cleanup(&coef);
	return (rv);
}


/*
 * Store the token object to a keystore file.
 */
CK_RV
soft_put_object_to_keystore(soft_object_t *objp)
{

	uchar_t *buf;
	size_t len;
	CK_RV rv;

	rv = soft_keystore_pack_obj(objp, &buf, &len);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&soft_slot.slot_mutex);
	if (soft_keystore_put_new_obj(buf, len,
	    !!(objp->object_type == TOKEN_PUBLIC), B_FALSE,
	    &objp->ks_handle) == -1) {
		rv = CKR_FUNCTION_FAILED;
	}
	(void) pthread_mutex_unlock(&soft_slot.slot_mutex);

	freezero(buf, len);
	return (rv);
}

/*
 * Modify the in-core token object and then write it to
 * a keystore file.
 */
CK_RV
soft_modify_object_to_keystore(soft_object_t *objp)
{

	uchar_t *buf;
	size_t len;
	CK_RV rv;

	rv = soft_keystore_pack_obj(objp, &buf, &len);
	if (rv != CKR_OK)
		return (rv);

	/* B_TRUE: caller has held a writelock on the keystore */
	if (soft_keystore_modify_obj(&objp->ks_handle, buf, len,
	    B_TRUE) < 0) {
		rv = CKR_FUNCTION_FAILED;
	}

	freezero(buf, len);
	return (rv);

}

/*
 * Read the token object from the keystore file.
 */
CK_RV
soft_get_token_objects_from_keystore(ks_search_type_t type)
{
	CK_RV rv;
	ks_obj_t	*ks_obj = NULL, *ks_obj_next;
	soft_object_t *new_objp = NULL;

	/* Load the token object from keystore based on the object type */
	rv = soft_keystore_get_objs(type, &ks_obj, B_FALSE);
	if (rv != CKR_OK) {
		return (rv);
	}

	while (ks_obj) {

		new_objp = calloc(1, sizeof (soft_object_t));
		if (new_objp == NULL) {
			rv = CKR_HOST_MEMORY;
			goto cleanup;
		}
		/* Convert the keystore format to memory format */
		rv = soft_keystore_unpack_obj(new_objp, ks_obj);
		if (rv != CKR_OK) {
			if (new_objp->class == CKO_CERTIFICATE)
				soft_cleanup_cert_object(new_objp);
			else
				soft_cleanup_object(new_objp);
			goto cleanup;
		}

		soft_add_token_object_to_slot(new_objp);

		/* Free the ks_obj list */
		ks_obj_next = ks_obj->next;
		freezero(ks_obj->buf, ks_obj->size);
		free(ks_obj);
		ks_obj = ks_obj_next;
	}

	return (CKR_OK);

cleanup:
	while (ks_obj) {
		ks_obj_next = ks_obj->next;
		freezero(ks_obj->buf, ks_obj->size);
		free(ks_obj);
		ks_obj = ks_obj_next;
	}
	return (rv);
}

/*
 * soft_gen_crypt_key()
 *
 * Arguments:
 *
 *	pPIN:	pointer to caller provided Pin
 *	key:	output argument which contains the address of the
 *		pointer to encryption key in the soft_object_t.
 *		It is caller's responsibility to call soft_delete_object()
 *		if this key is no longer in use.
 *	saltdata: input argument (if non-NULL), or
 *		  output argument (if NULL):
 *		  address of pointer to the "salt" of the encryption key
 *
 * Description:
 *
 *	Generate an encryption key of the input PIN.
 *
 * Returns:
 *
 *	CKR_OK: no error
 *	Other: some error occurred while generating the encryption key
 *
 */
CK_RV
soft_gen_crypt_key(uchar_t *pPIN, soft_object_t **key, CK_BYTE **saltdata)
{
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_ATTRIBUTE tmpl[5];
	int attrs = 0;
	CK_RV rv;
	CK_MECHANISM Mechanism;
	CK_PKCS5_PBKD2_PARAMS params;
	CK_BYTE		salt[PBKD2_SALT_SIZE];
	CK_ULONG	keylen = AES_MIN_KEY_BYTES;
	CK_KEY_TYPE keytype = CKK_AES;
	static CK_BBOOL truevalue = TRUE;
	soft_object_t *secret_key;
	CK_OBJECT_HANDLE hKey;
	CK_ULONG	passwd_size;

	if (pPIN == NULL)
		return (CKR_FUNCTION_FAILED);

	tmpl[attrs].type = CKA_CLASS;
	tmpl[attrs].pValue = &class;
	tmpl[attrs].ulValueLen = sizeof (class);
	attrs++;

	tmpl[attrs].type = CKA_KEY_TYPE;
	tmpl[attrs].pValue = &keytype;
	tmpl[attrs].ulValueLen = sizeof (keytype);
	attrs++;

	tmpl[attrs].type = CKA_ENCRYPT;
	tmpl[attrs].pValue = &truevalue;
	tmpl[attrs].ulValueLen = sizeof (CK_BBOOL);
	attrs++;

	tmpl[attrs].type = CKA_DECRYPT;
	tmpl[attrs].pValue = &truevalue;
	tmpl[attrs].ulValueLen = sizeof (CK_BBOOL);
	attrs++;

	tmpl[attrs].type = CKA_VALUE_LEN;
	tmpl[attrs].pValue = &keylen;
	tmpl[attrs].ulValueLen = sizeof (keylen);
	attrs++;

	if (*saltdata == NULL) {
		bzero(salt, sizeof (salt));
		(void) pkcs11_get_nzero_urandom(salt, sizeof (salt));
		*saltdata = malloc(PBKD2_SALT_SIZE);
		if (*saltdata == NULL)
			return (CKR_HOST_MEMORY);
		(void) memcpy(*saltdata, salt, PBKD2_SALT_SIZE);
	} else {
		bzero(salt, sizeof (salt));
		(void) memcpy(salt, *saltdata, PBKD2_SALT_SIZE);
	}

	Mechanism.mechanism = CKM_PKCS5_PBKD2;
	Mechanism.pParameter = &params;
	Mechanism.ulParameterLen = sizeof (params);
	passwd_size = (CK_ULONG)strlen((const char *)pPIN);

	params.saltSource = CKZ_SALT_SPECIFIED;
	params.pSaltSourceData = (void *)salt;
	params.ulSaltSourceDataLen = sizeof (salt);
	params.iterations = PBKD2_ITERATIONS;
	params.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
	params.pPrfData = NULL;
	params.ulPrfDataLen = 0;
	params.pPassword = (CK_UTF8CHAR_PTR)pPIN;
	params.ulPasswordLen = &passwd_size;

	rv = soft_gen_keyobject(tmpl, attrs, &hKey, &token_session,
	    CKO_SECRET_KEY, CKK_AES, 0, SOFT_GEN_KEY, B_TRUE);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Obtain the secret object pointer. */
	secret_key = (soft_object_t *)hKey;
	keylen = OBJ_SEC_VALUE_LEN(secret_key);
	if ((OBJ_SEC_VALUE(secret_key) = malloc(keylen)) == NULL) {
		soft_delete_object(&token_session, secret_key,
		    B_FALSE, B_FALSE);
		return (CKR_HOST_MEMORY);
	}

	rv = soft_generate_pkcs5_pbkdf2_key(&token_session, &Mechanism,
	    secret_key);

	if (rv != CKR_OK)
		soft_delete_object(&token_session, secret_key,
		    B_FALSE, B_FALSE);
	else
		*key = secret_key;

	return (rv);

}

/*
 * soft_gen_hmac_key()
 *
 * Arguments:
 *
 *	pPIN:	pointer to caller provided Pin
 *	key:	output argument which contains the address of the
 *		pointer to hmac key in the soft_object_t.
 *		It is caller's responsibility to call soft_delete_object()
 *		if this key is no longer in use.
 *	saltdata: input argument (if non-NULL), or
 *                output argument (if NULL):
 *                address of pointer to the "salt" of the hmac key
 *
 * Description:
 *
 *	Generate a hmac key of the input PIN.
 *
 * Returns:
 *
 *	CKR_OK: no error
 *	Other: some error occurred while generating the hmac key
 *
 */
CK_RV
soft_gen_hmac_key(uchar_t *pPIN, soft_object_t **key, CK_BYTE **saltdata)
{
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_ATTRIBUTE tmpl[5];
	int attrs = 0;
	CK_RV rv;
	CK_MECHANISM Mechanism;
	CK_PKCS5_PBKD2_PARAMS params;
	CK_BYTE		salt[PBKD2_SALT_SIZE];
	CK_ULONG	keylen = 16;
	CK_KEY_TYPE keytype = CKK_GENERIC_SECRET;
	static CK_BBOOL truevalue = TRUE;
	soft_object_t *secret_key;
	CK_OBJECT_HANDLE hKey;
	CK_ULONG	passwd_size;

	if (pPIN == NULL)
		return (CKR_FUNCTION_FAILED);

	tmpl[attrs].type = CKA_CLASS;
	tmpl[attrs].pValue = &class;
	tmpl[attrs].ulValueLen = sizeof (class);
	attrs++;

	tmpl[attrs].type = CKA_KEY_TYPE;
	tmpl[attrs].pValue = &keytype;
	tmpl[attrs].ulValueLen = sizeof (keytype);
	attrs++;

	tmpl[attrs].type = CKA_SIGN;
	tmpl[attrs].pValue = &truevalue;
	tmpl[attrs].ulValueLen = sizeof (CK_BBOOL);
	attrs++;

	tmpl[attrs].type = CKA_VERIFY;
	tmpl[attrs].pValue = &truevalue;
	tmpl[attrs].ulValueLen = sizeof (CK_BBOOL);
	attrs++;

	tmpl[attrs].type = CKA_VALUE_LEN;
	tmpl[attrs].pValue = &keylen;
	tmpl[attrs].ulValueLen = sizeof (keylen);
	attrs++;

	if (*saltdata == NULL) {
		bzero(salt, sizeof (salt));
		(void) pkcs11_get_nzero_urandom(salt, sizeof (salt));
		*saltdata = malloc(PBKD2_SALT_SIZE);
		if (*saltdata == NULL)
			return (CKR_HOST_MEMORY);
		(void) memcpy(*saltdata, salt, PBKD2_SALT_SIZE);
	} else {
		bzero(salt, sizeof (salt));
		(void) memcpy(salt, *saltdata, PBKD2_SALT_SIZE);
	}

	Mechanism.mechanism = CKM_PKCS5_PBKD2;
	Mechanism.pParameter = &params;
	Mechanism.ulParameterLen = sizeof (params);
	passwd_size = (CK_ULONG)strlen((const char *)pPIN);

	params.saltSource = CKZ_SALT_SPECIFIED;
	params.pSaltSourceData = (void *)salt;
	params.ulSaltSourceDataLen = sizeof (salt);
	params.iterations = PBKD2_ITERATIONS;
	params.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
	params.pPrfData = NULL;
	params.ulPrfDataLen = 0;
	params.pPassword = (CK_UTF8CHAR_PTR)pPIN;
	params.ulPasswordLen = &passwd_size;

	rv = soft_gen_keyobject(tmpl, attrs, &hKey, &token_session,
	    CKO_SECRET_KEY, CKK_GENERIC_SECRET, 0, SOFT_GEN_KEY, B_TRUE);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Obtain the secret object pointer. */
	secret_key = (soft_object_t *)hKey;
	keylen = OBJ_SEC_VALUE_LEN(secret_key);
	if ((OBJ_SEC_VALUE(secret_key) = malloc(keylen)) == NULL) {
		soft_delete_object(&token_session, secret_key,
		    B_FALSE, B_FALSE);
		return (CKR_HOST_MEMORY);
	}

	rv = soft_generate_pkcs5_pbkdf2_key(&token_session, &Mechanism,
	    secret_key);

	if (rv != CKR_OK)
		soft_delete_object(&token_session, secret_key,
		    B_FALSE, B_FALSE);
	else
		*key = secret_key;

	return (rv);

}

/*
 * The token session is just a psuedo session (a place holder)
 * to hold some information during encryption/decryption and
 * sign/verify operations when writing/reading the keystore
 * token object.
 */
CK_RV
soft_init_token_session(void)
{


	token_session.magic_marker = SOFTTOKEN_SESSION_MAGIC;
	token_session.pApplication = NULL_PTR;
	token_session.Notify = NULL;
	token_session.flags = CKF_SERIAL_SESSION;
	token_session.state = CKS_RO_PUBLIC_SESSION;
	token_session.object_list = NULL;
	token_session.ses_refcnt = 0;
	token_session.ses_close_sync = 0;
	token_session.next = NULL;
	token_session.prev = NULL;

	/* Initialize the lock for the token session */
	if (pthread_mutex_init(&token_session.session_mutex, NULL) != 0) {
		return (CKR_CANT_LOCK);
	}

	(void) pthread_cond_init(&token_session.ses_free_cond, NULL);

	return (CKR_OK);

}

void
soft_destroy_token_session(void)
{

	(void) pthread_cond_destroy(&token_session.ses_free_cond);
	(void) pthread_mutex_destroy(&token_session.session_mutex);

}

/*
 * Encrypt/Decrypt the private token object when dealing with the keystore.
 * This function only applies to the private token object.
 */
CK_RV
soft_keystore_crypt(soft_object_t *key_p, uchar_t *ivec, boolean_t encrypt,
    CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG_PTR out_len)
{
	CK_MECHANISM	mech;
	soft_aes_ctx_t *soft_aes_ctx;
	CK_RV rv;
	CK_ULONG tmplen, tmplen1;

	/*
	 * The caller will pass NULL for "out" (output buffer) to find out
	 * the output buffer size that it need to allocate for the encrption
	 * or decryption.
	 */
	if (out == NULL) {
		mech.mechanism = CKM_AES_CBC_PAD;
		mech.pParameter = (void *)ivec;
		mech.ulParameterLen = AES_BLOCK_LEN;

		if (encrypt)
			rv = soft_aes_crypt_init_common(&token_session, &mech,
			    key_p, B_TRUE);
		else
			rv = soft_aes_crypt_init_common(&token_session, &mech,
			    key_p, B_FALSE);

		if (rv != CKR_OK)
			return (rv);


		(void) pthread_mutex_lock(&token_session.session_mutex);

		if (encrypt)
			soft_aes_ctx =
			    (soft_aes_ctx_t *)token_session.encrypt.context;
		else
			soft_aes_ctx =
			    (soft_aes_ctx_t *)token_session.decrypt.context;

		/* Copy Initialization Vector (IV) into the context. */
		(void) memcpy(soft_aes_ctx->ivec, ivec, AES_BLOCK_LEN);

		/* Allocate a context for AES cipher-block chaining. */
		soft_aes_ctx->aes_cbc = (void *)aes_cbc_ctx_init(
		    soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len,
		    soft_aes_ctx->ivec);

		if (soft_aes_ctx->aes_cbc == NULL) {
			freezero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			if (encrypt) {
				free(token_session.encrypt.context);
				token_session.encrypt.context = NULL;
			} else {
				free(token_session.encrypt.context);
				token_session.encrypt.context = NULL;
			}

			(void) pthread_mutex_unlock(&token_session.
			    session_mutex);
			return (CKR_HOST_MEMORY);
		}

		(void) pthread_mutex_unlock(&token_session.session_mutex);
		/*
		 * Since out == NULL, the soft_aes_xxcrypt_common() will
		 * simply return the output buffer length to the caller.
		 */
		if (encrypt) {
			rv = soft_aes_encrypt_common(&token_session, in,
			    in_len, out, out_len, B_FALSE);
		} else {
			rv = soft_aes_decrypt_common(&token_session, in,
			    in_len, out, out_len, B_FALSE);
		}

	} else {
		/*
		 * The caller has allocated the output buffer, so that we
		 * are doing the real encryption/decryption this time.
		 */
		tmplen = *out_len;
		if (encrypt) {
			rv = soft_aes_encrypt_common(&token_session, in,
			    in_len, out, &tmplen, B_TRUE);
			if (rv == CKR_OK) {
				tmplen1 = *out_len - tmplen;
				rv = soft_encrypt_final(&token_session,
				    out+tmplen, &tmplen1);
				*out_len = tmplen + tmplen1;
			}
		} else {
			rv = soft_aes_decrypt_common(&token_session, in,
			    in_len, out, &tmplen, B_TRUE);
			if (rv == CKR_OK) {
				tmplen1 = *out_len - tmplen;
				rv = soft_decrypt_final(&token_session,
				    out+tmplen, &tmplen1);
				*out_len = tmplen + tmplen1;
			}
		}
	}

	return (rv);

}

/*
 * Sign/Verify the private token object for checking its data integrity
 * when dealing with the keystore.
 * This function only applies to the private token object.
 */
CK_RV
soft_keystore_hmac(soft_object_t *key_p, boolean_t sign,
    CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG_PTR out_len)
{
	CK_MECHANISM mech;
	CK_RV rv;

	mech.mechanism = CKM_MD5_HMAC;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	rv = soft_hmac_sign_verify_init_common(&token_session, &mech,
	    key_p, sign);

	if (rv != CKR_OK)
		return (rv);

	if (sign) {
		rv = soft_sign(&token_session, in, in_len, out, out_len);
	} else {
		rv = soft_verify(&token_session, in, in_len, out, *out_len);
	}

	return (rv);
}
