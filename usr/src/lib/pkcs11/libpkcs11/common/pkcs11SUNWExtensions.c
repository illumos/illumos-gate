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

/*
 * Solaris specific functions to reduce the initialization
 * overhead of using PKCS #11
 */

#include <stdlib.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <assert.h>
#include <cryptoutil.h>
#include <pkcs11Global.h>

static CK_OBJECT_CLASS objclass = CKO_SECRET_KEY;
static CK_BBOOL falsevalue = FALSE;
static CK_BBOOL truevalue = TRUE;

#define	NUM_SECRETKEY_ATTRS	12

typedef struct _ATTRTYPE_MECHINFO_MAPPING {
	CK_ATTRIBUTE_TYPE attr;
	CK_FLAGS	flag;
} ATTRTYPE_MECHINFO_MAPPING;

/* possible attribute types for creating key */
ATTRTYPE_MECHINFO_MAPPING mapping[] = {
	{CKA_ENCRYPT, CKF_ENCRYPT},
	{CKA_DECRYPT, CKF_DECRYPT},
	{CKA_SIGN, CKF_SIGN},
	{CKA_VERIFY, CKF_VERIFY},
	{CKA_WRAP, CKF_WRAP},
	{CKA_UNWRAP, CKF_UNWRAP}
};


/*
 * List of mechanisms that only supports asymmetric key operations
 * in PKCS #11 V2.11
 */
CK_MECHANISM_TYPE asymmetric_mechs[] = {
	CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_RSA_9796, CKM_RSA_X_509,
	CKM_RSA_PKCS_OAEP, CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31,
	CKM_RSA_PKCS_PSS, CKM_DSA_KEY_PAIR_GEN, CKM_DSA, CKM_DSA_SHA1,
	CKM_DSA_PARAMETER_GEN, CKM_ECDSA_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
	CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDH1_DERIVE,
	CKM_ECDH1_COFACTOR_DERIVE, CKM_ECMQV_DERIVE
};


typedef struct _KEY_TYPE_SIZE_MAPPING {
	CK_KEY_TYPE type;
	CK_ULONG len;
} KEY_TYPE_SIZE_MAPPING;

/*
 * List of secret key types that have fixed sizes and their sizes.
 * These key types do not allow CKA_VALUE_LEN for key generation.
 * The sizes are in bytes.
 *
 * Discrete-sized keys, such as AES and Twofish, and variable sized
 * keys, such as Blowfish, are not in this list.
 */
KEY_TYPE_SIZE_MAPPING fixed_size_secrets[] = {
	{CKK_DES, 8}, {CKK_DES2, 16}, {CKK_DES3, 24}, {CKK_IDEA, 16},
	{CKK_CDMF, 8}, {CKK_SKIPJACK, 12}, {CKK_BATON, 40}, {CKK_JUNIPER, 40}
};

/*
 * match_mech is an example of many possible criteria functions.
 * It matches the given mech type (in args) with the slot's mech info.
 * If no match is found, pkcs11_GetCriteriaSession is asked to return
 * CKR_MECHANISM_INVALID.
 */
boolean_t
match_mech(CK_SLOT_ID slot_id, void *args, CK_RV *rv)
{
	CK_MECHANISM_INFO mech_info;
	CK_MECHANISM_TYPE mech = (CK_MECHANISM_TYPE)args;

	*rv = CKR_MECHANISM_INVALID;
	return (C_GetMechanismInfo(slot_id, mech, &mech_info) == CKR_OK);
}

/*
 * pkcs11_GetCriteriaSession will initialize the framework and do all
 * the necessary work of calling C_GetSlotList(), C_GetMechanismInfo()
 * C_OpenSession() to create a session that meets all the criteria in
 * the given function pointer.
 *
 * The criteria function must return a boolean value of true or false.
 * The arguments to the function are the current slot id, an opaque
 * args value that is passed through to the function, and the error
 * value pkcs11_GetCriteriaSession should return if no slot id meets the
 * criteria.
 *
 * If the function is called multiple times, it will return a new session
 * without reinitializing the framework.
 */
CK_RV
pkcs11_GetCriteriaSession(
    boolean_t (*criteria)(CK_SLOT_ID slot_id, void *args, CK_RV *rv),
    void *args, CK_SESSION_HANDLE_PTR hSession)
{
	CK_RV rv;
	CK_ULONG slotcount;
	CK_SLOT_ID_PTR slot_list;
	CK_SLOT_ID slot_id;
	CK_ULONG i;

	if (hSession == NULL || criteria == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* initialize PKCS #11 */
	if (!pkcs11_initialized) {
		rv = C_Initialize(NULL);
		if ((rv != CKR_OK) &&
		    (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			return (rv);
		}
	}

	/* get slot count */
	rv = C_GetSlotList(0, NULL, &slotcount);
	if (rv != CKR_OK) {
		return (rv);
	}

	if (slotcount == 0) {
		return (CKR_FUNCTION_FAILED);
	}


	/* allocate memory for slot list */
	slot_list = malloc(slotcount * sizeof (CK_SLOT_ID));
	if (slot_list == NULL) {
		return (CKR_HOST_MEMORY);
	}

	if ((rv = C_GetSlotList(0, slot_list, &slotcount)) != CKR_OK) {
		free(slot_list);
		return (rv);
	}

	/* find slot with matching criteria */
	for (i = 0; i < slotcount; i++) {
		slot_id = slot_list[i];
		if ((*criteria)(slot_id, args, &rv)) {
			break;
		}
	}

	if (i == slotcount) {
		/* no matching slot found */
		free(slot_list);
		return (rv);	/* this rv is from the criteria function */
	}

	rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL,
	    NULL, hSession);

	free(slot_list);
	return (rv);
}

/*
 * SUNW_C_GetMechSession will initialize the framework and do all
 * of the neccessary work of calling C_GetSlotList(), C_GetMechanismInfo()
 * C_OpenSession() to create a session capable of providing the requested
 * mechanism.
 *
 * If the function is called multiple times, it will return a new session
 * without reinitializing the framework.
 */
CK_RV
SUNW_C_GetMechSession(CK_MECHANISM_TYPE mech, CK_SESSION_HANDLE_PTR hSession)
{
	/*
	 * All the code in this function can be replaced with one line:
	 *
	 * return (pkcs11_GetCriteriaSession(match_mech, (void *)mech,
	 *	hSession));
	 *
	 */
	CK_RV rv;
	CK_ULONG slotcount;
	CK_SLOT_ID_PTR slot_list;
	CK_SLOT_ID slot_id;
	CK_MECHANISM_INFO mech_info;
	CK_ULONG i;

	if (hSession == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* initialize PKCS #11 */
	if (!pkcs11_initialized) {
		rv = C_Initialize(NULL);
		if ((rv != CKR_OK) &&
		    (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			return (rv);
		}
	}

	/* get slot count */
	rv = C_GetSlotList(0, NULL, &slotcount);
	if (rv != CKR_OK) {
		return (rv);
	}

	if (slotcount == 0) {
		return (CKR_FUNCTION_FAILED);
	}


	/* allocate memory for slot list */
	slot_list = malloc(slotcount * sizeof (CK_SLOT_ID));
	if (slot_list == NULL) {
		return (CKR_HOST_MEMORY);
	}

	if ((rv = C_GetSlotList(0, slot_list, &slotcount)) != CKR_OK) {
		free(slot_list);
		return (rv);
	}

	/* find slot with matching mechanism */
	for (i = 0; i < slotcount; i++) {
		slot_id = slot_list[i];
		if (C_GetMechanismInfo(slot_id, mech, &mech_info) == CKR_OK) {
			/* found mechanism */
			break;
		}
	}

	if (i == slotcount) {
		/* no matching mechanism found */
		free(slot_list);
		return (CKR_MECHANISM_INVALID);
	}

	rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL,
	    NULL, hSession);

	free(slot_list);
	return (rv);
}

/*
 * SUNW_C_KeyToObject creates a secret key object for the given
 * mechanism from the rawkey data.
 */
CK_RV
SUNW_C_KeyToObject(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mech,
    const void *rawkey, size_t rawkey_len, CK_OBJECT_HANDLE_PTR obj)
{

	CK_RV rv;
	CK_SESSION_INFO session_info;
	CK_SLOT_ID slot_id;
	CK_MECHANISM_INFO mech_info;
	CK_ULONG i, j;
	CK_KEY_TYPE keytype;
	CK_ULONG num_asym_mechs, num_mapping;

	/* template for creating generic secret key object */
	CK_ATTRIBUTE template[NUM_SECRETKEY_ATTRS];

	if ((hSession == CK_INVALID_HANDLE) || (obj == NULL) ||
	    (rawkey == NULL) || (rawkey_len == 0)) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Check to make sure mechanism type is not for asymmetric key
	 * only operations.  This function is only applicable to
	 * generating secret key.
	 */
	num_asym_mechs = sizeof (asymmetric_mechs) / sizeof (CK_MECHANISM_TYPE);
	for (i = 0; i < num_asym_mechs; i++) {
		if (mech == asymmetric_mechs[i]) {
			return (CKR_MECHANISM_INVALID);
		}
	}

	rv = C_GetSessionInfo(hSession, &session_info);
	if (rv != CKR_OK) {
		return (rv);
	}

	slot_id = session_info.slotID;

	i = 0;
	template[i].type = CKA_CLASS;
	template[i].pValue = &objclass;
	template[i].ulValueLen = sizeof (objclass);
	i++;

	/* get the key type for this mechanism */
	if ((rv = pkcs11_mech2keytype(mech, &keytype)) != CKR_OK) {
		return (rv);
	}

	assert(i < NUM_SECRETKEY_ATTRS);
	template[i].type = CKA_KEY_TYPE;
	template[i].pValue = &keytype;
	template[i].ulValueLen = sizeof (keytype);
	i++;

	rv = C_GetMechanismInfo(slot_id, mech, &mech_info);
	if (rv != CKR_OK) {
		return (rv);
	}

	/* set the attribute type flag on object based on mechanism */
	num_mapping = sizeof (mapping) / sizeof (ATTRTYPE_MECHINFO_MAPPING);
	for (j = 0; j < num_mapping; j++) {
		assert(i < NUM_SECRETKEY_ATTRS);
		template[i].type = mapping[j].attr;
		template[i].ulValueLen = sizeof (falsevalue);
		if (mech_info.flags & ((mapping[j]).flag)) {
			template[i].pValue = &truevalue;
		} else {
			template[i].pValue = &falsevalue;
		}
		i++;
	}

	assert(i < NUM_SECRETKEY_ATTRS);
	template[i].type = CKA_TOKEN;
	template[i].pValue = &falsevalue;
	template[i].ulValueLen = sizeof (falsevalue);
	i++;

	assert(i < NUM_SECRETKEY_ATTRS);
	template[i].type = CKA_VALUE;
	template[i].pValue = (CK_VOID_PTR)rawkey;
	template[i].ulValueLen = (CK_ULONG)rawkey_len;
	i++;

	rv = C_CreateObject(hSession, template, i, obj);
	return (rv);
}


/*
 * pkcs11_PasswdToPBKD2Object will create a secret key from the given string
 * (e.g. passphrase) using PKCS#5 Password-Based Key Derivation Function 2
 * (PBKD2).
 *
 * Session must be open.  Salt and iterations use defaults.
 */
CK_RV
pkcs11_PasswdToPBKD2Object(CK_SESSION_HANDLE hSession, char *passphrase,
    size_t passphrase_len, void *salt, size_t salt_len, CK_ULONG iterations,
    CK_KEY_TYPE key_type, CK_ULONG key_len, CK_FLAGS key_flags,
    CK_OBJECT_HANDLE_PTR obj)
{
	CK_RV rv;
	CK_PKCS5_PBKD2_PARAMS params;
	CK_MECHANISM mechanism;
	CK_KEY_TYPE asym_key_type;
	CK_ULONG i, j, num_asym_mechs, num_fixed_secs, num_mapping;
	CK_ATTRIBUTE template[NUM_SECRETKEY_ATTRS];

	if (hSession == CK_INVALID_HANDLE || obj == NULL ||
	    passphrase == NULL || passphrase_len == 0 ||
	    iterations == 0UL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Check to make sure key type is not asymmetric.  This function
	 * is only applicable to generating secret key.
	 */
	num_asym_mechs = sizeof (asymmetric_mechs) / sizeof (CK_MECHANISM_TYPE);
	for (i = 0; i < num_asym_mechs; i++) {
		rv = pkcs11_mech2keytype(asymmetric_mechs[i], &asym_key_type);
		assert(rv == CKR_OK);
		if (key_type == asym_key_type) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}
	}

	/*
	 * Key length must either be 0 or the correct size for PBKD of
	 * fixed-size secret keys.  However, underlying key generation
	 * cannot have CKA_VALUE_LEN set for the key length attribute.
	 */
	num_fixed_secs =
	    sizeof (fixed_size_secrets) / sizeof (KEY_TYPE_SIZE_MAPPING);
	for (i = 0; i < num_fixed_secs; i++) {
		if (key_type == fixed_size_secrets[i].type) {
			if (key_len == fixed_size_secrets[i].len) {
				key_len = 0;
			}
			if (key_len == 0) {
				break;
			}
			return (CKR_KEY_SIZE_RANGE);
		}
	}

	if (salt == NULL || salt_len == 0) {
		params.saltSource = 0;
		params.pSaltSourceData = NULL;
		params.ulSaltSourceDataLen = 0;
	} else {
		params.saltSource = CKZ_SALT_SPECIFIED;
		params.pSaltSourceData = salt;
		params.ulSaltSourceDataLen = salt_len;
	}
	params.iterations = iterations;
	params.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
	params.pPrfData = NULL;
	params.ulPrfDataLen = 0;
	params.pPassword = (CK_UTF8CHAR_PTR)passphrase;
	params.ulPasswordLen = (CK_ULONG_PTR)&passphrase_len;
	/*
	 * PKCS#11 spec error, ulPasswordLen should have been pulPasswordLen,
	 * or its type should have been CK_ULONG instead of CK_ULONG_PTR,
	 * but it's legacy now
	 */

	mechanism.mechanism = CKM_PKCS5_PBKD2;
	mechanism.pParameter = &params;
	mechanism.ulParameterLen = sizeof (params);

	i = 0;
	template[i].type = CKA_CLASS;
	template[i].pValue = &objclass;
	template[i].ulValueLen = sizeof (objclass);
	i++;

	assert(i < NUM_SECRETKEY_ATTRS);
	template[i].type = CKA_KEY_TYPE;
	template[i].pValue = &key_type;
	template[i].ulValueLen = sizeof (key_type);
	i++;

	assert(i < NUM_SECRETKEY_ATTRS);
	template[i].type = CKA_TOKEN;
	template[i].pValue = &falsevalue;
	template[i].ulValueLen = sizeof (falsevalue);
	i++;

	if (key_len != 0) {
		assert(i < NUM_SECRETKEY_ATTRS);
		template[i].type = CKA_VALUE_LEN;
		template[i].pValue = &key_len;
		template[i].ulValueLen = sizeof (key_len);
		i++;
	}

	/*
	 * C_GenerateKey may not implicitly set capability attributes,
	 * e.g. CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, ...
	 */
	num_mapping = sizeof (mapping) / sizeof (ATTRTYPE_MECHINFO_MAPPING);
	for (j = 0; j < num_mapping; j++) {
		assert(i < NUM_SECRETKEY_ATTRS);
		template[i].type = mapping[j].attr;
		template[i].pValue = (key_flags & ((mapping[j]).flag)) ?
		    &truevalue : &falsevalue;
		template[i].ulValueLen = sizeof (falsevalue);
		i++;
	}

	rv = C_GenerateKey(hSession, &mechanism, template, i, obj);
	return (rv);
}

/*
 * pkcs11_ObjectToKey gets the rawkey data from a secret key object.
 * The caller is responsible to free the allocated rawkey data.
 *
 * Optionally the object can be destroyed after the value is retrieved.
 * As an example, after using pkcs11_PasswdToPBKD2Object() to create a
 * secret key object from a passphrase, an app may call pkcs11_ObjectToKey
 * to get the rawkey data.  The intermediate object may no longer be needed
 * and should be destroyed.
 */
CK_RV
pkcs11_ObjectToKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE obj,
    void **rawkey, size_t *rawkey_len, boolean_t destroy_obj)
{
	CK_RV rv;
	CK_ATTRIBUTE template;

	if (hSession == CK_INVALID_HANDLE)
		return (CKR_SESSION_HANDLE_INVALID);
	if (obj == 0)
		return (CKR_OBJECT_HANDLE_INVALID);
	if (rawkey == NULL || rawkey_len == NULL)
		return (CKR_ARGUMENTS_BAD);

	template.type = CKA_VALUE;
	template.pValue = NULL;
	template.ulValueLen = 0;

	/* First get the size of the rawkey */
	rv = C_GetAttributeValue(hSession, obj, &template, 1);
	if (rv != CKR_OK) {
		return (rv);
	}

	template.pValue = malloc(template.ulValueLen);
	if (template.pValue == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/* Then get the rawkey data */
	rv = C_GetAttributeValue(hSession, obj, &template, 1);
	if (rv != CKR_OK) {
		free(template.pValue);
		return (rv);
	}

	if (destroy_obj) {
		/*
		 * Could have asserted rv == CKR_OK, making threaded
		 * apps that share objects see stars.  Here mercy is ok.
		 */
		(void) C_DestroyObject(hSession, obj);
	}

	*rawkey = template.pValue;
	*rawkey_len = template.ulValueLen;

	return (CKR_OK);
}

/*
 * pkcs11_PasswdToKey will create PKCS#5 PBKD2 rawkey data from the
 * given passphrase.  The caller is responsible to free the allocated
 * rawkey data.
 */
CK_RV
pkcs11_PasswdToKey(CK_SESSION_HANDLE hSession, char *passphrase,
    size_t passphrase_len, void *salt, size_t salt_len, CK_KEY_TYPE key_type,
    CK_ULONG key_len, void **rawkey, size_t *rawkey_len)
{
	CK_RV rv;
	CK_OBJECT_HANDLE obj;

	rv = pkcs11_PasswdToPBKD2Object(hSession, passphrase, passphrase_len,
	    salt, salt_len, CK_PKCS5_PBKD2_ITERATIONS, key_type, key_len, 0,
	    &obj);
	if (rv != CKR_OK)
		return (rv);
	rv = pkcs11_ObjectToKey(hSession, obj, rawkey, rawkey_len, B_TRUE);
	return (rv);
}
