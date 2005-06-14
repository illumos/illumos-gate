/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Solaris specific functions to reduce the initialization
 * overhead of using PKCS #11
 */

#include <stdlib.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <assert.h>
#include <cryptoutil.h>

static CK_OBJECT_CLASS objclass = CKO_SECRET_KEY;
static CK_BBOOL falsevalue = FALSE;
static CK_BBOOL truevalue = TRUE;

#define	NUM_SECRETKEY_ATTRS	8

typedef struct _ATTRTYPE_MECHINFO_MAPPING {
	CK_ATTRIBUTE_TYPE attr;
	CK_FLAGS	flag;
} ATTRTYPE_MECHINFO_MAPPING;

/* possible attribute types for creating key */
ATTRTYPE_MECHINFO_MAPPING mapping[] = {
	{CKA_ENCRYPT, CKF_ENCRYPT},
	{CKA_DECRYPT, CKF_DECRYPT},
	{CKA_SIGN, CKF_SIGN},
	{CKA_VERIFY, CKF_VERIFY}
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


/*
 * SUNW_C_GetMechSession will initialize the framework and do all
 * of the neccessary work of calling C_GetSlotList(), C_GetMechanismInfo()
 * C_OpenSession() to provide a session capable of providing the requested
 * mechanism.
 *
 * If the function is called multiple times, it will return a new session
 * without reinitializing the framework.
 */
CK_RV
SUNW_C_GetMechSession(CK_MECHANISM_TYPE mech, CK_SESSION_HANDLE_PTR hSession)
{
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
	rv = C_Initialize(NULL);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
		return (rv);
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

	if ((hSession == NULL) || (obj == NULL) ||
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

	/* set the attribute type flag on object based on mechanism */
	rv = C_GetSessionInfo(hSession, &session_info);
	if (rv != CKR_OK) {
		goto cleanup;
	}

	slot_id = session_info.slotID;

	/* create a generic object first */
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
		goto cleanup;
	}

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
	if (rv != CKR_OK) {
		return (rv);
	}

	return (rv);

cleanup:
	/* This cleanup is only for failure cases */
	(void) C_DestroyObject(hSession, *obj);
	return (rv);
}
