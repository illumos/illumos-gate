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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Key Management Functions
 * (as defined in PKCS#11 spec section 11.14)
 */

#include "metaGlobal.h"


/*
 * meta_GenerateKey
 *
 */
CK_RV
meta_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *key = NULL;

	if (pMechanism == NULL || phKey == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);


	rv = meta_object_alloc(session, &key);
	if (rv != CKR_OK)
		goto finish;

	rv = meta_generate_keys(session, pMechanism, pTemplate, ulCount, key,
	    NULL, 0, NULL);
	if (rv != CKR_OK)
		goto finish;

	meta_object_activate(key);

	*phKey = (CK_OBJECT_HANDLE) key;

finish:
	if (rv != CKR_OK) {
		if (key)
			(void) meta_object_dealloc(session, key, B_TRUE);
	}

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_GenerateKeyPair
 *
 */
CK_RV
meta_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *key1 = NULL, *key2 = NULL;

	if (pMechanism == NULL || phPublicKey == NULL || phPrivateKey == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);


	rv = meta_object_alloc(session, &key1);
	if (rv != CKR_OK)
		goto finish;

	rv = meta_object_alloc(session, &key2);
	if (rv != CKR_OK)
		goto finish;

	rv = meta_generate_keys(session, pMechanism,
	    pPublicKeyTemplate, ulPublicKeyAttributeCount, key1,
	    pPrivateKeyTemplate, ulPrivateKeyAttributeCount, key2);
	if (rv != CKR_OK)
		goto finish;

	meta_object_activate(key1);
	meta_object_activate(key2);

	*phPublicKey = (CK_OBJECT_HANDLE) key1;
	*phPrivateKey = (CK_OBJECT_HANDLE) key2;

finish:
	if (rv != CKR_OK) {
		if (key1)
			(void) meta_object_dealloc(session, key1, B_TRUE);
		if (key2)
			(void) meta_object_dealloc(session, key2, B_TRUE);
	}

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_WrapKey
 *
 */
CK_RV
meta_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *wrappingKey, *inputKey;

	if (pMechanism == NULL || pulWrappedKeyLen == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hKey, &inputKey);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_handle2object(hWrappingKey, &wrappingKey);
	if (rv != CKR_OK) {
		OBJRELEASE(inputKey);
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_wrap_key(session, pMechanism, wrappingKey,
	    inputKey, pWrappedKey, pulWrappedKeyLen);

	OBJRELEASE(inputKey);
	OBJRELEASE(wrappingKey);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_UnwrapKey
 *
 */
CK_RV
meta_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *unwrappingKey, *outputKey = NULL;

	if (pMechanism == NULL || pWrappedKey == NULL || phKey == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hUnwrappingKey, &unwrappingKey);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_object_alloc(session, &outputKey);
	if (rv != CKR_OK)
		goto finish;

	(void) get_template_boolean(CKA_TOKEN, pTemplate, ulAttributeCount,
	    &(outputKey->isToken));

	rv = meta_unwrap_key(session, pMechanism, unwrappingKey,
	    pWrappedKey, ulWrappedKeyLen,
	    pTemplate, ulAttributeCount, outputKey);
	if (rv != CKR_OK)
		goto finish;

	meta_object_activate(outputKey);

	*phKey = (CK_OBJECT_HANDLE) outputKey;

finish:
	if (rv != CKR_OK) {
		if (outputKey)
			(void) meta_object_dealloc(session, outputKey, B_TRUE);
	}

	OBJRELEASE(unwrappingKey);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DeriveKey
 *
 * This function is a bit gross because of PKCS#11 kludges that pass extra
 * object handles in some mechanism parameters. It probably needs to be
 * broken up into more managable pieces.
 */
CK_RV
meta_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	CK_MECHANISM *pMech = pMechanism;
	meta_session_t *session;
	meta_object_t *basekey1 = NULL, *basekey2 = NULL;
	meta_object_t *newKey1 = NULL, *newKey2 = NULL, *newKey3 = NULL,
	    *newKey4 = NULL;
	boolean_t ssl_keys = B_FALSE;
	boolean_t tlsprf = B_FALSE;

	CK_MECHANISM metaMech;
	CK_OBJECT_HANDLE *phBaseKey2 = NULL;
	CK_X9_42_DH2_DERIVE_PARAMS x942_params, *x9_tmpptr;
	CK_ECDH2_DERIVE_PARAMS ecdh_params, *ec_tmpptr;
	CK_SSL3_KEY_MAT_OUT *ssl_key_mat;
	CK_SSL3_KEY_MAT_PARAMS *keyparams;

	if (pMech == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Special case: Normally, the caller must always provide storage
	 * for the derived key handle at phKey. Two (related) mechanisms
	 * are special, in that multiple keys are instead returned via
	 * pMech->pParameter. In these cases the spec says (see 12.38.4
	 * and 12.39.4) that phKey should be a NULL pointer, as it is not used.
	 */
	switch (pMech->mechanism) {
	case CKM_SSL3_KEY_AND_MAC_DERIVE:
	case CKM_TLS_KEY_AND_MAC_DERIVE:
		keyparams = (CK_SSL3_KEY_MAT_PARAMS*)pMech->pParameter;

		if ((keyparams == NULL) || (pMech->ulParameterLen
		    != sizeof (CK_SSL3_KEY_MAT_PARAMS)))
			return (CKR_ARGUMENTS_BAD);

		ssl_key_mat = keyparams->pReturnedKeyMaterial;
		if (ssl_key_mat == NULL)
			return (CKR_ARGUMENTS_BAD);

		ssl_keys = B_TRUE;
		break;

	case CKM_TLS_PRF:
		tlsprf = B_TRUE;
		break;

	default:
		if (phKey == NULL)
			return (CKR_ARGUMENTS_BAD);
	};

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hBaseKey, &basekey1);
	if (rv != CKR_OK)
		goto finish;


	/*
	 * A few oddball mechanisms pass a 2nd object handle in the parameters.
	 * Here we validate that handle, and create a duplicate copy of the
	 * mechanism and parameters. This is done because the application
	 * does not expect these values to be changing, and could be using the
	 * same data in multiple threads (eg concurrent calls to C_DeriveKey).
	 * We copy the data to make sure there are no MT-Safe problems.
	 */
	switch (pMech->mechanism) {

	case CKM_ECMQV_DERIVE:
		/* uses CK_ECDH2_DERIVE_PARAMS struct as the parameter */

		if ((pMech->pParameter == NULL) || (pMech->ulParameterLen
		    != sizeof (CK_ECDH2_DERIVE_PARAMS))) {
			rv = CKR_ARGUMENTS_BAD;
			goto finish;
		}

		/* Duplicate the mechanism and paramaters */
		ec_tmpptr = (CK_ECDH2_DERIVE_PARAMS *)pMech->pParameter;
		ecdh_params = *ec_tmpptr;
		metaMech = *pMech;
		metaMech.pParameter = &ecdh_params;
		pMech = &metaMech;

		/* Get the key the application is providing */
		phBaseKey2 = &ecdh_params.hPrivateData;
		break;

	case CKM_X9_42_DH_HYBRID_DERIVE:
	case CKM_X9_42_MQV_DERIVE:
		/* both use CK_X9_42_DH2_DERIVE_PARAMS as the parameter */

		if ((pMech->pParameter == NULL) || (pMech->ulParameterLen
		    != sizeof (CK_X9_42_DH2_DERIVE_PARAMS))) {
			rv = CKR_ARGUMENTS_BAD;
			goto finish;
		}

		/* Duplicate the mechanism and paramaters */
		x9_tmpptr = (CK_X9_42_DH2_DERIVE_PARAMS *)pMech->pParameter;
		x942_params = *x9_tmpptr;
		metaMech = *pMech;
		metaMech.pParameter  = &x942_params;
		pMech = &metaMech;

		/* Get the key the application is providing */
		phBaseKey2 = &x942_params.hPrivateData;
		break;

	case CKM_CONCATENATE_BASE_AND_KEY:
		/* uses a CK_OBJECT_HANDLE as the parameter */

		if ((pMech->pParameter == NULL) || (pMech->ulParameterLen
		    != sizeof (CK_OBJECT_HANDLE))) {
			rv = CKR_ARGUMENTS_BAD;
			goto finish;
		}

		/* Duplicate the mechanism and paramaters */
		metaMech = *pMech;
		pMech = &metaMech;

		/* Get the key the application is providing */
		phBaseKey2 = (CK_OBJECT_HANDLE *) &metaMech.pParameter;
		break;

	default:
		/* nothing special to do. */
		break;
	}

	if (phBaseKey2) {
		rv = meta_handle2object(*phBaseKey2, &basekey2);
		if (rv != CKR_OK)
			goto finish;
	}

	/*
	 * Allocate meta objects to store the derived key(s). Normally just
	 * a single key is created, but the SSL/TLS mechanisms generate four.
	 */
	rv = meta_object_alloc(session, &newKey1);
	if (rv != CKR_OK)
		goto finish;

	if (ssl_keys) {
		rv = meta_object_alloc(session, &newKey2);
		if (rv != CKR_OK)
			goto finish;
		rv = meta_object_alloc(session, &newKey3);
		if (rv != CKR_OK)
			goto finish;
		rv = meta_object_alloc(session, &newKey4);
		if (rv != CKR_OK)
			goto finish;
	}


	/* Perform the actual key derive operation. */
	rv = meta_derive_key(session, pMech, basekey1, basekey2, phBaseKey2,
	    pTemplate, ulAttributeCount, newKey1, newKey2, newKey3, newKey4);
	if (rv != CKR_OK)
		goto finish;

	if (tlsprf) {
		(void) meta_object_dealloc(session, newKey1, B_TRUE);
		newKey1 = NULL;
		/* phKey isn't used (is NULL) for mechanism CKM_TLS_PRF. */

	} else {
		/* Make derived key(s) active and visible to other threads. */
		meta_object_activate(newKey1);
		if (ssl_keys) {
			meta_object_activate(newKey2);
			meta_object_activate(newKey3);
			meta_object_activate(newKey4);

			ssl_key_mat->hClientMacSecret
			    = (CK_OBJECT_HANDLE) newKey1;
			ssl_key_mat->hServerMacSecret
			    = (CK_OBJECT_HANDLE) newKey2;
			ssl_key_mat->hClientKey = (CK_OBJECT_HANDLE) newKey3;
			ssl_key_mat->hServerKey = (CK_OBJECT_HANDLE) newKey4;
			/* phKey isn't used (is NULL) for these SSL/TLS mechs */

		} else {
			*phKey = (CK_OBJECT_HANDLE) newKey1;
		}
	}

finish:
	if (rv != CKR_OK) {
		if (newKey1)
			(void) meta_object_dealloc(session, newKey1, B_TRUE);
		if (newKey2)
			(void) meta_object_dealloc(session, newKey2, B_TRUE);
		if (newKey3)
			(void) meta_object_dealloc(session, newKey3, B_TRUE);
		if (newKey4)
			(void) meta_object_dealloc(session, newKey4, B_TRUE);
	}

	if (basekey1)
		OBJRELEASE(basekey1);
	if (basekey2)
		OBJRELEASE(basekey2);
	REFRELEASE(session);

	return (rv);
}
