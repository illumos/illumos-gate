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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <strings.h>
#include <errno.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "kmsGlobal.h"
#include "kmsSession.h"
#include "kmsObject.h"
#include "kmsKeystoreUtil.h"

static CK_RV
kms_generate_softkey(kms_object_t *keyp)
{
	if ((OBJ_SEC_VALUE(keyp) = malloc(OBJ_SEC_VALUE_LEN(keyp))) == NULL)
		return (CKR_HOST_MEMORY);

	if (pkcs11_get_urandom(OBJ_SEC_VALUE(keyp),
	    OBJ_SEC_VALUE_LEN(keyp)) < 0)
		return (CKR_DEVICE_ERROR);

	return (CKR_OK);
}

CK_RV
C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV			rv = CKR_OK;
	kms_session_t		*session_p;
	kms_object_t		*new_objp = NULL;
	kms_slot_t		*pslot;
	boolean_t		ses_lock_held = B_FALSE;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pMechanism == NULL) || (phKey == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto failed_exit;
	}

	if ((pTemplate == NULL) && (ulCount != 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto failed_exit;
	}

	switch (pMechanism->mechanism) {
		case CKM_AES_KEY_GEN:
			break;
		default:
			rv = CKR_MECHANISM_INVALID;
			goto failed_exit;
	}

	/* Create an object record */
	new_objp = kms_new_object();
	if (new_objp == NULL)
		return (CKR_HOST_MEMORY);

	new_objp->mechanism = pMechanism->mechanism;
	rv = kms_build_object(pTemplate, ulCount, new_objp);
	if (rv != CKR_OK)
		goto failed_exit;

	/*
	 * Generate the KMS key.
	 *
	 * This will put the AES key value from the KMS key into the
	 * key object record.
	 */
	if (new_objp->bool_attr_mask & TOKEN_BOOL_ON)
		rv = KMS_GenerateKey(session_p, new_objp);
	else
		rv = kms_generate_softkey(new_objp);

	if (rv != CKR_OK)
		goto failed_exit;

	if (new_objp->bool_attr_mask & TOKEN_BOOL_ON) {
		pslot = get_slotinfo();
		if (pslot == NULL) {
			rv = CKR_GENERAL_ERROR;
			goto failed_exit;
		}
		kms_add_token_object_to_slot(new_objp, pslot);
	} else {
		kms_add_object_to_session(new_objp, session_p);
	}

	*phKey = (CK_OBJECT_HANDLE)new_objp;
	REFRELE(session_p, ses_lock_held);
	return (rv);

failed_exit:
	if (new_objp != NULL)
		(void) free(new_objp);

	REFRELE(session_p, ses_lock_held);
	return (rv);
}

/*ARGSUSED*/
CK_RV
C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*ARGSUSED*/
CK_RV
C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*ARGSUSED*/
CK_RV
C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*ARGSUSED*/
CK_RV
C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}
