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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <errno.h>
#include <security/cryptoki.h>
#include <sys/crypto/ioctl.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelObject.h"

static boolean_t
is_secret_key_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount)
{
	int i;
	for (i = 0; i < ulAttributeCount; i++) {
		if (pTemplate[i].type == CKA_CLASS &&
		    *(CK_OBJECT_CLASS *)(pTemplate[i].pValue) ==
		    CKO_SECRET_KEY)
			return (B_TRUE);
	}
	return (B_FALSE);
}


CK_RV
C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV			rv = CKR_OK;
	kernel_session_t	*session_p;
	kernel_object_t		*new_objp = NULL;
	kernel_slot_t		*pslot;
	boolean_t		ses_lock_held = B_FALSE;
	CK_BBOOL		is_pri_obj;
	CK_BBOOL		is_token_obj = FALSE;
	crypto_mech_type_t	k_mech_type;
	crypto_object_generate_key_t 	obj_gk;
	int r;

	if (!kernel_initialized)
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

	/* Get the kernel's internal mechanism number. */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Create an object wrapper in the library first */
	new_objp = calloc(1, sizeof (kernel_object_t));
	if (new_objp == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	/* Process the attributes */
	rv = process_object_attributes(pTemplate, ulCount,
	    &obj_gk.gk_attributes, &is_token_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Cannot create a token object with a READ-ONLY session. */
	if (is_token_obj && session_p->ses_RO) {
		free_object_attributes(obj_gk.gk_attributes, ulCount);
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/* Call the CRYPTO_GENERATE_KEY ioctl */
	obj_gk.gk_session = session_p->k_session;
	obj_gk.gk_count = ulCount;
	obj_gk.gk_mechanism.cm_type = k_mech_type;
	obj_gk.gk_mechanism.cm_param = pMechanism->pParameter;
	obj_gk.gk_mechanism.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_GENERATE_KEY, &obj_gk)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_gk.gk_return_value);
	}

	free_object_attributes(obj_gk.gk_attributes, ulCount);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Get the value of the CKA_PRIVATE attribute. */
	rv = get_cka_private_value(session_p, obj_gk.gk_handle, &is_pri_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/*
	 * Store the kernel object handle in the object wrapper and
	 * initialize the library object.
	 */
	new_objp->k_handle = obj_gk.gk_handle;
	new_objp->is_lib_obj = B_FALSE;
	new_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_objp->extra_attrlistp = NULL;

	if (is_pri_obj)
		new_objp->bool_attr_mask |= PRIVATE_BOOL_ON;
	else
		new_objp->bool_attr_mask &= ~PRIVATE_BOOL_ON;

	if (is_token_obj)
		new_objp->bool_attr_mask |= TOKEN_BOOL_ON;
	else
		new_objp->bool_attr_mask &= ~TOKEN_BOOL_ON;

	(void) pthread_mutex_init(&new_objp->object_mutex, NULL);
	new_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;

	/*
	 * Add the new object to the slot's token object list if it is a
	 * a token object. Otherwise, add it to the session's object list.
	 */
	if (is_token_obj) {
		pslot = slot_table[session_p->ses_slotid];
		kernel_add_token_object_to_slot(new_objp, pslot);
	} else {
		kernel_add_object_to_session(new_objp, session_p);
	}

	*phKey = (CK_OBJECT_HANDLE)new_objp;
	REFRELE(session_p, ses_lock_held);
	return (rv);

failed_exit:
	if (new_objp != NULL) {
		(void) free(new_objp);
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV			rv = CKR_OK;
	kernel_session_t	*session_p;
	kernel_object_t		*new_pub_objp = NULL;
	kernel_object_t		*new_pri_objp = NULL;
	kernel_slot_t		*pslot;
	boolean_t		ses_lock_held = B_FALSE;
	CK_BBOOL		is_pri_obj1;
	CK_BBOOL		is_pri_obj2;
	CK_BBOOL		is_token_obj1 = FALSE;
	CK_BBOOL		is_token_obj2 = FALSE;
	crypto_mech_type_t	k_mech_type;
	crypto_object_generate_key_pair_t 	obj_kp;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pMechanism == NULL) || (phPublicKey == NULL) ||
	    (phPrivateKey == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto failed_exit;
	}

	if ((pPublicKeyTemplate == NULL) && (ulPublicKeyAttributeCount != 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto failed_exit;
	}

	if ((pPrivateKeyTemplate == NULL) &&
	    (ulPrivateKeyAttributeCount != 0)) {
		rv = CKR_ARGUMENTS_BAD;
		goto failed_exit;
	}

	/* Get the kernel's internal mechanism number. */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Create an object wrapper for the public key */
	new_pub_objp = calloc(1, sizeof (kernel_object_t));
	if (new_pub_objp == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	/* Create an object wrapper for the private key. */
	new_pri_objp = calloc(1, sizeof (kernel_object_t));
	if (new_pri_objp == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	/* Process the public key attributes. */
	rv = process_object_attributes(pPublicKeyTemplate,
	    ulPublicKeyAttributeCount, &obj_kp.kp_public_attributes,
	    &is_token_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Cannot create a token object with a READ-ONLY session. */
	if (is_token_obj1 && session_p->ses_RO) {
		free_object_attributes(obj_kp.kp_public_attributes,
		    ulPublicKeyAttributeCount);
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/* Process the private key attributes. */
	rv = process_object_attributes(pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount, &obj_kp.kp_private_attributes,
	    &is_token_obj2);
	if (rv != CKR_OK) {
		free_object_attributes(obj_kp.kp_public_attributes,
		    ulPublicKeyAttributeCount);
		goto failed_exit;
	}

	/*
	 * The public key and the private key need to contain the same
	 * attribute values for CKA_TOKEN.
	 */
	if (is_token_obj1 != is_token_obj2) {
		free_object_attributes(obj_kp.kp_public_attributes,
		    ulPublicKeyAttributeCount);
		free_object_attributes(obj_kp.kp_private_attributes,
		    ulPrivateKeyAttributeCount);
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto failed_exit;
	}

	/* Call the CRYPTO_GENERATE_KEY_PAIR ioctl. */
	obj_kp.kp_session = session_p-> k_session;
	obj_kp.kp_mechanism.cm_type = k_mech_type;
	obj_kp.kp_mechanism.cm_param = pMechanism->pParameter;
	obj_kp.kp_mechanism.cm_param_len = pMechanism->ulParameterLen;
	obj_kp.kp_public_count = ulPublicKeyAttributeCount;
	obj_kp.kp_private_count = ulPrivateKeyAttributeCount;

	while ((r = ioctl(kernel_fd, CRYPTO_GENERATE_KEY_PAIR, &obj_kp)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_kp.kp_return_value);
	}

	free_object_attributes(obj_kp.kp_public_attributes,
	    ulPublicKeyAttributeCount);
	free_object_attributes(obj_kp.kp_private_attributes,
	    ulPrivateKeyAttributeCount);

	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Get the CKA_PRIVATE value for the key pair. */
	rv = get_cka_private_value(session_p, obj_kp.kp_public_handle,
	    &is_pri_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	rv = get_cka_private_value(session_p, obj_kp.kp_private_handle,
	    &is_pri_obj2);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/*
	 * Store the kernel public key handle into the public key object and
	 * finish the public key object initialization.
	 */
	new_pub_objp->is_lib_obj = B_FALSE;
	new_pub_objp->k_handle = obj_kp.kp_public_handle;
	new_pub_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_pub_objp->extra_attrlistp = NULL;

	if (is_pri_obj1)
		new_pub_objp->bool_attr_mask |= PRIVATE_BOOL_ON;
	else
		new_pub_objp->bool_attr_mask &= ~PRIVATE_BOOL_ON;

	if (is_token_obj1)
		new_pub_objp->bool_attr_mask |= TOKEN_BOOL_ON;
	else
		new_pub_objp->bool_attr_mask &= ~TOKEN_BOOL_ON;

	(void) pthread_mutex_init(&new_pub_objp->object_mutex, NULL);
	new_pub_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;

	/*
	 * Store the kernel private key handle into the private key object
	 * and finish the private key object initialization.
	 */
	new_pri_objp->is_lib_obj = B_FALSE;
	new_pri_objp->k_handle = obj_kp.kp_private_handle;
	new_pri_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_pri_objp->extra_attrlistp = NULL;

	if (is_pri_obj2)
		new_pri_objp->bool_attr_mask |= PRIVATE_BOOL_ON;
	else
		new_pri_objp->bool_attr_mask &= ~PRIVATE_BOOL_ON;

	if (is_token_obj2)
		new_pri_objp->bool_attr_mask |= TOKEN_BOOL_ON;
	else
		new_pri_objp->bool_attr_mask &= ~TOKEN_BOOL_ON;

	(void) pthread_mutex_init(&new_pri_objp->object_mutex, NULL);
	new_pri_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;

	/*
	 * Add the new pub/pri objects to the slot's token list if they are
	 * token objects. Otherwise, add them to the session's object list.
	 */
	if (is_token_obj1) { /* is_token_obj1 == is_token_obj2 */
		pslot = slot_table[session_p->ses_slotid];
		kernel_add_token_object_to_slot(new_pub_objp, pslot);
		kernel_add_token_object_to_slot(new_pri_objp, pslot);
	} else {
		kernel_add_object_to_session(new_pub_objp, session_p);
		kernel_add_object_to_session(new_pri_objp, session_p);
	}

	*phPublicKey = (CK_OBJECT_HANDLE)new_pub_objp;
	*phPrivateKey = (CK_OBJECT_HANDLE)new_pri_objp;
	REFRELE(session_p, ses_lock_held);
	return (rv);

failed_exit:
	if (new_pub_objp != NULL) {
		(void) free(new_pub_objp);
	}

	if (new_pri_objp != NULL) {
		(void) free(new_pri_objp);
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV			rv = CKR_OK;
	kernel_session_t	*session_p;
	boolean_t		ses_lock_held = B_FALSE;
	kernel_object_t		*wrappingkey_p;
	kernel_object_t		*key_p;
	crypto_mech_type_t	k_mech_type;
	crypto_object_wrap_key_t obj_wrapkey;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pulWrappedKeyLen == NULL || pMechanism == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Obtain the session pointer.  Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Get the kernel's internal mechanism number. */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Obtain the wrapping key object pointer. */
	HANDLE2OBJECT(hWrappingKey, wrappingkey_p, rv);
	if (rv != CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Obtain the to_be_wrapped key object pointer. */
	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv != CKR_OK) {
		OBJ_REFRELE(wrappingkey_p);
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Make the CRYPTO_OBJECT_WRAP_KEY ioctl call. */
	obj_wrapkey.wk_session = session_p->k_session;
	obj_wrapkey.wk_mechanism.cm_type = k_mech_type;
	obj_wrapkey.wk_mechanism.cm_param = pMechanism->pParameter;
	obj_wrapkey.wk_mechanism.cm_param_len = pMechanism->ulParameterLen;
	obj_wrapkey.wk_wrapping_key.ck_format = CRYPTO_KEY_REFERENCE;
	obj_wrapkey.wk_wrapping_key.ck_obj_id = wrappingkey_p->k_handle;
	obj_wrapkey.wk_object_handle = key_p->k_handle;
	obj_wrapkey.wk_wrapped_key_len = *pulWrappedKeyLen;
	obj_wrapkey.wk_wrapped_key = (char *)pWrappedKey;

	while ((r = ioctl(kernel_fd, CRYPTO_WRAP_KEY, &obj_wrapkey)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_wrapkey.wk_return_value);
	}

	/*
	 * Besides rv == CKR_OK, we will set the value of pulWrappedKeyLen
	 * when the applciation-supplied wrapped key buffer is too small.
	 * The situation that the application only asks for the length of
	 * the wrapped key is covered in rv == CKR_OK.
	 */
	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) {
		*pulWrappedKeyLen = obj_wrapkey.wk_wrapped_key_len;
	}

	OBJ_REFRELE(key_p);
	OBJ_REFRELE(wrappingkey_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV			rv = CKR_OK;
	kernel_session_t	*session_p;
	kernel_object_t		*unwrappingkey_p;
	kernel_object_t		*new_objp = NULL;
	kernel_slot_t		*pslot;
	boolean_t		ses_lock_held = B_FALSE;
	CK_BBOOL		is_pri_obj;
	CK_BBOOL		is_token_obj = FALSE;
	CK_MECHANISM_INFO	info;
	uint32_t		k_mi_flags;
	CK_BYTE			*clear_key_val = NULL;
	CK_ULONG 		ulDataLen;
	CK_ATTRIBUTE_PTR	newTemplate = NULL;
	CK_ULONG		templ_size;
	crypto_mech_type_t	k_mech_type;
	crypto_object_unwrap_key_t obj_unwrapkey;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pMechanism == NULL || pWrappedKey == NULL || phKey == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	if ((pTemplate == NULL) && (ulAttributeCount != 0)) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the wrapping key object pointer. */
	HANDLE2OBJECT(hUnwrappingKey, unwrappingkey_p, rv);
	if (rv != CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/*
	 * If the HW provider doesn't support C_UnwrapKey, we will try
	 * to emulate it in the library.
	 */
	pslot = slot_table[session_p->ses_slotid];
	if ((pslot->sl_func_list.fl_object_create == B_FALSE) &&
	    (pslot->sl_func_list.fl_key_unwrap == B_FALSE)) {
		rv = get_mechanism_info(pslot, pMechanism->mechanism, &info,
		    &k_mi_flags);
		if (rv != CKR_OK) {
			goto failed_exit;
		}

		/*
		 * If the mechanism flag doesn't have CKF_UNWRAP, and it's
		 * an unwrapping of a secret key object, then help this
		 * out with a decryption followed by an object creation.
		 */
		if (!(k_mi_flags & CRYPTO_FG_UNWRAP) &&
		    (k_mi_flags & CRYPTO_FG_DECRYPT) &&
		    (is_secret_key_template(pTemplate, ulAttributeCount))) {

			/* First allocate space for the recovered key value */
			clear_key_val = malloc(ulWrappedKeyLen);
			if (clear_key_val == NULL) {
				rv = CKR_HOST_MEMORY;
				goto failed_exit;
			}

			rv = kernel_decrypt_init(session_p, unwrappingkey_p,
			    pMechanism);
			if (rv != CKR_OK) {
				goto failed_exit;
			}

			ulDataLen = ulWrappedKeyLen;
			rv = kernel_decrypt(session_p, pWrappedKey,
			    ulWrappedKeyLen, clear_key_val, &ulDataLen);
			if (rv != CKR_OK) {
				goto failed_exit;
			}

			/* Now add the CKA_VALUE attribute to template */
			templ_size = ulAttributeCount * sizeof (CK_ATTRIBUTE);
			newTemplate = malloc(templ_size +
			    sizeof (CK_ATTRIBUTE));
			if (newTemplate == NULL) {
				rv = CKR_HOST_MEMORY;
				goto failed_exit;
			}

			bcopy(pTemplate, newTemplate, templ_size);
			newTemplate[ulAttributeCount].type = CKA_VALUE;
			newTemplate[ulAttributeCount].pValue = clear_key_val;
			newTemplate[ulAttributeCount].ulValueLen = ulDataLen;

			/* Finally create the key, based on the new template */
			rv = kernel_add_object(newTemplate,
			    ulAttributeCount + 1, phKey, session_p);
			(void) free(clear_key_val);
			(void) free(newTemplate);
			OBJ_REFRELE(unwrappingkey_p);
			REFRELE(session_p, ses_lock_held);
			return (rv);
		} else {
			rv = CKR_FUNCTION_FAILED;
			goto failed_exit;
		}
	}

	/*
	 * If we come here, the HW provider must have registered the unwrapkey
	 * entry.  Therefore, the unwrap key will be performed in the HW
	 * provider.
	 */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Create an object wrapper for the new key in the library first */
	new_objp = calloc(1, sizeof (kernel_object_t));
	if (new_objp == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	/* Process the attributes */
	rv = process_object_attributes(pTemplate, ulAttributeCount,
	    &obj_unwrapkey.uk_attributes, &is_token_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Cannot create a token object with a READ-ONLY session. */
	if (is_token_obj && session_p->ses_RO) {
		free_object_attributes(obj_unwrapkey.uk_attributes,
		    ulAttributeCount);
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/* Make the CRYPTO_UNWRAP_KEY ioctl call. */
	obj_unwrapkey.uk_session = session_p->k_session;
	obj_unwrapkey.uk_mechanism.cm_type = k_mech_type;
	obj_unwrapkey.uk_mechanism.cm_param = pMechanism->pParameter;
	obj_unwrapkey.uk_mechanism.cm_param_len = pMechanism->ulParameterLen;
	obj_unwrapkey.uk_unwrapping_key.ck_format = CRYPTO_KEY_REFERENCE;
	obj_unwrapkey.uk_unwrapping_key.ck_obj_id = unwrappingkey_p->k_handle;
	obj_unwrapkey.uk_wrapped_key = (char *)pWrappedKey;
	obj_unwrapkey.uk_wrapped_key_len = ulWrappedKeyLen;
	obj_unwrapkey.uk_count = ulAttributeCount;

	while ((r = ioctl(kernel_fd, CRYPTO_UNWRAP_KEY, &obj_unwrapkey)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_unwrapkey.uk_return_value);
	}

	free_object_attributes(obj_unwrapkey.uk_attributes, ulAttributeCount);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Get the CKA_PRIVATE value for the unwrapped key. */
	rv = get_cka_private_value(session_p, obj_unwrapkey.uk_object_handle,
	    &is_pri_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/*
	 * Store the kernel object handle in the new key object wrapper and
	 * initialize it.
	 */
	new_objp->k_handle = obj_unwrapkey.uk_object_handle;
	new_objp->is_lib_obj = B_FALSE;
	new_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_objp->extra_attrlistp = NULL;

	if (is_pri_obj)
		new_objp->bool_attr_mask |= PRIVATE_BOOL_ON;
	else
		new_objp->bool_attr_mask &= ~PRIVATE_BOOL_ON;

	if (is_token_obj)
		new_objp->bool_attr_mask |= TOKEN_BOOL_ON;
	else
		new_objp->bool_attr_mask &= ~TOKEN_BOOL_ON;

	(void) pthread_mutex_init(&new_objp->object_mutex, NULL);
	new_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;

	/*
	 * Add the new object to the slot's token object list if it is a
	 * a token object. Otherwise, add it to the session's object list.
	 */
	if (is_token_obj) {
		pslot = slot_table[session_p->ses_slotid];
		kernel_add_token_object_to_slot(new_objp, pslot);
	} else {
		kernel_add_object_to_session(new_objp, session_p);
	}

	*phKey = (CK_OBJECT_HANDLE)new_objp;
	OBJ_REFRELE(unwrappingkey_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);

failed_exit:
	OBJ_REFRELE(unwrappingkey_p);
	if (new_objp != NULL)
		(void) free(new_objp);

	if (clear_key_val != NULL)
		(void) free(clear_key_val);

	if (newTemplate != NULL)
		(void) free(newTemplate);

	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV			rv = CKR_OK;
	kernel_session_t	*session_p;
	kernel_object_t		*basekey_p;
	kernel_object_t		*new_objp;
	kernel_slot_t		*pslot;
	boolean_t		ses_lock_held = B_FALSE;
	CK_BBOOL		is_pri_obj;
	CK_BBOOL		is_token_obj = FALSE;
	crypto_mech_type_t	k_mech_type;
	crypto_derive_key_t	obj_dk;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	if ((pTemplate == NULL && ulAttributeCount != 0) ||
	    (pTemplate != NULL && ulAttributeCount == 0)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	/* Obtain the base key object pointer. */
	HANDLE2OBJECT(hBaseKey, basekey_p, rv);
	if (rv != CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Get the kernel's internal mechanism number. */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Create an object wrapper in the library for the generated key. */
	new_objp = calloc(1, sizeof (kernel_object_t));
	if (new_objp == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	/* Process the attributes */
	rv = process_object_attributes(pTemplate, ulAttributeCount,
	    &obj_dk.dk_attributes, &is_token_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Cannot create a token object with a READ-ONLY session. */
	if (is_token_obj && session_p->ses_RO) {
		free_object_attributes(obj_dk.dk_attributes, ulAttributeCount);
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/* Call the CRYPTO_DERIVE_KEY ioctl */
	obj_dk.dk_session = session_p->k_session;
	obj_dk.dk_mechanism.cm_type = k_mech_type;
	obj_dk.dk_mechanism.cm_param = pMechanism->pParameter;
	obj_dk.dk_mechanism.cm_param_len = pMechanism->ulParameterLen;
	obj_dk.dk_base_key.ck_format = CRYPTO_KEY_REFERENCE;
	obj_dk.dk_base_key.ck_obj_id = basekey_p->k_handle;
	obj_dk.dk_count = ulAttributeCount;

	while ((r = ioctl(kernel_fd, CRYPTO_DERIVE_KEY, &obj_dk)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_dk.dk_return_value);
	}

	free_object_attributes(obj_dk.dk_attributes, ulAttributeCount);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Get the CKA_PRIVATE value for the derived key. */
	rv = get_cka_private_value(session_p, obj_dk.dk_object_handle,
	    &is_pri_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/*
	 * Store the kernel object handle into the new derived key object
	 * and finish the object initialization.
	 */
	new_objp->is_lib_obj = B_FALSE;
	new_objp->k_handle = obj_dk.dk_object_handle;
	new_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_objp->extra_attrlistp = NULL;

	if (is_pri_obj)
		new_objp->bool_attr_mask |= PRIVATE_BOOL_ON;
	else
		new_objp->bool_attr_mask &= ~PRIVATE_BOOL_ON;

	if (is_token_obj)
		new_objp->bool_attr_mask |= TOKEN_BOOL_ON;
	else
		new_objp->bool_attr_mask &= ~TOKEN_BOOL_ON;

	(void) pthread_mutex_init(&new_objp->object_mutex, NULL);
	new_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;

	/*
	 * Add the new derived object to the slot's token list if it is a
	 * token object. Otherwise, add it to the session's object list.
	 */
	if (is_token_obj) {
		pslot = slot_table[session_p->ses_slotid];
		kernel_add_token_object_to_slot(new_objp, pslot);
	} else {
		kernel_add_object_to_session(new_objp, session_p);
	}

	*phKey = (CK_OBJECT_HANDLE)new_objp;
	OBJ_REFRELE(basekey_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);

failed_exit:
	OBJ_REFRELE(basekey_p);
	if (new_objp != NULL) {
		(void) free(new_objp);
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}
