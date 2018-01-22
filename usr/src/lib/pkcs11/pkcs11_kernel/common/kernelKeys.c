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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018, Joyent, Inc.
 */

#include <strings.h>
#include <errno.h>
#include <ecc_impl.h>
#include <security/cryptoki.h>
#include <sys/crypto/ioctl.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelObject.h"

static boolean_t
attribute_in_template(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE_PTR t, CK_ULONG cnt)
{
	int i;

	for (i = 0; i < cnt; i++) {
		if (t[i].type == type)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * This routine returns modulus bytes rounded up to the nearest 8 byte
 * chunk. This is so we don't have to pass in max sized buffers for
 * returned attributes. Every unnecessary byte that we pass in results
 * in a kernel allocation.
 */
static ulong_t
get_modulus_bytes(CK_ATTRIBUTE_PTR t, CK_ULONG cnt)
{
	CK_ULONG modulus_len;
	int i;

	for (i = 0; i < cnt; i++) {
		if (t[i].type == CKA_MODULUS_BITS) {
			get_ulong_attr_from_template(&modulus_len, &t[i]);
			/* convert from bit length to byte length */
			modulus_len = (modulus_len - 1) / 64 + 1;
			return (modulus_len * 8);
		}
	}
	return (0);
}

/*
 * Remove specified attribute from array. Storage for the attribute's
 * value is freed if 'free_attr' is TRUE. Attributes are shifted so they are
 * contiguous within the array, i.e. the next attribute is shifted into
 * the position of the removed attribute. Returns TRUE if specified
 * attribute is removed.
 */
static boolean_t
remove_one_attribute(CK_ATTRIBUTE_PTR t, CK_ULONG type, uint_t count,
    boolean_t free_attr)
{
	int i, j;

	for (i = 0, j = 0; i < count; i++) {
		if (t[i].type == type) {
			if (free_attr) {
				free(t[i].pValue);
			}
			continue;
		}
		if (i != j) {
			t[j].type = t[i].type;
			t[j].pValue = t[i].pValue;
			t[j].ulValueLen = t[i].ulValueLen;
		}
		j++;
	}
	if (j == count)
		return (B_FALSE);

	/* safety */
	t[j].pValue = NULL;
	t[j].ulValueLen = 0;
	return (B_TRUE);
}

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

/*
 * Allocate a template with space for new_count entries and copy the
 * specified template into the new template.
 */
static CK_ATTRIBUTE_PTR
grow_template(CK_ATTRIBUTE_PTR old_template, CK_ULONG old_count,
    CK_ULONG new_count)
{
	CK_ATTRIBUTE_PTR new_template;

	new_template = malloc(new_count * sizeof (CK_ATTRIBUTE));
	if (new_template != NULL)
		bcopy(old_template, new_template,
		    old_count * sizeof (CK_ATTRIBUTE));
	return (new_template);
}

/*
 * For fixed length keys such as DES, return the length based on
 * the key type. For variable length keys such as AES, take the
 * length from the CKA_VALUE_LEN attribute.
 */
static int
get_key_len_from_template(CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    kernel_object_t *basekey_p,  ulong_t *key_len)
{
	boolean_t fixed_len_key = B_FALSE;
	ulong_t key_type;
	int i;

	for (i = 0; i < ulAttributeCount; i++) {
		if (pTemplate[i].type == CKA_KEY_TYPE) {
			get_ulong_attr_from_template(&key_type, &pTemplate[i]);
			break;
		}
	}
	/* CKA_KEY_TYPE must be present */
	if (i == ulAttributeCount)
		return (CKR_TEMPLATE_INCOMPLETE);

	switch (key_type) {
	case CKK_DES:
		*key_len = 8;
		fixed_len_key = B_TRUE;
		break;
	case CKK_DES3:
		*key_len = 24;
		fixed_len_key = B_TRUE;
		break;
	case CKK_AES:
	case CKK_BLOWFISH:
		for (i = 0; i < ulAttributeCount; i++) {
			if (pTemplate[i].type == CKA_VALUE_LEN) {
				get_ulong_attr_from_template(key_len,
				    &pTemplate[i]);
				break;
			}
		}
		/* CKA_VALUE_LEN must be present */
		if (i == ulAttributeCount)
			return (CKR_TEMPLATE_INCOMPLETE);
		break;
	case CKK_GENERIC_SECRET:
		/*
		 * The key will not be truncated, so we need to
		 * get the max length for the mechanism.
		 */
		if (pMechanism->mechanism == CKM_DH_PKCS_DERIVE) {
			CK_ATTRIBUTE tmp;

			tmp.type = CKA_PRIME;
			tmp.pValue = NULL;

			/* get size of attribute */
			if (kernel_get_attribute(basekey_p, &tmp) != CKR_OK) {
				return (CKR_ARGUMENTS_BAD);
			}
			*key_len = tmp.ulValueLen;
		} else if (pMechanism->mechanism == CKM_ECDH1_DERIVE) {
			*key_len = EC_MAX_VALUE_LEN;
		} else {
			return (CKR_ARGUMENTS_BAD);
		}
		break;
	default:
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	if (fixed_len_key && attribute_in_template(CKA_VALUE_LEN,
	    pTemplate, ulAttributeCount))
		return (CKR_TEMPLATE_INCONSISTENT);

	return (CKR_OK);
}

/* find specified attribute src template and copy to dest */
static int
copy_attribute(CK_ULONG type, CK_ATTRIBUTE_PTR src, CK_ULONG src_cnt,
    CK_ATTRIBUTE_PTR dst)
{
	int rv, i;

	for (i = 0; i < src_cnt; i++) {
		if (src[i].type == type) {
			rv = get_string_from_template(dst, &src[i]);
			break;
		}
	}
	/*
	 * The public template didn't have attribute.
	 */
	if (i == src_cnt) {
		rv = CKR_TEMPLATE_INCOMPLETE;
	}
	return (rv);
}

static void
free_attributes(caddr_t p, uint_t *countp)
{
	if (*countp > 0) {
		free_object_attributes(p, *countp);
		*countp = 0;
	}
}

CK_RV
key_gen_by_value(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, kernel_session_t *session_p,
    crypto_mech_type_t k_mech_type, kernel_object_t *new_objp)
{
	crypto_nostore_generate_key_t obj_ngk;
	char *key_buf = NULL;
	CK_ATTRIBUTE_PTR newTemplate = NULL;
	CK_BBOOL is_token_obj = FALSE;
	CK_RV rv = CKR_OK;
	ulong_t key_len = 0;
	uint_t attr_count;
	int r;

	obj_ngk.ngk_in_count = 0;
	obj_ngk.ngk_out_count = 0;

	rv = get_key_len_from_template(pMechanism, pTemplate, ulCount,
	    NULL, &key_len);
	if (rv != CRYPTO_SUCCESS)
		goto failed_exit;

	if ((key_buf = malloc(key_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	attr_count = ulCount + 1;
	newTemplate = grow_template(pTemplate, ulCount, attr_count);
	if (newTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	/* Now add the CKA_VALUE attribute to template */
	newTemplate[ulCount].type = CKA_VALUE;
	newTemplate[ulCount].pValue = (caddr_t)key_buf;
	newTemplate[ulCount].ulValueLen = key_len;

	rv = process_object_attributes(newTemplate, attr_count - 1,
	    &obj_ngk.ngk_in_attributes, &is_token_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	rv = process_object_attributes(&newTemplate[ulCount],
	    1, &obj_ngk.ngk_out_attributes, &is_token_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	/* Cannot create a token object with a READ-ONLY session. */
	if (is_token_obj && session_p->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/* Call the CRYPTO_NOSTORE_GENERATE_KEY ioctl */
	obj_ngk.ngk_session = session_p->k_session;
	obj_ngk.ngk_in_count = attr_count - 1;
	obj_ngk.ngk_out_count = 1;
	obj_ngk.ngk_mechanism.cm_type = k_mech_type;
	obj_ngk.ngk_mechanism.cm_param = pMechanism->pParameter;
	obj_ngk.ngk_mechanism.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_NOSTORE_GENERATE_KEY,
	    &obj_ngk)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_ngk.ngk_return_value);
	}
	free_attributes(obj_ngk.ngk_in_attributes, &obj_ngk.ngk_in_count);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	rv = get_object_attributes(&newTemplate[ulCount], 1,
	    obj_ngk.ngk_out_attributes);
	free_attributes(obj_ngk.ngk_out_attributes, &obj_ngk.ngk_out_count);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	/*
	 * CKA_VALUE_LEN is not stored with the secret key object,
	 * so we remove it by shifting attributes down one.
	 */
	(void) remove_one_attribute(newTemplate, CKA_VALUE_LEN,
	    attr_count, B_FALSE);

	rv = kernel_build_object(newTemplate, attr_count - 1,
	    new_objp, session_p, KERNEL_GEN_KEY);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}
	new_objp->is_lib_obj = B_TRUE;
	new_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	free(newTemplate);
	freezero(key_buf, key_len);
	return (CKR_OK);

failed_exit:
	free_attributes(obj_ngk.ngk_in_attributes, &obj_ngk.ngk_in_count);
	free_attributes(obj_ngk.ngk_out_attributes, &obj_ngk.ngk_out_count);
	freezero(key_buf, key_len);
	free(newTemplate);
	return (rv);
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

	/*
	 * Special Case: if token does not support object creation,
	 * but does support key generation by value, then create a session
	 * object and initialize with value returned by token.
	 */
	pslot = slot_table[session_p->ses_slotid];
	if (!pslot->sl_func_list.fl_object_create) {
		rv = key_gen_by_value(pMechanism, pTemplate, ulCount, session_p,
		    k_mech_type, new_objp);
		if (rv != CKR_OK)
			goto failed_exit;
	} else {
		crypto_object_generate_key_t obj_gk;

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

		while ((r = ioctl(kernel_fd, CRYPTO_GENERATE_KEY,
		    &obj_gk)) < 0) {
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
		rv = get_cka_private_value(session_p, obj_gk.gk_handle,
		    &is_pri_obj);
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
	}

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
key_gen_rsa_by_value(CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    kernel_session_t *session_p, crypto_mech_type_t k_mech_type,
    kernel_object_t *new_pub_objp, kernel_object_t *new_pri_objp)
{
	crypto_nostore_generate_key_pair_t obj_nkp;
	CK_ATTRIBUTE_PTR pubTemplate = NULL;
	CK_ATTRIBUTE_PTR priTemplate = NULL;
	CK_RV rv = CKR_OK;
	CK_BBOOL is_token_obj1 = FALSE;
	CK_BBOOL is_token_obj2 = FALSE;
	uint_t pub_attr_count, pri_attr_count;
	uint_t pub_out_attr_count = 0, pri_out_attr_count = 0;
	char public_modulus[512];
	char public_exponent[8];
	char private_exponent[512];
	char private_modulus[512];
	char prime_1[512];
	char prime_2[512];
	char exponent_1[512];
	char exponent_2[512];
	char coefficient[512];
	CK_ULONG pub_class = CKO_PUBLIC_KEY;
	CK_ULONG pri_class = CKO_PRIVATE_KEY;
	CK_ULONG key_type;
	CK_ULONG modulus_bytes;
	boolean_t has_class, has_key_type, has_pub_exponent;
	int n, r;

	obj_nkp.nkp_in_public_count = 0;
	obj_nkp.nkp_out_public_count = 0;
	obj_nkp.nkp_in_private_count = 0;
	obj_nkp.nkp_out_private_count = 0;

	/* modulus bits must be present when generating a RSA key pair */
	if (!attribute_in_template(CKA_MODULUS_BITS, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto failed_exit;
	}

	modulus_bytes = get_modulus_bytes(pPublicKeyTemplate,
	    ulPublicKeyAttributeCount);

	/*
	 * Add CKA_MODULUS to the public template.
	 * This attribute must not be in the template.
	 */
	if (attribute_in_template(CKA_MODULUS, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto failed_exit;
	}
	has_class = attribute_in_template(CKA_CLASS, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount);
	has_key_type = attribute_in_template(CKA_KEY_TYPE, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount);
	has_pub_exponent = attribute_in_template(CKA_PUBLIC_EXPONENT,
	    pPublicKeyTemplate, ulPublicKeyAttributeCount);

	pub_attr_count = ulPublicKeyAttributeCount + 1;
	if (!has_class)
		pub_attr_count++;
	if (!has_key_type)
		pub_attr_count++;
	if (!has_pub_exponent)
		pub_attr_count++;
	pubTemplate = grow_template(pPublicKeyTemplate,
	    ulPublicKeyAttributeCount, pub_attr_count);
	if (pubTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	n = ulPublicKeyAttributeCount;
	if (!has_class) {
		pubTemplate[n].type = CKA_CLASS;
		pubTemplate[n].pValue = (caddr_t)&pub_class;
		pubTemplate[n].ulValueLen = sizeof (pub_class);
		n++;
	}
	if (!has_key_type) {
		pubTemplate[n].type = CKA_KEY_TYPE;
		key_type = CKK_RSA;
		pubTemplate[n].pValue = (caddr_t)&key_type;
		pubTemplate[n].ulValueLen = sizeof (key_type);
		n++;
	}
	if (!has_pub_exponent) {
		pubTemplate[n].type = CKA_PUBLIC_EXPONENT;
		pubTemplate[n].pValue = (caddr_t)public_exponent;
		pubTemplate[n].ulValueLen = modulus_bytes;
		n++;
		pub_out_attr_count++;
	}
	pubTemplate[n].type = CKA_MODULUS;
	pubTemplate[n].pValue = (caddr_t)public_modulus;
	pubTemplate[n].ulValueLen = modulus_bytes;
	pub_out_attr_count++;

	rv = process_object_attributes(pubTemplate,
	    pub_attr_count - pub_out_attr_count,
	    &obj_nkp.nkp_in_public_attributes, &is_token_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_in_public_count = pub_attr_count - pub_out_attr_count;

	rv = process_object_attributes(
	    &pubTemplate[pub_attr_count - pub_out_attr_count],
	    pub_out_attr_count, &obj_nkp.nkp_out_public_attributes,
	    &is_token_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_out_public_count = pub_out_attr_count;

	/*
	 * Cannot create a token object with a READ-ONLY
	 * session.
	 */
	if (is_token_obj1 && session_p->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/*
	 * Add CKA_MODULUS and CKA_PRIVATE_EXPONENT
	 * to the private template. These attributes
	 * must not be in the template.
	 */
	if (attribute_in_template(CKA_PRIVATE_EXPONENT,
	    pPrivateKeyTemplate, ulPrivateKeyAttributeCount) ||
	    attribute_in_template(CKA_MODULUS,
	    pPrivateKeyTemplate, ulPrivateKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto failed_exit;
	}
	has_class = attribute_in_template(CKA_CLASS, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount);
	has_key_type = attribute_in_template(CKA_KEY_TYPE, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount);

	pri_attr_count = ulPrivateKeyAttributeCount + 7;
	if (!has_class)
		pri_attr_count++;
	if (!has_key_type)
		pri_attr_count++;

	/* allocate space for CKA_PUBLIC_EXPONENT */
	priTemplate = grow_template(pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount, pri_attr_count + 1);
	if (priTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}
	n = ulPrivateKeyAttributeCount;
	if (!has_class) {
		priTemplate[n].type = CKA_CLASS;
		priTemplate[n].pValue = (caddr_t)&pri_class;
		priTemplate[n].ulValueLen = sizeof (pri_class);
		n++;
	}
	if (!has_key_type) {
		priTemplate[n].type = CKA_KEY_TYPE;
		key_type = CKK_RSA;
		priTemplate[n].pValue = (caddr_t)&key_type;
		priTemplate[n].ulValueLen = sizeof (key_type);
		n++;
	}
	priTemplate[n].type = CKA_MODULUS;
	priTemplate[n].pValue = (caddr_t)private_modulus;
	priTemplate[n].ulValueLen = modulus_bytes;
	pri_out_attr_count++;

	n++;
	priTemplate[n].type = CKA_PRIVATE_EXPONENT;
	priTemplate[n].pValue = (caddr_t)private_exponent;
	priTemplate[n].ulValueLen = modulus_bytes;
	pri_out_attr_count++;

	n++;
	priTemplate[n].type = CKA_PRIME_1;
	priTemplate[n].pValue = (caddr_t)prime_1;
	priTemplate[n].ulValueLen = modulus_bytes/2;
	pri_out_attr_count++;

	n++;
	priTemplate[n].type = CKA_PRIME_2;
	priTemplate[n].pValue = (caddr_t)prime_2;
	priTemplate[n].ulValueLen = modulus_bytes/2;
	pri_out_attr_count++;

	n++;
	priTemplate[n].type = CKA_EXPONENT_1;
	priTemplate[n].pValue = (caddr_t)exponent_1;
	priTemplate[n].ulValueLen = modulus_bytes/2;
	pri_out_attr_count++;

	n++;
	priTemplate[n].type = CKA_EXPONENT_2;
	priTemplate[n].pValue = (caddr_t)exponent_2;
	priTemplate[n].ulValueLen = modulus_bytes/2;
	pri_out_attr_count++;

	n++;
	priTemplate[n].type = CKA_COEFFICIENT;
	priTemplate[n].pValue = (caddr_t)coefficient;
	priTemplate[n].ulValueLen = modulus_bytes/2;
	pri_out_attr_count++;

	rv = process_object_attributes(priTemplate,
	    pri_attr_count - pri_out_attr_count,
	    &obj_nkp.nkp_in_private_attributes, &is_token_obj2);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_in_private_count = pri_attr_count - pri_out_attr_count;

	rv = process_object_attributes(
	    &priTemplate[pri_attr_count - pri_out_attr_count],
	    pri_out_attr_count, &obj_nkp.nkp_out_private_attributes,
	    &is_token_obj2);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_out_private_count = pri_out_attr_count;

	/*
	 * The public key and the private key need to contain the same
	 * attribute values for CKA_TOKEN.
	 */
	if (is_token_obj1 != is_token_obj2) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto failed_exit;
	}

	/* Call the CRYPTO_NOSTORE_GENERATE_KEY_PAIR ioctl. */
	obj_nkp.nkp_session = session_p-> k_session;
	obj_nkp.nkp_mechanism.cm_type = k_mech_type;
	obj_nkp.nkp_mechanism.cm_param = pMechanism->pParameter;
	obj_nkp.nkp_mechanism.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_NOSTORE_GENERATE_KEY_PAIR,
	    &obj_nkp)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_nkp.nkp_return_value);
	}
	free_attributes(obj_nkp.nkp_in_public_attributes,
	    &obj_nkp.nkp_in_public_count);
	free_attributes(obj_nkp.nkp_in_private_attributes,
	    &obj_nkp.nkp_in_private_count);

	if (rv != CKR_OK) {
		goto failed_exit;
	}

	rv = get_object_attributes(
	    &pubTemplate[pub_attr_count - pub_out_attr_count],
	    pub_out_attr_count, obj_nkp.nkp_out_public_attributes);
	if (rv == CRYPTO_SUCCESS) {
		rv = get_object_attributes(
		    &priTemplate[pri_attr_count - pri_out_attr_count],
		    pri_out_attr_count, obj_nkp.nkp_out_private_attributes);
	}
	free_attributes(obj_nkp.nkp_out_public_attributes,
	    &obj_nkp.nkp_out_public_count);
	free_attributes(obj_nkp.nkp_out_private_attributes,
	    &obj_nkp.nkp_out_private_count);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	/* store generated modulus and public exponent */
	rv = kernel_build_object(pubTemplate, pub_attr_count, new_pub_objp,
	    session_p, KERNEL_GEN_KEY);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	/*
	 * Copy CKA_PUBLIC_EXPONENT from the public template
	 * to the private template.
	 */
	rv = copy_attribute(CKA_PUBLIC_EXPONENT, pubTemplate,
	    pub_attr_count, &priTemplate[pri_attr_count]);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	rv = kernel_build_object(priTemplate, pri_attr_count + 1, new_pri_objp,
	    session_p, KERNEL_GEN_KEY);
	(void) free(priTemplate[pri_attr_count].pValue);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}
	(void) free(pubTemplate);
	(void) free(priTemplate);

	new_pub_objp->is_lib_obj = B_TRUE;
	new_pri_objp->is_lib_obj = B_TRUE;
	new_pub_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_pri_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	(void) pthread_mutex_init(&new_pub_objp->object_mutex, NULL);
	new_pub_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	(void) pthread_mutex_init(&new_pri_objp->object_mutex, NULL);
	new_pri_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	return (CKR_OK);

failed_exit:
	free_attributes(obj_nkp.nkp_in_public_attributes,
	    &obj_nkp.nkp_in_public_count);
	free_attributes(obj_nkp.nkp_out_public_attributes,
	    &obj_nkp.nkp_out_public_count);
	free_attributes(obj_nkp.nkp_in_private_attributes,
	    &obj_nkp.nkp_in_private_count);
	free_attributes(obj_nkp.nkp_out_private_attributes,
	    &obj_nkp.nkp_out_private_count);
	if (pubTemplate != NULL) {
		(void) free(pubTemplate);
	}
	if (priTemplate != NULL) {
		(void) free(priTemplate);
	}
	return (rv);
}

CK_RV
key_gen_dh_by_value(CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    kernel_session_t *session_p, crypto_mech_type_t k_mech_type,
    kernel_object_t *new_pub_objp, kernel_object_t *new_pri_objp)
{
	crypto_nostore_generate_key_pair_t obj_nkp;
	CK_ATTRIBUTE_PTR pubTemplate = NULL;
	CK_ATTRIBUTE_PTR priTemplate = NULL;
	CK_RV rv = CKR_OK;
	CK_BBOOL is_token_obj1 = FALSE;
	CK_BBOOL is_token_obj2 = FALSE;
	uint_t pub_attr_count, pri_attr_count;
	uint_t pub_out_attr_count = 0, pri_out_attr_count = 0;
	char public_value[256];
	char private_value[256];
	CK_ULONG pub_class = CKO_PUBLIC_KEY;
	CK_ULONG pri_class = CKO_PRIVATE_KEY;
	CK_ULONG key_type;
	boolean_t has_class, has_key_type;
	int n, r;

	obj_nkp.nkp_in_public_count = 0;
	obj_nkp.nkp_out_public_count = 0;
	obj_nkp.nkp_in_private_count = 0;
	obj_nkp.nkp_out_private_count = 0;

	/*
	 * Add CKA_VALUE to the public template.
	 * This attribute must not be in the template.
	 */
	if (attribute_in_template(CKA_VALUE, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto failed_exit;
	}
	has_class = attribute_in_template(CKA_CLASS, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount);
	has_key_type = attribute_in_template(CKA_KEY_TYPE, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount);

	pub_attr_count = ulPublicKeyAttributeCount + 1;
	if (!has_class)
		pub_attr_count++;
	if (!has_key_type)
		pub_attr_count++;
	pubTemplate = grow_template(pPublicKeyTemplate,
	    ulPublicKeyAttributeCount, pub_attr_count);
	if (pubTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	n = ulPublicKeyAttributeCount;
	if (!has_class) {
		pubTemplate[n].type = CKA_CLASS;
		pubTemplate[n].pValue = (caddr_t)&pub_class;
		pubTemplate[n].ulValueLen = sizeof (pub_class);
		n++;
	}
	if (!has_key_type) {
		pubTemplate[n].type = CKA_KEY_TYPE;
		key_type = CKK_DH;
		pubTemplate[n].pValue = (caddr_t)&key_type;
		pubTemplate[n].ulValueLen = sizeof (key_type);
		n++;
	}
	pubTemplate[n].type = CKA_VALUE;
	pubTemplate[n].pValue = (caddr_t)public_value;
	pubTemplate[n].ulValueLen = sizeof (public_value);
	pub_out_attr_count++;

	rv = process_object_attributes(pubTemplate,
	    pub_attr_count - pub_out_attr_count,
	    &obj_nkp.nkp_in_public_attributes, &is_token_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_in_public_count = pub_attr_count - pub_out_attr_count;

	rv = process_object_attributes(
	    &pubTemplate[pub_attr_count - pub_out_attr_count],
	    pub_out_attr_count, &obj_nkp.nkp_out_public_attributes,
	    &is_token_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_out_public_count = pub_out_attr_count;

	/*
	 * Cannot create a token object with a READ-ONLY
	 * session.
	 */
	if (is_token_obj1 && session_p->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/*
	 * CKA_BASE, CKA_PRIME, and CKA_VALUE must not appear
	 * in private template.
	 */
	if (attribute_in_template(CKA_BASE, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount) ||
	    attribute_in_template(CKA_PRIME, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount) ||
	    attribute_in_template(CKA_VALUE, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto failed_exit;
	}

	if (attribute_in_template(CKA_VALUE, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto failed_exit;
	}
	has_class = attribute_in_template(CKA_CLASS, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount);
	has_key_type = attribute_in_template(CKA_KEY_TYPE, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount);

	pri_attr_count = ulPrivateKeyAttributeCount + 1;
	if (!has_class)
		pri_attr_count++;
	if (!has_key_type)
		pri_attr_count++;

	/* allocate space for CKA_BASE and CKA_PRIME */
	priTemplate = grow_template(pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount, pri_attr_count + 2);
	if (priTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}
	n = ulPrivateKeyAttributeCount;
	if (!has_class) {
		priTemplate[n].type = CKA_CLASS;
		priTemplate[n].pValue = (caddr_t)&pri_class;
		priTemplate[n].ulValueLen = sizeof (pri_class);
		n++;
	}
	if (!has_key_type) {
		priTemplate[n].type = CKA_KEY_TYPE;
		key_type = CKK_DH;
		priTemplate[n].pValue = (caddr_t)&key_type;
		priTemplate[n].ulValueLen = sizeof (key_type);
		n++;
	}
	priTemplate[n].type = CKA_VALUE;
	priTemplate[n].pValue = (caddr_t)private_value;
	priTemplate[n].ulValueLen = sizeof (private_value);
	pri_out_attr_count++;

	rv = process_object_attributes(priTemplate,
	    pri_attr_count - pri_out_attr_count,
	    &obj_nkp.nkp_in_private_attributes, &is_token_obj2);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_in_private_count = pri_attr_count - pri_out_attr_count;

	rv = process_object_attributes(
	    &priTemplate[pri_attr_count - pri_out_attr_count],
	    pri_out_attr_count, &obj_nkp.nkp_out_private_attributes,
	    &is_token_obj2);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_out_private_count = pri_out_attr_count;

	/*
	 * The public key and the private key need to contain the same
	 * attribute values for CKA_TOKEN.
	 */
	if (is_token_obj1 != is_token_obj2) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto failed_exit;
	}

	/* Call the CRYPTO_NOSTORE_GENERATE_KEY_PAIR ioctl. */
	obj_nkp.nkp_session = session_p-> k_session;
	obj_nkp.nkp_mechanism.cm_type = k_mech_type;
	obj_nkp.nkp_mechanism.cm_param = pMechanism->pParameter;
	obj_nkp.nkp_mechanism.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_NOSTORE_GENERATE_KEY_PAIR,
	    &obj_nkp)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_nkp.nkp_return_value);
	}
	free_attributes(obj_nkp.nkp_in_public_attributes,
	    &obj_nkp.nkp_in_public_count);
	free_attributes(obj_nkp.nkp_in_private_attributes,
	    &obj_nkp.nkp_in_private_count);

	if (rv != CKR_OK) {
		goto failed_exit;
	}

	rv = get_object_attributes(
	    &pubTemplate[pub_attr_count - pub_out_attr_count],
	    pub_out_attr_count, obj_nkp.nkp_out_public_attributes);
	if (rv == CRYPTO_SUCCESS) {
		rv = get_object_attributes(
		    &priTemplate[pri_attr_count - pri_out_attr_count],
		    pri_out_attr_count, obj_nkp.nkp_out_private_attributes);
	}
	free_attributes(obj_nkp.nkp_out_public_attributes,
	    &obj_nkp.nkp_out_public_count);
	free_attributes(obj_nkp.nkp_out_private_attributes,
	    &obj_nkp.nkp_out_private_count);

	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	rv = kernel_build_object(pubTemplate, pub_attr_count, new_pub_objp,
	    session_p, KERNEL_GEN_KEY);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	/*
	 * Copy CKA_BASE and CKA_PRIME from the public template
	 * to the private template.
	 */
	rv = copy_attribute(CKA_BASE, pubTemplate, pub_attr_count,
	    &priTemplate[pri_attr_count]);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}
	rv = copy_attribute(CKA_PRIME, pubTemplate, pub_attr_count,
	    &priTemplate[pri_attr_count + 1]);
	if (rv != CRYPTO_SUCCESS) {
		(void) free(priTemplate[pri_attr_count].pValue);
		goto failed_exit;
	}

	/* +2 to account for CKA_BASE and CKA_PRIME */
	rv = kernel_build_object(priTemplate, pri_attr_count + 2,
	    new_pri_objp, session_p, KERNEL_GEN_KEY);
	(void) free(priTemplate[pri_attr_count].pValue);
	(void) free(priTemplate[pri_attr_count + 1].pValue);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}
	(void) free(pubTemplate);
	(void) free(priTemplate);

	new_pub_objp->is_lib_obj = B_TRUE;
	new_pri_objp->is_lib_obj = B_TRUE;
	new_pub_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_pri_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	(void) pthread_mutex_init(&new_pub_objp->object_mutex, NULL);
	new_pub_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	(void) pthread_mutex_init(&new_pri_objp->object_mutex, NULL);
	new_pri_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	return (CKR_OK);

failed_exit:
	free_attributes(obj_nkp.nkp_in_public_attributes,
	    &obj_nkp.nkp_in_public_count);
	free_attributes(obj_nkp.nkp_out_public_attributes,
	    &obj_nkp.nkp_out_public_count);
	free_attributes(obj_nkp.nkp_in_private_attributes,
	    &obj_nkp.nkp_in_private_count);
	free_attributes(obj_nkp.nkp_out_private_attributes,
	    &obj_nkp.nkp_out_private_count);
	if (pubTemplate != NULL) {
		(void) free(pubTemplate);
	}
	if (priTemplate != NULL) {
		(void) free(priTemplate);
	}
	return (rv);
}

CK_RV
key_gen_ec_by_value(CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    kernel_session_t *session_p, crypto_mech_type_t k_mech_type,
    kernel_object_t *new_pub_objp, kernel_object_t *new_pri_objp)
{
	crypto_nostore_generate_key_pair_t obj_nkp;
	CK_ATTRIBUTE_PTR pubTemplate = NULL;
	CK_ATTRIBUTE_PTR priTemplate = NULL;
	CK_RV rv = CKR_OK;
	CK_BBOOL is_token_obj1 = FALSE;
	CK_BBOOL is_token_obj2 = FALSE;
	uint_t pub_attr_count, pri_attr_count;
	uint_t pub_out_attr_count = 0, pri_out_attr_count = 0;
	char value[EC_MAX_VALUE_LEN];
	char point[EC_MAX_POINT_LEN];
	CK_ULONG pub_class = CKO_PUBLIC_KEY;
	CK_ULONG pri_class = CKO_PRIVATE_KEY;
	CK_ULONG key_type;
	boolean_t has_class, has_key_type;
	int n, r;

	obj_nkp.nkp_in_public_count = 0;
	obj_nkp.nkp_out_public_count = 0;
	obj_nkp.nkp_in_private_count = 0;
	obj_nkp.nkp_out_private_count = 0;

	/*
	 * Add CKA_EC_POINT to the public template.
	 * This is the generated value Q. This attribute
	 * must not be in the template.
	 */
	if (attribute_in_template(CKA_EC_POINT, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto failed_exit;
	}
	has_class = attribute_in_template(CKA_CLASS, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount);
	has_key_type = attribute_in_template(CKA_KEY_TYPE, pPublicKeyTemplate,
	    ulPublicKeyAttributeCount);

	pub_attr_count = ulPublicKeyAttributeCount + 1;
	if (!has_class)
		pub_attr_count++;
	if (!has_key_type)
		pub_attr_count++;
	pubTemplate = grow_template(pPublicKeyTemplate,
	    ulPublicKeyAttributeCount, pub_attr_count);
	if (pubTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	n = ulPublicKeyAttributeCount;
	if (!has_class) {
		pubTemplate[n].type = CKA_CLASS;
		pubTemplate[n].pValue = (caddr_t)&pub_class;
		pubTemplate[n].ulValueLen = sizeof (pub_class);
		n++;
	}
	if (!has_key_type) {
		pubTemplate[n].type = CKA_KEY_TYPE;
		key_type = CKK_EC;
		pubTemplate[n].pValue = (caddr_t)&key_type;
		pubTemplate[n].ulValueLen = sizeof (key_type);
		n++;
	}
	pubTemplate[n].type = CKA_EC_POINT;
	pubTemplate[n].pValue = (caddr_t)point;
	pubTemplate[n].ulValueLen = sizeof (point);
	pub_out_attr_count++;

	rv = process_object_attributes(pubTemplate,
	    pub_attr_count - pub_out_attr_count,
	    &obj_nkp.nkp_in_public_attributes, &is_token_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_in_public_count = pub_attr_count - pub_out_attr_count;

	rv = process_object_attributes(
	    &pubTemplate[pub_attr_count - pub_out_attr_count],
	    pub_out_attr_count, &obj_nkp.nkp_out_public_attributes,
	    &is_token_obj1);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_out_public_count = pub_out_attr_count;

	/*
	 * Cannot create a token object with a READ-ONLY
	 * session.
	 */
	if (is_token_obj1 && session_p->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	/*
	 * CKA_EC_PARAMS and CKA_VALUE must not appear in
	 * private template.
	 */
	if (attribute_in_template(CKA_EC_PARAMS, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount) ||
	    attribute_in_template(CKA_VALUE, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto failed_exit;
	}
	has_class = attribute_in_template(CKA_CLASS, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount);
	has_key_type = attribute_in_template(CKA_KEY_TYPE, pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount);

	pri_attr_count = ulPrivateKeyAttributeCount + 1;
	if (!has_class)
		pri_attr_count++;
	if (!has_key_type)
		pri_attr_count++;

	/* allocate space for CKA_EC_PARAMS */
	priTemplate = grow_template(pPrivateKeyTemplate,
	    ulPrivateKeyAttributeCount, pri_attr_count + 1);
	if (priTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}
	n = ulPrivateKeyAttributeCount;
	if (!has_class) {
		priTemplate[n].type = CKA_CLASS;
		priTemplate[n].pValue = (caddr_t)&pri_class;
		priTemplate[n].ulValueLen = sizeof (pri_class);
		n++;
	}
	if (!has_key_type) {
		priTemplate[n].type = CKA_KEY_TYPE;
		key_type = CKK_EC;
		priTemplate[n].pValue = (caddr_t)&key_type;
		priTemplate[n].ulValueLen = sizeof (key_type);
		n++;
	}
	priTemplate[n].type = CKA_VALUE;
	priTemplate[n].pValue = (caddr_t)value;
	priTemplate[n].ulValueLen = sizeof (value);
	pri_out_attr_count++;

	rv = process_object_attributes(priTemplate,
	    pri_attr_count - pri_out_attr_count,
	    &obj_nkp.nkp_in_private_attributes, &is_token_obj2);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_in_private_count = pri_attr_count - pri_out_attr_count;

	rv = process_object_attributes(
	    &priTemplate[pri_attr_count - pri_out_attr_count],
	    pri_out_attr_count, &obj_nkp.nkp_out_private_attributes,
	    &is_token_obj2);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_nkp.nkp_out_private_count = pri_out_attr_count;

	/*
	 * The public key and the private key need to contain the same
	 * attribute values for CKA_TOKEN.
	 */
	if (is_token_obj1 != is_token_obj2) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto failed_exit;
	}

	/* Call the CRYPTO_NOSTORE_GENERATE_KEY_PAIR ioctl. */
	obj_nkp.nkp_session = session_p-> k_session;
	obj_nkp.nkp_mechanism.cm_type = k_mech_type;
	obj_nkp.nkp_mechanism.cm_param = pMechanism->pParameter;
	obj_nkp.nkp_mechanism.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_NOSTORE_GENERATE_KEY_PAIR,
	    &obj_nkp)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_nkp.nkp_return_value);
	}
	free_attributes(obj_nkp.nkp_in_public_attributes,
	    &obj_nkp.nkp_in_public_count);
	free_attributes(obj_nkp.nkp_in_private_attributes,
	    &obj_nkp.nkp_in_private_count);

	if (rv != CKR_OK) {
		goto failed_exit;
	}

	rv = get_object_attributes(
	    &pubTemplate[pub_attr_count - pub_out_attr_count],
	    pub_out_attr_count, obj_nkp.nkp_out_public_attributes);
	if (rv == CRYPTO_SUCCESS) {
		rv = get_object_attributes(
		    &priTemplate[pri_attr_count - pri_out_attr_count],
		    pri_out_attr_count, obj_nkp.nkp_out_private_attributes);
	}
	free_attributes(obj_nkp.nkp_out_public_attributes,
	    &obj_nkp.nkp_out_public_count);
	free_attributes(obj_nkp.nkp_out_private_attributes,
	    &obj_nkp.nkp_out_private_count);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	rv = kernel_build_object(pubTemplate, pub_attr_count, new_pub_objp,
	    session_p, KERNEL_GEN_KEY);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	/*
	 * Copy CKA_EC_PARAMS from the public template to the
	 * private template.
	 */
	rv = copy_attribute(CKA_EC_PARAMS, pubTemplate, pub_attr_count,
	    &priTemplate[pri_attr_count]);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	/* +1 to account for CKA_EC_PARAMS */
	rv = kernel_build_object(priTemplate, pri_attr_count + 1,
	    new_pri_objp, session_p, KERNEL_GEN_KEY);
	(void) free(priTemplate[pri_attr_count].pValue);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}
	(void) free(pubTemplate);
	(void) free(priTemplate);

	new_pub_objp->is_lib_obj = B_TRUE;
	new_pri_objp->is_lib_obj = B_TRUE;
	new_pub_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	new_pri_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	(void) pthread_mutex_init(&new_pub_objp->object_mutex, NULL);
	new_pub_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	(void) pthread_mutex_init(&new_pri_objp->object_mutex, NULL);
	new_pri_objp->magic_marker = KERNELTOKEN_OBJECT_MAGIC;
	return (CKR_OK);

failed_exit:
	free_attributes(obj_nkp.nkp_in_public_attributes,
	    &obj_nkp.nkp_in_public_count);
	free_attributes(obj_nkp.nkp_out_public_attributes,
	    &obj_nkp.nkp_out_public_count);
	free_attributes(obj_nkp.nkp_in_private_attributes,
	    &obj_nkp.nkp_in_private_count);
	free_attributes(obj_nkp.nkp_out_private_attributes,
	    &obj_nkp.nkp_out_private_count);
	if (pubTemplate != NULL) {
		(void) free(pubTemplate);
	}
	if (priTemplate != NULL) {
		(void) free(priTemplate);
	}
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
	int r;
	CK_RV (*func)(CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
	    CK_ATTRIBUTE_PTR, CK_ULONG, kernel_session_t *, crypto_mech_type_t,
	    kernel_object_t *, kernel_object_t *);

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

	/*
	 * Special Case: if token does not support object creation,
	 * but does support key generation by value, then create a session
	 * object and initialize with values returned by token.
	 */
	pslot = slot_table[session_p->ses_slotid];
	if (!pslot->sl_func_list.fl_object_create) {
		switch (pMechanism->mechanism) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			func = key_gen_rsa_by_value;
			break;

		case CKM_DH_PKCS_KEY_PAIR_GEN:
			func = key_gen_dh_by_value;
			break;

		case CKM_EC_KEY_PAIR_GEN:
			func = key_gen_ec_by_value;
			break;

		default:
			rv = CKR_MECHANISM_INVALID;
			goto failed_exit;
		}
		rv = (*func)(pMechanism, pPublicKeyTemplate,
		    ulPublicKeyAttributeCount, pPrivateKeyTemplate,
		    ulPrivateKeyAttributeCount, session_p, k_mech_type,
		    new_pub_objp, new_pri_objp);
		if (rv != CKR_OK)
			goto failed_exit;
	} else {
		crypto_object_generate_key_pair_t obj_kp;

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

		while ((r = ioctl(kernel_fd, CRYPTO_GENERATE_KEY_PAIR,
		    &obj_kp)) < 0) {
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

		if (rv != CKR_OK)
			goto failed_exit;

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
		 * Store the kernel public key handle into the public key
		 * object and finish the public key object initialization.
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
		 * Store the kernel private key handle into the private key
		 * object and finish the private key object initialization.
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

	}
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
	CK_ULONG		ulDataLen;
	CK_ATTRIBUTE_PTR	newTemplate = NULL;
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
	if ((!pslot->sl_func_list.fl_object_create) &&
	    (!pslot->sl_func_list.fl_key_unwrap)) {
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

			newTemplate = grow_template(pTemplate, ulAttributeCount,
			    ulAttributeCount + 1);
			if (newTemplate == NULL) {
				rv = CKR_HOST_MEMORY;
				goto failed_exit;
			}
			/* Now add the CKA_VALUE attribute to template */
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

/*
 * Get sufficient attributes from a base key to pass by value in a
 * crypto_key structure. Storage for attributes is allocated.
 * For EC public keys, it is CKA_EC_PARAMS and CKA_EC_POINT.
 * For EC private keys, it is CKA_EC_PARAMS and CKA_VALUE.
 */
static int
get_base_key_attributes(kernel_object_t *base_key, crypto_key_t *key_by_value)
{
	CK_ATTRIBUTE tmp;
	crypto_object_attribute_t *attrs = NULL;
	biginteger_t *big;
	int i, count = 0, rv;

	switch (base_key->key_type) {
	case CKK_EC:
		count = 2;
		attrs = malloc(count * sizeof (crypto_object_attribute_t));
		if (attrs == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		bzero(attrs, count * sizeof (crypto_object_attribute_t));

		(void) pthread_mutex_lock(&base_key->object_mutex);

		if (!base_key->is_lib_obj) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto out;
		}

		if (base_key->class != CKO_PUBLIC_KEY &&
		    base_key->class != CKO_PRIVATE_KEY) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto out;
		}

		/*
		 * Both public and private EC keys should have
		 * a CKA_EC_PARAMS attribute.
		 */
		tmp.type = CKA_EC_PARAMS;
		tmp.pValue = NULL;

		/* get size of attribute */
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			goto out;
		}

		tmp.pValue = malloc(tmp.ulValueLen);
		if (tmp.pValue == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			free(tmp.pValue);
			goto out;
		}
		attrs[0].oa_type = tmp.type;
		attrs[0].oa_value = tmp.pValue;
		attrs[0].oa_value_len = tmp.ulValueLen;

		switch (base_key->class) {
		case CKO_PUBLIC_KEY:
			big = OBJ_PUB_EC_POINT(base_key);
			tmp.type = CKA_EC_POINT;
			break;

		case CKO_PRIVATE_KEY:
			big = OBJ_PRI_EC_VALUE(base_key);
			tmp.type = CKA_VALUE;
			break;

		default:
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			goto out;
		}
		tmp.ulValueLen = big->big_value_len;
		tmp.pValue = malloc(tmp.ulValueLen);
		if (tmp.pValue == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			free(tmp.pValue);
			goto out;
		}
		attrs[1].oa_type = tmp.type;
		attrs[1].oa_value = tmp.pValue;
		attrs[1].oa_value_len = tmp.ulValueLen;
		key_by_value->ck_attrs = attrs;
		key_by_value->ck_count = 2;
		break;

	case CKK_DH:
		count = 3;
		attrs = malloc(count * sizeof (crypto_object_attribute_t));
		if (attrs == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		bzero(attrs, count * sizeof (crypto_object_attribute_t));

		(void) pthread_mutex_lock(&base_key->object_mutex);

		if (!base_key->is_lib_obj) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto out;
		}

		if (base_key->class != CKO_PRIVATE_KEY) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto out;
		}
		tmp.type = CKA_BASE;
		tmp.pValue = NULL;

		/* get size of attribute */
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			goto out;
		}

		tmp.pValue = malloc(tmp.ulValueLen);
		if (tmp.pValue == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			free(tmp.pValue);
			goto out;
		}
		attrs[0].oa_type = tmp.type;
		attrs[0].oa_value = tmp.pValue;
		attrs[0].oa_value_len = tmp.ulValueLen;

		tmp.type = CKA_PRIME;
		tmp.pValue = NULL;

		/* get size of attribute */
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			goto out;
		}

		tmp.pValue = malloc(tmp.ulValueLen);
		if (tmp.pValue == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			free(tmp.pValue);
			goto out;
		}
		attrs[1].oa_type = tmp.type;
		attrs[1].oa_value = tmp.pValue;
		attrs[1].oa_value_len = tmp.ulValueLen;

		big = OBJ_PRI_DH_VALUE(base_key);
		tmp.type = CKA_VALUE;

		tmp.ulValueLen = big->big_value_len;
		tmp.pValue = malloc(tmp.ulValueLen);
		if (tmp.pValue == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		rv = kernel_get_attribute(base_key, &tmp);
		if (rv != CKR_OK) {
			free(tmp.pValue);
			goto out;
		}
		attrs[2].oa_type = tmp.type;
		attrs[2].oa_value = tmp.pValue;
		attrs[2].oa_value_len = tmp.ulValueLen;
		key_by_value->ck_attrs = attrs;
		key_by_value->ck_count = 3;
		break;

	default:
		rv = CKR_ATTRIBUTE_TYPE_INVALID;
		goto out;
	}
	(void) pthread_mutex_unlock(&base_key->object_mutex);
	return (CKR_OK);

out:
	(void) pthread_mutex_unlock(&base_key->object_mutex);
	if (attrs != NULL) {
		for (i = 0; i < count; i++) {
			if (attrs[i].oa_value != NULL)
				free(attrs[i].oa_value);
		}
		free(attrs);
	}
	return (rv);
}

CK_RV
derive_key_by_value(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, kernel_session_t *session_p,
    crypto_mech_type_t k_mech_type, kernel_object_t *basekey_p,
    kernel_object_t *new_objp)
{
	crypto_nostore_derive_key_t obj_ndk;
	char *key_buf = NULL;
	CK_ATTRIBUTE_PTR newTemplate = NULL;
	CK_BBOOL is_token_obj = FALSE;
	CK_RV rv = CKR_OK;
	CK_ULONG secret_class = CKO_SECRET_KEY;
	ulong_t key_len = 0;
	uint_t attr_count = 0;
	boolean_t removed;
	boolean_t has_class;
	int r, n;

	obj_ndk.ndk_in_count = 0;
	obj_ndk.ndk_out_count = 0;
	obj_ndk.ndk_base_key.ck_count = 0;

	rv = get_key_len_from_template(pMechanism, pTemplate, ulAttributeCount,
	    basekey_p, &key_len);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	if ((key_buf = malloc(key_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	has_class = attribute_in_template(CKA_CLASS, pTemplate,
	    ulAttributeCount);

	attr_count = ulAttributeCount + 1;
	if (!has_class)
		attr_count++;

	newTemplate = grow_template(pTemplate, ulAttributeCount, attr_count);
	if (newTemplate == NULL) {
		rv = CKR_HOST_MEMORY;
		goto failed_exit;
	}

	n = ulAttributeCount;
	if (!has_class) {
		newTemplate[n].type = CKA_CLASS;
		newTemplate[n].pValue = (caddr_t)&secret_class;
		newTemplate[n].ulValueLen = sizeof (secret_class);
		n++;
	}

	/* Add CKA_VALUE to the template */
	newTemplate[n].type = CKA_VALUE;
	newTemplate[n].pValue = (caddr_t)key_buf;
	newTemplate[n].ulValueLen = key_len;

	rv = process_object_attributes(newTemplate, attr_count - 1,
	    &obj_ndk.ndk_in_attributes, &is_token_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_ndk.ndk_in_count = attr_count - 1;

	rv = process_object_attributes(&newTemplate[attr_count - 1],
	    1, &obj_ndk.ndk_out_attributes, &is_token_obj);
	if (rv != CKR_OK) {
		goto failed_exit;
	}
	obj_ndk.ndk_out_count = 1;

	/* Cannot create a token object with a READ-ONLY session. */
	if (is_token_obj && session_p->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		goto failed_exit;
	}

	obj_ndk.ndk_session = session_p->k_session;
	obj_ndk.ndk_mechanism.cm_type = k_mech_type;
	obj_ndk.ndk_mechanism.cm_param = pMechanism->pParameter;
	obj_ndk.ndk_mechanism.cm_param_len = pMechanism->ulParameterLen;

	/*
	 * Obtain the attributes of base key and pass them by value.
	 */
	rv = get_base_key_attributes(basekey_p, &obj_ndk.ndk_base_key);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	obj_ndk.ndk_base_key.ck_format = CRYPTO_KEY_ATTR_LIST;

	while ((r = ioctl(kernel_fd, CRYPTO_NOSTORE_DERIVE_KEY,
	    &obj_ndk)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(obj_ndk.ndk_return_value);
	}
	free_attributes(obj_ndk.ndk_in_attributes, &obj_ndk.ndk_in_count);
	free_attributes((caddr_t)obj_ndk.ndk_base_key.ck_attrs,
	    &obj_ndk.ndk_base_key.ck_count);
	if (rv != CKR_OK) {
		goto failed_exit;
	}

	rv = get_object_attributes(&newTemplate[attr_count - 1],
	    1, obj_ndk.ndk_out_attributes);
	free_attributes(obj_ndk.ndk_out_attributes, &obj_ndk.ndk_out_count);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	removed = remove_one_attribute(newTemplate, CKA_VALUE_LEN,
	    attr_count, B_FALSE);

	rv = kernel_build_object(newTemplate, removed ? attr_count - 1 :
	    attr_count, new_objp, session_p, KERNEL_GEN_KEY);
	if (rv != CRYPTO_SUCCESS) {
		goto failed_exit;
	}

	free(key_buf);
	free(newTemplate);
	new_objp->is_lib_obj = B_TRUE;
	new_objp->session_handle = (CK_SESSION_HANDLE)session_p;
	return (CKR_OK);

failed_exit:
	if (key_buf != NULL)
		free(key_buf);
	if (newTemplate != NULL)
		free(newTemplate);
	free_attributes(obj_ndk.ndk_in_attributes, &obj_ndk.ndk_in_count);
	free_attributes(obj_ndk.ndk_out_attributes, &obj_ndk.ndk_out_count);
	free_attributes((caddr_t)obj_ndk.ndk_base_key.ck_attrs,
	    &obj_ndk.ndk_base_key.ck_count);
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

	/*
	 * Special Case: if token does not support object creation,
	 * but does support key derivation by value, then create a session
	 * object and initialize with values returned by token.
	 */
	pslot = slot_table[session_p->ses_slotid];
	if (!pslot->sl_func_list.fl_object_create) {
		rv = derive_key_by_value(pMechanism, pTemplate,
		    ulAttributeCount, session_p, k_mech_type, basekey_p,
		    new_objp);
		if (rv != CKR_OK)
			goto failed_exit;
	} else {
		crypto_derive_key_t obj_dk;

		rv = process_object_attributes(pTemplate, ulAttributeCount,
		    &obj_dk.dk_attributes, &is_token_obj);
		if (rv != CKR_OK) {
			goto failed_exit;
		}

		/* Cannot create a token object with a READ-ONLY session. */
		if (is_token_obj && session_p->ses_RO) {
			free_object_attributes(obj_dk.dk_attributes,
			    ulAttributeCount);
			rv = CKR_SESSION_READ_ONLY;
			goto failed_exit;
		}

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
		 * Store the kernel object handle into the new derived key
		 * object and finish the object initialization.
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
	}
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
