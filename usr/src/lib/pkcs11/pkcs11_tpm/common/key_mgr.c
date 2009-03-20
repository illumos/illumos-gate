/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */
/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "tpmtok_int.h"

static CK_BBOOL true = TRUE, false = FALSE;

static CK_RV
key_mgr_get_private_key_type(
	CK_BYTE	*keydata,
	CK_ULONG	keylen,
	CK_KEY_TYPE *keytype)
{
	CK_BYTE  *alg = NULL;
	CK_BYTE  *priv_key = NULL;
	CK_ULONG  alg_len;
	CK_RV    rc;

	rc = ber_decode_PrivateKeyInfo(keydata, keylen, &alg,
	    &alg_len, &priv_key);
	if (rc != CKR_OK) {
		return (rc);
	}
	if (alg_len >= ber_rsaEncryptionLen) {
		if (memcmp(alg, ber_rsaEncryption,
		    ber_rsaEncryptionLen) == 0) {
			*keytype = CKK_RSA;
			return (CKR_OK);
		}
	}

	return (CKR_TEMPLATE_INCOMPLETE);
}

CK_RV
key_mgr_generate_key_pair(SESSION	   * sess,
	CK_MECHANISM	* mech,
	CK_ATTRIBUTE	* publ_tmpl,
	CK_ULONG	    publ_count,
	CK_ATTRIBUTE	* priv_tmpl,
	CK_ULONG	    priv_count,
	CK_OBJECT_HANDLE  * publ_key_handle,
	CK_OBJECT_HANDLE  * priv_key_handle)
{
	OBJECT	* publ_key_obj = NULL;
	OBJECT	* priv_key_obj = NULL;
	CK_ATTRIBUTE  * attr	 = NULL;
	CK_ATTRIBUTE  * new_attr	= NULL;
	CK_ULONG	i, keyclass, subclass = 0;
	CK_BBOOL	flag;
	CK_RV	   rc;

	if (! sess || ! mech || ! publ_key_handle || ! priv_key_handle) {
		return (CKR_FUNCTION_FAILED);
	}
	if (! publ_tmpl && (publ_count != 0)) {
		return (CKR_FUNCTION_FAILED);
	}
	if (! priv_tmpl && (priv_count != 0)) {
		return (CKR_FUNCTION_FAILED);
	}

	for (i = 0; i < publ_count; i++) {
		if (publ_tmpl[i].type == CKA_CLASS) {
			keyclass = *(CK_OBJECT_CLASS *)publ_tmpl[i].pValue;
			if (keyclass != CKO_PUBLIC_KEY) {
				return (CKR_TEMPLATE_INCONSISTENT);
			}
		}

		if (publ_tmpl[i].type == CKA_KEY_TYPE)
			subclass = *(CK_ULONG *)publ_tmpl[i].pValue;
	}


	for (i = 0; i < priv_count; i++) {
		if (priv_tmpl[i].type == CKA_CLASS) {
			keyclass = *(CK_OBJECT_CLASS *)priv_tmpl[i].pValue;
			if (keyclass != CKO_PRIVATE_KEY) {
				return (CKR_TEMPLATE_INCONSISTENT);
			}
		}

		if (priv_tmpl[i].type == CKA_KEY_TYPE) {
			CK_ULONG temp = *(CK_ULONG *)priv_tmpl[i].pValue;
			if (temp != subclass) {
				return (CKR_TEMPLATE_INCONSISTENT);
			}
		}
	}


	switch (mech->mechanism) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			if (subclass != 0 && subclass != CKK_RSA) {
				return (CKR_TEMPLATE_INCONSISTENT);
			}

			subclass = CKK_RSA;
		break;

		default:
			return (CKR_MECHANISM_INVALID);
	}


	rc = object_mgr_create_skel(sess,
	    publ_tmpl,	publ_count, MODE_KEYGEN,
	    CKO_PUBLIC_KEY,  subclass, &publ_key_obj);

	if (rc != CKR_OK) {
		goto error;
	}
	rc = object_mgr_create_skel(sess,
	    priv_tmpl,	priv_count, MODE_KEYGEN,
	    CKO_PRIVATE_KEY, subclass, &priv_key_obj);

	if (rc != CKR_OK) {
		goto error;
	}

	switch (mech->mechanism) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			rc = ckm_rsa_key_pair_gen(
			    sess->hContext,
			    publ_key_obj->template,
			    priv_key_obj->template);
		break;

		default:
			rc = CKR_MECHANISM_INVALID;
		break;
	}

	if (rc != CKR_OK) {
		goto error;
	}

	/*
	 * we can now set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE
	 * to their appropriate values.  this only applies to CKO_SECRET_KEY
	 * and CKO_PRIVATE_KEY objects
	 */
	flag = template_attribute_find(priv_key_obj->template,
	    CKA_SENSITIVE, &attr);
	if (flag == TRUE) {
		flag = *(CK_BBOOL *)attr->pValue;

		rc = build_attribute(CKA_ALWAYS_SENSITIVE, &flag,
		    sizeof (CK_BBOOL), &new_attr);
		if (rc != CKR_OK) {
			goto error;
		}
		(void) template_update_attribute(priv_key_obj->template,
		    new_attr);

	} else {
		rc = CKR_FUNCTION_FAILED;
		goto error;
	}


	flag = template_attribute_find(priv_key_obj->template,
	    CKA_EXTRACTABLE, &attr);
	if (flag == TRUE) {
		flag = *(CK_BBOOL *)attr->pValue;

		rc = build_attribute(CKA_NEVER_EXTRACTABLE, &true,
		    sizeof (CK_BBOOL), &new_attr);
		if (rc != CKR_OK) {
			goto error;
		}
		if (flag == TRUE)
			*(CK_BBOOL *)new_attr->pValue = false;

		(void) template_update_attribute(priv_key_obj->template,
		    new_attr);

	} else {
		rc = CKR_FUNCTION_FAILED;
		goto error;
	}

	rc = object_mgr_create_final(sess, publ_key_obj, publ_key_handle);
	if (rc != CKR_OK) {
		goto error;
	}
	rc = object_mgr_create_final(sess, priv_key_obj, priv_key_handle);
	if (rc != CKR_OK) {
		(void) object_mgr_destroy_object(sess, *publ_key_handle);
		publ_key_obj = NULL;
		goto error;
	}
	return (rc);

error:
	if (publ_key_obj)
		(void) object_free(publ_key_obj);
	if (priv_key_obj)
		(void) object_free(priv_key_obj);

	*publ_key_handle = 0;
	*priv_key_handle = 0;

	return (rc);
}

CK_RV
key_mgr_wrap_key(SESSION	   * sess,
	CK_BBOOL	length_only,
	CK_MECHANISM	* mech,
	CK_OBJECT_HANDLE    h_wrapping_key,
	CK_OBJECT_HANDLE    h_key,
	CK_BYTE	  * wrapped_key,
	CK_ULONG  * wrapped_key_len) {
	ENCR_DECR_CONTEXT * ctx	= NULL;
	OBJECT	  * key1_obj  = NULL;
	OBJECT	  * key2_obj  = NULL;
	CK_ATTRIBUTE	* attr	= NULL;
	CK_BYTE	  * data	= NULL;
	CK_ULONG    data_len;
	CK_OBJECT_CLASS	class;
	CK_KEY_TYPE	 keytype;
	CK_BBOOL    flag;
	CK_RV	rc;

	if (! sess || ! wrapped_key_len) {
		return (CKR_FUNCTION_FAILED);
	}

	rc = object_mgr_find_in_map1(sess->hContext, h_wrapping_key, &key1_obj);
	if (rc != CKR_OK) {
		return (CKR_WRAPPING_KEY_HANDLE_INVALID);
	}
	rc = object_mgr_find_in_map1(sess->hContext, h_key, &key2_obj);
	if (rc != CKR_OK) {
		return (CKR_KEY_HANDLE_INVALID);
	}

	rc = template_attribute_find(key2_obj->template,
	    CKA_EXTRACTABLE, &attr);
	if (rc == FALSE) {
		return (CKR_KEY_NOT_WRAPPABLE);
	} else {
		flag = *(CK_BBOOL *)attr->pValue;
		if (flag == FALSE) {
			return (CKR_KEY_NOT_WRAPPABLE);
		}
	}

	rc = template_attribute_find(key2_obj->template, CKA_CLASS, &attr);
	if (rc == FALSE) {
		return (CKR_KEY_NOT_WRAPPABLE);
	} else
		class = *(CK_OBJECT_CLASS *)attr->pValue;

	switch (mech->mechanism) {
		case CKM_RSA_PKCS:
		if (class != CKO_SECRET_KEY) {
			return (CKR_KEY_NOT_WRAPPABLE);
		}
		break;

		default:
		return (CKR_KEY_NOT_WRAPPABLE);
	}

	rc = template_attribute_find(key2_obj->template,
	    CKA_KEY_TYPE, &attr);
	if (rc == FALSE)
		return (CKR_KEY_NOT_WRAPPABLE);
	else
		keytype = *(CK_KEY_TYPE *)attr->pValue;

	switch (keytype) {
		case CKK_RSA:
		rc = rsa_priv_wrap_get_data(key2_obj->template, length_only,
		    &data, &data_len);
		if (rc != CKR_OK) {
			return (rc);
		}
		break;

		case CKK_GENERIC_SECRET:
		rc = generic_secret_wrap_get_data(key2_obj->template,
		    length_only, &data, &data_len);
		if (rc != CKR_OK) {
			return (rc);
		}
		break;
		default:
		return (CKR_KEY_NOT_WRAPPABLE);
	}

	switch (mech->mechanism) {
		case CKM_RSA_PKCS:
		break;

		default:
		return (CKR_KEY_NOT_WRAPPABLE);
	}

	ctx = (ENCR_DECR_CONTEXT *)malloc(sizeof (ENCR_DECR_CONTEXT));
	if (! ctx) {
		return (CKR_HOST_MEMORY);
	}
	(void) memset(ctx, 0x0, sizeof (ENCR_DECR_CONTEXT));

	rc = encr_mgr_init(sess, ctx, OP_WRAP, mech, h_wrapping_key);
	if (rc != CKR_OK) {
		return (rc);
	}
	rc = encr_mgr_encrypt(sess,	length_only,
	    ctx, data,	data_len, wrapped_key, wrapped_key_len);

	if (data != NULL) {
		free(data);
	}
	(void) encr_mgr_cleanup(ctx);
	free(ctx);

	return (rc);
}

CK_RV
key_mgr_unwrap_key(SESSION	   * sess,
	CK_MECHANISM	* mech,
	CK_ATTRIBUTE	* attributes,
	CK_ULONG	    attrib_count,
	CK_BYTE	   * wrapped_key,
	CK_ULONG	    wrapped_key_len,
	CK_OBJECT_HANDLE    h_unwrapping_key,
	CK_OBJECT_HANDLE  * h_unwrapped_key)
{
	ENCR_DECR_CONTEXT * ctx = NULL;
	OBJECT	    * key_obj = NULL;
	CK_BYTE	   * data = NULL;
	CK_ULONG	    data_len;
	CK_ULONG	    keyclass, keytype;
	CK_ULONG	    i;
	CK_BBOOL	    found_class, found_type, fromend;
	CK_RV		rc;


	if (! sess || ! wrapped_key || ! h_unwrapped_key) {
		return (CKR_FUNCTION_FAILED);
	}

	rc = object_mgr_find_in_map1(sess->hContext, h_unwrapping_key,
	    &key_obj);
	if (rc != CKR_OK) {
		return (CKR_WRAPPING_KEY_HANDLE_INVALID);
	}

	found_class    = FALSE;
	found_type	= FALSE;

	switch (mech->mechanism) {
		case CKM_RSA_PKCS:
			keyclass = CKO_SECRET_KEY;
			found_class = TRUE;
		break;
	}

	for (i = 0; i < attrib_count; i++) {
		switch (attributes[i].type) {
			case CKA_CLASS:
			keyclass = *(CK_OBJECT_CLASS *)attributes[i].pValue;
			found_class = TRUE;
			break;

			case CKA_KEY_TYPE:
			keytype = *(CK_KEY_TYPE *)attributes[i].pValue;
			found_type = TRUE;
			break;
		}
	}

	if (found_class == FALSE || (found_type == FALSE && keyclass !=
	    CKO_PRIVATE_KEY)) {
		return (CKR_TEMPLATE_INCOMPLETE);
	}

	switch (mech->mechanism) {
		case CKM_RSA_PKCS:
		if (keyclass != CKO_SECRET_KEY) {
			return (CKR_TEMPLATE_INCONSISTENT);
		}
		break;
		default:
			return (CKR_MECHANISM_INVALID);
	}


	ctx = (ENCR_DECR_CONTEXT *)malloc(sizeof (ENCR_DECR_CONTEXT));
	if (! ctx) {
		return (CKR_HOST_MEMORY);
	}
	(void) memset(ctx, 0x0, sizeof (ENCR_DECR_CONTEXT));

	rc = decr_mgr_init(sess, ctx, OP_UNWRAP, mech, h_unwrapping_key);
	if (rc != CKR_OK)
		return (rc);

	rc = decr_mgr_decrypt(sess,
	    TRUE, ctx, wrapped_key, wrapped_key_len,
	    data,	&data_len);
	if (rc != CKR_OK) {
		goto error;
	}
	data = (CK_BYTE *)malloc(data_len);
	if (! data) {
		rc = CKR_HOST_MEMORY;
		goto error;
	}

	rc = decr_mgr_decrypt(sess,
	    FALSE, ctx, wrapped_key, wrapped_key_len,
	    data,	&data_len);

	(void) decr_mgr_cleanup(ctx);
	free(ctx);

	if (rc != CKR_OK) {
		goto error;
	}
	/*
	 * if we use X.509, the data will be padded from the front with zeros.
	 * PKCS #11 specifies that for this mechanism, CK_VALUE is to be read
	 * from the end of the data.
	 *
	 * Note: the PKCS #11 reference implementation gets this wrong.
	 */
	if (mech->mechanism == CKM_RSA_X_509)
		fromend = TRUE;
	else
	fromend = FALSE;

	if (keyclass == CKO_PRIVATE_KEY) {
		rc = key_mgr_get_private_key_type(data, data_len, &keytype);
		if (rc != CKR_OK) {
			goto error;
		}
	}

	rc = object_mgr_create_skel(sess,
	    attributes,    attrib_count,
	    MODE_UNWRAP, keyclass,	keytype,
	    &key_obj);
	if (rc != CKR_OK) {
		goto error;
	}
	switch (keyclass) {
		case CKO_SECRET_KEY:
		rc = secret_key_unwrap(key_obj->template, keytype, data,
		    data_len, fromend);
		break;

		case CKO_PRIVATE_KEY:
		rc = priv_key_unwrap(key_obj->template, keytype,
		    data, data_len);
		break;

		default:
		rc = CKR_WRAPPED_KEY_INVALID;
		break;
	}

	if (rc != CKR_OK) {
		goto error;
	}
	rc = object_mgr_create_final(sess, key_obj, h_unwrapped_key);
	if (rc != CKR_OK) {
		goto error;
	}
	if (data) free(data);
	return (rc);

error:
	if (key_obj) (void) object_free(key_obj);
	if (data)    free(data);

	return (rc);
}
