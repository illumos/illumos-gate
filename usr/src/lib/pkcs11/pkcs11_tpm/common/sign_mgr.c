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

CK_RV
sign_mgr_init(SESSION		* sess,
	SIGN_VERIFY_CONTEXT    * ctx,
	CK_MECHANISM	   * mech,
	CK_BBOOL		 recover_mode,
	CK_OBJECT_HANDLE	 key)
{
	OBJECT	  * key_obj = NULL;
	CK_ATTRIBUTE    * attr    = NULL;
	CK_BYTE	 * ptr	= NULL;
	CK_KEY_TYPE	keytype;
	CK_OBJECT_CLASS   class;
	CK_BBOOL	  flag;
	CK_RV		rc;


	if (! sess || ! ctx) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->active != FALSE) {
		return (CKR_OPERATION_ACTIVE);
	}

	rc = object_mgr_find_in_map1(sess->hContext, key, &key_obj);
	if (rc != CKR_OK) {
		return (CKR_KEY_HANDLE_INVALID);
	}
	rc = template_attribute_find(key_obj->template, CKA_SIGN, &attr);
	if (rc == FALSE) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	} else {
		flag = *(CK_BBOOL *)attr->pValue;
		if (flag != TRUE) {
			return (CKR_KEY_FUNCTION_NOT_PERMITTED);
		}
	}

	switch (mech->mechanism) {
		case CKM_RSA_PKCS:
		{
			if (mech->ulParameterLen != 0) {
				return (CKR_MECHANISM_PARAM_INVALID);
			}
			rc = template_attribute_find(key_obj->template,
			    CKA_KEY_TYPE, &attr);
			if (rc == FALSE) {
				return (CKR_KEY_TYPE_INCONSISTENT);
			} else {
				keytype = *(CK_KEY_TYPE *)attr->pValue;
				if (keytype != CKK_RSA) {
					return (CKR_KEY_TYPE_INCONSISTENT);
				}
			}

			// must be a PRIVATE key
			//
			flag = template_attribute_find(key_obj->template,
			    CKA_CLASS, &attr);
			if (flag == FALSE) {
				return (CKR_KEY_TYPE_INCONSISTENT);
			}
			else
				class = *(CK_OBJECT_CLASS *)attr->pValue;

			if (class != CKO_PRIVATE_KEY) {
				return (CKR_KEY_TYPE_INCONSISTENT);
			}
			// PKCS #11 doesn't allow multi - part RSA operations
			//
			ctx->context_len = 0;
			ctx->context	= NULL;
		}
		break;
		case CKM_MD5_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		{
			if (mech->ulParameterLen != 0) {
				return (CKR_MECHANISM_PARAM_INVALID);
			}
			rc = template_attribute_find(key_obj->template,
			    CKA_KEY_TYPE, &attr);
			if (rc == FALSE) {
				return (CKR_KEY_TYPE_INCONSISTENT);
			} else {
				keytype = *(CK_KEY_TYPE *)attr->pValue;
				if (keytype != CKK_RSA) {
					return (CKR_KEY_TYPE_INCONSISTENT);
				}
			}

			// must be a PRIVATE key operation
			//
			flag = template_attribute_find(key_obj->template,
			    CKA_CLASS, &attr);
			if (flag == FALSE) {
				return (CKR_FUNCTION_FAILED);
			}
			else
				class = *(CK_OBJECT_CLASS *)attr->pValue;

			if (class != CKO_PRIVATE_KEY) {
				return (CKR_FUNCTION_FAILED);
			}
			ctx->context_len = sizeof (RSA_DIGEST_CONTEXT);
			ctx->context = (CK_BYTE *)malloc(
			    sizeof (RSA_DIGEST_CONTEXT));
			if (! ctx->context) {
				return (CKR_HOST_MEMORY);
			}
			(void) memset(ctx->context, 0x0,
			    sizeof (RSA_DIGEST_CONTEXT));
		}
		break;
		case CKM_MD5_HMAC:
		case CKM_SHA_1_HMAC:
		{
			if (mech->ulParameterLen != 0) {
				return (CKR_MECHANISM_PARAM_INVALID);
			}
			rc = template_attribute_find(key_obj->template,
			    CKA_KEY_TYPE, &attr);
			if (rc == FALSE) {
				return (CKR_KEY_TYPE_INCONSISTENT);
			} else {
				keytype = *(CK_KEY_TYPE *)attr->pValue;
				if (keytype != CKK_GENERIC_SECRET) {
					return (CKR_KEY_TYPE_INCONSISTENT);
				}
			}

			// PKCS #11 doesn't allow multi - part HMAC operations
			//
			ctx->context_len = 0;
			ctx->context	= NULL;
		}
		break;

		case CKM_MD5_HMAC_GENERAL:
		case CKM_SHA_1_HMAC_GENERAL:
		{
			CK_MAC_GENERAL_PARAMS *param =
			    (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

			if (mech->ulParameterLen !=
			    sizeof (CK_MAC_GENERAL_PARAMS)) {
				return (CKR_MECHANISM_PARAM_INVALID);
			}

			if ((mech->mechanism == CKM_MD5_HMAC_GENERAL) &&
			    (*param > 16)) {
				return (CKR_MECHANISM_PARAM_INVALID);
			}
			if ((mech->mechanism == CKM_SHA_1_HMAC_GENERAL) &&
			    (*param > 20)) {
				return (CKR_MECHANISM_PARAM_INVALID);
			}
			rc = template_attribute_find(key_obj->template,
			    CKA_KEY_TYPE, &attr);
			if (rc == FALSE) {
				return (CKR_KEY_TYPE_INCONSISTENT);
			} else {
				keytype = *(CK_KEY_TYPE *)attr->pValue;
				if (keytype != CKK_GENERIC_SECRET) {
					return (CKR_KEY_TYPE_INCONSISTENT);
				}
			}

			// PKCS #11 doesn't allow multi - part HMAC operations
			//
			ctx->context_len = 0;
			ctx->context	= NULL;
		}
		break;
		default:
			return (CKR_MECHANISM_INVALID);
	}


	if (mech->ulParameterLen > 0) {
		ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
		if (! ptr) {
			return (CKR_HOST_MEMORY);
		}
		(void) memcpy(ptr, mech->pParameter, mech->ulParameterLen);
	}

	ctx->key		 = key;
	ctx->mech.ulParameterLen = mech->ulParameterLen;
	ctx->mech.mechanism	= mech->mechanism;
	ctx->mech.pParameter	= ptr;
	ctx->multi		= FALSE;
	ctx->active		= TRUE;
	ctx->recover		= recover_mode;

	return (CKR_OK);
}

CK_RV
sign_mgr_cleanup(SIGN_VERIFY_CONTEXT *ctx)
{
	if (! ctx) {
		return (CKR_FUNCTION_FAILED);
	}
	ctx->key		 = 0;
	ctx->mech.ulParameterLen = 0;
	ctx->mech.mechanism	= 0;
	ctx->multi		= FALSE;
	ctx->active		= FALSE;
	ctx->recover		= FALSE;
	ctx->context_len	 = 0;

	if (ctx->mech.pParameter) {
		free(ctx->mech.pParameter);
		ctx->mech.pParameter = NULL;
	}

	if (ctx->context) {
		free(ctx->context);
		ctx->context = NULL;
	}

	return (CKR_OK);
}

CK_RV
sign_mgr_sign(SESSION	* sess,
	CK_BBOOL	length_only,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		* in_data,
	CK_ULONG	in_data_len,
	CK_BYTE		* out_data,
	CK_ULONG	* out_data_len)
{
	if (! sess || ! ctx) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->active == FALSE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	if (ctx->recover == TRUE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	// if the caller just wants the signature length, there is no reason to
	// specify the input data.  I just need the input data length
	//
	if ((length_only == FALSE) && (! in_data || ! out_data)) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->multi == TRUE) {
		return (CKR_OPERATION_ACTIVE);
	}
	switch (ctx->mech.mechanism) {
		case CKM_RSA_PKCS:
		return (rsa_pkcs_sign(sess,	length_only,  ctx,
		    in_data,  in_data_len,
		    out_data, out_data_len));
		case CKM_MD5_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		return (rsa_hash_pkcs_sign(sess,	length_only, ctx,
		    in_data,  in_data_len,
		    out_data, out_data_len));

		case CKM_MD5_HMAC:
		case CKM_MD5_HMAC_GENERAL:
		return (md5_hmac_sign(sess,	length_only, ctx,
		    in_data,  in_data_len,
		    out_data, out_data_len));
		case CKM_SHA_1_HMAC:
		case CKM_SHA_1_HMAC_GENERAL:
		return (sha1_hmac_sign(sess,	length_only, ctx,
		    in_data,  in_data_len,
		    out_data, out_data_len));
		default:
			return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
sign_mgr_sign_update(SESSION		* sess,
	SIGN_VERIFY_CONTEXT * ctx,
	CK_BYTE		* in_data,
	CK_ULONG		in_data_len)
{
	if (! sess || ! ctx || ! in_data) {
		return (CKR_FUNCTION_FAILED);
	}

	if (ctx->active == FALSE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	if (ctx->recover == TRUE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	ctx->multi = TRUE;

	switch (ctx->mech.mechanism) {
		case CKM_MD5_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
			return (rsa_hash_pkcs_sign_update(sess, ctx,
			    in_data, in_data_len));
		default:
			return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
sign_mgr_sign_final(SESSION		* sess,
	CK_BBOOL		length_only,
	SIGN_VERIFY_CONTEXT * ctx,
	CK_BYTE		* signature,
	CK_ULONG	    * sig_len)
{
	if (! sess || ! ctx) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->active == FALSE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	if (ctx->recover == TRUE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	switch (ctx->mech.mechanism) {
		case CKM_MD5_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
			return (rsa_hash_pkcs_sign_final(sess, length_only,
			    ctx, signature, sig_len));
		default:
		return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
sign_mgr_sign_recover(SESSION		* sess,
	CK_BBOOL		length_only,
	SIGN_VERIFY_CONTEXT * ctx,
	CK_BYTE		* in_data,
	CK_ULONG		in_data_len,
	CK_BYTE		* out_data,
	CK_ULONG	    * out_data_len)
{
	if (! sess || ! ctx) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->active == FALSE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	if (ctx->recover == FALSE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	// if the caller just wants the signature length, there is no reason to
	// specify the input data.  I just need the input data length
	//
	if ((length_only == FALSE) && (! in_data || ! out_data)) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->multi == TRUE) {
		return (CKR_OPERATION_ACTIVE);
	}
	switch (ctx->mech.mechanism) {
		case CKM_RSA_PKCS:
			return (rsa_pkcs_sign(sess,	length_only,  ctx,
			    in_data,  in_data_len,
			    out_data, out_data_len));
		default:
			return (CKR_MECHANISM_INVALID);
	}
}
