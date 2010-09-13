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
encr_mgr_init(SESSION	   * sess,
	ENCR_DECR_CONTEXT * ctx,
	CK_ULONG	    operation,
	CK_MECHANISM	* mech,
	CK_OBJECT_HANDLE    key_handle)
{
	OBJECT	* key_obj = NULL;
	CK_ATTRIBUTE  * attr    = NULL;
	CK_BYTE	* ptr	= NULL;
	CK_KEY_TYPE	keytype;
	CK_BBOOL	flag;
	CK_RV	   rc;


	if (! sess || ! ctx || ! mech) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->active != FALSE) {
		return (CKR_OPERATION_ACTIVE);
	}

	if (operation == OP_ENCRYPT_INIT) {
		rc = object_mgr_find_in_map1(sess->hContext, key_handle,
		    &key_obj);
		if (rc != CKR_OK) {
			return (CKR_KEY_HANDLE_INVALID);
		}
		rc = template_attribute_find(key_obj->template,
		    CKA_ENCRYPT, &attr);
		if (rc == FALSE) {
			return (CKR_KEY_FUNCTION_NOT_PERMITTED);
		} else {
			flag = *(CK_BBOOL *)attr->pValue;
			if (flag != TRUE) {
				return (CKR_KEY_FUNCTION_NOT_PERMITTED);
			}
		}
	} else if (operation == OP_WRAP) {
		rc = object_mgr_find_in_map1(sess->hContext, key_handle,
		    &key_obj);
		if (rc != CKR_OK) {
			return (CKR_WRAPPING_KEY_HANDLE_INVALID);
		}
		rc = template_attribute_find(key_obj->template,
		    CKA_WRAP, &attr);
		if (rc == FALSE) {
			return (CKR_KEY_NOT_WRAPPABLE);
		} else {
			flag = *(CK_BBOOL *)attr->pValue;
			if (flag == FALSE) {
				return (CKR_KEY_NOT_WRAPPABLE);
			}
		}
	} else {
		return (CKR_FUNCTION_FAILED);
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

	ctx->key		 = key_handle;
	ctx->mech.ulParameterLen = mech->ulParameterLen;
	ctx->mech.mechanism	= mech->mechanism;
	ctx->mech.pParameter	= ptr;
	ctx->multi		= FALSE;
	ctx->active		= TRUE;

	return (CKR_OK);
}

CK_RV
encr_mgr_cleanup(ENCR_DECR_CONTEXT *ctx)
{
	if (! ctx) {
		return (CKR_FUNCTION_FAILED);
	}
	ctx->key		 = 0;
	ctx->mech.ulParameterLen = 0;
	ctx->mech.mechanism	= 0;
	ctx->multi		= FALSE;
	ctx->active		= FALSE;
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
encr_mgr_encrypt(SESSION	   *sess,
	CK_BBOOL	   length_only,
	ENCR_DECR_CONTEXT *ctx,
	CK_BYTE	   *in_data,
	CK_ULONG	   in_data_len,
	CK_BYTE	   *out_data,
	CK_ULONG	  *out_data_len)
{
	if (! sess || ! ctx) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->active == FALSE) {
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	if ((length_only == FALSE) && (! in_data || ! out_data)) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->multi == TRUE) {
		return (CKR_OPERATION_ACTIVE);
	}
	switch (ctx->mech.mechanism) {
		case CKM_RSA_PKCS:
			return (rsa_pkcs_encrypt(sess,	length_only,
			    ctx, in_data,  in_data_len, out_data,
			    out_data_len));

		default:
			return (CKR_MECHANISM_INVALID);
	}
}
