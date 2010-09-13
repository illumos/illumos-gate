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
sha1_hash(SESSION *sess,
	CK_BBOOL length_only,
	DIGEST_CONTEXT  *ctx,
	CK_BYTE	 *in_data,
	CK_ULONG in_data_len,
	CK_BYTE	 *out_data,
	CK_ULONG *out_data_len)
{
	if (! sess || ! ctx || ! out_data_len) {
		return (CKR_FUNCTION_FAILED);
	}
	*out_data_len = SHA1_DIGEST_LENGTH;
	if (length_only == TRUE) {
		return (CKR_OK);
	}

	if (ctx->context.sha1ctx == NULL)
		return (CKR_HOST_MEMORY);
	SHA1Update(ctx->context.sha1ctx, in_data, in_data_len);

	SHA1Final(out_data, ctx->context.sha1ctx);

	return (CKR_OK);
}

CK_RV
sha1_hmac_sign(SESSION		* sess,
	CK_BBOOL		length_only,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		* in_data,
	CK_ULONG		in_data_len,
	CK_BYTE		* out_data,
	CK_ULONG		* out_data_len) {
	OBJECT	  * key_obj = NULL;
	CK_ATTRIBUTE    * attr    = NULL;
	CK_BYTE	   hash[SHA1_DIGEST_LENGTH];
	DIGEST_CONTEXT    digest_ctx;
	CK_MECHANISM	digest_mech;
	CK_BYTE	   k_ipad[SHA1_BLOCK_SIZE];
	CK_BYTE	   k_opad[SHA1_BLOCK_SIZE];
	CK_ULONG	  key_bytes, hash_len, hmac_len;
	CK_ULONG	  i;
	CK_RV		rc;

	if (! sess || ! ctx || ! out_data_len) {
		return (CKR_FUNCTION_FAILED);
	}

	if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL) {
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

		if (hmac_len == 0) {
			*out_data_len = 0;
			return (CKR_OK);
		}
	} else {
		hmac_len = SHA1_DIGEST_LENGTH;
	}

	*out_data_len = hmac_len;
	if (length_only == TRUE) {
		return (CKR_OK);
	}

	(void) memset(&digest_ctx, 0x0, sizeof (DIGEST_CONTEXT));

	rc = object_mgr_find_in_map1(sess->hContext, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		return (rc);
	}
	rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		return (CKR_FUNCTION_FAILED);
	} else
		key_bytes = attr->ulValueLen;


	if (key_bytes > SHA1_BLOCK_SIZE) {
		digest_mech.mechanism	= CKM_SHA_1;
		digest_mech.ulParameterLen = 0;
		digest_mech.pParameter	= NULL;

		rc = digest_mgr_init(sess, &digest_ctx, &digest_mech);
		if (rc != CKR_OK) {
			(void) digest_mgr_cleanup(&digest_ctx);
			return (rc);
		}

		hash_len = sizeof (hash);
		rc = digest_mgr_digest(sess, FALSE, &digest_ctx,
		    attr->pValue, attr->ulValueLen, hash,  &hash_len);
		if (rc != CKR_OK) {
			(void) digest_mgr_cleanup(&digest_ctx);
			return (rc);
		}

		(void) digest_mgr_cleanup(&digest_ctx);
		(void) memset(&digest_ctx, 0x0, sizeof (DIGEST_CONTEXT));

		for (i = 0; i < hash_len; i++) {
			k_ipad[i] = hash[i] ^ 0x36;
			k_opad[i] = hash[i] ^ 0x5C;
		}

		(void) memset(&k_ipad[i], 0x36, SHA1_BLOCK_SIZE - i);
		(void) memset(&k_opad[i], 0x5C, SHA1_BLOCK_SIZE - i);
	} else {
		CK_BYTE *key = attr->pValue;

		for (i = 0; i < key_bytes; i++) {
			k_ipad[i] = key[i] ^ 0x36;
			k_opad[i] = key[i] ^ 0x5C;
		}

		(void) memset(&k_ipad[i], 0x36, SHA1_BLOCK_SIZE - key_bytes);
		(void) memset(&k_opad[i], 0x5C, SHA1_BLOCK_SIZE - key_bytes);
	}

	digest_mech.mechanism	= CKM_SHA_1;
	digest_mech.ulParameterLen = 0;
	digest_mech.pParameter	= NULL;

	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	rc = digest_mgr_digest_update(sess, &digest_ctx,
	    k_ipad, SHA1_BLOCK_SIZE);
	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	rc = digest_mgr_digest_update(sess, &digest_ctx, in_data, in_data_len);
	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	hash_len = sizeof (hash);
	rc = digest_mgr_digest_final(sess, &digest_ctx, hash, &hash_len);
	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	(void) digest_mgr_cleanup(&digest_ctx);
	(void) memset(&digest_ctx, 0x0, sizeof (DIGEST_CONTEXT));

	rc = digest_mgr_init(sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	rc = digest_mgr_digest_update(sess, &digest_ctx,
	    k_opad, SHA1_BLOCK_SIZE);
	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	rc = digest_mgr_digest_update(sess, &digest_ctx, hash, hash_len);
	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	hash_len = sizeof (hash);
	rc = digest_mgr_digest_final(sess, &digest_ctx, hash, &hash_len);
	if (rc != CKR_OK) {
		(void) digest_mgr_cleanup(&digest_ctx);
		return (rc);
	}

	(void) memcpy(out_data, hash, hmac_len);
	*out_data_len = hmac_len;

	(void) digest_mgr_cleanup(&digest_ctx);

	return (CKR_OK);
}

CK_RV
sha1_hmac_verify(SESSION *sess,
	SIGN_VERIFY_CONTEXT  *ctx,
	CK_BYTE	*in_data,
	CK_ULONG in_data_len,
	CK_BYTE	*signature,
	CK_ULONG sig_len)
{
	CK_BYTE		hmac[SHA1_DIGEST_LENGTH];
	SIGN_VERIFY_CONTEXT  hmac_ctx;
	CK_ULONG	hmac_len, len;
	CK_RV		rc;

	if (! sess || ! ctx || ! in_data || ! signature) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL)
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
	else
		hmac_len = SHA1_DIGEST_LENGTH;

	(void) memset(&hmac_ctx, 0, sizeof (SIGN_VERIFY_CONTEXT));

	rc = sign_mgr_init(sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		goto done;
	}
	len = sizeof (hmac);
	rc = sign_mgr_sign(sess, FALSE, &hmac_ctx,
	    in_data, in_data_len, hmac,   &len);
	if (rc != CKR_OK) {
		goto done;
	}
	if ((len != hmac_len) || (len != sig_len)) {
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto done;
	}

	if (memcmp(hmac, signature, hmac_len) != 0) {
		rc = CKR_SIGNATURE_INVALID;
	}
	done:
	(void) sign_mgr_cleanup(&hmac_ctx);
	return (rc);
}
