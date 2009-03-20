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
ckm_rsa_key_pair_gen(TSS_HCONTEXT hContext,
	TEMPLATE  * publ_tmpl,
	TEMPLATE  * priv_tmpl)
{
	CK_RV		rc;

	rc = token_specific.t_rsa_generate_keypair(
	    hContext, publ_tmpl, priv_tmpl);

	return (rc);
}

static CK_RV
ckm_rsa_encrypt(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG  * out_data_len,
	OBJECT    * key_obj)
{
	CK_ATTRIBUTE	* attr    = NULL;
	CK_OBJECT_CLASS	keyclass;
	CK_RV		rc;

	rc = template_attribute_find(key_obj->template, CKA_CLASS, &attr);
	if (rc == FALSE) {
		return (CKR_FUNCTION_FAILED);
	} else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	if (keyclass != CKO_PUBLIC_KEY) {
		return (CKR_FUNCTION_FAILED);
	}

	rc = token_specific.t_rsa_encrypt(hContext,
	    in_data, in_data_len,
	    out_data, out_data_len, key_obj);

	return (rc);
}

static CK_RV
ckm_rsa_decrypt(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG  * out_data_len,
	OBJECT    * key_obj) {
	CK_ATTRIBUTE	* attr	= NULL;
	CK_OBJECT_CLASS	keyclass;
	CK_RV		rc;


	rc = template_attribute_find(key_obj->template, CKA_CLASS, &attr);
	if (rc == FALSE) {
		return (CKR_FUNCTION_FAILED);
	}
	else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	// this had better be a private key
	//
	if (keyclass != CKO_PRIVATE_KEY) {
		return (CKR_FUNCTION_FAILED);
	}
	rc = token_specific.t_rsa_decrypt(hContext,
	    in_data, in_data_len,
	    out_data, out_data_len, key_obj);

	return (rc);
}

static CK_RV
ckm_rsa_sign(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG  * out_data_len,
	OBJECT    * key_obj) {
	CK_ATTRIBUTE	* attr	= NULL;
	CK_OBJECT_CLASS	keyclass;
	CK_RV		rc;


	rc = template_attribute_find(key_obj->template, CKA_CLASS, &attr);
	if (rc == FALSE) {
		return (CKR_FUNCTION_FAILED);
	}
	else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	// this had better be a private key
	//
	if (keyclass != CKO_PRIVATE_KEY) {
		return (CKR_FUNCTION_FAILED);
	}
	rc = token_specific.t_rsa_sign(
	    hContext, in_data, in_data_len, out_data,
	    out_data_len, key_obj);

	return (rc);
}

static CK_RV
ckm_rsa_verify(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG    out_data_len,
	OBJECT    * key_obj) {
	CK_ATTRIBUTE	* attr	= NULL;
	CK_OBJECT_CLASS	keyclass;
	CK_RV		rc;


	rc = template_attribute_find(key_obj->template, CKA_CLASS, &attr);
	if (rc == FALSE) {
		return (CKR_FUNCTION_FAILED);
	}
	else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	if (keyclass != CKO_PUBLIC_KEY) {
		return (CKR_FUNCTION_FAILED);
	}
	rc = token_specific.t_rsa_verify(hContext,
	    in_data, in_data_len, out_data,
	    out_data_len, key_obj);

	return (rc);
}

/*ARGSUSED*/
CK_RV
rsa_pkcs_encrypt(SESSION	   *sess,
	CK_BBOOL	   length_only,
	ENCR_DECR_CONTEXT *ctx,
	CK_BYTE	   *in_data,
	CK_ULONG	   in_data_len,
	CK_BYTE	   *out_data,
	CK_ULONG	  *out_data_len) {
	OBJECT	  *key_obj  = NULL;
	CK_ATTRIBUTE    *attr	= NULL;
	CK_ULONG	 modulus_bytes;
	CK_BBOOL	 flag;
	CK_RV	    rc;


	rc = object_mgr_find_in_map1(sess->hContext, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		return (rc);
	}
	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		return (CKR_FUNCTION_FAILED);
	}
	else
		modulus_bytes = attr->ulValueLen;

	if (in_data_len > (modulus_bytes - 11)) {
		return (CKR_DATA_LEN_RANGE);
	}

	if (length_only == TRUE) {
		 *out_data_len = modulus_bytes;
		return (CKR_OK);
	}

	if (*out_data_len < modulus_bytes) {
		 *out_data_len = modulus_bytes;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rc = ckm_rsa_encrypt(sess->hContext, in_data, in_data_len, out_data,
	    out_data_len, key_obj);
	return (rc);
}

/*ARGSUSED*/
CK_RV
rsa_pkcs_decrypt(SESSION	   *sess,
	CK_BBOOL	   length_only,
	ENCR_DECR_CONTEXT *ctx,
	CK_BYTE	   *in_data,
	CK_ULONG	   in_data_len,
	CK_BYTE	   *out_data,
	CK_ULONG	  *out_data_len)
{
	OBJECT	  *key_obj  = NULL;
	CK_ATTRIBUTE    *attr	= NULL;
	CK_ULONG	 modulus_bytes;
	CK_BBOOL	 flag;
	CK_RV	    rc;


	rc = object_mgr_find_in_map1(sess->hContext, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		return (rc);
	}
	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE)
		return (CKR_FUNCTION_FAILED);
	else
		modulus_bytes = attr->ulValueLen;

	if (in_data_len != modulus_bytes) {
		return (CKR_ENCRYPTED_DATA_LEN_RANGE);
	}
	if (length_only == TRUE) {
		*out_data_len = modulus_bytes - 11;
		return (CKR_OK);
	}

	rc = ckm_rsa_decrypt(sess->hContext, in_data,
	    modulus_bytes, out_data,
	    out_data_len, key_obj);

	if (rc == CKR_DATA_LEN_RANGE) {
		return (CKR_ENCRYPTED_DATA_LEN_RANGE);
	}
	return (rc);
}

CK_RV
rsa_pkcs_sign(SESSION		*sess,
	CK_BBOOL		length_only,
	SIGN_VERIFY_CONTEXT *ctx,
	CK_BYTE		*in_data,
	CK_ULONG		in_data_len,
	CK_BYTE		*out_data,
	CK_ULONG	    *out_data_len)
{
	OBJECT	  *key_obj   = NULL;
	CK_ATTRIBUTE    *attr	= NULL;
	CK_ULONG	 modulus_bytes;
	CK_BBOOL	 flag;
	CK_RV	    rc;


	if (! sess || ! ctx || ! out_data_len) {
		return (CKR_FUNCTION_FAILED);
	}
	rc = object_mgr_find_in_map1(sess->hContext, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		return (rc);
	}
	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE)
		return (CKR_FUNCTION_FAILED);
	else
		modulus_bytes = attr->ulValueLen;

	if (in_data_len > modulus_bytes - 11) {
		return (CKR_DATA_LEN_RANGE);
	}
	if (length_only == TRUE) {
		*out_data_len = modulus_bytes;
		return (CKR_OK);
	}

	if (*out_data_len < modulus_bytes) {
		*out_data_len = modulus_bytes;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rc = ckm_rsa_sign(sess->hContext, in_data, in_data_len, out_data,
	    out_data_len, key_obj);
	return (rc);
}

/*ARGSUSED*/
CK_RV
rsa_pkcs_verify(SESSION		* sess,
	SIGN_VERIFY_CONTEXT * ctx,
	CK_BYTE		* in_data,
	CK_ULONG		in_data_len,
	CK_BYTE		* signature,
	CK_ULONG		sig_len)
{
	OBJECT	  *key_obj  = NULL;
	CK_ATTRIBUTE    *attr	= NULL;
	CK_ULONG	 modulus_bytes;
	CK_BBOOL	 flag;
	CK_RV	    rc;

	rc = object_mgr_find_in_map1(sess->hContext, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		return (rc);
	}
	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		return (CKR_FUNCTION_FAILED);
	}
	else
		modulus_bytes = attr->ulValueLen;

	// check input data length restrictions
	//
	if (sig_len != modulus_bytes) {
		return (CKR_SIGNATURE_LEN_RANGE);
	}
	// verify is a public key operation --> encrypt
	//
	rc = ckm_rsa_verify(sess->hContext, in_data, in_data_len, signature,
	    sig_len, key_obj);

	return (rc);
}

CK_RV
rsa_pkcs_verify_recover(SESSION		* sess,
	CK_BBOOL		length_only,
	SIGN_VERIFY_CONTEXT * ctx,
	CK_BYTE		* signature,
	CK_ULONG		sig_len,
	CK_BYTE		* out_data,
	CK_ULONG	    * out_data_len)
{
	OBJECT	  *key_obj  = NULL;
	CK_ATTRIBUTE    *attr	= NULL;
	CK_ULONG	 modulus_bytes;
	CK_BBOOL	 flag;
	CK_RV	    rc;

	if (! sess || ! ctx || ! out_data_len) {
		return (CKR_FUNCTION_FAILED);
	}
	rc = object_mgr_find_in_map1(sess->hContext, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		return (rc);
	}
	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		return (CKR_FUNCTION_FAILED);
	}
	else
		modulus_bytes = attr->ulValueLen;

	if (sig_len != modulus_bytes) {
		return (CKR_SIGNATURE_LEN_RANGE);
	}
	if (length_only == TRUE) {
		*out_data_len = modulus_bytes;
		return (CKR_OK);
	}

	rc = ckm_rsa_encrypt(sess->hContext, signature, modulus_bytes, out_data,
	    out_data_len, key_obj);

	return (rc);
}

CK_RV
rsa_hash_pkcs_sign(SESSION		* sess,
	CK_BBOOL		length_only,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		* in_data,
	CK_ULONG		in_data_len,
	CK_BYTE		* signature,
	CK_ULONG		* sig_len)
{
	CK_BYTE	    * ber_data  = NULL;
	CK_BYTE	    * octet_str = NULL;
	CK_BYTE	    * oid	= NULL;
	CK_BYTE	    * tmp	= NULL;

	CK_ULONG		buf1[16];

	CK_BYTE		hash[SHA1_DIGEST_LENGTH];
	DIGEST_CONTEXT	digest_ctx;
	SIGN_VERIFY_CONTEXT  sign_ctx;
	CK_MECHANISM	 digest_mech;
	CK_MECHANISM	 sign_mech;
	CK_ULONG	ber_data_len, hash_len, octet_str_len, oid_len;
	CK_RV		rc;

	if (! sess || ! ctx || ! in_data) {
		return (CKR_FUNCTION_FAILED);
	}
	(void) memset(&digest_ctx, 0x0, sizeof (digest_ctx));
	(void) memset(&sign_ctx,   0x0, sizeof (sign_ctx));

	if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
		digest_mech.mechanism	= CKM_MD5;
		oid = ber_AlgMd5;
		oid_len = ber_AlgMd5Len;
		hash_len = MD5_DIGEST_LENGTH;
	} else {
		digest_mech.mechanism	= CKM_SHA_1;
		oid = ber_AlgSha1;
		oid_len = ber_AlgSha1Len;
		hash_len = SHA1_DIGEST_LENGTH;
	}

	digest_mech.ulParameterLen = 0;
	digest_mech.pParameter	= NULL;

	rc = digest_mgr_init(sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		goto error;
	}
	rc = digest_mgr_digest(sess, length_only, &digest_ctx, in_data,
	    in_data_len, hash, &hash_len);
	if (rc != CKR_OK)
		goto error;

	rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len,
	    hash, hash_len);
	if (rc != CKR_OK) {
		goto error;
	}
	tmp = (CK_BYTE *)buf1;
	(void) memcpy(tmp,	   oid,	oid_len);
	(void) memcpy(tmp + oid_len, octet_str, octet_str_len);

	rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len,
	    tmp, (oid_len + octet_str_len));
	if (rc != CKR_OK)
		goto error;

	sign_mech.mechanism	= CKM_RSA_PKCS;
	sign_mech.ulParameterLen = 0;
	sign_mech.pParameter	= NULL;

	rc = sign_mgr_init(sess, &sign_ctx, &sign_mech, FALSE, ctx->key);
	if (rc != CKR_OK)
		goto error;

	rc = sign_mgr_sign(sess, length_only, &sign_ctx, ber_data,
	    ber_data_len, signature, sig_len);

error:
	if (octet_str) free(octet_str);
	if (ber_data)  free(ber_data);
	(void) digest_mgr_cleanup(&digest_ctx);
	(void) sign_mgr_cleanup(&sign_ctx);
	return (rc);
}

CK_RV
rsa_hash_pkcs_sign_update(
	SESSION		* sess,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		* in_data,
	CK_ULONG		in_data_len)
{
	RSA_DIGEST_CONTEXT  * context = NULL;
	CK_MECHANISM	  digest_mech;
	CK_RV		 rc;

	if (! sess || ! ctx || ! in_data)
		return (CKR_FUNCTION_FAILED);

	context = (RSA_DIGEST_CONTEXT *)ctx->context;

	if (context->flag == FALSE) {
		if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS)
			digest_mech.mechanism = CKM_MD5;
		else
			digest_mech.mechanism = CKM_SHA_1;

		digest_mech.ulParameterLen = 0;
		digest_mech.pParameter	= NULL;

		rc = digest_mgr_init(sess, &context->hash_context,
		    &digest_mech);
		if (rc != CKR_OK) {
			goto error;
		}
		context->flag = TRUE;
	}

	rc = digest_mgr_digest_update(sess, &context->hash_context,
	    in_data, in_data_len);
	if (rc != CKR_OK) {
		goto error;
	}
	return (CKR_OK);
error:
	(void) digest_mgr_cleanup(&context->hash_context);
	return (rc);
}

CK_RV
rsa_hash_pkcs_verify(SESSION		* sess,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		* in_data,
	CK_ULONG		in_data_len,
	CK_BYTE		* signature,
	CK_ULONG		sig_len)
{
	CK_BYTE	    * ber_data  = NULL;
	CK_BYTE	    * octet_str = NULL;
	CK_BYTE	    * oid	= NULL;
	CK_BYTE	    * tmp	= NULL;

	CK_ULONG	buf1[16];
	CK_BYTE		hash[SHA1_DIGEST_LENGTH];
	DIGEST_CONTEXT	digest_ctx;
	SIGN_VERIFY_CONTEXT  verify_ctx;
	CK_MECHANISM	 digest_mech;
	CK_MECHANISM	 verify_mech;
	CK_ULONG	ber_data_len, hash_len, octet_str_len, oid_len;
	CK_RV		rc;

	if (! sess || ! ctx || ! in_data) {
		return (CKR_FUNCTION_FAILED);
	}
	(void) memset(&digest_ctx, 0x0, sizeof (digest_ctx));
	(void) memset(&verify_ctx, 0x0, sizeof (verify_ctx));

	if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
		digest_mech.mechanism	= CKM_MD5;
		oid = ber_AlgMd5;
		oid_len = ber_AlgMd5Len;
		hash_len = MD5_DIGEST_LENGTH;
	} else {
		digest_mech.mechanism	= CKM_SHA_1;
		oid = ber_AlgSha1;
		oid_len = ber_AlgSha1Len;
		hash_len = SHA1_DIGEST_LENGTH;
	}

	digest_mech.ulParameterLen = 0;
	digest_mech.pParameter	= NULL;

	rc = digest_mgr_init(sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		goto done;
	}
	rc = digest_mgr_digest(sess, FALSE, &digest_ctx, in_data,
	    in_data_len, hash, &hash_len);
	if (rc != CKR_OK) {
		goto done;
	}
	rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len,
	    hash, hash_len);
	if (rc != CKR_OK)
		goto done;
	tmp = (CK_BYTE *)buf1;
	(void) memcpy(tmp,   oid, oid_len);
	(void) memcpy(tmp + oid_len, octet_str, octet_str_len);

	rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len, tmp,
	    (oid_len + octet_str_len));
	if (rc != CKR_OK) {
		goto done;
	}

	verify_mech.mechanism	= CKM_RSA_PKCS;
	verify_mech.ulParameterLen = 0;
	verify_mech.pParameter	= NULL;

	rc = verify_mgr_init(sess, &verify_ctx, &verify_mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		goto done;
	}
	rc = verify_mgr_verify(sess, &verify_ctx, ber_data,
	    ber_data_len, signature, sig_len);
done:
	if (octet_str) free(octet_str);
	if (ber_data)  free(ber_data);

	(void) digest_mgr_cleanup(&digest_ctx);
	(void) sign_mgr_cleanup(&verify_ctx);
	return (rc);
}

CK_RV
rsa_hash_pkcs_verify_update(SESSION		* sess,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		*in_data,
	CK_ULONG	in_data_len)
{
	RSA_DIGEST_CONTEXT  * context = NULL;
	CK_MECHANISM	  digest_mech;
	CK_RV		 rc;

	if (! sess || ! ctx || ! in_data) {
		return (CKR_FUNCTION_FAILED);
	}
	context = (RSA_DIGEST_CONTEXT *)ctx->context;

	if (context->flag == FALSE) {
		if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS)
			digest_mech.mechanism = CKM_MD5;
		else
			digest_mech.mechanism = CKM_SHA_1;

		digest_mech.ulParameterLen = 0;
		digest_mech.pParameter	= NULL;

		rc = digest_mgr_init(sess, &context->hash_context,
		    &digest_mech);
		if (rc != CKR_OK)
			goto error;
		context->flag = TRUE;
	}

	rc = digest_mgr_digest_update(sess, &context->hash_context,
	    in_data, in_data_len);
	if (rc != CKR_OK)
		goto error;
	return (CKR_OK);
error:
	(void) digest_mgr_cleanup(&context->hash_context);
	return (rc);
}

CK_RV
rsa_hash_pkcs_sign_final(SESSION		* sess,
	CK_BBOOL	length_only,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		* signature,
	CK_ULONG	* sig_len)
{
	CK_BYTE	    * ber_data  = NULL;
	CK_BYTE	    * octet_str = NULL;
	CK_BYTE	    * oid	= NULL;
	CK_BYTE	    * tmp	= NULL;

	CK_ULONG buf1[16];
	CK_BYTE		hash[SHA1_DIGEST_LENGTH];
	RSA_DIGEST_CONTEXT  * context = NULL;
	CK_ULONG	ber_data_len, hash_len, octet_str_len, oid_len;
	CK_MECHANISM  sign_mech;
	SIGN_VERIFY_CONTEXT   sign_ctx;
	CK_RV		 rc;

	if (! sess || ! ctx || ! sig_len) {
		return (CKR_FUNCTION_FAILED);
	}

	if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
		oid = ber_AlgMd5;
		oid_len = ber_AlgMd5Len;
		hash_len = MD5_DIGEST_LENGTH;
	} else {
		oid = ber_AlgSha1;
		oid_len = ber_AlgSha1Len;
		hash_len = SHA1_DIGEST_LENGTH;
	}

	(void) memset(&sign_ctx, 0x0, sizeof (sign_ctx));

	context = (RSA_DIGEST_CONTEXT *)ctx->context;

	rc = digest_mgr_digest_final(sess,
	    &context->hash_context, hash, &hash_len);
	if (rc != CKR_OK) {
		goto done;
	}

	rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len,
	    hash, hash_len);
	if (rc != CKR_OK) {
		goto done;
	}
	tmp = (CK_BYTE *)buf1;
	(void) memcpy(tmp,  oid, oid_len);
	(void) memcpy(tmp + oid_len, octet_str, octet_str_len);

	rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len,
	    tmp, (oid_len + octet_str_len));
	if (rc != CKR_OK) {
		goto done;
	}
	sign_mech.mechanism	= CKM_RSA_PKCS;
	sign_mech.ulParameterLen = 0;
	sign_mech.pParameter	= NULL;

	rc = sign_mgr_init(sess, &sign_ctx, &sign_mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		goto done;
	}
	rc = sign_mgr_sign(sess, length_only, &sign_ctx, ber_data,
	    ber_data_len, signature, sig_len);

	if (length_only == TRUE || rc == CKR_BUFFER_TOO_SMALL) {
		(void) sign_mgr_cleanup(&sign_ctx);
		return (rc);
	}

done:
	if (octet_str) free(octet_str);
	if (ber_data)  free(ber_data);

	(void) digest_mgr_cleanup(&context->hash_context);
	(void) sign_mgr_cleanup(&sign_ctx);
	return (rc);
}

CK_RV
rsa_hash_pkcs_verify_final(SESSION		* sess,
	SIGN_VERIFY_CONTEXT  * ctx,
	CK_BYTE		* signature,
	CK_ULONG		sig_len)
{
	CK_BYTE	    * ber_data  = NULL;
	CK_BYTE	    * octet_str = NULL;
	CK_BYTE	    * oid	= NULL;
	CK_BYTE	    * tmp	= NULL;

	CK_ULONG	buf1[16];
	CK_BYTE		hash[SHA1_DIGEST_LENGTH];
	RSA_DIGEST_CONTEXT  * context = NULL;
	CK_ULONG	ber_data_len, hash_len, octet_str_len, oid_len;
	CK_MECHANISM	  verify_mech;
	SIGN_VERIFY_CONTEXT   verify_ctx;
	CK_RV		 rc;

	if (! sess || ! ctx || ! signature) {
		return (CKR_FUNCTION_FAILED);
	}
	if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
		oid = ber_AlgMd5;
		oid_len = ber_AlgMd5Len;
		hash_len = MD5_DIGEST_LENGTH;
	} else {
		oid = ber_AlgSha1;
		oid_len = ber_AlgSha1Len;
		hash_len = SHA1_DIGEST_LENGTH;
	}

	(void) memset(&verify_ctx, 0x0, sizeof (verify_ctx));

	context = (RSA_DIGEST_CONTEXT *)ctx->context;

	rc = digest_mgr_digest_final(sess, &context->hash_context,
	    hash, &hash_len);
	if (rc != CKR_OK) {
		goto done;
	}
	rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len,
	    hash, hash_len);
	if (rc != CKR_OK) {
		goto done;
	}
	tmp = (CK_BYTE *)buf1;
	(void) memcpy(tmp, oid, oid_len);
	(void) memcpy(tmp + oid_len, octet_str, octet_str_len);

	rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len,
	    tmp, (oid_len + octet_str_len));
	if (rc != CKR_OK) {
		goto done;
	}
	verify_mech.mechanism	= CKM_RSA_PKCS;
	verify_mech.ulParameterLen = 0;
	verify_mech.pParameter	= NULL;

	rc = verify_mgr_init(sess, &verify_ctx, &verify_mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		goto done;
	}
	rc = verify_mgr_verify(sess, &verify_ctx, ber_data,
	    ber_data_len, signature, sig_len);
done:
	if (octet_str) free(octet_str);
	if (ber_data)  free(ber_data);
	(void) digest_mgr_cleanup(&context->hash_context);
	(void) verify_mgr_cleanup(&verify_ctx);
	return (rc);
}
