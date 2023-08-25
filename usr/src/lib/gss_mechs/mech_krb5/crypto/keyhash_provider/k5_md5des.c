/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "des_int.h"
#include "keyhash_provider.h"

#define CONFLENGTH 8

/* Force acceptance of krb5-beta5 md5des checksum for now. */
#define KRB5_MD5DES_BETA5_COMPAT

/* des-cbc(xorkey, conf | rsa-md5(conf | data)) */

/* this could be done in terms of the md5 and des providers, but
   that's less efficient, and there's no need for this to be generic */

/*ARGSUSED*/
static krb5_error_code
k5_md5des_hash(krb5_context context, krb5_const krb5_keyblock *key,
	       krb5_keyusage usage, const krb5_data *ivec,
	       const krb5_data *input, krb5_data *output)
{
    krb5_error_code ret = 0;
    krb5_data data;
    unsigned char conf[CONFLENGTH];
    krb5_keyblock xorkey;
    int i;
    CK_MECHANISM mechanism;
    CK_RV rv;
    CK_ULONG hashlen = MD5_CKSUM_LENGTH;

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if (ivec)
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length != (CONFLENGTH+MD5_CKSUM_LENGTH))
	return(KRB5_CRYPTO_INTERNAL);

    /* create the confouder */

    data.length = CONFLENGTH;
    data.data = (char *) conf;
    if ((ret = krb5_c_random_make_octets(context, &data)))
	return(ret);

    xorkey.magic = key->magic;
    xorkey.enctype = key->enctype;
    xorkey.length = key->length;
    xorkey.contents = (krb5_octet *)malloc(key->length);
    if (xorkey.contents == NULL)
	return(KRB5_CRYPTO_INTERNAL);

    (void) memcpy(xorkey.contents, key->contents, xorkey.length);

    for (i=0; i<xorkey.length; i++)
	xorkey.contents[i] ^= 0xf0;

    if (!mit_des_check_key_parity(xorkey.contents)) {
	ret = KRB5DES_BAD_KEYPAR;
	goto cleanup;
    }

    if (mit_des_is_weak_key(xorkey.contents)) {
	ret = KRB5DES_WEAK_KEY;
	goto cleanup;
    }

    /* hash the confounder, then the input data */
    mechanism.mechanism = CKM_MD5;
    mechanism.pParameter = NULL_PTR;
    mechanism.ulParameterLen = 0;

    if ((rv = C_DigestInit(krb_ctx_hSession(context), &mechanism)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestInit failed in k5_md5des_hash: "
	"rv = 0x%x.", rv);
	ret = PKCS_ERR;
	goto cleanup;
    }

    if ((rv = C_DigestUpdate(krb_ctx_hSession(context),
	(CK_BYTE_PTR)conf, (CK_ULONG)sizeof(conf))) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestUpdate failed in k5_md5des_hash: "
	    "rv = 0x%x", rv);
	ret = PKCS_ERR;
	goto cleanup;
    }

    if ((rv = C_DigestUpdate(krb_ctx_hSession(context),
	(CK_BYTE_PTR)input->data, (CK_ULONG)input->length)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestUpdate failed in k5_md5des_hash: "
	    "rv = 0x%x", rv);
	return(PKCS_ERR);
    }

    if ((rv = C_DigestFinal(krb_ctx_hSession(context),
	(CK_BYTE_PTR)(output->data + CONFLENGTH),
	(CK_ULONG_PTR)&hashlen)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestFinal failed in k5_md5des_hash: "
	    "rv = 0x%x", rv);
	ret = PKCS_ERR;
	goto cleanup;
    }

    /* construct the buffer to be encrypted */

    (void) memcpy(output->data, conf, CONFLENGTH);

    /* encrypt it, in place.  this has a return value, but it's
       always zero.  */

    ret = mit_des_cbc_encrypt(context,
	(krb5_pointer) output->data,
	(krb5_pointer) output->data, output->length,
	&xorkey, (unsigned char*) mit_des_zeroblock, 1);

cleanup:
    free(xorkey.contents);
    return(ret);
}

/*ARGSUSED*/
static krb5_error_code
k5_md5des_verify(krb5_context context,
	krb5_const krb5_keyblock *key,
	krb5_keyusage usage,
	krb5_const krb5_data *ivec,
	krb5_const krb5_data *input,
	krb5_const krb5_data *hash,
	krb5_boolean *valid)
{
    krb5_error_code ret = 0;
    unsigned char plaintext[CONFLENGTH+MD5_CKSUM_LENGTH];
    unsigned char digest[MD5_CKSUM_LENGTH];
    krb5_keyblock xorkey;
    int i;
    int compathash = 0;
    CK_MECHANISM mechanism;
    CK_RV rv;
    CK_ULONG hashlen = MD5_CKSUM_LENGTH;

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if (ivec)
	return(KRB5_CRYPTO_INTERNAL);
    if (hash->length != (CONFLENGTH + MD5_CKSUM_LENGTH)) {
#ifdef KRB5_MD5DES_BETA5_COMPAT
	if (hash->length != MD5_CKSUM_LENGTH)
	    return(KRB5_CRYPTO_INTERNAL);
	else
	    compathash = 1;
#else
	return(KRB5_CRYPTO_INTERNAL);
#endif
    }

    /* create and the encryption key */
    xorkey.magic = key->magic;
    xorkey.enctype = key->enctype;
    xorkey.length = key->length;
    xorkey.contents = (krb5_octet *)malloc(key->length);
    if (xorkey.contents == NULL)
	return(KRB5_CRYPTO_INTERNAL);

    (void) memcpy(xorkey.contents, key->contents, xorkey.length);
    if (!compathash) {
        for (i=0; i<xorkey.length; i++)
	    xorkey.contents[i] ^= 0xf0;
    }

    if (!mit_des_check_key_parity(xorkey.contents)) {
	ret = KRB5DES_BAD_KEYPAR;
	goto cleanup;
    }

    if (mit_des_is_weak_key(xorkey.contents)) {
	ret = KRB5DES_WEAK_KEY;
	goto cleanup;
    }

    /* decrypt it.  this has a return value, but it's always zero.  */
    if (!compathash) {
	ret = mit_des_cbc_encrypt(context,
		(krb5_pointer) hash->data,
		(krb5_pointer) plaintext, hash->length,
		&xorkey, (unsigned char*) mit_des_zeroblock, 0);
    } else {
	ret = mit_des_cbc_encrypt(context,
		(krb5_pointer) hash->data,
		(krb5_pointer) plaintext, hash->length,
		&xorkey, xorkey.contents, 0);
    }
    if (ret) goto cleanup;

    /* hash the confounder, then the input data */
    mechanism.mechanism = CKM_MD5;
    mechanism.pParameter = NULL_PTR;
    mechanism.ulParameterLen = 0;

    if ((rv = C_DigestInit(krb_ctx_hSession(context), &mechanism)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestInit failed in k5_md5des_verify: "
	"rv = 0x%x.", rv);
	ret = PKCS_ERR;
	goto cleanup;
    }

    if (!compathash) {
	if ((rv = C_DigestUpdate(krb_ctx_hSession(context),
	    (CK_BYTE_PTR)plaintext, (CK_ULONG)CONFLENGTH)) != CKR_OK) {
	    KRB5_LOG(KRB5_ERR, "C_DigestUpdate failed in k5_md5des_verify: "
		"rv = 0x%x", rv);
	    ret = PKCS_ERR;
	    goto cleanup;
	}
    }
    if ((rv = C_DigestUpdate(krb_ctx_hSession(context),
	(CK_BYTE_PTR)input->data, (CK_ULONG)input->length)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestUpdate failed in k5_md5des_verify: "
	    "rv = 0x%x", rv);
	ret = PKCS_ERR;
	goto cleanup;
    }
    if ((rv = C_DigestFinal(krb_ctx_hSession(context),
	(CK_BYTE_PTR)digest, (CK_ULONG_PTR)&hashlen)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestFinal failed in k5_md5des_verify: "
	    "rv = 0x%x", rv);
	ret = PKCS_ERR;
	goto cleanup;
    }

    /* compare the decrypted hash to the computed one */

    if (!compathash) {
	*valid = (memcmp(plaintext+CONFLENGTH, digest, sizeof(digest)) == 0);
    } else {
	*valid = (memcmp(plaintext, digest, sizeof(digest)) == 0);
    }
    (void) memset(plaintext, 0, sizeof(plaintext));

cleanup:
    free(xorkey.contents);
    return(ret);
}

const struct krb5_keyhash_provider krb5int_keyhash_md5des = {
    CONFLENGTH + MD5_CKSUM_LENGTH,
    k5_md5des_hash,
    k5_md5des_verify
};
