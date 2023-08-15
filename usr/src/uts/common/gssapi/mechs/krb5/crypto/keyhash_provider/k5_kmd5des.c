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

/* Solaris Kerberos:
 * this code is based on the
 * usr/src/lib/gss_mechs/mech_krb5/crypto/keyhash_provider/k5_md5des.c
 * file, but has been modified to use the Solaris resident md5.o kernel
 * module and associated header /usr/include/sys/md5.o.
 * This means that the MD5* functions are called instead of krb5_MD5*.
 */

#include <des_int.h>
#include <krb5.h>
#include <keyhash_provider.h>
#include <sys/kmem.h>
#include <sys/crypto/api.h>

#define CONFLENGTH 8

/* Force acceptance of krb5-beta5 md5des checksum for now. */
#define KRB5_MD5DES_BETA5_COMPAT

/* des-cbc(xorkey, conf | rsa-md5(conf | data)) */

/* this could be done in terms of the md5 and des providers, but
   that's less efficient, and there's no need for this to be generic */

/*ARGSUSED*/
static krb5_error_code
k5_md5des_hash(krb5_context context,
	krb5_const krb5_keyblock *key,
	krb5_keyusage usage,
	krb5_const krb5_data *ivec,
	krb5_const krb5_data *input, krb5_data *output)
{
    krb5_error_code ret = 0;
    krb5_data data;
    unsigned char conf[CONFLENGTH];
    unsigned char xorkey[MIT_DES_KEYSIZE];
    int i;
    krb5_data *hash_input;
    char *outptr;
    krb5_keyblock newkey;

    if (key->length != MIT_DES_KEYSIZE)
	return(KRB5_BAD_KEYSIZE);
    if (ivec)
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length != (CONFLENGTH + MD5_CKSUM_LENGTH))
	return(KRB5_CRYPTO_INTERNAL);

    /* create the confounder */
    data.length = CONFLENGTH;
    data.data = (char *) conf;
    if ((ret = krb5_c_random_make_octets(context, &data)))
	return(ret);

    /* hash the confounder, then the input data */
    hash_input = (krb5_data *)MALLOC(sizeof(krb5_data) * 2);
    if (hash_input == NULL)
	return(KRB5_RC_MALLOC);

    hash_input[0].data = (char *)conf;
    hash_input[0].length = CONFLENGTH;
    hash_input[1].data = input->data;
    hash_input[1].length = input->length;

    /* Save the pointer to the beginning of the output buffer */
    outptr = (char *)output->data;

    /*
     * Move the output ptr ahead so we can write the hash
     * digest directly into the buffer.
     */
    output->data = output->data + CONFLENGTH;

    /* Use generic hash function that calls to kEF */
    if (k5_ef_hash(context, 2, hash_input, output)) {
	FREE(hash_input, sizeof(krb5_data) * 2);
	return(KRB5_KEF_ERROR);
    }

    /* restore the original ptr to the output data */
    output->data = outptr;

    /*
     * Put the confounder in the beginning of the buffer to be
     * encrypted.
     */
    bcopy(conf, output->data, CONFLENGTH);

    bcopy(key->contents, xorkey, sizeof(xorkey));
    for (i=0; i<sizeof(xorkey); i++)
	xorkey[i] ^= 0xf0;

    /*
     * Solaris Kerberos:
     * Encryption Framework checks for parity and weak keys.
     */
    bzero(&newkey, sizeof(krb5_keyblock));
    newkey.enctype = key->enctype;
    newkey.contents = xorkey;
    newkey.length = sizeof(xorkey);
    newkey.dk_list = NULL;
    newkey.kef_key.ck_data = NULL;
    ret = init_key_kef(context->kef_cipher_mt, &newkey);
    if (ret) {
	FREE(hash_input, sizeof(krb5_data) * 2);
	return (ret);
    }

    /* encrypt it, in place.  this has a return value, but it's
       always zero.  */
    ret = mit_des_cbc_encrypt(context, (krb5_pointer) output->data,
	(krb5_pointer) output->data, output->length,
	&newkey, (unsigned char*) mit_des_zeroblock, 1);

    FREE(hash_input, sizeof(krb5_data) * 2);
    (void)crypto_destroy_ctx_template(newkey.key_tmpl);
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
    unsigned char plaintext[CONFLENGTH + MD5_CKSUM_LENGTH];
    unsigned char xorkey[8];
    int i;
    int compathash = 0;
    krb5_octet outtmp[MD5_CKSUM_LENGTH];
    size_t hisize;
    krb5_data *hash_input;
    krb5_data hash_output;
    krb5_keyblock newkey;

    if (key->length != MIT_DES_KEYSIZE)
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

    /* create and schedule the encryption key */
    (void) bcopy(key->contents, xorkey, sizeof(xorkey));
    if (!compathash) {
	for (i=0; i<sizeof(xorkey); i++)
	    xorkey[i] ^= 0xf0;
    }

    /*
     * Solaris Kerberos:
     * Encryption Framework checks for parity and weak keys
     */
    bzero(&newkey, sizeof(krb5_keyblock));
    newkey.enctype = key->enctype;
    newkey.contents = xorkey;
    newkey.length = sizeof(xorkey);
    newkey.dk_list = NULL;
    newkey.kef_key.ck_data = NULL;
    ret = init_key_kef(context->kef_cipher_mt, &newkey);

    /* decrypt it.  this has a return value, but it's always zero.  */
    if (!compathash) {
	ret = mit_des_cbc_encrypt(context, (krb5_pointer) hash->data,
			    (krb5_pointer) plaintext, hash->length,
			    &newkey, (unsigned char*) mit_des_zeroblock, 0);
    } else {
	ret = mit_des_cbc_encrypt(context, (krb5_pointer) hash->data,
			    (krb5_pointer) plaintext, hash->length,
			    &newkey, xorkey, 0);
    }
    if (ret) goto cleanup;

    /* hash the confounder, then the input data */
    i = 1;
    if (!compathash)
	i++;

    hisize = sizeof(krb5_data) * i;
    hash_input = (krb5_data *)MALLOC(hisize);
    if (hash_input == NULL)
	return(KRB5_RC_MALLOC);

    i=0;
    if (!compathash) {
    	hash_input[i].data = (char *)plaintext;
    	hash_input[i].length = CONFLENGTH;
	i++;
    }
    hash_input[i].data = input->data;
    hash_input[i].length = input->length;

    hash_output.data = (char *)outtmp;
    hash_output.length = sizeof(outtmp);

    if (k5_ef_hash(context, 1, hash_input, &hash_output)) {
	ret = KRB5_KEF_ERROR;
	goto cleanup;
    }

    /* compare the decrypted hash to the computed one */
    if (!compathash) {
	*valid = !bcmp((const void *)(plaintext+CONFLENGTH),
		(void *)outtmp, MD5_CKSUM_LENGTH);
    } else {
	*valid = !bcmp((const void *)plaintext,
		(void *)outtmp, MD5_CKSUM_LENGTH);
    }
    bzero((void *)plaintext, sizeof(plaintext));

cleanup:
    if (hash_input != NULL && hisize > 0)
	    FREE(hash_input, hisize);
    (void)crypto_destroy_ctx_template(newkey.key_tmpl);

    return(ret);
}

const struct krb5_keyhash_provider krb5int_keyhash_md5des = {
    CONFLENGTH+MD5_CKSUM_LENGTH,
    k5_md5des_hash,
    k5_md5des_verify
};
