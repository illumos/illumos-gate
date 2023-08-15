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

/*
 * Solaris Kerberos
 * krb5_string_to_key/krb5_use_enctype are needed by Samba
 */

krb5_error_code KRB5_CALLCONV
krb5_encrypt(krb5_context context, krb5_const_pointer inptr,
	     krb5_pointer outptr, size_t size, krb5_encrypt_block *eblock,
	     krb5_pointer ivec)
{
    krb5_data inputd, ivecd;
    krb5_enc_data outputd;
    size_t blocksize, outlen;
    krb5_error_code ret;

    if (ivec) {
	if ((ret = krb5_c_block_size(context, eblock->key->enctype, &blocksize)))
	    return(ret);

	ivecd.length = blocksize;
	ivecd.data = ivec;
    }

    /* size is the length of the input cleartext data */
    inputd.length = size;
    inputd.data = (char*)inptr;

    /* The size of the output buffer isn't part of the old api.  Not too
       safe.  So, we assume here that it's big enough. */
    if ((ret = krb5_c_encrypt_length(context, eblock->key->enctype, size,
				     &outlen)))
	return(ret);

    outputd.ciphertext.length = outlen;
    outputd.ciphertext.data = outptr;

    return(krb5_c_encrypt(context, eblock->key, 0, ivec?&ivecd:0,
			  &inputd, &outputd));
}

krb5_error_code KRB5_CALLCONV
krb5_decrypt(krb5_context context, krb5_const_pointer inptr,
	     krb5_pointer outptr, size_t size, krb5_encrypt_block *eblock,
	     krb5_pointer ivec)
{
    krb5_enc_data inputd;
    krb5_data outputd, ivecd;
    size_t blocksize;
    krb5_error_code ret;

    if (ivec) {
	if ((ret = krb5_c_block_size(context, eblock->key->enctype, &blocksize)))
	    return(ret);

	ivecd.length = blocksize;
	ivecd.data = ivec;
    }

    /* size is the length of the input ciphertext data */
    inputd.enctype = eblock->key->enctype;
    inputd.ciphertext.length = size;
    /* Solaris Kerberos */
    inputd.ciphertext.data = (char*)inptr;

    /* we don't really know how big this is, but the code tends to assume
       that the output buffer size should be the same as the input
       buffer size */
    outputd.length = size;
    outputd.data = outptr;

    return(krb5_c_decrypt(context, eblock->key, 0, ivec?&ivecd:0,
			  &inputd, &outputd));
}

krb5_error_code KRB5_CALLCONV
krb5_process_key(krb5_context context, krb5_encrypt_block *eblock,
		 const krb5_keyblock *key)
{
    eblock->key = (krb5_keyblock *) key;

    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_finish_key(krb5_context context, krb5_encrypt_block *eblock)
{
    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_string_to_key(krb5_context context, const krb5_encrypt_block *eblock,
		   krb5_keyblock *keyblock, const krb5_data *data,
		   const krb5_data *salt)
{
    return(krb5_c_string_to_key(context, eblock->crypto_entry, data, salt,
				keyblock));
}

krb5_error_code KRB5_CALLCONV
krb5_init_random_key(krb5_context context, const krb5_encrypt_block *eblock,
		     const krb5_keyblock *keyblock, krb5_pointer *ptr)
{
    krb5_data data;

    data.length = keyblock->length;
    data.data = (char *) keyblock->contents;

    return(krb5_c_random_seed(context, &data));
}

krb5_error_code KRB5_CALLCONV
krb5_finish_random_key(krb5_context context, const krb5_encrypt_block *eblock,
		       krb5_pointer *ptr)
{
    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_random_key(krb5_context context, const krb5_encrypt_block *eblock,
		krb5_pointer ptr, krb5_keyblock **keyblock)
{
    krb5_keyblock *key;
    krb5_error_code ret;

    if ((key = (krb5_keyblock *) malloc(sizeof(krb5_keyblock))) == NULL)
	return(ENOMEM);

    if ((ret = krb5_c_make_random_key(context, eblock->crypto_entry, key)))
	free(key);

    *keyblock = key;

    return(ret);
}

krb5_enctype KRB5_CALLCONV
krb5_eblock_enctype(krb5_context context, const krb5_encrypt_block *eblock)
{
    return(eblock->crypto_entry);
}

krb5_error_code KRB5_CALLCONV
krb5_use_enctype(krb5_context context, krb5_encrypt_block *eblock,
		 krb5_enctype enctype)
{
    eblock->crypto_entry = enctype;

    return(0);
}

size_t KRB5_CALLCONV
krb5_encrypt_size(size_t length, krb5_enctype crypto)
{
    size_t ret;

    if (krb5_c_encrypt_length(/* XXX */ 0, crypto, length, &ret))
	return(-1); /* XXX */

    return(ret);
}

size_t KRB5_CALLCONV
krb5_checksum_size(krb5_context context, krb5_cksumtype ctype)
{
    size_t ret;

    if (krb5_c_checksum_length(context, ctype, &ret))
	return(-1); /* XXX */

    return(ret);
}

krb5_error_code KRB5_CALLCONV
krb5_calculate_checksum(krb5_context context, krb5_cksumtype ctype,
			krb5_const_pointer in, size_t in_length,
			krb5_const_pointer seed, size_t seed_length,
			krb5_checksum *outcksum)
{
    krb5_data input;
    krb5_keyblock key;
    krb5_error_code ret;
    krb5_checksum cksum;

    /* Solaris Kerberos */
    input.data = (char*)in;
    input.length = in_length;

    key.length = seed_length;
    /* Solaris Kerberos */
    key.contents = (unsigned char*)seed;

    if ((ret = krb5_c_make_checksum(context, ctype, &key, 0, &input, &cksum)))
	return(ret);

    if (outcksum->length < cksum.length) {
	memset(cksum.contents, 0, cksum.length);
	free(cksum.contents);
	return(KRB5_BAD_MSIZE);
    }

    outcksum->magic = cksum.magic;
    outcksum->checksum_type = cksum.checksum_type;
    memcpy(outcksum->contents, cksum.contents, cksum.length);
    outcksum->length = cksum.length;

    free(cksum.contents);

    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_verify_checksum(krb5_context context, krb5_cksumtype ctype,
		     const krb5_checksum *cksum, krb5_const_pointer in,
		     size_t in_length, krb5_const_pointer seed,
		     size_t seed_length)
{
    krb5_data input;
    krb5_keyblock key;
    krb5_error_code ret;
    krb5_boolean valid;

    /* Solaris Kerberos */
    input.data = (char*)in;
    input.length = in_length;

    key.length = seed_length;
    /* Solaris Kerberos */
    key.contents = (unsigned char*)seed;

    if ((ret = krb5_c_verify_checksum(context, &key, 0, &input, cksum,
				      &valid)))
	return(ret);

    if (!valid)
	return(KRB5KRB_AP_ERR_BAD_INTEGRITY);

    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_random_confounder(size_t size, krb5_pointer ptr)
{
    krb5_data random_data;

    random_data.length = size;
    random_data.data = ptr;

    return(krb5_c_random_make_octets(/* XXX */ 0, &random_data));
}

krb5_error_code krb5_encrypt_data(krb5_context context, krb5_keyblock *key,
				  krb5_pointer ivec, krb5_data *data,
				  krb5_enc_data *enc_data)
{
    krb5_error_code ret;
    size_t enclen, blocksize;
    krb5_data ivecd;

    if ((ret = krb5_c_encrypt_length(context, key->enctype, data->length,
				     &enclen)))
	return(ret);

    if (ivec) {
	if ((ret = krb5_c_block_size(context, key->enctype, &blocksize)))
	    return(ret);

	ivecd.length = blocksize;
	ivecd.data = ivec;
    }

    enc_data->magic = KV5M_ENC_DATA;
    enc_data->kvno = 0;
    enc_data->enctype = key->enctype;
    enc_data->ciphertext.length = enclen;
    if ((enc_data->ciphertext.data = malloc(enclen)) == NULL)
	return(ENOMEM);

    if ((ret = krb5_c_encrypt(context, key, 0, ivec?&ivecd:0, data, enc_data)))
	free(enc_data->ciphertext.data);

    return(ret);
}

krb5_error_code krb5_decrypt_data(krb5_context context, krb5_keyblock *key,
				  krb5_pointer ivec, krb5_enc_data *enc_data,
				  krb5_data *data)
{
    krb5_error_code ret;
    krb5_data ivecd;
    size_t blocksize;

    if (ivec) {
	if ((ret = krb5_c_block_size(context, key->enctype, &blocksize)))
	    return(ret);

	ivecd.length = blocksize;
	ivecd.data = ivec;
    }

    data->length = enc_data->ciphertext.length;
    if ((data->data = (char *) malloc(data->length)) == NULL)
	return(ENOMEM);

    if ((ret = krb5_c_decrypt(context, key, 0, ivec?&ivecd:0, enc_data, data)))
	free(data->data);

    /* Solaris Kerberos */
    return(ret);
}
