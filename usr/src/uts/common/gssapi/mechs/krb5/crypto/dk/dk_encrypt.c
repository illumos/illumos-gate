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
#include "dk.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

/* the spec says that the confounder size and padding are specific to
   the encryption algorithm.  This code (dk_encrypt_length and
   dk_encrypt) assume the confounder is always the blocksize, and the
   padding is always zero bytes up to the blocksize.  If these
   assumptions ever fails, the keytype table should be extended to
   include these bits of info. */

void
krb5_dk_encrypt_length(const struct krb5_enc_provider *enc,
		       const struct krb5_hash_provider *hash,
		       size_t inputlen, size_t *length)
{
    size_t blocksize, hashsize;

    blocksize = enc->block_size;
    hashsize = hash->hashsize;
    *length = krb5_roundup(blocksize+inputlen, blocksize) + hashsize;
}

krb5_error_code
krb5_dk_encrypt(krb5_context context,
		const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key, krb5_keyusage usage,
		const krb5_data *ivec, const krb5_data *input,
		krb5_data *output)
{
    size_t blocksize, plainlen, enclen;
    krb5_error_code ret;
    krb5_data d1, d2;
    unsigned char *plaintext = NULL, *cn;
    krb5_keyblock *derived_encr_key = NULL;
    krb5_keyblock *derived_hmac_key = NULL;

    KRB5_LOG0(KRB5_INFO, "krb5_dk_encrypt() start");

    /*
     * Derive the encryption and hmac keys.
     * This routine is optimized to fetch the DK
     * from the original key's DK list.
     */
    ret = init_derived_keydata(context, enc,
			    (krb5_keyblock *)key,
			    usage,
			    &derived_encr_key,
			    &derived_hmac_key);
    if (ret)
	    return (ret);

    blocksize = enc->block_size;
    plainlen = krb5_roundup(blocksize+input->length, blocksize);

    krb5_dk_encrypt_length(enc, hash, input->length, &enclen);

    if (output->length < enclen)
	return(KRB5_BAD_MSIZE);

    if ((plaintext = (unsigned char *) MALLOC(plainlen)) == NULL) {
	return(ENOMEM);
    }

    /* put together the plaintext */
    d1.length = blocksize;
    d1.data = (char *) plaintext;

    if ((ret = krb5_c_random_make_octets(context, &d1)))
	goto cleanup;

    (void) memcpy(plaintext+blocksize, input->data, input->length);

    (void) memset(plaintext+blocksize+input->length, 0,
	   plainlen - (blocksize+input->length));

    /* encrypt the plaintext */
    d1.length = plainlen;
    d1.data = (char *) plaintext;

    d2.length = plainlen;
    d2.data = output->data;

    /*
     * Always use the derived encryption key here.
     */
    if ((ret = ((*(enc->encrypt))(context, derived_encr_key,
		ivec, &d1, &d2))))
	goto cleanup;

    if (ivec != NULL && ivec->length == blocksize)
	cn = (unsigned char *) d2.data + d2.length - blocksize;
    else
	cn = NULL;

    /* hash the plaintext */

    d2.length = enclen - plainlen;
    d2.data = output->data+plainlen;

    output->length = enclen;

#ifdef _KERNEL
    if ((ret = krb5_hmac(context, derived_hmac_key, &d1, &d2))) {
	(void) memset(d2.data, 0, d2.length);
	goto cleanup;
    }
#else
    if ((ret = krb5_hmac(context, hash, derived_hmac_key,
			1, &d1, &d2))) {
	(void) memset(d2.data, 0, d2.length);
	goto cleanup;
    }
#endif /* _KERNEL */

    /* update ivec */
    if (cn != NULL)
	(void) memcpy(ivec->data, cn, blocksize);

    /* ret is set correctly by the prior call */

cleanup:
    FREE(plaintext, plainlen);

    KRB5_LOG(KRB5_INFO, "krb5_dk_encrypt() end, ret=%d\n", ret);
    return(ret);
}

/* Not necessarily "AES", per se, but "a CBC+CTS mode block cipher
   with a 96-bit truncated HMAC".  */
/*ARGSUSED*/
void
krb5int_aes_encrypt_length(enc, hash, inputlen, length)
	const struct krb5_enc_provider *enc;
	const struct krb5_hash_provider *hash;
	size_t inputlen;
	size_t *length;
{
    size_t blocksize, hashsize;

    blocksize = enc->block_size;
    hashsize = 96 / 8;

    /* No roundup, since CTS requires no padding once we've hit the
       block size.  */
    *length = blocksize+inputlen + hashsize;
}

/*ARGSUSED*/
static krb5_error_code
trunc_hmac (krb5_context context,
	    const struct krb5_hash_provider *hash,
            const krb5_keyblock *ki, int num,
            const krb5_data *input, krb5_data *output)
{
    size_t hashsize;
    krb5_error_code ret;
    char buff[256]; /* sufficiently large enough to hold current hmacs */
    krb5_data tmphash;

    hashsize = hash->hashsize;
    if (hashsize < output->length)
	return (KRB5_CRYPTO_INTERNAL);

    tmphash.length = hashsize;
    tmphash.data = buff;

#ifdef _KERNEL
    ret = krb5_hmac(context, ki, input, &tmphash);
#else
    ret = krb5_hmac(context, hash, ki, num, input, &tmphash);
#endif /* _KERNEL */

    if (ret)
	(void) memset(output->data, 0, output->length);
    else
	/* truncate the HMAC output accordingly */
	(void) memcpy(output->data, tmphash.data, output->length);

    (void) memset(buff, 0, sizeof(buff));
    return (ret);
}


krb5_error_code
krb5int_aes_dk_encrypt(krb5_context context,
	const struct krb5_enc_provider *enc,
	const struct krb5_hash_provider *hash,
	const krb5_keyblock *key,
	krb5_keyusage usage,
	const krb5_data *ivec,
	const krb5_data *input,
	krb5_data *output)
{
    size_t blocksize, plainlen, enclen;
    krb5_error_code ret;
    krb5_data d1, d2;
    unsigned char *plaintext, *cn;
    krb5_keyblock *derived_encr_key = NULL;
    krb5_keyblock *derived_hmac_key = NULL;

    /*
     * Derive the encryption and hmac keys.
     * This routine is optimized to fetch the DK
     * from the original key's DK list.
     */
    ret = init_derived_keydata(context, enc,
                            (krb5_keyblock *)key,
                            usage,
                            &derived_encr_key,
                            &derived_hmac_key);
    if (ret)
            return (ret);

    blocksize = enc->block_size;
    plainlen = blocksize+input->length;

    krb5int_aes_encrypt_length(enc, hash, input->length, &enclen);

    /* key->length, ivec will be tested in enc->encrypt */
    if (output->length < enclen)
	return(KRB5_BAD_MSIZE);

    if ((plaintext = (unsigned char *) MALLOC(plainlen)) == NULL) {
	 return(ENOMEM);
    }

    d1.length = blocksize;
    d1.data = (char *)plaintext;

    if ((ret = krb5_c_random_make_octets(context, &d1)))
	goto cleanup;

    (void) memcpy(plaintext+blocksize, input->data, input->length);

    /* Ciphertext stealing; there should be no more.  */
    if (plainlen != blocksize + input->length) {
	ret = KRB5_BAD_KEYSIZE;
	goto cleanup;
    }

    /* encrypt the plaintext */

    d1.length = plainlen;
    d1.data = (char *)plaintext;

    d2.length = plainlen;
    d2.data = output->data;

    if ((ret = ((*(enc->encrypt))(context, derived_encr_key, ivec, &d1, &d2))))
	goto cleanup;

    if (ivec != NULL && ivec->length == blocksize) {
	int nblocks = (d2.length + blocksize - 1) / blocksize;
	cn = (uchar_t *) d2.data + blocksize * (nblocks - 2);
    } else {
	cn = NULL;
    }

    /* hash the plaintext */
    d2.length = enclen - plainlen;
    d2.data = output->data+plainlen;
    if (d2.length != 96 / 8)
	goto cleanup;

    if ((ret = trunc_hmac(context, hash, derived_hmac_key, 1, &d1, &d2))) {
	(void) memset(d2.data, 0, d2.length);
	goto cleanup;
    }

    output->length = enclen;

    /* update ivec */
    if (cn != NULL) {
	(void) memcpy(ivec->data, cn, blocksize);
    }

    /* ret is set correctly by the prior call */
cleanup:
    (void) memset(plaintext, 0, plainlen);

    FREE(plaintext, plainlen);

    return(ret);
}
