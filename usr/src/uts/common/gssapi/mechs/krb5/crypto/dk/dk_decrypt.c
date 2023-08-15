/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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

static krb5_error_code
krb5_dk_decrypt_maybe_trunc_hmac(krb5_context context,
				 const struct krb5_enc_provider *enc,
				 const struct krb5_hash_provider *hash,
				 const krb5_keyblock *key,
				 krb5_keyusage usage,
				 const krb5_data *ivec,
				 const krb5_data *input,
				 krb5_data *output,
				 size_t hmacsize);

krb5_error_code
krb5_dk_decrypt(
		krb5_context context,
		const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key, krb5_keyusage usage,
		const krb5_data *ivec, const krb5_data *input,
		krb5_data *output)
{
    return krb5_dk_decrypt_maybe_trunc_hmac(context, enc, hash, key, usage,
					    ivec, input, output, 0);
}

krb5_error_code
krb5int_aes_dk_decrypt(
		       krb5_context context,
		       const struct krb5_enc_provider *enc,
		       const struct krb5_hash_provider *hash,
		       const krb5_keyblock *key, krb5_keyusage usage,
		       const krb5_data *ivec, const krb5_data *input,
		       krb5_data *output)
{
    return krb5_dk_decrypt_maybe_trunc_hmac(context, enc, hash, key, usage,
					    ivec, input, output, 96 / 8);
}

static krb5_error_code
krb5_dk_decrypt_maybe_trunc_hmac(
				 krb5_context context,
				 const struct krb5_enc_provider *enc,
				 const struct krb5_hash_provider *hash,
				 const krb5_keyblock *key, krb5_keyusage usage,
				 const krb5_data *ivec, const krb5_data *input,
				 krb5_data *output, size_t hmacsize)
{
    krb5_error_code ret;
    size_t hashsize, blocksize, enclen, plainlen;
    unsigned char *plaindata = NULL, *cksum = NULL, *cn;
    krb5_data d1, d2;
    krb5_keyblock *derived_encr_key = NULL;
    krb5_keyblock *derived_hmac_key = NULL;

    KRB5_LOG0(KRB5_INFO, "krb5_dk_decrypt() start\n");

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

    hashsize = hash->hashsize;
    blocksize = enc->block_size;

    if (hmacsize == 0)
	hmacsize = hashsize;
    else if (hmacsize > hashsize)
	return (KRB5KRB_AP_ERR_BAD_INTEGRITY);

    /* Verify input and output lengths. */
    if (input->length < blocksize + hmacsize)
        return KRB5_BAD_MSIZE;
    if (output->length < input->length - blocksize - hmacsize)
        return KRB5_BAD_MSIZE;

    enclen = input->length - hmacsize;

    if ((plaindata = (unsigned char *) MALLOC(enclen)) == NULL) {
	    ret = ENOMEM;
	    goto cleanup;
    }

    /* decrypt the ciphertext */

    d1.length = enclen;
    d1.data = input->data;

    d2.length = enclen;
    d2.data = (char *) plaindata;

    if ((ret = ((*(enc->decrypt))(context, derived_encr_key,
			ivec, &d1, &d2))) != 0)
	goto cleanup;

    if (ivec != NULL && ivec->length == blocksize) {
	cn = (unsigned char *) d1.data + d1.length - blocksize;
    } else {
	cn = NULL;
    }

    /* verify the hash */

    if ((cksum = (unsigned char *) MALLOC(hashsize)) == NULL) {
	    ret = ENOMEM;
	    goto cleanup;
    }
    d1.length = hashsize;
    d1.data = (char *) cksum;

#ifdef _KERNEL
    if ((ret = krb5_hmac(context, derived_hmac_key, &d2, &d1)) != 0)
	goto cleanup;
#else
    if ((ret = krb5_hmac(context, hash, derived_hmac_key,
			1, &d2, &d1)) != 0)
	goto cleanup;
#endif /* _KERNEL */

    if (memcmp(cksum, input->data+enclen, hmacsize) != 0) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	goto cleanup;
    }

    /* because this encoding isn't self-describing wrt length, the
       best we can do here is to compute the length minus the
       confounder. */

    plainlen = enclen - blocksize;

    if (output->length < plainlen) {
	ret = KRB5_BAD_MSIZE;
	goto cleanup;
    }

    output->length = plainlen;

    (void) memcpy(output->data, d2.data+blocksize, output->length);

    /*
     * AES crypto updates the ivec differently, it is handled
     * in the AES crypto routines directly.
     */
    if (cn != NULL &&
	key->enctype != ENCTYPE_AES128_CTS_HMAC_SHA1_96 &&
	key->enctype != ENCTYPE_AES256_CTS_HMAC_SHA1_96) {
	(void) memcpy(ivec->data, cn, blocksize);
    }

    ret = 0;

cleanup:
    if (plaindata) {
	    (void) memset(plaindata, 0, enclen);
	    FREE(plaindata, enclen);
    }
    if (cksum) {
	    (void) memset(cksum, 0, hashsize);
	    FREE(cksum, hashsize);
    }

    KRB5_LOG(KRB5_INFO, "krb5_dk_decrypt() end, ret=%d\n", ret);
    return(ret);
}

