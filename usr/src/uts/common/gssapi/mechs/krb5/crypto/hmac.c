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

/* Solaris Kerberos */
#ifdef _KERNEL
/*
 * In kernel, use the Kernel encryption framework HMAC
 * operation, its far more efficient than the MIT method.
 * Also, a template is used to further improve performance.
 */
/* ARGSUSED */
krb5_error_code
krb5_hmac(krb5_context context, const krb5_keyblock *key,
	krb5_const krb5_data *input, krb5_data *output)
{
	int rv = CRYPTO_FAILED;
        crypto_mechanism_t mac_mech;
	crypto_data_t dd;
	crypto_data_t mac;

	KRB5_LOG0(KRB5_INFO, "krb5_hmac() start");
	if (output == NULL || output->data == NULL) {
		KRB5_LOG0(KRB5_INFO, "krb5_hmac() NULL output");
		return (rv);
	}
	if (input == NULL || input->data == NULL) {
		KRB5_LOG0(KRB5_INFO, "krb5_hmac() NULL input");
		return (rv);
	}

	dd.cd_format = CRYPTO_DATA_RAW;
	dd.cd_offset = 0;
	dd.cd_length = input->length;
	dd.cd_raw.iov_base = (char *)input->data;
	dd.cd_raw.iov_len = input->length;

	mac.cd_format = CRYPTO_DATA_RAW;
	mac.cd_offset = 0;
	mac.cd_length = output->length;
	mac.cd_raw.iov_base = (char *)output->data;
	mac.cd_raw.iov_len = output->length;

	mac_mech.cm_type = context->kef_hash_mt;
	mac_mech.cm_param = NULL;
	mac_mech.cm_param_len = 0;

	rv = crypto_mac(&mac_mech, &dd,
			(crypto_key_t *)&key->kef_key,
			key->key_tmpl, &mac, NULL);

	if (rv != CRYPTO_SUCCESS) {
		KRB5_LOG(KRB5_ERR,"crypto_mac error: %0x", rv);
	}

	KRB5_LOG(KRB5_INFO, "krb5_hmac() end ret=%d\n", rv);
	return(rv);
}

#else
/* Userland implementation of HMAC algorithm */

/*
 * the HMAC transform looks like:
 *
 * H(K XOR opad, H(K XOR ipad, text))
 *
 * where H is a cryptographic hash
 * K is an n byte key
 * ipad is the byte 0x36 repeated blocksize times
 * opad is the byte 0x5c repeated blocksize times
 * and text is the data being protected
 */

krb5_error_code
krb5_hmac(krb5_context context,
	krb5_const struct krb5_hash_provider *hash,
	krb5_const krb5_keyblock *key,
	krb5_const unsigned int icount,
	krb5_const krb5_data *input,
	krb5_data *output)
{
    size_t hashsize, blocksize;
    unsigned char *xorkey, *ihash;
    int i;
    krb5_data *hashin, hashout;
    krb5_error_code ret;

    /* Solaris Kerberos */
    KRB5_LOG0(KRB5_INFO, "krb5_hmac() start\n");

    if (hash == NULL) {
	KRB5_LOG0(KRB5_ERR, "krb5_hmac() error hash == NULL\n");
	return(EINVAL);
    }
    if (key == NULL) {
	KRB5_LOG0(KRB5_ERR, "krb5_hmac() error key == NULL\n");
	return(EINVAL);
    }
    if (input == NULL) {
	KRB5_LOG0(KRB5_ERR, "krb5_hmac() error input == NULL\n");
	return(EINVAL);
    }
    if (output == NULL) {
	KRB5_LOG0(KRB5_ERR, "krb5_hmac() error output == NULL\n");
	return(EINVAL);
    }

    hashsize = hash->hashsize;
    blocksize = hash->blocksize;

    if (key->length > blocksize)
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length < hashsize)
	return(KRB5_BAD_MSIZE);
    /* if this isn't > 0, then there won't be enough space in this
       array to compute the outer hash */
    if (icount == 0)
	return(KRB5_CRYPTO_INTERNAL);

    /* allocate space for the xor key, hash input vector, and inner hash */

    if ((xorkey = (unsigned char *) MALLOC(blocksize)) == NULL)
	return(ENOMEM);
    if ((ihash = (unsigned char *) MALLOC(hashsize)) == NULL) {
	FREE(xorkey, blocksize);
	return(ENOMEM);
    }
    if ((hashin = (krb5_data *)MALLOC(sizeof(krb5_data)*(icount+1))) == NULL) {
	FREE(ihash, hashsize);
	FREE(xorkey, blocksize);
	return(ENOMEM);
    }

    /* create the inner padded key */

    /* Solaris Kerberos */
    (void) memset(xorkey, 0x36, blocksize);

    for (i=0; i<key->length; i++)
	xorkey[i] ^= key->contents[i];

    /* compute the inner hash */

    for (i=0; i<icount; i++) {
	hashin[0].length = blocksize;
	hashin[0].data = (char *) xorkey;
	hashin[i+1] = input[i];
    }

    hashout.length = hashsize;
    hashout.data = (char *) ihash;

    /* Solaris Kerberos */
    if ((ret = ((*(hash->hash))(context, icount+1, hashin, &hashout))))
	goto cleanup;

    /* create the outer padded key */

    /* Solaris Kerberos */
    (void) memset(xorkey, 0x5c, blocksize);

    for (i=0; i<key->length; i++)
	xorkey[i] ^= key->contents[i];

    /* compute the outer hash */

    hashin[0].length = blocksize;
    hashin[0].data = (char *) xorkey;
    hashin[1] = hashout;

    output->length = hashsize;

    /* Solaris Kerberos */
    if ((ret = ((*(hash->hash))(context, 2, hashin, output))))
	(void) memset(output->data, 0, output->length);

    /* ret is set correctly by the prior call */

cleanup:
    /* Solaris Kerberos */
    (void) memset(xorkey, 0, blocksize);
    (void) memset(ihash, 0, hashsize);

    FREE(hashin, sizeof(krb5_data)*(icount+1));
    FREE(ihash, hashsize);
    FREE(xorkey, blocksize);

    /* Solaris Kerberos */
    KRB5_LOG(KRB5_INFO, "krb5_hmac() end ret=%d\n", ret);
    return(ret);
}
#endif /* _KERNEL */
