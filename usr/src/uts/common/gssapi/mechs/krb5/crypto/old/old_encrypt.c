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
#include "old.h"

void
krb5_old_encrypt_length(const struct krb5_enc_provider *enc,
			const struct krb5_hash_provider *hash,
			size_t inputlen,
			size_t *length)
{
    size_t blocksize, hashsize;

    blocksize = enc->block_size;
    hashsize = hash->hashsize;

    *length = krb5_roundup(blocksize+hashsize+inputlen, blocksize);
}

/*ARGSUSED*/
krb5_error_code
krb5_old_encrypt(krb5_context context,
		 const struct krb5_enc_provider *enc,
		 const struct krb5_hash_provider *hash,
		 const krb5_keyblock *key,
		 krb5_keyusage usage,
		 const krb5_data *ivec,
		 const krb5_data *input,
		 krb5_data *output)
{
    krb5_error_code ret;
    size_t blocksize, hashsize, enclen;
    krb5_data datain, crcivec;
    int real_ivec;

    blocksize = enc->block_size;
    hashsize = hash->hashsize;

    krb5_old_encrypt_length(enc, hash, input->length, &enclen);

    if (output->length < enclen)
	return(KRB5_BAD_MSIZE);

    output->length = enclen;

    /* fill in confounded, padded, plaintext buffer with zero checksum */

    (void) memset(output->data, 0, output->length);

    datain.length = blocksize;
    datain.data = (char *) output->data;

    if ((ret = krb5_c_random_make_octets(context, &datain)))
	return(ret);
    (void) memcpy(output->data+blocksize+hashsize, input->data, input->length);

    /* compute the checksum */

    datain.length = hashsize;
    datain.data = output->data+blocksize;

    if ((ret = ((*(hash->hash))(context, 1, output, &datain))))
	goto cleanup;

    /* encrypt it */

    /* XXX this is gross, but I don't have much choice */
    if ((key->enctype == ENCTYPE_DES_CBC_CRC) && (ivec == 0)) {
	crcivec.length = key->length;
	crcivec.data = (char *) key->contents;
	ivec = &crcivec;
	real_ivec = 0;
    } else
	real_ivec = 1;

    if ((ret = ((*(enc->encrypt))(context, key, ivec, output, output))))
	goto cleanup;

    /* update ivec */
    if (real_ivec && ivec != NULL && ivec->length == blocksize)
	(void) memcpy(ivec->data, output->data + output->length - blocksize,
	       blocksize);
cleanup:
    if (ret)
	(void) memset(output->data, 0, output->length);

    return(ret);
}
