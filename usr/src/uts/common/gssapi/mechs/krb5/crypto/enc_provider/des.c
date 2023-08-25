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
#include "enc_provider.h"

static krb5_error_code
k5_des_docrypt(krb5_context context, krb5_const krb5_keyblock *key,
	krb5_const krb5_data *ivec, krb5_const krb5_data *input,
	krb5_data *output, int encrypt)
{
    krb5_error_code ret;

    KRB5_LOG(KRB5_INFO, "k5_des_docrypt() start encrypt=%d\n", encrypt);
    /* key->enctype was checked by the caller */

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_BAD_MSIZE);
    if (input->length != output->length)
	return(KRB5_BAD_MSIZE);

    ret = mit_des_cbc_encrypt(context, (krb5_pointer) input->data,
	(krb5_pointer) output->data, input->length,
	(krb5_keyblock *)key,
	ivec?(unsigned char *)ivec->data:
	(unsigned char *)mit_des_zeroblock, encrypt);

    KRB5_LOG0(KRB5_INFO, "k5_des_docrypt() end\n");
    return(ret);
}

static krb5_error_code
k5_des_encrypt(krb5_context context, krb5_const krb5_keyblock *key,
		krb5_const krb5_data *ivec, krb5_const krb5_data *input,
		krb5_data *output)
{
    return(k5_des_docrypt(context, key, ivec, input, output, 1));
}

static krb5_error_code
k5_des_decrypt(krb5_context context, krb5_const krb5_keyblock *key,
		krb5_const krb5_data *ivec, krb5_const krb5_data *input,
		krb5_data *output)
{
    return(k5_des_docrypt(context, key, ivec, input, output, 0));
}

static krb5_error_code
k5_des_make_key(krb5_context context, krb5_const krb5_data *randombits,
		krb5_keyblock *key)
{
    krb5_error_code ret = 0;
    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != 7)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;
    key->length = 8;
    key->dk_list = NULL;

    /* take the seven bytes, move them around into the top 7 bits of the
       8 key bytes, then compute the parity bits */

    (void) memcpy(key->contents, randombits->data, randombits->length);
    key->contents[7] = (((key->contents[0]&1)<<1) | ((key->contents[1]&1)<<2) |
			((key->contents[2]&1)<<3) | ((key->contents[3]&1)<<4) |
			((key->contents[4]&1)<<5) | ((key->contents[5]&1)<<6) |
			((key->contents[6]&1)<<7));

    mit_des_fixup_key_parity(key->contents);

#ifdef _KERNEL
    key->kef_key.ck_data = NULL;
    key->key_tmpl = NULL;
    ret = init_key_kef(context->kef_cipher_mt, key);
#else
    key->hKey = CK_INVALID_HANDLE;
    ret = init_key_uef(krb_ctx_hSession(context), key);
#endif /* _KERNEL */

    return (ret);
}

const struct krb5_enc_provider krb5int_enc_des = {
    8,
    7, 8,
    k5_des_encrypt,
    k5_des_decrypt,
    k5_des_make_key,
    krb5int_des_init_state,
    krb5int_default_free_state
};
