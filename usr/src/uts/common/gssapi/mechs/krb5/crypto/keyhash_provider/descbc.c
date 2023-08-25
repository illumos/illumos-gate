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
#ifdef _KERNEL
#include <sys/kmem.h>
#include <sys/crypto/api.h>
#endif

/*ARGSUSED*/
static krb5_error_code
k5_descbc_hash(krb5_context context,
	krb5_const krb5_keyblock *key,
	krb5_keyusage usage,
	krb5_const krb5_data *ivec,
	krb5_const krb5_data *input, krb5_data *output)
{
    int ret;
    krb5_data zero_ivec;

    if (key->length != MIT_DES_KEYSIZE)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != MIT_DES_BLOCK_LENGTH))
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length != MIT_DES_BLOCK_LENGTH)
	return(KRB5_CRYPTO_INTERNAL);

    zero_ivec.data = (char *)mit_des_zeroblock;
    zero_ivec.length = sizeof(mit_des_zeroblock);

    ret = k5_ef_mac(context, (krb5_keyblock *)key,
	ivec ? (krb5_data *)ivec : &zero_ivec, input, output);

    return(ret);
}

const struct krb5_keyhash_provider krb5int_keyhash_descbc = {
    MIT_DES_BLOCK_LENGTH,
    k5_descbc_hash,
    NULL
};
