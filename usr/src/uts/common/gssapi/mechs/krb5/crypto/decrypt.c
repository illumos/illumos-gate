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
#include "etypes.h"

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_c_decrypt(krb5_context context, const krb5_keyblock *key,
	       krb5_keyusage usage, const krb5_data *ivec,
	       const krb5_enc_data *input, krb5_data *output)
{
    int i;
    krb5_error_code ret = 0;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key->enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    if ((input->enctype != ENCTYPE_UNKNOWN) &&
	(krb5_enctypes_list[i].etype != input->enctype))
	return(KRB5_BAD_ENCTYPE);

/* Solaris Kerberos */
#ifdef _KERNEL
    context->kef_cipher_mt = krb5_enctypes_list[i].kef_cipher_mt;
    context->kef_hash_mt = krb5_enctypes_list[i].kef_hash_mt;
    if (key->kef_key.ck_data == NULL)
      ret = init_key_kef(context->kef_cipher_mt, (krb5_keyblock *)key);
    if (ret)
	    return(ret);

#else
    if ((ret = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key)))
	return (ret);

#endif /* _KERNEL */

    /* Solaris Kerberos */
    return((*(krb5_enctypes_list[i].decrypt))
	   (context, krb5_enctypes_list[i].enc, krb5_enctypes_list[i].hash,
	    key, usage, ivec, &input->ciphertext, output));
}
