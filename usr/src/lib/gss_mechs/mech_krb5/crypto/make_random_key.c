/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <locale.h>

krb5_error_code KRB5_CALLCONV
krb5_c_make_random_key(krb5_context context, krb5_enctype enctype,
		       krb5_keyblock *random_key)
{
    int i;
    krb5_error_code ret;
    const struct krb5_enc_provider *enc;
    size_t keybytes, keylength;
    krb5_data random_data;
    unsigned char *bytes;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype)
	    break;
    }

    /* Solaris Kerberos: Better error message */
    if (i == krb5_enctypes_length) {
	krb5_set_error_message(context, KRB5_BAD_ENCTYPE,
			    dgettext(TEXT_DOMAIN,
				    "Unknown encryption type: %d"),
			    enctype);
	return(KRB5_BAD_ENCTYPE);
    }

    enc = krb5_enctypes_list[i].enc;

    keybytes = enc->keybytes;
    keylength = enc->keylength;

    if ((bytes = (unsigned char *) malloc(keybytes)) == NULL)
	return(ENOMEM);
    if ((random_key->contents = (krb5_octet *) malloc(keylength)) == NULL) {
	free(bytes);
	return(ENOMEM);
    }

    random_data.data = (char *) bytes;
    random_data.length = keybytes;

    if ((ret = krb5_c_random_make_octets(context, &random_data)))
	goto cleanup;

    random_key->magic = KV5M_KEYBLOCK;
    random_key->enctype = enctype;
    random_key->length = keylength;

    /* Solaris Kerberos */
    random_key->dk_list = NULL;
#ifdef _KERNEL
    random_key->kef_key = NULL;
#else
    random_key->hKey = CK_INVALID_HANDLE;
#endif

    /* Solaris Kerberos */
    ret = ((*(enc->make_key))(context, &random_data, random_key));

cleanup:
    memset(bytes, 0, keybytes);
    free(bytes);

    if (ret) {
	memset(random_key->contents, 0, keylength);
	free(random_key->contents);
	/* Solaris Kerberos */
	random_key->contents = NULL;
    }

    return(ret);
}
