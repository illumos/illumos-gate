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

#include "dk.h"

static const unsigned char kerberos[] = "kerberos";
#define kerberos_len (sizeof(kerberos)-1)

krb5_error_code
krb5int_dk_string_to_key(
			 krb5_context context,
			 const struct krb5_enc_provider *enc,
			 const krb5_data *string, const krb5_data *salt,
			 const krb5_data *parms, krb5_keyblock *key)
{
    krb5_error_code ret;
    size_t keybytes, keylength, concatlen;
    unsigned char *concat, *foldstring, *foldkeydata;
    krb5_data indata;
    krb5_keyblock foldkey;

    /* key->length is checked by krb5_derive_key */

    keybytes = enc->keybytes;
    keylength = enc->keylength;

    concatlen = string->length+(salt?salt->length:0);

    if ((concat = (unsigned char *) malloc(concatlen)) == NULL)
	return(ENOMEM);
    if ((foldstring = (unsigned char *) malloc(keybytes)) == NULL) {
	free(concat);
	return(ENOMEM);
    }
    if ((foldkeydata = (unsigned char *) malloc(keylength)) == NULL) {
	free(foldstring);
	free(concat);
	return(ENOMEM);
    }

    /* construct input string ( = string + salt), fold it, make_key it */

    memcpy(concat, string->data, string->length);
    if (salt)
	memcpy(concat+string->length, salt->data, salt->length);

    krb5_nfold(concatlen*8, concat, keybytes*8, foldstring);

    indata.length = keybytes;
    indata.data = (char *) foldstring;

    /* Solaris Kerberos */
    memset(&foldkey, 0, sizeof (krb5_keyblock));
    foldkey.enctype = key->enctype;
    foldkey.length = keylength;
    foldkey.contents = foldkeydata;

    /* Solaris Kerberos */
    (*(enc->make_key))(context, &indata, &foldkey);

    /* now derive the key from this one */

    indata.length = kerberos_len;
    indata.data = (char *) kerberos;
    /* Solaris Kerberos */
    if ((ret = krb5_derive_key(context, enc, &foldkey, key, &indata)))
	(void) memset(key->contents, 0, key->length);

    /* ret is set correctly by the prior call */

    memset(concat, 0, concatlen);
    memset(foldstring, 0, keybytes);
    memset(foldkeydata, 0, keylength);

    free(foldkeydata);
    free(foldstring);
    free(concat);

    return(ret);
}
