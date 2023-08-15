/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/kdb/decrypt_key.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * krb5_kdb_encrypt_key(), krb5_kdb_decrypt_key functions
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
#include <krb5/kdb.h>

/*
 * Decrypt a key from storage in the database.  "eblock" is used
 * to decrypt the key in "in" into "out"; the storage pointed to by "out"
 * is allocated before use.
 */

krb5_error_code
krb5_dbekd_decrypt_key_data( krb5_context 	  context,
			     const krb5_keyblock	* mkey,
			     const krb5_key_data	* key_data,
			     krb5_keyblock 	* dbkey,
			     krb5_keysalt 	* keysalt)
{
    krb5_error_code 	  retval = 0;
    krb5_int16		  tmplen;
    krb5_octet		* ptr;
    krb5_enc_data	  cipher;
    krb5_data		  plain;

    ptr = key_data->key_data_contents[0];

    if (ptr) {
	krb5_kdb_decode_int16(ptr, tmplen);
	ptr += 2;

	cipher.enctype = ENCTYPE_UNKNOWN;
	cipher.ciphertext.length = key_data->key_data_length[0]-2;
	cipher.ciphertext.data = (char *)ptr;  /* SUNWresync121 XXX */
	plain.length = key_data->key_data_length[0]-2;
	if ((plain.data = (char *) malloc(plain.length)) == NULL)
	    return(ENOMEM);
	(void) memset(plain.data, 0, plain.length);

	if ((retval = krb5_c_decrypt(context, mkey, 0 /* XXX */, 0,
				     &cipher, &plain))) {
	    krb5_xfree(plain.data);
	    return retval;
	}

	/* tmplen is the true length of the key.  plain.data is the
	   plaintext data length, but it may be padded, since the
	   old-style etypes didn't store the real length.  I can check
	   to make sure that there are enough bytes, but I can't do
	   any better than that. */

	if (tmplen > plain.length) {
	    krb5_xfree(plain.data);
	    return(KRB5_CRYPTO_INTERNAL);
	}

	dbkey->magic = KV5M_KEYBLOCK;
	dbkey->enctype = key_data->key_data_type[0];
	dbkey->length = tmplen;
	dbkey->contents = (unsigned char *) plain.data;  /* SUNWresync121 XXX */
	dbkey->dk_list = NULL;
	dbkey->hKey = CK_INVALID_HANDLE;
    }

    /* Decode salt data */
    if (keysalt) {
	if (key_data->key_data_ver == 2) {
	    keysalt->type = key_data->key_data_type[1];
	    if ((keysalt->data.length = key_data->key_data_length[1])) {
		if (!(keysalt->data.data=(char *)malloc(keysalt->data.length))){
		    if (key_data->key_data_contents[0]) {
			krb5_xfree(dbkey->contents);
			dbkey->contents = 0;
			dbkey->length = 0;
		    }
		    return ENOMEM;
		}
		memcpy(keysalt->data.data, key_data->key_data_contents[1],
		       (size_t) keysalt->data.length);
	    } else
		keysalt->data.data = (char *) NULL;
	} else {
	    keysalt->type = KRB5_KDB_SALTTYPE_NORMAL;
	    keysalt->data.data = (char *) NULL;
	    keysalt->data.length = 0;
	}
    }

    return retval;
}
