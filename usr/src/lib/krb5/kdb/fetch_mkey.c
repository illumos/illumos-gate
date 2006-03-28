/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/fetch_mkey.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb5_db_fetch_mkey():
 * Fetch a database master key from somewhere.
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
#include <libintl.h>

/* these are available to other funcs, and the pointers may be reassigned */

char *krb5_mkey_pwd_prompt1 = KRB5_KDC_MKEY_1;
char *krb5_mkey_pwd_prompt2 = KRB5_KDC_MKEY_2;

/*
 * Get the KDC database master key from somewhere, filling it into *key.
 *
 * key->enctype should be set to the desired key type.
 *
 * if fromkeyboard is TRUE, then the master key is read as a password
 * from the user's terminal.  In this case,
 * eblock should point to a block with an appropriate string_to_key function.
 * if twice is TRUE, the password is read twice for verification.
 *
 * mname is the name of the key sought; this can be used by the string_to_key
 * function or by some other method to isolate the desired key.
 *
 */

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

krb5_error_code
krb5_db_fetch_mkey(context, mname, etype, fromkeyboard, twice, keyfile,
		   salt, key)
    krb5_context context;
    krb5_principal mname;
    krb5_enctype etype;
    krb5_boolean fromkeyboard;
    krb5_boolean twice;
    char *keyfile;
    krb5_data * salt;
    krb5_keyblock * key;
{
    krb5_error_code retval;
    char password[BUFSIZ];
    krb5_data pwd;
    unsigned int size = sizeof(password);

    if (fromkeyboard) {
	krb5_data scratch;

	krb5_mkey_pwd_prompt1 = dgettext(TEXT_DOMAIN,
					"Enter KDC database master key");
	krb5_mkey_pwd_prompt2 = dgettext(TEXT_DOMAIN,
					"Re-enter KDC database master "
					"key to verify");
	if ((retval = krb5_read_password(context, krb5_mkey_pwd_prompt1,
					 twice ? krb5_mkey_pwd_prompt2 : 0,
					 password, &size)))
	    return(retval);

	pwd.data = password;
	pwd.length = size;
	if (!salt) {
		retval = krb5_principal2salt(context, mname, &scratch);
		if (retval)
			return retval;
	}
	retval = krb5_c_string_to_key(context, etype, &pwd, salt?salt:&scratch,
				      key);

	if (!salt)
		krb5_xfree(scratch.data);
	memset(password, 0, sizeof(password)); /* erase it */
	return retval;

    } else {
	/* from somewhere else */
        krb5_ui_2 enctype;
	char defkeyfile[MAXPATHLEN+1];
	krb5_data *realm = krb5_princ_realm(context, mname);
	FILE *kf;

	retval = 0;
	key->magic = KV5M_KEYBLOCK;
	key->hKey = CK_INVALID_HANDLE;
	(void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
	(void) strncat(defkeyfile, realm->data,
		       min(sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
			   realm->length));
	defkeyfile[sizeof(defkeyfile) - 1] = '\0';
	
#ifdef ANSI_STDIO
	if (!(kf = fopen((keyfile) ? keyfile : defkeyfile, "rb")))
#else
	if (!(kf = fopen((keyfile) ? keyfile : defkeyfile, "r")))
#endif
	    return KRB5_KDB_CANTREAD_STORED;
	if (fread((krb5_pointer) &enctype, 2, 1, kf) != 1) {
	    retval = KRB5_KDB_CANTREAD_STORED;
	    goto errout;
	}

	/*
	 * If an enctype was specified, it should match.
	 * If enctype was not specified, then just accept what
	 * was in the keyfile.  If its bad, things will fail later.
	 */
	if (etype != ENCTYPE_UNKNOWN && enctype != etype) {
	    retval = KRB5_KDB_BADSTORED_MKEY;
	    goto errout;
	}
	key->enctype = enctype;
	if (fread((krb5_pointer) &key->length,
		  sizeof(key->length), 1, kf) != 1) {
	    retval = KRB5_KDB_CANTREAD_STORED;
	    goto errout;
	}
	if (!key->length || key->length < 0) {
	    retval = KRB5_KDB_BADSTORED_MKEY;
	    goto errout;
	}
	if (!(key->contents = (krb5_octet *)malloc(key->length))) {
	    retval = ENOMEM;
	    goto errout;
	}
	if (fread((krb5_pointer) key->contents,
		  sizeof(key->contents[0]), key->length, kf) != key->length) {
	    retval = KRB5_KDB_CANTREAD_STORED;
	    memset(key->contents, 0, key->length);
	    free(key->contents);
	    key->contents = 0;
	} else
	    retval = 0;

    errout:
	(void) fclose(kf);
	return retval;
    }
}
