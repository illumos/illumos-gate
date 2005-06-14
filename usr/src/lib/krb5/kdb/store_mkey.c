#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/store_mkey.c
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
 * krb5_db_store_mkey():
 * Store a database master key in a file.
 */


#include <errno.h>
#include "k5-int.h"

/* Just in case sysincl.h didn't get it */

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

/*
 * Put the KDC database master key into a file.  If keyfile is NULL,
 * then a default name derived from the principal name mname is used.
 */

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

krb5_error_code
krb5_db_store_mkey(context, keyfile, mname, key)
    krb5_context context;
    char *keyfile;
    krb5_principal mname;
    krb5_keyblock *key;
{
    FILE *kf;
    krb5_error_code retval = 0;
    krb5_ui_2 enctype;
    char defkeyfile[MAXPATHLEN+1];
    krb5_data *realm = krb5_princ_realm(context, mname);
#if HAVE_UMASK
    int oumask;
#endif

    if (!keyfile) {
	(void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
	(void) strncat(defkeyfile, realm->data,
		       min(sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
			   realm->length));
	defkeyfile[sizeof(defkeyfile) - 1] = '\0';
	keyfile = defkeyfile;
    }

#if HAVE_UMASK
    oumask = umask(077);
#endif
#ifdef ANSI_STDIO
    if (!(kf = fopen(keyfile, "wb")))
#else
    if (!(kf = fopen(keyfile, "w")))
#endif
    {
#if HAVE_UMASK
	(void) umask(oumask);
#endif
	return errno;
    }
    enctype = key->enctype;
    if ((fwrite((krb5_pointer) &enctype,
		2, 1, kf) != 1) ||
	(fwrite((krb5_pointer) &key->length,
		sizeof(key->length), 1, kf) != 1) ||
	(fwrite((krb5_pointer) key->contents,
		sizeof(key->contents[0]), key->length, kf) != key->length)) {
	retval = errno;
	(void) fclose(kf);
    }
    if (fclose(kf) == EOF)
	retval = errno;
#if HAVE_UMASK
    (void) umask(oumask);
#endif
    return retval;
}
