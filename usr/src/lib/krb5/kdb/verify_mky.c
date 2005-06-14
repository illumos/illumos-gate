/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/verify_mky.c
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
 * krb5_db_verify_master_key();
 */

#include "k5-int.h"

/*
 * Verify that the master key in *mkey matches the database entry
 * for mprinc.
 */

krb5_error_code
krb5_db_verify_master_key(context, mprinc, mkey)
    krb5_context context;
    krb5_principal mprinc;
    krb5_keyblock *mkey;
{
    krb5_error_code retval;
    krb5_db_entry master_entry;
    int nprinc;
    krb5_boolean more;
    krb5_keyblock tempkey;

    nprinc = 1;
    if ((retval = krb5_db_get_principal(context, mprinc,
					&master_entry, &nprinc, &more)))
	return(retval);
	
    if (nprinc != 1) {
	if (nprinc)
	    krb5_db_free_principal(context, &master_entry, nprinc);
	return(KRB5_KDB_NOMASTERKEY);
    } else if (more) {
	krb5_db_free_principal(context, &master_entry, nprinc);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    }	

    (void) memset(&tempkey, 0, sizeof (krb5_keyblock));

    if ((retval = krb5_dbekd_decrypt_key_data(context, mkey, 
					      &master_entry.key_data[0],
					      &tempkey, NULL))) {
	krb5_db_free_principal(context, &master_entry, nprinc);
	return retval;
    }

    if (mkey->length != tempkey.length ||
	memcmp((char *)mkey->contents,
	       (char *)tempkey.contents,mkey->length)) {
	retval = KRB5_KDB_BADMASTERKEY;
    }

    krb5_free_keyblock_contents(context, &tempkey);
    krb5_db_free_principal(context, &master_entry, nprinc);
    
    return retval;
}
