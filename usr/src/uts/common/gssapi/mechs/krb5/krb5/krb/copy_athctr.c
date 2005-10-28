/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/krb/copy_athctr.c
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
 * krb5_copy_authenticator()
 */

#include <k5-int.h>

krb5_error_code KRB5_CALLCONV
krb5_copy_authenticator(krb5_context context, const krb5_authenticator *authfrom, krb5_authenticator **authto)
{
    krb5_error_code retval;
    krb5_authenticator *tempto;

    if (!(tempto = (krb5_authenticator *)MALLOC(sizeof(*tempto))))
	return ENOMEM;
#ifdef HAVE_C_STRUCTURE_ASSIGNMENT
    *tempto = *authfrom;
#else
    (void) memcpy(tempto, authfrom, sizeof(krb5_authenticator));
#endif

    retval = krb5_copy_principal(context, authfrom->client, &tempto->client);
    if (retval) {
	krb5_xfree_wrap(tempto, sizeof(*tempto));
	return retval;
    }
    
    if (authfrom->checksum &&
	(retval = krb5_copy_checksum(context, authfrom->checksum, &tempto->checksum))) {
	    krb5_free_principal(context, tempto->client);    
	    krb5_xfree_wrap(tempto, sizeof(*tempto));
	    return retval;
    }
    
    if (authfrom->subkey) {
	    retval = krb5_copy_keyblock(context, authfrom->subkey, &tempto->subkey);
	    if (retval) {
		    krb5_xfree_wrap(tempto->subkey, sizeof(krb5_keyblock));
		    krb5_free_checksum(context, tempto->checksum);
		    krb5_free_principal(context, tempto->client);    
		    krb5_xfree_wrap(tempto, sizeof(*tempto));
		    return retval;
	    }
    }
    
    if (authfrom->authorization_data) {
		retval = krb5_copy_authdata(context, authfrom->authorization_data,
				    &tempto->authorization_data);
		if (retval) {
		    krb5_xfree_wrap(tempto->subkey, sizeof(krb5_keyblock));
		    krb5_free_checksum(context, tempto->checksum);
		    krb5_free_principal(context, tempto->client);    
		    krb5_free_authdata(context, tempto->authorization_data);
		    krb5_xfree_wrap(tempto, sizeof(*tempto));
		    return retval;
		}
    }

    *authto = tempto;
    return 0;
}
