/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/copy_auth.c
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
 * krb5_copy_authdata()
 */

#include "k5-int.h"

/*ARGSUSED*/
static krb5_error_code
krb5_copy_authdatum(krb5_context context, const krb5_authdata *inad, krb5_authdata **outad)
{
    krb5_authdata *tmpad;

    if (!(tmpad = (krb5_authdata *)MALLOC(sizeof(*tmpad))))
	return ENOMEM;
    *tmpad = *inad;
    if (!(tmpad->contents = (krb5_octet *)MALLOC(inad->length))) {
	krb5_xfree_wrap(tmpad, inad->length);
	return ENOMEM;
    }
    (void) memcpy((char *)tmpad->contents, (char *)inad->contents, inad->length);
    *outad = tmpad;
    return 0;
}

/*
 * Copy an authdata array, with fresh allocation.
 */
krb5_error_code KRB5_CALLCONV
krb5_copy_authdata(krb5_context context, krb5_authdata *const *inauthdat, krb5_authdata ***outauthdat)
{
    krb5_error_code retval;
    krb5_authdata ** tempauthdat;
    register unsigned int nelems = 0;

    if (!inauthdat) {
	    *outauthdat = 0;
	    return 0;
    }

    while (inauthdat[nelems]) nelems++;

    /* one more for a null terminated list */
    if (!(tempauthdat = (krb5_authdata **) CALLOC(nelems+1,
						  sizeof(*tempauthdat))))
	return ENOMEM;

    for (nelems = 0; inauthdat[nelems]; nelems++) {
	retval = krb5_copy_authdatum(context, inauthdat[nelems],
				     &tempauthdat[nelems]);
	if (retval) {
	    krb5_free_authdata(context, tempauthdat);
	    return retval;
	}
    }

    *outauthdat = tempauthdat;
    return 0;
}
