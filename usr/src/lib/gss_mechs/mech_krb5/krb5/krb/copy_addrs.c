/*
 * lib/krb5/krb/copy_addrs.c
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
 * krb5_copy_addresses()
 */

#include "k5-int.h"

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_copy_addr(krb5_context context, const krb5_address *inad, krb5_address **outad)
{
    krb5_address *tmpad;

    if (!(tmpad = (krb5_address *)malloc(sizeof(*tmpad))))
	return ENOMEM;
    *tmpad = *inad;
    if (!(tmpad->contents = (krb5_octet *)malloc(inad->length))) {
	krb5_xfree(tmpad);
	return ENOMEM;
    }
    memcpy((char *)tmpad->contents, (char *)inad->contents, inad->length);
    *outad = tmpad;
    return 0;
}

/*
 * Copy an address array, with fresh allocation.
 */
krb5_error_code KRB5_CALLCONV
krb5_copy_addresses(krb5_context context, krb5_address *const *inaddr, krb5_address ***outaddr)
{
    krb5_error_code retval;
    krb5_address ** tempaddr;
    register unsigned int nelems = 0;

    if (!inaddr) {
	    *outaddr = 0;
	    return 0;
    }

    while (inaddr[nelems]) nelems++;

    /* one more for a null terminated list */
    if (!(tempaddr = (krb5_address **) calloc(nelems+1, sizeof(*tempaddr))))
	return ENOMEM;

    for (nelems = 0; inaddr[nelems]; nelems++) {
	retval = krb5_copy_addr(context, inaddr[nelems], &tempaddr[nelems]);
        if (retval) {
	    krb5_free_addresses(context, tempaddr);
	    return retval;
	}
    }

    *outaddr = tempaddr;
    return 0;
}

#if 0
/*
 * Append an address array, to another address array, with fresh allocation.
 * Note that this function may change the value of *outaddr even if it
 * returns failure, but it will not change the contents of the list.
 */
krb5_error_code
krb5_append_addresses(context, inaddr, outaddr)
    krb5_context context;
	krb5_address * const * inaddr;
	krb5_address ***outaddr;
{
    krb5_error_code retval;
    krb5_address ** tempaddr;
    krb5_address ** tempaddr2;
    register unsigned int nelems = 0;
    register int norigelems = 0;

    if (!inaddr)
	return 0;

    tempaddr2 = *outaddr;

    while (inaddr[nelems]) nelems++;
    while (tempaddr2[norigelems]) norigelems++;

    tempaddr = (krb5_address **) realloc((char *)*outaddr,
		       (nelems + norigelems + 1) * sizeof(*tempaddr));
    if (!tempaddr)
	return ENOMEM;

    /* The old storage has been freed.  */
    *outaddr = tempaddr;


    for (nelems = 0; inaddr[nelems]; nelems++) {
	retval = krb5_copy_addr(context, inaddr[nelems],
				&tempaddr[norigelems + nelems]);
	if (retval)
	    goto cleanup;
    }

    tempaddr[norigelems + nelems] = 0;
    return 0;

  cleanup:
    while (--nelems >= 0)
	krb5_free_address(context, tempaddr[norigelems + nelems]);

    /* Try to allocate a smaller amount of memory for *outaddr.  */
    tempaddr = (krb5_address **) realloc((char *)tempaddr,
					 (norigelems + 1) * sizeof(*tempaddr));
    if (tempaddr)
	*outaddr = tempaddr;
    return retval;
}
#endif

