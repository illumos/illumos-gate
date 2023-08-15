/*
 * lib/krb5/krb/bld_princ.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
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
 * Build a principal from a list of strings
 */

#include <stdarg.h>
#include "k5-int.h"

/*ARGSUSED*/
krb5_error_code
KRB5_CALLCONV
krb5_build_principal_va(krb5_context context, krb5_principal princ, unsigned int rlen, const char *realm, va_list ap)
{
    register int i, count = 0;
    register char *next;
    char *tmpdata;
    krb5_data *data;

    /* guess at an initial sufficent count of 2 pieces */
    count = 2;

    /* get space for array and realm, and insert realm */
    data = (krb5_data *) malloc(sizeof(krb5_data) * count);
    if (data == 0)
	return ENOMEM;
    krb5_princ_set_realm_length(context, princ, rlen);
    tmpdata = malloc(rlen + 1);
    if (!tmpdata) {
	free (data);
	return ENOMEM;
    }
    krb5_princ_set_realm_data(context, princ, tmpdata);
    memcpy(tmpdata, realm, rlen);
    tmpdata[rlen] = '\0';

    /* process rest of components */

    for (i = 0, next = va_arg(ap, char *);
	 next;
	 next = va_arg(ap, char *), i++) {
	if (i == count) {
	    /* not big enough.  realloc the array */
	    krb5_data *p_tmp;
	    p_tmp = (krb5_data *) realloc((char *)data,
					  sizeof(krb5_data)*(count*2));
	    if (!p_tmp) {
	    free_out:
		    while (--i >= 0)
			krb5_xfree(data[i].data);
		    krb5_xfree(data);
		    krb5_xfree(tmpdata);
		    return (ENOMEM);
	    }
	    count *= 2;
	    data = p_tmp;
	}

	data[i].length = strlen(next);
	data[i].data = strdup(next);
	if (!data[i].data)
	    goto free_out;
    }
    princ->data = data;
    princ->length = i;
    princ->type = KRB5_NT_UNKNOWN;
    princ->magic = KV5M_PRINCIPAL;
    return 0;
}

krb5_error_code KRB5_CALLCONV_C
krb5_build_principal(krb5_context context,  krb5_principal * princ,
		     unsigned int rlen,
		     const char * realm, ...)
{
    va_list ap;
    krb5_error_code retval;
    krb5_principal pr_ret = (krb5_principal)malloc(sizeof(krb5_principal_data));

    if (!pr_ret)
	return ENOMEM;

    va_start(ap, realm);
    retval = krb5_build_principal_va(context, pr_ret, rlen, realm, ap);
    va_end(ap);
    if (retval == 0)
	*princ = pr_ret;
    return retval;
}
