/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/copy_princ.c
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
 * krb5_copy_principal()
 */

#include "k5-int.h"

/*
 * Copy a principal structure, with fresh allocation.
 */
/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_copy_principal(krb5_context context, krb5_const_principal inprinc, krb5_principal *outprinc)
{
    register krb5_principal tempprinc;
    register int i, nelems;

    tempprinc = (krb5_principal)MALLOC(sizeof(krb5_principal_data));

    if (tempprinc == 0)
	return ENOMEM;

    *tempprinc = *inprinc;

    nelems = (int) krb5_princ_size(context, inprinc);
    tempprinc->data = MALLOC(nelems * sizeof(krb5_data));

    if (tempprinc->data == 0) {
	FREE((char *)tempprinc, sizeof(krb5_principal_data));
	return ENOMEM;
    }

    for (i = 0; i < nelems; i++) {
	unsigned int len = krb5_princ_component(context, inprinc, i)->length;
	krb5_princ_component(context, tempprinc, i)->length = len;

        /*
         * Allocate one extra byte for trailing zero byte so string ops
         * can be used on the components.
         */
	if (len &&
            ((krb5_princ_component(context, tempprinc, i)->data =
	      MALLOC(len + 1)) == 0)) {
	    while (--i >= 0)
		FREE(krb5_princ_component(context, tempprinc, i)->data,
			krb5_princ_component(context, inprinc, i)->length + 1);
	    FREE (tempprinc->data, nelems * sizeof(krb5_data));
	    FREE (tempprinc,sizeof(krb5_principal_data));
	    return ENOMEM;
	}
	if (len)
	    (void) memcpy(krb5_princ_component(context, tempprinc, i)->data,
		   krb5_princ_component(context, inprinc, i)->data, len);
	else
	    krb5_princ_component(context, tempprinc, i)->data = 0;
    }

    tempprinc->realm.length = inprinc->realm.length;

    /*
     * Allocate one extra byte for the realm name string terminator. The
     * realm and principle component strings alway leave a null byte after
     * 'length' bytes that needs to be malloc/freed.
     */
    tempprinc->realm.data = MALLOC(tempprinc->realm.length + 1);
    if (!tempprinc->realm.data) {
        for (i = 0; i < nelems; i++)
	    FREE(krb5_princ_component(context, tempprinc, i)->data,
                krb5_princ_component(context, inprinc, i)->length + 1);
        FREE(tempprinc->data, nelems * sizeof(krb5_data));
        FREE(tempprinc, sizeof(krb5_principal_data));
	return ENOMEM;
    }
    memcpy(tempprinc->realm.data, inprinc->realm.data,
	   inprinc->realm.length);
    tempprinc->realm.data[tempprinc->realm.length] = 0;

    *outprinc = tempprinc;
    return 0;
}
