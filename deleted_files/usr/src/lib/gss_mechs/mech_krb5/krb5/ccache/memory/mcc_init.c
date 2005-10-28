#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/memory/mcc_init.c
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
 * This file contains the source code for krb5_mcc_initialize.
 */

#include "mcc.h"

/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the file cred cache id.  If the cache exists, its
 * contents are destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */
void krb5_mcc_free KRB5_PROTOTYPE((krb5_context context, krb5_ccache id));

krb5_error_code KRB5_CALLCONV
krb5_mcc_initialize(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
    krb5_error_code ret; 

    krb5_mcc_free(context, id);
    ret = krb5_copy_principal(context, princ,
        &((krb5_mcc_data *)id->data)->prin);
    if (ret == KRB5_OK)
        krb5_change_cache();
    return ret;
}
