/*
 * lib/krb5/krb/pr_to_salt.c
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
 * krb5_principal2salt()
 */

#include "k5-int.h"

static krb5_error_code krb5_principal2salt_internal
    (krb5_context, krb5_const_principal, krb5_data *ret, int);

/*
 * Convert a krb5_principal into the default salt for that principal.
 */
/*ARGSUSED*/
static krb5_error_code
krb5_principal2salt_internal(krb5_context context, register krb5_const_principal pr, krb5_data *ret, int use_realm)
{
    unsigned int size = 0, offset=0;
    krb5_int32 nelem;
    register int i;

    if (pr == 0) {
	ret->length = 0;
	ret->data = 0;
	return 0;
    }

    nelem = krb5_princ_size(context, pr);

    if (use_realm)
	    size += krb5_princ_realm(context, pr)->length;

    for (i = 0; i < (int) nelem; i++)
	size += krb5_princ_component(context, pr, i)->length;

    ret->length = size;
    if (!(ret->data = malloc (size)))
	return ENOMEM;

    if (use_realm) {
	    offset = krb5_princ_realm(context, pr)->length;
	    memcpy(ret->data, krb5_princ_realm(context, pr)->data, offset);
    }

    for (i = 0; i < (int) nelem; i++) {
	memcpy(&ret->data[offset], krb5_princ_component(context, pr, i)->data,
	       krb5_princ_component(context, pr, i)->length);
	offset += krb5_princ_component(context, pr, i)->length;
    }
    return 0;
}

krb5_error_code
krb5_principal2salt(krb5_context context, register krb5_const_principal pr, krb5_data *ret)
{
	return krb5_principal2salt_internal(context, pr, ret, 1);
}

krb5_error_code
krb5_principal2salt_norealm(krb5_context context, register krb5_const_principal pr, krb5_data *ret)
{
	return krb5_principal2salt_internal(context, pr, ret, 0);
}
