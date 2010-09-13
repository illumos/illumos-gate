/*
 * lib/krb5/keytab/ktfns.c
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.
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
 */

/*
 * Dispatch methods for keytab code.
 */

#include "k5-int.h"

char * KRB5_CALLCONV
krb5_kt_get_type (krb5_context context, krb5_keytab keytab)
{
    return keytab->ops->prefix;
}

krb5_error_code KRB5_CALLCONV
krb5_kt_get_name(krb5_context context, krb5_keytab keytab, char *name,
		 unsigned int namelen)
{
    return krb5_x((keytab)->ops->get_name,(context, keytab,name,namelen));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_close(krb5_context context, krb5_keytab keytab)
{
    return krb5_x((keytab)->ops->close,(context, keytab));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_get_entry(krb5_context context, krb5_keytab keytab,
		  krb5_const_principal principal, krb5_kvno vno,
		  krb5_enctype enctype, krb5_keytab_entry *entry)
{
    krb5_error_code err;
    krb5_principal_data princ_data;

    if (krb5_is_referral_realm(&principal->realm)) {
	char *realm;
	princ_data = *principal;
	principal = &princ_data;
	err = krb5_get_default_realm(context, &realm);
	if (err)
	    return err;
	princ_data.realm.data = realm;
	princ_data.realm.length = strlen(realm);
    }
    err = krb5_x((keytab)->ops->get,(context, keytab, principal, vno, enctype,
				     entry));
    if (principal == &princ_data)
	krb5_free_default_realm(context, princ_data.realm.data);
    return err;
}

krb5_error_code KRB5_CALLCONV
krb5_kt_start_seq_get(krb5_context context, krb5_keytab keytab,
		      krb5_kt_cursor *cursor)
{
    return krb5_x((keytab)->ops->start_seq_get,(context, keytab, cursor));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_next_entry(krb5_context context, krb5_keytab keytab,
		   krb5_keytab_entry *entry, krb5_kt_cursor *cursor)
{
    return krb5_x((keytab)->ops->get_next,(context, keytab, entry, cursor));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_end_seq_get(krb5_context context, krb5_keytab keytab,
		    krb5_kt_cursor *cursor)
{
    return krb5_x((keytab)->ops->end_get,(context, keytab, cursor));
}
