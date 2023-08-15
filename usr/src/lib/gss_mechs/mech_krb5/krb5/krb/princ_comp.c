/*
 * lib/krb5/krb/princ_comp.c
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
 * compare two principals, returning a krb5_boolean true if equal, false if
 * not.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <k5-int.h>

/*ARGSUSED*/
krb5_boolean KRB5_CALLCONV
krb5_realm_compare(krb5_context context, krb5_const_principal princ1, krb5_const_principal princ2)
{
    if (krb5_princ_realm(context, princ1)->length !=
	krb5_princ_realm(context, princ2)->length ||
	memcmp (krb5_princ_realm(context, princ1)->data,
	 	krb5_princ_realm(context, princ2)->data,
		krb5_princ_realm(context, princ2)->length))
	return FALSE;

    return TRUE;
}

krb5_boolean KRB5_CALLCONV
krb5_principal_compare(krb5_context context, krb5_const_principal princ1, krb5_const_principal princ2)
{
    register int i;
    krb5_int32 nelem;

    nelem = krb5_princ_size(context, princ1);
    if (nelem != krb5_princ_size(context, princ2))
	return FALSE;

    if (! krb5_realm_compare(context, princ1, princ2))
	return FALSE;

    for (i = 0; i < (int) nelem; i++) {
	register const krb5_data *p1 = krb5_princ_component(context, princ1, i);
	register const krb5_data *p2 = krb5_princ_component(context, princ2, i);
	if (p1->length != p2->length ||
	    memcmp(p1->data, p2->data, p1->length))
	    return FALSE;
    }
    return TRUE;
}

/*
 * Solaris Kerberos: MS Interop requires that case insensitive comparisons of
 * service and host components are performed for key table lookup, etc.  Only
 * called if the private environment variable MS_INTEROP is defined.
 */
krb5_boolean KRB5_CALLCONV
__krb5_principal_compare_case_ins(krb5_context context,
    krb5_const_principal princ1, krb5_const_principal princ2)
{
    register int i;
    krb5_int32 nelem;

    nelem = krb5_princ_size(context, princ1);
    if (nelem != krb5_princ_size(context, princ2))
	return FALSE;

    if (! krb5_realm_compare(context, princ1, princ2))
	return FALSE;

    for (i = 0; i < (int) nelem; i++) {
	register const krb5_data *p1 = krb5_princ_component(context, princ1, i);
	register const krb5_data *p2 = krb5_princ_component(context, princ2, i);
	if (p1->length != p2->length ||
	    strncasecmp(p1->data, p2->data, p1->length))
	    return FALSE;
    }
    return TRUE;
}

krb5_boolean KRB5_CALLCONV krb5_is_referral_realm(const krb5_data *r)
{
    /*
     * Check for a match with KRB5_REFERRAL_REALM.  Currently this relies
     * on that string constant being zero-length.  (Unlike principal realm
     * names, KRB5_REFERRAL_REALM is known to be a string.)
     */
#ifdef DEBUG_REFERRALS
#if 0
    printf("krb5_is_ref_realm: checking <%s> for referralness: %s\n",
	   r->data,(r->length==0)?"true":"false");
#endif
#endif
    assert(strlen(KRB5_REFERRAL_REALM)==0);
    if (r->length==0)
        return TRUE;
    else
        return FALSE;
}
