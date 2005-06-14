#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/os/def_realm.c
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
 * krb5_get_default_realm(), krb5_set_default_realm(),
 * krb5_free_default_realm() functions.
 */

#include <k5-int.h>
#include "os-proto.h"
#include <stdio.h>

#ifdef KRB5_DNS_LOOKUP	     
#ifdef WSHELPER
#include <wshelper.h>
#else /* WSHELPER */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#endif /* WSHELPER */

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define MAX_DNS_NAMELEN (15*(MAXHOSTNAMELEN + 1)+1)

#endif /* KRB5_DNS_LOOKUP */

/*
 * Retrieves the default realm to be used if no user-specified realm is
 *  available.  [e.g. to interpret a user-typed principal name with the
 *  realm omitted for convenience]
 * 
 *  returns system errors, NOT_ENOUGH_SPACE, KV5M_CONTEXT
*/

/*
 * Implementation:  the default realm is stored in a configuration file,
 * named by krb5_config_file;  the first token in this file is taken as
 * the default local realm name.
 */

krb5_error_code KRB5_CALLCONV
krb5_get_default_realm(krb5_context context, char **lrealm)
{
    char *realm = 0;
    char *cp;
    krb5_error_code retval;

    if (!context || (context->magic != KV5M_CONTEXT)) 
	    return KV5M_CONTEXT;

    if (!context->default_realm) {
        /*
         * XXX should try to figure out a reasonable default based
         * on the host's DNS domain.
         */
        context->default_realm = 0;
        if (context->profile != 0) {
            retval = profile_get_string(context->profile, "libdefaults",
                                        "default_realm", 0, 0,
                                        &realm);

            if (!retval && realm) {
                context->default_realm = malloc(strlen(realm) + 1);
                if (!context->default_realm) {
                    profile_release_string(realm);
                    return ENOMEM;
                }
                strcpy(context->default_realm, realm);
                profile_release_string(realm);
            }
        }
#ifndef KRB5_DNS_LOOKUP
        else 
            return KRB5_CONFIG_CANTOPEN;
#else /* KRB5_DNS_LOOKUP */
        if (context->default_realm == 0) {
            int use_dns =  _krb5_use_dns_realm(context);
            if ( use_dns ) {
		/*
		 * Since this didn't appear in our config file, try looking
		 * it up via DNS.  Look for a TXT records of the form:
		 *
		 * _kerberos.<localhost>
		 * _kerberos.<domainname>
		 * _kerberos.<searchlist>
		 *
		 */
		char localhost[MAX_DNS_NAMELEN+1];
		char * p;

		krb5int_get_fq_local_hostname (localhost, sizeof(localhost));

		if ( localhost[0] ) {
		    p = localhost;
		    do {
			retval = krb5_try_realm_txt_rr("_kerberos", p, 
						       &context->default_realm);
			p = strchr(p,'.');
			if (p)
			    p++;
		    } while (retval && p && p[0]);

		    if (retval)
			retval = krb5_try_realm_txt_rr("_kerberos", "", 
						       &context->default_realm);
		} else {
		    retval = krb5_try_realm_txt_rr("_kerberos", "", 
						   &context->default_realm);
		}
		if (retval) {
		    return(KRB5_CONFIG_NODEFREALM);
		}
            }
        }
#endif /* KRB5_DNS_LOOKUP */
    }

    if (context->default_realm == 0)
	return(KRB5_CONFIG_NODEFREALM);
    if (context->default_realm[0] == 0) {
        free (context->default_realm);
        context->default_realm = 0;
        return KRB5_CONFIG_NODEFREALM;
    }

    realm = context->default_realm;
    
    /*LINTED*/
    if (!(*lrealm = cp = malloc((unsigned int) strlen(realm) + 1)))
        return ENOMEM;
    strcpy(cp, realm);
    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_set_default_realm(krb5_context context, const char *lrealm)
{
    if (!context || (context->magic != KV5M_CONTEXT)) 
	    return KV5M_CONTEXT;

    if (context->default_realm) {
	    free(context->default_realm);
	    context->default_realm = 0;
    }

    /* Allow the user to clear the default realm setting by passing in 
       NULL */
    if (!lrealm) return 0;

    context->default_realm = malloc(strlen (lrealm) + 1);

    if (!context->default_realm)
	    return ENOMEM;

    strcpy(context->default_realm, lrealm);
    return(0);

}

/*ARGSUSED*/
void KRB5_CALLCONV
krb5_free_default_realm(krb5_context context, char *lrealm)
{
	free (lrealm);
}
