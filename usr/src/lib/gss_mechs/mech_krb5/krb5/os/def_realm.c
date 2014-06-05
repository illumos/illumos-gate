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

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include "k5-int.h"
#include "os-proto.h"
#include <stdio.h>

/* 
 * Solaris Kerberos:
 * For krb5int_foreach_localaddr()
 */
#include "foreachaddr.h"

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
 * Solaris Kerberos:
 * The following prototype is needed because it is a
 * private interface that does not have a prototype in any .h
 */
extern struct hostent *res_gethostbyaddr(const char *addr, int len, int type);

/*
 * Solaris Kerberos:
 * krb5int_address_get_realm() given an address (either IPv4 or IPv6) tries to
 * find a realm based on the DNS name of that address. Assumes that its being
 * used as a callback for krb5int_foreach_localaddr().
 */
static int krb5int_address_get_realm(void *data, struct sockaddr *addr) {
	
	krb5_context context = data;
	struct hostent *he = NULL;

	switch (addr->sa_family) {
		case AF_INET:
			he = res_gethostbyaddr((char*)(&sa2sin(addr)->sin_addr),
			    sizeof(sa2sin(addr)->sin_addr), AF_INET);
			break;
		case AF_INET6:
			he = res_gethostbyaddr(
			    (char*)(&sa2sin6(addr)->sin6_addr),
			    sizeof(sa2sin6(addr)->sin6_addr), AF_INET6);
			break;
	}

	if (he) {
		/* Try to find realm using returned DNS name */
		krb5int_fqdn_get_realm(context, he->h_name,
		    &context->default_realm);

		/* If a realm was found return 1 to immediately halt
		 * krb5int_foreach_localaddr()
		 */ 
		if (context->default_realm != 0) {
			return (1);
		}
	}
	return (0);
}


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
    char localhost[MAX_DNS_NAMELEN+1];
    krb5_error_code retval;

    (void) memset(localhost, 0, sizeof(localhost));

    if (!context || (context->magic != KV5M_CONTEXT)) 
	    return KV5M_CONTEXT;

    /*
     * Solaris Kerberos: (illumos)
     * Another way to provide the default realm.
     */
    if (!context->default_realm) {
	if ((realm = getenv("KRB5_DEFAULT_REALM")) != NULL) {
	    context->default_realm = strdup(realm);
	    if (context->default_realm == NULL)
		return ENOMEM;
	}
    }

    if (!context->default_realm) {
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
        if (context->default_realm == 0) {
#ifdef KRB5_DNS_LOOKUP
            if (_krb5_use_dns_realm(context)) {
		/*
		 * Since this didn't appear in our config file, try looking
		 * it up via DNS.  Look for a TXT records of the form:
		 *
		 * _kerberos.<localhost>
		 * _kerberos.<domainname>
		 * _kerberos.<searchlist>
		 *
		 */
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
            } else
#endif /* KRB5_DNS_LOOKUP */
            if (getenv("MS_INTEROP") == NULL) {

	/*
	 * Solaris Kerberos:
	 * Try to find a realm based on one of the local IP addresses.
	 * Don't do this for AD, which often does _not_ support any
	 * DNS reverse lookup, making these queries take forever.
	 */
	(void) krb5int_foreach_localaddr(context,
	    krb5int_address_get_realm, 0, 0);

	/*
	 * Solaris Kerberos:
	 * As a final fallback try to find a realm based on the resolver search
	 * list
	 */
	if (context->default_realm == 0) {
		struct __res_state res;
		int i;

		(void) memset(&res, 0, sizeof (res));

		if (res_ninit(&res) == 0) {
			for (i = 0; res.dnsrch[i]; i++) {
				krb5int_domain_get_realm(context,
				    res.dnsrch[i], &context->default_realm); 

				if (context->default_realm != 0)
					break;
			}
		res_ndestroy(&res);
		}
	}

	}
	}
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
