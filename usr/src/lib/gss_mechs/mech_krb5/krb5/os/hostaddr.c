/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/os/hostaddr.c
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
 * This routine returns a list of krb5 addresses given a hostname.
 *
 */

#include "k5-int.h"
#include <locale.h>
#include "fake-addrinfo.h"

krb5_error_code
krb5_os_hostaddr(krb5_context context, const char *name, krb5_address ***ret_addrs)
{
    krb5_error_code 	retval;
    krb5_address 	**addrs;
    int			i, j, r;
    struct addrinfo hints, *ai, *aip;

    if (!name) {
	return KRB5_ERR_BAD_HOSTNAME;
    }

    memset (&hints, 0, sizeof (hints));
    hints.ai_flags = AI_NUMERICHOST;
    /* We don't care what kind at this point, really, but without
       this, we can get back multiple sockaddrs per address, for
       SOCK_DGRAM, SOCK_STREAM, and SOCK_RAW.  I haven't checked if
       that's what the spec indicates.  */
    hints.ai_socktype = SOCK_DGRAM;

    r = getaddrinfo (name, 0, &hints, &ai);
    if (r && AI_NUMERICHOST != 0) {
	hints.ai_flags &= ~AI_NUMERICHOST;
	r = getaddrinfo (name, 0, &hints, &ai);
    }
    if (r) {
        krb5_set_error_message(context, KRB5_ERR_BAD_HOSTNAME,
			    dgettext(TEXT_DOMAIN,
				    "Hostname cannot be canonicalized for '%s': %s"),
			    name, strerror(r));
	return KRB5_ERR_BAD_HOSTNAME;
    }

    for (i = 0, aip = ai; aip; aip = aip->ai_next) {
	switch (aip->ai_addr->sa_family) {
	case AF_INET:
#ifdef KRB5_USE_INET6
	case AF_INET6:
#endif
	    i++;
	default:
	    /* Ignore addresses of unknown families.  */
	    ;
	}
    }

    addrs = malloc ((i+1) * sizeof(*addrs));
    if (!addrs)
	return errno;

    for (j = 0; j < i + 1; j++)
	addrs[j] = 0;

    for (i = 0, aip = ai; aip; aip = aip->ai_next) {
	void *ptr;
	size_t addrlen;
	int atype;

	switch (aip->ai_addr->sa_family) {
	case AF_INET:
	    addrlen = sizeof (struct in_addr);
	    /*LINTED*/
	    ptr = &sa2sin(aip->ai_addr)->sin_addr;
	    atype = ADDRTYPE_INET;
	    break;
#ifdef KRB5_USE_INET6
	case AF_INET6:
	    addrlen = sizeof (struct in6_addr);
	    /*LINTED*/
	    ptr = &sa2sin6(aip->ai_addr)->sin6_addr;
	    atype = ADDRTYPE_INET6;
	    break;
#endif
	default:
	    continue;
	}
	addrs[i] = (krb5_address *) malloc(sizeof(krb5_address));
	if (!addrs[i]) {
	    retval = ENOMEM;
	    goto errout;
	}
	addrs[i]->magic = KV5M_ADDRESS;
	addrs[i]->addrtype = atype;
	addrs[i]->length = addrlen;
	addrs[i]->contents = malloc(addrs[i]->length);
	if (!addrs[i]->contents) {
	    retval = ENOMEM;
	    goto errout;
	}
	memcpy (addrs[i]->contents, ptr, addrs[i]->length);
	i++;
    }

    *ret_addrs = addrs;
    if (ai)
	freeaddrinfo(ai);
    return 0;

errout:
    /* Solaris Kerberos */
    if (addrs)
	krb5_free_addresses(context, addrs);
    if (ai)
	freeaddrinfo(ai);
    return retval;

}

