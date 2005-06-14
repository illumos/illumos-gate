/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/os/localaddr.c
 *
 * Copyright 1990,1991,2000,2001,2002 by the Massachusetts Institute of Technology.
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
 * Return the protocol addresses supported by this host.
 *
 * XNS support is untested, but "Should just work".  (Hah!)
 */

#define NEED_SOCKETS
#include <k5-int.h>

/* needed for solaris, harmless elsewhere... */
#define BSD_COMP
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <stddef.h>
#include <ctype.h>

static krb5_error_code
get_localaddrs (krb5_context context, krb5_address ***addr, int use_profile);

struct localaddr_data {
    int count, mem_err, cur_idx, cur_size;
    krb5_address **addr_temp;
};

static int
count_addrs (void *P_data, struct sockaddr *a)
     /*@*/
{
    struct localaddr_data *data = P_data;
    switch (a->sa_family) {
    case AF_INET:
#ifdef KRB5_USE_INET6
    case AF_INET6:
#endif
#ifdef KRB5_USE_NS
    case AF_XNS:
#endif
	data->count++;
	break;
    default:
	break;
    }
    return 0;
}

static int
allocate (void *P_data)
{
    struct localaddr_data *data = P_data;
    int i;
    void *n;

    n = realloc (data->addr_temp,
		 (1 + data->count + data->cur_idx) * sizeof (krb5_address *));
    if (n == 0) {
	data->mem_err++;
	return 1;
    }
    data->addr_temp = n;
    data->cur_size = 1 + data->count + data->cur_idx;
    for (i = data->cur_idx; i <= data->count + data->cur_idx; i++)
	data->addr_temp[i] = 0;
    return 0;
}

static krb5_address *
make_addr (int type, size_t length, const void *contents)
{
    krb5_address *a;
    void *data;

    data = malloc (length);
    if (data == NULL)
	return NULL;
    a = malloc (sizeof (krb5_address));
    if (a == NULL) {
	free (data);
	return NULL;
    }
    memcpy (data, contents, length);
    a->magic = KV5M_ADDRESS;
    a->addrtype = type;
    a->length = length;
    a->contents = data;
    return a;
}

static int
add_addr (void *P_data, struct sockaddr *a)
     /*@modifies *P_data@*/
{
    struct localaddr_data *data = P_data;
    krb5_address *address = 0;
#ifdef KRB5_DEBUG
    char buf[256];
#endif

    KRB5_LOG(KRB5_INFO, "add_addr() a->sa_family=%d", a->sa_family);

    switch (a->sa_family) {
#ifdef HAVE_NETINET_IN_H
    case AF_INET:
	address = make_addr (ADDRTYPE_INET, sizeof (struct in_addr),
			    /*LINTED*/
			     &((const struct sockaddr_in *) a)->sin_addr);
#ifdef KRB5_DEBUG
	inet_ntop(AF_INET, &sa2sin(a)->sin_addr, buf, sizeof(buf));
#endif
	KRB5_LOG(KRB5_INFO, "add_addr() AF_INET addr=%s", buf);
	if (address == NULL)
	    data->mem_err++;
	break;

#ifdef KRB5_USE_INET6
    case AF_INET6:
    {
	/*LINTED*/
	const struct sockaddr_in6 *in = (const struct sockaddr_in6 *) a;
	
#ifdef KRB5_DEBUG
	inet_ntop(AF_INET6, &sa2sin6(a)->sin6_addr, buf, sizeof(buf));
#endif
	KRB5_LOG(KRB5_INFO, "add_addr() AF_INET6 addr=%s", buf);

	if (IN6_IS_ADDR_LINKLOCAL (&in->sin6_addr)) {
	    KRB5_LOG0(KRB5_INFO, "add_addr() AF_INET6 linklocal, skipping");
	    break;
	}

	address = make_addr (ADDRTYPE_INET6, sizeof (struct in6_addr),
			     &in->sin6_addr);
	if (address == NULL)
	    data->mem_err++;
	break;
    }
#endif /* KRB5_USE_INET6 */
#endif /* netinet/in.h */

#ifdef KRB5_USE_NS
    case AF_XNS:
	address = make_addr (ADDRTYPE_XNS, sizeof (struct ns_addr),
			     &((const struct sockaddr_ns *)a)->sns_addr);
#ifdef KRB5_DEBUG
	inet_ntop(AF_XNS, &((const struct sockaddr_ns *)a)->sns_addr,
		buf, sizeof(buf));
#endif
	KRB5_LOG(KRB5_INFO, "add_addr() AF_XNS addr=%s", buf);
	if (address == NULL)
	    data->mem_err++;
	break;
#endif

#ifdef AF_LINK
	/* Some BSD-based systems (e.g. NetBSD 1.5) and AIX will
	   include the ethernet address, but we don't want that, at
	   least for now.  */
    case AF_LINK:
	break;
#endif
    /*
     * Add more address families here..
     */
    default:
	break;
    }
#ifdef __LCLINT__
    /* Redundant but unconditional store un-confuses lclint.  */
    data->addr_temp[data->cur_idx] = address;
#endif
    if (address) {
	data->addr_temp[data->cur_idx++] = address;
    }

    return data->mem_err;
}

static krb5_error_code
krb5_os_localaddr_profile (krb5_context context, struct localaddr_data *datap)
{
    krb5_error_code err;
    static const char *profile_name[] = {
	"libdefaults", "extra_addresses", 0
    };
    char **values;
    char **iter;
    krb5_address **newaddrs;

    err = profile_get_values (context->profile, profile_name, &values);
    /* Ignore all errors for now?  */
    if (err)
	return 0;

    for (iter = values; *iter; iter++) {
	char *cp = *iter, *next, *current;
	int i, count;

	for (cp = *iter, next = 0; *cp; cp = next) {
	    while (isspace ((int) *cp) || *cp == ',')
		cp++;
	    if (*cp == 0)
		break;
	    /* Start of an address.  */
	    current = cp;
	    while (*cp != 0 && !isspace((int) *cp) && *cp != ',')
		cp++;
	    if (*cp != 0) {
		next = cp + 1;
		*cp = 0;
	    } else
		next = cp;
	    /* Got a single address, process it.  */
	    newaddrs = 0;
	    err = krb5_os_hostaddr (context, current, &newaddrs);
	    if (err)
		continue;
	    for (i = 0; newaddrs[i]; i++) {
	    }

	    count = i;

	    if (datap->cur_idx + count >= datap->cur_size) {
		krb5_address **bigger;
		bigger = realloc (datap->addr_temp,
				  sizeof (krb5_address *) * (datap->cur_idx + count));
		if (bigger) {
		    datap->addr_temp = bigger;
		    datap->cur_size = datap->cur_idx + count;
		}
	    }
	    for (i = 0; i < count; i++) {
		if (datap->cur_idx < datap->cur_size)
		    datap->addr_temp[datap->cur_idx++] = newaddrs[i];
		else
		    free (newaddrs[i]->contents), free (newaddrs[i]);
	    }
	    free (newaddrs);
	}
    }
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_os_localaddr(krb5_context context, krb5_address ***addr)
{
    return get_localaddrs(context, addr, 1);
}

krb5_error_code
krb5int_local_addresses(krb5_context context, krb5_address ***addr)
{
    return get_localaddrs(context, addr, 0);
}

static krb5_error_code
get_localaddrs (krb5_context context, krb5_address ***addr, int use_profile)
{
    struct localaddr_data data = { 0 };
    int r;
    /* krb5_error_code err; */

    if (use_profile) {
	/* err = krb5_os_localaddr_profile (context, &data); */
	/* ignore err for now */
	(void) krb5_os_localaddr_profile (context, &data);
    }

    r = foreach_localaddr (&data, count_addrs, allocate, add_addr);
    if (r != 0) {
	int i;
	if (data.addr_temp) {
	    for (i = 0; i < data.count; i++)
		krb5_xfree (data.addr_temp[i]);
	    free (data.addr_temp);
	}
	if (data.mem_err)
	    return ENOMEM;
	else
	    return r;
    }

    data.cur_idx++; /* null termination */
    if (data.mem_err)
	return ENOMEM;
    else if (data.cur_idx == data.count)
	*addr = data.addr_temp;
    else {
	/* This can easily happen if we have IPv6 link-local
	   addresses.  Just shorten the array.  */
	*addr = (krb5_address **) realloc (data.addr_temp,
					   (sizeof (krb5_address *)
					    * data.cur_idx));
	if (*addr == 0)
	    /* Okay, shortening failed, but the original should still
	       be intact.  */
	    *addr = data.addr_temp;
    }

    return 0;
}

