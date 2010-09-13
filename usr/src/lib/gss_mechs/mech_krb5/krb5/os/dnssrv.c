/*
 * lib/krb5/os/dnssrv.c
 *
 * Copyright 1990,2000,2001,2002,2003 by the Massachusetts Institute of Technology.
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
 * do DNS SRV RR queries
 */

#include "autoconf.h"
#ifdef KRB5_DNS_LOOKUP

#include "dnsglue.h"

/*
 * Lookup a KDC via DNS SRV records
 */

void krb5int_free_srv_dns_data (struct srv_dns_entry *p)
{
    struct srv_dns_entry *next;
    while (p) {
	next = p->next;
	free(p->host);
	free(p);
	p = next;
    }
}

/* Do DNS SRV query, return results in *answers.

   Make best effort to return all the data we can.  On memory or
   decoding errors, just return what we've got.  Always return 0,
   currently.  */

krb5_error_code
krb5int_make_srv_query_realm(const krb5_data *realm,
			     const char *service,
			     const char *protocol,
			     struct srv_dns_entry **answers)
{
    const unsigned char *p = NULL, *base = NULL;
    char host[MAXDNAME], *h;
    int size, ret, rdlen, nlen;
    unsigned short priority, weight, port;
    struct krb5int_dns_state *ds = NULL;

    struct srv_dns_entry *head = NULL;
    struct srv_dns_entry *srv = NULL, *entry = NULL;

    /*
     * First off, build a query of the form:
     *
     * service.protocol.realm
     *
     * which will most likely be something like:
     *
     * _kerberos._udp.REALM
     *
     */

    if (memchr(realm->data, 0, realm->length))
	return 0;
    if ( strlen(service) + strlen(protocol) + realm->length + 6 
         > MAXDNAME )
	return 0;
    sprintf(host, "%s.%s.%.*s", service, protocol, (int) realm->length,
	    realm->data);

    /* Realm names don't (normally) end with ".", but if the query
       doesn't end with "." and doesn't get an answer as is, the
       resolv code will try appending the local domain.  Since the
       realm names are absolutes, let's stop that.  

       But only if a name has been specified.  If we are performing
       a search on the prefix alone then the intention is to allow
       the local domain or domain search lists to be expanded.  */

    h = host + strlen (host);
    if ((h[-1] != '.') && ((h - host + 1) < sizeof(host)))
        strcpy (h, ".");

#ifdef TEST
    fprintf (stderr, "sending DNS SRV query for %s\n", host);
#endif

    size = krb5int_dns_init(&ds, host, C_IN, T_SRV);
    if (size < 0)
	goto out;

    for (;;) {
	ret = krb5int_dns_nextans(ds, &base, &rdlen);
	if (ret < 0 || base == NULL)
	    goto out;

	p = base;

	SAFE_GETUINT16(base, rdlen, p, 2, priority, out);
	SAFE_GETUINT16(base, rdlen, p, 2, weight, out);
	SAFE_GETUINT16(base, rdlen, p, 2, port, out);

	/*
	 * RFC 2782 says the target is never compressed in the reply;
	 * do we believe that?  We need to flatten it anyway, though.
	 */
	nlen = krb5int_dns_expand(ds, p, host, sizeof(host));
	if (nlen < 0 || !INCR_OK(base, rdlen, p, nlen))
	    goto out;

	/*
	 * We got everything!  Insert it into our list, but make sure
	 * it's in the right order.  Right now we don't do anything
	 * with the weight field
	 */

	srv = (struct srv_dns_entry *) malloc(sizeof(struct srv_dns_entry));
	if (srv == NULL)
	    goto out;
	
	srv->priority = priority;
	srv->weight = weight;
	srv->port = port;
	/* The returned names are fully qualified.  Don't let the
	   local resolver code do domain search path stuff.  */
	if (strlen(host) + 2 < sizeof(host))
	    strcat(host, ".");
	srv->host = strdup(host);
	if (srv->host == NULL) {
	    free(srv);
	    goto out;
	}

	if (head == NULL || head->priority > srv->priority) {
	    srv->next = head;
	    head = srv;
	} else {
	    /*
	     * This is confusing.  Only insert an entry into this
	     * spot if:
	     * The next person has a higher priority (lower priorities
	     * are preferred).
	     * Or
	     * There is no next entry (we're at the end)
	     */
	    for (entry = head; entry != NULL; entry = entry->next) {
		if ((entry->next &&
		     entry->next->priority > srv->priority) ||
		    entry->next == NULL) {
		    srv->next = entry->next;
		    entry->next = srv;
		    break;
		}
	    }
	}
    }

out:
    if (ds != NULL) {
	krb5int_dns_fini(ds);
	ds = NULL;
    }
    *answers = head;
    return 0;
}
#endif
