/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/os/locate_kdc.c
 *
 * Copyright 1990,2000,2001,2002 by the Massachusetts Institute of Technology.
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
 * get socket addresses for KDC.
 */

#define NEED_SOCKETS
#include "fake-addrinfo.h"
#include "k5-int.h"
#include "os-proto.h"
#include <stdio.h>
#ifdef KRB5_DNS_LOOKUP
#ifdef WSHELPER
#include <wshelper.h>
#else /* WSHELPER */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#endif /* WSHELPER */
#ifndef T_SRV
#define T_SRV 33
#endif /* T_SRV */

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define MAX_DNS_NAMELEN (15*(MAXHOSTNAMELEN + 1)+1)

/* Solaris Kerberos: default to dns lookup for the KDC but not the realm */
#define DEFAULT_LOOKUP_KDC 1
#define DEFAULT_LOOKUP_REALM 0

#ifdef DEBUG
/* Solaris Kerberos: want dbg messages to syslog */

#define fprintf krbint_dbg_syslog
#include <stdarg.h>
#include <com_err.h>
static int
krbint_dbg_syslog(FILE *file, const char *fmt, ...)
{
    va_list args;
    char err_str[2048];

    va_start(args, fmt);
    vsnprintf(err_str, sizeof (err_str), fmt, args);
    syslog(LOG_DEBUG, err_str);
    va_end(args);

    return (0);
}
#endif

static int
maybe_use_dns (krb5_context context, const char *name, int defalt)
{
    krb5_error_code code;
    char * value = NULL;
    int use_dns = 0;

    code = profile_get_string(context->profile, "libdefaults",
                              name, 0, 0, &value);
    if (value == 0 && code == 0)
	code = profile_get_string(context->profile, "libdefaults",
				  "dns_fallback", 0, 0, &value);
    if (code)
        return defalt;

    if (value == 0)
	return defalt;

    use_dns = _krb5_conf_boolean(value);
    profile_release_string(value);
    return use_dns;
}

int
_krb5_use_dns_kdc(krb5_context context)
{
    return maybe_use_dns (context, "dns_lookup_kdc", DEFAULT_LOOKUP_KDC);
}

int
_krb5_use_dns_realm(krb5_context context)
{
    return maybe_use_dns (context, "dns_lookup_realm", DEFAULT_LOOKUP_REALM);
}

#endif /* KRB5_DNS_LOOKUP */

/*ARGSUSED*/
static int get_port (const char *service, int stream, int defalt)
{
#if 0 /* Only used for "kerberos" and "kerberos-sec", and we want the
	 right port numbers even on the OSes that botch the entries in
	 /etc/services.  So don't bother with the lookup, except maybe
	 to produce a warning.  */
    struct addrinfo hints = { 0 };
    struct addrinfo *ai;
    int err;

    hints.ai_family = PF_INET;
    hints.ai_socktype = stream ? SOCK_STREAM : SOCK_DGRAM;
    err = getaddrinfo (NULL, service, &hints, &ai);
    if (err == 0 && ai != 0) {
	if (ai->ai_addr->sa_family == AF_INET) {
	    int port = ((struct sockaddr_in *)ai->ai_addr)->sin_port;
	    freeaddrinfo (ai);
	    return port;
	}
	freeaddrinfo (ai);
    }
#endif
    /* Any error - don't complain, just use default.  */
    return htons (defalt);
}

int
krb5int_grow_addrlist (struct addrlist *lp, int nmore)
{
    int i;
    int newspace = lp->space + nmore;
    size_t newsize = newspace * sizeof (struct addrlist);
    struct addrinfo **newaddrs;

    /* NULL check a concession to SunOS4 compatibility for now; not
       required for pure ANSI support.  */
    if (lp->addrs)
	newaddrs = realloc (lp->addrs, newsize);
    else
	newaddrs = malloc (newsize);

    if (newaddrs == NULL)
	return errno;
    for (i = lp->space; i < newspace; i++)
	newaddrs[i] = NULL;
    lp->addrs = newaddrs;
    lp->space = newspace;
    return 0;
}
#define grow_list krb5int_grow_addrlist

/* Free up everything pointed to by the addrlist structure, but don't
   free the structure itself.  */
void
krb5int_free_addrlist (struct addrlist *lp)
{
    int i;
    for (i = 0; i < lp->naddrs; i++)
	freeaddrinfo (lp->addrs[i]);
    free (lp->addrs);
    lp->addrs = NULL;
    lp->naddrs = lp->space = 0;
}
#define free_list krb5int_free_addrlist

static int translate_ai_error (int err)
{
    switch (err) {
    case 0:
	return 0;
    case EAI_BADFLAGS:
    case EAI_FAMILY:
    case EAI_SOCKTYPE:
    case EAI_SERVICE:
	/* All of these indicate bad inputs to getaddrinfo.  */
	return EINVAL;
    case EAI_AGAIN:
	/* Translate to standard errno code.  */
	return EAGAIN;
    case EAI_MEMORY:
	/* Translate to standard errno code.  */
	return ENOMEM;
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
#endif
#if EAI_NODATA != EAI_NONAME
    case EAI_NODATA:
#endif
    case EAI_NONAME:
	/* Name not known or no address data, but no error.  Do
	   nothing more.  */
	return 0;
#ifdef EAI_SYSTEM
    case EAI_SYSTEM:
	/* System error, obviously.  */
	return errno;
#endif
    default:
	/* An error code we haven't handled?  */
	return EINVAL;
    }
}

static int add_addrinfo_to_list (struct addrlist *lp, struct addrinfo *a)
{
    int err;

#ifdef DEBUG
    switch (a->ai_socktype) {
    case SOCK_DGRAM:
	fprintf(stderr, "\tdgram\n");
	break;
    case SOCK_STREAM:
	fprintf(stderr, "\tstream\n");
	break;
    case SOCK_RAW:
	fprintf(stderr, "\traw\n");
	break;
    case 0:
	break;
    default:
	fprintf(stderr, "\tsocket type %d\n", a->ai_socktype);
	break;
    }
#endif

    if (lp->naddrs == lp->space) {
	err = grow_list (lp, 1);
	if (err) {
#ifdef DEBUG
	    fprintf (stderr, "grow_list failed %d\n", err);
#endif
	    return err;
	}
    }
    lp->addrs[lp->naddrs++] = a;
    a->ai_next = 0;
#ifdef DEBUG
    fprintf (stderr, "count is now %d\n", lp->naddrs);
#endif
    return 0;
}

#define add_host_to_list krb5int_add_host_to_list

int
krb5int_add_host_to_list (struct addrlist *lp, const char *hostname,
			  int port, int secport,
			  int socktype, int family)
{
    struct addrinfo *addrs, *a, *anext, hint;
    int err;
    char portbuf[10], secportbuf[10];

#ifdef DEBUG
    fprintf (stderr, "adding hostname %s, ports %d,%d\n", hostname,
	     ntohs (port), ntohs (secport));
#endif

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = family;
    hint.ai_socktype = socktype;
    sprintf(portbuf, "%d", ntohs(port));
    sprintf(secportbuf, "%d", ntohs(secport));
    err = getaddrinfo (hostname, portbuf, &hint, &addrs);
    if (err)
	return translate_ai_error (err);
    anext = 0;
    for (a = addrs; a != 0 && err == 0; a = anext) {
	anext = a->ai_next;
	err = add_addrinfo_to_list (lp, a);
    }
    if (err || secport == 0)
	goto egress;
    if (socktype == 0)
	socktype = SOCK_DGRAM;
    else if (socktype != SOCK_DGRAM)
	goto egress;
    hint.ai_family = AF_INET;
    err = getaddrinfo (hostname, secportbuf, &hint, &addrs);
    if (err) {
	err = translate_ai_error (err);
	goto egress;
    }
    for (a = addrs; a != 0 && err == 0; a = anext) {
	anext = a->ai_next;
	err = add_addrinfo_to_list (lp, a);
    }
egress:
    if (anext)
	freeaddrinfo (anext);
    return err;
}

/*
 * returns count of number of addresses found
 * if master is non-NULL, it is filled in with the index of
 * the master kdc
 */

static krb5_error_code
krb5_locate_srv_conf_1(krb5_context context, const krb5_data *realm,
		       const char * name, struct addrlist *addrlist,
		       int get_masters, int socktype,
		       int udpport, int sec_udpport, int family)
{
    const char	*realm_srv_names[4];
    char **masterlist, **hostlist, *host, *port, *cp;
    krb5_error_code code;
    int i, j, count, ismaster;

#ifdef DEBUG
    fprintf (stderr,
	     "looking in krb5.conf for realm %s entry %s; ports %d,%d\n",
	     realm->data, name, ntohs (udpport), ntohs (sec_udpport));
#endif

    if ((host = malloc(realm->length + 1)) == NULL) 
	return ENOMEM;

    strncpy(host, realm->data, realm->length);
    host[realm->length] = '\0';
    hostlist = 0;

    masterlist = NULL;

    realm_srv_names[0] = "realms";
    realm_srv_names[1] = host;
    realm_srv_names[2] = name;
    realm_srv_names[3] = 0;

    code = profile_get_values(context->profile, realm_srv_names, &hostlist);

    if (code) {
#ifdef DEBUG
	fprintf (stderr, "config file lookup failed: %s\n",
		 error_message(code));
#endif
        if (code == PROF_NO_SECTION || code == PROF_NO_RELATION)
	    code = KRB5_REALM_UNKNOWN;
 	krb5_xfree(host);
  	return code;
     }

    count = 0;
    while (hostlist && hostlist[count])
	    count++;
#ifdef DEBUG
    fprintf (stderr, "found %d entries under 'kdc'\n", count);
#endif
    
    if (count == 0) {
        profile_free_list(hostlist);
	krb5_xfree(host);
	addrlist->naddrs = 0;
	return 0;
    }
    
    if (get_masters) {
	realm_srv_names[0] = "realms";
	realm_srv_names[1] = host;
	realm_srv_names[2] = "admin_server";
	realm_srv_names[3] = 0;

	code = profile_get_values(context->profile, realm_srv_names,
				  &masterlist);

	krb5_xfree(host);

	if (code == 0) {
	    for (i=0; masterlist[i]; i++) {
		host = masterlist[i];

		/*
		 * Strip off excess whitespace
		 */
		cp = strchr(host, ' ');
		if (cp)
		    *cp = 0;
		cp = strchr(host, '\t');
		if (cp)
		    *cp = 0;
		cp = strchr(host, ':');
		if (cp)
		    *cp = 0;
	    }
	}
    } else {
	krb5_xfree(host);
    }

    /* at this point, if master is non-NULL, then either the master kdc
       is required, and there is one, or the master kdc is not required,
       and there may or may not be one. */

#ifdef HAVE_NETINET_IN_H
    if (sec_udpport)
	    count = count * 2;
#endif

    for (i=0; hostlist[i]; i++) {
	int p1, p2;

	host = hostlist[i];
#ifdef DEBUG
	fprintf (stderr, "entry %d is '%s'\n", i, host);
#endif
	/*
	 * Strip off excess whitespace
	 */
	cp = strchr(host, ' ');
	if (cp)
	    *cp = 0;
	cp = strchr(host, '\t');
	if (cp)
	    *cp = 0;
	port = strchr(host, ':');
	if (port) {
	    *port = 0;
	    port++;
	}

	ismaster = 0;
	if (masterlist) {
	    for (j=0; masterlist[j]; j++) {
		if (strcasecmp(hostlist[i], masterlist[j]) == 0) {
		    ismaster = 1;
		}
	    }
	}

	if (get_masters && !ismaster)
	    continue;

	if (port) {
	    unsigned long l;
#ifdef HAVE_STROUL
	    char *endptr;
	    l = strtoul (port, &endptr, 10);
	    if (endptr == NULL || *endptr != 0)
		return EINVAL;
#else
	    l = atoi (port);
#endif
	    /* L is unsigned, don't need to check <0.  */
	    if (l > 65535)
		return EINVAL;
	    p1 = htons (l);
	    p2 = 0;
	} else {
	    p1 = udpport;
	    p2 = sec_udpport;
	}

	if (socktype != 0)
	    code = add_host_to_list (addrlist, hostlist[i], p1, p2,
				     socktype, family);
	else {
	    code = add_host_to_list (addrlist, hostlist[i], p1, p2,
				     SOCK_DGRAM, family);
	    if (code == 0)
		code = add_host_to_list (addrlist, hostlist[i], p1, p2,
					 SOCK_STREAM, family);
	}
	if (code) {
#ifdef DEBUG
	    fprintf (stderr, "error %d returned from add_host_to_list\n", code);
#endif
	    if (hostlist)
		profile_free_list (hostlist);
	    if (masterlist)
		profile_free_list (masterlist);
	    return code;
	}
    }

    if (hostlist)
        profile_free_list(hostlist);
    if (masterlist)
        profile_free_list(masterlist);

    return 0;
}

#ifdef KRB5_DNS_LOOKUP

#define make_srv_query_realm krb5int_make_srv_query_realm

static krb5_error_code
krb5_locate_srv_dns_1 (const krb5_data *realm,
		       const char *service,
		       const char *protocol,
		       struct addrlist *addrlist,
		       int family)
{
    struct srv_dns_entry *head = NULL;
    struct srv_dns_entry *entry = NULL, *next;
    krb5_error_code code = 0;

    code = make_srv_query_realm(realm, service, protocol, &head);
    if (code)
	return 0;

    /*
     * Okay!  Now we've got a linked list of entries sorted by
     * priority.  Start looking up A records and returning
     * addresses.
     */

    if (head == NULL)
	return 0;

    /* Check for the "." case indicating no support.  */
    if (head->next == 0 && head->host[0] == 0) {
	free(head->host);
	free(head);
	return KRB5_ERR_NO_SERVICE;
    }

#ifdef DEBUG
    fprintf (stderr, "walking answer list:\n");
#endif
    for (entry = head; entry != NULL; entry = next) {
#ifdef DEBUG
	fprintf (stderr, "\tport=%d host=%s\n", entry->port, entry->host);
#endif
	next = entry->next;
	code = add_host_to_list (addrlist, entry->host, htons (entry->port), 0,
				 (strcmp("_tcp", protocol)
				  ? SOCK_DGRAM
				  : SOCK_STREAM), family);
	if (code)
	    break;
	if (entry == head) {
	    free(entry->host);
	    free(entry);
	    head = next;
	    entry = 0;
	}
    }
#ifdef DEBUG
    fprintf (stderr, "[end]\n");
#endif

    krb5int_free_srv_dns_data(head);
    return code;
}
#endif /* KRB5_DNS_LOOKUP */

/*
 * Wrapper function for the two backends
 */

krb5_error_code
krb5int_locate_server (krb5_context context, const krb5_data *realm,
		       struct addrlist *addrlist,
		       int get_masters,
		       const char *profname, const char *dnsname,
		       int socktype,
		       /* network order port numbers! */
		       int dflport1, int dflport2,
		       int family)
{
    krb5_error_code code;
    struct addrlist al = ADDRLIST_INIT;

    *addrlist = al;

    /* Solaris Kerberos: skip local file search if profname == NULL */
    if (profname != NULL) {
	/*
	 * We always try the local file first
	 */
	code = krb5_locate_srv_conf_1(context, realm, profname, &al,
	    get_masters, socktype, dflport1, dflport2, family);
    }

#ifdef KRB5_DNS_LOOKUP
    if (code && dnsname != 0) {
	int use_dns = _krb5_use_dns_kdc(context);
	if (use_dns) {
	    code = 0;
	    if (socktype == SOCK_DGRAM || socktype == 0) {
		code = krb5_locate_srv_dns_1(realm, dnsname, "_udp",
					     &al, family);
#ifdef DEBUG
		if (code)
		    fprintf(stderr, "dns udp lookup returned error %d\n",
			    code);
#endif
	    }
	    if ((socktype == SOCK_STREAM || socktype == 0) && code == 0) {
		code = krb5_locate_srv_dns_1(realm, dnsname, "_tcp",
					     &al, family);
#ifdef DEBUG
		if (code)
		    fprintf(stderr, "dns tcp lookup returned error %d\n",
			    code);
#endif
	    }
	}
    }
#endif /* KRB5_DNS_LOOKUP */
#ifdef DEBUG
    if (code == 0)
	fprintf (stderr, "krb5int_locate_server found %d addresses\n",
		 al.naddrs);
    else
	fprintf (stderr, "krb5int_locate_server returning error code %d\n",
		 code);
#endif
    if (code != 0) {
	if (al.space)
	    free_list (&al);
	return code;
    }
    if (al.naddrs == 0) {	/* No good servers */
	if (al.space)
	    free_list (&al);
	return KRB5_REALM_CANT_RESOLVE;
    }
    *addrlist = al;
    return 0;
}

krb5_error_code
krb5_locate_kdc(krb5_context context, const krb5_data *realm,
		struct addrlist *addrlist,
		int get_masters, int socktype, int family)
{
    int udpport, sec_udpport;

    udpport = get_port (KDC_PORTNAME, 0, KRB5_DEFAULT_PORT);
    if (socktype == SOCK_STREAM)
	sec_udpport = 0;
    else {
	sec_udpport = get_port (KDC_SECONDARY_PORTNAME, 0,
				(udpport == htons (KRB5_DEFAULT_PORT)
				 ? KRB5_DEFAULT_SEC_PORT
				 : KRB5_DEFAULT_PORT));
	if (sec_udpport == udpport)
	    sec_udpport = 0;
    }

    return krb5int_locate_server(context, realm, addrlist, get_masters, "kdc",
				 (get_masters
				  ? "_kerberos-master"
				  : "_kerberos"),
				 socktype, udpport, sec_udpport, family);
}

/* 
 * Solaris Kerberos: for backward compat.  Avoid using this
 * function!
 */
krb5_error_code
krb5_get_servername(krb5_context context,
    const krb5_data *realm,
    const char *name, const char *proto,
    char *srvhost,
    unsigned short *port)
{
    krb5_error_code code = KRB5_REALM_UNKNOWN;

#ifdef KRB5_DNS_LOOKUP
    {
	int use_dns = _krb5_use_dns_kdc(context);

	if (use_dns) {
	    struct srv_dns_entry *head = NULL;

	    code = make_srv_query_realm(realm, name, proto, &head);
	    if (code)
		return (code);

	    if (head == NULL)
		return KRB5_REALM_CANT_RESOLVE;

	    *port = head->port;
	    (void) strlcpy(srvhost, head->host, MAX_DNS_NAMELEN);

#ifdef DEBUG
	    fprintf (stderr, "krb5_get_servername svrhost %s, port %d\n",
		srvhost, *port);
#endif
	    krb5int_free_srv_dns_data(head);
	}
    }
#endif /* KRB5_DNS_LOOKUP */

    return (code);
}
