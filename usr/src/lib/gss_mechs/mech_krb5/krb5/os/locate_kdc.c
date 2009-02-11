/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/os/locate_kdc.c
 *
 * Copyright 1990,2000,2001,2002,2003,2004,2006 Massachusetts Institute of Technology.
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

int
krb5int_grow_addrlist (struct addrlist *lp, int nmore)
{
    int i;
    int newspace = lp->space + nmore;
    size_t newsize = newspace * sizeof (*lp->addrs);
    void *newaddrs;

    newaddrs = realloc (lp->addrs, newsize);
    if (newaddrs == NULL)
	return errno;
    lp->addrs = newaddrs;
    for (i = lp->space; i < newspace; i++) {
	lp->addrs[i].ai = NULL;
	lp->addrs[i].freefn = NULL;
	lp->addrs[i].data = NULL;
    }
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
	if (lp->addrs[i].freefn)
	    (lp->addrs[i].freefn)(lp->addrs[i].data);
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
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
    case EAI_NODATA:
#endif
    case EAI_NONAME:
	/* Name not known or no address data, but no error.  Do
	   nothing more.  */
	return 0;
#ifdef EAI_OVERFLOW
    case EAI_OVERFLOW:
	/* An argument buffer overflowed.  */
	return EINVAL;		/* XXX */
#endif
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

/* Solaris Kerberos: want dbg messages to syslog */
#include <stdarg.h>
static inline void Tprintf(const char *fmt, ...)
{
#ifdef TEST
    va_list ap;
    char err_str[2048];

    va_start(ap, fmt);
    vsnprintf(err_str, sizeof (err_str), fmt, args);
    syslog(LOG_DEBUG, err_str);
    va_end(ap);
#endif
}

#if 0
extern void krb5int_debug_fprint(const char *, ...);
#define dprint krb5int_debug_fprint
#define print_addrlist krb5int_print_addrlist
extern void print_addrlist (const struct addrlist *a);
#else
static inline void dprint(const char *fmt, ...) { }
static inline void print_addrlist(const struct addrlist *a) { }
#endif

static int add_addrinfo_to_list (struct addrlist *lp, struct addrinfo *a,
				 void (*freefn)(void *), void *data)
{
    int err;

    dprint("\tadding %p=%A to %p (naddrs=%d space=%d)\n", a, a, lp,
	   lp->naddrs, lp->space);

    if (lp->naddrs == lp->space) {
	err = grow_list (lp, 1);
	if (err) {
	    Tprintf ("grow_list failed %d\n", err);
	    return err;
	}
    }
    Tprintf("setting element %d\n", lp->naddrs);
    lp->addrs[lp->naddrs].ai = a;
    lp->addrs[lp->naddrs].freefn = freefn;
    lp->addrs[lp->naddrs].data = data;
    lp->naddrs++;
    Tprintf ("\tcount is now %d: ", lp->naddrs);
    print_addrlist(lp);
    Tprintf("\n");
    return 0;
}

#define add_host_to_list krb5int_add_host_to_list

static void call_freeaddrinfo(void *data)
{
    /* Strict interpretation of the C standard says we can't assume
       that the ABI for f(void*) and f(struct foo *) will be
       compatible.  Use this stub just to be paranoid.  */
    freeaddrinfo(data);
}

int
krb5int_add_host_to_list (struct addrlist *lp, const char *hostname,
			  int port, int secport,
			  int socktype, int family)
{
    struct addrinfo *addrs, *a, *anext, hint;
    int err;
    char portbuf[10], secportbuf[10];
    void (*freefn)(void *);

    Tprintf ("adding hostname %s, ports %d,%d, family %d, socktype %d\n",
	     hostname, ntohs (port), ntohs (secport),
	     family, socktype);

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = family;
    hint.ai_socktype = socktype;
#ifdef AI_NUMERICSERV
    hint.ai_flags = AI_NUMERICSERV;
#endif
    sprintf(portbuf, "%d", ntohs(port));
    sprintf(secportbuf, "%d", ntohs(secport));
    err = getaddrinfo (hostname, portbuf, &hint, &addrs);
    if (err) {
	Tprintf ("\tgetaddrinfo(\"%s\", \"%s\", ...)\n\treturns %d: %s\n",
		 hostname, portbuf, err, gai_strerror (err));
	return translate_ai_error (err);
    }
    freefn = call_freeaddrinfo;
    anext = 0;
    for (a = addrs; a != 0 && err == 0; a = anext, freefn = 0) {
	anext = a->ai_next;
	err = add_addrinfo_to_list (lp, a, freefn, a);
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
    freefn = call_freeaddrinfo;
    for (a = addrs; a != 0 && err == 0; a = anext, freefn = 0) {
	anext = a->ai_next;
	err = add_addrinfo_to_list (lp, a, freefn, a);
    }
egress:
    /* Solaris Kerberos */
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

    Tprintf ("looking in krb5.conf for realm %s entry %s; ports %d,%d\n",
	     realm->data, name, ntohs (udpport), ntohs (sec_udpport));

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
	Tprintf ("config file lookup failed: %s\n",
		 error_message(code));
        if (code == PROF_NO_SECTION || code == PROF_NO_RELATION)
	    code = KRB5_REALM_UNKNOWN;
 	krb5_xfree(host);
  	return code;
     }

    count = 0;
    while (hostlist && hostlist[count])
	    count++;
    Tprintf ("found %d entries under 'kdc'\n", count);
    
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
	Tprintf ("entry %d is '%s'\n", i, host);
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
	    Tprintf ("error %d (%s) returned from add_host_to_list\n", code,
		     error_message (code));
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

#ifdef TEST
static krb5_error_code
krb5_locate_srv_conf(krb5_context context, const krb5_data *realm,
		     const char *name, struct addrlist *al, int get_masters,
		     int udpport, int sec_udpport)
{
    krb5_error_code ret;

    ret = krb5_locate_srv_conf_1 (context, realm, name, al,
				  get_masters, 0, udpport, sec_udpport, 0);
    if (ret)
	return ret;
    if (al->naddrs == 0)	/* Couldn't resolve any KDC names */
	return KRB5_REALM_CANT_RESOLVE;
    return 0;
}
#endif

#ifdef KRB5_DNS_LOOKUP
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

    code = krb5int_make_srv_query_realm(realm, service, protocol, &head);
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

    Tprintf ("walking answer list:\n");
    for (entry = head; entry != NULL; entry = next) {
	Tprintf ("\tport=%d host=%s\n", entry->port, entry->host);
	next = entry->next;
	code = add_host_to_list (addrlist, entry->host, htons (entry->port), 0,
				 (strcmp("_tcp", protocol)
				  ? SOCK_DGRAM
				  : SOCK_STREAM), family);
	if (code) {
	    break;
	}
	if (entry == head) {
	    free(entry->host);
	    free(entry);
	    head = next;
	    entry = 0;
	}
    }
    Tprintf ("[end]\n");

    krb5int_free_srv_dns_data(head);
    return code;
}
#endif

#include <locate_plugin.h>

#if TARGET_OS_MAC
static const char *objdirs[] = { KRB5_PLUGIN_BUNDLE_DIR, LIBDIR "/krb5/plugins/libkrb5", NULL }; /* should be a list */
#else
static const char *objdirs[] = { LIBDIR "/krb5/plugins/libkrb5", NULL };
#endif

struct module_callback_data {
    int out_of_mem;
    struct addrlist *lp;
};

static int
module_callback (void *cbdata, int socktype, struct sockaddr *sa)
{
    struct module_callback_data *d = cbdata;
    struct {
	struct addrinfo ai;
	union {
	    struct sockaddr_in sin;
	    struct sockaddr_in6 sin6;
	} u;
    } *x;

    if (socktype != SOCK_STREAM && socktype != SOCK_DGRAM)
	return 0;
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
	return 0;
    x = malloc (sizeof (*x));
    if (x == 0) {
	d->out_of_mem = 1;
	return 1;
    }
    memset(x, 0, sizeof (*x));
    x->ai.ai_addr = (struct sockaddr *) &x->u;
    x->ai.ai_socktype = socktype;
    x->ai.ai_family = sa->sa_family;
    if (sa->sa_family == AF_INET) {
	x->u.sin = *(struct sockaddr_in *)sa;
	x->ai.ai_addrlen = sizeof(struct sockaddr_in);
    }
    if (sa->sa_family == AF_INET6) {
	x->u.sin6 = *(struct sockaddr_in6 *)sa;
	x->ai.ai_addrlen = sizeof(struct sockaddr_in6);
    }
    if (add_addrinfo_to_list (d->lp, &x->ai, free, x) != 0) {
	/* Assumes only error is ENOMEM.  */
	d->out_of_mem = 1;
	return 1;
    }
    return 0;
}

static krb5_error_code
module_locate_server (krb5_context ctx, const krb5_data *realm,
		      struct addrlist *addrlist,
		      enum locate_service_type svc, int socktype, int family)
{
    struct krb5plugin_service_locate_result *res = NULL;
    krb5_error_code code;
    struct krb5plugin_service_locate_ftable *vtbl = NULL;
    void **ptrs;
    int i;
    struct module_callback_data cbdata = { 0, };

    Tprintf("in module_locate_server\n");
    cbdata.lp = addrlist;
    if (!PLUGIN_DIR_OPEN (&ctx->libkrb5_plugins)) {
        
	code = krb5int_open_plugin_dirs (objdirs, NULL, &ctx->libkrb5_plugins,
					 &ctx->err);
	if (code)
	    return KRB5_PLUGIN_NO_HANDLE;
    }

    code = krb5int_get_plugin_dir_data (&ctx->libkrb5_plugins,
					"service_locator", &ptrs, &ctx->err);
    if (code) {
	Tprintf("error looking up plugin symbols: %s\n",
		krb5_get_error_message(ctx, code));
	return KRB5_PLUGIN_NO_HANDLE;
    }

    for (i = 0; ptrs[i]; i++) {
	void *blob;

	vtbl = ptrs[i];
	Tprintf("element %d is %p\n", i, ptrs[i]);

	/* For now, don't keep the plugin data alive.  For long-lived
	   contexts, it may be desirable to change that later.  */
	code = vtbl->init(ctx, &blob);
	if (code)
	    continue;

	code = vtbl->lookup(blob, svc, realm->data, socktype, family,
			    module_callback, &cbdata);
	vtbl->fini(blob);
	if (code == KRB5_PLUGIN_NO_HANDLE) {
	    /* Module passes, keep going.  */
	    /* XXX */
	    Tprintf("plugin doesn't handle this realm (KRB5_PLUGIN_NO_HANDLE)\n");
	    continue;
	}
	if (code != 0) {
	    /* Module encountered an actual error.  */
	    Tprintf("plugin lookup routine returned error %d: %s\n",
		    code, error_message(code));
	    krb5int_free_plugin_dir_data (ptrs);
	    return code;
	}
	break;
    }
    if (ptrs[i] == NULL) {
	Tprintf("ran off end of plugin list\n");
	krb5int_free_plugin_dir_data (ptrs);
	return KRB5_PLUGIN_NO_HANDLE;
    }
    Tprintf("stopped with plugin #%d, res=%p\n", i, res);

    /* Got something back, yippee.  */
    Tprintf("now have %d addrs in list %p\n", addrlist->naddrs, addrlist);
    print_addrlist(addrlist);
    krb5int_free_plugin_dir_data (ptrs);
    return 0;
}

static krb5_error_code
prof_locate_server (krb5_context context, const krb5_data *realm,
		    struct addrlist *addrlist,
		    enum locate_service_type svc, int socktype, int family)
{
    const char *profname;
    int dflport1, dflport2 = 0;
    struct servent *serv;

    switch (svc) {
    case locate_service_kdc:
	profname = "kdc";
	/* We used to use /etc/services for these, but enough systems
	   have old, crufty, wrong settings that this is probably
	   better.  */
    kdc_ports:
	dflport1 = htons(KRB5_DEFAULT_PORT);
	dflport2 = htons(KRB5_DEFAULT_SEC_PORT);
	break;
    case locate_service_master_kdc:
	profname = "master_kdc";
	goto kdc_ports;
    case locate_service_kadmin:
	profname = "admin_server";
	dflport1 = htons(DEFAULT_KADM5_PORT);
	break;
    case locate_service_krb524:
	profname = "krb524_server";
	serv = getservbyname(KRB524_SERVICE, "udp");
	dflport1 = serv ? serv->s_port : htons (KRB524_PORT);
	break;
    case locate_service_kpasswd:
	profname = "kpasswd_server";
	dflport1 = htons(DEFAULT_KPASSWD_PORT);
	break;
    default:
	return EBUSY;		/* XXX */
    }

    return krb5_locate_srv_conf_1 (context, realm, profname, addrlist,
				   0, socktype,
				   dflport1, dflport2, family);
}

static krb5_error_code
dns_locate_server (krb5_context context, const krb5_data *realm,
		   struct addrlist *addrlist,
		   enum locate_service_type svc, int socktype, int family)
{
    const char *dnsname;
    int use_dns = _krb5_use_dns_kdc(context);
    krb5_error_code code;

    if (!use_dns)
	return KRB5_PLUGIN_NO_HANDLE;

    switch (svc) {
    case locate_service_kdc:
	dnsname = "_kerberos";
	break;
    case locate_service_master_kdc:
	dnsname = "_kerberos-master";
	break;
    case locate_service_kadmin:
	dnsname = "_kerberos-adm";
	break;
    case locate_service_krb524:
	dnsname = "_krb524";
	break;
    case locate_service_kpasswd:
	dnsname = "_kpasswd";
	break;
    default:
	return KRB5_PLUGIN_NO_HANDLE;
    }

    code = 0;
    if (socktype == SOCK_DGRAM || socktype == 0) {
	code = krb5_locate_srv_dns_1(realm, dnsname, "_udp", addrlist, family);
	if (code)
	    Tprintf("dns udp lookup returned error %d\n", code);
    }
    if ((socktype == SOCK_STREAM || socktype == 0) && code == 0) {
	code = krb5_locate_srv_dns_1(realm, dnsname, "_tcp", addrlist, family);
	if (code)
	    Tprintf("dns tcp lookup returned error %d\n", code);
    }
    return code;
}

/*
 * Wrapper function for the various backends
 */

krb5_error_code
krb5int_locate_server (krb5_context context, const krb5_data *realm,
		       struct addrlist *addrlist,
		       enum locate_service_type svc,
		       int socktype, int family)
{
    krb5_error_code code;
    struct addrlist al = ADDRLIST_INIT;

    *addrlist = al;

    code = module_locate_server(context, realm, &al, svc, socktype, family);
    Tprintf("module_locate_server returns %d\n", code);
    if (code == KRB5_PLUGIN_NO_HANDLE) {
	/*
	 * We always try the local file before DNS.  Note that there
	 * is no way to indicate "service not available" via the
	 * config file.
	 */

	code = prof_locate_server(context, realm, &al, svc, socktype, family);

#ifdef KRB5_DNS_LOOKUP
	/*
	 * Solaris Kerberos:
	 * There is no point in trying to locate the KDC in DNS if "realm"
	 * is empty.
	 */
	/* Try DNS for all profile errors?  */
	if (code && !krb5_is_referral_realm(realm)) {
	    krb5_error_code code2;
	    code2 = dns_locate_server(context, realm, &al, svc, socktype,
				      family);
	    if (code2 != KRB5_PLUGIN_NO_HANDLE)
		code = code2;
	}
#endif /* KRB5_DNS_LOOKUP */

	/* We could put more heuristics here, like looking up a hostname
	   of "kerberos."+REALM, etc.  */
    }
    if (code == 0)
	Tprintf ("krb5int_locate_server found %d addresses\n",
		 al.naddrs);
    else
	Tprintf ("krb5int_locate_server returning error code %d/%s\n",
		 code, error_message(code));
    if (code != 0) {
	if (al.space)
	    free_list (&al);
	return code;
    }
    if (al.naddrs == 0) {	/* No good servers */
	if (al.space)
	    free_list (&al);
	krb5_set_error_message(context, KRB5_REALM_CANT_RESOLVE,
			       "Cannot resolve network address for KDC in realm %.*s",
			       realm->length, realm->data);
			       
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
    return krb5int_locate_server(context, realm, addrlist,
				 (get_masters
				  ? locate_service_master_kdc
				  : locate_service_kdc),
				 socktype, family);
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

	    code = krb5int_make_srv_query_realm(realm, name, proto, &head);
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
