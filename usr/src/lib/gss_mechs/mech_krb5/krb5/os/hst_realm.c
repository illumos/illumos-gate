/*
 * lib/krb5/os/hst_realm.c
 *
 * Copyright 1990,1991,2002 by the Massachusetts Institute of Technology.
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
 * krb5_get_host_realm()
 */

/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 Figures out the Kerberos realm names for host, filling in a
 pointer to an argv[] style list of names, terminated with a null pointer.

 If host is NULL, the local host's realms are determined.

 If there are no known realms for the host, the filled-in pointer is set
 to NULL.

 The pointer array and strings pointed to are all in allocated storage,
 and should be freed by the caller when finished.

 returns system errors
*/

/*
 * Implementation notes:
 *
 * this implementation only provides one realm per host, using the same
 * mapping file used in kerberos v4.

 * Given a fully-qualified domain-style primary host name,
 * return the name of the Kerberos realm for the host.
 * If the hostname contains no discernable domain, or an error occurs,
 * return the local realm name, as supplied by krb5_get_default_realm().
 * If the hostname contains a domain, but no translation is found,
 * the hostname's domain is converted to upper-case and returned.
 *
 * The format of each line of the translation file is:
 * domain_name kerberos_realm
 * -or-
 * host_name kerberos_realm
 *
 * domain_name should be of the form .XXX.YYY (e.g. .LCS.MIT.EDU)
 * host names should be in the usual form (e.g. FOO.BAR.BAZ)
 */


#include "k5-int.h"
#include "os-proto.h"
#include <ctype.h>
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "fake-addrinfo.h"

#ifdef KRB5_DNS_LOOKUP

#include "dnsglue.h"
/*
 * Try to look up a TXT record pointing to a Kerberos realm
 */

krb5_error_code
krb5_try_realm_txt_rr(const char *prefix, const char *name, char **realm)
{
    krb5_error_code retval = KRB5_ERR_HOST_REALM_UNKNOWN;
    const unsigned char *p, *base;
    char host[MAXDNAME], *h;
    int ret, rdlen, len;
    struct krb5int_dns_state *ds = NULL;

    /*
     * Form our query, and send it via DNS
     */

    if (name == NULL || name[0] == '\0') {
	if (strlen (prefix) >= sizeof(host)-1)
	    return KRB5_ERR_HOST_REALM_UNKNOWN;
        strcpy(host,prefix);
    } else {
        if ( strlen(prefix) + strlen(name) + 3 > MAXDNAME )
            return KRB5_ERR_HOST_REALM_UNKNOWN;
	/*LINTED*/
        sprintf(host,"%s.%s", prefix, name);

        /* Realm names don't (normally) end with ".", but if the query
           doesn't end with "." and doesn't get an answer as is, the
           resolv code will try appending the local domain.  Since the
           realm names are absolutes, let's stop that.

           But only if a name has been specified.  If we are performing
           a search on the prefix alone then the intention is to allow
           the local domain or domain search lists to be expanded.
        */

        h = host + strlen (host);
        if ((h > host) && (h[-1] != '.') && ((h - host + 1) < sizeof(host)))
            strcpy (h, ".");
    }
    ret = krb5int_dns_init(&ds, host, C_IN, T_TXT);
    if (ret < 0)
	goto errout;

    ret = krb5int_dns_nextans(ds, &base, &rdlen);
    if (ret < 0 || base == NULL)
	goto errout;

    p = base;
    if (!INCR_OK(base, rdlen, p, 1))
	goto errout;
    len = *p++;
    *realm = malloc((size_t)len + 1);
    if (*realm == NULL) {
	retval = ENOMEM;
	goto errout;
    }
    strncpy(*realm, (const char *)p, (size_t)len);
    (*realm)[len] = '\0';
    /* Avoid a common error. */
    if ( (*realm)[len-1] == '.' )
	(*realm)[len-1] = '\0';
    retval = 0;

errout:
    if (ds != NULL) {
	krb5int_dns_fini(ds);
	ds = NULL;
    }
    return retval;
}
#else /* KRB5_DNS_LOOKUP */
#ifndef MAXDNAME
#define MAXDNAME (16 * MAXHOSTNAMELEN)
#endif /* MAXDNAME */
#endif /* KRB5_DNS_LOOKUP */

krb5_error_code krb5int_translate_gai_error (int);

static krb5_error_code
krb5int_get_fq_hostname (char *buf, size_t bufsize, const char *name)
{
    struct addrinfo *ai, hints;
    int err;

    memset (&hints, 0, sizeof (hints));
    hints.ai_flags = AI_CANONNAME;
    err = getaddrinfo (name, 0, &hints, &ai);
    if (err)
	return krb5int_translate_gai_error (err);
    if (ai->ai_canonname == 0)
	return KRB5_EAI_FAIL;
    strncpy (buf, ai->ai_canonname, bufsize);
    buf[bufsize-1] = 0;
    freeaddrinfo (ai);
    return 0;
}

/* Get the local host name, try to make it fully-qualified.
   Always return a null-terminated string.
   Might return an error if gethostname fails.  */
krb5_error_code
krb5int_get_fq_local_hostname (char *buf, size_t bufsiz)
{
    buf[0] = 0;
    if (gethostname (buf, bufsiz) == -1)
	return SOCKET_ERRNO;
    buf[bufsiz - 1] = 0;
    return krb5int_get_fq_hostname (buf, bufsiz, buf);
}

krb5_error_code KRB5_CALLCONV
krb5_get_host_realm(krb5_context context, const char *host, char ***realmsp)
{
    char **retrealms;
    char *realm, *cp, *temp_realm;
    krb5_error_code retval;
    char local_host[MAXDNAME+1];

#ifdef DEBUG_REFERRALS
    printf("get_host_realm(host:%s) called\n",host);
#endif

    krb5int_clean_hostname(context, host, local_host, sizeof local_host);

    /*
       Search for the best match for the host or domain.
       Example: Given a host a.b.c.d, try to match on:
         1) A.B.C.D
	 2) .B.C.D
	 3) B.C.D
	 4) .C.D
	 5) C.D
	 6) .D
	 7) D
     */

    cp = local_host;
#ifdef DEBUG_REFERRALS
    printf("  local_host: %s\n",local_host);
#endif
    realm = (char *)NULL;
    temp_realm = 0;
    while (cp) {
#ifdef DEBUG_REFERRALS
        printf("  trying to look up %s in the domain_realm map\n",cp);
#endif
	retval = profile_get_string(context->profile, "domain_realm", cp,
				    0, (char *)NULL, &temp_realm);
	if (retval)
	    return retval;
	if (temp_realm != (char *)NULL)
	    break;	/* Match found */

	/* Setup for another test */
	if (*cp == '.') {
	    cp++;
	} else {
	    cp = strchr(cp, '.');
	}
    }
#ifdef DEBUG_REFERRALS
    printf("  done searching the domain_realm map\n");
#endif
    if (temp_realm) {
#ifdef DEBUG_REFERRALS
    printf("  temp_realm is %s\n",temp_realm);
#endif
        realm = malloc(strlen(temp_realm) + 1);
        if (!realm) {
            profile_release_string(temp_realm);
            return ENOMEM;
        }
        strcpy(realm, temp_realm);
        profile_release_string(temp_realm);
    }

    if (realm == (char *)NULL) {
        if (!(cp = (char *)malloc(strlen(KRB5_REFERRAL_REALM)+1)))
	    return ENOMEM;
	strcpy(cp, KRB5_REFERRAL_REALM);
	realm = cp;
    }

    if (!(retrealms = (char **)calloc(2, sizeof(*retrealms)))) {
	if (realm != (char *)NULL)
	    free(realm);
	return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;

    *realmsp = retrealms;
    return 0;
}

#if defined(_WIN32) && !defined(__CYGWIN32__)
# ifndef EAFNOSUPPORT
#  define EAFNOSUPPORT WSAEAFNOSUPPORT
# endif
#endif

krb5_error_code
krb5int_translate_gai_error (int num)
{
    switch (num) {
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
	return EAFNOSUPPORT;
#endif
    case EAI_AGAIN:
	return EAGAIN;
    case EAI_BADFLAGS:
	return EINVAL;
    case EAI_FAIL:
	return KRB5_EAI_FAIL;
    case EAI_FAMILY:
	return EAFNOSUPPORT;
    case EAI_MEMORY:
	return ENOMEM;
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
    case EAI_NODATA:
	return KRB5_EAI_NODATA;
#endif
    case EAI_NONAME:
	return KRB5_EAI_NONAME;
#if defined(EAI_OVERFLOW)
    case EAI_OVERFLOW:
	return EINVAL;		/* XXX */
#endif
    case EAI_SERVICE:
	return KRB5_EAI_SERVICE;
    case EAI_SOCKTYPE:
	return EINVAL;
#ifdef EAI_SYSTEM
    case EAI_SYSTEM:
	return errno;
#endif
    }
    /* Solaris Kerberos */
    /* abort (); */
    return -1;
}


/*
 * Ganked from krb5_get_host_realm; handles determining a fallback realm
 * to try in the case where referrals have failed and it's time to go
 * look at TXT records or make a DNS-based assumption.
 */

krb5_error_code KRB5_CALLCONV
krb5_get_fallback_host_realm(krb5_context context, krb5_data *hdata, char ***realmsp)
{
    char **retrealms;
    char *realm = (char *)NULL, *cp;
    krb5_error_code retval;
    char local_host[MAXDNAME+1], host[MAXDNAME+1];

    /* Convert what we hope is a hostname to a string. */
    memcpy(host, hdata->data, hdata->length);
    host[hdata->length]=0;

#ifdef DEBUG_REFERRALS
    printf("get_fallback_host_realm(host >%s<) called\n",host);
#endif

    krb5int_clean_hostname(context, host, local_host, sizeof local_host);

#ifdef DEBUG_REFERRALS
    printf("  local_host: %s\n",local_host);
#endif

#ifdef KRB5_DNS_LOOKUP
    if (_krb5_use_dns_realm(context)) {
        /*
         * Since this didn't appear in our config file, try looking
         * it up via DNS.  Look for a TXT records of the form:
         *
         * _kerberos.<hostname>
         *
         */
        cp = local_host;
        do {
            retval = krb5_try_realm_txt_rr("_kerberos", cp, &realm);
            cp = strchr(cp,'.');
            if (cp)
                cp++;
        } while (retval && cp && cp[0]);
    } else
#endif /* KRB5_DNS_LOOKUP */
    {
        /*
         * Solaris Kerberos:
         * Fallback to looking for a realm based on the DNS domain
         * of the host. Note: "local_host" here actually refers to the
         * host and NOT necessarily the local hostnane.
         */
        (void) krb5int_fqdn_get_realm(context, local_host,
                                    &realm);
#ifdef DEBUG_REFERRALS
        printf("  done finding DNS-based default realm: >%s<\n",realm);
#endif
    }


    if (realm == (char *)NULL) {
        /* We are defaulting to the local realm */
        retval = krb5_get_default_realm(context, &realm);
        if (retval) {
             return retval;
        }
    }
    if (!(retrealms = (char **)calloc(2, sizeof(*retrealms)))) {
	if (realm != (char *)NULL)
	    free(realm);
	return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;

    *realmsp = retrealms;
    return 0;
}

/*
 * Common code for krb5_get_host_realm and krb5_get_fallback_host_realm
 * to do basic sanity checks on supplied hostname.
 */
krb5_error_code KRB5_CALLCONV
krb5int_clean_hostname(krb5_context context, const char *host, char *local_host, size_t lhsize)
{
    char *cp;
    krb5_error_code retval;
    int l;

    local_host[0]=0;
#ifdef DEBUG_REFERRALS
    printf("krb5int_clean_hostname called: host<%s>, local_host<%s>, size %d\n",host,local_host,lhsize);
#endif
    if (host) {
	/* Filter out numeric addresses if the caller utterly failed to
	   convert them to names.  */
	/* IPv4 - dotted quads only */
	if (strspn(host, "01234567890.") == strlen(host)) {
	    /* All numbers and dots... if it's three dots, it's an
	       IP address, and we reject it.  But "12345" could be
	       a local hostname, couldn't it?  We'll just assume
	       that a name with three dots is not meant to be an
	       all-numeric hostname three all-numeric domains down
	       from the current domain.  */
	    int ndots = 0;
	    const char *p;
	    for (p = host; *p; p++)
		if (*p == '.')
		    ndots++;
	    if (ndots == 3)
		return KRB5_ERR_NUMERIC_REALM;
	}
	if (strchr(host, ':'))
	    /* IPv6 numeric address form?  Bye bye.  */
	    return KRB5_ERR_NUMERIC_REALM;

	/* Should probably error out if strlen(host) > MAXDNAME.  */
	strncpy(local_host, host, lhsize);
	local_host[lhsize - 1] = '\0';
    } else {
        retval = krb5int_get_fq_local_hostname (local_host, lhsize);
	if (retval)
	    return retval;
    }

    /* fold to lowercase */
    for (cp = local_host; *cp; cp++) {
	if (isupper((unsigned char) (*cp)))
	    *cp = tolower((unsigned char) *cp);
    }
    l = strlen(local_host);
    /* strip off trailing dot */
    if (l && local_host[l-1] == '.')
	    local_host[l-1] = 0;

#ifdef DEBUG_REFERRALS
    printf("krb5int_clean_hostname ending: host<%s>, local_host<%s>, size %d\n",host,local_host,lhsize);
#endif
    return 0;
}

/*
 * Solaris Kerberos:
 * Walk through the components of a domain. At each
 * stage determine if a KDC can be located for that domain.
 * Return a realm corresponding to the upper-cased domain name
 * for which a KDC was found or NULL if no KDC was found.
 */
krb5_error_code
krb5int_domain_get_realm(krb5_context context, const char *domain, char **realm) {
    krb5_error_code retval;
    struct addrlist addrlist = ADDRLIST_INIT;	/* Solaris Kerberos */
    krb5_data drealm;
    char *cp = NULL;
    char *fqdn = NULL;

    *realm = NULL;
    memset(&drealm, 0, sizeof (drealm));

    if (!(fqdn = malloc(strlen(domain) + 1))) {
        return (ENOMEM);
    }
    strlcpy(fqdn, domain, strlen(domain) + 1);

    /* Upper case the domain (for use as a realm) */
    for (cp = fqdn; *cp; cp++)
        if (islower((int)(*cp)))
            *cp = toupper((int)*cp);

    cp = fqdn;
    while (strchr(cp, '.') != NULL) {

        drealm.length = strlen(cp);
        drealm.data = cp;

        /* Find a kdc based on this part of the domain name */
        retval = krb5_locate_kdc(context, &drealm, &addrlist, 0, SOCK_DGRAM, 0);
        krb5int_free_addrlist(&addrlist);

        if (!retval) { /* Found a KDC! */
            if (!(*realm = malloc(strlen(cp) + 1))) {
                free(fqdn);
                return (ENOMEM);
            }
            strlcpy(*realm, cp, strlen(cp) + 1);
            break;
        }

        cp = strchr(cp, '.');
        cp++;
    }
    free(fqdn);
    return (0);
}

/*
 * Solaris Kerberos:
 * Discards the first component of the fqdn and calls
 * krb5int_domain_get_realm() with the remaining string (domain).
 *
 */
krb5_error_code
krb5int_fqdn_get_realm(krb5_context context, const char *fqdn, char **realm) {
    char *domain = strchr(fqdn, '.');

    if (domain) {
        domain++;
        return (krb5int_domain_get_realm(context, domain, realm));
    } else {
        return (-1);
    }
}

