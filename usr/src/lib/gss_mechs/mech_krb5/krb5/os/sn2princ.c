/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/os/sn2princ.c
 *
 * Copyright 1991,2002 by the Massachusetts Institute of Technology.
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
 * Convert a hostname and service name to a principal in the "standard"
 * form.
 */

#include "k5-int.h"
#include "os-proto.h"
#include "fake-addrinfo.h"
#include <ctype.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <locale.h>
#include <syslog.h>

#if !defined(DEFAULT_RDNS_LOOKUP)
/* Solaris Kerberos */
#define DEFAULT_RDNS_LOOKUP 0
#endif

/*
 * Solaris Kerberos:
 * The following prototypes are needed because these are
 * private interfaces that do not have prototypes in any .h
 */
extern struct hostent	*res_getipnodebyname(const char *, int, int, int *);
extern struct hostent	*res_getipnodebyaddr(const void *, size_t, int, int *);
extern void		res_freehostent(struct hostent *);

static int
maybe_use_reverse_dns (krb5_context context, int defalt)
{
    krb5_error_code code;
    char * value = NULL;
    int use_rdns = 0;

    code = profile_get_string(context->profile, "libdefaults",
                              "rdns", 0, 0, &value);
    if (code)
        return defalt;

    if (value == 0)
	return defalt;

    use_rdns = _krb5_conf_boolean(value);
    profile_release_string(value);
    return use_rdns;
}


/*
 * Solaris Kerberos:
 * Note, krb5_sname_to_principal() allocates memory for ret_princ.  Be sure to
 * use krb5_free_principal() on ret_princ to free it when done referencing it.
 */
krb5_error_code KRB5_CALLCONV
krb5_sname_to_principal(krb5_context context, const char *hostname, const char *sname, krb5_int32 type, krb5_principal *ret_princ)
{
    char **hrealms, *realm, *remote_host;
    krb5_error_code retval;
    register char *cp;
    char localname[MAXHOSTNAMELEN];
    /* Solaris Kerberos */
    KRB5_LOG0(KRB5_INFO, "krb5_sname_to_principal() start");
#ifdef DEBUG_REFERRALS
    printf("krb5_sname_to_principal(host=%s, sname=%s, type=%d)\n",hostname,sname,type);
    printf("      name types: 0=unknown, 3=srv_host\n");
#endif
    if ((type == KRB5_NT_UNKNOWN) ||
	(type == KRB5_NT_SRV_HST)) {

	/* if hostname is NULL, use local hostname */
	if (! hostname) {
	    if (gethostname(localname, MAXHOSTNAMELEN)) {
		/* Solaris Kerberos */
		KRB5_LOG0(KRB5_ERR, "krb5_sname_to_principal()"
		       " gethostname failed");
		return SOCKET_ERRNO;
	    }
	    hostname = localname;
	}

	/* if sname is NULL, use "host" */
	if (! sname)
	    sname = "host";

	/* copy the hostname into non-volatile storage */

	if (type == KRB5_NT_SRV_HST) {
	    /* Solaris Kerberos */
	    struct hostent *hp = NULL;
	    struct hostent *hp2 = NULL;
	    int err;
	    int addr_family;

	    /* Note that the old code would accept numeric addresses,
	       and if the gethostbyaddr step could convert them to
	       real hostnames, you could actually get reasonable
	       results.  If the mapping failed, you'd get dotted
	       triples as realm names.  *sigh*

	       The latter has been fixed in hst_realm.c, but we should
	       keep supporting numeric addresses if they do have
	       hostnames associated.  */

    /*
     * Solaris kerberos: using res_getipnodebyname() to force dns name
     * resolution.  Note, res_getaddrinfo() isn't exported by libreolv
     * so we use res_getipnodebyname() (MIT uses getaddrinfo()).
     */
	    KRB5_LOG(KRB5_INFO, "krb5_sname_to_principal() hostname %s",
	       hostname);

	    addr_family = AF_INET;
	try_getipnodebyname_again:
	    hp = res_getipnodebyname(hostname, addr_family, 0, &err);
	    if (!hp) {
#ifdef DEBUG_REFERRALS
	        printf("sname_to_princ: probably punting due to bad hostname of %s\n",hostname);
#endif
		if (addr_family == AF_INET) {
	    		KRB5_LOG(KRB5_INFO, "krb5_sname_to_principal()"
			   " can't get AF_INET addr, err = %d", err);
		    /* Just in case it's an IPv6-only name.  */
		    addr_family = AF_INET6;
		    goto try_getipnodebyname_again;
		}
		KRB5_LOG(KRB5_ERR, "krb5_sname_to_principal()"
		       " can't get AF_INET or AF_INET6 addr,"
		       " err = %d", err);

		krb5_set_error_message(context, KRB5_ERR_BAD_HOSTNAME,
				    dgettext(TEXT_DOMAIN,
					    "Hostname cannot be canonicalized for '%s': %s"),
				    hostname, strerror(err));
		return KRB5_ERR_BAD_HOSTNAME;
	    }
	    remote_host = strdup(hp ? hp->h_name : hostname);
	    if (!remote_host) {
		if (hp != NULL)
		    res_freehostent(hp);
		return ENOMEM;
	    }

            if (maybe_use_reverse_dns(context, DEFAULT_RDNS_LOOKUP)) {
                /*
                 * Do a reverse resolution to get the full name, just in
                 * case there's some funny business going on.  If there
                 * isn't an in-addr record, give up.
                 */
                /* XXX: This is *so* bogus.  There are several cases where
                   this won't get us the canonical name of the host, but
                   this is what we've trained people to expect.  We'll
                   probably fix it at some point, but let's try to
                   preserve the current behavior and only shake things up
                   once when it comes time to fix this lossage.  */
                hp2 = res_getipnodebyaddr(hp->h_addr, hp->h_length,
                			hp->h_addrtype, &err);

                if (hp2 != NULL) {
                    free(remote_host);
                    remote_host = strdup(hp2->h_name);
                    if (!remote_host) {
                        res_freehostent(hp2);
                        if (hp != NULL)
                            res_freehostent(hp);
                        return ENOMEM;
                    }
                    KRB5_LOG(KRB5_INFO, "krb5_sname_to_principal() remote_host %s",
                        remote_host);
                }
            }

            if (hp != NULL) {
                res_freehostent(hp);
            }

            if (hp2 != NULL) {
	        res_freehostent(hp2);
            }

	} else /* type == KRB5_NT_UNKNOWN */ {
	    remote_host = strdup(hostname);
	}
	if (!remote_host)
	    return ENOMEM;
#ifdef DEBUG_REFERRALS
 	printf("sname_to_princ: hostname <%s> after rdns processing\n",remote_host);
#endif

	if (type == KRB5_NT_SRV_HST)
	    for (cp = remote_host; *cp; cp++)
		if (isupper((unsigned char) (*cp)))
		    *cp = tolower((unsigned char) (*cp));

	/*
	 * Windows NT5's broken resolver gratuitously tacks on a
	 * trailing period to the hostname (at least it does in
	 * Beta2).  Find and remove it.
	 */
	if (remote_host[0]) {
		cp = remote_host + strlen(remote_host)-1;
		if (*cp == '.')
			*cp = 0;
	}


	if ((retval = krb5_get_host_realm(context, remote_host, &hrealms))) {
	    free(remote_host);
	    return retval;
	}

#ifdef DEBUG_REFERRALS
	printf("sname_to_princ:  realm <%s> after krb5_get_host_realm\n",hrealms[0]);
#endif

	if (!hrealms[0]) {
	    /* Solaris Kerberos */
	    krb5_set_error_message(context, KRB5_ERR_HOST_REALM_UNKNOWN,
				dgettext(TEXT_DOMAIN,
					"Cannot determine realm for host: host is '%s'"),
				remote_host ? remote_host : "unknown");

	    free(remote_host);
	    krb5_xfree(hrealms);
	    return KRB5_ERR_HOST_REALM_UNKNOWN;
	}
	realm = hrealms[0];

	retval = krb5_build_principal(context, ret_princ, strlen(realm),
				      realm, sname, remote_host,
				      (char *)0);

	if (retval == 0)
		krb5_princ_type(context, *ret_princ) = type;

#ifdef DEBUG_REFERRALS
	printf("krb5_sname_to_principal returning\n");
	printf("realm: <%s>, sname: <%s>, remote_host: <%s>\n",
	       realm,sname,remote_host);
	krb5int_dbgref_dump_principal("krb5_sname_to_principal",*ret_princ);
#endif

	free(remote_host);

	krb5_free_host_realm(context, hrealms);
	return retval;
    } else {
	return KRB5_SNAME_UNSUPP_NAMETYPE;
    }
}

