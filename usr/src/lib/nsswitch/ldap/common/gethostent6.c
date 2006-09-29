/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/systeminfo.h>
#include "ns_internal.h"
#include "ldap_common.h"

/* host attributes filters */

/* probably some change in the ipHostNumber field */

#define	_H_DN			"dn"
#define	_H_NAME			"cn"
#define	_H_ADDR			"iphostnumber"
#define	_F_GETHOSTS6BYNAME	"(&(objectClass=ipHost)(cn=%s))"
#define	_F_GETHOSTS6BYNAME_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETHOSTS6DOTTEDBYNAME \
				"(&(objectClass=ipHost)(|(cn=%s)(cn=%s)))"
#define	_F_GETHOSTS6DOTTEDBYNAME_SSD \
				"(&(%%s)(|(cn=%s)(cn=%s)))"
#define	_F_GETHOSTS6BYADDR	"(&(objectClass=ipHost)(ipHostNumber=%s))"
#define	_F_GETHOSTS6BYADDR_SSD	"(&(%%s)(ipHostNumber=%s))"

static const char *ipnodes_attrs[] = {
	_H_NAME,
	_H_ADDR,
	(char *)NULL
};

extern int
_nss_ldap_hosts2str_int(int af, ldap_backend_ptr be, nss_XbyY_args_t *argp);

/*
 * _nss_ldap_hosts2str is the data marshaling method for the ipnodes getXbyY
 * system call gethostbyname() and gethostbyaddr.
 * This method is called after a successful search has been performed.
 * This method will parse the search results into the file format.
 * e.g.
 *
 * fe80::a00:20ff:fec4:f2b6 ipnodes_1
 *
 */
static int
_nss_ldap_hosts2str(ldap_backend_ptr be, nss_XbyY_args_t *argp) {
	return (_nss_ldap_hosts2str_int(AF_INET6, be, argp));
}

/*
 * getbyname gets a struct hostent by hostname. This function constructs
 * an ldap search filter using the name invocation parameter and the
 * gethostbyname search filter defined. Once the filter is constructed,
 * we search for a matching entry and marshal the data results into
 * struct hostent for the frontend process.  Host name searches will be
 * on fully qualified host names (foo.bar.sun.com)
 */

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	char		hostname[3 * MAXHOSTNAMELEN];
	char		realdomain[BUFSIZ];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	nss_status_t	lstat;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		rc;

	if (_ldap_filter_name(hostname, argp->key.ipnode.name,
			sizeof (hostname)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	rc = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETHOSTS6BYNAME, hostname);
	if (rc >= sizeof (searchfilter) || rc < 0)
		return ((nss_status_t)NSS_NOTFOUND);
	rc = snprintf(userdata, sizeof (userdata),
	    _F_GETHOSTS6BYNAME_SSD, hostname);
	if (rc >= sizeof (userdata) || rc < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/* get the domain we are in */
	rc = sysinfo(SI_SRPC_DOMAIN, realdomain, BUFSIZ);
	if (rc <= 0)
		return ((nss_status_t)NSS_NOTFOUND);

	/* Is this a request for a host.domain */
	if (DOTTEDSUBDOMAIN(hostname)) {
		char	host[MAXHOSTNAMELEN];
		char	domain[MAXHOSTNAMELEN];
		char	hname[3 * MAXHOSTNAMELEN];

		/* separate host and domain.  this function */
		/* will munge hname, so use argp->keyname */
		/* from here on for original string */

		(void) strcpy(hname, hostname);
		if (chophostdomain(hname, host, domain) == -1) {
			return ((nss_status_t)NSS_NOTFOUND);
		}

		/* if domain is a proper subset of realdomain */
		/* ie. domain = "foo" and realdomain */
		/* = "foor.bar.sun.com", we try to lookup both" */
		/* host.domain and host */

		if (propersubdomain(realdomain, domain) == 1) {
			/* yes, it is a proper domain */
			rc = snprintf(searchfilter, sizeof (searchfilter),
			    _F_GETHOSTS6DOTTEDBYNAME, hostname, host);
			if (rc >= sizeof (searchfilter) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);

			rc = snprintf(userdata, sizeof (userdata),
			    _F_GETHOSTS6DOTTEDBYNAME_SSD, hostname, host);
			if (rc >= sizeof (userdata) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);
		} else {
			/* it is not a proper domain, so only try to look up */
			/* host.domain */
			rc = snprintf(searchfilter, sizeof (searchfilter),
			    _F_GETHOSTS6BYNAME, hostname);
			if (rc >= sizeof (searchfilter) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);

			rc = snprintf(userdata, sizeof (userdata),
			    _F_GETHOSTS6BYNAME_SSD, hostname);
			if (rc >= sizeof (userdata) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);
		}
	} else {
		rc = snprintf(searchfilter, sizeof (searchfilter),
		    _F_GETHOSTS6BYNAME, hostname);
		if (rc >= sizeof (searchfilter) || rc < 0)
			return ((nss_status_t)NSS_NOTFOUND);

		rc = snprintf(userdata, sizeof (userdata),
		    _F_GETHOSTS6BYNAME_SSD, hostname);
		if (rc >= sizeof (userdata) || rc < 0)
			return ((nss_status_t)NSS_NOTFOUND);
	}
	lstat = (nss_status_t)_nss_ldap_lookup(be, argp, _HOSTS,
		searchfilter, NULL,
		_merge_SSD_filter, userdata);
	if (lstat == (nss_status_t)NS_LDAP_SUCCESS)
		return ((nss_status_t)NSS_SUCCESS);

	argp->h_errno = __nss2herrno(lstat);
	return ((nss_status_t)lstat);
}


/*
 * getbyaddr gets a struct hostent by host address. This function
 * constructs an ldap search filter using the host address invocation
 * parameter and the gethostbyaddr search filter defined. Once the
 * filter is constructed, we search for a matching entry and marshal
 * the data results into struct hostent for the frontend process.
 */

static nss_status_t
getbyaddr(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	struct in6_addr	addr;
	char		addrbuf[INET6_ADDRSTRLEN + 1];
	nss_status_t	lstat;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	argp->h_errno = 0;
	if ((argp->key.hostaddr.type != AF_INET6) ||
	    (argp->key.hostaddr.len != sizeof (addr)))
		return (NSS_NOTFOUND);

	(void) memcpy(&addr, argp->key.hostaddr.addr, sizeof (addr));
	if (IN6_IS_ADDR_V4MAPPED(&addr)) {
		if (inet_ntop(AF_INET, (void *) &addr.s6_addr[12],
				(void *)addrbuf, INET_ADDRSTRLEN) == NULL) {
			return (NSS_NOTFOUND);
		}
	} else {
		if (inet_ntop(AF_INET6, (void *)&addr, (void *)addrbuf,
				INET6_ADDRSTRLEN) == NULL)
			return (NSS_NOTFOUND);
	}
	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETHOSTS6BYADDR, addrbuf);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETHOSTS6BYADDR_SSD, addrbuf);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	lstat = (nss_status_t)_nss_ldap_lookup(be, argp,
		_HOSTS6, searchfilter, NULL,
		_merge_SSD_filter, userdata);
	if (lstat == (nss_status_t)NS_LDAP_SUCCESS)
		return ((nss_status_t)NSS_SUCCESS);

	argp->h_errno = __nss2herrno(lstat);
	return ((nss_status_t)lstat);
}

static ldap_backend_op_t ipnodes_ops[] = {
	_nss_ldap_destr,
	0,
	0,
	0,
	getbyname,
	getbyaddr
};


/*
 * _nss_ldap_hosts_constr is where life begins. This function calls the generic
 * ldap constructor function to define and build the abstract data types
 * required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_ipnodes_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(ipnodes_ops,
		sizeof (ipnodes_ops)/sizeof (ipnodes_ops[0]), _HOSTS6,
		ipnodes_attrs, _nss_ldap_hosts2str));
}
