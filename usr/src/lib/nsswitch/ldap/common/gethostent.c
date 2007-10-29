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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <sys/systeminfo.h>
#include "ns_internal.h"
#include "ldap_common.h"

/* host attributes filters */
#define	_H_DN			"dn"
#define	_H_NAME			"cn"
#define	_H_ADDR			"iphostnumber"
#define	_F_GETHOSTBYNAME	"(&(objectClass=ipHost)(cn=%s))"
#define	_F_GETHOSTBYNAME_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETHOSTDOTTEDBYNAME	"(&(objectClass=ipHost)(|(cn=%s)(cn=%s)))"
#define	_F_GETHOSTDOTTEDBYNAME_SSD "(&(%%s)(|(cn=%s)(cn=%s)))"
#define	_F_GETHOSTBYADDR	"(&(objectClass=ipHost)(ipHostNumber=%s))"
#define	_F_GETHOSTBYADDR_SSD	"(&(%%s)(ipHostNumber=%s))"

static const char *hosts_attrs[] = {
	_H_NAME,
	_H_ADDR,
	(char *)NULL
};

/*
 * _nss_ldap_hosts2str is the data marshaling method for the hosts getXbyY
 * system call gethostbyname() and gethostbyaddr.
 * This method is called after a successful search has been performed.
 * This method will parse the search results into the file format.
 * e.g.
 *
 * 9.9.9.9 jurassic jurassic1 jurassic2
 * 10.10.10.10 puppy
 *
 */
int
_nss_ldap_hosts2str_int(int af, ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	uint_t			i;
	int			nss_result;
	int			buflen, buflen1, buflen2, len;
	int			firstimedn   = 1, first_entry;
	int			validaddress = 0, copy_cname;
	char			*cname = NULL, *h_name = NULL;
	char			*buffer = NULL;
	char			*name;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t		*names;
	ns_ldap_entry_t		*entry;
	char			**ips = NULL, **dns = NULL;
	char			*first_host = NULL, *other_hosts = NULL;
	char			*buf1, *buf2;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	buflen = buflen1 = buflen2 = argp->buf.buflen;

	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_host2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;
	if ((first_host = calloc(1, buflen1)) == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_host2str;
	}
	if ((other_hosts = calloc(1, buflen2)) == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_host2str;
	}

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);
	/*
	 * Multiple lines return will be sepereated by newlines
	 * Single line return or last line does not have newline
	 * e.g.
	 *
	 * 8.8.8.8 hostname
	 *
	 * or the search for hostname h1 returns 3 entries
	 *
	 * 9.9.9.9 h1
	 * 10.10.10.10 h1 xx
	 * 20.20.20.20 h1 yyy
	 *
	 * str2hostent expects all name/aliases in the first entry
	 * so the string is organized as
	 *
	 * "9.9.9.9 h1 xx yy\n10.10.10.10 \n20.20.20.20 "
	 *
	 * Use first_host to hold "9.9.9.9 h1 xx yy" and other_hosts to hold
	 * "\n10.10.10.10 \n20.20.20.20 "
	 *
	 */
	buf1 = first_host;
	buf2 = other_hosts;
	first_entry = 1;
	for (entry = result->entry; entry != NULL; entry = entry->next) {
		if (firstimedn) {
			dns =  __ns_ldap_getAttr(entry, _H_DN);
			if (dns == NULL || dns[0] == NULL || strlen(dns[0])
			    < 1) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_host2str;
			}
			/* get domain name associated with this dn */
			be->toglue = _get_domain_name(dns[0]);
			firstimedn = 0;
		}

		/* Get IP */
		ips = __ns_ldap_getAttr(entry, _H_ADDR);
		if (ips == NULL || ips[0] == NULL || strlen(ips[0]) < 1) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_host2str;
		}
		/* Skip IPV6 address in AF_INET mode */
		if (af == AF_INET &&
		    (inet_addr(_strip_quotes(ips[0])) == (in_addr_t)-1))
			continue;

		/* A valid address for either af mode */
		validaddress++;

		if (first_entry) {
			len = snprintf(buf1, buflen1, "%s", ips[0]);
			TEST_AND_ADJUST(len, buf1, buflen1, result_host2str);
		} else {
			len = snprintf(buf2, buflen2, "\n%s ", ips[0]);
			TEST_AND_ADJUST(len, buf2, buflen2, result_host2str);
		}

		/* Get host names */
		names = __ns_ldap_getAttrStruct(entry, _H_NAME);
		if (names == NULL || names->attrvalue == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_host2str;
		}

		/* Get canonical name of each entry */
		cname = __s_api_get_canonical_name(entry, names, 1);
		if (cname == NULL || strlen(cname) < 1) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_host2str;
		}

		/* Filter cname that's identical to h_name */
		if (first_entry) {
			h_name = cname;
			first_entry = 0;
			copy_cname = 1;
		} else if (strcasecmp(cname, h_name) != 0) {
			copy_cname = 1;
		} else
			copy_cname = 0;

		if (copy_cname) {
			/* Use the canonical name as the host name */
			if (be->toglue == NULL || DOTTEDSUBDOMAIN(cname))
				len = snprintf(buf1, buflen1, " %s", cname);
			else
				/* append domain name */
				len = snprintf(buf1, buflen1, " %s.%s", cname,
				    be->toglue);

			TEST_AND_ADJUST(len, buf1, buflen1, result_host2str);
		}

		/* Append aliases */
		for (i = 0; i < names->value_count; i++) {
			name = names->attrvalue[i];
			if (name == NULL) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_host2str;
			}
			/* Skip the canonical name and h_name */
			if (strcasecmp(name, cname) != 0 &&
			    strcasecmp(name, h_name) != 0) {
				if (be->toglue == NULL || DOTTEDSUBDOMAIN(name))
					len = snprintf(buf1, buflen1, " %s",
					    name);
				else
					/* append domain name */
					len = snprintf(buf1, buflen1, " %s.%s",
					    name, be->toglue);
				TEST_AND_ADJUST(len, buf1, buflen1,
				    result_host2str);
			}
		}
	}

	if (validaddress == 0) {
	/*
	 * For AF_INET mode, it found an IPv6 address and skipped it.
	 */
		nss_result = NSS_STR_PARSE_NO_ADDR;
		goto result_host2str;
	}
	/* Combine 2 strings */
	len = snprintf(buffer, buflen, "%s%s", first_host, other_hosts);
	TEST_AND_ADJUST(len, buffer, buflen, result_host2str);

	/* The front end marshaller doesn't need to copy trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_host2str:
	if (first_host)
		free(first_host);
	if (other_hosts)
		free(other_hosts);
	if (be->toglue) {
		free(be->toglue);
		be->toglue = NULL;
	}
	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

static int
_nss_ldap_hosts2str(ldap_backend_ptr be, nss_XbyY_args_t *argp) {
	return (_nss_ldap_hosts2str_int(AF_INET, be, argp));
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

	if (_ldap_filter_name(hostname, argp->key.name, sizeof (hostname)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	rc = snprintf(searchfilter, sizeof (searchfilter), _F_GETHOSTBYNAME,
	    hostname);
	if (rc >= sizeof (searchfilter) || rc < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	rc = snprintf(userdata, sizeof (userdata), _F_GETHOSTBYNAME_SSD,
	    hostname);
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
		/* ie. domain = "eng" and realdomain */
		/* = "eng.wiz.com", we try to lookup both" */
		/* host.domain and host */

		if (propersubdomain(realdomain, domain) == 1) {
			/* yes, it is a proper domain */
			rc = snprintf(searchfilter, sizeof (searchfilter),
			    _F_GETHOSTDOTTEDBYNAME, hostname, host);
			if (rc >= sizeof (searchfilter) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);

			rc = snprintf(userdata, sizeof (userdata),
			    _F_GETHOSTDOTTEDBYNAME_SSD, hostname, host);
			if (rc >= sizeof (userdata) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);
		} else {
			/* it is not a proper domain, so only try to look up */
			/* host.domain */
			rc = snprintf(searchfilter, sizeof (searchfilter),
			    _F_GETHOSTBYNAME, hostname);
			if (rc >= sizeof (searchfilter) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);

			rc = snprintf(userdata, sizeof (userdata),
			    _F_GETHOSTBYNAME_SSD, hostname);
			if (rc >= sizeof (userdata) || rc < 0)
				return ((nss_status_t)NSS_NOTFOUND);
		}
	} else {
		rc = snprintf(searchfilter, sizeof (searchfilter),
		    _F_GETHOSTBYNAME, hostname);
		if (rc >= sizeof (searchfilter) || rc < 0)
			return ((nss_status_t)NSS_NOTFOUND);

		rc = snprintf(userdata, sizeof (userdata),
		    _F_GETHOSTBYNAME_SSD, hostname);
		if (rc >= sizeof (userdata) || rc < 0)
			return ((nss_status_t)NSS_NOTFOUND);
	}
	lstat = (nss_status_t)_nss_ldap_lookup(be, argp, _HOSTS, searchfilter,
	    NULL, _merge_SSD_filter, userdata);
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
 *
 * extern char *inet_ntoa_r() not an advertised function from libnsl.
 * There is no man page and no prototype.
 */

static nss_status_t
getbyaddr(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	struct in_addr	addr;
	char		buf[18];
	nss_status_t	lstat;
	extern char	*inet_ntoa_r();
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	argp->h_errno = 0;
	if ((argp->key.hostaddr.type != AF_INET) ||
	    (argp->key.hostaddr.len != sizeof (addr)))
		return (NSS_NOTFOUND);

	(void) memcpy(&addr, argp->key.hostaddr.addr, sizeof (addr));
	(void) inet_ntoa_r(addr, buf);

	ret = snprintf(searchfilter, sizeof (searchfilter), _F_GETHOSTBYADDR,
	    buf);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata), _F_GETHOSTBYADDR_SSD, buf);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	lstat = (nss_status_t)_nss_ldap_lookup(be, argp, _HOSTS, searchfilter,
	    NULL, _merge_SSD_filter, userdata);
	if (lstat == (nss_status_t)NS_LDAP_SUCCESS)
		return ((nss_status_t)NSS_SUCCESS);

	argp->h_errno = __nss2herrno(lstat);
	return ((nss_status_t)lstat);
}

static ldap_backend_op_t hosts_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
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
_nss_ldap_hosts_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(hosts_ops,
	    sizeof (hosts_ops)/sizeof (hosts_ops[0]), _HOSTS,
	    hosts_attrs, _nss_ldap_hosts2str));
}
