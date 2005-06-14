/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
 * _nss_ldap_hosts2ent is the data marshaling method for the hosts getXbyY
 * system call gethostbyname() and gethostbyaddr. The format of this call
 * is a cononical name and alias (alias is cononical name too) and one or
 * more IP addresses in support of multihomed hosts. This method is called
 * after a successful synchronous search has been performed. This method
 * will parse the search results into struct hostent = argp->buf.buffer
 * which gets returned to the frontend process. One of three error
 * conditions is also returned to nsswitch.
 */

static int
_nss_ldap_hosts2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, j;
	int			nss_result;
	int			buflen = (int)0;
	int			firstimename = (int)1;
	int			firstimedn   = (int)1;
	int			firstimeaddr = (int)1;
	unsigned long		len = 0L;
	char			**hn, **ha, **dp;
	char			*cname = (char *)NULL;
	char			*buffer = (char *)NULL;
	char			*ceiling = (char *)NULL;
	struct hostent		*host = (struct hostent *)NULL;
	in_addr_t		addr;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t		*attrptr;
	in_addr_t		inet_addr(const char *cp);
	int			namecount = 0;
	int			addrcount = 0;
	int			aliascount = 0;
	int			validaddress = 0;
	int			gluelen = 0;
	ns_ldap_entry_t		*entry;
	ns_ldap_attr_t		*attr;
#ifdef DEBUG
	struct in_addr		in;
#endif /* DEBUG */

	buffer = argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_hosts2ent;
	}

	host = (struct hostent *)argp->buf.result;
	ceiling = buffer + buflen;

	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_hosts2ent;
	}

	namecount = 0;
	addrcount = 0;
	for (entry = result->entry; entry != NULL; entry = entry->next) {
		for (i = 0, attr = entry->attr_pair[i];
			i < entry->attr_count; i++) {
			attr = entry->attr_pair[i];
			if (strcasecmp(attr->attrname, _H_NAME) == 0)
				namecount += attr->value_count;
			if (strcasecmp(attr->attrname, _H_ADDR) == 0)
				addrcount += attr->value_count;
		}
	}
	for (entry = result->entry; entry != NULL; entry = entry->next) {
	    for (i = 0; i < entry->attr_count; i++) {
		attrptr = entry->attr_pair[i];
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_hosts2ent;
		}
		if (strcasecmp(attrptr->attrname, _H_DN) == 0) {
		    for (j = 0; j < attrptr->value_count; j++) {
			if (firstimedn) {
			    /* get domain name associated with this dn */
			    be->toglue = _get_domain_name(
					attrptr->attrvalue[j]);
			    firstimedn = (int)0;
			}
		    }
		}
		if (strcasecmp(attrptr->attrname, _H_NAME) == 0) {
		    for (j = 0; j < attrptr->value_count; j++) {
			if (firstimename) {
			    /* canonical name */
			    cname = __s_api_get_canonical_name(result->entry,
				attrptr, 1);
			    if (cname == NULL ||
				    (len = strlen(cname)) < 1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_hosts2ent;
			    }
			    if (be->toglue != NULL &&
				!DOTTEDSUBDOMAIN(cname))
				gluelen = strlen(be->toglue) + 1;
			    else
				gluelen = 0;
			    host->h_name = buffer;
			    buffer += len + gluelen + 1;
			    if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_hosts2ent;
			    }
			    (void) strcpy(host->h_name, cname);
			    if (gluelen > 0) {
				(void) strcat(host->h_name, ".");
				(void) strcat(host->h_name, be->toglue);
			    }
			    /* alias name */
			    aliascount = (namecount >= 1 ? (namecount - 1) : 0);
			    hn = host->h_aliases = (char **)ROUND_UP(buffer,
				sizeof (char **));
			    buffer = (char *)host->h_aliases +
				(sizeof (char *) * (aliascount + 1));
			    buffer = (char *)ROUND_UP(buffer,
				sizeof (char **));
			    if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_hosts2ent;
			    }
			    firstimename = (int)0;
			}
			/* alias list */
			if (aliascount > 0) {
				if ((attrptr->attrvalue[j] == NULL) ||
				    (len = strlen(attrptr->attrvalue[j])) < 1) {
				    nss_result = (int)NSS_STR_PARSE_PARSE;
				    goto result_hosts2ent;
				}
				/* skip canonical name */
				if (strcmp(cname, attrptr->attrvalue[j]) == 0)
					continue;
				/* check for duplicates */
				for (dp = host->h_aliases; *dp != NULL; dp++) {
				    if (strcmp(*dp, attrptr->attrvalue[j]) == 0)
					goto next_alias;
				}
				if (be->toglue != NULL &&
					!DOTTEDSUBDOMAIN(attrptr->attrvalue[j]))
					gluelen = strlen(be->toglue) + 1;
				else
					gluelen = 0;
				*hn = buffer;
				buffer += len + gluelen + 1;
				if (buffer >= ceiling) {
				    nss_result = (int)NSS_STR_PARSE_ERANGE;
				    goto result_hosts2ent;
				}
				(void) strcpy(*hn, attrptr->attrvalue[j]);
				if (gluelen > 0) {
				    (void) strcat(*hn, ".");
				    (void) strcat(*hn, be->toglue);
				}
				hn++;
			}
next_alias:
			continue;
		    }
		}
	    }
	}

	for (entry = result->entry; entry != NULL; entry = entry->next) {
	    for (i = 0; i < entry->attr_count; i++) {
		attrptr = entry->attr_pair[i];
		if (attrptr == NULL) {
		    nss_result = (int)NSS_STR_PARSE_PARSE;
		    goto result_hosts2ent;
		}
		if (strcasecmp(attrptr->attrname, _H_ADDR) == 0) {
		    for (j = 0; j < attrptr->value_count; j++) {
			if (firstimeaddr) {
			    /* allocate 1 address per entry */
			    ha = host->h_addr_list =
				(char **)ROUND_UP(buffer,
				sizeof (char **));
			    buffer = (char *)host->h_addr_list +
				sizeof (char *) *
				(addrcount + 1);
			    buffer = (char *)ROUND_UP(buffer,
				sizeof (char **));
			    if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_hosts2ent;
			    }
			    firstimeaddr = (int)0;
			}
			/* filter out IPV6 addresses */
			addr = inet_addr(_strip_quotes(attrptr->attrvalue[j]));
			if (addr == (in_addr_t)-1) {
			    goto next_addr;
			}
			validaddress++;
			/* check for duplicates */
			for (dp = host->h_addr_list; *dp != NULL; dp++) {
			if (memcmp(*dp, &addr, (size_t)sizeof (in_addr_t)) == 0)
			    goto next_addr;
			}
			*ha = buffer;
			len = (unsigned long)sizeof (in_addr_t);
			buffer += len;
			if (buffer >= ceiling) {
			    nss_result = (int)NSS_STR_PARSE_ERANGE;
			    goto result_hosts2ent;
			}
			(void) memcpy(*ha++, (char *)&addr, (size_t)len);
next_addr:
			continue;
		    }
		}
	    }
	}

	if (validaddress == 0) {
	    nss_result = (int)NSS_STR_PARSE_NO_ADDR;
	    goto result_hosts2ent;
	}

	host->h_addrtype = AF_INET;
	host->h_length = sizeof (uint_t);

#ifdef DEBUG
	(void) fprintf(stdout, "\n[gethostent.c: _nss_ldap_hosts2ent]\n");
	(void) fprintf(stdout, "        h_name: [%s]\n", host->h_name);
	if (host->h_aliases != NULL) {
		for (hn = host->h_aliases; *hn != NULL; hn++)
			(void) fprintf(stdout, "     h_aliases: [%s]\n", *hn);
	}
	(void) fprintf(stdout, "    h_addrtype: [%d]\n", host->h_addrtype);
	(void) fprintf(stdout, "      h_length: [%d]\n", host->h_length);
	for (ha = host->h_addr_list; *ha != NULL; ha++) {
		(void) memcpy(&in.s_addr, *ha, sizeof (in.s_addr));
		if (inet_ntoa(in) != NULL)
			(void) fprintf(stdout, "   h_addr_list: [%s]\n",
				inet_ntoa(in));
		else
			(void) fprintf(stdout, "   h_addr_list: <NULL>\n");
	}
#endif /* DEBUG */

result_hosts2ent:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
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
	lstat = (nss_status_t)_nss_ldap_lookup(be, argp, _HOSTS,
		searchfilter, NULL, _merge_SSD_filter,
		userdata);
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

	lstat = (nss_status_t)_nss_ldap_lookup(be, argp,
		_HOSTS, searchfilter, NULL, _merge_SSD_filter, userdata);
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

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[gethostent.c: _nss_ldap_hosts_constr]\n");
#endif	/* DEBUG */
	return ((nss_backend_t *)_nss_ldap_constr(hosts_ops,
		sizeof (hosts_ops)/sizeof (hosts_ops[0]), _HOSTS,
		hosts_attrs, _nss_ldap_hosts2ent));
}
