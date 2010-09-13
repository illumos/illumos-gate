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

#include <ctype.h>
#include <netdb.h>
#include "ns_internal.h"
#include "ldap_common.h"

/* services attributes filters */
#define	_S_NAME			"cn"
#define	_S_PORT			"ipserviceport"
#define	_S_PROTOCOL		"ipserviceprotocol"
#define	_F_GETSERVBYNAME	"(&(objectClass=ipService)(cn=%s))"
#define	_F_GETSERVBYNAME_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETSERVBYNAMEPROTO	\
	"(&(objectClass=ipService)(cn=%s)(ipServiceProtocol=%s))"
#define	_F_GETSERVBYNAMEPROTO_SSD	\
	"(&(%%s)(cn=%s)(ipServiceProtocol=%s))"
#define	_F_GETSERVBYPORT	"(&(objectClass=ipService)(ipServicePort=%ld))"
#define	_F_GETSERVBYPORT_SSD	"(&(%%s)(ipServicePort=%ld))"
#define	_F_GETSERVBYPORTPROTO	\
	"(&(objectClass=ipService)(ipServicePort=%ld)(ipServiceProtocol=%s))"
#define	_F_GETSERVBYPORTPROTO_SSD	\
	"(&(%%s)(ipServicePort=%ld)(ipServiceProtocol=%s))"

typedef struct _nss_services_cookie {
	int			index;	/* index of ipserviceprotocol */
	char			*cname;	/* canonical name, don't free it */
	ns_ldap_result_t	*result;
} _nss_services_cookie_t;

static const char *services_attrs[] = {
	_S_NAME,
	_S_PORT,
	_S_PROTOCOL,
	(char *)NULL
};

void
_nss_services_cookie_free(void **ckP) {
	_nss_services_cookie_t **cookieP = (_nss_services_cookie_t **)ckP;
	if (cookieP && *cookieP) {
		if ((*cookieP)->result)
			(void) __ns_ldap_freeResult(&(*cookieP)->result);
		free(*cookieP);
		*cookieP = NULL;
	}
}

static _nss_services_cookie_t *
_nss_services_cookie_new(ns_ldap_result_t *result, int index, char *cname) {

	_nss_services_cookie_t	*cookie;

	if ((cookie = calloc(1, sizeof (*cookie))) == NULL)
		return (NULL);

	/*
	 * result has been allocated either by __ns_ldap_firstEntry
	 * or __ns_ldap_nextEntry.
	 */
	cookie->result = result;

	cookie->index = index;
	cookie->cname = cname;

	return (cookie);
}
/*
 * _nss_ldap_services2str is the data marshaling method for the services
 * getXbyY * (e.g., getbyname(), getbyport(), getent()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 * e.g.
 *
 * nfsd 2049/udp nfs
 * nfsd 2049/tcp nfs
 *
 * In section 5.5 of RFC 2307, it specifies that a "services" LDAP entry
 * containing multiple ipserviceprotocol values should be able to be mapped
 * to multiple "services" entities. Code has been added to support
 * this one to many mapping feature.
 */

static int
_nss_ldap_services2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	uint_t		i, k;
	int		nss_result;
	int		buflen = 0, len;
	char		**ipport, *cname = NULL, *protoval = NULL;
	char		*buffer = NULL;
	ns_ldap_result_t	*result;
	ns_ldap_attr_t	*names = NULL, *protocol = NULL;
	_nss_services_cookie_t	*cookie = (_nss_services_cookie_t *)
						be->services_cookie;

	if (cookie) {
		/*
		 * getservent_r with multiple protocol values and the entry
		 * is enumerated 2nd time or beyond
		 */
		result =  cookie->result;
		cname = cookie->cname;
	} else {
		/*
		 * getservbyname_r, getservbyport_r or
		 * getservent_r with single protocol value or multiple values
		 * and the entry is enumerated 1st time
		 */
		result = be->result;
	}
	if (result == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_srvs2str;
	}

	buflen = argp->buf.buflen;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_srvs2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;


	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	/* Get services names */
	names = __ns_ldap_getAttrStruct(result->entry, _S_NAME);
	if (names == NULL || names->attrvalue == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_srvs2str;
	}
	/* Get canonical services name */
	if (cname == NULL) {
	    cname = __s_api_get_canonical_name(result->entry, names, 1);
	    if (cname == NULL || (len = strlen(cname)) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_srvs2str;
	    }
	}
	/* Get port */
	ipport = __ns_ldap_getAttr(result->entry, _S_PORT);
	if (ipport == NULL || ipport[0] == NULL ||
			(len = strlen(cname)) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_srvs2str;
	}
	/* Set services name and port and '/' */
	len = snprintf(buffer, buflen, "%s %s/", cname, ipport[0]);
	TEST_AND_ADJUST(len, buffer, buflen, result_srvs2str);

	/* Get protocol */
	protocol = __ns_ldap_getAttrStruct(result->entry, _S_PROTOCOL);
	if (protocol == NULL || protocol->attrvalue == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_srvs2str;
	}

	if (cookie) {
		/*
		 * getservent_r
		 * Get current value then increment index
		 */
		protoval = protocol->attrvalue[cookie->index++];
	} else if (protocol->value_count > 1 && be->setcalled == 0 &&
			argp->key.serv.proto) {
		/*
		 * getserverbyname_r and getservbyport_r
		 *
		 * If there are more than one value and
		 * it needs to match protocol too,
		 * iterate each value to find matching one.
		 */
		for (k = 0; k < protocol->value_count; k++) {
			if (protocol->attrvalue[k] == NULL) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_srvs2str;
			}
			if (strcmp(protocol->attrvalue[k],
				argp->key.serv.proto) == 0) {
				protoval = protocol->attrvalue[k];
				break;
			}
		}
	} else {
		/*
		 * 1. getserverbyname_r and getservbyport_r
		 *
		 * It does not need to match protocol or
		 * ipserviceprotocol has single value,
		 * return the first one.
		 *
		 * 2. getservent_r with single ipserviceprotocol value
		 * or multiple values and the entry is
		 * enumerated 1st time,  return the first one.
		 *
		 */
		protoval = protocol->attrvalue[0];
	}

	if (protoval == NULL || (len = strlen(protoval)) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_srvs2str;
	}

	/* Set protocol */
	len = snprintf(buffer, buflen, "%s", protoval);
	TEST_AND_ADJUST(len, buffer, buflen, result_srvs2str);

	/* Append aliases */
	for (i = 0; i < names->value_count; i++) {
		if (names->attrvalue[i] == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_srvs2str;
		}
		/* Skip the canonical name */
		if (strcmp(cname, names->attrvalue[i]) != 0) {
			len = snprintf(buffer, buflen, " %s",
					names->attrvalue[i]);
			TEST_AND_ADJUST(len, buffer, buflen, result_srvs2str);
		}
	}


	if (be->enumcookie != NULL && cookie == NULL &&
			protocol->value_count > 1) {
		/*
		 * getservent_r with multiple ipserviceprotocol values
		 * and the entry is enumerated 1st time
		 *
		 * Create cookie and save result in the cookie
		 * "attrvalue[0]" of ipserviceprotocol is returned,
		 * so it starts with index 1. Also save the canonical name.
		 */
		be->services_cookie =
			(void *)_nss_services_cookie_new(be->result, 1, cname);
		if (be->services_cookie == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_srvs2str;
		}

		/* reset be->result so it won't get freed later */
		be->result = NULL;
	}

	/* The front end marshaller doesn't need to copy trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_srvs2str:
	if (cookie) {
		/*
		 * getservent_r with multiple ipserviceprotocol values and
		 * the entry is enumerated 2nd time or beyond
		 */
		if (nss_result != NSS_STR_PARSE_SUCCESS ||
			cookie->index >= protocol->value_count) {
			/*
			 * If it's an error case or it has iterated all
			 * ipservicesprotocol value(s) then free cookie and
			 * set it to NULL
			 *
			 */
			_nss_services_cookie_free(
				(void **)&be->services_cookie);
		}
	} else {
		/*
		 * getservbyname_r, getservbyport_r, or
		 * getservent_r with single value or can't create cookie
		 */
		(void) __ns_ldap_freeResult(&be->result);
	}
	return (nss_result);
}

/*
 * getbyname gets struct servent values by service name. This
 * function constructs an ldap search filter using the service
 * name invocation parameter and the getservbyname search filter
 * defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into *serv = (struct servent *)
 * argp->buf.result. The function _nss_ldap_services2ent performs
 * the data marshaling.
 */

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	const char	*proto = argp->key.serv.proto;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		name[SEARCHFILTERLEN];
	char		protocol[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(name, argp->key.serv.serv.name, sizeof (name))
			!= 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if (proto == NULL) {
		ret = snprintf(searchfilter, sizeof (searchfilter),
		    _F_GETSERVBYNAME, name);
		if (ret >= sizeof (searchfilter) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);

		ret = snprintf(userdata, sizeof (userdata),
		    _F_GETSERVBYNAME_SSD, name);
		if (ret >= sizeof (userdata) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);
	} else {
		if (_ldap_filter_name(protocol, proto, sizeof (protocol)) != 0)
			return ((nss_status_t)NSS_NOTFOUND);

		ret = snprintf(searchfilter, sizeof (searchfilter),
		    _F_GETSERVBYNAMEPROTO, name, protocol);
		if (ret >= sizeof (searchfilter) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);

		ret = snprintf(userdata, sizeof (userdata),
		    _F_GETSERVBYNAMEPROTO_SSD, name, protocol);
		if (ret >= sizeof (userdata) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);
	}

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_SERVICES, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


/*
 * getbyport gets struct servent values by service port. This
 * function constructs an ldap search filter using the service
 * name invocation parameter and the getservbyport search filter
 * defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into *serv = (struct servent *)
 * argp->buf.result. The function _nss_ldap_services2ent performs
 * the data marshaling.
 */

static nss_status_t
getbyport(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	const char	*proto = argp->key.serv.proto;
	char		portstr[12];
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		protocol[SEARCHFILTERLEN];
	int		ret;

	ret = snprintf(portstr, sizeof (portstr), " %d",
	    ntohs((ushort_t)argp->key.serv.serv.port));
	if (ret >= sizeof (portstr) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if (proto == NULL) {
		ret = snprintf(searchfilter, sizeof (searchfilter),
		    _F_GETSERVBYPORT, strtol(portstr, (char **)NULL, 10));
		if (ret >= sizeof (searchfilter) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);

		ret = snprintf(userdata, sizeof (userdata),
		    _F_GETSERVBYPORT_SSD, strtol(portstr, (char **)NULL, 10));
		if (ret >= sizeof (userdata) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);
	} else {
		if (_ldap_filter_name(protocol, proto, sizeof (protocol)) != 0)
			return ((nss_status_t)NSS_NOTFOUND);

		ret = snprintf(searchfilter, sizeof (searchfilter),
		    _F_GETSERVBYPORTPROTO,
		    strtol(portstr, (char **)NULL, 10), protocol);
		if (ret >= sizeof (searchfilter) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);

		ret = snprintf(userdata, sizeof (userdata),
		    _F_GETSERVBYPORTPROTO_SSD,
		    strtol(portstr, (char **)NULL, 10), protocol);
		if (ret >= sizeof (userdata) || ret < 0)
			return ((nss_status_t)NSS_NOTFOUND);
	}

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_SERVICES, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}

static ldap_backend_op_t serv_ops[] = {
    _nss_ldap_destr,
    _nss_ldap_endent,
    _nss_ldap_setent,
    _nss_ldap_getent,
    getbyname,
    getbyport
};


/*
 * _nss_ldap_services_constr is where life begins. This function calls
 * the generic ldap constructor function to define and build the
 * abstract data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_services_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(serv_ops,
		sizeof (serv_ops)/sizeof (serv_ops[0]), _SERVICES,
		services_attrs, _nss_ldap_services2str));
}
