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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "ns_internal.h"
#include "ldap_common.h"

/* networks attributes filters */
#define	_N_NAME		"cn"
#define	_N_NETWORK	"ipnetworknumber"
#define	_F_GETNETBYNAME	"(&(objectClass=ipNetwork)(cn=%s))"
#define	_F_GETNETBYNAME_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETNETBYADDR	"(&(objectClass=ipNetwork)(|(ipNetworkNumber=%s)" \
						"(ipNetworkNumber=%s)))"
#define	_F_GETNETBYADDR_SSD	"(&(%%s)(|(ipNetworkNumber=%s)" \
						"(ipNetworkNumber=%s)))"

static const char *networks_attrs[] = {
	_N_NAME,
	_N_NETWORK,
	(char *)NULL
};

/*
 * _nss_ldap_networks2str is the data marshaling method for the networks
 * getXbyY * (e.g., getbyname(), getbyaddr(), getnetent() backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 * e.g.
 *
 * SunRay-ce2	10.34.96.0	SunRay
 *
 */
static int
_nss_ldap_networks2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	uint_t		i;
	int		nss_result;
	int		buflen = 0, len;
	char		**network, *cname = NULL;
	char		*buffer = NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*names;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	buflen = argp->buf.buflen;

	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_net2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	names = __ns_ldap_getAttrStruct(result->entry,  _N_NAME);
	if (names == NULL || names->attrvalue == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_net2str;
	}
	/* Get the canonical name */
	cname = __s_api_get_canonical_name(result->entry, names, 1);
	/*
	 * The definition of the object class  "ipNetwork" has a
	 * discrepency between RFC 2307 and 2307bis.
	 * In 2307, "cn" is a MUST attribute. In 2307bis, "cn" is a
	 * MAY attribute.
	 * If "cn" is a MAY attribute, it does not  appear in RDN and can't
	 * be derived from RDN as a canonical "cn" name. In that case, use 1st
	 * "cn" value as the official name.
	 */
	if (cname == NULL)
		/* 2307bis case */
		cname = names->attrvalue[0];
	if (cname == NULL || (len = strlen(cname)) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_net2str;
	}
	network = __ns_ldap_getAttr(result->entry, _N_NETWORK);
	if (network == NULL || network[0] == NULL ||
			(len = strlen(network[0])) < 1) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_net2str;
	}
	len = snprintf(buffer, buflen,  "%s %s", cname, network[0]);
	TEST_AND_ADJUST(len, buffer, buflen, result_net2str);
	/* Append aliases */
	for (i = 0; i < names->value_count; i++) {
		if (names->attrvalue[i] == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_net2str;
		}
		/* Skip the canonical name */
		if (strcasecmp(names->attrvalue[i], cname) != 0) {
			len = snprintf(buffer, buflen,  " %s",
					names->attrvalue[i]);
			TEST_AND_ADJUST(len, buffer, buflen, result_net2str);
		}
	}

	/* The front end marshaller doesn't need to copy trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_net2str:

	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

/*
 * Takes an unsigned integer in host order, and returns a printable
 * string for it as a network number.  To allow for the possibility of
 * naming subnets, only trailing dot-zeros are truncated.
 * buf2 is untruncated version.
 */

static int nettoa(int anet, char *buf, char *buf2, int buflen)
{
	int		addr;
	char		*p;
	struct in_addr	in;

	if (buf == NULL || buf2 == NULL)
		return ((int)1);

	in = inet_makeaddr(anet, INADDR_ANY);
	addr = in.s_addr;
	if (inet_ntop(AF_INET, (const void *)&in, buf2, INET_ADDRSTRLEN)
			== NULL)
		return ((int)1);
	if (strlcpy(buf, buf2, buflen) >= buflen)
		return ((int)1);
	if ((IN_CLASSA_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return ((int)1);
		*p = 0;
	} else if ((IN_CLASSB_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return ((int)1);
		p = strchr(p + 1, '.');
		if (p == NULL)
			return ((int)1);
		*p = 0;
	} else if ((IN_CLASSC_HOST & htonl(addr)) == 0) {
		p = strrchr(buf, '.');
		if (p == NULL)
			return ((int)1);
		*p = 0;
	}

	return ((int)0);
}


/*
 * getbyname gets a network entry by name. This function constructs an
 * ldap search filter using the network name invocation parameter and the
 * getnetbyname search filter defined. Once the filter is constructed, we
 * search for a matching entry and marshal the data results into struct
 * netent for the frontend process. The function _nss_ldap_networks2ent
 * performs the data marshaling.
 */

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		netname[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(netname, argp->key.name, sizeof (netname)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETNETBYNAME, netname);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETNETBYNAME_SSD, netname);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_NETWORKS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


/*
 * getbyaddr gets a network entry by ip address. This function constructs an
 * ldap search filter using the name invocation parameter and the getnetbyaddr
 * search filter defined. Once the filter is constructed, we search for a
 * matching entry and marshal the data results into struct netent for the
 * frontend process. The function _nss_ldap_networks2ent performs the data
 * marshaling.
 */

static nss_status_t
getbyaddr(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		addrstr[INET_ADDRSTRLEN], addrstr2[INET_ADDRSTRLEN];
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	if (nettoa((int)argp->key.netaddr.net, addrstr, addrstr2,
				INET_ADDRSTRLEN) != 0)
		return ((nss_status_t)NSS_UNAVAIL);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETNETBYADDR, addrstr, addrstr2);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETNETBYADDR_SSD, addrstr, addrstr2);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_NETWORKS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}

static ldap_backend_op_t net_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname,
	getbyaddr
};


/*
 * _nss_ldap_networks_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract data
 * types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_networks_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(net_ops,
		sizeof (net_ops)/sizeof (net_ops[0]), _NETWORKS,
		networks_attrs, _nss_ldap_networks2str));
}
