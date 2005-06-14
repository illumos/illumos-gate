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
#define	_F_GETNETBYADDR	"(&(objectClass=ipNetwork)(ipNetworkNumber=%s))"
#define	_F_GETNETBYADDR_SSD	"(&(%%s)(ipNetworkNumber=%s))"

static const char *networks_attrs[] = {
	_N_NAME,
	_N_NETWORK,
	(char *)NULL
};

/*
 * _nss_ldap_networks2ent is the data marshaling method for the networks
 * getXbyY * (e.g., getbyname(), getbyaddr(), getnetent() backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into struct netent =
 * argp->buf.buffer which the frontend process expects. Three error conditions
 * are expected and returned to nsswitch.
 */

static int
_nss_ldap_networks2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		i, j;
	int		nss_result;
	int		buflen = (int)0;
	int		firstime = (int)1;
	unsigned long	len = 0L;
	char		**mp, *cname = NULL;
#ifdef DEBUG
	char		addrstr[16];
#endif /* DEBUG */
	char		*buffer = (char *)NULL;
	char		*ceiling = (char *)NULL;
	struct netent	*ntk = (struct netent *)NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*attrptr;

	buffer = argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_net2ent;
	}
	ntk = (struct netent *)argp->buf.result;
	ceiling = buffer + buflen;

	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_net2ent;
	}

	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_net2ent;
		}
		if (strcasecmp(attrptr->attrname, _N_NAME) == 0) {
			for (j = 0; j < attrptr->value_count; j++) {
				if (firstime) {
					/*
					 * The definition of the object class
					 * "ipNetwork" has a descripency between
					 * RFC 2307 and 2307bis.
					 * In 2307, "cn" is a MUST attribute.
					 * In 2307bis, "cn" is a MAY attribute.
					 * If "cn" is a MAY attribute,
					 * it does not  appear in RDN and can't
					 * be derived from RDN as a canonical
					 * "cn" name. In that case, use 1st
					 * "cn" value as the official name.
					 */
					cname = __s_api_get_canonical_name(
						result->entry, attrptr, 1);
					if (cname == NULL)
						/* 2307bis case */
						cname = attrptr->attrvalue[j];

					if (cname == NULL ||
					    (len = strlen(cname)) < 1) {
						nss_result =
							NSS_STR_PARSE_PARSE;
						goto result_net2ent;
					}
					ntk->n_name = buffer;
					buffer += len + 1;
					if (buffer >= ceiling) {
						nss_result =
						    (int)NSS_STR_PARSE_ERANGE;
						goto result_net2ent;
					}
					(void) strcpy(ntk->n_name, cname);
					/* alias list */
					mp = ntk->n_aliases =
						(char **)ROUND_UP(buffer,
						sizeof (char **));
					buffer = (char *)ntk->n_aliases +
						sizeof (char *) *
						(attrptr->value_count + 1);
					buffer = (char *)ROUND_UP(buffer,
						sizeof (char **));
					if (buffer >= ceiling) {
						nss_result =
						    (int)NSS_STR_PARSE_ERANGE;
						goto result_net2ent;
					}
					firstime = (int)0;
				}
				/* alias list */
				if ((attrptr->attrvalue[j] == NULL) ||
				    (len = strlen(attrptr->attrvalue[j])) < 1) {
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_net2ent;
				}
				/* skip canonical name(official name) */
				if (strcmp(attrptr->attrvalue[j], cname) == 0)
					continue;
				*mp = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_net2ent;
				}
				(void) strcpy(*mp++, attrptr->attrvalue[j]);
				continue;
			}
		}
		if (strcasecmp(attrptr->attrname, _N_NETWORK) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_net2ent;
			}
			if ((ntk->n_net = (in_addr_t)
			    inet_network(attrptr->attrvalue[0])) ==
			    (in_addr_t)-1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_net2ent;
			}
#ifdef DEBUG
			strlcpy(addrstr, attrptr->attrvalue[0],
						sizeof (addrstr));
#endif /* DEBUG */
			continue;
		}
	}
	ntk->n_addrtype = AF_INET;

#ifdef DEBUG
	(void) fprintf(stdout, "\n[getnetent.c: _nss_ldap_networks2ent]\n");
	(void) fprintf(stdout, "        n_name: [%s]\n", ntk->n_name);
	if (mp != NULL) {
		for (mp = ntk->n_aliases; *mp != NULL; mp++)
			(void) fprintf(stdout, "     n_aliases: [%s]\n", *mp);
	}
	if (ntk->n_addrtype == AF_INET)
		(void) fprintf(stdout, "    n_addrtype: [AF_INET]\n");
	else
		(void) fprintf(stdout, "    n_addrtype: [%d]\n",
			    ntk->n_addrtype);
	(void) fprintf(stdout, "         n_net: [%s]\n", addrstr);
#endif /* DEBUG */

result_net2ent:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}


/*
 * Takes an unsigned integer in host order, and returns a printable
 * string for it as a network number.  To allow for the possibility of
 * naming subnets, only trailing dot-zeros are truncated.
 */

static int nettoa(int anet, char *buf, int buflen)
{
	int		addr;
	char		*p;
	struct in_addr	in;

	if (buf == 0)
		return ((int)1);

	in = inet_makeaddr(anet, INADDR_ANY);
	addr = in.s_addr;
	if (strlcpy(buf, inet_ntoa(in), buflen) >= buflen)
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
	char		addrstr[16];
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	if (nettoa((int)argp->key.netaddr.net, addrstr, 16) != 0)
		return ((nss_status_t)NSS_UNAVAIL);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETNETBYADDR, addrstr);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETNETBYADDR_SSD, addrstr);
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
		networks_attrs, _nss_ldap_networks2ent));
}
