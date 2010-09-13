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

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "ldap_common.h"

/* ether attributes filters */
#define	_E_HOSTNAME		"cn"
#define	_E_MACADDRESS		"macaddress"
#define	_F_GETETHERBYHOST	"(&(objectClass=ieee802Device)(cn=%s))"
#define	_F_GETETHERBYHOST_SSD	"(&(%%s)(cn=%s))"
#define	_F_GETETHERBYETHER	"(&(objectClass=ieee802Device)(macAddress=%s))"
#define	_F_GETETHERBYETHER_SSD	"(&(%%s)(macAddress=%s))"

static const char *ethers_attrs[] = {
	_E_HOSTNAME,
	_E_MACADDRESS,
	(char *)NULL
};

/*
 * _nss_ldap_ethers2str is the data marshaling method for the ethers
 * ether_hostton/ether_ntohost backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 * e.g.
 *
 * 8:0:20:8e:eb:8a8 borealis
 *
 * The front end marshaller str2ether uses argp->buf.result for a different
 * purpose so a flag be->db_type is set to work around this oddity.
 *
 */
/*ARGSUSED0*/
static int
_nss_ldap_ethers2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			nss_result;
	ns_ldap_result_t	*result = be->result;
	char			**host, **macaddress;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	nss_result = NSS_STR_PARSE_SUCCESS;

	host = __ns_ldap_getAttr(result->entry, _E_HOSTNAME);
	if (host == NULL || host[0] == NULL || (strlen(host[0]) < 1)) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_ea2str;
	}
	macaddress = __ns_ldap_getAttr(result->entry, _E_MACADDRESS);
	if (macaddress == NULL || macaddress[0] == NULL ||
				(strlen(macaddress[0]) < 1)) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_ea2str;
	}
	be->buflen = strlen(host[0]) + strlen(macaddress[0]) + 1; /* ' ' */
	/* Add a trailing null for easy debug */
	be->buffer = calloc(1, be->buflen + 1);
	if (be->buffer == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_ea2str;
	}

	(void) snprintf(be->buffer, be->buflen + 1, "%s %s",
			macaddress[0], host[0]);
	be->db_type = NSS_LDAP_DB_ETHERS;

result_ea2str:

	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

/*
 * getbyhost gets an ethernet address by hostname. This function
 * constructs an ldap search filter using the hostname invocation
 * parameter and the getetherbyhost search filter defined. Once
 * the filter is constructed, we search for a matching entry and
 * marshal the data results into uchar_t *ether for the frontend
 * process. The function _nss_ldap_ethers2ent performs the data
 * marshaling.
 *
 * RFC 2307, An Approach for Using LDAP as a Network Information Service,
 * indicates that dn's be fully qualified. Host name searches will be on
 * fully qualified host names (e.g., foo.bar.sun.com).
 */

static nss_status_t
getbyhost(ldap_backend_ptr be, void *a)
{
	char		hostname[3 * MAXHOSTNAMELEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;
	nss_status_t	rc;

	if (_ldap_filter_name(hostname, argp->key.name, sizeof (hostname)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETETHERBYHOST, hostname);

	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETETHERBYHOST_SSD, hostname);

	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	rc = (nss_status_t)_nss_ldap_lookup(be, argp,
		_ETHERS, searchfilter, NULL,
		_merge_SSD_filter, userdata);

	return (rc);
}


/*
 * getbyether gets an ethernet address by ethernet address. This
 * function constructs an ldap search filter using the ASCII
 * ethernet address invocation parameter and the getetherbyether
 * search filter defined. Once the filter is constructed, we
 * search for a matching entry and  marshal the data results into
 * uchar_t *ether for the frontend process. The function
 * _nss_ldap_ethers2ent performs the data marshaling.
 */

static nss_status_t
getbyether(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		etherstr[18];
	uchar_t	*e = argp->key.ether;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	ret = snprintf(etherstr, sizeof (etherstr), "%x:%x:%x:%x:%x:%x",
	    *e, *(e + 1), *(e + 2), *(e + 3), *(e + 4), *(e + 5));
	if (ret >= sizeof (etherstr) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETETHERBYETHER, etherstr);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETETHERBYETHER_SSD, etherstr);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_ETHERS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


static ldap_backend_op_t ethers_ops[] = {
	_nss_ldap_destr,
	getbyhost,
	getbyether
};


/*
 * _nss_ldap_ethers_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_ethers_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(ethers_ops,
		sizeof (ethers_ops)/sizeof (ethers_ops[0]), _ETHERS,
		ethers_attrs, _nss_ldap_ethers2str));
}
