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
#include "ldap_common.h"

/* netmasks attributes filters */
#define	_N_NETWORK	"ipnetworknumber"
#define	_N_NETMASK	"ipnetmasknumber"

#define	_F_GETMASKBYNET	"(&(objectClass=ipNetwork)(ipNetworkNumber=%s))"
#define	_F_GETMASKBYNET_SSD	"(&(%%s)(ipNetworkNumber=%s))"

static const char *netmasks_attrs[] = {
	_N_NETWORK,
	_N_NETMASK,
	(char *)NULL
};


/*
 * _nss_ldap_netmasks2str is the data marshaling method for the netmasks
 * getXbyY * (e.g., getnetmaskby[net|addr]()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 *
 * getnetmaskbykey set argp->buf.buffer to NULL and argp->buf.buflen to 0
 * and argp->buf.result to non-NULL.
 * The front end marshaller str2add expects "netmask" only
 *
 * e.g.
 *
 * 255.255.255.0
 *
 *
 */

static int
_nss_ldap_netmasks2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		nss_result, len;
	ns_ldap_result_t	*result = be->result;
	char		*buffer, **netmask;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	nss_result = NSS_STR_PARSE_SUCCESS;

	netmask = __ns_ldap_getAttr(result->entry, _N_NETMASK);
	if (netmask == NULL || netmask[0] == NULL ||
				(strlen(netmask[0]) < 1)) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_nmks2str;
	}
	/* Add a trailing null for debugging purpose */
	len = strlen(netmask[0]) + 1;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, len)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_nmks2str;
		}
		be->buflen = len - 1;
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;


	(void) snprintf(buffer, len, "%s", netmask[0]);

result_nmks2str:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}

/*
 * getbynet gets a network mask by address. This function constructs an
 * ldap search filter using the netmask name invocation parameter and the
 * getmaskbynet search filter defined. Once the filter is constructed, we
 * search for a matching entry and marshal the data results into struct
 * in_addr for the frontend process. The function _nss_ldap_netmasks2ent
 * performs the data marshaling.
 */

static nss_status_t
getbynet(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		netnumber[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(netnumber, argp->key.name, sizeof (netnumber))
			!= 0)
		return ((nss_status_t)NSS_NOTFOUND);
	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETMASKBYNET, netnumber);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETMASKBYNET_SSD, netnumber);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_NETMASKS, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}


static ldap_backend_op_t netmasks_ops[] = {
	_nss_ldap_destr,
	getbynet
};


/*
 * _nss_ldap_netmasks_constr is where life begins. This function calls
 * the generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_netmasks_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(netmasks_ops,
		sizeof (netmasks_ops)/sizeof (netmasks_ops[0]), _NETMASKS,
		netmasks_attrs, _nss_ldap_netmasks2str));
}
