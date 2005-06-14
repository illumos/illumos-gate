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
 * _nss_ldap_netmasks2ent is the data marshaling method for the netmasks
 * getXbyY * (e.g., getbynet()) backend processes. This method is called
 * after a successful ldap search has been performed. This method will
 * parse the ldap search values into struct in_addr *mask = argp->buf.result
 * only if argp->buf.result is initialized (not NULL). Three error
 * conditions are expected and returned to nsswitch.
 */

static int
_nss_ldap_netmasks2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		i, j;
	int		nss_result;
	unsigned long	len = 0L;
#ifdef DEBUG
	char		maskstr[16];
#endif /* DEBUG */
	struct in_addr	addr;
	struct in_addr	*mask = (struct in_addr *)NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_attr_t	*attrptr;

	mask = (struct in_addr *)argp->buf.result;
	nss_result = (int)NSS_STR_PARSE_SUCCESS;

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_nmks2ent;
	}

	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_nmks2ent;
		}
		if (strcasecmp(attrptr->attrname, _N_NETMASK) == 0) {
			for (j = 0;  j < attrptr->value_count; j++) {
				if (mask == NULL)
					continue;
				if ((attrptr->attrvalue[j] == NULL) ||
				    (len = strlen(attrptr->attrvalue[j])) < 1) {
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_nmks2ent;
				}
				/* addr a IPv4 address and 32 bits */
				addr.s_addr = inet_addr(attrptr->attrvalue[j]);
				if (addr.s_addr == 0xffffffffUL) {
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_nmks2ent;
				}
				mask->s_addr = addr.s_addr;
#ifdef DEBUG
				strlcpy(maskstr, attrptr->attrvalue[j],
							sizeof (maskstr));
#endif /* DEBUG */
				continue;
			}
		}
	}

#ifdef DEBUG
	(void) fprintf(stdout, "\n[netmasks.c: _nss_ldap_netmasks2ent]\n");
	(void) fprintf(stdout, "       netmask: [%s]\n", maskstr);
#endif /* DEBUG */

result_nmks2ent:

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
		netmasks_attrs, _nss_ldap_netmasks2ent));
}
