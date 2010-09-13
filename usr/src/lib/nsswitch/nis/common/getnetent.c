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
/*
 *	nis/getnetent.c -- "nis" backend for nsswitch "networks" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nis_common.h"
#include <synch.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

static int nettoa(int anet, char *buf, int buflen, char **pnull);

static nss_status_t
getbyname(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_nis_lookup(be, argp, 1, "networks.byname",
		argp->key.name, 0));
}

static nss_status_t
getbyaddr(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char			addrstr[16];
	char			*pnull;
	nss_status_t		rc;

	if (nettoa((int)argp->key.netaddr.net, addrstr, 16, &pnull) != 0)
		return (NSS_UNAVAIL);	/* it's really ENOMEM */
	rc = _nss_nis_lookup(be, argp, 1, "networks.byaddr", addrstr, 0);

	/*
	 * if not found, try again with the untruncated address string
	 * that has the trailing zero(s)
	 */
	if (rc == NSS_NOTFOUND && pnull != NULL) {
		*pnull = '.';
		rc = _nss_nis_lookup(be, argp, 1, "networks.byaddr",
			addrstr, 0);
	}
	return (rc);
}

static nis_backend_op_t net_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_netdb,
	getbyname,
	getbyaddr
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_networks_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(net_ops,
				sizeof (net_ops) / sizeof (net_ops[0]),
				"networks.byaddr"));
}

/*
 * Takes an unsigned integer in host order, and returns a printable
 * string for it as a network number.  To allow for the possibility of
 * naming subnets, only trailing dot-zeros are truncated. The location
 * where the string is truncated (or set to '\0') is returned in *pnull.
 */
static int
nettoa(int anet, char *buf, int buflen, char **pnull)
{
	char *p;
	struct in_addr in;
	int addr;

	*pnull = NULL;

	if (buf == 0)
		return (1);
	in = inet_makeaddr(anet, INADDR_ANY);
	addr = in.s_addr;
	(void) strncpy(buf, inet_ntoa(in), buflen);
	if ((IN_CLASSA_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return (1);
		*p = 0;
		*pnull = p;
	} else if ((IN_CLASSB_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return (1);
		p = strchr(p+1, '.');
		if (p == NULL)
			return (1);
		*p = 0;
		*pnull = p;
	} else if ((IN_CLASSC_HOST & htonl(addr)) == 0) {
		p = strrchr(buf, '.');
		if (p == NULL)
			return (1);
		*p = 0;
		*pnull = p;
	}
	return (0);
}
