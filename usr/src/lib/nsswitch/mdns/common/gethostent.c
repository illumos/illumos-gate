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

#include "mdns_common.h"

/*
 * gethostby* functions for the hosts database. The hosts
 * database stores IPv4 addresses only.
 * mDNS query functions to perform the host lookup
 * are in mdns/common/mdns_common.c file.
 * _nss_mdns_hosts_constr is called to initialize
 * the nsswitch backend data structures.
 */

static nss_status_t
getbyname(be, a)
	mdns_backend_ptr_t	be;
	void			*a;
{
	struct mdns_querydata   qdata;
	char			*hname;

	(void) memset(&qdata, 0, sizeof (struct mdns_querydata));

	qdata.argp = (nss_XbyY_args_t *)a;
	hname = (char *)qdata.argp->key.name;

	_nss_mdns_updatecfg(be);
	return (_nss_mdns_querybyname(be, hname, AF_INET, &qdata));
}

/*ARGSUSED*/
static nss_status_t
getbyaddr(be, a)
	mdns_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t *argp = (nss_XbyY_args_t *)a;
	struct in_addr addr;
	struct mdns_querydata  qdata;
	char buffer[sizeof ("255.255.255.255.in-addr.arpa.")];
	uint8_t *p;

	(void) memset(&qdata, 0, sizeof (struct mdns_querydata));
	qdata.argp = argp;

	argp->h_errno = 0;
	if ((argp->key.hostaddr.type != AF_INET) ||
	    (argp->key.hostaddr.len != sizeof (addr)))
		return (NSS_NOTFOUND);

	(void) memcpy(&addr, argp->key.hostaddr.addr, sizeof (addr));

	if (inet_ntop(AF_INET, (void *) &addr.s_addr,
		(void *)qdata.paddrbuf,
		sizeof (qdata.paddrbuf)) == NULL)
			return (NSS_NOTFOUND);

	qdata.af = AF_INET;
	p = (uint8_t *)&addr.s_addr;
	(void) snprintf(buffer, sizeof (buffer),
		"%u.%u.%u.%u.in-addr.arpa.", p[3], p[2], p[1], p[0]);

	_nss_mdns_updatecfg(be);
	return (_nss_mdns_querybyaddr(be, buffer, qdata.af, &qdata));
}

/*ARGSUSED*/
static nss_status_t
_nss_mdns_getent(be, args)
	mdns_backend_ptr_t	be;
	void			*args;
{
	return (NSS_UNAVAIL);
}

/*ARGSUSED*/
static nss_status_t
_nss_mdns_setent(be, dummy)
	mdns_backend_ptr_t	be;
	void			*dummy;
{
	return (NSS_UNAVAIL);
}

/*ARGSUSED*/
static nss_status_t
_nss_mdns_endent(be, dummy)
	mdns_backend_ptr_t	be;
	void			*dummy;
{
	return (NSS_UNAVAIL);
}

/*ARGSUSED*/
static nss_status_t
_nss_mdns_hosts_destr(be, dummy)
	mdns_backend_ptr_t	be;
	void			*dummy;
{
	_nss_mdns_destr(be);
	return (NSS_SUCCESS);
}

static mdns_backend_op_t host_ops[] = {
	_nss_mdns_hosts_destr,
	_nss_mdns_endent,
	_nss_mdns_setent,
	_nss_mdns_getent,
	getbyname,
	getbyaddr,
};

/*ARGSUSED*/
nss_backend_t *
_nss_mdns_hosts_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_mdns_constr(host_ops,
		sizeof (host_ops) / sizeof (host_ops[0])));
}

/*ARGSUSED*/
nss_status_t
_nss_get_mdns_hosts_name(mdns_backend_ptr_t *be, void **bufp, size_t *sizep)
{
	return (_nss_mdns_gethost_withttl(*bufp, *sizep, 0));
}
