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
 *
 *	nis/gethostent.c -- "nis" backend for nsswitch "ipnodes" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "nis_common.h"
#include <stdlib.h>


static nss_status_t
getbyname(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t	res;

	const char		*s;
	char			c;

	for (s = argp->key.ipnode.name;  (c = *s) != '\0';  s++) {
		if (isupper(c)) {
			char		*copy;
			char		*mung;

			if ((copy = strdup(argp->key.ipnode.name)) == 0) {
				return (NSS_UNAVAIL);
			}
			for (mung = copy + (s - argp->key.ipnode.name);
			    (c = *mung) != '\0';  mung++) {
				if (isupper(c)) {
					*mung = _tolower(c);
				}
			}
			res = _nss_nis_lookup(be, argp, 1, "ipnodes.byname",
				copy, 0);
			if (res != NSS_SUCCESS)
				argp->h_errno = __nss2herrno(res);
			free(copy);
			return (res);
		}
	}
	res = _nss_nis_lookup(be, argp, 1,
				"ipnodes.byname", argp->key.ipnode.name, 0);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss2herrno(res);
	return (res);
}

static nss_status_t
getbyaddr(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *)a;
	struct in6_addr		addr;
	char			buf[INET6_ADDRSTRLEN + 1];
	nss_status_t	res;

	/* === Do we really want to be this pedantic? */
	if (argp->key.hostaddr.type != AF_INET6 ||
	    argp->key.hostaddr.len  != sizeof (addr)) {
		return (NSS_NOTFOUND);
	}
	(void) memcpy(&addr, argp->key.hostaddr.addr, sizeof (addr));
	if (IN6_IS_ADDR_V4MAPPED(&addr)) {
		if (inet_ntop(AF_INET, (void *) &addr.s6_addr[12],
				(void *)buf, INET_ADDRSTRLEN) == NULL) {
			return (NSS_NOTFOUND);
		}
	} else {
		if (inet_ntop(AF_INET6, (void *)&addr, (void *)buf,
						INET6_ADDRSTRLEN) == NULL)
			return (NSS_NOTFOUND);
	}

	res = _nss_nis_lookup(be, argp, 1, "ipnodes.byaddr", buf, 0);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss2herrno(res);
	return (res);
}


static nis_backend_op_t ipnodes_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_netdb,
	getbyname,
	getbyaddr
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_ipnodes_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(ipnodes_ops,
			sizeof (ipnodes_ops) / sizeof (ipnodes_ops[0]),
			"ipnodes.byaddr"));
}
