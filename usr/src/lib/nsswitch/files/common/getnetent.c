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
 * files/getnetent.c -- "files" backend for nsswitch "networks" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "files_common.h"
#include <strings.h>
#include <ctype.h>

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void		*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_all(be, argp, 1, argp->key.name,
			_nss_files_check_name_aliases));
}

static int
check_addr(nss_XbyY_args_t *argp, const char *line, int linelen)
{

	const char	*limit, *linep, *addrstart;
	int		addrlen;
	char		addrbuf[NSS_LINELEN_NETWORKS];
	in_addr_t	linenet;

	linep = line;
	limit = line + linelen;

	/* skip network name */
	while (linep < limit && !isspace(*linep))
		linep++;
	/* skip the delimiting spaces */
	while (linep < limit && isspace(*linep))
		linep++;
	if (linep == limit)
		return (0);

	addrstart = linep;
	while (linep < limit && !isspace(*linep))
		linep++;
	addrlen = linep - addrstart;
	if (addrlen < sizeof (addrbuf)) {
		(void) memcpy(addrbuf, addrstart, addrlen);
		addrbuf[addrlen] = '\0';
		if ((linenet = inet_network(addrbuf)) ==
						(in_addr_t)0xffffffffU)
			return (0);
		return (AF_INET == argp->key.netaddr.type &&
			linenet == argp->key.netaddr.net);
	}
	return (0);
}

static nss_status_t
getbyaddr(be, a)
	files_backend_ptr_t	be;
	void		*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_all(be, argp, 1, 0, check_addr));
}

static files_backend_op_t net_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyname,
	getbyaddr
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_networks_constr(dummy1, dummy2, dummy3)
	const char  *dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(net_ops,
				sizeof (net_ops) / sizeof (net_ops[0]),
				_PATH_NETWORKS,
				NSS_LINELEN_NETWORKS,
				NULL));
}
