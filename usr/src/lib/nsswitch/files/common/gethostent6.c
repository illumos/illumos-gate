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
 * files/gethostent6.c -- "files" backend for nsswitch "hosts" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include "files_common.h"
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <ctype.h>

extern nss_status_t __nss_files_XY_hostbyname();
extern int __nss_files_2herrno();
extern int __nss_files_check_addr(int, nss_XbyY_args_t *, const char *, int);

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t		res;

	res = __nss_files_XY_hostbyname(be, argp, argp->key.ipnode.name,
							AF_INET6);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss_files_2herrno(res);
	return (res);
}

static int
check_addr(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	return (__nss_files_check_addr(AF_INET6, argp, line, linelen));
}

static nss_status_t
getbyaddr(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *)a;
	nss_status_t		res;


	res = _nss_files_XY_all(be, argp, 1, 0, check_addr);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss_files_2herrno(res);
	return (res);
}

static files_backend_op_t ipnodes_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyname,
	getbyaddr,
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_ipnodes_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(ipnodes_ops,
				sizeof (ipnodes_ops) / sizeof (ipnodes_ops[0]),
				_PATH_IPNODES,
				NSS_LINELEN_HOSTS,
				NULL));
}
