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
 *	Copyright (c) 1988-1995 Sun Microsystems Inc
 *	All Rights Reserved.
 *
 *	files/getprotoent.c -- "files" backend for nsswitch "protocols" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include "files_common.h"
#include <strings.h>

static int
check_name(args)
	nss_XbyY_args_t	*args;
{
	struct protoent	*proto = (struct protoent *)args->returnval;
	const char		*name = args->key.name;
	char			**aliasp;

	if (strcmp(proto->p_name, name) == 0)
		return (1);
	for (aliasp = proto->p_aliases; *aliasp != 0; aliasp++) {
		if (strcmp(*aliasp, name) == 0)
			return (1);
	}
	return (0);
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void		*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;

	return (_nss_files_XY_all(be, argp, 1, argp->key.name, check_name));
}

static int
check_addr(args)
	nss_XbyY_args_t	*args;
{
	struct protoent	*proto = (struct protoent *)args->returnval;

	return (proto->p_proto == args->key.number);
}

static nss_status_t
getbynumber(be, a)
	files_backend_ptr_t	be;
	void		*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;
	char		numstr[12];

	sprintf(numstr, "%d", argp->key.number);
	return (_nss_files_XY_all(be, argp, 1, 0, check_addr));
}

static files_backend_op_t proto_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyname,
	getbynumber
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_protocols_constr(dummy1, dummy2, dummy3)
	const char  *dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(proto_ops,
				sizeof (proto_ops) / sizeof (proto_ops[0]),
				_PATH_PROTOCOLS,
				NSS_LINELEN_PROTOCOLS,
				NULL));
}
