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
 *	files/getservent.c -- "files" backend for nsswitch "services" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include "files_common.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <strings.h>

static int
check_name(args)
	nss_XbyY_args_t		*args;
{
	struct servent		*serv	= (struct servent *) args->returnval;
	const char		*name	= args->key.serv.serv.name;
	const char		*proto	= args->key.serv.proto;
	char			**aliasp;

	if (proto != 0 && strcmp(serv->s_proto, proto) != 0) {
		return (0);
	}
	if (strcmp(serv->s_name, name) == 0) {
		return (1);
	}
	for (aliasp = serv->s_aliases;  *aliasp != 0;  aliasp++) {
		if (strcmp(*aliasp, name) == 0) {
			return (1);
		}
	}
	return (0);
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;

	return (_nss_files_XY_all(be, argp, 1,
				argp->key.serv.serv.name, check_name));
}

static int
check_port(args)
	nss_XbyY_args_t		*args;
{
	struct servent		*serv	= (struct servent *) args->returnval;
	const char		*proto	= args->key.serv.proto;

	return (serv->s_port == args->key.serv.serv.port &&
		(proto == 0 || strcmp(serv->s_proto, proto) == 0));
}

static nss_status_t
getbyport(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *) a;
	char			portstr[12];

	sprintf(portstr, "%d", ntohs(argp->key.serv.serv.port));
	return (_nss_files_XY_all(be, argp, 1, portstr, check_port));
}

static files_backend_op_t serv_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyname,
	getbyport
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_services_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(serv_ops,
				sizeof (serv_ops) / sizeof (serv_ops[0]),
				_PATH_SERVICES,
				NSS_LINELEN_SERVICES,
				NULL));
}
