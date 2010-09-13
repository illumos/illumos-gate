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
 * files/getprotoent.c -- "files" backend for nsswitch "protocols" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include "files_common.h"
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>

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
	int		proto;
	const char	*limit, *linep;

	linep = line;
	limit = line + linelen;

	/* skip name */
	while (linep < limit && !isspace(*linep))
		linep++;
	/* skip the delimiting spaces */
	while (linep < limit && isspace(*linep))
		linep++;
	if (linep == limit)
		return (0);
	proto = (int)strtol(linep, NULL, 10);
	return (proto == argp->key.number);
}

static nss_status_t
getbynumber(be, a)
	files_backend_ptr_t	be;
	void		*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char		numstr[12];

	(void) snprintf(numstr, 12, "%d", argp->key.number);
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
