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

#include "files_common.h"
#include <sys/tsol/tndb.h>
#include <string.h>

/*
 *	files/tsol_gettpent.c --
 *           "files" backend for nsswitch "tnrhtp" database
 */
static int
check_name(nss_XbyY_args_t *args, const char *line, int linelen)
{
	const char	*limit, *linep, *keyp;

	linep = line;
	limit = line + linelen;
	keyp = args->key.name;

	/* compare template name, ':' is the seperator */
	while (*keyp && linep < limit && *linep != ':' && *keyp == *linep) {
		keyp++;
		linep++;
	}
	if (*keyp == '\0' && linep < limit && *linep == ':')
		return (1);

	return (0);
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	if (argp->key.name == NULL)
		return (NSS_NOTFOUND);

	return (_nss_files_XY_all(be, argp, 1, argp->key.name, check_name));
}

static files_backend_op_t tsol_tp_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyname
};
nss_backend_t *
/* LINTED E_FUNC_ARG_UNUSED */
_nss_files_tnrhtp_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(tsol_tp_ops,
				sizeof (tsol_tp_ops) / sizeof (tsol_tp_ops[0]),
				"/etc/security/tsol/tnrhtp",
				NSS_LINELEN_TSOL_TP,
				NULL));
}
