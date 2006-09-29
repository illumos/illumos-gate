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
 *	files/printers_getbyname.c -- "files" backend for
 *	nsswitch "printers" database.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

static const char *printers = "/etc/printers.conf";

#pragma weak _nss_files__printers_constr = _nss_files_printers_constr

#include "files_common.h"
#include <stdlib.h>
#include <strings.h>

static int
check_name(nss_XbyY_args_t *argp, const char *line, int linelen)
{

	const char	*limit, *linep;
	const char	*keyp = argp->key.name;
	int		klen = strlen(keyp);

	linep = line;
	limit = line + linelen;

	/*
	 * find the name in the namelist a|b|c...:
	 */
	while (linep+klen < limit && *linep != '|' && *linep != ':') {
		if ((strncmp(linep, keyp, klen) == 0) &&
		    ((*(linep + klen) == '|') || (*(linep + klen) == ':'))) {
			return (1);
		} else {
			while (linep < limit && *linep != '|' && *linep != ':')
				linep++;
			if (linep >= limit || *linep == ':')
				return (0);
			if (*linep == '|')
				linep++;
		}
	}
	return (0);
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_all(be, argp, 1, argp->key.name,
			check_name));
}

static files_backend_op_t printers_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_rigid,
	getbyname
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_printers_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(printers_ops,
			sizeof (printers_ops) / sizeof (printers_ops[0]),
			printers,
			NSS_LINELEN_PRINTERS,
			NULL));
}
