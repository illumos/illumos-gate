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

#include <stdio.h>
#include <project.h>
#include "nis_common.h"
#include <string.h>

static nss_status_t
getbyname(nis_backend_ptr_t be, void *a) {
	nss_XbyY_args_t *argp = (nss_XbyY_args_t *)a;
	return (_nss_nis_lookup(be, argp, 0, "project.byname",
	    argp->key.name, 0));
}

static nss_status_t
getbyid(nis_backend_ptr_t be, void *a) {
	char projstr[PROJNAME_MAX];
	nss_XbyY_args_t *argp = (nss_XbyY_args_t *)a;
	(void) snprintf(projstr, PROJNAME_MAX, "%ld", argp->key.projid);
	return (_nss_nis_lookup(be, argp, 0, "project.byprojid", projstr, 0));
}

static nis_backend_op_t project_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_rigid,
	getbyname,
	getbyid
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_project_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(project_ops,
	    sizeof (project_ops) / sizeof (project_ops[0]),
	    "project.byname"));
}
