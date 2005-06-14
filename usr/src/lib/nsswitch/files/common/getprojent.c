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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <project.h>
#include <string.h>
#include "files_common.h"

static uint_t
hash_projname(nss_XbyY_args_t *argp, int keyhash) {
	struct project *p = argp->returnval;
	const char *name = keyhash ? argp->key.name : p->pj_name;
	uint_t hash = 0;

	while (*name != 0)
		hash = hash * 15 + *name++;

	return (hash);
}

static uint_t
hash_projid(nss_XbyY_args_t *argp, int keyhash) {
	struct project *p = argp->returnval;
	return (keyhash ? (uint_t)argp->key.projid : (uint_t)p->pj_projid);
}

static files_hash_func hash_proj[2] = {
	hash_projname,
	hash_projid
};

static files_hash_t hashinfo = {
	DEFAULTMUTEX,
	sizeof (struct project),
	NSS_BUFLEN_PROJECT,
	2,
	hash_proj
};

static int
check_projname(nss_XbyY_args_t *argp) {
	struct project *p = argp->returnval;

	if (p->pj_name == 0)
		return (0);
	return (strcmp(p->pj_name, argp->key.name) == 0);
}

static int
check_projid(nss_XbyY_args_t *argp) {
	struct project *p = argp->returnval;

	if (p->pj_name == 0)
		return (0);
	return (p->pj_projid == argp->key.projid);
}

static nss_status_t
getbyname(files_backend_ptr_t be, void *a) {
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 0, check_projname));
}

static nss_status_t
getbyprojid(files_backend_ptr_t be, void *a) {
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 1, check_projid));
}

static files_backend_op_t project_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_rigid,
	getbyname,
	getbyprojid
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_project_constr(dummy1, dummy2, dummy3)
	const char *dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(project_ops,
		    sizeof (project_ops) / sizeof (project_ops[0]),
		    PROJF_PATH,
		    NSS_LINELEN_PROJECT,
		    &hashinfo));
}
