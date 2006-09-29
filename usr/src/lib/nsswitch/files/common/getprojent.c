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

#include <sys/types.h>
#include <project.h>
#include <string.h>
#include <stdlib.h>
#include "files_common.h"

static uint_t
hash_projname(nss_XbyY_args_t *argp, int keyhash, const char *line,
		int linelen) {

	const char	*name;
	int		namelen, i;
	uint_t		hash = 0;

	if (keyhash) {
		name = argp->key.name;
		namelen = strlen(name);
	} else {
		name = line;
		namelen = 0;
		while (linelen-- && *line++ != ':')
			namelen++;
	}

	for (i = 0; i < namelen; i++)
		hash = hash * 15 + name[i];
	return (hash);
}

static uint_t
hash_projid(nss_XbyY_args_t *argp, int keyhash, const char *line,
		int linelen) {

	uint_t		id;
	const char	*linep, *limit, *end;

	linep = line;
	limit = line + linelen;

	if (keyhash)
		return ((uint_t)argp->key.projid);

	/* skip projname */
	while (linep < limit && *linep++ != ':');
	if (linep == limit)
		return (0);

	/* projid */
	end = linep;
	id = (uint_t)strtol(linep, (char **)&end, 10);
	if (linep == end)
		return (0);

	return (id);
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
check_projid(nss_XbyY_args_t *argp, const char *line, int linelen) {
	projid_t	projid;
	const char	*linep, *limit, *end;

	linep = line;
	limit = line + linelen;

	/* skip projname */
	while (linep < limit && *linep++ != ':');

	/* empty projname not allowed */
	if (linep == limit || linep == line + 1)
		return (0);

	/* projid */
	end = linep;
	projid = (projid_t)strtol(linep, (char **)&end, 10);

	/* empty projid is not valid */
	if (linep == end)
		return (0);

	return (projid == argp->key.projid);
}

static nss_status_t
getbyname(files_backend_ptr_t be, void *a) {
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 0,
			_nss_files_check_name_colon));
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
