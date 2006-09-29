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
 * files/getgrent.c -- "files" backend for nsswitch "group" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <grp.h>
#include <unistd.h>		/* for GF_PATH */
#include <stdlib.h>		/* for GF_PATH */
#include "files_common.h"
#include <strings.h>

static uint_t
hash_grname(nss_XbyY_args_t *argp, int keyhash, const char *line,
	int linelen)
{
	const char 	*name;
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
hash_grgid(nss_XbyY_args_t *argp, int keyhash, const char *line,
	int linelen)
{
	uint_t		id;
	const char	*linep, *limit, *end;

	linep = line;
	limit = line + linelen;

	if (keyhash)
		return ((uint_t)argp->key.gid);

	/* skip groupname */
	while (linep < limit && *linep++ != ':');
	/* skip password */
	while (linep < limit && *linep++ != ':');
	if (linep == limit)
		return (GID_NOBODY);

	/* gid */
	end = linep;
	id = (uint_t)strtol(linep, (char **)&end, 10);
	/* empty gid */
	if (linep == end)
		return (GID_NOBODY);

	return (id);
}

static files_hash_func hash_gr[2] = { hash_grname, hash_grgid };

static files_hash_t hashinfo = {
	DEFAULTMUTEX,
	sizeof (struct group),
	NSS_BUFLEN_GROUP,
	2,
	hash_gr
};

static int
check_grname(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char *linep, *limit;
	const char *keyp = argp->key.name;

	linep = line;
	limit = line + linelen;

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *line == '+' || *line == '-')
		return (0);
	while (*keyp && linep < limit && *keyp == *linep) {
		keyp++;
		linep++;
	}
	return (linep < limit && *keyp == '\0' && *linep == ':');
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 0, check_grname));
}

static int
check_grgid(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*linep, *limit, *end;
	gid_t		gr_gid;

	linep = line;
	limit = line + linelen;

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *line == '+' || *line == '-')
		return (0);

	/* skip username */
	while (linep < limit && *linep++ != ':');
	/* skip password */
	while (linep < limit && *linep++ != ':');
	if (linep == limit)
		return (0);

	/* uid */
	end = linep;
	gr_gid = (gid_t)strtol(linep, (char **)&end, 10);

	/* empty gid is not valid */
	if (linep == end)
		return (0);

	return (gr_gid == argp->key.gid);
}

static nss_status_t
getbygid(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 1, check_grgid));
}

static nss_status_t
getbymember(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	struct nss_groupsbymem	*argp = (struct nss_groupsbymem *)a;

	return (_nss_files_do_all(be, argp, argp->username,
				(files_do_all_func_t)argp->process_cstr));
}

static files_backend_op_t group_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_rigid,
	getbyname,
	getbygid,
	getbymember
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_group_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(group_ops,
				sizeof (group_ops) / sizeof (group_ops[0]),
				GF_PATH,
				NSS_LINELEN_GROUP,
				&hashinfo));
}
