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
 *	files/getgrent.c -- "files" backend for nsswitch "group" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <grp.h>
#include <unistd.h>		/* for GF_PATH */
#include "files_common.h"
#include <strings.h>

static u_int
hash_grname(nss_XbyY_args_t *argp, int keyhash)
{
	struct group *g = argp->returnval;
	const char *name = keyhash ? argp->key.name : g->gr_name;
	u_int hash = 0;

	while (*name != 0)
		hash = hash * 15 + *name++;

	return (hash);
}

static u_int
hash_grgid(nss_XbyY_args_t *argp, int keyhash)
{
	struct group *g = argp->returnval;
	return (keyhash ? (u_int)argp->key.gid : (u_int)g->gr_gid);
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
check_grname(argp)
	nss_XbyY_args_t		*argp;
{
	struct group		*g = (struct group *)argp->returnval;

	/* +/- entries only valid in compat source */
	if (g->gr_name != 0 && (g->gr_name[0] == '+' || g->gr_name[0] == '-'))
		return (0);
	return (strcmp(g->gr_name, argp->key.name) == 0);
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 0, check_grname));
}

static int
check_grgid(argp)
	nss_XbyY_args_t		*argp;
{
	struct group		*g = (struct group *)argp->returnval;

	/* +/- entries only valid in compat source */
	if (g->gr_name != 0 && (g->gr_name[0] == '+' || g->gr_name[0] == '-'))
		return (0);
	return (g->gr_gid == argp->key.gid);
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
	struct nss_groupsbymem	*argp = (struct nss_groupsbymem *) a;

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
