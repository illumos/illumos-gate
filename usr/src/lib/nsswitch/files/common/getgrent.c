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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * files/getgrent.c -- "files" backend for nsswitch "group" database
 */

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

	while (linep < limit && *linep++ != ':') /* skip groupname */
		continue;
	while (linep < limit && *linep++ != ':') /* skip password */
		continue;
	if (linep == limit)
		return (GID_NOBODY);

	/* gid */
	end = linep;
	id = (uint_t)strtoul(linep, (char **)&end, 10);
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
	ulong_t		gr_gid;

	linep = line;
	limit = line + linelen;

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *line == '+' || *line == '-')
		return (0);

	while (linep < limit && *linep++ != ':') /* skip groupname */
		continue;
	while (linep < limit && *linep++ != ':') /* skip password */
		continue;
	if (linep == limit)
		return (0);

	/* gid */
	end = linep;
	gr_gid = strtoul(linep, (char **)&end, 10);

	/* check if gid is empty or overflows */
	if (linep == end || gr_gid > UINT32_MAX)
		return (0);

	return ((gid_t)gr_gid == argp->key.gid);
}

static nss_status_t
getbygid(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t *argp = (nss_XbyY_args_t *)a;

	if (argp->key.gid > MAXUID)
		return (NSS_NOTFOUND);
	return (_nss_files_XY_hash(be, argp, 0, &hashinfo, 1, check_grgid));
}

/*
 * Validates group entry replacing gid > MAXUID by GID_NOBODY.
 */
int
validate_group_ids(char *line, int *linelenp, int buflen, int extra_chars,
		files_XY_check_func check)
{
	char	*linep, *limit, *gidp;
	ulong_t	gid;
	int	oldgidlen, idlen;
	int	linelen = *linelenp, newlinelen;

	/*
	 * getbygid() rejects searching by ephemeral gid therefore
	 * no need to validate because the matched entry won't have
	 * an ephemeral gid.
	 */
	if (check != NULL && check == check_grgid)
		return (NSS_STR_PARSE_SUCCESS);

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *line == '+' || *line == '-')
		return (NSS_STR_PARSE_SUCCESS);

	linep = line;
	limit = line + linelen;

	while (linep < limit && *linep++ != ':') /* skip groupname */
		continue;
	while (linep < limit && *linep++ != ':') /* skip password */
		continue;
	if (linep == limit)
		return (NSS_STR_PARSE_PARSE);

	gidp = linep;
	gid = strtoul(gidp, (char **)&linep, 10); /* grab gid */
	oldgidlen = linep - gidp;
	if (linep >= limit || oldgidlen == 0)
		return (NSS_STR_PARSE_PARSE);

	if (gid <= MAXUID)
		return (NSS_STR_PARSE_SUCCESS);

	idlen = snprintf(NULL, 0, "%u", GID_NOBODY);
	newlinelen = linelen + idlen - oldgidlen;
	if (newlinelen + extra_chars > buflen)
		return (NSS_STR_PARSE_ERANGE);

	(void) bcopy(linep, gidp + idlen, limit - linep + extra_chars);
	(void) snprintf(gidp, idlen + 1, "%u", GID_NOBODY);
	*(gidp + idlen) = ':';
	*linelenp = newlinelen;
	return (NSS_STR_PARSE_SUCCESS);
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
