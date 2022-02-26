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
 * files/getpwnam.c -- "files" backend for nsswitch "passwd" database
 */

#include <pwd.h>
#include <shadow.h>
#include <unistd.h>		/* for PF_PATH */
#include "files_common.h"
#include <strings.h>
#include <stdlib.h>

static uint_t
hash_pwname(nss_XbyY_args_t *argp, int keyhash, const char *line,
	int linelen)
{
	const char	*name;
	int		namelen, i;
	uint_t 		hash = 0;

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
hash_pwuid(nss_XbyY_args_t *argp, int keyhash, const char *line,
	int linelen)
{
	uint_t		id;
	const char	*linep, *limit, *end;

	linep = line;
	limit = line + linelen;

	if (keyhash)
		return ((uint_t)argp->key.uid);

	while (linep < limit && *linep++ != ':') /* skip username */
		continue;
	while (linep < limit && *linep++ != ':') /* skip password */
		continue;
	if (linep == limit)
		return (UID_NOBODY);

	/* uid */
	end = linep;
	id = (uint_t)strtoul(linep, (char **)&end, 10);

	/* empty uid */
	if (linep == end)
		return (UID_NOBODY);

	return (id);
}

static files_hash_func hash_pw[2] = { hash_pwname, hash_pwuid };

static files_hash_t hashinfo = {
	DEFAULTMUTEX,
	sizeof (struct passwd),
	NSS_BUFLEN_PASSWD,
	2,
	hash_pw
};

static int
check_pwname(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*linep, *limit;
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
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 0, check_pwname));
}

static int
check_pwuid(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*linep, *limit, *end;
	ulong_t		pw_uid;

	linep = line;
	limit = line + linelen;

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *line == '+' || *line == '-')
		return (0);

	while (linep < limit && *linep++ != ':') /* skip username */
		continue;
	while (linep < limit && *linep++ != ':') /* skip password */
		continue;
	if (linep == limit)
		return (0);

	/* uid */
	end = linep;
	pw_uid = strtoul(linep, (char **)&end, 10);

	/* check if the uid is empty or overflows */
	if (linep == end || pw_uid > UINT32_MAX)
		return (0);

	return ((uid_t)pw_uid == argp->key.uid);
}

static nss_status_t
getbyuid(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t *argp = (nss_XbyY_args_t *)a;

	if (argp->key.uid > MAXUID)
		return (NSS_NOTFOUND);
	return (_nss_files_XY_hash(be, argp, 0, &hashinfo, 1, check_pwuid));
}

/*
 * Validates passwd entry replacing uid/gid > MAXUID by ID_NOBODY.
 */
int
validate_passwd_ids(char *line, int *linelenp, int buflen, int extra_chars)
{
	char	*linep, *limit, *uidp, *gidp;
	uid_t	uid;
	gid_t	gid;
	ulong_t	uidl, gidl;
	int	olduidlen, oldgidlen, idlen;
	int	linelen = *linelenp, newlinelen;

	/*
	 * +name entries in passwd(5) do not override uid and gid
	 * values. Therefore no need to validate the ids in these
	 * entries.
	 */
	if (linelen == 0 || *line == '+' || *line == '-')
		return (NSS_STR_PARSE_SUCCESS);

	linep = line;
	limit = line + linelen;

	while (linep < limit && *linep++ != ':') /* skip username */
		continue;
	while (linep < limit && *linep++ != ':') /* skip password */
		continue;
	if (linep == limit)
		return (NSS_STR_PARSE_PARSE);

	uidp = linep;
	uidl = strtoul(uidp, (char **)&linep, 10); /* grab uid */
	olduidlen = linep - uidp;
	if (++linep >= limit || olduidlen == 0)
		return (NSS_STR_PARSE_PARSE);

	gidp = linep;
	gidl = strtoul(gidp, (char **)&linep, 10); /* grab gid */
	oldgidlen = linep - gidp;
	if (linep >= limit || oldgidlen == 0)
		return (NSS_STR_PARSE_PARSE);

	if (uidl <= MAXUID && gidl <= MAXUID)
		return (NSS_STR_PARSE_SUCCESS);
	uid = (uidl > MAXUID) ? UID_NOBODY : (uid_t)uidl;
	gid = (gidl > MAXUID) ? GID_NOBODY : (gid_t)gidl;

	/* Check if we have enough space in the buffer */
	idlen = snprintf(NULL, 0, "%u:%u", uid, gid);
	newlinelen = linelen + idlen - olduidlen - oldgidlen - 1;
	if (newlinelen + extra_chars > buflen)
		return (NSS_STR_PARSE_ERANGE);

	/* Replace ephemeral ids by ID_NOBODY */
	(void) bcopy(linep, uidp + idlen, limit - linep + extra_chars);
	(void) snprintf(uidp, idlen + 1, "%u:%u", uid, gid);
	*(uidp + idlen) = ':'; /* restore : that was overwritten by snprintf */
	*linelenp = newlinelen;
	return (NSS_STR_PARSE_SUCCESS);
}

static files_backend_op_t passwd_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_rigid,
	getbyname,
	getbyuid
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_passwd_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(passwd_ops,
				sizeof (passwd_ops) / sizeof (passwd_ops[0]),
				PF_PATH,
				NSS_LINELEN_PASSWD,
				&hashinfo));
}
