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
 *	nis/getpwnam.c -- "nis" backend for nsswitch "passwd" database
 */

#include <pwd.h>
#include "nis_common.h"

static nss_status_t
getbyname(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_nis_lookup(be, argp, 0,
				"passwd.byname", argp->key.name, 0));
}

static nss_status_t
getbyuid(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char			uidstr[12];	/* More than enough */

	if (argp->key.uid > MAXUID)
		return (NSS_NOTFOUND);
	(void) snprintf(uidstr, 12, "%u", argp->key.uid);
	return (_nss_nis_lookup(be, argp, 0, "passwd.byuid", uidstr, 0));
}

/*
 * Validates passwd entry replacing uid/gid > MAXUID by ID_NOBODY.
 */
int
validate_passwd_ids(char **linepp, int *linelenp, int allocbuf)
{
	char	*linep, *limit, *uidp, *gidp, *newline;
	uid_t	uid;
	gid_t	gid;
	ulong_t	uidl, gidl;
	int	olduidlen, oldgidlen, idlen;
	int	linelen = *linelenp, newlinelen;

	linep = *linepp;
	limit = linep + linelen;

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *linep == '+' || *linep == '-')
		return (NSS_STR_PARSE_SUCCESS);

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
	if (newlinelen > linelen) {
		/* need a larger buffer */
		if (!allocbuf || (newline = malloc(newlinelen + 1)) == NULL)
			return (NSS_STR_PARSE_ERANGE);
		/* Replace ephemeral ids by ID_NOBODY in the new buffer */
		*(uidp - 1) = '\0';
		(void) snprintf(newline, newlinelen + 1, "%s:%u:%u%s",
		    *linepp, uid, gid, linep);
		free(*linepp);
		*linepp = newline;
		*linelenp = newlinelen;
		return (NSS_STR_PARSE_SUCCESS);
	}

	/* Replace ephemeral ids by ID_NOBODY in the same buffer */
	(void) bcopy(linep, uidp + idlen, limit - linep + 1);
	(void) snprintf(uidp, idlen + 1, "%u:%u", uid, gid);
	*(uidp + idlen) = ':'; /* restore : that was overwritten by snprintf */
	*linelenp = newlinelen;
	return (NSS_STR_PARSE_SUCCESS);
}

static nis_backend_op_t passwd_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_rigid,
	getbyname,
	getbyuid
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_passwd_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, dummy3;
{
	return (_nss_nis_constr(passwd_ops,
				sizeof (passwd_ops) / sizeof (passwd_ops[0]),
				"passwd.byname"));
}
