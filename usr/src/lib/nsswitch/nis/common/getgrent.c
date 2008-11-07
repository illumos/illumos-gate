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
 */

/*
 * nis/getgrent.c -- "nis" backend for nsswitch "group" database
 */

#include <grp.h>
#include <pwd.h>
#include "nis_common.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/auth.h>	/* for MAXNETNAMELEN */

static nss_status_t netid_lookup(struct nss_groupsbymem *argp);

static nss_status_t
getbyname(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_nis_lookup(be, argp, 0,
				"group.byname", argp->key.name, 0));
}

static nss_status_t
getbygid(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char			gidstr[12];	/* More than enough */

	if (argp->key.gid > MAXUID)
		return (NSS_NOTFOUND);
	(void) snprintf(gidstr, 12, "%d", argp->key.gid);
	return (_nss_nis_lookup(be, argp, 0, "group.bygid", gidstr, 0));
}

/*
 * Validates group entry replacing gid > MAXUID by GID_NOBODY.
 */
int
validate_group_ids(char **linepp, int *linelenp, int allocbuf)
{
	char	*linep, *limit, *gidp, *newline;
	ulong_t	gid;
	int	oldgidlen, idlen;
	int	linelen = *linelenp, newlinelen;

	linep = *linepp;
	limit = linep + linelen;

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *linep == '+' || *linep == '-')
		return (NSS_STR_PARSE_SUCCESS);

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
	if (newlinelen > linelen) {
		/* need a larger buffer */
		if (!allocbuf || (newline = malloc(newlinelen + 1)) == NULL)
			return (NSS_STR_PARSE_ERANGE);
		/* Replace ephemeral ids by ID_NOBODY in the new buffer */
		*(gidp - 1) = '\0';
		(void) snprintf(newline, newlinelen + 1, "%s:%u%s",
		    *linepp, GID_NOBODY, linep);
		free(*linepp);
		*linepp = newline;
		*linelenp = newlinelen;
		return (NSS_STR_PARSE_SUCCESS);
	}

	/* Replace ephemeral gid by GID_NOBODY in the same buffer */
	(void) bcopy(linep, gidp + idlen, limit - linep + 1);
	(void) snprintf(gidp, idlen + 1, "%u", GID_NOBODY);
	*(gidp + idlen) = ':';
	*linelenp = newlinelen;
	return (NSS_STR_PARSE_SUCCESS);
}

static nss_status_t
getbymember(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	struct nss_groupsbymem	*argp = (struct nss_groupsbymem *)a;

	if (strcmp(argp->username, "root") == 0) {
		/*
		 * Assume that "root" can only sensibly be in /etc/group,
		 *   not in NIS or NIS+
		 * If we don't do this, a hung name-service may cause
		 *   a root login or su to hang.
		 */
		return (NSS_NOTFOUND);
	}

	if (argp->force_slow_way != 1) {
		switch (netid_lookup(argp)) {
		case NSS_SUCCESS:
			/*
			 * Return SUCESS only if array is full. Explained
			 * in <nss_dbdefs.h>.
			 */
			return ((argp->numgids == argp->maxgids)
			    ? NSS_SUCCESS
			    : NSS_NOTFOUND);
		case NSS_NOTFOUND:
		case NSS_UNAVAIL:
			/*
			 * Failover to group map search if no luck with netid.
			 */
			break;
		case NSS_TRYAGAIN:
			return (NSS_TRYAGAIN);
		}
	}

	return (_nss_nis_do_all(be, argp, argp->username,
				(nis_do_all_func_t)argp->process_cstr));
}

static nis_backend_op_t group_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_rigid,
	getbyname,
	getbygid,
	getbymember
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_group_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(group_ops,
				sizeof (group_ops) / sizeof (group_ops[0]),
				"group.byname"));
}

/*
 * Add gid to gid_array if it's not already there. gid_array must have room
 * for one more entry.  Return new size of array.
 */
static int
add_gid(gid_t gid_array[], int numgids, gid_t gid)
{
	int i = 0;

	for (i = 0; i < numgids; i++) {
		if (gid_array[i] == gid) {
			return (numgids);
		}
	}
	gid_array[numgids++] = gid;
	return (numgids);
}

/*
 * Given buf, a null-terminated string containing the result of a successful
 * netid lookup, add the gids to the gid_array.  The string may contain extra
 * whitesapce.  On parse error, the valid portion of the gid_array is not
 * modified.
 */
static int
parse_netid(const char *buf, gid_t gid_array[], int maxgids, int *numgids_ptr)
{
	int	numgids = *numgids_ptr;
	char	*buf_next;
	gid_t	gid;
	long	value;

	/* Scan past "<uid>:" */
	while (isspace(*buf) || isdigit(*buf)) {
		buf++;
	}

	if (*buf++ != ':') {
		return (NSS_STR_PARSE_PARSE);
	}

	/* buf should now point to a comma-separated list of gids */
	while (*buf != '\0' && *buf != '\n') {
		errno = 0;
		value = strtol(buf, &buf_next, 10);

		if (buf == buf_next) {
			return (NSS_STR_PARSE_PARSE);
		} else if ((value == LONG_MAX && errno == ERANGE) ||
		    (ulong_t)value > INT_MAX) {
			return (NSS_STR_PARSE_ERANGE);
		}

		gid = (gid_t)value;
		if (numgids < maxgids) {
			numgids = add_gid(gid_array, numgids, gid);
		}
		buf = buf_next;
		if (*buf == ',') {
			buf++;
		}
	}
	*numgids_ptr = numgids;
	return (NSS_STR_PARSE_SUCCESS);
}


/*
 * Perform a lookup in the netid map.  Fill in the gid_array if successful.
 * Return values are like those for _nss_nis_lookup().
 */
static nss_status_t
netid_lookup(struct nss_groupsbymem *argp)
{
	const char	*domain = _nss_nis_domain();
	struct passwd	pw;
	char		pwbuf[NSS_BUFLEN_PASSWD];
	char		netname[MAXNETNAMELEN + 1];
	nss_status_t	res;
	char		*val;
	int		vallen;
	int		parse_res;
	char		*lasts;

	/*
	 * Need to build up the netname for the user manually. Can't use
	 * user2netname() rpc library call, since that does all sorts of
	 * extra stuff based upon its own private name-service switch.
	 *
	 * Note that "root" has no user netname so return in error.
	 */
	if ((getpwnam_r(argp->username, &pw, pwbuf, sizeof (pwbuf)) == NULL) ||
	    (pw.pw_uid == 0)) {
		return (NSS_UNAVAIL);
	}
	if (snprintf(netname, MAXNETNAMELEN + 1, "unix.%d@%s",
	    pw.pw_uid, domain) < 0) {
		return (NSS_UNAVAIL);
	}

	if ((res = _nss_nis_ypmatch(domain, "netid.byname", netname,
	    &val, &vallen, 0)) != NSS_SUCCESS) {
		return (res);
	}

	(void) strtok_r(val, "#", &lasts);

	parse_res = parse_netid(val, argp->gid_array, argp->maxgids,
	    &argp->numgids);
	free(val);
	return ((parse_res == NSS_STR_PARSE_SUCCESS)
	    ? NSS_SUCCESS : NSS_NOTFOUND);
}
