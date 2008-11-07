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
 *	getgrent.c
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * lib/nsswitch/compat/getgrent.c -- name-service-switch backend for getgrnam()
 *   et al that does 4.x compatibility.  It looks in /etc/group; if it finds
 *   group entries there that begin with "+" or "-", it consults other
 *   services.  By default it uses NIS (YP), but the user can override this
 *   with a "group_compat" entry in /etc/nsswitch.conf, e.g.
 *			group_compat: nisplus
 *
 * This code tries to produce the same results as the 4.x code, even when
 *   the latter seems ill thought-out.  Bug-compatible, in other words.
 *   Though we do try to be more reasonable about the format of "+" and "-"
 *   entries here, i.e. you don't have to pad them with spurious colons and
 *   bogus uid/gid values.
 *
 * Caveats:
 *    -	More than one source may be specified, with the usual switch semantics,
 *	but having multiple sources here is definitely odd.
 *    -	People who recursively specify "compat" deserve what they get.
 */

#include <grp.h>
#include <stdlib.h>
#include <unistd.h>		/* for GF_PATH */
#include <strings.h>
#include "compat_common.h"

static DEFINE_NSS_DB_ROOT(db_root);

static void
_nss_initf_group_compat(p)
	nss_db_params_t	*p;
{
	p->name		  = NSS_DBNAM_GROUP;
	p->config_name	  = NSS_DBNAM_GROUP_COMPAT;
	p->default_config = NSS_DEFCONF_GROUP_COMPAT;
}

/*
 * Validates group entry replacing gid > MAXUID by GID_NOBODY.
 */
int
validate_group_ids(char *line, int *linelenp, int buflen, int extra_chars)
{
	char	*linep, *limit, *gidp;
	ulong_t	gid;
	int	oldgidlen, idlen;
	int	linelen = *linelenp, newlinelen;

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

static const char *
get_grname(argp)
	nss_XbyY_args_t		*argp;
{
	struct group		*g = (struct group *)argp->returnval;

	return (g->gr_name);
}

static int
check_grname(argp)
	nss_XbyY_args_t		*argp;
{
	struct group		*g = (struct group *)argp->returnval;

	return (strcmp(g->gr_name, argp->key.name) == 0);
}

static nss_status_t
getbyname(be, a)
	compat_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_compat_XY_all(be, argp, check_grname,
				NSS_DBOP_GROUP_BYNAME));
}

static int
check_grgid(argp)
	nss_XbyY_args_t		*argp;
{
	struct group		*g = (struct group *)argp->returnval;

	return (g->gr_gid == argp->key.gid);
}

static nss_status_t
getbygid(be, a)
	compat_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	if (argp->key.gid > MAXUID)
		return (NSS_NOTFOUND);
	return (_nss_compat_XY_all(be, argp, check_grgid,
				NSS_DBOP_GROUP_BYGID));
}

static nss_status_t
getbymember(be, a)
	compat_backend_ptr_t	be;
	void			*a;
{
	struct nss_groupsbymem	*argp = (struct nss_groupsbymem *)a;
	int			numgids = argp->numgids;
	int			maxgids = argp->maxgids;
	gid_t			*gid_array = argp->gid_array;
	struct nss_XbyY_args	grargs;
	struct group		*g;
	nss_XbyY_buf_t	*gb = NULL, *b = NULL;

	/*
	 * Generic implementation:  enumerate using getent(), then check each
	 *   group returned by getent() to see whether it contains the user.
	 *   There are much faster ways, but at least this one gets the right
	 *   answer.
	 */
	if (numgids >= maxgids) {
		/* full gid_array;  nobody should have bothered to call us */
		return (NSS_SUCCESS);
	}

	b = NSS_XbyY_ALLOC(&gb, sizeof (struct group), NSS_BUFLEN_GROUP);
	if (b == 0)
		return (NSS_UNAVAIL);

	NSS_XbyY_INIT(&grargs, gb->result, gb->buffer, gb->buflen,
		argp->str2ent);
	g = (struct group *)gb->result;

	(void) _nss_compat_setent(be, 0);
	while (_nss_compat_getent(be, &grargs) == NSS_SUCCESS) {
		char		**mem;

		if (grargs.returnval == 0) {
			continue;
		}
		for (mem = g->gr_mem;  *mem != 0;  mem++) {
			if (strcmp(*mem, argp->username) == 0) {
				int	gid = g->gr_gid;
				int	i;
				for (i = 0;  i < numgids;  i++) {
					if (gid == gid_array[i]) {
						break;
					}
				}
				if (i == numgids) {
					gid_array[numgids++] = gid;
					argp->numgids = numgids;
					if (numgids >= maxgids) {
						/* filled the gid_array */
						(void) _nss_compat_endent(be,
								0);
						NSS_XbyY_FREE(&gb);
						return (NSS_SUCCESS);
					}
					/* Done with this group, try next */
					break;
				}
			}
		}
	}
	(void) _nss_compat_endent(be, 0);
	NSS_XbyY_FREE(&gb);
	return (NSS_NOTFOUND);	/* Really means "gid_array not full yet" */
}

/*ARGSUSED*/
static int
merge_grents(be, argp, fields)
	compat_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
	const char		**fields;
{
	struct group		*g	= (struct group *)argp->buf.result;
	char			*buf;
	char			*s;
	int			parsestat;
	int			dlen;

	/*
	 * We're allowed to override the passwd (has anyone ever actually used
	 *   the passwd in a group entry?) and the membership list, but not
	 *   the groupname or the gid.
	 * That's what the SunOS 4.x code did;  who are we to question it...
	 *
	 * Efficiency is heartlessly abandoned in the quest for simplicity.
	 */
	if (fields[1] == 0 && fields[3] == 0 &&
			be->return_string_data != 1) {
		/* No legal overrides, leave *argp unscathed */
		return (NSS_STR_PARSE_SUCCESS);
	}
	if ((buf = malloc(NSS_LINELEN_GROUP)) == 0) {
		return (NSS_STR_PARSE_PARSE);
		/* Really "out of memory", but PARSE_PARSE will have to do */
	}
	s = buf;
	(void) snprintf(s, NSS_LINELEN_GROUP, "%s:%s:%u:",
		g->gr_name,
		fields[1] != 0 ? fields[1] : g->gr_passwd,
		g->gr_gid);
	s += strlen(s);
	if (fields[3] != 0) {
		(void) strcpy(s, fields[3]);
		s += strlen(s);
	} else {
		char	**memp;

		for (memp = g->gr_mem;  *memp != 0;  memp++) {
			size_t	len = strlen(*memp);
			if (s + len + 1 <= buf + NSS_LINELEN_GROUP) {
				if (memp != g->gr_mem) {
					*s++ = ',';
				}
				(void) memcpy(s, *memp, len);
				s += len;
			} else {
				free(buf);
				return (NSS_STR_PARSE_ERANGE);
			}
		}
	}

	dlen = s - buf;

	/*
	 * if asked, return the data in /etc file format
	 */
	if (be->return_string_data == 1) {
		/* reset the result ptr to the original value */
		argp->buf.result = NULL;

		if (dlen > argp->buf.buflen) {
			parsestat = NSS_STR_PARSE_ERANGE;
		} else {
			(void) strncpy(argp->buf.buffer, buf, dlen);
			argp->returnval = argp->buf.buffer;
			argp->returnlen = dlen;
			parsestat = NSS_SUCCESS;
		}
	} else {
		parsestat = (*argp->str2ent)(buf, dlen,
				    argp->buf.result,
				    argp->buf.buffer,
				    argp->buf.buflen);
	}

	free(buf);
	return (parsestat);
}

static compat_backend_op_t group_ops[] = {
	_nss_compat_destr,
	_nss_compat_endent,
	_nss_compat_setent,
	_nss_compat_getent,
	getbyname,
	getbygid,
	getbymember
};

/*ARGSUSED*/
nss_backend_t *
_nss_compat_group_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_compat_constr(group_ops,
				sizeof (group_ops) / sizeof (group_ops[0]),
				GF_PATH,
				NSS_LINELEN_GROUP,
				&db_root,
				_nss_initf_group_compat,
				0,
				get_grname,
				merge_grents));
}
