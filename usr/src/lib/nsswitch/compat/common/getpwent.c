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
 *	getpwent.c
 *
 * lib/nsswitch/compat/getpwent.c -- name-service-switch backend for getpwnam()
 *   et al that does 4.x compatibility.  It looks in /etc/passwd; if it finds
 *   passwd entries there that begin with "+" or "-", it consults other
 *   services.  By default it uses NIS (YP), but the user can override this
 *   with a "passwd_compat" entry in /etc/nsswitch.conf, e.g.
 *			passwd_compat: nisplus
 *
 * This code tries to produce the same results as the 4.x code, even when
 *   the latter seems ill thought-out (mostly in the handling of netgroups,
 *   "-", and the combination thereof).  Bug-compatible, in other words.
 *   Though we do try to be more reasonable about the format of "+" and "-"
 *   entries here, i.e. you don't have to pad them with spurious colons and
 *   bogus uid/gid values.
 *
 * Caveats:
 *    -	More than one source may be specified, with the usual switch semantics,
 *	but having multiple sources here is definitely odd.
 *    -	People who recursively specify "compat" deserve what they get.
 *    -	Entries that begin with "+@" or "-@" are interpreted using
 *	getnetgrent() and innetgr(), which use the "netgroup" entry in
 *	/etc/nsswitch.conf.  If the sources for "passwd_compat" and "netgroup"
 *	differ, everything should work fine, but the semantics will be pretty
 *	confusing.
 */

#include <pwd.h>
#include <shadow.h>		/* For PASSWD (pathname to passwd file) */
#include <stdlib.h>
#include <strings.h>
#include "compat_common.h"

static DEFINE_NSS_DB_ROOT(db_root);

static void
_nss_initf_passwd_compat(p)
	nss_db_params_t	*p;
{
	p->name		  = NSS_DBNAM_PASSWD;
	p->config_name	  = NSS_DBNAM_PASSWD_COMPAT;
	p->default_config = NSS_DEFCONF_PASSWD_COMPAT;
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

static const char *
get_pwname(argp)
	nss_XbyY_args_t		*argp;
{
	struct passwd		*p = (struct passwd *)argp->returnval;

	return (p->pw_name);
}

static int
check_pwname(argp)
	nss_XbyY_args_t		*argp;
{
	struct passwd		*p = (struct passwd *)argp->returnval;

	return (strcmp(p->pw_name, argp->key.name) == 0);
}

static nss_status_t
getbyname(be, a)
	compat_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_compat_XY_all(be, argp,
				check_pwname, NSS_DBOP_PASSWD_BYNAME));
}

static int
check_pwuid(argp)
	nss_XbyY_args_t		*argp;
{
	struct passwd		*p = (struct passwd *)argp->returnval;

	return (p->pw_uid == argp->key.uid);
}

static nss_status_t
getbyuid(be, a)
	compat_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	if (argp->key.uid > MAXUID)
		return (NSS_NOTFOUND);
	return (_nss_compat_XY_all(be, argp,
				check_pwuid, NSS_DBOP_PASSWD_BYUID));
}

/*ARGSUSED*/
static int
merge_pwents(be, argp, fields)
	compat_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
	const char		**fields;
{
	struct passwd		*pw	= (struct passwd *)argp->buf.result;
	char			*buf	= malloc(NSS_LINELEN_PASSWD);
	char			*s;
	int			parsestat;
	int			len;
	int			buflen;

	if (buf == 0) {
		return (NSS_STR_PARSE_PARSE);
		/* Really "out of memory", but PARSE_PARSE will have to do */
	}
	/*
	 * Don't allow overriding of
	 *	- username
	 *	- uid
	 *	- gid
	 * That's what the SunOS 4.x code did;  who are we to question it...
	 */
	s = buf;
	buflen = argp->buf.buflen;

	if (fields[1] != 0)
		len = snprintf(s, buflen, "%s:%s",
				pw->pw_name, fields[1]);
	else {
/* ====> Does this do the right thing? */
		if (pw->pw_age != 0 && *pw->pw_age != '\0')
			len = snprintf(s, buflen, "%s:%s,%s",
				pw->pw_name, pw->pw_passwd, pw->pw_age);
		else
			len = snprintf(s, buflen, "%s:%s",
				pw->pw_name, pw->pw_passwd);
	}

	if (len > buflen)
		return (NSS_STR_PARSE_ERANGE);

	s += len;
	buflen -= len;
	len = snprintf(s, buflen, ":%u:%u:%s:%s:%s",
		pw->pw_uid,
		pw->pw_gid,
		fields[4] != 0 ? fields[4] : pw->pw_gecos,
		fields[5] != 0 ? fields[5] : pw->pw_dir,
		fields[6] != 0 ? fields[6] : pw->pw_shell);

	if (len > buflen)
		return (NSS_STR_PARSE_ERANGE);

	s += len;
	len = s - buf;

	/*
	 * if asked, return the data in /etc file format
	 */
	if (be->return_string_data == 1) {
		/* reset the result ptr to the original value */
		argp->buf.result = NULL;

		if (len > argp->buf.buflen) {
			parsestat = NSS_STR_PARSE_ERANGE;
		} else {
			(void) strncpy(argp->buf.buffer, buf, len);
			argp->returnval = argp->buf.buffer;
			argp->returnlen = len;
			parsestat = NSS_SUCCESS;
		}
	} else {
		parsestat = (*argp->str2ent)(buf, len,
				    argp->buf.result,
				    argp->buf.buffer,
				    argp->buf.buflen);
	}
	free(buf);
	return (parsestat);
}

static compat_backend_op_t passwd_ops[] = {
	_nss_compat_destr,
	_nss_compat_endent,
	_nss_compat_setent,
	_nss_compat_getent,
	getbyname,
	getbyuid
};

/*ARGSUSED*/
nss_backend_t *
_nss_compat_passwd_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_compat_constr(passwd_ops,
				sizeof (passwd_ops) / sizeof (passwd_ops[0]),
				PASSWD,
				NSS_LINELEN_PASSWD,
				&db_root,
				_nss_initf_passwd_compat,
				1,
				get_pwname,
				merge_pwents));
}
