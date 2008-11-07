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
 * nisplus/getpwnam.c -- NIS+ backend for nsswitch "passwd" database
 */

#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

static nss_status_t
getbynam(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_nisplus_lookup(be, argp, PW_TAG_NAME, argp->key.name));
}

static nss_status_t
getbyuid(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char			uidstr[12];	/* More than enough */

	if (argp->key.uid > MAXUID)
		return (NSS_NOTFOUND);

	(void) snprintf(uidstr, 12, "%ld", argp->key.uid);
	return (_nss_nisplus_lookup(be, argp, PW_TAG_UID, uidstr));
}


/*
 * convert nisplus object into files format
 * place the results from the nis_object structure into argp->buf.result
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
/*ARGSUSED*/
static int
nis_object2str(nobj, obj, be, argp)
	int			nobj;
	nis_object		*obj;
	nisplus_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
{
	char			*buffer, *name, *uid, *gid, *gecos;
	ulong_t			uidl, gidl;
	char			uid_nobody[NOBODY_STR_LEN];
	char			gid_nobody[NOBODY_STR_LEN];
	char			*dir, *shell, *endnum;
	int			buflen, namelen, uidlen, gidlen, gecoslen;
	int			dirlen, shelllen;
	struct entry_col	*ecol;

	/*
	 * If we got more than one nis_object, we just ignore object(s)
	 * except the first. Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are
	 * null terminated.
	 */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < PW_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/* name: user name */
	__NISPLUS_GETCOL_OR_RETURN(ecol, PW_NDX_NAME, namelen, name);

	/* password field is 'x' */

	/* uid: user id. Must be numeric */
	__NISPLUS_GETCOL_OR_RETURN(ecol, PW_NDX_UID, uidlen, uid);
	uidl = strtoul(uid, &endnum, 10);
	if (*endnum != 0 || uid == endnum)
		return (NSS_STR_PARSE_PARSE);
	if (uidl > MAXUID) {
		(void) snprintf(uid_nobody, sizeof (uid_nobody),
		    "%u", UID_NOBODY);
		uid = uid_nobody;
		uidlen = strlen(uid);
	}

	/* gid: primary group id. Must be numeric */
	__NISPLUS_GETCOL_OR_RETURN(ecol, PW_NDX_GID, gidlen, gid);
	gidl = strtoul(gid, &endnum, 10);
	if (*endnum != 0 || gid == endnum)
		return (NSS_STR_PARSE_PARSE);
	if (gidl > MAXUID) {
		(void) snprintf(gid_nobody, sizeof (gid_nobody),
		    "%u", GID_NOBODY);
		gid = gid_nobody;
		gidlen = strlen(gid);
	}

	/* gecos: user's real name */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, PW_NDX_GCOS, gecoslen, gecos);

	/* dir: user's home directory */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, PW_NDX_HOME, dirlen, dir);

	/* shell: user's login shell */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, PW_NDX_SHELL, shelllen, shell);

	buflen = namelen + uidlen + gidlen + gecoslen +
		dirlen + shelllen + 8;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL)
			return (NSS_STR_PARSE_PARSE);
		/* include trailing null in length */
		be->buflen = buflen;
		buffer = be->buffer;
	} else {
		if (buflen > argp->buf.buflen)
			return (NSS_STR_PARSE_ERANGE);
		buflen = argp->buf.buflen;
		buffer = argp->buf.buffer;
		(void) memset(buffer, 0, buflen);
	}
	(void) snprintf(buffer, buflen, "%s:x:%s:%s:%s:%s:%s",
		name, uid, gid, gecos, dir, shell);
#ifdef DEBUG
	(void) fprintf(stdout, "passwd [%s]\n", buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t pw_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbynam,
	getbyuid
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_passwd_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(pw_ops,
				    sizeof (pw_ops) / sizeof (pw_ops[0]),
				    PW_TBLNAME, nis_object2str));
}
