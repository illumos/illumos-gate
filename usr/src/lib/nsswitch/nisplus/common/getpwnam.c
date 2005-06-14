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
 *	getpwnam.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 *
 *	nisplus/getpwnam.c -- NIS+ backend for nsswitch "passwd" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;

	return (_nss_nisplus_lookup(be, argp, PW_TAG_NAME, argp->key.name));
}

static nss_status_t
getbyuid(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;
	char			uidstr[12];	/* More than enough */

	sprintf(uidstr, "%d", argp->key.uid);
	return (_nss_nisplus_lookup(be, argp, PW_TAG_UID, uidstr));
}


/*
 * place the results from the nis_object structure into argp->buf.result
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 *
 * This routine does not tolerate non-numeric or empty pw_uid or pw_gid.
 * Nor empty name field.
 * It will immediately flag a PARSE error and return. Returns a
 * pointer-to-a-null in case of empty gecos, home_dir, or shell fields.
 */
/*ARGSUSED*/
static int
nis_object2ent(nobj, obj, argp)
	int		nobj;
	nis_object	*obj;
	nss_XbyY_args_t	*argp;
{
	char	*buffer, *limit, *val, *endnum, *nullstring;
	int		buflen = argp->buf.buflen;
	struct 	passwd *pw;
	struct	entry_col *ecol;
	int		len;

	limit = argp->buf.buffer + buflen;
	pw = (struct passwd *)argp->buf.result;
	buffer = argp->buf.buffer;

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

	/*
	 * pw_name: user name
	 */
	EC_SET(ecol, PW_NDX_NAME, len, val);
	if (len < 2 || (*val == '\0'))
		return (NSS_STR_PARSE_PARSE);
	pw->pw_name = buffer;
	buffer += len;
	if (buffer >= limit)
		return (NSS_STR_PARSE_ERANGE);
	strcpy(pw->pw_name, val);
	nullstring = (buffer - 1);

	/*
	 * pw_uid: user id
	 */
	EC_SET(ecol, PW_NDX_UID, len, val);
	if (len < 2) {
		return (NSS_STR_PARSE_PARSE);
	} else {
		pw->pw_uid = strtol(val, &endnum, 10);
		if (*endnum != 0 || val == endnum) {
			return (NSS_STR_PARSE_PARSE);
		}
	}

	/*
	 * pw_passwd: user passwd. Do not HAVE to get this here
	 * because the caller would do a getspnam() anyway.
	 */
	EC_SET(ecol, PW_NDX_PASSWD, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_passwd = nullstring;
	} else {
		pw->pw_passwd = buffer;
		buffer += len;
		if (buffer >= limit)
			return (NSS_STR_PARSE_ERANGE);
		strcpy(pw->pw_passwd, val);
	}

	/*
	 * pw_gid: user's primary group id.
	 */
	EC_SET(ecol, PW_NDX_GID, len, val);
	if (len < 2) {
		return (NSS_STR_PARSE_PARSE);
	} else {
		pw->pw_gid = strtol(val, &endnum, 10);
		if (*endnum != 0 || val == endnum) {
			return (NSS_STR_PARSE_PARSE);
		}
	}

	/*
	 * pw_gecos: user's real name.
	 */
	EC_SET(ecol, PW_NDX_GCOS, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_gecos = nullstring;
	} else {
		pw->pw_gecos = buffer;
		buffer += len;
		if (buffer >= limit)
			return (NSS_STR_PARSE_ERANGE);
		strcpy(pw->pw_gecos, val);
	}

	/*
	 * pw_dir: user's home directory
	 */
	EC_SET(ecol, PW_NDX_HOME, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_dir = nullstring;
	} else {
		pw->pw_dir = buffer;
		buffer += len;
		if (buffer >= limit)
			return (NSS_STR_PARSE_ERANGE);
		strcpy(pw->pw_dir, val);
	}

	/*
	 * pw_shell: user's login shell
	 */
	EC_SET(ecol, PW_NDX_SHELL, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_shell = nullstring;
	} else {
		pw->pw_shell = buffer;
		buffer += len;
		if (buffer >= limit)
			return (NSS_STR_PARSE_ERANGE);
		strcpy(pw->pw_shell, val);
	}

	/*
	 * pw_age and pw_comment shouldn't be used anymore, but various things
	 *   (allegedly in.ftpd) merrily do strlen() on them anyway, so we
	 *   keep the peace by returning a zero-length string instead of a
	 *   null pointer.
	 */
	pw->pw_age = pw->pw_comment = nullstring;

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
				    PW_TBLNAME, nis_object2ent));
}
