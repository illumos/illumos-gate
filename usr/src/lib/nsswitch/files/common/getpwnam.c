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
 *	files/getpwnam.c -- "files" backend for nsswitch "passwd" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pwd.h>
#include <shadow.h>
#include <unistd.h>		/* for PF_PATH */
#include "files_common.h"
#include <strings.h>

static u_int
hash_pwname(nss_XbyY_args_t *argp, int keyhash)
{
	struct passwd *p = argp->returnval;
	const char *name = keyhash ? argp->key.name : p->pw_name;
	u_int hash = 0;

	while (*name != 0)
		hash = hash * 15 + *name++;

	return (hash);
}

static u_int
hash_pwuid(nss_XbyY_args_t *argp, int keyhash)
{
	struct passwd *p = argp->returnval;
	return (keyhash ? (u_int)argp->key.uid : (u_int)p->pw_uid);
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
check_pwname(argp)
	nss_XbyY_args_t		*argp;
{
	struct passwd		*p = (struct passwd *)argp->returnval;

	/* +/- entries valid for compat source only */
	if (p->pw_name != 0 && (p->pw_name[0] == '+' || p->pw_name[0] == '-'))
		return (0);
	return (strcmp(p->pw_name, argp->key.name) == 0);
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 0, check_pwname));
}

static int
check_pwuid(argp)
	nss_XbyY_args_t		*argp;
{
	struct passwd		*p = (struct passwd *)argp->returnval;

	/* +/- entries valid for compat source only */
	if (p->pw_name != 0 && (p->pw_name[0] == '+' || p->pw_name[0] == '-'))
		return (0);
	return (p->pw_uid == argp->key.uid);
}

static nss_status_t
getbyuid(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	return (_nss_files_XY_hash(be, a, 0, &hashinfo, 1, check_pwuid));
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
