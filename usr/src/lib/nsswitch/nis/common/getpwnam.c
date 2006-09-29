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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	nis/getpwnam.c -- "nis" backend for nsswitch "passwd" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

	(void) snprintf(uidstr, 12, "%ld", argp->key.uid);
	return (_nss_nis_lookup(be, argp, 0, "passwd.byuid", uidstr, 0));
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
