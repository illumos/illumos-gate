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
 *	nis/getrpcent.c -- "nis" backend for nsswitch "rpc" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nis_common.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <synch.h>
#include <rpc/rpcent.h>
#include <rpcsvc/ypclnt.h>
#include <thread.h>

static int
check_name(args)
	nss_XbyY_args_t		*args;
{
	struct rpcent		*rpc	= (struct rpcent *)args->returnval;
	const char		*name	= args->key.name;
	char			**aliasp;

	if (rpc) {
		if (strcmp(rpc->r_name, name) == 0) {
			return (1);
		}
		for (aliasp = rpc->r_aliases;  *aliasp != 0;  aliasp++) {
			if (strcmp(*aliasp, name) == 0) {
				return (1);
			}
		}
		return (0);
	} else {
		/*
		 *  NSS2: nscd is running.
		 */
		return (_nss_nis_check_name_aliases(args,
					(const char *)args->buf.buffer,
					strlen(args->buf.buffer)));

	}
}

static mutex_t	no_byname_lock	= DEFAULTMUTEX;
static int	no_byname_map	= 0;

static nss_status_t
getbyname(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	int			no_map;
	sigset_t		oldmask, newmask;

	(void) sigfillset(&newmask);
	(void) thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
	(void) mutex_lock(&no_byname_lock);
	no_map = no_byname_map;
	(void) mutex_unlock(&no_byname_lock);
	(void) thr_sigsetmask(SIG_SETMASK, &oldmask, (sigset_t *)NULL);

	if (no_map == 0) {
		int		yp_status;
		nss_status_t	res;

		res = _nss_nis_lookup(be, argp, 1, "rpc.byname",
					argp->key.name, &yp_status);
		if (yp_status == YPERR_MAP) {
			(void) sigfillset(&newmask);
			(void) thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
			(void) mutex_lock(&no_byname_lock);
			no_byname_map = 1;
			(void) mutex_unlock(&no_byname_lock);
			(void) thr_sigsetmask(SIG_SETMASK, &oldmask,
					(sigset_t *)NULL);
		} else /* if (res == NSS_SUCCESS) <==== */ {
			return (res);
		}
	}

	return (_nss_nis_XY_all(be, argp, 1, argp->key.name, check_name));
}

static nss_status_t
getbynumber(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char			numstr[12];

	(void) sprintf(numstr, "%d", argp->key.number);
	return (_nss_nis_lookup(be, argp, 1, "rpc.bynumber", numstr, 0));
}

static nis_backend_op_t rpc_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_netdb,
	getbyname,
	getbynumber
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_rpc_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(rpc_ops,
				sizeof (rpc_ops) / sizeof (rpc_ops[0]),
				"rpc.bynumber"));
}
