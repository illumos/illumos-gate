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
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 *
 *	nis/getservent.c -- "nis" backend for nsswitch "services" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nis_common.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <malloc.h>
#include <netdb.h>
#include <synch.h>
#include <rpcsvc/ypclnt.h>
#include <thread.h>
#include <sys/types.h>
#include <netinet/in.h>

static int
check_name(args)
	nss_XbyY_args_t		*args;
{
	struct servent		*serv	= (struct servent *) args->returnval;
	const char		*name	= args->key.serv.serv.name;
	const char		*proto	= args->key.serv.proto;
	char			**aliasp;

	if (proto != 0 && strcmp(serv->s_proto, proto) != 0) {
		return (0);
	}
	if (strcmp(serv->s_name, name) == 0) {
		return (1);
	}
	for (aliasp = serv->s_aliases;  *aliasp != 0;  aliasp++) {
		if (strcmp(*aliasp, name) == 0) {
			return (1);
		}
	}
	return (0);
}

static mutex_t	no_byname_lock	= DEFAULTMUTEX;
static int	no_byname_map	= 0;

static nss_status_t
getbyname(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;
	const char		*name	= argp->key.serv.serv.name;
	const char		*proto	= argp->key.serv.proto;
	int			no_map;
	sigset_t		oldmask, newmask;

	sigfillset(&newmask);
	(void) _thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
	(void) _mutex_lock(&no_byname_lock);
	no_map = no_byname_map;
	(void) _mutex_unlock(&no_byname_lock);
	(void) _thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);

	if (no_map == 0) {
		int		yp_status;
		nss_status_t	res;

		if (proto == 0) {
			res = _nss_nis_lookup(be, argp, 1,
			    "services.byservicename", name, &yp_status);
		} else {
			char *key = malloc(strlen(name) + strlen(proto) + 3);

			if (key == 0) {
				return (NSS_UNAVAIL);
			}
			sprintf(key, "%s/%s", name, proto);
			res = _nss_nis_lookup(be, argp, 1,
			    "services.byservicename", key, &yp_status);
			free(key);
		}

		if (yp_status == YPERR_MAP) {
			sigfillset(&newmask);
			_thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
			_mutex_lock(&no_byname_lock);
			no_byname_map = 1;
			_mutex_unlock(&no_byname_lock);
			_thr_sigsetmask(SIG_SETMASK, &oldmask, (sigset_t*)NULL);
		} else /* if (res == NSS_SUCCESS) <==== */ {
			return (res);
		}
	}

	return (_nss_nis_XY_all(be, argp, 1, name, check_name));
}

static int
check_port(args)
	nss_XbyY_args_t		*args;
{
	struct servent		*serv	= (struct servent *) args->returnval;

	/*
	 * We only resorted to _nss_nis_XY_all because proto == 0, so just...
	 */
	return (serv->s_port == args->key.serv.serv.port);
}

static nss_status_t
getbyport(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *) a;
	int			port	= ntohs(argp->key.serv.serv.port);
	const char		*proto	= argp->key.serv.proto;
	char			*key;
	nss_status_t		res;

	if (proto == 0) {
		char		portstr[12];

		sprintf(portstr, "%d", port);
		return (_nss_nis_XY_all(be, argp, 1, portstr, check_port));
	}

	if ((key = malloc(strlen(proto) + 14)) == 0) {
		return (NSS_UNAVAIL);
	}
	sprintf(key, "%d/%s", port, proto);

	res = _nss_nis_lookup(be, argp, 1, "services.byname", key, 0);

	free(key);
	return (res);
}

static nis_backend_op_t serv_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_netdb,
	getbyname,
	getbyport
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_services_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(serv_ops,
				sizeof (serv_ops) / sizeof (serv_ops[0]),
				"services.byname"));
}
