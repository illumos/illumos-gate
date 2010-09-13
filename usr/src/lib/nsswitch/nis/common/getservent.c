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
 *	nis/getservent.c -- "nis" backend for nsswitch "services" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nis_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <malloc.h>
#include <netdb.h>
#include <synch.h>
#include <ctype.h>
#include <rpcsvc/ypclnt.h>
#include <thread.h>
#include <sys/types.h>
#include <netinet/in.h>

static int
check_name(args)
	nss_XbyY_args_t		*args;
{
	struct servent		*serv	= (struct servent *)args->returnval;
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

static int
check_name2(nss_XbyY_args_t *argp)
{
	const char	*limit, *linep, *keyp;
	int		name_match = 0;

	linep = (const char *)argp->buf.buffer;
	limit = linep + strlen(argp->buf.buffer);
	keyp = argp->key.serv.serv.name;

	/* compare name */
	while (*keyp && linep < limit && !isspace(*linep) && *keyp == *linep) {
		keyp++;
		linep++;
	}
	if (*keyp == '\0' && linep < limit && isspace(*linep)) {
		if (argp->key.serv.proto == NULL)
			return (1);
		else
			name_match = 1;
	}

	/* skip remainder of the name, if any */
	while (linep < limit && !isspace(*linep))
		linep++;
	/* skip the delimiting spaces */
	while (linep < limit && isspace(*linep))
		linep++;
	/* skip port number */
	while (linep < limit && !isspace(*linep) && *linep != '/')
		linep++;
	if (linep == limit || *linep != '/')
		return (0);

	linep++;
	if ((keyp = argp->key.serv.proto) == NULL) {
		/* skip protocol */
		while (linep < limit && !isspace(*linep))
			linep++;
	} else {
		/* compare protocol */
		while (*keyp && linep < limit && !isspace(*linep) &&
		    *keyp == *linep) {
			keyp++;
			linep++;
		}
		/* no protocol match */
		if (*keyp || (linep < limit && !isspace(*linep)))
			return (0);
		/* protocol and name match, return */
		if (name_match)
			return (1);
		/* protocol match but name yet to be matched, so continue */
	}

	/* compare with the aliases */
	while (linep < limit) {
		/* skip the delimiting spaces */
		while (linep < limit && isspace(*linep))
			linep++;

		/* compare with the alias name */
		keyp = argp->key.serv.serv.name;
		while (*keyp && linep < limit && !isspace(*linep) &&
		    *keyp == *linep) {
			keyp++;
			linep++;
		}
		if (*keyp == '\0' && (linep == limit || isspace(*linep)))
				return (1);

		/* skip remainder of the alias name, if any */
		while (linep < limit && !isspace(*linep))
			linep++;
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
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	const char		*name	= argp->key.serv.serv.name;
	const char		*proto	= argp->key.serv.proto;
	int			no_map;
	sigset_t		oldmask, newmask;

	(void) sigfillset(&newmask);
	(void) thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
	(void) mutex_lock(&no_byname_lock);
	no_map = no_byname_map;
	(void) mutex_unlock(&no_byname_lock);
	(void) thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);

	if (no_map == 0) {
		int		yp_status;
		nss_status_t	res;

		if (proto == 0) {
			res = _nss_nis_lookup(be, argp, 1,
			    "services.byservicename", name, &yp_status);
		} else {
			int len = strlen(name) + strlen(proto) + 3;
			char *key = malloc(len);

			if (key == NULL) {
				return (NSS_UNAVAIL);
			}
			(void) snprintf(key, len, "%s/%s", name, proto);
			res = _nss_nis_lookup(be, argp, 1,
			    "services.byservicename", key, &yp_status);
			free(key);
		}

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

	/*
	 * use check_anme to compare service name if nss1 or nss2 and
	 * request is not from nscd; otherwise use check_name2
	 */
	if (argp->buf.result != NULL)
		return (_nss_nis_XY_all(be, argp, 1, name, check_name));
	else
		return (_nss_nis_XY_all(be, argp, 1, name, check_name2));
}

static int
check_port(args)
	nss_XbyY_args_t		*args;
{
	struct servent		*serv	= (struct servent *)args->returnval;

	/*
	 * We only resorted to _nss_nis_XY_all because proto == 0, so just...
	 */
	return (serv->s_port == args->key.serv.serv.port);
}

static int
check_port2(nss_XbyY_args_t *argp)
{
	const char	*limit, *linep, *keyp, *numstart;
	int		numlen, s_port;
	char		numbuf[12], *numend;

	linep = (const char *)argp->buf.buffer;
	limit = linep + strlen(argp->buf.buffer);

	/* skip name */
	while (linep < limit && !isspace(*linep))
		linep++;
	/* skip the delimiting spaces */
	while (linep < limit && isspace(*linep))
		linep++;

	/* compare port num */
	numstart = linep;
	while (linep < limit && !isspace(*linep) && *linep != '/')
		linep++;
	if (linep == limit || *linep != '/')
		return (0);
	numlen = linep - numstart;
	if (numlen == 0 || numlen >= sizeof (numbuf))
		return (0);
	(void) memcpy(numbuf, numstart, numlen);
	numbuf[numlen] = '\0';
	s_port = htons((int)strtol(numbuf, &numend, 10));
	if (*numend != '\0')
		return (0);
	if (s_port == argp->key.serv.serv.port) {
		if ((keyp = argp->key.serv.proto) == NULL)
			return (1);
	} else
		return (0);

	/* compare protocol */
	linep++;
	while (*keyp && linep < limit && !isspace(*linep) && *keyp == *linep) {
		keyp++;
		linep++;
	}
	return (*keyp == '\0' && (linep == limit || isspace(*linep)));
}


static nss_status_t
getbyport(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *)a;
	int			port	= ntohs(argp->key.serv.serv.port);
	const char		*proto	= argp->key.serv.proto;
	char			*key;
	nss_status_t		res;
	int			len;

	if (proto == 0) {
		char		portstr[12];

		(void) snprintf(portstr, 12, "%d", port);
		/*
		 * use check_port to compare service port if nss1 or
		 * nss2 and request is not from nscd; otherwise use
		 * check_port2
		 */
		if (argp->buf.result != NULL)
			return (_nss_nis_XY_all(be, argp, 1, portstr,
				check_port));
		else
			return (_nss_nis_XY_all(be, argp, 1, portstr,
				check_port2));
	}

	len = strlen(proto) + 14;
	if ((key = malloc(len)) == 0) {
		return (NSS_UNAVAIL);
	}
	(void) snprintf(key, len, "%d/%s", port, proto);

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
