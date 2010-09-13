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
 * files/getservent.c -- "files" backend for nsswitch "services" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include "files_common.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>

static int
check_name(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*limit, *linep, *keyp;
	int		name_match = 0;

	linep = line;
	limit = line + linelen;
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

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_all(be, argp, 1,
				argp->key.serv.serv.name, check_name));
}

static int
check_port(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*limit, *linep, *keyp, *numstart;
	int		numlen, s_port;
	char		numbuf[12], *numend;

	linep = line;
	limit = line + linelen;

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
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *)a;
	char			portstr[12];

	(void) snprintf(portstr, 12, "%d", ntohs(argp->key.serv.serv.port));
	return (_nss_files_XY_all(be, argp, 1, portstr, check_port));
}

static files_backend_op_t serv_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyname,
	getbyport
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_services_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(serv_ops,
				sizeof (serv_ops) / sizeof (serv_ops[0]),
				_PATH_SERVICES,
				NSS_LINELEN_SERVICES,
				NULL));
}
