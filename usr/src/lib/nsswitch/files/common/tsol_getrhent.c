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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "files_common.h"
#include <string.h>
#include <libtsnet.h>
#include <netinet/in.h>

/*
 *	files/tsol_getrhent.c --
 *           "files" backend for nsswitch "tnrhdb" database
 */
static int
check_addr(nss_XbyY_args_t *args, const char *line, int linelen)
{
	const char	*limit, *linep, *keyp;
	char	prev;
	int	ipv6;

	linep = line;
	limit = line + linelen;
	keyp = args->key.hostaddr.addr;
	prev = '\0';

	if (strstr(linep, "\\:") != NULL)
		ipv6 = 1;
	else
		ipv6 = 0;

	/*
	 * compare addr in
	 *
	 * 192.168.120.6:public
	 * fec0\:\:a00\:20ff\:fea0\:21f7:cipso
	 *
	 * ':' is the seperator.
	 */

	while (*keyp && linep < limit && *keyp == *linep) {
		if ((ipv6 == 0 && *linep == ':') ||
			(ipv6 == 1 && prev != '\\' && *linep == ':'))
			break;

		prev = *linep;
		keyp++;
		linep++;
	}
	if (*keyp == '\0' && linep < limit && ((ipv6 == 0 && *linep == ':') ||
			(ipv6 == 1 && prev != '\\' && *linep == ':')))
		return (1);

	return (0);
}

static void
escape_colon(const char *in, char *out) {
	int i, j;
	for (i = 0, j = 0; in[i] != '\0'; i++) {
		if (in[i] == ':') {
			out[j++] = '\\';
			out[j++] = in[i];
		} else
			out[j++] = in[i];
	}
	out[j] = '\0';
}

static nss_status_t
getbyaddr(files_backend_ptr_t be, void *a)
{
	nss_XbyY_args_t *argp = a;
	char addr6[INET6_ADDRSTRLEN + 5]; /* 5 '\' for ':' */
	const char *addr = NULL;
	nss_status_t	rc;

	if (argp->key.hostaddr.addr == NULL ||
		(argp->key.hostaddr.type != AF_INET &&
		argp->key.hostaddr.type != AF_INET6))
			return (NSS_NOTFOUND);
	if (strchr(argp->key.hostaddr.addr, ':') != NULL) {
		/* IPV6 */
		if (argp->key.hostaddr.type == AF_INET)
			return (NSS_NOTFOUND);
		escape_colon(argp->key.hostaddr.addr, addr6);
		/* save the key in original format */
		addr = argp->key.hostaddr.addr;
		/* Replace the key with escaped format */
		argp->key.hostaddr.addr = addr6;
	} else {
		/* IPV4 */
		if (argp->key.hostaddr.type == AF_INET6)
			return (NSS_NOTFOUND);
	}

	rc = _nss_files_XY_all(be, argp, 1,
		argp->key.hostaddr.addr, check_addr);

	/* restore argp->key.hostaddr.addr */
	if (addr)
		argp->key.hostaddr.addr = addr;

	return (rc);
}

static files_backend_op_t tsol_rh_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyaddr
};

nss_backend_t *
/* LINTED E_FUNC_ARG_UNUSED */
_nss_files_tnrhdb_constr(const char *dummy1, const char *dummy2,
/* LINTED E_FUNC_ARG_UNUSED */
    const char *dummy3)
{
	return (_nss_files_constr(tsol_rh_ops,
	    sizeof (tsol_rh_ops) / sizeof (tsol_rh_ops[0]), TNRHDB_PATH,
	    NSS_LINELEN_TSOL_RH, NULL));
}
