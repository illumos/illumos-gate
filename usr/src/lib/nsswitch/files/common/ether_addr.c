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
 * files/ether_addr.c -- "files" backend for nsswitch "ethers" database
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal with the file /etc/ethers.  The file
 * contains mappings from 48 bit ethernet addresses to their corresponding
 * hosts names.  The addresses have an ascii representation of the form
 * "x:x:x:x:x:x" where x is a hex number between 0x00 and 0xff;  the
 * bytes are always in network order.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <nss_dbdefs.h>
#include "files_common.h"
#include <strings.h>
#include <ctype.h>

#define	_PATH_ETHERS	"/etc/ethers"
#define	DIGIT(x)	\
	(isdigit(x) ? (x) - '0' : islower(x) ? (x) + 10 - 'a' : (x) + 10 - 'A')

static int
check_host(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*limit, *linep, *keyp;
	linep = line;
	limit = line + linelen;

	/* skip leading spaces */
	while (linep < limit && isspace(*linep))
		linep++;
	/* skip mac address */
	while (linep < limit && !isspace(*linep))
		linep++;
	/* skip the delimiting spaces */
	while (linep < limit && isspace(*linep))
		linep++;
	if (linep == limit)
		return (0);

	/* compare the host name */
	keyp = argp->key.name;
	while (*keyp != '\0' && linep < limit && *keyp == *linep) {
		keyp++;
		linep++;
	}
	return (*keyp == '\0' && linep == limit);
}

static nss_status_t
getbyhost(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char	hostname[MAXHOSTNAMELEN];
	nss_status_t		res;

	/*
	 * use the buffer passed in if result is to be returned
	 * in /etc file format
	 */
	if (argp->buf.result != NULL) {
		argp->buf.buffer = hostname;
		argp->buf.buflen = MAXHOSTNAMELEN;
	}

	res = _nss_files_XY_all(be, argp, 0, argp->key.name, check_host);

	if (argp->buf.result != NULL) {
		argp->buf.buffer = NULL;
		argp->buf.buflen = 0;
	}

	return (res);
}

static int
check_ether(nss_XbyY_args_t *argp, const char *line, int linelen)
{

	const char	*limit, *linep;
	uchar_t		ether[6];
	ptrdiff_t	i;
	int		n;

	linep = line;
	limit = line + linelen;

	/* skip leading spaces */
	while (linep < limit && isspace(*linep))
		linep++;

	for (i = 0; i < 6; i++) {
		n = 0;
		while (linep < limit && isxdigit(*linep)) {
			n = 16 * n + DIGIT(*linep);
			linep++;
		}
		if (*linep != ':' && i < 5) {
			return (0);
		} else if (*linep == ':' && i == 5) {
			return (0);
		} else {
			linep++;
			ether[i] = (uchar_t)n;
		}
	}
	return (ether_cmp((void *)ether, (void *)argp->key.ether) == 0);
}

static nss_status_t
getbyether(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	struct ether_addr	etheraddr;
	nss_status_t		res;

	argp->buf.result	= &etheraddr;

	res = _nss_files_XY_all(be, argp, 0, NULL, check_ether);

	argp->buf.result	= NULL;
	return (res);
}

static files_backend_op_t ethers_ops[] = {
	_nss_files_destr,
	getbyhost,
	getbyether
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_ethers_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(ethers_ops,
				sizeof (ethers_ops) / sizeof (ethers_ops[0]),
				_PATH_ETHERS,
				NSS_LINELEN_ETHERS,
				NULL));
}
