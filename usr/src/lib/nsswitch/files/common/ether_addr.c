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
 *	files/ether_addr.c -- "files" backend for nsswitch "ethers" database
 *
 * Copyright 1988-1995,2002 Sun Microsystems, Inc.  All rights reserved.
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

#define	_PATH_ETHERS	"/etc/ethers"

static int
check_host(args)
	nss_XbyY_args_t		*args;
{
	return (strcmp(args->buf.buffer, args->key.name) == 0);
}

static nss_status_t
getbyhost(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char	hostname[MAXHOSTNAMELEN];
	nss_status_t		res;

	argp->buf.buffer = hostname;
	argp->buf.buflen = MAXHOSTNAMELEN;

	res = _nss_files_XY_all(be, argp, 0, argp->key.name, check_host);

	argp->buf.buffer = NULL;
	argp->buf.buflen = 0;
	return (res);
}

static int
check_ether(args)
	nss_XbyY_args_t		*args;
{
	return (ether_cmp(args->buf.result, args->key.ether) == 0);
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
