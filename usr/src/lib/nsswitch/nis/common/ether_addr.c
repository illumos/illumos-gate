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
 *	nis/ether_addr.c -- "nis" backend for nsswitch "ethers" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal with the ethers NIS maps.  The maps
 * contain mapping between 48 bit ethernet addresses and their corresponding
 * hosts name.  The addresses have an ascii representation of the form
 * "x:x:x:x:x:x" where x is a hex number between 0x00 and 0xff;  the
 * bytes are always in network order.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <nss_dbdefs.h>
#include "nis_common.h"

static nss_status_t
getbyhost(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_nis_lookup(be, argp, 0, "ethers.byname",
		argp->key.name, 0));
}

static nss_status_t
getbyether(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char	etherstr[18];
	uchar_t	*e = argp->key.ether;

	(void) snprintf(etherstr, 18, "%x:%x:%x:%x:%x:%x",
		*e, *(e + 1), *(e + 2), *(e + 3), *(e + 4), *(e + 5));
	return (_nss_nis_lookup(be, argp, 0, "ethers.byaddr", etherstr, 0));
}

static nis_backend_op_t ethers_ops[] = {
	_nss_nis_destr,
	getbyhost,
	getbyether
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_ethers_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(ethers_ops,
			sizeof (ethers_ops) / sizeof (ethers_ops[0]),
			"ethers.byaddr"));
}
