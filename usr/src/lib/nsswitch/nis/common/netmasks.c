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
 *	nis/netmasks.c -- "nis" backend for nsswitch "netmasks" database
 *
 *	Copyright (c) 1996 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal with the netmasks NIS maps.  The maps
 * contain mapping between 32 bit network internet addresses and their
 * corresponding 32 bit network mask internet address. The addresses are in
 * dotted internet address form.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <nss_dbdefs.h>
#include "nis_common.h"

static nss_status_t
getbynet(be, a)
	nis_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;
	return (_nss_nis_lookup(be, argp, 0, "netmasks.byaddr",
	    argp->key.name, 0));
}

static nis_backend_op_t netmasks_ops[] = {
	_nss_nis_destr,
	getbynet
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_netmasks_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nis_constr(netmasks_ops,
			sizeof (netmasks_ops) / sizeof (netmasks_ops[0]),
			"netmasks.byaddr"));
}
