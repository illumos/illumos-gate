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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines used by rpc.nisd and by rpc.nisd_resolv
 */

#include <rpc/rpc.h>
#include <netdb.h>
#include <rpcsvc/yp_prot.h>
#include <errno.h>
#include <sys/types.h>
#include "resolv_common.h"

bool_t
xdr_ypfwdreq_key4(XDR *xdrs, struct ypfwdreq_key4 *ps)
{
	return (xdr_ypmap_wrap_string(xdrs, &ps->map) &&
		xdr_datum(xdrs, &ps->keydat) &&
		xdr_u_long(xdrs, &ps->xid) &&
		xdr_u_long(xdrs, &ps->ip) &&
		xdr_u_short(xdrs, &ps->port));
}


bool_t
xdr_ypfwdreq_key6(XDR *xdrs, struct ypfwdreq_key6 *ps)
{
	uint_t	addrsize = sizeof (struct in6_addr)/sizeof (uint32_t);
	char	**addrp = (caddr_t *)&(ps->addr);

	return (xdr_ypmap_wrap_string(xdrs, &ps->map) &&
		xdr_datum(xdrs, &ps->keydat) &&
		xdr_u_long(xdrs, &ps->xid) &&
		xdr_array(xdrs, addrp, &addrsize, addrsize,
			sizeof (uint32_t), xdr_uint32_t) &&
		xdr_u_short(xdrs, &ps->port));
}


ulong_t
svc_getxid(SVCXPRT *xprt)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct svc_dg_data *su = get_svc_dg_data(xprt);
	if (su == NULL)
		return (0);
	return (su->su_xid);
}
