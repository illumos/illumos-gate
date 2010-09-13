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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <rpc/rpc.h>
#include <netconfig.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <sys/types.h>

bool_t
xdr_ypbind_resptype(XDR *xdrs, ypbind_resptype *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_ypbind_domain(XDR *xdrs, ypbind_domain *objp)
{
	if (!xdr_string(xdrs, &objp->ypbind_domainname, YPMAXDOMAIN))
		return (FALSE);
	return (xdr_rpcvers(xdrs, &objp->ypbind_vers));
}

bool_t
xdr_ypbind_binding(XDR *xdrs, ypbind_binding *objp)
{
	if (!xdr_pointer(xdrs, (char **)&objp->ypbind_nconf,
			sizeof (struct netconfig), xdr_netconfig))
		return (FALSE);
	if (!xdr_pointer(xdrs, (char **)&objp->ypbind_svcaddr,
			sizeof (struct netbuf), xdr_netbuf))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ypbind_servername, ~0))
		return (FALSE);
	if (!xdr_rpcvers(xdrs, &objp->ypbind_hi_vers))
		return (FALSE);
	return (xdr_rpcvers(xdrs, &objp->ypbind_lo_vers));
}

bool_t
xdr_ypbind_resp(XDR *xdrs, ypbind_resp *objp)
{
	if (!xdr_ypbind_resptype(xdrs, &objp->ypbind_status))
		return (FALSE);
	switch (objp->ypbind_status) {
	case YPBIND_FAIL_VAL:
		if (!xdr_u_int(xdrs, &objp->ypbind_resp_u.ypbind_error))
			return (FALSE);
		break;
	case YPBIND_SUCC_VAL:
		if (!xdr_pointer(xdrs,
			(char **)&objp->ypbind_resp_u.ypbind_bindinfo,
			sizeof (ypbind_binding), xdr_ypbind_binding))
			return (FALSE);
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_ypbind_setdom(XDR *xdrs, ypbind_setdom *objp)
{
	if (!xdr_string(xdrs, &objp->ypsetdom_domain, YPMAXDOMAIN))
		return (FALSE);
	return (xdr_pointer(xdrs, (char **)&objp->ypsetdom_bindinfo,
		sizeof (ypbind_binding), xdr_ypbind_binding));
}
