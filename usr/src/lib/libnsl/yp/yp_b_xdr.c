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
 *
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
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

#include <rpc/rpc.h>
#include <netconfig.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <sys/types.h>
#include <rpc/trace.h>

bool_t
xdr_ypbind_resptype(xdrs, objp)
	XDR *xdrs;
	ypbind_resptype *objp;
{
	trace1(TR_xdr_ypbind_resptype, 0);
	if (!xdr_enum(xdrs, (enum_t *)objp)) {
		trace1(TR_xdr_ypbind_resptype, 1);
		return (FALSE);
	}
	trace1(TR_xdr_ypbind_resptype, 1);
	return (TRUE);
}


#define	YPBIND_ERR_ERR 1		/* Internal error */
#define	YPBIND_ERR_NOSERV 2		/* No bound server for passed domain */
#define	YPBIND_ERR_RESC 3		/* System resource allocation failure */
#define	YPBIND_ERR_NODOMAIN 4		/* Domain doesn't exist */


bool_t
xdr_ypbind_domain(xdrs, objp)
	XDR *xdrs;
	ypbind_domain *objp;
{
	trace1(TR_xdr_ypbind_domain, 0);
	if (!xdr_string(xdrs, &objp->ypbind_domainname, YPMAXDOMAIN)) {
		trace1(TR_xdr_ypbind_domain, 1);
		return (FALSE);
	}
	if (!xdr_rpcvers(xdrs, &objp->ypbind_vers)) {
		trace1(TR_xdr_ypbind_domain, 1);
		return (FALSE);
	}
	trace1(TR_xdr_ypbind_domain, 1);
	return (TRUE);
}


bool_t
xdr_ypbind_binding(xdrs, objp)
	XDR *xdrs;
	ypbind_binding *objp;
{
	trace1(TR_xdr_ypbind_binding, 0);
	if (!xdr_pointer(xdrs, (char **)&objp->ypbind_nconf,
		sizeof (struct netconfig), xdr_netconfig)) {
		trace1(TR_xdr_ypbind_binding, 1);
		return (FALSE);
	}
	if (!xdr_pointer(xdrs, (char **)&objp->ypbind_svcaddr,
		sizeof (struct netbuf), xdr_netbuf)) {
		trace1(TR_xdr_ypbind_binding, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->ypbind_servername, ~0)) {
		trace1(TR_xdr_ypbind_binding, 1);
		return (FALSE);
	}
	if (!xdr_rpcvers(xdrs, &objp->ypbind_hi_vers)) {
		trace1(TR_xdr_ypbind_binding, 1);
		return (FALSE);
	}
	if (!xdr_rpcvers(xdrs, &objp->ypbind_lo_vers)) {
		trace1(TR_xdr_ypbind_binding, 1);
		return (FALSE);
	}
	trace1(TR_xdr_ypbind_binding, 1);
	return (TRUE);
}


bool_t
xdr_ypbind_resp(xdrs, objp)
	XDR *xdrs;
	ypbind_resp *objp;
{
	trace1(TR_xdr_ypbind_resp, 0);
	if (!xdr_ypbind_resptype(xdrs, &objp->ypbind_status)) {
		trace1(TR_xdr_ypbind_resp, 1);
		return (FALSE);
	}
	switch (objp->ypbind_status) {
	case YPBIND_FAIL_VAL:
		if (!xdr_u_int(xdrs, &objp->ypbind_resp_u.ypbind_error)) {
			trace1(TR_xdr_ypbind_resp, 1);
			return (FALSE);
		}
		break;
	case YPBIND_SUCC_VAL:
		if (!xdr_pointer(xdrs,
			(char **)&objp->ypbind_resp_u.ypbind_bindinfo,
			sizeof (ypbind_binding), xdr_ypbind_binding)) {
			trace1(TR_xdr_ypbind_resp, 1);
			return (FALSE);
		}
		break;
	default:
		trace1(TR_xdr_ypbind_resp, 1);
		return (FALSE);
	}
	trace1(TR_xdr_ypbind_resp, 1);
	return (TRUE);
}


bool_t
xdr_ypbind_setdom(xdrs, objp)
	XDR *xdrs;
	ypbind_setdom *objp;
{
	trace1(TR_xdr_ypbind_setdom, 0);
	if (!xdr_string(xdrs, &objp->ypsetdom_domain, YPMAXDOMAIN)) {
		trace1(TR_xdr_ypbind_setdom, 1);
		return (FALSE);
	}
	if (!xdr_pointer(xdrs, (char **)&objp->ypsetdom_bindinfo,
		sizeof (ypbind_binding), xdr_ypbind_binding)) {
		trace1(TR_xdr_ypbind_setdom, 1);
		return (FALSE);
	}
	trace1(TR_xdr_ypbind_setdom, 1);
	return (TRUE);
}
