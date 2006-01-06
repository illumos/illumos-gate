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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file was generated from rpcb_prot.x, but includes only those
 * routines used with the rpcbind stats facility.
 */

#include "mt.h"
#include <rpc/rpc.h>

/* Link list of all the stats about getport and getaddr */

bool_t
xdr_rpcbs_addrlist(XDR *xdrs, rpcbs_addrlist *objp)
{
	if (!xdr_u_int(xdrs, (uint_t *)&objp->prog))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->vers))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->success))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->failure))
		return (FALSE);
	return (xdr_string(xdrs, &objp->netid, ~0));
}

/* Link list of all the stats about rmtcall */

bool_t
xdr_rpcbs_rmtcalllist(XDR *xdrs, rpcbs_rmtcalllist *objp)
{
	rpc_inline_t *buf;

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_u_int(xdrs, (uint_t *)&objp->prog))
				return (FALSE);
			if (!xdr_u_int(xdrs, (uint_t *)&objp->vers))
				return (FALSE);
			if (!xdr_u_int(xdrs, (uint_t *)&objp->proc))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->success))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->failure))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->indirect))
				return (FALSE);
		} else {
			IXDR_PUT_U_INT32(buf, objp->prog);
			IXDR_PUT_U_INT32(buf, objp->vers);
			IXDR_PUT_U_INT32(buf, objp->proc);
			IXDR_PUT_INT32(buf, objp->success);
			IXDR_PUT_INT32(buf, objp->failure);
			IXDR_PUT_INT32(buf, objp->indirect);
		}
		if (!xdr_string(xdrs, &objp->netid, ~0))
			return (FALSE);
		return (xdr_pointer(xdrs, (char **)&objp->next,
				(uint_t)sizeof (rpcbs_rmtcalllist),
				(xdrproc_t)xdr_rpcbs_rmtcalllist));
	case XDR_DECODE:
		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_u_int(xdrs, (uint_t *)&objp->prog))
				return (FALSE);
			if (!xdr_u_int(xdrs, (uint_t *)&objp->vers))
				return (FALSE);
			if (!xdr_u_int(xdrs, (uint_t *)&objp->proc))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->success))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->failure))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->indirect))
				return (FALSE);
		} else {
			objp->prog = IXDR_GET_U_INT32(buf);
			objp->vers = IXDR_GET_U_INT32(buf);
			objp->proc = IXDR_GET_U_INT32(buf);
			objp->success = IXDR_GET_INT32(buf);
			objp->failure = IXDR_GET_INT32(buf);
			objp->indirect = IXDR_GET_INT32(buf);
		}
		if (!xdr_string(xdrs, &objp->netid, ~0))
			return (FALSE);
		return (xdr_pointer(xdrs, (char **)&objp->next,
				(uint_t)sizeof (rpcbs_rmtcalllist),
				(xdrproc_t)xdr_rpcbs_rmtcalllist));
	case XDR_FREE:
		if (!xdr_u_int(xdrs, (uint_t *)&objp->prog))
			return (FALSE);
		if (!xdr_u_int(xdrs, (uint_t *)&objp->vers))
			return (FALSE);
		if (!xdr_u_int(xdrs, (uint_t *)&objp->proc))
			return (FALSE);
		if (!xdr_int(xdrs, &objp->success))
			return (FALSE);
		if (!xdr_int(xdrs, &objp->failure))
			return (FALSE);
		if (!xdr_int(xdrs, &objp->indirect))
			return (FALSE);
		if (!xdr_string(xdrs, &objp->netid, ~0))
			return (FALSE);
		return (xdr_pointer(xdrs, (char **)&objp->next,
				(uint_t)sizeof (rpcbs_rmtcalllist),
				(xdrproc_t)xdr_rpcbs_rmtcalllist));
	default:
		return (FALSE);
	}
}

bool_t
xdr_rpcbs_proc(XDR *xdrs, rpcbs_proc objp)
{
	return (xdr_vector(xdrs, (char *)objp, RPCBSTAT_HIGHPROC, sizeof (int),
			(xdrproc_t)xdr_int));
}

bool_t
xdr_rpcbs_addrlist_ptr(XDR *xdrs, rpcbs_addrlist_ptr *objp)
{
	bool_t			more_data;
	rpcbs_addrlist_ptr	*nextp;

	for (;;) {
		more_data = (*objp != NULL);

		if (!xdr_bool(xdrs, &more_data))
			return (FALSE);

		if (!more_data)
			break;

		if (xdrs->x_op == XDR_FREE)
			nextp = &(*objp)->next;

		if (!xdr_reference(xdrs, (char **)objp,
			(uint_t)sizeof (rpcbs_addrlist),
			(xdrproc_t)xdr_rpcbs_addrlist))
			return (FALSE);

		objp = (xdrs->x_op == XDR_FREE) ? nextp : &(*objp)->next;

	}
	*objp = NULL;
	return (TRUE);
}

bool_t
xdr_rpcbs_rmtcalllist_ptr(XDR *xdrs, rpcbs_rmtcalllist_ptr *objp)
{
	return (xdr_pointer(xdrs, (char **)objp, sizeof (rpcbs_rmtcalllist),
			(xdrproc_t)xdr_rpcbs_rmtcalllist));
}

bool_t
xdr_rpcb_stat(XDR *xdrs, rpcb_stat *objp)
{
	if (!xdr_rpcbs_proc(xdrs, objp->info))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->setinfo))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->unsetinfo))
		return (FALSE);
	if (!xdr_rpcbs_addrlist_ptr(xdrs, &objp->addrinfo))
		return (FALSE);
	return (xdr_rpcbs_rmtcalllist_ptr(xdrs, &objp->rmtinfo));
}

/*
 * One rpcb_stat structure is returned for each version of rpcbind
 * being monitored.
 */
bool_t
xdr_rpcb_stat_byvers(XDR *xdrs, rpcb_stat_byvers objp)
{
	return (xdr_vector(xdrs, (char *)objp, RPCBVERS_STAT,
		sizeof (rpcb_stat), (xdrproc_t)xdr_rpcb_stat));
}
