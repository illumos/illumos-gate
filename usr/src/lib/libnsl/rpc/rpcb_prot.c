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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rpcb_prot.c
 * XDR routines for the rpcbinder version 3.
 *
 */

#include <rpc/rpc.h>
#include <rpc/trace.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/rpcb_prot.h>


bool_t
xdr_rpcb(xdrs, objp)
	XDR *xdrs;
	RPCB *objp;
{
	trace1(TR_xdr_rpcb, 0);
	if (!xdr_u_int(xdrs, (u_int *)&objp->r_prog)) {
		trace1(TR_xdr_rpcb, 1);
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, (u_int *)&objp->r_vers)) {
		trace1(TR_xdr_rpcb, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_netid, ~0)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_addr, ~0)) {
		trace1(TR_xdr_rpcb, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_owner, ~0)) {
		trace1(TR_xdr_rpcb, 1);
		return (FALSE);
	}
	trace1(TR_xdr_rpcb, 1);
	return (TRUE);
}

/*
 * rpcblist_ptr implements a linked list.  The RPCL definition from
 * rpcb_prot.x is:
 *
 * struct rpcblist {
 * 	rpcb		rpcb_map;
 *	struct rpcblist *rpcb_next;
 * };
 * typedef rpcblist *rpcblist_ptr;
 *
 * Recall that "pointers" in XDR are encoded as a boolean, indicating whether
 * there's any data behind the pointer, followed by the data (if any exists).
 * The boolean can be interpreted as ``more data follows me''; if FALSE then
 * nothing follows the boolean; if TRUE then the boolean is followed by an
 * actual struct rpcb, and another rpcblist_ptr (declared in RPCL as "struct
 * rpcblist *").
 *
 * This could be implemented via the xdr_pointer type, though this would
 * result in one recursive call per element in the list.  Rather than do that
 * we can ``unwind'' the recursion into a while loop and use xdr_reference to
 * serialize the rpcb elements.
 */

bool_t
xdr_rpcblist_ptr(xdrs, rp)
	register XDR *xdrs;
	register rpcblist_ptr *rp;
{
	/*
	 * more_elements is pre-computed in case the direction is
	 * XDR_ENCODE or XDR_FREE.  more_elements is overwritten by
	 * xdr_bool when the direction is XDR_DECODE.
	 */
	bool_t more_elements;
	register int freeing = (xdrs->x_op == XDR_FREE);
	rpcblist_ptr next;
	rpcblist_ptr next_copy;

	trace1(TR_xdr_rpcblist_ptr, 0);
	/*CONSTANTCONDITION*/
	while (TRUE) {
		more_elements = (bool_t)(*rp != NULL);
		if (! xdr_bool(xdrs, &more_elements)) {
			trace1(TR_xdr_rpcblist_ptr, 1);
			return (FALSE);
		}
		if (! more_elements) {
			trace1(TR_xdr_rpcblist_ptr, 1);
			return (TRUE);  /* we are done */
		}
		/*
		 * the unfortunate side effect of non-recursion is that in
		 * the case of freeing we must remember the next object
		 * before we free the current object ...
		 */
		if (freeing)
			next = (*rp)->rpcb_next;
		if (! xdr_reference(xdrs, (caddr_t *)rp,
		    (u_int) sizeof (rpcblist), (xdrproc_t)xdr_rpcb)) {
			trace1(TR_xdr_rpcblist_ptr, 1);
			return (FALSE);
		}
		if (freeing) {
			next_copy = next;
			rp = &next_copy;
			/*
			 * Note that in the subsequent iteration, next_copy
			 * gets nulled out by the xdr_reference
			 * but next itself survives.
			 */
		} else {
			rp = &((*rp)->rpcb_next);
		}
	}
	/*NOTREACHED*/
}

/*
 * xdr_rpcblist() is specified to take a RPCBLIST **, but is identical in
 * functionality to xdr_rpcblist_ptr().
 */
bool_t
xdr_rpcblist(xdrs, rp)
	register XDR *xdrs;
	register RPCBLIST **rp;
{
	bool_t	dummy;

	dummy = xdr_rpcblist_ptr(xdrs, (rpcblist_ptr *)rp);
	return (dummy);
}


bool_t
xdr_rpcb_entry(xdrs, objp)
	XDR *xdrs;
	rpcb_entry *objp;
{
	trace1(TR_xdr_rpcb_entry, 0);
	if (!xdr_string(xdrs, &objp->r_maddr, ~0)) {
		trace1(TR_xdr_rpcb_entry, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_nc_netid, ~0)) {
		trace1(TR_xdr_rpcb_entry, 1);
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->r_nc_semantics)) {
		trace1(TR_xdr_rpcb_entry, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_nc_protofmly, ~0)) {
		trace1(TR_xdr_rpcb_entry, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_nc_proto, ~0)) {
		trace1(TR_xdr_rpcb_entry, 1);
		return (FALSE);
	}
	trace1(TR_xdr_rpcb_entry, 1);
	return (TRUE);
}

bool_t
xdr_rpcb_entry_list_ptr(xdrs, rp)
	register XDR *xdrs;
	register rpcb_entry_list_ptr *rp;
{
	/*
	 * more_elements is pre-computed in case the direction is
	 * XDR_ENCODE or XDR_FREE.  more_elements is overwritten by
	 * xdr_bool when the direction is XDR_DECODE.
	 */
	bool_t more_elements;
	register int freeing = (xdrs->x_op == XDR_FREE);
	rpcb_entry_list_ptr next;
	rpcb_entry_list_ptr next_copy;

	trace1(TR_xdr_rpcb_entry_list_ptr, 0);
	/*CONSTANTCONDITION*/
	while (TRUE) {
		more_elements = (bool_t)(*rp != NULL);
		if (! xdr_bool(xdrs, &more_elements)) {
			trace1(TR_xdr_rpcb_entry_list, 1);
			return (FALSE);
		}
		if (! more_elements) {
			trace1(TR_xdr_rpcb_entry_list, 1);
			return (TRUE);  /* we are done */
		}
		/*
		 * the unfortunate side effect of non-recursion is that in
		 * the case of freeing we must remember the next object
		 * before we free the current object ...
		 */
		if (freeing)
			next = (*rp)->rpcb_entry_next;
		if (! xdr_reference(xdrs, (caddr_t *)rp,
		    (u_int) sizeof (rpcb_entry_list),
				    (xdrproc_t)xdr_rpcb_entry)) {
			trace1(TR_xdr_rpcb_entry_list, 1);
			return (FALSE);
		}
		if (freeing) {
			next_copy = next;
			rp = &next_copy;
			/*
			 * Note that in the subsequent iteration, next_copy
			 * gets nulled out by the xdr_reference
			 * but next itself survives.
			 */
		} else {
			rp = &((*rp)->rpcb_entry_next);
		}
	}
	/*NOTREACHED*/
}

/*
 * XDR remote call arguments
 * written for XDR_ENCODE direction only
 */
bool_t
xdr_rpcb_rmtcallargs(xdrs, objp)
	XDR *xdrs;
	struct r_rpcb_rmtcallargs *objp;
{
	u_int lenposition, argposition, position;
	register rpc_inline_t *buf;

	trace1(TR_xdr_rpcb_rmtcallargs, 0);
	buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT);
	if (buf == NULL) {
		if (!xdr_u_int(xdrs, (u_int *)&objp->prog)) {
			trace1(TR_xdr_rpcb_rmtcallargs, 1);
			return (FALSE);
		}
		if (!xdr_u_int(xdrs, (u_int *)&objp->vers)) {
			trace1(TR_xdr_rpcb_rmtcallargs, 1);
			return (FALSE);
		}
		if (!xdr_u_int(xdrs, (u_int *)&objp->proc)) {
			trace1(TR_xdr_rpcb_rmtcallargs, 1);
			return (FALSE);
		}
	} else {
		IXDR_PUT_U_INT32(buf, objp->prog);
		IXDR_PUT_U_INT32(buf, objp->vers);
		IXDR_PUT_U_INT32(buf, objp->proc);
	}

	/*
	 * All the jugglery for just getting the size of the arguments
	 */
	lenposition = XDR_GETPOS(xdrs);
	if (! xdr_u_int(xdrs, &(objp->args.args_len))) {
		trace1(TR_xdr_rpcb_rmtcallargs, 1);
		return (FALSE);
	}
	argposition = XDR_GETPOS(xdrs);
	if (! (*objp->xdr_args)(xdrs, objp->args.args_val)) {
		trace1(TR_xdr_rpcb_rmtcallargs, 1);
		return (FALSE);
	}
	position = XDR_GETPOS(xdrs);
	objp->args.args_len = (u_int)position - (u_int)argposition;
	XDR_SETPOS(xdrs, lenposition);
	if (! xdr_u_int(xdrs, &(objp->args.args_len))) {
		trace1(TR_xdr_rpcb_rmtcallargs, 1);
		return (FALSE);
	}
	XDR_SETPOS(xdrs, position);
	trace1(TR_xdr_rpcb_rmtcallargs, 1);
	return (TRUE);
}

/*
 * XDR remote call results
 * written for XDR_DECODE direction only
 */
bool_t
xdr_rpcb_rmtcallres(xdrs, objp)
	XDR *xdrs;
	struct r_rpcb_rmtcallres *objp;
{
	bool_t dummy;

	trace1(TR_xdr_rpcb_rmtcallres, 0);
	if (!xdr_string(xdrs, &objp->addr, ~0)) {
		trace1(TR_xdr_rpcb_rmtcallres, 1);
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->results.results_len)) {
		trace1(TR_xdr_rpcb_rmtcallres, 1);
		return (FALSE);
	}
	dummy = (*(objp->xdr_res))(xdrs, objp->results.results_val);
	trace1(TR_xdr_rpcb_rmtcallres, 1);
	return (dummy);
}

bool_t
xdr_netbuf(xdrs, objp)
	XDR *xdrs;
	struct netbuf *objp;
{
	bool_t dummy;

	trace1(TR_xdr_netbuf, 0);
	if (!xdr_u_int(xdrs, (u_int *) &objp->maxlen)) {
		trace1(TR_xdr_netbuf, 1);
		return (FALSE);
	}
	dummy = xdr_bytes(xdrs, (char **)&(objp->buf),
			(u_int *)&(objp->len), objp->maxlen);
	trace1(TR_xdr_netbuf, 1);
	return (dummy);
}
