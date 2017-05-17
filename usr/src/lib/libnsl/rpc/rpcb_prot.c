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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * XDR routines for the rpcbinder version 3.
 */

#include "mt.h"
#include <rpc/rpc.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/rpcb_prot.h>


bool_t
xdr_rpcb(XDR *xdrs, RPCB *objp)
{
	if (!xdr_u_int(xdrs, (uint_t *)&objp->r_prog))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->r_vers))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->r_netid, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->r_addr, ~0))
		return (FALSE);
	return (xdr_string(xdrs, &objp->r_owner, ~0));
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
xdr_rpcblist_ptr(XDR *xdrs, rpcblist_ptr *rp)
{
	/*
	 * more_elements is pre-computed in case the direction is
	 * XDR_ENCODE or XDR_FREE.  more_elements is overwritten by
	 * xdr_bool when the direction is XDR_DECODE.
	 */
	bool_t more_elements;
	int freeing = (xdrs->x_op == XDR_FREE);
	rpcblist_ptr next;
	rpcblist_ptr next_copy;

	for (;;) {
		more_elements = (bool_t)(*rp != NULL);
		if (!xdr_bool(xdrs, &more_elements))
			return (FALSE);
		if (!more_elements)
			return (TRUE);  /* we are done */
		/*
		 * the unfortunate side effect of non-recursion is that in
		 * the case of freeing we must remember the next object
		 * before we free the current object ...
		 */
		if (freeing)
			next = (*rp)->rpcb_next;
		if (!xdr_reference(xdrs, (caddr_t *)rp,
		    (uint_t)sizeof (rpcblist), (xdrproc_t)xdr_rpcb))
			return (FALSE);
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
xdr_rpcblist(XDR *xdrs, RPCBLIST **rp)
{
	return (xdr_rpcblist_ptr(xdrs, (rpcblist_ptr *)rp));
}


bool_t
xdr_rpcb_entry(XDR *xdrs, rpcb_entry *objp)
{
	if (!xdr_string(xdrs, &objp->r_maddr, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->r_nc_netid, ~0))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->r_nc_semantics))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->r_nc_protofmly, ~0))
		return (FALSE);
	return (xdr_string(xdrs, &objp->r_nc_proto, ~0));
}

bool_t
xdr_rpcb_entry_list_ptr(XDR *xdrs, rpcb_entry_list_ptr *rp)
{
	/*
	 * more_elements is pre-computed in case the direction is
	 * XDR_ENCODE or XDR_FREE.  more_elements is overwritten by
	 * xdr_bool when the direction is XDR_DECODE.
	 */
	bool_t more_elements;
	int freeing = (xdrs->x_op == XDR_FREE);
	rpcb_entry_list_ptr next;
	rpcb_entry_list_ptr next_copy;

	for (;;) {
		more_elements = (bool_t)(*rp != NULL);
		if (!xdr_bool(xdrs, &more_elements))
			return (FALSE);
		if (!more_elements)
			return (TRUE);  /* we are done */
		/*
		 * the unfortunate side effect of non-recursion is that in
		 * the case of freeing we must remember the next object
		 * before we free the current object ...
		 */
		if (freeing)
			next = (*rp)->rpcb_entry_next;
		if (!xdr_reference(xdrs, (caddr_t *)rp,
		    (uint_t)sizeof (rpcb_entry_list),
		    (xdrproc_t)xdr_rpcb_entry))
			return (FALSE);
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
xdr_rpcb_rmtcallargs(XDR *xdrs, struct r_rpcb_rmtcallargs *objp)
{
	uint_t lenposition, argposition, position;
	rpc_inline_t *buf;

	buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT);
	if (buf == NULL) {
		if (!xdr_u_int(xdrs, (uint_t *)&objp->prog))
			return (FALSE);
		if (!xdr_u_int(xdrs, (uint_t *)&objp->vers))
			return (FALSE);
		if (!xdr_u_int(xdrs, (uint_t *)&objp->proc))
			return (FALSE);
	} else {
		IXDR_PUT_U_INT32(buf, objp->prog);
		IXDR_PUT_U_INT32(buf, objp->vers);
		IXDR_PUT_U_INT32(buf, objp->proc);
	}

	/*
	 * All the jugglery for just getting the size of the arguments
	 */
	lenposition = XDR_GETPOS(xdrs);
	if (!xdr_u_int(xdrs, &(objp->args.args_len)))
		return (FALSE);
	argposition = XDR_GETPOS(xdrs);
	if (!(*objp->xdr_args)(xdrs, objp->args.args_val))
		return (FALSE);
	position = XDR_GETPOS(xdrs);
	objp->args.args_len = (uint_t)position - (uint_t)argposition;
	XDR_SETPOS(xdrs, lenposition);
	if (!xdr_u_int(xdrs, &(objp->args.args_len)))
		return (FALSE);
	XDR_SETPOS(xdrs, position);
	return (TRUE);
}

/*
 * XDR remote call results
 * written for XDR_DECODE direction only
 */
bool_t
xdr_rpcb_rmtcallres(XDR *xdrs, struct r_rpcb_rmtcallres *objp)
{
	if (!xdr_string(xdrs, &objp->addr, ~0))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->results.results_len))
		return (FALSE);
	return ((*(objp->xdr_res))(xdrs, objp->results.results_val));
}

bool_t
xdr_netbuf(XDR *xdrs, struct netbuf *objp)
{
	bool_t res;

	/*
	 * Save the passed in maxlen value and buf pointer.  We might
	 * need them later.
	 */
	uint_t maxlen_save = objp->maxlen;
	void *buf_save = objp->buf;

	if (!xdr_u_int(xdrs, &objp->maxlen))
		return (FALSE);

	/*
	 * We need to free maxlen, not len, so do it explicitly now.
	 */
	if (xdrs->x_op == XDR_FREE)
		return (xdr_bytes(xdrs, &objp->buf, &objp->maxlen,
		    objp->maxlen));

	/*
	 * If we're decoding and the caller has already allocated a
	 * buffer restore the maxlen value since the decoded value
	 * doesn't apply to the caller's buffer.  xdr_bytes() will
	 * return an error if the buffer isn't big enough.
	 */
	if (xdrs->x_op == XDR_DECODE && objp->buf != NULL)
		objp->maxlen = maxlen_save;

	res = xdr_bytes(xdrs, &objp->buf, &objp->len, objp->maxlen);

	/*
	 * If we are decoding and the buffer was allocated in the
	 * xdr_bytes() function we need to set maxlen properly to
	 * follow the netbuf semantics.
	 */
	if (xdrs->x_op == XDR_DECODE && objp->buf != buf_save)
		objp->maxlen = objp->len;

	return (res);
}
