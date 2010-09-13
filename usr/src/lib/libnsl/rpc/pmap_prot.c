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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Protocol for the local binder service, or pmap.
 * All the pmap xdr routines here.
 */

#include "mt.h"
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_rmt.h>

bool_t
xdr_pmap(XDR *xdrs, struct pmap *objp)
{
	rpc_inline_t *buf;

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		buf = XDR_INLINE(xdrs, 4 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->pm_prog))
				return (FALSE);
			if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->pm_vers))
				return (FALSE);
			if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->pm_prot))
				return (FALSE);
			if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->pm_port))
				return (FALSE);
		} else {
			IXDR_PUT_U_INT32(buf, objp->pm_prog);
			IXDR_PUT_U_INT32(buf, objp->pm_vers);
			IXDR_PUT_U_INT32(buf, objp->pm_prot);
			IXDR_PUT_U_INT32(buf, objp->pm_port);
		}
		return (TRUE);
	case XDR_DECODE:
		buf = XDR_INLINE(xdrs, 4 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!XDR_GETINT32(xdrs, (int32_t *)&objp->pm_prog))
				return (FALSE);
			if (!XDR_GETINT32(xdrs, (int32_t *)&objp->pm_vers))
				return (FALSE);
			if (!XDR_GETINT32(xdrs, (int32_t *)&objp->pm_prot))
				return (FALSE);
			if (!XDR_GETINT32(xdrs, (int32_t *)&objp->pm_port))
				return (FALSE);
		} else {
			objp->pm_prog = IXDR_GET_U_INT32(buf);
			objp->pm_vers = IXDR_GET_U_INT32(buf);
			objp->pm_prot = IXDR_GET_U_INT32(buf);
			objp->pm_port = IXDR_GET_U_INT32(buf);
		}
		return (TRUE);
	case XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
}

/*
 * pmaplist_ptr implements a linked list.  The RPCL definition from
 * pmap_prot.x is:
 *
 * struct pm__list {
 * 	pmap		pml_map;
 *	struct pm__list *pml_next;
 * };
 * typedef pm__list *pmaplist_ptr;
 *
 * Recall that "pointers" in XDR are encoded as a boolean, indicating whether
 * there's any data behind the pointer, followed by the data (if any exists).
 * The boolean can be interpreted as ``more data follows me''; if FALSE then
 * nothing follows the boolean; if TRUE then the boolean is followed by an
 * actual struct pmap, and another pmaplist_ptr (declared in RPCL as "struct
 * pmaplist *").
 *
 * This could be implemented via the xdr_pointer type, though this would
 * result in one recursive call per element in the list.  Rather than do that
 * we can ``unwind'' the recursion into a while loop and use xdr_reference to
 * serialize the pmap elements.
 */
bool_t
xdr_pmaplist_ptr(XDR *xdrs, pmaplist_ptr *rp)
{
	/*
	 * more_elements is pre-computed in case the direction is
	 * XDR_ENCODE or XDR_FREE.  more_elements is overwritten by
	 * xdr_bool when the direction is XDR_DECODE.
	 */
	bool_t more_elements;
	int freeing = (xdrs->x_op == XDR_FREE);
	pmaplist_ptr next;
	pmaplist_ptr next_copy;

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
			next = (*rp)->pml_next;
		if (!xdr_reference(xdrs, (caddr_t *)rp,
		    (uint_t)sizeof (struct pmaplist), (xdrproc_t)xdr_pmap))
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
			rp = &((*rp)->pml_next);
		}
	}
	/*NOTREACHED*/
}

/*
 * xdr_pmaplist() is specified to take a PMAPLIST **, but is identical in
 * functionality to xdr_pmaplist_ptr().
 */
bool_t
xdr_pmaplist(XDR *xdrs, PMAPLIST **rp)
{
	return (xdr_pmaplist_ptr(xdrs, (pmaplist_ptr *)rp));
}


/*
 * XDR remote call arguments
 * written for XDR_ENCODE direction only
 */
bool_t
xdr_rmtcallargs(XDR *xdrs, struct p_rmtcallargs *cap)
{
	uint_t lenposition, argposition, position;
	rpc_inline_t *buf;

	buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT);
	if (buf == NULL) {
		if (!xdr_u_int(xdrs, (uint_t *)&(cap->prog)) ||
		    !xdr_u_int(xdrs, (uint_t *)&(cap->vers)) ||
		    !xdr_u_int(xdrs, (uint_t *)&(cap->proc)))
			return (FALSE);
	} else {
		IXDR_PUT_U_INT32(buf, cap->prog);
		IXDR_PUT_U_INT32(buf, cap->vers);
		IXDR_PUT_U_INT32(buf, cap->proc);
	}

	/*
	 * All the jugglery for just getting the size of the arguments
	 */
	lenposition = XDR_GETPOS(xdrs);
	if (!xdr_u_int(xdrs, &(cap->args.args_len)))
		return (FALSE);
	argposition = XDR_GETPOS(xdrs);
	if (!(*cap->xdr_args)(xdrs, cap->args.args_val))
		return (FALSE);
	position = XDR_GETPOS(xdrs);
	cap->args.args_len = position - argposition;
	XDR_SETPOS(xdrs, lenposition);
	if (!xdr_u_int(xdrs, &(cap->args.args_len)))
		return (FALSE);
	XDR_SETPOS(xdrs, position);
	return (TRUE);
}

/*
 * XDR remote call results
 * written for XDR_DECODE direction only
 */
bool_t
xdr_rmtcallres(XDR *xdrs, struct p_rmtcallres *crp)
{
	if (xdr_u_int(xdrs, (uint_t *)&crp->port) &&
	    xdr_u_int(xdrs, &crp->res.res_len))
		return ((*(crp->xdr_res))(xdrs, crp->res.res_val));
	return (FALSE);
}
