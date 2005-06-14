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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * This contains ALL xdr routines used by the YP rpc interface.
 */

#define	NULL 0
#include <rpc/rpc.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <stdlib.h>
#include <limits.h>

static bool xdr_ypmaplist(XDR *, struct ypmaplist **);
static bool xdr_ypmaplist_wrap_string(XDR *, char *);

typedef struct xdr_discrim XDR_DISCRIM;
bool xdr_ypreq_key(XDR *, struct ypreq_key *);
bool xdr_ypreq_nokey(XDR *, struct ypreq_nokey *);
bool xdr_ypresp_val(XDR *, struct ypresp_val *);
bool xdr_ypresp_key_val(XDR *, struct ypresp_key_val *);
bool xdr_ypmap_parms(XDR *, struct ypmap_parms *);
bool xdr_ypowner_wrap_string(XDR *, char **);
bool xdr_ypreq_newname_string(XDR *, char **);


/*
 * Serializes/deserializes a dbm datum data structure.
 */
bool
xdr_datum(xdrs, pdatum)
	XDR * xdrs;
	datum * pdatum;
{
	bool dummy;
	uint_t dsize;

	/*
	 * LP64 case :
	 * xdr_bytes() expects a uint_t for the 3rd argument. Since
	 * datum.dsize is a long, we need a new temporary to pass to
	 * xdr_bytes()
	 */
	trace1(TR_xdr_datum, 0);
	if (xdrs->x_op == XDR_ENCODE) {
		if (pdatum->dsize > UINT_MAX)
			return (FALSE);
	}
	dsize = (uint_t)pdatum->dsize;
	dummy = xdr_bytes(xdrs, (char **)&(pdatum->dptr), &dsize, YPMAXRECORD);
	if (xdrs->x_op == XDR_DECODE) {
		pdatum->dsize = dsize;
	}

	trace1(TR_xdr_datum, 1);
	return (dummy);
}


/*
 * Serializes/deserializes a domain name string.  This is a "wrapper" for
 * xdr_string which knows about the maximum domain name size.
 */
bool
xdr_ypdomain_wrap_string(xdrs, ppstring)
	XDR * xdrs;
	char **ppstring;
{
	bool dummy;

	trace1(TR_xdr_ypdomain_wrap_string, 0);
	dummy = xdr_string(xdrs, ppstring, YPMAXDOMAIN);
	trace1(TR_xdr_ypdomain_wrap_string, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a map name string.  This is a "wrapper" for
 * xdr_string which knows about the maximum map name size.
 */
bool
xdr_ypmap_wrap_string(xdrs, ppstring)
	XDR * xdrs;
	char **ppstring;
{
	bool dummy;

	trace1(TR_xdr_ypmap_wrap_string, 0);
	dummy = xdr_string(xdrs, ppstring, YPMAXMAP);
	trace1(TR_xdr_ypmap_wrap_string, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypreq_key structure.
 */
bool
xdr_ypreq_key(xdrs, ps)
	XDR *xdrs;
	struct ypreq_key *ps;
{
	bool dummy;

	trace1(TR_xdr_ypreq_key, 0);
	dummy =  xdr_ypdomain_wrap_string(xdrs, &ps->domain) &&
		    xdr_ypmap_wrap_string(xdrs, &ps->map) &&
		    xdr_datum(xdrs, &ps->keydat);
	trace1(TR_xdr_ypreq_key, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypreq_nokey structure.
 */
bool
xdr_ypreq_nokey(xdrs, ps)
	XDR * xdrs;
	struct ypreq_nokey *ps;
{
	bool dummy;

	trace1(TR_xdr_ypreq_nokey, 0);
	dummy = xdr_ypdomain_wrap_string(xdrs, &ps->domain) &&
		    xdr_ypmap_wrap_string(xdrs, &ps->map);
	trace1(TR_xdr_ypreq_nokey, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypresp_val structure.
 */

bool
xdr_ypresp_val(xdrs, ps)
	XDR * xdrs;
	struct ypresp_val *ps;
{
	bool dummy;

	trace1(TR_xdr_ypresp_val, 0);
	dummy = xdr_u_int(xdrs, &ps->status) &&
		    xdr_datum(xdrs, &ps->valdat);
	trace1(TR_xdr_ypresp_val, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypresp_key_val structure.
 */
bool
xdr_ypresp_key_val(xdrs, ps)
	XDR * xdrs;
	struct ypresp_key_val *ps;
{
	bool dummy;

	trace1(TR_xdr_ypresp_key_val, 0);
	dummy = xdr_u_int(xdrs, &ps->status) &&
	    xdr_datum(xdrs, &ps->valdat) &&
	    xdr_datum(xdrs, &ps->keydat);
	trace1(TR_xdr_ypresp_key_val, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a peer server's node name
 */
bool
xdr_ypowner_wrap_string(xdrs, ppstring)
	XDR * xdrs;
	char **ppstring;
{
	bool dummy;

	trace1(TR_xdr_ypowner_wrap_string, 0);
	dummy = xdr_string(xdrs, ppstring, YPMAXPEER);
	trace1(TR_xdr_ypowner_wrap_string, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypmap_parms structure.
 */
bool
xdr_ypmap_parms(xdrs, ps)
	XDR *xdrs;
	struct ypmap_parms *ps;
{
	bool dummy;

	trace1(TR_xdr_ypmap_parms, 0);
	dummy = xdr_ypdomain_wrap_string(xdrs, &ps->domain) &&
	    xdr_ypmap_wrap_string(xdrs, &ps->map) &&
	    xdr_u_int(xdrs, &ps->ordernum) &&
	    xdr_ypowner_wrap_string(xdrs, &ps->owner);
	trace1(TR_xdr_ypmap_parms, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypreq_newxfr name
 */
bool
xdr_ypreq_newname_string(xdrs, ppstring)
	XDR * xdrs;
	char **ppstring;
{
	bool dummy;

	trace1(TR_xdr_ypreq_newname_string, 0);
	dummy =  xdr_string(xdrs, ppstring, 256);
	trace1(TR_xdr_ypreq_newname_string, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypresp_master structure.
 */
bool
xdr_ypresp_master(xdrs, ps)
	XDR * xdrs;
	struct ypresp_master *ps;
{
	bool dummy;

	trace1(TR_xdr_ypresp_master, 0);
	dummy = xdr_u_int(xdrs, &ps->status) &&
	    xdr_ypowner_wrap_string(xdrs, &ps->master);
	trace1(TR_xdr_ypresp_master, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypresp_order structure.
 */
bool
xdr_ypresp_order(xdrs, ps)
	XDR * xdrs;
	struct ypresp_order *ps;
{
	bool dummy;

	trace1(TR_xdr_ypresp_order, 0);
	dummy =  xdr_u_int(xdrs, &ps->status) &&
	    xdr_u_int(xdrs, &ps->ordernum);
	trace1(TR_xdr_ypresp_order, 1);
	return (dummy);
}

/*
 * This is like xdr_ypmap_wrap_string except that it serializes/deserializes
 * an array, instead of a pointer, so xdr_reference can work on the structure
 * containing the char array itself.
 */
static bool
xdr_ypmaplist_wrap_string(xdrs, pstring)
	XDR * xdrs;
	char *pstring;
{
	char *s;
	bool dummy;


	trace1(TR_xdr_ypmaplist_wrap_string, 0);
	s = pstring;
	dummy = xdr_string(xdrs, &s, YPMAXMAP);
	trace1(TR_xdr_ypmaplist_wrap_string, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypmaplist.
 */
static bool
xdr_ypmaplist(xdrs, lst)
	XDR *xdrs;
	struct ypmaplist **lst;
{
	bool_t more_elements;
	int freeing = (xdrs->x_op == XDR_FREE);
	struct ypmaplist **next;

	trace1(TR_xdr_ypmaplist, 0);
	for (;;) {
		more_elements = (*lst != (struct ypmaplist *) NULL);

		if (! xdr_bool(xdrs, &more_elements)) {
			trace1(TR_xdr_ypmaplist, 1);
			return (FALSE);
		}

		if (! more_elements) {
			trace1(TR_xdr_ypmaplist, 1);
			return (TRUE);  /* All done */
		}

		if (freeing)
			next = &((*lst)->ypml_next);

		if (! xdr_reference(xdrs, (caddr_t *)lst,
			(u_int) sizeof (struct ypmaplist),
		    (xdrproc_t)xdr_ypmaplist_wrap_string)) {
			trace1(TR_xdr_ypmaplist, 1);
			return (FALSE);
		}

		lst = (freeing) ? next : &((*lst)->ypml_next);
	}
	/*NOTREACHED*/
}

/*
 * Serializes/deserializes a ypresp_maplist.
 */
bool
xdr_ypresp_maplist(xdrs, ps)
	XDR * xdrs;
	struct ypresp_maplist *ps;
{
	bool dummy;

	trace1(TR_xdr_ypresp_maplist, 0);
	dummy = xdr_u_int(xdrs, &ps->status) &&
		xdr_ypmaplist(xdrs, &ps->list);
	trace1(TR_xdr_ypresp_maplist, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a yppushresp_xfr structure.
 */
bool
xdr_yppushresp_xfr(xdrs, ps)
	XDR *xdrs;
	struct yppushresp_xfr *ps;
{
	bool dummy;

	trace1(TR_xdr_yppushresp_xfr, 0);
	dummy = xdr_u_int(xdrs, &ps->transid) &&
	    xdr_u_int(xdrs, &ps->status);
	trace1(TR_xdr_yppushresp_xfr, 1);
	return (dummy);
}


/*
 * Serializes/deserializes a ypreq_xfr structure.
 */
bool
xdr_ypreq_newxfr(xdrs, ps)
	XDR * xdrs;
	struct ypreq_newxfr *ps;
{
	bool dummy;

	trace1(TR_xdr_ypreq_newxfr, 0);
	dummy = xdr_ypmap_parms(xdrs, &ps->map_parms) &&
	    xdr_u_int(xdrs, &ps->transid) &&
	    xdr_u_int(xdrs, &ps->proto) &&
	    xdr_string(xdrs, &ps->name, 256);
	trace1(TR_xdr_ypreq_newxfr, 1);
	return (dummy);
}

/*
 * Serializes/deserializes a ypreq_xfr structure.
 */
bool
xdr_ypreq_xfr(xdrs, ps)
	XDR * xdrs;
	struct ypreq_xfr *ps;
{
	bool dummy;

	trace1(TR_xdr_ypreq_xfr, 0);
	dummy =  xdr_ypmap_parms(xdrs, &ps->map_parms) &&
	    xdr_u_int(xdrs, &ps->transid) &&
	    xdr_u_int(xdrs, &ps->proto) &&
	    xdr_u_short(xdrs, &ps->port);
	trace1(TR_xdr_ypreq_xfr, 1);
	return (dummy);
}


/*
 * Serializes/deserializes a stream of struct ypresp_key_val's.  This is used
 * only by the client side of the batch enumerate operation.
 */
bool
xdr_ypall(xdrs, callback)
	XDR * xdrs;
	struct ypall_callback *callback;
{
	bool_t more;
	struct ypresp_key_val kv;
	bool s;
	char keybuf[YPMAXRECORD];
	char valbuf[YPMAXRECORD];

	trace1(TR_xdr_ypall, 0);
	if (xdrs->x_op == XDR_ENCODE) {
		trace1(TR_xdr_ypall, 1);
		return (FALSE);
	}

	if (xdrs->x_op == XDR_FREE) {
		trace1(TR_xdr_ypall, 1);
		return (TRUE);
	}

	kv.keydat.dptr = keybuf;
	kv.valdat.dptr = valbuf;
	kv.keydat.dsize = YPMAXRECORD;
	kv.valdat.dsize = YPMAXRECORD;

	for (;;) {
		if (! xdr_bool(xdrs, &more)) {
			trace1(TR_xdr_ypall, 1);
			return (FALSE);
		}

		if (! more) {
			trace1(TR_xdr_ypall, 1);
			return (TRUE);
		}

		s = xdr_ypresp_key_val(xdrs, &kv);

		if (s) {
			s = (*callback->foreach)(kv.status, kv.keydat.dptr,
			    kv.keydat.dsize, kv.valdat.dptr, kv.valdat.dsize,
			    callback->data);

			if (s) {
				trace1(TR_xdr_ypall, 1);
				return (TRUE);
			}
		} else {
			trace1(TR_xdr_ypall, 1);
			return (FALSE);
		}
	}
}

bool_t
xdr_netconfig(xdrs, objp)
	XDR *xdrs;
	struct netconfig *objp;
{

	trace1(TR_xdr_netconfig, 0);
	if (!xdr_string(xdrs, &objp->nc_netid, ~0)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->nc_semantics)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->nc_flag)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->nc_protofmly, ~0)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->nc_proto, ~0)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->nc_device, ~0)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	if (!xdr_array(xdrs, (char **) &objp->nc_lookups,
		(u_int *)&objp->nc_nlookups, 100, sizeof (char *),
		xdr_wrapstring)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	if (!xdr_vector(xdrs, (char *)objp->nc_unused,
		8, sizeof (u_int), xdr_u_int)) {
		trace1(TR_xdr_netconfig, 1);
		return (FALSE);
	}
	trace1(TR_xdr_netconfig, 1);
	return (TRUE);
}
