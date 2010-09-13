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

/*
 * This contains ALL xdr routines used by the YP rpc interface.
 */

#include "mt.h"
#include <unistd.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/types.h>
#include <limits.h>

static bool xdr_ypmaplist(XDR *, struct ypmaplist **);
static bool xdr_ypmaplist_wrap_string(XDR *, char *);

typedef struct xdr_discrim XDR_DISCRIM;
extern bool xdr_ypreq_key(XDR *, struct ypreq_key *);
extern bool xdr_ypreq_nokey(XDR *, struct ypreq_nokey *);
extern bool xdr_ypresp_val(XDR *, struct ypresp_val *);
extern bool xdr_ypresp_key_val(XDR *, struct ypresp_key_val *);
extern bool xdr_ypmap_parms(XDR *, struct ypmap_parms *);
extern bool xdr_ypowner_wrap_string(XDR *, char **);
extern bool xdr_ypreq_newname_string(XDR *, char **);


/*
 * Serializes/deserializes a dbm datum data structure.
 */
bool
xdr_datum(XDR *xdrs, datum *pdatum)
{
	bool res;
	uint_t dsize;

	/*
	 * LP64 case :
	 * xdr_bytes() expects a uint_t for the 3rd argument. Since
	 * datum.dsize is a long, we need a new temporary to pass to
	 * xdr_bytes()
	 */
	if (xdrs->x_op == XDR_ENCODE) {
		if (pdatum->dsize > UINT_MAX)
			return (FALSE);
	}
	dsize = (uint_t)pdatum->dsize;
	res = (bool)xdr_bytes(xdrs, (char **)&(pdatum->dptr), &dsize,
								YPMAXRECORD);
	if (xdrs->x_op == XDR_DECODE) {
		pdatum->dsize = dsize;
	}

	return (res);
}


/*
 * Serializes/deserializes a domain name string.  This is a "wrapper" for
 * xdr_string which knows about the maximum domain name size.
 */
bool
xdr_ypdomain_wrap_string(XDR *xdrs, char **ppstring)
{
	return ((bool)xdr_string(xdrs, ppstring, YPMAXDOMAIN));
}

/*
 * Serializes/deserializes a map name string.  This is a "wrapper" for
 * xdr_string which knows about the maximum map name size.
 */
bool
xdr_ypmap_wrap_string(XDR *xdrs, char **ppstring)
{
	return ((bool)xdr_string(xdrs, ppstring, YPMAXMAP));
}

/*
 * Serializes/deserializes a ypreq_key structure.
 */
bool
xdr_ypreq_key(XDR *xdrs, struct ypreq_key *ps)
{
	return ((bool)(xdr_ypdomain_wrap_string(xdrs, &ps->domain) &&
		    xdr_ypmap_wrap_string(xdrs, &ps->map) &&
		    xdr_datum(xdrs, &ps->keydat)));
}

/*
 * Serializes/deserializes a ypreq_nokey structure.
 */
bool
xdr_ypreq_nokey(XDR *xdrs, struct ypreq_nokey *ps)
{
	return ((bool)(xdr_ypdomain_wrap_string(xdrs, &ps->domain) &&
		    xdr_ypmap_wrap_string(xdrs, &ps->map)));
}

/*
 * Serializes/deserializes a ypresp_val structure.
 */
bool
xdr_ypresp_val(XDR *xdrs, struct ypresp_val *ps)
{
	return ((bool)(xdr_u_int(xdrs, &ps->status) &&
		    xdr_datum(xdrs, &ps->valdat)));
}

/*
 * Serializes/deserializes a ypresp_key_val structure.
 */
bool
xdr_ypresp_key_val(XDR *xdrs, struct ypresp_key_val *ps)
{
	return ((bool)(xdr_u_int(xdrs, &ps->status) &&
	    xdr_datum(xdrs, &ps->valdat) &&
	    xdr_datum(xdrs, &ps->keydat)));
}

/*
 * Serializes/deserializes a peer server's node name
 */
bool
xdr_ypowner_wrap_string(XDR *xdrs, char **ppstring)
{
	return ((bool)xdr_string(xdrs, ppstring, YPMAXPEER));
}

/*
 * Serializes/deserializes a ypmap_parms structure.
 */
bool
xdr_ypmap_parms(XDR *xdrs, struct ypmap_parms *ps)
{
	return ((bool)(xdr_ypdomain_wrap_string(xdrs, &ps->domain) &&
	    xdr_ypmap_wrap_string(xdrs, &ps->map) &&
	    xdr_u_int(xdrs, &ps->ordernum) &&
	    xdr_ypowner_wrap_string(xdrs, &ps->owner)));
}

/*
 * Serializes/deserializes a ypreq_newxfr name
 */
bool
xdr_ypreq_newname_string(XDR *xdrs, char **ppstring)
{
	return ((bool)xdr_string(xdrs, ppstring, 256));
}

/*
 * Serializes/deserializes a ypresp_master structure.
 */
bool
xdr_ypresp_master(XDR *xdrs, struct ypresp_master *ps)
{
	return ((bool)(xdr_u_int(xdrs, &ps->status) &&
	    xdr_ypowner_wrap_string(xdrs, &ps->master)));
}

/*
 * Serializes/deserializes a ypresp_order structure.
 */
bool
xdr_ypresp_order(XDR *xdrs, struct ypresp_order *ps)
{
	return ((bool)(xdr_u_int(xdrs, &ps->status) &&
	    xdr_u_int(xdrs, &ps->ordernum)));
}

/*
 * This is like xdr_ypmap_wrap_string except that it serializes/deserializes
 * an array, instead of a pointer, so xdr_reference can work on the structure
 * containing the char array itself.
 */
static bool
xdr_ypmaplist_wrap_string(XDR *xdrs, char *pstring)
{
	char *s;

	s = pstring;
	return ((bool)xdr_string(xdrs, &s, YPMAXMAP));
}

/*
 * Serializes/deserializes a ypmaplist.
 */
static bool
xdr_ypmaplist(XDR *xdrs, struct ypmaplist **lst)
{
	bool_t more_elements;
	int freeing = (xdrs->x_op == XDR_FREE);
	struct ypmaplist **next;

	for (;;) {
		more_elements = (*lst != NULL);

		if (!xdr_bool(xdrs, &more_elements))
			return (FALSE);

		if (!more_elements)
			return (TRUE);  /* All done */

		if (freeing)
			next = &((*lst)->ypml_next);

		if (!xdr_reference(xdrs, (caddr_t *)lst,
			(uint_t)sizeof (struct ypmaplist),
		    (xdrproc_t)xdr_ypmaplist_wrap_string))
			return (FALSE);

		lst = (freeing) ? next : &((*lst)->ypml_next);
	}
	/*NOTREACHED*/
}

/*
 * Serializes/deserializes a ypresp_maplist.
 */
bool
xdr_ypresp_maplist(XDR *xdrs, struct ypresp_maplist *ps)
{
	return ((bool)(xdr_u_int(xdrs, &ps->status) &&
		xdr_ypmaplist(xdrs, &ps->list)));
}

/*
 * Serializes/deserializes a yppushresp_xfr structure.
 */
bool
xdr_yppushresp_xfr(XDR *xdrs, struct yppushresp_xfr *ps)
{
	return ((bool)(xdr_u_int(xdrs, &ps->transid) &&
	    xdr_u_int(xdrs, &ps->status)));
}


/*
 * Serializes/deserializes a ypreq_xfr structure.
 */
bool
xdr_ypreq_newxfr(XDR *xdrs, struct ypreq_newxfr *ps)
{
	return ((bool)(xdr_ypmap_parms(xdrs, &ps->map_parms) &&
	    xdr_u_int(xdrs, &ps->transid) &&
	    xdr_u_int(xdrs, &ps->proto) &&
	    xdr_string(xdrs, &ps->name, 256)));
}

/*
 * Serializes/deserializes a ypreq_xfr structure.
 */
bool
xdr_ypreq_xfr(XDR *xdrs, struct ypreq_xfr *ps)
{
	return ((bool)(xdr_ypmap_parms(xdrs, &ps->map_parms) &&
	    xdr_u_int(xdrs, &ps->transid) &&
	    xdr_u_int(xdrs, &ps->proto) &&
	    xdr_u_short(xdrs, &ps->port)));
}


/*
 * Serializes/deserializes a stream of struct ypresp_key_val's.  This is used
 * only by the client side of the batch enumerate operation.
 */
bool
xdr_ypall(XDR *xdrs, struct ypall_callback *callback)
{
	bool_t more;
	struct ypresp_key_val kv;
	char keybuf[YPMAXRECORD];
	char valbuf[YPMAXRECORD];

	if (xdrs->x_op == XDR_ENCODE)
		return (FALSE);

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	kv.keydat.dptr = keybuf;
	kv.valdat.dptr = valbuf;
	kv.keydat.dsize = YPMAXRECORD;
	kv.valdat.dsize = YPMAXRECORD;

	for (;;) {
		if (!xdr_bool(xdrs, &more))
			return (FALSE);

		if (!more)
			return (TRUE);

		if (!xdr_ypresp_key_val(xdrs, &kv))
			return (FALSE);
		if ((*callback->foreach)(kv.status, kv.keydat.dptr,
			    kv.keydat.dsize, kv.valdat.dptr, kv.valdat.dsize,
			    callback->data))
			return (TRUE);
	}
}

bool_t
xdr_netconfig(XDR *xdrs, struct netconfig *objp)
{
	if (!xdr_string(xdrs, &objp->nc_netid, ~0))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->nc_semantics))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->nc_flag))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->nc_protofmly, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->nc_proto, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->nc_device, ~0))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->nc_lookups,
		(uint_t *)&objp->nc_nlookups, 100, sizeof (char *),
		xdr_wrapstring))
		return (FALSE);
	return ((bool)xdr_vector(xdrs, (char *)objp->nc_unused,
		8, sizeof (uint_t), xdr_u_int));
}
