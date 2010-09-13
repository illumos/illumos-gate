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
#ident	"%Z%%M%	%I%	%E% SMI"
/*
 *    Copyright (c) 1995  Sun Microsystems, Inc
 *      All rights reserved.
 */

/*
 * This contains the xdr functions needed by ypserv and the NIS
 * administrative tools to support the previous version of the NIS protocol.
 * Note that many "old" xdr functions are called, with the assumption that
 * they have not changed between the v1 protocol (which this module exists
 * to support) and the current v2 protocol.
 */

#define	NULL 0
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include "ypv1_prot.h"
#include <rpcsvc/ypclnt.h>
typedef struct xdr_discrim XDR_DISCRIM;

extern bool xdr_ypreq_key();
extern bool xdr_ypreq_nokey();
extern bool xdr_ypresp_val();
extern bool xdr_ypresp_key_val();
extern bool xdr_ypmap_parms();


/*
 * Serializes/deserializes a yprequest structure.
 */
bool
_xdr_yprequest(XDR *xdrs, struct yprequest *ps)
{
	XDR_DISCRIM yprequest_arms[4];

	yprequest_arms[0].value = (int)YPREQ_KEY;
	yprequest_arms[1].value = (int)YPREQ_NOKEY;
	yprequest_arms[2].value = (int)YPREQ_KEY;
	yprequest_arms[3].value = __dontcare__;
	yprequest_arms[0].proc = (xdrproc_t)xdr_ypreq_key;
	yprequest_arms[1].proc = (xdrproc_t)xdr_ypreq_nokey;
	yprequest_arms[2].proc = (xdrproc_t)xdr_ypmap_parms;
	yprequest_arms[3].proc = (xdrproc_t)NULL;

	return (xdr_union(xdrs,
				(int *) &ps->yp_reqtype,
				(char *) &ps->yp_reqbody,
				yprequest_arms, NULL));
}

/*
 * Serializes/deserializes a ypresponse structure.
 */
bool
_xdr_ypresponse(XDR *xdrs, struct ypresponse *ps)
{
	XDR_DISCRIM ypresponse_arms[4];

	ypresponse_arms[0].value = (int)YPRESP_VAL;
	ypresponse_arms[1].value = (int)YPRESP_KEY_VAL;
	ypresponse_arms[2].value = (int)YPRESP_MAP_PARMS;
	ypresponse_arms[3].value = __dontcare__;
	ypresponse_arms[0].proc = (xdrproc_t)xdr_ypresp_val;
	ypresponse_arms[1].proc = (xdrproc_t)xdr_ypresp_key_val;
	ypresponse_arms[2].proc = (xdrproc_t)xdr_ypmap_parms;
	ypresponse_arms[3].proc = (xdrproc_t)NULL;

	return (xdr_union(xdrs,
				(int *) &ps->yp_resptype,
				(char *) &ps->yp_respbody,
				ypresponse_arms, NULL));
}

/* XXX - Excess baggage? - georgn */
#if	0
/*
 * Serializes/deserializes a ypbind_oldsetdom structure.
 */
bool
_xdr_ypbind_oldsetdom(XDR *xdrs, struct ypbind_setdom *ps)
{
	char *domain = ps->ypsetdom_domain;

	return (xdr_ypdomain_wrap_string(xdrs, &domain) &&
		xdr_yp_binding(xdrs, &ps->ypsetdom_binding));
}
#endif
