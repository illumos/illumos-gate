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
#include <stdlib.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/types.h>
#include <string.h>

static int doorder(char *, char *, struct dom_binding *, struct timeval,
    unsigned long *);


/*
 * This checks parameters, and implements the outer "until binding success"
 * loop.
 */
int
yp_order(char *domain, char *map, unsigned long *order)
{
	size_t domlen;
	size_t maplen;
	int reason;
	struct dom_binding *pdomb;

	if ((map == NULL) || (domain == NULL))
		return (YPERR_BADARGS);

	domlen = strlen(domain);
	maplen = strlen(map);

	if ((domlen == 0) || (domlen > YPMAXDOMAIN) ||
	    (maplen == 0) || (maplen > YPMAXMAP) ||
	    (order == NULL))
		return (YPERR_BADARGS);

	for (;;) {

		if (reason = __yp_dobind(domain, &pdomb))
			return (reason);

		if (pdomb->dom_binding->ypbind_hi_vers >= YPVERS) {

			reason = doorder(domain, map, pdomb, _ypserv_timeout,
			    order);

			__yp_rel_binding(pdomb);
			if (reason == YPERR_RPC) {
				yp_unbind(domain);
				(void) sleep(_ypsleeptime);
			} else {
				break;
			}
		} else {
			__yp_rel_binding(pdomb);
			return (YPERR_VERS);
		}
	}

	return (reason);
}

/*
 * This talks v3 to ypserv
 */
static int
doorder(char *domain, char *map, struct dom_binding *pdomb,
				struct timeval timeout, unsigned long *order)
{
	struct ypreq_nokey req;
	struct ypresp_order resp;
	unsigned int retval = 0;

	req.domain = domain;
	req.map = map;
	(void) memset((char *)&resp, 0, sizeof (struct ypresp_order));

	/*
	 * Do the get_order request.  If the rpc call failed, return with
	 * status from this point.
	 */

	if (clnt_call(pdomb->dom_client, YPPROC_ORDER,
			(xdrproc_t)xdr_ypreq_nokey,
		    (char *)&req, (xdrproc_t)xdr_ypresp_order, (char *)&resp,
		    timeout) != RPC_SUCCESS)
		return (YPERR_RPC);

	/* See if the request succeeded */

	if (resp.status != YP_TRUE) {
		retval = ypprot_err(resp.status);
	}

	*order = (unsigned long)resp.ordernum;
	CLNT_FREERES(pdomb->dom_client,
		(xdrproc_t)xdr_ypresp_order, (char *)&resp);
	return (retval);
}
