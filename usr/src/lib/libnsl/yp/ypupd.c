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
#include <sys/types.h>
#include <rpcsvc/ypupd.h>

/*
 * Originally compiled from ypupdate_prot.x using rpcgen
 */
bool_t
xdr_yp_buf(XDR *xdrs, yp_buf *objp)
{
	return (xdr_bytes(xdrs, (char **)&objp->yp_buf_val,
		(uint_t *)&objp->yp_buf_len, MAXYPDATALEN));
}

bool_t
xdr_ypupdate_args(XDR *xdrs, ypupdate_args *objp)
{
	if (!xdr_string(xdrs, &objp->mapname, MAXMAPNAMELEN))
		return (FALSE);
	if (!xdr_yp_buf(xdrs, &objp->key))
		return (FALSE);
	return (xdr_yp_buf(xdrs, &objp->datum));
}

bool_t
xdr_ypdelete_args(XDR *xdrs, ypdelete_args *objp)
{
	if (!xdr_string(xdrs, &objp->mapname, MAXMAPNAMELEN))
		return (FALSE);
	return (xdr_yp_buf(xdrs, &objp->key));
}
