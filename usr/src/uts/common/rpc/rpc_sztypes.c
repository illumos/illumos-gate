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
 * Copyright (c) 1993-1997 Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * XDR routines for generic types that have explicit sizes.
 */

#include <rpc/rpc_sztypes.h>

/*
 * The new NFS protocol uses typedefs to name objects according to their
 * length (32 bits, 64 bits).  These objects appear in both the NFS and KLM
 * code, so the xdr routines live here.
 */

bool_t
xdr_uint64(XDR *xdrs, uint64 *objp)
{
	return (xdr_u_longlong_t(xdrs, objp));
}

bool_t
xdr_int64(XDR *xdrs, int64 *objp)
{
	return (xdr_longlong_t(xdrs, objp));
}

bool_t
xdr_uint32(XDR *xdrs, uint32 *objp)
{
	return (xdr_u_int(xdrs, objp));
}

bool_t
xdr_int32(XDR *xdrs, int32 *objp)
{
	return (xdr_int(xdrs, objp));
}
