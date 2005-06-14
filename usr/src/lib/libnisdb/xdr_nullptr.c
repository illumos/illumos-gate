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
 *	xdr_nullptr.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * xdr_nullptr.c
 *
 * This function is used to control serializing and de-serializing of the
 * database objects. Basically there are some pointers in the structure
 * that we don't bother to serialize because they are always NULL when we
 * deserialize them. This function then simply returns on encode operations
 * and stuffs NULL into the pointer passed when decoding.
 */
#include <rpc/rpc.h>

bool_t
xdr_nullptr(xdrs, objp)
	XDR	*xdrs;
	void	**objp;
{
	if (xdrs->x_op == XDR_DECODE) {
		*objp = NULL;
	}
	return (TRUE);
}
