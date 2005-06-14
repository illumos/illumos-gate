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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* c2 secure */

#include <rpc/rpc.h>
#include <rpcsvc/pwdnm.h>


bool_t
xdr_pwdnm(xdrs,objp)
	XDR *xdrs;
	pwdnm *objp;
{
	if (! xdr_wrapstring(xdrs, &objp->name)) {
		return(FALSE);
	}
	if (! xdr_wrapstring(xdrs, &objp->password)) {
		return(FALSE);
	}
	return(TRUE);
}


