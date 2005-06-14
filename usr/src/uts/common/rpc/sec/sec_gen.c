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
 * Copyright (c) 1994-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *  From  common/syscall/systeminfo.c
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systeminfo.h>	/* for SI_KERB stuff */

#include <sys/errno.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/svc_auth.h>


/*
 * authany_wrap() is a NO-OP routines for ah_wrap().
 */
/* ARGSUSED */
int
authany_wrap(AUTH *auth, caddr_t buf, u_int buflen,
    XDR *xdrs, xdrproc_t xfunc, caddr_t xwhere)
{
	return (*xfunc)(xdrs, xwhere);
}

/*
 * authany_unwrap() is a NO-OP routines for ah_unwrap().
 */
/* ARGSUSED */
int
authany_unwrap(AUTH *auth, XDR *xdrs, xdrproc_t xfunc, caddr_t xwhere)
{
	return (*xfunc)(xdrs, xwhere);
}
