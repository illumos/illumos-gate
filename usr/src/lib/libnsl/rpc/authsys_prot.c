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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
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
 * authsys_prot.c
 * XDR for UNIX style authentication parameters for RPC
 *
 */

#include <rpc/types.h>
#include <rpc/trace.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_sys.h>

bool_t xdr_uid_t();
bool_t xdr_gid_t();

/*
 * XDR for unix authentication parameters.
 */
bool_t
xdr_authsys_parms(XDR *xdrs, struct authsys_parms *p)
{
	trace1(TR_xdr_authsys_parms, 0);
	if (xdr_u_int(xdrs, &(p->aup_time)) &&
	    xdr_string(xdrs, &(p->aup_machname), MAX_MACHINE_NAME) &&
	    xdr_uid_t(xdrs, (uid_t *)&(p->aup_uid)) &&
	    xdr_gid_t(xdrs, (gid_t *)&(p->aup_gid)) &&
	    xdr_array(xdrs, (caddr_t *)&(p->aup_gids),
	    &(p->aup_len), NGRPS, (u_int)sizeof (gid_t),
	    (xdrproc_t) xdr_gid_t)) {
		trace1(TR_xdr_authsys_parms, 1);
		return (TRUE);
	}
	trace1(TR_xdr_authsys_parms, 1);
	return (FALSE);
}

/*
 * XDR for loopback unix authentication parameters.
 */
bool_t
xdr_authloopback_parms(XDR *xdrs, struct authsys_parms *p)
{
	/* trace1(TR_xdr_authsys_parms, 0); */
	if (xdr_u_int(xdrs, &(p->aup_time)) &&
	    xdr_string(xdrs, &(p->aup_machname), MAX_MACHINE_NAME) &&
	    xdr_uid_t(xdrs, (uid_t *)&(p->aup_uid)) &&
	    xdr_gid_t(xdrs, (gid_t *)&(p->aup_gid)) &&
	    xdr_array(xdrs, (caddr_t *)&(p->aup_gids),
	    &(p->aup_len), NGRPS_LOOPBACK, sizeof (gid_t),
	    (xdrproc_t) xdr_gid_t)) {
		/* trace1(TR_xdr_authsys_parms, 1); */
		return (TRUE);
	}
	/* trace1(TR_xdr_authsys_parms, 1); */
	return (FALSE);
}

/*
 * XDR user id types (uid_t)
 */
bool_t
xdr_uid_t(XDR *xdrs, uid_t *ip)
{
	bool_t dummy;

	trace1(TR_xdr_uid_t, 0);
#ifdef lint
	(void) (xdr_short(xdrs, (short *)ip));
	dummy = xdr_int(xdrs, (int *)ip);
	trace1(TR_xdr_uid_t, 1);
	return (dummy);
#else
	if (sizeof (uid_t) == sizeof (int)) {
		dummy = xdr_int(xdrs, (int *)ip);
		trace1(TR_xdr_uid_t, 1);
		return (dummy);
	} else {
		dummy = xdr_short(xdrs, (short *)ip);
		trace1(TR_xdr_uid_t, 1);
		return (dummy);
	}
#endif
}

/*
 * XDR group id types (gid_t)
 */
bool_t
xdr_gid_t(XDR *xdrs, gid_t *ip)
{
	bool_t dummy;

	trace1(TR_xdr_gid_t, 0);
#ifdef lint
	(void) (xdr_short(xdrs, (short *)ip));
	dummy = xdr_int(xdrs, (int *)ip);
	trace1(TR_xdr_gid_t, 1);
	return (dummy);
#else
	if (sizeof (gid_t) == sizeof (int)) {
		dummy = xdr_int(xdrs, (int *)ip);
		trace1(TR_xdr_gid_t, 1);
		return (dummy);
	} else {
		dummy = xdr_short(xdrs, (short *)ip);
		trace1(TR_xdr_gid_t, 1);
		return (dummy);
	}
#endif
}
