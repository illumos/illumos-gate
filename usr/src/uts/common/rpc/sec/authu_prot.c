/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * authunix_prot.c
 * XDR for UNIX style authentication parameters for RPC
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/utsname.h>

#include <rpc/types.h>
#include <rpc/rpc_sztypes.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/clnt.h>

/*
 * XDR for unix authentication parameters.
 */
bool_t
xdr_authunix_parms(XDR *xdrs, struct authunix_parms *p)
{
	if (xdr_u_int(xdrs, &p->aup_time) &&
	    xdr_string(xdrs, &p->aup_machname, MAX_MACHINE_NAME) &&
	    xdr_int(xdrs, (int *)&(p->aup_uid)) &&
	    xdr_int(xdrs, (int *)&(p->aup_gid)) &&
	    xdr_array(xdrs, (caddr_t *)&(p->aup_gids),
	    &(p->aup_len), NGRPS, sizeof (int),
	    (xdrproc_t)xdr_int)) {
		return (TRUE);
	}
	return (FALSE);
}

/*
 * XDR user id types (uid_t)
 */
bool_t
xdr_uid_t(XDR *xdrs, uid_t *ip)
{
#ifdef lint
	(void) (xdr_short(xdrs, (short *)ip));
	return (xdr_int32(xdrs, (int32_t *)ip));
#else
	if (sizeof (uid_t) == sizeof (int32_t)) {
		return (xdr_int(xdrs, (int32_t *)ip));
	} else {
		return (xdr_short(xdrs, (short *)ip));
	}
#endif
}

/*
 * XDR group id types (gid_t)
 */
bool_t
xdr_gid_t(XDR *xdrs, gid_t *ip)
{
#ifdef lint
	(void) (xdr_short(xdrs, (short *)ip));
	return (xdr_int32(xdrs, (int32_t *)ip));
#else
	if (sizeof (gid_t) == sizeof (int32_t)) {
		return (xdr_int32(xdrs, (int32_t *)ip));
	} else {
		return (xdr_short(xdrs, (short *)ip));
	}
#endif
}

/*
 * XDR kernel unix auth parameters.
 * Goes out of the u struct directly.
 * NOTE: this is an XDR_ENCODE only routine.
 */
bool_t
xdr_authkern(XDR *xdrs, cred_t *cr)
{
	uid_t uid;
	gid_t gid;
	uint_t len;
	caddr_t groups;
	char *name = uts_nodename();
	time_t now;

	if (xdrs->x_op != XDR_ENCODE)
		return (FALSE);

	uid = crgetuid(cr);
	gid = crgetgid(cr);
	len = crgetngroups(cr);

	if (len > NGRPS)
		len = NGRPS;

	groups = (caddr_t)crgetgroups(cr);
	now = gethrestime_sec();
	if (xdr_uint32(xdrs, (uint32_t *)&now) &&
	    xdr_string(xdrs, &name, MAX_MACHINE_NAME) &&
	    xdr_uid_t(xdrs, &uid) &&
	    xdr_gid_t(xdrs, &gid) &&
	    xdr_array(xdrs, &groups, &len, NGRPS, sizeof (gid_t), xdr_gid_t))
		return (TRUE);
	return (FALSE);
}

/*
 * XDR loopback unix auth parameters.
 * NOTE: this is an XDR_ENCODE only routine.
 */
bool_t
xdr_authloopback(XDR *xdrs, cred_t *cr)
{
	uid_t uid;
	gid_t gid;
	uint_t len;
	caddr_t groups;
	char *name = uts_nodename();
	time_t now;

	if (xdrs->x_op != XDR_ENCODE)
		return (FALSE);

	uid = crgetuid(cr);
	gid = crgetgid(cr);
	len = crgetngroups(cr);
	groups = (caddr_t)crgetgroups(cr);
	now = gethrestime_sec();
	if (xdr_uint32(xdrs, (uint32_t *)&now) &&
	    xdr_string(xdrs, &name, MAX_MACHINE_NAME) &&
	    xdr_uid_t(xdrs, &uid) &&
	    xdr_gid_t(xdrs, &gid) &&
	    xdr_array(xdrs, &groups, &len, NGROUPS_UMAX, sizeof (gid_t),
	    xdr_gid_t))
		return (TRUE);
	return (FALSE);
}
