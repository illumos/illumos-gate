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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <nfs/auth.h>

bool_t
xdr_varg(XDR *xdrs, varg_t *vap)
{
	if (!xdr_u_int(xdrs, &vap->vers))
		return (FALSE);

	switch (vap->vers) {
	case V_PROTO:
		if (!xdr_nfsauth_arg(xdrs, &vap->arg_u.arg))
			return (FALSE);
		break;

		/* Additional versions of the args go here */

	default:
		vap->vers = V_ERROR;
		return (FALSE);
		/* NOTREACHED */
	}
	return (TRUE);
}

bool_t
xdr_nfsauth_arg(XDR *xdrs, nfsauth_arg_t *argp)
{
	if (!xdr_u_int(xdrs, &argp->cmd))
		return (FALSE);
	if (!xdr_netobj(xdrs, &argp->areq.req_client))
		return (FALSE);
	if (!xdr_string(xdrs, &argp->areq.req_netid, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &argp->areq.req_path, A_MAXPATH))
		return (FALSE);
	if (!xdr_int(xdrs, &argp->areq.req_flavor))
		return (FALSE);
	if (!xdr_u_int(xdrs, &argp->areq.req_clnt_uid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &argp->areq.req_clnt_gid))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfsauth_res(XDR *xdrs, nfsauth_res_t *argp)
{
	if (!xdr_u_int(xdrs, &argp->stat))
		return (FALSE);
	if (!xdr_int(xdrs, &argp->ares.auth_perm))
		return (FALSE);
	if (!xdr_u_int(xdrs, &argp->ares.auth_srv_uid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &argp->ares.auth_srv_gid))
		return (FALSE);
	return (TRUE);
}
