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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <rpc/rpc.h>
#include <smbsrv/libsmb.h>

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file was originally generated using rpcgen.
 */

bool_t
xdr_ntgrp_dr_arg_t(xdrs, objp)
	XDR *xdrs;
	ntgrp_dr_arg_t *objp;
{
	if (!xdr_string(xdrs, &objp->gname, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->desc, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->member, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->newgname, ~0))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->privid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->priv_attr))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->offset))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->scope, ~0))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->type))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ntstatus))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_ntgrp_t(xdrs, objp)
	XDR *xdrs;
	ntgrp_t *objp;
{
	if (!xdr_uint32_t(xdrs, &objp->rid))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->name, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->desc, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->type, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->sid, ~0))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_ntgrp_list_t(xdrs, objp)
	XDR *xdrs;
	ntgrp_list_t *objp;
{
	if (!xdr_int(xdrs, &objp->cnt))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->groups, SMB_GROUP_PER_LIST,
		sizeof (ntgrp_t), (xdrproc_t)xdr_ntgrp_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_members_list(xdrs, objp)
	XDR *xdrs;
	members_list *objp;
{
	if (!xdr_string(xdrs, objp, ~0))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_ntgrp_member_list_t(xdrs, objp)
	XDR *xdrs;
	ntgrp_member_list_t *objp;
{
	if (!xdr_uint32_t(xdrs, &objp->rid))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->cnt))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->members, SMB_GROUP_PER_LIST,
		sizeof (members_list), (xdrproc_t)xdr_members_list))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_ntpriv_t(xdrs, objp)
	XDR *xdrs;
	ntpriv_t *objp;
{
	if (!xdr_uint32_t(xdrs, &objp->id))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->name, ~0))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_privs_t(xdrs, objp)
	XDR *xdrs;
	privs_t *objp;
{
	if (!xdr_pointer(xdrs, (char **)objp, sizeof (ntpriv_t),
	    (xdrproc_t)xdr_ntpriv_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_ntpriv_list_t(xdrs, objp)
	XDR *xdrs;
	ntpriv_list_t *objp;
{
	if (!xdr_int(xdrs, &objp->cnt))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->privs, objp->cnt,
		sizeof (privs_t), (xdrproc_t)xdr_privs_t))
		return (FALSE);
	return (TRUE);
}
