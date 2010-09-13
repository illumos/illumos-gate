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
 * Copyright (c) 1986,1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include <rpc/bootparam.h>

bool_t
xdr_bp_machine_name_t(XDR *xdrs, bp_machine_name_t *objp)
{
	return (xdr_string(xdrs, objp, MAX_MACHINE_NAME));
}

bool_t
xdr_bp_path_t(XDR *xdrs, bp_path_t *objp)
{
	return (xdr_string(xdrs, objp, MAX_PATH_LEN));
}

bool_t
xdr_bp_fileid_t(XDR *xdrs, bp_fileid_t *objp)
{
	return (xdr_string(xdrs, objp, MAX_FILEID));
}

bool_t
xdr_ip_addr_t(XDR *xdrs, ip_addr_t *objp)
{
	if (!xdr_char(xdrs, &objp->net))
		return (FALSE);
	if (!xdr_char(xdrs, &objp->host))
		return (FALSE);
	if (!xdr_char(xdrs, &objp->lh))
		return (FALSE);
	if (!xdr_char(xdrs, &objp->impno))
		return (FALSE);
	return (TRUE);
}

static struct xdr_discrim choices[] = {
	{ IP_ADDR_TYPE, xdr_ip_addr_t },
	{ __dontcare__, NULL }
};

bool_t
xdr_bp_address(XDR *xdrs, bp_address *objp)
{
	return (xdr_union(xdrs, (enum_t *)&objp->address_type,
	    (char *)&objp->bp_address, choices, (xdrproc_t)NULL));
}

bool_t
xdr_bp_whoami_arg(XDR *xdrs, bp_whoami_arg *objp)
{
	return (xdr_bp_address(xdrs, &objp->client_address));
}

bool_t
xdr_bp_whoami_res(XDR *xdrs, bp_whoami_res *objp)
{
	if (!xdr_bp_machine_name_t(xdrs, &objp->client_name))
		return (FALSE);
	if (!xdr_bp_machine_name_t(xdrs, &objp->domain_name))
		return (FALSE);
	if (!xdr_bp_address(xdrs, &objp->router_address))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_bp_getfile_arg(XDR *xdrs, bp_getfile_arg *objp)
{
	if (!xdr_bp_machine_name_t(xdrs, &objp->client_name))
		return (FALSE);
	if (!xdr_bp_fileid_t(xdrs, &objp->file_id))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_bp_getfile_res(XDR *xdrs, bp_getfile_res *objp)
{
	if (!xdr_bp_machine_name_t(xdrs, &objp->server_name))
		return (FALSE);
	if (!xdr_bp_address(xdrs, &objp->server_address))
		return (FALSE);
	if (!xdr_bp_path_t(xdrs, &objp->server_path))
		return (FALSE);
	return (TRUE);
}
