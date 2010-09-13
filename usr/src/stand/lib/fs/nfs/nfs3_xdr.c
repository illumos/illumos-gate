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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>

/*
 * Xdr routines for NFS ops.
 */

static bool_t
xdr_b_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	return (xdr_bytes(xdrs, (char **)&objp->data.data_val,
				(uint_t *)&objp->data.data_len, NFS3_FHSIZE));
}

static bool_t
xdr_b_fattr3(XDR *xdrs, fattr3 *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->type))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->mode))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->nlink))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->uid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->gid))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->size))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->used))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rdev.specdata1))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rdev.specdata2))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->fsid))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->fileid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->atime.seconds))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->atime.nseconds))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->mtime.seconds))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->mtime.nseconds))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->ctime.seconds))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->ctime.nseconds));
}

static bool_t
xdr_b_post_op_attr(XDR *xdrs, post_op_attr *objp)
{
	if (!xdr_bool(xdrs, &objp->attributes_follow))
		return (FALSE);
	switch (objp->attributes_follow) {
	case TRUE:
		return (xdr_b_fattr3(xdrs, &objp->post_op_attr_u.attributes));
	case FALSE:
		return (TRUE);
	default:
		return (FALSE);
	}
}

static bool_t
xdr_b_diropargs3(XDR *xdrs, diropargs3 *objp)
{
	if (!xdr_b_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
	return (xdr_string(xdrs, &objp->name, ~0));
}

bool_t
xdr_GETATTR3args(XDR *xdrs, GETATTR3args *objp)
{
	return (xdr_b_nfs_fh3(xdrs, &objp->object));
}

static bool_t
xdr_b_GETATTR3resok(XDR *xdrs, GETATTR3resok *objp)
{
	return (xdr_b_fattr3(xdrs, &objp->obj_attributes));
}

bool_t
xdr_GETATTR3res(XDR *xdrs, GETATTR3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status == NFS3_OK)
		return (xdr_b_GETATTR3resok(xdrs, &objp->GETATTR3res_u.resok));
	return (TRUE);
}

bool_t
xdr_LOOKUP3args(XDR *xdrs, LOOKUP3args *objp)
{
	return (xdr_b_diropargs3(xdrs, &objp->what));
}

static bool_t
xdr_b_LOOKUP3resok(XDR *xdrs, LOOKUP3resok *objp)
{
	if (!xdr_b_nfs_fh3(xdrs, &objp->object))
		return (FALSE);
	if (!xdr_b_post_op_attr(xdrs, &objp->obj_attributes))
		return (FALSE);
	return (xdr_b_post_op_attr(xdrs, &objp->dir_attributes));
}

static bool_t
xdr_b_LOOKUP3resfail(XDR *xdrs, LOOKUP3resfail *objp)
{
	return (xdr_b_post_op_attr(xdrs, &objp->dir_attributes));
}

bool_t
xdr_LOOKUP3res(XDR *xdrs, LOOKUP3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);

	if (objp->status == NFS3_OK)
		return (xdr_b_LOOKUP3resok(xdrs, &objp->LOOKUP3res_u.resok));

	return (xdr_b_LOOKUP3resfail(xdrs, &objp->LOOKUP3res_u.resfail));
}

bool_t
xdr_READLINK3args(XDR *xdrs, READLINK3args *objp)
{
	return (xdr_b_nfs_fh3(xdrs, &objp->symlink));
}

static bool_t
xdr_b_READLINK3resok(XDR *xdrs, READLINK3resok *objp)
{
	if (!xdr_b_post_op_attr(xdrs, &objp->symlink_attributes))
		return (FALSE);
	return (xdr_string(xdrs, &objp->data, ~0));
}

static bool_t
xdr_b_READLINK3resfail(XDR *xdrs, READLINK3resfail *objp)
{
	return (xdr_b_post_op_attr(xdrs, &objp->symlink_attributes));
}

bool_t
xdr_READLINK3res(XDR *xdrs, READLINK3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status == NFS3_OK)
		return (xdr_b_READLINK3resok(xdrs,
						&objp->READLINK3res_u.resok));
	return (xdr_b_READLINK3resfail(xdrs, &objp->READLINK3res_u.resfail));
}

bool_t
xdr_READ3args(XDR *xdrs, READ3args *objp)
{
	if (!xdr_b_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->offset))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->count));
}

static bool_t
xdr_b_READ3resok(XDR *xdrs, READ3resok *objp)
{
	if (!xdr_b_post_op_attr(xdrs, &objp->file_attributes))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->eof))
		return (FALSE);
	return (xdr_bytes(xdrs, (char **)&objp->data.data_val,
					(uint_t *)&objp->data.data_len, ~0));
}

static bool_t
xdr_b_READ3resfail(XDR *xdrs, READ3resfail *objp)
{
	return (xdr_b_post_op_attr(xdrs, &objp->file_attributes));
}

bool_t
xdr_READ3res(XDR *xdrs, READ3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status == NFS3_OK)
		return (xdr_b_READ3resok(xdrs, &objp->READ3res_u.resok));
	return (xdr_b_READ3resfail(xdrs, &objp->READ3res_u.resfail));
}

bool_t
xdr_READDIR3args(XDR *xdrs, READDIR3args *objp)
{
	if (!xdr_b_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->cookie))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->cookieverf, NFS3_COOKIEVERFSIZE))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->count));
}

static bool_t
xdr_b_entry3(XDR *xdrs, entry3 *objp)
{
	if (!xdr_u_longlong_t(xdrs, &objp->fileid))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->name, ~0))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->cookie))
		return (FALSE);
	return (xdr_pointer(xdrs, (char **)&objp->nextentry,
				sizeof (entry3), (xdrproc_t)xdr_b_entry3));
}

static bool_t
xdr_b_READDIR3resok(XDR *xdrs, READDIR3resok *objp)
{
	if (!xdr_b_post_op_attr(xdrs, &objp->dir_attributes))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->cookieverf, NFS3_COOKIEVERFSIZE))
		return (FALSE);
	if (!xdr_pointer(xdrs, (char **)&objp->reply.entries,
				sizeof (entry3), (xdrproc_t)xdr_b_entry3))
		return (FALSE);
	return (xdr_bool(xdrs, &objp->reply.eof));
}

static bool_t
xdr_b_READDIR3resfail(XDR *xdrs, READDIR3resfail *objp)
{
	return (xdr_b_post_op_attr(xdrs, &objp->dir_attributes));
}

bool_t
xdr_READDIR3res(XDR *xdrs, READDIR3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status == NFS3_OK)
		return (xdr_b_READDIR3resok(xdrs, &objp->READDIR3res_u.resok));
	return (xdr_b_READDIR3resfail(xdrs, &objp->READDIR3res_u.resfail));
}
