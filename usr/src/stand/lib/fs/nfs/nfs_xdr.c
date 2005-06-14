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
 * XDR routines for NFS ops.
 */
static bool_t
xdr_b_nfsstat(XDR *xdrs, nfsstat *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

static bool_t
xdr_b_ftype(XDR *xdrs, ftype *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_nfs_fh(XDR *xdrs, nfs_fh *objp)
{
	return (xdr_opaque(xdrs, objp->data, NFS_FHSIZE));
}

static bool_t
xdr_b_nfstime(XDR *xdrs, nfstime *objp)
{
	if (!xdr_u_int(xdrs, &objp->seconds)) {
		return (FALSE);
	}
	return (xdr_u_int(xdrs, &objp->useconds));
}

static bool_t
xdr_b_fattr(XDR *xdrs, fattr *objp)
{
	if (!xdr_b_ftype(xdrs, &objp->type)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->mode)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->nlink)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->uid)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->gid)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->size)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->blocksize)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->rdev)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->blocks)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->fsid)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->fileid)) {
		return (FALSE);
	}
	if (!xdr_b_nfstime(xdrs, &objp->atime)) {
		return (FALSE);
	}
	if (!xdr_b_nfstime(xdrs, &objp->mtime)) {
		return (FALSE);
	}
	return (xdr_b_nfstime(xdrs, &objp->ctime));
}

static bool_t
xdr_b_filename(XDR *xdrs, filename *objp)
{
	return (xdr_string(xdrs, objp, NFS_MAXNAMLEN));
}

static bool_t
xdr_b_nfspath(XDR *xdrs, nfspath *objp)
{
	return (xdr_string(xdrs, objp, NFS_MAXPATHLEN));
}

bool_t
xdr_attrstat(XDR *xdrs, attrstat *objp)
{
	if (!xdr_b_nfsstat(xdrs, &objp->status)) {
		return (FALSE);
	}
	if (objp->status == NFS_OK) {
		return (xdr_b_fattr(xdrs, &objp->attrstat_u.attributes));
	}
	return (TRUE);
}

bool_t
xdr_diropargs(XDR *xdrs, diropargs *objp)
{
	if (!xdr_nfs_fh(xdrs, &objp->dir)) {
		return (FALSE);
	}
	return (xdr_b_filename(xdrs, &objp->name));
}

static bool_t
xdr_b_diropokres(XDR *xdrs, diropokres *objp)
{
	if (!xdr_nfs_fh(xdrs, &objp->file)) {
		return (FALSE);
	}
	return (xdr_b_fattr(xdrs, &objp->attributes));
}

bool_t
xdr_diropres(XDR *xdrs, diropres *objp)
{
	if (!xdr_b_nfsstat(xdrs, &objp->status)) {
		return (FALSE);
	}
	if (objp->status == NFS_OK) {
		return (xdr_b_diropokres(xdrs, &objp->diropres_u.diropres));
	}
	return (TRUE);
}

bool_t
xdr_readlinkres(XDR *xdrs, readlinkres *objp)
{
	if (!xdr_b_nfsstat(xdrs, &objp->status)) {
		return (FALSE);
	}
	if (objp->status == NFS_OK) {
		return (xdr_b_nfspath(xdrs, &objp->readlinkres_u.data));
	}
	return (TRUE);
}

bool_t
xdr_readargs(XDR *xdrs, readargs *objp)
{
	if (!xdr_nfs_fh(xdrs, &objp->file)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->offset)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->count)) {
		return (FALSE);
	}
	return (xdr_u_int(xdrs, &objp->totalcount));
}

static bool_t
xdr_b_readokres(XDR *xdrs, readokres *objp)
{
	if (!xdr_b_fattr(xdrs, &objp->attributes)) {
		return (FALSE);
	}
	return (xdr_bytes(xdrs, (char **)&objp->data.data_val,
	    (uint_t *)&objp->data.data_len, NFS_MAXDATA));
}

bool_t
xdr_readres(XDR *xdrs, readres *objp)
{
	if (!xdr_b_nfsstat(xdrs, &objp->status)) {
		return (FALSE);
	}
	if (objp->status == NFS_OK) {
		return (xdr_b_readokres(xdrs, &objp->readres_u.reply));
	}
	return (TRUE);
}

static bool_t
xdr_b_nfscookie(XDR *xdrs, nfscookie objp)
{
	return (xdr_opaque(xdrs, objp, NFS_COOKIESIZE));
}

bool_t
xdr_readdirargs(XDR *xdrs, readdirargs *objp)
{
	if (!xdr_nfs_fh(xdrs, &objp->dir)) {
		return (FALSE);
	}
	if (!xdr_b_nfscookie(xdrs, objp->cookie)) {
		return (FALSE);
	}
	return (xdr_u_int(xdrs, &objp->count));
}

static bool_t
xdr_b_entry(XDR *xdrs, entry *objp)
{
	if (!xdr_u_int(xdrs, &objp->fileid)) {
		return (FALSE);
	}
	if (!xdr_b_filename(xdrs, &objp->name)) {
		return (FALSE);
	}
	if (!xdr_b_nfscookie(xdrs, objp->cookie)) {
		return (FALSE);
	}
	return (xdr_pointer(xdrs, (char **)&objp->nextentry, sizeof (entry),
						(xdrproc_t)xdr_b_entry));
}

static bool_t
xdr_b_dirlist(XDR *xdrs, dirlist *objp)
{
	if (!xdr_pointer(xdrs, (char **)&objp->entries, sizeof (entry),
	    (xdrproc_t)xdr_b_entry)) {
		return (FALSE);
	}
	return (xdr_bool(xdrs, &objp->eof));
}

bool_t
xdr_readdirres(XDR *xdrs, readdirres *objp)
{
	if (!xdr_b_nfsstat(xdrs, &objp->status)) {
		return (FALSE);
	}
	if (objp->status == NFS_OK) {
		return (xdr_b_dirlist(xdrs, &objp->readdirres_u.reply));
	}
	return (TRUE);
}
