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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nfs/nfs.h>
#include <nfs/nfs_log.h>

static bool_t xdr_timestruc32_t(XDR *, timestruc32_t *);
static bool_t xdr_nfs2_timeval(XDR *, nfs2_timeval *);
static bool_t xdr_ftype3(XDR *, ftype3 *);
static bool_t xdr_stable_how(XDR *, stable_how *);
static bool_t xdr_createmode3(XDR *, createmode3 *);
static bool_t xdr_size3(XDR *, size3 *);
static bool_t xdr_count3(XDR *, count3 *);
static bool_t xdr_set_size3(XDR *, set_size3 *);
static bool_t xdr_offset3(XDR *, offset3 *);
static bool_t xdr_post_op_fh3(XDR *, post_op_fh3 *);
static bool_t xdr_nfsreadargs(XDR *, struct nfsreadargs *);
static bool_t xdr_nfslog_record_header(XDR *, nfslog_record_header *);
static bool_t xdr_nfslog_drok(XDR *, nfslog_drok *);
static bool_t xdr_nfslog_rrok(XDR *, nfslog_rrok *);
static bool_t xdr_nfslog_sattr(XDR *, nfslog_sattr *);
static bool_t xdr_nfslog_rdok(XDR *, nfslog_rdok *);
static bool_t xdr_nfslog_createhow3(XDR *, nfslog_createhow3 *);
static bool_t xdr_nfslog_CREATE3resok(XDR *, nfslog_CREATE3resok *);
static bool_t xdr_nfslog_READ3resok(XDR *, nfslog_READ3resok *);
static bool_t xdr_nfslog_WRITE3resok(XDR *, nfslog_WRITE3resok *);
static bool_t xdr_nfslog_entryplus3(XDR *, nfslog_entryplus3 *);
static bool_t xdr_nfslog_dirlistplus3(XDR *, nfslog_dirlistplus3 *);
static bool_t xdr_nfslog_READDIRPLUS3resok(XDR *, nfslog_READDIRPLUS3resok *);

static bool_t
xdr_timestruc32_t(XDR *xdrs, timestruc32_t *objp)
{
	if (!xdr_int(xdrs, &objp->tv_sec))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->tv_nsec))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfs2_timeval(XDR *xdrs, nfs2_timeval *objp)
{
	if (!xdr_u_int(xdrs, &objp->tv_sec))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->tv_usec))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfsstat(XDR *xdrs, nfsstat *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_uint64(XDR *xdrs, uint64 *objp)
{
	return (xdr_u_longlong_t(xdrs, objp));
}

bool_t
xdr_uint32(XDR *xdrs, uint32 *objp)
{
	return (xdr_u_int(xdrs, objp));
}

static bool_t
xdr_ftype3(XDR *xdrs, ftype3 *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

static bool_t
xdr_stable_how(XDR *xdrs, stable_how *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

static bool_t
xdr_createmode3(XDR *xdrs, createmode3 *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

static bool_t
xdr_size3(XDR *xdrs, size3 *objp)
{
	return (xdr_uint64(xdrs, objp));
}

static bool_t
xdr_count3(XDR *xdrs, count3 *objp)
{
	return (xdr_uint32(xdrs, objp));
}

static bool_t
xdr_set_size3(XDR *xdrs, set_size3 *objp)
{
	if (!xdr_bool(xdrs, &objp->set_it))
		return (FALSE);
	switch (objp->set_it) {
	case TRUE:
		if (!xdr_size3(xdrs, &objp->size))
			return (FALSE);
		break;
	}
	return (TRUE);
}

static bool_t
xdr_offset3(XDR *xdrs, offset3 *objp)
{
	return (xdr_uint64(xdrs, objp));
}

bool_t
xdr_fhandle(XDR *xdrs, fhandle_t *fh)
{
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	return (xdr_opaque(xdrs, (caddr_t)fh, NFS_FHSIZE));
}


bool_t
xdr_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	if (!xdr_u_int(xdrs, &objp->fh3_length))
		return (FALSE);

	if (objp->fh3_length > NFS3_FHSIZE)
		return (FALSE);

	if (xdrs->x_op == XDR_DECODE || xdrs->x_op == XDR_ENCODE)
		return (xdr_opaque(xdrs, objp->fh3_u.data, objp->fh3_length));

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	return (FALSE);
}

static bool_t
xdr_post_op_fh3(XDR *xdrs, post_op_fh3 *objp)
{
	if (!xdr_bool(xdrs, &objp->handle_follows))
		return (FALSE);
	switch (objp->handle_follows) {
	case TRUE:
		if (!xdr_nfs_fh3(xdrs, &objp->handle))
			return (FALSE);
		break;
	case FALSE:
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_nfsstat3(XDR *xdrs, nfsstat3 *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

static bool_t
xdr_nfsreadargs(XDR *xdrs, struct nfsreadargs *ra)
{
	if (xdr_fhandle(xdrs, &ra->ra_fhandle) &&
	    xdr_u_int(xdrs, &ra->ra_offset) &&
	    xdr_u_int(xdrs, &ra->ra_count) &&
	    xdr_u_int(xdrs, &ra->ra_totcount)) {
		return (TRUE);
	}
	return (FALSE);
}


bool_t
xdr_nfslog_buffer_header(XDR *xdrs, nfslog_buffer_header *objp)
{
	if (!xdr_u_int(xdrs, &objp->bh_length))
		return (FALSE);
	if (!xdr_rpcvers(xdrs, &objp->bh_version))
		return (FALSE);
	if (objp->bh_version > 1) {
		if (!xdr_u_longlong_t(xdrs, &objp->bh_offset))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->bh_flags))
			return (FALSE);
	} else {
		uint_t	bh_offset;

		if (!xdr_u_int(xdrs, &objp->bh_flags))
			return (FALSE);
		if (xdrs->x_op == XDR_ENCODE)
			bh_offset = (uint_t)objp->bh_offset;
		if (!xdr_u_int(xdrs, &bh_offset))
			return (FALSE);
		if (xdrs->x_op == XDR_DECODE)
			objp->bh_offset = (u_offset_t)bh_offset;
	}
	if (!xdr_timestruc32_t(xdrs, &objp->bh_timestamp))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_record_header(XDR *xdrs, nfslog_record_header *objp)
{
	if (!xdr_u_int(xdrs, &objp->rh_reclen))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rh_rec_id))
		return (FALSE);
	if (!xdr_rpcprog(xdrs, &objp->rh_prognum))
		return (FALSE);
	if (!xdr_rpcproc(xdrs, &objp->rh_procnum))
		return (FALSE);
	if (!xdr_rpcvers(xdrs, &objp->rh_version))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rh_auth_flavor))
		return (FALSE);
	if (!xdr_timestruc32_t(xdrs, &objp->rh_timestamp))
		return (FALSE);
	if (!xdr_uid_t(xdrs, &objp->rh_uid))
		return (FALSE);
	if (!xdr_gid_t(xdrs, &objp->rh_gid))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_request_record(XDR *xdrs, nfslog_request_record *objp)
{
	if (!xdr_nfslog_record_header(xdrs, &objp->re_header))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->re_principal_name, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->re_netid, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->re_tag, ~0))
		return (FALSE);
	if (!xdr_netbuf(xdrs, &objp->re_ipaddr))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_sharefsargs(XDR *xdrs, nfslog_sharefsargs *objp)
{
	if (!xdr_int(xdrs, &objp->sh_flags))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->sh_anon))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->sh_path, ~0))
		return (FALSE);
	if (!xdr_fhandle(xdrs, &objp->sh_fh_buf))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_sharefsres(XDR *xdrs, nfslog_sharefsres *objp)
{
	if (!xdr_nfsstat(xdrs, objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_getfhargs(XDR *xdrs, nfslog_getfhargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->gfh_fh_buf))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->gfh_path, ~0))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_diropargs(XDR *xdrs, nfslog_diropargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->da_fhandle))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->da_name, ~0))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_drok(XDR *xdrs, nfslog_drok *objp)
{
	if (!xdr_fhandle(xdrs, &objp->drok_fhandle))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_diropres(XDR *xdrs, nfslog_diropres *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->dr_status))
		return (FALSE);
	switch (objp->dr_status) {
	case NFS_OK:
		if (!xdr_nfslog_drok(xdrs, &objp->nfslog_diropres_u.dr_ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_nfsreadargs(XDR *xdrs, nfslog_nfsreadargs *objp)
{
	if (!xdr_nfsreadargs(xdrs, objp))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_rrok(XDR *xdrs, nfslog_rrok *objp)
{
	if (!xdr_u_int(xdrs, &objp->filesize))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rrok_count))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_rdresult(XDR *xdrs, nfslog_rdresult *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->r_status))
		return (FALSE);
	switch (objp->r_status) {
	case NFS_OK:
		if (!xdr_nfslog_rrok(xdrs, &objp->nfslog_rdresult_u.r_ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_writeargs(XDR *xdrs, nfslog_writeargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->waargs_fhandle))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->waargs_begoff))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->waargs_offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->waargs_totcount))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->waargs_count))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_writeresult(XDR *xdrs, nfslog_writeresult *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->wr_status))
		return (FALSE);
	switch (objp->wr_status) {
	case NFS_OK:
		if (!xdr_u_int(xdrs, &objp->nfslog_writeresult_u.wr_size))
			return (FALSE);
		break;
	}
	return (TRUE);
}

static bool_t
xdr_nfslog_sattr(XDR *xdrs, nfslog_sattr *objp)
{
	if (!xdr_u_int(xdrs, &objp->sa_mode))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->sa_uid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->sa_gid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->sa_size))
		return (FALSE);
	if (!xdr_nfs2_timeval(xdrs, (nfs2_timeval *)&objp->sa_atime))
		return (FALSE);
	if (!xdr_nfs2_timeval(xdrs, (nfs2_timeval *)&objp->sa_mtime))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_createargs(XDR *xdrs, nfslog_createargs *objp)
{
	if (!xdr_nfslog_sattr(xdrs, &objp->ca_sa))
		return (FALSE);
	if (!xdr_nfslog_diropargs(xdrs, &objp->ca_da))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_setattrargs(XDR *xdrs, nfslog_setattrargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->saa_fh))
		return (FALSE);
	if (!xdr_nfslog_sattr(xdrs, &objp->saa_sa))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_rdlnres(XDR *xdrs, nfslog_rdlnres *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->rl_status))
		return (FALSE);
	switch (objp->rl_status) {
	case NFS_OK:
		if (!xdr_string(xdrs, &objp->nfslog_rdlnres_u.rl_ok, ~0))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_rnmargs(XDR *xdrs, nfslog_rnmargs *objp)
{
	if (!xdr_nfslog_diropargs(xdrs, &objp->rna_from))
		return (FALSE);
	if (!xdr_nfslog_diropargs(xdrs, &objp->rna_to))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_linkargs(XDR *xdrs, nfslog_linkargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->la_from))
		return (FALSE);
	if (!xdr_nfslog_diropargs(xdrs, &objp->la_to))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_symlinkargs(XDR *xdrs, nfslog_symlinkargs *objp)
{
	if (!xdr_nfslog_diropargs(xdrs, &objp->sla_from))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->sla_tnm, ~0))
		return (FALSE);
	if (!xdr_nfslog_sattr(xdrs, &objp->sla_sa))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_rddirargs(XDR *xdrs, nfslog_rddirargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->rda_fh))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rda_offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rda_count))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_rdok(XDR *xdrs, nfslog_rdok *objp)
{
	if (!xdr_u_int(xdrs, &objp->rdok_offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rdok_size))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->rdok_eof))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_rddirres(XDR *xdrs, nfslog_rddirres *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->rd_status))
		return (FALSE);
	switch (objp->rd_status) {
	case NFS_OK:
		if (!xdr_nfslog_rdok(xdrs, &objp->nfslog_rddirres_u.rd_ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_diropargs3(XDR *xdrs, nfslog_diropargs3 *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->name, ~0))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_LOOKUP3res(XDR *xdrs, nfslog_LOOKUP3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfs_fh3(xdrs, &objp->nfslog_LOOKUP3res_u.object))
			return (FALSE);
		break;
	}
	return (TRUE);
}

static bool_t
xdr_nfslog_createhow3(XDR *xdrs, nfslog_createhow3 *objp)
{
	if (!xdr_createmode3(xdrs, &objp->mode))
		return (FALSE);
	switch (objp->mode) {
	case UNCHECKED:
	case GUARDED:
		if (!xdr_set_size3(xdrs, &objp->nfslog_createhow3_u.size))
			return (FALSE);
		break;
	case EXCLUSIVE:
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_nfslog_CREATE3args(XDR *xdrs, nfslog_CREATE3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->where))
		return (FALSE);
	if (!xdr_nfslog_createhow3(xdrs, &objp->how))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_CREATE3resok(XDR *xdrs, nfslog_CREATE3resok *objp)
{
	if (!xdr_post_op_fh3(xdrs, &objp->obj))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_CREATE3res(XDR *xdrs, nfslog_CREATE3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_CREATE3resok(
			xdrs, &objp->nfslog_CREATE3res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_SETATTR3args(XDR *xdrs, nfslog_SETATTR3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return (FALSE);
	if (!xdr_set_size3(xdrs, &objp->size))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_READLINK3res(XDR *xdrs, nfslog_READLINK3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_string(xdrs, &objp->nfslog_READLINK3res_u.data, ~0))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_READ3args(XDR *xdrs, nfslog_READ3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_offset3(xdrs, &objp->offset))
		return (FALSE);
	if (!xdr_count3(xdrs, &objp->count))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_READ3resok(XDR *xdrs, nfslog_READ3resok *objp)
{
	if (!xdr_size3(xdrs, &objp->filesize))
		return (FALSE);
	if (!xdr_count3(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->eof))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->size))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_READ3res(XDR *xdrs, nfslog_READ3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_READ3resok(xdrs, &objp->nfslog_READ3res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_WRITE3args(XDR *xdrs, nfslog_WRITE3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_offset3(xdrs, &objp->offset))
		return (FALSE);
	if (!xdr_count3(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_stable_how(xdrs, &objp->stable))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_WRITE3resok(XDR *xdrs, nfslog_WRITE3resok *objp)
{
	if (!xdr_size3(xdrs, &objp->filesize))
		return (FALSE);
	if (!xdr_count3(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_stable_how(xdrs, &objp->committed))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_WRITE3res(XDR *xdrs, nfslog_WRITE3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_WRITE3resok(xdrs, &objp->nfslog_WRITE3res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_MKDIR3args(XDR *xdrs, nfslog_MKDIR3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->where))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_MKDIR3res(XDR *xdrs, nfslog_MKDIR3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_post_op_fh3(xdrs, &objp->nfslog_MKDIR3res_u.obj))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_SYMLINK3args(XDR *xdrs, nfslog_SYMLINK3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->where))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->symlink_data, ~0))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_SYMLINK3res(XDR *xdrs, nfslog_SYMLINK3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_post_op_fh3(xdrs, &objp->nfslog_SYMLINK3res_u.obj))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_MKNOD3args(XDR *xdrs, nfslog_MKNOD3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->where))
		return (FALSE);
	if (!xdr_ftype3(xdrs, &objp->type))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_MKNOD3res(XDR *xdrs, nfslog_MKNOD3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_post_op_fh3(xdrs, &objp->nfslog_MKNOD3res_u.obj))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_REMOVE3args(XDR *xdrs, nfslog_REMOVE3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->object))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_RMDIR3args(XDR *xdrs, nfslog_RMDIR3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->object))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_RENAME3args(XDR *xdrs, nfslog_RENAME3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->from))
		return (FALSE);
	if (!xdr_nfslog_diropargs3(xdrs, &objp->to))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_LINK3args(XDR *xdrs, nfslog_LINK3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_nfslog_diropargs3(xdrs, &objp->link))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_READDIRPLUS3args(XDR *xdrs, nfslog_READDIRPLUS3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
	if (!xdr_count3(xdrs, &objp->dircount))
		return (FALSE);
	if (!xdr_count3(xdrs, &objp->maxcount))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_entryplus3(XDR *xdrs, nfslog_entryplus3 *objp)
{
	if (!xdr_post_op_fh3(xdrs, &objp->name_handle))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->name, ~0))
		return (FALSE);
	if (!xdr_pointer(xdrs, (char **)&objp->nextentry,
		sizeof (nfslog_entryplus3), (xdrproc_t)xdr_nfslog_entryplus3))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_dirlistplus3(XDR *xdrs, nfslog_dirlistplus3 *objp)
{
	if (!xdr_pointer(xdrs, (char **)&objp->entries,
		sizeof (nfslog_entryplus3), (xdrproc_t)xdr_nfslog_entryplus3))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->eof))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfslog_READDIRPLUS3resok(XDR *xdrs, nfslog_READDIRPLUS3resok *objp)
{
	if (!xdr_nfslog_dirlistplus3(xdrs, &objp->reply))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfslog_READDIRPLUS3res(XDR *xdrs, nfslog_READDIRPLUS3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_READDIRPLUS3resok(
			xdrs, &objp->nfslog_READDIRPLUS3res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_COMMIT3args(XDR *xdrs, nfslog_COMMIT3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_offset3(xdrs, &objp->offset))
		return (FALSE);
	if (!xdr_count3(xdrs, &objp->count))
		return (FALSE);
	return (TRUE);
}
