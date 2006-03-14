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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <rpc/types.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <rpc/rpcb_prot.h>
#include <rpc/clnt.h>
#include <nfs/nfs_log.h>

/*
 * nfsl_principal_name_get - extracts principal from transport struct.
 * Based on "uts/common/rpc/sec/sec_svc.c" function sec_svc_getcred.
 */
static char *
nfsl_principal_name_get(struct svc_req *req)
{
	char				*principal_name = NULL;
	struct authdes_cred		*adc;
	rpc_gss_rawcred_t		*rcred;
	rpc_gss_ucred_t			*ucred;
	void				*cookie;

	switch (req->rq_cred.oa_flavor) {
	case AUTH_UNIX:
	case AUTH_NONE:
		/* no principal name provided */
		break;

	case AUTH_DES:
		adc = (struct authdes_cred *)req->rq_clntcred;
		principal_name = adc->adc_fullname.name;
		break;

	case RPCSEC_GSS:
		(void) rpc_gss_getcred(req, &rcred, &ucred, &cookie);
		principal_name = (caddr_t)rcred->client_principal;
		break;

	default:
		break;
	}
	return (principal_name);
}

bool_t
xdr_timestruc32_t(XDR *xdrs, timestruc32_t *objp)
{
	if (!xdr_int(xdrs, &objp->tv_sec))
		return (FALSE);
	return (xdr_int(xdrs, &objp->tv_nsec));
}

bool_t
xdr_nfsstat(XDR *xdrs, nfsstat *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_nfslog_sharefsres(XDR *xdrs, nfslog_sharefsres *objp)
{
	return (xdr_nfsstat(xdrs, objp));
}

bool_t
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
xdr_nfslog_nfsreadargs(xdrs, objp)
	register XDR *xdrs;
	nfslog_nfsreadargs *objp;
{
	return (xdr_nfsreadargs(xdrs, objp));
}

/*
 * Current version (2 and up) xdr function for buffer header
 * uses 64-bit offset (relocated to an 8 byte boundary), version 1 uses 32.
 */
bool_t
xdr_nfslog_buffer_header(xdrs, objp)
	register XDR *xdrs;
	nfslog_buffer_header *objp;
{
	if (!xdr_u_int(xdrs, &objp->bh_length))
		return (FALSE);
	if (!xdr_rpcvers(xdrs, &objp->bh_version))
		return (FALSE);
	ASSERT(objp->bh_version > 1);
	if (!xdr_u_longlong_t(xdrs, &objp->bh_offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->bh_flags))
		return (FALSE);
	return (xdr_timestruc32_t(xdrs, &objp->bh_timestamp));
}

/*
 * Hand coded xdr functions for the kernel ENCODE path
 */

bool_t
xdr_nfslog_request_record(
	XDR *xdrs,
	struct exportinfo *exi,
	struct svc_req *req,
	cred_t *cr,
	struct netbuf *pnb,
	unsigned int	reclen,
	unsigned int	record_id)
{
	char *netid = NULL;
	char *prin = NULL;
	unsigned int flavor;
	timestruc32_t ts;
	timestruc_t now;
	uid_t ruid;
	gid_t rgid;

	if (xdrs->x_op != XDR_ENCODE)
		return (FALSE);

	/*
	 * First we do the encoding of the record header
	 */
	if (!xdr_u_int(xdrs, &reclen))
		return (FALSE);
	if (!xdr_u_int(xdrs, &record_id))
		return (FALSE);
	if (!xdr_rpcprog(xdrs, &req->rq_prog))
		return (FALSE);
	if (!xdr_rpcproc(xdrs, &req->rq_proc))
		return (FALSE);
	if (!xdr_rpcvers(xdrs, &req->rq_vers))
		return (FALSE);
	flavor = req->rq_cred.oa_flavor;
	if (!xdr_u_int(xdrs, &flavor))
		return (FALSE);

	gethrestime(&now);
	TIMESPEC_TO_TIMESPEC32(&ts, &now);
	if (!xdr_timestruc32_t(xdrs, &ts))
		return (FALSE);

	/* This code depends on us doing XDR_ENCODE ops only */
	ruid = crgetruid(cr);
	if (!xdr_uid_t(xdrs, &ruid))
		return (FALSE);
	rgid = crgetrgid(cr);
	if (!xdr_gid_t(xdrs, &rgid))
		return (FALSE);

	/*
	 * Now encode the rest of the request record (but not args/res)
	 */
	prin = nfsl_principal_name_get(req);
	if (!xdr_string(xdrs, &prin, ~0))
		return (FALSE);
	if (req->rq_xprt)
		netid = svc_getnetid(req->rq_xprt);
	if (!xdr_string(xdrs, &netid, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &exi->exi_export.ex_tag, ~0))
		return (FALSE);
	return (xdr_netbuf(xdrs, pnb));
}

bool_t
xdr_nfslog_sharefsargs(XDR *xdrs, struct exportinfo *objp)
{

	if (xdrs->x_op != XDR_ENCODE)
		return (FALSE);

	if (!xdr_int(xdrs, &objp->exi_export.ex_flags))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->exi_export.ex_anon))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->exi_export.ex_path, ~0))
		return (FALSE);
	return (xdr_fhandle(xdrs, &objp->exi_fh));
}

bool_t
xdr_nfslog_getfhargs(XDR *xdrs, nfslog_getfhargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->gfh_fh_buf))
		return (FALSE);
	return (xdr_string(xdrs, &objp->gfh_path, ~0));
}

bool_t
xdr_nfslog_drok(XDR *xdrs, struct nfsdrok *objp)
{
	return (xdr_fhandle(xdrs, &objp->drok_fhandle));
}

bool_t
xdr_nfslog_diropres(XDR *xdrs, struct nfsdiropres *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->dr_status))
		return (FALSE);
	switch (objp->dr_status) {
	case NFS_OK:
		if (!xdr_nfslog_drok(xdrs, &objp->dr_drok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_getattrres(XDR *xdrs, struct nfsattrstat *objp)
{
	return (xdr_nfsstat(xdrs, &objp->ns_status));
}

bool_t
xdr_nfslog_rrok(XDR *xdrs, struct nfsrrok *objp)
{
	if (!xdr_u_int(xdrs, &objp->rrok_attr.na_size))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->rrok_count));
}

bool_t
xdr_nfslog_rdresult(XDR *xdrs, struct nfsrdresult *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->rr_status))
		return (FALSE);
	switch (objp->rr_status) {
	case NFS_OK:
		if (!xdr_nfslog_rrok(xdrs, &objp->rr_u.rr_ok_u))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_writeargs(XDR *xdrs, struct nfswriteargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->wa_args->otw_wa_fhandle))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->wa_args->otw_wa_begoff))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->wa_args->otw_wa_offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->wa_args->otw_wa_totcount))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->wa_count));
}

bool_t
xdr_nfslog_writeresult(XDR *xdrs, struct nfsattrstat *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->ns_status))
		return (FALSE);
	switch (objp->ns_status) {
	case NFS_OK:
		if (!xdr_u_int(xdrs, &objp->ns_u.ns_attr_u.na_size))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_diropargs(XDR *xdrs, struct nfsdiropargs *objp)
{
	if (!xdr_fhandle(xdrs, objp->da_fhandle))
		return (FALSE);
	return (xdr_string(xdrs, &objp->da_name, ~0));
}

bool_t
xdr_nfslog_sattr(XDR *xdrs, struct nfssattr *objp)
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
	return (xdr_nfs2_timeval(xdrs, (nfs2_timeval *)&objp->sa_mtime));
}

bool_t
xdr_nfslog_createargs(XDR *xdrs, struct nfscreatargs *objp)
{
	if (!xdr_nfslog_sattr(xdrs, objp->ca_sa))
		return (FALSE);
	return (xdr_nfslog_diropargs(xdrs, &objp->ca_da));
}

bool_t
xdr_nfslog_setattrargs(XDR *xdrs, struct nfssaargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->saa_fh))
		return (FALSE);
	return (xdr_nfslog_sattr(xdrs, &objp->saa_sa));
}

bool_t
xdr_nfslog_rdlnres(XDR *xdrs, struct nfsrdlnres *objp)
{
	caddr_t	lnres = NULL;
	int count;

	if (!xdr_nfsstat(xdrs, &objp->rl_status))
		return (FALSE);
	switch (objp->rl_status) {
	case NFS_OK:
		if ((count = objp->rl_u.rl_srok_u.srok_count) != 0) {
			/*
			 * allocate extra element for terminating NULL
			 */
			lnres = kmem_alloc(count + 1, KM_SLEEP);
			bcopy(objp->rl_u.rl_srok_u.srok_data, lnres, count);
			lnres[count] = '\0';
		}
		if (!xdr_string(xdrs, &lnres, ~0)) {
			if (lnres != NULL)
				kmem_free(lnres, count + 1);
			return (FALSE);
		}
		if (lnres != NULL)
			kmem_free(lnres, count + 1);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_rnmargs(XDR *xdrs, struct nfsrnmargs *objp)
{
	if (!xdr_nfslog_diropargs(xdrs, &objp->rna_from))
		return (FALSE);
	return (xdr_nfslog_diropargs(xdrs, &objp->rna_to));
}

bool_t
xdr_nfslog_linkargs(XDR *xdrs, struct nfslinkargs *objp)
{
	if (!xdr_fhandle(xdrs, objp->la_from))
		return (FALSE);
	return (xdr_nfslog_diropargs(xdrs, &objp->la_to));
}

bool_t
xdr_nfslog_symlinkargs(XDR *xdrs, struct nfsslargs *objp)
{
	if (!xdr_nfslog_diropargs(xdrs, &objp->sla_from))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->sla_tnm, ~0))
		return (FALSE);
	return (xdr_nfslog_sattr(xdrs, objp->sla_sa));
}

bool_t
xdr_nfslog_statfs(XDR *xdrs, struct nfsstatfs *objp)
{
	return (xdr_nfsstat(xdrs, &objp->fs_status));
}

bool_t
xdr_nfslog_rddirargs(XDR *xdrs, struct nfsrddirargs *objp)
{
	if (!xdr_fhandle(xdrs, &objp->rda_fh))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rda_offset))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->rda_count));
}

bool_t
xdr_nfslog_rdok(XDR *xdrs, struct nfsrdok *objp)
{
	if (!xdr_u_int(xdrs, &objp->rdok_offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->rdok_size))
		return (FALSE);
	return (xdr_bool(xdrs, &objp->rdok_eof));
}

bool_t
xdr_nfslog_rddirres(XDR *xdrs, struct nfsrddirres *objp)
{
	if (!xdr_nfsstat(xdrs, &objp->rd_status))
		return (FALSE);
	switch (objp->rd_status) {
	case NFS_OK:
		if (!xdr_nfslog_rdok(xdrs, &objp->rd_u.rd_rdok_u))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_diropargs3(XDR *xdrs, diropargs3 *objp)
{
	char *name;

	if (!xdr_nfslog_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
	if (objp->name != nfs3nametoolong)
		name = objp->name;
	else {
		/*
		 * The name is not defined, set it to the
		 * zero length string.
		 */
		name = NULL;
	}
	return (xdr_string(xdrs, &name, ~0));
}

bool_t
xdr_nfslog_LOOKUP3res(XDR *xdrs, LOOKUP3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_nfs_fh3(xdrs, &objp->res_u.ok.object))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_set_size3(XDR *xdrs, set_size3 *objp)
{
	if (!xdr_bool(xdrs, &objp->set_it))
		return (FALSE);
	switch (objp->set_it) {
	case TRUE:
		if (!xdr_uint64(xdrs, &objp->size))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_createhow3(XDR *xdrs, createhow3 *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->mode))
		return (FALSE);
	switch (objp->mode) {
	case UNCHECKED:
	case GUARDED:
		if (!xdr_set_size3(xdrs,
			&objp->createhow3_u.obj_attributes.size))
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
xdr_nfslog_CREATE3args(XDR *xdrs, CREATE3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->where))
		return (FALSE);
	return (xdr_nfslog_createhow3(xdrs, &objp->how));
}

bool_t
xdr_nfslog_CREATE3resok(XDR *xdrs, CREATE3resok *objp)
{
	return (xdr_post_op_fh3(xdrs, &objp->obj));
}

bool_t
xdr_nfslog_CREATE3res(XDR *xdrs, CREATE3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_CREATE3resok(xdrs, &objp->res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_GETATTR3res(XDR *xdrs, GETATTR3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_ACCESS3args(XDR *xdrs, ACCESS3args *objp)
{
	return (xdr_nfslog_nfs_fh3(xdrs, &objp->object));
}

bool_t
xdr_nfslog_ACCESS3res(XDR *xdrs, ACCESS3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_SETATTR3args(XDR *xdrs, SETATTR3args *objp)
{
	if (!xdr_nfslog_nfs_fh3(xdrs, &objp->object))
		return (FALSE);
	return (xdr_set_size3(xdrs, &objp->new_attributes.size));
}

bool_t
xdr_nfslog_SETATTR3res(XDR *xdrs, SETATTR3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_READLINK3res(XDR *xdrs, READLINK3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_string(xdrs, &objp->res_u.ok.data, ~0))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_READ3args(XDR *xdrs, READ3args *objp)
{
	if (!xdr_nfslog_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_uint64(xdrs, &objp->offset))
		return (FALSE);
	return (xdr_uint32(xdrs, &objp->count));
}

bool_t
xdr_nfslog_READ3resok(XDR *xdrs, READ3resok *objp)
{
	if (!xdr_uint64(xdrs, &objp->file_attributes.attr.size))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->eof))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->size));
}

bool_t
xdr_nfslog_READ3res(XDR *xdrs, READ3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_READ3resok(xdrs, &objp->res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_WRITE3args(XDR *xdrs, WRITE3args *objp)
{
	if (!xdr_nfslog_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_uint64(xdrs, &objp->offset))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->count))
		return (FALSE);
	return (xdr_enum(xdrs, (enum_t *)&objp->stable));
}

bool_t
xdr_nfslog_WRITE3resok(XDR *xdrs, WRITE3resok *objp)
{
	if (!xdr_uint64(xdrs, &objp->file_wcc.after.attr.size))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->count))
		return (FALSE);
	return (xdr_enum(xdrs, (enum_t *)&objp->committed));
}

bool_t
xdr_nfslog_WRITE3res(XDR *xdrs, WRITE3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_WRITE3resok(xdrs, &objp->res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_MKDIR3args(XDR *xdrs, MKDIR3args *objp)
{
	return (xdr_nfslog_diropargs3(xdrs, &objp->where));
}

bool_t
xdr_nfslog_MKDIR3res(XDR *xdrs, MKDIR3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_post_op_fh3(xdrs, &objp->res_u.ok.obj))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_SYMLINK3args(XDR *xdrs, SYMLINK3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->where))
		return (FALSE);
	return (xdr_string(xdrs, &objp->symlink.symlink_data, ~0));
}

bool_t
xdr_nfslog_SYMLINK3res(XDR *xdrs, SYMLINK3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_post_op_fh3(xdrs, &objp->res_u.ok.obj))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_MKNOD3args(XDR *xdrs, MKNOD3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->where))
		return (FALSE);
	return (xdr_enum(xdrs, (enum_t *)&objp->what.type));
}

bool_t
xdr_nfslog_MKNOD3res(XDR *xdrs, MKNOD3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_post_op_fh3(xdrs, &objp->res_u.ok.obj))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_REMOVE3args(XDR *xdrs, REMOVE3args *objp)
{
	return (xdr_nfslog_diropargs3(xdrs, &objp->object));
}

bool_t
xdr_nfslog_REMOVE3res(XDR *xdrs, REMOVE3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_RMDIR3args(XDR *xdrs, RMDIR3args *objp)
{
	return (xdr_nfslog_diropargs3(xdrs, &objp->object));
}

bool_t
xdr_nfslog_RMDIR3res(XDR *xdrs, RMDIR3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_RENAME3args(XDR *xdrs, RENAME3args *objp)
{
	if (!xdr_nfslog_diropargs3(xdrs, &objp->from))
		return (FALSE);
	return (xdr_nfslog_diropargs3(xdrs, &objp->to));
}

bool_t
xdr_nfslog_RENAME3res(XDR *xdrs, RENAME3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_LINK3args(XDR *xdrs, LINK3args *objp)
{
	if (!xdr_nfslog_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	return (xdr_nfslog_diropargs3(xdrs, &objp->link));
}

bool_t
xdr_nfslog_LINK3res(XDR *xdrs, LINK3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_READDIR3args(XDR *xdrs, READDIR3args *objp)
{
	return (xdr_nfslog_nfs_fh3(xdrs, &objp->dir));
}

bool_t
xdr_nfslog_READDIR3res(XDR *xdrs, READDIR3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_READDIRPLUS3args(XDR *xdrs, READDIRPLUS3args *objp)
{
	if (!xdr_nfslog_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->dircount))
		return (FALSE);
	return (xdr_uint32(xdrs, &objp->maxcount));
}

#ifdef	nextdp
#undef	nextdp
#endif
#define	nextdp(dp)	((struct dirent64 *)((char *)(dp) + (dp)->d_reclen))

bool_t
xdr_nfslog_READDIRPLUS3resok(XDR *xdrs, READDIRPLUS3resok *objp)
{
	struct dirent64 *dp;
	bool_t true = TRUE;
	bool_t false = FALSE;
	int nents;
	char *name;
	entryplus3_info *infop;

	dp = (struct dirent64 *)objp->reply.entries;
	nents = objp->size;
	infop = objp->infop;
	while (nents > 0) {
		if (dp->d_reclen == 0)
			return (FALSE);
		if (dp->d_ino == 0) {
			dp = nextdp(dp);
			infop++;
			nents--;
			continue;
		}
		name = dp->d_name;

		if (!xdr_bool(xdrs, &true) ||
		    !xdr_post_op_fh3(xdrs, &infop->fh) ||
		    !xdr_string(xdrs, &name, ~0)) {
			return (FALSE);
		}
		dp = nextdp(dp);
		infop++;
		nents--;
	}
	if (!xdr_bool(xdrs, &false))
		return (FALSE);

	return (xdr_bool(xdrs, &objp->reply.eof));
}

bool_t
xdr_nfslog_READDIRPLUS3res(XDR *xdrs, READDIRPLUS3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_nfslog_READDIRPLUS3resok(xdrs, &objp->res_u.ok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_nfslog_FSSTAT3args(XDR *xdrs, FSSTAT3args *objp)
{
	return (xdr_nfslog_nfs_fh3(xdrs, &objp->fsroot));
}

bool_t
xdr_nfslog_FSSTAT3res(XDR *xdrs, FSSTAT3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_FSINFO3args(XDR *xdrs, FSINFO3args *objp)
{
	return (xdr_nfslog_nfs_fh3(xdrs, &objp->fsroot));
}

bool_t
xdr_nfslog_FSINFO3res(XDR *xdrs, FSINFO3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_PATHCONF3args(XDR *xdrs, PATHCONF3args *objp)
{
	return (xdr_nfslog_nfs_fh3(xdrs, &objp->object));
}

bool_t
xdr_nfslog_PATHCONF3res(XDR *xdrs, PATHCONF3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_COMMIT3args(XDR *xdrs, COMMIT3args *objp)
{
	if (!xdr_nfslog_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_uint64(xdrs, &objp->offset))
		return (FALSE);
	return (xdr_uint32(xdrs, &objp->count));
}

bool_t
xdr_nfslog_COMMIT3res(XDR *xdrs, COMMIT3res *objp)
{
	return (xdr_enum(xdrs, (enum_t *)&objp->status));
}

bool_t
xdr_nfslog_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	nfs_fh3 fh;

	if (objp->fh3_len > NFS_FHMAXDATA || objp->fh3_xlen > NFS_FHMAXDATA) {
		fh = *objp;
		fh.fh3_len = NFS_FHMAXDATA;
		fh.fh3_xlen = NFS_FHMAXDATA;
		fh.fh3_length = NFS3_OLDFHSIZE;
		return (xdr_nfs_fh3_server(xdrs, &fh));
	}
	return (xdr_nfs_fh3_server(xdrs, objp));
}
