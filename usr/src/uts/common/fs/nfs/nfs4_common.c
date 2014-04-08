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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2011, 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2013 Joyent, Inc. All rights reserved.
 */

/*
 * This is the loadable module wrapper.
 */
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs4.h>
#include <nfs/rnode4.h>

/*
 * The global tag list.
 */
ctag_t nfs4_ctags[] = NFS4_TAG_INITIALIZER;

/*
 * The NFS Version 4 client VFS.
 */
static vfsdef_t vfw4 = {
	VFSDEF_VERSION,
	"nfs4",
	nfs4init,
	VSW_CANREMOUNT|VSW_NOTZONESAFE|VSW_STATS,
	NULL
};

struct modlfs modlfs4 = {
	&mod_fsops,
	"network filesystem version 4",
	&vfw4
};

uint_t nfs4_max_transfer_size = 32 * 1024;
uint_t nfs4_max_transfer_size_cots = 1024 * 1024;
uint_t nfs4_max_transfer_size_rdma = 1024 * 1024;

int
nfs4tsize(void)
{
	/*
	 * For the moment, just return nfs4_max_transfer_size until we
	 * can query the appropriate transport.
	 */
	return (nfs4_max_transfer_size);
}

uint_t
nfs4_tsize(struct knetconfig *knp)
{

	if (knp->knc_semantics == NC_TPI_COTS_ORD ||
	    knp->knc_semantics == NC_TPI_COTS)
		return (nfs4_max_transfer_size_cots);
	if (knp->knc_semantics == NC_TPI_RDMA)
		return (nfs4_max_transfer_size_rdma);
	return (nfs4_max_transfer_size);
}

uint_t
rfs4_tsize(struct svc_req *req)
{

	if (req->rq_xprt->xp_type == T_COTS_ORD ||
	    req->rq_xprt->xp_type == T_COTS)
		return (nfs4_max_transfer_size_cots);
	if (req->rq_xprt->xp_type == T_RDMA)
		return (nfs4_max_transfer_size_rdma);
	return (nfs4_max_transfer_size);
}

int
nfs4_setopts(vnode_t *vp, model_t model, struct nfs_args *buf)
{
	mntinfo4_t *mi;			/* mount info, pointed at by vfs */
	STRUCT_HANDLE(nfs_args, args);
	int flags;

#ifdef lint
	model = model;
#endif

	STRUCT_SET_HANDLE(args, model, buf);

	flags = STRUCT_FGET(args, flags);

	/*
	 * Set option fields in mount info record
	 */
	mi = VTOMI4(vp);


	if (flags & NFSMNT_NOAC) {
		mutex_enter(&mi->mi_lock);
		mi->mi_flags |= MI4_NOAC;
		mutex_exit(&mi->mi_lock);
		PURGE_ATTRCACHE4(vp);
	}

	mutex_enter(&mi->mi_lock);
	if (flags & NFSMNT_NOCTO)
		mi->mi_flags |= MI4_NOCTO;
	if (flags & NFSMNT_LLOCK)
		mi->mi_flags |= MI4_LLOCK;
	if (flags & NFSMNT_GRPID)
		mi->mi_flags |= MI4_GRPID;
	mutex_exit(&mi->mi_lock);

	if (flags & NFSMNT_RETRANS) {
		if (STRUCT_FGET(args, retrans) < 0)
			return (EINVAL);
		mi->mi_retrans = STRUCT_FGET(args, retrans);
	}
	if (flags & NFSMNT_TIMEO) {
		if (STRUCT_FGET(args, timeo) <= 0)
			return (EINVAL);
		mi->mi_timeo = STRUCT_FGET(args, timeo);
	}
	if (flags & NFSMNT_RSIZE) {
		if (STRUCT_FGET(args, rsize) <= 0)
			return (EINVAL);
		mi->mi_tsize = MIN(mi->mi_tsize, STRUCT_FGET(args, rsize));
		mi->mi_curread = MIN(mi->mi_curread, mi->mi_tsize);
	}
	if (flags & NFSMNT_WSIZE) {
		if (STRUCT_FGET(args, wsize) <= 0)
			return (EINVAL);
		mi->mi_stsize = MIN(mi->mi_stsize, STRUCT_FGET(args, wsize));
		mi->mi_curwrite = MIN(mi->mi_curwrite, mi->mi_stsize);
	}
	if (flags & NFSMNT_ACREGMIN) {
		if (STRUCT_FGET(args, acregmin) < 0)
			mi->mi_acregmin = SEC2HR(ACMINMAX);
		else
			mi->mi_acregmin = SEC2HR(MIN(STRUCT_FGET(args,
			    acregmin), ACMINMAX));
	}
	if (flags & NFSMNT_ACREGMAX) {
		if (STRUCT_FGET(args, acregmax) < 0)
			mi->mi_acregmax = SEC2HR(ACMAXMAX);
		else
			mi->mi_acregmax = SEC2HR(MIN(STRUCT_FGET(args,
			    acregmax), ACMAXMAX));
	}
	if (flags & NFSMNT_ACDIRMIN) {
		if (STRUCT_FGET(args, acdirmin) < 0)
			mi->mi_acdirmin = SEC2HR(ACMINMAX);
		else
			mi->mi_acdirmin = SEC2HR(MIN(STRUCT_FGET(args,
			    acdirmin), ACMINMAX));
	}
	if (flags & NFSMNT_ACDIRMAX) {
		if (STRUCT_FGET(args, acdirmax) < 0)
			mi->mi_acdirmax = SEC2HR(ACMAXMAX);
		else
			mi->mi_acdirmax = SEC2HR(MIN(STRUCT_FGET(args,
			    acdirmax), ACMAXMAX));
	}

	return (0);
}

/*
 * This returns 1 if the seqid should be bumped upon receiving this
 * 'res->status' for a seqid dependent operation; otherwise return 0.
 */
int
nfs4_need_to_bump_seqid(COMPOUND4res_clnt *res)
{
	int i, seqid_dep_op = 0;
	nfs_resop4 *resop;

	resop = res->array;

	for (i = 0; i < res->array_len; i++) {
		switch (resop[i].resop) {
		case OP_CLOSE:
		case OP_OPEN:
		case OP_OPEN_CONFIRM:
		case OP_OPEN_DOWNGRADE:
		case OP_LOCK:
		case OP_LOCKU:
			seqid_dep_op = 1;
			break;
		default:
			continue;
		}
	}

	if (!seqid_dep_op)
		return (0);

	switch (res->status) {
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_STALE_STATEID:
	case NFS4ERR_BAD_STATEID:
	case NFS4ERR_BAD_SEQID:
	case NFS4ERR_BADXDR:
	case NFS4ERR_OLD_STATEID:
	case NFS4ERR_RESOURCE:
	case NFS4ERR_NOFILEHANDLE:
		return (0);
	default:
		return (1);
	}
}

/*
 * Returns 1 if the error is a RPC error that we should retry.
 */
int
nfs4_rpc_retry_error(int error)
{
	switch (error) {
	case ETIMEDOUT:
	case ECONNREFUSED:
	case ENETDOWN:
	case ENETUNREACH:
	case ENETRESET:
	case ECONNABORTED:
	case EHOSTUNREACH:
	case ECONNRESET:
		return (1);
	default:
		return (0);
	}
}

char *
nfs4_stat_to_str(nfsstat4 error)
{
	static char	buf[40];

	switch (error) {
	case NFS4_OK:
		return ("NFS4_OK");
	case NFS4ERR_PERM:
		return ("NFS4ERR_PERM");
	case NFS4ERR_NOENT:
		return ("NFS4ERR_NOENT");
	case NFS4ERR_IO:
		return ("NFS4ERR_IO");
	case NFS4ERR_NXIO:
		return ("NFS4ERR_NXIO");
	case NFS4ERR_ACCESS:
		return ("NFS4ERR_ACCESS");
	case NFS4ERR_EXIST:
		return ("NFS4ERR_EXIST");
	case NFS4ERR_XDEV:
		return ("NFS4ERR_XDEV");
	case NFS4ERR_NOTDIR:
		return ("NFS4ERR_NOTDIR");
	case NFS4ERR_ISDIR:
		return ("NFS4ERR_ISDIR");
	case NFS4ERR_INVAL:
		return ("NFS4ERR_INVAL");
	case NFS4ERR_FBIG:
		return ("NFS4ERR_FBIG");
	case NFS4ERR_NOSPC:
		return ("NFS4ERR_NOSPC");
	case NFS4ERR_ROFS:
		return ("NFS4ERR_ROFS");
	case NFS4ERR_MLINK:
		return ("NFS4ERR_MLINK");
	case NFS4ERR_NAMETOOLONG:
		return ("NFS4ERR_NAMETOOLONG");
	case NFS4ERR_NOTEMPTY:
		return ("NFSS4ERR_NOTEMPTY");
	case NFS4ERR_DQUOT:
		return ("NFS4ERR_DQUOT");
	case NFS4ERR_STALE:
		return ("NFS4ERR_STALE");
	case NFS4ERR_BADHANDLE:
		return ("NFS4ERR_BADHANDLE");
	case NFS4ERR_BAD_COOKIE:
		return ("NFS4ERR_BAD_COOKIE");
	case NFS4ERR_NOTSUPP:
		return ("NFS4ERR_NOTSUPP");
	case NFS4ERR_TOOSMALL:
		return ("NFS4ERR_TOOSMALL");
	case NFS4ERR_SERVERFAULT:
		return ("NFS4ERR_SERVERFAULT");
	case NFS4ERR_BADTYPE:
		return ("NFS4ERR_BADTYPE");
	case NFS4ERR_DELAY:
		return ("NFS4ERR_DELAY");
	case NFS4ERR_SAME:
		return ("NFS4ERR_SAME");
	case NFS4ERR_DENIED:
		return ("NFS4ERR_DENIED");
	case NFS4ERR_EXPIRED:
		return ("NFS4ERR_EXPIRED");
	case NFS4ERR_LOCKED:
		return ("NFS4ERR_LOCKED");
	case NFS4ERR_GRACE:
		return ("NFS4ERR_GRACE");
	case NFS4ERR_FHEXPIRED:
		return ("NFS4ERR_FHEXPIRED");
	case NFS4ERR_SHARE_DENIED:
		return ("NFS4ERR_SHARE_DENIED");
	case NFS4ERR_WRONGSEC:
		return ("NFS4ERR_WRONGSEC");
	case NFS4ERR_CLID_INUSE:
		return ("NFS4ERR_CLID_INUSE");
	case NFS4ERR_RESOURCE:
		return ("NFS4ERR_RESOURCE");
	case NFS4ERR_MOVED:
		return ("NFS4ERR_MOVED");
	case NFS4ERR_NOFILEHANDLE:
		return ("NFS4ERR_NOFILEHANDLE");
	case NFS4ERR_MINOR_VERS_MISMATCH:
		return ("NFS4ERR_MINOR_VERS_MISMATCH");
	case NFS4ERR_STALE_CLIENTID:
		return ("NFS4ERR_STALE_CLIENTID");
	case NFS4ERR_STALE_STATEID:
		return ("NFS4ERR_STALE_STATEID");
	case NFS4ERR_OLD_STATEID:
		return ("NFS4ERR_OLD_STATEID");
	case NFS4ERR_BAD_STATEID:
		return ("NFS4ERR_BAD_STATEID");
	case NFS4ERR_BAD_SEQID:
		return ("NFS4ERR_BAD_SEQID");
	case NFS4ERR_NOT_SAME:
		return ("NFS4ERR_NOT_SAME");
	case NFS4ERR_LOCK_RANGE:
		return ("NFS4ERR_LOCK_RANGE");
	case NFS4ERR_SYMLINK:
		return ("NFS4ERR_SYMLINK");
	case NFS4ERR_RESTOREFH:
		return ("NFS4ERR_RESTOREFH");
	case NFS4ERR_LEASE_MOVED:
		return ("NFS4ERR_LEASE_MOVED");
	case NFS4ERR_ATTRNOTSUPP:
		return ("NFS4ERR_ATTRNOTSUPP");
	case NFS4ERR_NO_GRACE:
		return ("NFS4ERR_NO_GRACE");
	case NFS4ERR_RECLAIM_BAD:
		return ("NFS4ERR_RECLAIM_BAD");
	case NFS4ERR_RECLAIM_CONFLICT:
		return ("NFS4ERR_RECLAIM_CONFLICT");
	case NFS4ERR_BADXDR:
		return ("NFS4ERR_BADXDR");
	case NFS4ERR_LOCKS_HELD:
		return ("NFS4ERR_LOCKS_HELD");
	case NFS4ERR_OPENMODE:
		return ("NFS4ERR_OPENMODE");
	case NFS4ERR_BADOWNER:
		return ("NFS4ERR_BADOWNER");
	case NFS4ERR_BADCHAR:
		return ("NFS4ERR_BADCHAR");
	case NFS4ERR_BADNAME:
		return ("NFS4ERR_BADNAME");
	case NFS4ERR_BAD_RANGE:
		return ("NFS4ERR_BAD_RANGE");
	case NFS4ERR_LOCK_NOTSUPP:
		return ("NFS4ERR_LOCK_NOTSUPP");
	case NFS4ERR_OP_ILLEGAL:
		return ("NFS4ERR_OP_ILLEGAL");
	case NFS4ERR_DEADLOCK:
		return ("NFS4ERR_DEADLOCK");
	case NFS4ERR_FILE_OPEN:
		return ("NFS4ERR_FILE_OPEN");
	case NFS4ERR_ADMIN_REVOKED:
		return ("NFS4ERR_ADMIN_REVOKED");
	case NFS4ERR_CB_PATH_DOWN:
		return ("NFS4ERR_CB_PATH_DOWN");
	default:
		(void) snprintf(buf, 40, "Unknown error %d", (int)error);
		return (buf);
	}
}

char *
nfs4_recov_action_to_str(nfs4_recov_t what)
{
	static char buf[40];

	switch (what) {
	case NR_STALE:
		return ("NR_STALE");
	case NR_FAILOVER:
		return ("NR_FAILOVER");
	case NR_CLIENTID:
		return ("NR_CLIENTID");
	case NR_OPENFILES:
		return ("NR_OPENFILES");
	case NR_WRONGSEC:
		return ("NR_WRONGSEC");
	case NR_EXPIRED:
		return ("NR_EXPIRED");
	case NR_BAD_STATEID:
		return ("NR_BAD_STATEID");
	case NR_FHEXPIRED:
		return ("NR_FHEXPIRED");
	case NR_BADHANDLE:
		return ("NR_BADHANDLE");
	case NR_BAD_SEQID:
		return ("NR_BAD_SEQID");
	case NR_OLDSTATEID:
		return ("NR_OLDSTATEID");
	case NR_GRACE:
		return ("NR_GRACE");
	case NR_DELAY:
		return ("NR_DELAY");
	case NR_LOST_LOCK:
		return ("NR_LOST_LOCK");
	case NR_LOST_STATE_RQST:
		return ("NR_LOST_STATE_RQST");
	case NR_MOVED:
		return ("NR_MOVED");
	default:
		(void) snprintf(buf, 40, "Unknown, code %d", (int)what);
		return (buf);
	}
}

char *
nfs4_op_to_str(nfs_opnum4 op)
{
	static char buf[40];

	switch (REAL_OP4(op)) {
	case OP_ACCESS:
		return ("OP_ACCESS");
	case OP_CLOSE:
		return ("OP_CLOSE");
	case OP_COMMIT:
		return ("OP_COMMIT");
	case OP_CREATE:
		return ("OP_CREATE");
	case OP_DELEGPURGE:
		return ("OP_DELEGPURGE");
	case OP_DELEGRETURN:
		return ("OP_DELEGRETURN");
	case OP_GETATTR:
		return ("OP_GETATTR");
	case OP_GETFH:
		return ("OP_GETFH");
	case OP_LINK:
		return ("OP_LINK");
	case OP_LOCK:
		return ("OP_LOCK");
	case OP_LOCKT:
		return ("OP_LOCKT");
	case OP_LOCKU:
		return ("OP_LOCKU");
	case OP_LOOKUP:
		return ("OP_LOOKUP");
	case OP_LOOKUPP:
		return ("OP_LOOKUPP");
	case OP_NVERIFY:
		return ("OP_NVERIFY");
	case OP_OPEN:
		return ("OP_OPEN");
	case OP_OPENATTR:
		return ("OP_OPENATTR");
	case OP_OPEN_CONFIRM:
		return ("OP_OPEN_CONFIRM");
	case OP_OPEN_DOWNGRADE:
		return ("OP_OPEN_DOWNGRADE");
	case OP_PUTFH:
		return ("OP_PUTFH");
	case OP_PUTPUBFH:
		return ("OP_PUTPUBFH");
	case OP_PUTROOTFH:
		return ("OP_PUTROOTFH");
	case OP_READ:
		return ("OP_READ");
	case OP_READDIR:
		return ("OP_READDIR");
	case OP_READLINK:
		return ("OP_READLINK");
	case OP_REMOVE:
		return ("OP_REMOVE");
	case OP_RENAME:
		return ("OP_RENAME");
	case OP_RENEW:
		return ("OP_RENEW");
	case OP_RESTOREFH:
		return ("OP_RESTOREFH");
	case OP_SAVEFH:
		return ("OP_SAVEFH");
	case OP_SECINFO:
		return ("OP_SECINFO");
	case OP_SETATTR:
		return ("OP_SETATTR");
	case OP_SETCLIENTID:
		return ("OP_SETCLIENTID");
	case OP_SETCLIENTID_CONFIRM:
		return ("OP_SETCLIENTID_CONFIRM");
	case OP_VERIFY:
		return ("OP_VERIFY");
	case OP_WRITE:
		return ("OP_WRITE");
	case OP_RELEASE_LOCKOWNER:
		return ("OP_RELEASE_LOCKOWNER");
	case OP_ILLEGAL:
		return ("OP_ILLEGAL");
	default:
		(void) snprintf(buf, 40, "Unknown op %d", (int)op);
		return (buf);
	}
}
