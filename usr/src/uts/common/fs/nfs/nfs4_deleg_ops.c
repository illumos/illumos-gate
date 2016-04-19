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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/systm.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs4.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/time.h>
#include <sys/fem.h>
#include <sys/cmn_err.h>


extern u_longlong_t nfs4_srv_caller_id;

/*
 * This file contains the code for the monitors which are placed on the vnodes
 * of files that are granted delegations by the nfsV4 server.  These monitors
 * will detect local access, as well as access from other servers
 * (NFS and CIFS), that conflict with the delegations and recall the
 * delegation from the client before letting the offending operation continue.
 *
 * If the caller does not want to block while waiting for the delegation to
 * be returned, then it should set CC_DONTBLOCK in the flags of caller context.
 * This does not work for vnevnents; remove and rename, they always block.
 */

/*
 * This is the function to recall a delegation.  It will check if the caller
 * wishes to block or not while waiting for the delegation to be returned.
 * If the caller context flag has CC_DONTBLOCK set, then it will return
 * an error and set CC_WOULDBLOCK instead of waiting for the delegation.
 */

int
recall_all_delegations(rfs4_file_t *fp, bool_t trunc, caller_context_t *ct)
{
	clock_t rc;

	rfs4_recall_deleg(fp, trunc, NULL);

	/* optimization that may not stay */
	delay(NFS4_DELEGATION_CONFLICT_DELAY);

	/* if it has been returned, we're done. */
	rfs4_dbe_lock(fp->rf_dbe);
	if (fp->rf_dinfo.rd_dtype == OPEN_DELEGATE_NONE) {
		rfs4_dbe_unlock(fp->rf_dbe);
		return (0);
	}

	if (ct != NULL && ct->cc_flags & CC_DONTBLOCK) {
		rfs4_dbe_unlock(fp->rf_dbe);
		ct->cc_flags |= CC_WOULDBLOCK;
		return (NFS4ERR_DELAY);
	}

	while (fp->rf_dinfo.rd_dtype != OPEN_DELEGATE_NONE) {
		rc = rfs4_dbe_twait(fp->rf_dbe,
		    ddi_get_lbolt() + SEC_TO_TICK(rfs4_lease_time));
		if (rc == -1) { /* timed out */
			rfs4_dbe_unlock(fp->rf_dbe);
			rfs4_recall_deleg(fp, trunc, NULL);
			rfs4_dbe_lock(fp->rf_dbe);
		}
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	return (0);
}

/* monitor for open on read delegated file */
int
deleg_rd_open(femarg_t *arg, int mode, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	/*
	 * Now that the NFSv4 server calls VOP_OPEN, we need to check to
	 * to make sure it is not us calling open (like for DELEG_CUR) or
	 * we will end up panicing the system.
	 * Since this monitor is for a read delegated file, we know that
	 * only an open for write will cause a conflict.
	 */
	if ((ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) &&
	    (mode & (FWRITE|FTRUNC))) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_open(arg, mode, cr, ct));
}

/* monitor for open on write delegated file */
int
deleg_wr_open(femarg_t *arg, int mode, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	/*
	 * Now that the NFSv4 server calls VOP_OPEN, we need to check to
	 * to make sure it is not us calling open (like for DELEG_CUR) or
	 * we will end up panicing the system.
	 * Since this monitor is for a write delegated file, we know that
	 * any open will cause a conflict.
	 */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_open(arg, mode, cr, ct));
}

/*
 * This is op is for write delegations only and should only be hit
 * by the owner of the delegation.  If not, then someone is
 * doing a read without doing an open first. Like from nfs2/3.
 */
int
deleg_wr_read(femarg_t *arg, uio_t *uiop, int ioflag, cred_t *cr,
    struct caller_context *ct)
{
	int rc;
	rfs4_file_t *fp;

	/* Use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}
	return (vnext_read(arg, uiop, ioflag, cr, ct));
}

/*
 * If someone is doing a write on a read delegated file, it is a conflict.
 * conflicts should be caught at open, but NFSv2&3 don't use OPEN.
 */
int
deleg_rd_write(femarg_t *arg, uio_t *uiop, int ioflag, cred_t *cr,
    struct caller_context *ct)
{
	int rc;
	rfs4_file_t *fp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	rc = recall_all_delegations(fp, FALSE, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_write(arg, uiop, ioflag, cr, ct));
}

/*
 * The owner of the delegation can write the file, but nobody else can.
 * Conflicts should be caught at open, but NFSv2&3 don't use OPEN.
 */
int
deleg_wr_write(femarg_t *arg, uio_t *uiop, int ioflag, cred_t *cr,
    struct caller_context *ct)
{
	int rc;
	rfs4_file_t *fp;

	/* Use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}
	return (vnext_write(arg, uiop, ioflag, cr, ct));
}

/* Doing a setattr on a read delegated file is a conflict. */
int
deleg_rd_setattr(femarg_t *arg, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	bool_t trunc = FALSE;
	rfs4_file_t *fp;

	if ((vap->va_mask & AT_SIZE) && (vap->va_size == 0))
		trunc = TRUE;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	rc = recall_all_delegations(fp, trunc, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_setattr(arg, vap, flags, cr, ct));
}

/* Only the owner of the write delegation can do a setattr */
int
deleg_wr_setattr(femarg_t *arg, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	bool_t trunc = FALSE;
	rfs4_file_t *fp;

	/*
	 * Use caller context to compare caller to delegation owner
	 */
	if (ct == NULL || (ct->cc_caller_id != nfs4_srv_caller_id)) {
		if ((vap->va_mask & AT_SIZE) && (vap->va_size == 0))
			trunc = TRUE;

		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, trunc, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_setattr(arg, vap, flags, cr, ct));
}

int
deleg_rd_rwlock(femarg_t *arg, int write_lock, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	/*
	 * If this is a write lock, then we got us a conflict.
	 */
	if (write_lock) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_rwlock(arg, write_lock, ct));
}

/* Only the owner of the write delegation should be doing this. */
int
deleg_wr_rwlock(femarg_t *arg, int write_lock, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	/* Use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_rwlock(arg, write_lock, ct));
}

int
deleg_rd_space(femarg_t *arg, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	rc = recall_all_delegations(fp, FALSE, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_space(arg, cmd, bfp, flag, offset, cr, ct));
}

int
deleg_wr_space(femarg_t *arg, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	/* Use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_all_delegations(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_space(arg, cmd, bfp, flag, offset, cr, ct));
}

int
deleg_rd_setsecattr(femarg_t *arg, vsecattr_t *vsap, int flag, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;

	/* Changing security attribute triggers recall */
	rc = recall_all_delegations(fp, FALSE, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_setsecattr(arg, vsap, flag, cr, ct));
}

int
deleg_wr_setsecattr(femarg_t *arg, vsecattr_t *vsap, int flag, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;

	/* Changing security attribute triggers recall */
	rc = recall_all_delegations(fp, FALSE, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_setsecattr(arg, vsap, flag, cr, ct));
}

int
deleg_rd_vnevent(femarg_t *arg, vnevent_t vnevent, vnode_t *dvp, char *name,
    caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;
	bool_t trunc = FALSE;

	switch (vnevent) {
	case VE_REMOVE:
	case VE_PRE_RENAME_DEST:
	case VE_RENAME_DEST:
		trunc = TRUE;
		/*FALLTHROUGH*/

	case VE_PRE_RENAME_SRC:
	case VE_RENAME_SRC:
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, trunc, NULL);

		rfs4_dbe_lock(fp->rf_dbe);
		while (fp->rf_dinfo.rd_dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->rf_dbe,
			    ddi_get_lbolt() + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->rf_dbe);
				rfs4_recall_deleg(fp, trunc, NULL);
				rfs4_dbe_lock(fp->rf_dbe);
			}
		}
		rfs4_dbe_unlock(fp->rf_dbe);

		break;

	default:
		break;
	}
	return (vnext_vnevent(arg, vnevent, dvp, name, ct));
}

int
deleg_wr_vnevent(femarg_t *arg, vnevent_t vnevent, vnode_t *dvp, char *name,
    caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;
	bool_t trunc = FALSE;

	switch (vnevent) {
	case VE_REMOVE:
	case VE_PRE_RENAME_DEST:
	case VE_RENAME_DEST:
		trunc = TRUE;
		/*FALLTHROUGH*/

	case VE_PRE_RENAME_SRC:
	case VE_RENAME_SRC:
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, trunc, NULL);
		rfs4_dbe_lock(fp->rf_dbe);
		while (fp->rf_dinfo.rd_dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->rf_dbe,
			    ddi_get_lbolt() + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->rf_dbe);
				rfs4_recall_deleg(fp, trunc, NULL);
				rfs4_dbe_lock(fp->rf_dbe);
			}
		}
		rfs4_dbe_unlock(fp->rf_dbe);

		break;

	default:
		break;
	}
	return (vnext_vnevent(arg, vnevent, dvp, name, ct));
}
