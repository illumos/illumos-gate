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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * will detect local access that conflict with the delegations and recall the
 * delegation from the client before letting the offending operation continue.
 */

/* monitor for open on read delegated file */
int
deleg_rdopen(
	femarg_t *arg,
	int mode,
	cred_t *cr,
	caller_context_t *ct)
{
	clock_t rc;
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
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}

	return (vnext_open(arg, mode, cr, ct));
}

/* monitor for open on write delegated file */
int
deleg_wropen(
	femarg_t *arg,
	int mode,
	cred_t *cr,
	caller_context_t *ct)
{
	clock_t rc;
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
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}

	return (vnext_open(arg, mode, cr, ct));
}

/*
 * this is only a write delegation op and should only be hit
 * by the owner of the delegation.  if not, then someone is
 * doing a read without doing an open first.  shouldn't happen.
 */
int
deleg_read(
	femarg_t *arg,
	uio_t *uiop,
	int ioflag,
	cred_t *cr,
	struct caller_context *ct)
{
	clock_t rc;
	rfs4_file_t *fp;

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}
	return (vnext_read(arg, uiop, ioflag, cr, ct));
}

/*
 * this should only be hit by the owner of the delegation.  if not, then
 * someone is doing a write without doing an open first.  shouldn't happen.
 */
int
deleg_write(
	femarg_t *arg,
	uio_t *uiop,
	int ioflag,
	cred_t *cr,
	struct caller_context *ct)
{
	clock_t rc;
	rfs4_file_t *fp;

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}
	return (vnext_write(arg, uiop, ioflag, cr, ct));
}


int
deleg_setattr(
	femarg_t *arg,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;

	/*
	 * use caller context to compare caller to delegation owner
	 */
	if (ct == NULL || (ct->cc_caller_id != nfs4_srv_caller_id)) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}

	return (vnext_setattr(arg, vap, flags, cr, ct));
}



int
deleg_rd_rwlock(
	femarg_t *arg,
	int write_lock,
	caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;

	/*
	 * if this is a write lock, then use caller context to compare
	 * caller to delegation owner
	 */
	if (write_lock &&
	    (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id)) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}

	return (vnext_rwlock(arg, write_lock, ct));
}

int
deleg_wr_rwlock(
	femarg_t *arg,
	int write_lock,
	caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}

	return (vnext_rwlock(arg, write_lock, ct));
}

int
deleg_space(
	femarg_t *arg,
	int cmd,
	flock64_t *bfp,
	int flag,
	offset_t offset,
	cred_t *cr,
	caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != nfs4_srv_caller_id) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, FALSE, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, FALSE, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
	}

	return (vnext_space(arg, cmd, bfp, flag, offset, cr, ct));
}

int
deleg_setsecattr(
	femarg_t *arg,
	vsecattr_t *vsap,
	int flag,
	cred_t *cr,
	caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;

	/* changing security attribute triggers recall */
	rfs4_recall_deleg(fp, FALSE, NULL);
	rfs4_dbe_lock(fp->dbe);
	while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
		rc = rfs4_dbe_twait(fp->dbe,
		    lbolt + SEC_TO_TICK(rfs4_lease_time));
		if (rc == -1) { /* timed out */
			rfs4_dbe_unlock(fp->dbe);
			rfs4_recall_deleg(fp, FALSE, NULL);
			rfs4_dbe_lock(fp->dbe);
		}
	}
	rfs4_dbe_unlock(fp->dbe);

	return (vnext_setsecattr(arg, vsap, flag, cr, ct));
}

/* ARGSUSED */
int
deleg_vnevent(
	femarg_t *arg,
	vnevent_t vnevent,
	vnode_t *dvp,
	char *name,
	caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;
	bool_t trunc = FALSE;

	switch (vnevent) {
	case VE_REMOVE:
	case VE_RENAME_DEST:
		trunc = TRUE;
		/*FALLTHROUGH*/

	case VE_RENAME_SRC:
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, trunc, NULL);
		rfs4_dbe_lock(fp->dbe);
		while (fp->dinfo->dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->dbe,
			    lbolt + SEC_TO_TICK(rfs4_lease_time));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->dbe);
				rfs4_recall_deleg(fp, trunc, NULL);
				rfs4_dbe_lock(fp->dbe);
			}
		}
		rfs4_dbe_unlock(fp->dbe);
		break;

	default:
		break;
	}
	return (vnext_vnevent(arg, vnevent, dvp, name, ct));
}
