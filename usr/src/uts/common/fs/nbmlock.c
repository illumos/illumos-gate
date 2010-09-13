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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Utility routines and top-level conflict detection code for NBMAND
 * locks.
 */

#include <sys/nbmlock.h>
#include <sys/rwlock.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/vfs.h>

/*
 * Enter the critical region for synchronizing I/O requests with lock/share
 * requests.  "mode" specifies whether the caller intends to update
 * lock/share state (as opposed to just query it).
 */

void
nbl_start_crit(vnode_t *vp, krw_t mode)
{
	rw_enter(&vp->v_nbllock, mode);
}

/*
 * Leave the critical region.
 */

void
nbl_end_crit(vnode_t *vp)
{
	rw_exit(&vp->v_nbllock);
}

/*
 * Return non-zero if some thread is in the critical region.
 * Note that this is appropriate for use in ASSERT()s only.
 */

int
nbl_in_crit(vnode_t *vp)
{
	return (RW_LOCK_HELD(&vp->v_nbllock));
}

/*
 * Returns non-zero if we need to look further for an NBMAND lock or
 * share conflict.
 */
int
nbl_need_check(vnode_t *vp)
{
	/*
	 * Currently we only check if NBMAND locks/shares are allowed on
	 * the filesystem.  An option for the future would be to have a
	 * flag on the vnode, though the locking for that can get tricky.
	 */
	return ((vp->v_vfsp) && (vp->v_vfsp->vfs_flag & VFS_NBMAND));
}

/*
 * Top-level conflict detection routine.  The arguments describe the
 * operation that is being attempted.  If the operation conflicts with an
 * existing lock or share reservation, a non-zero value is returned.  If
 * the operation is allowed, zero is returned.  Note that there is an
 * implicit argument, which is the process ID of the requester.
 *
 * svmand indicates that the file has System V mandatory locking enabled,
 * so we should look at all record locks, not just NBMAND record locks.
 * (This is to avoid a deadlock between a process making an I/O request and
 * a process trying to release a lock.  Instead of letting the first
 * process block in the filesystem code, we flag a conflict here.)
 */

int
nbl_conflict(vnode_t *vp,
		nbl_op_t op,		/* attempted operation */
		u_offset_t offset,	/* ignore if not I/O */
		ssize_t length,		/* ignore if not I/O */
		int svmand,		/* System V mandatory locking */
		caller_context_t *ct)	/* caller context */
{
	ASSERT(nbl_in_crit(vp));
	ASSERT(op == NBL_READ || op == NBL_WRITE || op == NBL_RENAME ||
	    op == NBL_REMOVE || op == NBL_READWRITE);

	if (nbl_share_conflict(vp, op, ct)) {
		return (1);
	}

	/*
	 * If this is not an I/O request, there's no need to check against
	 * the locks on the file.
	 */
	if (op == NBL_REMOVE || op == NBL_RENAME)
		return (0);

	return (nbl_lock_conflict(vp, op, offset, length, svmand, ct));
}

/*
 * Determine if the given file has mode bits for System V mandatory locks.
 * If there was an error, the errno value is returned.  Otherwise, zero is
 * returned and *svp is set appropriately (non-zero for mandatory locks,
 * zero for no mandatory locks).
 */

int
nbl_svmand(vnode_t *vp, cred_t *cr, int *svp)
{
	struct vattr va;
	int error;

	va.va_mask = AT_MODE;
	error = VOP_GETATTR(vp, &va, 0, cr, NULL);
	if (error != 0)
		return (error);

	*svp = MANDLOCK(vp, va.va_mode);
	return (0);
}
