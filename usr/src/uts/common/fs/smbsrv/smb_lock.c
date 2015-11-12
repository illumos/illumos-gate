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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This module provides range lock functionality for CIFS/SMB clients.
 * Lock range service functions process SMB lock and and unlock
 * requests for a file by applying lock rules and marks file range
 * as locked if the lock is successful otherwise return proper
 * error code.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <sys/nbmlock.h>
#include <sys/param.h>

extern caller_context_t smb_ct;

static void smb_lock_posix_unlock(smb_node_t *, smb_lock_t *, cred_t *);
static boolean_t smb_is_range_unlocked(uint64_t, uint64_t, uint32_t,
    smb_llist_t *, uint64_t *);
static int smb_lock_range_overlap(smb_lock_t *, uint64_t, uint64_t);
static uint32_t smb_lock_range_lckrules(smb_request_t *, smb_ofile_t *,
    smb_node_t *, smb_lock_t *, smb_lock_t **);
static clock_t smb_lock_wait(smb_request_t *, smb_lock_t *, smb_lock_t *);
static uint32_t smb_lock_range_ulckrules(smb_request_t *, smb_node_t *,
    uint64_t, uint64_t, smb_lock_t **nodelock);
static smb_lock_t *smb_lock_create(smb_request_t *, uint64_t, uint64_t,
    uint32_t, uint32_t);
static void smb_lock_destroy(smb_lock_t *);
static void smb_lock_free(smb_lock_t *);

/*
 * Return the number of range locks on the specified ofile.
 */
uint32_t
smb_lock_get_lock_count(smb_node_t *node, smb_ofile_t *of)
{
	smb_lock_t 	*lock;
	smb_llist_t	*llist;
	uint32_t	count = 0;

	SMB_NODE_VALID(node);
	SMB_OFILE_VALID(of);

	llist = &node->n_lock_list;

	smb_llist_enter(llist, RW_READER);
	for (lock = smb_llist_head(llist);
	    lock != NULL;
	    lock = smb_llist_next(llist, lock)) {
		if (lock->l_file == of)
			++count;
	}
	smb_llist_exit(llist);

	return (count);
}

/*
 * smb_unlock_range
 *
 * locates lock range performed for corresponding to unlock request.
 *
 * NT_STATUS_SUCCESS - Lock range performed successfully.
 * !NT_STATUS_SUCCESS - Error in unlock range operation.
 */
uint32_t
smb_unlock_range(
    smb_request_t	*sr,
    smb_node_t		*node,
    uint64_t		start,
    uint64_t		length)
{
	smb_lock_t	*lock = NULL;
	uint32_t	status;

	/* Apply unlocking rules */
	smb_llist_enter(&node->n_lock_list, RW_WRITER);
	status = smb_lock_range_ulckrules(sr, node, start, length, &lock);
	if (status != NT_STATUS_SUCCESS) {
		/*
		 * If lock range is not matching in the list
		 * return error.
		 */
		ASSERT(lock == NULL);
		smb_llist_exit(&node->n_lock_list);
		return (status);
	}

	smb_llist_remove(&node->n_lock_list, lock);
	smb_lock_posix_unlock(node, lock, sr->user_cr);
	smb_llist_exit(&node->n_lock_list);
	smb_lock_destroy(lock);

	return (status);
}

/*
 * smb_lock_range
 *
 * Checks for integrity of file lock operation for the given range of file data.
 * This is performed by applying lock rules with all the elements of the node
 * lock list.
 *
 * Break shared (levelII) oplocks. If there is an exclusive oplock, it is
 * owned by this ofile and therefore should not be broken.
 *
 * The function returns with new lock added if lock request is non-conflicting
 * with existing range lock for the file. Otherwise smb request is filed
 * without returning.
 *
 * NT_STATUS_SUCCESS - Lock range performed successfully.
 * !NT_STATUS_SUCCESS - Error in lock range operation.
 */
uint32_t
smb_lock_range(
    smb_request_t	*sr,
    uint64_t		start,
    uint64_t		length,
    uint32_t		timeout,
    uint32_t		locktype)
{
	smb_ofile_t	*file = sr->fid_ofile;
	smb_node_t	*node = file->f_node;
	smb_lock_t	*lock;
	smb_lock_t	*clock = NULL;
	uint32_t	result = NT_STATUS_SUCCESS;
	boolean_t	lock_has_timeout =
	    (timeout != 0 && timeout != UINT_MAX);

	lock = smb_lock_create(sr, start, length, locktype, timeout);

	smb_llist_enter(&node->n_lock_list, RW_WRITER);
	for (;;) {
		clock_t	rc;

		/* Apply locking rules */
		result = smb_lock_range_lckrules(sr, file, node, lock, &clock);

		if ((result == NT_STATUS_CANCELLED) ||
		    (result == NT_STATUS_SUCCESS) ||
		    (result == NT_STATUS_RANGE_NOT_LOCKED)) {
			ASSERT(clock == NULL);
			break;
		} else if (timeout == 0) {
			break;
		}

		ASSERT(result == NT_STATUS_LOCK_NOT_GRANTED);
		ASSERT(clock);
		/*
		 * Call smb_lock_wait holding write lock for
		 * node lock list.  smb_lock_wait will release
		 * this lock if it blocks.
		 */
		ASSERT(node == clock->l_file->f_node);

		rc = smb_lock_wait(sr, lock, clock);
		if (rc == 0) {
			result = NT_STATUS_CANCELLED;
			break;
		}
		if (rc == -1)
			timeout = 0;

		clock = NULL;
	}

	lock->l_blocked_by = NULL;

	if (result != NT_STATUS_SUCCESS) {
		/*
		 * Under certain conditions NT_STATUS_FILE_LOCK_CONFLICT
		 * should be returned instead of NT_STATUS_LOCK_NOT_GRANTED.
		 * All of this appears to be specific to SMB1
		 */
		if (sr->session->dialect <= NT_LM_0_12 &&
		    result == NT_STATUS_LOCK_NOT_GRANTED) {
			/*
			 * Locks with timeouts always return
			 * NT_STATUS_FILE_LOCK_CONFLICT
			 */
			if (lock_has_timeout)
				result = NT_STATUS_FILE_LOCK_CONFLICT;

			/*
			 * Locks starting higher than 0xef000000 that do not
			 * have the MSB set always return
			 * NT_STATUS_FILE_LOCK_CONFLICT
			 */
			if ((lock->l_start >= 0xef000000) &&
			    !(lock->l_start & (1ULL << 63))) {
				result = NT_STATUS_FILE_LOCK_CONFLICT;
			}

			/*
			 * If the last lock attempt to fail on this file handle
			 * started at the same offset as this one then return
			 * NT_STATUS_FILE_LOCK_CONFLICT
			 */
			mutex_enter(&file->f_mutex);
			if ((file->f_flags & SMB_OFLAGS_LLF_POS_VALID) &&
			    (lock->l_start == file->f_llf_pos)) {
				result = NT_STATUS_FILE_LOCK_CONFLICT;
			}
			mutex_exit(&file->f_mutex);
		}

		/* Update last lock failed offset */
		mutex_enter(&file->f_mutex);
		file->f_llf_pos = lock->l_start;
		file->f_flags |= SMB_OFLAGS_LLF_POS_VALID;
		mutex_exit(&file->f_mutex);

		smb_lock_free(lock);
	} else {
		/*
		 * don't insert into the CIFS lock list unless the
		 * posix lock worked
		 */
		if (smb_fsop_frlock(node, lock, B_FALSE, sr->user_cr))
			result = NT_STATUS_FILE_LOCK_CONFLICT;
		else
			smb_llist_insert_tail(&node->n_lock_list, lock);
	}
	smb_llist_exit(&node->n_lock_list);

	if (result == NT_STATUS_SUCCESS)
		smb_oplock_break_levelII(node);

	return (result);
}


/*
 * smb_lock_range_access
 *
 * scans node lock list
 * to check if there is any overlapping lock. Overlapping
 * lock is allowed only under same session and client pid.
 *
 * Return values
 *	NT_STATUS_SUCCESS		lock access granted.
 *	NT_STATUS_FILE_LOCK_CONFLICT 	access denied due to lock conflict.
 */
int
smb_lock_range_access(
    smb_request_t	*sr,
    smb_node_t		*node,
    uint64_t		start,
    uint64_t		length,	 /* zero means to EoF */
    boolean_t		will_write)
{
	smb_lock_t	*lock;
	smb_llist_t	*llist;
	int		status = NT_STATUS_SUCCESS;

	llist = &node->n_lock_list;
	smb_llist_enter(llist, RW_READER);
	/* Search for any applicable lock */
	for (lock = smb_llist_head(llist);
	    lock != NULL;
	    lock = smb_llist_next(llist, lock)) {

		if (!smb_lock_range_overlap(lock, start, length))
			/* Lock does not overlap */
			continue;

		if (lock->l_type == SMB_LOCK_TYPE_READONLY && !will_write)
			continue;

		if (lock->l_type == SMB_LOCK_TYPE_READWRITE &&
		    lock->l_session_kid == sr->session->s_kid &&
		    lock->l_pid == sr->smb_pid)
			continue;

		status = NT_STATUS_FILE_LOCK_CONFLICT;
		break;
	}
	smb_llist_exit(llist);
	return (status);
}

void
smb_node_destroy_lock_by_ofile(smb_node_t *node, smb_ofile_t *file)
{
	smb_lock_t	*lock;
	smb_lock_t	*nxtl;
	list_t		destroy_list;

	SMB_NODE_VALID(node);
	ASSERT(node->n_refcnt);

	/*
	 * Move locks matching the specified file from the node->n_lock_list
	 * to a temporary list (holding the lock the entire time) then
	 * destroy all the matching locks.  We can't call smb_lock_destroy
	 * while we are holding the lock for node->n_lock_list because we will
	 * deadlock and we can't drop the lock because the list contents might
	 * change (for example nxtl might get removed on another thread).
	 */
	list_create(&destroy_list, sizeof (smb_lock_t),
	    offsetof(smb_lock_t, l_lnd));

	smb_llist_enter(&node->n_lock_list, RW_WRITER);
	lock = smb_llist_head(&node->n_lock_list);
	while (lock) {
		nxtl = smb_llist_next(&node->n_lock_list, lock);
		if (lock->l_file == file) {
			smb_llist_remove(&node->n_lock_list, lock);
			smb_lock_posix_unlock(node, lock, file->f_user->u_cred);
			list_insert_tail(&destroy_list, lock);
		}
		lock = nxtl;
	}
	smb_llist_exit(&node->n_lock_list);

	lock = list_head(&destroy_list);
	while (lock) {
		nxtl = list_next(&destroy_list, lock);
		list_remove(&destroy_list, lock);
		smb_lock_destroy(lock);
		lock = nxtl;
	}

	list_destroy(&destroy_list);
}

void
smb_lock_range_error(smb_request_t *sr, uint32_t status32)
{
	uint16_t errcode;

	if (status32 == NT_STATUS_CANCELLED)
		errcode = ERROR_OPERATION_ABORTED;
	else
		errcode = ERRlock;

	smbsr_error(sr, status32, ERRDOS, errcode);
}

/*
 * An SMB variant of nbl_conflict().
 *
 * SMB prevents remove or rename when conflicting locks exist
 * (unlike NFS, which is why we can't just use nbl_conflict).
 *
 * Returns:
 *	NT_STATUS_SHARING_VIOLATION - nbl_share_conflict
 *	NT_STATUS_FILE_LOCK_CONFLICT - nbl_lock_conflict
 *	NT_STATUS_SUCCESS - operation can proceed
 *
 * NB: This function used to also check the list of ofiles,
 * via: smb_lock_range_access() but we _can't_ do that here
 * due to lock order constraints between node->n_lock_list
 * and node->vp->vnbllock (taken via nvl_start_crit).
 * They must be taken in that order, and in here, we
 * already hold vp->vnbllock.
 */
DWORD
smb_nbl_conflict(smb_node_t *node, uint64_t off, uint64_t len, nbl_op_t op)
{
	int svmand;

	SMB_NODE_VALID(node);
	ASSERT(smb_node_in_crit(node));
	ASSERT(op == NBL_READ || op == NBL_WRITE || op == NBL_READWRITE ||
	    op == NBL_REMOVE || op == NBL_RENAME);

	if (smb_node_is_dir(node))
		return (NT_STATUS_SUCCESS);

	if (nbl_share_conflict(node->vp, op, &smb_ct))
		return (NT_STATUS_SHARING_VIOLATION);

	/*
	 * When checking for lock conflicts, rename and remove
	 * are not allowed, so treat those as read/write.
	 */
	if (op == NBL_RENAME || op == NBL_REMOVE)
		op = NBL_READWRITE;

	if (nbl_svmand(node->vp, zone_kcred(), &svmand))
		svmand = 1;

	if (nbl_lock_conflict(node->vp, op, off, len, svmand, &smb_ct))
		return (NT_STATUS_FILE_LOCK_CONFLICT);

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_lock_posix_unlock
 *
 * checks if the current unlock request is in another lock and repeatedly calls
 * smb_is_range_unlocked on a sliding basis to unlock all bits of the lock
 * that are not in other locks
 *
 */
static void
smb_lock_posix_unlock(smb_node_t *node, smb_lock_t *lock, cred_t *cr)
{
	uint64_t	new_mark;
	uint64_t	unlock_start;
	uint64_t	unlock_end;
	smb_lock_t	new_unlock;
	smb_llist_t	*llist;
	boolean_t	can_unlock;

	new_mark = 0;
	unlock_start = lock->l_start;
	unlock_end = unlock_start + lock->l_length;
	llist = &node->n_lock_list;

	for (;;) {
		can_unlock = smb_is_range_unlocked(unlock_start, unlock_end,
		    lock->l_file->f_uniqid, llist, &new_mark);
		if (can_unlock) {
			if (new_mark) {
				new_unlock = *lock;
				new_unlock.l_start = unlock_start;
				new_unlock.l_length = new_mark - unlock_start;
				(void) smb_fsop_frlock(node, &new_unlock,
				    B_TRUE, cr);
				unlock_start = new_mark;
			} else {
				new_unlock = *lock;
				new_unlock.l_start = unlock_start;
				new_unlock.l_length = unlock_end - unlock_start;
				(void) smb_fsop_frlock(node, &new_unlock,
				    B_TRUE, cr);
				break;
			}
		} else if (new_mark) {
			unlock_start = new_mark;
		} else {
			break;
		}
	}
}

/*
 * smb_lock_range_overlap
 *
 * Checks if lock range(start, length) overlaps range in lock structure.
 *
 * Zero-length byte range locks actually affect no single byte of the stream,
 * meaning they can still be accessed even with such locks in place. However,
 * they do conflict with other ranges in the following manner:
 *  conflict will only exist if the positive-length range contains the
 *  zero-length range's offset but doesn't start at it
 *
 * return values:
 *	0 - Lock range doesn't overlap
 *	1 - Lock range overlaps.
 */

#define	RANGE_NO_OVERLAP	0
#define	RANGE_OVERLAP		1

static int
smb_lock_range_overlap(struct smb_lock *lock, uint64_t start, uint64_t length)
{
	if (length == 0) {
		if ((lock->l_start < start) &&
		    ((lock->l_start + lock->l_length) > start))
			return (RANGE_OVERLAP);

		return (RANGE_NO_OVERLAP);
	}

	/* The following test is intended to catch roll over locks. */
	if ((start == lock->l_start) && (length == lock->l_length))
		return (RANGE_OVERLAP);

	if (start < lock->l_start) {
		if (start + length > lock->l_start)
			return (RANGE_OVERLAP);
	} else if (start < lock->l_start + lock->l_length)
		return (RANGE_OVERLAP);

	return (RANGE_NO_OVERLAP);
}

/*
 * smb_lock_range_lckrules
 *
 * Lock range rules:
 *	1. Overlapping read locks are allowed if the
 *	   current locks in the region are only read locks
 *	   irrespective of pid of smb client issuing lock request.
 *
 *	2. Read lock in the overlapped region of write lock
 *	   are allowed if the pervious lock is performed by the
 *	   same pid and connection.
 *
 * return status:
 *	NT_STATUS_SUCCESS - Input lock range adapts to lock rules.
 *	NT_STATUS_LOCK_NOT_GRANTED - Input lock conflicts lock rules.
 *	NT_STATUS_CANCELLED - Error in processing lock rules
 */
static uint32_t
smb_lock_range_lckrules(
    smb_request_t	*sr,
    smb_ofile_t		*file,
    smb_node_t		*node,
    smb_lock_t		*dlock,
    smb_lock_t		**clockp)
{
	smb_lock_t	*lock;
	uint32_t	status = NT_STATUS_SUCCESS;

	/* Check if file is closed */
	if (!smb_ofile_is_open(file)) {
		return (NT_STATUS_RANGE_NOT_LOCKED);
	}

	/* Caller must hold lock for node->n_lock_list */
	for (lock = smb_llist_head(&node->n_lock_list);
	    lock != NULL;
	    lock = smb_llist_next(&node->n_lock_list, lock)) {

		if (!smb_lock_range_overlap(lock, dlock->l_start,
		    dlock->l_length))
			continue;

		/*
		 * Check to see if lock in the overlapping record
		 * is only read lock. Current finding is read
		 * locks can overlapped irrespective of pids.
		 */
		if ((lock->l_type == SMB_LOCK_TYPE_READONLY) &&
		    (dlock->l_type == SMB_LOCK_TYPE_READONLY)) {
			continue;
		}

		/*
		 * When the read lock overlaps write lock, check if
		 * allowed.
		 */
		if ((dlock->l_type == SMB_LOCK_TYPE_READONLY) &&
		    !(lock->l_type == SMB_LOCK_TYPE_READONLY)) {
			if (lock->l_file == sr->fid_ofile &&
			    lock->l_session_kid == sr->session->s_kid &&
			    lock->l_pid == sr->smb_pid &&
			    lock->l_uid == sr->smb_uid) {
				continue;
			}
		}

		/* Conflict in overlapping lock element */
		*clockp = lock;
		status = NT_STATUS_LOCK_NOT_GRANTED;
		break;
	}

	return (status);
}

/*
 * smb_lock_wait
 *
 * Wait operation for smb overlapping lock to be released.  Caller must hold
 * write lock for node->n_lock_list so that the set of active locks can't
 * change unexpectedly.  The lock for node->n_lock_list  will be released
 * within this function during the sleep after the lock dependency has
 * been recorded.
 *
 * return value
 *
 *	0	The request was canceled.
 *	-1	The timeout was reached.
 *	>0	Condition met.
 */
static clock_t
smb_lock_wait(smb_request_t *sr, smb_lock_t *b_lock, smb_lock_t *c_lock)
{
	clock_t		rc = 0;

	ASSERT(sr->sr_awaiting == NULL);

	mutex_enter(&sr->sr_mutex);

	switch (sr->sr_state) {
	case SMB_REQ_STATE_ACTIVE:
		/*
		 * Wait up till the timeout time keeping track of actual
		 * time waited for possible retry failure.
		 */
		sr->sr_state = SMB_REQ_STATE_WAITING_LOCK;
		sr->sr_awaiting = c_lock;
		mutex_exit(&sr->sr_mutex);

		mutex_enter(&c_lock->l_mutex);
		/*
		 * The conflict list (l_conflict_list) for a lock contains
		 * all the locks that are blocked by and in conflict with
		 * that lock.  Add the new lock to the conflict list for the
		 * active lock.
		 *
		 * l_conflict_list is currently a fancy way of representing
		 * the references/dependencies on a lock.  It could be
		 * replaced with a reference count but this approach
		 * has the advantage that MDB can display the lock
		 * dependencies at any point in time.  In the future
		 * we should be able to leverage the list to implement
		 * an asynchronous locking model.
		 *
		 * l_blocked_by is the reverse of the conflict list.  It
		 * points to the lock that the new lock conflicts with.
		 * As currently implemented this value is purely for
		 * debug purposes -- there are windows of time when
		 * l_blocked_by may be non-NULL even though there is no
		 * conflict list
		 */
		b_lock->l_blocked_by = c_lock;
		smb_slist_insert_tail(&c_lock->l_conflict_list, b_lock);
		smb_llist_exit(&c_lock->l_file->f_node->n_lock_list);

		if (SMB_LOCK_INDEFINITE_WAIT(b_lock)) {
			cv_wait(&c_lock->l_cv, &c_lock->l_mutex);
		} else {
			rc = cv_timedwait(&c_lock->l_cv,
			    &c_lock->l_mutex, b_lock->l_end_time);
		}

		mutex_exit(&c_lock->l_mutex);

		smb_llist_enter(&c_lock->l_file->f_node->n_lock_list,
		    RW_WRITER);
		smb_slist_remove(&c_lock->l_conflict_list, b_lock);

		mutex_enter(&sr->sr_mutex);
		sr->sr_awaiting = NULL;
		if (sr->sr_state == SMB_REQ_STATE_CANCELED) {
			rc = 0;
		} else {
			sr->sr_state = SMB_REQ_STATE_ACTIVE;
		}
		break;

	default:
		ASSERT(sr->sr_state == SMB_REQ_STATE_CANCELED);
		rc = 0;
		break;
	}
	mutex_exit(&sr->sr_mutex);

	return (rc);
}

/*
 * smb_lock_range_ulckrules
 *
 *	1. Unlock should be performed at exactly matching ends.
 *	   This has been changed because overlapping ends is
 *	   allowed and there is no other precise way of locating
 *	   lock entity in node lock list.
 *
 *	2. Unlock is failed if there is no corresponding lock exists.
 *
 * Return values
 *
 *	NT_STATUS_SUCCESS		Unlock request matches lock record
 *					pointed by 'nodelock' lock structure.
 *
 *	NT_STATUS_RANGE_NOT_LOCKED	Unlock request doen't match any
 *					of lock record in node lock request or
 *					error in unlock range processing.
 */
static uint32_t
smb_lock_range_ulckrules(
    smb_request_t	*sr,
    smb_node_t		*node,
    uint64_t		start,
    uint64_t		length,
    smb_lock_t		**nodelock)
{
	smb_lock_t	*lock;
	uint32_t	status = NT_STATUS_RANGE_NOT_LOCKED;

	/* Caller must hold lock for node->n_lock_list */
	for (lock = smb_llist_head(&node->n_lock_list);
	    lock != NULL;
	    lock = smb_llist_next(&node->n_lock_list, lock)) {

		if ((start == lock->l_start) &&
		    (length == lock->l_length) &&
		    lock->l_file == sr->fid_ofile &&
		    lock->l_session_kid == sr->session->s_kid &&
		    lock->l_pid == sr->smb_pid &&
		    lock->l_uid == sr->smb_uid) {
			*nodelock = lock;
			status = NT_STATUS_SUCCESS;
			break;
		}
	}

	return (status);
}

static smb_lock_t *
smb_lock_create(
    smb_request_t *sr,
    uint64_t start,
    uint64_t length,
    uint32_t locktype,
    uint32_t timeout)
{
	smb_lock_t *lock;

	ASSERT(locktype == SMB_LOCK_TYPE_READWRITE ||
	    locktype == SMB_LOCK_TYPE_READONLY);

	lock = kmem_zalloc(sizeof (smb_lock_t), KM_SLEEP);
	lock->l_magic = SMB_LOCK_MAGIC;
	lock->l_sr = sr; /* Invalid after lock is active */
	lock->l_session_kid = sr->session->s_kid;
	lock->l_session = sr->session;
	lock->l_file = sr->fid_ofile;
	lock->l_uid = sr->smb_uid;
	lock->l_pid = sr->smb_pid;
	lock->l_type = locktype;
	lock->l_start = start;
	lock->l_length = length;
	/*
	 * Calculate the absolute end time so that we can use it
	 * in cv_timedwait.
	 */
	lock->l_end_time = ddi_get_lbolt() + MSEC_TO_TICK(timeout);
	if (timeout == UINT_MAX)
		lock->l_flags |= SMB_LOCK_FLAG_INDEFINITE;

	mutex_init(&lock->l_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&lock->l_cv, NULL, CV_DEFAULT, NULL);
	smb_slist_constructor(&lock->l_conflict_list, sizeof (smb_lock_t),
	    offsetof(smb_lock_t, l_conflict_lnd));

	return (lock);
}

static void
smb_lock_free(smb_lock_t *lock)
{
	smb_slist_destructor(&lock->l_conflict_list);
	cv_destroy(&lock->l_cv);
	mutex_destroy(&lock->l_mutex);

	kmem_free(lock, sizeof (smb_lock_t));
}

/*
 * smb_lock_destroy
 *
 * Caller must hold node->n_lock_list
 */
static void
smb_lock_destroy(smb_lock_t *lock)
{
	/*
	 * Caller must hold node->n_lock_list lock.
	 */
	mutex_enter(&lock->l_mutex);
	cv_broadcast(&lock->l_cv);
	mutex_exit(&lock->l_mutex);

	/*
	 * The cv_broadcast above should wake up any locks that previous
	 * had conflicts with this lock.  Wait for the locking threads
	 * to remove their references to this lock.
	 */
	smb_slist_wait_for_empty(&lock->l_conflict_list);

	smb_lock_free(lock);
}

/*
 * smb_is_range_unlocked
 *
 * Checks if the current unlock byte range request overlaps another lock
 * This function is used to determine where POSIX unlocks should be
 * applied.
 *
 * The return code and the value of new_mark must be interpreted as
 * follows:
 *
 * B_TRUE and (new_mark == 0):
 *   This is the last or only lock left to be unlocked
 *
 * B_TRUE and (new_mark > 0):
 *   The range from start to new_mark can be unlocked
 *
 * B_FALSE and (new_mark == 0):
 *   The unlock can't be performed and we are done
 *
 * B_FALSE and (new_mark > 0),
 *   The range from start to new_mark can't be unlocked
 *   Start should be reset to new_mark for the next pass
 */

static boolean_t
smb_is_range_unlocked(uint64_t start, uint64_t end, uint32_t uniqid,
    smb_llist_t *llist_head, uint64_t *new_mark)
{
	struct smb_lock *lk = NULL;
	uint64_t low_water_mark = MAXOFFSET_T;
	uint64_t lk_start;
	uint64_t lk_end;

	*new_mark = 0;
	lk = smb_llist_head(llist_head);
	while (lk) {
		if (lk->l_length == 0) {
			lk = smb_llist_next(llist_head, lk);
			continue;
		}

		if (lk->l_file->f_uniqid != uniqid) {
			lk = smb_llist_next(llist_head, lk);
			continue;
		}

		lk_end = lk->l_start + lk->l_length - 1;
		lk_start = lk->l_start;

		/*
		 * there is no overlap for the first 2 cases
		 * check next node
		 */
		if (lk_end < start) {
			lk = smb_llist_next(llist_head, lk);
			continue;
		}
		if (lk_start > end) {
			lk = smb_llist_next(llist_head, lk);
			continue;
		}

		/* this range is completely locked */
		if ((lk_start <= start) && (lk_end >= end)) {
			return (B_FALSE);
		}

		/* the first part of this range is locked */
		if ((start >= lk_start) && (start <= lk_end)) {
			if (end > lk_end)
				*new_mark = lk_end + 1;
			return (B_FALSE);
		}

		/* this piece is unlocked */
		if ((lk_start >= start) && (lk_start <= end)) {
			if (low_water_mark > lk_start)
				low_water_mark  = lk_start;
		}

		lk = smb_llist_next(llist_head, lk);
	}

	if (low_water_mark != MAXOFFSET_T) {
		*new_mark = low_water_mark;
		return (B_TRUE);
	}
	/* the range is completely unlocked */
	return (B_TRUE);
}
