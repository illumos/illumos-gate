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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB Locking library functions.
 */

#include <smbsrv/smb_incl.h>

/*
 * Oplock functionality enable/disable (see smb_oplock_init).
 */

/*
 *	Magic		0xFF 'S' 'M' 'B'
 *	smb_com 	a byte, the "first" command
 *	Error		a 4-byte union, ignored in a request
 *	smb_flg		a one byte set of eight flags
 *	smb_flg2	a two byte set of 16 flags
 *	.		twelve reserved bytes, have a role
 *			in connectionless transports (IPX, UDP?)
 *	smb_tid		a 16-bit tree ID, a mount point sorta,
 *			0xFFFF is this command does not have
 *			or require a tree context
 *	smb_pid		a 16-bit process ID
 *	smb_uid		a 16-bit user ID, specific to this "session"
 *			and mapped to a system (bona-fide) UID
 *	smb_mid		a 16-bit multiplex ID, used to differentiate
 *			multiple simultaneous requests from the same
 *			process (pid) (ref RPC "xid")
 *
 * SMB_COM_LOCKING_ANDX allows both locking and/or unlocking of file range(s).
 *
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 8
 *  UCHAR AndXCommand;                 Secondary (X) command;  0xFF = none
 *  UCHAR AndXReserved;                Reserved (must be 0)
 *  USHORT AndXOffset;                 Offset to next command WordCount
 *  USHORT Fid;                        File handle
 *  UCHAR LockType;                    See LockType table below
 *  UCHAR OplockLevel;                 The new oplock level
 *  ULONG Timeout;                     Milliseconds to wait for unlock
 *  USHORT NumberOfUnlocks;            Num. unlock range structs following
 *  USHORT NumberOfLocks;              Num. lock range structs following
 *  USHORT ByteCount;                  Count of data bytes
 *  LOCKING_ANDX_RANGE Unlocks[];      Unlock ranges
 *  LOCKING_ANDX_RANGE Locks[];        Lock ranges
 *
 *  LockType Flag Name            Value Description
 *  ============================  ===== ================================
 *
 *  LOCKING_ANDX_SHARED_LOCK      0x01  Read-only lock
 *  LOCKING_ANDX_OPLOCK_RELEASE   0x02  Oplock break notification
 *  LOCKING_ANDX_CHANGE_LOCKTYPE  0x04  Change lock type
 *  LOCKING_ANDX_CANCEL_LOCK      0x08  Cancel outstanding request
 *  LOCKING_ANDX_LARGE_FILES      0x10  Large file locking format
 *
 *  LOCKING_ANDX_RANGE Format
 *  =====================================================================
 *
 *  USHORT Pid;                        PID of process "owning" lock
 *  ULONG Offset;                      Offset to bytes to [un]lock
 *  ULONG Length;                      Number of bytes to [un]lock
 *
 *  Large File LOCKING_ANDX_RANGE Format
 *  =====================================================================
 *
 *  USHORT Pid;                        PID of process "owning" lock
 *  USHORT Pad;                        Pad to DWORD align (mbz)
 *  ULONG OffsetHigh;                  Offset to bytes to [un]lock
 *                                      (high)
 *  ULONG OffsetLow;                   Offset to bytes to [un]lock (low)
 *  ULONG LengthHigh;                  Number of bytes to [un]lock
 *                                      (high)
 *  ULONG LengthLow;                   Number of bytes to [un]lock (low)
 *
 *  Server Response                    Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 2
 *  UCHAR AndXCommand;                 Secondary (X) command;  0xFF =
 *                                      none
 *  UCHAR AndXReserved;                Reserved (must be 0)
 *  USHORT AndXOffset;                 Offset to next command WordCount
 *  USHORT ByteCount;                  Count of data bytes = 0
 *
 */

/*
 * smb_acquire_oplock
 *
 * Attempt to acquire an oplock. Note that the oplock granted may be
 * none, i.e. the oplock was not granted.
 *
 * We may have to break an oplock in order to acquire one, and depending
 * on what action is taken by the other client (unlock or close), we may
 * or may not end up with an oplock. The type of oplock being requested
 * is passed in level_requested, the result is returned in level_granted
 * and is only valid if the status is NT_STATUS_SUCCESS.
 *
 * The Returns NT status codes:
 *	NT_STATUS_SUCCESS
 *	NT_STATUS_CONNECTION_DISCONNECTED
 */
DWORD
smb_acquire_oplock(
    struct smb_request	*sr,
    struct smb_ofile	*file,
    unsigned int	level_requested,
    unsigned int	*level_granted)
{
	struct smb_node	*node = file->f_node;
	unsigned int	level;
	int		oplock_owner;
	DWORD		status;
	smb_user_t	*user;

	user = sr->uid_user;
	ASSERT(user);

	level = level_requested & MYF_OPLOCK_MASK;
	*level_granted = MYF_OPLOCK_NONE;

	if (sr->sr_cfg->skc_oplock_enable == 0)
		return (NT_STATUS_SUCCESS);

	if (fsd_chkcap(&sr->tid_tree->t_fsd, FSOLF_DISABLE_OPLOCKS) > 0)
		return (NT_STATUS_SUCCESS);

restart:
	oplock_owner = 0;

	/*
	 * I'm not convinced the client redirector will send multiple
	 * opens requesting a batch oplock for the same file. I think
	 * the client redirector will handle the multiple instances
	 * and only send a single open to the server. The the original
	 * implementation supported it, however, so I'll leave it here
	 * for now.
	 *
	 * Grant an oplock to the requester if this session is the
	 * only one that has the file open, regardless of the number
	 * of instances of the file opened by this session. We grant
	 * any oplock requested to the owner.
	 */
	if (node->n_refcnt == 1 || oplock_owner == 1) {
		if (MYF_IS_EXCLUSIVE_OPLOCK(level)) {
			node->flags &= ~NODE_OPLOCKS_IN_FORCE;
			node->flags |= NODE_EXCLUSIVE_OPLOCK;
			node->n_oplock.op_ofile = file;
		} else if (MYF_IS_BATCH_OPLOCK(level)) {
			node->flags &= ~NODE_OPLOCKS_IN_FORCE;
			node->flags |= NODE_BATCH_OPLOCK;
			node->n_oplock.op_ofile = file;
		} else {
			level &= ~MYF_OPLOCK_MASK;
		}

		*level_granted = level;
		return (NT_STATUS_SUCCESS);
	}

	/*
	 * Other clients have this file open but they do not have any
	 * oplocks in force, so we must reject this oplock request.
	 */
	if (node->n_refcnt > 1 && OPLOCKS_IN_FORCE(node) == 0) {
		return (NT_STATUS_SUCCESS);
	}

	/*
	 * Someone has an oplock, we need to break it.
	 */
	if ((status = smb_break_oplock(sr, node)) == NT_STATUS_SUCCESS)
		goto restart;

	return (status);
}


/*
 * smb_break_oplock
 *
 * The oplock break may succeed for multiple reasons: file close, oplock
 * release, holder connection dropped, requesting client disconnect etc.
 * Whatever the reason, the oplock should be broken when this function
 * returns. The exceptions are when the client making this request gets
 * disconnected or when another client is handling the break and it gets
 * disconnected.
 *
 * Returns NT status codes:
 *	NT_STATUS_SUCCESS                  No oplock in force, i.e. the
 *                                     oplock has been broken.
 *	NT_STATUS_CONNECTION_DISCONNECTED  Requesting client disconnected.
 *	NT_STATUS_INTERNAL_ERROR
 */
DWORD
smb_break_oplock(struct smb_request *sr, struct smb_node *node)
{
	struct smb_session	*sent_session;
	struct smb_ofile	*sent_ofile;
	struct mbuf_chain	mbc;
	int			retries = 0;
	int			tid;
	unsigned short		fid;
	clock_t			elapsed_time;
	clock_t			max_time;
	boolean_t		flag;
	smb_user_t		*user;

	user = sr->uid_user;
	ASSERT(user);

	smb_rwx_rwenter(&node->n_lock, RW_WRITER);

	if (node->n_oplock.op_flags & OPLOCK_FLAG_BREAKING) {

		elapsed_time = 0;
		max_time = MSEC_TO_TICK(smb_oplock_timeout * OPLOCK_RETRIES);
		/*
		 * Another client is already attempting to break the oplock.
		 * We wait for it to finish. If the caller was trying to
		 * acquire an oplock, he should retry in case the client's
		 * connection was dropped while trying to break the oplock.
		 *
		 * If the holder's connection has been dropped, we yield to
		 * allow the thread handling the break to detect it and set
		 * the flags.
		 */
		while ((node->n_oplock.op_flags & OPLOCK_FLAG_BREAKING) &&
		    (elapsed_time < max_time)) {
			clock_t	timeleft;

			timeleft = smb_rwx_rwwait(&node->n_lock, max_time);
			if (timeleft == -1) {
				elapsed_time = max_time;
			} else {
				elapsed_time += max_time - timeleft;
			}
		}
		/*
		 * If there are no oplocks in force we're done.
		 * Otherwise fall through and break the oplock.
		 */
		if (OPLOCKS_IN_FORCE(node) == 0) {
			smb_rwx_rwexit(&node->n_lock);
			return (NT_STATUS_SUCCESS);
		} else {
			/*
			 * Should we clear the
			 * LOCK_BREAKING_OPLOCK flag?
			 */
			smb_rwx_rwexit(&node->n_lock);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	/*
	 * No oplock break is in progress so we start one.
	 */
	sent_ofile = node->n_oplock.op_ofile;
	sent_session = sent_ofile->f_session;
	ASSERT(sent_session);
	/*
	 * If a client has an OPLOCK on a file it would not break it because
	 * another of its processes wants to open the same file. However, if
	 * a client were to behave like that it would create a deadlock in the
	 * code that follows. For now we leave the ASSERT(). Eventually the
	 * code will have to be more defensive.
	 */
	ASSERT(sent_session != sr->session);
	node->n_oplock.op_flags |= OPLOCK_FLAG_BREAKING;
	smb_rwx_rwexit(&node->n_lock);

	/*
	 * IR #104382
	 * What we could find from this panic was that the tree field
	 * of sent_ofile structure points to an invalid memory page,
	 * but we couldn't find why exactly this happened. So, this is
	 * a work around till we can find the real problem.
	 */
	tid = sent_ofile->f_tree->t_tid;
	fid = sent_ofile->f_fid;

	max_time = MSEC_TO_TICK(smb_oplock_timeout);
	do {
		MBC_INIT(&mbc, MLEN);
		(void) smb_encode_mbc(&mbc, "Mb19.wwwwbb3.ww10.",
		    SMB_COM_LOCKING_ANDX,	/* Command */
		    tid,  			/* TID */
		    0xffff,			/* PID */
		    0,				/* UID */
		    0xffff,			/* MID oplock break */
		    8,				/* parameter words=8 */
		    0xff,			/* 0xFF=none */
		    fid,			/* File handle */
		    LOCKING_ANDX_OPLOCK_RELEASE);

		flag = B_TRUE;
		smb_rwx_rwenter(&sent_session->s_lock, RW_WRITER);
		while (flag) {
			switch (sent_session->s_state) {
			case SMB_SESSION_STATE_DISCONNECTED:
			case SMB_SESSION_STATE_TERMINATED:
				smb_rwx_rwexit(&sent_session->s_lock);
				smb_rwx_rwenter(&node->n_lock, RW_WRITER);
				node->flags &= ~NODE_OPLOCKS_IN_FORCE;
				node->n_oplock.op_flags &=
				    ~OPLOCK_FLAG_BREAKING;
				node->n_oplock.op_ofile = NULL;
				smb_rwx_rwexit(&node->n_lock);
				return (NT_STATUS_SUCCESS);

			case SMB_SESSION_STATE_OPLOCK_BREAKING:
				flag = B_FALSE;
				break;

			case SMB_SESSION_STATE_NEGOTIATED:
				sent_session->s_state =
				    SMB_SESSION_STATE_OPLOCK_BREAKING;
				flag = B_FALSE;
				break;

			default:
				(void) smb_rwx_rwwait(&sent_session->s_lock,
				    -1);
				break;
			}
		}
		smb_rwx_rwexit(&sent_session->s_lock);

		(void) smb_session_send(sent_session, 0, &mbc);

		elapsed_time = 0;
		smb_rwx_rwenter(&node->n_lock, RW_WRITER);
		while ((node->n_oplock.op_flags & OPLOCK_FLAG_BREAKING) &&
		    (elapsed_time < max_time)) {
			clock_t	timeleft;

			timeleft = smb_rwx_rwwait(&node->n_lock, max_time);
			if (timeleft == -1) {
				elapsed_time = max_time;
			} else {
				elapsed_time += max_time - timeleft;
			}
		}
		if (OPLOCKS_IN_FORCE(node) == 0) {
			smb_rwx_rwexit(&node->n_lock);
			return (NT_STATUS_SUCCESS);
		}
	} while (++retries < OPLOCK_RETRIES);

	/*
	 * Retries exhausted and timed out.
	 * Cancel the oplock and continue.
	 */
	node->flags &= ~NODE_OPLOCKS_IN_FORCE;
	node->n_oplock.op_flags &= ~OPLOCK_FLAG_BREAKING;
	node->n_oplock.op_ofile = 0;
	smb_rwx_rwexit(&node->n_lock);
	return (NT_STATUS_SUCCESS);
}


/*
 * smb_release_oplock
 *
 * The original code supported batch oplock inheritance but I'm not
 * convinced the client redirector will open multiple instances of a
 * file with batch oplocks on the server (see smb_acquire_oplock).
 */
void /*ARGSUSED*/
smb_release_oplock(struct smb_ofile *file, int reason)
{
	struct smb_node *node = file->f_node;

	smb_rwx_rwenter(&node->n_lock, RW_WRITER);
	if ((node->n_oplock.op_ofile != file) || OPLOCKS_IN_FORCE(node) == 0) {
		smb_rwx_rwexit(&node->n_lock);
		return;
	}

	node->flags &= ~NODE_OPLOCKS_IN_FORCE;
	node->n_oplock.op_ofile = 0;

	if (node->n_oplock.op_flags & OPLOCK_FLAG_BREAKING) {
		node->n_oplock.op_flags &= ~OPLOCK_FLAG_BREAKING;
	}
	smb_rwx_rwexit(&node->n_lock);
}
