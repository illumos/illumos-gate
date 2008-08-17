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

#pragma ident	"@(#)smb_oplock.c	1.5	08/08/07 SMI"

/*
 * SMB Locking library functions.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

/*
 * Oplock functionality enable/disable
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
 * smb_oplock_acquire
 *
 * Attempt to acquire an oplock. Note that the oplock granted may be
 * none, i.e. the oplock was not granted.
 *
 * Grant an oplock to the requestor if this session is the only one
 * that has the file open, regardless of the number of instances of
 * the file opened by this session.
 *
 * However, if there is no oplock on this file and there is already
 * at least one open, we will not grant an oplock, even if the only
 * existing opens are from the same client.  This is "server discretion."
 *
 * An oplock may need to be broken in order for one to be granted, and
 * depending on what action is taken by the other client (unlock or close),
 * an oplock may or may not be granted.  (The breaking of an oplock is
 * done earlier in the calling path.)
 *
 * XXX: Node synchronization is not yet implemented.  However, racing
 * opens are handled thus:
 *
 * A racing oplock acquire can happen in the open path between
 * smb_oplock_break() and smb_fsop_open(), but no later.  (Once
 * the file is open via smb_fsop_open()/VOP_OPEN,
 * smb_fsop_oplock_install() will not be able to install an oplock,
 * which requires an open count of 1.)
 *
 * Hence, we can safely break any oplock that came in after the
 * smb_oplock_break() done previously in the open path, knowing that
 * no other racing oplock acquisitions should be able to succeed
 * because we already have the file open (see above).
 *
 * The type of oplock being requested is passed in op->my_flags.  The result
 * is also returned in op->my_flags.
 *
 * (Note that exclusive and batch oplocks are treated interchangeably.)
 *
 * The Returns NT status codes:
 *	NT_STATUS_SUCCESS
 *	NT_STATUS_CONNECTION_DISCONNECTED
 */
DWORD
smb_oplock_acquire(
    smb_request_t	*sr,
    smb_ofile_t		*of,
    struct open_param	*op)
{
	smb_node_t		*node;
	unsigned int		level;

	ASSERT(sr);
	ASSERT(of);
	ASSERT(op);
	ASSERT(op->fqi.last_attr.sa_vattr.va_type == VREG);

	level = op->my_flags & MYF_OPLOCK_MASK;

	op->my_flags &= ~MYF_OPLOCK_MASK;

	if ((sr->sr_cfg->skc_oplock_enable == 0) ||
	    smb_tree_has_feature(of->f_tree, SMB_TREE_NO_OPLOCKS))
		return (NT_STATUS_SUCCESS);

	if (!((MYF_IS_EXCLUSIVE_OPLOCK(level)) ||
	    (MYF_IS_BATCH_OPLOCK(level))))
		return (NT_STATUS_SUCCESS);

	node = of->f_node;

	smb_rwx_rwenter(&node->n_lock, RW_WRITER);

	if (EXCLUSIVE_OPLOCK_IN_FORCE(node) ||
	    BATCH_OPLOCK_IN_FORCE(node)) {

		smb_rwx_rwexit(&node->n_lock);

		if (SMB_SAME_SESSION(sr->session,
		    node->n_oplock.op_ofile->f_session)) {
			op->my_flags |= level;
			return (NT_STATUS_SUCCESS);
		} else if (SMB_ATTR_ONLY_OPEN(op)) {
			ASSERT(!(op->my_flags & MYF_OPLOCK_MASK));
			return (NT_STATUS_SUCCESS);
		}

		smb_oplock_break(node);

		smb_rwx_rwenter(&node->n_lock, RW_WRITER);
	}

	if (smb_fsop_oplock_install(node, of->f_mode) != 0) {
		smb_rwx_rwexit(&node->n_lock);
		return (NT_STATUS_SUCCESS);
	}

	node->n_oplock.op_ofile = of;
	node->n_oplock.op_ipaddr = sr->session->ipaddr;
	node->n_oplock.op_kid = sr->session->s_kid;
	node->flags &= ~NODE_OPLOCKS_IN_FORCE;

	if (MYF_IS_EXCLUSIVE_OPLOCK(level))
		node->flags |= NODE_EXCLUSIVE_OPLOCK;

	if (MYF_IS_BATCH_OPLOCK(level))
		node->flags |= NODE_BATCH_OPLOCK;

	op->my_flags |= level;

	smb_rwx_rwexit(&node->n_lock);

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_oplock_break
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
 *						oplock has been broken.
 *	NT_STATUS_CONNECTION_DISCONNECTED  Requesting client disconnected.
 *	NT_STATUS_INTERNAL_ERROR
 */

void
smb_oplock_break(smb_node_t *node)
{
	smb_session_t		*oplock_session;
	smb_ofile_t		*oplock_ofile;
	struct mbuf_chain	mbc;
	int			retries = 0;
	clock_t			elapsed_time;
	clock_t			max_time;
	boolean_t		flag;

	smb_rwx_rwenter(&node->n_lock, RW_WRITER);

	if (!OPLOCKS_IN_FORCE(node)) {
		smb_rwx_rwexit(&node->n_lock);
		return;
	}

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
		 */
		if (!OPLOCKS_IN_FORCE(node)) {
			smb_rwx_rwexit(&node->n_lock);
			return;
		} else {
			/*
			 * This is an anomalous condition.
			 * Cancel/release the oplock.
			 */
			smb_oplock_release(node, B_TRUE);
			smb_rwx_rwexit(&node->n_lock);
			return;
		}
	}

	oplock_ofile = node->n_oplock.op_ofile;
	ASSERT(oplock_ofile);

	oplock_session = oplock_ofile->f_session;
	ASSERT(oplock_session);

	/*
	 * Start oplock break.
	 */

	node->n_oplock.op_flags |= OPLOCK_FLAG_BREAKING;

	smb_rwx_rwexit(&node->n_lock);

	max_time = MSEC_TO_TICK(smb_oplock_timeout);
	do {
		MBC_INIT(&mbc, MLEN);
		(void) smb_mbc_encodef(&mbc, "Mb19.wwwwbb3.ww10.",
		    SMB_COM_LOCKING_ANDX, oplock_ofile->f_tree->t_tid,
		    0xffff, 0, 0xffff, 8, 0xff, oplock_ofile->f_fid,
		    LOCKING_ANDX_OPLOCK_RELEASE);

		flag = B_TRUE;
		smb_rwx_rwenter(&oplock_session->s_lock, RW_WRITER);
		while (flag) {
			switch (oplock_session->s_state) {
			case SMB_SESSION_STATE_DISCONNECTED:
			case SMB_SESSION_STATE_TERMINATED:
				smb_rwx_rwexit(&oplock_session->s_lock);
				smb_rwx_rwenter(&node->n_lock, RW_WRITER);

				node->flags &= ~NODE_OPLOCKS_IN_FORCE;
				node->n_oplock.op_flags &=
				    ~OPLOCK_FLAG_BREAKING;
				node->n_oplock.op_ofile = NULL;
				node->n_oplock.op_ipaddr = 0;
				node->n_oplock.op_kid = 0;

				smb_rwx_rwexit(&node->n_lock);

				return;

			case SMB_SESSION_STATE_OPLOCK_BREAKING:
				flag = B_FALSE;
				break;

			case SMB_SESSION_STATE_NEGOTIATED:
				oplock_session->s_state =
				    SMB_SESSION_STATE_OPLOCK_BREAKING;
				flag = B_FALSE;
				break;

			default:
				(void) smb_rwx_rwwait(&oplock_session->s_lock,
				    -1);
				break;
			}
		}
		smb_rwx_rwexit(&oplock_session->s_lock);

		(void) smb_session_send(oplock_session, 0, &mbc);

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

		if (!OPLOCKS_IN_FORCE(node)) {
			/*
			 * smb_oplock_release() was called
			 */
			smb_rwx_rwexit(&node->n_lock);
			return;
		}
	} while (++retries < OPLOCK_RETRIES);

	/*
	 * Retries exhausted and timed out.
	 * Cancel the oplock and continue.
	 */

	smb_oplock_release(node, B_TRUE);

	smb_rwx_rwexit(&node->n_lock);
}

/*
 * smb_oplock_release
 *
 * This function uninstalls the FEM oplock monitors and
 * clears all flags in relation to an oplock on the
 * given node.
 *
 * The function can be called with the node->n_lock held
 * or not held.
 */

void /*ARGSUSED*/
smb_oplock_release(smb_node_t *node, boolean_t have_rwx)
{
	if (!have_rwx)
		smb_rwx_rwenter(&node->n_lock, RW_WRITER);

	if (!OPLOCKS_IN_FORCE(node)) {
		if (!have_rwx)
			smb_rwx_rwexit(&node->n_lock);
		return;
	}

	smb_fsop_oplock_uninstall(node);

	node->flags &= ~NODE_OPLOCKS_IN_FORCE;
	node->n_oplock.op_flags &= ~OPLOCK_FLAG_BREAKING;
	node->n_oplock.op_ofile = NULL;
	node->n_oplock.op_ipaddr = 0;
	node->n_oplock.op_kid = 0;

	if (!have_rwx)
		smb_rwx_rwexit(&node->n_lock);
}

/*
 * smb_oplock_conflict
 *
 * The two checks on "session" and "op" are primarily for the open path.
 * Other CIFS functions may call smb_oplock_conflict() with a session
 * pointer so as to do the session check.
 */

boolean_t
smb_oplock_conflict(smb_node_t *node, smb_session_t *session,
    struct open_param *op)
{
	smb_session_t		*oplock_session;
	smb_ofile_t		*oplock_ofile;

	smb_rwx_rwenter(&node->n_lock, RW_READER);

	if (!OPLOCKS_IN_FORCE(node)) {
		smb_rwx_rwexit(&node->n_lock);
		return (B_FALSE);
	}

	oplock_ofile = node->n_oplock.op_ofile;
	ASSERT(oplock_ofile);

	oplock_session = oplock_ofile->f_session;
	ASSERT(oplock_session);

	if (SMB_SAME_SESSION(session, oplock_session)) {
		smb_rwx_rwexit(&node->n_lock);
		return (B_FALSE);
	}

	if (SMB_ATTR_ONLY_OPEN(op)) {
		smb_rwx_rwexit(&node->n_lock);
		return (B_FALSE);
	}

	smb_rwx_rwexit(&node->n_lock);
	return (B_TRUE);
}
