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
 */
/*
 * SMB Locking library functions.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <inet/tcp.h>

static void smb_oplock_enter(smb_node_t *);

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
 * none, i.e. the oplock was not granted. The result of the acquisition is
 * provided in ol->ol_level.
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
 */
void
smb_oplock_acquire(smb_node_t *node, smb_ofile_t *of, open_param_t *op)
{
	smb_session_t	*session;
	smb_oplock_t	*ol;
	clock_t		time;

	SMB_NODE_VALID(node);
	SMB_OFILE_VALID(of);

	ASSERT(node == SMB_OFILE_GET_NODE(of));

	session = SMB_OFILE_GET_SESSION(of);

	if (!smb_session_oplocks_enable(session) ||
	    smb_tree_has_feature(SMB_OFILE_GET_TREE(of), SMB_TREE_NO_OPLOCKS)) {
		/* This implies that trees cannot overlap. */
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	ol = &node->n_oplock;
	time = MSEC_TO_TICK(smb_oplock_timeout) + ddi_get_lbolt();

	mutex_enter(&node->n_mutex);

	for (;;) {
		int	rc;

		smb_oplock_enter(node);

		if (node->n_state == SMB_NODE_STATE_AVAILABLE) {
			if ((op->op_oplock_level == SMB_OPLOCK_LEVEL_II) ||
			    (op->op_oplock_level == SMB_OPLOCK_NONE) ||
			    (node->n_open_count > 1)) {
				mutex_exit(&node->n_mutex);
				op->op_oplock_level = SMB_OPLOCK_NONE;
				return;
			}
			ol->ol_ofile = of;
			ol->ol_sess_id = SMB_SESSION_GET_ID(session);
			ol->ol_level = op->op_oplock_level;
			ol->ol_xthread = curthread;
			node->n_state = SMB_NODE_STATE_OPLOCK_GRANTED;
			mutex_exit(&node->n_mutex);
			if (smb_fsop_oplock_install(node, of->f_mode) == 0) {
				smb_ofile_set_oplock_granted(of);
				return;
			}
			mutex_enter(&node->n_mutex);
			ASSERT(node->n_state == SMB_NODE_STATE_OPLOCK_GRANTED);
			node->n_state = SMB_NODE_STATE_AVAILABLE;
			ol->ol_xthread = NULL;
			op->op_oplock_level = SMB_OPLOCK_NONE;
			if (ol->ol_waiters_count != 0)
				cv_broadcast(&ol->ol_cv);
			break;
		}

		if (node->n_state == SMB_NODE_STATE_OPLOCK_GRANTED) {
			if (SMB_SESSION_GET_ID(session) == ol->ol_sess_id)
				break;
			node->n_state = SMB_NODE_STATE_OPLOCK_BREAKING;
			smb_session_oplock_break(
			    SMB_OFILE_GET_SESSION(ol->ol_ofile), ol->ol_ofile);
		}

		ASSERT(node->n_state == SMB_NODE_STATE_OPLOCK_BREAKING);

		ol->ol_waiters_count++;
		rc = cv_timedwait(&ol->ol_cv, &node->n_mutex, time);
		ol->ol_waiters_count--;

		if (rc == -1) {
			/*
			 * Oplock release timed out.
			 */
			if (node->n_state == SMB_NODE_STATE_OPLOCK_BREAKING) {
				node->n_state = SMB_NODE_STATE_AVAILABLE;
				ol->ol_xthread = curthread;
				mutex_exit(&node->n_mutex);
				smb_fsop_oplock_uninstall(node);
				smb_session_oplock_break_timedout(
				    SMB_OFILE_GET_SESSION(ol->ol_ofile));
				mutex_enter(&node->n_mutex);
				ol->ol_xthread = NULL;
				if (ol->ol_waiters_count != 0)
					cv_broadcast(&ol->ol_cv);
			}
		}
	}
	mutex_exit(&node->n_mutex);
}

/*
 * smb_oplock_break
 *
 * The oplock break may succeed for multiple reasons: file close, oplock
 * release, holder connection dropped, requesting client disconnect etc.
 *
 * Returns:
 *
 *	B_TRUE	The oplock is broken.
 *	B_FALSE	The oplock is being broken. This is returned if nowait is set
 *		to B_TRUE;
 */
boolean_t
smb_oplock_break(smb_node_t *node, uint64_t sess_id, boolean_t nowait)
{
	smb_oplock_t	*ol;
	clock_t		time;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;
	time = MSEC_TO_TICK(smb_oplock_timeout) + ddi_get_lbolt();

	mutex_enter(&node->n_mutex);
	if (ol->ol_sess_id == sess_id) {
		mutex_exit(&node->n_mutex);
		return (B_TRUE);
	}

	for (;;) {
		int	rc;

		smb_oplock_enter(node);

		if (node->n_state == SMB_NODE_STATE_AVAILABLE) {
			mutex_exit(&node->n_mutex);
			return (B_TRUE);
		}

		if (node->n_state == SMB_NODE_STATE_OPLOCK_GRANTED) {
			node->n_state = SMB_NODE_STATE_OPLOCK_BREAKING;
			smb_session_oplock_break(
			    SMB_OFILE_GET_SESSION(ol->ol_ofile), ol->ol_ofile);
		}

		ASSERT(node->n_state == SMB_NODE_STATE_OPLOCK_BREAKING);
		if (nowait) {
			mutex_exit(&node->n_mutex);
			return (B_FALSE);
		}
		ol->ol_waiters_count++;
		rc = cv_timedwait(&ol->ol_cv, &node->n_mutex, time);
		ol->ol_waiters_count--;
		if (rc == -1) {
			/*
			 * Oplock release timed out.
			 */
			if (node->n_state == SMB_NODE_STATE_OPLOCK_BREAKING) {
				node->n_state = SMB_NODE_STATE_AVAILABLE;
				ol->ol_xthread = curthread;
				mutex_exit(&node->n_mutex);
				smb_fsop_oplock_uninstall(node);
				smb_session_oplock_break_timedout(
				    SMB_OFILE_GET_SESSION(ol->ol_ofile));
				mutex_enter(&node->n_mutex);
				ol->ol_xthread = NULL;
				if (ol->ol_waiters_count != 0)
					cv_broadcast(&ol->ol_cv);
				break;
			}
		}
	}
	mutex_exit(&node->n_mutex);
	return (B_TRUE);
}

/*
 * smb_oplock_release
 *
 * This function releases the oplock on the node passed in. If other threads
 * were waiting for the oplock to be released they are signaled.
 */
void
smb_oplock_release(smb_node_t *node, smb_ofile_t *of)
{
	smb_oplock_t	*ol;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;

	mutex_enter(&node->n_mutex);
	smb_oplock_enter(node);
	switch (node->n_state) {
	case SMB_NODE_STATE_AVAILABLE:
		break;

	case SMB_NODE_STATE_OPLOCK_GRANTED:
	case SMB_NODE_STATE_OPLOCK_BREAKING:
		if (ol->ol_ofile == of) {
			node->n_state = SMB_NODE_STATE_AVAILABLE;
			ol->ol_xthread = curthread;
			mutex_exit(&node->n_mutex);
			smb_fsop_oplock_uninstall(node);
			smb_session_oplock_released(
			    SMB_OFILE_GET_SESSION(ol->ol_ofile));
			mutex_enter(&node->n_mutex);
			ol->ol_xthread = NULL;
			if (ol->ol_waiters_count != 0)
				cv_broadcast(&ol->ol_cv);
		}
		break;

	default:
		SMB_PANIC();
	}
	mutex_exit(&node->n_mutex);
}

/*
 * smb_oplock_conflict
 *
 * The two checks on "session" and "op" are primarily for the open path.
 * Other CIFS functions may call smb_oplock_conflict() with a session
 * pointer so as to do the session check.
 */
boolean_t
smb_oplock_conflict(smb_node_t *node, smb_session_t *session, open_param_t *op)
{
	boolean_t	rb;

	SMB_NODE_VALID(node);
	SMB_SESSION_VALID(session);

	mutex_enter(&node->n_mutex);
	smb_oplock_enter(node);
	switch (node->n_state) {
	case SMB_NODE_STATE_AVAILABLE:
		rb = B_FALSE;
		break;

	case SMB_NODE_STATE_OPLOCK_GRANTED:
	case SMB_NODE_STATE_OPLOCK_BREAKING:
		if (SMB_SESSION_GET_ID(session) == node->n_oplock.ol_sess_id) {
			rb = B_FALSE;
			break;
		}

		if (op != NULL) {
			if (((op->desired_access & ~(FILE_READ_ATTRIBUTES |
			    FILE_WRITE_ATTRIBUTES | SYNCHRONIZE)) == 0) &&
			    (op->create_disposition != FILE_SUPERSEDE) &&
			    (op->create_disposition != FILE_OVERWRITE)) {
				/* Attributs only */
				rb = B_FALSE;
				break;
			}
		}
		rb = B_TRUE;
		break;

	default:
		SMB_PANIC();
	}
	mutex_exit(&node->n_mutex);
	return (rb);
}

/*
 * smb_oplock_exit
 *
 * The the calling thread has the pointer to its context stored in ol_thread
 * it resets that field. If any other thread is waiting for that field to
 * turn to NULL it is signaled.
 *
 * Returns:
 *	B_TRUE	Oplock unlocked
 *	B_FALSE	Oplock still locked
 */
boolean_t
smb_oplock_exit(smb_node_t *node)
{
	smb_oplock_t	*ol;
	boolean_t	rb;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;
	rb = B_FALSE;

	mutex_enter(&node->n_mutex);
	if ((ol->ol_xthread != NULL) && (ol->ol_xthread == curthread)) {
		ol->ol_xthread = NULL;
		if (ol->ol_waiters_count != 0)
			cv_broadcast(&ol->ol_cv);
		rb = B_TRUE;
	}
	mutex_exit(&node->n_mutex);
	return (rb);
}

/*
 * smb_oplock_wait
 *
 * The mutex of the node must have benn entered before calling this function.
 * If the field ol_xthread is not NULL and doesn't contain the pointer to the
 * context of the calling thread, the caller will sleep until that field is
 * reset (set to NULL).
 */
static void
smb_oplock_enter(smb_node_t *node)
{
	smb_oplock_t	*ol = &node->n_oplock;

	if ((ol->ol_xthread != NULL) && (ol->ol_xthread != curthread)) {
		ol->ol_waiters_count++;
		while (ol->ol_xthread != NULL)
			cv_wait(&ol->ol_cv, &node->n_mutex);
		ol->ol_waiters_count--;
	}
}
