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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB: locking_andx
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
 * Locking is a simple mechanism for excluding other processes read/write
 * access to regions of a file.  The locked regions can be anywhere in the
 * logical file.  Locking beyond end-of-file is permitted.  Any process
 * using the Fid specified in this request's Fid has access to the locked
 * bytes, other processes will be denied the locking of the same bytes.
 *
 * The proper method for using locks is not to rely on being denied read or
 * write access on any of the read/write protocols but rather to attempt
 * the locking protocol and proceed with the read/write only if the locks
 * succeeded.
 *
 * Locking a range of bytes will fail if any subranges or overlapping
 * ranges are locked.  In other words, if any of the specified bytes are
 * already locked, the lock will fail.
 *
 * If NumberOfUnlocks is non-zero, the Unlocks vector contains
 * NumberOfUnlocks elements.  Each element requests that a lock at Offset
 * of Length be released.  If NumberOfLocks is nonzero, the Locks vector
 * contains NumberOfLocks elements.  Each element requests the acquisition
 * of a lock at Offset of Length.
 *
 * Timeout is the maximum amount of time to wait for the byte range(s)
 * specified to become unlocked.  A timeout value of 0 indicates that the
 * server should fail immediately if any lock range specified is locked.  A
 *
 * timeout value of -1 indicates that the server should wait as long as it
 * takes for each byte range specified to become unlocked so that it may be
 * again locked by this protocol.  Any other value of smb_timeout specifies
 * the maximum number of milliseconds to wait for all lock range(s)
 * specified to become available.
 *
 * If any of the lock ranges timeout because of the area to be locked is
 * already locked (or the lock fails), the other ranges in the protocol
 * request which were successfully locked as a result of this protocol will
 * be unlocked (either all requested ranges will be locked when this
 * protocol returns to the client or none).
 *
 * If LockType has the LOCKING_ANDX_SHARED_LOCK flag set, the lock is
 * specified as a shared lock.  Locks for both read and write (where
 * LOCKING_ANDX_SHARED_LOCK is clear) should be prohibited, but other
 * shared locks should be permitted.  If shared locks can not be supported
 * by a server, the server should map the lock to a lock for both read and
 * write.  Closing a file with locks still in force causes the locks to be
 * released in no defined order.
 *
 * If LockType has the LOCKING_ANDX_LARGE_FILES flag set and if the
 * negotiated protocol is NT LM 0.12 or later, then the Locks and Unlocks
 * vectors are in the Large File LOCKING_ANDX_RANGE format.  This allows
 * specification of 64 bit offsets for very large files.
 *
 * If the one and only member of the Locks vector has the
 * LOCKING_ANDX_CANCEL_LOCK flag set in the LockType field, the client is
 * requesting the server to cancel a previously requested, but not yet
 * responded to, lock.
 *
 * If LockType has the LOCKING_ANDX_CHANGE_LOCKTYPE flag set, the client is
 * requesting that the server atomically change the lock type from a shared
 * lock to an exclusive lock or vice versa.  If the server can not do this
 * in an atomic fashion, the server must reject this request.  NT and W95
 * servers do not support this capability.
 *
 * Oplocks are described in the "Opportunistic Locks" section elsewhere in
 * this document.  A client requests an oplock by setting the appropriate
 * bit in the SMB_COM_OPEN_ANDX request when the file is being opened in a
 * mode which is not exclusive.  The server responds by setting the
 * appropriate bit in the response SMB indicating whether or not the oplock
 * was granted.  By granting the oplock, the server tells the client the
 * file is currently only being used by this one client process at the
 * current time.  The client can therefore safely do read ahead and write
 * behind as well as local caching of file locks knowing that the file will
 * not be accessed/changed in any way by another process while the oplock
 * is in effect.  The client will be notified when any other process
 * attempts to open or modify the oplocked file.
 *
 * When another user attempts to open or otherwise modify the file which a
 * client has oplocked, the server delays the second attempt and notifies
 * the client via an SMB_LOCKING_ANDX SMB asynchronously sent from the
 * server to the client.  This message has the LOCKING_ANDX_OPLOCK_RELEASE
 * flag set indicating to the client that the oplock is being broken.
 *
 * OplockLevel indicates the type of oplock the client now owns. If
 * OplockLevel is 0, the client possesses no oplocks on the file at all, if
 * OplockLevel is 1 the client possesses a Level II oplock.  The client is
 * expected to flush any dirty buffers to the server, submit any file locks
 * and respond to the server with either an SMB_LOCKING_ANDX SMB having the
 * LOCKING_ANDX_OPLOCK_RELEASE flag set, or with a file close if the file
 * is no longer in use by the client.  If the client sends an
 * SMB_LOCKING_ANDX SMB with the LOCKING_ANDX_OPLOCK_RELEASE flag set and
 * NumberOfLocks is zero, the server does not send a response.  Since a
 * close being sent to the server and break oplock notification from the
 * server could cross on the wire, if the client gets an oplock
 * notification on a file which it does not have open, that notification
 * should be ignored.
 *
 * Due to timing, the client could get an "oplock broken" notification in a
 * user's data buffer as a result of this notification crossing on the wire
 * with a SMB_COM_READ_RAW request.  The client must detect this (use
 * length of msg, "FFSMB", MID of -1 and Command of SMB_COM_LOCKING_ANDX)
 * and honor the "oplock broken" notification as usual.  The server must
 * also note on receipt of an SMB_COM_READ_RAW request that there is an
 * outstanding (unanswered) "oplock broken" notification to the client and
 * return a zero length response denoting failure of the read raw request.
 * The client should (after responding to the "oplock broken"
 * notification), use a standard read protocol to redo the read request.
 * This allows a file to actually contain data matching an "oplock broken"
 * notification and still be read correctly.
 *
 * The entire message sent and received including the optional second
 * protocol must fit in the negotiated maximum transfer size.  The
 * following are the only valid SMB commands for AndXCommand for
 * SMB_COM_LOCKING_ANDX:
 *
 *     SMB_COM_READ       SMB_COM_READ_ANDX
 *     SMB_COM_WRITE      SMB_COM_WRITE_ANDX
 *     SMB_COM_FLUSH
 *
 * 4.2.6.1   Errors
 *
 * ERRDOS/ERRbadfile
 * ERRDOS/ERRbadfid
 * ERRDOS/ERRlock
 * ERRDOS/ERRinvdevice
 * ERRSRV/ERRinvid
 * ERRSRV/ERRbaduid
 */

#include <smbsrv/smb_kproto.h>

smb_sdrc_t
smb_pre_locking_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__LockingX__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_locking_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__LockingX__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_locking_andx(smb_request_t *sr)
{
	unsigned short	i;
	unsigned char	lock_type;	/* See lock_type table above */
	unsigned char	oplock_level;	/* The new oplock level */
	uint32_t	timeout;	/* Milliseconds to wait for lock */
	unsigned short	unlock_num;	/* # unlock range structs */
	unsigned short	lock_num;	/* # lock range structs */
	uint32_t	save_pid;	/* Process Id of owner */
	uint32_t	offset32, length32;
	uint64_t	offset64;
	uint64_t	length64;
	DWORD		result;
	int 		rc;
	uint32_t	ltype;
	smb_ofile_t	*ofile;
	uint16_t	tmp_pid;	/* locking uses 16-bit pids */
	uint8_t		brk;

	rc = smbsr_decode_vwv(sr, "4.wbblww", &sr->smb_fid, &lock_type,
	    &oplock_level, &timeout, &unlock_num, &lock_num);
	if (rc != 0)
		return (SDRC_ERROR);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}
	ofile = sr->fid_ofile;
	if (ofile->f_node == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);
	}

	if (lock_type & LOCKING_ANDX_SHARED_LOCK)
		ltype = SMB_LOCK_TYPE_READONLY;
	else
		ltype = SMB_LOCK_TYPE_READWRITE;

	save_pid = sr->smb_pid;	/* Save the original pid */

	if (lock_type & LOCKING_ANDX_OPLOCK_RELEASE) {
		if (oplock_level == 0)
			brk = SMB_OPLOCK_BREAK_TO_NONE;
		else
			brk = SMB_OPLOCK_BREAK_TO_LEVEL_II;
		smb_oplock_ack(ofile->f_node, ofile, brk);
		if (unlock_num == 0 && lock_num == 0)
			return (SDRC_NO_REPLY);
	}

	/*
	 * No support for changing locktype (although we could probably
	 * implement this)
	 */
	if (lock_type & LOCKING_ANDX_CHANGE_LOCK_TYPE) {
		smbsr_error(sr, 0, ERRDOS,
		    ERROR_ATOMIC_LOCKS_NOT_SUPPORTED);
		return (SDRC_ERROR);
	}

	/*
	 * No support for cancel lock (smbtorture expects this)
	 */
	if (lock_type & LOCKING_ANDX_CANCEL_LOCK) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);
	}

	if (lock_type & LOCKING_ANDX_LARGE_FILES) {
		/*
		 * negotiated protocol should be NT LM 0.12 or later
		 */
		if (sr->session->dialect < NT_LM_0_12) {
			smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
			    ERRDOS, ERROR_INVALID_PARAMETER);
			return (SDRC_ERROR);
		}

		for (i = 0; i < unlock_num; i++) {
			rc = smb_mbc_decodef(&sr->smb_data, "w2.QQ",
			    &tmp_pid, &offset64, &length64);
			if (rc) {
				/*
				 * This is the error returned by Windows 2000
				 * even when STATUS32 has been negotiated.
				 */
				smbsr_error(sr, 0, ERRSRV, ERRerror);
				return (SDRC_ERROR);
			}
			sr->smb_pid = tmp_pid;	/* NB: 16-bit */

			result = smb_unlock_range(sr, sr->fid_ofile->f_node,
			    offset64, length64);
			if (result != NT_STATUS_SUCCESS) {
				smbsr_error(sr, NT_STATUS_RANGE_NOT_LOCKED,
				    ERRDOS, ERROR_NOT_LOCKED);
				return (SDRC_ERROR);
			}
		}

		for (i = 0; i < lock_num; i++) {
			rc = smb_mbc_decodef(&sr->smb_data, "w2.QQ",
			    &tmp_pid, &offset64, &length64);
			if (rc) {
				smbsr_error(sr, 0, ERRSRV, ERRerror);
				return (SDRC_ERROR);
			}
			sr->smb_pid = tmp_pid;	/* NB: 16-bit */

			result = smb_lock_range(sr, offset64, length64, timeout,
			    ltype);
			if (result != NT_STATUS_SUCCESS) {
				smb_lock_range_error(sr, result);
				return (SDRC_ERROR);
			}
		}
	} else {
		for (i = 0; i < unlock_num; i++) {
			rc = smb_mbc_decodef(&sr->smb_data, "wll", &tmp_pid,
			    &offset32, &length32);
			if (rc) {
				smbsr_error(sr, 0, ERRSRV, ERRerror);
				return (SDRC_ERROR);
			}
			sr->smb_pid = tmp_pid;	/* NB: 16-bit */

			result = smb_unlock_range(sr, sr->fid_ofile->f_node,
			    (uint64_t)offset32, (uint64_t)length32);
			if (result != NT_STATUS_SUCCESS) {
				smbsr_error(sr, NT_STATUS_RANGE_NOT_LOCKED,
				    ERRDOS, ERROR_NOT_LOCKED);
				return (SDRC_ERROR);
			}
		}

		for (i = 0; i < lock_num; i++) {
			rc = smb_mbc_decodef(&sr->smb_data, "wll", &tmp_pid,
			    &offset32, &length32);
			if (rc) {
				smbsr_error(sr, 0, ERRSRV, ERRerror);
				return (SDRC_ERROR);
			}
			sr->smb_pid = tmp_pid;	/* NB: 16-bit */

			result = smb_lock_range(sr, (uint64_t)offset32,
			    (uint64_t)length32, timeout, ltype);
			if (result != NT_STATUS_SUCCESS) {
				smb_lock_range_error(sr, result);
				return (SDRC_ERROR);
			}
		}
	}

	sr->smb_pid = save_pid;
	if (smbsr_encode_result(sr, 2, 0, "bb.ww", 2, sr->andx_com, 7, 0))
		return (SDRC_ERROR);
	return (SDRC_SUCCESS);
}

/*
 * Compose an SMB1 Oplock Break Notification packet, including
 * the SMB1 header and everything, in sr->reply.
 * The caller will send it and free the request.
 */
void
smb1_oplock_break_notification(smb_request_t *sr, uint8_t brk)
{
	smb_ofile_t *ofile = sr->fid_ofile;
	uint16_t fid;
	uint8_t lock_type;
	uint8_t oplock_level;

	switch (brk) {
	default:
		ASSERT(0);
		/* FALLTHROUGH */
	case SMB_OPLOCK_BREAK_TO_NONE:
		oplock_level = 0;
		break;
	case SMB_OPLOCK_BREAK_TO_LEVEL_II:
		oplock_level = 1;
		break;
	}

	sr->smb_com = SMB_COM_LOCKING_ANDX;
	sr->smb_tid = ofile->f_tree->t_tid;
	sr->smb_pid = 0xFFFF;
	sr->smb_uid = 0;
	sr->smb_mid = 0xFFFF;
	fid = ofile->f_fid;
	lock_type = LOCKING_ANDX_OPLOCK_RELEASE;

	(void) smb_mbc_encodef(
	    &sr->reply, "Mb19.wwwwbb3.wbb10.",
	    /*  "\xffSMB"		   M */
	    sr->smb_com,		/* b */
	    /* status, flags, signature	 19. */
	    sr->smb_tid,		/* w */
	    sr->smb_pid,		/* w */
	    sr->smb_uid,		/* w */
	    sr->smb_mid,		/* w */
	    8,		/* word count	   b */
	    0xFF,	/* AndX cmd	   b */
	    /*  AndX reserved, offset	  3. */
	    fid,
	    lock_type,
	    oplock_level);
}
