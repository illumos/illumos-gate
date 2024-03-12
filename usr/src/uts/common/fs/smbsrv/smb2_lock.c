/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2022-2024 RackTop Systems, Inc.
 */

/*
 * Dispatch function for SMB2_LOCK
 */

#include <smbsrv/smb2_kproto.h>

/*
 * [MS-SMB2] 2.2.26 LockSequenceIndex, LockSequenceNumber.
 */
#define	SMB2_LSN_SHIFT	4
#define	SMB2_LSN_MASK	0xf

typedef struct SMB2_LOCK_ELEMENT {
	uint64_t Offset;
	uint64_t Length;
	uint32_t Flags;
	uint32_t reserved;
} lock_elem_t;

static uint32_t smb2_unlock(smb_request_t *);
static uint32_t smb2_locks(smb_request_t *);
static uint32_t smb2_lock_blocking(smb_request_t *);

static boolean_t smb2_lock_chk_lockseq(smb_ofile_t *, uint32_t);
static void smb2_lock_set_lockseq(smb_ofile_t *, uint32_t);

/*
 * This is a somewhat arbitrary sanity limit on the length of the
 * SMB2_LOCK_ELEMENT array.  It usually has length one or two.
 */
int smb2_lock_max_elem = 1024;

smb_sdrc_t
smb2_lock(smb_request_t *sr)
{
	lock_elem_t *lvec, *lk;
	smb2fid_t smb2fid;
	uint32_t LockSequence;
	uint32_t status;
	uint16_t StructSize;
	uint16_t LockCount;
	uint16_t i;
	int rc;

	/*
	 * Decode SMB2 Lock request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wwlqq",
	    &StructSize,		/* w */
	    &LockCount,			/* w */
	    &LockSequence,		/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal);		/* q */
	if (rc || StructSize != 48)
		return (SDRC_ERROR);

	/*
	 * Want FID lookup before the start probe.
	 */
	status = smb2sr_lookup_fid(sr, &smb2fid);
	DTRACE_SMB2_START(op__Lock, smb_request_t *, sr);

	if (status)
		goto errout; /* Bad FID */
	if (sr->fid_ofile->f_node == NULL || LockCount == 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}
	if (LockCount > smb2_lock_max_elem) {
		status = NT_STATUS_INSUFFICIENT_RESOURCES;
		goto errout;
	}

	/*
	 * Check the LockSequence to determine whether a previous
	 * lock request succeeded, but the client disconnected
	 * (retaining a durable or resilient handle).  If so, this
	 * is a lock "replay".  We'll find the lock sequence here
	 * and return success without processing the lock again.
	 */
	if (sr->session->dialect < SMB_VERS_2_1)
		LockSequence = 0;
	if ((sr->session->dialect == SMB_VERS_2_1) &&
	    sr->fid_ofile->dh_vers != SMB2_RESILIENT)
		LockSequence = 0;
	/* dialect 3.0 or later can always use LockSequence */

	if (LockSequence != 0 &&
	    smb2_lock_chk_lockseq(sr->fid_ofile, LockSequence)) {
		status = NT_STATUS_SUCCESS;
		goto errout;
	}

	/*
	 * Parse the array of SMB2_LOCK_ELEMENT structs.
	 * This array is free'd in smb_srm_fini.
	 */
	lvec = smb_srm_zalloc(sr, LockCount * sizeof (*lvec));
	for (i = 0; i < LockCount; i++) {
		lk = &lvec[i];
		rc = smb_mbc_decodef(
		    &sr->smb_data, "qqll",
		    &lk->Offset,	/* q */
		    &lk->Length,	/* q */
		    &lk->Flags,		/* l */
		    &lk->reserved);	/* l */
		if (rc) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}
	}

	/*
	 * [MS-SMB2] 3.3.5.14
	 * If the flags of the [first element of] the Locks array
	 * [has] SMB2_LOCKFLAG_UNLOCK set, the server MUST process
	 * the lock array as a series of unlocks. Otherwise, it
	 * MUST process the lock array as a series of lock requests.
	 */
	sr->arg.lock.lvec = lvec;
	sr->arg.lock.lcnt = LockCount;
	sr->arg.lock.lseq = LockSequence;
	if (lvec[0].Flags & SMB2_LOCKFLAG_UNLOCK) {
		status = smb2_unlock(sr);
	} else {
		status = smb2_locks(sr);
	}

	if (sr->fid_ofile->dh_persist) {
		smb2_dh_update_locks(sr, sr->fid_ofile);
	}

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Lock, smb_request_t *, sr);

	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * Encode SMB2 Lock reply
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "w..",
	    4); /* StructSize	w */
	    /* reserved		.. */
	return (SDRC_SUCCESS);
}

/*
 * Process what should be an array of unlock requests.
 */
static uint32_t
smb2_unlock(smb_request_t *sr)
{
	lock_elem_t *lk;
	lock_elem_t *lvec = sr->arg.lock.lvec;
	uint32_t LockCount = sr->arg.lock.lcnt;
	uint32_t LockSequence = sr->arg.lock.lseq;
	uint32_t status = 0;
	uint32_t pid = 0;	/* SMB2 ignores lock PIDs. */
	int i;

	for (i = 0; i < LockCount; i++) {
		lk = &lvec[i];

		if (lk->Flags != SMB2_LOCKFLAG_UNLOCK) {
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		status = smb_unlock_range(sr, lk->Offset, lk->Length, pid);
		if (status != 0)
			break;
	}
	if (status == 0 && LockSequence != 0) {
		smb2_lock_set_lockseq(sr->fid_ofile, LockSequence);
	}

	return (status);
}

/*
 * Process what should be an array of lock requests.
 */
static uint32_t
smb2_locks(smb_request_t *sr)
{
	lock_elem_t *lk;
	lock_elem_t *lvec = sr->arg.lock.lvec;
	uint32_t LockCount = sr->arg.lock.lcnt;
	uint32_t LockSequence = sr->arg.lock.lseq;
	uint32_t i;
	uint32_t ltype;
	uint32_t pid = 0;	/* SMB2 ignores lock PIDs */
	uint32_t timeout = 0;
	uint32_t status = 0;

	for (i = 0; i < LockCount; i++) {
		lk = &lvec[i];

		switch (lk->Flags) {

		case SMB2_LOCKFLAG_SHARED_LOCK:
		case SMB2_LOCKFLAG_EXCLUSIVE_LOCK:
			/*
			 * Blocking locks have special rules:
			 * Must be exactly one element, else
			 * invalid parameter.
			 */
			if (i == 0 && LockCount == 1) {
				status = smb2_lock_blocking(sr);
				return (status);
			}
			/* FALLTHROUGH */
		case SMB2_LOCKFLAG_UNLOCK:
		default:
			status = NT_STATUS_INVALID_PARAMETER;
			goto end_loop;

		/* BEGIN CSTYLED */
		case SMB2_LOCKFLAG_SHARED_LOCK |
		     SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		/* END CSTYLED */
			ltype = SMB_LOCK_TYPE_READONLY;
			break;

		/* BEGIN CSTYLED */
		case SMB2_LOCKFLAG_EXCLUSIVE_LOCK |
		     SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		/* END CSTYLED */
			ltype = SMB_LOCK_TYPE_READWRITE;
			break;
		}

		status = smb_lock_range(sr, lk->Offset, lk->Length, pid,
		    ltype, timeout);
		if (status != 0) {
			goto end_loop;
		}
	}

end_loop:
	if (status != 0) {
		/*
		 * Oh... we have to rollback.
		 */
		while (i > 0) {
			--i;
			lk = &lvec[i];
			(void) smb_unlock_range(sr,
			    lk->Offset, lk->Length, pid);
		}
	}
	if (status == 0 && LockSequence != 0)
		smb2_lock_set_lockseq(sr->fid_ofile, LockSequence);

	return (status);
}

/*
 * Handler for blocking lock requests, which may "go async".
 * Always exactly one lock request here.
 */
static uint32_t
smb2_lock_blocking(smb_request_t *sr)
{
	lock_elem_t *lk = sr->arg.lock.lvec;
	uint32_t LockCount = sr->arg.lock.lcnt;
	uint32_t LockSequence = sr->arg.lock.lseq;
	uint32_t status;
	uint32_t ltype;
	uint32_t pid = 0;	/* SMB2 ignores lock PIDs */
	uint32_t timeout = UINT_MAX;

	ASSERT(sr->fid_ofile->f_node != NULL);
	ASSERT(LockCount == 1);

	switch (lk->Flags) {
	case SMB2_LOCKFLAG_SHARED_LOCK:
		ltype = SMB_LOCK_TYPE_READONLY;
		break;

	case SMB2_LOCKFLAG_EXCLUSIVE_LOCK:
		ltype = SMB_LOCK_TYPE_READWRITE;
		break;

	default:
		ASSERT(0);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	/*
	 * Try the lock first with timeout=0 as we can often
	 * get a lock without going async and avoid an extra
	 * round trip with the client.  Also, only go async
	 * for status returns that mean we will block.
	 */
	status = smb_lock_range(sr, lk->Offset, lk->Length, pid, ltype, 0);
	if (status == NT_STATUS_LOCK_NOT_GRANTED ||
	    status == NT_STATUS_FILE_LOCK_CONFLICT) {
		status = smb2sr_go_async_indefinite(sr);
		if (status != 0)
			return (status);
		status = smb_lock_range(sr, lk->Offset, lk->Length,
		    pid, ltype, timeout);
	}

	if (status == 0 && LockSequence != 0)
		smb2_lock_set_lockseq(sr->fid_ofile, LockSequence);

	return (status);
}

/*
 * Check whether we've stored a given LockSequence
 *
 * [MS-SMB2] 3.3.5.14
 *
 * The server verifies the LockSequence by performing the following steps:
 *
 * 1. The server MUST use LockSequenceIndex as an index into the
 * Open.LockSequenceArray in order to locate the sequence number entry.
 * If the index exceeds the maximum extent of the Open.LockSequenceArray,
 * or LockSequenceIndex is 0, or if the sequence number entry is empty,
 * the server MUST skip step 2 and continue lock/unlock processing.
 *
 * 2. The server MUST compare LockSequenceNumber to the SequenceNumber of
 * the entry located in step 1. If the sequence numbers are equal, the
 * server MUST complete the lock/unlock request with success. Otherwise,
 * the server MUST reset the entry value to empty and continue lock/unlock
 * processing.
 */
boolean_t
smb2_lock_chk_lockseq(smb_ofile_t *ofile, uint32_t lockseq)
{
	uint32_t lsi;
	uint8_t lsn;
	boolean_t rv;

	/*
	 * LockSequenceNumber is the low four bits.
	 * LockSequenceIndex is the remaining 28 bits.
	 * valid range is 1..64, which we convert to an
	 * array index in the range 0..63
	 */
	lsn = lockseq & SMB2_LSN_MASK;
	lsi = (lockseq >> SMB2_LSN_SHIFT);
	if (lsi == 0 || lsi > SMB_OFILE_LSEQ_MAX)
		return (B_FALSE);
	--lsi;

	mutex_enter(&ofile->f_mutex);

	if (ofile->f_lock_seq[lsi] == lsn) {
		rv = B_TRUE;
	} else {
		ofile->f_lock_seq[lsi] = (uint8_t)-1;	/* "Empty" */
		rv = B_FALSE;
	}

	mutex_exit(&ofile->f_mutex);

	return (rv);
}

static void
smb2_lock_set_lockseq(smb_ofile_t *ofile, uint32_t lockseq)
{
	uint32_t lsi;
	uint8_t lsn;

	/*
	 * LockSequenceNumber is the low four bits.
	 * LockSequenceIndex is the remaining 28 bits.
	 * valid range is 1..64, which we convert to an
	 * array index in the range 0..63
	 */
	lsn = lockseq & SMB2_LSN_MASK;
	lsi = (lockseq >> SMB2_LSN_SHIFT);
	if (lsi == 0 || lsi > SMB_OFILE_LSEQ_MAX) {
		cmn_err(CE_NOTE, "smb2_lock_set_lockseq, index=%u", lsi);
		return;
	}
	--lsi;

	mutex_enter(&ofile->f_mutex);

	ofile->f_lock_seq[lsi] = lsn;

	mutex_exit(&ofile->f_mutex);
}
