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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_LOCK
 */

#include <smbsrv/smb2_kproto.h>

typedef struct SMB2_LOCK_ELEMENT {
	uint64_t Offset;
	uint64_t Length;
	uint32_t Flags;
	uint32_t reserved;
} lock_elem_t;

static uint32_t smb2_unlock(smb_request_t *);
static uint32_t smb2_locks(smb_request_t *);
static smb_sdrc_t smb2_lock_async(smb_request_t *);

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
	 * SMB2 Lock request
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

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status)
		goto errout;
	if (sr->fid_ofile->f_node == NULL || LockCount == 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}
	if (LockCount > smb2_lock_max_elem) {
		status = NT_STATUS_INSUFFICIENT_RESOURCES;
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
	if (status)
		goto errout;

	/*
	 * SMB2 Lock reply (sync)
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "w..",
	    4); /* StructSize	w */
	    /* reserved		.. */
	return (SDRC_SUCCESS);

errout:
	smb2sr_put_error(sr, status);
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
	(void) LockSequence; /* todo */

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
				status = smb2sr_go_async(sr, smb2_lock_async);
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

	return (status);
}

/*
 * Async handler for blocking lock requests.
 * Always exactly one lock request here.
 */
static smb_sdrc_t
smb2_lock_async(smb_request_t *sr)
{
	lock_elem_t *lk = sr->arg.lock.lvec;
	uint32_t LockCount = sr->arg.lock.lcnt;
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
		status = NT_STATUS_INTERNAL_ERROR;
		goto errout;
	}

	status = smb_lock_range(sr, lk->Offset, lk->Length, pid,
	    ltype, timeout);
	if (status != 0)
		goto errout;

	/*
	 * SMB2 Lock reply (async)
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "w..",
	    4); /* StructSize	w */
	    /* reserved		.. */
	return (SDRC_SUCCESS);

errout:
	smb2sr_put_error(sr, status);
	return (SDRC_SUCCESS);
}
