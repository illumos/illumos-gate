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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_LOCK
 */

#include <smbsrv/smb2_kproto.h>

struct SMB2_LOCK_ELEMENT {
	uint64_t Offset;
	uint64_t Length;
	uint32_t Flags;
	uint32_t reserved;
};

static smb_sdrc_t smb2_lock_async(smb_request_t *);
static uint32_t smb2_lock_exec(smb_request_t *, uint16_t);
static uint32_t smb2_lock_elem(smb_request_t *, struct SMB2_LOCK_ELEMENT *);

/*
 * This is a somewhat arbitrary sanity limit on the length of the
 * SMB2_LOCK_ELEMENT array.  It usually has length one or two.
 */
int smb2_lock_max_elem = 1024;

smb_sdrc_t
smb2_lock(smb_request_t *sr)
{
	struct SMB2_LOCK_ELEMENT elem;
	smb2fid_t smb2fid;
	uint32_t save_offset;
	uint32_t LockSequence;
	uint32_t status;
	uint16_t StructSize;
	uint16_t LockCount;
	uint16_t i;
	boolean_t MayBlock = B_FALSE;
	int rc = 0;

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
	 * Process the array of SMB2_LOCK_ELEMENT structs
	 * We do this twice.  (it's always a short list)
	 * The first time, just validate the flags, and check
	 * if any of the locking request might need to block.
	 * The second time (either here, or in the async
	 * handler function) process the locks for real.
	 */
	save_offset = sr->smb_data.chain_offset;
	for (i = 0; i < LockCount; i++) {
		rc = smb_mbc_decodef(
		    &sr->smb_data, "qqll",
		    &elem.Offset,	/* q */
		    &elem.Length,	/* q */
		    &elem.Flags,	/* l */
		    &elem.reserved);	/* l */
		if (rc) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}

		/*
		 * Make sure the flags are valid;
		 * Find out if we might block.
		 */
		switch (elem.Flags) {
		case SMB2_LOCKFLAG_SHARED_LOCK:
		case SMB2_LOCKFLAG_EXCLUSIVE_LOCK:
			MayBlock = B_TRUE;
			break;

		/* BEGIN CSTYLED */
		case SMB2_LOCKFLAG_SHARED_LOCK |
		     SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		case SMB2_LOCKFLAG_EXCLUSIVE_LOCK |
		     SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		case SMB2_LOCKFLAG_UNLOCK:
		/* END CSTYLED */
			break;

		default:
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}
	}

	if (MayBlock) {
		/*
		 * May need to block.  "Go async".
		 */
		status = smb2sr_go_async(sr, smb2_lock_async);
		goto errout;
	}

	sr->smb_data.chain_offset = save_offset;
	status = smb2_lock_exec(sr, LockCount);
	if (status)
		goto errout;

	/*
	 * SMB2 Lock reply (sync)
	 */
	StructSize = 4;
	(void) smb_mbc_encodef(
	    &sr->reply, "w..",
	    StructSize);	/* w */
	    /* reserved		  .. */
	return (SDRC_SUCCESS);

errout:
	smb2sr_put_error(sr, status);
	return (SDRC_SUCCESS);
}

static smb_sdrc_t
smb2_lock_async(smb_request_t *sr)
{
	smb2fid_t smb2fid;
	uint32_t LockSequence;
	uint32_t status;
	uint16_t StructSize;
	uint16_t LockCount;
	int rc = 0;

	/*
	 * Decode the lock request again.  It should all decode
	 * exactly the same as the first time we saw it.  If not,
	 * report an "internal error".
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
		status = NT_STATUS_INTERNAL_ERROR;
		goto errout;
	}

	status = smb2_lock_exec(sr, LockCount);
	if (status)
		goto errout;

	/*
	 * SMB2 Lock reply (async)
	 */
	StructSize = 4;
	(void) smb_mbc_encodef(
	    &sr->reply, "w..",
	    StructSize);	/* w */
	    /* reserved		  .. */
	return (SDRC_SUCCESS);

errout:
	smb2sr_put_error(sr, status);
	return (SDRC_SUCCESS);
}

/*
 * Execute the vector of locks.  This is the common function called by
 * either the sync or async code paths.  We've already decoded this
 * request once when we get here, so if there are any decode errors
 * then it's some kind of internal error.
 */
static uint32_t
smb2_lock_exec(smb_request_t *sr, uint16_t LockCount)
{
	struct SMB2_LOCK_ELEMENT elem;
	uint32_t status = 0;
	uint16_t i;
	int rc;

	/*
	 * On entry, out position in the input data should be
	 * after both the SMB2 header and the fixed part of
	 * the SMB Lock request header (24).
	 */
	ASSERT(sr->smb_data.chain_offset ==
	    (sr->smb2_cmd_hdr + SMB2_HDR_SIZE + 24));

	/*
	 * This is checked by our callers, but let's make sure.
	 */
	ASSERT(sr->fid_ofile->f_node != NULL);

	for (i = 0; i < LockCount; i++) {
		rc = smb_mbc_decodef(
		    &sr->smb_data, "qqll",
		    &elem.Offset,	/* q */
		    &elem.Length,	/* q */
		    &elem.Flags,	/* l */
		    &elem.reserved);	/* l */
		if (rc) {
			status = NT_STATUS_INTERNAL_ERROR;
			break;
		}
		status = smb2_lock_elem(sr, &elem);
		if (status)
			break;
	}
	return (status);
}

static uint32_t
smb2_lock_elem(smb_request_t *sr, struct SMB2_LOCK_ELEMENT *elem)
{
	smb_node_t *node = sr->fid_ofile->f_node;
	uint32_t status;
	uint32_t ltype;
	uint32_t timeout = 0;

	switch (elem->Flags) {
	case SMB2_LOCKFLAG_SHARED_LOCK:
		timeout = UINT_MAX;
		/* FALLTHROUGH */
	case SMB2_LOCKFLAG_SHARED_LOCK | SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		ltype = SMB_LOCK_TYPE_READONLY;
		status = smb_lock_range(sr,
		    elem->Offset, elem->Length,
		    timeout, ltype);
		break;

	case SMB2_LOCKFLAG_EXCLUSIVE_LOCK:
		timeout = UINT_MAX;
		/* FALLTHROUGH */
	case SMB2_LOCKFLAG_EXCLUSIVE_LOCK | SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		ltype = SMB_LOCK_TYPE_READWRITE;
		status = smb_lock_range(sr,
		    elem->Offset, elem->Length,
		    timeout, ltype);
		break;

	case SMB2_LOCKFLAG_UNLOCK:
		status = smb_unlock_range(sr, node,
		    elem->Offset, elem->Length);
		break;

	/*
	 * We've already checked the flags previously, so any
	 * surprises here are some kind of internal error.
	 */
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}

	return (status);
}
