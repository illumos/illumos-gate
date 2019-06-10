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
 */

/*
 * (SMB1/SMB2) common (FS-level) Oplock support.
 *
 * This is the file-system (FS) level oplock code.  This level
 * knows about the rules by which various kinds of oplocks may
 * coexist and how they interact.  Note that this code should
 * have NO knowledge of specific SMB protocol details.  Those
 * details are handled in smb_srv_oplock.c and related.
 *
 * This file is intentionally written to very closely follow the
 * [MS-FSA] specification sections about oplocks.  Almost every
 * section of code is preceeded by a block of text from that
 * specification describing the logic.  Where the implementation
 * differs from what the spec. describes, there are notes like:
 * Implementation specific: ...
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_oplock.h>

/*
 * Several short-hand defines and enums used in this file.
 */

#define	NODE_FLAGS_DELETING	(NODE_FLAGS_DELETE_ON_CLOSE |\
				NODE_FLAGS_DELETE_COMMITTED)

static uint32_t
smb_oplock_req_excl(
    smb_ofile_t *ofile,		/* in: the "Open" */
    uint32_t *rop);		/* in: "RequestedOplock", out:NewOplockLevel */

static uint32_t
smb_oplock_req_shared(
    smb_ofile_t *ofile,		/* the "Open" */
    uint32_t *rop,		/* in: "RequestedOplock", out:NewOplockLevel */
    boolean_t GrantingInAck);

static uint32_t smb_oplock_break_cmn(smb_node_t *node,
    smb_ofile_t *ofile, uint32_t BreakCacheLevel);


/*
 * [MS-FSA] 2.1.4.12.2 Algorithm to Compare Oplock Keys
 *
 * The inputs for this algorithm are:
 *
 *	OperationOpen: The Open used in the request that can
 *	  cause an oplock to break.
 *	OplockOpen: The Open originally used to request the oplock,
 *	  as specified in section 2.1.5.17.
 *	Flags: If unspecified it is considered to contain 0.
 *	  Valid nonzero values are:
 *		PARENT_OBJECT
 *
 * This algorithm returns TRUE if the appropriate oplock key field of
 * OperationOpen equals OplockOpen.TargetOplockKey, and FALSE otherwise.
 *
 * Note: Unlike many comparison functions, ARG ORDER MATTERS.
 */

static boolean_t
CompareOplockKeys(smb_ofile_t *OperOpen, smb_ofile_t *OplockOpen, int flags)
{
	static const uint8_t key0[SMB_LEASE_KEY_SZ] = { 0 };

	/*
	 * When we're called via FEM, (smb_oplock_break_...)
	 * the OperOpen arg is NULL because I/O outside of SMB
	 * doesn't have an "ofile".  That's "not a match".
	 */
	if (OperOpen == NULL)
		return (B_FALSE);
	ASSERT(OplockOpen != NULL);

	/*
	 * If OperationOpen equals OplockOpen:
	 * Return TRUE.
	 */
	if (OperOpen == OplockOpen)
		return (B_TRUE);

	/*
	 * If both OperationOpen.TargetOplockKey and
	 * OperationOpen.ParentOplockKey are empty
	 * or both OplockOpen.TargetOplockKey and
	 * OplockOpen.ParentOplockKey are empty:
	 * Return FALSE.
	 */
	if (bcmp(OperOpen->TargetOplockKey, key0, sizeof (key0)) == 0 &&
	    bcmp(OperOpen->ParentOplockKey, key0, sizeof (key0)) == 0)
		return (B_FALSE);
	if (bcmp(OplockOpen->TargetOplockKey, key0, sizeof (key0)) == 0 &&
	    bcmp(OplockOpen->ParentOplockKey, key0, sizeof (key0)) == 0)
		return (B_FALSE);

	/*
	 * If OplockOpen.TargetOplockKey is empty or...
	 */
	if (bcmp(OplockOpen->TargetOplockKey, key0, sizeof (key0)) == 0)
		return (B_FALSE);

	/*
	 * If Flags contains PARENT_OBJECT:
	 */
	if ((flags & PARENT_OBJECT) != 0) {
		/*
		 * If OperationOpen.ParentOplockKey is empty:
		 * Return FALSE.
		 */
		if (bcmp(OperOpen->ParentOplockKey, key0, sizeof (key0)) == 0)
			return (B_FALSE);

		/*
		 * If OperationOpen.ParentOplockKey equals
		 * OplockOpen.TargetOplockKey:
		 * return TRUE, else FALSE
		 */
		if (bcmp(OperOpen->ParentOplockKey,
		    OplockOpen->TargetOplockKey,
		    SMB_LEASE_KEY_SZ) == 0) {
			return (B_TRUE);
		}
	} else {
		/*
		 * ... from above:
		 * (Flags does not contain PARENT_OBJECT and
		 * OperationOpen.TargetOplockKey is empty):
		 * Return FALSE.
		 */
		if (bcmp(OperOpen->TargetOplockKey, key0, sizeof (key0)) == 0)
			return (B_FALSE);

		/*
		 * If OperationOpen.TargetOplockKey equals
		 * OplockOpen.TargetOplockKey:
		 *  Return TRUE, else FALSE
		 */
		if (bcmp(OperOpen->TargetOplockKey,
		    OplockOpen->TargetOplockKey,
		    SMB_LEASE_KEY_SZ) == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * 2.1.4.13 Algorithm to Recompute the State of a Shared Oplock
 *
 * The inputs for this algorithm are:
 *	ThisOplock: The Oplock on whose state is being recomputed.
 */
static void
RecomputeOplockState(smb_node_t *node)
{
	smb_oplock_t *ol = &node->n_oplock;

	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

	/*
	 * If ThisOplock.IIOplocks, ThisOplock.ROplocks, ThisOplock.RHOplocks,
	 * and ThisOplock.RHBreakQueue are all empty:
	 *	Set ThisOplock.State to NO_OPLOCK.
	 */
	if (ol->cnt_II == 0 && ol->cnt_R == 0 &&
	    ol->cnt_RH == 0 && ol->cnt_RHBQ == 0) {
		ol->ol_state = NO_OPLOCK;
		return;
	}

	/*
	 * Else If ThisOplock.ROplocks is not empty and either
	 *    ThisOplock.RHOplocks or ThisOplock.RHBreakQueue are not empty:
	 *	Set ThisOplock.State to
	 *	  (READ_CACHING|HANDLE_CACHING|MIXED_R_AND_RH).
	 */
	else if (ol->cnt_R != 0 && (ol->cnt_RH != 0 || ol->cnt_RHBQ != 0)) {
		ol->ol_state = (READ_CACHING|HANDLE_CACHING|MIXED_R_AND_RH);
	}

	/*
	 * Else If ThisOplock.ROplocks is empty and
	 * ThisOplock.RHOplocks is not empty:
	 *	Set ThisOplock.State to (READ_CACHING|HANDLE_CACHING).
	 */
	else if (ol->cnt_R == 0 && ol->cnt_RH != 0) {
		ol->ol_state = (READ_CACHING|HANDLE_CACHING);
	}

	/*
	 * Else If ThisOplock.ROplocks is not empty and
	 * ThisOplock.IIOplocks is not empty:
	 *	Set ThisOplock.State to (READ_CACHING|LEVEL_TWO_OPLOCK).
	 */
	else if (ol->cnt_R != 0 && ol->cnt_II != 0) {
		ol->ol_state = (READ_CACHING|LEVEL_TWO_OPLOCK);
	}

	/*
	 * Else If ThisOplock.ROplocks is not empty and
	 * ThisOplock.IIOplocks is empty:
	 *	Set ThisOplock.State to READ_CACHING.
	 */
	else if (ol->cnt_R != 0 && ol->cnt_II == 0) {
		ol->ol_state = READ_CACHING;
	}

	/*
	 * Else If ThisOplock.ROplocks is empty and
	 * ThisOplock.IIOplocks is not empty:
	 *	Set ThisOplock.State to LEVEL_TWO_OPLOCK.
	 */
	else if (ol->cnt_R == 0 && ol->cnt_II != 0) {
		ol->ol_state = LEVEL_TWO_OPLOCK;
	}

	else {
		smb_ofile_t *o;
		int cntBrkToRead;

		/*
		 * ThisOplock.RHBreakQueue MUST be non-empty by this point.
		 */
		ASSERT(ol->cnt_RHBQ != 0);

		/*
		 * How many on RHBQ have BreakingToRead set?
		 */
		cntBrkToRead = 0;
		FOREACH_NODE_OFILE(node, o) {
			if (o->f_oplock.onlist_RHBQ == 0)
				continue;
			if (o->f_oplock.BreakingToRead)
				cntBrkToRead++;
		}

		/*
		 * If RHOpContext.BreakingToRead is TRUE for
		 *  every RHOpContext on ThisOplock.RHBreakQueue:
		 */
		if (cntBrkToRead == ol->cnt_RHBQ) {
			/*
			 * Set ThisOplock.State to
			 * (READ_CACHING|HANDLE_CACHING|BREAK_TO_READ_CACHING).
			 */
			ol->ol_state = (READ_CACHING|HANDLE_CACHING|
			    BREAK_TO_READ_CACHING);
		}

		/*
		 * Else If RHOpContext.BreakingToRead is FALSE for
		 *  every RHOpContext on ThisOplock.RHBreakQueue:
		 */
		else if (cntBrkToRead == 0) {
			/*
			 * Set ThisOplock.State to
			 *  (READ_CACHING|HANDLE_CACHING|BREAK_TO_NO_CACHING).
			 */
			ol->ol_state = (READ_CACHING|HANDLE_CACHING|
			    BREAK_TO_NO_CACHING);
		} else {
			/*
			 * Set ThisOplock.State to
			 *  (READ_CACHING|HANDLE_CACHING).
			 */
			ol->ol_state = (READ_CACHING|HANDLE_CACHING);
		}
	}
}

/*
 * [MS-FSA] 2.1.5.17 Server Requests an Oplock
 *
 * The server (caller) provides:
 *	Open - The Open on which the oplock is being requested. (ofile)
 *	Type - The type of oplock being requested. Valid values are as follows:
 *		LEVEL_TWO (Corresponds to SMB2_OPLOCK_LEVEL_II)
 *		LEVEL_ONE (Corresponds to SMB2_OPLOCK_LEVEL_EXCLUSIVE)
 *		LEVEL_BATCH (Corresponds to SMB2_OPLOCK_LEVEL_BATCH)
 *		LEVEL_GRANULAR (Corresponds to SMB2_OPLOCK_LEVEL_LEASE)
 *	RequestedOplockLevel - A combination of zero or more of the
 *	  following flags (ignored if Type != LEVEL_GRANULAR)
 *		READ_CACHING
 *		HANDLE_CACHING
 *		WRITE_CACHING
 *
 *	(Type + RequestedOplockLevel come in *statep)
 *
 * Returns:
 *	*statep = NewOplockLevel (possibly less than requested)
 *		  containing: LEVEL_NONE, LEVEL_TWO + cache_flags
 *	NTSTATUS
 */

uint32_t
smb_oplock_request(smb_request_t *sr, smb_ofile_t *ofile, uint32_t *statep)
{
	smb_node_t *node = ofile->f_node;
	uint32_t type = *statep & OPLOCK_LEVEL_TYPE_MASK;
	uint32_t level = *statep & OPLOCK_LEVEL_CACHE_MASK;
	uint32_t status;

	*statep = LEVEL_NONE;

	/*
	 * If Open.Stream.StreamType is DirectoryStream:
	 *	The operation MUST be failed with STATUS_INVALID_PARAMETER
	 *	under either of the following conditions:
	 *	* Type is not LEVEL_GRANULAR.
	 *	* Type is LEVEL_GRANULAR but RequestedOplockLevel is
	 *	  neither READ_CACHING nor (READ_CACHING|HANDLE_CACHING).
	 */
	if (!smb_node_is_file(node)) {
		/* ofile is a directory. */
		if (type != LEVEL_GRANULAR)
			return (NT_STATUS_INVALID_PARAMETER);
		if (level != READ_CACHING &&
		    level != (READ_CACHING|HANDLE_CACHING))
			return (NT_STATUS_INVALID_PARAMETER);
		/*
		 * We're not supporting directory leases yet.
		 * Todo.
		 */
		return (NT_STATUS_OPLOCK_NOT_GRANTED);
	}

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	/*
	 * If Type is LEVEL_ONE or LEVEL_BATCH:
	 * The operation MUST be failed with STATUS_OPLOCK_NOT_GRANTED
	 * under either of the following conditions:
	 *	Open.File.OpenList contains more than one Open
	 *	  whose Stream is the same as Open.Stream.
	 *	Open.Mode contains either FILE_SYNCHRONOUS_IO_ALERT or
	 *	  FILE_SYNCHRONOUS_IO_NONALERT.
	 * Request an exclusive oplock according to the algorithm in
	 * section 2.1.5.17.1, setting the algorithm's params as follows:
	 *	Pass in the current Open.
	 *	RequestedOplock = Type.
	 * The operation MUST at this point return any status code
	 * returned by the exclusive oplock request algorithm.
	 */
	if (type == LEVEL_ONE || type == LEVEL_BATCH) {
		if (node->n_open_count > 1) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}
		/* XXX: Should be a flag on the ofile. */
		if (node->flags & NODE_FLAGS_WRITE_THROUGH) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}
		*statep = type;
		status = smb_oplock_req_excl(ofile, statep);
		goto out;
	}

	/*
	 * Else If Type is LEVEL_TWO:
	 * The operation MUST be failed with STATUS_OPLOCK_NOT_GRANTED under
	 *  either of the following conditions:
	 *	Open.Stream.ByteRangeLockList is not empty.
	 *	Open.Mode contains either FILE_SYNCHRONOUS_IO_ALERT or
	 *	  FILE_SYNCHRONOUS_IO_NONALERT.
	 * Request a shared oplock according to the algorithm in
	 * section 2.1.5.17.2, setting the algorithm's parameters as follows:
	 *	Pass in the current Open.
	 *	RequestedOplock = Type.
	 *	GrantingInAck = FALSE.
	 * The operation MUST at this point return any status code
	 * returned by the shared oplock request algorithm.
	 */
	if (type == LEVEL_TWO) {
		if (smb_lock_range_access(sr, node, 0, ~0, B_FALSE) != 0) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}
		/* XXX: Should be a flag on the ofile. */
		if (node->flags & NODE_FLAGS_WRITE_THROUGH) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}
		*statep = type;
		status = smb_oplock_req_shared(ofile, statep, B_FALSE);
		goto out;
	}

	/*
	 * Else If Type is LEVEL_GRANULAR:
	 *   Sub-cases on RequestedOplockLevel (our "level")
	 *
	 * This is the last Type, so error on !granular and then
	 * deal with the cache levels using one less indent.
	 */
	if (type != LEVEL_GRANULAR) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	switch (level) {

	/*
	 * If RequestedOplockLevel is READ_CACHING or
	 *   (READ_CACHING|HANDLE_CACHING):
	 *	The operation MUST be failed with STATUS_OPLOCK_NOT_GRANTED
	 *	under either of the following conditions:
	 *		Open.Stream.ByteRangeLockList is not empty.
	 *		Open.Mode contains either FILE_SYNCHRONOUS_IO_ALERT or
	 *		  FILE_SYNCHRONOUS_IO_NONALERT.
	 *	Request a shared oplock according to the algorithm in
	 *	section 2.1.5.17.2, setting the parameters as follows:
	 *		Pass in the current Open.
	 *		RequestedOplock = RequestedOplockLevel.
	 *		GrantingInAck = FALSE.
	 *
	 *	The operation MUST at this point return any status code
	 *	  returned by the shared oplock request algorithm.
	 */
	case READ_CACHING:
	case (READ_CACHING|HANDLE_CACHING):
		if (smb_lock_range_access(sr, node, 0, ~0, B_FALSE) != 0) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}
		/* XXX: Should be a flag on the ofile. */
		if (node->flags & NODE_FLAGS_WRITE_THROUGH) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}
		*statep = level;
		status = smb_oplock_req_shared(ofile, statep, B_FALSE);
		break;

	/*
	 * Else If RequestedOplockLevel is
	 * (READ_CACHING|WRITE_CACHING) or
	 * (READ_CACHING|WRITE_CACHING|HANDLE_CACHING):
	 * If Open.Mode contains either FILE_SYNCHRONOUS_IO_ALERT or
	 * FILE_SYNCHRONOUS_IO_NONALERT, the operation MUST be failed
	 * with STATUS_OPLOCK_NOT_GRANTED.
	 * Request an exclusive oplock according to the algorithm in
	 * section 2.1.5.17.1, setting the parameters as follows:
	 *	Pass in the current Open.
	 *	RequestedOplock = RequestedOplockLevel.
	 * The operation MUST at this point return any status code
	 * returned by the exclusive oplock request algorithm.
	 */
	case (READ_CACHING | WRITE_CACHING):
	case (READ_CACHING | WRITE_CACHING | HANDLE_CACHING):
		/* XXX: Should be a flag on the ofile. */
		if (node->flags & NODE_FLAGS_WRITE_THROUGH) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}
		*statep = level;
		status = smb_oplock_req_excl(ofile, statep);
		break;

	/*
	 * Else if RequestedOplockLevel is 0 (that is, no flags):
	 * The operation MUST return STATUS_SUCCESS at this point.
	 */
	case 0:
		*statep = 0;
		status = NT_STATUS_SUCCESS;
		break;

	/*
	 * Else
	 *  The operation MUST be failed with STATUS_INVALID_PARAMETER.
	 */
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	/* Give caller back the "Granular" bit. */
	if (status == NT_STATUS_SUCCESS)
		*statep |= LEVEL_GRANULAR;

out:
	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

	return (status);
}

/*
 * 2.1.5.17.1 Algorithm to Request an Exclusive Oplock
 *
 * The inputs for requesting an exclusive oplock are:
 *	Open: The Open on which the oplock is being requested.
 *	RequestedOplock: The oplock type being requested. One of:
 *	  LEVEL_ONE, LEVEL_BATCH, CACHE_RW, CACHE_RWH
 *
 * On completion, the object store MUST return:
 *	Status: An NTSTATUS code that specifies the result.
 *	NewOplockLevel: The type of oplock that the requested oplock has been
 *	  broken (reduced) to.  If a failure status is returned in Status,
 *	  the value of this field is undefined.  Valid values are as follows:
 *		LEVEL_NONE (that is, no oplock)
 *		LEVEL_TWO
 *		A combination of one or more of the following flags:
 *			READ_CACHING
 *			HANDLE_CACHING
 *			WRITE_CACHING
 *	AcknowledgeRequired: A Boolean value: TRUE if the server MUST
 *	acknowledge the oplock break; FALSE if not, as specified in
 *	section 2.1.5.18. If a failure status is returned in Status,
 *	the value of this field is undefined.
 *
 * Note: Stores NewOplockLevel in *rop
 */
static uint32_t
smb_oplock_req_excl(
    smb_ofile_t *ofile,		/* in: the "Open" */
    uint32_t *rop)		/* in: "RequestedOplock", out:NewOplockLevel */
{
	smb_node_t *node = ofile->f_node;
	smb_ofile_t *o;
	boolean_t GrantExcl = B_FALSE;
	uint32_t status = NT_STATUS_OPLOCK_NOT_GRANTED;

	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

	/*
	 * If Open.Stream.Oplock is empty:
	 *   Build a new Oplock object with fields initialized as follows:
	 *	Oplock.State set to NO_OPLOCK.
	 *	All other fields set to 0/empty.
	 *   Store the new Oplock object in Open.Stream.Oplock.
	 * EndIf
	 *
	 * Implementation specific:
	 * Open.Stream.Oplock maps to: node->n_oplock
	 */
	if (node->n_oplock.ol_state == 0) {
		node->n_oplock.ol_state = NO_OPLOCK;
	}

	/*
	 * If Open.Stream.Oplock.State contains
	 * LEVEL_TWO_OPLOCK or NO_OPLOCK: ...
	 *
	 * Per ms, this is the "If" matching the unbalalanced
	 * "Else If" below (for which we requested clarification).
	 */
	if ((node->n_oplock.ol_state & (LEVEL_TWO | NO_OPLOCK)) != 0) {

		/*
		 * If Open.Stream.Oplock.State contains LEVEL_TWO_OPLOCK and
		 * RequestedOplock contains one or more of READ_CACHING,
		 * HANDLE_CACHING, or WRITE_CACHING, the operation MUST be
		 * failed with Status set to STATUS_OPLOCK_NOT_GRANTED.
		 */
		if ((node->n_oplock.ol_state & LEVEL_TWO) != 0 &&
		    (*rop & CACHE_RWH) != 0) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}

		/*
		 * [ from dochelp@ms ]
		 *
		 * By this point if there is a level II oplock present,
		 * the caller can only be requesting an old-style oplock
		 * because we rejected enhanced oplock requests above.
		 * If the caller is requesting an old-style oplock our
		 * caller already verfied that there is only one handle
		 * open to this stream, and we've already verified that
		 * this request is for a legacy oplock, meaning that there
		 * can be at most one level II oplock (and no R oplocks),
		 * and the level II oplock belongs to this handle.  Clear
		 * the level II oplock and grant the exclusive oplock.
		 */

		/*
		 * If Open.Stream.Oplock.State is equal to LEVEL_TWO_OPLOCK:
		 * Remove the first Open ThisOpen from
		 *  Open.Stream.Oplock.IIOplocks (there is supposed to be
		 * exactly one present), and notify the server of an
		 * oplock break according to the algorithm in section
		 *  2.1.5.17.3, setting the algorithm's parameters as follows:
		 *	BreakingOplockOpen = ThisOpen.
		 *	NewOplockLevel = LEVEL_NONE.
		 *	AcknowledgeRequired = FALSE.
		 *	OplockCompletionStatus = STATUS_SUCCESS.
		 * (The operation does not end at this point; this call
		 *  to 2.1.5.17.3 completes some earlier call to 2.1.5.17.2.)
		 *
		 * Implementation specific:
		 *
		 * As explained above, the passed in ofile should be the
		 * only open file on this node.  Out of caution, we'll
		 * walk the ofile list as usual here, making sure there
		 * are no LevelII oplocks remaining, as those may not
		 * coexist with the exclusive oplock were're creating
		 * in this call.  Also, if the passed in ofile has a
		 * LevelII oplock, don't do an "ind break" up call on
		 * this ofile, as that would just cause an immediate
		 * "break to none" of the oplock we'll grant here.
		 * If there were other ofiles with LevelII oplocks,
		 * it would be appropriate to "ind break" those.
		 */
		if ((node->n_oplock.ol_state & LEVEL_TWO) != 0) {
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_II == 0)
					continue;
				o->f_oplock.onlist_II = B_FALSE;
				node->n_oplock.cnt_II--;
				ASSERT(node->n_oplock.cnt_II >= 0);
				if (o == ofile)
					continue;
				DTRACE_PROBE1(unexpected, smb_ofile_t, o);
				smb_oplock_ind_break(o,
				    LEVEL_NONE, B_FALSE,
				    NT_STATUS_SUCCESS);
			}
		}

		/*
		 * Note the spec. had an extra "EndIf" here.
		 * Confirmed by dochelp@ms
		 */

		/*
		 * If Open.File.OpenList contains more than one Open whose
		 * Stream is the same as Open.Stream, and NO_OPLOCK is present
		 * in Open.Stream.Oplock.State, the operation MUST be failed
		 * with Status set to STATUS_OPLOCK_NOT_GRANTED.
		 *
		 * Implementation specific:
		 * Allow other opens if they have the same lease ours,
		 * so we can upgrade RH to RWH (for example). Therefore
		 * only count opens with a different TargetOplockKey.
		 * Also ignore "attribute-only" opens.
		 */
		if ((node->n_oplock.ol_state & NO_OPLOCK) != 0) {
			FOREACH_NODE_OFILE(node, o) {
				if (!smb_ofile_is_open(o))
					continue;
				if ((o->f_granted_access & FILE_DATA_ALL) == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, 0)) {
					status = NT_STATUS_OPLOCK_NOT_GRANTED;
					goto out;
				}
			}
		}

		/*
		 * If Open.Stream.IsDeleted is TRUE and RequestedOplock
		 * contains HANDLE_CACHING, the operation MUST be failed
		 * with Status set to STATUS_OPLOCK_NOT_GRANTED.
		 */
		if (((node->flags & NODE_FLAGS_DELETING) != 0) &&
		    (*rop & HANDLE_CACHING) != 0) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}

		/* Set GrantExclusiveOplock to TRUE. */
		GrantExcl = B_TRUE;
	}

	/*
	 * "Else" If (Open.Stream.Oplock.State contains one or more of
	 * READ_CACHING, WRITE_CACHING, or HANDLE_CACHING) and
	 * (Open.Stream.Oplock.State contains none of (BREAK_ANY)) and
	 * (Open.Stream.Oplock.RHBreakQueue is empty):
	 */
	else if ((node->n_oplock.ol_state & CACHE_RWH) != 0 &&
	    (node->n_oplock.ol_state & BREAK_ANY) == 0 &&
	    node->n_oplock.cnt_RHBQ == 0) {

		/*
		 * This is a granular oplock and it is not breaking.
		 */

		/*
		 * If RequestedOplock contains none of READ_CACHING,
		 * WRITE_CACHING, or HANDLE_CACHING, the operation
		 * MUST be failed with Status set to
		 * STATUS_OPLOCK_NOT_GRANTED.
		 */
		if ((*rop & CACHE_RWH) == 0) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}

		/*
		 * If Open.Stream.IsDeleted (already checked above)
		 */

		/*
		 * Switch (Open.Stream.Oplock.State):
		 */
		switch (node->n_oplock.ol_state) {

		case CACHE_R:
			/*
			 * If RequestedOplock is neither
			 * (READ_CACHING|WRITE_CACHING) nor
			 * (READ_CACHING|WRITE_CACHING|HANDLE_CACHING),
			 * the operation MUST be failed with Status set
			 * to STATUS_OPLOCK_NOT_GRANTED.
			 */
			if (*rop != CACHE_RW && *rop != CACHE_RWH) {
				status = NT_STATUS_OPLOCK_NOT_GRANTED;
				goto out;
			}

			/*
			 * For each Open ThisOpen in
			 *  Open.Stream.Oplock.ROplocks:
			 *	If ThisOpen.TargetOplockKey !=
			 *	Open.TargetOplockKey, the operation
			 *	MUST be failed with Status set to
			 *	STATUS_OPLOCK_NOT_GRANTED.
			 * EndFor
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_R == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, 0)) {
					status = NT_STATUS_OPLOCK_NOT_GRANTED;
					goto out;
				}
			}

			/*
			 * For each Open o in Open.Stream.Oplock.ROplocks:
			 *	Remove o from Open.Stream.Oplock.ROplocks.
			 *	Notify the server of an oplock break
			 *	according to the algorithm in section
			 *	2.1.5.17.3, setting the algorithm's
			 *	parameters as follows:
			 *		BreakingOplockOpen = o.
			 *		NewOplockLevel = RequestedOplock.
			 *		AcknowledgeRequired = FALSE.
			 *		OplockCompletionStatus =
			 *		  STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE.
			 *	(The operation does not end at this point;
			 *	 this call to 2.1.5.17.3 completes some
			 *	 earlier call to 2.1.5.17.2.)
			 * EndFor
			 *
			 * Note: Upgrade to excl. on same lease.
			 * Won't send a break for this.
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_R == 0)
					continue;
				o->f_oplock.onlist_R = B_FALSE;
				node->n_oplock.cnt_R--;
				ASSERT(node->n_oplock.cnt_R >= 0);

				smb_oplock_ind_break(o, *rop,
				    B_FALSE, STATUS_NEW_HANDLE);
			}
			/*
			 * Set GrantExclusiveOplock to TRUE.
			 * EndCase // _R
			 */
			GrantExcl = B_TRUE;
			break;

		case CACHE_RH:
			/*
			 * If RequestedOplock is not
			 * (READ_CACHING|WRITE_CACHING|HANDLE_CACHING)
			 * or Open.Stream.Oplock.RHBreakQueue is not empty,
			 * the operation MUST be failed with Status set to
			 * STATUS_OPLOCK_NOT_GRANTED.
			 * Note: Have RHBreakQueue==0 from above.
			 */
			if (*rop != CACHE_RWH) {
				status = NT_STATUS_OPLOCK_NOT_GRANTED;
				goto out;
			}

			/*
			 * For each Open ThisOpen in
			 *  Open.Stream.Oplock.RHOplocks:
			 *	If ThisOpen.TargetOplockKey !=
			 *	Open.TargetOplockKey, the operation
			 *	MUST be failed with Status set to
			 *	STATUS_OPLOCK_NOT_GRANTED.
			 * EndFor
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RH == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, 0)) {
					status = NT_STATUS_OPLOCK_NOT_GRANTED;
					goto out;
				}
			}

			/*
			 * For each Open o in Open.Stream.Oplock.RHOplocks:
			 *	Remove o from Open.Stream.Oplock.RHOplocks.
			 *	Notify the server of an oplock break
			 *	according to the algorithm in section
			 *	2.1.5.17.3, setting the algorithm's
			 *	parameters as follows:
			 *		BreakingOplockOpen = o.
			 *		NewOplockLevel = RequestedOplock.
			 *		AcknowledgeRequired = FALSE.
			 *		OplockCompletionStatus =
			 *		  STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE.
			 *	(The operation does not end at this point;
			 *	 this call to 2.1.5.17.3 completes some
			 *	 earlier call to 2.1.5.17.2.)
			 * EndFor
			 *
			 * Note: Upgrade to excl. on same lease.
			 * Won't send a break for this.
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RH == 0)
					continue;
				o->f_oplock.onlist_RH = B_FALSE;
				node->n_oplock.cnt_RH--;
				ASSERT(node->n_oplock.cnt_RH >= 0);

				smb_oplock_ind_break(o, *rop,
				    B_FALSE, STATUS_NEW_HANDLE);
			}
			/*
			 * Set GrantExclusiveOplock to TRUE.
			 * EndCase // _RH
			 */
			GrantExcl = B_TRUE;
			break;

		case (CACHE_RWH | EXCLUSIVE):
			/*
			 * If RequestedOplock is not
			 * (READ_CACHING|WRITE_CACHING|HANDLE_CACHING),
			 * the operation MUST be failed with Status set to
			 * STATUS_OPLOCK_NOT_GRANTED.
			 */
			if (*rop != CACHE_RWH) {
				status = NT_STATUS_OPLOCK_NOT_GRANTED;
				goto out;
			}
			/* Deliberate FALL-THROUGH to next Case statement. */
			/* FALLTHROUGH */

		case (CACHE_RW | EXCLUSIVE):
			/*
			 * If RequestedOplock is neither
			 * (READ_CACHING|WRITE_CACHING|HANDLE_CACHING) nor
			 * (READ_CACHING|WRITE_CACHING), the operation MUST be
			 * failed with Status set to STATUS_OPLOCK_NOT_GRANTED.
			 */
			if (*rop != CACHE_RWH && *rop != CACHE_RW) {
				status = NT_STATUS_OPLOCK_NOT_GRANTED;
				goto out;
			}

			o = node->n_oplock.excl_open;
			if (o == NULL) {
				ASSERT(0);
				GrantExcl = B_TRUE;
				break;
			}

			/*
			 * If Open.TargetOplockKey !=
			 * Open.Stream.Oplock.ExclusiveOpen.TargetOplockKey,
			 * the operation MUST be failed with Status set to
			 * STATUS_OPLOCK_NOT_GRANTED.
			 */
			if (!CompareOplockKeys(ofile, o, 0)) {
				status = NT_STATUS_OPLOCK_NOT_GRANTED;
				goto out;
			}

			/*
			 * Notify the server of an oplock break according to
			 * the algorithm in section 2.1.5.17.3, setting the
			 * algorithm's parameters as follows:
			 *	BreakingOplockOpen =
			 *	  Open.Stream.Oplock.ExclusiveOpen.
			 *	NewOplockLevel = RequestedOplock.
			 *	AcknowledgeRequired = FALSE.
			 *	OplockCompletionStatus =
			 *	  STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE.
			 * (The operation does not end at this point;
			 *  this call to 2.1.5.17.3 completes some
			 *  earlier call to 2.1.5.17.1.)
			 *
			 * Set Open.Stream.Oplock.ExclusiveOpen to NULL.
			 * Set GrantExclusiveOplock to TRUE.
			 *
			 * Note: We will keep this exclusive oplock,
			 * but move it to a new handle on this lease.
			 * Won't send a break for this.
			 */
			smb_oplock_ind_break(o, *rop,
			    B_FALSE, STATUS_NEW_HANDLE);
			node->n_oplock.excl_open = o = NULL;
			GrantExcl = B_TRUE;
			break;

		default:
			/*
			 * The operation MUST be failed with Status set to
			 * STATUS_OPLOCK_NOT_GRANTED.
			 */
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;

		} /* switch n_oplock.ol_state */
	} /* EndIf CACHE_RWH & !BREAK_ANY... */
	else {
		/*
		 * The operation MUST be failed with...
		 */
		status = NT_STATUS_OPLOCK_NOT_GRANTED;
		goto out;
	}

	/*
	 * If GrantExclusiveOplock is TRUE:
	 *
	 * Set Open.Stream.Oplock.ExclusiveOpen = Open.
	 * Set Open.Stream.Oplock.State =
	 *   (RequestedOplock|EXCLUSIVE).
	 */
	if (GrantExcl) {
		node->n_oplock.excl_open = ofile;
		node->n_oplock.ol_state = *rop | EXCLUSIVE;

		/*
		 * This operation MUST be made cancelable...
		 * This operation waits until the oplock is
		 * broken or canceled, as specified in
		 * section 2.1.5.17.3.
		 *
		 * When the operation specified in section
		 * 2.1.5.17.3 is called, its following input
		 * parameters are transferred to this routine
		 * and then returned by it:
		 *
		 * Status is set to OplockCompletionStatus
		 * NewOplockLevel, AcknowledgeRequired...
		 * from the operation specified in
		 * section 2.1.5.17.3.
		 */
		/* Keep *rop = ... from caller. */
		if ((node->n_oplock.ol_state & BREAK_ANY) != 0) {
			status = NT_STATUS_OPLOCK_BREAK_IN_PROGRESS;
			/* Caller does smb_oplock_wait_break() */
		} else {
			status = NT_STATUS_SUCCESS;
		}
	}

out:
	if (status == NT_STATUS_OPLOCK_NOT_GRANTED)
		*rop = LEVEL_NONE;

	return (status);
}

/*
 * 2.1.5.17.2 Algorithm to Request a Shared Oplock
 *
 * The inputs for requesting a shared oplock are:
 *	Open: The Open on which the oplock is being requested.
 *	RequestedOplock: The oplock type being requested.
 *	GrantingInAck: A Boolean value, TRUE if this oplock is being
 *	  requested as part of an oplock break acknowledgement,
 *	  FALSE if not.
 *
 * On completion, the object store MUST return:
 *	Status: An NTSTATUS code that specifies the result.
 *	NewOplockLevel: The type of oplock that the requested oplock has been
 *	  broken (reduced) to.  If a failure status is returned in Status,
 *	  the value of this field is undefined.  Valid values are as follows:
 *		LEVEL_NONE (that is, no oplock)
 *		LEVEL_TWO
 *		A combination of one or more of the following flags:
 *			READ_CACHING
 *			HANDLE_CACHING
 *			WRITE_CACHING
 *	AcknowledgeRequired: A Boolean value: TRUE if the server MUST
 *	acknowledge the oplock break; FALSE if not, as specified in
 *	section 2.1.5.18. If a failure status is returned in Status,
 *	the value of this field is undefined.
 *
 * Note: Stores NewOplockLevel in *rop
 */
static uint32_t
smb_oplock_req_shared(
    smb_ofile_t *ofile,		/* in: the "Open" */
    uint32_t *rop,		/* in: "RequestedOplock", out:NewOplockLevel */
    boolean_t GrantingInAck)
{
	smb_node_t *node = ofile->f_node;
	smb_ofile_t *o;
	boolean_t OplockGranted = B_FALSE;
	uint32_t status = NT_STATUS_OPLOCK_NOT_GRANTED;

	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

	/*
	 * If Open.Stream.Oplock is empty:
	 *   Build a new Oplock object with fields initialized as follows:
	 *	Oplock.State set to NO_OPLOCK.
	 *	All other fields set to 0/empty.
	 *   Store the new Oplock object in Open.Stream.Oplock.
	 * EndIf
	 *
	 * Implementation specific:
	 * Open.Stream.Oplock maps to: node->n_oplock
	 */
	if (node->n_oplock.ol_state == 0) {
		node->n_oplock.ol_state = NO_OPLOCK;
	}

	/*
	 * If (GrantingInAck is FALSE) and (Open.Stream.Oplock.State
	 * contains one or more of BREAK_TO_TWO, BREAK_TO_NONE,
	 * BREAK_TO_TWO_TO_NONE, BREAK_TO_READ_CACHING,
	 * BREAK_TO_WRITE_CACHING, BREAK_TO_HANDLE_CACHING,
	 * BREAK_TO_NO_CACHING, or EXCLUSIVE), then:
	 *	The operation MUST be failed with Status set to
	 *	STATUS_OPLOCK_NOT_GRANTED.
	 * EndIf
	 */
	if (GrantingInAck == B_FALSE &&
	    (node->n_oplock.ol_state & (BREAK_ANY | EXCLUSIVE)) != 0) {
		status = NT_STATUS_OPLOCK_NOT_GRANTED;
		goto out;
	}

	/* Switch (RequestedOplock): */
	switch (*rop) {

	case LEVEL_TWO:
		/*
		 * The operation MUST be failed with Status set to
		 * STATUS_OPLOCK_NOT_GRANTED if Open.Stream.Oplock.State
		 * is anything other than the following:
		 *	NO_OPLOCK
		 *	LEVEL_TWO_OPLOCK
		 *	READ_CACHING
		 *	(LEVEL_TWO_OPLOCK|READ_CACHING)
		 */
		switch (node->n_oplock.ol_state) {
		default:
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		case NO_OPLOCK:
		case LEVEL_TWO:
		case READ_CACHING:
		case (LEVEL_TWO | READ_CACHING):
			break;
		}
		/* Deliberate FALL-THROUGH to next Case statement. */
		/* FALLTHROUGH */

	case READ_CACHING:
		/*
		 * The operation MUST be failed with Status set to
		 * STATUS_OPLOCK_NOT_GRANTED if GrantingInAck is FALSE
		 * and Open.Stream.Oplock.State is anything other than...
		 */
		switch (node->n_oplock.ol_state) {
		default:
			if (GrantingInAck == B_FALSE) {
				status = NT_STATUS_OPLOCK_NOT_GRANTED;
				goto out;
			}
			break;
		case NO_OPLOCK:
		case LEVEL_TWO:
		case READ_CACHING:
		case (LEVEL_TWO | READ_CACHING):
		case (READ_CACHING | HANDLE_CACHING):
		case (READ_CACHING | HANDLE_CACHING | MIXED_R_AND_RH):
		case (READ_CACHING | HANDLE_CACHING | BREAK_TO_READ_CACHING):
		case (READ_CACHING | HANDLE_CACHING | BREAK_TO_NO_CACHING):
			break;
		}

		if (GrantingInAck == B_FALSE) {
			/*
			 * If there is an Open on
			 * Open.Stream.Oplock.RHOplocks
			 * whose TargetOplockKey is equal to
			 * Open.TargetOplockKey, the operation
			 * MUST be failed with Status set to
			 * STATUS_OPLOCK_NOT_GRANTED.
			 *
			 * If there is an Open on
			 * Open.Stream.Oplock.RHBreakQueue
			 * whose TargetOplockKey is equal to
			 * Open.TargetOplockKey, the operation
			 * MUST be failed with Status set to
			 * STATUS_OPLOCK_NOT_GRANTED.
			 *
			 * Implement both in one list walk.
			 */
			FOREACH_NODE_OFILE(node, o) {
				if ((o->f_oplock.onlist_RH ||
				    o->f_oplock.onlist_RHBQ) &&
				    CompareOplockKeys(ofile, o, 0)) {
					status = NT_STATUS_OPLOCK_NOT_GRANTED;
					goto out;
				}
			}

			/*
			 * If there is an Open ThisOpen on
			 * Open.Stream.Oplock.ROplocks whose
			 * TargetOplockKey is equal to Open.TargetOplockKey
			 * (there is supposed to be at most one present):
			 *	* Remove ThisOpen from Open...ROplocks.
			 *	* Notify the server of an oplock break
			 *	  according to the algorithm in section
			 *	  2.1.5.17.3, setting the algorithm's
			 *	  parameters as follows:
			 *		* BreakingOplockOpen = ThisOpen
			 *		* NewOplockLevel = READ_CACHING
			 *		* AcknowledgeRequired = FALSE
			 *		* OplockCompletionStatus =
			 *		  STATUS_..._NEW_HANDLE
			 * (The operation does not end at this point;
			 *  this call to 2.1.5.17.3 completes some
			 *  earlier call to 2.1.5.17.2.)
			 * EndIf
			 *
			 * If this SMB2 lease already has an "R" handle,
			 * we'll update that lease locally to point to
			 * this new handle.
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_R == 0)
					continue;
				if (CompareOplockKeys(ofile, o, 0)) {
					o->f_oplock.onlist_R = B_FALSE;
					node->n_oplock.cnt_R--;
					ASSERT(node->n_oplock.cnt_R >= 0);
					smb_oplock_ind_break(o,
					    CACHE_R, B_FALSE,
					    STATUS_NEW_HANDLE);
				}
			}
		} /* EndIf !GrantingInAck */

		/*
		 * If RequestedOplock equals LEVEL_TWO:
		 *	Add Open to Open.Stream.Oplock.IIOplocks.
		 * Else // RequestedOplock equals READ_CACHING:
		 *	Add Open to Open.Stream.Oplock.ROplocks.
		 * EndIf
		 */
		if (*rop == LEVEL_TWO) {
			ofile->f_oplock.onlist_II = B_TRUE;
			node->n_oplock.cnt_II++;
		} else {
			/* (*rop == READ_CACHING) */
			if (ofile->f_oplock.onlist_R == B_FALSE) {
				ofile->f_oplock.onlist_R = B_TRUE;
				node->n_oplock.cnt_R++;
			}
		}

		/*
		 * Recompute Open.Stream.Oplock.State according to the
		 * algorithm in section 2.1.4.13, passing Open.Stream.Oplock
		 * as the ThisOplock parameter.
		 * Set OplockGranted to TRUE.
		 */
		RecomputeOplockState(node);
		OplockGranted = B_TRUE;
		break;

	case (READ_CACHING|HANDLE_CACHING):
		/*
		 * The operation MUST be failed with Status set to
		 * STATUS_OPLOCK_NOT_GRANTED if GrantingInAck is FALSE
		 * and Open.Stream.Oplock.State is anything other than...
		 */
		switch (node->n_oplock.ol_state) {
		default:
			if (GrantingInAck == B_FALSE) {
				status = NT_STATUS_OPLOCK_NOT_GRANTED;
				goto out;
			}
			break;
		case NO_OPLOCK:
		case READ_CACHING:
		case (READ_CACHING | HANDLE_CACHING):
		case (READ_CACHING | HANDLE_CACHING | MIXED_R_AND_RH):
		case (READ_CACHING | HANDLE_CACHING | BREAK_TO_READ_CACHING):
		case (READ_CACHING | HANDLE_CACHING | BREAK_TO_NO_CACHING):
			break;
		}

		/*
		 * If Open.Stream.IsDeleted is TRUE, the operation MUST be
		 *  failed with Status set to STATUS_OPLOCK_NOT_GRANTED.
		 */
		if ((node->flags & NODE_FLAGS_DELETING) != 0) {
			status = NT_STATUS_OPLOCK_NOT_GRANTED;
			goto out;
		}

		if (GrantingInAck == B_FALSE) {
			/*
			 * If there is an Open ThisOpen on
			 * Open.Stream.Oplock.ROplocks whose
			 * TargetOplockKey is equal to Open.TargetOplockKey
			 * (there is supposed to be at most one present):
			 *	* Remove ThisOpen from Open...ROplocks.
			 *	* Notify the server of an oplock break
			 *	  according to the algorithm in section
			 *	  2.1.5.17.3, setting the algorithm's
			 *	  parameters as follows:
			 *		* BreakingOplockOpen = ThisOpen
			 *		* NewOplockLevel = CACHE_RH
			 *		* AcknowledgeRequired = FALSE
			 *		* OplockCompletionStatus =
			 *		  STATUS_..._NEW_HANDLE
			 * (The operation does not end at this point;
			 *  this call to 2.1.5.17.3 completes some
			 *  earlier call to 2.1.5.17.2.)
			 * EndIf
			 *
			 * If this SMB2 lease already has an "R" handle,
			 * we'll update that lease locally to point to
			 * this new handle (upgrade to "RH").
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_R == 0)
					continue;
				if (CompareOplockKeys(ofile, o, 0)) {
					o->f_oplock.onlist_R = B_FALSE;
					node->n_oplock.cnt_R--;
					ASSERT(node->n_oplock.cnt_R >= 0);
					smb_oplock_ind_break(o,
					    CACHE_RH, B_FALSE,
					    STATUS_NEW_HANDLE);
				}
			}

			/*
			 * If there is an Open ThisOpen on
			 * Open.Stream.Oplock.RHOplocks whose
			 * TargetOplockKey is equal to Open.TargetOplockKey
			 * (there is supposed to be at most one present):
			 *	XXX: Note, the spec. was missing a step:
			 *	XXX: Remove the open from RHOplocks
			 *	XXX: Confirm with MS dochelp
			 *	* Notify the server of an oplock break
			 *	  according to the algorithm in section
			 *	  2.1.5.17.3, setting the algorithm's
			 *	  parameters as follows:
			 *		* BreakingOplockOpen = ThisOpen
			 *		* NewOplockLevel =
			 *		  (READ_CACHING|HANDLE_CACHING)
			 *		* AcknowledgeRequired = FALSE
			 *		* OplockCompletionStatus =
			 *		  STATUS_..._NEW_HANDLE
			 * (The operation does not end at this point;
			 *  this call to 2.1.5.17.3 completes some
			 *  earlier call to 2.1.5.17.2.)
			 * EndIf
			 *
			 * If this SMB2 lease already has an "RH" handle,
			 * we'll update that lease locally to point to
			 * this new handle.
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RH == 0)
					continue;
				if (CompareOplockKeys(ofile, o, 0)) {
					o->f_oplock.onlist_RH = B_FALSE;
					node->n_oplock.cnt_RH--;
					ASSERT(node->n_oplock.cnt_RH >= 0);
					smb_oplock_ind_break(o,
					    CACHE_RH, B_FALSE,
					    STATUS_NEW_HANDLE);
				}
			}
		} /* EndIf !GrantingInAck */

		/*
		 * Add Open to Open.Stream.Oplock.RHOplocks.
		 */
		if (ofile->f_oplock.onlist_RH == B_FALSE) {
			ofile->f_oplock.onlist_RH = B_TRUE;
			node->n_oplock.cnt_RH++;
		}

		/*
		 * Recompute Open.Stream.Oplock.State according to the
		 * algorithm in section 2.1.4.13, passing Open.Stream.Oplock
		 * as the ThisOplock parameter.
		 * Set OplockGranted to TRUE.
		 */
		RecomputeOplockState(node);
		OplockGranted = B_TRUE;
		break;

	default:
		/* No other value of RequestedOplock is possible. */
		ASSERT(0);
		status = NT_STATUS_OPLOCK_NOT_GRANTED;
		goto out;
	}  /* EndSwitch (RequestedOplock) */

	/*
	 * If OplockGranted is TRUE:
	 * This operation MUST be made cancelable by inserting it into
	 *   CancelableOperations.CancelableOperationList.
	 * The operation waits until the oplock is broken or canceled,
	 * as specified in section 2.1.5.17.3.
	 * When the operation specified in section 2.1.5.17.3 is called,
	 * its following input parameters are transferred to this routine
	 * and returned by it:
	 *	Status is set to OplockCompletionStatus from the
	 *	  operation specified in section 2.1.5.17.3.
	 *	NewOplockLevel is set to NewOplockLevel from the
	 *	  operation specified in section 2.1.5.17.3.
	 *	AcknowledgeRequired is set to AcknowledgeRequired from
	 *	  the operation specified in section 2.1.5.17.3.
	 * EndIf
	 */
	if (OplockGranted) {
		/* Note: *rop already set. */
		if ((node->n_oplock.ol_state & BREAK_ANY) != 0) {
			status = NT_STATUS_OPLOCK_BREAK_IN_PROGRESS;
			/* Caller does smb_oplock_wait_break() */
		} else {
			status = NT_STATUS_SUCCESS;
		}
	}

out:
	if (status == NT_STATUS_OPLOCK_NOT_GRANTED)
		*rop = LEVEL_NONE;

	return (status);
}

/*
 * 2.1.5.17.3 Indicating an Oplock Break to the Server
 * See smb_srv_oplock.c
 */

/*
 * 2.1.5.18 Server Acknowledges an Oplock Break
 *
 * The server provides:
 *	Open - The Open associated with the oplock that has broken.
 *	Type - As part of the acknowledgement, the server indicates a
 *	  new oplock it would like in place of the one that has broken.
 *	  Valid values are as follows:
 *		LEVEL_NONE
 *		LEVEL_TWO
 *		LEVEL_GRANULAR - If this oplock type is specified,
 *		  the server additionally provides:
 *	RequestedOplockLevel - A combination of zero or more of
 *	  the following flags:
 *		READ_CACHING
 *		HANDLE_CACHING
 *		WRITE_CACHING
 *
 * If the server requests a new oplock and it is granted, the request
 * does not complete until the oplock is broken; the operation waits for
 * this to happen. Processing of an oplock break is described in
 * section 2.1.5.17.3.  Whether the new oplock is granted or not, the
 * object store MUST return:
 *
 *	Status - An NTSTATUS code indicating the result of the operation.
 *
 * If the server requests a new oplock and it is granted, then when the
 * oplock breaks and the request finally completes, the object store MUST
 * additionally return:
 *	NewOplockLevel: The type of oplock the requested oplock has
 *	  been broken to. Valid values are as follows:
 *		LEVEL_NONE (that is, no oplock)
 *		LEVEL_TWO
 *		A combination of one or more of the following flags:
 *			READ_CACHING
 *			HANDLE_CACHING
 *			WRITE_CACHING
 *	AcknowledgeRequired: A Boolean value; TRUE if the server MUST
 *	  acknowledge the oplock break, FALSE if not, as specified in
 *	  section 2.1.5.17.2.
 *
 * Note: Stores NewOplockLevel in *rop
 */
uint32_t
smb_oplock_ack_break(
    smb_request_t *sr,
    smb_ofile_t *ofile,
    uint32_t *rop)
{
	smb_node_t *node = ofile->f_node;
	uint32_t type = *rop & OPLOCK_LEVEL_TYPE_MASK;
	uint32_t level = *rop & OPLOCK_LEVEL_CACHE_MASK;
	uint32_t status = NT_STATUS_SUCCESS;
	uint32_t BreakToLevel;
	boolean_t NewOplockGranted = B_FALSE;
	boolean_t ReturnBreakToNone = B_FALSE;
	boolean_t FoundMatchingRHOplock = B_FALSE;
	int other_keys;

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	/*
	 * If Open.Stream.Oplock is empty, the operation MUST be
	 * failed with Status set to STATUS_INVALID_OPLOCK_PROTOCOL.
	 */
	if (node->n_oplock.ol_state == 0) {
		status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		goto out;
	}

	if (type == LEVEL_NONE || type == LEVEL_TWO) {
		/*
		 * If Open.Stream.Oplock.ExclusiveOpen is not equal to Open,
		 * the operation MUST be failed with Status set to
		 * STATUS_INVALID_OPLOCK_PROTOCOL.
		 */
		if (node->n_oplock.excl_open != ofile) {
			status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
			goto out;
		}

		/*
		 * If Type is LEVEL_TWO and Open.Stream.Oplock.State
		 * contains BREAK_TO_TWO:
		 *	Set Open.Stream.Oplock.State to LEVEL_TWO_OPLOCK.
		 *	Set NewOplockGranted to TRUE.
		 */
		if (type == LEVEL_TWO &&
		    (node->n_oplock.ol_state & BREAK_TO_TWO) != 0) {
			node->n_oplock.ol_state = LEVEL_TWO;
			NewOplockGranted = B_TRUE;
		}

		/*
		 * Else If Open.Stream.Oplock.State contains
		 * BREAK_TO_TWO or BREAK_TO_NONE:
		 *	Set Open.Stream.Oplock.State to NO_OPLOCK.
		 */
		else if ((node->n_oplock.ol_state &
		    (BREAK_TO_TWO | BREAK_TO_NONE)) != 0) {
			node->n_oplock.ol_state = NO_OPLOCK;
		}

		/*
		 * Else If Open.Stream.Oplock.State contains
		 * BREAK_TO_TWO_TO_NONE:
		 *	Set Open.Stream.Oplock.State to NO_OPLOCK.
		 *	Set ReturnBreakToNone to TRUE.
		 */
		else if ((node->n_oplock.ol_state &
		    BREAK_TO_TWO_TO_NONE) != 0) {
			node->n_oplock.ol_state = NO_OPLOCK;
			ReturnBreakToNone = B_TRUE;
		}

		/*
		 * Else
		 *	The operation MUST be failed with Status set to
		 *	STATUS_INVALID_OPLOCK_PROTOCOL.
		 */
		else {
			status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
			goto out;
		}

		/*
		 * For each Open WaitingOpen on Open.Stream.Oplock.WaitList:
		 *	Indicate that the operation associated with
		 *	  WaitingOpen can continue according to the
		 *	  algorithm in section 2.1.4.12.1, setting
		 *	  OpenToRelease = WaitingOpen.
		 *	Remove WaitingOpen from Open.Stream.Oplock.WaitList.
		 * EndFor
		 */
		if (node->n_oplock.waiters)
			cv_broadcast(&node->n_oplock.WaitingOpenCV);

		/*
		 * Set Open.Stream.Oplock.ExclusiveOpen to NULL.
		 */
		node->n_oplock.excl_open = NULL;

		if (NewOplockGranted) {
			/*
			 * The operation waits until the newly-granted
			 * Level 2 oplock is broken, as specified in
			 * section 2.1.5.17.3.
			 *
			 * Here we have just Ack'ed a break-to-II
			 * so now get the level II oplock.  We also
			 * checked for break-to-none above, so this
			 * will not need to wait for oplock breaks.
			 */
			status = smb_oplock_req_shared(ofile, rop, B_TRUE);
		}

		else if (ReturnBreakToNone) {
			/*
			 * In this case the server was expecting the oplock
			 * to break to Level 2, but because the oplock is
			 * actually breaking to None (that is, no oplock),
			 * the object store MUST indicate an oplock break
			 * to the server according to the algorithm in
			 * section 2.1.5.17.3, setting the algorithm's
			 * parameters as follows:
			 *	BreakingOplockOpen = Open.
			 *	NewOplockLevel = LEVEL_NONE.
			 *	AcknowledgeRequired = FALSE.
			 *	OplockCompletionStatus = STATUS_SUCCESS.
			 * (Because BreakingOplockOpen is equal to the
			 * passed-in Open, the operation ends at this point.)
			 *
			 * It should be OK to return the reduced oplock
			 * (*rop = LEVEL_NONE) here and avoid the need
			 * to send another oplock break.  This is safe
			 * because we already have an Ack of the break
			 * to Level_II, and the additional break to none
			 * would use AckRequired = FALSE.
			 *
			 * If we followed the spec here, we'd have:
			 * smb_oplock_ind_break(ofile,
			 *    LEVEL_NONE, B_FALSE,
			 *    NT_STATUS_SUCCESS);
			 * (Or smb_oplock_ind_break_in_ack...)
			 */
			*rop = LEVEL_NONE;	/* Reduced from L2 */
		}
		status = NT_STATUS_SUCCESS;
		goto out;
	} /* LEVEL_NONE or LEVEL_TWO */

	if (type != LEVEL_GRANULAR) {
		status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		goto out;
	}

	/* LEVEL_GRANULAR */

	/*
	 * Let BREAK_LEVEL_MASK = (BREAK_TO_READ_CACHING |
	 *   BREAK_TO_WRITE_CACHING | BREAK_TO_HANDLE_CACHING |
	 *   BREAK_TO_NO_CACHING),
	 * R_AND_RH_GRANTED = (READ_CACHING | HANDLE_CACHING |
	 *   MIXED_R_AND_RH),
	 * RH_GRANTED = (READ_CACHING | HANDLE_CACHING)
	 *
	 * (See BREAK_LEVEL_MASK in smb_oplock.h)
	 */
#define	RH_GRANTED		(READ_CACHING|HANDLE_CACHING)
#define	R_AND_RH_GRANTED	(RH_GRANTED|MIXED_R_AND_RH)

	/*
	 * If there are no BREAK_LEVEL_MASK flags set, this is invalid,
	 * unless the state is R_AND_RH_GRANTED or RH_GRANTED, in which
	 * case we'll need to see if the RHBreakQueue is empty.
	 */

	/*
	 * If (Open.Stream.Oplock.State does not contain any flag in
	 * BREAK_LEVEL_MASK and
	 *  (Open.Stream.Oplock.State != R_AND_RH_GRANTED) and
	 *   (Open.Stream.Oplock.State != RH_GRANTED)) or
	 *   (((Open.Stream.Oplock.State == R_AND_RH_GRANTED) or
	 *  (Open.Stream.Oplock.State == RH_GRANTED)) and
	 *   Open.Stream.Oplock.RHBreakQueue is empty):
	 *	The request MUST be failed with Status set to
	 *	  STATUS_INVALID_OPLOCK_PROTOCOL.
	 * EndIf
	 */
	if ((node->n_oplock.ol_state & BREAK_LEVEL_MASK) == 0) {
		if ((node->n_oplock.ol_state != R_AND_RH_GRANTED) &&
		    (node->n_oplock.ol_state != RH_GRANTED)) {
			status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
			goto out;
		}
		/* State is R_AND_RH_GRANTED or RH_GRANTED */
		if (node->n_oplock.cnt_RHBQ == 0) {
			status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
			goto out;
		}
	}

	/*
	 * Compute the "Break To" cache level from the
	 * BREAK_TO_... flags
	 */
	switch (node->n_oplock.ol_state & BREAK_LEVEL_MASK) {
	case (BREAK_TO_READ_CACHING | BREAK_TO_WRITE_CACHING |
	    BREAK_TO_HANDLE_CACHING):
		BreakToLevel = CACHE_RWH;
		break;
	case (BREAK_TO_READ_CACHING | BREAK_TO_WRITE_CACHING):
		BreakToLevel = CACHE_RW;
		break;
	case (BREAK_TO_READ_CACHING | BREAK_TO_HANDLE_CACHING):
		BreakToLevel = CACHE_RH;
		break;
	case BREAK_TO_READ_CACHING:
		BreakToLevel = READ_CACHING;
		break;
	case BREAK_TO_NO_CACHING:
	default:
		BreakToLevel = LEVEL_NONE;
		break;
	}

	/* Switch Open.Stream.Oplock.State */
	switch (node->n_oplock.ol_state) {

	case (READ_CACHING|HANDLE_CACHING|MIXED_R_AND_RH):
	case (READ_CACHING|HANDLE_CACHING):
	case (READ_CACHING|HANDLE_CACHING|BREAK_TO_READ_CACHING):
	case (READ_CACHING|HANDLE_CACHING|BREAK_TO_NO_CACHING):
		/*
		 * For each RHOpContext ThisContext in
		 * Open.Stream.Oplock.RHBreakQueue:
		 *	If ThisContext.Open equals Open:
		 *		(see below)
		 *
		 * Implementation skips the list walk, because
		 * we can get the ofile directly.
		 */
		if (ofile->f_oplock.onlist_RHBQ) {
			smb_ofile_t *o;

			/*
			 * Set FoundMatchingRHOplock to TRUE.
			 * If ThisContext.BreakingToRead is FALSE:
			 *	If RequestedOplockLevel is not 0 and
			 *	Open.Stream.Oplock.WaitList is not empty:
			 *	    The object store MUST indicate an
			 *	    oplock break to the server according to
			 *	    the algorithm in section 2.1.5.17.3,
			 *	    setting the algorithm's params as follows:
			 *		BreakingOplockOpen = Open.
			 *		NewOplockLevel = LEVEL_NONE.
			 *		AcknowledgeRequired = TRUE.
			 *		OplockCompletionStatus =
			 *		  STATUS_CANNOT_GRANT_...
			 *  (Because BreakingOplockOpen is equal to the
			 *   passed Open, the operation ends at this point.)
			 * EndIf
			 */
			FoundMatchingRHOplock = B_TRUE;
			if (ofile->f_oplock.BreakingToRead == B_FALSE) {
				if (level != 0 && node->n_oplock.waiters) {
					/* The ofile stays on RHBQ */
					smb_oplock_ind_break_in_ack(
					    sr, ofile,
					    LEVEL_NONE, B_TRUE);
					status = NT_STATUS_SUCCESS;
					goto out;
				}
			}

			/*
			 * Else // ThisContext.BreakingToRead is TRUE.
			 *    If Open.Stream.Oplock.WaitList is not empty and
			 *    (RequestedOplockLevel is CACHE_RW or CACHE_RWH:
			 *	The object store MUST indicate an oplock
			 *	break to the server according to the
			 *	algorithm in section 2.1.5.17.3, setting
			 *	the algorithm's parameters as follows:
			 *		* BreakingOplockOpen = Open
			 *		* NewOplockLevel = READ_CACHING
			 *		* AcknowledgeRequired = TRUE
			 *		* OplockCompletionStatus =
			 *		  STATUS_CANNOT_GRANT...
			 *	(Because BreakingOplockOpen is equal to the
			 *	 passed-in Open, the operation ends at this
			 *	 point.)
			 *    EndIf
			 * EndIf
			 */
			else { /* BreakingToRead is TRUE */
				if (node->n_oplock.waiters &&
				    (level == CACHE_RW ||
				    level == CACHE_RWH)) {
					/* The ofile stays on RHBQ */
					smb_oplock_ind_break_in_ack(
					    sr, ofile,
					    CACHE_R, B_TRUE);
					status = NT_STATUS_SUCCESS;
					goto out;
				}
			}

			/*
			 * Remove ThisContext from Open...RHBreakQueue.
			 */
			ofile->f_oplock.onlist_RHBQ = B_FALSE;
			node->n_oplock.cnt_RHBQ--;
			ASSERT(node->n_oplock.cnt_RHBQ >= 0);

			/*
			 * The operation waiting for the Read-Handle
			 * oplock to break can continue if there are
			 * no more Read-Handle oplocks outstanding, or
			 * if all the remaining Read-Handle oplocks
			 * have the same oplock key as the waiting
			 * operation.
			 *
			 * For each Open WaitingOpen on Open...WaitList:
			 *
			 *	* If (Open...RHBreakQueue is empty) or
			 *	  (all RHOpContext.Open.TargetOplockKey values
			 *	  on Open.Stream.Oplock.RHBreakQueue are
			 *	  equal to WaitingOpen.TargetOplockKey):
			 *		* Indicate that the operation assoc.
			 *		  with WaitingOpen can continue
			 *		  according to the algorithm in
			 *		  section 2.1.4.12.1, setting
			 *		  OpenToRelease = WaitingOpen.
			 *		* Remove WaitingOpen from
			 *		  Open.Stream.Oplock.WaitList.
			 *	* EndIf
			 * EndFor
			 */
			other_keys = 0;
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RHBQ == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, 0))
					other_keys++;
			}
			if (other_keys == 0)
				cv_broadcast(&node->n_oplock.WaitingOpenCV);

			/*
			 * If RequestedOplockLevel is 0 (that is, no flags):
			 *	* Recompute Open.Stream.Oplock.State
			 *	  according to the algorithm in section
			 *	  2.1.4.13, passing Open.Stream.Oplock as
			 *	  the ThisOplock parameter.
			 *	* The algorithm MUST return Status set to
			 *	  STATUS_SUCCESS at this point.
			 */
			if (level == 0) {
				RecomputeOplockState(node);
				status = NT_STATUS_SUCCESS;
				goto out;
			}

			/*
			 * Else If RequestedOplockLevel does not contain
			 * WRITE_CACHING:
			 *	* The object store MUST request a shared oplock
			 *	  according to the algorithm in section
			 *	  2.1.5.17.2, setting the algorithm's
			 *	  parameters as follows:
			 *		* Open = current Open.
			 *		* RequestedOplock =
			 *		  RequestedOplockLevel.
			 *		* GrantingInAck = TRUE.
			 *	* The operation MUST at this point return any
			 *	  status code returned by the shared oplock
			 *	  request algorithm.
			 */
			else if ((level & WRITE_CACHING) == 0) {
				*rop = level;
				status = smb_oplock_req_shared(
				    ofile, rop, B_TRUE);
				goto out;
			}

			/*
			 * Set Open.Stream.Oplock.ExclusiveOpen to
			 *   ThisContext.Open.
			 * Set Open.Stream.Oplock.State to
			 *   (RequestedOplockLevel|EXCLUSIVE).
			 * This operation MUST be made cancelable by
			 *   inserting it into CancelableOperations...
			 * This operation waits until the oplock is
			 * broken or canceled, as specified in
			 * section 2.1.5.17.3.
			 *
			 * Implementation note:
			 *
			 * Once we assing ol_state below, there
			 * will be no BREAK_TO_... flags set,
			 * so no need to wait for oplock breaks.
			 */
			node->n_oplock.excl_open = ofile;
			node->n_oplock.ol_state = level | EXCLUSIVE;
			status = NT_STATUS_SUCCESS;
		} /* onlist_RHBQ */
		if (FoundMatchingRHOplock == B_FALSE) {
			/* The operation MUST be failed with Status... */
			status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
			goto out;
		}
		break;	/* case (READ_CACHING|HANDLE_CACHING...) */

	case (READ_CACHING|WRITE_CACHING|EXCLUSIVE|BREAK_TO_READ_CACHING):
	case (READ_CACHING|WRITE_CACHING|EXCLUSIVE|BREAK_TO_NO_CACHING):
	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_READ_CACHING|BREAK_TO_WRITE_CACHING):
	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_READ_CACHING|BREAK_TO_HANDLE_CACHING):
	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_READ_CACHING):
	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_NO_CACHING):
		/*
		 * If Open.Stream.Oplock.ExclusiveOpen != Open:
		 *	* The operation MUST be failed with Status set to
		 *	  STATUS_INVALID_OPLOCK_PROTOCOL.
		 * EndIf
		 */
		if (node->n_oplock.excl_open != ofile) {
			status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
			goto out;
		}

		/*
		 * If Open.Stream.Oplock.WaitList is not empty and
		 * Open.Stream.Oplock.State does not contain HANDLE_CACHING
		 * and RequestedOplockLevel is CACHE_RWH:
		 *	The object store MUST indicate an oplock break to
		 *	the server according to the algorithm in section
		 *	2.1.5.17.3, setting the algorithm's params as follows:
		 *	* BreakingOplockOpen = Open.
		 *	* NewOplockLevel = BreakToLevel (see above)
		 *	* AcknowledgeRequired = TRUE.
		 *	* OplockCompletionStatus =
		 *	  STATUS_CANNOT_GRANT_REQUESTED_OPLOCK.
		 *   (Because BreakingOplockOpen is equal to the passed-in
		 *    Open, the operation ends at this point.)
		 */
		if (node->n_oplock.waiters &&
		    (node->n_oplock.ol_state & HANDLE_CACHING) == 0 &&
		    level == CACHE_RWH) {
			smb_oplock_ind_break_in_ack(
			    sr, ofile,
			    BreakToLevel, B_TRUE);
			status = NT_STATUS_SUCCESS;
			goto out;
		}

		/*
		 * Else If Open.Stream.IsDeleted is TRUE and
		 * RequestedOplockLevel contains HANDLE_CACHING:
		 */
		else if (((node->flags & NODE_FLAGS_DELETING) != 0) &&
		    (level & HANDLE_CACHING) != 0) {

			/*
			 * The object store MUST indicate an oplock break to
			 * the server according to the algorithm in section
			 * 2.1.5.17.3, setting the algorithm's params as
			 * follows:
			 *	* BreakingOplockOpen = Open.
			 *	* NewOplockLevel = RequestedOplockLevel
			 *	  without HANDLE_CACHING (for example if
			 *	  RequestedOplockLevel is
			 *	  (READ_CACHING|HANDLE_CACHING), then
			 *	   NewOplockLevel would be just READ_CACHING).
			 *	* AcknowledgeRequired = TRUE.
			 *	* OplockCompletionStatus =
			 *	  STATUS_CANNOT_GRANT_REQUESTED_OPLOCK.
			 * (Because BreakingOplockOpen is equal to the
			 *  passed-in Open, the operation ends at this point.)
			 */
			level &= ~HANDLE_CACHING;
			smb_oplock_ind_break_in_ack(
			    sr, ofile,
			    level, B_TRUE);
			status = NT_STATUS_SUCCESS;
			goto out;
		}

		/*
		 * For each Open WaitingOpen on Open.Stream.Oplock.WaitList:
		 *	* Indicate that the operation associated with
		 *	  WaitingOpen can continue according to the algorithm
		 *	  in section 2.1.4.12.1, setting OpenToRelease
		 *	  = WaitingOpen.
		 *	* Remove WaitingOpen from Open.Stream.Oplock.WaitList.
		 * EndFor
		 */
		cv_broadcast(&node->n_oplock.WaitingOpenCV);

		/*
		 * If RequestedOplockLevel does not contain WRITE_CACHING:
		 *	* Set Open.Stream.Oplock.ExclusiveOpen to NULL.
		 * EndIf
		 */
		if ((level & WRITE_CACHING) == 0) {
			node->n_oplock.excl_open = NULL;
		}

		/*
		 * If RequestedOplockLevel is 0 (that is, no flags):
		 *	* Set Open.Stream.Oplock.State to NO_OPLOCK.
		 *	* The operation returns Status set to STATUS_SUCCESS
		 *	  at this point.
		 */
		if (level == 0) {
			node->n_oplock.ol_state = NO_OPLOCK;
			status = NT_STATUS_SUCCESS;
			goto out;
		}

		/*
		 * Deal with possibly still pending breaks.
		 * Two cases: R to none, RH to R or none.
		 *
		 * XXX: These two missing from [MS-FSA]
		 */

		/*
		 * Breaking R to none?  This is like:
		 * "If BreakCacheLevel contains READ_CACHING..."
		 * from smb_oplock_break_cmn.
		 */
		if (level == CACHE_R && BreakToLevel == LEVEL_NONE) {
			smb_oplock_ind_break_in_ack(
			    sr, ofile,
			    LEVEL_NONE, B_FALSE);
			node->n_oplock.ol_state = NO_OPLOCK;
			status = NT_STATUS_SUCCESS;
			goto out;
		}

		/*
		 * Breaking RH to R or RH to none?  This is like:
		 * "If BreakCacheLevel equals HANDLE_CACHING..."
		 * from smb_oplock_break_cmn.
		 */
		if (level == CACHE_RH &&
		    (BreakToLevel == CACHE_R ||
		    BreakToLevel == LEVEL_NONE)) {
			smb_oplock_ind_break_in_ack(
			    sr, ofile,
			    BreakToLevel, B_TRUE);

			ofile->f_oplock.BreakingToRead =
			    (BreakToLevel & READ_CACHING) ? 1: 0;

			ASSERT(!(ofile->f_oplock.onlist_RHBQ));
			ofile->f_oplock.onlist_RHBQ = B_TRUE;
			node->n_oplock.cnt_RHBQ++;

			RecomputeOplockState(node);
			status = NT_STATUS_SUCCESS;
			goto out;
		}

		/*
		 * Else If RequestedOplockLevel does not contain WRITE_CACHING:
		 *	* The object store MUST request a shared oplock
		 *	  according to the algorithm in section 2.1.5.17.2,
		 *	  setting the algorithm's parameters as follows:
		 *		* Pass in the current Open.
		 *		* RequestedOplock = RequestedOplockLevel.
		 *		* GrantingInAck = TRUE.
		 *	* The operation MUST at this point return any status
		 *	  returned by the shared oplock request algorithm.
		 */
		if ((level & WRITE_CACHING) == 0) {
			*rop = level;
			status = smb_oplock_req_shared(ofile, rop, B_TRUE);
			goto out;
		}

		/*
		 * Note that because this oplock is being set up as part of
		 * an acknowledgement of an exclusive oplock break,
		 * Open.Stream.Oplock.ExclusiveOpen was set
		 * at the time of the original oplock request;
		 * it contains Open.
		 *	* Set Open.Stream.Oplock.State to
		 *	  (RequestedOplockLevel|EXCLUSIVE).
		 *	* This operation MUST be made cancelable...
		 *	* This operation waits until the oplock is broken or
		 *	  canceled, as specified in section 2.1.5.17.3.
		 *
		 * Implementation notes:
		 *
		 * This can only be a break from RWH to RW.
		 * The assignment of ol_state below means there will be
		 * no BREAK_TO_... bits set, and therefore no need for
		 * "waits until the oplock is broken" as described in
		 * the spec for this bit of code.  Therefore, this will
		 * return SUCCESS instead of OPLOCK_BREAK_IN_PROGRESS.
		 */
		node->n_oplock.ol_state = level | EXCLUSIVE;
		status = NT_STATUS_SUCCESS;
		break;	/* case (READ_CACHING|WRITE_CACHING|...) */

	default:
		/* The operation MUST be failed with Status */
		status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
		break;

	} /* Switch (oplock.state) */

out:
	/*
	 * The spec. describes waiting for a break here,
	 * but we let the caller do that (when needed) if
	 * status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS
	 */
	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

	if (status == NT_STATUS_INVALID_OPLOCK_PROTOCOL)
		*rop = LEVEL_NONE;

	if (status == NT_STATUS_SUCCESS &&
	    type == LEVEL_GRANULAR &&
	    *rop != LEVEL_NONE)
		*rop |= LEVEL_GRANULAR;

	return (status);
}

/*
 * 2.1.4.12 Algorithm to Check for an Oplock Break
 *
 * The inputs for this algorithm are:
 *
 * Open: The Open being used in the request calling this algorithm.
 *
 * Oplock: The Oplock being checked.
 *
 * Operation: A code describing the operation being processed.
 *
 * OpParams: Parameters associated with the Operation code that are
 *   passed in from the calling request. For example, if Operation is
 *   OPEN, as specified in section 2.1.5.1, then OpParams will have the
 *   members DesiredAccess and CreateDisposition. Each of these is a
 *   parameter to the open request as specified in section 2.1.5.1.
 *   This parameter could be empty, depending on the Operation code.
 *
 * Flags: An optional parameter. If unspecified it is considered to
 *   contain 0. Valid nonzero values are:
 *	PARENT_OBJECT
 *
 * The algorithm uses the following local variables:
 *
 * Boolean values (initialized to FALSE):
 *   BreakToTwo, BreakToNone, NeedToWait
 *
 * BreakCacheLevel – MAY contain 0 or a combination of one or more of
 *   READ_CACHING, WRITE_CACHING, or HANDLE_CACHING, as specified in
 *   section 2.1.1.10. Initialized to 0.
 *   Note that there are only four legal nonzero combinations of flags
 *   for BreakCacheLevel:
 *	(READ_CACHING|WRITE_CACHING|HANDLE_CACHING)
 *	(READ_CACHING|WRITE_CACHING)
 *	WRITE_CACHING
 *	HANDLE_CACHING
 *
 * Algorithm: (all)
 * If Oplock is not empty and Oplock.State is not NO_OPLOCK:
 *	If Flags contains PARENT_OBJECT:
 *		If Operation is OPEN, CLOSE, FLUSH_DATA,
 *		  FS_CONTROL(set_encryption) or
 *		  SET_INFORMATION(Basic, Allocation, EoF,
 *		  Rename, Link, Shortname, VDL):
 *			Set BreakCacheLevel to (READ_CACHING|WRITE_CACHING).
 *		EndIf
 *	Else // Normal operation (not PARENT_OBJECT)
 *		Switch (Operation):
 *		Case OPEN, CLOSE, ...
 *		EndSwitch
 *	EndIf // not parent
 *	// Common section for all above
 *	If BreakToTwo is TRUE:
 *		...
 *	Else If BreakToNone
 *		...
 *	EndIf
 *	...
 * EndIf
 *
 * This implementation uses separate functions for each of:
 *	if (flags & PARENT)... else
 *	switch (Operation)...
 */


/*
 * If Flags contains PARENT_OBJECT:
 * ...
 * Note that this function is unusual in that the node arg is
 * the PARENT directory node, and ofile is NOT on the ofile list
 * of that directory but one of the nodes under it.
 *
 * Note that until we implement directory leases, this is a no-op.
 */
uint32_t
smb_oplock_break_PARENT(smb_node_t *node, smb_ofile_t *ofile)
{
	uint32_t BreakCacheLevel;

	/*
	 * If Operation is OPEN, CLOSE, FLUSH_DATA,
	 *  FS_CONTROL(set_encryption) or
	 * SET_INFORMATION(Basic, Allocation, EoF,
	 * Rename, Link, Shortname, VDL):
	 *	 Set BreakCacheLevel to (READ_CACHING|WRITE_CACHING).
	 * EndIf
	 */
	BreakCacheLevel = PARENT_OBJECT |
	    (READ_CACHING|WRITE_CACHING);

	return (smb_oplock_break_cmn(node, ofile, BreakCacheLevel));
}

/*
 * Helper for the cases where section 2.1.5.1 says:
 *
 * If Open.Stream.Oplock is not empty and Open.Stream.Oplock.State
 * contains BATCH_OPLOCK, the object store MUST check for an oplock
 * break according to the algorithm in section 2.1.4.12,
 * with input values as follows:
 *	Open equal to this operation's Open
 *	Oplock equal to Open.Stream.Oplock
 *	Operation equal to "OPEN"
 *	OpParams containing two members:
 *      (DesiredAccess, CreateDisposition)
 *
 * So basically, just call smb_oplock_break_OPEN(), but
 * only if there's a batch oplock.
 */
uint32_t
smb_oplock_break_BATCH(smb_node_t *node, smb_ofile_t *ofile,
    uint32_t DesiredAccess, uint32_t CreateDisposition)
{
	if ((node->n_oplock.ol_state & BATCH_OPLOCK) == 0)
		return (0);

	return (smb_oplock_break_OPEN(node, ofile,
	    DesiredAccess, CreateDisposition));
}

/*
 * Case OPEN, as specified in section 2.1.5.1:
 *
 * Note: smb_ofile_open constructs a partially complete smb_ofile_t
 * for this call, which can be considerd a "proposed open".  This
 * open may or may not turn into a usable open depending on what
 * happens in the remainder of the ofile_open code path.
 */
uint32_t
smb_oplock_break_OPEN(smb_node_t *node, smb_ofile_t *ofile,
    uint32_t DesiredAccess, uint32_t CreateDisposition)
{
	uint32_t BreakCacheLevel = 0;
	/* BreakToTwo, BreakToNone, NeedToWait */

	/*
	 * If OpParams.DesiredAccess contains no flags other than
	 * FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES, or SYNCHRONIZE,
	 *   the algorithm returns at this point.
	 * EndIf
	 */
	if ((DesiredAccess & ~(FILE_READ_ATTRIBUTES |
	    FILE_WRITE_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL)) == 0)
		return (0);

	/*
	 * If OpParams.CreateDisposition is FILE_SUPERSEDE,
	 * FILE_OVERWRITE, or FILE_OVERWRITE_IF:
	 *	Set BreakToNone to TRUE, set BreakCacheLevel to
	 *	   (READ_CACHING|WRITE_CACHING).
	 * Else
	 *	Set BreakToTwo to TRUE,
	 *	set BreakCacheLevel to WRITE_CACHING.
	 * EndIf
	 */
	if (CreateDisposition == FILE_SUPERSEDE ||
	    CreateDisposition == FILE_OVERWRITE ||
	    CreateDisposition == FILE_OVERWRITE_IF) {
		BreakCacheLevel = BREAK_TO_NONE |
		    (READ_CACHING|WRITE_CACHING);
	} else {
		/*
		 * CreateDispositons: OPEN, OPEN_IF
		 */
		BreakCacheLevel = BREAK_TO_TWO |
		    WRITE_CACHING;
	}

	return (smb_oplock_break_cmn(node, ofile, BreakCacheLevel));
}

/*
 * Case OPEN_BREAK_H, as specified in section 2.1.5.1:
 *	Set BreakCacheLevel to HANDLE_CACHING.
 * EndCase
 */
uint32_t
smb_oplock_break_HANDLE(smb_node_t *node, smb_ofile_t *ofile)
{
	uint32_t BreakCacheLevel = HANDLE_CACHING;

	return (smb_oplock_break_cmn(node, ofile, BreakCacheLevel));
}

/*
 * Case CLOSE, as specified in section 2.1.5.4:
 *
 * The MS-FSA spec. describes sending oplock break indications
 * (smb_oplock_ind_break ... NT_STATUS_OPLOCK_HANDLE_CLOSED)
 * for several cases where the ofile we're closing has some
 * oplock grants.  We modify these slightly and use them to
 * clear out the SMB-level oplock state.  We could probably
 * just skip most of these, as the caller knows this handle is
 * closing and could just discard the SMB-level oplock state.
 * For now, keeping this close to what the spec says.
 */
void
smb_oplock_break_CLOSE(smb_node_t *node, smb_ofile_t *ofile)
{
	smb_ofile_t *o;

	if (ofile == NULL) {
		ASSERT(0);
		return;
	}

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	/*
	 * If Oplock.IIOplocks is not empty:
	 *   For each Open ThisOpen in Oplock.IIOplocks:
	 *	If ThisOpen == Open:
	 *		Remove ThisOpen from Oplock.IIOplocks.
	 *		Notify the server of an oplock break according to
	 *		  the algorithm in section 2.1.5.17.3, setting the
	 *		  algorithm's parameters as follows:
	 *			BreakingOplockOpen = ThisOpen.
	 *			NewOplockLevel = LEVEL_NONE.
	 *			AcknowledgeRequired = FALSE.
	 *			OplockCompletionStatus = STATUS_SUCCESS.
	 *		(The operation does not end at this point;
	 *		 this call to 2.1.5.17.3 completes some
	 *		 earlier call to 2.1.5.17.2.)
	 *	EndIf
	 *   EndFor
	 *   Recompute Oplock.State according to the algorithm in
	 *     section 2.1.4.13, passing Oplock as the ThisOplock parameter.
	 * EndIf
	 */
	if (node->n_oplock.cnt_II > 0) {
		o = ofile; /* No need for list walk */
		if (o->f_oplock.onlist_II) {
			o->f_oplock.onlist_II = B_FALSE;
			node->n_oplock.cnt_II--;
			ASSERT(node->n_oplock.cnt_II >= 0);
			/*
			 * The spec. says to do:
			 * smb_oplock_ind_break(o,
			 *    LEVEL_NONE, B_FALSE,
			 *    NT_STATUS_SUCCESS);
			 *
			 * We'll use STATUS_OPLOCK_HANDLE_CLOSED
			 * like all the other ind_break calls in
			 * this function, so the SMB-level will
			 * just clear out its oplock state.
			 */
			smb_oplock_ind_break(o,
			    LEVEL_NONE, B_FALSE,
			    NT_STATUS_OPLOCK_HANDLE_CLOSED);
		}
		RecomputeOplockState(node);
	}

	/*
	 * If Oplock.ROplocks is not empty:
	 *   For each Open ThisOpen in Oplock.ROplocks:
	 *	If ThisOpen == Open:
	 *		Remove ThisOpen from Oplock.ROplocks.
	 *		Notify the server of an oplock break according to
	 *		  the algorithm in section 2.1.5.17.3, setting the
	 *		  algorithm's parameters as follows:
	 *			BreakingOplockOpen = ThisOpen.
	 *			NewOplockLevel = LEVEL_NONE.
	 *			AcknowledgeRequired = FALSE.
	 *			OplockCompletionStatus =
	 *			  STATUS_OPLOCK_HANDLE_CLOSED.
	 *		(The operation does not end at this point;
	 *		 this call to 2.1.5.17.3 completes some
	 *		 earlier call to 2.1.5.17.2.)
	 *	EndIf
	 *   EndFor
	 *   Recompute Oplock.State according to the algorithm in
	 *     section 2.1.4.13, passing Oplock as the ThisOplock parameter.
	 * EndIf
	 */
	if (node->n_oplock.cnt_R > 0) {
		o = ofile; /* No need for list walk */
		if (o->f_oplock.onlist_R) {
			o->f_oplock.onlist_R = B_FALSE;
			node->n_oplock.cnt_R--;
			ASSERT(node->n_oplock.cnt_R >= 0);

			smb_oplock_ind_break(o,
			    LEVEL_NONE, B_FALSE,
			    NT_STATUS_OPLOCK_HANDLE_CLOSED);
		}
		RecomputeOplockState(node);
	}

	/*
	 * If Oplock.RHOplocks is not empty:
	 *   For each Open ThisOpen in Oplock.RHOplocks:
	 *	If ThisOpen == Open:
	 *		Remove ThisOpen from Oplock.RHOplocks.
	 *		Notify the server of an oplock break according to
	 *		  the algorithm in section 2.1.5.17.3, setting the
	 *		  algorithm's parameters as follows:
	 *			BreakingOplockOpen = ThisOpen.
	 *			NewOplockLevel = LEVEL_NONE.
	 *			AcknowledgeRequired = FALSE.
	 *			OplockCompletionStatus =
	 *			   STATUS_OPLOCK_HANDLE_CLOSED.
	 *		(The operation does not end at this point;
	 *		 this call to 2.1.5.17.3 completes some
	 *		 earlier call to 2.1.5.17.2.)
	 *	EndIf
	 *   EndFor
	 *   Recompute Oplock.State according to the algorithm in
	 *     section 2.1.4.13, passing Oplock as the ThisOplock parameter.
	 * EndIf
	 */
	if (node->n_oplock.cnt_RH > 0) {
		o = ofile; /* No need for list walk */
		if (o->f_oplock.onlist_RH) {
			o->f_oplock.onlist_RH = B_FALSE;
			node->n_oplock.cnt_RH--;
			ASSERT(node->n_oplock.cnt_RH >= 0);

			smb_oplock_ind_break(o,
			    LEVEL_NONE, B_FALSE,
			    NT_STATUS_OPLOCK_HANDLE_CLOSED);
		}
		RecomputeOplockState(node);
	}

	/*
	 * If Oplock.RHBreakQueue is not empty:
	 *	For each RHOpContext ThisContext in Oplock.RHBreakQueue:
	 *		If ThisContext.Open == Open:
	 *			Remove ThisContext from Oplock.RHBreakQueue.
	 *		EndIf
	 *	EndFor
	 *	Recompute Oplock.State according to the algorithm in
	 *	  section 2.1.4.13, passing Oplock as the ThisOplock parameter.
	 *	For each Open WaitingOpen on Oplock.WaitList:
	 *		If Oplock.RHBreakQueue is empty:
	 *		(or) If the value of every
	 *		RHOpContext.Open.TargetOplockKey
	 *		on Oplock.RHBreakQueue is equal to
	 *		WaitingOpen .TargetOplockKey:
	 *			Indicate that the op. assoc. with
	 *			WaitingOpen can continue according to
	 *			the algorithm in section 2.1.4.12.1,
	 *			setting OpenToRelease = WaitingOpen.
	 *			Remove WaitingOpen from Oplock.WaitList.
	 *		EndIf
	 *	EndFor
	 * EndIf
	 */
	if (node->n_oplock.cnt_RHBQ > 0) {
		o = ofile; /* No need for list walk */
		if (o->f_oplock.onlist_RHBQ) {
			o->f_oplock.onlist_RHBQ = B_FALSE;
			node->n_oplock.cnt_RHBQ--;
			ASSERT(node->n_oplock.cnt_RHBQ >= 0);
		}
		RecomputeOplockState(node);
		/*
		 * We don't keep a WaitingOpen list, so just
		 * wake them all and let them look at the
		 * updated Oplock.RHBreakQueue
		 */
		cv_broadcast(&node->n_oplock.WaitingOpenCV);
	}

	/*
	 * If Open equals Open.Oplock.ExclusiveOpen
	 *	If Oplock.State contains none of (BREAK_ANY):
	 *		Notify the server of an oplock break according to
	 *		  the algorithm in section 2.1.5.17.3, setting the
	 *		  algorithm's parameters as follows:
	 *			BreakingOplockOpen = Oplock.ExclusiveOpen.
	 *			NewOplockLevel = LEVEL_NONE.
	 *			AcknowledgeRequired = FALSE.
	 *			OplockCompletionStatus equal to:
	 *				STATUS_OPLOCK_HANDLE_CLOSED if
	 *				  Oplock.State contains any of
	 *				  READ_CACHING, WRITE_CACHING, or
	 *				  HANDLE_CACHING.
	 *				STATUS_SUCCESS otherwise.
	 *		(The operation does not end at this point;
	 *		 this call to 2.1.5.17.3 completes some
	 *		 earlier call to 2.1.5.17.1.)
	 *	EndIf
	 *	Set Oplock.ExclusiveOpen to NULL.
	 *	Set Oplock.State to NO_OPLOCK.
	 *	For each Open WaitingOpen on Oplock.WaitList:
	 *		Indicate that the operation associated with WaitingOpen
	 *		  can continue according to the algorithm in section
	 *		  2.1.4.12.1, setting OpenToRelease = WaitingOpen.
	 *		Remove WaitingOpen from Oplock.WaitList.
	 *	EndFor
	 * EndIf
	 *
	 * Modify this slightly from what the spec. says and only
	 * up-call the break with status STATUS_OPLOCK_HANDLE_CLOSED.
	 * The STATUS_SUCCESS case would do nothing at the SMB level,
	 * so we'll just skip that part.
	 */
	if (ofile == node->n_oplock.excl_open) {
		uint32_t level = node->n_oplock.ol_state & CACHE_RWH;
		if (level != 0 &&
		    (node->n_oplock.ol_state & BREAK_ANY) == 0) {
			smb_oplock_ind_break(ofile,
			    LEVEL_NONE, B_FALSE,
			    NT_STATUS_OPLOCK_HANDLE_CLOSED);
		}
		node->n_oplock.excl_open = NULL;
		node->n_oplock.ol_state = NO_OPLOCK;
		cv_broadcast(&node->n_oplock.WaitingOpenCV);
	}

	/*
	 * The CLOSE sub-case of 2.1.5.4 (separate function here)
	 * happens to always leave BreakCacheLevel=0 (see 2.1.5.4)
	 * so there's never a need to call smb_oplock_break_cmn()
	 * in this function.  If that changed and we were to have
	 * BreakCacheLevel != 0 here, then we'd need to call:
	 * smb_oplock_break_cmn(node, ofile, BreakCacheLevel);
	 */

	if ((node->n_oplock.ol_state & BREAK_ANY) == 0)
		cv_broadcast(&node->n_oplock.WaitingOpenCV);

	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);
}

/*
 * Case READ, as specified in section 2.1.5.2:
 *	Set BreakToTwo to TRUE
 *	Set BreakCacheLevel to WRITE_CACHING.
 * EndCase
 */
uint32_t
smb_oplock_break_READ(smb_node_t *node, smb_ofile_t *ofile)
{
	uint32_t BreakCacheLevel = BREAK_TO_TWO | WRITE_CACHING;

	return (smb_oplock_break_cmn(node, ofile, BreakCacheLevel));
}

/*
 * Case FLUSH_DATA, as specified in section 2.1.5.6:
 *	Set BreakToTwo to TRUE
 *	Set BreakCacheLevel to WRITE_CACHING.
 * EndCase
 * Callers just use smb_oplock_break_READ() -- same thing.
 */

/*
 * Case LOCK_CONTROL, as specified in section 2.1.5.7:
 * Note: Spec does fall-through to WRITE here.
 *
 * Case WRITE, as specified in section 2.1.5.3:
 *	Set BreakToNone to TRUE
 *	Set BreakCacheLevel to (READ_CACHING|WRITE_CACHING).
 * EndCase
 */
uint32_t
smb_oplock_break_WRITE(smb_node_t *node, smb_ofile_t *ofile)
{
	uint32_t BreakCacheLevel = BREAK_TO_NONE |
	    (READ_CACHING|WRITE_CACHING);

	return (smb_oplock_break_cmn(node, ofile, BreakCacheLevel));
}

/*
 * Case SET_INFORMATION, as specified in section 2.1.5.14:
 * Switch (OpParams.FileInformationClass):
 *	Case FileEndOfFileInformation:
 *	Case FileAllocationInformation:
 *		Set BreakToNone to TRUE
 *		Set BreakCacheLevel to (READ_CACHING|WRITE_CACHING).
 *	EndCase
 *	Case FileRenameInformation:
 *	Case FileLinkInformation:
 *	Case FileShortNameInformation:
 *		Set BreakCacheLevel to HANDLE_CACHING.
 *		If Oplock.State contains BATCH_OPLOCK,
 *		  set BreakToNone to TRUE.
 *	EndCase
 *	Case FileDispositionInformation:
 *		If OpParams.DeleteFile is TRUE,
 *		Set BreakCacheLevel to HANDLE_CACHING.
 *	EndCase
 * EndSwitch
 */
uint32_t
smb_oplock_break_SETINFO(smb_node_t *node, smb_ofile_t *ofile,
    uint32_t InfoClass)
{
	uint32_t BreakCacheLevel = 0;

	switch (InfoClass) {
	case FileEndOfFileInformation:
	case FileAllocationInformation:
		BreakCacheLevel = BREAK_TO_NONE |
		    (READ_CACHING|WRITE_CACHING);
		break;

	case FileRenameInformation:
	case FileLinkInformation:
	case FileShortNameInformation:
		BreakCacheLevel = HANDLE_CACHING;
		if (node->n_oplock.ol_state & BATCH_OPLOCK) {
			BreakCacheLevel |= BREAK_TO_NONE;
		}
		break;
	case FileDispositionInformation:
		/* Only called if (OpParams.DeleteFile is TRUE) */
		BreakCacheLevel = HANDLE_CACHING;
		break;

	}

	return (smb_oplock_break_cmn(node, ofile, BreakCacheLevel));
}

/*
 * This one is not from the spec.  It appears that Windows will
 * open a handle for an SMB1 delete call (at least internally).
 * We don't open a handle for delete, but do want to break as if
 * we had done, so this breaks like a combination of:
 *	break_BATCH(... DELETE, FILE_OPEN_IF)
 *	break_HANDLE(...)
 */
uint32_t
smb_oplock_break_DELETE(smb_node_t *node, smb_ofile_t *ofile)
{
	uint32_t BreakCacheLevel = HANDLE_CACHING;

	if ((node->n_oplock.ol_state & BATCH_OPLOCK) != 0)
		BreakCacheLevel |= BREAK_TO_TWO;

	return (smb_oplock_break_cmn(node, ofile, BreakCacheLevel));
}

/*
 * Case FS_CONTROL, as specified in section 2.1.5.9:
 *	If OpParams.ControlCode is FSCTL_SET_ZERO_DATA:
 *		Set BreakToNone to TRUE.
 *		Set BreakCacheLevel to (READ_CACHING|WRITE_CACHING).
 *	EndIf
 * EndCase
 * Callers just use smb_oplock_break_WRITE() -- same thing.
 */

/*
 * Common section for all cases above
 * Note: When called via FEM: ofile == NULL
 */
static uint32_t
smb_oplock_break_cmn(smb_node_t *node,
    smb_ofile_t *ofile, uint32_t BreakCacheLevel)
{
	smb_oplock_t *nol = &node->n_oplock;
	uint32_t CmpFlags, status;
	boolean_t BreakToTwo, BreakToNone, NeedToWait;
	smb_ofile_t *o = NULL;

	CmpFlags = (BreakCacheLevel & PARENT_OBJECT);
	BreakToTwo = (BreakCacheLevel & BREAK_TO_TWO) != 0;
	BreakToNone = (BreakCacheLevel & BREAK_TO_NONE) != 0;
	BreakCacheLevel &= (READ_CACHING | WRITE_CACHING | HANDLE_CACHING);
	NeedToWait = B_FALSE;
	status = NT_STATUS_SUCCESS;

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	if (node->n_oplock.ol_state == 0 ||
	    node->n_oplock.ol_state == NO_OPLOCK)
		goto out;

	if (BreakToTwo) {
		/*
		 * If (Oplock.State != LEVEL_TWO_OPLOCK) and
		 *    ((Oplock.ExclusiveOpen is empty) or
		 *     (Oplock.ExclusiveOpen.TargetOplockKey !=
		 *      Open.TargetOplockKey)):
		 */
		if ((nol->ol_state != LEVEL_TWO_OPLOCK) &&
		    (((o = nol->excl_open) == NULL) ||
		    !CompareOplockKeys(ofile, o, CmpFlags))) {

			/*
			 * If (Oplock.State contains EXCLUSIVE) and
			 *  (Oplock.State contains none of READ_CACHING,
			 *   WRITE_CACHING, or HANDLE_CACHING):
			 */
			if ((nol->ol_state & EXCLUSIVE) != 0 &&
			    (nol->ol_state & CACHE_RWH) == 0) {
				/*
				 * If Oplock.State contains none of:
				 *	BREAK_TO_NONE,
				 *	BREAK_TO_TWO,
				 *	BREAK_TO_TWO_TO_NONE,
				 *	BREAK_TO_READ_CACHING,
				 *	BREAK_TO_WRITE_CACHING,
				 *	BREAK_TO_HANDLE_CACHING,
				 *	BREAK_TO_NO_CACHING:
				 */
				if ((nol->ol_state & BREAK_ANY) == 0) {

					/*
					 * Oplock.State MUST contain either
					 * LEVEL_ONE_OPLOCK or BATCH_OPLOCK.
					 * Set BREAK_TO_TWO in Oplock.State.
					 */
					ASSERT((nol->ol_state &
					    (LEVEL_ONE | LEVEL_BATCH)) != 0);
					nol->ol_state |= BREAK_TO_TWO;

					/*
					 * Notify the server of an oplock break
					 * according to the algorithm in section
					 * 2.1.5.17.3, setting the algorithm's
					 * parameters as follows:
					 *	BreakingOplockOpen =
					 *	  Oplock.ExclusiveOpen.
					 *	NewOplockLevel = LEVEL_TWO.
					 *	AcknowledgeRequired = TRUE.
					 *	Compl_Status = STATUS_SUCCESS.
					 * (The operation does not end at this
					 * point; this call to 2.1.5.17.3
					 * completes some earlier call to
					 * 2.1.5.17.1.)
					 */
					smb_oplock_ind_break(o,
					    LEVEL_TWO, B_TRUE,
					    NT_STATUS_SUCCESS);
				}

				/*
				 * The operation that called this algorithm
				 *  MUST be made cancelable by ...
				 * The operation that called this algorithm
				 *  waits until the oplock break is
				 *  acknowledged, as specified in section
				 *  2.1.5.18, or the operation is canceled.
				 */
				status = NT_STATUS_OPLOCK_BREAK_IN_PROGRESS;
				/* Caller does smb_oplock_wait_break() */
			}
		}
	} else if (BreakToNone) {
		/*
		 * If (Oplock.State == LEVEL_TWO_OPLOCK) or
		 *  (Oplock.ExclusiveOpen is empty) or
		 *  (Oplock.ExclusiveOpen.TargetOplockKey !=
		 *   Open.TargetOplockKey):
		 */
		if (nol->ol_state == LEVEL_TWO_OPLOCK ||
		    (((o = nol->excl_open) == NULL) ||
		    !CompareOplockKeys(ofile, o, CmpFlags))) {

			/*
			 * If (Oplock.State != NO_OPLOCK) and
			 * (Oplock.State contains neither
			 *  WRITE_CACHING nor HANDLE_CACHING):
			 */
			if (nol->ol_state != NO_OPLOCK &&
			    (nol->ol_state &
			    (WRITE_CACHING | HANDLE_CACHING)) == 0) {

				/*
				 * If Oplock.State contains none of:
				 *	LEVEL_TWO_OPLOCK,
				 *	BREAK_TO_NONE,
				 *	BREAK_TO_TWO,
				 *	BREAK_TO_TWO_TO_NONE,
				 *	BREAK_TO_READ_CACHING,
				 *	BREAK_TO_WRITE_CACHING,
				 *	BREAK_TO_HANDLE_CACHING, or
				 *	BREAK_TO_NO_CACHING:
				 */
				if ((nol->ol_state &
				    (LEVEL_TWO_OPLOCK | BREAK_ANY)) == 0) {

					/*
					 * There could be a READ_CACHING-only
					 * oplock here. Those are broken later.
					 *
					 * If Oplock.State contains READ_CACHING
					 *  go to the LeaveBreakToNone label.
					 * Set BREAK_TO_NONE in Oplock.State.
					 */
					if ((nol->ol_state & READ_CACHING) != 0)
						goto LeaveBreakToNone;
					nol->ol_state |= BREAK_TO_NONE;

					/*
					 * Notify the server of an oplock break
					 * according to the algorithm in section
					 * 2.1.5.17.3, setting the algorithm's
					 * parameters as follows:
					 *	BreakingOplockOpen =
					 *	  Oplock.ExclusiveOpen.
					 *	NewOplockLevel = LEVEL_NONE.
					 *	AcknowledgeRequired = TRUE.
					 *	Commpl_Status = STATUS_SUCCESS.
					 * (The operation does not end at this
					 * point; this call to 2.1.5.17.3
					 * completes some earlier call to
					 * 2.1.5.17.1.)
					 */
					smb_oplock_ind_break(o,
					    LEVEL_NONE, B_TRUE,
					    NT_STATUS_SUCCESS);
				}

				/*
				 * Else If Oplock.State equals LEVEL_TWO_OPLOCK
				 *  or (LEVEL_TWO_OPLOCK|READ_CACHING):
				 */
				else if (nol->ol_state == LEVEL_TWO ||
				    nol->ol_state == (LEVEL_TWO|READ_CACHING)) {

					/*
					 * For each Open O in Oplock.IIOplocks:
					 *   Remove O from Oplock.IIOplocks.
					 *   Notify the server of an oplock
					 *    break according to the algorithm
					 *    in section 2.1.5.17.3, setting the
					 *    algorithm's parameters as follows:
					 *	BreakingOplockOpen = ThisOpen.
					 *	NewOplockLevel = LEVEL_NONE.
					 *	AcknowledgeRequired = FALSE.
					 *	Compl_Status = STATUS_SUCCESS.
					 *    (The operation does not end at
					 *    this point; this call to
					 *    2.1.5.17.3 completes some
					 *    earlier call to 2.1.5.17.2.)
					 * EndFor
					 */
					FOREACH_NODE_OFILE(node, o) {
						if (o->f_oplock.onlist_II == 0)
							continue;
						o->f_oplock.onlist_II = B_FALSE;
						nol->cnt_II--;
						ASSERT(nol->cnt_II >= 0);

						smb_oplock_ind_break(o,
						    LEVEL_NONE, B_FALSE,
						    NT_STATUS_SUCCESS);
					}
					/*
					 * If Oplock.State equals
					 *  (LEVEL_TWO_OPLOCK|READ_CACHING):
					 *	Set Oplock.State = READ_CACHING.
					 * Else
					 *	Set Oplock.State = NO_OPLOCK.
					 * EndIf
					 * Go to the LeaveBreakToNone label.
					 */
					if (nol->ol_state ==
					    (LEVEL_TWO_OPLOCK | READ_CACHING)) {
						nol->ol_state = READ_CACHING;
					} else {
						nol->ol_state = NO_OPLOCK;
					}
					goto LeaveBreakToNone;
				}

				/*
				 * Else If Oplock.State contains BREAK_TO_TWO:
				 *	Clear BREAK_TO_TWO from Oplock.State.
				 *	Set BREAK_TO_TWO_TO_NONE in Oplock.State
				 * EndIf
				 */
				else if (nol->ol_state & BREAK_TO_TWO) {
					nol->ol_state &= ~BREAK_TO_TWO;
					nol->ol_state |= BREAK_TO_TWO_TO_NONE;
				}

				/*
				 * If Oplock.ExclusiveOpen is not empty,
				 *  and Oplock.Excl_Open.TargetOplockKey
				 *  equals Open.TargetOplockKey,
				 *	 go to the LeaveBreakToNone label.
				 */
				if (o != NULL &&
				    CompareOplockKeys(ofile, o, CmpFlags))
					goto LeaveBreakToNone;

				/*
				 * The operation that called this algorithm
				 *  MUST be made cancelable by ...
				 * The operation that called this algorithm
				 * waits until the opl. break is acknowledged,
				 * as specified in section 2.1.5.18, or the
				 * operation is canceled.
				 */
				status = NT_STATUS_OPLOCK_BREAK_IN_PROGRESS;
				/* Caller does smb_oplock_wait_break() */
			}
		}
	}

LeaveBreakToNone:

	/*
	 * if (BreakCacheLevel != 0) and		(pp 37)
	 * If Oplock.State contains any flags that are in BreakCacheLevel:
	 * (Body of that "If" was here to just above the out label.)
	 */
	if ((nol->ol_state & BreakCacheLevel) == 0)
		goto out;

	/*
	 * If Oplock.ExclusiveOpen is not empty, call the
	 * algorithm in section 2.1.4.12.2, passing
	 *	Open as the OperationOpen parameter,
	 *	Oplock.ExclusiveOpen as the OplockOpen parameter,
	 *	and Flags as the Flagsparameter.
	 * If the algorithm returns TRUE:
	 *	The algorithm returns at this point.
	 */
	if ((o = nol->excl_open) != NULL &&
	    CompareOplockKeys(ofile, o, CmpFlags) == B_TRUE) {
		status = NT_STATUS_SUCCESS;
		goto out;
	}

	/*
	 * Switch (Oplock.State):
	 */
	switch (nol->ol_state) {

	case (READ_CACHING|HANDLE_CACHING|MIXED_R_AND_RH):
	case READ_CACHING:
	case (LEVEL_TWO_OPLOCK|READ_CACHING):
		/*
		 * If BreakCacheLevel contains READ_CACHING:
		 */
		if ((BreakCacheLevel & READ_CACHING) != 0) {
			/*
			 * For each Open ThisOpen in Oplock.ROplocks:
			 *   Call the algorithm in section 2.1.4.12.2, pass:
			 *	Open as the OperationOpen parameter,
			 *	ThisOpen as the OplockOpen parameter,
			 *	and Flags as the Flagsparameter.
			 *   If the algorithm returns FALSE:
			 *	Remove ThisOpen from Oplock.ROplocks.
			 *	Notify the server of an oplock break
			 *	  according to the algorithm in
			 *	  section 2.1.5.17.3, setting the
			 *	  algorithm's parameters as follows:
			 *		BreakingOplockOpen = ThisOpen.
			 *		NewOplockLevel = LEVEL_NONE.
			 *		AcknowledgeRequired = FALSE.
			 *		Compl_Status = STATUS_SUCCESS.
			 *	(The operation does not end at this point;
			 *	 this call to 2.1.5.17.3 completes some
			 *	 earlier call to 2.1.5.17.2.)
			 *	EndIf
			 * EndFor
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_R == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, CmpFlags)) {
					o->f_oplock.onlist_R = B_FALSE;
					nol->cnt_R--;
					ASSERT(nol->cnt_R >= 0);

					smb_oplock_ind_break(o,
					    LEVEL_NONE, B_FALSE,
					    NT_STATUS_SUCCESS);
				}
			}
		}
		/*
		 * If Oplock.State equals
		 *  (READ_CACHING|HANDLE_CACHING|MIXED_R_AND_RH):
		 *	// Do nothing; FALL THROUGH to next Case statement.
		 * Else
		 *	Recompute Oplock.State according to the
		 *	algorithm in section 2.1.4.13, passing
		 *	Oplock as the ThisOplock parameter.
		 * EndIf
		 */
		if (nol->ol_state ==
		    (READ_CACHING|HANDLE_CACHING|MIXED_R_AND_RH))
			goto case_cache_rh;

		RecomputeOplockState(node);
		break;
	/* EndCase	XXX Note: spec. swapped this with prev. Endif. */

	case_cache_rh:
	case (READ_CACHING|HANDLE_CACHING):

		/*
		 * If BreakCacheLevel equals HANDLE_CACHING:
		 */
		if (BreakCacheLevel == HANDLE_CACHING) {

			/*
			 * For each Open ThisOpen in Oplock.RHOplocks:
			 *	If ThisOpen.OplockKey != Open.OplockKey:
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RH == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, CmpFlags)) {

					/*
					 * Remove ThisOpen from
					 *  Oplock.RHOplocks.
					 */
					o->f_oplock.onlist_RH = B_FALSE;
					nol->cnt_RH--;
					ASSERT(nol->cnt_RH >= 0);

					/*
					 * Notify the server of an oplock break
					 *   according to the algorithm in
					 *   section 2.1.5.17.3, setting the
					 *   algorithm's parameters as follows:
					 *	BreakingOplockOpen = ThisOpen.
					 *	NewOplockLevel = READ_CACHING.
					 *	AcknowledgeRequired = TRUE.
					 *	Compl_Status = STATUS_SUCCESS.
					 * (The operation does not end at this
					 *  point; this call to 2.1.5.17.3
					 *  completes some earlier call to
					 *  2.1.5.17.2.)
					 */
					smb_oplock_ind_break(o,
					    READ_CACHING, B_TRUE,
					    NT_STATUS_SUCCESS);

					/*
					 * Initialize a new RHOpContext object,
					 *   setting its fields as follows:
					 *	RHOpCtx.Open = ThisOpen.
					 *	RHOpCtx.BreakingToRead = TRUE.
					 * Add the new RHOpContext object to
					 *    Oplock.RHBreakQueue.
					 * Set NeedToWait to TRUE.
					 */
					o->f_oplock.BreakingToRead = B_TRUE;
					ASSERT(!(o->f_oplock.onlist_RHBQ));
					o->f_oplock.onlist_RHBQ = B_TRUE;
					nol->cnt_RHBQ++;

					NeedToWait = B_TRUE;
				}
			}
		}

		/*
		 * Else If BreakCacheLevel contains both
		 *   READ_CACHING and WRITE_CACHING:
		 */
		else if ((BreakCacheLevel & (READ_CACHING | WRITE_CACHING)) ==
		    (READ_CACHING | WRITE_CACHING)) {

			/*
			 * For each RHOpContext ThisContext in
			 * Oplock.RHBreakQueue:
			 *	Call the algorithm in section 2.1.4.12.2,
			 *	  passing Open as the OperationOpen parameter,
			 *	  ThisContext.Open as the OplockOpen parameter,
			 *	  and Flags as the Flags parameter.
			 *	If the algorithm returns FALSE:
			 *		Set ThisContext.BreakingToRead to FALSE.
			 *		If BreakCacheLevel & HANDLE_CACHING:
			 *			Set NeedToWait to TRUE.
			 *		EndIf
			 *	EndIf
			 * EndFor
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RHBQ == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, CmpFlags)) {
					o->f_oplock.BreakingToRead = B_FALSE;
					if (BreakCacheLevel & HANDLE_CACHING)
						NeedToWait = B_TRUE;
				}
			}

			/*
			 * For each Open ThisOpen in Oplock.RHOplocks:
			 *	Call the algorithm in section 2.1.4.12.2,
			 *	  passing Open as the OperationOpen parameter,
			 *	  ThisOpen as the OplockOpen parameter, and
			 *	  Flags as the Flagsparameter.
			 *	If the algorithm  returns FALSE:
			 *		Remove ThisOpen from Oplock.RHOplocks.
			 *		Notify the server of an oplock break
			 *		  according to the algorithm in
			 *		  section 2.1.5.17.3, setting the
			 *		  algorithm's parameters as follows:
			 *			BreakingOplockOpen = ThisOpen.
			 *			NewOplockLevel = LEVEL_NONE.
			 *			AcknowledgeRequired = TRUE.
			 *			Compl_Status = STATUS_SUCCESS.
			 *		(The operation does not end at this
			 *		 point; this call to 2.1.5.17.3
			 *		 completes some earlier call to
			 *		 2.1.5.17.2.)
			 *		Initialize a new RHOpContext object,
			 *		  setting its fields as follows:
			 *			RHOpCtx.Open = ThisOpen.
			 *			RHOpCtx.BreakingToRead = FALSE
			 *		Add the new RHOpContext object to
			 *		  Oplock.RHBreakQueue.
			 *		If BreakCacheLevel contains
			 *		  HANDLE_CACHING:
			 *			Set NeedToWait to TRUE.
			 *		EndIf
			 *	EndIf
			 * EndFor
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RH == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, CmpFlags)) {
					o->f_oplock.onlist_RH = B_FALSE;
					nol->cnt_RH--;
					ASSERT(nol->cnt_RH >= 0);

					smb_oplock_ind_break(o,
					    LEVEL_NONE, B_TRUE,
					    NT_STATUS_SUCCESS);

					o->f_oplock.BreakingToRead = B_FALSE;
					ASSERT(!(o->f_oplock.onlist_RHBQ));
					o->f_oplock.onlist_RHBQ = B_TRUE;
					nol->cnt_RHBQ++;

					if (BreakCacheLevel & HANDLE_CACHING)
						NeedToWait = B_TRUE;
				}
			}
		}

// If the oplock is explicitly losing HANDLE_CACHING, RHBreakQueue is
// not empty, and the algorithm has not yet decided to wait, this operation
// might have to wait if there is an oplock on RHBreakQueue with a
// non-matching key. This is done because even if this operation didn't
// cause a break of a currently-granted Read-Handle caching oplock, it
// might have done so had a currently-breaking oplock still been granted.

		/*
		 * If (NeedToWait is FALSE) and
		 *   (Oplock.RHBreakQueue is empty) and   (XXX: Not empty)
		 *   (BreakCacheLevel contains HANDLE_CACHING):
		 *	For each RHOpContext ThisContex in Oplock.RHBreakQueue:
		 *		If ThisContext.Open.OplockKey != Open.OplockKey:
		 *			Set NeedToWait to TRUE.
		 *			Break out of the For loop.
		 *		EndIf
		 *	EndFor
		 * EndIf
		 * Recompute Oplock.State according to the algorithm in
		 *   section 2.1.4.13, passing Oplock as ThisOplock.
		 */
		if (NeedToWait == B_FALSE &&
		    (BreakCacheLevel & HANDLE_CACHING) != 0) {
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RHBQ == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, CmpFlags)) {
					NeedToWait = B_TRUE;
					break;
				}
			}
		}
		RecomputeOplockState(node);
		break;

	case (READ_CACHING|HANDLE_CACHING|BREAK_TO_READ_CACHING):
		/*
		 * If BreakCacheLevel contains READ_CACHING:
		 */
		if ((BreakCacheLevel & READ_CACHING) != 0) {
			/*
			 * For each RHOpContext ThisContext in
			 *  Oplock.RHBreakQueue:
			 *	Call the algorithm in section 2.1.4.12.2,
			 *	  passing Open = OperationOpen parameter,
			 *	  ThisContext.Open = OplockOpen parameter,
			 *	  and Flags as the Flags parameter.
			 *	If the algorithm returns FALSE:
			 *		Set ThisCtx.BreakingToRead = FALSE.
			 *	EndIf
			 *	Recompute Oplock.State according to the
			 *	  algorithm in section 2.1.4.13, passing
			 *	  Oplock as the ThisOplock parameter.
			 * EndFor
			 */
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RHBQ == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, CmpFlags)) {
					o->f_oplock.BreakingToRead = B_FALSE;
				}
			}
			RecomputeOplockState(node);
		}
		/* FALLTHROUGH */

	case (READ_CACHING|HANDLE_CACHING|BREAK_TO_NO_CACHING):
		/*
		 * If BreakCacheLevel contains HANDLE_CACHING:
		 *	For each RHOpContext ThisContext in Oplock.RHBreakQueue:
		 *		If ThisContext.Open.OplockKey != Open.OplockKey:
		 *			Set NeedToWait to TRUE.
		 *			Break out of the For loop.
		 *		EndIf
		 *	EndFor
		 * EndIf
		 */
		if ((BreakCacheLevel & HANDLE_CACHING) != 0) {
			FOREACH_NODE_OFILE(node, o) {
				if (o->f_oplock.onlist_RHBQ == 0)
					continue;
				if (!CompareOplockKeys(ofile, o, CmpFlags)) {
					NeedToWait = B_TRUE;
					break;
				}
			}
		}
		break;

	case (READ_CACHING|WRITE_CACHING|EXCLUSIVE):
		/*
		 * If BreakCacheLevel contains both
		 *  READ_CACHING and WRITE_CACHING:
		 *	Notify the server of an oplock break according to
		 *	  the algorithm in section 2.1.5.17.3, setting the
		 *	  algorithm's parameters as follows:
		 *		BreakingOplockOpen = Oplock.ExclusiveOpen.
		 *		NewOplockLevel = LEVEL_NONE.
		 *		AcknowledgeRequired = TRUE.
		 *		OplockCompletionStatus = STATUS_SUCCESS.
		 *	(The operation does not end at this point;
		 *	 this call to 2.1.5.17.3 completes some
		 *	 earlier call to 2.1.5.17.1.)
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING| \
		 *			EXCLUSIVE|BREAK_TO_NO_CACHING).
		 *	Set NeedToWait to TRUE.
		 */
		if ((BreakCacheLevel & (READ_CACHING | WRITE_CACHING)) ==
		    (READ_CACHING | WRITE_CACHING)) {
			o = nol->excl_open;
			ASSERT(o != NULL);
			smb_oplock_ind_break(o,
			    LEVEL_NONE, B_TRUE,
			    NT_STATUS_SUCCESS);

			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|
			    EXCLUSIVE|BREAK_TO_NO_CACHING);
			NeedToWait = B_TRUE;
		}

		/*
		 * Else If BreakCacheLevel contains WRITE_CACHING:
		 *	Notify the server of an oplock break according to
		 *	  the algorithm in section 2.1.5.17.3, setting the
		 *	  algorithm's parameters as follows:
		 *		BreakingOplockOpen = Oplock.ExclusiveOpen.
		 *		NewOplockLevel = READ_CACHING.
		 *		AcknowledgeRequired = TRUE.
		 *		OplockCompletionStatus = STATUS_SUCCESS.
		 *	(The operation does not end at this point;
		 *	 this call to 2.1.5.17.3 completes some
		 *	 earlier call to 2.1.5.17.1.)
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			 EXCLUSIVE|BREAK_TO_READ_CACHING).
		 *	Set NeedToWait to TRUE.
		 * EndIf
		 */
		else if ((BreakCacheLevel & WRITE_CACHING) != 0) {
			o = nol->excl_open;
			ASSERT(o != NULL);
			smb_oplock_ind_break(o,
			    READ_CACHING, B_TRUE,
			    NT_STATUS_SUCCESS);

			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|
			    EXCLUSIVE|BREAK_TO_READ_CACHING);
			NeedToWait = B_TRUE;
		}
		break;

	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE):
		/*
		 * If BreakCacheLevel equals WRITE_CACHING:
		 *	Notify the server of an oplock break according to
		 *	  the algorithm in section 2.1.5.17.3, setting the
		 *	  algorithm's parameters as follows:
		 *		BreakingOplockOpen = Oplock.ExclusiveOpen.
		 *		NewOplockLevel = (READ_CACHING|HANDLE_CACHING).
		 *		AcknowledgeRequired = TRUE.
		 *		OplockCompletionStatus = STATUS_SUCCESS.
		 *	(The operation does not end at this point;
		 *	 this call to 2.1.5.17.3 completes some
		 *	 earlier call to 2.1.5.17.1.)
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			HANDLE_CACHING|EXCLUSIVE|
		 *			BREAK_TO_READ_CACHING|
		 *			BREAK_TO_HANDLE_CACHING).
		 *	Set NeedToWait to TRUE.
		 */
		if (BreakCacheLevel == WRITE_CACHING) {
			o = nol->excl_open;
			ASSERT(o != NULL);
			smb_oplock_ind_break(o,
			    CACHE_RH, B_TRUE,
			    NT_STATUS_SUCCESS);

			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|
			    EXCLUSIVE|BREAK_TO_READ_CACHING|
			    BREAK_TO_HANDLE_CACHING);
			NeedToWait = B_TRUE;
		}

		/*
		 * Else If BreakCacheLevel equals HANDLE_CACHING:
		 *	Notify the server of an oplock break according to
		 *	  the algorithm in section 2.1.5.17.3, setting the
		 *	  algorithm's parameters as follows:
		 *		BreakingOplockOpen = Oplock.ExclusiveOpen.
		 *		NewOplockLevel = (READ_CACHING|WRITE_CACHING).
		 *		AcknowledgeRequired = TRUE.
		 *		OplockCompletionStatus = STATUS_SUCCESS.
		 *	(The operation does not end at this point;
		 *	 this call to 2.1.5.17.3 completes some
		 *	 earlier call to 2.1.5.17.1.)
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			HANDLE_CACHING|EXCLUSIVE|
		 *			BREAK_TO_READ_CACHING|
		 *			BREAK_TO_WRITE_CACHING).
		 *	Set NeedToWait to TRUE.
		 */
		else if (BreakCacheLevel == HANDLE_CACHING) {
			o = nol->excl_open;
			ASSERT(o != NULL);
			smb_oplock_ind_break(o,
			    CACHE_RW, B_TRUE,
			    NT_STATUS_SUCCESS);

			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|
			    EXCLUSIVE|BREAK_TO_READ_CACHING|
			    BREAK_TO_WRITE_CACHING);
			NeedToWait = B_TRUE;
		}

		/*
		 * Else If BreakCacheLevel contains both
		 *  READ_CACHING and WRITE_CACHING:
		 *	Notify the server of an oplock break according to
		 *	  the algorithm in section 2.1.5.17.3, setting the
		 *	  algorithm's parameters as follows:
		 *		BreakingOplockOpen = Oplock.ExclusiveOpen.
		 *		NewOplockLevel = LEVEL_NONE.
		 *		AcknowledgeRequired = TRUE.
		 *		OplockCompletionStatus = STATUS_SUCCESS.
		 *	(The operation does not end at this point;
		 *	 this call to 2.1.5.17.3 completes some
		 *	 earlier call to 2.1.5.17.1.)
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			HANDLE_CACHING|EXCLUSIVE|
		 *			BREAK_TO_NO_CACHING).
		 *	Set NeedToWait to TRUE.
		 * EndIf
		 */
		else if ((BreakCacheLevel & (READ_CACHING | WRITE_CACHING)) ==
		    (READ_CACHING | WRITE_CACHING)) {
			o = nol->excl_open;
			ASSERT(o != NULL);
			smb_oplock_ind_break(o,
			    LEVEL_NONE, B_TRUE,
			    NT_STATUS_SUCCESS);

			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|
			    EXCLUSIVE|BREAK_TO_NO_CACHING);
			NeedToWait = B_TRUE;
		}
		break;

	case (READ_CACHING|WRITE_CACHING|EXCLUSIVE|BREAK_TO_READ_CACHING):
		/*
		 * If BreakCacheLevel contains READ_CACHING:
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			EXCLUSIVE|BREAK_TO_NO_CACHING).
		 * EndIf
		 * If BreakCacheLevel contains either
		 *  READ_CACHING or WRITE_CACHING:
		 *	Set NeedToWait to TRUE.
		 * EndIf
		 */
		if ((BreakCacheLevel & READ_CACHING) != 0) {
			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|
			    EXCLUSIVE|BREAK_TO_NO_CACHING);
		}
		if ((BreakCacheLevel & (READ_CACHING | WRITE_CACHING)) != 0) {
			NeedToWait = B_TRUE;
		}
		break;

	case (READ_CACHING|WRITE_CACHING|EXCLUSIVE|BREAK_TO_NO_CACHING):
		/*
		 * If BreakCacheLevel contains either
		 *  READ_CACHING or WRITE_CACHING:
		 *	Set NeedToWait to TRUE.
		 * EndIf
		 */
		if ((BreakCacheLevel & (READ_CACHING | WRITE_CACHING)) != 0) {
			NeedToWait = B_TRUE;
		}
		break;

	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_READ_CACHING|BREAK_TO_WRITE_CACHING):
		/*
		 * If BreakCacheLevel == WRITE_CACHING:
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *	    HANDLE_CACHING|EXCLUSIVE|BREAK_TO_READ_CACHING).
		 * Else If BreakCacheLevel contains both
		 *  READ_CACHING and WRITE_CACHING:
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *	    HANDLE_CACHING|EXCLUSIVE|BREAK_TO_NO_CACHING).
		 * EndIf
		 * Set NeedToWait to TRUE.
		 */
		if (BreakCacheLevel == WRITE_CACHING) {
			nol->ol_state = (READ_CACHING|WRITE_CACHING|
			    HANDLE_CACHING|EXCLUSIVE|BREAK_TO_READ_CACHING);
		}
		else if ((BreakCacheLevel & (READ_CACHING | WRITE_CACHING)) ==
		    (READ_CACHING | WRITE_CACHING)) {
			nol->ol_state = (READ_CACHING|WRITE_CACHING|
			    HANDLE_CACHING|EXCLUSIVE|BREAK_TO_NO_CACHING);
		}
		NeedToWait = B_TRUE;
		break;

	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_READ_CACHING|BREAK_TO_HANDLE_CACHING):
		/*
		 * If BreakCacheLevel == HANDLE_CACHING:
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			HANDLE_CACHING|EXCLUSIVE|
		 *			BREAK_TO_READ_CACHING).
		 * Else If BreakCacheLevel contains READ_CACHING:
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			HANDLE_CACHING|EXCLUSIVE|
		 *			BREAK_TO_NO_CACHING).
		 * EndIf
		 * Set NeedToWait to TRUE.
		 */
		if (BreakCacheLevel == HANDLE_CACHING) {
			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|
			    HANDLE_CACHING|EXCLUSIVE|
			    BREAK_TO_READ_CACHING);
		}
		else if ((BreakCacheLevel & READ_CACHING) != 0) {
			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|
			    HANDLE_CACHING|EXCLUSIVE|
			    BREAK_TO_NO_CACHING);
		}
		NeedToWait = B_TRUE;
		break;

	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_READ_CACHING):
		/*
		 * If BreakCacheLevel contains READ_CACHING,
		 *	Set Oplock.State to (READ_CACHING|WRITE_CACHING|
		 *			HANDLE_CACHING|EXCLUSIVE|
		 *			BREAK_TO_NO_CACHING).
		 * EndIf
		 * Set NeedToWait to TRUE.
		 */
		if ((BreakCacheLevel & READ_CACHING) != 0) {
			nol->ol_state =
			    (READ_CACHING|WRITE_CACHING|
			    HANDLE_CACHING|EXCLUSIVE|
			    BREAK_TO_NO_CACHING);
		}
		NeedToWait = B_TRUE;
		break;

	case (READ_CACHING|WRITE_CACHING|HANDLE_CACHING|EXCLUSIVE|
	    BREAK_TO_NO_CACHING):
		NeedToWait = B_TRUE;
		break;

	} /* Switch */

	if (NeedToWait) {
		/*
		 * The operation that called this algorithm MUST be
		 *   made cancelable by inserting it into
		 *   CancelableOperations.CancelableOperationList.
		 * The operation that called this algorithm waits until
		 *   the oplock break is acknowledged, as specified in
		 *   section 2.1.5.18, or the operation is canceled.
		 */
		status = NT_STATUS_OPLOCK_BREAK_IN_PROGRESS;
		/* Caller does smb_oplock_wait_break() */
	}

out:
	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

	return (status);
}

/*
 * smb_oplock_move()
 *
 * Helper function for smb2_lease_ofile_close, where we're closing the
 * ofile that has the oplock for a given lease, and need to move that
 * oplock to another handle with the same lease.
 *
 * This is not described in [MS-FSA], so presumably Windows does this
 * by keeping oplock objects separate from the open files (no action
 * needed in the FSA layer).  We keep the oplock state as part of the
 * ofile, so we need to relocate the oplock state in this case.
 *
 * Note that in here, we're moving state for both the FSA level and
 * the SMB level (which is unusual) but this is the easiest way to
 * make sure we move the state without any other effects.
 */
void
smb_oplock_move(smb_node_t *node,
    smb_ofile_t *fr_ofile, smb_ofile_t *to_ofile)
{
	/*
	 * These are the two common states for an ofile with
	 * a lease that's not the one holding the oplock.
	 * Log if it's not either of these.
	 */
	static const smb_oplock_grant_t og0 = { 0 };
	static const smb_oplock_grant_t og8 = {
	    .og_state = OPLOCK_LEVEL_GRANULAR, 0 };
	smb_oplock_grant_t og_tmp;

	ASSERT(fr_ofile->f_node == node);
	ASSERT(to_ofile->f_node == node);

	mutex_enter(&node->n_oplock.ol_mutex);

	/*
	 * The ofile to which we're moving the oplock
	 * should NOT have any oplock state.  However,
	 * as long as we just swap state between the
	 * two oplocks, we won't invalidate any of
	 * the node's "onlist" counts etc.
	 */
	if (bcmp(&to_ofile->f_oplock, &og0, sizeof (og0)) != 0 &&
	    bcmp(&to_ofile->f_oplock, &og8, sizeof (og8)) != 0) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "smb_oplock_move: not empty?");
#endif
		DTRACE_PROBE2(dst__not__empty,
		    smb_node_t, node, smb_ofile_t, to_ofile);
	}

	og_tmp = to_ofile->f_oplock;
	to_ofile->f_oplock = fr_ofile->f_oplock;
	fr_ofile->f_oplock = og_tmp;

	if (node->n_oplock.excl_open == fr_ofile)
		node->n_oplock.excl_open = to_ofile;

	mutex_exit(&node->n_oplock.ol_mutex);
}
