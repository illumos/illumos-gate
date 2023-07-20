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
 * Copyright 2021 Tintri by DDN, Inc.  All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

/*
 * Dispatch function for SMB2_OPLOCK_BREAK
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_oplock.h>

/* StructSize for the two "break" message formats. */
#define	SSZ_OPLOCK	24
#define	SSZ_LEASE_ACK	36
#define	SSZ_LEASE_BRK	44

#define	NODE_FLAGS_DELETING	(NODE_FLAGS_DELETE_ON_CLOSE |\
				NODE_FLAGS_DELETE_COMMITTED)

static const char lease_zero[UUID_LEN] = { 0 };

static kmem_cache_t	*smb_lease_cache = NULL;

void
smb2_lease_init()
{
	if (smb_lease_cache != NULL)
		return;

	smb_lease_cache = kmem_cache_create("smb_lease_cache",
	    sizeof (smb_lease_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
}

void
smb2_lease_fini()
{
	if (smb_lease_cache != NULL) {
		kmem_cache_destroy(smb_lease_cache);
		smb_lease_cache = NULL;
	}
}

static void
smb2_lease_hold(smb_lease_t *ls)
{
	mutex_enter(&ls->ls_mutex);
	ls->ls_refcnt++;
	mutex_exit(&ls->ls_mutex);
}

static void
lease_destroy(smb_lease_t *ls)
{
	smb_node_release(ls->ls_node);
	mutex_destroy(&ls->ls_mutex);
	kmem_cache_free(smb_lease_cache, ls);
}

void
smb2_lease_rele(smb_lease_t *ls)
{
	smb_llist_t *bucket;
	boolean_t destroy = B_FALSE;

	mutex_enter(&ls->ls_mutex);
	ls->ls_refcnt--;
	if (ls->ls_refcnt != 0) {
		mutex_exit(&ls->ls_mutex);
		return;
	}
	mutex_exit(&ls->ls_mutex);

	/*
	 * Get the list lock, then re-check the refcnt
	 * and if it's still zero, unlink & destroy.
	 */
	bucket = ls->ls_bucket;
	smb_llist_enter(bucket, RW_WRITER);

	mutex_enter(&ls->ls_mutex);
	if (ls->ls_refcnt == 0) {
		smb_llist_remove(bucket, ls);
		destroy = B_TRUE;
	}
	mutex_exit(&ls->ls_mutex);

	smb_llist_exit(bucket);

	if (destroy) {
		lease_destroy(ls);
	}
}

/*
 * Compute a hash from a uuid
 * Based on mod_hash_bystr()
 */
static uint_t
smb_hash_uuid(const uint8_t *uuid)
{
	char *k = (char *)uuid;
	uint_t hash = 0;
	uint_t g;
	int i;

	ASSERT(k);
	for (i = 0; i < UUID_LEN; i++) {
		hash = (hash << 4) + k[i];
		if ((g = (hash & 0xf0000000)) != 0) {
			hash ^= (g >> 24);
			hash ^= g;
		}
	}
	return (hash);
}

/*
 * Add or update a lease table entry for a new ofile.
 * (in the per-session lease table)
 * See [MS-SMB2] 3.3.5.9.8
 * Handling the SMB2_CREATE_REQUEST_LEASE Create Context
 */
uint32_t
smb2_lease_create(smb_request_t *sr, uint8_t *clnt)
{
	smb_arg_open_t *op = &sr->arg.open;
	uint8_t *key = op->lease_key;
	smb_ofile_t *of = sr->fid_ofile;
	smb_hash_t *ht = sr->sr_server->sv_lease_ht;
	smb_llist_t *bucket;
	smb_lease_t *lease;
	smb_lease_t *newlease;
	size_t hashkey;
	uint32_t status = NT_STATUS_INVALID_PARAMETER;

	if (bcmp(key, lease_zero, UUID_LEN) == 0)
		return (status);

	/*
	 * Find or create, and add a ref for the new ofile.
	 */
	hashkey = smb_hash_uuid(key);
	hashkey &= (ht->num_buckets - 1);
	bucket = &ht->buckets[hashkey].b_list;

	newlease = kmem_cache_alloc(smb_lease_cache, KM_SLEEP);
	bzero(newlease, sizeof (smb_lease_t));
	mutex_init(&newlease->ls_mutex, NULL, MUTEX_DEFAULT, NULL);
	newlease->ls_bucket = bucket;
	newlease->ls_node = of->f_node;
	smb_node_ref(newlease->ls_node);
	newlease->ls_refcnt = 1;
	newlease->ls_epoch = op->lease_epoch;
	newlease->ls_version = op->lease_version;
	bcopy(key, newlease->ls_key, UUID_LEN);
	bcopy(clnt, newlease->ls_clnt, UUID_LEN);

	smb_llist_enter(bucket, RW_WRITER);
	for (lease = smb_llist_head(bucket); lease != NULL;
	    lease = smb_llist_next(bucket, lease)) {
		/*
		 * Looking for this lease ID, on a node
		 * that's not being deleted.
		 */
		if (bcmp(lease->ls_key, key, UUID_LEN) == 0 &&
		    bcmp(lease->ls_clnt, clnt, UUID_LEN) == 0 &&
		    (lease->ls_node->flags & NODE_FLAGS_DELETING) == 0)
			break;
	}
	if (lease != NULL) {
		/*
		 * Found existing lease.  Make sure it refers to
		 * the same node...
		 */
		if (lease->ls_node == of->f_node) {
			smb2_lease_hold(lease);
		} else {
			/* Same lease ID, different node! */
#ifdef DEBUG
			cmn_err(CE_NOTE, "new lease on node %p (%s) "
			    "conflicts with existing node %p (%s)",
			    (void *) of->f_node,
			    of->f_node->od_name,
			    (void *) lease->ls_node,
			    lease->ls_node->od_name);
#endif
			DTRACE_PROBE2(dup_lease, smb_request_t *, sr,
			    smb_lease_t *, lease);
			lease = NULL; /* error */
		}
	} else {
		lease = newlease;
		smb_llist_insert_head(bucket, lease);
		newlease = NULL; /* don't free */
	}
	smb_llist_exit(bucket);

	if (newlease != NULL) {
		lease_destroy(newlease);
	}

	if (lease != NULL) {
		of->f_lease = lease;
		status = NT_STATUS_SUCCESS;
	}

	return (status);
}

/*
 * Find the lease for a given: client_uuid, lease_key
 * Returns the lease with a new ref.
 */
static smb_lease_t *
lease_lookup(smb_request_t *sr, uint8_t *lease_key)
{
	smb_server_t *sv = sr->sr_server;
	uint8_t *clnt_uuid = sr->session->clnt_uuid;
	smb_hash_t *ht = sv->sv_lease_ht;
	smb_llist_t *bucket;
	smb_lease_t *lease;
	size_t hashkey;

	hashkey = smb_hash_uuid(lease_key);
	hashkey &= (ht->num_buckets - 1);
	bucket = &ht->buckets[hashkey].b_list;

	smb_llist_enter(bucket, RW_READER);
	lease = smb_llist_head(bucket);
	while (lease != NULL) {
		if (bcmp(lease->ls_key, lease_key, UUID_LEN) == 0 &&
		    bcmp(lease->ls_clnt, clnt_uuid, UUID_LEN) == 0) {
			smb2_lease_hold(lease);
			break;
		}
		lease = smb_llist_next(bucket, lease);
	}
	smb_llist_exit(bucket);

	return (lease);
}

/*
 * Find the oplock smb_ofile_t for the specified lease.
 * If no such ofile, NT_STATUS_UNSUCCESSFUL.
 * On success, ofile (held) in sr->fid_ofile.
 */
static uint32_t
lease_find_oplock(smb_request_t *sr, smb_lease_t *lease)
{
	smb_node_t	*node = lease->ls_node;
	smb_ofile_t	*o;
	uint32_t	status = NT_STATUS_UNSUCCESSFUL;

	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));
	ASSERT(sr->fid_ofile == NULL);

	FOREACH_NODE_OFILE(node, o) {
		if (o->f_lease != lease)
			continue;
		if (o != lease->ls_oplock_ofile)
			continue;
		/*
		 * Found the ofile holding the oplock
		 * This hold released in smb_request_free
		 */
		if (smb_ofile_hold_olbrk(o)) {
			sr->fid_ofile = o;
			status = NT_STATUS_SUCCESS;
			break;
		}
	}

	return (status);
}

/*
 * This is called by smb2_oplock_break_ack when the struct size
 * indicates this is a lease break (SZ_LEASE).  See:
 * [MS-SMB2] 3.3.5.22.2 Processing a Lease Acknowledgment
 * This is an "Ack" from the client.
 */
smb_sdrc_t
smb2_lease_break_ack(smb_request_t *sr)
{
	smb_arg_olbrk_t	*olbrk = &sr->arg.olbrk;
	smb_lease_t *lease;
	smb_node_t  *node;
	smb_ofile_t *ofile;
	uint32_t LeaseState;
	uint32_t status;
	int rc = 0;

	if (sr->session->dialect < SMB_VERS_2_1)
		return (SDRC_ERROR);

	/*
	 * Decode an SMB2 Lease Acknowldgement
	 * [MS-SMB2] 2.2.24.2
	 * Note: Struct size decoded by caller.
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "6.#cl8.",
	    /* reserved		  6. */
	    UUID_LEN,		/* # */
	    olbrk->LeaseKey,	/* c */
	    &olbrk->NewLevel);	/* l */
	    /* duration		  8. */
	if (rc != 0)
		return (SDRC_ERROR);
	LeaseState = olbrk->NewLevel;

	/*
	 * Find the lease via the given key.
	 */
	lease = lease_lookup(sr, olbrk->LeaseKey);
	if (lease == NULL) {
		/*
		 * It's unusual to skip the dtrace start/done
		 * probes like this, but trying to run them
		 * with no lease->node would be complex and
		 * would not show anything particularly useful.
		 * Do the start probe after we find the ofile.
		 */
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}
	// Note: lease ref; smb_lease_rele() below.
	node = lease->ls_node;

	/*
	 * Find the leased oplock.  Hold locks so it can't move
	 * until we're done with ACK-break processing.
	 */
	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	status = lease_find_oplock(sr, lease);
	/* Normally have sr->fid_ofile now. */

	DTRACE_SMB2_START(op__OplockBreak, smb_request_t *, sr);

	if (status != 0) {
		/* Leased oplock not found.  Must have closed. */
		goto errout;
	}

	/* Success, so have sr->fid_ofile */
	ofile = sr->fid_ofile;

	if (lease->ls_breaking == B_FALSE) {
		/*
		 * This ACK is either unsolicited or too late,
		 * eg. we timed out the ACK and did it locally.
		 */
		status = NT_STATUS_UNSUCCESSFUL;
		goto errout;
	}

	/*
	 * If the new LeaseState has any bits in excess of
	 * the lease state we sent in the break, error...
	 */
	if ((LeaseState & ~(lease->ls_breakto)) != 0) {
		status = NT_STATUS_REQUEST_NOT_ACCEPTED;
		goto errout;
	}

	/*
	 * Process the lease break ack.
	 *
	 * Clear breaking flags before we ack,
	 * because ack might set those.
	 * Signal both CVs, out of paranoia.
	 */
	ofile->f_oplock.og_breaking = B_FALSE;
	cv_broadcast(&ofile->f_oplock.og_ack_cv);
	lease->ls_breaking = B_FALSE;
	cv_broadcast(&lease->ls_ack_cv);

	LeaseState |= OPLOCK_LEVEL_GRANULAR;
	status = smb_oplock_ack_break(sr, ofile, &LeaseState);

	ofile->f_oplock.og_state = LeaseState;
	lease->ls_state = LeaseState;
	/* ls_epoch does not change here */

	if (ofile->dh_persist)
		smb2_dh_update_oplock(sr, ofile);

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__OplockBreak, smb_request_t *, sr);

	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

	smb2_lease_rele(lease);

	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * Encode an SMB2 Lease Ack. response
	 * [MS-SMB2] 2.2.25.2
	 */
	LeaseState &= OPLOCK_LEVEL_CACHE_MASK;
	(void) smb_mbc_encodef(
	    &sr->reply, "w6.#cl8.",
	    SSZ_LEASE_ACK,	/* w */
	    /* reserved		  6. */
	    UUID_LEN,		/* # */
	    olbrk->LeaseKey,	/* c */
	    LeaseState);	/* l */
	    /* duration		  8. */

	return (SDRC_SUCCESS);

}

/*
 * Compose an SMB2 Lease Break Notification packet, including
 * the SMB2 header and everything, in sr->reply.
 * The caller will send it and free the request.
 *
 * [MS-SMB2] 2.2.23.2 Lease Break Notification
 */
static void
smb2_lease_break_notification(smb_request_t *sr,
    uint32_t OldLevel, uint32_t NewLevel,
    uint16_t Epoch, boolean_t AckReq)
{
	smb_lease_t *ls = sr->fid_ofile->f_lease;
	uint16_t Flags = 0;

	/*
	 * Convert internal lease info to SMB2
	 */
	if (AckReq)
		Flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;
	if (ls->ls_version < 2)
		Epoch = 0;
	OldLevel &= OPLOCK_LEVEL_CACHE_MASK;
	NewLevel &= OPLOCK_LEVEL_CACHE_MASK;

	/*
	 * SMB2 Header
	 */
	sr->smb2_cmd_code = SMB2_OPLOCK_BREAK;
	sr->smb2_hdr_flags = SMB2_FLAGS_SERVER_TO_REDIR;
	sr->smb_tid = 0;
	sr->smb_pid = 0;
	sr->smb2_ssnid = 0;
	sr->smb2_messageid = UINT64_MAX;
	(void) smb2_encode_header(sr, B_FALSE);

	/*
	 * SMB2 Oplock Break, variable part
	 *
	 * [MS-SMB2] says the current lease state preceeds the
	 * new lease state, but that looks like an error...
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "wwl#cll4.4.4.",
	    SSZ_LEASE_BRK,		/* w */
	    Epoch,			/* w */
	    Flags,			/* l */
	    SMB_LEASE_KEY_SZ,		/* # */
	    ls->ls_key,			/* c */
	    OldLevel,		/* cur.st  l */
	    NewLevel);		/* new.st  l */
	    /* reserved (4.4.4.) */
}

/*
 * Do our best to send a lease break message to the client.
 * When we get to multi-channel, this is supposed to try
 * every channel before giving up.  For now, try every
 * connected session with an ofile sharing this lease.
 *
 * If this ofile has a valid session, try that first.
 * Otherwise look on the node list for other ofiles with
 * the same lease and a connected session.
 */
static int
lease_send_any_cn(smb_request_t *sr)
{
	smb_ofile_t	*o;
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_lease_t	*lease = ofile->f_lease;
	smb_node_t	*node = ofile->f_node;
	int		rc = ENOTCONN;

	/*
	 * If the passed oplock ofile has a session,
	 * this IF expression will be true.
	 */
	if (sr->session == ofile->f_session) {
		rc = smb_session_send(sr->session, 0, &sr->reply);
		if (rc == 0)
			return (rc);
	}

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	FOREACH_NODE_OFILE(node, o) {
		if (o->f_lease != lease)
			continue;
		if (smb_ofile_hold(o)) {
			/* Has a session. */
			rc = smb_session_send(o->f_session, 0, &sr->reply);
			smb_llist_post(&node->n_ofile_list, o,
			    smb_ofile_release_LL);
		}
		if (rc == 0)
			break;
	}
	smb_llist_exit(&node->n_ofile_list);

	return (rc);
}

/*
 * See smb_llist_post on node->n_ofile_list below.
 * Can't call smb_ofile_close with that list entered.
 */
static void
lease_ofile_close_rele(void *arg)
{
	smb_ofile_t *of = (smb_ofile_t *)arg;

	smb_ofile_close(of, 0);
	smb_ofile_release(of);
}

/*
 * [MS-SMB2] 3.3.4.7 Object Store Indicates a Lease Break
 * If no connection, for each Open in Lease.LeaseOpens,
 * the server MUST close the Open as specified in sec...
 * for the following cases:
 * - Open.IsDurable, Open.IsResilient, and
 *   Open.IsPersistent are all FALSE.
 * - Open.IsDurable is TRUE and Lease.BreakToLeaseState
 *   does not contain SMB2_LEASE_HANDLE_CACHING and
 */
static void
lease_close_notconn(smb_request_t *sr, uint32_t NewLevel)
{
	smb_ofile_t	*o;
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_lease_t	*lease = ofile->f_lease;
	smb_node_t	*node = ofile->f_node;

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	FOREACH_NODE_OFILE(node, o) {
		if (o->f_lease != lease)
			continue;
		if (o->f_oplock_closing)
			continue;
		if (o->dh_persist)
			continue;
		if (o->dh_vers == SMB2_RESILIENT)
			continue;
		if (o->dh_vers == SMB2_NOT_DURABLE ||
		    (NewLevel & OPLOCK_LEVEL_CACHE_HANDLE) == 0) {
			if (smb_ofile_hold_olbrk(o)) {
				smb_llist_post(&node->n_ofile_list, o,
				    lease_ofile_close_rele);
			}
		}
	}
	smb_llist_exit(&node->n_ofile_list);
}

/*
 * Send a lease break over the wire, or if we can't,
 * then process the lease break locally.
 *
 * [MS-SMB2] 3.3.4.7 Object Store Indicates a Lease Break
 *
 * This is mostly similar to smb2_oplock_send_break()
 * See top comment there about the design.
 *
 * Differences beween a lease break and oplock break:
 *
 * Leases are an SMB-level mechanism whereby multiple open
 * SMB file handles can share an oplock.  All SMB handles
 * on the lease enjoy the same caching rights.  Down at the
 * file-system level, just one oplock holds the cache rights
 * for a lease, but (this is the tricky part) that oplock can
 * MOVE among the SMB file handles sharing the lease. Such
 * oplock moves can happen when a handle is closed (if that
 * handle is the one with the oplock) or when a new open on
 * the lease causes an upgrade of the caching rights.
 *
 * We have to deal here with lease movement because this call
 * happens asynchronously after the smb_oplock_ind_break call,
 * meaning that the oplock for the lease may have moved by the
 * time this runs.  In addition, the ofile holding the oplock
 * might not be the best one to use to send a lease break.
 * If the oplock is held by a handle that's "orphaned" and
 * there are other handles on the lease with active sessions,
 * we want to send the lease break on an active session.
 *
 * Also note: NewLevel (as provided by smb_oplock_ind_break etc.)
 * does NOT include the GRANULAR flag.  This level is expected to
 * keep track of how each oplock was acquired (by lease or not)
 * and put the GRANULAR flag back in when appropriate.
 */
void
smb2_lease_send_break(smb_request_t *sr)
{
	smb_ofile_t	*old_ofile;
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_node_t	*node = ofile->f_node;
	smb_lease_t	*lease = ofile->f_lease;
	smb_arg_olbrk_t	*olbrk = &sr->arg.olbrk;
	boolean_t	AckReq = olbrk->AckRequired;
	uint32_t	OldLevel = olbrk->OldLevel;
	uint32_t	NewLevel = olbrk->NewLevel;
	uint32_t	status;
	int		rc;

	NewLevel |= OPLOCK_LEVEL_GRANULAR;

	/*
	 * Build the break message in sr->reply.
	 * It's free'd in smb_request_free().
	 * Always an SMB2 lease here.
	 */
	sr->reply.max_bytes = MLEN;
	smb2_lease_break_notification(sr,
	    OldLevel, NewLevel, lease->ls_epoch, AckReq);

	/*
	 * Try to send the break message to the client,
	 * on any connection with this lease.
	 */
	rc = lease_send_any_cn(sr);
	if (rc != 0) {
		/*
		 * We were unable to send the oplock break request,
		 * presumably because the connection is gone.
		 * Close uninteresting handles.
		 */
		lease_close_notconn(sr, NewLevel);
		/* Note: some handles may remain on the lease. */
		if (!AckReq)
			return;
		/* Do local Ack below. */
	} else {
		/*
		 * OK, we were able to send the break message.
		 * If no ack. required, we're done.
		 */
		if (!AckReq)
			return;

		/*
		 * We're expecting an ACK.  Wait in this thread
		 * so we can log clients that don't respond.
		 * Note: this can also fail for other reasons
		 * such as client disconnect or server shutdown.
		 */
		status = smb_oplock_wait_ack(sr, NewLevel);
		if (status == 0)
			return;

		DTRACE_PROBE2(wait__ack__failed, smb_request_t *, sr,
		    uint32_t, status);

		/*
		 * Will do local ack below.  Note, after timeout,
		 * do a break to none or "no caching" regardless
		 * of what the passed in cache level was.
		 * That means: clear all except GRANULAR.
		 */
		NewLevel = OPLOCK_LEVEL_GRANULAR;
	}

	/*
	 * Do the ack locally.
	 *
	 * Find the ofile with the leased oplock
	 * (may have moved before we took locks)
	 */
	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	old_ofile = ofile;
	sr->fid_ofile = NULL;
	status = lease_find_oplock(sr, lease);
	if (status != 0) {
		/* put back old_ofile */
		sr->fid_ofile = old_ofile;
		goto unlock_out;
	}
	smb_llist_post(&node->n_ofile_list, old_ofile,
	    smb_ofile_release_LL);

	ofile = sr->fid_ofile;

	/*
	 * Now continue like the non-lease code
	 */
	ofile->f_oplock.og_breaking = B_FALSE;
	lease->ls_breaking = B_FALSE;
	cv_broadcast(&lease->ls_ack_cv);

	status = smb_oplock_ack_break(sr, ofile, &NewLevel);

	ofile->f_oplock.og_state = NewLevel;
	lease->ls_state = NewLevel;
	/* ls_epoch does not change here */

	if (ofile->dh_persist)
		smb2_dh_update_oplock(sr, ofile);

unlock_out:
	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

#ifdef	DEBUG
	if (status != 0) {
		cmn_err(CE_NOTE, "clnt %s local oplock ack, status=0x%x",
		    sr->session->ip_addr_str, status);
	}
#endif
}

/*
 * Client has an open handle and requests a lease.
 * Convert SMB2 lease request info in to internal form,
 * call common oplock code, convert result to SMB2.
 *
 * If necessary, "go async" here (at the end).
 */
void
smb2_lease_acquire(smb_request_t *sr)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *ofile = sr->fid_ofile;
	smb_lease_t *lease = ofile->f_lease;
	smb_node_t *node = ofile->f_node;
	uint32_t status = NT_STATUS_OPLOCK_NOT_GRANTED;
	uint32_t have, want; /* lease flags */
	boolean_t NewGrant = B_FALSE;

	/* Only disk trees get oplocks. */
	ASSERT((sr->tid_tree->t_res_type & STYPE_MASK) == STYPE_DISKTREE);

	/*
	 * Only plain files (for now).
	 * Later, test SMB2_CAP_DIRECTORY_LEASING
	 */
	if (!smb_node_is_file(ofile->f_node)) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_OPLOCKS)) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	/*
	 * SMB2: Convert to internal form.
	 * Caller should have setup the lease.
	 */
	ASSERT(op->op_oplock_level == SMB2_OPLOCK_LEVEL_LEASE);
	ASSERT(lease != NULL);
	if (lease == NULL) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}
	op->op_oplock_state = OPLOCK_LEVEL_GRANULAR |
	    (op->lease_state & CACHE_RWH);

	/*
	 * Tree options may force shared oplocks,
	 * in which case we reduce the request.
	 */
	if (smb_tree_has_feature(sr->tid_tree, SMB_TREE_FORCE_L2_OPLOCK)) {
		op->op_oplock_state &= ~WRITE_CACHING;
	}

	/*
	 * Using the "Locks Held" (LH) variant of smb_oplock_request
	 * below so things won't change underfoot.
	 */
	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	/*
	 * MS-SMB2 3.3.5.9.8 and 3.3.5.9.11 Lease (V2) create contexts
	 *
	 * If the caching state requested in LeaseState of the (create ctx)
	 * is not a superset of Lease.LeaseState or if Lease.Breaking is TRUE,
	 * the server MUST NOT promote Lease.LeaseState. If the lease state
	 * requested is a superset of Lease.LeaseState and Lease.Breaking is
	 * FALSE, the server MUST request promotion of the lease state from
	 * the underlying object store to the new caching state.
	 */
	have = lease->ls_state & CACHE_RWH;
	want = op->op_oplock_state & CACHE_RWH;
	if ((have & ~want) != 0 || lease->ls_breaking) {
		op->op_oplock_state = have |
		    OPLOCK_LEVEL_GRANULAR;
		goto done;
	}

	/*
	 * Handle oplock requests in three parts:
	 *	a: Requests with WRITE_CACHING
	 *	b: Requests with HANDLE_CACHING
	 *	c: Requests with READ_CACHING
	 * reducing the request before b and c.
	 *
	 * In each: first check if the lease grants the
	 * (possibly reduced) request, in which case we
	 * leave the lease unchanged and return what's
	 * granted by the lease.  Otherwise, try to get
	 * the oplock, and if the succeeds, wait for any
	 * breaks, update the lease, and return.
	 */

	/*
	 * Try exclusive (request is RW or RWH)
	 */
	if ((op->op_oplock_state & WRITE_CACHING) != 0) {
		/* Alread checked (want & ~have) */

		status = smb_oplock_request_LH(sr, ofile,
		    &op->op_oplock_state);
		if (status == NT_STATUS_SUCCESS ||
		    status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
			NewGrant = B_TRUE;
			goto done;
		}

		/*
		 * We did not get the exclusive oplock.
		 *
		 * There are odd rules about lease upgrade.
		 * If the existing lease grants R and the
		 * client fails to upgrade it to "RWH"
		 * (presumably due to handle conflicts)
		 * then just return the existing lease,
		 * even though upgrade to RH would work.
		 */
		if (have != 0) {
			op->op_oplock_state = have |
			    OPLOCK_LEVEL_GRANULAR;
			goto done;
		}

		/*
		 * Keep trying without write.
		 * Need to re-init op_oplock_state
		 */
		op->op_oplock_state = OPLOCK_LEVEL_GRANULAR |
		    (op->lease_state & CACHE_RH);
	}

	/*
	 * Try shared ("RH")
	 */
	if ((op->op_oplock_state & HANDLE_CACHING) != 0) {
		want = op->op_oplock_state & CACHE_RWH;
		if ((want & ~have) == 0)
			goto done;

		status = smb_oplock_request_LH(sr, ofile,
		    &op->op_oplock_state);
		if (status == NT_STATUS_SUCCESS ||
		    status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
			NewGrant = B_TRUE;
			goto done;
		}

		/*
		 * We did not get "RH", probably because
		 * ther were (old style) Level II oplocks.
		 * Continue, try for just read.
		 * Again, re-init op_oplock_state
		 */
		op->op_oplock_state = OPLOCK_LEVEL_GRANULAR |
		    (op->lease_state & CACHE_R);
	}

	/*
	 * Try shared ("R")
	 */
	if ((op->op_oplock_state & READ_CACHING) != 0) {
		want = op->op_oplock_state & CACHE_RWH;
		if ((want & ~have) == 0)
			goto done;

		status = smb_oplock_request_LH(sr, ofile,
		    &op->op_oplock_state);
		if (status == NT_STATUS_SUCCESS ||
		    status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
			NewGrant = B_TRUE;
			goto done;
		}

		/*
		 * We did not get "R".
		 * Fall into "none".
		 */
	}

	/*
	 * None of the above were able to get an oplock.
	 * The lease has no caching rights, and we didn't
	 * add any in this request.  Return it as-is.
	 */
	op->op_oplock_state = OPLOCK_LEVEL_GRANULAR;

done:
	/*
	 * Only success cases get here
	 */

	/*
	 * Keep track of what we got (ofile->f_oplock.og_state etc)
	 * so we'll know what we had when sending a break later.
	 * Also keep a copy of some things in the lease.
	 *
	 * Not using og_dialect here, as ofile->f_lease tells us
	 * this has to be using granular oplocks.
	 */
	if (NewGrant) {
		ofile->f_oplock.og_state   = op->op_oplock_state;
		ofile->f_oplock.og_breakto = op->op_oplock_state;
		ofile->f_oplock.og_breaking = B_FALSE;

		lease->ls_oplock_ofile = ofile;
		lease->ls_state   = ofile->f_oplock.og_state;
		lease->ls_breakto = ofile->f_oplock.og_breakto;
		lease->ls_breaking = B_FALSE;
		lease->ls_epoch++;

		if (ofile->dh_persist) {
			smb2_dh_update_oplock(sr, ofile);
		}
	}

	/*
	 * Convert internal oplock state to SMB2
	 */
	op->op_oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
	op->lease_state = lease->ls_state & CACHE_RWH;
	op->lease_flags = (lease->ls_breaking != 0) ?
	    SMB2_LEASE_FLAG_BREAK_IN_PROGRESS : 0;
	op->lease_epoch = lease->ls_epoch;
	op->lease_version = lease->ls_version;

	/*
	 * End of lock-held region
	 */
	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

	/*
	 * After a new oplock grant, the status return
	 * may indicate we need to wait for breaks.
	 */
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb2sr_go_async(sr);
		(void) smb_oplock_wait_break(sr, ofile->f_node, 0);
	}
}

/*
 * This ofile has a lease and is about to close.
 * Called by smb_ofile_close when there's a lease.
 *
 * Note that a client may close an ofile in response to an
 * oplock break or lease break intead of doing an Ack break,
 * so this must wake anything that might be waiting on an ack
 * when the last close of a lease happens.
 *
 * With leases, just one ofile on a lease owns the oplock.
 * If an ofile with a lease is closed and it's the one that
 * owns the oplock, try to move the oplock to another ofile
 * on the same lease.
 *
 * Would prefer that we could just use smb_ofile_hold_olbrk
 * to select a suitable destination for the move, but this
 * is called while holding the owning tree ofile list etc
 * which can cause deadlock as described in illumos 13850
 * when smb_ofile_hold_olbrk has to wait.  XXX todo
 */
void
smb2_lease_ofile_close(smb_ofile_t *ofile)
{
	smb_node_t *node = ofile->f_node;
	smb_lease_t *lease = ofile->f_lease;
	smb_ofile_t *o;

	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

#ifdef	DEBUG
	FOREACH_NODE_OFILE(node, o) {
		DTRACE_PROBE1(each_ofile, smb_ofile_t *, o);
	}
#endif

	/*
	 * If this ofile was not the oplock owner for this lease,
	 * we can leave things as they are.
	 */
	if (lease->ls_oplock_ofile != ofile)
		return;

	/*
	 * Find another ofile to which we can move the oplock.
	 * First try for one that's open.  Usually find one.
	 */
	FOREACH_NODE_OFILE(node, o) {
		if (o == ofile)
			continue;
		if (o->f_lease != lease)
			continue;
		if (o->f_oplock_closing)
			continue;

		mutex_enter(&o->f_mutex);
		if (o->f_state == SMB_OFILE_STATE_OPEN) {
			smb_oplock_move(node, ofile, o);
			lease->ls_oplock_ofile = o;
			mutex_exit(&o->f_mutex);
			return;
		}
		mutex_exit(&o->f_mutex);
	}

	/*
	 * Now try for one that's orphaned etc.
	 */
	FOREACH_NODE_OFILE(node, o) {
		if (o == ofile)
			continue;
		if (o->f_lease != lease)
			continue;
		if (o->f_oplock_closing)
			continue;

		/*
		 * Allow most states as seen in smb_ofile_hold_olbrk
		 * without waiting for "_reconnect" or "_saving".
		 * Skip "_expired" because that's about to close.
		 * This is OK because just swapping the oplock state
		 * between two ofiles does not interfere with the
		 * dh_save or reconnect code paths.
		 */
		mutex_enter(&o->f_mutex);
		switch (o->f_state) {
		case SMB_OFILE_STATE_OPEN:
		case SMB_OFILE_STATE_SAVE_DH:
		case SMB_OFILE_STATE_SAVING:
		case SMB_OFILE_STATE_ORPHANED:
		case SMB_OFILE_STATE_RECONNECT:
			smb_oplock_move(node, ofile, o);
			lease->ls_oplock_ofile = o;
			mutex_exit(&o->f_mutex);
			return;
		}
		mutex_exit(&o->f_mutex);
	}

	/*
	 * Normal for last close on a lease.
	 * Wakeup ACK waiters too.
	 */
	lease->ls_state = 0;
	lease->ls_breakto = 0;
	lease->ls_breaking = B_FALSE;
	cv_broadcast(&lease->ls_ack_cv);

	lease->ls_oplock_ofile = NULL;
}
