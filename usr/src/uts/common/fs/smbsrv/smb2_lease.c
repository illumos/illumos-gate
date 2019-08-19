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

void
smb2_lease_rele(smb_lease_t *ls)
{
	smb_llist_t *bucket;

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
	if (ls->ls_refcnt == 0)
		smb_llist_remove(bucket, ls);
	mutex_exit(&ls->ls_mutex);

	if (ls->ls_refcnt == 0) {
		mutex_destroy(&ls->ls_mutex);
		kmem_cache_free(smb_lease_cache, ls);
	}

	smb_llist_exit(bucket);
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
			DTRACE_PROBE2(dup_lease, smb_request_t, sr,
			    smb_lease_t, lease);
			lease = NULL; /* error */
		}
	} else {
		lease = newlease;
		smb_llist_insert_head(bucket, lease);
		newlease = NULL; /* don't free */
	}
	smb_llist_exit(bucket);

	if (newlease != NULL) {
		mutex_destroy(&newlease->ls_mutex);
		kmem_cache_free(smb_lease_cache, newlease);
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
smb_lease_t *
smb2_lease_lookup(smb_server_t *sv, uint8_t *clnt_uuid, uint8_t *lease_key)
{
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
 * Find an smb_ofile_t in the current tree that shares the
 * specified lease and has some oplock breaking flags set.
 * If lease not found, NT_STATUS_OBJECT_NAME_NOT_FOUND.
 * If ofile not breaking NT_STATUS_UNSUCCESSFUL.
 * On success, ofile (held) in sr->fid_ofile.
 */
static uint32_t
find_breaking_ofile(smb_request_t *sr, uint8_t *lease_key)
{
	smb_tree_t	*tree = sr->tid_tree;
	smb_lease_t	*lease;
	smb_llist_t	*of_list;
	smb_ofile_t	*o;
	uint32_t	status = NT_STATUS_OBJECT_NAME_NOT_FOUND;

	SMB_TREE_VALID(tree);
	of_list = &tree->t_ofile_list;

	smb_llist_enter(of_list, RW_READER);
	for (o = smb_llist_head(of_list); o != NULL;
	    o = smb_llist_next(of_list, o)) {

		ASSERT(o->f_magic == SMB_OFILE_MAGIC);
		ASSERT(o->f_tree == tree);

		if ((lease = o->f_lease) == NULL)
			continue; // no lease

		if (bcmp(lease->ls_key, lease_key, UUID_LEN) != 0)
			continue; // wrong lease

		/*
		 * Now we know the lease exists, so if we don't
		 * find an ofile with breaking flags, return:
		 */
		status = NT_STATUS_UNSUCCESSFUL;

		if (o->f_oplock.og_breaking == 0)
			continue; // not breaking

		/* Found breaking ofile. */
		if (smb_ofile_hold(o)) {
			sr->fid_ofile = o;
			status = NT_STATUS_SUCCESS;
			break;
		}
	}
	smb_llist_exit(of_list);

	return (status);
}

/*
 * This is called by smb2_oplock_break_ack when the struct size
 * indicates this is a lease break (SZ_LEASE).  See:
 * [MS-SMB2] 3.3.5.22.2 Processing a Lease Acknowledgment
 */
smb_sdrc_t
smb2_lease_break_ack(smb_request_t *sr)
{
	smb_lease_t *lease;
	smb_ofile_t *ofile;
	uint8_t LeaseKey[UUID_LEN];
	uint32_t LeaseState;
	uint32_t LeaseBreakTo;
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
	    LeaseKey,		/* c */
	    &LeaseState);	/* l */
	    /* duration		  8. */
	if (rc != 0)
		return (SDRC_ERROR);

	status = find_breaking_ofile(sr, LeaseKey);

	DTRACE_SMB2_START(op__OplockBreak, smb_request_t *, sr);
	if (status != 0)
		goto errout;

	/* Success, so have sr->fid_ofile and lease */
	ofile = sr->fid_ofile;
	lease = ofile->f_lease;

	/*
	 * Process the lease break ack.
	 *
	 * If the new LeaseState has any bits in excess of
	 * the lease state we sent in the break, error...
	 */
	LeaseBreakTo = (lease->ls_breaking >> BREAK_SHIFT) &
	    OPLOCK_LEVEL_CACHE_MASK;
	if ((LeaseState & ~LeaseBreakTo) != 0) {
		status = NT_STATUS_REQUEST_NOT_ACCEPTED;
		goto errout;
	}

	ofile->f_oplock.og_breaking = 0;
	lease->ls_breaking = 0;

	LeaseState |= OPLOCK_LEVEL_GRANULAR;
	status = smb_oplock_ack_break(sr, ofile, &LeaseState);
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb2sr_go_async(sr);
		(void) smb_oplock_wait_break(ofile->f_node, 0);
		status = NT_STATUS_SUCCESS;
	}

	ofile->f_oplock.og_state = LeaseState;
	lease->ls_state = LeaseState &
	    OPLOCK_LEVEL_CACHE_MASK;

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__OplockBreak, smb_request_t *, sr);
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
	    LeaseKey,		/* c */
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
void
smb2_lease_break_notification(smb_request_t *sr, uint32_t NewLevel,
    boolean_t AckReq)
{
	smb_ofile_t *ofile = sr->fid_ofile;
	smb_oplock_grant_t *og = &ofile->f_oplock;
	smb_lease_t *ls = ofile->f_lease;
	uint32_t oldcache;
	uint32_t newcache;
	uint16_t Epoch;
	uint16_t Flags;

	/*
	 * Convert internal level to SMB2
	 */
	oldcache = og->og_state & OPLOCK_LEVEL_CACHE_MASK;
	newcache = NewLevel & OPLOCK_LEVEL_CACHE_MASK;
	if (ls->ls_version < 2)
		Epoch = 0;
	else
		Epoch = ls->ls_epoch;

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
	Flags = AckReq ? SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED : 0;
	(void) smb_mbc_encodef(
	    &sr->reply, "wwl#cll4.4.4.",
	    SSZ_LEASE_BRK,		/* w */
	    Epoch,			/* w */
	    Flags,			/* l */
	    SMB_LEASE_KEY_SZ,		/* # */
	    ls->ls_key,			/* c */
	    oldcache,		/* cur.st  l */
	    newcache);		/* new.st  l */
	    /* reserved (4.4.4.) */
}

/*
 * Client has an open handle and requests a lease.
 * Convert SMB2 lease request info in to internal form,
 * call common oplock code, convert result to SMB2.
 *
 * If necessary, "go async" here.
 */
void
smb2_lease_acquire(smb_request_t *sr)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *ofile = sr->fid_ofile;
	smb_lease_t *lease = ofile->f_lease;
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
	 * Disallow downgrade
	 *
	 * Note that open with a lease is not allowed to turn off
	 * any cache rights.  If the client tries to "downgrade",
	 * any bits, just return the existing lease cache bits.
	 */
	have = lease->ls_state & CACHE_RWH;
	want = op->op_oplock_state & CACHE_RWH;
	if ((have & ~want) != 0) {
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
		want = op->op_oplock_state & CACHE_RWH;
		if (have == want)
			goto done;

		status = smb_oplock_request(sr, ofile,
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
		if (have == want)
			goto done;

		status = smb_oplock_request(sr, ofile,
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
		 */
		op->op_oplock_state = OPLOCK_LEVEL_GRANULAR |
		    (op->lease_state & CACHE_R);
	}

	/*
	 * Try shared ("R")
	 */
	if ((op->op_oplock_state & READ_CACHING) != 0) {
		want = op->op_oplock_state & CACHE_RWH;
		if (have == want)
			goto done;

		status = smb_oplock_request(sr, ofile,
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
	if (NewGrant) {
		/*
		 * After a new oplock grant, the status return
		 * may indicate we need to wait for breaks.
		 */
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
			(void) smb2sr_go_async(sr);
			(void) smb_oplock_wait_break(ofile->f_node, 0);
			status = NT_STATUS_SUCCESS;
		}
		ASSERT(status == NT_STATUS_SUCCESS);

		/*
		 * Keep track of what we got (in ofile->f_oplock.og_state)
		 * so we'll know what we had when sending a break later.
		 * Also update the lease with the new oplock state.
		 * Also track which ofile on the lease owns the oplock.
		 * The og_dialect here is the oplock dialect, not the
		 * SMB dialect.  Leasing, so SMB 2.1 (or later).
		 */
		ofile->f_oplock.og_dialect = SMB_VERS_2_1;
		ofile->f_oplock.og_state = op->op_oplock_state;
		mutex_enter(&lease->ls_mutex);
		lease->ls_state = op->op_oplock_state & CACHE_RWH;
		lease->ls_oplock_ofile = ofile;
		lease->ls_epoch++;
		mutex_exit(&lease->ls_mutex);
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
}

/*
 * This ofile has a lease and is about to close.
 * Called by smb_ofile_close when there's a lease.
 *
 * With leases, just one ofile on a lease owns the oplock.
 * If an ofile with a lease is closed and it's the one that
 * owns the oplock, try to move the oplock to another ofile
 * on the same lease.
 */
void
smb2_lease_ofile_close(smb_ofile_t *ofile)
{
	smb_node_t *node = ofile->f_node;
	smb_lease_t *lease = ofile->f_lease;
	smb_ofile_t *o;

	/*
	 * If this ofile was not the oplock owner for this lease,
	 * we can leave things as they are.
	 */
	if (lease->ls_oplock_ofile != ofile)
		return;

	/*
	 * Find another ofile to which we can move the oplock.
	 * The ofile must be open and allow a new ref.
	 */
	smb_llist_enter(&node->n_ofile_list, RW_READER);
	FOREACH_NODE_OFILE(node, o) {
		if (o == ofile)
			continue;
		if (o->f_lease != lease)
			continue;
		/* If we can get a hold, use this ofile. */
		if (smb_ofile_hold(o))
			break;
	}
	if (o == NULL) {
		/* Normal for last close on a lease. */
		smb_llist_exit(&node->n_ofile_list);
		return;
	}
	smb_oplock_move(node, ofile, o);
	lease->ls_oplock_ofile = o;

	smb_llist_exit(&node->n_ofile_list);
	smb_ofile_release(o);
}
