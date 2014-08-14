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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <nfs/nfs4_clnt.h>
#include <nfs/rnode4.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>

static void	nfs4_free_open_owner(nfs4_open_owner_t *, mntinfo4_t *);
static nfs4_open_owner_t *find_freed_open_owner(cred_t *,
				nfs4_oo_hash_bucket_t *, mntinfo4_t *);
static open_delegation_type4 get_dtype(rnode4_t *);

#ifdef DEBUG
int nfs4_client_foo_debug = 0x0;
int nfs4_client_open_dg = 0x0;
/*
 * If this is non-zero, the lockowner and openowner seqid sync primitives
 * will intermittently return errors.
 */
static int seqid_sync_faults = 0;
#endif

stateid4 clnt_special0 = {
	0,
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

stateid4 clnt_special1 = {
	0xffffffff,
	{
		(char)0xff, (char)0xff, (char)0xff, (char)0xff,
		(char)0xff, (char)0xff, (char)0xff, (char)0xff,
		(char)0xff, (char)0xff, (char)0xff, (char)0xff
	}
};

/* finds hash bucket and locks it */
static nfs4_oo_hash_bucket_t *
lock_bucket(cred_t *cr, mntinfo4_t *mi)
{
	nfs4_oo_hash_bucket_t *bucketp;
	uint32_t hash_key;

	hash_key = (uint32_t)(crgetuid(cr) + crgetruid(cr))
	    % NFS4_NUM_OO_BUCKETS;
	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE, "lock_bucket: "
	    "hash_key %d for cred %p", hash_key, (void*)cr));

	ASSERT(hash_key >= 0 && hash_key < NFS4_NUM_OO_BUCKETS);
	ASSERT(mi != NULL);
	ASSERT(mutex_owned(&mi->mi_lock));

	bucketp = &(mi->mi_oo_list[hash_key]);
	mutex_enter(&bucketp->b_lock);
	return (bucketp);
}

/* unlocks hash bucket pointed by bucket_ptr */
static void
unlock_bucket(nfs4_oo_hash_bucket_t *bucketp)
{
	mutex_exit(&bucketp->b_lock);
}

/*
 * Removes the lock owner from the rnode's lock_owners list and frees the
 * corresponding reference.
 */
void
nfs4_rnode_remove_lock_owner(rnode4_t *rp, nfs4_lock_owner_t *lop)
{
	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "nfs4_rnode_remove_lock_owner"));

	mutex_enter(&rp->r_statev4_lock);

	if (lop->lo_next_rnode == NULL) {
		/* already removed from list */
		mutex_exit(&rp->r_statev4_lock);
		return;
	}

	ASSERT(lop->lo_prev_rnode != NULL);

	lop->lo_prev_rnode->lo_next_rnode = lop->lo_next_rnode;
	lop->lo_next_rnode->lo_prev_rnode = lop->lo_prev_rnode;

	lop->lo_next_rnode = lop->lo_prev_rnode = NULL;

	mutex_exit(&rp->r_statev4_lock);

	/*
	 * This would be an appropriate place for
	 * RELEASE_LOCKOWNER.  For now, this is overkill
	 * because in the common case, close is going to
	 * release any lockowners anyway.
	 */
	lock_owner_rele(lop);
}

/*
 * Remove all lock owners from the rnode's lock_owners list.  Frees up
 * their references from the list.
 */

void
nfs4_flush_lock_owners(rnode4_t *rp)
{
	nfs4_lock_owner_t *lop;

	mutex_enter(&rp->r_statev4_lock);
	while (rp->r_lo_head.lo_next_rnode != &rp->r_lo_head) {
		lop = rp->r_lo_head.lo_next_rnode;
		lop->lo_prev_rnode->lo_next_rnode = lop->lo_next_rnode;
		lop->lo_next_rnode->lo_prev_rnode = lop->lo_prev_rnode;
		lop->lo_next_rnode = lop->lo_prev_rnode = NULL;
		lock_owner_rele(lop);
	}
	mutex_exit(&rp->r_statev4_lock);
}

void
nfs4_clear_open_streams(rnode4_t *rp)
{
	nfs4_open_stream_t *osp;

	mutex_enter(&rp->r_os_lock);
	while ((osp = list_head(&rp->r_open_streams)) != NULL) {
		open_owner_rele(osp->os_open_owner);
		list_remove(&rp->r_open_streams, osp);
		mutex_destroy(&osp->os_sync_lock);
		osp->os_open_owner = NULL;
		kmem_free(osp, sizeof (*osp));
	}
	mutex_exit(&rp->r_os_lock);
}

void
open_owner_hold(nfs4_open_owner_t *oop)
{
	mutex_enter(&oop->oo_lock);
	oop->oo_ref_count++;
	mutex_exit(&oop->oo_lock);
}

/*
 * Frees the open owner if the ref count hits zero.
 */
void
open_owner_rele(nfs4_open_owner_t *oop)
{
	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "open_owner_rele"));

	mutex_enter(&oop->oo_lock);
	oop->oo_ref_count--;
	if (oop->oo_ref_count == 0) {
		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
		    "open_owner_rele: freeing open owner"));
		oop->oo_valid = 0;
		mutex_exit(&oop->oo_lock);
		/*
		 * Ok, we don't destroy the open owner, nor do we put it on
		 * the mntinfo4's free list just yet.  We are lazy about it
		 * and let callers to find_open_owner() do that to keep locking
		 * simple.
		 */
	} else {
		mutex_exit(&oop->oo_lock);
	}
}

void
open_stream_hold(nfs4_open_stream_t *osp)
{
	mutex_enter(&osp->os_sync_lock);
	osp->os_ref_count++;
	mutex_exit(&osp->os_sync_lock);
}

/*
 * Frees the open stream and removes it from the rnode4's open streams list if
 * the ref count drops to zero.
 */
void
open_stream_rele(nfs4_open_stream_t *osp, rnode4_t *rp)
{
	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "open_stream_rele"));

	ASSERT(!mutex_owned(&rp->r_os_lock));

	mutex_enter(&osp->os_sync_lock);
	ASSERT(osp->os_ref_count > 0);
	osp->os_ref_count--;
	if (osp->os_ref_count == 0) {
		nfs4_open_owner_t *tmp_oop;

		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
		    "open_stream_rele: freeing open stream"));
		osp->os_valid = 0;
		tmp_oop = osp->os_open_owner;
		mutex_exit(&osp->os_sync_lock);

		/* now see if we need to destroy the open owner */
		open_owner_rele(tmp_oop);

		mutex_enter(&rp->r_os_lock);
		list_remove(&rp->r_open_streams, osp);
		mutex_exit(&rp->r_os_lock);

		/* free up osp */
		mutex_destroy(&osp->os_sync_lock);
		osp->os_open_owner = NULL;
		kmem_free(osp, sizeof (*osp));
	} else {
		mutex_exit(&osp->os_sync_lock);
	}
}

void
lock_owner_hold(nfs4_lock_owner_t *lop)
{
	mutex_enter(&lop->lo_lock);
	lop->lo_ref_count++;
	mutex_exit(&lop->lo_lock);
}

/*
 * Frees the lock owner if the ref count hits zero and
 * the structure no longer has no locks.
 */
void
lock_owner_rele(nfs4_lock_owner_t *lop)
{
	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "lock_owner_rele"));

	mutex_enter(&lop->lo_lock);
	lop->lo_ref_count--;
	if (lop->lo_ref_count == 0) {
		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
		    "lock_owner_rele: freeing lock owner: "
		    "%x", lop->lo_pid));
		lop->lo_valid = 0;
		/*
		 * If there are no references, the lock_owner should
		 * already be off the rnode's list.
		 */
		ASSERT(lop->lo_next_rnode == NULL);
		ASSERT(lop->lo_prev_rnode == NULL);
		ASSERT(!(lop->lo_flags & NFS4_LOCK_SEQID_INUSE));
		ASSERT(lop->lo_seqid_holder == NULL);
		mutex_exit(&lop->lo_lock);

		/* free up lop */
		cv_destroy(&lop->lo_cv_seqid_sync);
		mutex_destroy(&lop->lo_lock);
		kmem_free(lop, sizeof (*lop));
	} else {
		mutex_exit(&lop->lo_lock);
	}
}

/*
 * This increments the open owner ref count if found.
 * The argument 'just_created' determines whether we are looking for open
 * owners with the 'oo_just_created' flag set or not.
 */
nfs4_open_owner_t *
find_open_owner_nolock(cred_t *cr, int just_created, mntinfo4_t *mi)
{
	nfs4_open_owner_t	*oop = NULL, *next_oop;
	nfs4_oo_hash_bucket_t	*bucketp;

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "find_open_owner: cred %p, just_created %d",
	    (void*)cr, just_created));

	ASSERT(mi != NULL);
	ASSERT(mutex_owned(&mi->mi_lock));

	bucketp = lock_bucket(cr, mi);

	/* got hash bucket, search through open owners */
	for (oop = list_head(&bucketp->b_oo_hash_list); oop != NULL; ) {
		mutex_enter(&oop->oo_lock);
		if (!crcmp(oop->oo_cred, cr) &&
		    (oop->oo_just_created == just_created ||
		    just_created == NFS4_JUST_CREATED)) {
			/* match */
			if (oop->oo_valid == 0) {
				/* reactivate the open owner */
				oop->oo_valid = 1;
				ASSERT(oop->oo_ref_count == 0);
			}
			oop->oo_ref_count++;
			mutex_exit(&oop->oo_lock);
			unlock_bucket(bucketp);
			return (oop);
		}
		next_oop = list_next(&bucketp->b_oo_hash_list, oop);
		if (oop->oo_valid == 0) {
			list_remove(&bucketp->b_oo_hash_list, oop);

			/*
			 * Now we go ahead and put this open owner
			 * on the freed list.  This is our lazy method.
			 */
			nfs4_free_open_owner(oop, mi);
		}

		mutex_exit(&oop->oo_lock);
		oop = next_oop;
	}

	/* search through recently freed open owners */
	oop = find_freed_open_owner(cr, bucketp, mi);

	unlock_bucket(bucketp);

	return (oop);
}

nfs4_open_owner_t *
find_open_owner(cred_t *cr, int just_created, mntinfo4_t *mi)
{
	nfs4_open_owner_t *oop;

	mutex_enter(&mi->mi_lock);
	oop = find_open_owner_nolock(cr, just_created, mi);
	mutex_exit(&mi->mi_lock);

	return (oop);
}

/*
 * This increments osp's ref count if found.
 * Returns with 'os_sync_lock' held.
 */
nfs4_open_stream_t *
find_open_stream(nfs4_open_owner_t *oop, rnode4_t *rp)
{
	nfs4_open_stream_t	*osp;

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "find_open_stream"));

	mutex_enter(&rp->r_os_lock);
	/* Now, no one can add or delete to rp's open streams list */
	for (osp = list_head(&rp->r_open_streams); osp != NULL;
	    osp = list_next(&rp->r_open_streams, osp)) {
		mutex_enter(&osp->os_sync_lock);
		if (osp->os_open_owner == oop && osp->os_valid != 0) {
			/* match */
			NFS4_DEBUG(nfs4_client_state_debug,
			    (CE_NOTE, "find_open_stream "
			    "got a match"));

			osp->os_ref_count++;
			mutex_exit(&rp->r_os_lock);
			return (osp);
		}
		mutex_exit(&osp->os_sync_lock);
	}

	mutex_exit(&rp->r_os_lock);
	return (NULL);
}

/*
 * Find the lock owner for the given file and process ID.  If "which" is
 * LOWN_VALID_STATEID, require that the lock owner contain a valid stateid
 * from the server.
 *
 * This increments the lock owner's ref count if found.  Returns NULL if
 * there was no match.
 */
nfs4_lock_owner_t *
find_lock_owner(rnode4_t *rp, pid_t pid, lown_which_t which)
{
	nfs4_lock_owner_t	*lop, *next_lop;

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "find_lock_owner: pid %x, which %d", pid, which));

	ASSERT(which == LOWN_ANY || which == LOWN_VALID_STATEID);

	/* search by pid */
	mutex_enter(&rp->r_statev4_lock);

	lop = rp->r_lo_head.lo_next_rnode;
	while (lop != &rp->r_lo_head) {
		mutex_enter(&lop->lo_lock);
		if (lop->lo_pid == pid && lop->lo_valid != 0 &&
		    !(lop->lo_flags & NFS4_BAD_SEQID_LOCK)) {
			if (which == LOWN_ANY ||
			    lop->lo_just_created != NFS4_JUST_CREATED) {
				/* Found a matching lock owner */
				NFS4_DEBUG(nfs4_client_state_debug,
				    (CE_NOTE, "find_lock_owner: "
				    "got a match"));

				lop->lo_ref_count++;
				mutex_exit(&lop->lo_lock);
				mutex_exit(&rp->r_statev4_lock);
				return (lop);
			}
		}
		next_lop = lop->lo_next_rnode;
		mutex_exit(&lop->lo_lock);
		lop = next_lop;
	}

	mutex_exit(&rp->r_statev4_lock);
	return (NULL);
}

/*
 * This returns the delegation stateid as 'sid'. Returns 1 if a successful
 * delegation stateid was found, otherwise returns 0.
 */

static int
nfs4_get_deleg_stateid(rnode4_t *rp, nfs_opnum4 op, stateid4 *sid)
{
	ASSERT(!mutex_owned(&rp->r_statev4_lock));

	mutex_enter(&rp->r_statev4_lock);
	if (((rp->r_deleg_type == OPEN_DELEGATE_WRITE && op == OP_WRITE) ||
	    (rp->r_deleg_type != OPEN_DELEGATE_NONE && op != OP_WRITE)) &&
	    !rp->r_deleg_return_pending) {

		*sid = rp->r_deleg_stateid;
		mutex_exit(&rp->r_statev4_lock);
		return (1);
	}
	mutex_exit(&rp->r_statev4_lock);
	return (0);
}

/*
 * This returns the lock stateid as 'sid'. Returns 1 if a successful lock
 * stateid was found, otherwise returns 0.
 */
static int
nfs4_get_lock_stateid(rnode4_t *rp, pid_t pid, stateid4 *sid)
{
	nfs4_lock_owner_t *lop;

	lop = find_lock_owner(rp, pid, LOWN_VALID_STATEID);

	if (lop) {
		/*
		 * Found a matching lock owner, so use a lock
		 * stateid rather than an open stateid.
		 */
		mutex_enter(&lop->lo_lock);
		*sid = lop->lock_stateid;
		mutex_exit(&lop->lo_lock);
		lock_owner_rele(lop);
		return (1);
	}

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "nfs4_get_lock_stateid: no lop"));
	return (0);
}

/*
 * This returns the open stateid as 'sid'. Returns 1 if a successful open
 * stateid was found, otherwise returns 0.
 *
 * Once the stateid is returned to the caller, it is no longer protected;
 * so the caller must be prepared to handle OLD/BAD_STATEID where
 * appropiate.
 */
static int
nfs4_get_open_stateid(rnode4_t *rp, cred_t *cr, mntinfo4_t *mi, stateid4 *sid)
{
	nfs4_open_owner_t *oop;
	nfs4_open_stream_t *osp;

	ASSERT(mi != NULL);

	oop = find_open_owner(cr, NFS4_PERM_CREATED, mi);
	if (!oop) {
		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
		    "nfs4_get_open_stateid: no oop"));
		return (0);
	}

	osp = find_open_stream(oop, rp);
	open_owner_rele(oop);
	if (!osp) {
		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
		    "nfs4_get_open_stateid: no osp"));
		return (0);
	}

	if (osp->os_failed_reopen) {
		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
		    "nfs4_get_open_stateid: osp %p failed reopen",
		    (void *)osp));
		mutex_exit(&osp->os_sync_lock);
		open_stream_rele(osp, rp);
		return (0);
	}
	*sid = osp->open_stateid;
	mutex_exit(&osp->os_sync_lock);
	open_stream_rele(osp, rp);
	return (1);
}

/*
 * Returns the delegation stateid if this 'op' is OP_WRITE and the
 * delegation we hold is a write delegation, OR this 'op' is not
 * OP_WRITE and we have a delegation held (read or write), otherwise
 * returns the lock stateid if there is a lock owner, otherwise
 * returns the open stateid if there is a open stream, otherwise
 * returns special stateid <seqid = 0, other = 0>.
 *
 * Used for WRITE operations.
 */
stateid4
nfs4_get_w_stateid(cred_t *cr, rnode4_t *rp, pid_t pid, mntinfo4_t *mi,
	nfs_opnum4 op, nfs4_stateid_types_t *sid_tp)
{
	stateid4 sid;

	if (nfs4_get_deleg_stateid(rp, op, &sid)) {
		if (!stateid4_cmp(&sid, &sid_tp->d_sid)) {
			sid_tp->cur_sid_type = DEL_SID;
			return (sid);
		}
	}
	if (nfs4_get_lock_stateid(rp, pid, &sid)) {
		if (!stateid4_cmp(&sid, &sid_tp->l_sid)) {
			sid_tp->cur_sid_type = LOCK_SID;
			return (sid);
		}
	}
	if (nfs4_get_open_stateid(rp, cr, mi, &sid)) {
		if (!stateid4_cmp(&sid, &sid_tp->o_sid)) {
			sid_tp->cur_sid_type = OPEN_SID;
			return (sid);
		}
	}
	bzero(&sid, sizeof (stateid4));
	sid_tp->cur_sid_type = SPEC_SID;
	return (sid);
}

/*
 * Returns the delegation stateid if this 'op' is OP_WRITE and the
 * delegation we hold is a write delegation, OR this 'op' is not
 * OP_WRITE and we have a delegation held (read or write), otherwise
 * returns the lock stateid if there is a lock owner, otherwise
 * returns the open stateid if there is a open stream, otherwise
 * returns special stateid <seqid = 0, other = 0>.
 *
 * This also updates which stateid we are using in 'sid_tp', skips
 * previously attempted stateids, and skips checking higher priority
 * stateids than the current level as dictated by 'sid_tp->cur_sid_type'
 * for async reads.
 *
 * Used for READ and SETATTR operations.
 */
stateid4
nfs4_get_stateid(cred_t *cr, rnode4_t *rp, pid_t pid, mntinfo4_t *mi,
	nfs_opnum4 op, nfs4_stateid_types_t *sid_tp, bool_t async_read)
{
	stateid4 sid;

	/*
	 * For asynchronous READs, do not attempt to retry from the start of
	 * the stateid priority list, just continue from where you last left
	 * off.
	 */
	if (async_read) {
		switch (sid_tp->cur_sid_type) {
		case NO_SID:
			break;
		case DEL_SID:
			goto lock_stateid;
		case LOCK_SID:
			goto open_stateid;
		case OPEN_SID:
			goto special_stateid;
		case SPEC_SID:
		default:
			cmn_err(CE_PANIC, "nfs4_get_stateid: illegal current "
			    "stateid type %d", sid_tp->cur_sid_type);
		}
	}

	if (nfs4_get_deleg_stateid(rp, op, &sid)) {
		if (!stateid4_cmp(&sid, &sid_tp->d_sid)) {
			sid_tp->cur_sid_type = DEL_SID;
			return (sid);
		}
	}
lock_stateid:
	if (nfs4_get_lock_stateid(rp, pid, &sid)) {
		if (!stateid4_cmp(&sid, &sid_tp->l_sid)) {
			sid_tp->cur_sid_type = LOCK_SID;
			return (sid);
		}
	}
open_stateid:
	if (nfs4_get_open_stateid(rp, cr, mi, &sid)) {
		if (!stateid4_cmp(&sid, &sid_tp->o_sid)) {
			sid_tp->cur_sid_type = OPEN_SID;
			return (sid);
		}
	}
special_stateid:
	bzero(&sid, sizeof (stateid4));
	sid_tp->cur_sid_type = SPEC_SID;
	return	(sid);
}

void
nfs4_set_lock_stateid(nfs4_lock_owner_t *lop, stateid4 stateid)
{
	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "nfs4_set_lock_stateid"));

	ASSERT(lop);
	ASSERT(lop->lo_flags & NFS4_LOCK_SEQID_INUSE);

	mutex_enter(&lop->lo_lock);
	lop->lock_stateid = stateid;
	mutex_exit(&lop->lo_lock);
}

/*
 * Sequence number used when a new open owner is needed.
 * This is used so as to not confuse the server.  Since a open owner
 * is based off of cred, a cred could be re-used quickly, and the server
 * may not release all state for a cred.
 */
static uint64_t open_owner_seq_num = 0;

uint64_t
nfs4_get_new_oo_name(void)
{
	return (atomic_inc_64_nv(&open_owner_seq_num));
}

/*
 * Create a new open owner and add it to the open owner hash table.
 */
nfs4_open_owner_t *
create_open_owner(cred_t *cr, mntinfo4_t *mi)
{
	nfs4_open_owner_t	*oop;
	nfs4_oo_hash_bucket_t	*bucketp;

	oop = kmem_alloc(sizeof (nfs4_open_owner_t), KM_SLEEP);
	/*
	 * Make sure the cred doesn't go away when we put this open owner
	 * on the free list, as well as make crcmp() a valid check.
	 */
	crhold(cr);
	oop->oo_cred = cr;
	mutex_init(&oop->oo_lock, NULL, MUTEX_DEFAULT, NULL);
	oop->oo_ref_count = 1;
	oop->oo_valid = 1;
	oop->oo_just_created = NFS4_JUST_CREATED;
	oop->oo_seqid = 0;
	oop->oo_seqid_inuse = 0;
	oop->oo_last_good_seqid = 0;
	oop->oo_last_good_op = TAG_NONE;
	oop->oo_cred_otw = NULL;
	cv_init(&oop->oo_cv_seqid_sync, NULL, CV_DEFAULT, NULL);

	/*
	 * A Solaris open_owner is <oo_seq_num>
	 */
	oop->oo_name = nfs4_get_new_oo_name();

	/* now add the struct into the cred hash table */
	ASSERT(mutex_owned(&mi->mi_lock));
	bucketp = lock_bucket(cr, mi);
	list_insert_head(&bucketp->b_oo_hash_list, oop);
	unlock_bucket(bucketp);

	return (oop);
}

/*
 * Create a new open stream and it to the rnode's list.
 * Increments the ref count on oop.
 * Returns with 'os_sync_lock' held.
 */
nfs4_open_stream_t *
create_open_stream(nfs4_open_owner_t *oop, rnode4_t *rp)
{
	nfs4_open_stream_t	*osp;

#ifdef DEBUG
	mutex_enter(&oop->oo_lock);
	ASSERT(oop->oo_seqid_inuse);
	mutex_exit(&oop->oo_lock);
#endif

	osp = kmem_alloc(sizeof (nfs4_open_stream_t), KM_SLEEP);
	osp->os_open_ref_count = 1;
	osp->os_mapcnt = 0;
	osp->os_ref_count = 2;
	osp->os_valid = 1;
	osp->os_open_owner = oop;
	osp->os_orig_oo_name = oop->oo_name;
	bzero(&osp->open_stateid, sizeof (stateid4));
	osp->os_share_acc_read = 0;
	osp->os_share_acc_write = 0;
	osp->os_mmap_read = 0;
	osp->os_mmap_write = 0;
	osp->os_share_deny_none = 0;
	osp->os_share_deny_read = 0;
	osp->os_share_deny_write = 0;
	osp->os_delegation = 0;
	osp->os_dc_openacc = 0;
	osp->os_final_close = 0;
	osp->os_pending_close = 0;
	osp->os_failed_reopen = 0;
	osp->os_force_close = 0;
	mutex_init(&osp->os_sync_lock, NULL, MUTEX_DEFAULT, NULL);

	/* open owner gets a reference */
	open_owner_hold(oop);

	/* now add the open stream to rp */
	mutex_enter(&rp->r_os_lock);
	mutex_enter(&osp->os_sync_lock);
	list_insert_head(&rp->r_open_streams, osp);
	mutex_exit(&rp->r_os_lock);

	return (osp);
}

/*
 * Returns an open stream with 'os_sync_lock' held.
 * If the open stream is found (rather than created), its
 * 'os_open_ref_count' is bumped.
 *
 * There is no race with two threads entering this function
 * and creating two open streams for the same <oop, rp> pair.
 * This is because the open seqid sync must be acquired, thus
 * only allowing one thread in at a time.
 */
nfs4_open_stream_t *
find_or_create_open_stream(nfs4_open_owner_t *oop, rnode4_t *rp,
	int *created_osp)
{
	nfs4_open_stream_t *osp;

#ifdef DEBUG
	mutex_enter(&oop->oo_lock);
	ASSERT(oop->oo_seqid_inuse);
	mutex_exit(&oop->oo_lock);
#endif

	osp = find_open_stream(oop, rp);
	if (!osp) {
		osp = create_open_stream(oop, rp);
		if (osp)
			*created_osp = 1;
	} else {
		*created_osp = 0;
		osp->os_open_ref_count++;
	}

	return (osp);
}

static uint64_t lock_owner_seq_num = 0;

/*
 * Create a new lock owner and add it to the rnode's list.
 * Assumes the rnode's r_statev4_lock is held.
 * The created lock owner has a reference count of 2: one for the list and
 * one for the caller to use.  Returns the lock owner locked down.
 */
nfs4_lock_owner_t *
create_lock_owner(rnode4_t *rp, pid_t pid)
{
	nfs4_lock_owner_t	*lop;

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "create_lock_owner: pid %x", pid));

	ASSERT(mutex_owned(&rp->r_statev4_lock));

	lop = kmem_alloc(sizeof (nfs4_lock_owner_t), KM_SLEEP);
	lop->lo_ref_count = 2;
	lop->lo_valid = 1;
	bzero(&lop->lock_stateid, sizeof (stateid4));
	lop->lo_pid = pid;
	lop->lock_seqid = 0;
	lop->lo_pending_rqsts = 0;
	lop->lo_just_created = NFS4_JUST_CREATED;
	lop->lo_flags = 0;
	lop->lo_seqid_holder = NULL;

	/*
	 * A Solaris lock_owner is <seq_num><pid>
	 */
	lop->lock_owner_name.ln_seq_num =
	    atomic_inc_64_nv(&lock_owner_seq_num);
	lop->lock_owner_name.ln_pid = pid;

	cv_init(&lop->lo_cv_seqid_sync, NULL, CV_DEFAULT, NULL);
	mutex_init(&lop->lo_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_enter(&lop->lo_lock);

	/* now add the lock owner to rp */
	lop->lo_prev_rnode = &rp->r_lo_head;
	lop->lo_next_rnode = rp->r_lo_head.lo_next_rnode;
	rp->r_lo_head.lo_next_rnode->lo_prev_rnode = lop;
	rp->r_lo_head.lo_next_rnode = lop;

	return (lop);

}

/*
 * This sets the lock seqid of a lock owner.
 */
void
nfs4_set_lock_seqid(seqid4 seqid, nfs4_lock_owner_t *lop)
{
	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "nfs4_set_lock_seqid"));

	ASSERT(lop != NULL);
	ASSERT(lop->lo_flags & NFS4_LOCK_SEQID_INUSE);

	lop->lock_seqid = seqid;
}

static void
nfs4_set_new_lock_owner_args(lock_owner4 *owner, pid_t pid)
{
	nfs4_lo_name_t *cast_namep;

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "nfs4_set_new_lock_owner_args"));

	owner->owner_len = sizeof (*cast_namep);
	owner->owner_val = kmem_alloc(owner->owner_len, KM_SLEEP);
	/*
	 * A Solaris lock_owner is <seq_num><pid>
	 */
	cast_namep = (nfs4_lo_name_t *)owner->owner_val;
	cast_namep->ln_seq_num = atomic_inc_64_nv(&lock_owner_seq_num);
	cast_namep->ln_pid = pid;
}

/*
 * Fill in the lock owner args.
 */
void
nfs4_setlockowner_args(lock_owner4 *owner, rnode4_t *rp, pid_t pid)
{
	nfs4_lock_owner_t *lop;

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "nfs4_setlockowner_args"));

	/* This increments lop's ref count */
	lop = find_lock_owner(rp, pid, LOWN_VALID_STATEID);

	if (!lop)
		goto make_up_args;

	mutex_enter(&lop->lo_lock);
	owner->owner_len = sizeof (lop->lock_owner_name);
	owner->owner_val = kmem_alloc(owner->owner_len, KM_SLEEP);
	bcopy(&lop->lock_owner_name, owner->owner_val,
	    owner->owner_len);
	mutex_exit(&lop->lo_lock);
	lock_owner_rele(lop);
	return;

make_up_args:
	nfs4_set_new_lock_owner_args(owner, pid);
}

/*
 * This ends our use of the open owner's open seqid by setting
 * the appropiate flags and issuing a cv_signal to wake up another
 * thread waiting to use the open seqid.
 */

void
nfs4_end_open_seqid_sync(nfs4_open_owner_t *oop)
{
	mutex_enter(&oop->oo_lock);
	ASSERT(oop->oo_seqid_inuse);
	oop->oo_seqid_inuse = 0;
	cv_broadcast(&oop->oo_cv_seqid_sync);
	mutex_exit(&oop->oo_lock);
}

/*
 * This starts our use of the open owner's open seqid by setting
 * the oo_seqid_inuse to true.  We will wait (forever) with a
 * cv_wait() until we are woken up.
 *
 * Return values:
 * 0		no problems
 * EAGAIN	caller should retry (like a recovery retry)
 */
int
nfs4_start_open_seqid_sync(nfs4_open_owner_t *oop, mntinfo4_t *mi)
{
	int error = 0;
#ifdef DEBUG
	static int ops = 0;		/* fault injection */
#endif

#ifdef DEBUG
	if (seqid_sync_faults && curthread != mi->mi_recovthread &&
	    ++ops % 5 == 0)
		return (EAGAIN);
#endif

	mutex_enter(&mi->mi_lock);
	if ((mi->mi_flags & MI4_RECOV_ACTIV) &&
	    curthread != mi->mi_recovthread)
		error = EAGAIN;
	mutex_exit(&mi->mi_lock);
	if (error != 0)
		goto done;

	mutex_enter(&oop->oo_lock);

	while (oop->oo_seqid_inuse) {
		NFS4_DEBUG(nfs4_seqid_sync, (CE_NOTE,
		    "nfs4_start_open_seqid_sync waiting on cv"));

		cv_wait(&oop->oo_cv_seqid_sync, &oop->oo_lock);
	}

	oop->oo_seqid_inuse = 1;

	mutex_exit(&oop->oo_lock);

	mutex_enter(&mi->mi_lock);
	if ((mi->mi_flags & MI4_RECOV_ACTIV) &&
	    curthread != mi->mi_recovthread)
		error = EAGAIN;
	mutex_exit(&mi->mi_lock);

	if (error == EAGAIN)
		nfs4_end_open_seqid_sync(oop);

	NFS4_DEBUG(nfs4_seqid_sync, (CE_NOTE,
	    "nfs4_start_open_seqid_sync: error=%d", error));

done:
	return (error);
}

#ifdef	DEBUG
int bypass_otw[2];
#endif

/*
 * Checks to see if the OPEN OTW is necessary that is, if it's already
 * been opened with the same access and deny bits we are now asking for.
 * Note, this assumes that *vpp is a rnode.
 */
int
nfs4_is_otw_open_necessary(nfs4_open_owner_t *oop, int flag, vnode_t *vp,
	int just_been_created, int *errorp, int acc, nfs4_recov_state_t *rsp)
{
	rnode4_t *rp;
	nfs4_open_stream_t *osp;
	open_delegation_type4 dt;

	rp = VTOR4(vp);

	/*
	 * Grab the delegation type.  This function is protected against
	 * the delegation being returned by virtue of start_op (called
	 * by nfs4open_otw) taking the r_deleg_recall_lock in read mode,
	 * delegreturn requires this lock in write mode to proceed.
	 */
	ASSERT(nfs_rw_lock_held(&rp->r_deleg_recall_lock, RW_READER));
	dt = get_dtype(rp);

	/* returns with 'os_sync_lock' held */
	osp = find_open_stream(oop, rp);

	if (osp) {
		uint32_t	do_otw = 0;

		if (osp->os_failed_reopen) {
			NFS4_DEBUG(nfs4_open_stream_debug, (CE_NOTE,
			    "nfs4_is_otw_open_necessary: os_failed_reopen "
			    "set on osp %p, cr %p, rp %s", (void *)osp,
			    (void *)osp->os_open_owner->oo_cred,
			    rnode4info(rp)));
			do_otw = 1;
		}

		/*
		 * check access/deny bits
		 */
		if (!do_otw && (flag & FREAD))
			if (osp->os_share_acc_read == 0 &&
			    dt == OPEN_DELEGATE_NONE)
				do_otw = 1;

		if (!do_otw && (flag & FWRITE))
			if (osp->os_share_acc_write == 0 &&
			    dt != OPEN_DELEGATE_WRITE)
				do_otw = 1;

		if (!do_otw) {
			NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
			    "nfs4_is_otw_open_necessary: can skip this "
			    "open OTW"));
			if (!just_been_created) {
				osp->os_open_ref_count++;
				if (flag & FREAD)
					osp->os_share_acc_read++;
				if (flag & FWRITE)
					osp->os_share_acc_write++;
				osp->os_share_deny_none++;
			}

			/*
			 * Need to reset this bitfield for the possible case
			 * where we were going to OTW CLOSE the file, got a
			 * non-recoverable error, and before we could retry
			 * the CLOSE, OPENed the file again.
			 */
			ASSERT(osp->os_open_owner->oo_seqid_inuse);
			osp->os_final_close = 0;
			osp->os_force_close = 0;

			mutex_exit(&osp->os_sync_lock);
			open_stream_rele(osp, rp);

#ifdef	DEBUG
			bypass_otw[0]++;
#endif

			*errorp = 0;
			return (0);
		}
		mutex_exit(&osp->os_sync_lock);
		open_stream_rele(osp, rp);

	} else if (dt != OPEN_DELEGATE_NONE) {
		/*
		 * Even if there isn't an open_stream yet, we may still be
		 * able to bypass the otw open if the client owns a delegation.
		 *
		 * If you are asking for for WRITE, but I only have
		 * a read delegation, then you still have to go otw.
		 */

		if (flag & FWRITE && dt == OPEN_DELEGATE_READ)
			return (1);

		/*
		 * TODO - evaluate the nfsace4
		 */

		/*
		 * Check the access flags to make sure the caller
		 * had permission.
		 */
		if (flag & FREAD && !(acc & VREAD))
			return (1);

		if (flag & FWRITE && !(acc & VWRITE))
			return (1);

		/*
		 * create_open_stream will add a reference to oop,
		 * this will prevent the open_owner_rele done in
		 * nfs4open_otw from destroying the open_owner.
		 */

		/* returns with 'os_sync_lock' held */
		osp = create_open_stream(oop, rp);
		if (osp == NULL)
			return (1);

		osp->open_stateid = rp->r_deleg_stateid;
		osp->os_delegation = 1;

		if (flag & FREAD)
			osp->os_share_acc_read++;
		if (flag & FWRITE)
			osp->os_share_acc_write++;

		osp->os_share_deny_none++;
		mutex_exit(&osp->os_sync_lock);

		open_stream_rele(osp, rp);

		mutex_enter(&oop->oo_lock);
		oop->oo_just_created = NFS4_PERM_CREATED;
		mutex_exit(&oop->oo_lock);

		ASSERT(rsp != NULL);
		if (rsp->rs_sp != NULL) {
			mutex_enter(&rsp->rs_sp->s_lock);
			nfs4_inc_state_ref_count_nolock(rsp->rs_sp,
			    VTOMI4(vp));
			mutex_exit(&rsp->rs_sp->s_lock);
		}
#ifdef	DEBUG
		bypass_otw[1]++;
#endif

		*errorp = 0;
		return (0);
	}

	return (1);
}

static open_delegation_type4
get_dtype(rnode4_t *rp)
{
	open_delegation_type4 dt;

	mutex_enter(&rp->r_statev4_lock);
	ASSERT(!rp->r_deleg_return_inprog);
	if (rp->r_deleg_return_pending)
		dt = OPEN_DELEGATE_NONE;
	else
		dt = rp->r_deleg_type;
	mutex_exit(&rp->r_statev4_lock);

	return (dt);
}

/*
 * Fill in *locker with the lock state arguments for a LOCK call.  If
 * lop->lo_just_created == NFS4_JUST_CREATED, oop and osp must be non-NULL.
 * Caller must already hold the necessary seqid sync lock(s).
 */

void
nfs4_setup_lock_args(nfs4_lock_owner_t *lop, nfs4_open_owner_t *oop,
	nfs4_open_stream_t *osp, clientid4 clientid, locker4 *locker)
{
	ASSERT(lop->lo_flags & NFS4_LOCK_SEQID_INUSE);
	if (lop->lo_just_created == NFS4_JUST_CREATED) {
		/* this is a new lock request */
		open_to_lock_owner4 *nown;

		ASSERT(oop != NULL);
		ASSERT(osp != NULL);

		locker->new_lock_owner = TRUE;
		nown = &locker->locker4_u.open_owner;
		nown->open_seqid = nfs4_get_open_seqid(oop) + 1;
		mutex_enter(&osp->os_sync_lock);
		nown->open_stateid = osp->open_stateid;
		mutex_exit(&osp->os_sync_lock);
		nown->lock_seqid = lop->lock_seqid; /* initial, so no +1 */

		nown->lock_owner.clientid = clientid;
		nown->lock_owner.owner_len = sizeof (lop->lock_owner_name);
		nown->lock_owner.owner_val =
		    kmem_alloc(nown->lock_owner.owner_len, KM_SLEEP);
		bcopy(&lop->lock_owner_name, nown->lock_owner.owner_val,
		    nown->lock_owner.owner_len);
	} else {
		exist_lock_owner4 *eown;
		/* have an existing lock owner */

		locker->new_lock_owner = FALSE;
		eown = &locker->locker4_u.lock_owner;
		mutex_enter(&lop->lo_lock);
		eown->lock_stateid = lop->lock_stateid;
		mutex_exit(&lop->lo_lock);
		eown->lock_seqid = lop->lock_seqid + 1;
	}
}

/*
 * This starts our use of the lock owner's lock seqid by setting
 * the lo_flags to NFS4_LOCK_SEQID_INUSE.  We will wait (forever)
 * with a cv_wait() until we are woken up.
 *
 * Return values:
 * 0		no problems
 * EAGAIN	caller should retry (like a recovery retry)
 */
int
nfs4_start_lock_seqid_sync(nfs4_lock_owner_t *lop, mntinfo4_t *mi)
{
	int error = 0;
#ifdef DEBUG
	static int ops = 0;		/* fault injection */
#endif

#ifdef DEBUG
	if (seqid_sync_faults && curthread != mi->mi_recovthread &&
	    ++ops % 7 == 0)
		return (EAGAIN);
#endif

	mutex_enter(&mi->mi_lock);
	if ((mi->mi_flags & MI4_RECOV_ACTIV) &&
	    curthread != mi->mi_recovthread)
		error = EAGAIN;
	mutex_exit(&mi->mi_lock);
	if (error != 0)
		goto done;

	mutex_enter(&lop->lo_lock);

	ASSERT(lop->lo_seqid_holder != curthread);
	while (lop->lo_flags & NFS4_LOCK_SEQID_INUSE) {
		NFS4_DEBUG(nfs4_seqid_sync, (CE_NOTE,
		    "nfs4_start_lock_seqid_sync: waiting on cv"));

		cv_wait(&lop->lo_cv_seqid_sync, &lop->lo_lock);
	}
	NFS4_DEBUG(nfs4_seqid_sync, (CE_NOTE, "nfs4_start_lock_seqid_sync: "
	    "NFS4_LOCK_SEQID_INUSE"));

	lop->lo_flags |= NFS4_LOCK_SEQID_INUSE;
	lop->lo_seqid_holder = curthread;
	mutex_exit(&lop->lo_lock);

	mutex_enter(&mi->mi_lock);
	if ((mi->mi_flags & MI4_RECOV_ACTIV) &&
	    curthread != mi->mi_recovthread)
		error = EAGAIN;
	mutex_exit(&mi->mi_lock);

	if (error == EAGAIN)
		nfs4_end_lock_seqid_sync(lop);

	NFS4_DEBUG(nfs4_seqid_sync, (CE_NOTE,
	    "nfs4_start_lock_seqid_sync: error=%d", error));

done:
	return (error);
}

/*
 * This ends our use of the lock owner's lock seqid by setting
 * the appropiate flags and issuing a cv_signal to wake up another
 * thread waiting to use the lock seqid.
 */
void
nfs4_end_lock_seqid_sync(nfs4_lock_owner_t *lop)
{
	mutex_enter(&lop->lo_lock);
	ASSERT(lop->lo_flags & NFS4_LOCK_SEQID_INUSE);
	ASSERT(lop->lo_seqid_holder == curthread);
	lop->lo_flags &= ~NFS4_LOCK_SEQID_INUSE;
	lop->lo_seqid_holder = NULL;
	cv_broadcast(&lop->lo_cv_seqid_sync);
	mutex_exit(&lop->lo_lock);
}

/*
 * Returns a reference to a lock owner via lopp, which has its lock seqid
 * synchronization started.
 * If the lock owner is in the 'just_created' state, then we return its open
 * owner and open stream and start the open seqid synchronization.
 *
 * Return value:
 * NFS4_OK		no problems
 * NFS4ERR_DELAY	there is lost state to recover; caller should retry
 * NFS4ERR_IO		no open stream
 */
nfsstat4
nfs4_find_or_create_lock_owner(pid_t pid, rnode4_t *rp, cred_t *cr,
	nfs4_open_owner_t **oopp, nfs4_open_stream_t **ospp,
	nfs4_lock_owner_t **lopp)
{
	nfs4_lock_owner_t *lop, *next_lop;
	mntinfo4_t *mi;
	int error = 0;
	nfsstat4 stat;

	mi = VTOMI4(RTOV4(rp));

	mutex_enter(&rp->r_statev4_lock);

	lop = rp->r_lo_head.lo_next_rnode;
	while (lop != &rp->r_lo_head) {
		mutex_enter(&lop->lo_lock);
		if (lop->lo_pid == pid && lop->lo_valid != 0) {
			/* Found a matching lock owner */
			NFS4_DEBUG(nfs4_client_state_debug,
			    (CE_NOTE, "nfs4_find_or_create_lock_owner: "
			    "got a match"));
			lop->lo_ref_count++;
			break;
		}
		next_lop = lop->lo_next_rnode;
		mutex_exit(&lop->lo_lock);
		lop = next_lop;
	}

	if (lop == &rp->r_lo_head) {
		/* create temporary lock owner */
		lop = create_lock_owner(rp, pid);
	}
	mutex_exit(&rp->r_statev4_lock);

	/* Have a locked down lock owner struct now */
	if (lop->lo_just_created != NFS4_JUST_CREATED) {
		/* This is an existing lock owner */
		*oopp = NULL;
		*ospp = NULL;
	} else {
		/* Lock owner doesn't exist yet */

		/* First grab open owner seqid synchronization */
		mutex_exit(&lop->lo_lock);
		*oopp = find_open_owner(cr, NFS4_PERM_CREATED, mi);
		if (*oopp == NULL)
			goto kill_new_lop;
		error = nfs4_start_open_seqid_sync(*oopp, mi);
		if (error == EAGAIN) {
			stat = NFS4ERR_DELAY;
			goto failed;
		}
		*ospp = find_open_stream(*oopp, rp);
		if (*ospp == NULL) {
			nfs4_end_open_seqid_sync(*oopp);
			goto kill_new_lop;
		}
		if ((*ospp)->os_failed_reopen) {
			mutex_exit(&(*ospp)->os_sync_lock);
			NFS4_DEBUG((nfs4_open_stream_debug ||
			    nfs4_client_lock_debug), (CE_NOTE,
			    "nfs4_find_or_create_lock_owner: os_failed_reopen;"
			    "osp %p, cr %p, rp %s", (void *)(*ospp),
			    (void *)cr, rnode4info(rp)));
			nfs4_end_open_seqid_sync(*oopp);
			stat = NFS4ERR_IO;
			goto failed;
		}
		mutex_exit(&(*ospp)->os_sync_lock);

		/*
		 * Now see if the lock owner has become permanent while we
		 * had released our lock.
		 */
		mutex_enter(&lop->lo_lock);
		if (lop->lo_just_created != NFS4_JUST_CREATED) {
			nfs4_end_open_seqid_sync(*oopp);
			open_stream_rele(*ospp, rp);
			open_owner_rele(*oopp);
			*oopp = NULL;
			*ospp = NULL;
		}
	}
	mutex_exit(&lop->lo_lock);

	error = nfs4_start_lock_seqid_sync(lop, mi);
	if (error == EAGAIN) {
		if (*oopp != NULL)
			nfs4_end_open_seqid_sync(*oopp);
		stat = NFS4ERR_DELAY;
		goto failed;
	}
	ASSERT(error == 0);

	*lopp = lop;
	return (NFS4_OK);

kill_new_lop:
	/*
	 * A previous CLOSE was attempted but got EINTR, but the application
	 * continued to use the unspecified state file descriptor.  But now the
	 * open stream is gone (which could also destroy the open owner), hence
	 * we can no longer continue.  The calling function should return EIO
	 * to the application.
	 */
	NFS4_DEBUG(nfs4_lost_rqst_debug || nfs4_client_lock_debug,
	    (CE_NOTE, "nfs4_find_or_create_lock_owner: destroy newly created "
	    "lop %p, oop %p, osp %p", (void *)lop, (void *)(*oopp),
	    (void *)(*ospp)));

	nfs4_rnode_remove_lock_owner(rp, lop);
	stat = NFS4ERR_IO;

failed:
	lock_owner_rele(lop);
	if (*oopp) {
		open_owner_rele(*oopp);
		*oopp = NULL;
	}
	if (*ospp) {
		open_stream_rele(*ospp, rp);
		*ospp = NULL;
	}
	return (stat);
}

/*
 * This function grabs a recently freed open owner off of the freed open
 * owner list if there is a match on the cred 'cr'.  It returns NULL if no
 * such match is found.  It will set the 'oo_ref_count' and 'oo_valid' back
 * to both 1 (sane values) in the case a match is found.
 */
static nfs4_open_owner_t *
find_freed_open_owner(cred_t *cr, nfs4_oo_hash_bucket_t *bucketp,
	mntinfo4_t *mi)
{
	nfs4_open_owner_t		*foop;

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
	    "find_freed_open_owner: cred %p", (void*)cr));

	ASSERT(mutex_owned(&mi->mi_lock));
	ASSERT(mutex_owned(&bucketp->b_lock));

	/* got hash bucket, search through freed open owners */
	for (foop = list_head(&mi->mi_foo_list); foop != NULL;
	    foop = list_next(&mi->mi_foo_list, foop)) {
		if (!crcmp(foop->oo_cred, cr)) {
			NFS4_DEBUG(nfs4_client_foo_debug, (CE_NOTE,
			    "find_freed_open_owner: got a match open owner "
			    "%p", (void *)foop));
			foop->oo_ref_count = 1;
			foop->oo_valid = 1;
			list_remove(&mi->mi_foo_list, foop);
			mi->mi_foo_num--;

			/* now add the struct into the cred hash table */
			list_insert_head(&bucketp->b_oo_hash_list, foop);
			return (foop);
		}
	}

	return (NULL);
}

/*
 * Insert the newly freed 'oop' into the mi's freed oop list,
 * always at the head of the list.  If we've already reached
 * our maximum allowed number of freed open owners (mi_foo_max),
 * then remove the LRU open owner on the list (namely the tail).
 */
static void
nfs4_free_open_owner(nfs4_open_owner_t *oop, mntinfo4_t *mi)
{
	nfs4_open_owner_t *lru_foop;

	if (mi->mi_foo_num < mi->mi_foo_max) {
		NFS4_DEBUG(nfs4_client_foo_debug, (CE_NOTE,
		    "nfs4_free_open_owner: num free %d, max free %d, "
		    "insert open owner %p for mntinfo4 %p",
		    mi->mi_foo_num, mi->mi_foo_max, (void *)oop,
		    (void *)mi));
		list_insert_head(&mi->mi_foo_list, oop);
		mi->mi_foo_num++;
		return;
	}

	/* need to replace a freed open owner */

	lru_foop = list_tail(&mi->mi_foo_list);

	NFS4_DEBUG(nfs4_client_foo_debug, (CE_NOTE,
	    "nfs4_free_open_owner: destroy %p, insert %p",
	    (void *)lru_foop, (void *)oop));

	list_remove(&mi->mi_foo_list, lru_foop);
	nfs4_destroy_open_owner(lru_foop);

	/* head always has latest freed oop */
	list_insert_head(&mi->mi_foo_list, oop);
}

void
nfs4_destroy_open_owner(nfs4_open_owner_t *oop)
{
	ASSERT(oop != NULL);

	crfree(oop->oo_cred);
	if (oop->oo_cred_otw)
		crfree(oop->oo_cred_otw);
	mutex_destroy(&oop->oo_lock);
	cv_destroy(&oop->oo_cv_seqid_sync);
	kmem_free(oop, sizeof (*oop));
}

seqid4
nfs4_get_open_seqid(nfs4_open_owner_t *oop)
{
	ASSERT(oop->oo_seqid_inuse);
	return (oop->oo_seqid);
}

/*
 * This set's the open seqid for a <open owner/ mntinfo4> pair.
 */
void
nfs4_set_open_seqid(seqid4 seqid, nfs4_open_owner_t *oop,
	nfs4_tag_type_t tag_type)
{
	ASSERT(oop->oo_seqid_inuse);
	oop->oo_seqid = seqid;
	oop->oo_last_good_seqid = seqid;
	oop->oo_last_good_op = tag_type;
}

/*
 * This bumps the current open seqid for the open owner 'oop'.
 */
void
nfs4_get_and_set_next_open_seqid(nfs4_open_owner_t *oop,
    nfs4_tag_type_t tag_type)
{
	ASSERT(oop->oo_seqid_inuse);
	oop->oo_seqid++;
	oop->oo_last_good_seqid = oop->oo_seqid;
	oop->oo_last_good_op = tag_type;
}

/*
 * If no open owner was provided, this function takes the cred to find an
 * open owner within the given mntinfo4_t.  Either way we return the
 * open owner's OTW credential if it exists; otherwise returns the
 * supplied 'cr'.
 *
 * A hold is put on the returned credential, and it is up to the caller
 * to free the cred.
 */
cred_t *
nfs4_get_otw_cred(cred_t *cr, mntinfo4_t *mi, nfs4_open_owner_t *provided_oop)
{
	cred_t *ret_cr;
	nfs4_open_owner_t *oop = provided_oop;

	if (oop == NULL)
		oop = find_open_owner(cr, NFS4_PERM_CREATED, mi);
	if (oop != NULL) {
		mutex_enter(&oop->oo_lock);
		if (oop->oo_cred_otw)
			ret_cr = oop->oo_cred_otw;
		else
			ret_cr = cr;
		crhold(ret_cr);
		mutex_exit(&oop->oo_lock);
		if (provided_oop == NULL)
			open_owner_rele(oop);
	} else {
		ret_cr = cr;
		crhold(ret_cr);
	}
	return (ret_cr);
}

/*
 * Retrieves the next open stream in the rnode's list if an open stream
 * is provided; otherwise gets the first open stream in the list.
 * The open owner for that open stream is then retrieved, and if its
 * oo_cred_otw exists then it is returned; otherwise the provided 'cr'
 * is returned.  *osp is set to the 'found' open stream.
 *
 * Note: we don't set *osp to the open stream retrieved via the
 * optimized check since that won't necessarily be at the beginning
 * of the rnode list, and if that osp doesn't work we'd like to
 * check _all_ open streams (starting from the beginning of the
 * rnode list).
 */
cred_t *
nfs4_get_otw_cred_by_osp(rnode4_t *rp, cred_t *cr,
	nfs4_open_stream_t **osp, bool_t *first_time, bool_t *last_time)
{
	nfs4_open_stream_t *next_osp = NULL;
	cred_t *ret_cr;

	ASSERT(cr != NULL);
	/*
	 * As an optimization, try to find the open owner
	 * for the cred provided since that's most likely
	 * to work.
	 */
	if (*first_time) {
		nfs4_open_owner_t *oop;

		oop = find_open_owner(cr, NFS4_PERM_CREATED, VTOMI4(RTOV4(rp)));
		if (oop) {
			next_osp = find_open_stream(oop, rp);
			if (next_osp)
				mutex_exit(&next_osp->os_sync_lock);
			open_owner_rele(oop);
		}
	}
	if (next_osp == NULL) {
		int delay_rele = 0;
		*first_time = FALSE;

		/* return the next open stream for this rnode */
		mutex_enter(&rp->r_os_lock);
		/* Now, no one can add or delete to rp's open streams list */

		if (*osp) {
			next_osp = list_next(&rp->r_open_streams, *osp);
			/*
			 * Delay the rele of *osp until after we drop
			 * r_os_lock to not deadlock with oo_lock
			 * via an open_stream_rele()->open_owner_rele().
			 */
			delay_rele = 1;
		} else {
			next_osp = list_head(&rp->r_open_streams);
		}
		if (next_osp) {
			nfs4_open_stream_t *tmp_osp;

			/* find the next valid open stream */
			mutex_enter(&next_osp->os_sync_lock);
			while (next_osp && !next_osp->os_valid) {
				tmp_osp =
				    list_next(&rp->r_open_streams, next_osp);
				mutex_exit(&next_osp->os_sync_lock);
				next_osp = tmp_osp;
				if (next_osp)
					mutex_enter(&next_osp->os_sync_lock);
			}
			if (next_osp) {
				next_osp->os_ref_count++;
				mutex_exit(&next_osp->os_sync_lock);
			}
		}
		mutex_exit(&rp->r_os_lock);
		if (delay_rele)
			open_stream_rele(*osp, rp);
	}

	if (next_osp) {
		nfs4_open_owner_t *oop;

		oop = next_osp->os_open_owner;
		mutex_enter(&oop->oo_lock);
		if (oop->oo_cred_otw)
			ret_cr = oop->oo_cred_otw;
		else
			ret_cr = cr;
		crhold(ret_cr);
		mutex_exit(&oop->oo_lock);
		if (*first_time) {
			open_stream_rele(next_osp, rp);
			*osp = NULL;
		} else
			*osp = next_osp;
	} else {
		/* just return the cred provided to us */
		*last_time = TRUE;
		*osp = NULL;
		ret_cr = cr;
		crhold(ret_cr);
	}

	*first_time = FALSE;
	return (ret_cr);
}

void
nfs4_init_stateid_types(nfs4_stateid_types_t *sid_tp)
{
	bzero(&sid_tp->d_sid, sizeof (stateid4));
	bzero(&sid_tp->l_sid, sizeof (stateid4));
	bzero(&sid_tp->o_sid, sizeof (stateid4));
	sid_tp->cur_sid_type = NO_SID;
}

void
nfs4_save_stateid(stateid4 *s1, nfs4_stateid_types_t *sid_tp)
{
	NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
	    "nfs4_save_stateid: saved %s stateid",
	    sid_tp->cur_sid_type == DEL_SID ? "delegation" :
	    sid_tp->cur_sid_type == LOCK_SID ? "lock" :
	    sid_tp->cur_sid_type == OPEN_SID ? "open" : "special"));

	switch (sid_tp->cur_sid_type) {
	case DEL_SID:
		sid_tp->d_sid = *s1;
		break;
	case LOCK_SID:
		sid_tp->l_sid = *s1;
		break;
	case OPEN_SID:
		sid_tp->o_sid = *s1;
		break;
	case SPEC_SID:
	default:
		cmn_err(CE_PANIC, "nfs4_save_stateid: illegal "
		    "stateid type %d", sid_tp->cur_sid_type);
	}
}

/*
 * We got NFS4ERR_BAD_SEQID.  Setup some arguments to pass to recovery.
 * Caller is responsible for freeing.
 */
nfs4_bseqid_entry_t *
nfs4_create_bseqid_entry(nfs4_open_owner_t *oop, nfs4_lock_owner_t *lop,
    vnode_t *vp, pid_t pid, nfs4_tag_type_t tag, seqid4 seqid)
{
	nfs4_bseqid_entry_t	*bsep;

	bsep = kmem_alloc(sizeof (*bsep), KM_SLEEP);
	bsep->bs_oop = oop;
	bsep->bs_lop = lop;
	bsep->bs_vp = vp;
	bsep->bs_pid = pid;
	bsep->bs_tag = tag;
	bsep->bs_seqid = seqid;

	return (bsep);
}

void
nfs4open_dg_save_lost_rqst(int error, nfs4_lost_rqst_t *lost_rqstp,
	nfs4_open_owner_t *oop, nfs4_open_stream_t *osp, cred_t *cr,
	vnode_t *vp, int access_close, int deny_close)
{
	lost_rqstp->lr_putfirst = FALSE;

	ASSERT(vp != NULL);
	if (error == ETIMEDOUT || error == EINTR ||
	    NFS4_FRC_UNMT_ERR(error, vp->v_vfsp)) {
		NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
		    "nfs4open_dg_save_lost_rqst: error %d", error));

		lost_rqstp->lr_op = OP_OPEN_DOWNGRADE;
		/*
		 * The vp is held and rele'd via the recovery code.
		 * See nfs4_save_lost_rqst.
		 */
		lost_rqstp->lr_vp = vp;
		lost_rqstp->lr_dvp = NULL;
		lost_rqstp->lr_oop = oop;
		lost_rqstp->lr_osp = osp;
		lost_rqstp->lr_lop = NULL;
		lost_rqstp->lr_cr = cr;
		lost_rqstp->lr_flk = NULL;
		lost_rqstp->lr_dg_acc = access_close;
		lost_rqstp->lr_dg_deny = deny_close;
		lost_rqstp->lr_putfirst = FALSE;
	} else {
		lost_rqstp->lr_op = 0;
	}
}

/*
 * Change the access and deny bits of an OPEN.
 * If recovery is needed, *recov_credpp is set to the cred used OTW,
 * a hold is placed on it, and *recov_seqidp is set to the seqid used OTW.
 */
void
nfs4_open_downgrade(int access_close, int deny_close, nfs4_open_owner_t *oop,
	nfs4_open_stream_t *osp, vnode_t *vp, cred_t *cr, nfs4_lost_rqst_t *lrp,
	nfs4_error_t *ep, cred_t **recov_credpp, seqid4 *recov_seqidp)
{
	mntinfo4_t		*mi;
	int			downgrade_acc, downgrade_deny;
	int			new_acc, new_deny;
	COMPOUND4args_clnt	args;
	COMPOUND4res_clnt	res;
	OPEN_DOWNGRADE4res	*odg_res;
	nfs_argop4		argop[3];
	nfs_resop4		*resop;
	rnode4_t		*rp;
	bool_t			needrecov = FALSE;
	int			doqueue = 1;
	seqid4			seqid = 0;
	cred_t			*cred_otw;
	hrtime_t		t;

	ASSERT(mutex_owned(&osp->os_sync_lock));
#if DEBUG
	mutex_enter(&oop->oo_lock);
	ASSERT(oop->oo_seqid_inuse);
	mutex_exit(&oop->oo_lock);
#endif


	if (access_close == 0 && deny_close == 0) {
		nfs4_error_zinit(ep);
		return;
	}

	cred_otw = nfs4_get_otw_cred(cr, VTOMI4(vp), oop);

cred_retry:
	nfs4_error_zinit(ep);
	downgrade_acc = 0;
	downgrade_deny = 0;
	mi = VTOMI4(vp);
	rp = VTOR4(vp);

	/*
	 * Check to see if the open stream got closed before we go OTW,
	 * now that we have acquired the 'os_sync_lock'.
	 */
	if (!osp->os_valid) {
		NFS4_DEBUG(nfs4_client_open_dg, (CE_NOTE, "nfs4_open_downgrade:"
		    " open stream has already been closed, return success"));
		/* error has already been set */
		goto no_args_out;
	}

	/* If the file failed recovery, just quit. */
	mutex_enter(&rp->r_statelock);
	if (rp->r_flags & R4RECOVERR) {
		mutex_exit(&rp->r_statelock);
		ep->error = EIO;
		goto no_args_out;
	}
	mutex_exit(&rp->r_statelock);

	seqid = nfs4_get_open_seqid(oop) + 1;

	NFS4_DEBUG(nfs4_client_open_dg, (CE_NOTE, "nfs4_open_downgrade:"
	    "access_close %d, acc_read %"PRIu64" acc_write %"PRIu64"",
	    access_close, osp->os_share_acc_read, osp->os_share_acc_write));

	/* If we're closing the last READ, need to downgrade */
	if ((access_close & FREAD) && (osp->os_share_acc_read == 1))
		downgrade_acc |= OPEN4_SHARE_ACCESS_READ;

	/* if we're closing the last WRITE, need to downgrade */
	if ((access_close & FWRITE) && (osp->os_share_acc_write == 1))
		downgrade_acc |= OPEN4_SHARE_ACCESS_WRITE;

	downgrade_deny = OPEN4_SHARE_DENY_NONE;

	new_acc = 0;
	new_deny = 0;

	/* set our new access and deny share bits */
	if ((osp->os_share_acc_read > 0) &&
	    !(downgrade_acc & OPEN4_SHARE_ACCESS_READ))
		new_acc |= OPEN4_SHARE_ACCESS_READ;
	if ((osp->os_share_acc_write > 0) &&
	    !(downgrade_acc & OPEN4_SHARE_ACCESS_WRITE))
		new_acc |= OPEN4_SHARE_ACCESS_WRITE;

	new_deny = OPEN4_SHARE_DENY_NONE;

	NFS4_DEBUG(nfs4_client_open_dg, (CE_NOTE, "nfs4_open_downgrade:"
	    "downgrade acc 0x%x deny 0x%x", downgrade_acc, downgrade_deny));
	NFS4_DEBUG(nfs4_client_open_dg, (CE_NOTE, "nfs4_open_downgrade:"
	    "new acc 0x%x deny 0x%x", new_acc, new_deny));

	/*
	 * Check to see if we aren't actually doing any downgrade or
	 * if this is the last 'close' but the file is still mmapped.
	 * Skip this if this a lost request resend so we don't decrement
	 * the osp's share counts more than once.
	 */
	if (!lrp &&
	    ((downgrade_acc == 0 && downgrade_deny == 0) ||
	    (new_acc == 0 && new_deny == 0))) {
		/*
		 * No downgrade to do, but still need to
		 * update osp's os_share_* counts.
		 */
		NFS4_DEBUG(nfs4_client_open_dg, (CE_NOTE,
		    "nfs4_open_downgrade: just lower the osp's count by %s",
		    (access_close & FREAD) && (access_close & FWRITE) ?
		    "read and write" : (access_close & FREAD) ? "read" :
		    (access_close & FWRITE) ? "write" : "bogus"));
		if (access_close & FREAD)
			osp->os_share_acc_read--;
		if (access_close & FWRITE)
			osp->os_share_acc_write--;
		osp->os_share_deny_none--;
		nfs4_error_zinit(ep);

		goto no_args_out;
	}

	if (osp->os_orig_oo_name != oop->oo_name) {
		ep->error = EIO;
		goto no_args_out;
	}

	/* setup the COMPOUND args */
	if (lrp)
		args.ctag = TAG_OPEN_DG_LOST;
	else
		args.ctag = TAG_OPEN_DG;

	args.array_len = 3;
	args.array = argop;

	/* putfh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	argop[1].argop = OP_GETATTR;
	argop[1].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[1].nfs_argop4_u.opgetattr.mi = mi;

	ASSERT(mutex_owned(&osp->os_sync_lock));
	ASSERT(osp->os_delegation == FALSE);

	/* open downgrade */
	argop[2].argop = OP_OPEN_DOWNGRADE;
	argop[2].nfs_argop4_u.opopen_downgrade.open_stateid = osp->open_stateid;
	argop[2].nfs_argop4_u.opopen_downgrade.share_access = new_acc;
	argop[2].nfs_argop4_u.opopen_downgrade.share_deny = new_deny;
	argop[2].nfs_argop4_u.opopen_downgrade.seqid = seqid;

	t = gethrtime();

	rfs4call(mi, &args, &res, cred_otw, &doqueue, 0, ep);

	if (ep->error == 0 && nfs4_need_to_bump_seqid(&res))
		nfs4_set_open_seqid(seqid, oop, args.ctag);

	if ((ep->error == EACCES ||
	    (ep->error == 0 && res.status == NFS4ERR_ACCESS)) &&
	    cred_otw != cr) {
		crfree(cred_otw);
		cred_otw = cr;
		crhold(cred_otw);
		if (!ep->error)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		goto cred_retry;
	}

	needrecov = nfs4_needs_recovery(ep, TRUE, mi->mi_vfsp);

	if (needrecov && recov_credpp) {
		*recov_credpp = cred_otw;
		crhold(*recov_credpp);
		if (recov_seqidp)
			*recov_seqidp = seqid;
	}

	if (!ep->error && !res.status) {
		/* get the open downgrade results */
		resop = &res.array[2];
		odg_res = &resop->nfs_resop4_u.opopen_downgrade;

		osp->open_stateid = odg_res->open_stateid;

		/* set the open streams new access/deny bits */
		if (access_close & FREAD)
			osp->os_share_acc_read--;
		if (access_close & FWRITE)
			osp->os_share_acc_write--;
		osp->os_share_deny_none--;
		osp->os_dc_openacc = new_acc;

		nfs4_attr_cache(vp,
		    &res.array[1].nfs_resop4_u.opgetattr.ga_res,
		    t, cred_otw, TRUE, NULL);
	}

	if (!ep->error)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

no_args_out:
	crfree(cred_otw);
}

/*
 * If an OPEN request gets ETIMEDOUT or EINTR (that includes bailing out
 * because the filesystem was forcibly unmounted) then we don't know if we
 * potentially left state dangling on the server, therefore the recovery
 * framework makes this call to resend the OPEN request and then undo it.
 */
void
nfs4_resend_open_otw(vnode_t **vpp, nfs4_lost_rqst_t *resend_rqstp,
	nfs4_error_t *ep)
{
	COMPOUND4args_clnt	args;
	COMPOUND4res_clnt	res;
	nfs_argop4		argop[4];
	GETFH4res		*gf_res = NULL;
	OPEN4cargs		*open_args;
	OPEN4res		*op_res;
	char			*destcfp;
	int			destclen;
	nfs4_ga_res_t		*garp;
	vnode_t			*dvp = NULL, *vp = NULL;
	rnode4_t		*rp = NULL, *drp = NULL;
	cred_t			*cr = NULL;
	seqid4			seqid;
	nfs4_open_owner_t	*oop = NULL;
	nfs4_open_stream_t	*osp = NULL;
	component4		*srcfp;
	open_claim_type4	claim;
	mntinfo4_t		*mi;
	int			doqueue = 1;
	bool_t			retry_open = FALSE;
	int			created_osp = 0;
	hrtime_t		t;
	char 			*failed_msg = "";
	int			fh_different;
	int			reopen = 0;

	nfs4_error_zinit(ep);

	cr = resend_rqstp->lr_cr;
	dvp = resend_rqstp->lr_dvp;

	vp = *vpp;
	if (vp) {
		ASSERT(nfs4_consistent_type(vp));
		rp = VTOR4(vp);
	}

	if (rp) {
		/* If the file failed recovery, just quit. */
		mutex_enter(&rp->r_statelock);
		if (rp->r_flags & R4RECOVERR) {
			mutex_exit(&rp->r_statelock);
			ep->error = EIO;
			return;
		}
		mutex_exit(&rp->r_statelock);
	}

	if (dvp) {
		drp = VTOR4(dvp);
		/* If the parent directory failed recovery, just quit. */
		mutex_enter(&drp->r_statelock);
		if (drp->r_flags & R4RECOVERR) {
			mutex_exit(&drp->r_statelock);
			ep->error = EIO;
			return;
		}
		mutex_exit(&drp->r_statelock);
	} else
		reopen = 1;	/* NULL dvp means this is a reopen */

	claim = resend_rqstp->lr_oclaim;
	ASSERT(claim == CLAIM_NULL || claim == CLAIM_DELEGATE_CUR);

	args.ctag = TAG_OPEN_LOST;
	args.array_len = 4;
	args.array = argop;

	argop[0].argop = OP_CPUTFH;
	if (reopen) {
		ASSERT(vp != NULL);

		mi = VTOMI4(vp);
		/*
		 * if this is a file mount then
		 * use the mntinfo parentfh
		 */
		argop[0].nfs_argop4_u.opcputfh.sfh =
		    (vp->v_flag & VROOT) ? mi->mi_srvparentfh :
		    VTOSV(vp)->sv_dfh;
		args.ctag = TAG_REOPEN_LOST;
	} else {
		argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(dvp)->r_fh;
		mi = VTOMI4(dvp);
	}

	argop[1].argop = OP_COPEN;
	open_args = &argop[1].nfs_argop4_u.opcopen;
	open_args->claim = claim;

	/*
	 * If we sent over a OPEN with CREATE then the only
	 * thing we care about is to not leave dangling state
	 * on the server, not whether the file we potentially
	 * created remains on the server.  So even though the
	 * lost open request specified a CREATE, we only wish
	 * to do a non-CREATE OPEN.
	 */
	open_args->opentype = OPEN4_NOCREATE;

	srcfp = &resend_rqstp->lr_ofile;
	destclen = srcfp->utf8string_len;
	destcfp = kmem_alloc(destclen + 1, KM_SLEEP);
	bcopy(srcfp->utf8string_val, destcfp, destclen);
	destcfp[destclen] = '\0';
	if (claim == CLAIM_DELEGATE_CUR) {
		open_args->open_claim4_u.delegate_cur_info.delegate_stateid =
		    resend_rqstp->lr_ostateid;
		open_args->open_claim4_u.delegate_cur_info.cfile = destcfp;
	} else {
		open_args->open_claim4_u.cfile = destcfp;
	}

	open_args->share_access = resend_rqstp->lr_oacc;
	open_args->share_deny = resend_rqstp->lr_odeny;
	oop = resend_rqstp->lr_oop;
	ASSERT(oop != NULL);

	open_args->owner.clientid = mi2clientid(mi);
	/* this length never changes */
	open_args->owner.owner_len = sizeof (oop->oo_name);
	open_args->owner.owner_val =
	    kmem_alloc(open_args->owner.owner_len, KM_SLEEP);

	ep->error = nfs4_start_open_seqid_sync(oop, mi);
	ASSERT(ep->error == 0);		/* recov thread always succeeds */
	/*
	 * We can get away with not saving the seqid upon detection
	 * of a lost request, and now just use the open owner's current
	 * seqid since we only allow one op OTW per seqid and lost
	 * requests are saved FIFO.
	 */
	seqid = nfs4_get_open_seqid(oop) + 1;
	open_args->seqid = seqid;

	bcopy(&oop->oo_name, open_args->owner.owner_val,
	    open_args->owner.owner_len);

	/* getfh */
	argop[2].argop = OP_GETFH;

	/* Construct the getattr part of the compound */
	argop[3].argop = OP_GETATTR;
	argop[3].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[3].nfs_argop4_u.opgetattr.mi = mi;

	res.array = NULL;

	t = gethrtime();

	rfs4call(mi, &args, &res, cr, &doqueue, 0, ep);

	if (ep->error == 0 && nfs4_need_to_bump_seqid(&res))
		nfs4_set_open_seqid(seqid, oop, args.ctag);

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
	    "nfs4_resend_open_otw: error %d stat %d", ep->error, res.status));

	if (ep->error || res.status)
		goto err_out;

	op_res = &res.array[1].nfs_resop4_u.opopen;
	gf_res = &res.array[2].nfs_resop4_u.opgetfh;
	garp = &res.array[3].nfs_resop4_u.opgetattr.ga_res;

	if (!vp) {
		int rnode_err = 0;
		nfs4_sharedfh_t *sfh;

		/*
		 * If we can't decode all the attributes they are not usable,
		 * just make the vnode.
		 */

		sfh = sfh4_get(&gf_res->object, VTOMI4(dvp));
		*vpp = makenfs4node(sfh, garp, dvp->v_vfsp, t, cr, dvp,
		    fn_get(VTOSV(dvp)->sv_name,
		    open_args->open_claim4_u.cfile, sfh));
		sfh4_rele(&sfh);
		NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
		    "nfs4_resend_open_otw: made vp %p for file %s",
		    (void *)(*vpp), open_args->open_claim4_u.cfile));

		if (ep->error)
			PURGE_ATTRCACHE4(*vpp);

		/*
		 * For the newly created *vpp case, make sure the rnode
		 * isn't bad before using it.
		 */
		mutex_enter(&(VTOR4(*vpp))->r_statelock);
		if (VTOR4(*vpp)->r_flags & R4RECOVERR)
			rnode_err = EIO;
		mutex_exit(&(VTOR4(*vpp))->r_statelock);

		if (rnode_err) {
			NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
			    "nfs4_resend_open_otw: rp %p is bad",
			    (void *)VTOR4(*vpp)));
			ep->error = rnode_err;
			goto err_out;
		}

		vp = *vpp;
		rp = VTOR4(vp);
	}

	if (reopen) {
		/*
		 * Check if the path we reopened really is the same
		 * file. We could end up in a situation were the file
		 * was removed and a new file created with the same name.
		 */
		(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_READER, 0);
		fh_different =
		    (nfs4cmpfh(&rp->r_fh->sfh_fh, &gf_res->object) != 0);
		if (fh_different) {
			if (mi->mi_fh_expire_type == FH4_PERSISTENT ||
			    mi->mi_fh_expire_type & FH4_NOEXPIRE_WITH_OPEN) {
				/* Oops, we don't have the same file */
				if (mi->mi_fh_expire_type == FH4_PERSISTENT)
					failed_msg =
					    "Couldn't reopen: Persistant "
					    "file handle changed";
				else
					failed_msg =
					    "Couldn't reopen: Volatile "
					    "(no expire on open) file handle "
					    "changed";

				nfs4_end_open_seqid_sync(oop);
				kmem_free(destcfp, destclen + 1);
				nfs4args_copen_free(open_args);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				nfs_rw_exit(&mi->mi_fh_lock);
				nfs4_fail_recov(vp, failed_msg, ep->error,
				    ep->stat);
				return;
			} else {
				/*
				 * We have volatile file handles that don't
				 * compare.  If the fids are the same then we
				 * assume that the file handle expired but the
				 * renode still refers to the same file object.
				 *
				 * First check that we have fids or not.
				 * If we don't we have a dumb server so we will
				 * just assume every thing is ok for now.
				 */
				if (!ep->error &&
				    garp->n4g_va.va_mask & AT_NODEID &&
				    rp->r_attr.va_mask & AT_NODEID &&
				    rp->r_attr.va_nodeid !=
				    garp->n4g_va.va_nodeid) {
					/*
					 * We have fids, but they don't
					 * compare. So kill the file.
					 */
					failed_msg =
					    "Couldn't reopen: file handle "
					    "changed due to mismatched fids";
					nfs4_end_open_seqid_sync(oop);
					kmem_free(destcfp, destclen + 1);
					nfs4args_copen_free(open_args);
					(void) xdr_free(xdr_COMPOUND4res_clnt,
					    (caddr_t)&res);
					nfs_rw_exit(&mi->mi_fh_lock);
					nfs4_fail_recov(vp, failed_msg,
					    ep->error, ep->stat);
					return;
				} else {
					/*
					 * We have volatile file handles that
					 * refers to the same file (at least
					 * they have the same fid) or we don't
					 * have fids so we can't tell. :(. We'll
					 * be a kind and accepting client so
					 * we'll update the rnode's file
					 * handle with the otw handle.
					 *
					 * We need to drop mi->mi_fh_lock since
					 * sh4_update acquires it. Since there
					 * is only one recovery thread there is
					 * no race.
					 */
					nfs_rw_exit(&mi->mi_fh_lock);
					sfh4_update(rp->r_fh, &gf_res->object);
				}
			}
		} else {
			nfs_rw_exit(&mi->mi_fh_lock);
		}
	}

	ASSERT(nfs4_consistent_type(vp));

	if (op_res->rflags & OPEN4_RESULT_CONFIRM)
		nfs4open_confirm(vp, &seqid, &op_res->stateid, cr, TRUE,
		    &retry_open, oop, TRUE, ep, NULL);
	if (ep->error || ep->stat) {
		nfs4_end_open_seqid_sync(oop);
		kmem_free(destcfp, destclen + 1);
		nfs4args_copen_free(open_args);
		if (!ep->error)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	if (reopen) {
		/*
		 * Doing a reopen here so the osp should already exist.
		 * If not, something changed or went very wrong.
		 *
		 * returns with 'os_sync_lock' held
		 */
		osp = find_open_stream(oop, rp);
		if (!osp) {
			NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
			    "nfs4_resend_open_otw: couldn't find osp"));
			ep->error = EINVAL;
			goto err_out;
		}
		osp->os_open_ref_count++;
	} else {
		mutex_enter(&oop->oo_lock);
		oop->oo_just_created = NFS4_PERM_CREATED;
		mutex_exit(&oop->oo_lock);

		/* returns with 'os_sync_lock' held */
		osp = find_or_create_open_stream(oop, rp, &created_osp);
		if (!osp) {
			NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
			    "nfs4_resend_open_otw: couldn't create osp"));
			ep->error = EINVAL;
			goto err_out;
		}
	}

	osp->open_stateid = op_res->stateid;
	osp->os_delegation = FALSE;
	/*
	 * Need to reset this bitfield for the possible case where we were
	 * going to OTW CLOSE the file, got a non-recoverable error, and before
	 * we could retry the CLOSE, OPENed the file again.
	 */
	ASSERT(osp->os_open_owner->oo_seqid_inuse);
	osp->os_final_close = 0;
	osp->os_force_close = 0;

	if (!reopen) {
		if (open_args->share_access & OPEN4_SHARE_ACCESS_READ)
			osp->os_share_acc_read++;
		if (open_args->share_access & OPEN4_SHARE_ACCESS_WRITE)
			osp->os_share_acc_write++;
		osp->os_share_deny_none++;
	}

	mutex_exit(&osp->os_sync_lock);
	if (created_osp)
		nfs4_inc_state_ref_count(mi);
	open_stream_rele(osp, rp);

	nfs4_end_open_seqid_sync(oop);

	/* accept delegation, if any */
	nfs4_delegation_accept(rp, claim, op_res, garp, cr);

	kmem_free(destcfp, destclen + 1);
	nfs4args_copen_free(open_args);

	if (claim == CLAIM_DELEGATE_CUR)
		nfs4_attr_cache(vp, garp, t, cr, TRUE, NULL);
	else
		PURGE_ATTRCACHE4(vp);

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	ASSERT(nfs4_consistent_type(vp));

	return;

err_out:
	nfs4_end_open_seqid_sync(oop);
	kmem_free(destcfp, destclen + 1);
	nfs4args_copen_free(open_args);
	if (!ep->error)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
}
