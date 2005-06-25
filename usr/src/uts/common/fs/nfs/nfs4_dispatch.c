/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/auth_des.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_dispatch.h>
#include <nfs/nfs4_drc.h>

/*
 * This is the duplicate request cache for NFSv4
 */
rfs4_drc_t *nfs4_drc = NULL;

/*
 * How long the entry can remain in the cache
 * once it has been sent to the client and not
 * used in a reply (in seconds)
 */
unsigned nfs4_drc_lifetime = 1;

/*
 * The default size of the duplicate request cache
 */
uint32_t nfs4_drc_max = 8 * 1024;

/*
 * The number of buckets we'd like to hash the
 * replies into.. do not change this on the fly.
 */
uint32_t nfs4_drc_hash = 541;

/*
 * Initialize a duplicate request cache.
 */
rfs4_drc_t *
rfs4_init_drc(uint32_t drc_size, uint32_t drc_hash_size, unsigned ttl)
{
	rfs4_drc_t *drc;
	uint32_t   bki;

	ASSERT(drc_size);
	ASSERT(drc_hash_size);

	drc = kmem_alloc(sizeof (rfs4_drc_t), KM_SLEEP);

	drc->max_size = drc_size;
	drc->in_use = 0;
	drc->drc_ttl = ttl;

	mutex_init(&drc->lock, NULL, MUTEX_DEFAULT, NULL);

	drc->dr_hash = drc_hash_size;

	drc->dr_buckets = kmem_alloc(sizeof (list_t)*drc_hash_size, KM_SLEEP);

	for (bki = 0; bki < drc_hash_size; bki++) {
		list_create(&drc->dr_buckets[bki], sizeof (rfs4_dupreq_t),
		    offsetof(rfs4_dupreq_t, dr_bkt_next));
	}

	list_create(&(drc->dr_cache), sizeof (rfs4_dupreq_t),
		    offsetof(rfs4_dupreq_t, dr_next));

	return (drc);
}

/*
 * Destroy a duplicate request cache.
 */
void
rfs4_fini_drc(rfs4_drc_t *drc)
{
	rfs4_dupreq_t *drp, *drp_next;

	ASSERT(drc);

	/* iterate over the dr_cache and free the enties */
	for (drp = list_head(&(drc->dr_cache)); drp != NULL; drp = drp_next) {

		if (drp->dr_state == NFS4_DUP_REPLAY)
			rfs4_compound_free(&(drp->dr_res));

		if (drp->dr_addr.buf != NULL)
			kmem_free(drp->dr_addr.buf, drp->dr_addr.maxlen);

		drp_next = list_next(&(drc->dr_cache), drp);

		kmem_free(drp, sizeof (rfs4_dupreq_t));
	}

	mutex_destroy(&drc->lock);
	kmem_free(drc->dr_buckets,
		sizeof (list_t)*drc->dr_hash);
	kmem_free(drc, sizeof (rfs4_drc_t));
}

/*
 * rfs4_dr_chstate:
 *
 * Change the state of a rfs4_dupreq. If it's not in transition
 * to the FREE state, update the time used and return. If we
 * are moving to the FREE state then we need to clean up the
 * compound results and move the entry to the end of the list.
 */
void
rfs4_dr_chstate(rfs4_dupreq_t *drp, int new_state)
{
	rfs4_drc_t *drc;

	ASSERT(drp);
	ASSERT(drp->drc);
	ASSERT(drp->dr_bkt);
	ASSERT(MUTEX_HELD(&drp->drc->lock));

	drp->dr_state = new_state;

	if (new_state != NFS4_DUP_FREE) {
		gethrestime(&drp->dr_time_used);
		return;
	}

	drc = drp->drc;

	/*
	 * Remove entry from the bucket and
	 * dr_cache list, free compound results.
	 */
	list_remove(drp->dr_bkt, drp);
	list_remove(&(drc->dr_cache), drp);
	rfs4_compound_free(&(drp->dr_res));
}

/*
 * rfs4_alloc_dr:
 *
 * Pick an entry off the tail -- Use if it is
 * marked NFS4_DUP_FREE, or is an entry in the
 * NFS4_DUP_REPLAY state that has timed-out...
 * Otherwise malloc a new one if we have not reached
 * our maximum cache limit.
 *
 * The list should be in time order, so no need
 * to traverse backwards looking for a timed out
 * entry, NFS4_DUP_FREE's are place on the tail.
 */
rfs4_dupreq_t *
rfs4_alloc_dr(rfs4_drc_t *drc)
{
	rfs4_dupreq_t *drp_tail, *drp = NULL;

	ASSERT(drc);
	ASSERT(MUTEX_HELD(&drc->lock));

	if ((drp_tail = list_tail(&drc->dr_cache)) != NULL) {

		switch (drp_tail->dr_state) {

		case NFS4_DUP_FREE:
			list_remove(&(drc->dr_cache), drp_tail);
			DTRACE_PROBE1(nfss__i__drc_freeclaim,
					rfs4_dupreq_t *, drp_tail);
			return (drp_tail);
			/* NOTREACHED */

		case NFS4_DUP_REPLAY:
			if (gethrestime_sec() >
			    drp_tail->dr_time_used.tv_sec+drc->drc_ttl) {
				/* this entry has timedout so grab it. */
				rfs4_dr_chstate(drp_tail, NFS4_DUP_FREE);
				DTRACE_PROBE1(nfss__i__drc_ttlclaim,
					rfs4_dupreq_t *, drp_tail);
				return (drp_tail);
			}
			break;
		}
	}

	/*
	 * Didn't find something to recycle have
	 * we hit the cache limit ?
	 */
	if (drc->in_use >= drc->max_size) {
		DTRACE_PROBE1(nfss__i__drc_full,
			rfs4_drc_t *, drc);
		return (NULL);
	}


	/* nope, so let's malloc a new one */
	drp = kmem_zalloc(sizeof (rfs4_dupreq_t), KM_SLEEP);
	drp->drc = drc;
	drc->in_use++;
	gethrestime(&drp->dr_time_created);
	DTRACE_PROBE1(nfss__i__drc_new, rfs4_dupreq_t *, drp);

	return (drp);
}

/*
 * rfs4_find_dr:
 *
 * Search for an entry in the duplicate request cache by
 * calculating the hash index based on the XID, and examining
 * the entries in the hash bucket. If we find a match stamp the
 * time_used and return. If the entry does not match it could be
 * ready to be freed. Once we have searched the bucket and we
 * have not exhausted the maximum limit for the cache we will
 * allocate a new entry.
 */
int
rfs4_find_dr(struct svc_req *req, rfs4_drc_t *drc, rfs4_dupreq_t **dup)
{

	uint32_t	the_xid;
	list_t		*dr_bkt;
	rfs4_dupreq_t	*drp;
	int		bktdex;

	/*
	 * Get the XID, calculate the bucket and search to
	 * see if we need to replay from the cache.
	 */
	the_xid = req->rq_xprt->xp_xid;
	bktdex = the_xid % drc->dr_hash;

	dr_bkt = (list_t *)
		&(drc->dr_buckets[(the_xid % drc->dr_hash)]);

	DTRACE_PROBE3(nfss__i__drc_bktdex,
			int, bktdex,
			uint32_t, the_xid,
			list_t *, dr_bkt);

	*dup = NULL;

	mutex_enter(&drc->lock);
	/*
	 * Search the bucket for a matching xid and address.
	 */
	for (drp = list_head(dr_bkt); drp != NULL;
		drp = list_next(dr_bkt, drp)) {

		if (drp->dr_xid == the_xid &&
		    drp->dr_addr.len == req->rq_xprt->xp_rtaddr.len &&
		    bcmp((caddr_t)drp->dr_addr.buf,
		    (caddr_t)req->rq_xprt->xp_rtaddr.buf,
		    drp->dr_addr.len) == 0) {

			/*
			 * Found a match so REPLAY the Reply
			 */
			if (drp->dr_state == NFS4_DUP_REPLAY) {
				gethrestime(&drp->dr_time_used);
				mutex_exit(&drc->lock);
				*dup = drp;
				DTRACE_PROBE1(nfss__i__drc_replay,
					rfs4_dupreq_t *, drp);
				return (NFS4_DUP_REPLAY);
			}

			/*
			 * This entry must be in transition, so return
			 * the 'pending' status.
			 */
			mutex_exit(&drc->lock);
			return (NFS4_DUP_PENDING);
		}

		/*
		 * Not a match, but maybe this entry is ready
		 * to be reused.
		 */
		if (drp->dr_state == NFS4_DUP_REPLAY &&
			(gethrestime_sec() >
			drp->dr_time_used.tv_sec+drc->drc_ttl)) {
			rfs4_dr_chstate(drp, NFS4_DUP_FREE);
			list_insert_tail(&(drp->drc->dr_cache), drp);
		}
	}

	drp = rfs4_alloc_dr(drc);
	mutex_exit(&drc->lock);

	if (drp == NULL) {
		return (NFS4_DUP_ERROR);
	}

	/*
	 * Place at the head of the list, init the state
	 * to NEW and clear the time used field.
	 */

	drp->dr_state = NFS4_DUP_NEW;
	drp->dr_time_used.tv_sec = drp->dr_time_used.tv_nsec = 0;

	/*
	 * If needed, resize the address buffer
	 */
	if (drp->dr_addr.maxlen < req->rq_xprt->xp_rtaddr.len) {
		if (drp->dr_addr.buf != NULL)
			kmem_free(drp->dr_addr.buf, drp->dr_addr.maxlen);
		drp->dr_addr.maxlen = req->rq_xprt->xp_rtaddr.len;
		drp->dr_addr.buf = kmem_alloc(drp->dr_addr.maxlen, KM_NOSLEEP);
		if (drp->dr_addr.buf == NULL) {
			/*
			 * If the malloc fails, mark the entry
			 * as free and put on the tail.
			 */
			drp->dr_addr.maxlen = 0;
			drp->dr_state = NFS4_DUP_FREE;
			mutex_enter(&drc->lock);
			list_insert_tail(&(drc->dr_cache), drp);
			mutex_exit(&drc->lock);
			return (NFS4_DUP_ERROR);
		}
	}


	/*
	 * Copy the address.
	 */
	drp->dr_addr.len = req->rq_xprt->xp_rtaddr.len;

	bcopy((caddr_t)req->rq_xprt->xp_rtaddr.buf,
		(caddr_t)drp->dr_addr.buf,
		drp->dr_addr.len);

	drp->dr_xid = the_xid;
	drp->dr_bkt = dr_bkt;

	/*
	 * Insert at the head of the bucket and
	 * the drc lists..
	 */
	mutex_enter(&drc->lock);
	list_insert_head(&drc->dr_cache, drp);
	list_insert_head(dr_bkt, drp);
	mutex_exit(&drc->lock);

	*dup = drp;

	return (NFS4_DUP_NEW);
}

/*
 *
 * This function handles the duplicate request cache,
 * NULL_PROC and COMPOUND procedure calls for NFSv4;
 *
 * Passed into this function are:-
 *
 * 	disp	A pointer to our dispatch table entry
 * 	req	The request to process
 * 	xprt	The server transport handle
 * 	ap	A pointer to the arguments
 *
 *
 * When appropriate this function is responsible for inserting
 * the reply into the duplicate cache or replaying an existing
 * cached reply.
 *
 * dr_stat 	reflects the state of the duplicate request that
 * 		has been inserted into or retrieved from the cache
 *
 * drp		is the duplicate request entry
 *
 */
int
rfs4_dispatch(struct rpcdisp *disp, struct svc_req *req,
		SVCXPRT *xprt, char *ap)
{

	COMPOUND4res res_buf, *rbp;
	COMPOUND4args *cap;

	cred_t 	*cr = NULL;
	int	error = 0;
	int 	dis_flags = 0;
	int 	dr_stat = NFS4_NOT_DUP;
	rfs4_dupreq_t *drp = NULL;

	ASSERT(disp);

	/*
	 * Short circuit the RPC_NULL proc.
	 */
	if (disp->dis_proc == rpc_null) {
		if (!svc_sendreply(xprt, xdr_void, NULL)) {
			return (1);
		}
		return (0);
	}

	/* Only NFSv4 Compounds from this point onward */

	rbp = &res_buf;
	cap = (COMPOUND4args *)ap;

	/*
	 * Figure out the disposition of the whole COMPOUND
	 * and record it's IDEMPOTENTCY.
	 */
	rfs4_compound_flagproc(cap, &dis_flags);

	/*
	 * If NON-IDEMPOTENT then we need to figure out if this
	 * request can be replied from the duplicate cache.
	 *
	 * If this is a new request then we need to insert the
	 * reply into the duplicate cache.
	 */
	if (!(dis_flags & RPC_IDEMPOTENT)) {
		/* look for a replay from the cache or allocate */
		dr_stat = rfs4_find_dr(req, nfs4_drc, &drp);

		switch (dr_stat) {

		case NFS4_DUP_ERROR:
			svcerr_systemerr(xprt);
			return (1);
			/* NOTREACHED */

		case NFS4_DUP_PENDING:
			/*
			 * reply has previously been inserted into the
			 * duplicate cache, however the reply has
			 * not yet been sent via svc_sendreply()
			 */
			return (1);
			/* NOTREACHED */

		case NFS4_DUP_NEW:
			curthread->t_flag |= T_DONTPEND;
			/* NON-IDEMPOTENT proc call */
			rfs4_compound(cap, rbp, NULL, req, cr);

			curthread->t_flag &= ~T_DONTPEND;
			if (curthread->t_flag & T_WOULDBLOCK) {
				curthread->t_flag &= ~T_WOULDBLOCK;
				/*
				 * mark this entry as FREE and plop
				 * on the end of the cache list
				 */
				mutex_enter(&drp->drc->lock);
				rfs4_dr_chstate(drp, NFS4_DUP_FREE);
				list_insert_tail(&(drp->drc->dr_cache), drp);
				mutex_exit(&drp->drc->lock);
				return (1);
			}
			drp->dr_res = res_buf;
			break;

		case NFS4_DUP_REPLAY:
			/* replay from the cache */
			rbp = &(drp->dr_res);
			break;
		}
	} else {
		curthread->t_flag |= T_DONTPEND;
		/* IDEMPOTENT proc call */
		rfs4_compound(cap, rbp, NULL, req, cr);

		curthread->t_flag &= ~T_DONTPEND;
		if (curthread->t_flag & T_WOULDBLOCK) {
			curthread->t_flag &= ~T_WOULDBLOCK;
			return (1);
		}
	}

	/*
	 * Send out the replayed reply or the 'real' one.
	 */
	if (!svc_sendreply(xprt,  xdr_COMPOUND4res, (char *)rbp)) {
		DTRACE_PROBE2(nfss__e__dispatch_sendfail,
			struct svc_req *, xprt,
			char *, rbp);
		error++;
	}

	/*
	 * If this reply was just inserted into the duplicate cache
	 * mark it as available for replay
	 */
	if (dr_stat == NFS4_DUP_NEW) {
		mutex_enter(&drp->drc->lock);
		rfs4_dr_chstate(drp, NFS4_DUP_REPLAY);
		mutex_exit(&drp->drc->lock);
	} else if (dr_stat == NFS4_NOT_DUP) {
		rfs4_compound_free(rbp);
	}

	return (error);
}
