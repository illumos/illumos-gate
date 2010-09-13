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

#include <sys/systm.h>
#include <sys/sdt.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/auth_des.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_dispatch.h>
#include <nfs/nfs4_drc.h>

#define	NFS4_MAX_MINOR_VERSION	0

/*
 * This is the duplicate request cache for NFSv4
 */
rfs4_drc_t *nfs4_drc = NULL;

/*
 * The default size of the duplicate request cache
 */
uint32_t nfs4_drc_max = 8 * 1024;

/*
 * The number of buckets we'd like to hash the
 * replies into.. do not change this on the fly.
 */
uint32_t nfs4_drc_hash = 541;

static void rfs4_resource_err(struct svc_req *req, COMPOUND4args *argsp);

/*
 * Initialize a duplicate request cache.
 */
rfs4_drc_t *
rfs4_init_drc(uint32_t drc_size, uint32_t drc_hash_size)
{
	rfs4_drc_t *drc;
	uint32_t   bki;

	ASSERT(drc_size);
	ASSERT(drc_hash_size);

	drc = kmem_alloc(sizeof (rfs4_drc_t), KM_SLEEP);

	drc->max_size = drc_size;
	drc->in_use = 0;

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
 * to the FREE state, return. If we are moving to the FREE state
 * then we need to clean up the compound results and move the entry
 * to the end of the list.
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

	if (new_state != NFS4_DUP_FREE)
		return;

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
 * Malloc a new one if we have not reached our maximum cache
 * limit, otherwise pick an entry off the tail -- Use if it
 * is marked as NFS4_DUP_FREE, or is an entry in the
 * NFS4_DUP_REPLAY state.
 */
rfs4_dupreq_t *
rfs4_alloc_dr(rfs4_drc_t *drc)
{
	rfs4_dupreq_t *drp_tail, *drp = NULL;

	ASSERT(drc);
	ASSERT(MUTEX_HELD(&drc->lock));

	/*
	 * Have we hit the cache limit yet ?
	 */
	if (drc->in_use < drc->max_size) {
		/*
		 * nope, so let's malloc a new one
		 */
		drp = kmem_zalloc(sizeof (rfs4_dupreq_t), KM_SLEEP);
		drp->drc = drc;
		drc->in_use++;
		DTRACE_PROBE1(nfss__i__drc_new, rfs4_dupreq_t *, drp);
		return (drp);
	}

	/*
	 * Cache is all allocated now traverse the list
	 * backwards to find one we can reuse.
	 */
	for (drp_tail = list_tail(&drc->dr_cache); drp_tail != NULL;
	    drp_tail = list_prev(&drc->dr_cache, drp_tail)) {

		switch (drp_tail->dr_state) {

		case NFS4_DUP_FREE:
			list_remove(&(drc->dr_cache), drp_tail);
			DTRACE_PROBE1(nfss__i__drc_freeclaim,
			    rfs4_dupreq_t *, drp_tail);
			return (drp_tail);
			/* NOTREACHED */

		case NFS4_DUP_REPLAY:
			/* grab it. */
			rfs4_dr_chstate(drp_tail, NFS4_DUP_FREE);
			DTRACE_PROBE1(nfss__i__drc_replayclaim,
			    rfs4_dupreq_t *, drp_tail);
			return (drp_tail);
			/* NOTREACHED */
		}
	}
	DTRACE_PROBE1(nfss__i__drc_full, rfs4_drc_t *, drc);
	return (NULL);
}

/*
 * rfs4_find_dr:
 *
 * Search for an entry in the duplicate request cache by
 * calculating the hash index based on the XID, and examining
 * the entries in the hash bucket. If we find a match, return.
 * Once we have searched the bucket we call rfs4_alloc_dr() to
 * allocate a new entry, or reuse one that is available.
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
				rfs4_dr_chstate(drp, NFS4_DUP_INUSE);
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
	}

	drp = rfs4_alloc_dr(drc);
	mutex_exit(&drc->lock);

	/*
	 * The DRC is full and all entries are in use. Upper function
	 * should error out this request and force the client to
	 * retransmit -- effectively this is a resource issue. NFSD
	 * threads tied up with native File System, or the cache size
	 * is too small for the server load.
	 */
	if (drp == NULL)
		return (NFS4_DUP_ERROR);

	/*
	 * Init the state to NEW.
	 */
	drp->dr_state = NFS4_DUP_NEW;

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

	COMPOUND4res	 res_buf;
	COMPOUND4res	*rbp;
	COMPOUND4args	*cap;
	cred_t		*cr = NULL;
	int		 error = 0;
	int		 dis_flags = 0;
	int		 dr_stat = NFS4_NOT_DUP;
	rfs4_dupreq_t	*drp = NULL;
	int		 rv;

	ASSERT(disp);

	/*
	 * Short circuit the RPC_NULL proc.
	 */
	if (disp->dis_proc == rpc_null) {
		DTRACE_NFSV4_1(null__start, struct svc_req *, req);
		if (!svc_sendreply(xprt, xdr_void, NULL)) {
			DTRACE_NFSV4_1(null__done, struct svc_req *, req);
			svcerr_systemerr(xprt);
			return (1);
		}
		DTRACE_NFSV4_1(null__done, struct svc_req *, req);
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
			rfs4_resource_err(req, cap);
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
			rfs4_compound(cap, rbp, NULL, req, cr, &rv);
			curthread->t_flag &= ~T_DONTPEND;

			if (rv)		/* short ckt sendreply on error */
				return (rv);

			/*
			 * dr_res must be initialized before calling
			 * rfs4_dr_chstate (it frees the reply).
			 */
			drp->dr_res = res_buf;
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
			break;

		case NFS4_DUP_REPLAY:
			/* replay from the cache */
			rbp = &(drp->dr_res);
			break;
		}
	} else {
		curthread->t_flag |= T_DONTPEND;
		/* IDEMPOTENT proc call */
		rfs4_compound(cap, rbp, NULL, req, cr, &rv);
		curthread->t_flag &= ~T_DONTPEND;

		if (rv)		/* short ckt sendreply on error */
			return (rv);

		if (curthread->t_flag & T_WOULDBLOCK) {
			curthread->t_flag &= ~T_WOULDBLOCK;
			return (1);
		}
	}

	/*
	 * Send out the replayed reply or the 'real' one.
	 */
	if (!svc_sendreply(xprt,  xdr_COMPOUND4res_srv, (char *)rbp)) {
		DTRACE_PROBE2(nfss__e__dispatch_sendfail,
		    struct svc_req *, xprt,
		    char *, rbp);
		svcerr_systemerr(xprt);
		error++;
	}

	/*
	 * If this reply was just inserted into the duplicate cache
	 * or it was replayed from the dup cache; (re)mark it as
	 * available for replay
	 *
	 * At first glance, this 'if' statement seems a little strange;
	 * testing for NFS4_DUP_REPLAY, and then calling...
	 *
	 *	rfs4_dr_chatate(NFS4_DUP_REPLAY)
	 *
	 * ... but notice that we are checking dr_stat, and not the
	 * state of the entry itself, the entry will be NFS4_DUP_INUSE,
	 * we do that so that we know not to prematurely reap it whilst
	 * we resent it to the client.
	 *
	 */
	if (dr_stat == NFS4_DUP_NEW || dr_stat == NFS4_DUP_REPLAY) {
		mutex_enter(&drp->drc->lock);
		rfs4_dr_chstate(drp, NFS4_DUP_REPLAY);
		mutex_exit(&drp->drc->lock);
	} else if (dr_stat == NFS4_NOT_DUP) {
		rfs4_compound_free(rbp);
	}

	return (error);
}

bool_t
rfs4_minorvers_mismatch(struct svc_req *req, SVCXPRT *xprt, void *args)
{
	COMPOUND4args *argsp;
	COMPOUND4res res_buf, *resp;

	if (req->rq_vers != 4)
		return (FALSE);

	argsp = (COMPOUND4args *)args;

	if (argsp->minorversion <= NFS4_MAX_MINOR_VERSION)
		return (FALSE);

	resp = &res_buf;

	/*
	 * Form a reply tag by copying over the reqeuest tag.
	 */
	resp->tag.utf8string_val =
	    kmem_alloc(argsp->tag.utf8string_len, KM_SLEEP);
	resp->tag.utf8string_len = argsp->tag.utf8string_len;
	bcopy(argsp->tag.utf8string_val, resp->tag.utf8string_val,
	    resp->tag.utf8string_len);
	resp->array_len = 0;
	resp->array = NULL;
	resp->status = NFS4ERR_MINOR_VERS_MISMATCH;
	if (!svc_sendreply(xprt,  xdr_COMPOUND4res_srv, (char *)resp)) {
		DTRACE_PROBE2(nfss__e__minorvers_mismatch,
		    SVCXPRT *, xprt, char *, resp);
		svcerr_systemerr(xprt);
	}
	rfs4_compound_free(resp);
	return (TRUE);
}

void
rfs4_resource_err(struct svc_req *req, COMPOUND4args *argsp)
{
	COMPOUND4res res_buf, *rbp;
	nfs_resop4 *resop;
	PUTFH4res *resp;

	rbp = &res_buf;

	/*
	 * Form a reply tag by copying over the request tag.
	 */
	rbp->tag.utf8string_val =
	    kmem_alloc(argsp->tag.utf8string_len, KM_SLEEP);
	rbp->tag.utf8string_len = argsp->tag.utf8string_len;
	bcopy(argsp->tag.utf8string_val, rbp->tag.utf8string_val,
	    rbp->tag.utf8string_len);

	rbp->array_len = 1;
	rbp->array = kmem_zalloc(rbp->array_len * sizeof (nfs_resop4),
	    KM_SLEEP);
	resop = &rbp->array[0];
	resop->resop = argsp->array[0].argop;	/* copy first op over */

	/* Any op will do, just need to access status field */
	resp = &resop->nfs_resop4_u.opputfh;

	/*
	 * NFS4ERR_RESOURCE is allowed for all ops, except OP_ILLEGAL.
	 * Note that all op numbers in the compound array were already
	 * validated by the XDR decoder (xdr_COMPOUND4args_srv()).
	 */
	resp->status = (resop->resop == OP_ILLEGAL ?
	    NFS4ERR_OP_ILLEGAL : NFS4ERR_RESOURCE);

	/* compound status is same as first op status */
	rbp->status = resp->status;

	if (!svc_sendreply(req->rq_xprt, xdr_COMPOUND4res_srv, (char *)rbp)) {
		DTRACE_PROBE2(nfss__rsrc_err__sendfail,
		    struct svc_req *, req->rq_xprt, char *, rbp);
		svcerr_systemerr(req->rq_xprt);
	}

	UTF8STRING_FREE(rbp->tag);
	kmem_free(rbp->array, rbp->array_len * sizeof (nfs_resop4));
}
