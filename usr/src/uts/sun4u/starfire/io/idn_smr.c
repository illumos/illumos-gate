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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 * Inter-Domain Network
 *
 * Shared Memory Region (SMR) supporting code.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/systm.h>
#include <sys/machlock.h>
#include <sys/membar.h>
#include <sys/mman.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/hat_sfmmu.h>
#include <sys/vm_machparam.h>
#include <sys/x_call.h>

#include <sys/idn.h>

#ifdef DEBUG
#define	DIOCHECK(domid) \
{ \
	int	_dio; \
	if ((_dio = idn_domain[domid].dio) < 0) { \
		cmn_err(CE_WARN, \
			">>>>> file %s, line %d: domain %d, dio = %d", \
			__FILE__, __LINE__, (domid), _dio); \
	} \
}
#else
#define	DIOCHECK(domid)
#endif /* DEBUG */

static int	smr_slab_alloc_local(int domid, smr_slab_t **spp);
static int	smr_slab_alloc_remote(int domid, smr_slab_t **spp);
static void	smr_slab_free_local(int domid, smr_slab_t *sp);
static void	smr_slab_free_remote(int domid, smr_slab_t *sp);
static int 	smr_slabwaiter_register(int domid);
static int 	smr_slabwaiter_unregister(int domid, smr_slab_t **spp);
static int 	smr_slaballoc_wait(int domid, smr_slab_t **spp);
static smr_slab_t 	*smr_slab_reserve(int domid);
static void 	smr_slab_unreserve(int domid, smr_slab_t *sp);
static void	smr_slab_reap_global();

/*
 * Can only be called by the master.  Allocate a slab from the
 * local pool representing the SMR, on behalf of the given
 * domain.  Slab is either being requested for use by the
 * local domain (i.e. domid == idn.localid), or it's being
 * allocated to give to a remote domain which requested one.
 * In the base of allocating on behalf of a remote domain,
 * smr_slab_t structure is used simply to manage ownership.
 *
 * Returns:	smr_slaballoc_wait
 * 		(EINVAL, ETIMEDOUT)
 *		smr_slabwatier_unregister
 *		(0, EINVAL, EBUSY, ENOMEM)
 *		ENOLCK
 */
static int
smr_slab_alloc_local(int domid, smr_slab_t **spp)
{
	int		serrno = 0;
	int		nwait;
	smr_slab_t	*sp;
	idn_domain_t	*dp;


	/*
	 * Only the master can make local allocations.
	 */
	ASSERT(IDN_GET_MASTERID() != IDN_NIL_DOMID);
	ASSERT(idn.localid == IDN_GET_MASTERID());

	*spp = NULL;

	dp = &idn_domain[domid];
	ASSERT(DSLAB_READ_HELD(domid));
	ASSERT(dp->dslab_state == DSLAB_STATE_LOCAL);

	/*
	 * Register myself with the waiting list.
	 */
	nwait = smr_slabwaiter_register(domid);

	if (nwait > 1) {
		/*
		 * XXX - old comment?
		 * Need to drop the read lock _after_ registering
		 * ourselves with the potential wait list for this allocation.
		 * Although this allocation is not a remote one, we could
		 * still have multiple threads on the master trying to
		 * satisfy (allocate) request on behalf of a remote domain.
		 */
		/*
		 * Somebody is already in the process of satisfying
		 * the allocation request for this respective
		 * domain.  All we need to do is wait and let
		 * it happen.
		 */
		serrno = smr_slaballoc_wait(domid, spp);
		return (serrno);
	}
	/*
	 * I'm the original slab requester for this domain.  It's local
	 * so go ahead and do the job.
	 */

	if ((sp = smr_slab_reserve(domid)) == NULL)
		serrno = ENOMEM;

	/*
	 * Allocation may have failed.  In either case we've
	 * got to do the put to at least wake potential waiters up.
	 */
	if (!serrno) {
		if (DSLAB_LOCK_TRYUPGRADE(domid) == 0) {
			DSLAB_UNLOCK(domid);
			DSLAB_LOCK_EXCL(domid);
		}
	}

	(void) smr_slaballoc_put(domid, sp, 0, serrno);

	/*
	 * If serrno is ENOLCK here, then we must have failed
	 * on the upgrade above, so lock already dropped.
	 */
	if (serrno != ENOLCK) {
		/*
		 * Need to drop since reaping may be recursive?
		 */
		DSLAB_UNLOCK(domid);
	}

	/*
	 * Since we were the original requester but never went
	 * to sleep, we need to directly unregister ourselves
	 * from the waiting list.
	 */
	serrno = smr_slabwaiter_unregister(domid, spp);

	/*
	 * Now that we've satisfied the request, let's check if any
	 * reaping is necessary.  Only the master does this and only
	 * when allocating slabs, an infrequent event :-o
	 */
	smr_slab_reap_global();

	ASSERT((serrno == 0) ? (*spp != NULL) : (*spp == NULL));

	DSLAB_LOCK_SHARED(domid);

	return (serrno);
}

/*
 * Can only be called by a slave on behalf of himself.  Need to
 * make a request to the master to allocate a slab of SMR buffers
 * for the local domain.
 *
 * Returns:	smr_slaballoc_wait
 *		(0, EINVAL, EBUSY, ENOMEM)
 *		ENOLCK
 *		ECANCELED
 */
static int
smr_slab_alloc_remote(int domid, smr_slab_t **spp)
{
	int		nwait;
	int		serrno = 0;
	int		bailout = 0;
	int		masterid;
	idn_domain_t	*dp, *mdp = NULL;
	procname_t	proc = "smr_slab_alloc_remote";

	/*
	 * Only slaves make remote allocations.
	 */
	ASSERT(idn.localid != IDN_GET_MASTERID());
	ASSERT(domid == idn.localid);
	ASSERT(IDN_GET_MASTERID() != IDN_NIL_DOMID);

	*spp = NULL;

	dp = &idn_domain[domid];
	ASSERT(DSLAB_READ_HELD(domid));
	ASSERT(dp->dslab_state == DSLAB_STATE_REMOTE);

	/*
	 * Register myself with the slaballoc waiting list.
	 * Note that only allow one outstanding allocation
	 * request for the given domain.  Other callers which
	 * detect a slab is needed simply get stuck on the
	 * waiting list waiting for the original caller to
	 * get the job done.
	 * The waiter_register routine will allocate the necessary
	 * slab structure which will ultimately be inserted in
	 * the domain's slab list via smr_slaballoc_put().
	 */
	nwait = smr_slabwaiter_register(domid);

	/*
	 * Make sure we have a connection with the master
	 * before we wait around for nothing and send a
	 * command off to nowhere.
	 * First do a quick (no lock) check for global okayness.
	 */
	if ((idn.state != IDNGS_ONLINE) ||
	    ((masterid = IDN_GET_MASTERID()) == IDN_NIL_DOMID)) {
		bailout = 1;
		serrno = ECANCELED;
	}
	/*
	 * We need to drop our read lock _before_ acquiring the
	 * slaballoc waiter lock.  This is necessary because the
	 * thread that receives the slab alloc response and fills
	 * in the slab structure will need to grab the domain write
	 * lock while holding onto the slaballoc waiter lock.
	 * Potentially could deadlock if we didn't drop our domain
	 * lock before.  Plus, we've registered.
	 *
	 * 4093209 - Note also that we do this _after_ the check for
	 *	idn.masterid where we grab the READER global
	 *	lock.  This is to prevent somebody from
	 *	changing our state after we drop the drwlock.
	 *	A deadlock can occur when shutting down a
	 *	domain we're holding the
	 */

	if (!bailout) {
		mdp = &idn_domain[masterid];
		/*
		 * Global state is okay.  Let's double check the
		 * state of our actual target domain.
		 */
		if (mdp->dstate != IDNDS_CONNECTED) {
			bailout = 1;
			serrno = ECANCELED;
		} else if (IDN_DLOCK_TRY_SHARED(masterid)) {
			if (mdp->dstate != IDNDS_CONNECTED) {
				bailout = 1;
				serrno = ECANCELED;
				IDN_DUNLOCK(masterid);
			} else if (nwait != 1) {
				IDN_DUNLOCK(masterid);
			}
			/*
			 * Note that keep the drwlock(read) for
			 * the target (master) domain if it appears
			 * we're the lucky one to send the command.
			 * We hold onto the lock until we've actually
			 * sent the command out.
			 * We don't reach this place unless it
			 * appears everything is kosher with
			 * the target (master) domain.
			 */
		} else {
			bailout = 1;
			serrno = ENOLCK;
		}
	}

	if (bailout) {
		ASSERT(serrno);
		/*
		 * Gotta bail.  Abort operation.  Error result
		 * will be picked up when we attempt to wait.
		 */
		PR_SMR("%s: BAILING OUT on behalf domain %d "
		    "(err=%d, gs=%s, ms=%s)\n",
		    proc, domid, serrno, idngs_str[idn.state],
		    (masterid == IDN_NIL_DOMID)
		    ? "unknown" : idnds_str[idn_domain[masterid].dstate]);
		(void) smr_slabwaiter_abort(domid, serrno);

	} else if (nwait == 1) {
		/*
		 * We are the original requester.  Initiate the
		 * actual request to the master.
		 */
		idn_send_cmd(masterid, IDNCMD_SLABALLOC, IDN_SLAB_SIZE, 0, 0);
		ASSERT(mdp);
		IDN_DUNLOCK(masterid);
	}

	/*
	 * Wait here for response.  Once awakened func returns
	 * with slab structure possibly filled with gifts!
	 */
	serrno = smr_slaballoc_wait(domid, spp);

	return (serrno);
}

/*
 * Allocate a slab from the Master on behalf
 * of the given domain.  Note that master uses
 * this function to allocate slabs on behalf of
 * remote domains also.
 * Entered with drwlock held.
 * Leaves with drwlock dropped.
 * Returns:	EDQUOT
 *		EINVAL
 *		ENOLCK
 *		smr_slab_alloc_local
 *		smr_slab_alloc_remote
 *		(0, EINVAL, EBUSY, ENOMEM)
 */
int
smr_slab_alloc(int domid, smr_slab_t **spp)
{
	int		serrno = 0;
	idn_domain_t	*dp;
	procname_t	proc = "smr_slab_alloc";


	dp = &idn_domain[domid];

	ASSERT(DSLAB_READ_HELD(domid));
	ASSERT(dp->dslab_state != DSLAB_STATE_UNKNOWN);

	*spp = NULL;

	switch (dp->dslab_state) {
	case DSLAB_STATE_UNKNOWN:
		cmn_err(CE_WARN,
		    "IDN: 300: no slab allocations without a master");
		serrno = EINVAL;
		break;

	case DSLAB_STATE_LOCAL:
		/*
		 * If I'm the master, then get a slab
		 * from the local SMR pool, but only
		 * if the number of allocated slabs has
		 * not been exceeded.
		 */
		if (((int)dp->dnslabs < IDN_SLAB_MAXPERDOMAIN) ||
		    !IDN_SLAB_MAXPERDOMAIN)
			serrno = smr_slab_alloc_local(domid, spp);
		else
			serrno = EDQUOT;
		break;

	case DSLAB_STATE_REMOTE:
		/*
		 * Have to make a remote request.
		 * In order to prevent overwhelming the master
		 * with a bunch of requests that it won't be able
		 * to handle we do a check to see if we're still
		 * under quota.  Note that the limit is known
		 * apriori based on the SMR/NWR size and
		 * IDN_SLAB_MINTOTAL.  Domains must have the same
		 * size SMR/NWR, however they can have different
		 * IDN_SLAB_MINTOTAL.  Thus a domain could throttle
		 * itself however it wishes.
		 */
		if (((int)dp->dnslabs < IDN_SLAB_MAXPERDOMAIN) ||
		    !IDN_SLAB_MAXPERDOMAIN)
			serrno = smr_slab_alloc_remote(domid, spp);
		else
			serrno = EDQUOT;
		break;

	default:
		cmn_err(CE_WARN,
		    "IDN: 301: (ALLOC) unknown slab state (%d) "
		    "for domain %d", dp->dslab_state, domid);
		serrno = EINVAL;
		break;
	}

	if (*spp == NULL) {
		PR_SMR("%s: failed to allocate %s slab [serrno = %d]\n",
		    proc, (idn.localid == IDN_GET_MASTERID()) ?
		    "local" : "remote", serrno);
	}

	if (serrno) {
		IDN_GKSTAT_GLOBAL_EVENT(gk_slabfail, gk_slabfail_last);
	}

	return (serrno);
}

static void
smr_slab_free_local(int domid, smr_slab_t *sp)
{
	int	rv;

	/*
	 * Do a slaballoc_put just in case there may have
	 * been waiters for slabs for this respective domain
	 * before we unreserve this slab.
	 */
	rv = smr_slaballoc_put(domid, sp, 0, 0);

	if (rv == -1) {
		/*
		 * Put failed.  Must not have been any waiters.
		 * Go ahead and unreserve the space.
		 */
		smr_slab_unreserve(domid, sp);
	}
}

static void
smr_slab_free_remote(int domid, smr_slab_t *sp)
{
	smr_offset_t	slab_offset;
	int		slab_size;
	int		rv;
	int		masterid;

	ASSERT(domid == idn.localid);
	ASSERT(idn.localid != IDN_GET_MASTERID());
	ASSERT(DSLAB_WRITE_HELD(domid));
	ASSERT(idn_domain[domid].dslab_state == DSLAB_STATE_REMOTE);

	masterid = IDN_GET_MASTERID();

	ASSERT(masterid != IDN_NIL_DOMID);

	slab_offset = IDN_ADDR2OFFSET(sp->sl_start);
	slab_size   = (int)(sp->sl_end - sp->sl_start);

	/*
	 * Do a slaballoc_put just in case there may have
	 * been waiters for slabs for this domain before
	 * returning back to the master.
	 */
	rv = smr_slaballoc_put(domid, sp, 0, 0);

	if ((rv == -1) && (masterid != IDN_NIL_DOMID)) {
		/*
		 * Put failed.  No waiters so free the local data
		 * structure ship the SMR range off to the master.
		 */
		smr_free_buflist(sp);
		FREESTRUCT(sp, smr_slab_t, 1);

		IDN_DLOCK_SHARED(masterid);
		idn_send_cmd(masterid, IDNCMD_SLABFREE, slab_offset, slab_size,
		    0);
		IDN_DUNLOCK(masterid);
	}
}

/*
 * Free up the list of slabs passed
 */
void
smr_slab_free(int domid, smr_slab_t *sp)
{
	smr_slab_t	*nsp = NULL;

	ASSERT(DSLAB_WRITE_HELD(domid));

	if (sp == NULL)
		return;

	ASSERT(IDN_GET_MASTERID() != IDN_NIL_DOMID);

	switch (idn_domain[domid].dslab_state) {
	case DSLAB_STATE_UNKNOWN:
		cmn_err(CE_WARN, "IDN: 302: no slab free without a master");
		break;

	case DSLAB_STATE_LOCAL:
		/*
		 * If I'm the master then put the slabs
		 * back to the local SMR pool.
		 */
		for (; sp; sp = nsp) {
			nsp = sp->sl_next;
			smr_slab_free_local(domid, sp);
		}
		break;

	case DSLAB_STATE_REMOTE:
		/*
		 * If the domid is my own then I'm freeing
		 * a slab back to the Master.
		 */
		for (; sp; sp = nsp) {
			nsp = sp->sl_next;
			smr_slab_free_remote(domid, sp);
		}
		break;

	default:
		cmn_err(CE_WARN,
		    "IDN: 301: (FREE) unknown slab state (%d) for domain %d",
		    idn_domain[domid].dslab_state, domid);
		break;
	}
}

/*
 * Free up the list of slab data structures ONLY.
 * This is called during a fatal shutdown of the master
 * where we need to garbage collect the locally allocated
 * data structures used to manage slabs allocated to the
 * local domain.  Should never be called by a master since
 * the master can do a regular smr_slab_free.
 */
void
smr_slab_garbage_collection(smr_slab_t *sp)
{
	smr_slab_t	*nsp;

	ASSERT(idn_domain[idn.localid].dvote.v.master == 0);

	if (sp == NULL)
		return;
	/*
	 * Since this is only ever called by a slave,
	 * the slab structure size always contains a buflist.
	 */
	for (; sp; sp = nsp) {
		nsp = sp->sl_next;
		smr_free_buflist(sp);
		FREESTRUCT(sp, smr_slab_t, 1);
	}
}

/*
 * Allocate a SMR buffer on behalf of the local domain
 * which is ultimately targeted for the given domain.
 *
 * IMPORTANT: This routine is going to drop the domain rwlock (drwlock)
 *	      for the domain on whose behalf the request is being
 *	      made.  This routine canNOT block on trying to
 *	      reacquire the drwlock.  If it does block then somebody
 *	      must have the write lock on the domain which most likely
 *	      means the domain is going south anyway, so just bail on
 *	      this buffer.  Higher levels will retry if needed.
 *
 * XXX - Support larger than IDN_SMR_BUFSIZE allocations?
 *
 * Returns:	A negative return value indicates lock lost on domid.
 *		EINVAL, ENOLINK, ENOLCK(internal)
 *		smr_slaballoc_wait
 * 		(EINVAL, ETIMEDOUT)
 *		smr_slabwatier_unregister
 *		(0, EINVAL, EBUSY, ENOMEM)
 */
int
smr_buf_alloc(int domid, uint_t len, caddr_t *bufpp)
{
	register idn_domain_t	*dp, *ldp;
	smr_slab_t	*sp;
	caddr_t		bufp = NULL;
	int		serrno;
	procname_t	proc = "smr_buf_alloc";

	dp = &idn_domain[domid];
	/*
	 * Local domain can only allocate on behalf of
	 * itself if this is a priviledged call and the
	 * caller is the master.
	 */
	ASSERT((domid != idn.localid) && (domid != IDN_NIL_DOMID));

	*bufpp = NULL;

	if (len > IDN_DATA_SIZE) {
		cmn_err(CE_WARN,
		    "IDN: 303: buffer len %d > IDN_DATA_SIZE (%lu)",
		    len, IDN_DATA_SIZE);
		IDN_GKSTAT_GLOBAL_EVENT(gk_buffail, gk_buffail_last);
		return (EINVAL);
	}

	/*
	 * Need to go to my local slab list to find
	 * a buffer.
	 */
	ldp = &idn_domain[idn.localid];
	/*
	 * Now we loop trying to locate a buffer out of our
	 * slabs.  We continue this until either we find a
	 * buffer or we're unable to allocate a slab.  Note
	 * that new slabs are allocated to the front.
	 */
	DSLAB_LOCK_SHARED(idn.localid);
	sp = ldp->dslab;
	do {
		int	spl, all_empty;

		if (sp == NULL) {
			if ((serrno = smr_slab_alloc(idn.localid, &sp)) != 0) {
				PR_SMR("%s:%d: failed to allocate "
				    "slab [serrno = %d]",
				    proc, domid, serrno);
				DSLAB_UNLOCK(idn.localid);
				IDN_GKSTAT_GLOBAL_EVENT(gk_buffail,
				    gk_buffail_last);
				return (serrno);
			}
			/*
			 * Of course, the world may have changed while
			 * we dropped the lock.  Better make sure we're
			 * still established.
			 */
			if (dp->dstate != IDNDS_CONNECTED) {
				PR_SMR("%s:%d: state changed during slab "
				    "alloc (dstate = %s)\n",
				    proc, domid, idnds_str[dp->dstate]);
				DSLAB_UNLOCK(idn.localid);
				IDN_GKSTAT_GLOBAL_EVENT(gk_buffail,
				    gk_buffail_last);
				return (ENOLINK);
			}
			/*
			 * We were able to allocate a slab.  Should
			 * be at the front of the list, spin again.
			 */
			sp = ldp->dslab;
		}
		/*
		 * If we have reached here then we have a slab!
		 * Hopefully there are free bufs there :-o
		 */
		spl = splhi();
		all_empty = 1;
		for (; sp && !bufp; sp = sp->sl_next) {
			smr_slabbuf_t	*bp;

			if (sp->sl_free == NULL)
				continue;

			if (!lock_try(&sp->sl_lock)) {
				all_empty = 0;
				continue;
			}

			if ((bp = sp->sl_free) == NULL) {
				lock_clear(&sp->sl_lock);
				continue;
			}

			sp->sl_free = bp->sb_next;
			bp->sb_next = sp->sl_inuse;
			sp->sl_inuse = bp;
			/*
			 * Found a free buffer.
			 */
			bp->sb_domid = domid;
			bufp = bp->sb_bufp;
			lock_clear(&sp->sl_lock);
		}
		splx(spl);

		if (!all_empty && !bufp) {
			/*
			 * If we still haven't found a buffer, but
			 * there's still possibly a buffer available,
			 * then try again.  Only if we're absolutely
			 * sure all slabs are empty do we attempt
			 * to allocate a new one.
			 */
			sp = ldp->dslab;
		}
	} while (bufp == NULL);

	*bufpp = bufp;

	ATOMIC_INC(dp->dio);

	DSLAB_UNLOCK(idn.localid);

	return (0);
}

/*
 * Free a buffer allocated to the local domain back to
 * its respective slab.  Slabs are freed via the slab-reap command.
 * XXX - Support larger than IDN_SMR_BUFSIZE allocations?
 */
int
smr_buf_free(int domid, caddr_t bufp, uint_t len)
{
	register smr_slab_t	*sp;
	smr_slabbuf_t		*bp, **bpp;
	idn_domain_t		*ldp;
	int		buffreed;
	int		lockheld = (len == (uint_t)-1);

	/*
	 * We should never be free'ing a buffer on
	 * behalf of ourselves as we are never the
	 * target for allocated SMR buffers.
	 */
	ASSERT(domid != idn.localid);

	sp = NULL;
	buffreed = 0;
	ldp = &idn_domain[idn.localid];

	DSLAB_LOCK_SHARED(idn.localid);

	if (((uintptr_t)bufp & (IDN_SMR_BUFSIZE-1)) &&
	    (IDN_ADDR2OFFSET(bufp) % IDN_SMR_BUFSIZE)) {
		cmn_err(CE_WARN,
		    "IDN: 304: buffer (0x%p) from domain %d not on a "
		    "%d boundary", (void *)bufp, domid, IDN_SMR_BUFSIZE);
		goto bfdone;
	}
	if (!lockheld && (len > IDN_DATA_SIZE)) {
		cmn_err(CE_WARN,
		    "IDN: 305: buffer length (%d) from domain %d greater "
		    "than IDN_DATA_SIZE (%lu)",
		    len, domid, IDN_DATA_SIZE);
		goto bfdone;
	}

	for (sp = ldp->dslab; sp; sp = sp->sl_next)
		if ((bufp >= sp->sl_start) && (bufp < sp->sl_end))
			break;

	if (sp) {
		int spl;

		spl = splhi();
		while (!lock_try(&sp->sl_lock))
			;
		bpp = &sp->sl_inuse;
		for (bp = *bpp; bp; bp = *bpp) {
			if (bp->sb_bufp == bufp)
				break;
			bpp = &bp->sb_next;
		}
		if (bp) {
			ASSERT(bp->sb_domid == domid);
			buffreed++;
			bp->sb_domid = IDN_NIL_DOMID;
			*bpp = bp->sb_next;
			bp->sb_next = sp->sl_free;
			sp->sl_free = bp;
		}
		lock_clear(&sp->sl_lock);
		splx(spl);
	}
bfdone:
	if (buffreed) {
		ATOMIC_DEC(idn_domain[domid].dio);
		DIOCHECK(domid);
	} else {
		cmn_err(CE_WARN,
		    "IDN: 306: unknown buffer (0x%p) from domain %d",
		    (void *)bufp, domid);
		ATOMIC_INC(idn_domain[domid].dioerr);
	}

	DSLAB_UNLOCK(idn.localid);

	return (sp ? 0 : -1);
}

/*
 * Alternative interface to smr_buf_free, but with local drwlock
 * held.
 */
/* ARGSUSED2 */
int
smr_buf_free_locked(int domid, caddr_t bufp, uint_t len)
{
	return (smr_buf_free(domid, bufp, (uint_t)-1));
}

/*
 * Free any and all buffers associated with the given domain.
 * Assumption is that domain is dead and buffers are not in use.
 * Returns:	Number of buffers freed.
 *		-1 if error.
 */
int
smr_buf_free_all(int domid)
{
	register smr_slab_t	*sp;
	register smr_slabbuf_t	*bp, **bpp;
	idn_domain_t		*ldp;
	int			nbufsfreed = 0;
	procname_t	proc = "smr_buf_free_all";

	/*
	 * We should never be free'ing buffers on
	 * behalf of ourself
	 */
	ASSERT(domid != idn.localid);

	if (!VALID_DOMAINID(domid)) {
		cmn_err(CE_WARN, "IDN: 307: domain ID (%d) invalid", domid);
		return (-1);
	}

	ldp = &idn_domain[idn.localid];

	/*
	 * We grab the writer lock so that we don't have any
	 * competition during a "free-all" call.
	 * No need to grab individual slab locks when holding
	 * dslab(writer).
	 */
	DSLAB_LOCK_EXCL(idn.localid);

	for (sp = ldp->dslab; sp; sp = sp->sl_next) {
		bpp = &sp->sl_inuse;
		for (bp = *bpp; bp; bp = *bpp) {
			if (bp->sb_domid == domid) {
				bp->sb_domid = IDN_NIL_DOMID;
				*bpp = bp->sb_next;
				bp->sb_next = sp->sl_free;
				sp->sl_free = bp;
				nbufsfreed++;
			} else {
				bpp = &bp->sb_next;
			}
		}
	}

	if (nbufsfreed > 0) {
		ATOMIC_SUB(idn_domain[domid].dio, nbufsfreed);
		idn_domain[domid].dioerr = 0;
		DIOCHECK(domid);
	}

	DSLAB_UNLOCK(idn.localid);

	PR_SMR("%s: freed %d buffers for domain %d\n", proc, nbufsfreed, domid);

	return (nbufsfreed);
}

int
smr_buf_reclaim(int domid, int nbufs)
{
	int		num_reclaimed = 0;
	idn_domain_t	*ldp, *dp;
	procname_t	proc = "smr_buf_reclaim";

	ldp = &idn_domain[idn.localid];
	dp  = &idn_domain[domid];

	ASSERT(domid != idn.localid);

	if (ATOMIC_CAS(&dp->dreclaim_inprogress, 0, 1)) {
		/*
		 * Reclaim is already in progress, don't
		 * bother.
		 */
		PR_DATA("%s: reclaim already in progress\n", proc);
		return (0);
	}

	PR_SMR("%s: requested %d buffers from domain %d\n", proc, nbufs, domid);

	if (dp->dio && nbufs) {
		register smr_slab_t	*sp;
		int spl;

		DSLAB_LOCK_SHARED(idn.localid);
		spl = splhi();
		for (sp = ldp->dslab; sp && nbufs; sp = sp->sl_next) {
			register smr_slabbuf_t	*bp, **bpp;

			if (sp->sl_inuse == NULL)
				continue;

			if (!lock_try(&sp->sl_lock))
				continue;

			if (sp->sl_inuse == NULL) {
				lock_clear(&sp->sl_lock);
				continue;
			}

			bpp = &sp->sl_inuse;
			for (bp = *bpp; bp && nbufs; bp = *bpp) {
				if (bp->sb_domid == domid) {
					/*
					 * Buffer no longer in use,
					 * reclaim it.
					 */
					bp->sb_domid = IDN_NIL_DOMID;
					*bpp = bp->sb_next;
					bp->sb_next = sp->sl_free;
					sp->sl_free = bp;
					num_reclaimed++;
					nbufs--;
				} else {
					bpp = &bp->sb_next;
				}
			}
			lock_clear(&sp->sl_lock);
		}
		splx(spl);

		if (num_reclaimed > 0) {
			ATOMIC_SUB(dp->dio, num_reclaimed);
			DIOCHECK(domid);
		}
		DSLAB_UNLOCK(idn.localid);
	}

	PR_SMR("%s: reclaimed %d buffers from domain %d\n",
	    proc, num_reclaimed, domid);

	return (num_reclaimed);
}

/*
 * Returns 1	If any buffers are locked for the given slab.
 *	   0	If all buffers are free for the given slab.
 *
 * The caller is assumed to have the slab protected so that no
 * new allocations are attempted from it.  Also, this is only
 * valid to be called with respect to slabs that were allocated
 * on behalf of the local domain, i.e. the master is not expected
 * to call this function with (slave) slab "representatives".
 */
int
smr_slab_busy(smr_slab_t *sp)
{
	return ((sp && sp->sl_inuse) ? 1 : 0);
}

int
smr_slabwaiter_init()
{
	register int		i;
	struct slabwaiter	*wp;

	if (idn.slabwaiter != NULL)
		return (0);

	/*
	 * Initialize the slab waiting area for MAX_DOMAINS.
	 */
	idn.slabwaiter = GETSTRUCT(struct slabwaiter, MAX_DOMAINS);
	wp = idn.slabwaiter;
	for (i = 0; i < MAX_DOMAINS; wp++, i++) {
		wp->w_closed = 0;
		mutex_init(&wp->w_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&wp->w_cv, NULL, CV_DEFAULT, NULL);
	}

	return (0);
}

void
smr_slabwaiter_deinit()
{
	register int		i;
	struct slabwaiter	*wp;

	if ((wp = idn.slabwaiter) == NULL)
		return;

	for (i = 0; i < MAX_DOMAINS; wp++, i++) {
		ASSERT(wp->w_nwaiters == 0);
		ASSERT(wp->w_sp == NULL);
		cv_destroy(&wp->w_cv);
		mutex_destroy(&wp->w_mutex);
	}

	FREESTRUCT(idn.slabwaiter, struct slabwaiter, MAX_DOMAINS);
	idn.slabwaiter = NULL;
}

void
smr_slabwaiter_open(domainset_t domset)
{
	int			d;
	struct slabwaiter	*wp;

	if ((domset == 0) || !idn.slabwaiter)
		return;

	wp = idn.slabwaiter;

	for (d = 0; d < MAX_DOMAINS; wp++, d++) {
		if (!DOMAIN_IN_SET(domset, d))
			continue;
		mutex_enter(&wp->w_mutex);
		wp->w_closed = 0;
		mutex_exit(&wp->w_mutex);
	}
}

void
smr_slabwaiter_close(domainset_t domset)
{
	int			d;
	struct slabwaiter	*wp;

	if ((domset == 0) || !idn.slabwaiter)
		return;

	wp = idn.slabwaiter;

	for (d = 0; d < MAX_DOMAINS; wp++, d++) {
		if (!DOMAIN_IN_SET(domset, d))
			continue;
		mutex_enter(&wp->w_mutex);
		wp->w_closed = 1;
		cv_broadcast(&wp->w_cv);
		mutex_exit(&wp->w_mutex);
	}
}

/*
 * Register the caller with the waiting list for the
 * given domain.
 *
 * Protocol:
 *	1st Local requester:	register -> alloc ->
 *						put(wakeup|xdc) -> unregister
 *	Nth Local requester:	register -> wait
 *	1st Remote requester:	register -> xdc -> wait
 *	Nth Remote requester:	register -> wait
 *
 *	Remote Responder:	local alloc -> put(xdc)
 *	Local Handler:		xdc -> put(wakeup)
 *
 * E.g. A standard slave allocation request:
 *	slave			master
 *	-----			------
 *	idn_slab_alloc(remote)
 *	- register
 *	- xdc		->	idn_handler
 *	- wait			...
 *				idn_slab_alloc(local)
 *				- register
 *				- alloc
 *				- put
 *				  . wakeup [local]
 *				- unregister
 *	idn_handler    	<-	- xdc
 *	- put       		DONE
 *	  . wakeup [local]
 *	    |
 *	    V
 *      - wait
 *	  . unregister
 *	DONE
 */
static int
smr_slabwaiter_register(int domid)
{
	struct slabwaiter	*wp;
	int		nwait;
	procname_t	proc = "smr_slabwaiter_register";


	ASSERT(domid != IDN_NIL_DOMID);

	ASSERT(DSLAB_READ_HELD(domid));

	wp = &idn.slabwaiter[domid];

	ASSERT(MUTEX_NOT_HELD(&wp->w_mutex));

	mutex_enter(&wp->w_mutex);

	nwait = ++(wp->w_nwaiters);
	ASSERT(nwait > 0);

	PR_SMR("%s: domain = %d, (new)nwaiters = %d\n", proc, domid, nwait);

	if (nwait > 1) {
		/*
		 * There are already waiters for slab allocations
		 * with respect to this domain.
		 */
		PR_SMR("%s: existing waiters for slabs for domain %d\n",
		    proc, domid);
		mutex_exit(&wp->w_mutex);

		return (nwait);
	}
	PR_SMR("%s: initial waiter for slabs for domain %d\n", proc, domid);
	/*
	 * We are the first requester of a slab allocation for this
	 * respective domain.  Need to prep waiting area for
	 * subsequent arrival of a slab.
	 */
	wp->w_sp = NULL;
	wp->w_done = 0;
	wp->w_serrno = 0;

	mutex_exit(&wp->w_mutex);

	return (nwait);
}

/*
 * It is assumed that the caller had previously registered,
 * but wakeup did not occur due to caller never waiting.
 * Thus, slaballoc mutex is still held by caller.
 *
 * Returns:	0
 *		EINVAL
 *		EBUSY
 *		w_serrno (smr_slaballoc_put)
 *		(0, ENOLCK, ENOMEM, EDQUOT, EBUSY, ECANCELED)
 */
static int
smr_slabwaiter_unregister(int domid, smr_slab_t **spp)
{
	struct slabwaiter	*wp;
	int		serrno = 0;
	procname_t	proc = "smr_slabwaiter_unregister";


	ASSERT(domid != IDN_NIL_DOMID);

	wp = &idn.slabwaiter[domid];

	mutex_enter(&wp->w_mutex);

	PR_SMR("%s: domain = %d, nwaiters = %d\n", proc, domid, wp->w_nwaiters);

	if (wp->w_nwaiters <= 0) {
		/*
		 * Hmmm...nobody is registered!
		 */
		PR_SMR("%s: NO WAITERS (domid = %d)\n", proc, domid);
		mutex_exit(&wp->w_mutex);
		return (EINVAL);
	}
	(wp->w_nwaiters)--;
	/*
	 * Is our present under the tree?
	 */
	if (!wp->w_done) {
		/*
		 * Bummer...no presents.  Let the caller know
		 * via a null slab pointer.
		 * Note that we don't clean up immediately since
		 * message might still come in for other waiters.
		 * Thus, late sleepers may still get a chance.
		 */
		PR_SMR("%s: bummer no slab allocated for domain %d\n",
		    proc, domid);
		ASSERT(wp->w_sp == NULL);
		(*spp) = NULL;
		serrno = wp->w_closed ? ECANCELED : EBUSY;

	} else {
		(*spp) = wp->w_sp;
		serrno = wp->w_serrno;

#ifdef DEBUG
		if (serrno == 0) {
			register smr_slab_t	*sp;

			ASSERT(wp->w_sp);
			PR_SMR("%s: allocation succeeded (domain %d)\n",
			    proc, domid);

			DSLAB_LOCK_SHARED(domid);
			for (sp = idn_domain[domid].dslab; sp; sp = sp->sl_next)
				if (sp == wp->w_sp)
					break;
			if (sp == NULL)
				cmn_err(CE_WARN,
				    "%s:%d: slab ptr = NULL",
				    proc, domid);
			DSLAB_UNLOCK(domid);
		} else {
			PR_SMR("%s: allocation failed (domain %d) "
			    "[serrno = %d]\n", proc, domid, serrno);
		}
#endif /* DEBUG */
	}
	if (wp->w_nwaiters == 0) {
		/*
		 * Last one turns out the lights.
		 */
		PR_SMR("%s: domain %d last waiter, turning out lights\n",
		    proc, domid);
		wp->w_sp = NULL;
		wp->w_done = 0;
		wp->w_serrno = 0;
	}
	mutex_exit(&wp->w_mutex);

	return (serrno);
}

/*
 * Called to abort any slaballoc requests on behalf of the
 * given domain.
 */
int
smr_slabwaiter_abort(int domid, int serrno)
{
	ASSERT(serrno != 0);

	return (smr_slaballoc_put(domid, NULL, 0, serrno));
}

/*
 * Put ourselves into a timedwait waiting for slab to be
 * allocated.
 * Returns with slaballoc mutex dropped.
 *
 * Returns:	EINVAL
 *		ETIMEDOUT
 *		smr_slabwatier_unregister
 *		(0, EINVAL, EBUSY, ENOMEM)
 */
static int
smr_slaballoc_wait(int domid, smr_slab_t **spp)
{
	struct slabwaiter	*wp;
	int			serrno = 0, serrno_unreg;
	procname_t		proc = "smr_slaballoc_wait";


	wp = &idn.slabwaiter[domid];

	ASSERT(MUTEX_NOT_HELD(&wp->w_mutex));

	mutex_enter(&wp->w_mutex);

	PR_SMR("%s: domain = %d, nwaiters = %d, wsp = 0x%p\n",
	    proc, domid, wp->w_nwaiters, (void *)wp->w_sp);

	if (wp->w_nwaiters <= 0) {
		/*
		 * Hmmm...no waiters registered.
		 */
		PR_SMR("%s: domain %d, no waiters!\n", proc, domid);
		mutex_exit(&wp->w_mutex);
		return (EINVAL);
	}
	ASSERT(DSLAB_READ_HELD(domid));
	DSLAB_UNLOCK(domid);

	if (!wp->w_done && !wp->w_closed) {
		int	rv;

		/*
		 * Only wait if data hasn't arrived yet.
		 */
		PR_SMR("%s: domain %d, going to sleep...\n", proc, domid);

		rv = cv_reltimedwait_sig(&wp->w_cv, &wp->w_mutex,
		    IDN_SLABALLOC_WAITTIME, TR_CLOCK_TICK);
		if (rv == -1)
			serrno = ETIMEDOUT;

		PR_SMR("%s: domain %d, awakened (reason = %s)\n",
		    proc, domid, (rv == -1) ? "TIMEOUT" : "SIGNALED");
	}
	/*
	 * We've awakened or request already filled!
	 * Unregister ourselves.
	 */
	mutex_exit(&wp->w_mutex);

	/*
	 * Any gifts will be entered into spp.
	 */
	serrno_unreg = smr_slabwaiter_unregister(domid, spp);

	/*
	 * Leave with reader lock on dslab_lock.
	 */
	DSLAB_LOCK_SHARED(domid);

	if ((serrno_unreg == EBUSY) && (serrno == ETIMEDOUT))
		return (serrno);
	else
		return (serrno_unreg);
}

/*
 * A SMR slab was allocated on behalf of the given domain.
 * Wakeup anybody that may have been waiting for the allocation.
 * Note that if the domain is a remote one, i.e. master is allocating
 * on behalf of a slave, it's up to the caller to transmit the
 * allocation response to that domain.
 * The force flag indicates that we want to install the slab for
 * the given user regardless of whether there are waiters or not.
 * This is used primarily in situations where a slave may have timed
 * out before the response actually arrived.  In this situation we
 * don't want to send slab back to the master after we went through
 * the trouble of allocating one.  Master is _not_ allowed to do this
 * for remote domains.
 *
 * Returns:	-1	Non-registered waiter or waiting area garbaged.
 *		0	Successfully performed operation.
 */
int
smr_slaballoc_put(int domid, smr_slab_t *sp, int forceflag, int serrno)
{
	idn_domain_t		*dp;
	struct slabwaiter	*wp;
	procname_t		proc = "smr_slaballoc_put";


	dp = &idn_domain[domid];

	ASSERT(!serrno ? DSLAB_WRITE_HELD(domid) : 1);

	if (domid == IDN_NIL_DOMID)
		return (-1);

	ASSERT(serrno ? (sp == NULL) : (sp != NULL));

	wp = &idn.slabwaiter[domid];

	mutex_enter(&wp->w_mutex);

	PR_SMR("%s: domain = %d, bufp = 0x%p, ebufp = 0x%p, "
	    "(f = %d, se = %d)\n", proc, domid,
	    (sp ? (void *)sp->sl_start : 0),
	    (sp ? (void *)sp->sl_end : 0), forceflag, serrno);

	if (wp->w_nwaiters <= 0) {
		/*
		 * There are no waiters!!  Must have timed out
		 * and left.  Oh well...
		 */
		PR_SMR("%s: no slaballoc waiters found for domain %d\n",
		    proc, domid);
		if (!forceflag || serrno || !sp) {
			/*
			 * No waiters and caller doesn't want to force it.
			 */
			mutex_exit(&wp->w_mutex);
			return (-1);
		}
		PR_SMR("%s: forcing slab onto domain %d\n", proc, domid);
		ASSERT(domid == idn.localid);
		ASSERT(wp->w_sp == NULL);
		wp->w_done = 0;
		/*
		 * Now we fall through and let it be added in the
		 * regular manor.
		 */
	}
	if (wp->w_done) {
		/*
		 * There's at least one waiter so there has
		 * to be a slab structure waiting for us.
		 * If everything is going smoothly, there should only
		 * be one guy coming through the path of inserting
		 * an error or good slab.  However, if a disconnect was
		 * detected, you may get several guys coming through
		 * trying to let everybody know.
		 */
		ASSERT(wp->w_serrno ?
		    (wp->w_sp == NULL) : (wp->w_sp != NULL));

		cv_broadcast(&wp->w_cv);
		mutex_exit(&wp->w_mutex);

		return (-1);
	}
	if (serrno != 0) {
		/*
		 * Bummer...allocation failed.  This call is simply
		 * to wake up the sleepers and let them know.
		 */
		PR_SMR("%s: slaballoc failed for domain %d\n", proc, domid);
		wp->w_serrno = serrno;
		wp->w_done = 1;
		cv_broadcast(&wp->w_cv);
		mutex_exit(&wp->w_mutex);

		return (0);
	}
	PR_SMR("%s: putting slab into struct (domid=%d, localid=%d)\n",
	    proc, domid, idn.localid);
	/*
	 * Prep the slab structure.
	 */

	if (domid == idn.localid) {
		/*
		 * Allocation was indeed for me.
		 * Slab may or may not be locked when
		 * we reach.  Normally they will be locked
		 * if we're being called on behalf of a
		 * free, and not locked if on behalf of
		 * a new allocation request.
		 */
		lock_clear(&sp->sl_lock);
		smr_alloc_buflist(sp);
#ifdef DEBUG
	} else {
		uint_t	rv;
		/*
		 * Slab was not allocated on my behalf.  Must be
		 * a master request on behalf of some other domain.
		 * Prep appropriately.  Slab should have been locked
		 * by smr_slab_reserve.
		 */
		rv = lock_try(&sp->sl_lock);
		ASSERT(!rv);
		ASSERT(sp->sl_domid == (short)domid);
#endif /* DEBUG */
	}

	/*
	 * Slab is ready to go.  Insert it into the domain's
	 * slab list so once we wake everybody up they'll find it.
	 * You better have write lock if you're putting treasures
	 * there.
	 */
	ASSERT(DSLAB_WRITE_HELD(domid));

	sp->sl_next = dp->dslab;
	dp->dslab  = sp;
	dp->dnslabs++;

	/*
	 * It's possible to fall through here without waiters.
	 * This is a case where forceflag was set.
	 */
	if (wp->w_nwaiters > 0) {
		wp->w_sp = sp;
		wp->w_serrno = serrno;
		wp->w_done = 1;
		cv_broadcast(&wp->w_cv);
	} else {
		ASSERT(forceflag);
		wp->w_sp = NULL;
		wp->w_serrno = 0;
		wp->w_done = 0;
	}
	mutex_exit(&wp->w_mutex);

	return (0);
}

/*
 * Get the slab representing [bufp,ebufp] from the respective
 * domain's pool if all the buffers are free.  Remove them from
 * the domain's list and return it.
 * If bufp == NULL, then return however many free ones you
 * can find.
 * List of slabs are returned locked (sl_lock).
 * XXX - Need minimum limit to make sure we don't free up _all_
 *	 of our slabs!  However, during a shutdown we will need
 *	 method to free them all up regardless of locking.
 */
smr_slab_t *
smr_slaballoc_get(int domid, caddr_t bufp, caddr_t ebufp)
{
	idn_domain_t	*dp;
	smr_slab_t	*retsp, *sp, **psp;
	int		foundit, islocal = 0;
	int		nslabs;
	procname_t	proc = "smr_slaballoc_get";

	PR_SMR("%s: getting slab for domain %d [bufp=0x%p, ebufp=0x%p]\n",
	    proc, domid, (void *)bufp, (void *)ebufp);

	dp = &idn_domain[domid];

	ASSERT(DSLAB_WRITE_HELD(domid));

	if ((sp = dp->dslab) == NULL) {
		PR_SMR("%s: oops, no slabs for domain %d\n", proc, domid);
		return (NULL);
	}
	/*
	 * If domid is myself then I'm trying to get a slab out
	 * of my local pool.  Otherwise, I'm the master and
	 * I'm trying to get the slab representative from the
	 * global pool.
	 */
	if (domid == idn.localid)
		islocal = 1;

	if (bufp != NULL) {
		nslabs = -1;
	} else {
		nslabs = *(int *)ebufp;
		if (nslabs == 0) {
			PR_SMR("%s: requested nslabs (%d) <= 0\n",
			    proc, nslabs);
			return (NULL);
		} else if (nslabs < 0) {
			/*
			 * Caller wants them all!
			 */
			nslabs = (int)dp->dnslabs;
		}
	}

	retsp = NULL;
	foundit = 0;
	for (psp = &dp->dslab; sp; sp = *psp) {
		int	isbusy;

		if (bufp && (sp->sl_start != bufp)) {
			psp = &sp->sl_next;
			continue;
		}

		if (bufp && (ebufp > sp->sl_end)) {
			PR_SMR("%s: bufp/ebufp (0x%p/0x%p) "
			    "expected (0x%p/0x%p)\n", proc, (void *)bufp,
			    (void *)ebufp, (void *)sp->sl_start,
			    (void *)sp->sl_end);
			ASSERT(0);
		}
		/*
		 * We found the desired slab.  Make sure
		 * it's free.
		 */
		foundit++;
		isbusy = 0;
		if (islocal) {
			int spl;

			/*
			 * Some of the buffers in the slab
			 * are still in use.  Unlock the
			 * buffers we locked and bail out.
			 */
			spl = splhi();
			if (!lock_try(&sp->sl_lock)) {
				isbusy = 1;
				foundit--;
			} else if (sp->sl_inuse) {
				lock_clear(&sp->sl_lock);
				isbusy = 1;
				foundit--;
			}
			splx(spl);
		} else {
			/*
			 * If not local, then I'm the master getting
			 * a slab from one of the slaves.  In this case,
			 * their slab structs will always be locked.
			 */
			ASSERT(!lock_try(&sp->sl_lock));
		}
		if (!isbusy) {
			/*
			 * Delete the entry from the list and slap
			 * it onto our return list.
			 */
			*psp = sp->sl_next;
			sp->sl_next = retsp;
			retsp = sp;
		} else {
			psp = &sp->sl_next;
		}
		/*
		 * If bufp == NULL (alternate interface) and we haven't
		 * found the desired number of slabs yet, keep looking.
		 */
		if (bufp || (foundit == nslabs))
			break;
	}
	dp->dnslabs -= (short)foundit;

	if (foundit) {
		PR_SMR("%s: found %d free slabs (domid = %d)\n", proc, foundit,
		    domid);
	} else {
		PR_SMR("%s: no free slabs found (domid = %d)\n", proc, domid);
	}

	/*
	 * If this is the alternate interface, need to return
	 * the number of slabs found in the ebufp parameter.
	 */
	if (bufp == NULL)
		*(int *)ebufp = foundit;

	return (retsp);
}

/*
 * Wrapper to hide alternate interface to smr_slaballoc_get()
 */
smr_slab_t *
smr_slaballoc_get_n(int domid, int *nslabs)
{
	smr_slab_t	*sp;

	ASSERT(DSLAB_WRITE_HELD(domid));

	sp = smr_slaballoc_get(domid, NULL, (caddr_t)nslabs);

	return (sp);
}

/*
 * Only called by master.  Initialize slab pool based on local SMR.
 * Returns number of slabs initialized.
 * reserved_size = Length of area at the front of the NWR portion
 *		   of the SMR to reserve and not make available for
 *		   slab allocations.  Must be a IDN_SMR_BUFSIZE multiple.
 * reserved_area = Pointer to reserved area, if any.
 */
int
smr_slabpool_init(size_t reserved_size, caddr_t *reserved_area)
{
	size_t			nwr_available;
	int			minperpool, ntotslabs, nxslabs, nslabs;
	register int		p, pp;
	register caddr_t	bufp;
	register smr_slab_t	*sp;

	ASSERT(IDN_GLOCK_IS_EXCL());
	ASSERT(IDN_GET_MASTERID() != IDN_NIL_DOMID);

	*reserved_area = NULL;

	nwr_available = MB2B(IDN_NWR_SIZE) - reserved_size;

	if ((idn.localid != IDN_GET_MASTERID()) ||
	    (nwr_available < IDN_SLAB_SIZE) ||
	    (idn.slabpool != NULL) ||
	    ((reserved_size != 0) && (reserved_size & (IDN_SMR_BUFSIZE-1)))) {
		return (-1);
	}

	idn.slabpool = GETSTRUCT(struct slabpool, 1);
	idn.slabpool->ntotslabs = ntotslabs = nwr_available / IDN_SLAB_SIZE;
	ASSERT(ntotslabs > 0);
	minperpool = (ntotslabs < IDN_SLAB_MINPERPOOL) ?
	    1 : IDN_SLAB_MINPERPOOL;
	idn.slabpool->npools = (ntotslabs + (minperpool - 1)) / minperpool;

	if ((idn.slabpool->npools & 1) == 0) {
		/*
		 * npools needs to be odd for hashing algorithm.
		 */
		idn.slabpool->npools++;
	}
	ASSERT(idn.slabpool->npools > 0);
	minperpool = (ntotslabs < idn.slabpool->npools) ?
	    1 : (ntotslabs / idn.slabpool->npools);

	/*
	 * Calculate the number of extra slabs that will need to
	 * be alloted to the pools.  This number will be less than
	 * npools.  Only one extra slab is allocated to each pool
	 * until we have assigned all the extra slabs.
	 */
	if (ntotslabs > (idn.slabpool->npools * minperpool))
		nxslabs = ntotslabs - (idn.slabpool->npools * minperpool);
	else
		nxslabs = 0;
	ASSERT((nxslabs >= 0) && (nxslabs < idn.slabpool->npools));

	idn.slabpool->pool = GETSTRUCT(struct smr_slabtbl,
	    idn.slabpool->npools);
	sp = GETSTRUCT(smr_slab_t, idn.slabpool->ntotslabs);

	idn.slabpool->savep = sp;
	bufp = idn.smr.vaddr + reserved_size;

	for (p = nslabs = 0;
	    (p < idn.slabpool->npools) && (ntotslabs > 0);
	    p++, ntotslabs -= nslabs) {

		nslabs = (ntotslabs < minperpool) ? ntotslabs : minperpool;
		if (nxslabs > 0) {
			nslabs++;
			nxslabs--;
		}
		idn.slabpool->pool[p].sarray = sp;
		for (pp = 0; pp < nslabs; pp++) {

			sp->sl_next  = NULL;
			sp->sl_start = bufp;
			sp->sl_end   = bufp = sp->sl_start + IDN_SLAB_SIZE;
			sp->sl_lock  = 0;
			sp->sl_domid = (short)IDN_NIL_DOMID;

			sp++;
		}
		idn.slabpool->pool[p].nfree   = nslabs;
		idn.slabpool->pool[p].nslabs  = nslabs;
	}
	ASSERT((ntotslabs == 0) && (nxslabs == 0));
	/*
	 * We should be at the end of the SMR at this point.
	 */
	ASSERT(bufp == (idn.smr.vaddr + reserved_size
	    + (idn.slabpool->ntotslabs * IDN_SLAB_SIZE)));

	if (reserved_size != 0)
		*reserved_area = idn.smr.vaddr;

	return (0);
}

void
smr_slabpool_deinit()
{
	if (idn.slabpool == NULL)
		return;

	FREESTRUCT(idn.slabpool->savep, smr_slab_t, idn.slabpool->ntotslabs);
	FREESTRUCT(idn.slabpool->pool, struct smr_slabtbl,
	    idn.slabpool->npools);
	FREESTRUCT(idn.slabpool, struct slabpool, 1);

	idn.slabpool = NULL;
}

void
smr_alloc_buflist(smr_slab_t *sp)
{
	int		n, nbufs;
	caddr_t		sbufp;
	smr_slabbuf_t	*hp, *bp;

	if (sp->sl_head)
		return;

	nbufs = (sp->sl_end - sp->sl_start) / IDN_SMR_BUFSIZE;
	ASSERT(nbufs > 0);
	if (nbufs <= 0) {
		sp->sl_head = sp->sl_free = sp->sl_inuse = NULL;
		return;
	}

	hp = GETSTRUCT(smr_slabbuf_t, nbufs);

	sbufp = sp->sl_start;
	for (n = 0, bp = hp; n < nbufs; bp++, n++) {
		bp->sb_bufp = sbufp;
		bp->sb_domid = IDN_NIL_DOMID;
		bp->sb_next = bp + 1;
		sbufp += IDN_SMR_BUFSIZE;
	}
	(--bp)->sb_next = NULL;

	sp->sl_head = sp->sl_free = hp;
	sp->sl_inuse = NULL;
}

void
smr_free_buflist(smr_slab_t *sp)
{
	int	nbufs;

	if (sp->sl_head == NULL)
		return;

	nbufs = (sp->sl_end - sp->sl_start) / IDN_SMR_BUFSIZE;

	FREESTRUCT(sp->sl_head, smr_slabbuf_t, nbufs);

	sp->sl_head = sp->sl_free = sp->sl_inuse = NULL;
}

/*
 * Returns:	0 Successfully located a slab.
 *	       -1 Failure.
 */
static smr_slab_t *
smr_slab_reserve(int domid)
{
	register int		p, nextp, s, nexts;
	register smr_slab_t	*spa;
	int			startp, starts;
	int			foundone = 0;
	int			spl;
	procname_t		proc = "smr_slab_reserve";

	p = startp = SMR_SLABPOOL_HASH(domid);
	nextp = -1;

	spl = splhi();
	while ((nextp != startp) && !foundone) {

		s = starts = SMR_SLAB_HASH(p, domid);
		nexts = -1;
		spa = &(idn.slabpool->pool[p].sarray[0]);

		while ((nexts != starts) && !foundone) {
			if (lock_try(&spa[s].sl_lock)) {
				foundone = 1;
				break;
			}
			nexts = SMR_SLAB_HASHSTEP(p, s);
			s = nexts;
		}
		if (foundone)
			break;
		nextp = SMR_SLABPOOL_HASHSTEP(p);
		p = nextp;
	}
	splx(spl);

	if (foundone) {
		ASSERT((&spa[s] >= idn.slabpool->savep) &&
		    (&spa[s] < (idn.slabpool->savep +
		    idn.slabpool->ntotslabs)));

		spa[s].sl_domid = (short)domid;

		ATOMIC_DEC(idn.slabpool->pool[p].nfree);

		if (domid == idn.localid) {
			smr_slab_t	*nsp;
			/*
			 * Caller is actually reserving a slab for
			 * themself which means they'll need the full
			 * slab structure to represent all of the I/O
			 * buffers.  The "spa" is just a representative
			 * and doesn't contain the space to manage the
			 * individual buffers.  Need to alloc a full-size
			 * struct.
			 * Note that this results in the returning
			 * smr_slab_t structure being unlocked.
			 */
			ASSERT(idn.localid == IDN_GET_MASTERID());
			nsp = GETSTRUCT(smr_slab_t, 1);
			nsp->sl_start = spa[s].sl_start;
			nsp->sl_end   = spa[s].sl_end;
			smr_alloc_buflist(nsp);
			spa = nsp;
			PR_SMR("%s: allocated full slab struct for domain %d\n",
			    proc, domid);
		} else {
			/*
			 * Slab structure gets returned locked.
			 */
			spa += s;
		}

		PR_SMR("%s: allocated slab 0x%p (start=0x%p, size=%lu) for "
		    "domain %d\n", proc, (void *)spa, (void *)spa->sl_start,
		    spa->sl_end - spa->sl_start, domid);
	} else {
		PR_SMR("%s: FAILED to allocate for domain %d\n",
		    proc, domid);
		spa = NULL;
	}

	return (spa);
}

static void
smr_slab_unreserve(int domid, smr_slab_t *sp)
{
	register int		p, nextp, s, nexts;
	register smr_slab_t	*spa;
	int			foundit = 0;
	int			startp, starts;
	caddr_t			bufp;
	procname_t		proc = "smr_slab_unreserve";

	bufp = sp->sl_start;
	p = startp = SMR_SLABPOOL_HASH(domid);
	nextp = -1;

	while ((nextp != startp) && !foundit) {

		s = starts = SMR_SLAB_HASH(p, domid);
		nexts = -1;
		spa = &(idn.slabpool->pool[p].sarray[0]);

		while ((nexts != starts) && !foundit) {
			if (spa[s].sl_start == bufp) {
				foundit = 1;
				break;
			}
			nexts = SMR_SLAB_HASHSTEP(p, s);
			s = nexts;
		}
		if (foundit)
			break;
		nextp = SMR_SLABPOOL_HASHSTEP(p);
		p = nextp;
	}
	if (foundit) {
		ASSERT((&spa[s] >= idn.slabpool->savep) &&
		    (&spa[s] < (idn.slabpool->savep +
		    idn.slabpool->ntotslabs)));
		ASSERT(!lock_try(&spa[s].sl_lock));
		ASSERT(spa[s].sl_domid == (short)domid);

		spa[s].sl_next = NULL;
		spa[s].sl_domid = (short)IDN_NIL_DOMID;
		lock_clear(&spa[s].sl_lock);

		ATOMIC_INC(idn.slabpool->pool[p].nfree);

		PR_SMR("%s: freed (bufp=0x%p) for domain %d\n",
		    proc, (void *)bufp, domid);

		if (domid == idn.localid) {
			/*
			 * Caller is actually unreserving a slab of their
			 * own.  Note that only the master calls this
			 * routine.  Since the master's local slab
			 * structures do not get entered into the global
			 * "representative" pool, we need to free up the
			 * data structure that was passed in.
			 */
			ASSERT(idn.localid == IDN_GET_MASTERID());
			ASSERT(sp != &spa[s]);

			smr_free_buflist(sp);
			FREESTRUCT(sp, smr_slab_t, 1);
		} else {
			ASSERT(sp == &spa[s]);
		}
	} else {
		/*
		 * Couldn't find slab entry for given buf!
		 */
		PR_SMR("%s: FAILED to free (bufp=0x%p) for domain %d\n",
		    proc, (void *)bufp, domid);
	}
}

/*
 * The Reap Protocol:
 *	master				   slave
 *	------				   -----
 *	smr_slab_reap_global
 *	- idn_broadcast_cmd(SLABREAP) ->   idn_recv_cmd(SLABREAP)
 *	  . idn_local_cmd(SLABREAP)        - idn_recv_slabreap_req
 *	    - smr_slab_reap	             . smr_slab_reap
 *	      . smr_slaballoc_get_n            - smr_slaballoc_get_n
 *	      . smr_slab_free		       - smr_slab_free
 *		- smr_slab_free_local		 . smr_slab_free_remote
 *		  . smr_slab_unreserve
 *				      <-	   - idn_send_cmd(SLABFREE)
 *	idn_recv_cmd(SLABFREE)
 *	- idn_recv_slabfree_req
 *	  . smr_slaballoc_get
 *	  . smr_slab_free
 *	    - smr_slab_free_local
 *	      . smr_slab_unreserve
 *        . idn_send_slabfree_resp    ->   idn_recv_cmd(SLABFREE | ack)
 *					   - idn_recv_slabfree_resp
 *
 *	idn_recv_cmd(SLABREAP | ack)  <-     . idn_send_slabreap_resp
 *	- idn_recv_slabreap_resp	   DONE
 *	DONE
 *
 * Check available slabs and if we're below the threshold, kick
 * off reaping to all remote domains.  There is no guarantee remote
 * domains will be able to free up any.
 */
static void
smr_slab_reap_global()
{
	register int	p, npools;
	register int	total_free = 0;
	register struct smr_slabtbl	*tblp;
	static clock_t	reap_last = 0;
	procname_t	proc = "smr_slab_reap_global";
	clock_t		now;

	ASSERT(IDN_GET_MASTERID() != IDN_NIL_DOMID);

	DSLAB_LOCK_SHARED(idn.localid);
	if (idn_domain[idn.localid].dslab_state != DSLAB_STATE_LOCAL) {
		PR_SMR("%s: only allowed by master (%d)\n",
		    proc, IDN_GET_MASTERID());
		DSLAB_UNLOCK(idn.localid);
		return;
	}
	DSLAB_UNLOCK(idn.localid);

	now = ddi_get_lbolt();
	if ((now > 0) && (now > reap_last) &&
	    ((now - reap_last) < IDN_REAP_INTERVAL))
		return;

	reap_last = now;

	ASSERT(idn.slabpool);

	npools = idn.slabpool->npools;
	tblp   = idn.slabpool->pool;

	for (p = 0; p < npools; tblp++, p++)
		total_free += tblp->nfree;

	if (total_free <= IDN_SLAB_THRESHOLD) {
		int	diff, reap_per_domain;

		PR_SMR("%s: kicking off reaping "
		    "(total_free = %d, min = %d)\n",
		    proc, total_free, IDN_SLAB_THRESHOLD);

		diff = IDN_SLAB_THRESHOLD - total_free;
		reap_per_domain = (diff < idn.ndomains) ?
		    1 : (diff / idn.ndomains);

		idn_broadcast_cmd(IDNCMD_SLABREAP, reap_per_domain, 0, 0);
	}
}

void
smr_slab_reap(int domid, int *nslabs)
{
	register int	d;
	int		nreclaimed;
	smr_slab_t	*sp;
	domainset_t	reapset;
	procname_t	proc = "smr_slab_reap";

	/*
	 * Should only be called on behalf of local
	 * domain.
	 */
	if (domid != idn.localid) {
		PR_SMR("%s: called by domain %d, should only be local (%d)\n",
		    proc, domid, idn.localid);
		ASSERT(0);
		return;
	}
	/*
	 * Try and reclaim some buffers so we can possibly
	 * free up some slabs.
	 */
	reapset = idn.domset.ds_connected;

	IDN_GKSTAT_GLOBAL_EVENT(gk_reaps, gk_reap_last);

	nreclaimed = 0;
	for (d = 0; d < MAX_DOMAINS; d++) {
		int		nr;
		idn_domain_t	*dp;

		if (!DOMAIN_IN_SET(reapset, d))
			continue;

		IDN_DLOCK_SHARED(d);

		dp = &idn_domain[d];
		if ((d == idn.localid) || (dp->dcpu < 0)) {
			IDN_DUNLOCK(d);
			continue;
		}
		/*
		 * Clean up any dead I/O errors if possible.
		 */
		if (dp->dioerr > 0) {
			idn_domain_t	*ldp;
			register int	cnt;
			register smr_slabbuf_t	*bp;
			/*
			 * We need to grab the writer lock to prevent
			 * anybody from allocating buffers while we
			 * traverse the slabs outstanding.
			 */
			cnt = 0;
			ldp = &idn_domain[idn.localid];
			IDN_DLOCK_EXCL(idn.localid);
			DSLAB_LOCK_EXCL(idn.localid);
			for (sp = ldp->dslab; sp; sp = sp->sl_next)
				for (bp = sp->sl_inuse; bp; bp = bp->sb_next)
					if (bp->sb_domid == d)
						cnt++;
			DSLAB_UNLOCK(idn.localid);
			ASSERT((dp->dio + dp->dioerr) >= cnt);
			dp->dio = cnt;
			dp->dioerr = 0;
			IDN_DUNLOCK(idn.localid);
		}
		if ((dp->dstate == IDNDS_CONNECTED) &&
		    ((nr = idn_reclaim_mboxdata(d, 0, -1)) > 0))
			nreclaimed += nr;

		IDN_DUNLOCK(d);
	}

	DSLAB_LOCK_EXCL(domid);
	sp = smr_slaballoc_get_n(domid, nslabs);
	if (sp) {
		IDN_GKSTAT_ADD(gk_reap_count, (ulong_t)(*nslabs));
		smr_slab_free(domid, sp);
	}
	DSLAB_UNLOCK(domid);
}

/*
 * ---------------------------------------------------------------------
 * Remap the (IDN) shared memory region to a new physical address.
 * Caller is expected to have performed a ecache flush if needed.
 * ---------------------------------------------------------------------
 */
void
smr_remap(struct as *as, register caddr_t vaddr,
		register pfn_t new_pfn, uint_t mblen)
{
	tte_t		tte;
	size_t		blen;
	pgcnt_t		p, npgs;
	procname_t	proc = "smr_remap";

	if (va_to_pfn(vaddr) == new_pfn) {
		PR_REMAP("%s: vaddr (0x%p) already mapped to pfn (0x%lx)\n",
		    proc, (void *)vaddr, new_pfn);
		return;
	}

	blen = MB2B(mblen);
	npgs = btopr(blen);
	ASSERT(npgs != 0);

	PR_REMAP("%s: va = 0x%p, pfn = 0x%lx, npgs = %ld, mb = %d MB (%ld)\n",
	    proc, (void *)vaddr, new_pfn, npgs, mblen, blen);

	/*
	 * Unmap the SMR virtual address from it's current
	 * mapping.
	 */
	hat_unload(as->a_hat, vaddr, blen, HAT_UNLOAD_UNLOCK);

	if (new_pfn == PFN_INVALID)
		return;

	/*
	 * Map the SMR to the new physical address space,
	 * presumably a remote pfn.  Cannot use hat_devload
	 * because it will think pfn represents non-memory,
	 * since it may extend beyond its physmax.
	 */
	for (p = 0; p < npgs; p++) {
		sfmmu_memtte(&tte, new_pfn, PROT_READ | PROT_WRITE | HAT_NOSYNC,
		    TTE8K);
		sfmmu_tteload(as->a_hat, &tte, vaddr, NULL, HAT_LOAD_LOCK);

		vaddr += MMU_PAGESIZE;
		new_pfn++;
	}

	PR_REMAP("%s: remapped %ld pages (expected %ld)\n",
	    proc, npgs, btopr(MB2B(mblen)));
}
