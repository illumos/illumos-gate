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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/uio.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/systm.h>
#include <sys/socketvar.h>
#include <fs/sockfs/sodirect.h>

/*
 * In support of on-board asynchronous DMA hardware (e.g. Intel I/OAT)
 * we use a consolidation private KAPI to allow the protocol to start
 * an asynchronous copyout to a user-land receive-side buffer (uioa)
 * when a blocking socket read (e.g. read, recv, ...) is pending.
 *
 * In some broad strokes, this is what happens. When recv is called,
 * we first determine whether it would be beneficial to use uioa, and
 * if so set up the required state (all done by sod_rcv_init()).
 * The protocol can only initiate asynchronous copyout if the receive
 * queue is empty, so the first thing we do is drain any previously
 * queued data (using sod_uioa_so_init()). Once the copyouts (if any)
 * have been scheduled we wait for the receive to be satisfied. During
 * that time any new mblks that are enqueued will be scheduled to be
 * copied out asynchronously (sod_uioa_mblk_init()). When the receive
 * has been satisfied we wait for all scheduled copyout operations to
 * complete before we return to the user (sod_rcv_done())
 */

static struct kmem_cache *sock_sod_cache;

/*
 * This function is called at the beginning of recvmsg().
 *
 * If I/OAT is enabled on this sonode, initialize the uioa state machine
 * with state UIOA_ALLOC.
 */
uio_t *
sod_rcv_init(struct sonode *so, int flags, struct uio **uiopp)
{
	struct uio *suiop;
	struct uio *uiop;
	sodirect_t *sodp = so->so_direct;

	if (sodp == NULL)
		return (NULL);

	suiop = NULL;
	uiop = *uiopp;

	mutex_enter(&so->so_lock);
	if (uiop->uio_resid >= uioasync.mincnt &&
	    sodp != NULL && sodp->sod_enabled &&
	    uioasync.enabled && !(flags & MSG_PEEK) &&
	    !so->so_proto_props.sopp_loopback &&
	    !(so->so_state & SS_CANTRCVMORE)) {
		/*
		 * Big enough I/O for uioa min setup and an sodirect socket
		 * and sodirect enabled and uioa enabled and I/O will be done
		 * and not EOF so initialize the sodirect_t uioa_t with "uiop".
		 */
		if (!uioainit(uiop, &sodp->sod_uioa)) {
			/*
			 * Successful uioainit() so the uio_t part of the
			 * uioa_t will be used for all uio_t work to follow,
			 * we return the original "uiop" in "suiop".
			 */
			suiop = uiop;
			*uiopp = (uio_t *)&sodp->sod_uioa;
			/*
			 * Before returning to the caller the passed in uio_t
			 * "uiop" will be updated via a call to uioafini()
			 * below.
			 *
			 * Note, the uioa.uioa_state isn't set to UIOA_ENABLED
			 * here as first we have to uioamove() any currently
			 * queued M_DATA mblk_t(s) so it will be done later.
			 */
		}
	}
	mutex_exit(&so->so_lock);

	return (suiop);
}

/*
 * This function is called at the end of recvmsg(), it finializes all the I/OAT
 * operations, and reset the uioa state to UIOA_ALLOC.
 */
int
sod_rcv_done(struct sonode *so, struct uio *suiop, struct uio *uiop)
{
	int error = 0;
	sodirect_t *sodp = so->so_direct;
	mblk_t *mp;

	if (sodp == NULL) {
		return (0);
	}

	ASSERT(MUTEX_HELD(&so->so_lock));
	/* Finish any sodirect and uioa processing */
	if (suiop != NULL) {
		/* Finish any uioa_t processing */

		ASSERT(uiop == (uio_t *)&sodp->sod_uioa);
		error = uioafini(suiop, (uioa_t *)uiop);
		if ((mp = sodp->sod_uioafh) != NULL) {
			sodp->sod_uioafh = NULL;
			sodp->sod_uioaft = NULL;
			freemsg(mp);
		}
	}
	ASSERT(sodp->sod_uioafh == NULL);

	return (error);
}

/*
 * Schedule a uioamove() on a mblk. This is done as mblks are enqueued
 * by the protocol on the socket's rcv queue.
 *
 * Caller must be holding so_lock.
 */
void
sod_uioa_mblk_init(struct sodirect_s *sodp, mblk_t *mp, size_t msg_size)
{
	uioa_t *uioap = &sodp->sod_uioa;
	mblk_t *mp1 = mp;
	mblk_t *lmp = NULL;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(msg_size == msgdsize(mp));

	if (uioap->uioa_state & UIOA_ENABLED) {
		/* Uioa is enabled */

		if (msg_size > uioap->uio_resid) {
			/*
			 * There isn't enough uio space for the mblk_t chain
			 * so disable uioa such that this and any additional
			 * mblk_t data is handled by the socket and schedule
			 * the socket for wakeup to finish this uioa.
			 */
			uioap->uioa_state &= UIOA_CLR;
			uioap->uioa_state |= UIOA_FINI;
			return;
		}
		do {
			uint32_t	len = MBLKL(mp1);

			if (!uioamove(mp1->b_rptr, len, UIO_READ, uioap)) {
				/* Scheduled, mark dblk_t as such */
				DB_FLAGS(mp1) |= DBLK_UIOA;
			} else {
				/* Error, turn off async processing */
				uioap->uioa_state &= UIOA_CLR;
				uioap->uioa_state |= UIOA_FINI;
				break;
			}
			lmp = mp1;
		} while ((mp1 = mp1->b_cont) != NULL);

		if (mp1 != NULL || uioap->uio_resid == 0) {
			/* Break the mblk chain if neccessary. */
			if (mp1 != NULL && lmp != NULL) {
				mp->b_next = mp1;
				lmp->b_cont = NULL;
			}
		}
	}
}

/*
 * This function is called on a mblk that thas been successfully uioamoved().
 */
void
sod_uioa_mblk_done(sodirect_t *sodp, mblk_t *bp)
{
	if (bp != NULL && (bp->b_datap->db_flags & DBLK_UIOA)) {
		/*
		 * A uioa flaged mblk_t chain, already uio processed,
		 * add it to the sodirect uioa pending free list.
		 *
		 * Note, a b_cont chain headed by a DBLK_UIOA enable
		 * mblk_t must have all mblk_t(s) DBLK_UIOA enabled.
		 */
		mblk_t	*bpt = sodp->sod_uioaft;

		ASSERT(sodp != NULL);

		/*
		 * Add first mblk_t of "bp" chain to current sodirect uioa
		 * free list tail mblk_t, if any, else empty list so new head.
		 */
		if (bpt == NULL)
			sodp->sod_uioafh = bp;
		else
			bpt->b_cont = bp;

		/*
		 * Walk mblk_t "bp" chain to find tail and adjust rptr of
		 * each to reflect that uioamove() has consumed all data.
		 */
		bpt = bp;
		for (;;) {
			ASSERT(bpt->b_datap->db_flags & DBLK_UIOA);

			bpt->b_rptr = bpt->b_wptr;
			if (bpt->b_cont == NULL)
				break;
			bpt = bpt->b_cont;
		}
		/* New sodirect uioa free list tail */
		sodp->sod_uioaft = bpt;

		/* Only dequeue once with data returned per uioa_t */
		if (sodp->sod_uioa.uioa_state & UIOA_ENABLED) {
			sodp->sod_uioa.uioa_state &= UIOA_CLR;
			sodp->sod_uioa.uioa_state |= UIOA_FINI;
		}
	}
}

/*
 * When transit from UIOA_INIT state to UIOA_ENABLE state in recvmsg(), call
 * this function on a non-STREAMS socket to schedule uioamove() on the data
 * that has already queued in this socket.
 */
void
sod_uioa_so_init(struct sonode *so, struct sodirect_s *sodp, struct uio *uiop)
{
	uioa_t	*uioap = (uioa_t *)uiop;
	mblk_t	*lbp;
	mblk_t	*wbp;
	mblk_t	*bp;
	int	len;
	int	error;
	boolean_t in_rcv_q = B_TRUE;

	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(&sodp->sod_uioa == uioap);

	/*
	 * Walk first b_cont chain in sod_q
	 * and schedule any M_DATA mblk_t's for uio asynchronous move.
	 */
	bp = so->so_rcv_q_head;

again:
	/* Walk the chain */
	lbp = NULL;
	wbp = bp;

	do {
		if (bp == NULL)
			break;

		if (wbp->b_datap->db_type != M_DATA) {
			/* Not M_DATA, no more uioa */
			goto nouioa;
		}
		if ((len = wbp->b_wptr - wbp->b_rptr) > 0) {
			/* Have a M_DATA mblk_t with data */
			if (len > uioap->uio_resid || (so->so_oobmark > 0 &&
			    len + uioap->uioa_mbytes >= so->so_oobmark)) {
				/* Not enough uio sapce, or beyond oobmark */
				goto nouioa;
			}
			ASSERT(!(wbp->b_datap->db_flags & DBLK_UIOA));
			error = uioamove(wbp->b_rptr, len,
			    UIO_READ, uioap);
			if (!error) {
				/* Scheduled, mark dblk_t as such */
				wbp->b_datap->db_flags |= DBLK_UIOA;
			} else {
				/* Break the mblk chain */
				goto nouioa;
			}
		}
		/* Save last wbp processed */
		lbp = wbp;
	} while ((wbp = wbp->b_cont) != NULL);

	if (in_rcv_q && (bp == NULL || bp->b_next == NULL)) {
		/*
		 * We get here only once to process the sonode dump area
		 * if so_rcv_q_head is NULL or all the mblks have been
		 * successfully uioamoved()ed.
		 */
		in_rcv_q = B_FALSE;

		/* move to dump area */
		bp = so->so_rcv_head;
		goto again;
	}

	return;

nouioa:
	/* No more uioa */
	uioap->uioa_state &= UIOA_CLR;
	uioap->uioa_state |= UIOA_FINI;

	/*
	 * If we processed 1 or more mblk_t(s) then we need to split the
	 * current mblk_t chain in 2 so that all the uioamove()ed mblk_t(s)
	 * are in the current chain and the rest are in the following new
	 * chain.
	 */
	if (lbp != NULL) {
		/* New end of current chain */
		lbp->b_cont = NULL;

		/* Insert new chain wbp after bp */
		if ((wbp->b_next = bp->b_next) == NULL) {
			if (in_rcv_q)
				so->so_rcv_q_last_head = wbp;
			else
				so->so_rcv_last_head = wbp;
		}
		bp->b_next = wbp;
		bp->b_next->b_prev = bp->b_prev;
		bp->b_prev = lbp;
	}
}

/*
 * Initialize sodirect data structures on a socket.
 */
void
sod_sock_init(struct sonode *so)
{
	sodirect_t	*sodp;

	ASSERT(so->so_direct == NULL);

	so->so_state |= SS_SODIRECT;

	sodp = kmem_cache_alloc(sock_sod_cache, KM_SLEEP);
	sodp->sod_enabled = B_TRUE;
	sodp->sod_uioafh = NULL;
	sodp->sod_uioaft = NULL;
	/*
	 * Remainder of the sod_uioa members are left uninitialized
	 * but will be initialized later by uioainit() before uioa
	 * is enabled.
	 */
	sodp->sod_uioa.uioa_state = UIOA_ALLOC;
	so->so_direct = sodp;
}

void
sod_sock_fini(struct sonode *so)
{
	sodirect_t *sodp = so->so_direct;

	ASSERT(sodp->sod_uioafh == NULL);

	so->so_direct = NULL;
	kmem_cache_free(sock_sod_cache, sodp);
}

/*
 * Init the sodirect kmem cache while sockfs is loading.
 */
int
sod_init()
{
	/* Allocate sodirect_t kmem_cache */
	sock_sod_cache = kmem_cache_create("sock_sod_cache",
	    sizeof (sodirect_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	return (0);
}

ssize_t
sod_uioa_mblk(struct sonode *so, mblk_t *mp)
{
	sodirect_t *sodp = so->so_direct;

	ASSERT(sodp != NULL);
	ASSERT(MUTEX_HELD(&so->so_lock));

	ASSERT(sodp->sod_enabled);
	ASSERT(sodp->sod_uioa.uioa_state != (UIOA_ALLOC|UIOA_INIT));

	ASSERT(sodp->sod_uioa.uioa_state & (UIOA_ENABLED|UIOA_FINI));

	if (mp == NULL && so->so_rcv_q_head != NULL) {
		mp = so->so_rcv_q_head;
		ASSERT(mp->b_prev != NULL);
		mp->b_prev = NULL;
		so->so_rcv_q_head = mp->b_next;
		if (so->so_rcv_q_head == NULL) {
			so->so_rcv_q_last_head = NULL;
		}
		mp->b_next = NULL;
	}

	sod_uioa_mblk_done(sodp, mp);

	if (so->so_rcv_q_head == NULL && so->so_rcv_head != NULL &&
	    DB_TYPE(so->so_rcv_head) == M_DATA &&
	    (DB_FLAGS(so->so_rcv_head) & DBLK_UIOA)) {
		/* more arrived */
		ASSERT(so->so_rcv_q_head == NULL);
		mp = so->so_rcv_head;
		so->so_rcv_head = mp->b_next;
		if (so->so_rcv_head == NULL)
			so->so_rcv_last_head = NULL;
		mp->b_prev = mp->b_next = NULL;
		sod_uioa_mblk_done(sodp, mp);
	}

#ifdef DEBUG
	if (so->so_rcv_q_head != NULL) {
		mblk_t *m = so->so_rcv_q_head;
		while (m != NULL) {
			if (DB_FLAGS(m) & DBLK_UIOA) {
				cmn_err(CE_PANIC, "Unexpected I/OAT mblk %p"
				    " in so_rcv_q_head.\n", (void *)m);
			}
			m = m->b_next;
		}
	}
	if (so->so_rcv_head != NULL) {
		mblk_t *m = so->so_rcv_head;
		while (m != NULL) {
			if (DB_FLAGS(m) & DBLK_UIOA) {
				cmn_err(CE_PANIC, "Unexpected I/OAT mblk %p"
				    " in so_rcv_head.\n", (void *)m);
			}
			m = m->b_next;
		}
	}
#endif
	return (sodp->sod_uioa.uioa_mbytes);
}
