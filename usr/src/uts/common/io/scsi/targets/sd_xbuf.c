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

#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/thread.h>
#include <sys/var.h>

#include "sd_xbuf.h"

/*
 * xbuf.c: buf(9s) extension facility.
 *
 * The buf(9S) extension facility is intended to allow block drivers to
 * allocate additional memory that is associated with a particular buf(9S)
 * struct.  It is further intended to help in addressing the usual set of
 * problems associated with such allocations, in particular those involving
 * recovery from allocation failures, especially in code paths that the
 * system relies on to free memory.
 *
 * CAVEAT: Currently this code is completely private to the sd driver and in
 * NO WAY constitutes a public or supported interface of any kind. It is
 * envisioned that this may one day migrate into the Solaris DDI, but until
 * that time this ought to be considered completely unstable and is subject
 * to change without notice. This code may NOT in any way be utilized by
 * ANY code outside the sd driver.
 */


static int xbuf_iostart(ddi_xbuf_attr_t xap);
static void xbuf_dispatch(ddi_xbuf_attr_t xap);
static void xbuf_restart_callback(void *arg);
static int xbuf_brk_done(struct buf *bp);


/*
 * Note: Should this be exposed to the caller.... do we want to give the
 * caller the fexibility of specifying the parameters for the thread pool?
 * Note: these values are just estimates at this time, based upon what
 * seems reasonable for the sd driver. It may be preferable to make these
 * parameters self-scaling in a real (future) implementation.
 */
#define	XBUF_TQ_MINALLOC	64
#define	XBUF_TQ_MAXALLOC	512
#define	XBUF_DISPATCH_DELAY	(drv_usectohz(50000))	/* 50 msec */

static taskq_t *xbuf_tq = NULL;
static int xbuf_attr_tq_minalloc = XBUF_TQ_MINALLOC;
static int xbuf_attr_tq_maxalloc = XBUF_TQ_MAXALLOC;

static kmutex_t	xbuf_mutex = { 0 };
static uint32_t	xbuf_refcount = 0;

/*
 * Private wrapper for buf cloned via ddi_xbuf_qstrategy()
 */
struct xbuf_brk {
	kmutex_t mutex;
	struct buf *bp0;
	uint8_t nbufs;	/* number of buf allocated */
	uint8_t active; /* number of active xfer */

	size_t brksize;	/* break size used for this buf */
	int brkblk;

	/* xfer position */
	off_t off;
	off_t noff;
	daddr_t blkno;
};

_NOTE(DATA_READABLE_WITHOUT_LOCK(xbuf_brk::off))

/*
 * Hack needed in the prototype so buf breakup will work.
 * Here we can rely on the sd code not changing the value in
 * b_forw.
 */
#define	b_clone_private b_forw


/* ARGSUSED */
DDII ddi_xbuf_attr_t
ddi_xbuf_attr_create(size_t xsize,
    void (*xa_strategy)(struct buf *bp, ddi_xbuf_t xp, void *attr_arg),
    void *attr_arg, uint32_t active_limit, uint32_t reserve_limit,
    major_t major, int flags)
{
	ddi_xbuf_attr_t	xap;

	xap = kmem_zalloc(sizeof (struct __ddi_xbuf_attr), KM_SLEEP);

	mutex_init(&xap->xa_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&xap->xa_reserve_mutex, NULL, MUTEX_DRIVER, NULL);

	/* Future: Allow the caller to specify alignment requirements? */
	xap->xa_allocsize	= max(xsize, sizeof (void *));
	xap->xa_active_limit	= active_limit;
	xap->xa_active_lowater	= xap->xa_active_limit / 2;
	xap->xa_reserve_limit	= reserve_limit;
	xap->xa_strategy	= xa_strategy;
	xap->xa_attr_arg	= attr_arg;

	mutex_enter(&xbuf_mutex);
	if (xbuf_refcount == 0) {
		ASSERT(xbuf_tq == NULL);
		/*
		 * Note: Would be nice if: (1) #threads in the taskq pool (set
		 * to the value of 'ncpus' at the time the taskq is created)
		 * could adjust automatically with DR; (2) the taskq
		 * minalloc/maxalloc counts could be grown/shrunk on the fly.
		 */
		xbuf_tq = taskq_create("xbuf_taskq", ncpus,
		    (v.v_maxsyspri - 2), xbuf_attr_tq_minalloc,
		    xbuf_attr_tq_maxalloc, TASKQ_PREPOPULATE);
	}
	xbuf_refcount++;
	mutex_exit(&xbuf_mutex);

	/* In this prototype we just always use the global system pool. */
	xap->xa_tq = xbuf_tq;

	return (xap);
}


DDII void
ddi_xbuf_attr_destroy(ddi_xbuf_attr_t xap)
{
	ddi_xbuf_t	xp;

	mutex_destroy(&xap->xa_mutex);
	mutex_destroy(&xap->xa_reserve_mutex);

	/* Free any xbufs on the reserve list */
	while (xap->xa_reserve_count != 0) {
		xp = xap->xa_reserve_headp;
		xap->xa_reserve_headp = *((void **)xp);
		xap->xa_reserve_count--;
		kmem_free(xp, xap->xa_allocsize);
	}
	ASSERT(xap->xa_reserve_headp == NULL);

	mutex_enter(&xbuf_mutex);
	ASSERT((xbuf_refcount != 0) && (xbuf_tq != NULL));
	xbuf_refcount--;
	if (xbuf_refcount == 0) {
		taskq_destroy(xbuf_tq);
		xbuf_tq = NULL;
	}
	mutex_exit(&xbuf_mutex);

	kmem_free(xap, sizeof (struct __ddi_xbuf_attr));
}


/* ARGSUSED */
DDII void
ddi_xbuf_attr_register_devinfo(ddi_xbuf_attr_t xbuf_attr, dev_info_t *dip)
{
	/* Currently a no-op in this prototype */
}


/* ARGSUSED */
DDII void
ddi_xbuf_attr_unregister_devinfo(ddi_xbuf_attr_t xbuf_attr, dev_info_t *dip)
{
	/* Currently a no-op in this prototype */
}

DDII int
ddi_xbuf_attr_setup_brk(ddi_xbuf_attr_t xap, size_t size)
{
	if (size < DEV_BSIZE)
		return (0);

	mutex_enter(&xap->xa_mutex);
	xap->xa_brksize = size & ~(DEV_BSIZE - 1);
	mutex_exit(&xap->xa_mutex);
	return (1);
}



/*
 * Enqueue the given buf and attempt to initiate IO.
 * Called from the driver strategy(9E) routine.
 */

DDII int
ddi_xbuf_qstrategy(struct buf *bp, ddi_xbuf_attr_t xap)
{
	ASSERT(xap != NULL);
	ASSERT(!mutex_owned(&xap->xa_mutex));
	ASSERT(!mutex_owned(&xap->xa_reserve_mutex));

	mutex_enter(&xap->xa_mutex);

	ASSERT((bp->b_bcount & (DEV_BSIZE - 1)) == 0);

	/*
	 * Breakup buf if necessary. bp->b_private is temporarily
	 * used to save xbuf_brk
	 */
	if (xap->xa_brksize && bp->b_bcount > xap->xa_brksize) {
		struct xbuf_brk *brkp;

		brkp = kmem_zalloc(sizeof (struct xbuf_brk), KM_SLEEP);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*brkp))
		mutex_init(&brkp->mutex, NULL, MUTEX_DRIVER, NULL);
		brkp->bp0 = bp;
		brkp->brksize = xap->xa_brksize;
		brkp->brkblk = btodt(xap->xa_brksize);
		brkp->noff = xap->xa_brksize;
		brkp->blkno = bp->b_blkno;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*brkp))
		bp->b_private = brkp;
	} else {
		bp->b_private = NULL;
	}

	/* Enqueue buf */
	if (xap->xa_headp == NULL) {
		xap->xa_headp = xap->xa_tailp = bp;
	} else {
		xap->xa_tailp->av_forw = bp;
		xap->xa_tailp = bp;
	}
	bp->av_forw = NULL;

	xap->xa_pending++;
	mutex_exit(&xap->xa_mutex);
	return (xbuf_iostart(xap));
}


/*
 * Drivers call this immediately before calling biodone(9F), to notify the
 * framework that the indicated xbuf is no longer being used by the driver.
 * May be called under interrupt context.
 */

DDII int
ddi_xbuf_done(struct buf *bp, ddi_xbuf_attr_t xap)
{
	ddi_xbuf_t xp;
	int done;

	ASSERT(bp != NULL);
	ASSERT(xap != NULL);
	ASSERT(!mutex_owned(&xap->xa_mutex));
	ASSERT(!mutex_owned(&xap->xa_reserve_mutex));

	xp = ddi_xbuf_get(bp, xap);

	mutex_enter(&xap->xa_mutex);

#ifdef	SDDEBUG
	if (xap->xa_active_limit != 0) {
		ASSERT(xap->xa_active_count > 0);
	}
#endif
	xap->xa_active_count--;

	if (xap->xa_reserve_limit != 0) {
		mutex_enter(&xap->xa_reserve_mutex);
		if (xap->xa_reserve_count < xap->xa_reserve_limit) {
			/* Put this xbuf onto the reserve list & exit */
			*((void **)xp) = xap->xa_reserve_headp;
			xap->xa_reserve_headp = xp;
			xap->xa_reserve_count++;
			mutex_exit(&xap->xa_reserve_mutex);
			goto done;
		}
		mutex_exit(&xap->xa_reserve_mutex);
	}

	kmem_free(xp, xap->xa_allocsize);	/* return it to the system */

done:
	if (bp->b_iodone == xbuf_brk_done) {
		struct xbuf_brk *brkp = (struct xbuf_brk *)bp->b_clone_private;

		brkp->active--;
		if (brkp->active || xap->xa_headp == brkp->bp0) {
			done = 0;
		} else {
			brkp->off = -1;	/* mark bp0 as completed */
			done = 1;
		}
	} else {
		done = 1;
	}

	if ((xap->xa_active_limit == 0) ||
	    (xap->xa_active_count <= xap->xa_active_lowater)) {
		xbuf_dispatch(xap);
	}

	mutex_exit(&xap->xa_mutex);
	return (done);
}

static int
xbuf_brk_done(struct buf *bp)
{
	struct xbuf_brk *brkp = (struct xbuf_brk *)bp->b_clone_private;
	struct buf *bp0 = brkp->bp0;
	int done;

	mutex_enter(&brkp->mutex);
	if (bp->b_flags & B_ERROR && !(bp0->b_flags & B_ERROR)) {
		bp0->b_flags |= B_ERROR;
		bp0->b_error = bp->b_error;
	}
	if (bp->b_resid)
		bp0->b_resid = bp0->b_bcount;

	freerbuf(bp);
	brkp->nbufs--;

	done = (brkp->off == -1 && brkp->nbufs == 0);
	mutex_exit(&brkp->mutex);

	/* All buf segments done */
	if (done) {
		mutex_destroy(&brkp->mutex);
		kmem_free(brkp, sizeof (struct xbuf_brk));
		biodone(bp0);
	}
	return (0);
}

DDII void
ddi_xbuf_dispatch(ddi_xbuf_attr_t xap)
{
	mutex_enter(&xap->xa_mutex);
	if ((xap->xa_active_limit == 0) ||
	    (xap->xa_active_count <= xap->xa_active_lowater)) {
		xbuf_dispatch(xap);
	}
	mutex_exit(&xap->xa_mutex);
}


/*
 * ISSUE: in this prototype we cannot really implement ddi_xbuf_get()
 * unless we explicitly hide the xbuf pointer somewhere in the buf
 * during allocation, and then rely on the driver never changing it.
 * We can probably get away with using b_private for this for now,
 * tho it really is kinda gnarly.....
 */

/* ARGSUSED */
DDII ddi_xbuf_t
ddi_xbuf_get(struct buf *bp, ddi_xbuf_attr_t xap)
{
	return (bp->b_private);
}


/*
 * Initiate IOs for bufs on the queue.  Called from kernel thread or taskq
 * thread context. May execute concurrently for the same ddi_xbuf_attr_t.
 */

static int
xbuf_iostart(ddi_xbuf_attr_t xap)
{
	struct buf *bp;
	ddi_xbuf_t xp;

	ASSERT(xap != NULL);
	ASSERT(!mutex_owned(&xap->xa_mutex));
	ASSERT(!mutex_owned(&xap->xa_reserve_mutex));

	/*
	 * For each request on the queue, attempt to allocate the specified
	 * xbuf extension area, and call the driver's iostart() routine.
	 * We process as many requests on the queue as we can, until either
	 * (1) we run out of requests; or
	 * (2) we run out of resources; or
	 * (3) we reach the maximum limit for the given ddi_xbuf_attr_t.
	 */
	for (;;) {
		mutex_enter(&xap->xa_mutex);

		if ((bp = xap->xa_headp) == NULL) {
			break;	/* queue empty */
		}

		if ((xap->xa_active_limit != 0) &&
		    (xap->xa_active_count >= xap->xa_active_limit)) {
			break;	/* allocation limit reached */
		}

		/*
		 * If the reserve_limit is non-zero then work with the
		 * reserve else always allocate a new struct.
		 */
		if (xap->xa_reserve_limit != 0) {
			/*
			 * Don't penalize EVERY I/O by always allocating a new
			 * struct. for the sake of maintaining and not touching
			 * a reserve for a pathalogical condition that may never
			 * happen. Use the reserve entries first, this uses it
			 * like a local pool rather than a reserve that goes
			 * untouched. Make sure it's re-populated whenever it
			 * gets fully depleted just in case it really is needed.
			 * This is safe because under the pathalogical
			 * condition, when the system runs out of memory such
			 * that the below allocs fail, the reserve will still
			 * be available whether the entries are saved away on
			 * the queue unused or in-transport somewhere. Thus
			 * progress can still continue, however slowly.
			 */
			mutex_enter(&xap->xa_reserve_mutex);
			if (xap->xa_reserve_count != 0) {
				ASSERT(xap->xa_reserve_headp != NULL);
				/* Grab an xbuf from the reserve */
				xp = xap->xa_reserve_headp;
				xap->xa_reserve_headp = *((void **)xp);
				ASSERT(xap->xa_reserve_count > 0);
				xap->xa_reserve_count--;
			} else {
				/*
				 * Either this is the first time through,
				 * or the reserve has been totally depleted.
				 * Re-populate the reserve (pool). Excess
				 * structs. get released in the done path.
				 */
				while (xap->xa_reserve_count <
				    xap->xa_reserve_limit) {
					xp = kmem_alloc(xap->xa_allocsize,
					    KM_NOSLEEP);
					if (xp == NULL) {
						break;
					}
					*((void **)xp) = xap->xa_reserve_headp;
					xap->xa_reserve_headp = xp;
					xap->xa_reserve_count++;
				}
				/* And one more to use right now. */
				xp = kmem_alloc(xap->xa_allocsize, KM_NOSLEEP);
			}
			mutex_exit(&xap->xa_reserve_mutex);
		} else {
			/*
			 * Try to alloc a new xbuf struct. If this fails just
			 * exit for now. We'll get back here again either upon
			 * cmd completion or via the timer handler.
			 * Question: what if the allocation attempt for the very
			 * first cmd. fails? There are no outstanding cmds so
			 * how do we get back here?
			 * Should look at un_ncmds_in_transport, if it's zero
			 * then schedule xbuf_restart_callback via the timer.
			 * Athough that breaks the architecture by bringing
			 * softstate data into this code.
			 */
			xp = kmem_alloc(xap->xa_allocsize, KM_NOSLEEP);
		}
		if (xp == NULL) {
			break; /* Can't process a cmd. right now. */
		}

		/*
		 * Always run the counter. It's used/needed when xa_active_limit
		 * is non-zero which is the typical (and right now only) case.
		 */
		xap->xa_active_count++;

		if (bp->b_private) {
			struct xbuf_brk *brkp = bp->b_private;
			struct buf *bp0 = bp;

			brkp->active++;

			mutex_enter(&brkp->mutex);
			brkp->nbufs++;
			mutex_exit(&brkp->mutex);

			if (brkp->noff < bp0->b_bcount) {
				bp = bioclone(bp0, brkp->off, brkp->brksize,
				    bp0->b_edev, brkp->blkno, xbuf_brk_done,
				    NULL, KM_SLEEP);

				/* update xfer position */
				brkp->off = brkp->noff;
				brkp->noff += brkp->brksize;
				brkp->blkno += brkp->brkblk;
			} else {
				bp = bioclone(bp0, brkp->off,
				    bp0->b_bcount - brkp->off, bp0->b_edev,
				    brkp->blkno, xbuf_brk_done, NULL, KM_SLEEP);

				/* unlink the buf from the list */
				xap->xa_headp = bp0->av_forw;
				bp0->av_forw = NULL;
			}
			bp->b_clone_private = (struct buf *)brkp;
		} else {
			/* unlink the buf from the list */
			xap->xa_headp = bp->av_forw;
			bp->av_forw = NULL;
		}

		/*
		 * Hack needed in the prototype so ddi_xbuf_get() will work.
		 * Here we can rely on the sd code not changing the value in
		 * b_private (in fact it wants it there). See ddi_get_xbuf()
		 */
		bp->b_private = xp;

		/* call the driver's iostart routine */
		mutex_exit(&xap->xa_mutex);
		(*(xap->xa_strategy))(bp, xp, xap->xa_attr_arg);
	}

	ASSERT(xap->xa_pending > 0);
	xap->xa_pending--;
	mutex_exit(&xap->xa_mutex);
	return (0);
}


/*
 * Re-start IO processing if there is anything on the queue, AND if the
 * restart function is not already running/pending for this ddi_xbuf_attr_t
 */
static void
xbuf_dispatch(ddi_xbuf_attr_t xap)
{
	ASSERT(xap != NULL);
	ASSERT(xap->xa_tq != NULL);
	ASSERT(mutex_owned(&xap->xa_mutex));

	if ((xap->xa_headp != NULL) && (xap->xa_timeid == NULL) &&
	    (xap->xa_pending == 0)) {
		/*
		 * First try to see if we can dispatch the restart function
		 * immediately, in a taskq thread.  If this fails, then
		 * schedule a timeout(9F) callback to try again later.
		 */
		if (taskq_dispatch(xap->xa_tq,
		    (void (*)(void *)) xbuf_iostart, xap, KM_NOSLEEP) == 0) {
			/*
			 * Unable to enqueue the request for the taskq thread,
			 * try again later.  Note that this will keep re-trying
			 * until taskq_dispatch() succeeds.
			 */
			xap->xa_timeid = timeout(xbuf_restart_callback, xap,
			    XBUF_DISPATCH_DELAY);
		} else {
			/*
			 * This indicates that xbuf_iostart() will soon be
			 * run for this ddi_xbuf_attr_t, and we do not need to
			 * schedule another invocation via timeout/taskq
			 */
			xap->xa_pending++;
		}
	}
}

/* timeout(9F) callback routine for xbuf restart mechanism. */
static void
xbuf_restart_callback(void *arg)
{
	ddi_xbuf_attr_t	xap = arg;

	ASSERT(xap != NULL);
	ASSERT(xap->xa_tq != NULL);
	ASSERT(!mutex_owned(&xap->xa_mutex));

	mutex_enter(&xap->xa_mutex);
	xap->xa_timeid = NULL;
	xbuf_dispatch(xap);
	mutex_exit(&xap->xa_mutex);
}


DDII void
ddi_xbuf_flushq(ddi_xbuf_attr_t xap, int (*funcp)(struct buf *))
{
	struct buf *bp;
	struct buf *next_bp;
	struct buf *prev_bp = NULL;

	ASSERT(xap != NULL);
	ASSERT(xap->xa_tq != NULL);
	ASSERT(!mutex_owned(&xap->xa_mutex));

	mutex_enter(&xap->xa_mutex);

	for (bp = xap->xa_headp; bp != NULL; bp = next_bp) {

		next_bp = bp->av_forw;	/* Save for next iteration */

		/*
		 * If the user-supplied function is non-NULL and returns
		 * FALSE, then just leave the current bp on the queue.
		 */
		if ((funcp != NULL) && (!(*funcp)(bp))) {
			prev_bp = bp;
			continue;
		}

		/* de-queue the bp */
		if (bp == xap->xa_headp) {
			xap->xa_headp = next_bp;
			if (xap->xa_headp == NULL) {
				xap->xa_tailp = NULL;
			}
		} else {
			ASSERT(xap->xa_headp != NULL);
			ASSERT(prev_bp != NULL);
			if (bp == xap->xa_tailp) {
				ASSERT(next_bp == NULL);
				xap->xa_tailp = prev_bp;
			}
			prev_bp->av_forw = next_bp;
		}
		bp->av_forw = NULL;

		/* Add the bp to the flush queue */
		if (xap->xa_flush_headp == NULL) {
			ASSERT(xap->xa_flush_tailp == NULL);
			xap->xa_flush_headp = xap->xa_flush_tailp = bp;
		} else {
			ASSERT(xap->xa_flush_tailp != NULL);
			xap->xa_flush_tailp->av_forw = bp;
			xap->xa_flush_tailp = bp;
		}
	}

	while ((bp = xap->xa_flush_headp) != NULL) {
		xap->xa_flush_headp = bp->av_forw;
		if (xap->xa_flush_headp == NULL) {
			xap->xa_flush_tailp = NULL;
		}
		mutex_exit(&xap->xa_mutex);
		bioerror(bp, EIO);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		mutex_enter(&xap->xa_mutex);
	}

	mutex_exit(&xap->xa_mutex);
}
