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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *		UNIX Device Driver Interface functions
 *	This file contains the C-versions of putnext() and put().
 *	Assembly language versions exist for some architectures.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/t_lock.h>
#include <sys/stream.h>
#include <sys/thread.h>
#include <sys/strsubr.h>
#include <sys/ddi.h>
#include <sys/vtrace.h>
#include <sys/cmn_err.h>
#include <sys/strft.h>
#include <sys/stack.h>
#include <sys/archsystm.h>

/*
 * Streams with many modules may create long chains of calls via putnext() which
 * may exhaust stack space. When putnext detects that the stack space left is
 * too small (less then PUT_STACK_NEEDED), the call chain is broken and
 * further processing is delegated to the background thread via call to
 * putnext_tail(). Unfortunately there is no generic solution with fixed stack
 * size, and putnext() is recursive function, so this hack is a necessary evil.
 *
 * The redzone value is chosen dependent on the default stack size which is 8K
 * on 32-bit kernels and on x86 and 16K on 64-bit kernels. The values are chosen
 * empirically. For 64-bit kernels it is 5000 and for 32-bit kernels it is 3000.
 * Experiments showed that 2500 is not enough for either 32-bit or 64-bit
 * kernels.
 *
 * The redzone value is a tuneable rather then a constant to allow adjustments
 * in the field.
 *
 * The check in PUT_STACK_NOTENOUGH is taken from segkp_map_red() function. It
 * is possible to define it as a generic function exported by seg_kp, but
 *
 * a) It may sound like an open invitation to use the facility indiscriminately.
 * b) It adds extra function call in putnext path.
 *
 * We keep a global counter `put_stack_notenough' which keeps track how many
 * times the stack switching hack was used.
 */

static ulong_t put_stack_notenough;

#ifdef	_LP64
#define	PUT_STACK_NEEDED 5000
#else
#define	PUT_STACK_NEEDED 3000
#endif

int put_stack_needed = PUT_STACK_NEEDED;

#if defined(STACK_GROWTH_DOWN)
#define	PUT_STACK_NOTENOUGH() 					\
	(((STACK_BIAS + (uintptr_t)getfp() -			\
	    (uintptr_t)curthread->t_stkbase) < put_stack_needed) && \
	++put_stack_notenough)
#else
#error	"STACK_GROWTH_DOWN undefined"
#endif

boolean_t	UseFastlocks = B_FALSE;

/*
 * function: putnext()
 * purpose:  call the put routine of the queue linked to qp
 *
 * Note: this function is written to perform well on modern computer
 * architectures by e.g. preloading values into registers and "smearing" out
 * code.
 *
 * A note on the fastput mechanism.  The most significant bit of a
 * putcount is considered the "FASTPUT" bit.  If set, then there is
 * nothing stoping a concurrent put from occuring (note that putcounts
 * are only allowed on CIPUT perimiters).  If, however, it is cleared,
 * then we need to take the normal lock path by aquiring the SQLOCK.
 * This is a slowlock.  When a thread starts exclusiveness, e.g. wants
 * writer access, it will clear the FASTPUT bit, causing new threads
 * to take the slowlock path.  This assures that putcounts will not
 * increase in value, so the want-writer does not need to constantly
 * aquire the putlocks to sum the putcounts.  This does have the
 * possibility of having the count drop right after reading, but that
 * is no different than aquiring, reading and then releasing.  However,
 * in this mode, it cannot go up, so eventually they will drop to zero
 * and the want-writer can proceed.
 *
 * If the FASTPUT bit is set, or in the slowlock path we see that there
 * are no writers or want-writers, we make the choice of calling the
 * putproc, or a "fast-fill_syncq".  The fast-fill is a fill with
 * immediate intention to drain.  This is done because there are
 * messages already at the queue waiting to drain.  To preserve message
 * ordering, we need to put this message at the end, and pickup the
 * messages at the beginning.  We call the macro that actually
 * enqueues the message on the queue, and then call qdrain_syncq.  If
 * there is already a drainer, we just return.  We could make that
 * check before calling qdrain_syncq, but it is a little more clear
 * to have qdrain_syncq do this (we might try the above optimization
 * as this behavior evolves).  qdrain_syncq assumes that SQ_EXCL is set
 * already if this is a non-CIPUT perimiter, and that an appropriate
 * claim has been made.  So we do all that work before dropping the
 * SQLOCK with our claim.
 *
 * If we cannot proceed with the putproc/fast-fill, we just fall
 * through to the qfill_syncq, and then tail processing.  If state
 * has changed in that cycle, or wakeups are needed, it will occur
 * there.
 */
void
putnext(queue_t *qp, mblk_t *mp)
{
	queue_t		*fqp = qp; /* For strft tracing */
	syncq_t		*sq;
	uint16_t	flags;
	uint16_t	drain_mask;
	struct qinit	*qi;
	int		(*putproc)();
	struct stdata	*stp;
	int		ix;
	boolean_t	queued = B_FALSE;
	kmutex_t	*sdlock = NULL;
	kmutex_t	*sqciplock = NULL;
	ushort_t	*sqcipcount = NULL;

	TRACE_2(TR_FAC_STREAMS_FR, TR_PUTNEXT_START,
	    "putnext_start:(%p, %p)", qp, mp);

	ASSERT(mp->b_datap->db_ref != 0);
	ASSERT(mp->b_next == NULL && mp->b_prev == NULL);
	stp = STREAM(qp);
	ASSERT(stp != NULL);
	if (stp->sd_ciputctrl != NULL) {
		ix = CPU->cpu_seqid & stp->sd_nciputctrl;
		sdlock = &stp->sd_ciputctrl[ix].ciputctrl_lock;
		mutex_enter(sdlock);
	} else {
		mutex_enter(sdlock = &stp->sd_lock);
	}
	qp = qp->q_next;
	sq = qp->q_syncq;
	ASSERT(sq != NULL);
	ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
	qi = qp->q_qinfo;

	if (sq->sq_ciputctrl != NULL) {
		/* fastlock: */
		ASSERT(sq->sq_flags & SQ_CIPUT);
		ix = CPU->cpu_seqid & sq->sq_nciputctrl;
		sqciplock = &sq->sq_ciputctrl[ix].ciputctrl_lock;
		sqcipcount = &sq->sq_ciputctrl[ix].ciputctrl_count;
		mutex_enter(sqciplock);
		if (!((*sqcipcount) & SQ_FASTPUT) ||
		    (sq->sq_flags & (SQ_STAYAWAY|SQ_EXCL|SQ_EVENTS))) {
			mutex_exit(sqciplock);
			sqciplock = NULL;
			goto slowlock;
		}
		mutex_exit(sdlock);
		(*sqcipcount)++;
		ASSERT(*sqcipcount != 0);
		queued = qp->q_sqflags & Q_SQQUEUED;
		mutex_exit(sqciplock);
	} else {
	slowlock:
		ASSERT(sqciplock == NULL);
		mutex_enter(SQLOCK(sq));
		mutex_exit(sdlock);
		flags = sq->sq_flags;
		/*
		 * We are going to drop SQLOCK, so make a claim to prevent syncq
		 * from closing.
		 */
		sq->sq_count++;
		ASSERT(sq->sq_count != 0);		/* Wraparound */
		/*
		 * If there are writers or exclusive waiters, there is not much
		 * we can do.  Place the message on the syncq and schedule a
		 * background thread to drain it.
		 *
		 * Also if we are approaching end of stack, fill the syncq and
		 * switch processing to a background thread - see comments on
		 * top.
		 */
		if ((flags & (SQ_STAYAWAY|SQ_EXCL|SQ_EVENTS)) ||
		    (sq->sq_needexcl != 0) || PUT_STACK_NOTENOUGH()) {

			TRACE_3(TR_FAC_STREAMS_FR, TR_PUTNEXT_END,
			    "putnext_end:(%p, %p, %p) SQ_EXCL fill",
			    qp, mp, sq);

			/*
			 * NOTE: qfill_syncq will need QLOCK. It is safe to drop
			 * SQLOCK because positive sq_count keeps the syncq from
			 * closing.
			 */
			mutex_exit(SQLOCK(sq));

			qfill_syncq(sq, qp, mp);
			/*
			 * NOTE: after the call to qfill_syncq() qp may be
			 * closed, both qp and sq should not be referenced at
			 * this point.
			 *
			 * This ASSERT is located here to prevent stack frame
			 * consumption in the DEBUG code.
			 */
			ASSERT(sqciplock == NULL);
			return;
		}

		queued = qp->q_sqflags & Q_SQQUEUED;
		/*
		 * If not a concurrent perimiter, we need to acquire
		 * it exclusively.  It could not have been previously
		 * set since we held the SQLOCK before testing
		 * SQ_GOAWAY above (which includes SQ_EXCL).
		 * We do this here because we hold the SQLOCK, and need
		 * to make this state change BEFORE dropping it.
		 */
		if (!(flags & SQ_CIPUT)) {
			ASSERT((sq->sq_flags & SQ_EXCL) == 0);
			ASSERT(!(sq->sq_type & SQ_CIPUT));
			sq->sq_flags |= SQ_EXCL;
		}
		mutex_exit(SQLOCK(sq));
	}

	ASSERT((sq->sq_flags & (SQ_EXCL|SQ_CIPUT)));
	ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));

	/*
	 * We now have a claim on the syncq, we are either going to
	 * put the message on the syncq and then drain it, or we are
	 * going to call the putproc().
	 */
	putproc = qi->qi_putp;
	if (!queued) {
		STR_FTEVENT_MSG(mp, fqp, FTEV_PUTNEXT, mp->b_rptr -
		    mp->b_datap->db_base);
		(*putproc)(qp, mp);
		ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
		ASSERT(MUTEX_NOT_HELD(QLOCK(qp)));
	} else {
		mutex_enter(QLOCK(qp));
		/*
		 * If there are no messages in front of us, just call putproc(),
		 * otherwise enqueue the message and drain the queue.
		 */
		if (qp->q_syncqmsgs == 0) {
			mutex_exit(QLOCK(qp));
			STR_FTEVENT_MSG(mp, fqp, FTEV_PUTNEXT, mp->b_rptr -
			    mp->b_datap->db_base);
			(*putproc)(qp, mp);
			ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
		} else {
			/*
			 * We are doing a fill with the intent to
			 * drain (meaning we are filling because
			 * there are messages in front of us ane we
			 * need to preserve message ordering)
			 * Therefore, put the message on the queue
			 * and call qdrain_syncq (must be done with
			 * the QLOCK held).
			 */
			STR_FTEVENT_MSG(mp, fqp, FTEV_PUTNEXT,
			    mp->b_rptr - mp->b_datap->db_base);

#ifdef DEBUG
			/*
			 * These two values were in the original code for
			 * all syncq messages.  This is unnecessary in
			 * the current implementation, but was retained
			 * in debug mode as it is usefull to know where
			 * problems occur.
			 */
			mp->b_queue = qp;
			mp->b_prev = (mblk_t *)putproc;
#endif
			SQPUT_MP(qp, mp);
			qdrain_syncq(sq, qp);
			ASSERT(MUTEX_NOT_HELD(QLOCK(qp)));
		}
	}
	/*
	 * Before we release our claim, we need to see if any
	 * events were posted. If the syncq is SQ_EXCL && SQ_QUEUED,
	 * we were responsible for going exclusive and, therefore,
	 * are resposible for draining.
	 */
	if (sq->sq_flags & (SQ_EXCL)) {
		drain_mask = 0;
	} else {
		drain_mask = SQ_QUEUED;
	}

	if (sqciplock != NULL) {
		mutex_enter(sqciplock);
		flags = sq->sq_flags;
		ASSERT(flags & SQ_CIPUT);
		/* SQ_EXCL could have been set by qwriter_inner */
		if ((flags & (SQ_EXCL|SQ_TAIL)) || sq->sq_needexcl) {
			/*
			 * we need SQLOCK to handle
			 * wakeups/drains/flags change.  sqciplock
			 * is needed to decrement sqcipcount.
			 * SQLOCK has to be grabbed before sqciplock
			 * for lock ordering purposes.
			 * after sqcipcount is decremented some lock
			 * still needs to be held to make sure
			 * syncq won't get freed on us.
			 *
			 * To prevent deadlocks we try to grab SQLOCK and if it
			 * is held already we drop sqciplock, acquire SQLOCK and
			 * reacqwire sqciplock again.
			 */
			if (mutex_tryenter(SQLOCK(sq)) == 0) {
				mutex_exit(sqciplock);
				mutex_enter(SQLOCK(sq));
				mutex_enter(sqciplock);
			}
			flags = sq->sq_flags;
			ASSERT(*sqcipcount != 0);
			(*sqcipcount)--;
			mutex_exit(sqciplock);
		} else {
			ASSERT(*sqcipcount != 0);
			(*sqcipcount)--;
			mutex_exit(sqciplock);
			TRACE_3(TR_FAC_STREAMS_FR, TR_PUTNEXT_END,
			"putnext_end:(%p, %p, %p) done", qp, mp, sq);
			return;
		}
	} else {
		mutex_enter(SQLOCK(sq));
		flags = sq->sq_flags;
		ASSERT(sq->sq_count != 0);
		sq->sq_count--;
	}
	if ((flags & (SQ_TAIL)) || sq->sq_needexcl) {
		putnext_tail(sq, qp, (flags & ~drain_mask));
		/*
		 * The only purpose of this ASSERT is to preserve calling stack
		 * in DEBUG kernel.
		 */
		ASSERT(sq != NULL);
		return;
	}
	ASSERT((sq->sq_flags & (SQ_EXCL|SQ_CIPUT)) || queued);
	ASSERT((flags & (SQ_EXCL|SQ_CIPUT)) || queued);
	/*
	 * Safe to always drop SQ_EXCL:
	 *	Not SQ_CIPUT means we set SQ_EXCL above
	 *	For SQ_CIPUT SQ_EXCL will only be set if the put
	 *	procedure did a qwriter(INNER) in which case
	 *	nobody else is in the inner perimeter and we
	 *	are exiting.
	 *
	 * I would like to make the following assertion:
	 *
	 * ASSERT((flags & (SQ_EXCL|SQ_CIPUT)) != (SQ_EXCL|SQ_CIPUT) ||
	 * 	sq->sq_count == 0);
	 *
	 * which indicates that if we are both putshared and exclusive,
	 * we became exclusive while executing the putproc, and the only
	 * claim on the syncq was the one we dropped a few lines above.
	 * But other threads that enter putnext while the syncq is exclusive
	 * need to make a claim as they may need to drop SQLOCK in the
	 * has_writers case to avoid deadlocks.  If these threads are
	 * delayed or preempted, it is possible that the writer thread can
	 * find out that there are other claims making the (sq_count == 0)
	 * test invalid.
	 */

	sq->sq_flags = flags & ~SQ_EXCL;
	mutex_exit(SQLOCK(sq));
	TRACE_3(TR_FAC_STREAMS_FR, TR_PUTNEXT_END,
	    "putnext_end:(%p, %p, %p) done", qp, mp, sq);
}


/*
 * wrapper for qi_putp entry in module ops vec.
 * implements asynchronous putnext().
 * Note, that unlike putnext(), this routine is NOT optimized for the
 * fastpath.  Calling this routine will grab whatever locks are necessary
 * to protect the stream head, q_next, and syncq's.
 * And since it is in the normal locks path, we do not use putlocks if
 * they exist (though this can be changed by swapping the value of
 * UseFastlocks).
 */
void
put(queue_t *qp, mblk_t *mp)
{
	queue_t		*fqp = qp; /* For strft tracing */
	syncq_t		*sq;
	uint16_t	flags;
	uint16_t	drain_mask;
	struct qinit	*qi;
	int		(*putproc)();
	int		ix;
	boolean_t	queued = B_FALSE;
	kmutex_t	*sqciplock = NULL;
	ushort_t	*sqcipcount = NULL;

	TRACE_2(TR_FAC_STREAMS_FR, TR_PUT_START,
	    "put:(%X, %X)", qp, mp);
	ASSERT(mp->b_datap->db_ref != 0);
	ASSERT(mp->b_next == NULL && mp->b_prev == NULL);

	sq = qp->q_syncq;
	ASSERT(sq != NULL);
	qi = qp->q_qinfo;

	if (UseFastlocks && sq->sq_ciputctrl != NULL) {
		/* fastlock: */
		ASSERT(sq->sq_flags & SQ_CIPUT);
		ix = CPU->cpu_seqid & sq->sq_nciputctrl;
		sqciplock = &sq->sq_ciputctrl[ix].ciputctrl_lock;
		sqcipcount = &sq->sq_ciputctrl[ix].ciputctrl_count;
		mutex_enter(sqciplock);
		if (!((*sqcipcount) & SQ_FASTPUT) ||
		    (sq->sq_flags & (SQ_STAYAWAY|SQ_EXCL|SQ_EVENTS))) {
			mutex_exit(sqciplock);
			sqciplock = NULL;
			goto slowlock;
		}
		(*sqcipcount)++;
		ASSERT(*sqcipcount != 0);
		queued = qp->q_sqflags & Q_SQQUEUED;
		mutex_exit(sqciplock);
	} else {
	slowlock:
		ASSERT(sqciplock == NULL);
		mutex_enter(SQLOCK(sq));
		flags = sq->sq_flags;
		/*
		 * We are going to drop SQLOCK, so make a claim to prevent syncq
		 * from closing.
		 */
		sq->sq_count++;
		ASSERT(sq->sq_count != 0);		/* Wraparound */
		/*
		 * If there are writers or exclusive waiters, there is not much
		 * we can do.  Place the message on the syncq and schedule a
		 * background thread to drain it.
		 *
		 * Also if we are approaching end of stack, fill the syncq and
		 * switch processing to a background thread - see comments on
		 * top.
		 */
		if ((flags & (SQ_STAYAWAY|SQ_EXCL|SQ_EVENTS)) ||
		    (sq->sq_needexcl != 0) || PUT_STACK_NOTENOUGH()) {

			TRACE_3(TR_FAC_STREAMS_FR, TR_PUTNEXT_END,
			    "putnext_end:(%p, %p, %p) SQ_EXCL fill",
			    qp, mp, sq);

			/*
			 * NOTE: qfill_syncq will need QLOCK. It is safe to drop
			 * SQLOCK because positive sq_count keeps the syncq from
			 * closing.
			 */
			mutex_exit(SQLOCK(sq));

			qfill_syncq(sq, qp, mp);
			/*
			 * NOTE: after the call to qfill_syncq() qp may be
			 * closed, both qp and sq should not be referenced at
			 * this point.
			 *
			 * This ASSERT is located here to prevent stack frame
			 * consumption in the DEBUG code.
			 */
			ASSERT(sqciplock == NULL);
			return;
		}

		queued = qp->q_sqflags & Q_SQQUEUED;
		/*
		 * If not a concurrent perimiter, we need to acquire
		 * it exclusively.  It could not have been previously
		 * set since we held the SQLOCK before testing
		 * SQ_GOAWAY above (which includes SQ_EXCL).
		 * We do this here because we hold the SQLOCK, and need
		 * to make this state change BEFORE dropping it.
		 */
		if (!(flags & SQ_CIPUT)) {
			ASSERT((sq->sq_flags & SQ_EXCL) == 0);
			ASSERT(!(sq->sq_type & SQ_CIPUT));
			sq->sq_flags |= SQ_EXCL;
		}
		mutex_exit(SQLOCK(sq));
	}

	ASSERT((sq->sq_flags & (SQ_EXCL|SQ_CIPUT)));
	ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));

	/*
	 * We now have a claim on the syncq, we are either going to
	 * put the message on the syncq and then drain it, or we are
	 * going to call the putproc().
	 */
	putproc = qi->qi_putp;
	if (!queued) {
		STR_FTEVENT_MSG(mp, fqp, FTEV_PUTNEXT, mp->b_rptr -
		    mp->b_datap->db_base);
		(*putproc)(qp, mp);
		ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
		ASSERT(MUTEX_NOT_HELD(QLOCK(qp)));
	} else {
		mutex_enter(QLOCK(qp));
		/*
		 * If there are no messages in front of us, just call putproc(),
		 * otherwise enqueue the message and drain the queue.
		 */
		if (qp->q_syncqmsgs == 0) {
			mutex_exit(QLOCK(qp));
			STR_FTEVENT_MSG(mp, fqp, FTEV_PUTNEXT, mp->b_rptr -
			    mp->b_datap->db_base);
			(*putproc)(qp, mp);
			ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
		} else {
			/*
			 * We are doing a fill with the intent to
			 * drain (meaning we are filling because
			 * there are messages in front of us ane we
			 * need to preserve message ordering)
			 * Therefore, put the message on the queue
			 * and call qdrain_syncq (must be done with
			 * the QLOCK held).
			 */
			STR_FTEVENT_MSG(mp, fqp, FTEV_PUTNEXT,
			    mp->b_rptr - mp->b_datap->db_base);

#ifdef DEBUG
			/*
			 * These two values were in the original code for
			 * all syncq messages.  This is unnecessary in
			 * the current implementation, but was retained
			 * in debug mode as it is usefull to know where
			 * problems occur.
			 */
			mp->b_queue = qp;
			mp->b_prev = (mblk_t *)putproc;
#endif
			SQPUT_MP(qp, mp);
			qdrain_syncq(sq, qp);
			ASSERT(MUTEX_NOT_HELD(QLOCK(qp)));
		}
	}
	/*
	 * Before we release our claim, we need to see if any
	 * events were posted. If the syncq is SQ_EXCL && SQ_QUEUED,
	 * we were responsible for going exclusive and, therefore,
	 * are resposible for draining.
	 */
	if (sq->sq_flags & (SQ_EXCL)) {
		drain_mask = 0;
	} else {
		drain_mask = SQ_QUEUED;
	}

	if (sqciplock != NULL) {
		mutex_enter(sqciplock);
		flags = sq->sq_flags;
		ASSERT(flags & SQ_CIPUT);
		/* SQ_EXCL could have been set by qwriter_inner */
		if ((flags & (SQ_EXCL|SQ_TAIL)) || sq->sq_needexcl) {
			/*
			 * we need SQLOCK to handle
			 * wakeups/drains/flags change.  sqciplock
			 * is needed to decrement sqcipcount.
			 * SQLOCK has to be grabbed before sqciplock
			 * for lock ordering purposes.
			 * after sqcipcount is decremented some lock
			 * still needs to be held to make sure
			 * syncq won't get freed on us.
			 *
			 * To prevent deadlocks we try to grab SQLOCK and if it
			 * is held already we drop sqciplock, acquire SQLOCK and
			 * reacqwire sqciplock again.
			 */
			if (mutex_tryenter(SQLOCK(sq)) == 0) {
				mutex_exit(sqciplock);
				mutex_enter(SQLOCK(sq));
				mutex_enter(sqciplock);
			}
			flags = sq->sq_flags;
			ASSERT(*sqcipcount != 0);
			(*sqcipcount)--;
			mutex_exit(sqciplock);
		} else {
			ASSERT(*sqcipcount != 0);
			(*sqcipcount)--;
			mutex_exit(sqciplock);
			TRACE_3(TR_FAC_STREAMS_FR, TR_PUTNEXT_END,
			"putnext_end:(%p, %p, %p) done", qp, mp, sq);
			return;
		}
	} else {
		mutex_enter(SQLOCK(sq));
		flags = sq->sq_flags;
		ASSERT(sq->sq_count != 0);
		sq->sq_count--;
	}
	if ((flags & (SQ_TAIL)) || sq->sq_needexcl) {
		putnext_tail(sq, qp, (flags & ~drain_mask));
		/*
		 * The only purpose of this ASSERT is to preserve calling stack
		 * in DEBUG kernel.
		 */
		ASSERT(sq != NULL);
		return;
	}
	ASSERT((sq->sq_flags & (SQ_EXCL|SQ_CIPUT)) || queued);
	ASSERT((flags & (SQ_EXCL|SQ_CIPUT)) || queued);
	/*
	 * Safe to always drop SQ_EXCL:
	 *	Not SQ_CIPUT means we set SQ_EXCL above
	 *	For SQ_CIPUT SQ_EXCL will only be set if the put
	 *	procedure did a qwriter(INNER) in which case
	 *	nobody else is in the inner perimeter and we
	 *	are exiting.
	 *
	 * I would like to make the following assertion:
	 *
	 * ASSERT((flags & (SQ_EXCL|SQ_CIPUT)) != (SQ_EXCL|SQ_CIPUT) ||
	 * 	sq->sq_count == 0);
	 *
	 * which indicates that if we are both putshared and exclusive,
	 * we became exclusive while executing the putproc, and the only
	 * claim on the syncq was the one we dropped a few lines above.
	 * But other threads that enter putnext while the syncq is exclusive
	 * need to make a claim as they may need to drop SQLOCK in the
	 * has_writers case to avoid deadlocks.  If these threads are
	 * delayed or preempted, it is possible that the writer thread can
	 * find out that there are other claims making the (sq_count == 0)
	 * test invalid.
	 */

	sq->sq_flags = flags & ~SQ_EXCL;
	mutex_exit(SQLOCK(sq));
	TRACE_3(TR_FAC_STREAMS_FR, TR_PUTNEXT_END,
	    "putnext_end:(%p, %p, %p) done", qp, mp, sq);
}
