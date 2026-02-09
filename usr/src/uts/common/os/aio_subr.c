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
 * Copyright 2026 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <vm/as.h>
#include <vm/page.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/aio_impl.h>
#include <sys/epm.h>
#include <sys/fs/snode.h>
#include <sys/siginfo.h>
#include <sys/cpuvar.h>
#include <sys/conf.h>
#include <sys/sdt.h>

int aphysio(int (*)(), int (*)(), dev_t, int, void (*)(), struct aio_req *);
int aio_done(struct buf *);
void aphysio_unlock(aio_req_t *);
void aio_cleanup(int);
void aio_cleanup_exit(void);

/*
 * private functions
 */
static void aio_sigev_send(proc_t *, sigqueue_t *);
static void aio_hash_delete(aio_t *, aio_req_t *);
static void aio_lio_free(aio_t *, aio_lio_t *);
static int aio_cleanup_cleanupq(aio_t *, aio_req_t *, int);
static int aio_cleanup_notifyq(aio_t *, aio_req_t *, int);
static void aio_cleanup_pollq(aio_t *, aio_req_t *, int);
static void aio_cleanup_portq(aio_t *, aio_req_t *, int);

/*
 * async version of physio() that doesn't wait synchronously
 * for the driver's strategy routine to complete.
 */

int
aphysio(
	int (*strategy)(struct buf *),
	int (*cancel)(struct buf *),
	dev_t dev,
	int rw,
	void (*mincnt)(struct buf *),
	struct aio_req *aio)
{
	struct uio *uio = aio->aio_uio;
	aio_req_t *reqp = (aio_req_t *)aio->aio_private;
	struct buf *bp = &reqp->aio_req_buf;
	struct iovec *iov;
	struct as *as;
	char *a;
	int	error;
	size_t	c;
	struct page **pplist;
	struct dev_ops *ops = devopsp[getmajor(dev)];

	if (uio->uio_loffset < 0)
		return (EINVAL);
#ifdef	_ILP32
	/*
	 * For 32-bit kernels, check against SPEC_MAXOFFSET_T which represents
	 * the maximum size that can be supported by the IO subsystem.
	 * XXX this code assumes a D_64BIT driver.
	 */
	if (uio->uio_loffset > SPEC_MAXOFFSET_T)
		return (EINVAL);
#endif	/* _ILP32 */

	if (rw == B_READ) {
		CPU_STATS_ADD_K(sys, phread, 1);
	} else {
		CPU_STATS_ADD_K(sys, phwrite, 1);
	}

	iov = uio->uio_iov;
	sema_init(&bp->b_sem, 0, NULL, SEMA_DEFAULT, NULL);
	sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);

	bp->b_error = 0;
	bp->b_flags = B_BUSY | B_PHYS | B_ASYNC | rw;
	bp->b_edev = dev;
	bp->b_dev = cmpdev(dev);
	bp->b_lblkno = btodt(uio->uio_loffset);
	bp->b_offset = uio->uio_loffset;
	(void) ops->devo_getinfo(NULL, DDI_INFO_DEVT2DEVINFO,
	    (void *)bp->b_edev, (void **)&bp->b_dip);

	/*
	 * Clustering: Clustering can set the b_iodone, b_forw and
	 * b_proc fields to cluster-specifc values.
	 */
	if (bp->b_iodone == NULL) {
		bp->b_iodone = aio_done;
		/* b_forw points at an aio_req_t structure */
		bp->b_forw = (struct buf *)reqp;
		bp->b_proc = curproc;
	}

	a = bp->b_un.b_addr = iov->iov_base;
	c = bp->b_bcount = iov->iov_len;

	(*mincnt)(bp);
	if (bp->b_bcount != iov->iov_len)
		return (ENOTSUP);

	as = bp->b_proc->p_as;

	error = as_pagelock(as, &pplist, a,
	    c, rw == B_READ? S_WRITE : S_READ);
	if (error != 0) {
		bp->b_flags |= B_ERROR;
		bp->b_error = error;
		bp->b_flags &= ~(B_BUSY|B_WANTED|B_PHYS|B_SHADOW);
		return (error);
	}
	reqp->aio_req_flags |= AIO_PAGELOCKDONE;
	bp->b_shadow = pplist;
	if (pplist != NULL) {
		bp->b_flags |= B_SHADOW;
	}

	if (cancel != anocancel)
		cmn_err(CE_PANIC,
		    "aphysio: cancellation not supported, use anocancel");

	reqp->aio_req_cancel = cancel;

	DTRACE_IO1(start, struct buf *, bp);

	return ((*strategy)(bp));
}

/*ARGSUSED*/
int
anocancel(struct buf *bp)
{
	return (ENXIO);
}

/*
 * Called from biodone().
 * Notify process that a pending AIO has finished.
 */

/*
 * Clustering: This function is made non-static as it is used
 * by clustering s/w as contract private interface.
 */

int
aio_done(struct buf *bp)
{
	proc_t *p;
	struct as *as;
	aio_req_t *reqp;
	aio_lio_t *head = NULL;
	aio_t *aiop;
	sigqueue_t *sigev = NULL;
	sigqueue_t *lio_sigev = NULL;
	port_kevent_t *pkevp = NULL;
	port_kevent_t *lio_pkevp = NULL;
	int fd;
	int cleanupqflag;
	int pollqflag;
	int portevpend;
	void (*func)();
	int use_port = 0;
	int reqp_flags = 0;
	int send_signal = 0;

	p = bp->b_proc;
	as = p->p_as;
	reqp = (aio_req_t *)bp->b_forw;
	fd = reqp->aio_req_fd;

	/*
	 * mapout earlier so that more kmem is available when aio is
	 * heavily used. bug #1262082
	 */
	if (bp->b_flags & B_REMAPPED)
		bp_mapout(bp);

	/* decrement fd's ref count by one, now that aio request is done. */
	areleasef(fd, P_FINFO(p));

	aiop = p->p_aio;
	ASSERT(aiop != NULL);

	mutex_enter(&aiop->aio_portq_mutex);
	mutex_enter(&aiop->aio_mutex);
	ASSERT(aiop->aio_pending > 0);
	ASSERT(reqp->aio_req_flags & AIO_PENDING);
	aiop->aio_pending--;
	reqp->aio_req_flags &= ~AIO_PENDING;
	reqp_flags = reqp->aio_req_flags;
	if ((pkevp = reqp->aio_req_portkev) != NULL) {
		/* Event port notification is desired for this transaction */
		if (reqp->aio_req_flags & AIO_CLOSE_PORT) {
			/*
			 * The port is being closed and it is waiting for
			 * pending asynchronous I/O transactions to complete.
			 */
			portevpend = --aiop->aio_portpendcnt;
			aio_deq(&aiop->aio_portpending, reqp);
			aio_enq(&aiop->aio_portq, reqp, 0);
			mutex_exit(&aiop->aio_mutex);
			mutex_exit(&aiop->aio_portq_mutex);
			port_send_event(pkevp);
			if (portevpend == 0)
				cv_broadcast(&aiop->aio_portcv);
			return (0);
		}

		if (aiop->aio_flags & AIO_CLEANUP) {
			/*
			 * aio_cleanup_thread() is waiting for completion of
			 * transactions.
			 */
			mutex_enter(&as->a_contents);
			aio_deq(&aiop->aio_portpending, reqp);
			aio_enq(&aiop->aio_portcleanupq, reqp, 0);
			cv_signal(&aiop->aio_cleanupcv);
			mutex_exit(&as->a_contents);
			mutex_exit(&aiop->aio_mutex);
			mutex_exit(&aiop->aio_portq_mutex);
			return (0);
		}

		aio_deq(&aiop->aio_portpending, reqp);
		aio_enq(&aiop->aio_portq, reqp, 0);

		use_port = 1;
	} else {
		/*
		 * when the AIO_CLEANUP flag is enabled for this
		 * process, or when the AIO_POLL bit is set for
		 * this request, special handling is required.
		 * otherwise the request is put onto the doneq.
		 */
		cleanupqflag = (aiop->aio_flags & AIO_CLEANUP);
		pollqflag = (reqp->aio_req_flags & AIO_POLL);
		if (cleanupqflag | pollqflag) {

			if (cleanupqflag)
				mutex_enter(&as->a_contents);

			/*
			 * requests with their AIO_POLL bit set are put
			 * on the pollq, requests with sigevent structures
			 * or with listio heads are put on the notifyq, and
			 * the remaining requests don't require any special
			 * cleanup handling, so they're put onto the default
			 * cleanupq.
			 */
			if (pollqflag)
				aio_enq(&aiop->aio_pollq, reqp, AIO_POLLQ);
			else if (reqp->aio_req_sigqp || reqp->aio_req_lio)
				aio_enq(&aiop->aio_notifyq, reqp, AIO_NOTIFYQ);
			else
				aio_enq(&aiop->aio_cleanupq, reqp,
				    AIO_CLEANUPQ);

			if (cleanupqflag) {
				cv_signal(&aiop->aio_cleanupcv);
				mutex_exit(&as->a_contents);
				mutex_exit(&aiop->aio_mutex);
				mutex_exit(&aiop->aio_portq_mutex);
			} else {
				ASSERT(pollqflag);
				/* block aio_cleanup_exit until we're done */
				aiop->aio_done_cnt++;
				mutex_exit(&aiop->aio_mutex);
				mutex_exit(&aiop->aio_portq_mutex);
				/*
				 * let the cleanup processing happen from an AST
				 * set an AST on all threads in this process
				 */
				mutex_enter(&p->p_lock);
				set_proc_ast(p);
				mutex_exit(&p->p_lock);
				mutex_enter(&aiop->aio_mutex);
				/* wake up anybody waiting in aiowait() */
				cv_broadcast(&aiop->aio_waitcv);

				/* wake up aio_cleanup_exit if needed */
				ASSERT3U(aiop->aio_done_cnt, >, 0);
				aiop->aio_done_cnt--;
				if ((aiop->aio_flags & AIO_CLEANUP) &&
				    aiop->aio_done_cnt == 0) {
					cv_signal(&aiop->aio_cleanupcv);
				}
				mutex_exit(&aiop->aio_mutex);
			}
			return (0);
		}

		/*
		 * save req's sigevent pointer, and check its
		 * value after releasing aio_mutex lock.
		 */
		sigev = reqp->aio_req_sigqp;
		reqp->aio_req_sigqp = NULL;

		/* put request on done queue. */
		aio_enq(&aiop->aio_doneq, reqp, AIO_DONEQ);
	} /* portkevent */

	/*
	 * when list IO notification is enabled, a notification or
	 * signal is sent only when all entries in the list are done.
	 */
	if ((head = reqp->aio_req_lio) != NULL) {
		ASSERT(head->lio_refcnt > 0);
		if (--head->lio_refcnt == 0) {
			/*
			 * save lio's sigevent pointer, and check
			 * its value after releasing aio_mutex lock.
			 */
			lio_sigev = head->lio_sigqp;
			head->lio_sigqp = NULL;
			cv_signal(&head->lio_notify);
			if (head->lio_port >= 0 &&
			    (lio_pkevp = head->lio_portkev) != NULL)
				head->lio_port = -1;
		}
	}

	/*
	 * if AIO_WAITN set then
	 * send signal only when we reached the
	 * required amount of IO's finished
	 * or when all IO's are done
	 */
	if (aiop->aio_flags & AIO_WAITN) {
		if (aiop->aio_waitncnt > 0)
			aiop->aio_waitncnt--;
		if (aiop->aio_pending == 0 ||
		    aiop->aio_waitncnt == 0)
			cv_broadcast(&aiop->aio_waitcv);
	} else {
		cv_broadcast(&aiop->aio_waitcv);
	}

	/*
	 * No need to set this flag for pollq, portq, lio requests.
	 * If this is an old Solaris aio request, and the process has
	 * a SIGIO signal handler enabled, then send a SIGIO signal.
	 */
	if (!sigev && !use_port && head == NULL &&
	    (reqp->aio_req_flags & AIO_SOLARIS) &&
	    (func = PTOU(p)->u_signal[SIGIO - 1]) != SIG_DFL &&
	    (func != SIG_IGN)) {
		send_signal = 1;
		reqp->aio_req_flags |= AIO_SIGNALLED;
	}

	mutex_exit(&aiop->aio_mutex);
	mutex_exit(&aiop->aio_portq_mutex);

	/*
	 * Could the cleanup thread be waiting for AIO with locked
	 * resources to finish?
	 * Ideally in that case cleanup thread should block on cleanupcv,
	 * but there is a window, where it could miss to see a new aio
	 * request that sneaked in.
	 */
	mutex_enter(&as->a_contents);
	if ((reqp_flags & AIO_PAGELOCKDONE) && AS_ISUNMAPWAIT(as))
		cv_broadcast(&as->a_cv);
	mutex_exit(&as->a_contents);

	if (sigev)
		aio_sigev_send(p, sigev);
	else if (send_signal)
		psignal(p, SIGIO);

	if (pkevp)
		port_send_event(pkevp);
	if (lio_sigev)
		aio_sigev_send(p, lio_sigev);
	if (lio_pkevp)
		port_send_event(lio_pkevp);

	return (0);
}

/*
 * send a queued signal to the specified process when
 * the event signal is non-NULL. A return value of 1
 * will indicate that a signal is queued, and 0 means that
 * no signal was specified, nor sent.
 */
static void
aio_sigev_send(proc_t *p, sigqueue_t *sigev)
{
	ASSERT(sigev != NULL);

	mutex_enter(&p->p_lock);
	sigaddqa(p, NULL, sigev);
	mutex_exit(&p->p_lock);
}

/*
 * special case handling for zero length requests. the aio request
 * short circuits the normal completion path since all that's required
 * to complete this request is to copyout a zero to the aio request's
 * return value.
 */
void
aio_zerolen(aio_req_t *reqp)
{

	struct buf *bp = &reqp->aio_req_buf;

	reqp->aio_req_flags |= AIO_ZEROLEN;

	bp->b_forw = (struct buf *)reqp;
	bp->b_proc = curproc;

	bp->b_resid = 0;
	bp->b_flags = 0;

	aio_done(bp);
}

/*
 * unlock pages previously locked by as_pagelock
 */
void
aphysio_unlock(aio_req_t *reqp)
{
	struct buf *bp;
	struct iovec *iov;
	int flags;

	if (reqp->aio_req_flags & AIO_PHYSIODONE)
		return;

	reqp->aio_req_flags |= AIO_PHYSIODONE;

	if (reqp->aio_req_flags & AIO_ZEROLEN)
		return;

	bp = &reqp->aio_req_buf;
	iov = reqp->aio_req_uio.uio_iov;
	flags = (((bp->b_flags & B_READ) == B_READ) ? S_WRITE : S_READ);
	if (reqp->aio_req_flags & AIO_PAGELOCKDONE) {
		as_pageunlock(bp->b_proc->p_as,
		    bp->b_flags & B_SHADOW ? bp->b_shadow : NULL,
		    iov->iov_base, iov->iov_len, flags);
		reqp->aio_req_flags &= ~AIO_PAGELOCKDONE;
	}
	bp->b_flags &= ~(B_BUSY|B_WANTED|B_PHYS|B_SHADOW);
	bp->b_flags |= B_DONE;
}

/*
 * deletes a requests id from the hash table of outstanding io.
 */
static void
aio_hash_delete(aio_t *aiop, struct aio_req_t *reqp)
{
	long index;
	aio_result_t *resultp = reqp->aio_req_resultp;
	aio_req_t *current;
	aio_req_t **nextp;

	index = AIO_HASH(resultp);
	nextp = (aiop->aio_hash + index);
	while ((current = *nextp) != NULL) {
		if (current->aio_req_resultp == resultp) {
			*nextp = current->aio_hash_next;
			return;
		}
		nextp = &current->aio_hash_next;
	}
}

/*
 * Put a list head struct onto its free list.
 */
static void
aio_lio_free(aio_t *aiop, aio_lio_t *head)
{
	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	if (head->lio_sigqp != NULL)
		kmem_free(head->lio_sigqp, sizeof (sigqueue_t));
	head->lio_next = aiop->aio_lio_free;
	aiop->aio_lio_free = head;
}

/*
 * Put a reqp onto the freelist.
 */
void
aio_req_free(aio_t *aiop, aio_req_t *reqp)
{
	aio_lio_t *liop;

	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	if (reqp->aio_req_portkev) {
		port_free_event(reqp->aio_req_portkev);
		reqp->aio_req_portkev = NULL;
	}

	if ((liop = reqp->aio_req_lio) != NULL) {
		if (--liop->lio_nent == 0)
			aio_lio_free(aiop, liop);
		reqp->aio_req_lio = NULL;
	}
	if (reqp->aio_req_sigqp != NULL) {
		kmem_free(reqp->aio_req_sigqp, sizeof (sigqueue_t));
		reqp->aio_req_sigqp = NULL;
	}
	reqp->aio_req_next = aiop->aio_free;
	reqp->aio_req_prev = NULL;
	aiop->aio_free = reqp;
	aiop->aio_outstanding--;
	if (aiop->aio_outstanding == 0)
		cv_broadcast(&aiop->aio_waitcv);
	aio_hash_delete(aiop, reqp);
}

/*
 * Put a reqp onto the freelist.
 */
void
aio_req_free_port(aio_t *aiop, aio_req_t *reqp)
{
	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	reqp->aio_req_next = aiop->aio_free;
	reqp->aio_req_prev = NULL;
	aiop->aio_free = reqp;
	aiop->aio_outstanding--;
	aio_hash_delete(aiop, reqp);
}


/*
 * Verify the integrity of a queue.
 */
#if defined(DEBUG)
static void
aio_verify_queue(aio_req_t *head, aio_req_t *entry_present,
    aio_req_t *entry_missing)
{
	aio_req_t *reqp;
	int found = 0;
	int present = 0;

	if ((reqp = head) != NULL) {
		do {
			ASSERT(reqp->aio_req_prev->aio_req_next == reqp);
			ASSERT(reqp->aio_req_next->aio_req_prev == reqp);
			if (entry_present == reqp)
				found++;
			if (entry_missing == reqp)
				present++;
		} while ((reqp = reqp->aio_req_next) != head);
	}
	ASSERT(entry_present == NULL || found == 1);
	ASSERT(entry_missing == NULL || present == 0);
}
#else
#define	aio_verify_queue(x, y, z)
#endif

/*
 * Put a request onto the tail of a queue.
 */
void
aio_enq(aio_req_t **qhead, aio_req_t *reqp, int qflg_new)
{
	aio_req_t *head;
	aio_req_t *prev;

	aio_verify_queue(*qhead, NULL, reqp);

	if ((head = *qhead) == NULL) {
		reqp->aio_req_next = reqp;
		reqp->aio_req_prev = reqp;
		*qhead = reqp;
	} else {
		reqp->aio_req_next = head;
		reqp->aio_req_prev = prev = head->aio_req_prev;
		prev->aio_req_next = reqp;
		head->aio_req_prev = reqp;
	}
	reqp->aio_req_flags |= qflg_new;
}

/*
 * Remove a request from its queue.
 */
void
aio_deq(aio_req_t **qhead, aio_req_t *reqp)
{
	aio_verify_queue(*qhead, reqp, NULL);

	if (reqp->aio_req_next == reqp) {
		*qhead = NULL;
	} else {
		reqp->aio_req_prev->aio_req_next = reqp->aio_req_next;
		reqp->aio_req_next->aio_req_prev = reqp->aio_req_prev;
		if (*qhead == reqp)
			*qhead = reqp->aio_req_next;
	}
	reqp->aio_req_next = NULL;
	reqp->aio_req_prev = NULL;
}

/*
 * concatenate a specified queue with the cleanupq. the specified
 * queue is put onto the tail of the cleanupq. all elements on the
 * specified queue should have their aio_req_flags field cleared.
 */
/*ARGSUSED*/
void
aio_cleanupq_concat(aio_t *aiop, aio_req_t *q2, int qflg)
{
	aio_req_t *cleanupqhead, *q2tail;
	aio_req_t *reqp = q2;

	do {
		ASSERT(reqp->aio_req_flags & qflg);
		reqp->aio_req_flags &= ~qflg;
		reqp->aio_req_flags |= AIO_CLEANUPQ;
	} while ((reqp = reqp->aio_req_next) != q2);

	cleanupqhead = aiop->aio_cleanupq;
	if (cleanupqhead == NULL)
		aiop->aio_cleanupq = q2;
	else {
		cleanupqhead->aio_req_prev->aio_req_next = q2;
		q2tail = q2->aio_req_prev;
		q2tail->aio_req_next = cleanupqhead;
		q2->aio_req_prev = cleanupqhead->aio_req_prev;
		cleanupqhead->aio_req_prev = q2tail;
	}
}

/*
 * cleanup aio requests that are on the per-process poll queue.
 */
void
aio_cleanup(int flag)
{
	aio_t *aiop = curproc->p_aio;
	aio_req_t *pollqhead, *cleanupqhead, *notifyqhead;
	aio_req_t *cleanupport;
	aio_req_t *portq = NULL;
	void (*func)();
	int signalled = 0;
	int qflag = 0;
	int exitflg;

	ASSERT(aiop != NULL);

	if (flag == AIO_CLEANUP_EXIT)
		exitflg = AIO_CLEANUP_EXIT;
	else
		exitflg = 0;

	/*
	 * We need to get the aio_cleanupq_mutex because we are calling
	 * aio_cleanup_cleanupq()
	 */
	mutex_enter(&aiop->aio_cleanupq_mutex);
	/*
	 * take all the requests off the cleanupq, the notifyq,
	 * and the pollq.
	 */
	mutex_enter(&aiop->aio_mutex);
	if ((cleanupqhead = aiop->aio_cleanupq) != NULL) {
		aiop->aio_cleanupq = NULL;
		qflag++;
	}
	if ((notifyqhead = aiop->aio_notifyq) != NULL) {
		aiop->aio_notifyq = NULL;
		qflag++;
	}
	if ((pollqhead = aiop->aio_pollq) != NULL) {
		aiop->aio_pollq = NULL;
		qflag++;
	}
	if (flag) {
		if ((portq = aiop->aio_portq) != NULL)
			qflag++;

		if ((cleanupport = aiop->aio_portcleanupq) != NULL) {
			aiop->aio_portcleanupq = NULL;
			qflag++;
		}
	}
	mutex_exit(&aiop->aio_mutex);

	/*
	 * return immediately if cleanupq, pollq, and
	 * notifyq are all empty. someone else must have
	 * emptied them.
	 */
	if (!qflag) {
		mutex_exit(&aiop->aio_cleanupq_mutex);
		return;
	}

	/*
	 * do cleanup for the various queues.
	 */
	if (cleanupqhead)
		signalled = aio_cleanup_cleanupq(aiop, cleanupqhead, exitflg);
	mutex_exit(&aiop->aio_cleanupq_mutex);
	if (notifyqhead)
		signalled = aio_cleanup_notifyq(aiop, notifyqhead, exitflg);
	if (pollqhead)
		aio_cleanup_pollq(aiop, pollqhead, exitflg);
	if (flag && (cleanupport || portq))
		aio_cleanup_portq(aiop, cleanupport, exitflg);

	if (exitflg)
		return;

	/*
	 * If we have an active aio_cleanup_thread it's possible for
	 * this routine to push something on to the done queue after
	 * an aiowait/aiosuspend thread has already decided to block.
	 * This being the case, we need a cv_broadcast here to wake
	 * these threads up. It is simpler and cleaner to do this
	 * broadcast here than in the individual cleanup routines.
	 */

	mutex_enter(&aiop->aio_mutex);
	/*
	 * If there has never been an old solaris aio request
	 * issued by this process, then do not send a SIGIO signal.
	 */
	if (!(aiop->aio_flags & AIO_SOLARIS_REQ))
		signalled = 1;
	cv_broadcast(&aiop->aio_waitcv);
	mutex_exit(&aiop->aio_mutex);

	/*
	 * Only if the process wasn't already signalled,
	 * determine if a SIGIO signal should be delievered.
	 */
	if (!signalled &&
	    (func = PTOU(curproc)->u_signal[SIGIO - 1]) != SIG_DFL &&
	    func != SIG_IGN)
		psignal(curproc, SIGIO);
}


/*
 * Do cleanup for every element of the port cleanup queue.
 */
static void
aio_cleanup_portq(aio_t *aiop, aio_req_t *cleanupq, int exitflag)
{
	aio_req_t	*reqp;
	aio_req_t	*next;
	aio_req_t	*headp;
	aio_lio_t	*liop;

	/* first check the portq */
	if (exitflag || ((aiop->aio_flags & AIO_CLEANUP_PORT) == 0)) {
		mutex_enter(&aiop->aio_mutex);
		if (aiop->aio_flags & AIO_CLEANUP)
			aiop->aio_flags |= AIO_CLEANUP_PORT;
		mutex_exit(&aiop->aio_mutex);

		/*
		 * It is not allowed to hold locks during aphysio_unlock().
		 * The aio_done() interrupt function will try to acquire
		 * aio_mutex and aio_portq_mutex.  Therefore we disconnect
		 * the portq list from the aiop for the duration of the
		 * aphysio_unlock() loop below.
		 */
		mutex_enter(&aiop->aio_portq_mutex);
		headp = aiop->aio_portq;
		aiop->aio_portq = NULL;
		mutex_exit(&aiop->aio_portq_mutex);
		if ((reqp = headp) != NULL) {
			do {
				next = reqp->aio_req_next;
				aphysio_unlock(reqp);
				if (exitflag) {
					mutex_enter(&aiop->aio_mutex);
					aio_req_free(aiop, reqp);
					mutex_exit(&aiop->aio_mutex);
				}
			} while ((reqp = next) != headp);
		}

		if (headp != NULL && exitflag == 0) {
			/* move unlocked requests back to the port queue */
			aio_req_t *newq;

			mutex_enter(&aiop->aio_portq_mutex);
			if ((newq = aiop->aio_portq) != NULL) {
				aio_req_t *headprev = headp->aio_req_prev;
				aio_req_t *newqprev = newq->aio_req_prev;

				headp->aio_req_prev = newqprev;
				newq->aio_req_prev = headprev;
				headprev->aio_req_next = newq;
				newqprev->aio_req_next = headp;
			}
			aiop->aio_portq = headp;
			cv_broadcast(&aiop->aio_portcv);
			mutex_exit(&aiop->aio_portq_mutex);
		}
	}

	/* now check the port cleanup queue */
	if ((reqp = cleanupq) == NULL)
		return;
	do {
		next = reqp->aio_req_next;
		aphysio_unlock(reqp);
		if (exitflag) {
			mutex_enter(&aiop->aio_mutex);
			aio_req_free(aiop, reqp);
			mutex_exit(&aiop->aio_mutex);
		} else {
			mutex_enter(&aiop->aio_portq_mutex);
			aio_enq(&aiop->aio_portq, reqp, 0);
			mutex_exit(&aiop->aio_portq_mutex);
			port_send_event(reqp->aio_req_portkev);
			if ((liop = reqp->aio_req_lio) != NULL) {
				int send_event = 0;

				mutex_enter(&aiop->aio_mutex);
				ASSERT(liop->lio_refcnt > 0);
				if (--liop->lio_refcnt == 0) {
					if (liop->lio_port >= 0 &&
					    liop->lio_portkev) {
						liop->lio_port = -1;
						send_event = 1;
					}
				}
				mutex_exit(&aiop->aio_mutex);
				if (send_event)
					port_send_event(liop->lio_portkev);
			}
		}
	} while ((reqp = next) != cleanupq);
}

/*
 * Do cleanup for every element of the cleanupq.
 */
static int
aio_cleanup_cleanupq(aio_t *aiop, aio_req_t *qhead, int exitflg)
{
	aio_req_t *reqp, *next;
	int signalled = 0;

	ASSERT(MUTEX_HELD(&aiop->aio_cleanupq_mutex));

	/*
	 * Since aio_req_done() or aio_req_find() use the HASH list to find
	 * the required requests, they could potentially take away elements
	 * if they are already done (AIO_DONEQ is set).
	 * The aio_cleanupq_mutex protects the queue for the duration of the
	 * loop from aio_req_done() and aio_req_find().
	 */
	if ((reqp = qhead) == NULL)
		return (0);
	do {
		ASSERT(reqp->aio_req_flags & AIO_CLEANUPQ);
		ASSERT(reqp->aio_req_portkev == NULL);
		next = reqp->aio_req_next;
		aphysio_unlock(reqp);
		mutex_enter(&aiop->aio_mutex);
		if (exitflg)
			aio_req_free(aiop, reqp);
		else
			aio_enq(&aiop->aio_doneq, reqp, AIO_DONEQ);
		if (!exitflg) {
			if (reqp->aio_req_flags & AIO_SIGNALLED)
				signalled++;
			else
				reqp->aio_req_flags |= AIO_SIGNALLED;
		}
		mutex_exit(&aiop->aio_mutex);
	} while ((reqp = next) != qhead);
	return (signalled);
}

/*
 * do cleanup for every element of the notify queue.
 */
static int
aio_cleanup_notifyq(aio_t *aiop, aio_req_t *qhead, int exitflg)
{
	aio_req_t *reqp, *next;
	aio_lio_t *liohead;
	sigqueue_t *sigev, *lio_sigev = NULL;
	int signalled = 0;

	if ((reqp = qhead) == NULL)
		return (0);
	do {
		ASSERT(reqp->aio_req_flags & AIO_NOTIFYQ);
		next = reqp->aio_req_next;
		aphysio_unlock(reqp);
		if (exitflg) {
			mutex_enter(&aiop->aio_mutex);
			aio_req_free(aiop, reqp);
			mutex_exit(&aiop->aio_mutex);
		} else {
			mutex_enter(&aiop->aio_mutex);
			aio_enq(&aiop->aio_doneq, reqp, AIO_DONEQ);
			sigev = reqp->aio_req_sigqp;
			reqp->aio_req_sigqp = NULL;
			if ((liohead = reqp->aio_req_lio) != NULL) {
				ASSERT(liohead->lio_refcnt > 0);
				if (--liohead->lio_refcnt == 0) {
					cv_signal(&liohead->lio_notify);
					lio_sigev = liohead->lio_sigqp;
					liohead->lio_sigqp = NULL;
				}
			}
			mutex_exit(&aiop->aio_mutex);
			if (sigev) {
				signalled++;
				aio_sigev_send(reqp->aio_req_buf.b_proc,
				    sigev);
			}
			if (lio_sigev) {
				signalled++;
				aio_sigev_send(reqp->aio_req_buf.b_proc,
				    lio_sigev);
			}
		}
	} while ((reqp = next) != qhead);

	return (signalled);
}

/*
 * Do cleanup for every element of the poll queue.
 */
static void
aio_cleanup_pollq(aio_t *aiop, aio_req_t *qhead, int exitflg)
{
	aio_req_t *reqp, *next;

	/*
	 * As no other threads should be accessing the queue at this point,
	 * it isn't necessary to hold aio_mutex while we traverse its elements.
	 */
	if ((reqp = qhead) == NULL)
		return;
	do {
		ASSERT(reqp->aio_req_flags & AIO_POLLQ);
		next = reqp->aio_req_next;
		aphysio_unlock(reqp);
		if (exitflg) {
			mutex_enter(&aiop->aio_mutex);
			aio_req_free(aiop, reqp);
			mutex_exit(&aiop->aio_mutex);
		} else {
			aio_copyout_result(reqp);
			mutex_enter(&aiop->aio_mutex);
			aio_enq(&aiop->aio_doneq, reqp, AIO_DONEQ);
			mutex_exit(&aiop->aio_mutex);
		}
	} while ((reqp = next) != qhead);
}

/*
 * called by exit(). waits for all outstanding kaio to finish
 * before the kaio resources are freed.
 */
void
aio_cleanup_exit(void)
{
	proc_t *p = curproc;
	aio_t *aiop = p->p_aio;
	aio_req_t *reqp, *next, *head;
	aio_lio_t *nxtlio, *liop;

	/*
	 * wait for all outstanding kaio to complete. process
	 * is now single-threaded; no other kaio requests can
	 * happen once aio_pending is zero.
	 */
	mutex_enter(&aiop->aio_mutex);
	aiop->aio_flags |= AIO_CLEANUP;
	while (aiop->aio_pending != 0 || aiop->aio_done_cnt > 0)
		cv_wait(&aiop->aio_cleanupcv, &aiop->aio_mutex);
	mutex_exit(&aiop->aio_mutex);

	/* cleanup the cleanup-thread queues. */
	aio_cleanup(AIO_CLEANUP_EXIT);

	/*
	 * Although this process is now single-threaded, we
	 * still need to protect ourselves against a race with
	 * aio_cleanup_dr_delete_memory().
	 */
	mutex_enter(&p->p_lock);

	/*
	 * free up the done queue's resources.
	 */
	if ((head = aiop->aio_doneq) != NULL) {
		aiop->aio_doneq = NULL;
		reqp = head;
		do {
			next = reqp->aio_req_next;
			aphysio_unlock(reqp);
			kmem_free(reqp, sizeof (struct aio_req_t));
		} while ((reqp = next) != head);
	}
	/*
	 * release aio request freelist.
	 */
	for (reqp = aiop->aio_free; reqp != NULL; reqp = next) {
		next = reqp->aio_req_next;
		kmem_free(reqp, sizeof (struct aio_req_t));
	}

	/*
	 * release io list head freelist.
	 */
	for (liop = aiop->aio_lio_free; liop != NULL; liop = nxtlio) {
		nxtlio = liop->lio_next;
		kmem_free(liop, sizeof (aio_lio_t));
	}

	if (aiop->aio_iocb)
		kmem_free(aiop->aio_iocb, aiop->aio_iocbsz);

	mutex_destroy(&aiop->aio_mutex);
	mutex_destroy(&aiop->aio_portq_mutex);
	mutex_destroy(&aiop->aio_cleanupq_mutex);
	p->p_aio = NULL;
	mutex_exit(&p->p_lock);
	kmem_free(aiop, sizeof (struct aio));
}

/*
 * copy out aio request's result to a user-level result_t buffer.
 */
void
aio_copyout_result(aio_req_t *reqp)
{
	struct buf	*bp;
	struct iovec	*iov;
	void		*resultp;
	int		error;
	size_t		retval;

	if (reqp->aio_req_flags & AIO_COPYOUTDONE)
		return;

	reqp->aio_req_flags |= AIO_COPYOUTDONE;

	iov = reqp->aio_req_uio.uio_iov;
	bp = &reqp->aio_req_buf;
	/* "resultp" points to user-level result_t buffer */
	resultp = (void *)reqp->aio_req_resultp;
	if (bp->b_flags & B_ERROR) {
		if (bp->b_error)
			error = bp->b_error;
		else
			error = EIO;
		retval = (size_t)-1;
	} else {
		error = 0;
		retval = iov->iov_len - bp->b_resid;
	}
#ifdef	_SYSCALL32_IMPL
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		(void) sulword(&((aio_result_t *)resultp)->aio_return, retval);
		(void) suword32(&((aio_result_t *)resultp)->aio_errno, error);
	} else {
		(void) suword32(&((aio_result32_t *)resultp)->aio_return,
		    (int)retval);
		(void) suword32(&((aio_result32_t *)resultp)->aio_errno, error);
	}
#else
	(void) suword32(&((aio_result_t *)resultp)->aio_return, retval);
	(void) suword32(&((aio_result_t *)resultp)->aio_errno, error);
#endif
}


void
aio_copyout_result_port(struct iovec *iov, struct buf *bp, void *resultp)
{
	int errno;
	size_t retval;

	if (bp->b_flags & B_ERROR) {
		if (bp->b_error)
			errno = bp->b_error;
		else
			errno = EIO;
		retval = (size_t)-1;
	} else {
		errno = 0;
		retval = iov->iov_len - bp->b_resid;
	}
#ifdef	_SYSCALL32_IMPL
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		(void) sulword(&((aio_result_t *)resultp)->aio_return, retval);
		(void) suword32(&((aio_result_t *)resultp)->aio_errno, errno);
	} else {
		(void) suword32(&((aio_result32_t *)resultp)->aio_return,
		    (int)retval);
		(void) suword32(&((aio_result32_t *)resultp)->aio_errno, errno);
	}
#else
	(void) suword32(&((aio_result_t *)resultp)->aio_return, retval);
	(void) suword32(&((aio_result_t *)resultp)->aio_errno, errno);
#endif
}

/*
 * This function is used to remove a request from the done queue.
 */

void
aio_req_remove_portq(aio_t *aiop, aio_req_t *reqp)
{
	ASSERT(MUTEX_HELD(&aiop->aio_portq_mutex));
	while (aiop->aio_portq == NULL) {
		/*
		 * aio_portq is set to NULL when aio_cleanup_portq()
		 * is working with the event queue.
		 * The aio_cleanup_thread() uses aio_cleanup_portq()
		 * to unlock all AIO buffers with completed transactions.
		 * Wait here until aio_cleanup_portq() restores the
		 * list of completed transactions in aio_portq.
		 */
		cv_wait(&aiop->aio_portcv, &aiop->aio_portq_mutex);
	}
	aio_deq(&aiop->aio_portq, reqp);
}

/* ARGSUSED */
void
aio_close_port(void *arg, int port, pid_t pid, int lastclose)
{
	aio_t		*aiop;
	aio_req_t	*reqp;
	aio_req_t	*next;
	aio_req_t	*headp;
	int		counter;

	if (arg == NULL)
		aiop = curproc->p_aio;
	else
		aiop = (aio_t *)arg;

	/*
	 * The PORT_SOURCE_AIO source is always associated with every new
	 * created port by default.
	 * If no asynchronous I/O transactions were associated with the port
	 * then the aiop pointer will still be set to NULL.
	 */
	if (aiop == NULL)
		return;

	/*
	 * Within a process event ports can be used to collect events other
	 * than PORT_SOURCE_AIO events. At the same time the process can submit
	 * asynchronous I/Os transactions which are not associated with the
	 * current port.
	 * The current process oriented model of AIO uses a sigle queue for
	 * pending events. On close the pending queue (queue of asynchronous
	 * I/O transactions using event port notification) must be scanned
	 * to detect and handle pending I/Os using the current port.
	 */
	mutex_enter(&aiop->aio_portq_mutex);
	mutex_enter(&aiop->aio_mutex);
	counter = 0;
	if ((headp = aiop->aio_portpending) != NULL) {
		reqp = headp;
		do {
			if (reqp->aio_req_portkev &&
			    reqp->aio_req_port == port) {
				reqp->aio_req_flags |= AIO_CLOSE_PORT;
				counter++;
			}
		} while ((reqp = reqp->aio_req_next) != headp);
	}
	if (counter == 0) {
		/* no AIOs pending */
		mutex_exit(&aiop->aio_mutex);
		mutex_exit(&aiop->aio_portq_mutex);
		return;
	}
	aiop->aio_portpendcnt += counter;
	mutex_exit(&aiop->aio_mutex);
	while (aiop->aio_portpendcnt)
		cv_wait(&aiop->aio_portcv, &aiop->aio_portq_mutex);

	/*
	 * all pending AIOs are completed.
	 * check port doneq
	 */
	headp = NULL;
	if ((reqp = aiop->aio_portq) != NULL) {
		do {
			next = reqp->aio_req_next;
			if (reqp->aio_req_port == port) {
				/* dequeue request and discard event */
				aio_req_remove_portq(aiop, reqp);
				port_free_event(reqp->aio_req_portkev);
				/* put request in temporary queue */
				reqp->aio_req_next = headp;
				headp = reqp;
			}
		} while ((reqp = next) != aiop->aio_portq);
	}
	mutex_exit(&aiop->aio_portq_mutex);

	/* headp points to the list of requests to be discarded */
	for (reqp = headp; reqp != NULL; reqp = next) {
		next = reqp->aio_req_next;
		aphysio_unlock(reqp);
		mutex_enter(&aiop->aio_mutex);
		aio_req_free_port(aiop, reqp);
		mutex_exit(&aiop->aio_mutex);
	}

	if (aiop->aio_flags & AIO_CLEANUP)
		cv_broadcast(&aiop->aio_waitcv);
}

/*
 * aio_cleanup_dr_delete_memory is used by dr's delete_memory_thread
 * to kick start the aio_cleanup_thread for the give process to do the
 * necessary cleanup.
 * This is needed so that delete_memory_thread can obtain writer locks
 * on pages that need to be relocated during a dr memory delete operation,
 * otherwise a deadly embrace may occur.
 */
int
aio_cleanup_dr_delete_memory(proc_t *procp)
{
	struct aio *aiop = procp->p_aio;
	struct as *as = procp->p_as;
	int ret = 0;

	ASSERT(MUTEX_HELD(&procp->p_lock));

	mutex_enter(&as->a_contents);

	if (aiop != NULL) {
		aiop->aio_rqclnup = 1;
		cv_broadcast(&as->a_cv);
		ret = 1;
	}
	mutex_exit(&as->a_contents);
	return (ret);
}
