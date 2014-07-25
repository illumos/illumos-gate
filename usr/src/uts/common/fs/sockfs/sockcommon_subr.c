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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/cmn_err.h>

#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/atomic.h>
#include <sys/tihdr.h>

#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/sockfilter_impl.h>
#include <fs/sockfs/socktpi.h>
#include <fs/sockfs/sodirect.h>
#include <sys/ddi.h>
#include <inet/ip.h>
#include <sys/time.h>
#include <sys/cmn_err.h>

#ifdef SOCK_TEST
extern int do_useracc;
extern clock_t sock_test_timelimit;
#endif /* SOCK_TEST */

#define	MBLK_PULL_LEN 64
uint32_t so_mblk_pull_len = MBLK_PULL_LEN;

#ifdef DEBUG
boolean_t so_debug_length = B_FALSE;
static boolean_t so_check_length(sonode_t *so);
#endif

static int
so_acceptq_dequeue_locked(struct sonode *so, boolean_t dontblock,
    struct sonode **nsop)
{
	struct sonode *nso = NULL;

	*nsop = NULL;
	ASSERT(MUTEX_HELD(&so->so_acceptq_lock));
	while ((nso = list_remove_head(&so->so_acceptq_list)) == NULL) {
		/*
		 * No need to check so_error here, because it is not
		 * possible for a listening socket to be reset or otherwise
		 * disconnected.
		 *
		 * So now we just need check if it's ok to wait.
		 */
		if (dontblock)
			return (EWOULDBLOCK);
		if (so->so_state & (SS_CLOSING | SS_FALLBACK_PENDING))
			return (EINTR);

		if (cv_wait_sig_swap(&so->so_acceptq_cv,
		    &so->so_acceptq_lock) == 0)
			return (EINTR);
	}

	ASSERT(nso != NULL);
	ASSERT(so->so_acceptq_len > 0);
	so->so_acceptq_len--;
	nso->so_listener = NULL;

	*nsop = nso;

	return (0);
}

/*
 * int so_acceptq_dequeue(struct sonode *, boolean_t, struct sonode **)
 *
 * Pulls a connection off of the accept queue.
 *
 * Arguments:
 *   so	       - listening socket
 *   dontblock - indicate whether it's ok to sleep if there are no
 *		 connections on the queue
 *   nsop      - Value-return argument
 *
 * Return values:
 *   0 when a connection is successfully dequeued, in which case nsop
 *   is set to point to the new connection. Upon failure a non-zero
 *   value is returned, and the value of nsop is set to NULL.
 *
 * Note:
 *   so_acceptq_dequeue() may return prematurly if the socket is falling
 *   back to TPI.
 */
int
so_acceptq_dequeue(struct sonode *so, boolean_t dontblock,
    struct sonode **nsop)
{
	int error;

	mutex_enter(&so->so_acceptq_lock);
	error = so_acceptq_dequeue_locked(so, dontblock, nsop);
	mutex_exit(&so->so_acceptq_lock);

	return (error);
}

static void
so_acceptq_flush_impl(struct sonode *so, list_t *list, boolean_t doclose)
{
	struct sonode *nso;

	while ((nso = list_remove_head(list)) != NULL) {
		nso->so_listener = NULL;
		if (doclose) {
			(void) socket_close(nso, 0, CRED());
		} else {
			/*
			 * Only used for fallback - not possible when filters
			 * are present.
			 */
			ASSERT(so->so_filter_active == 0);
			/*
			 * Since the socket is on the accept queue, there can
			 * only be one reference. We drop the reference and
			 * just blow off the socket.
			 */
			ASSERT(nso->so_count == 1);
			nso->so_count--;
			/* drop the proto ref */
			VN_RELE(SOTOV(nso));
		}
		socket_destroy(nso);
	}
}
/*
 * void so_acceptq_flush(struct sonode *so)
 *
 * Removes all pending connections from a listening socket, and
 * frees the associated resources.
 *
 * Arguments
 *   so	     - listening socket
 *   doclose - make a close downcall for each socket on the accept queue
 *
 * Return values:
 *   None.
 *
 * Note:
 *   The caller has to ensure that no calls to so_acceptq_enqueue() or
 *   so_acceptq_dequeue() occur while the accept queue is being flushed.
 *   So either the socket needs to be in a state where no operations
 *   would come in, or so_lock needs to be obtained.
 */
void
so_acceptq_flush(struct sonode *so, boolean_t doclose)
{
	so_acceptq_flush_impl(so, &so->so_acceptq_list, doclose);
	so_acceptq_flush_impl(so, &so->so_acceptq_defer, doclose);

	so->so_acceptq_len = 0;
}

int
so_wait_connected_locked(struct sonode *so, boolean_t nonblock,
    sock_connid_t id)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	/*
	 * The protocol has notified us that a connection attempt is being
	 * made, so before we wait for a notification to arrive we must
	 * clear out any errors associated with earlier connection attempts.
	 */
	if (so->so_error != 0 && SOCK_CONNID_LT(so->so_proto_connid, id))
		so->so_error = 0;

	while (SOCK_CONNID_LT(so->so_proto_connid, id)) {
		if (nonblock)
			return (EINPROGRESS);

		if (so->so_state & (SS_CLOSING | SS_FALLBACK_PENDING))
			return (EINTR);

		if (cv_wait_sig_swap(&so->so_state_cv, &so->so_lock) == 0)
			return (EINTR);
	}

	if (so->so_error != 0)
		return (sogeterr(so, B_TRUE));
	/*
	 * Under normal circumstances, so_error should contain an error
	 * in case the connect failed. However, it is possible for another
	 * thread to come in a consume the error, so generate a sensible
	 * error in that case.
	 */
	if ((so->so_state & SS_ISCONNECTED) == 0)
		return (ECONNREFUSED);

	return (0);
}

/*
 * int so_wait_connected(struct sonode *so, boolean_t nonblock,
 *    sock_connid_t id)
 *
 * Wait until the socket is connected or an error has occured.
 *
 * Arguments:
 *   so	      - socket
 *   nonblock - indicate whether it's ok to sleep if the connection has
 *		not yet been established
 *   gen      - generation number that was returned by the protocol
 *		when the operation was started
 *
 * Returns:
 *   0 if the connection attempt was successful, or an error indicating why
 *   the connection attempt failed.
 */
int
so_wait_connected(struct sonode *so, boolean_t nonblock, sock_connid_t id)
{
	int error;

	mutex_enter(&so->so_lock);
	error = so_wait_connected_locked(so, nonblock, id);
	mutex_exit(&so->so_lock);

	return (error);
}

int
so_snd_wait_qnotfull_locked(struct sonode *so, boolean_t dontblock)
{
	int error;

	ASSERT(MUTEX_HELD(&so->so_lock));
	while (SO_SND_FLOWCTRLD(so)) {
		if (so->so_state & SS_CANTSENDMORE)
			return (EPIPE);
		if (dontblock)
			return (EWOULDBLOCK);

		if (so->so_state & (SS_CLOSING | SS_FALLBACK_PENDING))
			return (EINTR);

		if (so->so_sndtimeo == 0) {
			/*
			 * Zero means disable timeout.
			 */
			error = cv_wait_sig(&so->so_snd_cv, &so->so_lock);
		} else {
			error = cv_reltimedwait_sig(&so->so_snd_cv,
			    &so->so_lock, so->so_sndtimeo, TR_CLOCK_TICK);
		}
		if (error == 0)
			return (EINTR);
		else if (error == -1)
			return (EAGAIN);
	}
	return (0);
}

/*
 * int so_wait_sendbuf(struct sonode *so, boolean_t dontblock)
 *
 * Wait for the transport to notify us about send buffers becoming
 * available.
 */
int
so_snd_wait_qnotfull(struct sonode *so, boolean_t dontblock)
{
	int error = 0;

	mutex_enter(&so->so_lock);
	so->so_snd_wakeup = B_TRUE;
	error = so_snd_wait_qnotfull_locked(so, dontblock);
	so->so_snd_wakeup = B_FALSE;
	mutex_exit(&so->so_lock);

	return (error);
}

void
so_snd_qfull(struct sonode *so)
{
	mutex_enter(&so->so_lock);
	so->so_snd_qfull = B_TRUE;
	mutex_exit(&so->so_lock);
}

void
so_snd_qnotfull(struct sonode *so)
{
	mutex_enter(&so->so_lock);
	so->so_snd_qfull = B_FALSE;
	/* wake up everyone waiting for buffers */
	cv_broadcast(&so->so_snd_cv);
	mutex_exit(&so->so_lock);
}

/*
 * Change the process/process group to which SIGIO is sent.
 */
int
socket_chgpgrp(struct sonode *so, pid_t pid)
{
	int error;

	ASSERT(MUTEX_HELD(&so->so_lock));
	if (pid != 0) {
		/*
		 * Permissions check by sending signal 0.
		 * Note that when kill fails it does a
		 * set_errno causing the system call to fail.
		 */
		error = kill(pid, 0);
		if (error != 0) {
			return (error);
		}
	}
	so->so_pgrp = pid;
	return (0);
}


/*
 * Generate a SIGIO, for 'writable' events include siginfo structure,
 * for read events just send the signal.
 */
/*ARGSUSED*/
static void
socket_sigproc(proc_t *proc, int event)
{
	k_siginfo_t info;

	ASSERT(event & (SOCKETSIG_WRITE | SOCKETSIG_READ | SOCKETSIG_URG));

	if (event & SOCKETSIG_WRITE) {
		info.si_signo = SIGPOLL;
		info.si_code = POLL_OUT;
		info.si_errno = 0;
		info.si_fd = 0;
		info.si_band = 0;
		sigaddq(proc, NULL, &info, KM_NOSLEEP);
	}
	if (event & SOCKETSIG_READ) {
		sigtoproc(proc, NULL, SIGPOLL);
	}
	if (event & SOCKETSIG_URG) {
		sigtoproc(proc, NULL, SIGURG);
	}
}

void
socket_sendsig(struct sonode *so, int event)
{
	proc_t *proc;

	ASSERT(MUTEX_HELD(&so->so_lock));

	if (so->so_pgrp == 0 || (!(so->so_state & SS_ASYNC) &&
	    event != SOCKETSIG_URG)) {
		return;
	}

	dprint(3, ("sending sig %d to %d\n", event, so->so_pgrp));

	if (so->so_pgrp > 0) {
		/*
		 * XXX This unfortunately still generates
		 * a signal when a fd is closed but
		 * the proc is active.
		 */
		mutex_enter(&pidlock);
		/*
		 * Even if the thread started in another zone, we're receiving
		 * on behalf of this socket's zone, so find the proc using the
		 * socket's zone ID.
		 */
		proc = prfind_zone(so->so_pgrp, so->so_zoneid);
		if (proc == NULL) {
			mutex_exit(&pidlock);
			return;
		}
		mutex_enter(&proc->p_lock);
		mutex_exit(&pidlock);
		socket_sigproc(proc, event);
		mutex_exit(&proc->p_lock);
	} else {
		/*
		 * Send to process group. Hold pidlock across
		 * calls to socket_sigproc().
		 */
		pid_t pgrp = -so->so_pgrp;

		mutex_enter(&pidlock);
		/*
		 * Even if the thread started in another zone, we're receiving
		 * on behalf of this socket's zone, so find the pgrp using the
		 * socket's zone ID.
		 */
		proc = pgfind_zone(pgrp, so->so_zoneid);
		while (proc != NULL) {
			mutex_enter(&proc->p_lock);
			socket_sigproc(proc, event);
			mutex_exit(&proc->p_lock);
			proc = proc->p_pglink;
		}
		mutex_exit(&pidlock);
	}
}

#define	MIN(a, b) ((a) < (b) ? (a) : (b))
/* Copy userdata into a new mblk_t */
mblk_t *
socopyinuio(uio_t *uiop, ssize_t iosize, size_t wroff, ssize_t maxblk,
    size_t tail_len, int *errorp)
{
	mblk_t	*head = NULL, **tail = &head;

	ASSERT(iosize == INFPSZ || iosize > 0);

	if (iosize == INFPSZ || iosize > uiop->uio_resid)
		iosize = uiop->uio_resid;

	if (maxblk == INFPSZ)
		maxblk = iosize;

	/* Nothing to do in these cases, so we're done */
	if (iosize < 0 || maxblk < 0 || (maxblk == 0 && iosize > 0))
		goto done;

	/*
	 * We will enter the loop below if iosize is 0; it will allocate an
	 * empty message block and call uiomove(9F) which will just return.
	 * We could avoid that with an extra check but would only slow
	 * down the much more likely case where iosize is larger than 0.
	 */
	do {
		ssize_t blocksize;
		mblk_t	*mp;

		blocksize = MIN(iosize, maxblk);
		ASSERT(blocksize >= 0);
		mp = allocb(wroff + blocksize + tail_len, BPRI_MED);
		if (mp == NULL) {
			*errorp = ENOMEM;
			return (head);
		}
		mp->b_rptr += wroff;
		mp->b_wptr = mp->b_rptr + blocksize;

		*tail = mp;
		tail = &mp->b_cont;

		/* uiomove(9F) either returns 0 or EFAULT */
		if ((*errorp = uiomove(mp->b_rptr, (size_t)blocksize,
		    UIO_WRITE, uiop)) != 0) {
			ASSERT(*errorp != ENOMEM);
			freemsg(head);
			return (NULL);
		}

		iosize -= blocksize;
	} while (iosize > 0);

done:
	*errorp = 0;
	return (head);
}

mblk_t *
socopyoutuio(mblk_t *mp, struct uio *uiop, ssize_t max_read, int *errorp)
{
	int error;
	ptrdiff_t n;
	mblk_t *nmp;

	ASSERT(mp->b_wptr >= mp->b_rptr);

	/*
	 * max_read is the offset of the oobmark and read can not go pass
	 * the oobmark.
	 */
	if (max_read == INFPSZ || max_read > uiop->uio_resid)
		max_read = uiop->uio_resid;

	do {
		if ((n = MIN(max_read, MBLKL(mp))) != 0) {
			ASSERT(n > 0);

			error = uiomove(mp->b_rptr, n, UIO_READ, uiop);
			if (error != 0) {
				freemsg(mp);
				*errorp = error;
				return (NULL);
			}
		}

		mp->b_rptr += n;
		max_read -= n;
		while (mp != NULL && (mp->b_rptr >= mp->b_wptr)) {
			/*
			 * get rid of zero length mblks
			 */
			nmp = mp;
			mp = mp->b_cont;
			freeb(nmp);
		}
	} while (mp != NULL && max_read > 0);

	*errorp = 0;
	return (mp);
}

static void
so_prepend_msg(struct sonode *so, mblk_t *mp, mblk_t *last_tail)
{
	ASSERT(last_tail != NULL);
	mp->b_next = so->so_rcv_q_head;
	mp->b_prev = last_tail;
	ASSERT(!(DB_FLAGS(mp) & DBLK_UIOA));

	if (so->so_rcv_q_head == NULL) {
		ASSERT(so->so_rcv_q_last_head == NULL);
		so->so_rcv_q_last_head = mp;
#ifdef DEBUG
	} else {
		ASSERT(!(DB_FLAGS(so->so_rcv_q_head) & DBLK_UIOA));
#endif
	}
	so->so_rcv_q_head = mp;

#ifdef DEBUG
	if (so_debug_length) {
		mutex_enter(&so->so_lock);
		ASSERT(so_check_length(so));
		mutex_exit(&so->so_lock);
	}
#endif
}

/*
 * Move a mblk chain (mp_head, mp_last_head) to the sonode's rcv queue so it
 * can be processed by so_dequeue_msg().
 */
void
so_process_new_message(struct sonode *so, mblk_t *mp_head, mblk_t *mp_last_head)
{
	if (so->so_filter_active > 0 &&
	    (mp_head = sof_filter_data_in_proc(so, mp_head,
	    &mp_last_head)) == NULL)
		return;

	ASSERT(mp_head->b_prev != NULL);
	if (so->so_rcv_q_head == NULL) {
		so->so_rcv_q_head = mp_head;
		so->so_rcv_q_last_head = mp_last_head;
		ASSERT(so->so_rcv_q_last_head->b_prev != NULL);
	} else {
		boolean_t flag_equal = ((DB_FLAGS(mp_head) & DBLK_UIOA) ==
		    (DB_FLAGS(so->so_rcv_q_last_head) & DBLK_UIOA));

		if (mp_head->b_next == NULL &&
		    DB_TYPE(mp_head) == M_DATA &&
		    DB_TYPE(so->so_rcv_q_last_head) == M_DATA && flag_equal) {
			so->so_rcv_q_last_head->b_prev->b_cont = mp_head;
			so->so_rcv_q_last_head->b_prev = mp_head->b_prev;
			mp_head->b_prev = NULL;
		} else if (flag_equal && (DB_FLAGS(mp_head) & DBLK_UIOA)) {
			/*
			 * Append to last_head if more than one mblks, and both
			 * mp_head and last_head are I/OAT mblks.
			 */
			ASSERT(mp_head->b_next != NULL);
			so->so_rcv_q_last_head->b_prev->b_cont = mp_head;
			so->so_rcv_q_last_head->b_prev = mp_head->b_prev;
			mp_head->b_prev = NULL;

			so->so_rcv_q_last_head->b_next = mp_head->b_next;
			mp_head->b_next = NULL;
			so->so_rcv_q_last_head = mp_last_head;
		} else {
#ifdef DEBUG
			{
				mblk_t *tmp_mblk;
				tmp_mblk = mp_head;
				while (tmp_mblk != NULL) {
					ASSERT(tmp_mblk->b_prev != NULL);
					tmp_mblk = tmp_mblk->b_next;
				}
			}
#endif
			so->so_rcv_q_last_head->b_next = mp_head;
			so->so_rcv_q_last_head = mp_last_head;
		}
	}
}

/*
 * Check flow control on a given sonode.  Must have so_lock held, and
 * this function will release the hold.  Return true if flow control
 * is cleared.
 */
boolean_t
so_check_flow_control(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	if (so->so_flowctrld && (so->so_rcv_queued < so->so_rcvlowat &&
	    !(so->so_state & SS_FIL_RCV_FLOWCTRL))) {
		so->so_flowctrld = B_FALSE;
		mutex_exit(&so->so_lock);
		/*
		 * Open up flow control. SCTP does not have any downcalls, and
		 * it will clr flow ctrl in sosctp_recvmsg().
		 */
		if (so->so_downcalls != NULL &&
		    so->so_downcalls->sd_clr_flowctrl != NULL) {
			(*so->so_downcalls->sd_clr_flowctrl)
			    (so->so_proto_handle);
		}
		/* filters can start injecting data */
		sof_sonode_notify_filters(so, SOF_EV_INJECT_DATA_IN_OK, 0);
		return (B_TRUE);
	} else {
		mutex_exit(&so->so_lock);
		return (B_FALSE);
	}
}

int
so_dequeue_msg(struct sonode *so, mblk_t **mctlp, struct uio *uiop,
    rval_t *rvalp, int flags)
{
	mblk_t	*mp, *nmp;
	mblk_t	*savemp, *savemptail;
	mblk_t	*new_msg_head;
	mblk_t	*new_msg_last_head;
	mblk_t	*last_tail;
	boolean_t partial_read;
	boolean_t reset_atmark = B_FALSE;
	int more = 0;
	int error;
	ssize_t oobmark;
	sodirect_t *sodp = so->so_direct;

	partial_read = B_FALSE;
	*mctlp = NULL;
again:
	mutex_enter(&so->so_lock);
again1:
#ifdef DEBUG
	if (so_debug_length) {
		ASSERT(so_check_length(so));
	}
#endif
	if (so->so_state & SS_RCVATMARK) {
		/* Check whether the caller is OK to read past the mark */
		if (flags & MSG_NOMARK) {
			mutex_exit(&so->so_lock);
			return (EWOULDBLOCK);
		}
		reset_atmark = B_TRUE;
	}
	/*
	 * First move messages from the dump area to processing area
	 */
	if (sodp != NULL) {
		if (sodp->sod_enabled) {
			if (sodp->sod_uioa.uioa_state & UIOA_ALLOC) {
				/* nothing to uioamove */
				sodp = NULL;
			} else if (sodp->sod_uioa.uioa_state & UIOA_INIT) {
				sodp->sod_uioa.uioa_state &= UIOA_CLR;
				sodp->sod_uioa.uioa_state |= UIOA_ENABLED;
				/*
				 * try to uioamove() the data that
				 * has already queued.
				 */
				sod_uioa_so_init(so, sodp, uiop);
			}
		} else {
			sodp = NULL;
		}
	}
	new_msg_head = so->so_rcv_head;
	new_msg_last_head = so->so_rcv_last_head;
	so->so_rcv_head = NULL;
	so->so_rcv_last_head = NULL;
	oobmark = so->so_oobmark;
	/*
	 * We can release the lock as there can only be one reader
	 */
	mutex_exit(&so->so_lock);

	if (new_msg_head != NULL) {
		so_process_new_message(so, new_msg_head, new_msg_last_head);
	}
	savemp = savemptail = NULL;
	rvalp->r_vals = 0;
	error = 0;
	mp = so->so_rcv_q_head;

	if (mp != NULL &&
	    (so->so_rcv_timer_tid == 0 ||
	    so->so_rcv_queued >= so->so_rcv_thresh)) {
		partial_read = B_FALSE;

		if (flags & MSG_PEEK) {
			if ((nmp = dupmsg(mp)) == NULL &&
			    (nmp = copymsg(mp)) == NULL) {
				size_t size = msgsize(mp);

				error = strwaitbuf(size, BPRI_HI);
				if (error) {
					return (error);
				}
				goto again;
			}
			mp = nmp;
		} else {
			ASSERT(mp->b_prev != NULL);
			last_tail = mp->b_prev;
			mp->b_prev = NULL;
			so->so_rcv_q_head = mp->b_next;
			if (so->so_rcv_q_head == NULL) {
				so->so_rcv_q_last_head = NULL;
			}
			mp->b_next = NULL;
		}

		ASSERT(mctlp != NULL);
		/*
		 * First process PROTO or PCPROTO blocks, if any.
		 */
		if (DB_TYPE(mp) != M_DATA) {
			*mctlp = mp;
			savemp = mp;
			savemptail = mp;
			ASSERT(DB_TYPE(mp) == M_PROTO ||
			    DB_TYPE(mp) == M_PCPROTO);
			while (mp->b_cont != NULL &&
			    DB_TYPE(mp->b_cont) != M_DATA) {
				ASSERT(DB_TYPE(mp->b_cont) == M_PROTO ||
				    DB_TYPE(mp->b_cont) == M_PCPROTO);
				mp = mp->b_cont;
				savemptail = mp;
			}
			mp = savemptail->b_cont;
			savemptail->b_cont = NULL;
		}

		ASSERT(DB_TYPE(mp) == M_DATA);
		/*
		 * Now process DATA blocks, if any. Note that for sodirect
		 * enabled socket, uio_resid can be 0.
		 */
		if (uiop->uio_resid >= 0) {
			ssize_t copied = 0;

			if (sodp != NULL && (DB_FLAGS(mp) & DBLK_UIOA)) {
				mutex_enter(&so->so_lock);
				ASSERT(uiop == (uio_t *)&sodp->sod_uioa);
				copied = sod_uioa_mblk(so, mp);
				if (copied > 0)
					partial_read = B_TRUE;
				mutex_exit(&so->so_lock);
				/* mark this mblk as processed */
				mp = NULL;
			} else {
				ssize_t oldresid = uiop->uio_resid;

				if (MBLKL(mp) < so_mblk_pull_len) {
					if (pullupmsg(mp, -1) == 1) {
						last_tail = mp;
					}
				}
				/*
				 * Can not read beyond the oobmark
				 */
				mp = socopyoutuio(mp, uiop,
				    oobmark == 0 ? INFPSZ : oobmark, &error);
				if (error != 0) {
					freemsg(*mctlp);
					*mctlp = NULL;
					more = 0;
					goto done;
				}
				ASSERT(oldresid >= uiop->uio_resid);
				copied = oldresid - uiop->uio_resid;
				if (oldresid > uiop->uio_resid)
					partial_read = B_TRUE;
			}
			ASSERT(copied >= 0);
			if (copied > 0 && !(flags & MSG_PEEK)) {
				mutex_enter(&so->so_lock);
				so->so_rcv_queued -= copied;
				ASSERT(so->so_oobmark >= 0);
				if (so->so_oobmark > 0) {
					so->so_oobmark -= copied;
					ASSERT(so->so_oobmark >= 0);
					if (so->so_oobmark == 0) {
						ASSERT(so->so_state &
						    SS_OOBPEND);
						so->so_oobmark = 0;
						so->so_state |= SS_RCVATMARK;
					}
				}
				/*
				 * so_check_flow_control() will drop
				 * so->so_lock.
				 */
				rvalp->r_val2 = so_check_flow_control(so);
			}
		}
		if (mp != NULL) { /* more data blocks in msg */
			more |= MOREDATA;
			if ((flags & (MSG_PEEK|MSG_TRUNC))) {
				if (flags & MSG_PEEK) {
					freemsg(mp);
				} else {
					unsigned int msize = msgdsize(mp);

					freemsg(mp);
					mutex_enter(&so->so_lock);
					so->so_rcv_queued -= msize;
					/*
					 * so_check_flow_control() will drop
					 * so->so_lock.
					 */
					rvalp->r_val2 =
					    so_check_flow_control(so);
				}
			} else if (partial_read && !somsghasdata(mp)) {
				/*
				 * Avoid queuing a zero-length tail part of
				 * a message. partial_read == 1 indicates that
				 * we read some of the message.
				 */
				freemsg(mp);
				more &= ~MOREDATA;
			} else {
				if (savemp != NULL &&
				    (flags & MSG_DUPCTRL)) {
					mblk_t *nmp;
					/*
					 * There should only be non data mblks
					 */
					ASSERT(DB_TYPE(savemp) != M_DATA &&
					    DB_TYPE(savemptail) != M_DATA);
try_again:
					if ((nmp = dupmsg(savemp)) == NULL &&
					    (nmp = copymsg(savemp)) == NULL) {

						size_t size = msgsize(savemp);

						error = strwaitbuf(size,
						    BPRI_HI);
						if (error != 0) {
							/*
							 * In case we
							 * cannot copy
							 * control data
							 * free the remaining
							 * data.
							 */
							freemsg(mp);
							goto done;
						}
						goto try_again;
					}

					ASSERT(nmp != NULL);
					ASSERT(DB_TYPE(nmp) != M_DATA);
					savemptail->b_cont = mp;
					*mctlp = nmp;
					mp = savemp;
				}
				/*
				 * putback mp
				 */
				so_prepend_msg(so, mp, last_tail);
			}
		}

		/* fast check so_rcv_head if there is more data */
		if (partial_read && !(so->so_state & SS_RCVATMARK) &&
		    *mctlp == NULL && uiop->uio_resid > 0 &&
		    !(flags & MSG_PEEK) && so->so_rcv_head != NULL) {
			goto again;
		}
	} else if (!partial_read) {
		mutex_enter(&so->so_lock);
		if (so->so_error != 0) {
			error = sogeterr(so, !(flags & MSG_PEEK));
			mutex_exit(&so->so_lock);
			return (error);
		}
		/*
		 * No pending data. Return right away for nonblocking
		 * socket, otherwise sleep waiting for data.
		 */
		if (!(so->so_state & SS_CANTRCVMORE) && uiop->uio_resid > 0) {
			if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
			    (flags & MSG_DONTWAIT)) {
				error = EWOULDBLOCK;
			} else {
				if (so->so_state & (SS_CLOSING |
				    SS_FALLBACK_PENDING)) {
					mutex_exit(&so->so_lock);
					error = EINTR;
					goto done;
				}

				if (so->so_rcv_head != NULL) {
					goto again1;
				}
				so->so_rcv_wakeup = B_TRUE;
				so->so_rcv_wanted = uiop->uio_resid;
				if (so->so_rcvtimeo == 0) {
					/*
					 * Zero means disable timeout.
					 */
					error = cv_wait_sig(&so->so_rcv_cv,
					    &so->so_lock);
				} else {
					error = cv_reltimedwait_sig(
					    &so->so_rcv_cv, &so->so_lock,
					    so->so_rcvtimeo, TR_CLOCK_TICK);
				}
				so->so_rcv_wakeup = B_FALSE;
				so->so_rcv_wanted = 0;

				if (error == 0) {
					error = EINTR;
				} else if (error == -1) {
					error = EAGAIN;
				} else {
					goto again1;
				}
			}
		}
		mutex_exit(&so->so_lock);
	}
	if (reset_atmark && partial_read && !(flags & MSG_PEEK)) {
		/*
		 * We are passed the mark, update state
		 * 4.3BSD and 4.4BSD clears the mark when peeking across it.
		 * The draft Posix socket spec states that the mark should
		 * not be cleared when peeking. We follow the latter.
		 */
		mutex_enter(&so->so_lock);
		ASSERT(so_verify_oobstate(so));
		so->so_state &= ~(SS_OOBPEND|SS_HAVEOOBDATA|SS_RCVATMARK);
		freemsg(so->so_oobmsg);
		so->so_oobmsg = NULL;
		ASSERT(so_verify_oobstate(so));
		mutex_exit(&so->so_lock);
	}
	ASSERT(so->so_rcv_wakeup == B_FALSE);
done:
	if (sodp != NULL) {
		mutex_enter(&so->so_lock);
		if (sodp->sod_enabled &&
		    (sodp->sod_uioa.uioa_state & UIOA_ENABLED)) {
			SOD_UIOAFINI(sodp);
			if (sodp->sod_uioa.uioa_mbytes > 0) {
				ASSERT(so->so_rcv_q_head != NULL ||
				    so->so_rcv_head != NULL);
				so->so_rcv_queued -= sod_uioa_mblk(so, NULL);
				if (error == EWOULDBLOCK)
					error = 0;
			}
		}
		mutex_exit(&so->so_lock);
	}
#ifdef DEBUG
	if (so_debug_length) {
		mutex_enter(&so->so_lock);
		ASSERT(so_check_length(so));
		mutex_exit(&so->so_lock);
	}
#endif
	rvalp->r_val1 = more;
	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	return (error);
}

/*
 * Enqueue data from the protocol on the socket's rcv queue.
 *
 * We try to hook new M_DATA mblks onto an existing chain, however,
 * that cannot be done if the existing chain has already been
 * processed by I/OAT. Non-M_DATA mblks are just linked together via
 * b_next. In all cases the b_prev of the enqueued mblk is set to
 * point to the last mblk in its b_cont chain.
 */
void
so_enqueue_msg(struct sonode *so, mblk_t *mp, size_t msg_size)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

#ifdef DEBUG
	if (so_debug_length) {
		ASSERT(so_check_length(so));
	}
#endif
	so->so_rcv_queued += msg_size;

	if (so->so_rcv_head == NULL) {
		ASSERT(so->so_rcv_last_head == NULL);
		so->so_rcv_head = mp;
		so->so_rcv_last_head = mp;
	} else if ((DB_TYPE(mp) == M_DATA &&
	    DB_TYPE(so->so_rcv_last_head) == M_DATA) &&
	    ((DB_FLAGS(mp) & DBLK_UIOA) ==
	    (DB_FLAGS(so->so_rcv_last_head) & DBLK_UIOA))) {
		/* Added to the end */
		ASSERT(so->so_rcv_last_head != NULL);
		ASSERT(so->so_rcv_last_head->b_prev != NULL);
		so->so_rcv_last_head->b_prev->b_cont = mp;
	} else {
		/* Start a new end */
		so->so_rcv_last_head->b_next = mp;
		so->so_rcv_last_head = mp;
	}
	while (mp->b_cont != NULL)
		mp = mp->b_cont;

	so->so_rcv_last_head->b_prev = mp;
#ifdef DEBUG
	if (so_debug_length) {
		ASSERT(so_check_length(so));
	}
#endif
}

/*
 * Return B_TRUE if there is data in the message, B_FALSE otherwise.
 */
boolean_t
somsghasdata(mblk_t *mp)
{
	for (; mp; mp = mp->b_cont)
		if (mp->b_datap->db_type == M_DATA) {
			ASSERT(mp->b_wptr >= mp->b_rptr);
			if (mp->b_wptr > mp->b_rptr)
				return (B_TRUE);
		}
	return (B_FALSE);
}

/*
 * Flush the read side of sockfs.
 *
 * The caller must be sure that a reader is not already active when the
 * buffer is being flushed.
 */
void
so_rcv_flush(struct sonode *so)
{
	mblk_t  *mp;

	ASSERT(MUTEX_HELD(&so->so_lock));

	if (so->so_oobmsg != NULL) {
		freemsg(so->so_oobmsg);
		so->so_oobmsg = NULL;
		so->so_oobmark = 0;
		so->so_state &=
		    ~(SS_OOBPEND|SS_HAVEOOBDATA|SS_HADOOBDATA|SS_RCVATMARK);
	}

	/*
	 * Free messages sitting in the recv queues
	 */
	while (so->so_rcv_q_head != NULL) {
		mp = so->so_rcv_q_head;
		so->so_rcv_q_head = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		freemsg(mp);
	}
	while (so->so_rcv_head != NULL) {
		mp = so->so_rcv_head;
		so->so_rcv_head = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		freemsg(mp);
	}
	so->so_rcv_queued = 0;
	so->so_rcv_q_head = NULL;
	so->so_rcv_q_last_head = NULL;
	so->so_rcv_head = NULL;
	so->so_rcv_last_head = NULL;
}

/*
 * Handle recv* calls that set MSG_OOB or MSG_OOB together with MSG_PEEK.
 */
int
sorecvoob(struct sonode *so, struct nmsghdr *msg, struct uio *uiop, int flags,
    boolean_t oob_inline)
{
	mblk_t		*mp, *nmp;
	int		error;

	dprintso(so, 1, ("sorecvoob(%p, %p, 0x%x)\n", (void *)so, (void *)msg,
	    flags));

	if (msg != NULL) {
		/*
		 * There is never any oob data with addresses or control since
		 * the T_EXDATA_IND does not carry any options.
		 */
		msg->msg_controllen = 0;
		msg->msg_namelen = 0;
		msg->msg_flags = 0;
	}

	mutex_enter(&so->so_lock);
	ASSERT(so_verify_oobstate(so));
	if (oob_inline ||
	    (so->so_state & (SS_OOBPEND|SS_HADOOBDATA)) != SS_OOBPEND) {
		dprintso(so, 1, ("sorecvoob: inline or data consumed\n"));
		mutex_exit(&so->so_lock);
		return (EINVAL);
	}
	if (!(so->so_state & SS_HAVEOOBDATA)) {
		dprintso(so, 1, ("sorecvoob: no data yet\n"));
		mutex_exit(&so->so_lock);
		return (EWOULDBLOCK);
	}
	ASSERT(so->so_oobmsg != NULL);
	mp = so->so_oobmsg;
	if (flags & MSG_PEEK) {
		/*
		 * Since recv* can not return ENOBUFS we can not use dupmsg.
		 * Instead we revert to the consolidation private
		 * allocb_wait plus bcopy.
		 */
		mblk_t *mp1;

		mp1 = allocb_wait(msgdsize(mp), BPRI_MED, STR_NOSIG, NULL);
		ASSERT(mp1);

		while (mp != NULL) {
			ssize_t size;

			size = MBLKL(mp);
			bcopy(mp->b_rptr, mp1->b_wptr, size);
			mp1->b_wptr += size;
			ASSERT(mp1->b_wptr <= mp1->b_datap->db_lim);
			mp = mp->b_cont;
		}
		mp = mp1;
	} else {
		/*
		 * Update the state indicating that the data has been consumed.
		 * Keep SS_OOBPEND set until data is consumed past the mark.
		 */
		so->so_oobmsg = NULL;
		so->so_state ^= SS_HAVEOOBDATA|SS_HADOOBDATA;
	}
	ASSERT(so_verify_oobstate(so));
	mutex_exit(&so->so_lock);

	error = 0;
	nmp = mp;
	while (nmp != NULL && uiop->uio_resid > 0) {
		ssize_t n = MBLKL(nmp);

		n = MIN(n, uiop->uio_resid);
		if (n > 0)
			error = uiomove(nmp->b_rptr, n,
			    UIO_READ, uiop);
		if (error)
			break;
		nmp = nmp->b_cont;
	}
	ASSERT(mp->b_next == NULL && mp->b_prev == NULL);
	freemsg(mp);
	return (error);
}

/*
 * Allocate and initializ sonode
 */
/* ARGSUSED */
struct sonode *
socket_sonode_create(struct sockparams *sp, int family, int type,
    int protocol, int version, int sflags, int *errorp, struct cred *cr)
{
	sonode_t *so;
	int	kmflags;

	/*
	 * Choose the right set of sonodeops based on the upcall and
	 * down call version that the protocol has provided
	 */
	if (SOCK_UC_VERSION != sp->sp_smod_info->smod_uc_version ||
	    SOCK_DC_VERSION != sp->sp_smod_info->smod_dc_version) {
		/*
		 * mismatch
		 */
#ifdef DEBUG
		cmn_err(CE_CONT, "protocol and socket module version mismatch");
#endif
		*errorp = EINVAL;
		return (NULL);
	}

	kmflags = (sflags & SOCKET_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	so = kmem_cache_alloc(socket_cache, kmflags);
	if (so == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}

	sonode_init(so, sp, family, type, protocol, &so_sonodeops);

	if (version == SOV_DEFAULT)
		version = so_default_version;

	so->so_version = (short)version;

	/*
	 * set the default values to be INFPSZ
	 * if a protocol desires it can change the value later
	 */
	so->so_proto_props.sopp_rxhiwat = SOCKET_RECVHIWATER;
	so->so_proto_props.sopp_rxlowat = SOCKET_RECVLOWATER;
	so->so_proto_props.sopp_maxpsz = INFPSZ;
	so->so_proto_props.sopp_maxblk = INFPSZ;

	return (so);
}

int
socket_init_common(struct sonode *so, struct sonode *pso, int flags, cred_t *cr)
{
	int error = 0;

	if (pso != NULL) {
		/*
		 * We have a passive open, so inherit basic state from
		 * the parent (listener).
		 *
		 * No need to grab the new sonode's lock, since there is no
		 * one that can have a reference to it.
		 */
		mutex_enter(&pso->so_lock);

		so->so_state |= SS_ISCONNECTED | (pso->so_state & SS_ASYNC);
		so->so_pgrp = pso->so_pgrp;
		so->so_rcvtimeo = pso->so_rcvtimeo;
		so->so_sndtimeo = pso->so_sndtimeo;
		so->so_xpg_rcvbuf = pso->so_xpg_rcvbuf;
		/*
		 * Make note of the socket level options. TCP and IP level
		 * options are already inherited. We could do all this after
		 * accept is successful but doing it here simplifies code and
		 * no harm done for error case.
		 */
		so->so_options = pso->so_options & (SO_DEBUG|SO_REUSEADDR|
		    SO_KEEPALIVE|SO_DONTROUTE|SO_BROADCAST|SO_USELOOPBACK|
		    SO_OOBINLINE|SO_DGRAM_ERRIND|SO_LINGER);
		so->so_proto_props = pso->so_proto_props;
		so->so_mode = pso->so_mode;
		so->so_pollev = pso->so_pollev & SO_POLLEV_ALWAYS;

		mutex_exit(&pso->so_lock);

		/*
		 * If the parent has any filters, try to inherit them.
		 */
		if (pso->so_filter_active > 0 &&
		    (error = sof_sonode_inherit_filters(so, pso)) != 0)
			return (error);

	} else {
		struct sockparams *sp = so->so_sockparams;
		sock_upcalls_t *upcalls_to_use;

		/*
		 * Attach automatic filters, if there are any.
		 */
		if (!list_is_empty(&sp->sp_auto_filters) &&
		    (error = sof_sonode_autoattach_filters(so, cr)) != 0)
			return (error);

		/* OK to attach filters */
		so->so_state |= SS_FILOP_OK;

		/*
		 * Based on the version number select the right upcalls to
		 * pass down. Currently we only have one version so choose
		 * default
		 */
		upcalls_to_use = &so_upcalls;

		/* active open, so create a lower handle */
		so->so_proto_handle =
		    sp->sp_smod_info->smod_proto_create_func(so->so_family,
		    so->so_type, so->so_protocol, &so->so_downcalls,
		    &so->so_mode, &error, flags, cr);

		if (so->so_proto_handle == NULL) {
			ASSERT(error != 0);
			/*
			 * To be safe; if a lower handle cannot be created, and
			 * the proto does not give a reason why, assume there
			 * was a lack of memory.
			 */
			return ((error == 0) ? ENOMEM : error);
		}
		ASSERT(so->so_downcalls != NULL);
		ASSERT(so->so_downcalls->sd_send != NULL ||
		    so->so_downcalls->sd_send_uio != NULL);
		if (so->so_downcalls->sd_recv_uio != NULL) {
			ASSERT(so->so_downcalls->sd_poll != NULL);
			so->so_pollev |= SO_POLLEV_ALWAYS;
		}

		(*so->so_downcalls->sd_activate)(so->so_proto_handle,
		    (sock_upper_handle_t)so, upcalls_to_use, 0, cr);

		/* Wildcard */

		/*
		 * FIXME No need for this, the protocol can deal with it in
		 * sd_create(). Should update ICMP.
		 */
		if (so->so_protocol != so->so_sockparams->sp_protocol) {
			int protocol = so->so_protocol;
			int error;
			/*
			 * Issue SO_PROTOTYPE setsockopt.
			 */
			error = socket_setsockopt(so, SOL_SOCKET, SO_PROTOTYPE,
			    &protocol, (t_uscalar_t)sizeof (protocol), cr);
			if (error) {
				(void) (*so->so_downcalls->sd_close)
				    (so->so_proto_handle, 0, cr);

				mutex_enter(&so->so_lock);
				so_rcv_flush(so);
				mutex_exit(&so->so_lock);
				/*
				 * Setsockopt often fails with ENOPROTOOPT but
				 * socket() should fail with
				 * EPROTONOSUPPORT/EPROTOTYPE.
				 */
				return (EPROTONOSUPPORT);
			}
		}
	}

	if (uioasync.enabled)
		sod_sock_init(so);

	/* put an extra reference on the socket for the protocol */
	VN_HOLD(SOTOV(so));

	return (0);
}

/*
 * int socket_ioctl_common(struct sonode *so, int cmd, intptr_t arg, int mode,
 *         struct cred *cr, int32_t *rvalp)
 *
 * Handle ioctls that manipulate basic socket state; non-blocking,
 * async, etc.
 *
 * Returns:
 *   < 0  - ioctl was not handle
 *  >= 0  - ioctl was handled, if > 0, then it is an errno
 *
 * Notes:
 *   Assumes the standard receive buffer is used to obtain info for
 *   NREAD.
 */
/* ARGSUSED */
int
socket_ioctl_common(struct sonode *so, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	switch (cmd) {
	case SIOCSQPTR:
		/*
		 * SIOCSQPTR is valid only when helper stream is created
		 * by the protocol.
		 */

		return (EOPNOTSUPP);
	case FIONBIO: {
		int32_t value;

		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		if (value) {
			so->so_state |= SS_NDELAY;
		} else {
			so->so_state &= ~SS_NDELAY;
		}
		mutex_exit(&so->so_lock);
		return (0);
	}
	case FIOASYNC: {
		int32_t value;

		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);

		if (value) {
			/* Turn on SIGIO */
			so->so_state |= SS_ASYNC;
		} else {
			/* Turn off SIGIO */
			so->so_state &= ~SS_ASYNC;
		}
		mutex_exit(&so->so_lock);

		return (0);
	}

	case SIOCSPGRP:
	case FIOSETOWN: {
		int error;
		pid_t pid;

		if (so_copyin((void *)arg, &pid, sizeof (pid_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		error = (pid != so->so_pgrp) ? socket_chgpgrp(so, pid) : 0;
		mutex_exit(&so->so_lock);
		return (error);
	}
	case SIOCGPGRP:
	case FIOGETOWN:
		if (so_copyout(&so->so_pgrp, (void *)arg,
		    sizeof (pid_t), (mode & (int)FKIOCTL)))
			return (EFAULT);

		return (0);
	case SIOCATMARK: {
		int retval;

		/*
		 * Only protocols that support urgent data can handle ATMARK.
		 */
		if ((so->so_mode & SM_EXDATA) == 0)
			return (EINVAL);

		/*
		 * If the protocol is maintaining its own buffer, then the
		 * request must be passed down.
		 */
		if (so->so_downcalls->sd_recv_uio != NULL)
			return (-1);

		retval = (so->so_state & SS_RCVATMARK) != 0;

		if (so_copyout(&retval, (void *)arg, sizeof (int),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		return (0);
	}

	case FIONREAD: {
		int retval;

		/*
		 * If the protocol is maintaining its own buffer, then the
		 * request must be passed down.
		 */
		if (so->so_downcalls->sd_recv_uio != NULL)
			return (-1);

		retval = MIN(so->so_rcv_queued, INT_MAX);

		if (so_copyout(&retval, (void *)arg,
		    sizeof (retval), (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		return (0);
	}

	case _I_GETPEERCRED: {
		int error = 0;

		if ((mode & FKIOCTL) == 0)
			return (EINVAL);

		mutex_enter(&so->so_lock);
		if ((so->so_mode & SM_CONNREQUIRED) == 0) {
			error = ENOTSUP;
		} else if ((so->so_state & SS_ISCONNECTED) == 0) {
			error = ENOTCONN;
		} else if (so->so_peercred != NULL) {
			k_peercred_t *kp = (k_peercred_t *)arg;
			kp->pc_cr = so->so_peercred;
			kp->pc_cpid = so->so_cpid;
			crhold(so->so_peercred);
		} else {
			error = EINVAL;
		}
		mutex_exit(&so->so_lock);
		return (error);
	}
	default:
		return (-1);
	}
}

/*
 * Handle the I_NREAD STREAM ioctl.
 */
static int
so_strioc_nread(struct sonode *so, intptr_t arg, int mode, int32_t *rvalp)
{
	size_t size = 0;
	int retval;
	int count = 0;
	mblk_t *mp;
	clock_t wakeup = drv_usectohz(10);

	if (so->so_downcalls == NULL ||
	    so->so_downcalls->sd_recv_uio != NULL)
		return (EINVAL);

	mutex_enter(&so->so_lock);
	/* Wait for reader to get out of the way. */
	while (so->so_flag & SOREADLOCKED) {
		/*
		 * If reader is waiting for data, then there should be nothing
		 * on the rcv queue.
		 */
		if (so->so_rcv_wakeup)
			goto out;

		/* Do a timed sleep, in case the reader goes to sleep. */
		(void) cv_reltimedwait(&so->so_read_cv, &so->so_lock, wakeup,
		    TR_CLOCK_TICK);
	}

	/*
	 * Since we are holding so_lock no new reader will come in, and the
	 * protocol will not be able to enqueue data. So it's safe to walk
	 * both rcv queues.
	 */
	mp = so->so_rcv_q_head;
	if (mp != NULL) {
		size = msgdsize(so->so_rcv_q_head);
		for (; mp != NULL; mp = mp->b_next)
			count++;
	} else {
		/*
		 * In case the processing list was empty, get the size of the
		 * next msg in line.
		 */
		size = msgdsize(so->so_rcv_head);
	}

	for (mp = so->so_rcv_head; mp != NULL; mp = mp->b_next)
		count++;
out:
	mutex_exit(&so->so_lock);

	/*
	 * Drop down from size_t to the "int" required by the
	 * interface.  Cap at INT_MAX.
	 */
	retval = MIN(size, INT_MAX);
	if (so_copyout(&retval, (void *)arg, sizeof (retval),
	    (mode & (int)FKIOCTL))) {
		return (EFAULT);
	} else {
		*rvalp = count;
		return (0);
	}
}

/*
 * Process STREAM ioctls.
 *
 * Returns:
 *   < 0  - ioctl was not handle
 *  >= 0  - ioctl was handled, if > 0, then it is an errno
 */
int
socket_strioc_common(struct sonode *so, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	int retval;

	/* Only STREAM iotcls are handled here */
	if ((cmd & 0xffffff00U) != STR)
		return (-1);

	switch (cmd) {
	case I_CANPUT:
		/*
		 * We return an error for I_CANPUT so that isastream(3C) will
		 * not report the socket as being a STREAM.
		 */
		return (EOPNOTSUPP);
	case I_NREAD:
		/* Avoid doing a fallback for I_NREAD. */
		return (so_strioc_nread(so, arg, mode, rvalp));
	case I_LOOK:
		/* Avoid doing a fallback for I_LOOK. */
		if (so_copyout("sockmod", (void *)arg, strlen("sockmod") + 1,
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		return (0);
	default:
		break;
	}

	/*
	 * Try to fall back to TPI, and if successful, reissue the ioctl.
	 */
	if ((retval = so_tpi_fallback(so, cr)) == 0) {
		/* Reissue the ioctl */
		ASSERT(so->so_rcv_q_head == NULL);
		return (SOP_IOCTL(so, cmd, arg, mode, cr, rvalp));
	} else {
		return (retval);
	}
}

/*
 * This is called for all socket types to verify that the buffer size is large
 * enough for the option, and if we can, handle the request as well. Most
 * options will be forwarded to the protocol.
 */
int
socket_getopt_common(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, int flags)
{
	if (level != SOL_SOCKET)
		return (-1);

	switch (option_name) {
	case SO_ERROR:
	case SO_DOMAIN:
	case SO_TYPE:
	case SO_ACCEPTCONN: {
		int32_t value;
		socklen_t optlen = *optlenp;

		if (optlen < (t_uscalar_t)sizeof (int32_t)) {
			return (EINVAL);
		}

		switch (option_name) {
		case SO_ERROR:
			mutex_enter(&so->so_lock);
			value = sogeterr(so, B_TRUE);
			mutex_exit(&so->so_lock);
			break;
		case SO_DOMAIN:
			value = so->so_family;
			break;
		case SO_TYPE:
			value = so->so_type;
			break;
		case SO_ACCEPTCONN:
			if (so->so_state & SS_ACCEPTCONN)
				value = SO_ACCEPTCONN;
			else
				value = 0;
			break;
		}

		bcopy(&value, optval, sizeof (value));
		*optlenp = sizeof (value);

		return (0);
	}
	case SO_SNDTIMEO:
	case SO_RCVTIMEO: {
		clock_t value;
		socklen_t optlen = *optlenp;

		if (get_udatamodel() == DATAMODEL_NONE ||
		    get_udatamodel() == DATAMODEL_NATIVE) {
			if (optlen < sizeof (struct timeval))
				return (EINVAL);
		} else {
			if (optlen < sizeof (struct timeval32))
				return (EINVAL);
		}
		if (option_name == SO_RCVTIMEO)
			value = drv_hztousec(so->so_rcvtimeo);
		else
			value = drv_hztousec(so->so_sndtimeo);

		if (get_udatamodel() == DATAMODEL_NONE ||
		    get_udatamodel() == DATAMODEL_NATIVE) {
			((struct timeval *)(optval))->tv_sec =
			    value / (1000 * 1000);
			((struct timeval *)(optval))->tv_usec =
			    value % (1000 * 1000);
			*optlenp = sizeof (struct timeval);
		} else {
			((struct timeval32 *)(optval))->tv_sec =
			    value / (1000 * 1000);
			((struct timeval32 *)(optval))->tv_usec =
			    value % (1000 * 1000);
			*optlenp = sizeof (struct timeval32);
		}
		return (0);
	}
	case SO_DEBUG:
	case SO_REUSEADDR:
	case SO_KEEPALIVE:
	case SO_DONTROUTE:
	case SO_BROADCAST:
	case SO_USELOOPBACK:
	case SO_OOBINLINE:
	case SO_SNDBUF:
#ifdef notyet
	case SO_SNDLOWAT:
	case SO_RCVLOWAT:
#endif /* notyet */
	case SO_DGRAM_ERRIND: {
		socklen_t optlen = *optlenp;

		if (optlen < (t_uscalar_t)sizeof (int32_t))
			return (EINVAL);
		break;
	}
	case SO_RCVBUF: {
		socklen_t optlen = *optlenp;

		if (optlen < (t_uscalar_t)sizeof (int32_t))
			return (EINVAL);

		if ((flags & _SOGETSOCKOPT_XPG4_2) && so->so_xpg_rcvbuf != 0) {
			/*
			 * XXX If SO_RCVBUF has been set and this is an
			 * XPG 4.2 application then do not ask the transport
			 * since the transport might adjust the value and not
			 * return exactly what was set by the application.
			 * For non-XPG 4.2 application we return the value
			 * that the transport is actually using.
			 */
			*(int32_t *)optval = so->so_xpg_rcvbuf;
			*optlenp = sizeof (so->so_xpg_rcvbuf);
			return (0);
		}
		/*
		 * If the option has not been set then get a default
		 * value from the transport.
		 */
		break;
	}
	case SO_LINGER: {
		socklen_t optlen = *optlenp;

		if (optlen < (t_uscalar_t)sizeof (struct linger))
			return (EINVAL);
		break;
	}
	case SO_SND_BUFINFO: {
		socklen_t optlen = *optlenp;

		if (optlen < (t_uscalar_t)sizeof (struct so_snd_bufinfo))
			return (EINVAL);
		((struct so_snd_bufinfo *)(optval))->sbi_wroff =
		    (so->so_proto_props).sopp_wroff;
		((struct so_snd_bufinfo *)(optval))->sbi_maxblk =
		    (so->so_proto_props).sopp_maxblk;
		((struct so_snd_bufinfo *)(optval))->sbi_maxpsz =
		    (so->so_proto_props).sopp_maxpsz;
		((struct so_snd_bufinfo *)(optval))->sbi_tail =
		    (so->so_proto_props).sopp_tail;
		*optlenp = sizeof (struct so_snd_bufinfo);
		return (0);
	}
	case SO_SND_COPYAVOID: {
		sof_instance_t *inst;

		/*
		 * Avoid zero-copy if there is a filter with a data_out
		 * callback. We could let the operation succeed, but then
		 * the filter would have to copy the data anyway.
		 */
		for (inst = so->so_filter_top; inst != NULL;
		    inst = inst->sofi_next) {
			if (SOF_INTERESTED(inst, data_out))
				return (EOPNOTSUPP);
		}
		break;
	}

	default:
		break;
	}

	/* Unknown Option */
	return (-1);
}

void
socket_sonode_destroy(struct sonode *so)
{
	sonode_fini(so);
	kmem_cache_free(socket_cache, so);
}

int
so_zcopy_wait(struct sonode *so)
{
	int error = 0;

	mutex_enter(&so->so_lock);
	while (!(so->so_copyflag & STZCNOTIFY)) {
		if (so->so_state & SS_CLOSING) {
			mutex_exit(&so->so_lock);
			return (EINTR);
		}
		if (cv_wait_sig(&so->so_copy_cv, &so->so_lock) == 0) {
			error = EINTR;
			break;
		}
	}
	so->so_copyflag &= ~STZCNOTIFY;
	mutex_exit(&so->so_lock);
	return (error);
}

void
so_timer_callback(void *arg)
{
	struct sonode *so = (struct sonode *)arg;

	mutex_enter(&so->so_lock);

	so->so_rcv_timer_tid = 0;
	if (so->so_rcv_queued > 0) {
		so_notify_data(so, so->so_rcv_queued);
	} else {
		mutex_exit(&so->so_lock);
	}
}

#ifdef DEBUG
/*
 * Verify that the length stored in so_rcv_queued and the length of data blocks
 * queued is same.
 */
static boolean_t
so_check_length(sonode_t *so)
{
	mblk_t *mp = so->so_rcv_q_head;
	int len = 0;

	ASSERT(MUTEX_HELD(&so->so_lock));

	if (mp != NULL) {
		len = msgdsize(mp);
		while ((mp = mp->b_next) != NULL)
			len += msgdsize(mp);
	}
	mp = so->so_rcv_head;
	if (mp != NULL) {
		len += msgdsize(mp);
		while ((mp = mp->b_next) != NULL)
			len += msgdsize(mp);
	}
	return ((len == so->so_rcv_queued) ? B_TRUE : B_FALSE);
}
#endif

int
so_get_mod_version(struct sockparams *sp)
{
	ASSERT(sp != NULL && sp->sp_smod_info != NULL);
	return (sp->sp_smod_info->smod_version);
}

/*
 * so_start_fallback()
 *
 * Block new socket operations from coming in, and wait for active operations
 * to complete. Threads that are sleeping will be woken up so they can get
 * out of the way.
 *
 * The caller must be a reader on so_fallback_rwlock.
 */
static boolean_t
so_start_fallback(struct sonode *so)
{
	ASSERT(RW_READ_HELD(&so->so_fallback_rwlock));

	mutex_enter(&so->so_lock);
	if (so->so_state & SS_FALLBACK_PENDING) {
		mutex_exit(&so->so_lock);
		return (B_FALSE);
	}
	so->so_state |= SS_FALLBACK_PENDING;
	/*
	 * Poke all threads that might be sleeping. Any operation that comes
	 * in after the cv_broadcast will observe the fallback pending flag
	 * which cause the call to return where it would normally sleep.
	 */
	cv_broadcast(&so->so_state_cv);		/* threads in connect() */
	cv_broadcast(&so->so_rcv_cv);		/* threads in recvmsg() */
	cv_broadcast(&so->so_snd_cv);		/* threads in sendmsg() */
	mutex_enter(&so->so_acceptq_lock);
	cv_broadcast(&so->so_acceptq_cv);	/* threads in accept() */
	mutex_exit(&so->so_acceptq_lock);
	mutex_exit(&so->so_lock);

	/*
	 * The main reason for the rw_tryupgrade call is to provide
	 * observability during the fallback process. We want to
	 * be able to see if there are pending operations.
	 */
	if (rw_tryupgrade(&so->so_fallback_rwlock) == 0) {
		/*
		 * It is safe to drop and reaquire the fallback lock, because
		 * we are guaranteed that another fallback cannot take place.
		 */
		rw_exit(&so->so_fallback_rwlock);
		DTRACE_PROBE1(pending__ops__wait, (struct sonode *), so);
		rw_enter(&so->so_fallback_rwlock, RW_WRITER);
		DTRACE_PROBE1(pending__ops__complete, (struct sonode *), so);
	}

	return (B_TRUE);
}

/*
 * so_end_fallback()
 *
 * Allow socket opertions back in.
 *
 * The caller must be a writer on so_fallback_rwlock.
 */
static void
so_end_fallback(struct sonode *so)
{
	ASSERT(RW_ISWRITER(&so->so_fallback_rwlock));

	mutex_enter(&so->so_lock);
	so->so_state &= ~(SS_FALLBACK_PENDING|SS_FALLBACK_DRAIN);
	mutex_exit(&so->so_lock);

	rw_downgrade(&so->so_fallback_rwlock);
}

/*
 * so_quiesced_cb()
 *
 * Callback passed to the protocol during fallback. It is called once
 * the endpoint is quiescent.
 *
 * No requests from the user, no notifications from the protocol, so it
 * is safe to synchronize the state. Data can also be moved without
 * risk for reordering.
 *
 * We do not need to hold so_lock, since there can be only one thread
 * operating on the sonode.
 */
static mblk_t *
so_quiesced_cb(sock_upper_handle_t sock_handle, sock_quiesce_arg_t *arg,
    struct T_capability_ack *tcap,
    struct sockaddr *laddr, socklen_t laddrlen,
    struct sockaddr *faddr, socklen_t faddrlen, short opts)
{
	struct sonode *so = (struct sonode *)sock_handle;
	boolean_t atmark;
	mblk_t *retmp = NULL, **tailmpp = &retmp;

	if (tcap != NULL)
		sotpi_update_state(so, tcap, laddr, laddrlen, faddr, faddrlen,
		    opts);

	/*
	 * Some protocols do not quiece the data path during fallback. Once
	 * we set the SS_FALLBACK_DRAIN flag any attempt to queue data will
	 * fail and the protocol is responsible for saving the data for later
	 * delivery (i.e., once the fallback has completed).
	 */
	mutex_enter(&so->so_lock);
	so->so_state |= SS_FALLBACK_DRAIN;
	SOCKET_TIMER_CANCEL(so);
	mutex_exit(&so->so_lock);

	if (so->so_rcv_head != NULL) {
		if (so->so_rcv_q_last_head == NULL)
			so->so_rcv_q_head = so->so_rcv_head;
		else
			so->so_rcv_q_last_head->b_next = so->so_rcv_head;
		so->so_rcv_q_last_head = so->so_rcv_last_head;
	}

	atmark = (so->so_state & SS_RCVATMARK) != 0;
	/*
	 * Clear any OOB state having to do with pending data. The TPI
	 * code path will set the appropriate oob state when we move the
	 * oob data to the STREAM head. We leave SS_HADOOBDATA since the oob
	 * data has already been consumed.
	 */
	so->so_state &= ~(SS_RCVATMARK|SS_OOBPEND|SS_HAVEOOBDATA);

	ASSERT(so->so_oobmsg != NULL || so->so_oobmark <= so->so_rcv_queued);

	/*
	 * Move data to the STREAM head.
	 */
	while (so->so_rcv_q_head != NULL) {
		mblk_t *mp = so->so_rcv_q_head;
		size_t mlen = msgdsize(mp);

		so->so_rcv_q_head = mp->b_next;
		mp->b_next = NULL;
		mp->b_prev = NULL;

		/*
		 * Send T_EXDATA_IND if we are at the oob mark.
		 */
		if (atmark) {
			struct T_exdata_ind *tei;
			mblk_t *mp1 = arg->soqa_exdata_mp;

			arg->soqa_exdata_mp = NULL;
			ASSERT(mp1 != NULL);
			mp1->b_datap->db_type = M_PROTO;
			tei = (struct T_exdata_ind *)mp1->b_rptr;
			tei->PRIM_type = T_EXDATA_IND;
			tei->MORE_flag = 0;
			mp1->b_wptr = (uchar_t *)&tei[1];

			if (IS_SO_OOB_INLINE(so)) {
				mp1->b_cont = mp;
			} else {
				ASSERT(so->so_oobmsg != NULL);
				mp1->b_cont = so->so_oobmsg;
				so->so_oobmsg = NULL;

				/* process current mp next time around */
				mp->b_next = so->so_rcv_q_head;
				so->so_rcv_q_head = mp;
				mlen = 0;
			}
			mp = mp1;

			/* we have consumed the oob mark */
			atmark = B_FALSE;
		} else if (so->so_oobmark > 0) {
			/*
			 * Check if the OOB mark is within the current
			 * mblk chain. In that case we have to split it up.
			 */
			if (so->so_oobmark < mlen) {
				mblk_t *urg_mp = mp;

				atmark = B_TRUE;
				mp = NULL;
				mlen = so->so_oobmark;

				/*
				 * It is assumed that the OOB mark does
				 * not land within a mblk.
				 */
				do {
					so->so_oobmark -= MBLKL(urg_mp);
					mp = urg_mp;
					urg_mp = urg_mp->b_cont;
				} while (so->so_oobmark > 0);
				mp->b_cont = NULL;
				if (urg_mp != NULL) {
					urg_mp->b_next = so->so_rcv_q_head;
					so->so_rcv_q_head = urg_mp;
				}
			} else {
				so->so_oobmark -= mlen;
				if (so->so_oobmark == 0)
					atmark = B_TRUE;
			}
		}

		/*
		 * Queue data on the STREAM head.
		 */
		so->so_rcv_queued -= mlen;
		*tailmpp = mp;
		tailmpp = &mp->b_next;
	}
	so->so_rcv_head = NULL;
	so->so_rcv_last_head = NULL;
	so->so_rcv_q_head = NULL;
	so->so_rcv_q_last_head = NULL;

	/*
	 * Check if the oob byte is at the end of the data stream, or if the
	 * oob byte has not yet arrived. In the latter case we have to send a
	 * SIGURG and a mark indicator to the STREAM head. The mark indicator
	 * is needed to guarantee correct behavior for SIOCATMARK. See block
	 * comment in socktpi.h for more details.
	 */
	if (atmark || so->so_oobmark > 0) {
		mblk_t *mp;

		if (atmark && so->so_oobmsg != NULL) {
			struct T_exdata_ind *tei;

			mp = arg->soqa_exdata_mp;
			arg->soqa_exdata_mp = NULL;
			ASSERT(mp != NULL);
			mp->b_datap->db_type = M_PROTO;
			tei = (struct T_exdata_ind *)mp->b_rptr;
			tei->PRIM_type = T_EXDATA_IND;
			tei->MORE_flag = 0;
			mp->b_wptr = (uchar_t *)&tei[1];

			mp->b_cont = so->so_oobmsg;
			so->so_oobmsg = NULL;

			*tailmpp = mp;
			tailmpp = &mp->b_next;
		} else {
			/* Send up the signal */
			mp = arg->soqa_exdata_mp;
			arg->soqa_exdata_mp = NULL;
			ASSERT(mp != NULL);
			DB_TYPE(mp) = M_PCSIG;
			*mp->b_wptr++ = (uchar_t)SIGURG;
			*tailmpp = mp;
			tailmpp = &mp->b_next;

			/* Send up the mark indicator */
			mp = arg->soqa_urgmark_mp;
			arg->soqa_urgmark_mp = NULL;
			mp->b_flag = atmark ? MSGMARKNEXT : MSGNOTMARKNEXT;
			*tailmpp = mp;
			tailmpp = &mp->b_next;

			so->so_oobmark = 0;
		}
	}
	ASSERT(so->so_oobmark == 0);
	ASSERT(so->so_rcv_queued == 0);

	return (retmp);
}

#ifdef DEBUG
/*
 * Do an integrity check of the sonode. This should be done if a
 * fallback fails after sonode has initially been converted to use
 * TPI and subsequently have to be reverted.
 *
 * Failure to pass the integrity check will panic the system.
 */
void
so_integrity_check(struct sonode *cur, struct sonode *orig)
{
	VERIFY(cur->so_vnode == orig->so_vnode);
	VERIFY(cur->so_ops == orig->so_ops);
	/*
	 * For so_state we can only VERIFY the state flags in CHECK_STATE.
	 * The other state flags might be affected by a notification from the
	 * protocol.
	 */
#define	CHECK_STATE	(SS_CANTRCVMORE|SS_CANTSENDMORE|SS_NDELAY|SS_NONBLOCK| \
	SS_ASYNC|SS_ACCEPTCONN|SS_SAVEDEOR|SS_RCVATMARK|SS_OOBPEND| \
	SS_HAVEOOBDATA|SS_HADOOBDATA|SS_SENTLASTREADSIG|SS_SENTLASTWRITESIG)
	VERIFY((cur->so_state & (orig->so_state & CHECK_STATE)) ==
	    (orig->so_state & CHECK_STATE));
	VERIFY(cur->so_mode == orig->so_mode);
	VERIFY(cur->so_flag == orig->so_flag);
	VERIFY(cur->so_count == orig->so_count);
	/* Cannot VERIFY so_proto_connid; proto can update it */
	VERIFY(cur->so_sockparams == orig->so_sockparams);
	/* an error might have been recorded, but it can not be lost */
	VERIFY(cur->so_error != 0 || orig->so_error == 0);
	VERIFY(cur->so_family == orig->so_family);
	VERIFY(cur->so_type == orig->so_type);
	VERIFY(cur->so_protocol == orig->so_protocol);
	VERIFY(cur->so_version == orig->so_version);
	/* New conns might have arrived, but none should have been lost */
	VERIFY(cur->so_acceptq_len >= orig->so_acceptq_len);
	VERIFY(list_head(&cur->so_acceptq_list) ==
	    list_head(&orig->so_acceptq_list));
	VERIFY(cur->so_backlog == orig->so_backlog);
	/* New OOB migth have arrived, but mark should not have been lost */
	VERIFY(cur->so_oobmark >= orig->so_oobmark);
	/* Cannot VERIFY so_oobmsg; the proto might have sent up a new one */
	VERIFY(cur->so_pgrp == orig->so_pgrp);
	VERIFY(cur->so_peercred == orig->so_peercred);
	VERIFY(cur->so_cpid == orig->so_cpid);
	VERIFY(cur->so_zoneid == orig->so_zoneid);
	/* New data migth have arrived, but none should have been lost */
	VERIFY(cur->so_rcv_queued >= orig->so_rcv_queued);
	VERIFY(cur->so_rcv_q_head == orig->so_rcv_q_head);
	VERIFY(cur->so_rcv_head == orig->so_rcv_head);
	VERIFY(cur->so_proto_handle == orig->so_proto_handle);
	VERIFY(cur->so_downcalls == orig->so_downcalls);
	/* Cannot VERIFY so_proto_props; they can be updated by proto */
}
#endif

/*
 * so_tpi_fallback()
 *
 * This is the fallback initation routine; things start here.
 *
 * Basic strategy:
 *   o Block new socket operations from coming in
 *   o Allocate/initate info needed by TPI
 *   o Quiesce the connection, at which point we sync
 *     state and move data
 *   o Change operations (sonodeops) associated with the socket
 *   o Unblock threads waiting for the fallback to finish
 */
int
so_tpi_fallback(struct sonode *so, struct cred *cr)
{
	int error;
	queue_t *q;
	struct sockparams *sp;
	struct sockparams *newsp = NULL;
	so_proto_fallback_func_t fbfunc;
	const char *devpath;
	boolean_t direct;
	struct sonode *nso;
	sock_quiesce_arg_t arg = { NULL, NULL };
#ifdef DEBUG
	struct sonode origso;
#endif
	error = 0;
	sp = so->so_sockparams;
	fbfunc = sp->sp_smod_info->smod_proto_fallback_func;

	/*
	 * Cannot fallback if the socket has active filters
	 */
	if (so->so_filter_active > 0)
		return (EINVAL);

	switch (so->so_family) {
	case AF_INET:
		devpath = sp->sp_smod_info->smod_fallback_devpath_v4;
		break;
	case AF_INET6:
		devpath = sp->sp_smod_info->smod_fallback_devpath_v6;
		break;
	default:
		return (EINVAL);
	}

	/*
	 * Fallback can only happen if the socket module has a TPI device
	 * and fallback function.
	 */
	if (devpath == NULL || fbfunc == NULL)
		return (EINVAL);

	/*
	 * Initiate fallback; upon success we know that no new requests
	 * will come in from the user.
	 */
	if (!so_start_fallback(so))
		return (EAGAIN);
#ifdef DEBUG
	/*
	 * Make a copy of the sonode in case we need to make an integrity
	 * check later on.
	 */
	bcopy(so, &origso, sizeof (*so));
#endif

	sp->sp_stats.sps_nfallback.value.ui64++;

	newsp = sockparams_hold_ephemeral_bydev(so->so_family, so->so_type,
	    so->so_protocol, devpath, KM_SLEEP, &error);
	if (error != 0)
		goto out;

	if (so->so_direct != NULL) {
		sodirect_t *sodp = so->so_direct;
		mutex_enter(&so->so_lock);

		so->so_direct->sod_enabled = B_FALSE;
		so->so_state &= ~SS_SODIRECT;
		ASSERT(sodp->sod_uioafh == NULL);
		mutex_exit(&so->so_lock);
	}

	/* Turn sonode into a TPI socket */
	error = sotpi_convert_sonode(so, newsp, &direct, &q, cr);
	if (error != 0)
		goto out;
	/*
	 * When it comes to urgent data we have two cases to deal with;
	 * (1) The oob byte has already arrived, or (2) the protocol has
	 * notified that oob data is pending, but it has not yet arrived.
	 *
	 * For (1) all we need to do is send a T_EXDATA_IND to indicate were
	 * in the byte stream the oob byte is. For (2) we have to send a
	 * SIGURG (M_PCSIG), followed by a zero-length mblk indicating whether
	 * the oob byte will be the next byte from the protocol.
	 *
	 * So in the worst case we need two mblks, one for the signal, another
	 * for mark indication. In that case we use the exdata_mp for the sig.
	 */
	arg.soqa_exdata_mp = allocb_wait(sizeof (struct T_exdata_ind),
	    BPRI_MED, STR_NOSIG, NULL);
	arg.soqa_urgmark_mp = allocb_wait(0, BPRI_MED, STR_NOSIG, NULL);

	/*
	 * Now tell the protocol to start using TPI. so_quiesced_cb be
	 * called once it's safe to synchronize state.
	 */
	DTRACE_PROBE1(proto__fallback__begin, struct sonode *, so);
	error = (*fbfunc)(so->so_proto_handle, q, direct, so_quiesced_cb,
	    &arg);
	DTRACE_PROBE1(proto__fallback__end, struct sonode *, so);

	if (error != 0) {
		/* protocol was unable to do a fallback, revert the sonode */
		sotpi_revert_sonode(so, cr);
		goto out;
	}

	/*
	 * Walk the accept queue and notify the proto that they should
	 * fall back to TPI. The protocol will send up the T_CONN_IND.
	 */
	nso = list_head(&so->so_acceptq_list);
	while (nso != NULL) {
		int rval;
		struct sonode *next;

		if (arg.soqa_exdata_mp == NULL) {
			arg.soqa_exdata_mp =
			    allocb_wait(sizeof (struct T_exdata_ind),
			    BPRI_MED, STR_NOSIG, NULL);
		}
		if (arg.soqa_urgmark_mp == NULL) {
			arg.soqa_urgmark_mp = allocb_wait(0, BPRI_MED,
			    STR_NOSIG, NULL);
		}

		DTRACE_PROBE1(proto__fallback__begin, struct sonode *, nso);
		rval = (*fbfunc)(nso->so_proto_handle, NULL, direct,
		    so_quiesced_cb, &arg);
		DTRACE_PROBE1(proto__fallback__end, struct sonode *, nso);
		if (rval != 0) {
			/* Abort the connection */
			zcmn_err(getzoneid(), CE_WARN,
			    "Failed to convert socket in accept queue to TPI. "
			    "Pid = %d\n", curproc->p_pid);
			next = list_next(&so->so_acceptq_list, nso);
			list_remove(&so->so_acceptq_list, nso);
			so->so_acceptq_len--;

			(void) socket_close(nso, 0, CRED());
			socket_destroy(nso);
			nso = next;
		} else {
			nso = list_next(&so->so_acceptq_list, nso);
		}
	}

	/*
	 * Now flush the acceptq, this will destroy all sockets. They will
	 * be recreated in sotpi_accept().
	 */
	so_acceptq_flush(so, B_FALSE);

	mutex_enter(&so->so_lock);
	so->so_state |= SS_FALLBACK_COMP;
	mutex_exit(&so->so_lock);

	/*
	 * Swap the sonode ops. Socket opertations that come in once this
	 * is done will proceed without blocking.
	 */
	so->so_ops = &sotpi_sonodeops;

	/*
	 * Wake up any threads stuck in poll. This is needed since the poll
	 * head changes when the fallback happens (moves from the sonode to
	 * the STREAMS head).
	 */
	pollwakeup(&so->so_poll_list, POLLERR);

	/*
	 * When this non-STREAM socket was created we placed an extra ref on
	 * the associated vnode to support asynchronous close. Drop that ref
	 * here.
	 */
	ASSERT(SOTOV(so)->v_count >= 2);
	VN_RELE(SOTOV(so));
out:
	so_end_fallback(so);

	if (error != 0) {
#ifdef DEBUG
		so_integrity_check(so, &origso);
#endif
		zcmn_err(getzoneid(), CE_WARN,
		    "Failed to convert socket to TPI (err=%d). Pid = %d\n",
		    error, curproc->p_pid);
		if (newsp != NULL)
			SOCKPARAMS_DEC_REF(newsp);
	}
	if (arg.soqa_exdata_mp != NULL)
		freemsg(arg.soqa_exdata_mp);
	if (arg.soqa_urgmark_mp != NULL)
		freemsg(arg.soqa_urgmark_mp);

	return (error);
}
