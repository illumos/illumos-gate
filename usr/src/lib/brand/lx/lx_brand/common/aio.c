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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <thread.h>
#include <synch.h>
#include <port.h>
#include <aio.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/lx_types.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_misc.h>
#include <sys/lx_aio.h>

/*
 * We implement the Linux asynchronous I/O system calls by using the POSIX
 * asynchronous I/O facilities together with event port notification.  This
 * approach allows us to broadly approximate Linux semantics, but see
 * lx_io_cancel() for some limitations.
 *
 * NOTE:
 * The Linux implementation of the io_* syscalls is not exposed via glibc.
 * These syscalls are documented to use an aio_context_t for the context
 * parameter. On Linux this is a ulong_t. On Linux the contexts live in the
 * kernel address space and are looked up using the aio_context_t parameter.
 * The Linux libaio interface uses a different type for the context_t parameter.
 *
 * Our implementation assumes the lx_aio_context_t can be treated as a
 * pointer. This works fortuitously because a ulong_t is the same size as a
 * pointer. Our implementation maps the contexts into the program's address
 * space so the aio_context_t we pass back and forth will be valid as a
 * pointer for the program. This is similar to the native aio implementation.
 */

typedef struct lx_aiocb {
	struct aiocb	lxaiocb_cb;		/* POSIX AIO control block */
	struct lx_aiocb *lxaiocb_next;		/* next outstanding/free I/O */
	struct lx_aiocb	*lxaiocb_prev;		/* prev outstanding I/O */
	uintptr_t	lxaiocb_iocbp;		/* pointer to lx_iocb_t */
	uintptr_t	lxaiocb_data;		/* data payload */
} lx_aiocb_t;

typedef struct lx_aio_ctxt {
	mutex_t		lxaio_lock;		/* lock protecting context */
	boolean_t	lxaio_destroying;	/* boolean: being destroyed */
	cond_t		lxaio_destroyer;	/* destroyer's condvar */
	int		lxaio_waiters;		/* number of waiters */
	size_t		lxaio_size;		/* total size of mapping */
	int		lxaio_port;		/* port for completion */
	lx_aiocb_t	*lxaio_outstanding;	/* outstanding I/O */
	lx_aiocb_t	*lxaio_free;		/* free I/O control blocks */
	int		lxaio_nevents;		/* max number of events */
} lx_aio_ctxt_t;

int lx_aio_max_nr = 65536;

/* Perform some basic validation on the context */
#define	INVALID_CTX(C)	(C == NULL || (long)C == -1 || \
			(C->lxaio_size == 0 && C->lxaio_nevents == 0) || \
			C->lxaio_nevents > lx_aio_max_nr)

long
lx_io_setup(unsigned int nr_events, lx_aio_context_t *cidp)
{
	lx_aio_ctxt_t *ctx;
	intptr_t tp;
	lx_aiocb_t *lxcbs;
	uintptr_t check;
	size_t size;
	int i;

	if (uucopy(cidp, &check, sizeof (cidp)) != 0)
		return (-EFAULT);

	if (check != NULL || nr_events == 0 || nr_events > lx_aio_max_nr)
		return (-EINVAL);

	/*
	 * We're saved from complexity in no small measure by the fact that the
	 * cap on the number of concurrent events must be specified a priori;
	 * we use that to determine the amount of memory we need and mmap() it
	 * upfront.
	 */
	size = sizeof (lx_aio_ctxt_t) + nr_events * sizeof (lx_aiocb_t);

	if ((tp = (intptr_t)mmap(0, size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0)) == -1) {
		return (-ENOMEM);
	}
	ctx = (lx_aio_ctxt_t *)tp;

	ctx->lxaio_size = size;
	ctx->lxaio_nevents = nr_events;

	if ((ctx->lxaio_port = port_create()) == -1) {
		(void) munmap((caddr_t)ctx, ctx->lxaio_size);
		return (-EAGAIN);
	}

	(void) mutex_init(&ctx->lxaio_lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL);

	/*
	 * Link up the free list.
	 */
	lxcbs = (lx_aiocb_t *)((uintptr_t)ctx + sizeof (lx_aio_ctxt_t));

	for (i = 0; i < nr_events - 1; i++)
		lxcbs[i].lxaiocb_next = &lxcbs[i + 1];

	ctx->lxaio_free = &lxcbs[0];

	if (uucopy(&ctx, cidp, sizeof (cidp)) != 0) {
		(void) close(ctx->lxaio_port);
		(void) munmap((caddr_t)ctx, ctx->lxaio_size);
		return (-EFAULT);
	}

	return (0);
}

long
lx_io_submit(lx_aio_context_t cid, long nr, uintptr_t **bpp)
{
	int processed = 0, err = 0, i;
	port_notify_t notify;
	lx_aiocb_t *lxcb;
	lx_iocb_t **iocbpp, iocb, *iocbp = &iocb;
	struct aiocb *aiocb;
	lx_aio_ctxt_t *ctx = (lx_aio_ctxt_t *)cid;

	/*
	 * To accomodate LTP tests we have to check in a specific order.
	 * Linux checks for invalid context first, then passes if nr == 0.
	 */
	if (INVALID_CTX(ctx))
		return (-EINVAL);

	if (nr == 0)
		return (0);

	if (nr < 0)
		return (-EINVAL);

	if ((iocbpp = (lx_iocb_t **)malloc(nr * sizeof (uintptr_t))) == NULL)
		return (-EAGAIN);

	if (uucopy(bpp, iocbpp, nr * sizeof (uintptr_t)) != 0) {
		free(iocbpp);
		return (-EFAULT);
	}

	mutex_enter(&ctx->lxaio_lock);

	for (i = 0; i < nr; i++) {
		if ((lxcb = ctx->lxaio_free) == NULL) {
			err = EAGAIN;
			break;
		}

		if (uucopy(iocbpp[i], &iocb, sizeof (iocb)) != 0) {
			err = EFAULT;
			break;
		}

		lxcb->lxaiocb_iocbp = (uintptr_t)iocbpp[i];
		lxcb->lxaiocb_data = iocbp->lxiocb_data;

		/*
		 * We don't currently support eventfd-based notification.
		 */
		if (iocbp->lxiocb_flags & LX_IOCB_FLAG_RESFD) {
			err = ENOSYS;
			break;
		}

		notify.portnfy_port = ctx->lxaio_port;
		notify.portnfy_user = lxcb;

		aiocb = &lxcb->lxaiocb_cb;
		aiocb->aio_fildes = iocbp->lxiocb_fd;
		aiocb->aio_sigevent.sigev_notify = SIGEV_PORT;
		aiocb->aio_sigevent.sigev_value.sival_ptr = &notify;

		switch (iocbp->lxiocb_op) {
		case LX_IOCB_CMD_FSYNC:
		case LX_IOCB_CMD_FDSYNC:
			err = aio_fsync(iocbp->lxiocb_op == LX_IOCB_CMD_FSYNC ?
			    O_SYNC : O_DSYNC, aiocb);
			break;

		case LX_IOCB_CMD_PREAD:
		case LX_IOCB_CMD_PWRITE:
			aiocb->aio_offset = iocbp->lxiocb_offset;

			if (aiocb->aio_nbytes > LONG_MAX) {
				err = EINVAL;
				break;
			}

			aiocb->aio_nbytes = iocbp->lxiocb_nbytes;

			if ((uintptr_t)iocbp->lxiocb_buf > ULONG_MAX) {
				err = EINVAL;
				break;
			}

			aiocb->aio_buf = (void *)(uintptr_t)iocbp->lxiocb_buf;
			aiocb->aio_reqprio = 0;

			if (iocbp->lxiocb_op == LX_IOCB_CMD_PREAD) {
				err = aio_read(aiocb);
			} else {
				err = aio_write(aiocb);
			}

			break;

		case LX_IOCB_CMD_NOOP:
			/*
			 * Yet another whodunit in Adventure Playground: why
			 * does Linux define an operation -- IOCB_CMD_NOOP --
			 * for which it always returns EINVAL?!  And what
			 * could a "no-op" possibly mean for asynchronous I/O
			 * anyway?! Do nothing... later?!
			 */
			err = EINVAL;
			break;

		case LX_IOCB_CMD_PREADV:
		case LX_IOCB_CMD_PWRITEV:
			/*
			 * We don't support asynchronous preadv and pwritev
			 * (an asynchronous scatter/gather being a somewhat odd
			 * notion to begin with); we return EINVAL in this
			 * case, which the caller should be able to deal with.
			 */
			err = EINVAL;
			break;

		default:
			err = EINVAL;
			break;
		}

		if (err == -1)
			err = errno;

		if (err != 0)
			break;

		/*
		 * We successfully enqueued I/O.  Take our control block off
		 * of the free list and transition it to our list of
		 * outstanding I/O.
		 */
		ctx->lxaio_free = lxcb->lxaiocb_next;
		lxcb->lxaiocb_next = ctx->lxaio_outstanding;

		if (ctx->lxaio_outstanding != NULL)
			ctx->lxaio_outstanding->lxaiocb_prev = lxcb;

		ctx->lxaio_outstanding = lxcb;
		processed++;
	}

	mutex_exit(&ctx->lxaio_lock);

	free(iocbpp);
	if (processed == 0)
		return (-err);

	return (processed);
}

long
lx_io_getevents(lx_aio_context_t cid, long min_nr, long nr,
    lx_io_event_t *events, struct timespec *timeoutp)
{
	port_event_t *list;
	lx_io_event_t *out;
	uint_t nget, max;
	int rval, i, err;
	lx_aio_ctxt_t *ctx = (lx_aio_ctxt_t *)cid;
	struct timespec timeout, *tp;

	if (INVALID_CTX(ctx))
		return (-EINVAL);

	if (min_nr < 0 || min_nr > ctx->lxaio_nevents ||
	    nr < 0 || nr > ctx->lxaio_nevents)
		return (-EINVAL);

	if (events == NULL)
		return (-EFAULT);

	if (timeoutp == NULL) {
		tp = NULL;
	} else if (uucopy(timeoutp, &timeout, sizeof (struct timespec)) != 0) {
		return (-EFAULT);
	} else {
		/* A timeout of 0:0 should behave like a NULL timeout */
		if (timeout.tv_sec == 0 && timeout.tv_nsec == 0) {
			tp = NULL;
		} else {
			tp = &timeout;
		}
	}

	/*
	 * We can't return ENOMEM from this syscall so EINTR is the closest
	 * we can come.
	 */
	if ((list = malloc(nr * sizeof (port_event_t))) == NULL)
		return (-EINTR);

	/*
	 * For Linux, the io_getevents() min_nr argument specifies *at least*
	 * that number of events, but for illumos the port_getn() nget argument
	 * specifies the *desired* numbers of events. Some applications pass 0
	 * for min_nr. This will cause port_getn to short-circuit and return
	 * immediately, so we use a value of 1 in this case. The port_getn()
	 * function can still return up to max events when nget == 1.
	 */
	nget = (min_nr == 0 ? 1 : min_nr);

	max = nr;

	/*
	 * Grab the lock associated with the context to bump the number of
	 * waiters.  This is needed in case this context is destroyed while
	 * we're still waiting on it.
	 */
	mutex_enter(&ctx->lxaio_lock);

	if (ctx->lxaio_destroying) {
		mutex_exit(&ctx->lxaio_lock);
		free(list);
		return (-EINVAL);
	}

	ctx->lxaio_waiters++;
	mutex_exit(&ctx->lxaio_lock);

	rval = port_getn(ctx->lxaio_port, list, max, &nget, tp);
	err = errno;

	mutex_enter(&ctx->lxaio_lock);

	assert(ctx->lxaio_waiters > 0);
	ctx->lxaio_waiters--;

	if ((rval == -1 && err != ETIME) || nget == 0 ||
	    (nget == 1 && list[0].portev_source == PORT_SOURCE_ALERT)) {
		/*
		 * If we're being destroyed, kick our waiter and clear out with
		 * EINVAL -- this is effectively an application-level race.
		 */
		if (ctx->lxaio_destroying) {
			(void) cond_signal(&ctx->lxaio_destroyer);
			err = EINVAL;
		}

		mutex_exit(&ctx->lxaio_lock);

		free(list);
		return (nget == 0 ? 0 : -err);
	}

	if ((out = malloc(nget * sizeof (lx_io_event_t))) == NULL) {
		mutex_exit(&ctx->lxaio_lock);
		free(list);
		return (-EINTR);
	}

	/*
	 * For each returned event, translate it into the Linux event in our
	 * stack-based buffer.  As we're doing this, we also free the lxcb by
	 * moving it from the outstanding list to the free list.
	 */
	for (i = 0; i < nget; i++) {
		port_event_t *pe = &list[i];
		lx_io_event_t *lxe = &out[i];
		struct aiocb *aiocb;
		lx_aiocb_t *lxcb;

		lxcb = pe->portev_user;
		aiocb = (struct aiocb *)pe->portev_object;

		assert(pe->portev_source == PORT_SOURCE_AIO);
		assert(aiocb == &lxcb->lxaiocb_cb);

		lxe->lxioe_data = lxcb->lxaiocb_data;
		lxe->lxioe_object = lxcb->lxaiocb_iocbp;
		lxe->lxioe_res = aio_return(aiocb);
		lxe->lxioe_res2 = 0;

		if (lxcb->lxaiocb_next != NULL)
			lxcb->lxaiocb_next->lxaiocb_prev = lxcb->lxaiocb_prev;

		if (lxcb->lxaiocb_prev != NULL) {
			lxcb->lxaiocb_prev->lxaiocb_next = lxcb->lxaiocb_next;
		} else {
			assert(ctx->lxaio_outstanding == lxcb);
			ctx->lxaio_outstanding = lxcb->lxaiocb_next;
		}

		lxcb->lxaiocb_prev = NULL;
		lxcb->lxaiocb_next = ctx->lxaio_free;
		ctx->lxaio_free = lxcb;
	}

	free(list);

	/*
	 * Perform one final check for a shutdown -- it's possible that we
	 * raced with the port transitioning into alert mode, in which case we
	 * have a blocked destroyer that we need to kick.  (Note that we do
	 * this after having properly cleaned up the completed I/O.)
	 */
	if (ctx->lxaio_destroying) {
		(void) cond_signal(&ctx->lxaio_destroyer);
		mutex_exit(&ctx->lxaio_lock);
		free(out);
		return (-EINVAL);
	}

	mutex_exit(&ctx->lxaio_lock);

	if (uucopy(out, events, nget * sizeof (lx_io_event_t)) != 0) {
		free(out);
		return (-EFAULT);
	}

	free(out);
	return (nget);
}

/*
 * Cancellation is unfortunately problematic for us as the POSIX semantics for
 * AIO cancellation differ slightly from the Linux semantics: on Linux,
 * io_cancel() regrettably does not use the same mechanism for event
 * consumption (that is, as an event retrievable via io_getevents()), but
 * rather returns the cancellation event directly from io_cancel().  This is
 * in contrast to POSIX AIO cancellation, which does not actually alter the
 * notification mechanism:  the cancellation is still received via its
 * specified notification (i.e., an event port or signal).  The unfortunate
 * Linux semantics leave us with several (suboptimal) choices:
 *
 * (1) Cancel the I/O via aio_cancel(), and then somehow attempt to block on
 *     the asynchronous cancellation notification without otherwise disturbing
 *     other events that may be pending.
 *
 * (2) Cancel the I/O via aio_cancel() but ignore (and later, discard) the
 *     asynchronous cancellation notification.
 *
 * (3) Explicitly fail to cancel any asynchronous I/O by having io_cancel()
 *     always return EAGAIN.
 *
 * While the third option is the least satisfying from an engineering
 * perspective, it is also entirely within the rights of the interface (which
 * may return EAGAIN to merely denote that the specified I/O "was not
 * canceled") and has the added advantage of being entirely honest.  (This is
 * in stark contrast to the first two options, each of which tries to tell
 * small lies that seem to sure to end in elaborate webs of deceit.)  Honesty
 * is the best policy; after checking that the specified I/O is outstanding,
 * we fail with EAGAIN.
 */
/*ARGSUSED*/
long
lx_io_cancel(lx_aio_context_t cid, lx_iocb_t *iocbp, lx_io_event_t *result)
{
	lx_iocb_t iocb;
	lx_aiocb_t *lxcb;
	lx_aio_ctxt_t *ctx = (lx_aio_ctxt_t *)cid;

	/* This is in a specific order for LTP */
	if (uucopy(iocbp, &iocb, sizeof (lx_iocb_t)) != 0)
		return (-EFAULT);

	if (INVALID_CTX(ctx))
		return (-EINVAL);

	mutex_enter(&ctx->lxaio_lock);

	if (ctx->lxaio_destroying) {
		mutex_exit(&ctx->lxaio_lock);
		return (-EINVAL);
	}

	for (lxcb = ctx->lxaio_outstanding; lxcb != NULL &&
	    lxcb->lxaiocb_iocbp != (uintptr_t)iocbp; lxcb = lxcb->lxaiocb_next)
		continue;

	mutex_exit(&ctx->lxaio_lock);

	if (lxcb == NULL)
		return (-EINVAL);

	/*
	 * Congratulations on your hard-won EAGAIN!
	 */
	return (-EAGAIN);
}

/*
 * As is often the case, the destruction case makes everything a lot more
 * complicated.  In this case, io_destroy() is defined to block on the
 * completion of all outstanding operations.  To effect this, we throw the
 * event port into the rarely-used alert mode -- invented long ago for just
 * this purpose -- thereby kicking any waiters out of their port_get().
 */
long
lx_io_destroy(lx_aio_context_t cid)
{
	lx_aiocb_t *lxcb;
	unsigned int nget = 0, i;
	int port;
	lx_aio_ctxt_t *ctx = (lx_aio_ctxt_t *)cid;

	if (INVALID_CTX(ctx))
		return (-EINVAL);

	port = ctx->lxaio_port;
	mutex_enter(&ctx->lxaio_lock);

	if (ctx->lxaio_destroying) {
		mutex_exit(&ctx->lxaio_lock);
		return (-EINVAL);
	}

	ctx->lxaio_destroying = B_TRUE;

	if (ctx->lxaio_waiters) {
		/*
		 * If we have waiters, put the port into alert mode.
		 */
		(void) port_alert(port, PORT_ALERT_SET, B_TRUE, NULL);

		while (ctx->lxaio_waiters) {
			(void) cond_wait(&ctx->lxaio_destroyer,
			    &ctx->lxaio_lock);
		}

		/*
		 * Transition the port out of alert mode:  we will need to
		 * block on the port ourselves for any outstanding I/O.
		 */
		(void) port_alert(port, PORT_ALERT_SET, B_FALSE, NULL);
	}

	/*
	 * We have no waiters and we never will again -- we can be assured
	 * that our list of outstanding I/Os is now completely static and it's
	 * now safe to iterate over our outstanding I/Os and aio_cancel() them.
	 */
	for (lxcb = ctx->lxaio_outstanding; lxcb != NULL;
	    lxcb = lxcb->lxaiocb_next) {
		struct aiocb *aiocb = &lxcb->lxaiocb_cb;

		/*
		 * Surely a new bureaucratic low even for POSIX that we must
		 * specify both the file descriptor and the structure that
		 * must contain the file desctiptor...
		 */
		(void) aio_cancel(aiocb->aio_fildes, aiocb);
		nget++;
	}

	/*
	 * Drain one at a time using port_get (vs. port_getn) so that we don't
	 * have to malloc a port_event list, which might fail.
	 */
	for (i = 0; i < nget; i++) {
		port_event_t pe;
		int rval;

		do {
			rval = port_get(port, &pe, NULL);
		} while (rval == -1 && errno == EINTR);

		assert(rval == 0);
	}

	/*
	 * I/Os are either cancelled or completed.  We can safely close our
	 * port and nuke the mapping that contains our context.
	 */
	(void) close(ctx->lxaio_port);
	(void) munmap((caddr_t)ctx, ctx->lxaio_size);

	return (0);
}
