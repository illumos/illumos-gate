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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * posix_aio.c implements the POSIX async. I/O
 * functions for librt
 *
 *	aio_read
 *	aio_write
 *	aio_error
 *	aio_return
 *	aio_suspend
 *	lio_listio
 *	aio_fsync
 *	aio_cancel
 */

#include "libaio.h"
#include <sys/file.h>

extern int __fdsync(int, int);
extern aio_req_t *_aio_hash_find(aio_result_t *);

/* __aio_suspend stuff */

extern	int	_aio_kernel_suspend;
extern	int	_aio_suscv_cnt;

/* __aio_waitn stuff */

static	mutex_t	__aio_waitn_mutex = DEFAULTMUTEX; /* 1 aio_waitn per process */
static	cond_t	_aio_waitn_cv = DEFAULTCV;	/* wait for end of aio_waitn */
extern	int	_aio_flags;
extern	cond_t	_aio_iowait_cv;
extern	int	_aio_doneq_cnt;
extern	int	_aio_outstand_cnt;
extern	int	_aio_waitncnt;

static int _aio_check_timeout(const struct timespec *, struct timespec *,
	int *);

/* defines for timedwait in __aio_waitn()  and __aio_suspend() */
#define	AIO_TIMEOUT_INDEF	-1
#define	AIO_TIMEOUT_POLL	0
#define	AIO_TIMEOUT_WAIT	1
#define	AIO_TIMEOUT_UNDEF	2

/*
 * List I/O list head stuff
 */
static aio_lio_t *_lio_head_freelist = NULL;
static int _aio_lio_alloc(aio_lio_t **);
static void _aio_lio_free(aio_lio_t *);
static void _lio_list_decr(aio_lio_t *);

int
__aio_read(aiocb_t *cb)
{
	aio_lio_t	*head = NULL;

	if ((cb == NULL) || cb->aio_reqprio < 0) {
		errno = EINVAL;
		return (-1);
	}

	cb->aio_lio_opcode = LIO_READ;
	return (_aio_rw(cb, head, &__nextworker_rd, AIOAREAD,
	    (AIO_KAIO | AIO_NO_DUPS), NULL));
}

int
__aio_write(aiocb_t *cb)
{
	aio_lio_t	*head = NULL;

	if ((cb == NULL) || cb->aio_reqprio < 0) {
		errno = EINVAL;
		return (-1);
	}

	cb->aio_lio_opcode = LIO_WRITE;
	return (_aio_rw(cb, head, &__nextworker_wr, AIOAWRITE,
	    (AIO_KAIO | AIO_NO_DUPS), NULL));
}


int
__lio_listio(int mode, aiocb_t * const list[],
    int nent, struct sigevent *sig)
{
	int 		i, err;
	int 		aio_ufs = 0;
	int 		oerrno = 0;
	aio_lio_t	*head = NULL;
	int		state = 0;
	static long	aio_list_max = 0;
	aio_worker_t 	**nextworker;
	int 		EIOflg = 0;
	int 		rw;
	int		do_kaio = 0;

	if (!_kaio_ok)
		_kaio_init();

	if (aio_list_max == 0)
		aio_list_max = sysconf(_SC_AIO_LISTIO_MAX);

	if (nent < 0 || (long)nent > aio_list_max) {
		errno = EINVAL;
		return (-1);
	}

	switch (mode) {
	case LIO_WAIT:
		state = NOCHECK;
		break;
	case LIO_NOWAIT:
		state = CHECK;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	for (i = 0; i < nent; i++) {
		if (list[i]) {
			if (list[i]->aio_lio_opcode != LIO_NOP) {
				list[i]->aio_state = state;
				if (KAIO_SUPPORTED(list[i]->aio_fildes))
					do_kaio++;
				else
					list[i]->aio_resultp.aio_errno =
					    ENOTSUP;
			} else
				list[i]->aio_state = NOCHECK;
		}
	}

	if (do_kaio) {
		if ((err = (int)_kaio(AIOLIO, mode, list, nent, sig)) == 0)
			return (0);
		oerrno = errno;
	} else {
		oerrno = errno = ENOTSUP;
		err = -1;
	}
	if ((err == -1) && (errno == ENOTSUP)) {
		err = errno = 0;
		/*
		 * If LIO_WAIT, or signal required, allocate a list head.
		 */
		if ((mode == LIO_WAIT) || ((sig) &&
		    (sig->sigev_notify == SIGEV_SIGNAL)))
			(void) _aio_lio_alloc(&head);
		if (head) {
			(void) mutex_lock(&head->lio_mutex);
			head->lio_mode = (char)mode;
			if ((mode == LIO_NOWAIT) && (sig) &&
			    (sig->sigev_notify != SIGEV_NONE) &&
			    (sig->sigev_signo > 0)) {
				head->lio_signo = sig->sigev_signo;
				head->lio_sigval.sival_ptr =
				    sig->sigev_value.sival_ptr;
			} else
				head->lio_signo = 0;
			head->lio_nent = head->lio_refcnt = nent;
			(void) mutex_unlock(&head->lio_mutex);
		}
		/*
		 * find UFS requests, errno == ENOTSUP/EBADFD,
		 */
		for (i = 0; i < nent; i++) {
			if (list[i] &&
			    ((list[i]->aio_resultp.aio_errno == ENOTSUP) ||
			    (list[i]->aio_resultp.aio_errno == EBADFD))) {
				if (list[i]->aio_lio_opcode == LIO_NOP) {
					if (head)
						_lio_list_decr(head);
					continue;
				}
				if (list[i]->aio_resultp.aio_errno == EBADFD)
					SET_KAIO_NOT_SUPPORTED(
					    list[i]->aio_fildes);
				if (list[i]->aio_reqprio < 0) {
					list[i]->aio_resultp.aio_errno =
					    EINVAL;
					list[i]->aio_resultp.aio_return = -1;
					EIOflg = 1;
					if (head)
						_lio_list_decr(head);
					continue;
				}
				/*
				 * submit an AIO request with flags AIO_NO_KAIO
				 * to avoid the kaio() syscall in _aio_rw()
				 */
				switch (list[i]->aio_lio_opcode) {
					case LIO_READ:
						rw = AIOAREAD;
						nextworker = &__nextworker_rd;
						break;
					case LIO_WRITE:
						rw = AIOAWRITE;
						nextworker = &__nextworker_wr;
						break;
				}
				if (sig && sig->sigev_notify == SIGEV_PORT)
					err = _aio_rw(list[i], head, nextworker,
					    rw, (AIO_NO_KAIO | AIO_NO_DUPS),
					    sig);
				else
					err = _aio_rw(list[i], head, nextworker,
					    rw, (AIO_NO_KAIO | AIO_NO_DUPS),
					    NULL);
				if (err != 0) {
					if (head)
						_lio_list_decr(head);
					list[i]->aio_resultp.aio_errno = err;
					EIOflg = 1;
				} else
					aio_ufs++;

			} else {
				if (head)
					_lio_list_decr(head);
				continue;
			}
		}
	}
	if (EIOflg) {
		errno = EIO;
		return (-1);
	}
	if ((mode == LIO_WAIT) && (oerrno == ENOTSUP)) {
		/*
		 * call kaio(AIOLIOWAIT) to get all outstanding
		 * kernel AIO requests
		 */
		if ((nent - aio_ufs) > 0) {
			(void) _kaio(AIOLIOWAIT, mode, list, nent, sig);
		}
		if (head && head->lio_nent > 0) {
			(void) mutex_lock(&head->lio_mutex);
			while (head->lio_refcnt > 0) {
				errno = cond_wait(&head->lio_cond_cv,
				    &head->lio_mutex);
				if (errno) {
					(void) mutex_unlock(&head->lio_mutex);
					return (-1);
				}
			}
			(void) mutex_unlock(&head->lio_mutex);
			for (i = 0; i < nent; i++) {
				if (list[i] &&
				    list[i]->aio_resultp.aio_errno) {
					errno = EIO;
					return (-1);
				}
			}
		}
		return (0);
	}
	return (err);
}

static void
_lio_list_decr(aio_lio_t *head)
{
	(void) mutex_lock(&head->lio_mutex);
	head->lio_nent--;
	head->lio_refcnt--;
	(void) mutex_unlock(&head->lio_mutex);
}

extern void _cancelon(void);
extern void _canceloff(void);

int
__aio_suspend(void **list, int nent, const timespec_t *timo, int largefile)
{
	int		cv_err;	/* error code from cond_xxx() */
	int		kerr;	/* error code from _kaio(AIOSUSPEND) */
	int		i;
	struct timespec	twait;	/* copy of timo for internal calculations */
	struct timespec	*wait = NULL;
	int		timedwait;
	int		req_outstanding;
	aiocb_t		**listp;
	aiocb64_t	**listp64;
	hrtime_t	hrtstart;
	hrtime_t	hrtend;
	hrtime_t	hrtres;

	if (nent <= 0) {
		errno = EINVAL;
		return (-1);
	}

	if (timo) {
		if (timo->tv_sec < 0 || timo->tv_nsec < 0 ||
		    timo->tv_nsec >= NANOSEC) {
			errno = EINVAL;
			return (-1);
		}
		/* Initialize start time if time monitoring desired */
		if (timo->tv_sec > 0 || timo->tv_nsec > 0) {
			timedwait = AIO_TIMEOUT_WAIT;
			hrtstart = gethrtime();
		} else {
			/* content of timeout = 0 : polling */
			timedwait = AIO_TIMEOUT_POLL;
		}
	} else {
		/* timeout pointer = NULL : wait indefinitely */
		timedwait = AIO_TIMEOUT_INDEF;
	}

	if (largefile) {
		/* _LARGEFILE64_SOURCE && !_LP64 */
		listp64 = (aiocb64_t **)list;
		for (i = 0; i < nent; i++) {
			if (listp64[i] && listp64[i]->aio_state == CHECK)
				listp64[i]->aio_state = CHECKED;
		}
	} else {
		listp = (aiocb_t **)list;
		for (i = 0; i < nent; i++) {
			if (listp[i] && listp[i]->aio_state == CHECK)
				listp[i]->aio_state = CHECKED;
		}
	}

	/*
	 * The next "if -case" is required to accelerate the
	 * access to completed RAW-IO requests.
	 */

	if ((_aio_doneq_cnt + _aio_outstand_cnt) == 0) {
		/* Only kernel requests pending */

		_cancelon();

		/*
		 * _aio_kernel_suspend is used to detect completed non RAW-IO
		 * requests.
		 * As long as this thread resides in the kernel (_kaio) further
		 * asynchronous non RAW-IO requests could be submitted.
		 */
		_aio_lock();
		_aio_kernel_suspend++;
		_aio_unlock();

		/*
		 * Always do the kaio() call without using the KAIO_SUPPORTED()
		 * checks because it is not mandatory to have a valid fd
		 * set in the list entries, only the resultp must be set.
		 *
		 * _kaio(AIOSUSPEND ...) return values :
		 *  0:  everythink ok, completed request found
		 * -1:  error
		 *  1:  no error : _aiodone awaked the _kaio(AIOSUSPEND,,)
		 *	system call using  _kaio(AIONOTIFY). It means, that some
		 *	non RAW-IOs completed inbetween.
		 */

		if (largefile)
			kerr = (int)_kaio(AIOSUSPEND64, list, nent, timo, -1);
		else
			kerr = (int)_kaio(AIOSUSPEND, list, nent, timo, -1);

		_aio_lock();
		_aio_kernel_suspend--;
		_aio_unlock();

		_canceloff();
		if (!kerr)
			return (0);
	} else {
		kerr = 1;	/* simulation: _kaio detected AIONOTIFY */
	}

	/* Return kernel error code, if no other IOs are outstanding */

	_aio_lock();
	req_outstanding = _aio_doneq_cnt + _aio_outstand_cnt;
	_aio_unlock();

	if (req_outstanding == 0) {
		/* no IOs outstanding in the thread pool */
		if (kerr == 1)
			/* return "no IOs completed" */
			errno = EAGAIN;
		return (-1);
	}

	/* IOs using the thread pool are outstanding */

	if (timedwait == AIO_TIMEOUT_WAIT) {
		/* time monitoring */
		hrtend = hrtstart + (hrtime_t)timo->tv_sec * (hrtime_t)NANOSEC +
		    (hrtime_t)timo->tv_nsec;
		hrtres = hrtend - gethrtime();
		if (hrtres <= 0)
			hrtres = 1;
		twait.tv_sec = hrtres / (hrtime_t)NANOSEC;
		twait.tv_nsec = hrtres % (hrtime_t)NANOSEC;
		wait = &twait;
	} else {
		if (timedwait == AIO_TIMEOUT_POLL) {
			twait = *timo;	/* content of timo = 0 : polling */
			wait = &twait;
		}
	}

	for (;;) {
		int	aio_errno;
		int	aio_inprogress;

		/* first scan file system requests */
		aio_inprogress = 0;
		if (largefile) {
			for (i = 0; i < nent; i++) {
				if (listp64[i] == NULL)
					continue;
				aio_errno = listp64[i]->aio_resultp.aio_errno;
				if (aio_errno == EINPROGRESS) {
					aio_inprogress = 1;
				} else {
					if (aio_errno != ECANCELED) {
						errno = 0;
						return (0);
					}
				}
			}
		} else {
			for (i = 0; i < nent; i++) {
				if (listp[i] == NULL)
					continue;
				aio_errno = listp[i]->aio_resultp.aio_errno;
				if (aio_errno == EINPROGRESS) {
					aio_inprogress = 1;
				} else {
					if (aio_errno != ECANCELED) {
						errno = 0;
						return (0);
					}
				}
			}
		}

		/*
		 * If there aren't outstanding I/Os in the thread pool then
		 * we have to return here, provided that all kernel RAW-IOs
		 * also completed.
		 * If the kernel was notified to return, then we have to check
		 * possible pending RAW-IOs.
		 */
		if (_aio_outstand_cnt == 0 && aio_inprogress == 0 &&
		    kerr != 1) {
			errno = EAGAIN;
			break;
		}

		/*
		 * There are outstanding IOs in the thread pool or the kernel
		 * was notified to return.
		 * Check pending RAW-IOs first.
		 */
		if (kerr == 1) {
			/*
			 * _aiodone just notified the kernel about
			 * completed non RAW-IOs (AIONOTIFY was detected).
			 */
			if (timedwait == AIO_TIMEOUT_WAIT) {
				/* Update remaining timeout for the kernel */
				hrtres = hrtend - gethrtime();
				if (hrtres <= 0) {
					/* timer expired */
					errno = EAGAIN;
					break;
				}
				wait->tv_sec = hrtres / (hrtime_t)NANOSEC;
				wait->tv_nsec = hrtres % (hrtime_t)NANOSEC;
			}
			_aio_lock();
			_aio_kernel_suspend++;
			_aio_unlock();

			_cancelon();
			if (largefile)
				kerr = (int)_kaio(AIOSUSPEND64, list, nent,
				    wait, -1);
			else
				kerr = (int)_kaio(AIOSUSPEND, list, nent,
				    wait, -1);
			_canceloff();

			_aio_lock();
			_aio_kernel_suspend--;
			_aio_unlock();

			if (!kerr) {
				return (0);
			}
		}

		if (timedwait == AIO_TIMEOUT_POLL) {
			errno = EAGAIN;
			break;
		}

		if (timedwait == AIO_TIMEOUT_WAIT) {
			/* Update remaining timeout */
			hrtres = hrtend - gethrtime();
			if (hrtres <= 0) {
				/* timer expired */
				errno = EAGAIN;
				break;
			}
			wait->tv_sec = hrtres / (hrtime_t)NANOSEC;
			wait->tv_nsec = hrtres % (hrtime_t)NANOSEC;
		}

		_aio_lock();
		if (_aio_outstand_cnt == 0) {
			_aio_unlock();
			continue;
		}

		_aio_suscv_cnt++;	/* ID for _aiodone (wake up) */

		if (timedwait == AIO_TIMEOUT_WAIT) {
			cv_err = cond_reltimedwait(&_aio_iowait_cv,
			    &__aio_mutex, wait);

			if (cv_err == ETIME)
				cv_err = EAGAIN;
		} else {
			/* wait indefinitely */
			cv_err = cond_wait(&_aio_iowait_cv, &__aio_mutex);
		}

		_aio_suscv_cnt--;
		_aio_unlock();

		if (cv_err) {
			errno = cv_err;
			break;
		}
	}
	return (-1);
}

int
__aio_error(aiocb_t *cb)
{
	aio_req_t *reqp;
	int aio_errno = cb->aio_resultp.aio_errno;

	if (aio_errno == EINPROGRESS) {
		if (cb->aio_state == CHECK) {
			/*
			 * Always do the kaio() call without using
			 * the KAIO_SUPPORTED()
			 * checks because it is not mandatory to
			 * have a valid fd
			 * set in the aiocb, only the resultp must be set.
			 */
			if (((int)_kaio(AIOERROR, cb)) == EINVAL) {
				errno = EINVAL;
				return (-1);
			}
		} else if (cb->aio_state == CHECKED)
			cb->aio_state =  CHECK;
	} else if (cb->aio_state == USERAIO) {
		_aio_lock();
		if (reqp = _aio_hash_find(&cb->aio_resultp)) {
			cb->aio_state = NOCHECK;
			_lio_remove(reqp->lio_head);
			(void) _aio_hash_del(reqp->req_resultp);
			(void) _aio_req_remove(reqp);
			_aio_req_free(reqp);
		}
		_aio_unlock();
	}
	return (aio_errno);
}

ssize_t
__aio_return(aiocb_t *cb)
{
	ssize_t ret;
	aio_req_t *reqp;

	/*
	 * graceful detection of an invalid cb is not possible. a
	 * SIGSEGV will be generated if it is invalid.
	 */
	if (cb == NULL) {
		errno = EINVAL;
		exit(-1);
	}

	/*
	 * we use this condition to indicate that
	 * aio_return has been called before
	 */
	if (cb->aio_resultp.aio_return == -1 &&
	    cb->aio_resultp.aio_errno == EINVAL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Before we return mark the result as being returned so that later
	 * calls to aio_return() will return the fact that the result has
	 * already been returned
	 */
	ret = cb->aio_resultp.aio_return;
	cb->aio_resultp.aio_return = -1;
	cb->aio_resultp.aio_errno = EINVAL;
	if (cb->aio_state == USERAIO) {
		_aio_lock();
		if (reqp = _aio_hash_find(&cb->aio_resultp)) {
			cb->aio_state = NOCHECK;
			_lio_remove(reqp->lio_head);
			(void) _aio_hash_del(reqp->req_resultp);
			(void) _aio_req_remove(reqp);
			_aio_req_free(reqp);
		}
		_aio_unlock();
	}
	return (ret);

}

void
_lio_remove(aio_lio_t *head)
{
	int refcnt;

	if (head) {
		(void) mutex_lock(&head->lio_mutex);
		refcnt = --head->lio_nent;
		(void) mutex_unlock(&head->lio_mutex);
		if (!refcnt)
			_aio_lio_free(head);
	}
}

void
_aio_remove(aio_req_t *reqp)
{
	_lio_remove(reqp->lio_head);
	_aio_lock();
	(void) _aio_hash_del(reqp->req_resultp);
	(void) _aio_req_remove(reqp);
	_aio_req_free(reqp);
	_aio_unlock();
}

int
_aio_lio_alloc(aio_lio_t **head)
{
	aio_lio_t	*lio_head;

	(void) mutex_lock(&__lio_mutex);
	if (_lio_head_freelist == NULL) {
		lio_head = (aio_lio_t *)malloc(sizeof (aio_lio_t));
	} else {
		lio_head = _lio_head_freelist;
		_lio_head_freelist = lio_head->lio_next;
	}
	if (lio_head == NULL) {
		(void) mutex_unlock(&__lio_mutex);
		return (-1);
	}
	(void) memset(lio_head, 0, sizeof (aio_lio_t));
	(void) cond_init(&lio_head->lio_cond_cv, USYNC_THREAD, NULL);
	(void) mutex_init(&lio_head->lio_mutex, USYNC_THREAD, NULL);
	*head = lio_head;
	(void) mutex_unlock(&__lio_mutex);
	return (0);
}

void
_aio_lio_free(aio_lio_t *head)
{
	(void) mutex_lock(&__lio_mutex);
	head->lio_next = _lio_head_freelist;
	_lio_head_freelist = head;
	(void) mutex_unlock(&__lio_mutex);
}

/*
 * This function returns the number of asynchronous I/O requests submitted.
 */

static int
__aio_fsync_bar(aiocb_t *cb, aio_lio_t *head, aio_worker_t *aiowp,
    int workerscnt)
{
	int i;
	int err;
	aio_worker_t *next = aiowp;

	for (i = 0; i < workerscnt; i++) {
		err = _aio_rw(cb, head, &next, AIOFSYNC, AIO_NO_KAIO, NULL);
		if (err != 0) {
			(void) mutex_lock(&head->lio_mutex);
			head->lio_mode = LIO_DESTROY;	/* ignore fsync */
			head->lio_nent -= workerscnt - i;
			head->lio_refcnt -= workerscnt - i;
			(void) mutex_unlock(&head->lio_mutex);
			errno = EAGAIN;
			return (i);
		}
		next = next->work_forw;
	}
	return (i);
}

/*
 * This function is called from aio_fsync(3RT).
 */

int
__aio_fsync(int op, aiocb_t *cb)
{
	struct stat buf;
	aio_lio_t *head;
	int	retval;

	if (cb == NULL) {
		return (0);
	}

	if ((op != O_DSYNC) && (op != O_SYNC)) {
		errno = EINVAL;
		return (-1);
	}

	if (fstat(cb->aio_fildes, &buf) < 0)
		return (-1);

	/*
	 * The first asynchronous I/O request in the current process
	 * will create a bunch of workers.
	 * If the sum of workers (read + write) is zero then the
	 * number of pending asynchronous I/O requests is zero.
	 * In such a case only execute the standard fsync(3C) or
	 * fdatasync(3RT) as appropriate (see flag of __fdsync()).
	 */
	if ((__wr_workerscnt + __rd_workerscnt) == 0) {
		if (op == O_DSYNC)
			return (__fdsync(cb->aio_fildes, FDSYNC));
		else
			return (__fdsync(cb->aio_fildes, FSYNC));
	}

	/*
	 * re-use aio_offset as the op field.
	 * 	O_DSYNC - fdatasync()
	 * 	O_SYNC - fsync()
	 */
	cb->aio_offset = op;
	cb->aio_lio_opcode = AIOFSYNC;

	/*
	 * create a list of fsync requests. the worker
	 * that gets the last request will do the fsync
	 * request.
	 */
	(void) _aio_lio_alloc(&head);
	if (head == NULL) {
		errno = EAGAIN;
		return (-1);
	}
	head->lio_mode = LIO_FSYNC;
	head->lio_signo = 0;
	head->lio_nent = head->lio_refcnt = __wr_workerscnt + __rd_workerscnt;
	/* insert an fsync request on every read workers' queue. */
	retval = __aio_fsync_bar(cb, head, __workers_rd, __rd_workerscnt);
	if (retval != __rd_workerscnt) {
		/*
		 * Less fsync requests than workers means that
		 * it was not possible to submit fsync requests to all
		 * workers.
		 * Actions:
		 * a) number of fsync requests submitted is 0:
		 *    => free allocated memory (aio_lio_t).
		 * b) number of fsync requests submitted is > 0:
		 *    => the last worker executing the fsync request
		 *	 will free the aio_lio_t struct.
		 */
		if (retval == 0)
			_aio_lio_free(head);
		return (-1);
	}

	/* insert an fsync request on every write workers' queue. */
	retval = __aio_fsync_bar(cb, head, __workers_wr, __wr_workerscnt);
	if (retval != __wr_workerscnt)
		return (-1);
	return (0);
}

int
__aio_cancel(int fd, aiocb_t *cb)
{
	aio_req_t *rp;
	aio_worker_t *aiowp;
	int done = 0;
	int canceled = 0;
	struct stat buf;

	if (fstat(fd, &buf) < 0)
		return (-1);

	if (cb != NULL) {
		if (cb->aio_state == USERAIO) {
			_aio_lock();
			rp = _aio_hash_find(&cb->aio_resultp);
			if (rp == NULL) {
				_aio_unlock();
				return (AIO_ALLDONE);
			} else {
				aiowp = rp->req_worker;
				(void) mutex_lock(&aiowp->work_qlock1);
				(void) _aio_cancel_req(aiowp, rp, &canceled,
				    &done);
				(void) mutex_unlock(&aiowp->work_qlock1);
				_aio_unlock();
				if (done)
					return (AIO_ALLDONE);
				else if (canceled)
					return (AIO_CANCELED);
				else
					return (AIO_NOTCANCELED);
			}
		}

		if (cb->aio_state == USERAIO_DONE)
			return (AIO_ALLDONE);

		return ((int)_kaio(AIOCANCEL, fd, cb));
	}

	return (aiocancel_all(fd));
}


/*
 * aio_waitn can be used to reap the results of several I/O operations that
 * were submitted asynchronously. The submission of I/Os can be done using
 * existing POSIX interfaces: lio_listio, aio_write or aio_read.
 * aio_waitn waits until "nwait" I/Os (supplied as a parameter) have
 * completed and it returns the descriptors for these I/Os in "list". The
 * maximum size of this list is given by "nent" and the actual number of I/Os
 * completed is returned in "nwait". Otherwise aio_waitn might also
 * return if the timeout expires. Additionally, aio_waitn returns 0 if
 * successful or -1 if an error occurred.
 */

/*ARGSUSED*/
int
__aio_waitn(void **list, uint_t nent, uint_t *nwait,
    const struct timespec *utimo, int largefile)
{
	int err = 0;
	uint_t dnwait = 0;	/* amount of requests in the waitn-done list */
	uint_t kwaitcnt;	/* expected "done" requests from kernel */
	uint_t knentcnt;	/* max. expected "done" requests from kernel */
	int uerrno = 0;
	int kerrno = 0;		/* save errno from _kaio() call */
	int timedwait = AIO_TIMEOUT_UNDEF;
	aio_req_t *aiorp;
#if	defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
	aiocb64_t *aiop64;
#endif
	struct timespec end;
	struct timespec twait;	/* copy of utimo for internal calculations */
	struct timespec *wait = NULL;

	if (nent == 0 || *nwait == 0 || *nwait > nent) {
		errno = EINVAL;
		return (-1);
	}

	if (nwait == NULL) {
		errno = EFAULT;
		return (-1);
	}

	/*
	 * Only one running aio_waitn call per process allowed.
	 * Further calls will be blocked here until the running
	 * call finishes.
	 */

	(void) mutex_lock(&__aio_waitn_mutex);

	while (_aio_flags & AIO_LIB_WAITN) {

		if (utimo && utimo->tv_sec == 0 && utimo->tv_nsec == 0) {
			(void) mutex_unlock(&__aio_waitn_mutex);
			*nwait = 0;
			return (0);
		}

		_aio_flags |= AIO_LIB_WAITN_PENDING;
		err = cond_wait(&_aio_waitn_cv, &__aio_waitn_mutex);
		if (err != 0) {
			(void) mutex_unlock(&__aio_waitn_mutex);
			*nwait = 0;
			errno = err;
			return (-1);
		}
	}

	_aio_flags |= AIO_LIB_WAITN;

	(void) mutex_unlock(&__aio_waitn_mutex);

	if (*nwait >= AIO_WAITN_MAXIOCBS) {
		err = _aio_check_timeout(utimo, &end, &timedwait);
		if (err) {
			*nwait = 0;
			return (-1);
		}

		if (timedwait != AIO_TIMEOUT_INDEF) {
			twait = *utimo;
			wait = &twait;
		}
	}

	/*
	 * _aio_lock() is not required at this time, but the
	 * condition is that "_aio_doneq_cnt" has to be updated
	 * before "_aio_outstand_cnt". Otherwise we could hit
	 * a zero value in both counters during the transition
	 * time (see _aiodone).
	 *
	 * If both counters are still set to zero, then only
	 * kernel requests are currently outstanding (raw-I/Os).
	 */

	if ((_aio_doneq_cnt + _aio_outstand_cnt) == 0) {

		for (;;) {
			kwaitcnt = *nwait - dnwait;
			knentcnt = nent - dnwait;
			if (knentcnt > AIO_WAITN_MAXIOCBS)
				knentcnt = AIO_WAITN_MAXIOCBS;

			kwaitcnt = (kwaitcnt > knentcnt) ? knentcnt : kwaitcnt;

			err = (int)_kaio(AIOWAITN, &list[dnwait], knentcnt,
			    &kwaitcnt, wait);

			if (err == 0) {
				dnwait += kwaitcnt;
				if (dnwait >= *nwait ||
				    *nwait < AIO_WAITN_MAXIOCBS)
					break;

				if (timedwait == AIO_TIMEOUT_WAIT) {
					err = _aio_get_timedelta(&end, wait);
					if (err ==  -1) {
						/* timer expired */
						errno = ETIME;
						break;
					}
				}
				continue;
			}

			if (errno == EAGAIN) {
				if (dnwait > 0)
					err = 0;
				break;
			}

			if (errno == ETIME || errno == EINTR) {
				dnwait += kwaitcnt;
				break;
			}

			/* fatal error */
			break;
		}

		*nwait = dnwait;

		/* check for pending aio_waitn() calls */
		(void) mutex_lock(&__aio_waitn_mutex);
		_aio_flags &= ~AIO_LIB_WAITN;
		if (_aio_flags & AIO_LIB_WAITN_PENDING) {
			_aio_flags &= ~AIO_LIB_WAITN_PENDING;
			(void) cond_signal(&_aio_waitn_cv);
		}
		(void) mutex_unlock(&__aio_waitn_mutex);

		return (err);
	}

	/* File system I/Os outstanding ... */

	if (timedwait == AIO_TIMEOUT_UNDEF) {
		err = _aio_check_timeout(utimo, &end, &timedwait);
		if (err) {
			*nwait = 0;
			return (-1);
		}

		if (timedwait != AIO_TIMEOUT_INDEF) {
			twait = *utimo;
			wait = &twait;
		}
	}

	for (;;) {
		uint_t	sum_reqs;

		/*
		 * Calculate sum of active non RAW-IO requests (sum_reqs).
		 * If the expected amount of completed requests (*nwait) is
		 * greater than the calculated sum (sum_reqs) then
		 * use _kaio to check pending RAW-IO requests.
		 */

		(void) mutex_lock(&__aio_mutex);
		sum_reqs = _aio_doneq_cnt + dnwait + _aio_outstand_cnt;
		kwaitcnt = (*nwait > sum_reqs) ? *nwait - sum_reqs : 0;
		(void) mutex_unlock(&__aio_mutex);

		if (kwaitcnt != 0) {

			/* possibly some kernel I/Os outstanding */

			knentcnt = nent - dnwait;
			if (knentcnt > AIO_WAITN_MAXIOCBS)
				knentcnt = AIO_WAITN_MAXIOCBS;

			kwaitcnt = (kwaitcnt > knentcnt) ? knentcnt : kwaitcnt;

			(void) mutex_lock(&__aio_waitn_mutex);
			_aio_flags |= AIO_WAIT_INPROGRESS;
			(void) mutex_unlock(&__aio_waitn_mutex);

			err = (int)_kaio(AIOWAITN, &list[dnwait], knentcnt,
			    &kwaitcnt, wait);

			(void) mutex_lock(&__aio_waitn_mutex);
			_aio_flags &= ~AIO_WAIT_INPROGRESS;
			(void) mutex_unlock(&__aio_waitn_mutex);

			if (err == 0) {
				dnwait += kwaitcnt;
			} else {
				switch (errno) {
				case EINVAL:
				case EAGAIN:
					/* don't wait for kernel I/Os */
					kerrno = 0; /* ignore _kaio() errno */
					(void) mutex_lock(&__aio_mutex);
					*nwait = _aio_doneq_cnt +
					    _aio_outstand_cnt + dnwait;
					(void) mutex_unlock(&__aio_mutex);
					err = 0;
					break;
				case EINTR:
				case ETIME:
					/* just scan for completed LIB I/Os */
					dnwait += kwaitcnt;
					timedwait = AIO_TIMEOUT_POLL;
					kerrno = errno;	/* save _kaio() errno */
					err = 0;
					break;
				default:
					kerrno = errno;	/* save _kaio() errno */
					break;
				}
			}

			if (err)
				break;		/* fatal kernel error */
		}

		/* check completed FS requests in the "done" queue */

		(void) mutex_lock(&__aio_mutex);
		while (_aio_doneq_cnt && (dnwait < nent)) {
			/* get done requests */
			if ((aiorp = _aio_req_remove(NULL)) != NULL) {
				(void) _aio_hash_del(aiorp->req_resultp);
				list[dnwait++] = aiorp->req_iocb;
#if	defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
				if (largefile) {
					aiop64 = (void *)aiorp->req_iocb;
					aiop64->aio_state = USERAIO_DONE;
				} else
#endif
					aiorp->req_iocb->aio_state =
					    USERAIO_DONE;
				_aio_req_free(aiorp);
			}
		}

		if (dnwait >= *nwait) {
			/* min. requested amount of completed I/Os satisfied */
			(void) mutex_unlock(&__aio_mutex);
			break;
		}

		if (timedwait == AIO_TIMEOUT_WAIT) {
			if ((err = _aio_get_timedelta(&end, wait)) == -1) {
				/* timer expired */
				(void) mutex_unlock(&__aio_mutex);
				uerrno = ETIME;
				break;
			}
		}

		/*
		 * If some I/Os are outstanding and we have to wait for them,
		 * then sleep here.
		 * _aiodone() will wakeup this thread as soon as the
		 * required amount of completed I/Os is done.
		 */

		if (_aio_outstand_cnt > 0 && timedwait != AIO_TIMEOUT_POLL) {

			/*
			 * _aiodone() will wake up this thread as soon as
			 * - _aio_waitncnt -requests are completed or
			 * - _aio_outstand_cnt becomes zero.
			 * cond_reltimedwait() could also return with
			 * timeout error (ETIME).
			 */

			if (*nwait < _aio_outstand_cnt)
				_aio_waitncnt = *nwait;
			else
				_aio_waitncnt = _aio_outstand_cnt;

			(void) mutex_lock(&__aio_waitn_mutex);
			_aio_flags |= AIO_IO_WAITING;
			(void) mutex_unlock(&__aio_waitn_mutex);

			if (wait)
				uerrno = cond_reltimedwait(&_aio_iowait_cv,
				    &__aio_mutex, wait);
			else
				uerrno = cond_wait(&_aio_iowait_cv,
				    &__aio_mutex);

			(void) mutex_lock(&__aio_waitn_mutex);
			_aio_flags &= ~AIO_IO_WAITING;
			(void) mutex_unlock(&__aio_waitn_mutex);

			if (uerrno == ETIME) {
				timedwait = AIO_TIMEOUT_POLL;
				(void) mutex_unlock(&__aio_mutex);
				continue;
			}

			if (uerrno != 0)
				timedwait = AIO_TIMEOUT_POLL;
		}

		(void) mutex_unlock(&__aio_mutex);
		if (timedwait == AIO_TIMEOUT_POLL) {
			/* polling or timer expired */
			break;
		}
	}

	/* check for pending aio_waitn() calls */
	(void) mutex_lock(&__aio_waitn_mutex);
	_aio_flags &= ~AIO_LIB_WAITN;
	if (_aio_flags & AIO_LIB_WAITN_PENDING) {
		_aio_flags &= ~AIO_LIB_WAITN_PENDING;
		(void) cond_signal(&_aio_waitn_cv);
	}
	(void) mutex_unlock(&__aio_waitn_mutex);

	*nwait = dnwait;

	errno = uerrno == 0 ? kerrno : uerrno;
	if (errno)
		err = -1;
	else
		err = 0;

	return (err);
}

/*
 * timedwait values :
 * AIO_TIMEOUT_POLL 	: polling
 * AIO_TIMEOUT_WAIT 	: timeout
 * AIO_TIMEOUT_INDEF	: wait indefinitely
 */
int
_aio_check_timeout(const struct timespec *utimo, struct timespec *end,
	int *timedwait)
{
	struct	timeval	curtime;

	if (utimo) {
		if ((utimo->tv_sec < 0) || (utimo->tv_nsec < 0) ||
		    (utimo->tv_nsec >= NANOSEC)) {
			/*
			 * invalid timer values => return EINVAL
			 * check for pending aio_waitn() calls
			 */
			(void) mutex_lock(&__aio_waitn_mutex);
			_aio_flags &= ~AIO_LIB_WAITN;
			if (_aio_flags & AIO_LIB_WAITN_PENDING) {
				_aio_flags &= ~AIO_LIB_WAITN_PENDING;
				(void) cond_signal(&_aio_waitn_cv);
			}
			(void) mutex_unlock(&__aio_waitn_mutex);
			errno = EINVAL;
			return (-1);
		}

		if ((utimo->tv_sec > 0) || (utimo->tv_nsec > 0)) {
			(void) gettimeofday(&curtime, NULL);
			end->tv_sec = utimo->tv_sec + curtime.tv_sec;
			end->tv_nsec = utimo->tv_nsec +
			    1000 * curtime.tv_usec;
			if (end->tv_nsec >= NANOSEC) {
				end->tv_nsec -= NANOSEC;
				end->tv_sec += 1;
			}
			*timedwait = AIO_TIMEOUT_WAIT;
		} else {
			/* polling */
			*timedwait = AIO_TIMEOUT_POLL;
		}
	} else {
		*timedwait = AIO_TIMEOUT_INDEF;		/* wait indefinitely */
	}
	return (0);
}

#if	defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
__aio_read64(aiocb64_t *cb)
{
	aio_lio_t	*head = NULL;

	if (cb == NULL || cb->aio_offset < 0 || cb->aio_reqprio < 0) {
		errno = EINVAL;
		return (-1);
	}

	cb->aio_lio_opcode = LIO_READ;
	return (_aio_rw64(cb, head, &__nextworker_rd, AIOAREAD64,
	    (AIO_KAIO | AIO_NO_DUPS), NULL));
}

int
__aio_write64(aiocb64_t *cb)
{
	aio_lio_t	*head = NULL;

	if (cb == NULL || cb->aio_offset < 0 || cb->aio_reqprio < 0) {
		errno = EINVAL;
		return (-1);
	}
	cb->aio_lio_opcode = LIO_WRITE;
	return (_aio_rw64(cb, head, &__nextworker_wr, AIOAWRITE64,
	    (AIO_KAIO | AIO_NO_DUPS), NULL));
}

int
__lio_listio64(int mode, aiocb64_t * const list[],
    int nent, struct sigevent *sig)
{
	int 		i, err;
	int 		aio_ufs = 0;
	int 		oerrno = 0;
	aio_lio_t	*head = NULL;
	int		state = 0;
	static long	aio_list_max = 0;
	aio_worker_t 	**nextworker;
	int 		EIOflg = 0;
	int 		rw;
	int		do_kaio = 0;

	if (!_kaio_ok)
		_kaio_init();

	if (aio_list_max == 0)
		aio_list_max = sysconf(_SC_AIO_LISTIO_MAX);

	if (nent < 0 || nent > aio_list_max) {
		errno = EINVAL;
		return (-1);
	}

	switch (mode) {
	case LIO_WAIT:
		state = NOCHECK;
		break;
	case LIO_NOWAIT:
		state = CHECK;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	for (i = 0; i < nent; i++) {
		if (list[i]) {
			if (list[i]->aio_lio_opcode != LIO_NOP) {
				list[i]->aio_state = state;
				if (KAIO_SUPPORTED(list[i]->aio_fildes))
					do_kaio++;
				else
					list[i]->aio_resultp.aio_errno =
					    ENOTSUP;
			} else
				list[i]->aio_state = NOCHECK;
		}
	}

	if (do_kaio) {
		if ((err = (int)_kaio(AIOLIO64, mode, list, nent, sig)) == 0)
			return (0);
		oerrno = errno;
	} else {
		oerrno = errno = ENOTSUP;
		err = -1;
	}
	if ((err == -1) && (errno == ENOTSUP)) {
		err = errno = 0;
		/*
		 * If LIO_WAIT, or signal required, allocate a list head.
		 */
		if ((mode == LIO_WAIT) ||
		    ((sig) && (sig->sigev_notify == SIGEV_SIGNAL)))
			(void) _aio_lio_alloc(&head);
		if (head) {
			(void) mutex_lock(&head->lio_mutex);
			head->lio_mode = mode;
			if ((mode == LIO_NOWAIT) && (sig) &&
			    (sig->sigev_notify != SIGEV_NONE) &&
			    (sig->sigev_signo > 0)) {
				head->lio_signo = sig->sigev_signo;
				head->lio_sigval.sival_ptr =
				    sig->sigev_value.sival_ptr;
			} else
				head->lio_signo = 0;
			head->lio_nent = head->lio_refcnt = nent;
			(void) mutex_unlock(&head->lio_mutex);
		}
		/*
		 * find UFS requests, errno == ENOTSUP/EBADFD,
		 */
		for (i = 0; i < nent; i++) {
			if (list[i] &&
			    ((list[i]->aio_resultp.aio_errno == ENOTSUP) ||
			    (list[i]->aio_resultp.aio_errno == EBADFD))) {
				if (list[i]->aio_lio_opcode == LIO_NOP) {
					if (head)
						_lio_list_decr(head);
					continue;
				}
				if (list[i]->aio_resultp.aio_errno == EBADFD)
					SET_KAIO_NOT_SUPPORTED(
					    list[i]->aio_fildes);
				if (list[i]->aio_reqprio < 0) {
					list[i]->aio_resultp.aio_errno =
					    EINVAL;
					list[i]->aio_resultp.aio_return = -1;
					EIOflg = 1;
					if (head)
						_lio_list_decr(head);
					continue;
				}
				/*
				 * submit an AIO request with flags AIO_NO_KAIO
				 * to avoid the kaio() syscall in _aio_rw()
				 */
				switch (list[i]->aio_lio_opcode) {
					case LIO_READ:
						rw = AIOAREAD64;
						nextworker = &__nextworker_rd;
						break;
					case LIO_WRITE:
						rw = AIOAWRITE64;
						nextworker = &__nextworker_wr;
						break;
				}
				if (sig && (sig->sigev_notify == SIGEV_PORT))
					err = _aio_rw64(list[i], head,
					    nextworker, rw,
					    (AIO_NO_KAIO | AIO_NO_DUPS), sig);
				else
					err = _aio_rw64(list[i], head,
					    nextworker, rw,
					    (AIO_NO_KAIO | AIO_NO_DUPS), NULL);
				if (err != 0) {
					if (head)
						_lio_list_decr(head);
					list[i]->aio_resultp.aio_errno = err;
					EIOflg = 1;
				} else
					aio_ufs++;

			} else {
				if (head)
					_lio_list_decr(head);
				continue;
			}
		}
	}
	if (EIOflg) {
		errno = EIO;
		return (-1);
	}
	if ((mode == LIO_WAIT) && (oerrno == ENOTSUP)) {
		/*
		 * call kaio(AIOLIOWAIT) to get all outstanding
		 * kernel AIO requests
		 */
		if ((nent - aio_ufs) > 0) {
			_kaio(AIOLIOWAIT, mode, list, nent, sig);
		}
		if (head && head->lio_nent > 0) {
			(void) mutex_lock(&head->lio_mutex);
			while (head->lio_refcnt > 0) {
				errno = cond_wait(&head->lio_cond_cv,
				    &head->lio_mutex);
				if (errno) {
					(void) mutex_unlock(&head->lio_mutex);
					return (-1);
				}
			}
			(void) mutex_unlock(&head->lio_mutex);
			for (i = 0; i < nent; i++) {
				if (list[i] &&
				    list[i]->aio_resultp.aio_errno) {
					errno = EIO;
					return (-1);
				}
			}
		}
		return (0);
	}
	return (err);
}

int
__aio_error64(aiocb64_t *cb)
{
	aio_req_t *reqp;
	int aio_errno = cb->aio_resultp.aio_errno;

	if (aio_errno == EINPROGRESS) {
		if (cb->aio_state == CHECK) {
			/*
			 * Always do the kaio() call without using
			 * the KAIO_SUPPORTED()
			 * checks because it is not mandatory to
			 * have a valid fd
			 * set in the aiocb, only the resultp must be set.
			 */
			if ((_kaio(AIOERROR64, cb)) == EINVAL) {
				errno = EINVAL;
				return (-1);
			}
		} else if (cb->aio_state == CHECKED)
			cb->aio_state =  CHECK;
		return (aio_errno);
	}

	if (cb->aio_state == USERAIO) {
		_aio_lock();
		if (reqp = _aio_hash_find(&cb->aio_resultp)) {
			cb->aio_state = NOCHECK;
			_lio_remove(reqp->lio_head);
			(void) _aio_hash_del(reqp->req_resultp);
			(void) _aio_req_remove(reqp);
			_aio_req_free(reqp);
		}
		_aio_unlock();
	}
	return (aio_errno);
}

ssize_t
__aio_return64(aiocb64_t *cb)
{
	aio_req_t *reqp;
	int ret;

	/*
	 * graceful detection of an invalid cb is not possible. a
	 * SIGSEGV will be generated if it is invalid.
	 */
	if (cb == NULL) {
		errno = EINVAL;
		exit(-1);
	}
	/*
	 * we use this condition to indicate that
	 * aio_return has been called before
	 */
	if (cb->aio_resultp.aio_return == -1 &&
	    cb->aio_resultp.aio_errno == EINVAL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Before we return mark the result as being returned so that later
	 * calls to aio_return() will return the fact that the result has
	 * already been returned
	 */
	ret = cb->aio_resultp.aio_return;
	cb->aio_resultp.aio_return = -1;
	cb->aio_resultp.aio_errno = EINVAL;
	if (cb->aio_state == USERAIO) {
		_aio_lock();
		if (reqp = _aio_hash_find(&cb->aio_resultp)) {
			cb->aio_state = NOCHECK;
			_lio_remove(reqp->lio_head);
			(void) _aio_hash_del(reqp->req_resultp);
			(void) _aio_req_remove(reqp);
			_aio_req_free(reqp);
		}
		_aio_unlock();
	}
	return (ret);
}

static int
__aio_fsync_bar64(aiocb64_t *cb, aio_lio_t *head, aio_worker_t *aiowp,
    int workerscnt)
{
	int i;
	int err;
	aio_worker_t *next = aiowp;

	for (i = 0; i < workerscnt; i++) {
		err = _aio_rw64(cb, head, &next, AIOFSYNC, AIO_NO_KAIO, NULL);
		if (err != 0) {
			(void) mutex_lock(&head->lio_mutex);
			head->lio_mode = LIO_DESTROY;	/* ignore fsync */
			head->lio_nent -= workerscnt - i;
			head->lio_refcnt -= workerscnt - i;
			(void) mutex_unlock(&head->lio_mutex);
			errno = EAGAIN;
			return (i);
		}
		next = next->work_forw;
	}
	return (i);
}

int
__aio_fsync64(int op, aiocb64_t *cb)
{
	struct stat buf;
	aio_lio_t *head;
	int retval;

	if (cb == NULL) {
		return (0);
	}

	if ((op != O_DSYNC) && (op != O_SYNC)) {
		errno = EINVAL;
		return (-1);
	}

	if (fstat(cb->aio_fildes, &buf) < 0)
		return (-1);

	if ((buf.st_mode & S_IWRITE) == 0) {
		errno = EBADF;
		return (-1);
	}

	/*
	 * The first asynchronous I/O request in the current process
	 * will create a bunch of workers.
	 * If the sum of workers (read + write) is zero then the
	 * number of pending asynchronous I/O requests is zero.
	 * In such a case only execute the standard fsync(3C) or
	 * fdatasync(3RT) as appropriate (see flag of __fdsync()).
	 */
	if ((__wr_workerscnt + __rd_workerscnt) == 0) {
		if (op == O_DSYNC)
			return (__fdsync(cb->aio_fildes, FDSYNC));
		else
			return (__fdsync(cb->aio_fildes, FSYNC));
	}

	/*
	 * re-use aio_offset as the op field.
	 * 	O_DSYNC - fdatasync()
	 * 	O_SYNC - fsync()
	 */
	cb->aio_offset = op;
	cb->aio_lio_opcode = AIOFSYNC;

	/*
	 * create a list of fsync requests. the worker
	 * that gets the last request will do the fsync
	 * request.
	 */
	(void) _aio_lio_alloc(&head);
	if (head == NULL) {
		errno = EAGAIN;
		return (-1);
	}

	head->lio_mode = LIO_FSYNC;
	head->lio_signo = 0;
	head->lio_nent = head->lio_refcnt = __wr_workerscnt + __rd_workerscnt;
	/* insert an fsync request on every read workers' queue. */
	retval = __aio_fsync_bar64(cb, head, __workers_rd, __rd_workerscnt);
	if (retval != __rd_workerscnt) {
		/*
		 * Less fsync requests than workers means that
		 * it was not possible to submit fsync requests to all
		 * workers.
		 * Actions:
		 * a) number of fsync requests submitted is 0:
		 *    => free allocated memory (aio_lio_t).
		 * b) number of fsync requests submitted is > 0:
		 *    => the last worker executing the fsync request
		 *	 will free the aio_lio_t struct.
		 */
		if (retval == 0)
			_aio_lio_free(head);
		return (-1);
	}

	/* insert an fsync request on every write workers' queue. */
	retval = __aio_fsync_bar64(cb, head, __workers_wr, __wr_workerscnt);
	if (retval != __wr_workerscnt)
		return (-1);
	return (0);
}

int
__aio_cancel64(int fd, aiocb64_t *cb)
{
	aio_req_t	*rp;
	aio_worker_t *aiowp;
	int done = 0;
	int canceled = 0;
	struct stat	buf;

	if (fstat(fd, &buf) < 0)
		return (-1);

	if (cb != NULL) {
		if (cb->aio_state == USERAIO) {
			_aio_lock();
			rp = _aio_hash_find(&cb->aio_resultp);
			if (rp == NULL) {
				_aio_unlock();
				return (AIO_ALLDONE);
			} else {
				aiowp = rp->req_worker;
				(void) mutex_lock(&aiowp->work_qlock1);
				(void) _aio_cancel_req(aiowp, rp, &canceled,
				    &done);
				(void) mutex_unlock(&aiowp->work_qlock1);
				_aio_unlock();
				if (done)
					return (AIO_ALLDONE);
				else if (canceled)
					return (AIO_CANCELED);
				else
					return (AIO_NOTCANCELED);
			}
		}
		return ((int)_kaio(AIOCANCEL, fd, cb));
	}

	return (aiocancel_all(fd));
}

#endif /* (_LARGEFILE64_SOURCE) && !defined(_LP64) */
