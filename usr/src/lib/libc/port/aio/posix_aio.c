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

/*
 * posix_aio.c implements the POSIX async. I/O functions.
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

#include "lint.h"
#include "thr_uberdata.h"
#include "libc.h"
#include "asyncio.h"
#include <atomic.h>
#include <sys/file.h>
#include <sys/port.h>

cond_t	_aio_waitn_cv = DEFAULTCV;	/* wait for end of aio_waitn */

static int _aio_check_timeout(const timespec_t *, timespec_t *, int *);

/* defines for timedwait in __aio_waitn()  and __aio_suspend() */
#define	AIO_TIMEOUT_INDEF	-1
#define	AIO_TIMEOUT_POLL	0
#define	AIO_TIMEOUT_WAIT	1
#define	AIO_TIMEOUT_UNDEF	2

/*
 * List I/O stuff
 */
static void _lio_list_decr(aio_lio_t *);
static long aio_list_max = 0;

int
aio_read(aiocb_t *aiocbp)
{
	if (aiocbp == NULL || aiocbp->aio_reqprio != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
		errno = EBUSY;
		return (-1);
	}
	if (_aio_sigev_thread(aiocbp) != 0)
		return (-1);
	aiocbp->aio_lio_opcode = LIO_READ;
	return (_aio_rw(aiocbp, NULL, &__nextworker_rw, AIOAREAD,
	    (AIO_KAIO | AIO_NO_DUPS)));
}

int
aio_write(aiocb_t *aiocbp)
{
	if (aiocbp == NULL || aiocbp->aio_reqprio != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
		errno = EBUSY;
		return (-1);
	}
	if (_aio_sigev_thread(aiocbp) != 0)
		return (-1);
	aiocbp->aio_lio_opcode = LIO_WRITE;
	return (_aio_rw(aiocbp, NULL, &__nextworker_rw, AIOAWRITE,
	    (AIO_KAIO | AIO_NO_DUPS)));
}

/*
 * __lio_listio() cancellation handler.
 */
/* ARGSUSED */
static void
_lio_listio_cleanup(aio_lio_t *head)
{
	int freeit = 0;

	ASSERT(MUTEX_HELD(&head->lio_mutex));
	if (head->lio_refcnt == 0) {
		ASSERT(head->lio_nent == 0);
		freeit = 1;
	}
	head->lio_waiting = 0;
	sig_mutex_unlock(&head->lio_mutex);
	if (freeit)
		_aio_lio_free(head);
}

int
lio_listio(int mode, aiocb_t *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
    int nent, struct sigevent *_RESTRICT_KYWD sigevp)
{
	int		aio_ufs = 0;
	int		oerrno = 0;
	aio_lio_t	*head = NULL;
	aiocb_t		*aiocbp;
	int		state = 0;
	int		EIOflg = 0;
	int		rw;
	int		do_kaio = 0;
	int		error;
	int		i;

	if (!_kaio_ok)
		_kaio_init();

	if (aio_list_max == 0)
		aio_list_max = sysconf(_SC_AIO_LISTIO_MAX);

	if (nent <= 0 || nent > aio_list_max) {
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
		if ((aiocbp = list[i]) == NULL)
			continue;
		if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
			errno = EBUSY;
			return (-1);
		}
		if (_aio_sigev_thread(aiocbp) != 0)
			return (-1);
		if (aiocbp->aio_lio_opcode == LIO_NOP)
			aiocbp->aio_state = NOCHECK;
		else {
			aiocbp->aio_state = state;
			if (KAIO_SUPPORTED(aiocbp->aio_fildes))
				do_kaio++;
			else
				aiocbp->aio_resultp.aio_errno = ENOTSUP;
		}
	}
	if (_aio_sigev_thread_init(sigevp) != 0)
		return (-1);

	if (do_kaio) {
		error = (int)_kaio(AIOLIO, mode, list, nent, sigevp);
		if (error == 0)
			return (0);
		oerrno = errno;
	} else {
		oerrno = errno = ENOTSUP;
		error = -1;
	}

	if (error == -1 && errno == ENOTSUP) {
		error = errno = 0;
		/*
		 * If LIO_WAIT, or notification required, allocate a list head.
		 */
		if (mode == LIO_WAIT ||
		    (sigevp != NULL &&
		    (sigevp->sigev_notify == SIGEV_SIGNAL ||
		    sigevp->sigev_notify == SIGEV_THREAD ||
		    sigevp->sigev_notify == SIGEV_PORT)))
			head = _aio_lio_alloc();
		if (head) {
			sig_mutex_lock(&head->lio_mutex);
			head->lio_mode = mode;
			head->lio_largefile = 0;
			if (mode == LIO_NOWAIT && sigevp != NULL) {
				if (sigevp->sigev_notify == SIGEV_THREAD) {
					head->lio_port = sigevp->sigev_signo;
					head->lio_event = AIOLIO;
					head->lio_sigevent = sigevp;
					head->lio_sigval.sival_ptr =
					    sigevp->sigev_value.sival_ptr;
				} else if (sigevp->sigev_notify == SIGEV_PORT) {
					port_notify_t *pn =
					    sigevp->sigev_value.sival_ptr;
					head->lio_port = pn->portnfy_port;
					head->lio_event = AIOLIO;
					head->lio_sigevent = sigevp;
					head->lio_sigval.sival_ptr =
					    pn->portnfy_user;
				} else {	/* SIGEV_SIGNAL */
					head->lio_signo = sigevp->sigev_signo;
					head->lio_sigval.sival_ptr =
					    sigevp->sigev_value.sival_ptr;
				}
			}
			head->lio_nent = head->lio_refcnt = nent;
			sig_mutex_unlock(&head->lio_mutex);
		}
		/*
		 * find UFS requests, errno == ENOTSUP/EBADFD,
		 */
		for (i = 0; i < nent; i++) {
			if ((aiocbp = list[i]) == NULL ||
			    aiocbp->aio_lio_opcode == LIO_NOP ||
			    (aiocbp->aio_resultp.aio_errno != ENOTSUP &&
			    aiocbp->aio_resultp.aio_errno != EBADFD)) {
				if (head)
					_lio_list_decr(head);
				continue;
			}
			if (aiocbp->aio_resultp.aio_errno == EBADFD)
				SET_KAIO_NOT_SUPPORTED(aiocbp->aio_fildes);
			if (aiocbp->aio_reqprio != 0) {
				aiocbp->aio_resultp.aio_errno = EINVAL;
				aiocbp->aio_resultp.aio_return = -1;
				EIOflg = 1;
				if (head)
					_lio_list_decr(head);
				continue;
			}
			/*
			 * submit an AIO request with flags AIO_NO_KAIO
			 * to avoid the kaio() syscall in _aio_rw()
			 */
			switch (aiocbp->aio_lio_opcode) {
			case LIO_READ:
				rw = AIOAREAD;
				break;
			case LIO_WRITE:
				rw = AIOAWRITE;
				break;
			}
			error = _aio_rw(aiocbp, head, &__nextworker_rw, rw,
			    (AIO_NO_KAIO | AIO_NO_DUPS));
			if (error == 0)
				aio_ufs++;
			else {
				if (head)
					_lio_list_decr(head);
				aiocbp->aio_resultp.aio_errno = error;
				EIOflg = 1;
			}
		}
	}
	if (EIOflg) {
		errno = EIO;
		return (-1);
	}
	if (mode == LIO_WAIT && oerrno == ENOTSUP) {
		/*
		 * call kaio(AIOLIOWAIT) to get all outstanding
		 * kernel AIO requests
		 */
		if ((nent - aio_ufs) > 0)
			(void) _kaio(AIOLIOWAIT, mode, list, nent, sigevp);
		if (head != NULL && head->lio_nent > 0) {
			sig_mutex_lock(&head->lio_mutex);
			while (head->lio_refcnt > 0) {
				int err;
				head->lio_waiting = 1;
				pthread_cleanup_push(_lio_listio_cleanup, head);
				err = sig_cond_wait(&head->lio_cond_cv,
				    &head->lio_mutex);
				pthread_cleanup_pop(0);
				head->lio_waiting = 0;
				if (err && head->lio_nent > 0) {
					sig_mutex_unlock(&head->lio_mutex);
					errno = err;
					return (-1);
				}
			}
			sig_mutex_unlock(&head->lio_mutex);
			ASSERT(head->lio_nent == 0 && head->lio_refcnt == 0);
			_aio_lio_free(head);
			for (i = 0; i < nent; i++) {
				if ((aiocbp = list[i]) != NULL &&
				    aiocbp->aio_resultp.aio_errno) {
					errno = EIO;
					return (-1);
				}
			}
		}
		return (0);
	}
	return (error);
}

static void
_lio_list_decr(aio_lio_t *head)
{
	sig_mutex_lock(&head->lio_mutex);
	head->lio_nent--;
	head->lio_refcnt--;
	sig_mutex_unlock(&head->lio_mutex);
}

/*
 * __aio_suspend() cancellation handler.
 */
/* ARGSUSED */
static void
_aio_suspend_cleanup(int *counter)
{
	ASSERT(MUTEX_HELD(&__aio_mutex));
	(*counter)--;		/* _aio_kernel_suspend or _aio_suscv_cnt */
	sig_mutex_unlock(&__aio_mutex);
}

static int
__aio_suspend(void **list, int nent, const timespec_t *timo, int largefile)
{
	int		cv_err;	/* error code from cond_xxx() */
	int		kerr;	/* error code from _kaio(AIOSUSPEND) */
	int		i;
	timespec_t	twait;	/* copy of timo for internal calculations */
	timespec_t	*wait = NULL;
	int		timedwait;
	int		req_outstanding;
	aiocb_t		**listp;
	aiocb_t		*aiocbp;
#if !defined(_LP64)
	aiocb64_t	**listp64;
	aiocb64_t	*aiocbp64;
#endif
	hrtime_t	hrtstart;
	hrtime_t	hrtend;
	hrtime_t	hrtres;

#if defined(_LP64)
	if (largefile)
		aio_panic("__aio_suspend: largefile set when _LP64 defined");
#endif

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

#if !defined(_LP64)
	if (largefile) {
		listp64 = (aiocb64_t **)list;
		for (i = 0; i < nent; i++) {
			if ((aiocbp64 = listp64[i]) != NULL &&
			    aiocbp64->aio_state == CHECK)
				aiocbp64->aio_state = CHECKED;
		}
	} else
#endif	/* !_LP64 */
	{
		listp = (aiocb_t **)list;
		for (i = 0; i < nent; i++) {
			if ((aiocbp = listp[i]) != NULL &&
			    aiocbp->aio_state == CHECK)
				aiocbp->aio_state = CHECKED;
		}
	}

	sig_mutex_lock(&__aio_mutex);

	/*
	 * The next "if -case" is required to accelerate the
	 * access to completed RAW-IO requests.
	 */
	if ((_aio_doneq_cnt + _aio_outstand_cnt) == 0) {
		/* Only kernel requests pending */

		/*
		 * _aio_kernel_suspend is used to detect completed non RAW-IO
		 * requests.
		 * As long as this thread resides in the kernel (_kaio) further
		 * asynchronous non RAW-IO requests could be submitted.
		 */
		_aio_kernel_suspend++;

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

		pthread_cleanup_push(_aio_suspend_cleanup,
		    &_aio_kernel_suspend);
		pthread_cleanup_push(sig_mutex_lock, &__aio_mutex);
		sig_mutex_unlock(&__aio_mutex);
		_cancel_prologue();
		kerr = (int)_kaio(largefile? AIOSUSPEND64 : AIOSUSPEND,
		    list, nent, timo, -1);
		_cancel_epilogue();
		pthread_cleanup_pop(1);	/* sig_mutex_lock(&__aio_mutex) */
		pthread_cleanup_pop(0);

		_aio_kernel_suspend--;

		if (!kerr) {
			sig_mutex_unlock(&__aio_mutex);
			return (0);
		}
	} else {
		kerr = 1;	/* simulation: _kaio detected AIONOTIFY */
	}

	/*
	 * Return kernel error code if no other IOs are outstanding.
	 */
	req_outstanding = _aio_doneq_cnt + _aio_outstand_cnt;

	sig_mutex_unlock(&__aio_mutex);

	if (req_outstanding == 0) {
		/* no IOs outstanding in the thread pool */
		if (kerr == 1)
			/* return "no IOs completed" */
			errno = EAGAIN;
		return (-1);
	}

	/*
	 * IOs using the thread pool are outstanding.
	 */
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
	} else if (timedwait == AIO_TIMEOUT_POLL) {
		twait = *timo;	/* content of timo = 0 : polling */
		wait = &twait;
	}

	for (;;) {
		int	error;
		int	inprogress;

		/* first scan file system requests */
		inprogress = 0;
		for (i = 0; i < nent; i++) {
#if !defined(_LP64)
			if (largefile) {
				if ((aiocbp64 = listp64[i]) == NULL)
					continue;
				error = aiocbp64->aio_resultp.aio_errno;
			} else
#endif
			{
				if ((aiocbp = listp[i]) == NULL)
					continue;
				error = aiocbp->aio_resultp.aio_errno;
			}
			if (error == EINPROGRESS)
				inprogress = 1;
			else if (error != ECANCELED) {
				errno = 0;
				return (0);
			}
		}

		sig_mutex_lock(&__aio_mutex);

		/*
		 * If there aren't outstanding I/Os in the thread pool then
		 * we have to return here, provided that all kernel RAW-IOs
		 * also completed.
		 * If the kernel was notified to return, then we have to check
		 * possible pending RAW-IOs.
		 */
		if (_aio_outstand_cnt == 0 && inprogress == 0 && kerr != 1) {
			sig_mutex_unlock(&__aio_mutex);
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
					sig_mutex_unlock(&__aio_mutex);
					errno = EAGAIN;
					break;
				}
				wait->tv_sec = hrtres / (hrtime_t)NANOSEC;
				wait->tv_nsec = hrtres % (hrtime_t)NANOSEC;
			}
			_aio_kernel_suspend++;

			pthread_cleanup_push(_aio_suspend_cleanup,
			    &_aio_kernel_suspend);
			pthread_cleanup_push(sig_mutex_lock, &__aio_mutex);
			sig_mutex_unlock(&__aio_mutex);
			_cancel_prologue();
			kerr = (int)_kaio(largefile? AIOSUSPEND64 : AIOSUSPEND,
			    list, nent, wait, -1);
			_cancel_epilogue();
			pthread_cleanup_pop(1);
			pthread_cleanup_pop(0);

			_aio_kernel_suspend--;

			if (!kerr) {
				sig_mutex_unlock(&__aio_mutex);
				return (0);
			}
		}

		if (timedwait == AIO_TIMEOUT_POLL) {
			sig_mutex_unlock(&__aio_mutex);
			errno = EAGAIN;
			break;
		}

		if (timedwait == AIO_TIMEOUT_WAIT) {
			/* Update remaining timeout */
			hrtres = hrtend - gethrtime();
			if (hrtres <= 0) {
				/* timer expired */
				sig_mutex_unlock(&__aio_mutex);
				errno = EAGAIN;
				break;
			}
			wait->tv_sec = hrtres / (hrtime_t)NANOSEC;
			wait->tv_nsec = hrtres % (hrtime_t)NANOSEC;
		}

		if (_aio_outstand_cnt == 0) {
			sig_mutex_unlock(&__aio_mutex);
			continue;
		}

		_aio_suscv_cnt++;	/* ID for _aiodone (wake up) */

		pthread_cleanup_push(_aio_suspend_cleanup, &_aio_suscv_cnt);
		if (timedwait == AIO_TIMEOUT_WAIT) {
			cv_err = sig_cond_reltimedwait(&_aio_iowait_cv,
			    &__aio_mutex, wait);
			if (cv_err == ETIME)
				cv_err = EAGAIN;
		} else {
			/* wait indefinitely */
			cv_err = sig_cond_wait(&_aio_iowait_cv, &__aio_mutex);
		}
		/* this decrements _aio_suscv_cnt and drops __aio_mutex */
		pthread_cleanup_pop(1);

		if (cv_err) {
			errno = cv_err;
			break;
		}
	}
	return (-1);
}

int
aio_suspend(const aiocb_t * const list[], int nent,
    const timespec_t *timeout)
{
	return (__aio_suspend((void **)list, nent, timeout, 0));
}

int
aio_error(const aiocb_t *aiocbp)
{
	const aio_result_t *resultp = &aiocbp->aio_resultp;
	aio_req_t *reqp;
	int error;

	if ((error = resultp->aio_errno) == EINPROGRESS) {
		if (aiocbp->aio_state == CHECK) {
			/*
			 * Always do the kaio() call without using the
			 * KAIO_SUPPORTED() checks because it is not
			 * mandatory to have a valid fd set in the
			 * aiocb, only the resultp must be set.
			 */
			if ((int)_kaio(AIOERROR, aiocbp) == EINVAL) {
				errno = EINVAL;
				return (-1);
			}
			error = resultp->aio_errno;
		} else if (aiocbp->aio_state == CHECKED) {
			((aiocb_t *)aiocbp)->aio_state = CHECK;
		}
	} else if (aiocbp->aio_state == USERAIO) {
		sig_mutex_lock(&__aio_mutex);
		if ((reqp = _aio_hash_del((aio_result_t *)resultp)) == NULL) {
			sig_mutex_unlock(&__aio_mutex);
			((aiocb_t *)aiocbp)->aio_state = CHECKED;
		} else {
			((aiocb_t *)aiocbp)->aio_state = NOCHECK;
			ASSERT(reqp->req_head == NULL);
			(void) _aio_req_remove(reqp);
			sig_mutex_unlock(&__aio_mutex);
			_aio_req_free(reqp);
		}
	}
	return (error);
}

ssize_t
aio_return(aiocb_t *aiocbp)
{
	aio_result_t *resultp = &aiocbp->aio_resultp;
	aio_req_t *reqp;
	int error;
	ssize_t retval;

	/*
	 * The _aiodone() function stores resultp->aio_return before
	 * storing resultp->aio_errno (with an membar_producer() in
	 * between).  We use membar_consumer() below to ensure proper
	 * memory ordering between _aiodone() and ourself.
	 */
	error = resultp->aio_errno;
	membar_consumer();
	retval = resultp->aio_return;

	/*
	 * we use this condition to indicate either that
	 * aio_return() has been called before or should
	 * not have been called yet.
	 */
	if ((retval == -1 && error == EINVAL) || error == EINPROGRESS) {
		errno = error;
		return (-1);
	}

	/*
	 * Before we return, mark the result as being returned so that later
	 * calls to aio_return() will return the fact that the result has
	 * already been returned.
	 */
	sig_mutex_lock(&__aio_mutex);
	/* retest, in case more than one thread actually got in here */
	if (resultp->aio_return == -1 && resultp->aio_errno == EINVAL) {
		sig_mutex_unlock(&__aio_mutex);
		errno = EINVAL;
		return (-1);
	}
	resultp->aio_return = -1;
	resultp->aio_errno = EINVAL;
	if ((reqp = _aio_hash_del(resultp)) == NULL)
		sig_mutex_unlock(&__aio_mutex);
	else {
		aiocbp->aio_state = NOCHECK;
		ASSERT(reqp->req_head == NULL);
		(void) _aio_req_remove(reqp);
		sig_mutex_unlock(&__aio_mutex);
		_aio_req_free(reqp);
	}

	if (retval == -1)
		errno = error;
	return (retval);
}

void
_lio_remove(aio_req_t *reqp)
{
	aio_lio_t *head;
	int refcnt;

	if ((head = reqp->req_head) != NULL) {
		sig_mutex_lock(&head->lio_mutex);
		ASSERT(head->lio_refcnt == head->lio_nent);
		refcnt = --head->lio_nent;
		head->lio_refcnt--;
		sig_mutex_unlock(&head->lio_mutex);
		if (refcnt == 0)
			_aio_lio_free(head);
		reqp->req_head = NULL;
	}
}

/*
 * This function returns the number of asynchronous I/O requests submitted.
 */
static int
__aio_fsync_bar(aiocb_t *aiocbp, aio_lio_t *head, aio_worker_t *aiowp,
    int workerscnt)
{
	int i;
	int error;
	aio_worker_t *next = aiowp;

	for (i = 0; i < workerscnt; i++) {
		error = _aio_rw(aiocbp, head, &next, AIOFSYNC, AIO_NO_KAIO);
		if (error != 0) {
			sig_mutex_lock(&head->lio_mutex);
			head->lio_mode = LIO_DESTROY;	/* ignore fsync */
			head->lio_nent -= workerscnt - i;
			head->lio_refcnt -= workerscnt - i;
			sig_mutex_unlock(&head->lio_mutex);
			errno = EAGAIN;
			return (i);
		}
		next = next->work_forw;
	}
	return (i);
}

int
aio_fsync(int op, aiocb_t *aiocbp)
{
	aio_lio_t *head;
	struct stat statb;
	int fret;

	if (aiocbp == NULL)
		return (0);
	if (op != O_DSYNC && op != O_SYNC) {
		errno = EINVAL;
		return (-1);
	}
	if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
		errno = EBUSY;
		return (-1);
	}
	if (fstat(aiocbp->aio_fildes, &statb) < 0)
		return (-1);
	if (_aio_sigev_thread(aiocbp) != 0)
		return (-1);

	/*
	 * Kernel aio_fsync() is not supported.
	 * We force user-level aio_fsync() just
	 * for the notification side-effect.
	 */
	if (!__uaio_ok && __uaio_init() == -1)
		return (-1);

	/*
	 * The first asynchronous I/O request in the current process will
	 * create a bunch of workers (via __uaio_init()).  If the number
	 * of workers is zero then the number of pending asynchronous I/O
	 * requests is zero.  In such a case only execute the standard
	 * fsync(3C) or fdatasync(3C) as appropriate.
	 */
	if (__rw_workerscnt == 0) {
		if (op == O_DSYNC)
			return (__fdsync(aiocbp->aio_fildes, FDSYNC_DATA));
		else
			return (__fdsync(aiocbp->aio_fildes, FDSYNC_FILE));
	}

	/*
	 * re-use aio_offset as the op field.
	 *	O_DSYNC - fdatasync()
	 *	O_SYNC - fsync()
	 */
	aiocbp->aio_offset = op;
	aiocbp->aio_lio_opcode = AIOFSYNC;

	/*
	 * Create a list of fsync requests.  The worker that
	 * gets the last request will do the fsync request.
	 */
	head = _aio_lio_alloc();
	if (head == NULL) {
		errno = EAGAIN;
		return (-1);
	}
	head->lio_mode = LIO_FSYNC;
	head->lio_nent = head->lio_refcnt = __rw_workerscnt;
	head->lio_largefile = 0;

	/*
	 * Insert an fsync request on every worker's queue.
	 */
	fret = __aio_fsync_bar(aiocbp, head, __workers_rw, __rw_workerscnt);
	if (fret != __rw_workerscnt) {
		/*
		 * Fewer fsync requests than workers means that it was
		 * not possible to submit fsync requests to all workers.
		 * Actions:
		 * a) number of fsync requests submitted is 0:
		 *    => free allocated memory (aio_lio_t).
		 * b) number of fsync requests submitted is > 0:
		 *    => the last worker executing the fsync request
		 *	 will free the aio_lio_t struct.
		 */
		if (fret == 0)
			_aio_lio_free(head);
		return (-1);
	}
	return (0);
}

int
aio_cancel(int fd, aiocb_t *aiocbp)
{
	aio_req_t *reqp;
	aio_worker_t *aiowp;
	int done = 0;
	int canceled = 0;
	struct stat buf;

	if (fstat(fd, &buf) < 0)
		return (-1);

	if (aiocbp != NULL) {
		if (fd != aiocbp->aio_fildes) {
			errno = EINVAL;
			return (-1);
		}
		if (aiocbp->aio_state == USERAIO) {
			sig_mutex_lock(&__aio_mutex);
			reqp = _aio_hash_find(&aiocbp->aio_resultp);
			if (reqp == NULL) {
				sig_mutex_unlock(&__aio_mutex);
				return (AIO_ALLDONE);
			}
			aiowp = reqp->req_worker;
			sig_mutex_lock(&aiowp->work_qlock1);
			(void) _aio_cancel_req(aiowp, reqp, &canceled, &done);
			sig_mutex_unlock(&aiowp->work_qlock1);
			sig_mutex_unlock(&__aio_mutex);
			if (done)
				return (AIO_ALLDONE);
			if (canceled)
				return (AIO_CANCELED);
			return (AIO_NOTCANCELED);
		}
		if (aiocbp->aio_state == USERAIO_DONE)
			return (AIO_ALLDONE);
		return ((int)_kaio(AIOCANCEL, fd, aiocbp));
	}

	return (aiocancel_all(fd));
}

/*
 * __aio_waitn() cancellation handler.
 */
static void
_aio_waitn_cleanup(void *arg __unused)
{
	ASSERT(MUTEX_HELD(&__aio_mutex));

	/* check for pending aio_waitn() calls */
	_aio_flags &= ~(AIO_LIB_WAITN | AIO_WAIT_INPROGRESS | AIO_IO_WAITING);
	if (_aio_flags & AIO_LIB_WAITN_PENDING) {
		_aio_flags &= ~AIO_LIB_WAITN_PENDING;
		(void) cond_signal(&_aio_waitn_cv);
	}

	sig_mutex_unlock(&__aio_mutex);
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
static int
__aio_waitn(void **list, uint_t nent, uint_t *nwait, const timespec_t *utimo)
{
	int error = 0;
	uint_t dnwait = 0;	/* amount of requests in the waitn-done list */
	uint_t kwaitcnt;	/* expected "done" requests from kernel */
	uint_t knentcnt;	/* max. expected "done" requests from kernel */
	int uerrno = 0;
	int kerrno = 0;		/* save errno from _kaio() call */
	int timedwait = AIO_TIMEOUT_UNDEF;
	aio_req_t *reqp;
	timespec_t end;
	timespec_t twait;	/* copy of utimo for internal calculations */
	timespec_t *wait = NULL;

	if (nent == 0 || *nwait == 0 || *nwait > nent) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Only one running aio_waitn call per process allowed.
	 * Further calls will be blocked here until the running
	 * call finishes.
	 */

	sig_mutex_lock(&__aio_mutex);

	while (_aio_flags & AIO_LIB_WAITN) {
		if (utimo && utimo->tv_sec == 0 && utimo->tv_nsec == 0) {
			sig_mutex_unlock(&__aio_mutex);
			*nwait = 0;
			return (0);
		}
		_aio_flags |= AIO_LIB_WAITN_PENDING;
		pthread_cleanup_push(sig_mutex_unlock, &__aio_mutex);
		error = sig_cond_wait(&_aio_waitn_cv, &__aio_mutex);
		pthread_cleanup_pop(0);
		if (error != 0) {
			sig_mutex_unlock(&__aio_mutex);
			*nwait = 0;
			errno = error;
			return (-1);
		}
	}

	pthread_cleanup_push(_aio_waitn_cleanup, NULL);

	_aio_flags |= AIO_LIB_WAITN;

	if (_aio_check_timeout(utimo, &end, &timedwait) != 0) {
		error = -1;
		dnwait = 0;
		goto out;
	}
	if (timedwait != AIO_TIMEOUT_INDEF) {
		twait = *utimo;
		wait = &twait;
	}

	/*
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

			pthread_cleanup_push(sig_mutex_lock, &__aio_mutex);
			sig_mutex_unlock(&__aio_mutex);
			_cancel_prologue();
			error = (int)_kaio(AIOWAITN, &list[dnwait], knentcnt,
			    &kwaitcnt, wait);
			_cancel_epilogue();
			pthread_cleanup_pop(1);

			if (error == 0) {
				dnwait += kwaitcnt;
				if (dnwait >= *nwait ||
				    *nwait < AIO_WAITN_MAXIOCBS)
					break;
				if (timedwait == AIO_TIMEOUT_WAIT) {
					error = _aio_get_timedelta(&end, wait);
					if (error ==  -1) {
						/* timer expired */
						errno = ETIME;
						break;
					}
				}
				continue;
			}
			if (errno == EAGAIN) {
				if (dnwait > 0)
					error = 0;
				break;
			}
			if (errno == ETIME || errno == EINTR) {
				dnwait += kwaitcnt;
				break;
			}
			/* fatal error */
			break;
		}

		goto out;
	}

	/* File system I/Os outstanding ... */

	if (timedwait == AIO_TIMEOUT_UNDEF) {
		if (_aio_check_timeout(utimo, &end, &timedwait) != 0) {
			error = -1;
			dnwait = 0;
			goto out;
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
		sum_reqs = _aio_doneq_cnt + dnwait + _aio_outstand_cnt;
		kwaitcnt = (*nwait > sum_reqs) ? *nwait - sum_reqs : 0;

		if (kwaitcnt != 0) {
			/* possibly some kernel I/Os outstanding */
			knentcnt = nent - dnwait;
			if (knentcnt > AIO_WAITN_MAXIOCBS)
				knentcnt = AIO_WAITN_MAXIOCBS;
			kwaitcnt = (kwaitcnt > knentcnt) ? knentcnt : kwaitcnt;

			_aio_flags |= AIO_WAIT_INPROGRESS;

			pthread_cleanup_push(sig_mutex_lock, &__aio_mutex);
			sig_mutex_unlock(&__aio_mutex);
			_cancel_prologue();
			error = (int)_kaio(AIOWAITN, &list[dnwait], knentcnt,
			    &kwaitcnt, wait);
			_cancel_epilogue();
			pthread_cleanup_pop(1);

			_aio_flags &= ~AIO_WAIT_INPROGRESS;

			if (error == 0) {
				dnwait += kwaitcnt;
			} else {
				switch (errno) {
				case EINVAL:
				case EAGAIN:
					/* don't wait for kernel I/Os */
					kerrno = 0; /* ignore _kaio() errno */
					*nwait = _aio_doneq_cnt +
					    _aio_outstand_cnt + dnwait;
					error = 0;
					break;
				case EINTR:
				case ETIME:
					/* just scan for completed LIB I/Os */
					dnwait += kwaitcnt;
					timedwait = AIO_TIMEOUT_POLL;
					kerrno = errno;	/* save _kaio() errno */
					error = 0;
					break;
				default:
					kerrno = errno;	/* save _kaio() errno */
					break;
				}
			}
			if (error)
				break;		/* fatal kernel error */
		}

		/* check completed FS requests in the "done" queue */

		while (_aio_doneq_cnt && dnwait < nent) {
			/* get done requests */
			if ((reqp = _aio_req_remove(NULL)) != NULL) {
				(void) _aio_hash_del(reqp->req_resultp);
				list[dnwait++] = reqp->req_aiocbp;
				_aio_req_mark_done(reqp);
				_lio_remove(reqp);
				_aio_req_free(reqp);
			}
		}

		if (dnwait >= *nwait) {
			/* min. requested amount of completed I/Os satisfied */
			break;
		}
		if (timedwait == AIO_TIMEOUT_WAIT &&
		    (error = _aio_get_timedelta(&end, wait)) == -1) {
			/* timer expired */
			uerrno = ETIME;
			break;
		}

		/*
		 * If some I/Os are outstanding and we have to wait for them,
		 * then sleep here.  _aiodone() will call _aio_waitn_wakeup()
		 * to wakeup this thread as soon as the required amount of
		 * completed I/Os is done.
		 */
		if (_aio_outstand_cnt > 0 && timedwait != AIO_TIMEOUT_POLL) {
			/*
			 * _aio_waitn_wakeup() will wake up this thread when:
			 * - _aio_waitncnt requests are completed or
			 * - _aio_outstand_cnt becomes zero.
			 * sig_cond_reltimedwait() could also return with
			 * a timeout error (ETIME).
			 */
			if (*nwait < _aio_outstand_cnt)
				_aio_waitncnt = *nwait;
			else
				_aio_waitncnt = _aio_outstand_cnt;

			_aio_flags |= AIO_IO_WAITING;

			if (wait)
				uerrno = sig_cond_reltimedwait(&_aio_iowait_cv,
				    &__aio_mutex, wait);
			else
				uerrno = sig_cond_wait(&_aio_iowait_cv,
				    &__aio_mutex);

			_aio_flags &= ~AIO_IO_WAITING;

			if (uerrno == ETIME) {
				timedwait = AIO_TIMEOUT_POLL;
				continue;
			}
			if (uerrno != 0)
				timedwait = AIO_TIMEOUT_POLL;
		}

		if (timedwait == AIO_TIMEOUT_POLL) {
			/* polling or timer expired */
			break;
		}
	}

	errno = uerrno == 0 ? kerrno : uerrno;
	if (errno)
		error = -1;
	else
		error = 0;

out:
	*nwait = dnwait;

	pthread_cleanup_pop(1);		/* drops __aio_mutex */

	return (error);
}

int
aio_waitn(aiocb_t *list[], uint_t nent, uint_t *nwait,
    const timespec_t *timeout)
{
	return (__aio_waitn((void **)list, nent, nwait, timeout));
}

void
_aio_waitn_wakeup(void)
{
	/*
	 * __aio_waitn() sets AIO_IO_WAITING to notify _aiodone() that
	 * it is waiting for completed I/Os. The number of required
	 * completed I/Os is stored into "_aio_waitncnt".
	 * aio_waitn() is woken up when
	 * - there are no further outstanding I/Os
	 *   (_aio_outstand_cnt == 0) or
	 * - the expected number of I/Os has completed.
	 * Only one __aio_waitn() function waits for completed I/Os at
	 * a time.
	 *
	 * __aio_suspend() increments "_aio_suscv_cnt" to notify
	 * _aiodone() that at least one __aio_suspend() call is
	 * waiting for completed I/Os.
	 * There could be more than one __aio_suspend() function
	 * waiting for completed I/Os. Because every function should
	 * be waiting for different I/Os, _aiodone() has to wake up all
	 * __aio_suspend() functions each time.
	 * Every __aio_suspend() function will compare the recently
	 * completed I/O with its own list.
	 */
	ASSERT(MUTEX_HELD(&__aio_mutex));
	if (_aio_flags & AIO_IO_WAITING) {
		if (_aio_waitncnt > 0)
			_aio_waitncnt--;
		if (_aio_outstand_cnt == 0 || _aio_waitncnt == 0 ||
		    _aio_suscv_cnt > 0)
			(void) cond_broadcast(&_aio_iowait_cv);
	} else {
		/* Wake up waiting aio_suspend calls */
		if (_aio_suscv_cnt > 0)
			(void) cond_broadcast(&_aio_iowait_cv);
	}
}

/*
 * timedwait values :
 * AIO_TIMEOUT_POLL	: polling
 * AIO_TIMEOUT_WAIT	: timeout
 * AIO_TIMEOUT_INDEF	: wait indefinitely
 */
static int
_aio_check_timeout(const timespec_t *utimo, timespec_t *end, int *timedwait)
{
	struct	timeval	curtime;

	if (utimo) {
		if (utimo->tv_sec < 0 || utimo->tv_nsec < 0 ||
		    utimo->tv_nsec >= NANOSEC) {
			errno = EINVAL;
			return (-1);
		}
		if (utimo->tv_sec > 0 || utimo->tv_nsec > 0) {
			(void) gettimeofday(&curtime, NULL);
			end->tv_sec = utimo->tv_sec + curtime.tv_sec;
			end->tv_nsec = utimo->tv_nsec + 1000 * curtime.tv_usec;
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

#if !defined(_LP64)

int
aio_read64(aiocb64_t *aiocbp)
{
	if (aiocbp == NULL || aiocbp->aio_reqprio != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
		errno = EBUSY;
		return (-1);
	}
	if (_aio_sigev_thread64(aiocbp) != 0)
		return (-1);
	aiocbp->aio_lio_opcode = LIO_READ;
	return (_aio_rw64(aiocbp, NULL, &__nextworker_rw, AIOAREAD64,
	    (AIO_KAIO | AIO_NO_DUPS)));
}

int
aio_write64(aiocb64_t *aiocbp)
{
	if (aiocbp == NULL || aiocbp->aio_reqprio != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
		errno = EBUSY;
		return (-1);
	}
	if (_aio_sigev_thread64(aiocbp) != 0)
		return (-1);
	aiocbp->aio_lio_opcode = LIO_WRITE;
	return (_aio_rw64(aiocbp, NULL, &__nextworker_rw, AIOAWRITE64,
	    (AIO_KAIO | AIO_NO_DUPS)));
}

int
lio_listio64(int mode, aiocb64_t *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
    int nent, struct sigevent *_RESTRICT_KYWD sigevp)
{
	int		aio_ufs = 0;
	int		oerrno = 0;
	aio_lio_t	*head = NULL;
	aiocb64_t	*aiocbp;
	int		state = 0;
	int		EIOflg = 0;
	int		rw;
	int		do_kaio = 0;
	int		error;
	int		i;

	if (!_kaio_ok)
		_kaio_init();

	if (aio_list_max == 0)
		aio_list_max = sysconf(_SC_AIO_LISTIO_MAX);

	if (nent <= 0 || nent > aio_list_max) {
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
		if ((aiocbp = list[i]) == NULL)
			continue;
		if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
			errno = EBUSY;
			return (-1);
		}
		if (_aio_sigev_thread64(aiocbp) != 0)
			return (-1);
		if (aiocbp->aio_lio_opcode == LIO_NOP)
			aiocbp->aio_state = NOCHECK;
		else {
			aiocbp->aio_state = state;
			if (KAIO_SUPPORTED(aiocbp->aio_fildes))
				do_kaio++;
			else
				aiocbp->aio_resultp.aio_errno = ENOTSUP;
		}
	}
	if (_aio_sigev_thread_init(sigevp) != 0)
		return (-1);

	if (do_kaio) {
		error = (int)_kaio(AIOLIO64, mode, list, nent, sigevp);
		if (error == 0)
			return (0);
		oerrno = errno;
	} else {
		oerrno = errno = ENOTSUP;
		error = -1;
	}

	if (error == -1 && errno == ENOTSUP) {
		error = errno = 0;
		/*
		 * If LIO_WAIT, or notification required, allocate a list head.
		 */
		if (mode == LIO_WAIT ||
		    (sigevp != NULL &&
		    (sigevp->sigev_notify == SIGEV_SIGNAL ||
		    sigevp->sigev_notify == SIGEV_THREAD ||
		    sigevp->sigev_notify == SIGEV_PORT)))
			head = _aio_lio_alloc();
		if (head) {
			sig_mutex_lock(&head->lio_mutex);
			head->lio_mode = mode;
			head->lio_largefile = 1;
			if (mode == LIO_NOWAIT && sigevp != NULL) {
				if (sigevp->sigev_notify == SIGEV_THREAD) {
					head->lio_port = sigevp->sigev_signo;
					head->lio_event = AIOLIO64;
					head->lio_sigevent = sigevp;
					head->lio_sigval.sival_ptr =
					    sigevp->sigev_value.sival_ptr;
				} else if (sigevp->sigev_notify == SIGEV_PORT) {
					port_notify_t *pn =
					    sigevp->sigev_value.sival_ptr;
					head->lio_port = pn->portnfy_port;
					head->lio_event = AIOLIO64;
					head->lio_sigevent = sigevp;
					head->lio_sigval.sival_ptr =
					    pn->portnfy_user;
				} else {	/* SIGEV_SIGNAL */
					head->lio_signo = sigevp->sigev_signo;
					head->lio_sigval.sival_ptr =
					    sigevp->sigev_value.sival_ptr;
				}
			}
			head->lio_nent = head->lio_refcnt = nent;
			sig_mutex_unlock(&head->lio_mutex);
		}
		/*
		 * find UFS requests, errno == ENOTSUP/EBADFD,
		 */
		for (i = 0; i < nent; i++) {
			if ((aiocbp = list[i]) == NULL ||
			    aiocbp->aio_lio_opcode == LIO_NOP ||
			    (aiocbp->aio_resultp.aio_errno != ENOTSUP &&
			    aiocbp->aio_resultp.aio_errno != EBADFD)) {
				if (head)
					_lio_list_decr(head);
				continue;
			}
			if (aiocbp->aio_resultp.aio_errno == EBADFD)
				SET_KAIO_NOT_SUPPORTED(aiocbp->aio_fildes);
			if (aiocbp->aio_reqprio != 0) {
				aiocbp->aio_resultp.aio_errno = EINVAL;
				aiocbp->aio_resultp.aio_return = -1;
				EIOflg = 1;
				if (head)
					_lio_list_decr(head);
				continue;
			}
			/*
			 * submit an AIO request with flags AIO_NO_KAIO
			 * to avoid the kaio() syscall in _aio_rw()
			 */
			switch (aiocbp->aio_lio_opcode) {
			case LIO_READ:
				rw = AIOAREAD64;
				break;
			case LIO_WRITE:
				rw = AIOAWRITE64;
				break;
			}
			error = _aio_rw64(aiocbp, head, &__nextworker_rw, rw,
			    (AIO_NO_KAIO | AIO_NO_DUPS));
			if (error == 0)
				aio_ufs++;
			else {
				if (head)
					_lio_list_decr(head);
				aiocbp->aio_resultp.aio_errno = error;
				EIOflg = 1;
			}
		}
	}
	if (EIOflg) {
		errno = EIO;
		return (-1);
	}
	if (mode == LIO_WAIT && oerrno == ENOTSUP) {
		/*
		 * call kaio(AIOLIOWAIT) to get all outstanding
		 * kernel AIO requests
		 */
		if ((nent - aio_ufs) > 0)
			(void) _kaio(AIOLIOWAIT, mode, list, nent, sigevp);
		if (head != NULL && head->lio_nent > 0) {
			sig_mutex_lock(&head->lio_mutex);
			while (head->lio_refcnt > 0) {
				int err;
				head->lio_waiting = 1;
				pthread_cleanup_push(_lio_listio_cleanup, head);
				err = sig_cond_wait(&head->lio_cond_cv,
				    &head->lio_mutex);
				pthread_cleanup_pop(0);
				head->lio_waiting = 0;
				if (err && head->lio_nent > 0) {
					sig_mutex_unlock(&head->lio_mutex);
					errno = err;
					return (-1);
				}
			}
			sig_mutex_unlock(&head->lio_mutex);
			ASSERT(head->lio_nent == 0 && head->lio_refcnt == 0);
			_aio_lio_free(head);
			for (i = 0; i < nent; i++) {
				if ((aiocbp = list[i]) != NULL &&
				    aiocbp->aio_resultp.aio_errno) {
					errno = EIO;
					return (-1);
				}
			}
		}
		return (0);
	}
	return (error);
}

int
aio_suspend64(const aiocb64_t * const list[], int nent,
    const timespec_t *timeout)
{
	return (__aio_suspend((void **)list, nent, timeout, 1));
}

int
aio_error64(const aiocb64_t *aiocbp)
{
	const aio_result_t *resultp = &aiocbp->aio_resultp;
	int error;

	if ((error = resultp->aio_errno) == EINPROGRESS) {
		if (aiocbp->aio_state == CHECK) {
			/*
			 * Always do the kaio() call without using the
			 * KAIO_SUPPORTED() checks because it is not
			 * mandatory to have a valid fd set in the
			 * aiocb, only the resultp must be set.
			 */
			if ((int)_kaio(AIOERROR64, aiocbp) == EINVAL) {
				errno = EINVAL;
				return (-1);
			}
			error = resultp->aio_errno;
		} else if (aiocbp->aio_state == CHECKED) {
			((aiocb64_t *)aiocbp)->aio_state = CHECK;
		}
	}
	return (error);
}

ssize_t
aio_return64(aiocb64_t *aiocbp)
{
	aio_result_t *resultp = &aiocbp->aio_resultp;
	aio_req_t *reqp;
	int error;
	ssize_t retval;

	/*
	 * The _aiodone() function stores resultp->aio_return before
	 * storing resultp->aio_errno (with an membar_producer() in
	 * between).  We use membar_consumer() below to ensure proper
	 * memory ordering between _aiodone() and ourself.
	 */
	error = resultp->aio_errno;
	membar_consumer();
	retval = resultp->aio_return;

	/*
	 * we use this condition to indicate either that
	 * aio_return() has been called before or should
	 * not have been called yet.
	 */
	if ((retval == -1 && error == EINVAL) || error == EINPROGRESS) {
		errno = error;
		return (-1);
	}

	/*
	 * Before we return, mark the result as being returned so that later
	 * calls to aio_return() will return the fact that the result has
	 * already been returned.
	 */
	sig_mutex_lock(&__aio_mutex);
	/* retest, in case more than one thread actually got in here */
	if (resultp->aio_return == -1 && resultp->aio_errno == EINVAL) {
		sig_mutex_unlock(&__aio_mutex);
		errno = EINVAL;
		return (-1);
	}
	resultp->aio_return = -1;
	resultp->aio_errno = EINVAL;
	if ((reqp = _aio_hash_del(resultp)) == NULL)
		sig_mutex_unlock(&__aio_mutex);
	else {
		aiocbp->aio_state = NOCHECK;
		ASSERT(reqp->req_head == NULL);
		(void) _aio_req_remove(reqp);
		sig_mutex_unlock(&__aio_mutex);
		_aio_req_free(reqp);
	}

	if (retval == -1)
		errno = error;
	return (retval);
}

static int
__aio_fsync_bar64(aiocb64_t *aiocbp, aio_lio_t *head, aio_worker_t *aiowp,
    int workerscnt)
{
	int i;
	int error;
	aio_worker_t *next = aiowp;

	for (i = 0; i < workerscnt; i++) {
		error = _aio_rw64(aiocbp, head, &next, AIOFSYNC, AIO_NO_KAIO);
		if (error != 0) {
			sig_mutex_lock(&head->lio_mutex);
			head->lio_mode = LIO_DESTROY;	/* ignore fsync */
			head->lio_nent -= workerscnt - i;
			head->lio_refcnt -= workerscnt - i;
			sig_mutex_unlock(&head->lio_mutex);
			errno = EAGAIN;
			return (i);
		}
		next = next->work_forw;
	}
	return (i);
}

int
aio_fsync64(int op, aiocb64_t *aiocbp)
{
	aio_lio_t *head;
	struct stat64 statb;
	int fret;

	if (aiocbp == NULL)
		return (0);
	if (op != O_DSYNC && op != O_SYNC) {
		errno = EINVAL;
		return (-1);
	}
	if (_aio_hash_find(&aiocbp->aio_resultp) != NULL) {
		errno = EBUSY;
		return (-1);
	}
	if (fstat64(aiocbp->aio_fildes, &statb) < 0)
		return (-1);
	if (_aio_sigev_thread64(aiocbp) != 0)
		return (-1);

	/*
	 * Kernel aio_fsync() is not supported.
	 * We force user-level aio_fsync() just
	 * for the notification side-effect.
	 */
	if (!__uaio_ok && __uaio_init() == -1)
		return (-1);

	/*
	 * The first asynchronous I/O request in the current process will
	 * create a bunch of workers (via __uaio_init()).  If the number
	 * of workers is zero then the number of pending asynchronous I/O
	 * requests is zero.  In such a case only execute the standard
	 * fsync(3C) or fdatasync(3C) as appropriate.
	 */
	if (__rw_workerscnt == 0) {
		if (op == O_DSYNC)
			return (__fdsync(aiocbp->aio_fildes, FDSYNC_DATA));
		else
			return (__fdsync(aiocbp->aio_fildes, FDSYNC_FILE));
	}

	/*
	 * re-use aio_offset as the op field.
	 *	O_DSYNC - fdatasync()
	 *	O_SYNC - fsync()
	 */
	aiocbp->aio_offset = op;
	aiocbp->aio_lio_opcode = AIOFSYNC;

	/*
	 * Create a list of fsync requests.  The worker that
	 * gets the last request will do the fsync request.
	 */
	head = _aio_lio_alloc();
	if (head == NULL) {
		errno = EAGAIN;
		return (-1);
	}
	head->lio_mode = LIO_FSYNC;
	head->lio_nent = head->lio_refcnt = __rw_workerscnt;
	head->lio_largefile = 1;

	/*
	 * Insert an fsync request on every worker's queue.
	 */
	fret = __aio_fsync_bar64(aiocbp, head, __workers_rw, __rw_workerscnt);
	if (fret != __rw_workerscnt) {
		/*
		 * Fewer fsync requests than workers means that it was
		 * not possible to submit fsync requests to all workers.
		 * Actions:
		 * a) number of fsync requests submitted is 0:
		 *    => free allocated memory (aio_lio_t).
		 * b) number of fsync requests submitted is > 0:
		 *    => the last worker executing the fsync request
		 *	 will free the aio_lio_t struct.
		 */
		if (fret == 0)
			_aio_lio_free(head);
		return (-1);
	}
	return (0);
}

int
aio_cancel64(int fd, aiocb64_t *aiocbp)
{
	aio_req_t *reqp;
	aio_worker_t *aiowp;
	int done = 0;
	int canceled = 0;
	struct stat64 buf;

	if (fstat64(fd, &buf) < 0)
		return (-1);

	if (aiocbp != NULL) {
		if (fd != aiocbp->aio_fildes) {
			errno = EINVAL;
			return (-1);
		}
		if (aiocbp->aio_state == USERAIO) {
			sig_mutex_lock(&__aio_mutex);
			reqp = _aio_hash_find(&aiocbp->aio_resultp);
			if (reqp == NULL) {
				sig_mutex_unlock(&__aio_mutex);
				return (AIO_ALLDONE);
			}
			aiowp = reqp->req_worker;
			sig_mutex_lock(&aiowp->work_qlock1);
			(void) _aio_cancel_req(aiowp, reqp, &canceled, &done);
			sig_mutex_unlock(&aiowp->work_qlock1);
			sig_mutex_unlock(&__aio_mutex);
			if (done)
				return (AIO_ALLDONE);
			if (canceled)
				return (AIO_CANCELED);
			return (AIO_NOTCANCELED);
		}
		if (aiocbp->aio_state == USERAIO_DONE)
			return (AIO_ALLDONE);
		return ((int)_kaio(AIOCANCEL, fd, aiocbp));
	}

	return (aiocancel_all(fd));
}

int
aio_waitn64(aiocb64_t *list[], uint_t nent, uint_t *nwait,
    const timespec_t *timeout)
{
	return (__aio_waitn((void **)list, nent, nwait, timeout));
}

#endif /* !defined(_LP64) */
