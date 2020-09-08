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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2025 MNX Cloud, Inc.
 */

#include "lint.h"
#include "thr_uberdata.h"
#include "libc.h"
#include "asyncio.h"
#include <atomic.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/port.h>

static int _aio_hash_insert(aio_result_t *, aio_req_t *);
static aio_req_t *_aio_req_get(aio_worker_t *);
static void _aio_req_add(aio_req_t *, aio_worker_t **, int);
static void _aio_req_del(aio_worker_t *, aio_req_t *, int);
static void _aio_work_done(aio_worker_t *);
static void _aio_enq_doneq(aio_req_t *);

extern void _aio_lio_free(aio_lio_t *);

extern int __fcntl(int, int, ...);
extern int _port_dispatch(int, int, int, int, uintptr_t, void *);

static int _aio_fsync_del(aio_worker_t *, aio_req_t *);
static void _aiodone(aio_req_t *, ssize_t, int);
static void _aio_cancel_work(aio_worker_t *, int, int *, int *);
static void _aio_finish_request(aio_worker_t *, ssize_t, int);

/*
 * switch for kernel async I/O
 */
int _kaio_ok = 0;		/* 0 = disabled, 1 = on, -1 = error */

/*
 * Key for thread-specific data
 */
pthread_key_t _aio_key;

/*
 * Array for determining whether or not a file supports kaio.
 * Initialized in _kaio_init().
 */
uint32_t *_kaio_supported = NULL;

/*
 *  workers for read/write requests
 * (__aio_mutex lock protects circular linked list of workers)
 */
aio_worker_t *__workers_rw;	/* circular list of AIO workers */
aio_worker_t *__nextworker_rw;	/* next worker in list of workers */
int __rw_workerscnt;		/* number of read/write workers */

/*
 * worker for notification requests.
 */
aio_worker_t *__workers_no;	/* circular list of AIO workers */
aio_worker_t *__nextworker_no;	/* next worker in list of workers */
int __no_workerscnt;		/* number of write workers */

aio_req_t *_aio_done_tail;		/* list of done requests */
aio_req_t *_aio_done_head;

mutex_t __aio_initlock = DEFAULTMUTEX;	/* makes aio initialization atomic */
cond_t __aio_initcv = DEFAULTCV;
int __aio_initbusy = 0;

mutex_t __aio_mutex = DEFAULTMUTEX;	/* protects counts, and linked lists */
cond_t _aio_iowait_cv = DEFAULTCV;	/* wait for userland I/Os */

pid_t __pid = (pid_t)-1;		/* initialize as invalid pid */
int _sigio_enabled = 0;			/* when set, send SIGIO signal */

aio_hash_t *_aio_hash;

aio_req_t *_aio_doneq;			/* double linked done queue list */

int _aio_donecnt = 0;
int _aio_waitncnt = 0;			/* # of requests for aio_waitn */
int _aio_doneq_cnt = 0;
int _aio_outstand_cnt = 0;		/* # of outstanding requests */
int _kaio_outstand_cnt = 0;		/* # of outstanding kaio requests */
int _aio_req_done_cnt = 0;		/* req. done but not in "done queue" */
int _aio_kernel_suspend = 0;		/* active kernel kaio calls */
int _aio_suscv_cnt = 0;			/* aio_suspend calls waiting on cv's */

int _max_workers = 256;			/* max number of workers permitted */
int _min_workers = 4;			/* min number of workers */
int _minworkload = 2;			/* min number of request in q */
int _aio_worker_cnt = 0;		/* number of workers to do requests */
int __uaio_ok = 0;			/* AIO has been enabled */
sigset_t _worker_set;			/* worker's signal mask */

int _aiowait_flag = 0;			/* when set, aiowait() is inprogress */
int _aio_flags = 0;			/* see asyncio.h defines for */

aio_worker_t *_kaiowp = NULL;		/* points to kaio cleanup thread */

int hz;					/* clock ticks per second */

static int
_kaio_supported_init(void)
{
	void *ptr;
	size_t size;

	if (_kaio_supported != NULL)	/* already initialized */
		return (0);

	size = MAX_KAIO_FDARRAY_SIZE * sizeof (uint32_t);
	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, (off_t)0);
	if (ptr == MAP_FAILED)
		return (-1);
	_kaio_supported = ptr;
	return (0);
}

/*
 * The aio subsystem is initialized when an AIO request is made.
 * Constants are initialized like the max number of workers that
 * the subsystem can create, and the minimum number of workers
 * permitted before imposing some restrictions.  Also, some
 * workers are created.
 */
int
__uaio_init(void)
{
	int ret = -1;
	int i;
	int cancel_state;

	lmutex_lock(&__aio_initlock);
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	while (__aio_initbusy)
		(void) cond_wait(&__aio_initcv, &__aio_initlock);
	(void) pthread_setcancelstate(cancel_state, NULL);
	if (__uaio_ok) {	/* already initialized */
		lmutex_unlock(&__aio_initlock);
		return (0);
	}
	__aio_initbusy = 1;
	lmutex_unlock(&__aio_initlock);

	hz = (int)sysconf(_SC_CLK_TCK);
	__pid = getpid();

	setup_cancelsig(SIGAIOCANCEL);

	if (_kaio_supported_init() != 0)
		goto out;

	/*
	 * Allocate and initialize the hash table.
	 * Do this only once, even if __uaio_init() is called twice.
	 */
	if (_aio_hash == NULL) {
		/* LINTED pointer cast */
		_aio_hash = (aio_hash_t *)mmap(NULL,
		    HASHSZ * sizeof (aio_hash_t), PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON, -1, (off_t)0);
		if ((void *)_aio_hash == MAP_FAILED) {
			_aio_hash = NULL;
			goto out;
		}
		for (i = 0; i < HASHSZ; i++)
			(void) mutex_init(&_aio_hash[i].hash_lock,
			    USYNC_THREAD, NULL);
	}

	/*
	 * Initialize worker's signal mask to only catch SIGAIOCANCEL.
	 */
	(void) sigfillset(&_worker_set);
	(void) sigdelset(&_worker_set, SIGAIOCANCEL);

	/*
	 * Create one worker to send asynchronous notifications.
	 * Do this only once, even if __uaio_init() is called twice.
	 */
	if (__no_workerscnt == 0 &&
	    (_aio_create_worker(NULL, AIONOTIFY) != 0)) {
		errno = EAGAIN;
		goto out;
	}

	/*
	 * Create the minimum number of read/write workers.
	 * And later check whether atleast one worker is created;
	 * lwp_create() calls could fail because of segkp exhaustion.
	 */
	for (i = 0; i < _min_workers; i++)
		(void) _aio_create_worker(NULL, AIOREAD);
	if (__rw_workerscnt == 0) {
		errno = EAGAIN;
		goto out;
	}

	ret = 0;
out:
	lmutex_lock(&__aio_initlock);
	if (ret == 0)
		__uaio_ok = 1;
	__aio_initbusy = 0;
	(void) cond_broadcast(&__aio_initcv);
	lmutex_unlock(&__aio_initlock);
	return (ret);
}

/*
 * Called from close() before actually performing the real _close().
 */
void
_aio_close(int fd)
{
	if (fd < 0)	/* avoid cancelling everything */
		return;
	/*
	 * Cancel all outstanding aio requests for this file descriptor.
	 */
	if (__uaio_ok)
		(void) aiocancel_all(fd);
	/*
	 * If we have allocated the bit array, clear the bit for this file.
	 * The next open may re-use this file descriptor and the new file
	 * may have different kaio() behaviour.
	 */
	if (_kaio_supported != NULL)
		CLEAR_KAIO_SUPPORTED(fd);
}

/*
 * special kaio cleanup thread sits in a loop in the
 * kernel waiting for pending kaio requests to complete.
 */
void *
_kaio_cleanup_thread(void *arg)
{
	if (pthread_setspecific(_aio_key, arg) != 0)
		aio_panic("_kaio_cleanup_thread, pthread_setspecific()");
	(void) _kaio(AIOSTART);
	return (arg);
}

/*
 * initialize kaio.
 */
void
_kaio_init()
{
	int error;
	sigset_t oset;
	int cancel_state;

	lmutex_lock(&__aio_initlock);
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	while (__aio_initbusy)
		(void) cond_wait(&__aio_initcv, &__aio_initlock);
	(void) pthread_setcancelstate(cancel_state, NULL);
	if (_kaio_ok) {		/* already initialized */
		lmutex_unlock(&__aio_initlock);
		return;
	}
	__aio_initbusy = 1;
	lmutex_unlock(&__aio_initlock);

	if (_kaio_supported_init() != 0)
		error = ENOMEM;
	else if ((_kaiowp = _aio_worker_alloc()) == NULL)
		error = ENOMEM;
	else if ((error = (int)_kaio(AIOINIT)) == 0) {
		(void) pthread_sigmask(SIG_SETMASK, &maskset, &oset);
		error = thr_create(NULL, AIOSTKSIZE, _kaio_cleanup_thread,
		    _kaiowp, THR_DAEMON, &_kaiowp->work_tid);
		(void) pthread_sigmask(SIG_SETMASK, &oset, NULL);
	}
	if (error && _kaiowp != NULL) {
		_aio_worker_free(_kaiowp);
		_kaiowp = NULL;
	}

	lmutex_lock(&__aio_initlock);
	if (error)
		_kaio_ok = -1;
	else
		_kaio_ok = 1;
	__aio_initbusy = 0;
	(void) cond_broadcast(&__aio_initcv);
	lmutex_unlock(&__aio_initlock);
}

int
aioread(int fd, caddr_t buf, int bufsz, off_t offset, int whence,
    aio_result_t *resultp)
{
	return (_aiorw(fd, buf, bufsz, offset, whence, resultp, AIOREAD));
}

int
aiowrite(int fd, caddr_t buf, int bufsz, off_t offset, int whence,
    aio_result_t *resultp)
{
	return (_aiorw(fd, buf, bufsz, offset, whence, resultp, AIOWRITE));
}

#if !defined(_LP64)
int
aioread64(int fd, caddr_t buf, int bufsz, off64_t offset, int whence,
    aio_result_t *resultp)
{
	return (_aiorw(fd, buf, bufsz, offset, whence, resultp, AIOAREAD64));
}

int
aiowrite64(int fd, caddr_t buf, int bufsz, off64_t offset, int whence,
    aio_result_t *resultp)
{
	return (_aiorw(fd, buf, bufsz, offset, whence, resultp, AIOAWRITE64));
}
#endif	/* !defined(_LP64) */

int
_aiorw(int fd, caddr_t buf, int bufsz, offset_t offset, int whence,
    aio_result_t *resultp, int mode)
{
	aio_req_t *reqp;
	aio_args_t *ap;
	offset_t loffset;
	struct stat64 stat64;
	int error = 0;
	int kerr;
	int umode;

	switch (whence) {

	case SEEK_SET:
		loffset = offset;
		break;
	case SEEK_CUR:
		if ((loffset = llseek(fd, 0, SEEK_CUR)) == -1)
			error = -1;
		else
			loffset += offset;
		break;
	case SEEK_END:
		if (fstat64(fd, &stat64) == -1)
			error = -1;
		else
			loffset = offset + stat64.st_size;
		break;
	default:
		errno = EINVAL;
		error = -1;
	}

	if (error)
		return (error);

	/* initialize kaio */
	if (!_kaio_ok)
		_kaio_init();

	/*
	 * _aio_do_request() needs the original request code (mode) to be able
	 * to choose the appropiate 32/64 bit function.  All other functions
	 * only require the difference between READ and WRITE (umode).
	 */
	if (mode == AIOAREAD64 || mode == AIOAWRITE64)
		umode = mode - AIOAREAD64;
	else
		umode = mode;

	/*
	 * Try kernel aio first.
	 * If errno is ENOTSUP/EBADFD, fall back to the thread implementation.
	 */
	if (_kaio_ok > 0 && KAIO_SUPPORTED(fd)) {
		resultp->aio_errno = 0;
		sig_mutex_lock(&__aio_mutex);
		_kaio_outstand_cnt++;
		sig_mutex_unlock(&__aio_mutex);
		kerr = (int)_kaio(((resultp->aio_return == AIO_INPROGRESS) ?
		    (umode | AIO_POLL_BIT) : umode),
		    fd, buf, bufsz, loffset, resultp);
		if (kerr == 0) {
			return (0);
		}
		sig_mutex_lock(&__aio_mutex);
		_kaio_outstand_cnt--;
		sig_mutex_unlock(&__aio_mutex);
		if (errno != ENOTSUP && errno != EBADFD)
			return (-1);
		if (errno == EBADFD)
			SET_KAIO_NOT_SUPPORTED(fd);
	}

	if (!__uaio_ok && __uaio_init() == -1)
		return (-1);

	if ((reqp = _aio_req_alloc()) == NULL) {
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * _aio_do_request() checks reqp->req_op to differentiate
	 * between 32 and 64 bit access.
	 */
	reqp->req_op = mode;
	reqp->req_resultp = resultp;
	ap = &reqp->req_args;
	ap->fd = fd;
	ap->buf = buf;
	ap->bufsz = bufsz;
	ap->offset = loffset;

	if (_aio_hash_insert(resultp, reqp) != 0) {
		_aio_req_free(reqp);
		errno = EINVAL;
		return (-1);
	}
	/*
	 * _aio_req_add() only needs the difference between READ and
	 * WRITE to choose the right worker queue.
	 */
	_aio_req_add(reqp, &__nextworker_rw, umode);
	return (0);
}

int
aiocancel(aio_result_t *resultp)
{
	aio_req_t *reqp;
	aio_worker_t *aiowp;
	int ret;
	int done = 0;
	int canceled = 0;

	if (!__uaio_ok) {
		errno = EINVAL;
		return (-1);
	}

	sig_mutex_lock(&__aio_mutex);
	reqp = _aio_hash_find(resultp);
	if (reqp == NULL) {
		if (_aio_outstand_cnt == _aio_req_done_cnt)
			errno = EINVAL;
		else
			errno = EACCES;
		ret = -1;
	} else {
		aiowp = reqp->req_worker;
		sig_mutex_lock(&aiowp->work_qlock1);
		(void) _aio_cancel_req(aiowp, reqp, &canceled, &done);
		sig_mutex_unlock(&aiowp->work_qlock1);

		if (canceled) {
			ret = 0;
		} else {
			if (_aio_outstand_cnt == 0 ||
			    _aio_outstand_cnt == _aio_req_done_cnt)
				errno = EINVAL;
			else
				errno = EACCES;
			ret = -1;
		}
	}
	sig_mutex_unlock(&__aio_mutex);
	return (ret);
}

static void
_aiowait_cleanup(void *arg __unused)
{
	sig_mutex_lock(&__aio_mutex);
	_aiowait_flag--;
	sig_mutex_unlock(&__aio_mutex);
}

/*
 * This must be asynch safe and cancel safe
 */
aio_result_t *
aiowait(struct timeval *uwait)
{
	aio_result_t *uresultp;
	aio_result_t *kresultp;
	aio_result_t *resultp;
	int dontblock;
	int timedwait = 0;
	int kaio_errno = 0;
	struct timeval twait;
	struct timeval *wait = NULL;
	hrtime_t hrtend;
	hrtime_t hres;

	if (uwait) {
		/*
		 * Check for a valid specified wait time.
		 * If it is invalid, fail the call right away.
		 */
		if (uwait->tv_sec < 0 || uwait->tv_usec < 0 ||
		    uwait->tv_usec >= MICROSEC) {
			errno = EINVAL;
			return ((aio_result_t *)-1);
		}

		if (uwait->tv_sec > 0 || uwait->tv_usec > 0) {
			hrtend = gethrtime() +
			    (hrtime_t)uwait->tv_sec * NANOSEC +
			    (hrtime_t)uwait->tv_usec * (NANOSEC / MICROSEC);
			twait = *uwait;
			wait = &twait;
			timedwait++;
		} else {
			/* polling */
			sig_mutex_lock(&__aio_mutex);
			if (_kaio_outstand_cnt == 0) {
				kresultp = (aio_result_t *)-1;
			} else {
				kresultp = (aio_result_t *)_kaio(AIOWAIT,
				    (struct timeval *)-1, 1);
				if (kresultp != (aio_result_t *)-1 &&
				    kresultp != NULL &&
				    kresultp != (aio_result_t *)1) {
					_kaio_outstand_cnt--;
					sig_mutex_unlock(&__aio_mutex);
					return (kresultp);
				}
			}
			uresultp = _aio_req_done();
			sig_mutex_unlock(&__aio_mutex);
			if (uresultp != NULL &&
			    uresultp != (aio_result_t *)-1) {
				return (uresultp);
			}
			if (uresultp == (aio_result_t *)-1 &&
			    kresultp == (aio_result_t *)-1) {
				errno = EINVAL;
				return ((aio_result_t *)-1);
			} else {
				return (NULL);
			}
		}
	}

	for (;;) {
		sig_mutex_lock(&__aio_mutex);
		uresultp = _aio_req_done();
		if (uresultp != NULL && uresultp != (aio_result_t *)-1) {
			sig_mutex_unlock(&__aio_mutex);
			resultp = uresultp;
			break;
		}
		_aiowait_flag++;
		dontblock = (uresultp == (aio_result_t *)-1);
		if (dontblock && _kaio_outstand_cnt == 0) {
			kresultp = (aio_result_t *)-1;
			kaio_errno = EINVAL;
		} else {
			sig_mutex_unlock(&__aio_mutex);
			pthread_cleanup_push(_aiowait_cleanup, NULL);
			_cancel_prologue();
			kresultp = (aio_result_t *)_kaio(AIOWAIT,
			    wait, dontblock);
			_cancel_epilogue();
			pthread_cleanup_pop(0);
			sig_mutex_lock(&__aio_mutex);
			kaio_errno = errno;
		}
		_aiowait_flag--;
		sig_mutex_unlock(&__aio_mutex);
		if (kresultp == (aio_result_t *)1) {
			/* aiowait() awakened by an aionotify() */
			continue;
		} else if (kresultp != NULL &&
		    kresultp != (aio_result_t *)-1) {
			resultp = kresultp;
			sig_mutex_lock(&__aio_mutex);
			_kaio_outstand_cnt--;
			sig_mutex_unlock(&__aio_mutex);
			break;
		} else if (kresultp == (aio_result_t *)-1 &&
		    kaio_errno == EINVAL &&
		    uresultp == (aio_result_t *)-1) {
			errno = kaio_errno;
			resultp = (aio_result_t *)-1;
			break;
		} else if (kresultp == (aio_result_t *)-1 &&
		    kaio_errno == EINTR) {
			errno = kaio_errno;
			resultp = (aio_result_t *)-1;
			break;
		} else if (timedwait) {
			hres = hrtend - gethrtime();
			if (hres <= 0) {
				/* time is up; return */
				resultp = NULL;
				break;
			} else {
				/*
				 * Some time left.  Round up the remaining time
				 * in nanoseconds to microsec.  Retry the call.
				 */
				hres += (NANOSEC / MICROSEC) - 1;
				wait->tv_sec = hres / NANOSEC;
				wait->tv_usec =
				    (hres % NANOSEC) / (NANOSEC / MICROSEC);
			}
		} else {
			ASSERT(kresultp == NULL && uresultp == NULL);
			resultp = NULL;
			continue;
		}
	}
	return (resultp);
}

/*
 * _aio_get_timedelta calculates the remaining time and stores the result
 * into timespec_t *wait.
 */

int
_aio_get_timedelta(timespec_t *end, timespec_t *wait)
{
	int	ret = 0;
	struct	timeval cur;
	timespec_t curtime;

	(void) gettimeofday(&cur, NULL);
	curtime.tv_sec = cur.tv_sec;
	curtime.tv_nsec = cur.tv_usec * 1000;   /* convert us to ns */

	if (end->tv_sec >= curtime.tv_sec) {
		wait->tv_sec = end->tv_sec - curtime.tv_sec;
		if (end->tv_nsec >= curtime.tv_nsec) {
			wait->tv_nsec = end->tv_nsec - curtime.tv_nsec;
			if (wait->tv_sec == 0 && wait->tv_nsec == 0)
				ret = -1;	/* timer expired */
		} else {
			if (end->tv_sec > curtime.tv_sec) {
				wait->tv_sec -= 1;
				wait->tv_nsec = NANOSEC -
				    (curtime.tv_nsec - end->tv_nsec);
			} else {
				ret = -1;	/* timer expired */
			}
		}
	} else {
		ret = -1;
	}
	return (ret);
}

/*
 * If closing by file descriptor: we will simply cancel all the outstanding
 * aio`s and return.  Those aio's in question will have either noticed the
 * cancellation notice before, during, or after initiating io.
 */
int
aiocancel_all(int fd)
{
	aio_req_t *reqp;
	aio_req_t **reqpp, *last;
	aio_worker_t *first;
	aio_worker_t *next;
	int canceled = 0;
	int done = 0;
	int cancelall = 0;

	sig_mutex_lock(&__aio_mutex);

	if (_aio_outstand_cnt == 0) {
		sig_mutex_unlock(&__aio_mutex);
		return (AIO_ALLDONE);
	}

	/*
	 * Cancel requests from the read/write workers' queues.
	 */
	first = __nextworker_rw;
	next = first;
	do {
		_aio_cancel_work(next, fd, &canceled, &done);
	} while ((next = next->work_forw) != first);

	/*
	 * finally, check if there are requests on the done queue that
	 * should be canceled.
	 */
	if (fd < 0)
		cancelall = 1;
	reqpp = &_aio_done_tail;
	last = _aio_done_tail;
	while ((reqp = *reqpp) != NULL) {
		if (cancelall || reqp->req_args.fd == fd) {
			*reqpp = reqp->req_next;
			if (last == reqp) {
				last = reqp->req_next;
			}
			if (_aio_done_head == reqp) {
				/* this should be the last req in list */
				_aio_done_head = last;
			}
			_aio_donecnt--;
			_aio_set_result(reqp, -1, ECANCELED);
			(void) _aio_hash_del(reqp->req_resultp);
			_aio_req_free(reqp);
		} else {
			reqpp = &reqp->req_next;
			last = reqp;
		}
	}

	if (cancelall) {
		ASSERT(_aio_donecnt == 0);
		_aio_done_head = NULL;
	}
	sig_mutex_unlock(&__aio_mutex);

	if (canceled && done == 0)
		return (AIO_CANCELED);
	else if (done && canceled == 0)
		return (AIO_ALLDONE);
	else if ((canceled + done == 0) && KAIO_SUPPORTED(fd))
		return ((int)_kaio(AIOCANCEL, fd, NULL));
	return (AIO_NOTCANCELED);
}

/*
 * Cancel requests from a given work queue.  If the file descriptor
 * parameter, fd, is non-negative, then only cancel those requests
 * in this queue that are to this file descriptor.  If the fd
 * parameter is -1, then cancel all requests.
 */
static void
_aio_cancel_work(aio_worker_t *aiowp, int fd, int *canceled, int *done)
{
	aio_req_t *reqp;

	sig_mutex_lock(&aiowp->work_qlock1);
	/*
	 * cancel queued requests first.
	 */
	reqp = aiowp->work_tail1;
	while (reqp != NULL) {
		if (fd < 0 || reqp->req_args.fd == fd) {
			if (_aio_cancel_req(aiowp, reqp, canceled, done)) {
				/*
				 * Callers locks were dropped.
				 * reqp is invalid; start traversing
				 * the list from the beginning again.
				 */
				reqp = aiowp->work_tail1;
				continue;
			}
		}
		reqp = reqp->req_next;
	}
	/*
	 * Since the queued requests have been canceled, there can
	 * only be one inprogress request that should be canceled.
	 */
	if ((reqp = aiowp->work_req) != NULL &&
	    (fd < 0 || reqp->req_args.fd == fd))
		(void) _aio_cancel_req(aiowp, reqp, canceled, done);
	sig_mutex_unlock(&aiowp->work_qlock1);
}

/*
 * Cancel a request.  Return 1 if the callers locks were temporarily
 * dropped, otherwise return 0.
 */
int
_aio_cancel_req(aio_worker_t *aiowp, aio_req_t *reqp, int *canceled, int *done)
{
	int ostate = reqp->req_state;

	ASSERT(MUTEX_HELD(&__aio_mutex));
	ASSERT(MUTEX_HELD(&aiowp->work_qlock1));
	if (ostate == AIO_REQ_CANCELED)
		return (0);
	if (ostate == AIO_REQ_DONE && !POSIX_AIO(reqp) &&
	    aiowp->work_prev1 == reqp) {
		ASSERT(aiowp->work_done1 != 0);
		/*
		 * If not on the done queue yet, just mark it CANCELED,
		 * _aio_work_done() will do the necessary clean up.
		 * This is required to ensure that aiocancel_all() cancels
		 * all the outstanding requests, including this one which
		 * is not yet on done queue but has been marked done.
		 */
		_aio_set_result(reqp, -1, ECANCELED);
		(void) _aio_hash_del(reqp->req_resultp);
		reqp->req_state = AIO_REQ_CANCELED;
		(*canceled)++;
		return (0);
	}

	if (ostate == AIO_REQ_DONE || ostate == AIO_REQ_DONEQ) {
		(*done)++;
		return (0);
	}
	if (reqp->req_op == AIOFSYNC && reqp != aiowp->work_req) {
		ASSERT(POSIX_AIO(reqp));
		/* Cancel the queued aio_fsync() request */
		if (!reqp->req_head->lio_canned) {
			reqp->req_head->lio_canned = 1;
			_aio_outstand_cnt--;
			(*canceled)++;
		}
		return (0);
	}
	reqp->req_state = AIO_REQ_CANCELED;
	_aio_req_del(aiowp, reqp, ostate);
	(void) _aio_hash_del(reqp->req_resultp);
	(*canceled)++;
	if (reqp == aiowp->work_req) {
		ASSERT(ostate == AIO_REQ_INPROGRESS);
		/*
		 * Set the result values now, before _aiodone() is called.
		 * We do this because the application can expect aio_return
		 * and aio_errno to be set to -1 and ECANCELED, respectively,
		 * immediately after a successful return from aiocancel()
		 * or aio_cancel().
		 */
		_aio_set_result(reqp, -1, ECANCELED);
		(void) thr_kill(aiowp->work_tid, SIGAIOCANCEL);
		return (0);
	}
	if (!POSIX_AIO(reqp)) {
		_aio_outstand_cnt--;
		_aio_set_result(reqp, -1, ECANCELED);
		_aio_req_free(reqp);
		return (0);
	}
	sig_mutex_unlock(&aiowp->work_qlock1);
	sig_mutex_unlock(&__aio_mutex);
	_aiodone(reqp, -1, ECANCELED);
	sig_mutex_lock(&__aio_mutex);
	sig_mutex_lock(&aiowp->work_qlock1);
	return (1);
}

int
_aio_create_worker(aio_req_t *reqp, int mode)
{
	aio_worker_t *aiowp, **workers, **nextworker;
	int *aio_workerscnt;
	void *(*func)(void *);
	sigset_t oset;
	int error;

	/*
	 * Put the new worker thread in the right queue.
	 */
	switch (mode) {
	case AIOREAD:
	case AIOWRITE:
	case AIOAREAD:
	case AIOAWRITE:
#if !defined(_LP64)
	case AIOAREAD64:
	case AIOAWRITE64:
#endif
		workers = &__workers_rw;
		nextworker = &__nextworker_rw;
		aio_workerscnt = &__rw_workerscnt;
		func = _aio_do_request;
		break;
	case AIONOTIFY:
		workers = &__workers_no;
		nextworker = &__nextworker_no;
		func = _aio_do_notify;
		aio_workerscnt = &__no_workerscnt;
		break;
	default:
		aio_panic("_aio_create_worker: invalid mode");
		break;
	}

	if ((aiowp = _aio_worker_alloc()) == NULL)
		return (-1);

	if (reqp) {
		reqp->req_state = AIO_REQ_QUEUED;
		reqp->req_worker = aiowp;
		aiowp->work_head1 = reqp;
		aiowp->work_tail1 = reqp;
		aiowp->work_next1 = reqp;
		aiowp->work_count1 = 1;
		aiowp->work_minload1 = 1;
	}

	(void) pthread_sigmask(SIG_SETMASK, &maskset, &oset);
	error = thr_create(NULL, AIOSTKSIZE, func, aiowp,
	    THR_DAEMON | THR_SUSPENDED, &aiowp->work_tid);
	(void) pthread_sigmask(SIG_SETMASK, &oset, NULL);
	if (error) {
		if (reqp) {
			reqp->req_state = 0;
			reqp->req_worker = NULL;
		}
		_aio_worker_free(aiowp);
		return (-1);
	}

	lmutex_lock(&__aio_mutex);
	(*aio_workerscnt)++;
	if (*workers == NULL) {
		aiowp->work_forw = aiowp;
		aiowp->work_backw = aiowp;
		*nextworker = aiowp;
		*workers = aiowp;
	} else {
		aiowp->work_backw = (*workers)->work_backw;
		aiowp->work_forw = (*workers);
		(*workers)->work_backw->work_forw = aiowp;
		(*workers)->work_backw = aiowp;
	}
	_aio_worker_cnt++;
	lmutex_unlock(&__aio_mutex);

	(void) thr_continue(aiowp->work_tid);

	return (0);
}

/*
 * This is the worker's main routine.
 * The task of this function is to execute all queued requests;
 * once the last pending request is executed this function will block
 * in _aio_idle().  A new incoming request must wakeup this thread to
 * restart the work.
 * Every worker has an own work queue.  The queue lock is required
 * to synchronize the addition of new requests for this worker or
 * cancellation of pending/running requests.
 *
 * Cancellation scenarios:
 * The cancellation of a request is being done asynchronously using
 * _aio_cancel_req() from another thread context.
 * A queued request can be cancelled in different manners :
 * a) request is queued but not "in progress" or "done" (AIO_REQ_QUEUED):
 *	- lock the queue -> remove the request -> unlock the queue
 *	- this function/thread does not detect this cancellation process
 * b) request is in progress (AIO_REQ_INPROGRESS) :
 *	- this function first allow the cancellation of the running
 *	  request with the flag "work_cancel_flg=1"
 *		see _aio_req_get() -> _aio_cancel_on()
 *	  During this phase, it is allowed to interrupt the worker
 *	  thread running the request (this thread) using the SIGAIOCANCEL
 *	  signal.
 *	  Once this thread returns from the kernel (because the request
 *	  is just done), then it must disable a possible cancellation
 *	  and proceed to finish the request.  To disable the cancellation
 *	  this thread must use _aio_cancel_off() to set "work_cancel_flg=0".
 * c) request is already done (AIO_REQ_DONE || AIO_REQ_DONEQ):
 *	  same procedure as in a)
 *
 * To b)
 *	This thread uses sigsetjmp() to define the position in the code, where
 *	it wish to continue working in the case that a SIGAIOCANCEL signal
 *	is detected.
 *	Normally this thread should get the cancellation signal during the
 *	kernel phase (reading or writing).  In that case the signal handler
 *	aiosigcancelhndlr() is activated using the worker thread context,
 *	which again will use the siglongjmp() function to break the standard
 *	code flow and jump to the "sigsetjmp" position, provided that
 *	"work_cancel_flg" is set to "1".
 *	Because the "work_cancel_flg" is only manipulated by this worker
 *	thread and it can only run on one CPU at a given time, it is not
 *	necessary to protect that flag with the queue lock.
 *	Returning from the kernel (read or write system call) we must
 *	first disable the use of the SIGAIOCANCEL signal and accordingly
 *	the use of the siglongjmp() function to prevent a possible deadlock:
 *	- It can happens that this worker thread returns from the kernel and
 *	  blocks in "work_qlock1",
 *	- then a second thread cancels the apparently "in progress" request
 *	  and sends the SIGAIOCANCEL signal to the worker thread,
 *	- the worker thread gets assigned the "work_qlock1" and will returns
 *	  from the kernel,
 *	- the kernel detects the pending signal and activates the signal
 *	  handler instead,
 *	- if the "work_cancel_flg" is still set then the signal handler
 *	  should use siglongjmp() to cancel the "in progress" request and
 *	  it would try to acquire the same work_qlock1 in _aio_req_get()
 *	  for a second time => deadlock.
 *	To avoid that situation we disable the cancellation of the request
 *	in progress BEFORE we try to acquire the work_qlock1.
 *	In that case the signal handler will not call siglongjmp() and the
 *	worker thread will continue running the standard code flow.
 *	Then this thread must check the AIO_REQ_CANCELED flag to emulate
 *	an eventually required siglongjmp() freeing the work_qlock1 and
 *	avoiding a deadlock.
 */
void *
_aio_do_request(void *arglist)
{
	aio_worker_t *aiowp = (aio_worker_t *)arglist;
	ulwp_t *self = curthread;
	struct aio_args *arg;
	aio_req_t *reqp;		/* current AIO request */
	ssize_t retval;
	int append;
	int error;

	if (pthread_setspecific(_aio_key, aiowp) != 0)
		aio_panic("_aio_do_request, pthread_setspecific()");
	(void) pthread_sigmask(SIG_SETMASK, &_worker_set, NULL);
	ASSERT(aiowp->work_req == NULL);

	/*
	 * We resume here when an operation is cancelled.
	 * On first entry, aiowp->work_req == NULL, so all
	 * we do is block SIGAIOCANCEL.
	 */
	(void) sigsetjmp(aiowp->work_jmp_buf, 0);
	ASSERT(self->ul_sigdefer == 0);

	sigoff(self);	/* block SIGAIOCANCEL */
	if (aiowp->work_req != NULL)
		_aio_finish_request(aiowp, -1, ECANCELED);

	for (;;) {
		/*
		 * Put completed requests on aio_done_list.  This has
		 * to be done as part of the main loop to ensure that
		 * we don't artificially starve any aiowait'ers.
		 */
		if (aiowp->work_done1)
			_aio_work_done(aiowp);

top:
		/* consume any deferred SIGAIOCANCEL signal here */
		sigon(self);
		sigoff(self);

		while ((reqp = _aio_req_get(aiowp)) == NULL) {
			if (_aio_idle(aiowp) != 0)
				goto top;
		}
		arg = &reqp->req_args;
		ASSERT(reqp->req_state == AIO_REQ_INPROGRESS ||
		    reqp->req_state == AIO_REQ_CANCELED);
		error = 0;

		switch (reqp->req_op) {
		case AIOREAD:
		case AIOAREAD:
			sigon(self);	/* unblock SIGAIOCANCEL */
			retval = pread(arg->fd, arg->buf,
			    arg->bufsz, arg->offset);
			if (retval == -1) {
				if (errno == ESPIPE) {
					retval = read(arg->fd,
					    arg->buf, arg->bufsz);
					if (retval == -1)
						error = errno;
				} else {
					error = errno;
				}
			}
			sigoff(self);	/* block SIGAIOCANCEL */
			break;
		case AIOWRITE:
		case AIOAWRITE:
			/*
			 * The SUSv3 POSIX spec for aio_write() states:
			 *	If O_APPEND is set for the file descriptor,
			 *	write operations append to the file in the
			 *	same order as the calls were made.
			 * but, somewhat inconsistently, it requires pwrite()
			 * to ignore the O_APPEND setting.  So we have to use
			 * fcntl() to get the open modes and call write() for
			 * the O_APPEND case.
			 */
			append = (__fcntl(arg->fd, F_GETFL) & O_APPEND);
			sigon(self);	/* unblock SIGAIOCANCEL */
			retval = append?
			    write(arg->fd, arg->buf, arg->bufsz) :
			    pwrite(arg->fd, arg->buf, arg->bufsz,
			    arg->offset);
			if (retval == -1) {
				if (errno == ESPIPE) {
					retval = write(arg->fd,
					    arg->buf, arg->bufsz);
					if (retval == -1)
						error = errno;
				} else {
					error = errno;
				}
			}
			sigoff(self);	/* block SIGAIOCANCEL */
			break;
#if !defined(_LP64)
		case AIOAREAD64:
			sigon(self);	/* unblock SIGAIOCANCEL */
			retval = pread64(arg->fd, arg->buf,
			    arg->bufsz, arg->offset);
			if (retval == -1) {
				if (errno == ESPIPE) {
					retval = read(arg->fd,
					    arg->buf, arg->bufsz);
					if (retval == -1)
						error = errno;
				} else {
					error = errno;
				}
			}
			sigoff(self);	/* block SIGAIOCANCEL */
			break;
		case AIOAWRITE64:
			/*
			 * The SUSv3 POSIX spec for aio_write() states:
			 *	If O_APPEND is set for the file descriptor,
			 *	write operations append to the file in the
			 *	same order as the calls were made.
			 * but, somewhat inconsistently, it requires pwrite()
			 * to ignore the O_APPEND setting.  So we have to use
			 * fcntl() to get the open modes and call write() for
			 * the O_APPEND case.
			 */
			append = (__fcntl(arg->fd, F_GETFL) & O_APPEND);
			sigon(self);	/* unblock SIGAIOCANCEL */
			retval = append?
			    write(arg->fd, arg->buf, arg->bufsz) :
			    pwrite64(arg->fd, arg->buf, arg->bufsz,
			    arg->offset);
			if (retval == -1) {
				if (errno == ESPIPE) {
					retval = write(arg->fd,
					    arg->buf, arg->bufsz);
					if (retval == -1)
						error = errno;
				} else {
					error = errno;
				}
			}
			sigoff(self);	/* block SIGAIOCANCEL */
			break;
#endif	/* !defined(_LP64) */
		case AIOFSYNC:
			if (_aio_fsync_del(aiowp, reqp))
				goto top;
			ASSERT(reqp->req_head == NULL);
			/*
			 * All writes for this fsync request are now
			 * acknowledged.  Now make these writes visible
			 * and put the final request into the hash table.
			 */
			if (reqp->req_state == AIO_REQ_CANCELED) {
				/* EMPTY */;
			} else if (arg->offset == O_SYNC) {
				if ((retval = __fdsync(arg->fd, FDSYNC_FILE)) ==
				    -1) {
					error = errno;
				}
			} else {
				if ((retval = __fdsync(arg->fd, FDSYNC_DATA)) ==
				    -1) {
					error = errno;
				}
			}
			if (_aio_hash_insert(reqp->req_resultp, reqp) != 0)
				aio_panic("_aio_do_request(): AIOFSYNC: "
				    "request already in hash table");
			break;
		default:
			aio_panic("_aio_do_request, bad op");
		}

		_aio_finish_request(aiowp, retval, error);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Perform the tail processing for _aio_do_request().
 * The in-progress request may or may not have been cancelled.
 */
static void
_aio_finish_request(aio_worker_t *aiowp, ssize_t retval, int error)
{
	aio_req_t *reqp;

	sig_mutex_lock(&aiowp->work_qlock1);
	if ((reqp = aiowp->work_req) == NULL)
		sig_mutex_unlock(&aiowp->work_qlock1);
	else {
		aiowp->work_req = NULL;
		if (reqp->req_state == AIO_REQ_CANCELED) {
			retval = -1;
			error = ECANCELED;
		}
		if (!POSIX_AIO(reqp)) {
			int notify;
			if (reqp->req_state == AIO_REQ_INPROGRESS) {
				reqp->req_state = AIO_REQ_DONE;
				_aio_set_result(reqp, retval, error);
			}
			sig_mutex_unlock(&aiowp->work_qlock1);
			sig_mutex_lock(&__aio_mutex);
			/*
			 * If it was canceled, this request will not be
			 * added to done list. Just free it.
			 */
			if (error == ECANCELED) {
				_aio_outstand_cnt--;
				_aio_req_free(reqp);
			} else {
				_aio_req_done_cnt++;
			}
			/*
			 * Notify any thread that may have blocked
			 * because it saw an outstanding request.
			 */
			notify = 0;
			if (_aio_outstand_cnt == 0 && _aiowait_flag) {
				notify = 1;
			}
			sig_mutex_unlock(&__aio_mutex);
			if (notify) {
				(void) _kaio(AIONOTIFY);
			}
		} else {
			if (reqp->req_state == AIO_REQ_INPROGRESS)
				reqp->req_state = AIO_REQ_DONE;
			sig_mutex_unlock(&aiowp->work_qlock1);
			_aiodone(reqp, retval, error);
		}
	}
}

void
_aio_req_mark_done(aio_req_t *reqp)
{
#if !defined(_LP64)
	if (reqp->req_largefile)
		((aiocb64_t *)reqp->req_aiocbp)->aio_state = USERAIO_DONE;
	else
#endif
		((aiocb_t *)reqp->req_aiocbp)->aio_state = USERAIO_DONE;
}

/*
 * Sleep for 'ticks' clock ticks to give somebody else a chance to run,
 * hopefully to consume one of our queued signals.
 */
static void
_aio_delay(int ticks)
{
	(void) usleep(ticks * (MICROSEC / hz));
}

/*
 * Actually send the notifications.
 * We could block indefinitely here if the application
 * is not listening for the signal or port notifications.
 */
static void
send_notification(notif_param_t *npp)
{
	extern int __sigqueue(pid_t pid, int signo,
	    /* const union sigval */ void *value, int si_code, int block);

	if (npp->np_signo)
		(void) __sigqueue(__pid, npp->np_signo, npp->np_user,
		    SI_ASYNCIO, 1);
	else if (npp->np_port >= 0)
		(void) _port_dispatch(npp->np_port, 0, PORT_SOURCE_AIO,
		    npp->np_event, npp->np_object, npp->np_user);

	if (npp->np_lio_signo)
		(void) __sigqueue(__pid, npp->np_lio_signo, npp->np_lio_user,
		    SI_ASYNCIO, 1);
	else if (npp->np_lio_port >= 0)
		(void) _port_dispatch(npp->np_lio_port, 0, PORT_SOURCE_AIO,
		    npp->np_lio_event, npp->np_lio_object, npp->np_lio_user);
}

/*
 * Asynchronous notification worker.
 */
void *
_aio_do_notify(void *arg)
{
	aio_worker_t *aiowp = (aio_worker_t *)arg;
	aio_req_t *reqp;

	/*
	 * This isn't really necessary.  All signals are blocked.
	 */
	if (pthread_setspecific(_aio_key, aiowp) != 0)
		aio_panic("_aio_do_notify, pthread_setspecific()");

	/*
	 * Notifications are never cancelled.
	 * All signals remain blocked, forever.
	 */
	for (;;) {
		while ((reqp = _aio_req_get(aiowp)) == NULL) {
			if (_aio_idle(aiowp) != 0)
				aio_panic("_aio_do_notify: _aio_idle() failed");
		}
		send_notification(&reqp->req_notify);
		_aio_req_free(reqp);
	}

	/* NOTREACHED */
	return (NULL);
}

/*
 * Do the completion semantics for a request that was either canceled
 * by _aio_cancel_req() or was completed by _aio_do_request().
 */
static void
_aiodone(aio_req_t *reqp, ssize_t retval, int error)
{
	aio_result_t *resultp = reqp->req_resultp;
	int notify = 0;
	aio_lio_t *head;
	int sigev_none;
	int sigev_signal;
	int sigev_thread;
	int sigev_port;
	notif_param_t np;

	/*
	 * We call _aiodone() only for Posix I/O.
	 */
	ASSERT(POSIX_AIO(reqp));

	sigev_none = 0;
	sigev_signal = 0;
	sigev_thread = 0;
	sigev_port = 0;
	np.np_signo = 0;
	np.np_port = -1;
	np.np_lio_signo = 0;
	np.np_lio_port = -1;

	switch (reqp->req_sigevent.sigev_notify) {
	case SIGEV_NONE:
		sigev_none = 1;
		break;
	case SIGEV_SIGNAL:
		sigev_signal = 1;
		break;
	case SIGEV_THREAD:
		sigev_thread = 1;
		break;
	case SIGEV_PORT:
		sigev_port = 1;
		break;
	default:
		aio_panic("_aiodone: improper sigev_notify");
		break;
	}

	/*
	 * Figure out the notification parameters while holding __aio_mutex.
	 * Actually perform the notifications after dropping __aio_mutex.
	 * This allows us to sleep for a long time (if the notifications
	 * incur delays) without impeding other async I/O operations.
	 */

	sig_mutex_lock(&__aio_mutex);

	if (sigev_signal) {
		if ((np.np_signo = reqp->req_sigevent.sigev_signo) != 0)
			notify = 1;
		np.np_user = reqp->req_sigevent.sigev_value.sival_ptr;
	} else if (sigev_thread | sigev_port) {
		if ((np.np_port = reqp->req_sigevent.sigev_signo) >= 0)
			notify = 1;
		np.np_event = reqp->req_op;
		if (np.np_event == AIOFSYNC && reqp->req_largefile)
			np.np_event = AIOFSYNC64;
		np.np_object = (uintptr_t)reqp->req_aiocbp;
		np.np_user = reqp->req_sigevent.sigev_value.sival_ptr;
	}

	if (resultp->aio_errno == EINPROGRESS)
		_aio_set_result(reqp, retval, error);

	_aio_outstand_cnt--;

	head = reqp->req_head;
	reqp->req_head = NULL;

	if (sigev_none) {
		_aio_enq_doneq(reqp);
		reqp = NULL;
	} else {
		(void) _aio_hash_del(resultp);
		_aio_req_mark_done(reqp);
	}

	_aio_waitn_wakeup();

	/*
	 * __aio_waitn() sets AIO_WAIT_INPROGRESS and
	 * __aio_suspend() increments "_aio_kernel_suspend"
	 * when they are waiting in the kernel for completed I/Os.
	 *
	 * _kaio(AIONOTIFY) awakes the corresponding function
	 * in the kernel; then the corresponding __aio_waitn() or
	 * __aio_suspend() function could reap the recently
	 * completed I/Os (_aiodone()).
	 */
	if ((_aio_flags & AIO_WAIT_INPROGRESS) || _aio_kernel_suspend > 0)
		(void) _kaio(AIONOTIFY);

	sig_mutex_unlock(&__aio_mutex);

	if (head != NULL) {
		/*
		 * If all the lio requests have completed,
		 * prepare to notify the waiting thread.
		 */
		sig_mutex_lock(&head->lio_mutex);
		ASSERT(head->lio_refcnt == head->lio_nent);
		if (head->lio_refcnt == 1) {
			int waiting = 0;
			if (head->lio_mode == LIO_WAIT) {
				if ((waiting = head->lio_waiting) != 0)
					(void) cond_signal(&head->lio_cond_cv);
			} else if (head->lio_port < 0) { /* none or signal */
				if ((np.np_lio_signo = head->lio_signo) != 0)
					notify = 1;
				np.np_lio_user = head->lio_sigval.sival_ptr;
			} else {			/* thread or port */
				notify = 1;
				np.np_lio_port = head->lio_port;
				np.np_lio_event = head->lio_event;
				np.np_lio_object =
				    (uintptr_t)head->lio_sigevent;
				np.np_lio_user = head->lio_sigval.sival_ptr;
			}
			head->lio_nent = head->lio_refcnt = 0;
			sig_mutex_unlock(&head->lio_mutex);
			if (waiting == 0)
				_aio_lio_free(head);
		} else {
			head->lio_nent--;
			head->lio_refcnt--;
			sig_mutex_unlock(&head->lio_mutex);
		}
	}

	/*
	 * The request is completed; now perform the notifications.
	 */
	if (notify) {
		if (reqp != NULL) {
			/*
			 * We usually put the request on the notification
			 * queue because we don't want to block and delay
			 * other operations behind us in the work queue.
			 * Also we must never block on a cancel notification
			 * because we are being called from an application
			 * thread in this case and that could lead to deadlock
			 * if no other thread is receiving notificatins.
			 */
			reqp->req_notify = np;
			reqp->req_op = AIONOTIFY;
			_aio_req_add(reqp, &__workers_no, AIONOTIFY);
			reqp = NULL;
		} else {
			/*
			 * We already put the request on the done queue,
			 * so we can't queue it to the notification queue.
			 * Just do the notification directly.
			 */
			send_notification(&np);
		}
	}

	if (reqp != NULL)
		_aio_req_free(reqp);
}

/*
 * Delete fsync requests from list head until there is
 * only one left.  Return 0 when there is only one,
 * otherwise return a non-zero value.
 */
static int
_aio_fsync_del(aio_worker_t *aiowp, aio_req_t *reqp)
{
	aio_lio_t *head = reqp->req_head;
	int rval = 0;

	ASSERT(reqp == aiowp->work_req);
	sig_mutex_lock(&aiowp->work_qlock1);
	sig_mutex_lock(&head->lio_mutex);
	if (head->lio_refcnt > 1) {
		head->lio_refcnt--;
		head->lio_nent--;
		aiowp->work_req = NULL;
		sig_mutex_unlock(&head->lio_mutex);
		sig_mutex_unlock(&aiowp->work_qlock1);
		sig_mutex_lock(&__aio_mutex);
		_aio_outstand_cnt--;
		_aio_waitn_wakeup();
		sig_mutex_unlock(&__aio_mutex);
		_aio_req_free(reqp);
		return (1);
	}
	ASSERT(head->lio_nent == 1 && head->lio_refcnt == 1);
	reqp->req_head = NULL;
	if (head->lio_canned)
		reqp->req_state = AIO_REQ_CANCELED;
	if (head->lio_mode == LIO_DESTROY) {
		aiowp->work_req = NULL;
		rval = 1;
	}
	sig_mutex_unlock(&head->lio_mutex);
	sig_mutex_unlock(&aiowp->work_qlock1);
	head->lio_refcnt--;
	head->lio_nent--;
	_aio_lio_free(head);
	if (rval != 0)
		_aio_req_free(reqp);
	return (rval);
}

/*
 * A worker is set idle when its work queue is empty.
 * The worker checks again that it has no more work
 * and then goes to sleep waiting for more work.
 */
int
_aio_idle(aio_worker_t *aiowp)
{
	int error = 0;

	sig_mutex_lock(&aiowp->work_qlock1);
	if (aiowp->work_count1 == 0) {
		ASSERT(aiowp->work_minload1 == 0);
		aiowp->work_idleflg = 1;
		/*
		 * A cancellation handler is not needed here.
		 * aio worker threads are never cancelled via pthread_cancel().
		 */
		error = sig_cond_wait(&aiowp->work_idle_cv,
		    &aiowp->work_qlock1);
		/*
		 * The idle flag is normally cleared before worker is awakened
		 * by aio_req_add().  On error (EINTR), we clear it ourself.
		 */
		if (error)
			aiowp->work_idleflg = 0;
	}
	sig_mutex_unlock(&aiowp->work_qlock1);
	return (error);
}

/*
 * A worker's completed AIO requests are placed onto a global
 * done queue.  The application is only sent a SIGIO signal if
 * the process has a handler enabled and it is not waiting via
 * aiowait().
 */
static void
_aio_work_done(aio_worker_t *aiowp)
{
	aio_req_t *reqp;

	sig_mutex_lock(&__aio_mutex);
	sig_mutex_lock(&aiowp->work_qlock1);
	reqp = aiowp->work_prev1;
	reqp->req_next = NULL;
	aiowp->work_done1 = 0;
	aiowp->work_tail1 = aiowp->work_next1;
	if (aiowp->work_tail1 == NULL)
		aiowp->work_head1 = NULL;
	aiowp->work_prev1 = NULL;
	_aio_outstand_cnt--;
	_aio_req_done_cnt--;
	if (reqp->req_state == AIO_REQ_CANCELED) {
		/*
		 * Request got cancelled after it was marked done. This can
		 * happen because _aio_finish_request() marks it AIO_REQ_DONE
		 * and drops all locks. Don't add the request to the done
		 * queue and just discard it.
		 */
		sig_mutex_unlock(&aiowp->work_qlock1);
		_aio_req_free(reqp);
		if (_aio_outstand_cnt == 0 && _aiowait_flag) {
			sig_mutex_unlock(&__aio_mutex);
			(void) _kaio(AIONOTIFY);
		} else {
			sig_mutex_unlock(&__aio_mutex);
		}
		return;
	}
	sig_mutex_unlock(&aiowp->work_qlock1);
	_aio_donecnt++;
	ASSERT(_aio_donecnt > 0 &&
	    _aio_outstand_cnt >= 0 &&
	    _aio_req_done_cnt >= 0);
	ASSERT(reqp != NULL);

	if (_aio_done_tail == NULL) {
		_aio_done_head = _aio_done_tail = reqp;
	} else {
		_aio_done_head->req_next = reqp;
		_aio_done_head = reqp;
	}

	if (_aiowait_flag) {
		sig_mutex_unlock(&__aio_mutex);
		(void) _kaio(AIONOTIFY);
	} else {
		sig_mutex_unlock(&__aio_mutex);
		if (_sigio_enabled)
			(void) kill(__pid, SIGIO);
	}
}

/*
 * The done queue consists of AIO requests that are in either the
 * AIO_REQ_DONE or AIO_REQ_CANCELED state.  Requests that were cancelled
 * are discarded.  If the done queue is empty then NULL is returned.
 * Otherwise the address of a done aio_result_t is returned.
 */
aio_result_t *
_aio_req_done(void)
{
	aio_req_t *reqp;
	aio_result_t *resultp;

	ASSERT(MUTEX_HELD(&__aio_mutex));

	if ((reqp = _aio_done_tail) != NULL) {
		if ((_aio_done_tail = reqp->req_next) == NULL)
			_aio_done_head = NULL;
		ASSERT(_aio_donecnt > 0);
		_aio_donecnt--;
		(void) _aio_hash_del(reqp->req_resultp);
		resultp = reqp->req_resultp;
		ASSERT(reqp->req_state == AIO_REQ_DONE);
		_aio_req_free(reqp);
		return (resultp);
	}
	/* is queue empty? */
	if (reqp == NULL && _aio_outstand_cnt == 0) {
		return ((aio_result_t *)-1);
	}
	return (NULL);
}

/*
 * Set the return and errno values for the application's use.
 *
 * For the Posix interfaces, we must set the return value first followed
 * by the errno value because the Posix interfaces allow for a change
 * in the errno value from EINPROGRESS to something else to signal
 * the completion of the asynchronous request.
 *
 * The opposite is true for the Solaris interfaces.  These allow for
 * a change in the return value from AIO_INPROGRESS to something else
 * to signal the completion of the asynchronous request.
 */
void
_aio_set_result(aio_req_t *reqp, ssize_t retval, int error)
{
	aio_result_t *resultp = reqp->req_resultp;

	if (POSIX_AIO(reqp)) {
		resultp->aio_return = retval;
		membar_producer();
		resultp->aio_errno = error;
	} else {
		resultp->aio_errno = error;
		membar_producer();
		resultp->aio_return = retval;
	}
}

/*
 * Add an AIO request onto the next work queue.
 * A circular list of workers is used to choose the next worker.
 */
void
_aio_req_add(aio_req_t *reqp, aio_worker_t **nextworker, int mode)
{
	ulwp_t *self = curthread;
	aio_worker_t *aiowp;
	aio_worker_t *first;
	int load_bal_flg = 1;
	int found;

	ASSERT(reqp->req_state != AIO_REQ_DONEQ);
	reqp->req_next = NULL;
	/*
	 * Try to acquire the next worker's work queue.  If it is locked,
	 * then search the list of workers until a queue is found unlocked,
	 * or until the list is completely traversed at which point another
	 * worker will be created.
	 */
	sigoff(self);		/* defer SIGIO */
	sig_mutex_lock(&__aio_mutex);
	first = aiowp = *nextworker;
	if (mode != AIONOTIFY)
		_aio_outstand_cnt++;
	sig_mutex_unlock(&__aio_mutex);

	switch (mode) {
	case AIOREAD:
	case AIOWRITE:
	case AIOAREAD:
	case AIOAWRITE:
#if !defined(_LP64)
	case AIOAREAD64:
	case AIOAWRITE64:
#endif
		/* try to find an idle worker */
		found = 0;
		do {
			if (sig_mutex_trylock(&aiowp->work_qlock1) == 0) {
				if (aiowp->work_idleflg) {
					found = 1;
					break;
				}
				sig_mutex_unlock(&aiowp->work_qlock1);
			}
		} while ((aiowp = aiowp->work_forw) != first);

		if (found) {
			aiowp->work_minload1++;
			break;
		}

		/* try to acquire some worker's queue lock */
		do {
			if (sig_mutex_trylock(&aiowp->work_qlock1) == 0) {
				found = 1;
				break;
			}
		} while ((aiowp = aiowp->work_forw) != first);

		/*
		 * Create more workers when the workers appear overloaded.
		 * Either all the workers are busy draining their queues
		 * or no worker's queue lock could be acquired.
		 */
		if (!found) {
			if (_aio_worker_cnt < _max_workers) {
				if (_aio_create_worker(reqp, mode))
					aio_panic("_aio_req_add: add worker");
				sigon(self);	/* reenable SIGIO */
				return;
			}

			/*
			 * No worker available and we have created
			 * _max_workers, keep going through the
			 * list slowly until we get a lock
			 */
			while (sig_mutex_trylock(&aiowp->work_qlock1) != 0) {
				/*
				 * give someone else a chance
				 */
				_aio_delay(1);
				aiowp = aiowp->work_forw;
			}
		}

		ASSERT(MUTEX_HELD(&aiowp->work_qlock1));
		if (_aio_worker_cnt < _max_workers &&
		    aiowp->work_minload1 >= _minworkload) {
			sig_mutex_unlock(&aiowp->work_qlock1);
			sig_mutex_lock(&__aio_mutex);
			*nextworker = aiowp->work_forw;
			sig_mutex_unlock(&__aio_mutex);
			if (_aio_create_worker(reqp, mode))
				aio_panic("aio_req_add: add worker");
			sigon(self);	/* reenable SIGIO */
			return;
		}
		aiowp->work_minload1++;
		break;
	case AIOFSYNC:
	case AIONOTIFY:
		load_bal_flg = 0;
		sig_mutex_lock(&aiowp->work_qlock1);
		break;
	default:
		aio_panic("_aio_req_add: invalid mode");
		break;
	}
	/*
	 * Put request onto worker's work queue.
	 */
	if (aiowp->work_tail1 == NULL) {
		ASSERT(aiowp->work_count1 == 0);
		aiowp->work_tail1 = reqp;
		aiowp->work_next1 = reqp;
	} else {
		aiowp->work_head1->req_next = reqp;
		if (aiowp->work_next1 == NULL)
			aiowp->work_next1 = reqp;
	}
	reqp->req_state = AIO_REQ_QUEUED;
	reqp->req_worker = aiowp;
	aiowp->work_head1 = reqp;
	/*
	 * Awaken worker if it is not currently active.
	 */
	if (aiowp->work_count1++ == 0 && aiowp->work_idleflg) {
		aiowp->work_idleflg = 0;
		(void) cond_signal(&aiowp->work_idle_cv);
	}
	sig_mutex_unlock(&aiowp->work_qlock1);

	if (load_bal_flg) {
		sig_mutex_lock(&__aio_mutex);
		*nextworker = aiowp->work_forw;
		sig_mutex_unlock(&__aio_mutex);
	}
	sigon(self);	/* reenable SIGIO */
}

/*
 * Get an AIO request for a specified worker.
 * If the work queue is empty, return NULL.
 */
aio_req_t *
_aio_req_get(aio_worker_t *aiowp)
{
	aio_req_t *reqp;

	sig_mutex_lock(&aiowp->work_qlock1);
	if ((reqp = aiowp->work_next1) != NULL) {
		/*
		 * Remove a POSIX request from the queue; the
		 * request queue is a singularly linked list
		 * with a previous pointer.  The request is
		 * removed by updating the previous pointer.
		 *
		 * Non-posix requests are left on the queue
		 * to eventually be placed on the done queue.
		 */

		if (POSIX_AIO(reqp)) {
			if (aiowp->work_prev1 == NULL) {
				aiowp->work_tail1 = reqp->req_next;
				if (aiowp->work_tail1 == NULL)
					aiowp->work_head1 = NULL;
			} else {
				aiowp->work_prev1->req_next = reqp->req_next;
				if (aiowp->work_head1 == reqp)
					aiowp->work_head1 = reqp->req_next;
			}

		} else {
			aiowp->work_prev1 = reqp;
			ASSERT(aiowp->work_done1 >= 0);
			aiowp->work_done1++;
		}
		ASSERT(reqp != reqp->req_next);
		aiowp->work_next1 = reqp->req_next;
		ASSERT(aiowp->work_count1 >= 1);
		aiowp->work_count1--;
		switch (reqp->req_op) {
		case AIOREAD:
		case AIOWRITE:
		case AIOAREAD:
		case AIOAWRITE:
#if !defined(_LP64)
		case AIOAREAD64:
		case AIOAWRITE64:
#endif
			ASSERT(aiowp->work_minload1 > 0);
			aiowp->work_minload1--;
			break;
		}
		reqp->req_state = AIO_REQ_INPROGRESS;
	}
	aiowp->work_req = reqp;
	ASSERT(reqp != NULL || aiowp->work_count1 == 0);
	sig_mutex_unlock(&aiowp->work_qlock1);
	return (reqp);
}

static void
_aio_req_del(aio_worker_t *aiowp, aio_req_t *reqp, int ostate)
{
	aio_req_t **last;
	aio_req_t *lastrp;
	aio_req_t *next;

	ASSERT(aiowp != NULL);
	ASSERT(MUTEX_HELD(&aiowp->work_qlock1));
	if (POSIX_AIO(reqp)) {
		if (ostate != AIO_REQ_QUEUED)
			return;
	}
	last = &aiowp->work_tail1;
	lastrp = aiowp->work_tail1;
	ASSERT(ostate == AIO_REQ_QUEUED || ostate == AIO_REQ_INPROGRESS);
	while ((next = *last) != NULL) {
		if (next == reqp) {
			*last = next->req_next;
			if (aiowp->work_next1 == next)
				aiowp->work_next1 = next->req_next;

			/*
			 * if this is the first request on the queue, move
			 * the lastrp pointer forward.
			 */
			if (lastrp == next)
				lastrp = next->req_next;

			/*
			 * if this request is pointed by work_head1, then
			 * make work_head1 point to the last request that is
			 * present on the queue.
			 */
			if (aiowp->work_head1 == next)
				aiowp->work_head1 = lastrp;

			/*
			 * work_prev1 is used only in non posix case and it
			 * points to the current AIO_REQ_INPROGRESS request.
			 * If work_prev1 points to this request which is being
			 * deleted, make work_prev1 NULL and set  work_done1
			 * to 0.
			 *
			 * A worker thread can be processing only one request
			 * at a time.
			 */
			if (aiowp->work_prev1 == next) {
				ASSERT(ostate == AIO_REQ_INPROGRESS &&
				    !POSIX_AIO(reqp) && aiowp->work_done1 > 0);
				aiowp->work_prev1 = NULL;
				aiowp->work_done1--;
			}

			if (ostate == AIO_REQ_QUEUED) {
				ASSERT(aiowp->work_count1 >= 1);
				aiowp->work_count1--;
				ASSERT(aiowp->work_minload1 >= 1);
				aiowp->work_minload1--;
			}
			return;
		}
		last = &next->req_next;
		lastrp = next;
	}
	/* NOTREACHED */
}

static void
_aio_enq_doneq(aio_req_t *reqp)
{
	if (_aio_doneq == NULL) {
		_aio_doneq = reqp;
		reqp->req_next = reqp->req_prev = reqp;
	} else {
		reqp->req_next = _aio_doneq;
		reqp->req_prev = _aio_doneq->req_prev;
		_aio_doneq->req_prev->req_next = reqp;
		_aio_doneq->req_prev = reqp;
	}
	reqp->req_state = AIO_REQ_DONEQ;
	_aio_doneq_cnt++;
}

/*
 * caller owns the _aio_mutex
 */
aio_req_t *
_aio_req_remove(aio_req_t *reqp)
{
	if (reqp && reqp->req_state != AIO_REQ_DONEQ)
		return (NULL);

	if (reqp) {
		/* request in done queue */
		if (_aio_doneq == reqp)
			_aio_doneq = reqp->req_next;
		if (_aio_doneq == reqp) {
			/* only one request on queue */
			_aio_doneq = NULL;
		} else {
			aio_req_t *tmp = reqp->req_next;
			reqp->req_prev->req_next = tmp;
			tmp->req_prev = reqp->req_prev;
		}
	} else if ((reqp = _aio_doneq) != NULL) {
		if (reqp == reqp->req_next) {
			/* only one request on queue */
			_aio_doneq = NULL;
		} else {
			reqp->req_prev->req_next = _aio_doneq = reqp->req_next;
			_aio_doneq->req_prev = reqp->req_prev;
		}
	}
	if (reqp) {
		_aio_doneq_cnt--;
		reqp->req_next = reqp->req_prev = reqp;
		reqp->req_state = AIO_REQ_DONE;
	}
	return (reqp);
}

/*
 * An AIO request is identified by an aio_result_t pointer.  The library
 * maps this aio_result_t pointer to its internal representation using a
 * hash table.  This function adds an aio_result_t pointer to the hash table.
 */
static int
_aio_hash_insert(aio_result_t *resultp, aio_req_t *reqp)
{
	aio_hash_t *hashp;
	aio_req_t **prev;
	aio_req_t *next;

	hashp = _aio_hash + AIOHASH(resultp);
	lmutex_lock(&hashp->hash_lock);
	prev = &hashp->hash_ptr;
	while ((next = *prev) != NULL) {
		if (resultp == next->req_resultp) {
			lmutex_unlock(&hashp->hash_lock);
			return (-1);
		}
		prev = &next->req_link;
	}
	*prev = reqp;
	ASSERT(reqp->req_link == NULL);
	lmutex_unlock(&hashp->hash_lock);
	return (0);
}

/*
 * Remove an entry from the hash table.
 */
aio_req_t *
_aio_hash_del(aio_result_t *resultp)
{
	aio_hash_t *hashp;
	aio_req_t **prev;
	aio_req_t *next = NULL;

	if (_aio_hash != NULL) {
		hashp = _aio_hash + AIOHASH(resultp);
		lmutex_lock(&hashp->hash_lock);
		prev = &hashp->hash_ptr;
		while ((next = *prev) != NULL) {
			if (resultp == next->req_resultp) {
				*prev = next->req_link;
				next->req_link = NULL;
				break;
			}
			prev = &next->req_link;
		}
		lmutex_unlock(&hashp->hash_lock);
	}
	return (next);
}

/*
 *  find an entry in the hash table
 */
aio_req_t *
_aio_hash_find(aio_result_t *resultp)
{
	aio_hash_t *hashp;
	aio_req_t **prev;
	aio_req_t *next = NULL;

	if (_aio_hash != NULL) {
		hashp = _aio_hash + AIOHASH(resultp);
		lmutex_lock(&hashp->hash_lock);
		prev = &hashp->hash_ptr;
		while ((next = *prev) != NULL) {
			if (resultp == next->req_resultp)
				break;
			prev = &next->req_link;
		}
		lmutex_unlock(&hashp->hash_lock);
	}
	return (next);
}

/*
 * AIO interface for POSIX
 */
int
_aio_rw(aiocb_t *aiocbp, aio_lio_t *lio_head, aio_worker_t **nextworker,
    int mode, int flg)
{
	aio_req_t *reqp;
	aio_args_t *ap;
	int kerr;

	if (aiocbp == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* initialize kaio */
	if (!_kaio_ok)
		_kaio_init();

	aiocbp->aio_state = NOCHECK;

	/*
	 * If we have been called because a list I/O
	 * kaio() failed, we dont want to repeat the
	 * system call
	 */

	if (flg & AIO_KAIO) {
		/*
		 * Try kernel aio first.
		 * If errno is ENOTSUP/EBADFD,
		 * fall back to the thread implementation.
		 */
		if (_kaio_ok > 0 && KAIO_SUPPORTED(aiocbp->aio_fildes)) {
			aiocbp->aio_resultp.aio_errno = EINPROGRESS;
			aiocbp->aio_state = CHECK;
			kerr = (int)_kaio(mode, aiocbp);
			if (kerr == 0)
				return (0);
			if (errno != ENOTSUP && errno != EBADFD) {
				aiocbp->aio_resultp.aio_errno = errno;
				aiocbp->aio_resultp.aio_return = -1;
				aiocbp->aio_state = NOCHECK;
				return (-1);
			}
			if (errno == EBADFD)
				SET_KAIO_NOT_SUPPORTED(aiocbp->aio_fildes);
		}
	}

	aiocbp->aio_resultp.aio_errno = EINPROGRESS;
	aiocbp->aio_state = USERAIO;

	if (!__uaio_ok && __uaio_init() == -1)
		return (-1);

	if ((reqp = _aio_req_alloc()) == NULL) {
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * If an LIO request, add the list head to the aio request
	 */
	reqp->req_head = lio_head;
	reqp->req_type = AIO_POSIX_REQ;
	reqp->req_op = mode;
	reqp->req_largefile = 0;

	if (aiocbp->aio_sigevent.sigev_notify == SIGEV_NONE) {
		reqp->req_sigevent.sigev_notify = SIGEV_NONE;
	} else if (aiocbp->aio_sigevent.sigev_notify == SIGEV_SIGNAL) {
		reqp->req_sigevent.sigev_notify = SIGEV_SIGNAL;
		reqp->req_sigevent.sigev_signo =
		    aiocbp->aio_sigevent.sigev_signo;
		reqp->req_sigevent.sigev_value.sival_ptr =
		    aiocbp->aio_sigevent.sigev_value.sival_ptr;
	} else if (aiocbp->aio_sigevent.sigev_notify == SIGEV_PORT) {
		port_notify_t *pn = aiocbp->aio_sigevent.sigev_value.sival_ptr;
		reqp->req_sigevent.sigev_notify = SIGEV_PORT;
		/*
		 * Reuse the sigevent structure to contain the port number
		 * and the user value.  Same for SIGEV_THREAD, below.
		 */
		reqp->req_sigevent.sigev_signo =
		    pn->portnfy_port;
		reqp->req_sigevent.sigev_value.sival_ptr =
		    pn->portnfy_user;
	} else if (aiocbp->aio_sigevent.sigev_notify == SIGEV_THREAD) {
		reqp->req_sigevent.sigev_notify = SIGEV_THREAD;
		/*
		 * The sigevent structure contains the port number
		 * and the user value.  Same for SIGEV_PORT, above.
		 */
		reqp->req_sigevent.sigev_signo =
		    aiocbp->aio_sigevent.sigev_signo;
		reqp->req_sigevent.sigev_value.sival_ptr =
		    aiocbp->aio_sigevent.sigev_value.sival_ptr;
	}

	reqp->req_resultp = &aiocbp->aio_resultp;
	reqp->req_aiocbp = aiocbp;
	ap = &reqp->req_args;
	ap->fd = aiocbp->aio_fildes;
	ap->buf = (caddr_t)aiocbp->aio_buf;
	ap->bufsz = aiocbp->aio_nbytes;
	ap->offset = aiocbp->aio_offset;

	if ((flg & AIO_NO_DUPS) &&
	    _aio_hash_insert(&aiocbp->aio_resultp, reqp) != 0) {
		aio_panic("_aio_rw(): request already in hash table");
	}
	_aio_req_add(reqp, nextworker, mode);
	return (0);
}

#if !defined(_LP64)
/*
 * 64-bit AIO interface for POSIX
 */
int
_aio_rw64(aiocb64_t *aiocbp, aio_lio_t *lio_head, aio_worker_t **nextworker,
    int mode, int flg)
{
	aio_req_t *reqp;
	aio_args_t *ap;
	int kerr;

	if (aiocbp == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* initialize kaio */
	if (!_kaio_ok)
		_kaio_init();

	aiocbp->aio_state = NOCHECK;

	/*
	 * If we have been called because a list I/O
	 * kaio() failed, we dont want to repeat the
	 * system call
	 */

	if (flg & AIO_KAIO) {
		/*
		 * Try kernel aio first.
		 * If errno is ENOTSUP/EBADFD,
		 * fall back to the thread implementation.
		 */
		if (_kaio_ok > 0 && KAIO_SUPPORTED(aiocbp->aio_fildes)) {
			aiocbp->aio_resultp.aio_errno = EINPROGRESS;
			aiocbp->aio_state = CHECK;
			kerr = (int)_kaio(mode, aiocbp);
			if (kerr == 0)
				return (0);
			if (errno != ENOTSUP && errno != EBADFD) {
				aiocbp->aio_resultp.aio_errno = errno;
				aiocbp->aio_resultp.aio_return = -1;
				aiocbp->aio_state = NOCHECK;
				return (-1);
			}
			if (errno == EBADFD)
				SET_KAIO_NOT_SUPPORTED(aiocbp->aio_fildes);
		}
	}

	aiocbp->aio_resultp.aio_errno = EINPROGRESS;
	aiocbp->aio_state = USERAIO;

	if (!__uaio_ok && __uaio_init() == -1)
		return (-1);

	if ((reqp = _aio_req_alloc()) == NULL) {
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * If an LIO request, add the list head to the aio request
	 */
	reqp->req_head = lio_head;
	reqp->req_type = AIO_POSIX_REQ;
	reqp->req_op = mode;
	reqp->req_largefile = 1;

	if (aiocbp->aio_sigevent.sigev_notify == SIGEV_NONE) {
		reqp->req_sigevent.sigev_notify = SIGEV_NONE;
	} else if (aiocbp->aio_sigevent.sigev_notify == SIGEV_SIGNAL) {
		reqp->req_sigevent.sigev_notify = SIGEV_SIGNAL;
		reqp->req_sigevent.sigev_signo =
		    aiocbp->aio_sigevent.sigev_signo;
		reqp->req_sigevent.sigev_value.sival_ptr =
		    aiocbp->aio_sigevent.sigev_value.sival_ptr;
	} else if (aiocbp->aio_sigevent.sigev_notify == SIGEV_PORT) {
		port_notify_t *pn = aiocbp->aio_sigevent.sigev_value.sival_ptr;
		reqp->req_sigevent.sigev_notify = SIGEV_PORT;
		reqp->req_sigevent.sigev_signo =
		    pn->portnfy_port;
		reqp->req_sigevent.sigev_value.sival_ptr =
		    pn->portnfy_user;
	} else if (aiocbp->aio_sigevent.sigev_notify == SIGEV_THREAD) {
		reqp->req_sigevent.sigev_notify = SIGEV_THREAD;
		reqp->req_sigevent.sigev_signo =
		    aiocbp->aio_sigevent.sigev_signo;
		reqp->req_sigevent.sigev_value.sival_ptr =
		    aiocbp->aio_sigevent.sigev_value.sival_ptr;
	}

	reqp->req_resultp = &aiocbp->aio_resultp;
	reqp->req_aiocbp = aiocbp;
	ap = &reqp->req_args;
	ap->fd = aiocbp->aio_fildes;
	ap->buf = (caddr_t)aiocbp->aio_buf;
	ap->bufsz = aiocbp->aio_nbytes;
	ap->offset = aiocbp->aio_offset;

	if ((flg & AIO_NO_DUPS) &&
	    _aio_hash_insert(&aiocbp->aio_resultp, reqp) != 0) {
		aio_panic("_aio_rw64(): request already in hash table");
	}
	_aio_req_add(reqp, nextworker, mode);
	return (0);
}
#endif	/* !defined(_LP64) */
