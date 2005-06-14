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

#include "libaio.h"
#include <sys/param.h>
#include <sys/file.h>
#include <sys/port.h>

static int _aio_hash_insert(aio_result_t *, aio_req_t *);
static aio_req_t *_aio_req_alloc(void);
static aio_req_t *_aio_req_get(aio_worker_t *);
static void _aio_req_add(aio_req_t *, aio_worker_t **, int);
static void _aio_req_del(aio_worker_t *, aio_req_t *, int);
static aio_result_t *_aio_req_done(void);
static void _aio_work_done(aio_worker_t *);
aio_req_t *_aio_req_remove(aio_req_t *reqp);
static void _aio_enq_doneq(aio_req_t *reqp);
int _aio_get_timedelta(struct timespec *end, struct timespec *wait);

aio_req_t *_aio_hash_find(aio_result_t *);
void _aio_req_free(aio_req_t *);
void _aio_lock(void);
void _aio_unlock(void);

extern int __fdsync(int fd, int mode);
extern int _sigprocmask(int, const sigset_t *, sigset_t *);
extern int _port_dispatch(int, int, int, int, uintptr_t, void *);

static int _aio_fsync_del(aio_req_t *, aio_lio_t *);
static int _aiodone(aio_req_t *, aio_lio_t *, int, ssize_t, int);
static void _aio_cancel_work(aio_worker_t *, int, int *, int *);

#ifdef DEBUG
void _aio_stats(void);
#endif

int _pagesize;

#define	AIOREQSZ		(sizeof (struct aio_req))
#define	AIOCLICKS		((_pagesize)/AIOREQSZ)
#define	HASHSZ			8192L	/* power of 2 */
#define	AIOHASH(resultp)	((((uintptr_t)(resultp) >> 13) ^ \
				    ((uintptr_t)(resultp))) & (HASHSZ-1))
#define	POSIX_AIO(x)		((x)->req_type == AIO_POSIX_REQ)

/*
 * switch for kernel async I/O
 */
int _kaio_ok = 0;			/* 0 = disabled, 1 = on, -1 = error */

/*
 * Key for thread-specific data
 */
thread_key_t _aio_key = 0;

/*
 * Array for determining whether or not a file supports kaio
 */
uint32_t _kaio_supported[MAX_KAIO_FDARRAY_SIZE];

int _aioreqsize = AIOREQSZ;

#ifdef DEBUG
int *_donecnt;				/* per worker AIO done count */
int *_idlecnt;				/* per worker idle count */
int *_qfullcnt;				/* per worker full q count */
int *_firstqcnt;			/* num times queue one is used */
int *_newworker;			/* num times new worker is created */
int _clogged = 0;			/* num times all queues are locked */
int _qlocked = 0;			/* num times submitter finds q locked */
int _aio_submitcnt = 0;
int _aio_submitcnt2 = 0;
int _submitcnt = 0;
int _avesubmitcnt = 0;
int _aiowaitcnt = 0;
int _startaiowaitcnt = 1;
int _avedone = 0;
int _new_workers = 0;
#endif

/*
 *  workers for read requests.
 * (__aio_mutex lock protects circular linked list of workers.)
 */
aio_worker_t *__workers_rd;	/* circular list of AIO workers */
aio_worker_t *__nextworker_rd;	/* next worker in list of workers */
int __rd_workerscnt;		/* number of read workers */

/*
 * workers for write requests.
 * (__aio_mutex lock protects circular linked list of workers.)
 */
aio_worker_t *__workers_wr;	/* circular list of AIO workers */
aio_worker_t *__nextworker_wr;	/* next worker in list of workers */
int __wr_workerscnt;		/* number of write workers */

/*
 * worker for sigevent requests.
 */
aio_worker_t *__workers_si;	/* circular list of AIO workers */
aio_worker_t *__nextworker_si;	/* next worker in list of workers */
int __si_workerscnt;		/* number of write workers */

struct aio_req *_aio_done_tail;		/* list of done requests */
struct aio_req *_aio_done_head;

mutex_t __aio_initlock = DEFAULTMUTEX;	/* makes aio initialization atomic */
mutex_t __aio_mutex = DEFAULTMUTEX;	/* protects counts, and linked lists */
mutex_t __aio_cachefillock = DEFAULTMUTEX; /* single-thread aio cache filling */
cond_t _aio_iowait_cv = DEFAULTCV;	/* wait for userland I/Os */
cond_t __aio_cachefillcv = DEFAULTCV;	/* sleep cv for cache filling */

mutex_t __lio_mutex = DEFAULTMUTEX;	/* protects lio lists */

int __aiostksz;				/* aio worker's stack size */
int __aio_cachefilling = 0;		/* set when aio cache is filling */
int __sigio_masked = 0;			/* bit mask for SIGIO signal */
int __sigio_maskedcnt = 0;		/* mask count for SIGIO signal */
pid_t __pid = (pid_t)-1;		/* initialize as invalid pid */
static struct aio_req **_aio_hash;
static struct aio_req *_aio_freelist;
static struct aio_req *_aio_doneq;	/* double linked done queue list */
static int _aio_freelist_cnt;

static struct sigaction act;

cond_t _aio_done_cv = DEFAULTCV;

/*
 * Input queue of requests which is serviced by the aux. threads.
 */
cond_t _aio_idle_cv = DEFAULTCV;

int _aio_cnt = 0;
int _aio_donecnt = 0;
int _aio_waitncnt = 0;			/* # fs requests for aio_waitn */
int _aio_doneq_cnt = 0;
int _aio_outstand_cnt = 0;		/* number of outstanding requests */
int _aio_outstand_waitn = 0;		/* # of queued requests for aio_waitn */
int _aio_req_done_cnt = 0;		/* req. done but not in "done queue" */
int _aio_kernel_suspend = 0;		/* active kernel kaio calls */
int _aio_suscv_cnt = 0;			/* aio_suspend calls waiting on cv's */

int _max_workers = 256;			/* max number of workers permitted */
int _min_workers = 8;			/* min number of workers */
int _maxworkload = 32;			/* max length of worker's request q */
int _minworkload = 2;			/* min number of request in q */
int _aio_worker_cnt = 0;		/* number of workers to do requests */
int _idle_workers = 0;			/* number of idle workers */
int __uaio_ok = 0;			/* AIO has been enabled */
sigset_t _worker_set;			/* worker's signal mask */

int _aiowait_flag = 0;			/* when set, aiowait() is inprogress */
int _aio_flags = 0;			/* see libaio.h defines for */

struct aio_worker *_kaiowp;		/* points to kaio cleanup thread */

/*
 * called by the child when the main thread forks. the child is
 * cleaned up so that it can use libaio.
 */
void
_aio_forkinit(void)
{
	__uaio_ok = 0;
	__workers_rd = NULL;
	__nextworker_rd = NULL;
	__workers_wr = NULL;
	__nextworker_wr = NULL;
	_aio_done_tail = NULL;
	_aio_done_head = NULL;
	_aio_hash = NULL;
	_aio_freelist = NULL;
	_aio_freelist_cnt = 0;
	_aio_doneq = NULL;
	_aio_doneq_cnt = 0;
	_aio_waitncnt = 0;
	_aio_outstand_cnt = 0;
	_aio_outstand_waitn = 0;
	_aio_req_done_cnt = 0;
	_aio_kernel_suspend = 0;
	_aio_suscv_cnt = 0;
	_aio_flags = 0;
	_aio_worker_cnt = 0;
	_idle_workers = 0;
	_kaio_ok = 0;
#ifdef	DEBUG
	_clogged = 0;
	_qlocked = 0;
#endif
}

#ifdef DEBUG
/*
 * print out a bunch of interesting statistics when the process
 * exits.
 */
void
_aio_stats()
{
	int i;
	char *fmt;
	int cnt;
	FILE *fp;

	fp = fopen("/tmp/libaio.log", "w+a");
	if (fp == NULL)
		return;
	fprintf(fp, "size of AIO request struct = %d bytes\n", _aioreqsize);
	fprintf(fp, "number of AIO workers = %d\n", _aio_worker_cnt);
	cnt = _aio_worker_cnt + 1;
	for (i = 2; i <= cnt; i++) {
		fmt = "%d done %d, idle = %d, qfull = %d, newworker = %d\n";
		fprintf(fp, fmt, i, _donecnt[i], _idlecnt[i], _qfullcnt[i],
		    _newworker[i]);
	}
	fprintf(fp, "num times submitter found next work queue locked = %d\n",
	    _qlocked);
	fprintf(fp, "num times submitter found all work queues locked = %d\n",
	    _clogged);
	fprintf(fp, "average submit request = %d\n", _avesubmitcnt);
	fprintf(fp, "average number of submit requests per new worker = %d\n",
	    _avedone);
}
#endif

/*
 * libaio is initialized when an AIO request is made. important
 * constants are initialized like the max number of workers that
 * libaio can create, and the minimum number of workers permitted before
 * imposing some restrictions. also, some workers are created.
 */
int
__uaio_init(void)
{
	int i;
	size_t size;
	extern sigset_t __sigiomask;
	struct sigaction oact;

	(void) mutex_lock(&__aio_initlock);
	if (_aio_key == 0 &&
	    thr_keycreate(&_aio_key, _aio_free_worker) != 0)
		_aiopanic("__uaio_init, thr_keycreate()\n");
	if (!__uaio_ok) {
		__pid = getpid();

		if (_sigaction(SIGAIOCANCEL, NULL, &oact) == -1) {
			(void) mutex_unlock(&__aio_initlock);
			return (-1);
		}

		if (oact.sa_handler != aiosigcancelhndlr) {
			act.sa_handler = aiosigcancelhndlr;
			act.sa_flags = SA_SIGINFO;
			if (_sigaction(SIGAIOCANCEL, &act, &sigcanact) == -1) {
				(void) mutex_unlock(&__aio_initlock);
				return (-1);
			}
		}

		/*
		 * Constant sigiomask, used by _aiosendsig()
		 */
		(void) sigaddset(&__sigiomask, SIGIO);
#ifdef DEBUG
		size = _max_workers * (sizeof (int) * 5 +
		    sizeof (int));
		_donecnt = malloc(size);
		(void) memset((caddr_t)_donecnt, 0, size);
		_idlecnt = _donecnt + _max_workers;
		_qfullcnt = _idlecnt + _max_workers;
		_firstqcnt = _qfullcnt + _max_workers;
		_newworker = _firstqcnt + _max_workers;
		atexit(_aio_stats);
#endif
		size = HASHSZ * sizeof (struct aio_req *);
		_aio_hash = malloc(size);
		if (_aio_hash == NULL) {
			(void) mutex_unlock(&__aio_initlock);
			return (-1);
		}
		(void) memset((caddr_t)_aio_hash, 0, size);

		/* initialize worker's signal mask to only catch SIGAIOCANCEL */
		(void) sigfillset(&_worker_set);
		(void) sigdelset(&_worker_set, SIGAIOCANCEL);

		/*
		 * Create equal number of READ and WRITE workers.
		 */
		i = 0;
		while (i++ < (_min_workers/2))
			(void) _aio_create_worker(NULL, AIOREAD);
		i = 0;
		while (i++ < (_min_workers/2))
			(void) _aio_create_worker(NULL, AIOWRITE);

		/* create one worker to send completion signals. */
		(void) _aio_create_worker(NULL, AIOSIGEV);
		(void) mutex_unlock(&__aio_initlock);
		__uaio_ok = 1;
		return (0);
	}

	(void) mutex_unlock(&__aio_initlock);
	return (0);
}

/*
 * special kaio cleanup thread sits in a loop in the
 * kernel waiting for pending kaio requests to complete.
 */
void *
_kaio_cleanup_thread(void *arg)
{
	if (thr_setspecific(_aio_key, arg) != 0)
		_aiopanic("_kaio_cleanup_thread, thr_setspecific()\n");
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
	sigset_t set, oset;

	(void) mutex_lock(&__aio_initlock);
	if (_aio_key == 0 &&
	    thr_keycreate(&_aio_key, _aio_free_worker) != 0)
		_aiopanic("_kaio_init, thr_keycreate()\n");
	if (!_kaio_ok) {
		_pagesize = (int)PAGESIZE;
		__aiostksz = 8 * _pagesize;
		if ((_kaiowp = _aio_alloc_worker()) == NULL) {
			error =  ENOMEM;
		} else {
			if ((error = (int)_kaio(AIOINIT)) == 0) {
				(void) sigfillset(&set);
				(void) _sigprocmask(SIG_SETMASK, &set, &oset);
				error = thr_create(NULL, __aiostksz,
				    _kaio_cleanup_thread, _kaiowp,
				    THR_BOUND | THR_DAEMON, &_kaiowp->work_tid);
				(void) _sigprocmask(SIG_SETMASK, &oset, NULL);
			}
			if (error) {
				_aio_free_worker(_kaiowp);
				_kaiowp = NULL;
			}
		}
		if (error)
			_kaio_ok = -1;
		else
			_kaio_ok = 1;
	}
	(void) mutex_unlock(&__aio_initlock);
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

#if	defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
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
#endif	/* (_LARGEFILE64_SOURCE) && !defined(_LP64) */

int
_aiorw(int fd, caddr_t buf, int bufsz, offset_t offset, int whence,
    aio_result_t *resultp, int mode)
{
	aio_worker_t **nextworker;
	aio_req_t *aiorp = NULL;
	aio_args_t *ap = NULL;
	offset_t loffset = 0;
	struct stat stat;
	int err = 0;
	int kerr;
	int umode;

	switch (whence) {

	case SEEK_SET:
		loffset = offset;
		break;
	case SEEK_CUR:
		if ((loffset = llseek(fd, 0, SEEK_CUR)) == -1)
			err = -1;
		else
			loffset += offset;
		break;
	case SEEK_END:
		if (fstat(fd, &stat) == -1)
			err = -1;
		else
			loffset = offset + stat.st_size;
		break;
	default:
		errno = EINVAL;
		err = -1;
	}

	if (err)
		return (err);

	/* initialize kaio */
	if (!_kaio_ok)
		_kaio_init();

	/*
	 * _aio_do_request() needs the original request code (mode) to be able
	 * to choose the appropiate 32/64 bit function. All other functions
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
	if ((_kaio_ok > 0) && (KAIO_SUPPORTED(fd))) {
		resultp->aio_errno = 0;
		kerr = (int)_kaio(((resultp->aio_return == AIO_INPROGRESS) ?
		    (umode | AIO_POLL_BIT) : umode),
		    fd, buf, bufsz, loffset, resultp);
		if (kerr == 0)
			return (0);
		else if ((errno != ENOTSUP) && (errno != EBADFD))
			return (-1);
		if (errno == EBADFD)
			SET_KAIO_NOT_SUPPORTED(fd);
	}
	if (!__uaio_ok) {
		if (__uaio_init() == -1)
			return (-1);
	}

	aiorp = _aio_req_alloc();
	if (aiorp == (aio_req_t *)-1) {
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * _aio_do_request() checks aiorp->req_op to differentiate
	 * between 32 and 64 bit access.
	 */
	aiorp->req_op = mode;
	aiorp->req_resultp = resultp;
	ap = &(aiorp->req_args);
	ap->fd = fd;
	ap->buf = buf;
	ap->bufsz = bufsz;
	ap->offset = loffset;

	nextworker = ((umode == AIOWRITE) ? &__nextworker_wr :
	    &__nextworker_rd);
	_aio_lock();
	if (_aio_hash_insert(resultp, aiorp)) {
		_aio_req_free(aiorp);
		_aio_unlock();
		errno = EINVAL;
		return (-1);
	} else {
		_aio_unlock();

		/*
		 * _aio_req_add() only needs the difference between READ and
		 * WRITE to choose the right worker queue.
		 */
		_aio_req_add(aiorp, nextworker, umode);
		return (0);
	}
}

int
aiocancel(aio_result_t *resultp)
{
	aio_req_t *aiorp;
	struct aio_worker *aiowp;
	int done = 0, canceled = 0;

	if (!__uaio_ok) {
		errno = EINVAL;
		return (-1);
	}

	_aio_lock();
	aiorp = _aio_hash_find(resultp);
	if (aiorp == NULL) {
		if (_aio_outstand_cnt == _aio_req_done_cnt)
			errno = EINVAL;
		else
			errno = EACCES;

		_aio_unlock();
		return (-1);
	} else {
		aiowp = aiorp->req_worker;
		(void) mutex_lock(&aiowp->work_qlock1);
		(void) _aio_cancel_req(aiowp, aiorp, &canceled, &done);
		(void) mutex_unlock(&aiowp->work_qlock1);

		if (canceled) {
			_aio_unlock();
			return (0);
		}

		if (_aio_outstand_cnt == 0) {
			_aio_unlock();
			errno = EINVAL;
			return (-1);
		}

		if (_aio_outstand_cnt == _aio_req_done_cnt)  {
			errno = EINVAL;
		} else {
			errno = EACCES;
		}

		_aio_unlock();
		return (-1);

	}
}

/*
 * This must be asynch safe
 */
aio_result_t *
aiowait(struct timeval *uwait)
{
	aio_result_t *uresultp, *kresultp, *resultp;
	int dontblock;
	int timedwait = 0;
	int kaio_errno = 0;
	struct timeval twait, *wait = NULL;
	hrtime_t hrtend;
	hrtime_t hres;

	if (uwait) {
		/*
		 * Check for valid specified wait time. If they are invalid
		 * fail the call right away.
		 */
		if (uwait->tv_sec < 0 || uwait->tv_usec < 0 ||
		    uwait->tv_usec >= MICROSEC) {
			errno = EINVAL;
			return ((aio_result_t *)-1);
		}

		if ((uwait->tv_sec > 0) || (uwait->tv_usec > 0)) {
			hrtend = gethrtime() +
				(hrtime_t)uwait->tv_sec * NANOSEC +
				(hrtime_t)uwait->tv_usec * (NANOSEC / MICROSEC);
			twait = *uwait;
			wait = &twait;
			timedwait++;
		} else {
			/* polling */
			kresultp = (aio_result_t *)_kaio(AIOWAIT,
						(struct timeval *)-1, 1);
			if (kresultp != (aio_result_t *)-1 &&
			    kresultp != NULL && kresultp != (aio_result_t *)1)
				return (kresultp);
			_aio_lock();
			uresultp = _aio_req_done();
			if (uresultp != NULL && uresultp !=
			    (aio_result_t *)-1) {
				_aio_unlock();
				return (uresultp);
			}
			_aio_unlock();
			if (uresultp == (aio_result_t *)-1 &&
			    kresultp == (aio_result_t *)-1) {
				errno = EINVAL;
				return ((aio_result_t *)-1);
			} else
				return (NULL);
		}
	}

	for (;;) {
		_aio_lock();
		uresultp = _aio_req_done();
		if (uresultp != NULL && uresultp != (aio_result_t *)-1) {
			_aio_unlock();
			resultp = uresultp;
			break;
		}
		_aiowait_flag++;
		_aio_unlock();
		dontblock = (uresultp == (aio_result_t *)-1);
		kresultp = (aio_result_t *)_kaio(AIOWAIT, wait, dontblock);
		kaio_errno = errno;
		_aio_lock();
		_aiowait_flag--;
		_aio_unlock();
		if (kresultp == (aio_result_t *)1) {
			/* aiowait() awakened by an aionotify() */
			continue;
		} else if (kresultp != NULL && kresultp != (aio_result_t *)-1) {
			resultp = kresultp;
			break;
		} else if (kresultp == (aio_result_t *)-1 && kaio_errno ==
		    EINVAL && uresultp == (aio_result_t *)-1) {
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
				/* time is up. Return */
				resultp = NULL;
				break;
			} else {
				/*
				 * some time left. Round up the remaining time
				 * in nanoseconds to microsec. Retry the call.
				 */
				hres += (NANOSEC / MICROSEC)-1;
				wait->tv_sec = hres / NANOSEC;
				wait->tv_usec =
					(hres % NANOSEC) / (NANOSEC / MICROSEC);
			}
		} else {
			ASSERT((kresultp == NULL && uresultp == NULL));
			resultp = NULL;
			continue;
		}
	}
	return (resultp);
}

/*
 * _aio_get_timedelta calculates the remaining time and stores the result
 * into struct timespec *wait.
 */

int
_aio_get_timedelta(struct timespec *end, struct timespec *wait)
{

	int	ret = 0;
	struct	timeval cur;
	struct	timespec curtime;

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
 * aio`s and return. Those aio's in question will have either noticed the
 * cancellation notice before, during, or after initiating io.
 */
int
aiocancel_all(int fd)
{
	aio_req_t *aiorp;
	aio_req_t **aiorpp;
	struct aio_worker *first, *next;
	int canceled = 0;
	int done = 0;
	int cancelall = 0;

	if (_aio_outstand_cnt == 0)
		return (AIO_ALLDONE);

	_aio_lock();
	/*
	 * cancel read requests from the read worker's queue.
	 */
	first = __nextworker_rd;
	next = first;
	do {
		_aio_cancel_work(next, fd, &canceled, &done);
	} while ((next = next->work_forw) != first);

	/*
	 * cancel write requests from the write workers queue.
	 */

	first = __nextworker_wr;
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
	aiorpp = &_aio_done_tail;
	while ((aiorp = *aiorpp) != NULL) {
		if (cancelall || aiorp->req_args.fd == fd) {
			*aiorpp = aiorp->req_next;
			_aio_donecnt--;
			(void) _aio_hash_del(aiorp->req_resultp);
			_aio_req_free(aiorp);
		} else
			aiorpp = &aiorp->req_next;
	}
	if (cancelall) {
		ASSERT(_aio_donecnt == 0);
		_aio_done_head = NULL;
	}
	_aio_unlock();

	if (canceled && done == 0)
		return (AIO_CANCELED);
	else if (done && canceled == 0)
		return (AIO_ALLDONE);
	else if ((canceled + done == 0) && KAIO_SUPPORTED(fd))
		return ((int)_kaio(AIOCANCEL, fd, NULL));
	return (AIO_NOTCANCELED);
}

/*
 * cancel requests from a given work queue. if the file descriptor
 * parameter, fd, is non NULL, then only cancel those requests in
 * this queue that are to this file descriptor. if the "fd"
 * parameter is -1, then cancel all requests.
 */
static void
_aio_cancel_work(aio_worker_t *aiowp, int fd, int *canceled, int *done)
{
	aio_req_t *aiorp;

	(void) mutex_lock(&aiowp->work_qlock1);
	/*
	 * cancel queued requests first.
	 */
	aiorp = aiowp->work_tail1;
	while (aiorp != NULL) {
		if (fd < 0 || aiorp->req_args.fd == fd) {
			if (_aio_cancel_req(aiowp, aiorp, canceled, done)) {
				/*
				 * callers locks were dropped. aiorp is
				 * invalid, start traversing the list from
				 * the beginning.
				 */
				aiorp = aiowp->work_tail1;
				continue;
			}
		}
		aiorp = aiorp->req_next;
	}
	/*
	 * since the queued requests have been canceled, there can
	 * only be one inprogress request that shoule be canceled.
	 */
	if ((aiorp = aiowp->work_req) != NULL) {
		if (fd < 0 || aiorp->req_args.fd == fd) {
			(void) _aio_cancel_req(aiowp, aiorp, canceled, done);
			aiowp->work_req = NULL;
		}
	}
	(void) mutex_unlock(&aiowp->work_qlock1);
}

/*
 * cancel a request. return 1 if the callers locks were temporarily
 * dropped, otherwise return 0.
 */
int
_aio_cancel_req(aio_worker_t *aiowp, aio_req_t *aiorp, int *canceled, int *done)
{
	int ostate;
	int rwflg = 1;
	int siqueued;
	int canned;

	ASSERT(MUTEX_HELD(&__aio_mutex));
	ASSERT(MUTEX_HELD(&aiowp->work_qlock1));
	ostate = aiorp->req_state;
	if (ostate == AIO_REQ_CANCELED) {
		return (0);
	}
	if (ostate == AIO_REQ_DONE || ostate == AIO_REQ_DONEQ) {
		(*done)++;
		return (0);
	}
	if (ostate == AIO_REQ_FREE)
		return (0);
	if (aiorp->req_op == AIOFSYNC) {
		canned = aiorp->lio_head->lio_canned;
		aiorp->lio_head->lio_canned = 1;
		rwflg = 0;
		if (canned)
			return (0);
	}
	aiorp->req_state = AIO_REQ_CANCELED;
	_aio_req_del(aiowp, aiorp, ostate);
	if (ostate == AIO_REQ_INPROGRESS)
		(void) thr_kill(aiowp->work_tid, SIGAIOCANCEL);
	(void) mutex_unlock(&aiowp->work_qlock1);
	(void) _aio_hash_del(aiorp->req_resultp);
	(void) mutex_unlock(&__aio_mutex);
	siqueued = _aiodone(aiorp, aiorp->lio_head, rwflg, -1, ECANCELED);
	(void) mutex_lock(&__aio_mutex);
	(void) mutex_lock(&aiowp->work_qlock1);
	_lio_remove(aiorp->lio_head);
	if (!siqueued)
		_aio_req_free(aiorp);
	(*canceled)++;
	return (1);
}

/*
 * This is the worker's main routine.
 * The task of this function is to execute all queued requests;
 * once the last pending request is executed this function will block
 * in _aio_idle(). A new incoming request must wakeup this thread to
 * restart the work.
 * Every worker has an own work queue. The queue lock is required
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
 * 		see _aio_req_get() -> _aio_cancel_on()
 *	  During this phase, it is allowed to interrupt the worker
 *	  thread running the request (this thread) using the SIGAIOCANCEL
 *	  signal.
 *	  Once this thread returns from the kernel (because the request
 *	  is just done), then it must disable a possible cancellation
 *	  and proceed to finish the request. To disable the cancellation
 *	  this thread must use _aio_cancel_off() to set "work_cancel_flg=0".
 * c) request is already done (AIO_REQ_DONE || AIO_REQ_DONEQ):
 *	  same procedure as in a)
 *
 * To b)
 *	This thread uses sigsetjmp() to define the position in the code, where
 *	it wish to continue working in the case that a SIGAIOCANCEL signal
 *	is detected.
 *	Normally this thread should get the cancellation signal during the
 *	kernel phase (reading or writing). In that case the signal handler
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
	struct aio_args *arg;
	aio_req_t *aiorp;		/* current AIO request */
	int ostate;
	ssize_t retval;
	int rwflg;

	aiowp->work_tid = thr_self();
	if (thr_setspecific(_aio_key, aiowp) != 0)
		_aiopanic("_aio_do_request, thr_setspecific()\n");

cancelit:
	if (sigsetjmp(aiowp->work_jmp_buf, 0)) {
		_sigprocmask(SIG_SETMASK, &_worker_set, NULL);
		goto cancelit;
	}

	for (;;) {
		int err = 0;

		/*
		 * Put completed requests on aio_done_list. This has
		 * to be done as part of the main loop to ensure that
		 * we don't artificially starve any aiowait'ers.
		 */
		if (aiowp->work_done1)
			_aio_work_done(aiowp);

		while ((aiorp = _aio_req_get(aiowp)) == NULL) {
			_aio_idle(aiowp);
		}
#ifdef DEBUG
		_donecnt[aiowp->work_tid]++;
#endif
		arg = &aiorp->req_args;

		err = 0;
		rwflg = 1;
		switch (aiorp->req_op) {
			case AIOREAD:
				retval = pread(arg->fd, arg->buf,
				    arg->bufsz, arg->offset);
				if (retval == -1) {
					if (errno == ESPIPE) {
						retval = read(arg->fd,
						    arg->buf, arg->bufsz);
						if (retval == -1)
							err = errno;
					} else {
						err = errno;
					}
				}
				break;
			case AIOWRITE:
				retval = pwrite(arg->fd, arg->buf,
				    arg->bufsz, arg->offset);
				if (retval == -1) {
					if (errno == ESPIPE) {
						retval = write(arg->fd,
						    arg->buf, arg->bufsz);
						if (retval == -1)
							err = errno;
					} else {
						err = errno;
					}
				}
				break;
#if	defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
			case AIOAREAD64:
				retval = pread64(arg->fd, arg->buf,
				    arg->bufsz, arg->offset);
				if (retval == -1) {
					if (errno == ESPIPE) {
						retval = read(arg->fd,
						    arg->buf, arg->bufsz);
						if (retval == -1)
							err = errno;
					} else {
						err = errno;
					}
				}
				break;
			case AIOAWRITE64:
				retval = pwrite64(arg->fd, arg->buf,
				    arg->bufsz, arg->offset);
				if (retval == -1) {
					if (errno == ESPIPE) {
						retval = write(arg->fd,
						    arg->buf, arg->bufsz);
						if (retval == -1)
							err = errno;
					} else {
						err = errno;
					}
				}
				break;
#endif	/* (_LARGEFILE64_SOURCE) && !defined(_LP64) */
			case AIOFSYNC:
				if (_aio_fsync_del(aiorp, aiorp->lio_head))
					continue;
				(void) mutex_lock(&aiowp->work_qlock1);
				ostate = aiorp->req_state;
				(void) mutex_unlock(&aiowp->work_qlock1);
				if (ostate == AIO_REQ_CANCELED) {
					(void) mutex_lock(&aiorp->req_lock);
					aiorp->req_canned = 1;
					(void) cond_broadcast(
						&aiorp->req_cancv);
					(void) mutex_unlock(&aiorp->req_lock);
					continue;
				}
				rwflg = 0;
				/*
				 * all writes for this fsync request are
				 * now acknowledged. now, make these writes
				 * visible.
				 */
				if (arg->offset == O_SYNC)
					retval = __fdsync(arg->fd, FSYNC);
				else
					retval = __fdsync(arg->fd, FDSYNC);
				if (retval == -1)
					err = errno;
				break;
			default:
				rwflg = 0;
				_aiopanic("_aio_do_request, bad op\n");
		}

		/*
		 * Disable the cancellation of the "in progress"
		 * request before trying to acquire the lock of the queue.
		 *
		 * It is not necessary to protect "work_cancel_flg" with
		 * work_qlock1, because this thread can only run on one
		 * CPU at a time.
		 */

		_aio_cancel_off(aiowp);
		(void) mutex_lock(&aiowp->work_qlock1);

		/*
		 * if we return here either
		 * - we got the lock and can close the transaction
		 *   as usual or
		 * - the current transaction was cancelled, but siglongjmp
		 *   was not executed
		 */

		if (aiorp->req_state == AIO_REQ_CANCELED) {
			(void) mutex_unlock(&aiowp->work_qlock1);
			continue;
		}

		aiorp->req_state = AIO_REQ_DONE;
		_aio_req_done_cnt++;
		(void) mutex_unlock(&aiowp->work_qlock1);
		(void) _aiodone(aiorp, aiorp->lio_head, rwflg, retval, err);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * posix supports signal notification for completed aio requests.
 * when aio_do_requests() notices that an aio requests should send
 * a signal, the aio request is moved to the signal notification
 * queue. this routine drains this queue, and guarentees that the
 * signal notification is sent.
 */
void *
_aio_send_sigev(void *arg)
{
	aio_req_t *rp;
	aio_worker_t *aiowp = (aio_worker_t *)arg;

	aiowp->work_tid = thr_self();
	if (thr_setspecific(_aio_key, aiowp) != 0)
		_aiopanic("_aio_send_sigev, thr_setspecific()\n");

	for (;;) {
		while ((rp = _aio_req_get(aiowp)) == NULL) {
			_aio_idle(aiowp);
		}
		if (rp->aio_sigevent.sigev_notify == SIGEV_SIGNAL) {
			while (__sigqueue(__pid, rp->aio_sigevent.sigev_signo,
			    rp->aio_sigevent.sigev_value.sival_ptr,
			    SI_ASYNCIO) == -1)
				thr_yield();
		}
		if (rp->lio_signo) {
			while (__sigqueue(__pid, rp->lio_signo,
			    rp->lio_sigval.sival_ptr, SI_ASYNCIO) == -1)
				thr_yield();
		}
		_aio_lock();
		_lio_remove(rp->lio_head);
		_aio_req_free(rp);
		_aio_unlock();
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * do the completion semantic for a request that was either canceled
 * by _aio_cancel_req(), or was completed by _aio_do_request(). return
 * the value 1 when a sigevent was queued, otherwise return 0.
 */

static int
_aiodone(aio_req_t *rp, aio_lio_t *head, int rwflg, ssize_t retval, int err)
{
	volatile aio_result_t *resultp;
#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
	aiocb64_t	*aiop64;
#endif
	int sigev;

	_aio_lock();

	if (POSIX_AIO(rp)) {
		void	*user;
		int	port;
		int	error;

		if (rp->aio_sigevent.sigev_notify == SIGEV_PORT) {
			resultp = rp->req_resultp;
			resultp->aio_return = retval;
			resultp->aio_errno = err;

			if (err == ECANCELED || rwflg)
				_aio_outstand_cnt--;

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
			if (rp->req_op == AIOAREAD64 ||
			    rp->req_op == AIOAWRITE64) {
				aiop64 = (void *)rp->req_iocb;
				aiop64->aio_state = USERAIO_DONE;
			} else
#endif
				rp->req_iocb->aio_state = USERAIO_DONE;

			port = rp->aio_sigevent.sigev_signo;
			user = rp->aio_sigevent.sigev_value.sival_ptr;
			error = _port_dispatch(port, 0, PORT_SOURCE_AIO, 0,
			    (uintptr_t)rp->req_iocb, user);
			if (error == 0) {
				(void) _aio_hash_del(rp->req_resultp);
				_aio_req_free(rp);
				_aio_unlock();
				return (1);
			}
			/*
			 * Can not submit the I/O completion to the port,
			 * set status of transaction to NONE
			 */
			rp->aio_sigevent.sigev_notify = SIGEV_NONE;
			if (err == ECANCELED || rwflg)
				_aio_outstand_cnt++;
		}

		sigev = (rp->aio_sigevent.sigev_notify == SIGEV_SIGNAL ||
		    (head && head->lio_signo));
		if (sigev)
			(void) _aio_hash_del(rp->req_resultp);

		resultp = rp->req_resultp;
		/*
		 * resultp is declared "volatile" (above) to avoid
		 * optimization by compiler ie. switching order which could
		 * lead aio_return getting checked by aio_error() following
		 * a particular aio_errno value (aio_return would not have been
		 * set yet)
		 */
		resultp->aio_return = retval;
		resultp->aio_errno = err;

		if (err == ECANCELED) {
			_aio_outstand_cnt--;
		} else {
			if (rwflg) {
				if (!sigev)
					_aio_enq_doneq(rp);
				_aio_outstand_cnt--;
			}

		}

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

		_aio_unlock();

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
		if (err != ECANCELED) {
			if (_aio_flags & AIO_WAIT_INPROGRESS ||
			    _aio_kernel_suspend > 0) {
				(void) _kaio(AIONOTIFY);
			}
		}

		rp->lio_signo = 0;
		rp->lio_sigval.sival_int = 0;
		if (head) {
			/*
			 * If all the lio requests have completed,
			 * signal the waiting process
			 */
			(void) mutex_lock(&head->lio_mutex);
			if (--head->lio_refcnt == 0) {
				if (head->lio_mode == LIO_WAIT)
					(void) cond_signal(&head->lio_cond_cv);
				else {
					rp->lio_signo = head->lio_signo;
					rp->lio_sigval = head->lio_sigval;
				}
			}
			(void) mutex_unlock(&head->lio_mutex);
		}
		if (sigev) {
			_aio_req_add(rp, &__workers_si, AIOSIGEV);
			return (1);
		}
	} else {
		/* Solaris I/O */
		if (err == ECANCELED)
			_aio_outstand_cnt--;

		_aio_unlock();

		resultp = rp->req_resultp;
		resultp->aio_return = retval;
		resultp->aio_errno = err;
	}
	return (0);
}

/*
 * delete fsync requests from list head until there is
 * only one left. return 0 when there is only one, otherwise
 * return a non-zero value.
 */
static int
_aio_fsync_del(aio_req_t *rp, aio_lio_t *head)
{
	int refcnt;

	(void) mutex_lock(&head->lio_mutex);
	if (head->lio_refcnt > 1 || head->lio_mode == LIO_DESTROY ||
	    head->lio_canned) {
		refcnt = --head->lio_refcnt;
		if (refcnt || head->lio_canned) {
			head->lio_nent--;
			(void) mutex_unlock(&head->lio_mutex);
			(void) mutex_lock(&__aio_mutex);
			_aio_req_free(rp);
			(void) mutex_unlock(&__aio_mutex);
			if (head->lio_canned) {
				ASSERT(refcnt >= 0);
				return (0);
			}
			return (1);
		}
		ASSERT(head->lio_mode == LIO_DESTROY);
		ASSERT(head->lio_nent == 1 && head->lio_refcnt == 0);
		(void) mutex_unlock(&head->lio_mutex);
		_aio_remove(rp);
		return (0);
	}
	ASSERT(head->lio_refcnt == head->lio_nent);
	(void) mutex_unlock(&head->lio_mutex);
	return (0);
}

/*
 * worker is set idle when its work queue is empty.
 * The worker checks again that it has no more work and then
 * goes to sleep waiting for more work.
 */
void
_aio_idle(aio_worker_t *aiowp)
{
	(void) mutex_lock(&aiowp->work_lock);
	if (aiowp->work_cnt1 == 0) {
#ifdef DEBUG
		_idlecnt[aiowp->work_tid]++;
#endif
		aiowp->work_idleflg = 1;
		(void) cond_wait(&aiowp->work_idle_cv, &aiowp->work_lock);
		/*
		 * idle flag is cleared before worker is awakened
		 * by aio_req_add().
		 */
	}
	(void) mutex_unlock(&aiowp->work_lock);
}

/*
 * A worker's completed AIO requests are placed onto a global
 * done queue. The application is only sent a SIGIO signal if
 * the process has a handler enabled and it is not waiting via
 * aiowait().
 */
static void
_aio_work_done(struct aio_worker *aiowp)
{
	struct aio_req *done_req = NULL;

	(void) mutex_lock(&aiowp->work_qlock1);
	done_req = aiowp->work_prev1;
	done_req->req_next = NULL;
	aiowp->work_done1 = 0;
	aiowp->work_tail1 = aiowp->work_next1;
	if (aiowp->work_tail1 == NULL)
		aiowp->work_head1 = NULL;
	aiowp->work_prev1 = NULL;
	(void) mutex_unlock(&aiowp->work_qlock1);
	(void) mutex_lock(&__aio_mutex);
	_aio_donecnt++;
	_aio_outstand_cnt--;
	_aio_req_done_cnt--;
	ASSERT(_aio_donecnt > 0 && _aio_outstand_cnt >= 0);
	ASSERT(done_req != NULL);

	if (_aio_done_tail == NULL) {
		_aio_done_head = _aio_done_tail = done_req;
	} else {
		_aio_done_head->req_next = done_req;
		_aio_done_head = done_req;
	}

	if (_aiowait_flag) {
		(void) mutex_unlock(&__aio_mutex);
		(void) _kaio(AIONOTIFY);
	} else {
		(void) mutex_unlock(&__aio_mutex);
		if (_sigio_enabled) {
			(void) kill(__pid, SIGIO);
		}
	}
}

/*
 * the done queue consists of AIO requests that are in either the
 * AIO_REQ_DONE or AIO_REQ_CANCELED state. requests that were cancelled
 * are discarded. if the done queue is empty then NULL is returned.
 * otherwise the address of a done aio_result_t is returned.
 */
struct aio_result_t *
_aio_req_done(void)
{
	struct aio_req *next;
	aio_result_t *resultp;

	ASSERT(MUTEX_HELD(&__aio_mutex));

	if ((next = _aio_done_tail) != NULL) {
		_aio_done_tail = next->req_next;
		ASSERT(_aio_donecnt > 0);
		_aio_donecnt--;
		(void) _aio_hash_del(next->req_resultp);
		resultp = next->req_resultp;
		ASSERT(next->req_state == AIO_REQ_DONE);
		_aio_req_free(next);
		return (resultp);
	}
	/* is queue empty? */
	if (next == NULL && _aio_outstand_cnt == 0) {
		return ((aio_result_t *)-1);
	}
	return (NULL);
}

/*
 * add an AIO request onto the next work queue. a circular list of
 * workers is used to choose the next worker. each worker has two
 * work queues. if the lock for the first queue is busy then the
 * request is placed on the second queue. the request is always
 * placed on one of the two queues depending on which one is locked.
 */
void
_aio_req_add(aio_req_t *aiorp, aio_worker_t **nextworker, int mode)
{
	struct aio_worker *aiowp;
	struct aio_worker *first;
	int clogged = 0;
	int found = 0;
	int load_bal_flg;
	int idleflg;
	int qactive;

	aiorp->req_next = NULL;
	ASSERT(*nextworker != NULL);
	aiowp = *nextworker;
	/*
	 * try to acquire the next worker's work queue. if it is locked,
	 * then search the list of workers until a queue is found unlocked,
	 * or until the list is completely traversed at which point another
	 * worker will be created.
	 */
	first = aiowp;
	_aio_lock();
	__sigio_maskedcnt++;	/* disable SIGIO */
	if (mode == AIOREAD || mode == AIOWRITE) {
		_aio_outstand_cnt++;
		load_bal_flg = 1;
	}
	_aio_unlock();
	switch (mode) {
		case AIOREAD:
			/* try to find an idle worker. */
			do {
				if (mutex_trylock(&aiowp->work_qlock1) == 0) {
					if (aiowp->work_idleflg) {
						found = 1;
						break;
					}
					(void) mutex_unlock(
						&aiowp->work_qlock1);
				}
			} while ((aiowp = aiowp->work_forw) != first);
			if (found)
				break;
			/*FALLTHROUGH*/
		case AIOWRITE:
			while (mutex_trylock(&aiowp->work_qlock1)) {
#ifdef DEBUG
				_qlocked++;
#endif
				if (((aiowp = aiowp->work_forw)) == first) {
					clogged = 1;
					break;
				}
			}
			/*
			 * create more workers when the workers appear
			 * overloaded. either all the workers are busy
			 * draining their queues, no worker's queue lock
			 * could be acquired, or the selected worker has
			 * exceeded its minimum work load, but has not
			 * exceeded the max number of workers.
			 */
			if (clogged) {
#ifdef DEBUG
				_new_workers++;
				_clogged++;
#endif
				if (_aio_worker_cnt < _max_workers) {
					if (_aio_create_worker(aiorp, mode))
						_aiopanic(
						    "_aio_req_add: clogged");
					_aio_lock();
					__sigio_maskedcnt--;
					_aio_unlock();
					return;
				}

				/*
				 * No worker available and we have created
				 * _max_workers, keep going through the
				 * list until we get a lock
				 */
				while (mutex_trylock(&aiowp->work_qlock1)) {
					/*
					 * give someone else a chance
					 */
					thr_yield();
					aiowp = aiowp->work_forw;
				}

			}
			ASSERT(MUTEX_HELD(&aiowp->work_qlock1));
			aiowp->work_minload1++;
			if (_aio_worker_cnt < _max_workers &&
			    aiowp->work_minload1 > _minworkload) {
				aiowp->work_minload1 = 0;
				(void) mutex_unlock(&aiowp->work_qlock1);
#ifdef DEBUG
				_qfullcnt[aiowp->work_tid]++;
				_new_workers++;
				_newworker[aiowp->work_tid]++;
				_avedone = _aio_submitcnt2/_new_workers;
#endif
				(void) mutex_lock(&__aio_mutex);
				*nextworker = aiowp->work_forw;
				(void) mutex_unlock(&__aio_mutex);
				if (_aio_create_worker(aiorp, mode))
					_aiopanic("aio_req_add: add worker");
				_aio_lock();
				__sigio_maskedcnt--; /* enable signals again */
				_aio_unlock(); /* send evt. SIGIO signal */
				return;
			}
			break;
		case AIOFSYNC:
			aiorp->req_op = mode;
			/*FALLTHROUGH*/
		case AIOSIGEV:
			load_bal_flg = 0;
			(void) mutex_lock(&aiowp->work_qlock1);
			break;
	}
	/*
	 * Put request onto worker's work queue.
	 */
	if (aiowp->work_tail1 == NULL) {
		ASSERT(aiowp->work_cnt1 == 0);
		aiowp->work_tail1 = aiorp;
		aiowp->work_next1 = aiorp;
	} else {
		aiowp->work_head1->req_next = aiorp;
		if (aiowp->work_next1 == NULL)
			aiowp->work_next1 = aiorp;
	}
	aiorp->req_state = AIO_REQ_QUEUED;
	aiorp->req_worker = aiowp;
	aiowp->work_head1 = aiorp;
	qactive = aiowp->work_cnt1++;
	(void) mutex_unlock(&aiowp->work_qlock1);
	if (load_bal_flg) {
		_aio_lock();
		*nextworker = aiowp->work_forw;
		_aio_unlock();
	}
	/*
	 * Awaken worker if it is not currently active.
	 */
	if (!qactive) {
		(void) mutex_lock(&aiowp->work_lock);
		idleflg = aiowp->work_idleflg;
		aiowp->work_idleflg = 0;
		(void) mutex_unlock(&aiowp->work_lock);
		if (idleflg)
			(void) cond_signal(&aiowp->work_idle_cv);
	}
	_aio_lock();
	__sigio_maskedcnt--;	/* enable signals again */
	_aio_unlock();		/* send SIGIO signal if pending */
}

/*
 * get an AIO request for a specified worker. each worker has
 * two work queues. find the first one that is not empty and
 * remove this request from the queue and return it back to the
 * caller. if both queues are empty, then return a NULL.
 */
aio_req_t *
_aio_req_get(aio_worker_t *aiowp)
{
	aio_req_t *next;
	int mode;

	(void) mutex_lock(&aiowp->work_qlock1);
	if ((next = aiowp->work_next1) != NULL) {
		/*
		 * remove a POSIX request from the queue; the
		 * request queue is a singularly linked list
		 * with a previous pointer. The request is removed
		 * by updating the previous pointer.
		 *
		 * non-posix requests are left on the queue to
		 * eventually be placed on the done queue.
		 */

		if (next->req_type == AIO_POSIX_REQ) {
			if (aiowp->work_prev1 == NULL) {
				aiowp->work_tail1 = next->req_next;
				if (aiowp->work_tail1 == NULL)
					aiowp->work_head1 = NULL;
			} else {
				aiowp->work_prev1->req_next = next->req_next;
				if (aiowp->work_head1 == next)
					aiowp->work_head1 = next->req_next;
			}

		} else {
			aiowp->work_prev1 = next;
			ASSERT(aiowp->work_done1 >= 0);
			aiowp->work_done1++;
		}
		ASSERT(next != next->req_next);
		aiowp->work_next1 = next->req_next;
		ASSERT(aiowp->work_cnt1 >= 1);
		aiowp->work_cnt1--;
		mode = next->req_op;
		if (mode == AIOWRITE || mode == AIOREAD || mode == AIOAREAD64 ||
		    mode == AIOAWRITE64)
			aiowp->work_minload1--;
#ifdef DEBUG
		_firstqcnt[aiowp->work_tid]++;
#endif
		next->req_state = AIO_REQ_INPROGRESS;
		_aio_cancel_on(aiowp);
	}
	aiowp->work_req = next;
	ASSERT(next != NULL || (next == NULL && aiowp->work_cnt1 == 0));
	(void) mutex_unlock(&aiowp->work_qlock1);
	return (next);
}

static void
_aio_req_del(aio_worker_t *aiowp, aio_req_t *rp, int ostate)
{
	aio_req_t **last, *lastrp, *next;

	ASSERT(aiowp != NULL);
	ASSERT(MUTEX_HELD(&aiowp->work_qlock1));
	if (POSIX_AIO(rp)) {
		if (ostate != AIO_REQ_QUEUED)
			return;
	}
	last = &aiowp->work_tail1;
	lastrp = aiowp->work_tail1;
	ASSERT(ostate == AIO_REQ_QUEUED || ostate == AIO_REQ_INPROGRESS);
	while ((next = *last) != NULL) {
		if (next == rp) {
			*last = next->req_next;
			if (aiowp->work_next1 == next)
				aiowp->work_next1 = next->req_next;

			if ((next->req_next != NULL) ||
			    (aiowp->work_done1 == 0)) {
				if (aiowp->work_head1 == next)
					aiowp->work_head1 = next->req_next;
				if (aiowp->work_prev1 == next)
					aiowp->work_prev1 = next->req_next;
			} else {
				if (aiowp->work_head1 == next)
					aiowp->work_head1 = lastrp;
				if (aiowp->work_prev1 == next)
					aiowp->work_prev1 = lastrp;
			}

			if (ostate == AIO_REQ_QUEUED) {
				ASSERT(aiowp->work_cnt1 >= 1);
				aiowp->work_cnt1--;
			} else {
				ASSERT(ostate == AIO_REQ_INPROGRESS &&
				    !POSIX_AIO(rp));
				aiowp->work_done1--;
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
		reqp->req_next = reqp;
		reqp->req_prev = reqp;
	} else {
		reqp->req_next = _aio_doneq;
		reqp->req_prev = _aio_doneq->req_prev;
		reqp->req_prev->req_next = reqp;
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
	aio_req_t *head;

	if (reqp && reqp->req_state != AIO_REQ_DONEQ)
		return (NULL);

	if (reqp) {
		/* request in done queue */
		if (reqp->req_next == reqp) {
			/* only one request on queue */
			_aio_doneq = NULL;
		} else {
			reqp->req_next->req_prev = reqp->req_prev;
			reqp->req_prev->req_next = reqp->req_next;
			if (reqp == _aio_doneq)
				_aio_doneq = reqp->req_next;
		}
		_aio_doneq_cnt--;
		return (reqp);
	}

	if (_aio_doneq) {
		head = _aio_doneq;
		if (head == head->req_next) {
			/* only one request on queue */
			_aio_doneq = NULL;
		} else {
			head->req_prev->req_next = head->req_next;
			head->req_next->req_prev = head->req_prev;
			_aio_doneq = head->req_next;
		}
		_aio_doneq_cnt--;
		return (head);
	}
	return (NULL);

}

/*
 * An AIO request is identified by an aio_result_t pointer.  The AIO
 * library maps this aio_result_t pointer to its internal representation
 * via a hash table.  This function adds an aio_result_t pointer to
 * the hash table.
 */
static int
_aio_hash_insert(aio_result_t *resultp, aio_req_t *aiorp)
{
	uintptr_t i;
	aio_req_t *next, **last;

	ASSERT(MUTEX_HELD(&__aio_mutex));
	i = AIOHASH(resultp);
	last = (_aio_hash + i);
	while ((next = *last) != NULL) {
		if (resultp == next->req_resultp)
			return (-1);
		last = &next->req_link;
	}
	*last = aiorp;
	ASSERT(aiorp->req_link == NULL);
	return (0);
}

/*
 * remove an entry from the hash table.
 */
struct aio_req *
_aio_hash_del(aio_result_t *resultp)
{
	struct aio_req *next, **prev;
	uintptr_t i;

	ASSERT(MUTEX_HELD(&__aio_mutex));
	i = AIOHASH(resultp);
	prev = (_aio_hash + i);
	while ((next = *prev) != NULL) {
		if (resultp == next->req_resultp) {
			*prev = next->req_link;
			return (next);
		}
		prev = &next->req_link;
	}
	ASSERT(next == NULL);
	return ((struct aio_req *)NULL);
}

/*
 *  find an entry on the hash table
 */
struct aio_req *
_aio_hash_find(aio_result_t *resultp)
{
	struct aio_req *next, **prev;
	uintptr_t i;

	/*
	 * no user AIO
	 */
	if (_aio_hash == NULL)
		return (NULL);

	i = AIOHASH(resultp);
	prev = (_aio_hash + i);
	while ((next = *prev) != NULL) {
		if (resultp == next->req_resultp) {
			return (next);
		}
		prev = &next->req_link;
	}
	return (NULL);
}

/*
 * Allocate and free aios.  They are cached.
 */
aio_req_t *
_aio_req_alloc(void)
{
	aio_req_t *aiorp;
	int err;

	_aio_lock();
	while (_aio_freelist == NULL) {
		_aio_unlock();
		err = 0;
		(void) mutex_lock(&__aio_cachefillock);
		if (__aio_cachefilling)
			(void) cond_wait(&__aio_cachefillcv,
				&__aio_cachefillock);
		else
			err = _fill_aiocache(HASHSZ);
		(void) mutex_unlock(&__aio_cachefillock);
		if (err)
			return ((aio_req_t *)-1);
		_aio_lock();
	}
	aiorp = _aio_freelist;
	_aio_freelist = _aio_freelist->req_link;
	aiorp->req_type = 0;
	aiorp->req_link = NULL;
	aiorp->req_next = NULL;
	aiorp->lio_head = NULL;
	aiorp->aio_sigevent.sigev_notify = SIGEV_NONE;
	_aio_freelist_cnt--;
	_aio_unlock();
	return (aiorp);
}

/*
 * fill the aio request cache with empty aio request structures.
 */
int
_fill_aiocache(int n)
{
	aio_req_t *next, *aiorp, *first;
	int cnt;
	uintptr_t ptr;
	int i;

	__aio_cachefilling = 1;
	if ((ptr = (uintptr_t)malloc(sizeof (struct aio_req) * n)) == NULL) {
		__aio_cachefilling = 0;
		(void) cond_broadcast(&__aio_cachefillcv);
		return (-1);
	}
	if (ptr & 0x7)
		_aiopanic("_fill_aiocache");
	first = (struct aio_req *)ptr;
	next = first;
	cnt = n - 1;
	for (i = 0; i < cnt; i++) {
		aiorp = next++;
		aiorp->req_state = AIO_REQ_FREE;
		aiorp->req_link = next;
		(void) mutex_init(&aiorp->req_lock, USYNC_THREAD, NULL);
		(void) cond_init(&aiorp->req_cancv, USYNC_THREAD, NULL);
	}
	__aio_cachefilling = 0;
	(void) cond_broadcast(&__aio_cachefillcv);
	next->req_state = AIO_REQ_FREE;
	next->req_link = NULL;
	(void) mutex_init(&next->req_lock, USYNC_THREAD, NULL);
	(void) cond_init(&next->req_cancv, USYNC_THREAD, NULL);
	_aio_lock();
	_aio_freelist_cnt = n;
	_aio_freelist = first;
	_aio_unlock();
	return (0);
}

/*
 * put an aio request back onto the freelist.
 */
void
_aio_req_free(aio_req_t *aiorp)
{
	ASSERT(MUTEX_HELD(&__aio_mutex));
	aiorp->req_state = AIO_REQ_FREE;
	aiorp->req_link = _aio_freelist;
	_aio_freelist = aiorp;
	_aio_freelist_cnt++;
}

/*
 * global aio lock that masks SIGIO signals.
 */
void
_aio_lock(void)
{
	__sigio_masked = 1;
	(void) mutex_lock(&__aio_mutex);
	__sigio_maskedcnt++;
}

/*
 * release global aio lock. send SIGIO signal if one
 * is pending.
 */
void
_aio_unlock(void)
{
	if (--__sigio_maskedcnt == 0)
		__sigio_masked = 0;
	(void) mutex_unlock(&__aio_mutex);
	if (__sigio_pending)
		__aiosendsig();
}

/*
 * AIO interface for POSIX
 */
int
_aio_rw(aiocb_t *cb, aio_lio_t *lio_head, aio_worker_t **nextworker,
    int mode, int flg, struct sigevent *sigp)
{
	aio_req_t *aiorp = NULL;
	aio_args_t *ap = NULL;
	int kerr;
	int umode;

	if (cb == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* initialize kaio */
	if (!_kaio_ok)
		_kaio_init();

	cb->aio_state = NOCHECK;

	/*
	 * If _aio_rw() is called because a list I/O
	 * kaio() failed, we dont want to repeat the
	 * system call
	 */

	if (flg & AIO_KAIO) {
		/*
		 * Try kernel aio first.
		 * If errno is ENOTSUP/EBADFD,
		 * fall back to the thread implementation.
		 */
		if ((_kaio_ok > 0) && (KAIO_SUPPORTED(cb->aio_fildes)))  {
			cb->aio_resultp.aio_errno = EINPROGRESS;
			cb->aio_state = CHECK;
			kerr = (int)_kaio(mode, cb);
			if (kerr == 0)
				return (0);
			else if ((errno != ENOTSUP) && (errno != EBADFD)) {
				cb->aio_resultp.aio_errno = errno;
				cb->aio_resultp.aio_return = -1;
				cb->aio_state = NOCHECK;
				return (-1);
			}
			if (errno == EBADFD)
				SET_KAIO_NOT_SUPPORTED(cb->aio_fildes);
		}
	}

	cb->aio_resultp.aio_errno = EINPROGRESS;
	cb->aio_state = USERAIO;

	if (!__uaio_ok) {
		if (__uaio_init() == -1)
			return (-1);
	}

	aiorp = _aio_req_alloc();
	if (aiorp == (aio_req_t *)-1) {
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * If an LIO request, add the list head to the
	 * aio request
	 */
	aiorp->lio_head = lio_head;
	aiorp->req_type = AIO_POSIX_REQ;
	umode = ((mode == AIOFSYNC) ? mode : mode - AIOAREAD);
	aiorp->req_op = umode;

	if (cb->aio_sigevent.sigev_notify == SIGEV_SIGNAL) {
		aiorp->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
		aiorp->aio_sigevent.sigev_signo =
		    cb->aio_sigevent.sigev_signo;
		aiorp->aio_sigevent.sigev_value.sival_ptr =
		    cb->aio_sigevent.sigev_value.sival_ptr;
	}

	if (sigp) {
		/* SIGEV_PORT */
		port_notify_t *pn = sigp->sigev_value.sival_ptr;
		aiorp->aio_sigevent.sigev_notify = SIGEV_PORT;
		aiorp->aio_sigevent.sigev_signo = pn->portnfy_port;
		aiorp->aio_sigevent.sigev_value.sival_ptr = pn->portnfy_user;
	} else if (cb->aio_sigevent.sigev_notify == SIGEV_PORT) {
		port_notify_t *pn;
		pn = cb->aio_sigevent.sigev_value.sival_ptr;
		aiorp->aio_sigevent.sigev_notify = SIGEV_PORT;
		aiorp->aio_sigevent.sigev_signo = pn->portnfy_port;
		aiorp->aio_sigevent.sigev_value.sival_ptr = pn->portnfy_user;
	}

	aiorp->req_resultp = &cb->aio_resultp;
	aiorp->req_iocb = cb;
	ap = &(aiorp->req_args);
	ap->fd = cb->aio_fildes;
	ap->buf = (caddr_t)cb->aio_buf;
	ap->bufsz = cb->aio_nbytes;
	ap->offset = cb->aio_offset;

	_aio_lock();
	if ((flg & AIO_NO_DUPS) && _aio_hash_insert(&cb->aio_resultp, aiorp)) {
		_aio_req_free(aiorp);
		_aio_unlock();
		errno = EINVAL;
		return (-1);
	} else {
		_aio_unlock();
		_aio_req_add(aiorp, nextworker, umode);
		return (0);
	}
}

#if	defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
/*
 * 64-bit AIO interface for POSIX
 */
int
_aio_rw64(aiocb64_t *cb, aio_lio_t *lio_head, aio_worker_t **nextworker,
    int mode, int flg, struct sigevent *sigp)
{
	aio_req_t *aiorp = NULL;
	aio_args_t *ap = NULL;
	int kerr;
	int umode;

	if (cb == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* initialize kaio */
	if (!_kaio_ok)
		_kaio_init();

	cb->aio_state = NOCHECK;

	/*
	 * If _aio_rw() is called because a list I/O
	 * kaio() failed, we dont want to repeat the
	 * system call
	 */

	if (flg & AIO_KAIO) {
		/*
		 * Try kernel aio first.
		 * If errno is ENOTSUP/EBADFD,
		 * fall back to the thread implementation.
		 */
		if ((_kaio_ok > 0) && (KAIO_SUPPORTED(cb->aio_fildes))) {
			cb->aio_resultp.aio_errno = EINPROGRESS;
			cb->aio_state = CHECK;
			kerr = (int)_kaio(mode, cb);
			if (kerr == 0)
				return (0);
			else if ((errno != ENOTSUP) && (errno != EBADFD)) {
				cb->aio_resultp.aio_errno = errno;
				cb->aio_resultp.aio_return = -1;
				cb->aio_state = NOCHECK;
				return (-1);
			}
			if (errno == EBADFD)
				SET_KAIO_NOT_SUPPORTED(cb->aio_fildes);
		}
	}

	cb->aio_resultp.aio_errno = EINPROGRESS;
	cb->aio_state = USERAIO;

	if (!__uaio_ok) {
		if (__uaio_init() == -1)
			return (-1);
	}


	aiorp = _aio_req_alloc();
	if (aiorp == (aio_req_t *)-1) {
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * If an LIO request, add the list head to the
	 * aio request
	 */
	aiorp->lio_head = lio_head;
	aiorp->req_type = AIO_POSIX_REQ;

	/*
	 * _aio_do_request() needs the original request code to be able
	 * to choose the appropriate 32/64 bit function.
	 */
	aiorp->req_op = mode;

	if (cb->aio_sigevent.sigev_notify == SIGEV_SIGNAL) {
		aiorp->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
		aiorp->aio_sigevent.sigev_signo =
		    cb->aio_sigevent.sigev_signo;
		aiorp->aio_sigevent.sigev_value.sival_ptr =
		    cb->aio_sigevent.sigev_value.sival_ptr;
	}

	if (sigp) {
		/* SIGEV_PORT */
		port_notify_t *pn = sigp->sigev_value.sival_ptr;
		aiorp->aio_sigevent.sigev_notify = SIGEV_PORT;
		aiorp->aio_sigevent.sigev_signo = pn->portnfy_port;
		aiorp->aio_sigevent.sigev_value.sival_ptr = pn->portnfy_user;
	} else if (cb->aio_sigevent.sigev_notify == SIGEV_PORT) {
		port_notify_t *pn;
		pn = cb->aio_sigevent.sigev_value.sival_ptr;
		aiorp->aio_sigevent.sigev_notify = SIGEV_PORT;
		aiorp->aio_sigevent.sigev_signo = pn->portnfy_port;
		aiorp->aio_sigevent.sigev_value.sival_ptr = pn->portnfy_user;
	}

	aiorp->req_resultp = &cb->aio_resultp;
	aiorp->req_iocb = (aiocb_t *)cb;
	ap = &(aiorp->req_args);
	ap->fd = cb->aio_fildes;
	ap->buf = (caddr_t)cb->aio_buf;
	ap->bufsz = cb->aio_nbytes;
	ap->offset = cb->aio_offset;

	_aio_lock();
	if ((flg & AIO_NO_DUPS) && _aio_hash_insert(&cb->aio_resultp, aiorp)) {
		_aio_req_free(aiorp);
		_aio_unlock();
		errno = EINVAL;
		return (-1);
	} else {
		_aio_unlock();

		/*
		 * _aio_req_add() only needs the difference between READ,
		 * WRITE and other to choose the right worker queue.
		 * AIOAREAD64 is mapped to AIOREAD and
		 * AIOAWRITE64 is mapped to AIOWRITE.
		 * mode is AIOAREAD64, AIOAWRITE64 or AIOFSYNC.
		 */
		umode = ((mode == AIOFSYNC) ? mode : mode - AIOAREAD64);
		_aio_req_add(aiorp, nextworker, umode);
		return (0);
	}
}
#endif	/* (_LARGEFILE64_SOURCE) && !defined(_LP64) */
