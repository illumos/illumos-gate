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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ASYNCIO_H
#define	_ASYNCIO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <thread.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <siginfo.h>
#include <aio.h>
#include <limits.h>
#include <ucontext.h>
#include <sys/asynch.h>
#include <sys/mman.h>

#if !defined(_LP64)
#define	AIOSTKSIZE	(64 * 1024)
#else
#define	AIOSTKSIZE	(128 * 1024)
#endif

#define	SIGAIOCANCEL		SIGLWP	/* special aio cancelation signal */

#define	AIO_WAITN_MAXIOCBS	32768	/* max. iocbs per system call */

/*
 * Declare structure types.  The structures themselves are defined below.
 */
typedef struct aio_args		aio_args_t;
typedef struct aio_lio		aio_lio_t;
typedef struct notif_param	notif_param_t;
typedef struct aio_req		aio_req_t;
typedef struct aio_worker	aio_worker_t;
typedef struct aio_hash		aio_hash_t;

struct aio_args {
	int		fd;
	caddr_t		buf;
	size_t		bufsz;
	offset_t	offset;
};

/*
 * list head for UFS list I/O
 */
struct aio_lio {
	mutex_t		lio_mutex;	/* list mutex */
	cond_t		lio_cond_cv;	/* list notification for I/O done */
	aio_lio_t	*lio_next;	/* pointer to next on freelist */
	char		lio_mode;	/* LIO_WAIT/LIO_NOWAIT */
	char		lio_canned;	/* lio was canceled */
	char		lio_largefile;	/* largefile operation */
	char		lio_waiting;	/* waiting in __lio_listio() */
	int		lio_nent;	/* Number of list I/O's */
	int		lio_refcnt;	/* outstanding I/O's */
	int		lio_event;	/* Event number for notification */
	int		lio_port;	/* Port number for notification */
	int		lio_signo;	/* Signal number for notification */
	union sigval	lio_sigval;	/* Signal parameter */
	uintptr_t	lio_object;	/* for SIGEV_THREAD or SIGEV_PORT */
	struct sigevent	*lio_sigevent;	/* Notification function and attr. */
};

/*
 * Notification parameters
 */
struct notif_param {
	int		np_signo;	/* SIGEV_SIGNAL */
	int		np_port;	/* SIGEV_THREAD or SIGEV_PORT */
	void		*np_user;
	int		np_event;
	uintptr_t	np_object;
	int		np_lio_signo;	/* listio: SIGEV_SIGNAL */
	int		np_lio_port;	/* listio: SIGEV_THREAD or SIGEV_PORT */
	void		*np_lio_user;
	int		np_lio_event;
	uintptr_t	np_lio_object;
};

struct aio_req {
	/*
	 * fields protected by _aio_mutex lock.
	 */
	aio_req_t *req_link;		/* hash/freelist chain link */
	/*
	 * when req is on the doneq, then req_next is protected by
	 * the _aio_mutex lock. when the req is on a work q, then
	 * req_next is protected by a worker's work_qlock1 lock.
	 */
	aio_req_t *req_next;		/* request/done queue link */
	aio_req_t *req_prev;		/* double linked list */
	/*
	 * fields protected by a worker's work_qlock1 lock.
	 */
	char		req_state;	/* AIO_REQ_QUEUED, ... */
	/*
	 * fields require no locking.
	 */
	char		req_type;	/* AIO_POSIX_REQ or not */
	char		req_largefile;	/* largefile operation */
	char		req_op;		/* AIOREAD, etc. */
	aio_worker_t	*req_worker;	/* associate request with worker */
	aio_result_t	*req_resultp;	/* address of result buffer */
	aio_args_t	req_args;	/* arglist */
	aio_lio_t	*req_head;	/* list head for LIO */
	struct sigevent	req_sigevent;
	void		*req_aiocbp;	/* ptr to aiocb or aiocb64 */
	notif_param_t	req_notify;	/* notification parameters */
};

/* special lio type that destroys itself when lio refcnt becomes zero */
#define	LIO_FSYNC	LIO_WAIT+1
#define	LIO_DESTROY	LIO_FSYNC+1

/* lio flags */
#define	LIO_FSYNC_CANCELED	0x1

/* values for aio_state */

#define	AIO_REQ_QUEUED		1
#define	AIO_REQ_INPROGRESS	2
#define	AIO_REQ_CANCELED	3
#define	AIO_REQ_DONE		4
#define	AIO_REQ_FREE		5
#define	AIO_REQ_DONEQ		6

/* use KAIO in _aio_rw() */
#define	AIO_NO_KAIO		0x0
#define	AIO_KAIO		0x1
#define	AIO_NO_DUPS		0x2

#define	AIO_POSIX_REQ		0x1

#define	CHECK			1
#define	NOCHECK			2
#define	CHECKED			3
#define	USERAIO			4
#define	USERAIO_DONE		5

/* values for _aio_flags */

/* if set, _aiodone() notifies aio_waitn about done requests */
#define	AIO_WAIT_INPROGRESS	0x1
/* if set, _aiodone() wakes up functions waiting for completed I/Os */
#define	AIO_IO_WAITING		0x2
#define	AIO_LIB_WAITN		0x4	/* aio_waitn in progress */
#define	AIO_LIB_WAITN_PENDING	0x8	/* aio_waitn requests pending */

/*
 * Before a kaio() system call, the fd will be checked
 * to ensure that kernel async. I/O is supported for this file.
 * The only way to find out is if a kaio() call returns ENOTSUP,
 * so the default will always be to try the kaio() call. Only in
 * the specific instance of a kaio() call returning ENOTSUP
 * will we stop submitting kaio() calls for that fd.
 * If the fd is outside the array bounds, we will allow the kaio()
 * call.
 *
 * The only way that an fd entry can go from ENOTSUP to supported
 * is if that fd is freed up by a close(), and close will clear
 * the entry for that fd.
 *
 * Each fd gets a bit in the array _kaio_supported[].
 *
 * uint32_t	_kaio_supported[MAX_KAIO_FDARRAY_SIZE];
 *
 * Array is MAX_KAIO_ARRAY_SIZE of 32-bit elements, for 8kb.
 * If more than (MAX_KAIO_FDARRAY_SIZE * KAIO_FDARRAY_ELEM_SIZE)
 * files are open, this can be expanded.
 */

#define	MAX_KAIO_FDARRAY_SIZE		2048
#define	KAIO_FDARRAY_ELEM_SIZE		WORD_BIT	/* uint32_t */

#define	MAX_KAIO_FDS	(MAX_KAIO_FDARRAY_SIZE * KAIO_FDARRAY_ELEM_SIZE)

#define	VALID_FD(fdes)		((fdes) >= 0 && (fdes) < MAX_KAIO_FDS)

#define	KAIO_SUPPORTED(fdes)						\
	(!VALID_FD(fdes) ||						\
		((_kaio_supported[(fdes) / KAIO_FDARRAY_ELEM_SIZE] &	\
		(uint32_t)(1 << ((fdes) % KAIO_FDARRAY_ELEM_SIZE))) == 0))

#define	SET_KAIO_NOT_SUPPORTED(fdes)					\
	if (VALID_FD(fdes))						\
		_kaio_supported[(fdes) / KAIO_FDARRAY_ELEM_SIZE] |=	\
		(uint32_t)(1 << ((fdes) % KAIO_FDARRAY_ELEM_SIZE))

#define	CLEAR_KAIO_SUPPORTED(fdes)					\
	if (VALID_FD(fdes))						\
		_kaio_supported[(fdes) / KAIO_FDARRAY_ELEM_SIZE] &=	\
		~(uint32_t)(1 << ((fdes) % KAIO_FDARRAY_ELEM_SIZE))

struct aio_worker {
	aio_worker_t *work_forw;	/* forward link in list of workers */
	aio_worker_t *work_backw;	/* backwards link in list of workers */
	mutex_t work_qlock1;		/* lock for work queue 1 */
	cond_t work_idle_cv;		/* place to sleep when idle */
	aio_req_t *work_head1;		/* head of work request queue 1 */
	aio_req_t *work_tail1;		/* tail of work request queue 1 */
	aio_req_t *work_next1;		/* work queue one's next pointer */
	aio_req_t *work_prev1;		/* last request done from queue 1 */
	aio_req_t *work_req;		/* active work request */
	thread_t work_tid;		/* worker's thread-id */
	int work_count1;		/* length of work queue one */
	int work_done1;			/* number of requests done */
	int work_minload1;		/* min length of queue */
	int work_idleflg;		/* when set, worker is idle */
	sigjmp_buf work_jmp_buf;	/* cancellation point */
};

struct aio_hash {			/* resultp hash table */
	mutex_t		hash_lock;
	aio_req_t	*hash_ptr;
#if !defined(_LP64)
	void		*hash_pad;	/* ensure sizeof (aio_hash_t) == 32 */
#endif
};

extern aio_hash_t *_aio_hash;

#define	HASHSZ			2048	/* power of 2 */
#define	AIOHASH(resultp)	((((uintptr_t)(resultp) >> 17) ^ \
				((uintptr_t)(resultp) >> 2)) & (HASHSZ - 1))
#define	POSIX_AIO(x)		((x)->req_type == AIO_POSIX_REQ)

extern int __uaio_init(void);
extern void _kaio_init(void);
extern intptr_t _kaio(int, ...);
extern int _aiorw(int, caddr_t, int, offset_t, int, aio_result_t *, int);
extern int _aio_rw(aiocb_t *, aio_lio_t *, aio_worker_t **, int, int);
#if !defined(_LP64)
extern int _aio_rw64(aiocb64_t *, aio_lio_t *, aio_worker_t **, int, int);
#endif
extern int _aio_create_worker(aio_req_t *, int);
extern int _aio_cancel_req(aio_worker_t *, aio_req_t *, int *, int *);
extern int aiocancel_all(int);
extern void aio_panic(const char *) __NORETURN;
extern aio_req_t *_aio_hash_find(aio_result_t *);
extern aio_req_t *_aio_hash_del(aio_result_t *);
extern void _aio_req_mark_done(aio_req_t *);
extern void _aio_waitn_wakeup(void);
extern aio_worker_t *_aio_worker_alloc(void);
extern void _aio_worker_free(void *);
extern aio_req_t *_aio_req_alloc(void);
extern void _aio_req_free(aio_req_t *);
extern aio_lio_t *_aio_lio_alloc(void);
extern void _aio_lio_free(aio_lio_t *);
extern int _aio_idle(aio_worker_t *);
extern void *_aio_do_request(void *);
extern void *_aio_do_notify(void *);
extern void _lio_remove(aio_req_t *);
extern aio_req_t *_aio_req_remove(aio_req_t *);
extern int _aio_get_timedelta(timespec_t *, timespec_t *);
extern aio_result_t *_aio_req_done(void);
extern void _aio_set_result(aio_req_t *, ssize_t, int);
extern int _aio_sigev_thread_init(struct sigevent *);
extern int _aio_sigev_thread(aiocb_t *);
#if !defined(_LP64)
extern int _aio_sigev_thread64(aiocb64_t *);
#endif

extern aio_worker_t *_kaiowp;		/* points to kaio cleanup thread */
extern aio_worker_t *__workers_rw;	/* list of all rw workers */
extern aio_worker_t *__nextworker_rw;	/* worker chosen for next rw request */
extern int __rw_workerscnt;		/* number of rw workers */
extern aio_worker_t *__workers_no;	/* list of all notification workers */
extern aio_worker_t *__nextworker_no;	/* worker chosen, next notification */
extern int __no_workerscnt;		/* number of notification workers */
extern mutex_t __aio_initlock;		/* makes aio initialization atomic */
extern cond_t __aio_initcv;
extern int __aio_initbusy;
extern mutex_t __aio_mutex;		/* global aio lock */
extern cond_t _aio_iowait_cv;		/* wait for userland I/Os */
extern cond_t _aio_waitn_cv;		/* wait for end of aio_waitn */
extern int _max_workers;		/* max number of workers permitted */
extern int _min_workers;		/* min number of workers */
extern sigset_t _worker_set;		/* worker's signal mask */
extern int _aio_worker_cnt;		/* number of AIO workers */
extern int _sigio_enabled;		/* when set, send SIGIO signal */
extern pid_t __pid;			/* process's PID */
extern int __uaio_ok;			/* indicates if aio is initialized */
extern int _kaio_ok;			/* indicates if kaio is initialized */
extern pthread_key_t _aio_key;		/* for thread-specific data */
extern aio_req_t *_aio_done_tail;	/* list of done requests */
extern aio_req_t *_aio_done_head;
extern aio_req_t *_aio_doneq;
extern int _aio_freelist_cnt;
extern int _aio_allocated_cnt;
extern int _aio_donecnt;
extern int _aio_doneq_cnt;
extern int _aio_waitncnt;		/* # of requests for aio_waitn */
extern int _aio_outstand_cnt;		/* # of outstanding requests */
extern int _kaio_outstand_cnt;		/* # of outstanding kaio requests */
extern int _aio_req_done_cnt;		/* req. done but not in "done queue" */
extern int _aio_kernel_suspend;		/* active kernel kaio calls */
extern int _aio_suscv_cnt;		/* aio_suspend calls waiting on cv's */
extern int _aiowait_flag;		/* when set, aiowait() is inprogress */
extern int _aio_flags;			/* see defines, above */
extern uint32_t *_kaio_supported;

extern const sigset_t maskset;		/* all maskable signals */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASYNCIO_H */
