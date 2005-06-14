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

#ifndef	_LIBAIO_H
#define	_LIBAIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <asynch.h>
#include <setjmp.h>
#include <signal.h>
#include <siginfo.h>
#include <aio.h>
#include <limits.h>
#include <ucontext.h>

#ifndef _REENTRANT
#define	_REENTRANT
#endif

#ifdef DEBUG
extern int assfail(char *, char *, int);
#define	ASSERT(EX) ((void)((EX) || assfail(#EX, __FILE__, __LINE__)))
#else
#define	ASSERT(EX)
#endif

#define	SIGAIOCANCEL	SIGPROF		/* special aio cancelation signal */
#define	AIO_WAITN_MAXIOCBS	32768	/* max. iocbs per system call */

typedef struct aio_args {
	int 		fd;
	caddr_t		buf;
	size_t		bufsz;
	offset_t	offset;
} aio_args_t;

/*
 * list head for UFS list I/O
 */
typedef struct aio_lio {
	char		lio_mode;	/* LIO_WAIT/LIO_NOWAIT */
	int		lio_nent;	/* Number of list I/O's		*/
	int		lio_refcnt;	/* outstanding I/O's 		*/
	cond_t		lio_cond_cv;	/* list notification for I/O done */
	mutex_t		lio_mutex;	/* list mutex 			*/
	struct aio_lio	*lio_next;	/* pointer to next on freelist  */
	int		lio_signo;	/* Signal for LIO_NOWAIT */
	union sigval	lio_sigval;	/* Signal parameter */
	char		lio_canned;	/* lio was canceled */
} aio_lio_t;

/*
 * size of aio_req should be power of 2. this helps to improve the
 * effectiveness of the hashing function.
 */
typedef struct aio_req {
	/*
	 * fields protected by _aio_mutex lock.
	 */
	struct aio_req *req_link;	/* hash chain link */
	/*
	 * when req is on the doneq, then req_next is protected by
	 * the _aio_mutex lock. when the req is on a work q, then
	 * req_next is protected by a worker's work_qlock1 lock.
	 */
	struct aio_req *req_next;	/* request/done queue link */
	struct aio_req *req_prev;	/* double linked list */
	/*
	 * condition variable that waits for a request to be
	 * canceled.
	 */
	mutex_t		req_lock;	/* protects the following 2 fields */
	cond_t		req_cancv;	/* cancel req condition variable */
	char		req_canned;	/* set when canceled */
	/*
	 * fields protected by a worker's work_qlock1 lock.
	 */
	int		req_state;	/* AIO_REQ_QUEUED, ... */
	/*
	 * fields require no locking.
	 */
	int		req_type;	/* AIO_POSIX_REQ ? */
	struct aio_worker *req_worker;	/* associate req. with worker */
	aio_result_t	*req_resultp;	/* address of result buffer */
	int		req_op;		/* read or write */
	aio_args_t	req_args;	/* arglist */
	aio_lio_t	*lio_head;	/* list head for LIO */
	int		req_retval;	/* resultp's retval */
	int		req_errno;	/* resultp's errno */
	char		req_canwait;	/* waiting for req to be canceled */
	struct	sigevent aio_sigevent;
	int		lio_signo;	/* Signal for LIO_NOWAIT */
	union sigval lio_sigval;	/* Signal parameter */
	aiocb_t		*req_iocb;	/* ptr to aiocb */
} aio_req_t;

/* special request type for handling sigevent notification */
#define	AIOSIGEV	AIOFSYNC+1

/* special lio type that destroys itself when lio refcnt becomes zero */
#define	LIO_FSYNC	LIO_WAIT+1
#define	LIO_DESTROY	LIO_FSYNC+1

/* lio flags */
#define	LIO_FSYNC_CANCELED	0x1

/* values for aios_state */

#define	AIO_REQ_QUEUED		1
#define	AIO_REQ_INPROGRESS	2
#define	AIO_REQ_CANCELED	3
#define	AIO_REQ_DONE 		4
#define	AIO_REQ_FREE		5
#define	AIO_LIO_DONE		6
#define	AIO_REQ_DONEQ 		7

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

/*
 * if set, _aiodone() notifies aio_waitn about done requests
 * from the threads
 */
#define	AIO_WAIT_INPROGRESS	0x1

/*
 * if set, _aiodone() wakes up functions waiting for completed I/Os
 */
#define	AIO_IO_WAITING		0x2

#define	AIO_LIB_WAITN		0x4		/* aio_waitn in progress */
#define	AIO_LIB_WAITN_PENDING	0x8		/* aio_waitn requests pending */

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
 * Array is MAX_KAIO_ARRAY_SIZE of 32-bit elements, for 4kb.
 * If more than (MAX_KAIO_FDARRAY_SIZE * KAIO_FDARRAY_ELEM_SIZE )
 * files are open, this can be expanded.
 */

#define	MAX_KAIO_FDARRAY_SIZE		1024
#define	KAIO_FDARRAY_ELEM_SIZE		WORD_BIT	/* uint32_t */

#define	MAX_KAIO_FDS	(MAX_KAIO_FDARRAY_SIZE * KAIO_FDARRAY_ELEM_SIZE)

#define	VALID_FD(fdes)		(((fdes) >= 0) && ((fdes) < MAX_KAIO_FDS))

#define	KAIO_SUPPORTED(fdes)						\
	((!VALID_FD(fdes)) || 						\
		((_kaio_supported[(fdes) / KAIO_FDARRAY_ELEM_SIZE] &	\
		(uint32_t)(1 << ((fdes) % KAIO_FDARRAY_ELEM_SIZE))) == 0))

#define	SET_KAIO_NOT_SUPPORTED(fdes)					\
	if (VALID_FD((fdes)))						\
		_kaio_supported[(fdes) / KAIO_FDARRAY_ELEM_SIZE] |=	\
		(uint32_t)(1 << ((fdes) % KAIO_FDARRAY_ELEM_SIZE))

#define	CLEAR_KAIO_SUPPORTED(fdes)					\
	if (VALID_FD((fdes)))						\
		_kaio_supported[(fdes) / KAIO_FDARRAY_ELEM_SIZE] &=	\
		~(uint32_t)(1 << ((fdes) % KAIO_FDARRAY_ELEM_SIZE))

typedef struct aio_worker {
	/*
	 * fields protected by _aio_mutex lock
	 */
	struct aio_worker *work_forw;	/* forward link in list of workers */
	struct aio_worker *work_backw;	/* backwards link in list of workers */
	/*
	 * fields require no locking.
	 */
	thread_t work_tid;		/* worker's thread-id */
	mutex_t work_qlock1;		/* lock for work queue 1 */
	struct aio_req *work_head1;	/* head of work request queue 1 */
	struct aio_req *work_tail1;	/* tail of work request queue 1 */
	struct aio_req *work_next1;	/* work queue one's next pointer */
	struct aio_req *work_prev1;	/* last request done from queue 1 */
	int work_cnt1;			/* length of work queue one */
	int work_done1;			/* number of requests done */
	int work_minload1;		/* min length of queue */
	struct aio_req *work_req;	/* active work request */
	int work_idleflg;		/* when set, worker is idle */
	cond_t work_idle_cv;		/* place to sleep when idle */
	mutex_t work_lock;		/* protects work flags */
	sigjmp_buf work_jmp_buf;	/* cancellation point */
	char work_cancel_flg;		/* flag set when at cancellation pt */
} aio_worker_t;

extern void _kaio_init(void);
extern intptr_t _kaio(int, ...);
extern int _aiorw(int, caddr_t, int, offset_t, int, aio_result_t *, int);
extern int _aio_rw(aiocb_t *, aio_lio_t *, aio_worker_t **, int, int,
	struct sigevent *);
extern int __aio_fsync(int, aiocb_t *);
#if	defined(_LARGEFILE64_SOURCE) && !defined(_LP64)
extern int _aio_rw64(aiocb64_t *, aio_lio_t *, aio_worker_t **, int, int,
	struct sigevent *);
extern int __aio_fsync64(int, aiocb64_t *);
#endif
extern int aiocancel_all(int);
extern int _aio_create_worker(aio_req_t *, int);
extern void *_aio_send_sigev(void *);

extern void _aio_cancel_on(aio_worker_t *);
extern void _aio_cancel_off(aio_worker_t *);
extern int _aio_cancel_req(aio_worker_t *, aio_req_t *, int *, int *);

extern void _aio_forkinit(void);
extern void _aiopanic(char *);
extern void _aio_lock(void);
extern void _aio_unlock(void);
extern void _aio_req_free(aio_req_t *);
extern aio_req_t *_aio_hash_del(aio_result_t *);
extern int _fill_aiocache(int);

extern aio_worker_t *_aio_alloc_worker(void);
extern void _aio_free_worker(void *);

extern void _aio_idle(struct aio_worker *);
extern void __aiosendsig(void);
extern void *_aio_do_request(void *);
extern void _aio_remove(aio_req_t *);
extern void _lio_remove(aio_lio_t *);
extern aio_req_t *_aio_req_remove(aio_req_t *);
extern int _aio_get_timedelta(struct timespec *, struct timespec *);

extern int _close(int);
extern int __sigqueue(pid_t pid, int signo,
	/* const union sigval */ void *value, int si_code);
extern pid_t _fork(void);
extern int _sigaction(int sig, const struct sigaction *act,
	struct sigaction *oact);
extern int _sigemptyset(sigset_t *set);
extern int _sigaddset(sigset_t *set, int signo);
extern int _sigismember(sigset_t *set, int signo);
extern int _sigprocmask(int how, const sigset_t *set, sigset_t *oset);
extern void aiosigcancelhndlr(int, siginfo_t *, void *);

extern aio_worker_t *__nextworker_rd;	/* worker chosen for next rd request */
extern aio_worker_t *__workers_rd;	/* list of all rd workers */
extern int __rd_workerscnt;		/* number of rd workers */
extern aio_worker_t *__nextworker_wr;	/* worker chosen for next wr request */
extern aio_worker_t *__workers_wr;	/* list of all wr workers */
extern int __wr_workerscnt;		/* number of wr workers */
extern aio_worker_t *__nextworker_si;	/* worker chosen for next si request */
extern aio_worker_t *__workers_si;	/* list of all si workers */
extern int __si_workerscnt;		/* number of si workers */
extern int __aiostksz;			/* stack size for workers */
extern mutex_t __aio_mutex;		/* global aio lock that's SIGIO-safe */
extern mutex_t __lio_mutex;		/* global lio lock */
extern int _max_workers;		/* max number of workers permitted */
extern int _min_workers;		/* min number of workers */
extern sigset_t _worker_set;		/* worker's signal mask */
extern int _aio_worker_cnt;		/* number of AIO workers */
extern int _sigio_enabled;		/* when set, send SIGIO signal */
extern int __sigio_pending;		/* count of pending SIGIO signals */
extern int __sigio_masked;		/* when set, SIGIO is masked */
extern int __sigio_maskedcnt;		/* count number times bit mask is set */
extern pid_t __pid;			/* process's PID */
extern int _kaio_ok;			/* indicates if kaio is initialized */
extern thread_key_t _aio_key;		/* for thread-specific data */
extern struct sigaction sigcanact;	/* action for SIGAIOCANCEL */
extern int _pagesize;

/*
 * Array for determining whether or not a file supports kaio
 *
 */
extern uint32_t _kaio_supported[];

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBAIO_H */
