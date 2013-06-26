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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _THR_UBERDATA_H
#define	_THR_UBERDATA_H

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <thread.h>
#include <pthread.h>
#include <atomic.h>
#include <link.h>
#include <sys/resource.h>
#include <sys/lwp.h>
#include <errno.h>
#include <sys/asm_linkage.h>
#include <sys/regset.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <synch.h>
#include <door.h>
#include <limits.h>
#include <sys/synch32.h>
#include <schedctl.h>
#include <sys/priocntl.h>
#include <thread_db.h>
#include <setjmp.h>
#include "libc_int.h"
#include "tdb_agent.h"
#include "thr_debug.h"

/*
 * This is an implementation-specific include file for threading support.
 * It is not to be seen by the clients of the library.
 *
 * This file also describes uberdata in libc.
 *
 * The term "uberdata" refers to data that is unique and visible across
 * all link maps.  The name is meant to imply that such data is truly
 * global, not just locally global to a particular link map.
 *
 * See the Linker and Libraries Guide for a full description of alternate
 * link maps and how they are set up and used.
 *
 * Alternate link maps implement multiple global namespaces within a single
 * process.  There may be multiple instances of identical dynamic libraries
 * loaded in a process's address space at the same time, each on a different
 * link map (as determined by the dynamic linker), each with its own set of
 * global variables.  Which particular instance of a global variable is seen
 * by a thread running in the process is determined by the link map on which
 * the thread happens to be executing at the time.
 *
 * However, there are aspects of a process that are unique across all
 * link maps, in particular the structures used to implement threads
 * of control (in Sparc terminology, there is only one %g7 regardless
 * of the link map on which the thread is executing).
 *
 * All uberdata is referenced from a base pointer in the thread's ulwp_t
 * structure (which is also uberdata).  All allocations and deallocations
 * of uberdata are made via the uberdata-aware lmalloc() and lfree()
 * interfaces (malloc() and free() are simply locally-global).
 */

/*
 * Special libc-private access to errno.
 * We do this so that references to errno do not invoke the dynamic linker.
 */
#undef errno
#define	errno (*curthread->ul_errnop)

/*
 * See <sys/synch32.h> for the reasons for these values
 * and why they are different for sparc and intel.
 */
#if defined(__sparc)

/* lock.lock64.pad[x]	   4 5 6 7 */
#define	LOCKMASK	0xff000000
#define	WAITERMASK	0x000000ff
#define	SPINNERMASK	0x00ff0000
#define	SPINNERSHIFT	16
#define	WAITER		0x00000001
#define	LOCKSET		0xff
#define	LOCKCLEAR	0

#define	PIDSHIFT	32
#define	LOCKMASK64	0xffffffffff000000ULL
#define	LOCKBYTE64	0x00000000ff000000ULL
#define	WAITERMASK64	0x00000000000000ffULL
#define	SPINNERMASK64	0x0000000000ff0000ULL

#elif defined(__x86)

/* lock.lock64.pad[x]	   7 6 5 4 */
#define	LOCKMASK	0xff000000
#define	WAITERMASK	0x00ff0000
#define	SPINNERMASK	0x0000ff00
#define	SPINNERSHIFT	8
#define	WAITER		0x00010000
#define	LOCKSET		0x01
#define	LOCKCLEAR	0

#define	PIDSHIFT	0
#define	LOCKMASK64	0xff000000ffffffffULL
#define	LOCKBYTE64	0x0100000000000000ULL
#define	WAITERMASK64	0x00ff000000000000ULL
#define	SPINNERMASK64	0x0000ff0000000000ULL

#else
#error "neither __sparc nor __x86 is defined"
#endif

/*
 * Fetch the owner of a USYNC_THREAD mutex.
 * Don't use this with process-shared mutexes;
 * the owing thread may be in a different process.
 */
#define	MUTEX_OWNER(mp)	((ulwp_t *)(uintptr_t)(mp)->mutex_owner)

/*
 * Test if a thread owns a process-private (USYNC_THREAD) mutex.
 * This is inappropriate for a process-shared (USYNC_PROCESS) mutex.
 * The 'mp' argument must not have side-effects since it is evaluated twice.
 */
#define	MUTEX_OWNED(mp, thrp)	\
	((mp)->mutex_lockw != 0 && MUTEX_OWNER(mp) == thrp)


/*
 * uberflags.uf_tdb_register_sync is an interface with libc_db to enable the
 * collection of lock statistics by a debugger or other collecting tool.
 *
 * uberflags.uf_thread_error_detection is set by an environment variable:
 *	_THREAD_ERROR_DETECTION
 *		0 == no detection of locking primitive errors.
 *		1 == detect errors and issue a warning message.
 *		2 == detect errors, issue a warning message, and dump core.
 *
 * We bundle these together in uberflags.uf_trs_ted to make a test of either
 * being non-zero a single memory reference (for speed of mutex_lock(), etc).
 *
 * uberflags.uf_mt is set non-zero when the first thread (in addition
 * to the main thread) is created.
 *
 * We bundle all these flags together in uberflags.uf_all to make a test
 * of any being non-zero a single memory reference (again, for speed).
 */
typedef union {
	int	uf_all;			/* combined all flags */
	struct {
		short	h_pad;
		short	h_trs_ted;	/* combined reg sync & error detect */
	} uf_h;
	struct {
		char	x_mt;
		char	x_pad;
		char	x_tdb_register_sync;
		char	x_thread_error_detection;
	} uf_x;
} uberflags_t;

#define	uf_mt				uf_x.x_mt
#define	uf_tdb_register_sync		uf_x.x_tdb_register_sync
#define	uf_thread_error_detection	uf_x.x_thread_error_detection
#define	uf_trs_ted			uf_h.h_trs_ted	/* both of the above */

/*
 * NOTE WELL:
 * To enable further optimization, the "ul_schedctl_called" member
 * of the ulwp_t structure (below) serves double-duty:
 *	1. If NULL, it means that the thread must call __schedctl()
 *	   to set up its schedctl mappings before acquiring a mutex.
 *	   This is required by the implementation of adaptive mutex locking.
 *	2. If non-NULL, it points to uberdata.uberflags, so that tests of
 *	   uberflags can be made without additional memory references.
 * This allows the common case of _mutex_lock() and _mutex_unlock() for
 * USYNC_THREAD mutexes with no error detection and no lock statistics
 * to be optimized for speed.
 */

/* double the default stack size for 64-bit processes */
#ifdef _LP64
#define	MINSTACK	(8 * 1024)
#define	DEFAULTSTACK	(2 * 1024 * 1024)
#else
#define	MINSTACK	(4 * 1024)
#define	DEFAULTSTACK	(1024 * 1024)
#endif

#define	MUTEX_TRY	0
#define	MUTEX_LOCK	1
#define	MUTEX_NOCEIL	0x40

#if defined(__x86)

typedef struct {	/* structure returned by fnstenv */
	int	fctrl;		/* control word */
	int	fstat;		/* status word (flags, etc) */
	int	ftag;		/* tag of which regs busy */
	int	misc[4];	/* other stuff, 28 bytes total */
} fpuenv_t;

#ifdef _SYSCALL32
typedef fpuenv_t fpuenv32_t;
#endif	/* _SYSCALL32 */

#elif defined(__sparc)

typedef struct {	/* fp state structure */
	greg_t	fsr;
	greg_t	fpu_en;
} fpuenv_t;

#ifdef _SYSCALL32
typedef struct {
	greg32_t	fsr;
	greg32_t	fpu_en;
} fpuenv32_t;
#endif	/* _SYSCALL32 */

#endif	/* __x86 */

#if defined(__x86)
extern	void	ht_pause(void);		/* "pause" instruction */
#define	SMT_PAUSE()	ht_pause()
#elif defined(SMT_PAUSE_FUNCTION)
extern	void	SMT_PAUSE_FUNCTION(void);
#define	SMT_PAUSE()	SMT_PAUSE_FUNCTION()
#else
#define	SMT_PAUSE()	smt_pause()
#endif	/* __x86 */

/*
 * Cleanup handler related data.
 * This structure is exported as _cleanup_t in pthread.h.
 * pthread.h exports only the size of this structure, so check
 * _cleanup_t in pthread.h before making any change here.
 */
typedef struct __cleanup {
	struct __cleanup *next;		/* pointer to next handler */
	caddr_t	fp;			/* current frame pointer */
	void	(*func)(void *);	/* cleanup handler address */
	void	*arg;			/* handler's argument */
} __cleanup_t;

/*
 * Thread-Specific Data (TSD)
 * TSD_NFAST includes the invalid key zero, so there
 * are really only (TSD_NFAST - 1) fast key slots.
 */
typedef	void (*PFrV)(void *);
#define	TSD_UNALLOCATED	((PFrV)1)
#define	TSD_NFAST	9

/*
 * The tsd union is designed to burn a little memory (9 words) to make
 * lookups blindingly fast.  Note that tsd_nalloc could be placed at the
 * end of the pad region to increase the likelihood that it falls on the
 * same cache line as the data.
 */
typedef union tsd {
	uint_t tsd_nalloc;		/* Amount of allocated storage */
	void *tsd_pad[TSD_NFAST];
	void *tsd_data[1];
} tsd_t;

typedef struct {
	mutex_t tsdm_lock;		/* Lock protecting the data */
	uint_t tsdm_nkeys;		/* Number of allocated keys */
	uint_t tsdm_nused;		/* Number of used keys */
	PFrV *tsdm_destro;		/* Per-key destructors */
	char tsdm_pad[64 -		/* pad to 64 bytes */
		(sizeof (mutex_t) + 2 * sizeof (uint_t) + sizeof (PFrV *))];
} tsd_metadata_t;

#ifdef _SYSCALL32
typedef union tsd32 {
	uint_t tsd_nalloc;		/* Amount of allocated storage */
	caddr32_t tsd_pad[TSD_NFAST];
	caddr32_t tsd_data[1];
} tsd32_t;

typedef struct {
	mutex_t tsdm_lock;		/* Lock protecting the data */
	uint_t tsdm_nkeys;		/* Number of allocated keys */
	uint_t tsdm_nused;		/* Number of used keys */
	caddr32_t tsdm_destro;		/* Per-key destructors */
	char tsdm_pad[64 -		/* pad to 64 bytes */
		(sizeof (mutex_t) + 2 * sizeof (uint_t) + sizeof (caddr32_t))];
} tsd_metadata32_t;
#endif	/* _SYSCALL32 */


/*
 * Thread-Local Storage (TLS)
 */
typedef struct {
	void		*tls_data;
	size_t		tls_size;
} tls_t;

typedef struct {
	mutex_t	tls_lock;		/* Lock protecting the data */
	tls_t	tls_modinfo;		/* Root of all TLS_modinfo data */
	tls_t	static_tls;		/* Template for static TLS */
	char	tls_pad[64 -		/* pad to 64 bytes */
		(sizeof (mutex_t) + 2 * sizeof (tls_t))];
} tls_metadata_t;

#ifdef _SYSCALL32
typedef struct {
	caddr32_t	tls_data;
	size32_t	tls_size;
} tls32_t;

typedef struct {
	mutex_t	tls_lock;		/* Lock protecting the data */
	tls32_t	tls_modinfo;		/* Root of all TLS_modinfo data */
	tls32_t	static_tls;		/* Template for static TLS */
	char	tls_pad[64 -		/* pad to 64 bytes */
		(sizeof (mutex_t) + 2 * sizeof (tls32_t))];
} tls_metadata32_t;
#endif	/* _SYSCALL32 */


/*
 * Sleep queue root for USYNC_THREAD condvars and mutexes.
 * There is a default queue root for each queue head (see below).
 * Also, each ulwp_t contains a queue root that can be used
 * when the thread is enqueued on the queue, if necessary
 * (when more than one wchan hashes to the same queue head).
 */
typedef struct queue_root {
	struct queue_root	*qr_next;
	struct queue_root	*qr_prev;
	struct ulwp		*qr_head;
	struct ulwp		*qr_tail;
	void			*qr_wchan;
	uint32_t		qr_rtcount;
	uint32_t		qr_qlen;
	uint32_t		qr_qmax;
} queue_root_t;

#ifdef _SYSCALL32
typedef struct queue_root32 {
	caddr32_t		qr_next;
	caddr32_t		qr_prev;
	caddr32_t		qr_head;
	caddr32_t		qr_tail;
	caddr32_t		qr_wchan;
	uint32_t		qr_rtcount;
	uint32_t		qr_qlen;
	uint32_t		qr_qmax;
} queue_root32_t;
#endif

/*
 * Sleep queue heads for USYNC_THREAD condvars and mutexes.
 * The size and alignment is 128 bytes to reduce cache conflicts.
 * Each queue head points to a list of queue roots, defined above.
 * Each queue head contains a default queue root for use when only one
 * is needed.  It is always at the tail of the queue root hash chain.
 */
typedef union {
	uint64_t		qh_64[16];
	struct {
		mutex_t		q_lock;
		uint8_t		q_qcnt;
		uint8_t		q_type;		/* MX or CV */
		uint8_t		q_pad1[2];
		uint32_t	q_lockcount;
		uint32_t	q_qlen;
		uint32_t	q_qmax;
		void		*q_wchan;	/* valid only while locked */
		struct queue_root *q_root;	/* valid only while locked */
		struct queue_root *q_hlist;
#if !defined(_LP64)
		caddr_t		q_pad2[3];
#endif
		queue_root_t	q_def_root;
		uint32_t	q_hlen;
		uint32_t	q_hmax;
	} qh_qh;
} queue_head_t;

#define	qh_lock		qh_qh.q_lock
#define	qh_qcnt		qh_qh.q_qcnt
#define	qh_type		qh_qh.q_type
#if defined(THREAD_DEBUG)
#define	qh_lockcount	qh_qh.q_lockcount
#define	qh_qlen		qh_qh.q_qlen
#define	qh_qmax		qh_qh.q_qmax
#endif
#define	qh_wchan	qh_qh.q_wchan
#define	qh_root		qh_qh.q_root
#define	qh_hlist	qh_qh.q_hlist
#define	qh_def_root	qh_qh.q_def_root
#define	qh_hlen		qh_qh.q_hlen
#define	qh_hmax		qh_qh.q_hmax

/* queue types passed to queue_lock() */
#define	MX	0
#define	CV	1
#define	QHASHSHIFT	9			/* number of hashing bits */
#define	QHASHSIZE	(1 << QHASHSHIFT)	/* power of 2 (1<<9 == 512) */
#define	QUEUE_HASH(wchan, type)	((uint_t)			\
	((((uintptr_t)(wchan) >> 3)				\
	^ ((uintptr_t)(wchan) >> (QHASHSHIFT + 3)))		\
	& (QHASHSIZE - 1)) + (((type) == MX)? 0 : QHASHSIZE))

extern	queue_head_t	*queue_lock(void *, int);
extern	void		queue_unlock(queue_head_t *);
extern	void		enqueue(queue_head_t *, struct ulwp *, int);
extern	struct ulwp	*dequeue(queue_head_t *, int *);
extern	struct ulwp	**queue_slot(queue_head_t *, struct ulwp **, int *);
extern	struct ulwp	*queue_waiter(queue_head_t *);
extern	int		dequeue_self(queue_head_t *);
extern	void		queue_unlink(queue_head_t *,
				struct ulwp **, struct ulwp *);
extern	void		unsleep_self(void);
extern	void		spin_lock_set(mutex_t *);
extern	void		spin_lock_clear(mutex_t *);

/*
 * Scheduling class information structure.
 */
typedef struct {
	short		pcc_state;
	short		pcc_policy;
	pri_t		pcc_primin;
	pri_t		pcc_primax;
	pcinfo_t	pcc_info;
} pcclass_t;

/*
 * Memory block for chain of owned ceiling mutexes.
 */
typedef struct mxchain {
	struct mxchain	*mxchain_next;
	mutex_t		*mxchain_mx;
} mxchain_t;

/*
 * Pointer to an rwlock that is held for reading.
 * Used in rw_rdlock() to allow a thread that already holds a read
 * lock to acquire another read lock on the same rwlock even if
 * there are writers waiting.  This to avoid deadlock when acquiring
 * a read lock more than once in the presence of pending writers.
 * POSIX mandates this behavior.
 */
typedef struct {
	void	*rd_rwlock;	/* the rwlock held for reading */
	size_t	rd_count;	/* count of read locks applied */
} readlock_t;

#ifdef _SYSCALL32
typedef struct {
	caddr32_t	rd_rwlock;
	size32_t	rd_count;
} readlock32_t;
#endif	/* _SYSCALL32 */

/*
 * Maximum number of read locks allowed for one thread on one rwlock.
 * This could be as large as INT_MAX, but the SUSV3 test suite would
 * take an inordinately long time to complete.  This is big enough.
 */
#define	READ_LOCK_MAX	100000

#define	ul_tlsent	ul_tls.tls_data	/* array of pointers to dynamic TLS */
#define	ul_ntlsent	ul_tls.tls_size	/* number of entries in ul_tlsent */

/*
 * Round up an integral value to a multiple of 64
 */
#define	roundup64(x)	(-(-(x) & -64))

/*
 * NOTE:  Whatever changes are made to ulwp_t must be
 * reflected in $SRC/cmd/mdb/common/modules/libc/libc.c
 *
 * NOTE: ul_self *must* be the first member of ulwp_t on x86
 * Low-level x86 code relies on this.
 */
typedef struct ulwp {
	/*
	 * These members always need to come first on sparc.
	 * For dtrace, a ulwp_t must be aligned on a 64-byte boundary.
	 */
#if defined(__sparc)
	uint32_t	ul_dinstr;	/* scratch space for dtrace */
	uint32_t	ul_padsparc0[15];
	uint32_t	ul_dsave;	/* dtrace: save %g1, %g0, %sp */
	uint32_t	ul_drestore;	/* dtrace: restore %g0, %g0, %g0 */
	uint32_t	ul_dftret;	/* dtrace: return probe fasttrap */
	uint32_t	ul_dreturn;	/* dtrace: return %o0 */
#endif
	struct ulwp	*ul_self;	/* pointer to self */
#if defined(__i386)
	uint8_t		ul_dinstr[40];	/* scratch space for dtrace */
#elif defined(__amd64)
	uint8_t		ul_dinstr[56];	/* scratch space for dtrace */
#endif
	struct uberdata *ul_uberdata;	/* uber (super-global) data */
	tls_t		ul_tls;		/* dynamic thread-local storage base */
	struct ulwp	*ul_forw;	/* forw, back all_lwps list, */
	struct ulwp	*ul_back;	/* protected by link_lock */
	struct ulwp	*ul_next;	/* list to keep track of stacks */
	struct ulwp	*ul_hash;	/* hash chain linked list */
	void		*ul_rval;	/* return value from thr_exit() */
	caddr_t		ul_stk;		/* mapping base of the stack */
	size_t		ul_mapsiz;	/* mapping size of the stack */
	size_t		ul_guardsize;	/* normally _lpagesize */
	uintptr_t	ul_stktop;	/* broken thr_stksegment() interface */
	size_t		ul_stksiz;	/* broken thr_stksegment() interface */
	stack_t		ul_ustack;	/* current stack boundaries */
	int		ul_ix;		/* hash index */
	lwpid_t		ul_lwpid;	/* thread id, aka the lwp id */
	pri_t		ul_pri;		/* scheduling priority */
	pri_t		ul_epri;	/* real-time ceiling priority */
	char		ul_policy;	/* scheduling policy */
	char		ul_cid;		/* scheduling class id */
	union {
		struct {
			char	cursig;	/* deferred signal number */
			char	pleasestop; /* lwp requested to stop itself */
		} s;
		short	curplease;	/* for testing both at once */
	} ul_cp;
	char		ul_stop;	/* reason for stopping */
	char		ul_signalled;	/* this lwp was cond_signal()d */
	char		ul_dead;	/* this lwp has called thr_exit */
	char		ul_unwind;	/* posix: unwind C++ stack */
	char		ul_detached;	/* THR_DETACHED at thread_create() */
					/* or pthread_detach() was called */
	char		ul_writer;	/* sleeping in rw_wrlock() */
	char		ul_stopping;	/* set by curthread: stopping self */
	char		ul_cancel_prologue;	/* for _cancel_prologue() */
	short		ul_preempt;	/* no_preempt()/preempt() */
	short		ul_savpreempt;	/* pre-existing preempt value */
	char		ul_sigsuspend;	/* thread is in sigsuspend/pollsys */
	char		ul_main;	/* thread is the main thread */
	char		ul_fork;	/* thread is performing a fork */
	char		ul_primarymap;	/* primary link-map is initialized */
	/* per-thread copies of the corresponding global variables */
	uint8_t		ul_max_spinners;	/* thread_max_spinners */
	char		ul_door_noreserve;	/* thread_door_noreserve */
	char		ul_queue_fifo;		/* thread_queue_fifo */
	char		ul_cond_wait_defer;	/* thread_cond_wait_defer */
	char		ul_error_detection;	/* thread_error_detection */
	char		ul_async_safe;		/* thread_async_safe */
	char		ul_rt;			/* found on an RT queue */
	char		ul_rtqueued;		/* was RT when queued */
	char		ul_misaligned;		/* thread_locks_misaligned */
	char		ul_pad[3];
	int		ul_adaptive_spin;	/* thread_adaptive_spin */
	int		ul_queue_spin;		/* thread_queue_spin */
	volatile int	ul_critical;	/* non-zero == in a critical region */
	int		ul_sigdefer;	/* non-zero == defer signals */
	int		ul_vfork;	/* thread is the child of vfork() */
	int		ul_cancelable;	/* _cancelon()/_canceloff() */
	char		ul_cancel_pending;  /* pthread_cancel() was called */
	char		ul_cancel_disabled; /* PTHREAD_CANCEL_DISABLE */
	char		ul_cancel_async;    /* PTHREAD_CANCEL_ASYNCHRONOUS */
	char		ul_save_async;	/* saved copy of ul_cancel_async */
	char		ul_mutator;	/* lwp is a mutator (java interface) */
	char		ul_created;	/* created suspended */
	char		ul_replace;	/* replacement; must be free()d */
	uchar_t		ul_nocancel;	/* cancellation can't happen */
	int		ul_errno;	/* per-thread errno */
	int		*ul_errnop;	/* pointer to errno or self->ul_errno */
	__cleanup_t	*ul_clnup_hdr;	/* head of cleanup handlers list */
	uberflags_t	*ul_schedctl_called;	/* ul_schedctl is set up */
	volatile sc_shared_t *ul_schedctl;	/* schedctl data */
	int		ul_bindflags;	/* bind_guard() interface to ld.so.1 */
	uint_t		ul_libc_locks;	/* count of cancel_safe_mutex_lock()s */
	tsd_t		*ul_stsd;	/* slow TLS for keys >= TSD_NFAST */
	void		*ul_ftsd[TSD_NFAST]; /* fast TLS for keys < TSD_NFAST */
	td_evbuf_t	ul_td_evbuf;	/* event buffer */
	char		ul_td_events_enable;	/* event mechanism enabled */
	char		ul_sync_obj_reg;	/* tdb_sync_obj_register() */
	char		ul_qtype;	/* MX or CV */
	char		ul_cv_wake;	/* != 0: just wake up, don't requeue */
	int		ul_rtld;	/* thread is running inside ld.so.1 */
	int		ul_usropts;	/* flags given to thr_create() */
	void		*(*ul_startpc)(void *); /* start func (thr_create()) */
	void		*ul_startarg;	/* argument for start function */
	void		*ul_wchan;	/* synch object when sleeping */
	struct ulwp	*ul_link;	/* sleep queue link */
	queue_head_t	*ul_sleepq;	/* sleep queue thread is waiting on */
	mutex_t		*ul_cvmutex;	/* mutex dropped when waiting on a cv */
	mxchain_t	*ul_mxchain;	/* chain of owned ceiling mutexes */
	int		ul_save_state;	/* bind_guard() interface to ld.so.1 */
	uint_t		ul_rdlockcnt;	/* # entries in ul_readlock array */
				/* 0 means there is but a single entry */
	union {				/* single entry or pointer to array */
		readlock_t	single;
		readlock_t	*array;
	} ul_readlock;
	uint_t		ul_heldlockcnt;	/* # entries in ul_heldlocks array */
				/* 0 means there is but a single entry */
	union {				/* single entry or pointer to array */
		mutex_t		*single;
		mutex_t		**array;
	} ul_heldlocks;
	/* PROBE_SUPPORT begin */
	void		*ul_tpdp;
	/* PROBE_SUPPORT end */
	ucontext_t	*ul_siglink;	/* pointer to previous context */
	uint_t		ul_spin_lock_spin;	/* spin lock statistics */
	uint_t		ul_spin_lock_spin2;
	uint_t		ul_spin_lock_sleep;
	uint_t		ul_spin_lock_wakeup;
	queue_root_t	ul_queue_root;	/* root of a sleep queue */
	id_t		ul_rtclassid;	/* real-time class id */
	uint_t		ul_pilocks;	/* count of PI locks held */
		/* the following members *must* be last in the structure */
		/* they are discarded when ulwp is replaced on thr_exit() */
	sigset_t	ul_sigmask;	/* thread's current signal mask */
	sigset_t	ul_tmpmask;	/* signal mask for sigsuspend/pollsys */
	siginfo_t	ul_siginfo;	/* deferred siginfo */
	mutex_t		ul_spinlock;	/* used when suspending/continuing */
	fpuenv_t	ul_fpuenv;	/* floating point state */
	uintptr_t	ul_sp;		/* stack pointer when blocked */
	void		*ul_ex_unwind;	/* address of _ex_unwind() or -1 */
#if defined(sparc)
	void		*ul_unwind_ret;	/* used only by _ex_clnup_handler() */
#endif
} ulwp_t;

#define	ul_cursig	ul_cp.s.cursig		/* deferred signal number */
#define	ul_pleasestop	ul_cp.s.pleasestop	/* lwp requested to stop */
#define	ul_curplease	ul_cp.curplease		/* for testing both at once */

/*
 * This is the size of a replacement ulwp, retained only for the benefit
 * of thr_join().  The trailing members are unneeded for this purpose.
 */
#define	REPLACEMENT_SIZE	((size_t)&((ulwp_t *)NULL)->ul_sigmask)

/*
 * Definitions for static initialization of signal sets,
 * plus some sneaky optimizations in various places.
 */

#define	SIGMASK(sig)	((uint32_t)1 << (((sig) - 1) & (32 - 1)))

#if (MAXSIG > (2 * 32) && MAXSIG <= (3 * 32))
#define	FILLSET0	0xffffffffu
#define	FILLSET1	0xffffffffu
#define	FILLSET2	((1u << (MAXSIG - 64)) - 1)
#define	FILLSET3	0
#else
#error "fix me: MAXSIG out of bounds"
#endif

#define	CANTMASK0	(SIGMASK(SIGKILL) | SIGMASK(SIGSTOP))
#define	CANTMASK1	0
#define	CANTMASK2	0
#define	CANTMASK3	0

#define	MASKSET0	(FILLSET0 & ~CANTMASK0)
#define	MASKSET1	(FILLSET1 & ~CANTMASK1)
#define	MASKSET2	(FILLSET2 & ~CANTMASK2)
#define	MASKSET3	(FILLSET3 & ~CANTMASK3)

extern	const sigset_t maskset;		/* set of all maskable signals */

extern	int	thread_adaptive_spin;
extern	uint_t	thread_max_spinners;
extern	int	thread_queue_spin;
extern	int	thread_queue_fifo;
extern	int	thread_queue_dump;
extern	int	thread_cond_wait_defer;
extern	int	thread_async_safe;
extern	int	thread_queue_verify;

/*
 * pthread_atfork() related data, used to store atfork handlers.
 */
typedef struct atfork {
	struct atfork *forw;		/* forward pointer */
	struct atfork *back;		/* backward pointer */
	void (*prepare)(void);		/* pre-fork handler */
	void (*parent)(void);		/* post-fork parent handler */
	void (*child)(void);		/* post-fork child handler */
} atfork_t;

/*
 * Element in the table and in the list of registered process
 * robust locks.  We keep track of these to make sure that we
 * only call ___lwp_mutex_register() once for each such lock
 * after it is first mapped in (or newly mapped in).
 */
typedef struct robust {
	struct robust	*robust_next;	/* hash table list */
	struct robust	*robust_list;	/* global list */
	mutex_t		*robust_lock;
} robust_t;

/*
 * Invalid address, used to mark an unused element in the hash table.
 */
#define	INVALID_ADDR	((void *)(uintptr_t)(-1L))

/*
 * Parameters of the lock registration hash table.
 */
#define	LOCKSHIFT	15			/* number of hashing bits */
#define	LOCKHASHSZ	(1 << LOCKSHIFT)	/* power of 2 (1<<15 == 32K) */
#define	LOCK_HASH(addr)	(uint_t)			\
	((((uintptr_t)(addr) >> 3)			\
	^ ((uintptr_t)(addr) >> (LOCKSHIFT + 3)))	\
	& (LOCKHASHSZ - 1))

/*
 * Make our hot locks reside on private cache lines (64 bytes).
 */
typedef struct {
	mutex_t	pad_lock;
	char	pad_pad[64 - sizeof (mutex_t)];
} pad_lock_t;

/*
 * Make our semi-hot locks reside on semi-private cache lines (32 bytes).
 */
typedef struct {
	mutex_t	pad_lock;
	char	pad_pad[32 - sizeof (mutex_t)];
} pad32_lock_t;

/*
 * The threads hash table is used for fast lookup and locking of an active
 * thread structure (ulwp_t) given a thread-id.  It is an N-element array of
 * thr_hash_table_t structures, where N == 1 before the main thread creates
 * the first additional thread and N == 1024 afterwards.  Each element of the
 * table is 64 bytes in size and alignment to reduce cache conflicts.
 */
typedef struct {
	mutex_t	hash_lock;	/* lock per bucket */
	cond_t	hash_cond;	/* convar per bucket */
	ulwp_t	*hash_bucket;	/* hash bucket points to the list of ulwps */
	char	hash_pad[64 -	/* pad out to 64 bytes */
		(sizeof (mutex_t) + sizeof (cond_t) + sizeof (ulwp_t *))];
} thr_hash_table_t;

#ifdef _SYSCALL32
typedef struct {
	mutex_t	hash_lock;
	cond_t	hash_cond;
	caddr32_t hash_bucket;
	char	hash_pad[64 -
		(sizeof (mutex_t) + sizeof (cond_t) + sizeof (caddr32_t))];
} thr_hash_table32_t;
#endif	/* _SYSCALL32 */


/*
 * siguaction members have 128-byte size and 64-byte alignment.
 * We know that sizeof (struct sigaction) is 32 bytes for both
 * _ILP32 and _LP64 and that sizeof (rwlock_t) is 64 bytes.
 */
typedef struct {
	rwlock_t	sig_lock;
	struct sigaction sig_uaction;
	char	sig_pad[128 - sizeof (rwlock_t) - sizeof (struct sigaction)];
} siguaction_t;

#ifdef _SYSCALL32
typedef struct {
	rwlock_t	sig_lock;
	struct sigaction32 sig_uaction;
	char	sig_pad[128 - sizeof (rwlock_t) - sizeof (struct sigaction32)];
} siguaction32_t;
#endif	/* _SYSCALL32 */


/*
 * Bucket structures, used by lmalloc()/lfree().
 * See port/threads/alloc.c for details.
 * A bucket's size and alignment is 64 bytes.
 */
typedef struct {
	mutex_t	bucket_lock;	/* protects the free list allocations */
	void	*free_list;	/* LIFO list of blocks to allocate/free */
	size_t	chunks;		/* number of 64K blocks mmap()ed last time */
	char	pad64[64 -	/* pad out to 64 bytes */
		(sizeof (mutex_t) + sizeof (void *) + sizeof (size_t))];
} bucket_t;

#ifdef _SYSCALL32
typedef struct {
	mutex_t		bucket_lock;
	caddr32_t	free_list;
	size32_t	chunks;
	char	pad64[64 -	/* pad out to 64 bytes */
		(sizeof (mutex_t) + sizeof (caddr32_t) + sizeof (size32_t))];
} bucket32_t;
#endif	/* _SYSCALL32 */

#define	NBUCKETS	10	/* sizes ranging from 64 to 32768 */


/*
 * atexit() data structures.
 * See port/gen/atexit.c for details.
 */
typedef void (*_exithdlr_func_t) (void*);

typedef struct _exthdlr {
	struct _exthdlr 	*next;	/* next in handler list */
	_exithdlr_func_t	hdlr;	/* handler itself */
	void			*arg;	/* argument to handler */
	void			*dso;	/* DSO associated with handler */
} _exthdlr_t;

typedef struct {
	mutex_t		exitfns_lock;
	_exthdlr_t	*head;
	/*
	 * exit_frame_monitor is part of a private contract between libc and
	 * the Sun C++ runtime.
	 *
	 * It should be NULL until exit() is called, and thereafter hold the
	 * frame pointer of the function implementing our exit processing.
	 */
	void		*exit_frame_monitor;
	char		exit_pad[64 -	/* pad out to 64 bytes */
		(sizeof (mutex_t) + sizeof (_exthdlr_t *) + sizeof (void *))];
} atexit_root_t;

#ifdef _SYSCALL32
typedef struct {
	mutex_t		exitfns_lock;
	caddr32_t	head;
	caddr32_t	exit_frame_monitor;
	char		exit_pad[64 -	/* pad out to 64 bytes */
		(sizeof (mutex_t) + sizeof (caddr32_t) + sizeof (caddr32_t))];
} atexit_root32_t;
#endif	/* _SYSCALL32 */


/*
 * This is data that is global to all link maps (uberdata, aka super-global).
 * Note: When changing this, please be sure to keep the 32-bit variant of
 * this in sync.  (see uberdata32_t below)
 */
typedef struct uberdata {
	pad_lock_t	_link_lock;
	pad_lock_t	_ld_lock;
	pad_lock_t	_fork_lock;
	pad_lock_t	_atfork_lock;
	pad32_lock_t	_callout_lock;
	pad32_lock_t	_tdb_hash_lock;
	tdb_sync_stats_t tdb_hash_lock_stats;
	siguaction_t	siguaction[NSIG];
	bucket_t	bucket[NBUCKETS];
	atexit_root_t	atexit_root;
	tsd_metadata_t	tsd_metadata;
	tls_metadata_t	tls_metadata;
	/*
	 * Every object before this point has size and alignment of 64 bytes.
	 * Don't add any other type of data before this point.
	 */
	char	primary_map;	/* set when primary link map is initialized */
	char	bucket_init;	/* set when bucket[NBUCKETS] is initialized */
	char	pad[2];
	uberflags_t	uberflags;
	queue_head_t	*queue_head;
	thr_hash_table_t *thr_hash_table;
	uint_t		hash_size;	/* # of entries in thr_hash_table[] */
	uint_t		hash_mask;	/* hash_size - 1 */
	ulwp_t	*ulwp_one;	/* main thread */
	ulwp_t	*all_lwps;	/* circular ul_forw/ul_back list of live lwps */
	ulwp_t	*all_zombies;	/* circular ul_forw/ul_back list of zombies */
	int	nthreads;	/* total number of live threads/lwps */
	int	nzombies;	/* total number of zombie threads */
	int	ndaemons;	/* total number of THR_DAEMON threads/lwps */
	pid_t	pid;		/* the current process's pid */
	void	(*sigacthandler)(int, siginfo_t *, void *);
	ulwp_t	*lwp_stacks;
	ulwp_t	*lwp_laststack;
	int	nfreestack;
	int	thread_stack_cache;
	ulwp_t	*ulwp_freelist;
	ulwp_t	*ulwp_lastfree;
	ulwp_t	*ulwp_replace_free;
	ulwp_t	*ulwp_replace_last;
	atfork_t	*atforklist;	/* circular Q for fork handlers */
	robust_t	**robustlocks;	/* table of registered robust locks */
	robust_t	*robustlist;	/* list of registered robust locks */
	char	*progname;	/* the basename of the program, from argv[0] */
	struct uberdata **tdb_bootstrap;
	tdb_t	tdb;		/* thread debug interfaces (for libc_db) */
} uberdata_t;

#define	link_lock	_link_lock.pad_lock
#define	ld_lock		_ld_lock.pad_lock
#define	fork_lock	_fork_lock.pad_lock
#define	atfork_lock	_atfork_lock.pad_lock
#define	callout_lock	_callout_lock.pad_lock
#define	tdb_hash_lock	_tdb_hash_lock.pad_lock

#pragma align 64(__uberdata)
extern	uberdata_t	__uberdata;
extern	uberdata_t	**__tdb_bootstrap;	/* known to libc_db and mdb */
extern	int		primary_link_map;

#define	ulwp_mutex(ulwp, udp)	\
	(&(udp)->thr_hash_table[(ulwp)->ul_ix].hash_lock)
#define	ulwp_condvar(ulwp, udp)	\
	(&(udp)->thr_hash_table[(ulwp)->ul_ix].hash_cond)

/*
 * Grab and release the hash table lock for the specified lwp.
 */
#define	ulwp_lock(ulwp, udp)	lmutex_lock(ulwp_mutex(ulwp, udp))
#define	ulwp_unlock(ulwp, udp)	lmutex_unlock(ulwp_mutex(ulwp, udp))

#ifdef _SYSCALL32	/* needed by libc_db */

typedef struct ulwp32 {
#if defined(__sparc)
	uint32_t	ul_dinstr;	/* scratch space for dtrace */
	uint32_t	ul_padsparc0[15];
	uint32_t	ul_dsave;	/* dtrace: save %g1, %g0, %sp */
	uint32_t	ul_drestore;	/* dtrace: restore %g0, %g0, %g0 */
	uint32_t	ul_dftret;	/* dtrace: return probe fasttrap */
	uint32_t	ul_dreturn;	/* dtrace: return %o0 */
#endif
	caddr32_t	ul_self;	/* pointer to self */
#if defined(__x86)
	uint8_t		ul_dinstr[40];	/* scratch space for dtrace */
#endif
	caddr32_t	ul_uberdata;	/* uber (super-global) data */
	tls32_t		ul_tls;		/* dynamic thread-local storage base */
	caddr32_t	ul_forw;	/* forw, back all_lwps list, */
	caddr32_t	ul_back;	/* protected by link_lock */
	caddr32_t	ul_next;	/* list to keep track of stacks */
	caddr32_t	ul_hash;	/* hash chain linked list */
	caddr32_t	ul_rval;	/* return value from thr_exit() */
	caddr32_t	ul_stk;		/* mapping base of the stack */
	size32_t	ul_mapsiz;	/* mapping size of the stack */
	size32_t	ul_guardsize;	/* normally _lpagesize */
	caddr32_t	ul_stktop;	/* broken thr_stksegment() interface */
	size32_t	ul_stksiz;	/* broken thr_stksegment() interface */
	stack32_t	ul_ustack;	/* current stack boundaries */
	int		ul_ix;		/* hash index */
	lwpid_t		ul_lwpid;	/* thread id, aka the lwp id */
	pri_t		ul_pri;		/* scheduling priority */
	pri_t		ul_epri;	/* real-time ceiling priority */
	char		ul_policy;	/* scheduling policy */
	char		ul_cid;		/* scheduling class id */
	union {
		struct {
			char	cursig;	/* deferred signal number */
			char	pleasestop; /* lwp requested to stop itself */
		} s;
		short	curplease;	/* for testing both at once */
	} ul_cp;
	char		ul_stop;	/* reason for stopping */
	char		ul_signalled;	/* this lwp was cond_signal()d */
	char		ul_dead;	/* this lwp has called thr_exit */
	char		ul_unwind;	/* posix: unwind C++ stack */
	char		ul_detached;	/* THR_DETACHED at thread_create() */
					/* or pthread_detach() was called */
	char		ul_writer;	/* sleeping in rw_wrlock() */
	char		ul_stopping;	/* set by curthread: stopping self */
	char		ul_cancel_prologue;	/* for _cancel_prologue() */
	short		ul_preempt;	/* no_preempt()/preempt() */
	short		ul_savpreempt;	/* pre-existing preempt value */
	char		ul_sigsuspend;	/* thread is in sigsuspend/pollsys */
	char		ul_main;	/* thread is the main thread */
	char		ul_fork;	/* thread is performing a fork */
	char		ul_primarymap;	/* primary link-map is initialized */
	/* per-thread copies of the corresponding global variables */
	uint8_t		ul_max_spinners;	/* thread_max_spinners */
	char		ul_door_noreserve;	/* thread_door_noreserve */
	char		ul_queue_fifo;		/* thread_queue_fifo */
	char		ul_cond_wait_defer;	/* thread_cond_wait_defer */
	char		ul_error_detection;	/* thread_error_detection */
	char		ul_async_safe;		/* thread_async_safe */
	char		ul_rt;			/* found on an RT queue */
	char		ul_rtqueued;		/* was RT when queued */
	char		ul_misaligned;		/* thread_locks_misaligned */
	char		ul_pad[3];
	int		ul_adaptive_spin;	/* thread_adaptive_spin */
	int		ul_queue_spin;		/* thread_queue_spin */
	int		ul_critical;	/* non-zero == in a critical region */
	int		ul_sigdefer;	/* non-zero == defer signals */
	int		ul_vfork;	/* thread is the child of vfork() */
	int		ul_cancelable;	/* _cancelon()/_canceloff() */
	char		ul_cancel_pending;  /* pthread_cancel() was called */
	char		ul_cancel_disabled; /* PTHREAD_CANCEL_DISABLE */
	char		ul_cancel_async;    /* PTHREAD_CANCEL_ASYNCHRONOUS */
	char		ul_save_async;	/* saved copy of ul_cancel_async */
	char		ul_mutator;	/* lwp is a mutator (java interface) */
	char		ul_created;	/* created suspended */
	char		ul_replace;	/* replacement; must be free()d */
	uchar_t		ul_nocancel;	/* cancellation can't happen */
	int		ul_errno;	/* per-thread errno */
	caddr32_t	ul_errnop;	/* pointer to errno or self->ul_errno */
	caddr32_t	ul_clnup_hdr;	/* head of cleanup handlers list */
	caddr32_t	ul_schedctl_called; /* ul_schedctl is set up */
	caddr32_t	ul_schedctl;	/* schedctl data */
	int		ul_bindflags;	/* bind_guard() interface to ld.so.1 */
	uint_t		ul_libc_locks;	/* count of cancel_safe_mutex_lock()s */
	caddr32_t	ul_stsd;	/* slow TLS for keys >= TSD_NFAST */
	caddr32_t	ul_ftsd[TSD_NFAST]; /* fast TLS for keys < TSD_NFAST */
	td_evbuf32_t	ul_td_evbuf;	/* event buffer */
	char		ul_td_events_enable;	/* event mechanism enabled */
	char		ul_sync_obj_reg;	/* tdb_sync_obj_register() */
	char		ul_qtype;	/* MX or CV */
	char		ul_cv_wake;	/* != 0: just wake up, don't requeue */
	int		ul_rtld;	/* thread is running inside ld.so.1 */
	int		ul_usropts;	/* flags given to thr_create() */
	caddr32_t	ul_startpc;	/* start func (thr_create()) */
	caddr32_t	ul_startarg;	/* argument for start function */
	caddr32_t	ul_wchan;	/* synch object when sleeping */
	caddr32_t	ul_link;	/* sleep queue link */
	caddr32_t	ul_sleepq;	/* sleep queue thread is waiting on */
	caddr32_t	ul_cvmutex;	/* mutex dropped when waiting on a cv */
	caddr32_t	ul_mxchain;	/* chain of owned ceiling mutexes */
	int		ul_save_state;	/* bind_guard() interface to ld.so.1 */
	uint_t		ul_rdlockcnt;	/* # entries in ul_readlock array */
				/* 0 means there is but a single entry */
	union {				/* single entry or pointer to array */
		readlock32_t	single;
		caddr32_t	array;
	} ul_readlock;
	uint_t		ul_heldlockcnt;	/* # entries in ul_heldlocks array */
				/* 0 means there is but a single entry */
	union {				/* single entry or pointer to array */
		caddr32_t	single;
		caddr32_t	array;
	} ul_heldlocks;
	/* PROBE_SUPPORT begin */
	caddr32_t	ul_tpdp;
	/* PROBE_SUPPORT end */
	caddr32_t	ul_siglink;	/* pointer to previous context */
	uint_t		ul_spin_lock_spin;	/* spin lock statistics */
	uint_t		ul_spin_lock_spin2;
	uint_t		ul_spin_lock_sleep;
	uint_t		ul_spin_lock_wakeup;
	queue_root32_t	ul_queue_root;	/* root of a sleep queue */
	id_t		ul_rtclassid;	/* real-time class id */
	uint_t		ul_pilocks;	/* count of PI locks held */
		/* the following members *must* be last in the structure */
		/* they are discarded when ulwp is replaced on thr_exit() */
	sigset_t	ul_sigmask;	/* thread's current signal mask */
	sigset_t	ul_tmpmask;	/* signal mask for sigsuspend/pollsys */
	siginfo32_t	ul_siginfo;	/* deferred siginfo */
	mutex_t		ul_spinlock;	/* used when suspending/continuing */
	fpuenv32_t	ul_fpuenv;	/* floating point state */
	caddr32_t	ul_sp;		/* stack pointer when blocked */
#if defined(sparc)
	caddr32_t	ul_unwind_ret;	/* used only by _ex_clnup_handler() */
#endif
} ulwp32_t;

#define	REPLACEMENT_SIZE32	((size_t)&((ulwp32_t *)NULL)->ul_sigmask)

typedef struct uberdata32 {
	pad_lock_t	_link_lock;
	pad_lock_t	_ld_lock;
	pad_lock_t	_fork_lock;
	pad_lock_t	_atfork_lock;
	pad32_lock_t	_callout_lock;
	pad32_lock_t	_tdb_hash_lock;
	tdb_sync_stats_t tdb_hash_lock_stats;
	siguaction32_t	siguaction[NSIG];
	bucket32_t	bucket[NBUCKETS];
	atexit_root32_t	atexit_root;
	tsd_metadata32_t tsd_metadata;
	tls_metadata32_t tls_metadata;
	char		primary_map;
	char		bucket_init;
	char		pad[2];
	uberflags_t	uberflags;
	caddr32_t	queue_head;
	caddr32_t	thr_hash_table;
	uint_t		hash_size;
	uint_t		hash_mask;
	caddr32_t	ulwp_one;
	caddr32_t	all_lwps;
	caddr32_t	all_zombies;
	int		nthreads;
	int		nzombies;
	int		ndaemons;
	int		pid;
	caddr32_t	sigacthandler;
	caddr32_t	lwp_stacks;
	caddr32_t	lwp_laststack;
	int		nfreestack;
	int		thread_stack_cache;
	caddr32_t	ulwp_freelist;
	caddr32_t	ulwp_lastfree;
	caddr32_t	ulwp_replace_free;
	caddr32_t	ulwp_replace_last;
	caddr32_t	atforklist;
	caddr32_t	robustlocks;
	caddr32_t	robustlist;
	caddr32_t	progname;
	caddr32_t	tdb_bootstrap;
	tdb32_t		tdb;
} uberdata32_t;

#endif	/* _SYSCALL32 */

/* ul_stop values */
#define	TSTP_REGULAR	0x01	/* Stopped by thr_suspend() */
#define	TSTP_MUTATOR	0x08	/* stopped by thr_suspend_*mutator*() */
#define	TSTP_FORK	0x20	/* stopped by suspend_fork() */

/*
 * Implementation-specific attribute types for pthread_mutexattr_init() etc.
 */

typedef	struct	_cvattr {
	int	pshared;
	clockid_t clockid;
} cvattr_t;

typedef	struct	_mattr {
	int	pshared;
	int	protocol;
	int	prioceiling;
	int	type;
	int	robustness;
} mattr_t;

typedef	struct	_thrattr {
	size_t	stksize;
	void	*stkaddr;
	int	detachstate;
	int	daemonstate;
	int	scope;
	int	prio;
	int	policy;
	int	inherit;
	size_t	guardsize;
} thrattr_t;

typedef	struct	_rwlattr {
	int	pshared;
} rwlattr_t;

/* _curthread() is inline for speed */
extern	ulwp_t		*_curthread(void);
#define	curthread	(_curthread())

/* this version (also inline) can be tested for NULL */
extern	ulwp_t		*__curthread(void);

/* get the current stack pointer (also inline) */
extern	greg_t		stkptr(void);

/*
 * Suppress __attribute__((...)) if we are not compiling with gcc
 */
#if !defined(__GNUC__)
#define	__attribute__(string)
#endif

/* Fetch the dispatch (kernel) priority of a thread */
#define	real_priority(ulwp)	\
	((ulwp)->ul_schedctl? (ulwp)->ul_schedctl->sc_priority : 0)

/*
 * Implementation functions.  Not visible outside of the library itself.
 */
extern	int	__nanosleep(const timespec_t *, timespec_t *);
extern	void	getgregs(ulwp_t *, gregset_t);
extern	void	setgregs(ulwp_t *, gregset_t);
extern	void	thr_panic(const char *);
#pragma rarely_called(thr_panic)
extern	ulwp_t	*find_lwp(thread_t);
extern	void	finish_init(void);
extern	void	update_sched(ulwp_t *);
extern	void	queue_alloc(void);
extern	void	tsd_exit(void);
extern	void	tsd_free(ulwp_t *);
extern	void	tls_setup(void);
extern	void	tls_exit(void);
extern	void	tls_free(ulwp_t *);
extern	void	rwl_free(ulwp_t *);
extern	void	heldlock_exit(void);
extern	void	heldlock_free(ulwp_t *);
extern	void	sigacthandler(int, siginfo_t *, void *);
extern	void	signal_init(void);
extern	int	sigequalset(const sigset_t *, const sigset_t *);
extern	void	mutex_setup(void);
extern	void	take_deferred_signal(int);
extern	void	*setup_top_frame(void *, size_t, ulwp_t *);
extern	int	setup_context(ucontext_t *, void *(*func)(ulwp_t *),
			ulwp_t *ulwp, caddr_t stk, size_t stksize);
extern	volatile sc_shared_t *setup_schedctl(void);
extern	void	*lmalloc(size_t);
extern	void	lfree(void *, size_t);
extern	void	*libc_malloc(size_t);
extern	void	*libc_realloc(void *, size_t);
extern	void	libc_free(void *);
extern	char	*libc_strdup(const char *);
extern	void	ultos(uint64_t, int, char *);
extern	void	lock_error(const mutex_t *, const char *, void *, const char *);
extern	void	rwlock_error(const rwlock_t *, const char *, const char *);
extern	void	thread_error(const char *);
extern	void	grab_assert_lock(void);
extern	void	dump_queue_statistics(void);
extern	void	collect_queue_statistics(void);
extern	void	record_spin_locks(ulwp_t *);
extern	void	remember_lock(mutex_t *);
extern	void	forget_lock(mutex_t *);
extern	void	register_lock(mutex_t *);
extern	void	unregister_locks(void);
#if defined(__sparc)
extern	void	_flush_windows(void);
#else
#define	_flush_windows()
#endif
extern	void	set_curthread(void *);

/*
 * Utility function used when waking up many threads (more than MAXLWPS)
 * all at once.  See mutex_wakeup_all(), cond_broadcast(), and rw_unlock().
 */
#define	MAXLWPS	128	/* max remembered lwpids before overflow */
#define	NEWLWPS	2048	/* max remembered lwpids at first overflow */
extern	lwpid_t	*alloc_lwpids(lwpid_t *, int *, int *);

/* enter a critical section */
#define	enter_critical(self)	(self->ul_critical++)

/* exit a critical section, take deferred actions if necessary */
extern	void	do_exit_critical(void);
#define	exit_critical(self)					\
	(void) (self->ul_critical--,				\
	    ((self->ul_curplease && self->ul_critical == 0)?	\
	    (do_exit_critical(), 0) : 0))

/*
 * Like enter_critical()/exit_critical() but just for deferring signals.
 * Unlike enter_critical()/exit_critical(), ul_sigdefer may be set while
 * calling application functions like constructors and destructors.
 * Care must be taken if the application function attempts to set
 * the signal mask while a deferred signal is present; the setting
 * of the signal mask must also be deferred.
 */
#define	sigoff(self)	(self->ul_sigdefer++)
#define	sigon(self)						\
	(void) ((--self->ul_sigdefer == 0 &&			\
	    self->ul_curplease && self->ul_critical == 0)?	\
	    (do_exit_critical(), 0) : 0)

/* these are exported functions */
extern	void	_sigoff(void);
extern	void	_sigon(void);

#define	sigorset(s1, s2)				\
	(((s1)->__sigbits[0] |= (s2)->__sigbits[0]),	\
	((s1)->__sigbits[1] |= (s2)->__sigbits[1]),	\
	((s1)->__sigbits[2] |= (s2)->__sigbits[2]),	\
	((s1)->__sigbits[3] |= (s2)->__sigbits[3]))

#define	sigandset(s1, s2)				\
	(((s1)->__sigbits[0] &= (s2)->__sigbits[0]),	\
	((s1)->__sigbits[1] &= (s2)->__sigbits[1]),	\
	((s1)->__sigbits[2] &= (s2)->__sigbits[2]),	\
	((s1)->__sigbits[3] &= (s2)->__sigbits[3]))

#define	sigdiffset(s1, s2)				\
	(((s1)->__sigbits[0] &= ~(s2)->__sigbits[0]),	\
	((s1)->__sigbits[1] &= ~(s2)->__sigbits[1]),	\
	((s1)->__sigbits[2] &= ~(s2)->__sigbits[2]),	\
	((s1)->__sigbits[3] &= ~(s2)->__sigbits[3]))

#define	delete_reserved_signals(s)			\
	(((s)->__sigbits[0] &= MASKSET0),		\
	((s)->__sigbits[1] &= (MASKSET1 & ~SIGMASK(SIGCANCEL))),\
	((s)->__sigbits[2] &= MASKSET2),		\
	((s)->__sigbits[3] &= MASKSET3))

extern	void	block_all_signals(ulwp_t *self);

/*
 * When restoring the signal mask after having previously called
 * block_all_signals(), if we have a deferred signal present then
 * do nothing other than ASSERT() that we are in a critical region.
 * The signal mask will be set when we emerge from the critical region
 * and call take_deferred_signal().  There is no race condition here
 * because the kernel currently has all signals blocked for this thread.
 */
#define	restore_signals(self)						\
	((void) ((self)->ul_cursig?					\
	(ASSERT((self)->ul_critical + (self)->ul_sigdefer != 0), 0) :	\
	__lwp_sigmask(SIG_SETMASK, &(self)->ul_sigmask)))

extern	void	set_cancel_pending_flag(ulwp_t *, int);
extern	void	set_cancel_eintr_flag(ulwp_t *);
extern	void	set_parking_flag(ulwp_t *, int);
extern	int	cancel_active(void);

extern	void	*_thrp_setup(ulwp_t *);
extern	void	_fpinherit(ulwp_t *);
extern	void	_lwp_start(void);
extern	void	_lwp_terminate(void);
extern	void	lmutex_lock(mutex_t *);
extern	void	lmutex_unlock(mutex_t *);
extern	void	lrw_rdlock(rwlock_t *);
extern	void	lrw_wrlock(rwlock_t *);
extern	void	lrw_unlock(rwlock_t *);
extern	void	sig_mutex_lock(mutex_t *);
extern	void	sig_mutex_unlock(mutex_t *);
extern	int	sig_mutex_trylock(mutex_t *);
extern	int	sig_cond_wait(cond_t *, mutex_t *);
extern	int	sig_cond_reltimedwait(cond_t *, mutex_t *, const timespec_t *);
extern	void	cancel_safe_mutex_lock(mutex_t *);
extern	void	cancel_safe_mutex_unlock(mutex_t *);
extern	int	cancel_safe_mutex_trylock(mutex_t *);
extern	void	_prefork_handler(void);
extern	void	_postfork_parent_handler(void);
extern	void	_postfork_child_handler(void);
extern	void	postfork1_child(void);
extern	void	postfork1_child_aio(void);
extern	void	postfork1_child_sigev_aio(void);
extern	void	postfork1_child_sigev_mq(void);
extern	void	postfork1_child_sigev_timer(void);
extern	void	postfork1_child_tpool(void);
extern	void	fork_lock_enter(void);
extern	void	fork_lock_exit(void);
extern	void	suspend_fork(void);
extern	void	continue_fork(int);
extern	void	do_sigcancel(void);
extern	void	setup_cancelsig(int);
extern	void	init_sigev_thread(void);
extern	void	init_aio(void);
extern	void	init_progname(void);
extern	void	_cancelon(void);
extern	void	_canceloff(void);
extern	void	_canceloff_nocancel(void);
extern	void	_cancel_prologue(void);
extern	void	_cancel_epilogue(void);
extern	void	no_preempt(ulwp_t *);
extern	void	preempt(ulwp_t *);
extern	void	_thrp_unwind(void *);

extern	pid_t	__forkx(int);
extern	pid_t	__forkallx(int);
extern	int	__open(const char *, int, mode_t);
extern	int	__open64(const char *, int, mode_t);
extern	int	__openat(int, const char *, int, mode_t);
extern	int	__openat64(int, const char *, int, mode_t);
extern	int	__close(int);
extern	ssize_t	__read(int, void *, size_t);
extern	ssize_t	__write(int, const void *, size_t);
extern	int	__fcntl(int, int, ...);
extern	int	__lwp_continue(lwpid_t);
extern	int	__lwp_create(ucontext_t *, uint_t, lwpid_t *);
extern	int	___lwp_suspend(lwpid_t);
extern	int	lwp_wait(lwpid_t, lwpid_t *);
extern	int	__lwp_wait(lwpid_t, lwpid_t *);
extern	int	__lwp_detach(lwpid_t);
extern	sc_shared_t *__schedctl(void);

/* actual system call traps */
extern	int	__setcontext(const ucontext_t *);
extern	int	__getcontext(ucontext_t *);
extern	int	__clock_gettime(clockid_t, timespec_t *);
extern	void	abstime_to_reltime(clockid_t, const timespec_t *, timespec_t *);
extern	void	hrt2ts(hrtime_t, timespec_t *);

extern	int	__sigaction(int, const struct sigaction *, struct sigaction *);
extern	int	__sigprocmask(int, const sigset_t *, sigset_t *);
extern	int	__lwp_sigmask(int, const sigset_t *);
extern	void	__sighndlr(int, siginfo_t *, ucontext_t *, void (*)());
extern	caddr_t	__sighndlrend;
#pragma unknown_control_flow(__sighndlr)

/* belongs in <pthread.h> */
#define	PTHREAD_CREATE_DAEMON_NP	0x100	/* = THR_DAEMON */
#define	PTHREAD_CREATE_NONDAEMON_NP	0
extern	int	pthread_attr_setdaemonstate_np(pthread_attr_t *, int);
extern	int	pthread_attr_getdaemonstate_np(const pthread_attr_t *, int *);

extern	int	mutex_held(mutex_t *);
extern	int	mutex_lock_internal(mutex_t *, timespec_t *, int);
extern	int	mutex_unlock_internal(mutex_t *, int);

/* not cancellation points: */
extern	int	__cond_wait(cond_t *, mutex_t *);
extern	int	__cond_timedwait(cond_t *, mutex_t *, const timespec_t *);
extern	int	__cond_reltimedwait(cond_t *, mutex_t *, const timespec_t *);

extern	int	rw_read_held(rwlock_t *);
extern	int	rw_write_held(rwlock_t *);

extern	int	_thrp_create(void *, size_t, void *(*)(void *), void *, long,
			thread_t *, size_t);
extern	int	_thrp_suspend(thread_t, uchar_t);
extern	int	_thrp_continue(thread_t, uchar_t);

extern	void	_thrp_terminate(void *);
extern	void	_thrp_exit(void);

extern	const pcclass_t *get_info_by_class(id_t);
extern	const pcclass_t *get_info_by_policy(int);
extern	const thrattr_t *def_thrattr(void);
extern	id_t	setparam(idtype_t, id_t, int, int);
extern	id_t	setprio(idtype_t, id_t, int, int *);
extern	id_t	getparam(idtype_t, id_t, int *, struct sched_param *);

/*
 * System call wrappers (direct interfaces to the kernel)
 */
extern	int	___lwp_mutex_register(mutex_t *, mutex_t **);
extern	int	___lwp_mutex_trylock(mutex_t *, ulwp_t *);
extern	int	___lwp_mutex_timedlock(mutex_t *, timespec_t *, ulwp_t *);
extern	int	___lwp_mutex_unlock(mutex_t *);
extern	int	___lwp_mutex_wakeup(mutex_t *, int);
extern	int	___lwp_cond_wait(cond_t *, mutex_t *, timespec_t *, int);
extern	int	___lwp_sema_timedwait(lwp_sema_t *, timespec_t *, int);
extern	int	__lwp_rwlock_rdlock(rwlock_t *, timespec_t *);
extern	int	__lwp_rwlock_wrlock(rwlock_t *, timespec_t *);
extern	int	__lwp_rwlock_tryrdlock(rwlock_t *);
extern	int	__lwp_rwlock_trywrlock(rwlock_t *);
extern	int	__lwp_rwlock_unlock(rwlock_t *);
extern	int	__lwp_park(timespec_t *, lwpid_t);
extern	int	__lwp_unpark(lwpid_t);
extern	int	__lwp_unpark_all(lwpid_t *, int);
#if defined(__x86)
extern	int	___lwp_private(int, int, void *);
#endif	/* __x86 */

/*
 * inlines
 */
extern	int		set_lock_byte(volatile uint8_t *);
extern	uint32_t	atomic_swap_32(volatile uint32_t *, uint32_t);
extern	uint32_t	atomic_cas_32(volatile uint32_t *, uint32_t, uint32_t);
extern	void		atomic_inc_32(volatile uint32_t *);
extern	void		atomic_dec_32(volatile uint32_t *);
extern	void		atomic_and_32(volatile uint32_t *, uint32_t);
extern	void		atomic_or_32(volatile uint32_t *, uint32_t);
#if defined(__sparc)
extern	ulong_t		caller(void);
extern	ulong_t		getfp(void);
#endif	/* __sparc */

#include "thr_inlines.h"

#endif	/* _THR_UBERDATA_H */
