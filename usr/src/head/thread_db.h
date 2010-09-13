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
 */

#ifndef _THREAD_DB_H
#define	_THREAD_DB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 *  Description:
 *	Types, global variables, and function definitions for users
 *	of libc_db (formerly libthread_db).
 *
 */


#include <sys/lwp.h>
#include <sys/procfs_isa.h>
#include <thread.h>
#include <proc_service.h>

#ifdef __cplusplus
extern "C" {
#endif

#define		TD_THR_ANY_USER_FLAGS	0xffffffff
#define		TD_THR_LOWEST_PRIORITY	-128
#define		TD_SIGNO_MASK 0
#define		TD_EVENTSIZE 2

/*
 * Opaque handle types.
 */

/* Client's handle for a process */
struct ps_prochandle;

/* libthread's handle for a process */
typedef struct td_thragent td_thragent_t;

/* The thread handle. */
typedef struct td_thrhandle {
	td_thragent_t	*th_ta_p;
	psaddr_t	th_unique;
} td_thrhandle_t;

/* The handle for a synchronization object. */
typedef struct td_synchandle {
	td_thragent_t	*sh_ta_p;
	psaddr_t	sh_unique;
} td_synchandle_t;

/* ------------------------------------------------------------------ */

/*
 * The libc_db event facility.
 */
#define	BT_UISHIFT	5 /* log base 2 of BT_NBIPUI, to extract word index */
#define	BT_NBIPUI	(1 << BT_UISHIFT)	/* n bits per uint */
#define	BT_UIMASK	(BT_NBIPUI - 1)		/* to extract bit index */

/* Bitmask of enabled events. */
typedef struct td_thr_events {
	uint_t	event_bits[TD_EVENTSIZE];
} td_thr_events_t;

/* Event set manipulation macros. */
#define	__td_eventmask(n)	((unsigned int)1 << (((n) - 1)	\
				    & (BT_NBIPUI - 1)))
#define	__td_eventword(n)	(((unsigned int)((n) - 1))>>5)

#define	td_event_emptyset(setp)				\
	{								\
		int _i_; 						\
		_i_ = TD_EVENTSIZE;					\
		while (_i_) (setp)->event_bits[--_i_] = 0;	\
	}

#define	td_event_fillset(setp)				\
	{								\
		int _i_;						\
		_i_ = TD_EVENTSIZE;					\
		while (_i_) (setp)->event_bits[--_i_] =	\
			0xffffffff;				\
	}

#define	td_event_addset(setp, n)			\
	(((setp)->event_bits[__td_eventword(n)]) |= __td_eventmask(n))
#define	td_event_delset(setp, n)			\
	(((setp)->event_bits[__td_eventword(n)]) &= ~__td_eventmask(n))
#define	td_eventismember(setp, n)		\
	(__td_eventmask(n) & ((setp)->event_bits[__td_eventword(n)]))
#define	td_eventisempty(setp)			\
	(!((setp)->event_bits[0]) && !((setp)->event_bits[1]))

typedef enum {
	TD_ALL_EVENTS,	/* pseudo-event number */
	TD_EVENT_NONE = TD_ALL_EVENTS,	/* depends on context */
	TD_READY,
	TD_SLEEP,
	TD_SWITCHTO,
	TD_SWITCHFROM,
	TD_LOCK_TRY,
	TD_CATCHSIG,
	TD_IDLE,
	TD_CREATE,
	TD_DEATH,
	TD_PREEMPT,
	TD_PRI_INHERIT,
	TD_REAP,
	TD_CONCURRENCY,
	TD_TIMEOUT,
	TD_MIN_EVENT_NUM = TD_READY,
	TD_MAX_EVENT_NUM = TD_TIMEOUT,
	TD_EVENTS_ENABLE = 31		/* Event reporting enabled */
} td_event_e;

/*
 *   Ways that an event type can be reported.
 */
typedef enum {
	NOTIFY_BPT,
				/*
				 * bpt to be inserted at u.bptaddr by
				 * debugger
				 */
	NOTIFY_AUTOBPT,		/* bpt inserted at u.bptaddr by application */
	NOTIFY_SYSCALL		/* syscall u.syscallno will be invoked */
} td_notify_e;

/*
 * How an event type is reported.
 */
typedef struct td_notify {
	td_notify_e	type;
	union {
		psaddr_t	bptaddr;
		int		syscallno;
	} u;
} td_notify_t;

/*
 * An event message.
 */
typedef struct td_event_msg {
	td_event_e event;		/* Event type being reported */
	const td_thrhandle_t *th_p;	/* Thread reporting the event */
	union {				/* Type-dependent event data */
		td_synchandle_t *sh;	/* historical rubbish; ignore */
		uintptr_t	data;	/* valid, depending on event type */
	} msg;
} td_event_msg_t;

/* --------------------------------------------------------------------- */

/*
 * Thread information structure as returned by td_thr_get_info(), and
 * related types.
 */

/*
 * Possible thread states.  TD_THR_ANY_STATE is a pseudo-state used
 * to select threads regardless of state in td_ta_thr_iter().
 */
typedef enum {
	TD_THR_ANY_STATE,
	TD_THR_UNKNOWN,
	TD_THR_STOPPED,
	TD_THR_RUN,
	TD_THR_ACTIVE,
	TD_THR_ZOMBIE,
	TD_THR_SLEEP,
	TD_THR_STOPPED_ASLEEP
} td_thr_state_e;

/*
 * Thread type: user or system.
 * As of Solaris 9, all threads are type TD_THR_USER.
 */
typedef enum {
	TD_THR_ANY_TYPE,	/* not used */
	TD_THR_USER,
	TD_THR_SYSTEM
} td_thr_type_e;

typedef struct td_thrinfo {
	td_thragent_t	*ti_ta_p;	/* process handle */
	unsigned	ti_user_flags;	/* flags passed to thr_create() */
	thread_t	ti_tid;		/* tid returned by thr_create() */
	void		*ti_exitval;	/* thread exit value (TD_THR_ZOMBIE) */
	psaddr_t	ti_startfunc;	/* startfunc passed to thr_create() */
	psaddr_t	ti_stkbase;	/* base of thread's stack */
	long		ti_stksize;	/* size of thread's stack */
	psaddr_t	ti_ro_area;	/* address of uthread_t struct */
	int		ti_ro_size;	/* size of uthread_t struct */
	td_thr_state_e	ti_state;	/* thread state */
	uchar_t		ti_db_suspended; /* boolean:  suspended by debugger? */
	td_thr_type_e	ti_type;	/* thread type */
	intptr_t	ti_pc;		/* resume PC when sleeping */
	intptr_t	ti_sp;		/* resume SP when sleeping */
	short		ti_flags;	/* flags used by libthread */
	int		ti_pri;		/* thread priority */
	lwpid_t		ti_lid;		/* last LWP assigned to this thread */
	sigset_t	ti_sigmask;	/* signal mask */
	uchar_t		ti_traceme;	/* event reporting enabled? */
	uchar_t		ti_preemptflag;	/* was thread preemppted? */
	uchar_t		ti_pirecflag;	/* priority inheritance happened */
	sigset_t	ti_pending;	/* set of pending signals */
	td_thr_events_t ti_events;	/* set of enabled events */
} td_thrinfo_t;

#define	ti_tls	ti_exitval	/* for source compatibility */

typedef struct td_ta_stats {
	int	nthreads;	/* total number of threads in use */
	int	r_concurrency;	/* requested concurrency level */
	int	nrunnable_num;	/* numerator, avg. runnable threads */
	int	nrunnable_den;	/* denominator, avg. runnable threads */
	int	a_concurrency_num; /* numerator, achieved concurrency level */
	int	a_concurrency_den; /* denominator,  concurrency level */
	int	nlwps_num;	/* numerator, average number of LWP's in use */
	int	nlwps_den;	/* denom., average number of LWP's in use */
	int	nidle_num;	/* numerator, avg. number of idling LWP's */
	int	nidle_den;	/* denom., avg. number of idling LWP's */
} td_ta_stats_t;

/*
 * Iterator callback function declarations.
 */

/* Callback function for td_ta_tsd_iter(). */
typedef int	td_key_iter_f(thread_key_t, void (*destructor)(), void *);

/* Callback function for td_ta_thr_iter(). */
typedef int	td_thr_iter_f(const td_thrhandle_t *, void *);

/* Callback function for td_ta_sync_iter(). */
typedef int	td_sync_iter_f(const td_synchandle_t *, void *);

/* -------------------------------------------------------------------- */

/*
 * Synchronization Objects
 */

/* Enumeration of synchronization object types. */
typedef enum td_sync_type_e {
	TD_SYNC_UNKNOWN,	/* Sync. variable of unknown type  */
	TD_SYNC_COND,		/* Condition variable  */
	TD_SYNC_MUTEX,		/* Mutex lock  */
	TD_SYNC_SEMA,		/* Semaphore  */
	TD_SYNC_RWLOCK		/* Reader/Writer lock  */
} td_sync_type_e;

#define	TD_SV_MAX_FLAGS 4
typedef uint8_t td_sync_flags_t;

/*
 * Synchronization object information structure filled in by td_sync_get_info()
 */
typedef struct td_syncinfo {
	td_thragent_t	*si_ta_p;	/* process handle */
	psaddr_t	si_sv_addr;	/* address of sync. object */
	td_sync_type_e	si_type;	/* object type */
	uint32_t	si_shared_type;	/* process-shared or process-private */
	td_sync_flags_t	si_flags[TD_SV_MAX_FLAGS];	/* flags (?) */
	pid_t		si_ownerpid;	/* owner's process-id (USYNC_PROCESS) */
	union _si_un_state {
		int	sem_count;	/* semaphore count */
		int	nreaders;	/* number of readers, -1 if writer */
		int	mutex_locked;	/* non-zero iff locked */
	} si_state;
	int		si_size;	/* size in bytes of synch variable */
	uint8_t		si_has_waiters;	/* non-zero iff at least one waiter */
	uint8_t		si_is_wlock;	/* non-zero iff rwlock write-locked */
	uint8_t		si_rcount;	/* count for locked recursive mutex */
	uint8_t		si_prioceiling;	/* ceiling pri (PTHREAD_PRIO_PROTECT) */
	td_thrhandle_t	si_owner;	/* mutex holder or write-lock holder */
	psaddr_t	si_data;	/* optional data */
} td_syncinfo_t;

/*
 * Statistics structures for the various synchronization objects, contained
 * within the td_syncstats structure returned by td_sync_get_stats().
 */
typedef struct {
	uint_t		mutex_lock;
	uint_t		mutex_sleep;
	hrtime_t	mutex_sleep_time;
	hrtime_t	mutex_hold_time;
	uint_t		mutex_try;
	uint_t		mutex_try_fail;
	uint_t		mutex_internal;		/* internal to libthread */
} td_mutex_stats_t;

typedef struct {
	uint_t		cond_wait;
	uint_t		cond_timedwait;
	hrtime_t	cond_wait_sleep_time;
	hrtime_t	cond_timedwait_sleep_time;
	uint_t		cond_timedwait_timeout;
	uint_t		cond_signal;
	uint_t		cond_broadcast;
	uint_t		cond_internal;		/* internal to libthread */
} td_cond_stats_t;

typedef struct {
	uint_t		rw_rdlock;
	uint_t		rw_rdlock_sleep;
	hrtime_t	rw_rdlock_sleep_time;
	uint_t		rw_rdlock_try;
	uint_t		rw_rdlock_try_fail;
	uint_t		rw_wrlock;
	uint_t		rw_wrlock_sleep;
	hrtime_t	rw_wrlock_sleep_time;
	hrtime_t	rw_wrlock_hold_time;
	uint_t		rw_wrlock_try;
	uint_t		rw_wrlock_try_fail;
} td_rwlock_stats_t;

typedef struct {
	uint_t		sema_wait;
	uint_t		sema_wait_sleep;
	hrtime_t	sema_wait_sleep_time;
	uint_t		sema_trywait;
	uint_t		sema_trywait_fail;
	uint_t		sema_post;
	uint_t		sema_max_count;
	uint_t		sema_min_count;
} td_sema_stats_t;

/*
 * Synchronization object statistics structure filled in by td_sync_get_stats()
 */
typedef struct td_syncstats {
	td_syncinfo_t	ss_info;	/* as returned by td_sync_get_info() */
	union {
		td_mutex_stats_t	mutex;
		td_cond_stats_t		cond;
		td_rwlock_stats_t	rwlock;
		td_sema_stats_t		sema;
		uint_t			pad[32];	/* for future growth */
	} ss_un;
} td_syncstats_t;

/* The set of error codes. */
typedef enum {
	TD_OK,		/* generic "call succeeded" */
	TD_ERR,		/* generic error. */
	TD_NOTHR,	/* no thread can be found to satisfy query */
	TD_NOSV,	/* no synch. handle can be found to satisfy query */
	TD_NOLWP,	/* no lwp can be found to satisfy query */
	TD_BADPH,	/* invalid process handle */
	TD_BADTH,	/* invalid thread handle */
	TD_BADSH,	/* invalid synchronization handle */
	TD_BADTA,	/* invalid thread agent */
	TD_BADKEY,	/* invalid key */
	TD_NOMSG,	/* no event message for td_thr_event_getmsg() */
	TD_NOFPREGS,	/* FPU register set not available */
	TD_NOLIBTHREAD,	/* application not linked with libthread */
	TD_NOEVENT,	/* requested event is not supported */
	TD_NOCAPAB,	/* capability not available */
	TD_DBERR,	/* Debugger service failed */
	TD_NOAPLIC,	/* Operation not applicable to */
	TD_NOTSD,	/* No thread-specific data for this thread */
	TD_MALLOC,	/* Malloc failed */
	TD_PARTIALREG,	/* Only part of register set was writen/read */
	TD_NOXREGS,	/* X register set not available for given thread */
	TD_NOTLS,	/* There is no TLS in the specified module */
	TD_TLSDEFER	/* module's TLS not yet allocated by the thread */
}	td_err_e;


/* ----------------------------------------------------------------------- */

/*
 * Exported functions.
 */

/*
 * Initialize the threads debug interface.
 */
td_err_e
td_init(void);

/*
 * A no-op, left for historical reasons.
 */
void
td_log(void);

/*
 * Allocate a new process handle ("thread agent").
 */
td_err_e
td_ta_new(struct ps_prochandle *, td_thragent_t **);

/*
 * De-allocate a process handle, releasing all related resources.
 */
td_err_e
td_ta_delete(td_thragent_t *);

/*
 * Map a process handle to a client process handle.
 */
td_err_e
td_ta_get_ph(const td_thragent_t *, struct ps_prochandle **);

/*
 * Set the process's suggested concurrency level.
 */
td_err_e
td_ta_setconcurrency(const td_thragent_t *, int);

/*
 * Get the number of threads in the process, including zombie threads.
 */
td_err_e
td_ta_get_nthreads(const td_thragent_t *, int *);

/*
 * Map a tid, as returned by thr_create(), to a thread handle.
 */
td_err_e
td_ta_map_id2thr(const td_thragent_t *, thread_t,  td_thrhandle_t *);

/*
 * Map the address of a synchronization object to a sync. object handle.
 */
td_err_e
td_ta_map_addr2sync(const td_thragent_t *, psaddr_t, td_synchandle_t *);

/*
 * Iterate over a process's thread-specific data (TSD) keys.
 */
td_err_e
td_ta_tsd_iter(const td_thragent_t *, td_key_iter_f *, void *);

/*
 * Iterate over a process's threads, including zombie threads.
 */
td_err_e
td_ta_thr_iter(const td_thragent_t *, td_thr_iter_f *, void *,
	td_thr_state_e, int, sigset_t *, unsigned);

/*
 * Iterate over a process's known synchronization objects.
 */
td_err_e
td_ta_sync_iter(const td_thragent_t *, td_sync_iter_f *, void *);

/*
 * Enable/disable process statistics collection.
 */
td_err_e
td_ta_enable_stats(const td_thragent_t *, int);

/*
 * Reset process statistics.
 */
td_err_e
td_ta_reset_stats(const td_thragent_t *);

/*
 * Read process statistics.
 */
td_err_e
td_ta_get_stats(const td_thragent_t *, td_ta_stats_t *);

/*
 * Get thread information.
 */
td_err_e
td_thr_get_info(const td_thrhandle_t *, td_thrinfo_t *);

/*
 * Get the "event address" for an event type.
 */
td_err_e
td_ta_event_addr(const td_thragent_t *, td_event_e, td_notify_t *);

/*
 * Enable/disable event reporting for a thread.
 */
td_err_e
td_thr_event_enable(const td_thrhandle_t *, int);

/*
 * Enable a set of events for a thread.
 */
td_err_e
td_thr_set_event(const td_thrhandle_t *, td_thr_events_t *);

/*
 * Disable a set of events for a thread.
 */
td_err_e
td_thr_clear_event(const td_thrhandle_t *, td_thr_events_t *);

/*
 * Retrieve (and consume) an event message for a thread.
 */
td_err_e
td_thr_event_getmsg(const td_thrhandle_t *, td_event_msg_t *);

/*
 * Enable a set of events in the process.
 */
td_err_e
td_ta_set_event(const td_thragent_t *, td_thr_events_t *);

/*
 * Disable a set of events in the process.
 */
td_err_e
td_ta_clear_event(const td_thragent_t *, td_thr_events_t *);

/*
 * Retrieve (and consume) an event message for some thread in the process.
 */
td_err_e
td_ta_event_getmsg(const td_thragent_t *, td_event_msg_t *);

/*
 * Suspend a thread.
 */
td_err_e
td_thr_dbsuspend(const td_thrhandle_t *);

/*
 * Resume a suspended thread.
 */
td_err_e
td_thr_dbresume(const td_thrhandle_t *);

/*
 * Set a thread's signal mask.
 */
td_err_e
td_thr_sigsetmask(const td_thrhandle_t *, const sigset_t);

/*
 * Set a thread's "signals-pending" set.
 */
td_err_e
td_thr_setsigpending(const td_thrhandle_t *, uchar_t, const sigset_t);

/*
 * Get a thread's general register set.
 */
td_err_e
td_thr_getgregs(const td_thrhandle_t *, prgregset_t);

/*
 * Set a thread's general register set.
 */
td_err_e
td_thr_setgregs(const td_thrhandle_t *, const prgregset_t);

/*
 * Get a thread's floating-point register set.
 */
td_err_e
td_thr_getfpregs(const td_thrhandle_t *, prfpregset_t *);

/*
 * Set a thread's floating-point register set.
 */
td_err_e
td_thr_setfpregs(const td_thrhandle_t *, const prfpregset_t *);

/*
 * Get the size of the extra state register set for this architecture.
 */
td_err_e
td_thr_getxregsize(const td_thrhandle_t *th_p, int *xregsize);

/*
 * Get a thread's extra state register set.
 */
td_err_e
td_thr_getxregs(const td_thrhandle_t *th_p, void *xregs);

/*
 * Set a thread's extra state register set.
 */
td_err_e
td_thr_setxregs(const td_thrhandle_t *th_p, const void *xregs);

/*
 * Validate a thread handle.
 */
td_err_e
td_thr_validate(const td_thrhandle_t *);

/*
 * Get a thread-specific data pointer for a thread.
 */
td_err_e
td_thr_tsd(const td_thrhandle_t *, thread_key_t, void **);

/*
 * Get the base address of a thread's thread local storage (TLS) block
 * for the module (executable or shared object) identified by 'moduleid'.
 */
td_err_e
td_thr_tlsbase(const td_thrhandle_t *, ulong_t moduleid, psaddr_t *base);

/*
 * Set a thread's priority.
 */
td_err_e
td_thr_setprio(const td_thrhandle_t *, int);

/*
 * Iterate over the set of locks owned by a thread.
 */
td_err_e
td_thr_lockowner(const td_thrhandle_t *, td_sync_iter_f *, void *);

/*
 * Return the sync. handle of the object this thread is sleeping on.
 */
td_err_e
td_thr_sleepinfo(const td_thrhandle_t *, td_synchandle_t *);

/*
 * Map an lwpid, as returned by _lwp_create(), to a thread handle.
 */
td_err_e
td_ta_map_lwp2thr(const td_thragent_t *, lwpid_t, td_thrhandle_t *th_p);

/*
 * Enable/disable a process's synchronization object tracking.
 */
td_err_e
td_ta_sync_tracking_enable(const td_thragent_t *, int);

/*
 * Get information about a synchronization object.
 */
td_err_e
td_sync_get_info(const td_synchandle_t *, td_syncinfo_t *);

/*
 * Get statistics for a synchronization object.
 */
td_err_e
td_sync_get_stats(const td_synchandle_t *, td_syncstats_t *);

/*
 * Set the state of a synchronization object.
 */
td_err_e
td_sync_setstate(const td_synchandle_t *, int value);

/*
 * Iterate over all threads blocked on a synchronization object.
 */
td_err_e
td_sync_waiters(const td_synchandle_t *, td_thr_iter_f *, void *);

#ifdef __cplusplus
}
#endif

#endif	/* _THREAD_DB_H */
