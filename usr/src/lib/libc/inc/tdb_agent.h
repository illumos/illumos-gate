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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TDB_AGENT_H
#define	_TDB_AGENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Thread debug agent control structures.
 *
 * This is an implementation-specific header file that is shared
 * between libc and libc_db.  It is NOT a public header file
 * and must never be installed in /usr/include
 */

#include <thread_db.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The structure containing per-thread event data.
 */
typedef struct {
	td_thr_events_t	eventmask;	/* Which events are enabled? */
	td_event_e	eventnum;	/* Most recent enabled event */
	void		*eventdata;	/* Param. for most recent event */
} td_evbuf_t;

#ifdef _SYSCALL32
typedef struct {
	td_thr_events_t	eventmask;	/* Which events are enabled? */
	td_event_e	eventnum;	/* Most recent enabled event */
	caddr32_t	eventdata;	/* Param. for most recent event */
} td_evbuf32_t;
#endif /* _SYSCALL32 */


/*
 * All of these structures are constrained to have a size of 48 bytes.
 * This is so that two 8-byte pointers can be inserted at the front to
 * make up a complete tdb_sync_stats_t structure of exactly 64 bytes.
 * The 'type' element of each structure identifies the type of the union,
 * with values from the following defines.
 */

#define	TDB_NONE	0
#define	TDB_MUTEX	1
#define	TDB_COND	2
#define	TDB_RWLOCK	3
#define	TDB_SEMA	4

typedef struct {
	uint16_t	type;
	uint16_t	unused;
	uint_t		mutex_lock;
	hrtime_t	mutex_hold_time;
	hrtime_t	mutex_sleep_time;
	uint_t		mutex_sleep;
	uint_t		mutex_try;
	uint_t		mutex_try_fail;
	uint_t		mutex_pad[1];
	hrtime_t	mutex_begin_hold;
} tdb_mutex_stats_t;

typedef struct {
	uint16_t	type;
	uint16_t	unused;
	uint_t		cond_wait;
	uint_t		cond_timedwait;
	uint_t		cond_timedwait_timeout;
	hrtime_t	cond_wait_sleep_time;
	hrtime_t	cond_timedwait_sleep_time;
	uint_t		cond_signal;
	uint_t		cond_broadcast;
	uint_t		cond_pad[2];
} tdb_cond_stats_t;

typedef struct {
	uint16_t	type;
	uint16_t	unused;
	uint_t		rw_rdlock;
	/* rw_rdlock_sleep is the reader cv's cond_wait count */
	/* rw_rdlock_sleep_time is the reader cv's cond_wait_sleep_time */
	uint_t		rw_rdlock_try;
	uint_t		rw_rdlock_try_fail;
	uint_t		rw_pad[1];
	uint_t		rw_wrlock;
	/* rw_wrlock_sleep is the writer cv's cond_wait count */
	/* rw_wrlock_sleep_time is the writer cv's cond_wait_sleep_time */
	hrtime_t	rw_wrlock_hold_time;
	uint_t		rw_wrlock_try;
	uint_t		rw_wrlock_try_fail;
	hrtime_t	rw_wrlock_begin_hold;
} tdb_rwlock_stats_t;

typedef struct {
	uint16_t	type;
	uint16_t	unused;
	uint_t		sema_post;
	uint_t		sema_wait;
	uint_t		sema_wait_sleep;
	hrtime_t	sema_wait_sleep_time;
	uint_t		sema_trywait;
	uint_t		sema_trywait_fail;
	uint_t		sema_max_count;
	uint_t		sema_min_count;
	uint_t		sema_pad[2];
} tdb_sema_stats_t;

/*
 * An entry in the sync. object hash table.
 */
typedef struct {
	uint64_t	next;
	uint64_t	sync_addr;
	union {
		uint16_t		type;
		tdb_mutex_stats_t	mutex;
		tdb_cond_stats_t	cond;
		tdb_rwlock_stats_t	rwlock;
		tdb_sema_stats_t	sema;
	} un;
} tdb_sync_stats_t;

/* peg count values at UINT_MAX */
#define	tdb_incr(x)	(((x) != UINT_MAX)? (x)++ : 0)

/*
 * The tdb_register_sync variable is set to REGISTER_SYNC_ENABLE by a
 * debugger to enable synchronization object registration.
 * Thereafter, synchronization primitives call tdb_sync_obj_register()
 * to put their synchronization objects in the registration hash table.
 * In this state, the first call to tdb_sync_obj_register() empties the
 * hash table and sets tdb_register_sync to REGISTER_SYNC_ON.
 *
 * The tdb_register_sync variable is set to REGISTER_SYNC_DISABLE by a
 * debugger to disable synchronization object registration.
 * In this state, the first call to tdb_sync_obj_register() empties the
 * hash table and sets tdb_register_sync to REGISTER_SYNC_OFF.
 * Thereafter, synchronization primitives do not call tdb_sync_obj_register().
 *
 * Sync object *_destroy() functions always call tdb_sync_obj_deregister().
 */
typedef	uint8_t	register_sync_t;
#define	REGISTER_SYNC_OFF	0	/* registration is off */
#define	REGISTER_SYNC_ON	1	/* registration is on */
#define	REGISTER_SYNC_DISABLE	2	/* request to disable registration */
#define	REGISTER_SYNC_ENABLE	3	/* request to enable registration */

extern	tdb_sync_stats_t	*tdb_sync_obj_register(void *, int *);
extern	void			tdb_sync_obj_deregister(void *);

/*
 * Definitions for acquiring pointers to synch object statistics blocks
 * contained in the synchronization object registration hash table.
 */
extern	tdb_mutex_stats_t	*tdb_mutex_stats(mutex_t *);
extern	tdb_cond_stats_t	*tdb_cond_stats(cond_t *);
extern	tdb_rwlock_stats_t	*tdb_rwlock_stats(rwlock_t *);
extern	tdb_sema_stats_t	*tdb_sema_stats(sema_t *);

#define	REGISTER_SYNC(udp)	(udp)->uberflags.uf_tdb_register_sync

#define	MUTEX_STATS(mp, udp)	\
		(REGISTER_SYNC(udp)? tdb_mutex_stats(mp): NULL)
#define	COND_STATS(cvp, udp)	\
		(REGISTER_SYNC(udp)? tdb_cond_stats(cvp): NULL)
#define	RWLOCK_STATS(rwlp, udp)	\
		(REGISTER_SYNC(udp)? tdb_rwlock_stats(rwlp): NULL)
#define	SEMA_STATS(sp, udp)	\
		(REGISTER_SYNC(udp)? tdb_sema_stats(sp): NULL)

/*
 * Parameters of the synchronization object registration hash table.
 */
#define	TDB_HASH_SHIFT	15	/* 32K hash table entries */
#define	TDB_HASH_SIZE	(1 << TDB_HASH_SHIFT)
#define	TDB_HASH_MASK	(TDB_HASH_SIZE - 1)

/*
 * uberdata.tdb_hash_lock protects all synchronization object
 * hash table data structures.
 * uberdata.tdb_hash_lock_stats is a special tdb_sync_stats structure
 * reserved for tdb_hash_lock.
 */

typedef	void (*tdb_ev_func_t)(void);

/*
 * Uberdata for thread debug interfaces (known to libc_db).
 */
typedef struct {
	/*
	 * Pointer to the hash table of sync_addr_t descriptors.
	 * This holds the addresses of all of the synchronization variables
	 * that the library has seen since tracking was enabled by a debugger.
	 */
	uint64_t		*tdb_sync_addr_hash;
	/*
	 * The number of entries in the hash table.
	 */
	uint_t			tdb_register_count;
	int			tdb_hash_alloc_failed;
	/*
	 * The free list of sync_addr_t descriptors.
	 * When the free list is used up, it is replenished using mmap().
	 * sync_addr_t descriptors are never freed, though they may be
	 * removed from the hash table and returned to the free list.
	 */
	tdb_sync_stats_t	*tdb_sync_addr_free;
	tdb_sync_stats_t	*tdb_sync_addr_last;
	size_t			tdb_sync_alloc;
	/*
	 * The set of globally enabled events to report to libc_db.
	 */
	td_thr_events_t		tdb_ev_global_mask;
	/*
	 * The array of event function pointers.
	 */
	const tdb_ev_func_t	*tdb_events;
} tdb_t;

#ifdef _SYSCALL32
typedef struct {
	caddr32_t	tdb_sync_addr_hash;
	uint_t		tdb_register_count;
	int		tdb_hash_alloc_failed;
	caddr32_t	tdb_sync_addr_free;
	caddr32_t	tdb_sync_addr_last;
	size32_t	tdb_sync_alloc;
	td_thr_events_t	tdb_ev_global_mask;
	caddr32_t	tdb_events;
} tdb32_t;
#endif /* _SYSCALL32 */

/*
 * This will have to change if event numbers exceed 31.
 * Note that we only test tdb_ev_global_mask.event_bits[0] below.
 */
#define	__td_event_report(ulwp, event, udp)				\
	(((ulwp)->ul_td_events_enable &&				\
	td_eventismember(&(ulwp)->ul_td_evbuf.eventmask, (event))) ||	\
	((udp)->tdb.tdb_ev_global_mask.event_bits[0] &&			\
	td_eventismember(&(udp)->tdb.tdb_ev_global_mask, (event))))

/*
 * Event "reporting" functions.  A thread reports an event by calling
 * one of these empty functions; a debugger can set a breakpoint
 * at the address of any of these functions to determine that an
 * event is being reported.
 */
extern const tdb_ev_func_t tdb_events[TD_MAX_EVENT_NUM - TD_MIN_EVENT_NUM + 1];

#define	tdb_event(event, udp)		\
	(*(udp)->tdb.tdb_events[(event) - TD_MIN_EVENT_NUM])()

#ifdef __cplusplus
}
#endif

#endif	/* _TDB_AGENT_H */
