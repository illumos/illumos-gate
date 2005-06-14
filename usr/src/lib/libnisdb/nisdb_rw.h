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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_NISDB_RW_H
#define	_NISDB_RW_H

#include <pthread.h>
#include <thread.h>
#include <synch.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/errno.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	INV_PTHREAD_ID	0

/*
 * DEFAULTNISDBRWLOCK_RW is the default initializer that does _not_
 * force read lock requests to write locks, while DEFAULTNISDBRWLOCK_W
 * does force all locks to be exclusive.
 *
 * Locks should be initialized DEFAULTNISDBRWLOCK_W until it's been
 * determined that non-exclusive locking can be safely used; see
 * comments in __nisdb_rwinit() in nisdb_rw.c.
 */
#define	DEFAULTNISDBRWLOCK_RW	{DEFAULTMUTEX, DEFAULTCV, 0, 0, \
					0, {INV_PTHREAD_ID, 0, 0, 0}, \
					0, 0, {INV_PTHREAD_ID, 0, 0, 0}}

#define	DEFAULTNISDBRWLOCK_W	{DEFAULTMUTEX, DEFAULTCV, 0, 1, \
					0, {INV_PTHREAD_ID, 0, 0, 0}, \
					0, 0, {INV_PTHREAD_ID, 0, 0, 0}}

#define	DEFAULTNISDBRWLOCK	DEFAULTNISDBRWLOCK_W

/*
 * The value used for the 'force_write' field initialization in
 * __nisdb_rwinit(). Should be one unless it's been determined that
 * read locks can safely be used in for _all_ locks initialized
 * by __nisdb_rwinit().
 */
#define	NISDB_FORCE_WRITE	1

#ifdef	NISDB_MT_DEBUG

#define	DECLMUTEXLOCK(var)	pthread_mutex_t var ## _pmutex = \
					PTHREAD_MUTEX_INITIALIZER; \
				pthread_t var ## _owner = INV_PTHREAD_ID
#define	USEMUTEXLOCK(var)	extern pthread_mutex_t var ## _pmutex; \
				extern pthread_t var ## _owner
#define	STRUCTMUTEXLOCK(var)	pthread_mutex_t var ## _pmutex; \
				pthread_t var ## _owner
#define	INITMUTEX(var)		(void) pthread_mutex_init(&var ## _pmutex, 0)
#define	MUTEXLOCK(var, msg)	if (var ## _owner != pthread_self()) { \
					pthread_mutex_lock(&var ## _pmutex); \
					var ## _owner = pthread_self(); \
				} else \
					abort();
#define	MUTEXUNLOCK(var, msg)	if (var ## _owner == pthread_self()) { \
					var ## _owner = INV_PTHREAD_ID; \
					pthread_mutex_unlock(&var ## _pmutex);\
				} else \
					abort();
#define	ASSERTMUTEXHELD(var)	if (var ## _owner != pthread_self()) \
					abort();

#define	DECLRWLOCK(var)		__nisdb_rwlock_t var ## _rwlock = \
						DEFAULTNISDBRWLOCK
#define	USERWLOCK(var)		extern __nisdb_rwlock_t var ## _rwlock
#define	STRUCTRWLOCK(var)	__nisdb_rwlock_t var ## _rwlock
#define	INITRW(var)		(void) __nisdb_rwinit(&var ## _rwlock)
#define	READLOCKOK(var)		(void) __nisdb_rw_readlock_ok(&var ## _rwlock)
#define	RLOCK(var)		__nisdb_rlock(&var ## _rwlock)
#define	WLOCK(var)		__nisdb_wlock(&var ## _rwlock)
#define	TRYWLOCK(var)		__nisdb_wlock_trylock(&var ## _rwlock, 1)
#define	RULOCK(var)		__nisdb_rulock(&var ## _rwlock)
#define	WULOCK(var)		__nisdb_wulock(&var ## _rwlock)
#define	DESTROYRW(var)		__nisdb_destroy_lock(&var ## _rwlock)
#define	ASSERTWHELD(var)	if (__nisdb_assert_wheld(&var ## _rwlock) \
					!= 0) \
					abort();
#define	ASSERTRHELD(var)	if (__nisdb_assert_rheld(&var ## _rwlock) \
					!= 0) \
					abort();

#else	/* NISDB_MT_DEBUG */

#define	DECLMUTEXLOCK(var)	pthread_mutex_t var ## _pmutex = \
					PTHREAD_MUTEX_INITIALIZER
#define	USEMUTEXLOCK(var)	extern pthread_mutex_t var ## _pmutex
#define	STRUCTMUTEXLOCK(var)	pthread_mutex_t var ## _pmutex
#define	INITMUTEX(var)		(void) pthread_mutex_init(&var ## _pmutex, 0)
#define	MUTEXLOCK(var, msg)	pthread_mutex_lock(&var ## _pmutex)
#define	MUTEXUNLOCK(var, msg)	pthread_mutex_unlock(&var ## _pmutex)

#define	DECLRWLOCK(var)		__nisdb_rwlock_t var ## _rwlock = \
						DEFAULTNISDBRWLOCK
#define	USERWLOCK(var)		extern __nisdb_rwlock_t var ## _rwlock
#define	STRUCTRWLOCK(var)	__nisdb_rwlock_t var ## _rwlock
#define	INITRW(var)		(void) __nisdb_rwinit(&var ## _rwlock)
#define	READLOCKOK(var)		(void) __nisdb_rw_readlock_ok(&var ## _rwlock)
#define	RLOCK(var)		__nisdb_rlock(&var ## _rwlock)
#define	WLOCK(var)		__nisdb_wlock(&var ## _rwlock)
#define	TRYWLOCK(var)		__nisdb_wlock_trylock(&var ## _rwlock, 1)
#define	RULOCK(var)		__nisdb_rulock(&var ## _rwlock)
#define	WULOCK(var)		__nisdb_wulock(&var ## _rwlock)
#define	DESTROYRW(var)		__nisdb_destroy_lock(&var ## _rwlock)
#define	ASSERTMUTEXHELD(var)
#define	ASSERTWHELD(var)
#define	ASSERTRHELD(var)

#endif	/* NISDB_MT_DEBUG */

/* Nesting-safe RW locking */
typedef struct __nisdb_rwlock {
	pthread_t		id;	/* Which thread */
	uint32_t		count;	/* Lock depth for thread */
	uint32_t		wait;	/* Blocked on mutex */
	struct __nisdb_rwlock	*next;	/* Next reader record */
} __nisdb_rl_t;

typedef struct {
	mutex_t		mutex;		/* Exclusive access to structure */
	cond_t		cv;		/* CV for signaling */
	uint32_t	destroyed;	/* Set if lock has been destroyed */
	uint32_t	force_write;	/* Set if read locks forced to write */
	uint32_t	writer_count;	/* Number of writer threads [0, 1] */
	__nisdb_rl_t	writer;		/* Writer record */
	uint32_t	reader_count;	/* # of reader threads [0, N] */
	uint32_t	reader_blocked;	/* # of readers blocked on mutex */
	__nisdb_rl_t	reader;		/* List of reader records */
} __nisdb_rwlock_t;

extern int		__nisdb_rwinit(__nisdb_rwlock_t *);
extern int		__nisdb_rw_readlock_ok(__nisdb_rwlock_t *rw);
extern int		__nisdb_rw_force_writelock(__nisdb_rwlock_t *rw);
extern int		__nisdb_wlock(__nisdb_rwlock_t *);
extern int		__nisdb_wlock_trylock(__nisdb_rwlock_t *, int);
extern int		__nisdb_rlock(__nisdb_rwlock_t *);
extern int		__nisdb_wulock(__nisdb_rwlock_t *);
extern int		__nisdb_rulock(__nisdb_rwlock_t *);
extern int		__nisdb_assert_wheld(__nisdb_rwlock_t *);
extern int		__nisdb_assert_rheld(__nisdb_rwlock_t *);
extern int		__nisdb_destroy_lock(__nisdb_rwlock_t *);
extern void		__nisdb_lock_report(__nisdb_rwlock_t *rw);

#ifdef	__cplusplus
}
#endif

#endif	/* _NISDB_RW_H */
