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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2016 Joyent, Inc.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PTHREAD_H
#define	_PTHREAD_H

#include <sys/feature_tests.h>

#ifndef	_ASM
#include <sys/types.h>
#include <time.h>
#include <sched.h>
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Thread related attribute values defined as in thread.h.
 * These are defined as bit pattern in thread.h.
 * Any change here should be reflected in thread.h.
 */
/* detach */
#define	PTHREAD_CREATE_DETACHED		0x40	/* = THR_DETACHED */
#define	PTHREAD_CREATE_JOINABLE		0
/* scope */
#define	PTHREAD_SCOPE_SYSTEM		0x01	/* = THR_BOUND */
#define	PTHREAD_SCOPE_PROCESS		0

/*
 * Other attributes which are not defined in thread.h
 */
/* inherit */
#define	PTHREAD_INHERIT_SCHED		1
#define	PTHREAD_EXPLICIT_SCHED		0

/*
 * Value of process-shared attribute
 * These are defined as values defined in sys/synch.h
 * Any change here should be reflected in sys/synch.h.
 */
#define	PTHREAD_PROCESS_SHARED		1	/* = USYNC_PROCESS */
#define	PTHREAD_PROCESS_PRIVATE		0	/* = USYNC_THREAD */

#define	_DEFAULT_TYPE 			PTHREAD_PROCESS_PRIVATE
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#define	DEFAULT_TYPE			_DEFAULT_TYPE
#endif

/*
 * mutex types
 * keep these in synch which sys/synch.h lock flags
 */
#define	PTHREAD_MUTEX_NORMAL		0x0
#define	PTHREAD_MUTEX_ERRORCHECK	0x2
#define	PTHREAD_MUTEX_RECURSIVE		0x4
#define	PTHREAD_MUTEX_DEFAULT		PTHREAD_MUTEX_NORMAL

/*
 * Mutex protocol values. Keep these in synch with sys/synch.h lock types.
 */
#define	PTHREAD_PRIO_NONE		0x0
#define	PTHREAD_PRIO_INHERIT		0x10
#define	PTHREAD_PRIO_PROTECT		0x20

/*
 * Mutex robust attribute values.
 * Keep these in synch with sys/synch.h lock types.
 */
#define	PTHREAD_MUTEX_STALLED		0x0
#define	PTHREAD_MUTEX_ROBUST		0x40
/*
 * Historical solaris-specific names,
 * from before pthread_mutexattr_getrobust() became standardized
 */
#define	PTHREAD_MUTEX_STALL_NP		PTHREAD_MUTEX_STALLED
#define	PTHREAD_MUTEX_ROBUST_NP		PTHREAD_MUTEX_ROBUST

/*
 * macros - default initializers defined as in synch.h
 * Any change here should be reflected in synch.h.
 *
 * NOTE:
 * Make sure that any change in the macros is consistent with the definition
 * of the corresponding types in sys/types.h (e.g. PTHREAD_MUTEX_INITIALIZER
 * should be consistent with the definition for pthread_mutex_t).
 */
#define	PTHREAD_MUTEX_INITIALIZER		/* = DEFAULTMUTEX */	\
	{{0, 0, 0, _DEFAULT_TYPE, _MUTEX_MAGIC}, {{{0}}}, 0}

#define	PTHREAD_COND_INITIALIZER		/* = DEFAULTCV */	\
	{{{0, 0, 0, 0}, _DEFAULT_TYPE, _COND_MAGIC}, 0}

#define	PTHREAD_RWLOCK_INITIALIZER		/* = DEFAULTRWLOCK */	\
	{0, _DEFAULT_TYPE, _RWL_MAGIC, PTHREAD_MUTEX_INITIALIZER,	\
	PTHREAD_COND_INITIALIZER, PTHREAD_COND_INITIALIZER}

/* cancellation type and state */
#define	PTHREAD_CANCEL_ENABLE		0x00
#define	PTHREAD_CANCEL_DISABLE		0x01
#define	PTHREAD_CANCEL_DEFERRED		0x00
#define	PTHREAD_CANCEL_ASYNCHRONOUS	0x02
#define	PTHREAD_CANCELED		(void *)-19

/* pthread_once related values */
#define	PTHREAD_ONCE_NOTDONE	0
#define	PTHREAD_ONCE_DONE	1
#define	PTHREAD_ONCE_INIT	{ {0, 0, 0, PTHREAD_ONCE_NOTDONE} }

/*
 * The key to be created by pthread_key_create_once_np()
 * must be statically initialized with PTHREAD_ONCE_KEY_NP.
 * This must be the same as THR_ONCE_KEY in <thread.h>
 */
#define	PTHREAD_ONCE_KEY_NP	(pthread_key_t)(-1)

/* barriers */
#define	PTHREAD_BARRIER_SERIAL_THREAD	-2

#ifndef	_ASM

/*
 * cancellation cleanup structure
 */
typedef struct _cleanup {
	uintptr_t	pthread_cleanup_pad[4];
} _cleanup_t;

void	__pthread_cleanup_push(void (*)(void *), void *, caddr_t, _cleanup_t *);
void	__pthread_cleanup_pop(int, _cleanup_t *);
caddr_t	_getfp(void);

#if __cplusplus
extern "C" {
#endif

typedef void (*_Voidfp)(void*); /* pointer to extern "C" function */

#if __cplusplus
} /* extern "C" */
#endif

#define	pthread_cleanup_push(routine, args) { \
	_cleanup_t _cleanup_info; \
	__pthread_cleanup_push((_Voidfp)(routine), (void *)(args), \
				(caddr_t)_getfp(), &_cleanup_info);

#define	pthread_cleanup_pop(ex) \
	__pthread_cleanup_pop(ex, &_cleanup_info); \
}

/*
 * function prototypes - thread related calls
 */

/*
 * pthread_atfork() is also declared in <unistd.h> as per SUSv2. The
 * declarations are identical. A change to either one may also require
 * appropriate namespace updates in order to avoid redeclaration
 * warnings in the case where both prototypes are exposed via inclusion
 * of both <pthread.h> and <unistd.h>.
 */
extern int pthread_atfork(void (*) (void), void (*) (void), void (*) (void));
extern int pthread_attr_init(pthread_attr_t *);
extern int pthread_attr_destroy(pthread_attr_t *);
extern int pthread_attr_setstack(pthread_attr_t *, void *, size_t);
extern int pthread_attr_getstack(const pthread_attr_t *_RESTRICT_KYWD,
		void **_RESTRICT_KYWD, size_t *_RESTRICT_KYWD);
extern int pthread_attr_setstacksize(pthread_attr_t *, size_t);
extern int pthread_attr_getstacksize(const pthread_attr_t *_RESTRICT_KYWD,
		size_t *_RESTRICT_KYWD);
extern int pthread_attr_setstackaddr(pthread_attr_t *, void *);
extern int pthread_attr_getstackaddr(const pthread_attr_t *_RESTRICT_KYWD,
		void **_RESTRICT_KYWD);
extern int pthread_attr_setdetachstate(pthread_attr_t *, int);
extern int pthread_attr_getdetachstate(const pthread_attr_t *, int *);
extern int pthread_attr_setscope(pthread_attr_t *, int);
extern int pthread_attr_getscope(const pthread_attr_t *_RESTRICT_KYWD,
	int *_RESTRICT_KYWD);
extern int pthread_attr_setinheritsched(pthread_attr_t *, int);
extern int pthread_attr_getinheritsched(const pthread_attr_t *_RESTRICT_KYWD,
	int *_RESTRICT_KYWD);
extern int pthread_attr_setschedpolicy(pthread_attr_t *, int);
extern int pthread_attr_getschedpolicy(const pthread_attr_t *_RESTRICT_KYWD,
	int *_RESTRICT_KYWD);
extern int pthread_attr_setschedparam(pthread_attr_t *_RESTRICT_KYWD,
		const struct sched_param *_RESTRICT_KYWD);
extern int pthread_attr_getschedparam(const pthread_attr_t *_RESTRICT_KYWD,
		struct sched_param *_RESTRICT_KYWD);
extern int pthread_create(pthread_t *_RESTRICT_KYWD,
		const pthread_attr_t *_RESTRICT_KYWD, void * (*)(void *),
		void *_RESTRICT_KYWD);
extern int pthread_once(pthread_once_t *, void (*)(void));
extern int pthread_join(pthread_t, void **);
extern int pthread_detach(pthread_t);
extern void pthread_exit(void *) __NORETURN;
extern int pthread_cancel(pthread_t);
extern int pthread_setschedparam(pthread_t, int, const struct sched_param *);
extern int pthread_getschedparam(pthread_t, int *_RESTRICT_KYWD,
		struct sched_param *_RESTRICT_KYWD);
extern int pthread_setschedprio(pthread_t, int);
extern int pthread_setcancelstate(int, int *);
extern int pthread_setcanceltype(int, int *);
extern void pthread_testcancel(void);
extern int pthread_equal(pthread_t, pthread_t);
extern int pthread_key_create(pthread_key_t *, void (*)(void *));
extern int pthread_key_create_once_np(pthread_key_t *, void (*)(void *));
extern int pthread_key_delete(pthread_key_t);
extern int pthread_setspecific(pthread_key_t, const void *);
extern void *pthread_getspecific(pthread_key_t);
extern pthread_t pthread_self(void);

/*
 * function prototypes - synchronization related calls
 */
extern int pthread_mutexattr_init(pthread_mutexattr_t *);
extern int pthread_mutexattr_destroy(pthread_mutexattr_t *);
extern int pthread_mutexattr_setpshared(pthread_mutexattr_t *, int);
extern int pthread_mutexattr_getpshared(
	const pthread_mutexattr_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern int pthread_mutexattr_setprotocol(pthread_mutexattr_t *, int);
extern int pthread_mutexattr_getprotocol(
	const pthread_mutexattr_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *, int);
extern int pthread_mutexattr_getprioceiling(
	const pthread_mutexattr_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern int pthread_mutexattr_setrobust(pthread_mutexattr_t *, int);
extern int pthread_mutexattr_getrobust(
	const pthread_mutexattr_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern int pthread_mutex_init(pthread_mutex_t *_RESTRICT_KYWD,
	const pthread_mutexattr_t *_RESTRICT_KYWD);
extern int pthread_mutex_consistent(pthread_mutex_t *);
extern int pthread_mutex_destroy(pthread_mutex_t *);
extern int pthread_mutex_lock(pthread_mutex_t *);
extern int pthread_mutex_timedlock(pthread_mutex_t *_RESTRICT_KYWD,
	const struct timespec *_RESTRICT_KYWD);
extern int pthread_mutex_reltimedlock_np(pthread_mutex_t *_RESTRICT_KYWD,
	const struct timespec *_RESTRICT_KYWD);
extern int pthread_mutex_unlock(pthread_mutex_t *);
extern int pthread_mutex_trylock(pthread_mutex_t *);
extern int pthread_mutex_setprioceiling(pthread_mutex_t *_RESTRICT_KYWD,
	int, int *_RESTRICT_KYWD);
extern int pthread_mutex_getprioceiling(const pthread_mutex_t *_RESTRICT_KYWD,
	int *_RESTRICT_KYWD);
extern int pthread_condattr_init(pthread_condattr_t *);
extern int pthread_condattr_destroy(pthread_condattr_t *);
extern int pthread_condattr_setclock(pthread_condattr_t *, clockid_t);
extern int pthread_condattr_getclock(const pthread_condattr_t *_RESTRICT_KYWD,
	clockid_t *_RESTRICT_KYWD);
extern int pthread_condattr_setpshared(pthread_condattr_t *, int);
extern int pthread_condattr_getpshared(const pthread_condattr_t *_RESTRICT_KYWD,
	int *_RESTRICT_KYWD);
extern int pthread_cond_init(pthread_cond_t *_RESTRICT_KYWD,
	const pthread_condattr_t *_RESTRICT_KYWD);
extern int pthread_cond_destroy(pthread_cond_t *);
extern int pthread_cond_broadcast(pthread_cond_t *);
extern int pthread_cond_signal(pthread_cond_t *);
extern int pthread_cond_wait(pthread_cond_t *_RESTRICT_KYWD,
	pthread_mutex_t *_RESTRICT_KYWD);
extern int pthread_cond_timedwait(pthread_cond_t *_RESTRICT_KYWD,
	pthread_mutex_t *_RESTRICT_KYWD, const struct timespec *_RESTRICT_KYWD);
extern int pthread_cond_reltimedwait_np(pthread_cond_t *_RESTRICT_KYWD,
	pthread_mutex_t *_RESTRICT_KYWD, const struct timespec *_RESTRICT_KYWD);
extern int pthread_attr_getguardsize(const pthread_attr_t *_RESTRICT_KYWD,
	size_t *_RESTRICT_KYWD);
extern int pthread_attr_setguardsize(pthread_attr_t *, size_t);
extern int pthread_getconcurrency(void);
extern int pthread_setconcurrency(int);
extern int pthread_mutexattr_settype(pthread_mutexattr_t *, int);
extern int pthread_mutexattr_gettype(const pthread_mutexattr_t *_RESTRICT_KYWD,
	int *_RESTRICT_KYWD);
extern int pthread_rwlock_init(pthread_rwlock_t *_RESTRICT_KYWD,
	const pthread_rwlockattr_t *_RESTRICT_KYWD);
extern int pthread_rwlock_destroy(pthread_rwlock_t *);
extern int pthread_rwlock_rdlock(pthread_rwlock_t *);
extern int pthread_rwlock_timedrdlock(pthread_rwlock_t *_RESTRICT_KYWD,
	const struct timespec *_RESTRICT_KYWD);
extern int pthread_rwlock_reltimedrdlock_np(pthread_rwlock_t *_RESTRICT_KYWD,
	const struct timespec *_RESTRICT_KYWD);
extern int pthread_rwlock_tryrdlock(pthread_rwlock_t *);
extern int pthread_rwlock_wrlock(pthread_rwlock_t *);
extern int pthread_rwlock_timedwrlock(pthread_rwlock_t *_RESTRICT_KYWD,
	const struct timespec *_RESTRICT_KYWD);
extern int pthread_rwlock_reltimedwrlock_np(pthread_rwlock_t *_RESTRICT_KYWD,
	const struct timespec *_RESTRICT_KYWD);
extern int pthread_rwlock_trywrlock(pthread_rwlock_t *);
extern int pthread_rwlock_unlock(pthread_rwlock_t *);
extern int pthread_rwlockattr_init(pthread_rwlockattr_t *);
extern int pthread_rwlockattr_destroy(pthread_rwlockattr_t *);
extern int pthread_rwlockattr_getpshared(
	const pthread_rwlockattr_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *, int);
extern int pthread_spin_init(pthread_spinlock_t *, int);
extern int pthread_spin_destroy(pthread_spinlock_t *);
extern int pthread_spin_lock(pthread_spinlock_t *);
extern int pthread_spin_trylock(pthread_spinlock_t *);
extern int pthread_spin_unlock(pthread_spinlock_t *);
extern int pthread_barrierattr_init(pthread_barrierattr_t *);
extern int pthread_barrierattr_destroy(pthread_barrierattr_t *);
extern int pthread_barrierattr_setpshared(pthread_barrierattr_t *, int);
extern int pthread_barrierattr_getpshared(
	const pthread_barrierattr_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern int pthread_barrier_init(pthread_barrier_t *_RESTRICT_KYWD,
	const pthread_barrierattr_t *_RESTRICT_KYWD, uint_t);
extern int pthread_barrier_destroy(pthread_barrier_t *);
extern int pthread_barrier_wait(pthread_barrier_t *);

/* Historical names -- present only for binary compatibility */
extern int pthread_mutex_consistent_np(pthread_mutex_t *);
extern int pthread_mutexattr_setrobust_np(pthread_mutexattr_t *, int);
extern int pthread_mutexattr_getrobust_np(
	const pthread_mutexattr_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);

/*
 * These are non-standardized extensions that we provide. Their origins are
 * documented in their manual pages.
 */
#if !defined(_STRICT_SYMBOLS) || defined(__EXTENSIONS__)
extern int pthread_attr_get_np(pthread_t, pthread_attr_t *);
#endif	/* !_STRICT_SYMBOLS || __EXTENSIONS__ */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _PTHREAD_H */
