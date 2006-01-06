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

/*
 * This file is included in library source files (other than libc) when it
 * is desired to call libc functions by their restricted names rather than
 * by their public names, to avoid a namespace collision with applications.
 * "mtlib.h" is included by "synonyms.h".  There is no need to include both.
 */

#ifndef _COMMON_INC_MTLIB_H
#define	_COMMON_INC_MTLIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__lint)

/* lock primitives and other multithreading interfaces */
#define	atomic_add_16			_atomic_add_16
#define	atomic_add_32			_atomic_add_32
#define	atomic_add_64			_atomic_add_64
#define	atomic_add_long			_atomic_add_long
#define	atomic_add_16_nv		_atomic_add_16_nv
#define	atomic_add_32_nv		_atomic_add_32_nv
#define	atomic_add_64_nv		_atomic_add_64_nv
#define	atomic_add_long_nv		_atomic_add_long_nv
#define	atomic_or_uint			_atomic_or_uint
#define	atomic_or_32			_atomic_or_32
#define	atomic_and_uint			_atomic_and_uint
#define	atomic_and_32			_atomic_and_32
#define	mutex_init			__mutex_init
#define	mutex_destroy			__mutex_destroy
#define	mutex_lock			__mutex_lock
#define	mutex_trylock			__mutex_trylock
#define	mutex_unlock			__mutex_unlock
#define	mutex_held			__mutex_held
#define	_mutex_init			__mutex_init
#define	_mutex_destroy			__mutex_destroy
#define	_mutex_lock			__mutex_lock
#define	_mutex_trylock			__mutex_trylock
#define	_mutex_unlock			__mutex_unlock
#define	_mutex_held			__mutex_held
#define	cond_init			_cond_init
#define	cond_destroy			_cond_destroy
#define	cond_wait			_cond_wait
#define	cond_timedwait			_cond_timedwait
#define	cond_reltimedwait		_cond_reltimedwait
#define	cond_signal			_cond_signal
#define	cond_broadcast			_cond_broadcast
#define	rwlock_init			_rwlock_init
#define	rwlock_destroy			_rwlock_destroy
#define	rw_rdlock			_rw_rdlock
#define	rw_wrlock			_rw_wrlock
#define	rw_tryrdlock			_rw_tryrdlock
#define	rw_trywrlock			_rw_trywrlock
#define	rw_unlock			_rw_unlock
#define	rw_read_held			_rw_read_held
#define	rw_write_held			_rw_write_held
#define	sema_held			_sema_held
#define	sema_init			_sema_init
#define	sema_destroy			_sema_destroy
#define	sema_wait			_sema_wait
#define	sema_reltimedwait		_sema_reltimedwait
#define	sema_timedwait			_sema_timedwait
#define	sema_trywait			_sema_trywait
#define	sema_post			_sema_post
#define	sem_open			_sem_open
#define	sem_close			_sem_close
#define	sem_unlink			_sem_unlink
#define	sem_init			_sem_init
#define	sem_destroy			_sem_destroy
#define	sem_post			_sem_post
#define	sem_wait			_sem_wait
#define	sem_timedwait			_sem_timedwait
#define	sem_reltimedwait_np		_sem_reltimedwait_np
#define	sem_trywait			_sem_trywait
#define	sem_getvalue			_sem_getvalue
#define	thr_continue			_thr_continue
#define	thr_continue_allmutators	_thr_continue_allmutators
#define	thr_continue_mutator		_thr_continue_mutator
#define	thr_create			_thr_create
#define	thr_exit			_thr_exit
#define	thr_getconcurrency		_thr_getconcurrency
#define	thr_getprio			_thr_getprio
#define	thr_getspecific			_thr_getspecific
#define	thr_getstate			_thr_getstate
#define	thr_join			_thr_join
#define	thr_keycreate			_thr_keycreate
#define	thr_kill			_thr_kill
#define	thr_main			_thr_main
#define	thr_min_stack			_thr_min_stack
#define	thr_mutators_barrier		_thr_mutators_barrier
#define	thr_self			_thr_self
#define	thr_setconcurrency		_thr_setconcurrency
#define	thr_setmutator			_thr_setmutator
#define	thr_setprio			_thr_setprio
#define	thr_setspecific			_thr_setspecific
#define	thr_setstate			_thr_setstate
#define	thr_sighndlrinfo		_thr_sighndlrinfo
#define	thr_sigsetmask			_thr_sigsetmask
#define	thr_stksegment			_thr_stksegment
#define	thr_suspend			_thr_suspend
#define	thr_suspend_allmutators		_thr_suspend_allmutators
#define	thr_suspend_mutator		_thr_suspend_mutator
#define	thr_wait_mutator		_thr_wait_mutator
#define	thr_yield			_thr_yield
#define	pthread_atfork			_pthread_atfork
#define	pthread_attr_destroy		_pthread_attr_destroy
#define	pthread_attr_getdetachstate	_pthread_attr_getdetachstate
#define	pthread_attr_getguardsize	_pthread_attr_getguardsize
#define	pthread_attr_getinheritsched	_pthread_attr_getinheritsched
#define	pthread_attr_getschedparam	_pthread_attr_getschedparam
#define	pthread_attr_getschedpolicy	_pthread_attr_getschedpolicy
#define	pthread_attr_getscope		_pthread_attr_getscope
#define	pthread_attr_getstack		_pthread_attr_getstack
#define	pthread_attr_getstackaddr	_pthread_attr_getstackaddr
#define	pthread_attr_getstacksize	_pthread_attr_getstacksize
#define	pthread_attr_init		_pthread_attr_init
#define	pthread_attr_setdetachstate	_pthread_attr_setdetachstate
#define	pthread_attr_setguardsize	_pthread_attr_setguardsize
#define	pthread_attr_setinheritsched	_pthread_attr_setinheritsched
#define	pthread_attr_setschedparam	_pthread_attr_setschedparam
#define	pthread_attr_setschedpolicy	_pthread_attr_setschedpolicy
#define	pthread_attr_setscope		_pthread_attr_setscope
#define	pthread_attr_setstack		_pthread_attr_setstack
#define	pthread_attr_setstackaddr	_pthread_attr_setstackaddr
#define	pthread_attr_setstacksize	_pthread_attr_setstacksize
#define	pthread_barrier_destroy		_pthread_barrier_destroy
#define	pthread_barrier_init		_pthread_barrier_init
#define	pthread_barrier_wait		_pthread_barrier_wait
#define	pthread_barrierattr_destroy	_pthread_barrierattr_destroy
#define	pthread_barrierattr_getpshared	_pthread_barrierattr_getpshared
#define	pthread_barrierattr_init	_pthread_barrierattr_init
#define	pthread_barrierattr_setpshared	_pthread_barrierattr_setpshared
#define	pthread_cancel			_pthread_cancel
#define	pthread_cond_broadcast		_pthread_cond_broadcast
#define	pthread_cond_destroy		_pthread_cond_destroy
#define	pthread_cond_init		_pthread_cond_init
#define	pthread_cond_reltimedwait_np	_pthread_cond_reltimedwait_np
#define	pthread_cond_signal		_pthread_cond_signal
#define	pthread_cond_timedwait		_pthread_cond_timedwait
#define	pthread_cond_wait		_pthread_cond_wait
#define	pthread_condattr_destroy	_pthread_condattr_destroy
#define	pthread_condattr_getclock	_pthread_condattr_getclock
#define	pthread_condattr_getpshared	_pthread_condattr_getpshared
#define	pthread_condattr_init		_pthread_condattr_init
#define	pthread_condattr_setclock	_pthread_condattr_setclock
#define	pthread_condattr_setpshared	_pthread_condattr_setpshared
#define	pthread_create			_pthread_create
#define	pthread_detach			_pthread_detach
#define	pthread_equal			_pthread_equal
#define	pthread_exit			_pthread_exit
#define	pthread_getconcurrency		_pthread_getconcurrency
#define	pthread_getschedparam		_pthread_getschedparam
#define	pthread_getspecific		_pthread_getspecific
#define	pthread_join			_pthread_join
#define	pthread_key_create		_pthread_key_create
#define	pthread_key_delete		_pthread_key_delete
#define	pthread_kill			_pthread_kill
#define	pthread_mutex_consistent_np	_pthread_mutex_consistent_np
#define	pthread_mutex_destroy		_pthread_mutex_destroy
#define	pthread_mutex_getprioceiling	_pthread_mutex_getprioceiling
#define	pthread_mutex_init		_pthread_mutex_init
#define	pthread_mutex_lock		_pthread_mutex_lock
#define	pthread_mutex_setprioceiling	_pthread_mutex_setprioceiling
#define	pthread_mutex_trylock		_pthread_mutex_trylock
#define	pthread_mutex_unlock		_pthread_mutex_unlock
#define	pthread_mutexattr_destroy	_pthread_mutexattr_destroy
#define	pthread_mutexattr_getprioceiling _pthread_mutexattr_getprioceiling
#define	pthread_mutexattr_getprotocol	_pthread_mutexattr_getprotocol
#define	pthread_mutexattr_getpshared	_pthread_mutexattr_getpshared
#define	pthread_mutexattr_getrobust_np	_pthread_mutexattr_getrobust_np
#define	pthread_mutexattr_gettype	_pthread_mutexattr_gettype
#define	pthread_mutexattr_init		_pthread_mutexattr_init
#define	pthread_mutexattr_setprioceiling _pthread_mutexattr_setprioceiling
#define	pthread_mutexattr_setprotocol	_pthread_mutexattr_setprotocol
#define	pthread_mutexattr_setpshared	_pthread_mutexattr_setpshared
#define	pthread_mutexattr_setrobust_np	_pthread_mutexattr_setrobust_np
#define	pthread_mutexattr_settype	_pthread_mutexattr_settype
#define	pthread_once			_pthread_once
#define	pthread_rwlock_destroy		_pthread_rwlock_destroy
#define	pthread_rwlock_init		_pthread_rwlock_init
#define	pthread_rwlock_rdlock		_pthread_rwlock_rdlock
#define	pthread_rwlock_tryrdlock	_pthread_rwlock_tryrdlock
#define	pthread_rwlock_trywrlock	_pthread_rwlock_trywrlock
#define	pthread_rwlock_unlock		_pthread_rwlock_unlock
#define	pthread_rwlock_wrlock		_pthread_rwlock_wrlock
#define	pthread_rwlockattr_destroy	_pthread_rwlockattr_destroy
#define	pthread_rwlockattr_getpshared	_pthread_rwlockattr_getpshared
#define	pthread_rwlockattr_init		_pthread_rwlockattr_init
#define	pthread_rwlockattr_setpshared	_pthread_rwlockattr_setpshared
#define	pthread_self			_pthread_self
#define	pthread_setcancelstate		_pthread_setcancelstate
#define	pthread_setcanceltype		_pthread_setcanceltype
#define	pthread_setconcurrency		_pthread_setconcurrency
#define	pthread_setschedparam		_pthread_setschedparam
#define	pthread_setschedprio		_pthread_setschedprio
#define	pthread_setspecific		_pthread_setspecific
#define	pthread_sigmask			_pthread_sigmask
#define	pthread_testcancel		_pthread_testcancel

#endif	/* !defined(__lint) */

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_INC_MTLIB_H */
