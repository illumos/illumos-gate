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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MUTEX_IMPL_H
#define	_SYS_MUTEX_IMPL_H

#ifndef	_ASM
#include <sys/types.h>
#include <sys/machlock.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

/*
 * mutex_enter() assumes that the mutex is adaptive and tries to grab the
 * lock by doing a atomic compare and exchange on the first word of the mutex.
 * If the compare and exchange fails, it means that either (1) the lock is a
 * spin lock, or (2) the lock is adaptive but already held.
 * mutex_vector_enter() distinguishes these cases by looking at the mutex
 * type, which is encoded in the low-order bits of the owner field.
 */
typedef union mutex_impl {
	/*
	 * Adaptive mutex.
	 */
	struct adaptive_mutex {
		uintptr_t _m_owner;	/* 0-3/0-7 owner and waiters bit */
#ifndef _LP64
		uintptr_t _m_filler;	/* 4-7 unused */
#endif
	} m_adaptive;

	/*
	 * Spin Mutex.
	 */
	struct spin_mutex {
		lock_t	m_dummylock;	/* 0	dummy lock (always set) */
		lock_t	m_spinlock;	/* 1	real lock */
		ushort_t m_filler;	/* 2-3	unused */
		ushort_t m_oldspl;	/* 4-5	old pil value */
		ushort_t m_minspl;	/* 6-7	min pil val if lock held */
	} m_spin;

} mutex_impl_t;

#define	m_owner	m_adaptive._m_owner

#define	MUTEX_ALIGN	_LONG_ALIGNMENT
#define	MUTEX_ALIGN_WARNINGS	10	/* num of warnings to issue */

#define	MUTEX_WAITERS		0x1
#define	MUTEX_DEAD		0x6
#define	MUTEX_THREAD		(-0x8)

#define	MUTEX_OWNER(lp)		((kthread_id_t)((lp)->m_owner & MUTEX_THREAD))
#define	MUTEX_NO_OWNER		((kthread_id_t)NULL)

#define	MUTEX_SET_WAITERS(lp)						\
{									\
	uintptr_t old;							\
	while ((old = (lp)->m_owner) != 0 &&				\
	    casip(&(lp)->m_owner, old, old | MUTEX_WAITERS) != old)	\
		continue;						\
}

#define	MUTEX_HAS_WAITERS(lp)			((lp)->m_owner & MUTEX_WAITERS)
#define	MUTEX_CLEAR_LOCK_AND_WAITERS(lp)	(lp)->m_owner = 0

#define	MUTEX_SET_TYPE(lp, type)
#define	MUTEX_TYPE_ADAPTIVE(lp)	(((lp)->m_owner & MUTEX_DEAD) == 0)
#define	MUTEX_TYPE_SPIN(lp)	((lp)->m_spin.m_dummylock == LOCK_HELD_VALUE)

#define	MUTEX_DESTROY(lp)	\
	(lp)->m_owner = ((uintptr_t)curthread | MUTEX_DEAD)
/* mutex backoff delay macro and constants  */
#define	MUTEX_BACKOFF_BASE	1
#define	MUTEX_BACKOFF_SHIFT	2
#define	MUTEX_CAP_FACTOR	64
#define	MUTEX_DELAY()	{	\
			mutex_delay(); \
			SMT_PAUSE();	\
			}

/* low overhead clock read */
#define	MUTEX_GETTICK()	tsc_read()
extern void null_xcall(void);
#define	MUTEX_SYNC()	{	\
			cpuset_t set;   \
			CPUSET_ALL(set);        \
			xc_call(0, 0, 0, CPUSET2BV(set),	\
			    (xc_func_t)null_xcall); \
		}

extern int mutex_adaptive_tryenter(mutex_impl_t *);
extern void *mutex_owner_running(mutex_impl_t *);

#else	/* _ASM */

#define	MUTEX_THREAD	-0x8

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MUTEX_IMPL_H */
