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

#ifndef _SYS_MUTEX_IMPL_H
#define	_SYS_MUTEX_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_ASM
#include <sys/types.h>
#include <sys/machlock.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	MUTEX_THREAD	(-0x8)
#ifndef	_ASM

/*
 * mutex_enter() assumes that the mutex is adaptive and tries to grab the
 * lock by doing a cas on the first word of the mutex.  If the cas fails,
 * it means that either (1) the lock is a spin lock, or (2) the lock is
 * adaptive but already held.  mutex_vector_enter() distinguishes these
 * cases by looking at the mutex type, which is encoded in the low-order
 * bits of the owner field.
 */
typedef union mutex_impl {
	/*
	 * Adaptive mutex.
	 */
	struct adaptive_mutex {
		uintptr_t _m_owner;	/* 0-3/0-7 owner and waiters bit */
	} m_adaptive;

	/*
	 * Spin Mutex.
	 */
	struct spin_mutex {
		ushort_t m_oldspl;	/* 0-1	old %pil value */
		ushort_t m_minspl;	/* 2-3	min %pil val if lock held */
		ushort_t m_filler;	/* 4-5	unused */
		lock_t	m_spinlock;	/* 6	real lock */
		lock_t	m_dummylock;	/* 7	dummy lock (always set) */
	} m_spin;

} mutex_impl_t;

#define	m_owner	m_adaptive._m_owner

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

#define	MUTEX_BACKOFF_BASE	1
#define	MUTEX_BACKOFF_SHIFT	1
#define	MUTEX_CAP_FACTOR	8
#define	MUTEX_DELAY()	{ \
				mutex_delay(); \
			}

/* low-overhead clock read */
extern u_longlong_t gettick(void);
#define	MUTEX_GETTICK()	gettick()
extern void null_xcall(void);
#define	MUTEX_SYNC()	xc_all((xcfunc_t *)null_xcall, 0, 0)

extern void cas_delay(void *);
extern void rdccr_delay(void);
extern int mutex_adaptive_tryenter(mutex_impl_t *);
extern void *mutex_owner_running(mutex_impl_t *);

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MUTEX_IMPL_H */
