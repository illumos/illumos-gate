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
 * Copyright (c) 1991-1998 by Sun Microsystems, Inc.
 * All rights reserved.
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

#ifndef	_ASM

/*
 * mutex_enter() assumes that the mutex is adaptive and tries to grab the
 * lock by doing an ldstub on byte 0 of the mutex.  If the ldstub fails,
 * it means that either (1) the lock is a spin lock, or (2) the lock is
 * adaptive but already held.  mutex_vector_enter() distinguishes these
 * cases by looking at the mutex type, which is byte 7 for both types.
 *
 * Once the lock byte is set for an adaptive lock, the owner is stuffed
 * into the remaining 24 bits such that the owner word is 0xff:owner24.
 * This works because a thread pointer only has 24 significant bits: the
 * upper 3 bits are 111 (since all kernel addresses are above 0xe0000000),
 * and the lower 5 bits are zero (because threads are 32-byte aligned).
 */
typedef union mutex_impl {
	/*
	 * Adaptive mutex.
	 */
	struct adaptive_mutex {
		uintptr_t _m_owner;	/* 0-3	owner and lock */
		uchar_t	_m_waiters;	/* 4	are there waiters? */
		uchar_t	_m_filler[2];	/* 5-6	unused */
		uchar_t	_m_type;	/* 7	type */
	} m_adaptive;

	/*
	 * Spin Mutex.
	 */
	struct spin_mutex {
		lock_t	m_dummylock;	/* 0	lock (always set) */
		lock_t	m_spinlock;	/* 1	real lock */
		ushort_t m_oldspl;	/* 2-3	old %psr value */
		ushort_t m_minspl;	/* 4-5	min PSR_PIL val if lock held */
		uchar_t m_filler;	/* 6	unused */
		uchar_t _m_type;	/* 7	type */
	} m_spin;
} mutex_impl_t;

#define	m_owner		m_adaptive._m_owner
#define	m_waiters	m_adaptive._m_waiters
#define	m_type		m_adaptive._m_type

/*
 * Macro to retrieve 32-bit pointer field out of mutex.
 * Relies on 32-byte alignment of thread structures.
 * Also relies on KERNELBASE (and all thread pointers)
 * being above 0xe0000000.
 */
#define	MUTEX_OWNER(lp)		((kthread_id_t)((lp)->m_owner << PTR24_LSB))
#define	MUTEX_NO_OWNER		((kthread_id_t)PTR24_BASE)

#define	MUTEX_SET_WAITERS(lp)	((lp)->m_waiters = 1)
#define	MUTEX_HAS_WAITERS(lp)	((lp)->m_waiters != 0)
#define	MUTEX_CLEAR_LOCK_AND_WAITERS(lp)	\
	(lp)->m_waiters = 0, (lp)->m_owner = 0

#define	MUTEX_SET_TYPE(lp, type)	(lp)->m_type = (type)
#define	MUTEX_TYPE_ADAPTIVE(lp)		((lp)->m_type == MUTEX_ADAPTIVE)
#define	MUTEX_TYPE_SPIN(lp)		((lp)->m_type == MUTEX_SPIN)

#define	MUTEX_DESTROY(lp)	\
	(lp)->m_type = 0xdd, LOCK_INIT_HELD(&lp->m_spin.m_dummylock)

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MUTEX_IMPL_H */
