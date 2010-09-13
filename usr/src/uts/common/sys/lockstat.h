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

#ifndef _SYS_LOCKSTAT_H
#define	_SYS_LOCKSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dtrace.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LS_MUTEX_ENTER_ACQUIRE		0
#define	LS_MUTEX_ENTER_BLOCK		1
#define	LS_MUTEX_ENTER_SPIN		2
#define	LS_MUTEX_EXIT_RELEASE		3
#define	LS_MUTEX_DESTROY_RELEASE	4
#define	LS_MUTEX_TRYENTER_ACQUIRE	5
#define	LS_LOCK_SET_ACQUIRE		6
#define	LS_LOCK_SET_SPIN		7
#define	LS_LOCK_SET_SPL_ACQUIRE		8
#define	LS_LOCK_SET_SPL_SPIN		9
#define	LS_LOCK_TRY_ACQUIRE		10
#define	LS_LOCK_CLEAR_RELEASE		11
#define	LS_LOCK_CLEAR_SPLX_RELEASE	12
#define	LS_CLOCK_UNLOCK_RELEASE		13
#define	LS_RW_ENTER_ACQUIRE		14
#define	LS_RW_ENTER_BLOCK		15
#define	LS_RW_EXIT_RELEASE		16
#define	LS_RW_TRYENTER_ACQUIRE		17
#define	LS_RW_TRYUPGRADE_UPGRADE	18
#define	LS_RW_DOWNGRADE_DOWNGRADE	19
#define	LS_THREAD_LOCK_ACQUIRE		20
#define	LS_THREAD_LOCK_SPIN		21
#define	LS_THREAD_LOCK_HIGH_ACQUIRE	22
#define	LS_THREAD_LOCK_HIGH_SPIN	23
#define	LS_TURNSTILE_INTERLOCK_SPIN	24
#define	LS_NPROBES			25

#define	LS_MUTEX_ENTER			"mutex_enter"
#define	LS_MUTEX_EXIT			"mutex_exit"
#define	LS_MUTEX_DESTROY		"mutex_destroy"
#define	LS_MUTEX_TRYENTER		"mutex_tryenter"
#define	LS_LOCK_SET			"lock_set"
#define	LS_LOCK_SET_SPL			"lock_set_spl"
#define	LS_LOCK_TRY			"lock_try"
#define	LS_LOCK_CLEAR			"lock_clear"
#define	LS_LOCK_CLEAR_SPLX		"lock_clear_splx"
#define	LS_CLOCK_UNLOCK			"CLOCK_UNLOCK"
#define	LS_RW_ENTER			"rw_enter"
#define	LS_RW_EXIT			"rw_exit"
#define	LS_RW_TRYENTER			"rw_tryenter"
#define	LS_RW_TRYUPGRADE		"rw_tryupgrade"
#define	LS_RW_DOWNGRADE			"rw_downgrade"
#define	LS_THREAD_LOCK			"thread_lock"
#define	LS_THREAD_LOCK_HIGH		"thread_lock_high"

#define	LS_ACQUIRE			"acquire"
#define	LS_RELEASE			"release"
#define	LS_SPIN				"spin"
#define	LS_BLOCK			"block"
#define	LS_UPGRADE			"upgrade"
#define	LS_DOWNGRADE			"downgrade"

#define	LS_TYPE_ADAPTIVE		"adaptive"
#define	LS_TYPE_SPIN			"spin"
#define	LS_TYPE_THREAD			"thread"
#define	LS_TYPE_RW			"rw"

#define	LSA_ACQUIRE			(LS_TYPE_ADAPTIVE "-" LS_ACQUIRE)
#define	LSA_RELEASE			(LS_TYPE_ADAPTIVE "-" LS_RELEASE)
#define	LSA_SPIN			(LS_TYPE_ADAPTIVE "-" LS_SPIN)
#define	LSA_BLOCK			(LS_TYPE_ADAPTIVE "-" LS_BLOCK)
#define	LSS_ACQUIRE			(LS_TYPE_SPIN "-" LS_ACQUIRE)
#define	LSS_RELEASE			(LS_TYPE_SPIN "-" LS_RELEASE)
#define	LSS_SPIN			(LS_TYPE_SPIN "-" LS_SPIN)
#define	LSR_ACQUIRE			(LS_TYPE_RW "-" LS_ACQUIRE)
#define	LSR_RELEASE			(LS_TYPE_RW "-" LS_RELEASE)
#define	LSR_BLOCK			(LS_TYPE_RW "-" LS_BLOCK)
#define	LSR_UPGRADE			(LS_TYPE_RW "-" LS_UPGRADE)
#define	LSR_DOWNGRADE			(LS_TYPE_RW "-" LS_DOWNGRADE)
#define	LST_SPIN			(LS_TYPE_THREAD "-" LS_SPIN)

#ifndef _ASM

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/systm.h>
#include <sys/atomic.h>

#ifdef _KERNEL

/*
 * Platform-independent kernel support for the lockstat driver.
 */
extern dtrace_id_t lockstat_probemap[LS_NPROBES];
extern void (*lockstat_probe)(dtrace_id_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);

extern int lockstat_active_threads(void);
extern int lockstat_depth(void);
extern void lockstat_hot_patch(void);

/*
 * Macros to record lockstat probes.
 */

/* used for 32 bit systems to avoid overflow */
#if defined(_ILP32)
#define	CLAMP32(x)	((x) > UINT_MAX ? UINT_MAX : (x))
#else
#define	CLAMP32(x)	(x)
#endif

#define	LOCKSTAT_RECORD4(probe, lp, arg0, arg1, arg2, arg3)		\
	if (lockstat_probemap[(probe)]) {				\
		dtrace_id_t id;						\
		curthread->t_lockstat++;				\
		membar_enter();						\
		if ((id = lockstat_probemap[(probe)]) != 0)		\
			(*lockstat_probe)(id, (uintptr_t)(lp), (arg0),	\
			    (arg1), (arg2), (arg3));			\
		curthread->t_lockstat--;				\
	}

#define	LOCKSTAT_RECORD(probe, lp, arg)	\
	LOCKSTAT_RECORD4(probe, lp, arg, 0, 0, 0)

#define	LOCKSTAT_RECORD0(probe, lp)	\
	LOCKSTAT_RECORD4(probe, lp, 0, 0, 0, 0)

/*
 * Return timestamp for start of busy-waiting (for spin probes)
 */
#define	LOCKSTAT_START_TIME(probe)	(			\
	lockstat_probemap[(probe)] ? gethrtime_waitfree() : 0	\
)

/*
 * Record elapsed time since LOCKSTAT_START_TIME was called if the
 * probe is enabled at start and end, else return 0. t_start must
 * be the value returned by LOCKSTAT_START_TIME.
 */
#define	LOCKSTAT_RECORD_TIME(probe, lp, t_start)		\
	if (lockstat_probemap[(probe)]) {				\
		dtrace_id_t id;						\
		hrtime_t t_spin = (t_start);				\
		curthread->t_lockstat++;				\
		membar_enter();						\
		if ((id = lockstat_probemap[(probe)]) != 0) {		\
			if (t_spin) {					\
				t_spin = gethrtime_waitfree() - t_spin;	\
				t_spin = CLAMP32(t_spin);		\
			} 						\
			(*lockstat_probe)(id, (uintptr_t)(lp), t_spin,	\
			0, 0, 0);					\
		} 							\
		curthread->t_lockstat--;				\
	}


#endif /* _KERNEL */

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LOCKSTAT_H */
