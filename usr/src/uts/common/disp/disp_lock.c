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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/inline.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/vtrace.h>
#include <sys/lockstat.h>
#include <sys/spl.h>
#include <sys/atomic.h>
#include <sys/cpu.h>

/*
 * We check CPU_ON_INTR(CPU) when exiting a disp lock, rather than when
 * entering it, for a purely pragmatic reason: when exiting a disp lock
 * we know that we must be at PIL 10, and thus not preemptible; therefore
 * we can safely load the CPU pointer without worrying about it changing.
 */
static void
disp_onintr_panic(void)
{
	panic("dispatcher invoked from high-level interrupt handler");
}

/* ARGSUSED */
void
disp_lock_init(disp_lock_t *lp, char *name)
{
	DISP_LOCK_INIT(lp);
}

/* ARGSUSED */
void
disp_lock_destroy(disp_lock_t *lp)
{
	DISP_LOCK_DESTROY(lp);
}

void
disp_lock_enter_high(disp_lock_t *lp)
{
	lock_set(lp);
}

void
disp_lock_exit_high(disp_lock_t *lp)
{
	if (CPU_ON_INTR(CPU) != 0)
		disp_onintr_panic();
	ASSERT(DISP_LOCK_HELD(lp));
	lock_clear(lp);
}

void
disp_lock_enter(disp_lock_t *lp)
{
	lock_set_spl(lp, ipltospl(DISP_LEVEL), &curthread->t_oldspl);
}

void
disp_lock_exit(disp_lock_t *lp)
{
	if (CPU_ON_INTR(CPU) != 0)
		disp_onintr_panic();
	ASSERT(DISP_LOCK_HELD(lp));
	if (CPU->cpu_kprunrun) {
		lock_clear_splx(lp, curthread->t_oldspl);
		kpreempt(KPREEMPT_SYNC);
	} else {
		lock_clear_splx(lp, curthread->t_oldspl);
	}
}

void
disp_lock_exit_nopreempt(disp_lock_t *lp)
{
	if (CPU_ON_INTR(CPU) != 0)
		disp_onintr_panic();
	ASSERT(DISP_LOCK_HELD(lp));
	lock_clear_splx(lp, curthread->t_oldspl);
}

/*
 * Thread_lock() - get the correct dispatcher lock for the thread.
 */
void
thread_lock(kthread_id_t t)
{
	int s = splhigh();

	if (CPU_ON_INTR(CPU) != 0)
		disp_onintr_panic();

	for (;;) {
		lock_t *volatile *tlpp = &t->t_lockp;
		lock_t *lp = *tlpp;
		if (lock_try(lp)) {
			if (lp == *tlpp) {
				curthread->t_oldspl = (ushort_t)s;
				return;
			}
			lock_clear(lp);
		} else {
			hrtime_t spin_time =
			    LOCKSTAT_START_TIME(LS_THREAD_LOCK_SPIN);
			/*
			 * Lower spl and spin on lock with non-atomic load
			 * to avoid cache activity.  Spin until the lock
			 * becomes available or spontaneously changes.
			 */
			splx(s);
			while (lp == *tlpp && LOCK_HELD(lp)) {
				if (panicstr) {
					curthread->t_oldspl = splhigh();
					return;
				}
				SMT_PAUSE();
			}

			LOCKSTAT_RECORD_TIME(LS_THREAD_LOCK_SPIN,
			    lp, spin_time);
			s = splhigh();
		}
	}
}

/*
 * Thread_lock_high() - get the correct dispatcher lock for the thread.
 *	This version is called when already at high spl.
 */
void
thread_lock_high(kthread_id_t t)
{
	if (CPU_ON_INTR(CPU) != 0)
		disp_onintr_panic();

	for (;;) {
		lock_t *volatile *tlpp = &t->t_lockp;
		lock_t *lp = *tlpp;
		if (lock_try(lp)) {
			if (lp == *tlpp)
				return;
			lock_clear(lp);
		} else {
			hrtime_t spin_time =
			    LOCKSTAT_START_TIME(LS_THREAD_LOCK_HIGH_SPIN);
			while (lp == *tlpp && LOCK_HELD(lp)) {
				if (panicstr)
					return;
				SMT_PAUSE();
			}
			LOCKSTAT_RECORD_TIME(LS_THREAD_LOCK_HIGH_SPIN,
			    lp, spin_time);
		}
	}
}

/*
 * Called by THREAD_TRANSITION macro to change the thread state to
 * the intermediate state-in-transititon state.
 */
void
thread_transition(kthread_id_t t)
{
	disp_lock_t	*lp;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t->t_lockp != &transition_lock);

	lp = t->t_lockp;
	t->t_lockp = &transition_lock;
	disp_lock_exit_high(lp);
}

/*
 * Put thread in stop state, and set the lock pointer to the stop_lock.
 * This effectively drops the lock on the thread, since the stop_lock
 * isn't held.
 * Eventually, stop_lock could be hashed if there is too much contention.
 */
void
thread_stop(kthread_id_t t)
{
	disp_lock_t	*lp;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t->t_lockp != &stop_lock);

	lp = t->t_lockp;
	t->t_state = TS_STOPPED;
	/*
	 * Ensure that t_state reaches global visibility before t_lockp
	 */
	membar_producer();
	t->t_lockp = &stop_lock;
	disp_lock_exit(lp);
}
