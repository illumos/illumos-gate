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

/*
 * Facilities for cross-processor subroutine calls using "mailbox" interrupts.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <sys/cpu.h>
#include <sys/psw.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/mutex_impl.h>
#include <sys/traptrace.h>


static struct	xc_mbox xc_mboxes[X_CALL_LEVELS];
static kmutex_t xc_mbox_lock[X_CALL_LEVELS];
static uint_t 	xc_xlat_xcptoipl[X_CALL_LEVELS] = {
	XC_LO_PIL,
	XC_MED_PIL,
	XC_HI_PIL
};

static void xc_common(xc_func_t, xc_arg_t, xc_arg_t, xc_arg_t,
    int, cpuset_t, int);

static int	xc_initialized = 0;

void
xc_init()
{
	/*
	 * By making these mutexes type MUTEX_DRIVER, the ones below
	 * LOCK_LEVEL will be implemented as adaptive mutexes, and the
	 * ones above LOCK_LEVEL will be spin mutexes.
	 */
	mutex_init(&xc_mbox_lock[0], NULL, MUTEX_DRIVER,
	    (void *)ipltospl(XC_LO_PIL));
	mutex_init(&xc_mbox_lock[1], NULL, MUTEX_DRIVER,
	    (void *)ipltospl(XC_MED_PIL));
	mutex_init(&xc_mbox_lock[2], NULL, MUTEX_DRIVER,
	    (void *)ipltospl(XC_HI_PIL));

	xc_initialized = 1;
}

#if defined(TRAPTRACE)

/*
 * When xc_traptrace is on, put x-call records into the trap trace buffer.
 */
int xc_traptrace;

void
xc_make_trap_trace_entry(uint8_t marker, int pri, ulong_t arg)
{
	trap_trace_rec_t *ttr;
	struct _xc_entry *xce;

	if (xc_traptrace == 0)
		return;

	ttr = trap_trace_get_traceptr(TT_XCALL,
	    (ulong_t)caller(), (ulong_t)getfp());
	xce = &(ttr->ttr_info.xc_entry);

	xce->xce_marker = marker;
	xce->xce_pri = pri;
	xce->xce_arg = arg;

	if ((uint_t)pri < X_CALL_LEVELS) {
		struct machcpu *mcpu = &CPU->cpu_m;

		xce->xce_pend = mcpu->xc_pend[pri];
		xce->xce_ack = mcpu->xc_ack[pri];
		xce->xce_state = mcpu->xc_state[pri];
		xce->xce_retval = mcpu->xc_retval[pri];
		xce->xce_func = (uintptr_t)xc_mboxes[pri].func;
	}
}
#endif

#define	CAPTURE_CPU_ARG	~0UL

/*
 * X-call interrupt service routine.
 *
 * arg == X_CALL_MEDPRI	-  capture cpus.
 *
 * We're protected against changing CPUs by being a high-priority interrupt.
 */
/*ARGSUSED*/
uint_t
xc_serv(caddr_t arg1, caddr_t arg2)
{
	int op;
	int pri = (int)(uintptr_t)arg1;
	struct cpu *cpup = CPU;
	xc_arg_t arg2val;

	XC_TRACE(TT_XC_SVC_BEGIN, pri, (ulong_t)arg2);

	if (pri == X_CALL_MEDPRI) {

		arg2val = xc_mboxes[X_CALL_MEDPRI].arg2;

		if (arg2val != CAPTURE_CPU_ARG ||
		    !CPU_IN_SET(xc_mboxes[X_CALL_MEDPRI].set, cpup->cpu_id))
			goto unclaimed;

		ASSERT(arg2val == CAPTURE_CPU_ARG);

		if (cpup->cpu_m.xc_pend[pri] == 0)
			goto unclaimed;

		cpup->cpu_m.xc_pend[X_CALL_MEDPRI] = 0;
		cpup->cpu_m.xc_ack[X_CALL_MEDPRI] = 1;

		for (;;) {
			if ((cpup->cpu_m.xc_state[X_CALL_MEDPRI] == XC_DONE) ||
			    (cpup->cpu_m.xc_pend[X_CALL_MEDPRI]))
				break;
			SMT_PAUSE();
		}
		CPUSET_DEL(xc_mboxes[X_CALL_MEDPRI].set, cpup->cpu_id);
		XC_TRACE(TT_XC_SVC_END, pri, DDI_INTR_CLAIMED);
		return (DDI_INTR_CLAIMED);
	}

	if (cpup->cpu_m.xc_pend[pri] == 0)
		goto unclaimed;

	cpup->cpu_m.xc_pend[pri] = 0;
	op = cpup->cpu_m.xc_state[pri];

	/*
	 * Don't invoke a null function.
	 */
	if (xc_mboxes[pri].func != NULL) {
		cpup->cpu_m.xc_retval[pri] =
		    (*xc_mboxes[pri].func)(xc_mboxes[pri].arg1,
		    xc_mboxes[pri].arg2, xc_mboxes[pri].arg3);
	} else
		cpup->cpu_m.xc_retval[pri] = 0;

	/*
	 * Acknowledge that we have completed the x-call operation.
	 */
	cpup->cpu_m.xc_ack[pri] = 1;

	if (op != XC_CALL_OP) {
		/*
		 * for (op == XC_SYNC_OP)
		 * Wait for the initiator of the x-call to indicate
		 * that all CPUs involved can proceed.
		 */
		while (cpup->cpu_m.xc_wait[pri])
			SMT_PAUSE();

		while (cpup->cpu_m.xc_state[pri] != XC_DONE)
			SMT_PAUSE();

		/*
		 * Acknowledge that we have received the directive to continue.
		 */
		ASSERT(cpup->cpu_m.xc_ack[pri] == 0);
		cpup->cpu_m.xc_ack[pri] = 1;
	}

	XC_TRACE(TT_XC_SVC_END, pri, DDI_INTR_CLAIMED);
	return (DDI_INTR_CLAIMED);

unclaimed:
	XC_TRACE(TT_XC_SVC_END, pri, DDI_INTR_UNCLAIMED);
	return (DDI_INTR_UNCLAIMED);
}


/*
 * xc_do_call:
 */
static void
xc_do_call(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	int pri,
	cpuset_t set,
	xc_func_t func,
	int sync)
{
	/*
	 * If the pri indicates a low priority lock (below LOCK_LEVEL),
	 * we must disable preemption to avoid migrating to another CPU
	 * during the call.
	 */
	if (pri == X_CALL_LOPRI) {
		kpreempt_disable();
	} else {
		pri = X_CALL_HIPRI;
	}

	/* always grab highest mutex to avoid deadlock */
	mutex_enter(&xc_mbox_lock[X_CALL_HIPRI]);
	xc_common(func, arg1, arg2, arg3, pri, set, sync);
	mutex_exit(&xc_mbox_lock[X_CALL_HIPRI]);
	if (pri == X_CALL_LOPRI)
		kpreempt_enable();
}


/*
 * xc_call: call specified function on all processors
 * remotes may continue after service
 * we wait here until everybody has completed.
 */
void
xc_call(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	int pri,
	cpuset_t set,
	xc_func_t func)
{
	xc_do_call(arg1, arg2, arg3, pri, set, func, 0);
}

/*
 * xc_sync: call specified function on all processors
 * after doing work, each remote waits until we let
 * it continue; send the contiunue after everyone has
 * informed us that they are done.
 */
void
xc_sync(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	int pri,
	cpuset_t set,
	xc_func_t func)
{
	xc_do_call(arg1, arg2, arg3, pri, set, func, 1);
}

/*
 * The routines xc_capture_cpus and xc_release_cpus
 * can be used in place of xc_sync in order to implement a critical
 * code section where all CPUs in the system can be controlled.
 * xc_capture_cpus is used to start the critical code section, and
 * xc_release_cpus is used to end the critical code section.
 */

/*
 * Capture the CPUs specified in order to start a x-call session,
 * and/or to begin a critical section.
 */
void
xc_capture_cpus(cpuset_t set)
{
	int cix;
	int lcx;
	struct cpu *cpup;
	int	i;

	CPU_STATS_ADDQ(CPU, sys, xcalls, 1);

	/*
	 * Prevent deadlocks where we take an interrupt and are waiting
	 * for a mutex owned by one of the CPUs that is captured for
	 * the x-call, while that CPU is waiting for some x-call signal
	 * to be set by us.
	 *
	 * This mutex also prevents preemption, since it raises SPL above
	 * LOCK_LEVEL (it is a spin-type driver mutex).
	 */
	/* always grab highest mutex to avoid deadlock */
	mutex_enter(&xc_mbox_lock[X_CALL_HIPRI]);
	lcx = CPU->cpu_id;	/* now we're safe */

	ASSERT(CPU->cpu_flags & CPU_READY);

	/*
	 * Wait for all cpus.
	 */

	/*
	 * First remove ourself.
	 */
	if (CPU_IN_SET(xc_mboxes[X_CALL_MEDPRI].set, CPU->cpu_id))
		CPUSET_ATOMIC_DEL(xc_mboxes[X_CALL_MEDPRI].set, CPU->cpu_id);
	/*
	 * We must wait for all cpus to clear their bit from
	 * xc_mboxes[X_CALL_MEDPRI].set before we write to this set.
	 */
	for (;;) {
		CPUSET_AND(xc_mboxes[X_CALL_MEDPRI].set, cpu_ready_set);
		if (CPUSET_ISNULL(xc_mboxes[X_CALL_MEDPRI].set))
			break;
		SMT_PAUSE();
	}

	/*
	 * Store the set of CPUs involved in the x-call session, so that
	 * xc_release_cpus will know what CPUs to act upon.
	 */
	xc_mboxes[X_CALL_MEDPRI].set = set;
	xc_mboxes[X_CALL_MEDPRI].arg2 = CAPTURE_CPU_ARG;

	/*
	 * Now capture each CPU in the set and cause it to go into a
	 * holding pattern.
	 */
	i = 0;
	for (cix = 0; cix < NCPU; cix++) {
		if ((cpup = cpu[cix]) == NULL ||
		    (cpup->cpu_flags & CPU_READY) == 0) {
			/*
			 * In case CPU wasn't ready, but becomes ready later,
			 * take the CPU out of the set now.
			 */
			CPUSET_DEL(set, cix);
			continue;
		}
		if (cix != lcx && CPU_IN_SET(set, cix)) {
			cpup->cpu_m.xc_ack[X_CALL_MEDPRI] = 0;
			cpup->cpu_m.xc_state[X_CALL_MEDPRI] = XC_HOLD;
			cpup->cpu_m.xc_pend[X_CALL_MEDPRI] = 1;
			XC_TRACE(TT_XC_CAPTURE, X_CALL_MEDPRI, cix);
			send_dirint(cix, XC_MED_PIL);
		}
		i++;
		if (i >= ncpus)
			break;
	}

	/*
	 * Wait here until all remote calls to acknowledge.
	 */
	i = 0;
	for (cix = 0; cix < NCPU; cix++) {
		if (lcx != cix && CPU_IN_SET(set, cix)) {
			cpup = cpu[cix];
			while (cpup->cpu_m.xc_ack[X_CALL_MEDPRI] == 0)
				SMT_PAUSE();
			cpup->cpu_m.xc_ack[X_CALL_MEDPRI] = 0;
		}
		i++;
		if (i >= ncpus)
			break;
	}

}

/*
 * Release the CPUs captured by xc_capture_cpus, thus terminating the
 * x-call session and exiting the critical section.
 */
void
xc_release_cpus(void)
{
	int cix;
	int lcx = (int)(CPU->cpu_id);
	cpuset_t set = xc_mboxes[X_CALL_MEDPRI].set;
	struct cpu *cpup;
	int	i;

	ASSERT(MUTEX_HELD(&xc_mbox_lock[X_CALL_HIPRI]));

	/*
	 * Allow each CPU to exit its holding pattern.
	 */
	i = 0;
	for (cix = 0; cix < NCPU; cix++) {
		if ((cpup = cpu[cix]) == NULL)
			continue;
		if ((cpup->cpu_flags & CPU_READY) &&
		    (cix != lcx) && CPU_IN_SET(set, cix)) {
			/*
			 * Clear xc_ack since we will be waiting for it
			 * to be set again after we set XC_DONE.
			 */
			XC_TRACE(TT_XC_RELEASE, X_CALL_MEDPRI, cix);
			cpup->cpu_m.xc_state[X_CALL_MEDPRI] = XC_DONE;
		}
		i++;
		if (i >= ncpus)
			break;
	}

	xc_mboxes[X_CALL_MEDPRI].arg2 = 0;
	mutex_exit(&xc_mbox_lock[X_CALL_HIPRI]);
}

/*
 * Common code to call a specified function on a set of processors.
 * sync specifies what kind of waiting is done.
 *	-1 - no waiting, don't release remotes
 *	0 - no waiting, release remotes immediately
 *	1 - run service locally w/o waiting for remotes.
 */
static void
xc_common(
	xc_func_t func,
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	int pri,
	cpuset_t set,
	int sync)
{
	int cix;
	int do_local = 0;
	struct cpu *cpup;
	cpuset_t tset;
	int last_cpu = 0;

	ASSERT(panicstr == NULL);

	ASSERT(MUTEX_HELD(&xc_mbox_lock[X_CALL_HIPRI]));
	ASSERT(CPU->cpu_flags & CPU_READY);

	/*
	 * Set up the service definition mailbox.
	 */
	xc_mboxes[pri].func = func;
	xc_mboxes[pri].arg1 = arg1;
	xc_mboxes[pri].arg2 = arg2;
	xc_mboxes[pri].arg3 = arg3;

	if (CPU_IN_SET(set, CPU->cpu_id)) {
		do_local = 1;
		CPUSET_DEL(set, CPU->cpu_id);
	}

	/*
	 * Request service on all remote processors.
	 */
	tset = set;
	for (cix = 0; cix < max_ncpus; cix++) {
		if (!CPU_IN_SET(tset, cix))
			continue;

		if ((cpup = cpu[cix]) == NULL ||
		    (cpup->cpu_flags & CPU_READY) == 0) {
			/*
			 * In case the CPU is not ready but becomes
			 * ready later, take it out of the set now.
			 */
			CPUSET_DEL(set, cix);
		} else {
			CPU_STATS_ADDQ(CPU, sys, xcalls, 1);
			cpup->cpu_m.xc_ack[pri] = 0;
			cpup->cpu_m.xc_wait[pri] = sync;
			if (sync > 0)
				cpup->cpu_m.xc_state[pri] = XC_SYNC_OP;
			else
				cpup->cpu_m.xc_state[pri] = XC_CALL_OP;
			cpup->cpu_m.xc_pend[pri] = 1;
			XC_TRACE(TT_XC_START, pri, cix);
			send_dirint(cix, xc_xlat_xcptoipl[pri]);
			last_cpu = cix;
		}

		CPUSET_DEL(tset, cix);
		if (CPUSET_ISNULL(tset))
			break;
	}

	/*
	 * Run service locally
	 */
	if (do_local && func != NULL) {
		XC_TRACE(TT_XC_START, pri, CPU->cpu_id);
		CPU->cpu_m.xc_retval[pri] = (*func)(arg1, arg2, arg3);
	}

	if (sync == -1)
		return;

	/*
	 * Wait here until all remote calls acknowledge.
	 */
	for (cix = 0; cix <= last_cpu; cix++) {
		if (CPU_IN_SET(set, cix)) {
			cpup = cpu[cix];
			while (cpup->cpu_m.xc_ack[pri] == 0)
				SMT_PAUSE();
			XC_TRACE(TT_XC_WAIT, pri, cix);
			cpup->cpu_m.xc_ack[pri] = 0;
		}
	}

	if (sync == 0)
		return;

	/*
	 * Release any waiting CPUs
	 */
	for (cix = 0; cix <= last_cpu; cix++) {
		if (CPU_IN_SET(set, cix)) {
			cpup = cpu[cix];
			if (cpup != NULL && (cpup->cpu_flags & CPU_READY)) {
				cpup->cpu_m.xc_wait[pri] = 0;
				cpup->cpu_m.xc_state[pri] = XC_DONE;
			}
		}
	}

	/*
	 * Wait for all CPUs to acknowledge completion before we continue.
	 * Without this check it's possible (on a VM or hyper-threaded CPUs
	 * or in the presence of Service Management Interrupts which can all
	 * cause delays) for the remote processor to still be waiting by
	 * the time xc_common() is next invoked with the sync flag set
	 * resulting in a deadlock.
	 */
	for (cix = 0; cix <= last_cpu; cix++) {
		if (CPU_IN_SET(set, cix)) {
			cpup = cpu[cix];
			if (cpup != NULL && (cpup->cpu_flags & CPU_READY)) {
				while (cpup->cpu_m.xc_ack[pri] == 0)
					SMT_PAUSE();
				XC_TRACE(TT_XC_ACK, pri, cix);
				cpup->cpu_m.xc_ack[pri] = 0;
			}
		}
	}
}

/*
 * xc_trycall: attempt to call specified function on all processors
 * remotes may wait for a long time
 * we continue immediately
 */
void
xc_trycall(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	cpuset_t set,
	xc_func_t func)
{
	int		save_kernel_preemption;
	extern int	IGNORE_KERNEL_PREEMPTION;

	/*
	 * If we can grab the mutex, we'll do the cross-call.  If not -- if
	 * someone else is already doing a cross-call -- we won't.
	 */

	save_kernel_preemption = IGNORE_KERNEL_PREEMPTION;
	IGNORE_KERNEL_PREEMPTION = 1;
	if (mutex_tryenter(&xc_mbox_lock[X_CALL_HIPRI])) {
		xc_common(func, arg1, arg2, arg3, X_CALL_HIPRI, set, -1);
		mutex_exit(&xc_mbox_lock[X_CALL_HIPRI]);
	}
	IGNORE_KERNEL_PREEMPTION = save_kernel_preemption;
}

/*
 * Used by the debugger to cross-call the other CPUs, thus causing them to
 * enter the debugger.  We can't hold locks, so we spin on the cross-call
 * lock until we get it.  When we get it, we send the cross-call, and assume
 * that we successfully stopped the other CPUs.
 */
void
kdi_xc_others(int this_cpu, void (*func)(void))
{
	extern int	IGNORE_KERNEL_PREEMPTION;
	int save_kernel_preemption;
	mutex_impl_t *lp;
	cpuset_t set;
	int x;

	if (!xc_initialized)
		return;

	CPUSET_ALL_BUT(set, this_cpu);

	save_kernel_preemption = IGNORE_KERNEL_PREEMPTION;
	IGNORE_KERNEL_PREEMPTION = 1;

	lp = (mutex_impl_t *)&xc_mbox_lock[X_CALL_HIPRI];
	for (x = 0; x < 0x400000; x++) {
		if (lock_spin_try(&lp->m_spin.m_spinlock)) {
			xc_common((xc_func_t)func, 0, 0, 0, X_CALL_HIPRI,
			    set, -1);
			lp->m_spin.m_spinlock = 0; /* XXX */
			break;
		}
		SMT_PAUSE();
	}
	IGNORE_KERNEL_PREEMPTION = save_kernel_preemption;
}
