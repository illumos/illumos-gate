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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/ftrace.h>

/*
 * Tunable parameters:
 *
 * ftrace_atboot	- whether to start fast tracing at boot.
 * ftrace_nent		- size of the per-CPU event ring buffer.
 */
int ftrace_atboot = 0;
int ftrace_nent = FTRACE_NENT;

/*
 * The current overall state of the ftrace subsystem.
 * If FTRACE_READY is set, then tracing can be enabled.
 * If FTRACE_ENABLED is set, tracing is enabled on the set of CPUs
 *   which are currently FTRACE_READY.
 */
static int ftrace_state = 0;

/*
 * Protects assignments to:
 *   ftrace_state
 *   cpu[N]->cpu_ftrace.ftd_state
 *   cpu[N]->cpu_ftrace.ftd_cur
 *   cpu[N]->cpu_ftrace.ftd_first
 *   cpu[N]->cpu_ftrace.ftd_last
 * Does _not_ protect readers of cpu[N]->cpu_ftrace.ftd_state.
 * Does not protect reading the FTRACE_READY bit in ftrace_state,
 *   since non-READY to READY is a stable transition.  This is used
 *   to ensure ftrace_init() has been called.
 */
static kmutex_t ftrace_lock;

/*
 * Check whether a CPU is installed.
 */
#define	IS_CPU(i) (cpu[i] != NULL)

static void
ftrace_cpu_init(int cpuid)
{
	ftrace_data_t *ftd;

	/*
	 * This can be called with "cpu[cpuid]->cpu_flags & CPU_EXISTS"
	 * being false - e.g. when a CPU is DR'ed in.
	 */
	ASSERT(MUTEX_HELD(&ftrace_lock));
	ASSERT(IS_CPU(cpuid));

	ftd = &cpu[cpuid]->cpu_ftrace;
	if (ftd->ftd_state & FTRACE_READY)
		return;

	/*
	 * We don't allocate the buffers until the first time
	 *   ftrace_cpu_start() is called, so that they're not
	 *   allocated if ftrace is never enabled.
	 */
	ftd->ftd_state |= FTRACE_READY;
	ASSERT(!(ftd->ftd_state & FTRACE_ENABLED));
}

/*
 * Only called from cpu_unconfigure() (and cpu_configure() on error).
 * At this point, cpu[cpuid] is about to be freed and NULLed out,
 *   so we'd better clean up after ourselves.
 */
static void
ftrace_cpu_fini(int cpuid)
{
	ftrace_data_t *ftd;

	ASSERT(MUTEX_HELD(&ftrace_lock));
	ASSERT(IS_CPU(cpuid));
	ASSERT((cpu[cpuid]->cpu_flags & CPU_POWEROFF) != 0);

	ftd = &cpu[cpuid]->cpu_ftrace;
	if (!(ftd->ftd_state & FTRACE_READY))
		return;

	/*
	 * Do not free mutex and the the trace buffer once they are
	 * allocated. A thread, preempted from the now powered-off CPU
	 * may be holding the mutex and in the middle of adding a trace
	 * record.
	 */
}

static void
ftrace_cpu_start(int cpuid)
{
	ftrace_data_t *ftd;

	ASSERT(MUTEX_HELD(&ftrace_lock));
	ASSERT(IS_CPU(cpuid));
	ASSERT(ftrace_state & FTRACE_ENABLED);

	ftd = &cpu[cpuid]->cpu_ftrace;
	if (ftd->ftd_state & FTRACE_READY) {
		if (ftd->ftd_first == NULL) {
			ftrace_record_t *ptrs;

			mutex_init(&ftd->ftd_mutex, NULL, MUTEX_DEFAULT, NULL);
			mutex_exit(&ftrace_lock);
			ptrs = kmem_zalloc(ftrace_nent *
			    sizeof (ftrace_record_t), KM_SLEEP);
			mutex_enter(&ftrace_lock);

			ftd->ftd_first = ptrs;
			ftd->ftd_last = ptrs + (ftrace_nent - 1);
			ftd->ftd_cur = ptrs;
			membar_producer();
		}
		ftd->ftd_state |= FTRACE_ENABLED;
	}
}

static void
ftrace_cpu_stop(int cpuid)
{
	ASSERT(MUTEX_HELD(&ftrace_lock));
	ASSERT(IS_CPU(cpuid));
	cpu[cpuid]->cpu_ftrace.ftd_state &= ~(FTRACE_ENABLED);
}

/*
 * Hook for DR.
 */
/*ARGSUSED*/
int
ftrace_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	if (!(ftrace_state & FTRACE_READY))
		return (0);

	switch (what) {
	case CPU_CONFIG:
		mutex_enter(&ftrace_lock);
		ftrace_cpu_init(id);
		if (ftrace_state & FTRACE_ENABLED)
			ftrace_cpu_start(id);
		mutex_exit(&ftrace_lock);
		break;

	case CPU_UNCONFIG:
		mutex_enter(&ftrace_lock);
		ftrace_cpu_fini(id);
		mutex_exit(&ftrace_lock);
		break;

	default:
		break;
	}
	return (0);
}

void
ftrace_init(void)
{
	int i;

	ASSERT(!(ftrace_state & FTRACE_READY));
	mutex_init(&ftrace_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_enter(&ftrace_lock);
	for (i = 0; i < NCPU; i++) {
		if (IS_CPU(i)) {
			/* should have been kmem_zalloc()'ed */
			ASSERT(cpu[i]->cpu_ftrace.ftd_state == 0);
			ASSERT(cpu[i]->cpu_ftrace.ftd_first == NULL);
			ASSERT(cpu[i]->cpu_ftrace.ftd_last == NULL);
			ASSERT(cpu[i]->cpu_ftrace.ftd_cur == NULL);
		}
	}

	if (ftrace_nent < 1) {
		mutex_exit(&ftrace_lock);
		return;
	}

	for (i = 0; i < NCPU; i++)
		if (IS_CPU(i))
			ftrace_cpu_init(i);

	ftrace_state |= FTRACE_READY;
	mutex_enter(&cpu_lock);
	register_cpu_setup_func(ftrace_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
	mutex_exit(&ftrace_lock);

	if (ftrace_atboot)
		(void) ftrace_start();
}

int
ftrace_start(void)
{
	int i, was_enabled = 0;

	if (ftrace_state & FTRACE_READY) {
		mutex_enter(&ftrace_lock);
		was_enabled = ((ftrace_state & FTRACE_ENABLED) != 0);
		ftrace_state |= FTRACE_ENABLED;
		for (i = 0; i < NCPU; i++)
			if (IS_CPU(i))
				ftrace_cpu_start(i);
		mutex_exit(&ftrace_lock);
	}

	return (was_enabled);
}

int
ftrace_stop(void)
{
	int i, was_enabled = 0;

	if (ftrace_state & FTRACE_READY) {
		mutex_enter(&ftrace_lock);
		if (ftrace_state & FTRACE_ENABLED) {
			was_enabled = 1;
			for (i = 0; i < NCPU; i++)
				if (IS_CPU(i))
					ftrace_cpu_stop(i);
			ftrace_state &= ~(FTRACE_ENABLED);
		}
		mutex_exit(&ftrace_lock);
	}
	return (was_enabled);
}

void
ftrace_0(char *str)
{
	ftrace_record_t *r;
	struct cpu *cp = CPU;
	ftrace_data_t *ftd = &cp->cpu_ftrace;

	if (mutex_tryenter(&ftd->ftd_mutex) == 0) {
		if (CPU_ON_INTR(cp))
			return;
		else
			mutex_enter(&ftd->ftd_mutex);
	}
	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = gethrtime_unscaled();
	r->ftr_caller = caller();

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;
	mutex_exit(&ftd->ftd_mutex);
}

void
ftrace_1(char *str, ulong_t arg1)
{
	ftrace_record_t *r;
	struct cpu *cp = CPU;
	ftrace_data_t *ftd = &cp->cpu_ftrace;

	if (mutex_tryenter(&ftd->ftd_mutex) == 0) {
		if (CPU_ON_INTR(cp))
			return;
		else
			mutex_enter(&ftd->ftd_mutex);
	}
	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = gethrtime_unscaled();
	r->ftr_caller = caller();
	r->ftr_data1 = arg1;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;
	mutex_exit(&ftd->ftd_mutex);
}

void
ftrace_2(char *str, ulong_t arg1, ulong_t arg2)
{
	ftrace_record_t *r;
	struct cpu *cp = CPU;
	ftrace_data_t *ftd = &cp->cpu_ftrace;

	if (mutex_tryenter(&ftd->ftd_mutex) == 0) {
		if (CPU_ON_INTR(cp))
			return;
		else
			mutex_enter(&ftd->ftd_mutex);
	}
	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = gethrtime_unscaled();
	r->ftr_caller = caller();
	r->ftr_data1 = arg1;
	r->ftr_data2 = arg2;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;
	mutex_exit(&ftd->ftd_mutex);
}

void
ftrace_3(char *str, ulong_t arg1, ulong_t arg2, ulong_t arg3)
{
	ftrace_record_t *r;
	struct cpu *cp = CPU;
	ftrace_data_t *ftd = &cp->cpu_ftrace;

	if (mutex_tryenter(&ftd->ftd_mutex) == 0) {
		if (CPU_ON_INTR(cp))
			return;
		else
			mutex_enter(&ftd->ftd_mutex);
	}
	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = gethrtime_unscaled();
	r->ftr_caller = caller();
	r->ftr_data1 = arg1;
	r->ftr_data2 = arg2;
	r->ftr_data3 = arg3;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;
	mutex_exit(&ftd->ftd_mutex);
}

void
ftrace_3_notick(char *str, ulong_t arg1, ulong_t arg2, ulong_t arg3)
{
	ftrace_record_t *r;
	struct cpu *cp = CPU;
	ftrace_data_t *ftd = &cp->cpu_ftrace;

	if (mutex_tryenter(&ftd->ftd_mutex) == 0) {
		if (CPU_ON_INTR(cp))
			return;
		else
			mutex_enter(&ftd->ftd_mutex);
	}
	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = 0;
	r->ftr_caller = caller();
	r->ftr_data1 = arg1;
	r->ftr_data2 = arg2;
	r->ftr_data3 = arg3;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;
	mutex_exit(&ftd->ftd_mutex);
}
