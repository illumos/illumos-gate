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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
 * Global Tracing State:
 *
 *                NOTREADY(=0)
 *                  |
 *            ftrace_init()
 *                  |
 *                  |
 *                  v
 *      +-------->READY-------+
 *      |                     |
 *  ftrace_stop()         ftrace_start()
 *      |                     |
 *      +---(ENABLED|READY)<--+
 *
 * During boot, ftrace_init() is called and the state becomes
 * READY. If ftrace_atboot is set, ftrace_start() is called at
 * this time.
 *
 * If FTRACE_READY is set, then tracing can be enabled.
 * If FTRACE_ENABLED is set, tracing is enabled on the set of CPUs
 *   which are currently FTRACE_READY.
 */
static int ftrace_state = 0;

/*
 * Per-CPU Tracing State:
 *
 *     +-----------------READY<--------------+
 *     |                 ^   |               |
 *     |                 | ftrace_cpu_fini() |
 *     |                 |   |               |
 *     |   ftrace_cpu_init() |               |
 *     |                 |   v     ftrace_cpu_stop()
 *     |              NOTREADY(=0)           |
 *     |                   ^                 |
 * ftrace_cpu_start()      |                 |
 *     |              ftrace_cpu_fini()      |
 *     |                   |                 |
 *     +----------->(ENABLED|READY)----------+
 *
 */

/*
 * Locking :
 *
 * Trace context code does not use any lock. There is a per-cpu circular trace
 * buffer that has a head, a tail and a current pointer. Each record of this
 * buffer is of equal length. Before doing anything, trace context code checks
 * the per-cpu ENABLED bit. Trace buffer is allocated in non-trace context and
 * it sets this bit only after allocating and setting up the buffer. So trace
 * context code can't access the buffer till it is set up completely. The
 * buffer is freed also in non-trace context. The code that frees the buffer is
 * executed only after the corresponding cpu is powered off. So when this
 * happens, no trace context code can be running on it. We only need to make
 * sure that trace context code is not preempted from the cpu in the middle of
 * accessing the trace buffer. This can be achieved simply by disabling
 * interrupts temporarily. This approach makes the least assumption about the
 * state of the callers of tracing functions.
 *
 * A single global lock, ftrace_lock protects assignments to all global and
 * per-cpu trace variables. It does not protect reading of those in some cases.
 *
 * More specifically, it protects assignments to:
 *
 *   ftrace_state
 *   cpu[N]->cpu_ftrace.ftd_state
 *   cpu[N]->cpu_ftrace.ftd_first
 *   cpu[N]->cpu_ftrace.ftd_last
 *
 * Does _not_ protect reading of cpu[N]->cpu_ftrace.ftd_state
 * Does _not_ protect cpu[N]->cpu_ftrace.ftd_cur
 * Does _not_ protect reading of ftrace_state
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
	 * This cpu is powered off and no code can be executing on it. So
	 * we can simply finish our cleanup. There is no need for a xcall
	 * to make sure that this cpu is out of trace context.
	 *
	 * The cpu structure will be cleared soon. But, for the sake of
	 * debugging, clear our pointers and state.
	 */
	if (ftd->ftd_first != NULL) {
		kmem_free(ftd->ftd_first,
		    ftrace_nent * sizeof (ftrace_record_t));
	}
	bzero(ftd, sizeof (ftrace_data_t));
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

			mutex_exit(&ftrace_lock);
			ptrs = kmem_zalloc(ftrace_nent *
			    sizeof (ftrace_record_t), KM_SLEEP);
			mutex_enter(&ftrace_lock);
			if (ftd->ftd_first != NULL) {
				/*
				 * Someone else beat us to it. The winner will
				 * set up the pointers and the state.
				 */
				kmem_free(ptrs,
				    ftrace_nent * sizeof (ftrace_record_t));
				return;
			}

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

/*
 * Called from uadmin ioctl, or via mp_init_table[] during boot.
 */
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

/*
 * Called from uadmin ioctl, to stop tracing.
 */
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

/*
 * ftrace_X() functions are called from trace context. All callers of ftrace_X()
 * tests FTRACE_ENABLED first. Although this is not very accurate, it keeps the
 * overhead very low when tracing is not enabled.
 *
 * gethrtime_unscaled() appears to be safe to be called in trace context. As an
 * added precaution, we call these before we disable interrupts on this cpu.
 */

void
ftrace_0(char *str, caddr_t caller)
{
	ftrace_record_t *r;
	struct cpu *cp;
	ftrace_data_t *ftd;
	ftrace_icookie_t cookie;
	hrtime_t  timestamp;

	timestamp = gethrtime_unscaled();

	cookie = ftrace_interrupt_disable();

	cp = CPU;
	ftd = &cp->cpu_ftrace;

	if (!(ftd->ftd_state & FTRACE_ENABLED)) {
		ftrace_interrupt_enable(cookie);
		return;
	}

	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = timestamp;
	r->ftr_caller = caller;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;

	ftrace_interrupt_enable(cookie);
}

void
ftrace_1(char *str, ulong_t arg1, caddr_t caller)
{
	ftrace_record_t *r;
	struct cpu *cp;
	ftrace_data_t *ftd;
	ftrace_icookie_t cookie;
	hrtime_t  timestamp;

	timestamp = gethrtime_unscaled();

	cookie = ftrace_interrupt_disable();

	cp = CPU;
	ftd = &cp->cpu_ftrace;

	if (!(ftd->ftd_state & FTRACE_ENABLED)) {
		ftrace_interrupt_enable(cookie);
		return;
	}

	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = timestamp;
	r->ftr_caller = caller;
	r->ftr_data1 = arg1;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;

	ftrace_interrupt_enable(cookie);
}

void
ftrace_2(char *str, ulong_t arg1, ulong_t arg2, caddr_t caller)
{
	ftrace_record_t *r;
	struct cpu *cp;
	ftrace_data_t *ftd;
	ftrace_icookie_t cookie;
	hrtime_t  timestamp;

	timestamp = gethrtime_unscaled();

	cookie = ftrace_interrupt_disable();

	cp = CPU;
	ftd = &cp->cpu_ftrace;

	if (!(ftd->ftd_state & FTRACE_ENABLED)) {
		ftrace_interrupt_enable(cookie);
		return;
	}

	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = timestamp;
	r->ftr_caller = caller;
	r->ftr_data1 = arg1;
	r->ftr_data2 = arg2;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;

	ftrace_interrupt_enable(cookie);
}

void
ftrace_3(char *str, ulong_t arg1, ulong_t arg2, ulong_t arg3, caddr_t caller)
{
	ftrace_record_t *r;
	struct cpu *cp;
	ftrace_data_t *ftd;
	ftrace_icookie_t cookie;
	hrtime_t  timestamp;

	timestamp = gethrtime_unscaled();

	cookie = ftrace_interrupt_disable();

	cp = CPU;
	ftd = &cp->cpu_ftrace;

	if (!(ftd->ftd_state & FTRACE_ENABLED)) {
		ftrace_interrupt_enable(cookie);
		return;
	}

	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = timestamp;
	r->ftr_caller = caller;
	r->ftr_data1 = arg1;
	r->ftr_data2 = arg2;
	r->ftr_data3 = arg3;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;

	ftrace_interrupt_enable(cookie);
}

void
ftrace_3_notick(char *str, ulong_t arg1, ulong_t arg2,
    ulong_t arg3, caddr_t caller)
{
	ftrace_record_t *r;
	struct cpu *cp;
	ftrace_data_t *ftd;
	ftrace_icookie_t cookie;

	cookie = ftrace_interrupt_disable();

	cp = CPU;
	ftd = &cp->cpu_ftrace;

	if (!(ftd->ftd_state & FTRACE_ENABLED)) {
		ftrace_interrupt_enable(cookie);
		return;
	}

	r = ftd->ftd_cur;
	r->ftr_event = str;
	r->ftr_thread = curthread;
	r->ftr_tick = 0;
	r->ftr_caller = caller;
	r->ftr_data1 = arg1;
	r->ftr_data2 = arg2;
	r->ftr_data3 = arg3;

	if (r++ == ftd->ftd_last)
		r = ftd->ftd_first;
	ftd->ftd_cur = r;

	ftrace_interrupt_enable(cookie);
}
