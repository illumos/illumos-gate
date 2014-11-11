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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/membar.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/platform_module.h>
#include <sys/cpuvar.h>
#include <sys/cpu_module.h>
#include <sys/cmp.h>
#include <sys/dumphdr.h>

#include <sys/cpu_sgnblk_defs.h>

static cpuset_t cpu_idle_set;
static kmutex_t cpu_idle_lock;
typedef const char *fn_t;

/*
 * flags to determine if the PROM routines
 * should be used to idle/resume/stop cpus
 */
static int kern_idle[NCPU];		/* kernel's idle loop */
static int cpu_are_paused;
extern void debug_flush_windows();

/*
 * Initialize the idlestop mutex
 */
void
idlestop_init(void)
{
	mutex_init(&cpu_idle_lock, NULL, MUTEX_SPIN, (void *)ipltospl(PIL_15));
}

static void
cpu_idle_self(void)
{
	uint_t s;
	label_t save;

	s = spl8();
	debug_flush_windows();

	CPU->cpu_m.in_prom = 1;
	membar_stld();

	save = curthread->t_pcb;
	(void) setjmp(&curthread->t_pcb);

	kern_idle[CPU->cpu_id] = 1;
	while (kern_idle[CPU->cpu_id])
		dumpsys_helper_nw();

	CPU->cpu_m.in_prom = 0;
	membar_stld();

	curthread->t_pcb = save;
	splx(s);
}

void
idle_other_cpus(void)
{
	int i, cpuid, ntries;
	int failed = 0;

	if (ncpus == 1)
		return;

	mutex_enter(&cpu_idle_lock);

	cpuid = CPU->cpu_id;
	ASSERT(cpuid < NCPU);

	cpu_idle_set = cpu_ready_set;
	CPUSET_DEL(cpu_idle_set, cpuid);

	if (CPUSET_ISNULL(cpu_idle_set))
		return;

	xt_some(cpu_idle_set, (xcfunc_t *)idle_stop_xcall,
	    (uint64_t)cpu_idle_self, NULL);

	for (i = 0; i < NCPU; i++) {
		if (!CPU_IN_SET(cpu_idle_set, i))
			continue;

		ntries = 0x10000;
		while (!cpu[i]->cpu_m.in_prom && ntries) {
			DELAY(50);
			ntries--;
		}

		/*
		 * A cpu failing to idle is an error condition, since
		 * we can't be sure anymore of its state.
		 */
		if (!cpu[i]->cpu_m.in_prom) {
			cmn_err(CE_WARN, "cpuid 0x%x failed to idle", i);
			failed++;
		}
	}

	if (failed) {
		mutex_exit(&cpu_idle_lock);
		cmn_err(CE_PANIC, "idle_other_cpus: not all cpus idled");
	}
}

void
resume_other_cpus(void)
{
	int i, ntries;
	int cpuid = CPU->cpu_id;
	boolean_t failed = B_FALSE;

	if (ncpus == 1)
		return;

	ASSERT(cpuid < NCPU);
	ASSERT(MUTEX_HELD(&cpu_idle_lock));

	for (i = 0; i < NCPU; i++) {
		if (!CPU_IN_SET(cpu_idle_set, i))
			continue;

		kern_idle[i] = 0;
		membar_stld();
	}

	for (i = 0; i < NCPU; i++) {
		if (!CPU_IN_SET(cpu_idle_set, i))
			continue;

		ntries = 0x10000;
		while (cpu[i]->cpu_m.in_prom && ntries) {
			DELAY(50);
			ntries--;
		}

		/*
		 * A cpu failing to resume is an error condition, since
		 * intrs may have been directed there.
		 */
		if (cpu[i]->cpu_m.in_prom) {
			cmn_err(CE_WARN, "cpuid 0x%x failed to resume", i);
			continue;
		}
		CPUSET_DEL(cpu_idle_set, i);
	}

	failed = !CPUSET_ISNULL(cpu_idle_set);

	mutex_exit(&cpu_idle_lock);

	/*
	 * Non-zero if a cpu failed to resume
	 */
	if (failed)
		cmn_err(CE_PANIC, "resume_other_cpus: not all cpus resumed");

}

/*
 * Stop all other cpu's before halting or rebooting. We pause the cpu's
 * instead of sending a cross call.
 */
void
stop_other_cpus(void)
{
	mutex_enter(&cpu_lock);
	if (cpu_are_paused) {
		mutex_exit(&cpu_lock);
		return;
	}

	if (ncpus > 1)
		intr_redist_all_cpus_shutdown();

	pause_cpus(NULL, NULL);
	cpu_are_paused = 1;

	mutex_exit(&cpu_lock);
}

int cpu_quiesce_microsecond_sanity_limit = 60 * 1000000;

void
mp_cpu_quiesce(cpu_t *cp0)
{

	volatile cpu_t  *cp = (volatile cpu_t *) cp0;
	int i, sanity_limit = cpu_quiesce_microsecond_sanity_limit;
	int		cpuid = cp->cpu_id;
	int 		found_intr = 1;
	static fn_t	f = "mp_cpu_quiesce";

	ASSERT(CPU->cpu_id != cpuid);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cp->cpu_flags & CPU_QUIESCED);


	/*
	 * Declare CPU as no longer being READY to process interrupts and
	 * wait for them to stop. A CPU that is not READY can no longer
	 * participate in x-calls or x-traps.
	 */
	cp->cpu_flags &= ~CPU_READY;
	CPUSET_DEL(cpu_ready_set, cpuid);
	membar_sync();

	for (i = 0; i < sanity_limit; i++) {
		if (cp->cpu_intr_actv == 0 &&
		    (cp->cpu_thread == cp->cpu_idle_thread ||
		    cp->cpu_thread == cp->cpu_startup_thread)) {
			found_intr = 0;
			break;
		}
		DELAY(1);
	}

	if (found_intr) {

		if (cp->cpu_intr_actv) {
			cmn_err(CE_PANIC, "%s: cpu_intr_actv != 0", f);
		} else if (cp->cpu_thread != cp->cpu_idle_thread &&
		    cp->cpu_thread != cp->cpu_startup_thread) {
			cmn_err(CE_PANIC, "%s: CPU %d is not quiesced",
			    f, cpuid);
		}

	}
}

/*
 * Start CPU on user request.
 */
/* ARGSUSED */
int
mp_cpu_start(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	/*
	 * Platforms that use CPU signatures require the signature
	 * block update to indicate that this CPU is in the OS now.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_RUN, SIGSUBST_NULL, cp->cpu_id);

	cmp_error_resteer(cp->cpu_id);

	return (0);			/* nothing special to do on this arch */
}

/*
 * Stop CPU on user request.
 */
/* ARGSUSED */
int
mp_cpu_stop(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	cmp_error_resteer(cp->cpu_id);

	/*
	 * Platforms that use CPU signatures require the signature
	 * block update to indicate that this CPU is offlined now.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_OFFLINE, SIGSUBST_NULL, cp->cpu_id);
	return (0);			/* nothing special to do on this arch */
}

/*
 * Power on CPU.
 */
int
mp_cpu_poweron(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	if (&plat_cpu_poweron)
		return (plat_cpu_poweron(cp));	/* platform-dependent hook */

	return (ENOTSUP);
}

/*
 * Power off CPU.
 */
int
mp_cpu_poweroff(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	if (&plat_cpu_poweroff)
		return (plat_cpu_poweroff(cp));	/* platform-dependent hook */

	return (ENOTSUP);
}

void
mp_cpu_faulted_enter(struct cpu *cp)
{
	cpu_faulted_enter(cp);
}

void
mp_cpu_faulted_exit(struct cpu *cp)
{
	cpu_faulted_exit(cp);
}
