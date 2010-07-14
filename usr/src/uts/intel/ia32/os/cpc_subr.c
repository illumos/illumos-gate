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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * x86-specific routines used by the CPU Performance counter driver.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/atomic.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>
#include <sys/machcpuvar.h>
#include <sys/archsystm.h>
#include <sys/cpc_pcbe.h>
#include <sys/cpc_impl.h>
#include <sys/x_call.h>
#include <sys/cmn_err.h>
#include <sys/cmt.h>
#include <sys/spl.h>
#include <sys/apic.h>

static const uint64_t allstopped = 0;
static kcpc_ctx_t *(*overflow_intr_handler)(caddr_t);

/* Do threads share performance monitoring hardware? */
static int strands_perfmon_shared = 0;

int kcpc_hw_overflow_intr_installed;		/* set by APIC code */
extern kcpc_ctx_t *kcpc_overflow_intr(caddr_t arg, uint64_t bitmap);

extern int kcpc_counts_include_idle; /* Project Private /etc/system variable */

void (*kcpc_hw_enable_cpc_intr)(void);		/* set by APIC code */

int
kcpc_hw_add_ovf_intr(kcpc_ctx_t *(*handler)(caddr_t))
{
	if (x86_type != X86_TYPE_P6)
		return (0);
	overflow_intr_handler = handler;
	return (ipltospl(APIC_PCINT_IPL));
}

void
kcpc_hw_rem_ovf_intr(void)
{
	overflow_intr_handler = NULL;
}

/*
 * Hook used on P4 systems to catch online/offline events.
 */
/*ARGSUSED*/
static int
kcpc_cpu_setup(cpu_setup_t what, int cpuid, void *arg)
{
	pg_cmt_t	*chip_pg;
	int		active_cpus_cnt;

	if (what != CPU_ON)
		return (0);

	/*
	 * If any CPU-bound contexts exist, we don't need to invalidate
	 * anything, as no per-LWP contexts can coexist.
	 */
	if (kcpc_cpuctx || dtrace_cpc_in_use)
		return (0);

	/*
	 * If this chip now has more than 1 active cpu, we must invalidate all
	 * contexts in the system.
	 */
	chip_pg = (pg_cmt_t *)pghw_find_pg(cpu[cpuid], PGHW_CHIP);
	if (chip_pg != NULL) {
		active_cpus_cnt = GROUP_SIZE(&chip_pg->cmt_cpus_actv);
		if (active_cpus_cnt > 1)
			kcpc_invalidate_all();
	}

	return (0);
}

static kmutex_t cpu_setup_lock;	/* protects setup_registered */
static int setup_registered;


void
kcpc_hw_init(cpu_t *cp)
{
	kthread_t *t = cp->cpu_idle_thread;
	uint32_t versionid;
	struct cpuid_regs cpuid;

	strands_perfmon_shared = 0;
	if (is_x86_feature(x86_featureset, X86FSET_HTT)) {
		if (cpuid_getvendor(cpu[0]) == X86_VENDOR_Intel) {
			/*
			 * Intel processors that support Architectural
			 * Performance Monitoring Version 3 have per strand
			 * performance monitoring hardware.
			 * Hence we can allow use of performance counters on
			 * multiple strands on the same core simultaneously.
			 */
			cpuid.cp_eax = 0x0;
			(void) __cpuid_insn(&cpuid);
			if (cpuid.cp_eax < 0xa) {
				strands_perfmon_shared = 1;
			} else {
				cpuid.cp_eax = 0xa;
				(void) __cpuid_insn(&cpuid);

				versionid = cpuid.cp_eax & 0xFF;
				if (versionid < 3) {
					strands_perfmon_shared = 1;
				}
			}
		} else {
			strands_perfmon_shared = 1;
		}
	}

	if (strands_perfmon_shared) {
		mutex_enter(&cpu_setup_lock);
		if (setup_registered == 0) {
			mutex_enter(&cpu_lock);
			register_cpu_setup_func(kcpc_cpu_setup, NULL);
			mutex_exit(&cpu_lock);
			setup_registered = 1;
		}
		mutex_exit(&cpu_setup_lock);
	}

	mutex_init(&cp->cpu_cpc_ctxlock, "cpu_cpc_ctxlock", MUTEX_DEFAULT, 0);

	if (kcpc_counts_include_idle)
		return;

	installctx(t, cp, kcpc_idle_save, kcpc_idle_restore,
	    NULL, NULL, NULL, NULL);
}

void
kcpc_hw_fini(cpu_t *cp)
{
	ASSERT(cp->cpu_idle_thread == NULL);

	mutex_destroy(&cp->cpu_cpc_ctxlock);
}

#define	BITS(v, u, l)	\
	(((v) >> (l)) & ((1 << (1 + (u) - (l))) - 1))

#define	PCBE_NAMELEN 30	/* Enough Room for pcbe.manuf.model.family.stepping */

/*
 * Examine the processor and load an appropriate PCBE.
 */
int
kcpc_hw_load_pcbe(void)
{
	return (kcpc_pcbe_tryload(cpuid_getvendorstr(CPU), cpuid_getfamily(CPU),
	    cpuid_getmodel(CPU), cpuid_getstep(CPU)));
}

/*
 * Called by the generic framework to check if it's OK to bind a set to a CPU.
 */
int
kcpc_hw_cpu_hook(processorid_t cpuid, ulong_t *kcpc_cpumap)
{
	cpu_t		*cpu, *p;
	pg_t		*chip_pg;
	pg_cpu_itr_t	itr;

	if (!strands_perfmon_shared)
		return (0);

	/*
	 * Only one logical CPU on each Pentium 4 HT CPU may be bound to at
	 * once.
	 *
	 * This loop is protected by holding cpu_lock, in order to properly
	 * access the cpu_t of the desired cpu.
	 */
	mutex_enter(&cpu_lock);
	if ((cpu = cpu_get(cpuid)) == NULL) {
		mutex_exit(&cpu_lock);
		return (-1);
	}

	chip_pg = (pg_t *)pghw_find_pg(cpu, PGHW_CHIP);

	PG_CPU_ITR_INIT(chip_pg, itr);
	while ((p = pg_cpu_next(&itr)) != NULL) {
		if (p == cpu)
			continue;
		if (BT_TEST(kcpc_cpumap, p->cpu_id)) {
			mutex_exit(&cpu_lock);
			return (-1);
		}
	}

	mutex_exit(&cpu_lock);
	return (0);
}

/*
 * Called by the generic framework to check if it's OK to bind a set to an LWP.
 */
int
kcpc_hw_lwp_hook(void)
{
	pg_cmt_t	*chip;
	group_t		*chips;
	group_iter_t	i;

	if (!strands_perfmon_shared)
		return (0);

	/*
	 * Only one CPU per chip may be online.
	 */
	mutex_enter(&cpu_lock);

	chips = pghw_set_lookup(PGHW_CHIP);
	if (chips == NULL) {
		mutex_exit(&cpu_lock);
		return (0);
	}

	group_iter_init(&i);
	while ((chip = group_iterate(chips, &i)) != NULL) {
		if (GROUP_SIZE(&chip->cmt_cpus_actv) > 1) {
			mutex_exit(&cpu_lock);
			return (-1);
		}
	}

	mutex_exit(&cpu_lock);
	return (0);
}
