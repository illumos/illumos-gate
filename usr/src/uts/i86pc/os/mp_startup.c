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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2018 Joyent, Inc.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cpu.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/note.h>
#include <sys/asm_linkage.h>
#include <sys/x_call.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/vtrace.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <sys/segments.h>
#include <sys/kmem.h>
#include <sys/stack.h>
#include <sys/smp_impldefs.h>
#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/cpc_impl.h>
#include <sys/pg.h>
#include <sys/cmt.h>
#include <sys/dtrace.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/reboot.h>
#include <sys/kdi_machimpl.h>
#include <vm/hat_i86.h>
#include <vm/vm_dep.h>
#include <sys/memnode.h>
#include <sys/pci_cfgspace.h>
#include <sys/mach_mmu.h>
#include <sys/sysmacros.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif
#include <sys/cpu_module.h>
#include <sys/ontrap.h>

struct cpu	cpus[1] __aligned(MMU_PAGESIZE);
struct cpu	*cpu[NCPU] = {&cpus[0]};
struct cpu	*cpu_free_list;
cpu_core_t	cpu_core[NCPU];

#define	cpu_next_free	cpu_prev

/*
 * Useful for disabling MP bring-up on a MP capable system.
 */
int use_mp = 1;

/*
 * to be set by a PSM to indicate what cpus
 * are sitting around on the system.
 */
cpuset_t mp_cpus;

/*
 * This variable is used by the hat layer to decide whether or not
 * critical sections are needed to prevent race conditions.  For sun4m,
 * this variable is set once enough MP initialization has been done in
 * order to allow cross calls.
 */
int flushes_require_xcalls;

cpuset_t cpu_ready_set;		/* initialized in startup() */

static void mp_startup_boot(void);
static void mp_startup_hotplug(void);

static void cpu_sep_enable(void);
static void cpu_sep_disable(void);
static void cpu_asysc_enable(void);
static void cpu_asysc_disable(void);

/*
 * Init CPU info - get CPU type info for processor_info system call.
 */
void
init_cpu_info(struct cpu *cp)
{
	processor_info_t *pi = &cp->cpu_type_info;

	/*
	 * Get clock-frequency property for the CPU.
	 */
	pi->pi_clock = cpu_freq;

	/*
	 * Current frequency in Hz.
	 */
	cp->cpu_curr_clock = cpu_freq_hz;

	/*
	 * Supported frequencies.
	 */
	if (cp->cpu_supp_freqs == NULL) {
		cpu_set_supp_freqs(cp, NULL);
	}

	(void) strcpy(pi->pi_processor_type, "i386");
	if (fpu_exists)
		(void) strcpy(pi->pi_fputypes, "i387 compatible");

	cp->cpu_idstr = kmem_zalloc(CPU_IDSTRLEN, KM_SLEEP);
	cp->cpu_brandstr = kmem_zalloc(CPU_IDSTRLEN, KM_SLEEP);

	/*
	 * If called for the BSP, cp is equal to current CPU.
	 * For non-BSPs, cpuid info of cp is not ready yet, so use cpuid info
	 * of current CPU as default values for cpu_idstr and cpu_brandstr.
	 * They will be corrected in mp_startup_common() after cpuid_pass1()
	 * has been invoked on target CPU.
	 */
	(void) cpuid_getidstr(CPU, cp->cpu_idstr, CPU_IDSTRLEN);
	(void) cpuid_getbrandstr(CPU, cp->cpu_brandstr, CPU_IDSTRLEN);
}

/*
 * Configure syscall support on this CPU.
 */
/*ARGSUSED*/
void
init_cpu_syscall(struct cpu *cp)
{
	kpreempt_disable();

	if (is_x86_feature(x86_featureset, X86FSET_MSR) &&
	    is_x86_feature(x86_featureset, X86FSET_ASYSC)) {
		uint64_t flags;

#if !defined(__xpv)
		/*
		 * The syscall instruction imposes a certain ordering on
		 * segment selectors, so we double-check that ordering
		 * here.
		 */
		CTASSERT(KDS_SEL == KCS_SEL + 8);
		CTASSERT(UDS_SEL == U32CS_SEL + 8);
		CTASSERT(UCS_SEL == U32CS_SEL + 16);
#endif

		/*
		 * Turn syscall/sysret extensions on.
		 */
		cpu_asysc_enable();

		/*
		 * Program the magic registers ..
		 */
		wrmsr(MSR_AMD_STAR,
		    ((uint64_t)(U32CS_SEL << 16 | KCS_SEL)) << 32);
		if (kpti_enable == 1) {
			wrmsr(MSR_AMD_LSTAR,
			    (uint64_t)(uintptr_t)tr_sys_syscall);
			wrmsr(MSR_AMD_CSTAR,
			    (uint64_t)(uintptr_t)tr_sys_syscall32);
		} else {
			wrmsr(MSR_AMD_LSTAR,
			    (uint64_t)(uintptr_t)sys_syscall);
			wrmsr(MSR_AMD_CSTAR,
			    (uint64_t)(uintptr_t)sys_syscall32);
		}

		/*
		 * This list of flags is masked off the incoming
		 * %rfl when we enter the kernel.
		 */
		flags = PS_IE | PS_T;
		if (is_x86_feature(x86_featureset, X86FSET_SMAP) == B_TRUE)
			flags |= PS_ACHK;
		wrmsr(MSR_AMD_SFMASK, flags);
	}

	/*
	 * On 64-bit kernels on Nocona machines, the 32-bit syscall
	 * variant isn't available to 32-bit applications, but sysenter is.
	 */
	if (is_x86_feature(x86_featureset, X86FSET_MSR) &&
	    is_x86_feature(x86_featureset, X86FSET_SEP)) {

#if !defined(__xpv)
		/*
		 * The sysenter instruction imposes a certain ordering on
		 * segment selectors, so we double-check that ordering
		 * here. See "sysenter" in Intel document 245471-012, "IA-32
		 * Intel Architecture Software Developer's Manual Volume 2:
		 * Instruction Set Reference"
		 */
		CTASSERT(KDS_SEL == KCS_SEL + 8);

		CTASSERT(U32CS_SEL == ((KCS_SEL + 16) | 3));
		CTASSERT(UDS_SEL == U32CS_SEL + 8);
#endif

		cpu_sep_enable();

		/*
		 * resume() sets this value to the base of the threads stack
		 * via a context handler.
		 */
		wrmsr(MSR_INTC_SEP_ESP, 0);

		if (kpti_enable == 1) {
			wrmsr(MSR_INTC_SEP_EIP,
			    (uint64_t)(uintptr_t)tr_sys_sysenter);
		} else {
			wrmsr(MSR_INTC_SEP_EIP,
			    (uint64_t)(uintptr_t)sys_sysenter);
		}
	}

	kpreempt_enable();
}

#if !defined(__xpv)
/*
 * Configure per-cpu ID GDT
 */
static void
init_cpu_id_gdt(struct cpu *cp)
{
	/* Write cpu_id into limit field of GDT for usermode retrieval */
#if defined(__amd64)
	set_usegd(&cp->cpu_gdt[GDT_CPUID], SDP_SHORT, NULL, cp->cpu_id,
	    SDT_MEMRODA, SEL_UPL, SDP_BYTES, SDP_OP32);
#elif defined(__i386)
	set_usegd(&cp->cpu_gdt[GDT_CPUID], NULL, cp->cpu_id, SDT_MEMRODA,
	    SEL_UPL, SDP_BYTES, SDP_OP32);
#endif
}
#endif /* !defined(__xpv) */

/*
 * Multiprocessor initialization.
 *
 * Allocate and initialize the cpu structure, TRAPTRACE buffer, and the
 * startup and idle threads for the specified CPU.
 * Parameter boot is true for boot time operations and is false for CPU
 * DR operations.
 */
static struct cpu *
mp_cpu_configure_common(int cpun, boolean_t boot)
{
	struct cpu *cp;
	kthread_id_t tp;
	caddr_t	sp;
	proc_t *procp;
#if !defined(__xpv)
	extern int idle_cpu_prefer_mwait;
	extern void cpu_idle_mwait();
#endif
	extern void idle();
	extern void cpu_idle();

#ifdef TRAPTRACE
	trap_trace_ctl_t *ttc = &trap_trace_ctl[cpun];
#endif

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpun < NCPU && cpu[cpun] == NULL);

	if (cpu_free_list == NULL) {
		cp = kmem_zalloc(sizeof (*cp), KM_SLEEP);
	} else {
		cp = cpu_free_list;
		cpu_free_list = cp->cpu_next_free;
	}

	cp->cpu_m.mcpu_istamp = cpun << 16;

	/* Create per CPU specific threads in the process p0. */
	procp = &p0;

	/*
	 * Initialize the dispatcher first.
	 */
	disp_cpu_init(cp);

	cpu_vm_data_init(cp);

	/*
	 * Allocate and initialize the startup thread for this CPU.
	 * Interrupt and process switch stacks get allocated later
	 * when the CPU starts running.
	 */
	tp = thread_create(NULL, 0, NULL, NULL, 0, procp,
	    TS_STOPPED, maxclsyspri);

	/*
	 * Set state to TS_ONPROC since this thread will start running
	 * as soon as the CPU comes online.
	 *
	 * All the other fields of the thread structure are setup by
	 * thread_create().
	 */
	THREAD_ONPROC(tp, cp);
	tp->t_preempt = 1;
	tp->t_bound_cpu = cp;
	tp->t_affinitycnt = 1;
	tp->t_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;

	/*
	 * Setup thread to start in mp_startup_common.
	 */
	sp = tp->t_stk;
	tp->t_sp = (uintptr_t)(sp - MINFRAME);
#if defined(__amd64)
	tp->t_sp -= STACK_ENTRY_ALIGN;		/* fake a call */
#endif
	/*
	 * Setup thread start entry point for boot or hotplug.
	 */
	if (boot) {
		tp->t_pc = (uintptr_t)mp_startup_boot;
	} else {
		tp->t_pc = (uintptr_t)mp_startup_hotplug;
	}

	cp->cpu_id = cpun;
	cp->cpu_self = cp;
	cp->cpu_thread = tp;
	cp->cpu_lwp = NULL;
	cp->cpu_dispthread = tp;
	cp->cpu_dispatch_pri = DISP_PRIO(tp);

	/*
	 * cpu_base_spl must be set explicitly here to prevent any blocking
	 * operations in mp_startup_common from causing the spl of the cpu
	 * to drop to 0 (allowing device interrupts before we're ready) in
	 * resume().
	 * cpu_base_spl MUST remain at LOCK_LEVEL until the cpu is CPU_READY.
	 * As an extra bit of security on DEBUG kernels, this is enforced with
	 * an assertion in mp_startup_common() -- before cpu_base_spl is set
	 * to its proper value.
	 */
	cp->cpu_base_spl = ipltospl(LOCK_LEVEL);

	/*
	 * Now, initialize per-CPU idle thread for this CPU.
	 */
	tp = thread_create(NULL, PAGESIZE, idle, NULL, 0, procp, TS_ONPROC, -1);

	cp->cpu_idle_thread = tp;

	tp->t_preempt = 1;
	tp->t_bound_cpu = cp;
	tp->t_affinitycnt = 1;
	tp->t_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;

	/*
	 * Bootstrap the CPU's PG data
	 */
	pg_cpu_bootstrap(cp);

	/*
	 * Perform CPC initialization on the new CPU.
	 */
	kcpc_hw_init(cp);

	/*
	 * Allocate virtual addresses for cpu_caddr1 and cpu_caddr2
	 * for each CPU.
	 */
	setup_vaddr_for_ppcopy(cp);

	/*
	 * Allocate page for new GDT and initialize from current GDT.
	 */
#if !defined(__lint)
	ASSERT((sizeof (*cp->cpu_gdt) * NGDT) <= PAGESIZE);
#endif
	cp->cpu_gdt = kmem_zalloc(PAGESIZE, KM_SLEEP);
	bcopy(CPU->cpu_gdt, cp->cpu_gdt, (sizeof (*cp->cpu_gdt) * NGDT));

#if defined(__i386)
	/*
	 * setup kernel %gs.
	 */
	set_usegd(&cp->cpu_gdt[GDT_GS], cp, sizeof (struct cpu) -1, SDT_MEMRWA,
	    SEL_KPL, 0, 1);
#endif

	/*
	 * Allocate pages for the CPU LDT.
	 */
	cp->cpu_m.mcpu_ldt = kmem_zalloc(LDT_CPU_SIZE, KM_SLEEP);
	cp->cpu_m.mcpu_ldt_len = 0;

	/*
	 * Allocate a per-CPU IDT and initialize the new IDT to the currently
	 * runing CPU.
	 */
#if !defined(__lint)
	ASSERT((sizeof (*CPU->cpu_idt) * NIDT) <= PAGESIZE);
#endif
	cp->cpu_idt = kmem_alloc(PAGESIZE, KM_SLEEP);
	bcopy(CPU->cpu_idt, cp->cpu_idt, PAGESIZE);

	/*
	 * alloc space for cpuid info
	 */
	cpuid_alloc_space(cp);
#if !defined(__xpv)
	if (is_x86_feature(x86_featureset, X86FSET_MWAIT) &&
	    idle_cpu_prefer_mwait) {
		cp->cpu_m.mcpu_mwait = cpuid_mwait_alloc(cp);
		cp->cpu_m.mcpu_idle_cpu = cpu_idle_mwait;
	} else
#endif
		cp->cpu_m.mcpu_idle_cpu = cpu_idle;

	init_cpu_info(cp);

#if !defined(__xpv)
	init_cpu_id_gdt(cp);
#endif

	/*
	 * alloc space for ucode_info
	 */
	ucode_alloc_space(cp);
	xc_init_cpu(cp);
	hat_cpu_online(cp);

#ifdef TRAPTRACE
	/*
	 * If this is a TRAPTRACE kernel, allocate TRAPTRACE buffers
	 */
	ttc->ttc_first = (uintptr_t)kmem_zalloc(trap_trace_bufsize, KM_SLEEP);
	ttc->ttc_next = ttc->ttc_first;
	ttc->ttc_limit = ttc->ttc_first + trap_trace_bufsize;
#endif

	/*
	 * Record that we have another CPU.
	 */
	/*
	 * Initialize the interrupt threads for this CPU
	 */
	cpu_intr_alloc(cp, NINTR_THREADS);

	cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;
	cpu_set_state(cp);

	/*
	 * Add CPU to list of available CPUs.  It'll be on the active list
	 * after mp_startup_common().
	 */
	cpu_add_unit(cp);

	return (cp);
}

/*
 * Undo what was done in mp_cpu_configure_common
 */
static void
mp_cpu_unconfigure_common(struct cpu *cp, int error)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Remove the CPU from the list of available CPUs.
	 */
	cpu_del_unit(cp->cpu_id);

	if (error == ETIMEDOUT) {
		/*
		 * The cpu was started, but never *seemed* to run any
		 * code in the kernel; it's probably off spinning in its
		 * own private world, though with potential references to
		 * our kmem-allocated IDTs and GDTs (for example).
		 *
		 * Worse still, it may actually wake up some time later,
		 * so rather than guess what it might or might not do, we
		 * leave the fundamental data structures intact.
		 */
		cp->cpu_flags = 0;
		return;
	}

	/*
	 * At this point, the only threads bound to this CPU should
	 * special per-cpu threads: it's idle thread, it's pause threads,
	 * and it's interrupt threads.  Clean these up.
	 */
	cpu_destroy_bound_threads(cp);
	cp->cpu_idle_thread = NULL;

	/*
	 * Free the interrupt stack.
	 */
	segkp_release(segkp,
	    cp->cpu_intr_stack - (INTR_STACK_SIZE - SA(MINFRAME)));
	cp->cpu_intr_stack = NULL;

#ifdef TRAPTRACE
	/*
	 * Discard the trap trace buffer
	 */
	{
		trap_trace_ctl_t *ttc = &trap_trace_ctl[cp->cpu_id];

		kmem_free((void *)ttc->ttc_first, trap_trace_bufsize);
		ttc->ttc_first = NULL;
	}
#endif

	hat_cpu_offline(cp);

	ucode_free_space(cp);

	/* Free CPU ID string and brand string. */
	if (cp->cpu_idstr) {
		kmem_free(cp->cpu_idstr, CPU_IDSTRLEN);
		cp->cpu_idstr = NULL;
	}
	if (cp->cpu_brandstr) {
		kmem_free(cp->cpu_brandstr, CPU_IDSTRLEN);
		cp->cpu_brandstr = NULL;
	}

#if !defined(__xpv)
	if (cp->cpu_m.mcpu_mwait != NULL) {
		cpuid_mwait_free(cp);
		cp->cpu_m.mcpu_mwait = NULL;
	}
#endif
	cpuid_free_space(cp);

	if (cp->cpu_idt != CPU->cpu_idt)
		kmem_free(cp->cpu_idt, PAGESIZE);
	cp->cpu_idt = NULL;

	kmem_free(cp->cpu_m.mcpu_ldt, LDT_CPU_SIZE);
	cp->cpu_m.mcpu_ldt = NULL;
	cp->cpu_m.mcpu_ldt_len = 0;

	kmem_free(cp->cpu_gdt, PAGESIZE);
	cp->cpu_gdt = NULL;

	if (cp->cpu_supp_freqs != NULL) {
		size_t len = strlen(cp->cpu_supp_freqs) + 1;
		kmem_free(cp->cpu_supp_freqs, len);
		cp->cpu_supp_freqs = NULL;
	}

	teardown_vaddr_for_ppcopy(cp);

	kcpc_hw_fini(cp);

	cp->cpu_dispthread = NULL;
	cp->cpu_thread = NULL;	/* discarded by cpu_destroy_bound_threads() */

	cpu_vm_data_destroy(cp);

	xc_fini_cpu(cp);
	disp_cpu_fini(cp);

	ASSERT(cp != CPU0);
	bzero(cp, sizeof (*cp));
	cp->cpu_next_free = cpu_free_list;
	cpu_free_list = cp;
}

/*
 * Apply workarounds for known errata, and warn about those that are absent.
 *
 * System vendors occasionally create configurations which contain different
 * revisions of the CPUs that are almost but not exactly the same.  At the
 * time of writing, this meant that their clock rates were the same, their
 * feature sets were the same, but the required workaround were -not-
 * necessarily the same.  So, this routine is invoked on -every- CPU soon
 * after starting to make sure that the resulting system contains the most
 * pessimal set of workarounds needed to cope with *any* of the CPUs in the
 * system.
 *
 * workaround_errata is invoked early in mlsetup() for CPU 0, and in
 * mp_startup_common() for all slave CPUs. Slaves process workaround_errata
 * prior to acknowledging their readiness to the master, so this routine will
 * never be executed by multiple CPUs in parallel, thus making updates to
 * global data safe.
 *
 * These workarounds are based on Rev 3.57 of the Revision Guide for
 * AMD Athlon(tm) 64 and AMD Opteron(tm) Processors, August 2005.
 */

#if defined(OPTERON_ERRATUM_88)
int opteron_erratum_88;		/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_91)
int opteron_erratum_91;		/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_93)
int opteron_erratum_93;		/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_95)
int opteron_erratum_95;		/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_100)
int opteron_erratum_100;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_108)
int opteron_erratum_108;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_109)
int opteron_erratum_109;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_121)
int opteron_erratum_121;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_122)
int opteron_erratum_122;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_123)
int opteron_erratum_123;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_131)
int opteron_erratum_131;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_WORKAROUND_6336786)
int opteron_workaround_6336786;	/* non-zero -> WA relevant and applied */
int opteron_workaround_6336786_UP = 0;	/* Not needed for UP */
#endif

#if defined(OPTERON_WORKAROUND_6323525)
int opteron_workaround_6323525;	/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_298)
int opteron_erratum_298;
#endif

#if defined(OPTERON_ERRATUM_721)
int opteron_erratum_721;
#endif

static void
workaround_warning(cpu_t *cp, uint_t erratum)
{
	cmn_err(CE_WARN, "cpu%d: no workaround for erratum %u",
	    cp->cpu_id, erratum);
}

static void
workaround_applied(uint_t erratum)
{
	if (erratum > 1000000)
		cmn_err(CE_CONT, "?workaround applied for cpu issue #%d\n",
		    erratum);
	else
		cmn_err(CE_CONT, "?workaround applied for cpu erratum #%d\n",
		    erratum);
}

static void
msr_warning(cpu_t *cp, const char *rw, uint_t msr, int error)
{
	cmn_err(CE_WARN, "cpu%d: couldn't %smsr 0x%x, error %d",
	    cp->cpu_id, rw, msr, error);
}

/*
 * Determine the number of nodes in a Hammer / Greyhound / Griffin family
 * system.
 */
static uint_t
opteron_get_nnodes(void)
{
	static uint_t nnodes = 0;

	if (nnodes == 0) {
#ifdef	DEBUG
		uint_t family;

		/*
		 * This routine uses a PCI config space based mechanism
		 * for retrieving the number of nodes in the system.
		 * Device 24, function 0, offset 0x60 as used here is not
		 * AMD processor architectural, and may not work on processor
		 * families other than those listed below.
		 *
		 * Callers of this routine must ensure that we're running on
		 * a processor which supports this mechanism.
		 * The assertion below is meant to catch calls on unsupported
		 * processors.
		 */
		family = cpuid_getfamily(CPU);
		ASSERT(family == 0xf || family == 0x10 || family == 0x11);
#endif	/* DEBUG */

		/*
		 * Obtain the number of nodes in the system from
		 * bits [6:4] of the Node ID register on node 0.
		 *
		 * The actual node count is NodeID[6:4] + 1
		 *
		 * The Node ID register is accessed via function 0,
		 * offset 0x60. Node 0 is device 24.
		 */
		nnodes = ((pci_getl_func(0, 24, 0, 0x60) & 0x70) >> 4) + 1;
	}
	return (nnodes);
}

uint_t
do_erratum_298(struct cpu *cpu)
{
	static int	osvwrc = -3;
	extern int	osvw_opteron_erratum(cpu_t *, uint_t);

	/*
	 * L2 Eviction May Occur During Processor Operation To Set
	 * Accessed or Dirty Bit.
	 */
	if (osvwrc == -3) {
		osvwrc = osvw_opteron_erratum(cpu, 298);
	} else {
		/* osvw return codes should be consistent for all cpus */
		ASSERT(osvwrc == osvw_opteron_erratum(cpu, 298));
	}

	switch (osvwrc) {
	case 0:		/* erratum is not present: do nothing */
		break;
	case 1:		/* erratum is present: BIOS workaround applied */
		/*
		 * check if workaround is actually in place and issue warning
		 * if not.
		 */
		if (((rdmsr(MSR_AMD_HWCR) & AMD_HWCR_TLBCACHEDIS) == 0) ||
		    ((rdmsr(MSR_AMD_BU_CFG) & AMD_BU_CFG_E298) == 0)) {
#if defined(OPTERON_ERRATUM_298)
			opteron_erratum_298++;
#else
			workaround_warning(cpu, 298);
			return (1);
#endif
		}
		break;
	case -1:	/* cannot determine via osvw: check cpuid */
		if ((cpuid_opteron_erratum(cpu, 298) > 0) &&
		    (((rdmsr(MSR_AMD_HWCR) & AMD_HWCR_TLBCACHEDIS) == 0) ||
		    ((rdmsr(MSR_AMD_BU_CFG) & AMD_BU_CFG_E298) == 0))) {
#if defined(OPTERON_ERRATUM_298)
			opteron_erratum_298++;
#else
			workaround_warning(cpu, 298);
			return (1);
#endif
		}
		break;
	}
	return (0);
}

uint_t
workaround_errata(struct cpu *cpu)
{
	uint_t missing = 0;

	ASSERT(cpu == CPU);

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 88) > 0) {
		/*
		 * SWAPGS May Fail To Read Correct GS Base
		 */
#if defined(OPTERON_ERRATUM_88)
		/*
		 * The workaround is an mfence in the relevant assembler code
		 */
		opteron_erratum_88++;
#else
		workaround_warning(cpu, 88);
		missing++;
#endif
	}

	if (cpuid_opteron_erratum(cpu, 91) > 0) {
		/*
		 * Software Prefetches May Report A Page Fault
		 */
#if defined(OPTERON_ERRATUM_91)
		/*
		 * fix is in trap.c
		 */
		opteron_erratum_91++;
#else
		workaround_warning(cpu, 91);
		missing++;
#endif
	}

	if (cpuid_opteron_erratum(cpu, 93) > 0) {
		/*
		 * RSM Auto-Halt Restart Returns to Incorrect RIP
		 */
#if defined(OPTERON_ERRATUM_93)
		/*
		 * fix is in trap.c
		 */
		opteron_erratum_93++;
#else
		workaround_warning(cpu, 93);
		missing++;
#endif
	}

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 95) > 0) {
		/*
		 * RET Instruction May Return to Incorrect EIP
		 */
#if defined(OPTERON_ERRATUM_95)
#if defined(_LP64)
		/*
		 * Workaround this by ensuring that 32-bit user code and
		 * 64-bit kernel code never occupy the same address
		 * range mod 4G.
		 */
		if (_userlimit32 > 0xc0000000ul)
			*(uintptr_t *)&_userlimit32 = 0xc0000000ul;

		/*LINTED*/
		ASSERT((uint32_t)COREHEAP_BASE == 0xc0000000u);
		opteron_erratum_95++;
#endif	/* _LP64 */
#else
		workaround_warning(cpu, 95);
		missing++;
#endif
	}

	if (cpuid_opteron_erratum(cpu, 100) > 0) {
		/*
		 * Compatibility Mode Branches Transfer to Illegal Address
		 */
#if defined(OPTERON_ERRATUM_100)
		/*
		 * fix is in trap.c
		 */
		opteron_erratum_100++;
#else
		workaround_warning(cpu, 100);
		missing++;
#endif
	}

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 108) > 0) {
		/*
		 * CPUID Instruction May Return Incorrect Model Number In
		 * Some Processors
		 */
#if defined(OPTERON_ERRATUM_108)
		/*
		 * (Our cpuid-handling code corrects the model number on
		 * those processors)
		 */
#else
		workaround_warning(cpu, 108);
		missing++;
#endif
	}

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 109) > 0) do {
		/*
		 * Certain Reverse REP MOVS May Produce Unpredictable Behavior
		 */
#if defined(OPTERON_ERRATUM_109)
		/*
		 * The "workaround" is to print a warning to upgrade the BIOS
		 */
		uint64_t value;
		const uint_t msr = MSR_AMD_PATCHLEVEL;
		int err;

		if ((err = checked_rdmsr(msr, &value)) != 0) {
			msr_warning(cpu, "rd", msr, err);
			workaround_warning(cpu, 109);
			missing++;
		}
		if (value == 0)
			opteron_erratum_109++;
#else
		workaround_warning(cpu, 109);
		missing++;
#endif
	/*CONSTANTCONDITION*/
	} while (0);

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 121) > 0) {
		/*
		 * Sequential Execution Across Non_Canonical Boundary Caused
		 * Processor Hang
		 */
#if defined(OPTERON_ERRATUM_121)
#if defined(_LP64)
		/*
		 * Erratum 121 is only present in long (64 bit) mode.
		 * Workaround is to include the page immediately before the
		 * va hole to eliminate the possibility of system hangs due to
		 * sequential execution across the va hole boundary.
		 */
		if (opteron_erratum_121)
			opteron_erratum_121++;
		else {
			if (hole_start) {
				hole_start -= PAGESIZE;
			} else {
				/*
				 * hole_start not yet initialized by
				 * mmu_init. Initialize hole_start
				 * with value to be subtracted.
				 */
				hole_start = PAGESIZE;
			}
			opteron_erratum_121++;
		}
#endif	/* _LP64 */
#else
		workaround_warning(cpu, 121);
		missing++;
#endif
	}

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 122) > 0) do {
		/*
		 * TLB Flush Filter May Cause Coherency Problem in
		 * Multiprocessor Systems
		 */
#if defined(OPTERON_ERRATUM_122)
		uint64_t value;
		const uint_t msr = MSR_AMD_HWCR;
		int error;

		/*
		 * Erratum 122 is only present in MP configurations (multi-core
		 * or multi-processor).
		 */
#if defined(__xpv)
		if (!DOMAIN_IS_INITDOMAIN(xen_info))
			break;
		if (!opteron_erratum_122 && xpv_nr_phys_cpus() == 1)
			break;
#else
		if (!opteron_erratum_122 && opteron_get_nnodes() == 1 &&
		    cpuid_get_ncpu_per_chip(cpu) == 1)
			break;
#endif
		/* disable TLB Flush Filter */

		if ((error = checked_rdmsr(msr, &value)) != 0) {
			msr_warning(cpu, "rd", msr, error);
			workaround_warning(cpu, 122);
			missing++;
		} else {
			value |= (uint64_t)AMD_HWCR_FFDIS;
			if ((error = checked_wrmsr(msr, value)) != 0) {
				msr_warning(cpu, "wr", msr, error);
				workaround_warning(cpu, 122);
				missing++;
			}
		}
		opteron_erratum_122++;
#else
		workaround_warning(cpu, 122);
		missing++;
#endif
	/*CONSTANTCONDITION*/
	} while (0);

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 123) > 0) do {
		/*
		 * Bypassed Reads May Cause Data Corruption of System Hang in
		 * Dual Core Processors
		 */
#if defined(OPTERON_ERRATUM_123)
		uint64_t value;
		const uint_t msr = MSR_AMD_PATCHLEVEL;
		int err;

		/*
		 * Erratum 123 applies only to multi-core cpus.
		 */
		if (cpuid_get_ncpu_per_chip(cpu) < 2)
			break;
#if defined(__xpv)
		if (!DOMAIN_IS_INITDOMAIN(xen_info))
			break;
#endif
		/*
		 * The "workaround" is to print a warning to upgrade the BIOS
		 */
		if ((err = checked_rdmsr(msr, &value)) != 0) {
			msr_warning(cpu, "rd", msr, err);
			workaround_warning(cpu, 123);
			missing++;
		}
		if (value == 0)
			opteron_erratum_123++;
#else
		workaround_warning(cpu, 123);
		missing++;

#endif
	/*CONSTANTCONDITION*/
	} while (0);

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 131) > 0) do {
		/*
		 * Multiprocessor Systems with Four or More Cores May Deadlock
		 * Waiting for a Probe Response
		 */
#if defined(OPTERON_ERRATUM_131)
		uint64_t nbcfg;
		const uint_t msr = MSR_AMD_NB_CFG;
		const uint64_t wabits =
		    AMD_NB_CFG_SRQ_HEARTBEAT | AMD_NB_CFG_SRQ_SPR;
		int error;

		/*
		 * Erratum 131 applies to any system with four or more cores.
		 */
		if (opteron_erratum_131)
			break;
#if defined(__xpv)
		if (!DOMAIN_IS_INITDOMAIN(xen_info))
			break;
		if (xpv_nr_phys_cpus() < 4)
			break;
#else
		if (opteron_get_nnodes() * cpuid_get_ncpu_per_chip(cpu) < 4)
			break;
#endif
		/*
		 * Print a warning if neither of the workarounds for
		 * erratum 131 is present.
		 */
		if ((error = checked_rdmsr(msr, &nbcfg)) != 0) {
			msr_warning(cpu, "rd", msr, error);
			workaround_warning(cpu, 131);
			missing++;
		} else if ((nbcfg & wabits) == 0) {
			opteron_erratum_131++;
		} else {
			/* cannot have both workarounds set */
			ASSERT((nbcfg & wabits) != wabits);
		}
#else
		workaround_warning(cpu, 131);
		missing++;
#endif
	/*CONSTANTCONDITION*/
	} while (0);

	/*
	 * This isn't really an erratum, but for convenience the
	 * detection/workaround code lives here and in cpuid_opteron_erratum.
	 */
	if (cpuid_opteron_erratum(cpu, 6336786) > 0) {
#if defined(OPTERON_WORKAROUND_6336786)
		/*
		 * Disable C1-Clock ramping on multi-core/multi-processor
		 * K8 platforms to guard against TSC drift.
		 */
		if (opteron_workaround_6336786) {
			opteron_workaround_6336786++;
#if defined(__xpv)
		} else if ((DOMAIN_IS_INITDOMAIN(xen_info) &&
		    xpv_nr_phys_cpus() > 1) ||
		    opteron_workaround_6336786_UP) {
			/*
			 * XXPV	Hmm.  We can't walk the Northbridges on
			 *	the hypervisor; so just complain and drive
			 *	on.  This probably needs to be fixed in
			 *	the hypervisor itself.
			 */
			opteron_workaround_6336786++;
			workaround_warning(cpu, 6336786);
#else	/* __xpv */
		} else if ((opteron_get_nnodes() *
		    cpuid_get_ncpu_per_chip(cpu) > 1) ||
		    opteron_workaround_6336786_UP) {

			uint_t	node, nnodes;
			uint8_t data;

			nnodes = opteron_get_nnodes();
			for (node = 0; node < nnodes; node++) {
				/*
				 * Clear PMM7[1:0] (function 3, offset 0x87)
				 * Northbridge device is the node id + 24.
				 */
				data = pci_getb_func(0, node + 24, 3, 0x87);
				data &= 0xFC;
				pci_putb_func(0, node + 24, 3, 0x87, data);
			}
			opteron_workaround_6336786++;
#endif	/* __xpv */
		}
#else
		workaround_warning(cpu, 6336786);
		missing++;
#endif
	}

	/*LINTED*/
	/*
	 * Mutex primitives don't work as expected.
	 */
	if (cpuid_opteron_erratum(cpu, 6323525) > 0) {
#if defined(OPTERON_WORKAROUND_6323525)
		/*
		 * This problem only occurs with 2 or more cores. If bit in
		 * MSR_AMD_BU_CFG set, then not applicable. The workaround
		 * is to patch the semaphone routines with the lfence
		 * instruction to provide necessary load memory barrier with
		 * possible subsequent read-modify-write ops.
		 *
		 * It is too early in boot to call the patch routine so
		 * set erratum variable to be done in startup_end().
		 */
		if (opteron_workaround_6323525) {
			opteron_workaround_6323525++;
#if defined(__xpv)
		} else if (is_x86_feature(x86_featureset, X86FSET_SSE2)) {
			if (DOMAIN_IS_INITDOMAIN(xen_info)) {
				/*
				 * XXPV	Use dom0_msr here when extended
				 *	operations are supported?
				 */
				if (xpv_nr_phys_cpus() > 1)
					opteron_workaround_6323525++;
			} else {
				/*
				 * We have no way to tell how many physical
				 * cpus there are, or even if this processor
				 * has the problem, so enable the workaround
				 * unconditionally (at some performance cost).
				 */
				opteron_workaround_6323525++;
			}
#else	/* __xpv */
		} else if (is_x86_feature(x86_featureset, X86FSET_SSE2) &&
		    ((opteron_get_nnodes() *
		    cpuid_get_ncpu_per_chip(cpu)) > 1)) {
			if ((xrdmsr(MSR_AMD_BU_CFG) & (UINT64_C(1) << 33)) == 0)
				opteron_workaround_6323525++;
#endif	/* __xpv */
		}
#else
		workaround_warning(cpu, 6323525);
		missing++;
#endif
	}

	missing += do_erratum_298(cpu);

	if (cpuid_opteron_erratum(cpu, 721) > 0) {
#if defined(OPTERON_ERRATUM_721)
		on_trap_data_t otd;

		if (!on_trap(&otd, OT_DATA_ACCESS))
			wrmsr(MSR_AMD_DE_CFG,
			    rdmsr(MSR_AMD_DE_CFG) | AMD_DE_CFG_E721);
		no_trap();

		opteron_erratum_721++;
#else
		workaround_warning(cpu, 721);
		missing++;
#endif
	}

#ifdef __xpv
	return (0);
#else
	return (missing);
#endif
}

void
workaround_errata_end()
{
#if defined(OPTERON_ERRATUM_88)
	if (opteron_erratum_88)
		workaround_applied(88);
#endif
#if defined(OPTERON_ERRATUM_91)
	if (opteron_erratum_91)
		workaround_applied(91);
#endif
#if defined(OPTERON_ERRATUM_93)
	if (opteron_erratum_93)
		workaround_applied(93);
#endif
#if defined(OPTERON_ERRATUM_95)
	if (opteron_erratum_95)
		workaround_applied(95);
#endif
#if defined(OPTERON_ERRATUM_100)
	if (opteron_erratum_100)
		workaround_applied(100);
#endif
#if defined(OPTERON_ERRATUM_108)
	if (opteron_erratum_108)
		workaround_applied(108);
#endif
#if defined(OPTERON_ERRATUM_109)
	if (opteron_erratum_109) {
		cmn_err(CE_WARN,
		    "BIOS microcode patch for AMD Athlon(tm) 64/Opteron(tm)"
		    " processor\nerratum 109 was not detected; updating your"
		    " system's BIOS to a version\ncontaining this"
		    " microcode patch is HIGHLY recommended or erroneous"
		    " system\noperation may occur.\n");
	}
#endif
#if defined(OPTERON_ERRATUM_121)
	if (opteron_erratum_121)
		workaround_applied(121);
#endif
#if defined(OPTERON_ERRATUM_122)
	if (opteron_erratum_122)
		workaround_applied(122);
#endif
#if defined(OPTERON_ERRATUM_123)
	if (opteron_erratum_123) {
		cmn_err(CE_WARN,
		    "BIOS microcode patch for AMD Athlon(tm) 64/Opteron(tm)"
		    " processor\nerratum 123 was not detected; updating your"
		    " system's BIOS to a version\ncontaining this"
		    " microcode patch is HIGHLY recommended or erroneous"
		    " system\noperation may occur.\n");
	}
#endif
#if defined(OPTERON_ERRATUM_131)
	if (opteron_erratum_131) {
		cmn_err(CE_WARN,
		    "BIOS microcode patch for AMD Athlon(tm) 64/Opteron(tm)"
		    " processor\nerratum 131 was not detected; updating your"
		    " system's BIOS to a version\ncontaining this"
		    " microcode patch is HIGHLY recommended or erroneous"
		    " system\noperation may occur.\n");
	}
#endif
#if defined(OPTERON_WORKAROUND_6336786)
	if (opteron_workaround_6336786)
		workaround_applied(6336786);
#endif
#if defined(OPTERON_WORKAROUND_6323525)
	if (opteron_workaround_6323525)
		workaround_applied(6323525);
#endif
#if defined(OPTERON_ERRATUM_298)
	if (opteron_erratum_298) {
		cmn_err(CE_WARN,
		    "BIOS microcode patch for AMD 64/Opteron(tm)"
		    " processor\nerratum 298 was not detected; updating your"
		    " system's BIOS to a version\ncontaining this"
		    " microcode patch is HIGHLY recommended or erroneous"
		    " system\noperation may occur.\n");
	}
#endif
#if defined(OPTERON_ERRATUM_721)
	if (opteron_erratum_721)
		workaround_applied(721);
#endif
}

/*
 * The procset_slave and procset_master are used to synchronize
 * between the control CPU and the target CPU when starting CPUs.
 */
static cpuset_t procset_slave, procset_master;

static void
mp_startup_wait(cpuset_t *sp, processorid_t cpuid)
{
	cpuset_t tempset;

	for (tempset = *sp; !CPU_IN_SET(tempset, cpuid);
	    tempset = *(volatile cpuset_t *)sp) {
		SMT_PAUSE();
	}
	CPUSET_ATOMIC_DEL(*(cpuset_t *)sp, cpuid);
}

static void
mp_startup_signal(cpuset_t *sp, processorid_t cpuid)
{
	cpuset_t tempset;

	CPUSET_ATOMIC_ADD(*(cpuset_t *)sp, cpuid);
	for (tempset = *sp; CPU_IN_SET(tempset, cpuid);
	    tempset = *(volatile cpuset_t *)sp) {
		SMT_PAUSE();
	}
}

int
mp_start_cpu_common(cpu_t *cp, boolean_t boot)
{
	_NOTE(ARGUNUSED(boot));

	void *ctx;
	int delays;
	int error = 0;
	cpuset_t tempset;
	processorid_t cpuid;
#ifndef __xpv
	extern void cpupm_init(cpu_t *);
#endif

	ASSERT(cp != NULL);
	cpuid = cp->cpu_id;
	ctx = mach_cpucontext_alloc(cp);
	if (ctx == NULL) {
		cmn_err(CE_WARN,
		    "cpu%d: failed to allocate context", cp->cpu_id);
		return (EAGAIN);
	}
	error = mach_cpu_start(cp, ctx);
	if (error != 0) {
		cmn_err(CE_WARN,
		    "cpu%d: failed to start, error %d", cp->cpu_id, error);
		mach_cpucontext_free(cp, ctx, error);
		return (error);
	}

	for (delays = 0, tempset = procset_slave; !CPU_IN_SET(tempset, cpuid);
	    delays++) {
		if (delays == 500) {
			/*
			 * After five seconds, things are probably looking
			 * a bit bleak - explain the hang.
			 */
			cmn_err(CE_NOTE, "cpu%d: started, "
			    "but not running in the kernel yet", cpuid);
		} else if (delays > 2000) {
			/*
			 * We waited at least 20 seconds, bail ..
			 */
			error = ETIMEDOUT;
			cmn_err(CE_WARN, "cpu%d: timed out", cpuid);
			mach_cpucontext_free(cp, ctx, error);
			return (error);
		}

		/*
		 * wait at least 10ms, then check again..
		 */
		delay(USEC_TO_TICK_ROUNDUP(10000));
		tempset = *((volatile cpuset_t *)&procset_slave);
	}
	CPUSET_ATOMIC_DEL(procset_slave, cpuid);

	mach_cpucontext_free(cp, ctx, 0);

#ifndef __xpv
	if (tsc_gethrtime_enable)
		tsc_sync_master(cpuid);
#endif

	if (dtrace_cpu_init != NULL) {
		(*dtrace_cpu_init)(cpuid);
	}

	/*
	 * During CPU DR operations, the cpu_lock is held by current
	 * (the control) thread. We can't release the cpu_lock here
	 * because that will break the CPU DR logic.
	 * On the other hand, CPUPM and processor group initialization
	 * routines need to access the cpu_lock. So we invoke those
	 * routines here on behalf of mp_startup_common().
	 *
	 * CPUPM and processor group initialization routines depend
	 * on the cpuid probing results. Wait for mp_startup_common()
	 * to signal that cpuid probing is done.
	 */
	mp_startup_wait(&procset_slave, cpuid);
#ifndef __xpv
	cpupm_init(cp);
#endif
	(void) pg_cpu_init(cp, B_FALSE);
	cpu_set_state(cp);
	mp_startup_signal(&procset_master, cpuid);

	return (0);
}

/*
 * Start a single cpu, assuming that the kernel context is available
 * to successfully start another cpu.
 *
 * (For example, real mode code is mapped into the right place
 * in memory and is ready to be run.)
 */
int
start_cpu(processorid_t who)
{
	cpu_t *cp;
	int error = 0;
	cpuset_t tempset;

	ASSERT(who != 0);

	/*
	 * Check if there's at least a Mbyte of kmem available
	 * before attempting to start the cpu.
	 */
	if (kmem_avail() < 1024 * 1024) {
		/*
		 * Kick off a reap in case that helps us with
		 * later attempts ..
		 */
		kmem_reap();
		return (ENOMEM);
	}

	/*
	 * First configure cpu.
	 */
	cp = mp_cpu_configure_common(who, B_TRUE);
	ASSERT(cp != NULL);

	/*
	 * Then start cpu.
	 */
	error = mp_start_cpu_common(cp, B_TRUE);
	if (error != 0) {
		mp_cpu_unconfigure_common(cp, error);
		return (error);
	}

	mutex_exit(&cpu_lock);
	tempset = cpu_ready_set;
	while (!CPU_IN_SET(tempset, who)) {
		drv_usecwait(1);
		tempset = *((volatile cpuset_t *)&cpu_ready_set);
	}
	mutex_enter(&cpu_lock);

	return (0);
}

void
start_other_cpus(int cprboot)
{
	_NOTE(ARGUNUSED(cprboot));

	uint_t who;
	uint_t bootcpuid = 0;

	/*
	 * Initialize our own cpu_info.
	 */
	init_cpu_info(CPU);

#if !defined(__xpv)
	init_cpu_id_gdt(CPU);
#endif

	cmn_err(CE_CONT, "?cpu%d: %s\n", CPU->cpu_id, CPU->cpu_idstr);
	cmn_err(CE_CONT, "?cpu%d: %s\n", CPU->cpu_id, CPU->cpu_brandstr);

	/*
	 * KPTI initialisation happens very early in boot, before logging is
	 * set up. Output a status message now as the boot CPU comes online.
	 */
	cmn_err(CE_CONT, "?KPTI %s (PCID %s, INVPCID %s)\n",
	    kpti_enable ? "enabled" : "disabled",
	    x86_use_pcid == 1 ? "in use" :
	    (is_x86_feature(x86_featureset, X86FSET_PCID) ? "disabled" :
	    "not supported"),
	    x86_use_pcid == 1 && x86_use_invpcid == 1 ? "in use" :
	    (is_x86_feature(x86_featureset, X86FSET_INVPCID) ? "disabled" :
	    "not supported"));

	/*
	 * Initialize our syscall handlers
	 */
	init_cpu_syscall(CPU);

	/*
	 * Take the boot cpu out of the mp_cpus set because we know
	 * it's already running.  Add it to the cpu_ready_set for
	 * precisely the same reason.
	 */
	CPUSET_DEL(mp_cpus, bootcpuid);
	CPUSET_ADD(cpu_ready_set, bootcpuid);

	/*
	 * skip the rest of this if
	 * . only 1 cpu dectected and system isn't hotplug-capable
	 * . not using MP
	 */
	if ((CPUSET_ISNULL(mp_cpus) && plat_dr_support_cpu() == 0) ||
	    use_mp == 0) {
		if (use_mp == 0)
			cmn_err(CE_CONT, "?***** Not in MP mode\n");
		goto done;
	}

	/*
	 * perform such initialization as is needed
	 * to be able to take CPUs on- and off-line.
	 */
	cpu_pause_init();

	xc_init_cpu(CPU);		/* initialize processor crosscalls */

	if (mach_cpucontext_init() != 0)
		goto done;

	flushes_require_xcalls = 1;

	/*
	 * We lock our affinity to the master CPU to ensure that all slave CPUs
	 * do their TSC syncs with the same CPU.
	 */
	affinity_set(CPU_CURRENT);

	for (who = 0; who < NCPU; who++) {
		if (!CPU_IN_SET(mp_cpus, who))
			continue;
		ASSERT(who != bootcpuid);

		mutex_enter(&cpu_lock);
		if (start_cpu(who) != 0)
			CPUSET_DEL(mp_cpus, who);
		cpu_state_change_notify(who, CPU_SETUP);
		mutex_exit(&cpu_lock);
	}

	/* Free the space allocated to hold the microcode file */
	ucode_cleanup();

	affinity_clear();

	mach_cpucontext_fini();

done:
	if (get_hwenv() == HW_NATIVE)
		workaround_errata_end();
	cmi_post_mpstartup();

	if (use_mp && ncpus != boot_max_ncpus) {
		cmn_err(CE_NOTE,
		    "System detected %d cpus, but "
		    "only %d cpu(s) were enabled during boot.",
		    boot_max_ncpus, ncpus);
		cmn_err(CE_NOTE,
		    "Use \"boot-ncpus\" parameter to enable more CPU(s). "
		    "See eeprom(1M).");
	}
}

int
mp_cpu_configure(int cpuid)
{
	cpu_t *cp;

	if (use_mp == 0 || plat_dr_support_cpu() == 0) {
		return (ENOTSUP);
	}

	cp = cpu_get(cpuid);
	if (cp != NULL) {
		return (EALREADY);
	}

	/*
	 * Check if there's at least a Mbyte of kmem available
	 * before attempting to start the cpu.
	 */
	if (kmem_avail() < 1024 * 1024) {
		/*
		 * Kick off a reap in case that helps us with
		 * later attempts ..
		 */
		kmem_reap();
		return (ENOMEM);
	}

	cp = mp_cpu_configure_common(cpuid, B_FALSE);
	ASSERT(cp != NULL && cpu_get(cpuid) == cp);

	return (cp != NULL ? 0 : EAGAIN);
}

int
mp_cpu_unconfigure(int cpuid)
{
	cpu_t *cp;

	if (use_mp == 0 || plat_dr_support_cpu() == 0) {
		return (ENOTSUP);
	} else if (cpuid < 0 || cpuid >= max_ncpus) {
		return (EINVAL);
	}

	cp = cpu_get(cpuid);
	if (cp == NULL) {
		return (ENODEV);
	}
	mp_cpu_unconfigure_common(cp, 0);

	return (0);
}

/*
 * Startup function for 'other' CPUs (besides boot cpu).
 * Called from real_mode_start.
 *
 * WARNING: until CPU_READY is set, mp_startup_common and routines called by
 * mp_startup_common should not call routines (e.g. kmem_free) that could call
 * hat_unload which requires CPU_READY to be set.
 */
static void
mp_startup_common(boolean_t boot)
{
	cpu_t *cp = CPU;
	uchar_t new_x86_featureset[BT_SIZEOFMAP(NUM_X86_FEATURES)];
	extern void cpu_event_init_cpu(cpu_t *);

	/*
	 * We need to get TSC on this proc synced (i.e., any delta
	 * from cpu0 accounted for) as soon as we can, because many
	 * many things use gethrtime/pc_gethrestime, including
	 * interrupts, cmn_err, etc.  Before we can do that, we want to
	 * clear TSC if we're on a buggy Sandy/Ivy Bridge CPU, so do that
	 * right away.
	 */
	bzero(new_x86_featureset, BT_SIZEOFMAP(NUM_X86_FEATURES));
	cpuid_pass1(cp, new_x86_featureset);

	if (boot && get_hwenv() == HW_NATIVE &&
	    cpuid_getvendor(CPU) == X86_VENDOR_Intel &&
	    cpuid_getfamily(CPU) == 6 &&
	    (cpuid_getmodel(CPU) == 0x2d || cpuid_getmodel(CPU) == 0x3e) &&
	    is_x86_feature(new_x86_featureset, X86FSET_TSC)) {
		(void) wrmsr(REG_TSC, 0UL);
	}

	/* Let the control CPU continue into tsc_sync_master() */
	mp_startup_signal(&procset_slave, cp->cpu_id);

#ifndef __xpv
	if (tsc_gethrtime_enable)
		tsc_sync_slave();
#endif

	/*
	 * Once this was done from assembly, but it's safer here; if
	 * it blocks, we need to be able to swtch() to and from, and
	 * since we get here by calling t_pc, we need to do that call
	 * before swtch() overwrites it.
	 */
	(void) (*ap_mlsetup)();

#ifndef __xpv
	/*
	 * Program this cpu's PAT
	 */
	pat_sync();
#endif

	/*
	 * Set up TSC_AUX to contain the cpuid for this processor
	 * for the rdtscp instruction.
	 */
	if (is_x86_feature(x86_featureset, X86FSET_TSCP))
		(void) wrmsr(MSR_AMD_TSCAUX, cp->cpu_id);

	/*
	 * Initialize this CPU's syscall handlers
	 */
	init_cpu_syscall(cp);

	/*
	 * Enable interrupts with spl set to LOCK_LEVEL. LOCK_LEVEL is the
	 * highest level at which a routine is permitted to block on
	 * an adaptive mutex (allows for cpu poke interrupt in case
	 * the cpu is blocked on a mutex and halts). Setting LOCK_LEVEL blocks
	 * device interrupts that may end up in the hat layer issuing cross
	 * calls before CPU_READY is set.
	 */
	splx(ipltospl(LOCK_LEVEL));
	sti();

	/*
	 * Do a sanity check to make sure this new CPU is a sane thing
	 * to add to the collection of processors running this system.
	 *
	 * XXX	Clearly this needs to get more sophisticated, if x86
	 * systems start to get built out of heterogenous CPUs; as is
	 * likely to happen once the number of processors in a configuration
	 * gets large enough.
	 */
	if (compare_x86_featureset(x86_featureset, new_x86_featureset) ==
	    B_FALSE) {
		cmn_err(CE_CONT, "cpu%d: featureset\n", cp->cpu_id);
		print_x86_featureset(new_x86_featureset);
		cmn_err(CE_WARN, "cpu%d feature mismatch", cp->cpu_id);
	}

	/*
	 * There exists a small subset of systems which expose differing
	 * MWAIT/MONITOR support between CPUs.  If MWAIT support is absent from
	 * the boot CPU, but is found on a later CPU, the system continues to
	 * operate as if no MWAIT support is available.
	 *
	 * The reverse case, where MWAIT is available on the boot CPU but not
	 * on a subsequently initialized CPU, is not presently allowed and will
	 * result in a panic.
	 */
	if (is_x86_feature(x86_featureset, X86FSET_MWAIT) !=
	    is_x86_feature(new_x86_featureset, X86FSET_MWAIT)) {
		if (!is_x86_feature(x86_featureset, X86FSET_MWAIT)) {
			remove_x86_feature(new_x86_featureset, X86FSET_MWAIT);
		} else {
			panic("unsupported mixed cpu mwait support detected");
		}
	}

	/*
	 * We could be more sophisticated here, and just mark the CPU
	 * as "faulted" but at this point we'll opt for the easier
	 * answer of dying horribly.  Provided the boot cpu is ok,
	 * the system can be recovered by booting with use_mp set to zero.
	 */
	if (workaround_errata(cp) != 0)
		panic("critical workaround(s) missing for cpu%d", cp->cpu_id);

	/*
	 * We can touch cpu_flags here without acquiring the cpu_lock here
	 * because the cpu_lock is held by the control CPU which is running
	 * mp_start_cpu_common().
	 * Need to clear CPU_QUIESCED flag before calling any function which
	 * may cause thread context switching, such as kmem_alloc() etc.
	 * The idle thread checks for CPU_QUIESCED flag and loops for ever if
	 * it's set. So the startup thread may have no chance to switch back
	 * again if it's switched away with CPU_QUIESCED set.
	 */
	cp->cpu_flags &= ~(CPU_POWEROFF | CPU_QUIESCED);

	enable_pcid();

	/*
	 * Setup this processor for XSAVE.
	 */
	if (fp_save_mech == FP_XSAVE) {
		xsave_setup_msr(cp);
	}

	cpuid_pass2(cp);
	cpuid_pass3(cp);
	cpuid_pass4(cp, NULL);

	/*
	 * Correct cpu_idstr and cpu_brandstr on target CPU after
	 * cpuid_pass1() is done.
	 */
	(void) cpuid_getidstr(cp, cp->cpu_idstr, CPU_IDSTRLEN);
	(void) cpuid_getbrandstr(cp, cp->cpu_brandstr, CPU_IDSTRLEN);

	cp->cpu_flags |= CPU_RUNNING | CPU_READY | CPU_EXISTS;

	post_startup_cpu_fixups();

	cpu_event_init_cpu(cp);

	/*
	 * Enable preemption here so that contention for any locks acquired
	 * later in mp_startup_common may be preempted if the thread owning
	 * those locks is continuously executing on other CPUs (for example,
	 * this CPU must be preemptible to allow other CPUs to pause it during
	 * their startup phases).  It's safe to enable preemption here because
	 * the CPU state is pretty-much fully constructed.
	 */
	curthread->t_preempt = 0;

	/* The base spl should still be at LOCK LEVEL here */
	ASSERT(cp->cpu_base_spl == ipltospl(LOCK_LEVEL));
	set_base_spl();		/* Restore the spl to its proper value */

	pghw_physid_create(cp);
	/*
	 * Delegate initialization tasks, which need to access the cpu_lock,
	 * to mp_start_cpu_common() because we can't acquire the cpu_lock here
	 * during CPU DR operations.
	 */
	mp_startup_signal(&procset_slave, cp->cpu_id);
	mp_startup_wait(&procset_master, cp->cpu_id);
	pg_cmt_cpu_startup(cp);

	if (boot) {
		mutex_enter(&cpu_lock);
		cp->cpu_flags &= ~CPU_OFFLINE;
		cpu_enable_intr(cp);
		cpu_add_active(cp);
		mutex_exit(&cpu_lock);
	}

	/* Enable interrupts */
	(void) spl0();

	/*
	 * Fill out cpu_ucode_info.  Update microcode if necessary.
	 */
	ucode_check(cp);

#ifndef __xpv
	{
		/*
		 * Set up the CPU module for this CPU.  This can't be done
		 * before this CPU is made CPU_READY, because we may (in
		 * heterogeneous systems) need to go load another CPU module.
		 * The act of attempting to load a module may trigger a
		 * cross-call, which will ASSERT unless this cpu is CPU_READY.
		 */
		cmi_hdl_t hdl;

		if ((hdl = cmi_init(CMI_HDL_NATIVE, cmi_ntv_hwchipid(CPU),
		    cmi_ntv_hwcoreid(CPU), cmi_ntv_hwstrandid(CPU))) != NULL) {
			if (is_x86_feature(x86_featureset, X86FSET_MCA))
				cmi_mca_init(hdl);
			cp->cpu_m.mcpu_cmi_hdl = hdl;
		}
	}
#endif /* __xpv */

	if (boothowto & RB_DEBUG)
		kdi_cpu_init();

	(void) mach_cpu_create_device_node(cp, NULL);

	/*
	 * Setting the bit in cpu_ready_set must be the last operation in
	 * processor initialization; the boot CPU will continue to boot once
	 * it sees this bit set for all active CPUs.
	 */
	CPUSET_ATOMIC_ADD(cpu_ready_set, cp->cpu_id);

	cmn_err(CE_CONT, "?cpu%d: %s\n", cp->cpu_id, cp->cpu_idstr);
	cmn_err(CE_CONT, "?cpu%d: %s\n", cp->cpu_id, cp->cpu_brandstr);
	cmn_err(CE_CONT, "?cpu%d initialization complete - online\n",
	    cp->cpu_id);

	/*
	 * Now we are done with the startup thread, so free it up.
	 */
	thread_exit();
	panic("mp_startup: cannot return");
	/*NOTREACHED*/
}

/*
 * Startup function for 'other' CPUs at boot time (besides boot cpu).
 */
static void
mp_startup_boot(void)
{
	mp_startup_common(B_TRUE);
}

/*
 * Startup function for hotplug CPUs at runtime.
 */
void
mp_startup_hotplug(void)
{
	mp_startup_common(B_FALSE);
}

/*
 * Start CPU on user request.
 */
/* ARGSUSED */
int
mp_cpu_start(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (0);
}

/*
 * Stop CPU on user request.
 */
int
mp_cpu_stop(struct cpu *cp)
{
	extern int cbe_psm_timer_mode;
	ASSERT(MUTEX_HELD(&cpu_lock));

#ifdef __xpv
	/*
	 * We can't offline vcpu0.
	 */
	if (cp->cpu_id == 0)
		return (EBUSY);
#endif

	/*
	 * If TIMER_PERIODIC mode is used, CPU0 is the one running it;
	 * can't stop it.  (This is true only for machines with no TSC.)
	 */

	if ((cbe_psm_timer_mode == TIMER_PERIODIC) && (cp->cpu_id == 0))
		return (EBUSY);

	return (0);
}

/*
 * Take the specified CPU out of participation in interrupts.
 */
int
cpu_disable_intr(struct cpu *cp)
{
	if (psm_disable_intr(cp->cpu_id) != DDI_SUCCESS)
		return (EBUSY);

	cp->cpu_flags &= ~CPU_ENABLE;
	return (0);
}

/*
 * Allow the specified CPU to participate in interrupts.
 */
void
cpu_enable_intr(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	cp->cpu_flags |= CPU_ENABLE;
	psm_enable_intr(cp->cpu_id);
}

void
mp_cpu_faulted_enter(struct cpu *cp)
{
#ifdef __xpv
	_NOTE(ARGUNUSED(cp));
#else
	cmi_hdl_t hdl = cp->cpu_m.mcpu_cmi_hdl;

	if (hdl != NULL) {
		cmi_hdl_hold(hdl);
	} else {
		hdl = cmi_hdl_lookup(CMI_HDL_NATIVE, cmi_ntv_hwchipid(cp),
		    cmi_ntv_hwcoreid(cp), cmi_ntv_hwstrandid(cp));
	}
	if (hdl != NULL) {
		cmi_faulted_enter(hdl);
		cmi_hdl_rele(hdl);
	}
#endif
}

void
mp_cpu_faulted_exit(struct cpu *cp)
{
#ifdef __xpv
	_NOTE(ARGUNUSED(cp));
#else
	cmi_hdl_t hdl = cp->cpu_m.mcpu_cmi_hdl;

	if (hdl != NULL) {
		cmi_hdl_hold(hdl);
	} else {
		hdl = cmi_hdl_lookup(CMI_HDL_NATIVE, cmi_ntv_hwchipid(cp),
		    cmi_ntv_hwcoreid(cp), cmi_ntv_hwstrandid(cp));
	}
	if (hdl != NULL) {
		cmi_faulted_exit(hdl);
		cmi_hdl_rele(hdl);
	}
#endif
}

/*
 * The following two routines are used as context operators on threads belonging
 * to processes with a private LDT (see sysi86).  Due to the rarity of such
 * processes, these routines are currently written for best code readability and
 * organization rather than speed.  We could avoid checking x86_featureset at
 * every context switch by installing different context ops, depending on
 * x86_featureset, at LDT creation time -- one for each combination of fast
 * syscall features.
 */

void
cpu_fast_syscall_disable(void)
{
	if (is_x86_feature(x86_featureset, X86FSET_MSR) &&
	    is_x86_feature(x86_featureset, X86FSET_SEP))
		cpu_sep_disable();
	if (is_x86_feature(x86_featureset, X86FSET_MSR) &&
	    is_x86_feature(x86_featureset, X86FSET_ASYSC))
		cpu_asysc_disable();
}

void
cpu_fast_syscall_enable(void)
{
	if (is_x86_feature(x86_featureset, X86FSET_MSR) &&
	    is_x86_feature(x86_featureset, X86FSET_SEP))
		cpu_sep_enable();
	if (is_x86_feature(x86_featureset, X86FSET_MSR) &&
	    is_x86_feature(x86_featureset, X86FSET_ASYSC))
		cpu_asysc_enable();
}

static void
cpu_sep_enable(void)
{
	ASSERT(is_x86_feature(x86_featureset, X86FSET_SEP));
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	wrmsr(MSR_INTC_SEP_CS, (uint64_t)(uintptr_t)KCS_SEL);
}

static void
cpu_sep_disable(void)
{
	ASSERT(is_x86_feature(x86_featureset, X86FSET_SEP));
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	/*
	 * Setting the SYSENTER_CS_MSR register to 0 causes software executing
	 * the sysenter or sysexit instruction to trigger a #gp fault.
	 */
	wrmsr(MSR_INTC_SEP_CS, 0);
}

static void
cpu_asysc_enable(void)
{
	ASSERT(is_x86_feature(x86_featureset, X86FSET_ASYSC));
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	wrmsr(MSR_AMD_EFER, rdmsr(MSR_AMD_EFER) |
	    (uint64_t)(uintptr_t)AMD_EFER_SCE);
}

static void
cpu_asysc_disable(void)
{
	ASSERT(is_x86_feature(x86_featureset, X86FSET_ASYSC));
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	/*
	 * Turn off the SCE (syscall enable) bit in the EFER register. Software
	 * executing syscall or sysret with this bit off will incur a #ud trap.
	 */
	wrmsr(MSR_AMD_EFER, rdmsr(MSR_AMD_EFER) &
	    ~((uint64_t)(uintptr_t)AMD_EFER_SCE));
}
