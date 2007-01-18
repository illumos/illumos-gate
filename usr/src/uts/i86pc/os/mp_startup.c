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
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/mmu.h>
#include <sys/class.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/asm_linkage.h>
#include <sys/x_call.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/vtrace.h>
#include <vm/hat.h>
#include <sys/mmu.h>
#include <vm/as.h>
#include <vm/seg_kmem.h>
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
#include <sys/kdi.h>
#include <vm/hat_i86.h>
#include <sys/memnode.h>
#include <sys/pci_cfgspace.h>
#include <sys/cpu_module.h>

struct cpu	cpus[1];			/* CPU data */
struct cpu	*cpu[NCPU] = {&cpus[0]};	/* pointers to all CPUs */
cpu_core_t	cpu_core[NCPU];			/* cpu_core structures */

/*
 * Useful for disabling MP bring-up for an MP capable kernel
 * (a kernel that was built with MP defined)
 */
int use_mp = 1;

/*
 * To be set by a PSM to indicate what CPUs are available on the system.
 */
cpuset_t mp_cpus = 1;

/*
 * This variable is used by the hat layer to decide whether or not
 * critical sections are needed to prevent race conditions.  For sun4m,
 * this variable is set once enough MP initialization has been done in
 * order to allow cross calls.
 */
int flushes_require_xcalls = 0;
cpuset_t	cpu_ready_set = 1;

extern	void	real_mode_start(void);
extern	void	real_mode_end(void);
static 	void	mp_startup(void);

static void cpu_sep_enable(void);
static void cpu_sep_disable(void);
static void cpu_asysc_enable(void);
static void cpu_asysc_disable(void);

extern int tsc_gethrtime_enable;

/*
 * Init CPU info - get CPU type info for processor_info system call.
 */
void
init_cpu_info(struct cpu *cp)
{
	processor_info_t *pi = &cp->cpu_type_info;
	char buf[CPU_IDSTRLEN];

	/*
	 * Get clock-frequency property for the CPU.
	 */
	pi->pi_clock = cpu_freq;

	(void) strcpy(pi->pi_processor_type, "i386");
	if (fpu_exists)
		(void) strcpy(pi->pi_fputypes, "i387 compatible");

	(void) cpuid_getidstr(cp, buf, sizeof (buf));

	cp->cpu_idstr = kmem_alloc(strlen(buf) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_idstr, buf);

	cmn_err(CE_CONT, "?cpu%d: %s\n", cp->cpu_id, cp->cpu_idstr);

	(void) cpuid_getbrandstr(cp, buf, sizeof (buf));
	cp->cpu_brandstr = kmem_alloc(strlen(buf) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_brandstr, buf);

	cmn_err(CE_CONT, "?cpu%d: %s\n", cp->cpu_id, cp->cpu_brandstr);
}

/*
 * Configure syscall support on this CPU.
 */
/*ARGSUSED*/
static void
init_cpu_syscall(struct cpu *cp)
{
	kpreempt_disable();

#if defined(__amd64)
	if (x86_feature & X86_ASYSC) {

#if !defined(__lint)
		/*
		 * The syscall instruction imposes a certain ordering on
		 * segment selectors, so we double-check that ordering
		 * here.
		 */
		ASSERT(KDS_SEL == KCS_SEL + 8);
		ASSERT(UDS_SEL == U32CS_SEL + 8);
		ASSERT(UCS_SEL == U32CS_SEL + 16);
#endif
		/*
		 * Turn syscall/sysret extensions on.
		 */
		cpu_asysc_enable();

		/*
		 * Program the magic registers ..
		 */
		wrmsr(MSR_AMD_STAR, ((uint64_t)(U32CS_SEL << 16 | KCS_SEL)) <<
		    32);
		wrmsr(MSR_AMD_LSTAR, (uint64_t)(uintptr_t)sys_syscall);
		wrmsr(MSR_AMD_CSTAR, (uint64_t)(uintptr_t)sys_syscall32);

		/*
		 * This list of flags is masked off the incoming
		 * %rfl when we enter the kernel.
		 */
		wrmsr(MSR_AMD_SFMASK, (uint64_t)(uintptr_t)(PS_IE | PS_T));
	}
#endif

	/*
	 * On 32-bit kernels, we use sysenter/sysexit because it's too
	 * hard to use syscall/sysret, and it is more portable anyway.
	 *
	 * On 64-bit kernels on Nocona machines, the 32-bit syscall
	 * variant isn't available to 32-bit applications, but sysenter is.
	 */
	if (x86_feature & X86_SEP) {

#if !defined(__lint)
		/*
		 * The sysenter instruction imposes a certain ordering on
		 * segment selectors, so we double-check that ordering
		 * here. See "sysenter" in Intel document 245471-012, "IA-32
		 * Intel Architecture Software Developer's Manual Volume 2:
		 * Instruction Set Reference"
		 */
		ASSERT(KDS_SEL == KCS_SEL + 8);

		ASSERT32(UCS_SEL == ((KCS_SEL + 16) | 3));
		ASSERT32(UDS_SEL == UCS_SEL + 8);

		ASSERT64(U32CS_SEL == ((KCS_SEL + 16) | 3));
		ASSERT64(UDS_SEL == U32CS_SEL + 8);
#endif

		cpu_sep_enable();

		/*
		 * resume() sets this value to the base of the threads stack
		 * via a context handler.
		 */
		wrmsr(MSR_INTC_SEP_ESP, 0ULL);
		wrmsr(MSR_INTC_SEP_EIP, (uint64_t)(uintptr_t)sys_sysenter);
	}

	kpreempt_enable();
}

/*
 * Multiprocessor initialization.
 *
 * Allocate and initialize the cpu structure, TRAPTRACE buffer, and the
 * startup and idle threads for the specified CPU.
 */
static void
mp_startup_init(int cpun)
{
#if defined(__amd64)
extern void *long_mode_64(void);
#endif	/* __amd64 */

	struct cpu *cp;
	struct tss *ntss;
	kthread_id_t tp;
	caddr_t	sp;
	int size;
	proc_t *procp;
	extern void idle();

	struct cpu_tables *tablesp;
	rm_platter_t *real_mode_platter = (rm_platter_t *)rm_platter_va;

#ifdef TRAPTRACE
	trap_trace_ctl_t *ttc = &trap_trace_ctl[cpun];
#endif

	ASSERT(cpun < NCPU && cpu[cpun] == NULL);

	if ((cp = kmem_zalloc(sizeof (*cp), KM_NOSLEEP)) == NULL) {
		panic("mp_startup_init: cpu%d: "
		    "no memory for cpu structure", cpun);
		/*NOTREACHED*/
	}
	procp = curthread->t_procp;

	mutex_enter(&cpu_lock);
	/*
	 * Initialize the dispatcher first.
	 */
	disp_cpu_init(cp);
	mutex_exit(&cpu_lock);

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
	 * Setup thread to start in mp_startup.
	 */
	sp = tp->t_stk;
	tp->t_pc = (uintptr_t)mp_startup;
	tp->t_sp = (uintptr_t)(sp - MINFRAME);

	cp->cpu_id = cpun;
	cp->cpu_self = cp;
	cp->cpu_thread = tp;
	cp->cpu_lwp = NULL;
	cp->cpu_dispthread = tp;
	cp->cpu_dispatch_pri = DISP_PRIO(tp);

	/*
	 * cpu_base_spl must be set explicitly here to prevent any blocking
	 * operations in mp_startup from causing the spl of the cpu to drop
	 * to 0 (allowing device interrupts before we're ready) in resume().
	 * cpu_base_spl MUST remain at LOCK_LEVEL until the cpu is CPU_READY.
	 * As an extra bit of security on DEBUG kernels, this is enforced with
	 * an assertion in mp_startup() -- before cpu_base_spl is set to its
	 * proper value.
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
	 * Perform CPC intialization on the new CPU.
	 */
	kcpc_hw_init(cp);

	/*
	 * Allocate virtual addresses for cpu_caddr1 and cpu_caddr2
	 * for each CPU.
	 */

	setup_vaddr_for_ppcopy(cp);

	/*
	 * Allocate space for page directory, stack, tss, gdt and idt.
	 * This assumes that kmem_alloc will return memory which is aligned
	 * to the next higher power of 2 or a page(if size > MAXABIG)
	 * If this assumption goes wrong at any time due to change in
	 * kmem alloc, things may not work as the page directory has to be
	 * page aligned
	 */
	if ((tablesp = kmem_zalloc(sizeof (*tablesp), KM_NOSLEEP)) == NULL)
		panic("mp_startup_init: cpu%d cannot allocate tables", cpun);

	if ((uintptr_t)tablesp & ~MMU_STD_PAGEMASK) {
		kmem_free(tablesp, sizeof (struct cpu_tables));
		size = sizeof (struct cpu_tables) + MMU_STD_PAGESIZE;
		tablesp = kmem_zalloc(size, KM_NOSLEEP);
		tablesp = (struct cpu_tables *)
		    (((uintptr_t)tablesp + MMU_STD_PAGESIZE) &
		    MMU_STD_PAGEMASK);
	}

	ntss = cp->cpu_tss = &tablesp->ct_tss;

	if ((tablesp->ct_gdt = kmem_zalloc(PAGESIZE, KM_NOSLEEP)) == NULL)
		panic("mp_startup_init: cpu%d cannot allocate GDT", cpun);
	cp->cpu_gdt = tablesp->ct_gdt;
	bcopy(CPU->cpu_gdt, cp->cpu_gdt, NGDT * (sizeof (user_desc_t)));

#if defined(__amd64)

	/*
	 * #DF (double fault).
	 */
	ntss->tss_ist1 =
	    (uint64_t)&tablesp->ct_stack[sizeof (tablesp->ct_stack)];

#elif defined(__i386)

	ntss->tss_esp0 = ntss->tss_esp1 = ntss->tss_esp2 = ntss->tss_esp =
	    (uint32_t)&tablesp->ct_stack[sizeof (tablesp->ct_stack)];

	ntss->tss_ss0 = ntss->tss_ss1 = ntss->tss_ss2 = ntss->tss_ss = KDS_SEL;

	ntss->tss_eip = (uint32_t)mp_startup;

	ntss->tss_cs = KCS_SEL;
	ntss->tss_fs = KFS_SEL;
	ntss->tss_gs = KGS_SEL;

	/*
	 * setup kernel %gs.
	 */
	set_usegd(&cp->cpu_gdt[GDT_GS], cp, sizeof (struct cpu) -1, SDT_MEMRWA,
	    SEL_KPL, 0, 1);

#endif	/* __i386 */

	/*
	 * Set I/O bit map offset equal to size of TSS segment limit
	 * for no I/O permission map. This will cause all user I/O
	 * instructions to generate #gp fault.
	 */
	ntss->tss_bitmapbase = sizeof (*ntss);

	/*
	 * setup kernel tss.
	 */
	set_syssegd((system_desc_t *)&cp->cpu_gdt[GDT_KTSS], cp->cpu_tss,
	    sizeof (*cp->cpu_tss) -1, SDT_SYSTSS, SEL_KPL);

	/*
	 * If we have more than one node, each cpu gets a copy of IDT
	 * local to its node. If this is a Pentium box, we use cpu 0's
	 * IDT. cpu 0's IDT has been made read-only to workaround the
	 * cmpxchgl register bug
	 */
	cp->cpu_idt = CPU->cpu_idt;
	if (system_hardware.hd_nodes && x86_type != X86_TYPE_P5) {
		cp->cpu_idt = kmem_alloc(sizeof (idt0), KM_SLEEP);
		bcopy(idt0, cp->cpu_idt, sizeof (idt0));
	}

	/*
	 * Get interrupt priority data from cpu 0
	 */
	cp->cpu_pri_data = CPU->cpu_pri_data;

	hat_cpu_online(cp);

	/* Should remove all entries for the current process/thread here */

	/*
	 * Fill up the real mode platter to make it easy for real mode code to
	 * kick it off. This area should really be one passed by boot to kernel
	 * and guaranteed to be below 1MB and aligned to 16 bytes. Should also
	 * have identical physical and virtual address in paged mode.
	 */
	real_mode_platter->rm_idt_base = cp->cpu_idt;
	real_mode_platter->rm_idt_lim = sizeof (idt0) - 1;
	real_mode_platter->rm_gdt_base = cp->cpu_gdt;
	real_mode_platter->rm_gdt_lim = sizeof (gdt0) -1;
	real_mode_platter->rm_pdbr = getcr3();
	real_mode_platter->rm_cpu = cpun;
	real_mode_platter->rm_x86feature = x86_feature;
	real_mode_platter->rm_cr4 = cr4_value;

#if defined(__amd64)
	if (getcr3() > 0xffffffffUL)
		panic("Cannot initialize CPUs; kernel's 64-bit page tables\n"
			"located above 4G in physical memory (@ 0x%llx).",
			(unsigned long long)getcr3());

	/*
	 * Setup pseudo-descriptors for temporary GDT and IDT for use ONLY
	 * by code in real_mode_start():
	 *
	 * GDT[0]:  NULL selector
	 * GDT[1]:  64-bit CS: Long = 1, Present = 1, bits 12, 11 = 1
	 *
	 * Clear the IDT as interrupts will be off and a limit of 0 will cause
	 * the CPU to triple fault and reset on an NMI, seemingly as reasonable
	 * a course of action as any other, though it may cause the entire
	 * platform to reset in some cases...
	 */
	real_mode_platter->rm_temp_gdt[0] = 0ULL;
	real_mode_platter->rm_temp_gdt[TEMPGDT_KCODE64] = 0x20980000000000ULL;

	real_mode_platter->rm_temp_gdt_lim = (ushort_t)
	    (sizeof (real_mode_platter->rm_temp_gdt) - 1);
	real_mode_platter->rm_temp_gdt_base = rm_platter_pa +
	    (uint32_t)(&((rm_platter_t *)0)->rm_temp_gdt);

	real_mode_platter->rm_temp_idt_lim = 0;
	real_mode_platter->rm_temp_idt_base = 0;

	/*
	 * Since the CPU needs to jump to protected mode using an identity
	 * mapped address, we need to calculate it here.
	 */
	real_mode_platter->rm_longmode64_addr = rm_platter_pa +
	    ((uint32_t)long_mode_64 - (uint32_t)real_mode_start);
#endif	/* __amd64 */

#ifdef TRAPTRACE
	/*
	 * If this is a TRAPTRACE kernel, allocate TRAPTRACE buffers for this
	 * CPU.
	 */
	ttc->ttc_first = (uintptr_t)kmem_zalloc(trap_trace_bufsize, KM_SLEEP);
	ttc->ttc_next = ttc->ttc_first;
	ttc->ttc_limit = ttc->ttc_first + trap_trace_bufsize;
#endif

	/*
	 * Record that we have another CPU.
	 */
	mutex_enter(&cpu_lock);
	/*
	 * Initialize the interrupt threads for this CPU
	 */
	cpu_intr_alloc(cp, NINTR_THREADS);
	/*
	 * Add CPU to list of available CPUs.  It'll be on the active list
	 * after mp_startup().
	 */
	cpu_add_unit(cp);
	mutex_exit(&cpu_lock);
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
 * mp_startup() for all slave CPUs. Slaves process workaround_errata prior
 * to acknowledging their readiness to the master, so this routine will
 * never be executed by multiple CPUs in parallel, thus making updates to
 * global data safe.
 *
 * These workarounds are based on Rev 3.57 of the Revision Guide for
 * AMD Athlon(tm) 64 and AMD Opteron(tm) Processors, August 2005.
 */

#if defined(OPTERON_ERRATUM_91)
int opteron_erratum_91;		/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_93)
int opteron_erratum_93;		/* if non-zero -> at least one cpu has it */
#endif

#if defined(OPTERON_ERRATUM_100)
int opteron_erratum_100;	/* if non-zero -> at least one cpu has it */
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

#define	WARNING(cpu, n)						\
	cmn_err(CE_WARN, "cpu%d: no workaround for erratum %d",	\
	    (cpu)->cpu_id, (n))

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
#else
		WARNING(cpu, 88);
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
		WARNING(cpu, 91);
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
		WARNING(cpu, 93);
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
#endif	/* _LP64 */
#else
		WARNING(cpu, 95);
		missing++;
#endif	/* OPTERON_ERRATUM_95 */
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
		WARNING(cpu, 100);
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
		WARNING(cpu, 108);
		missing++;
#endif
	}

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 109) > 0) {
		/*
		 * Certain Reverse REP MOVS May Produce Unpredictable Behaviour
		 */
#if defined(OPTERON_ERRATUM_109)

		/* workaround is to print a warning to upgrade BIOS */
		if (rdmsr(MSR_AMD_PATCHLEVEL) == 0)
			opteron_erratum_109++;
#else
		WARNING(cpu, 109);
		missing++;
#endif
	}
	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 121) > 0) {
		/*
		 * Sequential Execution Across Non_Canonical Boundary Caused
		 * Processor Hang
		 */
#if defined(OPTERON_ERRATUM_121)
		static int	lma;

		if (opteron_erratum_121)
			opteron_erratum_121++;

		/*
		 * Erratum 121 is only present in long (64 bit) mode.
		 * Workaround is to include the page immediately before the
		 * va hole to eliminate the possibility of system hangs due to
		 * sequential execution across the va hole boundary.
		 */
		if (lma == 0) {
			/*
			 * check LMA once: assume all cpus are in long mode
			 * or not.
			 */
			lma = 1;

			if (rdmsr(MSR_AMD_EFER) & AMD_EFER_LMA) {
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
		}
#else
		WARNING(cpu, 121);
		missing++;
#endif
	}

	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 122) > 0) {
		/*
		 * TLB Flush Filter May Cause Cohenrency Problem in
		 * Multiprocessor Systems
		 */
#if defined(OPTERON_ERRATUM_122)
		/*
		 * Erratum 122 is only present in MP configurations (multi-core
		 * or multi-processor).
		 */

		if (opteron_erratum_122 || lgrp_plat_node_cnt > 1 ||
		    cpuid_get_ncpu_per_chip(cpu) > 1) {
			/* disable TLB Flush Filter */
			wrmsr(MSR_AMD_HWCR, rdmsr(MSR_AMD_HWCR) |
			    (uint64_t)(uintptr_t)AMD_HWCR_FFDIS);
			opteron_erratum_122++;
		}

#else
		WARNING(cpu, 122);
		missing++;
#endif
	}

#if defined(OPTERON_ERRATUM_123)
	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 123) > 0) {
		/*
		 * Bypassed Reads May Cause Data Corruption of System Hang in
		 * Dual Core Processors
		 */
		/*
		 * Erratum 123 applies only to multi-core cpus.
		 */

		if (cpuid_get_ncpu_per_chip(cpu) > 1) {
			/* workaround is to print a warning to upgrade BIOS */
			if (rdmsr(MSR_AMD_PATCHLEVEL) == 0)
				opteron_erratum_123++;
		}
	}
#endif

#if defined(OPTERON_ERRATUM_131)
	/*LINTED*/
	if (cpuid_opteron_erratum(cpu, 131) > 0) {
		/*
		 * Multiprocessor Systems with Four or More Cores May Deadlock
		 * Waiting for a Probe Response
		 */
		/*
		 * Erratum 131 applies to any system with four or more cores.
		 */
		if ((opteron_erratum_131 == 0) && ((lgrp_plat_node_cnt *
		    cpuid_get_ncpu_per_chip(cpu)) >= 4)) {
			uint64_t nbcfg;
			uint64_t wabits;

			/*
			 * Print a warning if neither of the workarounds
			 * for Erratum 131 is present.
			 */

			wabits = AMD_NB_CFG_SRQ_HEARTBEAT |
			    AMD_NB_CFG_SRQ_SPR;

			nbcfg = rdmsr(MSR_AMD_NB_CFG);
			if ((nbcfg & wabits) == 0) {
				opteron_erratum_131++;
			} else {
				/* cannot have both workarounds set */
				ASSERT((nbcfg & wabits) != wabits);
			}
		}
	}
#endif

#if defined(OPTERON_WORKAROUND_6336786)
	/*
	 * This isn't really erratum, but for convenience the
	 * detection/workaround code lives here and in cpuid_opteron_erratum.
	 */
	if (cpuid_opteron_erratum(cpu, 6336786) > 0) {
		int	node;
		uint8_t data;

		/*
		 * Disable C1-Clock ramping on multi-core/multi-processor
		 * K8 platforms to guard against TSC drift.
		 */
		if (opteron_workaround_6336786) {
			opteron_workaround_6336786++;
		} else if ((lgrp_plat_node_cnt *
		    cpuid_get_ncpu_per_chip(cpu) >= 2) ||
		    opteron_workaround_6336786_UP) {
			for (node = 0; node < lgrp_plat_node_cnt; node++) {
				/*
				 * Clear PMM7[1:0] (function 3, offset 0x87)
				 * Northbridge device is the node id + 24.
				 */
				data = pci_getb_func(0, node + 24, 3, 0x87);
				data &= 0xFC;
				pci_putb_func(0, node + 24, 3, 0x87, data);
			}
			opteron_workaround_6336786++;
		}
	}
#endif

#if defined(OPTERON_WORKAROUND_6323525)
	/*LINTED*/
	/*
	 * Mutex primitives don't work as expected.
	 */
	if (cpuid_opteron_erratum(cpu, 6323525) > 0) {

		/*
		 * problem only occurs with 2 or more cores. If bit in
		 * MSR_BU_CFG set, then not applicable. The workaround
		 * is to patch the semaphone routines with the lfence
		 * instruction to provide necessary load memory barrier with
		 * possible subsequent read-modify-write ops.
		 *
		 * It is too early in boot to call the patch routine so
		 * set erratum variable to be done in startup_end().
		 */
		if (opteron_workaround_6323525) {
			opteron_workaround_6323525++;
		} else if ((x86_feature & X86_SSE2) && ((lgrp_plat_node_cnt *
		    cpuid_get_ncpu_per_chip(cpu)) >= 2)) {
			if ((xrdmsr(MSR_BU_CFG) & 0x02) == 0)
				opteron_workaround_6323525++;
		}
	}
#endif
	return (missing);
}

void
workaround_errata_end()
{
#if defined(OPTERON_ERRATUM_109)
	if (opteron_erratum_109) {
		cmn_err(CE_WARN,
		    "BIOS microcode patch for AMD Athlon(tm) 64/Opteron(tm)"
		    " processor\nerratum 109 was not detected; updating your"
		    " system's BIOS to a version\ncontaining this"
		    " microcode patch is HIGHLY recommended or erroneous"
		    " system\noperation may occur.\n");
	}
#endif	/* OPTERON_ERRATUM_109 */
#if defined(OPTERON_ERRATUM_123)
	if (opteron_erratum_123) {
		cmn_err(CE_WARN,
		    "BIOS microcode patch for AMD Athlon(tm) 64/Opteron(tm)"
		    " processor\nerratum 123 was not detected; updating your"
		    " system's BIOS to a version\ncontaining this"
		    " microcode patch is HIGHLY recommended or erroneous"
		    " system\noperation may occur.\n");
	}
#endif	/* OPTERON_ERRATUM_123 */
#if defined(OPTERON_ERRATUM_131)
	if (opteron_erratum_131) {
		cmn_err(CE_WARN,
		    "BIOS microcode patch for AMD Athlon(tm) 64/Opteron(tm)"
		    " processor\nerratum 131 was not detected; updating your"
		    " system's BIOS to a version\ncontaining this"
		    " microcode patch is HIGHLY recommended or erroneous"
		    " system\noperation may occur.\n");
	}
#endif	/* OPTERON_ERRATUM_131 */
}

static ushort_t *mp_map_warm_reset_vector();
static void mp_unmap_warm_reset_vector(ushort_t *warm_reset_vector);

static cpuset_t procset = 1;

/*ARGSUSED*/
void
start_other_cpus(int cprboot)
{
	unsigned int who;
	int skipped = 0;
	int cpuid = 0;
	int delays = 0;
	int started_cpu;
	ushort_t *warm_reset_vector = NULL;

	/*
	 * Initialize our own cpu_info.
	 */
	init_cpu_info(CPU);

	/*
	 * Initialize our syscall handlers
	 */
	init_cpu_syscall(CPU);

	/*
	 * if only 1 cpu or not using MP, skip the rest of this
	 */
	if (CPUSET_ISEQUAL(mp_cpus, cpu_ready_set) || use_mp == 0) {
		if (use_mp == 0)
			cmn_err(CE_CONT, "?***** Not in MP mode\n");
		goto done;
	}

	/*
	 * perform such initialization as is needed
	 * to be able to take CPUs on- and off-line.
	 */
	cpu_pause_init();

	xc_init();		/* initialize processor crosscalls */

	/*
	 * Copy the real mode code at "real_mode_start" to the
	 * page at rm_platter_va.
	 */
	warm_reset_vector = mp_map_warm_reset_vector();
	if (warm_reset_vector == NULL)
		goto done;

	bcopy((caddr_t)real_mode_start,
	    (caddr_t)((rm_platter_t *)rm_platter_va)->rm_code,
	    (size_t)real_mode_end - (size_t)real_mode_start);

	flushes_require_xcalls = 1;

	ASSERT(CPU_IN_SET(procset, cpuid));
	ASSERT(CPU_IN_SET(cpu_ready_set, cpuid));

	/*
	 * We lock our affinity to the master CPU to ensure that all slave CPUs
	 * do their TSC syncs with the same CPU.
	 */
	affinity_set(CPU_CURRENT);

	for (who = 0; who < NCPU; who++) {
		if (who == cpuid)
			continue;

		delays = 0;

		if (!CPU_IN_SET(mp_cpus, who))
			continue;

		if (ncpus >= max_ncpus) {
			skipped = who;
			continue;
		}

		mp_startup_init(who);
		started_cpu = 1;
		(*cpu_startf)(who, rm_platter_pa);

		while (!CPU_IN_SET(procset, who)) {
			delay(1);
			if (++delays > (20 * hz)) {

				cmn_err(CE_WARN,
				    "cpu%d failed to start", who);

				mutex_enter(&cpu_lock);
				cpu[who]->cpu_flags = 0;
				cpu_vm_data_destroy(cpu[who]);
				cpu_del_unit(who);
				mutex_exit(&cpu_lock);

				started_cpu = 0;
				break;
			}
		}
		if (!started_cpu)
			continue;
		if (tsc_gethrtime_enable)
			tsc_sync_master(who);

	}

	affinity_clear();

	/*
	 * Wait for all CPUs that booted (have presence in procset)
	 * to come online (have presence in cpu_ready_set).  Note
	 * that the start CPU already satisfies both of these, so no
	 * special case is needed.
	 */
	for (who = 0; who < NCPU; who++) {
		if (!CPU_IN_SET(procset, who))
			continue;

		while (!CPU_IN_SET(cpu_ready_set, who))
			delay(1);
	}

	if (skipped) {
		cmn_err(CE_NOTE,
		    "System detected %d CPU(s), but "
		    "only %d CPU(s) were enabled during boot.",
		    skipped + 1, ncpus);
		cmn_err(CE_NOTE,
		    "Use \"boot-ncpus\" parameter to enable more CPU(s). "
		    "See eeprom(1M).");
	}

done:
	workaround_errata_end();

	if (warm_reset_vector != NULL)
		mp_unmap_warm_reset_vector(warm_reset_vector);
	hat_unload(kas.a_hat, (caddr_t)(uintptr_t)rm_platter_pa, MMU_PAGESIZE,
	    HAT_UNLOAD);

	cmi_post_mpstartup();
}

/*
 * Dummy functions - no i86pc platforms support dynamic cpu allocation.
 */
/*ARGSUSED*/
int
mp_cpu_configure(int cpuid)
{
	return (ENOTSUP);		/* not supported */
}

/*ARGSUSED*/
int
mp_cpu_unconfigure(int cpuid)
{
	return (ENOTSUP);		/* not supported */
}

/*
 * Startup function for 'other' CPUs (besides boot cpu).
 * Called from real_mode_start.
 *
 * WARNING: until CPU_READY is set, mp_startup and routines called by
 * mp_startup should not call routines (e.g. kmem_free) that could call
 * hat_unload which requires CPU_READY to be set.
 */
void
mp_startup(void)
{
	struct cpu *cp = CPU;
	uint_t new_x86_feature;

	/*
	 * We need to get TSC on this proc synced (i.e., any delta
	 * from cpu0 accounted for) as soon as we can, because many
	 * many things use gethrtime/pc_gethrestime, including
	 * interrupts, cmn_err, etc.
	 */

	/* Let cpu0 continue into tsc_sync_master() */
	CPUSET_ATOMIC_ADD(procset, cp->cpu_id);

	if (tsc_gethrtime_enable)
		tsc_sync_slave();

	/*
	 * Once this was done from assembly, but it's safer here; if
	 * it blocks, we need to be able to swtch() to and from, and
	 * since we get here by calling t_pc, we need to do that call
	 * before swtch() overwrites it.
	 */

	(void) (*ap_mlsetup)();

	new_x86_feature = cpuid_pass1(cp);

	/*
	 * We need to Sync MTRR with cpu0's MTRR. We have to do
	 * this with interrupts disabled.
	 */
	if (x86_feature & X86_MTRR)
		mtrr_sync();

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
	(void) splx(ipltospl(LOCK_LEVEL));

	/*
	 * Do a sanity check to make sure this new CPU is a sane thing
	 * to add to the collection of processors running this system.
	 *
	 * XXX	Clearly this needs to get more sophisticated, if x86
	 * systems start to get built out of heterogenous CPUs; as is
	 * likely to happen once the number of processors in a configuration
	 * gets large enough.
	 */
	if ((x86_feature & new_x86_feature) != x86_feature) {
		cmn_err(CE_CONT, "?cpu%d: %b\n",
		    cp->cpu_id, new_x86_feature, FMT_X86_FEATURE);
		cmn_err(CE_WARN, "cpu%d feature mismatch", cp->cpu_id);
	}

	/*
	 * We could be more sophisticated here, and just mark the CPU
	 * as "faulted" but at this point we'll opt for the easier
	 * answer of dieing horribly.  Provided the boot cpu is ok,
	 * the system can be recovered by booting with use_mp set to zero.
	 */
	if (workaround_errata(cp) != 0)
		panic("critical workaround(s) missing for cpu%d", cp->cpu_id);

	cpuid_pass2(cp);
	cpuid_pass3(cp);
	(void) cpuid_pass4(cp);

	init_cpu_info(cp);

	mutex_enter(&cpu_lock);
	/*
	 * Processor group initialization for this CPU is dependent on the
	 * cpuid probing, which must be done in the context of the current
	 * CPU.
	 */
	pghw_physid_create(cp);
	pg_cpu_init(cp);
	pg_cmt_cpu_startup(cp);

	cp->cpu_flags |= CPU_RUNNING | CPU_READY | CPU_ENABLE | CPU_EXISTS;
	cpu_add_active(cp);

	if (dtrace_cpu_init != NULL) {
		(*dtrace_cpu_init)(cp->cpu_id);
	}

	mutex_exit(&cpu_lock);

	/*
	 * Enable preemption here so that contention for any locks acquired
	 * later in mp_startup may be preempted if the thread owning those
	 * locks is continously executing on other CPUs (for example, this
	 * CPU must be preemptible to allow other CPUs to pause it during their
	 * startup phases).  It's safe to enable preemption here because the
	 * CPU state is pretty-much fully constructed.
	 */
	curthread->t_preempt = 0;

	add_cpunode2devtree(cp->cpu_id, cp->cpu_m.mcpu_cpi);

	/* The base spl should still be at LOCK LEVEL here */
	ASSERT(cp->cpu_base_spl == ipltospl(LOCK_LEVEL));
	set_base_spl();		/* Restore the spl to its proper value */

	(void) spl0();				/* enable interrupts */

	/*
	 * Set up the CPU module for this CPU.  This can't be done before
	 * this CPU is made CPU_READY, because we may (in heterogeneous systems)
	 * need to go load another CPU module.  The act of attempting to load
	 * a module may trigger a cross-call, which will ASSERT unless this
	 * cpu is CPU_READY.
	 */
	cmi_init();

	if (x86_feature & X86_MCA)
		cmi_mca_init();

	if (boothowto & RB_DEBUG)
		kdi_dvec_cpu_init(cp);

	/*
	 * Setting the bit in cpu_ready_set must be the last operation in
	 * processor initialization; the boot CPU will continue to boot once
	 * it sees this bit set for all active CPUs.
	 */
	CPUSET_ATOMIC_ADD(cpu_ready_set, cp->cpu_id);

	/*
	 * Because mp_startup() gets fired off after init() starts, we
	 * can't use the '?' trick to do 'boot -v' printing - so we
	 * always direct the 'cpu .. online' messages to the log.
	 */
	cmn_err(CE_CONT, "!cpu%d initialization complete - online\n",
	    cp->cpu_id);

	/*
	 * Now we are done with the startup thread, so free it up.
	 */
	thread_exit();
	panic("mp_startup: cannot return");
	/*NOTREACHED*/
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
/* ARGSUSED */
int
mp_cpu_stop(struct cpu *cp)
{
	extern int cbe_psm_timer_mode;
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * If TIMER_PERIODIC mode is used, CPU0 is the one running it;
	 * can't stop it.  (This is true only for machines with no TSC.)
	 */

	if ((cbe_psm_timer_mode == TIMER_PERIODIC) && (cp->cpu_id == 0))
		return (1);

	return (0);
}

/*
 * Power on CPU.
 */
/* ARGSUSED */
int
mp_cpu_poweron(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (ENOTSUP);		/* not supported */
}

/*
 * Power off CPU.
 */
/* ARGSUSED */
int
mp_cpu_poweroff(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (ENOTSUP);		/* not supported */
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



static ushort_t *
mp_map_warm_reset_vector()
{
	ushort_t *warm_reset_vector;

	if (!(warm_reset_vector = (ushort_t *)psm_map_phys(WARM_RESET_VECTOR,
	    sizeof (ushort_t *), PROT_READ|PROT_WRITE)))
		return (NULL);

	/*
	 * setup secondary cpu bios boot up vector
	 */
	*warm_reset_vector = (ushort_t)((caddr_t)
		((struct rm_platter *)rm_platter_va)->rm_code - rm_platter_va
		+ ((ulong_t)rm_platter_va & 0xf));
	warm_reset_vector++;
	*warm_reset_vector = (ushort_t)(rm_platter_pa >> 4);

	--warm_reset_vector;
	return (warm_reset_vector);
}

static void
mp_unmap_warm_reset_vector(ushort_t *warm_reset_vector)
{
	psm_unmap_phys((caddr_t)warm_reset_vector, sizeof (ushort_t *));
}

void
mp_cpu_faulted_enter(struct cpu *cp)
{
	cmi_faulted_enter(cp);
}

void
mp_cpu_faulted_exit(struct cpu *cp)
{
	cmi_faulted_exit(cp);
}

/*
 * The following two routines are used as context operators on threads belonging
 * to processes with a private LDT (see sysi86).  Due to the rarity of such
 * processes, these routines are currently written for best code readability and
 * organization rather than speed.  We could avoid checking x86_feature at every
 * context switch by installing different context ops, depending on the
 * x86_feature flags, at LDT creation time -- one for each combination of fast
 * syscall feature flags.
 */

/*ARGSUSED*/
void
cpu_fast_syscall_disable(void *arg)
{
	if (x86_feature & X86_SEP)
		cpu_sep_disable();
	if (x86_feature & X86_ASYSC)
		cpu_asysc_disable();
}

/*ARGSUSED*/
void
cpu_fast_syscall_enable(void *arg)
{
	if (x86_feature & X86_SEP)
		cpu_sep_enable();
	if (x86_feature & X86_ASYSC)
		cpu_asysc_enable();
}

static void
cpu_sep_enable(void)
{
	ASSERT(x86_feature & X86_SEP);
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	wrmsr(MSR_INTC_SEP_CS, (uint64_t)(uintptr_t)KCS_SEL);
}

static void
cpu_sep_disable(void)
{
	ASSERT(x86_feature & X86_SEP);
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	/*
	 * Setting the SYSENTER_CS_MSR register to 0 causes software executing
	 * the sysenter or sysexit instruction to trigger a #gp fault.
	 */
	wrmsr(MSR_INTC_SEP_CS, 0ULL);
}

static void
cpu_asysc_enable(void)
{
	ASSERT(x86_feature & X86_ASYSC);
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	wrmsr(MSR_AMD_EFER, rdmsr(MSR_AMD_EFER) |
	    (uint64_t)(uintptr_t)AMD_EFER_SCE);
}

static void
cpu_asysc_disable(void)
{
	ASSERT(x86_feature & X86_ASYSC);
	ASSERT(curthread->t_preempt || getpil() >= LOCK_LEVEL);

	/*
	 * Turn off the SCE (syscall enable) bit in the EFER register. Software
	 * executing syscall or sysret with this bit off will incur a #ud trap.
	 */
	wrmsr(MSR_AMD_EFER, rdmsr(MSR_AMD_EFER) &
	    ~((uint64_t)(uintptr_t)AMD_EFER_SCE));
}
