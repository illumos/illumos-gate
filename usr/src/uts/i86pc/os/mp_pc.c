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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2018 Joyent, Inc
 */

/*
 * Welcome to the world of the "real mode platter".
 * See also startup.c, mpcore.s and apic.c for related routines.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/cpu_module.h>
#include <sys/kmem.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/controlregs.h>
#include <sys/x86_archext.h>
#include <sys/smp_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/mach_mmu.h>
#include <sys/promif.h>
#include <sys/cpu.h>
#include <sys/cpu_event.h>
#include <sys/sunndi.h>
#include <sys/fs/dv_node.h>
#include <vm/hat_i86.h>
#include <vm/as.h>

extern cpuset_t cpu_ready_set;

extern int  mp_start_cpu_common(cpu_t *cp, boolean_t boot);
extern void real_mode_start_cpu(void);
extern void real_mode_start_cpu_end(void);
extern void real_mode_stop_cpu_stage1(void);
extern void real_mode_stop_cpu_stage1_end(void);
extern void real_mode_stop_cpu_stage2(void);
extern void real_mode_stop_cpu_stage2_end(void);

void rmp_gdt_init(rm_platter_t *);

/*
 * Fill up the real mode platter to make it easy for real mode code to
 * kick it off. This area should really be one passed by boot to kernel
 * and guaranteed to be below 1MB and aligned to 16 bytes. Should also
 * have identical physical and virtual address in paged mode.
 */
static ushort_t *warm_reset_vector = NULL;

int
mach_cpucontext_init(void)
{
	ushort_t *vec;
	ulong_t addr;
	struct rm_platter *rm = (struct rm_platter *)rm_platter_va;

	if (!(vec = (ushort_t *)psm_map_phys(WARM_RESET_VECTOR,
	    sizeof (vec), PROT_READ | PROT_WRITE)))
		return (-1);

	/*
	 * setup secondary cpu bios boot up vector
	 * Write page offset to 0x467 and page frame number to 0x469.
	 */
	addr = (ulong_t)((caddr_t)rm->rm_code - (caddr_t)rm) + rm_platter_pa;
	vec[0] = (ushort_t)(addr & PAGEOFFSET);
	vec[1] = (ushort_t)((addr & (0xfffff & PAGEMASK)) >> 4);
	warm_reset_vector = vec;

	/* Map real mode platter into kas so kernel can access it. */
	hat_devload(kas.a_hat,
	    (caddr_t)(uintptr_t)rm_platter_pa, MMU_PAGESIZE,
	    btop(rm_platter_pa), PROT_READ | PROT_WRITE | PROT_EXEC,
	    HAT_LOAD_NOCONSIST);

	/* Copy CPU startup code to rm_platter if it's still during boot. */
	if (!plat_dr_enabled()) {
		ASSERT((size_t)real_mode_start_cpu_end -
		    (size_t)real_mode_start_cpu <= RM_PLATTER_CODE_SIZE);
		bcopy((caddr_t)real_mode_start_cpu, (caddr_t)rm->rm_code,
		    (size_t)real_mode_start_cpu_end -
		    (size_t)real_mode_start_cpu);
	}

	return (0);
}

void
mach_cpucontext_fini(void)
{
	if (warm_reset_vector)
		psm_unmap_phys((caddr_t)warm_reset_vector,
		    sizeof (warm_reset_vector));
	hat_unload(kas.a_hat, (caddr_t)(uintptr_t)rm_platter_pa, MMU_PAGESIZE,
	    HAT_UNLOAD);
}

#if defined(__amd64)
extern void *long_mode_64(void);
#endif	/* __amd64 */

/*ARGSUSED*/
void
rmp_gdt_init(rm_platter_t *rm)
{

#if defined(__amd64)
	/* Use the kas address space for the CPU startup thread. */
	if (mmu_ptob(kas.a_hat->hat_htable->ht_pfn) > 0xffffffffUL) {
		panic("Cannot initialize CPUs; kernel's 64-bit page tables\n"
		    "located above 4G in physical memory (@ 0x%lx)",
		    mmu_ptob(kas.a_hat->hat_htable->ht_pfn));
	}

	/*
	 * Setup pseudo-descriptors for temporary GDT and IDT for use ONLY
	 * by code in real_mode_start_cpu():
	 *
	 * GDT[0]:  NULL selector
	 * GDT[1]:  64-bit CS: Long = 1, Present = 1, bits 12, 11 = 1
	 *
	 * Clear the IDT as interrupts will be off and a limit of 0 will cause
	 * the CPU to triple fault and reset on an NMI, seemingly as reasonable
	 * a course of action as any other, though it may cause the entire
	 * platform to reset in some cases...
	 */
	rm->rm_temp_gdt[0] = 0;
	rm->rm_temp_gdt[TEMPGDT_KCODE64] = 0x20980000000000ULL;

	rm->rm_temp_gdt_lim = (ushort_t)(sizeof (rm->rm_temp_gdt) - 1);
	rm->rm_temp_gdt_base = rm_platter_pa +
	    (uint32_t)offsetof(rm_platter_t, rm_temp_gdt);
	rm->rm_temp_idt_lim = 0;
	rm->rm_temp_idt_base = 0;

	/*
	 * Since the CPU needs to jump to protected mode using an identity
	 * mapped address, we need to calculate it here.
	 */
	rm->rm_longmode64_addr = rm_platter_pa +
	    (uint32_t)((uintptr_t)long_mode_64 -
	    (uintptr_t)real_mode_start_cpu);
#endif	/* __amd64 */
}

static void *
mach_cpucontext_alloc_tables(struct cpu *cp)
{
	tss_t *ntss;
	struct cpu_tables *ct;
	size_t ctsize;

	/*
	 * Allocate space for stack, tss, gdt and idt. We round the size
	 * allotted for cpu_tables up, so that the TSS is on a unique page.
	 * This is more efficient when running in virtual machines.
	 */
	ctsize = P2ROUNDUP(sizeof (*ct), PAGESIZE);
	ct = kmem_zalloc(ctsize, KM_SLEEP);
	if ((uintptr_t)ct & PAGEOFFSET)
		panic("mach_cpucontext_alloc_tables: cpu%d misaligned tables",
		    cp->cpu_id);

	ntss = cp->cpu_tss = &ct->ct_tss;

#if defined(__amd64)
	uintptr_t va;
	size_t len;

	/*
	 * #DF (double fault).
	 */
	ntss->tss_ist1 = (uintptr_t)&ct->ct_stack1[sizeof (ct->ct_stack1)];

	/*
	 * #NM (non-maskable interrupt)
	 */
	ntss->tss_ist2 = (uintptr_t)&ct->ct_stack2[sizeof (ct->ct_stack2)];

	/*
	 * #MC (machine check exception / hardware error)
	 */
	ntss->tss_ist3 = (uintptr_t)&ct->ct_stack3[sizeof (ct->ct_stack3)];

	/*
	 * #DB, #BP debug interrupts and KDI/kmdb
	 */
	ntss->tss_ist4 = (uintptr_t)&cp->cpu_m.mcpu_kpti_dbg.kf_tr_rsp;

	if (kpti_enable == 1) {
		/*
		 * #GP, #PF, #SS fault interrupts
		 */
		ntss->tss_ist5 = (uintptr_t)&cp->cpu_m.mcpu_kpti_flt.kf_tr_rsp;

		/*
		 * Used by all other interrupts
		 */
		ntss->tss_ist6 = (uint64_t)&cp->cpu_m.mcpu_kpti.kf_tr_rsp;

		/*
		 * On AMD64 we need to make sure that all of the pages of the
		 * struct cpu_tables are punched through onto the user CPU for
		 * kpti.
		 *
		 * The final page will always be the TSS, so treat that
		 * separately.
		 */
		for (va = (uintptr_t)ct, len = ctsize - MMU_PAGESIZE;
		    len >= MMU_PAGESIZE;
		    len -= MMU_PAGESIZE, va += MMU_PAGESIZE) {
			/* The doublefault stack must be RW */
			hati_cpu_punchin(cp, va, PROT_READ | PROT_WRITE);
		}
		ASSERT3U((uintptr_t)ntss, ==, va);
		hati_cpu_punchin(cp, (uintptr_t)ntss, PROT_READ);
	}

#elif defined(__i386)

	ntss->tss_esp0 = ntss->tss_esp1 = ntss->tss_esp2 = ntss->tss_esp =
	    (uint32_t)&ct->ct_stack1[sizeof (ct->ct_stack1)];

	ntss->tss_ss0 = ntss->tss_ss1 = ntss->tss_ss2 = ntss->tss_ss = KDS_SEL;

	ntss->tss_eip = (uint32_t)cp->cpu_thread->t_pc;

	ntss->tss_cs = KCS_SEL;
	ntss->tss_ds = ntss->tss_es = KDS_SEL;
	ntss->tss_fs = KFS_SEL;
	ntss->tss_gs = KGS_SEL;

#endif	/* __i386 */

	/*
	 * Set I/O bit map offset equal to size of TSS segment limit
	 * for no I/O permission map. This will cause all user I/O
	 * instructions to generate #gp fault.
	 */
	ntss->tss_bitmapbase = sizeof (*ntss);

	/*
	 * Setup kernel tss.
	 */
	set_syssegd((system_desc_t *)&cp->cpu_gdt[GDT_KTSS], cp->cpu_tss,
	    sizeof (*cp->cpu_tss) - 1, SDT_SYSTSS, SEL_KPL);

	return (ct);
}

void *
mach_cpucontext_xalloc(struct cpu *cp, int optype)
{
	size_t len;
	struct cpu_tables *ct;
	rm_platter_t *rm = (rm_platter_t *)rm_platter_va;
	static int cpu_halt_code_ready;

	if (optype == MACH_CPUCONTEXT_OP_STOP) {
		ASSERT(plat_dr_enabled());

		/*
		 * The WARM_RESET_VECTOR has a limitation that the physical
		 * address written to it must be page-aligned. To work around
		 * this limitation, the CPU stop code has been splitted into
		 * two stages.
		 * The stage 2 code, which implements the real logic to halt
		 * CPUs, is copied to the rm_cpu_halt_code field in the real
		 * mode platter. The stage 1 code, which simply jumps to the
		 * stage 2 code in the rm_cpu_halt_code field, is copied to
		 * rm_code field in the real mode platter and it may be
		 * overwritten after the CPU has been stopped.
		 */
		if (!cpu_halt_code_ready) {
			/*
			 * The rm_cpu_halt_code field in the real mode platter
			 * is used by the CPU stop code only. So only copy the
			 * CPU stop stage 2 code into the rm_cpu_halt_code
			 * field on the first call.
			 */
			len = (size_t)real_mode_stop_cpu_stage2_end -
			    (size_t)real_mode_stop_cpu_stage2;
			ASSERT(len <= RM_PLATTER_CPU_HALT_CODE_SIZE);
			bcopy((caddr_t)real_mode_stop_cpu_stage2,
			    (caddr_t)rm->rm_cpu_halt_code, len);
			cpu_halt_code_ready = 1;
		}

		/*
		 * The rm_code field in the real mode platter is shared by
		 * the CPU start, CPU stop, CPR and fast reboot code. So copy
		 * the CPU stop stage 1 code into the rm_code field every time.
		 */
		len = (size_t)real_mode_stop_cpu_stage1_end -
		    (size_t)real_mode_stop_cpu_stage1;
		ASSERT(len <= RM_PLATTER_CODE_SIZE);
		bcopy((caddr_t)real_mode_stop_cpu_stage1,
		    (caddr_t)rm->rm_code, len);
		rm->rm_cpu_halted = 0;

		return (cp->cpu_m.mcpu_mach_ctx_ptr);
	} else if (optype != MACH_CPUCONTEXT_OP_START) {
		return (NULL);
	}

	/*
	 * Only need to allocate tables when starting CPU.
	 * Tables allocated when starting CPU will be reused when stopping CPU.
	 */
	ct = mach_cpucontext_alloc_tables(cp);
	if (ct == NULL) {
		return (NULL);
	}

	/* Copy CPU startup code to rm_platter for CPU hot-add operations. */
	if (plat_dr_enabled()) {
		bcopy((caddr_t)real_mode_start_cpu, (caddr_t)rm->rm_code,
		    (size_t)real_mode_start_cpu_end -
		    (size_t)real_mode_start_cpu);
	}

	/*
	 * Now copy all that we've set up onto the real mode platter
	 * for the real mode code to digest as part of starting the cpu.
	 */
	rm->rm_idt_base = cp->cpu_idt;
	rm->rm_idt_lim = sizeof (*cp->cpu_idt) * NIDT - 1;
	rm->rm_gdt_base = cp->cpu_gdt;
	rm->rm_gdt_lim = sizeof (*cp->cpu_gdt) * NGDT - 1;

	/*
	 * CPU needs to access kernel address space after powering on.
	 */
	rm->rm_pdbr = MAKECR3(kas.a_hat->hat_htable->ht_pfn, PCID_NONE);
	rm->rm_cpu = cp->cpu_id;

	/*
	 * We need to mask off any bits set on our boot CPU that can't apply
	 * while the subject CPU is initializing.  If appropriate, they are
	 * enabled later on.
	 */
	rm->rm_cr4 = getcr4();
	rm->rm_cr4 &= ~(CR4_MCE | CR4_PCE | CR4_PCIDE);

	rmp_gdt_init(rm);

	return (ct);
}

void
mach_cpucontext_xfree(struct cpu *cp, void *arg, int err, int optype)
{
	struct cpu_tables *ct = arg;

	ASSERT(&ct->ct_tss == cp->cpu_tss);
	if (optype == MACH_CPUCONTEXT_OP_START) {
		switch (err) {
		case 0:
			/*
			 * Save pointer for reuse when stopping CPU.
			 */
			cp->cpu_m.mcpu_mach_ctx_ptr = arg;
			break;
		case ETIMEDOUT:
			/*
			 * The processor was poked, but failed to start before
			 * we gave up waiting for it.  In case it starts later,
			 * don't free anything.
			 */
			cp->cpu_m.mcpu_mach_ctx_ptr = arg;
			break;
		default:
			/*
			 * Some other, passive, error occurred.
			 */
			kmem_free(ct, P2ROUNDUP(sizeof (*ct), PAGESIZE));
			cp->cpu_tss = NULL;
			break;
		}
	} else if (optype == MACH_CPUCONTEXT_OP_STOP) {
		switch (err) {
		case 0:
			/*
			 * Free resources allocated when starting CPU.
			 */
			kmem_free(ct, P2ROUNDUP(sizeof (*ct), PAGESIZE));
			cp->cpu_tss = NULL;
			cp->cpu_m.mcpu_mach_ctx_ptr = NULL;
			break;
		default:
			/*
			 * Don't touch table pointer in case of failure.
			 */
			break;
		}
	} else {
		ASSERT(0);
	}
}

void *
mach_cpucontext_alloc(struct cpu *cp)
{
	return (mach_cpucontext_xalloc(cp, MACH_CPUCONTEXT_OP_START));
}

void
mach_cpucontext_free(struct cpu *cp, void *arg, int err)
{
	mach_cpucontext_xfree(cp, arg, err, MACH_CPUCONTEXT_OP_START);
}

/*
 * "Enter monitor."  Called via cross-call from stop_other_cpus().
 */
void
mach_cpu_halt(char *msg)
{
	if (msg)
		prom_printf("%s\n", msg);

	/*CONSTANTCONDITION*/
	while (1)
		;
}

void
mach_cpu_idle(void)
{
	i86_halt();
}

void
mach_cpu_pause(volatile char *safe)
{
	/*
	 * This cpu is now safe.
	 */
	*safe = PAUSE_WAIT;
	membar_enter(); /* make sure stores are flushed */

	/*
	 * Now we wait.  When we are allowed to continue, safe
	 * will be set to PAUSE_IDLE.
	 */
	while (*safe != PAUSE_IDLE)
		SMT_PAUSE();
}

/*
 * Power on the target CPU.
 */
int
mp_cpu_poweron(struct cpu *cp)
{
	int error;
	cpuset_t tempset;
	processorid_t cpuid;

	ASSERT(cp != NULL);
	cpuid = cp->cpu_id;
	if (use_mp == 0 || plat_dr_support_cpu() == 0) {
		return (ENOTSUP);
	} else if (cpuid < 0 || cpuid >= max_ncpus) {
		return (EINVAL);
	}

	/*
	 * The currrent x86 implementaiton of mp_cpu_configure() and
	 * mp_cpu_poweron() have a limitation that mp_cpu_poweron() could only
	 * be called once after calling mp_cpu_configure() for a specific CPU.
	 * It's because mp_cpu_poweron() will destroy data structure created
	 * by mp_cpu_configure(). So reject the request if the CPU has already
	 * been powered on once after calling mp_cpu_configure().
	 * This limitaiton only affects the p_online syscall and the DR driver
	 * won't be affected because the DR driver always invoke public CPU
	 * management interfaces in the predefined order:
	 * cpu_configure()->cpu_poweron()...->cpu_poweroff()->cpu_unconfigure()
	 */
	if (cpuid_checkpass(cp, 4) || cp->cpu_thread == cp->cpu_idle_thread) {
		return (ENOTSUP);
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

	affinity_set(CPU->cpu_id);

	/*
	 * Start the target CPU. No need to call mach_cpucontext_fini()
	 * if mach_cpucontext_init() fails.
	 */
	if ((error = mach_cpucontext_init()) == 0) {
		error = mp_start_cpu_common(cp, B_FALSE);
		mach_cpucontext_fini();
	}
	if (error != 0) {
		affinity_clear();
		return (error);
	}

	/* Wait for the target cpu to reach READY state. */
	tempset = cpu_ready_set;
	while (!CPU_IN_SET(tempset, cpuid)) {
		delay(1);
		tempset = *((volatile cpuset_t *)&cpu_ready_set);
	}

	/* Mark the target CPU as available for mp operation. */
	CPUSET_ATOMIC_ADD(mp_cpus, cpuid);

	/* Free the space allocated to hold the microcode file */
	ucode_cleanup();

	affinity_clear();

	return (0);
}

#define	MP_CPU_DETACH_MAX_TRIES		5
#define	MP_CPU_DETACH_DELAY		100

static int
mp_cpu_detach_driver(dev_info_t *dip)
{
	int i;
	int rv = EBUSY;
	dev_info_t *pdip;

	pdip = ddi_get_parent(dip);
	ASSERT(pdip != NULL);
	/*
	 * Check if caller holds pdip busy - can cause deadlocks in
	 * e_ddi_branch_unconfigure(), which calls devfs_clean().
	 */
	if (DEVI_BUSY_OWNED(pdip)) {
		return (EDEADLOCK);
	}

	for (i = 0; i < MP_CPU_DETACH_MAX_TRIES; i++) {
		if (e_ddi_branch_unconfigure(dip, NULL, 0) == 0) {
			rv = 0;
			break;
		}
		DELAY(MP_CPU_DETACH_DELAY);
	}

	return (rv);
}

/*
 * Power off the target CPU.
 * Note: cpu_lock will be released and then reacquired.
 */
int
mp_cpu_poweroff(struct cpu *cp)
{
	int rv = 0;
	void *ctx;
	dev_info_t *dip = NULL;
	rm_platter_t *rm = (rm_platter_t *)rm_platter_va;
	extern void cpupm_start(cpu_t *);
	extern void cpupm_stop(cpu_t *);

	ASSERT(cp != NULL);
	ASSERT((cp->cpu_flags & CPU_OFFLINE) != 0);
	ASSERT((cp->cpu_flags & CPU_QUIESCED) != 0);

	if (use_mp == 0 || plat_dr_support_cpu() == 0) {
		return (ENOTSUP);
	}
	/*
	 * There is no support for powering off cpu0 yet.
	 * There are many pieces of code which have a hard dependency on cpu0.
	 */
	if (cp->cpu_id == 0) {
		return (ENOTSUP);
	};

	if (mach_cpu_get_device_node(cp, &dip) != PSM_SUCCESS) {
		return (ENXIO);
	}
	ASSERT(dip != NULL);
	if (mp_cpu_detach_driver(dip) != 0) {
		rv = EBUSY;
		goto out_online;
	}

	/* Allocate CPU context for stopping */
	if (mach_cpucontext_init() != 0) {
		rv = ENXIO;
		goto out_online;
	}
	ctx = mach_cpucontext_xalloc(cp, MACH_CPUCONTEXT_OP_STOP);
	if (ctx == NULL) {
		rv = ENXIO;
		goto out_context_fini;
	}

	cpupm_stop(cp);
	cpu_event_fini_cpu(cp);

	if (cp->cpu_m.mcpu_cmi_hdl != NULL) {
		cmi_fini(cp->cpu_m.mcpu_cmi_hdl);
		cp->cpu_m.mcpu_cmi_hdl = NULL;
	}

	rv = mach_cpu_stop(cp, ctx);
	if (rv != 0) {
		goto out_enable_cmi;
	}

	/* Wait until the target CPU has been halted. */
	while (*(volatile ushort_t *)&(rm->rm_cpu_halted) != 0xdead) {
		delay(1);
	}
	rm->rm_cpu_halted = 0xffff;

	/* CPU_READY has been cleared by mach_cpu_stop. */
	ASSERT((cp->cpu_flags & CPU_READY) == 0);
	ASSERT((cp->cpu_flags & CPU_RUNNING) == 0);
	cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;
	CPUSET_ATOMIC_DEL(mp_cpus, cp->cpu_id);

	mach_cpucontext_xfree(cp, ctx, 0, MACH_CPUCONTEXT_OP_STOP);
	mach_cpucontext_fini();

	return (0);

out_enable_cmi:
	{
		cmi_hdl_t hdl;

		if ((hdl = cmi_init(CMI_HDL_NATIVE, cmi_ntv_hwchipid(cp),
		    cmi_ntv_hwcoreid(cp), cmi_ntv_hwstrandid(cp))) != NULL) {
			if (is_x86_feature(x86_featureset, X86FSET_MCA))
				cmi_mca_init(hdl);
			cp->cpu_m.mcpu_cmi_hdl = hdl;
		}
	}
	cpu_event_init_cpu(cp);
	cpupm_start(cp);
	mach_cpucontext_xfree(cp, ctx, rv, MACH_CPUCONTEXT_OP_STOP);

out_context_fini:
	mach_cpucontext_fini();

out_online:
	(void) e_ddi_branch_configure(dip, NULL, 0);

	if (rv != EAGAIN && rv != ETIME) {
		rv = ENXIO;
	}

	return (rv);
}

/*
 * Return vcpu state, since this could be a virtual environment that we
 * are unaware of, return "unknown".
 */
/* ARGSUSED */
int
vcpu_on_pcpu(processorid_t cpu)
{
	return (VCPU_STATE_UNKNOWN);
}
