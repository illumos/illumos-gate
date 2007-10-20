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

/*
 * Welcome to the world of the "real mode platter".
 * See also startup.c, mpcore.s and apic.c for related routines.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
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
#include <vm/hat_i86.h>

extern void real_mode_start(void);
extern void real_mode_end(void);
extern void *(*cpu_pause_func)(void *);

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

	if (!(vec = (ushort_t *)psm_map_phys(WARM_RESET_VECTOR,
	    sizeof (vec), PROT_READ | PROT_WRITE)))
		return (-1);
	/*
	 * setup secondary cpu bios boot up vector
	 */
	*vec = (ushort_t)((caddr_t)
	    ((struct rm_platter *)rm_platter_va)->rm_code - rm_platter_va
	    + ((ulong_t)rm_platter_va & 0xf));
	vec[1] = (ushort_t)(rm_platter_pa >> 4);
	warm_reset_vector = vec;

	bcopy((caddr_t)real_mode_start,
	    (caddr_t)((rm_platter_t *)rm_platter_va)->rm_code,
	    (size_t)real_mode_end - (size_t)real_mode_start);

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

void *
mach_cpucontext_alloc(struct cpu *cp)
{
	rm_platter_t *rm = (rm_platter_t *)rm_platter_va;
	struct cpu_tables *ct;
	struct tss *ntss;

	/*
	 * Allocate space for page directory, stack, tss, gdt and idt.
	 * The page directory has to be page aligned
	 */
	ct = kmem_zalloc(sizeof (*ct), KM_SLEEP);
	if ((uintptr_t)ct & ~MMU_STD_PAGEMASK)
		panic("mp_startup_init: cpu%d misaligned tables", cp->cpu_id);

	ntss = cp->cpu_tss = &ct->ct_tss;

#if defined(__amd64)

	/*
	 * #DF (double fault).
	 */
	ntss->tss_ist1 = (uint64_t)&ct->ct_stack[sizeof (ct->ct_stack)];

#elif defined(__i386)

	ntss->tss_esp0 = ntss->tss_esp1 = ntss->tss_esp2 = ntss->tss_esp =
	    (uint32_t)&ct->ct_stack[sizeof (ct->ct_stack)];

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
	    sizeof (*cp->cpu_tss) -1, SDT_SYSTSS, SEL_KPL);

	/*
	 * Now copy all that we've set up onto the real mode platter
	 * for the real mode code to digest as part of starting the cpu.
	 */

	rm->rm_idt_base = cp->cpu_idt;
	rm->rm_idt_lim = sizeof (idt0) - 1;
	rm->rm_gdt_base = cp->cpu_gdt;
	rm->rm_gdt_lim = ((sizeof (*cp->cpu_gdt) * NGDT)) -1;

	rm->rm_pdbr = getcr3();
	rm->rm_cpu = cp->cpu_id;
	rm->rm_x86feature = x86_feature;
	rm->rm_cr4 = getcr4();

	rmp_gdt_init(rm);

	return (ct);
}

/*ARGSUSED*/
void
rmp_gdt_init(rm_platter_t *rm)
{

#if defined(__amd64)

	if (getcr3() > 0xffffffffUL)
		panic("Cannot initialize CPUs; kernel's 64-bit page tables\n"
		    "located above 4G in physical memory (@ 0x%lx)", getcr3());

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
	    ((uint32_t)long_mode_64 - (uint32_t)real_mode_start);
#endif	/* __amd64 */

}

/*ARGSUSED*/
void
mach_cpucontext_free(struct cpu *cp, void *arg, int err)
{
	struct cpu_tables *ct = arg;

	ASSERT(&ct->ct_tss == cp->cpu_tss);

	switch (err) {
	case 0:
		break;
	case ETIMEDOUT:
		/*
		 * The processor was poked, but failed to start before
		 * we gave up waiting for it.  In case it starts later,
		 * don't free anything.
		 */
		break;
	default:
		/*
		 * Some other, passive, error occurred.
		 */
		kmem_free(ct, sizeof (*ct));
		cp->cpu_tss = NULL;
		break;
	}
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
	tlb_going_idle();
	i86_halt();
	tlb_service();
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
 * Power on CPU.
 */
/*ARGSUSED*/
int
mp_cpu_poweron(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (ENOTSUP);		/* not supported */
}

/*
 * Power off CPU.
 */
/*ARGSUSED*/
int
mp_cpu_poweroff(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (ENOTSUP);		/* not supported */
}
