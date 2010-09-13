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
 * Kernel/Debugger Interface (KDI) routines.  Called during debugger under
 * various system states (boot, while running, while the debugger has control).
 * Functions intended for use while the debugger has control may not grab any
 * locks or perform any functions that assume the availability of other system
 * services.
 */

#include <sys/systm.h>
#include <sys/x86_archext.h>
#include <sys/kdi_impl.h>
#include <sys/smp_impldefs.h>
#include <sys/psm_types.h>
#include <sys/segments.h>
#include <sys/archsystm.h>
#include <sys/controlregs.h>
#include <sys/trap.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/hypervisor.h>
#include <sys/bootconf.h>
#include <sys/bootinfo.h>
#include <sys/promif.h>
#include <sys/evtchn_impl.h>
#include <sys/cpu.h>
#include <vm/kboot_mmu.h>
#include <vm/hat_pte.h>

static volatile int kdi_slaves_go;

/*
 * These are not safe against dropping into kmdb when fbt::: is active. This is
 * also broken on i86pc...
 */

void
kdi_idtr_write(desctbr_t *idtr)
{
	gate_desc_t *idt = (gate_desc_t *)idtr->dtr_base;
	uint_t nidt = (idtr->dtr_limit + 1) / sizeof (*idt);
	uint_t vec;

	for (vec = 0; vec < nidt; vec++, idt++)
		xen_idt_write(idt, vec);
}

void
kdi_idt_write(gate_desc_t *gate, uint_t vec)
{
	gate_desc_t *idt = CPU->cpu_m.mcpu_idt;

	/*
	 * See kdi_idtr_set().
	 */
	if (idt != NULL)
		idt[vec] = *gate;

	xen_idt_write(gate, vec);
}

ulong_t
kdi_dreg_get(int reg)
{
	return (__hypercall1(__HYPERVISOR_get_debugreg, (long)reg));
}

void
kdi_dreg_set(int reg, ulong_t value)
{
	(void) __hypercall2(__HYPERVISOR_set_debugreg, (long)reg, value);
}

void
kdi_flush_caches(void)
{
}

/*
 * To avoid domains sucking up CPU while sitting in kmdb, we make all the slave
 * CPUs wait for a wake-up evtchn.  The master CPU, meanwhile, sleeps for
 * console activity.
 */

extern void kdi_slave_entry(void);

void
kdi_stop_slaves(int cpu, int doxc)
{
	if (doxc)
		kdi_xc_others(cpu, kdi_slave_entry);
	kdi_slaves_go = 0;
}

void
kdi_start_slaves(void)
{
	int c;

	kdi_slaves_go = 1;

	for (c = 0; c < NCPU; c++) {
		if (cpu[c] == NULL || !(cpu[c]->cpu_flags & CPU_READY))
			continue;
		ec_try_ipi(XC_CPUPOKE_PIL, c);
	}
}

/*ARGSUSED*/
static int
check_slave(void *arg)
{
	return (kdi_slaves_go == 1);
}

void
kdi_slave_wait(void)
{
	if (!(cpu[CPU->cpu_id]->cpu_flags & CPU_READY))
		return;

	ec_wait_on_ipi(XC_CPUPOKE_PIL, check_slave, NULL);
}

/*
 * Caution.
 * These routines are called -extremely- early, during kmdb initialization.
 *
 * Many common kernel functions assume that %gs has been initialized,
 * and fail horribly if it hasn't.  At this point, the boot code has
 * reserved a descriptor for us (KMDBGS_SEL) in it's GDT; arrange for it
 * to point at a dummy cpu_t, temporarily at least.
 *
 * Note that kmdb entry relies on the fake cpu_t having zero cpu_idt/cpu_id.
 */

#if defined(__amd64)

void *
boot_kdi_tmpinit(void)
{
	cpu_t *cpu = kobj_zalloc(sizeof (*cpu), KM_TMP);
	user_desc_t *bgdt;
	uint64_t gdtpa;
	ulong_t ma[1];

	cpu->cpu_self = cpu;

	/*
	 * (Note that we had better switch to a -new- GDT before
	 * we discard the KM_TMP mappings, or disaster will ensue.)
	 */
	bgdt = kobj_zalloc(PAGESIZE, KM_TMP);
	ASSERT(((uintptr_t)bgdt & PAGEOFFSET) == 0);

	init_boot_gdt(bgdt);

	gdtpa = pfn_to_pa(va_to_pfn(bgdt));
	ma[0] = (ulong_t)(pa_to_ma(gdtpa) >> PAGESHIFT);
	kbm_read_only((uintptr_t)bgdt, gdtpa);
	if (HYPERVISOR_set_gdt(ma, PAGESIZE / sizeof (user_desc_t)))
		panic("boot_kdi_tmpinit:HYPERVISOR_set_gdt() failed");

	load_segment_registers(B64CODE_SEL, 0, 0, B32DATA_SEL);

	/*
	 * Now point %gsbase to our temp cpu structure.
	 */
	xen_set_segment_base(SEGBASE_GS_KERNEL, (ulong_t)cpu);
	return (0);
}

/*ARGSUSED*/
void
boot_kdi_tmpfini(void *old)
{
	/*
	 * This breaks, why do we need it anyway?
	 */
#if 0	/* XXPV */
	load_segment_registers(B64CODE_SEL, 0, KMDBGS_SEL, B32DATA_SEL);
#endif
}

#elif defined(__i386)

/*
 * Sigh.  We're called before we've initialized the kernels GDT, living
 * off the hypervisor's default GDT.  For kmdb's sake, we switch now to
 * a GDT that looks like dboot's GDT; very shortly we'll initialize and
 * switch to the kernel's GDT.
 */

void *
boot_kdi_tmpinit(void)
{
	cpu_t *cpu = kobj_zalloc(sizeof (*cpu), KM_TMP);
	user_desc_t *bgdt;
	uint64_t gdtpa;
	ulong_t ma[1];

	cpu->cpu_self = cpu;

	/*
	 * (Note that we had better switch to a -new- GDT before
	 * we discard the KM_TMP mappings, or disaster will ensue.)
	 */
	bgdt = kobj_zalloc(PAGESIZE, KM_TMP);

	ASSERT(((uintptr_t)bgdt & PAGEOFFSET) == 0);
	gdtpa = pfn_to_pa(va_to_pfn(bgdt));

	init_boot_gdt(bgdt);

	set_usegd(&bgdt[GDT_BGSTMP],
	    cpu, sizeof (*cpu), SDT_MEMRWA, SEL_KPL, SDP_BYTES, SDP_OP32);

	ma[0] = (ulong_t)(pa_to_ma(gdtpa) >> PAGESHIFT);
	kbm_read_only((uintptr_t)bgdt, gdtpa);
	if (HYPERVISOR_set_gdt(ma, PAGESIZE / sizeof (user_desc_t)))
		panic("boot_kdi_tmpinit:HYPERVISOR_set_gdt() failed");

	load_segment_registers(B32CODE_SEL, B32DATA_SEL, B32DATA_SEL, 0,
	    KMDBGS_SEL, B32DATA_SEL);
	return (0);
}

/*ARGSUSED*/
void
boot_kdi_tmpfini(void *old)
{
	load_segment_registers(B32CODE_SEL, B32DATA_SEL, B32DATA_SEL, 0,
	    0, B32DATA_SEL);
}

#endif	/* __i386 */
