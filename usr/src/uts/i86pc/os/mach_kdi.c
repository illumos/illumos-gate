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
#include <sys/mach_mmu.h>

void
kdi_idt_write(gate_desc_t *gate, uint_t vec)
{
	gate_desc_t *idt = CPU->cpu_m.mcpu_idt;

	/*
	 * See kdi_idtr_set().
	 */
	if (idt == NULL) {
		desctbr_t idtr;
		rd_idtr(&idtr);
		idt = (gate_desc_t *)idtr.dtr_base;
	}

	idt[vec] = *gate;
}

ulong_t
kdi_dreg_get(int reg)
{
	switch (reg) {
	case 0:
		return (kdi_getdr0());
	case 1:
		return (kdi_getdr1());
	case 2:
		return (kdi_getdr2());
	case 3:
		return (kdi_getdr3());
	case 6:
		return (kdi_getdr6());
	case 7:
		return (kdi_getdr7());
	default:
		panic("invalid debug register dr%d", reg);
		/*NOTREACHED*/
	}
}

void
kdi_dreg_set(int reg, ulong_t value)
{
	switch (reg) {
	case 0:
		kdi_setdr0(value);
		break;
	case 1:
		kdi_setdr1(value);
		break;
	case 2:
		kdi_setdr2(value);
		break;
	case 3:
		kdi_setdr3(value);
		break;
	case 6:
		kdi_setdr6(value);
		break;
	case 7:
		kdi_setdr7(value);
		break;
	default:
		panic("invalid debug register dr%d", reg);
		/*NOTREACHED*/
	}
}

void
kdi_flush_caches(void)
{
	reload_cr3();
}

extern void kdi_slave_entry(void);

void
kdi_stop_slaves(int cpu, int doxc)
{
	if (doxc)
		kdi_xc_others(cpu, kdi_slave_entry);
}

/*
 * On i86pc, slaves busy-loop, so we don't need to do anything here.
 */
void
kdi_start_slaves(void)
{
}

void
kdi_slave_wait(void)
{
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
	uintptr_t old;

	cpu->cpu_self = cpu;

	old = (uintptr_t)rdmsr(MSR_AMD_GSBASE);
	wrmsr(MSR_AMD_GSBASE, (uint64_t)cpu);
	return ((void *)old);
}

void
boot_kdi_tmpfini(void *old)
{
	wrmsr(MSR_AMD_GSBASE, (uint64_t)old);
}

#elif defined(__i386)

void *
boot_kdi_tmpinit(void)
{
	cpu_t *cpu = kobj_zalloc(sizeof (*cpu), KM_TMP);
	uintptr_t old;
	desctbr_t b_gdtr;
	user_desc_t *bgdt;

	cpu->cpu_self = cpu;

	rd_gdtr(&b_gdtr);
	bgdt = (user_desc_t *)(b_gdtr.dtr_base);

	set_usegd(&bgdt[GDT_BGSTMP],
	    cpu, sizeof (*cpu), SDT_MEMRWA, SEL_KPL, SDP_BYTES, SDP_OP32);

	/*
	 * Now switch %gs to point at it.
	 */
	old = getgs();
	setgs(KMDBGS_SEL);

	return ((void *)old);
}

void
boot_kdi_tmpfini(void *old)
{
	setgs((uintptr_t)old);
}

#endif	/* __i386 */
