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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

static void
kdi_system_claim(void)
{
	psm_notifyf(PSM_DEBUG_ENTER);
}

static void
kdi_system_release(void)
{
	psm_notifyf(PSM_DEBUG_EXIT);
}

static cpu_t *
kdi_gdt2cpu(uintptr_t gdtbase)
{
	cpu_t *cp = cpu_list;

	if (cp == NULL)
		return (NULL);

	do {
		if (gdtbase == (uintptr_t)cp->cpu_gdt)
			return (cp);
	} while ((cp = cp->cpu_next) != cpu_list);

	return (NULL);
}

#if defined(__amd64)
static uintptr_t
kdi_gdt2gsbase(uintptr_t gdtbase)
{
	return ((uintptr_t)kdi_gdt2cpu(gdtbase));
}
#endif

static void
kdi_cpu_iter(void (*iter)(cpu_t *, uint_t), uint_t arg)
{
	cpu_t *cp;

	mutex_enter(&cpu_lock);

	cp = cpu_list;
	do {
		iter(cp, arg);
	} while ((cp = cp->cpu_next) != cpu_list);

	mutex_exit(&cpu_lock);
}

static gate_desc_t *
curidt(void)
{
	desctbr_t idtdesc;
	rd_idtr(&idtdesc);
	return ((gate_desc_t *)idtdesc.dtr_base);
}

static void
kdi_idt_init_gate(gate_desc_t *gate, void (*hdlr)(void), uint_t dpl,
    int useboot)
{
	bzero(gate, sizeof (gate_desc_t));

#if defined(__amd64)
	set_gatesegd(gate, hdlr, (useboot ? B64CODE_SEL : KCS_SEL), 0,
	    SDT_SYSIGT, dpl);
#else
	set_gatesegd(gate, hdlr, (useboot ? BOOTCODE_SEL : KCS_SEL), 0,
	    SDT_SYSIGT, dpl);
#endif
}

static void
kdi_idt_read(gate_desc_t *idt, gate_desc_t *gatep, uint_t vec)
{
	if (idt == NULL)
		idt = curidt();
	*gatep = idt[vec];
}

static void
kdi_idt_write(gate_desc_t *idt, gate_desc_t *gate, uint_t vec)
{
	if (idt == NULL)
		idt = curidt();
	idt[vec] = *gate;
}

static gate_desc_t *
kdi_cpu2idt(cpu_t *cp)
{
	if (cp == NULL)
		cp = CPU;
	return (cp->cpu_idt);
}

void
kdi_flush_caches(void)
{
	reload_cr3();
}

static int
kdi_get_cpuinfo(uint_t *vendorp, uint_t *familyp, uint_t *modelp)
{
	desctbr_t gdtr;
	cpu_t *cpu;

	/*
	 * CPU doesn't work until the GDT and gs/GSBASE have been set up.
	 * Boot-loaded kmdb will call us well before then, so we have to
	 * find the current cpu_t the hard way.
	 */
	rd_gdtr(&gdtr);
	if ((cpu = kdi_gdt2cpu(gdtr.dtr_base)) == NULL ||
	    !cpuid_checkpass(cpu, 1))
		return (EAGAIN); /* cpuid isn't done yet */

	*vendorp = cpuid_getvendor(cpu);
	*familyp = cpuid_getfamily(cpu);
	*modelp = cpuid_getmodel(cpu);

	return (0);
}

static void
kdi_plat_call(void (*platfn)(void))
{
	if (platfn != NULL)
		platfn();
}

void
mach_kdi_init(kdi_t *kdi)
{
	kdi->kdi_plat_call = kdi_plat_call;
	kdi->mkdi_get_cpuinfo = kdi_get_cpuinfo;
	kdi->mkdi_xc_initialized = kdi_xc_initialized;
	kdi->mkdi_xc_others = kdi_xc_others;
	kdi->mkdi_get_userlimit = kdi_get_userlimit;

	kdi->mkdi_idt_init_gate = kdi_idt_init_gate;
	kdi->mkdi_idt_read = kdi_idt_read;
	kdi->mkdi_idt_write = kdi_idt_write;
	kdi->mkdi_cpu2idt = kdi_cpu2idt;

	kdi->mkdi_shutdownp = &psm_shutdownf;
#if defined(__amd64)
	kdi->mkdi_gdt2gsbase = &kdi_gdt2gsbase;
#endif

	kdi->mkdi_cpu_iter = kdi_cpu_iter;
}

/*ARGSUSED*/
void
mach_kdi_fini(kdi_t *kdi)
{
	hat_kdi_fini();
}

void
plat_kdi_init(kdi_t *kdi)
{
	kdi->pkdi_system_claim = kdi_system_claim;
	kdi->pkdi_system_release = kdi_system_release;
}
