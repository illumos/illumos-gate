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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

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
#include <sys/clock_impl.h>

static void
kdi_system_claim(void)
{
	lbolt_debug_entry();

	psm_notifyf(PSM_DEBUG_ENTER);
}

static void
kdi_system_release(void)
{
	psm_notifyf(PSM_DEBUG_EXIT);

	lbolt_debug_return();
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
uintptr_t
kdi_gdt2gsbase(uintptr_t gdtbase)
{
	return ((uintptr_t)kdi_gdt2cpu(gdtbase));
}
#endif

static uintptr_t
kdi_get_userlimit(void)
{
	return (_userlimit);
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

void
kdi_idtr_set(gate_desc_t *idt, size_t limit)
{
	desctbr_t idtr;

	/*
	 * This rare case could happen if we entered kmdb whilst still on the
	 * fake CPU set up by boot_kdi_tmpinit().  We're trying to restore the
	 * kernel's IDT that we saved on entry, but it was from the fake cpu_t
	 * rather than the real IDT (which is still boot's).  It's unpleasant,
	 * but we just encode knowledge that it's idt0 we want to restore.
	 */
	if (idt == NULL)
		idt = idt0;

	CPU->cpu_m.mcpu_idt = idt;
	idtr.dtr_base = (uintptr_t)idt;
	idtr.dtr_limit = limit;
	kdi_idtr_write(&idtr);
}

static void
kdi_plat_call(void (*platfn)(void))
{
	if (platfn != NULL)
		platfn();
}

/*
 * On Intel, most of these are shared between i86*, so this is really an
 * arch_kdi_init().
 */
void
mach_kdi_init(kdi_t *kdi)
{
	kdi->kdi_plat_call = kdi_plat_call;
	kdi->kdi_kmdb_enter = kmdb_enter;
	kdi->mkdi_activate = kdi_activate;
	kdi->mkdi_deactivate = kdi_deactivate;
	kdi->mkdi_idt_switch = kdi_idt_switch;
	kdi->mkdi_update_drreg = kdi_update_drreg;
	kdi->mkdi_get_userlimit = kdi_get_userlimit;
	kdi->mkdi_get_cpuinfo = kdi_get_cpuinfo;
	kdi->mkdi_stop_slaves = kdi_stop_slaves;
	kdi->mkdi_start_slaves = kdi_start_slaves;
	kdi->mkdi_slave_wait = kdi_slave_wait;
	kdi->mkdi_memrange_add = kdi_memrange_add;
	kdi->mkdi_reboot = kdi_reboot;
}

void
plat_kdi_init(kdi_t *kdi)
{
	kdi->pkdi_system_claim = kdi_system_claim;
	kdi->pkdi_system_release = kdi_system_release;
}
