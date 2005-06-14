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
 * The debugger/"PROM" interface layer - debugger activation
 *
 * Debugger activation has two flavors, which cover the cases where KMDB is
 * loaded at boot, and when it is loaded after boot.  In brief, in both cases,
 * to interpose upon several handlers in the IDT.  When mod-loaded KMDB is
 * deactivated, we undo the IDT interposition, restoring the handlers to what
 * they were before we started.
 *
 * Boot-loaded KMDB
 *
 * When we're first activated, we're running on boot's IDT.  We need to be able
 * to function in this world, so we'll install our handlers into boot's IDT.
 * Later, when we're about to switch to the kernel's IDT, it'll call us,
 * allowing us to add our handlers to the new IDT.  While boot-loaded KMDB can't
 * be unloaded, we still need to save the descriptors we replace so we can pass
 * traps back to the kernel as necessary.
 *
 * The last phase of boot-loaded KMDB activation occurs at non-boot CPU startup.
 * We will be called on each non-boot CPU, thus allowing us to set up any
 * watchpoints that may have been configured on the boot CPU and interpose on
 * the given CPU's IDT.  We don't save the interposed descriptors in this
 * case -- see kaif_cpu_init() for details.
 *
 * Mod-loaded KMDB
 *
 * This style of activation is much simpler, as the CPUs are already running,
 * and are using their own copy of the kernel's IDT.  We simply interpose upon
 * each CPU's IDT.  We save the handlers we replace, both for deactivation and
 * for passing traps back to the kernel.
 */

#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kmdb_start.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kaif_asmutil.h>
#include <kmdb/kaif_regs.h>
#include <kmdb/kaif.h>

#include <strings.h>
#include <sys/types.h>
#include <sys/segments.h>
#include <sys/trap.h>
#include <sys/cpuvar.h>
#include <sys/machcpuvar.h>
#include <sys/kdi_impl.h>

#define	KAIF_GATE_NVECS	3

#define	KAIF_IDT_NOSAVE		0
#define	KAIF_IDT_SAVEOLD	1

#define	KAIF_IDT_DTYPE_KERNEL	0
#define	KAIF_IDT_DTYPE_BOOT	1

typedef struct kaif_gate_spec {
	uint_t kgs_vec;
	uint_t kgs_dpl;
} kaif_gate_spec_t;

static const kaif_gate_spec_t kaif_gate_specs[KAIF_GATE_NVECS] = {
	{ T_SGLSTP, SEL_KPL },
	{ T_BPTFLT, SEL_UPL },
	{ T_DBGENTR, SEL_KPL }
};

static gate_desc_t kaif_kgates[KAIF_GATE_NVECS];

static void
kaif_idt_gates_create(gate_desc_t *gates, int useboot)
{
	int i;

	for (i = 0; i < KAIF_GATE_NVECS; i++) {
		const kaif_gate_spec_t *gs = &kaif_gate_specs[i];
		kmdb_kdi_idt_init_gate(&gates[i],
		    (void (*)())GATESEG_GETOFFSET(&kaif_idt[gs->kgs_vec]),
		    gs->kgs_dpl, useboot);
	}
}

static void
kaif_idt_gates_install(gate_desc_t *idt, gate_desc_t *gates, int saveold)
{
	int i;

	for (i = 0; i < KAIF_GATE_NVECS; i++) {
		uint_t vec = kaif_gate_specs[i].kgs_vec;

		if (saveold)
			kmdb_kdi_idt_read(idt, &kaif_kgates[i], vec);

		kmdb_kdi_idt_write(idt, &gates[i], vec);
	}
}

static void
kaif_idt_gates_install_by_cpu(cpu_t *cp, gate_desc_t *gates, int saveold)
{
	kaif_idt_gates_install(kmdb_kdi_cpu2idt(cp), gates, saveold);
}

static void
kaif_idt_gates_restore(cpu_t *cp)
{
	gate_desc_t *idt = kmdb_kdi_cpu2idt(cp);
	int i;

	for (i = 0; i < KAIF_GATE_NVECS; i++) {
		kmdb_kdi_idt_write(idt, &kaif_kgates[i],
		    kaif_gate_specs[i].kgs_vec);
	}
}

/*
 * Used by the code which passes traps back to the kernel to retrieve the
 * address of the kernel's handler for a given trap.  We get this address
 * from the descriptor save area, which we populated when we loaded the
 * debugger (mod-loaded) or initialized the kernel's IDT (boot-loaded).
 */
uintptr_t
kaif_kernel_trap2hdlr(int vec)
{
	int i;

	for (i = 0; i < KAIF_GATE_NVECS; i++) {
		if (kaif_gate_specs[i].kgs_vec == vec)
			return (GATESEG_GETOFFSET(&kaif_kgates[i]));
	}

	return (NULL);
}

/*
 * We're still in single-CPU mode on CPU zero.  Install our handlers in the
 * current IDT.
 */
static void
kaif_boot_activate(void)
{
	gate_desc_t gates[KAIF_GATE_NVECS];

	kaif_idt_gates_create(gates, KAIF_IDT_DTYPE_BOOT);
	kaif_idt_gates_install(NULL, gates, KAIF_IDT_NOSAVE);
}

/* Per-CPU debugger activation for boot-loaded and mod-loaded KMDB */
/*ARGSUSED*/
static void
kaif_cpu_activate(cpu_t *cp, uint_t saveold)
{
	gate_desc_t gates[KAIF_GATE_NVECS];

	kaif_idt_gates_create(gates, KAIF_IDT_DTYPE_KERNEL);
	kaif_idt_gates_install_by_cpu(cp, gates, saveold);
}

/* Per-CPU debugger de-activation for mod-loaded KMDB */
/*ARGSUSED*/
static void
kaif_cpu_deactivate(cpu_t *cp, uint_t arg)
{
	kaif_idt_gates_restore(cp);
}

/*
 * Called on each non-boot CPU during CPU initialization.  We saved the kernel's
 * descriptors when we initialized the boot CPU, so we don't want to do it
 * again.  Saving the handlers from this CPU's IDT would actually be dangerous
 * with the CPU initialization method in use at the time of this writing.  With
 * that method, the startup code creates the IDTs for slave CPUs by copying
 * the one used by the boot CPU, which has already been interposed upon by
 * KMDB.  Were we to interpose again, we'd replace the kernel's descriptors
 * with our own in the save area.  By not saving, but still overwriting, we'll
 * work in the current world, and in any future world where the IDT is generated
 * from scratch.
 */
/*ARGSUSED*/
static void
kaif_cpu_init(cpu_t *cp)
{
	kaif_cpu_activate(cp, KAIF_IDT_NOSAVE);

	/* Load the debug registers and MSRs */
	kaif_cpu_debug_init(&kaif_cpusave[cp->cpu_id]);
}

/*
 * Called very early in _start, just before we switch to the kernel's IDT.  We
 * need to interpose on the kernel's IDT entries and we need to update our copy
 * of the #df handler.
 */
static void
kaif_idt_sync(gate_desc_t *idt)
{
	gate_desc_t gates[KAIF_GATE_NVECS];
	gate_desc_t kdfgate;

	kaif_idt_gates_create(gates, KAIF_IDT_DTYPE_KERNEL);
	kaif_idt_gates_install(idt, gates, KAIF_IDT_SAVEOLD);

	kmdb_kdi_idt_read(idt, &kdfgate, T_DBLFLT);
	kaif_idt_write(&kdfgate, T_DBLFLT);
}

static void
kaif_vmready(void)
{
}

static kdi_debugvec_t kaif_dvec = {
	kaif_enter,
	kaif_cpu_init,
	NULL,			/* dv_kctl_cpu_init */
	kaif_idt_sync,
	kaif_vmready,
	NULL,			/* dv_kctl_vmready */
	NULL,			/* dv_kctl_memavail */
	kaif_memrange_add,
	NULL,			/* dv_kctl_modavail */
	NULL,			/* dv_kctl_thravail */
	kaif_mod_loaded,
	kaif_mod_unloading
};

void
kaif_activate(kdi_debugvec_t **dvecp, uint_t flags)
{
	gate_desc_t kdfgate;

	/* Copy the kernel's #df handler to our IDT */
	kmdb_kdi_idt_read(NULL, &kdfgate, T_DBLFLT);
	kaif_idt_write(&kdfgate, T_DBLFLT);

	if (flags & KMDB_ACT_F_BOOT)
		kaif_boot_activate();
	else
		kmdb_kdi_cpu_iter(kaif_cpu_activate, KAIF_IDT_SAVEOLD);

	*dvecp = &kaif_dvec;
}

void
kaif_deactivate(void)
{
	kmdb_kdi_cpu_iter(kaif_cpu_deactivate, 0);
}
