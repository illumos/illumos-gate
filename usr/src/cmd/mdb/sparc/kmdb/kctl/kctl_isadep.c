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
#include <sys/systm.h>
#include <sys/bootconf.h>
#include <sys/cpu_module.h>
#include <sys/x_call.h>
#include <sys/kdi_impl.h>
#include <sys/mmu.h>
#include <sys/cpuvar.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#ifdef sun4v
#include <sys/ldoms.h>
#include <sys/promif_impl.h>
#include <kmdb/kmdb_kctl.h>
#endif

#include <kmdb/kctl/kctl.h>

#define	KCTL_TTABLE_SIZE	0x6000	/* trap table size */

static uint32_t kctl_trap_brsav;	/* saved ba,a from kmdb_trap */
static uint32_t kctl_trap_tl1_brsav;	/* saved ba,a from kmdb_trap_tl1 */

extern struct scb trap_table;

static void
kctl_patch_text(caddr_t addr, uint32_t data)
{
	if (kctl.kctl_boot_loaded) {
		/* LINTED - pointer alignment */
		*((uint32_t *)addr) = data;
	} else {
		hot_patch_kernel_text(addr, data, sizeof (data));
	}
}

/*
 * The traps that transfer control to kmdb (breakpoint, programmed entry, etc)
 * use kmdb_trap and kmdb_trap_tl1, which normally begin with a ba,a to
 * trap_table0 - a bad trap entry.  When kmdb starts, it will use
 * kctl_ktrap_install to replace the ba with a jmp to the appropriate kmdb
 * entry points.  Deactivation uses kctl_ktrap_restore to restore the ba
 * instructions.
 */
static void
kctl_ktrap_install(int tl, void (*handler)(void))
{
	extern uint32_t kmdb_trap, kmdb_trap_tl1;
	uint32_t *entryp = tl ? &kmdb_trap_tl1 : &kmdb_trap;
	uint32_t *savp = tl ? &kctl_trap_brsav : &kctl_trap_tl1_brsav;
	uint32_t hi = (uint32_t)(uintptr_t)handler >> 10;
	uint32_t lo = (uint32_t)(uintptr_t)handler & 0x3ff;
	uint32_t inst;

	*savp = *entryp;

	inst = 0x81c06000 | lo; /* jmp %g1 + %lo(handler) */
	kctl_patch_text((caddr_t)(entryp + 1), inst);

	inst = 0x03000000 | hi;	/* sethi %hi(handler), %g1 */
	kctl_patch_text((caddr_t)entryp, inst);
}

static void
kctl_ktrap_restore(void)
{
	extern uint32_t kmdb_trap, kmdb_trap_tl1;

	hot_patch_kernel_text((caddr_t)&kmdb_trap, kctl_trap_brsav, 4);
	hot_patch_kernel_text((caddr_t)&kmdb_trap_tl1, kctl_trap_tl1_brsav, 4);
}

static void
kctl_ttable_tlb_modify(caddr_t tba, size_t sz, void (*func)(caddr_t, int))
{
#if defined(KMDB_TRAPCOUNT)
	int do_dtlb = 1;
#else
	int do_dtlb = 0;
#endif

	caddr_t va;

	ASSERT((sz & MMU_PAGEOFFSET) == 0);

	for (va = tba; sz > 0; sz -= MMU_PAGESIZE, va += MMU_PAGESIZE)
		func(va, do_dtlb);
}

static void
kctl_ttable_tlb_lock(caddr_t tba, size_t sz)
{
	kctl_ttable_tlb_modify(tba, sz, kdi_tlb_page_lock);
}

static void
kctl_ttable_tlb_unlock(caddr_t tba, size_t sz)
{
	kctl_ttable_tlb_modify(tba, sz, kdi_tlb_page_unlock);
}

/*
 * kmdb has its own trap table.  Life is made considerably easier if
 * we allocate and configure it here, passing it to the debugger for
 * final tweaking.
 *
 * The debugger code, and data accessed by the handlers are either
 * a) locked into the TLB or b) accessible by our tte-lookup code.  As
 * such, we need only lock the trap table itself into the TLBs.  We'll
 * get the memory for the table from the beginning of the debugger
 * segment, which has already been allocated.
 */
static void
kctl_ttable_init(void)
{
	xc_all((xcfunc_t *)kctl_ttable_tlb_lock, (uint64_t)kctl.kctl_tba,
	    KCTL_TTABLE_SIZE);
}

static void
kctl_ttable_fini(void)
{
	xc_all((xcfunc_t *)kctl_ttable_tlb_unlock, (uint64_t)kctl.kctl_dseg,
	    KCTL_TTABLE_SIZE);
}

static caddr_t
kctl_ttable_reserve(kmdb_auxv_t *kav, size_t *szp)
{
	caddr_t tba = kav->kav_dseg;

	ASSERT(kav->kav_dseg_size > KCTL_TTABLE_SIZE);
	ASSERT(((uintptr_t)kav->kav_dseg & ((1 << 16) - 1)) == 0);

	kav->kav_dseg += KCTL_TTABLE_SIZE;
	kav->kav_dseg_size -= KCTL_TTABLE_SIZE;

	*szp = KCTL_TTABLE_SIZE;
	return (tba);
}

static void
kctl_cpu_init(void)
{
	kctl_ttable_tlb_lock(kctl.kctl_tba, KCTL_TTABLE_SIZE);
}

int
kctl_preactivate_isadep(void)
{
	if (!kctl.kctl_boot_loaded) {
		if (kdi_watchdog_disable() != 0) {
			cmn_err(CE_WARN, "hardware watchdog disabled while "
			    "debugger is activated");
		}

		kctl_ttable_init();
	}

	return (0);
}

void
kctl_depreactivate_isadep(void)
{
	kctl_ttable_fini();

	kdi_watchdog_restore();
}

void
kctl_activate_isadep(kdi_debugvec_t *dvec)
{
	dvec->dv_kctl_cpu_init = kctl_cpu_init;
	dvec->dv_kctl_vmready = kctl_ttable_init;
}

void
kctl_auxv_init_isadep(kmdb_auxv_t *kav, void *romp)
{
	extern caddr_t boot_tba;
	extern void *get_tba(void);
	extern int (*cif_handler)(void *);
	extern int prom_exit_enter_debugger;

	kctl.kctl_tba = kav->kav_tba_native = kctl_ttable_reserve(kav,
	    &kav->kav_tba_native_sz);

	kav->kav_tba_obp = (boot_tba == NULL ? get_tba() : boot_tba);
#ifdef	sun4v
	kav->kav_tba_kernel = (caddr_t)&trap_table;
#endif
	kav->kav_tba_active = (kctl.kctl_boot_loaded ? kav->kav_tba_obp :
	    kav->kav_tba_native);

	kav->kav_promexitarmp = &prom_exit_enter_debugger;

	kav->kav_romp = (kctl.kctl_boot_loaded ? romp : (void *)cif_handler);

	kav->kav_ktrap_install = kctl_ktrap_install;
	kav->kav_ktrap_restore = kctl_ktrap_restore;
#ifdef sun4v
	if (kctl.kctl_boot_loaded) {
		/*
		 * When booting kmdb, kmdb starts before domaining is
		 * enabled and before the cif handler is changed to the
		 * kernel cif handler. So we start kmdb with using the
		 * OBP and we will change this when the cif handler is
		 * installed.
		 */
		kav->kav_domaining = 0;
	} else {
		kctl_auxv_set_promif(kav);
	}
#endif
}

#ifdef sun4v

void
kctl_auxv_set_promif(kmdb_auxv_t *kav)
{
	kav->kav_domaining = domaining_enabled();
	kav->kav_promif_root = promif_stree_getroot();
	kav->kav_promif_in = prom_stdin_ihandle();
	kav->kav_promif_out = prom_stdout_ihandle();
	kav->kav_promif_pin = prom_stdin_node();
	kav->kav_promif_pout = prom_stdout_node();
	kav->kav_promif_chosennode = prom_chosennode();
	kav->kav_promif_optionsnode = prom_finddevice("/options");
}

void
kctl_switch_promif(void)
{
	kmdb_auxv_t kav;

	kctl_auxv_set_promif(&kav);
	kmdb_init_promif(NULL, &kav);
}

#endif

/*ARGSUSED*/
void
kctl_auxv_fini_isadep(kmdb_auxv_t *auxv)
{
}

void *
kctl_boot_tmpinit(void)
{
	kthread_t *kt0 = kobj_zalloc(sizeof (kthread_t), KM_TMP);
	cpu_t *cpu = kobj_zalloc(sizeof (cpu_t), KM_TMP);
	kt0->t_cpu = cpu;

	return (kctl_curthread_set(kt0));
}

void
kctl_boot_tmpfini(void *old)
{
	(void) kctl_curthread_set(old);
}
