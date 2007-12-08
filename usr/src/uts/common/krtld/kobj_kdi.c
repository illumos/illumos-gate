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
 * The KDI is used to allow the kernel debugger to directly invoke various
 * kernel functions.  In some cases, such as with kdi_mod_iter(), the
 * debugger needs to execute functions that use the kernel's linker bindings.
 * In other cases, the implementation of the KDI functions vary by platform
 * and/or by CPU.  By embedding the implementation of these functions in
 * the platmod/cpumod, we can avoid the need for platform-specific knowledge
 * in the debugger, and can thus have a single debugger binary for all
 * platforms.
 *
 * There are three classes of KDI function:
 *
 * 1. Normal - These are functions whose implementations are in the kernel for
 *    convenience.  An example is the modctl iterator, kdi_mod_iter.  Using the
 *    modules symbol, this function iterates through the kernel's modctl list,
 *    invoking a debugger-provided callback for each one.  This function is in
 *    the KDI because the debugger needs to be able to execute it in order to
 *    enable symbol resolution.  Without symbol resolution, the debugger can't
 *    locate the modules symbol.  A chicken-and-egg problem results.  We solve
 *    this problem by locating the module iterator in the kernel, where run-time
 *    linking solves the problem for us.
 *
 * 2. CPU-specific - Functions in this class have implementations that differ
 *    by CPU.  For example, the crosscall delivery notification method differs
 *    between Cheetah and Jalapeno, necessitating a different implementation for
 *    each.  By locating the KDI implementation of these functions in the
 *    cpumods, we automatically get the correct implementation, as krtld
 *    automatically loads the correct cpumod when it starts.  The cpumods
 *    directly fill in their portion of the kdi_t, using the mandatory
 *    cpu_kdi_init cpumod entry point.
 *
 * 3. Platform-specific - Similar to the CPU-specific class, platform-specific
 *    KDI functions have implementations that differ from platform to platform.
 *    As such, the implementations live in the platmods.  Further
 *    differentiating the platform-specific KDI functions from their
 *    CPU-dependent brethren, many directly invoke PROM functions.  This poses
 *    a problem, as the platmods use the kernel's promif functions, rather than
 *    the lock-free kmdb versions.  We provide an interposition layer for these
 *    platform-specific calls that disables the pre- and post-processing
 *    functions used by the kernel to implement kernel-specific functionality
 *    that must not be executed when kmdb has control of the machine.  Platmods
 *    fill in a kdi_plat_t using their optional plat_kdi_init entry point.
 *    krtld provides wrapper functions which suspend the necessary functions in
 *    the promif layer before invoking the kdi_plat_t functions (if any).
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/reboot.h>
#include <sys/kdi_impl.h>

#include <krtld/kobj_kdi.h>

#define	KOBJ_KDI_MOD_IDLE	0
#define	KOBJ_KDI_MOD_CHANGING	1
#define	KOBJ_KDI_MOD_CHANGED	2

static int kobj_kdi_mod_state = KOBJ_KDI_MOD_IDLE;

extern int standalone;

cons_polledio_t *
kobj_kdi_get_polled_io(void)
{
	cons_polledio_t **polled_io = &cons_polledio;

	return (polled_io == NULL ? NULL : *polled_io);
}

int
kobj_kdi_mod_iter(int (*func)(struct modctl *, void *), void *arg)
{
	int rc;

	if (standalone) {
		struct modctl_list *lp, **lpp;

		for (lpp = kobj_linkmaps; *lpp != NULL; lpp++) {
			for (lp = *lpp; lp != NULL; lp = lp->modl_next) {
				if ((rc = func(lp->modl_modp, arg)) != 0)
					return (rc);
			}
		}

	} else {
		struct modctl *modp = &modules;

		do {
			if ((rc = func(modp, arg)) != 0)
				return (rc);
		} while ((modp = modp->mod_next) != &modules);
	}

	return (0);
}

int
kobj_kdi_mod_isloaded(struct modctl *modp)
{
	return (modp->mod_mp != NULL);
}

int
kobj_kdi_mods_changed(void)
{
	int state;

	if ((state = kobj_kdi_mod_state) == KOBJ_KDI_MOD_CHANGED)
		kobj_kdi_mod_state = KOBJ_KDI_MOD_IDLE;

	return (state != KOBJ_KDI_MOD_IDLE);
}

/*ARGSUSED1*/
void
kobj_kdi_mod_notify(uint_t why, struct modctl *what)
{
	switch (why) {
	case KOBJ_NOTIFY_MODLOADING:
		kobj_kdi_mod_state = KOBJ_KDI_MOD_CHANGING;
		break;
	case KOBJ_NOTIFY_MODLOADED:
		kobj_kdi_mod_state = KOBJ_KDI_MOD_CHANGED;
		if (boothowto & RB_DEBUG)
			kdi_dvec_mod_loaded(what);
		break;
	case KOBJ_NOTIFY_MODUNLOADING:
		kobj_kdi_mod_state = KOBJ_KDI_MOD_CHANGING;
		if (boothowto & RB_DEBUG)
			kdi_dvec_mod_unloading(what);
		break;
	case KOBJ_NOTIFY_MODUNLOADED:
		kobj_kdi_mod_state = KOBJ_KDI_MOD_CHANGED;
		break;
	}
}

/*
 * Compare two modctl and module snapshots, attempting to determine whether
 * the module to which they both refer has changed between the time of the first
 * and the time of the second.  We can't do a straight bcmp, because there are
 * fields that change in the normal course of operations.  False positives
 * aren't the end of the world, but it'd be nice to avoid flagging a module
 * as changed every time someone holds or releases it.
 */
int
kobj_kdi_mod_haschanged(struct modctl *mc1, struct module *mp1,
    struct modctl *mc2, struct module *mp2)
{
	if (mc1->mod_loadcnt != mc2->mod_loadcnt || mc1->mod_mp != mc2->mod_mp)
		return (1);

	if (mc1->mod_mp == NULL)
		return (0);

	/* Take breath here. */
	return (bcmp(&mp1->hdr, &mp2->hdr, sizeof (mp1->hdr)) != 0 ||
	    mp1->symhdr != mp2->symhdr || mp1->strhdr != mp2->strhdr ||
	    mp1->text != mp2->text || mp1->bss != mp2->bss ||
	    mp1->ctfdata != mp2->ctfdata || mp1->ctfsize != mp2->ctfsize);
}

void
kobj_kdi_system_claim(void)
{
	kobj_kdi.kdi_plat_call(kobj_kdi.pkdi_system_claim);
	kobj_kdi.kdi_plat_call(kobj_kdi.pkdi_console_claim);
}

void
kobj_kdi_system_release(void)
{
	kobj_kdi.kdi_plat_call(kobj_kdi.pkdi_console_release);
	kobj_kdi.kdi_plat_call(kobj_kdi.pkdi_system_release);
}

void
kobj_kdi_init(void)
{
	static const char *const initializers[] = {
		"cpu_kdi_init", "mach_kdi_init", "plat_kdi_init", NULL
	};

	Sym *sym;
	int i;

	for (i = 0; initializers[i] != NULL; i++) {
		if ((sym = kobj_lookup_kernel(initializers[i])) != NULL)
			((void (*)(kdi_t *))sym->st_value)(&kobj_kdi);
	}
}

kdi_t kobj_kdi = {
	KDI_VERSION,
	kobj_kdi_mods_changed,
	kobj_kdi_mod_iter,
	kobj_kdi_mod_isloaded,
	kobj_kdi_mod_haschanged,
	kobj_kdi_system_claim,
	kobj_kdi_system_release,
	kdi_pread,
	kdi_pwrite,
	kdi_flush_caches,
	kdi_range_is_nontoxic,
	kobj_kdi_get_polled_io,
	kdi_vtop,
	kdi_dtrace_get_state,
	kdi_dtrace_set,
	/*
	 * The rest are filled in by cpu_kdi_init, mach_kdi_init, and/or
	 * plat_kdi_init.
	 */
	NULL,			/* kdi_plat_call */
	NULL,			/* kdi_kmdb_enter */
	{ NULL },		/* kdi_arch */
	{ NULL }		/* kdi_plat */
};
