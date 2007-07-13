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

#ifndef _KDI_IMPL_H
#define	_KDI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/kdi.h>
#include <sys/kdi_machimpl.h>
#include <sys/privregs.h>

#ifdef __cplusplus
extern "C" {
#endif

struct module;
struct gdscr;

/*
 * The debugvec is used by the kernel to interact with the debugger.
 */
struct kdi_debugvec {
	void	(*dv_kctl_vmready)(void);
	void	(*dv_kctl_memavail)(void);
	void	(*dv_kctl_modavail)(void);
	void	(*dv_kctl_thravail)(void);

	void	(*dv_vmready)(void);
	void	(*dv_memavail)(caddr_t, size_t);
	void	(*dv_mod_loaded)(struct modctl *);
	void	(*dv_mod_unloading)(struct modctl *);

#if defined(__i386) || defined(__amd64)
	void	(*dv_handle_fault)(greg_t, greg_t, greg_t, int);
#endif
#if defined(__sparc)
	void	(*dv_kctl_cpu_init)(void);
	void	(*dv_cpu_init)(struct cpu *);
	void	(*dv_cpr_restart)(void);
#endif
};

typedef struct kdi_plat {
	void (*pkdi_system_claim)(void);
	void (*pkdi_system_release)(void);
	void (*pkdi_console_claim)(void);
	void (*pkdi_console_release)(void);
} kdi_plat_t;

#define	pkdi_system_claim	kdi_plat.pkdi_system_claim
#define	pkdi_system_release	kdi_plat.pkdi_system_release
#define	pkdi_console_claim	kdi_plat.pkdi_console_claim
#define	pkdi_console_release	kdi_plat.pkdi_console_release

/*
 * The KDI, or Kernel/Debugger Interface, consists of an ops vector describing
 * kernel services that may be directly invoked by the debugger.  Unless
 * otherwise specified, the functions implementing this ops vector are designed
 * to function when the debugger has control of the system - when all other CPUs
 * have been stopped.  In such an environment, blocking services such as memory
 * allocation or synchronization primitives are not available.
 */

struct kdi {
	int kdi_version;

	/*
	 * Determines whether significant changes (loads or unloads) have
	 * been made to the modules since the last time this op was invoked.
	 */
	int (*kdi_mods_changed)(void);

	/*
	 * Iterates through the current set of modctls, and invokes the
	 * caller-provided callback on each one.
	 */
	int (*kdi_mod_iter)(int (*)(struct modctl *, void *), void *);

	/*
	 * Determines whether or not a given module is loaded.
	 */
	int (*kdi_mod_isloaded)(struct modctl *);

	/*
	 * Has anything changed between two versions of the same modctl?
	 */
	int (*kdi_mod_haschanged)(struct modctl *, struct module *,
	    struct modctl *, struct module *);

	/*
	 * Invoked by the debugger when it assumes control of the machine.
	 */
	void (*kdi_system_claim)(void);

	/*
	 * Invoked by the debugger when it relinquishes control of the machine.
	 */
	void (*kdi_system_release)(void);

	int (*kdi_pread)(caddr_t, size_t, uint64_t, size_t *);
	int (*kdi_pwrite)(caddr_t, size_t, uint64_t, size_t *);
	void (*kdi_flush_caches)(void);

	size_t (*kdi_range_is_nontoxic)(uintptr_t, size_t, int);

	struct cons_polledio *(*kdi_get_polled_io)(void);

	int (*kdi_vtop)(uintptr_t, uint64_t *);

	kdi_dtrace_state_t (*kdi_dtrace_get_state)(void);
	int (*kdi_dtrace_set)(kdi_dtrace_set_t);

	void (*kdi_plat_call)(void (*)(void));

	void (*kdi_kmdb_enter)(void);

	kdi_mach_t kdi_mach;
	kdi_plat_t kdi_plat;
};

extern void kdi_softcall(void (*)(void));
extern void kdi_setsoftint(uint64_t);
extern int kdi_pread(caddr_t, size_t, uint64_t, size_t *);
extern int kdi_pwrite(caddr_t, size_t, uint64_t, size_t *);
extern size_t kdi_range_is_nontoxic(uintptr_t, size_t, int);
extern void kdi_flush_caches(void);
extern kdi_dtrace_state_t kdi_dtrace_get_state(void);
extern int kdi_vtop(uintptr_t, uint64_t *);

extern void cpu_kdi_init(kdi_t *);
extern void mach_kdi_init(kdi_t *);
extern void plat_kdi_init(kdi_t *);

extern void *boot_kdi_tmpinit(void);
extern void boot_kdi_tmpfini(void *);

#ifdef __cplusplus
}
#endif

#endif /* _KDI_IMPL_H */
