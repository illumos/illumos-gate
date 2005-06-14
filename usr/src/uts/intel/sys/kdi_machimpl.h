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

#ifndef _SYS_KDI_MACHIMPL_H
#define	_SYS_KDI_MACHIMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The Kernel/Debugger interface.  The operations provided by the kdi_t,
 * defined below, comprise the Debugger -> Kernel portion of the interface,
 * and are to be used only when the system has been stopped.
 */

/* The VA range reserved for the debugger. */

#include <sys/modctl.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kdi_mach {
	int (*mkdi_get_cpuinfo)(uint_t *, uint_t *, uint_t *);

	int (*mkdi_xc_initialized)(void);
	void (*mkdi_xc_others)(int, void (*)());

	uintptr_t (*mkdi_get_userlimit)(void);

	void (*mkdi_idt_init_gate)(struct gate_desc *, void (*)(void), uint_t,
	    int);
	void (*mkdi_idt_read)(struct gate_desc *, struct gate_desc *, uint_t);
	void (*mkdi_idt_write)(struct gate_desc *, struct gate_desc *, uint_t);
	struct gate_desc *(*mkdi_cpu2idt)(struct cpu *);

	void (**mkdi_shutdownp)(int, int);

#if defined(__amd64)
	uintptr_t (*mkdi_gdt2gsbase)(uintptr_t);
#endif

	/* for use only when the kernel is running */
	void (*mkdi_cpu_iter)(void (*)(struct cpu *, uint_t),
	    uint_t);
} kdi_mach_t;

#define	mkdi_get_cpuinfo		kdi_mach.mkdi_get_cpuinfo
#define	mkdi_xc_initialized		kdi_mach.mkdi_xc_initialized
#define	mkdi_xc_others			kdi_mach.mkdi_xc_others
#define	mkdi_get_userlimit		kdi_mach.mkdi_get_userlimit
#define	mkdi_idt_init_gate		kdi_mach.mkdi_idt_init_gate
#define	mkdi_idt_read			kdi_mach.mkdi_idt_read
#define	mkdi_idt_write			kdi_mach.mkdi_idt_write
#define	mkdi_cpu2idt			kdi_mach.mkdi_cpu2idt
#define	mkdi_shutdownp			kdi_mach.mkdi_shutdownp
#if defined(__amd64)
#define	mkdi_gdt2gsbase			kdi_mach.mkdi_gdt2gsbase
#endif
#define	mkdi_cpu_iter			kdi_mach.mkdi_cpu_iter

extern int kdi_xc_initialized(void);
extern void kdi_xc_others(int, void (*)());

extern void hat_kdi_init(void);
extern void hat_kdi_fini(void);

extern uintptr_t kdi_get_userlimit(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KDI_MACHIMPL_H */
