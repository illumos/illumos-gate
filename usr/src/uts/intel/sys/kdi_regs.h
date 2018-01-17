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
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _SYS_KDI_REGS_H
#define	_SYS_KDI_REGS_H

#ifndef _ASM
#include <sys/types.h>
#include <sys/segments.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#endif

#if defined(__amd64)
#include <amd64/sys/kdi_regs.h>
#elif defined(__i386)
#include <ia32/sys/kdi_regs.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	KDI_NCRUMBS	5

#define	KDI_CPU_STATE_NONE		0
#define	KDI_CPU_STATE_MASTER		1
#define	KDI_CPU_STATE_SLAVE		2

#define	KDIREG_DRCTL_WPALLEN_MASK	0x000000ff
#define	KDIREG_DRSTAT_RESERVED		0xffff0ff0
#define	KDIREG_DRCTL_RESERVED		0x00000700

#ifndef _ASM

/*
 * We maintain a ring buffer of bread crumbs for debugging purposes.  The
 * current buffer pointer is advanced along the ring with each intercepted
 * trap (debugger entry, invalid memory access, fault during step, etc).
 */
typedef struct kdi_crumb {
	greg_t krm_cpu_state;	/* This CPU's state at last entry */
	greg_t krm_pc;		/* Instruction pointer at trap */
	greg_t krm_sp;		/* Stack pointer at trap */
	greg_t krm_trapno;	/* The last trap number */
	greg_t krm_flag;	/* KAIF_CRUMB_F_* */
} kdi_crumb_t;

#define	KDI_MAXWPIDX	3

/*
 * Storage for %dr0-3, %dr6, and %dr7.
 */
typedef struct kdi_drreg {
	greg_t			dr_ctl;
	greg_t			dr_stat;
	greg_t			dr_addr[KDI_MAXWPIDX + 1];
} kdi_drreg_t;

/*
 * Data structure used to hold all of the state for a given CPU.
 */
typedef struct kdi_cpusave {
	greg_t			*krs_gregs;	/* saved registers */

	kdi_drreg_t		krs_dr;		/* saved debug registers */

	user_desc_t		*krs_gdt;	/* GDT address */
	gate_desc_t		*krs_idt;	/* IDT address */

	greg_t			krs_cr0;	/* saved %cr0 */

	uint_t			krs_cpu_state;	/* KDI_CPU_STATE_* mstr/slv */
	uint_t			krs_cpu_flushed; /* Have caches been flushed? */
	uint_t			krs_cpu_id;	/* this CPU's ID */

	/* Bread crumb ring buffer */
	ulong_t			krs_curcrumbidx; /* Current krs_crumbs idx */
	kdi_crumb_t		*krs_curcrumb;	/* Pointer to current crumb */
	kdi_crumb_t		krs_crumbs[KDI_NCRUMBS]; /* Crumbs */
} kdi_cpusave_t;

#endif /* !_ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KDI_REGS_H */
