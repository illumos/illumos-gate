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

#ifndef _KAIF_REGS_H
#define	_KAIF_REGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM
#include <sys/types.h>
#include <sys/segments.h>

#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_target.h>
#include <kmdb/kmdb_dpi.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	KAIF_NCRUMBS	5

#ifndef _ASM

/*
 * We maintain a ring buffer of bread crumbs for debugging purposes.  The
 * current buffer pointer is advanced along the ring with each intercepted
 * trap (debugger entry, invalid memory access, fault during step, etc).
 * The macros used to populate the crumb buffers assume that all members are
 * 32 bits wide.
 */
typedef struct kaif_crumb {
	kreg_t krm_cpu_state;	/* This CPU's state at last entry */
	kreg_t krm_pc;		/* Instruction pointer at trap */
	kreg_t krm_sp;		/* Stack pointer at trap */
	kreg_t krm_trapno;	/* The last trap number */
	kreg_t krm_flag;	/* KAIF_CRUMB_F_* */
} kaif_crumb_t;

/*
 * Storage for %dr0-3, %dr6, and %dr7.
 */
typedef struct kaif_drreg {
	kreg_t			dr_ctl;
	kreg_t			dr_stat;
	kreg_t			dr_addr[KREG_MAXWPIDX + 1];
} kaif_drreg_t;

/*
 * Data structure used to hold all of the state for a given CPU.
 */
typedef struct kaif_cpusave {
	mdb_tgt_gregset_t	*krs_gregs;	/* saved registers */

	kaif_drreg_t		krs_dr;		/* saved debug registers */

	desctbr_t		krs_gdtr;	/* saved GDT register */
	desctbr_t		krs_idtr;	/* saved IDT register */
	desctbr_t		krs_tmpdesc;	/* pre-save *DT comparisons */

	kreg_t			krs_cr0;	/* saved %cr0 */

	kmdb_msr_t		*krs_msr;	/* ptr to MSR save area */

	uint_t			krs_cpu_state;	/* KAIF_CPU_STATE_* mstr/slv */
	uint_t			krs_cpu_flushed; /* Have caches been flushed? */
	uint_t			krs_cpu_id;	/* this CPU's ID */

	/* Bread crumb ring buffer */
	ulong_t			krs_curcrumbidx; /* Current krs_crumbs idx */
	kaif_crumb_t		*krs_curcrumb;	/* Pointer to current crumb */
	kaif_crumb_t		krs_crumbs[KAIF_NCRUMBS]; /* Crumbs */
} kaif_cpusave_t;

#endif /* !_ASM */

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_REGS_H */
