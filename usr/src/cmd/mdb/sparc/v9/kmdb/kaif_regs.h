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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KAIF_REGS_H
#define	_KAIF_REGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM
#include <sys/types.h>
#include <sys/regset.h>
#include <sys/stack.h>
#include <sys/kdi_impl.h>

#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	KAIF_CPU_STKSZ	((MINFRAME64 * 20) + STACK_ALIGN64)

#define	KAIF_NCRUMBS	5

#define	KAIF_CRUMB_SRC_OBP	1
#define	KAIF_CRUMB_SRC_IVEC	2
#define	KAIF_CRUMB_SRC_MAIN	3

#define	KAIF_CRUMB_F_MAIN_OBPWAPT	0x01
#define	KAIF_CRUMB_F_MAIN_OBPPENT	0x02
#define	KAIF_CRUMB_F_MAIN_NORMAL	0x04

#define	KAIF_CRUMB_F_IVEC_REENTER	0x08
#define	KAIF_CRUMB_F_IVEC_INOBP		0x10
#define	KAIF_CRUMB_F_IVEC_NORMAL	0x20

#define	KAIF_CRUMB_F_OBP_NORMAL		0x40
#define	KAIF_CRUMB_F_OBP_REVECT		0x80

#ifndef _ASM

/*
 * We maintain a ring buffer of bread crumbs for debugging purposes.  The
 * current buffer pointer is advanced along the ring with each intercepted
 * trap (debugger entry, invalid memory access, etc).  The structure must have a
 * size equal to a multiple of 8.
 */
typedef struct kaif_crumb {
	uint64_t krm_src;
	uint64_t krm_pc;
	uint64_t krm_tt;
	uint32_t krm_flag;
	uint32_t krm_pad;
} kaif_crumb_t;

/* Keep in sync with kaif_regs.in */
typedef struct kaif_cpusave {
	mdb_tgt_gregset_t	krs_gregs;	/* Saved registers */
	struct rwindow		*krs_rwins;	/* Saved register windows */
	kfpu_t			krs_fpregs;	/* Saved FP registers */

	kreg_t			krs_tstate;	/* Saved %tstate */
	kreg_t			krs_mmu_pcontext; /* Context # at kmdb entry */

	uint_t			krs_cpu_state;	/* KAIF_CPU_STATE_* */
	uint_t			krs_cpu_flushed; /* Have caches been flushed? */
	uint_t			krs_cpu_id;	/* this CPU's ID */
	uint_t			krs_cpu_acked;	/* for slave to ack master */

	uint64_t		krs_lsucr_save;	/* LSUCR for wapt step */
	uint32_t		krs_instr_save;	/* OBP instr for wapt step */

	/* Bread crumb ring buffer */
	uint_t			krs_curcrumbidx; /* Current krs_crumbs idx */
	kaif_crumb_t		*krs_curcrumb;	/* Current crumb */
	kaif_crumb_t		krs_crumbs[KAIF_NCRUMBS];  /* Crumbs */

	char			krs_cpustack[KAIF_CPU_STKSZ];
} kaif_cpusave_t;
#endif

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_REGS_H */
