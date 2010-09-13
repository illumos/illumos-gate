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

#ifndef _KMDB_DPI_H
#define	_KMDB_DPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Retargetable Kmdb/PROM interface
 */

#include <sys/types.h>
#include <setjmp.h>
#ifdef	__sparc
#include <sys/regset.h>
#endif	/* __sparc */

#include <mdb/mdb_kreg.h>
#include <mdb/mdb_target.h>
#include <kmdb/kmdb_auxv.h>
#include <kmdb/kmdb_dpi_isadep.h>
#include <kmdb/kmdb_kctl.h>

/*
 * The following directive tells the mapfile generator that only those
 * prototypes and declarations ending with a "Driver OK" comment should be
 * included in the mapfile.
 *
 * MAPFILE: export "Driver OK"
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	DPI_MASTER_CPUID	(-1)	/* matches CPU ID for master */

#define	DPI_ALLOW_FAULTS	NULL

#define	DPI_STATE_INIT		1	/* debugger initializing */
#define	DPI_STATE_STOPPED	2	/* User-requested stop (debug_enter) */
#define	DPI_STATE_FAULTED	3	/* Breakpoint, watchpoint, etc. */
#define	DPI_STATE_LOST		4	/* debugger fault */

#define	DPI_STATE_WHY_BKPT	1
#define	DPI_STATE_WHY_V_WAPT	2
#define	DPI_STATE_WHY_P_WAPT	3
#define	DPI_STATE_WHY_TRAP	4

#define	DPI_WAPT_TYPE_PHYS	0x1	/* Physical address (SPARC only) */
#define	DPI_WAPT_TYPE_VIRT	0x2	/* Virtual address */
#define	DPI_WAPT_TYPE_IO	0x4	/* I/O space (Intel only) */

#define	DPI_CPU_STATE_NONE	0
#define	DPI_CPU_STATE_MASTER	1
#define	DPI_CPU_STATE_SLAVE	2

typedef struct dpi_ops dpi_ops_t;

typedef struct kmdb_wapt {
	uintptr_t wp_addr;		/* Watchpoint base address */
	size_t wp_size;			/* Size of watched area, in bytes */
	int wp_type;			/* DPI_WAPT_TYPE_* */
	uint_t wp_wflags;		/* access modes */
	void *wp_priv;			/* DPI-private data */
} kmdb_wapt_t;

extern int kmdb_dpi_init(kmdb_auxv_t *);

extern void kmdb_dpi_enter_mon(void);

extern void kmdb_dpi_modchg_register(void (*)(struct modctl *, int));
extern void kmdb_dpi_modchg_cancel(void);

extern int kmdb_dpi_get_cpu_state(int);
extern int kmdb_dpi_get_master_cpuid(void);

extern const mdb_tgt_gregset_t *kmdb_dpi_get_gregs(int);

extern int kmdb_dpi_get_register(const char *, kreg_t *);
extern int kmdb_dpi_set_register(const char *, kreg_t);

extern jmp_buf *kmdb_dpi_set_fault_hdlr(jmp_buf *);
extern void kmdb_dpi_restore_fault_hdlr(jmp_buf *);

extern int kmdb_dpi_brkpt_arm(uintptr_t, mdb_instr_t *);
extern int kmdb_dpi_brkpt_disarm(uintptr_t, mdb_instr_t);

extern int kmdb_dpi_wapt_validate(kmdb_wapt_t *);
extern int kmdb_dpi_wapt_reserve(kmdb_wapt_t *);
extern void kmdb_dpi_wapt_release(kmdb_wapt_t *);
extern void kmdb_dpi_wapt_arm(kmdb_wapt_t *);
extern void kmdb_dpi_wapt_disarm(kmdb_wapt_t *);
extern int kmdb_dpi_wapt_match(kmdb_wapt_t *);

extern void kmdb_dpi_set_state(int, int);
extern int kmdb_dpi_get_state(int *);

extern int kmdb_dpi_step(void);

extern uintptr_t kmdb_dpi_call(uintptr_t, uint_t, const uintptr_t *);

extern void kmdb_dpi_process_work_queue(void);
extern int kmdb_dpi_work_required(void);			/* Driver OK */

extern void kmdb_dpi_flush_slave_caches(void);

extern void kmdb_dpi_dump_crumbs(uintptr_t, int);

/*
 * Debugger/Kernel suspend
 */

extern jmp_buf kmdb_dpi_entry_pcb;
extern uint_t kmdb_dpi_resume_requested;			/* Driver OK */
extern uint_t kmdb_dpi_switch_target;				/* Driver OK */
extern jmp_buf kmdb_dpi_resume_pcb;

extern int kmdb_dpi_reenter(void);
extern void kmdb_dpi_resume(void);
extern void kmdb_dpi_resume_unload(void);
extern int kmdb_dpi_switch_master(int);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_DPI_H */
