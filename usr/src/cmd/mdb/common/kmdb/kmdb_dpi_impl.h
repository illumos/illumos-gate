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

#ifndef _KMDB_DPI_IMPL_H
#define	_KMDB_DPI_IMPL_H

#include <setjmp.h>
#ifdef	__sparc
#include <sys/regset.h>
#endif	/* __sparc */
#include <sys/types.h>

#include <kmdb/kmdb_auxv.h>
#include <kmdb/kmdb_dpi.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb_target.h>

#ifdef __cplusplus
extern "C" {
#endif

extern jmp_buf *kmdb_dpi_fault_pcb;

/*
 * The routines used by the kmdb side of the DPI to access the saved state
 * of the current kernel instance, and to control that instance.  A populated
 * version of this vector is provided by the DPI backend used to control the
 * machine.  General use of the kmdb DPI is not via direct invocation of the
 * functions in this ops vector, but rather flows through the convenience
 * wrappers in kmdb_dpi.c.
 */
struct dpi_ops {
	int (*dpo_init)(kmdb_auxv_t *);

	void (*dpo_debugger_activate)(kdi_debugvec_t **, uint_t);
	void (*dpo_debugger_deactivate)(void);

	void (*dpo_enter_mon)(void);

	void (*dpo_modchg_register)(void (*)(struct modctl *, int));
	void (*dpo_modchg_cancel)(void);

	int (*dpo_get_cpu_state)(int);
	int (*dpo_get_master_cpuid)(void);

	const mdb_tgt_gregset_t *(*dpo_get_gregs)(int);
	int (*dpo_get_register)(const char *, kreg_t *);
	int (*dpo_set_register)(const char *, kreg_t);
#ifdef __sparc
	int (*dpo_get_rwin)(int, int, struct rwindow *);
	int (*dpo_get_nwin)(int);
#endif

	int (*dpo_brkpt_arm)(uintptr_t, mdb_instr_t *);
	int (*dpo_brkpt_disarm)(uintptr_t, mdb_instr_t);

	int (*dpo_wapt_validate)(kmdb_wapt_t *);
	int (*dpo_wapt_reserve)(kmdb_wapt_t *);
	void (*dpo_wapt_release)(kmdb_wapt_t *);
	void (*dpo_wapt_arm)(kmdb_wapt_t *);
	void (*dpo_wapt_disarm)(kmdb_wapt_t *);
	int (*dpo_wapt_match)(kmdb_wapt_t *);

	int (*dpo_step)(void);

	uintptr_t (*dpo_call)(uintptr_t, uint_t, const uintptr_t *);

	void (*dpo_dump_crumbs)(uintptr_t, int);

#ifdef __sparc
	void (*dpo_kernpanic)(int);
#endif
};

extern void (*kmdb_dpi_wrintr_fire)(void);

extern dpi_ops_t kmdb_dpi_ops;

extern void kmdb_dpi_resume_common(int);
extern void kmdb_dpi_resume_master(void);

/* Used by the debugger to tell the driver how to resume */
#define	KMDB_DPI_CMD_RESUME_ALL		1	/* Resume all CPUs */
#define	KMDB_DPI_CMD_RESUME_MASTER	2	/* Resume only master CPU */
#define	KMDB_DPI_CMD_RESUME_UNLOAD	3	/* Resume for debugger unload */
#define	KMDB_DPI_CMD_SWITCH_CPU		4	/* Switch to another CPU */
#define	KMDB_DPI_CMD_FLUSH_CACHES	5	/* Flush slave caches */
#define	KMDB_DPI_CMD_REBOOT		6	/* Reboot the machine */

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_DPI_IMPL_H */
