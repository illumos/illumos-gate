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

#ifndef _KAIF_H
#define	_KAIF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	sun4v
#include <sys/spitregs.h>
#endif	/* sun4v */

#ifndef _ASM
#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kaif_regs.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	KAIF_CPU_STATE_NONE		0
#define	KAIF_CPU_STATE_MASTER		1
#define	KAIF_CPU_STATE_SLAVE		2

#define	KAIF_LSUCTL_VWAPT_MASK	(LSU_VM|LSU_VR|LSU_VW)
#define	KAIF_LSUCTL_PWAPT_MASK	(LSU_PM|LSU_PR|LSU_PW)
#define	KAIF_LSUCTL_WAPT_MASK	(LSU_PM|LSU_VM|LSU_PR|LSU_PW|LSU_VR|LSU_VW)

#ifndef _ASM
extern kaif_cpusave_t *kaif_cpusave;
extern kaif_cpusave_t kaif_cb_save;
extern int kaif_ncpusave;
extern int kaif_master_cpuid;

extern int *kaif_promexitarmp;

extern void (*kaif_ktrap_install)(int, void (*)(void));
extern void (*kaif_ktrap_restore)(void);

extern caddr_t kaif_tba;
extern caddr_t kaif_tba_obp;
#ifdef	sun4v
extern caddr_t	kaif_tba_kernel;
#endif
extern caddr_t kaif_tba_native;
extern size_t kaif_tba_native_sz;

extern int kaif_trap_switch;

extern void kaif_trap_set_debugger(void);
extern void kaif_trap_set_saved(kaif_cpusave_t *);

extern void kaif_hdlr_imiss(void);
extern caddr_t kaif_hdlr_imiss_patch;
extern void kaif_hdlr_dmiss(void);
extern caddr_t kaif_hdlr_dmiss_patch;
extern void kaif_hdlr_generic(void);
extern void kaif_dtrap(void);

extern caddr_t kaif_dseg_start;
extern caddr_t kaif_dseg_lim;

extern uintptr_t kaif_invoke(uintptr_t, uint_t, const uintptr_t[],
    kreg_t, kreg_t);

extern void kaif_enter(void);

extern void kaif_ktrap(void);
extern void kaif_slave_entry(void);
extern void kaif_trap_obp(void);

extern void kaif_mod_loaded(struct modctl *);
extern void kaif_mod_unloading(struct modctl *);

extern void kaif_wapt_set_regs(void);
extern void kaif_wapt_clear_regs(void);

extern void kaif_activate(kdi_debugvec_t **, uint_t);
extern void kaif_deactivate(void);
extern void kaif_resume(int);
extern void kaif_slave_entry(void);
extern void kaif_prom_rearm(void);
extern void kaif_debugger_entry(kaif_cpusave_t *);

extern void kaif_slave_loop_barrier(void);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_H */
