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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KAIF_H
#define	_KAIF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM
#include <sys/kdi.h>
#include <sys/types.h>
#include <sys/segments.h>
#include <kmdb/kaif_regs.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	KAIF_MASTER_CPUID_UNSET		-1

#define	KAIF_CPU_CMD_RESUME		0
#define	KAIF_CPU_CMD_RESUME_MASTER	1
#define	KAIF_CPU_CMD_SWITCH		2
#define	KAIF_CPU_CMD_PASS_TO_KERNEL	3
#define	KAIF_CPU_CMD_REBOOT		4

#define	KAIF_CPU_STATE_NONE		0
#define	KAIF_CPU_STATE_MASTER		1
#define	KAIF_CPU_STATE_SLAVE		2

#ifndef _ASM

typedef struct kaif_memrange {
	caddr_t mr_base;
	caddr_t mr_lim;
} kaif_memrange_t;

extern kaif_memrange_t kaif_memranges[];
extern int kaif_nmemranges;

extern kaif_cpusave_t *kaif_cpusave;
extern int kaif_ncpusave;
extern int kaif_master_cpuid;

extern uint32_t kaif_cs;
extern uint32_t	kaif_ds;
extern uint32_t	kaif_fs;
extern uint32_t	kaif_gs;

extern char kaif_slave_entry_patch;

extern struct gate_desc kaif_idt[];
extern desctbr_t kaif_idtr;
extern size_t kaif_ivct_size;
extern int kaif_trap_switch;

extern uintptr_t kaif_kernel_handler;
extern uintptr_t kaif_sys_sysenter;

extern void kaif_trap_set_debugger(void);
extern void kaif_trap_set_saved(kaif_cpusave_t *);

extern uintptr_t kaif_invoke(uintptr_t, uint_t, const uintptr_t[]);

extern void kaif_nmiint(void);
extern void kaif_cmnint(void);
extern void kaif_enter(void);
extern void kaif_slave_entry(void);
extern int kaif_debugger_entry(kaif_cpusave_t *);

extern void kaif_mod_loaded(struct modctl *);
extern void kaif_mod_unloading(struct modctl *);

extern void kaif_cpu_debug_init(kaif_cpusave_t *);

extern void kaif_idt_init(void);
extern void kaif_idt_write(gate_desc_t *, uint_t);
extern void kaif_idt_patch(caddr_t, size_t);
extern uintptr_t kaif_kernel_trap2hdlr(int);

extern void kaif_activate(kdi_debugvec_t **, uint_t);
extern void kaif_deactivate(void);

extern int kaif_memrange_add(caddr_t, size_t);

extern void get_idt(desctbr_t *);
extern void set_idt(desctbr_t *);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_H */
