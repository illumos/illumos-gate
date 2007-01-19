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

#ifndef _KDI_H
#define	_KDI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

/*
 * The Kernel/Debugger interface.
 *
 * The Debugger -> Kernel portion of the interface is handled by the kdi_t,
 * which is defined in the archkdi.h files.  These functions are intended to
 * be called only when the system is stopped and the debugger is in control.
 *
 * The Kernel -> Debugger portion is handled by the debugvec_t, which is
 * defined here.  These functions are used by the kernel to inform the debugger
 * of various state changes.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The VA range reserved for the debugger; used by kmdb.
 */
extern const caddr_t kdi_segdebugbase;
extern const size_t kdi_segdebugsize;

struct cpu;
struct modctl;
struct gate_desc;
struct user_desc;

typedef struct kdi_debugvec kdi_debugvec_t;
typedef struct kdi kdi_t;

extern kdi_debugvec_t	*kdi_dvec;
extern struct modctl	*kdi_dmods;

#define	KDI_VERSION		7

extern void kdi_dvec_vmready(void);
extern void kdi_dvec_memavail(void);
#if defined(__sparc)
extern void kdi_dvec_cpu_init(struct cpu *);
extern void kdi_dvec_cpr_restart(void);
#endif
extern void kdi_dvec_modavail(void);
extern void kdi_dvec_thravail(void);
extern void kdi_dvec_mod_loaded(struct modctl *);
extern void kdi_dvec_mod_unloading(struct modctl *);

/*
 * The state machine described below is used to coordinate the efforts of
 * kmdb and dtrace.  As both use breakpoints, only one may be currently be
 * active at a given time.  Transitions are possible between the idle state
 * and either of the active states, but not directly between the two active
 * states.
 */
typedef enum kdi_dtrace_set {
	KDI_DTSET_DTRACE_ACTIVATE,
	KDI_DTSET_DTRACE_DEACTIVATE,
	KDI_DTSET_KMDB_BPT_ACTIVATE,
	KDI_DTSET_KMDB_BPT_DEACTIVATE
} kdi_dtrace_set_t;

typedef enum {
	KDI_DTSTATE_DTRACE_ACTIVE,
	KDI_DTSTATE_IDLE,
	KDI_DTSTATE_KMDB_BPT_ACTIVE
} kdi_dtrace_state_t;

extern int kdi_dtrace_set(kdi_dtrace_set_t);

#ifdef __cplusplus
}
#endif

#endif /* _KDI_H */
