/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _SYS_HMA_H
#define	_SYS_HMA_H

/*
 * Hypervisor Multiplexor API
 *
 * This provides a set of APIs that are usable by hypervisor implementations
 * that allows them to coexist and to make sure that they are all in a
 * consistent state.
 */

#include <sys/fp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FPU related management. These functions provide a set of APIs to manage the
 * FPU state and switch between host and guest management of this state.
 */

typedef struct hma_fpu hma_fpu_t;

/*
 * Allocate and free FPU state management structures.
 */
extern hma_fpu_t *hma_fpu_alloc(int);
extern void hma_fpu_free(hma_fpu_t *);

/*
 * Resets the FPU to the standard x86 default state. This should be called after
 * allocation and whenever the guest needs to logically reset the state (when
 * the CPU is reset, etc.). If the system supports xsave, then the xbv state
 * will be set to have the x87 and SSE portions as valid and the rest will be
 * set to their initial states (regardless of whether or not they will be
 * advertised in the host).
 */
extern int hma_fpu_init(hma_fpu_t *);

/*
 * Save the current host's FPU state and restore the guest's state in the FPU.
 * At this point, CR0.TS will not be set. The caller must not use the FPU in any
 * way before entering the guest.
 *
 * This should be used in normal operation before entering the guest. It should
 * also be used in a thread context operation when the thread is being scheduled
 * again. This interface has an implicit assumption that a given guest state
 * will be mapped to only one specific OS thread at any given time.
 *
 * This must be called with preemption disabled.
 */
extern void hma_fpu_start_guest(hma_fpu_t *);

/*
 * Save the current guest's FPU state and restore the host's state in the FPU.
 * By the time the thread returns to userland, the FPU will be in a usable
 * state; however, the FPU will not be usable while inside the kernel (CR0.TS
 * will be set).
 *
 * This should be used in normal operation after leaving the guest and returning
 * to user land. It should also be used in a thread context operation when the
 * thread is being descheduled. Like the hma_fpu_start_guest() interface, this
 * interface has an implicit assumption that a given guest state will be mapped
 * to only a single OS thread at any given time.
 *
 * This must be called with preemption disabled.
 */
extern void hma_fpu_stop_guest(hma_fpu_t *);

/*
 * Get and set the contents of the FPU save area. This sets the fxsave style
 * information. In all cases when this is in use, if an XSAVE state is actually
 * used by the host, then this will end up zeroing all of the non-fxsave state
 * and it will reset the xbv to indicate that the legacy x87 and SSE portions
 * are valid.
 *
 * These functions cannot be called while the FPU is in use by the guest. It is
 * up to callers to guarantee this fact.
 */
extern void hma_fpu_get_fxsave_state(const hma_fpu_t *, struct fxsave_state *);
extern int hma_fpu_set_fxsave_state(hma_fpu_t *, const struct fxsave_state *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_HMA_H */
