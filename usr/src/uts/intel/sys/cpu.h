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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CPU_H
#define	_SYS_CPU_H

/*
 * WARNING:
 *	This header file is Obsolete and may be deleted in a
 *	future release of Solaris.
 */

/*
 * Include generic bustype cookies.
 */
#include <sys/bustypes.h>
#include <sys/inttypes.h>

#if defined(_KERNEL)
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif
#if defined(__GNUC__) && defined(_ASM_INLINES)
#include <asm/cpu.h>
#endif
#endif	/* _KERNEL */

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)
extern void ht_pause(void);
extern void cli(void);
extern void sti(void);
extern void i86_halt(void);
extern void i86_monitor(volatile uint32_t *addr, uint32_t extensions,
    uint32_t hints);
extern void i86_mwait(uint32_t data, uint32_t extensions);

/*
 * Used to insert cpu-dependent instructions into spin loops
 */
#define	SMT_PAUSE()		ht_pause()

/*
 *
 * C-state defines for the idle_state_transition DTrace probe
 *
 * The probe fires when the CPU undergoes an idle state change (e.g. C-state)
 * The argument passed is the C-state to which the CPU is transitioning.
 *
 * These states will be shared by cpupm subsystem, so they should be kept in
 * consistence with ACPI defined C states.
 */
#define	IDLE_STATE_C0 0
#define	IDLE_STATE_C1 1
#define	IDLE_STATE_C2 2
#define	IDLE_STATE_C3 3

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPU_H */
