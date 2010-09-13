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
/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_CPUIDLE_H
#define	_CPUIDLE_H

#include <sys/cpupm.h>
#include <sys/cpu.h>

#ifdef __cplusplus
extern "C" {
#endif
#define	CPU_MAX_CSTATES	8

#define	CPU_ACPI_C0	IDLE_STATE_C0
#define	CPU_ACPI_C1	IDLE_STATE_C1
#define	CPU_ACPI_C2	IDLE_STATE_C2
#define	CPU_ACPI_C3	IDLE_STATE_C3

#define	BM_CTL		0x1
#define	BM_RLD		0x2
#define	BM_ARB_DIS	0x4

#define	CPUID_TSC_INVARIANCE	0x100

#define	CPU_IDLE_DEEP_CFG	(0x1)	/* Deep Idle disabled by user */
#define	CPU_IDLE_CPR_CFG	(0x2)	/* In CPR */

typedef struct cpu_idle_kstat_s {
	struct kstat_named	addr_space_id;	/* register address space id */
	struct kstat_named	cs_latency;	/* worst latency */
	struct kstat_named	cs_power;	/* average power consumption */
} cpu_idle_kstat_t;

extern cpupm_state_ops_t cpu_idle_ops;

extern void cpu_acpi_idle(void);
extern void cstate_wakeup(cpu_t *, int);
extern boolean_t cpu_deep_cstates_supported(void);
extern void cpu_wakeup(cpu_t *, int);
extern void cpu_wakeup_mwait(cpu_t *, int);
extern void cpuidle_manage_cstates(void *);
extern boolean_t cstate_timer_callback(int code);

#ifdef __cplusplus
}
#endif

#endif	/* _CPUIDLE_H */
