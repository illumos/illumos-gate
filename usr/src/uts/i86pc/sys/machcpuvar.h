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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MACHCPUVAR_H
#define	_SYS_MACHCPUVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/inttypes.h>
#include <sys/xc_levels.h>
#include <sys/tss.h>
#include <sys/segments.h>
#include <sys/rm_platter.h>
#include <sys/avintr.h>
#include <sys/mmu.h>
#include <sys/pte.h>

#ifndef	_ASM
/*
 * Machine specific fields of the cpu struct
 * defined in common/sys/cpuvar.h.
 *
 * Note:  This is kinda kludgy but seems to be the best
 * of our alternatives.
 */
typedef void *cpu_pri_lev_t;

struct cpuid_info;
struct cmi;

struct	machcpu {
	/* define all the x_call stuff */
	volatile int	xc_pend[X_CALL_LEVELS];
	volatile int	xc_wait[X_CALL_LEVELS];
	volatile int	xc_ack[X_CALL_LEVELS];
	volatile int	xc_state[X_CALL_LEVELS];
	volatile int	xc_retval[X_CALL_LEVELS];

	int		mcpu_nodeid;		/* node-id */
	int		mcpu_pri;		/* CPU priority */
	cpu_pri_lev_t	mcpu_pri_data;		/* ptr to machine dependent */
						/* data for setting priority */
						/* level */

	uint_t		mcpu_mask;	/* bitmask for this cpu (1<<cpu_id) */
	struct hat	*mcpu_current_hat; /* cpu's current hat */

	struct hat_cpu_info	*mcpu_hat_info;

	/* i86 hardware table addresses that cannot be shared */
	user_desc_t	*mcpu_gdt;	/* GDT */
	gate_desc_t	*mcpu_idt;	/* IDT */
	struct tss	*mcpu_tss;	/* TSS */

	struct	cpu_tables *mcpu_cp_tables;	/* pointer to space acquired */
						/* while starting up */
						/* auxillary processors */
	kmutex_t	mcpu_ppaddr_mutex;

	caddr_t		mcpu_caddr1;	/* per cpu CADDR1 */
	caddr_t		mcpu_caddr2;	/* per cpu CADDR2 */
	void		*mcpu_caddr1pte;
	void		*mcpu_caddr2pte;
	struct softint mcpu_softinfo;
	uint64_t	pil_high_start[HIGH_LEVELS];
	uint64_t	intrstat[PIL_MAX + 1][2];
	struct cpuid_info	 *mcpu_cpi;
	struct cmi	*mcpu_cmi;	/* CPU module state */
	void		*mcpu_cmidata;
#if defined(__amd64)
	greg_t	mcpu_rtmp_rsp;		/* syscall: temporary %rsp stash */
	greg_t	mcpu_rtmp_r15;		/* syscall: temporary %r15 stash */
#endif
};

#endif	/* _ASM */

#define	cpu_nodeid cpu_m.mcpu_nodeid
#define	cpu_pri cpu_m.mcpu_pri
#define	cpu_pri_data cpu_m.mcpu_pri_data
#define	cpu_mask cpu_m.mcpu_mask
#define	cpu_current_hat cpu_m.mcpu_current_hat
#define	cpu_hat_info cpu_m.mcpu_hat_info
#define	cpu_ppaddr_mutex cpu_m.mcpu_ppaddr_mutex
#define	cpu_gdt cpu_m.mcpu_gdt
#define	cpu_idt cpu_m.mcpu_idt
#define	cpu_tss cpu_m.mcpu_tss
#define	cpu_ldt cpu_m.mcpu_ldt
#define	cpu_caddr1 cpu_m.mcpu_caddr1
#define	cpu_caddr2 cpu_m.mcpu_caddr2
#define	cpu_softinfo cpu_m.mcpu_softinfo
#define	cpu_caddr1pte cpu_m.mcpu_caddr1pte
#define	cpu_caddr2pte cpu_m.mcpu_caddr2pte

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHCPUVAR_H */
