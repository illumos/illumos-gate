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
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_MACHCPUVAR_H
#define	_SYS_MACHCPUVAR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/inttypes.h>
#include <sys/x_call.h>
#include <sys/tss.h>
#include <sys/segments.h>
#include <sys/rm_platter.h>
#include <sys/avintr.h>
#include <sys/pte.h>

#ifndef	_ASM
/*
 * On a virtualized platform a virtual cpu may not be actually
 * on a physical cpu, especially in situations where a configuration has
 * more vcpus than pcpus.  This function tells us (if it's able) if the
 * specified vcpu is currently running on a pcpu.  Note if it is not
 * known or not able to determine, it will return the unknown state.
 */
#define	VCPU_STATE_UNKNOWN	0
#define	VCPU_ON_PCPU		1
#define	VCPU_NOT_ON_PCPU	2

extern int vcpu_on_pcpu(processorid_t);

/*
 * Machine specific fields of the cpu struct
 * defined in common/sys/cpuvar.h.
 *
 * Note:  This is kinda kludgy but seems to be the best
 * of our alternatives.
 */

struct cpuid_info;
struct cpu_ucode_info;
struct cmi_hdl;

/*
 * A note about the hypervisor affinity bits: a one bit in the affinity mask
 * means the corresponding event channel is allowed to be serviced
 * by this cpu.
 */
struct xen_evt_data {
	ulong_t		pending_sel[PIL_MAX + 1]; /* event array selectors */
	ulong_t		pending_evts[PIL_MAX + 1][sizeof (ulong_t) * 8];
	ulong_t		evt_affinity[sizeof (ulong_t) * 8]; /* service on cpu */
};

struct	machcpu {
	/*
	 * x_call fields - used for interprocessor cross calls
	 */
	struct xc_msg	*xc_msgbox;
	struct xc_msg	*xc_free;
	xc_data_t	xc_data;
	uint32_t	xc_wait_cnt;
	volatile uint32_t xc_work_cnt;

	int		mcpu_nodeid;		/* node-id */
	int		mcpu_pri;		/* CPU priority */

	struct hat	*mcpu_current_hat; /* cpu's current hat */

	struct hat_cpu_info	*mcpu_hat_info;

	volatile ulong_t	mcpu_tlb_info;

	/* i86 hardware table addresses that cannot be shared */

	user_desc_t	*mcpu_gdt;	/* GDT */
	gate_desc_t	*mcpu_idt;	/* current IDT */

	tss_t		*mcpu_tss;	/* TSS */

	kmutex_t	mcpu_ppaddr_mutex;
	caddr_t		mcpu_caddr1;	/* per cpu CADDR1 */
	caddr_t		mcpu_caddr2;	/* per cpu CADDR2 */
	uint64_t	mcpu_caddr1pte;
	uint64_t	mcpu_caddr2pte;

	struct softint	mcpu_softinfo;
	uint64_t	pil_high_start[HIGH_LEVELS];
	uint64_t	intrstat[PIL_MAX + 1][2];

	struct cpuid_info	 *mcpu_cpi;

#if defined(__amd64)
	greg_t	mcpu_rtmp_rsp;		/* syscall: temporary %rsp stash */
	greg_t	mcpu_rtmp_r15;		/* syscall: temporary %r15 stash */
#endif

	struct vcpu_info *mcpu_vcpu_info;
	uint64_t	mcpu_gdtpa;	/* hypervisor: GDT physical address */

	uint16_t mcpu_intr_pending;	/* hypervisor: pending intrpt levels */
	uint16_t mcpu_ec_mbox;		/* hypervisor: evtchn_dev mailbox */
	struct xen_evt_data *mcpu_evt_pend; /* hypervisor: pending events */

	volatile uint32_t *mcpu_mwait;	/* MONITOR/MWAIT buffer */
	void (*mcpu_idle_cpu)(void);	/* idle function */
	uint16_t mcpu_idle_type;	/* CPU next idle type */
	uint16_t max_cstates;		/* supported max cstates */

	struct cpu_ucode_info	*mcpu_ucode_info;

	void			*mcpu_pm_mach_state;
	struct cmi_hdl		*mcpu_cmi_hdl;
	void			*mcpu_mach_ctx_ptr;

	/*
	 * A stamp that is unique per processor and changes
	 * whenever an interrupt happens. Userful for detecting
	 * if a section of code gets interrupted.
	 * The high order 16 bits will hold the cpu->cpu_id.
	 * The low order bits will be incremented on every interrupt.
	 */
	volatile uint32_t	mcpu_istamp;
};

#define	NINTR_THREADS	(LOCK_LEVEL-1)	/* number of interrupt threads */
#define	MWAIT_HALTED	(1)		/* mcpu_mwait set when halting */
#define	MWAIT_RUNNING	(0)		/* mcpu_mwait set to wakeup */
#define	MWAIT_WAKEUP_IPI	(2)	/* need IPI to wakeup */
#define	MWAIT_WAKEUP(cpu)	(*((cpu)->cpu_m.mcpu_mwait) = MWAIT_RUNNING)

#endif	/* _ASM */

/* Please DON'T add any more of this namespace-poisoning sewage here */

#define	cpu_nodeid cpu_m.mcpu_nodeid
#define	cpu_pri cpu_m.mcpu_pri
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
