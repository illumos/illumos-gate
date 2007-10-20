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

#ifndef _SYS_MACHSYSTM_H
#define	_SYS_MACHSYSTM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Numerous platform-dependent interfaces that don't seem to belong
 * in any other header file.
 *
 * This file should not be included by code that purports to be
 * platform-independent.
 *
 */

#include <sys/machparam.h>
#include <sys/varargs.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/privregs.h>
#include <sys/systm.h>
#include <sys/traptrace.h>
#include <vm/page.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern void mach_cpu_idle(void);
extern void mach_cpu_halt(char *);
extern int mach_cpu_start(cpu_t *, void *);
extern int mach_cpuid_start(processorid_t, void *);

extern int Cpudelay;
extern void setcpudelay(void);

extern void send_dirint(int, int);
extern void siron(void);
extern void sir_on(int);

extern void return_instr(void);

extern int kcpc_hw_load_pcbe(void);
extern void kcpc_hw_init(cpu_t *cp);
extern void kcpc_hw_fini(cpu_t *cp);
extern int kcpc_hw_overflow_intr_installed;

struct panic_trap_info {
	struct regs *trap_regs;
	uint_t trap_type;
	caddr_t trap_addr;
};

struct memconf {
	pfn_t	mcf_spfn;	/* begin page frame number */
	pfn_t	mcf_epfn;	/* end page frame number */
};

struct system_hardware {
	int		hd_nodes;		/* number of nodes */
	int		hd_cpus_per_node; 	/* max cpus in a node */
	struct memconf 	hd_mem[MAXNODES];
						/*
						 * memory layout for each
						 * node.
						 */
};
extern struct system_hardware system_hardware;
extern void get_system_configuration(void);
extern void mmu_init(void);
extern int cpuid2nodeid(int);
extern void map_kaddr(caddr_t, pfn_t, int, int);

extern void memscrub_init(void);
extern void trap(struct regs *, caddr_t, processorid_t);

extern void do_interrupt(struct regs *, trap_trace_rec_t *);
extern void memscrub_disable(void);

#ifndef __xpv
extern unsigned int microdata;
#endif

extern int use_mp;

extern struct cpu	cpus[];		/* pointer to other cpus */
extern struct cpu	*cpu[];		/* pointer to all cpus */

extern int mach_cpucontext_init(void);
extern void mach_cpucontext_fini(void);
extern void *mach_cpucontext_alloc(struct cpu *);
extern void mach_cpucontext_free(struct cpu *, void *, int);
extern void rmp_gdt_init(rm_platter_t *);

extern uintptr_t hole_start, hole_end;

#define	INVALID_VADDR(a)	\
	(((a) >= (caddr_t)hole_start && (a) < (caddr_t)hole_end))

/* kpm mapping window */
extern size_t   kpm_size;
extern uchar_t  kpm_size_shift;
extern caddr_t  kpm_vbase;

struct memlist;
extern void memlist_add(uint64_t, uint64_t, struct memlist *,
    struct memlist **);
extern page_t *page_get_physical(uintptr_t);
extern int linear_pc(struct regs *rp, proc_t *p, caddr_t *linearp);
extern int dtrace_linear_pc(struct regs *rp, proc_t *p, caddr_t *linearp);

#ifdef __xpv
#include <sys/xen_mmu.h>
extern page_t *page_get_high_mfn(mfn_t);
#endif


#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_MACHSYSTM_H */
