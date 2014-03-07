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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_MACHSYSTM_H
#define	_SYS_MACHSYSTM_H

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

typedef enum mach_cpu_add_arg_type {
	MACH_CPU_ARG_LOCAL_APIC,
	MACH_CPU_ARG_LOCAL_X2APIC,
} mach_cpu_add_arg_type_t;

typedef struct mach_cpu_add_arg {
	mach_cpu_add_arg_type_t		type;
	union {
		struct {
			uint32_t	apic_id;
			uint32_t	proc_id;
		} apic;
	} arg;
} mach_cpu_add_arg_t;

extern void mach_cpu_idle(void);
extern void mach_cpu_halt(char *);
extern int mach_cpu_start(cpu_t *, void *);
extern int mach_cpuid_start(processorid_t, void *);
extern int mach_cpu_stop(cpu_t *, void *);
extern int mach_cpu_add(mach_cpu_add_arg_t *, processorid_t *);
extern int mach_cpu_remove(processorid_t);
extern int mach_cpu_create_device_node(cpu_t *, dev_info_t **);
extern int mach_cpu_get_device_node(cpu_t *, dev_info_t **);

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

/*
 * Interrupt handling hooks
 */
extern void (*do_interrupt_common)(struct regs *, trap_trace_rec_t *);
extern uintptr_t (*get_intr_handler)(int, short);

/*
 * Dispatcher hooks.
 */
void    (*idle_cpu)();
void    (*non_deep_idle_cpu)();
void    (*disp_enq_thread)(cpu_t *, int);
void    (*non_deep_idle_disp_enq_thread)(cpu_t *, int);

#ifndef __xpv
extern unsigned int microdata;
#endif

extern int use_mp;

extern struct cpu	cpus[];		/* pointer to other cpus */
extern struct cpu	*cpu[];		/* pointer to all cpus */

/* Operation types for extended mach_cpucontext interfaces */
#define	MACH_CPUCONTEXT_OP_START	0
#define	MACH_CPUCONTEXT_OP_STOP		1

extern int mach_cpucontext_init(void);
extern void mach_cpucontext_fini(void);
extern void *mach_cpucontext_alloc(struct cpu *);
extern void mach_cpucontext_free(struct cpu *, void *, int);
extern void *mach_cpucontext_xalloc(struct cpu *, int);
extern void mach_cpucontext_xfree(struct cpu *, void *, int, int);
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
extern page_t *page_get_physical(uintptr_t seed);
extern int linear_pc(struct regs *rp, proc_t *p, caddr_t *linearp);
extern int dtrace_linear_pc(struct regs *rp, proc_t *p, caddr_t *linearp);

extern int force_shutdown_method;

/* Dynamic Reconfiguration capability interface. */
#define	PLAT_DR_OPTIONS_NAME		"plat-dr-options"
#define	PLAT_DR_PHYSMAX_NAME		"plat-dr-physmax"
#define	PLAT_MAX_NCPUS_NAME		"plat-max-ncpus"
#define	BOOT_MAX_NCPUS_NAME		"boot-max-ncpus"
#define	BOOT_NCPUS_NAME			"boot-ncpus"

#define	PLAT_DR_FEATURE_CPU		0x1
#define	PLAT_DR_FEATURE_MEMORY		0x2
#define	PLAT_DR_FEATURE_ENABLED		0x1000000

#define	plat_dr_enabled()		\
	plat_dr_check_capability(PLAT_DR_FEATURE_ENABLED)

#define	plat_dr_enable()		\
	plat_dr_enable_capability(PLAT_DR_FEATURE_ENABLED)

#define	plat_dr_disable_cpu()		\
	plat_dr_disable_capability(PLAT_DR_FEATURE_CPU)
#define	plat_dr_disable_memory()	\
	plat_dr_disable_capability(PLAT_DR_FEATURE_MEMORY)

extern boolean_t plat_dr_support_cpu(void);
extern boolean_t plat_dr_support_memory(void);
extern boolean_t plat_dr_check_capability(uint64_t features);
extern void plat_dr_enable_capability(uint64_t features);
extern void plat_dr_disable_capability(uint64_t features);

#pragma	weak plat_dr_support_cpu
#pragma	weak plat_dr_support_memory

/*
 * Used to communicate DR updates to platform lgroup framework
 */
typedef struct {
	uint64_t	u_base;
	uint64_t	u_length;
	uint32_t	u_domain;
	uint32_t	u_device_id;
	uint32_t	u_sli_cnt;
	uchar_t		*u_sli_ptr;
} update_membounds_t;

/* Maximum physical page number (PFN) for memory DR operations. */
extern uint64_t plat_dr_physmax;

#ifdef __xpv
#include <sys/xen_mmu.h>
extern page_t *page_get_high_mfn(mfn_t);
#endif

extern hrtime_t tsc_gethrtime_tick_delta(void);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_MACHSYSTM_H */
