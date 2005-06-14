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
#include <vm/page.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern processorid_t getbootcpuid(void);
extern void mp_halt(char *);

extern int Cpudelay;
extern void setcpudelay(void);

extern void init_intr_threads(struct cpu *);
extern void init_clock_thread(void);

extern void send_dirint(int, int);
extern void siron(void);

extern void return_instr(void);

extern int pokefault;

extern int kcpc_hw_load_pcbe(void);
extern void kcpc_hw_init(cpu_t *cp);
extern int kcpc_hw_overflow_intr_installed;

struct memconf {
	pfn_t	mcf_spfn;	/* begin page fram number */
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
extern void post_startup_mmu_initialization(void);
extern int cpuid2nodeid(int);
extern void map_kaddr(caddr_t, pfn_t, int, int);

extern unsigned int microdata;
extern int use_mp;

extern struct cpu	cpus[];		/* pointer to other cpus */
extern struct cpu	*cpu[];		/* pointer to all cpus */

extern uintptr_t hole_start, hole_end;

#define	INVALID_VADDR(a)	\
	(((a) >= (caddr_t)hole_start && (a) < (caddr_t)hole_end))

/* kpm mapping window */
extern size_t   kpm_size;
extern uchar_t  kpm_size_shift;
extern caddr_t  kpm_vbase;

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_MACHSYSTM_H */
