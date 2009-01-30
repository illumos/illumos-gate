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

#ifndef _SYS_CPU_MODULE_H
#define	_SYS_CPU_MODULE_H

#include <sys/pte.h>
#include <sys/async.h>
#include <sys/x_call.h>
#include <sys/conf.h>
#include <sys/obpdefs.h>

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef _KERNEL

/*
 * The are functions that are expected of the cpu modules.
 */

extern struct module_ops *moduleops;

struct kdi;

/*
 * module initialization
 */
void	cpu_setup(void);
void	cpu_kdi_init(struct kdi *);

/*
 * set CPU implementation details
 *
 * set Panther CPU implementation details
 *
 * On Panther-only domains and Olympus-C, mmu_init_mmu_page_sizes
 * changes the mmu_page_sizes variable from the default 4 page sizes
 * to 6 page sizes and is called from fillsysinfo.c:check_cpus_set
 * at early bootup time.
 */
void	cpu_fiximp(pnode_t dnode);
#pragma weak cpu_fix_allpanther
void	cpu_fix_allpanther(void);
#pragma weak cpu_fix_alljupiter
void	cpu_fix_alljupiter(void);
#pragma weak mmu_init_mmu_page_sizes
int	mmu_init_mmu_page_sizes(int cinfo);

/*
 * virtual demap flushes (tlbs & virtual tag caches)
 */
void	vtag_flushpage(caddr_t addr, uint64_t sfmmup);
void	vtag_flushall(void);
#pragma weak vtag_flushall_uctxs
void	vtag_flushall_uctxs(void);
void	vtag_flushpage_tl1(uint64_t addr, uint64_t sfmmup);
void	vtag_flush_pgcnt_tl1(uint64_t addr, uint64_t sfmmup_pgcnt);
void	vtag_flushall_tl1(uint64_t dummy1, uint64_t dummy2);

/*
 * virtual alias flushes (virtual address caches)
 */
void	vac_flushpage(pfn_t pf, int color);
void	vac_flushpage_tl1(uint64_t pf, uint64_t color);
void	vac_flushcolor(int color, pfn_t pf);
void	vac_flushcolor_tl1(uint64_t color, uint64_t dummy);

/*
 * sending x-calls
 */
void	init_mondo(xcfunc_t *func, uint64_t arg1, uint64_t arg2);
void	send_one_mondo(int cpuid);
#ifdef _MACHDEP
void	send_mondo_set(cpuset_t set);
#endif

/*
 * flag to support optimal dtlb pagesize setting, for ISM and mpss, to support
 * cpus with non-fully-associative dtlbs. Page size is stored in hat sfmmu_cext
 */
extern uint_t cpu_impl_dual_pgsz;

/*
 * flush instruction cache if needed
 */
void	flush_instr_mem(caddr_t addr, size_t len);

/*
 * flush instruction and data caches
 */
void	kdi_flush_caches(void);

/*
 * take pending fp traps if fpq present
 * this function is also defined in fpusystm.h
 */
void	syncfpu(void);

/*
 * Cpu-specific error and ecache handling routines
 */
void	ce_err(void);
void	ce_err_tl1(void);
void	async_err(void);
void	cpu_flush_ecache(void);
void	cpu_disable_errors(void);
/* It could be removed later if prom enables errors */
void	cpu_enable_errors(void);
void	cpu_faulted_enter(struct cpu *);
void	cpu_faulted_exit(struct cpu *);
void	cpu_ce_count_unum(struct async_flt *ecc, int len, char *unum);
void	cpu_ce_scrub_mem_err(struct async_flt *, boolean_t);
void	cpu_ce_log_err(struct async_flt *, errorq_elem_t *);
void	cpu_ue_log_err(struct async_flt *);
int	cpu_aflt_size(void);
void	cpu_async_panic_callb(void);
void	cpu_check_allcpus(struct async_flt *aflt);
int	cpu_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp);

/* Interfaces for getting memory-related information */
int	cpu_get_mem_name(uint64_t synd, uint64_t *afsr, uint64_t afar,
	    char *buf, int buflen, int *lenp);
int	cpu_get_mem_info(uint64_t synd, uint64_t afar,
	    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
	    int *segsp, int *banksp, int *mcidp);
size_t	cpu_get_name_bufsize();
extern int cpu_get_mem_addr(char *unum, char *sid, uint64_t offset,
	    uint64_t *addrp);

/*
 * FMA Event Memory Routines
 *
 * The following routines are used by FMA Event generators to retrieve data
 * to store in memory ereports.  These routines may call through to platform-
 * specific code and/or drivers, and can be called from passive context, low-
 * level interrupt context, or panic context.  They may grab adaptive locks,
 * but should not be allocating new data structures or calling cv_wait().
 */
int	cpu_get_mem_unum(int synd_status, ushort_t synd, uint64_t afsr,
	    uint64_t afar, int cpuid, int flt_in_memory,
	    ushort_t flt_status, char *buf, int buflen, int *lenp);
int	cpu_get_mem_unum_aflt(int synd_status, struct async_flt *aflt,
	    char *buf, int buflen, int *lenp);
extern int cpu_get_mem_sid(char *unum, char *buf, int buflen, int *lenp);
extern int cpu_get_mem_offset(uint64_t flt_addr, uint64_t *offp);

void	read_ecc_data(struct async_flt *ecc, short verbose, short ce_err);
/* add clr_datapath to aviod lint warning for ac_test.c temporarily */
void	clr_datapath(void);

#pragma weak itlb_parity_trap
void itlb_parity_trap(void);

#pragma weak dtlb_parity_trap
void dtlb_parity_trap(void);

/*
 * FMA Protocol and error handling support routines
 */

void cpu_ereport_post(struct async_flt *);
void cpu_run_bus_error_handlers(struct async_flt *, int);
void cpu_errorq_dispatch(char *, void *, size_t, errorq_t *, uint_t);

/*
 * retrieve information from the specified tlb entry. these functions are
 * called by "cpr" module
 */
void	itlb_rd_entry(uint_t entry, tte_t *tte, uint64_t *va_tag);
void	dtlb_rd_entry(uint_t entry, tte_t *tte, uint64_t *va_tag);

/*
 * this symbol appears as a second label for vtag_flushall
 * only for cpus that implement DEMAP_ALL_TYPE
 */
#pragma	weak demap_all

/*
 * change cpu speed
 */
void	cpu_change_speed(uint64_t divisor, uint64_t arg2);

/*
 * ecache scrub operations
 */
void cpu_init_cache_scrub(void);
void cpu_idle_ecache_scrub(struct cpu *);
void cpu_busy_ecache_scrub(struct cpu *);

/*
 * Cpu private initialize/uninitialize, including ecache scrubber.
 */
void	cpu_init_private(struct cpu *);
void	cpu_uninit_private(struct cpu *);

#pragma weak cpu_mp_init
void    cpu_mp_init(void);

#pragma weak cpu_feature_init
void    cpu_feature_init(void);

#pragma weak cpu_early_feature_init
void    cpu_early_feature_init(void);

#pragma weak cpu_error_init
void	cpu_error_init(int);

/*
 * clock/tick register operations
 */
void	cpu_clearticknpt(void);
void	cpu_init_tick_freq(void);

/*
 * stick synchronization
 */
void	sticksync_slave(void);
void	sticksync_master(void);

/*
 * flags for calling cpu_check_ce
 */
#define	SCRUBBER_CEEN_CHECK		0
#define	TIMEOUT_CEEN_CHECK		1

/*
 * Check for Correctable Errors that may have occurred
 * while CEEN was disabled.
 */
void cpu_check_ce(int, uint64_t, caddr_t, uint_t);

/* initialize kernel context pgsz codes in DMMU primary context register */
void mmu_init_kernel_pgsz(struct hat *hat);

/* get large page size for kernel heap */
size_t mmu_get_kernel_lpsize(size_t value);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CPU_MODULE_H */
