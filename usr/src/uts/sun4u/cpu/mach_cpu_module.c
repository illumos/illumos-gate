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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpu_module.h>
#include <vm/page.h>
#include <vm/seg_map.h>

void
cpu_fiximp(pnode_t dnode)
{}

void
ce_err(void)
{}

void
ce_err_tl1(void)
{}

void
async_err(void)
{}

void
cpu_flush_ecache(void)
{}

void
cpu_disable_errors(void)
{}

/* It could be removed later if prom enables error handling */
void
cpu_enable_errors(void)
{}

/*ARGSUSED*/
void
cpu_faulted_enter(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_faulted_exit(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_ce_count_unum(struct async_flt *ecc, int len, char *unum)
{}

/*ARGSUSED*/
void
cpu_ce_scrub_mem_err(struct async_flt *ecc, boolean_t triedcpulogout)
{}

/*ARGSUSED*/
void
cpu_ce_log_err(struct async_flt *ecc, errorq_elem_t *eqep)
{}

/*ARGSUSED*/
void
cpu_ue_log_err(struct async_flt *ecc)
{}

/*ARGSUSED*/
int
ce_scrub_xdiag_recirc(struct async_flt *aflt, errorq_t *eqp,
    errorq_elem_t *eqep, size_t afltoffset)
{ return (0); }

/*ARGSUSED*/
char *
flt_to_error_type(struct async_flt *aflt)
{ return (NULL); }

int
cpu_aflt_size(void)
{ return (0); }

void
cpu_async_panic_callb(void)
{}

/*ARGSUSED*/
void
cpu_check_allcpus(struct async_flt *aflt)
{}

/*ARGSUSED*/
int
cpu_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{ return (ENOTSUP); }

/*ARGSUSED*/
int
cpu_get_mem_offset(uint64_t flt_addr, uint64_t *offp)
{ return (ENOTSUP); }

/*ARGSUSED*/
int
cpu_get_mem_addr(char *unum, char *sid, uint64_t offset,
    uint64_t *addrp)
{ return (ENOTSUP); }

/*ARGSUSED*/
int
cpu_get_mem_unum(int synd_stat, ushort_t synd, uint64_t afsr, uint64_t afar,
    int cpuid, int flt_in_memory, ushort_t flt_status, char *buf,
    int buflen, int *lenp)
{ return (ENOTSUP); }

/*ARGSUSED*/
int
cpu_get_mem_unum_aflt(int synd_stat, struct async_flt *aflt,
    char *buf, int buflen, int *lenp)
{ return (ENOTSUP); }

/*ARGSUSED*/
int
cpu_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{ return (ENOTSUP); }

/*ARGSUSED*/
int
cpu_get_mem_name(uint64_t synd, uint64_t *afsr, uint64_t afar,
    char *buf, int buflen, int *lenp)
{ return (ENOTSUP); }

/*ARGSUSED*/
size_t
cpu_get_name_bufsize()
{ return (0); }

/*ARGSUSED*/
int
cpu_get_mem_info(uint64_t synd, uint64_t afar,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp)
{ return (ENOTSUP); }

/*ARGSUSED*/
void
cpu_ereport_post(struct async_flt *aflt)
{}

/*ARGSUSED*/
void
cpu_run_bus_error_handlers(struct async_flt *aflt, int expected)
{}

void
cpu_errorq_dispatch(char *error_class, void *payload, size_t payload_sz,
    errorq_t *eqp, uint_t flag)
{}

void
clr_datapath(void)
{}

/*ARGSUSED*/
void
read_ecc_data(struct async_flt *ecc, short verbose, short ce_err)
{}

/*ARGSUSED*/
void
itlb_rd_entry(uint_t entry, tte_t *tte, uint64_t *va_tag)
{}

/*ARGSUSED*/
void
dtlb_rd_entry(uint_t entry, tte_t *tte, uint64_t *va_tag)
{}

/*
 * tick operations
 */

void
cpu_clearticknpt(void)
{ }

/*
 * Ecache scrub operations
 */
void
cpu_init_cache_scrub(void)
{}

/*ARGSUSED*/
void
cpu_busy_ecache_scrub(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_idle_ecache_scrub(struct cpu *cp)
{}

/* ARGSUSED */
void
cpu_check_ce(int flag, uint64_t pa, caddr_t va, uint_t bpp)
{}

/* ARGSUSED */
void
prefetch_page_w(void *pp)
{
#define	ECACHE_SUBBLOCKS_PER_PAGE	2
#define	ECACHE_SUBBLOCK_SIZE_BYTES	64
#define	ECACHE_PAGE_BYTE_MAX	\
	(ECACHE_SUBBLOCKS_PER_PAGE*ECACHE_SUBBLOCK_SIZE_BYTES+1)

	/*
	 * The following line is intended to cause an error
	 * whenever the sun4u page_t grows beyond 128
	 * bytes.
	 *
	 * If you get an error here, you'll need to change
	 * the 'prefetch_page_w' assembly language code
	 * (see also prefetch_page_w prologue comment)
	 */
	/*LINTED*/
	volatile int garbage[ECACHE_PAGE_BYTE_MAX - sizeof (page_t)];
}

/* ARGSUSED */
void
prefetch_page_r(void *pp)
{
#define	ECACHE_SUBBLOCKS_PER_PAGE	2
#define	ECACHE_SUBBLOCK_SIZE_BYTES	64
#define	ECACHE_PAGE_BYTE_MAX	\
	(ECACHE_SUBBLOCKS_PER_PAGE*ECACHE_SUBBLOCK_SIZE_BYTES+1)

	/*
	 * The following line is intended to cause an error
	 * whenever the sun4u page_t grows beyond 128
	 * bytes.
	 *
	 * If you get an error here, you'll need to change
	 * the 'prefetch_page_r' assembly language code
	 * (see also prefetch_page_w prologue comment)
	 */
	/*LINTED*/
	volatile int garbage[ECACHE_PAGE_BYTE_MAX - sizeof (page_t)];
}


#ifdef	SEGKPM_SUPPORT
#define	SMAP_SIZE	80
#else
#define	SMAP_SIZE	56
#endif

/* ARGSUSED */
void
prefetch_smap_w(void *smp)
{

	/*
	 * The following lines are intended to cause an error
	 * whenever the smap object size changes from the current
	 * size of 48 bytes.  If you get an error here, you'll
	 * need to update the code in the 'prefetch_smap_w' assembly
	 * language code.
	 */
	/*LINTED*/
	volatile int smap_size_changed [SMAP_SIZE - sizeof (struct smap) + 1];
	volatile int smap_size_changed2 [sizeof (struct smap) - SMAP_SIZE + 1];
}

void
kdi_flush_caches(void)
{}

/*ARGSUSED*/
void
mmu_init_kernel_pgsz(struct hat *hat)
{
}

size_t
mmu_get_kernel_lpsize(size_t value)
{
	return (value);
}
