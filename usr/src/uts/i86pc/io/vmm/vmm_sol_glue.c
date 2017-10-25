/*
 * Copyright (c) 2004 Poul-Henning Kamp
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/sys/kern/subr_unit.c 255057 2013-08-30 07:37:45Z kib $
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/archsystm.h>
#include <sys/cpuset.h>
#include <sys/fp.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/spl.h>
#include <sys/systm.h>
#include <sys/ddidmareq.h>
#include <sys/id_space.h>
#include <sys/psm_defs.h>
#include <sys/smp_impldefs.h>

#include <machine/cpufunc.h>
#include <machine/fpu.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <sys/vmm_impl.h>

#include <vm/as.h>
#include <vm/seg_kmem.h>


u_char const bin2bcd_data[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99
};

vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	pfn_t	pfn;

	/*
	 * Since hat_getpfnum() may block on an htable mutex, this is not at
	 * all safe to run from a critical_enter/kpreempt_disable context.
	 * The FreeBSD analog does not have the same locking constraints, so
	 * close attention must be paid wherever this is called.
	 */
	ASSERT(curthread->t_preempt == 0);

	pfn = hat_getpfnum(kas.a_hat, (caddr_t)va);
	ASSERT(pfn != PFN_INVALID);
	return (pfn << PAGE_SHIFT) | ((uintptr_t)va & PAGE_MASK);
}

int
cpusetobj_ffs(const cpuset_t *set)
{
#if	CPUSET_WORDS > 1
	int	i, cbit;

	cbit = 0;
	for (i = 0; i < CPUSET_WORDS; i++) {
		if (set->cpub[i] != 0) {
			cbit = ffsl(set->cpub[i]);
			cbit += i * sizeof (set->cpub[0]);
			break;
		}
	}
	return (cbit);
#else
	return (ffsl(*set));
#endif
}

void
smp_rendezvous(void (* setup_func)(void *), void (* action_func)(void *),
    void (* teardown_func)(void *), void *arg)
{
	cpuset_t cpuset;

	ASSERT(setup_func == NULL);
	ASSERT(teardown_func == NULL);

	CPUSET_ALL(cpuset);
	xc_sync((xc_arg_t)arg, 0, 0, CPUSET2BV(cpuset), (xc_func_t)action_func);
}

struct kmem_item {
	void			*addr;
	size_t			size;
	LIST_ENTRY(kmem_item)	next;
};
static kmutex_t kmem_items_lock;
static LIST_HEAD(, kmem_item) kmem_items;

void *
malloc(unsigned long size, struct malloc_type *mtp, int flags)
{
	void			*p;
	struct kmem_item	*i;
	int			kmem_flag = KM_SLEEP;

	if (flags & M_NOWAIT)
		kmem_flag = KM_NOSLEEP;

	if (flags & M_ZERO) {
		p = kmem_zalloc(size + sizeof (struct kmem_item), kmem_flag);
	} else {
		p = kmem_alloc(size + sizeof (struct kmem_item), kmem_flag);
	}

	mutex_enter(&kmem_items_lock);
	i = p + size;
	i->addr = p;
	i->size = size;

	LIST_INSERT_HEAD(&kmem_items, i, next);
	mutex_exit(&kmem_items_lock);

	return (p);
}

void
free(void *addr, struct malloc_type *mtp)
{
	struct kmem_item	*i;

	mutex_enter(&kmem_items_lock);
	LIST_FOREACH(i, &kmem_items, next) {
		if (i->addr == addr)
			break;
	}
	ASSERT(i != NULL);
	LIST_REMOVE(i, next);
	mutex_exit(&kmem_items_lock);

	kmem_free(addr, i->size + sizeof (struct kmem_item));
}

extern void *contig_alloc(size_t, ddi_dma_attr_t *, uintptr_t, int);
extern void contig_free(void *, size_t);

void *
contigmalloc(unsigned long size, struct malloc_type *type, int flags,
    vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
    vm_paddr_t boundary)
{
	ddi_dma_attr_t attr = {
		/* Using fastboot_dma_attr as a guide... */
		DMA_ATTR_V0,
		low,			/* dma_attr_addr_lo */
		high,			/* dma_attr_addr_hi */
		0x00000000FFFFFFFFULL,	/* dma_attr_count_max */
		alignment,		/* dma_attr_align */
		1,			/* dma_attr_burstsize */
		1,			/* dma_attr_minxfer */
		0x00000000FFFFFFFFULL,	/* dma_attr_maxxfer */
		0x00000000FFFFFFFFULL,	/* dma_attr_seg: any */
		1,			/* dma_attr_sgllen */
		alignment,		/* dma_attr_granular */
		0,			/* dma_attr_flags */
	};
	int cansleep = (flags & M_WAITOK);
	void *result;

	ASSERT(alignment == PAGESIZE);

	result = contig_alloc((size_t)size, &attr, alignment, cansleep);

	if (result != NULL && (flags & M_ZERO) != 0) {
		bzero(result, size);
	}
	return (result);
}

void
contigfree(void *addr, unsigned long size, struct malloc_type *type)
{
	contig_free(addr, size);
}

void
mtx_init(struct mtx *mtx, char *name, const char *type_name, int opts)
{
	if (opts & MTX_SPIN) {
		mutex_init(&mtx->m, name, MUTEX_SPIN,
		    (ddi_iblock_cookie_t)ipltospl(DISP_LEVEL));
	} else {
		mutex_init(&mtx->m, name, MUTEX_DRIVER, NULL);
	}
}

void
mtx_destroy(struct mtx *mtx)
{
	mutex_destroy(&mtx->m);
}

void
critical_enter(void)
{
	kpreempt_disable();
}

void
critical_exit(void)
{
	kpreempt_enable();
}

struct unrhdr;
static kmutex_t unr_lock;
static uint_t unr_idx;

/*
 * Allocate a new unrheader set.
 *
 * Highest and lowest valid values given as parameters.
 */
struct unrhdr *
new_unrhdr(int low, int high, struct mtx *mtx)
{
	id_space_t *ids;
	char name[] = "vmm_unr_00000000";

	ASSERT(mtx == NULL);

	mutex_enter(&unr_lock);
	/* Get a unique name for the id space */
	(void) snprintf(name, sizeof (name), "vmm_unr_%08X", unr_idx);
	VERIFY(++unr_idx != UINT_MAX);
	mutex_exit(&unr_lock);

	ids = id_space_create(name, low, high);

	return ((struct unrhdr *)ids);
}

void
delete_unrhdr(struct unrhdr *uh)
{
	id_space_t *ids = (id_space_t *)uh;

	id_space_destroy(ids);
}

int
alloc_unr(struct unrhdr *uh)
{
	id_space_t *ids = (id_space_t *)uh;

	return (id_alloc(ids));
}

void
free_unr(struct unrhdr *uh, u_int item)
{
	id_space_t *ids = (id_space_t *)uh;

	id_free(ids, item);
}


static void
vmm_glue_callout_handler(void *arg)
{
	struct callout *c = arg;

	c->c_flags &= ~CALLOUT_PENDING;
	if (c->c_flags & CALLOUT_ACTIVE) {
		(c->c_func)(c->c_arg);
	}
}

void
vmm_glue_callout_init(struct callout *c, int mpsafe)
{
	cyc_handler_t	hdlr;
	cyc_time_t	when;

	hdlr.cyh_level = CY_LOW_LEVEL;
	hdlr.cyh_func = vmm_glue_callout_handler;
	hdlr.cyh_arg = c;
	when.cyt_when = CY_INFINITY;
	when.cyt_interval = CY_INFINITY;

	mutex_enter(&cpu_lock);
#if 0
	/*
	 * XXXJOY: according to the freebsd sources, callouts do not begin
	 * their life in the ACTIVE state.
	 */
	c->c_flags |= CALLOUT_ACTIVE;
#else
	bzero(c, sizeof (*c));
#endif
	c->c_cyc_id = cyclic_add(&hdlr, &when);
	mutex_exit(&cpu_lock);
}

static __inline hrtime_t
sbttohrtime(sbintime_t sbt)
{
	return (((sbt >> 32) * NANOSEC) +
	    (((uint64_t)NANOSEC * (uint32_t)sbt) >> 32));
}

int
vmm_glue_callout_reset_sbt(struct callout *c, sbintime_t sbt, sbintime_t pr,
    void (*func)(void *), void *arg, int flags)
{
	hrtime_t target = sbttohrtime(sbt);

	ASSERT(c->c_cyc_id != CYCLIC_NONE);

	c->c_func = func;
	c->c_arg = arg;
	c->c_flags |= (CALLOUT_ACTIVE | CALLOUT_PENDING);

	if (flags & C_ABSOLUTE) {
		cyclic_reprogram(c->c_cyc_id, target);
	} else {
		cyclic_reprogram(c->c_cyc_id, target + gethrtime());
	}

	return (0);
}

int
vmm_glue_callout_stop(struct callout *c)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);
	cyclic_reprogram(c->c_cyc_id, CY_INFINITY);
	c->c_flags &= ~(CALLOUT_ACTIVE | CALLOUT_PENDING);

	return (0);
}

int
vmm_glue_callout_drain(struct callout *c)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);
	mutex_enter(&cpu_lock);
	cyclic_remove(c->c_cyc_id);
	c->c_cyc_id = CYCLIC_NONE;
	c->c_flags &= ~(CALLOUT_ACTIVE | CALLOUT_PENDING);
	mutex_exit(&cpu_lock);

	return (0);
}

void
ipi_cpu(int cpu, u_int ipi)
{
	/*
	 * This was previously implemented as an invocation of asynchronous
	 * no-op crosscalls to interrupt the target CPU.  Since even nowait
	 * crosscalls can block in certain circumstances, a direct poke_cpu()
	 * is safer when called from delicate contexts.
	 */
	poke_cpu(cpu);
}

u_int	cpu_high;		/* Highest arg to CPUID */
u_int	cpu_exthigh;		/* Highest arg to extended CPUID */
u_int	cpu_id;			/* Stepping ID */
char	cpu_vendor[20];		/* CPU Origin code */

static void
vmm_cpuid_init(void)
{
	u_int regs[4];

	do_cpuid(0, regs);
	cpu_high = regs[0];
	((u_int *)&cpu_vendor)[0] = regs[1];
	((u_int *)&cpu_vendor)[1] = regs[3];
	((u_int *)&cpu_vendor)[2] = regs[2];
	cpu_vendor[12] = '\0';

	do_cpuid(1, regs);
	cpu_id = regs[0];

	do_cpuid(0x80000000, regs);
	cpu_exthigh = regs[0];
}

struct savefpu {
	fpu_ctx_t	fsa_fp_ctx;
};

static vmem_t *fpu_save_area_arena;

static void
fpu_save_area_init(void)
{
	fpu_save_area_arena = vmem_create("fpu_save_area",
	    NULL, 0, XSAVE_AREA_ALIGN,
	    segkmem_alloc, segkmem_free, heap_arena, 0, VM_BESTFIT | VM_SLEEP);
}

static void
fpu_save_area_cleanup(void)
{
	vmem_destroy(fpu_save_area_arena);
}

struct savefpu *
fpu_save_area_alloc(void)
{
	struct savefpu *fsa = vmem_alloc(fpu_save_area_arena,
	    sizeof (struct savefpu), VM_SLEEP);

	bzero(fsa, sizeof (struct savefpu));
	fsa->fsa_fp_ctx.fpu_regs.kfpu_u.kfpu_generic =
	    kmem_cache_alloc(fpsave_cachep, KM_SLEEP);

	return (fsa);
}

void
fpu_save_area_free(struct savefpu *fsa)
{
	kmem_cache_free(fpsave_cachep,
	    fsa->fsa_fp_ctx.fpu_regs.kfpu_u.kfpu_generic);
	vmem_free(fpu_save_area_arena, fsa, sizeof (struct savefpu));
}

void
fpu_save_area_reset(struct savefpu *fsa)
{
	extern const struct fxsave_state sse_initial;
	extern const struct xsave_state avx_initial;
	struct fpu_ctx *fp;
	struct fxsave_state *fx;
	struct xsave_state *xs;

	fp = &fsa->fsa_fp_ctx;

	fp->fpu_regs.kfpu_status = 0;
	fp->fpu_regs.kfpu_xstatus = 0;

	switch (fp_save_mech) {
	case FP_FXSAVE:
		fx = fp->fpu_regs.kfpu_u.kfpu_fx;
		bcopy(&sse_initial, fx, sizeof (*fx));
		break;
	case FP_XSAVE:
		fp->fpu_xsave_mask = (XFEATURE_ENABLED_X87 |
		    XFEATURE_ENABLED_SSE | XFEATURE_ENABLED_AVX);
		xs = fp->fpu_regs.kfpu_u.kfpu_xs;
		bcopy(&avx_initial, xs, sizeof (*xs));
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}
}

void
fpuexit(kthread_t *td)
{
	fp_save(&curthread->t_lwp->lwp_pcb.pcb_fpu);
}

static __inline void
vmm_fxrstor(struct fxsave_state *addr)
{
	__asm __volatile("fxrstor %0" : : "m" (*(addr)));
}

static __inline void
vmm_fxsave(struct fxsave_state *addr)
{
	__asm __volatile("fxsave %0" : "=m" (*(addr)));
}

static __inline void
vmm_xrstor(struct xsave_state *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xrstor %0" : : "m" (*addr), "a" (low), "d" (hi));
}

static __inline void
vmm_xsave(struct xsave_state *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xsave %0" : "=m" (*addr) : "a" (low), "d" (hi) :
	    "memory");
}

void
fpurestore(void *arg)
{
	struct savefpu *fsa = (struct savefpu *)arg;
	struct fpu_ctx *fp;

	fp = &fsa->fsa_fp_ctx;

	switch (fp_save_mech) {
	case FP_FXSAVE:
		vmm_fxrstor(fp->fpu_regs.kfpu_u.kfpu_fx);
		break;
	case FP_XSAVE:
		vmm_xrstor(fp->fpu_regs.kfpu_u.kfpu_xs, fp->fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}
}

void
fpusave(void *arg)
{
	struct savefpu *fsa = (struct savefpu *)arg;
	struct fpu_ctx *fp;

	fp = &fsa->fsa_fp_ctx;

	switch (fp_save_mech) {
	case FP_FXSAVE:
		vmm_fxsave(fp->fpu_regs.kfpu_u.kfpu_fx);
		break;
	case FP_XSAVE:
		vmm_xsave(fp->fpu_regs.kfpu_u.kfpu_xs, fp->fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}
}

void
vmm_sol_glue_init(void)
{
	vmm_cpuid_init();
	fpu_save_area_init();
	unr_idx = 0;
}

void
vmm_sol_glue_cleanup(void)
{
	fpu_save_area_cleanup();
}

int idtvec_justreturn;

int
lapic_ipi_alloc(int *id)
{
	/* Only poke_cpu() equivalent is supported */
	VERIFY(id == &idtvec_justreturn);

	/*
	 * This is only used by VMX to allocate a do-nothing vector for
	 * interrupting other running CPUs.  The cached poke_cpu() vector
	 * as an "allocation" is perfect for this.
	 */
	if (psm_cached_ipivect != NULL) {
		return (psm_cached_ipivect(XC_CPUPOKE_PIL, PSM_INTR_POKE));
	}

	return (-1);
}

void
lapic_ipi_free(int vec)
{
	VERIFY(vec > 0);

	/*
	 * A cached vector was used in the first place.
	 * No deallocation is necessary
	 */
	return;
}


/* From FreeBSD's sys/kern/subr_clock.c */

/*-
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1982, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: Utah $Hdr: clock.c 1.18 91/01/21$
 *	from: @(#)clock.c	8.2 (Berkeley) 1/12/94
 *	from: NetBSD: clock_subr.c,v 1.6 2001/07/07 17:04:02 thorpej Exp
 *	and
 *	from: src/sys/i386/isa/clock.c,v 1.176 2001/09/04
 */

#include <sys/clock.h>

/*--------------------------------------------------------------------*
 * Generic routines to convert between a POSIX date
 * (seconds since 1/1/1970) and yr/mo/day/hr/min/sec
 * Derived from NetBSD arch/hp300/hp300/clock.c
 */

#define	FEBRUARY	2
#define	days_in_year(y) 	(leapyear(y) ? 366 : 365)
#define	days_in_month(y, m) \
	(month_days[(m) - 1] + (m == FEBRUARY ? leapyear(y) : 0))
/* Day of week. Days are counted from 1/1/1970, which was a Thursday */
#define	day_of_week(days)	(((days) + 4) % 7)

static const int month_days[12] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};


/*
 * This inline avoids some unnecessary modulo operations
 * as compared with the usual macro:
 *   ( ((year % 4) == 0 &&
 *      (year % 100) != 0) ||
 *     ((year % 400) == 0) )
 * It is otherwise equivalent.
 */
static int
leapyear(int year)
{
	int rv = 0;

	if ((year & 3) == 0) {
		rv = 1;
		if ((year % 100) == 0) {
			rv = 0;
			if ((year % 400) == 0)
				rv = 1;
		}
	}
	return (rv);
}

int
clock_ct_to_ts(struct clocktime *ct, struct timespec *ts)
{
	int i, year, days;

	year = ct->year;

#ifdef __FreeBSD__
	if (ct_debug) {
		printf("ct_to_ts(");
		print_ct(ct);
		printf(")");
	}
#endif

	/* Sanity checks. */
	if (ct->mon < 1 || ct->mon > 12 || ct->day < 1 ||
	    ct->day > days_in_month(year, ct->mon) ||
	    ct->hour > 23 ||  ct->min > 59 || ct->sec > 59 ||
	    (sizeof(time_t) == 4 && year > 2037)) {	/* time_t overflow */
#ifdef __FreeBSD__
		if (ct_debug)
			printf(" = EINVAL\n");
#endif
		return (EINVAL);
	}

	/*
	 * Compute days since start of time
	 * First from years, then from months.
	 */
	days = 0;
	for (i = POSIX_BASE_YEAR; i < year; i++)
		days += days_in_year(i);

	/* Months */
	for (i = 1; i < ct->mon; i++)
	  	days += days_in_month(year, i);
	days += (ct->day - 1);

	ts->tv_sec = (((time_t)days * 24 + ct->hour) * 60 + ct->min) * 60 +
	    ct->sec;
	ts->tv_nsec = ct->nsec;

#ifdef __FreeBSD__
	if (ct_debug)
		printf(" = %ld.%09ld\n", (long)ts->tv_sec, (long)ts->tv_nsec);
#endif
	return (0);
}

void
clock_ts_to_ct(struct timespec *ts, struct clocktime *ct)
{
	int i, year, days;
	time_t rsec;	/* remainder seconds */
	time_t secs;

	secs = ts->tv_sec;
	days = secs / SECDAY;
	rsec = secs % SECDAY;

	ct->dow = day_of_week(days);

	/* Subtract out whole years, counting them in i. */
	for (year = POSIX_BASE_YEAR; days >= days_in_year(year); year++)
		days -= days_in_year(year);
	ct->year = year;

	/* Subtract out whole months, counting them in i. */
	for (i = 1; days >= days_in_month(year, i); i++)
		days -= days_in_month(year, i);
	ct->mon = i;

	/* Days are what is left over (+1) from all that. */
	ct->day = days + 1;

	/* Hours, minutes, seconds are easy */
	ct->hour = rsec / 3600;
	rsec = rsec % 3600;
	ct->min  = rsec / 60;
	rsec = rsec % 60;
	ct->sec  = rsec;
	ct->nsec = ts->tv_nsec;
#ifdef __FreeBSD__
	if (ct_debug) {
		printf("ts_to_ct(%ld.%09ld) = ",
		    (long)ts->tv_sec, (long)ts->tv_nsec);
		print_ct(ct);
		printf("\n");
	}
#endif
}
