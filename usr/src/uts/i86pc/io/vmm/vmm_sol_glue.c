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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
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
#include <sys/modhash.h>
#include <sys/hma.h>

#include <sys/x86_archext.h>

#include <machine/cpufunc.h>
#include <machine/fpu.h>
#include <machine/md_var.h>
#include <machine/pmap.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <sys/vmm_impl.h>
#include <sys/kernel.h>

#include <vm/as.h>
#include <vm/seg_kmem.h>

SET_DECLARE(sysinit_set, struct sysinit);

void
sysinit(void)
{
	struct sysinit **si;

	SET_FOREACH(si, sysinit_set)
		(*si)->func((*si)->data);
}

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

void
pmap_invalidate_cache(void)
{
	cpuset_t cpuset;

	kpreempt_disable();
	cpuset_all_but(&cpuset, CPU->cpu_id);
	xc_call((xc_arg_t)NULL, (xc_arg_t)NULL, (xc_arg_t)NULL,
	    CPUSET2BV(cpuset), (xc_func_t)invalidate_cache);
	invalidate_cache();
	kpreempt_enable();
}

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
	uint_t large, small;

	/*
	 * Rather than reaching into the cpuset_t ourselves, leave that task to
	 * cpuset_bounds().  The simplicity is worth the extra wasted work to
	 * find the upper bound.
	 */
	cpuset_bounds(set, &small, &large);

	if (small == CPUSET_NOTINSET) {
		/* The FreeBSD version returns 0 if it find nothing */
		return (0);
	}

	ASSERT3U(small, <=, INT_MAX);

	/* Least significant bit index starts at 1 for valid results */
	return (small + 1);
}

struct kmem_item {
	void			*addr;
	size_t			size;
};
static kmutex_t kmem_items_lock;

static mod_hash_t *vmm_alloc_hash;
uint_t vmm_alloc_hash_nchains = 16381;
uint_t vmm_alloc_hash_size = PAGESIZE;

static void
vmm_alloc_hash_valdtor(mod_hash_val_t val)
{
	struct kmem_item *i = (struct kmem_item *)val;

	kmem_free(i->addr, i->size);
	kmem_free(i, sizeof (struct kmem_item));
}

static void
vmm_alloc_init(void)
{
	vmm_alloc_hash = mod_hash_create_ptrhash("vmm_alloc_hash",
	    vmm_alloc_hash_nchains, vmm_alloc_hash_valdtor,
	    vmm_alloc_hash_size);

	VERIFY(vmm_alloc_hash != NULL);
}

static uint_t
vmm_alloc_check(mod_hash_key_t key, mod_hash_val_t *val, void *unused)
{
	struct kmem_item *i = (struct kmem_item *)val;

	cmn_err(CE_PANIC, "!vmm_alloc_check: hash not empty: %p, %d", i->addr,
	    i->size);

	return (MH_WALK_TERMINATE);
}

static void
vmm_alloc_cleanup(void)
{
	mod_hash_walk(vmm_alloc_hash, vmm_alloc_check, NULL);
	mod_hash_destroy_ptrhash(vmm_alloc_hash);
}

void *
malloc(unsigned long size, struct malloc_type *mtp, int flags)
{
	void			*p;
	struct kmem_item	*i;
	int			kmem_flag = KM_SLEEP;

	if (flags & M_NOWAIT)
		kmem_flag = KM_NOSLEEP;

	if (flags & M_ZERO) {
		p = kmem_zalloc(size, kmem_flag);
	} else {
		p = kmem_alloc(size, kmem_flag);
	}

	if (p == NULL)
		return (NULL);

	i = kmem_zalloc(sizeof (struct kmem_item), kmem_flag);

	if (i == NULL) {
		kmem_free(p, size);
		return (NULL);
	}

	mutex_enter(&kmem_items_lock);
	i->addr = p;
	i->size = size;

	VERIFY(mod_hash_insert(vmm_alloc_hash,
	    (mod_hash_key_t)PHYS_TO_DMAP(vtophys(p)), (mod_hash_val_t)i) == 0);

	mutex_exit(&kmem_items_lock);

	return (p);
}

void
free(void *addr, struct malloc_type *mtp)
{
	mutex_enter(&kmem_items_lock);
	VERIFY(mod_hash_destroy(vmm_alloc_hash,
	    (mod_hash_key_t)PHYS_TO_DMAP(vtophys(addr))) == 0);
	mutex_exit(&kmem_items_lock);
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
	/*
	 * Requests that a mutex be initialized to the MTX_SPIN type are
	 * ignored.  The limitations which may have required spinlocks on
	 * FreeBSD do not apply to how bhyve has been structured here.
	 *
	 * Adaptive mutexes are required to avoid deadlocks when certain
	 * cyclics behavior interacts with interrupts and contended locks.
	 */
	mutex_init(&mtx->m, name, MUTEX_ADAPTIVE, NULL);
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


static void
vmm_glue_callout_handler(void *arg)
{
	struct callout *c = arg;

	if (callout_active(c)) {
		/*
		 * Record the handler fire time so that callout_pending() is
		 * able to detect if the callout becomes rescheduled during the
		 * course of the handler.
		 */
		c->c_fired = gethrtime();
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
	bzero(c, sizeof (*c));

	mutex_enter(&cpu_lock);
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

	if ((flags & C_ABSOLUTE) == 0) {
		target += gethrtime();
	}

	c->c_func = func;
	c->c_arg = arg;
	c->c_target = target;
	cyclic_reprogram(c->c_cyc_id, target);

	return (0);
}

int
vmm_glue_callout_stop(struct callout *c)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);

	c->c_target = 0;
	cyclic_reprogram(c->c_cyc_id, CY_INFINITY);

	return (0);
}

int
vmm_glue_callout_drain(struct callout *c)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);

	c->c_target = 0;
	mutex_enter(&cpu_lock);
	cyclic_remove(c->c_cyc_id);
	c->c_cyc_id = CYCLIC_NONE;
	mutex_exit(&cpu_lock);

	return (0);
}

void
vmm_glue_callout_localize(struct callout *c)
{
	mutex_enter(&cpu_lock);
	cyclic_move_here(c->c_cyc_id);
	mutex_exit(&cpu_lock);
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

/*
 * FreeBSD uses the struct savefpu for managing the FPU state. That is mimicked
 * by our hypervisor multiplexor framework structure.
 */
struct savefpu *
fpu_save_area_alloc(void)
{
	return ((struct savefpu *)hma_fpu_alloc(KM_SLEEP));
}

void
fpu_save_area_free(struct savefpu *fsa)
{
	hma_fpu_t *fpu = (hma_fpu_t *)fsa;
	hma_fpu_free(fpu);
}

void
fpu_save_area_reset(struct savefpu *fsa)
{
	hma_fpu_t *fpu = (hma_fpu_t *)fsa;
	hma_fpu_init(fpu);
}

/*
 * This glue function is supposed to save the host's FPU state. This is always
 * paired in the general bhyve code with a call to fpusave. Therefore, we treat
 * this as a nop and do all the work in fpusave(), which will have the context
 * argument that we want anyways.
 */
void
fpuexit(kthread_t *td)
{
}

/*
 * This glue function is supposed to restore the guest's FPU state from the save
 * area back to the host. In FreeBSD, it is assumed that the host state has
 * already been saved by a call to fpuexit(); however, we do both here.
 */
void
fpurestore(void *arg)
{
	hma_fpu_t *fpu = arg;

	hma_fpu_start_guest(fpu);
}

/*
 * This glue function is supposed to save the guest's FPU state. The host's FPU
 * state is not expected to be restored necessarily due to the use of FPU
 * emulation through CR0.TS. However, we can and do restore it here.
 */
void
fpusave(void *arg)
{
	hma_fpu_t *fpu = arg;

	hma_fpu_stop_guest(fpu);
}

void
vmm_sol_glue_init(void)
{
	vmm_alloc_init();
	vmm_cpuid_init();
}

void
vmm_sol_glue_cleanup(void)
{
	vmm_alloc_cleanup();
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
