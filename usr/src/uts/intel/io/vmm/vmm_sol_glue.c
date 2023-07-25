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
#include <sys/kmem.h>
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
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <machine/vmparam.h>
#include <sys/vmm_impl.h>
#include <sys/kernel.h>

#include <vm/as.h>
#include <vm/seg_kmem.h>


static void vmm_tsc_init(void);

SET_DECLARE(sysinit_set, struct sysinit);

void
sysinit(void)
{
	struct sysinit **si;

	SET_FOREACH(si, sysinit_set)
		(*si)->func((*si)->data);
}

void
invalidate_cache_all(void)
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
vtophys(void *va)
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

struct vmm_ptp_item {
	void *vpi_vaddr;
};
static kmutex_t vmm_ptp_lock;

static mod_hash_t *vmm_ptp_hash;
uint_t vmm_ptp_hash_nchains = 16381;
uint_t vmm_ptp_hash_size = PAGESIZE;

static void
vmm_ptp_hash_valdtor(mod_hash_val_t val)
{
	struct vmm_ptp_item *i = (struct vmm_ptp_item *)val;

	kmem_free(i->vpi_vaddr, PAGE_SIZE);
	kmem_free(i, sizeof (*i));
}

static void
vmm_ptp_init(void)
{
	vmm_ptp_hash = mod_hash_create_ptrhash("vmm_ptp_hash",
	    vmm_ptp_hash_nchains, vmm_ptp_hash_valdtor, vmm_ptp_hash_size);

	VERIFY(vmm_ptp_hash != NULL);
}

static uint_t
vmm_ptp_check(mod_hash_key_t key, mod_hash_val_t *val, void *unused)
{
	struct vmm_ptp_item *i = (struct vmm_ptp_item *)val;

	cmn_err(CE_PANIC, "!vmm_ptp_check: hash not empty: %p", i->vpi_vaddr);

	return (MH_WALK_TERMINATE);
}

static void
vmm_ptp_cleanup(void)
{
	mod_hash_walk(vmm_ptp_hash, vmm_ptp_check, NULL);
	mod_hash_destroy_ptrhash(vmm_ptp_hash);
}

/*
 * The logic in VT-d uses both kernel-virtual and direct-mapped addresses when
 * freeing PTP pages.  Until the consuming code is improved to better track the
 * pages it allocates, we keep the kernel-virtual addresses to those pages in a
 * hash table for when they are freed.
 */
void *
vmm_ptp_alloc(void)
{
	void *p;
	struct vmm_ptp_item *i;

	p = kmem_zalloc(PAGE_SIZE, KM_SLEEP);
	i = kmem_alloc(sizeof (struct vmm_ptp_item), KM_SLEEP);
	i->vpi_vaddr = p;

	mutex_enter(&vmm_ptp_lock);
	VERIFY(mod_hash_insert(vmm_ptp_hash,
	    (mod_hash_key_t)PHYS_TO_DMAP(vtophys(p)), (mod_hash_val_t)i) == 0);
	mutex_exit(&vmm_ptp_lock);

	return (p);
}

void
vmm_ptp_free(void *addr)
{
	mutex_enter(&vmm_ptp_lock);
	VERIFY(mod_hash_destroy(vmm_ptp_hash,
	    (mod_hash_key_t)PHYS_TO_DMAP(vtophys(addr))) == 0);
	mutex_exit(&vmm_ptp_lock);
}

/* Reach into i86pc/os/ddi_impl.c for these */
extern void *contig_alloc(size_t, ddi_dma_attr_t *, uintptr_t, int);
extern void contig_free(void *, size_t);

void *
vmm_contig_alloc(size_t size)
{
	ddi_dma_attr_t attr = {
		/* Using fastboot_dma_attr as a guide... */
		.dma_attr_version	= DMA_ATTR_V0,
		.dma_attr_addr_lo	= 0,
		.dma_attr_addr_hi	= ~0UL,
		.dma_attr_count_max	= 0x00000000FFFFFFFFULL,
		.dma_attr_align		= PAGE_SIZE,
		.dma_attr_burstsizes	= 1,
		.dma_attr_minxfer	= 1,
		.dma_attr_maxxfer	= 0x00000000FFFFFFFFULL,
		.dma_attr_seg		= 0x00000000FFFFFFFFULL, /* any */
		.dma_attr_sgllen	= 1,
		.dma_attr_granular	= PAGE_SIZE,
		.dma_attr_flags		= 0,
	};
	void *res;

	res = contig_alloc(size, &attr, PAGE_SIZE, 1);
	if (res != NULL) {
		bzero(res, size);
	}

	return (res);
}

void
vmm_contig_free(void *addr, size_t size)
{
	contig_free(addr, size);
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

void
callout_reset_hrtime(struct callout *c, hrtime_t target, void (*func)(void *),
    void *arg, int flags)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);

	if ((flags & C_ABSOLUTE) == 0) {
		target += gethrtime();
	}

	c->c_func = func;
	c->c_arg = arg;
	c->c_target = target;
	(void) cyclic_reprogram(c->c_cyc_id, target);
}

void
vmm_glue_callout_stop(struct callout *c)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);

	c->c_target = 0;
	(void) cyclic_reprogram(c->c_cyc_id, CY_INFINITY);
}

void
vmm_glue_callout_drain(struct callout *c)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);

	c->c_target = 0;
	mutex_enter(&cpu_lock);
	cyclic_remove(c->c_cyc_id);
	c->c_cyc_id = CYCLIC_NONE;
	mutex_exit(&cpu_lock);
}

void
vmm_glue_callout_localize(struct callout *c)
{
	mutex_enter(&cpu_lock);
	cyclic_move_here(c->c_cyc_id);
	mutex_exit(&cpu_lock);
}

/*
 * Given an interval (in ns) and a frequency (in hz), calculate the number of
 * "ticks" at that frequency which cover the interval.
 */
uint64_t
hrt_freq_count(hrtime_t interval, uint32_t freq)
{
	ASSERT3S(interval, >=, 0);
	const uint64_t sec = interval / NANOSEC;
	const uint64_t nsec = interval % NANOSEC;

	return ((sec * freq) + ((nsec * freq) / NANOSEC));
}

/*
 * Given a frequency (in hz) and number of "ticks", calculate the interval
 * (in ns) which would be covered by those ticks.
 */
hrtime_t
hrt_freq_interval(uint32_t freq, uint64_t count)
{
	const uint64_t sec = count / freq;
	const uint64_t frac = count % freq;

	return ((NANOSEC * sec) + ((frac * NANOSEC) / freq));
}


uint_t	cpu_high;		/* Highest arg to CPUID */
uint_t	cpu_exthigh;		/* Highest arg to extended CPUID */
uint_t	cpu_id;			/* Stepping ID */
char	cpu_vendor[20];		/* CPU Origin code */

static void
vmm_cpuid_init(void)
{
	uint_t regs[4];

	do_cpuid(0, regs);
	cpu_high = regs[0];
	((uint_t *)&cpu_vendor)[0] = regs[1];
	((uint_t *)&cpu_vendor)[1] = regs[3];
	((uint_t *)&cpu_vendor)[2] = regs[2];
	cpu_vendor[12] = '\0';

	do_cpuid(1, regs);
	cpu_id = regs[0];

	do_cpuid(0x80000000, regs);
	cpu_exthigh = regs[0];
}

void
vmm_sol_glue_init(void)
{
	vmm_ptp_init();
	vmm_cpuid_init();
	vmm_tsc_init();
}

void
vmm_sol_glue_cleanup(void)
{
	vmm_ptp_cleanup();
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

/*
 * Generic routines to convert between a POSIX date
 * (seconds since 1/1/1970) and yr/mo/day/hr/min/sec
 * Derived from NetBSD arch/hp300/hp300/clock.c
 */

#define	FEBRUARY	2
#define	days_in_year(y)		(leapyear(y) ? 366 : 365)
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
	    ct->hour > 23 || ct->min > 59 || ct->sec > 59 ||
	    (sizeof (time_t) == 4 && year > 2037)) {	/* time_t overflow */
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

/* Do the host CPU TSCs require offsets be applied for proper sync? */
static bool vmm_host_tsc_offset;

static void
vmm_tsc_init(void)
{
	/*
	 * The timestamp logic will decide if a delta need be applied to the
	 * unscaled hrtime reading (effectively rdtsc), but we do require it be
	 * backed by the TSC itself.
	 */
	extern hrtime_t (*gethrtimeunscaledf)(void);
	extern hrtime_t tsc_gethrtimeunscaled(void);
	extern hrtime_t tsc_gethrtimeunscaled_delta(void);

	VERIFY(*gethrtimeunscaledf == tsc_gethrtimeunscaled ||
	    *gethrtimeunscaledf == tsc_gethrtimeunscaled_delta);

	/*
	 * If a delta is being applied to the TSC on a per-host-CPU basis,
	 * expose that delta via vmm_host_tsc_delta().
	 */
	vmm_host_tsc_offset =
	    (*gethrtimeunscaledf == tsc_gethrtimeunscaled_delta);

}

/* Equivalent to the FreeBSD rdtsc(), but with any necessary per-cpu offset */
uint64_t
rdtsc_offset(void)
{
	return ((uint64_t)gethrtimeunscaledf());
}

/*
 * The delta (if any) which needs to be applied to the TSC of this host CPU to
 * bring it in sync with the others.
 */
uint64_t
vmm_host_tsc_delta(void)
{
	if (vmm_host_tsc_offset) {
		extern hrtime_t tsc_gethrtime_tick_delta(void);
		return (tsc_gethrtime_tick_delta());
	} else {
		return (0);
	}
}
