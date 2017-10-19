/*
 * Copyright (c) 2004 John Baldwin <jhb@FreeBSD.org>
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
 * $FreeBSD: head/sys/kern/subr_sleepqueue.c 261520 2014-02-05 18:13:27Z jhb $
 */
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

#include <machine/cpufunc.h>
#include <machine/fpu.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <sys/vmm_impl.h>

#include <vm/as.h>
#include <vm/seg_kmem.h>

vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	pfn_t	pfn;

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
	thread_affinity_set(curthread, CPU_CURRENT);
}

void
critical_exit(void)
{
	thread_affinity_clear(curthread);
	kpreempt_enable();
}

struct unr {
	u_int		item;
	struct unr	*link;
};

#define	UNR_HASHSIZE	8

struct unrhdr {
	struct mtx	*mtx;
	struct unr	*hash[UNR_HASHSIZE];
	u_int		min;
	u_int		max;
	u_int		next;
};

#define	HASH_UNR(uh, i)	((uh)->hash[(i) & ((UNR_HASHSIZE) - 1)])

static struct mtx unr_mtx;

/*
 * Allocate a new unrheader set.
 *
 * Highest and lowest valid values given as parameters.
 */
struct unrhdr *
new_unrhdr(int low, int high, struct mtx *mtx)
{
	struct unrhdr	*uh;

	uh = kmem_zalloc(sizeof (struct unrhdr), KM_SLEEP);
	if (mtx) {
		uh->mtx = mtx;
	} else {
		uh->mtx = &unr_mtx;
	}
	uh->min = low;
	uh->max = high;
	uh->next = uh->min;

	return (uh);
}

void
delete_unrhdr(struct unrhdr *uh)
{
	kmem_free(uh, sizeof (struct unrhdr));
}

static struct unr *
unr_lookup(struct unrhdr *uh, int item)
{
	struct unr	*unr;

	ASSERT(MUTEX_HELD(&uh->mtx->m));

	for (unr = HASH_UNR(uh, item); unr != NULL; unr = unr->link) {
		if (unr->item == item)
			break;
	}

	return (unr);
}

int
alloc_unr(struct unrhdr *uh)
{
	struct unr	*unr;
	int		item, start;

	mutex_enter(&uh->mtx->m);
	start = uh->next;
	for (;;) {
		item = uh->next;
		if (++uh->next == uh->max) {
			uh->next = uh->min;
		}

		if (unr_lookup(uh, item) == NULL) {
			unr = kmem_zalloc(sizeof (struct unr), KM_SLEEP);
			unr->item = item;
			unr->link = HASH_UNR(uh, item);
			HASH_UNR(uh, item) = unr;
			break;
		}

		if (item == start) {
			item = -1;
			break;
		}
	}
	mutex_exit(&uh->mtx->m);

	return (item);
}

void
free_unr(struct unrhdr *uh, u_int item)
{
	struct unr	*unr, **unrp;

	mutex_enter(&uh->mtx->m);
	unrp = &HASH_UNR(uh, item);
	for (;;) {
		ASSERT(*unrp != NULL);
		if ((*unrp)->item == item)
			break;
		unrp = &(*unrp)->link;
	}
	unr = *unrp;
	*unrp = unr->link;
	mutex_exit(&uh->mtx->m);
	kmem_free(unr, sizeof (struct unr));
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
	c->c_cyc_id = cyclic_add(&hdlr, &when);
	c->c_flags |= CALLOUT_ACTIVE;
	mutex_exit(&cpu_lock);
}

int
vmm_glue_callout_reset_sbt(struct callout *c, sbintime_t sbt, sbintime_t pr,
    void (*func)(void *), void *arg, int flags)
{
	ASSERT(c->c_cyc_id != CYCLIC_NONE);

	c->c_func = func;
	c->c_arg = arg;
	c->c_flags |= (CALLOUT_ACTIVE | CALLOUT_PENDING);

	if (flags & C_ABSOLUTE)
		cyclic_reprogram(c->c_cyc_id, sbt);
	else
		cyclic_reprogram(c->c_cyc_id, sbt + gethrtime());

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

static int
ipi_cpu_justreturn(xc_arg_t a1, xc_arg_t a2, xc_arg_t a3)
{
	return (0);
}

void
ipi_cpu(int cpu, u_int ipi)
{
	cpuset_t	set;

	CPUSET_ONLY(set, cpu);
	xc_call_nowait(NULL, NULL, NULL, CPUSET2BV(set), ipi_cpu_justreturn);
}

#define	SC_TABLESIZE	256			/* Must be power of 2. */
#define	SC_MASK		(SC_TABLESIZE - 1)
#define	SC_SHIFT	8
#define	SC_HASH(wc)	((((uintptr_t)(wc) >> SC_SHIFT) ^ (uintptr_t)(wc)) & \
			    SC_MASK)
#define	SC_LOOKUP(wc)	&sleepq_chains[SC_HASH(wc)]

struct sleepqueue {
	u_int sq_blockedcnt;			/* Num. of blocked threads. */
	LIST_ENTRY(sleepqueue) sq_hash;		/* Chain. */
	void		*sq_wchan;		/* Wait channel. */
	kcondvar_t	sq_cv;
};

struct sleepqueue_chain {
	LIST_HEAD(, sleepqueue) sc_queues;	/* List of sleep queues. */
	struct mtx	sc_lock;		/* Spin lock for this chain. */
};

static struct sleepqueue_chain	sleepq_chains[SC_TABLESIZE];

#define	SLEEPQ_CACHE_SZ		(64)
static kmem_cache_t		*vmm_sleepq_cache;

static int
vmm_sleepq_cache_init(void *buf, void *user_arg, int kmflags)
{
	struct sleepqueue *sq = (struct sleepqueue *)buf;

	bzero(sq, sizeof (struct sleepqueue));
	cv_init(&sq->sq_cv, NULL, CV_DRIVER, NULL);

	return (0);
}

static void
vmm_sleepq_cache_fini(void *buf, void *user_arg)
{
	struct sleepqueue *sq = (struct sleepqueue *)buf;
	cv_destroy(&sq->sq_cv);
}

static void
init_sleepqueues(void)
{
	int	i;

        for (i = 0; i < SC_TABLESIZE; i++) {
		LIST_INIT(&sleepq_chains[i].sc_queues);
		mtx_init(&sleepq_chains[i].sc_lock, "sleepq chain", NULL,
		    MTX_SPIN);
	}

	vmm_sleepq_cache = kmem_cache_create("vmm_sleepq_cache",
	    sizeof (struct sleepqueue), SLEEPQ_CACHE_SZ, vmm_sleepq_cache_init,
	    vmm_sleepq_cache_fini, NULL, NULL, NULL, 0);

}

/*
 * Lock the sleep queue chain associated with the specified wait channel.
 */
static void
sleepq_lock(void *wchan)
{
	struct sleepqueue_chain *sc;

	sc = SC_LOOKUP(wchan);
	mtx_lock_spin(&sc->sc_lock);
}

/*
 * Look up the sleep queue associated with a given wait channel in the hash
 * table locking the associated sleep queue chain.  If no queue is found in
 * the table, NULL is returned.
 */
static struct sleepqueue *
sleepq_lookup(void *wchan)
{
	struct sleepqueue_chain	*sc;
	struct sleepqueue	*sq;

	KASSERT(wchan != NULL, ("%s: invalid NULL wait channel", __func__));
	sc = SC_LOOKUP(wchan);
	mtx_assert(&sc->sc_lock, MA_OWNED);
	LIST_FOREACH(sq, &sc->sc_queues, sq_hash)
		if (sq->sq_wchan == wchan)
			return (sq);
	return (NULL);
}

/*
 * Unlock the sleep queue chain associated with a given wait channel.
 */
static void
sleepq_release(void *wchan)
{
	struct sleepqueue_chain *sc;

	sc = SC_LOOKUP(wchan);
	mtx_unlock_spin(&sc->sc_lock);
}

struct sleepqueue *
sleepq_add(void *wchan)
{
	struct sleepqueue_chain	*sc;
	struct sleepqueue	*sq;

	sc = SC_LOOKUP(wchan);

	/* Look up the sleep queue associated with the wait channel 'wchan'. */
	sq = sleepq_lookup(wchan);

	if (sq == NULL) {
		sq = kmem_cache_alloc(vmm_sleepq_cache, KM_SLEEP);
		LIST_INSERT_HEAD(&sc->sc_queues, sq, sq_hash);
		sq->sq_wchan = wchan;
	}

	sq->sq_blockedcnt++;

	return (sq);
}

void
sleepq_remove(struct sleepqueue *sq)
{
	sq->sq_blockedcnt--;

	if (sq->sq_blockedcnt == 0) {
		LIST_REMOVE(sq, sq_hash);
		kmem_cache_free(vmm_sleepq_cache, sq);
	}
}

int
msleep_spin(void *chan, struct mtx *mtx, const char *wmesg, int ticks)
{
	struct sleepqueue	*sq;
	int			error = 0;

	sleepq_lock(chan);
	sq = sleepq_add(chan);
	sleepq_release(chan);

	cv_reltimedwait(&sq->sq_cv, &mtx->m, ticks, TR_CLOCK_TICK);

	sleepq_lock(chan);
	sleepq_remove(sq);
	sleepq_release(chan);

	return (error);
}

void
wakeup(void *chan)
{
	struct sleepqueue	*sq;

	sleepq_lock(chan);
	sq = sleepq_lookup(chan);
	if (sq != NULL) {
		cv_broadcast(&sq->sq_cv);
	}
	sleepq_release(chan);
}

void
wakeup_one(void *chan)
{
	struct sleepqueue	*sq;

	sleepq_lock(chan);
	sq = sleepq_lookup(chan);
	if (sq != NULL) {
		cv_signal(&sq->sq_cv);
	}
	sleepq_release(chan);
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
	init_sleepqueues();
}

void
vmm_sol_glue_cleanup(void)
{
	fpu_save_area_cleanup();
	kmem_cache_destroy(vmm_sleepq_cache);
}
