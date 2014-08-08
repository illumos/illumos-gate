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

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/param.h>
#include <sys/stack.h>
#include <sys/regset.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/procfs_isa.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/machpcb.h>
#include <sys/machasi.h>
#include <sys/vis.h>
#include <sys/fpu/fpusystm.h>
#include <sys/cpu_module.h>
#include <sys/privregs.h>
#include <sys/archsystm.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/clock.h>
#include <sys/cmp.h>
#include <sys/platform_module.h>
#include <sys/bl.h>
#include <sys/nvpair.h>
#include <sys/kdi_impl.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/pool_pset.h>
#include <sys/mem.h>
#include <sys/dumphdr.h>
#include <vm/seg_kmem.h>
#include <sys/hold_page.h>
#include <sys/cpu.h>
#include <sys/ivintr.h>
#include <sys/clock_impl.h>
#include <sys/machclock.h>

int maxphys = MMU_PAGESIZE * 16;	/* 128k */
int klustsize = MMU_PAGESIZE * 16;	/* 128k */

/*
 * Initialize kernel thread's stack.
 */
caddr_t
thread_stk_init(caddr_t stk)
{
	kfpu_t *fp;
	ulong_t align;

	/* allocate extra space for floating point state */
	stk -= SA(sizeof (kfpu_t) + GSR_SIZE);
	align = (uintptr_t)stk & 0x3f;
	stk -= align;		/* force v9_fpu to be 16 byte aligned */
	fp = (kfpu_t *)stk;
	fp->fpu_fprs = 0;

	stk -= SA(MINFRAME);
	return (stk);
}

#define	WIN32_SIZE	(MAXWIN * sizeof (struct rwindow32))
#define	WIN64_SIZE	(MAXWIN * sizeof (struct rwindow64))

kmem_cache_t	*wbuf32_cache;
kmem_cache_t	*wbuf64_cache;

void
lwp_stk_cache_init(void)
{
	/*
	 * Window buffers are allocated from the static arena
	 * because they are accessed at TL>0. We also must use
	 * KMC_NOHASH to prevent them from straddling page
	 * boundaries as they are accessed by physical address.
	 */
	wbuf32_cache = kmem_cache_create("wbuf32_cache", WIN32_SIZE,
	    0, NULL, NULL, NULL, NULL, static_arena, KMC_NOHASH);
	wbuf64_cache = kmem_cache_create("wbuf64_cache", WIN64_SIZE,
	    0, NULL, NULL, NULL, NULL, static_arena, KMC_NOHASH);
}

/*
 * Initialize lwp's kernel stack.
 * Note that now that the floating point register save area (kfpu_t)
 * has been broken out from machpcb and aligned on a 64 byte boundary so that
 * we can do block load/stores to/from it, there are a couple of potential
 * optimizations to save stack space. 1. The floating point register save
 * area could be aligned on a 16 byte boundary, and the floating point code
 * changed to (a) check the alignment and (b) use different save/restore
 * macros depending upon the alignment. 2. The lwp_stk_init code below
 * could be changed to calculate if less space would be wasted if machpcb
 * was first instead of second. However there is a REGOFF macro used in
 * locore, syscall_trap, machdep and mlsetup that assumes that the saved
 * register area is a fixed distance from the %sp, and would have to be
 * changed to a pointer or something...JJ said later.
 */
caddr_t
lwp_stk_init(klwp_t *lwp, caddr_t stk)
{
	struct machpcb *mpcb;
	kfpu_t *fp;
	uintptr_t aln;

	stk -= SA(sizeof (kfpu_t) + GSR_SIZE);
	aln = (uintptr_t)stk & 0x3F;
	stk -= aln;
	fp = (kfpu_t *)stk;
	stk -= SA(sizeof (struct machpcb));
	mpcb = (struct machpcb *)stk;
	bzero(mpcb, sizeof (struct machpcb));
	bzero(fp, sizeof (kfpu_t) + GSR_SIZE);
	lwp->lwp_regs = (void *)&mpcb->mpcb_regs;
	lwp->lwp_fpu = (void *)fp;
	mpcb->mpcb_fpu = fp;
	mpcb->mpcb_fpu->fpu_q = mpcb->mpcb_fpu_q;
	mpcb->mpcb_thread = lwp->lwp_thread;
	mpcb->mpcb_wbcnt = 0;
	if (lwp->lwp_procp->p_model == DATAMODEL_ILP32) {
		mpcb->mpcb_wstate = WSTATE_USER32;
		mpcb->mpcb_wbuf = kmem_cache_alloc(wbuf32_cache, KM_SLEEP);
	} else {
		mpcb->mpcb_wstate = WSTATE_USER64;
		mpcb->mpcb_wbuf = kmem_cache_alloc(wbuf64_cache, KM_SLEEP);
	}
	ASSERT(((uintptr_t)mpcb->mpcb_wbuf & 7) == 0);
	mpcb->mpcb_wbuf_pa = va_to_pa(mpcb->mpcb_wbuf);
	mpcb->mpcb_pa = va_to_pa(mpcb);
	return (stk);
}

void
lwp_stk_fini(klwp_t *lwp)
{
	struct machpcb *mpcb = lwptompcb(lwp);

	/*
	 * there might be windows still in the wbuf due to unmapped
	 * stack, misaligned stack pointer, etc.  We just free it.
	 */
	mpcb->mpcb_wbcnt = 0;
	if (mpcb->mpcb_wstate == WSTATE_USER32)
		kmem_cache_free(wbuf32_cache, mpcb->mpcb_wbuf);
	else
		kmem_cache_free(wbuf64_cache, mpcb->mpcb_wbuf);
	mpcb->mpcb_wbuf = NULL;
	mpcb->mpcb_wbuf_pa = -1;
}


/*
 * Copy regs from parent to child.
 */
void
lwp_forkregs(klwp_t *lwp, klwp_t *clwp)
{
	kthread_t *t, *pt = lwptot(lwp);
	struct machpcb *mpcb = lwptompcb(clwp);
	struct machpcb *pmpcb = lwptompcb(lwp);
	kfpu_t *fp, *pfp = lwptofpu(lwp);
	caddr_t wbuf;
	uint_t wstate;

	t = mpcb->mpcb_thread;
	/*
	 * remember child's fp and wbuf since they will get erased during
	 * the bcopy.
	 */
	fp = mpcb->mpcb_fpu;
	wbuf = mpcb->mpcb_wbuf;
	wstate = mpcb->mpcb_wstate;
	/*
	 * Don't copy mpcb_frame since we hand-crafted it
	 * in thread_load().
	 */
	bcopy(lwp->lwp_regs, clwp->lwp_regs, sizeof (struct machpcb) - REGOFF);
	mpcb->mpcb_thread = t;
	mpcb->mpcb_fpu = fp;
	fp->fpu_q = mpcb->mpcb_fpu_q;

	/*
	 * It is theoretically possibly for the lwp's wstate to
	 * be different from its value assigned in lwp_stk_init,
	 * since lwp_stk_init assumed the data model of the process.
	 * Here, we took on the data model of the cloned lwp.
	 */
	if (mpcb->mpcb_wstate != wstate) {
		if (wstate == WSTATE_USER32) {
			kmem_cache_free(wbuf32_cache, wbuf);
			wbuf = kmem_cache_alloc(wbuf64_cache, KM_SLEEP);
			wstate = WSTATE_USER64;
		} else {
			kmem_cache_free(wbuf64_cache, wbuf);
			wbuf = kmem_cache_alloc(wbuf32_cache, KM_SLEEP);
			wstate = WSTATE_USER32;
		}
	}

	mpcb->mpcb_pa = va_to_pa(mpcb);
	mpcb->mpcb_wbuf = wbuf;
	mpcb->mpcb_wbuf_pa = va_to_pa(wbuf);

	ASSERT(mpcb->mpcb_wstate == wstate);

	if (mpcb->mpcb_wbcnt != 0) {
		bcopy(pmpcb->mpcb_wbuf, mpcb->mpcb_wbuf,
		    mpcb->mpcb_wbcnt * ((mpcb->mpcb_wstate == WSTATE_USER32) ?
		    sizeof (struct rwindow32) : sizeof (struct rwindow64)));
	}

	if (pt == curthread)
		pfp->fpu_fprs = _fp_read_fprs();
	if ((pfp->fpu_en) || (pfp->fpu_fprs & FPRS_FEF)) {
		if (pt == curthread && fpu_exists) {
			save_gsr(clwp->lwp_fpu);
		} else {
			uint64_t gsr;
			gsr = get_gsr(lwp->lwp_fpu);
			set_gsr(gsr, clwp->lwp_fpu);
		}
		fp_fork(lwp, clwp);
	}
}

/*
 * Free lwp fpu regs.
 */
void
lwp_freeregs(klwp_t *lwp, int isexec)
{
	kfpu_t *fp = lwptofpu(lwp);

	if (lwptot(lwp) == curthread)
		fp->fpu_fprs = _fp_read_fprs();
	if ((fp->fpu_en) || (fp->fpu_fprs & FPRS_FEF))
		fp_free(fp, isexec);
}

/*
 * These function are currently unused on sparc.
 */
/*ARGSUSED*/
void
lwp_attach_brand_hdlrs(klwp_t *lwp)
{}

/*ARGSUSED*/
void
lwp_detach_brand_hdlrs(klwp_t *lwp)
{}

/*
 * fill in the extra register state area specified with the
 * specified lwp's platform-dependent non-floating-point extra
 * register state information
 */
/* ARGSUSED */
void
xregs_getgfiller(klwp_id_t lwp, caddr_t xrp)
{
	/* for sun4u nothing to do here, added for symmetry */
}

/*
 * fill in the extra register state area specified with the specified lwp's
 * platform-dependent floating-point extra register state information.
 * NOTE:  'lwp' might not correspond to 'curthread' since this is
 * called from code in /proc to get the registers of another lwp.
 */
void
xregs_getfpfiller(klwp_id_t lwp, caddr_t xrp)
{
	prxregset_t *xregs = (prxregset_t *)xrp;
	kfpu_t *fp = lwptofpu(lwp);
	uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);
	uint64_t gsr;

	/*
	 * fp_fksave() does not flush the GSR register into
	 * the lwp area, so do it now
	 */
	kpreempt_disable();
	if (ttolwp(curthread) == lwp && fpu_exists) {
		fp->fpu_fprs = _fp_read_fprs();
		if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
			_fp_write_fprs(fprs);
			fp->fpu_fprs = (V9_FPU_FPRS_TYPE)fprs;
		}
		save_gsr(fp);
	}
	gsr = get_gsr(fp);
	kpreempt_enable();
	PRXREG_GSR(xregs) = gsr;
}

/*
 * set the specified lwp's platform-dependent non-floating-point
 * extra register state based on the specified input
 */
/* ARGSUSED */
void
xregs_setgfiller(klwp_id_t lwp, caddr_t xrp)
{
	/* for sun4u nothing to do here, added for symmetry */
}

/*
 * set the specified lwp's platform-dependent floating-point
 * extra register state based on the specified input
 */
void
xregs_setfpfiller(klwp_id_t lwp, caddr_t xrp)
{
	prxregset_t *xregs = (prxregset_t *)xrp;
	kfpu_t *fp = lwptofpu(lwp);
	uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);
	uint64_t gsr = PRXREG_GSR(xregs);

	kpreempt_disable();
	set_gsr(gsr, lwptofpu(lwp));

	if ((lwp == ttolwp(curthread)) && fpu_exists) {
		fp->fpu_fprs = _fp_read_fprs();
		if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
			_fp_write_fprs(fprs);
			fp->fpu_fprs = (V9_FPU_FPRS_TYPE)fprs;
		}
		restore_gsr(lwptofpu(lwp));
	}
	kpreempt_enable();
}

/*
 * fill in the sun4u asrs, ie, the lwp's platform-dependent
 * non-floating-point extra register state information
 */
/* ARGSUSED */
void
getasrs(klwp_t *lwp, asrset_t asr)
{
	/* for sun4u nothing to do here, added for symmetry */
}

/*
 * fill in the sun4u asrs, ie, the lwp's platform-dependent
 * floating-point extra register state information
 */
void
getfpasrs(klwp_t *lwp, asrset_t asr)
{
	kfpu_t *fp = lwptofpu(lwp);
	uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);

	kpreempt_disable();
	if (ttolwp(curthread) == lwp)
		fp->fpu_fprs = _fp_read_fprs();
	if ((fp->fpu_en) || (fp->fpu_fprs & FPRS_FEF)) {
		if (fpu_exists && ttolwp(curthread) == lwp) {
			if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				_fp_write_fprs(fprs);
				fp->fpu_fprs = (V9_FPU_FPRS_TYPE)fprs;
			}
			save_gsr(fp);
		}
		asr[ASR_GSR] = (int64_t)get_gsr(fp);
	}
	kpreempt_enable();
}

/*
 * set the sun4u asrs, ie, the lwp's platform-dependent
 * non-floating-point extra register state information
 */
/* ARGSUSED */
void
setasrs(klwp_t *lwp, asrset_t asr)
{
	/* for sun4u nothing to do here, added for symmetry */
}

void
setfpasrs(klwp_t *lwp, asrset_t asr)
{
	kfpu_t *fp = lwptofpu(lwp);
	uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);

	kpreempt_disable();
	if (ttolwp(curthread) == lwp)
		fp->fpu_fprs = _fp_read_fprs();
	if ((fp->fpu_en) || (fp->fpu_fprs & FPRS_FEF)) {
		set_gsr(asr[ASR_GSR], fp);
		if (fpu_exists && ttolwp(curthread) == lwp) {
			if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				_fp_write_fprs(fprs);
				fp->fpu_fprs = (V9_FPU_FPRS_TYPE)fprs;
			}
			restore_gsr(fp);
		}
	}
	kpreempt_enable();
}

/*
 * Create interrupt kstats for this CPU.
 */
void
cpu_create_intrstat(cpu_t *cp)
{
	int		i;
	kstat_t		*intr_ksp;
	kstat_named_t	*knp;
	char		name[KSTAT_STRLEN];
	zoneid_t	zoneid;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (pool_pset_enabled())
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = ALL_ZONES;

	intr_ksp = kstat_create_zone("cpu", cp->cpu_id, "intrstat", "misc",
	    KSTAT_TYPE_NAMED, PIL_MAX * 2, NULL, zoneid);

	/*
	 * Initialize each PIL's named kstat
	 */
	if (intr_ksp != NULL) {
		intr_ksp->ks_update = cpu_kstat_intrstat_update;
		knp = (kstat_named_t *)intr_ksp->ks_data;
		intr_ksp->ks_private = cp;
		for (i = 0; i < PIL_MAX; i++) {
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-time",
			    i + 1);
			kstat_named_init(&knp[i * 2], name, KSTAT_DATA_UINT64);
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-count",
			    i + 1);
			kstat_named_init(&knp[(i * 2) + 1], name,
			    KSTAT_DATA_UINT64);
		}
		kstat_install(intr_ksp);
	}
}

/*
 * Delete interrupt kstats for this CPU.
 */
void
cpu_delete_intrstat(cpu_t *cp)
{
	kstat_delete_byname_zone("cpu", cp->cpu_id, "intrstat", ALL_ZONES);
}

/*
 * Convert interrupt statistics from CPU ticks to nanoseconds and
 * update kstat.
 */
int
cpu_kstat_intrstat_update(kstat_t *ksp, int rw)
{
	kstat_named_t	*knp = ksp->ks_data;
	cpu_t		*cpup = (cpu_t *)ksp->ks_private;
	int		i;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	/*
	 * We use separate passes to copy and convert the statistics to
	 * nanoseconds. This assures that the snapshot of the data is as
	 * self-consistent as possible.
	 */

	for (i = 0; i < PIL_MAX; i++) {
		knp[i * 2].value.ui64 = cpup->cpu_m.intrstat[i + 1][0];
		knp[(i * 2) + 1].value.ui64 = cpup->cpu_stats.sys.intr[i];
	}

	for (i = 0; i < PIL_MAX; i++) {
		knp[i * 2].value.ui64 =
		    (uint64_t)tick2ns((hrtime_t)knp[i * 2].value.ui64,
		    cpup->cpu_id);
	}

	return (0);
}

/*
 * Called by common/os/cpu.c for psrinfo(1m) kstats
 */
char *
cpu_fru_fmri(cpu_t *cp)
{
	return (cpunodes[cp->cpu_id].fru_fmri);
}

/*
 * An interrupt thread is ending a time slice, so compute the interval it
 * ran for and update the statistic for its PIL.
 */
void
cpu_intr_swtch_enter(kthread_id_t t)
{
	uint64_t	interval;
	uint64_t	start;
	cpu_t		*cpu;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	/*
	 * We could be here with a zero timestamp. This could happen if:
	 * an interrupt thread which no longer has a pinned thread underneath
	 * it (i.e. it blocked at some point in its past) has finished running
	 * its handler. intr_thread() updated the interrupt statistic for its
	 * PIL and zeroed its timestamp. Since there was no pinned thread to
	 * return to, swtch() gets called and we end up here.
	 *
	 * It can also happen if an interrupt thread in intr_thread() calls
	 * preempt. It will have already taken care of updating stats. In
	 * this event, the interrupt thread will be runnable.
	 */
	if (t->t_intr_start) {
		do {
			start = t->t_intr_start;
			interval = CLOCK_TICK_COUNTER() - start;
		} while (atomic_cas_64(&t->t_intr_start, start, 0) != start);
		cpu = CPU;
		if (cpu->cpu_m.divisor > 1)
			interval *= cpu->cpu_m.divisor;
		cpu->cpu_m.intrstat[t->t_pil][0] += interval;

		atomic_add_64((uint64_t *)&cpu->cpu_intracct[cpu->cpu_mstate],
		    interval);
	} else
		ASSERT(t->t_intr == NULL || t->t_state == TS_RUN);
}


/*
 * An interrupt thread is returning from swtch(). Place a starting timestamp
 * in its thread structure.
 */
void
cpu_intr_swtch_exit(kthread_id_t t)
{
	uint64_t ts;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	do {
		ts = t->t_intr_start;
	} while (atomic_cas_64(&t->t_intr_start, ts, CLOCK_TICK_COUNTER()) !=
	    ts);
}


int
blacklist(int cmd, const char *scheme, nvlist_t *fmri, const char *class)
{
	if (&plat_blacklist)
		return (plat_blacklist(cmd, scheme, fmri, class));

	return (ENOTSUP);
}

int
kdi_pread(caddr_t buf, size_t nbytes, uint64_t addr, size_t *ncopiedp)
{
	extern void kdi_flush_caches(void);
	size_t nread = 0;
	uint32_t word;
	int slop, i;

	kdi_flush_caches();
	membar_enter();

	/* We might not begin on a word boundary. */
	if ((slop = addr & 3) != 0) {
		word = ldphys(addr & ~3);
		for (i = slop; i < 4 && nbytes > 0; i++, nbytes--, nread++)
			*buf++ = ((uchar_t *)&word)[i];
		addr = roundup(addr, 4);
	}

	while (nbytes > 0) {
		word = ldphys(addr);
		for (i = 0; i < 4 && nbytes > 0; i++, nbytes--, nread++, addr++)
			*buf++ = ((uchar_t *)&word)[i];
	}

	kdi_flush_caches();

	*ncopiedp = nread;
	return (0);
}

int
kdi_pwrite(caddr_t buf, size_t nbytes, uint64_t addr, size_t *ncopiedp)
{
	extern void kdi_flush_caches(void);
	size_t nwritten = 0;
	uint32_t word;
	int slop, i;

	kdi_flush_caches();

	/* We might not begin on a word boundary. */
	if ((slop = addr & 3) != 0) {
		word = ldphys(addr & ~3);
		for (i = slop; i < 4 && nbytes > 0; i++, nbytes--, nwritten++)
			((uchar_t *)&word)[i] = *buf++;
		stphys(addr & ~3, word);
		addr = roundup(addr, 4);
	}

	while (nbytes > 3) {
		for (word = 0, i = 0; i < 4; i++, nbytes--, nwritten++)
			((uchar_t *)&word)[i] = *buf++;
		stphys(addr, word);
		addr += 4;
	}

	/* We might not end with a whole word. */
	if (nbytes > 0) {
		word = ldphys(addr);
		for (i = 0; nbytes > 0; i++, nbytes--, nwritten++)
			((uchar_t *)&word)[i] = *buf++;
		stphys(addr, word);
	}

	membar_enter();
	kdi_flush_caches();

	*ncopiedp = nwritten;
	return (0);
}

static void
kdi_kernpanic(struct regs *regs, uint_t tt)
{
	sync_reg_buf = *regs;
	sync_tt = tt;

	sync_handler();
}

static void
kdi_plat_call(void (*platfn)(void))
{
	if (platfn != NULL) {
		prom_suspend_prepost();
		platfn();
		prom_resume_prepost();
	}
}

/*
 * kdi_system_claim and release are defined here for all sun4 platforms and
 * pointed to by mach_kdi_init() to provide default callbacks for such systems.
 * Specific sun4u or sun4v platforms may implement their own claim and release
 * routines, at which point their respective callbacks will be updated.
 */
static void
kdi_system_claim(void)
{
	lbolt_debug_entry();
}

static void
kdi_system_release(void)
{
	lbolt_debug_return();
}

void
mach_kdi_init(kdi_t *kdi)
{
	kdi->kdi_plat_call = kdi_plat_call;
	kdi->kdi_kmdb_enter = kmdb_enter;
	kdi->pkdi_system_claim = kdi_system_claim;
	kdi->pkdi_system_release = kdi_system_release;
	kdi->mkdi_cpu_index = kdi_cpu_index;
	kdi->mkdi_trap_vatotte = kdi_trap_vatotte;
	kdi->mkdi_kernpanic = kdi_kernpanic;
}


/*
 * get_cpu_mstate() is passed an array of timestamps, NCMSTATES
 * long, and it fills in the array with the time spent on cpu in
 * each of the mstates, where time is returned in nsec.
 *
 * No guarantee is made that the returned values in times[] will
 * monotonically increase on sequential calls, although this will
 * be true in the long run. Any such guarantee must be handled by
 * the caller, if needed. This can happen if we fail to account
 * for elapsed time due to a generation counter conflict, yet we
 * did account for it on a prior call (see below).
 *
 * The complication is that the cpu in question may be updating
 * its microstate at the same time that we are reading it.
 * Because the microstate is only updated when the CPU's state
 * changes, the values in cpu_intracct[] can be indefinitely out
 * of date. To determine true current values, it is necessary to
 * compare the current time with cpu_mstate_start, and add the
 * difference to times[cpu_mstate].
 *
 * This can be a problem if those values are changing out from
 * under us. Because the code path in new_cpu_mstate() is
 * performance critical, we have not added a lock to it. Instead,
 * we have added a generation counter. Before beginning
 * modifications, the counter is set to 0. After modifications,
 * it is set to the old value plus one.
 *
 * get_cpu_mstate() will not consider the values of cpu_mstate
 * and cpu_mstate_start to be usable unless the value of
 * cpu_mstate_gen is both non-zero and unchanged, both before and
 * after reading the mstate information. Note that we must
 * protect against out-of-order loads around accesses to the
 * generation counter. Also, this is a best effort approach in
 * that we do not retry should the counter be found to have
 * changed.
 *
 * cpu_intracct[] is used to identify time spent in each CPU
 * mstate while handling interrupts. Such time should be reported
 * against system time, and so is subtracted out from its
 * corresponding cpu_acct[] time and added to
 * cpu_acct[CMS_SYSTEM]. Additionally, intracct time is stored in
 * %ticks, but acct time may be stored as %sticks, thus requiring
 * different conversions before they can be compared.
 */

void
get_cpu_mstate(cpu_t *cpu, hrtime_t *times)
{
	int i;
	hrtime_t now, start;
	uint16_t gen;
	uint16_t state;
	hrtime_t intracct[NCMSTATES];

	/*
	 * Load all volatile state under the protection of membar.
	 * cpu_acct[cpu_mstate] must be loaded to avoid double counting
	 * of (now - cpu_mstate_start) by a change in CPU mstate that
	 * arrives after we make our last check of cpu_mstate_gen.
	 */

	now = gethrtime_unscaled();
	gen = cpu->cpu_mstate_gen;

	membar_consumer();	/* guarantee load ordering */
	start = cpu->cpu_mstate_start;
	state = cpu->cpu_mstate;
	for (i = 0; i < NCMSTATES; i++) {
		intracct[i] = cpu->cpu_intracct[i];
		times[i] = cpu->cpu_acct[i];
	}
	membar_consumer();	/* guarantee load ordering */

	if (gen != 0 && gen == cpu->cpu_mstate_gen && now > start)
		times[state] += now - start;

	for (i = 0; i < NCMSTATES; i++) {
		scalehrtime(&times[i]);
		intracct[i] = tick2ns((hrtime_t)intracct[i], cpu->cpu_id);
	}

	for (i = 0; i < NCMSTATES; i++) {
		if (i == CMS_SYSTEM)
			continue;
		times[i] -= intracct[i];
		if (times[i] < 0) {
			intracct[i] += times[i];
			times[i] = 0;
		}
		times[CMS_SYSTEM] += intracct[i];
	}
}

void
mach_cpu_pause(volatile char *safe)
{
	/*
	 * This cpu is now safe.
	 */
	*safe = PAUSE_WAIT;
	membar_enter(); /* make sure stores are flushed */

	/*
	 * Now we wait.  When we are allowed to continue, safe
	 * will be set to PAUSE_IDLE.
	 */
	while (*safe != PAUSE_IDLE)
		SMT_PAUSE();
}

/*ARGSUSED*/
int
plat_mem_do_mmio(struct uio *uio, enum uio_rw rw)
{
	return (ENOTSUP);
}

/* cpu threshold for compressed dumps */
#ifdef sun4v
uint_t dump_plat_mincpu_default = DUMP_PLAT_SUN4V_MINCPU;
#else
uint_t dump_plat_mincpu_default = DUMP_PLAT_SUN4U_MINCPU;
#endif

int
dump_plat_addr()
{
	return (0);
}

void
dump_plat_pfn()
{
}

/* ARGSUSED */
int
dump_plat_data(void *dump_cdata)
{
	return (0);
}

/* ARGSUSED */
int
plat_hold_page(pfn_t pfn, int lock, page_t **pp_ret)
{
	return (PLAT_HOLD_OK);
}

/* ARGSUSED */
void
plat_release_page(page_t *pp)
{
}

/* ARGSUSED */
void
progressbar_key_abort(ldi_ident_t li)
{
}

/*
 * We need to post a soft interrupt to reprogram the lbolt cyclic when
 * switching from event to cyclic driven lbolt. The following code adds
 * and posts the softint for sun4 platforms.
 */
static uint64_t lbolt_softint_inum;

void
lbolt_softint_add(void)
{
	lbolt_softint_inum = add_softintr(LOCK_LEVEL,
	    (softintrfunc)lbolt_ev_to_cyclic, NULL, SOFTINT_MT);
}

void
lbolt_softint_post(void)
{
	setsoftint(lbolt_softint_inum);
}
