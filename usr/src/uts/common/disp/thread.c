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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/stack.h>
#include <sys/pcb.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/sysinfo.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/resource.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <sys/machlock.h>
#include <sys/kmem.h>
#include <sys/varargs.h>
#include <sys/turnstile.h>
#include <sys/poll.h>
#include <sys/vtrace.h>
#include <sys/callb.h>
#include <c2/audit.h>
#include <sys/tnf.h>
#include <sys/sobject.h>
#include <sys/cpupart.h>
#include <sys/pset.h>
#include <sys/door.h>
#include <sys/spl.h>
#include <sys/copyops.h>
#include <sys/rctl.h>
#include <sys/brand.h>
#include <sys/pool.h>
#include <sys/zone.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tndb.h>
#include <sys/cpc_impl.h>
#include <sys/sdt.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/schedctl.h>
#include <sys/waitq.h>
#include <sys/cpucaps.h>
#include <sys/kiconv.h>

struct kmem_cache *thread_cache;	/* cache of free threads */
struct kmem_cache *lwp_cache;		/* cache of free lwps */
struct kmem_cache *turnstile_cache;	/* cache of free turnstiles */

/*
 * allthreads is only for use by kmem_readers.  All kernel loops can use
 * the current thread as a start/end point.
 */
static kthread_t *allthreads = &t0;	/* circular list of all threads */

static kcondvar_t reaper_cv;		/* synchronization var */
kthread_t	*thread_deathrow;	/* circular list of reapable threads */
kthread_t	*lwp_deathrow;		/* circular list of reapable threads */
kmutex_t	reaplock;		/* protects lwp and thread deathrows */
int	thread_reapcnt = 0;		/* number of threads on deathrow */
int	lwp_reapcnt = 0;		/* number of lwps on deathrow */
int	reaplimit = 16;			/* delay reaping until reaplimit */

thread_free_lock_t	*thread_free_lock;
					/* protects tick thread from reaper */

extern int nthread;

/* System Scheduling classes. */
id_t	syscid;				/* system scheduling class ID */
id_t	sysdccid = CLASS_UNUSED;	/* reset when SDC loads */

void	*segkp_thread;			/* cookie for segkp pool */

int lwp_cache_sz = 32;
int t_cache_sz = 8;
static kt_did_t next_t_id = 1;

/* Default mode for thread binding to CPUs and processor sets */
int default_binding_mode = TB_ALLHARD;

/*
 * Min/Max stack sizes for stack size parameters
 */
#define	MAX_STKSIZE	(32 * DEFAULTSTKSZ)
#define	MIN_STKSIZE	DEFAULTSTKSZ

/*
 * default_stksize overrides lwp_default_stksize if it is set.
 */
int	default_stksize;
int	lwp_default_stksize;

static zone_key_t zone_thread_key;

unsigned int kmem_stackinfo;		/* stackinfo feature on-off */
kmem_stkinfo_t *kmem_stkinfo_log;	/* stackinfo circular log */
static kmutex_t kmem_stkinfo_lock;	/* protects kmem_stkinfo_log */

/*
 * forward declarations for internal thread specific data (tsd)
 */
static void *tsd_realloc(void *, size_t, size_t);

void thread_reaper(void);

/* forward declarations for stackinfo feature */
static void stkinfo_begin(kthread_t *);
static void stkinfo_end(kthread_t *);
static size_t stkinfo_percent(caddr_t, caddr_t, caddr_t);

/*ARGSUSED*/
static int
turnstile_constructor(void *buf, void *cdrarg, int kmflags)
{
	bzero(buf, sizeof (turnstile_t));
	return (0);
}

/*ARGSUSED*/
static void
turnstile_destructor(void *buf, void *cdrarg)
{
	turnstile_t *ts = buf;

	ASSERT(ts->ts_free == NULL);
	ASSERT(ts->ts_waiters == 0);
	ASSERT(ts->ts_inheritor == NULL);
	ASSERT(ts->ts_sleepq[0].sq_first == NULL);
	ASSERT(ts->ts_sleepq[1].sq_first == NULL);
}

void
thread_init(void)
{
	kthread_t *tp;
	extern char sys_name[];
	extern void idle();
	struct cpu *cpu = CPU;
	int i;
	kmutex_t *lp;

	mutex_init(&reaplock, NULL, MUTEX_SPIN, (void *)ipltospl(DISP_LEVEL));
	thread_free_lock =
	    kmem_alloc(sizeof (thread_free_lock_t) * THREAD_FREE_NUM, KM_SLEEP);
	for (i = 0; i < THREAD_FREE_NUM; i++) {
		lp = &thread_free_lock[i].tf_lock;
		mutex_init(lp, NULL, MUTEX_DEFAULT, NULL);
	}

#if defined(__i386) || defined(__amd64)
	thread_cache = kmem_cache_create("thread_cache", sizeof (kthread_t),
	    PTR24_ALIGN, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * "struct _klwp" includes a "struct pcb", which includes a
	 * "struct fpu", which needs to be 64-byte aligned on amd64
	 * (and even on i386) for xsave/xrstor.
	 */
	lwp_cache = kmem_cache_create("lwp_cache", sizeof (klwp_t),
	    64, NULL, NULL, NULL, NULL, NULL, 0);
#else
	/*
	 * Allocate thread structures from static_arena.  This prevents
	 * issues where a thread tries to relocate its own thread
	 * structure and touches it after the mapping has been suspended.
	 */
	thread_cache = kmem_cache_create("thread_cache", sizeof (kthread_t),
	    PTR24_ALIGN, NULL, NULL, NULL, NULL, static_arena, 0);

	lwp_stk_cache_init();

	lwp_cache = kmem_cache_create("lwp_cache", sizeof (klwp_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
#endif

	turnstile_cache = kmem_cache_create("turnstile_cache",
	    sizeof (turnstile_t), 0,
	    turnstile_constructor, turnstile_destructor, NULL, NULL, NULL, 0);

	label_init();
	cred_init();

	/*
	 * Initialize various resource management facilities.
	 */
	rctl_init();
	cpucaps_init();
	/*
	 * Zone_init() should be called before project_init() so that project ID
	 * for the first project is initialized correctly.
	 */
	zone_init();
	project_init();
	brand_init();
	kiconv_init();
	task_init();
	tcache_init();
	pool_init();

	curthread->t_ts = kmem_cache_alloc(turnstile_cache, KM_SLEEP);

	/*
	 * Originally, we had two parameters to set default stack
	 * size: one for lwp's (lwp_default_stksize), and one for
	 * kernel-only threads (DEFAULTSTKSZ, a.k.a. _defaultstksz).
	 * Now we have a third parameter that overrides both if it is
	 * set to a legal stack size, called default_stksize.
	 */

	if (default_stksize == 0) {
		default_stksize = DEFAULTSTKSZ;
	} else if (default_stksize % PAGESIZE != 0 ||
	    default_stksize > MAX_STKSIZE ||
	    default_stksize < MIN_STKSIZE) {
		cmn_err(CE_WARN, "Illegal stack size. Using %d",
		    (int)DEFAULTSTKSZ);
		default_stksize = DEFAULTSTKSZ;
	} else {
		lwp_default_stksize = default_stksize;
	}

	if (lwp_default_stksize == 0) {
		lwp_default_stksize = default_stksize;
	} else if (lwp_default_stksize % PAGESIZE != 0 ||
	    lwp_default_stksize > MAX_STKSIZE ||
	    lwp_default_stksize < MIN_STKSIZE) {
		cmn_err(CE_WARN, "Illegal stack size. Using %d",
		    default_stksize);
		lwp_default_stksize = default_stksize;
	}

	segkp_lwp = segkp_cache_init(segkp, lwp_cache_sz,
	    lwp_default_stksize,
	    (KPD_NOWAIT | KPD_HASREDZONE | KPD_LOCKED));

	segkp_thread = segkp_cache_init(segkp, t_cache_sz,
	    default_stksize, KPD_HASREDZONE | KPD_LOCKED | KPD_NO_ANON);

	(void) getcid(sys_name, &syscid);
	curthread->t_cid = syscid;	/* current thread is t0 */

	/*
	 * Set up the first CPU's idle thread.
	 * It runs whenever the CPU has nothing worthwhile to do.
	 */
	tp = thread_create(NULL, 0, idle, NULL, 0, &p0, TS_STOPPED, -1);
	cpu->cpu_idle_thread = tp;
	tp->t_preempt = 1;
	tp->t_disp_queue = cpu->cpu_disp;
	ASSERT(tp->t_disp_queue != NULL);
	tp->t_bound_cpu = cpu;
	tp->t_affinitycnt = 1;

	/*
	 * Registering a thread in the callback table is usually
	 * done in the initialization code of the thread. In this
	 * case, we do it right after thread creation to avoid
	 * blocking idle thread while registering itself. It also
	 * avoids the possibility of reregistration in case a CPU
	 * restarts its idle thread.
	 */
	CALLB_CPR_INIT_SAFE(tp, "idle");

	/*
	 * Create the thread_reaper daemon. From this point on, exited
	 * threads will get reaped.
	 */
	(void) thread_create(NULL, 0, (void (*)())thread_reaper,
	    NULL, 0, &p0, TS_RUN, minclsyspri);

	/*
	 * Finish initializing the kernel memory allocator now that
	 * thread_create() is available.
	 */
	kmem_thread_init();

	if (boothowto & RB_DEBUG)
		kdi_dvec_thravail();
}

/*
 * Create a thread.
 *
 * thread_create() blocks for memory if necessary.  It never fails.
 *
 * If stk is NULL, the thread is created at the base of the stack
 * and cannot be swapped.
 */
kthread_t *
thread_create(
	caddr_t	stk,
	size_t	stksize,
	void	(*proc)(),
	void	*arg,
	size_t	len,
	proc_t	 *pp,
	int	state,
	pri_t	pri)
{
	kthread_t *t;
	extern struct classfuncs sys_classfuncs;
	turnstile_t *ts;

	/*
	 * Every thread keeps a turnstile around in case it needs to block.
	 * The only reason the turnstile is not simply part of the thread
	 * structure is that we may have to break the association whenever
	 * more than one thread blocks on a given synchronization object.
	 * From a memory-management standpoint, turnstiles are like the
	 * "attached mblks" that hang off dblks in the streams allocator.
	 */
	ts = kmem_cache_alloc(turnstile_cache, KM_SLEEP);

	if (stk == NULL) {
		/*
		 * alloc both thread and stack in segkp chunk
		 */

		if (stksize < default_stksize)
			stksize = default_stksize;

		if (stksize == default_stksize) {
			stk = (caddr_t)segkp_cache_get(segkp_thread);
		} else {
			stksize = roundup(stksize, PAGESIZE);
			stk = (caddr_t)segkp_get(segkp, stksize,
			    (KPD_HASREDZONE | KPD_NO_ANON | KPD_LOCKED));
		}

		ASSERT(stk != NULL);

		/*
		 * The machine-dependent mutex code may require that
		 * thread pointers (since they may be used for mutex owner
		 * fields) have certain alignment requirements.
		 * PTR24_ALIGN is the size of the alignment quanta.
		 * XXX - assumes stack grows toward low addresses.
		 */
		if (stksize <= sizeof (kthread_t) + PTR24_ALIGN)
			cmn_err(CE_PANIC, "thread_create: proposed stack size"
			    " too small to hold thread.");
#ifdef STACK_GROWTH_DOWN
		stksize -= SA(sizeof (kthread_t) + PTR24_ALIGN - 1);
		stksize &= -PTR24_ALIGN;	/* make thread aligned */
		t = (kthread_t *)(stk + stksize);
		bzero(t, sizeof (kthread_t));
		if (audit_active)
			audit_thread_create(t);
		t->t_stk = stk + stksize;
		t->t_stkbase = stk;
#else	/* stack grows to larger addresses */
		stksize -= SA(sizeof (kthread_t));
		t = (kthread_t *)(stk);
		bzero(t, sizeof (kthread_t));
		t->t_stk = stk + sizeof (kthread_t);
		t->t_stkbase = stk + stksize + sizeof (kthread_t);
#endif	/* STACK_GROWTH_DOWN */
		t->t_flag |= T_TALLOCSTK;
		t->t_swap = stk;
	} else {
		t = kmem_cache_alloc(thread_cache, KM_SLEEP);
		bzero(t, sizeof (kthread_t));
		ASSERT(((uintptr_t)t & (PTR24_ALIGN - 1)) == 0);
		if (audit_active)
			audit_thread_create(t);
		/*
		 * Initialize t_stk to the kernel stack pointer to use
		 * upon entry to the kernel
		 */
#ifdef STACK_GROWTH_DOWN
		t->t_stk = stk + stksize;
		t->t_stkbase = stk;
#else
		t->t_stk = stk;			/* 3b2-like */
		t->t_stkbase = stk + stksize;
#endif /* STACK_GROWTH_DOWN */
	}

	if (kmem_stackinfo != 0) {
		stkinfo_begin(t);
	}

	t->t_ts = ts;

	/*
	 * p_cred could be NULL if it thread_create is called before cred_init
	 * is called in main.
	 */
	mutex_enter(&pp->p_crlock);
	if (pp->p_cred)
		crhold(t->t_cred = pp->p_cred);
	mutex_exit(&pp->p_crlock);
	t->t_start = gethrestime_sec();
	t->t_startpc = proc;
	t->t_procp = pp;
	t->t_clfuncs = &sys_classfuncs.thread;
	t->t_cid = syscid;
	t->t_pri = pri;
	t->t_stime = ddi_get_lbolt();
	t->t_schedflag = TS_LOAD | TS_DONT_SWAP;
	t->t_bind_cpu = PBIND_NONE;
	t->t_bindflag = (uchar_t)default_binding_mode;
	t->t_bind_pset = PS_NONE;
	t->t_plockp = &pp->p_lock;
	t->t_copyops = NULL;
	t->t_taskq = NULL;
	t->t_anttime = 0;
	t->t_hatdepth = 0;

	t->t_dtrace_vtime = 1;	/* assure vtimestamp is always non-zero */

	CPU_STATS_ADDQ(CPU, sys, nthreads, 1);
#ifndef NPROBE
	/* Kernel probe */
	tnf_thread_create(t);
#endif /* NPROBE */
	LOCK_INIT_CLEAR(&t->t_lock);

	/*
	 * Callers who give us a NULL proc must do their own
	 * stack initialization.  e.g. lwp_create()
	 */
	if (proc != NULL) {
		t->t_stk = thread_stk_init(t->t_stk);
		thread_load(t, proc, arg, len);
	}

	/*
	 * Put a hold on project0. If this thread is actually in a
	 * different project, then t_proj will be changed later in
	 * lwp_create().  All kernel-only threads must be in project 0.
	 */
	t->t_proj = project_hold(proj0p);

	lgrp_affinity_init(&t->t_lgrp_affinity);

	mutex_enter(&pidlock);
	nthread++;
	t->t_did = next_t_id++;
	t->t_prev = curthread->t_prev;
	t->t_next = curthread;

	/*
	 * Add the thread to the list of all threads, and initialize
	 * its t_cpu pointer.  We need to block preemption since
	 * cpu_offline walks the thread list looking for threads
	 * with t_cpu pointing to the CPU being offlined.  We want
	 * to make sure that the list is consistent and that if t_cpu
	 * is set, the thread is on the list.
	 */
	kpreempt_disable();
	curthread->t_prev->t_next = t;
	curthread->t_prev = t;

	/*
	 * Threads should never have a NULL t_cpu pointer so assign it
	 * here.  If the thread is being created with state TS_RUN a
	 * better CPU may be chosen when it is placed on the run queue.
	 *
	 * We need to keep kernel preemption disabled when setting all
	 * three fields to keep them in sync.  Also, always create in
	 * the default partition since that's where kernel threads go
	 * (if this isn't a kernel thread, t_cpupart will be changed
	 * in lwp_create before setting the thread runnable).
	 */
	t->t_cpupart = &cp_default;

	/*
	 * For now, affiliate this thread with the root lgroup.
	 * Since the kernel does not (presently) allocate its memory
	 * in a locality aware fashion, the root is an appropriate home.
	 * If this thread is later associated with an lwp, it will have
	 * it's lgroup re-assigned at that time.
	 */
	lgrp_move_thread(t, &cp_default.cp_lgrploads[LGRP_ROOTID], 1);

	/*
	 * Inherit the current cpu.  If this cpu isn't part of the chosen
	 * lgroup, a new cpu will be chosen by cpu_choose when the thread
	 * is ready to run.
	 */
	if (CPU->cpu_part == &cp_default)
		t->t_cpu = CPU;
	else
		t->t_cpu = disp_lowpri_cpu(cp_default.cp_cpulist, t->t_lpl,
		    t->t_pri, NULL);

	t->t_disp_queue = t->t_cpu->cpu_disp;
	kpreempt_enable();

	/*
	 * Initialize thread state and the dispatcher lock pointer.
	 * Need to hold onto pidlock to block allthreads walkers until
	 * the state is set.
	 */
	switch (state) {
	case TS_RUN:
		curthread->t_oldspl = splhigh();	/* get dispatcher spl */
		THREAD_SET_STATE(t, TS_STOPPED, &transition_lock);
		CL_SETRUN(t);
		thread_unlock(t);
		break;

	case TS_ONPROC:
		THREAD_ONPROC(t, t->t_cpu);
		break;

	case TS_FREE:
		/*
		 * Free state will be used for intr threads.
		 * The interrupt routine must set the thread dispatcher
		 * lock pointer (t_lockp) if starting on a CPU
		 * other than the current one.
		 */
		THREAD_FREEINTR(t, CPU);
		break;

	case TS_STOPPED:
		THREAD_SET_STATE(t, TS_STOPPED, &stop_lock);
		break;

	default:			/* TS_SLEEP, TS_ZOMB or TS_TRANS */
		cmn_err(CE_PANIC, "thread_create: invalid state %d", state);
	}
	mutex_exit(&pidlock);
	return (t);
}

/*
 * Move thread to project0 and take care of project reference counters.
 */
void
thread_rele(kthread_t *t)
{
	kproject_t *kpj;

	thread_lock(t);

	ASSERT(t == curthread || t->t_state == TS_FREE || t->t_procp == &p0);
	kpj = ttoproj(t);
	t->t_proj = proj0p;

	thread_unlock(t);

	if (kpj != proj0p) {
		project_rele(kpj);
		(void) project_hold(proj0p);
	}
}

void
thread_exit(void)
{
	kthread_t *t = curthread;

	if ((t->t_proc_flag & TP_ZTHREAD) != 0)
		cmn_err(CE_PANIC, "thread_exit: zthread_exit() not called");

	tsd_exit();		/* Clean up this thread's TSD */

	kcpc_passivate();	/* clean up performance counter state */

	/*
	 * No kernel thread should have called poll() without arranging
	 * calling pollcleanup() here.
	 */
	ASSERT(t->t_pollstate == NULL);
	ASSERT(t->t_schedctl == NULL);
	if (t->t_door)
		door_slam();	/* in case thread did an upcall */

#ifndef NPROBE
	/* Kernel probe */
	if (t->t_tnf_tpdp)
		tnf_thread_exit();
#endif /* NPROBE */

	thread_rele(t);
	t->t_preempt++;

	/*
	 * remove thread from the all threads list so that
	 * death-row can use the same pointers.
	 */
	mutex_enter(&pidlock);
	t->t_next->t_prev = t->t_prev;
	t->t_prev->t_next = t->t_next;
	ASSERT(allthreads != t);	/* t0 never exits */
	cv_broadcast(&t->t_joincv);	/* wake up anyone in thread_join */
	mutex_exit(&pidlock);

	if (t->t_ctx != NULL)
		exitctx(t);
	if (t->t_procp->p_pctx != NULL)
		exitpctx(t->t_procp);

	if (kmem_stackinfo != 0) {
		stkinfo_end(t);
	}

	t->t_state = TS_ZOMB;	/* set zombie thread */

	swtch_from_zombie();	/* give up the CPU */
	/* NOTREACHED */
}

/*
 * Check to see if the specified thread is active (defined as being on
 * the thread list).  This is certainly a slow way to do this; if there's
 * ever a reason to speed it up, we could maintain a hash table of active
 * threads indexed by their t_did.
 */
static kthread_t *
did_to_thread(kt_did_t tid)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&pidlock));
	for (t = curthread->t_next; t != curthread; t = t->t_next) {
		if (t->t_did == tid)
			break;
	}
	if (t->t_did == tid)
		return (t);
	else
		return (NULL);
}

/*
 * Wait for specified thread to exit.  Returns immediately if the thread
 * could not be found, meaning that it has either already exited or never
 * existed.
 */
void
thread_join(kt_did_t tid)
{
	kthread_t *t;

	ASSERT(tid != curthread->t_did);
	ASSERT(tid != t0.t_did);

	mutex_enter(&pidlock);
	/*
	 * Make sure we check that the thread is on the thread list
	 * before blocking on it; otherwise we could end up blocking on
	 * a cv that's already been freed.  In other words, don't cache
	 * the thread pointer across calls to cv_wait.
	 *
	 * The choice of loop invariant means that whenever a thread
	 * is taken off the allthreads list, a cv_broadcast must be
	 * performed on that thread's t_joincv to wake up any waiters.
	 * The broadcast doesn't have to happen right away, but it
	 * shouldn't be postponed indefinitely (e.g., by doing it in
	 * thread_free which may only be executed when the deathrow
	 * queue is processed.
	 */
	while (t = did_to_thread(tid))
		cv_wait(&t->t_joincv, &pidlock);
	mutex_exit(&pidlock);
}

void
thread_free_prevent(kthread_t *t)
{
	kmutex_t *lp;

	lp = &thread_free_lock[THREAD_FREE_HASH(t)].tf_lock;
	mutex_enter(lp);
}

void
thread_free_allow(kthread_t *t)
{
	kmutex_t *lp;

	lp = &thread_free_lock[THREAD_FREE_HASH(t)].tf_lock;
	mutex_exit(lp);
}

static void
thread_free_barrier(kthread_t *t)
{
	kmutex_t *lp;

	lp = &thread_free_lock[THREAD_FREE_HASH(t)].tf_lock;
	mutex_enter(lp);
	mutex_exit(lp);
}

void
thread_free(kthread_t *t)
{
	boolean_t allocstk = (t->t_flag & T_TALLOCSTK);
	klwp_t *lwp = t->t_lwp;
	caddr_t swap = t->t_swap;

	ASSERT(t != &t0 && t->t_state == TS_FREE);
	ASSERT(t->t_door == NULL);
	ASSERT(t->t_schedctl == NULL);
	ASSERT(t->t_pollstate == NULL);

	t->t_pri = 0;
	t->t_pc = 0;
	t->t_sp = 0;
	t->t_wchan0 = NULL;
	t->t_wchan = NULL;
	if (t->t_cred != NULL) {
		crfree(t->t_cred);
		t->t_cred = 0;
	}
	if (t->t_pdmsg) {
		kmem_free(t->t_pdmsg, strlen(t->t_pdmsg) + 1);
		t->t_pdmsg = NULL;
	}
	if (audit_active)
		audit_thread_free(t);
#ifndef NPROBE
	if (t->t_tnf_tpdp)
		tnf_thread_free(t);
#endif /* NPROBE */
	if (t->t_cldata) {
		CL_EXITCLASS(t->t_cid, (caddr_t *)t->t_cldata);
	}
	if (t->t_rprof != NULL) {
		kmem_free(t->t_rprof, sizeof (*t->t_rprof));
		t->t_rprof = NULL;
	}
	t->t_lockp = NULL;	/* nothing should try to lock this thread now */
	if (lwp)
		lwp_freeregs(lwp, 0);
	if (t->t_ctx)
		freectx(t, 0);
	t->t_stk = NULL;
	if (lwp)
		lwp_stk_fini(lwp);
	lock_clear(&t->t_lock);

	if (t->t_ts->ts_waiters > 0)
		panic("thread_free: turnstile still active");

	kmem_cache_free(turnstile_cache, t->t_ts);

	free_afd(&t->t_activefd);

	/*
	 * Barrier for the tick accounting code.  The tick accounting code
	 * holds this lock to keep the thread from going away while it's
	 * looking at it.
	 */
	thread_free_barrier(t);

	ASSERT(ttoproj(t) == proj0p);
	project_rele(ttoproj(t));

	lgrp_affinity_free(&t->t_lgrp_affinity);

	mutex_enter(&pidlock);
	nthread--;
	mutex_exit(&pidlock);

	/*
	 * Free thread, lwp and stack.  This needs to be done carefully, since
	 * if T_TALLOCSTK is set, the thread is part of the stack.
	 */
	t->t_lwp = NULL;
	t->t_swap = NULL;

	if (swap) {
		segkp_release(segkp, swap);
	}
	if (lwp) {
		kmem_cache_free(lwp_cache, lwp);
	}
	if (!allocstk) {
		kmem_cache_free(thread_cache, t);
	}
}

/*
 * Removes threads associated with the given zone from a deathrow queue.
 * tp is a pointer to the head of the deathrow queue, and countp is a
 * pointer to the current deathrow count.  Returns a linked list of
 * threads removed from the list.
 */
static kthread_t *
thread_zone_cleanup(kthread_t **tp, int *countp, zoneid_t zoneid)
{
	kthread_t *tmp, *list = NULL;
	cred_t *cr;

	ASSERT(MUTEX_HELD(&reaplock));
	while (*tp != NULL) {
		if ((cr = (*tp)->t_cred) != NULL && crgetzoneid(cr) == zoneid) {
			tmp = *tp;
			*tp = tmp->t_forw;
			tmp->t_forw = list;
			list = tmp;
			(*countp)--;
		} else {
			tp = &(*tp)->t_forw;
		}
	}
	return (list);
}

static void
thread_reap_list(kthread_t *t)
{
	kthread_t *next;

	while (t != NULL) {
		next = t->t_forw;
		thread_free(t);
		t = next;
	}
}

/* ARGSUSED */
static void
thread_zone_destroy(zoneid_t zoneid, void *unused)
{
	kthread_t *t, *l;

	mutex_enter(&reaplock);
	/*
	 * Pull threads and lwps associated with zone off deathrow lists.
	 */
	t = thread_zone_cleanup(&thread_deathrow, &thread_reapcnt, zoneid);
	l = thread_zone_cleanup(&lwp_deathrow, &lwp_reapcnt, zoneid);
	mutex_exit(&reaplock);

	/*
	 * Guard against race condition in mutex_owner_running:
	 * 	thread=owner(mutex)
	 * 	<interrupt>
	 * 				thread exits mutex
	 * 				thread exits
	 * 				thread reaped
	 * 				thread struct freed
	 * cpu = thread->t_cpu <- BAD POINTER DEREFERENCE.
	 * A cross call to all cpus will cause the interrupt handler
	 * to reset the PC if it is in mutex_owner_running, refreshing
	 * stale thread pointers.
	 */
	mutex_sync();   /* sync with mutex code */

	/*
	 * Reap threads
	 */
	thread_reap_list(t);

	/*
	 * Reap lwps
	 */
	thread_reap_list(l);
}

/*
 * cleanup zombie threads that are on deathrow.
 */
void
thread_reaper()
{
	kthread_t *t, *l;
	callb_cpr_t cprinfo;

	/*
	 * Register callback to clean up threads when zone is destroyed.
	 */
	zone_key_create(&zone_thread_key, NULL, NULL, thread_zone_destroy);

	CALLB_CPR_INIT(&cprinfo, &reaplock, callb_generic_cpr, "t_reaper");
	for (;;) {
		mutex_enter(&reaplock);
		while (thread_deathrow == NULL && lwp_deathrow == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&reaper_cv, &reaplock);
			CALLB_CPR_SAFE_END(&cprinfo, &reaplock);
		}
		/*
		 * mutex_sync() needs to be called when reaping, but
		 * not too often.  We limit reaping rate to once
		 * per second.  Reaplimit is max rate at which threads can
		 * be freed. Does not impact thread destruction/creation.
		 */
		t = thread_deathrow;
		l = lwp_deathrow;
		thread_deathrow = NULL;
		lwp_deathrow = NULL;
		thread_reapcnt = 0;
		lwp_reapcnt = 0;
		mutex_exit(&reaplock);

		/*
		 * Guard against race condition in mutex_owner_running:
		 * 	thread=owner(mutex)
		 * 	<interrupt>
		 * 				thread exits mutex
		 * 				thread exits
		 * 				thread reaped
		 * 				thread struct freed
		 * cpu = thread->t_cpu <- BAD POINTER DEREFERENCE.
		 * A cross call to all cpus will cause the interrupt handler
		 * to reset the PC if it is in mutex_owner_running, refreshing
		 * stale thread pointers.
		 */
		mutex_sync();   /* sync with mutex code */
		/*
		 * Reap threads
		 */
		thread_reap_list(t);

		/*
		 * Reap lwps
		 */
		thread_reap_list(l);
		delay(hz);
	}
}

/*
 * This is called by lwpcreate, etc.() to put a lwp_deathrow thread onto
 * thread_deathrow. The thread's state is changed already TS_FREE to indicate
 * that is reapable. The thread already holds the reaplock, and was already
 * freed.
 */
void
reapq_move_lq_to_tq(kthread_t *t)
{
	ASSERT(t->t_state == TS_FREE);
	ASSERT(MUTEX_HELD(&reaplock));
	t->t_forw = thread_deathrow;
	thread_deathrow = t;
	thread_reapcnt++;
	if (lwp_reapcnt + thread_reapcnt > reaplimit)
		cv_signal(&reaper_cv);  /* wake the reaper */
}

/*
 * This is called by resume() to put a zombie thread onto deathrow.
 * The thread's state is changed to TS_FREE to indicate that is reapable.
 * This is called from the idle thread so it must not block - just spin.
 */
void
reapq_add(kthread_t *t)
{
	mutex_enter(&reaplock);

	/*
	 * lwp_deathrow contains threads with lwp linkage and
	 * swappable thread stacks which have the default stacksize.
	 * These threads' lwps and stacks may be reused by lwp_create().
	 *
	 * Anything else goes on thread_deathrow(), where it will eventually
	 * be thread_free()d.
	 */
	if (t->t_flag & T_LWPREUSE) {
		ASSERT(ttolwp(t) != NULL);
		t->t_forw = lwp_deathrow;
		lwp_deathrow = t;
		lwp_reapcnt++;
	} else {
		t->t_forw = thread_deathrow;
		thread_deathrow = t;
		thread_reapcnt++;
	}
	if (lwp_reapcnt + thread_reapcnt > reaplimit)
		cv_signal(&reaper_cv);	/* wake the reaper */
	t->t_state = TS_FREE;
	lock_clear(&t->t_lock);

	/*
	 * Before we return, we need to grab and drop the thread lock for
	 * the dead thread.  At this point, the current thread is the idle
	 * thread, and the dead thread's CPU lock points to the current
	 * CPU -- and we must grab and drop the lock to synchronize with
	 * a racing thread walking a blocking chain that the zombie thread
	 * was recently in.  By this point, that blocking chain is (by
	 * definition) stale:  the dead thread is not holding any locks, and
	 * is therefore not in any blocking chains -- but if we do not regrab
	 * our lock before freeing the dead thread's data structures, the
	 * thread walking the (stale) blocking chain will die on memory
	 * corruption when it attempts to drop the dead thread's lock.  We
	 * only need do this once because there is no way for the dead thread
	 * to ever again be on a blocking chain:  once we have grabbed and
	 * dropped the thread lock, we are guaranteed that anyone that could
	 * have seen this thread in a blocking chain can no longer see it.
	 */
	thread_lock(t);
	thread_unlock(t);

	mutex_exit(&reaplock);
}

/*
 * Install thread context ops for the current thread.
 */
void
installctx(
	kthread_t *t,
	void	*arg,
	void	(*save)(void *),
	void	(*restore)(void *),
	void	(*fork)(void *, void *),
	void	(*lwp_create)(void *, void *),
	void	(*exit)(void *),
	void	(*free)(void *, int))
{
	struct ctxop *ctx;

	ctx = kmem_alloc(sizeof (struct ctxop), KM_SLEEP);
	ctx->save_op = save;
	ctx->restore_op = restore;
	ctx->fork_op = fork;
	ctx->lwp_create_op = lwp_create;
	ctx->exit_op = exit;
	ctx->free_op = free;
	ctx->arg = arg;
	ctx->next = t->t_ctx;
	t->t_ctx = ctx;
}

/*
 * Remove the thread context ops from a thread.
 */
int
removectx(
	kthread_t *t,
	void	*arg,
	void	(*save)(void *),
	void	(*restore)(void *),
	void	(*fork)(void *, void *),
	void	(*lwp_create)(void *, void *),
	void	(*exit)(void *),
	void	(*free)(void *, int))
{
	struct ctxop *ctx, *prev_ctx;

	/*
	 * The incoming kthread_t (which is the thread for which the
	 * context ops will be removed) should be one of the following:
	 *
	 * a) the current thread,
	 *
	 * b) a thread of a process that's being forked (SIDL),
	 *
	 * c) a thread that belongs to the same process as the current
	 *    thread and for which the current thread is the agent thread,
	 *
	 * d) a thread that is TS_STOPPED which is indicative of it
	 *    being (if curthread is not an agent) a thread being created
	 *    as part of an lwp creation.
	 */
	ASSERT(t == curthread || ttoproc(t)->p_stat == SIDL ||
	    ttoproc(t)->p_agenttp == curthread || t->t_state == TS_STOPPED);

	/*
	 * Serialize modifications to t->t_ctx to prevent the agent thread
	 * and the target thread from racing with each other during lwp exit.
	 */
	mutex_enter(&t->t_ctx_lock);
	prev_ctx = NULL;
	kpreempt_disable();
	for (ctx = t->t_ctx; ctx != NULL; ctx = ctx->next) {
		if (ctx->save_op == save && ctx->restore_op == restore &&
		    ctx->fork_op == fork && ctx->lwp_create_op == lwp_create &&
		    ctx->exit_op == exit && ctx->free_op == free &&
		    ctx->arg == arg) {
			if (prev_ctx)
				prev_ctx->next = ctx->next;
			else
				t->t_ctx = ctx->next;
			mutex_exit(&t->t_ctx_lock);
			if (ctx->free_op != NULL)
				(ctx->free_op)(ctx->arg, 0);
			kmem_free(ctx, sizeof (struct ctxop));
			kpreempt_enable();
			return (1);
		}
		prev_ctx = ctx;
	}
	mutex_exit(&t->t_ctx_lock);
	kpreempt_enable();

	return (0);
}

void
savectx(kthread_t *t)
{
	struct ctxop *ctx;

	ASSERT(t == curthread);
	for (ctx = t->t_ctx; ctx != 0; ctx = ctx->next)
		if (ctx->save_op != NULL)
			(ctx->save_op)(ctx->arg);
}

void
restorectx(kthread_t *t)
{
	struct ctxop *ctx;

	ASSERT(t == curthread);
	for (ctx = t->t_ctx; ctx != 0; ctx = ctx->next)
		if (ctx->restore_op != NULL)
			(ctx->restore_op)(ctx->arg);
}

void
forkctx(kthread_t *t, kthread_t *ct)
{
	struct ctxop *ctx;

	for (ctx = t->t_ctx; ctx != NULL; ctx = ctx->next)
		if (ctx->fork_op != NULL)
			(ctx->fork_op)(t, ct);
}

/*
 * Note that this operator is only invoked via the _lwp_create
 * system call.  The system may have other reasons to create lwps
 * e.g. the agent lwp or the doors unreferenced lwp.
 */
void
lwp_createctx(kthread_t *t, kthread_t *ct)
{
	struct ctxop *ctx;

	for (ctx = t->t_ctx; ctx != NULL; ctx = ctx->next)
		if (ctx->lwp_create_op != NULL)
			(ctx->lwp_create_op)(t, ct);
}

/*
 * exitctx is called from thread_exit() and lwp_exit() to perform any actions
 * needed when the thread/LWP leaves the processor for the last time. This
 * routine is not intended to deal with freeing memory; freectx() is used for
 * that purpose during thread_free(). This routine is provided to allow for
 * clean-up that can't wait until thread_free().
 */
void
exitctx(kthread_t *t)
{
	struct ctxop *ctx;

	for (ctx = t->t_ctx; ctx != NULL; ctx = ctx->next)
		if (ctx->exit_op != NULL)
			(ctx->exit_op)(t);
}

/*
 * freectx is called from thread_free() and exec() to get
 * rid of old thread context ops.
 */
void
freectx(kthread_t *t, int isexec)
{
	struct ctxop *ctx;

	kpreempt_disable();
	while ((ctx = t->t_ctx) != NULL) {
		t->t_ctx = ctx->next;
		if (ctx->free_op != NULL)
			(ctx->free_op)(ctx->arg, isexec);
		kmem_free(ctx, sizeof (struct ctxop));
	}
	kpreempt_enable();
}

/*
 * freectx_ctx is called from lwp_create() when lwp is reused from
 * lwp_deathrow and its thread structure is added to thread_deathrow.
 * The thread structure to which this ctx was attached may be already
 * freed by the thread reaper so free_op implementations shouldn't rely
 * on thread structure to which this ctx was attached still being around.
 */
void
freectx_ctx(struct ctxop *ctx)
{
	struct ctxop *nctx;

	ASSERT(ctx != NULL);

	kpreempt_disable();
	do {
		nctx = ctx->next;
		if (ctx->free_op != NULL)
			(ctx->free_op)(ctx->arg, 0);
		kmem_free(ctx, sizeof (struct ctxop));
	} while ((ctx = nctx) != NULL);
	kpreempt_enable();
}

/*
 * Set the thread running; arrange for it to be swapped in if necessary.
 */
void
setrun_locked(kthread_t *t)
{
	ASSERT(THREAD_LOCK_HELD(t));
	if (t->t_state == TS_SLEEP) {
		/*
		 * Take off sleep queue.
		 */
		SOBJ_UNSLEEP(t->t_sobj_ops, t);
	} else if (t->t_state & (TS_RUN | TS_ONPROC)) {
		/*
		 * Already on dispatcher queue.
		 */
		return;
	} else if (t->t_state == TS_WAIT) {
		waitq_setrun(t);
	} else if (t->t_state == TS_STOPPED) {
		/*
		 * All of the sending of SIGCONT (TC_XSTART) and /proc
		 * (TC_PSTART) and lwp_continue() (TC_CSTART) must have
		 * requested that the thread be run.
		 * Just calling setrun() is not sufficient to set a stopped
		 * thread running.  TP_TXSTART is always set if the thread
		 * is not stopped by a jobcontrol stop signal.
		 * TP_TPSTART is always set if /proc is not controlling it.
		 * TP_TCSTART is always set if lwp_suspend() didn't stop it.
		 * The thread won't be stopped unless one of these
		 * three mechanisms did it.
		 *
		 * These flags must be set before calling setrun_locked(t).
		 * They can't be passed as arguments because the streams
		 * code calls setrun() indirectly and the mechanism for
		 * doing so admits only one argument.  Note that the
		 * thread must be locked in order to change t_schedflags.
		 */
		if ((t->t_schedflag & TS_ALLSTART) != TS_ALLSTART)
			return;
		/*
		 * Process is no longer stopped (a thread is running).
		 */
		t->t_whystop = 0;
		t->t_whatstop = 0;
		/*
		 * Strictly speaking, we do not have to clear these
		 * flags here; they are cleared on entry to stop().
		 * However, they are confusing when doing kernel
		 * debugging or when they are revealed by ps(1).
		 */
		t->t_schedflag &= ~TS_ALLSTART;
		THREAD_TRANSITION(t);	/* drop stopped-thread lock */
		ASSERT(t->t_lockp == &transition_lock);
		ASSERT(t->t_wchan0 == NULL && t->t_wchan == NULL);
		/*
		 * Let the class put the process on the dispatcher queue.
		 */
		CL_SETRUN(t);
	}
}

void
setrun(kthread_t *t)
{
	thread_lock(t);
	setrun_locked(t);
	thread_unlock(t);
}

/*
 * Unpin an interrupted thread.
 *	When an interrupt occurs, the interrupt is handled on the stack
 *	of an interrupt thread, taken from a pool linked to the CPU structure.
 *
 *	When swtch() is switching away from an interrupt thread because it
 *	blocked or was preempted, this routine is called to complete the
 *	saving of the interrupted thread state, and returns the interrupted
 *	thread pointer so it may be resumed.
 *
 *	Called by swtch() only at high spl.
 */
kthread_t *
thread_unpin()
{
	kthread_t	*t = curthread;	/* current thread */
	kthread_t	*itp;		/* interrupted thread */
	int		i;		/* interrupt level */
	extern int	intr_passivate();

	ASSERT(t->t_intr != NULL);

	itp = t->t_intr;		/* interrupted thread */
	t->t_intr = NULL;		/* clear interrupt ptr */

	/*
	 * Get state from interrupt thread for the one
	 * it interrupted.
	 */

	i = intr_passivate(t, itp);

	TRACE_5(TR_FAC_INTR, TR_INTR_PASSIVATE,
	    "intr_passivate:level %d curthread %p (%T) ithread %p (%T)",
	    i, t, t, itp, itp);

	/*
	 * Dissociate the current thread from the interrupted thread's LWP.
	 */
	t->t_lwp = NULL;

	/*
	 * Interrupt handlers above the level that spinlocks block must
	 * not block.
	 */
#if DEBUG
	if (i < 0 || i > LOCK_LEVEL)
		cmn_err(CE_PANIC, "thread_unpin: ipl out of range %x", i);
#endif

	/*
	 * Compute the CPU's base interrupt level based on the active
	 * interrupts.
	 */
	ASSERT(CPU->cpu_intr_actv & (1 << i));
	set_base_spl();

	return (itp);
}

/*
 * Create and initialize an interrupt thread.
 *	Returns non-zero on error.
 *	Called at spl7() or better.
 */
void
thread_create_intr(struct cpu *cp)
{
	kthread_t *tp;

	tp = thread_create(NULL, 0,
	    (void (*)())thread_create_intr, NULL, 0, &p0, TS_ONPROC, 0);

	/*
	 * Set the thread in the TS_FREE state.  The state will change
	 * to TS_ONPROC only while the interrupt is active.  Think of these
	 * as being on a private free list for the CPU.  Being TS_FREE keeps
	 * inactive interrupt threads out of debugger thread lists.
	 *
	 * We cannot call thread_create with TS_FREE because of the current
	 * checks there for ONPROC.  Fix this when thread_create takes flags.
	 */
	THREAD_FREEINTR(tp, cp);

	/*
	 * Nobody should ever reference the credentials of an interrupt
	 * thread so make it NULL to catch any such references.
	 */
	tp->t_cred = NULL;
	tp->t_flag |= T_INTR_THREAD;
	tp->t_cpu = cp;
	tp->t_bound_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;
	tp->t_affinitycnt = 1;
	tp->t_preempt = 1;

	/*
	 * Don't make a user-requested binding on this thread so that
	 * the processor can be offlined.
	 */
	tp->t_bind_cpu = PBIND_NONE;	/* no USER-requested binding */
	tp->t_bind_pset = PS_NONE;

#if defined(__i386) || defined(__amd64)
	tp->t_stk -= STACK_ALIGN;
	*(tp->t_stk) = 0;		/* terminate intr thread stack */
#endif

	/*
	 * Link onto CPU's interrupt pool.
	 */
	tp->t_link = cp->cpu_intr_thread;
	cp->cpu_intr_thread = tp;
}

/*
 * TSD -- THREAD SPECIFIC DATA
 */
static kmutex_t		tsd_mutex;	 /* linked list spin lock */
static uint_t		tsd_nkeys;	 /* size of destructor array */
/* per-key destructor funcs */
static void 		(**tsd_destructor)(void *);
/* list of tsd_thread's */
static struct tsd_thread	*tsd_list;

/*
 * Default destructor
 *	Needed because NULL destructor means that the key is unused
 */
/* ARGSUSED */
void
tsd_defaultdestructor(void *value)
{}

/*
 * Create a key (index into per thread array)
 *	Locks out tsd_create, tsd_destroy, and tsd_exit
 *	May allocate memory with lock held
 */
void
tsd_create(uint_t *keyp, void (*destructor)(void *))
{
	int	i;
	uint_t	nkeys;

	/*
	 * if key is allocated, do nothing
	 */
	mutex_enter(&tsd_mutex);
	if (*keyp) {
		mutex_exit(&tsd_mutex);
		return;
	}
	/*
	 * find an unused key
	 */
	if (destructor == NULL)
		destructor = tsd_defaultdestructor;

	for (i = 0; i < tsd_nkeys; ++i)
		if (tsd_destructor[i] == NULL)
			break;

	/*
	 * if no unused keys, increase the size of the destructor array
	 */
	if (i == tsd_nkeys) {
		if ((nkeys = (tsd_nkeys << 1)) == 0)
			nkeys = 1;
		tsd_destructor =
		    (void (**)(void *))tsd_realloc((void *)tsd_destructor,
		    (size_t)(tsd_nkeys * sizeof (void (*)(void *))),
		    (size_t)(nkeys * sizeof (void (*)(void *))));
		tsd_nkeys = nkeys;
	}

	/*
	 * allocate the next available unused key
	 */
	tsd_destructor[i] = destructor;
	*keyp = i + 1;
	mutex_exit(&tsd_mutex);
}

/*
 * Destroy a key -- this is for unloadable modules
 *
 * Assumes that the caller is preventing tsd_set and tsd_get
 * Locks out tsd_create, tsd_destroy, and tsd_exit
 * May free memory with lock held
 */
void
tsd_destroy(uint_t *keyp)
{
	uint_t key;
	struct tsd_thread *tsd;

	/*
	 * protect the key namespace and our destructor lists
	 */
	mutex_enter(&tsd_mutex);
	key = *keyp;
	*keyp = 0;

	ASSERT(key <= tsd_nkeys);

	/*
	 * if the key is valid
	 */
	if (key != 0) {
		uint_t k = key - 1;
		/*
		 * for every thread with TSD, call key's destructor
		 */
		for (tsd = tsd_list; tsd; tsd = tsd->ts_next) {
			/*
			 * no TSD for key in this thread
			 */
			if (key > tsd->ts_nkeys)
				continue;
			/*
			 * call destructor for key
			 */
			if (tsd->ts_value[k] && tsd_destructor[k])
				(*tsd_destructor[k])(tsd->ts_value[k]);
			/*
			 * reset value for key
			 */
			tsd->ts_value[k] = NULL;
		}
		/*
		 * actually free the key (NULL destructor == unused)
		 */
		tsd_destructor[k] = NULL;
	}

	mutex_exit(&tsd_mutex);
}

/*
 * Quickly return the per thread value that was stored with the specified key
 * Assumes the caller is protecting key from tsd_create and tsd_destroy
 */
void *
tsd_get(uint_t key)
{
	return (tsd_agent_get(curthread, key));
}

/*
 * Set a per thread value indexed with the specified key
 */
int
tsd_set(uint_t key, void *value)
{
	return (tsd_agent_set(curthread, key, value));
}

/*
 * Like tsd_get(), except that the agent lwp can get the tsd of
 * another thread in the same process (the agent thread only runs when the
 * process is completely stopped by /proc), or syslwp is creating a new lwp.
 */
void *
tsd_agent_get(kthread_t *t, uint_t key)
{
	struct tsd_thread *tsd = t->t_tsd;

	ASSERT(t == curthread ||
	    ttoproc(t)->p_agenttp == curthread || t->t_state == TS_STOPPED);

	if (key && tsd != NULL && key <= tsd->ts_nkeys)
		return (tsd->ts_value[key - 1]);
	return (NULL);
}

/*
 * Like tsd_set(), except that the agent lwp can set the tsd of
 * another thread in the same process, or syslwp can set the tsd
 * of a thread it's in the middle of creating.
 *
 * Assumes the caller is protecting key from tsd_create and tsd_destroy
 * May lock out tsd_destroy (and tsd_create), may allocate memory with
 * lock held
 */
int
tsd_agent_set(kthread_t *t, uint_t key, void *value)
{
	struct tsd_thread *tsd = t->t_tsd;

	ASSERT(t == curthread ||
	    ttoproc(t)->p_agenttp == curthread || t->t_state == TS_STOPPED);

	if (key == 0)
		return (EINVAL);
	if (tsd == NULL)
		tsd = t->t_tsd = kmem_zalloc(sizeof (*tsd), KM_SLEEP);
	if (key <= tsd->ts_nkeys) {
		tsd->ts_value[key - 1] = value;
		return (0);
	}

	ASSERT(key <= tsd_nkeys);

	/*
	 * lock out tsd_destroy()
	 */
	mutex_enter(&tsd_mutex);
	if (tsd->ts_nkeys == 0) {
		/*
		 * Link onto list of threads with TSD
		 */
		if ((tsd->ts_next = tsd_list) != NULL)
			tsd_list->ts_prev = tsd;
		tsd_list = tsd;
	}

	/*
	 * Allocate thread local storage and set the value for key
	 */
	tsd->ts_value = tsd_realloc(tsd->ts_value,
	    tsd->ts_nkeys * sizeof (void *),
	    key * sizeof (void *));
	tsd->ts_nkeys = key;
	tsd->ts_value[key - 1] = value;
	mutex_exit(&tsd_mutex);

	return (0);
}


/*
 * Return the per thread value that was stored with the specified key
 *	If necessary, create the key and the value
 *	Assumes the caller is protecting *keyp from tsd_destroy
 */
void *
tsd_getcreate(uint_t *keyp, void (*destroy)(void *), void *(*allocate)(void))
{
	void *value;
	uint_t key = *keyp;
	struct tsd_thread *tsd = curthread->t_tsd;

	if (tsd == NULL)
		tsd = curthread->t_tsd = kmem_zalloc(sizeof (*tsd), KM_SLEEP);
	if (key && key <= tsd->ts_nkeys && (value = tsd->ts_value[key - 1]))
		return (value);
	if (key == 0)
		tsd_create(keyp, destroy);
	(void) tsd_set(*keyp, value = (*allocate)());

	return (value);
}

/*
 * Called from thread_exit() to run the destructor function for each tsd
 *	Locks out tsd_create and tsd_destroy
 *	Assumes that the destructor *DOES NOT* use tsd
 */
void
tsd_exit(void)
{
	int i;
	struct tsd_thread *tsd = curthread->t_tsd;

	if (tsd == NULL)
		return;

	if (tsd->ts_nkeys == 0) {
		kmem_free(tsd, sizeof (*tsd));
		curthread->t_tsd = NULL;
		return;
	}

	/*
	 * lock out tsd_create and tsd_destroy, call
	 * the destructor, and mark the value as destroyed.
	 */
	mutex_enter(&tsd_mutex);

	for (i = 0; i < tsd->ts_nkeys; i++) {
		if (tsd->ts_value[i] && tsd_destructor[i])
			(*tsd_destructor[i])(tsd->ts_value[i]);
		tsd->ts_value[i] = NULL;
	}

	/*
	 * remove from linked list of threads with TSD
	 */
	if (tsd->ts_next)
		tsd->ts_next->ts_prev = tsd->ts_prev;
	if (tsd->ts_prev)
		tsd->ts_prev->ts_next = tsd->ts_next;
	if (tsd_list == tsd)
		tsd_list = tsd->ts_next;

	mutex_exit(&tsd_mutex);

	/*
	 * free up the TSD
	 */
	kmem_free(tsd->ts_value, tsd->ts_nkeys * sizeof (void *));
	kmem_free(tsd, sizeof (struct tsd_thread));
	curthread->t_tsd = NULL;
}

/*
 * realloc
 */
static void *
tsd_realloc(void *old, size_t osize, size_t nsize)
{
	void *new;

	new = kmem_zalloc(nsize, KM_SLEEP);
	if (old) {
		bcopy(old, new, osize);
		kmem_free(old, osize);
	}
	return (new);
}

/*
 * Return non-zero if an interrupt is being serviced.
 */
int
servicing_interrupt()
{
	int onintr = 0;

	/* Are we an interrupt thread */
	if (curthread->t_flag & T_INTR_THREAD)
		return (1);
	/* Are we servicing a high level interrupt? */
	if (CPU_ON_INTR(CPU)) {
		kpreempt_disable();
		onintr = CPU_ON_INTR(CPU);
		kpreempt_enable();
	}
	return (onintr);
}


/*
 * Change the dispatch priority of a thread in the system.
 * Used when raising or lowering a thread's priority.
 * (E.g., priority inheritance)
 *
 * Since threads are queued according to their priority, we
 * we must check the thread's state to determine whether it
 * is on a queue somewhere. If it is, we've got to:
 *
 *	o Dequeue the thread.
 *	o Change its effective priority.
 *	o Enqueue the thread.
 *
 * Assumptions: The thread whose priority we wish to change
 * must be locked before we call thread_change_(e)pri().
 * The thread_change(e)pri() function doesn't drop the thread
 * lock--that must be done by its caller.
 */
void
thread_change_epri(kthread_t *t, pri_t disp_pri)
{
	uint_t	state;

	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * If the inherited priority hasn't actually changed,
	 * just return.
	 */
	if (t->t_epri == disp_pri)
		return;

	state = t->t_state;

	/*
	 * If it's not on a queue, change the priority with impunity.
	 */
	if ((state & (TS_SLEEP | TS_RUN | TS_WAIT)) == 0) {
		t->t_epri = disp_pri;
		if (state == TS_ONPROC) {
			cpu_t *cp = t->t_disp_queue->disp_cpu;

			if (t == cp->cpu_dispthread)
				cp->cpu_dispatch_pri = DISP_PRIO(t);
		}
	} else if (state == TS_SLEEP) {
		/*
		 * Take the thread out of its sleep queue.
		 * Change the inherited priority.
		 * Re-enqueue the thread.
		 * Each synchronization object exports a function
		 * to do this in an appropriate manner.
		 */
		SOBJ_CHANGE_EPRI(t->t_sobj_ops, t, disp_pri);
	} else if (state == TS_WAIT) {
		/*
		 * Re-enqueue a thread on the wait queue if its
		 * effective priority needs to change.
		 */
		if (disp_pri != t->t_epri)
			waitq_change_pri(t, disp_pri);
	} else {
		/*
		 * The thread is on a run queue.
		 * Note: setbackdq() may not put the thread
		 * back on the same run queue where it originally
		 * resided.
		 */
		(void) dispdeq(t);
		t->t_epri = disp_pri;
		setbackdq(t);
	}
	schedctl_set_cidpri(t);
}

/*
 * Function: Change the t_pri field of a thread.
 * Side Effects: Adjust the thread ordering on a run queue
 *		 or sleep queue, if necessary.
 * Returns: 1 if the thread was on a run queue, else 0.
 */
int
thread_change_pri(kthread_t *t, pri_t disp_pri, int front)
{
	uint_t	state;
	int	on_rq = 0;

	ASSERT(THREAD_LOCK_HELD(t));

	state = t->t_state;
	THREAD_WILLCHANGE_PRI(t, disp_pri);

	/*
	 * If it's not on a queue, change the priority with impunity.
	 */
	if ((state & (TS_SLEEP | TS_RUN | TS_WAIT)) == 0) {
		t->t_pri = disp_pri;

		if (state == TS_ONPROC) {
			cpu_t *cp = t->t_disp_queue->disp_cpu;

			if (t == cp->cpu_dispthread)
				cp->cpu_dispatch_pri = DISP_PRIO(t);
		}
	} else if (state == TS_SLEEP) {
		/*
		 * If the priority has changed, take the thread out of
		 * its sleep queue and change the priority.
		 * Re-enqueue the thread.
		 * Each synchronization object exports a function
		 * to do this in an appropriate manner.
		 */
		if (disp_pri != t->t_pri)
			SOBJ_CHANGE_PRI(t->t_sobj_ops, t, disp_pri);
	} else if (state == TS_WAIT) {
		/*
		 * Re-enqueue a thread on the wait queue if its
		 * priority needs to change.
		 */
		if (disp_pri != t->t_pri)
			waitq_change_pri(t, disp_pri);
	} else {
		/*
		 * The thread is on a run queue.
		 * Note: setbackdq() may not put the thread
		 * back on the same run queue where it originally
		 * resided.
		 *
		 * We still requeue the thread even if the priority
		 * is unchanged to preserve round-robin (and other)
		 * effects between threads of the same priority.
		 */
		on_rq = dispdeq(t);
		ASSERT(on_rq);
		t->t_pri = disp_pri;
		if (front) {
			setfrontdq(t);
		} else {
			setbackdq(t);
		}
	}
	schedctl_set_cidpri(t);
	return (on_rq);
}

/*
 * Tunable kmem_stackinfo is set, fill the kernel thread stack with a
 * specific pattern.
 */
static void
stkinfo_begin(kthread_t *t)
{
	caddr_t	start;	/* stack start */
	caddr_t	end;	/* stack end  */
	uint64_t *ptr;	/* pattern pointer */

	/*
	 * Stack grows up or down, see thread_create(),
	 * compute stack memory area start and end (start < end).
	 */
	if (t->t_stk > t->t_stkbase) {
		/* stack grows down */
		start = t->t_stkbase;
		end = t->t_stk;
	} else {
		/* stack grows up */
		start = t->t_stk;
		end = t->t_stkbase;
	}

	/*
	 * Stackinfo pattern size is 8 bytes. Ensure proper 8 bytes
	 * alignement for start and end in stack area boundaries
	 * (protection against corrupt t_stkbase/t_stk data).
	 */
	if ((((uintptr_t)start) & 0x7) != 0) {
		start = (caddr_t)((((uintptr_t)start) & (~0x7)) + 8);
	}
	end = (caddr_t)(((uintptr_t)end) & (~0x7));

	if ((end <= start) || (end - start) > (1024 * 1024)) {
		/* negative or stack size > 1 meg, assume bogus */
		return;
	}

	/* fill stack area with a pattern (instead of zeros) */
	ptr = (uint64_t *)((void *)start);
	while (ptr < (uint64_t *)((void *)end)) {
		*ptr++ = KMEM_STKINFO_PATTERN;
	}
}


/*
 * Tunable kmem_stackinfo is set, create stackinfo log if doesn't already exist,
 * compute the percentage of kernel stack really used, and set in the log
 * if it's the latest highest percentage.
 */
static void
stkinfo_end(kthread_t *t)
{
	caddr_t	start;	/* stack start */
	caddr_t	end;	/* stack end  */
	uint64_t *ptr;	/* pattern pointer */
	size_t stksz;	/* stack size */
	size_t smallest = 0;
	size_t percent = 0;
	uint_t index = 0;
	uint_t i;
	static size_t smallest_percent = (size_t)-1;
	static uint_t full = 0;

	/* create the stackinfo log, if doesn't already exist */
	mutex_enter(&kmem_stkinfo_lock);
	if (kmem_stkinfo_log == NULL) {
		kmem_stkinfo_log = (kmem_stkinfo_t *)
		    kmem_zalloc(KMEM_STKINFO_LOG_SIZE *
		    (sizeof (kmem_stkinfo_t)), KM_NOSLEEP);
		if (kmem_stkinfo_log == NULL) {
			mutex_exit(&kmem_stkinfo_lock);
			return;
		}
	}
	mutex_exit(&kmem_stkinfo_lock);

	/*
	 * Stack grows up or down, see thread_create(),
	 * compute stack memory area start and end (start < end).
	 */
	if (t->t_stk > t->t_stkbase) {
		/* stack grows down */
		start = t->t_stkbase;
		end = t->t_stk;
	} else {
		/* stack grows up */
		start = t->t_stk;
		end = t->t_stkbase;
	}

	/* stack size as found in kthread_t */
	stksz = end - start;

	/*
	 * Stackinfo pattern size is 8 bytes. Ensure proper 8 bytes
	 * alignement for start and end in stack area boundaries
	 * (protection against corrupt t_stkbase/t_stk data).
	 */
	if ((((uintptr_t)start) & 0x7) != 0) {
		start = (caddr_t)((((uintptr_t)start) & (~0x7)) + 8);
	}
	end = (caddr_t)(((uintptr_t)end) & (~0x7));

	if ((end <= start) || (end - start) > (1024 * 1024)) {
		/* negative or stack size > 1 meg, assume bogus */
		return;
	}

	/* search until no pattern in the stack */
	if (t->t_stk > t->t_stkbase) {
		/* stack grows down */
#if defined(__i386) || defined(__amd64)
		/*
		 * 6 longs are pushed on stack, see thread_load(). Skip
		 * them, so if kthread has never run, percent is zero.
		 * 8 bytes alignement is preserved for a 32 bit kernel,
		 * 6 x 4 = 24, 24 is a multiple of 8.
		 *
		 */
		end -= (6 * sizeof (long));
#endif
		ptr = (uint64_t *)((void *)start);
		while (ptr < (uint64_t *)((void *)end)) {
			if (*ptr != KMEM_STKINFO_PATTERN) {
				percent = stkinfo_percent(end,
				    start, (caddr_t)ptr);
				break;
			}
			ptr++;
		}
	} else {
		/* stack grows up */
		ptr = (uint64_t *)((void *)end);
		ptr--;
		while (ptr >= (uint64_t *)((void *)start)) {
			if (*ptr != KMEM_STKINFO_PATTERN) {
				percent = stkinfo_percent(start,
				    end, (caddr_t)ptr);
				break;
			}
			ptr--;
		}
	}

	DTRACE_PROBE3(stack__usage, kthread_t *, t,
	    size_t, stksz, size_t, percent);

	if (percent == 0) {
		return;
	}

	mutex_enter(&kmem_stkinfo_lock);
	if (full == KMEM_STKINFO_LOG_SIZE && percent < smallest_percent) {
		/*
		 * The log is full and already contains the highest values
		 */
		mutex_exit(&kmem_stkinfo_lock);
		return;
	}

	/* keep a log of the highest used stack */
	for (i = 0; i < KMEM_STKINFO_LOG_SIZE; i++) {
		if (kmem_stkinfo_log[i].percent == 0) {
			index = i;
			full++;
			break;
		}
		if (smallest == 0) {
			smallest = kmem_stkinfo_log[i].percent;
			index = i;
			continue;
		}
		if (kmem_stkinfo_log[i].percent < smallest) {
			smallest = kmem_stkinfo_log[i].percent;
			index = i;
		}
	}

	if (percent >= kmem_stkinfo_log[index].percent) {
		kmem_stkinfo_log[index].kthread = (caddr_t)t;
		kmem_stkinfo_log[index].t_startpc = (caddr_t)t->t_startpc;
		kmem_stkinfo_log[index].start = start;
		kmem_stkinfo_log[index].stksz = stksz;
		kmem_stkinfo_log[index].percent = percent;
		kmem_stkinfo_log[index].t_tid = t->t_tid;
		kmem_stkinfo_log[index].cmd[0] = '\0';
		if (t->t_tid != 0) {
			stksz = strlen((t->t_procp)->p_user.u_comm);
			if (stksz >= KMEM_STKINFO_STR_SIZE) {
				stksz = KMEM_STKINFO_STR_SIZE - 1;
				kmem_stkinfo_log[index].cmd[stksz] = '\0';
			} else {
				stksz += 1;
			}
			(void) memcpy(kmem_stkinfo_log[index].cmd,
			    (t->t_procp)->p_user.u_comm, stksz);
		}
		if (percent < smallest_percent) {
			smallest_percent = percent;
		}
	}
	mutex_exit(&kmem_stkinfo_lock);
}

/*
 * Tunable kmem_stackinfo is set, compute stack utilization percentage.
 */
static size_t
stkinfo_percent(caddr_t t_stk, caddr_t t_stkbase, caddr_t sp)
{
	size_t percent;
	size_t s;

	if (t_stk > t_stkbase) {
		/* stack grows down */
		if (sp > t_stk) {
			return (0);
		}
		if (sp < t_stkbase) {
			return (100);
		}
		percent = t_stk - sp + 1;
		s = t_stk - t_stkbase + 1;
	} else {
		/* stack grows up */
		if (sp < t_stk) {
			return (0);
		}
		if (sp > t_stkbase) {
			return (100);
		}
		percent = sp - t_stk + 1;
		s = t_stkbase - t_stk + 1;
	}
	percent = ((100 * percent) / s) + 1;
	if (percent > 100) {
		percent = 100;
	}
	return (percent);
}
