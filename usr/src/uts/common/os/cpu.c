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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * Architecture-independent CPU control functions.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/kstat.h>
#include <sys/uadmin.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/debug.h>
#include <sys/cpupart.h>
#include <sys/lgrp.h>
#include <sys/pset.h>
#include <sys/pghw.h>
#include <sys/kmem.h>
#include <sys/kmem_impl.h>	/* to set per-cpu kmem_cache offset */
#include <sys/atomic.h>
#include <sys/callb.h>
#include <sys/vtrace.h>
#include <sys/cyclic.h>
#include <sys/bitmap.h>
#include <sys/nvpair.h>
#include <sys/pool_pset.h>
#include <sys/msacct.h>
#include <sys/time.h>
#include <sys/archsystm.h>
#include <sys/sdt.h>
#if defined(__x86) || defined(__amd64)
#include <sys/x86_archext.h>
#endif
#include <sys/callo.h>

extern int	mp_cpu_start(cpu_t *);
extern int	mp_cpu_stop(cpu_t *);
extern int	mp_cpu_poweron(cpu_t *);
extern int	mp_cpu_poweroff(cpu_t *);
extern int	mp_cpu_configure(int);
extern int	mp_cpu_unconfigure(int);
extern void	mp_cpu_faulted_enter(cpu_t *);
extern void	mp_cpu_faulted_exit(cpu_t *);

extern int cmp_cpu_to_chip(processorid_t cpuid);
#ifdef __sparcv9
extern char *cpu_fru_fmri(cpu_t *cp);
#endif

static void cpu_add_active_internal(cpu_t *cp);
static void cpu_remove_active(cpu_t *cp);
static void cpu_info_kstat_create(cpu_t *cp);
static void cpu_info_kstat_destroy(cpu_t *cp);
static void cpu_stats_kstat_create(cpu_t *cp);
static void cpu_stats_kstat_destroy(cpu_t *cp);

static int cpu_sys_stats_ks_update(kstat_t *ksp, int rw);
static int cpu_vm_stats_ks_update(kstat_t *ksp, int rw);
static int cpu_stat_ks_update(kstat_t *ksp, int rw);
static int cpu_state_change_hooks(int, cpu_setup_t, cpu_setup_t);

/*
 * cpu_lock protects ncpus, ncpus_online, cpu_flag, cpu_list, cpu_active,
 * max_cpu_seqid_ever, and dispatch queue reallocations.  The lock ordering with
 * respect to related locks is:
 *
 *	cpu_lock --> thread_free_lock  --->  p_lock  --->  thread_lock()
 *
 * Warning:  Certain sections of code do not use the cpu_lock when
 * traversing the cpu_list (e.g. mutex_vector_enter(), clock()).  Since
 * all cpus are paused during modifications to this list, a solution
 * to protect the list is too either disable kernel preemption while
 * walking the list, *or* recheck the cpu_next pointer at each
 * iteration in the loop.  Note that in no cases can any cached
 * copies of the cpu pointers be kept as they may become invalid.
 */
kmutex_t	cpu_lock;
cpu_t		*cpu_list;		/* list of all CPUs */
cpu_t		*clock_cpu_list;	/* used by clock to walk CPUs */
cpu_t		*cpu_active;		/* list of active CPUs */
static cpuset_t	cpu_available;		/* set of available CPUs */
cpuset_t	cpu_seqid_inuse;	/* which cpu_seqids are in use */

cpu_t		**cpu_seq;		/* ptrs to CPUs, indexed by seq_id */

/*
 * max_ncpus keeps the max cpus the system can have. Initially
 * it's NCPU, but since most archs scan the devtree for cpus
 * fairly early on during boot, the real max can be known before
 * ncpus is set (useful for early NCPU based allocations).
 */
int max_ncpus = NCPU;
/*
 * platforms that set max_ncpus to maxiumum number of cpus that can be
 * dynamically added will set boot_max_ncpus to the number of cpus found
 * at device tree scan time during boot.
 */
int boot_max_ncpus = -1;
int boot_ncpus = -1;
/*
 * Maximum possible CPU id.  This can never be >= NCPU since NCPU is
 * used to size arrays that are indexed by CPU id.
 */
processorid_t max_cpuid = NCPU - 1;

/*
 * Maximum cpu_seqid was given. This number can only grow and never shrink. It
 * can be used to optimize NCPU loops to avoid going through CPUs which were
 * never on-line.
 */
processorid_t max_cpu_seqid_ever = 0;

int ncpus = 1;
int ncpus_online = 1;

/*
 * CPU that we're trying to offline.  Protected by cpu_lock.
 */
cpu_t *cpu_inmotion;

/*
 * Can be raised to suppress further weakbinding, which are instead
 * satisfied by disabling preemption.  Must be raised/lowered under cpu_lock,
 * while individual thread weakbinding synchronization is done under thread
 * lock.
 */
int weakbindingbarrier;

/*
 * Variables used in pause_cpus().
 */
static volatile char safe_list[NCPU];

static struct _cpu_pause_info {
	int		cp_spl;		/* spl saved in pause_cpus() */
	volatile int	cp_go;		/* Go signal sent after all ready */
	int		cp_count;	/* # of CPUs to pause */
	ksema_t		cp_sem;		/* synch pause_cpus & cpu_pause */
	kthread_id_t	cp_paused;
	void		*(*cp_func)(void *);
} cpu_pause_info;

static kmutex_t pause_free_mutex;
static kcondvar_t pause_free_cv;


static struct cpu_sys_stats_ks_data {
	kstat_named_t cpu_ticks_idle;
	kstat_named_t cpu_ticks_user;
	kstat_named_t cpu_ticks_kernel;
	kstat_named_t cpu_ticks_wait;
	kstat_named_t cpu_nsec_idle;
	kstat_named_t cpu_nsec_user;
	kstat_named_t cpu_nsec_kernel;
	kstat_named_t cpu_nsec_dtrace;
	kstat_named_t cpu_nsec_intr;
	kstat_named_t cpu_load_intr;
	kstat_named_t wait_ticks_io;
	kstat_named_t dtrace_probes;
	kstat_named_t bread;
	kstat_named_t bwrite;
	kstat_named_t lread;
	kstat_named_t lwrite;
	kstat_named_t phread;
	kstat_named_t phwrite;
	kstat_named_t pswitch;
	kstat_named_t trap;
	kstat_named_t intr;
	kstat_named_t syscall;
	kstat_named_t sysread;
	kstat_named_t syswrite;
	kstat_named_t sysfork;
	kstat_named_t sysvfork;
	kstat_named_t sysexec;
	kstat_named_t readch;
	kstat_named_t writech;
	kstat_named_t rcvint;
	kstat_named_t xmtint;
	kstat_named_t mdmint;
	kstat_named_t rawch;
	kstat_named_t canch;
	kstat_named_t outch;
	kstat_named_t msg;
	kstat_named_t sema;
	kstat_named_t namei;
	kstat_named_t ufsiget;
	kstat_named_t ufsdirblk;
	kstat_named_t ufsipage;
	kstat_named_t ufsinopage;
	kstat_named_t procovf;
	kstat_named_t intrthread;
	kstat_named_t intrblk;
	kstat_named_t intrunpin;
	kstat_named_t idlethread;
	kstat_named_t inv_swtch;
	kstat_named_t nthreads;
	kstat_named_t cpumigrate;
	kstat_named_t xcalls;
	kstat_named_t mutex_adenters;
	kstat_named_t rw_rdfails;
	kstat_named_t rw_wrfails;
	kstat_named_t modload;
	kstat_named_t modunload;
	kstat_named_t bawrite;
	kstat_named_t iowait;
} cpu_sys_stats_ks_data_template = {
	{ "cpu_ticks_idle",	KSTAT_DATA_UINT64 },
	{ "cpu_ticks_user",	KSTAT_DATA_UINT64 },
	{ "cpu_ticks_kernel",	KSTAT_DATA_UINT64 },
	{ "cpu_ticks_wait",	KSTAT_DATA_UINT64 },
	{ "cpu_nsec_idle",	KSTAT_DATA_UINT64 },
	{ "cpu_nsec_user",	KSTAT_DATA_UINT64 },
	{ "cpu_nsec_kernel",	KSTAT_DATA_UINT64 },
	{ "cpu_nsec_dtrace",	KSTAT_DATA_UINT64 },
	{ "cpu_nsec_intr",	KSTAT_DATA_UINT64 },
	{ "cpu_load_intr",	KSTAT_DATA_UINT64 },
	{ "wait_ticks_io",	KSTAT_DATA_UINT64 },
	{ "dtrace_probes",	KSTAT_DATA_UINT64 },
	{ "bread",		KSTAT_DATA_UINT64 },
	{ "bwrite",		KSTAT_DATA_UINT64 },
	{ "lread",		KSTAT_DATA_UINT64 },
	{ "lwrite",		KSTAT_DATA_UINT64 },
	{ "phread",		KSTAT_DATA_UINT64 },
	{ "phwrite",		KSTAT_DATA_UINT64 },
	{ "pswitch",		KSTAT_DATA_UINT64 },
	{ "trap",		KSTAT_DATA_UINT64 },
	{ "intr",		KSTAT_DATA_UINT64 },
	{ "syscall",		KSTAT_DATA_UINT64 },
	{ "sysread",		KSTAT_DATA_UINT64 },
	{ "syswrite",		KSTAT_DATA_UINT64 },
	{ "sysfork",		KSTAT_DATA_UINT64 },
	{ "sysvfork",		KSTAT_DATA_UINT64 },
	{ "sysexec",		KSTAT_DATA_UINT64 },
	{ "readch",		KSTAT_DATA_UINT64 },
	{ "writech",		KSTAT_DATA_UINT64 },
	{ "rcvint",		KSTAT_DATA_UINT64 },
	{ "xmtint",		KSTAT_DATA_UINT64 },
	{ "mdmint",		KSTAT_DATA_UINT64 },
	{ "rawch",		KSTAT_DATA_UINT64 },
	{ "canch",		KSTAT_DATA_UINT64 },
	{ "outch",		KSTAT_DATA_UINT64 },
	{ "msg",		KSTAT_DATA_UINT64 },
	{ "sema",		KSTAT_DATA_UINT64 },
	{ "namei",		KSTAT_DATA_UINT64 },
	{ "ufsiget",		KSTAT_DATA_UINT64 },
	{ "ufsdirblk",		KSTAT_DATA_UINT64 },
	{ "ufsipage",		KSTAT_DATA_UINT64 },
	{ "ufsinopage",		KSTAT_DATA_UINT64 },
	{ "procovf",		KSTAT_DATA_UINT64 },
	{ "intrthread",		KSTAT_DATA_UINT64 },
	{ "intrblk",		KSTAT_DATA_UINT64 },
	{ "intrunpin",		KSTAT_DATA_UINT64 },
	{ "idlethread",		KSTAT_DATA_UINT64 },
	{ "inv_swtch",		KSTAT_DATA_UINT64 },
	{ "nthreads",		KSTAT_DATA_UINT64 },
	{ "cpumigrate",		KSTAT_DATA_UINT64 },
	{ "xcalls",		KSTAT_DATA_UINT64 },
	{ "mutex_adenters",	KSTAT_DATA_UINT64 },
	{ "rw_rdfails",		KSTAT_DATA_UINT64 },
	{ "rw_wrfails",		KSTAT_DATA_UINT64 },
	{ "modload",		KSTAT_DATA_UINT64 },
	{ "modunload",		KSTAT_DATA_UINT64 },
	{ "bawrite",		KSTAT_DATA_UINT64 },
	{ "iowait",		KSTAT_DATA_UINT64 },
};

static struct cpu_vm_stats_ks_data {
	kstat_named_t pgrec;
	kstat_named_t pgfrec;
	kstat_named_t pgin;
	kstat_named_t pgpgin;
	kstat_named_t pgout;
	kstat_named_t pgpgout;
	kstat_named_t swapin;
	kstat_named_t pgswapin;
	kstat_named_t swapout;
	kstat_named_t pgswapout;
	kstat_named_t zfod;
	kstat_named_t dfree;
	kstat_named_t scan;
	kstat_named_t rev;
	kstat_named_t hat_fault;
	kstat_named_t as_fault;
	kstat_named_t maj_fault;
	kstat_named_t cow_fault;
	kstat_named_t prot_fault;
	kstat_named_t softlock;
	kstat_named_t kernel_asflt;
	kstat_named_t pgrrun;
	kstat_named_t execpgin;
	kstat_named_t execpgout;
	kstat_named_t execfree;
	kstat_named_t anonpgin;
	kstat_named_t anonpgout;
	kstat_named_t anonfree;
	kstat_named_t fspgin;
	kstat_named_t fspgout;
	kstat_named_t fsfree;
} cpu_vm_stats_ks_data_template = {
	{ "pgrec",		KSTAT_DATA_UINT64 },
	{ "pgfrec",		KSTAT_DATA_UINT64 },
	{ "pgin",		KSTAT_DATA_UINT64 },
	{ "pgpgin",		KSTAT_DATA_UINT64 },
	{ "pgout",		KSTAT_DATA_UINT64 },
	{ "pgpgout",		KSTAT_DATA_UINT64 },
	{ "swapin",		KSTAT_DATA_UINT64 },
	{ "pgswapin",		KSTAT_DATA_UINT64 },
	{ "swapout",		KSTAT_DATA_UINT64 },
	{ "pgswapout",		KSTAT_DATA_UINT64 },
	{ "zfod",		KSTAT_DATA_UINT64 },
	{ "dfree",		KSTAT_DATA_UINT64 },
	{ "scan",		KSTAT_DATA_UINT64 },
	{ "rev",		KSTAT_DATA_UINT64 },
	{ "hat_fault",		KSTAT_DATA_UINT64 },
	{ "as_fault",		KSTAT_DATA_UINT64 },
	{ "maj_fault",		KSTAT_DATA_UINT64 },
	{ "cow_fault",		KSTAT_DATA_UINT64 },
	{ "prot_fault",		KSTAT_DATA_UINT64 },
	{ "softlock",		KSTAT_DATA_UINT64 },
	{ "kernel_asflt",	KSTAT_DATA_UINT64 },
	{ "pgrrun",		KSTAT_DATA_UINT64 },
	{ "execpgin",		KSTAT_DATA_UINT64 },
	{ "execpgout",		KSTAT_DATA_UINT64 },
	{ "execfree",		KSTAT_DATA_UINT64 },
	{ "anonpgin",		KSTAT_DATA_UINT64 },
	{ "anonpgout",		KSTAT_DATA_UINT64 },
	{ "anonfree",		KSTAT_DATA_UINT64 },
	{ "fspgin",		KSTAT_DATA_UINT64 },
	{ "fspgout",		KSTAT_DATA_UINT64 },
	{ "fsfree",		KSTAT_DATA_UINT64 },
};

/*
 * Force the specified thread to migrate to the appropriate processor.
 * Called with thread lock held, returns with it dropped.
 */
static void
force_thread_migrate(kthread_id_t tp)
{
	ASSERT(THREAD_LOCK_HELD(tp));
	if (tp == curthread) {
		THREAD_TRANSITION(tp);
		CL_SETRUN(tp);
		thread_unlock_nopreempt(tp);
		swtch();
	} else {
		if (tp->t_state == TS_ONPROC) {
			cpu_surrender(tp);
		} else if (tp->t_state == TS_RUN) {
			(void) dispdeq(tp);
			setbackdq(tp);
		}
		thread_unlock(tp);
	}
}

/*
 * Set affinity for a specified CPU.
 * A reference count is incremented and the affinity is held until the
 * reference count is decremented to zero by thread_affinity_clear().
 * This is so regions of code requiring affinity can be nested.
 * Caller needs to ensure that cpu_id remains valid, which can be
 * done by holding cpu_lock across this call, unless the caller
 * specifies CPU_CURRENT in which case the cpu_lock will be acquired
 * by thread_affinity_set and CPU->cpu_id will be the target CPU.
 */
void
thread_affinity_set(kthread_id_t t, int cpu_id)
{
	cpu_t		*cp;
	int		c;

	ASSERT(!(t == curthread && t->t_weakbound_cpu != NULL));

	if ((c = cpu_id) == CPU_CURRENT) {
		mutex_enter(&cpu_lock);
		cpu_id = CPU->cpu_id;
	}
	/*
	 * We should be asserting that cpu_lock is held here, but
	 * the NCA code doesn't acquire it.  The following assert
	 * should be uncommented when the NCA code is fixed.
	 *
	 * ASSERT(MUTEX_HELD(&cpu_lock));
	 */
	ASSERT((cpu_id >= 0) && (cpu_id < NCPU));
	cp = cpu[cpu_id];
	ASSERT(cp != NULL);		/* user must provide a good cpu_id */
	/*
	 * If there is already a hard affinity requested, and this affinity
	 * conflicts with that, panic.
	 */
	thread_lock(t);
	if (t->t_affinitycnt > 0 && t->t_bound_cpu != cp) {
		panic("affinity_set: setting %p but already bound to %p",
		    (void *)cp, (void *)t->t_bound_cpu);
	}
	t->t_affinitycnt++;
	t->t_bound_cpu = cp;

	/*
	 * Make sure we're running on the right CPU.
	 */
	if (cp != t->t_cpu || t != curthread) {
		force_thread_migrate(t);	/* drops thread lock */
	} else {
		thread_unlock(t);
	}

	if (c == CPU_CURRENT)
		mutex_exit(&cpu_lock);
}

/*
 *	Wrapper for backward compatibility.
 */
void
affinity_set(int cpu_id)
{
	thread_affinity_set(curthread, cpu_id);
}

/*
 * Decrement the affinity reservation count and if it becomes zero,
 * clear the CPU affinity for the current thread, or set it to the user's
 * software binding request.
 */
void
thread_affinity_clear(kthread_id_t t)
{
	register processorid_t binding;

	thread_lock(t);
	if (--t->t_affinitycnt == 0) {
		if ((binding = t->t_bind_cpu) == PBIND_NONE) {
			/*
			 * Adjust disp_max_unbound_pri if necessary.
			 */
			disp_adjust_unbound_pri(t);
			t->t_bound_cpu = NULL;
			if (t->t_cpu->cpu_part != t->t_cpupart) {
				force_thread_migrate(t);
				return;
			}
		} else {
			t->t_bound_cpu = cpu[binding];
			/*
			 * Make sure the thread is running on the bound CPU.
			 */
			if (t->t_cpu != t->t_bound_cpu) {
				force_thread_migrate(t);
				return;		/* already dropped lock */
			}
		}
	}
	thread_unlock(t);
}

/*
 * Wrapper for backward compatibility.
 */
void
affinity_clear(void)
{
	thread_affinity_clear(curthread);
}

/*
 * Weak cpu affinity.  Bind to the "current" cpu for short periods
 * of time during which the thread must not block (but may be preempted).
 * Use this instead of kpreempt_disable() when it is only "no migration"
 * rather than "no preemption" semantics that are required - disabling
 * preemption holds higher priority threads off of cpu and if the
 * operation that is protected is more than momentary this is not good
 * for realtime etc.
 *
 * Weakly bound threads will not prevent a cpu from being offlined -
 * we'll only run them on the cpu to which they are weakly bound but
 * (because they do not block) we'll always be able to move them on to
 * another cpu at offline time if we give them just a short moment to
 * run during which they will unbind.  To give a cpu a chance of offlining,
 * however, we require a barrier to weak bindings that may be raised for a
 * given cpu (offline/move code may set this and then wait a short time for
 * existing weak bindings to drop); the cpu_inmotion pointer is that barrier.
 *
 * There are few restrictions on the calling context of thread_nomigrate.
 * The caller must not hold the thread lock.  Calls may be nested.
 *
 * After weakbinding a thread must not perform actions that may block.
 * In particular it must not call thread_affinity_set; calling that when
 * already weakbound is nonsensical anyway.
 *
 * If curthread is prevented from migrating for other reasons
 * (kernel preemption disabled; high pil; strongly bound; interrupt thread)
 * then the weak binding will succeed even if this cpu is the target of an
 * offline/move request.
 */
void
thread_nomigrate(void)
{
	cpu_t *cp;
	kthread_id_t t = curthread;

again:
	kpreempt_disable();
	cp = CPU;

	/*
	 * A highlevel interrupt must not modify t_nomigrate or
	 * t_weakbound_cpu of the thread it has interrupted.  A lowlevel
	 * interrupt thread cannot migrate and we can avoid the
	 * thread_lock call below by short-circuiting here.  In either
	 * case we can just return since no migration is possible and
	 * the condition will persist (ie, when we test for these again
	 * in thread_allowmigrate they can't have changed).   Migration
	 * is also impossible if we're at or above DISP_LEVEL pil.
	 */
	if (CPU_ON_INTR(cp) || t->t_flag & T_INTR_THREAD ||
	    getpil() >= DISP_LEVEL) {
		kpreempt_enable();
		return;
	}

	/*
	 * We must be consistent with existing weak bindings.  Since we
	 * may be interrupted between the increment of t_nomigrate and
	 * the store to t_weakbound_cpu below we cannot assume that
	 * t_weakbound_cpu will be set if t_nomigrate is.  Note that we
	 * cannot assert t_weakbound_cpu == t_bind_cpu since that is not
	 * always the case.
	 */
	if (t->t_nomigrate && t->t_weakbound_cpu && t->t_weakbound_cpu != cp) {
		if (!panicstr)
			panic("thread_nomigrate: binding to %p but already "
			    "bound to %p", (void *)cp,
			    (void *)t->t_weakbound_cpu);
	}

	/*
	 * At this point we have preemption disabled and we don't yet hold
	 * the thread lock.  So it's possible that somebody else could
	 * set t_bind_cpu here and not be able to force us across to the
	 * new cpu (since we have preemption disabled).
	 */
	thread_lock(curthread);

	/*
	 * If further weak bindings are being (temporarily) suppressed then
	 * we'll settle for disabling kernel preemption (which assures
	 * no migration provided the thread does not block which it is
	 * not allowed to if using thread_nomigrate).  We must remember
	 * this disposition so we can take appropriate action in
	 * thread_allowmigrate.  If this is a nested call and the
	 * thread is already weakbound then fall through as normal.
	 * We remember the decision to settle for kpreempt_disable through
	 * negative nesting counting in t_nomigrate.  Once a thread has had one
	 * weakbinding request satisfied in this way any further (nested)
	 * requests will continue to be satisfied in the same way,
	 * even if weak bindings have recommenced.
	 */
	if (t->t_nomigrate < 0 || weakbindingbarrier && t->t_nomigrate == 0) {
		--t->t_nomigrate;
		thread_unlock(curthread);
		return;		/* with kpreempt_disable still active */
	}

	/*
	 * We hold thread_lock so t_bind_cpu cannot change.  We could,
	 * however, be running on a different cpu to which we are t_bound_cpu
	 * to (as explained above).  If we grant the weak binding request
	 * in that case then the dispatcher must favour our weak binding
	 * over our strong (in which case, just as when preemption is
	 * disabled, we can continue to run on a cpu other than the one to
	 * which we are strongbound; the difference in this case is that
	 * this thread can be preempted and so can appear on the dispatch
	 * queues of a cpu other than the one it is strongbound to).
	 *
	 * If the cpu we are running on does not appear to be a current
	 * offline target (we check cpu_inmotion to determine this - since
	 * we don't hold cpu_lock we may not see a recent store to that,
	 * so it's possible that we at times can grant a weak binding to a
	 * cpu that is an offline target, but that one request will not
	 * prevent the offline from succeeding) then we will always grant
	 * the weak binding request.  This includes the case above where
	 * we grant a weakbinding not commensurate with our strong binding.
	 *
	 * If our cpu does appear to be an offline target then we're inclined
	 * not to grant the weakbinding request just yet - we'd prefer to
	 * migrate to another cpu and grant the request there.  The
	 * exceptions are those cases where going through preemption code
	 * will not result in us changing cpu:
	 *
	 *	. interrupts have already bypassed this case (see above)
	 *	. we are already weakbound to this cpu (dispatcher code will
	 *	  always return us to the weakbound cpu)
	 *	. preemption was disabled even before we disabled it above
	 *	. we are strongbound to this cpu (if we're strongbound to
	 *	another and not yet running there the trip through the
	 *	dispatcher will move us to the strongbound cpu and we
	 *	will grant the weak binding there)
	 */
	if (cp != cpu_inmotion || t->t_nomigrate > 0 || t->t_preempt > 1 ||
	    t->t_bound_cpu == cp) {
		/*
		 * Don't be tempted to store to t_weakbound_cpu only on
		 * the first nested bind request - if we're interrupted
		 * after the increment of t_nomigrate and before the
		 * store to t_weakbound_cpu and the interrupt calls
		 * thread_nomigrate then the assertion in thread_allowmigrate
		 * would fail.
		 */
		t->t_nomigrate++;
		t->t_weakbound_cpu = cp;
		membar_producer();
		thread_unlock(curthread);
		/*
		 * Now that we have dropped the thread_lock another thread
		 * can set our t_weakbound_cpu, and will try to migrate us
		 * to the strongbound cpu (which will not be prevented by
		 * preemption being disabled since we're about to enable
		 * preemption).  We have granted the weakbinding to the current
		 * cpu, so again we are in the position that is is is possible
		 * that our weak and strong bindings differ.  Again this
		 * is catered for by dispatcher code which will favour our
		 * weak binding.
		 */
		kpreempt_enable();
	} else {
		/*
		 * Move to another cpu before granting the request by
		 * forcing this thread through preemption code.  When we
		 * get to set{front,back}dq called from CL_PREEMPT()
		 * cpu_choose() will be used to select a cpu to queue
		 * us on - that will see cpu_inmotion and take
		 * steps to avoid returning us to this cpu.
		 */
		cp->cpu_kprunrun = 1;
		thread_unlock(curthread);
		kpreempt_enable();	/* will call preempt() */
		goto again;
	}
}

void
thread_allowmigrate(void)
{
	kthread_id_t t = curthread;

	ASSERT(t->t_weakbound_cpu == CPU ||
	    (t->t_nomigrate < 0 && t->t_preempt > 0) ||
	    CPU_ON_INTR(CPU) || t->t_flag & T_INTR_THREAD ||
	    getpil() >= DISP_LEVEL);

	if (CPU_ON_INTR(CPU) || (t->t_flag & T_INTR_THREAD) ||
	    getpil() >= DISP_LEVEL)
		return;

	if (t->t_nomigrate < 0) {
		/*
		 * This thread was granted "weak binding" in the
		 * stronger form of kernel preemption disabling.
		 * Undo a level of nesting for both t_nomigrate
		 * and t_preempt.
		 */
		++t->t_nomigrate;
		kpreempt_enable();
	} else if (--t->t_nomigrate == 0) {
		/*
		 * Time to drop the weak binding.  We need to cater
		 * for the case where we're weakbound to a different
		 * cpu than that to which we're strongbound (a very
		 * temporary arrangement that must only persist until
		 * weak binding drops).  We don't acquire thread_lock
		 * here so even as this code executes t_bound_cpu
		 * may be changing.  So we disable preemption and
		 * a) in the case that t_bound_cpu changes while we
		 * have preemption disabled kprunrun will be set
		 * asynchronously, and b) if before disabling
		 * preemption we were already on a different cpu to
		 * our t_bound_cpu then we set kprunrun ourselves
		 * to force a trip through the dispatcher when
		 * preemption is enabled.
		 */
		kpreempt_disable();
		if (t->t_bound_cpu &&
		    t->t_weakbound_cpu != t->t_bound_cpu)
			CPU->cpu_kprunrun = 1;
		t->t_weakbound_cpu = NULL;
		membar_producer();
		kpreempt_enable();
	}
}

/*
 * weakbinding_stop can be used to temporarily cause weakbindings made
 * with thread_nomigrate to be satisfied through the stronger action of
 * kpreempt_disable.  weakbinding_start recommences normal weakbinding.
 */

void
weakbinding_stop(void)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	weakbindingbarrier = 1;
	membar_producer();	/* make visible before subsequent thread_lock */
}

void
weakbinding_start(void)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	weakbindingbarrier = 0;
}

void
null_xcall(void)
{
}

/*
 * This routine is called to place the CPUs in a safe place so that
 * one of them can be taken off line or placed on line.  What we are
 * trying to do here is prevent a thread from traversing the list
 * of active CPUs while we are changing it or from getting placed on
 * the run queue of a CPU that has just gone off line.  We do this by
 * creating a thread with the highest possible prio for each CPU and
 * having it call this routine.  The advantage of this method is that
 * we can eliminate all checks for CPU_ACTIVE in the disp routines.
 * This makes disp faster at the expense of making p_online() slower
 * which is a good trade off.
 */
static void
cpu_pause(int index)
{
	int s;
	struct _cpu_pause_info *cpi = &cpu_pause_info;
	volatile char *safe = &safe_list[index];
	long    lindex = index;

	ASSERT((curthread->t_bound_cpu != NULL) || (*safe == PAUSE_DIE));

	while (*safe != PAUSE_DIE) {
		*safe = PAUSE_READY;
		membar_enter();		/* make sure stores are flushed */
		sema_v(&cpi->cp_sem);	/* signal requesting thread */

		/*
		 * Wait here until all pause threads are running.  That
		 * indicates that it's safe to do the spl.  Until
		 * cpu_pause_info.cp_go is set, we don't want to spl
		 * because that might block clock interrupts needed
		 * to preempt threads on other CPUs.
		 */
		while (cpi->cp_go == 0)
			;
		/*
		 * Even though we are at the highest disp prio, we need
		 * to block out all interrupts below LOCK_LEVEL so that
		 * an intr doesn't come in, wake up a thread, and call
		 * setbackdq/setfrontdq.
		 */
		s = splhigh();
		/*
		 * if cp_func has been set then call it using index as the
		 * argument, currently only used by cpr_suspend_cpus().
		 * This function is used as the code to execute on the
		 * "paused" cpu's when a machine comes out of a sleep state
		 * and CPU's were powered off.  (could also be used for
		 * hotplugging CPU's).
		 */
		if (cpi->cp_func != NULL)
			(*cpi->cp_func)((void *)lindex);

		mach_cpu_pause(safe);

		splx(s);
		/*
		 * Waiting is at an end. Switch out of cpu_pause
		 * loop and resume useful work.
		 */
		swtch();
	}

	mutex_enter(&pause_free_mutex);
	*safe = PAUSE_DEAD;
	cv_broadcast(&pause_free_cv);
	mutex_exit(&pause_free_mutex);
}

/*
 * Allow the cpus to start running again.
 */
void
start_cpus()
{
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu_pause_info.cp_paused);
	cpu_pause_info.cp_paused = NULL;
	for (i = 0; i < NCPU; i++)
		safe_list[i] = PAUSE_IDLE;
	membar_enter();			/* make sure stores are flushed */
	affinity_clear();
	splx(cpu_pause_info.cp_spl);
	kpreempt_enable();
}

/*
 * Allocate a pause thread for a CPU.
 */
static void
cpu_pause_alloc(cpu_t *cp)
{
	kthread_id_t	t;
	long		cpun = cp->cpu_id;

	/*
	 * Note, v.v_nglobpris will not change value as long as I hold
	 * cpu_lock.
	 */
	t = thread_create(NULL, 0, cpu_pause, (void *)cpun,
	    0, &p0, TS_STOPPED, v.v_nglobpris - 1);
	thread_lock(t);
	t->t_bound_cpu = cp;
	t->t_disp_queue = cp->cpu_disp;
	t->t_affinitycnt = 1;
	t->t_preempt = 1;
	thread_unlock(t);
	cp->cpu_pause_thread = t;
	/*
	 * Registering a thread in the callback table is usually done
	 * in the initialization code of the thread.  In this
	 * case, we do it right after thread creation because the
	 * thread itself may never run, and we need to register the
	 * fact that it is safe for cpr suspend.
	 */
	CALLB_CPR_INIT_SAFE(t, "cpu_pause");
}

/*
 * Free a pause thread for a CPU.
 */
static void
cpu_pause_free(cpu_t *cp)
{
	kthread_id_t	t;
	int		cpun = cp->cpu_id;

	ASSERT(MUTEX_HELD(&cpu_lock));
	/*
	 * We have to get the thread and tell it to die.
	 */
	if ((t = cp->cpu_pause_thread) == NULL) {
		ASSERT(safe_list[cpun] == PAUSE_IDLE);
		return;
	}
	thread_lock(t);
	t->t_cpu = CPU;		/* disp gets upset if last cpu is quiesced. */
	t->t_bound_cpu = NULL;	/* Must un-bind; cpu may not be running. */
	t->t_pri = v.v_nglobpris - 1;
	ASSERT(safe_list[cpun] == PAUSE_IDLE);
	safe_list[cpun] = PAUSE_DIE;
	THREAD_TRANSITION(t);
	setbackdq(t);
	thread_unlock_nopreempt(t);

	/*
	 * If we don't wait for the thread to actually die, it may try to
	 * run on the wrong cpu as part of an actual call to pause_cpus().
	 */
	mutex_enter(&pause_free_mutex);
	while (safe_list[cpun] != PAUSE_DEAD) {
		cv_wait(&pause_free_cv, &pause_free_mutex);
	}
	mutex_exit(&pause_free_mutex);
	safe_list[cpun] = PAUSE_IDLE;

	cp->cpu_pause_thread = NULL;
}

/*
 * Initialize basic structures for pausing CPUs.
 */
void
cpu_pause_init()
{
	sema_init(&cpu_pause_info.cp_sem, 0, NULL, SEMA_DEFAULT, NULL);
	/*
	 * Create initial CPU pause thread.
	 */
	cpu_pause_alloc(CPU);
}

/*
 * Start the threads used to pause another CPU.
 */
static int
cpu_pause_start(processorid_t cpu_id)
{
	int	i;
	int	cpu_count = 0;

	for (i = 0; i < NCPU; i++) {
		cpu_t		*cp;
		kthread_id_t	t;

		cp = cpu[i];
		if (!CPU_IN_SET(cpu_available, i) || (i == cpu_id)) {
			safe_list[i] = PAUSE_WAIT;
			continue;
		}

		/*
		 * Skip CPU if it is quiesced or not yet started.
		 */
		if ((cp->cpu_flags & (CPU_QUIESCED | CPU_READY)) != CPU_READY) {
			safe_list[i] = PAUSE_WAIT;
			continue;
		}

		/*
		 * Start this CPU's pause thread.
		 */
		t = cp->cpu_pause_thread;
		thread_lock(t);
		/*
		 * Reset the priority, since nglobpris may have
		 * changed since the thread was created, if someone
		 * has loaded the RT (or some other) scheduling
		 * class.
		 */
		t->t_pri = v.v_nglobpris - 1;
		THREAD_TRANSITION(t);
		setbackdq(t);
		thread_unlock_nopreempt(t);
		++cpu_count;
	}
	return (cpu_count);
}


/*
 * Pause all of the CPUs except the one we are on by creating a high
 * priority thread bound to those CPUs.
 *
 * Note that one must be extremely careful regarding code
 * executed while CPUs are paused.  Since a CPU may be paused
 * while a thread scheduling on that CPU is holding an adaptive
 * lock, code executed with CPUs paused must not acquire adaptive
 * (or low-level spin) locks.  Also, such code must not block,
 * since the thread that is supposed to initiate the wakeup may
 * never run.
 *
 * With a few exceptions, the restrictions on code executed with CPUs
 * paused match those for code executed at high-level interrupt
 * context.
 */
void
pause_cpus(cpu_t *off_cp, void *(*func)(void *))
{
	processorid_t	cpu_id;
	int		i;
	struct _cpu_pause_info	*cpi = &cpu_pause_info;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpi->cp_paused == NULL);
	cpi->cp_count = 0;
	cpi->cp_go = 0;
	for (i = 0; i < NCPU; i++)
		safe_list[i] = PAUSE_IDLE;
	kpreempt_disable();

	cpi->cp_func = func;

	/*
	 * If running on the cpu that is going offline, get off it.
	 * This is so that it won't be necessary to rechoose a CPU
	 * when done.
	 */
	if (CPU == off_cp)
		cpu_id = off_cp->cpu_next_part->cpu_id;
	else
		cpu_id = CPU->cpu_id;
	affinity_set(cpu_id);

	/*
	 * Start the pause threads and record how many were started
	 */
	cpi->cp_count = cpu_pause_start(cpu_id);

	/*
	 * Now wait for all CPUs to be running the pause thread.
	 */
	while (cpi->cp_count > 0) {
		/*
		 * Spin reading the count without grabbing the disp
		 * lock to make sure we don't prevent the pause
		 * threads from getting the lock.
		 */
		while (sema_held(&cpi->cp_sem))
			;
		if (sema_tryp(&cpi->cp_sem))
			--cpi->cp_count;
	}
	cpi->cp_go = 1;			/* all have reached cpu_pause */

	/*
	 * Now wait for all CPUs to spl. (Transition from PAUSE_READY
	 * to PAUSE_WAIT.)
	 */
	for (i = 0; i < NCPU; i++) {
		while (safe_list[i] != PAUSE_WAIT)
			;
	}
	cpi->cp_spl = splhigh();	/* block dispatcher on this CPU */
	cpi->cp_paused = curthread;
}

/*
 * Check whether the current thread has CPUs paused
 */
int
cpus_paused(void)
{
	if (cpu_pause_info.cp_paused != NULL) {
		ASSERT(cpu_pause_info.cp_paused == curthread);
		return (1);
	}
	return (0);
}

static cpu_t *
cpu_get_all(processorid_t cpun)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cpun >= NCPU || cpun < 0 || !CPU_IN_SET(cpu_available, cpun))
		return (NULL);
	return (cpu[cpun]);
}

/*
 * Check whether cpun is a valid processor id and whether it should be
 * visible from the current zone. If it is, return a pointer to the
 * associated CPU structure.
 */
cpu_t *
cpu_get(processorid_t cpun)
{
	cpu_t *c;

	ASSERT(MUTEX_HELD(&cpu_lock));
	c = cpu_get_all(cpun);
	if (c != NULL && !INGLOBALZONE(curproc) && pool_pset_enabled() &&
	    zone_pset_get(curproc->p_zone) != cpupart_query_cpu(c))
		return (NULL);
	return (c);
}

/*
 * The following functions should be used to check CPU states in the kernel.
 * They should be invoked with cpu_lock held.  Kernel subsystems interested
 * in CPU states should *not* use cpu_get_state() and various P_ONLINE/etc
 * states.  Those are for user-land (and system call) use only.
 */

/*
 * Determine whether the CPU is online and handling interrupts.
 */
int
cpu_is_online(cpu_t *cpu)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (cpu_flagged_online(cpu->cpu_flags));
}

/*
 * Determine whether the CPU is offline (this includes spare and faulted).
 */
int
cpu_is_offline(cpu_t *cpu)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (cpu_flagged_offline(cpu->cpu_flags));
}

/*
 * Determine whether the CPU is powered off.
 */
int
cpu_is_poweredoff(cpu_t *cpu)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (cpu_flagged_poweredoff(cpu->cpu_flags));
}

/*
 * Determine whether the CPU is handling interrupts.
 */
int
cpu_is_nointr(cpu_t *cpu)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (cpu_flagged_nointr(cpu->cpu_flags));
}

/*
 * Determine whether the CPU is active (scheduling threads).
 */
int
cpu_is_active(cpu_t *cpu)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (cpu_flagged_active(cpu->cpu_flags));
}

/*
 * Same as above, but these require cpu_flags instead of cpu_t pointers.
 */
int
cpu_flagged_online(cpu_flag_t cpu_flags)
{
	return (cpu_flagged_active(cpu_flags) &&
	    (cpu_flags & CPU_ENABLE));
}

int
cpu_flagged_offline(cpu_flag_t cpu_flags)
{
	return (((cpu_flags & CPU_POWEROFF) == 0) &&
	    ((cpu_flags & (CPU_READY | CPU_OFFLINE)) != CPU_READY));
}

int
cpu_flagged_poweredoff(cpu_flag_t cpu_flags)
{
	return ((cpu_flags & CPU_POWEROFF) == CPU_POWEROFF);
}

int
cpu_flagged_nointr(cpu_flag_t cpu_flags)
{
	return (cpu_flagged_active(cpu_flags) &&
	    (cpu_flags & CPU_ENABLE) == 0);
}

int
cpu_flagged_active(cpu_flag_t cpu_flags)
{
	return (((cpu_flags & (CPU_POWEROFF | CPU_FAULTED | CPU_SPARE)) == 0) &&
	    ((cpu_flags & (CPU_READY | CPU_OFFLINE)) == CPU_READY));
}

/*
 * Bring the indicated CPU online.
 */
int
cpu_online(cpu_t *cp)
{
	int	error = 0;

	/*
	 * Handle on-line request.
	 *	This code must put the new CPU on the active list before
	 *	starting it because it will not be paused, and will start
	 * 	using the active list immediately.  The real start occurs
	 *	when the CPU_QUIESCED flag is turned off.
	 */

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Put all the cpus into a known safe place.
	 * No mutexes can be entered while CPUs are paused.
	 */
	error = mp_cpu_start(cp);	/* arch-dep hook */
	if (error == 0) {
		pg_cpupart_in(cp, cp->cpu_part);
		pause_cpus(NULL, NULL);
		cpu_add_active_internal(cp);
		if (cp->cpu_flags & CPU_FAULTED) {
			cp->cpu_flags &= ~CPU_FAULTED;
			mp_cpu_faulted_exit(cp);
		}
		cp->cpu_flags &= ~(CPU_QUIESCED | CPU_OFFLINE | CPU_FROZEN |
		    CPU_SPARE);
		CPU_NEW_GENERATION(cp);
		start_cpus();
		cpu_stats_kstat_create(cp);
		cpu_create_intrstat(cp);
		lgrp_kstat_create(cp);
		cpu_state_change_notify(cp->cpu_id, CPU_ON);
		cpu_intr_enable(cp);	/* arch-dep hook */
		cpu_state_change_notify(cp->cpu_id, CPU_INTR_ON);
		cpu_set_state(cp);
		cyclic_online(cp);
		/*
		 * This has to be called only after cyclic_online(). This
		 * function uses cyclics.
		 */
		callout_cpu_online(cp);
		poke_cpu(cp->cpu_id);
	}

	return (error);
}

/*
 * Take the indicated CPU offline.
 */
int
cpu_offline(cpu_t *cp, int flags)
{
	cpupart_t *pp;
	int	error = 0;
	cpu_t	*ncp;
	int	intr_enable;
	int	cyclic_off = 0;
	int	callout_off = 0;
	int	loop_count;
	int	no_quiesce = 0;
	int	(*bound_func)(struct cpu *, int);
	kthread_t *t;
	lpl_t	*cpu_lpl;
	proc_t	*p;
	int	lgrp_diff_lpl;
	boolean_t unbind_all_threads = (flags & CPU_FORCED) != 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * If we're going from faulted or spare to offline, just
	 * clear these flags and update CPU state.
	 */
	if (cp->cpu_flags & (CPU_FAULTED | CPU_SPARE)) {
		if (cp->cpu_flags & CPU_FAULTED) {
			cp->cpu_flags &= ~CPU_FAULTED;
			mp_cpu_faulted_exit(cp);
		}
		cp->cpu_flags &= ~CPU_SPARE;
		cpu_set_state(cp);
		return (0);
	}

	/*
	 * Handle off-line request.
	 */
	pp = cp->cpu_part;
	/*
	 * Don't offline last online CPU in partition
	 */
	if (ncpus_online <= 1 || pp->cp_ncpus <= 1 || cpu_intr_count(cp) < 2)
		return (EBUSY);
	/*
	 * Unbind all soft-bound threads bound to our CPU and hard bound threads
	 * if we were asked to.
	 */
	error = cpu_unbind(cp->cpu_id, unbind_all_threads);
	if (error != 0)
		return (error);
	/*
	 * We shouldn't be bound to this CPU ourselves.
	 */
	if (curthread->t_bound_cpu == cp)
		return (EBUSY);

	/*
	 * Tell interested parties that this CPU is going offline.
	 */
	CPU_NEW_GENERATION(cp);
	cpu_state_change_notify(cp->cpu_id, CPU_OFF);

	/*
	 * Tell the PG subsystem that the CPU is leaving the partition
	 */
	pg_cpupart_out(cp, pp);

	/*
	 * Take the CPU out of interrupt participation so we won't find
	 * bound kernel threads.  If the architecture cannot completely
	 * shut off interrupts on the CPU, don't quiesce it, but don't
	 * run anything but interrupt thread... this is indicated by
	 * the CPU_OFFLINE flag being on but the CPU_QUIESCE flag being
	 * off.
	 */
	intr_enable = cp->cpu_flags & CPU_ENABLE;
	if (intr_enable)
		no_quiesce = cpu_intr_disable(cp);

	/*
	 * Record that we are aiming to offline this cpu.  This acts as
	 * a barrier to further weak binding requests in thread_nomigrate
	 * and also causes cpu_choose, disp_lowpri_cpu and setfrontdq to
	 * lean away from this cpu.  Further strong bindings are already
	 * avoided since we hold cpu_lock.  Since threads that are set
	 * runnable around now and others coming off the target cpu are
	 * directed away from the target, existing strong and weak bindings
	 * (especially the latter) to the target cpu stand maximum chance of
	 * being able to unbind during the short delay loop below (if other
	 * unbound threads compete they may not see cpu in time to unbind
	 * even if they would do so immediately.
	 */
	cpu_inmotion = cp;
	membar_enter();

	/*
	 * Check for kernel threads (strong or weak) bound to that CPU.
	 * Strongly bound threads may not unbind, and we'll have to return
	 * EBUSY.  Weakly bound threads should always disappear - we've
	 * stopped more weak binding with cpu_inmotion and existing
	 * bindings will drain imminently (they may not block).  Nonetheless
	 * we will wait for a fixed period for all bound threads to disappear.
	 * Inactive interrupt threads are OK (they'll be in TS_FREE
	 * state).  If test finds some bound threads, wait a few ticks
	 * to give short-lived threads (such as interrupts) chance to
	 * complete.  Note that if no_quiesce is set, i.e. this cpu
	 * is required to service interrupts, then we take the route
	 * that permits interrupt threads to be active (or bypassed).
	 */
	bound_func = no_quiesce ? disp_bound_threads : disp_bound_anythreads;

again:	for (loop_count = 0; (*bound_func)(cp, 0); loop_count++) {
		if (loop_count >= 5) {
			error = EBUSY;	/* some threads still bound */
			break;
		}

		/*
		 * If some threads were assigned, give them
		 * a chance to complete or move.
		 *
		 * This assumes that the clock_thread is not bound
		 * to any CPU, because the clock_thread is needed to
		 * do the delay(hz/100).
		 *
		 * Note: we still hold the cpu_lock while waiting for
		 * the next clock tick.  This is OK since it isn't
		 * needed for anything else except processor_bind(2),
		 * and system initialization.  If we drop the lock,
		 * we would risk another p_online disabling the last
		 * processor.
		 */
		delay(hz/100);
	}

	if (error == 0 && callout_off == 0) {
		callout_cpu_offline(cp);
		callout_off = 1;
	}

	if (error == 0 && cyclic_off == 0) {
		if (!cyclic_offline(cp)) {
			/*
			 * We must have bound cyclics...
			 */
			error = EBUSY;
			goto out;
		}
		cyclic_off = 1;
	}

	/*
	 * Call mp_cpu_stop() to perform any special operations
	 * needed for this machine architecture to offline a CPU.
	 */
	if (error == 0)
		error = mp_cpu_stop(cp);	/* arch-dep hook */

	/*
	 * If that all worked, take the CPU offline and decrement
	 * ncpus_online.
	 */
	if (error == 0) {
		/*
		 * Put all the cpus into a known safe place.
		 * No mutexes can be entered while CPUs are paused.
		 */
		pause_cpus(cp, NULL);
		/*
		 * Repeat the operation, if necessary, to make sure that
		 * all outstanding low-level interrupts run to completion
		 * before we set the CPU_QUIESCED flag.  It's also possible
		 * that a thread has weak bound to the cpu despite our raising
		 * cpu_inmotion above since it may have loaded that
		 * value before the barrier became visible (this would have
		 * to be the thread that was on the target cpu at the time
		 * we raised the barrier).
		 */
		if ((!no_quiesce && cp->cpu_intr_actv != 0) ||
		    (*bound_func)(cp, 1)) {
			start_cpus();
			(void) mp_cpu_start(cp);
			goto again;
		}
		ncp = cp->cpu_next_part;
		cpu_lpl = cp->cpu_lpl;
		ASSERT(cpu_lpl != NULL);

		/*
		 * Remove the CPU from the list of active CPUs.
		 */
		cpu_remove_active(cp);

		/*
		 * Walk the active process list and look for threads
		 * whose home lgroup needs to be updated, or
		 * the last CPU they run on is the one being offlined now.
		 */

		ASSERT(curthread->t_cpu != cp);
		for (p = practive; p != NULL; p = p->p_next) {

			t = p->p_tlist;

			if (t == NULL)
				continue;

			lgrp_diff_lpl = 0;

			do {
				ASSERT(t->t_lpl != NULL);
				/*
				 * Taking last CPU in lpl offline
				 * Rehome thread if it is in this lpl
				 * Otherwise, update the count of how many
				 * threads are in this CPU's lgroup but have
				 * a different lpl.
				 */

				if (cpu_lpl->lpl_ncpu == 0) {
					if (t->t_lpl == cpu_lpl)
						lgrp_move_thread(t,
						    lgrp_choose(t,
						    t->t_cpupart), 0);
					else if (t->t_lpl->lpl_lgrpid ==
					    cpu_lpl->lpl_lgrpid)
						lgrp_diff_lpl++;
				}
				ASSERT(t->t_lpl->lpl_ncpu > 0);

				/*
				 * Update CPU last ran on if it was this CPU
				 */
				if (t->t_cpu == cp && t->t_bound_cpu != cp)
					t->t_cpu = disp_lowpri_cpu(ncp,
					    t->t_lpl, t->t_pri, NULL);
				ASSERT(t->t_cpu != cp || t->t_bound_cpu == cp ||
				    t->t_weakbound_cpu == cp);

				t = t->t_forw;
			} while (t != p->p_tlist);

			/*
			 * Didn't find any threads in the same lgroup as this
			 * CPU with a different lpl, so remove the lgroup from
			 * the process lgroup bitmask.
			 */

			if (lgrp_diff_lpl == 0)
				klgrpset_del(p->p_lgrpset, cpu_lpl->lpl_lgrpid);
		}

		/*
		 * Walk thread list looking for threads that need to be
		 * rehomed, since there are some threads that are not in
		 * their process's p_tlist.
		 */

		t = curthread;
		do {
			ASSERT(t != NULL && t->t_lpl != NULL);

			/*
			 * Rehome threads with same lpl as this CPU when this
			 * is the last CPU in the lpl.
			 */

			if ((cpu_lpl->lpl_ncpu == 0) && (t->t_lpl == cpu_lpl))
				lgrp_move_thread(t,
				    lgrp_choose(t, t->t_cpupart), 1);

			ASSERT(t->t_lpl->lpl_ncpu > 0);

			/*
			 * Update CPU last ran on if it was this CPU
			 */

			if (t->t_cpu == cp && t->t_bound_cpu != cp) {
				t->t_cpu = disp_lowpri_cpu(ncp,
				    t->t_lpl, t->t_pri, NULL);
			}
			ASSERT(t->t_cpu != cp || t->t_bound_cpu == cp ||
			    t->t_weakbound_cpu == cp);
			t = t->t_next;

		} while (t != curthread);
		ASSERT((cp->cpu_flags & (CPU_FAULTED | CPU_SPARE)) == 0);
		cp->cpu_flags |= CPU_OFFLINE;
		disp_cpu_inactive(cp);
		if (!no_quiesce)
			cp->cpu_flags |= CPU_QUIESCED;
		ncpus_online--;
		cpu_set_state(cp);
		cpu_inmotion = NULL;
		start_cpus();
		cpu_stats_kstat_destroy(cp);
		cpu_delete_intrstat(cp);
		lgrp_kstat_destroy(cp);
	}

out:
	cpu_inmotion = NULL;

	/*
	 * If we failed, re-enable interrupts.
	 * Do this even if cpu_intr_disable returned an error, because
	 * it may have partially disabled interrupts.
	 */
	if (error && intr_enable)
		cpu_intr_enable(cp);

	/*
	 * If we failed, but managed to offline the cyclic subsystem on this
	 * CPU, bring it back online.
	 */
	if (error && cyclic_off)
		cyclic_online(cp);

	/*
	 * If we failed, but managed to offline callouts on this CPU,
	 * bring it back online.
	 */
	if (error && callout_off)
		callout_cpu_online(cp);

	/*
	 * If we failed, tell the PG subsystem that the CPU is back
	 */
	pg_cpupart_in(cp, pp);

	/*
	 * If we failed, we need to notify everyone that this CPU is back on.
	 */
	if (error != 0) {
		CPU_NEW_GENERATION(cp);
		cpu_state_change_notify(cp->cpu_id, CPU_ON);
		cpu_state_change_notify(cp->cpu_id, CPU_INTR_ON);
	}

	return (error);
}

/*
 * Mark the indicated CPU as faulted, taking it offline.
 */
int
cpu_faulted(cpu_t *cp, int flags)
{
	int	error = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(!cpu_is_poweredoff(cp));

	if (cpu_is_offline(cp)) {
		cp->cpu_flags &= ~CPU_SPARE;
		cp->cpu_flags |= CPU_FAULTED;
		mp_cpu_faulted_enter(cp);
		cpu_set_state(cp);
		return (0);
	}

	if ((error = cpu_offline(cp, flags)) == 0) {
		cp->cpu_flags |= CPU_FAULTED;
		mp_cpu_faulted_enter(cp);
		cpu_set_state(cp);
	}

	return (error);
}

/*
 * Mark the indicated CPU as a spare, taking it offline.
 */
int
cpu_spare(cpu_t *cp, int flags)
{
	int	error = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(!cpu_is_poweredoff(cp));

	if (cpu_is_offline(cp)) {
		if (cp->cpu_flags & CPU_FAULTED) {
			cp->cpu_flags &= ~CPU_FAULTED;
			mp_cpu_faulted_exit(cp);
		}
		cp->cpu_flags |= CPU_SPARE;
		cpu_set_state(cp);
		return (0);
	}

	if ((error = cpu_offline(cp, flags)) == 0) {
		cp->cpu_flags |= CPU_SPARE;
		cpu_set_state(cp);
	}

	return (error);
}

/*
 * Take the indicated CPU from poweroff to offline.
 */
int
cpu_poweron(cpu_t *cp)
{
	int	error = ENOTSUP;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu_is_poweredoff(cp));

	error = mp_cpu_poweron(cp);	/* arch-dep hook */
	if (error == 0)
		cpu_set_state(cp);

	return (error);
}

/*
 * Take the indicated CPU from any inactive state to powered off.
 */
int
cpu_poweroff(cpu_t *cp)
{
	int	error = ENOTSUP;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu_is_offline(cp));

	if (!(cp->cpu_flags & CPU_QUIESCED))
		return (EBUSY);		/* not completely idle */

	error = mp_cpu_poweroff(cp);	/* arch-dep hook */
	if (error == 0)
		cpu_set_state(cp);

	return (error);
}

/*
 * Initialize the Sequential CPU id lookup table
 */
void
cpu_seq_tbl_init()
{
	cpu_t	**tbl;

	tbl = kmem_zalloc(sizeof (struct cpu *) * max_ncpus, KM_SLEEP);
	tbl[0] = CPU;

	cpu_seq = tbl;
}

/*
 * Initialize the CPU lists for the first CPU.
 */
void
cpu_list_init(cpu_t *cp)
{
	cp->cpu_next = cp;
	cp->cpu_prev = cp;
	cpu_list = cp;
	clock_cpu_list = cp;

	cp->cpu_next_onln = cp;
	cp->cpu_prev_onln = cp;
	cpu_active = cp;

	cp->cpu_seqid = 0;
	CPUSET_ADD(cpu_seqid_inuse, 0);

	/*
	 * Bootstrap cpu_seq using cpu_list
	 * The cpu_seq[] table will be dynamically allocated
	 * when kmem later becomes available (but before going MP)
	 */
	cpu_seq = &cpu_list;

	cp->cpu_cache_offset = KMEM_CPU_CACHE_OFFSET(cp->cpu_seqid);
	cp_default.cp_cpulist = cp;
	cp_default.cp_ncpus = 1;
	cp->cpu_next_part = cp;
	cp->cpu_prev_part = cp;
	cp->cpu_part = &cp_default;

	CPUSET_ADD(cpu_available, cp->cpu_id);
}

/*
 * Insert a CPU into the list of available CPUs.
 */
void
cpu_add_unit(cpu_t *cp)
{
	int seqid;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu_list != NULL);	/* list started in cpu_list_init */

	lgrp_config(LGRP_CONFIG_CPU_ADD, (uintptr_t)cp, 0);

	/*
	 * Note: most users of the cpu_list will grab the
	 * cpu_lock to insure that it isn't modified.  However,
	 * certain users can't or won't do that.  To allow this
	 * we pause the other cpus.  Users who walk the list
	 * without cpu_lock, must disable kernel preemption
	 * to insure that the list isn't modified underneath
	 * them.  Also, any cached pointers to cpu structures
	 * must be revalidated by checking to see if the
	 * cpu_next pointer points to itself.  This check must
	 * be done with the cpu_lock held or kernel preemption
	 * disabled.  This check relies upon the fact that
	 * old cpu structures are not free'ed or cleared after
	 * then are removed from the cpu_list.
	 *
	 * Note that the clock code walks the cpu list dereferencing
	 * the cpu_part pointer, so we need to initialize it before
	 * adding the cpu to the list.
	 */
	cp->cpu_part = &cp_default;
	pause_cpus(NULL, NULL);
	cp->cpu_next = cpu_list;
	cp->cpu_prev = cpu_list->cpu_prev;
	cpu_list->cpu_prev->cpu_next = cp;
	cpu_list->cpu_prev = cp;
	start_cpus();

	for (seqid = 0; CPU_IN_SET(cpu_seqid_inuse, seqid); seqid++)
		continue;
	CPUSET_ADD(cpu_seqid_inuse, seqid);
	cp->cpu_seqid = seqid;

	if (seqid > max_cpu_seqid_ever)
		max_cpu_seqid_ever = seqid;

	ASSERT(ncpus < max_ncpus);
	ncpus++;
	cp->cpu_cache_offset = KMEM_CPU_CACHE_OFFSET(cp->cpu_seqid);
	cpu[cp->cpu_id] = cp;
	CPUSET_ADD(cpu_available, cp->cpu_id);
	cpu_seq[cp->cpu_seqid] = cp;

	/*
	 * allocate a pause thread for this CPU.
	 */
	cpu_pause_alloc(cp);

	/*
	 * So that new CPUs won't have NULL prev_onln and next_onln pointers,
	 * link them into a list of just that CPU.
	 * This is so that disp_lowpri_cpu will work for thread_create in
	 * pause_cpus() when called from the startup thread in a new CPU.
	 */
	cp->cpu_next_onln = cp;
	cp->cpu_prev_onln = cp;
	cpu_info_kstat_create(cp);
	cp->cpu_next_part = cp;
	cp->cpu_prev_part = cp;

	init_cpu_mstate(cp, CMS_SYSTEM);

	pool_pset_mod = gethrtime();
}

/*
 * Do the opposite of cpu_add_unit().
 */
void
cpu_del_unit(int cpuid)
{
	struct cpu	*cp, *cpnext;

	ASSERT(MUTEX_HELD(&cpu_lock));
	cp = cpu[cpuid];
	ASSERT(cp != NULL);

	ASSERT(cp->cpu_next_onln == cp);
	ASSERT(cp->cpu_prev_onln == cp);
	ASSERT(cp->cpu_next_part == cp);
	ASSERT(cp->cpu_prev_part == cp);

	/*
	 * Tear down the CPU's physical ID cache, and update any
	 * processor groups
	 */
	pg_cpu_fini(cp, NULL);
	pghw_physid_destroy(cp);

	/*
	 * Destroy kstat stuff.
	 */
	cpu_info_kstat_destroy(cp);
	term_cpu_mstate(cp);
	/*
	 * Free up pause thread.
	 */
	cpu_pause_free(cp);
	CPUSET_DEL(cpu_available, cp->cpu_id);
	cpu[cp->cpu_id] = NULL;
	cpu_seq[cp->cpu_seqid] = NULL;

	/*
	 * The clock thread and mutex_vector_enter cannot hold the
	 * cpu_lock while traversing the cpu list, therefore we pause
	 * all other threads by pausing the other cpus. These, and any
	 * other routines holding cpu pointers while possibly sleeping
	 * must be sure to call kpreempt_disable before processing the
	 * list and be sure to check that the cpu has not been deleted
	 * after any sleeps (check cp->cpu_next != NULL). We guarantee
	 * to keep the deleted cpu structure around.
	 *
	 * Note that this MUST be done AFTER cpu_available
	 * has been updated so that we don't waste time
	 * trying to pause the cpu we're trying to delete.
	 */
	pause_cpus(NULL, NULL);

	cpnext = cp->cpu_next;
	cp->cpu_prev->cpu_next = cp->cpu_next;
	cp->cpu_next->cpu_prev = cp->cpu_prev;
	if (cp == cpu_list)
		cpu_list = cpnext;

	/*
	 * Signals that the cpu has been deleted (see above).
	 */
	cp->cpu_next = NULL;
	cp->cpu_prev = NULL;

	start_cpus();

	CPUSET_DEL(cpu_seqid_inuse, cp->cpu_seqid);
	ncpus--;
	lgrp_config(LGRP_CONFIG_CPU_DEL, (uintptr_t)cp, 0);

	pool_pset_mod = gethrtime();
}

/*
 * Add a CPU to the list of active CPUs.
 *	This routine must not get any locks, because other CPUs are paused.
 */
static void
cpu_add_active_internal(cpu_t *cp)
{
	cpupart_t	*pp = cp->cpu_part;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu_list != NULL);	/* list started in cpu_list_init */

	ncpus_online++;
	cpu_set_state(cp);
	cp->cpu_next_onln = cpu_active;
	cp->cpu_prev_onln = cpu_active->cpu_prev_onln;
	cpu_active->cpu_prev_onln->cpu_next_onln = cp;
	cpu_active->cpu_prev_onln = cp;

	if (pp->cp_cpulist) {
		cp->cpu_next_part = pp->cp_cpulist;
		cp->cpu_prev_part = pp->cp_cpulist->cpu_prev_part;
		pp->cp_cpulist->cpu_prev_part->cpu_next_part = cp;
		pp->cp_cpulist->cpu_prev_part = cp;
	} else {
		ASSERT(pp->cp_ncpus == 0);
		pp->cp_cpulist = cp->cpu_next_part = cp->cpu_prev_part = cp;
	}
	pp->cp_ncpus++;
	if (pp->cp_ncpus == 1) {
		cp_numparts_nonempty++;
		ASSERT(cp_numparts_nonempty != 0);
	}

	pg_cpu_active(cp);
	lgrp_config(LGRP_CONFIG_CPU_ONLINE, (uintptr_t)cp, 0);

	bzero(&cp->cpu_loadavg, sizeof (cp->cpu_loadavg));
}

/*
 * Add a CPU to the list of active CPUs.
 *	This is called from machine-dependent layers when a new CPU is started.
 */
void
cpu_add_active(cpu_t *cp)
{
	pg_cpupart_in(cp, cp->cpu_part);

	pause_cpus(NULL, NULL);
	cpu_add_active_internal(cp);
	start_cpus();

	cpu_stats_kstat_create(cp);
	cpu_create_intrstat(cp);
	lgrp_kstat_create(cp);
	cpu_state_change_notify(cp->cpu_id, CPU_INIT);
}


/*
 * Remove a CPU from the list of active CPUs.
 *	This routine must not get any locks, because other CPUs are paused.
 */
/* ARGSUSED */
static void
cpu_remove_active(cpu_t *cp)
{
	cpupart_t	*pp = cp->cpu_part;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cp->cpu_next_onln != cp);	/* not the last one */
	ASSERT(cp->cpu_prev_onln != cp);	/* not the last one */

	pg_cpu_inactive(cp);

	lgrp_config(LGRP_CONFIG_CPU_OFFLINE, (uintptr_t)cp, 0);

	if (cp == clock_cpu_list)
		clock_cpu_list = cp->cpu_next_onln;

	cp->cpu_prev_onln->cpu_next_onln = cp->cpu_next_onln;
	cp->cpu_next_onln->cpu_prev_onln = cp->cpu_prev_onln;
	if (cpu_active == cp) {
		cpu_active = cp->cpu_next_onln;
	}
	cp->cpu_next_onln = cp;
	cp->cpu_prev_onln = cp;

	cp->cpu_prev_part->cpu_next_part = cp->cpu_next_part;
	cp->cpu_next_part->cpu_prev_part = cp->cpu_prev_part;
	if (pp->cp_cpulist == cp) {
		pp->cp_cpulist = cp->cpu_next_part;
		ASSERT(pp->cp_cpulist != cp);
	}
	cp->cpu_next_part = cp;
	cp->cpu_prev_part = cp;
	pp->cp_ncpus--;
	if (pp->cp_ncpus == 0) {
		cp_numparts_nonempty--;
		ASSERT(cp_numparts_nonempty != 0);
	}
}

/*
 * Routine used to setup a newly inserted CPU in preparation for starting
 * it running code.
 */
int
cpu_configure(int cpuid)
{
	int retval = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Some structures are statically allocated based upon
	 * the maximum number of cpus the system supports.  Do not
	 * try to add anything beyond this limit.
	 */
	if (cpuid < 0 || cpuid >= NCPU) {
		return (EINVAL);
	}

	if ((cpu[cpuid] != NULL) && (cpu[cpuid]->cpu_flags != 0)) {
		return (EALREADY);
	}

	if ((retval = mp_cpu_configure(cpuid)) != 0) {
		return (retval);
	}

	cpu[cpuid]->cpu_flags = CPU_QUIESCED | CPU_OFFLINE | CPU_POWEROFF;
	cpu_set_state(cpu[cpuid]);
	retval = cpu_state_change_hooks(cpuid, CPU_CONFIG, CPU_UNCONFIG);
	if (retval != 0)
		(void) mp_cpu_unconfigure(cpuid);

	return (retval);
}

/*
 * Routine used to cleanup a CPU that has been powered off.  This will
 * destroy all per-cpu information related to this cpu.
 */
int
cpu_unconfigure(int cpuid)
{
	int error;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cpu[cpuid] == NULL) {
		return (ENODEV);
	}

	if (cpu[cpuid]->cpu_flags == 0) {
		return (EALREADY);
	}

	if ((cpu[cpuid]->cpu_flags & CPU_POWEROFF) == 0) {
		return (EBUSY);
	}

	if (cpu[cpuid]->cpu_props != NULL) {
		(void) nvlist_free(cpu[cpuid]->cpu_props);
		cpu[cpuid]->cpu_props = NULL;
	}

	error = cpu_state_change_hooks(cpuid, CPU_UNCONFIG, CPU_CONFIG);

	if (error != 0)
		return (error);

	return (mp_cpu_unconfigure(cpuid));
}

/*
 * Routines for registering and de-registering cpu_setup callback functions.
 *
 * Caller's context
 *	These routines must not be called from a driver's attach(9E) or
 *	detach(9E) entry point.
 *
 * NOTE: CPU callbacks should not block. They are called with cpu_lock held.
 */

/*
 * Ideally, these would be dynamically allocated and put into a linked
 * list; however that is not feasible because the registration routine
 * has to be available before the kmem allocator is working (in fact,
 * it is called by the kmem allocator init code).  In any case, there
 * are quite a few extra entries for future users.
 */
#define	NCPU_SETUPS	20

struct cpu_setup {
	cpu_setup_func_t *func;
	void *arg;
} cpu_setups[NCPU_SETUPS];

void
register_cpu_setup_func(cpu_setup_func_t *func, void *arg)
{
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	for (i = 0; i < NCPU_SETUPS; i++)
		if (cpu_setups[i].func == NULL)
			break;
	if (i >= NCPU_SETUPS)
		cmn_err(CE_PANIC, "Ran out of cpu_setup callback entries");

	cpu_setups[i].func = func;
	cpu_setups[i].arg = arg;
}

void
unregister_cpu_setup_func(cpu_setup_func_t *func, void *arg)
{
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	for (i = 0; i < NCPU_SETUPS; i++)
		if ((cpu_setups[i].func == func) &&
		    (cpu_setups[i].arg == arg))
			break;
	if (i >= NCPU_SETUPS)
		cmn_err(CE_PANIC, "Could not find cpu_setup callback to "
		    "deregister");

	cpu_setups[i].func = NULL;
	cpu_setups[i].arg = 0;
}

/*
 * Call any state change hooks for this CPU, ignore any errors.
 */
void
cpu_state_change_notify(int id, cpu_setup_t what)
{
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	for (i = 0; i < NCPU_SETUPS; i++) {
		if (cpu_setups[i].func != NULL) {
			cpu_setups[i].func(what, id, cpu_setups[i].arg);
		}
	}
}

/*
 * Call any state change hooks for this CPU, undo it if error found.
 */
static int
cpu_state_change_hooks(int id, cpu_setup_t what, cpu_setup_t undo)
{
	int i;
	int retval = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	for (i = 0; i < NCPU_SETUPS; i++) {
		if (cpu_setups[i].func != NULL) {
			retval = cpu_setups[i].func(what, id,
			    cpu_setups[i].arg);
			if (retval) {
				for (i--; i >= 0; i--) {
					if (cpu_setups[i].func != NULL)
						cpu_setups[i].func(undo,
						    id, cpu_setups[i].arg);
				}
				break;
			}
		}
	}
	return (retval);
}

/*
 * Export information about this CPU via the kstat mechanism.
 */
static struct {
	kstat_named_t ci_state;
	kstat_named_t ci_state_begin;
	kstat_named_t ci_cpu_type;
	kstat_named_t ci_fpu_type;
	kstat_named_t ci_clock_MHz;
	kstat_named_t ci_chip_id;
	kstat_named_t ci_implementation;
	kstat_named_t ci_brandstr;
	kstat_named_t ci_core_id;
	kstat_named_t ci_curr_clock_Hz;
	kstat_named_t ci_supp_freq_Hz;
	kstat_named_t ci_pg_id;
#if defined(__sparcv9)
	kstat_named_t ci_device_ID;
	kstat_named_t ci_cpu_fru;
#endif
#if defined(__x86)
	kstat_named_t ci_vendorstr;
	kstat_named_t ci_family;
	kstat_named_t ci_model;
	kstat_named_t ci_step;
	kstat_named_t ci_clogid;
	kstat_named_t ci_pkg_core_id;
	kstat_named_t ci_ncpuperchip;
	kstat_named_t ci_ncoreperchip;
	kstat_named_t ci_max_cstates;
	kstat_named_t ci_curr_cstate;
	kstat_named_t ci_cacheid;
	kstat_named_t ci_sktstr;
#endif
} cpu_info_template = {
	{ "state",			KSTAT_DATA_CHAR },
	{ "state_begin",		KSTAT_DATA_LONG },
	{ "cpu_type",			KSTAT_DATA_CHAR },
	{ "fpu_type",			KSTAT_DATA_CHAR },
	{ "clock_MHz",			KSTAT_DATA_LONG },
	{ "chip_id",			KSTAT_DATA_LONG },
	{ "implementation",		KSTAT_DATA_STRING },
	{ "brand",			KSTAT_DATA_STRING },
	{ "core_id",			KSTAT_DATA_LONG },
	{ "current_clock_Hz",		KSTAT_DATA_UINT64 },
	{ "supported_frequencies_Hz",	KSTAT_DATA_STRING },
	{ "pg_id",			KSTAT_DATA_LONG },
#if defined(__sparcv9)
	{ "device_ID",			KSTAT_DATA_UINT64 },
	{ "cpu_fru",			KSTAT_DATA_STRING },
#endif
#if defined(__x86)
	{ "vendor_id",			KSTAT_DATA_STRING },
	{ "family",			KSTAT_DATA_INT32 },
	{ "model",			KSTAT_DATA_INT32 },
	{ "stepping",			KSTAT_DATA_INT32 },
	{ "clog_id",			KSTAT_DATA_INT32 },
	{ "pkg_core_id",		KSTAT_DATA_LONG },
	{ "ncpu_per_chip",		KSTAT_DATA_INT32 },
	{ "ncore_per_chip",		KSTAT_DATA_INT32 },
	{ "supported_max_cstates",	KSTAT_DATA_INT32 },
	{ "current_cstate",		KSTAT_DATA_INT32 },
	{ "cache_id",			KSTAT_DATA_INT32 },
	{ "socket_type",		KSTAT_DATA_STRING },
#endif
};

static kmutex_t cpu_info_template_lock;

static int
cpu_info_kstat_update(kstat_t *ksp, int rw)
{
	cpu_t	*cp = ksp->ks_private;
	const char *pi_state;

	if (rw == KSTAT_WRITE)
		return (EACCES);

#if defined(__x86)
	/* Is the cpu still initialising itself? */
	if (cpuid_checkpass(cp, 1) == 0)
		return (ENXIO);
#endif
	switch (cp->cpu_type_info.pi_state) {
	case P_ONLINE:
		pi_state = PS_ONLINE;
		break;
	case P_POWEROFF:
		pi_state = PS_POWEROFF;
		break;
	case P_NOINTR:
		pi_state = PS_NOINTR;
		break;
	case P_FAULTED:
		pi_state = PS_FAULTED;
		break;
	case P_SPARE:
		pi_state = PS_SPARE;
		break;
	case P_OFFLINE:
		pi_state = PS_OFFLINE;
		break;
	default:
		pi_state = "unknown";
	}
	(void) strcpy(cpu_info_template.ci_state.value.c, pi_state);
	cpu_info_template.ci_state_begin.value.l = cp->cpu_state_begin;
	(void) strncpy(cpu_info_template.ci_cpu_type.value.c,
	    cp->cpu_type_info.pi_processor_type, 15);
	(void) strncpy(cpu_info_template.ci_fpu_type.value.c,
	    cp->cpu_type_info.pi_fputypes, 15);
	cpu_info_template.ci_clock_MHz.value.l = cp->cpu_type_info.pi_clock;
	cpu_info_template.ci_chip_id.value.l =
	    pg_plat_hw_instance_id(cp, PGHW_CHIP);
	kstat_named_setstr(&cpu_info_template.ci_implementation,
	    cp->cpu_idstr);
	kstat_named_setstr(&cpu_info_template.ci_brandstr, cp->cpu_brandstr);
	cpu_info_template.ci_core_id.value.l = pg_plat_get_core_id(cp);
	cpu_info_template.ci_curr_clock_Hz.value.ui64 =
	    cp->cpu_curr_clock;
	cpu_info_template.ci_pg_id.value.l =
	    cp->cpu_pg && cp->cpu_pg->cmt_lineage ?
	    cp->cpu_pg->cmt_lineage->pg_id : -1;
	kstat_named_setstr(&cpu_info_template.ci_supp_freq_Hz,
	    cp->cpu_supp_freqs);
#if defined(__sparcv9)
	cpu_info_template.ci_device_ID.value.ui64 =
	    cpunodes[cp->cpu_id].device_id;
	kstat_named_setstr(&cpu_info_template.ci_cpu_fru, cpu_fru_fmri(cp));
#endif
#if defined(__x86)
	kstat_named_setstr(&cpu_info_template.ci_vendorstr,
	    cpuid_getvendorstr(cp));
	cpu_info_template.ci_family.value.l = cpuid_getfamily(cp);
	cpu_info_template.ci_model.value.l = cpuid_getmodel(cp);
	cpu_info_template.ci_step.value.l = cpuid_getstep(cp);
	cpu_info_template.ci_clogid.value.l = cpuid_get_clogid(cp);
	cpu_info_template.ci_ncpuperchip.value.l = cpuid_get_ncpu_per_chip(cp);
	cpu_info_template.ci_ncoreperchip.value.l =
	    cpuid_get_ncore_per_chip(cp);
	cpu_info_template.ci_pkg_core_id.value.l = cpuid_get_pkgcoreid(cp);
	cpu_info_template.ci_max_cstates.value.l = cp->cpu_m.max_cstates;
	cpu_info_template.ci_curr_cstate.value.l = cpu_idle_get_cpu_state(cp);
	cpu_info_template.ci_cacheid.value.i32 = cpuid_get_cacheid(cp);
	kstat_named_setstr(&cpu_info_template.ci_sktstr,
	    cpuid_getsocketstr(cp));
#endif

	return (0);
}

static void
cpu_info_kstat_create(cpu_t *cp)
{
	zoneid_t zoneid;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (pool_pset_enabled())
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = ALL_ZONES;
	if ((cp->cpu_info_kstat = kstat_create_zone("cpu_info", cp->cpu_id,
	    NULL, "misc", KSTAT_TYPE_NAMED,
	    sizeof (cpu_info_template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_VAR_SIZE, zoneid)) != NULL) {
		cp->cpu_info_kstat->ks_data_size += 2 * CPU_IDSTRLEN;
#if defined(__sparcv9)
		cp->cpu_info_kstat->ks_data_size +=
		    strlen(cpu_fru_fmri(cp)) + 1;
#endif
#if defined(__x86)
		cp->cpu_info_kstat->ks_data_size += X86_VENDOR_STRLEN;
#endif
		if (cp->cpu_supp_freqs != NULL)
			cp->cpu_info_kstat->ks_data_size +=
			    strlen(cp->cpu_supp_freqs) + 1;
		cp->cpu_info_kstat->ks_lock = &cpu_info_template_lock;
		cp->cpu_info_kstat->ks_data = &cpu_info_template;
		cp->cpu_info_kstat->ks_private = cp;
		cp->cpu_info_kstat->ks_update = cpu_info_kstat_update;
		kstat_install(cp->cpu_info_kstat);
	}
}

static void
cpu_info_kstat_destroy(cpu_t *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	kstat_delete(cp->cpu_info_kstat);
	cp->cpu_info_kstat = NULL;
}

/*
 * Create and install kstats for the boot CPU.
 */
void
cpu_kstat_init(cpu_t *cp)
{
	mutex_enter(&cpu_lock);
	cpu_info_kstat_create(cp);
	cpu_stats_kstat_create(cp);
	cpu_create_intrstat(cp);
	cpu_set_state(cp);
	mutex_exit(&cpu_lock);
}

/*
 * Make visible to the zone that subset of the cpu information that would be
 * initialized when a cpu is configured (but still offline).
 */
void
cpu_visibility_configure(cpu_t *cp, zone_t *zone)
{
	zoneid_t zoneid = zone ? zone->zone_id : ALL_ZONES;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(pool_pset_enabled());
	ASSERT(cp != NULL);

	if (zoneid != ALL_ZONES && zoneid != GLOBAL_ZONEID) {
		zone->zone_ncpus++;
		ASSERT(zone->zone_ncpus <= ncpus);
	}
	if (cp->cpu_info_kstat != NULL)
		kstat_zone_add(cp->cpu_info_kstat, zoneid);
}

/*
 * Make visible to the zone that subset of the cpu information that would be
 * initialized when a previously configured cpu is onlined.
 */
void
cpu_visibility_online(cpu_t *cp, zone_t *zone)
{
	kstat_t *ksp;
	char name[sizeof ("cpu_stat") + 10];	/* enough for 32-bit cpuids */
	zoneid_t zoneid = zone ? zone->zone_id : ALL_ZONES;
	processorid_t cpun;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(pool_pset_enabled());
	ASSERT(cp != NULL);
	ASSERT(cpu_is_active(cp));

	cpun = cp->cpu_id;
	if (zoneid != ALL_ZONES && zoneid != GLOBAL_ZONEID) {
		zone->zone_ncpus_online++;
		ASSERT(zone->zone_ncpus_online <= ncpus_online);
	}
	(void) snprintf(name, sizeof (name), "cpu_stat%d", cpun);
	if ((ksp = kstat_hold_byname("cpu_stat", cpun, name, ALL_ZONES))
	    != NULL) {
		kstat_zone_add(ksp, zoneid);
		kstat_rele(ksp);
	}
	if ((ksp = kstat_hold_byname("cpu", cpun, "sys", ALL_ZONES)) != NULL) {
		kstat_zone_add(ksp, zoneid);
		kstat_rele(ksp);
	}
	if ((ksp = kstat_hold_byname("cpu", cpun, "vm", ALL_ZONES)) != NULL) {
		kstat_zone_add(ksp, zoneid);
		kstat_rele(ksp);
	}
	if ((ksp = kstat_hold_byname("cpu", cpun, "intrstat", ALL_ZONES)) !=
	    NULL) {
		kstat_zone_add(ksp, zoneid);
		kstat_rele(ksp);
	}
}

/*
 * Update relevant kstats such that cpu is now visible to processes
 * executing in specified zone.
 */
void
cpu_visibility_add(cpu_t *cp, zone_t *zone)
{
	cpu_visibility_configure(cp, zone);
	if (cpu_is_active(cp))
		cpu_visibility_online(cp, zone);
}

/*
 * Make invisible to the zone that subset of the cpu information that would be
 * torn down when a previously offlined cpu is unconfigured.
 */
void
cpu_visibility_unconfigure(cpu_t *cp, zone_t *zone)
{
	zoneid_t zoneid = zone ? zone->zone_id : ALL_ZONES;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(pool_pset_enabled());
	ASSERT(cp != NULL);

	if (zoneid != ALL_ZONES && zoneid != GLOBAL_ZONEID) {
		ASSERT(zone->zone_ncpus != 0);
		zone->zone_ncpus--;
	}
	if (cp->cpu_info_kstat)
		kstat_zone_remove(cp->cpu_info_kstat, zoneid);
}

/*
 * Make invisible to the zone that subset of the cpu information that would be
 * torn down when a cpu is offlined (but still configured).
 */
void
cpu_visibility_offline(cpu_t *cp, zone_t *zone)
{
	kstat_t *ksp;
	char name[sizeof ("cpu_stat") + 10];	/* enough for 32-bit cpuids */
	zoneid_t zoneid = zone ? zone->zone_id : ALL_ZONES;
	processorid_t cpun;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(pool_pset_enabled());
	ASSERT(cp != NULL);
	ASSERT(cpu_is_active(cp));

	cpun = cp->cpu_id;
	if (zoneid != ALL_ZONES && zoneid != GLOBAL_ZONEID) {
		ASSERT(zone->zone_ncpus_online != 0);
		zone->zone_ncpus_online--;
	}

	if ((ksp = kstat_hold_byname("cpu", cpun, "intrstat", ALL_ZONES)) !=
	    NULL) {
		kstat_zone_remove(ksp, zoneid);
		kstat_rele(ksp);
	}
	if ((ksp = kstat_hold_byname("cpu", cpun, "vm", ALL_ZONES)) != NULL) {
		kstat_zone_remove(ksp, zoneid);
		kstat_rele(ksp);
	}
	if ((ksp = kstat_hold_byname("cpu", cpun, "sys", ALL_ZONES)) != NULL) {
		kstat_zone_remove(ksp, zoneid);
		kstat_rele(ksp);
	}
	(void) snprintf(name, sizeof (name), "cpu_stat%d", cpun);
	if ((ksp = kstat_hold_byname("cpu_stat", cpun, name, ALL_ZONES))
	    != NULL) {
		kstat_zone_remove(ksp, zoneid);
		kstat_rele(ksp);
	}
}

/*
 * Update relevant kstats such that cpu is no longer visible to processes
 * executing in specified zone.
 */
void
cpu_visibility_remove(cpu_t *cp, zone_t *zone)
{
	if (cpu_is_active(cp))
		cpu_visibility_offline(cp, zone);
	cpu_visibility_unconfigure(cp, zone);
}

/*
 * Bind a thread to a CPU as requested.
 */
int
cpu_bind_thread(kthread_id_t tp, processorid_t bind, processorid_t *obind,
    int *error)
{
	processorid_t	binding;
	cpu_t		*cp = NULL;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&ttoproc(tp)->p_lock));

	thread_lock(tp);

	/*
	 * Record old binding, but change the obind, which was initialized
	 * to PBIND_NONE, only if this thread has a binding.  This avoids
	 * reporting PBIND_NONE for a process when some LWPs are bound.
	 */
	binding = tp->t_bind_cpu;
	if (binding != PBIND_NONE)
		*obind = binding;	/* record old binding */

	switch (bind) {
	case PBIND_QUERY:
		/* Just return the old binding */
		thread_unlock(tp);
		return (0);

	case PBIND_QUERY_TYPE:
		/* Return the binding type */
		*obind = TB_CPU_IS_SOFT(tp) ? PBIND_SOFT : PBIND_HARD;
		thread_unlock(tp);
		return (0);

	case PBIND_SOFT:
		/*
		 *  Set soft binding for this thread and return the actual
		 *  binding
		 */
		TB_CPU_SOFT_SET(tp);
		thread_unlock(tp);
		return (0);

	case PBIND_HARD:
		/*
		 *  Set hard binding for this thread and return the actual
		 *  binding
		 */
		TB_CPU_HARD_SET(tp);
		thread_unlock(tp);
		return (0);

	default:
		break;
	}

	/*
	 * If this thread/LWP cannot be bound because of permission
	 * problems, just note that and return success so that the
	 * other threads/LWPs will be bound.  This is the way
	 * processor_bind() is defined to work.
	 *
	 * Binding will get EPERM if the thread is of system class
	 * or hasprocperm() fails.
	 */
	if (tp->t_cid == 0 || !hasprocperm(tp->t_cred, CRED())) {
		*error = EPERM;
		thread_unlock(tp);
		return (0);
	}

	binding = bind;
	if (binding != PBIND_NONE) {
		cp = cpu_get((processorid_t)binding);
		/*
		 * Make sure binding is valid and is in right partition.
		 */
		if (cp == NULL || tp->t_cpupart != cp->cpu_part) {
			*error = EINVAL;
			thread_unlock(tp);
			return (0);
		}
	}
	tp->t_bind_cpu = binding;	/* set new binding */

	/*
	 * If there is no system-set reason for affinity, set
	 * the t_bound_cpu field to reflect the binding.
	 */
	if (tp->t_affinitycnt == 0) {
		if (binding == PBIND_NONE) {
			/*
			 * We may need to adjust disp_max_unbound_pri
			 * since we're becoming unbound.
			 */
			disp_adjust_unbound_pri(tp);

			tp->t_bound_cpu = NULL;	/* set new binding */

			/*
			 * Move thread to lgroup with strongest affinity
			 * after unbinding
			 */
			if (tp->t_lgrp_affinity)
				lgrp_move_thread(tp,
				    lgrp_choose(tp, tp->t_cpupart), 1);

			if (tp->t_state == TS_ONPROC &&
			    tp->t_cpu->cpu_part != tp->t_cpupart)
				cpu_surrender(tp);
		} else {
			lpl_t	*lpl;

			tp->t_bound_cpu = cp;
			ASSERT(cp->cpu_lpl != NULL);

			/*
			 * Set home to lgroup with most affinity containing CPU
			 * that thread is being bound or minimum bounding
			 * lgroup if no affinities set
			 */
			if (tp->t_lgrp_affinity)
				lpl = lgrp_affinity_best(tp, tp->t_cpupart,
				    LGRP_NONE, B_FALSE);
			else
				lpl = cp->cpu_lpl;

			if (tp->t_lpl != lpl) {
				/* can't grab cpu_lock */
				lgrp_move_thread(tp, lpl, 1);
			}

			/*
			 * Make the thread switch to the bound CPU.
			 * If the thread is runnable, we need to
			 * requeue it even if t_cpu is already set
			 * to the right CPU, since it may be on a
			 * kpreempt queue and need to move to a local
			 * queue.  We could check t_disp_queue to
			 * avoid unnecessary overhead if it's already
			 * on the right queue, but since this isn't
			 * a performance-critical operation it doesn't
			 * seem worth the extra code and complexity.
			 *
			 * If the thread is weakbound to the cpu then it will
			 * resist the new binding request until the weak
			 * binding drops.  The cpu_surrender or requeueing
			 * below could be skipped in such cases (since it
			 * will have no effect), but that would require
			 * thread_allowmigrate to acquire thread_lock so
			 * we'll take the very occasional hit here instead.
			 */
			if (tp->t_state == TS_ONPROC) {
				cpu_surrender(tp);
			} else if (tp->t_state == TS_RUN) {
				cpu_t *ocp = tp->t_cpu;

				(void) dispdeq(tp);
				setbackdq(tp);
				/*
				 * Either on the bound CPU's disp queue now,
				 * or swapped out or on the swap queue.
				 */
				ASSERT(tp->t_disp_queue == cp->cpu_disp ||
				    tp->t_weakbound_cpu == ocp ||
				    (tp->t_schedflag & (TS_LOAD | TS_ON_SWAPQ))
				    != TS_LOAD);
			}
		}
	}

	/*
	 * Our binding has changed; set TP_CHANGEBIND.
	 */
	tp->t_proc_flag |= TP_CHANGEBIND;
	aston(tp);

	thread_unlock(tp);

	return (0);
}

#if CPUSET_WORDS > 1

/*
 * Functions for implementing cpuset operations when a cpuset is more
 * than one word.  On platforms where a cpuset is a single word these
 * are implemented as macros in cpuvar.h.
 */

void
cpuset_all(cpuset_t *s)
{
	int i;

	for (i = 0; i < CPUSET_WORDS; i++)
		s->cpub[i] = ~0UL;
}

void
cpuset_all_but(cpuset_t *s, uint_t cpu)
{
	cpuset_all(s);
	CPUSET_DEL(*s, cpu);
}

void
cpuset_only(cpuset_t *s, uint_t cpu)
{
	CPUSET_ZERO(*s);
	CPUSET_ADD(*s, cpu);
}

int
cpuset_isnull(cpuset_t *s)
{
	int i;

	for (i = 0; i < CPUSET_WORDS; i++)
		if (s->cpub[i] != 0)
			return (0);
	return (1);
}

int
cpuset_cmp(cpuset_t *s1, cpuset_t *s2)
{
	int i;

	for (i = 0; i < CPUSET_WORDS; i++)
		if (s1->cpub[i] != s2->cpub[i])
			return (0);
	return (1);
}

uint_t
cpuset_find(cpuset_t *s)
{

	uint_t	i;
	uint_t	cpu = (uint_t)-1;

	/*
	 * Find a cpu in the cpuset
	 */
	for (i = 0; i < CPUSET_WORDS; i++) {
		cpu = (uint_t)(lowbit(s->cpub[i]) - 1);
		if (cpu != (uint_t)-1) {
			cpu += i * BT_NBIPUL;
			break;
		}
	}
	return (cpu);
}

void
cpuset_bounds(cpuset_t *s, uint_t *smallestid, uint_t *largestid)
{
	int	i, j;
	uint_t	bit;

	/*
	 * First, find the smallest cpu id in the set.
	 */
	for (i = 0; i < CPUSET_WORDS; i++) {
		if (s->cpub[i] != 0) {
			bit = (uint_t)(lowbit(s->cpub[i]) - 1);
			ASSERT(bit != (uint_t)-1);
			*smallestid = bit + (i * BT_NBIPUL);

			/*
			 * Now find the largest cpu id in
			 * the set and return immediately.
			 * Done in an inner loop to avoid
			 * having to break out of the first
			 * loop.
			 */
			for (j = CPUSET_WORDS - 1; j >= i; j--) {
				if (s->cpub[j] != 0) {
					bit = (uint_t)(highbit(s->cpub[j]) - 1);
					ASSERT(bit != (uint_t)-1);
					*largestid = bit + (j * BT_NBIPUL);
					ASSERT(*largestid >= *smallestid);
					return;
				}
			}

			/*
			 * If this code is reached, a
			 * smallestid was found, but not a
			 * largestid. The cpuset must have
			 * been changed during the course
			 * of this function call.
			 */
			ASSERT(0);
		}
	}
	*smallestid = *largestid = CPUSET_NOTINSET;
}

#endif	/* CPUSET_WORDS */

/*
 * Unbind threads bound to specified CPU.
 *
 * If `unbind_all_threads' is true, unbind all user threads bound to a given
 * CPU. Otherwise unbind all soft-bound user threads.
 */
int
cpu_unbind(processorid_t cpu, boolean_t unbind_all_threads)
{
	processorid_t obind;
	kthread_t *tp;
	int ret = 0;
	proc_t *pp;
	int err, berr = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	mutex_enter(&pidlock);
	for (pp = practive; pp != NULL; pp = pp->p_next) {
		mutex_enter(&pp->p_lock);
		tp = pp->p_tlist;
		/*
		 * Skip zombies, kernel processes, and processes in
		 * other zones, if called from a non-global zone.
		 */
		if (tp == NULL || (pp->p_flag & SSYS) ||
		    !HASZONEACCESS(curproc, pp->p_zone->zone_id)) {
			mutex_exit(&pp->p_lock);
			continue;
		}
		do {
			if (tp->t_bind_cpu != cpu)
				continue;
			/*
			 * Skip threads with hard binding when
			 * `unbind_all_threads' is not specified.
			 */
			if (!unbind_all_threads && TB_CPU_IS_HARD(tp))
				continue;
			err = cpu_bind_thread(tp, PBIND_NONE, &obind, &berr);
			if (ret == 0)
				ret = err;
		} while ((tp = tp->t_forw) != pp->p_tlist);
		mutex_exit(&pp->p_lock);
	}
	mutex_exit(&pidlock);
	if (ret == 0)
		ret = berr;
	return (ret);
}


/*
 * Destroy all remaining bound threads on a cpu.
 */
void
cpu_destroy_bound_threads(cpu_t *cp)
{
	extern id_t syscid;
	register kthread_id_t	t, tlist, tnext;

	/*
	 * Destroy all remaining bound threads on the cpu.  This
	 * should include both the interrupt threads and the idle thread.
	 * This requires some care, since we need to traverse the
	 * thread list with the pidlock mutex locked, but thread_free
	 * also locks the pidlock mutex.  So, we collect the threads
	 * we're going to reap in a list headed by "tlist", then we
	 * unlock the pidlock mutex and traverse the tlist list,
	 * doing thread_free's on the thread's.	 Simple, n'est pas?
	 * Also, this depends on thread_free not mucking with the
	 * t_next and t_prev links of the thread.
	 */

	if ((t = curthread) != NULL) {

		tlist = NULL;
		mutex_enter(&pidlock);
		do {
			tnext = t->t_next;
			if (t->t_bound_cpu == cp) {

				/*
				 * We've found a bound thread, carefully unlink
				 * it out of the thread list, and add it to
				 * our "tlist".	 We "know" we don't have to
				 * worry about unlinking curthread (the thread
				 * that is executing this code).
				 */
				t->t_next->t_prev = t->t_prev;
				t->t_prev->t_next = t->t_next;
				t->t_next = tlist;
				tlist = t;
				ASSERT(t->t_cid == syscid);
				/* wake up anyone blocked in thread_join */
				cv_broadcast(&t->t_joincv);
				/*
				 * t_lwp set by interrupt threads and not
				 * cleared.
				 */
				t->t_lwp = NULL;
				/*
				 * Pause and idle threads always have
				 * t_state set to TS_ONPROC.
				 */
				t->t_state = TS_FREE;
				t->t_prev = NULL;	/* Just in case */
			}

		} while ((t = tnext) != curthread);

		mutex_exit(&pidlock);

		mutex_sync();
		for (t = tlist; t != NULL; t = tnext) {
			tnext = t->t_next;
			thread_free(t);
		}
	}
}

/*
 * Update the cpu_supp_freqs of this cpu. This information is returned
 * as part of cpu_info kstats. If the cpu_info_kstat exists already, then
 * maintain the kstat data size.
 */
void
cpu_set_supp_freqs(cpu_t *cp, const char *freqs)
{
	char clkstr[sizeof ("18446744073709551615") + 1]; /* ui64 MAX */
	const char *lfreqs = clkstr;
	boolean_t kstat_exists = B_FALSE;
	kstat_t *ksp;
	size_t len;

	/*
	 * A NULL pointer means we only support one speed.
	 */
	if (freqs == NULL)
		(void) snprintf(clkstr, sizeof (clkstr), "%"PRIu64,
		    cp->cpu_curr_clock);
	else
		lfreqs = freqs;

	/*
	 * Make sure the frequency doesn't change while a snapshot is
	 * going on. Of course, we only need to worry about this if
	 * the kstat exists.
	 */
	if ((ksp = cp->cpu_info_kstat) != NULL) {
		mutex_enter(ksp->ks_lock);
		kstat_exists = B_TRUE;
	}

	/*
	 * Free any previously allocated string and if the kstat
	 * already exists, then update its data size.
	 */
	if (cp->cpu_supp_freqs != NULL) {
		len = strlen(cp->cpu_supp_freqs) + 1;
		kmem_free(cp->cpu_supp_freqs, len);
		if (kstat_exists)
			ksp->ks_data_size -= len;
	}

	/*
	 * Allocate the new string and set the pointer.
	 */
	len = strlen(lfreqs) + 1;
	cp->cpu_supp_freqs = kmem_alloc(len, KM_SLEEP);
	(void) strcpy(cp->cpu_supp_freqs, lfreqs);

	/*
	 * If the kstat already exists then update the data size and
	 * free the lock.
	 */
	if (kstat_exists) {
		ksp->ks_data_size += len;
		mutex_exit(ksp->ks_lock);
	}
}

/*
 * Indicate the current CPU's clock freqency (in Hz).
 * The calling context must be such that CPU references are safe.
 */
void
cpu_set_curr_clock(uint64_t new_clk)
{
	uint64_t old_clk;

	old_clk = CPU->cpu_curr_clock;
	CPU->cpu_curr_clock = new_clk;

	/*
	 * The cpu-change-speed DTrace probe exports the frequency in Hz
	 */
	DTRACE_PROBE3(cpu__change__speed, processorid_t, CPU->cpu_id,
	    uint64_t, old_clk, uint64_t, new_clk);
}

/*
 * processor_info(2) and p_online(2) status support functions
 *   The constants returned by the cpu_get_state() and cpu_get_state_str() are
 *   for use in communicating processor state information to userland.  Kernel
 *   subsystems should only be using the cpu_flags value directly.  Subsystems
 *   modifying cpu_flags should record the state change via a call to the
 *   cpu_set_state().
 */

/*
 * Update the pi_state of this CPU.  This function provides the CPU status for
 * the information returned by processor_info(2).
 */
void
cpu_set_state(cpu_t *cpu)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	cpu->cpu_type_info.pi_state = cpu_get_state(cpu);
	cpu->cpu_state_begin = gethrestime_sec();
	pool_cpu_mod = gethrtime();
}

/*
 * Return offline/online/other status for the indicated CPU.  Use only for
 * communication with user applications; cpu_flags provides the in-kernel
 * interface.
 */
int
cpu_get_state(cpu_t *cpu)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	if (cpu->cpu_flags & CPU_POWEROFF)
		return (P_POWEROFF);
	else if (cpu->cpu_flags & CPU_FAULTED)
		return (P_FAULTED);
	else if (cpu->cpu_flags & CPU_SPARE)
		return (P_SPARE);
	else if ((cpu->cpu_flags & (CPU_READY | CPU_OFFLINE)) != CPU_READY)
		return (P_OFFLINE);
	else if (cpu->cpu_flags & CPU_ENABLE)
		return (P_ONLINE);
	else
		return (P_NOINTR);
}

/*
 * Return processor_info(2) state as a string.
 */
const char *
cpu_get_state_str(cpu_t *cpu)
{
	const char *string;

	switch (cpu_get_state(cpu)) {
	case P_ONLINE:
		string = PS_ONLINE;
		break;
	case P_POWEROFF:
		string = PS_POWEROFF;
		break;
	case P_NOINTR:
		string = PS_NOINTR;
		break;
	case P_SPARE:
		string = PS_SPARE;
		break;
	case P_FAULTED:
		string = PS_FAULTED;
		break;
	case P_OFFLINE:
		string = PS_OFFLINE;
		break;
	default:
		string = "unknown";
		break;
	}
	return (string);
}

/*
 * Export this CPU's statistics (cpu_stat_t and cpu_stats_t) as raw and named
 * kstats, respectively.  This is done when a CPU is initialized or placed
 * online via p_online(2).
 */
static void
cpu_stats_kstat_create(cpu_t *cp)
{
	int 	instance = cp->cpu_id;
	char 	*module = "cpu";
	char 	*class = "misc";
	kstat_t	*ksp;
	zoneid_t zoneid;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (pool_pset_enabled())
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = ALL_ZONES;
	/*
	 * Create named kstats
	 */
#define	CPU_STATS_KS_CREATE(name, tsize, update_func)                    \
	ksp = kstat_create_zone(module, instance, (name), class,         \
	    KSTAT_TYPE_NAMED, (tsize) / sizeof (kstat_named_t), 0,       \
	    zoneid);                                                     \
	if (ksp != NULL) {                                               \
		ksp->ks_private = cp;                                    \
		ksp->ks_update = (update_func);                          \
		kstat_install(ksp);                                      \
	} else                                                           \
		cmn_err(CE_WARN, "cpu: unable to create %s:%d:%s kstat", \
		    module, instance, (name));

	CPU_STATS_KS_CREATE("sys", sizeof (cpu_sys_stats_ks_data_template),
	    cpu_sys_stats_ks_update);
	CPU_STATS_KS_CREATE("vm", sizeof (cpu_vm_stats_ks_data_template),
	    cpu_vm_stats_ks_update);

	/*
	 * Export the familiar cpu_stat_t KSTAT_TYPE_RAW kstat.
	 */
	ksp = kstat_create_zone("cpu_stat", cp->cpu_id, NULL,
	    "misc", KSTAT_TYPE_RAW, sizeof (cpu_stat_t), 0, zoneid);
	if (ksp != NULL) {
		ksp->ks_update = cpu_stat_ks_update;
		ksp->ks_private = cp;
		kstat_install(ksp);
	}
}

static void
cpu_stats_kstat_destroy(cpu_t *cp)
{
	char ks_name[KSTAT_STRLEN];

	(void) sprintf(ks_name, "cpu_stat%d", cp->cpu_id);
	kstat_delete_byname("cpu_stat", cp->cpu_id, ks_name);

	kstat_delete_byname("cpu", cp->cpu_id, "sys");
	kstat_delete_byname("cpu", cp->cpu_id, "vm");
}

static int
cpu_sys_stats_ks_update(kstat_t *ksp, int rw)
{
	cpu_t *cp = (cpu_t *)ksp->ks_private;
	struct cpu_sys_stats_ks_data *csskd;
	cpu_sys_stats_t *css;
	hrtime_t msnsecs[NCMSTATES];
	int	i;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	csskd = ksp->ks_data;
	css = &cp->cpu_stats.sys;

	/*
	 * Read CPU mstate, but compare with the last values we
	 * received to make sure that the returned kstats never
	 * decrease.
	 */

	get_cpu_mstate(cp, msnsecs);
	if (csskd->cpu_nsec_idle.value.ui64 > msnsecs[CMS_IDLE])
		msnsecs[CMS_IDLE] = csskd->cpu_nsec_idle.value.ui64;
	if (csskd->cpu_nsec_user.value.ui64 > msnsecs[CMS_USER])
		msnsecs[CMS_USER] = csskd->cpu_nsec_user.value.ui64;
	if (csskd->cpu_nsec_kernel.value.ui64 > msnsecs[CMS_SYSTEM])
		msnsecs[CMS_SYSTEM] = csskd->cpu_nsec_kernel.value.ui64;

	bcopy(&cpu_sys_stats_ks_data_template, ksp->ks_data,
	    sizeof (cpu_sys_stats_ks_data_template));

	csskd->cpu_ticks_wait.value.ui64 = 0;
	csskd->wait_ticks_io.value.ui64 = 0;

	csskd->cpu_nsec_idle.value.ui64 = msnsecs[CMS_IDLE];
	csskd->cpu_nsec_user.value.ui64 = msnsecs[CMS_USER];
	csskd->cpu_nsec_kernel.value.ui64 = msnsecs[CMS_SYSTEM];
	csskd->cpu_ticks_idle.value.ui64 =
	    NSEC_TO_TICK(csskd->cpu_nsec_idle.value.ui64);
	csskd->cpu_ticks_user.value.ui64 =
	    NSEC_TO_TICK(csskd->cpu_nsec_user.value.ui64);
	csskd->cpu_ticks_kernel.value.ui64 =
	    NSEC_TO_TICK(csskd->cpu_nsec_kernel.value.ui64);
	csskd->cpu_nsec_dtrace.value.ui64 = cp->cpu_dtrace_nsec;
	csskd->dtrace_probes.value.ui64 = cp->cpu_dtrace_probes;
	csskd->cpu_nsec_intr.value.ui64 = cp->cpu_intrlast;
	csskd->cpu_load_intr.value.ui64 = cp->cpu_intrload;
	csskd->bread.value.ui64 = css->bread;
	csskd->bwrite.value.ui64 = css->bwrite;
	csskd->lread.value.ui64 = css->lread;
	csskd->lwrite.value.ui64 = css->lwrite;
	csskd->phread.value.ui64 = css->phread;
	csskd->phwrite.value.ui64 = css->phwrite;
	csskd->pswitch.value.ui64 = css->pswitch;
	csskd->trap.value.ui64 = css->trap;
	csskd->intr.value.ui64 = 0;
	for (i = 0; i < PIL_MAX; i++)
		csskd->intr.value.ui64 += css->intr[i];
	csskd->syscall.value.ui64 = css->syscall;
	csskd->sysread.value.ui64 = css->sysread;
	csskd->syswrite.value.ui64 = css->syswrite;
	csskd->sysfork.value.ui64 = css->sysfork;
	csskd->sysvfork.value.ui64 = css->sysvfork;
	csskd->sysexec.value.ui64 = css->sysexec;
	csskd->readch.value.ui64 = css->readch;
	csskd->writech.value.ui64 = css->writech;
	csskd->rcvint.value.ui64 = css->rcvint;
	csskd->xmtint.value.ui64 = css->xmtint;
	csskd->mdmint.value.ui64 = css->mdmint;
	csskd->rawch.value.ui64 = css->rawch;
	csskd->canch.value.ui64 = css->canch;
	csskd->outch.value.ui64 = css->outch;
	csskd->msg.value.ui64 = css->msg;
	csskd->sema.value.ui64 = css->sema;
	csskd->namei.value.ui64 = css->namei;
	csskd->ufsiget.value.ui64 = css->ufsiget;
	csskd->ufsdirblk.value.ui64 = css->ufsdirblk;
	csskd->ufsipage.value.ui64 = css->ufsipage;
	csskd->ufsinopage.value.ui64 = css->ufsinopage;
	csskd->procovf.value.ui64 = css->procovf;
	csskd->intrthread.value.ui64 = 0;
	for (i = 0; i < LOCK_LEVEL - 1; i++)
		csskd->intrthread.value.ui64 += css->intr[i];
	csskd->intrblk.value.ui64 = css->intrblk;
	csskd->intrunpin.value.ui64 = css->intrunpin;
	csskd->idlethread.value.ui64 = css->idlethread;
	csskd->inv_swtch.value.ui64 = css->inv_swtch;
	csskd->nthreads.value.ui64 = css->nthreads;
	csskd->cpumigrate.value.ui64 = css->cpumigrate;
	csskd->xcalls.value.ui64 = css->xcalls;
	csskd->mutex_adenters.value.ui64 = css->mutex_adenters;
	csskd->rw_rdfails.value.ui64 = css->rw_rdfails;
	csskd->rw_wrfails.value.ui64 = css->rw_wrfails;
	csskd->modload.value.ui64 = css->modload;
	csskd->modunload.value.ui64 = css->modunload;
	csskd->bawrite.value.ui64 = css->bawrite;
	csskd->iowait.value.ui64 = css->iowait;

	return (0);
}

static int
cpu_vm_stats_ks_update(kstat_t *ksp, int rw)
{
	cpu_t *cp = (cpu_t *)ksp->ks_private;
	struct cpu_vm_stats_ks_data *cvskd;
	cpu_vm_stats_t *cvs;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	cvs = &cp->cpu_stats.vm;
	cvskd = ksp->ks_data;

	bcopy(&cpu_vm_stats_ks_data_template, ksp->ks_data,
	    sizeof (cpu_vm_stats_ks_data_template));
	cvskd->pgrec.value.ui64 = cvs->pgrec;
	cvskd->pgfrec.value.ui64 = cvs->pgfrec;
	cvskd->pgin.value.ui64 = cvs->pgin;
	cvskd->pgpgin.value.ui64 = cvs->pgpgin;
	cvskd->pgout.value.ui64 = cvs->pgout;
	cvskd->pgpgout.value.ui64 = cvs->pgpgout;
	cvskd->swapin.value.ui64 = cvs->swapin;
	cvskd->pgswapin.value.ui64 = cvs->pgswapin;
	cvskd->swapout.value.ui64 = cvs->swapout;
	cvskd->pgswapout.value.ui64 = cvs->pgswapout;
	cvskd->zfod.value.ui64 = cvs->zfod;
	cvskd->dfree.value.ui64 = cvs->dfree;
	cvskd->scan.value.ui64 = cvs->scan;
	cvskd->rev.value.ui64 = cvs->rev;
	cvskd->hat_fault.value.ui64 = cvs->hat_fault;
	cvskd->as_fault.value.ui64 = cvs->as_fault;
	cvskd->maj_fault.value.ui64 = cvs->maj_fault;
	cvskd->cow_fault.value.ui64 = cvs->cow_fault;
	cvskd->prot_fault.value.ui64 = cvs->prot_fault;
	cvskd->softlock.value.ui64 = cvs->softlock;
	cvskd->kernel_asflt.value.ui64 = cvs->kernel_asflt;
	cvskd->pgrrun.value.ui64 = cvs->pgrrun;
	cvskd->execpgin.value.ui64 = cvs->execpgin;
	cvskd->execpgout.value.ui64 = cvs->execpgout;
	cvskd->execfree.value.ui64 = cvs->execfree;
	cvskd->anonpgin.value.ui64 = cvs->anonpgin;
	cvskd->anonpgout.value.ui64 = cvs->anonpgout;
	cvskd->anonfree.value.ui64 = cvs->anonfree;
	cvskd->fspgin.value.ui64 = cvs->fspgin;
	cvskd->fspgout.value.ui64 = cvs->fspgout;
	cvskd->fsfree.value.ui64 = cvs->fsfree;

	return (0);
}

static int
cpu_stat_ks_update(kstat_t *ksp, int rw)
{
	cpu_stat_t *cso;
	cpu_t *cp;
	int i;
	hrtime_t msnsecs[NCMSTATES];

	cso = (cpu_stat_t *)ksp->ks_data;
	cp = (cpu_t *)ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	/*
	 * Read CPU mstate, but compare with the last values we
	 * received to make sure that the returned kstats never
	 * decrease.
	 */

	get_cpu_mstate(cp, msnsecs);
	msnsecs[CMS_IDLE] = NSEC_TO_TICK(msnsecs[CMS_IDLE]);
	msnsecs[CMS_USER] = NSEC_TO_TICK(msnsecs[CMS_USER]);
	msnsecs[CMS_SYSTEM] = NSEC_TO_TICK(msnsecs[CMS_SYSTEM]);
	if (cso->cpu_sysinfo.cpu[CPU_IDLE] < msnsecs[CMS_IDLE])
		cso->cpu_sysinfo.cpu[CPU_IDLE] = msnsecs[CMS_IDLE];
	if (cso->cpu_sysinfo.cpu[CPU_USER] < msnsecs[CMS_USER])
		cso->cpu_sysinfo.cpu[CPU_USER] = msnsecs[CMS_USER];
	if (cso->cpu_sysinfo.cpu[CPU_KERNEL] < msnsecs[CMS_SYSTEM])
		cso->cpu_sysinfo.cpu[CPU_KERNEL] = msnsecs[CMS_SYSTEM];
	cso->cpu_sysinfo.cpu[CPU_WAIT] 	= 0;
	cso->cpu_sysinfo.wait[W_IO] 	= 0;
	cso->cpu_sysinfo.wait[W_SWAP]	= 0;
	cso->cpu_sysinfo.wait[W_PIO]	= 0;
	cso->cpu_sysinfo.bread 		= CPU_STATS(cp, sys.bread);
	cso->cpu_sysinfo.bwrite 	= CPU_STATS(cp, sys.bwrite);
	cso->cpu_sysinfo.lread 		= CPU_STATS(cp, sys.lread);
	cso->cpu_sysinfo.lwrite 	= CPU_STATS(cp, sys.lwrite);
	cso->cpu_sysinfo.phread 	= CPU_STATS(cp, sys.phread);
	cso->cpu_sysinfo.phwrite 	= CPU_STATS(cp, sys.phwrite);
	cso->cpu_sysinfo.pswitch 	= CPU_STATS(cp, sys.pswitch);
	cso->cpu_sysinfo.trap 		= CPU_STATS(cp, sys.trap);
	cso->cpu_sysinfo.intr		= 0;
	for (i = 0; i < PIL_MAX; i++)
		cso->cpu_sysinfo.intr += CPU_STATS(cp, sys.intr[i]);
	cso->cpu_sysinfo.syscall	= CPU_STATS(cp, sys.syscall);
	cso->cpu_sysinfo.sysread	= CPU_STATS(cp, sys.sysread);
	cso->cpu_sysinfo.syswrite	= CPU_STATS(cp, sys.syswrite);
	cso->cpu_sysinfo.sysfork	= CPU_STATS(cp, sys.sysfork);
	cso->cpu_sysinfo.sysvfork	= CPU_STATS(cp, sys.sysvfork);
	cso->cpu_sysinfo.sysexec	= CPU_STATS(cp, sys.sysexec);
	cso->cpu_sysinfo.readch		= CPU_STATS(cp, sys.readch);
	cso->cpu_sysinfo.writech	= CPU_STATS(cp, sys.writech);
	cso->cpu_sysinfo.rcvint		= CPU_STATS(cp, sys.rcvint);
	cso->cpu_sysinfo.xmtint		= CPU_STATS(cp, sys.xmtint);
	cso->cpu_sysinfo.mdmint		= CPU_STATS(cp, sys.mdmint);
	cso->cpu_sysinfo.rawch		= CPU_STATS(cp, sys.rawch);
	cso->cpu_sysinfo.canch		= CPU_STATS(cp, sys.canch);
	cso->cpu_sysinfo.outch		= CPU_STATS(cp, sys.outch);
	cso->cpu_sysinfo.msg		= CPU_STATS(cp, sys.msg);
	cso->cpu_sysinfo.sema		= CPU_STATS(cp, sys.sema);
	cso->cpu_sysinfo.namei		= CPU_STATS(cp, sys.namei);
	cso->cpu_sysinfo.ufsiget	= CPU_STATS(cp, sys.ufsiget);
	cso->cpu_sysinfo.ufsdirblk	= CPU_STATS(cp, sys.ufsdirblk);
	cso->cpu_sysinfo.ufsipage	= CPU_STATS(cp, sys.ufsipage);
	cso->cpu_sysinfo.ufsinopage	= CPU_STATS(cp, sys.ufsinopage);
	cso->cpu_sysinfo.inodeovf	= 0;
	cso->cpu_sysinfo.fileovf	= 0;
	cso->cpu_sysinfo.procovf	= CPU_STATS(cp, sys.procovf);
	cso->cpu_sysinfo.intrthread	= 0;
	for (i = 0; i < LOCK_LEVEL - 1; i++)
		cso->cpu_sysinfo.intrthread += CPU_STATS(cp, sys.intr[i]);
	cso->cpu_sysinfo.intrblk	= CPU_STATS(cp, sys.intrblk);
	cso->cpu_sysinfo.idlethread	= CPU_STATS(cp, sys.idlethread);
	cso->cpu_sysinfo.inv_swtch	= CPU_STATS(cp, sys.inv_swtch);
	cso->cpu_sysinfo.nthreads	= CPU_STATS(cp, sys.nthreads);
	cso->cpu_sysinfo.cpumigrate	= CPU_STATS(cp, sys.cpumigrate);
	cso->cpu_sysinfo.xcalls		= CPU_STATS(cp, sys.xcalls);
	cso->cpu_sysinfo.mutex_adenters	= CPU_STATS(cp, sys.mutex_adenters);
	cso->cpu_sysinfo.rw_rdfails	= CPU_STATS(cp, sys.rw_rdfails);
	cso->cpu_sysinfo.rw_wrfails	= CPU_STATS(cp, sys.rw_wrfails);
	cso->cpu_sysinfo.modload	= CPU_STATS(cp, sys.modload);
	cso->cpu_sysinfo.modunload	= CPU_STATS(cp, sys.modunload);
	cso->cpu_sysinfo.bawrite	= CPU_STATS(cp, sys.bawrite);
	cso->cpu_sysinfo.rw_enters	= 0;
	cso->cpu_sysinfo.win_uo_cnt	= 0;
	cso->cpu_sysinfo.win_uu_cnt	= 0;
	cso->cpu_sysinfo.win_so_cnt	= 0;
	cso->cpu_sysinfo.win_su_cnt	= 0;
	cso->cpu_sysinfo.win_suo_cnt	= 0;

	cso->cpu_syswait.iowait		= CPU_STATS(cp, sys.iowait);
	cso->cpu_syswait.swap		= 0;
	cso->cpu_syswait.physio		= 0;

	cso->cpu_vminfo.pgrec		= CPU_STATS(cp, vm.pgrec);
	cso->cpu_vminfo.pgfrec		= CPU_STATS(cp, vm.pgfrec);
	cso->cpu_vminfo.pgin		= CPU_STATS(cp, vm.pgin);
	cso->cpu_vminfo.pgpgin		= CPU_STATS(cp, vm.pgpgin);
	cso->cpu_vminfo.pgout		= CPU_STATS(cp, vm.pgout);
	cso->cpu_vminfo.pgpgout		= CPU_STATS(cp, vm.pgpgout);
	cso->cpu_vminfo.swapin		= CPU_STATS(cp, vm.swapin);
	cso->cpu_vminfo.pgswapin	= CPU_STATS(cp, vm.pgswapin);
	cso->cpu_vminfo.swapout		= CPU_STATS(cp, vm.swapout);
	cso->cpu_vminfo.pgswapout	= CPU_STATS(cp, vm.pgswapout);
	cso->cpu_vminfo.zfod		= CPU_STATS(cp, vm.zfod);
	cso->cpu_vminfo.dfree		= CPU_STATS(cp, vm.dfree);
	cso->cpu_vminfo.scan		= CPU_STATS(cp, vm.scan);
	cso->cpu_vminfo.rev		= CPU_STATS(cp, vm.rev);
	cso->cpu_vminfo.hat_fault	= CPU_STATS(cp, vm.hat_fault);
	cso->cpu_vminfo.as_fault	= CPU_STATS(cp, vm.as_fault);
	cso->cpu_vminfo.maj_fault	= CPU_STATS(cp, vm.maj_fault);
	cso->cpu_vminfo.cow_fault	= CPU_STATS(cp, vm.cow_fault);
	cso->cpu_vminfo.prot_fault	= CPU_STATS(cp, vm.prot_fault);
	cso->cpu_vminfo.softlock	= CPU_STATS(cp, vm.softlock);
	cso->cpu_vminfo.kernel_asflt	= CPU_STATS(cp, vm.kernel_asflt);
	cso->cpu_vminfo.pgrrun		= CPU_STATS(cp, vm.pgrrun);
	cso->cpu_vminfo.execpgin	= CPU_STATS(cp, vm.execpgin);
	cso->cpu_vminfo.execpgout	= CPU_STATS(cp, vm.execpgout);
	cso->cpu_vminfo.execfree	= CPU_STATS(cp, vm.execfree);
	cso->cpu_vminfo.anonpgin	= CPU_STATS(cp, vm.anonpgin);
	cso->cpu_vminfo.anonpgout	= CPU_STATS(cp, vm.anonpgout);
	cso->cpu_vminfo.anonfree	= CPU_STATS(cp, vm.anonfree);
	cso->cpu_vminfo.fspgin		= CPU_STATS(cp, vm.fspgin);
	cso->cpu_vminfo.fspgout		= CPU_STATS(cp, vm.fspgout);
	cso->cpu_vminfo.fsfree		= CPU_STATS(cp, vm.fsfree);

	return (0);
}
