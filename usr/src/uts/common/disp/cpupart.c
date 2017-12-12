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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/cpupart.h>
#include <sys/pset.h>
#include <sys/var.h>
#include <sys/cyclic.h>
#include <sys/lgrp.h>
#include <sys/pghw.h>
#include <sys/loadavg.h>
#include <sys/class.h>
#include <sys/fss.h>
#include <sys/pool.h>
#include <sys/pool_pset.h>
#include <sys/policy.h>

/*
 * Calling pool_lock() protects the pools configuration, which includes
 * CPU partitions.  cpu_lock protects the CPU partition list, and prevents
 * partitions from being created or destroyed while the lock is held.
 * The lock ordering with respect to related locks is:
 *
 *    pool_lock() ---> cpu_lock  --->  pidlock  -->  p_lock
 *
 * Blocking memory allocations may be made while holding "pool_lock"
 * or cpu_lock.
 */

/*
 * The cp_default partition is allocated statically, but its lgroup load average
 * (lpl) list is allocated dynamically after kmem subsystem is initialized. This
 * saves some memory since the space allocated reflects the actual number of
 * lgroups supported by the platform. The lgrp facility provides a temporary
 * space to hold lpl information during system bootstrap.
 */

cpupart_t		*cp_list_head;
cpupart_t		cp_default;
static cpupartid_t	cp_id_next;
uint_t			cp_numparts;
uint_t			cp_numparts_nonempty;

/*
 * Need to limit total number of partitions to avoid slowing down the
 * clock code too much.  The clock code traverses the list of
 * partitions and needs to be able to execute in a reasonable amount
 * of time (less than 1/hz seconds).  The maximum is sized based on
 * max_ncpus so it shouldn't be a problem unless there are large
 * numbers of empty partitions.
 */
static uint_t		cp_max_numparts;

/*
 * Processor sets and CPU partitions are different but related concepts.
 * A processor set is a user-level abstraction allowing users to create
 * sets of CPUs and bind threads exclusively to those sets.  A CPU
 * partition is a kernel dispatcher object consisting of a set of CPUs
 * and a global dispatch queue.  The processor set abstraction is
 * implemented via a CPU partition, and currently there is a 1-1
 * mapping between processor sets and partitions (excluding the default
 * partition, which is not visible as a processor set).  Hence, the
 * numbering for processor sets and CPU partitions is identical.  This
 * may not always be true in the future, and these macros could become
 * less trivial if we support e.g. a processor set containing multiple
 * CPU partitions.
 */
#define	PSTOCP(psid)	((cpupartid_t)((psid) == PS_NONE ? CP_DEFAULT : (psid)))
#define	CPTOPS(cpid)	((psetid_t)((cpid) == CP_DEFAULT ? PS_NONE : (cpid)))

static int cpupart_unbind_threads(cpupart_t *, boolean_t);

/*
 * Find a CPU partition given a processor set ID.
 */
static cpupart_t *
cpupart_find_all(psetid_t psid)
{
	cpupart_t *cp;
	cpupartid_t cpid = PSTOCP(psid);

	ASSERT(MUTEX_HELD(&cpu_lock));

	/* default partition not visible as a processor set */
	if (psid == CP_DEFAULT)
		return (NULL);

	if (psid == PS_MYID)
		return (curthread->t_cpupart);

	cp = cp_list_head;
	do {
		if (cp->cp_id == cpid)
			return (cp);
		cp = cp->cp_next;
	} while (cp != cp_list_head);
	return (NULL);
}

/*
 * Find a CPU partition given a processor set ID if the processor set
 * should be visible from the calling zone.
 */
cpupart_t *
cpupart_find(psetid_t psid)
{
	cpupart_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));
	cp = cpupart_find_all(psid);
	if (cp != NULL && !INGLOBALZONE(curproc) && pool_pset_enabled() &&
	    zone_pset_get(curproc->p_zone) != CPTOPS(cp->cp_id))
			return (NULL);
	return (cp);
}

static int
cpupart_kstat_update(kstat_t *ksp, int rw)
{
	cpupart_t *cp = (cpupart_t *)ksp->ks_private;
	cpupart_kstat_t *cpksp = ksp->ks_data;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	cpksp->cpk_updates.value.ui64 = cp->cp_updates;
	cpksp->cpk_runnable.value.ui64 = cp->cp_nrunnable_cum;
	cpksp->cpk_waiting.value.ui64 = cp->cp_nwaiting_cum;
	cpksp->cpk_ncpus.value.ui32 = cp->cp_ncpus;
	cpksp->cpk_avenrun_1min.value.ui32 = cp->cp_hp_avenrun[0] >>
	    (16 - FSHIFT);
	cpksp->cpk_avenrun_5min.value.ui32 = cp->cp_hp_avenrun[1] >>
	    (16 - FSHIFT);
	cpksp->cpk_avenrun_15min.value.ui32 = cp->cp_hp_avenrun[2] >>
	    (16 - FSHIFT);
	return (0);
}

static void
cpupart_kstat_create(cpupart_t *cp)
{
	kstat_t *ksp;
	zoneid_t zoneid;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * We have a bit of a chicken-egg problem since this code will
	 * get called to create the kstats for CP_DEFAULT before the
	 * pools framework gets initialized.  We circumvent the problem
	 * by special-casing cp_default.
	 */
	if (cp != &cp_default && pool_pset_enabled())
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = ALL_ZONES;
	ksp = kstat_create_zone("unix", cp->cp_id, "pset", "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (cpupart_kstat_t) / sizeof (kstat_named_t), 0, zoneid);
	if (ksp != NULL) {
		cpupart_kstat_t *cpksp = ksp->ks_data;

		kstat_named_init(&cpksp->cpk_updates, "updates",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&cpksp->cpk_runnable, "runnable",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&cpksp->cpk_waiting, "waiting",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&cpksp->cpk_ncpus, "ncpus",
		    KSTAT_DATA_UINT32);
		kstat_named_init(&cpksp->cpk_avenrun_1min, "avenrun_1min",
		    KSTAT_DATA_UINT32);
		kstat_named_init(&cpksp->cpk_avenrun_5min, "avenrun_5min",
		    KSTAT_DATA_UINT32);
		kstat_named_init(&cpksp->cpk_avenrun_15min, "avenrun_15min",
		    KSTAT_DATA_UINT32);

		ksp->ks_update = cpupart_kstat_update;
		ksp->ks_private = cp;

		kstat_install(ksp);
	}
	cp->cp_kstat = ksp;
}

/*
 * Initialize the cpupart's lgrp partions (lpls)
 */
static void
cpupart_lpl_initialize(cpupart_t *cp)
{
	int i, sz;

	sz = cp->cp_nlgrploads = lgrp_plat_max_lgrps();
	cp->cp_lgrploads = kmem_zalloc(sizeof (lpl_t) * sz, KM_SLEEP);

	for (i = 0; i < sz; i++) {
		/*
		 * The last entry of the lpl's resource set is always NULL
		 * by design (to facilitate iteration)...hence the "oversizing"
		 * by 1.
		 */
		cp->cp_lgrploads[i].lpl_rset_sz = sz + 1;
		cp->cp_lgrploads[i].lpl_rset =
		    kmem_zalloc(sizeof (struct lgrp_ld *) * (sz + 1), KM_SLEEP);
		cp->cp_lgrploads[i].lpl_id2rset =
		    kmem_zalloc(sizeof (int) * (sz + 1), KM_SLEEP);
		cp->cp_lgrploads[i].lpl_lgrpid = i;
	}
}

/*
 * Teardown the cpupart's lgrp partitions
 */
static void
cpupart_lpl_teardown(cpupart_t *cp)
{
	int i, sz;
	lpl_t *lpl;

	for (i = 0; i < cp->cp_nlgrploads; i++) {
		lpl = &cp->cp_lgrploads[i];

		sz = lpl->lpl_rset_sz;
		kmem_free(lpl->lpl_rset, sizeof (struct lgrp_ld *) * sz);
		kmem_free(lpl->lpl_id2rset, sizeof (int) * sz);
		lpl->lpl_rset = NULL;
		lpl->lpl_id2rset = NULL;
	}
	kmem_free(cp->cp_lgrploads, sizeof (lpl_t) * cp->cp_nlgrploads);
	cp->cp_lgrploads = NULL;
}

/*
 * Initialize the default partition and kpreempt disp queue.
 */
void
cpupart_initialize_default(void)
{
	lgrp_id_t i;

	cp_list_head = &cp_default;
	cp_default.cp_next = &cp_default;
	cp_default.cp_prev = &cp_default;
	cp_default.cp_id = CP_DEFAULT;
	cp_default.cp_kp_queue.disp_maxrunpri = -1;
	cp_default.cp_kp_queue.disp_max_unbound_pri = -1;
	cp_default.cp_kp_queue.disp_cpu = NULL;
	cp_default.cp_gen = 0;
	cp_default.cp_loadavg.lg_cur = 0;
	cp_default.cp_loadavg.lg_len = 0;
	cp_default.cp_loadavg.lg_total = 0;
	for (i = 0; i < S_LOADAVG_SZ; i++) {
		cp_default.cp_loadavg.lg_loads[i] = 0;
	}
	DISP_LOCK_INIT(&cp_default.cp_kp_queue.disp_lock);
	cp_id_next = CP_DEFAULT + 1;
	cpupart_kstat_create(&cp_default);
	cp_numparts = 1;
	if (cp_max_numparts == 0)	/* allow for /etc/system tuning */
		cp_max_numparts = max_ncpus * 2 + 1;
	/*
	 * Allocate space for cp_default list of lgrploads
	 */
	cpupart_lpl_initialize(&cp_default);

	/*
	 * The initial lpl topology is created in a special lpl list
	 * lpl_bootstrap. It should be copied to cp_default.
	 * NOTE: lpl_topo_bootstrap() also updates CPU0 cpu_lpl pointer to point
	 *	 to the correct lpl in the cp_default.cp_lgrploads list.
	 */
	lpl_topo_bootstrap(cp_default.cp_lgrploads,
	    cp_default.cp_nlgrploads);


	cp_default.cp_attr = PSET_NOESCAPE;
	cp_numparts_nonempty = 1;
	/*
	 * Set t0's home
	 */
	t0.t_lpl = &cp_default.cp_lgrploads[LGRP_ROOTID];

	bitset_init(&cp_default.cp_cmt_pgs);
	bitset_init_fanout(&cp_default.cp_haltset, cp_haltset_fanout);

	bitset_resize(&cp_default.cp_haltset, max_ncpus);
}


static int
cpupart_move_cpu(cpu_t *cp, cpupart_t *newpp, int forced)
{
	cpupart_t *oldpp;
	cpu_t	*ncp, *newlist;
	kthread_t *t;
	int	move_threads = 1;
	lgrp_id_t lgrpid;
	proc_t 	*p;
	int lgrp_diff_lpl;
	lpl_t	*cpu_lpl;
	int	ret;
	boolean_t unbind_all_threads = (forced != 0);

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(newpp != NULL);

	oldpp = cp->cpu_part;
	ASSERT(oldpp != NULL);
	ASSERT(oldpp->cp_ncpus > 0);

	if (newpp == oldpp) {
		/*
		 * Don't need to do anything.
		 */
		return (0);
	}

	cpu_state_change_notify(cp->cpu_id, CPU_CPUPART_OUT);

	if (!disp_bound_partition(cp, 0)) {
		/*
		 * Don't need to move threads if there are no threads in
		 * the partition.  Note that threads can't enter the
		 * partition while we're holding cpu_lock.
		 */
		move_threads = 0;
	} else if (oldpp->cp_ncpus == 1) {
		/*
		 * The last CPU is removed from a partition which has threads
		 * running in it. Some of these threads may be bound to this
		 * CPU.
		 *
		 * Attempt to unbind threads from the CPU and from the processor
		 * set. Note that no threads should be bound to this CPU since
		 * cpupart_move_threads will refuse to move bound threads to
		 * other CPUs.
		 */
		(void) cpu_unbind(oldpp->cp_cpulist->cpu_id, B_FALSE);
		(void) cpupart_unbind_threads(oldpp, B_FALSE);

		if (!disp_bound_partition(cp, 0)) {
			/*
			 * No bound threads in this partition any more
			 */
			move_threads = 0;
		} else {
			/*
			 * There are still threads bound to the partition
			 */
			cpu_state_change_notify(cp->cpu_id, CPU_CPUPART_IN);
			return (EBUSY);
		}
	}

	/*
	 * If forced flag is set unbind any threads from this CPU.
	 * Otherwise unbind soft-bound threads only.
	 */
	if ((ret = cpu_unbind(cp->cpu_id, unbind_all_threads)) != 0) {
		cpu_state_change_notify(cp->cpu_id, CPU_CPUPART_IN);
		return (ret);
	}

	/*
	 * Stop further threads weak binding to this cpu.
	 */
	cpu_inmotion = cp;
	membar_enter();

	/*
	 * Notify the Processor Groups subsystem that the CPU
	 * will be moving cpu partitions. This is done before
	 * CPUs are paused to provide an opportunity for any
	 * needed memory allocations.
	 */
	pg_cpupart_out(cp, oldpp);
	pg_cpupart_in(cp, newpp);

again:
	if (move_threads) {
		int loop_count;
		/*
		 * Check for threads strong or weak bound to this CPU.
		 */
		for (loop_count = 0; disp_bound_threads(cp, 0); loop_count++) {
			if (loop_count >= 5) {
				cpu_state_change_notify(cp->cpu_id,
				    CPU_CPUPART_IN);
				pg_cpupart_out(cp, newpp);
				pg_cpupart_in(cp, oldpp);
				cpu_inmotion = NULL;
				return (EBUSY);	/* some threads still bound */
			}
			delay(1);
		}
	}

	/*
	 * Before we actually start changing data structures, notify
	 * the cyclic subsystem that we want to move this CPU out of its
	 * partition.
	 */
	if (!cyclic_move_out(cp)) {
		/*
		 * This CPU must be the last CPU in a processor set with
		 * a bound cyclic.
		 */
		cpu_state_change_notify(cp->cpu_id, CPU_CPUPART_IN);
		pg_cpupart_out(cp, newpp);
		pg_cpupart_in(cp, oldpp);
		cpu_inmotion = NULL;
		return (EBUSY);
	}

	pause_cpus(cp, NULL);

	if (move_threads) {
		/*
		 * The thread on cpu before the pause thread may have read
		 * cpu_inmotion before we raised the barrier above.  Check
		 * again.
		 */
		if (disp_bound_threads(cp, 1)) {
			start_cpus();
			goto again;
		}

	}

	/*
	 * Now that CPUs are paused, let the PG subsystem perform
	 * any necessary data structure updates.
	 */
	pg_cpupart_move(cp, oldpp, newpp);

	/* save this cpu's lgroup -- it'll be the same in the new partition */
	lgrpid = cp->cpu_lpl->lpl_lgrpid;

	cpu_lpl = cp->cpu_lpl;
	/*
	 * let the lgroup framework know cp has left the partition
	 */
	lgrp_config(LGRP_CONFIG_CPUPART_DEL, (uintptr_t)cp, lgrpid);

	/* move out of old partition */
	oldpp->cp_ncpus--;
	if (oldpp->cp_ncpus > 0) {

		ncp = cp->cpu_prev_part->cpu_next_part = cp->cpu_next_part;
		cp->cpu_next_part->cpu_prev_part = cp->cpu_prev_part;
		if (oldpp->cp_cpulist == cp) {
			oldpp->cp_cpulist = ncp;
		}
	} else {
		ncp = oldpp->cp_cpulist = NULL;
		cp_numparts_nonempty--;
		ASSERT(cp_numparts_nonempty != 0);
	}
	oldpp->cp_gen++;

	/* move into new partition */
	newlist = newpp->cp_cpulist;
	if (newlist == NULL) {
		newpp->cp_cpulist = cp->cpu_next_part = cp->cpu_prev_part = cp;
		cp_numparts_nonempty++;
		ASSERT(cp_numparts_nonempty != 0);
	} else {
		cp->cpu_next_part = newlist;
		cp->cpu_prev_part = newlist->cpu_prev_part;
		newlist->cpu_prev_part->cpu_next_part = cp;
		newlist->cpu_prev_part = cp;
	}
	cp->cpu_part = newpp;
	newpp->cp_ncpus++;
	newpp->cp_gen++;

	ASSERT(bitset_is_null(&newpp->cp_haltset));
	ASSERT(bitset_is_null(&oldpp->cp_haltset));

	/*
	 * let the lgroup framework know cp has entered the partition
	 */
	lgrp_config(LGRP_CONFIG_CPUPART_ADD, (uintptr_t)cp, lgrpid);

	/*
	 * If necessary, move threads off processor.
	 */
	if (move_threads) {
		ASSERT(ncp != NULL);

		/*
		 * Walk thru the active process list to look for
		 * threads that need to have a new home lgroup,
		 * or the last CPU they run on is the same CPU
		 * being moved out of the partition.
		 */

		for (p = practive; p != NULL; p = p->p_next) {

			t = p->p_tlist;

			if (t == NULL)
				continue;

			lgrp_diff_lpl = 0;

			do {

				ASSERT(t->t_lpl != NULL);

				/*
				 * Update the count of how many threads are
				 * in this CPU's lgroup but have a different lpl
				 */

				if (t->t_lpl != cpu_lpl &&
				    t->t_lpl->lpl_lgrpid == lgrpid)
					lgrp_diff_lpl++;
				/*
				 * If the lgroup that t is assigned to no
				 * longer has any CPUs in t's partition,
				 * we'll have to choose a new lgroup for t.
				 */

				if (!LGRP_CPUS_IN_PART(t->t_lpl->lpl_lgrpid,
				    t->t_cpupart)) {
					lgrp_move_thread(t,
					    lgrp_choose(t, t->t_cpupart), 0);
				}

				/*
				 * make sure lpl points to our own partition
				 */
				ASSERT(t->t_lpl >= t->t_cpupart->cp_lgrploads &&
				    (t->t_lpl < t->t_cpupart->cp_lgrploads +
				    t->t_cpupart->cp_nlgrploads));

				ASSERT(t->t_lpl->lpl_ncpu > 0);

				/* Update CPU last ran on if it was this CPU */
				if (t->t_cpu == cp && t->t_cpupart == oldpp &&
				    t->t_bound_cpu != cp) {
					t->t_cpu = disp_lowpri_cpu(ncp,
					    t->t_lpl, t->t_pri, NULL);
				}
				t = t->t_forw;
			} while (t != p->p_tlist);

			/*
			 * Didn't find any threads in the same lgroup as this
			 * CPU with a different lpl, so remove the lgroup from
			 * the process lgroup bitmask.
			 */

			if (lgrp_diff_lpl)
				klgrpset_del(p->p_lgrpset, lgrpid);
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
			 * If the lgroup that t is assigned to no
			 * longer has any CPUs in t's partition,
			 * we'll have to choose a new lgroup for t.
			 * Also, choose best lgroup for home when
			 * thread has specified lgroup affinities,
			 * since there may be an lgroup with more
			 * affinity available after moving CPUs
			 * around.
			 */
			if (!LGRP_CPUS_IN_PART(t->t_lpl->lpl_lgrpid,
			    t->t_cpupart) || t->t_lgrp_affinity) {
				lgrp_move_thread(t,
				    lgrp_choose(t, t->t_cpupart), 1);
			}

			/* make sure lpl points to our own partition */
			ASSERT((t->t_lpl >= t->t_cpupart->cp_lgrploads) &&
			    (t->t_lpl < t->t_cpupart->cp_lgrploads +
			    t->t_cpupart->cp_nlgrploads));

			ASSERT(t->t_lpl->lpl_ncpu > 0);

			/* Update CPU last ran on if it was this CPU */
			if (t->t_cpu == cp && t->t_cpupart == oldpp &&
			    t->t_bound_cpu != cp) {
				t->t_cpu = disp_lowpri_cpu(ncp, t->t_lpl,
				    t->t_pri, NULL);
			}

			t = t->t_next;
		} while (t != curthread);

		/*
		 * Clear off the CPU's run queue, and the kp queue if the
		 * partition is now empty.
		 */
		disp_cpu_inactive(cp);

		/*
		 * Make cp switch to a thread from the new partition.
		 */
		cp->cpu_runrun = 1;
		cp->cpu_kprunrun = 1;
	}

	cpu_inmotion = NULL;
	start_cpus();

	/*
	 * Let anyone interested know that cpu has been added to the set.
	 */
	cpu_state_change_notify(cp->cpu_id, CPU_CPUPART_IN);

	/*
	 * Now let the cyclic subsystem know that it can reshuffle cyclics
	 * bound to the new processor set.
	 */
	cyclic_move_in(cp);

	return (0);
}

/*
 * Check if thread can be moved to a new cpu partition.  Called by
 * cpupart_move_thread() and pset_bind_start().
 */
int
cpupart_movable_thread(kthread_id_t tp, cpupart_t *cp, int ignore)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&ttoproc(tp)->p_lock));
	ASSERT(cp != NULL);
	ASSERT(THREAD_LOCK_HELD(tp));

	/*
	 * CPU-bound threads can't be moved.
	 */
	if (!ignore) {
		cpu_t *boundcpu = tp->t_bound_cpu ? tp->t_bound_cpu :
		    tp->t_weakbound_cpu;
		if (boundcpu != NULL && boundcpu->cpu_part != cp)
			return (EBUSY);
	}

	if (tp->t_cid == sysdccid) {
		return (EINVAL);	/* For now, sysdc threads can't move */
	}

	return (0);
}

/*
 * Move thread to new partition.  If ignore is non-zero, then CPU
 * bindings should be ignored (this is used when destroying a
 * partition).
 */
static int
cpupart_move_thread(kthread_id_t tp, cpupart_t *newpp, int ignore,
    void *projbuf, void *zonebuf)
{
	cpupart_t *oldpp = tp->t_cpupart;
	int ret;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&ttoproc(tp)->p_lock));
	ASSERT(newpp != NULL);

	if (newpp->cp_cpulist == NULL)
		return (EINVAL);

	/*
	 * Check for errors first.
	 */
	thread_lock(tp);
	if ((ret = cpupart_movable_thread(tp, newpp, ignore)) != 0) {
		thread_unlock(tp);
		return (ret);
	}

	/* move the thread */
	if (oldpp != newpp) {
		/*
		 * Make the thread switch to the new partition.
		 */
		tp->t_cpupart = newpp;
		ASSERT(tp->t_lpl != NULL);
		/*
		 * Leave the thread on the same lgroup if possible; otherwise
		 * choose a new lgroup for it.  In either case, update its
		 * t_lpl.
		 */
		if (LGRP_CPUS_IN_PART(tp->t_lpl->lpl_lgrpid, newpp) &&
		    tp->t_lgrp_affinity == NULL) {
			/*
			 * The thread's lgroup has CPUs in the thread's new
			 * partition, so the thread can stay assigned to the
			 * same lgroup.  Update its t_lpl to point to the
			 * lpl_t for its lgroup in its new partition.
			 */
			lgrp_move_thread(tp, &tp->t_cpupart->\
			    cp_lgrploads[tp->t_lpl->lpl_lgrpid], 1);
		} else {
			/*
			 * The thread's lgroup has no cpus in its new
			 * partition or it has specified lgroup affinities,
			 * so choose the best lgroup for the thread and
			 * assign it to that lgroup.
			 */
			lgrp_move_thread(tp, lgrp_choose(tp, tp->t_cpupart),
			    1);
		}
		/*
		 * make sure lpl points to our own partition
		 */
		ASSERT((tp->t_lpl >= tp->t_cpupart->cp_lgrploads) &&
		    (tp->t_lpl < tp->t_cpupart->cp_lgrploads +
		    tp->t_cpupart->cp_nlgrploads));

		ASSERT(tp->t_lpl->lpl_ncpu > 0);

		if (tp->t_state == TS_ONPROC) {
			cpu_surrender(tp);
		} else if (tp->t_state == TS_RUN) {
			(void) dispdeq(tp);
			setbackdq(tp);
		}
	}

	/*
	 * Our binding has changed; set TP_CHANGEBIND.
	 */
	tp->t_proc_flag |= TP_CHANGEBIND;
	aston(tp);

	thread_unlock(tp);
	fss_changepset(tp, newpp, projbuf, zonebuf);

	return (0);		/* success */
}


/*
 * This function binds a thread to a partition.  Must be called with the
 * p_lock of the containing process held (to keep the thread from going
 * away), and thus also with cpu_lock held (since cpu_lock must be
 * acquired before p_lock).  If ignore is non-zero, then CPU bindings
 * should be ignored (this is used when destroying a partition).
 */
int
cpupart_bind_thread(kthread_id_t tp, psetid_t psid, int ignore, void *projbuf,
    void *zonebuf)
{
	cpupart_t	*newpp;

	ASSERT(pool_lock_held());
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&ttoproc(tp)->p_lock));

	if (psid == PS_NONE)
		newpp = &cp_default;
	else {
		newpp = cpupart_find(psid);
		if (newpp == NULL) {
			return (EINVAL);
		}
	}
	return (cpupart_move_thread(tp, newpp, ignore, projbuf, zonebuf));
}


/*
 * Create a new partition.  On MP systems, this also allocates a
 * kpreempt disp queue for that partition.
 */
int
cpupart_create(psetid_t *psid)
{
	cpupart_t	*pp;

	ASSERT(pool_lock_held());

	pp = kmem_zalloc(sizeof (cpupart_t), KM_SLEEP);

	mutex_enter(&cpu_lock);
	if (cp_numparts == cp_max_numparts) {
		mutex_exit(&cpu_lock);
		kmem_free(pp, sizeof (cpupart_t));
		return (ENOMEM);
	}
	cp_numparts++;
	/* find the next free partition ID */
	while (cpupart_find(CPTOPS(cp_id_next)) != NULL)
		cp_id_next++;
	pp->cp_id = cp_id_next++;
	pp->cp_ncpus = 0;
	pp->cp_cpulist = NULL;
	pp->cp_attr = 0;
	klgrpset_clear(pp->cp_lgrpset);
	pp->cp_kp_queue.disp_maxrunpri = -1;
	pp->cp_kp_queue.disp_max_unbound_pri = -1;
	pp->cp_kp_queue.disp_cpu = NULL;
	pp->cp_gen = 0;
	DISP_LOCK_INIT(&pp->cp_kp_queue.disp_lock);
	*psid = CPTOPS(pp->cp_id);
	disp_kp_alloc(&pp->cp_kp_queue, v.v_nglobpris);
	cpupart_kstat_create(pp);
	cpupart_lpl_initialize(pp);

	bitset_init(&pp->cp_cmt_pgs);

	/*
	 * Initialize and size the partition's bitset of halted CPUs.
	 */
	bitset_init_fanout(&pp->cp_haltset, cp_haltset_fanout);
	bitset_resize(&pp->cp_haltset, max_ncpus);

	/*
	 * Pause all CPUs while changing the partition list, to make sure
	 * the clock thread (which traverses the list without holding
	 * cpu_lock) isn't running.
	 */
	pause_cpus(NULL, NULL);
	pp->cp_next = cp_list_head;
	pp->cp_prev = cp_list_head->cp_prev;
	cp_list_head->cp_prev->cp_next = pp;
	cp_list_head->cp_prev = pp;
	start_cpus();
	mutex_exit(&cpu_lock);

	return (0);
}

/*
 * Move threads from specified partition to cp_default. If `force' is specified,
 * move all threads, otherwise move only soft-bound threads.
 */
static int
cpupart_unbind_threads(cpupart_t *pp, boolean_t unbind_all)
{
	void 	*projbuf, *zonebuf;
	kthread_t *t;
	proc_t	*p;
	int	err = 0;
	psetid_t psid = pp->cp_id;

	ASSERT(pool_lock_held());
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (pp == NULL || pp == &cp_default) {
		return (EINVAL);
	}

	/*
	 * Pre-allocate enough buffers for FSS for all active projects and
	 * for all active zones on the system.  Unused buffers will be
	 * freed later by fss_freebuf().
	 */
	projbuf = fss_allocbuf(FSS_NPROJ_BUF, FSS_ALLOC_PROJ);
	zonebuf = fss_allocbuf(FSS_NPROJ_BUF, FSS_ALLOC_ZONE);

	mutex_enter(&pidlock);
	t = curthread;
	do {
		if (t->t_bind_pset == psid) {
again:			p = ttoproc(t);
			mutex_enter(&p->p_lock);
			if (ttoproc(t) != p) {
				/*
				 * lwp_exit has changed this thread's process
				 * pointer before we grabbed its p_lock.
				 */
				mutex_exit(&p->p_lock);
				goto again;
			}

			/*
			 * Can only unbind threads which have revocable binding
			 * unless force unbinding requested.
			 */
			if (unbind_all || TB_PSET_IS_SOFT(t)) {
				err = cpupart_bind_thread(t, PS_NONE, 1,
				    projbuf, zonebuf);
				if (err) {
					mutex_exit(&p->p_lock);
					mutex_exit(&pidlock);
					fss_freebuf(projbuf, FSS_ALLOC_PROJ);
					fss_freebuf(zonebuf, FSS_ALLOC_ZONE);
					return (err);
				}
				t->t_bind_pset = PS_NONE;
			}
			mutex_exit(&p->p_lock);
		}
		t = t->t_next;
	} while (t != curthread);

	mutex_exit(&pidlock);
	fss_freebuf(projbuf, FSS_ALLOC_PROJ);
	fss_freebuf(zonebuf, FSS_ALLOC_ZONE);
	return (err);
}

/*
 * Destroy a partition.
 */
int
cpupart_destroy(psetid_t psid)
{
	cpu_t	*cp, *first_cp;
	cpupart_t *pp, *newpp;
	int	err = 0;

	ASSERT(pool_lock_held());
	mutex_enter(&cpu_lock);

	pp = cpupart_find(psid);
	if (pp == NULL || pp == &cp_default) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}

	/*
	 * Unbind all the threads currently bound to the partition.
	 */
	err = cpupart_unbind_threads(pp, B_TRUE);
	if (err) {
		mutex_exit(&cpu_lock);
		return (err);
	}

	newpp = &cp_default;
	while ((cp = pp->cp_cpulist) != NULL) {
		if (err = cpupart_move_cpu(cp, newpp, 0)) {
			mutex_exit(&cpu_lock);
			return (err);
		}
	}

	ASSERT(bitset_is_null(&pp->cp_cmt_pgs));
	ASSERT(bitset_is_null(&pp->cp_haltset));

	/*
	 * Teardown the partition's group of active CMT PGs and halted
	 * CPUs now that they have all left.
	 */
	bitset_fini(&pp->cp_cmt_pgs);
	bitset_fini(&pp->cp_haltset);

	/*
	 * Reset the pointers in any offline processors so they won't
	 * try to rejoin the destroyed partition when they're turned
	 * online.
	 */
	first_cp = cp = CPU;
	do {
		if (cp->cpu_part == pp) {
			ASSERT(cp->cpu_flags & CPU_OFFLINE);
			cp->cpu_part = newpp;
		}
		cp = cp->cpu_next;
	} while (cp != first_cp);

	/*
	 * Pause all CPUs while changing the partition list, to make sure
	 * the clock thread (which traverses the list without holding
	 * cpu_lock) isn't running.
	 */
	pause_cpus(NULL, NULL);
	pp->cp_prev->cp_next = pp->cp_next;
	pp->cp_next->cp_prev = pp->cp_prev;
	if (cp_list_head == pp)
		cp_list_head = pp->cp_next;
	start_cpus();

	if (cp_id_next > pp->cp_id)
		cp_id_next = pp->cp_id;

	if (pp->cp_kstat)
		kstat_delete(pp->cp_kstat);

	cp_numparts--;

	disp_kp_free(&pp->cp_kp_queue);

	cpupart_lpl_teardown(pp);

	kmem_free(pp, sizeof (cpupart_t));
	mutex_exit(&cpu_lock);

	return (err);
}


/*
 * Return the ID of the partition to which the specified processor belongs.
 */
psetid_t
cpupart_query_cpu(cpu_t *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	return (CPTOPS(cp->cpu_part->cp_id));
}


/*
 * Attach a processor to an existing partition.
 */
int
cpupart_attach_cpu(psetid_t psid, cpu_t *cp, int forced)
{
	cpupart_t	*pp;
	int		err;

	ASSERT(pool_lock_held());
	ASSERT(MUTEX_HELD(&cpu_lock));

	pp = cpupart_find(psid);
	if (pp == NULL)
		return (EINVAL);
	if (cp->cpu_flags & CPU_OFFLINE)
		return (EINVAL);

	err = cpupart_move_cpu(cp, pp, forced);
	return (err);
}

/*
 * Get a list of cpus belonging to the partition.  If numcpus is NULL,
 * this just checks for a valid partition.  If numcpus is non-NULL but
 * cpulist is NULL, the current number of cpus is stored in *numcpus.
 * If both are non-NULL, the current number of cpus is stored in *numcpus,
 * and a list of those cpus up to the size originally in *numcpus is
 * stored in cpulist[].  Also, store the processor set id in *psid.
 * This is useful in case the processor set id passed in was PS_MYID.
 */
int
cpupart_get_cpus(psetid_t *psid, processorid_t *cpulist, uint_t *numcpus)
{
	cpupart_t	*pp;
	uint_t		ncpus;
	cpu_t		*c;
	int		i;

	mutex_enter(&cpu_lock);
	pp = cpupart_find(*psid);
	if (pp == NULL) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}
	*psid = CPTOPS(pp->cp_id);
	ncpus = pp->cp_ncpus;
	if (numcpus) {
		if (ncpus > *numcpus) {
			/*
			 * Only copy as many cpus as were passed in, but
			 * pass back the real number.
			 */
			uint_t t = ncpus;
			ncpus = *numcpus;
			*numcpus = t;
		} else
			*numcpus = ncpus;

		if (cpulist) {
			c = pp->cp_cpulist;
			for (i = 0; i < ncpus; i++) {
				ASSERT(c != NULL);
				cpulist[i] = c->cpu_id;
				c = c->cpu_next_part;
			}
		}
	}
	mutex_exit(&cpu_lock);
	return (0);
}

/*
 * Reallocate kpreempt queues for each CPU partition.  Called from
 * disp_setup when a new scheduling class is loaded that increases the
 * number of priorities in the system.
 */
void
cpupart_kpqalloc(pri_t npri)
{
	cpupart_t *cpp;

	ASSERT(MUTEX_HELD(&cpu_lock));
	cpp = cp_list_head;
	do {
		disp_kp_alloc(&cpp->cp_kp_queue, npri);
		cpp = cpp->cp_next;
	} while (cpp != cp_list_head);
}

int
cpupart_get_loadavg(psetid_t psid, int *buf, int nelem)
{
	cpupart_t *cp;
	int i;

	ASSERT(nelem >= 0);
	ASSERT(nelem <= LOADAVG_NSTATS);
	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpupart_find(psid);
	if (cp == NULL)
		return (EINVAL);
	for (i = 0; i < nelem; i++)
		buf[i] = cp->cp_hp_avenrun[i] >> (16 - FSHIFT);

	return (0);
}


uint_t
cpupart_list(psetid_t *list, uint_t nelem, int flag)
{
	uint_t numpart = 0;
	cpupart_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(flag == CP_ALL || flag == CP_NONEMPTY);

	if (list != NULL) {
		cp = cp_list_head;
		do {
			if (((flag == CP_ALL) && (cp != &cp_default)) ||
			    ((flag == CP_NONEMPTY) && (cp->cp_ncpus != 0))) {
				if (numpart == nelem)
					break;
				list[numpart++] = CPTOPS(cp->cp_id);
			}
			cp = cp->cp_next;
		} while (cp != cp_list_head);
	}

	ASSERT(numpart < cp_numparts);

	if (flag == CP_ALL)
		numpart = cp_numparts - 1; /* leave out default partition */
	else if (flag == CP_NONEMPTY)
		numpart = cp_numparts_nonempty;

	return (numpart);
}

int
cpupart_setattr(psetid_t psid, uint_t attr)
{
	cpupart_t *cp;

	ASSERT(pool_lock_held());

	mutex_enter(&cpu_lock);
	if ((cp = cpupart_find(psid)) == NULL) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}
	/*
	 * PSET_NOESCAPE attribute for default cpu partition is always set
	 */
	if (cp == &cp_default && !(attr & PSET_NOESCAPE)) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}
	cp->cp_attr = attr;
	mutex_exit(&cpu_lock);
	return (0);
}

int
cpupart_getattr(psetid_t psid, uint_t *attrp)
{
	cpupart_t *cp;

	mutex_enter(&cpu_lock);
	if ((cp = cpupart_find(psid)) == NULL) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}
	*attrp = cp->cp_attr;
	mutex_exit(&cpu_lock);
	return (0);
}
