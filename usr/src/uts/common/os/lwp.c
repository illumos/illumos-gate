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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <sys/vmparam.h>
#include <sys/stack.h>
#include <sys/procfs.h>
#include <sys/prsystm.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/vtrace.h>
#include <sys/door.h>
#include <vm/seg_kp.h>
#include <sys/debug.h>
#include <sys/tnf.h>
#include <sys/schedctl.h>
#include <sys/poll.h>
#include <sys/copyops.h>
#include <sys/lwp_upimutex_impl.h>
#include <sys/cpupart.h>
#include <sys/lgrp.h>
#include <sys/rctl.h>
#include <sys/contract_impl.h>
#include <sys/cpc_impl.h>
#include <sys/sdt.h>
#include <sys/cmn_err.h>
#include <sys/brand.h>
#include <sys/cyclic.h>
#include <sys/pool.h>

/* hash function for the lwpid hash table, p->p_tidhash[] */
#define	TIDHASH(tid, hash_sz)	((tid) & ((hash_sz) - 1))

void *segkp_lwp;		/* cookie for pool of segkp resources */
extern void reapq_move_lq_to_tq(kthread_t *);
extern void freectx_ctx(struct ctxop *);

/*
 * Create a kernel thread associated with a particular system process.  Give
 * it an LWP so that microstate accounting will be available for it.
 */
kthread_t *
lwp_kernel_create(proc_t *p, void (*proc)(), void *arg, int state, pri_t pri)
{
	klwp_t *lwp;

	VERIFY((p->p_flag & SSYS) != 0);

	lwp = lwp_create(proc, arg, 0, p, state, pri, &t0.t_hold, syscid, 0);

	VERIFY(lwp != NULL);

	return (lwptot(lwp));
}

/*
 * Create a thread that appears to be stopped at sys_rtt.
 */
klwp_t *
lwp_create(void (*proc)(), caddr_t arg, size_t len, proc_t *p,
    int state, int pri, const k_sigset_t *smask, int cid, id_t lwpid)
{
	klwp_t *lwp = NULL;
	kthread_t *t;
	kthread_t *tx;
	cpupart_t *oldpart = NULL;
	size_t	stksize;
	caddr_t lwpdata = NULL;
	processorid_t	binding;
	int err = 0;
	kproject_t *oldkpj, *newkpj;
	void *bufp = NULL;
	klwp_t *curlwp;
	lwpent_t *lep;
	lwpdir_t *old_dir = NULL;
	uint_t old_dirsz = 0;
	tidhash_t *old_hash = NULL;
	uint_t old_hashsz = 0;
	ret_tidhash_t *ret_tidhash = NULL;
	int i;
	int rctlfail = 0;
	boolean_t branded = 0;
	struct ctxop *ctx = NULL;

	ASSERT(cid != sysdccid);	/* system threads must start in SYS */

	ASSERT(p != &p0);		/* No new LWPs in p0. */

	mutex_enter(&p->p_lock);
	mutex_enter(&p->p_zone->zone_nlwps_lock);
	/*
	 * don't enforce rctl limits on system processes
	 */
	if (!CLASS_KERNEL(cid)) {
		if (p->p_task->tk_nlwps >= p->p_task->tk_nlwps_ctl)
			if (rctl_test(rc_task_lwps, p->p_task->tk_rctls, p,
			    1, 0) & RCT_DENY)
				rctlfail = 1;
		if (p->p_task->tk_proj->kpj_nlwps >=
		    p->p_task->tk_proj->kpj_nlwps_ctl)
			if (rctl_test(rc_project_nlwps,
			    p->p_task->tk_proj->kpj_rctls, p, 1, 0)
			    & RCT_DENY)
				rctlfail = 1;
		if (p->p_zone->zone_nlwps >= p->p_zone->zone_nlwps_ctl)
			if (rctl_test(rc_zone_nlwps, p->p_zone->zone_rctls, p,
			    1, 0) & RCT_DENY)
				rctlfail = 1;
	}
	if (rctlfail) {
		mutex_exit(&p->p_zone->zone_nlwps_lock);
		mutex_exit(&p->p_lock);
		atomic_inc_32(&p->p_zone->zone_ffcap);
		return (NULL);
	}
	p->p_task->tk_nlwps++;
	p->p_task->tk_proj->kpj_nlwps++;
	p->p_zone->zone_nlwps++;
	mutex_exit(&p->p_zone->zone_nlwps_lock);
	mutex_exit(&p->p_lock);

	curlwp = ttolwp(curthread);
	if (curlwp == NULL || (stksize = curlwp->lwp_childstksz) == 0)
		stksize = lwp_default_stksize;

	if (CLASS_KERNEL(cid)) {
		/*
		 * Since we are creating an LWP in an SSYS process, we do not
		 * inherit anything from the current thread's LWP.  We set
		 * stksize and lwpdata to 0 in order to let thread_create()
		 * allocate a regular kernel thread stack for this thread.
		 */
		curlwp = NULL;
		stksize = 0;
		lwpdata = NULL;

	} else if (stksize == lwp_default_stksize) {
		/*
		 * Try to reuse an <lwp,stack> from the LWP deathrow.
		 */
		if (lwp_reapcnt > 0) {
			mutex_enter(&reaplock);
			if ((t = lwp_deathrow) != NULL) {
				ASSERT(t->t_swap);
				lwp_deathrow = t->t_forw;
				lwp_reapcnt--;
				lwpdata = t->t_swap;
				lwp = t->t_lwp;
				ctx = t->t_ctx;
				t->t_swap = NULL;
				t->t_lwp = NULL;
				t->t_ctx = NULL;
				reapq_move_lq_to_tq(t);
			}
			mutex_exit(&reaplock);
			if (lwp != NULL) {
				lwp_stk_fini(lwp);
			}
			if (ctx != NULL) {
				freectx_ctx(ctx);
			}
		}
		if (lwpdata == NULL &&
		    (lwpdata = (caddr_t)segkp_cache_get(segkp_lwp)) == NULL) {
			mutex_enter(&p->p_lock);
			mutex_enter(&p->p_zone->zone_nlwps_lock);
			p->p_task->tk_nlwps--;
			p->p_task->tk_proj->kpj_nlwps--;
			p->p_zone->zone_nlwps--;
			mutex_exit(&p->p_zone->zone_nlwps_lock);
			mutex_exit(&p->p_lock);
			atomic_inc_32(&p->p_zone->zone_ffnomem);
			return (NULL);
		}
	} else {
		stksize = roundup(stksize, PAGESIZE);
		if ((lwpdata = (caddr_t)segkp_get(segkp, stksize,
		    (KPD_NOWAIT | KPD_HASREDZONE | KPD_LOCKED))) == NULL) {
			mutex_enter(&p->p_lock);
			mutex_enter(&p->p_zone->zone_nlwps_lock);
			p->p_task->tk_nlwps--;
			p->p_task->tk_proj->kpj_nlwps--;
			p->p_zone->zone_nlwps--;
			mutex_exit(&p->p_zone->zone_nlwps_lock);
			mutex_exit(&p->p_lock);
			atomic_inc_32(&p->p_zone->zone_ffnomem);
			return (NULL);
		}
	}

	/*
	 * Create a thread, initializing the stack pointer
	 */
	t = thread_create(lwpdata, stksize, NULL, NULL, 0, p, TS_STOPPED, pri);

	/*
	 * If a non-NULL stack base is passed in, thread_create() assumes
	 * that the stack might be statically allocated (as opposed to being
	 * allocated from segkp), and so it does not set t_swap.  Since
	 * the lwpdata was allocated from segkp, we must set t_swap to point
	 * to it ourselves.
	 *
	 * This would be less confusing if t_swap had a better name; it really
	 * indicates that the stack is allocated from segkp, regardless of
	 * whether or not it is swappable.
	 */
	if (lwpdata != NULL) {
		ASSERT(!CLASS_KERNEL(cid));
		ASSERT(t->t_swap == NULL);
		t->t_swap = lwpdata;	/* Start of page-able data */
	}

	/*
	 * If the stack and lwp can be reused, mark the thread as such.
	 * When we get to reapq_add() from resume_from_zombie(), these
	 * threads will go onto lwp_deathrow instead of thread_deathrow.
	 */
	if (!CLASS_KERNEL(cid) && stksize == lwp_default_stksize)
		t->t_flag |= T_LWPREUSE;

	if (lwp == NULL)
		lwp = kmem_cache_alloc(lwp_cache, KM_SLEEP);
	bzero(lwp, sizeof (*lwp));
	t->t_lwp = lwp;

	t->t_hold = *smask;
	lwp->lwp_thread = t;
	lwp->lwp_procp = p;
	lwp->lwp_sigaltstack.ss_flags = SS_DISABLE;
	if (curlwp != NULL && curlwp->lwp_childstksz != 0)
		lwp->lwp_childstksz = curlwp->lwp_childstksz;

	t->t_stk = lwp_stk_init(lwp, t->t_stk);
	thread_load(t, proc, arg, len);

	/*
	 * Allocate the SIGPROF buffer if ITIMER_REALPROF is in effect.
	 */
	if (p->p_rprof_cyclic != CYCLIC_NONE)
		t->t_rprof = kmem_zalloc(sizeof (struct rprof), KM_SLEEP);

	if (cid != NOCLASS)
		(void) CL_ALLOC(&bufp, cid, KM_SLEEP);

	/*
	 * Allocate an lwp directory entry for the new lwp.
	 */
	lep = kmem_zalloc(sizeof (*lep), KM_SLEEP);

	mutex_enter(&p->p_lock);
grow:
	/*
	 * Grow the lwp (thread) directory and lwpid hash table if necessary.
	 * A note on the growth algorithm:
	 *	The new lwp directory size is computed as:
	 *		new = 2 * old + 2
	 *	Starting with an initial size of 2 (see exec_common()),
	 *	this yields numbers that are a power of two minus 2:
	 *		2, 6, 14, 30, 62, 126, 254, 510, 1022, ...
	 *	The size of the lwpid hash table must be a power of two
	 *	and must be commensurate in size with the lwp directory
	 *	so that hash bucket chains remain short.  Therefore,
	 *	the lwpid hash table size is computed as:
	 *		hashsz = (dirsz + 2) / 2
	 *	which leads to these hash table sizes corresponding to
	 *	the above directory sizes:
	 *		2, 4, 8, 16, 32, 64, 128, 256, 512, ...
	 * A note on growing the hash table:
	 *	For performance reasons, code in lwp_unpark() does not
	 *	acquire curproc->p_lock when searching the hash table.
	 *	Rather, it calls lwp_hash_lookup_and_lock() which
	 *	acquires only the individual hash bucket lock, taking
	 *	care to deal with reallocation of the hash table
	 *	during the time it takes to acquire the lock.
	 *
	 *	This is sufficient to protect the integrity of the
	 *	hash table, but it requires us to acquire all of the
	 *	old hash bucket locks before growing the hash table
	 *	and to release them afterwards.  It also requires us
	 *	not to free the old hash table because some thread
	 *	in lwp_hash_lookup_and_lock() might still be trying
	 *	to acquire the old bucket lock.
	 *
	 *	So we adopt the tactic of keeping all of the retired
	 *	hash tables on a linked list, so they can be safely
	 *	freed when the process exits or execs.
	 *
	 *	Because the hash table grows in powers of two, the
	 *	total size of all of the hash tables will be slightly
	 *	less than twice the size of the largest hash table.
	 */
	while (p->p_lwpfree == NULL) {
		uint_t dirsz = p->p_lwpdir_sz;
		lwpdir_t *new_dir;
		uint_t new_dirsz;
		lwpdir_t *ldp;
		tidhash_t *new_hash;
		uint_t new_hashsz;

		mutex_exit(&p->p_lock);

		/*
		 * Prepare to remember the old p_tidhash for later
		 * kmem_free()ing when the process exits or execs.
		 */
		if (ret_tidhash == NULL)
			ret_tidhash = kmem_zalloc(sizeof (ret_tidhash_t),
			    KM_SLEEP);
		if (old_dir != NULL)
			kmem_free(old_dir, old_dirsz * sizeof (*old_dir));
		if (old_hash != NULL)
			kmem_free(old_hash, old_hashsz * sizeof (*old_hash));

		new_dirsz = 2 * dirsz + 2;
		new_dir = kmem_zalloc(new_dirsz * sizeof (lwpdir_t), KM_SLEEP);
		for (ldp = new_dir, i = 1; i < new_dirsz; i++, ldp++)
			ldp->ld_next = ldp + 1;
		new_hashsz = (new_dirsz + 2) / 2;
		new_hash = kmem_zalloc(new_hashsz * sizeof (tidhash_t),
		    KM_SLEEP);

		mutex_enter(&p->p_lock);
		if (p == curproc)
			prbarrier(p);

		if (dirsz != p->p_lwpdir_sz || p->p_lwpfree != NULL) {
			/*
			 * Someone else beat us to it or some lwp exited.
			 * Set up to free our memory and take a lap.
			 */
			old_dir = new_dir;
			old_dirsz = new_dirsz;
			old_hash = new_hash;
			old_hashsz = new_hashsz;
		} else {
			/*
			 * For the benefit of lwp_hash_lookup_and_lock(),
			 * called from lwp_unpark(), which searches the
			 * tid hash table without acquiring p->p_lock,
			 * we must acquire all of the tid hash table
			 * locks before replacing p->p_tidhash.
			 */
			old_hash = p->p_tidhash;
			old_hashsz = p->p_tidhash_sz;
			for (i = 0; i < old_hashsz; i++) {
				mutex_enter(&old_hash[i].th_lock);
				mutex_enter(&new_hash[i].th_lock);
			}

			/*
			 * We simply hash in all of the old directory entries.
			 * This works because the old directory has no empty
			 * slots and the new hash table starts out empty.
			 * This reproduces the original directory ordering
			 * (required for /proc directory semantics).
			 */
			old_dir = p->p_lwpdir;
			old_dirsz = p->p_lwpdir_sz;
			p->p_lwpdir = new_dir;
			p->p_lwpfree = new_dir;
			p->p_lwpdir_sz = new_dirsz;
			for (ldp = old_dir, i = 0; i < old_dirsz; i++, ldp++)
				lwp_hash_in(p, ldp->ld_entry,
				    new_hash, new_hashsz, 0);

			/*
			 * Remember the old hash table along with all
			 * of the previously-remembered hash tables.
			 * We will free them at process exit or exec.
			 */
			ret_tidhash->rth_tidhash = old_hash;
			ret_tidhash->rth_tidhash_sz = old_hashsz;
			ret_tidhash->rth_next = p->p_ret_tidhash;
			p->p_ret_tidhash = ret_tidhash;

			/*
			 * Now establish the new tid hash table.
			 * As soon as we assign p->p_tidhash,
			 * code in lwp_unpark() can start using it.
			 */
			membar_producer();
			p->p_tidhash = new_hash;

			/*
			 * It is necessary that p_tidhash reach global
			 * visibility before p_tidhash_sz.  Otherwise,
			 * code in lwp_hash_lookup_and_lock() could
			 * index into the old p_tidhash using the new
			 * p_tidhash_sz and thereby access invalid data.
			 */
			membar_producer();
			p->p_tidhash_sz = new_hashsz;

			/*
			 * Release the locks; allow lwp_unpark() to carry on.
			 */
			for (i = 0; i < old_hashsz; i++) {
				mutex_exit(&old_hash[i].th_lock);
				mutex_exit(&new_hash[i].th_lock);
			}

			/*
			 * Avoid freeing these objects below.
			 */
			ret_tidhash = NULL;
			old_hash = NULL;
			old_hashsz = 0;
		}
	}

	/*
	 * Block the process against /proc while we manipulate p->p_tlist,
	 * unless lwp_create() was called by /proc for the PCAGENT operation.
	 * We want to do this early enough so that we don't drop p->p_lock
	 * until the thread is put on the p->p_tlist.
	 */
	if (p == curproc) {
		prbarrier(p);
		/*
		 * If the current lwp has been requested to stop, do so now.
		 * Otherwise we have a race condition between /proc attempting
		 * to stop the process and this thread creating a new lwp
		 * that was not seen when the /proc PCSTOP request was issued.
		 * We rely on stop() to call prbarrier(p) before returning.
		 */
		while ((curthread->t_proc_flag & TP_PRSTOP) &&
		    !ttolwp(curthread)->lwp_nostop) {
			/*
			 * We called pool_barrier_enter() before calling
			 * here to lwp_create(). We have to call
			 * pool_barrier_exit() before stopping.
			 */
			pool_barrier_exit();
			prbarrier(p);
			stop(PR_REQUESTED, 0);
			/*
			 * And we have to repeat the call to
			 * pool_barrier_enter after stopping.
			 */
			pool_barrier_enter();
			prbarrier(p);
		}

		/*
		 * If process is exiting, there could be a race between
		 * the agent lwp creation and the new lwp currently being
		 * created. So to prevent this race lwp creation is failed
		 * if the process is exiting.
		 */
		if (p->p_flag & (SEXITLWPS|SKILLED)) {
			err = 1;
			goto error;
		}

		/*
		 * Since we might have dropped p->p_lock, the
		 * lwp directory free list might have changed.
		 */
		if (p->p_lwpfree == NULL)
			goto grow;
	}

	kpreempt_disable();	/* can't grab cpu_lock here */

	/*
	 * Inherit processor and processor set bindings from curthread.
	 *
	 * For kernel LWPs, we do not inherit processor set bindings at
	 * process creation time (i.e. when p != curproc).  After the
	 * kernel process is created, any subsequent LWPs must be created
	 * by threads in the kernel process, at which point we *will*
	 * inherit processor set bindings.
	 */
	if (CLASS_KERNEL(cid) && p != curproc) {
		t->t_bind_cpu = binding = PBIND_NONE;
		t->t_cpupart = oldpart = &cp_default;
		t->t_bind_pset = PS_NONE;
		t->t_bindflag = (uchar_t)default_binding_mode;
	} else {
		binding = curthread->t_bind_cpu;
		t->t_bind_cpu = binding;
		oldpart = t->t_cpupart;
		t->t_cpupart = curthread->t_cpupart;
		t->t_bind_pset = curthread->t_bind_pset;
		t->t_bindflag = curthread->t_bindflag |
		    (uchar_t)default_binding_mode;
	}

	/*
	 * thread_create() initializes this thread's home lgroup to the root.
	 * Choose a more suitable lgroup, since this thread is associated
	 * with an lwp.
	 */
	ASSERT(oldpart != NULL);
	if (binding != PBIND_NONE && t->t_affinitycnt == 0) {
		t->t_bound_cpu = cpu[binding];
		if (t->t_lpl != t->t_bound_cpu->cpu_lpl)
			lgrp_move_thread(t, t->t_bound_cpu->cpu_lpl, 1);
	} else if (CLASS_KERNEL(cid)) {
		/*
		 * Kernel threads are always in the root lgrp.
		 */
		lgrp_move_thread(t,
		    &t->t_cpupart->cp_lgrploads[LGRP_ROOTID], 1);
	} else {
		lgrp_move_thread(t, lgrp_choose(t, t->t_cpupart), 1);
	}

	kpreempt_enable();

	/*
	 * make sure lpl points to our own partition
	 */
	ASSERT(t->t_lpl >= t->t_cpupart->cp_lgrploads);
	ASSERT(t->t_lpl < t->t_cpupart->cp_lgrploads +
	    t->t_cpupart->cp_nlgrploads);

	/*
	 * It is safe to point the thread to the new project without holding it
	 * since we're holding the target process' p_lock here and therefore
	 * we're guaranteed that it will not move to another project.
	 */
	newkpj = p->p_task->tk_proj;
	oldkpj = ttoproj(t);
	if (newkpj != oldkpj) {
		t->t_proj = newkpj;
		(void) project_hold(newkpj);
		project_rele(oldkpj);
	}

	if (cid != NOCLASS) {
		/*
		 * If the lwp is being created in the current process
		 * and matches the current thread's scheduling class,
		 * we should propagate the current thread's scheduling
		 * parameters by calling CL_FORK.  Otherwise just use
		 * the defaults by calling CL_ENTERCLASS.
		 */
		if (p != curproc || curthread->t_cid != cid) {
			err = CL_ENTERCLASS(t, cid, NULL, NULL, bufp);
			t->t_pri = pri;	/* CL_ENTERCLASS may have changed it */
			/*
			 * We don't call schedctl_set_cidpri(t) here
			 * because the schedctl data is not yet set
			 * up for the newly-created lwp.
			 */
		} else {
			t->t_clfuncs = &(sclass[cid].cl_funcs->thread);
			err = CL_FORK(curthread, t, bufp);
			t->t_cid = cid;
		}
		if (err) {
			atomic_inc_32(&p->p_zone->zone_ffmisc);
			goto error;
		} else {
			bufp = NULL;
		}
	}

	/*
	 * If we were given an lwpid then use it, else allocate one.
	 */
	if (lwpid != 0)
		t->t_tid = lwpid;
	else {
		/*
		 * lwp/thread id 0 is never valid; reserved for special checks.
		 * lwp/thread id 1 is reserved for the main thread.
		 * Start again at 2 when INT_MAX has been reached
		 * (id_t is a signed 32-bit integer).
		 */
		id_t prev_id = p->p_lwpid;	/* last allocated tid */

		do {			/* avoid lwpid duplication */
			if (p->p_lwpid == INT_MAX) {
				p->p_flag |= SLWPWRAP;
				p->p_lwpid = 1;
			}
			if ((t->t_tid = ++p->p_lwpid) == prev_id) {
				/*
				 * All lwpids are allocated; fail the request.
				 */
				err = 1;
				atomic_inc_32(&p->p_zone->zone_ffnoproc);
				goto error;
			}
			/*
			 * We only need to worry about colliding with an id
			 * that's already in use if this process has
			 * cycled through all available lwp ids.
			 */
			if ((p->p_flag & SLWPWRAP) == 0)
				break;
		} while (lwp_hash_lookup(p, t->t_tid) != NULL);
	}

	/*
	 * If this is a branded process, let the brand do any necessary lwp
	 * initialization.
	 */
	if (PROC_IS_BRANDED(p)) {
		if (BROP(p)->b_initlwp(lwp)) {
			err = 1;
			atomic_inc_32(&p->p_zone->zone_ffmisc);
			goto error;
		}
		branded = 1;
	}

	if (t->t_tid == 1) {
		kpreempt_disable();
		ASSERT(t->t_lpl != NULL);
		p->p_t1_lgrpid = t->t_lpl->lpl_lgrpid;
		kpreempt_enable();
		if (p->p_tr_lgrpid != LGRP_NONE &&
		    p->p_tr_lgrpid != p->p_t1_lgrpid) {
			lgrp_update_trthr_migrations(1);
		}
	}

	p->p_lwpcnt++;
	t->t_waitfor = -1;

	/*
	 * Turn microstate accounting on for thread if on for process.
	 */
	if (p->p_flag & SMSACCT)
		t->t_proc_flag |= TP_MSACCT;

	/*
	 * If the process has watchpoints, mark the new thread as such.
	 */
	if (pr_watch_active(p))
		watch_enable(t);

	/*
	 * The lwp is being created in the stopped state.
	 * We set all the necessary flags to indicate that fact here.
	 * We omit the TS_CREATE flag from t_schedflag so that the lwp
	 * cannot be set running until the caller is finished with it,
	 * even if lwp_continue() is called on it after we drop p->p_lock.
	 * When the caller is finished with the newly-created lwp,
	 * the caller must call lwp_create_done() to allow the lwp
	 * to be set running.  If the TP_HOLDLWP is left set, the
	 * lwp will suspend itself after reaching system call exit.
	 */
	init_mstate(t, LMS_STOPPED);
	t->t_proc_flag |= TP_HOLDLWP;
	t->t_schedflag |= (TS_ALLSTART & ~(TS_CSTART | TS_CREATE));
	t->t_whystop = PR_SUSPENDED;
	t->t_whatstop = SUSPEND_NORMAL;
	t->t_sig_check = 1;	/* ensure that TP_HOLDLWP is honored */

	/*
	 * Set system call processing flags in case tracing or profiling
	 * is set.  The first system call will evaluate these and turn
	 * them off if they aren't needed.
	 */
	t->t_pre_sys = 1;
	t->t_post_sys = 1;

	/*
	 * Insert the new thread into the list of all threads.
	 */
	if ((tx = p->p_tlist) == NULL) {
		t->t_back = t;
		t->t_forw = t;
		p->p_tlist = t;
	} else {
		t->t_forw = tx;
		t->t_back = tx->t_back;
		tx->t_back->t_forw = t;
		tx->t_back = t;
	}

	/*
	 * Insert the new lwp into an lwp directory slot position
	 * and into the lwpid hash table.
	 */
	lep->le_thread = t;
	lep->le_lwpid = t->t_tid;
	lep->le_start = t->t_start;
	lwp_hash_in(p, lep, p->p_tidhash, p->p_tidhash_sz, 1);

	if (state == TS_RUN) {
		/*
		 * We set the new lwp running immediately.
		 */
		t->t_proc_flag &= ~TP_HOLDLWP;
		lwp_create_done(t);
	}

error:
	if (err) {
		if (CLASS_KERNEL(cid)) {
			/*
			 * This should only happen if a system process runs
			 * out of lwpids, which shouldn't occur.
			 */
			panic("Failed to create a system LWP");
		}
		/*
		 * We have failed to create an lwp, so decrement the number
		 * of lwps in the task and let the lgroup load averages know
		 * that this thread isn't going to show up.
		 */
		kpreempt_disable();
		lgrp_move_thread(t, NULL, 1);
		kpreempt_enable();

		ASSERT(MUTEX_HELD(&p->p_lock));
		mutex_enter(&p->p_zone->zone_nlwps_lock);
		p->p_task->tk_nlwps--;
		p->p_task->tk_proj->kpj_nlwps--;
		p->p_zone->zone_nlwps--;
		mutex_exit(&p->p_zone->zone_nlwps_lock);
		if (cid != NOCLASS && bufp != NULL)
			CL_FREE(cid, bufp);

		if (branded)
			BROP(p)->b_freelwp(lwp);

		mutex_exit(&p->p_lock);
		t->t_state = TS_FREE;
		thread_rele(t);

		/*
		 * We need to remove t from the list of all threads
		 * because thread_exit()/lwp_exit() isn't called on t.
		 */
		mutex_enter(&pidlock);
		ASSERT(t != t->t_next);		/* t0 never exits */
		t->t_next->t_prev = t->t_prev;
		t->t_prev->t_next = t->t_next;
		mutex_exit(&pidlock);

		thread_free(t);
		kmem_free(lep, sizeof (*lep));
		lwp = NULL;
	} else {
		mutex_exit(&p->p_lock);
	}

	if (old_dir != NULL)
		kmem_free(old_dir, old_dirsz * sizeof (*old_dir));
	if (old_hash != NULL)
		kmem_free(old_hash, old_hashsz * sizeof (*old_hash));
	if (ret_tidhash != NULL)
		kmem_free(ret_tidhash, sizeof (ret_tidhash_t));

	DTRACE_PROC1(lwp__create, kthread_t *, t);
	return (lwp);
}

/*
 * lwp_create_done() is called by the caller of lwp_create() to set the
 * newly-created lwp running after the caller has finished manipulating it.
 */
void
lwp_create_done(kthread_t *t)
{
	proc_t *p = ttoproc(t);

	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * We set the TS_CREATE and TS_CSTART flags and call setrun_locked().
	 * (The absence of the TS_CREATE flag prevents the lwp from running
	 * until we are finished with it, even if lwp_continue() is called on
	 * it by some other lwp in the process or elsewhere in the kernel.)
	 */
	thread_lock(t);
	ASSERT(t->t_state == TS_STOPPED && !(t->t_schedflag & TS_CREATE));
	/*
	 * If TS_CSTART is set, lwp_continue(t) has been called and
	 * has already incremented p_lwprcnt; avoid doing this twice.
	 */
	if (!(t->t_schedflag & TS_CSTART))
		p->p_lwprcnt++;
	t->t_schedflag |= (TS_CSTART | TS_CREATE);
	setrun_locked(t);
	thread_unlock(t);
}

/*
 * Copy an LWP's active templates, and clear the latest contracts.
 */
void
lwp_ctmpl_copy(klwp_t *dst, klwp_t *src)
{
	int i;

	for (i = 0; i < ct_ntypes; i++) {
		dst->lwp_ct_active[i] = ctmpl_dup(src->lwp_ct_active[i]);
		dst->lwp_ct_latest[i] = NULL;
	}
}

/*
 * Clear an LWP's contract template state.
 */
void
lwp_ctmpl_clear(klwp_t *lwp)
{
	ct_template_t *tmpl;
	int i;

	for (i = 0; i < ct_ntypes; i++) {
		if ((tmpl = lwp->lwp_ct_active[i]) != NULL) {
			ctmpl_free(tmpl);
			lwp->lwp_ct_active[i] = NULL;
		}

		if (lwp->lwp_ct_latest[i] != NULL) {
			contract_rele(lwp->lwp_ct_latest[i]);
			lwp->lwp_ct_latest[i] = NULL;
		}
	}
}

/*
 * Individual lwp exit.
 * If this is the last lwp, exit the whole process.
 */
void
lwp_exit(void)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);

	ASSERT(MUTEX_HELD(&p->p_lock));

	mutex_exit(&p->p_lock);

#if defined(__sparc)
	/*
	 * Ensure that the user stack is fully abandoned..
	 */
	trash_user_windows();
#endif

	tsd_exit();			/* free thread specific data */

	kcpc_passivate();		/* Clean up performance counter state */

	pollcleanup();

	if (t->t_door)
		door_slam();

	if (t->t_schedctl != NULL)
		schedctl_lwp_cleanup(t);

	if (t->t_upimutex != NULL)
		upimutex_cleanup();

	/*
	 * Perform any brand specific exit processing, then release any
	 * brand data associated with the lwp
	 */
	if (PROC_IS_BRANDED(p))
		BROP(p)->b_lwpexit(lwp);

	lwp_pcb_exit();

	mutex_enter(&p->p_lock);
	lwp_cleanup();

	/*
	 * When this process is dumping core, its lwps are held here
	 * until the core dump is finished. Then exitlwps() is called
	 * again to release these lwps so that they can finish exiting.
	 */
	if (p->p_flag & SCOREDUMP)
		stop(PR_SUSPENDED, SUSPEND_NORMAL);

	/*
	 * Block the process against /proc now that we have really acquired
	 * p->p_lock (to decrement p_lwpcnt and manipulate p_tlist at least).
	 */
	prbarrier(p);

	/*
	 * Call proc_exit() if this is the last non-daemon lwp in the process.
	 */
	if (!(t->t_proc_flag & TP_DAEMON) &&
	    p->p_lwpcnt == p->p_lwpdaemon + 1) {
		mutex_exit(&p->p_lock);
		if (proc_exit(CLD_EXITED, 0) == 0) {
			/* Restarting init. */
			return;
		}

		/*
		 * proc_exit() returns a non-zero value when some other
		 * lwp got there first.  We just have to continue in
		 * lwp_exit().
		 */
		mutex_enter(&p->p_lock);
		ASSERT(curproc->p_flag & SEXITLWPS);
		prbarrier(p);
	}

	DTRACE_PROC(lwp__exit);

	/*
	 * If the lwp is a detached lwp or if the process is exiting,
	 * remove (lwp_hash_out()) the lwp from the lwp directory.
	 * Otherwise null out the lwp's le_thread pointer in the lwp
	 * directory so that other threads will see it as a zombie lwp.
	 */
	prlwpexit(t);		/* notify /proc */
	if (!(t->t_proc_flag & TP_TWAIT) || (p->p_flag & SEXITLWPS))
		lwp_hash_out(p, t->t_tid);
	else {
		ASSERT(!(t->t_proc_flag & TP_DAEMON));
		p->p_lwpdir[t->t_dslot].ld_entry->le_thread = NULL;
		p->p_zombcnt++;
		cv_broadcast(&p->p_lwpexit);
	}
	if (t->t_proc_flag & TP_DAEMON) {
		p->p_lwpdaemon--;
		t->t_proc_flag &= ~TP_DAEMON;
	}
	t->t_proc_flag &= ~TP_TWAIT;

	/*
	 * Maintain accurate lwp count for task.max-lwps resource control.
	 */
	mutex_enter(&p->p_zone->zone_nlwps_lock);
	p->p_task->tk_nlwps--;
	p->p_task->tk_proj->kpj_nlwps--;
	p->p_zone->zone_nlwps--;
	mutex_exit(&p->p_zone->zone_nlwps_lock);

	CL_EXIT(t);		/* tell the scheduler that t is exiting */
	ASSERT(p->p_lwpcnt != 0);
	p->p_lwpcnt--;

	/*
	 * If all remaining non-daemon lwps are waiting in lwp_wait(),
	 * wake them up so someone can return EDEADLK.
	 * (See the block comment preceeding lwp_wait().)
	 */
	if (p->p_lwpcnt == p->p_lwpdaemon + (p->p_lwpwait - p->p_lwpdwait))
		cv_broadcast(&p->p_lwpexit);

	t->t_proc_flag |= TP_LWPEXIT;
	term_mstate(t);

#ifndef NPROBE
	/* Kernel probe */
	if (t->t_tnf_tpdp)
		tnf_thread_exit();
#endif /* NPROBE */

	t->t_forw->t_back = t->t_back;
	t->t_back->t_forw = t->t_forw;
	if (t == p->p_tlist)
		p->p_tlist = t->t_forw;

	/*
	 * Clean up the signal state.
	 */
	if (t->t_sigqueue != NULL)
		sigdelq(p, t, 0);
	if (lwp->lwp_curinfo != NULL) {
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}

	/*
	 * If we have spymaster information (that is, if we're an agent LWP),
	 * free that now.
	 */
	if (lwp->lwp_spymaster != NULL) {
		kmem_free(lwp->lwp_spymaster, sizeof (psinfo_t));
		lwp->lwp_spymaster = NULL;
	}

	thread_rele(t);

	/*
	 * Terminated lwps are associated with process zero and are put onto
	 * death-row by resume().  Avoid preemption after resetting t->t_procp.
	 */
	t->t_preempt++;

	if (t->t_ctx != NULL)
		exitctx(t);
	if (p->p_pctx != NULL)
		exitpctx(p);

	t->t_procp = &p0;

	/*
	 * Notify the HAT about the change of address space
	 */
	hat_thread_exit(t);
	/*
	 * When this is the last running lwp in this process and some lwp is
	 * waiting for this condition to become true, or this thread was being
	 * suspended, then the waiting lwp is awakened.
	 *
	 * Also, if the process is exiting, we may have a thread waiting in
	 * exitlwps() that needs to be notified.
	 */
	if (--p->p_lwprcnt == 0 || (t->t_proc_flag & TP_HOLDLWP) ||
	    (p->p_flag & SEXITLWPS))
		cv_broadcast(&p->p_holdlwps);

	/*
	 * Need to drop p_lock so we can reacquire pidlock.
	 */
	mutex_exit(&p->p_lock);
	mutex_enter(&pidlock);

	ASSERT(t != t->t_next);		/* t0 never exits */
	t->t_next->t_prev = t->t_prev;
	t->t_prev->t_next = t->t_next;
	cv_broadcast(&t->t_joincv);	/* wake up anyone in thread_join */
	mutex_exit(&pidlock);

	t->t_state = TS_ZOMB;
	swtch_from_zombie();
	/* never returns */
}


/*
 * Cleanup function for an exiting lwp.
 * Called both from lwp_exit() and from proc_exit().
 * p->p_lock is repeatedly released and grabbed in this function.
 */
void
lwp_cleanup(void)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);

	ASSERT(MUTEX_HELD(&p->p_lock));

	/* untimeout any lwp-bound realtime timers */
	if (p->p_itimer != NULL)
		timer_lwpexit();

	/*
	 * If this is the /proc agent lwp that is exiting, readjust p_lwpid
	 * so it appears that the agent never existed, and clear p_agenttp.
	 */
	if (t == p->p_agenttp) {
		ASSERT(t->t_tid == p->p_lwpid);
		p->p_lwpid--;
		p->p_agenttp = NULL;
	}

	/*
	 * Do lgroup bookkeeping to account for thread exiting.
	 */
	kpreempt_disable();
	lgrp_move_thread(t, NULL, 1);
	if (t->t_tid == 1) {
		p->p_t1_lgrpid = LGRP_NONE;
	}
	kpreempt_enable();

	lwp_ctmpl_clear(ttolwp(t));
}

int
lwp_suspend(kthread_t *t)
{
	int tid;
	proc_t *p = ttoproc(t);

	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * Set the thread's TP_HOLDLWP flag so it will stop in holdlwp().
	 * If an lwp is stopping itself, there is no need to wait.
	 */
top:
	t->t_proc_flag |= TP_HOLDLWP;
	if (t == curthread) {
		t->t_sig_check = 1;
	} else {
		/*
		 * Make sure the lwp stops promptly.
		 */
		thread_lock(t);
		t->t_sig_check = 1;
		/*
		 * XXX Should use virtual stop like /proc does instead of
		 * XXX waking the thread to get it to stop.
		 */
		if (ISWAKEABLE(t) || ISWAITING(t)) {
			setrun_locked(t);
		} else if (t->t_state == TS_ONPROC && t->t_cpu != CPU) {
			poke_cpu(t->t_cpu->cpu_id);
		}

		tid = t->t_tid;	 /* remember thread ID */
		/*
		 * Wait for lwp to stop
		 */
		while (!SUSPENDED(t)) {
			/*
			 * Drop the thread lock before waiting and reacquire it
			 * afterwards, so the thread can change its t_state
			 * field.
			 */
			thread_unlock(t);

			/*
			 * Check if aborted by exitlwps().
			 */
			if (p->p_flag & SEXITLWPS)
				lwp_exit();

			/*
			 * Cooperate with jobcontrol signals and /proc stopping
			 * by calling cv_wait_sig() to wait for the target
			 * lwp to stop.  Just using cv_wait() can lead to
			 * deadlock because, if some other lwp has stopped
			 * by either of these mechanisms, then p_lwprcnt will
			 * never become zero if we do a cv_wait().
			 */
			if (!cv_wait_sig(&p->p_holdlwps, &p->p_lock))
				return (EINTR);

			/*
			 * Check to see if thread died while we were
			 * waiting for it to suspend.
			 */
			if (idtot(p, tid) == NULL)
				return (ESRCH);

			thread_lock(t);
			/*
			 * If the TP_HOLDLWP flag went away, lwp_continue()
			 * or vfork() must have been called while we were
			 * waiting, so start over again.
			 */
			if ((t->t_proc_flag & TP_HOLDLWP) == 0) {
				thread_unlock(t);
				goto top;
			}
		}
		thread_unlock(t);
	}
	return (0);
}

/*
 * continue a lwp that's been stopped by lwp_suspend().
 */
void
lwp_continue(kthread_t *t)
{
	proc_t *p = ttoproc(t);
	int was_suspended = t->t_proc_flag & TP_HOLDLWP;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t->t_proc_flag &= ~TP_HOLDLWP;
	thread_lock(t);
	if (SUSPENDED(t) &&
	    !(p->p_flag & (SHOLDFORK | SHOLDFORK1 | SHOLDWATCH))) {
		p->p_lwprcnt++;
		t->t_schedflag |= TS_CSTART;
		setrun_locked(t);
	}
	thread_unlock(t);
	/*
	 * Wakeup anyone waiting for this thread to be suspended
	 */
	if (was_suspended)
		cv_broadcast(&p->p_holdlwps);
}

/*
 * ********************************
 *  Miscellaneous lwp routines	  *
 * ********************************
 */
/*
 * When a process is undergoing a forkall(), its p_flag is set to SHOLDFORK.
 * This will cause the process's lwps to stop at a hold point.  A hold
 * point is where a kernel thread has a flat stack.  This is at the
 * return from a system call and at the return from a user level trap.
 *
 * When a process is undergoing a fork1() or vfork(), its p_flag is set to
 * SHOLDFORK1.  This will cause the process's lwps to stop at a modified
 * hold point.  The lwps in the process are not being cloned, so they
 * are held at the usual hold points and also within issig_forreal().
 * This has the side-effect that their system calls do not return
 * showing EINTR.
 *
 * An lwp can also be held.  This is identified by the TP_HOLDLWP flag on
 * the thread.  The TP_HOLDLWP flag is set in lwp_suspend(), where the active
 * lwp is waiting for the target lwp to be stopped.
 */
void
holdlwp(void)
{
	proc_t *p = curproc;
	kthread_t *t = curthread;

	mutex_enter(&p->p_lock);
	/*
	 * Don't terminate immediately if the process is dumping core.
	 * Once the process has dumped core, all lwps are terminated.
	 */
	if (!(p->p_flag & SCOREDUMP)) {
		if ((p->p_flag & SEXITLWPS) || (t->t_proc_flag & TP_EXITLWP))
			lwp_exit();
	}
	if (!(ISHOLD(p)) && !(p->p_flag & (SHOLDFORK1 | SHOLDWATCH))) {
		mutex_exit(&p->p_lock);
		return;
	}
	/*
	 * stop() decrements p->p_lwprcnt and cv_signal()s &p->p_holdlwps
	 * when p->p_lwprcnt becomes zero.
	 */
	stop(PR_SUSPENDED, SUSPEND_NORMAL);
	if (p->p_flag & SEXITLWPS)
		lwp_exit();
	mutex_exit(&p->p_lock);
}

/*
 * Have all lwps within the process hold at a point where they are
 * cloneable (SHOLDFORK) or just safe w.r.t. fork1 (SHOLDFORK1).
 */
int
holdlwps(int holdflag)
{
	proc_t *p = curproc;

	ASSERT(holdflag == SHOLDFORK || holdflag == SHOLDFORK1);
	mutex_enter(&p->p_lock);
	schedctl_finish_sigblock(curthread);
again:
	while (p->p_flag & (SEXITLWPS | SHOLDFORK | SHOLDFORK1 | SHOLDWATCH)) {
		/*
		 * If another lwp is doing a forkall() or proc_exit(), bail out.
		 */
		if (p->p_flag & (SEXITLWPS | SHOLDFORK)) {
			mutex_exit(&p->p_lock);
			return (0);
		}
		/*
		 * Another lwp is doing a fork1() or is undergoing
		 * watchpoint activity.  We hold here for it to complete.
		 */
		stop(PR_SUSPENDED, SUSPEND_NORMAL);
	}
	p->p_flag |= holdflag;
	pokelwps(p);
	--p->p_lwprcnt;
	/*
	 * Wait for the process to become quiescent (p->p_lwprcnt == 0).
	 */
	while (p->p_lwprcnt > 0) {
		/*
		 * Check if aborted by exitlwps().
		 * Also check if SHOLDWATCH is set; it takes precedence.
		 */
		if (p->p_flag & (SEXITLWPS | SHOLDWATCH)) {
			p->p_lwprcnt++;
			p->p_flag &= ~holdflag;
			cv_broadcast(&p->p_holdlwps);
			goto again;
		}
		/*
		 * Cooperate with jobcontrol signals and /proc stopping.
		 * If some other lwp has stopped by either of these
		 * mechanisms, then p_lwprcnt will never become zero
		 * and the process will appear deadlocked unless we
		 * stop here in sympathy with the other lwp before
		 * doing the cv_wait() below.
		 *
		 * If the other lwp stops after we do the cv_wait(), it
		 * will wake us up to loop around and do the sympathy stop.
		 *
		 * Since stop() drops p->p_lock, we must start from
		 * the top again on returning from stop().
		 */
		if (p->p_stopsig | (curthread->t_proc_flag & TP_PRSTOP)) {
			int whystop = p->p_stopsig? PR_JOBCONTROL :
			    PR_REQUESTED;
			p->p_lwprcnt++;
			p->p_flag &= ~holdflag;
			stop(whystop, p->p_stopsig);
			goto again;
		}
		cv_wait(&p->p_holdlwps, &p->p_lock);
	}
	p->p_lwprcnt++;
	p->p_flag &= ~holdflag;
	mutex_exit(&p->p_lock);
	return (1);
}

/*
 * See comments for holdwatch(), below.
 */
static int
holdcheck(int clearflags)
{
	proc_t *p = curproc;

	/*
	 * If we are trying to exit, that takes precedence over anything else.
	 */
	if (p->p_flag & SEXITLWPS) {
		p->p_lwprcnt++;
		p->p_flag &= ~clearflags;
		lwp_exit();
	}

	/*
	 * If another thread is calling fork1(), stop the current thread so the
	 * other can complete.
	 */
	if (p->p_flag & SHOLDFORK1) {
		p->p_lwprcnt++;
		stop(PR_SUSPENDED, SUSPEND_NORMAL);
		if (p->p_flag & SEXITLWPS) {
			p->p_flag &= ~clearflags;
			lwp_exit();
		}
		return (-1);
	}

	/*
	 * If another thread is calling fork(), then indicate we are doing
	 * watchpoint activity.  This will cause holdlwps() above to stop the
	 * forking thread, at which point we can continue with watchpoint
	 * activity.
	 */
	if (p->p_flag & SHOLDFORK) {
		p->p_lwprcnt++;
		while (p->p_flag & SHOLDFORK) {
			p->p_flag |= SHOLDWATCH;
			cv_broadcast(&p->p_holdlwps);
			cv_wait(&p->p_holdlwps, &p->p_lock);
			p->p_flag &= ~SHOLDWATCH;
		}
		return (-1);
	}

	return (0);
}

/*
 * Stop all lwps within the process, holding themselves in the kernel while the
 * active lwp undergoes watchpoint activity.  This is more complicated than
 * expected because stop() relies on calling holdwatch() in order to copyin data
 * from the user's address space.  A double barrier is used to prevent an
 * infinite loop.
 *
 * 	o The first thread into holdwatch() is the 'master' thread and does
 *        the following:
 *
 *              - Sets SHOLDWATCH on the current process
 *              - Sets TP_WATCHSTOP on the current thread
 *              - Waits for all threads to be either stopped or have
 *                TP_WATCHSTOP set.
 *              - Sets the SWATCHOK flag on the process
 *              - Unsets TP_WATCHSTOP
 *              - Waits for the other threads to completely stop
 *              - Unsets SWATCHOK
 *
 * 	o If SHOLDWATCH is already set when we enter this function, then another
 *        thread is already trying to stop this thread.  This 'slave' thread
 *        does the following:
 *
 *              - Sets TP_WATCHSTOP on the current thread
 *              - Waits for SWATCHOK flag to be set
 *              - Calls stop()
 *
 * 	o If SWATCHOK is set on the process, then this function immediately
 *        returns, as we must have been called via stop().
 *
 * In addition, there are other flags that take precedence over SHOLDWATCH:
 *
 * 	o If SEXITLWPS is set, exit immediately.
 *
 * 	o If SHOLDFORK1 is set, wait for fork1() to complete.
 *
 * 	o If SHOLDFORK is set, then watchpoint activity takes precedence In this
 *        case, set SHOLDWATCH, signalling the forking thread to stop first.
 *
 * 	o If the process is being stopped via /proc (TP_PRSTOP is set), then we
 *        stop the current thread.
 *
 * Returns 0 if all threads have been quiesced.  Returns non-zero if not all
 * threads were stopped, or the list of watched pages has changed.
 */
int
holdwatch(void)
{
	proc_t *p = curproc;
	kthread_t *t = curthread;
	int ret = 0;

	mutex_enter(&p->p_lock);

	p->p_lwprcnt--;

	/*
	 * Check for bail-out conditions as outlined above.
	 */
	if (holdcheck(0) != 0) {
		mutex_exit(&p->p_lock);
		return (-1);
	}

	if (!(p->p_flag & SHOLDWATCH)) {
		/*
		 * We are the master watchpoint thread.  Set SHOLDWATCH and poke
		 * the other threads.
		 */
		p->p_flag |= SHOLDWATCH;
		pokelwps(p);

		/*
		 * Wait for all threads to be stopped or have TP_WATCHSTOP set.
		 */
		while (pr_allstopped(p, 1) > 0) {
			if (holdcheck(SHOLDWATCH) != 0) {
				p->p_flag &= ~SHOLDWATCH;
				mutex_exit(&p->p_lock);
				return (-1);
			}

			cv_wait(&p->p_holdlwps, &p->p_lock);
		}

		/*
		 * All threads are now stopped or in the process of stopping.
		 * Set SWATCHOK and let them stop completely.
		 */
		p->p_flag |= SWATCHOK;
		t->t_proc_flag &= ~TP_WATCHSTOP;
		cv_broadcast(&p->p_holdlwps);

		while (pr_allstopped(p, 0) > 0) {
			/*
			 * At first glance, it may appear that we don't need a
			 * call to holdcheck() here.  But if the process gets a
			 * SIGKILL signal, one of our stopped threads may have
			 * been awakened and is waiting in exitlwps(), which
			 * takes precedence over watchpoints.
			 */
			if (holdcheck(SHOLDWATCH | SWATCHOK) != 0) {
				p->p_flag &= ~(SHOLDWATCH | SWATCHOK);
				mutex_exit(&p->p_lock);
				return (-1);
			}

			cv_wait(&p->p_holdlwps, &p->p_lock);
		}

		/*
		 * All threads are now completely stopped.
		 */
		p->p_flag &= ~SWATCHOK;
		p->p_flag &= ~SHOLDWATCH;
		p->p_lwprcnt++;

	} else if (!(p->p_flag & SWATCHOK)) {

		/*
		 * SHOLDWATCH is set, so another thread is trying to do
		 * watchpoint activity.  Indicate this thread is stopping, and
		 * wait for the OK from the master thread.
		 */
		t->t_proc_flag |= TP_WATCHSTOP;
		cv_broadcast(&p->p_holdlwps);

		while (!(p->p_flag & SWATCHOK)) {
			if (holdcheck(0) != 0) {
				t->t_proc_flag &= ~TP_WATCHSTOP;
				mutex_exit(&p->p_lock);
				return (-1);
			}

			cv_wait(&p->p_holdlwps, &p->p_lock);
		}

		/*
		 * Once the master thread has given the OK, this thread can
		 * actually call stop().
		 */
		t->t_proc_flag &= ~TP_WATCHSTOP;
		p->p_lwprcnt++;

		stop(PR_SUSPENDED, SUSPEND_NORMAL);

		/*
		 * It's not OK to do watchpoint activity, notify caller to
		 * retry.
		 */
		ret = -1;

	} else {

		/*
		 * The only way we can hit the case where SHOLDWATCH is set and
		 * SWATCHOK is set is if we are triggering this from within a
		 * stop() call.  Assert that this is the case.
		 */

		ASSERT(t->t_proc_flag & TP_STOPPING);
		p->p_lwprcnt++;
	}

	mutex_exit(&p->p_lock);

	return (ret);
}

/*
 * force all interruptible lwps to trap into the kernel.
 */
void
pokelwps(proc_t *p)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t = p->p_tlist;
	do {
		if (t == curthread)
			continue;
		thread_lock(t);
		aston(t);	/* make thread trap or do post_syscall */
		if (ISWAKEABLE(t) || ISWAITING(t)) {
			setrun_locked(t);
		} else if (t->t_state == TS_STOPPED) {
			/*
			 * Ensure that proc_exit() is not blocked by lwps
			 * that were stopped via jobcontrol or /proc.
			 */
			if (p->p_flag & SEXITLWPS) {
				p->p_stopsig = 0;
				t->t_schedflag |= (TS_XSTART | TS_PSTART);
				setrun_locked(t);
			}
			/*
			 * If we are holding lwps for a forkall(),
			 * force lwps that have been suspended via
			 * lwp_suspend() and are suspended inside
			 * of a system call to proceed to their
			 * holdlwp() points where they are clonable.
			 */
			if ((p->p_flag & SHOLDFORK) && SUSPENDED(t)) {
				if ((t->t_schedflag & TS_CSTART) == 0) {
					p->p_lwprcnt++;
					t->t_schedflag |= TS_CSTART;
					setrun_locked(t);
				}
			}
		} else if (t->t_state == TS_ONPROC) {
			if (t->t_cpu != CPU)
				poke_cpu(t->t_cpu->cpu_id);
		}
		thread_unlock(t);
	} while ((t = t->t_forw) != p->p_tlist);
}

/*
 * undo the effects of holdlwps() or holdwatch().
 */
void
continuelwps(proc_t *p)
{
	kthread_t *t;

	/*
	 * If this flag is set, then the original holdwatch() didn't actually
	 * stop the process.  See comments for holdwatch().
	 */
	if (p->p_flag & SWATCHOK) {
		ASSERT(curthread->t_proc_flag & TP_STOPPING);
		return;
	}

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT((p->p_flag & (SHOLDFORK | SHOLDFORK1 | SHOLDWATCH)) == 0);

	t = p->p_tlist;
	do {
		thread_lock(t);		/* SUSPENDED looks at t_schedflag */
		if (SUSPENDED(t) && !(t->t_proc_flag & TP_HOLDLWP)) {
			p->p_lwprcnt++;
			t->t_schedflag |= TS_CSTART;
			setrun_locked(t);
		}
		thread_unlock(t);
	} while ((t = t->t_forw) != p->p_tlist);
}

/*
 * Force all other LWPs in the current process other than the caller to exit,
 * and then cv_wait() on p_holdlwps for them to exit.  The exitlwps() function
 * is typically used in these situations:
 *
 *   (a) prior to an exec() system call
 *   (b) prior to dumping a core file
 *   (c) prior to a uadmin() shutdown
 *
 * If the 'coredump' flag is set, other LWPs are quiesced but not destroyed.
 * Multiple threads in the process can call this function at one time by
 * triggering execs or core dumps simultaneously, so the SEXITLWPS bit is used
 * to declare one particular thread the winner who gets to kill the others.
 * If a thread wins the exitlwps() dance, zero is returned; otherwise an
 * appropriate errno value is returned to caller for its system call to return.
 */
int
exitlwps(int coredump)
{
	proc_t *p = curproc;
	int heldcnt;

	if (curthread->t_door)
		door_slam();
	if (p->p_door_list)
		door_revoke_all();
	if (curthread->t_schedctl != NULL)
		schedctl_lwp_cleanup(curthread);

	/*
	 * Ensure that before starting to wait for other lwps to exit,
	 * cleanup all upimutexes held by curthread. Otherwise, some other
	 * lwp could be waiting (uninterruptibly) for a upimutex held by
	 * curthread, and the call to pokelwps() below would deadlock.
	 * Even if a blocked upimutex_lock is made interruptible,
	 * curthread's upimutexes need to be unlocked: do it here.
	 */
	if (curthread->t_upimutex != NULL)
		upimutex_cleanup();

	/*
	 * Grab p_lock in order to check and set SEXITLWPS to declare a winner.
	 * We must also block any further /proc access from this point forward.
	 */
	mutex_enter(&p->p_lock);
	prbarrier(p);

	if (p->p_flag & SEXITLWPS) {
		mutex_exit(&p->p_lock);
		aston(curthread);	/* force a trip through post_syscall */
		return (set_errno(EINTR));
	}

	p->p_flag |= SEXITLWPS;
	if (coredump)		/* tell other lwps to stop, not exit */
		p->p_flag |= SCOREDUMP;

	/*
	 * Give precedence to exitlwps() if a holdlwps() is
	 * in progress. The lwp doing the holdlwps() operation
	 * is aborted when it is awakened.
	 */
	while (p->p_flag & (SHOLDFORK | SHOLDFORK1 | SHOLDWATCH)) {
		cv_broadcast(&p->p_holdlwps);
		cv_wait(&p->p_holdlwps, &p->p_lock);
		prbarrier(p);
	}
	p->p_flag |= SHOLDFORK;
	pokelwps(p);

	/*
	 * Wait for process to become quiescent.
	 */
	--p->p_lwprcnt;
	while (p->p_lwprcnt > 0) {
		cv_wait(&p->p_holdlwps, &p->p_lock);
		prbarrier(p);
	}
	p->p_lwprcnt++;
	ASSERT(p->p_lwprcnt == 1);

	/*
	 * The SCOREDUMP flag puts the process into a quiescent
	 * state.  The process's lwps remain attached to this
	 * process until exitlwps() is called again without the
	 * 'coredump' flag set, then the lwps are terminated
	 * and the process can exit.
	 */
	if (coredump) {
		p->p_flag &= ~(SCOREDUMP | SHOLDFORK | SEXITLWPS);
		goto out;
	}

	/*
	 * Determine if there are any lwps left dangling in
	 * the stopped state.  This happens when exitlwps()
	 * aborts a holdlwps() operation.
	 */
	p->p_flag &= ~SHOLDFORK;
	if ((heldcnt = p->p_lwpcnt) > 1) {
		kthread_t *t;
		for (t = curthread->t_forw; --heldcnt > 0; t = t->t_forw) {
			t->t_proc_flag &= ~TP_TWAIT;
			lwp_continue(t);
		}
	}

	/*
	 * Wait for all other lwps to exit.
	 */
	--p->p_lwprcnt;
	while (p->p_lwpcnt > 1) {
		cv_wait(&p->p_holdlwps, &p->p_lock);
		prbarrier(p);
	}
	++p->p_lwprcnt;
	ASSERT(p->p_lwpcnt == 1 && p->p_lwprcnt == 1);

	p->p_flag &= ~SEXITLWPS;
	curthread->t_proc_flag &= ~TP_TWAIT;

out:
	if (!coredump && p->p_zombcnt) {	/* cleanup the zombie lwps */
		lwpdir_t *ldp;
		lwpent_t *lep;
		int i;

		for (ldp = p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++, ldp++) {
			lep = ldp->ld_entry;
			if (lep != NULL && lep->le_thread != curthread) {
				ASSERT(lep->le_thread == NULL);
				p->p_zombcnt--;
				lwp_hash_out(p, lep->le_lwpid);
			}
		}
		ASSERT(p->p_zombcnt == 0);
	}

	/*
	 * If some other LWP in the process wanted us to suspend ourself,
	 * then we will not do it.  The other LWP is now terminated and
	 * no one will ever continue us again if we suspend ourself.
	 */
	curthread->t_proc_flag &= ~TP_HOLDLWP;
	p->p_flag &= ~(SHOLDFORK | SHOLDFORK1 | SHOLDWATCH | SLWPWRAP);
	mutex_exit(&p->p_lock);
	return (0);
}

/*
 * duplicate a lwp.
 */
klwp_t *
forklwp(klwp_t *lwp, proc_t *cp, id_t lwpid)
{
	klwp_t *clwp;
	void *tregs, *tfpu;
	kthread_t *t = lwptot(lwp);
	kthread_t *ct;
	proc_t *p = lwptoproc(lwp);
	int cid;
	void *bufp;
	void *brand_data;
	int val;

	ASSERT(p == curproc);
	ASSERT(t == curthread || (SUSPENDED(t) && lwp->lwp_asleep == 0));

#if defined(__sparc)
	if (t == curthread)
		(void) flush_user_windows_to_stack(NULL);
#endif

	if (t == curthread)
		/* copy args out of registers first */
		(void) save_syscall_args();

	clwp = lwp_create(cp->p_lwpcnt == 0 ? lwp_rtt_initial : lwp_rtt,
	    NULL, 0, cp, TS_STOPPED, t->t_pri, &t->t_hold, NOCLASS, lwpid);
	if (clwp == NULL)
		return (NULL);

	/*
	 * most of the parent's lwp can be copied to its duplicate,
	 * except for the fields that are unique to each lwp, like
	 * lwp_thread, lwp_procp, lwp_regs, and lwp_ap.
	 */
	ct = clwp->lwp_thread;
	tregs = clwp->lwp_regs;
	tfpu = clwp->lwp_fpu;
	brand_data = clwp->lwp_brand;

	/*
	 * Copy parent lwp to child lwp.  Hold child's p_lock to prevent
	 * mstate_aggr_state() from reading stale mstate entries copied
	 * from lwp to clwp.
	 */
	mutex_enter(&cp->p_lock);
	*clwp = *lwp;

	/* clear microstate and resource usage data in new lwp */
	init_mstate(ct, LMS_STOPPED);
	bzero(&clwp->lwp_ru, sizeof (clwp->lwp_ru));
	mutex_exit(&cp->p_lock);

	/* fix up child's lwp */

	clwp->lwp_pcb.pcb_flags = 0;
#if defined(__sparc)
	clwp->lwp_pcb.pcb_step = STEP_NONE;
#endif
	clwp->lwp_cursig = 0;
	clwp->lwp_extsig = 0;
	clwp->lwp_curinfo = (struct sigqueue *)0;
	clwp->lwp_thread = ct;
	ct->t_sysnum = t->t_sysnum;
	clwp->lwp_regs = tregs;
	clwp->lwp_fpu = tfpu;
	clwp->lwp_brand = brand_data;
	clwp->lwp_ap = clwp->lwp_arg;
	clwp->lwp_procp = cp;
	bzero(clwp->lwp_timer, sizeof (clwp->lwp_timer));
	clwp->lwp_lastfault = 0;
	clwp->lwp_lastfaddr = 0;

	/* copy parent's struct regs to child. */
	lwp_forkregs(lwp, clwp);

	/*
	 * Fork thread context ops, if any.
	 */
	if (t->t_ctx)
		forkctx(t, ct);

	/* fix door state in the child */
	if (t->t_door)
		door_fork(t, ct);

	/* copy current contract templates, clear latest contracts */
	lwp_ctmpl_copy(clwp, lwp);

	mutex_enter(&cp->p_lock);
	/* lwp_create() set the TP_HOLDLWP flag */
	if (!(t->t_proc_flag & TP_HOLDLWP))
		ct->t_proc_flag &= ~TP_HOLDLWP;
	if (cp->p_flag & SMSACCT)
		ct->t_proc_flag |= TP_MSACCT;
	mutex_exit(&cp->p_lock);

	/* Allow brand to propagate brand-specific state */
	if (PROC_IS_BRANDED(p))
		BROP(p)->b_forklwp(lwp, clwp);

retry:
	cid = t->t_cid;

	val = CL_ALLOC(&bufp, cid, KM_SLEEP);
	ASSERT(val == 0);

	mutex_enter(&p->p_lock);
	if (cid != t->t_cid) {
		/*
		 * Someone just changed this thread's scheduling class,
		 * so try pre-allocating the buffer again.  Hopefully we
		 * don't hit this often.
		 */
		mutex_exit(&p->p_lock);
		CL_FREE(cid, bufp);
		goto retry;
	}

	ct->t_unpark = t->t_unpark;
	ct->t_clfuncs = t->t_clfuncs;
	CL_FORK(t, ct, bufp);
	ct->t_cid = t->t_cid;	/* after data allocated so prgetpsinfo works */
	mutex_exit(&p->p_lock);

	return (clwp);
}

/*
 * Add a new lwp entry to the lwp directory and to the lwpid hash table.
 */
void
lwp_hash_in(proc_t *p, lwpent_t *lep, tidhash_t *tidhash, uint_t tidhash_sz,
    int do_lock)
{
	tidhash_t *thp = &tidhash[TIDHASH(lep->le_lwpid, tidhash_sz)];
	lwpdir_t **ldpp;
	lwpdir_t *ldp;
	kthread_t *t;

	/*
	 * Allocate a directory element from the free list.
	 * Code elsewhere guarantees a free slot.
	 */
	ldp = p->p_lwpfree;
	p->p_lwpfree = ldp->ld_next;
	ASSERT(ldp->ld_entry == NULL);
	ldp->ld_entry = lep;

	if (do_lock)
		mutex_enter(&thp->th_lock);

	/*
	 * Insert it into the lwpid hash table.
	 */
	ldpp = &thp->th_list;
	ldp->ld_next = *ldpp;
	*ldpp = ldp;

	/*
	 * Set the active thread's directory slot entry.
	 */
	if ((t = lep->le_thread) != NULL) {
		ASSERT(lep->le_lwpid == t->t_tid);
		t->t_dslot = (int)(ldp - p->p_lwpdir);
	}

	if (do_lock)
		mutex_exit(&thp->th_lock);
}

/*
 * Remove an lwp from the lwpid hash table and free its directory entry.
 * This is done when a detached lwp exits in lwp_exit() or
 * when a non-detached lwp is waited for in lwp_wait() or
 * when a zombie lwp is detached in lwp_detach().
 */
void
lwp_hash_out(proc_t *p, id_t lwpid)
{
	tidhash_t *thp = &p->p_tidhash[TIDHASH(lwpid, p->p_tidhash_sz)];
	lwpdir_t **ldpp;
	lwpdir_t *ldp;
	lwpent_t *lep;

	mutex_enter(&thp->th_lock);
	for (ldpp = &thp->th_list;
	    (ldp = *ldpp) != NULL; ldpp = &ldp->ld_next) {
		lep = ldp->ld_entry;
		if (lep->le_lwpid == lwpid) {
			prlwpfree(p, lep);	/* /proc deals with le_trace */
			*ldpp = ldp->ld_next;
			ldp->ld_entry = NULL;
			ldp->ld_next = p->p_lwpfree;
			p->p_lwpfree = ldp;
			kmem_free(lep, sizeof (*lep));
			break;
		}
	}
	mutex_exit(&thp->th_lock);
}

/*
 * Lookup an lwp in the lwpid hash table by lwpid.
 */
lwpdir_t *
lwp_hash_lookup(proc_t *p, id_t lwpid)
{
	tidhash_t *thp;
	lwpdir_t *ldp;

	/*
	 * The process may be exiting, after p_tidhash has been set to NULL in
	 * proc_exit() but before prfee() has been called.  Return failure in
	 * this case.
	 */
	if (p->p_tidhash == NULL)
		return (NULL);

	thp = &p->p_tidhash[TIDHASH(lwpid, p->p_tidhash_sz)];
	for (ldp = thp->th_list; ldp != NULL; ldp = ldp->ld_next) {
		if (ldp->ld_entry->le_lwpid == lwpid)
			return (ldp);
	}

	return (NULL);
}

/*
 * Same as lwp_hash_lookup(), but acquire and return
 * the tid hash table entry lock on success.
 */
lwpdir_t *
lwp_hash_lookup_and_lock(proc_t *p, id_t lwpid, kmutex_t **mpp)
{
	tidhash_t *tidhash;
	uint_t tidhash_sz;
	tidhash_t *thp;
	lwpdir_t *ldp;

top:
	tidhash_sz = p->p_tidhash_sz;
	membar_consumer();
	if ((tidhash = p->p_tidhash) == NULL)
		return (NULL);

	thp = &tidhash[TIDHASH(lwpid, tidhash_sz)];
	mutex_enter(&thp->th_lock);

	/*
	 * Since we are not holding p->p_lock, the tid hash table
	 * may have changed.  If so, start over.  If not, then
	 * it cannot change until after we drop &thp->th_lock;
	 */
	if (tidhash != p->p_tidhash || tidhash_sz != p->p_tidhash_sz) {
		mutex_exit(&thp->th_lock);
		goto top;
	}

	for (ldp = thp->th_list; ldp != NULL; ldp = ldp->ld_next) {
		if (ldp->ld_entry->le_lwpid == lwpid) {
			*mpp = &thp->th_lock;
			return (ldp);
		}
	}

	mutex_exit(&thp->th_lock);
	return (NULL);
}

/*
 * Update the indicated LWP usage statistic for the current LWP.
 */
void
lwp_stat_update(lwp_stat_id_t lwp_stat_id, long inc)
{
	klwp_t *lwp = ttolwp(curthread);

	if (lwp == NULL)
		return;

	switch (lwp_stat_id) {
	case LWP_STAT_INBLK:
		lwp->lwp_ru.inblock += inc;
		break;
	case LWP_STAT_OUBLK:
		lwp->lwp_ru.oublock += inc;
		break;
	case LWP_STAT_MSGRCV:
		lwp->lwp_ru.msgrcv += inc;
		break;
	case LWP_STAT_MSGSND:
		lwp->lwp_ru.msgsnd += inc;
		break;
	default:
		panic("lwp_stat_update: invalid lwp_stat_id 0x%x", lwp_stat_id);
	}
}
