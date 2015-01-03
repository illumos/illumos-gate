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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/var.h>
#include <sys/tuneable.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/disp.h>
#include <sys/vmsystm.h>
#include <sys/vmparam.h>
#include <sys/class.h>
#include <sys/vtrace.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/tnf_probe.h>
#include <sys/procfs.h>

#include <vm/seg.h>
#include <vm/seg_kp.h>
#include <vm/as.h>
#include <vm/rm.h>
#include <vm/seg_kmem.h>
#include <sys/callb.h>

/*
 * The swapper sleeps on runout when there is no one to swap in.
 * It sleeps on runin when it could not find space to swap someone
 * in or after swapping someone in.
 */
char	runout;
char	runin;
char	wake_sched;	/* flag tells clock to wake swapper on next tick */
char	wake_sched_sec;	/* flag tells clock to wake swapper after a second */

/*
 * The swapper swaps processes to reduce memory demand and runs
 * when avefree < desfree.  The swapper resorts to SOFTSWAP when
 * avefree < desfree which results in swapping out all processes
 * sleeping for more than maxslp seconds.  HARDSWAP occurs when the
 * system is on the verge of thrashing and this results in swapping
 * out runnable threads or threads sleeping for less than maxslp secs.
 *
 * The swapper runs through all the active processes in the system
 * and invokes the scheduling class specific swapin/swapout routine
 * for every thread in the process to obtain an effective priority
 * for the process.  A priority of -1 implies that the thread isn't
 * swappable.  This effective priority is used to find the most
 * eligible process to swapout or swapin.
 *
 * NOTE:  Threads which have been swapped are not linked on any
 *	  queue and their dispatcher lock points at the "swapped_lock".
 *
 * Processes containing threads with the TS_DONT_SWAP flag set cannot be
 * swapped out immediately by the swapper.  This is due to the fact that
 * such threads may be holding locks which may be needed by the swapper
 * to push its pages out.  The TS_SWAPENQ flag is set on such threads
 * to prevent them running in user mode.  When such threads reach a
 * safe point (i.e., are not holding any locks - CL_TRAPRET), they
 * queue themseleves onto the swap queue which is processed by the
 * swapper.  This results in reducing memory demand when the system
 * is desparate for memory as the thread can't run in user mode.
 *
 * The swap queue consists of threads, linked via t_link, which are
 * haven't been swapped, are runnable but not on the run queue.  The
 * swap queue is protected by the "swapped_lock".  The dispatcher
 * lock (t_lockp) of all threads on the swap queue points at the
 * "swapped_lock".  Thus, the entire queue and/or threads on the
 * queue can be locked by acquiring "swapped_lock".
 */
static kthread_t *tswap_queue;
extern disp_lock_t swapped_lock; /* protects swap queue and threads on it */

int	maxslp = 0;
pgcnt_t	avefree;	/* 5 sec moving average of free memory */
pgcnt_t	avefree30;	/* 30 sec moving average of free memory */

/*
 * Minimum size used to decide if sufficient memory is available
 * before a process is swapped in.  This is necessary since in most
 * cases the actual size of a process (p_swrss) being swapped in
 * is usually 2 pages (kernel stack pages).  This is due to the fact
 * almost all user pages of a process are stolen by pageout before
 * the swapper decides to swapout it out.
 */
int	min_procsize = 12;

static int	swapin(proc_t *);
static int	swapout(proc_t *, uint_t *, int);
static void	process_swap_queue();

#ifdef __sparc
extern void lwp_swapin(kthread_t *);
#endif /* __sparc */

/*
 * Counters to keep track of the number of swapins or swapouts.
 */
uint_t tot_swapped_in, tot_swapped_out;
uint_t softswap, hardswap, swapqswap;

/*
 * Macro to determine if a process is eligble to be swapped.
 */
#define	not_swappable(p)					\
	(((p)->p_flag & SSYS) || (p)->p_stat == SIDL ||		\
	    (p)->p_stat == SZOMB || (p)->p_as == NULL ||	\
	    (p)->p_as == &kas)

/*
 * Memory scheduler.
 */
void
sched()
{
	kthread_id_t	t;
	pri_t		proc_pri;
	pri_t		thread_pri;
	pri_t		swapin_pri;
	int		desperate;
	pgcnt_t		needs;
	int		divisor;
	proc_t		*prp;
	proc_t		*swapout_prp;
	proc_t		*swapin_prp;
	spgcnt_t	avail;
	int		chosen_pri;
	time_t		swapout_time;
	time_t		swapin_proc_time;
	callb_cpr_t	cprinfo;
	kmutex_t	swap_cpr_lock;

	mutex_init(&swap_cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cprinfo, &swap_cpr_lock, callb_generic_cpr, "sched");
	if (maxslp == 0)
		maxslp = MAXSLP;
loop:
	needs = 0;
	desperate = 0;

	swapin_pri = v.v_nglobpris;
	swapin_prp = NULL;
	chosen_pri = -1;

	process_swap_queue();

	/*
	 * Set desperate if
	 * 	1.  At least 2 runnable processes (on average).
	 *	2.  Short (5 sec) and longer (30 sec) average is less
	 *	    than minfree and desfree respectively.
	 *	3.  Pagein + pageout rate is excessive.
	 */
	if (avenrun[0] >= 2 * FSCALE &&
	    (MAX(avefree, avefree30) < desfree) &&
	    (pginrate + pgoutrate > maxpgio || avefree < minfree)) {
		TRACE_4(TR_FAC_SCHED, TR_DESPERATE,
		    "desp:avefree: %d, avefree30: %d, freemem: %d"
		    " pginrate: %d\n", avefree, avefree30, freemem, pginrate);
		desperate = 1;
		goto unload;
	}

	/*
	 * Search list of processes to swapin and swapout deadwood.
	 */
	swapin_proc_time = 0;
top:
	mutex_enter(&pidlock);
	for (prp = practive; prp != NULL; prp = prp->p_next) {
		if (not_swappable(prp))
			continue;

		/*
		 * Look at processes with at least one swapped lwp.
		 */
		if (prp->p_swapcnt) {
			time_t proc_time;

			/*
			 * Higher priority processes are good candidates
			 * to swapin.
			 */
			mutex_enter(&prp->p_lock);
			proc_pri = -1;
			t = prp->p_tlist;
			proc_time = 0;
			do {
				if (t->t_schedflag & TS_LOAD)
					continue;

				thread_lock(t);
				thread_pri = CL_SWAPIN(t, 0);
				thread_unlock(t);

				if (t->t_stime - proc_time > 0)
					proc_time = t->t_stime;
				if (thread_pri > proc_pri)
					proc_pri = thread_pri;
			} while ((t = t->t_forw) != prp->p_tlist);
			mutex_exit(&prp->p_lock);

			if (proc_pri == -1)
				continue;

			TRACE_3(TR_FAC_SCHED, TR_CHOOSE_SWAPIN,
			    "prp %p epri %d proc_time %d",
			    prp, proc_pri, proc_time);

			/*
			 * Swapin processes with a high effective priority.
			 */
			if (swapin_prp == NULL || proc_pri > chosen_pri) {
				swapin_prp = prp;
				chosen_pri = proc_pri;
				swapin_pri = proc_pri;
				swapin_proc_time = proc_time;
			}
		} else {
			/*
			 * No need to soft swap if we have sufficient
			 * memory.
			 */
			if (avefree > desfree ||
			    avefree < desfree && freemem > desfree)
				continue;

			/*
			 * Skip processes that are exiting
			 * or whose address spaces are locked.
			 */
			mutex_enter(&prp->p_lock);
			if ((prp->p_flag & SEXITING) ||
			    (prp->p_as != NULL && AS_ISPGLCK(prp->p_as))) {
				mutex_exit(&prp->p_lock);
				continue;
			}

			/*
			 * Softswapping to kick out deadwood.
			 */
			proc_pri = -1;
			t = prp->p_tlist;
			do {
				if ((t->t_schedflag & (TS_SWAPENQ |
				    TS_ON_SWAPQ | TS_LOAD)) != TS_LOAD)
					continue;

				thread_lock(t);
				thread_pri = CL_SWAPOUT(t, SOFTSWAP);
				thread_unlock(t);
				if (thread_pri > proc_pri)
					proc_pri = thread_pri;
			} while ((t = t->t_forw) != prp->p_tlist);

			if (proc_pri != -1) {
				uint_t swrss;

				mutex_exit(&pidlock);

				TRACE_1(TR_FAC_SCHED, TR_SOFTSWAP,
				    "softswap:prp %p", prp);

				(void) swapout(prp, &swrss, SOFTSWAP);
				softswap++;
				prp->p_swrss += swrss;
				mutex_exit(&prp->p_lock);
				goto top;
			}
			mutex_exit(&prp->p_lock);
		}
	}
	if (swapin_prp != NULL)
		mutex_enter(&swapin_prp->p_lock);
	mutex_exit(&pidlock);

	if (swapin_prp == NULL) {
		TRACE_3(TR_FAC_SCHED, TR_RUNOUT,
		"schedrunout:runout nswapped: %d, avefree: %ld freemem: %ld",
		    nswapped, avefree, freemem);

		t = curthread;
		thread_lock(t);
		runout++;
		t->t_schedflag |= (TS_ALLSTART & ~TS_CSTART);
		t->t_whystop = PR_SUSPENDED;
		t->t_whatstop = SUSPEND_NORMAL;
		(void) new_mstate(t, LMS_SLEEP);
		mutex_enter(&swap_cpr_lock);
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		mutex_exit(&swap_cpr_lock);
		thread_stop(t);		/* change state and drop lock */
		swtch();
		mutex_enter(&swap_cpr_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &swap_cpr_lock);
		mutex_exit(&swap_cpr_lock);
		goto loop;
	}

	/*
	 * Decide how deserving this process is to be brought in.
	 * Needs is an estimate of how much core the process will
	 * need.  If the process has been out for a while, then we
	 * will bring it in with 1/2 the core needed, otherwise
	 * we are conservative.
	 */
	divisor = 1;
	swapout_time = (ddi_get_lbolt() - swapin_proc_time) / hz;
	if (swapout_time > maxslp / 2)
		divisor = 2;

	needs = MIN(swapin_prp->p_swrss, lotsfree);
	needs = MAX(needs, min_procsize);
	needs = needs / divisor;

	/*
	 * Use freemem, since we want processes to be swapped
	 * in quickly.
	 */
	avail = freemem - deficit;
	if (avail > (spgcnt_t)needs) {
		deficit += needs;

		TRACE_2(TR_FAC_SCHED, TR_SWAPIN_VALUES,
		    "swapin_values: prp %p needs %lu", swapin_prp, needs);

		if (swapin(swapin_prp)) {
			mutex_exit(&swapin_prp->p_lock);
			goto loop;
		}
		deficit -= MIN(needs, deficit);
		mutex_exit(&swapin_prp->p_lock);
	} else {
		mutex_exit(&swapin_prp->p_lock);
		/*
		 * If deficit is high, too many processes have been
		 * swapped in so wait a sec before attempting to
		 * swapin more.
		 */
		if (freemem > needs) {
			TRACE_2(TR_FAC_SCHED, TR_HIGH_DEFICIT,
			    "deficit: prp %p needs %lu", swapin_prp, needs);
			goto block;
		}
	}

	TRACE_2(TR_FAC_SCHED, TR_UNLOAD,
	    "unload: prp %p needs %lu", swapin_prp, needs);

unload:
	/*
	 * Unload all unloadable modules, free all other memory
	 * resources we can find, then look for a thread to hardswap.
	 */
	modreap();
	segkp_cache_free();

	swapout_prp = NULL;
	mutex_enter(&pidlock);
	for (prp = practive; prp != NULL; prp = prp->p_next) {

		/*
		 * No need to soft swap if we have sufficient
		 * memory.
		 */
		if (not_swappable(prp))
			continue;

		if (avefree > minfree ||
		    avefree < minfree && freemem > desfree) {
			swapout_prp = NULL;
			break;
		}

		/*
		 * Skip processes that are exiting
		 * or whose address spaces are locked.
		 */
		mutex_enter(&prp->p_lock);
		if ((prp->p_flag & SEXITING) ||
		    (prp->p_as != NULL && AS_ISPGLCK(prp->p_as))) {
			mutex_exit(&prp->p_lock);
			continue;
		}

		proc_pri = -1;
		t = prp->p_tlist;
		do {
			if ((t->t_schedflag & (TS_SWAPENQ |
			    TS_ON_SWAPQ | TS_LOAD)) != TS_LOAD)
				continue;

			thread_lock(t);
			thread_pri = CL_SWAPOUT(t, HARDSWAP);
			thread_unlock(t);
			if (thread_pri > proc_pri)
				proc_pri = thread_pri;
		} while ((t = t->t_forw) != prp->p_tlist);

		mutex_exit(&prp->p_lock);
		if (proc_pri == -1)
			continue;

		/*
		 * Swapout processes sleeping with a lower priority
		 * than the one currently being swapped in, if any.
		 */
		if (swapin_prp == NULL || swapin_pri > proc_pri) {
			TRACE_2(TR_FAC_SCHED, TR_CHOOSE_SWAPOUT,
			    "hardswap: prp %p needs %lu", prp, needs);

			if (swapout_prp == NULL || proc_pri < chosen_pri) {
				swapout_prp = prp;
				chosen_pri = proc_pri;
			}
		}
	}

	/*
	 * Acquire the "p_lock" before dropping "pidlock"
	 * to prevent the proc structure from being freed
	 * if the process exits before swapout completes.
	 */
	if (swapout_prp != NULL)
		mutex_enter(&swapout_prp->p_lock);
	mutex_exit(&pidlock);

	if ((prp = swapout_prp) != NULL) {
		uint_t swrss = 0;
		int swapped;

		swapped = swapout(prp, &swrss, HARDSWAP);
		if (swapped) {
			/*
			 * If desperate, we want to give the space obtained
			 * by swapping this process out to processes in core,
			 * so we give them a chance by increasing deficit.
			 */
			prp->p_swrss += swrss;
			if (desperate)
				deficit += MIN(prp->p_swrss, lotsfree);
			hardswap++;
		}
		mutex_exit(&swapout_prp->p_lock);

		if (swapped)
			goto loop;
	}

	/*
	 * Delay for 1 second and look again later.
	 */
	TRACE_3(TR_FAC_SCHED, TR_RUNIN,
	    "schedrunin:runin nswapped: %d, avefree: %ld freemem: %ld",
	    nswapped, avefree, freemem);

block:
	t = curthread;
	thread_lock(t);
	runin++;
	t->t_schedflag |= (TS_ALLSTART & ~TS_CSTART);
	t->t_whystop = PR_SUSPENDED;
	t->t_whatstop = SUSPEND_NORMAL;
	(void) new_mstate(t, LMS_SLEEP);
	mutex_enter(&swap_cpr_lock);
	CALLB_CPR_SAFE_BEGIN(&cprinfo);
	mutex_exit(&swap_cpr_lock);
	thread_stop(t);		/* change to stop state and drop lock */
	swtch();
	mutex_enter(&swap_cpr_lock);
	CALLB_CPR_SAFE_END(&cprinfo, &swap_cpr_lock);
	mutex_exit(&swap_cpr_lock);
	goto loop;
}

/*
 * Remove the specified thread from the swap queue.
 */
static void
swapdeq(kthread_id_t tp)
{
	kthread_id_t *tpp;

	ASSERT(THREAD_LOCK_HELD(tp));
	ASSERT(tp->t_schedflag & TS_ON_SWAPQ);

	tpp = &tswap_queue;
	for (;;) {
		ASSERT(*tpp != NULL);
		if (*tpp == tp)
			break;
		tpp = &(*tpp)->t_link;
	}
	*tpp = tp->t_link;
	tp->t_schedflag &= ~TS_ON_SWAPQ;
}

/*
 * Swap in lwps.  Returns nonzero on success (i.e., if at least one lwp is
 * swapped in) and 0 on failure.
 */
static int
swapin(proc_t *pp)
{
	kthread_id_t tp;
	int err;
	int num_swapped_in = 0;
	struct cpu *cpup = CPU;
	pri_t thread_pri;

	ASSERT(MUTEX_HELD(&pp->p_lock));
	ASSERT(pp->p_swapcnt);

top:
	tp = pp->p_tlist;
	do {
		/*
		 * Only swapin eligible lwps (specified by the scheduling
		 * class) which are unloaded and ready to run.
		 */
		thread_lock(tp);
		thread_pri = CL_SWAPIN(tp, 0);
		if (thread_pri != -1 && tp->t_state == TS_RUN &&
		    (tp->t_schedflag & TS_LOAD) == 0) {
			size_t stack_size;
			pgcnt_t stack_pages;

			ASSERT((tp->t_schedflag & TS_ON_SWAPQ) == 0);

			thread_unlock(tp);
			/*
			 * Now drop the p_lock since the stack needs
			 * to brought in.
			 */
			mutex_exit(&pp->p_lock);

			stack_size = swapsize(tp->t_swap);
			stack_pages = btopr(stack_size);
			/* Kernel probe */
			TNF_PROBE_4(swapin_lwp, "vm swap swapin", /* CSTYLED */,
			    tnf_pid,		pid,		pp->p_pid,
			    tnf_lwpid,		lwpid,		tp->t_tid,
			    tnf_kthread_id,	tid,		tp,
			    tnf_ulong,		page_count,	stack_pages);

			rw_enter(&kas.a_lock, RW_READER);
			err = segkp_fault(segkp->s_as->a_hat, segkp,
			    tp->t_swap, stack_size, F_SOFTLOCK, S_OTHER);
			rw_exit(&kas.a_lock);

			/*
			 * Re-acquire the p_lock.
			 */
			mutex_enter(&pp->p_lock);
			if (err) {
				num_swapped_in = 0;
				break;
			} else {
#ifdef __sparc
				lwp_swapin(tp);
#endif /* __sparc */
				CPU_STATS_ADDQ(cpup, vm, swapin, 1);
				CPU_STATS_ADDQ(cpup, vm, pgswapin,
				    stack_pages);

				pp->p_swapcnt--;
				pp->p_swrss -= stack_pages;

				thread_lock(tp);
				tp->t_schedflag |= TS_LOAD;
				dq_sruninc(tp);

				/* set swapin time */
				tp->t_stime = ddi_get_lbolt();
				thread_unlock(tp);

				nswapped--;
				tot_swapped_in++;
				num_swapped_in++;

				TRACE_2(TR_FAC_SCHED, TR_SWAPIN,
				    "swapin: pp %p stack_pages %lu",
				    pp, stack_pages);
				goto top;
			}
		}
		thread_unlock(tp);
	} while ((tp = tp->t_forw) != pp->p_tlist);
	return (num_swapped_in);
}

/*
 * Swap out lwps.  Returns nonzero on success (i.e., if at least one lwp is
 * swapped out) and 0 on failure.
 */
static int
swapout(proc_t *pp, uint_t *swrss, int swapflags)
{
	kthread_id_t tp;
	pgcnt_t ws_pages = 0;
	int err;
	int swapped_lwps = 0;
	struct as *as = pp->p_as;
	struct cpu *cpup = CPU;
	pri_t thread_pri;

	ASSERT(MUTEX_HELD(&pp->p_lock));

	if (pp->p_flag & SEXITING)
		return (0);

top:
	tp = pp->p_tlist;
	do {
		klwp_t *lwp = ttolwp(tp);

		/*
		 * Swapout eligible lwps (specified by the scheduling class)
		 * which don't have TS_DONT_SWAP set.  Set the "intent to swap"
		 * flag (TS_SWAPENQ) on threads which have either TS_DONT_SWAP
		 * set or are currently on a split stack so that they can be
		 * swapped if and when they reach a safe point.
		 */
		thread_lock(tp);
		thread_pri = CL_SWAPOUT(tp, swapflags);
		if (thread_pri != -1) {
			if ((tp->t_schedflag & TS_DONT_SWAP) ||
			    (tp->t_flag & T_SPLITSTK)) {
				tp->t_schedflag |= TS_SWAPENQ;
				tp->t_trapret = 1;
				aston(tp);
			} else {
				pgcnt_t stack_pages;
				size_t stack_size;

				ASSERT((tp->t_schedflag &
				    (TS_DONT_SWAP | TS_LOAD)) == TS_LOAD);

				if (lock_try(&tp->t_lock)) {
					/*
					 * Remove thread from the swap_queue.
					 */
					if (tp->t_schedflag & TS_ON_SWAPQ) {
						ASSERT(!(tp->t_schedflag &
						    TS_SWAPENQ));
						swapdeq(tp);
					} else if (tp->t_state == TS_RUN)
						dq_srundec(tp);

					tp->t_schedflag &=
					    ~(TS_LOAD | TS_SWAPENQ);
					lock_clear(&tp->t_lock);

					/*
					 * Set swapout time if the thread isn't
					 * sleeping.
					 */
					if (tp->t_state != TS_SLEEP)
						tp->t_stime = ddi_get_lbolt();
					thread_unlock(tp);

					nswapped++;
					tot_swapped_out++;

					lwp->lwp_ru.nswap++;

					/*
					 * Now drop the p_lock since the
					 * stack needs to pushed out.
					 */
					mutex_exit(&pp->p_lock);

					stack_size = swapsize(tp->t_swap);
					stack_pages = btopr(stack_size);
					ws_pages += stack_pages;
					/* Kernel probe */
					TNF_PROBE_4(swapout_lwp,
					    "vm swap swapout",
					    /* CSTYLED */,
					    tnf_pid, pid, pp->p_pid,
					    tnf_lwpid, lwpid, tp->t_tid,
					    tnf_kthread_id, tid, tp,
					    tnf_ulong, page_count,
					    stack_pages);

					rw_enter(&kas.a_lock, RW_READER);
					err = segkp_fault(segkp->s_as->a_hat,
					    segkp, tp->t_swap, stack_size,
					    F_SOFTUNLOCK, S_WRITE);
					rw_exit(&kas.a_lock);

					if (err) {
						cmn_err(CE_PANIC,
						    "swapout: segkp_fault "
						    "failed err: %d", err);
					}
					CPU_STATS_ADDQ(cpup,
					    vm, pgswapout, stack_pages);

					mutex_enter(&pp->p_lock);
					pp->p_swapcnt++;
					swapped_lwps++;
					goto top;
				}
			}
		}
		thread_unlock(tp);
	} while ((tp = tp->t_forw) != pp->p_tlist);

	/*
	 * Unload address space when all lwps are swapped out.
	 */
	if (pp->p_swapcnt == pp->p_lwpcnt) {
		size_t as_size = 0;

		/*
		 * Avoid invoking as_swapout() if the process has
		 * no MMU resources since pageout will eventually
		 * steal pages belonging to this address space.  This
		 * saves CPU cycles as the number of pages that are
		 * potentially freed or pushed out by the segment
		 * swapout operation is very small.
		 */
		if (rm_asrss(pp->p_as) != 0)
			as_size = as_swapout(as);

		CPU_STATS_ADDQ(cpup, vm, pgswapout, btop(as_size));
		CPU_STATS_ADDQ(cpup, vm, swapout, 1);
		ws_pages += btop(as_size);

		TRACE_2(TR_FAC_SCHED, TR_SWAPOUT,
		    "swapout: pp %p pages_pushed %lu", pp, ws_pages);
		/* Kernel probe */
		TNF_PROBE_2(swapout_process, "vm swap swapout", /* CSTYLED */,
		    tnf_pid,	pid,		pp->p_pid,
		    tnf_ulong,	page_count,	ws_pages);
	}
	*swrss = ws_pages;
	return (swapped_lwps);
}

void
swapout_lwp(klwp_t *lwp)
{
	kthread_id_t tp = curthread;

	ASSERT(curthread == lwptot(lwp));

	/*
	 * Don't insert the thread onto the swap queue if
	 * sufficient memory is available.
	 */
	if (avefree > desfree || avefree < desfree && freemem > desfree) {
		thread_lock(tp);
		tp->t_schedflag &= ~TS_SWAPENQ;
		thread_unlock(tp);
		return;
	}

	/*
	 * Lock the thread, then move it to the swapped queue from the
	 * onproc queue and set its state to be TS_RUN.
	 */
	thread_lock(tp);
	ASSERT(tp->t_state == TS_ONPROC);
	if (tp->t_schedflag & TS_SWAPENQ) {
		tp->t_schedflag &= ~TS_SWAPENQ;

		/*
		 * Set the state of this thread to be runnable
		 * and move it from the onproc queue to the swap queue.
		 */
		disp_swapped_enq(tp);

		/*
		 * Insert the thread onto the swap queue.
		 */
		tp->t_link = tswap_queue;
		tswap_queue = tp;
		tp->t_schedflag |= TS_ON_SWAPQ;

		thread_unlock_nopreempt(tp);

		TRACE_1(TR_FAC_SCHED, TR_SWAPOUT_LWP, "swapout_lwp:%x", lwp);

		swtch();
	} else {
		thread_unlock(tp);
	}
}

/*
 * Swap all threads on the swap queue.
 */
static void
process_swap_queue(void)
{
	kthread_id_t tp;
	uint_t ws_pages;
	proc_t *pp;
	struct cpu *cpup = CPU;
	klwp_t *lwp;
	int err;

	if (tswap_queue == NULL)
		return;

	/*
	 * Acquire the "swapped_lock" which locks the swap queue,
	 * and unload the stacks of all threads on it.
	 */
	disp_lock_enter(&swapped_lock);
	while ((tp = tswap_queue) != NULL) {
		pgcnt_t stack_pages;
		size_t stack_size;

		tswap_queue = tp->t_link;
		tp->t_link = NULL;

		/*
		 * Drop the "dispatcher lock" before acquiring "t_lock"
		 * to avoid spinning on it since the thread at the front
		 * of the swap queue could be pinned before giving up
		 * its "t_lock" in resume.
		 */
		disp_lock_exit(&swapped_lock);
		lock_set(&tp->t_lock);

		/*
		 * Now, re-acquire the "swapped_lock".  Acquiring this lock
		 * results in locking the thread since its dispatcher lock
		 * (t_lockp) is the "swapped_lock".
		 */
		disp_lock_enter(&swapped_lock);
		ASSERT(tp->t_state == TS_RUN);
		ASSERT(tp->t_schedflag & (TS_LOAD | TS_ON_SWAPQ));

		tp->t_schedflag &= ~(TS_LOAD | TS_ON_SWAPQ);
		tp->t_stime = ddi_get_lbolt();		/* swapout time */
		disp_lock_exit(&swapped_lock);
		lock_clear(&tp->t_lock);

		lwp = ttolwp(tp);
		lwp->lwp_ru.nswap++;

		pp = ttoproc(tp);
		stack_size = swapsize(tp->t_swap);
		stack_pages = btopr(stack_size);

		/* Kernel probe */
		TNF_PROBE_4(swapout_lwp, "vm swap swapout", /* CSTYLED */,
		    tnf_pid,		pid,		pp->p_pid,
		    tnf_lwpid,		lwpid,		tp->t_tid,
		    tnf_kthread_id,	tid,		tp,
		    tnf_ulong,		page_count,	stack_pages);

		rw_enter(&kas.a_lock, RW_READER);
		err = segkp_fault(segkp->s_as->a_hat, segkp, tp->t_swap,
		    stack_size, F_SOFTUNLOCK, S_WRITE);
		rw_exit(&kas.a_lock);

		if (err) {
			cmn_err(CE_PANIC,
			"process_swap_list: segkp_fault failed err: %d", err);
		}
		CPU_STATS_ADDQ(cpup, vm, pgswapout, stack_pages);

		nswapped++;
		tot_swapped_out++;
		swapqswap++;

		/*
		 * Don't need p_lock since the swapper is the only
		 * thread which increments/decrements p_swapcnt and p_swrss.
		 */
		ws_pages = stack_pages;
		pp->p_swapcnt++;

		TRACE_1(TR_FAC_SCHED, TR_SWAPQ_LWP, "swaplist: pp %p", pp);

		/*
		 * Unload address space when all lwps are swapped out.
		 */
		if (pp->p_swapcnt == pp->p_lwpcnt) {
			size_t as_size = 0;

			if (rm_asrss(pp->p_as) != 0)
				as_size = as_swapout(pp->p_as);

			CPU_STATS_ADDQ(cpup, vm, pgswapout,
			    btop(as_size));
			CPU_STATS_ADDQ(cpup, vm, swapout, 1);

			ws_pages += btop(as_size);

			TRACE_2(TR_FAC_SCHED, TR_SWAPQ_PROC,
			    "swaplist_proc: pp %p pages_pushed: %lu",
			    pp, ws_pages);
			/* Kernel probe */
			TNF_PROBE_2(swapout_process, "vm swap swapout",
			    /* CSTYLED */,
			    tnf_pid,	pid,		pp->p_pid,
			    tnf_ulong,	page_count,	ws_pages);
		}
		pp->p_swrss += ws_pages;
		disp_lock_enter(&swapped_lock);
	}
	disp_lock_exit(&swapped_lock);
}
