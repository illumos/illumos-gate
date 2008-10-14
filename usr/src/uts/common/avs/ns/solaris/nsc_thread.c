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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/errno.h>
#include "nsc_thread.h"

#ifdef DS_DDICT
#include "../contract.h"
#endif

#include "../nsctl.h"
#include "nskernd.h"
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */


/*
 * Global data
 */
static nstset_t		*nst_sets;
static nsthread_t	*nst_pending;
static kmutex_t		nst_global_lock;	/* nst_sets, nst_pending */


/*
 * nst_kmem_xalloc
 *
 * Poll for memory.
 */
static void *
nst_kmem_xalloc(size_t size, int sec, void *(*alloc)(size_t, int))
{
	clock_t usec = sec * 1000000;
	void *p = NULL;

	while (usec > 0) {
		if ((p = (*alloc)(size, KM_NOSLEEP)) != NULL)
			return (p);

		delay(drv_usectohz((clock_t)NST_MEMORY_TIMEOUT));
		usec -= NST_MEMORY_TIMEOUT;
	}

	cmn_err(CE_WARN, "nst_kmem_xalloc: failed to allocate %ld bytes", size);
	return (NULL);
}


#if 0
/* currently unused */
static void *
nst_kmem_alloc(size_t size, int sec)
{
	return (nst_kmem_xalloc(size, sec, kmem_alloc));
}
#endif


static void *
nst_kmem_zalloc(size_t size, int sec)
{
	return (nst_kmem_xalloc(size, sec, kmem_zalloc));
}


/*
 * Queue stuff that should be in the DDI.
 */

/*
 * nst_insque
 *
 * Insert entryp after predp in a doubly linked list.
 */
static void
nst_insque(nst_q_t *entryp, nst_q_t *predp)
{
	entryp->q_back = predp;
	entryp->q_forw = predp->q_forw;
	predp->q_forw = entryp;
	entryp->q_forw->q_back = entryp;
}
#ifndef DS_DDICT
#pragma inline(nst_insque)	/* compiler hint to inline this function */
#endif


/*
 * nst_remque
 *
 * Remove entryp from a doubly linked list.
 */
static void
nst_remque(nst_q_t *entryp)
{
	entryp->q_back->q_forw = entryp->q_forw;
	entryp->q_forw->q_back = entryp->q_back;
	entryp->q_forw = entryp->q_back = NULL;
}
#ifndef DS_DDICT
#pragma inline(nst_remque)	/* compiler hint to inline this function */
#endif


/*
 * nst_thread_init
 *
 * Initialise the dynamic part of a thread
 */
static void
nst_thread_init(nsthread_t *tp)
{
	ASSERT(MUTEX_HELD(&((tp->tp_set)->set_lock)));
	ASSERT(!(tp->tp_flag & NST_TF_INUSE));
	tp->tp_flag = NST_TF_INUSE;
	tp->tp_func = NULL;
	tp->tp_arg = NULL;
}
#ifndef DS_DDICT
#pragma inline(nst_thread_init)	/* compiler hint to inline this function */
#endif


/*
 * nst_thread_alloc
 *
 * Return an nsthread from the free pool, NULL if none
 */
static nsthread_t *
nst_thread_alloc(nstset_t *set, const int sleep)
{
	nsthread_t *tp = NULL;

	mutex_enter(&set->set_lock);

	if (set->set_flag & NST_SF_KILL) {
		mutex_exit(&set->set_lock);
		DTRACE_PROBE1(nst_thread_alloc_err_kill,
				nstset_t *, set);
		return (NULL);
	}

	do {
		tp = (nsthread_t *)set->set_free.q_forw;
		if (tp != (nsthread_t *)&set->set_free)
			nst_remque(&tp->tp_link);
		else {
			tp = NULL;

			if (!sleep)
				break;

			set->set_res_cnt++;

			DTRACE_PROBE2(nst_thread_alloc_sleep,
				nstset_t *, set,
				int, set->set_res_cnt);

			cv_wait(&set->set_res_cv, &set->set_lock);

			DTRACE_PROBE1(nst_thread_alloc_wake,
				nstset_t *, set);

			set->set_res_cnt--;

			if (set->set_flag & NST_SF_KILL)
				break;
		}
	} while (tp == NULL);

	/* initialise the thread */

	if (tp != NULL) {
		nst_thread_init(tp);
		set->set_nlive++;
	}

	mutex_exit(&set->set_lock);

	return (tp);
}


/*
 * nst_thread_free
 *
 * Requeue a thread on the free or reuse pools.  Threads are always
 * queued to the tail of the list to prevent rapid recycling.
 *
 * Must be called with set->set_lock held.
 */
static void
nst_thread_free(nsthread_t *tp)
{
	nstset_t *set = tp->tp_set;

	if (!set)
		return;

	ASSERT(MUTEX_HELD(&set->set_lock));

	tp->tp_flag &= ~NST_TF_INUSE;
	if (tp->tp_flag & NST_TF_DESTROY) {
		/* add self to reuse pool */
		nst_insque(&tp->tp_link, set->set_reuse.q_back);
	} else {
		/* add self to free pool */
		nst_insque(&tp->tp_link, set->set_free.q_back);
		if (set->set_res_cnt > 0)
			cv_broadcast(&set->set_res_cv);
	}
}


/*
 * nst_thread_run
 *
 * The first function that a new thread runs on entry from user land.
 * This is the main thread function that handles thread work and death.
 */
static void
nst_thread_run(void *arg)
{
	nsthread_t *tp;
	nstset_t *set;
	int first = 1;

	mutex_enter(&nst_global_lock);

	/* check if this thread is still on the pending list */

	for (tp = nst_pending; tp; tp = tp->tp_chain) {
		if (tp == (nsthread_t *)arg) {
			break;
		}
	}

	if (!tp) {
		mutex_exit(&nst_global_lock);
		return;
	}

	if (!tp->tp_set) {
		mutex_exit(&nst_global_lock);
#ifdef DEBUG
		cmn_err(CE_WARN, "nst_thread_run(%p): already dead?",
		    (void *)tp);
#endif
		return;
	}

	/* check that the set is still on the list of sets */

	for (set = nst_sets; set; set = set->set_next) {
		if (set == tp->tp_set) {
			break;
		}
	}

	if (!set) {
		mutex_exit(&nst_global_lock);
#ifdef DEBUG
		cmn_err(CE_WARN, "nst_thread_run(%p): no set?", (void *)tp);
#endif
		return;
	}

	mutex_enter(&set->set_lock);

	mutex_exit(&nst_global_lock);

	/*
	 * Mark the parent.
	 * The parent won't actually run until set->set_lock is dropped.
	 */

	tp->tp_flag &= ~NST_TF_PENDING;
	cv_broadcast(&tp->tp_cv);

	/*
	 * Main loop.
	 */

	while (!(set->set_flag & NST_SF_KILL) &&
	    !(tp->tp_flag & NST_TF_KILL)) {
		/*
		 * On initial entry the caller will add this thread to
		 * the free pool if required, there after the thread
		 * must do it for itself.
		 */

		if (first) {
			first = 0;
		} else {
			nst_thread_free(tp);
			set->set_nlive--;
		}

		DTRACE_PROBE1(nst_thread_run_sleep,
			    nsthread_t *, tp);

		cv_wait(&tp->tp_cv, &set->set_lock);

		DTRACE_PROBE1(nst_thread_run_wake,
			    nsthread_t *, tp);

		if ((set->set_flag & NST_SF_KILL) ||
		    (tp->tp_flag & NST_TF_KILL)) {
			break;
		}

		mutex_exit(&set->set_lock);

		if (tp->tp_func) {
			(*tp->tp_func)(tp->tp_arg);
			tp->tp_func = 0;
			tp->tp_arg = 0;
		}
#ifdef DEBUG
		else {
			cmn_err(CE_WARN,
			    "nst_thread_run(%p): NULL function pointer",
			    (void *)tp);
		}
#endif

		mutex_enter(&set->set_lock);
	}

	/* remove self from the free and/or reuse pools */
	if (tp->tp_link.q_forw != NULL || tp->tp_link.q_back != NULL) {
		ASSERT(tp->tp_link.q_forw != NULL &&
		    tp->tp_link.q_back != NULL);
		nst_remque(&tp->tp_link);
	}

	set->set_nthread--;
	tp->tp_flag &= ~NST_TF_KILL;

	/* wake the context that is running nst_destroy() or nst_del_thread() */
	cv_broadcast(&set->set_kill_cv);

	mutex_exit(&set->set_lock);

	/* suicide */
}


/*
 * nst_thread_destroy
 *
 * Free up the kernel level resources.  The thread must already be
 * un-chained from the set, and the caller must not be the thread
 * itself.
 */
static void
nst_thread_destroy(nsthread_t *tp)
{
	if (!tp)
		return;

	ASSERT(tp->tp_chain == NULL);

	tp->tp_set = NULL;

	if (tp->tp_flag & NST_TF_INUSE) {
		cmn_err(CE_WARN, "nst_thread_destroy(%p): still in use!",
		    (void *)tp);
		/* leak the thread */
		return;
	}

	cv_destroy(&tp->tp_cv);
	kmem_free(tp, sizeof (*tp));
}


/*
 * nst_thread_create
 *
 * Create and return a new thread from a threadset.
 */
static nsthread_t *
nst_thread_create(nstset_t *set)
{
	nsthread_t *tp, **tpp;
	int rc;

	/* try and reuse a thread first */

	if (set->set_reuse.q_forw != &set->set_reuse) {
		mutex_enter(&set->set_lock);

		tp = (nsthread_t *)set->set_reuse.q_forw;
		if (tp != (nsthread_t *)&set->set_reuse)
			nst_remque(&tp->tp_link);
		else
			tp = NULL;

		mutex_exit(&set->set_lock);

		if (tp) {
			DTRACE_PROBE2(nst_thread_create_end,
				nstset_t *, set,
				nsthread_t *, tp);
			return (tp);
		}
	}

	/* create a thread using nskernd */

	tp = nst_kmem_zalloc(sizeof (*tp), 2);
	if (!tp) {
		DTRACE_PROBE1(nst_thread_create_err_mem,
				nstset_t *, set);
		return (NULL);
	}

	cv_init(&tp->tp_cv, NULL, CV_DRIVER, NULL);
	tp->tp_flag = NST_TF_PENDING;
	tp->tp_set = set;

	mutex_enter(&set->set_lock);

	if (set->set_flag & NST_SF_KILL) {
		mutex_exit(&set->set_lock);
		nst_thread_destroy(tp);
#ifdef DEBUG
		cmn_err(CE_WARN, "nst_thread_create: called during destroy");
#endif
		DTRACE_PROBE2(nst_thread_create_err_kill,
				nstset_t *, set,
				nsthread_t *, tp);
		return (NULL);
	}

	set->set_pending++;

	mutex_exit(&set->set_lock);

	mutex_enter(&nst_global_lock);

	tp->tp_chain = nst_pending;
	nst_pending = tp;

	mutex_exit(&nst_global_lock);

	DTRACE_PROBE2(nst_dbg_thr_create_proc_start,
				nstset_t *, set,
				nsthread_t *, tp);

	rc = nsc_create_process(nst_thread_run, tp, 0);

	DTRACE_PROBE2(nst_dbg_thr_create_proc_end,
				nstset_t *, set,
				nsthread_t *, tp);

	if (!rc) {
		/*
		 * wait for child to start and check in.
		 */

		mutex_enter(&set->set_lock);

		while (tp->tp_flag & NST_TF_PENDING)
			cv_wait(&tp->tp_cv, &set->set_lock);

		mutex_exit(&set->set_lock);
	}

	/*
	 * remove from pending chain.
	 */

	mutex_enter(&nst_global_lock);

	for (tpp = &nst_pending; (*tpp); tpp = &((*tpp)->tp_chain)) {
		if (*tpp == tp) {
			*tpp = tp->tp_chain;
			tp->tp_chain = NULL;
			break;
		}
	}

	mutex_exit(&nst_global_lock);

	/*
	 * Check for errors and return if required.
	 */

	mutex_enter(&set->set_lock);

	set->set_pending--;

	if (rc ||
	    (set->set_flag & NST_SF_KILL) ||
	    (set->set_nthread + 1) > USHRT_MAX) {
		if (rc == 0) {
			/*
			 * Thread is alive, and needs to be woken and killed.
			 */
			tp->tp_flag |= NST_TF_KILL;
			cv_broadcast(&tp->tp_cv);

			while (tp->tp_flag & NST_TF_KILL)
				cv_wait(&set->set_kill_cv, &set->set_lock);
		}
		mutex_exit(&set->set_lock);

		nst_thread_destroy(tp);
#ifdef DEBUG
		cmn_err(CE_WARN,
		"nst_thread_create: error (rc %d, set_flag %x, set_nthread %d)",
			rc, set->set_flag, set->set_nthread);
#endif
		DTRACE_PROBE2(nst_thread_create_err_proc,
				nstset_t *, set,
				nsthread_t *, tp);

		return (NULL);
	}

	/*
	 * Move into set proper.
	 */

	tp->tp_chain = set->set_chain;
	set->set_chain = tp;
	set->set_nthread++;

	mutex_exit(&set->set_lock);

	return (tp);
}


/*
 * nst_create
 *
 * Start a new thread from a thread set, returning the
 * address of the thread, or NULL on failure.
 *
 * All threads are created detached.
 *
 * Valid flag values:
 *
 *      NST_CREATE      - create a new thread rather than using one
 *                        from the threadset.  Once the thread
 *                        completes it will not be added to the active
 *                        portion of the threadset, but will be cached
 *                        on the reuse chain, and so is available for
 *                        subsequent NST_CREATE or nst_add_thread()
 *			  operations.
 *
 *	NST_SLEEP	- wait for a thread to be available instead of
 *			  returning NULL.  Has no meaning with NST_CREATE.
 *
 * Returns a pointer to the new thread, or NULL.
 */
nsthread_t *
nst_create(nstset_t *set, void (*func)(), blind_t arg, int flags)
{
	nsthread_t *tp = NULL;

	if (!set)
		return (NULL);

	if (set->set_flag & NST_SF_KILL) {
		DTRACE_PROBE1(nst_create_err_kill,
				nstset_t *, set);
		return (NULL);
	}

	if (flags & NST_CREATE) {
		/* get new thread */

		if ((tp = nst_thread_create(set)) == NULL)
			return (NULL);

		/* initialise the thread */

		mutex_enter(&set->set_lock);
		nst_thread_init(tp);
		tp->tp_flag |= NST_TF_DESTROY;
		set->set_nlive++;
		mutex_exit(&set->set_lock);
	} else {
		if (!(tp = nst_thread_alloc(set, (flags & NST_SLEEP))))
			return (NULL);
	}

	/* set thread running */

	tp->tp_func = func;
	tp->tp_arg = arg;

	mutex_enter(&set->set_lock);
	cv_broadcast(&tp->tp_cv);
	mutex_exit(&set->set_lock);

	return (tp);
}


/*
 * nst_destroy
 *
 * Destroy a thread set created by nst_init(). It is the
 * caller's responsibility to ensure that all prior thread
 * calls have completed prior to this call and that the
 * caller is not executing from within thread context.
 */
void
nst_destroy(nstset_t *set)
{
	nsthread_t *tp, *ntp;
	nstset_t *sp, **spp;

	if (!set)
		return;

	mutex_enter(&nst_global_lock);

	for (sp = nst_sets; sp; sp = sp->set_next) {
		if (sp == set) {
			break;
		}
	}

	if (!sp) {
		mutex_exit(&nst_global_lock);
#ifdef DEBUG
		cmn_err(CE_WARN, "nst_destroy(%p): no set?", (void *)set);
#endif
		DTRACE_PROBE1(nst_destroy_err_noset,
				nstset_t *, set);
		return;
	}

	mutex_enter(&set->set_lock);

	mutex_exit(&nst_global_lock);

	if (set->set_flag & NST_SF_KILL) {
		/*
		 * Wait for a pending destroy to complete
		 */

#ifdef DEBUG
		cmn_err(CE_WARN,
		    "nst_destroy(%p): duplicate destroy of set", (void *)set);
#endif

		set->set_destroy_cnt++;
		(void) cv_wait_sig(&set->set_destroy_cv, &set->set_lock);
		set->set_destroy_cnt--;

		mutex_exit(&set->set_lock);

		DTRACE_PROBE1(nst_destroy_end,
				nstset_t *, set);

		return;
	}

	set->set_flag |= NST_SF_KILL;

	/* Wake all threads in nst_create(NST_SLEEP) */
	cv_broadcast(&set->set_res_cv);

	/*
	 * Wake all the threads chained in the set.
	 */

	for (tp = set->set_chain; tp; tp = tp->tp_chain)
		cv_broadcast(&tp->tp_cv);

	/* Wait for the threads to exit */

	while ((set->set_free.q_forw != &set->set_free) ||
	    (set->set_reuse.q_forw != &set->set_reuse))
		cv_wait(&set->set_kill_cv, &set->set_lock);

	/* Unchain and destroy all the threads in the set */

	tp = set->set_chain;
	set->set_chain = 0;

	while (tp) {
		ntp = tp->tp_chain;
		tp->tp_chain = 0;

		nst_thread_destroy(tp);

		tp = ntp;
	}

	mutex_exit(&set->set_lock);

	mutex_enter(&nst_global_lock);

	/* remove the set from the chain */

	for (spp = &nst_sets; *spp; spp = &((*spp)->set_next)) {
		if (*spp == set) {
			*spp = set->set_next;
			set->set_next = NULL;
			break;
		}
	}

	mutex_exit(&nst_global_lock);

	mutex_enter(&set->set_lock);

#ifdef DEBUG
	if (set->set_nthread != 0) {
		cmn_err(CE_WARN,
		    "nst_destroy(%p): nthread != 0 (%d)",
		    (void *)set, set->set_nthread);
	}
#endif

	/* Allow any waiters (above) to continue */

	cv_broadcast(&set->set_destroy_cv);

	while (set->set_destroy_cnt > 0 || set->set_pending > 0 ||
	    set->set_res_cnt > 0) {
		mutex_exit(&set->set_lock);
		delay(drv_usectohz((clock_t)NST_KILL_TIMEOUT));
		mutex_enter(&set->set_lock);
	}

	mutex_exit(&set->set_lock);

	if (set->set_nthread != 0) {
		/* leak the set control structure */

		DTRACE_PROBE1(nst_destroy_end,
				nstset_t *, set);

		return;
	}

	cv_destroy(&set->set_res_cv);
	cv_destroy(&set->set_kill_cv);
	cv_destroy(&set->set_destroy_cv);
	mutex_destroy(&set->set_lock);
	kmem_free(set, sizeof (*set));

}


/*
 * nst_add_thread
 *
 * Add more threads into an existing thread set.
 * Returns the number successfully added.
 */
int
nst_add_thread(nstset_t *set, int nthread)
{
	nsthread_t *tp;
	int i;

	if (!set || nthread < 1) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "nst_add_thread(%p, %d) - bad args", (void *)set, nthread);
#endif
		return (0);
	}

	for (i = 0; i < nthread; i++) {
		/* get new thread */

		if ((tp = nst_thread_create(set)) == NULL)
			break;

		/* add to free list */

		mutex_enter(&set->set_lock);
		nst_thread_free(tp);
		mutex_exit(&set->set_lock);
	}

	return (i);
}


/*
 * nst_del_thread
 *
 * Removes threads from an existing thread set.
 * Returns the number successfully removed.
 */
int
nst_del_thread(nstset_t *set, int nthread)
{
	nsthread_t **tpp, *tp;
	int i;

	if (!set || nthread < 1) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "nst_del_thread(%p, %d) - bad args", (void *)set, nthread);
#endif
		return (0);
	}

	for (i = 0; i < nthread; i++) {
		/* get thread */

		if (!(tp = nst_thread_alloc(set, FALSE)))
			break;

		mutex_enter(&set->set_lock);

		/* unlink from the set */

		for (tpp = &set->set_chain; *tpp; tpp = &(*tpp)->tp_chain) {
			if (*tpp == tp) {
				*tpp = tp->tp_chain;
				tp->tp_chain = NULL;
				break;
			}
		}

		/* kill the thread */

		tp->tp_flag |= NST_TF_KILL;
		tp->tp_flag &= ~NST_TF_INUSE;
		cv_broadcast(&tp->tp_cv);

		/* wait for thread to exit */

		while (tp->tp_flag & NST_TF_KILL)
			cv_wait(&set->set_kill_cv, &set->set_lock);

		set->set_nlive--;
		mutex_exit(&set->set_lock);

		/* free kernel resources */

		nst_thread_destroy(tp);
	}

	return (i);
}


/*
 * nst_init
 *
 * Initialise a new nsthread set, returning its address or
 * NULL in the event of failure. The set should be destroyed
 * by calling nst_destroy().
 */
nstset_t *
nst_init(char *name, int nthread)
{
	nstset_t *set, *sp;
	int len, i;

	if (nthread < 1) {
#ifdef DEBUG
		cmn_err(CE_WARN, "nst_init: invalid arg");
#endif
		return (NULL);
	}

	if (nthread > USHRT_MAX) {
#ifdef DEBUG
		cmn_err(CE_WARN, "nst_init: arg limit exceeded");
#endif
		return (NULL);
	}

	if (!(set = nst_kmem_zalloc(sizeof (*set), 2)))
		return (NULL);

	len = strlen(name);
	if (len >= sizeof (set->set_name))
		len = sizeof (set->set_name) - 1;

	bcopy(name, set->set_name, len);

	mutex_init(&set->set_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&set->set_destroy_cv, NULL, CV_DRIVER, NULL);
	cv_init(&set->set_kill_cv, NULL, CV_DRIVER, NULL);
	cv_init(&set->set_res_cv, NULL, CV_DRIVER, NULL);

	set->set_reuse.q_forw = set->set_reuse.q_back = &set->set_reuse;
	set->set_free.q_forw = set->set_free.q_back = &set->set_free;

	mutex_enter(&nst_global_lock);

	/* check for duplicates */

	for (sp = nst_sets; sp; sp = sp->set_next) {
		if (strcmp(sp->set_name, set->set_name) == 0) {
			/* duplicate */
			mutex_exit(&nst_global_lock);
			cv_destroy(&set->set_res_cv);
			cv_destroy(&set->set_kill_cv);
			cv_destroy(&set->set_destroy_cv);
			mutex_destroy(&set->set_lock);
			kmem_free(set, sizeof (*set));
#ifdef DEBUG
			cmn_err(CE_WARN,
				"nst_init: duplicate set \"%s\"", name);
#endif
			/* add threads if necessary */

			if (nthread > sp->set_nthread) {
			    i = nst_add_thread(sp, nthread - sp->set_nthread);
#ifdef DEBUG
			    if (i !=  (nthread - sp->set_nthread))
				cmn_err(CE_WARN,
					"nst_init: failed to allocate %d "
					"threads (got %d)",
					(nthread - sp->set_nthread), i);
#endif
			}

			/* return pointer to existing set */

			return (sp);
		}
	}

	/* add new set to chain */
	set->set_next = nst_sets;
	nst_sets = set;

	mutex_exit(&nst_global_lock);

	i = nst_add_thread(set, nthread);

	if (i != nthread) {
#ifdef DEBUG
		cmn_err(CE_WARN,
			"nst_init: failed to allocate %d threads (got %d)",
			nthread, i);
#endif
		nst_destroy(set);
		return (NULL);
	}

	return (set);
}


/*
 * nst_nlive
 *
 * Return the number of live threads in a set.
 */
int
nst_nlive(nstset_t *set)
{
	return (set ? set->set_nlive : 0);
}


/*
 * nst_nthread
 *
 * Return the number of threads in the set.
 */
int
nst_nthread(nstset_t *set)
{
	return (set ? set->set_nthread : 0);
}


/*
 * nst_shutdown
 *
 * Called by nskern to shutdown the nsthread software.
 */
void
nst_shutdown(void)
{
	nstset_t *set;

	mutex_enter(&nst_global_lock);

	while ((set = nst_sets) != NULL) {
		mutex_exit(&nst_global_lock);
		nst_destroy(set);
		mutex_enter(&nst_global_lock);
	}

	mutex_exit(&nst_global_lock);
	mutex_destroy(&nst_global_lock);
}


/*
 * nst_startup
 *
 * Called by nskern to initialise the nsthread software
 */
int
nst_startup(void)
{
	mutex_init(&nst_global_lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}
