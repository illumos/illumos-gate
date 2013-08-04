/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/cmn_err.h>
#include <sys/ddi_periodic.h>
#include <sys/id_space.h>
#include <sys/kobj.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/taskq.h>
#include <sys/taskq_impl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sdt.h>

extern void sir_on(int);

/*
 * The ddi_periodic_add(9F) Implementation
 *
 * This file contains the implementation of the ddi_periodic_add(9F) interface.
 * It is a thin wrapper around the cyclic subsystem (see documentation in
 * uts/common/os/cyclic.c), providing a DDI interface for registering
 * (and unregistering) callbacks for periodic invocation at arbitrary
 * interrupt levels, or in kernel context.
 *
 * Each call to ddi_periodic_add will result in a new opaque handle, as
 * allocated from an id_space, a new "periodic" object (ddi_periodic_impl_t)
 * and a registered cyclic.
 *
 * Operation
 *
 * Whenever the cyclic fires, our cyclic handler checks that the particular
 * periodic is not dispatched already (we do not support overlapping execution
 * of the consumer's handler function), and not yet cancelled.  If both of
 * these conditions hold, we mark the periodic as DPF_DISPATCHED and enqueue it
 * to either the taskq (for DDI_IPL_0) or to one of the soft interrupt queues
 * (DDI_IPL_1 to DDI_IPL_10).
 *
 * While the taskq (or soft interrupt handler) is handling a particular
 * periodic, we mark it as DPF_EXECUTING.  When complete, we reset both
 * DPF_DISPATCHED and DPF_EXECUTING.
 *
 * Cancellation
 *
 * ddi_periodic_delete(9F) historically had spectacularly loose semantics with
 * respect to cancellation concurrent with handler execution.  These semantics
 * are now tighter:
 *
 *   1. At most one invocation of ddi_periodic_delete(9F) will actually
 *      perform the deletion, all others will return immediately.
 *   2. The invocation that performs the deletion will _block_ until
 *      the handler is no longer running, and all resources have been
 *      released.
 *
 * We affect this model by removing the cancelling periodic from the
 * global list and marking it DPF_CANCELLED.  This will prevent further
 * execution of the handler.  We then wait on a CV until the DPF_EXECUTING
 * and DPF_DISPATCHED flags are clear, which means the periodic is removed
 * from all request queues, is no longer executing, and may be freed.  At this
 * point we return the opaque ID to the id_space and free the memory.
 *
 * NOTE:
 * The ddi_periodic_add(9F) interface is presently limited to a minimum period
 * of 10ms between firings.
 */

/*
 * Tuneables:
 */
int ddi_periodic_max_id = 1024;
int ddi_periodic_taskq_threadcount = 4;
hrtime_t ddi_periodic_resolution = 10000000;

/*
 * Globals:
 */
static kmem_cache_t *periodic_cache;
static id_space_t *periodic_id_space;
static taskq_t *periodic_taskq;

/*
 * periodics_lock protects the list of all periodics (periodics), and
 * each of the soft interrupt request queues (periodic_softint_queue).
 *
 * Do not hold an individual periodic's lock while obtaining periodics_lock.
 * While in the periodic_softint_queue list, the periodic will be marked
 * DPF_DISPATCHED, and thus safe from frees.  Only the invocation of
 * i_untimeout() that removes the periodic from the global list is allowed
 * to free it.
 */
static kmutex_t periodics_lock;
static list_t periodics;
static list_t periodic_softint_queue[10]; /* for IPL1 up to IPL10 */

typedef enum periodic_ipl {
	PERI_IPL_0 = 0,
	PERI_IPL_1,
	PERI_IPL_2,
	PERI_IPL_3,
	PERI_IPL_4,
	PERI_IPL_5,
	PERI_IPL_6,
	PERI_IPL_7,
	PERI_IPL_8,
	PERI_IPL_9,
	PERI_IPL_10
} periodic_ipl_t;

static char *
periodic_handler_symbol(ddi_periodic_impl_t *dpr)
{
	ulong_t off;

	return (kobj_getsymname((uintptr_t)dpr->dpr_handler, &off));
}

/*
 * This function may be called either from a soft interrupt handler
 * (ddi_periodic_softintr), or as a taskq worker function.
 */
static void
periodic_execute(void *arg)
{
	ddi_periodic_impl_t *dpr = arg;
	mutex_enter(&dpr->dpr_lock);

	/*
	 * We must be DISPATCHED, but not yet EXECUTING:
	 */
	VERIFY((dpr->dpr_flags & (DPF_DISPATCHED | DPF_EXECUTING)) ==
	    DPF_DISPATCHED);
	VERIFY(dpr->dpr_thread == NULL);

	if (!(dpr->dpr_flags & DPF_CANCELLED)) {
		int level = dpr->dpr_level;
		uint64_t count = dpr->dpr_fire_count;
		/*
		 * If we have not yet been cancelled, then
		 * mark us executing:
		 */
		dpr->dpr_flags |= DPF_EXECUTING;
		dpr->dpr_thread = curthread;
		mutex_exit(&dpr->dpr_lock);

		/*
		 * Execute the handler, without holding locks:
		 */
		DTRACE_PROBE4(ddi__periodic__execute, void *, dpr->dpr_handler,
		    void *, dpr->dpr_arg, int, level, uint64_t, count);
		(*dpr->dpr_handler)(dpr->dpr_arg);
		DTRACE_PROBE4(ddi__periodic__done, void *, dpr->dpr_handler,
		    void *, dpr->dpr_arg, int, level, uint64_t, count);

		mutex_enter(&dpr->dpr_lock);
		dpr->dpr_thread = NULL;
		dpr->dpr_fire_count++;
	}

	/*
	 * We're done with this periodic for now, so release it and
	 * wake anybody that was waiting for us to be finished:
	 */
	dpr->dpr_flags &= ~(DPF_DISPATCHED | DPF_EXECUTING);
	cv_broadcast(&dpr->dpr_cv);
	mutex_exit(&dpr->dpr_lock);
}

void
ddi_periodic_softintr(int level)
{
	ddi_periodic_impl_t *dpr;
	VERIFY(level >= PERI_IPL_1 && level <= PERI_IPL_10);

	mutex_enter(&periodics_lock);
	/*
	 * Pull the first scheduled periodic off the queue for this priority
	 * level:
	 */
	while ((dpr = list_remove_head(&periodic_softint_queue[level - 1])) !=
	    NULL) {
		mutex_exit(&periodics_lock);
		/*
		 * And execute it:
		 */
		periodic_execute(dpr);
		mutex_enter(&periodics_lock);
	}
	mutex_exit(&periodics_lock);
}

void
ddi_periodic_init(void)
{
	int i;

	/*
	 * Create a kmem_cache for request tracking objects, and a list
	 * to store them in so we can later delete based on opaque handles:
	 */
	periodic_cache = kmem_cache_create("ddi_periodic",
	    sizeof (ddi_periodic_impl_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	list_create(&periodics, sizeof (ddi_periodic_impl_t),
	    offsetof(ddi_periodic_impl_t, dpr_link));

	/*
	 * Initialise the identifier space for ddi_periodic_add(9F):
	 */
	periodic_id_space = id_space_create("ddi_periodic", 1,
	    ddi_periodic_max_id);

	/*
	 * Initialise the request queue for each soft interrupt level:
	 */
	for (i = PERI_IPL_1; i <= PERI_IPL_10; i++) {
		list_create(&periodic_softint_queue[i - 1],
		    sizeof (ddi_periodic_impl_t), offsetof(ddi_periodic_impl_t,
		    dpr_softint_link));
	}

	/*
	 * Create the taskq for running PERI_IPL_0 handlers.  This taskq will
	 * _only_ be used with taskq_dispatch_ent(), and a taskq_ent_t
	 * pre-allocated with the ddi_periodic_impl_t.
	 */
	periodic_taskq = taskq_create_instance("ddi_periodic_taskq", -1,
	    ddi_periodic_taskq_threadcount, maxclsyspri, 0, 0, 0);

	/*
	 * Initialize the mutex lock used for the soft interrupt request
	 * queues.
	 */
	mutex_init(&periodics_lock, NULL, MUTEX_ADAPTIVE, NULL);
}

void
ddi_periodic_fini(void)
{
	int i;
	ddi_periodic_impl_t *dpr;

	/*
	 * Find all periodics that have not yet been unregistered and,
	 * on DEBUG bits, print a warning about this resource leak.
	 */
	mutex_enter(&periodics_lock);
	while ((dpr = list_head(&periodics)) != NULL) {
#ifdef	DEBUG
		printf("DDI periodic handler not deleted (id=%lx, hdlr=%s)\n",
		    (unsigned long)dpr->dpr_id, periodic_handler_symbol(dpr));
#endif

		mutex_exit(&periodics_lock);
		/*
		 * Delete the periodic ourselves:
		 */
		i_untimeout((timeout_t)(uintptr_t)dpr->dpr_id);
		mutex_enter(&periodics_lock);
	}
	mutex_exit(&periodics_lock);

	/*
	 * At this point there are no remaining cyclics, so clean up the
	 * remaining resources:
	 */
	taskq_destroy(periodic_taskq);
	periodic_taskq = NULL;

	id_space_destroy(periodic_id_space);
	periodic_id_space = NULL;

	kmem_cache_destroy(periodic_cache);
	periodic_cache = NULL;

	list_destroy(&periodics);
	for (i = PERI_IPL_1; i <= PERI_IPL_10; i++)
		list_destroy(&periodic_softint_queue[i - 1]);

	mutex_destroy(&periodics_lock);
}

static void
periodic_cyclic_handler(void *arg)
{
	ddi_periodic_impl_t *dpr = arg;

	mutex_enter(&dpr->dpr_lock);
	/*
	 * If we've been cancelled, or we're already dispatched, then exit
	 * immediately:
	 */
	if (dpr->dpr_flags & (DPF_CANCELLED | DPF_DISPATCHED)) {
		mutex_exit(&dpr->dpr_lock);
		return;
	}
	VERIFY(!(dpr->dpr_flags & DPF_EXECUTING));

	/*
	 * This periodic is not presently dispatched, so dispatch it now:
	 */
	dpr->dpr_flags |= DPF_DISPATCHED;
	mutex_exit(&dpr->dpr_lock);

	if (dpr->dpr_level == PERI_IPL_0) {
		/*
		 * DDI_IPL_0 periodics are dispatched onto the taskq:
		 */
		taskq_dispatch_ent(periodic_taskq, periodic_execute,
		    dpr, 0, &dpr->dpr_taskq_ent);
	} else {
		/*
		 * Higher priority periodics are handled by a soft interrupt
		 * handler.  Enqueue us for processing by the handler:
		 */
		mutex_enter(&periodics_lock);
		list_insert_tail(&periodic_softint_queue[dpr->dpr_level - 1],
		    dpr);
		mutex_exit(&periodics_lock);

		/*
		 * Request the execution of the soft interrupt handler for this
		 * periodic's priority level.
		 */
		sir_on(dpr->dpr_level);
	}
}

static void
periodic_destroy(ddi_periodic_impl_t *dpr)
{
	if (dpr == NULL)
		return;

	/*
	 * By now, we should have a periodic that is not busy, and has been
	 * cancelled:
	 */
	VERIFY(dpr->dpr_flags == DPF_CANCELLED);
	VERIFY(dpr->dpr_thread == NULL);

	id_free(periodic_id_space, dpr->dpr_id);
	cv_destroy(&dpr->dpr_cv);
	mutex_destroy(&dpr->dpr_lock);
	kmem_cache_free(periodic_cache, dpr);
}

static ddi_periodic_impl_t *
periodic_create(void)
{
	ddi_periodic_impl_t *dpr;

	dpr = kmem_cache_alloc(periodic_cache, KM_SLEEP);
	bzero(dpr, sizeof (*dpr));
	dpr->dpr_id = id_alloc(periodic_id_space);
	mutex_init(&dpr->dpr_lock, NULL, MUTEX_ADAPTIVE, NULL);
	cv_init(&dpr->dpr_cv, NULL, CV_DEFAULT, NULL);

	return (dpr);
}

/*
 * This function provides the implementation for the ddi_periodic_add(9F)
 * interface.  It registers a periodic handler and returns an opaque identifier
 * that can be unregistered via ddi_periodic_delete(9F)/i_untimeout().
 *
 * It may be called in user or kernel context, provided cpu_lock is not held.
 */
timeout_t
i_timeout(void (*func)(void *), void *arg, hrtime_t interval, int level)
{
	cyc_handler_t cyh;
	cyc_time_t cyt;
	ddi_periodic_impl_t *dpr;

	VERIFY(func != NULL);
	VERIFY(level >= 0 && level <= 10);

	/*
	 * Allocate object to track this periodic:
	 */
	dpr = periodic_create();
	dpr->dpr_level = level;
	dpr->dpr_handler = func;
	dpr->dpr_arg = arg;

	/*
	 * The minimum supported interval between firings of the periodic
	 * handler is 10ms; see ddi_periodic_add(9F) for more details.  If a
	 * shorter interval is requested, round up.
	 */
	if (ddi_periodic_resolution > interval) {
		cmn_err(CE_WARN,
		    "The periodic timeout (handler=%s, interval=%lld) "
		    "requests a finer interval than the supported resolution. "
		    "It rounds up to %lld\n", periodic_handler_symbol(dpr),
		    interval, ddi_periodic_resolution);
		interval = ddi_periodic_resolution;
	}

	/*
	 * Ensure that the interval is an even multiple of the base resolution
	 * that is at least as long as the requested interval.
	 */
	dpr->dpr_interval = roundup(interval, ddi_periodic_resolution);

	/*
	 * Create the underlying cyclic:
	 */
	cyh.cyh_func = periodic_cyclic_handler;
	cyh.cyh_arg = dpr;
	cyh.cyh_level = CY_LOCK_LEVEL;

	cyt.cyt_when = 0;
	cyt.cyt_interval = dpr->dpr_interval;

	mutex_enter(&cpu_lock);
	dpr->dpr_cyclic_id = cyclic_add(&cyh, &cyt);
	mutex_exit(&cpu_lock);

	/*
	 * Make the id visible to ddi_periodic_delete(9F) before we
	 * return it:
	 */
	mutex_enter(&periodics_lock);
	list_insert_tail(&periodics, dpr);
	mutex_exit(&periodics_lock);

	return ((timeout_t)(uintptr_t)dpr->dpr_id);
}

/*
 * This function provides the implementation for the ddi_periodic_delete(9F)
 * interface.  It cancels a periodic handler previously registered through
 * ddi_periodic_add(9F)/i_timeout().
 *
 * It may be called in user or kernel context, provided cpu_lock is not held.
 * It may NOT be called from within a periodic handler.
 */
void
i_untimeout(timeout_t id)
{
	ddi_periodic_impl_t *dpr;

	/*
	 * Find the periodic in the list of all periodics and remove it.
	 * If we find in (and remove it from) the global list, we have
	 * license to free it once it is no longer busy.
	 */
	mutex_enter(&periodics_lock);
	for (dpr = list_head(&periodics); dpr != NULL; dpr =
	    list_next(&periodics, dpr)) {
		if (dpr->dpr_id == (id_t)(uintptr_t)id) {
			list_remove(&periodics, dpr);
			break;
		}
	}
	mutex_exit(&periodics_lock);

	/*
	 * We could not find a periodic for this id, so bail out:
	 */
	if (dpr == NULL)
		return;

	mutex_enter(&dpr->dpr_lock);
	/*
	 * We should be the only one trying to cancel this periodic:
	 */
	VERIFY(!(dpr->dpr_flags & DPF_CANCELLED));
	/*
	 * Removing a periodic from within its own handler function will
	 * cause a deadlock, so panic explicitly.
	 */
	if (dpr->dpr_thread == curthread) {
		panic("ddi_periodic_delete(%lx) called from its own handler\n",
		    (unsigned long)dpr->dpr_id);
	}
	/*
	 * Mark the periodic as cancelled:
	 */
	dpr->dpr_flags |= DPF_CANCELLED;
	mutex_exit(&dpr->dpr_lock);

	/*
	 * Cancel our cyclic.  cyclic_remove() guarantees that the cyclic
	 * handler will not run again after it returns.  Note that the cyclic
	 * handler merely _dispatches_ the periodic, so this does _not_ mean
	 * the periodic handler is also finished running.
	 */
	mutex_enter(&cpu_lock);
	cyclic_remove(dpr->dpr_cyclic_id);
	mutex_exit(&cpu_lock);

	/*
	 * Wait until the periodic handler is no longer running:
	 */
	mutex_enter(&dpr->dpr_lock);
	while (dpr->dpr_flags & (DPF_DISPATCHED | DPF_EXECUTING)) {
		cv_wait(&dpr->dpr_cv, &dpr->dpr_lock);
	}
	mutex_exit(&dpr->dpr_lock);

	periodic_destroy(dpr);
}
