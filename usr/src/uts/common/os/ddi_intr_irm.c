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

#include <sys/note.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>	/* include prototypes */

/*
 * Interrupt Resource Management (IRM).
 */

#define	DDI_IRM_BALANCE_DELAY	(60)	/* In seconds */

#define	DDI_IRM_HAS_CB(c)	((c) && (c->cb_flags & DDI_CB_FLAG_INTR))

#define	DDI_IRM_IS_REDUCIBLE(r)	(((r->ireq_flags & DDI_IRM_FLAG_CALLBACK) && \
				(r->ireq_type == DDI_INTR_TYPE_MSIX)) || \
				(r->ireq_flags & DDI_IRM_FLAG_NEW))

extern pri_t	minclsyspri;

/* Global policies */
int		irm_enable = 1;
boolean_t	irm_active = B_FALSE;
int		irm_default_policy = DDI_IRM_POLICY_LARGE;
uint_t		irm_balance_delay = DDI_IRM_BALANCE_DELAY;

/* Global list of interrupt pools */
kmutex_t	irm_pools_lock;
list_t		irm_pools_list;

/* Global debug tunables */
#ifdef	DEBUG
int		irm_debug_policy = 0;
uint_t		irm_debug_size = 0;
#endif	/* DEBUG */

static void	irm_balance_thread(ddi_irm_pool_t *);
static void	i_ddi_irm_balance(ddi_irm_pool_t *);
static void	i_ddi_irm_enqueue(ddi_irm_pool_t *, boolean_t);
static void	i_ddi_irm_reduce(ddi_irm_pool_t *pool);
static int	i_ddi_irm_reduce_large(ddi_irm_pool_t *, int);
static void	i_ddi_irm_reduce_large_resort(ddi_irm_pool_t *);
static int	i_ddi_irm_reduce_even(ddi_irm_pool_t *, int);
static void	i_ddi_irm_reduce_new(ddi_irm_pool_t *, int);
static void	i_ddi_irm_insertion_sort(list_t *, ddi_irm_req_t *);
static int	i_ddi_irm_notify(ddi_irm_pool_t *, ddi_irm_req_t *);

/*
 * OS Initialization Routines
 */

/*
 * irm_init()
 *
 *	Initialize IRM subsystem before any drivers are attached.
 */
void
irm_init(void)
{
	/* Do nothing if IRM is disabled */
	if (!irm_enable)
		return;

	/* Verify that the default balancing policy is valid */
	if (!DDI_IRM_POLICY_VALID(irm_default_policy))
		irm_default_policy = DDI_IRM_POLICY_LARGE;

	/* Initialize the global list of interrupt pools */
	mutex_init(&irm_pools_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&irm_pools_list, sizeof (ddi_irm_pool_t),
	    offsetof(ddi_irm_pool_t, ipool_link));
}

/*
 * i_ddi_irm_poststartup()
 *
 *	IRM is not activated until after the IO subsystem is initialized.
 *	When activated, per-pool balancing threads are spawned and a flag
 *	is set so that all future pools will be activated when created.
 *
 *	NOTE: the global variable 'irm_enable' disables IRM if zero.
 */
void
i_ddi_irm_poststartup(void)
{
	ddi_irm_pool_t	*pool_p;

	/* Do nothing if IRM is disabled */
	if (!irm_enable)
		return;

	/* Lock the global list */
	mutex_enter(&irm_pools_lock);

	/* Activate all defined pools */
	for (pool_p = list_head(&irm_pools_list); pool_p;
	    pool_p = list_next(&irm_pools_list, pool_p))
		pool_p->ipool_thread = thread_create(NULL, 0,
		    irm_balance_thread, pool_p, 0, &p0, TS_RUN, minclsyspri);

	/* Set future pools to be active */
	irm_active = B_TRUE;

	/* Unlock the global list */
	mutex_exit(&irm_pools_lock);
}

/*
 * NDI interfaces for creating/destroying IRM pools.
 */

/*
 * ndi_irm_create()
 *
 *	Nexus interface to create an IRM pool.  Create the new
 *	pool and add it to the global list of interrupt pools.
 */
int
ndi_irm_create(dev_info_t *dip, ddi_irm_params_t *paramsp,
    ddi_irm_pool_t **pool_retp)
{
	ddi_irm_pool_t	*pool_p;

	ASSERT(dip != NULL);
	ASSERT(paramsp != NULL);
	ASSERT(pool_retp != NULL);
	ASSERT(paramsp->iparams_total >= 1);
	ASSERT(paramsp->iparams_types != 0);
	ASSERT(paramsp->iparams_default >= 1);

	DDI_INTR_IRMDBG((CE_CONT, "ndi_irm_create: dip %p\n", (void *)dip));

	/* Check if IRM is enabled */
	if (!irm_enable)
		return (NDI_FAILURE);

	/* Validate parameters */
	if ((dip == NULL) || (paramsp == NULL) || (pool_retp == NULL) ||
	    (paramsp->iparams_total < 1) || (paramsp->iparams_types == 0) ||
	    (paramsp->iparams_default < 1))
		return (NDI_FAILURE);

	/* Allocate and initialize the pool */
	pool_p = kmem_zalloc(sizeof (ddi_irm_pool_t), KM_SLEEP);
	pool_p->ipool_owner = dip;
	pool_p->ipool_policy = irm_default_policy;
	pool_p->ipool_types = paramsp->iparams_types;
	pool_p->ipool_totsz = paramsp->iparams_total;
	pool_p->ipool_defsz = paramsp->iparams_default;
	list_create(&pool_p->ipool_req_list, sizeof (ddi_irm_req_t),
	    offsetof(ddi_irm_req_t, ireq_link));
	list_create(&pool_p->ipool_scratch_list, sizeof (ddi_irm_req_t),
	    offsetof(ddi_irm_req_t, ireq_scratch_link));
	cv_init(&pool_p->ipool_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&pool_p->ipool_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pool_p->ipool_navail_lock, NULL, MUTEX_DRIVER, NULL);

	/* Add to global list of pools */
	mutex_enter(&irm_pools_lock);
	list_insert_tail(&irm_pools_list, pool_p);
	mutex_exit(&irm_pools_lock);

	/* If IRM is active, then activate the pool */
	if (irm_active)
		pool_p->ipool_thread = thread_create(NULL, 0,
		    irm_balance_thread, pool_p, 0, &p0, TS_RUN, minclsyspri);

	*pool_retp = pool_p;
	return (NDI_SUCCESS);
}

/*
 * ndi_irm_destroy()
 *
 *	Nexus interface to destroy an IRM pool.  Destroy the pool
 *	and remove it from the global list of interrupt pools.
 */
int
ndi_irm_destroy(ddi_irm_pool_t *pool_p)
{
	ASSERT(pool_p != NULL);
	ASSERT(pool_p->ipool_resno == 0);

	DDI_INTR_IRMDBG((CE_CONT, "ndi_irm_destroy: pool_p %p\n",
	    (void *)pool_p));

	/* Validate parameters */
	if (pool_p == NULL)
		return (NDI_FAILURE);

	/* Validate that pool is empty */
	if (pool_p->ipool_resno != 0)
		return (NDI_BUSY);

	/* Remove the pool from the global list */
	mutex_enter(&irm_pools_lock);
	list_remove(&irm_pools_list, pool_p);
	mutex_exit(&irm_pools_lock);

	/* Terminate the balancing thread */
	mutex_enter(&pool_p->ipool_lock);
	if (pool_p->ipool_thread &&
	    (pool_p->ipool_flags & DDI_IRM_FLAG_ACTIVE)) {
		pool_p->ipool_flags |= DDI_IRM_FLAG_EXIT;
		cv_signal(&pool_p->ipool_cv);
		mutex_exit(&pool_p->ipool_lock);
		thread_join(pool_p->ipool_thread->t_did);
	} else
		mutex_exit(&pool_p->ipool_lock);

	/* Destroy the pool */
	cv_destroy(&pool_p->ipool_cv);
	mutex_destroy(&pool_p->ipool_lock);
	mutex_destroy(&pool_p->ipool_navail_lock);
	list_destroy(&pool_p->ipool_req_list);
	list_destroy(&pool_p->ipool_scratch_list);
	kmem_free(pool_p, sizeof (ddi_irm_pool_t));

	return (NDI_SUCCESS);
}

/*
 * Insert/Modify/Remove Interrupt Requests
 */

/*
 * i_ddi_irm_insert()
 *
 *	Insert a new request into an interrupt pool, and balance the pool.
 */
int
i_ddi_irm_insert(dev_info_t *dip, int type, int count)
{
	ddi_cb_t	*cb_p;
	ddi_irm_req_t	*req_p;
	devinfo_intr_t	*intr_p;
	ddi_irm_pool_t	*pool_p;
	uint_t		nreq, nmin, npartial;
	boolean_t	irm_flag = B_FALSE;

	ASSERT(dip != NULL);
	ASSERT(DDI_INTR_TYPE_FLAG_VALID(type));
	ASSERT(count > 0);

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_insert: dip %p type %d count %d\n",
	    (void *)dip, type, count));

	/* Validate parameters */
	if ((dip == NULL) || (count < 1) || !DDI_INTR_TYPE_FLAG_VALID(type)) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_insert: invalid args\n"));
		return (DDI_EINVAL);
	}

	/* Check for an existing request */
	if (((intr_p = DEVI(dip)->devi_intr_p) != NULL) &&
	    (intr_p->devi_irm_req_p != NULL))
		return (DDI_SUCCESS);

	/* Check for IRM support from the system */
	if ((pool_p = i_ddi_intr_get_pool(dip, type)) == NULL) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_insert: not supported\n"));
		return (DDI_ENOTSUP);
	}

	/* Check for IRM support from the driver */
	if (((cb_p = DEVI(dip)->devi_cb_p) != NULL) && DDI_IRM_HAS_CB(cb_p) &&
	    (type == DDI_INTR_TYPE_MSIX))
		irm_flag = B_TRUE;

	/* Determine request size */
	nreq = (irm_flag) ? count : i_ddi_intr_get_current_navail(dip, type);
	nmin = (irm_flag) ? 1 : nreq;
	npartial = MIN(nreq, pool_p->ipool_defsz);

	/* Allocate and initialize the request */
	req_p = kmem_zalloc(sizeof (ddi_irm_req_t), KM_SLEEP);
	req_p->ireq_type = type;
	req_p->ireq_dip = dip;
	req_p->ireq_pool_p = pool_p;
	req_p->ireq_nreq = nreq;
	req_p->ireq_flags = DDI_IRM_FLAG_NEW;
	if (DDI_IRM_HAS_CB(cb_p))
		req_p->ireq_flags |= DDI_IRM_FLAG_CALLBACK;

	/* Lock the pool */
	mutex_enter(&pool_p->ipool_lock);

	/* Check for minimal fit before inserting */
	if ((pool_p->ipool_minno + nmin) > pool_p->ipool_totsz) {
		cmn_err(CE_WARN, "%s%d: interrupt pool too full.\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		mutex_exit(&pool_p->ipool_lock);
		kmem_free(req_p, sizeof (ddi_irm_req_t));
		return (DDI_EAGAIN);
	}

	/* Insert the request into the pool */
	pool_p->ipool_reqno += nreq;
	pool_p->ipool_minno += nmin;
	i_ddi_irm_insertion_sort(&pool_p->ipool_req_list, req_p);

	/*
	 * Try to fulfill the request.
	 *
	 * If all the interrupts are available, and either the request
	 * is static or the pool is active, then just take them directly.
	 *
	 * If only some of the interrupts are available, and the request
	 * can receive future callbacks, then take some now but queue the
	 * pool to be rebalanced later.
	 *
	 * Otherwise, immediately rebalance the pool and wait.
	 */
	if ((!irm_flag || (pool_p->ipool_flags & DDI_IRM_FLAG_ACTIVE)) &&
	    ((pool_p->ipool_resno + nreq) <= pool_p->ipool_totsz)) {

		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_insert: "
		    "request completely fulfilled.\n"));
		pool_p->ipool_resno += nreq;
		req_p->ireq_navail = nreq;
		req_p->ireq_flags &= ~(DDI_IRM_FLAG_NEW);

	} else if (irm_flag &&
	    ((pool_p->ipool_resno + npartial) <= pool_p->ipool_totsz)) {

		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_insert: "
		    "request partially fulfilled.\n"));
		pool_p->ipool_resno += npartial;
		req_p->ireq_navail = npartial;
		req_p->ireq_flags &= ~(DDI_IRM_FLAG_NEW);
		i_ddi_irm_enqueue(pool_p, B_FALSE);

	} else {

		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_insert: "
		    "request needs immediate rebalance.\n"));
		i_ddi_irm_enqueue(pool_p, B_TRUE);
		req_p->ireq_flags &= ~(DDI_IRM_FLAG_NEW);
	}

	/* Fail if the request cannot be fulfilled at all */
	if (req_p->ireq_navail == 0) {
		cmn_err(CE_WARN, "%s%d: interrupt pool too full.\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		mutex_exit(&pool_p->ipool_lock);
		pool_p->ipool_reqno -= nreq;
		pool_p->ipool_minno -= nmin;
		list_remove(&pool_p->ipool_req_list, req_p);
		kmem_free(req_p, sizeof (ddi_irm_req_t));
		return (DDI_EAGAIN);
	}

	/* Unlock the pool */
	mutex_exit(&pool_p->ipool_lock);

	intr_p->devi_irm_req_p = req_p;
	return (DDI_SUCCESS);
}

/*
 * i_ddi_irm_modify()
 *
 *	Modify an existing request in an interrupt pool, and balance the pool.
 */
int
i_ddi_irm_modify(dev_info_t *dip, int nreq)
{
	devinfo_intr_t	*intr_p;
	ddi_irm_req_t	*req_p;
	ddi_irm_pool_t	*pool_p;

	ASSERT(dip != NULL);

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_modify: dip %p nreq %d\n",
	    (void *)dip, nreq));

	/* Validate parameters */
	if ((dip == NULL) || (nreq < 1)) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_modify: invalid args\n"));
		return (DDI_EINVAL);
	}

	/* Check that the operation is supported */
	if (!(intr_p = DEVI(dip)->devi_intr_p) ||
	    !(req_p = intr_p->devi_irm_req_p) ||
	    !DDI_IRM_IS_REDUCIBLE(req_p)) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_modify: not supported\n"));
		return (DDI_ENOTSUP);
	}

	/* Validate request size is not too large */
	if (nreq > intr_p->devi_intr_sup_nintrs) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_modify: invalid args\n"));
		return (DDI_EINVAL);
	}

	/*
	 * Modify request, but only if new size is different.
	 */
	if (nreq != req_p->ireq_nreq) {

		/* Lock the pool */
		pool_p = req_p->ireq_pool_p;
		mutex_enter(&pool_p->ipool_lock);

		/* Update pool and request */
		pool_p->ipool_reqno -= req_p->ireq_nreq;
		pool_p->ipool_reqno += nreq;
		req_p->ireq_nreq = nreq;

		/* Re-sort request in the pool */
		list_remove(&pool_p->ipool_req_list, req_p);
		i_ddi_irm_insertion_sort(&pool_p->ipool_req_list, req_p);

		/* Queue pool to be rebalanced */
		i_ddi_irm_enqueue(pool_p, B_FALSE);

		/* Unlock the pool */
		mutex_exit(&pool_p->ipool_lock);
	}

	return (DDI_SUCCESS);
}

/*
 * i_ddi_irm_remove()
 *
 *	Remove a request from an interrupt pool, and balance the pool.
 */
int
i_ddi_irm_remove(dev_info_t *dip)
{
	devinfo_intr_t	*intr_p;
	ddi_irm_pool_t	*pool_p;
	ddi_irm_req_t	*req_p;
	uint_t		nmin;

	ASSERT(dip != NULL);

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_remove: dip %p\n", (void *)dip));

	/* Validate parameters */
	if (dip == NULL) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_remove: invalid args\n"));
		return (DDI_EINVAL);
	}

	/* Check if the device has a request */
	if (!(intr_p = DEVI(dip)->devi_intr_p) ||
	    !(req_p = intr_p->devi_irm_req_p)) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_modify: not found\n"));
		return (DDI_EINVAL);
	}

	/* Lock the pool */
	pool_p = req_p->ireq_pool_p;
	mutex_enter(&pool_p->ipool_lock);

	/* Remove request */
	nmin = DDI_IRM_IS_REDUCIBLE(req_p) ? 1 : req_p->ireq_nreq;
	pool_p->ipool_minno -= nmin;
	pool_p->ipool_reqno -= req_p->ireq_nreq;
	pool_p->ipool_resno -= req_p->ireq_navail;
	list_remove(&pool_p->ipool_req_list, req_p);

	/* Queue pool to be rebalanced */
	i_ddi_irm_enqueue(pool_p, B_FALSE);

	/* Unlock the pool */
	mutex_exit(&pool_p->ipool_lock);

	/* Destroy the request */
	intr_p->devi_irm_req_p = NULL;
	kmem_free(req_p, sizeof (ddi_irm_req_t));

	return (DDI_SUCCESS);
}

/*
 * i_ddi_irm_set_cb()
 *
 *	Change the callback flag for a request, in response to
 *	a change in its callback registration.  Then rebalance
 *	the interrupt pool.
 *
 *	NOTE: the request is not locked because the navail value
 *	      is not directly affected.  The balancing thread may
 *	      modify the navail value in the background after it
 *	      locks the request itself.
 */
void
i_ddi_irm_set_cb(dev_info_t *dip, boolean_t has_cb_flag)
{
	devinfo_intr_t	*intr_p;
	ddi_irm_pool_t	*pool_p;
	ddi_irm_req_t	*req_p;
	uint_t		nreq;

	ASSERT(dip != NULL);

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_set_cb: dip %p has_cb_flag %d\n",
	    (void *)dip, (int)has_cb_flag));

	/* Validate parameters */
	if (dip == NULL)
		return;

	/* Check for association with interrupt pool */
	if (!(intr_p = DEVI(dip)->devi_intr_p) ||
	    !(req_p = intr_p->devi_irm_req_p)) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_set_cb: not in pool\n"));
		return;
	}

	/* Lock the pool */
	pool_p = req_p->ireq_pool_p;
	mutex_enter(&pool_p->ipool_lock);

	/*
	 * Update the request and the pool
	 */
	if (has_cb_flag) {

		/* Update pool statistics */
		if (req_p->ireq_type == DDI_INTR_TYPE_MSIX)
			pool_p->ipool_minno -= (req_p->ireq_nreq - 1);

		/* Update request */
		req_p->ireq_flags |= DDI_IRM_FLAG_CALLBACK;

		/* Rebalance in background */
		i_ddi_irm_enqueue(pool_p, B_FALSE);

	} else {

		/* Determine new request size */
		nreq = MIN(req_p->ireq_nreq, pool_p->ipool_defsz);

		/* Update pool statistics */
		pool_p->ipool_reqno -= req_p->ireq_nreq;
		pool_p->ipool_reqno += nreq;
		if (req_p->ireq_type == DDI_INTR_TYPE_MSIX) {
			pool_p->ipool_minno -= 1;
			pool_p->ipool_minno += nreq;
		} else {
			pool_p->ipool_minno -= req_p->ireq_nreq;
			pool_p->ipool_minno += nreq;
		}

		/* Update request size, and re-sort in pool */
		req_p->ireq_nreq = nreq;
		list_remove(&pool_p->ipool_req_list, req_p);
		i_ddi_irm_insertion_sort(&pool_p->ipool_req_list, req_p);

		/* Rebalance synchronously, before losing callback */
		i_ddi_irm_enqueue(pool_p, B_TRUE);

		/* Remove callback flag */
		req_p->ireq_flags &= ~(DDI_IRM_FLAG_CALLBACK);
	}

	/* Unlock the pool */
	mutex_exit(&pool_p->ipool_lock);
}

/*
 * Interrupt Pool Balancing
 */

/*
 * irm_balance_thread()
 *
 *	One instance of this thread operates per each defined IRM pool.
 *	It does the initial activation of the pool, as well as balancing
 *	any requests that were queued up before the pool was active.
 *	Once active, it waits forever to service balance operations.
 */
static void
irm_balance_thread(ddi_irm_pool_t *pool_p)
{
	clock_t		interval, wakeup;

	DDI_INTR_IRMDBG((CE_CONT, "irm_balance_thread: pool_p %p\n",
	    (void *)pool_p));

	/* Lock the pool */
	mutex_enter(&pool_p->ipool_lock);

	/* Perform initial balance if required */
	if (pool_p->ipool_reqno > pool_p->ipool_resno)
		i_ddi_irm_balance(pool_p);

	/* Activate the pool */
	pool_p->ipool_flags |= DDI_IRM_FLAG_ACTIVE;

	/* Main loop */
	for (;;) {

		/* Compute the delay interval */
		interval = drv_usectohz(irm_balance_delay * 1000000);

		/* Sleep until queued */
		cv_wait(&pool_p->ipool_cv, &pool_p->ipool_lock);

		DDI_INTR_IRMDBG((CE_CONT, "irm_balance_thread: signaled.\n"));

		/* Wait one interval, or until there are waiters */
		if ((interval > 0) &&
		    !(pool_p->ipool_flags & DDI_IRM_FLAG_WAITERS) &&
		    !(pool_p->ipool_flags & DDI_IRM_FLAG_EXIT)) {
			wakeup = ddi_get_lbolt() + interval;
			(void) cv_timedwait(&pool_p->ipool_cv,
			    &pool_p->ipool_lock, wakeup);
		}

		/* Check if awakened to exit */
		if (pool_p->ipool_flags & DDI_IRM_FLAG_EXIT) {
			DDI_INTR_IRMDBG((CE_CONT,
			    "irm_balance_thread: exiting...\n"));
			mutex_exit(&pool_p->ipool_lock);
			thread_exit();
		}

		/* Balance the pool */
		i_ddi_irm_balance(pool_p);

		/* Notify waiters */
		if (pool_p->ipool_flags & DDI_IRM_FLAG_WAITERS) {
			cv_broadcast(&pool_p->ipool_cv);
			pool_p->ipool_flags &= ~(DDI_IRM_FLAG_WAITERS);
		}

		/* Clear QUEUED condition */
		pool_p->ipool_flags &= ~(DDI_IRM_FLAG_QUEUED);
	}
}

/*
 * i_ddi_irm_balance()
 *
 *	Balance a pool.  The general algorithm is to first reset all
 *	requests to their maximum size, use reduction algorithms to
 *	solve any imbalance, and then notify affected drivers.
 */
static void
i_ddi_irm_balance(ddi_irm_pool_t *pool_p)
{
	ddi_irm_req_t	*req_p;

#ifdef	DEBUG
	uint_t		debug_totsz = 0;
	int		debug_policy = 0;
#endif	/* DEBUG */

	ASSERT(pool_p != NULL);
	ASSERT(MUTEX_HELD(&pool_p->ipool_lock));

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_balance: pool_p %p\n",
	    (void *)pool_p));

#ifdef	DEBUG	/* Adjust size and policy settings */
	if (irm_debug_size > pool_p->ipool_minno) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_balance: debug size %d\n",
		    irm_debug_size));
		debug_totsz = pool_p->ipool_totsz;
		pool_p->ipool_totsz = irm_debug_size;
	}
	if (DDI_IRM_POLICY_VALID(irm_debug_policy)) {
		DDI_INTR_IRMDBG((CE_CONT,
		    "i_ddi_irm_balance: debug policy %d\n", irm_debug_policy));
		debug_policy = pool_p->ipool_policy;
		pool_p->ipool_policy = irm_debug_policy;
	}
#endif	/* DEBUG */

	/* Lock the availability lock */
	mutex_enter(&pool_p->ipool_navail_lock);

	/*
	 * Put all of the reducible requests into a scratch list.
	 * Reset each one of them to their maximum availability.
	 */
	for (req_p = list_head(&pool_p->ipool_req_list); req_p;
	    req_p = list_next(&pool_p->ipool_req_list, req_p)) {
		if (DDI_IRM_IS_REDUCIBLE(req_p)) {
			pool_p->ipool_resno -= req_p->ireq_navail;
			req_p->ireq_scratch = req_p->ireq_navail;
			req_p->ireq_navail = req_p->ireq_nreq;
			pool_p->ipool_resno += req_p->ireq_navail;
			list_insert_tail(&pool_p->ipool_scratch_list, req_p);
		}
	}

	/* Balance the requests */
	i_ddi_irm_reduce(pool_p);

	/* Unlock the availability lock */
	mutex_exit(&pool_p->ipool_navail_lock);

	/*
	 * Process REMOVE notifications.
	 *
	 * If a driver fails to release interrupts: exclude it from
	 * further processing, correct the resulting imbalance, and
	 * start over again at the head of the scratch list.
	 */
	req_p = list_head(&pool_p->ipool_scratch_list);
	while (req_p) {
		if ((req_p->ireq_navail < req_p->ireq_scratch) &&
		    (i_ddi_irm_notify(pool_p, req_p) != DDI_SUCCESS)) {
			list_remove(&pool_p->ipool_scratch_list, req_p);
			mutex_enter(&pool_p->ipool_navail_lock);
			i_ddi_irm_reduce(pool_p);
			mutex_exit(&pool_p->ipool_navail_lock);
			req_p = list_head(&pool_p->ipool_scratch_list);
		} else {
			req_p = list_next(&pool_p->ipool_scratch_list, req_p);
		}
	}

	/*
	 * Process ADD notifications.
	 *
	 * This is the last use of the scratch list, so empty it.
	 */
	while (req_p = list_remove_head(&pool_p->ipool_scratch_list)) {
		if (req_p->ireq_navail > req_p->ireq_scratch) {
			(void) i_ddi_irm_notify(pool_p, req_p);
		}
	}

#ifdef	DEBUG	/* Restore size and policy settings */
	if (debug_totsz != 0)
		pool_p->ipool_totsz = debug_totsz;
	if (debug_policy != 0)
		pool_p->ipool_policy = debug_policy;
#endif	/* DEBUG */
}

/*
 * i_ddi_irm_reduce()
 *
 *	Use reduction algorithms to correct an imbalance in a pool.
 */
static void
i_ddi_irm_reduce(ddi_irm_pool_t *pool_p)
{
	int	ret, imbalance;

	ASSERT(pool_p != NULL);
	ASSERT(MUTEX_HELD(&pool_p->ipool_lock));
	ASSERT(DDI_IRM_POLICY_VALID(pool_p->ipool_policy));

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_reduce: pool_p %p\n",
	    (void *)pool_p));

	/* Compute the imbalance.  Do nothing if already balanced. */
	if ((imbalance = pool_p->ipool_resno - pool_p->ipool_totsz) <= 0)
		return;

	/* Reduce by policy */
	switch (pool_p->ipool_policy) {
	case DDI_IRM_POLICY_LARGE:
		ret = i_ddi_irm_reduce_large(pool_p, imbalance);
		break;
	case DDI_IRM_POLICY_EVEN:
		ret = i_ddi_irm_reduce_even(pool_p, imbalance);
		break;
	}

	/*
	 * If the policy based reductions failed, then
	 * possibly reduce new requests as a last resort.
	 */
	if (ret != DDI_SUCCESS) {

		DDI_INTR_IRMDBG((CE_CONT,
		    "i_ddi_irm_reduce: policy reductions failed.\n"));

		/* Compute remaining imbalance */
		imbalance = pool_p->ipool_resno - pool_p->ipool_totsz;

		ASSERT(imbalance > 0);

		i_ddi_irm_reduce_new(pool_p, imbalance);
	}
}

/*
 * i_ddi_irm_enqueue()
 *
 *	Queue a pool to be balanced.  Signals the balancing thread to wake
 *	up and process the pool.  If 'wait_flag' is true, then the current
 *	thread becomes a waiter and blocks until the balance is completed.
 */
static void
i_ddi_irm_enqueue(ddi_irm_pool_t *pool_p, boolean_t wait_flag)
{
	ASSERT(pool_p != NULL);
	ASSERT(MUTEX_HELD(&pool_p->ipool_lock));

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_enqueue: pool_p %p wait_flag %d\n",
	    (void *)pool_p, (int)wait_flag));

	/* Do nothing if pool is already balanced */
#ifndef	DEBUG
	if ((pool_p->ipool_reqno == pool_p->ipool_resno)) {
#else
	if ((pool_p->ipool_reqno == pool_p->ipool_resno) && !irm_debug_size) {
#endif	/* DEBUG */
		DDI_INTR_IRMDBG((CE_CONT,
		    "i_ddi_irm_enqueue: pool already balanced\n"));
		return;
	}

	/* Avoid deadlocks when IRM is not active */
	if (!irm_active && wait_flag) {
		DDI_INTR_IRMDBG((CE_CONT,
		    "i_ddi_irm_enqueue: pool not active.\n"));
		return;
	}

	if (wait_flag)
		pool_p->ipool_flags |= DDI_IRM_FLAG_WAITERS;

	if (wait_flag || !(pool_p->ipool_flags & DDI_IRM_FLAG_QUEUED)) {
		pool_p->ipool_flags |= DDI_IRM_FLAG_QUEUED;
		cv_signal(&pool_p->ipool_cv);
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_enqueue: pool queued.\n"));
	}

	if (wait_flag) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_enqueue: waiting...\n"));
		cv_wait(&pool_p->ipool_cv, &pool_p->ipool_lock);
	}
}

/*
 * Reduction Algorithms, Used For Balancing
 */

/*
 * i_ddi_irm_reduce_large()
 *
 *	Algorithm for the DDI_IRM_POLICY_LARGE reduction policy.
 *
 *	This algorithm generally reduces larger requests first, before
 *	advancing to smaller requests.  The scratch list is initially
 *	sorted in descending order by current navail values, which are
 *	maximized prior to reduction.  This sorted order is preserved,
 *	but within a range of equally sized requests they are secondarily
 *	sorted in ascending order by initial nreq value.  The head of the
 *	list is always selected for reduction, since it is the current
 *	largest request.  After being reduced, it is sorted further into
 *	the list before the next iteration.
 *
 *	Optimizations in this algorithm include trying to reduce multiple
 *	requests together if they are equally sized.  And the algorithm
 *	attempts to reduce in larger increments when possible to minimize
 *	the total number of iterations.
 */
static int
i_ddi_irm_reduce_large(ddi_irm_pool_t *pool_p, int imbalance)
{
	ddi_irm_req_t	*req_p, *next_p;
	int		nreqs, reduction;

	ASSERT(pool_p != NULL);
	ASSERT(imbalance > 0);
	ASSERT(MUTEX_HELD(&pool_p->ipool_lock));

	DDI_INTR_IRMDBG((CE_CONT,
	    "i_ddi_irm_reduce_large: pool_p %p imbalance %d\n", (void *)pool_p,
	    imbalance));

	while (imbalance > 0) {

		req_p = list_head(&pool_p->ipool_scratch_list);
		next_p = list_next(&pool_p->ipool_scratch_list, req_p);

		/* Fail if nothing is reducible */
		if (req_p->ireq_navail == 1) {
			DDI_INTR_IRMDBG((CE_CONT,
			    "i_ddi_irm_reduce_large: failure.\n"));
			return (DDI_FAILURE);
		}

		/* Count the number of equally sized requests */
		nreqs = 1;
		while (next_p && (req_p->ireq_navail == next_p->ireq_navail)) {
			next_p = list_next(&pool_p->ipool_scratch_list, next_p);
			nreqs++;
		}

		/* Try to reduce multiple requests together */
		if (nreqs > 1) {

			if (next_p) {
				reduction = req_p->ireq_navail -
				    (next_p->ireq_navail + 1);
			} else {
				reduction = req_p->ireq_navail - 1;
			}

			if ((reduction * nreqs) > imbalance)
				reduction = imbalance / nreqs;

			if (reduction > 0) {
				while (req_p && (req_p != next_p)) {
					imbalance -= reduction;
					req_p->ireq_navail -= reduction;
					pool_p->ipool_resno -= reduction;
					req_p = list_next(
					    &pool_p->ipool_scratch_list, req_p);
				}
				continue;
			}
		}

		/* Or just reduce the current request */
		next_p = list_next(&pool_p->ipool_scratch_list, req_p);
		if (next_p && (req_p->ireq_navail > next_p->ireq_navail)) {
			reduction = req_p->ireq_navail - next_p->ireq_navail;
			reduction = MIN(reduction, imbalance);
		} else {
			reduction = 1;
		}
		imbalance -= reduction;
		req_p->ireq_navail -= reduction;
		pool_p->ipool_resno -= reduction;

		/* Re-sort the scratch list if not yet finished */
		if (imbalance > 0) {
			i_ddi_irm_reduce_large_resort(pool_p);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * i_ddi_irm_reduce_large_resort()
 *
 *	Helper function for i_ddi_irm_reduce_large().  Once a request
 *	is reduced, this resorts it further down into the list as necessary.
 */
static void
i_ddi_irm_reduce_large_resort(ddi_irm_pool_t *pool_p)
{
	ddi_irm_req_t	*req_p, *next_p;

	ASSERT(pool_p != NULL);
	ASSERT(MUTEX_HELD(&pool_p->ipool_lock));

	req_p = list_remove_head(&pool_p->ipool_scratch_list);
	next_p = list_head(&pool_p->ipool_scratch_list);

	while (next_p &&
	    ((next_p->ireq_navail > req_p->ireq_navail) ||
	    ((next_p->ireq_navail == req_p->ireq_navail) &&
	    (next_p->ireq_nreq < req_p->ireq_nreq))))
		next_p = list_next(&pool_p->ipool_scratch_list, next_p);

	list_insert_before(&pool_p->ipool_scratch_list, next_p, req_p);
}

/*
 * i_ddi_irm_reduce_even()
 *
 *	Algorithm for the DDI_IRM_POLICY_EVEN reduction policy.
 *
 *	This algorithm reduces requests evenly, without giving a
 *	specific preference to smaller or larger requests.  Each
 *	iteration reduces all reducible requests by the same amount
 *	until the imbalance is corrected.  Although when possible,
 *	it tries to avoid reducing requests below the threshold of
 *	the interrupt pool's default allocation size.
 *
 *	An optimization in this algorithm is to reduce the requests
 *	in larger increments during each iteration, to minimize the
 *	total number of iterations required.
 */
static int
i_ddi_irm_reduce_even(ddi_irm_pool_t *pool_p, int imbalance)
{
	ddi_irm_req_t	*req_p, *last_p;
	uint_t		nmin = pool_p->ipool_defsz;
	uint_t		nreduce, reduction;

	ASSERT(pool_p != NULL);
	ASSERT(imbalance > 0);
	ASSERT(MUTEX_HELD(&pool_p->ipool_lock));

	DDI_INTR_IRMDBG((CE_CONT,
	    "i_ddi_irm_reduce_even: pool_p %p imbalance %d\n",
	    (void *)pool_p, imbalance));

	while ((nmin > 0) && (imbalance > 0)) {

		/* Count reducible requests */
		nreduce = 0;
		for (req_p = list_head(&pool_p->ipool_scratch_list); req_p;
		    req_p = list_next(&pool_p->ipool_scratch_list, req_p)) {
			if (req_p->ireq_navail <= nmin)
				break;
			last_p = req_p;
			nreduce++;
		}

		/* If none are reducible, try a lower minimum */
		if (nreduce == 0) {
			nmin--;
			continue;
		}

		/* Compute reduction */
		if (nreduce < imbalance) {
			reduction = last_p->ireq_navail - nmin;
			if ((reduction * nreduce) > imbalance) {
				reduction = imbalance / nreduce;
			}
		} else {
			reduction = 1;
		}

		/* Start at head of list, but skip excess */
		req_p = list_head(&pool_p->ipool_scratch_list);
		while (nreduce > imbalance) {
			req_p = list_next(&pool_p->ipool_scratch_list, req_p);
			nreduce--;
		}

		/* Do reductions */
		while (req_p && (nreduce > 0)) {
			imbalance -= reduction;
			req_p->ireq_navail -= reduction;
			pool_p->ipool_resno -= reduction;
			req_p = list_next(&pool_p->ipool_scratch_list, req_p);
			nreduce--;
		}
	}

	if (nmin == 0) {
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_reduce_even: failure.\n"));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * i_ddi_irm_reduce_new()
 *
 *	Reduces new requests to zero.  This is only used as a
 *	last resort after another reduction algorithm failed.
 */
static void
i_ddi_irm_reduce_new(ddi_irm_pool_t *pool_p, int imbalance)
{
	ddi_irm_req_t	*req_p;

	ASSERT(pool_p != NULL);
	ASSERT(imbalance > 0);
	ASSERT(MUTEX_HELD(&pool_p->ipool_lock));

	for (req_p = list_head(&pool_p->ipool_scratch_list);
	    req_p && (imbalance > 0);
	    req_p = list_next(&pool_p->ipool_scratch_list, req_p)) {
		ASSERT(req_p->ireq_navail == 1);
		if (req_p->ireq_flags & DDI_IRM_FLAG_NEW) {
			req_p->ireq_navail--;
			pool_p->ipool_resno--;
			imbalance--;
		}
	}
}

/*
 * Miscellaneous Helper Functions
 */

/*
 * i_ddi_intr_get_pool()
 *
 *	Get an IRM pool that supplies interrupts of a specified type.
 *	Invokes a DDI_INTROP_GETPOOL to the bus nexus driver.  Fails
 *	if no pool exists.
 */
ddi_irm_pool_t *
i_ddi_intr_get_pool(dev_info_t *dip, int type)
{
	devinfo_intr_t		*intr_p;
	ddi_irm_pool_t		*pool_p;
	ddi_irm_req_t		*req_p;
	ddi_intr_handle_impl_t	hdl;

	ASSERT(dip != NULL);
	ASSERT(DDI_INTR_TYPE_FLAG_VALID(type));

	if (((intr_p = DEVI(dip)->devi_intr_p) != NULL) &&
	    ((req_p = intr_p->devi_irm_req_p) != NULL) &&
	    ((pool_p = req_p->ireq_pool_p) != NULL) &&
	    (pool_p->ipool_types & type)) {
		return (pool_p);
	}

	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_dip = dip;
	hdl.ih_type = type;

	if (i_ddi_intr_ops(dip, dip, DDI_INTROP_GETPOOL,
	    &hdl, (void *)&pool_p) == DDI_SUCCESS)
		return (pool_p);

	return (NULL);
}

/*
 * i_ddi_irm_insertion_sort()
 *
 *	Use the insertion sort method to insert a request into a list.
 *	The list is sorted in descending order by request size.
 */
static void
i_ddi_irm_insertion_sort(list_t *req_list, ddi_irm_req_t *req_p)
{
	ddi_irm_req_t	*next_p;

	next_p = list_head(req_list);

	while (next_p && (next_p->ireq_nreq > req_p->ireq_nreq))
		next_p = list_next(req_list, next_p);

	list_insert_before(req_list, next_p, req_p);
}

/*
 * i_ddi_irm_notify()
 *
 *	Notify a driver of changes to its interrupt request using the
 *	generic callback mechanism.  Checks for errors in processing.
 */
static int
i_ddi_irm_notify(ddi_irm_pool_t *pool_p, ddi_irm_req_t *req_p)
{
	ddi_cb_action_t	action;
	ddi_cb_t	*cb_p;
	uint_t		nintrs;
	int		ret, count;

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_notify: pool_p %p req_p %p\n",
	    (void *)pool_p, (void *)req_p));

	/* Do not notify new or unchanged requests */
	if ((req_p->ireq_navail == req_p->ireq_scratch) ||
	    (req_p->ireq_flags & DDI_IRM_FLAG_NEW))
		return (DDI_SUCCESS);

	/* Determine action and count */
	if (req_p->ireq_navail > req_p->ireq_scratch) {
		action = DDI_CB_INTR_ADD;
		count = req_p->ireq_navail - req_p->ireq_scratch;
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_notify: adding %d\n",
		    count));
	} else {
		action = DDI_CB_INTR_REMOVE;
		count = req_p->ireq_scratch - req_p->ireq_navail;
		DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_notify: removing %d\n",
		    count));
	}

	/* Lookup driver callback */
	if ((cb_p = DEVI(req_p->ireq_dip)->devi_cb_p) == NULL) {
		DDI_INTR_IRMDBG((CE_WARN, "i_ddi_irm_notify: no callback!\n"));
		return (DDI_FAILURE);
	}

	/* Do callback */
	ret = cb_p->cb_func(req_p->ireq_dip, action, (void *)(uintptr_t)count,
	    cb_p->cb_arg1, cb_p->cb_arg2);

	/* Log callback errors */
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed callback (action=%d, ret=%d)\n",
		    ddi_driver_name(req_p->ireq_dip),
		    ddi_get_instance(req_p->ireq_dip), (int)action, ret);
	}

	/* Check if the driver exceeds its availability */
	nintrs = i_ddi_intr_get_current_nintrs(req_p->ireq_dip);
	if (nintrs > req_p->ireq_navail) {
		cmn_err(CE_WARN, "%s%d: failed to release interrupts "
		    "(nintrs=%d, navail=%d).\n",
		    ddi_driver_name(req_p->ireq_dip),
		    ddi_get_instance(req_p->ireq_dip), nintrs,
		    req_p->ireq_navail);
		pool_p->ipool_resno += (nintrs - req_p->ireq_navail);
		req_p->ireq_navail = nintrs;
		return (DDI_FAILURE);
	}

	/* Update request */
	req_p->ireq_scratch = req_p->ireq_navail;

	return (DDI_SUCCESS);
}

/*
 * i_ddi_irm_debug_balance()
 *
 *	A debug/test only routine to force the immediate,
 *	synchronous rebalancing of an interrupt pool.
 */
#ifdef	DEBUG
void
i_ddi_irm_debug_balance(dev_info_t *dip, boolean_t wait_flag)
{
	ddi_irm_pool_t	*pool_p;
	int		type;

	DDI_INTR_IRMDBG((CE_CONT, "i_ddi_irm_debug_balance: dip %p wait %d\n",
	    (void *)dip, (int)wait_flag));

	if (((type = i_ddi_intr_get_current_type(dip)) != 0) &&
	    ((pool_p = i_ddi_intr_get_pool(dip, type)) != NULL)) {
		mutex_enter(&pool_p->ipool_lock);
		i_ddi_irm_enqueue(pool_p, wait_flag);
		mutex_exit(&pool_p->ipool_lock);
	}
}
#endif
