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
 * Copyright (c) 2017, Joyent, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/tuneable.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <sys/mutex.h>
#include <sys/bitmap.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/kobj.h>
#include <sys/disp.h>
#include <vm/seg_kmem.h>
#include <sys/zone.h>
#include <sys/netstack.h>

/*
 * What we use so that the zones framework can tell us about new zones,
 * which we use to create new stacks.
 */
static zone_key_t netstack_zone_key;

static int	netstack_initialized = 0;

/*
 * Track the registered netstacks.
 * The global lock protects
 * - ns_reg
 * - the list starting at netstack_head and following the netstack_next
 *   pointers.
 */
static kmutex_t netstack_g_lock;

/*
 * Registry of netstacks with their create/shutdown/destory functions.
 */
static struct netstack_registry	ns_reg[NS_MAX];

/*
 * Global list of existing stacks.  We use this when a new zone with
 * an exclusive IP instance is created.
 *
 * Note that in some cases a netstack_t needs to stay around after the zone
 * has gone away. This is because there might be outstanding references
 * (from TCP TIME_WAIT connections, IPsec state, etc). The netstack_t data
 * structure and all the foo_stack_t's hanging off of it will be cleaned up
 * when the last reference to it is dropped.
 * However, the same zone might be rebooted. That is handled using the
 * assumption that the zones framework picks a new zoneid each time a zone
 * is (re)booted. We assert for that condition in netstack_zone_create().
 * Thus the old netstack_t can take its time for things to time out.
 */
static netstack_t *netstack_head;

/*
 * To support kstat_create_netstack() using kstat_zone_add we need
 * to track both
 *  - all zoneids that use the global/shared stack
 *  - all kstats that have been added for the shared stack
 */
struct shared_zone_list {
	struct shared_zone_list *sz_next;
	zoneid_t		sz_zoneid;
};

struct shared_kstat_list {
	struct shared_kstat_list *sk_next;
	kstat_t			 *sk_kstat;
};

static kmutex_t netstack_shared_lock;	/* protects the following two */
static struct shared_zone_list	*netstack_shared_zones;
static struct shared_kstat_list	*netstack_shared_kstats;

static void	*netstack_zone_create(zoneid_t zoneid);
static void	netstack_zone_shutdown(zoneid_t zoneid, void *arg);
static void	netstack_zone_destroy(zoneid_t zoneid, void *arg);

static void	netstack_shared_zone_add(zoneid_t zoneid);
static void	netstack_shared_zone_remove(zoneid_t zoneid);
static void	netstack_shared_kstat_add(kstat_t *ks);
static void	netstack_shared_kstat_remove(kstat_t *ks);

typedef boolean_t applyfn_t(kmutex_t *, netstack_t *, int);

static void	apply_all_netstacks(int, applyfn_t *);
static void	apply_all_modules(netstack_t *, applyfn_t *);
static void	apply_all_modules_reverse(netstack_t *, applyfn_t *);
static boolean_t netstack_apply_create(kmutex_t *, netstack_t *, int);
static boolean_t netstack_apply_shutdown(kmutex_t *, netstack_t *, int);
static boolean_t netstack_apply_destroy(kmutex_t *, netstack_t *, int);
static boolean_t wait_for_zone_creator(netstack_t *, kmutex_t *);
static boolean_t wait_for_nms_inprogress(netstack_t *, nm_state_t *,
    kmutex_t *);

static void netstack_hold_locked(netstack_t *);

static ksema_t netstack_reap_limiter;
/*
 * Hard-coded constant, but since this is not tunable in real-time, it seems
 * making it an /etc/system tunable is better than nothing.
 */
uint_t netstack_outstanding_reaps = 1024;

void
netstack_init(void)
{
	mutex_init(&netstack_g_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&netstack_shared_lock, NULL, MUTEX_DEFAULT, NULL);

	sema_init(&netstack_reap_limiter, netstack_outstanding_reaps, NULL,
	    SEMA_DRIVER, NULL);

	netstack_initialized = 1;

	/*
	 * We want to be informed each time a zone is created or
	 * destroyed in the kernel, so we can maintain the
	 * stack instance information.
	 */
	zone_key_create(&netstack_zone_key, netstack_zone_create,
	    netstack_zone_shutdown, netstack_zone_destroy);
}

/*
 * Register a new module with the framework.
 * This registers interest in changes to the set of netstacks.
 * The createfn and destroyfn are required, but the shutdownfn can be
 * NULL.
 * Note that due to the current zsd implementation, when the create
 * function is called the zone isn't fully present, thus functions
 * like zone_find_by_* will fail, hence the create function can not
 * use many zones kernel functions including zcmn_err().
 */
void
netstack_register(int moduleid,
    void *(*module_create)(netstackid_t, netstack_t *),
    void (*module_shutdown)(netstackid_t, void *),
    void (*module_destroy)(netstackid_t, void *))
{
	netstack_t *ns;

	ASSERT(netstack_initialized);
	ASSERT(moduleid >= 0 && moduleid < NS_MAX);
	ASSERT(module_create != NULL);

	/*
	 * Make instances created after this point in time run the create
	 * callback.
	 */
	mutex_enter(&netstack_g_lock);
	ASSERT(ns_reg[moduleid].nr_create == NULL);
	ASSERT(ns_reg[moduleid].nr_flags == 0);
	ns_reg[moduleid].nr_create = module_create;
	ns_reg[moduleid].nr_shutdown = module_shutdown;
	ns_reg[moduleid].nr_destroy = module_destroy;
	ns_reg[moduleid].nr_flags = NRF_REGISTERED;

	/*
	 * Determine the set of stacks that exist before we drop the lock.
	 * Set NSS_CREATE_NEEDED for each of those.
	 * netstacks which have been deleted will have NSS_CREATE_COMPLETED
	 * set, but check NSF_CLOSING to be sure.
	 */
	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		nm_state_t *nms = &ns->netstack_m_state[moduleid];

		mutex_enter(&ns->netstack_lock);
		if (!(ns->netstack_flags & NSF_CLOSING) &&
		    (nms->nms_flags & NSS_CREATE_ALL) == 0) {
			nms->nms_flags |= NSS_CREATE_NEEDED;
			DTRACE_PROBE2(netstack__create__needed,
			    netstack_t *, ns, int, moduleid);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);

	/*
	 * At this point in time a new instance can be created or an instance
	 * can be destroyed, or some other module can register or unregister.
	 * Make sure we either run all the create functions for this moduleid
	 * or we wait for any other creators for this moduleid.
	 */
	apply_all_netstacks(moduleid, netstack_apply_create);
}

void
netstack_unregister(int moduleid)
{
	netstack_t *ns;

	ASSERT(moduleid >= 0 && moduleid < NS_MAX);

	ASSERT(ns_reg[moduleid].nr_create != NULL);
	ASSERT(ns_reg[moduleid].nr_flags & NRF_REGISTERED);

	mutex_enter(&netstack_g_lock);
	/*
	 * Determine the set of stacks that exist before we drop the lock.
	 * Set NSS_SHUTDOWN_NEEDED and NSS_DESTROY_NEEDED for each of those.
	 * That ensures that when we return all the callbacks for existing
	 * instances have completed. And since we set NRF_DYING no new
	 * instances can use this module.
	 */
	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		boolean_t created = B_FALSE;
		nm_state_t *nms = &ns->netstack_m_state[moduleid];

		mutex_enter(&ns->netstack_lock);

		/*
		 * We need to be careful here. We could actually have a netstack
		 * being created as we speak waiting for us to let go of this
		 * lock to proceed. It may have set NSS_CREATE_NEEDED, but not
		 * have gotten to the point of completing it yet. If
		 * NSS_CREATE_NEEDED, we can safely just remove it here and
		 * never create the module. However, if NSS_CREATE_INPROGRESS is
		 * set, we need to still flag this module for shutdown and
		 * deletion, just as though it had reached NSS_CREATE_COMPLETED.
		 *
		 * It is safe to do that because of two different guarantees
		 * that exist in the system. The first is that before we do a
		 * create, shutdown, or destroy, we ensure that nothing else is
		 * in progress in the system for this netstack and wait for it
		 * to complete. Secondly, because the zone is being created, we
		 * know that the following call to apply_all_netstack will block
		 * on the zone finishing its initialization.
		 */
		if (nms->nms_flags & NSS_CREATE_NEEDED)
			nms->nms_flags &= ~NSS_CREATE_NEEDED;

		if (nms->nms_flags & NSS_CREATE_INPROGRESS ||
		    nms->nms_flags & NSS_CREATE_COMPLETED)
			created = B_TRUE;

		if (ns_reg[moduleid].nr_shutdown != NULL && created &&
		    (nms->nms_flags & NSS_CREATE_COMPLETED) &&
		    (nms->nms_flags & NSS_SHUTDOWN_ALL) == 0) {
			nms->nms_flags |= NSS_SHUTDOWN_NEEDED;
			DTRACE_PROBE2(netstack__shutdown__needed,
			    netstack_t *, ns, int, moduleid);
		}
		if ((ns_reg[moduleid].nr_flags & NRF_REGISTERED) &&
		    ns_reg[moduleid].nr_destroy != NULL && created &&
		    (nms->nms_flags & NSS_DESTROY_ALL) == 0) {
			nms->nms_flags |= NSS_DESTROY_NEEDED;
			DTRACE_PROBE2(netstack__destroy__needed,
			    netstack_t *, ns, int, moduleid);
		}
		mutex_exit(&ns->netstack_lock);
	}
	/*
	 * Prevent any new netstack from calling the registered create
	 * function, while keeping the function pointers in place until the
	 * shutdown and destroy callbacks are complete.
	 */
	ns_reg[moduleid].nr_flags |= NRF_DYING;
	mutex_exit(&netstack_g_lock);

	apply_all_netstacks(moduleid, netstack_apply_shutdown);
	apply_all_netstacks(moduleid, netstack_apply_destroy);

	/*
	 * Clear the nms_flags so that we can handle this module
	 * being loaded again.
	 * Also remove the registered functions.
	 */
	mutex_enter(&netstack_g_lock);
	ASSERT(ns_reg[moduleid].nr_flags & NRF_REGISTERED);
	ASSERT(ns_reg[moduleid].nr_flags & NRF_DYING);
	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		nm_state_t *nms = &ns->netstack_m_state[moduleid];

		mutex_enter(&ns->netstack_lock);
		if (nms->nms_flags & NSS_DESTROY_COMPLETED) {
			nms->nms_flags = 0;
			DTRACE_PROBE2(netstack__destroy__done,
			    netstack_t *, ns, int, moduleid);
		}
		mutex_exit(&ns->netstack_lock);
	}

	ns_reg[moduleid].nr_create = NULL;
	ns_reg[moduleid].nr_shutdown = NULL;
	ns_reg[moduleid].nr_destroy = NULL;
	ns_reg[moduleid].nr_flags = 0;
	mutex_exit(&netstack_g_lock);
}

/*
 * Lookup and/or allocate a netstack for this zone.
 */
static void *
netstack_zone_create(zoneid_t zoneid)
{
	netstackid_t stackid;
	netstack_t *ns;
	netstack_t **nsp;
	zone_t	*zone;
	int i;

	ASSERT(netstack_initialized);

	zone = zone_find_by_id_nolock(zoneid);
	ASSERT(zone != NULL);

	if (zone->zone_flags & ZF_NET_EXCL) {
		stackid = zoneid;
	} else {
		/* Look for the stack instance for the global */
		stackid = GLOBAL_NETSTACKID;
	}

	/* Allocate even if it isn't needed; simplifies locking */
	ns = (netstack_t *)kmem_zalloc(sizeof (netstack_t), KM_SLEEP);

	/* Look if there is a matching stack instance */
	mutex_enter(&netstack_g_lock);
	for (nsp = &netstack_head; *nsp != NULL;
	    nsp = &((*nsp)->netstack_next)) {
		if ((*nsp)->netstack_stackid == stackid) {
			/*
			 * Should never find a pre-existing exclusive stack
			 */
			VERIFY(stackid == GLOBAL_NETSTACKID);
			kmem_free(ns, sizeof (netstack_t));
			ns = *nsp;
			mutex_enter(&ns->netstack_lock);
			ns->netstack_numzones++;
			mutex_exit(&ns->netstack_lock);
			mutex_exit(&netstack_g_lock);
			DTRACE_PROBE1(netstack__inc__numzones,
			    netstack_t *, ns);
			/* Record that we have a new shared stack zone */
			netstack_shared_zone_add(zoneid);
			zone->zone_netstack = ns;
			return (ns);
		}
	}
	/* Not found */
	mutex_init(&ns->netstack_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ns->netstack_cv, NULL, CV_DEFAULT, NULL);
	ns->netstack_stackid = zoneid;
	ns->netstack_numzones = 1;
	ns->netstack_refcnt = 1; /* Decremented by netstack_zone_destroy */
	ns->netstack_flags = NSF_UNINIT;
	*nsp = ns;
	zone->zone_netstack = ns;

	mutex_enter(&ns->netstack_lock);
	/*
	 * Mark this netstack as having a CREATE running so
	 * any netstack_register/netstack_unregister waits for
	 * the existing create callbacks to complete in moduleid order
	 */
	ns->netstack_flags |= NSF_ZONE_CREATE;

	/*
	 * Determine the set of module create functions that need to be
	 * called before we drop the lock.
	 * Set NSS_CREATE_NEEDED for each of those.
	 * Skip any with NRF_DYING set, since those are in the process of
	 * going away, by checking for flags being exactly NRF_REGISTERED.
	 */
	for (i = 0; i < NS_MAX; i++) {
		nm_state_t *nms = &ns->netstack_m_state[i];

		cv_init(&nms->nms_cv, NULL, CV_DEFAULT, NULL);

		if ((ns_reg[i].nr_flags == NRF_REGISTERED) &&
		    (nms->nms_flags & NSS_CREATE_ALL) == 0) {
			nms->nms_flags |= NSS_CREATE_NEEDED;
			DTRACE_PROBE2(netstack__create__needed,
			    netstack_t *, ns, int, i);
		}
	}
	mutex_exit(&ns->netstack_lock);
	mutex_exit(&netstack_g_lock);

	apply_all_modules(ns, netstack_apply_create);

	/* Tell any waiting netstack_register/netstack_unregister to proceed */
	mutex_enter(&ns->netstack_lock);
	ns->netstack_flags &= ~NSF_UNINIT;
	ASSERT(ns->netstack_flags & NSF_ZONE_CREATE);
	ns->netstack_flags &= ~NSF_ZONE_CREATE;
	cv_broadcast(&ns->netstack_cv);
	mutex_exit(&ns->netstack_lock);

	return (ns);
}

/* ARGSUSED */
static void
netstack_zone_shutdown(zoneid_t zoneid, void *arg)
{
	netstack_t *ns = (netstack_t *)arg;
	int i;

	ASSERT(arg != NULL);

	mutex_enter(&ns->netstack_lock);
	ASSERT(ns->netstack_numzones > 0);
	if (ns->netstack_numzones != 1) {
		/* Stack instance being used by other zone */
		mutex_exit(&ns->netstack_lock);
		ASSERT(ns->netstack_stackid == GLOBAL_NETSTACKID);
		return;
	}
	mutex_exit(&ns->netstack_lock);

	mutex_enter(&netstack_g_lock);
	mutex_enter(&ns->netstack_lock);
	/*
	 * Mark this netstack as having a SHUTDOWN running so
	 * any netstack_register/netstack_unregister waits for
	 * the existing create callbacks to complete in moduleid order
	 */
	ASSERT(!(ns->netstack_flags & NSF_ZONE_INPROGRESS));
	ns->netstack_flags |= NSF_ZONE_SHUTDOWN;

	/*
	 * Determine the set of stacks that exist before we drop the lock.
	 * Set NSS_SHUTDOWN_NEEDED for each of those.
	 */
	for (i = 0; i < NS_MAX; i++) {
		nm_state_t *nms = &ns->netstack_m_state[i];

		if ((ns_reg[i].nr_flags & NRF_REGISTERED) &&
		    ns_reg[i].nr_shutdown != NULL &&
		    (nms->nms_flags & NSS_CREATE_COMPLETED) &&
		    (nms->nms_flags & NSS_SHUTDOWN_ALL) == 0) {
			nms->nms_flags |= NSS_SHUTDOWN_NEEDED;
			DTRACE_PROBE2(netstack__shutdown__needed,
			    netstack_t *, ns, int, i);
		}
	}
	mutex_exit(&ns->netstack_lock);
	mutex_exit(&netstack_g_lock);

	/*
	 * Call the shutdown function for all registered modules for this
	 * netstack.
	 */
	apply_all_modules_reverse(ns, netstack_apply_shutdown);

	/* Tell any waiting netstack_register/netstack_unregister to proceed */
	mutex_enter(&ns->netstack_lock);
	ASSERT(ns->netstack_flags & NSF_ZONE_SHUTDOWN);
	ns->netstack_flags &= ~NSF_ZONE_SHUTDOWN;
	cv_broadcast(&ns->netstack_cv);
	mutex_exit(&ns->netstack_lock);
}

/*
 * Common routine to release a zone.
 * If this was the last zone using the stack instance then prepare to
 * have the refcnt dropping to zero free the zone.
 */
/* ARGSUSED */
static void
netstack_zone_destroy(zoneid_t zoneid, void *arg)
{
	netstack_t *ns = (netstack_t *)arg;

	ASSERT(arg != NULL);

	mutex_enter(&ns->netstack_lock);
	ASSERT(ns->netstack_numzones > 0);
	ns->netstack_numzones--;
	if (ns->netstack_numzones != 0) {
		/* Stack instance being used by other zone */
		mutex_exit(&ns->netstack_lock);
		ASSERT(ns->netstack_stackid == GLOBAL_NETSTACKID);
		/* Record that we a shared stack zone has gone away */
		netstack_shared_zone_remove(zoneid);
		return;
	}
	/*
	 * Set CLOSING so that netstack_find_by will not find it.
	 */
	ns->netstack_flags |= NSF_CLOSING;
	mutex_exit(&ns->netstack_lock);
	DTRACE_PROBE1(netstack__dec__numzones, netstack_t *, ns);
	/* No other thread can call zone_destroy for this stack */

	/*
	 * Decrease refcnt to account for the one in netstack_zone_init()
	 */
	netstack_rele(ns);
}

/*
 * Called when the reference count drops to zero.
 * Call the destroy functions for each registered module.
 */
static void
netstack_stack_inactive(netstack_t *ns)
{
	int i;

	mutex_enter(&netstack_g_lock);
	mutex_enter(&ns->netstack_lock);
	/*
	 * Mark this netstack as having a DESTROY running so
	 * any netstack_register/netstack_unregister waits for
	 * the existing destroy callbacks to complete in reverse moduleid order
	 */
	ASSERT(!(ns->netstack_flags & NSF_ZONE_INPROGRESS));
	ns->netstack_flags |= NSF_ZONE_DESTROY;
	/*
	 * If the shutdown callback wasn't called earlier (e.g., if this is
	 * a netstack shared between multiple zones), then we schedule it now.
	 *
	 * Determine the set of stacks that exist before we drop the lock.
	 * Set NSS_DESTROY_NEEDED for each of those. That
	 * ensures that when we return all the callbacks for existing
	 * instances have completed.
	 */
	for (i = 0; i < NS_MAX; i++) {
		nm_state_t *nms = &ns->netstack_m_state[i];

		if ((ns_reg[i].nr_flags & NRF_REGISTERED) &&
		    ns_reg[i].nr_shutdown != NULL &&
		    (nms->nms_flags & NSS_CREATE_COMPLETED) &&
		    (nms->nms_flags & NSS_SHUTDOWN_ALL) == 0) {
			nms->nms_flags |= NSS_SHUTDOWN_NEEDED;
			DTRACE_PROBE2(netstack__shutdown__needed,
			    netstack_t *, ns, int, i);
		}

		if ((ns_reg[i].nr_flags & NRF_REGISTERED) &&
		    ns_reg[i].nr_destroy != NULL &&
		    (nms->nms_flags & NSS_CREATE_COMPLETED) &&
		    (nms->nms_flags & NSS_DESTROY_ALL) == 0) {
			nms->nms_flags |= NSS_DESTROY_NEEDED;
			DTRACE_PROBE2(netstack__destroy__needed,
			    netstack_t *, ns, int, i);
		}
	}
	mutex_exit(&ns->netstack_lock);
	mutex_exit(&netstack_g_lock);

	/*
	 * Call the shutdown and destroy functions for all registered modules
	 * for this netstack.
	 *
	 * Since there are some ordering dependencies between the modules we
	 * tear them down in the reverse order of what was used to create them.
	 *
	 * Since a netstack_t is never reused (when a zone is rebooted it gets
	 * a new zoneid == netstackid i.e. a new netstack_t is allocated) we
	 * leave nms_flags the way it is i.e. with NSS_DESTROY_COMPLETED set.
	 * That is different than in the netstack_unregister() case.
	 */
	apply_all_modules_reverse(ns, netstack_apply_shutdown);
	apply_all_modules_reverse(ns, netstack_apply_destroy);

	/* Tell any waiting netstack_register/netstack_unregister to proceed */
	mutex_enter(&ns->netstack_lock);
	ASSERT(ns->netstack_flags & NSF_ZONE_DESTROY);
	ns->netstack_flags &= ~NSF_ZONE_DESTROY;
	cv_broadcast(&ns->netstack_cv);
	mutex_exit(&ns->netstack_lock);
}

/*
 * Apply a function to all netstacks for a particular moduleid.
 *
 * If there is any zone activity (due to a zone being created, shutdown,
 * or destroyed) we wait for that to complete before we proceed. This ensures
 * that the moduleids are processed in order when a zone is created or
 * destroyed.
 *
 * The applyfn has to drop netstack_g_lock if it does some work.
 * In that case we don't follow netstack_next,
 * even if it is possible to do so without any hazards. This is
 * because we want the design to allow for the list of netstacks threaded
 * by netstack_next to change in any arbitrary way during the time the
 * lock was dropped.
 *
 * It is safe to restart the loop at netstack_head since the applyfn
 * changes netstack_m_state as it processes things, so a subsequent
 * pass through will have no effect in applyfn, hence the loop will terminate
 * in at worst O(N^2).
 */
static void
apply_all_netstacks(int moduleid, applyfn_t *applyfn)
{
	netstack_t *ns;

	mutex_enter(&netstack_g_lock);
	ns = netstack_head;
	while (ns != NULL) {
		if (wait_for_zone_creator(ns, &netstack_g_lock)) {
			/* Lock dropped - restart at head */
			ns = netstack_head;
		} else if ((applyfn)(&netstack_g_lock, ns, moduleid)) {
			/* Lock dropped - restart at head */
			ns = netstack_head;
		} else {
			ns = ns->netstack_next;
		}
	}
	mutex_exit(&netstack_g_lock);
}

/*
 * Apply a function to all moduleids for a particular netstack.
 *
 * Since the netstack linkage doesn't matter in this case we can
 * ignore whether the function drops the lock.
 */
static void
apply_all_modules(netstack_t *ns, applyfn_t *applyfn)
{
	int i;

	mutex_enter(&netstack_g_lock);
	for (i = 0; i < NS_MAX; i++) {
		/*
		 * We don't care whether the lock was dropped
		 * since we are not iterating over netstack_head.
		 */
		(void) (applyfn)(&netstack_g_lock, ns, i);
	}
	mutex_exit(&netstack_g_lock);
}

/* Like the above but in reverse moduleid order */
static void
apply_all_modules_reverse(netstack_t *ns, applyfn_t *applyfn)
{
	int i;

	mutex_enter(&netstack_g_lock);
	for (i = NS_MAX-1; i >= 0; i--) {
		/*
		 * We don't care whether the lock was dropped
		 * since we are not iterating over netstack_head.
		 */
		(void) (applyfn)(&netstack_g_lock, ns, i);
	}
	mutex_exit(&netstack_g_lock);
}

/*
 * Call the create function for the ns and moduleid if CREATE_NEEDED
 * is set.
 * If some other thread gets here first and sets *_INPROGRESS, then
 * we wait for that thread to complete so that we can ensure that
 * all the callbacks are done when we've looped over all netstacks/moduleids.
 *
 * When we call the create function, we temporarily drop the netstack_lock
 * held by the caller, and return true to tell the caller it needs to
 * re-evalute the state.
 */
static boolean_t
netstack_apply_create(kmutex_t *lockp, netstack_t *ns, int moduleid)
{
	void *result;
	netstackid_t stackid;
	nm_state_t *nms = &ns->netstack_m_state[moduleid];
	boolean_t dropped = B_FALSE;

	ASSERT(MUTEX_HELD(lockp));
	mutex_enter(&ns->netstack_lock);

	if (wait_for_nms_inprogress(ns, nms, lockp))
		dropped = B_TRUE;

	if (nms->nms_flags & NSS_CREATE_NEEDED) {
		nms->nms_flags &= ~NSS_CREATE_NEEDED;
		nms->nms_flags |= NSS_CREATE_INPROGRESS;
		DTRACE_PROBE2(netstack__create__inprogress,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		mutex_exit(lockp);
		dropped = B_TRUE;

		ASSERT(ns_reg[moduleid].nr_create != NULL);
		stackid = ns->netstack_stackid;
		DTRACE_PROBE2(netstack__create__start,
		    netstackid_t, stackid,
		    netstack_t *, ns);
		result = (ns_reg[moduleid].nr_create)(stackid, ns);
		DTRACE_PROBE2(netstack__create__end,
		    void *, result, netstack_t *, ns);

		ASSERT(result != NULL);
		mutex_enter(lockp);
		mutex_enter(&ns->netstack_lock);
		ns->netstack_modules[moduleid] = result;
		nms->nms_flags &= ~NSS_CREATE_INPROGRESS;
		nms->nms_flags |= NSS_CREATE_COMPLETED;
		cv_broadcast(&nms->nms_cv);
		DTRACE_PROBE2(netstack__create__completed,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		return (dropped);
	} else {
		mutex_exit(&ns->netstack_lock);
		return (dropped);
	}
}

/*
 * Call the shutdown function for the ns and moduleid if SHUTDOWN_NEEDED
 * is set.
 * If some other thread gets here first and sets *_INPROGRESS, then
 * we wait for that thread to complete so that we can ensure that
 * all the callbacks are done when we've looped over all netstacks/moduleids.
 *
 * When we call the shutdown function, we temporarily drop the netstack_lock
 * held by the caller, and return true to tell the caller it needs to
 * re-evalute the state.
 */
static boolean_t
netstack_apply_shutdown(kmutex_t *lockp, netstack_t *ns, int moduleid)
{
	netstackid_t stackid;
	void * netstack_module;
	nm_state_t *nms = &ns->netstack_m_state[moduleid];
	boolean_t dropped = B_FALSE;

	ASSERT(MUTEX_HELD(lockp));
	mutex_enter(&ns->netstack_lock);

	if (wait_for_nms_inprogress(ns, nms, lockp))
		dropped = B_TRUE;

	if (nms->nms_flags & NSS_SHUTDOWN_NEEDED) {
		nms->nms_flags &= ~NSS_SHUTDOWN_NEEDED;
		nms->nms_flags |= NSS_SHUTDOWN_INPROGRESS;
		DTRACE_PROBE2(netstack__shutdown__inprogress,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		mutex_exit(lockp);
		dropped = B_TRUE;

		ASSERT(ns_reg[moduleid].nr_shutdown != NULL);
		stackid = ns->netstack_stackid;
		netstack_module = ns->netstack_modules[moduleid];
		DTRACE_PROBE2(netstack__shutdown__start,
		    netstackid_t, stackid,
		    void *, netstack_module);
		(ns_reg[moduleid].nr_shutdown)(stackid, netstack_module);
		DTRACE_PROBE1(netstack__shutdown__end,
		    netstack_t *, ns);

		mutex_enter(lockp);
		mutex_enter(&ns->netstack_lock);
		nms->nms_flags &= ~NSS_SHUTDOWN_INPROGRESS;
		nms->nms_flags |= NSS_SHUTDOWN_COMPLETED;
		cv_broadcast(&nms->nms_cv);
		DTRACE_PROBE2(netstack__shutdown__completed,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		return (dropped);
	} else {
		mutex_exit(&ns->netstack_lock);
		return (dropped);
	}
}

/*
 * Call the destroy function for the ns and moduleid if DESTROY_NEEDED
 * is set.
 * If some other thread gets here first and sets *_INPROGRESS, then
 * we wait for that thread to complete so that we can ensure that
 * all the callbacks are done when we've looped over all netstacks/moduleids.
 *
 * When we call the destroy function, we temporarily drop the netstack_lock
 * held by the caller, and return true to tell the caller it needs to
 * re-evalute the state.
 */
static boolean_t
netstack_apply_destroy(kmutex_t *lockp, netstack_t *ns, int moduleid)
{
	netstackid_t stackid;
	void * netstack_module;
	nm_state_t *nms = &ns->netstack_m_state[moduleid];
	boolean_t dropped = B_FALSE;

	ASSERT(MUTEX_HELD(lockp));
	mutex_enter(&ns->netstack_lock);

	if (wait_for_nms_inprogress(ns, nms, lockp))
		dropped = B_TRUE;

	if (nms->nms_flags & NSS_DESTROY_NEEDED) {
		nms->nms_flags &= ~NSS_DESTROY_NEEDED;
		nms->nms_flags |= NSS_DESTROY_INPROGRESS;
		DTRACE_PROBE2(netstack__destroy__inprogress,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		mutex_exit(lockp);
		dropped = B_TRUE;

		ASSERT(ns_reg[moduleid].nr_destroy != NULL);
		stackid = ns->netstack_stackid;
		netstack_module = ns->netstack_modules[moduleid];
		DTRACE_PROBE2(netstack__destroy__start,
		    netstackid_t, stackid,
		    void *, netstack_module);
		(ns_reg[moduleid].nr_destroy)(stackid, netstack_module);
		DTRACE_PROBE1(netstack__destroy__end,
		    netstack_t *, ns);

		mutex_enter(lockp);
		mutex_enter(&ns->netstack_lock);
		ns->netstack_modules[moduleid] = NULL;
		nms->nms_flags &= ~NSS_DESTROY_INPROGRESS;
		nms->nms_flags |= NSS_DESTROY_COMPLETED;
		cv_broadcast(&nms->nms_cv);
		DTRACE_PROBE2(netstack__destroy__completed,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		return (dropped);
	} else {
		mutex_exit(&ns->netstack_lock);
		return (dropped);
	}
}

/*
 * If somebody  is creating the netstack (due to a new zone being created)
 * then we wait for them to complete. This ensures that any additional
 * netstack_register() doesn't cause the create functions to run out of
 * order.
 * Note that we do not need such a global wait in the case of the shutdown
 * and destroy callbacks, since in that case it is sufficient for both
 * threads to set NEEDED and wait for INPROGRESS to ensure ordering.
 * Returns true if lockp was temporarily dropped while waiting.
 */
static boolean_t
wait_for_zone_creator(netstack_t *ns, kmutex_t *lockp)
{
	boolean_t dropped = B_FALSE;

	mutex_enter(&ns->netstack_lock);
	while (ns->netstack_flags & NSF_ZONE_CREATE) {
		DTRACE_PROBE1(netstack__wait__zone__inprogress,
		    netstack_t *, ns);
		if (lockp != NULL) {
			dropped = B_TRUE;
			mutex_exit(lockp);
		}
		cv_wait(&ns->netstack_cv, &ns->netstack_lock);
		if (lockp != NULL) {
			/* First drop netstack_lock to preserve order */
			mutex_exit(&ns->netstack_lock);
			mutex_enter(lockp);
			mutex_enter(&ns->netstack_lock);
		}
	}
	mutex_exit(&ns->netstack_lock);
	return (dropped);
}

/*
 * Wait for any INPROGRESS flag to be cleared for the netstack/moduleid
 * combination.
 * Returns true if lockp was temporarily dropped while waiting.
 */
static boolean_t
wait_for_nms_inprogress(netstack_t *ns, nm_state_t *nms, kmutex_t *lockp)
{
	boolean_t dropped = B_FALSE;

	while (nms->nms_flags & NSS_ALL_INPROGRESS) {
		DTRACE_PROBE2(netstack__wait__nms__inprogress,
		    netstack_t *, ns, nm_state_t *, nms);
		if (lockp != NULL) {
			dropped = B_TRUE;
			mutex_exit(lockp);
		}
		cv_wait(&nms->nms_cv, &ns->netstack_lock);
		if (lockp != NULL) {
			/* First drop netstack_lock to preserve order */
			mutex_exit(&ns->netstack_lock);
			mutex_enter(lockp);
			mutex_enter(&ns->netstack_lock);
		}
	}
	return (dropped);
}

/*
 * Get the stack instance used in caller's zone.
 * Increases the reference count, caller must do a netstack_rele.
 * It can't be called after zone_destroy() has started.
 */
netstack_t *
netstack_get_current(void)
{
	netstack_t *ns;

	ns = curproc->p_zone->zone_netstack;
	ASSERT(ns != NULL);
	return (netstack_hold_if_active(ns));
}

/*
 * Find a stack instance given the cred.
 * This is used by the modules to potentially allow for a future when
 * something other than the zoneid is used to determine the stack.
 */
netstack_t *
netstack_find_by_cred(const cred_t *cr)
{
	zoneid_t zoneid = crgetzoneid(cr);

	/* Handle the case when cr_zone is NULL */
	if (zoneid == (zoneid_t)-1)
		zoneid = GLOBAL_ZONEID;

	/* For performance ... */
	if (curproc->p_zone->zone_id == zoneid)
		return (netstack_get_current());
	else
		return (netstack_find_by_zoneid(zoneid));
}

/*
 * Find a stack instance given the zoneid.
 * Increases the reference count if found; caller must do a
 * netstack_rele().
 *
 * If there is no exact match then assume the shared stack instance
 * matches.
 *
 * Skip the uninitialized and closing ones.
 */
netstack_t *
netstack_find_by_zoneid(zoneid_t zoneid)
{
	netstack_t *ns;
	zone_t *zone;

	zone = zone_find_by_id(zoneid);

	if (zone == NULL)
		return (NULL);

	ASSERT(zone->zone_netstack != NULL);
	ns = netstack_hold_if_active(zone->zone_netstack);

	zone_rele(zone);
	return (ns);
}

/*
 * Find a stack instance given the zoneid. Can only be called from
 * the create callback. See the comments in zone_find_by_id_nolock why
 * that limitation exists.
 *
 * Increases the reference count if found; caller must do a
 * netstack_rele().
 *
 * If there is no exact match then assume the shared stack instance
 * matches.
 *
 * Skip the unitialized ones.
 */
netstack_t *
netstack_find_by_zoneid_nolock(zoneid_t zoneid)
{
	zone_t *zone;

	zone = zone_find_by_id_nolock(zoneid);

	if (zone == NULL)
		return (NULL);

	ASSERT(zone->zone_netstack != NULL);
	/* zone_find_by_id_nolock does not have a hold on the zone */
	return (netstack_hold_if_active(zone->zone_netstack));
}

/*
 * Find a stack instance given the stackid with exact match?
 * Increases the reference count if found; caller must do a
 * netstack_rele().
 *
 * Skip the unitialized ones.
 */
netstack_t *
netstack_find_by_stackid(netstackid_t stackid)
{
	netstack_t *ns;

	mutex_enter(&netstack_g_lock);
	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		/* Can't use hold_if_active because of stackid check. */
		mutex_enter(&ns->netstack_lock);
		if (ns->netstack_stackid == stackid &&
		    !(ns->netstack_flags & (NSF_UNINIT|NSF_CLOSING))) {
			netstack_hold_locked(ns);
			mutex_exit(&ns->netstack_lock);
			mutex_exit(&netstack_g_lock);
			return (ns);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);
	return (NULL);
}

boolean_t
netstack_inuse_by_stackid(netstackid_t stackid)
{
	netstack_t *ns;
	boolean_t rval = B_FALSE;

	mutex_enter(&netstack_g_lock);

	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		if (ns->netstack_stackid == stackid) {
			rval = B_TRUE;
			break;
		}
	}

	mutex_exit(&netstack_g_lock);

	return (rval);
}


static void
netstack_reap(void *arg)
{
	netstack_t **nsp, *ns = (netstack_t *)arg;
	boolean_t found;
	int i;

	/*
	 * Time to call the destroy functions and free up
	 * the structure
	 */
	netstack_stack_inactive(ns);

	/* Make sure nothing increased the references */
	ASSERT(ns->netstack_refcnt == 0);
	ASSERT(ns->netstack_numzones == 0);

	/* Finally remove from list of netstacks */
	mutex_enter(&netstack_g_lock);
	found = B_FALSE;
	for (nsp = &netstack_head; *nsp != NULL;
	    nsp = &(*nsp)->netstack_next) {
		if (*nsp == ns) {
			*nsp = ns->netstack_next;
			ns->netstack_next = NULL;
			found = B_TRUE;
			break;
		}
	}
	ASSERT(found);
	mutex_exit(&netstack_g_lock);

	/* Make sure nothing increased the references */
	ASSERT(ns->netstack_refcnt == 0);
	ASSERT(ns->netstack_numzones == 0);

	ASSERT(ns->netstack_flags & NSF_CLOSING);

	for (i = 0; i < NS_MAX; i++) {
		nm_state_t *nms = &ns->netstack_m_state[i];

		cv_destroy(&nms->nms_cv);
	}
	mutex_destroy(&ns->netstack_lock);
	cv_destroy(&ns->netstack_cv);
	kmem_free(ns, sizeof (*ns));
	/* Allow another reap to be scheduled. */
	sema_v(&netstack_reap_limiter);
}

void
netstack_rele(netstack_t *ns)
{
	int refcnt, numzones;

	mutex_enter(&ns->netstack_lock);
	ASSERT(ns->netstack_refcnt > 0);
	ns->netstack_refcnt--;
	/*
	 * As we drop the lock additional netstack_rele()s can come in
	 * and decrement the refcnt to zero and free the netstack_t.
	 * Store pointers in local variables and if we were not the last
	 * then don't reference the netstack_t after that.
	 */
	refcnt = ns->netstack_refcnt;
	numzones = ns->netstack_numzones;
	DTRACE_PROBE1(netstack__dec__ref, netstack_t *, ns);
	mutex_exit(&ns->netstack_lock);

	if (refcnt == 0 && numzones == 0) {
		/*
		 * Because there are possibilities of re-entrancy in various
		 * netstack structures by callers, which might cause a lock up
		 * due to odd reference models, or other factors, we choose to
		 * schedule the actual deletion of this netstack as a deferred
		 * task on the system taskq.  This way, any such reference
		 * models won't trip over themselves.
		 *
		 * Assume we aren't in a high-priority interrupt context, so
		 * we can use KM_SLEEP and semaphores.
		 */
		if (sema_tryp(&netstack_reap_limiter) == 0) {
			/*
			 * Indicate we're slamming against a limit.
			 */
			hrtime_t measurement = gethrtime();

			sema_p(&netstack_reap_limiter);
			/* Capture delay in ns. */
			DTRACE_PROBE1(netstack__reap__rate__limited,
			    hrtime_t, gethrtime() - measurement);
		}

		/* TQ_SLEEP should prevent taskq_dispatch() from failing. */
		(void) taskq_dispatch(system_taskq, netstack_reap, ns,
		    TQ_SLEEP);
	}
}

static void
netstack_hold_locked(netstack_t *ns)
{
	ASSERT(MUTEX_HELD(&ns->netstack_lock));
	ns->netstack_refcnt++;
	ASSERT(ns->netstack_refcnt > 0);
	DTRACE_PROBE1(netstack__inc__ref, netstack_t *, ns);
}

/*
 * If the passed-in netstack isn't active (i.e. it's uninitialized or closing),
 * return NULL, otherwise return it with its reference held.  Common code
 * for many netstack_find*() functions.
 */
netstack_t *
netstack_hold_if_active(netstack_t *ns)
{
	netstack_t *retval;

	mutex_enter(&ns->netstack_lock);
	if (ns->netstack_flags & (NSF_UNINIT | NSF_CLOSING)) {
		retval = NULL;
	} else {
		netstack_hold_locked(ns);
		retval = ns;
	}
	mutex_exit(&ns->netstack_lock);

	return (retval);
}

void
netstack_hold(netstack_t *ns)
{
	mutex_enter(&ns->netstack_lock);
	netstack_hold_locked(ns);
	mutex_exit(&ns->netstack_lock);
}

/*
 * To support kstat_create_netstack() using kstat_zone_add we need
 * to track both
 *  - all zoneids that use the global/shared stack
 *  - all kstats that have been added for the shared stack
 */
kstat_t *
kstat_create_netstack(char *ks_module, int ks_instance, char *ks_name,
    char *ks_class, uchar_t ks_type, uint_t ks_ndata, uchar_t ks_flags,
    netstackid_t ks_netstackid)
{
	kstat_t *ks;

	if (ks_netstackid == GLOBAL_NETSTACKID) {
		ks = kstat_create_zone(ks_module, ks_instance, ks_name,
		    ks_class, ks_type, ks_ndata, ks_flags, GLOBAL_ZONEID);
		if (ks != NULL)
			netstack_shared_kstat_add(ks);
		return (ks);
	} else {
		zoneid_t zoneid = ks_netstackid;

		return (kstat_create_zone(ks_module, ks_instance, ks_name,
		    ks_class, ks_type, ks_ndata, ks_flags, zoneid));
	}
}

void
kstat_delete_netstack(kstat_t *ks, netstackid_t ks_netstackid)
{
	if (ks_netstackid == GLOBAL_NETSTACKID) {
		netstack_shared_kstat_remove(ks);
	}
	kstat_delete(ks);
}

static void
netstack_shared_zone_add(zoneid_t zoneid)
{
	struct shared_zone_list *sz;
	struct shared_kstat_list *sk;

	sz = (struct shared_zone_list *)kmem_zalloc(sizeof (*sz), KM_SLEEP);
	sz->sz_zoneid = zoneid;

	/* Insert in list */
	mutex_enter(&netstack_shared_lock);
	sz->sz_next = netstack_shared_zones;
	netstack_shared_zones = sz;

	/*
	 * Perform kstat_zone_add for each existing shared stack kstat.
	 * Note: Holds netstack_shared_lock lock across kstat_zone_add.
	 */
	for (sk = netstack_shared_kstats; sk != NULL; sk = sk->sk_next) {
		kstat_zone_add(sk->sk_kstat, zoneid);
	}
	mutex_exit(&netstack_shared_lock);
}

static void
netstack_shared_zone_remove(zoneid_t zoneid)
{
	struct shared_zone_list **szp, *sz;
	struct shared_kstat_list *sk;

	/* Find in list */
	mutex_enter(&netstack_shared_lock);
	sz = NULL;
	for (szp = &netstack_shared_zones; *szp != NULL;
	    szp = &((*szp)->sz_next)) {
		if ((*szp)->sz_zoneid == zoneid) {
			sz = *szp;
			break;
		}
	}
	/* We must find it */
	ASSERT(sz != NULL);
	*szp = sz->sz_next;
	sz->sz_next = NULL;

	/*
	 * Perform kstat_zone_remove for each existing shared stack kstat.
	 * Note: Holds netstack_shared_lock lock across kstat_zone_remove.
	 */
	for (sk = netstack_shared_kstats; sk != NULL; sk = sk->sk_next) {
		kstat_zone_remove(sk->sk_kstat, zoneid);
	}
	mutex_exit(&netstack_shared_lock);

	kmem_free(sz, sizeof (*sz));
}

static void
netstack_shared_kstat_add(kstat_t *ks)
{
	struct shared_zone_list *sz;
	struct shared_kstat_list *sk;

	sk = (struct shared_kstat_list *)kmem_zalloc(sizeof (*sk), KM_SLEEP);
	sk->sk_kstat = ks;

	/* Insert in list */
	mutex_enter(&netstack_shared_lock);
	sk->sk_next = netstack_shared_kstats;
	netstack_shared_kstats = sk;

	/*
	 * Perform kstat_zone_add for each existing shared stack zone.
	 * Note: Holds netstack_shared_lock lock across kstat_zone_add.
	 */
	for (sz = netstack_shared_zones; sz != NULL; sz = sz->sz_next) {
		kstat_zone_add(ks, sz->sz_zoneid);
	}
	mutex_exit(&netstack_shared_lock);
}

static void
netstack_shared_kstat_remove(kstat_t *ks)
{
	struct shared_zone_list *sz;
	struct shared_kstat_list **skp, *sk;

	/* Find in list */
	mutex_enter(&netstack_shared_lock);
	sk = NULL;
	for (skp = &netstack_shared_kstats; *skp != NULL;
	    skp = &((*skp)->sk_next)) {
		if ((*skp)->sk_kstat == ks) {
			sk = *skp;
			break;
		}
	}
	/* Must find it */
	ASSERT(sk != NULL);
	*skp = sk->sk_next;
	sk->sk_next = NULL;

	/*
	 * Perform kstat_zone_remove for each existing shared stack kstat.
	 * Note: Holds netstack_shared_lock lock across kstat_zone_remove.
	 */
	for (sz = netstack_shared_zones; sz != NULL; sz = sz->sz_next) {
		kstat_zone_remove(ks, sz->sz_zoneid);
	}
	mutex_exit(&netstack_shared_lock);
	kmem_free(sk, sizeof (*sk));
}

/*
 * If a zoneid is part of the shared zone, return true
 */
static boolean_t
netstack_find_shared_zoneid(zoneid_t zoneid)
{
	struct shared_zone_list *sz;

	mutex_enter(&netstack_shared_lock);
	for (sz = netstack_shared_zones; sz != NULL; sz = sz->sz_next) {
		if (sz->sz_zoneid == zoneid) {
			mutex_exit(&netstack_shared_lock);
			return (B_TRUE);
		}
	}
	mutex_exit(&netstack_shared_lock);
	return (B_FALSE);
}

/*
 * Hide the fact that zoneids and netstackids are allocated from
 * the same space in the current implementation.
 * We currently do not check that the stackid/zoneids are valid, since there
 * is no need for that. But this should only be done for ids that are
 * valid.
 */
zoneid_t
netstackid_to_zoneid(netstackid_t stackid)
{
	return (stackid);
}

netstackid_t
zoneid_to_netstackid(zoneid_t zoneid)
{
	if (netstack_find_shared_zoneid(zoneid))
		return (GLOBAL_ZONEID);
	else
		return (zoneid);
}

zoneid_t
netstack_get_zoneid(netstack_t *ns)
{
	return (netstackid_to_zoneid(ns->netstack_stackid));
}

/*
 * Simplistic support for walking all the handles.
 * Example usage:
 *	netstack_handle_t nh;
 *	netstack_t *ns;
 *
 *	netstack_next_init(&nh);
 *	while ((ns = netstack_next(&nh)) != NULL) {
 *		do something;
 *		netstack_rele(ns);
 *	}
 *	netstack_next_fini(&nh);
 */
void
netstack_next_init(netstack_handle_t *handle)
{
	*handle = 0;
}

/* ARGSUSED */
void
netstack_next_fini(netstack_handle_t *handle)
{
}

netstack_t *
netstack_next(netstack_handle_t *handle)
{
	netstack_t *ns;
	int i, end;

	end = *handle;
	/* Walk skipping *handle number of instances */

	/* Look if there is a matching stack instance */
	mutex_enter(&netstack_g_lock);
	ns = netstack_head;
	for (i = 0; i < end; i++) {
		if (ns == NULL)
			break;
		ns = ns->netstack_next;
	}
	/*
	 * Skip those that aren't really here (uninitialized or closing).
	 * Can't use hold_if_active because of "end" tracking.
	 */
	while (ns != NULL) {
		mutex_enter(&ns->netstack_lock);
		if ((ns->netstack_flags & (NSF_UNINIT|NSF_CLOSING)) == 0) {
			*handle = end + 1;
			netstack_hold_locked(ns);
			mutex_exit(&ns->netstack_lock);
			break;
		}
		mutex_exit(&ns->netstack_lock);
		end++;
		ns = ns->netstack_next;
	}
	mutex_exit(&netstack_g_lock);
	return (ns);
}
