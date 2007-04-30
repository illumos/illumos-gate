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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static void	netstack_do_create(void);
static void	netstack_do_shutdown(void);
static void	netstack_do_destroy(void);

static void	netstack_shared_zone_add(zoneid_t zoneid);
static void	netstack_shared_zone_remove(zoneid_t zoneid);
static void	netstack_shared_kstat_add(kstat_t *ks);
static void	netstack_shared_kstat_remove(kstat_t *ks);


void
netstack_init(void)
{
	mutex_init(&netstack_g_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&netstack_shared_lock, NULL, MUTEX_DEFAULT, NULL);

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

	mutex_enter(&netstack_g_lock);
	ASSERT(ns_reg[moduleid].nr_create == NULL);
	ASSERT(ns_reg[moduleid].nr_flags == 0);
	ns_reg[moduleid].nr_create = module_create;
	ns_reg[moduleid].nr_shutdown = module_shutdown;
	ns_reg[moduleid].nr_destroy = module_destroy;
	ns_reg[moduleid].nr_flags = NRF_REGISTERED;

	/*
	 * Determine the set of stacks that exist before we drop the lock.
	 * Set CREATE_NEEDED for each of those.
	 * netstacks which have been deleted will have NSS_CREATE_COMPLETED
	 * set, but check NSF_CLOSING to be sure.
	 */
	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		mutex_enter(&ns->netstack_lock);
		if (!(ns->netstack_flags & NSF_CLOSING) &&
		    (ns->netstack_m_state[moduleid] & NSS_CREATE_ALL) == 0) {
			ns->netstack_m_state[moduleid] |= NSS_CREATE_NEEDED;
			DTRACE_PROBE2(netstack__create__needed,
			    netstack_t *, ns, int, moduleid);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);

	/*
	 * Call the create function for each stack that has CREATE_NEEDED.
	 * Set CREATE_INPROGRESS, drop lock, and after done,
	 * set CREATE_COMPLETE
	 */
	netstack_do_create();
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
	 * Set SHUTDOWN_NEEDED and DESTROY_NEEDED for each of those.
	 */
	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		mutex_enter(&ns->netstack_lock);
		if (ns_reg[moduleid].nr_shutdown != NULL &&
		    (ns->netstack_m_state[moduleid] & NSS_CREATE_COMPLETED) &&
		    (ns->netstack_m_state[moduleid] & NSS_SHUTDOWN_ALL) == 0) {
			ns->netstack_m_state[moduleid] |= NSS_SHUTDOWN_NEEDED;
			DTRACE_PROBE2(netstack__shutdown__needed,
			    netstack_t *, ns, int, moduleid);
		}
		if ((ns_reg[moduleid].nr_flags & NRF_REGISTERED) &&
		    ns_reg[moduleid].nr_destroy != NULL &&
		    (ns->netstack_m_state[moduleid] & NSS_CREATE_COMPLETED) &&
		    (ns->netstack_m_state[moduleid] & NSS_DESTROY_ALL) == 0) {
			ns->netstack_m_state[moduleid] |= NSS_DESTROY_NEEDED;
			DTRACE_PROBE2(netstack__destroy__needed,
			    netstack_t *, ns, int, moduleid);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);

	netstack_do_shutdown();
	netstack_do_destroy();

	/*
	 * Clear the netstack_m_state so that we can handle this module
	 * being loaded again.
	 */
	mutex_enter(&netstack_g_lock);
	for (ns = netstack_head; ns != NULL; ns = ns->netstack_next) {
		mutex_enter(&ns->netstack_lock);
		if (ns->netstack_m_state[moduleid] & NSS_DESTROY_COMPLETED) {
			ns->netstack_m_state[moduleid] = 0;
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
			ASSERT(stackid == GLOBAL_NETSTACKID);
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
	ns->netstack_stackid = zoneid;
	ns->netstack_numzones = 1;
	ns->netstack_refcnt = 1; /* Decremented by netstack_zone_destroy */
	ns->netstack_flags = NSF_UNINIT;
	*nsp = ns;
	zone->zone_netstack = ns;

	/*
	 * Determine the set of module create functions that need to be
	 * called before we drop the lock.
	 */
	for (i = 0; i < NS_MAX; i++) {
		mutex_enter(&ns->netstack_lock);
		if ((ns_reg[i].nr_flags & NRF_REGISTERED) &&
		    (ns->netstack_m_state[i] & NSS_CREATE_ALL) == 0) {
			ns->netstack_m_state[i] |= NSS_CREATE_NEEDED;
			DTRACE_PROBE2(netstack__create__needed,
			    netstack_t *, ns, int, i);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);

	netstack_do_create();

	mutex_enter(&ns->netstack_lock);
	ns->netstack_flags &= ~NSF_UNINIT;
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
	/*
	 * Determine the set of stacks that exist before we drop the lock.
	 * Set SHUTDOWN_NEEDED for each of those.
	 */
	for (i = 0; i < NS_MAX; i++) {
		mutex_enter(&ns->netstack_lock);
		if ((ns_reg[i].nr_flags & NRF_REGISTERED) &&
		    ns_reg[i].nr_shutdown != NULL &&
		    (ns->netstack_m_state[i] & NSS_CREATE_COMPLETED) &&
		    (ns->netstack_m_state[i] & NSS_SHUTDOWN_ALL) == 0) {
			ns->netstack_m_state[i] |= NSS_SHUTDOWN_NEEDED;
			DTRACE_PROBE2(netstack__shutdown__needed,
			    netstack_t *, ns, int, i);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);

	/* Call the shutdown function for all registered modules */
	netstack_do_shutdown();
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
	 * Set CLOSING so that netstack_find_by will not find it
	 * and decrement the reference count.
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
	/*
	 * If the shutdown callback wasn't called earlier (e.g., if this is
	 * a netstack shared between multiple zones), then we call it now.
	 */
	for (i = 0; i < NS_MAX; i++) {
		mutex_enter(&ns->netstack_lock);
		if ((ns_reg[i].nr_flags & NRF_REGISTERED) &&
		    ns_reg[i].nr_shutdown != NULL &&
		    (ns->netstack_m_state[i] & NSS_CREATE_COMPLETED) &&
		    (ns->netstack_m_state[i] & NSS_SHUTDOWN_ALL) == 0) {
			ns->netstack_m_state[i] |= NSS_SHUTDOWN_NEEDED;
			DTRACE_PROBE2(netstack__shutdown__needed,
			    netstack_t *, ns, int, i);
		}
		mutex_exit(&ns->netstack_lock);
	}
	/*
	 * Determine the set of stacks that exist before we drop the lock.
	 * Set DESTROY_NEEDED for each of those.
	 */
	for (i = 0; i < NS_MAX; i++) {
		mutex_enter(&ns->netstack_lock);
		if ((ns_reg[i].nr_flags & NRF_REGISTERED) &&
		    ns_reg[i].nr_destroy != NULL &&
		    (ns->netstack_m_state[i] & NSS_CREATE_COMPLETED) &&
		    (ns->netstack_m_state[i] & NSS_DESTROY_ALL) == 0) {
			ns->netstack_m_state[i] |= NSS_DESTROY_NEEDED;
			DTRACE_PROBE2(netstack__destroy__needed,
			    netstack_t *, ns, int, i);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);

	netstack_do_shutdown();
	netstack_do_destroy();
}

/*
 * Call the create function for the ns and moduleid if CREATE_NEEDED
 * is set.
 * When it calls it, it drops the netstack_lock held by the caller,
 * and returns true to tell the caller it needs to re-evalute the
 * state..
 */
static boolean_t
netstack_apply_create(kmutex_t *lockp, netstack_t *ns, int moduleid)
{
	void *result;
	netstackid_t stackid;

	ASSERT(MUTEX_HELD(lockp));
	mutex_enter(&ns->netstack_lock);
	if (ns->netstack_m_state[moduleid] & NSS_CREATE_NEEDED) {
		ns->netstack_m_state[moduleid] &= ~NSS_CREATE_NEEDED;
		ns->netstack_m_state[moduleid] |= NSS_CREATE_INPROGRESS;
		DTRACE_PROBE2(netstack__create__inprogress,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		mutex_exit(lockp);

		ASSERT(ns_reg[moduleid].nr_create != NULL);
		stackid = ns->netstack_stackid;
		DTRACE_PROBE2(netstack__create__start,
		    netstackid_t, stackid,
		    netstack_t *, ns);
		result = (ns_reg[moduleid].nr_create)(stackid, ns);
		DTRACE_PROBE2(netstack__create__end,
		    void *, result, netstack_t *, ns);

		ASSERT(result != NULL);
		mutex_enter(&ns->netstack_lock);
		ns->netstack_modules[moduleid] = result;
		ns->netstack_m_state[moduleid] &= ~NSS_CREATE_INPROGRESS;
		ns->netstack_m_state[moduleid] |= NSS_CREATE_COMPLETED;
		DTRACE_PROBE2(netstack__create__completed,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		return (B_TRUE);
	} else {
		mutex_exit(&ns->netstack_lock);
		return (B_FALSE);
	}
}

/*
 * Call the shutdown function for the ns and moduleid if SHUTDOWN_NEEDED
 * is set.
 * When it calls it, it drops the netstack_lock held by the caller,
 * and returns true to tell the caller it needs to re-evalute the
 * state..
 */
static boolean_t
netstack_apply_shutdown(kmutex_t *lockp, netstack_t *ns, int moduleid)
{
	netstackid_t stackid;
	void * netstack_module;

	ASSERT(MUTEX_HELD(lockp));
	mutex_enter(&ns->netstack_lock);
	if (ns->netstack_m_state[moduleid] & NSS_SHUTDOWN_NEEDED) {
		ns->netstack_m_state[moduleid] &= ~NSS_SHUTDOWN_NEEDED;
		ns->netstack_m_state[moduleid] |= NSS_SHUTDOWN_INPROGRESS;
		DTRACE_PROBE2(netstack__shutdown__inprogress,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		mutex_exit(lockp);

		ASSERT(ns_reg[moduleid].nr_shutdown != NULL);
		stackid = ns->netstack_stackid;
		netstack_module = ns->netstack_modules[moduleid];
		DTRACE_PROBE2(netstack__shutdown__start,
		    netstackid_t, stackid,
		    void *, netstack_module);
		(ns_reg[moduleid].nr_shutdown)(stackid, netstack_module);
		DTRACE_PROBE1(netstack__shutdown__end,
		    netstack_t *, ns);

		mutex_enter(&ns->netstack_lock);
		ns->netstack_m_state[moduleid] &= ~NSS_SHUTDOWN_INPROGRESS;
		ns->netstack_m_state[moduleid] |= NSS_SHUTDOWN_COMPLETED;
		DTRACE_PROBE2(netstack__shutdown__completed,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		return (B_TRUE);
	} else {
		mutex_exit(&ns->netstack_lock);
		return (B_FALSE);
	}
}

/*
 * Call the destroy function for the ns and moduleid if DESTROY_NEEDED
 * is set.
 * When it calls it, it drops the netstack_lock held by the caller,
 * and returns true to tell the caller it needs to re-evalute the
 * state..
 */
static boolean_t
netstack_apply_destroy(kmutex_t *lockp, netstack_t *ns, int moduleid)
{
	netstackid_t stackid;
	void * netstack_module;

	ASSERT(MUTEX_HELD(lockp));
	mutex_enter(&ns->netstack_lock);
	if (ns->netstack_m_state[moduleid] & NSS_DESTROY_NEEDED) {
		ns->netstack_m_state[moduleid] &= ~NSS_DESTROY_NEEDED;
		ns->netstack_m_state[moduleid] |= NSS_DESTROY_INPROGRESS;
		DTRACE_PROBE2(netstack__destroy__inprogress,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		mutex_exit(lockp);

		/* XXX race against unregister? */
		ASSERT(ns_reg[moduleid].nr_destroy != NULL);
		stackid = ns->netstack_stackid;
		netstack_module = ns->netstack_modules[moduleid];
		DTRACE_PROBE2(netstack__destroy__start,
		    netstackid_t, stackid,
		    void *, netstack_module);
		(ns_reg[moduleid].nr_destroy)(stackid, netstack_module);
		DTRACE_PROBE1(netstack__destroy__end,
		    netstack_t *, ns);

		mutex_enter(&ns->netstack_lock);
		ns->netstack_modules[moduleid] = NULL;
		ns->netstack_m_state[moduleid] &= ~NSS_DESTROY_INPROGRESS;
		ns->netstack_m_state[moduleid] |= NSS_DESTROY_COMPLETED;
		DTRACE_PROBE2(netstack__destroy__completed,
		    netstack_t *, ns, int, moduleid);
		mutex_exit(&ns->netstack_lock);
		return (B_TRUE);
	} else {
		mutex_exit(&ns->netstack_lock);
		return (B_FALSE);
	}
}

static void
apply_loop(netstack_t **headp, kmutex_t *lockp,
    boolean_t (*applyfn)(kmutex_t *, netstack_t *, int moduleid))
{
	netstack_t *ns;
	int i;
	boolean_t lock_dropped, result;

	lock_dropped = B_FALSE;
	ns = *headp;
	while (ns != NULL) {
		for (i = 0; i < NS_MAX; i++) {
			result = (applyfn)(lockp, ns, i);
			if (result) {
#ifdef NS_DEBUG
				(void) printf("netstack_do_apply: "
				    "LD for %p/%d, %d\n",
				    (void *)ns, ns->netstack_stackid, i);
#endif
				lock_dropped = B_TRUE;
				mutex_enter(lockp);
			}
		}
		/*
		 * If at least one applyfn call caused lockp to be dropped,
		 * then we don't follow netstack_next after reacquiring the
		 * lock, even if it is possible to do so without any hazards.
		 * This is because we want the design to allow for the list of
		 * netstacks threaded by netstack_next to change in any
		 * arbitrary way during the time the 'lockp' was dropped.
		 *
		 * It is safe to restart the loop at *headp since
		 * the applyfn changes netstack_m_state as it processes
		 * things, so a subsequent pass through will have no
		 * effect in applyfn, hence the loop will terminate
		 * in at worst O(N^2).
		 */
		if (lock_dropped) {
#ifdef NS_DEBUG
			(void) printf("netstack_do_apply: "
			    "Lock Dropped for %p/%d, %d\n",
			    (void *)ns, ns->netstack_stackid, i);
#endif
			lock_dropped = B_FALSE;
			ns = *headp;
		} else {
			ns = ns->netstack_next;
		}
	}
}

/* Like above, but in the reverse order of moduleids */
static void
apply_loop_reverse(netstack_t **headp, kmutex_t *lockp,
    boolean_t (*applyfn)(kmutex_t *, netstack_t *, int moduleid))
{
	netstack_t *ns;
	int i;
	boolean_t lock_dropped, result;

	lock_dropped = B_FALSE;
	ns = *headp;
	while (ns != NULL) {
		for (i = NS_MAX-1; i >= 0; i--) {
			result = (applyfn)(lockp, ns, i);
			if (result) {
#ifdef NS_DEBUG
				(void) printf("netstack_do_apply: "
				    "LD for %p/%d, %d\n",
				    (void *)ns, ns->netstack_stackid, i);
#endif
				lock_dropped = B_TRUE;
				mutex_enter(lockp);
			}
		}
		/*
		 * If at least one applyfn call caused lockp to be dropped,
		 * then we don't follow netstack_next after reacquiring the
		 * lock, even if it is possible to do so without any hazards.
		 * This is because we want the design to allow for the list of
		 * netstacks threaded by netstack_next to change in any
		 * arbitrary way during the time the 'lockp' was dropped.
		 *
		 * It is safe to restart the loop at *headp since
		 * the applyfn changes netstack_m_state as it processes
		 * things, so a subsequent pass through will have no
		 * effect in applyfn, hence the loop will terminate
		 * in at worst O(N^2).
		 */
		if (lock_dropped) {
#ifdef NS_DEBUG
			(void) printf("netstack_do_apply: "
			    "Lock Dropped for %p/%d, %d\n",
			    (void *)ns, ns->netstack_stackid, i);
#endif
			lock_dropped = B_FALSE;
			ns = *headp;
		} else {
			ns = ns->netstack_next;
		}
	}
}

/*
 * Apply a function to all module/netstack combinations.
 * The applyfn returns true if it had dropped the locks.
 */
static void
netstack_do_apply(int reverse,
    boolean_t (*applyfn)(kmutex_t *, netstack_t *, int moduleid))
{
	mutex_enter(&netstack_g_lock);
	if (reverse)
		apply_loop_reverse(&netstack_head, &netstack_g_lock, applyfn);
	else
		apply_loop(&netstack_head, &netstack_g_lock, applyfn);
	mutex_exit(&netstack_g_lock);
}

/*
 * Run the create function for all modules x stack combinations
 * that have NSS_CREATE_NEEDED set.
 *
 * Call the create function for each stack that has CREATE_NEEDED.
 * Set CREATE_INPROGRESS, drop lock, and after done,
 * set CREATE_COMPLETE
 */
static void
netstack_do_create(void)
{
	netstack_do_apply(B_FALSE, netstack_apply_create);
}

/*
 * Run the shutdown function for all modules x stack combinations
 * that have NSS_SHUTDOWN_NEEDED set.
 *
 * Call the shutdown function for each stack that has SHUTDOWN_NEEDED.
 * Set SHUTDOWN_INPROGRESS, drop lock, and after done,
 * set SHUTDOWN_COMPLETE
 */
static void
netstack_do_shutdown(void)
{
	netstack_do_apply(B_FALSE, netstack_apply_shutdown);
}

/*
 * Run the destroy function for all modules x stack combinations
 * that have NSS_DESTROY_NEEDED set.
 *
 * Call the destroy function for each stack that has DESTROY_NEEDED.
 * Set DESTROY_INPROGRESS, drop lock, and after done,
 * set DESTROY_COMPLETE
 *
 * Since a netstack_t is never reused (when a zone is rebooted it gets
 * a new zoneid == netstackid i.e. a new netstack_t is allocated) we leave
 * netstack_m_state the way it is i.e. with NSS_DESTROY_COMPLETED set.
 */
static void
netstack_do_destroy(void)
{
	/*
	 * Have to walk the moduleids in reverse order since some
	 * modules make implicit assumptions about the order
	 */
	netstack_do_apply(B_TRUE, netstack_apply_destroy);
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
	if (ns->netstack_flags & (NSF_UNINIT|NSF_CLOSING))
		return (NULL);

	netstack_hold(ns);

	return (ns);
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
 * Skip the unitialized ones.
 */
netstack_t *
netstack_find_by_zoneid(zoneid_t zoneid)
{
	netstack_t *ns;
	zone_t *zone;

	zone = zone_find_by_id(zoneid);

	if (zone == NULL)
		return (NULL);

	ns = zone->zone_netstack;
	ASSERT(ns != NULL);
	if (ns->netstack_flags & (NSF_UNINIT|NSF_CLOSING))
		ns = NULL;
	else
		netstack_hold(ns);

	zone_rele(zone);
	return (ns);
}

/*
 * Find a stack instance given the zoneid.
 * Increases the reference count if found; caller must do a
 * netstack_rele().
 *
 * If there is no exact match then assume the shared stack instance
 * matches.
 *
 * Skip the unitialized ones.
 *
 * NOTE: The caller must hold zonehash_lock.
 */
netstack_t *
netstack_find_by_zoneid_nolock(zoneid_t zoneid)
{
	netstack_t *ns;
	zone_t *zone;

	zone = zone_find_by_id_nolock(zoneid);

	if (zone == NULL)
		return (NULL);

	ns = zone->zone_netstack;
	ASSERT(ns != NULL);

	if (ns->netstack_flags & (NSF_UNINIT|NSF_CLOSING))
		ns = NULL;
	else
		netstack_hold(ns);

	zone_rele(zone);
	return (ns);
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
		mutex_enter(&ns->netstack_lock);
		if (ns->netstack_stackid == stackid &&
		    !(ns->netstack_flags & (NSF_UNINIT|NSF_CLOSING))) {
			mutex_exit(&ns->netstack_lock);
			netstack_hold(ns);
			mutex_exit(&netstack_g_lock);
			return (ns);
		}
		mutex_exit(&ns->netstack_lock);
	}
	mutex_exit(&netstack_g_lock);
	return (NULL);
}

void
netstack_rele(netstack_t *ns)
{
	netstack_t **nsp;
	boolean_t found;
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
		 * Time to call the destroy functions and free up
		 * the structure
		 */
		netstack_stack_inactive(ns);

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

		ASSERT(ns->netstack_flags & NSF_CLOSING);
		kmem_free(ns, sizeof (*ns));
	}
}

void
netstack_hold(netstack_t *ns)
{
	mutex_enter(&ns->netstack_lock);
	ns->netstack_refcnt++;
	ASSERT(ns->netstack_refcnt > 0);
	mutex_exit(&ns->netstack_lock);
	DTRACE_PROBE1(netstack__inc__ref, netstack_t *, ns);
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
 * XXX could add checks that the stackid/zoneids are valid...
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
	/* skip those with that aren't really here */
	while (ns != NULL) {
		mutex_enter(&ns->netstack_lock);
		if ((ns->netstack_flags & (NSF_UNINIT|NSF_CLOSING)) == 0) {
			mutex_exit(&ns->netstack_lock);
			break;
		}
		mutex_exit(&ns->netstack_lock);
		end++;
		ns = ns->netstack_next;
	}
	if (ns != NULL) {
		*handle = end + 1;
		netstack_hold(ns);
	}
	mutex_exit(&netstack_g_lock);
	return (ns);
}
