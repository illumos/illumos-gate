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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * ipd: Internet packet disturber
 *
 * The purpose of ipd is to simulate congested and lossy networks when they
 * don't actually exist. The features of these congested and lossy networks are
 * events that end up leading to retransmits and thus kicking us out of the
 * TCP/IP fastpath. Since normally this would require us to have an actually
 * congested network, which can be problematic, we instead simulate this
 * behavior.
 *
 * 1. ipd's operations and restrictions
 *
 * ipd currently has facilities to cause IP traffic to be:
 *
 *   - Corrupted with some probability.
 *   - Delayed for a set number of microseconds.
 *   - Dropped with some probability.
 *
 * Each of these features are enabled on a per-zone basic. The current
 * implementation restricts this specifically to exclusive stack zones.
 * Enabling ipd on a given zone causes pfhooks to be installed for that zone's
 * netstack. Because of the nature of ipd, it currently only supports exclusive
 * stack zones and as a further restriction, it only allows the global zone
 * administrative access. ipd can be enabled for the global zone, but doing so
 * will cause all shared-stack zones to also be affected.
 *
 * 2. General architecture and Locking
 *
 * ipd consists of a few components. There is a per netstack data structure that
 * is created and destroyed with the creation and destruction of each exclusive
 * stack zone. Each of these netstacks is stored in a global list which is
 * accessed for control of ipd via ioctls. The following diagram touches on the
 * data structures that are used throughout ipd.
 *
 *   ADMINISTRATIVE			         DATA PATH
 *
 *    +--------+                          +------+       +------+
 *    | ipdadm |                          |  ip  |       | nics |
 *    +--------+                          +------+       +------+
 *       |  ^                                |               |
 *       |  | ioctl(2)                       |               |
 *       V  |                                V               V
 *    +----------+                     +-------------------------+
 *    | /dev/ipd |                     | pfhooks packet callback | == ipd_hook()
 *    +----------+                     +-------------------------+
 *         |                                         |
 *         |                                         |
 *         V                                         |
 *    +----------------+                             |
 *    | list_t ipd_nsl |------+                      |
 *    +----------------+      |                      |
 *                            |                      |
 *                            V     per netstack     V
 *                         +----------------------------+
 *                         |       ipd_nestack_t        |
 *                         +----------------------------+
 *
 * ipd has two different entry points, one is administrative, the other is the
 * data path. The administrative path is accessed by a userland component called
 * ipdadm(1M). It communicates to the kernel component via ioctls to /dev/ipd.
 * If the administrative path enables a specific zone, then the data path will
 * become active for that zone. Any packet that leaves that zone's IP stack or
 * is going to enter it, comes through the callback specified in the hook_t(9S)
 * structure. This will cause each packet to go through ipd_hook().
 *
 * While the locking inside of ipd should be straightforward, unfortunately, the
 * pfhooks subsystem necessarily complicates this a little bit. There are
 * currently three different sets of locks in ipd.
 *
 *   - Global lock N on the netstack list.
 *   - Global lock A on the active count.
 *   - Per-netstack data structure lock Z.
 *
 * # Locking rules
 *
 * L.1a N must always be acquired first and released last
 *
 * If you need to acquire the netstack list lock, either for reading or writing,
 * then N must be acquired first and before any other locks. It may not be
 * dropped before any other lock.
 *
 * L.1b N must only be acquired from the administrative path and zone creation,
 *      shutdown, and destruct callbacks.
 *
 * The data path, e.g. receiving the per-packet callbacks, should never be
 * grabbing the list lock. If it is, then the architecture here needs to be
 * reconsidered.
 *
 * L.2 Z cannot be held across calls to the pfhooks subsystem if packet hooks
 *     are active.
 *
 * The way the pfhooks subsystem is designed is that a reference count is
 * present on the hook_t while it is active. As long as that reference count is
 * non-zero, a call to net_hook_unregister will block until it is lowered.
 * Because the callbacks want the same lock for the netstack that is held by the
 * administrative path calling into net_hook_unregister, we deadlock.
 *
 *  ioctl from ipdadm remove      hook_t cb (from nic)       hook_t cb (from IP)
 *  -----------------------       --------------------       -------------------
 *       |                             |                             |
 *       |                        bump hook_t refcount               |
 *  mutex_enter(ipd_nsl_lock);    enter ipd_hook()          bump hook_t refcount
 *  mutex acquired                mutex_enter(ins->ipdn_lock);       |
 *       |                        mutex acquired            enter ipd_hook()
 *  mutex_enter(ins->ipdn_lock);       |            mutex_enter(ins->ipdn_lock);
 *       |                             |                             |
 *       |                             |                             |
 *       |                        mutex_exit(ins->ipdn_lock);        |
 *       |                             |                             |
 *  mutex acquired                leave ipd_hook()                   |
 *       |                        decrement hook_t refcount          |
 *       |                             |                             |
 *  ipd_teardown_hooks()               |                             |
 *  net_hook_unregister()              |                             |
 *  cv_wait() if recount               |                             |
 *       |                             |                             |
 *  ---------------------------------------------------------------------------
 *
 * At this point, we can see that the second hook callback still doesn't have
 * the mutex, but it has bumped the hook_t refcount. However, it will never
 * acquire the mutex that it needs to finish its operation and decrement the
 * refcount.
 *
 * Obviously, deadlocking is not acceptable, thus the following corollary to the
 * second locking rule:
 *
 * L.2 Corollary: If Z is being released across a call to the pfhooks subsystem,
 *                N must be held.
 *
 * There is currently only one path where we have to worry about this. That is
 * when we are removing a hook, but the zone is not being shutdown, then hooks
 * are currently active. The only place that this currently happens is in
 * ipd_check_hooks().
 *
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/neti.h>
#include <sys/list.h>
#include <sys/ksynch.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/atomic.h>
#include <sys/model.h>
#include <sys/strsun.h>

#include <sys/netstack.h>
#include <sys/hook.h>
#include <sys/hook_event.h>

#include <sys/ipd.h>

#define	IPDN_STATUS_DISABLED	0x1
#define	IPDN_STATUS_ENABLED	0x2
#define	IPDN_STATUS_CONDEMNED	0x4

/*
 * These flags are used to determine whether or not the hooks are registered.
 */
#define	IPDN_HOOK_NONE		0x0
#define	IPDN_HOOK_V4IN		0x1
#define	IPDN_HOOK_V4OUT		0x2
#define	IPDN_HOOK_V6IN		0x4
#define	IPDN_HOOK_V6OUT		0x8
#define	IPDN_HOOK_ALL		0xf

/*
 * Per-netstack kstats.
 */
typedef struct ipd_nskstat {
	kstat_named_t	ink_ndrops;
	kstat_named_t	ink_ncorrupts;
	kstat_named_t	ink_ndelays;
} ipd_nskstat_t;

/*
 * Different parts of this structure have different locking semantics. The list
 * node is not normally referenced, if it is, one has to hold the ipd_nsl_lock.
 * The following members are read only: ipdn_netid and ipdn_zoneid. The members
 * of the kstat structure are always accessible in the data path, but the
 * counters must be bumped with atomic operations. The ipdn_lock protects every
 * other aspect of this structure. Please see the big theory statement on the
 * requirements for lock ordering.
 */
typedef struct ipd_netstack {
	list_node_t	ipdn_link;		/* link on ipd_nsl */
	netid_t		ipdn_netid;		/* netstack id */
	zoneid_t	ipdn_zoneid;		/* zone id */
	kstat_t		*ipdn_kstat;		/* kstat_t ptr */
	ipd_nskstat_t	ipdn_ksdata;		/* kstat data */
	kmutex_t	ipdn_lock;		/* protects following members */
	int		ipdn_status;		/* status flags */
	net_handle_t	ipdn_v4hdl;		/* IPv4 net handle */
	net_handle_t	ipdn_v6hdl;		/* IPv4 net handle */
	int		ipdn_hooked;		/* are hooks registered */
	hook_t		*ipdn_v4in;		/* IPv4 traffic in hook */
	hook_t		*ipdn_v4out;		/* IPv4 traffice out hook */
	hook_t		*ipdn_v6in;		/* IPv6 traffic in hook */
	hook_t		*ipdn_v6out;		/* IPv6 traffic out hook */
	int		ipdn_enabled;		/* which perturbs are on */
	int		ipdn_corrupt;		/* corrupt percentage */
	int		ipdn_drop;		/* drop percentage */
	uint_t		ipdn_delay;		/* delay us */
	long		ipdn_rand;		/* random seed */
} ipd_netstack_t;

/*
 * ipd internal variables
 */
static dev_info_t	*ipd_devi;		/* device info */
static net_instance_t	*ipd_neti;		/* net_instance for hooks */
static unsigned int	ipd_max_delay = IPD_MAX_DELAY;	/* max delay in us */
static kmutex_t		ipd_nsl_lock;		/* lock for the nestack list */
static list_t		ipd_nsl;		/* list of netstacks */
static kmutex_t		ipd_nactive_lock;	/* lock for nactive */
static unsigned int	ipd_nactive; 		/* number of active netstacks */
static int		ipd_nactive_fudge = 4;	/* amount to fudge by in list */

/*
 * Note that this random number implementation is based upon the old BSD 4.1
 * rand. It's good enough for us!
 */
static int
ipd_nextrand(ipd_netstack_t *ins)
{
	ins->ipdn_rand = ins->ipdn_rand * 1103515245L + 12345;
	return (ins->ipdn_rand & 0x7fffffff);
}

static void
ipd_ksbump(kstat_named_t *nkp)
{
	atomic_inc_64(&nkp->value.ui64);
}

/*
 * This is where all the magic actually happens. The way that this works is we
 * grab the ins lock to basically get a copy of all the data that we need to do
 * our job and then let it go to minimize contention. In terms of actual work on
 * the packet we do them in the following order:
 *
 * - drop
 * - delay
 * - corrupt
 */
/*ARGSUSED*/
static int
ipd_hook(hook_event_token_t event, hook_data_t data, void *arg)
{
	unsigned char *crp;
	int dwait, corrupt, drop, rand, off, status;
	mblk_t *mbp;
	ipd_netstack_t *ins = arg;
	hook_pkt_event_t *pkt = (hook_pkt_event_t *)data;

	mutex_enter(&ins->ipdn_lock);
	status = ins->ipdn_status;
	dwait = ins->ipdn_delay;
	corrupt = ins->ipdn_corrupt;
	drop = ins->ipdn_drop;
	rand = ipd_nextrand(ins);
	mutex_exit(&ins->ipdn_lock);

	/*
	 * This probably cannot happen, but we'll do an extra guard just in
	 * case.
	 */
	if (status & IPDN_STATUS_CONDEMNED)
		return (0);

	if (drop != 0 && rand % 100 < drop) {
		freemsg(*pkt->hpe_mp);
		*pkt->hpe_mp = NULL;
		pkt->hpe_mb = NULL;
		pkt->hpe_hdr = NULL;
		ipd_ksbump(&ins->ipdn_ksdata.ink_ndrops);

		return (1);
	}

	if (dwait != 0) {
		if (dwait < TICK_TO_USEC(1))
			drv_usecwait(dwait);
		else
			delay(drv_usectohz(dwait));
		ipd_ksbump(&ins->ipdn_ksdata.ink_ndelays);
	}

	if (corrupt != 0 && rand % 100 < corrupt) {
		/*
		 * Since we're corrupting the mblk, just corrupt everything in
		 * the chain. While we could corrupt the entire packet, that's a
		 * little strong. Instead we're going to just change one of the
		 * bytes in each mblock.
		 */
		mbp = *pkt->hpe_mp;
		while (mbp != NULL) {
			if (mbp->b_wptr == mbp->b_rptr)
				continue;

			/*
			 * While pfhooks probably won't send us anything else,
			 * let's just be extra careful. The stack probably isn't
			 * as resiliant to corruption of control messages.
			 */
			if (DB_TYPE(mbp) != M_DATA)
				continue;

			off = rand % ((uintptr_t)mbp->b_wptr -
			    (uintptr_t)mbp->b_rptr);
			crp = mbp->b_rptr + off;
			off = rand % 8;
			*crp = *crp ^ (1 << off);

			mbp = mbp->b_cont;
		}
		ipd_ksbump(&ins->ipdn_ksdata.ink_ncorrupts);
	}

	return (0);
}

/*
 * Sets up and registers all the proper hooks needed for the netstack to capture
 * packets. Callers are assumed to already be holding the ipd_netstack_t's lock.
 * If there is a failure in setting something up, it is the responsibility of
 * this function to clean it up. Once this function has been called, it should
 * not be called until a corresponding call to tear down the hooks has been
 * done.
 */
static int
ipd_setup_hooks(ipd_netstack_t *ins)
{
	ASSERT(MUTEX_HELD(&ins->ipdn_lock));
	ins->ipdn_v4hdl = net_protocol_lookup(ins->ipdn_netid, NHF_INET);
	if (ins->ipdn_v4hdl == NULL)
		goto cleanup;

	ins->ipdn_v6hdl = net_protocol_lookup(ins->ipdn_netid, NHF_INET6);
	if (ins->ipdn_v6hdl == NULL)
		goto cleanup;

	ins->ipdn_v4in = hook_alloc(HOOK_VERSION);
	if (ins->ipdn_v4in == NULL)
		goto cleanup;

	ins->ipdn_v4in->h_flags = 0;
	ins->ipdn_v4in->h_hint = HH_NONE;
	ins->ipdn_v4in->h_hintvalue = 0;
	ins->ipdn_v4in->h_func = ipd_hook;
	ins->ipdn_v4in->h_arg = ins;
	ins->ipdn_v4in->h_name = "ipd IPv4 in";

	if (net_hook_register(ins->ipdn_v4hdl, NH_PHYSICAL_IN,
	    ins->ipdn_v4in) != 0)
		goto cleanup;
	ins->ipdn_hooked |= IPDN_HOOK_V4IN;

	ins->ipdn_v4out = hook_alloc(HOOK_VERSION);
	if (ins->ipdn_v4out == NULL)
		goto cleanup;
	ins->ipdn_v4out->h_flags = 0;
	ins->ipdn_v4out->h_hint = HH_NONE;
	ins->ipdn_v4out->h_hintvalue = 0;
	ins->ipdn_v4out->h_func = ipd_hook;
	ins->ipdn_v4out->h_arg = ins;
	ins->ipdn_v4out->h_name = "ipd IPv4 out";

	if (net_hook_register(ins->ipdn_v4hdl, NH_PHYSICAL_OUT,
	    ins->ipdn_v4out) != 0)
		goto cleanup;
	ins->ipdn_hooked |= IPDN_HOOK_V4OUT;

	ins->ipdn_v6in = hook_alloc(HOOK_VERSION);
	if (ins->ipdn_v6in == NULL)
		goto cleanup;
	ins->ipdn_v6in->h_flags = 0;
	ins->ipdn_v6in->h_hint = HH_NONE;
	ins->ipdn_v6in->h_hintvalue = 0;
	ins->ipdn_v6in->h_func = ipd_hook;
	ins->ipdn_v6in->h_arg = ins;
	ins->ipdn_v6in->h_name = "ipd IPv6 in";

	if (net_hook_register(ins->ipdn_v6hdl, NH_PHYSICAL_IN,
	    ins->ipdn_v6in) != 0)
		goto cleanup;
	ins->ipdn_hooked |= IPDN_HOOK_V6IN;

	ins->ipdn_v6out = hook_alloc(HOOK_VERSION);
	if (ins->ipdn_v6out == NULL)
		goto cleanup;
	ins->ipdn_v6out->h_flags = 0;
	ins->ipdn_v6out->h_hint = HH_NONE;
	ins->ipdn_v6out->h_hintvalue = 0;
	ins->ipdn_v6out->h_func = ipd_hook;
	ins->ipdn_v6out->h_arg = ins;
	ins->ipdn_v6out->h_name = "ipd IPv6 out";

	if (net_hook_register(ins->ipdn_v6hdl, NH_PHYSICAL_OUT,
	    ins->ipdn_v6out) != 0)
		goto cleanup;
	ins->ipdn_hooked |= IPDN_HOOK_V6OUT;
	mutex_enter(&ipd_nactive_lock);
	ipd_nactive++;
	mutex_exit(&ipd_nactive_lock);

	return (0);

cleanup:
	if (ins->ipdn_hooked & IPDN_HOOK_V6OUT)
		(void) net_hook_unregister(ins->ipdn_v6hdl, NH_PHYSICAL_OUT,
		    ins->ipdn_v6out);

	if (ins->ipdn_hooked & IPDN_HOOK_V6IN)
		(void) net_hook_unregister(ins->ipdn_v6hdl, NH_PHYSICAL_IN,
		    ins->ipdn_v6in);

	if (ins->ipdn_hooked & IPDN_HOOK_V4OUT)
		(void) net_hook_unregister(ins->ipdn_v4hdl, NH_PHYSICAL_OUT,
		    ins->ipdn_v4out);

	if (ins->ipdn_hooked & IPDN_HOOK_V4IN)
		(void) net_hook_unregister(ins->ipdn_v4hdl, NH_PHYSICAL_IN,
		    ins->ipdn_v4in);

	ins->ipdn_hooked = IPDN_HOOK_NONE;

	if (ins->ipdn_v6out != NULL)
		hook_free(ins->ipdn_v6out);

	if (ins->ipdn_v6in != NULL)
		hook_free(ins->ipdn_v6in);

	if (ins->ipdn_v4out != NULL)
		hook_free(ins->ipdn_v4out);

	if (ins->ipdn_v4in != NULL)
		hook_free(ins->ipdn_v4in);

	if (ins->ipdn_v6hdl != NULL)
		(void) net_protocol_release(ins->ipdn_v6hdl);

	if (ins->ipdn_v4hdl != NULL)
		(void) net_protocol_release(ins->ipdn_v4hdl);

	return (1);
}

static void
ipd_teardown_hooks(ipd_netstack_t *ins)
{
	ASSERT(ins->ipdn_hooked == IPDN_HOOK_ALL);
	VERIFY(net_hook_unregister(ins->ipdn_v6hdl, NH_PHYSICAL_OUT,
	    ins->ipdn_v6out) == 0);
	VERIFY(net_hook_unregister(ins->ipdn_v6hdl, NH_PHYSICAL_IN,
	    ins->ipdn_v6in) == 0);
	VERIFY(net_hook_unregister(ins->ipdn_v4hdl, NH_PHYSICAL_OUT,
	    ins->ipdn_v4out) == 0);
	VERIFY(net_hook_unregister(ins->ipdn_v4hdl, NH_PHYSICAL_IN,
	    ins->ipdn_v4in) == 0);

	ins->ipdn_hooked = IPDN_HOOK_NONE;

	hook_free(ins->ipdn_v6out);
	hook_free(ins->ipdn_v6in);
	hook_free(ins->ipdn_v4out);
	hook_free(ins->ipdn_v4in);

	VERIFY(net_protocol_release(ins->ipdn_v6hdl) == 0);
	VERIFY(net_protocol_release(ins->ipdn_v4hdl) == 0);

	mutex_enter(&ipd_nactive_lock);
	ipd_nactive--;
	mutex_exit(&ipd_nactive_lock);
}

static int
ipd_check_hooks(ipd_netstack_t *ins, int type, boolean_t enable)
{
	int olden, rval;
	olden = ins->ipdn_enabled;

	if (enable)
		ins->ipdn_enabled |= type;
	else
		ins->ipdn_enabled &= ~type;

	/*
	 * If hooks were previously enabled.
	 */
	if (olden == 0 && ins->ipdn_enabled != 0) {
		rval = ipd_setup_hooks(ins);
		if (rval != 0) {
			ins->ipdn_enabled &= ~type;
			ASSERT(ins->ipdn_enabled == 0);
			return (rval);
		}

		return (0);
	}

	if (olden != 0 && ins->ipdn_enabled == 0) {
		ASSERT(olden != 0);

		/*
		 * We have to drop the lock here, lest we cause a deadlock.
		 * Unfortunately, there may be hooks that are running and are
		 * actively in flight and we have to call the unregister
		 * function. Due to the hooks framework, if there is an inflight
		 * hook (most likely right now), and we are holding the
		 * netstack's lock, those hooks will never return. This is
		 * unfortunate.
		 *
		 * Because we only come into this path holding the list lock, we
		 * know that only way that someone else can come in and get to
		 * this structure is via the hook callbacks which are going to
		 * only be doing reads. They'll also see that everything has
		 * been disabled and return. So while this is unfortunate, it
		 * should be relatively safe.
		 */
		mutex_exit(&ins->ipdn_lock);
		ipd_teardown_hooks(ins);
		mutex_enter(&ins->ipdn_lock);
		return (0);
	}

	/*
	 * Othwerise, nothing should have changed here.
	 */
	ASSERT((olden == 0) == (ins->ipdn_enabled == 0));
	return (0);
}

static int
ipd_toggle_corrupt(ipd_netstack_t *ins, int percent)
{
	int rval;

	ASSERT(MUTEX_HELD(&ins->ipdn_lock));

	if (percent < 0 || percent > 100)
		return (ERANGE);

	/*
	 * If we've been asked to set the value to a value that we already have,
	 * great, then we're done.
	 */
	if (percent == ins->ipdn_corrupt)
		return (0);

	ins->ipdn_corrupt = percent;
	rval = ipd_check_hooks(ins, IPD_CORRUPT, percent != 0);

	/*
	 * If ipd_check_hooks_failed, that must mean that we failed to set up
	 * the hooks, so we are going to effectively zero out and fail the
	 * request to enable corruption.
	 */
	if (rval != 0)
		ins->ipdn_corrupt = 0;

	return (rval);
}

static int
ipd_toggle_delay(ipd_netstack_t *ins, uint32_t delay)
{
	int rval;

	ASSERT(MUTEX_HELD(&ins->ipdn_lock));

	if (delay > ipd_max_delay)
		return (ERANGE);

	/*
	 * If we've been asked to set the value to a value that we already have,
	 * great, then we're done.
	 */
	if (delay == ins->ipdn_delay)
		return (0);

	ins->ipdn_delay = delay;
	rval = ipd_check_hooks(ins, IPD_DELAY, delay != 0);

	/*
	 * If ipd_check_hooks_failed, that must mean that we failed to set up
	 * the hooks, so we are going to effectively zero out and fail the
	 * request to enable corruption.
	 */
	if (rval != 0)
		ins->ipdn_delay = 0;

	return (rval);
}
static int
ipd_toggle_drop(ipd_netstack_t *ins, int percent)
{
	int rval;

	ASSERT(MUTEX_HELD(&ins->ipdn_lock));

	if (percent < 0 || percent > 100)
		return (ERANGE);

	/*
	 * If we've been asked to set the value to a value that we already have,
	 * great, then we're done.
	 */
	if (percent == ins->ipdn_drop)
		return (0);

	ins->ipdn_drop = percent;
	rval = ipd_check_hooks(ins, IPD_DROP, percent != 0);

	/*
	 * If ipd_check_hooks_failed, that must mean that we failed to set up
	 * the hooks, so we are going to effectively zero out and fail the
	 * request to enable corruption.
	 */
	if (rval != 0)
		ins->ipdn_drop = 0;

	return (rval);
}

static int
ipd_ioctl_perturb(ipd_ioc_perturb_t *ipi, cred_t *cr, intptr_t cmd)
{
	zoneid_t zid;
	ipd_netstack_t *ins;
	int rval = 0;

	/*
	 * If the zone that we're coming from is not the GZ, then we ignore it
	 * completely and then instead just set the zoneid to be that of the
	 * caller. If the zoneid is that of the GZ, then we don't touch this
	 * value.
	 */
	zid = crgetzoneid(cr);
	if (zid != GLOBAL_ZONEID)
		ipi->ipip_zoneid = zid;

	if (zoneid_to_netstackid(ipi->ipip_zoneid) == GLOBAL_NETSTACKID &&
	    zid != GLOBAL_ZONEID)
		return (EPERM);

	/*
	 * We need to hold the ipd_nsl_lock throughout the entire operation,
	 * otherwise someone else could come in and remove us from the list and
	 * free us, e.g. the netstack destroy handler. By holding the lock, we
	 * stop it from being able to do anything wrong.
	 */
	mutex_enter(&ipd_nsl_lock);
	for (ins = list_head(&ipd_nsl); ins != NULL;
	    ins = list_next(&ipd_nsl, ins)) {
		if (ins->ipdn_zoneid == ipi->ipip_zoneid)
			break;
	}

	if (ins == NULL) {
		mutex_exit(&ipd_nsl_lock);
		return (EINVAL);
	}

	mutex_enter(&ins->ipdn_lock);

	if (ins->ipdn_status & IPDN_STATUS_CONDEMNED) {
		rval = ESHUTDOWN;
		goto cleanup;
	}

	switch (cmd) {
	case IPDIOC_CORRUPT:
		rval = ipd_toggle_corrupt(ins, ipi->ipip_arg);
		break;
	case IPDIOC_DELAY:
		rval = ipd_toggle_delay(ins, ipi->ipip_arg);
		break;
	case IPDIOC_DROP:
		rval = ipd_toggle_drop(ins, ipi->ipip_arg);
		break;
	}

cleanup:
	mutex_exit(&ins->ipdn_lock);
	mutex_exit(&ipd_nsl_lock);
	return (rval);
}

static int
ipd_ioctl_remove(ipd_ioc_perturb_t *ipi, cred_t *cr)
{
	zoneid_t zid;
	ipd_netstack_t *ins;
	int rval = 0;

	/*
	 * See ipd_ioctl_perturb for the rational here.
	 */
	zid = crgetzoneid(cr);
	if (zid != GLOBAL_ZONEID)
		ipi->ipip_zoneid = zid;

	if (zoneid_to_netstackid(ipi->ipip_zoneid) == GLOBAL_NETSTACKID &&
	    zid != GLOBAL_ZONEID)
		return (EPERM);

	mutex_enter(&ipd_nsl_lock);
	for (ins = list_head(&ipd_nsl); ins != NULL;
	    ins = list_next(&ipd_nsl, ins)) {
		if (ins->ipdn_zoneid == ipi->ipip_zoneid)
			break;
	}

	if (ins == NULL) {
		mutex_exit(&ipd_nsl_lock);
		return (EINVAL);
	}

	mutex_enter(&ins->ipdn_lock);

	/*
	 * If this is condemned, that means it's very shortly going to be torn
	 * down. In that case, there's no reason to actually do anything here,
	 * as it will all be done rather shortly in the destroy function.
	 * Furthermore, because condemned corresponds with it having hit
	 * shutdown, we know that no more packets can be received by this
	 * netstack. All this translates to a no-op.
	 */
	if (ins->ipdn_status & IPDN_STATUS_CONDEMNED) {
		rval = 0;
		goto cleanup;
	}

	rval = EINVAL;
	/*
	 * Go through and disable the requested pieces. We can safely ignore the
	 * return value of ipd_check_hooks because the removal case should never
	 * fail, we verify that in the hook teardown case.
	 */
	if (ipi->ipip_arg & IPD_CORRUPT) {
		ins->ipdn_corrupt = 0;
		(void) ipd_check_hooks(ins, IPD_CORRUPT, B_FALSE);
		rval = 0;
	}

	if (ipi->ipip_arg & IPD_DELAY) {
		ins->ipdn_delay = 0;
		(void) ipd_check_hooks(ins, IPD_DELAY, B_FALSE);
		rval = 0;
	}

	if (ipi->ipip_arg & IPD_DROP) {
		ins->ipdn_drop = 0;
		(void) ipd_check_hooks(ins, IPD_DROP, B_FALSE);
		rval = 0;
	}

cleanup:
	mutex_exit(&ins->ipdn_lock);
	mutex_exit(&ipd_nsl_lock);
	return (rval);
}

/*
 * When this function is called, the value of the ipil_nzones argument controls
 * how this function works. When called with a value of zero, then we treat that
 * as the caller asking us what's a reasonable number of entries for me to
 * allocate memory for. If the zone is the global zone, then we tell them how
 * many folks are currently active and add a fudge factor. Otherwise the answer
 * is always one.
 *
 * In the non-zero case, we give them that number of zone ids. While this isn't
 * quite ideal as it might mean that someone misses something, this generally
 * won't be an issue, as it involves a rather tight race condition in the
 * current ipdadm implementation.
 */
static int
ipd_ioctl_list(intptr_t arg, cred_t *cr)
{
	zoneid_t zid;
	ipd_ioc_info_t *configs;
	ipd_netstack_t *ins;
	uint_t azones, rzones, nzones, cur;
	int rval = 0;
	STRUCT_DECL(ipd_ioc_list, h);

	STRUCT_INIT(h, get_udatamodel());
	if (ddi_copyin((void *)arg, STRUCT_BUF(h),
	    STRUCT_SIZE(h), 0) != 0)
		return (EFAULT);

	zid = crgetzoneid(cr);

	rzones = STRUCT_FGET(h, ipil_nzones);
	if (rzones == 0) {
		if (zid == GLOBAL_ZONEID) {
			mutex_enter(&ipd_nactive_lock);
			rzones = ipd_nactive + ipd_nactive_fudge;
			mutex_exit(&ipd_nactive_lock);
		} else {
			rzones = 1;
		}
		STRUCT_FSET(h, ipil_nzones, rzones);
		if (ddi_copyout(STRUCT_BUF(h), (void *)arg,
		    STRUCT_SIZE(h), 0) != 0)
			return (EFAULT);

		return (0);
	}

	mutex_enter(&ipd_nsl_lock);
	if (zid == GLOBAL_ZONEID) {
		azones = ipd_nactive;
	} else {
		azones = 1;
	}

	configs = kmem_alloc(sizeof (ipd_ioc_info_t) * azones, KM_SLEEP);
	cur = 0;
	for (ins = list_head(&ipd_nsl); ins != NULL;
	    ins = list_next(&ipd_nsl, ins)) {
		if (ins->ipdn_enabled == 0)
			continue;

		ASSERT(cur < azones);

		if (zid == GLOBAL_ZONEID || zid == ins->ipdn_zoneid) {
			configs[cur].ipii_zoneid = ins->ipdn_zoneid;

			mutex_enter(&ins->ipdn_lock);
			configs[cur].ipii_corrupt = ins->ipdn_corrupt;
			configs[cur].ipii_delay = ins->ipdn_delay;
			configs[cur].ipii_drop = ins->ipdn_drop;
			mutex_exit(&ins->ipdn_lock);

			++cur;
		}

		if (zid != GLOBAL_ZONEID && zid == ins->ipdn_zoneid)
			break;
	}
	mutex_exit(&ipd_nsl_lock);

	ASSERT(zid != GLOBAL_ZONEID || cur == azones);

	if (cur == 0)
		STRUCT_FSET(h, ipil_nzones, 0);
	else
		STRUCT_FSET(h, ipil_nzones, cur);

	nzones = MIN(cur, rzones);
	if (nzones > 0) {
		if (ddi_copyout(configs, STRUCT_FGETP(h, ipil_info),
		    nzones * sizeof (ipd_ioc_info_t), NULL) != 0)
			rval = EFAULT;
	}

	kmem_free(configs, sizeof (ipd_ioc_info_t) * azones);
	if (ddi_copyout(STRUCT_BUF(h), (void *)arg, STRUCT_SIZE(h), 0) != 0)
		return (EFAULT);

	return (rval);
}

static void *
ipd_nin_create(const netid_t id)
{
	ipd_netstack_t *ins;
	ipd_nskstat_t *ink;

	ins = kmem_zalloc(sizeof (ipd_netstack_t), KM_SLEEP);
	ins->ipdn_status = IPDN_STATUS_DISABLED;
	ins->ipdn_netid = id;
	ins->ipdn_zoneid = netstackid_to_zoneid(id);
	ins->ipdn_rand = gethrtime();
	mutex_init(&ins->ipdn_lock, NULL, MUTEX_DRIVER, NULL);

	ins->ipdn_kstat = net_kstat_create(id, "ipd", ins->ipdn_zoneid,
	    "ipd", "net",  KSTAT_TYPE_NAMED,
	    sizeof (ipd_nskstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (ins->ipdn_kstat != NULL) {
		if (ins->ipdn_zoneid != GLOBAL_ZONEID)
			kstat_zone_add(ins->ipdn_kstat, GLOBAL_ZONEID);

		ink = &ins->ipdn_ksdata;
		ins->ipdn_kstat->ks_data = ink;
		kstat_named_init(&ink->ink_ncorrupts, "corrupts",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&ink->ink_ndrops, "drops", KSTAT_DATA_UINT64);
		kstat_named_init(&ink->ink_ndelays, "delays",
		    KSTAT_DATA_UINT64);
		kstat_install(ins->ipdn_kstat);
	}

	mutex_enter(&ipd_nsl_lock);
	list_insert_tail(&ipd_nsl, ins);
	mutex_exit(&ipd_nsl_lock);

	return (ins);
}

static void
ipd_nin_shutdown(const netid_t id, void *arg)
{
	ipd_netstack_t *ins = arg;

	VERIFY(id == ins->ipdn_netid);
	mutex_enter(&ins->ipdn_lock);
	ASSERT(ins->ipdn_status == IPDN_STATUS_DISABLED ||
	    ins->ipdn_status == IPDN_STATUS_ENABLED);
	ins->ipdn_status |= IPDN_STATUS_CONDEMNED;
	if (ins->ipdn_kstat != NULL)
		net_kstat_delete(id, ins->ipdn_kstat);
	mutex_exit(&ins->ipdn_lock);
}

/*ARGSUSED*/
static void
ipd_nin_destroy(const netid_t id, void *arg)
{
	ipd_netstack_t *ins = arg;

	/*
	 * At this point none of the hooks should be able to fire because the
	 * zone has been shutdown and we are in the process of destroying it.
	 * Thus it should not be possible for someone else to come in and grab
	 * our ipd_netstack_t for this zone. Because of that, we know that we
	 * are the only ones who could be running here.
	 */
	mutex_enter(&ipd_nsl_lock);
	list_remove(&ipd_nsl, ins);
	mutex_exit(&ipd_nsl_lock);

	if (ins->ipdn_hooked)
		ipd_teardown_hooks(ins);
	mutex_destroy(&ins->ipdn_lock);
	kmem_free(ins, sizeof (ipd_netstack_t));
}

/*ARGSUSED*/
static int
ipd_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	if (flag & FEXCL || flag & FNDELAY)
		return (EINVAL);

	if (otype != OTYP_CHR)
		return (EINVAL);

	if (!(flag & FREAD && flag & FWRITE))
		return (EINVAL);

	if (secpolicy_ip_config(credp, B_FALSE) != 0)
		return (EPERM);

	return (0);
}

/*ARGSUSED*/
static int
ipd_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	int rval;
	ipd_ioc_perturb_t ipip;

	switch (cmd) {
	case IPDIOC_CORRUPT:
	case IPDIOC_DELAY:
	case IPDIOC_DROP:
		if (ddi_copyin((void *)arg, &ipip, sizeof (ipd_ioc_perturb_t),
		    0) != 0)
			return (EFAULT);
		rval = ipd_ioctl_perturb(&ipip, cr, cmd);
		return (rval);
	case IPDIOC_REMOVE:
		if (ddi_copyin((void *)arg, &ipip, sizeof (ipd_ioc_perturb_t),
		    0) != 0)
			return (EFAULT);
		rval = ipd_ioctl_remove(&ipip, cr);
		return (rval);
	case IPDIOC_LIST:
		/*
		 * Because the list ioctl doesn't have a fixed-size struct due
		 * to needing to pass around a pointer, we instead delegate the
		 * copyin logic to the list code.
		 */
		return (ipd_ioctl_list(arg, cr));
	default:
		break;
	}
	return (ENOTTY);
}

/*ARGSUSED*/
static int
ipd_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	return (0);
}

static int
ipd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	minor_t instance;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ipd_devi != NULL)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if (ddi_create_minor_node(dip, "ipd", S_IFCHR, instance,
	    DDI_PSEUDO, 0) == DDI_FAILURE)
		return (DDI_FAILURE);

	ipd_neti = net_instance_alloc(NETINFO_VERSION);
	if (ipd_neti == NULL) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	/*
	 * Note that these global structures MUST be initialized before we call
	 * net_instance_register, as that will instantly cause us to drive into
	 * the ipd_nin_create callbacks.
	 */
	list_create(&ipd_nsl, sizeof (ipd_netstack_t),
	    offsetof(ipd_netstack_t, ipdn_link));
	mutex_init(&ipd_nsl_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ipd_nactive_lock, NULL, MUTEX_DRIVER, NULL);

	/* Note, net_instance_alloc sets the version. */
	ipd_neti->nin_name = "ipd";
	ipd_neti->nin_create = ipd_nin_create;
	ipd_neti->nin_destroy = ipd_nin_destroy;
	ipd_neti->nin_shutdown = ipd_nin_shutdown;
	if (net_instance_register(ipd_neti) == DDI_FAILURE) {
		net_instance_free(ipd_neti);
		ddi_remove_minor_node(dip, NULL);
	}

	ddi_report_dev(dip);
	ipd_devi = dip;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
ipd_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = ipd_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);
		error = DDI_SUCCESS;
	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

static int
ipd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	mutex_enter(&ipd_nactive_lock);
	if (ipd_nactive > 0) {
		mutex_exit(&ipd_nactive_lock);
		return (EBUSY);
	}
	mutex_exit(&ipd_nactive_lock);
	ASSERT(dip == ipd_devi);
	ddi_remove_minor_node(dip, NULL);
	ipd_devi = NULL;

	if (ipd_neti != NULL) {
		VERIFY(net_instance_unregister(ipd_neti) == 0);
		net_instance_free(ipd_neti);
	}

	mutex_destroy(&ipd_nsl_lock);
	mutex_destroy(&ipd_nactive_lock);
	list_destroy(&ipd_nsl);

	return (DDI_SUCCESS);
}

static struct cb_ops ipd_cb_ops = {
	ipd_open,	/* open */
	ipd_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	ipd_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,		/* streamtab */
	D_NEW | D_MP,	/* Driver compatibility flag */
	CB_REV,		/* rev */
	nodev,		/* aread */
	nodev		/* awrite */
};

static struct dev_ops ipd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	ipd_getinfo,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	ipd_attach,		/* attach */
	ipd_detach,		/* detach */
	nodev,			/* reset */
	&ipd_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Internet packet disturber",
	&ipd_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ (void *)&modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
