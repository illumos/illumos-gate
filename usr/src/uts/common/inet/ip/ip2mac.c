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

/*
 * Functions to implement IP address -> link layer address (PSARC 2006/482)
 */
#include <inet/ip2mac.h>
#include <inet/ip2mac_impl.h>
#include <sys/zone.h>
#include <sys/dlpi.h>
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <inet/ip6.h>

/*
 * dispatch pending callbacks.
 */
void
nce_cb_dispatch(nce_t *nce)
{
	nce_cb_t *nce_cb = list_head(&nce->nce_cb);
	ip2mac_t ip2m;

	mutex_enter(&nce->nce_lock);
	if (list_is_empty(&nce->nce_cb)) {
		mutex_exit(&nce->nce_lock);
		return;
	}
	nce_ip2mac_response(&ip2m, nce);
	nce_cb_refhold_locked(nce);
	/*
	 * IP does not hold internal locks like nce_lock across calls to
	 * other subsystems for fear of recursive lock entry and lock
	 * hierarchy violation. The caller may be holding locks across
	 * the call to IP. (It would be ideal if no subsystem holds locks
	 * across calls into another subsystem, especially if calls can
	 * happen in either direction).
	 */
	nce_cb = list_head(&nce->nce_cb);
	for (; nce_cb != NULL; nce_cb = list_next(&nce->nce_cb, nce_cb)) {
		if (nce_cb->nce_cb_flags & NCE_CB_DISPATCHED)
			continue;
		nce_cb->nce_cb_flags |= NCE_CB_DISPATCHED;
		mutex_exit(&nce->nce_lock);
		(*nce_cb->nce_cb_func)(&ip2m, nce_cb->nce_cb_arg);
		mutex_enter(&nce->nce_lock);
	}
	nce_cb_refrele(nce);
	mutex_exit(&nce->nce_lock);
}

/*
 * fill up the ip2m response fields with inforamation from the nce.
 */
void
nce_ip2mac_response(ip2mac_t *ip2m, nce_t *nce)
{
	boolean_t isv6 = (nce->nce_ipversion == IPV6_VERSION);
	sin6_t	*sin6;
	struct sockaddr_dl *sdl;
	uchar_t *nce_lladdr;

	ASSERT(MUTEX_HELD(&nce->nce_lock));
	bzero(ip2m, sizeof (*ip2m));
	if (NCE_ISREACHABLE(nce) && (nce->nce_flags & NCE_F_CONDEMNED) == 0)
		ip2m->ip2mac_err = 0;
	else
		ip2m->ip2mac_err = ESRCH;
	if (isv6) {
		sin6 = (sin6_t *)&ip2m->ip2mac_pa;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = nce->nce_addr;
	}
	if (ip2m->ip2mac_err == 0) {
		sdl = &ip2m->ip2mac_ha;
		sdl->sdl_family = AF_LINK;
		sdl->sdl_type = nce->nce_ill->ill_type;
		sdl->sdl_nlen = 0;
		sdl->sdl_alen = nce->nce_ill->ill_phys_addr_length;
		nce_lladdr = nce->nce_res_mp->b_rptr +
		    NCE_LL_ADDR_OFFSET(nce->nce_ill);
		bcopy(nce_lladdr, LLADDR(sdl), sdl->sdl_alen);
	}
}

void
nce_cb_refhold_locked(nce_t *nce)
{
	ASSERT(MUTEX_HELD(&nce->nce_lock));
	nce->nce_cb_walker_cnt++;
}

void
nce_cb_refrele(nce_t *nce)
{
	nce_cb_t *nce_cb, *nce_cb_next = NULL;

	ASSERT(MUTEX_HELD(&nce->nce_lock));
	if (--nce->nce_cb_walker_cnt == 0) {
		for (nce_cb = list_head(&nce->nce_cb); nce_cb != NULL;
		    nce_cb = nce_cb_next) {

			nce_cb_next = list_next(&nce->nce_cb, nce_cb);
			if ((nce_cb->nce_cb_flags & NCE_CB_DISPATCHED) == 0)
				continue;
			list_remove(&nce->nce_cb, nce_cb);
			kmem_free(nce_cb, sizeof (*nce_cb));
		}
	}
}

/*
 * add a callback to the nce, so that the callback can be invoked
 * after address resolution succeeds/fails.
 */
static ip2mac_id_t
nce_add_cb(nce_t *nce, ip2mac_callback_t *cb, void *cbarg)
{
	nce_cb_t	*nce_cb;
	ip2mac_id_t	ip2mid = NULL;

	ASSERT(MUTEX_HELD(&nce->nce_lock));
	if ((nce_cb = kmem_zalloc(sizeof (*nce_cb), KM_NOSLEEP)) == NULL)
		return (ip2mid);
	nce_cb->nce_cb_func = cb;
	nce_cb->nce_cb_arg = cbarg;
	/*
	 * We identify the nce_cb_t during cancellation by the address
	 * of the nce_cb_t itself, and, as a short-cut for eliminating
	 * clear mismatches, only look in the callback list of nce's
	 * whose address is equal to the nce_cb_id.
	 */
	nce_cb->nce_cb_id = nce; /* no refs! just an address */
	list_insert_tail(&nce->nce_cb, nce_cb);
	ip2mid = nce;  /* this is the id to be used in ip2mac_cancel */

	return (nce_cb);
}

/*
 * Resolve an IP address to a link-layer address using the data-structures
 * defined in PSARC 2006/482. If the current link-layer address for the
 * IP address is not known, the state-machine for resolving the resolution
 * will be triggered, and the callback function (*cb) will be invoked after
 * the resolution completes.
 */
ip2mac_id_t
ip2mac(uint_t flags, ip2mac_t *ip2m, ip2mac_callback_t *cb, void *cbarg,
    zoneid_t zoneid)
{
	nce_t		*nce;
	boolean_t	isv6;
	ill_t		*ill;
	netstack_t	*ns;
	ip_stack_t	*ipst;
	ip2mac_id_t	ip2mid = NULL;
	sin6_t		*sin6;
	int		err;
	uint64_t	delta;

	isv6 = (ip2m->ip2mac_pa.ss_family == AF_INET6);

	if (!isv6) {
		/*
		 * IPv4 is not currently supported.
		 */
		ip2m->ip2mac_err = ENOTSUP;
		return (NULL);
	}

	ns = netstack_find_by_zoneid(zoneid);
	if (ns == NULL) {
		ip2m->ip2mac_err = EINVAL;
		return (NULL);
	}
	/*
	 * For exclusive stacks we reset the zoneid to zero
	 * since IP uses the global zoneid in the exclusive stacks.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	ipst = ns->netstack_ip;
	/*
	 * find the ill from the ip2m->ip2mac_ifindex
	 */
	ill = ill_lookup_on_ifindex(ip2m->ip2mac_ifindex, isv6, NULL,
	    NULL, NULL, NULL, ipst);
	if (ill == NULL) {
		ip2m->ip2mac_err = ENXIO;
		netstack_rele(ns);
		return (NULL);
	}
	if (isv6) {
		sin6 = (sin6_t *)&ip2m->ip2mac_pa;
		if (flags == IP2MAC_LOOKUP) {
			nce = ndp_lookup_v6(ill, B_FALSE, &sin6->sin6_addr,
			    B_FALSE);
		} else {
			err = ndp_lookup_then_add_v6(ill, B_FALSE, NULL,
			    &sin6->sin6_addr, &ipv6_all_ones, &ipv6_all_zeros,
			    0, 0, ND_INCOMPLETE, &nce);
		}
	} else  {
		ip2m->ip2mac_err = ENOTSUP; /* yet. */
		goto done;
	}
	if (flags == IP2MAC_LOOKUP) {
		if (nce == NULL) {
			ip2m->ip2mac_err = ESRCH;
			goto done;
		}
		mutex_enter(&nce->nce_lock);
		if (NCE_ISREACHABLE(nce)) {
			nce_ip2mac_response(ip2m, nce);
			ip2m->ip2mac_err = 0;
		} else {
			ip2m->ip2mac_err = ESRCH;
		}
		mutex_exit(&nce->nce_lock);
		NCE_REFRELE(nce);
		goto done;
	} else {
		if (err != 0 && err != EEXIST) {
			ip2m->ip2mac_err = err;
			goto done;
		}
	}
	delta = TICK_TO_MSEC(lbolt64) - nce->nce_last;
	mutex_enter(&nce->nce_lock);
	if (nce->nce_flags & NCE_F_CONDEMNED) {
		ip2m->ip2mac_err = ESRCH;
	} else if (!NCE_ISREACHABLE(nce) ||
	    delta > (uint64_t)ill->ill_reachable_time) {
		if (NCE_ISREACHABLE(nce)) {
			/*
			 * Since we do not control the packet output
			 * path for ip2mac() callers, we need to verify
			 * if the existing information in the nce is
			 * very old, and retrigger resolution if necessary.
			 * We will not return the existing stale
			 * information until it is verified through a
			 * resolver request/response exchange.
			 *
			 * In the future, we may want to support extensions
			 * that do additional callbacks on link-layer updates,
			 * so that we can return the stale information but
			 * also update the caller if the lladdr changes.
			 */
			nce->nce_rcnt = ill->ill_xmit_count;
			nce->nce_state = ND_PROBE;
			err = 0; /* treat this nce as a new one */
		}
		if (nce->nce_rcnt > 0) {
			/*
			 * Still resolving this nce, so we can
			 * queue the callback information in nce->nce_cb
			 */
			ip2mid = nce_add_cb(nce, cb, cbarg);
			ip2m->ip2mac_err = EINPROGRESS;
		} else {
			/*
			 * Resolution failed.
			 */
			ip2m->ip2mac_err = ESRCH;
		}
	} else {
		nce_ip2mac_response(ip2m, nce);
		ip2m->ip2mac_err = 0;
	}
	if (ip2m->ip2mac_err == EINPROGRESS && err != EEXIST)
		ip_ndp_resolve(nce);
	mutex_exit(&nce->nce_lock);
	NCE_REFRELE(nce);
done:
	netstack_rele(ns);
	ill_refrele(ill);
	return (ip2mid);
}

/*
 * data passed to nce_walk for canceling outstanding callbacks.
 */
typedef struct ip2mac_cancel_data_s {
	ip2mac_id_t ip2m_cancel_id;
	int	ip2m_cancel_err;
} ip2mac_cancel_data_t;

/*
 * callback invoked for each active nce. If the ip2mac_id_t corresponds
 * to an active nce_cb_t in the nce's callback list, we want to remove
 * the callback (if there are no walkers) or return EBUSY to the caller
 */
static int
ip2mac_cancel_callback(nce_t *nce, void *arg)
{
	ip2mac_cancel_data_t *ip2m_wdata = arg;
	nce_cb_t *ip2m_nce_cb = ip2m_wdata->ip2m_cancel_id;
	nce_cb_t *nce_cb;

	if (ip2m_nce_cb->nce_cb_id != nce)
		return (0);

	mutex_enter(&nce->nce_lock);
	if (list_is_empty(&nce->nce_cb)) {
		mutex_exit(&nce->nce_lock);
		return (0);
	}
	/*
	 * IP does not hold internal locks like nce_lock across calls to
	 * other subsystems for fear of recursive lock entry and lock
	 * hierarchy violation. The caller may be holding locks across
	 * the call to IP. (It would be ideal if no subsystem holds locks
	 * across calls into another subsystem, especially if calls can
	 * happen in either direction).
	 */
	nce_cb = list_head(&nce->nce_cb);
	for (; nce_cb != NULL; nce_cb = list_next(&nce->nce_cb, nce_cb)) {
		if (nce_cb != ip2m_nce_cb)
			continue;
		/*
		 * If there are no walkers we can remove the nce_cb.
		 * Otherwise the exiting walker will clean up.
		 */
		if (nce->nce_cb_walker_cnt == 0) {
			list_remove(&nce->nce_cb, nce_cb);
		} else {
			ip2m_wdata->ip2m_cancel_err = EBUSY;
		}
		break;
	}
	mutex_exit(&nce->nce_lock);
	return (0);
}

/*
 * cancel an outstanding timeout set up via ip2mac
 */
int
ip2mac_cancel(ip2mac_id_t ip2mid, zoneid_t zoneid)
{
	netstack_t	*ns;
	ip_stack_t	*ipst;
	ip2mac_cancel_data_t ip2m_wdata;

	ns = netstack_find_by_zoneid(zoneid);
	if (ns == NULL) {
		ip2m_wdata.ip2m_cancel_err = EINVAL;
		return (ip2m_wdata.ip2m_cancel_err);
	}
	/*
	 * For exclusive stacks we reset the zoneid to zero
	 * since IP uses the global zoneid in the exclusive stacks.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	ipst = ns->netstack_ip;

	ip2m_wdata.ip2m_cancel_id = ip2mid;
	ip2m_wdata.ip2m_cancel_err = 0;
	ndp_walk(NULL, ip2mac_cancel_callback, &ip2m_wdata, ipst);
	/*
	 * We may return EBUSY if a walk to dispatch callbacks is
	 * in progress, in which case the caller needs to synchronize
	 * with the registered callback function to make sure the
	 * module does not exit when there is a callback pending.
	 */
	netstack_rele(ns);
	return (ip2m_wdata.ip2m_cancel_err);
}
