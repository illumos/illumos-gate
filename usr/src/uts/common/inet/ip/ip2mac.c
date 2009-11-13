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
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <inet/ip6.h>

/*
 * dispatch pending callbacks.
 */
void
ncec_cb_dispatch(ncec_t *ncec)
{
	ncec_cb_t *ncec_cb;
	ip2mac_t ip2m;

	mutex_enter(&ncec->ncec_lock);
	if (list_is_empty(&ncec->ncec_cb)) {
		mutex_exit(&ncec->ncec_lock);
		return;
	}
	ncec_ip2mac_response(&ip2m, ncec);
	ncec_cb_refhold_locked(ncec);
	/*
	 * IP does not hold internal locks like nce_lock across calls to
	 * other subsystems for fear of recursive lock entry and lock
	 * hierarchy violation. The caller may be holding locks across
	 * the call to IP. (It would be ideal if no subsystem holds locks
	 * across calls into another subsystem, especially if calls can
	 * happen in either direction).
	 */
	ncec_cb = list_head(&ncec->ncec_cb);
	for (; ncec_cb != NULL; ncec_cb = list_next(&ncec->ncec_cb, ncec_cb)) {
		if (ncec_cb->ncec_cb_flags & NCE_CB_DISPATCHED)
			continue;
		ncec_cb->ncec_cb_flags |= NCE_CB_DISPATCHED;
		mutex_exit(&ncec->ncec_lock);
		(*ncec_cb->ncec_cb_func)(&ip2m, ncec_cb->ncec_cb_arg);
		mutex_enter(&ncec->ncec_lock);
	}
	ncec_cb_refrele(ncec);
	mutex_exit(&ncec->ncec_lock);
}

/*
 * fill up the ip2m response fields with inforamation from the nce.
 */
void
ncec_ip2mac_response(ip2mac_t *ip2m, ncec_t *ncec)
{
	boolean_t isv6 = (ncec->ncec_ipversion == IPV6_VERSION);
	sin_t	*sin;
	sin6_t	*sin6;
	struct sockaddr_dl *sdl;

	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	bzero(ip2m, sizeof (*ip2m));
	if (NCE_ISREACHABLE(ncec) && !NCE_ISCONDEMNED(ncec))
		ip2m->ip2mac_err = 0;
	else
		ip2m->ip2mac_err = ESRCH;
	if (isv6) {
		sin6 = (sin6_t *)&ip2m->ip2mac_pa;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = ncec->ncec_addr;
	} else {
		sin = (sin_t *)&ip2m->ip2mac_pa;
		sin->sin_family = AF_INET;
		IN6_V4MAPPED_TO_INADDR(&ncec->ncec_addr, &sin->sin_addr);
	}
	if (ip2m->ip2mac_err == 0) {
		sdl = &ip2m->ip2mac_ha;
		sdl->sdl_family = AF_LINK;
		sdl->sdl_type = ncec->ncec_ill->ill_type;
		/*
		 * should we put ncec_ill->ill_name in there? why?
		 * likewise for the sdl_index
		 */
		sdl->sdl_nlen = 0;
		sdl->sdl_alen = ncec->ncec_ill->ill_phys_addr_length;
		if (ncec->ncec_lladdr != NULL)
			bcopy(ncec->ncec_lladdr, LLADDR(sdl), sdl->sdl_alen);
	}
}

void
ncec_cb_refhold_locked(ncec_t *ncec)
{
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	ncec->ncec_cb_walker_cnt++;
}

void
ncec_cb_refrele(ncec_t *ncec)
{
	ncec_cb_t *ncec_cb, *ncec_cb_next = NULL;

	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	if (--ncec->ncec_cb_walker_cnt == 0) {
		for (ncec_cb = list_head(&ncec->ncec_cb); ncec_cb != NULL;
		    ncec_cb = ncec_cb_next) {

			ncec_cb_next = list_next(&ncec->ncec_cb, ncec_cb);
			if ((ncec_cb->ncec_cb_flags & NCE_CB_DISPATCHED) == 0)
				continue;
			list_remove(&ncec->ncec_cb, ncec_cb);
			kmem_free(ncec_cb, sizeof (*ncec_cb));
		}
	}
}

/*
 * add a callback to the nce, so that the callback can be invoked
 * after address resolution succeeds/fails.
 */
static ip2mac_id_t
ncec_add_cb(ncec_t *ncec, ip2mac_callback_t *cb, void *cbarg)
{
	ncec_cb_t	*nce_cb;
	ip2mac_id_t	ip2mid = NULL;

	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	if ((nce_cb = kmem_zalloc(sizeof (*nce_cb), KM_NOSLEEP)) == NULL)
		return (ip2mid);
	nce_cb->ncec_cb_func = cb;
	nce_cb->ncec_cb_arg = cbarg;
	/*
	 * We identify the ncec_cb_t during cancellation by the address
	 * of the nce_cb_t itself, and, as a short-cut for eliminating
	 * clear mismatches, only look in the callback list of ncec's
	 * whose address is equal to the nce_cb_id.
	 */
	nce_cb->ncec_cb_id = ncec; /* no refs! just an address */
	list_insert_tail(&ncec->ncec_cb, nce_cb);
	ip2mid = ncec;  /* this is the id to be used in ip2mac_cancel */

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
ip2mac(uint_t op, ip2mac_t *ip2m, ip2mac_callback_t *cb, void *cbarg,
    zoneid_t zoneid)
{
	ncec_t		*ncec;
	nce_t		*nce = NULL;
	boolean_t	isv6;
	ill_t		*ill;
	netstack_t	*ns;
	ip_stack_t	*ipst;
	ip2mac_id_t	ip2mid = NULL;
	sin_t		*sin;
	sin6_t		*sin6;
	int		err;
	uint64_t	delta;
	boolean_t	need_resolve = B_FALSE;

	isv6 = (ip2m->ip2mac_pa.ss_family == AF_INET6);

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
	ill = ill_lookup_on_ifindex(ip2m->ip2mac_ifindex, isv6, ipst);
	if (ill == NULL) {
		ip2m->ip2mac_err = ENXIO;
		netstack_rele(ns);
		return (NULL);
	}
	if (isv6) {
		sin6 = (sin6_t *)&ip2m->ip2mac_pa;
		if (op == IP2MAC_LOOKUP) {
			nce = nce_lookup_v6(ill, &sin6->sin6_addr);
		} else {
			err = nce_lookup_then_add_v6(ill, NULL,
			    ill->ill_phys_addr_length,
			    &sin6->sin6_addr, 0, ND_UNCHANGED, &nce);
		}
	} else  {
		sin = (sin_t *)&ip2m->ip2mac_pa;
		if (op == IP2MAC_LOOKUP) {
			nce = nce_lookup_v4(ill, &sin->sin_addr.s_addr);
		} else {
			err = nce_lookup_then_add_v4(ill, NULL,
			    ill->ill_phys_addr_length,
			    &sin->sin_addr.s_addr, 0, ND_UNCHANGED, &nce);
		}
	}
	if (op == IP2MAC_LOOKUP) {
		if (nce == NULL) {
			ip2m->ip2mac_err = ESRCH;
			goto done;
		}
		ncec = nce->nce_common;
		delta = TICK_TO_MSEC(ddi_get_lbolt64()) - ncec->ncec_last;
		mutex_enter(&ncec->ncec_lock);
		if (NCE_ISREACHABLE(ncec) &&
		    delta < (uint64_t)ill->ill_reachable_time) {
			ncec_ip2mac_response(ip2m, ncec);
			ip2m->ip2mac_err = 0;
		} else {
			ip2m->ip2mac_err = ESRCH;
		}
		mutex_exit(&ncec->ncec_lock);
		goto done;
	} else {
		if (err != 0 && err != EEXIST) {
			ip2m->ip2mac_err = err;
			goto done;
		}
	}
	ncec = nce->nce_common;
	delta = TICK_TO_MSEC(ddi_get_lbolt64()) - ncec->ncec_last;
	mutex_enter(&ncec->ncec_lock);
	if (NCE_ISCONDEMNED(ncec)) {
		ip2m->ip2mac_err = ESRCH;
	} else {
		if (NCE_ISREACHABLE(ncec)) {
			if (NCE_MYADDR(ncec) ||
			    delta < (uint64_t)ill->ill_reachable_time) {
				ncec_ip2mac_response(ip2m, ncec);
				ip2m->ip2mac_err = 0;
				mutex_exit(&ncec->ncec_lock);
				goto done;
			}
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
			ncec->ncec_rcnt = ill->ill_xmit_count;
			ncec->ncec_state = ND_PROBE;
			need_resolve = B_TRUE; /* reachable but very old nce */
		} else if (ncec->ncec_state == ND_INITIAL) {
			need_resolve = B_TRUE; /* ND_INITIAL nce */
			ncec->ncec_state = ND_INCOMPLETE;
		}
		/*
		 * NCE not known to be reachable in the recent past. We must
		 * reconfirm the information before returning it to the caller
		 */
		if (ncec->ncec_rcnt > 0) {
			/*
			 * Still resolving this ncec, so we can queue the
			 * callback information in ncec->ncec_cb
			 */
			ip2mid = ncec_add_cb(ncec, cb, cbarg);
			ip2m->ip2mac_err = EINPROGRESS;
		} else {
			/*
			 * No more retransmits allowed -- resolution failed.
			 */
			ip2m->ip2mac_err = ESRCH;
		}
	}
	mutex_exit(&ncec->ncec_lock);
done:
	/*
	 * if NCE_ISREACHABLE(ncec) but very old, or if it is ND_INITIAL,
	 * trigger resolve.
	 */
	if (need_resolve)
		ip_ndp_resolve(ncec);
	if (nce != NULL)
		nce_refrele(nce);
	netstack_rele(ns);
	ill_refrele(ill);
	return (ip2mid);
}

/*
 * data passed to ncec_walk for canceling outstanding callbacks.
 */
typedef struct ip2mac_cancel_data_s {
	ip2mac_id_t ip2m_cancel_id;
	int	ip2m_cancel_err;
} ip2mac_cancel_data_t;

/*
 * callback invoked for each active ncec. If the ip2mac_id_t corresponds
 * to an active nce_cb_t in the ncec's callback list, we want to remove
 * the callback (if there are no walkers) or return EBUSY to the caller
 */
static int
ip2mac_cancel_callback(ncec_t *ncec, void *arg)
{
	ip2mac_cancel_data_t *ip2m_wdata = arg;
	ncec_cb_t *ip2m_nce_cb = ip2m_wdata->ip2m_cancel_id;
	ncec_cb_t *ncec_cb;

	if (ip2m_nce_cb->ncec_cb_id != ncec)
		return (0);

	mutex_enter(&ncec->ncec_lock);
	if (list_is_empty(&ncec->ncec_cb)) {
		mutex_exit(&ncec->ncec_lock);
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
	ncec_cb = list_head(&ncec->ncec_cb);
	for (; ncec_cb != NULL; ncec_cb = list_next(&ncec->ncec_cb, ncec_cb)) {
		if (ncec_cb != ip2m_nce_cb)
			continue;
		/*
		 * If there are no walkers we can remove the nce_cb.
		 * Otherwise the exiting walker will clean up.
		 */
		if (ncec->ncec_cb_walker_cnt == 0) {
			list_remove(&ncec->ncec_cb, ncec_cb);
		} else {
			ip2m_wdata->ip2m_cancel_err = EBUSY;
		}
		break;
	}
	mutex_exit(&ncec->ncec_lock);
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
	ncec_walk(NULL, ip2mac_cancel_callback, &ip2m_wdata, ipst);
	/*
	 * We may return EBUSY if a walk to dispatch callbacks is
	 * in progress, in which case the caller needs to synchronize
	 * with the registered callback function to make sure the
	 * module does not exit when there is a callback pending.
	 */
	netstack_rele(ns);
	return (ip2m_wdata.ip2m_cancel_err);
}
