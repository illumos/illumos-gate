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
 *
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */

/*
 * This is used to support the hidden __sin6_src_id in the sockaddr_in6
 * structure which is there to ensure that applications (such as UDP apps)
 * which get an address from recvfrom and use that address in a sendto
 * or connect will by default use the same source address in the "response"
 * as the destination address in the "request" they received.
 *
 * This is built using some new functions (in IP - doing their own locking
 * so they can be called from the transports) to map between integer IDs
 * and in6_addr_t.
 * The use applies to sockaddr_in6 - whether or not mapped addresses are used.
 *
 * This file contains the functions used by both IP and the transports
 * to implement __sin6_src_id.
 * The routines do their own locking since they are called from
 * the transports (to map between a source id and an address)
 * and from IP proper when IP addresses are added and removed.
 *
 * The routines handle both IPv4 and IPv6 with the IPv4 addresses represented
 * as IPv4-mapped addresses.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strlog.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/xti_inet.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <sys/zone.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/callb.h>
#include <sys/socket.h>
#include <sys/vtrace.h>
#include <sys/isa_defs.h>
#include <sys/kmem.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if_dl.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/arp.h>
#include <inet/snmpcom.h>

#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/optcom.h>
#include <inet/ip_ndp.h>
#include <netinet/igmp.h>
#include <netinet/ip_mroute.h>
#include <inet/ipclassifier.h>

#include <sys/kmem.h>

static uint_t		srcid_nextid(ip_stack_t *);
static srcid_map_t	**srcid_lookup_addr(const in6_addr_t *addr,
    zoneid_t zoneid, ip_stack_t *);
static srcid_map_t	**srcid_lookup_id(uint_t id, ip_stack_t *);


/*
 * Insert/add a new address to the map.
 * Returns zero if ok; otherwise errno (e.g. for memory allocation failure).
 */
int
ip_srcid_insert(const in6_addr_t *addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	srcid_map_t	**smpp;
#ifdef DEBUG
	char		abuf[INET6_ADDRSTRLEN];

	ip1dbg(("ip_srcid_insert(%s, %d)\n",
	    inet_ntop(AF_INET6, addr, abuf, sizeof (abuf)), zoneid));
#endif

	rw_enter(&ipst->ips_srcid_lock, RW_WRITER);
	smpp = srcid_lookup_addr(addr, zoneid, ipst);
	if (*smpp != NULL) {
		/* Already present - increment refcount */
		(*smpp)->sm_refcnt++;
		ASSERT((*smpp)->sm_refcnt != 0);	/* wraparound */
		rw_exit(&ipst->ips_srcid_lock);
		return (0);
	}
	/* Insert new */
	*smpp = kmem_alloc(sizeof (srcid_map_t), KM_NOSLEEP);
	if (*smpp == NULL) {
		rw_exit(&ipst->ips_srcid_lock);
		return (ENOMEM);
	}
	(*smpp)->sm_next = NULL;
	(*smpp)->sm_addr = *addr;
	(*smpp)->sm_srcid = srcid_nextid(ipst);
	(*smpp)->sm_refcnt = 1;
	(*smpp)->sm_zoneid = zoneid;

	rw_exit(&ipst->ips_srcid_lock);
	return (0);
}

/*
 * Remove an new address from the map.
 * Returns zero if ok; otherwise errno (e.g. for nonexistent address).
 */
int
ip_srcid_remove(const in6_addr_t *addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	srcid_map_t	**smpp;
	srcid_map_t	*smp;
#ifdef DEBUG
	char		abuf[INET6_ADDRSTRLEN];

	ip1dbg(("ip_srcid_remove(%s, %d)\n",
	    inet_ntop(AF_INET6, addr, abuf, sizeof (abuf)), zoneid));
#endif

	rw_enter(&ipst->ips_srcid_lock, RW_WRITER);
	smpp = srcid_lookup_addr(addr, zoneid, ipst);
	smp = *smpp;
	if (smp == NULL) {
		/* Not preset */
		rw_exit(&ipst->ips_srcid_lock);
		return (ENOENT);
	}

	/* Decrement refcount */
	ASSERT(smp->sm_refcnt != 0);
	smp->sm_refcnt--;
	if (smp->sm_refcnt != 0) {
		rw_exit(&ipst->ips_srcid_lock);
		return (0);
	}
	/* Remove entry */
	*smpp = smp->sm_next;
	rw_exit(&ipst->ips_srcid_lock);
	smp->sm_next = NULL;
	kmem_free(smp, sizeof (srcid_map_t));
	return (0);
}

/*
 * Map from an address to a source id.
 * If the address is unknown return the unknown id (zero).
 */
uint_t
ip_srcid_find_addr(const in6_addr_t *addr, zoneid_t zoneid,
    netstack_t *ns)
{
	srcid_map_t	**smpp;
	srcid_map_t	*smp;
	uint_t		id;
	ip_stack_t	*ipst = ns->netstack_ip;

	rw_enter(&ipst->ips_srcid_lock, RW_READER);
	smpp = srcid_lookup_addr(addr, zoneid, ipst);
	smp = *smpp;
	if (smp == NULL) {
		char		abuf[INET6_ADDRSTRLEN];

		/* Not present - could be broadcast or multicast address */
		ip1dbg(("ip_srcid_find_addr: unknown %s in zone %d\n",
		    inet_ntop(AF_INET6, addr, abuf, sizeof (abuf)), zoneid));
		id = 0;
	} else {
		ASSERT(smp->sm_refcnt != 0);
		id = smp->sm_srcid;
	}
	rw_exit(&ipst->ips_srcid_lock);
	return (id);
}

/*
 * Map from a source id to an address.
 * If the id is unknown return the unspecified address.
 *
 * For known IDs, check if the returned address is v4mapped or not, and
 * return B_TRUE if it matches the desired v4mapped state or not.  This
 * prevents a broken app from requesting (via __sin6_src_id) a v4mapped
 * address for a v6 destination, or vice versa.
 *
 * "addr" will not be set if we return B_FALSE.
 */
boolean_t
ip_srcid_find_id(uint_t id, in6_addr_t *addr, zoneid_t zoneid,
    boolean_t v4mapped, netstack_t *ns)
{
	srcid_map_t	**smpp;
	srcid_map_t	*smp;
	ip_stack_t	*ipst = ns->netstack_ip;
	boolean_t	rc;

	rw_enter(&ipst->ips_srcid_lock, RW_READER);
	smpp = srcid_lookup_id(id, ipst);
	smp = *smpp;
	if (smp == NULL || (smp->sm_zoneid != zoneid && zoneid != ALL_ZONES)) {
		/* Not preset */
		ip1dbg(("ip_srcid_find_id: unknown %u or in wrong zone\n", id));
		*addr = ipv6_all_zeros;
		rc = B_TRUE;
	} else {
		ASSERT(smp->sm_refcnt != 0);
		/*
		 * The caller tells us if it expects a v4mapped address.
		 * Use it, along with the property of "addr" to set the rc.
		 */
		if (IN6_IS_ADDR_V4MAPPED(&smp->sm_addr))
			rc = v4mapped;	/* We want a v4mapped address. */
		else
			rc = !v4mapped; /* We don't want a v4mapped address. */

		if (rc)
			*addr = smp->sm_addr;

	}
	rw_exit(&ipst->ips_srcid_lock);
	return (rc);
}

/* Assign the next available ID */
static uint_t
srcid_nextid(ip_stack_t *ipst)
{
	uint_t id;
	srcid_map_t	**smpp;

	ASSERT(rw_owner(&ipst->ips_srcid_lock) == curthread);

	if (!ipst->ips_srcid_wrapped) {
		id = ipst->ips_ip_src_id++;
		if (ipst->ips_ip_src_id == 0)
			ipst->ips_srcid_wrapped = B_TRUE;
		return (id);
	}
	/* Once it wraps we search for an unused ID. */
	for (id = 0; id < 0xffffffff; id++) {
		smpp = srcid_lookup_id(id, ipst);
		if (*smpp == NULL)
			return (id);
	}
	panic("srcid_nextid: No free identifiers!");
	/* NOTREACHED */
}

/*
 * Lookup based on address.
 * Always returns a non-null pointer.
 * If found then *ptr will be the found object.
 * Otherwise *ptr will be NULL and can be used to insert a new object.
 */
static srcid_map_t **
srcid_lookup_addr(const in6_addr_t *addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	srcid_map_t	**smpp;

	ASSERT(RW_LOCK_HELD(&ipst->ips_srcid_lock));
	smpp = &ipst->ips_srcid_head;
	while (*smpp != NULL) {
		if (IN6_ARE_ADDR_EQUAL(&(*smpp)->sm_addr, addr) &&
		    (zoneid == (*smpp)->sm_zoneid || zoneid == ALL_ZONES))
			return (smpp);
		smpp = &(*smpp)->sm_next;
	}
	return (smpp);
}

/*
 * Lookup based on address.
 * Always returns a non-null pointer.
 * If found then *ptr will be the found object.
 * Otherwise *ptr will be NULL and can be used to insert a new object.
 */
static srcid_map_t **
srcid_lookup_id(uint_t id, ip_stack_t *ipst)
{
	srcid_map_t	**smpp;

	ASSERT(RW_LOCK_HELD(&ipst->ips_srcid_lock));
	smpp = &ipst->ips_srcid_head;
	while (*smpp != NULL) {
		if ((*smpp)->sm_srcid == id)
			return (smpp);
		smpp = &(*smpp)->sm_next;
	}
	return (smpp);
}
