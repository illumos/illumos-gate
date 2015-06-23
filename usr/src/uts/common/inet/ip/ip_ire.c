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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 1990 Mentat Inc.
 */

/*
 * This file contains routines that manipulate Internet Routing Entries (IREs).
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>

#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ndp.h>
#include <inet/arp.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/nd.h>
#include <inet/tunables.h>

#include <inet/tcp.h>
#include <inet/ipclassifier.h>
#include <sys/zone.h>
#include <sys/cpuvar.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

struct kmem_cache *rt_entry_cache;

typedef struct nce_clookup_s {
	ipaddr_t ncecl_addr;
	boolean_t ncecl_found;
} nce_clookup_t;

/*
 * Synchronization notes:
 *
 * The fields of the ire_t struct are protected in the following way :
 *
 * ire_next/ire_ptpn
 *
 *	- bucket lock of the forwarding table in which is ire stored.
 *
 * ire_ill, ire_u *except* ire_gateway_addr[v6], ire_mask,
 * ire_type, ire_create_time, ire_masklen, ire_ipversion, ire_flags,
 * ire_bucket
 *
 *	- Set in ire_create_v4/v6 and never changes after that. Thus,
 *	  we don't need a lock whenever these fields are accessed.
 *
 *	- ire_bucket and ire_masklen (also set in ire_create) is set in
 *        ire_add before inserting in the bucket and never
 *        changes after that. Thus we don't need a lock whenever these
 *	  fields are accessed.
 *
 * ire_gateway_addr_v4[v6]
 *
 *	- ire_gateway_addr_v4[v6] is set during ire_create and later modified
 *	  by rts_setgwr[v6]. As ire_gateway_addr is a uint32_t, updates to
 *	  it assumed to be atomic and hence the other parts of the code
 *	  does not use any locks. ire_gateway_addr_v6 updates are not atomic
 *	  and hence any access to it uses ire_lock to get/set the right value.
 *
 * ire_refcnt, ire_identical_ref
 *
 *	- Updated atomically using atomic_add_32
 *
 * ire_ssthresh, ire_rtt_sd, ire_rtt, ire_ib_pkt_count, ire_ob_pkt_count
 *
 *	- Assumes that 32 bit writes are atomic. No locks. ire_lock is
 *	  used to serialize updates to ire_ssthresh, ire_rtt_sd, ire_rtt.
 *
 * ire_generation
 *	- Under ire_lock
 *
 * ire_nce_cache
 *	- Under ire_lock
 *
 * ire_dep_parent (To next IRE in recursive lookup chain)
 *	- Under ips_ire_dep_lock. Write held when modifying. Read held when
 *	  walking. We also hold ire_lock when modifying to allow the data path
 *	  to only acquire ire_lock.
 *
 * ire_dep_parent_generation (Generation number from ire_dep_parent)
 *	- Under ips_ire_dep_lock and/or ire_lock. (A read claim on the dep_lock
 *	  and ire_lock held when modifying)
 *
 * ire_dep_children (From parent to first child)
 * ire_dep_sib_next (linked list of siblings)
 * ire_dep_sib_ptpn (linked list of siblings)
 *	- Under ips_ire_dep_lock. Write held when modifying. Read held when
 *	  walking.
 *
 * As we always hold the bucket locks in all the places while accessing
 * the above values, it is natural to use them for protecting them.
 *
 * We have a forwarding table for IPv4 and IPv6. The IPv6 forwarding table
 * (ip_forwarding_table_v6) is an array of pointers to arrays of irb_t
 * structures. ip_forwarding_table_v6 is allocated dynamically in
 * ire_add_v6. ire_ft_init_lock is used to serialize multiple threads
 * initializing the same bucket. Once a bucket is initialized, it is never
 * de-alloacted. This assumption enables us to access
 * ip_forwarding_table_v6[i] without any locks.
 *
 * The forwarding table for IPv4 is a radix tree whose leaves
 * are rt_entry structures containing the irb_t for the rt_dst. The irb_t
 * for IPv4 is dynamically allocated and freed.
 *
 * Each irb_t - ire bucket structure has a lock to protect
 * a bucket and the ires residing in the bucket have a back pointer to
 * the bucket structure. It also has a reference count for the number
 * of threads walking the bucket - irb_refcnt which is bumped up
 * using the irb_refhold function. The flags irb_marks can be
 * set to IRB_MARK_CONDEMNED indicating that there are some ires
 * in this bucket that are IRE_IS_CONDEMNED and the
 * last thread to leave the bucket should delete the ires. Usually
 * this is done by the irb_refrele function which is used to decrement
 * the reference count on a bucket. See comments above irb_t structure
 * definition in ip.h for further details.
 *
 * The ire_refhold/ire_refrele functions operate on the ire which increments/
 * decrements the reference count, ire_refcnt, atomically on the ire.
 * ire_refcnt is modified only using those functions. Operations on the IRE
 * could be described as follows :
 *
 * CREATE an ire with reference count initialized to 1.
 *
 * ADDITION of an ire holds the bucket lock, checks for duplicates
 * and then adds the ire. ire_add returns the ire after
 * bumping up once more i.e the reference count is 2. This is to avoid
 * an extra lookup in the functions calling ire_add which wants to
 * work with the ire after adding.
 *
 * LOOKUP of an ire bumps up the reference count using ire_refhold
 * function. It is valid to bump up the referece count of the IRE,
 * after the lookup has returned an ire. Following are the lookup
 * functions that return an HELD ire :
 *
 * ire_ftable_lookup[_v6], ire_lookup_multi_ill[_v6]
 *
 * DELETION of an ire holds the bucket lock, removes it from the list
 * and then decrements the reference count for having removed from the list
 * by using the ire_refrele function. If some other thread has looked up
 * the ire, the reference count would have been bumped up and hence
 * this ire will not be freed once deleted. It will be freed once the
 * reference count drops to zero.
 *
 * Add and Delete acquires the bucket lock as RW_WRITER, while all the
 * lookups acquire the bucket lock as RW_READER.
 *
 * The general rule is to do the ire_refrele in the function
 * that is passing the ire as an argument.
 *
 * In trying to locate ires the following points are to be noted.
 *
 * IRE_IS_CONDEMNED signifies that the ire has been logically deleted and is
 * to be ignored when walking the ires using ire_next.
 *
 * Zones note:
 *	Walking IREs within a given zone also walks certain ires in other
 *	zones.  This is done intentionally.  IRE walks with a specified
 *	zoneid are used only when doing informational reports, and
 *	zone users want to see things that they can access. See block
 *	comment in ire_walk_ill_match().
 */

/*
 * The size of the forwarding table.  We will make sure that it is a
 * power of 2 in ip_ire_init().
 * Setable in /etc/system
 */
uint32_t ip6_ftable_hash_size = IP6_FTABLE_HASH_SIZE;

struct	kmem_cache	*ire_cache;
struct	kmem_cache	*ncec_cache;
struct	kmem_cache	*nce_cache;

static ire_t	ire_null;

static ire_t	*ire_add_v4(ire_t *ire);
static void	ire_delete_v4(ire_t *ire);
static void	ire_dep_invalidate_children(ire_t *child);
static void	ire_walk_ipvers(pfv_t func, void *arg, uchar_t vers,
    zoneid_t zoneid, ip_stack_t *);
static void	ire_walk_ill_ipvers(uint_t match_flags, uint_t ire_type,
    pfv_t func, void *arg, uchar_t vers, ill_t *ill);
#ifdef DEBUG
static void	ire_trace_cleanup(const ire_t *);
#endif
static void	ire_dep_incr_generation_locked(ire_t *);

/*
 * Following are the functions to increment/decrement the reference
 * count of the IREs and IRBs (ire bucket).
 *
 * 1) We bump up the reference count of an IRE to make sure that
 *    it does not get deleted and freed while we are using it.
 *    Typically all the lookup functions hold the bucket lock,
 *    and look for the IRE. If it finds an IRE, it bumps up the
 *    reference count before dropping the lock. Sometimes we *may* want
 *    to bump up the reference count after we *looked* up i.e without
 *    holding the bucket lock. So, the ire_refhold function does not assert
 *    on the bucket lock being held. Any thread trying to delete from
 *    the hash bucket can still do so but cannot free the IRE if
 *    ire_refcnt is not 0.
 *
 * 2) We bump up the reference count on the bucket where the IRE resides
 *    (IRB), when we want to prevent the IREs getting deleted from a given
 *    hash bucket. This makes life easier for ire_walk type functions which
 *    wants to walk the IRE list, call a function, but needs to drop
 *    the bucket lock to prevent recursive rw_enters. While the
 *    lock is dropped, the list could be changed by other threads or
 *    the same thread could end up deleting the ire or the ire pointed by
 *    ire_next. ire_refholding the ire or ire_next is not sufficient as
 *    a delete will still remove the ire from the bucket while we have
 *    dropped the lock and hence the ire_next would be NULL. Thus, we
 *    need a mechanism to prevent deletions from a given bucket.
 *
 *    To prevent deletions, we bump up the reference count on the
 *    bucket. If the bucket is held, ire_delete just marks both
 *    the ire and irb as CONDEMNED. When the
 *    reference count on the bucket drops to zero, all the CONDEMNED ires
 *    are deleted. We don't have to bump up the reference count on the
 *    bucket if we are walking the bucket and never have to drop the bucket
 *    lock. Note that irb_refhold does not prevent addition of new ires
 *    in the list. It is okay because addition of new ires will not cause
 *    ire_next to point to freed memory. We do irb_refhold only when
 *    all of the 3 conditions are true :
 *
 *    1) The code needs to walk the IRE bucket from start to end.
 *    2) It may have to drop the bucket lock sometimes while doing (1)
 *    3) It does not want any ires to be deleted meanwhile.
 */

/*
 * Bump up the reference count on the hash bucket - IRB to
 * prevent ires from being deleted in this bucket.
 */
void
irb_refhold(irb_t *irb)
{
	rw_enter(&irb->irb_lock, RW_WRITER);
	irb->irb_refcnt++;
	ASSERT(irb->irb_refcnt != 0);
	rw_exit(&irb->irb_lock);
}

void
irb_refhold_locked(irb_t *irb)
{
	ASSERT(RW_WRITE_HELD(&irb->irb_lock));
	irb->irb_refcnt++;
	ASSERT(irb->irb_refcnt != 0);
}

/*
 * Note: when IRB_MARK_DYNAMIC is not set the irb_t
 * is statically allocated, so that when the irb_refcnt goes to 0,
 * we simply clean up the ire list and continue.
 */
void
irb_refrele(irb_t *irb)
{
	if (irb->irb_marks & IRB_MARK_DYNAMIC) {
		irb_refrele_ftable(irb);
	} else {
		rw_enter(&irb->irb_lock, RW_WRITER);
		ASSERT(irb->irb_refcnt != 0);
		if (--irb->irb_refcnt	== 0 &&
		    (irb->irb_marks & IRB_MARK_CONDEMNED)) {
			ire_t *ire_list;

			ire_list = ire_unlink(irb);
			rw_exit(&irb->irb_lock);
			ASSERT(ire_list != NULL);
			ire_cleanup(ire_list);
		} else {
			rw_exit(&irb->irb_lock);
		}
	}
}


/*
 * Bump up the reference count on the IRE. We cannot assert that the
 * bucket lock is being held as it is legal to bump up the reference
 * count after the first lookup has returned the IRE without
 * holding the lock.
 */
void
ire_refhold(ire_t *ire)
{
	atomic_inc_32(&(ire)->ire_refcnt);
	ASSERT((ire)->ire_refcnt != 0);
#ifdef DEBUG
	ire_trace_ref(ire);
#endif
}

void
ire_refhold_notr(ire_t *ire)
{
	atomic_inc_32(&(ire)->ire_refcnt);
	ASSERT((ire)->ire_refcnt != 0);
}

void
ire_refhold_locked(ire_t *ire)
{
#ifdef DEBUG
	ire_trace_ref(ire);
#endif
	ire->ire_refcnt++;
}

/*
 * Release a ref on an IRE.
 *
 * Must not be called while holding any locks. Otherwise if this is
 * the last reference to be released there is a chance of recursive mutex
 * panic due to ire_refrele -> ipif_ill_refrele_tail -> qwriter_ip trying
 * to restart an ioctl. The one exception is when the caller is sure that
 * this is not the last reference to be released. Eg. if the caller is
 * sure that the ire has not been deleted and won't be deleted.
 *
 * In architectures e.g sun4u, where atomic_add_32_nv is just
 * a cas, we need to maintain the right memory barrier semantics
 * as that of mutex_exit i.e all the loads and stores should complete
 * before the cas is executed. membar_exit() does that here.
 */
void
ire_refrele(ire_t *ire)
{
#ifdef DEBUG
	ire_untrace_ref(ire);
#endif
	ASSERT((ire)->ire_refcnt != 0);
	membar_exit();
	if (atomic_dec_32_nv(&(ire)->ire_refcnt) == 0)
		ire_inactive(ire);
}

void
ire_refrele_notr(ire_t *ire)
{
	ASSERT((ire)->ire_refcnt != 0);
	membar_exit();
	if (atomic_dec_32_nv(&(ire)->ire_refcnt) == 0)
		ire_inactive(ire);
}

/*
 * This function is associated with the IP_IOC_IRE_DELETE[_NO_REPLY]
 * IOCTL[s].  The NO_REPLY form is used by TCP to tell IP that it is
 * having problems reaching a particular destination.
 * This will make IP consider alternate routes (e.g., when there are
 * muliple default routes), and it will also make IP discard any (potentially)
 * stale redirect.
 * Management processes may want to use the version that generates a reply.
 *
 * With the use of NUD like behavior for IPv4/ARP in addition to IPv6
 * this function shouldn't be necessary for IP to recover from a bad redirect,
 * a bad default router (when there are multiple default routers), or
 * a stale ND/ARP entry. But we retain it in any case.
 * For instance, this is helpful when TCP suspects a failure before NUD does.
 */
int
ip_ire_delete(queue_t *q, mblk_t *mp, cred_t *ioc_cr)
{
	uchar_t		*addr_ucp;
	uint_t		ipversion;
	sin_t		*sin;
	sin6_t		*sin6;
	ipaddr_t	v4addr;
	in6_addr_t	v6addr;
	ire_t		*ire;
	ipid_t		*ipid;
	zoneid_t	zoneid;
	ip_stack_t	*ipst;

	ASSERT(q->q_next == NULL);
	zoneid = IPCL_ZONEID(Q_TO_CONN(q));
	ipst = CONNQ_TO_IPST(q);

	/*
	 * Check privilege using the ioctl credential; if it is NULL
	 * then this is a kernel message and therefor privileged.
	 */
	if (ioc_cr != NULL && secpolicy_ip_config(ioc_cr, B_FALSE) != 0)
		return (EPERM);

	ipid = (ipid_t *)mp->b_rptr;

	addr_ucp = mi_offset_param(mp, ipid->ipid_addr_offset,
	    ipid->ipid_addr_length);
	if (addr_ucp == NULL || !OK_32PTR(addr_ucp))
		return (EINVAL);
	switch (ipid->ipid_addr_length) {
	case sizeof (sin_t):
		/*
		 * got complete (sockaddr) address - increment addr_ucp to point
		 * at the ip_addr field.
		 */
		sin = (sin_t *)addr_ucp;
		addr_ucp = (uchar_t *)&sin->sin_addr.s_addr;
		ipversion = IPV4_VERSION;
		break;
	case sizeof (sin6_t):
		/*
		 * got complete (sockaddr) address - increment addr_ucp to point
		 * at the ip_addr field.
		 */
		sin6 = (sin6_t *)addr_ucp;
		addr_ucp = (uchar_t *)&sin6->sin6_addr;
		ipversion = IPV6_VERSION;
		break;
	default:
		return (EINVAL);
	}
	if (ipversion == IPV4_VERSION) {
		/* Extract the destination address. */
		bcopy(addr_ucp, &v4addr, IP_ADDR_LEN);

		ire = ire_ftable_lookup_v4(v4addr, 0, 0, 0, NULL,
		    zoneid, NULL, MATCH_IRE_DSTONLY, 0, ipst, NULL);
	} else {
		/* Extract the destination address. */
		bcopy(addr_ucp, &v6addr, IPV6_ADDR_LEN);

		ire = ire_ftable_lookup_v6(&v6addr, NULL, NULL, 0, NULL,
		    zoneid, NULL, MATCH_IRE_DSTONLY, 0, ipst, NULL);
	}
	if (ire != NULL) {
		if (ipversion == IPV4_VERSION) {
			ip_rts_change(RTM_LOSING, ire->ire_addr,
			    ire->ire_gateway_addr, ire->ire_mask,
			    (Q_TO_CONN(q))->conn_laddr_v4,  0, 0, 0,
			    (RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFA),
			    ire->ire_ipst);
		}
		(void) ire_no_good(ire);
		ire_refrele(ire);
	}
	return (0);
}

/*
 * Initialize the ire that is specific to IPv4 part and call
 * ire_init_common to finish it.
 * Returns zero or errno.
 */
int
ire_init_v4(ire_t *ire, uchar_t *addr, uchar_t *mask, uchar_t *gateway,
    ushort_t type, ill_t *ill, zoneid_t zoneid, uint_t flags,
    tsol_gc_t *gc, ip_stack_t *ipst)
{
	int error;

	/*
	 * Reject IRE security attribute creation/initialization
	 * if system is not running in Trusted mode.
	 */
	if (gc != NULL && !is_system_labeled())
		return (EINVAL);

	BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_alloced);

	if (addr != NULL)
		bcopy(addr, &ire->ire_addr, IP_ADDR_LEN);
	if (gateway != NULL)
		bcopy(gateway, &ire->ire_gateway_addr, IP_ADDR_LEN);

	/* Make sure we don't have stray values in some fields */
	switch (type) {
	case IRE_LOOPBACK:
	case IRE_HOST:
	case IRE_BROADCAST:
	case IRE_LOCAL:
	case IRE_IF_CLONE:
		ire->ire_mask = IP_HOST_MASK;
		ire->ire_masklen = IPV4_ABITS;
		break;
	case IRE_PREFIX:
	case IRE_DEFAULT:
	case IRE_IF_RESOLVER:
	case IRE_IF_NORESOLVER:
		if (mask != NULL) {
			bcopy(mask, &ire->ire_mask, IP_ADDR_LEN);
			ire->ire_masklen = ip_mask_to_plen(ire->ire_mask);
		}
		break;
	case IRE_MULTICAST:
	case IRE_NOROUTE:
		ASSERT(mask == NULL);
		break;
	default:
		ASSERT(0);
		return (EINVAL);
	}

	error = ire_init_common(ire, type, ill, zoneid, flags, IPV4_VERSION,
	    gc, ipst);
	if (error != NULL)
		return (error);

	/* Determine which function pointers to use */
	ire->ire_postfragfn = ip_xmit;		/* Common case */

	switch (ire->ire_type) {
	case IRE_LOCAL:
		ire->ire_sendfn = ire_send_local_v4;
		ire->ire_recvfn = ire_recv_local_v4;
		ASSERT(ire->ire_ill != NULL);
		if (ire->ire_ill->ill_flags & ILLF_NOACCEPT)
			ire->ire_recvfn = ire_recv_noaccept_v6;
		break;
	case IRE_LOOPBACK:
		ire->ire_sendfn = ire_send_local_v4;
		ire->ire_recvfn = ire_recv_loopback_v4;
		break;
	case IRE_BROADCAST:
		ire->ire_postfragfn = ip_postfrag_loopcheck;
		ire->ire_sendfn = ire_send_broadcast_v4;
		ire->ire_recvfn = ire_recv_broadcast_v4;
		break;
	case IRE_MULTICAST:
		ire->ire_postfragfn = ip_postfrag_loopcheck;
		ire->ire_sendfn = ire_send_multicast_v4;
		ire->ire_recvfn = ire_recv_multicast_v4;
		break;
	default:
		/*
		 * For IRE_IF_ALL and IRE_OFFLINK we forward received
		 * packets by default.
		 */
		ire->ire_sendfn = ire_send_wire_v4;
		ire->ire_recvfn = ire_recv_forward_v4;
		break;
	}
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire->ire_sendfn = ire_send_noroute_v4;
		ire->ire_recvfn = ire_recv_noroute_v4;
	} else if (ire->ire_flags & RTF_MULTIRT) {
		ire->ire_postfragfn = ip_postfrag_multirt_v4;
		ire->ire_sendfn = ire_send_multirt_v4;
		/* Multirt receive of broadcast uses ire_recv_broadcast_v4 */
		if (ire->ire_type != IRE_BROADCAST)
			ire->ire_recvfn = ire_recv_multirt_v4;
	}
	ire->ire_nce_capable = ire_determine_nce_capable(ire);
	return (0);
}

/*
 * Determine ire_nce_capable
 */
boolean_t
ire_determine_nce_capable(ire_t *ire)
{
	int max_masklen;

	if ((ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    (ire->ire_type & IRE_MULTICAST))
		return (B_TRUE);

	if (ire->ire_ipversion == IPV4_VERSION)
		max_masklen = IPV4_ABITS;
	else
		max_masklen = IPV6_ABITS;

	if ((ire->ire_type & IRE_ONLINK) && ire->ire_masklen == max_masklen)
		return (B_TRUE);
	return (B_FALSE);
}

/*
 * ire_create is called to allocate and initialize a new IRE.
 *
 * NOTE : This is called as writer sometimes though not required
 * by this function.
 */
ire_t *
ire_create(uchar_t *addr, uchar_t *mask, uchar_t *gateway,
    ushort_t type, ill_t *ill, zoneid_t zoneid, uint_t flags, tsol_gc_t *gc,
    ip_stack_t *ipst)
{
	ire_t	*ire;
	int	error;

	ire = kmem_cache_alloc(ire_cache, KM_NOSLEEP);
	if (ire == NULL) {
		DTRACE_PROBE(kmem__cache__alloc);
		return (NULL);
	}
	*ire = ire_null;

	error = ire_init_v4(ire, addr, mask, gateway, type, ill, zoneid, flags,
	    gc, ipst);
	if (error != 0) {
		DTRACE_PROBE2(ire__init, ire_t *, ire, int, error);
		kmem_cache_free(ire_cache, ire);
		return (NULL);
	}
	return (ire);
}

/*
 * Common to IPv4 and IPv6
 * Returns zero or errno.
 */
int
ire_init_common(ire_t *ire, ushort_t type, ill_t *ill, zoneid_t zoneid,
    uint_t flags, uchar_t ipversion, tsol_gc_t *gc, ip_stack_t *ipst)
{
	int error;

#ifdef DEBUG
	if (ill != NULL) {
		if (ill->ill_isv6)
			ASSERT(ipversion == IPV6_VERSION);
		else
			ASSERT(ipversion == IPV4_VERSION);
	}
#endif /* DEBUG */

	/*
	 * Create/initialize IRE security attribute only in Trusted mode;
	 * if the passed in gc is non-NULL, we expect that the caller
	 * has held a reference to it and will release it when this routine
	 * returns a failure, otherwise we own the reference.  We do this
	 * prior to initializing the rest IRE fields.
	 */
	if (is_system_labeled()) {
		if ((type & (IRE_LOCAL | IRE_LOOPBACK | IRE_BROADCAST |
		    IRE_IF_ALL | IRE_MULTICAST | IRE_NOROUTE)) != 0) {
			/* release references on behalf of caller */
			if (gc != NULL)
				GC_REFRELE(gc);
		} else {
			error = tsol_ire_init_gwattr(ire, ipversion, gc);
			if (error != 0)
				return (error);
		}
	}

	ire->ire_type = type;
	ire->ire_flags = RTF_UP | flags;
	ire->ire_create_time = (uint32_t)gethrestime_sec();
	ire->ire_generation = IRE_GENERATION_INITIAL;

	/*
	 * The ill_ire_cnt isn't increased until
	 * the IRE is added to ensure that a walker will find
	 * all IREs that hold a reference on an ill.
	 *
	 * Note that ill_ire_multicast doesn't hold a ref on the ill since
	 * ire_add() is not called for the IRE_MULTICAST.
	 */
	ire->ire_ill = ill;
	ire->ire_zoneid = zoneid;
	ire->ire_ipversion = ipversion;

	mutex_init(&ire->ire_lock, NULL, MUTEX_DEFAULT, NULL);
	ire->ire_refcnt = 1;
	ire->ire_identical_ref = 1;	/* Number of ire_delete's needed */
	ire->ire_ipst = ipst;	/* No netstack_hold */
	ire->ire_trace_disable = B_FALSE;

	return (0);
}

/*
 * This creates an IRE_BROADCAST based on the arguments.
 * A mirror is ire_lookup_bcast().
 *
 * Any supression of unneeded ones is done in ire_add_v4.
 * We add one IRE_BROADCAST per address. ire_send_broadcast_v4()
 * takes care of generating a loopback copy of the packet.
 */
ire_t **
ire_create_bcast(ill_t *ill, ipaddr_t addr, zoneid_t zoneid, ire_t **irep)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_ILL(ill));

	*irep++ = ire_create(
	    (uchar_t *)&addr,			/* dest addr */
	    (uchar_t *)&ip_g_all_ones,		/* mask */
	    NULL,				/* no gateway */
	    IRE_BROADCAST,
	    ill,
	    zoneid,
	    RTF_KERNEL,
	    NULL,
	    ipst);

	return (irep);
}

/*
 * This looks up an IRE_BROADCAST based on the arguments.
 * Mirrors ire_create_bcast().
 */
ire_t *
ire_lookup_bcast(ill_t *ill, ipaddr_t addr, zoneid_t zoneid)
{
	ire_t		*ire;
	int		match_args;

	match_args = MATCH_IRE_TYPE | MATCH_IRE_ILL | MATCH_IRE_GW |
	    MATCH_IRE_MASK | MATCH_IRE_ZONEONLY;

	if (IS_UNDER_IPMP(ill))
		match_args |= MATCH_IRE_TESTHIDDEN;

	ire = ire_ftable_lookup_v4(
	    addr,				/* dest addr */
	    ip_g_all_ones,			/* mask */
	    0,					/* no gateway */
	    IRE_BROADCAST,
	    ill,
	    zoneid,
	    NULL,
	    match_args,
	    0,
	    ill->ill_ipst,
	    NULL);
	return (ire);
}

/* Arrange to call the specified function for every IRE in the world. */
void
ire_walk(pfv_t func, void *arg, ip_stack_t *ipst)
{
	ire_walk_ipvers(func, arg, 0, ALL_ZONES, ipst);
}

void
ire_walk_v4(pfv_t func, void *arg, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_walk_ipvers(func, arg, IPV4_VERSION, zoneid, ipst);
}

void
ire_walk_v6(pfv_t func, void *arg, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_walk_ipvers(func, arg, IPV6_VERSION, zoneid, ipst);
}

/*
 * Walk a particular version. version == 0 means both v4 and v6.
 */
static void
ire_walk_ipvers(pfv_t func, void *arg, uchar_t vers, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	if (vers != IPV6_VERSION) {
		/*
		 * ip_forwarding_table variable doesn't matter for IPv4 since
		 * ire_walk_ill_tables uses ips_ip_ftable for IPv4.
		 */
		ire_walk_ill_tables(0, 0, func, arg, IP_MASK_TABLE_SIZE,
		    0, NULL,
		    NULL, zoneid, ipst);
	}
	if (vers != IPV4_VERSION) {
		ire_walk_ill_tables(0, 0, func, arg, IP6_MASK_TABLE_SIZE,
		    ipst->ips_ip6_ftable_hash_size,
		    ipst->ips_ip_forwarding_table_v6,
		    NULL, zoneid, ipst);
	}
}

/*
 * Arrange to call the specified function for every IRE that matches the ill.
 */
void
ire_walk_ill(uint_t match_flags, uint_t ire_type, pfv_t func, void *arg,
    ill_t *ill)
{
	uchar_t vers = (ill->ill_isv6 ? IPV6_VERSION : IPV4_VERSION);

	ire_walk_ill_ipvers(match_flags, ire_type, func, arg, vers, ill);
}

/*
 * Walk a particular ill and version.
 */
static void
ire_walk_ill_ipvers(uint_t match_flags, uint_t ire_type, pfv_t func,
    void *arg, uchar_t vers, ill_t *ill)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	if (vers == IPV4_VERSION) {
		ire_walk_ill_tables(match_flags, ire_type, func, arg,
		    IP_MASK_TABLE_SIZE,
		    0, NULL,
		    ill, ALL_ZONES, ipst);
	}
	if (vers != IPV4_VERSION) {
		ire_walk_ill_tables(match_flags, ire_type, func, arg,
		    IP6_MASK_TABLE_SIZE, ipst->ips_ip6_ftable_hash_size,
		    ipst->ips_ip_forwarding_table_v6,
		    ill, ALL_ZONES, ipst);
	}
}

/*
 * Do the specific matching of IREs to shared-IP zones.
 *
 * We have the same logic as in ire_match_args but implemented slightly
 * differently.
 */
boolean_t
ire_walk_ill_match(uint_t match_flags, uint_t ire_type, ire_t *ire,
    ill_t *ill, zoneid_t zoneid, ip_stack_t *ipst)
{
	ill_t *dst_ill = ire->ire_ill;

	ASSERT(match_flags != 0 || zoneid != ALL_ZONES);

	if (zoneid != ALL_ZONES && zoneid != ire->ire_zoneid &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * We're walking the IREs for a specific zone. The only relevant
		 * IREs are:
		 * - all IREs with a matching ire_zoneid
		 * - IRE_IF_ALL IREs for interfaces with a usable source addr
		 *   with a matching zone
		 * - IRE_OFFLINK with a gateway reachable from the zone
		 * Note that ealier we only did the IRE_OFFLINK check for
		 * IRE_DEFAULT (and only when we had multiple IRE_DEFAULTs).
		 */
		if (ire->ire_type & IRE_ONLINK) {
			uint_t	ifindex;

			/*
			 * Note there is no IRE_INTERFACE on vniN thus
			 * can't do an IRE lookup for a matching route.
			 */
			ifindex = dst_ill->ill_usesrc_ifindex;
			if (ifindex == 0)
				return (B_FALSE);

			/*
			 * If there is a usable source address in the
			 * zone, then it's ok to return an
			 * IRE_INTERFACE
			 */
			if (!ipif_zone_avail(ifindex, dst_ill->ill_isv6,
			    zoneid, ipst)) {
				return (B_FALSE);
			}
		}
		if (dst_ill != NULL && (ire->ire_type & IRE_OFFLINK)) {
			ipif_t	*tipif;

			mutex_enter(&dst_ill->ill_lock);
			for (tipif = dst_ill->ill_ipif;
			    tipif != NULL; tipif = tipif->ipif_next) {
				if (!IPIF_IS_CONDEMNED(tipif) &&
				    (tipif->ipif_flags & IPIF_UP) &&
				    (tipif->ipif_zoneid == zoneid ||
				    tipif->ipif_zoneid == ALL_ZONES))
					break;
			}
			mutex_exit(&dst_ill->ill_lock);
			if (tipif == NULL) {
				return (B_FALSE);
			}
		}
	}
	/*
	 * Except for ALL_ZONES, we only match the offlink routes
	 * where ire_gateway_addr has an IRE_INTERFACE for the zoneid.
	 * Since we can have leftover routes after the IP addresses have
	 * changed, the global zone will also match offlink routes where the
	 * gateway is unreachable from any zone.
	 */
	if ((ire->ire_type & IRE_OFFLINK) && zoneid != ALL_ZONES) {
		in6_addr_t gw_addr_v6;
		boolean_t reach;

		if (ire->ire_ipversion == IPV4_VERSION) {
			reach = ire_gateway_ok_zone_v4(ire->ire_gateway_addr,
			    zoneid, dst_ill, NULL, ipst, B_FALSE);
		} else {
			ASSERT(ire->ire_ipversion == IPV6_VERSION);
			mutex_enter(&ire->ire_lock);
			gw_addr_v6 = ire->ire_gateway_addr_v6;
			mutex_exit(&ire->ire_lock);

			reach = ire_gateway_ok_zone_v6(&gw_addr_v6, zoneid,
			    dst_ill, NULL, ipst, B_FALSE);
		}
		if (!reach) {
			if (zoneid != GLOBAL_ZONEID)
				return (B_FALSE);

			/*
			 * Check if ALL_ZONES reachable - if not then let the
			 * global zone see it.
			 */
			if (ire->ire_ipversion == IPV4_VERSION) {
				reach = ire_gateway_ok_zone_v4(
				    ire->ire_gateway_addr, ALL_ZONES,
				    dst_ill, NULL, ipst, B_FALSE);
			} else {
				reach = ire_gateway_ok_zone_v6(&gw_addr_v6,
				    ALL_ZONES, dst_ill, NULL, ipst, B_FALSE);
			}
			if (reach) {
				/*
				 * Some other zone could see it, hence hide it
				 * in the global zone.
				 */
				return (B_FALSE);
			}
		}
	}

	if (((!(match_flags & MATCH_IRE_TYPE)) ||
	    (ire->ire_type & ire_type)) &&
	    ((!(match_flags & MATCH_IRE_ILL)) ||
	    (dst_ill == ill ||
	    dst_ill != NULL && IS_IN_SAME_ILLGRP(dst_ill, ill)))) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

int
rtfunc(struct radix_node *rn, void *arg)
{
	struct rtfuncarg *rtf = arg;
	struct rt_entry *rt;
	irb_t *irb;
	ire_t *ire;
	boolean_t ret;

	rt = (struct rt_entry *)rn;
	ASSERT(rt != NULL);
	irb = &rt->rt_irb;
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if ((rtf->rt_match_flags != 0) ||
		    (rtf->rt_zoneid != ALL_ZONES)) {
			ret = ire_walk_ill_match(rtf->rt_match_flags,
			    rtf->rt_ire_type, ire,
			    rtf->rt_ill, rtf->rt_zoneid, rtf->rt_ipst);
		} else {
			ret = B_TRUE;
		}
		if (ret)
			(*rtf->rt_func)(ire, rtf->rt_arg);
	}
	return (0);
}

/*
 * Walk the ftable entries that match the ill.
 */
void
ire_walk_ill_tables(uint_t match_flags, uint_t ire_type, pfv_t func,
    void *arg, size_t ftbl_sz, size_t htbl_sz, irb_t **ipftbl,
    ill_t *ill, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	irb_t	*irb_ptr;
	irb_t	*irb;
	ire_t	*ire;
	int i, j;
	boolean_t ret;
	struct rtfuncarg rtfarg;

	ASSERT((!(match_flags & MATCH_IRE_ILL)) || (ill != NULL));
	ASSERT(!(match_flags & MATCH_IRE_TYPE) || (ire_type != 0));

	/* knobs such that routine is called only for v6 case */
	if (ipftbl == ipst->ips_ip_forwarding_table_v6) {
		for (i = (ftbl_sz - 1);  i >= 0; i--) {
			if ((irb_ptr = ipftbl[i]) == NULL)
				continue;
			for (j = 0; j < htbl_sz; j++) {
				irb = &irb_ptr[j];
				if (irb->irb_ire == NULL)
					continue;

				irb_refhold(irb);
				for (ire = irb->irb_ire; ire != NULL;
				    ire = ire->ire_next) {
					if (match_flags == 0 &&
					    zoneid == ALL_ZONES) {
						ret = B_TRUE;
					} else {
						ret =
						    ire_walk_ill_match(
						    match_flags,
						    ire_type, ire, ill,
						    zoneid, ipst);
					}
					if (ret)
						(*func)(ire, arg);
				}
				irb_refrele(irb);
			}
		}
	} else {
		bzero(&rtfarg, sizeof (rtfarg));
		rtfarg.rt_func = func;
		rtfarg.rt_arg = arg;
		if (match_flags != 0) {
			rtfarg.rt_match_flags = match_flags;
		}
		rtfarg.rt_ire_type = ire_type;
		rtfarg.rt_ill = ill;
		rtfarg.rt_zoneid = zoneid;
		rtfarg.rt_ipst = ipst;	/* No netstack_hold */
		(void) ipst->ips_ip_ftable->rnh_walktree_mt(
		    ipst->ips_ip_ftable,
		    rtfunc, &rtfarg, irb_refhold_rn, irb_refrele_rn);
	}
}

/*
 * This function takes a mask and returns
 * number of bits set in the mask. If no
 * bit is set it returns 0.
 * Assumes a contiguous mask.
 */
int
ip_mask_to_plen(ipaddr_t mask)
{
	return (mask == 0 ? 0 : IP_ABITS - (ffs(ntohl(mask)) -1));
}

/*
 * Convert length for a mask to the mask.
 */
ipaddr_t
ip_plen_to_mask(uint_t masklen)
{
	if (masklen == 0)
		return (0);

	return (htonl(IP_HOST_MASK << (IP_ABITS - masklen)));
}

void
ire_atomic_end(irb_t *irb_ptr, ire_t *ire)
{
	ill_t		*ill;

	ill = ire->ire_ill;
	if (ill != NULL)
		mutex_exit(&ill->ill_lock);
	rw_exit(&irb_ptr->irb_lock);
}

/*
 * ire_add_v[46] atomically make sure that the ill associated
 * with the new ire is not going away i.e., we check ILL_CONDEMNED.
 */
int
ire_atomic_start(irb_t *irb_ptr, ire_t *ire)
{
	ill_t		*ill;

	ill = ire->ire_ill;

	rw_enter(&irb_ptr->irb_lock, RW_WRITER);
	if (ill != NULL) {
		mutex_enter(&ill->ill_lock);

		/*
		 * Don't allow IRE's to be created on dying ills, or on
		 * ill's for which the last ipif is going down, or ones which
		 * don't have even a single UP interface
		 */
		if ((ill->ill_state_flags &
		    (ILL_CONDEMNED|ILL_DOWN_IN_PROGRESS)) != 0) {
			ire_atomic_end(irb_ptr, ire);
			DTRACE_PROBE1(ire__add__on__dying__ill, ire_t *, ire);
			return (ENXIO);
		}

		if (IS_UNDER_IPMP(ill)) {
			int	error = 0;
			mutex_enter(&ill->ill_phyint->phyint_lock);
			if (!ipmp_ill_is_active(ill) &&
			    IRE_HIDDEN_TYPE(ire->ire_type) &&
			    !ire->ire_testhidden) {
				error = EINVAL;
			}
			mutex_exit(&ill->ill_phyint->phyint_lock);
			if (error != 0) {
				ire_atomic_end(irb_ptr, ire);
				return (error);
			}
		}

	}
	return (0);
}

/*
 * Add a fully initialized IRE to the forwarding table.
 * This returns NULL on failure, or a held IRE on success.
 * Normally the returned IRE is the same as the argument. But a different
 * IRE will be returned if the added IRE is deemed identical to an existing
 * one. In that case ire_identical_ref will be increased.
 * The caller always needs to do an ire_refrele() on the returned IRE.
 */
ire_t *
ire_add(ire_t *ire)
{
	if (IRE_HIDDEN_TYPE(ire->ire_type) &&
	    ire->ire_ill != NULL && IS_UNDER_IPMP(ire->ire_ill)) {
		/*
		 * IREs hosted on interfaces that are under IPMP
		 * should be hidden so that applications don't
		 * accidentally end up sending packets with test
		 * addresses as their source addresses, or
		 * sending out interfaces that are e.g. IFF_INACTIVE.
		 * Hide them here.
		 */
		ire->ire_testhidden = B_TRUE;
	}

	if (ire->ire_ipversion == IPV6_VERSION)
		return (ire_add_v6(ire));
	else
		return (ire_add_v4(ire));
}

/*
 * Add a fully initialized IPv4 IRE to the forwarding table.
 * This returns NULL on failure, or a held IRE on success.
 * Normally the returned IRE is the same as the argument. But a different
 * IRE will be returned if the added IRE is deemed identical to an existing
 * one. In that case ire_identical_ref will be increased.
 * The caller always needs to do an ire_refrele() on the returned IRE.
 */
static ire_t *
ire_add_v4(ire_t *ire)
{
	ire_t	*ire1;
	irb_t	*irb_ptr;
	ire_t	**irep;
	int	match_flags;
	int	error;
	ip_stack_t	*ipst = ire->ire_ipst;

	if (ire->ire_ill != NULL)
		ASSERT(!MUTEX_HELD(&ire->ire_ill->ill_lock));
	ASSERT(ire->ire_ipversion == IPV4_VERSION);

	/* Make sure the address is properly masked. */
	ire->ire_addr &= ire->ire_mask;

	match_flags = (MATCH_IRE_MASK | MATCH_IRE_TYPE | MATCH_IRE_GW);

	if (ire->ire_ill != NULL) {
		match_flags |= MATCH_IRE_ILL;
	}
	irb_ptr = ire_get_bucket(ire);
	if (irb_ptr == NULL) {
		printf("no bucket for %p\n", (void *)ire);
		ire_delete(ire);
		return (NULL);
	}

	/*
	 * Start the atomic add of the ire. Grab the ill lock,
	 * the bucket lock. Check for condemned.
	 */
	error = ire_atomic_start(irb_ptr, ire);
	if (error != 0) {
		printf("no ire_atomic_start for %p\n", (void *)ire);
		ire_delete(ire);
		irb_refrele(irb_ptr);
		return (NULL);
	}
	/*
	 * If we are creating a hidden IRE, make sure we search for
	 * hidden IREs when searching for duplicates below.
	 * Otherwise, we might find an IRE on some other interface
	 * that's not marked hidden.
	 */
	if (ire->ire_testhidden)
		match_flags |= MATCH_IRE_TESTHIDDEN;

	/*
	 * Atomically check for duplicate and insert in the table.
	 */
	for (ire1 = irb_ptr->irb_ire; ire1 != NULL; ire1 = ire1->ire_next) {
		if (IRE_IS_CONDEMNED(ire1))
			continue;
		/*
		 * Here we need an exact match on zoneid, i.e.,
		 * ire_match_args doesn't fit.
		 */
		if (ire1->ire_zoneid != ire->ire_zoneid)
			continue;

		if (ire1->ire_type != ire->ire_type)
			continue;

		/*
		 * Note: We do not allow multiple routes that differ only
		 * in the gateway security attributes; such routes are
		 * considered duplicates.
		 * To change that we explicitly have to treat them as
		 * different here.
		 */
		if (ire_match_args(ire1, ire->ire_addr, ire->ire_mask,
		    ire->ire_gateway_addr, ire->ire_type, ire->ire_ill,
		    ire->ire_zoneid, NULL, match_flags)) {
			/*
			 * Return the old ire after doing a REFHOLD.
			 * As most of the callers continue to use the IRE
			 * after adding, we return a held ire. This will
			 * avoid a lookup in the caller again. If the callers
			 * don't want to use it, they need to do a REFRELE.
			 *
			 * We only allow exactly one IRE_IF_CLONE for any dst,
			 * so, if the is an IF_CLONE, return the ire without
			 * an identical_ref, but with an ire_ref held.
			 */
			if (ire->ire_type != IRE_IF_CLONE) {
				atomic_inc_32(&ire1->ire_identical_ref);
				DTRACE_PROBE2(ire__add__exist, ire_t *, ire1,
				    ire_t *, ire);
			}
			ire_refhold(ire1);
			ire_atomic_end(irb_ptr, ire);
			ire_delete(ire);
			irb_refrele(irb_ptr);
			return (ire1);
		}
	}

	/*
	 * Normally we do head insertion since most things do not care about
	 * the order of the IREs in the bucket. Note that ip_cgtp_bcast_add
	 * assumes we at least do head insertion so that its IRE_BROADCAST
	 * arrive ahead of existing IRE_HOST for the same address.
	 * However, due to shared-IP zones (and restrict_interzone_loopback)
	 * we can have an IRE_LOCAL as well as IRE_IF_CLONE for the same
	 * address. For that reason we do tail insertion for IRE_IF_CLONE.
	 * Due to the IRE_BROADCAST on cgtp0, which must be last in the bucket,
	 * we do tail insertion of IRE_BROADCASTs that do not have RTF_MULTIRT
	 * set.
	 */
	irep = (ire_t **)irb_ptr;
	if ((ire->ire_type & IRE_IF_CLONE) ||
	    ((ire->ire_type & IRE_BROADCAST) &&
	    !(ire->ire_flags & RTF_MULTIRT))) {
		while ((ire1 = *irep) != NULL)
			irep = &ire1->ire_next;
	}
	/* Insert at *irep */
	ire1 = *irep;
	if (ire1 != NULL)
		ire1->ire_ptpn = &ire->ire_next;
	ire->ire_next = ire1;
	/* Link the new one in. */
	ire->ire_ptpn = irep;

	/*
	 * ire_walk routines de-reference ire_next without holding
	 * a lock. Before we point to the new ire, we want to make
	 * sure the store that sets the ire_next of the new ire
	 * reaches global visibility, so that ire_walk routines
	 * don't see a truncated list of ires i.e if the ire_next
	 * of the new ire gets set after we do "*irep = ire" due
	 * to re-ordering, the ire_walk thread will see a NULL
	 * once it accesses the ire_next of the new ire.
	 * membar_producer() makes sure that the following store
	 * happens *after* all of the above stores.
	 */
	membar_producer();
	*irep = ire;
	ire->ire_bucket = irb_ptr;
	/*
	 * We return a bumped up IRE above. Keep it symmetrical
	 * so that the callers will always have to release. This
	 * helps the callers of this function because they continue
	 * to use the IRE after adding and hence they don't have to
	 * lookup again after we return the IRE.
	 *
	 * NOTE : We don't have to use atomics as this is appearing
	 * in the list for the first time and no one else can bump
	 * up the reference count on this yet.
	 */
	ire_refhold_locked(ire);
	BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_inserted);

	irb_ptr->irb_ire_cnt++;
	if (irb_ptr->irb_marks & IRB_MARK_DYNAMIC)
		irb_ptr->irb_nire++;

	if (ire->ire_ill != NULL) {
		ire->ire_ill->ill_ire_cnt++;
		ASSERT(ire->ire_ill->ill_ire_cnt != 0);	/* Wraparound */
	}

	ire_atomic_end(irb_ptr, ire);

	/* Make any caching of the IREs be notified or updated */
	ire_flush_cache_v4(ire, IRE_FLUSH_ADD);

	if (ire->ire_ill != NULL)
		ASSERT(!MUTEX_HELD(&ire->ire_ill->ill_lock));
	irb_refrele(irb_ptr);
	return (ire);
}

/*
 * irb_refrele is the only caller of the function. ire_unlink calls to
 * do the final cleanup for this ire.
 */
void
ire_cleanup(ire_t *ire)
{
	ire_t *ire_next;
	ip_stack_t *ipst = ire->ire_ipst;

	ASSERT(ire != NULL);

	while (ire != NULL) {
		ire_next = ire->ire_next;
		if (ire->ire_ipversion == IPV4_VERSION) {
			ire_delete_v4(ire);
			BUMP_IRE_STATS(ipst->ips_ire_stats_v4,
			    ire_stats_deleted);
		} else {
			ASSERT(ire->ire_ipversion == IPV6_VERSION);
			ire_delete_v6(ire);
			BUMP_IRE_STATS(ipst->ips_ire_stats_v6,
			    ire_stats_deleted);
		}
		/*
		 * Now it's really out of the list. Before doing the
		 * REFRELE, set ire_next to NULL as ire_inactive asserts
		 * so.
		 */
		ire->ire_next = NULL;
		ire_refrele_notr(ire);
		ire = ire_next;
	}
}

/*
 * irb_refrele is the only caller of the function. It calls to unlink
 * all the CONDEMNED ires from this bucket.
 */
ire_t *
ire_unlink(irb_t *irb)
{
	ire_t *ire;
	ire_t *ire1;
	ire_t **ptpn;
	ire_t *ire_list = NULL;

	ASSERT(RW_WRITE_HELD(&irb->irb_lock));
	ASSERT(((irb->irb_marks & IRB_MARK_DYNAMIC) && irb->irb_refcnt == 1) ||
	    (irb->irb_refcnt == 0));
	ASSERT(irb->irb_marks & IRB_MARK_CONDEMNED);
	ASSERT(irb->irb_ire != NULL);

	for (ire = irb->irb_ire; ire != NULL; ire = ire1) {
		ire1 = ire->ire_next;
		if (IRE_IS_CONDEMNED(ire)) {
			ptpn = ire->ire_ptpn;
			ire1 = ire->ire_next;
			if (ire1)
				ire1->ire_ptpn = ptpn;
			*ptpn = ire1;
			ire->ire_ptpn = NULL;
			ire->ire_next = NULL;

			/*
			 * We need to call ire_delete_v4 or ire_delete_v6 to
			 * clean up dependents and the redirects pointing at
			 * the default gateway. We need to drop the lock
			 * as ire_flush_cache/ire_delete_host_redircts require
			 * so. But we can't drop the lock, as ire_unlink needs
			 * to atomically remove the ires from the list.
			 * So, create a temporary list of CONDEMNED ires
			 * for doing ire_delete_v4/ire_delete_v6 operations
			 * later on.
			 */
			ire->ire_next = ire_list;
			ire_list = ire;
		}
	}
	irb->irb_marks &= ~IRB_MARK_CONDEMNED;
	return (ire_list);
}

/*
 * Clean up the radix node for this ire. Must be called by irb_refrele
 * when there are no ire's left in the bucket. Returns TRUE if the bucket
 * is deleted and freed.
 */
boolean_t
irb_inactive(irb_t *irb)
{
	struct rt_entry *rt;
	struct radix_node *rn;
	ip_stack_t *ipst = irb->irb_ipst;

	ASSERT(irb->irb_ipst != NULL);

	rt = IRB2RT(irb);
	rn = (struct radix_node *)rt;

	/* first remove it from the radix tree. */
	RADIX_NODE_HEAD_WLOCK(ipst->ips_ip_ftable);
	rw_enter(&irb->irb_lock, RW_WRITER);
	if (irb->irb_refcnt == 1 && irb->irb_nire == 0) {
		rn = ipst->ips_ip_ftable->rnh_deladdr(rn->rn_key, rn->rn_mask,
		    ipst->ips_ip_ftable);
		DTRACE_PROBE1(irb__free, rt_t *,  rt);
		ASSERT((void *)rn == (void *)rt);
		Free(rt, rt_entry_cache);
		/* irb_lock is freed */
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		return (B_TRUE);
	}
	rw_exit(&irb->irb_lock);
	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
	return (B_FALSE);
}

/*
 * Delete the specified IRE.
 * We assume that if ire_bucket is not set then ire_ill->ill_ire_cnt was
 * not incremented i.e., that the insertion in the bucket and the increment
 * of that counter is done atomically.
 */
void
ire_delete(ire_t *ire)
{
	ire_t	*ire1;
	ire_t	**ptpn;
	irb_t	*irb;
	ip_stack_t	*ipst = ire->ire_ipst;

	if ((irb = ire->ire_bucket) == NULL) {
		/*
		 * It was never inserted in the list. Should call REFRELE
		 * to free this IRE.
		 */
		ire_make_condemned(ire);
		ire_refrele_notr(ire);
		return;
	}

	/*
	 * Move the use counts from an IRE_IF_CLONE to its parent
	 * IRE_INTERFACE.
	 * We need to do this before acquiring irb_lock.
	 */
	if (ire->ire_type & IRE_IF_CLONE) {
		ire_t *parent;

		rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
		if ((parent = ire->ire_dep_parent) != NULL) {
			parent->ire_ob_pkt_count += ire->ire_ob_pkt_count;
			parent->ire_ib_pkt_count += ire->ire_ib_pkt_count;
			ire->ire_ob_pkt_count = 0;
			ire->ire_ib_pkt_count = 0;
		}
		rw_exit(&ipst->ips_ire_dep_lock);
	}

	rw_enter(&irb->irb_lock, RW_WRITER);
	if (ire->ire_ptpn == NULL) {
		/*
		 * Some other thread has removed us from the list.
		 * It should have done the REFRELE for us.
		 */
		rw_exit(&irb->irb_lock);
		return;
	}

	if (!IRE_IS_CONDEMNED(ire)) {
		/* Is this an IRE representing multiple duplicate entries? */
		ASSERT(ire->ire_identical_ref >= 1);
		if (atomic_dec_32_nv(&ire->ire_identical_ref) != 0) {
			/* Removed one of the identical parties */
			rw_exit(&irb->irb_lock);
			return;
		}

		irb->irb_ire_cnt--;
		ire_make_condemned(ire);
	}

	if (irb->irb_refcnt != 0) {
		/*
		 * The last thread to leave this bucket will
		 * delete this ire.
		 */
		irb->irb_marks |= IRB_MARK_CONDEMNED;
		rw_exit(&irb->irb_lock);
		return;
	}

	/*
	 * Normally to delete an ire, we walk the bucket. While we
	 * walk the bucket, we normally bump up irb_refcnt and hence
	 * we return from above where we mark CONDEMNED and the ire
	 * gets deleted from ire_unlink. This case is where somebody
	 * knows the ire e.g by doing a lookup, and wants to delete the
	 * IRE. irb_refcnt would be 0 in this case if nobody is walking
	 * the bucket.
	 */
	ptpn = ire->ire_ptpn;
	ire1 = ire->ire_next;
	if (ire1 != NULL)
		ire1->ire_ptpn = ptpn;
	ASSERT(ptpn != NULL);
	*ptpn = ire1;
	ire->ire_ptpn = NULL;
	ire->ire_next = NULL;
	if (ire->ire_ipversion == IPV6_VERSION) {
		BUMP_IRE_STATS(ipst->ips_ire_stats_v6, ire_stats_deleted);
	} else {
		BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_deleted);
	}
	rw_exit(&irb->irb_lock);

	/* Cleanup dependents and related stuff */
	if (ire->ire_ipversion == IPV6_VERSION) {
		ire_delete_v6(ire);
	} else {
		ire_delete_v4(ire);
	}
	/*
	 * We removed it from the list. Decrement the
	 * reference count.
	 */
	ire_refrele_notr(ire);
}

/*
 * Delete the specified IRE.
 * All calls should use ire_delete().
 * Sometimes called as writer though not required by this function.
 *
 * NOTE : This function is called only if the ire was added
 * in the list.
 */
static void
ire_delete_v4(ire_t *ire)
{
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_refcnt >= 1);
	ASSERT(ire->ire_ipversion == IPV4_VERSION);

	ire_flush_cache_v4(ire, IRE_FLUSH_DELETE);
	if (ire->ire_type == IRE_DEFAULT) {
		/*
		 * when a default gateway is going away
		 * delete all the host redirects pointing at that
		 * gateway.
		 */
		ire_delete_host_redirects(ire->ire_gateway_addr, ipst);
	}

	/*
	 * If we are deleting an IRE_INTERFACE then we make sure we also
	 * delete any IRE_IF_CLONE that has been created from it.
	 * Those are always in ire_dep_children.
	 */
	if ((ire->ire_type & IRE_INTERFACE) && ire->ire_dep_children != NULL)
		ire_dep_delete_if_clone(ire);

	/* Remove from parent dependencies and child */
	rw_enter(&ipst->ips_ire_dep_lock, RW_WRITER);
	if (ire->ire_dep_parent != NULL)
		ire_dep_remove(ire);

	while (ire->ire_dep_children != NULL)
		ire_dep_remove(ire->ire_dep_children);
	rw_exit(&ipst->ips_ire_dep_lock);
}

/*
 * ire_refrele is the only caller of the function. It calls
 * to free the ire when the reference count goes to zero.
 */
void
ire_inactive(ire_t *ire)
{
	ill_t	*ill;
	irb_t 	*irb;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_refcnt == 0);
	ASSERT(ire->ire_ptpn == NULL);
	ASSERT(ire->ire_next == NULL);

	/* Count how many condemned ires for kmem_cache callback */
	ASSERT(IRE_IS_CONDEMNED(ire));
	atomic_add_32(&ipst->ips_num_ire_condemned, -1);

	if (ire->ire_gw_secattr != NULL) {
		ire_gw_secattr_free(ire->ire_gw_secattr);
		ire->ire_gw_secattr = NULL;
	}

	/*
	 * ire_nce_cache is cleared in ire_delete, and we make sure we don't
	 * set it once the ire is marked condemned.
	 */
	ASSERT(ire->ire_nce_cache == NULL);

	/*
	 * Since any parent would have a refhold on us they would already
	 * have been removed.
	 */
	ASSERT(ire->ire_dep_parent == NULL);
	ASSERT(ire->ire_dep_sib_next == NULL);
	ASSERT(ire->ire_dep_sib_ptpn == NULL);

	/*
	 * Since any children would have a refhold on us they should have
	 * already been removed.
	 */
	ASSERT(ire->ire_dep_children == NULL);

	/*
	 * ill_ire_ref is increased when the IRE is inserted in the
	 * bucket - not when the IRE is created.
	 */
	irb = ire->ire_bucket;
	ill = ire->ire_ill;
	if (irb != NULL && ill != NULL) {
		mutex_enter(&ill->ill_lock);
		ASSERT(ill->ill_ire_cnt != 0);
		DTRACE_PROBE3(ill__decr__cnt, (ill_t *), ill,
		    (char *), "ire", (void *), ire);
		ill->ill_ire_cnt--;
		if (ILL_DOWN_OK(ill)) {
			/* Drops the ill lock */
			ipif_ill_refrele_tail(ill);
		} else {
			mutex_exit(&ill->ill_lock);
		}
	}
	ire->ire_ill = NULL;

	/* This should be true for both V4 and V6 */
	if (irb != NULL && (irb->irb_marks & IRB_MARK_DYNAMIC)) {
		rw_enter(&irb->irb_lock, RW_WRITER);
		irb->irb_nire--;
		/*
		 * Instead of examining the conditions for freeing
		 * the radix node here, we do it by calling
		 * irb_refrele which is a single point in the code
		 * that embeds that logic. Bump up the refcnt to
		 * be able to call irb_refrele
		 */
		irb_refhold_locked(irb);
		rw_exit(&irb->irb_lock);
		irb_refrele(irb);
	}

#ifdef DEBUG
	ire_trace_cleanup(ire);
#endif
	mutex_destroy(&ire->ire_lock);
	if (ire->ire_ipversion == IPV6_VERSION) {
		BUMP_IRE_STATS(ipst->ips_ire_stats_v6, ire_stats_freed);
	} else {
		BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_freed);
	}
	kmem_cache_free(ire_cache, ire);
}

/*
 * ire_update_generation is the callback function provided by
 * ire_get_bucket() to update the generation number of any
 * matching shorter route when a new route is added.
 *
 * This fucntion always returns a failure return (B_FALSE)
 * to force the caller (rn_matchaddr_args)
 * to back-track up the tree looking for shorter matches.
 */
/* ARGSUSED */
static boolean_t
ire_update_generation(struct radix_node *rn, void *arg)
{
	struct rt_entry *rt = (struct rt_entry *)rn;

	/* We need to handle all in the same bucket */
	irb_increment_generation(&rt->rt_irb);
	return (B_FALSE);
}

/*
 * Take care of all the generation numbers in the bucket.
 */
void
irb_increment_generation(irb_t *irb)
{
	ire_t *ire;
	ip_stack_t *ipst;

	if (irb == NULL || irb->irb_ire_cnt == 0)
		return;

	ipst = irb->irb_ipst;
	/*
	 * we cannot do an irb_refhold/irb_refrele here as the caller
	 * already has the global RADIX_NODE_HEAD_WLOCK, and the irb_refrele
	 * may result in an attempt to free the irb_t, which also needs
	 * the RADIX_NODE_HEAD lock. However, since we want to traverse the
	 * irb_ire list without fear of having a condemned ire removed from
	 * the list, we acquire the irb_lock as WRITER. Moreover, since
	 * the ire_generation increments are done under the ire_dep_lock,
	 * acquire the locks in the prescribed lock order first.
	 */
	rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
	rw_enter(&irb->irb_lock, RW_WRITER);
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (!IRE_IS_CONDEMNED(ire))
			ire_increment_generation(ire);	/* Ourselves */
		ire_dep_incr_generation_locked(ire);	/* Dependants */
	}
	rw_exit(&irb->irb_lock);
	rw_exit(&ipst->ips_ire_dep_lock);
}

/*
 * When an IRE is added or deleted this routine is called to make sure
 * any caching of IRE information is notified or updated.
 *
 * The flag argument indicates if the flush request is due to addition
 * of new route (IRE_FLUSH_ADD), deletion of old route (IRE_FLUSH_DELETE),
 * or a change to ire_gateway_addr (IRE_FLUSH_GWCHANGE).
 */
void
ire_flush_cache_v4(ire_t *ire, int flag)
{
	irb_t *irb = ire->ire_bucket;
	struct rt_entry *rt = IRB2RT(irb);
	ip_stack_t *ipst = ire->ire_ipst;

	/*
	 * IRE_IF_CLONE ire's don't provide any new information
	 * than the parent from which they are cloned, so don't
	 * perturb the generation numbers.
	 */
	if (ire->ire_type & IRE_IF_CLONE)
		return;

	/*
	 * Ensure that an ire_add during a lookup serializes the updates of the
	 * generation numbers under the radix head lock so that the lookup gets
	 * either the old ire and old generation number, or a new ire and new
	 * generation number.
	 */
	RADIX_NODE_HEAD_WLOCK(ipst->ips_ip_ftable);

	/*
	 * If a route was just added, we need to notify everybody that
	 * has cached an IRE_NOROUTE since there might now be a better
	 * route for them.
	 */
	if (flag == IRE_FLUSH_ADD) {
		ire_increment_generation(ipst->ips_ire_reject_v4);
		ire_increment_generation(ipst->ips_ire_blackhole_v4);
	}

	/* Adding a default can't otherwise provide a better route */
	if (ire->ire_type == IRE_DEFAULT && flag == IRE_FLUSH_ADD) {
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		return;
	}

	switch (flag) {
	case IRE_FLUSH_DELETE:
	case IRE_FLUSH_GWCHANGE:
		/*
		 * Update ire_generation for all ire_dep_children chains
		 * starting with this IRE
		 */
		ire_dep_incr_generation(ire);
		break;
	case IRE_FLUSH_ADD:
		/*
		 * Update the generation numbers of all shorter matching routes.
		 * ire_update_generation takes care of the dependants by
		 * using ire_dep_incr_generation.
		 */
		(void) ipst->ips_ip_ftable->rnh_matchaddr_args(&rt->rt_dst,
		    ipst->ips_ip_ftable, ire_update_generation, NULL);
		break;
	}
	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
}

/*
 * Matches the arguments passed with the values in the ire.
 *
 * Note: for match types that match using "ill" passed in, ill
 * must be checked for non-NULL before calling this routine.
 */
boolean_t
ire_match_args(ire_t *ire, ipaddr_t addr, ipaddr_t mask, ipaddr_t gateway,
    int type, const ill_t *ill, zoneid_t zoneid,
    const ts_label_t *tsl, int match_flags)
{
	ill_t *ire_ill = NULL, *dst_ill;
	ip_stack_t *ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV4_VERSION);
	ASSERT((ire->ire_addr & ~ire->ire_mask) == 0);
	ASSERT((!(match_flags & (MATCH_IRE_ILL|MATCH_IRE_SRC_ILL))) ||
	    (ill != NULL && !ill->ill_isv6));

	/*
	 * If MATCH_IRE_TESTHIDDEN is set, then only return the IRE if it is
	 * in fact hidden, to ensure the caller gets the right one.
	 */
	if (ire->ire_testhidden) {
		if (!(match_flags & MATCH_IRE_TESTHIDDEN))
			return (B_FALSE);
	}

	if (zoneid != ALL_ZONES && zoneid != ire->ire_zoneid &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * If MATCH_IRE_ZONEONLY has been set and the supplied zoneid
		 * does not match that of ire_zoneid, a failure to
		 * match is reported at this point. Otherwise, since some IREs
		 * that are available in the global zone can be used in local
		 * zones, additional checks need to be performed:
		 *
		 * IRE_LOOPBACK
		 *	entries should never be matched in this situation.
		 *	Each zone has its own IRE_LOOPBACK.
		 *
		 * IRE_LOCAL
		 *	We allow them for any zoneid. ire_route_recursive
		 *	does additional checks when
		 *	ip_restrict_interzone_loopback is set.
		 *
		 * If ill_usesrc_ifindex is set
		 *	Then we check if the zone has a valid source address
		 *	on the usesrc ill.
		 *
		 * If ire_ill is set, then check that the zone has an ipif
		 *	on that ill.
		 *
		 * Outside of this function (in ire_round_robin) we check
		 * that any IRE_OFFLINK has a gateway that reachable from the
		 * zone when we have multiple choices (ECMP).
		 */
		if (match_flags & MATCH_IRE_ZONEONLY)
			return (B_FALSE);
		if (ire->ire_type & IRE_LOOPBACK)
			return (B_FALSE);

		if (ire->ire_type & IRE_LOCAL)
			goto matchit;

		/*
		 * The normal case of IRE_ONLINK has a matching zoneid.
		 * Here we handle the case when shared-IP zones have been
		 * configured with IP addresses on vniN. In that case it
		 * is ok for traffic from a zone to use IRE_ONLINK routes
		 * if the ill has a usesrc pointing at vniN
		 */
		dst_ill = ire->ire_ill;
		if (ire->ire_type & IRE_ONLINK) {
			uint_t	ifindex;

			/*
			 * Note there is no IRE_INTERFACE on vniN thus
			 * can't do an IRE lookup for a matching route.
			 */
			ifindex = dst_ill->ill_usesrc_ifindex;
			if (ifindex == 0)
				return (B_FALSE);

			/*
			 * If there is a usable source address in the
			 * zone, then it's ok to return this IRE_INTERFACE
			 */
			if (!ipif_zone_avail(ifindex, dst_ill->ill_isv6,
			    zoneid, ipst)) {
				ip3dbg(("ire_match_args: no usrsrc for zone"
				    " dst_ill %p\n", (void *)dst_ill));
				return (B_FALSE);
			}
		}
		/*
		 * For example, with
		 * route add 11.0.0.0 gw1 -ifp bge0
		 * route add 11.0.0.0 gw2 -ifp bge1
		 * this code would differentiate based on
		 * where the sending zone has addresses.
		 * Only if the zone has an address on bge0 can it use the first
		 * route. It isn't clear if this behavior is documented
		 * anywhere.
		 */
		if (dst_ill != NULL && (ire->ire_type & IRE_OFFLINK)) {
			ipif_t	*tipif;

			mutex_enter(&dst_ill->ill_lock);
			for (tipif = dst_ill->ill_ipif;
			    tipif != NULL; tipif = tipif->ipif_next) {
				if (!IPIF_IS_CONDEMNED(tipif) &&
				    (tipif->ipif_flags & IPIF_UP) &&
				    (tipif->ipif_zoneid == zoneid ||
				    tipif->ipif_zoneid == ALL_ZONES))
					break;
			}
			mutex_exit(&dst_ill->ill_lock);
			if (tipif == NULL) {
				return (B_FALSE);
			}
		}
	}

matchit:
	ire_ill = ire->ire_ill;
	if (match_flags & MATCH_IRE_ILL) {

		/*
		 * If asked to match an ill, we *must* match
		 * on the ire_ill for ipmp test addresses, or
		 * any of the ill in the group for data addresses.
		 * If we don't, we may as well fail.
		 * However, we need an exception for IRE_LOCALs to ensure
		 * we loopback packets even sent to test addresses on different
		 * interfaces in the group.
		 */
		if ((match_flags & MATCH_IRE_TESTHIDDEN) &&
		    !(ire->ire_type & IRE_LOCAL)) {
			if (ire->ire_ill != ill)
				return (B_FALSE);
		} else  {
			match_flags &= ~MATCH_IRE_TESTHIDDEN;
			/*
			 * We know that ill is not NULL, but ire_ill could be
			 * NULL
			 */
			if (ire_ill == NULL || !IS_ON_SAME_LAN(ill, ire_ill))
				return (B_FALSE);
		}
	}
	if (match_flags & MATCH_IRE_SRC_ILL) {
		if (ire_ill == NULL)
			return (B_FALSE);
		if (!IS_ON_SAME_LAN(ill, ire_ill)) {
			if (ire_ill->ill_usesrc_ifindex == 0 ||
			    (ire_ill->ill_usesrc_ifindex !=
			    ill->ill_phyint->phyint_ifindex))
				return (B_FALSE);
		}
	}

	if ((ire->ire_addr == (addr & mask)) &&
	    ((!(match_flags & MATCH_IRE_GW)) ||
	    (ire->ire_gateway_addr == gateway)) &&
	    ((!(match_flags & MATCH_IRE_DIRECT)) ||
	    !(ire->ire_flags & RTF_INDIRECT)) &&
	    ((!(match_flags & MATCH_IRE_TYPE)) || (ire->ire_type & type)) &&
	    ((!(match_flags & MATCH_IRE_TESTHIDDEN)) || ire->ire_testhidden) &&
	    ((!(match_flags & MATCH_IRE_MASK)) || (ire->ire_mask == mask)) &&
	    ((!(match_flags & MATCH_IRE_SECATTR)) ||
	    (!is_system_labeled()) ||
	    (tsol_ire_match_gwattr(ire, tsl) == 0))) {
		/* We found the matched IRE */
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Check if the IRE_LOCAL uses the same ill as another route would use.
 * If there is no alternate route, or the alternate is a REJECT or BLACKHOLE,
 * then we don't allow this IRE_LOCAL to be used.
 * We always return an IRE; will be RTF_REJECT if no route available.
 */
ire_t *
ire_alt_local(ire_t *ire, zoneid_t zoneid, const ts_label_t *tsl,
    const ill_t *ill, uint_t *generationp)
{
	ip_stack_t	*ipst = ire->ire_ipst;
	ire_t		*alt_ire;
	uint_t		ire_type;
	uint_t		generation;
	uint_t		match_flags;

	ASSERT(ire->ire_type & IRE_LOCAL);
	ASSERT(ire->ire_ill != NULL);

	/*
	 * Need to match on everything but local.
	 * This might result in the creation of a IRE_IF_CLONE for the
	 * same address as the IRE_LOCAL when restrict_interzone_loopback is
	 * set. ire_add_*() ensures that the IRE_IF_CLONE are tail inserted
	 * to make sure the IRE_LOCAL is always found first.
	 */
	ire_type = (IRE_ONLINK | IRE_OFFLINK) & ~(IRE_LOCAL|IRE_LOOPBACK);
	match_flags = MATCH_IRE_TYPE | MATCH_IRE_SECATTR;
	if (ill != NULL)
		match_flags |= MATCH_IRE_ILL;

	if (ire->ire_ipversion == IPV4_VERSION) {
		alt_ire = ire_route_recursive_v4(ire->ire_addr, ire_type,
		    ill, zoneid, tsl, match_flags, IRR_ALLOCATE, 0, ipst, NULL,
		    NULL, &generation);
	} else {
		alt_ire = ire_route_recursive_v6(&ire->ire_addr_v6, ire_type,
		    ill, zoneid, tsl, match_flags, IRR_ALLOCATE, 0, ipst, NULL,
		    NULL, &generation);
	}
	ASSERT(alt_ire != NULL);

	if (alt_ire->ire_ill == ire->ire_ill) {
		/* Going out the same ILL - ok to send to IRE_LOCAL */
		ire_refrele(alt_ire);
	} else {
		/* Different ill - ignore IRE_LOCAL */
		ire_refrele(ire);
		ire = alt_ire;
		if (generationp != NULL)
			*generationp = generation;
	}
	return (ire);
}

boolean_t
ire_find_zoneid(struct radix_node *rn, void *arg)
{
	struct rt_entry *rt = (struct rt_entry *)rn;
	irb_t *irb;
	ire_t *ire;
	ire_ftable_args_t *margs = arg;

	ASSERT(rt != NULL);

	irb = &rt->rt_irb;

	if (irb->irb_ire_cnt == 0)
		return (B_FALSE);

	rw_enter(&irb->irb_lock, RW_READER);
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (IRE_IS_CONDEMNED(ire))
			continue;

		if (!(ire->ire_type & IRE_INTERFACE))
			continue;

		if (ire->ire_zoneid != ALL_ZONES &&
		    ire->ire_zoneid != margs->ift_zoneid)
			continue;

		if (margs->ift_ill != NULL && margs->ift_ill != ire->ire_ill)
			continue;

		if (is_system_labeled() &&
		    tsol_ire_match_gwattr(ire, margs->ift_tsl) != 0)
			continue;

		rw_exit(&irb->irb_lock);
		return (B_TRUE);
	}
	rw_exit(&irb->irb_lock);
	return (B_FALSE);
}

/*
 * Check if the zoneid (not ALL_ZONES) has an IRE_INTERFACE for the specified
 * gateway address. If ill is non-NULL we also match on it.
 * The caller must hold a read lock on RADIX_NODE_HEAD if lock_held is set.
 */
boolean_t
ire_gateway_ok_zone_v4(ipaddr_t gateway, zoneid_t zoneid, ill_t *ill,
    const ts_label_t *tsl, ip_stack_t *ipst, boolean_t lock_held)
{
	struct rt_sockaddr rdst;
	struct rt_entry *rt;
	ire_ftable_args_t margs;

	ASSERT(ill == NULL || !ill->ill_isv6);
	if (lock_held)
		ASSERT(RW_READ_HELD(&ipst->ips_ip_ftable->rnh_lock));
	else
		RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);

	bzero(&rdst, sizeof (rdst));
	rdst.rt_sin_len = sizeof (rdst);
	rdst.rt_sin_family = AF_INET;
	rdst.rt_sin_addr.s_addr = gateway;

	/*
	 * We only use margs for ill, zoneid, and tsl matching in
	 * ire_find_zoneid
	 */
	bzero(&margs, sizeof (margs));
	margs.ift_ill = ill;
	margs.ift_zoneid = zoneid;
	margs.ift_tsl = tsl;
	rt = (struct rt_entry *)ipst->ips_ip_ftable->rnh_matchaddr_args(&rdst,
	    ipst->ips_ip_ftable, ire_find_zoneid, (void *)&margs);

	if (!lock_held)
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);

	return (rt != NULL);
}

/*
 * ire_walk routine to delete a fraction of redirect IREs and IRE_CLONE_IF IREs.
 * The fraction argument tells us what fraction of the IREs to delete.
 * Common for IPv4 and IPv6.
 * Used when memory backpressure.
 */
static void
ire_delete_reclaim(ire_t *ire, char *arg)
{
	ip_stack_t	*ipst = ire->ire_ipst;
	uint_t		fraction = *(uint_t *)arg;
	uint_t		rand;

	if ((ire->ire_flags & RTF_DYNAMIC) ||
	    (ire->ire_type & IRE_IF_CLONE)) {

		/* Pick a random number */
		rand = (uint_t)ddi_get_lbolt() +
		    IRE_ADDR_HASH_V6(ire->ire_addr_v6, 256);

		/* Use truncation */
		if ((rand/fraction)*fraction == rand) {
			IP_STAT(ipst, ip_ire_reclaim_deleted);
			ire_delete(ire);
		}
	}

}

/*
 * kmem_cache callback to free up memory.
 *
 * Free a fraction (ips_ip_ire_reclaim_fraction) of things IP added dynamically
 * (RTF_DYNAMIC and IRE_IF_CLONE).
 */
static void
ip_ire_reclaim_stack(ip_stack_t *ipst)
{
	uint_t	fraction = ipst->ips_ip_ire_reclaim_fraction;

	IP_STAT(ipst, ip_ire_reclaim_calls);

	ire_walk(ire_delete_reclaim, &fraction, ipst);

	/*
	 * Walk all CONNs that can have a reference on an ire, nce or dce.
	 * Get them to update any stale references to drop any refholds they
	 * have.
	 */
	ipcl_walk(conn_ixa_cleanup, (void *)B_FALSE, ipst);
}

/*
 * Called by the memory allocator subsystem directly, when the system
 * is running low on memory.
 */
/* ARGSUSED */
void
ip_ire_reclaim(void *args)
{
	netstack_handle_t nh;
	netstack_t *ns;
	ip_stack_t *ipst;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		/*
		 * netstack_next() can return a netstack_t with a NULL
		 * netstack_ip at boot time.
		 */
		if ((ipst = ns->netstack_ip) == NULL) {
			netstack_rele(ns);
			continue;
		}
		ip_ire_reclaim_stack(ipst);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
}

static void
power2_roundup(uint32_t *value)
{
	int i;

	for (i = 1; i < 31; i++) {
		if (*value <= (1 << i))
			break;
	}
	*value = (1 << i);
}

/* Global init for all zones */
void
ip_ire_g_init()
{
	/*
	 * Create kmem_caches.  ip_ire_reclaim() and ip_nce_reclaim()
	 * will give disposable IREs back to system when needed.
	 * This needs to be done here before anything else, since
	 * ire_add() expects the cache to be created.
	 */
	ire_cache = kmem_cache_create("ire_cache",
	    sizeof (ire_t), 0, NULL, NULL,
	    ip_ire_reclaim, NULL, NULL, 0);

	ncec_cache = kmem_cache_create("ncec_cache",
	    sizeof (ncec_t), 0, NULL, NULL,
	    ip_nce_reclaim, NULL, NULL, 0);
	nce_cache = kmem_cache_create("nce_cache",
	    sizeof (nce_t), 0, NULL, NULL,
	    NULL, NULL, NULL, 0);

	rt_entry_cache = kmem_cache_create("rt_entry",
	    sizeof (struct rt_entry), 0, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * Have radix code setup kmem caches etc.
	 */
	rn_init();
}

void
ip_ire_init(ip_stack_t *ipst)
{
	ire_t	*ire;
	int	error;

	mutex_init(&ipst->ips_ire_ft_init_lock, NULL, MUTEX_DEFAULT, 0);

	(void) rn_inithead((void **)&ipst->ips_ip_ftable, 32);

	/*
	 * Make sure that the forwarding table size is a power of 2.
	 * The IRE*_ADDR_HASH() macroes depend on that.
	 */
	ipst->ips_ip6_ftable_hash_size = ip6_ftable_hash_size;
	power2_roundup(&ipst->ips_ip6_ftable_hash_size);

	/*
	 * Allocate/initialize a pair of IRE_NOROUTEs for each of IPv4 and IPv6.
	 * The ire_reject_v* has RTF_REJECT set, and the ire_blackhole_v* has
	 * RTF_BLACKHOLE set. We use the latter for transient errors such
	 * as memory allocation failures and tripping on IRE_IS_CONDEMNED
	 * entries.
	 */
	ire = kmem_cache_alloc(ire_cache, KM_SLEEP);
	*ire = ire_null;
	error = ire_init_v4(ire, 0, 0, 0, IRE_NOROUTE, NULL, ALL_ZONES,
	    RTF_REJECT|RTF_UP, NULL, ipst);
	ASSERT(error == 0);
	ipst->ips_ire_reject_v4 = ire;

	ire = kmem_cache_alloc(ire_cache, KM_SLEEP);
	*ire = ire_null;
	error = ire_init_v6(ire, 0, 0, 0, IRE_NOROUTE, NULL, ALL_ZONES,
	    RTF_REJECT|RTF_UP, NULL, ipst);
	ASSERT(error == 0);
	ipst->ips_ire_reject_v6 = ire;

	ire = kmem_cache_alloc(ire_cache, KM_SLEEP);
	*ire = ire_null;
	error = ire_init_v4(ire, 0, 0, 0, IRE_NOROUTE, NULL, ALL_ZONES,
	    RTF_BLACKHOLE|RTF_UP, NULL, ipst);
	ASSERT(error == 0);
	ipst->ips_ire_blackhole_v4 = ire;

	ire = kmem_cache_alloc(ire_cache, KM_SLEEP);
	*ire = ire_null;
	error = ire_init_v6(ire, 0, 0, 0, IRE_NOROUTE, NULL, ALL_ZONES,
	    RTF_BLACKHOLE|RTF_UP, NULL, ipst);
	ASSERT(error == 0);
	ipst->ips_ire_blackhole_v6 = ire;

	rw_init(&ipst->ips_ip6_ire_head_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&ipst->ips_ire_dep_lock, NULL, RW_DEFAULT, NULL);
}

void
ip_ire_g_fini(void)
{
	kmem_cache_destroy(ire_cache);
	kmem_cache_destroy(ncec_cache);
	kmem_cache_destroy(nce_cache);
	kmem_cache_destroy(rt_entry_cache);

	rn_fini();
}

void
ip_ire_fini(ip_stack_t *ipst)
{
	int i;

	ire_make_condemned(ipst->ips_ire_reject_v6);
	ire_refrele_notr(ipst->ips_ire_reject_v6);
	ipst->ips_ire_reject_v6 = NULL;

	ire_make_condemned(ipst->ips_ire_reject_v4);
	ire_refrele_notr(ipst->ips_ire_reject_v4);
	ipst->ips_ire_reject_v4 = NULL;

	ire_make_condemned(ipst->ips_ire_blackhole_v6);
	ire_refrele_notr(ipst->ips_ire_blackhole_v6);
	ipst->ips_ire_blackhole_v6 = NULL;

	ire_make_condemned(ipst->ips_ire_blackhole_v4);
	ire_refrele_notr(ipst->ips_ire_blackhole_v4);
	ipst->ips_ire_blackhole_v4 = NULL;

	/*
	 * Delete all IREs - assumes that the ill/ipifs have
	 * been removed so what remains are just the ftable to handle.
	 */
	ire_walk(ire_delete, NULL, ipst);

	rn_freehead(ipst->ips_ip_ftable);
	ipst->ips_ip_ftable = NULL;

	rw_destroy(&ipst->ips_ire_dep_lock);
	rw_destroy(&ipst->ips_ip6_ire_head_lock);

	mutex_destroy(&ipst->ips_ire_ft_init_lock);

	for (i = 0; i < IP6_MASK_TABLE_SIZE; i++) {
		irb_t *ptr;
		int j;

		if ((ptr = ipst->ips_ip_forwarding_table_v6[i]) == NULL)
			continue;

		for (j = 0; j < ipst->ips_ip6_ftable_hash_size; j++) {
			ASSERT(ptr[j].irb_ire == NULL);
			rw_destroy(&ptr[j].irb_lock);
		}
		mi_free(ptr);
		ipst->ips_ip_forwarding_table_v6[i] = NULL;
	}
}

#ifdef DEBUG
void
ire_trace_ref(ire_t *ire)
{
	mutex_enter(&ire->ire_lock);
	if (ire->ire_trace_disable) {
		mutex_exit(&ire->ire_lock);
		return;
	}

	if (th_trace_ref(ire, ire->ire_ipst)) {
		mutex_exit(&ire->ire_lock);
	} else {
		ire->ire_trace_disable = B_TRUE;
		mutex_exit(&ire->ire_lock);
		ire_trace_cleanup(ire);
	}
}

void
ire_untrace_ref(ire_t *ire)
{
	mutex_enter(&ire->ire_lock);
	if (!ire->ire_trace_disable)
		th_trace_unref(ire);
	mutex_exit(&ire->ire_lock);
}

static void
ire_trace_cleanup(const ire_t *ire)
{
	th_trace_cleanup(ire, ire->ire_trace_disable);
}
#endif /* DEBUG */

/*
 * Find, or create if needed, the nce_t pointer to the neighbor cache
 * entry ncec_t for an IPv4 address. The nce_t will be created on the ill_t
 * in the non-IPMP case, or on the cast-ill in the IPMP bcast/mcast case, or
 * on the next available under-ill (selected by the IPMP rotor) in the
 * unicast IPMP case.
 *
 * If a neighbor-cache entry has to be created (i.e., one does not already
 * exist in the nce list) the ncec_lladdr and ncec_state of the neighbor cache
 * entry are initialized in nce_add_v4(). The broadcast, multicast, and
 * link-layer type determine the contents of {ncec_state, ncec_lladdr} of
 * the ncec_t created. The ncec_lladdr is non-null for all link types with
 * non-zero ill_phys_addr_length, though the contents may be zero in cases
 * where the link-layer type is not known at the time of creation
 * (e.g., IRE_IFRESOLVER links)
 *
 * All IRE_BROADCAST entries have ncec_state = ND_REACHABLE, and the nce_lladr
 * has the physical broadcast address of the outgoing interface.
 * For unicast ire entries,
 *   - if the outgoing interface is of type IRE_IF_RESOLVER, a newly created
 *     ncec_t with 0 nce_lladr contents, and will be in the ND_INITIAL state.
 *   - if the outgoing interface is a IRE_IF_NORESOLVER interface, no link
 *     layer resolution is necessary, so that the ncec_t will be in the
 *     ND_REACHABLE state
 *
 * The link layer information needed for broadcast addresses, and for
 * packets sent on IRE_IF_NORESOLVER interfaces is a constant mapping that
 * never needs re-verification for the lifetime of the ncec_t. These are
 * therefore marked NCE_F_NONUD.
 *
 * The nce returned will be created such that the nce_ill == ill that
 * is passed in. Note that the nce itself may not have ncec_ill == ill
 * where IPMP links are involved.
 */
static nce_t *
ire_nce_init(ill_t *ill, const void *addr, int ire_type)
{
	int		err;
	nce_t		*nce = NULL;
	uint16_t	ncec_flags;
	uchar_t		*hwaddr;
	boolean_t	need_refrele = B_FALSE;
	ill_t		*in_ill = ill;
	boolean_t	is_unicast;
	uint_t		hwaddr_len;

	is_unicast = ((ire_type & (IRE_MULTICAST|IRE_BROADCAST)) == 0);
	if (IS_IPMP(ill) ||
	    ((ire_type & IRE_BROADCAST) && IS_UNDER_IPMP(ill))) {
		if ((ill = ipmp_ill_hold_xmit_ill(ill, is_unicast)) == NULL)
			return (NULL);
		need_refrele = B_TRUE;
	}
	ncec_flags = (ill->ill_flags & ILLF_NONUD) ? NCE_F_NONUD : 0;

	switch (ire_type) {
	case IRE_BROADCAST:
		ASSERT(!ill->ill_isv6);
		ncec_flags |= (NCE_F_BCAST|NCE_F_NONUD);
		break;
	case IRE_MULTICAST:
		ncec_flags |= (NCE_F_MCAST|NCE_F_NONUD);
		break;
	}

	if (ill->ill_net_type == IRE_IF_NORESOLVER && is_unicast) {
		hwaddr = ill->ill_dest_addr;
	} else {
		hwaddr = NULL;
	}
	hwaddr_len = ill->ill_phys_addr_length;

retry:
	/* nce_state will be computed by nce_add_common() */
	if (!ill->ill_isv6) {
		err = nce_lookup_then_add_v4(ill, hwaddr, hwaddr_len, addr,
		    ncec_flags, ND_UNCHANGED, &nce);
	} else {
		err = nce_lookup_then_add_v6(ill, hwaddr, hwaddr_len, addr,
		    ncec_flags, ND_UNCHANGED, &nce);
	}

	switch (err) {
	case 0:
		break;
	case EEXIST:
		/*
		 * When subnets change or partially overlap what was once
		 * a broadcast address could now be a unicast, or vice versa.
		 */
		if (((ncec_flags ^ nce->nce_common->ncec_flags) &
		    NCE_F_BCAST) != 0) {
			ASSERT(!ill->ill_isv6);
			ncec_delete(nce->nce_common);
			nce_refrele(nce);
			goto retry;
		}
		break;
	default:
		DTRACE_PROBE2(nce__init__fail, ill_t *, ill, int, err);
		if (need_refrele)
			ill_refrele(ill);
		return (NULL);
	}
	/*
	 * If the ill was an under-ill of an IPMP group, we need to verify
	 * that it is still active so that we select an active interface in
	 * the group. However, since ipmp_ill_is_active ASSERTs for
	 * IS_UNDER_IPMP(), we first need to verify that the ill is an
	 * under-ill, and since this is being done in the data path, the
	 * only way to ascertain this is by holding the ill_g_lock.
	 */
	rw_enter(&ill->ill_ipst->ips_ill_g_lock, RW_READER);
	mutex_enter(&ill->ill_lock);
	mutex_enter(&ill->ill_phyint->phyint_lock);
	if (need_refrele && IS_UNDER_IPMP(ill) && !ipmp_ill_is_active(ill)) {
		/*
		 * need_refrele implies that the under ill was selected by
		 * ipmp_ill_hold_xmit_ill() because either the in_ill was an
		 * ipmp_ill, or we are sending a non-unicast packet on an
		 * under_ill. However, when we get here, the ill selected by
		 * ipmp_ill_hold_xmit_ill was pulled out of the active set
		 * (for unicast) or cast_ill nomination (for !unicast) after
		 * it was picked as the outgoing ill.  We have to pick an
		 * active interface and/or cast_ill in the group.
		 */
		mutex_exit(&ill->ill_phyint->phyint_lock);
		nce_delete(nce);
		mutex_exit(&ill->ill_lock);
		rw_exit(&ill->ill_ipst->ips_ill_g_lock);
		nce_refrele(nce);
		ill_refrele(ill);
		if ((ill = ipmp_ill_hold_xmit_ill(in_ill, is_unicast)) == NULL)
			return (NULL);
		goto retry;
	} else {
		mutex_exit(&ill->ill_phyint->phyint_lock);
		mutex_exit(&ill->ill_lock);
		rw_exit(&ill->ill_ipst->ips_ill_g_lock);
	}
done:
	ASSERT(nce->nce_ill == ill);
	if (need_refrele)
		ill_refrele(ill);
	return (nce);
}

nce_t *
arp_nce_init(ill_t *ill, in_addr_t addr4, int ire_type)
{
	return (ire_nce_init(ill, &addr4, ire_type));
}

nce_t *
ndp_nce_init(ill_t *ill, const in6_addr_t *addr6, int ire_type)
{
	ASSERT((ire_type & IRE_BROADCAST) == 0);
	return (ire_nce_init(ill, addr6, ire_type));
}

/*
 * The caller should hold irb_lock as a writer if the ire is in a bucket.
 * This routine will clear ire_nce_cache, and we make sure that we can never
 * set ire_nce_cache after the ire is marked condemned.
 */
void
ire_make_condemned(ire_t *ire)
{
	ip_stack_t	*ipst = ire->ire_ipst;
	nce_t		*nce;

	mutex_enter(&ire->ire_lock);
	ASSERT(ire->ire_bucket == NULL ||
	    RW_WRITE_HELD(&ire->ire_bucket->irb_lock));
	ASSERT(!IRE_IS_CONDEMNED(ire));
	ire->ire_generation = IRE_GENERATION_CONDEMNED;
	/* Count how many condemned ires for kmem_cache callback */
	atomic_inc_32(&ipst->ips_num_ire_condemned);
	nce = ire->ire_nce_cache;
	ire->ire_nce_cache = NULL;
	mutex_exit(&ire->ire_lock);
	if (nce != NULL)
		nce_refrele(nce);
}

/*
 * Increment the generation avoiding the special condemned value
 */
void
ire_increment_generation(ire_t *ire)
{
	uint_t generation;

	mutex_enter(&ire->ire_lock);
	/*
	 * Even though the caller has a hold it can't prevent a concurrent
	 * ire_delete marking the IRE condemned
	 */
	if (!IRE_IS_CONDEMNED(ire)) {
		generation = ire->ire_generation + 1;
		if (generation == IRE_GENERATION_CONDEMNED)
			generation = IRE_GENERATION_INITIAL;
		ASSERT(generation != IRE_GENERATION_VERIFY);
		ire->ire_generation = generation;
	}
	mutex_exit(&ire->ire_lock);
}

/*
 * Increment ire_generation on all the IRE_MULTICASTs
 * Used when the default multicast interface (as determined by
 * ill_lookup_multicast) might have changed.
 *
 * That includes the zoneid, IFF_ flags, the IPv6 scope of the address, and
 * ill unplumb.
 */
void
ire_increment_multicast_generation(ip_stack_t *ipst, boolean_t isv6)
{
	ill_t	*ill;
	ill_walk_context_t ctx;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (isv6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (ILL_IS_CONDEMNED(ill))
			continue;
		if (ill->ill_ire_multicast != NULL)
			ire_increment_generation(ill->ill_ire_multicast);
	}
	rw_exit(&ipst->ips_ill_g_lock);
}

/*
 * Return a held IRE_NOROUTE with RTF_REJECT set
 */
ire_t *
ire_reject(ip_stack_t *ipst, boolean_t isv6)
{
	ire_t *ire;

	if (isv6)
		ire = ipst->ips_ire_reject_v6;
	else
		ire = ipst->ips_ire_reject_v4;

	ASSERT(ire->ire_generation != IRE_GENERATION_CONDEMNED);
	ire_refhold(ire);
	return (ire);
}

/*
 * Return a held IRE_NOROUTE with RTF_BLACKHOLE set
 */
ire_t *
ire_blackhole(ip_stack_t *ipst, boolean_t isv6)
{
	ire_t *ire;

	if (isv6)
		ire = ipst->ips_ire_blackhole_v6;
	else
		ire = ipst->ips_ire_blackhole_v4;

	ASSERT(ire->ire_generation != IRE_GENERATION_CONDEMNED);
	ire_refhold(ire);
	return (ire);
}

/*
 * Return a held IRE_MULTICAST.
 */
ire_t *
ire_multicast(ill_t *ill)
{
	ire_t *ire = ill->ill_ire_multicast;

	ASSERT(ire == NULL || ire->ire_generation != IRE_GENERATION_CONDEMNED);
	if (ire == NULL)
		ire = ire_blackhole(ill->ill_ipst, ill->ill_isv6);
	else
		ire_refhold(ire);
	return (ire);
}

/*
 * Given an IRE return its nexthop IRE. The nexthop IRE is an IRE_ONLINK
 * that is an exact match (i.e., a /32 for IPv4 and /128 for IPv6).
 * This can return an RTF_REJECT|RTF_BLACKHOLE.
 * The returned IRE is held.
 * The assumption is that ip_select_route() has been called and returned the
 * IRE (thus ip_select_route would have set up the ire_dep* information.)
 * If some IRE is deleteted then ire_dep_remove() will have been called and
 * we might not find a nexthop IRE, in which case we return NULL.
 */
ire_t *
ire_nexthop(ire_t *ire)
{
	ip_stack_t	*ipst = ire->ire_ipst;

	/* Acquire lock to walk ire_dep_parent */
	rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
	while (ire != NULL) {
		if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
			goto done;
		}
		/*
		 * If we find an IRE_ONLINK we are done. This includes
		 * the case of IRE_MULTICAST.
		 * Note that in order to send packets we need a host-specific
		 * IRE_IF_ALL first in the ire_dep_parent chain. Normally this
		 * is done by inserting an IRE_IF_CLONE if the IRE_INTERFACE
		 * was not host specific.
		 * However, ip_rts_request doesn't want to send packets
		 * hence doesn't want to allocate an IRE_IF_CLONE. Yet
		 * it needs an IRE_IF_ALL to get to the ill. Thus
		 * we return IRE_IF_ALL that are not host specific here.
		 */
		if (ire->ire_type & IRE_ONLINK)
			goto done;
		ire = ire->ire_dep_parent;
	}
	rw_exit(&ipst->ips_ire_dep_lock);
	return (NULL);

done:
	ire_refhold(ire);
	rw_exit(&ipst->ips_ire_dep_lock);
	return (ire);
}

/*
 * Find the ill used to send packets. This will be NULL in case
 * of a reject or blackhole.
 * The returned ill is held; caller needs to do ill_refrele when done.
 */
ill_t *
ire_nexthop_ill(ire_t *ire)
{
	ill_t		*ill;

	ire = ire_nexthop(ire);
	if (ire == NULL)
		return (NULL);

	/* ire_ill can not change for an existing ire */
	ill = ire->ire_ill;
	if (ill != NULL)
		ill_refhold(ill);
	ire_refrele(ire);
	return (ill);
}

#ifdef DEBUG
static boolean_t
parent_has_child(ire_t *parent, ire_t *child)
{
	ire_t	*ire;
	ire_t	*prev;

	ire = parent->ire_dep_children;
	prev = NULL;
	while (ire != NULL) {
		if (prev == NULL) {
			ASSERT(ire->ire_dep_sib_ptpn ==
			    &(parent->ire_dep_children));
		} else {
			ASSERT(ire->ire_dep_sib_ptpn ==
			    &(prev->ire_dep_sib_next));
		}
		if (ire == child)
			return (B_TRUE);
		prev = ire;
		ire = ire->ire_dep_sib_next;
	}
	return (B_FALSE);
}

static void
ire_dep_verify(ire_t *ire)
{
	ire_t		*parent = ire->ire_dep_parent;
	ire_t		*child = ire->ire_dep_children;

	ASSERT(ire->ire_ipversion == IPV4_VERSION ||
	    ire->ire_ipversion == IPV6_VERSION);
	if (parent != NULL) {
		ASSERT(parent->ire_ipversion == IPV4_VERSION ||
		    parent->ire_ipversion == IPV6_VERSION);
		ASSERT(parent->ire_refcnt >= 1);
		ASSERT(parent_has_child(parent, ire));
	}
	if (child != NULL) {
		ASSERT(child->ire_ipversion == IPV4_VERSION ||
		    child->ire_ipversion == IPV6_VERSION);
		ASSERT(child->ire_dep_parent == ire);
		ASSERT(child->ire_dep_sib_ptpn != NULL);
		ASSERT(parent_has_child(ire, child));
	}
}
#endif /* DEBUG */

/*
 * Assumes ire_dep_parent is set. Remove this child from its parent's linkage.
 */
void
ire_dep_remove(ire_t *ire)
{
	ip_stack_t	*ipst = ire->ire_ipst;
	ire_t		*parent = ire->ire_dep_parent;
	ire_t		*next;
	nce_t		*nce;

	ASSERT(RW_WRITE_HELD(&ipst->ips_ire_dep_lock));
	ASSERT(ire->ire_dep_parent != NULL);
	ASSERT(ire->ire_dep_sib_ptpn != NULL);

#ifdef DEBUG
	ire_dep_verify(ire);
	ire_dep_verify(parent);
#endif

	next = ire->ire_dep_sib_next;
	if (next != NULL)
		next->ire_dep_sib_ptpn = ire->ire_dep_sib_ptpn;

	ASSERT(*(ire->ire_dep_sib_ptpn) == ire);
	*(ire->ire_dep_sib_ptpn) = ire->ire_dep_sib_next;

	ire->ire_dep_sib_ptpn = NULL;
	ire->ire_dep_sib_next = NULL;

	mutex_enter(&ire->ire_lock);
	parent = ire->ire_dep_parent;
	ire->ire_dep_parent = NULL;
	mutex_exit(&ire->ire_lock);

	/*
	 * Make sure all our children, grandchildren, etc set
	 * ire_dep_parent_generation to IRE_GENERATION_VERIFY since
	 * we can no longer guarantee than the children have a current
	 * ire_nce_cache and ire_nexthop_ill().
	 */
	if (ire->ire_dep_children != NULL)
		ire_dep_invalidate_children(ire->ire_dep_children);

	/*
	 * Since the parent is gone we make sure we clear ire_nce_cache.
	 * We can clear it under ire_lock even if the IRE is used
	 */
	mutex_enter(&ire->ire_lock);
	nce = ire->ire_nce_cache;
	ire->ire_nce_cache = NULL;
	mutex_exit(&ire->ire_lock);
	if (nce != NULL)
		nce_refrele(nce);

#ifdef DEBUG
	ire_dep_verify(ire);
	ire_dep_verify(parent);
#endif

	ire_refrele_notr(parent);
	ire_refrele_notr(ire);
}

/*
 * Insert the child in the linkage of the parent
 */
static void
ire_dep_parent_insert(ire_t *child, ire_t *parent)
{
	ip_stack_t	*ipst = child->ire_ipst;
	ire_t		*next;

	ASSERT(RW_WRITE_HELD(&ipst->ips_ire_dep_lock));
	ASSERT(child->ire_dep_parent == NULL);

#ifdef DEBUG
	ire_dep_verify(child);
	ire_dep_verify(parent);
#endif
	/* No parents => no siblings */
	ASSERT(child->ire_dep_sib_ptpn == NULL);
	ASSERT(child->ire_dep_sib_next == NULL);

	ire_refhold_notr(parent);
	ire_refhold_notr(child);

	/* Head insertion */
	next = parent->ire_dep_children;
	if (next != NULL) {
		ASSERT(next->ire_dep_sib_ptpn == &(parent->ire_dep_children));
		child->ire_dep_sib_next = next;
		next->ire_dep_sib_ptpn = &(child->ire_dep_sib_next);
	}
	parent->ire_dep_children = child;
	child->ire_dep_sib_ptpn = &(parent->ire_dep_children);

	mutex_enter(&child->ire_lock);
	child->ire_dep_parent = parent;
	mutex_exit(&child->ire_lock);

#ifdef DEBUG
	ire_dep_verify(child);
	ire_dep_verify(parent);
#endif
}


/*
 * Given count worth of ires and generations, build ire_dep_* relationships
 * from ires[0] to ires[count-1]. Record generations[i+1] in
 * ire_dep_parent_generation for ires[i].
 * We graft onto an existing parent chain by making sure that we don't
 * touch ire_dep_parent for ires[count-1].
 *
 * We check for any condemned ire_generation count and return B_FALSE in
 * that case so that the caller can tear it apart.
 *
 * Note that generations[0] is not used. Caller handles that.
 */
boolean_t
ire_dep_build(ire_t *ires[], uint_t generations[], uint_t count)
{
	ire_t		*ire = ires[0];
	ip_stack_t	*ipst;
	uint_t		i;

	ASSERT(count > 0);
	if (count == 1) {
		/* No work to do */
		return (B_TRUE);
	}
	ipst = ire->ire_ipst;
	rw_enter(&ipst->ips_ire_dep_lock, RW_WRITER);
	/*
	 * Do not remove the linkage for any existing parent chain i.e.,
	 * ires[count-1] is left alone.
	 */
	for (i = 0; i < count-1; i++) {
		/* Remove existing parent if we need to change it */
		if (ires[i]->ire_dep_parent != NULL &&
		    ires[i]->ire_dep_parent != ires[i+1])
			ire_dep_remove(ires[i]);
	}

	for (i = 0; i < count - 1; i++) {
		ASSERT(ires[i]->ire_ipversion == IPV4_VERSION ||
		    ires[i]->ire_ipversion == IPV6_VERSION);
		/* Does it need to change? */
		if (ires[i]->ire_dep_parent != ires[i+1])
			ire_dep_parent_insert(ires[i], ires[i+1]);

		mutex_enter(&ires[i+1]->ire_lock);
		if (IRE_IS_CONDEMNED(ires[i+1])) {
			mutex_exit(&ires[i+1]->ire_lock);
			rw_exit(&ipst->ips_ire_dep_lock);
			return (B_FALSE);
		}
		mutex_exit(&ires[i+1]->ire_lock);

		mutex_enter(&ires[i]->ire_lock);
		ires[i]->ire_dep_parent_generation = generations[i+1];
		mutex_exit(&ires[i]->ire_lock);
	}
	rw_exit(&ipst->ips_ire_dep_lock);
	return (B_TRUE);
}

/*
 * Given count worth of ires, unbuild ire_dep_* relationships
 * from ires[0] to ires[count-1].
 */
void
ire_dep_unbuild(ire_t *ires[], uint_t count)
{
	ip_stack_t	*ipst;
	uint_t		i;

	if (count == 0) {
		/* No work to do */
		return;
	}
	ipst = ires[0]->ire_ipst;
	rw_enter(&ipst->ips_ire_dep_lock, RW_WRITER);
	for (i = 0; i < count; i++) {
		ASSERT(ires[i]->ire_ipversion == IPV4_VERSION ||
		    ires[i]->ire_ipversion == IPV6_VERSION);
		if (ires[i]->ire_dep_parent != NULL)
			ire_dep_remove(ires[i]);
		mutex_enter(&ires[i]->ire_lock);
		ires[i]->ire_dep_parent_generation = IRE_GENERATION_VERIFY;
		mutex_exit(&ires[i]->ire_lock);
	}
	rw_exit(&ipst->ips_ire_dep_lock);
}

/*
 * Both the forwarding and the outbound code paths can trip on
 * a condemned NCE, in which case we call this function.
 * We have two different behaviors: if the NCE was UNREACHABLE
 * it is an indication that something failed. In that case
 * we see if we should look for a different IRE (for example,
 * delete any matching redirect IRE, or try a different
 * IRE_DEFAULT (ECMP)). We mark the ire as bad so a hopefully
 * different IRE will be picked next time we send/forward.
 *
 * If we are called by the output path then fail_if_better is set
 * and we return NULL if there could be a better IRE. This is because the
 * output path retries the IRE lookup. (The input/forward path can not retry.)
 *
 * If the NCE was not unreachable then we pick/allocate a
 * new (most likely ND_INITIAL) NCE and proceed with it.
 *
 * ipha/ip6h are needed for multicast packets; ipha needs to be
 * set for IPv4 and ip6h needs to be set for IPv6 packets.
 */
nce_t *
ire_handle_condemned_nce(nce_t *nce, ire_t *ire, ipha_t *ipha, ip6_t *ip6h,
    boolean_t fail_if_better)
{
	if (nce->nce_common->ncec_state == ND_UNREACHABLE) {
		if (ire_no_good(ire) && fail_if_better) {
			/*
			 * Did some changes, or ECMP likely to exist.
			 * Make ip_output look for a different IRE
			 */
			return (NULL);
		}
	}
	if (ire_revalidate_nce(ire) == ENETUNREACH) {
		/* The ire_dep_parent chain went bad, or no memory? */
		(void) ire_no_good(ire);
		return (NULL);
	}
	if (ire->ire_ipversion == IPV4_VERSION) {
		ASSERT(ipha != NULL);
		nce = ire_to_nce(ire, ipha->ipha_dst, NULL);
	} else {
		ASSERT(ip6h != NULL);
		nce = ire_to_nce(ire, INADDR_ANY, &ip6h->ip6_dst);
	}

	if (nce == NULL)
		return (NULL);
	if (nce->nce_is_condemned) {
		nce_refrele(nce);
		return (NULL);
	}
	return (nce);
}

/*
 * The caller has found that the ire is bad, either due to a reference to an NCE
 * in ND_UNREACHABLE state, or a MULTIRT route whose gateway can't be resolved.
 * We update things so a subsequent attempt to send to the destination
 * is likely to find different IRE, or that a new NCE would be created.
 *
 * Returns B_TRUE if it is likely that a subsequent ire_ftable_lookup would
 * find a different route (either due to having deleted a redirect, or there
 * being ECMP routes.)
 *
 * If we have a redirect (RTF_DYNAMIC) we delete it.
 * Otherwise we increment ire_badcnt and increment the generation number so
 * that a cached ixa_ire will redo the route selection. ire_badcnt is taken
 * into account in the route selection when we have multiple choices (multiple
 * default routes or ECMP in general).
 * Any time ip_select_route find an ire with a condemned ire_nce_cache
 * (e.g., if no equal cost route to the bad one) ip_select_route will make
 * sure the NCE is revalidated to avoid getting stuck on a
 * NCE_F_CONDMNED ncec that caused ire_no_good to be called.
 */
boolean_t
ire_no_good(ire_t *ire)
{
	ip_stack_t	*ipst = ire->ire_ipst;
	ire_t		*ire2;
	nce_t		*nce;

	if (ire->ire_flags & RTF_DYNAMIC) {
		ire_delete(ire);
		return (B_TRUE);
	}
	if (ire->ire_flags & RTF_INDIRECT) {
		/* Check if next IRE is a redirect */
		rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
		if (ire->ire_dep_parent != NULL &&
		    (ire->ire_dep_parent->ire_flags & RTF_DYNAMIC)) {
			ire2 = ire->ire_dep_parent;
			ire_refhold(ire2);
		} else {
			ire2 = NULL;
		}
		rw_exit(&ipst->ips_ire_dep_lock);
		if (ire2 != NULL) {
			ire_delete(ire2);
			ire_refrele(ire2);
			return (B_TRUE);
		}
	}
	/*
	 * No redirect involved. Increment badcnt so that if we have ECMP
	 * routes we are likely to pick a different one for the next packet.
	 *
	 * If the NCE is unreachable and condemned we should drop the reference
	 * to it so that a new NCE can be created.
	 *
	 * Finally we increment the generation number so that any ixa_ire
	 * cache will be revalidated.
	 */
	mutex_enter(&ire->ire_lock);
	ire->ire_badcnt++;
	ire->ire_last_badcnt = TICK_TO_SEC(ddi_get_lbolt64());
	nce = ire->ire_nce_cache;
	if (nce != NULL && nce->nce_is_condemned &&
	    nce->nce_common->ncec_state == ND_UNREACHABLE)
		ire->ire_nce_cache = NULL;
	else
		nce = NULL;
	mutex_exit(&ire->ire_lock);
	if (nce != NULL)
		nce_refrele(nce);

	ire_increment_generation(ire);
	ire_dep_incr_generation(ire);

	return (ire->ire_bucket->irb_ire_cnt > 1);
}

/*
 * Walk ire_dep_parent chain and validate that ire_dep_parent->ire_generation ==
 * ire_dep_parent_generation.
 * If they all match we just return ire_generation from the topmost IRE.
 * Otherwise we propagate the mismatch by setting all ire_dep_parent_generation
 * above the mismatch to IRE_GENERATION_VERIFY and also returning
 * IRE_GENERATION_VERIFY.
 */
uint_t
ire_dep_validate_generations(ire_t *ire)
{
	ip_stack_t	*ipst = ire->ire_ipst;
	uint_t		generation;
	ire_t		*ire1;

	rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
	generation = ire->ire_generation;	/* Assuming things match */
	for (ire1 = ire; ire1 != NULL; ire1 = ire1->ire_dep_parent) {
		ASSERT(ire1->ire_ipversion == IPV4_VERSION ||
		    ire1->ire_ipversion == IPV6_VERSION);
		if (ire1->ire_dep_parent == NULL)
			break;
		if (ire1->ire_dep_parent_generation !=
		    ire1->ire_dep_parent->ire_generation)
			goto mismatch;
	}
	rw_exit(&ipst->ips_ire_dep_lock);
	return (generation);

mismatch:
	generation = IRE_GENERATION_VERIFY;
	/* Fill from top down to the mismatch with _VERIFY */
	while (ire != ire1) {
		ASSERT(ire->ire_ipversion == IPV4_VERSION ||
		    ire->ire_ipversion == IPV6_VERSION);
		mutex_enter(&ire->ire_lock);
		ire->ire_dep_parent_generation = IRE_GENERATION_VERIFY;
		mutex_exit(&ire->ire_lock);
		ire = ire->ire_dep_parent;
	}
	rw_exit(&ipst->ips_ire_dep_lock);
	return (generation);
}

/*
 * Used when we need to return an ire with ire_dep_parent, but we
 * know the chain is invalid for instance we didn't create an IRE_IF_CLONE
 * Using IRE_GENERATION_VERIFY means that next time we'll redo the
 * recursive lookup.
 */
void
ire_dep_invalidate_generations(ire_t *ire)
{
	ip_stack_t	*ipst = ire->ire_ipst;

	rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
	while (ire != NULL) {
		ASSERT(ire->ire_ipversion == IPV4_VERSION ||
		    ire->ire_ipversion == IPV6_VERSION);
		mutex_enter(&ire->ire_lock);
		ire->ire_dep_parent_generation = IRE_GENERATION_VERIFY;
		mutex_exit(&ire->ire_lock);
		ire = ire->ire_dep_parent;
	}
	rw_exit(&ipst->ips_ire_dep_lock);
}

/* Set _VERIFY ire_dep_parent_generation for all children recursively */
static void
ire_dep_invalidate_children(ire_t *child)
{
	ip_stack_t	*ipst = child->ire_ipst;

	ASSERT(RW_WRITE_HELD(&ipst->ips_ire_dep_lock));
	/* Depth first */
	if (child->ire_dep_children != NULL)
		ire_dep_invalidate_children(child->ire_dep_children);

	while (child != NULL) {
		mutex_enter(&child->ire_lock);
		child->ire_dep_parent_generation = IRE_GENERATION_VERIFY;
		mutex_exit(&child->ire_lock);
		child = child->ire_dep_sib_next;
	}
}

static void
ire_dep_increment_children(ire_t *child)
{
	ip_stack_t	*ipst = child->ire_ipst;

	ASSERT(RW_READ_HELD(&ipst->ips_ire_dep_lock));
	/* Depth first */
	if (child->ire_dep_children != NULL)
		ire_dep_increment_children(child->ire_dep_children);

	while (child != NULL) {
		if (!IRE_IS_CONDEMNED(child))
			ire_increment_generation(child);
		child = child->ire_dep_sib_next;
	}
}

/*
 * Walk all the children of this ire recursively and increment their
 * generation number.
 */
static void
ire_dep_incr_generation_locked(ire_t *parent)
{
	ASSERT(RW_READ_HELD(&parent->ire_ipst->ips_ire_dep_lock));
	if (parent->ire_dep_children != NULL)
		ire_dep_increment_children(parent->ire_dep_children);
}

void
ire_dep_incr_generation(ire_t *parent)
{
	ip_stack_t	*ipst = parent->ire_ipst;

	rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
	ire_dep_incr_generation_locked(parent);
	rw_exit(&ipst->ips_ire_dep_lock);
}

/*
 * Get a new ire_nce_cache for this IRE as well as its nexthop.
 * Returns zero if it succeeds. Can fail due to lack of memory or when
 * the route has become unreachable. Returns ENOMEM and ENETUNREACH in those
 * cases.
 *
 * In the in.mpathd case, the ire will have ire_testhidden
 * set; so we should create the ncec for the underlying ill.
 *
 * Note that the error returned by ire_revalidate_nce() is ignored by most
 * callers except ire_handle_condemned_nce(), which handles the ENETUNREACH
 * error to mark potentially bad ire's. For all the other callers, an
 * error return could indicate a transient condition like ENOMEM, or could
 * be the result of an interface that is going down/unplumbing. In the former
 * case (transient error), we would leave the old stale ire/ire_nce_cache
 * in place, and possibly use incorrect link-layer information to send packets
 * but would eventually recover. In the latter case (ill down/replumb),
 * ire_revalidate_nce() might return a condemned nce back, but we would then
 * recover in the packet output path.
 */
int
ire_revalidate_nce(ire_t *ire)
{
	nce_t		*nce, *old_nce;
	ire_t		*nexthop;

	/*
	 * For multicast we conceptually have an NCE but we don't store it
	 * in ire_nce_cache; when ire_to_nce is called we allocate the nce.
	 */
	if (ire->ire_type & IRE_MULTICAST)
		return (0);

	/* ire_testhidden should only be set on under-interfaces */
	ASSERT(!ire->ire_testhidden || !IS_IPMP(ire->ire_ill));

	nexthop = ire_nexthop(ire);
	if (nexthop == NULL) {
		/* The route is potentially bad */
		(void) ire_no_good(ire);
		return (ENETUNREACH);
	}
	if (ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK)) {
		ASSERT(ire->ire_ill != NULL);

		if (ire->ire_ipversion == IPV4_VERSION)
			nce = nce_lookup_v4(ire->ire_ill, &ire->ire_addr);
		else
			nce = nce_lookup_v6(ire->ire_ill, &ire->ire_addr_v6);
	} else {
		ASSERT(nexthop->ire_type & IRE_ONLINK);
		if (ire->ire_ipversion == IPV4_VERSION) {
			nce = arp_nce_init(nexthop->ire_ill, nexthop->ire_addr,
			    nexthop->ire_type);
		} else {
			nce = ndp_nce_init(nexthop->ire_ill,
			    &nexthop->ire_addr_v6, nexthop->ire_type);
		}
	}
	if (nce == NULL) {
		/*
		 * Leave the old stale one in place to avoid a NULL
		 * ire_nce_cache.
		 */
		ire_refrele(nexthop);
		return (ENOMEM);
	}

	if (nexthop != ire) {
		/* Update the nexthop ire */
		mutex_enter(&nexthop->ire_lock);
		old_nce = nexthop->ire_nce_cache;
		if (!IRE_IS_CONDEMNED(nexthop)) {
			nce_refhold(nce);
			nexthop->ire_nce_cache = nce;
		} else {
			nexthop->ire_nce_cache = NULL;
		}
		mutex_exit(&nexthop->ire_lock);
		if (old_nce != NULL)
			nce_refrele(old_nce);
	}
	ire_refrele(nexthop);

	mutex_enter(&ire->ire_lock);
	old_nce = ire->ire_nce_cache;
	if (!IRE_IS_CONDEMNED(ire)) {
		nce_refhold(nce);
		ire->ire_nce_cache = nce;
	} else {
		ire->ire_nce_cache = NULL;
	}
	mutex_exit(&ire->ire_lock);
	if (old_nce != NULL)
		nce_refrele(old_nce);

	nce_refrele(nce);
	return (0);
}

/*
 * Get a held nce for a given ire.
 * In the common case this is just from ire_nce_cache.
 * For IRE_MULTICAST this needs to do an explicit lookup since we do not
 * have an IRE_MULTICAST per address.
 * Note that this explicitly returns CONDEMNED NCEs. The caller needs those
 * so they can check whether the NCE went unreachable (as opposed to was
 * condemned for some other reason).
 */
nce_t *
ire_to_nce(ire_t *ire, ipaddr_t v4nexthop, const in6_addr_t *v6nexthop)
{
	nce_t	*nce;

	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))
		return (NULL);

	/* ire_testhidden should only be set on under-interfaces */
	ASSERT(!ire->ire_testhidden || !IS_IPMP(ire->ire_ill));

	mutex_enter(&ire->ire_lock);
	nce = ire->ire_nce_cache;
	if (nce != NULL) {
		nce_refhold(nce);
		mutex_exit(&ire->ire_lock);
		return (nce);
	}
	mutex_exit(&ire->ire_lock);

	if (ire->ire_type & IRE_MULTICAST) {
		ASSERT(ire->ire_ill != NULL);

		if (ire->ire_ipversion == IPV4_VERSION) {
			ASSERT(v6nexthop == NULL);

			nce = arp_nce_init(ire->ire_ill, v4nexthop,
			    ire->ire_type);
		} else {
			ASSERT(v6nexthop != NULL);
			ASSERT(v4nexthop == 0);
			nce = ndp_nce_init(ire->ire_ill, v6nexthop,
			    ire->ire_type);
		}
		return (nce);
	}
	return (NULL);
}

nce_t *
ire_to_nce_pkt(ire_t *ire, mblk_t *mp)
{
	ipha_t		*ipha;
	ip6_t		*ip6h;

	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		ipha = (ipha_t *)mp->b_rptr;
		return (ire_to_nce(ire, ipha->ipha_dst, NULL));
	} else {
		ip6h = (ip6_t *)mp->b_rptr;
		return (ire_to_nce(ire, INADDR_ANY, &ip6h->ip6_dst));
	}
}

/*
 * Given an IRE_INTERFACE (that matches more than one address) create
 * and return an IRE_IF_CLONE for the specific address.
 * Return the generation number.
 * Returns NULL is no memory for the IRE.
 * Handles both IPv4 and IPv6.
 *
 * IRE_IF_CLONE entries may only be created adn added by calling
 * ire_create_if_clone(), and we depend on the fact that ire_add will
 * atomically ensure that attempts to add multiple identical IRE_IF_CLONE
 * entries will not result in duplicate (i.e., ire_identical_ref > 1)
 * CLONE entries, so that a single ire_delete is sufficient to remove the
 * CLONE.
 */
ire_t *
ire_create_if_clone(ire_t *ire_if, const in6_addr_t *addr, uint_t *generationp)
{
	ire_t		*ire;
	ire_t		*nire;

	if (ire_if->ire_ipversion == IPV4_VERSION) {
		ipaddr_t	v4addr;
		ipaddr_t	mask = IP_HOST_MASK;

		ASSERT(IN6_IS_ADDR_V4MAPPED(addr));
		IN6_V4MAPPED_TO_IPADDR(addr, v4addr);

		ire = ire_create(
		    (uchar_t *)&v4addr,			/* dest address */
		    (uchar_t *)&mask,			/* mask */
		    (uchar_t *)&ire_if->ire_gateway_addr,
		    IRE_IF_CLONE,			/* IRE type */
		    ire_if->ire_ill,
		    ire_if->ire_zoneid,
		    ire_if->ire_flags | RTF_HOST,
		    NULL,		/* No security attr for IRE_IF_ALL */
		    ire_if->ire_ipst);
	} else {
		ASSERT(!IN6_IS_ADDR_V4MAPPED(addr));
		ire = ire_create_v6(
		    addr,				/* dest address */
		    &ipv6_all_ones,			/* mask */
		    &ire_if->ire_gateway_addr_v6,	/* gateway addr */
		    IRE_IF_CLONE,			/* IRE type */
		    ire_if->ire_ill,
		    ire_if->ire_zoneid,
		    ire_if->ire_flags | RTF_HOST,
		    NULL,		/* No security attr for IRE_IF_ALL */
		    ire_if->ire_ipst);
	}
	if (ire == NULL)
		return (NULL);

	/* Take the metrics, in particular the mtu, from the IRE_IF */
	ire->ire_metrics = ire_if->ire_metrics;

	nire = ire_add(ire);
	if (nire == NULL) /* Some failure */
		return (NULL);

	if (generationp != NULL)
		*generationp = nire->ire_generation;

	return (nire);
}

/*
 * The argument is an IRE_INTERFACE. Delete all of IRE_IF_CLONE in the
 * ire_dep_children (just walk the ire_dep_sib_next since they are all
 * immediate children.)
 * Since we hold a lock while we remove them we need to defer the actual
 * calls to ire_delete() until we have dropped the lock. This makes things
 * less efficient since we restart at the top after dropping the lock. But
 * we only run when an IRE_INTERFACE is deleted which is infrquent.
 *
 * Note that ire_dep_children can be any mixture of offlink routes and
 * IRE_IF_CLONE entries.
 */
void
ire_dep_delete_if_clone(ire_t *parent)
{
	ip_stack_t	*ipst = parent->ire_ipst;
	ire_t		*child, *next;

restart:
	rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
	if (parent->ire_dep_children == NULL) {
		rw_exit(&ipst->ips_ire_dep_lock);
		return;
	}
	child = parent->ire_dep_children;
	while (child != NULL) {
		next = child->ire_dep_sib_next;
		if ((child->ire_type & IRE_IF_CLONE) &&
		    !IRE_IS_CONDEMNED(child)) {
			ire_refhold(child);
			rw_exit(&ipst->ips_ire_dep_lock);
			ire_delete(child);
			ASSERT(IRE_IS_CONDEMNED(child));
			ire_refrele(child);
			goto restart;
		}
		child = next;
	}
	rw_exit(&ipst->ips_ire_dep_lock);
}

/*
 * In the preferred/strict src multihoming modes, unbound routes (i.e.,
 * ire_t entries with ire_unbound set to B_TRUE) are bound to an interface
 * by selecting the first available interface that has an interface route for
 * the ire_gateway. If that interface is subsequently brought down, ill_downi()
 * will call ire_rebind() so that the unbound route can be bound to some other
 * matching interface thereby preserving the intended reachability information
 * from the original unbound route.
 */
void
ire_rebind(ire_t *ire)
{
	ire_t	*gw_ire, *new_ire;
	int	match_flags = MATCH_IRE_TYPE;
	ill_t	*gw_ill;
	boolean_t isv6 = (ire->ire_ipversion == IPV6_VERSION);
	ip_stack_t *ipst = ire->ire_ipst;

	ASSERT(ire->ire_unbound);
again:
	if (isv6) {
		gw_ire = ire_ftable_lookup_v6(&ire->ire_gateway_addr_v6, 0, 0,
		    IRE_INTERFACE, NULL, ALL_ZONES, NULL, match_flags, 0,
		    ipst, NULL);
	} else {
		gw_ire = ire_ftable_lookup_v4(ire->ire_gateway_addr, 0, 0,
		    IRE_INTERFACE, NULL, ALL_ZONES, NULL, match_flags, 0,
		    ipst, NULL);
	}
	if (gw_ire == NULL) {
		/* see comments in ip_rt_add[_v6]() for IPMP */
		if (match_flags & MATCH_IRE_TESTHIDDEN)
			return;

		match_flags |= MATCH_IRE_TESTHIDDEN;
		goto again;
	}
	gw_ill = gw_ire->ire_ill;
	if (isv6) {
		new_ire = ire_create_v6(&ire->ire_addr_v6, &ire->ire_mask_v6,
		    &ire->ire_gateway_addr_v6, ire->ire_type, gw_ill,
		    ire->ire_zoneid, ire->ire_flags, NULL, ipst);
	} else {
		new_ire = ire_create((uchar_t *)&ire->ire_addr,
		    (uchar_t *)&ire->ire_mask,
		    (uchar_t *)&ire->ire_gateway_addr, ire->ire_type, gw_ill,
		    ire->ire_zoneid, ire->ire_flags, NULL, ipst);
	}
	ire_refrele(gw_ire);
	if (new_ire == NULL)
		return;
	new_ire->ire_unbound = B_TRUE;
	new_ire = ire_add(new_ire);
	if (new_ire != NULL)
		ire_refrele(new_ire);
}
