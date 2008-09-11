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
/* Copyright (c) 1990 Mentat Inc. */

/*
 * This file contains routines that manipulate Internet Routing Entries (IREs).
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
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

#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>
#include <inet/sadb.h>
#include <sys/kmem.h>
#include <inet/tcp.h>
#include <inet/ipclassifier.h>
#include <sys/zone.h>
#include <sys/cpuvar.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

struct kmem_cache *rt_entry_cache;

/*
 * Synchronization notes:
 *
 * The fields of the ire_t struct are protected in the following way :
 *
 * ire_next/ire_ptpn
 *
 *	- bucket lock of the respective tables (cache or forwarding tables).
 *
 * ire_mp, ire_rfq, ire_stq, ire_u *except* ire_gateway_addr[v6], ire_mask,
 * ire_type, ire_create_time, ire_masklen, ire_ipversion, ire_flags, ire_ipif,
 * ire_ihandle, ire_phandle, ire_nce, ire_bucket, ire_in_ill, ire_in_src_addr
 *
 *	- Set in ire_create_v4/v6 and never changes after that. Thus,
 *	  we don't need a lock whenever these fields are accessed.
 *
 *	- ire_bucket and ire_masklen (also set in ire_create) is set in
 *        ire_add_v4/ire_add_v6 before inserting in the bucket and never
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
 * ire_ident, ire_refcnt
 *
 *	- Updated atomically using atomic_add_32
 *
 * ire_ssthresh, ire_rtt_sd, ire_rtt, ire_ib_pkt_count, ire_ob_pkt_count
 *
 *	- Assumes that 32 bit writes are atomic. No locks. ire_lock is
 *	  used to serialize updates to ire_ssthresh, ire_rtt_sd, ire_rtt.
 *
 * ire_max_frag, ire_frag_flag
 *
 *	- ire_lock is used to set/read both of them together.
 *
 * ire_tire_mark
 *
 *	- Set in ire_create and updated in ire_expire, which is called
 *	  by only one function namely ip_trash_timer_expire. Thus only
 *	  one function updates and examines the value.
 *
 * ire_marks
 *	- bucket lock protects this.
 *
 * ire_ipsec_overhead/ire_ll_hdr_length
 *
 *	- Place holder for returning the information to the upper layers
 *	  when IRE_DB_REQ comes down.
 *
 *
 * ipv6_ire_default_count is protected by the bucket lock of
 * ip_forwarding_table_v6[0][0].
 *
 * ipv6_ire_default_index is not protected as it  is just a hint
 * at which default gateway to use. There is nothing
 * wrong in using the same gateway for two different connections.
 *
 * As we always hold the bucket locks in all the places while accessing
 * the above values, it is natural to use them for protecting them.
 *
 * We have a separate cache table and forwarding table for IPv4 and IPv6.
 * Cache table (ip_cache_table/ip_cache_table_v6) is a pointer to an
 * array of irb_t structures. The IPv6 forwarding table
 * (ip_forwarding_table_v6) is an array of pointers to arrays of irb_t
 *  structure. ip_forwarding_table_v6 is allocated dynamically in
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
 * using the macro IRB_REFHOLD macro. The flags irb_flags can be
 * set to IRE_MARK_CONDEMNED indicating that there are some ires
 * in this bucket that are marked with IRE_MARK_CONDEMNED and the
 * last thread to leave the bucket should delete the ires. Usually
 * this is done by the IRB_REFRELE macro which is used to decrement
 * the reference count on a bucket. See comments above irb_t structure
 * definition in ip.h for further details.
 *
 * IRE_REFHOLD/IRE_REFRELE macros operate on the ire which increments/
 * decrements the reference count, ire_refcnt, atomically on the ire.
 * ire_refcnt is modified only using this macro. Operations on the IRE
 * could be described as follows :
 *
 * CREATE an ire with reference count initialized to 1.
 *
 * ADDITION of an ire holds the bucket lock, checks for duplicates
 * and then adds the ire. ire_add_v4/ire_add_v6 returns the ire after
 * bumping up once more i.e the reference count is 2. This is to avoid
 * an extra lookup in the functions calling ire_add which wants to
 * work with the ire after adding.
 *
 * LOOKUP of an ire bumps up the reference count using IRE_REFHOLD
 * macro. It is valid to bump up the referece count of the IRE,
 * after the lookup has returned an ire. Following are the lookup
 * functions that return an HELD ire :
 *
 * ire_lookup_local[_v6], ire_ctable_lookup[_v6], ire_ftable_lookup[_v6],
 * ire_cache_lookup[_v6], ire_lookup_multi[_v6], ire_route_lookup[_v6],
 * ipif_to_ire[_v6].
 *
 * DELETION of an ire holds the bucket lock, removes it from the list
 * and then decrements the reference count for having removed from the list
 * by using the IRE_REFRELE macro. If some other thread has looked up
 * the ire, the reference count would have been bumped up and hence
 * this ire will not be freed once deleted. It will be freed once the
 * reference count drops to zero.
 *
 * Add and Delete acquires the bucket lock as RW_WRITER, while all the
 * lookups acquire the bucket lock as RW_READER.
 *
 * NOTE : The only functions that does the IRE_REFRELE when an ire is
 *	  passed as an argument are :
 *
 *	  1) ip_wput_ire : This is because it IRE_REFHOLD/RELEs the
 *			   broadcast ires it looks up internally within
 *			   the function. Currently, for simplicity it does
 *			   not differentiate the one that is passed in and
 *			   the ones it looks up internally. It always
 *			   IRE_REFRELEs.
 *	  2) ire_send
 *	     ire_send_v6 : As ire_send calls ip_wput_ire and other functions
 *			   that take ire as an argument, it has to selectively
 *			   IRE_REFRELE the ire. To maintain symmetry,
 *			   ire_send_v6 does the same.
 *
 * Otherwise, the general rule is to do the IRE_REFRELE in the function
 * that is passing the ire as an argument.
 *
 * In trying to locate ires the following points are to be noted.
 *
 * IRE_MARK_CONDEMNED signifies that the ire has been logically deleted and is
 * to be ignored when walking the ires using ire_next.
 *
 * IRE_MARK_HIDDEN signifies that the ire is a special ire typically for the
 * benefit of in.mpathd which needs to probe interfaces for failures. Normal
 * applications should not be seeing this ire and hence this ire is ignored
 * in most cases in the search using ire_next.
 *
 * Zones note:
 *	Walking IREs within a given zone also walks certain ires in other
 *	zones.  This is done intentionally.  IRE walks with a specified
 *	zoneid are used only when doing informational reports, and
 *	zone users want to see things that they can access. See block
 *	comment in ire_walk_ill_match().
 */

/*
 * The minimum size of IRE cache table.  It will be recalcuated in
 * ip_ire_init().
 * Setable in /etc/system
 */
uint32_t ip_cache_table_size = IP_CACHE_TABLE_SIZE;
uint32_t ip6_cache_table_size = IP6_CACHE_TABLE_SIZE;

/*
 * The size of the forwarding table.  We will make sure that it is a
 * power of 2 in ip_ire_init().
 * Setable in /etc/system
 */
uint32_t ip6_ftable_hash_size = IP6_FTABLE_HASH_SIZE;

struct	kmem_cache	*ire_cache;
static ire_t	ire_null;

/*
 * The threshold number of IRE in a bucket when the IREs are
 * cleaned up.  This threshold is calculated later in ip_open()
 * based on the speed of CPU and available memory.  This default
 * value is the maximum.
 *
 * We have two kinds of cached IRE, temporary and
 * non-temporary.  Temporary IREs are marked with
 * IRE_MARK_TEMPORARY.  They are IREs created for non
 * TCP traffic and for forwarding purposes.  All others
 * are non-temporary IREs.  We don't mark IRE created for
 * TCP as temporary because TCP is stateful and there are
 * info stored in the IRE which can be shared by other TCP
 * connections to the same destination.  For connected
 * endpoint, we also don't want to mark the IRE used as
 * temporary because the same IRE will be used frequently,
 * otherwise, the app should not do a connect().  We change
 * the marking at ip_bind_connected_*() if necessary.
 *
 * We want to keep the cache IRE hash bucket length reasonably
 * short, otherwise IRE lookup functions will take "forever."
 * We use the "crude" function that the IRE bucket
 * length should be based on the CPU speed, which is 1 entry
 * per x MHz, depending on the shift factor ip_ire_cpu_ratio
 * (n).  This means that with a 750MHz CPU, the max bucket
 * length can be (750 >> n) entries.
 *
 * Note that this threshold is separate for temp and non-temp
 * IREs.  This means that the actual bucket length can be
 * twice as that.  And while we try to keep temporary IRE
 * length at most at the threshold value, we do not attempt to
 * make the length for non-temporary IREs fixed, for the
 * reason stated above.  Instead, we start trying to find
 * "unused" non-temporary IREs when the bucket length reaches
 * this threshold and clean them up.
 *
 * We also want to limit the amount of memory used by
 * IREs.  So if we are allowed to use ~3% of memory (M)
 * for those IREs, each bucket should not have more than
 *
 * 	M / num of cache bucket / sizeof (ire_t)
 *
 * Again the above memory uses are separate for temp and
 * non-temp cached IREs.
 *
 * We may also want the limit to be a function of the number
 * of interfaces and number of CPUs.  Doing the initialization
 * in ip_open() means that every time an interface is plumbed,
 * the max is re-calculated.  Right now, we don't do anything
 * different.  In future, when we have more experience, we
 * may want to change this behavior.
 */
uint32_t ip_ire_max_bucket_cnt = 10;	/* Setable in /etc/system */
uint32_t ip6_ire_max_bucket_cnt = 10;
uint32_t ip_ire_cleanup_cnt = 2;

/*
 * The minimum of the temporary IRE bucket count.  We do not want
 * the length of each bucket to be too short.  This may hurt
 * performance of some apps as the temporary IREs are removed too
 * often.
 */
uint32_t ip_ire_min_bucket_cnt = 3;	/* /etc/system - not used */
uint32_t ip6_ire_min_bucket_cnt = 3;

/*
 * The ratio of memory consumed by IRE used for temporary to available
 * memory.  This is a shift factor, so 6 means the ratio 1 to 64.  This
 * value can be changed in /etc/system.  6 is a reasonable number.
 */
uint32_t ip_ire_mem_ratio = 6;	/* /etc/system */
/* The shift factor for CPU speed to calculate the max IRE bucket length. */
uint32_t ip_ire_cpu_ratio = 7;	/* /etc/system */

typedef struct nce_clookup_s {
	ipaddr_t ncecl_addr;
	boolean_t ncecl_found;
} nce_clookup_t;

/*
 * The maximum number of buckets in IRE cache table.  In future, we may
 * want to make it a dynamic hash table.  For the moment, we fix the
 * size and allocate the table in ip_ire_init() when IP is first loaded.
 * We take into account the amount of memory a system has.
 */
#define	IP_MAX_CACHE_TABLE_SIZE	4096

/* Setable in /etc/system */
static uint32_t	ip_max_cache_table_size = IP_MAX_CACHE_TABLE_SIZE;
static uint32_t	ip6_max_cache_table_size = IP_MAX_CACHE_TABLE_SIZE;

#define	NUM_ILLS	2	/* To build the ILL list to unlock */

/* Zero iulp_t for initialization. */
const iulp_t	ire_uinfo_null = { 0 };

static int	ire_add_v4(ire_t **ire_p, queue_t *q, mblk_t *mp,
    ipsq_func_t func, boolean_t);
static void	ire_delete_v4(ire_t *ire);
static void	ire_walk_ipvers(pfv_t func, void *arg, uchar_t vers,
    zoneid_t zoneid, ip_stack_t *);
static void	ire_walk_ill_ipvers(uint_t match_flags, uint_t ire_type,
    pfv_t func, void *arg, uchar_t vers, ill_t *ill);
static void	ire_cache_cleanup(irb_t *irb, uint32_t threshold,
    ire_t *ref_ire);
static	void	ip_nce_clookup_and_delete(nce_t *nce, void *arg);
#ifdef DEBUG
static void	ire_trace_cleanup(const ire_t *);
#endif

/*
 * To avoid bloating the code, we call this function instead of
 * using the macro IRE_REFRELE. Use macro only in performance
 * critical paths.
 *
 * Must not be called while holding any locks. Otherwise if this is
 * the last reference to be released there is a chance of recursive mutex
 * panic due to ire_refrele -> ipif_ill_refrele_tail -> qwriter_ip trying
 * to restart an ioctl. The one exception is when the caller is sure that
 * this is not the last reference to be released. Eg. if the caller is
 * sure that the ire has not been deleted and won't be deleted.
 */
void
ire_refrele(ire_t *ire)
{
	IRE_REFRELE(ire);
}

void
ire_refrele_notr(ire_t *ire)
{
	IRE_REFRELE_NOTR(ire);
}

/*
 * kmem_cache_alloc constructor for IRE in kma space.
 * Note that when ire_mp is set the IRE is stored in that mblk and
 * not in this cache.
 */
/* ARGSUSED */
static int
ip_ire_constructor(void *buf, void *cdrarg, int kmflags)
{
	ire_t	*ire = buf;

	ire->ire_nce = NULL;

	return (0);
}

/* ARGSUSED1 */
static void
ip_ire_destructor(void *buf, void *cdrarg)
{
	ire_t	*ire = buf;

	ASSERT(ire->ire_nce == NULL);
}

/*
 * This function is associated with the IP_IOC_IRE_ADVISE_NO_REPLY
 * IOCTL.  It is used by TCP (or other ULPs) to supply revised information
 * for an existing CACHED IRE.
 */
/* ARGSUSED */
int
ip_ire_advise(queue_t *q, mblk_t *mp, cred_t *ioc_cr)
{
	uchar_t	*addr_ucp;
	ipic_t	*ipic;
	ire_t	*ire;
	ipaddr_t	addr;
	in6_addr_t	v6addr;
	irb_t	*irb;
	zoneid_t	zoneid;
	ip_stack_t	*ipst = CONNQ_TO_IPST(q);

	ASSERT(q->q_next == NULL);
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/*
	 * Check privilege using the ioctl credential; if it is NULL
	 * then this is a kernel message and therefor privileged.
	 */
	if (ioc_cr != NULL && secpolicy_ip_config(ioc_cr, B_FALSE) != 0)
		return (EPERM);

	ipic = (ipic_t *)mp->b_rptr;
	if (!(addr_ucp = mi_offset_param(mp, ipic->ipic_addr_offset,
	    ipic->ipic_addr_length))) {
		return (EINVAL);
	}
	if (!OK_32PTR(addr_ucp))
		return (EINVAL);
	switch (ipic->ipic_addr_length) {
	case IP_ADDR_LEN: {
		/* Extract the destination address. */
		addr = *(ipaddr_t *)addr_ucp;
		/* Find the corresponding IRE. */
		ire = ire_cache_lookup(addr, zoneid, NULL, ipst);
		break;
	}
	case IPV6_ADDR_LEN: {
		/* Extract the destination address. */
		v6addr = *(in6_addr_t *)addr_ucp;
		/* Find the corresponding IRE. */
		ire = ire_cache_lookup_v6(&v6addr, zoneid, NULL, ipst);
		break;
	}
	default:
		return (EINVAL);
	}

	if (ire == NULL)
		return (ENOENT);
	/*
	 * Update the round trip time estimate and/or the max frag size
	 * and/or the slow start threshold.
	 *
	 * We serialize multiple advises using ire_lock.
	 */
	mutex_enter(&ire->ire_lock);
	if (ipic->ipic_rtt) {
		/*
		 * If there is no old cached values, initialize them
		 * conservatively.  Set them to be (1.5 * new value).
		 */
		if (ire->ire_uinfo.iulp_rtt != 0) {
			ire->ire_uinfo.iulp_rtt = (ire->ire_uinfo.iulp_rtt +
			    ipic->ipic_rtt) >> 1;
		} else {
			ire->ire_uinfo.iulp_rtt = ipic->ipic_rtt +
			    (ipic->ipic_rtt >> 1);
		}
		if (ire->ire_uinfo.iulp_rtt_sd != 0) {
			ire->ire_uinfo.iulp_rtt_sd =
			    (ire->ire_uinfo.iulp_rtt_sd +
			    ipic->ipic_rtt_sd) >> 1;
		} else {
			ire->ire_uinfo.iulp_rtt_sd = ipic->ipic_rtt_sd +
			    (ipic->ipic_rtt_sd >> 1);
		}
	}
	if (ipic->ipic_max_frag)
		ire->ire_max_frag = MIN(ipic->ipic_max_frag, IP_MAXPACKET);
	if (ipic->ipic_ssthresh != 0) {
		if (ire->ire_uinfo.iulp_ssthresh != 0)
			ire->ire_uinfo.iulp_ssthresh =
			    (ipic->ipic_ssthresh +
			    ire->ire_uinfo.iulp_ssthresh) >> 1;
		else
			ire->ire_uinfo.iulp_ssthresh = ipic->ipic_ssthresh;
	}
	/*
	 * Don't need the ire_lock below this. ire_type does not change
	 * after initialization. ire_marks is protected by irb_lock.
	 */
	mutex_exit(&ire->ire_lock);

	if (ipic->ipic_ire_marks != 0 && ire->ire_type == IRE_CACHE) {
		/*
		 * Only increment the temporary IRE count if the original
		 * IRE is not already marked temporary.
		 */
		irb = ire->ire_bucket;
		rw_enter(&irb->irb_lock, RW_WRITER);
		if ((ipic->ipic_ire_marks & IRE_MARK_TEMPORARY) &&
		    !(ire->ire_marks & IRE_MARK_TEMPORARY)) {
			irb->irb_tmp_ire_cnt++;
		}
		ire->ire_marks |= ipic->ipic_ire_marks;
		rw_exit(&irb->irb_lock);
	}

	ire_refrele(ire);
	return (0);
}

/*
 * This function is associated with the IP_IOC_IRE_DELETE[_NO_REPLY]
 * IOCTL[s].  The NO_REPLY form is used by TCP to delete a route IRE
 * for a host that is not responding.  This will force an attempt to
 * establish a new route, if available, and flush out the ARP entry so
 * it will re-resolve.  Management processes may want to use the
 * version that generates a reply.
 *
 * This function does not support IPv6 since Neighbor Unreachability Detection
 * means that negative advise like this is useless.
 */
/* ARGSUSED */
int
ip_ire_delete(queue_t *q, mblk_t *mp, cred_t *ioc_cr)
{
	uchar_t		*addr_ucp;
	ipaddr_t	addr;
	ire_t		*ire;
	ipid_t		*ipid;
	boolean_t	routing_sock_info = B_FALSE;	/* Sent info? */
	zoneid_t	zoneid;
	ire_t		*gire = NULL;
	ill_t		*ill;
	mblk_t		*arp_mp;
	ip_stack_t	*ipst;

	ASSERT(q->q_next == NULL);
	zoneid = Q_TO_CONN(q)->conn_zoneid;
	ipst = CONNQ_TO_IPST(q);

	/*
	 * Check privilege using the ioctl credential; if it is NULL
	 * then this is a kernel message and therefor privileged.
	 */
	if (ioc_cr != NULL && secpolicy_ip_config(ioc_cr, B_FALSE) != 0)
		return (EPERM);

	ipid = (ipid_t *)mp->b_rptr;

	/* Only actions on IRE_CACHEs are acceptable at present. */
	if (ipid->ipid_ire_type != IRE_CACHE)
		return (EINVAL);

	addr_ucp = mi_offset_param(mp, ipid->ipid_addr_offset,
	    ipid->ipid_addr_length);
	if (addr_ucp == NULL || !OK_32PTR(addr_ucp))
		return (EINVAL);
	switch (ipid->ipid_addr_length) {
	case IP_ADDR_LEN:
		/* addr_ucp points at IP addr */
		break;
	case sizeof (sin_t): {
		sin_t	*sin;
		/*
		 * got complete (sockaddr) address - increment addr_ucp to point
		 * at the ip_addr field.
		 */
		sin = (sin_t *)addr_ucp;
		addr_ucp = (uchar_t *)&sin->sin_addr.s_addr;
		break;
	}
	default:
		return (EINVAL);
	}
	/* Extract the destination address. */
	bcopy(addr_ucp, &addr, IP_ADDR_LEN);

	/* Try to find the CACHED IRE. */
	ire = ire_cache_lookup(addr, zoneid, NULL, ipst);

	/* Nail it. */
	if (ire) {
		/* Allow delete only on CACHE entries */
		if (ire->ire_type != IRE_CACHE) {
			ire_refrele(ire);
			return (EINVAL);
		}

		/*
		 * Verify that the IRE has been around for a while.
		 * This is to protect against transport protocols
		 * that are too eager in sending delete messages.
		 */
		if (gethrestime_sec() <
		    ire->ire_create_time + ipst->ips_ip_ignore_delete_time) {
			ire_refrele(ire);
			return (EINVAL);
		}
		/*
		 * Now we have a potentially dead cache entry. We need
		 * to remove it.
		 * If this cache entry is generated from a
		 * default route (i.e., ire_cmask == 0),
		 * search the default list and mark it dead and some
		 * background process will try to activate it.
		 */
		if ((ire->ire_gateway_addr != 0) && (ire->ire_cmask == 0)) {
			/*
			 * Make sure that we pick a different
			 * IRE_DEFAULT next time.
			 */
			ire_t *gw_ire;
			irb_t *irb = NULL;
			uint_t match_flags;

			match_flags = (MATCH_IRE_DEFAULT | MATCH_IRE_RJ_BHOLE);

			gire = ire_ftable_lookup(ire->ire_addr,
			    ire->ire_cmask, 0, 0,
			    ire->ire_ipif, NULL, zoneid, 0, NULL, match_flags,
			    ipst);

			ip3dbg(("ire_ftable_lookup() returned gire %p\n",
			    (void *)gire));

			if (gire != NULL) {
				irb = gire->ire_bucket;

				/*
				 * We grab it as writer just to serialize
				 * multiple threads trying to bump up
				 * irb_rr_origin
				 */
				rw_enter(&irb->irb_lock, RW_WRITER);
				if ((gw_ire = irb->irb_rr_origin) == NULL) {
					rw_exit(&irb->irb_lock);
					goto done;
				}

				DTRACE_PROBE1(ip__ire__del__origin,
				    (ire_t *), gw_ire);

				/* Skip past the potentially bad gateway */
				if (ire->ire_gateway_addr ==
				    gw_ire->ire_gateway_addr) {
					ire_t *next = gw_ire->ire_next;

					DTRACE_PROBE2(ip__ire__del,
					    (ire_t *), gw_ire, (irb_t *), irb);
					IRE_FIND_NEXT_ORIGIN(next);
					irb->irb_rr_origin = next;
				}
				rw_exit(&irb->irb_lock);
			}
		}
done:
		if (gire != NULL)
			IRE_REFRELE(gire);
		/* report the bad route to routing sockets */
		ip_rts_change(RTM_LOSING, ire->ire_addr, ire->ire_gateway_addr,
		    ire->ire_mask, ire->ire_src_addr, 0, 0, 0,
		    (RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFA), ipst);
		routing_sock_info = B_TRUE;

		/*
		 * TCP is really telling us to start over completely, and it
		 * expects that we'll resend the ARP query.  Tell ARP to
		 * discard the entry, if this is a local destination.
		 *
		 * But, if the ARP entry is permanent then it shouldn't be
		 * deleted, so we set ARED_F_PRESERVE_PERM.
		 */
		ill = ire->ire_stq->q_ptr;
		if (ire->ire_gateway_addr == 0 &&
		    (arp_mp = ill_ared_alloc(ill, addr)) != NULL) {
			ared_t *ared = (ared_t *)arp_mp->b_rptr;

			ASSERT(ared->ared_cmd == AR_ENTRY_DELETE);
			ared->ared_flags |= ARED_F_PRESERVE_PERM;
			putnext(ill->ill_rq, arp_mp);
		}

		ire_delete(ire);
		ire_refrele(ire);
	}
	/*
	 * Also look for an IRE_HOST type redirect ire and
	 * remove it if present.
	 */
	ire = ire_route_lookup(addr, 0, 0, IRE_HOST, NULL, NULL,
	    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);

	/* Nail it. */
	if (ire != NULL) {
		if (ire->ire_flags & RTF_DYNAMIC) {
			if (!routing_sock_info) {
				ip_rts_change(RTM_LOSING, ire->ire_addr,
				    ire->ire_gateway_addr, ire->ire_mask,
				    ire->ire_src_addr, 0, 0, 0,
				    (RTA_DST | RTA_GATEWAY |
				    RTA_NETMASK | RTA_IFA),
				    ipst);
			}
			ire_delete(ire);
		}
		ire_refrele(ire);
	}
	return (0);
}


/*
 * ip_ire_req is called by ip_wput when an IRE_DB_REQ_TYPE message is handed
 * down from the Upper Level Protocol to request a copy of the IRE (to check
 * its type or to extract information like round-trip time estimates or the
 * MTU.)
 * The address is assumed to be in the ire_addr field. If no IRE is found
 * an IRE is returned with ire_type being zero.
 * Note that the upper lavel protocol has to check for broadcast
 * (IRE_BROADCAST) and multicast (CLASSD(addr)).
 * If there is a b_cont the resulting IRE_DB_TYPE mblk is placed at the
 * end of the returned message.
 *
 * TCP sends down a message of this type with a connection request packet
 * chained on. UDP and ICMP send it down to verify that a route exists for
 * the destination address when they get connected.
 */
void
ip_ire_req(queue_t *q, mblk_t *mp)
{
	ire_t	*inire;
	ire_t	*ire;
	mblk_t	*mp1;
	ire_t	*sire = NULL;
	zoneid_t zoneid = Q_TO_CONN(q)->conn_zoneid;
	ip_stack_t	*ipst = CONNQ_TO_IPST(q);

	ASSERT(q->q_next == NULL);

	if ((mp->b_wptr - mp->b_rptr) < sizeof (ire_t) ||
	    !OK_32PTR(mp->b_rptr)) {
		freemsg(mp);
		return;
	}
	inire = (ire_t *)mp->b_rptr;
	/*
	 * Got it, now take our best shot at an IRE.
	 */
	if (inire->ire_ipversion == IPV6_VERSION) {
		ire = ire_route_lookup_v6(&inire->ire_addr_v6, 0, 0, 0,
		    NULL, &sire, zoneid, NULL,
		    (MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT), ipst);
	} else {
		ASSERT(inire->ire_ipversion == IPV4_VERSION);
		ire = ire_route_lookup(inire->ire_addr, 0, 0, 0,
		    NULL, &sire, zoneid, NULL,
		    (MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT), ipst);
	}

	/*
	 * We prevent returning IRES with source address INADDR_ANY
	 * as these were temporarily created for sending packets
	 * from endpoints that have conn_unspec_src set.
	 */
	if (ire == NULL ||
	    (ire->ire_ipversion == IPV4_VERSION &&
	    ire->ire_src_addr == INADDR_ANY) ||
	    (ire->ire_ipversion == IPV6_VERSION &&
	    IN6_IS_ADDR_UNSPECIFIED(&ire->ire_src_addr_v6))) {
		inire->ire_type = 0;
	} else {
		bcopy(ire, inire, sizeof (ire_t));
		/* Copy the route metrics from the parent. */
		if (sire != NULL) {
			bcopy(&(sire->ire_uinfo), &(inire->ire_uinfo),
			    sizeof (iulp_t));
		}

		/*
		 * As we don't lookup global policy here, we may not
		 * pass the right size if per-socket policy is not
		 * present. For these cases, path mtu discovery will
		 * do the right thing.
		 */
		inire->ire_ipsec_overhead = conn_ipsec_length(Q_TO_CONN(q));

		/* Pass the latest setting of the ip_path_mtu_discovery */
		inire->ire_frag_flag |=
		    (ipst->ips_ip_path_mtu_discovery) ? IPH_DF : 0;
	}
	if (ire != NULL)
		ire_refrele(ire);
	if (sire != NULL)
		ire_refrele(sire);
	mp->b_wptr = &mp->b_rptr[sizeof (ire_t)];
	mp->b_datap->db_type = IRE_DB_TYPE;

	/* Put the IRE_DB_TYPE mblk last in the chain */
	mp1 = mp->b_cont;
	if (mp1 != NULL) {
		mp->b_cont = NULL;
		linkb(mp1, mp);
		mp = mp1;
	}
	qreply(q, mp);
}

/*
 * Send a packet using the specified IRE.
 * If ire_src_addr_v6 is all zero then discard the IRE after
 * the packet has been sent.
 */
static void
ire_send(queue_t *q, mblk_t *pkt, ire_t *ire)
{
	mblk_t *ipsec_mp;
	boolean_t is_secure;
	uint_t ifindex;
	ill_t	*ill;
	zoneid_t zoneid = ire->ire_zoneid;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV4_VERSION);
	ASSERT(!(ire->ire_type & IRE_LOCAL)); /* Has different ire_zoneid */
	ipsec_mp = pkt;
	is_secure = (pkt->b_datap->db_type == M_CTL);
	if (is_secure) {
		ipsec_out_t *io;

		pkt = pkt->b_cont;
		io = (ipsec_out_t *)ipsec_mp->b_rptr;
		if (io->ipsec_out_type == IPSEC_OUT)
			zoneid = io->ipsec_out_zoneid;
	}

	/* If the packet originated externally then */
	if (pkt->b_prev) {
		ire_refrele(ire);
		/*
		 * Extract the ifindex from b_prev (set in ip_rput_noire).
		 * Look up interface to see if it still exists (it could have
		 * been unplumbed by the time the reply came back from ARP)
		 */
		ifindex = (uint_t)(uintptr_t)pkt->b_prev;
		ill = ill_lookup_on_ifindex(ifindex, B_FALSE,
		    NULL, NULL, NULL, NULL, ipst);
		if (ill == NULL) {
			pkt->b_prev = NULL;
			pkt->b_next = NULL;
			freemsg(ipsec_mp);
			return;
		}
		q = ill->ill_rq;
		pkt->b_prev = NULL;
		/*
		 * This packet has not gone through IPSEC processing
		 * and hence we should not have any IPSEC message
		 * prepended.
		 */
		ASSERT(ipsec_mp == pkt);
		put(q, pkt);
		ill_refrele(ill);
	} else if (pkt->b_next) {
		/* Packets from multicast router */
		pkt->b_next = NULL;
		/*
		 * We never get the IPSEC_OUT while forwarding the
		 * packet for multicast router.
		 */
		ASSERT(ipsec_mp == pkt);
		ip_rput_forward(ire, (ipha_t *)pkt->b_rptr, ipsec_mp, NULL);
		ire_refrele(ire);
	} else {
		/* Locally originated packets */
		boolean_t delete_ire = B_FALSE;
		ipha_t *ipha = (ipha_t *)pkt->b_rptr;

		/*
		 * If this IRE shouldn't be kept in the table (because its
		 * source address is unspecified), hold a reference to it so
		 * we can delete it even after e.g. ip_wput_ire() has dropped
		 * its reference.
		 */
		if (!(ire->ire_marks & IRE_MARK_NOADD) &&
		    ire->ire_src_addr == INADDR_ANY) {
			delete_ire = B_TRUE;
			IRE_REFHOLD(ire);
		}

		/*
		 * If we were resolving a router we can not use the
		 * routers IRE for sending the packet (since it would
		 * violate the uniqness of the IP idents) thus we
		 * make another pass through ip_wput to create the IRE_CACHE
		 * for the destination.
		 * When IRE_MARK_NOADD is set, ire_add() is not called.
		 * Thus ip_wput() will never find a ire and result in an
		 * infinite loop. Thus we check whether IRE_MARK_NOADD is
		 * is set. This also implies that IRE_MARK_NOADD can only be
		 * used to send packets to directly connected hosts.
		 */
		if (ipha->ipha_dst != ire->ire_addr &&
		    !(ire->ire_marks & IRE_MARK_NOADD)) {
			ire_refrele(ire);	/* Held in ire_add */
			if (CONN_Q(q)) {
				(void) ip_output(Q_TO_CONN(q), ipsec_mp, q,
				    IRE_SEND);
			} else {
				(void) ip_output((void *)(uintptr_t)zoneid,
				    ipsec_mp, q, IRE_SEND);
			}
		} else {
			if (is_secure) {
				ipsec_out_t *oi;
				ipha_t *ipha;

				oi = (ipsec_out_t *)ipsec_mp->b_rptr;
				ipha = (ipha_t *)ipsec_mp->b_cont->b_rptr;
				if (oi->ipsec_out_proc_begin) {
					/*
					 * This is the case where
					 * ip_wput_ipsec_out could not find
					 * the IRE and recreated a new one.
					 * As ip_wput_ipsec_out does ire
					 * lookups, ire_refrele for the extra
					 * bump in ire_add.
					 */
					ire_refrele(ire);
					ip_wput_ipsec_out(q, ipsec_mp, ipha,
					    NULL, NULL);
				} else {
					/*
					 * IRE_REFRELE will be done in
					 * ip_wput_ire.
					 */
					ip_wput_ire(q, ipsec_mp, ire, NULL,
					    IRE_SEND, zoneid);
				}
			} else {
				/*
				 * IRE_REFRELE will be done in ip_wput_ire.
				 */
				ip_wput_ire(q, ipsec_mp, ire, NULL,
				    IRE_SEND, zoneid);
			}
		}
		/*
		 * Special code to support sending a single packet with
		 * conn_unspec_src using an IRE which has no source address.
		 * The IRE is deleted here after sending the packet to avoid
		 * having other code trip on it. But before we delete the
		 * ire, somebody could have looked up this ire.
		 * We prevent returning/using this IRE by the upper layers
		 * by making checks to NULL source address in other places
		 * like e.g ip_ire_append, ip_ire_req and ip_bind_connected.
		 * Though this does not completely prevent other threads
		 * from using this ire, this should not cause any problems.
		 */
		if (delete_ire) {
			ip1dbg(("ire_send: delete IRE\n"));
			ire_delete(ire);
			ire_refrele(ire);	/* Held above */
		}
	}
}

/*
 * Send a packet using the specified IRE.
 * If ire_src_addr_v6 is all zero then discard the IRE after
 * the packet has been sent.
 */
static void
ire_send_v6(queue_t *q, mblk_t *pkt, ire_t *ire)
{
	mblk_t *ipsec_mp;
	boolean_t secure;
	uint_t ifindex;
	zoneid_t zoneid = ire->ire_zoneid;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV6_VERSION);
	ASSERT(!(ire->ire_type & IRE_LOCAL)); /* Has different ire_zoneid */
	if (pkt->b_datap->db_type == M_CTL) {
		ipsec_out_t *io;

		ipsec_mp = pkt;
		pkt = pkt->b_cont;
		secure = B_TRUE;
		io = (ipsec_out_t *)ipsec_mp->b_rptr;
		if (io->ipsec_out_type == IPSEC_OUT)
			zoneid = io->ipsec_out_zoneid;
	} else {
		ipsec_mp = pkt;
		secure = B_FALSE;
	}

	/* If the packet originated externally then */
	if (pkt->b_prev) {
		ill_t	*ill;
		/*
		 * Extract the ifindex from b_prev (set in ip_rput_data_v6).
		 * Look up interface to see if it still exists (it could have
		 * been unplumbed by the time the reply came back from the
		 * resolver).
		 */
		ifindex = (uint_t)(uintptr_t)pkt->b_prev;
		ill = ill_lookup_on_ifindex(ifindex, B_TRUE,
		    NULL, NULL, NULL, NULL, ipst);
		if (ill == NULL) {
			pkt->b_prev = NULL;
			pkt->b_next = NULL;
			freemsg(ipsec_mp);
			ire_refrele(ire);	/* Held in ire_add */
			return;
		}
		q = ill->ill_rq;
		pkt->b_prev = NULL;
		/*
		 * This packet has not gone through IPSEC processing
		 * and hence we should not have any IPSEC message
		 * prepended.
		 */
		ASSERT(ipsec_mp == pkt);
		put(q, pkt);
		ill_refrele(ill);
	} else if (pkt->b_next) {
		/* Packets from multicast router */
		pkt->b_next = NULL;
		/*
		 * We never get the IPSEC_OUT while forwarding the
		 * packet for multicast router.
		 */
		ASSERT(ipsec_mp == pkt);
		/*
		 * XXX TODO IPv6.
		 */
		freemsg(pkt);
#ifdef XXX
		ip_rput_forward(ire, (ipha_t *)pkt->b_rptr, pkt, NULL);
#endif
	} else {
		if (secure) {
			ipsec_out_t *oi;
			ip6_t *ip6h;

			oi = (ipsec_out_t *)ipsec_mp->b_rptr;
			ip6h = (ip6_t *)ipsec_mp->b_cont->b_rptr;
			if (oi->ipsec_out_proc_begin) {
				/*
				 * This is the case where
				 * ip_wput_ipsec_out could not find
				 * the IRE and recreated a new one.
				 */
				ip_wput_ipsec_out_v6(q, ipsec_mp, ip6h,
				    NULL, NULL);
			} else {
				if (CONN_Q(q)) {
					(void) ip_output_v6(Q_TO_CONN(q),
					    ipsec_mp, q, IRE_SEND);
				} else {
					(void) ip_output_v6(
					    (void *)(uintptr_t)zoneid,
					    ipsec_mp, q, IRE_SEND);
				}
			}
		} else {
			/*
			 * Send packets through ip_output_v6 so that any
			 * ip6_info header can be processed again.
			 */
			if (CONN_Q(q)) {
				(void) ip_output_v6(Q_TO_CONN(q), ipsec_mp, q,
				    IRE_SEND);
			} else {
				(void) ip_output_v6((void *)(uintptr_t)zoneid,
				    ipsec_mp, q, IRE_SEND);
			}
		}
		/*
		 * Special code to support sending a single packet with
		 * conn_unspec_src using an IRE which has no source address.
		 * The IRE is deleted here after sending the packet to avoid
		 * having other code trip on it. But before we delete the
		 * ire, somebody could have looked up this ire.
		 * We prevent returning/using this IRE by the upper layers
		 * by making checks to NULL source address in other places
		 * like e.g ip_ire_append_v6, ip_ire_req and
		 * ip_bind_connected_v6. Though, this does not completely
		 * prevent other threads from using this ire, this should
		 * not cause any problems.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ire->ire_src_addr_v6)) {
			ip1dbg(("ire_send_v6: delete IRE\n"));
			ire_delete(ire);
		}
	}
	ire_refrele(ire);	/* Held in ire_add */
}

/*
 * Make sure that IRE bucket does not get too long.
 * This can cause lock up because ire_cache_lookup()
 * may take "forever" to finish.
 *
 * We only remove a maximum of cnt IREs each time.  This
 * should keep the bucket length approximately constant,
 * depending on cnt.  This should be enough to defend
 * against DoS attack based on creating temporary IREs
 * (for forwarding and non-TCP traffic).
 *
 * We also pass in the address of the newly created IRE
 * as we do not want to remove this straight after adding
 * it. New IREs are normally added at the tail of the
 * bucket.  This means that we are removing the "oldest"
 * temporary IREs added.  Only if there are IREs with
 * the same ire_addr, do we not add it at the tail.  Refer
 * to ire_add_v*().  It should be OK for our purpose.
 *
 * For non-temporary cached IREs, we make sure that they
 * have not been used for some time (defined below), they
 * are non-local destinations, and there is no one using
 * them at the moment (refcnt == 1).
 *
 * The above means that the IRE bucket length may become
 * very long, consisting of mostly non-temporary IREs.
 * This can happen when the hash function does a bad job
 * so that most TCP connections cluster to a specific bucket.
 * This "hopefully" should never happen.  It can also
 * happen if most TCP connections have very long lives.
 * Even with the minimal hash table size of 256, there
 * has to be a lot of such connections to make the bucket
 * length unreasonably long.  This should probably not
 * happen either.  The third can when this can happen is
 * when the machine is under attack, such as SYN flooding.
 * TCP should already have the proper mechanism to protect
 * that.  So we should be safe.
 *
 * This function is called by ire_add_then_send() after
 * a new IRE is added and the packet is sent.
 *
 * The idle cutoff interval is set to 60s.  It can be
 * changed using /etc/system.
 */
uint32_t ire_idle_cutoff_interval = 60000;

static void
ire_cache_cleanup(irb_t *irb, uint32_t threshold, ire_t *ref_ire)
{
	ire_t *ire;
	clock_t cut_off = drv_usectohz(ire_idle_cutoff_interval * 1000);
	int cnt = ip_ire_cleanup_cnt;

	/*
	 * Try to remove cnt temporary IREs first.
	 */
	for (ire = irb->irb_ire; cnt > 0 && ire != NULL; ire = ire->ire_next) {
		if (ire == ref_ire)
			continue;
		if (ire->ire_marks & IRE_MARK_CONDEMNED)
			continue;
		if (ire->ire_marks & IRE_MARK_TEMPORARY) {
			ASSERT(ire->ire_type == IRE_CACHE);
			ire_delete(ire);
			cnt--;
		}
	}
	if (cnt == 0)
		return;

	/*
	 * If we didn't satisfy our removal target from temporary IREs
	 * we see how many non-temporary IREs are currently in the bucket.
	 * If this quantity is above the threshold then we see if there are any
	 * candidates for removal. We are still limited to removing a maximum
	 * of cnt IREs.
	 */
	if ((irb->irb_ire_cnt - irb->irb_tmp_ire_cnt) > threshold) {
		for (ire = irb->irb_ire; cnt > 0 && ire != NULL;
		    ire = ire->ire_next) {
			if (ire == ref_ire)
				continue;
			if (ire->ire_type != IRE_CACHE)
				continue;
			if (ire->ire_marks & IRE_MARK_CONDEMNED)
				continue;
			if ((ire->ire_refcnt == 1) &&
			    (lbolt - ire->ire_last_used_time > cut_off)) {
				ire_delete(ire);
				cnt--;
			}
		}
	}
}

/*
 * ire_add_then_send is called when a new IRE has been created in order to
 * route an outgoing packet.  Typically, it is called from ip_wput when
 * a response comes back down from a resolver.  We add the IRE, and then
 * possibly run the packet through ip_wput or ip_rput, as appropriate.
 * However, we do not add the newly created IRE in the cache when
 * IRE_MARK_NOADD is set in the IRE. IRE_MARK_NOADD is set at
 * ip_newroute_ipif(). The ires with IRE_MARK_NOADD are ire_refrele'd by
 * ip_wput_ire() and get deleted.
 * Multirouting support: the packet is silently discarded when the new IRE
 * holds the RTF_MULTIRT flag, but is not the first IRE to be added with the
 * RTF_MULTIRT flag for the same destination address.
 * In this case, we just want to register this additional ire without
 * sending the packet, as it has already been replicated through
 * existing multirt routes in ip_wput().
 */
void
ire_add_then_send(queue_t *q, ire_t *ire, mblk_t *mp)
{
	irb_t *irb;
	boolean_t drop = B_FALSE;
	/* LINTED : set but not used in function */
	boolean_t mctl_present;
	mblk_t *first_mp = NULL;
	mblk_t *save_mp = NULL;
	ire_t *dst_ire;
	ipha_t *ipha;
	ip6_t *ip6h;
	ip_stack_t	*ipst = ire->ire_ipst;
	int		ire_limit;

	if (mp != NULL) {
		/*
		 * We first have to retrieve the destination address carried
		 * by the packet.
		 * We can't rely on ire as it can be related to a gateway.
		 * The destination address will help in determining if
		 * other RTF_MULTIRT ires are already registered.
		 *
		 * We first need to know where we are going : v4 or V6.
		 * the ire version is enough, as there is no risk that
		 * we resolve an IPv6 address with an IPv4 ire
		 * or vice versa.
		 */
		if (ire->ire_ipversion == IPV4_VERSION) {
			EXTRACT_PKT_MP(mp, first_mp, mctl_present);
			ipha = (ipha_t *)mp->b_rptr;
			save_mp = mp;
			mp = first_mp;

			dst_ire = ire_cache_lookup(ipha->ipha_dst,
			    ire->ire_zoneid, MBLK_GETLABEL(mp), ipst);
		} else {
			ASSERT(ire->ire_ipversion == IPV6_VERSION);
			/*
			 * Get a pointer to the beginning of the IPv6 header.
			 * Ignore leading IPsec control mblks.
			 */
			first_mp = mp;
			if (mp->b_datap->db_type == M_CTL) {
				mp = mp->b_cont;
			}
			ip6h = (ip6_t *)mp->b_rptr;
			save_mp = mp;
			mp = first_mp;
			dst_ire = ire_cache_lookup_v6(&ip6h->ip6_dst,
			    ire->ire_zoneid, MBLK_GETLABEL(mp), ipst);
		}
		if (dst_ire != NULL) {
			if (dst_ire->ire_flags & RTF_MULTIRT) {
				/*
				 * At least one resolved multirt route
				 * already exists for the destination,
				 * don't sent this packet: either drop it
				 * or complete the pending resolution,
				 * depending on the ire.
				 */
				drop = B_TRUE;
			}
			ip1dbg(("ire_add_then_send: dst_ire %p "
			    "[dst %08x, gw %08x], drop %d\n",
			    (void *)dst_ire,
			    (dst_ire->ire_ipversion == IPV4_VERSION) ? \
			    ntohl(dst_ire->ire_addr) : \
			    ntohl(V4_PART_OF_V6(dst_ire->ire_addr_v6)),
			    (dst_ire->ire_ipversion == IPV4_VERSION) ? \
			    ntohl(dst_ire->ire_gateway_addr) : \
			    ntohl(V4_PART_OF_V6(
			    dst_ire->ire_gateway_addr_v6)),
			    drop));
			ire_refrele(dst_ire);
		}
	}

	if (!(ire->ire_marks & IRE_MARK_NOADD)) {
		/* Regular packets with cache bound ires are here. */
		(void) ire_add(&ire, NULL, NULL, NULL, B_FALSE);

		if (ire == NULL) {
			mp->b_prev = NULL;
			mp->b_next = NULL;
			MULTIRT_DEBUG_UNTAG(mp);
			freemsg(mp);
			return;
		}
		if (mp == NULL) {
			ire_refrele(ire);	/* Held in ire_add_v4/v6 */
			return;
		}
	}
	if (drop) {
		/*
		 * If we're adding an RTF_MULTIRT ire, the resolution
		 * is over: we just drop the packet.
		 */
		if (ire->ire_flags & RTF_MULTIRT) {
			if (save_mp) {
				save_mp->b_prev = NULL;
				save_mp->b_next = NULL;
			}
			MULTIRT_DEBUG_UNTAG(mp);
			freemsg(mp);
		} else {
			/*
			 * Otherwise, we're adding the ire to a gateway
			 * for a multirt route.
			 * Invoke ip_newroute() to complete the resolution
			 * of the route. We will then come back here and
			 * finally drop this packet in the above code.
			 */
			if (ire->ire_ipversion == IPV4_VERSION) {
				/*
				 * TODO: in order for CGTP to work in non-global
				 * zones, ip_newroute() must create the IRE
				 * cache in the zone indicated by
				 * ire->ire_zoneid.
				 */
				ip_newroute(q, mp, ipha->ipha_dst,
				    (CONN_Q(q) ? Q_TO_CONN(q) : NULL),
				    ire->ire_zoneid, ipst);
			} else {
				ASSERT(ire->ire_ipversion == IPV6_VERSION);
				ip_newroute_v6(q, mp, &ip6h->ip6_dst, NULL,
				    NULL, ire->ire_zoneid, ipst);
			}
		}

		ire_refrele(ire); /* As done by ire_send(). */
		return;
	}
	/*
	 * Need to remember ire_bucket here as ire_send*() may delete
	 * the ire so we cannot reference it after that.
	 */
	irb = ire->ire_bucket;
	if (ire->ire_ipversion == IPV4_VERSION) {
		ire_send(q, mp, ire);
		ire_limit = ip_ire_max_bucket_cnt;
	} else {
		ire_send_v6(q, mp, ire);
		ire_limit = ip6_ire_max_bucket_cnt;
	}

	/*
	 * irb is NULL if the IRE was not added to the hash. This happens
	 * when IRE_MARK_NOADD is set and when IREs are returned from
	 * ire_update_srcif_v4().
	 */
	if (irb != NULL) {
		IRB_REFHOLD(irb);
		if (irb->irb_ire_cnt > ire_limit)
			ire_cache_cleanup(irb, ire_limit, ire);
		IRB_REFRELE(irb);
	}
}

/*
 * Initialize the ire that is specific to IPv4 part and call
 * ire_init_common to finish it.
 */
ire_t *
ire_init(ire_t *ire, uchar_t *addr, uchar_t *mask, uchar_t *src_addr,
    uchar_t *gateway, uint_t *max_fragp, nce_t *src_nce, queue_t *rfq,
    queue_t *stq, ushort_t type, ipif_t *ipif, ipaddr_t cmask, uint32_t phandle,
    uint32_t ihandle, uint32_t flags, const iulp_t *ulp_info, tsol_gc_t *gc,
    tsol_gcgrp_t *gcgrp, ip_stack_t *ipst)
{
	ASSERT(type != IRE_CACHE || stq != NULL);
	/*
	 * Reject IRE security attribute creation/initialization
	 * if system is not running in Trusted mode.
	 */
	if ((gc != NULL || gcgrp != NULL) && !is_system_labeled())
		return (NULL);


	BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_alloced);

	if (addr != NULL)
		bcopy(addr, &ire->ire_addr, IP_ADDR_LEN);
	if (src_addr != NULL)
		bcopy(src_addr, &ire->ire_src_addr, IP_ADDR_LEN);
	if (mask != NULL) {
		bcopy(mask, &ire->ire_mask, IP_ADDR_LEN);
		ire->ire_masklen = ip_mask_to_plen(ire->ire_mask);
	}
	if (gateway != NULL) {
		bcopy(gateway, &ire->ire_gateway_addr, IP_ADDR_LEN);
	}

	if (type == IRE_CACHE)
		ire->ire_cmask = cmask;

	/* ire_init_common will free the mblks upon encountering any failure */
	if (!ire_init_common(ire, max_fragp, src_nce, rfq, stq, type, ipif,
	    phandle, ihandle, flags, IPV4_VERSION, ulp_info, gc, gcgrp, ipst))
		return (NULL);

	return (ire);
}

/*
 * Similar to ire_create except that it is called only when
 * we want to allocate ire as an mblk e.g. we have an external
 * resolver ARP.
 */
ire_t *
ire_create_mp(uchar_t *addr, uchar_t *mask, uchar_t *src_addr, uchar_t *gateway,
    uint_t max_frag, nce_t *src_nce, queue_t *rfq, queue_t *stq, ushort_t type,
    ipif_t *ipif, ipaddr_t cmask, uint32_t phandle, uint32_t ihandle,
    uint32_t flags, const iulp_t *ulp_info, tsol_gc_t *gc, tsol_gcgrp_t *gcgrp,
    ip_stack_t *ipst)
{
	ire_t	*ire, *buf;
	ire_t	*ret_ire;
	mblk_t	*mp;
	size_t	bufsize;
	frtn_t	*frtnp;
	ill_t	*ill;

	bufsize = sizeof (ire_t) + sizeof (frtn_t);
	buf = kmem_alloc(bufsize, KM_NOSLEEP);
	if (buf == NULL) {
		ip1dbg(("ire_create_mp: alloc failed\n"));
		return (NULL);
	}
	frtnp = (frtn_t *)(buf + 1);
	frtnp->free_arg = (caddr_t)buf;
	frtnp->free_func = ire_freemblk;

	/*
	 * Allocate the new IRE. The ire created will hold a ref on
	 * an nce_t after ire_nce_init, and this ref must either be
	 * (a)  transferred to the ire_cache entry created when ire_add_v4
	 *	is called after successful arp resolution, or,
	 * (b)  released, when arp resolution fails
	 * Case (b) is handled in ire_freemblk() which will be called
	 * when mp is freed as a result of failed arp.
	 */
	mp = esballoc((unsigned char *)buf, bufsize, BPRI_MED, frtnp);
	if (mp == NULL) {
		ip1dbg(("ire_create_mp: alloc failed\n"));
		kmem_free(buf, bufsize);
		return (NULL);
	}
	ire = (ire_t *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)&ire[1];

	/* Start clean. */
	*ire = ire_null;
	ire->ire_mp = mp;
	mp->b_datap->db_type = IRE_DB_TYPE;
	ire->ire_marks |= IRE_MARK_UNCACHED;

	ret_ire = ire_init(ire, addr, mask, src_addr, gateway, NULL, src_nce,
	    rfq, stq, type, ipif, cmask, phandle, ihandle, flags, ulp_info, gc,
	    gcgrp, ipst);

	ill = (ill_t *)(stq->q_ptr);
	if (ret_ire == NULL) {
		/* ire_freemblk needs these set */
		ire->ire_stq_ifindex = ill->ill_phyint->phyint_ifindex;
		ire->ire_stackid = ipst->ips_netstack->netstack_stackid;
		ire->ire_ipst = ipst;
		freeb(ire->ire_mp);
		return (NULL);
	}
	ret_ire->ire_stq_ifindex = ill->ill_phyint->phyint_ifindex;
	ret_ire->ire_stackid = ipst->ips_netstack->netstack_stackid;
	ASSERT(ret_ire == ire);
	ASSERT(ret_ire->ire_ipst == ipst);
	/*
	 * ire_max_frag is normally zero here and is atomically set
	 * under the irebucket lock in ire_add_v[46] except for the
	 * case of IRE_MARK_NOADD. In that event the the ire_max_frag
	 * is non-zero here.
	 */
	ire->ire_max_frag = max_frag;
	return (ire);
}

/*
 * ire_create is called to allocate and initialize a new IRE.
 *
 * NOTE : This is called as writer sometimes though not required
 * by this function.
 */
ire_t *
ire_create(uchar_t *addr, uchar_t *mask, uchar_t *src_addr, uchar_t *gateway,
    uint_t *max_fragp, nce_t *src_nce, queue_t *rfq, queue_t *stq,
    ushort_t type, ipif_t *ipif, ipaddr_t cmask, uint32_t phandle,
    uint32_t ihandle, uint32_t flags, const iulp_t *ulp_info, tsol_gc_t *gc,
    tsol_gcgrp_t *gcgrp, ip_stack_t *ipst)
{
	ire_t	*ire;
	ire_t	*ret_ire;

	ire = kmem_cache_alloc(ire_cache, KM_NOSLEEP);
	if (ire == NULL) {
		ip1dbg(("ire_create: alloc failed\n"));
		return (NULL);
	}
	*ire = ire_null;

	ret_ire = ire_init(ire, addr, mask, src_addr, gateway, max_fragp,
	    src_nce, rfq, stq, type, ipif, cmask, phandle, ihandle, flags,
	    ulp_info, gc, gcgrp, ipst);

	if (ret_ire == NULL) {
		kmem_cache_free(ire_cache, ire);
		return (NULL);
	}
	ASSERT(ret_ire == ire);
	return (ire);
}


/*
 * Common to IPv4 and IPv6
 */
boolean_t
ire_init_common(ire_t *ire, uint_t *max_fragp, nce_t *src_nce, queue_t *rfq,
    queue_t *stq, ushort_t type, ipif_t *ipif, uint32_t phandle,
    uint32_t ihandle, uint32_t flags, uchar_t ipversion, const iulp_t *ulp_info,
    tsol_gc_t *gc, tsol_gcgrp_t *gcgrp, ip_stack_t *ipst)
{
	ire->ire_max_fragp = max_fragp;
	ire->ire_frag_flag |= (ipst->ips_ip_path_mtu_discovery) ? IPH_DF : 0;

#ifdef DEBUG
	if (ipif != NULL) {
		if (ipif->ipif_isv6)
			ASSERT(ipversion == IPV6_VERSION);
		else
			ASSERT(ipversion == IPV4_VERSION);
	}
#endif /* DEBUG */

	/*
	 * Create/initialize IRE security attribute only in Trusted mode;
	 * if the passed in gc/gcgrp is non-NULL, we expect that the caller
	 * has held a reference to it and will release it when this routine
	 * returns a failure, otherwise we own the reference.  We do this
	 * prior to initializing the rest IRE fields.
	 *
	 * Don't allocate ire_gw_secattr for the resolver case to prevent
	 * memory leak (in case of external resolution failure). We'll
	 * allocate it after a successful external resolution, in ire_add().
	 * Note that ire->ire_mp != NULL here means this ire is headed
	 * to an external resolver.
	 */
	if (is_system_labeled()) {
		if ((type & (IRE_LOCAL | IRE_LOOPBACK | IRE_BROADCAST |
		    IRE_INTERFACE)) != 0) {
			/* release references on behalf of caller */
			if (gc != NULL)
				GC_REFRELE(gc);
			if (gcgrp != NULL)
				GCGRP_REFRELE(gcgrp);
		} else if ((ire->ire_mp == NULL) &&
		    tsol_ire_init_gwattr(ire, ipversion, gc, gcgrp) != 0) {
			return (B_FALSE);
		}
	}

	ire->ire_stq = stq;
	ire->ire_rfq = rfq;
	ire->ire_type = type;
	ire->ire_flags = RTF_UP | flags;
	ire->ire_ident = TICK_TO_MSEC(lbolt);
	bcopy(ulp_info, &ire->ire_uinfo, sizeof (iulp_t));

	ire->ire_tire_mark = ire->ire_ob_pkt_count + ire->ire_ib_pkt_count;
	ire->ire_last_used_time = lbolt;
	ire->ire_create_time = (uint32_t)gethrestime_sec();

	/*
	 * If this IRE is an IRE_CACHE, inherit the handles from the
	 * parent IREs. For others in the forwarding table, assign appropriate
	 * new ones.
	 *
	 * The mutex protecting ire_handle is because ire_create is not always
	 * called as a writer.
	 */
	if (ire->ire_type & IRE_OFFSUBNET) {
		mutex_enter(&ipst->ips_ire_handle_lock);
		ire->ire_phandle = (uint32_t)ipst->ips_ire_handle++;
		mutex_exit(&ipst->ips_ire_handle_lock);
	} else if (ire->ire_type & IRE_INTERFACE) {
		mutex_enter(&ipst->ips_ire_handle_lock);
		ire->ire_ihandle = (uint32_t)ipst->ips_ire_handle++;
		mutex_exit(&ipst->ips_ire_handle_lock);
	} else if (ire->ire_type == IRE_CACHE) {
		ire->ire_phandle = phandle;
		ire->ire_ihandle = ihandle;
	}
	ire->ire_ipif = ipif;
	if (ipif != NULL) {
		ire->ire_ipif_seqid = ipif->ipif_seqid;
		ire->ire_zoneid = ipif->ipif_zoneid;
	} else {
		ire->ire_zoneid = GLOBAL_ZONEID;
	}
	ire->ire_ipversion = ipversion;
	mutex_init(&ire->ire_lock, NULL, MUTEX_DEFAULT, NULL);
	if (ipversion == IPV4_VERSION) {
		/*
		 * IPv6 initializes the ire_nce in ire_add_v6, which expects
		 * to find the ire_nce to be null when it is called.
		 */
		if (ire_nce_init(ire, src_nce) != 0) {
			/* some failure occurred. propagate error back */
			return (B_FALSE);
		}
	}
	ire->ire_refcnt = 1;
	ire->ire_ipst = ipst;	/* No netstack_hold */
	ire->ire_trace_disable = B_FALSE;

	return (B_TRUE);
}

/*
 * This routine is called repeatedly by ipif_up to create broadcast IREs.
 * It is passed a pointer to a slot in an IRE pointer array into which to
 * place the pointer to the new IRE, if indeed we create one.  If the
 * IRE corresponding to the address passed in would be a duplicate of an
 * existing one, we don't create the new one.  irep is incremented before
 * return only if we do create a new IRE.  (Always called as writer.)
 *
 * Note that with the "match_flags" parameter, we can match on either
 * a particular logical interface (MATCH_IRE_IPIF) or for all logical
 * interfaces for a given physical interface (MATCH_IRE_ILL).  Currently,
 * we only create broadcast ire's on a per physical interface basis. If
 * someone is going to be mucking with logical interfaces, it is important
 * to call "ipif_check_bcast_ires()" to make sure that any change to a
 * logical interface will not cause critical broadcast IRE's to be deleted.
 */
ire_t **
ire_check_and_create_bcast(ipif_t *ipif, ipaddr_t  addr, ire_t **irep,
    int match_flags)
{
	ire_t *ire;
	uint64_t check_flags = IPIF_DEPRECATED | IPIF_NOLOCAL | IPIF_ANYCAST;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	/*
	 * No broadcast IREs for the LOOPBACK interface
	 * or others such as point to point and IPIF_NOXMIT.
	 */
	if (!(ipif->ipif_flags & IPIF_BROADCAST) ||
	    (ipif->ipif_flags & IPIF_NOXMIT))
		return (irep);

	/* If this would be a duplicate, don't bother. */
	if ((ire = ire_ctable_lookup(addr, 0, IRE_BROADCAST, ipif,
	    ipif->ipif_zoneid, NULL, match_flags, ipst)) != NULL) {
		/*
		 * We look for non-deprecated (and non-anycast, non-nolocal)
		 * ipifs as the best choice. ipifs with check_flags matching
		 * (deprecated, etc) are used only if non-deprecated ipifs
		 * are not available. if the existing ire's ipif is deprecated
		 * and the new ipif is non-deprecated, switch to the new ipif
		 */
		if ((!(ire->ire_ipif->ipif_flags & check_flags)) ||
		    (ipif->ipif_flags & check_flags)) {
			ire_refrele(ire);
			return (irep);
		}
		/*
		 * Bcast ires exist in pairs. Both have to be deleted,
		 * Since we are exclusive we can make the above assertion.
		 * The 1st has to be refrele'd since it was ctable_lookup'd.
		 */
		ASSERT(IAM_WRITER_IPIF(ipif));
		ASSERT(ire->ire_next->ire_addr == ire->ire_addr);
		ire_delete(ire->ire_next);
		ire_delete(ire);
		ire_refrele(ire);
	}

	irep = ire_create_bcast(ipif, addr, irep);

	return (irep);
}

uint_t ip_loopback_mtu = IP_LOOPBACK_MTU;

/*
 * This routine is called from ipif_check_bcast_ires and ire_check_bcast.
 * It leaves all the verifying and deleting to those routines. So it always
 * creates 2 bcast ires and chains them into the ire array passed in.
 */
ire_t **
ire_create_bcast(ipif_t *ipif, ipaddr_t  addr, ire_t **irep)
{
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	*irep++ = ire_create(
	    (uchar_t *)&addr,			/* dest addr */
	    (uchar_t *)&ip_g_all_ones,		/* mask */
	    (uchar_t *)&ipif->ipif_src_addr,	/* source addr */
	    NULL,				/* no gateway */
	    &ipif->ipif_mtu,			/* max frag */
	    NULL,				/* no src nce */
	    ipif->ipif_rq,			/* recv-from queue */
	    ipif->ipif_wq,			/* send-to queue */
	    IRE_BROADCAST,
	    ipif,
	    0,
	    0,
	    0,
	    0,
	    &ire_uinfo_null,
	    NULL,
	    NULL,
	    ipst);

	*irep++ = ire_create(
	    (uchar_t *)&addr,			/* dest address */
	    (uchar_t *)&ip_g_all_ones,		/* mask */
	    (uchar_t *)&ipif->ipif_src_addr,	/* source address */
	    NULL,				/* no gateway */
	    &ip_loopback_mtu,			/* max frag size */
	    NULL,				/* no src_nce */
	    ipif->ipif_rq,			/* recv-from queue */
	    NULL,				/* no send-to queue */
	    IRE_BROADCAST,			/* Needed for fanout in wput */
	    ipif,
	    0,
	    0,
	    0,
	    0,
	    &ire_uinfo_null,
	    NULL,
	    NULL,
	    ipst);

	return (irep);
}

/*
 * ire_walk routine to delete or update any IRE_CACHE that might contain
 * stale information.
 * The flags state which entries to delete or update.
 * Garbage collection is done separately using kmem alloc callbacks to
 * ip_trash_ire_reclaim.
 * Used for both IPv4 and IPv6. However, IPv6 only uses FLUSH_MTU_TIME
 * since other stale information is cleaned up using NUD.
 */
void
ire_expire(ire_t *ire, char *arg)
{
	ire_expire_arg_t	*ieap = (ire_expire_arg_t *)(uintptr_t)arg;
	ill_t			*stq_ill;
	int			flush_flags = ieap->iea_flush_flag;
	ip_stack_t		*ipst = ieap->iea_ipst;

	if ((flush_flags & FLUSH_REDIRECT_TIME) &&
	    (ire->ire_flags & RTF_DYNAMIC)) {
		/* Make sure we delete the corresponding IRE_CACHE */
		ip1dbg(("ire_expire: all redirects\n"));
		ip_rts_rtmsg(RTM_DELETE, ire, 0, ipst);
		ire_delete(ire);
		atomic_dec_32(&ipst->ips_ip_redirect_cnt);
		return;
	}
	if (ire->ire_type != IRE_CACHE)
		return;

	if (flush_flags & FLUSH_ARP_TIME) {
		/*
		 * Remove all IRE_CACHE except IPv4 multicast ires. These
		 * ires will be deleted by ip_trash_ire_reclaim_stack()
		 * when system runs low in memory.
		 * Verify that create time is more than ip_ire_arp_interval
		 * milliseconds ago.
		 */

		if (!(ire->ire_ipversion == IPV4_VERSION &&
		    CLASSD(ire->ire_addr)) && NCE_EXPIRED(ire->ire_nce, ipst)) {
			ire_delete(ire);
			return;
		}
	}

	if (ipst->ips_ip_path_mtu_discovery && (flush_flags & FLUSH_MTU_TIME) &&
	    (ire->ire_ipif != NULL)) {
		/* Increase pmtu if it is less than the interface mtu */
		mutex_enter(&ire->ire_lock);
		/*
		 * If the ipif is a vni (whose mtu is 0, since it's virtual)
		 * get the mtu from the sending interfaces' ipif
		 */
		if (IS_VNI(ire->ire_ipif->ipif_ill)) {
			stq_ill = ire->ire_stq->q_ptr;
			ire->ire_max_frag = MIN(stq_ill->ill_ipif->ipif_mtu,
			    IP_MAXPACKET);
		} else {
			ire->ire_max_frag = MIN(ire->ire_ipif->ipif_mtu,
			    IP_MAXPACKET);
		}
		ire->ire_frag_flag |= IPH_DF;
		mutex_exit(&ire->ire_lock);
	}
}

/*
 * Return any local address.  We use this to target ourselves
 * when the src address was specified as 'default'.
 * Preference for IRE_LOCAL entries.
 */
ire_t *
ire_lookup_local(zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t	*ire;
	irb_t	*irb;
	ire_t	*maybe = NULL;
	int i;

	for (i = 0; i < ipst->ips_ip_cache_table_size;  i++) {
		irb = &ipst->ips_ip_cache_table[i];
		if (irb->irb_ire == NULL)
			continue;
		rw_enter(&irb->irb_lock, RW_READER);
		for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
			if ((ire->ire_marks & IRE_MARK_CONDEMNED) ||
			    (ire->ire_zoneid != zoneid &&
			    ire->ire_zoneid != ALL_ZONES))
				continue;
			switch (ire->ire_type) {
			case IRE_LOOPBACK:
				if (maybe == NULL) {
					IRE_REFHOLD(ire);
					maybe = ire;
				}
				break;
			case IRE_LOCAL:
				if (maybe != NULL) {
					ire_refrele(maybe);
				}
				IRE_REFHOLD(ire);
				rw_exit(&irb->irb_lock);
				return (ire);
			}
		}
		rw_exit(&irb->irb_lock);
	}
	return (maybe);
}

/*
 * If the specified IRE is associated with a particular ILL, return
 * that ILL pointer (May be called as writer.).
 *
 * NOTE : This is not a generic function that can be used always.
 * This function always returns the ill of the outgoing packets
 * if this ire is used.
 */
ill_t *
ire_to_ill(const ire_t *ire)
{
	ill_t *ill = NULL;

	/*
	 * 1) For an IRE_CACHE, ire_ipif is the one where it obtained
	 *    the source address from. ire_stq is the one where the
	 *    packets will be sent out on. We return that here.
	 *
	 * 2) IRE_BROADCAST normally has a loopback and a non-loopback
	 *    copy and they always exist next to each other with loopback
	 *    copy being the first one. If we are called on the non-loopback
	 *    copy, return the one pointed by ire_stq. If it was called on
	 *    a loopback copy, we still return the one pointed by the next
	 *    ire's ire_stq pointer i.e the one pointed by the non-loopback
	 *    copy. We don't want use ire_ipif as it might represent the
	 *    source address (if we borrow source addresses for
	 *    IRE_BROADCASTS in the future).
	 *    However if an interface is currently coming up, the above
	 *    condition may not hold during that period since the ires
	 *    are added one at a time. Thus one of the pair could have been
	 *    added and the other not yet added.
	 * 3) For many other IREs (e.g., IRE_LOCAL), ire_rfq indicates the ill.
	 * 4) For all others return the ones pointed by ire_ipif->ipif_ill.
	 *    That handles IRE_LOOPBACK.
	 */

	if (ire->ire_type == IRE_CACHE) {
		ill = (ill_t *)ire->ire_stq->q_ptr;
	} else if (ire->ire_type == IRE_BROADCAST) {
		if (ire->ire_stq != NULL) {
			ill = (ill_t *)ire->ire_stq->q_ptr;
		} else {
			ire_t  *ire_next;

			ire_next = ire->ire_next;
			if (ire_next != NULL &&
			    ire_next->ire_type == IRE_BROADCAST &&
			    ire_next->ire_addr == ire->ire_addr &&
			    ire_next->ire_ipif == ire->ire_ipif) {
				ill = (ill_t *)ire_next->ire_stq->q_ptr;
			}
		}
	} else if (ire->ire_rfq != NULL) {
		ill = ire->ire_rfq->q_ptr;
	} else if (ire->ire_ipif != NULL) {
		ill = ire->ire_ipif->ipif_ill;
	}
	return (ill);
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
		    ipst->ips_ip_cache_table_size, ipst->ips_ip_cache_table,
		    NULL, zoneid, ipst);
	}
	if (vers != IPV4_VERSION) {
		ire_walk_ill_tables(0, 0, func, arg, IP6_MASK_TABLE_SIZE,
		    ipst->ips_ip6_ftable_hash_size,
		    ipst->ips_ip_forwarding_table_v6,
		    ipst->ips_ip6_cache_table_size,
		    ipst->ips_ip_cache_table_v6, NULL, zoneid, ipst);
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

void
ire_walk_ill_v4(uint_t match_flags, uint_t ire_type, pfv_t func, void *arg,
    ill_t *ill)
{
	ire_walk_ill_ipvers(match_flags, ire_type, func, arg, IPV4_VERSION,
	    ill);
}

void
ire_walk_ill_v6(uint_t match_flags, uint_t ire_type, pfv_t func, void *arg,
    ill_t *ill)
{
	ire_walk_ill_ipvers(match_flags, ire_type, func, arg, IPV6_VERSION,
	    ill);
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
		    IP_MASK_TABLE_SIZE, 0,
		    NULL, ipst->ips_ip_cache_table_size,
		    ipst->ips_ip_cache_table, ill, ALL_ZONES, ipst);
	} else if (vers == IPV6_VERSION) {
		ire_walk_ill_tables(match_flags, ire_type, func, arg,
		    IP6_MASK_TABLE_SIZE, ipst->ips_ip6_ftable_hash_size,
		    ipst->ips_ip_forwarding_table_v6,
		    ipst->ips_ip6_cache_table_size,
		    ipst->ips_ip_cache_table_v6, ill, ALL_ZONES, ipst);
	}
}

boolean_t
ire_walk_ill_match(uint_t match_flags, uint_t ire_type, ire_t *ire,
    ill_t *ill, zoneid_t zoneid, ip_stack_t *ipst)
{
	ill_t *ire_stq_ill = NULL;
	ill_t *ire_ipif_ill = NULL;
	ill_group_t *ire_ill_group = NULL;

	ASSERT(match_flags != 0 || zoneid != ALL_ZONES);
	/*
	 * MATCH_IRE_ILL/MATCH_IRE_ILL_GROUP : We match both on ill
	 *    pointed by ire_stq and ire_ipif. Only in the case of
	 *    IRE_CACHEs can ire_stq and ire_ipif be pointing to
	 *    different ills. But we want to keep this function generic
	 *    enough for future use. So, we always try to match on both.
	 *    The only caller of this function ire_walk_ill_tables, will
	 *    call "func" after we return from this function. We expect
	 *    "func" to do the right filtering of ires in this case.
	 *
	 * NOTE : In the case of MATCH_IRE_ILL_GROUP, groups
	 * pointed by ire_stq and ire_ipif should always be the same.
	 * So, we just match on only one of them.
	 */
	if (match_flags & (MATCH_IRE_ILL|MATCH_IRE_ILL_GROUP)) {
		if (ire->ire_stq != NULL)
			ire_stq_ill = (ill_t *)ire->ire_stq->q_ptr;
		if (ire->ire_ipif != NULL)
			ire_ipif_ill = ire->ire_ipif->ipif_ill;
		if (ire_stq_ill != NULL)
			ire_ill_group = ire_stq_ill->ill_group;
		if ((ire_ill_group == NULL) && (ire_ipif_ill != NULL))
			ire_ill_group = ire_ipif_ill->ill_group;
	}

	if (zoneid != ALL_ZONES) {
		/*
		 * We're walking the IREs for a specific zone. The only relevant
		 * IREs are:
		 * - all IREs with a matching ire_zoneid
		 * - all IRE_OFFSUBNETs as they're shared across all zones
		 * - IRE_INTERFACE IREs for interfaces with a usable source addr
		 *   with a matching zone
		 * - IRE_DEFAULTs with a gateway reachable from the zone
		 * We should really match on IRE_OFFSUBNETs and IRE_DEFAULTs
		 * using the same rule; but the above rules are consistent with
		 * the behavior of ire_ftable_lookup[_v6]() so that all the
		 * routes that can be matched during lookup are also matched
		 * here.
		 */
		if (zoneid != ire->ire_zoneid && ire->ire_zoneid != ALL_ZONES) {
			/*
			 * Note, IRE_INTERFACE can have the stq as NULL. For
			 * example, if the default multicast route is tied to
			 * the loopback address.
			 */
			if ((ire->ire_type & IRE_INTERFACE) &&
			    (ire->ire_stq != NULL)) {
				ire_stq_ill = (ill_t *)ire->ire_stq->q_ptr;
				if (ire->ire_ipversion == IPV4_VERSION) {
					if (!ipif_usesrc_avail(ire_stq_ill,
					    zoneid))
						/* No usable src addr in zone */
						return (B_FALSE);
				} else if (ire_stq_ill->ill_usesrc_ifindex
				    != 0) {
					/*
					 * For IPv6 use ipif_select_source_v6()
					 * so the right scope selection is done
					 */
					ipif_t *src_ipif;
					src_ipif =
					    ipif_select_source_v6(ire_stq_ill,
					    &ire->ire_addr_v6, RESTRICT_TO_NONE,
					    IPV6_PREFER_SRC_DEFAULT,
					    zoneid);
					if (src_ipif != NULL) {
						ipif_refrele(src_ipif);
					} else {
						return (B_FALSE);
					}
				} else {
					return (B_FALSE);
				}

			} else if (!(ire->ire_type & IRE_OFFSUBNET)) {
				return (B_FALSE);
			}
		}

		/*
		 * Match all default routes from the global zone, irrespective
		 * of reachability. For a non-global zone only match those
		 * where ire_gateway_addr has a IRE_INTERFACE for the zoneid.
		 */
		if (ire->ire_type == IRE_DEFAULT && zoneid != GLOBAL_ZONEID) {
			int ire_match_flags = 0;
			in6_addr_t gw_addr_v6;
			ire_t *rire;

			ire_match_flags |= MATCH_IRE_TYPE;
			if (ire->ire_ipif != NULL) {
				ire_match_flags |= MATCH_IRE_ILL_GROUP;
			}
			if (ire->ire_ipversion == IPV4_VERSION) {
				rire = ire_route_lookup(ire->ire_gateway_addr,
				    0, 0, IRE_INTERFACE, ire->ire_ipif, NULL,
				    zoneid, NULL, ire_match_flags, ipst);
			} else {
				ASSERT(ire->ire_ipversion == IPV6_VERSION);
				mutex_enter(&ire->ire_lock);
				gw_addr_v6 = ire->ire_gateway_addr_v6;
				mutex_exit(&ire->ire_lock);
				rire = ire_route_lookup_v6(&gw_addr_v6,
				    NULL, NULL, IRE_INTERFACE, ire->ire_ipif,
				    NULL, zoneid, NULL, ire_match_flags, ipst);
			}
			if (rire == NULL) {
				return (B_FALSE);
			}
			ire_refrele(rire);
		}
	}

	if (((!(match_flags & MATCH_IRE_TYPE)) ||
	    (ire->ire_type & ire_type)) &&
	    ((!(match_flags & MATCH_IRE_ILL)) ||
	    (ire_stq_ill == ill || ire_ipif_ill == ill)) &&
	    ((!(match_flags & MATCH_IRE_ILL_GROUP)) ||
	    (ire_stq_ill == ill) || (ire_ipif_ill == ill) ||
	    (ire_ill_group != NULL &&
	    ire_ill_group == ill->ill_group))) {
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
		} else
			ret = B_TRUE;
		if (ret)
			(*rtf->rt_func)(ire, rtf->rt_arg);
	}
	return (0);
}

/*
 * Walk the ftable and the ctable entries that match the ill.
 */
void
ire_walk_ill_tables(uint_t match_flags, uint_t ire_type, pfv_t func,
    void *arg, size_t ftbl_sz, size_t htbl_sz, irb_t **ipftbl,
    size_t ctbl_sz, irb_t *ipctbl, ill_t *ill, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	irb_t	*irb_ptr;
	irb_t	*irb;
	ire_t	*ire;
	int i, j;
	boolean_t ret;
	struct rtfuncarg rtfarg;

	ASSERT((!(match_flags & (MATCH_IRE_ILL |
	    MATCH_IRE_ILL_GROUP))) || (ill != NULL));
	ASSERT(!(match_flags & MATCH_IRE_TYPE) || (ire_type != 0));
	/*
	 * Optimize by not looking at the forwarding table if there
	 * is a MATCH_IRE_TYPE specified with no IRE_FORWARDTABLE
	 * specified in ire_type.
	 */
	if (!(match_flags & MATCH_IRE_TYPE) ||
	    ((ire_type & IRE_FORWARDTABLE) != 0)) {
		/* knobs such that routine is called only for v6 case */
		if (ipftbl == ipst->ips_ip_forwarding_table_v6) {
			for (i = (ftbl_sz - 1);  i >= 0; i--) {
				if ((irb_ptr = ipftbl[i]) == NULL)
					continue;
				for (j = 0; j < htbl_sz; j++) {
					irb = &irb_ptr[j];
					if (irb->irb_ire == NULL)
						continue;

					IRB_REFHOLD(irb);
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
					IRB_REFRELE(irb);
				}
			}
		} else {
			(void) memset(&rtfarg, 0, sizeof (rtfarg));
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
	 * Optimize by not looking at the cache table if there
	 * is a MATCH_IRE_TYPE specified with no IRE_CACHETABLE
	 * specified in ire_type.
	 */
	if (!(match_flags & MATCH_IRE_TYPE) ||
	    ((ire_type & IRE_CACHETABLE) != 0)) {
		for (i = 0; i < ctbl_sz;  i++) {
			irb = &ipctbl[i];
			if (irb->irb_ire == NULL)
				continue;
			IRB_REFHOLD(irb);
			for (ire = irb->irb_ire; ire != NULL;
			    ire = ire->ire_next) {
				if (match_flags == 0 && zoneid == ALL_ZONES) {
					ret = B_TRUE;
				} else {
					ret = ire_walk_ill_match(
					    match_flags, ire_type,
					    ire, ill, zoneid, ipst);
				}
				if (ret)
					(*func)(ire, arg);
			}
			IRB_REFRELE(irb);
		}
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
	return (htonl(IP_HOST_MASK << (IP_ABITS - masklen)));
}

void
ire_atomic_end(irb_t *irb_ptr, ire_t *ire)
{
	ill_t	*ill_list[NUM_ILLS];
	ip_stack_t	*ipst = ire->ire_ipst;

	ill_list[0] = ire->ire_stq != NULL ? ire->ire_stq->q_ptr : NULL;
	ill_list[1] = ire->ire_ipif != NULL ? ire->ire_ipif->ipif_ill : NULL;
	ill_unlock_ills(ill_list, NUM_ILLS);
	rw_exit(&irb_ptr->irb_lock);
	rw_exit(&ipst->ips_ill_g_usesrc_lock);
}

/*
 * ire_add_v[46] atomically make sure that the ipif or ill associated
 * with the new ire being added is stable and not IPIF_CHANGING or ILL_CHANGING
 * before adding the ire to the table. This ensures that we don't create
 * new IRE_CACHEs with stale values for parameters that are passed to
 * ire_create such as ire_max_frag. Note that ire_create() is passed a pointer
 * to the ipif_mtu, and not the value. The actual value is derived from the
 * parent ire or ipif under the bucket lock.
 */
int
ire_atomic_start(irb_t *irb_ptr, ire_t *ire, queue_t *q, mblk_t *mp,
    ipsq_func_t func)
{
	ill_t	*stq_ill;
	ill_t	*ipif_ill;
	ill_t	*ill_list[NUM_ILLS];
	int	cnt = NUM_ILLS;
	int	error = 0;
	ill_t	*ill = NULL;
	ip_stack_t	*ipst = ire->ire_ipst;

	ill_list[0] = stq_ill = ire->ire_stq !=
	    NULL ? ire->ire_stq->q_ptr : NULL;
	ill_list[1] = ipif_ill = ire->ire_ipif !=
	    NULL ? ire->ire_ipif->ipif_ill : NULL;

	ASSERT((q != NULL && mp != NULL && func != NULL) ||
	    (q == NULL && mp == NULL && func == NULL));
	rw_enter(&ipst->ips_ill_g_usesrc_lock, RW_READER);
	GRAB_CONN_LOCK(q);
	rw_enter(&irb_ptr->irb_lock, RW_WRITER);
	ill_lock_ills(ill_list, cnt);

	/*
	 * While the IRE is in the process of being added, a user may have
	 * invoked the ifconfig usesrc option on the stq_ill to make it a
	 * usesrc client ILL. Check for this possibility here, if it is true
	 * then we fail adding the IRE_CACHE. Another check is to make sure
	 * that an ipif_ill of an IRE_CACHE being added is not part of a usesrc
	 * group. The ill_g_usesrc_lock is released in ire_atomic_end
	 */
	if ((ire->ire_type & IRE_CACHE) &&
	    (ire->ire_marks & IRE_MARK_USESRC_CHECK)) {
		if (stq_ill->ill_usesrc_ifindex != 0) {
			ASSERT(stq_ill->ill_usesrc_grp_next != NULL);
			if ((ipif_ill->ill_phyint->phyint_ifindex !=
			    stq_ill->ill_usesrc_ifindex) ||
			    (ipif_ill->ill_usesrc_grp_next == NULL) ||
			    (ipif_ill->ill_usesrc_ifindex != 0)) {
				error = EINVAL;
				goto done;
			}
		} else if (ipif_ill->ill_usesrc_grp_next != NULL) {
			error = EINVAL;
			goto done;
		}
	}

	/*
	 * IPMP flag settings happen without taking the exclusive route
	 * in ip_sioctl_flags. So we need to make an atomic check here
	 * for FAILED/OFFLINE/INACTIVE flags or if it has hit the
	 * FAILBACK=no case.
	 */
	if ((stq_ill != NULL) && !IAM_WRITER_ILL(stq_ill)) {
		if (stq_ill->ill_state_flags & ILL_CHANGING) {
			ill = stq_ill;
			error = EAGAIN;
		} else if ((stq_ill->ill_phyint->phyint_flags & PHYI_OFFLINE) ||
		    (ill_is_probeonly(stq_ill) &&
		    !(ire->ire_marks & IRE_MARK_HIDDEN))) {
			error = EINVAL;
		}
		goto done;
	}

	/*
	 * We don't check for OFFLINE/FAILED in this case because
	 * the source address selection logic (ipif_select_source)
	 * may still select a source address from such an ill. The
	 * assumption is that these addresses will be moved by in.mpathd
	 * soon. (i.e. this is a race). However link local addresses
	 * will not move and hence ipif_select_source_v6 tries to avoid
	 * FAILED ills. Please see ipif_select_source_v6 for more info
	 */
	if ((ipif_ill != NULL) && !IAM_WRITER_ILL(ipif_ill) &&
	    (ipif_ill->ill_state_flags & ILL_CHANGING)) {
		ill = ipif_ill;
		error = EAGAIN;
		goto done;
	}

	if ((ire->ire_ipif != NULL) && !IAM_WRITER_IPIF(ire->ire_ipif) &&
	    (ire->ire_ipif->ipif_state_flags & IPIF_CHANGING)) {
		ill = ire->ire_ipif->ipif_ill;
		ASSERT(ill != NULL);
		error = EAGAIN;
		goto done;
	}

done:
	if (error == EAGAIN && ILL_CAN_WAIT(ill, q)) {
		ipsq_t *ipsq = ill->ill_phyint->phyint_ipsq;
		mutex_enter(&ipsq->ipsq_lock);
		ire_atomic_end(irb_ptr, ire);
		ipsq_enq(ipsq, q, mp, func, NEW_OP, ill);
		mutex_exit(&ipsq->ipsq_lock);
		error = EINPROGRESS;
	} else if (error != 0) {
		ire_atomic_end(irb_ptr, ire);
	}

	RELEASE_CONN_LOCK(q);
	return (error);
}

/*
 * Add a fully initialized IRE to an appropriate table based on
 * ire_type.
 *
 * allow_unresolved == B_FALSE indicates a legacy code-path call
 * that has prohibited the addition of incomplete ire's. If this
 * parameter is set, and we find an nce that is in a state other
 * than ND_REACHABLE, we fail the add. Note that nce_state could be
 * something other than ND_REACHABLE if the nce had just expired and
 * the ire_create preceding the ire_add added a new ND_INITIAL nce.
 */
int
ire_add(ire_t **irep, queue_t *q, mblk_t *mp, ipsq_func_t func,
    boolean_t allow_unresolved)
{
	ire_t	*ire1;
	ill_t	*stq_ill = NULL;
	ill_t	*ill;
	ipif_t	*ipif = NULL;
	ill_walk_context_t ctx;
	ire_t	*ire = *irep;
	int	error;
	boolean_t ire_is_mblk = B_FALSE;
	tsol_gcgrp_t *gcgrp = NULL;
	tsol_gcgrp_addr_t ga;
	ip_stack_t	*ipst = ire->ire_ipst;

	/* get ready for the day when original ire is not created as mblk */
	if (ire->ire_mp != NULL) {
		ire_is_mblk = B_TRUE;
		/* Copy the ire to a kmem_alloc'ed area */
		ire1 = kmem_cache_alloc(ire_cache, KM_NOSLEEP);
		if (ire1 == NULL) {
			ip1dbg(("ire_add: alloc failed\n"));
			ire_delete(ire);
			*irep = NULL;
			return (ENOMEM);
		}
		ire->ire_marks &= ~IRE_MARK_UNCACHED;
		*ire1 = *ire;
		ire1->ire_mp = NULL;
		ire1->ire_stq_ifindex = 0;
		freeb(ire->ire_mp);
		ire = ire1;
	}
	if (ire->ire_stq != NULL)
		stq_ill = (ill_t *)ire->ire_stq->q_ptr;

	if (ire->ire_type == IRE_CACHE) {
		/*
		 * If this interface is FAILED, or INACTIVE or has hit
		 * the FAILBACK=no case, we create IRE_CACHES marked
		 * HIDDEN for some special cases e.g. bind to
		 * IPIF_NOFAILOVER address etc. So, if this interface
		 * is FAILED/INACTIVE/hit FAILBACK=no case, and we are
		 * not creating hidden ires, we should not allow that.
		 * This happens because the state of the interface
		 * changed while we were waiting in ARP. If this is the
		 * daemon sending probes, the next probe will create
		 * HIDDEN ires and we will create an ire then. This
		 * cannot happen with NDP currently because IRE is
		 * never queued in NDP. But it can happen in the
		 * future when we have external resolvers with IPv6.
		 * If the interface gets marked with OFFLINE while we
		 * are waiting in ARP, don't add the ire.
		 */
		if ((stq_ill->ill_phyint->phyint_flags & PHYI_OFFLINE) ||
		    (ill_is_probeonly(stq_ill) &&
		    !(ire->ire_marks & IRE_MARK_HIDDEN))) {
			/*
			 * We don't know whether it is a valid ipif or not.
			 * unless we do the check below. So, set it to NULL.
			 */
			ire->ire_ipif = NULL;
			ire_delete(ire);
			*irep = NULL;
			return (EINVAL);
		}
	}

	if (stq_ill != NULL && ire->ire_type == IRE_CACHE &&
	    stq_ill->ill_net_type == IRE_IF_RESOLVER) {
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		ill = ILL_START_WALK_ALL(&ctx, ipst);
		for (; ill != NULL; ill = ill_next(&ctx, ill)) {
			mutex_enter(&ill->ill_lock);
			if (ill->ill_state_flags & ILL_CONDEMNED) {
				mutex_exit(&ill->ill_lock);
				continue;
			}
			/*
			 * We need to make sure that the ipif is a valid one
			 * before adding the IRE_CACHE. This happens only
			 * with IRE_CACHE when there is an external resolver.
			 *
			 * We can unplumb a logical interface while the
			 * packet is waiting in ARP with the IRE. Then,
			 * later on when we feed the IRE back, the ipif
			 * has to be re-checked. This can't happen with
			 * NDP currently, as we never queue the IRE with
			 * the packet. We always try to recreate the IRE
			 * when the resolution is completed. But, we do
			 * it for IPv6 also here so that in future if
			 * we have external resolvers, it will work without
			 * any change.
			 */
			ipif = ipif_lookup_seqid(ill, ire->ire_ipif_seqid);
			if (ipif != NULL) {
				ipif_refhold_locked(ipif);
				mutex_exit(&ill->ill_lock);
				break;
			}
			mutex_exit(&ill->ill_lock);
		}
		rw_exit(&ipst->ips_ill_g_lock);
		if (ipif == NULL ||
		    (ipif->ipif_isv6 &&
		    !IN6_ARE_ADDR_EQUAL(&ire->ire_src_addr_v6,
		    &ipif->ipif_v6src_addr)) ||
		    (!ipif->ipif_isv6 &&
		    ire->ire_src_addr != ipif->ipif_src_addr) ||
		    ire->ire_zoneid != ipif->ipif_zoneid) {

			if (ipif != NULL)
				ipif_refrele(ipif);
			ire->ire_ipif = NULL;
			ire_delete(ire);
			*irep = NULL;
			return (EINVAL);
		}


		ASSERT(ill != NULL);
		/*
		 * If this group was dismantled while this packets was
		 * queued in ARP, don't add it here.
		 */
		if (ire->ire_ipif->ipif_ill->ill_group != ill->ill_group) {
			/* We don't want ire_inactive bump stats for this */
			ipif_refrele(ipif);
			ire->ire_ipif = NULL;
			ire_delete(ire);
			*irep = NULL;
			return (EINVAL);
		}

		/*
		 * Since we didn't attach label security attributes to the
		 * ire for the resolver case, we need to add it now. (only
		 * for v4 resolver and v6 xresolv case).
		 */
		if (is_system_labeled() && ire_is_mblk) {
			if (ire->ire_ipversion == IPV4_VERSION) {
				ga.ga_af = AF_INET;
				IN6_IPADDR_TO_V4MAPPED(ire->ire_gateway_addr !=
				    INADDR_ANY ? ire->ire_gateway_addr :
				    ire->ire_addr, &ga.ga_addr);
			} else {
				ga.ga_af = AF_INET6;
				ga.ga_addr = IN6_IS_ADDR_UNSPECIFIED(
				    &ire->ire_gateway_addr_v6) ?
				    ire->ire_addr_v6 :
				    ire->ire_gateway_addr_v6;
			}
			gcgrp = gcgrp_lookup(&ga, B_FALSE);
			error = tsol_ire_init_gwattr(ire, ire->ire_ipversion,
			    NULL, gcgrp);
			if (error != 0) {
				if (gcgrp != NULL) {
					GCGRP_REFRELE(gcgrp);
					gcgrp = NULL;
				}
				ipif_refrele(ipif);
				ire->ire_ipif = NULL;
				ire_delete(ire);
				*irep = NULL;
				return (error);
			}
		}
	}

	/*
	 * In case ire was changed
	 */
	*irep = ire;
	if (ire->ire_ipversion == IPV6_VERSION)
		error = ire_add_v6(irep, q, mp, func);
	else
		error = ire_add_v4(irep, q, mp, func, allow_unresolved);
	if (ipif != NULL)
		ipif_refrele(ipif);
	return (error);
}

/*
 * Add an initialized IRE to an appropriate table based on ire_type.
 *
 * The forward table contains IRE_PREFIX/IRE_HOST and
 * IRE_IF_RESOLVER/IRE_IF_NORESOLVER and IRE_DEFAULT.
 *
 * The cache table contains IRE_BROADCAST/IRE_LOCAL/IRE_LOOPBACK
 * and IRE_CACHE.
 *
 * NOTE : This function is called as writer though not required
 * by this function.
 */
static int
ire_add_v4(ire_t **ire_p, queue_t *q, mblk_t *mp, ipsq_func_t func,
    boolean_t allow_unresolved)
{
	ire_t	*ire1;
	irb_t	*irb_ptr;
	ire_t	**irep;
	int	flags;
	ire_t	*pire = NULL;
	ill_t	*stq_ill;
	ire_t	*ire = *ire_p;
	int	error;
	boolean_t need_refrele = B_FALSE;
	nce_t	*nce;
	ip_stack_t	*ipst = ire->ire_ipst;

	if (ire->ire_ipif != NULL)
		ASSERT(!MUTEX_HELD(&ire->ire_ipif->ipif_ill->ill_lock));
	if (ire->ire_stq != NULL)
		ASSERT(!MUTEX_HELD(
		    &((ill_t *)(ire->ire_stq->q_ptr))->ill_lock));
	ASSERT(ire->ire_ipversion == IPV4_VERSION);
	ASSERT(ire->ire_mp == NULL); /* Calls should go through ire_add */

	/* Find the appropriate list head. */
	switch (ire->ire_type) {
	case IRE_HOST:
		ire->ire_mask = IP_HOST_MASK;
		ire->ire_masklen = IP_ABITS;
		if ((ire->ire_flags & RTF_SETSRC) == 0)
			ire->ire_src_addr = 0;
		break;
	case IRE_CACHE:
	case IRE_BROADCAST:
	case IRE_LOCAL:
	case IRE_LOOPBACK:
		ire->ire_mask = IP_HOST_MASK;
		ire->ire_masklen = IP_ABITS;
		break;
	case IRE_PREFIX:
		if ((ire->ire_flags & RTF_SETSRC) == 0)
			ire->ire_src_addr = 0;
		break;
	case IRE_DEFAULT:
		if ((ire->ire_flags & RTF_SETSRC) == 0)
			ire->ire_src_addr = 0;
		break;
	case IRE_IF_RESOLVER:
	case IRE_IF_NORESOLVER:
		break;
	default:
		ip0dbg(("ire_add_v4: ire %p has unrecognized IRE type (%d)\n",
		    (void *)ire, ire->ire_type));
		ire_delete(ire);
		*ire_p = NULL;
		return (EINVAL);
	}

	/* Make sure the address is properly masked. */
	ire->ire_addr &= ire->ire_mask;

	/*
	 * ip_newroute/ip_newroute_multi are unable to prevent the deletion
	 * of the interface route while adding an IRE_CACHE for an on-link
	 * destination in the IRE_IF_RESOLVER case, since the ire has to
	 * go to ARP and return. We can't do a REFHOLD on the
	 * associated interface ire for fear of ARP freeing the message.
	 * Here we look up the interface ire in the forwarding table and
	 * make sure that the interface route has not been deleted.
	 */
	if (ire->ire_type == IRE_CACHE && ire->ire_gateway_addr == 0 &&
	    ((ill_t *)ire->ire_stq->q_ptr)->ill_net_type == IRE_IF_RESOLVER) {

		ASSERT(ire->ire_max_fragp == NULL);
		if (CLASSD(ire->ire_addr) && !(ire->ire_flags & RTF_SETSRC)) {
			/*
			 * The ihandle that we used in ip_newroute_multi
			 * comes from the interface route corresponding
			 * to ire_ipif. Lookup here to see if it exists
			 * still.
			 * If the ire has a source address assigned using
			 * RTF_SETSRC, ire_ipif is the logical interface holding
			 * this source address, so we can't use it to check for
			 * the existence of the interface route. Instead we rely
			 * on the brute force ihandle search in
			 * ire_ihandle_lookup_onlink() below.
			 */
			pire = ipif_to_ire(ire->ire_ipif);
			if (pire == NULL) {
				ire_delete(ire);
				*ire_p = NULL;
				return (EINVAL);
			} else if (pire->ire_ihandle != ire->ire_ihandle) {
				ire_refrele(pire);
				ire_delete(ire);
				*ire_p = NULL;
				return (EINVAL);
			}
		} else {
			pire = ire_ihandle_lookup_onlink(ire);
			if (pire == NULL) {
				ire_delete(ire);
				*ire_p = NULL;
				return (EINVAL);
			}
		}
		/* Prevent pire from getting deleted */
		IRB_REFHOLD(pire->ire_bucket);
		/* Has it been removed already ? */
		if (pire->ire_marks & IRE_MARK_CONDEMNED) {
			IRB_REFRELE(pire->ire_bucket);
			ire_refrele(pire);
			ire_delete(ire);
			*ire_p = NULL;
			return (EINVAL);
		}
	} else {
		ASSERT(ire->ire_max_fragp != NULL);
	}
	flags = (MATCH_IRE_MASK | MATCH_IRE_TYPE | MATCH_IRE_GW);

	if (ire->ire_ipif != NULL) {
		/*
		 * We use MATCH_IRE_IPIF while adding IRE_CACHES only
		 * for historic reasons and to maintain symmetry with
		 * IPv6 code path. Historically this was used by
		 * multicast code to create multiple IRE_CACHES on
		 * a single ill with different ipifs. This was used
		 * so that multicast packets leaving the node had the
		 * right source address. This is no longer needed as
		 * ip_wput initializes the address correctly.
		 */
		flags |= MATCH_IRE_IPIF;
		/*
		 * If we are creating hidden ires, make sure we search on
		 * this ill (MATCH_IRE_ILL) and a hidden ire,
		 * while we are searching for duplicates below. Otherwise we
		 * could potentially find an IRE on some other interface
		 * and it may not be a IRE marked with IRE_MARK_HIDDEN. We
		 * shouldn't do this as this will lead to an infinite loop
		 * (if we get to ip_wput again) eventually we need an hidden
		 * ire for this packet to go out. MATCH_IRE_ILL is explicitly
		 * done below.
		 */
		if (ire->ire_type == IRE_CACHE &&
		    (ire->ire_marks & IRE_MARK_HIDDEN))
			flags |= (MATCH_IRE_MARK_HIDDEN);
	}
	if ((ire->ire_type & IRE_CACHETABLE) == 0) {
		irb_ptr = ire_get_bucket(ire);
		need_refrele = B_TRUE;
		if (irb_ptr == NULL) {
			/*
			 * This assumes that the ire has not added
			 * a reference to the ipif.
			 */
			ire->ire_ipif = NULL;
			ire_delete(ire);
			if (pire != NULL) {
				IRB_REFRELE(pire->ire_bucket);
				ire_refrele(pire);
			}
			*ire_p = NULL;
			return (EINVAL);
		}
	} else {
		irb_ptr = &(ipst->ips_ip_cache_table[IRE_ADDR_HASH(
		    ire->ire_addr, ipst->ips_ip_cache_table_size)]);
	}

	/*
	 * Start the atomic add of the ire. Grab the ill locks,
	 * ill_g_usesrc_lock and the bucket lock. Check for condemned
	 *
	 * If ipif or ill is changing ire_atomic_start() may queue the
	 * request and return EINPROGRESS.
	 * To avoid lock order problems, get the ndp4->ndp_g_lock.
	 */
	mutex_enter(&ipst->ips_ndp4->ndp_g_lock);
	error = ire_atomic_start(irb_ptr, ire, q, mp, func);
	if (error != 0) {
		mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
		/*
		 * We don't know whether it is a valid ipif or not.
		 * So, set it to NULL. This assumes that the ire has not added
		 * a reference to the ipif.
		 */
		ire->ire_ipif = NULL;
		ire_delete(ire);
		if (pire != NULL) {
			IRB_REFRELE(pire->ire_bucket);
			ire_refrele(pire);
		}
		*ire_p = NULL;
		if (need_refrele)
			IRB_REFRELE(irb_ptr);
		return (error);
	}
	/*
	 * To avoid creating ires having stale values for the ire_max_frag
	 * we get the latest value atomically here. For more details
	 * see the block comment in ip_sioctl_mtu and in DL_NOTE_SDU_CHANGE
	 * in ip_rput_dlpi_writer
	 */
	if (ire->ire_max_fragp == NULL) {
		if (CLASSD(ire->ire_addr))
			ire->ire_max_frag = ire->ire_ipif->ipif_mtu;
		else
			ire->ire_max_frag = pire->ire_max_frag;
	} else {
		uint_t	max_frag;

		max_frag = *ire->ire_max_fragp;
		ire->ire_max_fragp = NULL;
		ire->ire_max_frag = max_frag;
	}
	/*
	 * Atomically check for duplicate and insert in the table.
	 */
	for (ire1 = irb_ptr->irb_ire; ire1 != NULL; ire1 = ire1->ire_next) {
		if (ire1->ire_marks & IRE_MARK_CONDEMNED)
			continue;
		if (ire->ire_ipif != NULL) {
			/*
			 * We do MATCH_IRE_ILL implicitly here for IREs
			 * with a non-null ire_ipif, including IRE_CACHEs.
			 * As ire_ipif and ire_stq could point to two
			 * different ills, we can't pass just ire_ipif to
			 * ire_match_args and get a match on both ills.
			 * This is just needed for duplicate checks here and
			 * so we don't add an extra argument to
			 * ire_match_args for this. Do it locally.
			 *
			 * NOTE : Currently there is no part of the code
			 * that asks for both MATH_IRE_IPIF and MATCH_IRE_ILL
			 * match for IRE_CACHEs. Thus we don't want to
			 * extend the arguments to ire_match_args.
			 */
			if (ire1->ire_stq != ire->ire_stq)
				continue;
			/*
			 * Multiroute IRE_CACHEs for a given destination can
			 * have the same ire_ipif, typically if their source
			 * address is forced using RTF_SETSRC, and the same
			 * send-to queue. We differentiate them using the parent
			 * handle.
			 */
			if (ire->ire_type == IRE_CACHE &&
			    (ire1->ire_flags & RTF_MULTIRT) &&
			    (ire->ire_flags & RTF_MULTIRT) &&
			    (ire1->ire_phandle != ire->ire_phandle))
				continue;
		}
		if (ire1->ire_zoneid != ire->ire_zoneid)
			continue;
		if (ire_match_args(ire1, ire->ire_addr, ire->ire_mask,
		    ire->ire_gateway_addr, ire->ire_type, ire->ire_ipif,
		    ire->ire_zoneid, 0, NULL, flags)) {
			/*
			 * Return the old ire after doing a REFHOLD.
			 * As most of the callers continue to use the IRE
			 * after adding, we return a held ire. This will
			 * avoid a lookup in the caller again. If the callers
			 * don't want to use it, they need to do a REFRELE.
			 */
			ip1dbg(("found dup ire existing %p new %p",
			    (void *)ire1, (void *)ire));
			IRE_REFHOLD(ire1);
			ire_atomic_end(irb_ptr, ire);
			mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
			ire_delete(ire);
			if (pire != NULL) {
				/*
				 * Assert that it is not removed from the
				 * list yet.
				 */
				ASSERT(pire->ire_ptpn != NULL);
				IRB_REFRELE(pire->ire_bucket);
				ire_refrele(pire);
			}
			*ire_p = ire1;
			if (need_refrele)
				IRB_REFRELE(irb_ptr);
			return (0);
		}
	}
	if (ire->ire_type & IRE_CACHE) {
		ASSERT(ire->ire_stq != NULL);
		nce = ndp_lookup_v4(ire_to_ill(ire),
		    ((ire->ire_gateway_addr != INADDR_ANY) ?
		    &ire->ire_gateway_addr : &ire->ire_addr),
		    B_TRUE);
		if (nce != NULL)
			mutex_enter(&nce->nce_lock);
		/*
		 * if the nce is NCE_F_CONDEMNED, or if it is not ND_REACHABLE
		 * and the caller has prohibited the addition of incomplete
		 * ire's, we fail the add. Note that nce_state could be
		 * something other than ND_REACHABLE if the nce had
		 * just expired and the ire_create preceding the
		 * ire_add added a new ND_INITIAL nce.
		 */
		if ((nce == NULL) ||
		    (nce->nce_flags & NCE_F_CONDEMNED) ||
		    (!allow_unresolved &&
		    (nce->nce_state != ND_REACHABLE))) {
			if (nce != NULL) {
				DTRACE_PROBE1(ire__bad__nce, nce_t *, nce);
				mutex_exit(&nce->nce_lock);
			}
			ire_atomic_end(irb_ptr, ire);
			mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
			if (nce != NULL)
				NCE_REFRELE(nce);
			DTRACE_PROBE1(ire__no__nce, ire_t *, ire);
			ire_delete(ire);
			if (pire != NULL) {
				IRB_REFRELE(pire->ire_bucket);
				ire_refrele(pire);
			}
			*ire_p = NULL;
			if (need_refrele)
				IRB_REFRELE(irb_ptr);
			return (EINVAL);
		} else {
			ire->ire_nce = nce;
			mutex_exit(&nce->nce_lock);
			/*
			 * We are associating this nce to the ire, so
			 * change the nce ref taken in ndp_lookup_v4() from
			 * NCE_REFHOLD to NCE_REFHOLD_NOTR
			 */
			NCE_REFHOLD_TO_REFHOLD_NOTR(ire->ire_nce);
		}
	}
	/*
	 * Make it easy for ip_wput_ire() to hit multiple broadcast ires by
	 * grouping identical addresses together on the hash chain. We also
	 * don't want to send multiple copies out if there are two ills part
	 * of the same group. Thus we group the ires with same addr and same
	 * ill group together so that ip_wput_ire can easily skip all the
	 * ires with same addr and same group after sending the first copy.
	 * We do this only for IRE_BROADCASTs as ip_wput_ire is currently
	 * interested in such groupings only for broadcasts.
	 *
	 * NOTE : If the interfaces are brought up first and then grouped,
	 * illgrp_insert will handle it. We come here when the interfaces
	 * are already in group and we are bringing them UP.
	 *
	 * Find the first entry that matches ire_addr. *irep will be null
	 * if no match.
	 *
	 * Note: the loopback and non-loopback broadcast entries for an
	 * interface MUST be added before any MULTIRT entries.
	 */
	irep = (ire_t **)irb_ptr;
	while ((ire1 = *irep) != NULL && ire->ire_addr != ire1->ire_addr)
		irep = &ire1->ire_next;
	if (ire->ire_type == IRE_BROADCAST && *irep != NULL) {
		/*
		 * We found some ire (i.e *irep) with a matching addr. We
		 * want to group ires with same addr and same ill group
		 * together.
		 *
		 * First get to the entry that matches our address and
		 * ill group i.e stop as soon as we find the first ire
		 * matching the ill group and address. If there is only
		 * an address match, we should walk and look for some
		 * group match. These are some of the possible scenarios :
		 *
		 * 1) There are no groups at all i.e all ire's ill_group
		 *    are NULL. In that case we will essentially group
		 *    all the ires with the same addr together. Same as
		 *    the "else" block of this "if".
		 *
		 * 2) There are some groups and this ire's ill_group is
		 *    NULL. In this case, we will first find the group
		 *    that matches the address and a NULL group. Then
		 *    we will insert the ire at the end of that group.
		 *
		 * 3) There are some groups and this ires's ill_group is
		 *    non-NULL. In this case we will first find the group
		 *    that matches the address and the ill_group. Then
		 *    we will insert the ire at the end of that group.
		 */
		for (;;) {
			ire1 = *irep;
			if ((ire1->ire_next == NULL) ||
			    (ire1->ire_next->ire_addr != ire->ire_addr) ||
			    (ire1->ire_type != IRE_BROADCAST) ||
			    (ire1->ire_flags & RTF_MULTIRT) ||
			    (ire1->ire_ipif->ipif_ill->ill_group ==
			    ire->ire_ipif->ipif_ill->ill_group))
				break;
			irep = &ire1->ire_next;
		}
		ASSERT(*irep != NULL);
		/*
		 * The ire will be added before *irep, so
		 * if irep is a MULTIRT ire, just break to
		 * ire insertion code.
		 */
		if (((*irep)->ire_flags & RTF_MULTIRT) != 0)
			goto insert_ire;

		irep = &((*irep)->ire_next);

		/*
		 * Either we have hit the end of the list or the address
		 * did not match or the group *matched*. If we found
		 * a match on the group, skip to the end of the group.
		 */
		while (*irep != NULL) {
			ire1 = *irep;
			if ((ire1->ire_addr != ire->ire_addr) ||
			    (ire1->ire_type != IRE_BROADCAST) ||
			    (ire1->ire_ipif->ipif_ill->ill_group !=
			    ire->ire_ipif->ipif_ill->ill_group))
				break;
			if (ire1->ire_ipif->ipif_ill->ill_group == NULL &&
			    ire1->ire_ipif == ire->ire_ipif) {
				irep = &ire1->ire_next;
				break;
			}
			irep = &ire1->ire_next;
		}
	} else if (*irep != NULL) {
		/*
		 * Find the last ire which matches ire_addr.
		 * Needed to do tail insertion among entries with the same
		 * ire_addr.
		 */
		while (ire->ire_addr == ire1->ire_addr) {
			irep = &ire1->ire_next;
			ire1 = *irep;
			if (ire1 == NULL)
				break;
		}
	}

insert_ire:
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
	IRE_REFHOLD_LOCKED(ire);
	BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_inserted);

	irb_ptr->irb_ire_cnt++;
	if (irb_ptr->irb_marks & IRB_MARK_FTABLE)
		irb_ptr->irb_nire++;

	if (ire->ire_marks & IRE_MARK_TEMPORARY)
		irb_ptr->irb_tmp_ire_cnt++;

	if (ire->ire_ipif != NULL) {
		DTRACE_PROBE3(ipif__incr__cnt, (ipif_t *), ire->ire_ipif,
		    (char *), "ire", (void *), ire);
		ire->ire_ipif->ipif_ire_cnt++;
		if (ire->ire_stq != NULL) {
			stq_ill = (ill_t *)ire->ire_stq->q_ptr;
			DTRACE_PROBE3(ill__incr__cnt, (ill_t *), stq_ill,
			    (char *), "ire", (void *), ire);
			stq_ill->ill_ire_cnt++;
		}
	} else {
		ASSERT(ire->ire_stq == NULL);
	}

	ire_atomic_end(irb_ptr, ire);
	mutex_exit(&ipst->ips_ndp4->ndp_g_lock);

	if (pire != NULL) {
		/* Assert that it is not removed from the list yet */
		ASSERT(pire->ire_ptpn != NULL);
		IRB_REFRELE(pire->ire_bucket);
		ire_refrele(pire);
	}

	if (ire->ire_type != IRE_CACHE) {
		/*
		 * For ire's with host mask see if there is an entry
		 * in the cache. If there is one flush the whole cache as
		 * there might be multiple entries due to RTF_MULTIRT (CGTP).
		 * If no entry is found than there is no need to flush the
		 * cache.
		 */
		if (ire->ire_mask == IP_HOST_MASK) {
			ire_t *lire;
			lire = ire_ctable_lookup(ire->ire_addr, NULL, IRE_CACHE,
			    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (lire != NULL) {
				ire_refrele(lire);
				ire_flush_cache_v4(ire, IRE_FLUSH_ADD);
			}
		} else {
			ire_flush_cache_v4(ire, IRE_FLUSH_ADD);
		}
	}
	/*
	 * We had to delay the fast path probe until the ire is inserted
	 * in the list. Otherwise the fast path ack won't find the ire in
	 * the table.
	 */
	if (ire->ire_type == IRE_CACHE ||
	    (ire->ire_type == IRE_BROADCAST && ire->ire_stq != NULL)) {
		ASSERT(ire->ire_nce != NULL);
		if (ire->ire_nce->nce_state == ND_REACHABLE)
			nce_fastpath(ire->ire_nce);
	}
	if (ire->ire_ipif != NULL)
		ASSERT(!MUTEX_HELD(&ire->ire_ipif->ipif_ill->ill_lock));
	*ire_p = ire;
	if (need_refrele) {
		IRB_REFRELE(irb_ptr);
	}
	return (0);
}

/*
 * IRB_REFRELE is the only caller of the function. ire_unlink calls to
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
		IRE_REFRELE_NOTR(ire);
		ire = ire_next;
	}
}

/*
 * IRB_REFRELE is the only caller of the function. It calls to unlink
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
	ASSERT(((irb->irb_marks & IRB_MARK_FTABLE) && irb->irb_refcnt == 1) ||
	    (irb->irb_refcnt == 0));
	ASSERT(irb->irb_marks & IRB_MARK_CONDEMNED);
	ASSERT(irb->irb_ire != NULL);

	for (ire = irb->irb_ire; ire != NULL; ire = ire1) {
		ip_stack_t	*ipst = ire->ire_ipst;

		ire1 = ire->ire_next;
		if (ire->ire_marks & IRE_MARK_CONDEMNED) {
			ptpn = ire->ire_ptpn;
			ire1 = ire->ire_next;
			if (ire1)
				ire1->ire_ptpn = ptpn;
			*ptpn = ire1;
			ire->ire_ptpn = NULL;
			ire->ire_next = NULL;
			if (ire->ire_type == IRE_DEFAULT) {
				/*
				 * IRE is out of the list. We need to adjust
				 * the accounting before the caller drops
				 * the lock.
				 */
				if (ire->ire_ipversion == IPV6_VERSION) {
					ASSERT(ipst->
					    ips_ipv6_ire_default_count !=
					    0);
					ipst->ips_ipv6_ire_default_count--;
				}
			}
			/*
			 * We need to call ire_delete_v4 or ire_delete_v6
			 * to clean up the cache or the redirects pointing at
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
 * Delete all the cache entries with this 'addr'.  When IP gets a gratuitous
 * ARP message on any of its interface queue, it scans the nce table and
 * deletes and calls ndp_delete() for the appropriate nce. This action
 * also deletes all the neighbor/ire cache entries for that address.
 * This function is called from ip_arp_news in ip.c and also for
 * ARP ioctl processing in ip_if.c. ip_ire_clookup_and_delete returns
 * true if it finds a nce entry which is used by ip_arp_news to determine if
 * it needs to do an ire_walk_v4. The return value is also  used for the
 * same purpose by ARP IOCTL processing * in ip_if.c when deleting
 * ARP entries. For SIOC*IFARP ioctls in addition to the address,
 * ip_if->ipif_ill also needs to be matched.
 */
boolean_t
ip_ire_clookup_and_delete(ipaddr_t addr, ipif_t *ipif, ip_stack_t *ipst)
{
	ill_t	*ill;
	nce_t	*nce;

	ill = (ipif ? ipif->ipif_ill : NULL);

	if (ill != NULL) {
		/*
		 * clean up the nce (and any relevant ire's) that matches
		 * on addr and ill.
		 */
		nce = ndp_lookup_v4(ill, &addr, B_FALSE);
		if (nce != NULL) {
			ndp_delete(nce);
			return (B_TRUE);
		}
	} else {
		/*
		 * ill is wildcard. clean up all nce's and
		 * ire's that match on addr
		 */
		nce_clookup_t cl;

		cl.ncecl_addr = addr;
		cl.ncecl_found = B_FALSE;

		ndp_walk_common(ipst->ips_ndp4, NULL,
		    (pfi_t)ip_nce_clookup_and_delete, (uchar_t *)&cl, B_TRUE);

		/*
		 *  ncecl_found would be set by ip_nce_clookup_and_delete if
		 *  we found a matching nce.
		 */
		return (cl.ncecl_found);
	}
	return (B_FALSE);

}

/* Delete the supplied nce if its nce_addr matches the supplied address */
static void
ip_nce_clookup_and_delete(nce_t *nce, void *arg)
{
	nce_clookup_t *cl = (nce_clookup_t *)arg;
	ipaddr_t nce_addr;

	IN6_V4MAPPED_TO_IPADDR(&nce->nce_addr, nce_addr);
	if (nce_addr == cl->ncecl_addr) {
		cl->ncecl_found = B_TRUE;
		/* clean up the nce (and any relevant ire's) */
		ndp_delete(nce);
	}
}

/*
 * Clean up the radix node for this ire. Must be called by IRB_REFRELE
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
 */
void
ire_delete(ire_t *ire)
{
	ire_t	*ire1;
	ire_t	**ptpn;
	irb_t *irb;
	ip_stack_t	*ipst = ire->ire_ipst;

	if ((irb = ire->ire_bucket) == NULL) {
		/*
		 * It was never inserted in the list. Should call REFRELE
		 * to free this IRE.
		 */
		IRE_REFRELE_NOTR(ire);
		return;
	}

	rw_enter(&irb->irb_lock, RW_WRITER);

	if (irb->irb_rr_origin == ire) {
		irb->irb_rr_origin = NULL;
	}

	/*
	 * In case of V4 we might still be waiting for fastpath ack.
	 */
	if (ire->ire_ipversion == IPV4_VERSION &&
	    (ire->ire_type == IRE_CACHE ||
	    (ire->ire_type == IRE_BROADCAST && ire->ire_stq != NULL))) {
		ASSERT(ire->ire_nce != NULL);
		nce_fastpath_list_delete(ire->ire_nce);
	}

	if (ire->ire_ptpn == NULL) {
		/*
		 * Some other thread has removed us from the list.
		 * It should have done the REFRELE for us.
		 */
		rw_exit(&irb->irb_lock);
		return;
	}

	if (!(ire->ire_marks & IRE_MARK_CONDEMNED)) {
		irb->irb_ire_cnt--;
		ire->ire_marks |= IRE_MARK_CONDEMNED;
		if (ire->ire_marks & IRE_MARK_TEMPORARY) {
			irb->irb_tmp_ire_cnt--;
			ire->ire_marks &= ~IRE_MARK_TEMPORARY;
		}
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
	/*
	 * ip_wput/ip_wput_v6 checks this flag to see whether
	 * it should still use the cached ire or not.
	 */
	if (ire->ire_type == IRE_DEFAULT) {
		/*
		 * IRE is out of the list. We need to adjust the
		 * accounting before we drop the lock.
		 */
		if (ire->ire_ipversion == IPV6_VERSION) {
			ASSERT(ipst->ips_ipv6_ire_default_count != 0);
			ipst->ips_ipv6_ire_default_count--;
		}
	}
	rw_exit(&irb->irb_lock);

	if (ire->ire_ipversion == IPV6_VERSION) {
		ire_delete_v6(ire);
	} else {
		ire_delete_v4(ire);
	}
	/*
	 * We removed it from the list. Decrement the
	 * reference count.
	 */
	IRE_REFRELE_NOTR(ire);
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

	if (ire->ire_type != IRE_CACHE)
		ire_flush_cache_v4(ire, IRE_FLUSH_DELETE);
	if (ire->ire_type == IRE_DEFAULT) {
		/*
		 * when a default gateway is going away
		 * delete all the host redirects pointing at that
		 * gateway.
		 */
		ire_delete_host_redirects(ire->ire_gateway_addr, ipst);
	}
}

/*
 * IRE_REFRELE/ire_refrele are the only caller of the function. It calls
 * to free the ire when the reference count goes to zero.
 */
void
ire_inactive(ire_t *ire)
{
	nce_t	*nce;
	ill_t	*ill = NULL;
	ill_t	*stq_ill = NULL;
	ipif_t	*ipif;
	boolean_t	need_wakeup = B_FALSE;
	irb_t 	*irb;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_refcnt == 0);
	ASSERT(ire->ire_ptpn == NULL);
	ASSERT(ire->ire_next == NULL);

	if (ire->ire_gw_secattr != NULL) {
		ire_gw_secattr_free(ire->ire_gw_secattr);
		ire->ire_gw_secattr = NULL;
	}

	if (ire->ire_mp != NULL) {
		ASSERT(ire->ire_bucket == NULL);
		mutex_destroy(&ire->ire_lock);
		BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_freed);
		if (ire->ire_nce != NULL)
			NCE_REFRELE_NOTR(ire->ire_nce);
		freeb(ire->ire_mp);
		return;
	}

	if ((nce = ire->ire_nce) != NULL) {
		NCE_REFRELE_NOTR(nce);
		ire->ire_nce = NULL;
	}

	if (ire->ire_ipif == NULL)
		goto end;

	ipif = ire->ire_ipif;
	ill = ipif->ipif_ill;

	if (ire->ire_bucket == NULL) {
		/* The ire was never inserted in the table. */
		goto end;
	}

	/*
	 * ipif_ire_cnt on this ipif goes down by 1. If the ire_stq is
	 * non-null ill_ire_count also goes down by 1.
	 *
	 * The ipif that is associated with an ire is ire->ire_ipif and
	 * hence when the ire->ire_ipif->ipif_ire_cnt drops to zero we call
	 * ipif_ill_refrele_tail. Usually stq_ill is null or the same as
	 * ire->ire_ipif->ipif_ill. So nothing more needs to be done. Only
	 * in the case of IRE_CACHES when IPMP is used, stq_ill can be
	 * different. If this is different from ire->ire_ipif->ipif_ill and
	 * if the ill_ire_cnt on the stq_ill also has dropped to zero, we call
	 * ipif_ill_refrele_tail on the stq_ill.
	 */

	if (ire->ire_stq != NULL)
		stq_ill = (ill_t *)ire->ire_stq->q_ptr;

	if (stq_ill == NULL || stq_ill == ill) {
		/* Optimize the most common case */
		mutex_enter(&ill->ill_lock);
		ASSERT(ipif->ipif_ire_cnt != 0);
		DTRACE_PROBE3(ipif__decr__cnt, (ipif_t *), ipif,
		    (char *), "ire", (void *), ire);
		ipif->ipif_ire_cnt--;
		if (IPIF_DOWN_OK(ipif))
			need_wakeup = B_TRUE;
		if (stq_ill != NULL) {
			ASSERT(stq_ill->ill_ire_cnt != 0);
			DTRACE_PROBE3(ill__decr__cnt, (ill_t *), stq_ill,
			    (char *), "ire", (void *), ire);
			stq_ill->ill_ire_cnt--;
			if (ILL_DOWN_OK(stq_ill))
				need_wakeup = B_TRUE;
		}
		if (need_wakeup) {
			/* Drops the ill lock */
			ipif_ill_refrele_tail(ill);
		} else {
			mutex_exit(&ill->ill_lock);
		}
	} else {
		/*
		 * We can't grab all the ill locks at the same time.
		 * It can lead to recursive lock enter in the call to
		 * ipif_ill_refrele_tail and later. Instead do it 1 at
		 * a time.
		 */
		mutex_enter(&ill->ill_lock);
		ASSERT(ipif->ipif_ire_cnt != 0);
		DTRACE_PROBE3(ipif__decr__cnt, (ipif_t *), ipif,
		    (char *), "ire", (void *), ire);
		ipif->ipif_ire_cnt--;
		if (IPIF_DOWN_OK(ipif)) {
			/* Drops the lock */
			ipif_ill_refrele_tail(ill);
		} else {
			mutex_exit(&ill->ill_lock);
		}
		if (stq_ill != NULL) {
			mutex_enter(&stq_ill->ill_lock);
			ASSERT(stq_ill->ill_ire_cnt != 0);
			DTRACE_PROBE3(ill__decr__cnt, (ill_t *), stq_ill,
			    (char *), "ire", (void *), ire);
			stq_ill->ill_ire_cnt--;
			if (ILL_DOWN_OK(stq_ill)) {
				/* Drops the ill lock */
				ipif_ill_refrele_tail(stq_ill);
			} else {
				mutex_exit(&stq_ill->ill_lock);
			}
		}
	}
end:
	/* This should be true for both V4 and V6 */

	if ((ire->ire_type & IRE_FORWARDTABLE) &&
	    (ire->ire_ipversion == IPV4_VERSION) &&
	    ((irb = ire->ire_bucket) != NULL)) {
		rw_enter(&irb->irb_lock, RW_WRITER);
		irb->irb_nire--;
		/*
		 * Instead of examining the conditions for freeing
		 * the radix node here, we do it by calling
		 * IRB_REFRELE which is a single point in the code
		 * that embeds that logic. Bump up the refcnt to
		 * be able to call IRB_REFRELE
		 */
		IRB_REFHOLD_LOCKED(irb);
		rw_exit(&irb->irb_lock);
		IRB_REFRELE(irb);
	}
	ire->ire_ipif = NULL;

#ifdef DEBUG
	ire_trace_cleanup(ire);
#endif
	mutex_destroy(&ire->ire_lock);
	if (ire->ire_ipversion == IPV6_VERSION) {
		BUMP_IRE_STATS(ipst->ips_ire_stats_v6, ire_stats_freed);
	} else {
		BUMP_IRE_STATS(ipst->ips_ire_stats_v4, ire_stats_freed);
	}
	ASSERT(ire->ire_mp == NULL);
	/* Has been allocated out of the cache */
	kmem_cache_free(ire_cache, ire);
}

/*
 * ire_walk routine to delete all IRE_CACHE/IRE_HOST types redirect
 * entries that have a given gateway address.
 */
void
ire_delete_cache_gw(ire_t *ire, char *cp)
{
	ipaddr_t	gw_addr;

	if (!(ire->ire_type & IRE_CACHE) &&
	    !(ire->ire_flags & RTF_DYNAMIC))
		return;

	bcopy(cp, &gw_addr, sizeof (gw_addr));
	if (ire->ire_gateway_addr == gw_addr) {
		ip1dbg(("ire_delete_cache_gw: deleted 0x%x type %d to 0x%x\n",
		    (int)ntohl(ire->ire_addr), ire->ire_type,
		    (int)ntohl(ire->ire_gateway_addr)));
		ire_delete(ire);
	}
}

/*
 * Remove all IRE_CACHE entries that match the ire specified.
 *
 * The flag argument indicates if the flush request is due to addition
 * of new route (IRE_FLUSH_ADD) or deletion of old route (IRE_FLUSH_DELETE).
 *
 * This routine takes only the IREs from the forwarding table and flushes
 * the corresponding entries from the cache table.
 *
 * When flushing due to the deletion of an old route, it
 * just checks the cache handles (ire_phandle and ire_ihandle) and
 * deletes the ones that match.
 *
 * When flushing due to the creation of a new route, it checks
 * if a cache entry's address matches the one in the IRE and
 * that the cache entry's parent has a less specific mask than the
 * one in IRE. The destination of such a cache entry could be the
 * gateway for other cache entries, so we need to flush those as
 * well by looking for gateway addresses matching the IRE's address.
 */
void
ire_flush_cache_v4(ire_t *ire, int flag)
{
	int i;
	ire_t *cire;
	irb_t *irb;
	ip_stack_t	*ipst = ire->ire_ipst;

	if (ire->ire_type & IRE_CACHE)
		return;

	/*
	 * If a default is just created, there is no point
	 * in going through the cache, as there will not be any
	 * cached ires.
	 */
	if (ire->ire_type == IRE_DEFAULT && flag == IRE_FLUSH_ADD)
		return;
	if (flag == IRE_FLUSH_ADD) {
		/*
		 * This selective flush is due to the addition of
		 * new IRE.
		 */
		for (i = 0; i < ipst->ips_ip_cache_table_size; i++) {
			irb = &ipst->ips_ip_cache_table[i];
			if ((cire = irb->irb_ire) == NULL)
				continue;
			IRB_REFHOLD(irb);
			for (cire = irb->irb_ire; cire != NULL;
			    cire = cire->ire_next) {
				if (cire->ire_type != IRE_CACHE)
					continue;
				/*
				 * If 'cire' belongs to the same subnet
				 * as the new ire being added, and 'cire'
				 * is derived from a prefix that is less
				 * specific than the new ire being added,
				 * we need to flush 'cire'; for instance,
				 * when a new interface comes up.
				 */
				if (((cire->ire_addr & ire->ire_mask) ==
				    (ire->ire_addr & ire->ire_mask)) &&
				    (ip_mask_to_plen(cire->ire_cmask) <=
				    ire->ire_masklen)) {
					ire_delete(cire);
					continue;
				}
				/*
				 * This is the case when the ire_gateway_addr
				 * of 'cire' belongs to the same subnet as
				 * the new ire being added.
				 * Flushing such ires is sometimes required to
				 * avoid misrouting: say we have a machine with
				 * two interfaces (I1 and I2), a default router
				 * R on the I1 subnet, and a host route to an
				 * off-link destination D with a gateway G on
				 * the I2 subnet.
				 * Under normal operation, we will have an
				 * on-link cache entry for G and an off-link
				 * cache entry for D with G as ire_gateway_addr,
				 * traffic to D will reach its destination
				 * through gateway G.
				 * If the administrator does 'ifconfig I2 down',
				 * the cache entries for D and G will be
				 * flushed. However, G will now be resolved as
				 * an off-link destination using R (the default
				 * router) as gateway. Then D will also be
				 * resolved as an off-link destination using G
				 * as gateway - this behavior is due to
				 * compatibility reasons, see comment in
				 * ire_ihandle_lookup_offlink(). Traffic to D
				 * will go to the router R and probably won't
				 * reach the destination.
				 * The administrator then does 'ifconfig I2 up'.
				 * Since G is on the I2 subnet, this routine
				 * will flush its cache entry. It must also
				 * flush the cache entry for D, otherwise
				 * traffic will stay misrouted until the IRE
				 * times out.
				 */
				if ((cire->ire_gateway_addr & ire->ire_mask) ==
				    (ire->ire_addr & ire->ire_mask)) {
					ire_delete(cire);
					continue;
				}
			}
			IRB_REFRELE(irb);
		}
	} else {
		/*
		 * delete the cache entries based on
		 * handle in the IRE as this IRE is
		 * being deleted/changed.
		 */
		for (i = 0; i < ipst->ips_ip_cache_table_size; i++) {
			irb = &ipst->ips_ip_cache_table[i];
			if ((cire = irb->irb_ire) == NULL)
				continue;
			IRB_REFHOLD(irb);
			for (cire = irb->irb_ire; cire != NULL;
			    cire = cire->ire_next) {
				if (cire->ire_type != IRE_CACHE)
					continue;
				if ((cire->ire_phandle == 0 ||
				    cire->ire_phandle != ire->ire_phandle) &&
				    (cire->ire_ihandle == 0 ||
				    cire->ire_ihandle != ire->ire_ihandle))
					continue;
				ire_delete(cire);
			}
			IRB_REFRELE(irb);
		}
	}
}

/*
 * Matches the arguments passed with the values in the ire.
 *
 * Note: for match types that match using "ipif" passed in, ipif
 * must be checked for non-NULL before calling this routine.
 */
boolean_t
ire_match_args(ire_t *ire, ipaddr_t addr, ipaddr_t mask, ipaddr_t gateway,
    int type, const ipif_t *ipif, zoneid_t zoneid, uint32_t ihandle,
    const ts_label_t *tsl, int match_flags)
{
	ill_t *ire_ill = NULL, *dst_ill;
	ill_t *ipif_ill = NULL;
	ill_group_t *ire_ill_group = NULL;
	ill_group_t *ipif_ill_group = NULL;

	ASSERT(ire->ire_ipversion == IPV4_VERSION);
	ASSERT((ire->ire_addr & ~ire->ire_mask) == 0);
	ASSERT((!(match_flags & (MATCH_IRE_ILL|MATCH_IRE_ILL_GROUP))) ||
	    (ipif != NULL && !ipif->ipif_isv6));

	/*
	 * HIDDEN cache entries have to be looked up specifically with
	 * MATCH_IRE_MARK_HIDDEN. MATCH_IRE_MARK_HIDDEN is usually set
	 * when the interface is FAILED or INACTIVE. In that case,
	 * any IRE_CACHES that exists should be marked with
	 * IRE_MARK_HIDDEN. So, we don't really need to match below
	 * for IRE_MARK_HIDDEN. But we do so for consistency.
	 */
	if (!(match_flags & MATCH_IRE_MARK_HIDDEN) &&
	    (ire->ire_marks & IRE_MARK_HIDDEN))
		return (B_FALSE);

	/*
	 * MATCH_IRE_MARK_PRIVATE_ADDR is set when IP_NEXTHOP option
	 * is used. In that case the routing table is bypassed and the
	 * packets are sent directly to the specified nexthop. The
	 * IRE_CACHE entry representing this route should be marked
	 * with IRE_MARK_PRIVATE_ADDR.
	 */

	if (!(match_flags & MATCH_IRE_MARK_PRIVATE_ADDR) &&
	    (ire->ire_marks & IRE_MARK_PRIVATE_ADDR))
		return (B_FALSE);

	if (zoneid != ALL_ZONES && zoneid != ire->ire_zoneid &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * If MATCH_IRE_ZONEONLY has been set and the supplied zoneid is
		 * valid and does not match that of ire_zoneid, a failure to
		 * match is reported at this point. Otherwise, since some IREs
		 * that are available in the global zone can be used in local
		 * zones, additional checks need to be performed:
		 *
		 *	IRE_BROADCAST, IRE_CACHE and IRE_LOOPBACK
		 *	entries should never be matched in this situation.
		 *
		 *	IRE entries that have an interface associated with them
		 *	should in general not match unless they are an IRE_LOCAL
		 *	or in the case when MATCH_IRE_DEFAULT has been set in
		 *	the caller.  In the case of the former, checking of the
		 *	other fields supplied should take place.
		 *
		 *	In the case where MATCH_IRE_DEFAULT has been set,
		 *	all of the ipif's associated with the IRE's ill are
		 *	checked to see if there is a matching zoneid.  If any
		 *	one ipif has a matching zoneid, this IRE is a
		 *	potential candidate so checking of the other fields
		 *	takes place.
		 *
		 *	In the case where the IRE_INTERFACE has a usable source
		 *	address (indicated by ill_usesrc_ifindex) in the
		 *	correct zone then it's permitted to return this IRE
		 */
		if (match_flags & MATCH_IRE_ZONEONLY)
			return (B_FALSE);
		if (ire->ire_type & (IRE_BROADCAST | IRE_CACHE | IRE_LOOPBACK))
			return (B_FALSE);
		/*
		 * Note, IRE_INTERFACE can have the stq as NULL. For
		 * example, if the default multicast route is tied to
		 * the loopback address.
		 */
		if ((ire->ire_type & IRE_INTERFACE) &&
		    (ire->ire_stq != NULL)) {
			dst_ill = (ill_t *)ire->ire_stq->q_ptr;
			/*
			 * If there is a usable source address in the
			 * zone, then it's ok to return an
			 * IRE_INTERFACE
			 */
			if (ipif_usesrc_avail(dst_ill, zoneid)) {
				ip3dbg(("ire_match_args: dst_ill %p match %d\n",
				    (void *)dst_ill,
				    (ire->ire_addr == (addr & mask))));
			} else {
				ip3dbg(("ire_match_args: src_ipif NULL"
				    " dst_ill %p\n", (void *)dst_ill));
				return (B_FALSE);
			}
		}
		if (ire->ire_ipif != NULL && ire->ire_type != IRE_LOCAL &&
		    !(ire->ire_type & IRE_INTERFACE)) {
			ipif_t	*tipif;

			if ((match_flags & MATCH_IRE_DEFAULT) == 0) {
				return (B_FALSE);
			}
			mutex_enter(&ire->ire_ipif->ipif_ill->ill_lock);
			for (tipif = ire->ire_ipif->ipif_ill->ill_ipif;
			    tipif != NULL; tipif = tipif->ipif_next) {
				if (IPIF_CAN_LOOKUP(tipif) &&
				    (tipif->ipif_flags & IPIF_UP) &&
				    (tipif->ipif_zoneid == zoneid ||
				    tipif->ipif_zoneid == ALL_ZONES))
					break;
			}
			mutex_exit(&ire->ire_ipif->ipif_ill->ill_lock);
			if (tipif == NULL) {
				return (B_FALSE);
			}
		}
	}

	/*
	 * For IRE_CACHES, MATCH_IRE_ILL/ILL_GROUP really means that
	 * somebody wants to send out on a particular interface which
	 * is given by ire_stq and hence use ire_stq to derive the ill
	 * value. ire_ipif for IRE_CACHES is just the means of getting
	 * a source address i.e ire_src_addr = ire->ire_ipif->ipif_src_addr.
	 * ire_to_ill does the right thing for this.
	 */
	if (match_flags & (MATCH_IRE_ILL|MATCH_IRE_ILL_GROUP)) {
		ire_ill = ire_to_ill(ire);
		if (ire_ill != NULL)
			ire_ill_group = ire_ill->ill_group;
		ipif_ill = ipif->ipif_ill;
		ipif_ill_group = ipif_ill->ill_group;
	}

	if ((ire->ire_addr == (addr & mask)) &&
	    ((!(match_flags & MATCH_IRE_GW)) ||
	    (ire->ire_gateway_addr == gateway)) &&
	    ((!(match_flags & MATCH_IRE_TYPE)) ||
	    (ire->ire_type & type)) &&
	    ((!(match_flags & MATCH_IRE_SRC)) ||
	    (ire->ire_src_addr == ipif->ipif_src_addr)) &&
	    ((!(match_flags & MATCH_IRE_IPIF)) ||
	    (ire->ire_ipif == ipif)) &&
	    ((!(match_flags & MATCH_IRE_MARK_HIDDEN)) ||
	    (ire->ire_type != IRE_CACHE ||
	    ire->ire_marks & IRE_MARK_HIDDEN)) &&
	    ((!(match_flags & MATCH_IRE_MARK_PRIVATE_ADDR)) ||
	    (ire->ire_type != IRE_CACHE ||
	    ire->ire_marks & IRE_MARK_PRIVATE_ADDR)) &&
	    ((!(match_flags & MATCH_IRE_ILL)) ||
	    (ire_ill == ipif_ill)) &&
	    ((!(match_flags & MATCH_IRE_IHANDLE)) ||
	    (ire->ire_ihandle == ihandle)) &&
	    ((!(match_flags & MATCH_IRE_MASK)) ||
	    (ire->ire_mask == mask)) &&
	    ((!(match_flags & MATCH_IRE_ILL_GROUP)) ||
	    (ire_ill == ipif_ill) ||
	    (ire_ill_group != NULL &&
	    ire_ill_group == ipif_ill_group)) &&
	    ((!(match_flags & MATCH_IRE_SECATTR)) ||
	    (!is_system_labeled()) ||
	    (tsol_ire_match_gwattr(ire, tsl) == 0))) {
		/* We found the matched IRE */
		return (B_TRUE);
	}
	return (B_FALSE);
}


/*
 * Lookup for a route in all the tables
 */
ire_t *
ire_route_lookup(ipaddr_t addr, ipaddr_t mask, ipaddr_t gateway,
    int type, const ipif_t *ipif, ire_t **pire, zoneid_t zoneid,
    const ts_label_t *tsl, int flags, ip_stack_t *ipst)
{
	ire_t *ire = NULL;

	/*
	 * ire_match_args() will dereference ipif MATCH_IRE_SRC or
	 * MATCH_IRE_ILL is set.
	 */
	if ((flags & (MATCH_IRE_SRC | MATCH_IRE_ILL | MATCH_IRE_ILL_GROUP)) &&
	    (ipif == NULL))
		return (NULL);

	/*
	 * might be asking for a cache lookup,
	 * This is not best way to lookup cache,
	 * user should call ire_cache_lookup directly.
	 *
	 * If MATCH_IRE_TYPE was set, first lookup in the cache table and then
	 * in the forwarding table, if the applicable type flags were set.
	 */
	if ((flags & MATCH_IRE_TYPE) == 0 || (type & IRE_CACHETABLE) != 0) {
		ire = ire_ctable_lookup(addr, gateway, type, ipif, zoneid,
		    tsl, flags, ipst);
		if (ire != NULL)
			return (ire);
	}
	if ((flags & MATCH_IRE_TYPE) == 0 || (type & IRE_FORWARDTABLE) != 0) {
		ire = ire_ftable_lookup(addr, mask, gateway, type, ipif, pire,
		    zoneid, 0, tsl, flags, ipst);
	}
	return (ire);
}


/*
 * Delete the IRE cache for the gateway and all IRE caches whose
 * ire_gateway_addr points to this gateway, and allow them to
 * be created on demand by ip_newroute.
 */
void
ire_clookup_delete_cache_gw(ipaddr_t addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	irb_t *irb;
	ire_t *ire;

	irb = &ipst->ips_ip_cache_table[IRE_ADDR_HASH(addr,
	    ipst->ips_ip_cache_table_size)];
	IRB_REFHOLD(irb);
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (ire->ire_marks & IRE_MARK_CONDEMNED)
			continue;

		ASSERT(ire->ire_mask == IP_HOST_MASK);
		if (ire_match_args(ire, addr, ire->ire_mask, 0, IRE_CACHE,
		    NULL, zoneid, 0, NULL, MATCH_IRE_TYPE)) {
			ire_delete(ire);
		}
	}
	IRB_REFRELE(irb);

	ire_walk_v4(ire_delete_cache_gw, &addr, zoneid, ipst);
}

/*
 * Looks up cache table for a route.
 * specific lookup can be indicated by
 * passing the MATCH_* flags and the
 * necessary parameters.
 */
ire_t *
ire_ctable_lookup(ipaddr_t addr, ipaddr_t gateway, int type, const ipif_t *ipif,
    zoneid_t zoneid, const ts_label_t *tsl, int flags, ip_stack_t *ipst)
{
	irb_t *irb_ptr;
	ire_t *ire;

	/*
	 * ire_match_args() will dereference ipif MATCH_IRE_SRC or
	 * MATCH_IRE_ILL is set.
	 */
	if ((flags & (MATCH_IRE_SRC | MATCH_IRE_ILL | MATCH_IRE_ILL_GROUP)) &&
	    (ipif == NULL))
		return (NULL);

	irb_ptr = &ipst->ips_ip_cache_table[IRE_ADDR_HASH(addr,
	    ipst->ips_ip_cache_table_size)];
	rw_enter(&irb_ptr->irb_lock, RW_READER);
	for (ire = irb_ptr->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (ire->ire_marks & IRE_MARK_CONDEMNED)
			continue;
		ASSERT(ire->ire_mask == IP_HOST_MASK);
		if (ire_match_args(ire, addr, ire->ire_mask, gateway, type,
		    ipif, zoneid, 0, tsl, flags)) {
			IRE_REFHOLD(ire);
			rw_exit(&irb_ptr->irb_lock);
			return (ire);
		}
	}
	rw_exit(&irb_ptr->irb_lock);
	return (NULL);
}

/*
 * Check whether the IRE_LOCAL and the IRE potentially used to transmit
 * (could be an IRE_CACHE, IRE_BROADCAST, or IRE_INTERFACE) are part of
 * the same ill group.
 */
boolean_t
ire_local_same_ill_group(ire_t *ire_local, ire_t *xmit_ire)
{
	ill_t		*recv_ill, *xmit_ill;
	ill_group_t	*recv_group, *xmit_group;

	ASSERT(ire_local->ire_type & (IRE_LOCAL|IRE_LOOPBACK));
	ASSERT(xmit_ire->ire_type & (IRE_CACHETABLE|IRE_INTERFACE));

	recv_ill = ire_to_ill(ire_local);
	xmit_ill = ire_to_ill(xmit_ire);

	ASSERT(recv_ill != NULL);
	ASSERT(xmit_ill != NULL);

	if (recv_ill == xmit_ill)
		return (B_TRUE);

	recv_group = recv_ill->ill_group;
	xmit_group = xmit_ill->ill_group;

	if (recv_group != NULL && recv_group == xmit_group)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Check if the IRE_LOCAL uses the same ill (group) as another route would use.
 * If there is no alternate route, or the alternate is a REJECT or BLACKHOLE,
 * then we don't allow this IRE_LOCAL to be used.
 */
boolean_t
ire_local_ok_across_zones(ire_t *ire_local, zoneid_t zoneid, void *addr,
    const ts_label_t *tsl, ip_stack_t *ipst)
{
	ire_t		*alt_ire;
	boolean_t	rval;

	if (ire_local->ire_ipversion == IPV4_VERSION) {
		alt_ire = ire_ftable_lookup(*((ipaddr_t *)addr), 0, 0, 0, NULL,
		    NULL, zoneid, 0, tsl,
		    MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
		    MATCH_IRE_RJ_BHOLE, ipst);
	} else {
		alt_ire = ire_ftable_lookup_v6((in6_addr_t *)addr, NULL, NULL,
		    0, NULL, NULL, zoneid, 0, tsl,
		    MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
		    MATCH_IRE_RJ_BHOLE, ipst);
	}

	if (alt_ire == NULL)
		return (B_FALSE);

	if (alt_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire_refrele(alt_ire);
		return (B_FALSE);
	}
	rval = ire_local_same_ill_group(ire_local, alt_ire);

	ire_refrele(alt_ire);
	return (rval);
}

/*
 * Lookup cache. Don't return IRE_MARK_HIDDEN entries. Callers
 * should use ire_ctable_lookup with MATCH_IRE_MARK_HIDDEN to get
 * to the hidden ones.
 *
 * In general the zoneid has to match (where ALL_ZONES match all of them).
 * But for IRE_LOCAL we also need to handle the case where L2 should
 * conceptually loop back the packet. This is necessary since neither
 * Ethernet drivers nor Ethernet hardware loops back packets sent to their
 * own MAC address. This loopback is needed when the normal
 * routes (ignoring IREs with different zoneids) would send out the packet on
 * the same ill (or ill group) as the ill with which this IRE_LOCAL is
 * associated.
 *
 * Earlier versions of this code always matched an IRE_LOCAL independently of
 * the zoneid. We preserve that earlier behavior when
 * ip_restrict_interzone_loopback is turned off.
 */
ire_t *
ire_cache_lookup(ipaddr_t addr, zoneid_t zoneid, const ts_label_t *tsl,
    ip_stack_t *ipst)
{
	irb_t *irb_ptr;
	ire_t *ire;

	irb_ptr = &ipst->ips_ip_cache_table[IRE_ADDR_HASH(addr,
	    ipst->ips_ip_cache_table_size)];
	rw_enter(&irb_ptr->irb_lock, RW_READER);
	for (ire = irb_ptr->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (ire->ire_marks & (IRE_MARK_CONDEMNED |
		    IRE_MARK_HIDDEN | IRE_MARK_PRIVATE_ADDR)) {
			continue;
		}
		if (ire->ire_addr == addr) {
			/*
			 * Finally, check if the security policy has any
			 * restriction on using this route for the specified
			 * message.
			 */
			if (tsl != NULL &&
			    ire->ire_gw_secattr != NULL &&
			    tsol_ire_match_gwattr(ire, tsl) != 0) {
				continue;
			}

			if (zoneid == ALL_ZONES || ire->ire_zoneid == zoneid ||
			    ire->ire_zoneid == ALL_ZONES) {
				IRE_REFHOLD(ire);
				rw_exit(&irb_ptr->irb_lock);
				return (ire);
			}

			if (ire->ire_type == IRE_LOCAL) {
				if (ipst->ips_ip_restrict_interzone_loopback &&
				    !ire_local_ok_across_zones(ire, zoneid,
				    &addr, tsl, ipst))
					continue;

				IRE_REFHOLD(ire);
				rw_exit(&irb_ptr->irb_lock);
				return (ire);
			}
		}
	}
	rw_exit(&irb_ptr->irb_lock);
	return (NULL);
}

/*
 * Locate the interface ire that is tied to the cache ire 'cire' via
 * cire->ire_ihandle.
 *
 * We are trying to create the cache ire for an offlink destn based
 * on the cache ire of the gateway in 'cire'. 'pire' is the prefix ire
 * as found by ip_newroute(). We are called from ip_newroute() in
 * the IRE_CACHE case.
 */
ire_t *
ire_ihandle_lookup_offlink(ire_t *cire, ire_t *pire)
{
	ire_t	*ire;
	int	match_flags;
	ipaddr_t gw_addr;
	ipif_t	*gw_ipif;
	ip_stack_t	*ipst = cire->ire_ipst;

	ASSERT(cire != NULL && pire != NULL);

	/*
	 * We don't need to specify the zoneid to ire_ftable_lookup() below
	 * because the ihandle refers to an ipif which can be in only one zone.
	 */
	match_flags =  MATCH_IRE_TYPE | MATCH_IRE_IHANDLE | MATCH_IRE_MASK;
	/*
	 * ip_newroute calls ire_ftable_lookup with MATCH_IRE_ILL only
	 * for on-link hosts. We should never be here for onlink.
	 * Thus, use MATCH_IRE_ILL_GROUP.
	 */
	if (pire->ire_ipif != NULL)
		match_flags |= MATCH_IRE_ILL_GROUP;
	/*
	 * We know that the mask of the interface ire equals cire->ire_cmask.
	 * (When ip_newroute() created 'cire' for the gateway it set its
	 * cmask from the interface ire's mask)
	 */
	ire = ire_ftable_lookup(cire->ire_addr, cire->ire_cmask, 0,
	    IRE_INTERFACE, pire->ire_ipif, NULL, ALL_ZONES, cire->ire_ihandle,
	    NULL, match_flags, ipst);
	if (ire != NULL)
		return (ire);
	/*
	 * If we didn't find an interface ire above, we can't declare failure.
	 * For backwards compatibility, we need to support prefix routes
	 * pointing to next hop gateways that are not on-link.
	 *
	 * Assume we are trying to ping some offlink destn, and we have the
	 * routing table below.
	 *
	 * Eg.	default	- gw1		<--- pire	(line 1)
	 *	gw1	- gw2				(line 2)
	 *	gw2	- hme0				(line 3)
	 *
	 * If we already have a cache ire for gw1 in 'cire', the
	 * ire_ftable_lookup above would have failed, since there is no
	 * interface ire to reach gw1. We will fallthru below.
	 *
	 * Here we duplicate the steps that ire_ftable_lookup() did in
	 * getting 'cire' from 'pire', in the MATCH_IRE_RECURSIVE case.
	 * The differences are the following
	 * i.   We want the interface ire only, so we call ire_ftable_lookup()
	 *	instead of ire_route_lookup()
	 * ii.  We look for only prefix routes in the 1st call below.
	 * ii.  We want to match on the ihandle in the 2nd call below.
	 */
	match_flags =  MATCH_IRE_TYPE;
	if (pire->ire_ipif != NULL)
		match_flags |= MATCH_IRE_ILL_GROUP;
	ire = ire_ftable_lookup(pire->ire_gateway_addr, 0, 0, IRE_OFFSUBNET,
	    pire->ire_ipif, NULL, ALL_ZONES, 0, NULL, match_flags, ipst);
	if (ire == NULL)
		return (NULL);
	/*
	 * At this point 'ire' corresponds to the entry shown in line 2.
	 * gw_addr is 'gw2' in the example above.
	 */
	gw_addr = ire->ire_gateway_addr;
	gw_ipif = ire->ire_ipif;
	ire_refrele(ire);

	match_flags |= MATCH_IRE_IHANDLE;
	ire = ire_ftable_lookup(gw_addr, 0, 0, IRE_INTERFACE,
	    gw_ipif, NULL, ALL_ZONES, cire->ire_ihandle, NULL, match_flags,
	    ipst);
	return (ire);
}

/*
 * Return the IRE_LOOPBACK, IRE_IF_RESOLVER or IRE_IF_NORESOLVER
 * ire associated with the specified ipif.
 *
 * This might occasionally be called when IPIF_UP is not set since
 * the IP_MULTICAST_IF as well as creating interface routes
 * allows specifying a down ipif (ipif_lookup* match ipifs that are down).
 *
 * Note that if IPIF_NOLOCAL, IPIF_NOXMIT, or IPIF_DEPRECATED is set on
 * the ipif, this routine might return NULL.
 */
ire_t *
ipif_to_ire(const ipif_t *ipif)
{
	ire_t	*ire;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(!ipif->ipif_isv6);
	if (ipif->ipif_ire_type == IRE_LOOPBACK) {
		ire = ire_ctable_lookup(ipif->ipif_lcl_addr, 0, IRE_LOOPBACK,
		    ipif, ALL_ZONES, NULL, (MATCH_IRE_TYPE | MATCH_IRE_IPIF),
		    ipst);
	} else if (ipif->ipif_flags & IPIF_POINTOPOINT) {
		/* In this case we need to lookup destination address. */
		ire = ire_ftable_lookup(ipif->ipif_pp_dst_addr, IP_HOST_MASK, 0,
		    IRE_INTERFACE, ipif, NULL, ALL_ZONES, 0, NULL,
		    (MATCH_IRE_TYPE | MATCH_IRE_IPIF | MATCH_IRE_MASK), ipst);
	} else {
		ire = ire_ftable_lookup(ipif->ipif_subnet,
		    ipif->ipif_net_mask, 0, IRE_INTERFACE, ipif, NULL,
		    ALL_ZONES, 0, NULL, (MATCH_IRE_TYPE | MATCH_IRE_IPIF |
		    MATCH_IRE_MASK), ipst);
	}
	return (ire);
}

/*
 * ire_walk function.
 * Count the number of IRE_CACHE entries in different categories.
 */
void
ire_cache_count(ire_t *ire, char *arg)
{
	ire_cache_count_t *icc = (ire_cache_count_t *)arg;

	if (ire->ire_type != IRE_CACHE)
		return;

	icc->icc_total++;

	if (ire->ire_ipversion == IPV6_VERSION) {
		mutex_enter(&ire->ire_lock);
		if (IN6_IS_ADDR_UNSPECIFIED(&ire->ire_gateway_addr_v6)) {
			mutex_exit(&ire->ire_lock);
			icc->icc_onlink++;
			return;
		}
		mutex_exit(&ire->ire_lock);
	} else {
		if (ire->ire_gateway_addr == 0) {
			icc->icc_onlink++;
			return;
		}
	}

	ASSERT(ire->ire_ipif != NULL);
	if (ire->ire_max_frag < ire->ire_ipif->ipif_mtu)
		icc->icc_pmtu++;
	else if (ire->ire_tire_mark != ire->ire_ob_pkt_count +
	    ire->ire_ib_pkt_count)
		icc->icc_offlink++;
	else
		icc->icc_unused++;
}

/*
 * ire_walk function called by ip_trash_ire_reclaim().
 * Free a fraction of the IRE_CACHE cache entries. The fractions are
 * different for different categories of IRE_CACHE entries.
 * A fraction of zero means to not free any in that category.
 * Use the hash bucket id plus lbolt as a random number. Thus if the fraction
 * is N then every Nth hash bucket chain will be freed.
 */
void
ire_cache_reclaim(ire_t *ire, char *arg)
{
	ire_cache_reclaim_t *icr = (ire_cache_reclaim_t *)arg;
	uint_t rand;
	ip_stack_t	*ipst = icr->icr_ipst;

	if (ire->ire_type != IRE_CACHE)
		return;

	if (ire->ire_ipversion == IPV6_VERSION) {
		rand = (uint_t)lbolt +
		    IRE_ADDR_HASH_V6(ire->ire_addr_v6,
		    ipst->ips_ip6_cache_table_size);
		mutex_enter(&ire->ire_lock);
		if (IN6_IS_ADDR_UNSPECIFIED(&ire->ire_gateway_addr_v6)) {
			mutex_exit(&ire->ire_lock);
			if (icr->icr_onlink != 0 &&
			    (rand/icr->icr_onlink)*icr->icr_onlink == rand) {
				ire_delete(ire);
				return;
			}
			goto done;
		}
		mutex_exit(&ire->ire_lock);
	} else {
		rand = (uint_t)lbolt +
		    IRE_ADDR_HASH(ire->ire_addr, ipst->ips_ip_cache_table_size);
		if (ire->ire_gateway_addr == 0) {
			if (icr->icr_onlink != 0 &&
			    (rand/icr->icr_onlink)*icr->icr_onlink == rand) {
				ire_delete(ire);
				return;
			}
			goto done;
		}
	}
	/* Not onlink IRE */
	ASSERT(ire->ire_ipif != NULL);
	if (ire->ire_max_frag < ire->ire_ipif->ipif_mtu) {
		/* Use ptmu fraction */
		if (icr->icr_pmtu != 0 &&
		    (rand/icr->icr_pmtu)*icr->icr_pmtu == rand) {
			ire_delete(ire);
			return;
		}
	} else if (ire->ire_tire_mark != ire->ire_ob_pkt_count +
	    ire->ire_ib_pkt_count) {
		/* Use offlink fraction */
		if (icr->icr_offlink != 0 &&
		    (rand/icr->icr_offlink)*icr->icr_offlink == rand) {
			ire_delete(ire);
			return;
		}
	} else {
		/* Use unused fraction */
		if (icr->icr_unused != 0 &&
		    (rand/icr->icr_unused)*icr->icr_unused == rand) {
			ire_delete(ire);
			return;
		}
	}
done:
	/*
	 * Update tire_mark so that those that haven't been used since this
	 * reclaim will be considered unused next time we reclaim.
	 */
	ire->ire_tire_mark = ire->ire_ob_pkt_count + ire->ire_ib_pkt_count;
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
	 * Create ire caches, ire_reclaim()
	 * will give IRE_CACHE back to system when needed.
	 * This needs to be done here before anything else, since
	 * ire_add() expects the cache to be created.
	 */
	ire_cache = kmem_cache_create("ire_cache",
	    sizeof (ire_t), 0, ip_ire_constructor,
	    ip_ire_destructor, ip_trash_ire_reclaim, NULL, NULL, 0);

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
	int i;
	uint32_t mem_cnt;
	uint32_t cpu_cnt;
	uint32_t min_cnt;
	pgcnt_t mem_avail;

	/*
	 * ip_ire_max_bucket_cnt is sized below based on the memory
	 * size and the cpu speed of the machine. This is upper
	 * bounded by the compile time value of ip_ire_max_bucket_cnt
	 * and is lower bounded by the compile time value of
	 * ip_ire_min_bucket_cnt.  Similar logic applies to
	 * ip6_ire_max_bucket_cnt.
	 *
	 * We calculate this for each IP Instances in order to use
	 * the kmem_avail and ip_ire_{min,max}_bucket_cnt that are
	 * in effect when the zone is booted.
	 */
	mem_avail = kmem_avail();
	mem_cnt = (mem_avail >> ip_ire_mem_ratio) /
	    ip_cache_table_size / sizeof (ire_t);
	cpu_cnt = CPU->cpu_type_info.pi_clock >> ip_ire_cpu_ratio;

	min_cnt = MIN(cpu_cnt, mem_cnt);
	if (min_cnt < ip_ire_min_bucket_cnt)
		min_cnt = ip_ire_min_bucket_cnt;
	if (ip_ire_max_bucket_cnt > min_cnt) {
		ip_ire_max_bucket_cnt = min_cnt;
	}

	mem_cnt = (mem_avail >> ip_ire_mem_ratio) /
	    ip6_cache_table_size / sizeof (ire_t);
	min_cnt = MIN(cpu_cnt, mem_cnt);
	if (min_cnt < ip6_ire_min_bucket_cnt)
		min_cnt = ip6_ire_min_bucket_cnt;
	if (ip6_ire_max_bucket_cnt > min_cnt) {
		ip6_ire_max_bucket_cnt = min_cnt;
	}

	mutex_init(&ipst->ips_ire_ft_init_lock, NULL, MUTEX_DEFAULT, 0);
	mutex_init(&ipst->ips_ire_handle_lock, NULL, MUTEX_DEFAULT, NULL);

	(void) rn_inithead((void **)&ipst->ips_ip_ftable, 32);


	/* Calculate the IPv4 cache table size. */
	ipst->ips_ip_cache_table_size = MAX(ip_cache_table_size,
	    ((mem_avail >> ip_ire_mem_ratio) / sizeof (ire_t) /
	    ip_ire_max_bucket_cnt));
	if (ipst->ips_ip_cache_table_size > ip_max_cache_table_size)
		ipst->ips_ip_cache_table_size = ip_max_cache_table_size;
	/*
	 * Make sure that the table size is always a power of 2.  The
	 * hash macro IRE_ADDR_HASH() depends on that.
	 */
	power2_roundup(&ipst->ips_ip_cache_table_size);

	ipst->ips_ip_cache_table = kmem_zalloc(ipst->ips_ip_cache_table_size *
	    sizeof (irb_t), KM_SLEEP);

	for (i = 0; i < ipst->ips_ip_cache_table_size; i++) {
		rw_init(&ipst->ips_ip_cache_table[i].irb_lock, NULL,
		    RW_DEFAULT, NULL);
	}

	/* Calculate the IPv6 cache table size. */
	ipst->ips_ip6_cache_table_size = MAX(ip6_cache_table_size,
	    ((mem_avail >> ip_ire_mem_ratio) / sizeof (ire_t) /
	    ip6_ire_max_bucket_cnt));
	if (ipst->ips_ip6_cache_table_size > ip6_max_cache_table_size)
		ipst->ips_ip6_cache_table_size = ip6_max_cache_table_size;
	/*
	 * Make sure that the table size is always a power of 2.  The
	 * hash macro IRE_ADDR_HASH_V6() depends on that.
	 */
	power2_roundup(&ipst->ips_ip6_cache_table_size);

	ipst->ips_ip_cache_table_v6 = kmem_zalloc(
	    ipst->ips_ip6_cache_table_size * sizeof (irb_t), KM_SLEEP);

	for (i = 0; i < ipst->ips_ip6_cache_table_size; i++) {
		rw_init(&ipst->ips_ip_cache_table_v6[i].irb_lock, NULL,
		    RW_DEFAULT, NULL);
	}

	/*
	 * Make sure that the forwarding table size is a power of 2.
	 * The IRE*_ADDR_HASH() macroes depend on that.
	 */
	ipst->ips_ip6_ftable_hash_size = ip6_ftable_hash_size;
	power2_roundup(&ipst->ips_ip6_ftable_hash_size);

	ipst->ips_ire_handle = 1;
}

void
ip_ire_g_fini(void)
{
	kmem_cache_destroy(ire_cache);
	kmem_cache_destroy(rt_entry_cache);

	rn_fini();
}

void
ip_ire_fini(ip_stack_t *ipst)
{
	int i;

	/*
	 * Delete all IREs - assumes that the ill/ipifs have
	 * been removed so what remains are just the ftable and IRE_CACHE.
	 */
	ire_walk(ire_delete, NULL, ipst);

	rn_freehead(ipst->ips_ip_ftable);
	ipst->ips_ip_ftable = NULL;

	mutex_destroy(&ipst->ips_ire_ft_init_lock);
	mutex_destroy(&ipst->ips_ire_handle_lock);

	for (i = 0; i < ipst->ips_ip_cache_table_size; i++) {
		ASSERT(ipst->ips_ip_cache_table[i].irb_ire == NULL);
		rw_destroy(&ipst->ips_ip_cache_table[i].irb_lock);
	}
	kmem_free(ipst->ips_ip_cache_table,
	    ipst->ips_ip_cache_table_size * sizeof (irb_t));
	ipst->ips_ip_cache_table = NULL;

	for (i = 0; i < ipst->ips_ip6_cache_table_size; i++) {
		ASSERT(ipst->ips_ip_cache_table_v6[i].irb_ire == NULL);
		rw_destroy(&ipst->ips_ip_cache_table_v6[i].irb_lock);
	}
	kmem_free(ipst->ips_ip_cache_table_v6,
	    ipst->ips_ip6_cache_table_size * sizeof (irb_t));
	ipst->ips_ip_cache_table_v6 = NULL;

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

/*
 * Check if another multirt route resolution is needed.
 * B_TRUE is returned is there remain a resolvable route,
 * or if no route for that dst is resolved yet.
 * B_FALSE is returned if all routes for that dst are resolved
 * or if the remaining unresolved routes are actually not
 * resolvable.
 * This only works in the global zone.
 */
boolean_t
ire_multirt_need_resolve(ipaddr_t dst, const ts_label_t *tsl, ip_stack_t *ipst)
{
	ire_t	*first_fire;
	ire_t	*first_cire;
	ire_t	*fire;
	ire_t	*cire;
	irb_t	*firb;
	irb_t	*cirb;
	int	unres_cnt = 0;
	boolean_t resolvable = B_FALSE;

	/* Retrieve the first IRE_HOST that matches the destination */
	first_fire = ire_ftable_lookup(dst, IP_HOST_MASK, 0, IRE_HOST, NULL,
	    NULL, ALL_ZONES, 0, tsl,
	    MATCH_IRE_MASK | MATCH_IRE_TYPE | MATCH_IRE_SECATTR, ipst);

	/* No route at all */
	if (first_fire == NULL) {
		return (B_TRUE);
	}

	firb = first_fire->ire_bucket;
	ASSERT(firb != NULL);

	/* Retrieve the first IRE_CACHE ire for that destination. */
	first_cire = ire_cache_lookup(dst, GLOBAL_ZONEID, tsl, ipst);

	/* No resolved route. */
	if (first_cire == NULL) {
		ire_refrele(first_fire);
		return (B_TRUE);
	}

	/*
	 * At least one route is resolved. Here we look through the forward
	 * and cache tables, to compare the number of declared routes
	 * with the number of resolved routes. The search for a resolvable
	 * route is performed only if at least one route remains
	 * unresolved.
	 */
	cirb = first_cire->ire_bucket;
	ASSERT(cirb != NULL);

	/* Count the number of routes to that dest that are declared. */
	IRB_REFHOLD(firb);
	for (fire = first_fire; fire != NULL; fire = fire->ire_next) {
		if (!(fire->ire_flags & RTF_MULTIRT))
			continue;
		if (fire->ire_addr != dst)
			continue;
		unres_cnt++;
	}
	IRB_REFRELE(firb);

	/* Then subtract the number of routes to that dst that are resolved */
	IRB_REFHOLD(cirb);
	for (cire = first_cire; cire != NULL; cire = cire->ire_next) {
		if (!(cire->ire_flags & RTF_MULTIRT))
			continue;
		if (cire->ire_addr != dst)
			continue;
		if (cire->ire_marks & (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN))
			continue;
		unres_cnt--;
	}
	IRB_REFRELE(cirb);

	/* At least one route is unresolved; search for a resolvable route. */
	if (unres_cnt > 0)
		resolvable = ire_multirt_lookup(&first_cire, &first_fire,
		    MULTIRT_USESTAMP | MULTIRT_CACHEGW, tsl, ipst);

	if (first_fire != NULL)
		ire_refrele(first_fire);

	if (first_cire != NULL)
		ire_refrele(first_cire);

	return (resolvable);
}


/*
 * Explore a forward_table bucket, starting from fire_arg.
 * fire_arg MUST be an IRE_HOST entry.
 *
 * Return B_TRUE and update *ire_arg and *fire_arg
 * if at least one resolvable route is found. *ire_arg
 * is the IRE entry for *fire_arg's gateway.
 *
 * Return B_FALSE otherwise (all routes are resolved or
 * the remaining unresolved routes are all unresolvable).
 *
 * The IRE selection relies on a priority mechanism
 * driven by the flags passed in by the caller.
 * The caller, such as ip_newroute_ipif(), can get the most
 * relevant ire at each stage of a multiple route resolution.
 *
 * The rules are:
 *
 * - if MULTIRT_CACHEGW is specified in flags, IRE_CACHETABLE
 *   ires are preferred for the gateway. This gives the highest
 *   priority to routes that can be resolved without using
 *   a resolver.
 *
 * - if MULTIRT_CACHEGW is not specified, or if MULTIRT_CACHEGW
 *   is specified but no IRE_CACHETABLE ire entry for the gateway
 *   is found, the following rules apply.
 *
 * - if MULTIRT_USESTAMP is specified in flags, IRE_INTERFACE
 *   ires for the gateway, that have not been tried since
 *   a configurable amount of time, are preferred.
 *   This applies when a resolver must be invoked for
 *   a missing route, but we don't want to use the resolver
 *   upon each packet emission. If no such resolver is found,
 *   B_FALSE is returned.
 *   The MULTIRT_USESTAMP flag can be combined with
 *   MULTIRT_CACHEGW.
 *
 * - if MULTIRT_USESTAMP is not specified in flags, the first
 *   unresolved but resolvable route is selected.
 *
 * - Otherwise, there is no resolvalble route, and
 *   B_FALSE is returned.
 *
 * At last, MULTIRT_SETSTAMP can be specified in flags to
 * request the timestamp of unresolvable routes to
 * be refreshed. This prevents the useless exploration
 * of those routes for a while, when MULTIRT_USESTAMP is used.
 *
 * This only works in the global zone.
 */
boolean_t
ire_multirt_lookup(ire_t **ire_arg, ire_t **fire_arg, uint32_t flags,
    const ts_label_t *tsl, ip_stack_t *ipst)
{
	clock_t	delta;
	ire_t	*best_fire = NULL;
	ire_t	*best_cire = NULL;
	ire_t	*first_fire;
	ire_t	*first_cire;
	ire_t	*fire;
	ire_t	*cire;
	irb_t	*firb = NULL;
	irb_t	*cirb = NULL;
	ire_t	*gw_ire;
	boolean_t	already_resolved;
	boolean_t	res;
	ipaddr_t	dst;
	ipaddr_t	gw;

	ip2dbg(("ire_multirt_lookup: *ire_arg %p, *fire_arg %p, flags %04x\n",
	    (void *)*ire_arg, (void *)*fire_arg, flags));

	ASSERT(ire_arg != NULL);
	ASSERT(fire_arg != NULL);

	/* Not an IRE_HOST ire; give up. */
	if ((*fire_arg == NULL) || ((*fire_arg)->ire_type != IRE_HOST)) {
		return (B_FALSE);
	}

	/* This is the first IRE_HOST ire for that destination. */
	first_fire = *fire_arg;
	firb = first_fire->ire_bucket;
	ASSERT(firb != NULL);

	dst = first_fire->ire_addr;

	ip2dbg(("ire_multirt_lookup: dst %08x\n", ntohl(dst)));

	/*
	 * Retrieve the first IRE_CACHE ire for that destination;
	 * if we don't find one, no route for that dest is
	 * resolved yet.
	 */
	first_cire = ire_cache_lookup(dst, GLOBAL_ZONEID, tsl, ipst);
	if (first_cire != NULL) {
		cirb = first_cire->ire_bucket;
	}

	ip2dbg(("ire_multirt_lookup: first_cire %p\n", (void *)first_cire));

	/*
	 * Search for a resolvable route, giving the top priority
	 * to routes that can be resolved without any call to the resolver.
	 */
	IRB_REFHOLD(firb);

	if (!CLASSD(dst)) {
		/*
		 * For all multiroute IRE_HOST ires for that destination,
		 * check if the route via the IRE_HOST's gateway is
		 * resolved yet.
		 */
		for (fire = first_fire; fire != NULL; fire = fire->ire_next) {

			if (!(fire->ire_flags & RTF_MULTIRT))
				continue;
			if (fire->ire_addr != dst)
				continue;

			if (fire->ire_gw_secattr != NULL &&
			    tsol_ire_match_gwattr(fire, tsl) != 0) {
				continue;
			}

			gw = fire->ire_gateway_addr;

			ip2dbg(("ire_multirt_lookup: fire %p, "
			    "ire_addr %08x, ire_gateway_addr %08x\n",
			    (void *)fire, ntohl(fire->ire_addr), ntohl(gw)));

			already_resolved = B_FALSE;

			if (first_cire != NULL) {
				ASSERT(cirb != NULL);

				IRB_REFHOLD(cirb);
				/*
				 * For all IRE_CACHE ires for that
				 * destination.
				 */
				for (cire = first_cire;
				    cire != NULL;
				    cire = cire->ire_next) {

					if (!(cire->ire_flags & RTF_MULTIRT))
						continue;
					if (cire->ire_addr != dst)
						continue;
					if (cire->ire_marks &
					    (IRE_MARK_CONDEMNED |
					    IRE_MARK_HIDDEN))
						continue;

					if (cire->ire_gw_secattr != NULL &&
					    tsol_ire_match_gwattr(cire,
					    tsl) != 0) {
						continue;
					}

					/*
					 * Check if the IRE_CACHE's gateway
					 * matches the IRE_HOST's gateway.
					 */
					if (cire->ire_gateway_addr == gw) {
						already_resolved = B_TRUE;
						break;
					}
				}
				IRB_REFRELE(cirb);
			}

			/*
			 * This route is already resolved;
			 * proceed with next one.
			 */
			if (already_resolved) {
				ip2dbg(("ire_multirt_lookup: found cire %p, "
				    "already resolved\n", (void *)cire));
				continue;
			}

			/*
			 * The route is unresolved; is it actually
			 * resolvable, i.e. is there a cache or a resolver
			 * for the gateway?
			 */
			gw_ire = ire_route_lookup(gw, 0, 0, 0, NULL, NULL,
			    ALL_ZONES, tsl,
			    MATCH_IRE_RECURSIVE | MATCH_IRE_SECATTR, ipst);

			ip2dbg(("ire_multirt_lookup: looked up gw_ire %p\n",
			    (void *)gw_ire));

			/*
			 * If gw_ire is typed IRE_CACHETABLE,
			 * this route can be resolved without any call to the
			 * resolver. If the MULTIRT_CACHEGW flag is set,
			 * give the top priority to this ire and exit the
			 * loop.
			 * This is typically the case when an ARP reply
			 * is processed through ip_wput_nondata().
			 */
			if ((flags & MULTIRT_CACHEGW) &&
			    (gw_ire != NULL) &&
			    (gw_ire->ire_type & IRE_CACHETABLE)) {
				ASSERT(gw_ire->ire_nce == NULL ||
				    gw_ire->ire_nce->nce_state == ND_REACHABLE);
				/*
				 * Release the resolver associated to the
				 * previous candidate best ire, if any.
				 */
				if (best_cire != NULL) {
					ire_refrele(best_cire);
					ASSERT(best_fire != NULL);
				}

				best_fire = fire;
				best_cire = gw_ire;

				ip2dbg(("ire_multirt_lookup: found top prio "
				    "best_fire %p, best_cire %p\n",
				    (void *)best_fire, (void *)best_cire));
				break;
			}

			/*
			 * Compute the time elapsed since our preceding
			 * attempt to  resolve that route.
			 * If the MULTIRT_USESTAMP flag is set, we take that
			 * route into account only if this time interval
			 * exceeds ip_multirt_resolution_interval;
			 * this prevents us from attempting to resolve a
			 * broken route upon each sending of a packet.
			 */
			delta = lbolt - fire->ire_last_used_time;
			delta = TICK_TO_MSEC(delta);

			res = (boolean_t)((delta >
			    ipst->ips_ip_multirt_resolution_interval) ||
			    (!(flags & MULTIRT_USESTAMP)));

			ip2dbg(("ire_multirt_lookup: fire %p, delta %lu, "
			    "res %d\n",
			    (void *)fire, delta, res));

			if (res) {
				/*
				 * We are here if MULTIRT_USESTAMP flag is set
				 * and the resolver for fire's gateway
				 * has not been tried since
				 * ip_multirt_resolution_interval, or if
				 * MULTIRT_USESTAMP is not set but gw_ire did
				 * not fill the conditions for MULTIRT_CACHEGW,
				 * or if neither MULTIRT_USESTAMP nor
				 * MULTIRT_CACHEGW are set.
				 */
				if (gw_ire != NULL) {
					if (best_fire == NULL) {
						ASSERT(best_cire == NULL);

						best_fire = fire;
						best_cire = gw_ire;

						ip2dbg(("ire_multirt_lookup:"
						    "found candidate "
						    "best_fire %p, "
						    "best_cire %p\n",
						    (void *)best_fire,
						    (void *)best_cire));

						/*
						 * If MULTIRT_CACHEGW is not
						 * set, we ignore the top
						 * priority ires that can
						 * be resolved without any
						 * call to the resolver;
						 * In that case, there is
						 * actually no need
						 * to continue the loop.
						 */
						if (!(flags &
						    MULTIRT_CACHEGW)) {
							break;
						}
						continue;
					}
				} else {
					/*
					 * No resolver for the gateway: the
					 * route is not resolvable.
					 * If the MULTIRT_SETSTAMP flag is
					 * set, we stamp the IRE_HOST ire,
					 * so we will not select it again
					 * during this resolution interval.
					 */
					if (flags & MULTIRT_SETSTAMP)
						fire->ire_last_used_time =
						    lbolt;
				}
			}

			if (gw_ire != NULL)
				ire_refrele(gw_ire);
		}
	} else { /* CLASSD(dst) */

		for (fire = first_fire;
		    fire != NULL;
		    fire = fire->ire_next) {

			if (!(fire->ire_flags & RTF_MULTIRT))
				continue;
			if (fire->ire_addr != dst)
				continue;

			if (fire->ire_gw_secattr != NULL &&
			    tsol_ire_match_gwattr(fire, tsl) != 0) {
				continue;
			}

			already_resolved = B_FALSE;

			gw = fire->ire_gateway_addr;

			gw_ire = ire_ftable_lookup(gw, 0, 0, IRE_INTERFACE,
			    NULL, NULL, ALL_ZONES, 0, tsl,
			    MATCH_IRE_RECURSIVE | MATCH_IRE_TYPE |
			    MATCH_IRE_SECATTR, ipst);

			/* No resolver for the gateway; we skip this ire. */
			if (gw_ire == NULL) {
				continue;
			}
			ASSERT(gw_ire->ire_nce == NULL ||
			    gw_ire->ire_nce->nce_state == ND_REACHABLE);

			if (first_cire != NULL) {

				IRB_REFHOLD(cirb);
				/*
				 * For all IRE_CACHE ires for that
				 * destination.
				 */
				for (cire = first_cire;
				    cire != NULL;
				    cire = cire->ire_next) {

					if (!(cire->ire_flags & RTF_MULTIRT))
						continue;
					if (cire->ire_addr != dst)
						continue;
					if (cire->ire_marks &
					    (IRE_MARK_CONDEMNED |
					    IRE_MARK_HIDDEN))
						continue;

					if (cire->ire_gw_secattr != NULL &&
					    tsol_ire_match_gwattr(cire,
					    tsl) != 0) {
						continue;
					}

					/*
					 * Cache entries are linked to the
					 * parent routes using the parent handle
					 * (ire_phandle). If no cache entry has
					 * the same handle as fire, fire is
					 * still unresolved.
					 */
					ASSERT(cire->ire_phandle != 0);
					if (cire->ire_phandle ==
					    fire->ire_phandle) {
						already_resolved = B_TRUE;
						break;
					}
				}
				IRB_REFRELE(cirb);
			}

			/*
			 * This route is already resolved; proceed with
			 * next one.
			 */
			if (already_resolved) {
				ire_refrele(gw_ire);
				continue;
			}

			/*
			 * Compute the time elapsed since our preceding
			 * attempt to resolve that route.
			 * If the MULTIRT_USESTAMP flag is set, we take
			 * that route into account only if this time
			 * interval exceeds ip_multirt_resolution_interval;
			 * this prevents us from attempting to resolve a
			 * broken route upon each sending of a packet.
			 */
			delta = lbolt - fire->ire_last_used_time;
			delta = TICK_TO_MSEC(delta);

			res = (boolean_t)((delta >
			    ipst->ips_ip_multirt_resolution_interval) ||
			    (!(flags & MULTIRT_USESTAMP)));

			ip3dbg(("ire_multirt_lookup: fire %p, delta %lx, "
			    "flags %04x, res %d\n",
			    (void *)fire, delta, flags, res));

			if (res) {
				if (best_cire != NULL) {
					/*
					 * Release the resolver associated
					 * to the preceding candidate best
					 * ire, if any.
					 */
					ire_refrele(best_cire);
					ASSERT(best_fire != NULL);
				}
				best_fire = fire;
				best_cire = gw_ire;
				continue;
			}

			ire_refrele(gw_ire);
		}
	}

	if (best_fire != NULL) {
		IRE_REFHOLD(best_fire);
	}
	IRB_REFRELE(firb);

	/* Release the first IRE_CACHE we initially looked up, if any. */
	if (first_cire != NULL)
		ire_refrele(first_cire);

	/* Found a resolvable route. */
	if (best_fire != NULL) {
		ASSERT(best_cire != NULL);

		if (*fire_arg != NULL)
			ire_refrele(*fire_arg);
		if (*ire_arg != NULL)
			ire_refrele(*ire_arg);

		/*
		 * Update the passed-in arguments with the
		 * resolvable multirt route we found.
		 */
		*fire_arg = best_fire;
		*ire_arg = best_cire;

		ip2dbg(("ire_multirt_lookup: returning B_TRUE, "
		    "*fire_arg %p, *ire_arg %p\n",
		    (void *)best_fire, (void *)best_cire));

		return (B_TRUE);
	}

	ASSERT(best_cire == NULL);

	ip2dbg(("ire_multirt_lookup: returning B_FALSE, *fire_arg %p, "
	    "*ire_arg %p\n",
	    (void *)*fire_arg, (void *)*ire_arg));

	/* No resolvable route. */
	return (B_FALSE);
}

/*
 * IRE iterator for inbound and loopback broadcast processing.
 * Given an IRE_BROADCAST ire, walk the ires with the same destination
 * address, but skip over the passed-in ire. Returns the next ire without
 * a hold - assumes that the caller holds a reference on the IRE bucket.
 */
ire_t *
ire_get_next_bcast_ire(ire_t *curr, ire_t *ire)
{
	ill_t *ill;

	if (curr == NULL) {
		for (curr = ire->ire_bucket->irb_ire; curr != NULL;
		    curr = curr->ire_next) {
			if (curr->ire_addr == ire->ire_addr)
				break;
		}
	} else {
		curr = curr->ire_next;
	}
	ill = ire_to_ill(ire);
	for (; curr != NULL; curr = curr->ire_next) {
		if (curr->ire_addr != ire->ire_addr) {
			/*
			 * All the IREs to a given destination are contiguous;
			 * break out once the address doesn't match.
			 */
			break;
		}
		if (curr == ire) {
			/* skip over the passed-in ire */
			continue;
		}
		if ((curr->ire_stq != NULL && ire->ire_stq == NULL) ||
		    (curr->ire_stq == NULL && ire->ire_stq != NULL)) {
			/*
			 * If the passed-in ire is loopback, skip over
			 * non-loopback ires and vice versa.
			 */
			continue;
		}
		if (ire_to_ill(curr) != ill) {
			/* skip over IREs going through a different interface */
			continue;
		}
		if (curr->ire_marks & IRE_MARK_CONDEMNED) {
			/* skip over deleted IREs */
			continue;
		}
		return (curr);
	}
	return (NULL);
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
 * Generate a message chain with an arp request to resolve the in_ire.
 * It is assumed that in_ire itself is currently in the ire cache table,
 * so we create a fake_ire filled with enough information about ire_addr etc.
 * to retrieve in_ire when the DL_UNITDATA response from the resolver
 * comes back. The fake_ire itself is created by calling esballoc with
 * the fr_rtnp (free routine) set to ire_freemblk. This routine will be
 * invoked when the mblk containing fake_ire is freed.
 */
void
ire_arpresolve(ire_t *in_ire, ill_t *dst_ill)
{
	areq_t		*areq;
	ipaddr_t	*addrp;
	mblk_t 		*ire_mp, *areq_mp;
	ire_t 		*ire, *buf;
	size_t		bufsize;
	frtn_t		*frtnp;
	ill_t		*ill;
	ip_stack_t	*ipst = dst_ill->ill_ipst;

	/*
	 * Construct message chain for the resolver
	 * of the form:
	 *	ARP_REQ_MBLK-->IRE_MBLK
	 *
	 * NOTE : If the response does not
	 * come back, ARP frees the packet. For this reason,
	 * we can't REFHOLD the bucket of save_ire to prevent
	 * deletions. We may not be able to REFRELE the bucket
	 * if the response never comes back. Thus, before
	 * adding the ire, ire_add_v4 will make sure that the
	 * interface route does not get deleted. This is the
	 * only case unlike ip_newroute_v6, ip_newroute_ipif_v6
	 * where we can always prevent deletions because of
	 * the synchronous nature of adding IRES i.e
	 * ire_add_then_send is called after creating the IRE.
	 */

	/*
	 * We use esballoc to allocate the second part(the ire_t size mblk)
	 * of the message chain depicted above. THis mblk will be freed
	 * by arp when there is a  timeout, and otherwise passed to IP
	 * and IP will * free it after processing the ARP response.
	 */

	bufsize = sizeof (ire_t) + sizeof (frtn_t);
	buf = kmem_alloc(bufsize, KM_NOSLEEP);
	if (buf == NULL) {
		ip1dbg(("ire_arpresolver:alloc buffer failed\n "));
		return;
	}
	frtnp = (frtn_t *)(buf + 1);
	frtnp->free_arg = (caddr_t)buf;
	frtnp->free_func = ire_freemblk;

	ire_mp = esballoc((unsigned char *)buf, bufsize, BPRI_MED, frtnp);

	if (ire_mp == NULL) {
		ip1dbg(("ire_arpresolve: esballoc failed\n"));
		kmem_free(buf, bufsize);
		return;
	}
	ASSERT(in_ire->ire_nce != NULL);
	areq_mp = copyb(dst_ill->ill_resolver_mp);
	if (areq_mp == NULL) {
		kmem_free(buf, bufsize);
		return;
	}

	ire_mp->b_datap->db_type = IRE_ARPRESOLVE_TYPE;
	ire = (ire_t *)buf;
	/*
	 * keep enough info in the fake ire so that we can pull up
	 * the incomplete ire (in_ire) after result comes back from
	 * arp and make it complete.
	 */
	*ire = ire_null;
	ire->ire_u = in_ire->ire_u;
	ire->ire_ipif_seqid = in_ire->ire_ipif_seqid;
	ire->ire_ipif = in_ire->ire_ipif;
	ire->ire_stq = in_ire->ire_stq;
	ill = ire_to_ill(ire);
	ire->ire_stq_ifindex = ill->ill_phyint->phyint_ifindex;
	ire->ire_zoneid = in_ire->ire_zoneid;
	ire->ire_stackid = ipst->ips_netstack->netstack_stackid;
	ire->ire_ipst = ipst;

	/*
	 * ire_freemblk will be called when ire_mp is freed, both for
	 * successful and failed arp resolution. IRE_MARK_UNCACHED will be set
	 * when the arp resolution failed.
	 */
	ire->ire_marks |= IRE_MARK_UNCACHED;
	ire->ire_mp = ire_mp;
	ire_mp->b_wptr = (uchar_t *)&ire[1];
	ire_mp->b_cont = NULL;
	linkb(areq_mp, ire_mp);

	/*
	 * Fill in the source and dest addrs for the resolver.
	 * NOTE: this depends on memory layouts imposed by
	 * ill_init().
	 */
	areq = (areq_t *)areq_mp->b_rptr;
	addrp = (ipaddr_t *)((char *)areq + areq->areq_sender_addr_offset);
	*addrp = ire->ire_src_addr;

	addrp = (ipaddr_t *)((char *)areq + areq->areq_target_addr_offset);
	if (ire->ire_gateway_addr != INADDR_ANY) {
		*addrp = ire->ire_gateway_addr;
	} else {
		*addrp = ire->ire_addr;
	}

	/* Up to the resolver. */
	if (canputnext(dst_ill->ill_rq)) {
		putnext(dst_ill->ill_rq, areq_mp);
	} else {
		freemsg(areq_mp);
	}
}

/*
 * Esballoc free function for AR_ENTRY_QUERY request to clean up any
 * unresolved ire_t and/or nce_t structures when ARP resolution fails.
 *
 * This function can be called by ARP via free routine for ire_mp or
 * by IPv4(both host and forwarding path) via ire_delete
 * in case ARP resolution fails.
 * NOTE: Since IP is MT, ARP can call into IP but not vice versa
 * (for IP to talk to ARP, it still has to send AR* messages).
 *
 * Note that the ARP/IP merge should replace the functioanlity by providing
 * direct function calls to clean up unresolved entries in ire/nce lists.
 */

void
ire_freemblk(ire_t *ire_mp)
{
	nce_t		*nce = NULL;
	ill_t		*ill;
	ip_stack_t	*ipst;
	netstack_t	*ns = NULL;

	ASSERT(ire_mp != NULL);

	if ((ire_mp->ire_addr == NULL) && (ire_mp->ire_gateway_addr == NULL)) {
		ip1dbg(("ire_freemblk(0x%p) ire_addr is NULL\n",
		    (void *)ire_mp));
		goto cleanup;
	}
	if ((ire_mp->ire_marks & IRE_MARK_UNCACHED) == 0) {
		goto cleanup; /* everything succeeded. just free and return */
	}

	/*
	 * the arp information corresponding to this ire_mp was not
	 * transferred to an ire_cache entry. Need
	 * to clean up incomplete ire's and nce, if necessary.
	 */
	ASSERT(ire_mp->ire_stq != NULL);
	ASSERT(ire_mp->ire_stq_ifindex != 0);
	ASSERT(ire_mp->ire_ipst != NULL);

	ns = netstack_find_by_stackid(ire_mp->ire_stackid);
	ipst = (ns ? ns->netstack_ip : NULL);
	if (ipst == NULL || ipst != ire_mp->ire_ipst) /* Disapeared on us */
		goto  cleanup;

	/*
	 * Get any nce's corresponding to this ire_mp. We first have to
	 * make sure that the ill is still around.
	 */
	ill = ill_lookup_on_ifindex(ire_mp->ire_stq_ifindex,
	    B_FALSE, NULL, NULL, NULL, NULL, ipst);
	if (ill == NULL || (ire_mp->ire_stq != ill->ill_wq) ||
	    (ill->ill_state_flags & ILL_CONDEMNED)) {
		/*
		 * ill went away. no nce to clean up.
		 * Note that the ill_state_flags could be set to
		 * ILL_CONDEMNED after this point, but if we know
		 * that it is CONDEMNED now, we just bail out quickly.
		 */
		if (ill != NULL)
			ill_refrele(ill);
		goto cleanup;
	}
	nce = ndp_lookup_v4(ill,
	    ((ire_mp->ire_gateway_addr != INADDR_ANY) ?
	    &ire_mp->ire_gateway_addr : &ire_mp->ire_addr),
	    B_FALSE);
	ill_refrele(ill);

	if ((nce != NULL) && (nce->nce_state != ND_REACHABLE)) {
		/*
		 * some incomplete nce was found.
		 */
		DTRACE_PROBE2(ire__freemblk__arp__resolv__fail,
		    nce_t *, nce, ire_t *, ire_mp);
		/*
		 * Send the icmp_unreachable messages for the queued mblks in
		 * ire->ire_nce->nce_qd_mp, since ARP resolution failed
		 * for this ire
		 */
		arp_resolv_failed(nce);
		/*
		 * Delete the nce and clean up all ire's pointing at this nce
		 * in the cachetable
		 */
		ndp_delete(nce);
	}
	if (nce != NULL)
		NCE_REFRELE(nce); /* release the ref taken by ndp_lookup_v4 */

cleanup:
	if (ns != NULL)
		netstack_rele(ns);
	/*
	 * Get rid of the ire buffer
	 * We call kmem_free here(instead of ire_delete()), since
	 * this is the freeb's callback.
	 */
	kmem_free(ire_mp, sizeof (ire_t) + sizeof (frtn_t));
}

/*
 * find, or create if needed, a neighbor cache entry nce_t for IRE_CACHE and
 * non-loopback IRE_BROADCAST ire's.
 *
 * If a neighbor-cache entry has to be created (i.e., one does not already
 * exist in the nce list) the nce_res_mp and nce_state of the neighbor cache
 * entry are initialized in ndp_add_v4(). These values are picked from
 * the src_nce, if one is passed in. Otherwise (if src_nce == NULL) the
 * ire->ire_type and the outgoing interface (ire_to_ill(ire)) values
 * determine the {nce_state, nce_res_mp} of the nce_t created. All
 * IRE_BROADCAST entries have nce_state = ND_REACHABLE, and the nce_res_mp
 * is set to the ill_bcast_mp of the outgoing inerface. For unicast ire
 * entries,
 *   - if the outgoing interface is of type IRE_IF_RESOLVER, a newly created
 *     nce_t will have a null nce_res_mp, and will be in the ND_INITIAL state.
 *   - if the outgoing interface is a IRE_IF_NORESOLVER interface, no link
 *     layer resolution is necessary, so that the nce_t will be in the
 *     ND_REACHABLE state and the nce_res_mp will have a copy of the
 *     ill_resolver_mp of the outgoing interface.
 *
 * The link layer information needed for broadcast addresses, and for
 * packets sent on IRE_IF_NORESOLVER interfaces is a constant mapping that
 * never needs re-verification for the lifetime of the nce_t. These are
 * therefore marked NCE_F_PERMANENT, and never allowed to expire via
 * NCE_EXPIRED.
 *
 * IRE_CACHE ire's contain the information for  the nexthop (ire_gateway_addr)
 * in the case of indirect routes, and for the dst itself (ire_addr) in the
 * case of direct routes, with the nce_res_mp containing a template
 * DL_UNITDATA request.
 *
 * The actual association of the ire_nce to the nce created here is
 * typically done in ire_add_v4 for IRE_CACHE entries. Exceptions
 * to this rule are SO_DONTROUTE ire's (IRE_MARK_NO_ADD), for which
 * the ire_nce assignment is done in ire_add_then_send.
 */
int
ire_nce_init(ire_t *ire, nce_t *src_nce)
{
	in_addr_t	addr4;
	int		err;
	nce_t		*nce = NULL;
	ill_t		*ire_ill;
	uint16_t	nce_flags = 0;
	ip_stack_t	*ipst;

	if (ire->ire_stq == NULL)
		return (0); /* no need to create nce for local/loopback */

	switch (ire->ire_type) {
	case IRE_CACHE:
		if (ire->ire_gateway_addr != INADDR_ANY)
			addr4 = ire->ire_gateway_addr; /* 'G' route */
		else
			addr4 = ire->ire_addr; /* direct route */
		break;
	case IRE_BROADCAST:
		addr4 = ire->ire_addr;
		nce_flags |= (NCE_F_PERMANENT|NCE_F_BCAST);
		break;
	default:
		return (0);
	}

	/*
	 * ire_ipif is picked based on RTF_SETSRC, usesrc etc.
	 * rules in ire_forward_src_ipif. We want the dlureq_mp
	 * for the outgoing interface, which we get from the ire_stq.
	 */
	ire_ill = ire_to_ill(ire);
	ipst = ire_ill->ill_ipst;

	/*
	 * IRE_IF_NORESOLVER entries never need re-verification and
	 * do not expire, so we mark them as NCE_F_PERMANENT.
	 */
	if (ire_ill->ill_net_type == IRE_IF_NORESOLVER)
		nce_flags |= NCE_F_PERMANENT;

retry_nce:
	err = ndp_lookup_then_add_v4(ire_ill, &addr4, nce_flags,
	    &nce, src_nce);

	if (err == EEXIST && NCE_EXPIRED(nce, ipst)) {
		/*
		 * We looked up an expired nce.
		 * Go back and try to create one again.
		 */
		ndp_delete(nce);
		NCE_REFRELE(nce);
		nce = NULL;
		goto retry_nce;
	}

	ip1dbg(("ire 0x%p addr 0x%lx type 0x%x; found nce 0x%p err %d\n",
	    (void *)ire, (ulong_t)addr4, ire->ire_type, (void *)nce, err));

	switch (err) {
	case 0:
	case EEXIST:
		/*
		 * return a pointer to a newly created or existing nce_t;
		 * note that the ire-nce mapping is many-one, i.e.,
		 * multiple ire's could point to the same nce_t.
		 */
		break;
	default:
		DTRACE_PROBE2(nce__init__fail, ill_t *, ire_ill, int, err);
		return (EINVAL);
	}
	if (ire->ire_type == IRE_BROADCAST) {
		/*
		 * Two bcast ires are created for each interface;
		 * 1. loopback copy (which does not  have an
		 *    ire_stq, and therefore has no ire_nce), and,
		 * 2. the non-loopback copy, which has the nce_res_mp
		 *    initialized to a copy of the ill_bcast_mp, and
		 *    is marked as ND_REACHABLE at this point.
		 *    This nce does not undergo any further state changes,
		 *    and exists as long as the interface is plumbed.
		 * Note: we do the ire_nce assignment here for IRE_BROADCAST
		 * because some functions like ill_mark_bcast() inline the
		 * ire_add functionality.
		 */
		ire->ire_nce = nce;
		/*
		 * We are associating this nce to the ire,
		 * so change the nce ref taken in
		 * ndp_lookup_then_add_v4() from
		 * NCE_REFHOLD to NCE_REFHOLD_NOTR
		 */
		NCE_REFHOLD_TO_REFHOLD_NOTR(ire->ire_nce);
	} else {
		/*
		 * We are not using this nce_t just yet so release
		 * the ref taken in ndp_lookup_then_add_v4()
		 */
		NCE_REFRELE(nce);
	}
	return (0);
}
