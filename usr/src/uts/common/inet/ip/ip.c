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

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#include <sys/zone.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/xti_inet.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kobj.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/priv.h>
#include <sys/taskq.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/sdt.h>
#include <sys/socket.h>
#include <sys/vtrace.h>
#include <sys/isa_defs.h>
#include <sys/mac.h>
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
#include <inet/optcom.h>
#include <inet/kstatcom.h>

#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/sctp.h>

#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/ip_ndp.h>
#include <inet/ip_listutils.h>
#include <netinet/igmp.h>
#include <netinet/ip_mroute.h>
#include <inet/ipp_common.h>

#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <sys/iphada.h>
#include <inet/tun.h>
#include <inet/ipdrop.h>
#include <inet/ip_netinfo.h>

#include <sys/ethernet.h>
#include <net/if_types.h>
#include <sys/cpuvar.h>

#include <ipp/ipp.h>
#include <ipp/ipp_impl.h>
#include <ipp/ipgpc/ipgpc.h>

#include <sys/multidata.h>
#include <sys/pattr.h>

#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/udp_impl.h>
#include <inet/rawip_impl.h>
#include <inet/rts_impl.h>
#include <sys/sunddi.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#include <rpc/pmap_prot.h>
#include <sys/squeue_impl.h>

/*
 * Values for squeue switch:
 * IP_SQUEUE_ENTER_NODRAIN: SQ_NODRAIN
 * IP_SQUEUE_ENTER: SQ_PROCESS
 * IP_SQUEUE_FILL: SQ_FILL
 */
int ip_squeue_enter = 2;	/* Setable in /etc/system */

int ip_squeue_flag;
#define	SET_BPREV_FLAG(x)	((mblk_t *)(uintptr_t)(x))

/*
 * Setable in /etc/system
 */
int ip_poll_normal_ms = 100;
int ip_poll_normal_ticks = 0;
int ip_modclose_ackwait_ms = 3000;

/*
 * It would be nice to have these present only in DEBUG systems, but the
 * current design of the global symbol checking logic requires them to be
 * unconditionally present.
 */
uint_t ip_thread_data;			/* TSD key for debug support */
krwlock_t ip_thread_rwlock;
list_t	ip_thread_list;

/*
 * Structure to represent a linked list of msgblks. Used by ip_snmp_ functions.
 */

struct listptr_s {
	mblk_t	*lp_head;	/* pointer to the head of the list */
	mblk_t	*lp_tail;	/* pointer to the tail of the list */
};

typedef struct listptr_s listptr_t;

/*
 * This is used by ip_snmp_get_mib2_ip_route_media and
 * ip_snmp_get_mib2_ip6_route_media to carry the lists of return data.
 */
typedef struct iproutedata_s {
	uint_t		ird_idx;
	listptr_t	ird_route;	/* ipRouteEntryTable */
	listptr_t	ird_netmedia;	/* ipNetToMediaEntryTable */
	listptr_t	ird_attrs;	/* ipRouteAttributeTable */
} iproutedata_t;

/*
 * Cluster specific hooks. These should be NULL when booted as a non-cluster
 */

/*
 * Hook functions to enable cluster networking
 * On non-clustered systems these vectors must always be NULL.
 *
 * Hook function to Check ip specified ip address is a shared ip address
 * in the cluster
 *
 */
int (*cl_inet_isclusterwide)(uint8_t protocol,
    sa_family_t addr_family, uint8_t *laddrp) = NULL;

/*
 * Hook function to generate cluster wide ip fragment identifier
 */
uint32_t (*cl_inet_ipident)(uint8_t protocol, sa_family_t addr_family,
    uint8_t *laddrp, uint8_t *faddrp) = NULL;

/*
 * Hook function to generate cluster wide SPI.
 */
void (*cl_inet_getspi)(uint8_t, uint8_t *, size_t) = NULL;

/*
 * Hook function to verify if the SPI is already utlized.
 */

int (*cl_inet_checkspi)(uint8_t, uint32_t) = NULL;

/*
 * Hook function to delete the SPI from the cluster wide repository.
 */

void (*cl_inet_deletespi)(uint8_t, uint32_t) = NULL;

/*
 * Hook function to inform the cluster when packet received on an IDLE SA
 */

void (*cl_inet_idlesa)(uint8_t, uint32_t, sa_family_t, in6_addr_t,
    in6_addr_t) = NULL;

/*
 * Synchronization notes:
 *
 * IP is a fully D_MP STREAMS module/driver. Thus it does not depend on any
 * MT level protection given by STREAMS. IP uses a combination of its own
 * internal serialization mechanism and standard Solaris locking techniques.
 * The internal serialization is per phyint (no IPMP) or per IPMP group.
 * This is used to serialize plumbing operations, IPMP operations, certain
 * multicast operations, most set ioctls, igmp/mld timers etc.
 *
 * Plumbing is a long sequence of operations involving message
 * exchanges between IP, ARP and device drivers. Many set ioctls are typically
 * involved in plumbing operations. A natural model is to serialize these
 * ioctls one per ill. For example plumbing of hme0 and qfe0 can go on in
 * parallel without any interference. But various set ioctls on hme0 are best
 * serialized. However if the system uses IPMP, the operations are easier if
 * they are serialized on a per IPMP group basis since IPMP operations
 * happen across ill's of a group. Thus the lowest common denominator is to
 * serialize most set ioctls, multicast join/leave operations, IPMP operations
 * igmp/mld timer operations, and processing of DLPI control messages received
 * from drivers on a per IPMP group basis. If the system does not employ
 * IPMP the serialization is on a per phyint basis. This serialization is
 * provided by the ipsq_t and primitives operating on this. Details can
 * be found in ip_if.c above the core primitives operating on ipsq_t.
 *
 * Lookups of an ipif or ill by a thread return a refheld ipif / ill.
 * Simiarly lookup of an ire by a thread also returns a refheld ire.
 * In addition ipif's and ill's referenced by the ire are also indirectly
 * refheld. Thus no ipif or ill can vanish nor can critical parameters like
 * the ipif's address or netmask change as long as an ipif is refheld
 * directly or indirectly. For example an SIOCLIFADDR ioctl that changes the
 * address of an ipif has to go through the ipsq_t. This ensures that only
 * 1 such exclusive operation proceeds at any time on the ipif. It then
 * deletes all ires associated with this ipif, and waits for all refcnts
 * associated with this ipif to come down to zero. The address is changed
 * only after the ipif has been quiesced. Then the ipif is brought up again.
 * More details are described above the comment in ip_sioctl_flags.
 *
 * Packet processing is based mostly on IREs and are fully multi-threaded
 * using standard Solaris MT techniques.
 *
 * There are explicit locks in IP to handle:
 * - The ip_g_head list maintained by mi_open_link() and friends.
 *
 * - The reassembly data structures (one lock per hash bucket)
 *
 * - conn_lock is meant to protect conn_t fields. The fields actually
 *   protected by conn_lock are documented in the conn_t definition.
 *
 * - ire_lock to protect some of the fields of the ire, IRE tables
 *   (one lock per hash bucket). Refer to ip_ire.c for details.
 *
 * - ndp_g_lock and nce_lock for protecting NCEs.
 *
 * - ill_lock protects fields of the ill and ipif. Details in ip.h
 *
 * - ill_g_lock: This is a global reader/writer lock. Protects the following
 *	* The AVL tree based global multi list of all ills.
 *	* The linked list of all ipifs of an ill
 *	* The <ill-ipsq> mapping
 *	* The ipsq->ipsq_phyint_list threaded by phyint_ipsq_next
 *	* The illgroup list threaded by ill_group_next.
 *	* <ill-phyint> association
 *   Insertion/deletion of an ill in the system, insertion/deletion of an ipif
 *   into an ill, changing the <ill-ipsq> mapping of an ill, insertion/deletion
 *   of an ill into the illgrp list, changing the <ill-phyint> assoc of an ill
 *   will all have to hold the ill_g_lock as writer for the actual duration
 *   of the insertion/deletion/change. More details about the <ill-ipsq> mapping
 *   may be found in the IPMP section.
 *
 * - ill_lock:  This is a per ill mutex.
 *   It protects some members of the ill and is documented below.
 *   It also protects the <ill-ipsq> mapping
 *   It also protects the illgroup list threaded by ill_group_next.
 *   It also protects the <ill-phyint> assoc.
 *   It also protects the list of ipifs hanging off the ill.
 *
 * - ipsq_lock: This is a per ipsq_t mutex lock.
 *   This protects all the other members of the ipsq struct except
 *   ipsq_refs and ipsq_phyint_list which are protected by ill_g_lock
 *
 * - illgrp_lock: This is a per ill_group mutex lock.
 *   The only thing it protects is the illgrp_ill_schednext member of ill_group
 *   which dictates which is the next ill in an ill_group that is to be chosen
 *   for sending outgoing packets, through creation of an IRE_CACHE that
 *   references this ill.
 *
 * - phyint_lock: This is a per phyint mutex lock. Protects just the
 *   phyint_flags
 *
 * - ip_g_nd_lock: This is a global reader/writer lock.
 *   Any call to nd_load to load a new parameter to the ND table must hold the
 *   lock as writer. ND_GET/ND_SET routines that read the ND table hold the lock
 *   as reader.
 *
 * - ip_addr_avail_lock: This is used to ensure the uniqueness of IP addresses.
 *   This lock is held in ipif_up_done and the ipif is marked IPIF_UP and the
 *   uniqueness check also done atomically.
 *
 * - ipsec_capab_ills_lock: This readers/writer lock protects the global
 *   lists of IPsec capable ills (ipsec_capab_ills_{ah,esp}). It is taken
 *   as a writer when adding or deleting elements from these lists, and
 *   as a reader when walking these lists to send a SADB update to the
 *   IPsec capable ills.
 *
 * - ill_g_usesrc_lock: This readers/writer lock protects the usesrc
 *   group list linked by ill_usesrc_grp_next. It also protects the
 *   ill_usesrc_ifindex field. It is taken as a writer when a member of the
 *   group is being added or deleted.  This lock is taken as a reader when
 *   walking the list/group(eg: to get the number of members in a usesrc group).
 *   Note, it is only necessary to take this lock if the ill_usesrc_grp_next
 *   field is changing state i.e from NULL to non-NULL or vice-versa. For
 *   example, it is not necessary to take this lock in the initial portion
 *   of ip_sioctl_slifusesrc or at all in ip_sioctl_groupname and
 *   ip_sioctl_flags since the these operations are executed exclusively and
 *   that ensures that the "usesrc group state" cannot change. The "usesrc
 *   group state" change can happen only in the latter part of
 *   ip_sioctl_slifusesrc and in ill_delete.
 *
 * Changing <ill-phyint>, <ill-ipsq>, <ill-illgroup> assocications.
 *
 * To change the <ill-phyint> association, the ill_g_lock must be held
 * as writer, and the ill_locks of both the v4 and v6 instance of the ill
 * must be held.
 *
 * To change the <ill-ipsq> association the ill_g_lock must be held as writer
 * and the ill_lock of the ill in question must be held.
 *
 * To change the <ill-illgroup> association the ill_g_lock must be held as
 * writer and the ill_lock of the ill in question must be held.
 *
 * To add or delete an ipif from the list of ipifs hanging off the ill,
 * ill_g_lock (writer) and ill_lock must be held and the thread must be
 * a writer on the associated ipsq,.
 *
 * To add or delete an ill to the system, the ill_g_lock must be held as
 * writer and the thread must be a writer on the associated ipsq.
 *
 * To add or delete an ilm to an ill, the ill_lock must be held and the thread
 * must be a writer on the associated ipsq.
 *
 * Lock hierarchy
 *
 * Some lock hierarchy scenarios are listed below.
 *
 * ill_g_lock -> conn_lock -> ill_lock -> ipsq_lock
 * ill_g_lock -> illgrp_lock -> ill_lock
 * ill_g_lock -> ill_lock(s) -> phyint_lock
 * ill_g_lock -> ndp_g_lock -> ill_lock -> nce_lock
 * ill_g_lock -> ip_addr_avail_lock
 * conn_lock -> irb_lock -> ill_lock -> ire_lock
 * ill_g_lock -> ip_g_nd_lock
 *
 * When more than 1 ill lock is needed to be held, all ill lock addresses
 * are sorted on address and locked starting from highest addressed lock
 * downward.
 *
 * IPsec scenarios
 *
 * ipsa_lock -> ill_g_lock -> ill_lock
 * ipsec_capab_ills_lock -> ill_g_lock -> ill_lock
 * ipsec_capab_ills_lock -> ipsa_lock
 * ill_g_usesrc_lock -> ill_g_lock -> ill_lock
 *
 * Trusted Solaris scenarios
 *
 * igsa_lock -> gcgrp_rwlock -> gcgrp_lock
 * igsa_lock -> gcdb_lock
 * gcgrp_rwlock -> ire_lock
 * gcgrp_rwlock -> gcdb_lock
 *
 * squeue(sq_lock), flow related (ft_lock, fe_lock) locking
 *
 * cpu_lock --> ill_lock --> sqset_lock --> sq_lock
 * sq_lock -> conn_lock -> QLOCK(q)
 * ill_lock -> ft_lock -> fe_lock
 *
 * Routing/forwarding table locking notes:
 *
 * Lock acquisition order: Radix tree lock, irb_lock.
 * Requirements:
 * i.  Walker must not hold any locks during the walker callback.
 * ii  Walker must not see a truncated tree during the walk because of any node
 *     deletion.
 * iii Existing code assumes ire_bucket is valid if it is non-null and is used
 *     in many places in the code to walk the irb list. Thus even if all the
 *     ires in a bucket have been deleted, we still can't free the radix node
 *     until the ires have actually been inactive'd (freed).
 *
 * Tree traversal - Need to hold the global tree lock in read mode.
 * Before dropping the global tree lock, need to either increment the ire_refcnt
 * to ensure that the radix node can't be deleted.
 *
 * Tree add - Need to hold the global tree lock in write mode to add a
 * radix node. To prevent the node from being deleted, increment the
 * irb_refcnt, after the node is added to the tree. The ire itself is
 * added later while holding the irb_lock, but not the tree lock.
 *
 * Tree delete - Need to hold the global tree lock and irb_lock in write mode.
 * All associated ires must be inactive (i.e. freed), and irb_refcnt
 * must be zero.
 *
 * Walker - Increment irb_refcnt before calling the walker callback. Hold the
 * global tree lock (read mode) for traversal.
 *
 * IPsec notes :
 *
 * IP interacts with the IPsec code (AH/ESP) by tagging a M_CTL message
 * in front of the actual packet. For outbound datagrams, the M_CTL
 * contains a ipsec_out_t (defined in ipsec_info.h), which has the
 * information used by the IPsec code for applying the right level of
 * protection. The information initialized by IP in the ipsec_out_t
 * is determined by the per-socket policy or global policy in the system.
 * For inbound datagrams, the M_CTL contains a ipsec_in_t (defined in
 * ipsec_info.h) which starts out with nothing in it. It gets filled
 * with the right information if it goes through the AH/ESP code, which
 * happens if the incoming packet is secure. The information initialized
 * by AH/ESP, is later used by IP(during fanouts to ULP) to see whether
 * the policy requirements needed by per-socket policy or global policy
 * is met or not.
 *
 * If there is both per-socket policy (set using setsockopt) and there
 * is also global policy match for the 5 tuples of the socket,
 * ipsec_override_policy() makes the decision of which one to use.
 *
 * For fully connected sockets i.e dst, src [addr, port] is known,
 * conn_policy_cached is set indicating that policy has been cached.
 * conn_in_enforce_policy may or may not be set depending on whether
 * there is a global policy match or per-socket policy match.
 * Policy inheriting happpens in ip_bind during the ipa_conn_t bind.
 * Once the right policy is set on the conn_t, policy cannot change for
 * this socket. This makes life simpler for TCP (UDP ?) where
 * re-transmissions go out with the same policy. For symmetry, policy
 * is cached for fully connected UDP sockets also. Thus if policy is cached,
 * it also implies that policy is latched i.e policy cannot change
 * on these sockets. As we have the right policy on the conn, we don't
 * have to lookup global policy for every outbound and inbound datagram
 * and thus serving as an optimization. Note that a global policy change
 * does not affect fully connected sockets if they have policy. If fully
 * connected sockets did not have any policy associated with it, global
 * policy change may affect them.
 *
 * IP Flow control notes:
 *
 * Non-TCP streams are flow controlled by IP. On the send side, if the packet
 * cannot be sent down to the driver by IP, because of a canput failure, IP
 * does a putq on the conn_wq. This will cause ip_wsrv to run on the conn_wq.
 * ip_wsrv in turn, inserts the conn in a list of conn's that need to be drained
 * when the flowcontrol condition subsides. Ultimately STREAMS backenables the
 * ip_wsrv on the IP module, which in turn does a qenable of the conn_wq of the
 * first conn in the list of conn's to be drained. ip_wsrv on this conn drains
 * the queued messages, and removes the conn from the drain list, if all
 * messages were drained. It also qenables the next conn in the drain list to
 * continue the drain process.
 *
 * In reality the drain list is not a single list, but a configurable number
 * of lists. The ip_wsrv on the IP module, qenables the first conn in each
 * list. If the ip_wsrv of the next qenabled conn does not run, because the
 * stream closes, ip_close takes responsibility to qenable the next conn in
 * the drain list. The directly called ip_wput path always does a putq, if
 * it cannot putnext. Thus synchronization problems are handled between
 * ip_wsrv and ip_close. conn_drain_insert and conn_drain_tail are the only
 * functions that manipulate this drain list. Furthermore conn_drain_insert
 * is called only from ip_wsrv, and there can be only 1 instance of ip_wsrv
 * running on a queue at any time. conn_drain_tail can be simultaneously called
 * from both ip_wsrv and ip_close.
 *
 * IPQOS notes:
 *
 * IPQoS Policies are applied to packets using IPPF (IP Policy framework)
 * and IPQoS modules. IPPF includes hooks in IP at different control points
 * (callout positions) which direct packets to IPQoS modules for policy
 * processing. Policies, if present, are global.
 *
 * The callout positions are located in the following paths:
 *		o local_in (packets destined for this host)
 *		o local_out (packets orginating from this host )
 *		o fwd_in  (packets forwarded by this m/c - inbound)
 *		o fwd_out (packets forwarded by this m/c - outbound)
 * Hooks at these callout points can be enabled/disabled using the ndd variable
 * ip_policy_mask (a bit mask with the 4 LSB indicating the callout positions).
 * By default all the callout positions are enabled.
 *
 * Outbound (local_out)
 * Hooks are placed in ip_wput_ire and ipsec_out_process.
 *
 * Inbound (local_in)
 * Hooks are placed in ip_proto_input, icmp_inbound, ip_fanout_proto and
 * TCP and UDP fanout routines.
 *
 * Forwarding (in and out)
 * Hooks are placed in ip_rput_forward.
 *
 * IP Policy Framework processing (IPPF processing)
 * Policy processing for a packet is initiated by ip_process, which ascertains
 * that the classifier (ipgpc) is loaded and configured, failing which the
 * packet resumes normal processing in IP. If the clasifier is present, the
 * packet is acted upon by one or more IPQoS modules (action instances), per
 * filters configured in ipgpc and resumes normal IP processing thereafter.
 * An action instance can drop a packet in course of its processing.
 *
 * A boolean variable, ip_policy, is used in all the fanout routines that can
 * invoke ip_process for a packet. This variable indicates if the packet should
 * to be sent for policy processing. The variable is set to B_TRUE by default,
 * i.e. when the routines are invoked in the normal ip procesing path for a
 * packet. The two exceptions being ip_wput_local and icmp_inbound_error_fanout;
 * ip_policy is set to B_FALSE for all the routines called in these two
 * functions because, in the former case,  we don't process loopback traffic
 * currently while in the latter, the packets have already been processed in
 * icmp_inbound.
 *
 * Zones notes:
 *
 * The partitioning rules for networking are as follows:
 * 1) Packets coming from a zone must have a source address belonging to that
 * zone.
 * 2) Packets coming from a zone can only be sent on a physical interface on
 * which the zone has an IP address.
 * 3) Between two zones on the same machine, packet delivery is only allowed if
 * there's a matching route for the destination and zone in the forwarding
 * table.
 * 4) The TCP and UDP port spaces are per-zone; that is, two processes in
 * different zones can bind to the same port with the wildcard address
 * (INADDR_ANY).
 *
 * The granularity of interface partitioning is at the logical interface level.
 * Therefore, every zone has its own IP addresses, and incoming packets can be
 * attributed to a zone unambiguously. A logical interface is placed into a zone
 * using the SIOCSLIFZONE ioctl; this sets the ipif_zoneid field in the ipif_t
 * structure. Rule (1) is implemented by modifying the source address selection
 * algorithm so that the list of eligible addresses is filtered based on the
 * sending process zone.
 *
 * The Internet Routing Entries (IREs) are either exclusive to a zone or shared
 * across all zones, depending on their type. Here is the break-up:
 *
 * IRE type				Shared/exclusive
 * --------				----------------
 * IRE_BROADCAST			Exclusive
 * IRE_DEFAULT (default routes)		Shared (*)
 * IRE_LOCAL				Exclusive (x)
 * IRE_LOOPBACK				Exclusive
 * IRE_PREFIX (net routes)		Shared (*)
 * IRE_CACHE				Exclusive
 * IRE_IF_NORESOLVER (interface routes)	Exclusive
 * IRE_IF_RESOLVER (interface routes)	Exclusive
 * IRE_HOST (host routes)		Shared (*)
 *
 * (*) A zone can only use a default or off-subnet route if the gateway is
 * directly reachable from the zone, that is, if the gateway's address matches
 * one of the zone's logical interfaces.
 *
 * (x) IRE_LOCAL are handled a bit differently, since for all other entries
 * in ire_ctable and IRE_INTERFACE, ire_src_addr is what can be used as source
 * when sending packets using the IRE. For IRE_LOCAL ire_src_addr is the IP
 * address of the zone itself (the destination). Since IRE_LOCAL is used
 * for communication between zones, ip_wput_ire has special logic to set
 * the right source address when sending using an IRE_LOCAL.
 *
 * Furthermore, when ip_restrict_interzone_loopback is set (the default),
 * ire_cache_lookup restricts loopback using an IRE_LOCAL
 * between zone to the case when L2 would have conceptually looped the packet
 * back, i.e. the loopback which is required since neither Ethernet drivers
 * nor Ethernet hardware loops them back. This is the case when the normal
 * routes (ignoring IREs with different zoneids) would send out the packet on
 * the same ill (or ill group) as the ill with which is IRE_LOCAL is
 * associated.
 *
 * Multiple zones can share a common broadcast address; typically all zones
 * share the 255.255.255.255 address. Incoming as well as locally originated
 * broadcast packets must be dispatched to all the zones on the broadcast
 * network. For directed broadcasts (e.g. 10.16.72.255) this is not trivial
 * since some zones may not be on the 10.16.72/24 network. To handle this, each
 * zone has its own set of IRE_BROADCAST entries; then, broadcast packets are
 * sent to every zone that has an IRE_BROADCAST entry for the destination
 * address on the input ill, see conn_wantpacket().
 *
 * Applications in different zones can join the same multicast group address.
 * For IPv4, group memberships are per-logical interface, so they're already
 * inherently part of a zone. For IPv6, group memberships are per-physical
 * interface, so we distinguish IPv6 group memberships based on group address,
 * interface and zoneid. In both cases, received multicast packets are sent to
 * every zone for which a group membership entry exists. On IPv6 we need to
 * check that the target zone still has an address on the receiving physical
 * interface; it could have been removed since the application issued the
 * IPV6_JOIN_GROUP.
 */

/*
 * Squeue Fanout flags:
 *	0: No fanout.
 *	1: Fanout across all squeues
 */
boolean_t	ip_squeue_fanout = 0;

/*
 * Maximum dups allowed per packet.
 */
uint_t ip_max_frag_dups = 10;

#define	IS_SIMPLE_IPH(ipha)						\
	((ipha)->ipha_version_and_hdr_length == IP_SIMPLE_HDR_VERSION)

/* RFC1122 Conformance */
#define	IP_FORWARD_DEFAULT	IP_FORWARD_NEVER

#define	ILL_MAX_NAMELEN			LIFNAMSIZ

static int	conn_set_held_ipif(conn_t *, ipif_t **, ipif_t *);

static int	ip_open(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp, boolean_t isv6);
static mblk_t	*ip_wput_attach_llhdr(mblk_t *, ire_t *, ip_proc_t, uint32_t,
		    ipha_t **);

static void	icmp_frag_needed(queue_t *, mblk_t *, int, zoneid_t,
		    ip_stack_t *);
static void	icmp_inbound(queue_t *, mblk_t *, boolean_t, ill_t *, int,
		    uint32_t, boolean_t, boolean_t, ill_t *, zoneid_t);
static ipaddr_t	icmp_get_nexthop_addr(ipha_t *, ill_t *, zoneid_t, mblk_t *mp);
static boolean_t icmp_inbound_too_big(icmph_t *, ipha_t *, ill_t *, zoneid_t,
		    mblk_t *, int, ip_stack_t *);
static void	icmp_inbound_error_fanout(queue_t *, ill_t *, mblk_t *,
		    icmph_t *, ipha_t *, int, int, boolean_t, boolean_t,
		    ill_t *, zoneid_t);
static void	icmp_options_update(ipha_t *);
static void	icmp_param_problem(queue_t *, mblk_t *, uint8_t, zoneid_t,
		    ip_stack_t *);
static void	icmp_pkt(queue_t *, mblk_t *, void *, size_t, boolean_t,
		    zoneid_t zoneid, ip_stack_t *);
static mblk_t	*icmp_pkt_err_ok(mblk_t *, ip_stack_t *);
static void	icmp_redirect(ill_t *, mblk_t *);
static void	icmp_send_redirect(queue_t *, mblk_t *, ipaddr_t,
		    ip_stack_t *);

static void	ip_arp_news(queue_t *, mblk_t *);
static boolean_t ip_bind_insert_ire(mblk_t *, ire_t *, iulp_t *,
		    ip_stack_t *);
mblk_t		*ip_dlpi_alloc(size_t, t_uscalar_t);
char		*ip_dot_addr(ipaddr_t, char *);
mblk_t		*ip_carve_mp(mblk_t **, ssize_t);
int		ip_close(queue_t *, int);
static char	*ip_dot_saddr(uchar_t *, char *);
static void	ip_fanout_proto(queue_t *, mblk_t *, ill_t *, ipha_t *, uint_t,
		    boolean_t, boolean_t, ill_t *, zoneid_t);
static void	ip_fanout_tcp(queue_t *, mblk_t *, ill_t *, ipha_t *, uint_t,
		    boolean_t, boolean_t, zoneid_t);
static void	ip_fanout_udp(queue_t *, mblk_t *, ill_t *, ipha_t *, uint32_t,
		    boolean_t, uint_t, boolean_t, boolean_t, ill_t *, zoneid_t);
static void	ip_lrput(queue_t *, mblk_t *);
ipaddr_t	ip_net_mask(ipaddr_t);
void		ip_newroute(queue_t *, mblk_t *, ipaddr_t, conn_t *, zoneid_t,
		    ip_stack_t *);
static void	ip_newroute_ipif(queue_t *, mblk_t *, ipif_t *, ipaddr_t,
		    conn_t *, uint32_t, zoneid_t, ip_opt_info_t *);
char		*ip_nv_lookup(nv_t *, int);
static boolean_t	ip_check_for_ipsec_opt(queue_t *, mblk_t *);
static int	ip_param_get(queue_t *, mblk_t *, caddr_t, cred_t *);
static int	ip_param_generic_get(queue_t *, mblk_t *, caddr_t, cred_t *);
static boolean_t	ip_param_register(IDP *ndp, ipparam_t *, size_t,
    ipndp_t *, size_t);
static int	ip_param_set(queue_t *, mblk_t *, char *, caddr_t, cred_t *);
void	ip_rput(queue_t *, mblk_t *);
static void	ip_rput_dlpi_writer(ipsq_t *dummy_sq, queue_t *q, mblk_t *mp,
		    void *dummy_arg);
void	ip_rput_forward(ire_t *, ipha_t *, mblk_t *, ill_t *);
static int	ip_rput_forward_options(mblk_t *, ipha_t *, ire_t *,
    ip_stack_t *);
static boolean_t	ip_rput_local_options(queue_t *, mblk_t *, ipha_t *,
			    ire_t *, ip_stack_t *);
static boolean_t	ip_rput_multimblk_ipoptions(queue_t *, ill_t *,
			    mblk_t *, ipha_t **, ipaddr_t *, ip_stack_t *);
static int	ip_rput_options(queue_t *, mblk_t *, ipha_t *, ipaddr_t *,
    ip_stack_t *);
static boolean_t ip_rput_fragment(queue_t *, mblk_t **, ipha_t *, uint32_t *,
		    uint16_t *);
int		ip_snmp_get(queue_t *, mblk_t *, int);
static mblk_t	*ip_snmp_get_mib2_ip(queue_t *, mblk_t *,
		    mib2_ipIfStatsEntry_t *, ip_stack_t *);
static mblk_t	*ip_snmp_get_mib2_ip_traffic_stats(queue_t *, mblk_t *,
		    ip_stack_t *);
static mblk_t	*ip_snmp_get_mib2_ip6(queue_t *, mblk_t *, ip_stack_t *);
static mblk_t	*ip_snmp_get_mib2_icmp(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_icmp6(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_igmp(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_multi(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip_addr(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip6_addr(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip_group_src(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip6_group_src(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip_group_mem(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip6_group_mem(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_virt_multi(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_multi_rtable(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip_route_media(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip6_route_media(queue_t *, mblk_t *,
		    ip_stack_t *ipst);
static void	ip_snmp_get2_v4(ire_t *, iproutedata_t *);
static void	ip_snmp_get2_v6_route(ire_t *, iproutedata_t *);
static int	ip_snmp_get2_v6_media(nce_t *, iproutedata_t *);
int		ip_snmp_set(queue_t *, int, int, uchar_t *, int);
static boolean_t	ip_source_routed(ipha_t *, ip_stack_t *);
static boolean_t	ip_source_route_included(ipha_t *);
static void	ip_trash_ire_reclaim_stack(ip_stack_t *);

static void	ip_wput_frag(ire_t *, mblk_t *, ip_pkt_t, uint32_t, uint32_t,
		    zoneid_t, ip_stack_t *, conn_t *);
static mblk_t	*ip_wput_frag_copyhdr(uchar_t *, int, int, ip_stack_t *);
static void	ip_wput_local_options(ipha_t *, ip_stack_t *);
static int	ip_wput_options(queue_t *, mblk_t *, ipha_t *, boolean_t,
		    zoneid_t, ip_stack_t *);

static void	conn_drain_init(ip_stack_t *);
static void	conn_drain_fini(ip_stack_t *);
static void	conn_drain_tail(conn_t *connp, boolean_t closing);

static void	conn_walk_drain(ip_stack_t *);
static void	conn_walk_fanout_table(connf_t *, uint_t, pfv_t, void *,
    zoneid_t);

static void	*ip_stack_init(netstackid_t stackid, netstack_t *ns);
static void	ip_stack_shutdown(netstackid_t stackid, void *arg);
static void	ip_stack_fini(netstackid_t stackid, void *arg);

static boolean_t	conn_wantpacket(conn_t *, ill_t *, ipha_t *, int,
    zoneid_t);
static void	ip_arp_done(ipsq_t *dummy_sq, queue_t *q, mblk_t *mp,
    void *dummy_arg);

static int	ip_forward_set(queue_t *, mblk_t *, char *, caddr_t, cred_t *);

static int	ip_multirt_apply_membership(int (*fn)(conn_t *, boolean_t,
    ipaddr_t, ipaddr_t, uint_t *, mcast_record_t, ipaddr_t, mblk_t *), ire_t *,
    conn_t *, boolean_t, ipaddr_t, mcast_record_t, ipaddr_t, mblk_t *);
static void	ip_multirt_bad_mtu(ire_t *, uint32_t);

static int	ip_cgtp_filter_get(queue_t *, mblk_t *, caddr_t, cred_t *);
static int	ip_cgtp_filter_set(queue_t *, mblk_t *, char *,
    caddr_t, cred_t *);
static int	ip_input_proc_set(queue_t *q, mblk_t *mp, char *value,
    caddr_t cp, cred_t *cr);
static int	ip_int_set(queue_t *, mblk_t *, char *, caddr_t,
    cred_t *);
static int	ipmp_hook_emulation_set(queue_t *, mblk_t *, char *, caddr_t,
    cred_t *);
static int	ip_squeue_switch(int);

static void	*ip_kstat_init(netstackid_t, ip_stack_t *);
static void	ip_kstat_fini(netstackid_t, kstat_t *);
static int	ip_kstat_update(kstat_t *kp, int rw);
static void	*icmp_kstat_init(netstackid_t);
static void	icmp_kstat_fini(netstackid_t, kstat_t *);
static int	icmp_kstat_update(kstat_t *kp, int rw);
static void	*ip_kstat2_init(netstackid_t, ip_stat_t *);
static void	ip_kstat2_fini(netstackid_t, kstat_t *);

static int	ip_conn_report(queue_t *, mblk_t *, caddr_t, cred_t *);

static mblk_t	*ip_tcp_input(mblk_t *, ipha_t *, ill_t *, boolean_t,
    ire_t *, mblk_t *, uint_t, queue_t *, ill_rx_ring_t *);

static void	ip_rput_process_forward(queue_t *, mblk_t *, ire_t *,
    ipha_t *, ill_t *, boolean_t, boolean_t);

static void ipobs_init(ip_stack_t *);
static void ipobs_fini(ip_stack_t *);
ipaddr_t	ip_g_all_ones = IP_HOST_MASK;

/* How long, in seconds, we allow frags to hang around. */
#define	IP_FRAG_TIMEOUT	15

/*
 * Threshold which determines whether MDT should be used when
 * generating IP fragments; payload size must be greater than
 * this threshold for MDT to take place.
 */
#define	IP_WPUT_FRAG_MDT_MIN	32768

/* Setable in /etc/system only */
int	ip_wput_frag_mdt_min = IP_WPUT_FRAG_MDT_MIN;

static long ip_rput_pullups;
int	dohwcksum = 1;	/* use h/w cksum if supported by the hardware */

vmem_t *ip_minor_arena_sa; /* for minor nos. from INET_MIN_DEV+2 thru 2^^18-1 */
vmem_t *ip_minor_arena_la; /* for minor nos. from 2^^18 thru 2^^32-1 */

int	ip_debug;

#ifdef DEBUG
uint32_t ipsechw_debug = 0;
#endif

/*
 * Multirouting/CGTP stuff
 */
int	ip_cgtp_filter_rev = CGTP_FILTER_REV;	/* CGTP hooks version */

/*
 * XXX following really should only be in a header. Would need more
 * header and .c clean up first.
 */
extern optdb_obj_t	ip_opt_obj;

ulong_t ip_squeue_enter_unbound = 0;

/*
 * Named Dispatch Parameter Table.
 * All of these are alterable, within the min/max values given, at run time.
 */
static ipparam_t	lcl_param_arr[] = {
	/* min	max	value	name */
	{  0,	1,	0,	"ip_respond_to_address_mask_broadcast"},
	{  0,	1,	1,	"ip_respond_to_echo_broadcast"},
	{  0,	1,	1,	"ip_respond_to_echo_multicast"},
	{  0,	1,	0,	"ip_respond_to_timestamp"},
	{  0,	1,	0,	"ip_respond_to_timestamp_broadcast"},
	{  0,	1,	1,	"ip_send_redirects"},
	{  0,	1,	0,	"ip_forward_directed_broadcasts"},
	{  0,	10,	0,	"ip_mrtdebug"},
	{  5000, 999999999,	60000, "ip_ire_timer_interval" },
	{  60000, 999999999,	1200000, "ip_ire_arp_interval" },
	{  60000, 999999999,	60000, "ip_ire_redirect_interval" },
	{  1,	255,	255,	"ip_def_ttl" },
	{  0,	1,	0,	"ip_forward_src_routed"},
	{  0,	256,	32,	"ip_wroff_extra" },
	{  5000, 999999999, 600000, "ip_ire_pathmtu_interval" },
	{  8,	65536,  64,	"ip_icmp_return_data_bytes" },
	{  0,	1,	1,	"ip_path_mtu_discovery" },
	{  0,	240,	30,	"ip_ignore_delete_time" },
	{  0,	1,	0,	"ip_ignore_redirect" },
	{  0,	1,	1,	"ip_output_queue" },
	{  1,	254,	1,	"ip_broadcast_ttl" },
	{  0,	99999,	100,	"ip_icmp_err_interval" },
	{  1,	99999,	10,	"ip_icmp_err_burst" },
	{  0,	999999999,	1000000, "ip_reass_queue_bytes" },
	{  0,	1,	0,	"ip_strict_dst_multihoming" },
	{  1,	MAX_ADDRS_PER_IF,	256,	"ip_addrs_per_if"},
	{  0,	1,	0,	"ipsec_override_persocket_policy" },
	{  0,	1,	1,	"icmp_accept_clear_messages" },
	{  0,	1,	1,	"igmp_accept_clear_messages" },
	{  2,	999999999, ND_DELAY_FIRST_PROBE_TIME,
				"ip_ndp_delay_first_probe_time"},
	{  1,	999999999, ND_MAX_UNICAST_SOLICIT,
				"ip_ndp_max_unicast_solicit"},
	{  1,	255,	IPV6_MAX_HOPS,	"ip6_def_hops" },
	{  8,	IPV6_MIN_MTU,	IPV6_MIN_MTU, "ip6_icmp_return_data_bytes" },
	{  0,	1,	0,	"ip6_forward_src_routed"},
	{  0,	1,	1,	"ip6_respond_to_echo_multicast"},
	{  0,	1,	1,	"ip6_send_redirects"},
	{  0,	1,	0,	"ip6_ignore_redirect" },
	{  0,	1,	0,	"ip6_strict_dst_multihoming" },

	{  1,	8,	3,	"ip_ire_reclaim_fraction" },

	{  0,	999999,	1000,	"ipsec_policy_log_interval" },

	{  0,	1,	1,	"pim_accept_clear_messages" },
	{  1000, 20000,	2000,	"ip_ndp_unsolicit_interval" },
	{  1,	20,	3,	"ip_ndp_unsolicit_count" },
	{  0,	1,	1,	"ip6_ignore_home_address_opt" },
	{  0,	15,	0,	"ip_policy_mask" },
	{  1000, 60000, 1000,	"ip_multirt_resolution_interval" },
	{  0,	255,	1,	"ip_multirt_ttl" },
	{  0,	1,	1,	"ip_multidata_outbound" },
	{  0,	3600000, 300000, "ip_ndp_defense_interval" },
	{  0,	999999,	60*60*24, "ip_max_temp_idle" },
	{  0,	1000,	1,	"ip_max_temp_defend" },
	{  0,	1000,	3,	"ip_max_defend" },
	{  0,	999999,	30,	"ip_defend_interval" },
	{  0,	3600000, 300000, "ip_dup_recovery" },
	{  0,	1,	1,	"ip_restrict_interzone_loopback" },
	{  0,	1,	1,	"ip_lso_outbound" },
	{  IGMP_V1_ROUTER, IGMP_V3_ROUTER, IGMP_V3_ROUTER, "igmp_max_version" },
	{  MLD_V1_ROUTER, MLD_V2_ROUTER, MLD_V2_ROUTER, "mld_max_version" },
	{ 68,	65535,	576,	"ip_pmtu_min" },
#ifdef DEBUG
	{  0,	1,	0,	"ip6_drop_inbound_icmpv6" },
#else
	{  0,	0,	0,	"" },
#endif
};

/*
 * Extended NDP table
 * The addresses for the first two are filled in to be ips_ip_g_forward
 * and ips_ipv6_forward at init time.
 */
static ipndp_t	lcl_ndp_arr[] = {
	/* getf			setf		data			name */
#define	IPNDP_IP_FORWARDING_OFFSET	0
	{  ip_param_generic_get,	ip_forward_set,	NULL,
	    "ip_forwarding" },
#define	IPNDP_IP6_FORWARDING_OFFSET	1
	{  ip_param_generic_get,	ip_forward_set,	NULL,
	    "ip6_forwarding" },
	{  ip_ill_report,	NULL,		NULL,
	    "ip_ill_status" },
	{  ip_ipif_report,	NULL,		NULL,
	    "ip_ipif_status" },
	{  ip_conn_report,	NULL,		NULL,
	    "ip_conn_status" },
	{  nd_get_long,		nd_set_long,	(caddr_t)&ip_rput_pullups,
	    "ip_rput_pullups" },
	{  ip_srcid_report,	NULL,		NULL,
	    "ip_srcid_status" },
	{ ip_param_generic_get, ip_input_proc_set,
	    (caddr_t)&ip_squeue_enter, "ip_squeue_enter" },
	{ ip_param_generic_get, ip_int_set,
	    (caddr_t)&ip_squeue_fanout, "ip_squeue_fanout" },
#define	IPNDP_CGTP_FILTER_OFFSET	9
	{  ip_cgtp_filter_get,	ip_cgtp_filter_set, NULL,
	    "ip_cgtp_filter" },
#define	IPNDP_IPMP_HOOK_OFFSET		10
	{  ip_param_generic_get, ipmp_hook_emulation_set, NULL,
	    "ipmp_hook_emulation" },
	{  ip_param_generic_get, ip_int_set, (caddr_t)&ip_debug,
	    "ip_debug" },
};

/*
 * Table of IP ioctls encoding the various properties of the ioctl and
 * indexed based on the last byte of the ioctl command. Occasionally there
 * is a clash, and there is more than 1 ioctl with the same last byte.
 * In such a case 1 ioctl is encoded in the ndx table and the remaining
 * ioctls are encoded in the misc table. An entry in the ndx table is
 * retrieved by indexing on the last byte of the ioctl command and comparing
 * the ioctl command with the value in the ndx table. In the event of a
 * mismatch the misc table is then searched sequentially for the desired
 * ioctl command.
 *
 * Entry: <command> <copyin_size> <flags> <cmd_type> <function> <restart_func>
 */
ip_ioctl_cmd_t ip_ndx_ioctl_table[] = {
	/* 000 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 001 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 002 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 003 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 004 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 005 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 006 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 007 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 008 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 009 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 010 */ { SIOCADDRT,	sizeof (struct rtentry), IPI_PRIV,
			MISC_CMD, ip_siocaddrt, NULL },
	/* 011 */ { SIOCDELRT,	sizeof (struct rtentry), IPI_PRIV,
			MISC_CMD, ip_siocdelrt, NULL },

	/* 012 */ { SIOCSIFADDR, sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_addr, ip_sioctl_addr_restart },
	/* 013 */ { SIOCGIFADDR, sizeof (struct ifreq), IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_addr, NULL },

	/* 014 */ { SIOCSIFDSTADDR, sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_dstaddr, ip_sioctl_dstaddr_restart },
	/* 015 */ { SIOCGIFDSTADDR, sizeof (struct ifreq),
			IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_dstaddr, NULL },

	/* 016 */ { SIOCSIFFLAGS, sizeof (struct ifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			IF_CMD, ip_sioctl_flags, ip_sioctl_flags_restart },
	/* 017 */ { SIOCGIFFLAGS, sizeof (struct ifreq),
			IPI_MODOK | IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_flags, NULL },

	/* 018 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 019 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* copyin size cannot be coded for SIOCGIFCONF */
	/* 020 */ { O_SIOCGIFCONF, 0, IPI_GET_CMD,
			MISC_CMD, ip_sioctl_get_ifconf, NULL },

	/* 021 */ { SIOCSIFMTU,	sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_mtu, NULL },
	/* 022 */ { SIOCGIFMTU,	sizeof (struct ifreq), IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_mtu, NULL },
	/* 023 */ { SIOCGIFBRDADDR, sizeof (struct ifreq),
			IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_brdaddr, NULL },
	/* 024 */ { SIOCSIFBRDADDR, sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_brdaddr, NULL },
	/* 025 */ { SIOCGIFNETMASK, sizeof (struct ifreq),
			IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_netmask, NULL },
	/* 026 */ { SIOCSIFNETMASK, sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_netmask, ip_sioctl_netmask_restart },
	/* 027 */ { SIOCGIFMETRIC, sizeof (struct ifreq),
			IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_metric, NULL },
	/* 028 */ { SIOCSIFMETRIC, sizeof (struct ifreq), IPI_PRIV,
			IF_CMD, ip_sioctl_metric, NULL },
	/* 029 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* See 166-168 below for extended SIOC*XARP ioctls */
	/* 030 */ { SIOCSARP, sizeof (struct arpreq), IPI_PRIV,
			ARP_CMD, ip_sioctl_arp, NULL },
	/* 031 */ { SIOCGARP, sizeof (struct arpreq), IPI_GET_CMD | IPI_REPL,
			ARP_CMD, ip_sioctl_arp, NULL },
	/* 032 */ { SIOCDARP, sizeof (struct arpreq), IPI_PRIV,
			ARP_CMD, ip_sioctl_arp, NULL },

	/* 033 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 034 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 035 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 036 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 037 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 038 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 039 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 040 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 041 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 042 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 043 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 044 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 045 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 046 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 047 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 048 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 049 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 050 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 051 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 052 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 053 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 054 */ { IF_UNITSEL,	sizeof (int), IPI_PRIV | IPI_WR | IPI_MODOK,
			MISC_CMD, if_unitsel, if_unitsel_restart },

	/* 055 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 056 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 057 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 058 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 059 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 060 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 061 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 062 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 063 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 064 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 065 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 066 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 067 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 068 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 069 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 070 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 071 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 072 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 073 */ { SIOCSIFNAME, sizeof (struct ifreq),
			IPI_PRIV | IPI_WR | IPI_MODOK,
			IF_CMD, ip_sioctl_sifname, NULL },

	/* 074 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 075 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 076 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 077 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 078 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 079 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 080 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 081 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 082 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 083 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 084 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 085 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 086 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 087 */ { SIOCGIFNUM, sizeof (int), IPI_GET_CMD | IPI_REPL,
			MISC_CMD, ip_sioctl_get_ifnum, NULL },
	/* 088 */ { SIOCGIFMUXID, sizeof (struct ifreq), IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_muxid, NULL },
	/* 089 */ { SIOCSIFMUXID, sizeof (struct ifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			IF_CMD, ip_sioctl_muxid, NULL },

	/* Both if and lif variants share same func */
	/* 090 */ { SIOCGIFINDEX, sizeof (struct ifreq), IPI_GET_CMD | IPI_REPL,
			IF_CMD, ip_sioctl_get_lifindex, NULL },
	/* Both if and lif variants share same func */
	/* 091 */ { SIOCSIFINDEX, sizeof (struct ifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			IF_CMD, ip_sioctl_slifindex, NULL },

	/* copyin size cannot be coded for SIOCGIFCONF */
	/* 092 */ { SIOCGIFCONF, 0, IPI_GET_CMD,
			MISC_CMD, ip_sioctl_get_ifconf, NULL },
	/* 093 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 094 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 095 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 096 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 097 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 098 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 099 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 100 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 101 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 102 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 103 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 104 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 105 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 106 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 107 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 108 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 109 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 110 */ { SIOCLIFREMOVEIF, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_removeif,
			ip_sioctl_removeif_restart },
	/* 111 */ { SIOCLIFADDIF, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_addif, NULL },
#define	SIOCLIFADDR_NDX 112
	/* 112 */ { SIOCSLIFADDR, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_addr, ip_sioctl_addr_restart },
	/* 113 */ { SIOCGLIFADDR, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_addr, NULL },
	/* 114 */ { SIOCSLIFDSTADDR, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_dstaddr, ip_sioctl_dstaddr_restart },
	/* 115 */ { SIOCGLIFDSTADDR, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_dstaddr, NULL },
	/* 116 */ { SIOCSLIFFLAGS, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_flags, ip_sioctl_flags_restart },
	/* 117 */ { SIOCGLIFFLAGS, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_MODOK | IPI_REPL,
			LIF_CMD, ip_sioctl_get_flags, NULL },

	/* 118 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 119 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 120 */ { O_SIOCGLIFCONF, 0, IPI_GET_CMD, MISC_CMD,
			ip_sioctl_get_lifconf, NULL },
	/* 121 */ { SIOCSLIFMTU, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_mtu, NULL },
	/* 122 */ { SIOCGLIFMTU, sizeof (struct lifreq), IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_mtu, NULL },
	/* 123 */ { SIOCGLIFBRDADDR, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_brdaddr, NULL },
	/* 124 */ { SIOCSLIFBRDADDR, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_brdaddr, NULL },
	/* 125 */ { SIOCGLIFNETMASK, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_netmask, NULL },
	/* 126 */ { SIOCSLIFNETMASK, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_netmask, ip_sioctl_netmask_restart },
	/* 127 */ { SIOCGLIFMETRIC, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_metric, NULL },
	/* 128 */ { SIOCSLIFMETRIC, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_metric, NULL },
	/* 129 */ { SIOCSLIFNAME, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_MODOK | IPI_REPL,
			LIF_CMD, ip_sioctl_slifname,
			ip_sioctl_slifname_restart },

	/* 130 */ { SIOCGLIFNUM, sizeof (struct lifnum), IPI_GET_CMD | IPI_REPL,
			MISC_CMD, ip_sioctl_get_lifnum, NULL },
	/* 131 */ { SIOCGLIFMUXID, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_muxid, NULL },
	/* 132 */ { SIOCSLIFMUXID, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_muxid, NULL },
	/* 133 */ { SIOCGLIFINDEX, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_lifindex, 0 },
	/* 134 */ { SIOCSLIFINDEX, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_slifindex, 0 },
	/* 135 */ { SIOCSLIFTOKEN, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_token, NULL },
	/* 136 */ { SIOCGLIFTOKEN, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_token, NULL },
	/* 137 */ { SIOCSLIFSUBNET, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_subnet, ip_sioctl_subnet_restart },
	/* 138 */ { SIOCGLIFSUBNET, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_subnet, NULL },
	/* 139 */ { SIOCSLIFLNKINFO, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_lnkinfo, NULL },

	/* 140 */ { SIOCGLIFLNKINFO, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_lnkinfo, NULL },
	/* 141 */ { SIOCLIFDELND, sizeof (struct lifreq), IPI_PRIV,
			LIF_CMD, ip_siocdelndp_v6, NULL },
	/* 142 */ { SIOCLIFGETND, sizeof (struct lifreq), IPI_GET_CMD,
			LIF_CMD, ip_siocqueryndp_v6, NULL },
	/* 143 */ { SIOCLIFSETND, sizeof (struct lifreq), IPI_PRIV,
			LIF_CMD, ip_siocsetndp_v6, NULL },
	/* 144 */ { SIOCTMYADDR, sizeof (struct sioc_addrreq), IPI_GET_CMD,
			MISC_CMD, ip_sioctl_tmyaddr, NULL },
	/* 145 */ { SIOCTONLINK, sizeof (struct sioc_addrreq), IPI_GET_CMD,
			MISC_CMD, ip_sioctl_tonlink, NULL },
	/* 146 */ { SIOCTMYSITE, sizeof (struct sioc_addrreq), 0,
			MISC_CMD, ip_sioctl_tmysite, NULL },
	/* 147 */ { SIOCGTUNPARAM, sizeof (struct iftun_req), IPI_REPL,
		    TUN_CMD, ip_sioctl_tunparam, NULL },
	/* 148 */ { SIOCSTUNPARAM, sizeof (struct iftun_req),
		    IPI_PRIV | IPI_WR,
		    TUN_CMD, ip_sioctl_tunparam, NULL },

	/* IPSECioctls handled in ip_sioctl_copyin_setup itself */
	/* 149 */ { SIOCFIPSECONFIG, 0, IPI_PRIV, MISC_CMD, NULL, NULL },
	/* 150 */ { SIOCSIPSECONFIG, 0, IPI_PRIV, MISC_CMD, NULL, NULL },
	/* 151 */ { SIOCDIPSECONFIG, 0, IPI_PRIV, MISC_CMD, NULL, NULL },
	/* 152 */ { SIOCLIPSECONFIG, 0, IPI_PRIV, MISC_CMD, NULL, NULL },

	/* 153 */ { SIOCLIFFAILOVER, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_move, ip_sioctl_move },
	/* 154 */ { SIOCLIFFAILBACK, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_move, ip_sioctl_move },
	/* 155 */ { SIOCSLIFGROUPNAME, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_groupname, ip_sioctl_groupname },
	/* 156 */ { SIOCGLIFGROUPNAME, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_groupname, NULL },
	/* 157 */ { SIOCGLIFOINDEX, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_oindex, NULL },

	/* Leave 158-160 unused; used to be SIOC*IFARP ioctls */
	/* 158 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 159 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 160 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 161 */ { SIOCSLIFOINDEX, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
		    LIF_CMD, ip_sioctl_slifoindex, NULL },

	/* These are handled in ip_sioctl_copyin_setup itself */
	/* 162 */ { SIOCGIP6ADDRPOLICY, 0, IPI_NULL_BCONT,
			MISC_CMD, NULL, NULL },
	/* 163 */ { SIOCSIP6ADDRPOLICY, 0, IPI_PRIV | IPI_NULL_BCONT,
			MISC_CMD, NULL, NULL },
	/* 164 */ { SIOCGDSTINFO, 0, IPI_GET_CMD, MISC_CMD, NULL, NULL },

	/* 165 */ { SIOCGLIFCONF, 0, IPI_GET_CMD, MISC_CMD,
			ip_sioctl_get_lifconf, NULL },

	/* 166 */ { SIOCSXARP, sizeof (struct xarpreq), IPI_PRIV,
			XARP_CMD, ip_sioctl_arp, NULL },
	/* 167 */ { SIOCGXARP, sizeof (struct xarpreq), IPI_GET_CMD | IPI_REPL,
			XARP_CMD, ip_sioctl_arp, NULL },
	/* 168 */ { SIOCDXARP, sizeof (struct xarpreq), IPI_PRIV,
			XARP_CMD, ip_sioctl_arp, NULL },

	/* SIOCPOPSOCKFS is not handled by IP */
	/* 169 */ { IPI_DONTCARE /* SIOCPOPSOCKFS */, 0, 0, 0, NULL, NULL },

	/* 170 */ { SIOCGLIFZONE, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_REPL,
			LIF_CMD, ip_sioctl_get_lifzone, NULL },
	/* 171 */ { SIOCSLIFZONE, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_REPL,
			LIF_CMD, ip_sioctl_slifzone,
			ip_sioctl_slifzone_restart },
	/* 172-174 are SCTP ioctls and not handled by IP */
	/* 172 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 173 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 174 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 175 */ { SIOCGLIFUSESRC, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD,
			ip_sioctl_get_lifusesrc, 0 },
	/* 176 */ { SIOCSLIFUSESRC, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_slifusesrc,
			NULL },
	/* 177 */ { SIOCGLIFSRCOF, 0, IPI_GET_CMD, MISC_CMD,
			ip_sioctl_get_lifsrcof, NULL },
	/* 178 */ { SIOCGMSFILTER, sizeof (struct group_filter), IPI_GET_CMD,
			MSFILT_CMD, ip_sioctl_msfilter, NULL },
	/* 179 */ { SIOCSMSFILTER, sizeof (struct group_filter), IPI_WR,
			MSFILT_CMD, ip_sioctl_msfilter, NULL },
	/* 180 */ { SIOCGIPMSFILTER, sizeof (struct ip_msfilter), IPI_GET_CMD,
			MSFILT_CMD, ip_sioctl_msfilter, NULL },
	/* 181 */ { SIOCSIPMSFILTER, sizeof (struct ip_msfilter), IPI_WR,
			MSFILT_CMD, ip_sioctl_msfilter, NULL },
	/* 182 */ { SIOCSIPMPFAILBACK, sizeof (int), IPI_PRIV, MISC_CMD,
			ip_sioctl_set_ipmpfailback, NULL },
	/* SIOCSENABLESDP is handled by SDP */
	/* 183 */ { IPI_DONTCARE /* SIOCSENABLESDP */, 0, 0, 0, NULL, NULL },
};

int ip_ndx_ioctl_count = sizeof (ip_ndx_ioctl_table) / sizeof (ip_ioctl_cmd_t);

ip_ioctl_cmd_t ip_misc_ioctl_table[] = {
	{ OSIOCGTUNPARAM, sizeof (struct old_iftun_req),
		IPI_GET_CMD | IPI_REPL, TUN_CMD, ip_sioctl_tunparam, NULL },
	{ OSIOCSTUNPARAM, sizeof (struct old_iftun_req), IPI_PRIV | IPI_WR,
		TUN_CMD, ip_sioctl_tunparam, NULL },
	{ I_LINK,	0, IPI_PRIV | IPI_WR | IPI_PASS_DOWN, 0, NULL, NULL },
	{ I_UNLINK,	0, IPI_PRIV | IPI_WR | IPI_PASS_DOWN, 0, NULL, NULL },
	{ I_PLINK,	0, IPI_PRIV | IPI_WR | IPI_PASS_DOWN, 0, NULL, NULL },
	{ I_PUNLINK,	0, IPI_PRIV | IPI_WR | IPI_PASS_DOWN, 0, NULL, NULL },
	{ ND_GET,	0, IPI_PASS_DOWN, 0, NULL, NULL },
	{ ND_SET,	0, IPI_PRIV | IPI_WR | IPI_PASS_DOWN, 0, NULL, NULL },
	{ IP_IOCTL,	0, 0, 0, NULL, NULL },
	{ SIOCGETVIFCNT, sizeof (struct sioc_vif_req), IPI_REPL | IPI_GET_CMD,
		MISC_CMD, mrt_ioctl},
	{ SIOCGETSGCNT,	sizeof (struct sioc_sg_req), IPI_REPL | IPI_GET_CMD,
		MISC_CMD, mrt_ioctl},
	{ SIOCGETLSGCNT, sizeof (struct sioc_lsg_req), IPI_REPL | IPI_GET_CMD,
		MISC_CMD, mrt_ioctl}
};

int ip_misc_ioctl_count =
    sizeof (ip_misc_ioctl_table) / sizeof (ip_ioctl_cmd_t);

int	conn_drain_nthreads;		/* Number of drainers reqd. */
					/* Settable in /etc/system */
/* Defined in ip_ire.c */
extern uint32_t ip_ire_max_bucket_cnt, ip6_ire_max_bucket_cnt;
extern uint32_t ip_ire_min_bucket_cnt, ip6_ire_min_bucket_cnt;
extern uint32_t ip_ire_mem_ratio, ip_ire_cpu_ratio;

static nv_t	ire_nv_arr[] = {
	{ IRE_BROADCAST, "BROADCAST" },
	{ IRE_LOCAL, "LOCAL" },
	{ IRE_LOOPBACK, "LOOPBACK" },
	{ IRE_CACHE, "CACHE" },
	{ IRE_DEFAULT, "DEFAULT" },
	{ IRE_PREFIX, "PREFIX" },
	{ IRE_IF_NORESOLVER, "IF_NORESOL" },
	{ IRE_IF_RESOLVER, "IF_RESOLV" },
	{ IRE_HOST, "HOST" },
	{ 0 }
};

nv_t	*ire_nv_tbl = ire_nv_arr;

/* Simple ICMP IP Header Template */
static ipha_t icmp_ipha = {
	IP_SIMPLE_HDR_VERSION, 0, 0, 0, 0, 0, IPPROTO_ICMP
};

struct module_info ip_mod_info = {
	IP_MOD_ID, IP_MOD_NAME, 1, INFPSZ, 65536, 1024
};

/*
 * Duplicate static symbols within a module confuses mdb; so we avoid the
 * problem by making the symbols here distinct from those in udp.c.
 */

/*
 * Entry points for IP as a device and as a module.
 * FIXME: down the road we might want a separate module and driver qinit.
 * We have separate open functions for the /dev/ip and /dev/ip6 devices.
 */
static struct qinit iprinitv4 = {
	(pfi_t)ip_rput, NULL, ip_openv4, ip_close, NULL,
	&ip_mod_info
};

struct qinit iprinitv6 = {
	(pfi_t)ip_rput_v6, NULL, ip_openv6, ip_close, NULL,
	&ip_mod_info
};

static struct qinit ipwinitv4 = {
	(pfi_t)ip_wput, (pfi_t)ip_wsrv, NULL, NULL, NULL,
	&ip_mod_info
};

struct qinit ipwinitv6 = {
	(pfi_t)ip_wput_v6, (pfi_t)ip_wsrv, NULL, NULL, NULL,
	&ip_mod_info
};

static struct qinit iplrinit = {
	(pfi_t)ip_lrput, NULL, ip_openv4, ip_close, NULL,
	&ip_mod_info
};

static struct qinit iplwinit = {
	(pfi_t)ip_lwput, NULL, NULL, NULL, NULL,
	&ip_mod_info
};

/* For AF_INET aka /dev/ip */
struct streamtab ipinfov4 = {
	&iprinitv4, &ipwinitv4, &iplrinit, &iplwinit
};

/* For AF_INET6 aka /dev/ip6 */
struct streamtab ipinfov6 = {
	&iprinitv6, &ipwinitv6, &iplrinit, &iplwinit
};

#ifdef	DEBUG
static boolean_t skip_sctp_cksum = B_FALSE;
#endif

/*
 * Prepend the zoneid using an ipsec_out_t for later use by functions like
 * ip_rput_v6(), ip_output(), etc.  If the message
 * block already has a M_CTL at the front of it, then simply set the zoneid
 * appropriately.
 */
mblk_t *
ip_prepend_zoneid(mblk_t *mp, zoneid_t zoneid, ip_stack_t *ipst)
{
	mblk_t		*first_mp;
	ipsec_out_t	*io;

	ASSERT(zoneid != ALL_ZONES);
	if (mp->b_datap->db_type == M_CTL) {
		io = (ipsec_out_t *)mp->b_rptr;
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
		io->ipsec_out_zoneid = zoneid;
		return (mp);
	}

	first_mp = ipsec_alloc_ipsec_out(ipst->ips_netstack);
	if (first_mp == NULL)
		return (NULL);
	io = (ipsec_out_t *)first_mp->b_rptr;
	/* This is not a secure packet */
	io->ipsec_out_secure = B_FALSE;
	io->ipsec_out_zoneid = zoneid;
	first_mp->b_cont = mp;
	return (first_mp);
}

/*
 * Copy an M_CTL-tagged message, preserving reference counts appropriately.
 */
mblk_t *
ip_copymsg(mblk_t *mp)
{
	mblk_t *nmp;
	ipsec_info_t *in;

	if (mp->b_datap->db_type != M_CTL)
		return (copymsg(mp));

	in = (ipsec_info_t *)mp->b_rptr;

	/*
	 * Note that M_CTL is also used for delivering ICMP error messages
	 * upstream to transport layers.
	 */
	if (in->ipsec_info_type != IPSEC_OUT &&
	    in->ipsec_info_type != IPSEC_IN)
		return (copymsg(mp));

	nmp = copymsg(mp->b_cont);

	if (in->ipsec_info_type == IPSEC_OUT) {
		return (ipsec_out_tag(mp, nmp,
		    ((ipsec_out_t *)in)->ipsec_out_ns));
	} else {
		return (ipsec_in_tag(mp, nmp,
		    ((ipsec_in_t *)in)->ipsec_in_ns));
	}
}

/* Generate an ICMP fragmentation needed message. */
static void
icmp_frag_needed(queue_t *q, mblk_t *mp, int mtu, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	icmph_t	icmph;
	mblk_t *first_mp;
	boolean_t mctl_present;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	if (!(mp = icmp_pkt_err_ok(mp, ipst))) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_DEST_UNREACHABLE;
	icmph.icmph_code = ICMP_FRAGMENTATION_NEEDED;
	icmph.icmph_du_mtu = htons((uint16_t)mtu);
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutFragNeeded);
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDestUnreachs);
	icmp_pkt(q, first_mp, &icmph, sizeof (icmph_t), mctl_present, zoneid,
	    ipst);
}

/*
 * icmp_inbound deals with ICMP messages in the following ways.
 *
 * 1) It needs to send a reply back and possibly delivering it
 *    to the "interested" upper clients.
 * 2) It needs to send it to the upper clients only.
 * 3) It needs to change some values in IP only.
 * 4) It needs to change some values in IP and upper layers e.g TCP.
 *
 * We need to accomodate icmp messages coming in clear until we get
 * everything secure from the wire. If icmp_accept_clear_messages
 * is zero we check with the global policy and act accordingly. If
 * it is non-zero, we accept the message without any checks. But
 * *this does not mean* that this will be delivered to the upper
 * clients. By accepting we might send replies back, change our MTU
 * value etc. but delivery to the ULP/clients depends on their policy
 * dispositions.
 *
 * We handle the above 4 cases in the context of IPsec in the
 * following way :
 *
 * 1) Send the reply back in the same way as the request came in.
 *    If it came in encrypted, it goes out encrypted. If it came in
 *    clear, it goes out in clear. Thus, this will prevent chosen
 *    plain text attack.
 * 2) The client may or may not expect things to come in secure.
 *    If it comes in secure, the policy constraints are checked
 *    before delivering it to the upper layers. If it comes in
 *    clear, ipsec_inbound_accept_clear will decide whether to
 *    accept this in clear or not. In both the cases, if the returned
 *    message (IP header + 8 bytes) that caused the icmp message has
 *    AH/ESP headers, it is sent up to AH/ESP for validation before
 *    sending up. If there are only 8 bytes of returned message, then
 *    upper client will not be notified.
 * 3) Check with global policy to see whether it matches the constaints.
 *    But this will be done only if icmp_accept_messages_in_clear is
 *    zero.
 * 4) If we need to change both in IP and ULP, then the decision taken
 *    while affecting the values in IP and while delivering up to TCP
 *    should be the same.
 *
 * 	There are two cases.
 *
 * 	a) If we reject data at the IP layer (ipsec_check_global_policy()
 *	   failed), we will not deliver it to the ULP, even though they
 *	   are *willing* to accept in *clear*. This is fine as our global
 *	   disposition to icmp messages asks us reject the datagram.
 *
 *	b) If we accept data at the IP layer (ipsec_check_global_policy()
 *	   succeeded or icmp_accept_messages_in_clear is 1), and not able
 *	   to deliver it to ULP (policy failed), it can lead to
 *	   consistency problems. The cases known at this time are
 *	   ICMP_DESTINATION_UNREACHABLE  messages with following code
 *	   values :
 *
 *	   - ICMP_FRAGMENTATION_NEEDED : IP adapts to the new value
 *	     and Upper layer rejects. Then the communication will
 *	     come to a stop. This is solved by making similar decisions
 *	     at both levels. Currently, when we are unable to deliver
 *	     to the Upper Layer (due to policy failures) while IP has
 *	     adjusted ire_max_frag, the next outbound datagram would
 *	     generate a local ICMP_FRAGMENTATION_NEEDED message - which
 *	     will be with the right level of protection. Thus the right
 *	     value will be communicated even if we are not able to
 *	     communicate when we get from the wire initially. But this
 *	     assumes there would be at least one outbound datagram after
 *	     IP has adjusted its ire_max_frag value. To make things
 *	     simpler, we accept in clear after the validation of
 *	     AH/ESP headers.
 *
 *	   - Other ICMP ERRORS : We may not be able to deliver it to the
 *	     upper layer depending on the level of protection the upper
 *	     layer expects and the disposition in ipsec_inbound_accept_clear().
 *	     ipsec_inbound_accept_clear() decides whether a given ICMP error
 *	     should be accepted in clear when the Upper layer expects secure.
 *	     Thus the communication may get aborted by some bad ICMP
 *	     packets.
 *
 * IPQoS Notes:
 * The only instance when a packet is sent for processing is when there
 * isn't an ICMP client and if we are interested in it.
 * If there is a client, IPPF processing will take place in the
 * ip_fanout_proto routine.
 *
 * Zones notes:
 * The packet is only processed in the context of the specified zone: typically
 * only this zone will reply to an echo request, and only interested clients in
 * this zone will receive a copy of the packet. This means that the caller must
 * call icmp_inbound() for each relevant zone.
 */
static void
icmp_inbound(queue_t *q, mblk_t *mp, boolean_t broadcast, ill_t *ill,
    int sum_valid, uint32_t sum, boolean_t mctl_present, boolean_t ip_policy,
    ill_t *recv_ill, zoneid_t zoneid)
{
	icmph_t	*icmph;
	ipha_t	*ipha;
	int	iph_hdr_length;
	int	hdr_length;
	boolean_t	interested;
	uint32_t	ts;
	uchar_t	*wptr;
	ipif_t	*ipif;
	mblk_t *first_mp;
	ipsec_in_t *ii;
	ire_t *src_ire;
	boolean_t onlink;
	timestruc_t now;
	uint32_t ill_index;
	ip_stack_t *ipst;

	ASSERT(ill != NULL);
	ipst = ill->ill_ipst;

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		ASSERT(mp != NULL);
	}

	ipha = (ipha_t *)mp->b_rptr;
	if (ipst->ips_icmp_accept_clear_messages == 0) {
		first_mp = ipsec_check_global_policy(first_mp, NULL,
		    ipha, NULL, mctl_present, ipst->ips_netstack);
		if (first_mp == NULL)
			return;
	}

	/*
	 * On a labeled system, we have to check whether the zone itself is
	 * permitted to receive raw traffic.
	 */
	if (is_system_labeled()) {
		if (zoneid == ALL_ZONES)
			zoneid = tsol_packet_to_zoneid(mp);
		if (!tsol_can_accept_raw(mp, B_FALSE)) {
			ip1dbg(("icmp_inbound: zone %d can't receive raw",
			    zoneid));
			BUMP_MIB(&ipst->ips_icmp_mib, icmpInErrors);
			freemsg(first_mp);
			return;
		}
	}

	/*
	 * We have accepted the ICMP message. It means that we will
	 * respond to the packet if needed. It may not be delivered
	 * to the upper client depending on the policy constraints
	 * and the disposition in ipsec_inbound_accept_clear.
	 */

	ASSERT(ill != NULL);

	BUMP_MIB(&ipst->ips_icmp_mib, icmpInMsgs);
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	if ((mp->b_wptr - mp->b_rptr) < (iph_hdr_length + ICMPH_SIZE)) {
		/* Last chance to get real. */
		if (!pullupmsg(mp, iph_hdr_length + ICMPH_SIZE)) {
			BUMP_MIB(&ipst->ips_icmp_mib, icmpInErrors);
			freemsg(first_mp);
			return;
		}
		/* Refresh iph following the pullup. */
		ipha = (ipha_t *)mp->b_rptr;
	}
	/* ICMP header checksum, including checksum field, should be zero. */
	if (sum_valid ? (sum != 0 && sum != 0xFFFF) :
	    IP_CSUM(mp, iph_hdr_length, 0)) {
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInCksumErrs);
		freemsg(first_mp);
		return;
	}
	/* The IP header will always be a multiple of four bytes */
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	ip2dbg(("icmp_inbound: type %d code %d\n", icmph->icmph_type,
	    icmph->icmph_code));
	wptr = (uchar_t *)icmph + ICMPH_SIZE;
	/* We will set "interested" to "true" if we want a copy */
	interested = B_FALSE;
	switch (icmph->icmph_type) {
	case ICMP_ECHO_REPLY:
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInEchoReps);
		break;
	case ICMP_DEST_UNREACHABLE:
		if (icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED)
			BUMP_MIB(&ipst->ips_icmp_mib, icmpInFragNeeded);
		interested = B_TRUE;	/* Pass up to transport */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInDestUnreachs);
		break;
	case ICMP_SOURCE_QUENCH:
		interested = B_TRUE;	/* Pass up to transport */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInSrcQuenchs);
		break;
	case ICMP_REDIRECT:
		if (!ipst->ips_ip_ignore_redirect)
			interested = B_TRUE;
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInRedirects);
		break;
	case ICMP_ECHO_REQUEST:
		/*
		 * Whether to respond to echo requests that come in as IP
		 * broadcasts or as IP multicast is subject to debate
		 * (what isn't?).  We aim to please, you pick it.
		 * Default is do it.
		 */
		if (!broadcast && !CLASSD(ipha->ipha_dst)) {
			/* unicast: always respond */
			interested = B_TRUE;
		} else if (CLASSD(ipha->ipha_dst)) {
			/* multicast: respond based on tunable */
			interested = ipst->ips_ip_g_resp_to_echo_mcast;
		} else if (broadcast) {
			/* broadcast: respond based on tunable */
			interested = ipst->ips_ip_g_resp_to_echo_bcast;
		}
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInEchos);
		break;
	case ICMP_ROUTER_ADVERTISEMENT:
	case ICMP_ROUTER_SOLICITATION:
		break;
	case ICMP_TIME_EXCEEDED:
		interested = B_TRUE;	/* Pass up to transport */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInTimeExcds);
		break;
	case ICMP_PARAM_PROBLEM:
		interested = B_TRUE;	/* Pass up to transport */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInParmProbs);
		break;
	case ICMP_TIME_STAMP_REQUEST:
		/* Response to Time Stamp Requests is local policy. */
		if (ipst->ips_ip_g_resp_to_timestamp &&
		    /* So is whether to respond if it was an IP broadcast. */
		    (!broadcast || ipst->ips_ip_g_resp_to_timestamp_bcast)) {
			int tstamp_len = 3 * sizeof (uint32_t);

			if (wptr +  tstamp_len > mp->b_wptr) {
				if (!pullupmsg(mp, wptr + tstamp_len -
				    mp->b_rptr)) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					freemsg(first_mp);
					return;
				}
				/* Refresh ipha following the pullup. */
				ipha = (ipha_t *)mp->b_rptr;
				icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
				wptr = (uchar_t *)icmph + ICMPH_SIZE;
			}
			interested = B_TRUE;
		}
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInTimestamps);
		break;
	case ICMP_TIME_STAMP_REPLY:
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInTimestampReps);
		break;
	case ICMP_INFO_REQUEST:
		/* Per RFC 1122 3.2.2.7, ignore this. */
	case ICMP_INFO_REPLY:
		break;
	case ICMP_ADDRESS_MASK_REQUEST:
		if ((ipst->ips_ip_respond_to_address_mask_broadcast ||
		    !broadcast) &&
		    /* TODO m_pullup of complete header? */
		    (mp->b_datap->db_lim - wptr) >= IP_ADDR_LEN) {
			interested = B_TRUE;
		}
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInAddrMasks);
		break;
	case ICMP_ADDRESS_MASK_REPLY:
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInAddrMaskReps);
		break;
	default:
		interested = B_TRUE;	/* Pass up to transport */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInUnknowns);
		break;
	}
	/* See if there is an ICMP client. */
	if (ipst->ips_ipcl_proto_fanout[IPPROTO_ICMP].connf_head != NULL) {
		/* If there is an ICMP client and we want one too, copy it. */
		mblk_t *first_mp1;

		if (!interested) {
			ip_fanout_proto(q, first_mp, ill, ipha, 0, mctl_present,
			    ip_policy, recv_ill, zoneid);
			return;
		}
		first_mp1 = ip_copymsg(first_mp);
		if (first_mp1 != NULL) {
			ip_fanout_proto(q, first_mp1, ill, ipha,
			    0, mctl_present, ip_policy, recv_ill, zoneid);
		}
	} else if (!interested) {
		freemsg(first_mp);
		return;
	} else {
		/*
		 * Initiate policy processing for this packet if ip_policy
		 * is true.
		 */
		if (IPP_ENABLED(IPP_LOCAL_IN, ipst) && ip_policy) {
			ill_index = ill->ill_phyint->phyint_ifindex;
			ip_process(IPP_LOCAL_IN, &mp, ill_index);
			if (mp == NULL) {
				if (mctl_present) {
					freeb(first_mp);
				}
				BUMP_MIB(&ipst->ips_icmp_mib, icmpInErrors);
				return;
			}
		}
	}
	/* We want to do something with it. */
	/* Check db_ref to make sure we can modify the packet. */
	if (mp->b_datap->db_ref > 1) {
		mblk_t	*first_mp1;

		first_mp1 = ip_copymsg(first_mp);
		freemsg(first_mp);
		if (!first_mp1) {
			BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
			return;
		}
		first_mp = first_mp1;
		if (mctl_present) {
			mp = first_mp->b_cont;
			ASSERT(mp != NULL);
		} else {
			mp = first_mp;
		}
		ipha = (ipha_t *)mp->b_rptr;
		icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
		wptr = (uchar_t *)icmph + ICMPH_SIZE;
	}
	switch (icmph->icmph_type) {
	case ICMP_ADDRESS_MASK_REQUEST:
		ipif = ipif_lookup_remote(ill, ipha->ipha_src, zoneid);
		if (ipif == NULL) {
			freemsg(first_mp);
			return;
		}
		/*
		 * outging interface must be IPv4
		 */
		ASSERT(ipif != NULL && !ipif->ipif_isv6);
		icmph->icmph_type = ICMP_ADDRESS_MASK_REPLY;
		bcopy(&ipif->ipif_net_mask, wptr, IP_ADDR_LEN);
		ipif_refrele(ipif);
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutAddrMaskReps);
		break;
	case ICMP_ECHO_REQUEST:
		icmph->icmph_type = ICMP_ECHO_REPLY;
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutEchoReps);
		break;
	case ICMP_TIME_STAMP_REQUEST: {
		uint32_t *tsp;

		icmph->icmph_type = ICMP_TIME_STAMP_REPLY;
		tsp = (uint32_t *)wptr;
		tsp++;		/* Skip past 'originate time' */
		/* Compute # of milliseconds since midnight */
		gethrestime(&now);
		ts = (now.tv_sec % (24 * 60 * 60)) * 1000 +
		    now.tv_nsec / (NANOSEC / MILLISEC);
		*tsp++ = htonl(ts);	/* Lay in 'receive time' */
		*tsp++ = htonl(ts);	/* Lay in 'send time' */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutTimestampReps);
		break;
	}
	default:
		ipha = (ipha_t *)&icmph[1];
		if ((uchar_t *)&ipha[1] > mp->b_wptr) {
			if (!pullupmsg(mp, (uchar_t *)&ipha[1] - mp->b_rptr)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(first_mp);
				return;
			}
			icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
			ipha = (ipha_t *)&icmph[1];
		}
		if ((IPH_HDR_VERSION(ipha) != IPV4_VERSION)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
			return;
		}
		hdr_length = IPH_HDR_LENGTH(ipha);
		if (hdr_length < sizeof (ipha_t)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
			return;
		}
		if ((uchar_t *)ipha + hdr_length > mp->b_wptr) {
			if (!pullupmsg(mp,
			    (uchar_t *)ipha + hdr_length - mp->b_rptr)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(first_mp);
				return;
			}
			icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
			ipha = (ipha_t *)&icmph[1];
		}
		switch (icmph->icmph_type) {
		case ICMP_REDIRECT:
			/*
			 * As there is no upper client to deliver, we don't
			 * need the first_mp any more.
			 */
			if (mctl_present) {
				freeb(first_mp);
			}
			icmp_redirect(ill, mp);
			return;
		case ICMP_DEST_UNREACHABLE:
			if (icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED) {
				if (!icmp_inbound_too_big(icmph, ipha, ill,
				    zoneid, mp, iph_hdr_length, ipst)) {
					freemsg(first_mp);
					return;
				}
				/*
				 * icmp_inbound_too_big() may alter mp.
				 * Resynch ipha and icmph accordingly.
				 */
				icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
				ipha = (ipha_t *)&icmph[1];
			}
			/* FALLTHRU */
		default :
			/*
			 * IPQoS notes: Since we have already done IPQoS
			 * processing we don't want to do it again in
			 * the fanout routines called by
			 * icmp_inbound_error_fanout, hence the last
			 * argument, ip_policy, is B_FALSE.
			 */
			icmp_inbound_error_fanout(q, ill, first_mp, icmph,
			    ipha, iph_hdr_length, hdr_length, mctl_present,
			    B_FALSE, recv_ill, zoneid);
		}
		return;
	}
	/* Send out an ICMP packet */
	icmph->icmph_checksum = 0;
	icmph->icmph_checksum = IP_CSUM(mp, iph_hdr_length, 0);
	if (broadcast || CLASSD(ipha->ipha_dst)) {
		ipif_t	*ipif_chosen;
		/*
		 * Make it look like it was directed to us, so we don't look
		 * like a fool with a broadcast or multicast source address.
		 */
		ipif = ipif_lookup_remote(ill, ipha->ipha_src, zoneid);
		/*
		 * Make sure that we haven't grabbed an interface that's DOWN.
		 */
		if (ipif != NULL) {
			ipif_chosen = ipif_select_source(ipif->ipif_ill,
			    ipha->ipha_src, zoneid);
			if (ipif_chosen != NULL) {
				ipif_refrele(ipif);
				ipif = ipif_chosen;
			}
		}
		if (ipif == NULL) {
			ip0dbg(("icmp_inbound: "
			    "No source for broadcast/multicast:\n"
			    "\tsrc 0x%x dst 0x%x ill %p "
			    "ipif_lcl_addr 0x%x\n",
			    ntohl(ipha->ipha_src), ntohl(ipha->ipha_dst),
			    (void *)ill,
			    ill->ill_ipif->ipif_lcl_addr));
			freemsg(first_mp);
			return;
		}
		ASSERT(ipif != NULL && !ipif->ipif_isv6);
		ipha->ipha_dst = ipif->ipif_src_addr;
		ipif_refrele(ipif);
	}
	/* Reset time to live. */
	ipha->ipha_ttl = ipst->ips_ip_def_ttl;
	{
		/* Swap source and destination addresses */
		ipaddr_t tmp;

		tmp = ipha->ipha_src;
		ipha->ipha_src = ipha->ipha_dst;
		ipha->ipha_dst = tmp;
	}
	ipha->ipha_ident = 0;
	if (!IS_SIMPLE_IPH(ipha))
		icmp_options_update(ipha);

	/*
	 * ICMP echo replies should go out on the same interface
	 * the request came on as probes used by in.mpathd for detecting
	 * NIC failures are ECHO packets. We turn-off load spreading
	 * by setting ipsec_in_attach_if to B_TRUE, which is copied
	 * to ipsec_out_attach_if by ipsec_in_to_out called later in this
	 * function. This is in turn handled by ip_wput and ip_newroute
	 * to make sure that the packet goes out on the interface it came
	 * in on. If we don't turnoff load spreading, the packets might get
	 * dropped if there are no non-FAILED/INACTIVE interfaces for it
	 * to go out and in.mpathd would wrongly detect a failure or
	 * mis-detect a NIC failure for link failure. As load spreading
	 * can happen only if ill_group is not NULL, we do only for
	 * that case and this does not affect the normal case.
	 *
	 * We turn off load spreading only on echo packets that came from
	 * on-link hosts. If the interface route has been deleted, this will
	 * not be enforced as we can't do much. For off-link hosts, as the
	 * default routes in IPv4 does not typically have an ire_ipif
	 * pointer, we can't force MATCH_IRE_ILL in ip_wput/ip_newroute.
	 * Moreover, expecting a default route through this interface may
	 * not be correct. We use ipha_dst because of the swap above.
	 */
	onlink = B_FALSE;
	if (icmph->icmph_type == ICMP_ECHO_REPLY && ill->ill_group != NULL) {
		/*
		 * First, we need to make sure that it is not one of our
		 * local addresses. If we set onlink when it is one of
		 * our local addresses, we will end up creating IRE_CACHES
		 * for one of our local addresses. Then, we will never
		 * accept packets for them afterwards.
		 */
		src_ire = ire_ctable_lookup(ipha->ipha_dst, 0, IRE_LOCAL,
		    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
		if (src_ire == NULL) {
			ipif = ipif_get_next_ipif(NULL, ill);
			if (ipif == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(mp);
				return;
			}
			src_ire = ire_ftable_lookup(ipha->ipha_dst, 0, 0,
			    IRE_INTERFACE, ipif, NULL, ALL_ZONES, 0,
			    NULL, MATCH_IRE_ILL | MATCH_IRE_TYPE, ipst);
			ipif_refrele(ipif);
			if (src_ire != NULL) {
				onlink = B_TRUE;
				ire_refrele(src_ire);
			}
		} else {
			ire_refrele(src_ire);
		}
	}
	if (!mctl_present) {
		/*
		 * This packet should go out the same way as it
		 * came in i.e in clear. To make sure that global
		 * policy will not be applied to this in ip_wput_ire,
		 * we attach a IPSEC_IN mp and clear ipsec_in_secure.
		 */
		ASSERT(first_mp == mp);
		first_mp = ipsec_in_alloc(B_TRUE, ipst->ips_netstack);
		if (first_mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(mp);
			return;
		}
		ii = (ipsec_in_t *)first_mp->b_rptr;

		/* This is not a secure packet */
		ii->ipsec_in_secure = B_FALSE;
		if (onlink) {
			ii->ipsec_in_attach_if = B_TRUE;
			ii->ipsec_in_ill_index =
			    ill->ill_phyint->phyint_ifindex;
			ii->ipsec_in_rill_index =
			    recv_ill->ill_phyint->phyint_ifindex;
		}
		first_mp->b_cont = mp;
	} else if (onlink) {
		ii = (ipsec_in_t *)first_mp->b_rptr;
		ii->ipsec_in_attach_if = B_TRUE;
		ii->ipsec_in_ill_index = ill->ill_phyint->phyint_ifindex;
		ii->ipsec_in_rill_index = recv_ill->ill_phyint->phyint_ifindex;
		ii->ipsec_in_ns = ipst->ips_netstack;	/* No netstack_hold */
	} else {
		ii = (ipsec_in_t *)first_mp->b_rptr;
		ii->ipsec_in_ns = ipst->ips_netstack;	/* No netstack_hold */
	}
	ii->ipsec_in_zoneid = zoneid;
	ASSERT(zoneid != ALL_ZONES);
	if (!ipsec_in_to_out(first_mp, ipha, NULL)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		return;
	}
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutMsgs);
	put(WR(q), first_mp);
}

static ipaddr_t
icmp_get_nexthop_addr(ipha_t *ipha, ill_t *ill, zoneid_t zoneid, mblk_t *mp)
{
	conn_t *connp;
	connf_t *connfp;
	ipaddr_t nexthop_addr = INADDR_ANY;
	int hdr_length = IPH_HDR_LENGTH(ipha);
	uint16_t *up;
	uint32_t ports;
	ip_stack_t *ipst = ill->ill_ipst;

	up = (uint16_t *)((uchar_t *)ipha + hdr_length);
	switch (ipha->ipha_protocol) {
		case IPPROTO_TCP:
		{
			tcph_t *tcph;

			/* do a reverse lookup */
			tcph = (tcph_t *)((uchar_t *)ipha + hdr_length);
			connp = ipcl_tcp_lookup_reversed_ipv4(ipha, tcph,
			    TCPS_LISTEN, ipst);
			break;
		}
		case IPPROTO_UDP:
		{
			uint32_t dstport, srcport;

			((uint16_t *)&ports)[0] = up[1];
			((uint16_t *)&ports)[1] = up[0];

			/* Extract ports in net byte order */
			dstport = htons(ntohl(ports) & 0xFFFF);
			srcport = htons(ntohl(ports) >> 16);

			connfp = &ipst->ips_ipcl_udp_fanout[
			    IPCL_UDP_HASH(dstport, ipst)];
			mutex_enter(&connfp->connf_lock);
			connp = connfp->connf_head;

			/* do a reverse lookup */
			while ((connp != NULL) &&
			    (!IPCL_UDP_MATCH(connp, dstport,
			    ipha->ipha_src, srcport, ipha->ipha_dst) ||
			    !IPCL_ZONE_MATCH(connp, zoneid))) {
				connp = connp->conn_next;
			}
			if (connp != NULL)
				CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);
			break;
		}
		case IPPROTO_SCTP:
		{
			in6_addr_t map_src, map_dst;

			IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &map_src);
			IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &map_dst);
			((uint16_t *)&ports)[0] = up[1];
			((uint16_t *)&ports)[1] = up[0];

			connp = sctp_find_conn(&map_src, &map_dst, ports,
			    zoneid, ipst->ips_netstack->netstack_sctp);
			if (connp == NULL) {
				connp = ipcl_classify_raw(mp, IPPROTO_SCTP,
				    zoneid, ports, ipha, ipst);
			} else {
				CONN_INC_REF(connp);
				SCTP_REFRELE(CONN2SCTP(connp));
			}
			break;
		}
		default:
		{
			ipha_t ripha;

			ripha.ipha_src = ipha->ipha_dst;
			ripha.ipha_dst = ipha->ipha_src;
			ripha.ipha_protocol = ipha->ipha_protocol;

			connfp = &ipst->ips_ipcl_proto_fanout[
			    ipha->ipha_protocol];
			mutex_enter(&connfp->connf_lock);
			connp = connfp->connf_head;
			for (connp = connfp->connf_head; connp != NULL;
			    connp = connp->conn_next) {
				if (IPCL_PROTO_MATCH(connp,
				    ipha->ipha_protocol, &ripha, ill,
				    0, zoneid)) {
					CONN_INC_REF(connp);
					break;
				}
			}
			mutex_exit(&connfp->connf_lock);
		}
	}
	if (connp != NULL) {
		if (connp->conn_nexthop_set)
			nexthop_addr = connp->conn_nexthop_v4;
		CONN_DEC_REF(connp);
	}
	return (nexthop_addr);
}

/* Table from RFC 1191 */
static int icmp_frag_size_table[] =
{ 32000, 17914, 8166, 4352, 2002, 1496, 1006, 508, 296, 68 };

/*
 * Process received ICMP Packet too big.
 * After updating any IRE it does the fanout to any matching transport streams.
 * Assumes the message has been pulled up till the IP header that caused
 * the error.
 *
 * Returns B_FALSE on failure and B_TRUE on success.
 */
static boolean_t
icmp_inbound_too_big(icmph_t *icmph, ipha_t *ipha, ill_t *ill,
    zoneid_t zoneid, mblk_t *mp, int iph_hdr_length,
    ip_stack_t *ipst)
{
	ire_t	*ire, *first_ire;
	int	mtu, orig_mtu;
	int	hdr_length;
	ipaddr_t nexthop_addr;
	boolean_t disable_pmtud;

	ASSERT(icmph->icmph_type == ICMP_DEST_UNREACHABLE &&
	    icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED);
	ASSERT(ill != NULL);

	hdr_length = IPH_HDR_LENGTH(ipha);

	/* Drop if the original packet contained a source route */
	if (ip_source_route_included(ipha)) {
		return (B_FALSE);
	}
	/*
	 * Verify we have atleast ICMP_MIN_TP_HDR_LENGTH bytes of transport
	 * header.
	 */
	if ((uchar_t *)ipha + hdr_length + ICMP_MIN_TP_HDR_LEN >
	    mp->b_wptr) {
		if (!pullupmsg(mp, (uchar_t *)ipha + hdr_length +
		    ICMP_MIN_TP_HDR_LEN - mp->b_rptr)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip1dbg(("icmp_inbound_too_big: insufficient hdr\n"));
			return (B_FALSE);
		}
		icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
		ipha = (ipha_t *)&icmph[1];
	}
	nexthop_addr = icmp_get_nexthop_addr(ipha, ill, zoneid, mp);
	if (nexthop_addr != INADDR_ANY) {
		/* nexthop set */
		first_ire = ire_ctable_lookup(ipha->ipha_dst,
		    nexthop_addr, 0, NULL, ALL_ZONES, MBLK_GETLABEL(mp),
		    MATCH_IRE_MARK_PRIVATE_ADDR | MATCH_IRE_GW, ipst);
	} else {
		/* nexthop not set */
		first_ire = ire_ctable_lookup(ipha->ipha_dst, 0, IRE_CACHE,
		    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	}

	if (!first_ire) {
		ip1dbg(("icmp_inbound_too_big: no route for 0x%x\n",
		    ntohl(ipha->ipha_dst)));
		return (B_FALSE);
	}

	/* Check for MTU discovery advice as described in RFC 1191 */
	mtu = ntohs(icmph->icmph_du_mtu);
	orig_mtu = mtu;
	disable_pmtud = B_FALSE;

	rw_enter(&first_ire->ire_bucket->irb_lock, RW_READER);
	for (ire = first_ire; ire != NULL && ire->ire_addr == ipha->ipha_dst;
	    ire = ire->ire_next) {
		/*
		 * Look for the connection to which this ICMP message is
		 * directed. If it has the IP_NEXTHOP option set, then the
		 * search is limited to IREs with the MATCH_IRE_PRIVATE
		 * option. Else the search is limited to regular IREs.
		 */
		if (((ire->ire_marks & IRE_MARK_PRIVATE_ADDR) &&
		    (nexthop_addr != ire->ire_gateway_addr)) ||
		    (!(ire->ire_marks & IRE_MARK_PRIVATE_ADDR) &&
		    (nexthop_addr != INADDR_ANY)))
			continue;

		mutex_enter(&ire->ire_lock);
		if (icmph->icmph_du_zero != 0 || mtu < ipst->ips_ip_pmtu_min) {
			uint32_t length;
			int	i;

			/*
			 * Use the table from RFC 1191 to figure out
			 * the next "plateau" based on the length in
			 * the original IP packet.
			 */
			length = ntohs(ipha->ipha_length);
			DTRACE_PROBE2(ip4__pmtu__guess, ire_t *, ire,
			    uint32_t, length);
			if (ire->ire_max_frag <= length &&
			    ire->ire_max_frag >= length - hdr_length) {
				/*
				 * Handle broken BSD 4.2 systems that
				 * return the wrong iph_length in ICMP
				 * errors.
				 */
				length -= hdr_length;
			}
			for (i = 0; i < A_CNT(icmp_frag_size_table); i++) {
				if (length > icmp_frag_size_table[i])
					break;
			}
			if (i == A_CNT(icmp_frag_size_table)) {
				/* Smaller than 68! */
				disable_pmtud = B_TRUE;
				mtu = ipst->ips_ip_pmtu_min;
			} else {
				mtu = icmp_frag_size_table[i];
				if (mtu < ipst->ips_ip_pmtu_min) {
					mtu = ipst->ips_ip_pmtu_min;
					disable_pmtud = B_TRUE;
				}
			}
			/* Fool the ULP into believing our guessed PMTU. */
			icmph->icmph_du_zero = 0;
			icmph->icmph_du_mtu = htons(mtu);
		}
		if (disable_pmtud)
			ire->ire_frag_flag = 0;
		/* Reduce the IRE max frag value as advised. */
		ire->ire_max_frag = MIN(ire->ire_max_frag, mtu);
		mutex_exit(&ire->ire_lock);
		DTRACE_PROBE4(ip4__pmtu__change, icmph_t *, icmph, ire_t *,
		    ire, int, orig_mtu, int, mtu);
	}
	rw_exit(&first_ire->ire_bucket->irb_lock);
	ire_refrele(first_ire);
	return (B_TRUE);
}

/*
 * If the packet in error is Self-Encapsulated, icmp_inbound_error_fanout
 * calls this function.
 */
static mblk_t *
icmp_inbound_self_encap_error(mblk_t *mp, int iph_hdr_length, int hdr_length)
{
	ipha_t *ipha;
	icmph_t *icmph;
	ipha_t *in_ipha;
	int length;

	ASSERT(mp->b_datap->db_type == M_DATA);

	/*
	 * For Self-encapsulated packets, we added an extra IP header
	 * without the options. Inner IP header is the one from which
	 * the outer IP header was formed. Thus, we need to remove the
	 * outer IP header. To do this, we pullup the whole message
	 * and overlay whatever follows the outer IP header over the
	 * outer IP header.
	 */

	if (!pullupmsg(mp, -1))
		return (NULL);

	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	ipha = (ipha_t *)&icmph[1];
	in_ipha = (ipha_t *)((uchar_t *)ipha + hdr_length);

	/*
	 * The length that we want to overlay is following the inner
	 * IP header. Subtracting the IP header + icmp header + outer
	 * IP header's length should give us the length that we want to
	 * overlay.
	 */
	length = msgdsize(mp) - iph_hdr_length - sizeof (icmph_t) -
	    hdr_length;
	/*
	 * Overlay whatever follows the inner header over the
	 * outer header.
	 */
	bcopy((uchar_t *)in_ipha, (uchar_t *)ipha, length);

	/* Set the wptr to account for the outer header */
	mp->b_wptr -= hdr_length;
	return (mp);
}

/*
 * Try to pass the ICMP message upstream in case the ULP cares.
 *
 * If the packet that caused the ICMP error is secure, we send
 * it to AH/ESP to make sure that the attached packet has a
 * valid association. ipha in the code below points to the
 * IP header of the packet that caused the error.
 *
 * We handle ICMP_FRAGMENTATION_NEEDED(IFN) message differently
 * in the context of IPsec. Normally we tell the upper layer
 * whenever we send the ire (including ip_bind), the IPsec header
 * length in ire_ipsec_overhead. TCP can deduce the MSS as it
 * has both the MTU (ire_max_frag) and the ire_ipsec_overhead.
 * Similarly, we pass the new MTU icmph_du_mtu and TCP does the
 * same thing. As TCP has the IPsec options size that needs to be
 * adjusted, we just pass the MTU unchanged.
 *
 * IFN could have been generated locally or by some router.
 *
 * LOCAL : *ip_wput_ire -> icmp_frag_needed could have generated this.
 *	    This happens because IP adjusted its value of MTU on an
 *	    earlier IFN message and could not tell the upper layer,
 *	    the new adjusted value of MTU e.g. Packet was encrypted
 *	    or there was not enough information to fanout to upper
 *	    layers. Thus on the next outbound datagram, ip_wput_ire
 *	    generates the IFN, where IPsec processing has *not* been
 *	    done.
 *
 *	   *ip_wput_ire_fragmentit -> ip_wput_frag -> icmp_frag_needed
 *	    could have generated this. This happens because ire_max_frag
 *	    value in IP was set to a new value, while the IPsec processing
 *	    was being done and after we made the fragmentation check in
 *	    ip_wput_ire. Thus on return from IPsec processing,
 *	    ip_wput_ipsec_out finds that the new length is > ire_max_frag
 *	    and generates the IFN. As IPsec processing is over, we fanout
 *	    to AH/ESP to remove the header.
 *
 *	    In both these cases, ipsec_in_loopback will be set indicating
 *	    that IFN was generated locally.
 *
 * ROUTER : IFN could be secure or non-secure.
 *
 *	    * SECURE : We use the IPSEC_IN to fanout to AH/ESP if the
 *	      packet in error has AH/ESP headers to validate the AH/ESP
 *	      headers. AH/ESP will verify whether there is a valid SA or
 *	      not and send it back. We will fanout again if we have more
 *	      data in the packet.
 *
 *	      If the packet in error does not have AH/ESP, we handle it
 *	      like any other case.
 *
 *	    * NON_SECURE : If the packet in error has AH/ESP headers,
 *	      we attach a dummy ipsec_in and send it up to AH/ESP
 *	      for validation. AH/ESP will verify whether there is a
 *	      valid SA or not and send it back. We will fanout again if
 *	      we have more data in the packet.
 *
 *	      If the packet in error does not have AH/ESP, we handle it
 *	      like any other case.
 */
static void
icmp_inbound_error_fanout(queue_t *q, ill_t *ill, mblk_t *mp,
    icmph_t *icmph, ipha_t *ipha, int iph_hdr_length, int hdr_length,
    boolean_t mctl_present, boolean_t ip_policy, ill_t *recv_ill,
    zoneid_t zoneid)
{
	uint16_t *up;	/* Pointer to ports in ULP header */
	uint32_t ports;	/* reversed ports for fanout */
	ipha_t ripha;	/* With reversed addresses */
	mblk_t *first_mp;
	ipsec_in_t *ii;
	tcph_t	*tcph;
	conn_t	*connp;
	ip_stack_t *ipst;

	ASSERT(ill != NULL);

	ASSERT(recv_ill != NULL);
	ipst = recv_ill->ill_ipst;

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		ASSERT(mp != NULL);

		ii = (ipsec_in_t *)first_mp->b_rptr;
		ASSERT(ii->ipsec_in_type == IPSEC_IN);
	} else {
		ii = NULL;
	}

	switch (ipha->ipha_protocol) {
	case IPPROTO_UDP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ipha + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr) {
			if (!pullupmsg(mp, (uchar_t *)ipha + hdr_length +
			    ICMP_MIN_TP_HDR_LEN - mp->b_rptr)) {
				goto discard_pkt;
			}
			icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
			ipha = (ipha_t *)&icmph[1];
		}
		up = (uint16_t *)((uchar_t *)ipha + hdr_length);

		/*
		 * Attempt to find a client stream based on port.
		 * Note that we do a reverse lookup since the header is
		 * in the form we sent it out.
		 * The ripha header is only used for the IP_UDP_MATCH and we
		 * only set the src and dst addresses and protocol.
		 */
		ripha.ipha_src = ipha->ipha_dst;
		ripha.ipha_dst = ipha->ipha_src;
		ripha.ipha_protocol = ipha->ipha_protocol;
		((uint16_t *)&ports)[0] = up[1];
		((uint16_t *)&ports)[1] = up[0];
		ip2dbg(("icmp_inbound_error: UDP %x:%d to %x:%d: %d/%d\n",
		    ntohl(ipha->ipha_src), ntohs(up[0]),
		    ntohl(ipha->ipha_dst), ntohs(up[1]),
		    icmph->icmph_type, icmph->icmph_code));

		/* Have to change db_type after any pullupmsg */
		DB_TYPE(mp) = M_CTL;

		ip_fanout_udp(q, first_mp, ill, &ripha, ports, B_FALSE, 0,
		    mctl_present, ip_policy, recv_ill, zoneid);
		return;

	case IPPROTO_TCP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ipha + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr) {
			if (!pullupmsg(mp, (uchar_t *)ipha + hdr_length +
			    ICMP_MIN_TP_HDR_LEN - mp->b_rptr)) {
				goto discard_pkt;
			}
			icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
			ipha = (ipha_t *)&icmph[1];
		}
		/*
		 * Find a TCP client stream for this packet.
		 * Note that we do a reverse lookup since the header is
		 * in the form we sent it out.
		 */
		tcph = (tcph_t *)((uchar_t *)ipha + hdr_length);
		connp = ipcl_tcp_lookup_reversed_ipv4(ipha, tcph, TCPS_LISTEN,
		    ipst);
		if (connp == NULL)
			goto discard_pkt;

		/* Have to change db_type after any pullupmsg */
		DB_TYPE(mp) = M_CTL;
		SQUEUE_ENTER_ONE(connp->conn_sqp, first_mp, tcp_input, connp,
		    SQ_FILL, SQTAG_TCP_INPUT_ICMP_ERR);
		return;

	case IPPROTO_SCTP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ipha + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr) {
			if (!pullupmsg(mp, (uchar_t *)ipha + hdr_length +
			    ICMP_MIN_TP_HDR_LEN - mp->b_rptr)) {
				goto discard_pkt;
			}
			icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
			ipha = (ipha_t *)&icmph[1];
		}
		up = (uint16_t *)((uchar_t *)ipha + hdr_length);
		/*
		 * Find a SCTP client stream for this packet.
		 * Note that we do a reverse lookup since the header is
		 * in the form we sent it out.
		 * The ripha header is only used for the matching and we
		 * only set the src and dst addresses, protocol, and version.
		 */
		ripha.ipha_src = ipha->ipha_dst;
		ripha.ipha_dst = ipha->ipha_src;
		ripha.ipha_protocol = ipha->ipha_protocol;
		ripha.ipha_version_and_hdr_length =
		    ipha->ipha_version_and_hdr_length;
		((uint16_t *)&ports)[0] = up[1];
		((uint16_t *)&ports)[1] = up[0];

		/* Have to change db_type after any pullupmsg */
		DB_TYPE(mp) = M_CTL;
		ip_fanout_sctp(first_mp, recv_ill, &ripha, ports, 0,
		    mctl_present, ip_policy, zoneid);
		return;

	case IPPROTO_ESP:
	case IPPROTO_AH: {
		int ipsec_rc;
		ipsec_stack_t *ipss = ipst->ips_netstack->netstack_ipsec;

		/*
		 * We need a IPSEC_IN in the front to fanout to AH/ESP.
		 * We will re-use the IPSEC_IN if it is already present as
		 * AH/ESP will not affect any fields in the IPSEC_IN for
		 * ICMP errors. If there is no IPSEC_IN, allocate a new
		 * one and attach it in the front.
		 */
		if (ii != NULL) {
			/*
			 * ip_fanout_proto_again converts the ICMP errors
			 * that come back from AH/ESP to M_DATA so that
			 * if it is non-AH/ESP and we do a pullupmsg in
			 * this function, it would work. Convert it back
			 * to M_CTL before we send up as this is a ICMP
			 * error. This could have been generated locally or
			 * by some router. Validate the inner IPsec
			 * headers.
			 *
			 * NOTE : ill_index is used by ip_fanout_proto_again
			 * to locate the ill.
			 */
			ASSERT(ill != NULL);
			ii->ipsec_in_ill_index =
			    ill->ill_phyint->phyint_ifindex;
			ii->ipsec_in_rill_index =
			    recv_ill->ill_phyint->phyint_ifindex;
			DB_TYPE(first_mp->b_cont) = M_CTL;
		} else {
			/*
			 * IPSEC_IN is not present. We attach a ipsec_in
			 * message and send up to IPsec for validating
			 * and removing the IPsec headers. Clear
			 * ipsec_in_secure so that when we return
			 * from IPsec, we don't mistakenly think that this
			 * is a secure packet came from the network.
			 *
			 * NOTE : ill_index is used by ip_fanout_proto_again
			 * to locate the ill.
			 */
			ASSERT(first_mp == mp);
			first_mp = ipsec_in_alloc(B_TRUE, ipst->ips_netstack);
			if (first_mp == NULL) {
				freemsg(mp);
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				return;
			}
			ii = (ipsec_in_t *)first_mp->b_rptr;

			/* This is not a secure packet */
			ii->ipsec_in_secure = B_FALSE;
			first_mp->b_cont = mp;
			DB_TYPE(mp) = M_CTL;
			ASSERT(ill != NULL);
			ii->ipsec_in_ill_index =
			    ill->ill_phyint->phyint_ifindex;
			ii->ipsec_in_rill_index =
			    recv_ill->ill_phyint->phyint_ifindex;
		}
		ip2dbg(("icmp_inbound_error: ipsec\n"));

		if (!ipsec_loaded(ipss)) {
			ip_proto_not_sup(q, first_mp, 0, zoneid, ipst);
			return;
		}

		if (ipha->ipha_protocol == IPPROTO_ESP)
			ipsec_rc = ipsecesp_icmp_error(first_mp);
		else
			ipsec_rc = ipsecah_icmp_error(first_mp);
		if (ipsec_rc == IPSEC_STATUS_FAILED)
			return;

		ip_fanout_proto_again(first_mp, ill, recv_ill, NULL);
		return;
	}
	default:
		/*
		 * The ripha header is only used for the lookup and we
		 * only set the src and dst addresses and protocol.
		 */
		ripha.ipha_src = ipha->ipha_dst;
		ripha.ipha_dst = ipha->ipha_src;
		ripha.ipha_protocol = ipha->ipha_protocol;
		ip2dbg(("icmp_inbound_error: proto %d %x to %x: %d/%d\n",
		    ripha.ipha_protocol, ntohl(ipha->ipha_src),
		    ntohl(ipha->ipha_dst),
		    icmph->icmph_type, icmph->icmph_code));
		if (ipha->ipha_protocol == IPPROTO_ENCAP) {
			ipha_t *in_ipha;

			if ((uchar_t *)ipha + hdr_length + sizeof (ipha_t) >
			    mp->b_wptr) {
				if (!pullupmsg(mp, (uchar_t *)ipha +
				    hdr_length + sizeof (ipha_t) -
				    mp->b_rptr)) {
					goto discard_pkt;
				}
				icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
				ipha = (ipha_t *)&icmph[1];
			}
			/*
			 * Caller has verified that length has to be
			 * at least the size of IP header.
			 */
			ASSERT(hdr_length >= sizeof (ipha_t));
			/*
			 * Check the sanity of the inner IP header like
			 * we did for the outer header.
			 */
			in_ipha = (ipha_t *)((uchar_t *)ipha + hdr_length);
			if ((IPH_HDR_VERSION(in_ipha) != IPV4_VERSION)) {
				goto discard_pkt;
			}
			if (IPH_HDR_LENGTH(in_ipha) < sizeof (ipha_t)) {
				goto discard_pkt;
			}
			/* Check for Self-encapsulated tunnels */
			if (in_ipha->ipha_src == ipha->ipha_src &&
			    in_ipha->ipha_dst == ipha->ipha_dst) {

				mp = icmp_inbound_self_encap_error(mp,
				    iph_hdr_length, hdr_length);
				if (mp == NULL)
					goto discard_pkt;
				icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
				ipha = (ipha_t *)&icmph[1];
				hdr_length = IPH_HDR_LENGTH(ipha);
				/*
				 * The packet in error is self-encapsualted.
				 * And we are finding it further encapsulated
				 * which we could not have possibly generated.
				 */
				if (ipha->ipha_protocol == IPPROTO_ENCAP) {
					goto discard_pkt;
				}
				icmp_inbound_error_fanout(q, ill, first_mp,
				    icmph, ipha, iph_hdr_length, hdr_length,
				    mctl_present, ip_policy, recv_ill, zoneid);
				return;
			}
		}
		if ((ipha->ipha_protocol == IPPROTO_ENCAP ||
		    ipha->ipha_protocol == IPPROTO_IPV6) &&
		    icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED &&
		    ii != NULL &&
		    ii->ipsec_in_loopback &&
		    ii->ipsec_in_secure) {
			/*
			 * For IP tunnels that get a looped-back
			 * ICMP_FRAGMENTATION_NEEDED message, adjust the
			 * reported new MTU to take into account the IPsec
			 * headers protecting this configured tunnel.
			 *
			 * This allows the tunnel module (tun.c) to blindly
			 * accept the MTU reported in an ICMP "too big"
			 * message.
			 *
			 * Non-looped back ICMP messages will just be
			 * handled by the security protocols (if needed),
			 * and the first subsequent packet will hit this
			 * path.
			 */
			icmph->icmph_du_mtu = htons(ntohs(icmph->icmph_du_mtu) -
			    ipsec_in_extra_length(first_mp));
		}
		/* Have to change db_type after any pullupmsg */
		DB_TYPE(mp) = M_CTL;

		ip_fanout_proto(q, first_mp, ill, &ripha, 0, mctl_present,
		    ip_policy, recv_ill, zoneid);
		return;
	}
	/* NOTREACHED */
discard_pkt:
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
drop_pkt:;
	ip1dbg(("icmp_inbound_error_fanout: drop pkt\n"));
	freemsg(first_mp);
}

/*
 * Common IP options parser.
 *
 * Setup routine: fill in *optp with options-parsing state, then
 * tail-call ipoptp_next to return the first option.
 */
uint8_t
ipoptp_first(ipoptp_t *optp, ipha_t *ipha)
{
	uint32_t totallen; /* total length of all options */

	totallen = ipha->ipha_version_and_hdr_length -
	    (uint8_t)((IP_VERSION << 4) + IP_SIMPLE_HDR_LENGTH_IN_WORDS);
	totallen <<= 2;
	optp->ipoptp_next = (uint8_t *)(&ipha[1]);
	optp->ipoptp_end = optp->ipoptp_next + totallen;
	optp->ipoptp_flags = 0;
	return (ipoptp_next(optp));
}

/*
 * Common IP options parser: extract next option.
 */
uint8_t
ipoptp_next(ipoptp_t *optp)
{
	uint8_t *end = optp->ipoptp_end;
	uint8_t *cur = optp->ipoptp_next;
	uint8_t opt, len, pointer;

	/*
	 * If cur > end already, then the ipoptp_end or ipoptp_next pointer
	 * has been corrupted.
	 */
	ASSERT(cur <= end);

	if (cur == end)
		return (IPOPT_EOL);

	opt = cur[IPOPT_OPTVAL];

	/*
	 * Skip any NOP options.
	 */
	while (opt == IPOPT_NOP) {
		cur++;
		if (cur == end)
			return (IPOPT_EOL);
		opt = cur[IPOPT_OPTVAL];
	}

	if (opt == IPOPT_EOL)
		return (IPOPT_EOL);

	/*
	 * Option requiring a length.
	 */
	if ((cur + 1) >= end) {
		optp->ipoptp_flags |= IPOPTP_ERROR;
		return (IPOPT_EOL);
	}
	len = cur[IPOPT_OLEN];
	if (len < 2) {
		optp->ipoptp_flags |= IPOPTP_ERROR;
		return (IPOPT_EOL);
	}
	optp->ipoptp_cur = cur;
	optp->ipoptp_len = len;
	optp->ipoptp_next = cur + len;
	if (cur + len > end) {
		optp->ipoptp_flags |= IPOPTP_ERROR;
		return (IPOPT_EOL);
	}

	/*
	 * For the options which require a pointer field, make sure
	 * its there, and make sure it points to either something
	 * inside this option, or the end of the option.
	 */
	switch (opt) {
	case IPOPT_RR:
	case IPOPT_TS:
	case IPOPT_LSRR:
	case IPOPT_SSRR:
		if (len <= IPOPT_OFFSET) {
			optp->ipoptp_flags |= IPOPTP_ERROR;
			return (opt);
		}
		pointer = cur[IPOPT_OFFSET];
		if (pointer - 1 > len) {
			optp->ipoptp_flags |= IPOPTP_ERROR;
			return (opt);
		}
		break;
	}

	/*
	 * Sanity check the pointer field based on the type of the
	 * option.
	 */
	switch (opt) {
	case IPOPT_RR:
	case IPOPT_SSRR:
	case IPOPT_LSRR:
		if (pointer < IPOPT_MINOFF_SR)
			optp->ipoptp_flags |= IPOPTP_ERROR;
		break;
	case IPOPT_TS:
		if (pointer < IPOPT_MINOFF_IT)
			optp->ipoptp_flags |= IPOPTP_ERROR;
		/*
		 * Note that the Internet Timestamp option also
		 * contains two four bit fields (the Overflow field,
		 * and the Flag field), which follow the pointer
		 * field.  We don't need to check that these fields
		 * fall within the length of the option because this
		 * was implicitely done above.  We've checked that the
		 * pointer value is at least IPOPT_MINOFF_IT, and that
		 * it falls within the option.  Since IPOPT_MINOFF_IT >
		 * IPOPT_POS_OV_FLG, we don't need the explicit check.
		 */
		ASSERT(len > IPOPT_POS_OV_FLG);
		break;
	}

	return (opt);
}

/*
 * Use the outgoing IP header to create an IP_OPTIONS option the way
 * it was passed down from the application.
 */
int
ip_opt_get_user(const ipha_t *ipha, uchar_t *buf)
{
	ipoptp_t	opts;
	const uchar_t	*opt;
	uint8_t		optval;
	uint8_t		optlen;
	uint32_t	len = 0;
	uchar_t	*buf1 = buf;

	buf += IP_ADDR_LEN;	/* Leave room for final destination */
	len += IP_ADDR_LEN;
	bzero(buf1, IP_ADDR_LEN);

	/*
	 * OK to cast away const here, as we don't store through the returned
	 * opts.ipoptp_cur pointer.
	 */
	for (optval = ipoptp_first(&opts, (ipha_t *)ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		int	off;

		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		switch (optval) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:

			/*
			 * Insert ipha_dst as the first entry in the source
			 * route and move down the entries on step.
			 * The last entry gets placed at buf1.
			 */
			buf[IPOPT_OPTVAL] = optval;
			buf[IPOPT_OLEN] = optlen;
			buf[IPOPT_OFFSET] = optlen;

			off = optlen - IP_ADDR_LEN;
			if (off < 0) {
				/* No entries in source route */
				break;
			}
			/* Last entry in source route */
			bcopy(opt + off, buf1, IP_ADDR_LEN);
			off -= IP_ADDR_LEN;

			while (off > 0) {
				bcopy(opt + off,
				    buf + off + IP_ADDR_LEN,
				    IP_ADDR_LEN);
				off -= IP_ADDR_LEN;
			}
			/* ipha_dst into first slot */
			bcopy(&ipha->ipha_dst,
			    buf + off + IP_ADDR_LEN,
			    IP_ADDR_LEN);
			buf += optlen;
			len += optlen;
			break;

		case IPOPT_COMSEC:
		case IPOPT_SECURITY:
			/* if passing up a label is not ok, then remove */
			if (is_system_labeled())
				break;
			/* FALLTHROUGH */
		default:
			bcopy(opt, buf, optlen);
			buf += optlen;
			len += optlen;
			break;
		}
	}
done:
	/* Pad the resulting options */
	while (len & 0x3) {
		*buf++ = IPOPT_EOL;
		len++;
	}
	return (len);
}

/*
 * Update any record route or timestamp options to include this host.
 * Reverse any source route option.
 * This routine assumes that the options are well formed i.e. that they
 * have already been checked.
 */
static void
icmp_options_update(ipha_t *ipha)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	ipaddr_t	src;		/* Our local address */
	ipaddr_t	dst;

	ip2dbg(("icmp_options_update\n"));
	src = ipha->ipha_src;
	dst = ipha->ipha_dst;

	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		opt = opts.ipoptp_cur;
		ip2dbg(("icmp_options_update: opt %d, len %d\n",
		    optval, opts.ipoptp_len));
		switch (optval) {
			int off1, off2;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			/*
			 * Reverse the source route.  The first entry
			 * should be the next to last one in the current
			 * source route (the last entry is our address).
			 * The last entry should be the final destination.
			 */
			off1 = IPOPT_MINOFF_SR - 1;
			off2 = opt[IPOPT_OFFSET] - IP_ADDR_LEN - 1;
			if (off2 < 0) {
				/* No entries in source route */
				ip1dbg((
				    "icmp_options_update: bad src route\n"));
				break;
			}
			bcopy((char *)opt + off2, &dst, IP_ADDR_LEN);
			bcopy(&ipha->ipha_dst, (char *)opt + off2, IP_ADDR_LEN);
			bcopy(&dst, &ipha->ipha_dst, IP_ADDR_LEN);
			off2 -= IP_ADDR_LEN;

			while (off1 < off2) {
				bcopy((char *)opt + off1, &src, IP_ADDR_LEN);
				bcopy((char *)opt + off2, (char *)opt + off1,
				    IP_ADDR_LEN);
				bcopy(&src, (char *)opt + off2, IP_ADDR_LEN);
				off1 += IP_ADDR_LEN;
				off2 -= IP_ADDR_LEN;
			}
			opt[IPOPT_OFFSET] = IPOPT_MINOFF_SR;
			break;
		}
	}
}

/*
 * Process received ICMP Redirect messages.
 */
static void
icmp_redirect(ill_t *ill, mblk_t *mp)
{
	ipha_t	*ipha;
	int	iph_hdr_length;
	icmph_t	*icmph;
	ipha_t	*ipha_err;
	ire_t	*ire;
	ire_t	*prev_ire;
	ire_t	*save_ire;
	ipaddr_t  src, dst, gateway;
	iulp_t	ulp_info = { 0 };
	int	error;
	ip_stack_t *ipst;

	ASSERT(ill != NULL);
	ipst = ill->ill_ipst;

	ipha = (ipha_t *)mp->b_rptr;
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	if (((mp->b_wptr - mp->b_rptr) - iph_hdr_length) <
	    sizeof (icmph_t) + IP_SIMPLE_HDR_LENGTH) {
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInErrors);
		freemsg(mp);
		return;
	}
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	ipha_err = (ipha_t *)&icmph[1];
	src = ipha->ipha_src;
	dst = ipha_err->ipha_dst;
	gateway = icmph->icmph_rd_gateway;
	/* Make sure the new gateway is reachable somehow. */
	ire = ire_route_lookup(gateway, 0, 0, IRE_INTERFACE, NULL, NULL,
	    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	/*
	 * Make sure we had a route for the dest in question and that
	 * that route was pointing to the old gateway (the source of the
	 * redirect packet.)
	 */
	prev_ire = ire_route_lookup(dst, 0, src, 0, NULL, NULL, ALL_ZONES,
	    NULL, MATCH_IRE_GW, ipst);
	/*
	 * Check that
	 *	the redirect was not from ourselves
	 *	the new gateway and the old gateway are directly reachable
	 */
	if (!prev_ire ||
	    !ire ||
	    ire->ire_type == IRE_LOCAL) {
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInBadRedirects);
		freemsg(mp);
		if (ire != NULL)
			ire_refrele(ire);
		if (prev_ire != NULL)
			ire_refrele(prev_ire);
		return;
	}

	/*
	 * Should we use the old ULP info to create the new gateway?  From
	 * a user's perspective, we should inherit the info so that it
	 * is a "smooth" transition.  If we do not do that, then new
	 * connections going thru the new gateway will have no route metrics,
	 * which is counter-intuitive to user.  From a network point of
	 * view, this may or may not make sense even though the new gateway
	 * is still directly connected to us so the route metrics should not
	 * change much.
	 *
	 * But if the old ire_uinfo is not initialized, we do another
	 * recursive lookup on the dest using the new gateway.  There may
	 * be a route to that.  If so, use it to initialize the redirect
	 * route.
	 */
	if (prev_ire->ire_uinfo.iulp_set) {
		bcopy(&prev_ire->ire_uinfo, &ulp_info, sizeof (iulp_t));
	} else {
		ire_t *tmp_ire;
		ire_t *sire;

		tmp_ire = ire_ftable_lookup(dst, 0, gateway, 0, NULL, &sire,
		    ALL_ZONES, 0, NULL,
		    (MATCH_IRE_RECURSIVE | MATCH_IRE_GW | MATCH_IRE_DEFAULT),
		    ipst);
		if (sire != NULL) {
			bcopy(&sire->ire_uinfo, &ulp_info, sizeof (iulp_t));
			/*
			 * If sire != NULL, ire_ftable_lookup() should not
			 * return a NULL value.
			 */
			ASSERT(tmp_ire != NULL);
			ire_refrele(tmp_ire);
			ire_refrele(sire);
		} else if (tmp_ire != NULL) {
			bcopy(&tmp_ire->ire_uinfo, &ulp_info,
			    sizeof (iulp_t));
			ire_refrele(tmp_ire);
		}
	}
	if (prev_ire->ire_type == IRE_CACHE)
		ire_delete(prev_ire);
	ire_refrele(prev_ire);
	/*
	 * TODO: more precise handling for cases 0, 2, 3, the latter two
	 * require TOS routing
	 */
	switch (icmph->icmph_code) {
	case 0:
	case 1:
		/* TODO: TOS specificity for cases 2 and 3 */
	case 2:
	case 3:
		break;
	default:
		freemsg(mp);
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInBadRedirects);
		ire_refrele(ire);
		return;
	}
	/*
	 * Create a Route Association.  This will allow us to remember that
	 * someone we believe told us to use the particular gateway.
	 */
	save_ire = ire;
	ire = ire_create(
	    (uchar_t *)&dst,			/* dest addr */
	    (uchar_t *)&ip_g_all_ones,		/* mask */
	    (uchar_t *)&save_ire->ire_src_addr,	/* source addr */
	    (uchar_t *)&gateway,		/* gateway addr */
	    &save_ire->ire_max_frag,		/* max frag */
	    NULL,				/* no src nce */
	    NULL,				/* no rfq */
	    NULL,				/* no stq */
	    IRE_HOST,
	    NULL,				/* ipif */
	    0,					/* cmask */
	    0,					/* phandle */
	    0,					/* ihandle */
	    (RTF_DYNAMIC | RTF_GATEWAY | RTF_HOST),
	    &ulp_info,
	    NULL,				/* tsol_gc_t */
	    NULL,				/* gcgrp */
	    ipst);

	if (ire == NULL) {
		freemsg(mp);
		ire_refrele(save_ire);
		return;
	}
	error = ire_add(&ire, NULL, NULL, NULL, B_FALSE);
	ire_refrele(save_ire);
	atomic_inc_32(&ipst->ips_ip_redirect_cnt);

	if (error == 0) {
		ire_refrele(ire);		/* Held in ire_add_v4 */
		/* tell routing sockets that we received a redirect */
		ip_rts_change(RTM_REDIRECT, dst, gateway, IP_HOST_MASK, 0, src,
		    (RTF_DYNAMIC | RTF_GATEWAY | RTF_HOST), 0,
		    (RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_AUTHOR), ipst);
	}

	/*
	 * Delete any existing IRE_HOST type redirect ires for this destination.
	 * This together with the added IRE has the effect of
	 * modifying an existing redirect.
	 */
	prev_ire = ire_ftable_lookup(dst, 0, src, IRE_HOST, NULL, NULL,
	    ALL_ZONES, 0, NULL, (MATCH_IRE_GW | MATCH_IRE_TYPE), ipst);
	if (prev_ire != NULL) {
		if (prev_ire ->ire_flags & RTF_DYNAMIC)
			ire_delete(prev_ire);
		ire_refrele(prev_ire);
	}

	freemsg(mp);
}

/*
 * Generate an ICMP parameter problem message.
 */
static void
icmp_param_problem(queue_t *q, mblk_t *mp, uint8_t ptr, zoneid_t zoneid,
	ip_stack_t *ipst)
{
	icmph_t	icmph;
	boolean_t mctl_present;
	mblk_t *first_mp;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	if (!(mp = icmp_pkt_err_ok(mp, ipst))) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_PARAM_PROBLEM;
	icmph.icmph_pp_ptr = ptr;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutParmProbs);
	icmp_pkt(q, first_mp, &icmph, sizeof (icmph_t), mctl_present, zoneid,
	    ipst);
}

/*
 * Build and ship an IPv4 ICMP message using the packet data in mp, and
 * the ICMP header pointed to by "stuff".  (May be called as writer.)
 * Note: assumes that icmp_pkt_err_ok has been called to verify that
 * an icmp error packet can be sent.
 * Assigns an appropriate source address to the packet. If ipha_dst is
 * one of our addresses use it for source. Otherwise pick a source based
 * on a route lookup back to ipha_src.
 * Note that ipha_src must be set here since the
 * packet is likely to arrive on an ill queue in ip_wput() which will
 * not set a source address.
 */
static void
icmp_pkt(queue_t *q, mblk_t *mp, void *stuff, size_t len,
    boolean_t mctl_present, zoneid_t zoneid, ip_stack_t *ipst)
{
	ipaddr_t dst;
	icmph_t	*icmph;
	ipha_t	*ipha;
	uint_t	len_needed;
	size_t	msg_len;
	mblk_t	*mp1;
	ipaddr_t src;
	ire_t	*ire;
	mblk_t *ipsec_mp;
	ipsec_out_t	*io = NULL;

	if (mctl_present) {
		/*
		 * If it is :
		 *
		 * 1) a IPSEC_OUT, then this is caused by outbound
		 *    datagram originating on this host. IPsec processing
		 *    may or may not have been done. Refer to comments above
		 *    icmp_inbound_error_fanout for details.
		 *
		 * 2) a IPSEC_IN if we are generating a icmp_message
		 *    for an incoming datagram destined for us i.e called
		 *    from ip_fanout_send_icmp.
		 */
		ipsec_info_t *in;
		ipsec_mp = mp;
		mp = ipsec_mp->b_cont;

		in = (ipsec_info_t *)ipsec_mp->b_rptr;
		ipha = (ipha_t *)mp->b_rptr;

		ASSERT(in->ipsec_info_type == IPSEC_OUT ||
		    in->ipsec_info_type == IPSEC_IN);

		if (in->ipsec_info_type == IPSEC_IN) {
			/*
			 * Convert the IPSEC_IN to IPSEC_OUT.
			 */
			if (!ipsec_in_to_out(ipsec_mp, ipha, NULL)) {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsOutDiscards);
				return;
			}
			io = (ipsec_out_t *)ipsec_mp->b_rptr;
		} else {
			ASSERT(in->ipsec_info_type == IPSEC_OUT);
			io = (ipsec_out_t *)in;
			/*
			 * Clear out ipsec_out_proc_begin, so we do a fresh
			 * ire lookup.
			 */
			io->ipsec_out_proc_begin = B_FALSE;
		}
		ASSERT(zoneid == io->ipsec_out_zoneid);
		ASSERT(zoneid != ALL_ZONES);
	} else {
		/*
		 * This is in clear. The icmp message we are building
		 * here should go out in clear.
		 *
		 * Pardon the convolution of it all, but it's easier to
		 * allocate a "use cleartext" IPSEC_IN message and convert
		 * it than it is to allocate a new one.
		 */
		ipsec_in_t *ii;
		ASSERT(DB_TYPE(mp) == M_DATA);
		ipsec_mp = ipsec_in_alloc(B_TRUE, ipst->ips_netstack);
		if (ipsec_mp == NULL) {
			freemsg(mp);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			return;
		}
		ii = (ipsec_in_t *)ipsec_mp->b_rptr;

		/* This is not a secure packet */
		ii->ipsec_in_secure = B_FALSE;
		/*
		 * For trusted extensions using a shared IP address we can
		 * send using any zoneid.
		 */
		if (zoneid == ALL_ZONES)
			ii->ipsec_in_zoneid = GLOBAL_ZONEID;
		else
			ii->ipsec_in_zoneid = zoneid;
		ipsec_mp->b_cont = mp;
		ipha = (ipha_t *)mp->b_rptr;
		/*
		 * Convert the IPSEC_IN to IPSEC_OUT.
		 */
		if (!ipsec_in_to_out(ipsec_mp, ipha, NULL)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			return;
		}
		io = (ipsec_out_t *)ipsec_mp->b_rptr;
	}

	/* Remember our eventual destination */
	dst = ipha->ipha_src;

	ire = ire_route_lookup(ipha->ipha_dst, 0, 0, (IRE_LOCAL|IRE_LOOPBACK),
	    NULL, NULL, zoneid, NULL, MATCH_IRE_TYPE, ipst);
	if (ire != NULL &&
	    (ire->ire_zoneid == zoneid || ire->ire_zoneid == ALL_ZONES)) {
		src = ipha->ipha_dst;
	} else {
		if (ire != NULL)
			ire_refrele(ire);
		ire = ire_route_lookup(dst, 0, 0, 0, NULL, NULL, zoneid, NULL,
		    (MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE|MATCH_IRE_ZONEONLY),
		    ipst);
		if (ire == NULL) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutNoRoutes);
			freemsg(ipsec_mp);
			return;
		}
		src = ire->ire_src_addr;
	}

	if (ire != NULL)
		ire_refrele(ire);

	/*
	 * Check if we can send back more then 8 bytes in addition to
	 * the IP header.  We try to send 64 bytes of data and the internal
	 * header in the special cases of ipv4 encapsulated ipv4 or ipv6.
	 */
	len_needed = IPH_HDR_LENGTH(ipha);
	if (ipha->ipha_protocol == IPPROTO_ENCAP ||
	    ipha->ipha_protocol == IPPROTO_IPV6) {

		if (!pullupmsg(mp, -1)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			freemsg(ipsec_mp);
			return;
		}
		ipha = (ipha_t *)mp->b_rptr;

		if (ipha->ipha_protocol == IPPROTO_ENCAP) {
			len_needed += IPH_HDR_LENGTH(((uchar_t *)ipha +
			    len_needed));
		} else {
			ip6_t *ip6h = (ip6_t *)((uchar_t *)ipha + len_needed);

			ASSERT(ipha->ipha_protocol == IPPROTO_IPV6);
			len_needed += ip_hdr_length_v6(mp, ip6h);
		}
	}
	len_needed += ipst->ips_ip_icmp_return;
	msg_len = msgdsize(mp);
	if (msg_len > len_needed) {
		(void) adjmsg(mp, len_needed - msg_len);
		msg_len = len_needed;
	}
	mp1 = allocb_tmpl(sizeof (icmp_ipha) + len, mp);
	if (mp1 == NULL) {
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutErrors);
		freemsg(ipsec_mp);
		return;
	}
	mp1->b_cont = mp;
	mp = mp1;
	ASSERT(ipsec_mp->b_datap->db_type == M_CTL &&
	    ipsec_mp->b_rptr == (uint8_t *)io &&
	    io->ipsec_out_type == IPSEC_OUT);
	ipsec_mp->b_cont = mp;

	/*
	 * Set ipsec_out_icmp_loopback so we can let the ICMP messages this
	 * node generates be accepted in peace by all on-host destinations.
	 * If we do NOT assume that all on-host destinations trust
	 * self-generated ICMP messages, then rework here, ip6.c, and spd.c.
	 * (Look for ipsec_out_icmp_loopback).
	 */
	io->ipsec_out_icmp_loopback = B_TRUE;

	ipha = (ipha_t *)mp->b_rptr;
	mp1->b_wptr = (uchar_t *)ipha + (sizeof (icmp_ipha) + len);
	*ipha = icmp_ipha;
	ipha->ipha_src = src;
	ipha->ipha_dst = dst;
	ipha->ipha_ttl = ipst->ips_ip_def_ttl;
	msg_len += sizeof (icmp_ipha) + len;
	if (msg_len > IP_MAXPACKET) {
		(void) adjmsg(mp, IP_MAXPACKET - msg_len);
		msg_len = IP_MAXPACKET;
	}
	ipha->ipha_length = htons((uint16_t)msg_len);
	icmph = (icmph_t *)&ipha[1];
	bcopy(stuff, icmph, len);
	icmph->icmph_checksum = 0;
	icmph->icmph_checksum = IP_CSUM(mp, (int32_t)sizeof (ipha_t), 0);
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutMsgs);
	put(q, ipsec_mp);
}

/*
 * Determine if an ICMP error packet can be sent given the rate limit.
 * The limit consists of an average frequency (icmp_pkt_err_interval measured
 * in milliseconds) and a burst size. Burst size number of packets can
 * be sent arbitrarely closely spaced.
 * The state is tracked using two variables to implement an approximate
 * token bucket filter:
 *	icmp_pkt_err_last - lbolt value when the last burst started
 *	icmp_pkt_err_sent - number of packets sent in current burst
 */
boolean_t
icmp_err_rate_limit(ip_stack_t *ipst)
{
	clock_t now = TICK_TO_MSEC(lbolt);
	uint_t refilled; /* Number of packets refilled in tbf since last */
	/* Guard against changes by loading into local variable */
	uint_t err_interval = ipst->ips_ip_icmp_err_interval;

	if (err_interval == 0)
		return (B_FALSE);

	if (ipst->ips_icmp_pkt_err_last > now) {
		/* 100HZ lbolt in ms for 32bit arch wraps every 49.7 days */
		ipst->ips_icmp_pkt_err_last = 0;
		ipst->ips_icmp_pkt_err_sent = 0;
	}
	/*
	 * If we are in a burst update the token bucket filter.
	 * Update the "last" time to be close to "now" but make sure
	 * we don't loose precision.
	 */
	if (ipst->ips_icmp_pkt_err_sent != 0) {
		refilled = (now - ipst->ips_icmp_pkt_err_last)/err_interval;
		if (refilled > ipst->ips_icmp_pkt_err_sent) {
			ipst->ips_icmp_pkt_err_sent = 0;
		} else {
			ipst->ips_icmp_pkt_err_sent -= refilled;
			ipst->ips_icmp_pkt_err_last += refilled * err_interval;
		}
	}
	if (ipst->ips_icmp_pkt_err_sent == 0) {
		/* Start of new burst */
		ipst->ips_icmp_pkt_err_last = now;
	}
	if (ipst->ips_icmp_pkt_err_sent < ipst->ips_ip_icmp_err_burst) {
		ipst->ips_icmp_pkt_err_sent++;
		ip1dbg(("icmp_err_rate_limit: %d sent in burst\n",
		    ipst->ips_icmp_pkt_err_sent));
		return (B_FALSE);
	}
	ip1dbg(("icmp_err_rate_limit: dropped\n"));
	return (B_TRUE);
}

/*
 * Check if it is ok to send an IPv4 ICMP error packet in
 * response to the IPv4 packet in mp.
 * Free the message and return null if no
 * ICMP error packet should be sent.
 */
static mblk_t *
icmp_pkt_err_ok(mblk_t *mp, ip_stack_t *ipst)
{
	icmph_t	*icmph;
	ipha_t	*ipha;
	uint_t	len_needed;
	ire_t	*src_ire;
	ire_t	*dst_ire;

	if (!mp)
		return (NULL);
	ipha = (ipha_t *)mp->b_rptr;
	if (ip_csum_hdr(ipha)) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInCksumErrs);
		freemsg(mp);
		return (NULL);
	}
	src_ire = ire_ctable_lookup(ipha->ipha_dst, 0, IRE_BROADCAST,
	    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	dst_ire = ire_ctable_lookup(ipha->ipha_src, 0, IRE_BROADCAST,
	    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	if (src_ire != NULL || dst_ire != NULL ||
	    CLASSD(ipha->ipha_dst) ||
	    CLASSD(ipha->ipha_src) ||
	    (ntohs(ipha->ipha_fragment_offset_and_flags) & IPH_OFFSET)) {
		/* Note: only errors to the fragment with offset 0 */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
		freemsg(mp);
		if (src_ire != NULL)
			ire_refrele(src_ire);
		if (dst_ire != NULL)
			ire_refrele(dst_ire);
		return (NULL);
	}
	if (ipha->ipha_protocol == IPPROTO_ICMP) {
		/*
		 * Check the ICMP type.  RFC 1122 sez:  don't send ICMP
		 * errors in response to any ICMP errors.
		 */
		len_needed = IPH_HDR_LENGTH(ipha) + ICMPH_SIZE;
		if (mp->b_wptr - mp->b_rptr < len_needed) {
			if (!pullupmsg(mp, len_needed)) {
				BUMP_MIB(&ipst->ips_icmp_mib, icmpInErrors);
				freemsg(mp);
				return (NULL);
			}
			ipha = (ipha_t *)mp->b_rptr;
		}
		icmph = (icmph_t *)
		    (&((char *)ipha)[IPH_HDR_LENGTH(ipha)]);
		switch (icmph->icmph_type) {
		case ICMP_DEST_UNREACHABLE:
		case ICMP_SOURCE_QUENCH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAM_PROBLEM:
		case ICMP_REDIRECT:
			BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
			freemsg(mp);
			return (NULL);
		default:
			break;
		}
	}
	/*
	 * If this is a labeled system, then check to see if we're allowed to
	 * send a response to this particular sender.  If not, then just drop.
	 */
	if (is_system_labeled() && !tsol_can_reply_error(mp)) {
		ip2dbg(("icmp_pkt_err_ok: can't respond to packet\n"));
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
		freemsg(mp);
		return (NULL);
	}
	if (icmp_err_rate_limit(ipst)) {
		/*
		 * Only send ICMP error packets every so often.
		 * This should be done on a per port/source basis,
		 * but for now this will suffice.
		 */
		freemsg(mp);
		return (NULL);
	}
	return (mp);
}

/*
 * Generate an ICMP redirect message.
 */
static void
icmp_send_redirect(queue_t *q, mblk_t *mp, ipaddr_t gateway, ip_stack_t *ipst)
{
	icmph_t	icmph;

	/*
	 * We are called from ip_rput where we could
	 * not have attached an IPSEC_IN.
	 */
	ASSERT(mp->b_datap->db_type == M_DATA);

	if (!(mp = icmp_pkt_err_ok(mp, ipst))) {
		return;
	}

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_REDIRECT;
	icmph.icmph_code = 1;
	icmph.icmph_rd_gateway = gateway;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutRedirects);
	/* Redirects sent by router, and router is global zone */
	icmp_pkt(q, mp, &icmph, sizeof (icmph_t), B_FALSE, GLOBAL_ZONEID, ipst);
}

/*
 * Generate an ICMP time exceeded message.
 */
void
icmp_time_exceeded(queue_t *q, mblk_t *mp, uint8_t code, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	icmph_t	icmph;
	boolean_t mctl_present;
	mblk_t *first_mp;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	if (!(mp = icmp_pkt_err_ok(mp, ipst))) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_TIME_EXCEEDED;
	icmph.icmph_code = code;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutTimeExcds);
	icmp_pkt(q, first_mp, &icmph, sizeof (icmph_t), mctl_present, zoneid,
	    ipst);
}

/*
 * Generate an ICMP unreachable message.
 */
void
icmp_unreachable(queue_t *q, mblk_t *mp, uint8_t code, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	icmph_t	icmph;
	mblk_t *first_mp;
	boolean_t mctl_present;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	if (!(mp = icmp_pkt_err_ok(mp, ipst))) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_DEST_UNREACHABLE;
	icmph.icmph_code = code;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDestUnreachs);
	ip2dbg(("send icmp destination unreachable code %d\n", code));
	icmp_pkt(q, first_mp, (char *)&icmph, sizeof (icmph_t), mctl_present,
	    zoneid, ipst);
}

/*
 * Attempt to start recovery of an IPv4 interface that's been shut down as a
 * duplicate.  As long as someone else holds the address, the interface will
 * stay down.  When that conflict goes away, the interface is brought back up.
 * This is done so that accidental shutdowns of addresses aren't made
 * permanent.  Your server will recover from a failure.
 *
 * For DHCP, recovery is not done in the kernel.  Instead, it's handled by a
 * user space process (dhcpagent).
 *
 * Recovery completes if ARP reports that the address is now ours (via
 * AR_CN_READY).  In that case, we go to ip_arp_excl to finish the operation.
 *
 * This function is entered on a timer expiry; the ID is in ipif_recovery_id.
 */
static void
ipif_dup_recovery(void *arg)
{
	ipif_t *ipif = arg;
	ill_t *ill = ipif->ipif_ill;
	mblk_t *arp_add_mp;
	mblk_t *arp_del_mp;
	area_t *area;
	ip_stack_t *ipst = ill->ill_ipst;

	ipif->ipif_recovery_id = 0;

	/*
	 * No lock needed for moving or condemned check, as this is just an
	 * optimization.
	 */
	if (ill->ill_arp_closing || !(ipif->ipif_flags & IPIF_DUPLICATE) ||
	    (ipif->ipif_flags & IPIF_POINTOPOINT) ||
	    (ipif->ipif_state_flags & (IPIF_MOVING | IPIF_CONDEMNED))) {
		/* No reason to try to bring this address back. */
		return;
	}

	if ((arp_add_mp = ipif_area_alloc(ipif)) == NULL)
		goto alloc_fail;

	if (ipif->ipif_arp_del_mp == NULL) {
		if ((arp_del_mp = ipif_ared_alloc(ipif)) == NULL)
			goto alloc_fail;
		ipif->ipif_arp_del_mp = arp_del_mp;
	}

	/* Setting the 'unverified' flag restarts DAD */
	area = (area_t *)arp_add_mp->b_rptr;
	area->area_flags = ACE_F_PERMANENT | ACE_F_PUBLISH | ACE_F_MYADDR |
	    ACE_F_UNVERIFIED;
	putnext(ill->ill_rq, arp_add_mp);
	return;

alloc_fail:
	/*
	 * On allocation failure, just restart the timer.  Note that the ipif
	 * is down here, so no other thread could be trying to start a recovery
	 * timer.  The ill_lock protects the condemned flag and the recovery
	 * timer ID.
	 */
	freemsg(arp_add_mp);
	mutex_enter(&ill->ill_lock);
	if (ipst->ips_ip_dup_recovery > 0 && ipif->ipif_recovery_id == 0 &&
	    !(ipif->ipif_state_flags & IPIF_CONDEMNED)) {
		ipif->ipif_recovery_id = timeout(ipif_dup_recovery, ipif,
		    MSEC_TO_TICK(ipst->ips_ip_dup_recovery));
	}
	mutex_exit(&ill->ill_lock);
}

/*
 * This is for exclusive changes due to ARP.  Either tear down an interface due
 * to AR_CN_FAILED and AR_CN_BOGON, or bring one up for successful recovery.
 */
/* ARGSUSED */
static void
ip_arp_excl(ipsq_t *ipsq, queue_t *rq, mblk_t *mp, void *dummy_arg)
{
	ill_t	*ill = rq->q_ptr;
	arh_t *arh;
	ipaddr_t src;
	ipif_t	*ipif;
	char ibuf[LIFNAMSIZ + 10];	/* 10 digits for logical i/f number */
	char hbuf[MAC_STR_LEN];
	char sbuf[INET_ADDRSTRLEN];
	const char *failtype;
	boolean_t bring_up;
	ip_stack_t *ipst = ill->ill_ipst;

	switch (((arcn_t *)mp->b_rptr)->arcn_code) {
	case AR_CN_READY:
		failtype = NULL;
		bring_up = B_TRUE;
		break;
	case AR_CN_FAILED:
		failtype = "in use";
		bring_up = B_FALSE;
		break;
	default:
		failtype = "claimed";
		bring_up = B_FALSE;
		break;
	}

	arh = (arh_t *)mp->b_cont->b_rptr;
	bcopy((char *)&arh[1] + arh->arh_hlen, &src, IP_ADDR_LEN);

	(void) mac_colon_addr((uint8_t *)(arh + 1), arh->arh_hlen, hbuf,
	    sizeof (hbuf));
	(void) ip_dot_addr(src, sbuf);
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {

		if ((ipif->ipif_flags & IPIF_POINTOPOINT) ||
		    ipif->ipif_lcl_addr != src) {
			continue;
		}

		/*
		 * If we failed on a recovery probe, then restart the timer to
		 * try again later.
		 */
		if (!bring_up && (ipif->ipif_flags & IPIF_DUPLICATE) &&
		    !(ipif->ipif_flags & (IPIF_DHCPRUNNING|IPIF_TEMPORARY)) &&
		    ill->ill_net_type == IRE_IF_RESOLVER &&
		    !(ipif->ipif_state_flags & IPIF_CONDEMNED) &&
		    ipst->ips_ip_dup_recovery > 0 &&
		    ipif->ipif_recovery_id == 0) {
			ipif->ipif_recovery_id = timeout(ipif_dup_recovery,
			    ipif, MSEC_TO_TICK(ipst->ips_ip_dup_recovery));
			continue;
		}

		/*
		 * If what we're trying to do has already been done, then do
		 * nothing.
		 */
		if (bring_up == ((ipif->ipif_flags & IPIF_UP) != 0))
			continue;

		ipif_get_name(ipif, ibuf, sizeof (ibuf));

		if (failtype == NULL) {
			cmn_err(CE_NOTE, "recovered address %s on %s", sbuf,
			    ibuf);
		} else {
			cmn_err(CE_WARN, "%s has duplicate address %s (%s "
			    "by %s); disabled", ibuf, sbuf, failtype, hbuf);
		}

		if (bring_up) {
			ASSERT(ill->ill_dl_up);
			/*
			 * Free up the ARP delete message so we can allocate
			 * a fresh one through the normal path.
			 */
			freemsg(ipif->ipif_arp_del_mp);
			ipif->ipif_arp_del_mp = NULL;
			if (ipif_resolver_up(ipif, Res_act_initial) !=
			    EINPROGRESS) {
				ipif->ipif_addr_ready = 1;
				(void) ipif_up_done(ipif);
			}
			continue;
		}

		mutex_enter(&ill->ill_lock);
		ASSERT(!(ipif->ipif_flags & IPIF_DUPLICATE));
		ipif->ipif_flags |= IPIF_DUPLICATE;
		ill->ill_ipif_dup_count++;
		mutex_exit(&ill->ill_lock);
		/*
		 * Already exclusive on the ill; no need to handle deferred
		 * processing here.
		 */
		(void) ipif_down(ipif, NULL, NULL);
		ipif_down_tail(ipif);
		mutex_enter(&ill->ill_lock);
		if (!(ipif->ipif_flags & (IPIF_DHCPRUNNING|IPIF_TEMPORARY)) &&
		    ill->ill_net_type == IRE_IF_RESOLVER &&
		    !(ipif->ipif_state_flags & IPIF_CONDEMNED) &&
		    ipst->ips_ip_dup_recovery > 0) {
			ipif->ipif_recovery_id = timeout(ipif_dup_recovery,
			    ipif, MSEC_TO_TICK(ipst->ips_ip_dup_recovery));
		}
		mutex_exit(&ill->ill_lock);
	}
	freemsg(mp);
}

/* ARGSUSED */
static void
ip_arp_defend(ipsq_t *ipsq, queue_t *rq, mblk_t *mp, void *dummy_arg)
{
	ill_t	*ill = rq->q_ptr;
	arh_t *arh;
	ipaddr_t src;
	ipif_t	*ipif;

	arh = (arh_t *)mp->b_cont->b_rptr;
	bcopy((char *)&arh[1] + arh->arh_hlen, &src, IP_ADDR_LEN);
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if ((ipif->ipif_flags & IPIF_UP) && ipif->ipif_lcl_addr == src)
			(void) ipif_resolver_up(ipif, Res_act_defend);
	}
	freemsg(mp);
}

/*
 * News from ARP.  ARP sends notification of interesting events down
 * to its clients using M_CTL messages with the interesting ARP packet
 * attached via b_cont.
 * The interesting event from a device comes up the corresponding ARP-IP-DEV
 * queue as opposed to ARP sending the message to all the clients, i.e. all
 * its ARP-IP-DEV instances. Thus, for AR_CN_ANNOUNCE, we must walk the cache
 * table if a cache IRE is found to delete all the entries for the address in
 * the packet.
 */
static void
ip_arp_news(queue_t *q, mblk_t *mp)
{
	arcn_t		*arcn;
	arh_t		*arh;
	ire_t		*ire = NULL;
	char		hbuf[MAC_STR_LEN];
	char		sbuf[INET_ADDRSTRLEN];
	ipaddr_t	src;
	in6_addr_t	v6src;
	boolean_t	isv6 = B_FALSE;
	ipif_t		*ipif;
	ill_t		*ill;
	ip_stack_t	*ipst;

	if (CONN_Q(q)) {
		conn_t *connp = Q_TO_CONN(q);

		ipst = connp->conn_netstack->netstack_ip;
	} else {
		ill_t *ill = (ill_t *)q->q_ptr;

		ipst = ill->ill_ipst;
	}

	if ((mp->b_wptr - mp->b_rptr) < sizeof (arcn_t)	|| !mp->b_cont) {
		if (q->q_next) {
			putnext(q, mp);
		} else
			freemsg(mp);
		return;
	}
	arh = (arh_t *)mp->b_cont->b_rptr;
	/* Is it one we are interested in? */
	if (BE16_TO_U16(arh->arh_proto) == IP6_DL_SAP) {
		isv6 = B_TRUE;
		bcopy((char *)&arh[1] + (arh->arh_hlen & 0xFF), &v6src,
		    IPV6_ADDR_LEN);
	} else if (BE16_TO_U16(arh->arh_proto) == IP_ARP_PROTO_TYPE) {
		bcopy((char *)&arh[1] + (arh->arh_hlen & 0xFF), &src,
		    IP_ADDR_LEN);
	} else {
		freemsg(mp);
		return;
	}

	ill = q->q_ptr;

	arcn = (arcn_t *)mp->b_rptr;
	switch (arcn->arcn_code) {
	case AR_CN_BOGON:
		/*
		 * Someone is sending ARP packets with a source protocol
		 * address that we have published and for which we believe our
		 * entry is authoritative and (when ill_arp_extend is set)
		 * verified to be unique on the network.
		 *
		 * The ARP module internally handles the cases where the sender
		 * is just probing (for DAD) and where the hardware address of
		 * a non-authoritative entry has changed.  Thus, these are the
		 * real conflicts, and we have to do resolution.
		 *
		 * We back away quickly from the address if it's from DHCP or
		 * otherwise temporary and hasn't been used recently (or at
		 * all).  We'd like to include "deprecated" addresses here as
		 * well (as there's no real reason to defend something we're
		 * discarding), but IPMP "reuses" this flag to mean something
		 * other than the standard meaning.
		 *
		 * If the ARP module above is not extended (meaning that it
		 * doesn't know how to defend the address), then we just log
		 * the problem as we always did and continue on.  It's not
		 * right, but there's little else we can do, and those old ATM
		 * users are going away anyway.
		 */
		(void) mac_colon_addr((uint8_t *)(arh + 1), arh->arh_hlen,
		    hbuf, sizeof (hbuf));
		(void) ip_dot_addr(src, sbuf);
		if (isv6) {
			ire = ire_cache_lookup_v6(&v6src, ALL_ZONES, NULL,
			    ipst);
		} else {
			ire = ire_cache_lookup(src, ALL_ZONES, NULL, ipst);
		}
		if (ire != NULL	&& IRE_IS_LOCAL(ire)) {
			uint32_t now;
			uint32_t maxage;
			clock_t lused;
			uint_t maxdefense;
			uint_t defs;

			/*
			 * First, figure out if this address hasn't been used
			 * in a while.  If it hasn't, then it's a better
			 * candidate for abandoning.
			 */
			ipif = ire->ire_ipif;
			ASSERT(ipif != NULL);
			now = gethrestime_sec();
			maxage = now - ire->ire_create_time;
			if (maxage > ipst->ips_ip_max_temp_idle)
				maxage = ipst->ips_ip_max_temp_idle;
			lused = drv_hztousec(ddi_get_lbolt() -
			    ire->ire_last_used_time) / MICROSEC + 1;
			if (lused >= maxage && (ipif->ipif_flags &
			    (IPIF_DHCPRUNNING | IPIF_TEMPORARY)))
				maxdefense = ipst->ips_ip_max_temp_defend;
			else
				maxdefense = ipst->ips_ip_max_defend;

			/*
			 * Now figure out how many times we've defended
			 * ourselves.  Ignore defenses that happened long in
			 * the past.
			 */
			mutex_enter(&ire->ire_lock);
			if ((defs = ire->ire_defense_count) > 0 &&
			    now - ire->ire_defense_time >
			    ipst->ips_ip_defend_interval) {
				ire->ire_defense_count = defs = 0;
			}
			ire->ire_defense_count++;
			ire->ire_defense_time = now;
			mutex_exit(&ire->ire_lock);
			ill_refhold(ill);
			ire_refrele(ire);

			/*
			 * If we've defended ourselves too many times already,
			 * then give up and tear down the interface(s) using
			 * this address.  Otherwise, defend by sending out a
			 * gratuitous ARP.
			 */
			if (defs >= maxdefense && ill->ill_arp_extend) {
				qwriter_ip(ill, q, mp, ip_arp_excl, NEW_OP,
				    B_FALSE);
			} else {
				cmn_err(CE_WARN,
				    "node %s is using our IP address %s on %s",
				    hbuf, sbuf, ill->ill_name);
				/*
				 * If this is an old (ATM) ARP module, then
				 * don't try to defend the address.  Remain
				 * compatible with the old behavior.  Defend
				 * only with new ARP.
				 */
				if (ill->ill_arp_extend) {
					qwriter_ip(ill, q, mp, ip_arp_defend,
					    NEW_OP, B_FALSE);
				} else {
					ill_refrele(ill);
				}
			}
			return;
		}
		cmn_err(CE_WARN,
		    "proxy ARP problem?  Node '%s' is using %s on %s",
		    hbuf, sbuf, ill->ill_name);
		if (ire != NULL)
			ire_refrele(ire);
		break;
	case AR_CN_ANNOUNCE:
		if (isv6) {
			/*
			 * For XRESOLV interfaces.
			 * Delete the IRE cache entry and NCE for this
			 * v6 address
			 */
			ip_ire_clookup_and_delete_v6(&v6src, ipst);
			/*
			 * If v6src is a non-zero, it's a router address
			 * as below. Do the same sort of thing to clean
			 * out off-net IRE_CACHE entries that go through
			 * the router.
			 */
			if (!IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
				ire_walk_v6(ire_delete_cache_gw_v6,
				    (char *)&v6src, ALL_ZONES, ipst);
			}
		} else {
			nce_hw_map_t hwm;

			/*
			 * ARP gives us a copy of any packet where it thinks
			 * the address has changed, so that we can update our
			 * caches.  We're responsible for caching known answers
			 * in the current design.  We check whether the
			 * hardware address really has changed in all of our
			 * entries that have cached this mapping, and if so, we
			 * blow them away.  This way we will immediately pick
			 * up the rare case of a host changing hardware
			 * address.
			 */
			if (src == 0)
				break;
			hwm.hwm_addr = src;
			hwm.hwm_hwlen = arh->arh_hlen;
			hwm.hwm_hwaddr = (uchar_t *)(arh + 1);
			NDP_HW_CHANGE_INCR(ipst->ips_ndp4);
			ndp_walk_common(ipst->ips_ndp4, NULL,
			    (pfi_t)nce_delete_hw_changed, &hwm, ALL_ZONES);
			NDP_HW_CHANGE_DECR(ipst->ips_ndp4);
		}
		break;
	case AR_CN_READY:
		/* No external v6 resolver has a contract to use this */
		if (isv6)
			break;
		/* If the link is down, we'll retry this later */
		if (!(ill->ill_phyint->phyint_flags & PHYI_RUNNING))
			break;
		ipif = ipif_lookup_addr(src, ill, ALL_ZONES, NULL, NULL,
		    NULL, NULL, ipst);
		if (ipif != NULL) {
			/*
			 * If this is a duplicate recovery, then we now need to
			 * go exclusive to bring this thing back up.
			 */
			if ((ipif->ipif_flags & (IPIF_UP|IPIF_DUPLICATE)) ==
			    IPIF_DUPLICATE) {
				ipif_refrele(ipif);
				ill_refhold(ill);
				qwriter_ip(ill, q, mp, ip_arp_excl, NEW_OP,
				    B_FALSE);
				return;
			}
			/*
			 * If this is the first notice that this address is
			 * ready, then let the user know now.
			 */
			if ((ipif->ipif_flags & IPIF_UP) &&
			    !ipif->ipif_addr_ready) {
				ipif_mask_reply(ipif);
				ipif_up_notify(ipif);
			}
			ipif->ipif_addr_ready = 1;
			ipif_refrele(ipif);
		}
		ire = ire_cache_lookup(src, ALL_ZONES, MBLK_GETLABEL(mp), ipst);
		if (ire != NULL) {
			ire->ire_defense_count = 0;
			ire_refrele(ire);
		}
		break;
	case AR_CN_FAILED:
		/* No external v6 resolver has a contract to use this */
		if (isv6)
			break;
		ill_refhold(ill);
		qwriter_ip(ill, q, mp, ip_arp_excl, NEW_OP, B_FALSE);
		return;
	}
	freemsg(mp);
}

/*
 * Create a mblk suitable for carrying the interface index and/or source link
 * address. This mblk is tagged as an M_CTL and is sent to ULP. This is used
 * when the IP_RECVIF and/or IP_RECVSLLA socket option is set by the user
 * application.
 */
mblk_t *
ip_add_info(mblk_t *data_mp, ill_t *ill, uint_t flags, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	mblk_t		*mp;
	ip_pktinfo_t	*pinfo;
	ipha_t *ipha;
	struct ether_header *pether;

	mp = allocb(sizeof (ip_pktinfo_t), BPRI_MED);
	if (mp == NULL) {
		ip1dbg(("ip_add_info: allocation failure.\n"));
		return (data_mp);
	}

	ipha	= (ipha_t *)data_mp->b_rptr;
	pinfo = (ip_pktinfo_t *)mp->b_rptr;
	bzero(pinfo, sizeof (ip_pktinfo_t));
	pinfo->ip_pkt_flags = (uchar_t)flags;
	pinfo->ip_pkt_ulp_type = IN_PKTINFO;	/* Tell ULP what type of info */

	if (flags & (IPF_RECVIF | IPF_RECVADDR))
		pinfo->ip_pkt_ifindex = ill->ill_phyint->phyint_ifindex;
	if (flags & IPF_RECVADDR) {
		ipif_t	*ipif;
		ire_t	*ire;

		/*
		 * Only valid for V4
		 */
		ASSERT((ipha->ipha_version_and_hdr_length & 0xf0) ==
		    (IPV4_VERSION << 4));

		ipif = ipif_get_next_ipif(NULL, ill);
		if (ipif != NULL) {
			/*
			 * Since a decision has already been made to deliver the
			 * packet, there is no need to test for SECATTR and
			 * ZONEONLY.
			 * When a multicast packet is transmitted
			 * a cache entry is created for the multicast address.
			 * When delivering a copy of the packet or when new
			 * packets are received we do not want to match on the
			 * cached entry so explicitly match on
			 * IRE_LOCAL and IRE_LOOPBACK
			 */
			ire = ire_ctable_lookup(ipha->ipha_dst, 0,
			    IRE_LOCAL | IRE_LOOPBACK,
			    ipif, zoneid, NULL,
			    MATCH_IRE_TYPE | MATCH_IRE_ILL_GROUP, ipst);
			if (ire == NULL) {
				/*
				 * packet must have come on a different
				 * interface.
				 * Since a decision has already been made to
				 * deliver the packet, there is no need to test
				 * for SECATTR and ZONEONLY.
				 * Only match on local and broadcast ire's.
				 * See detailed comment above.
				 */
				ire = ire_ctable_lookup(ipha->ipha_dst, 0,
				    IRE_LOCAL | IRE_LOOPBACK, ipif, zoneid,
				    NULL, MATCH_IRE_TYPE, ipst);
			}

			if (ire == NULL) {
				/*
				 * This is either a multicast packet or
				 * the address has been removed since
				 * the packet was received.
				 * Return INADDR_ANY so that normal source
				 * selection occurs for the response.
				 */

				pinfo->ip_pkt_match_addr.s_addr = INADDR_ANY;
			} else {
				pinfo->ip_pkt_match_addr.s_addr =
				    ire->ire_src_addr;
				ire_refrele(ire);
			}
			ipif_refrele(ipif);
		} else {
			pinfo->ip_pkt_match_addr.s_addr = INADDR_ANY;
		}
	}

	pether = (struct ether_header *)((char *)ipha
	    - sizeof (struct ether_header));
	/*
	 * Make sure the interface is an ethernet type, since this option
	 * is currently supported only on this type of interface. Also make
	 * sure we are pointing correctly above db_base.
	 */

	if ((flags & IPF_RECVSLLA) &&
	    ((uchar_t *)pether >= data_mp->b_datap->db_base) &&
	    (ill->ill_type == IFT_ETHER) &&
	    (ill->ill_net_type == IRE_IF_RESOLVER)) {

		pinfo->ip_pkt_slla.sdl_type = IFT_ETHER;
		bcopy((uchar_t *)pether->ether_shost.ether_addr_octet,
		    (uchar_t *)pinfo->ip_pkt_slla.sdl_data, ETHERADDRL);
	} else {
		/*
		 * Clear the bit. Indicate to upper layer that IP is not
		 * sending this ancillary info.
		 */
		pinfo->ip_pkt_flags = pinfo->ip_pkt_flags & ~IPF_RECVSLLA;
	}

	mp->b_datap->db_type = M_CTL;
	mp->b_wptr += sizeof (ip_pktinfo_t);
	mp->b_cont = data_mp;

	return (mp);
}

/*
 * Latch in the IPsec state for a stream based on the ipsec_in_t passed in as
 * part of the bind request.
 */

boolean_t
ip_bind_ipsec_policy_set(conn_t *connp, mblk_t *policy_mp)
{
	ipsec_in_t *ii;

	ASSERT(policy_mp != NULL);
	ASSERT(policy_mp->b_datap->db_type == IPSEC_POLICY_SET);

	ii = (ipsec_in_t *)policy_mp->b_rptr;
	ASSERT(ii->ipsec_in_type == IPSEC_IN);

	connp->conn_policy = ii->ipsec_in_policy;
	ii->ipsec_in_policy = NULL;

	if (ii->ipsec_in_action != NULL) {
		if (connp->conn_latch == NULL) {
			connp->conn_latch = iplatch_create();
			if (connp->conn_latch == NULL)
				return (B_FALSE);
		}
		ipsec_latch_inbound(connp->conn_latch, ii);
	}
	return (B_TRUE);
}

/*
 * Upper level protocols (ULP) pass through bind requests to IP for inspection
 * and to arrange for power-fanout assist.  The ULP is identified by
 * adding a single byte at the end of the original bind message.
 * A ULP other than UDP or TCP that wishes to be recognized passes
 * down a bind with a zero length address.
 *
 * The binding works as follows:
 * - A zero byte address means just bind to the protocol.
 * - A four byte address is treated as a request to validate
 *   that the address is a valid local address, appropriate for
 *   an application to bind to. This does not affect any fanout
 *   information in IP.
 * - A sizeof sin_t byte address is used to bind to only the local address
 *   and port.
 * - A sizeof ipa_conn_t byte address contains complete fanout information
 *   consisting of local and remote addresses and ports.  In
 *   this case, the addresses are both validated as appropriate
 *   for this operation, and, if so, the information is retained
 *   for use in the inbound fanout.
 *
 * The ULP (except in the zero-length bind) can append an
 * additional mblk of db_type IRE_DB_REQ_TYPE or IPSEC_POLICY_SET to the
 * T_BIND_REQ/O_T_BIND_REQ. IRE_DB_REQ_TYPE indicates that the ULP wants
 * a copy of the source or destination IRE (source for local bind;
 * destination for complete bind). IPSEC_POLICY_SET indicates that the
 * policy information contained should be copied on to the conn.
 *
 * NOTE : Only one of IRE_DB_REQ_TYPE or IPSEC_POLICY_SET can be present.
 */
mblk_t *
ip_bind_v4(queue_t *q, mblk_t *mp, conn_t *connp)
{
	ssize_t		len;
	struct T_bind_req	*tbr;
	sin_t		*sin;
	ipa_conn_t	*ac;
	uchar_t		*ucp;
	mblk_t		*mp1;
	boolean_t	ire_requested;
	boolean_t	ipsec_policy_set = B_FALSE;
	int		error = 0;
	int		protocol;
	ipa_conn_x_t	*acx;

	ASSERT(!connp->conn_af_isv6);
	connp->conn_pkt_isv6 = B_FALSE;

	len = MBLKL(mp);
	if (len < (sizeof (*tbr) + 1)) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "ip_bind: bogus msg, len %ld", len);
		/* XXX: Need to return something better */
		goto bad_addr;
	}
	/* Back up and extract the protocol identifier. */
	mp->b_wptr--;
	protocol = *mp->b_wptr & 0xFF;
	tbr = (struct T_bind_req *)mp->b_rptr;
	/* Reset the message type in preparation for shipping it back. */
	DB_TYPE(mp) = M_PCPROTO;

	connp->conn_ulp = (uint8_t)protocol;

	/*
	 * Check for a zero length address.  This is from a protocol that
	 * wants to register to receive all packets of its type.
	 */
	if (tbr->ADDR_length == 0) {
		/*
		 * These protocols are now intercepted in ip_bind_v6().
		 * Reject protocol-level binds here for now.
		 *
		 * For SCTP raw socket, ICMP sends down a bind with sin_t
		 * so that the protocol type cannot be SCTP.
		 */
		if (protocol == IPPROTO_TCP || protocol == IPPROTO_AH ||
		    protocol == IPPROTO_ESP || protocol == IPPROTO_SCTP) {
			goto bad_addr;
		}

		/*
		 *
		 * The udp module never sends down a zero-length address,
		 * and allowing this on a labeled system will break MLP
		 * functionality.
		 */
		if (is_system_labeled() && protocol == IPPROTO_UDP)
			goto bad_addr;

		if (connp->conn_mac_exempt)
			goto bad_addr;

		/* No hash here really.  The table is big enough. */
		connp->conn_srcv6 = ipv6_all_zeros;

		ipcl_proto_insert(connp, protocol);

		tbr->PRIM_type = T_BIND_ACK;
		return (mp);
	}

	/* Extract the address pointer from the message. */
	ucp = (uchar_t *)mi_offset_param(mp, tbr->ADDR_offset,
	    tbr->ADDR_length);
	if (ucp == NULL) {
		ip1dbg(("ip_bind: no address\n"));
		goto bad_addr;
	}
	if (!OK_32PTR(ucp)) {
		ip1dbg(("ip_bind: unaligned address\n"));
		goto bad_addr;
	}
	/*
	 * Check for trailing mps.
	 */

	mp1 = mp->b_cont;
	ire_requested = (mp1 != NULL && DB_TYPE(mp1) == IRE_DB_REQ_TYPE);
	ipsec_policy_set = (mp1 != NULL && DB_TYPE(mp1) == IPSEC_POLICY_SET);

	switch (tbr->ADDR_length) {
	default:
		ip1dbg(("ip_bind: bad address length %d\n",
		    (int)tbr->ADDR_length));
		goto bad_addr;

	case IP_ADDR_LEN:
		/* Verification of local address only */
		error = ip_bind_laddr(connp, mp, *(ipaddr_t *)ucp, 0,
		    ire_requested, ipsec_policy_set, B_FALSE);
		break;

	case sizeof (sin_t):
		sin = (sin_t *)ucp;
		error = ip_bind_laddr(connp, mp, sin->sin_addr.s_addr,
		    sin->sin_port, ire_requested, ipsec_policy_set, B_TRUE);
		break;

	case sizeof (ipa_conn_t):
		ac = (ipa_conn_t *)ucp;
		/* For raw socket, the local port is not set. */
		if (ac->ac_lport == 0)
			ac->ac_lport = connp->conn_lport;
		/* Always verify destination reachability. */
		error = ip_bind_connected(connp, mp, &ac->ac_laddr,
		    ac->ac_lport, ac->ac_faddr, ac->ac_fport, ire_requested,
		    ipsec_policy_set, B_TRUE, B_TRUE);
		break;

	case sizeof (ipa_conn_x_t):
		acx = (ipa_conn_x_t *)ucp;
		/*
		 * Whether or not to verify destination reachability depends
		 * on the setting of the ACX_VERIFY_DST flag in acx->acx_flags.
		 */
		error = ip_bind_connected(connp, mp, &acx->acx_conn.ac_laddr,
		    acx->acx_conn.ac_lport, acx->acx_conn.ac_faddr,
		    acx->acx_conn.ac_fport, ire_requested, ipsec_policy_set,
		    B_TRUE, (acx->acx_flags & ACX_VERIFY_DST) != 0);
		break;
	}
	if (error == EINPROGRESS)
		return (NULL);
	else if (error != 0)
		goto bad_addr;
	/*
	 * Pass the IPsec headers size in ire_ipsec_overhead.
	 * We can't do this in ip_bind_insert_ire because the policy
	 * may not have been inherited at that point in time and hence
	 * conn_out_enforce_policy may not be set.
	 */
	mp1 = mp->b_cont;
	if (ire_requested && connp->conn_out_enforce_policy &&
	    mp1 != NULL && DB_TYPE(mp1) == IRE_DB_REQ_TYPE) {
		ire_t *ire = (ire_t *)mp1->b_rptr;
		ASSERT(MBLKL(mp1) >= sizeof (ire_t));
		ire->ire_ipsec_overhead = conn_ipsec_length(connp);
	}

	/* Send it home. */
	mp->b_datap->db_type = M_PCPROTO;
	tbr->PRIM_type = T_BIND_ACK;
	return (mp);

bad_addr:
	/*
	 * If error = -1 then we generate a TBADADDR - otherwise error is
	 * a unix errno.
	 */
	if (error > 0)
		mp = mi_tpi_err_ack_alloc(mp, TSYSERR, error);
	else
		mp = mi_tpi_err_ack_alloc(mp, TBADADDR, 0);
	return (mp);
}

/*
 * Here address is verified to be a valid local address.
 * If the IRE_DB_REQ_TYPE mp is present, a broadcast/multicast
 * address is also considered a valid local address.
 * In the case of a broadcast/multicast address, however, the
 * upper protocol is expected to reset the src address
 * to 0 if it sees a IRE_BROADCAST type returned so that
 * no packets are emitted with broadcast/multicast address as
 * source address (that violates hosts requirements RFC1122)
 * The addresses valid for bind are:
 *	(1) - INADDR_ANY (0)
 *	(2) - IP address of an UP interface
 *	(3) - IP address of a DOWN interface
 *	(4) - valid local IP broadcast addresses. In this case
 *	the conn will only receive packets destined to
 *	the specified broadcast address.
 *	(5) - a multicast address. In this case
 *	the conn will only receive packets destined to
 *	the specified multicast address. Note: the
 *	application still has to issue an
 *	IP_ADD_MEMBERSHIP socket option.
 *
 * On error, return -1 for TBADADDR otherwise pass the
 * errno with TSYSERR reply.
 *
 * In all the above cases, the bound address must be valid in the current zone.
 * When the address is loopback, multicast or broadcast, there might be many
 * matching IREs so bind has to look up based on the zone.
 *
 * Note: lport is in network byte order.
 */
int
ip_bind_laddr(conn_t *connp, mblk_t *mp, ipaddr_t src_addr, uint16_t lport,
    boolean_t ire_requested, boolean_t ipsec_policy_set,
    boolean_t fanout_insert)
{
	int		error = 0;
	ire_t		*src_ire;
	mblk_t		*policy_mp;
	ipif_t		*ipif;
	zoneid_t	zoneid;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	if (ipsec_policy_set) {
		policy_mp = mp->b_cont;
	}

	/*
	 * If it was previously connected, conn_fully_bound would have
	 * been set.
	 */
	connp->conn_fully_bound = B_FALSE;

	src_ire = NULL;
	ipif = NULL;

	zoneid = IPCL_ZONEID(connp);

	if (src_addr) {
		src_ire = ire_route_lookup(src_addr, 0, 0, 0,
		    NULL, NULL, zoneid, NULL, MATCH_IRE_ZONEONLY, ipst);
		/*
		 * If an address other than 0.0.0.0 is requested,
		 * we verify that it is a valid address for bind
		 * Note: Following code is in if-else-if form for
		 * readability compared to a condition check.
		 */
		/* LINTED - statement has no consequent */
		if (IRE_IS_LOCAL(src_ire)) {
			/*
			 * (2) Bind to address of local UP interface
			 */
		} else if (src_ire && src_ire->ire_type == IRE_BROADCAST) {
			/*
			 * (4) Bind to broadcast address
			 * Note: permitted only from transports that
			 * request IRE
			 */
			if (!ire_requested)
				error = EADDRNOTAVAIL;
		} else {
			/*
			 * (3) Bind to address of local DOWN interface
			 * (ipif_lookup_addr() looks up all interfaces
			 * but we do not get here for UP interfaces
			 * - case (2) above)
			 * We put the protocol byte back into the mblk
			 * since we may come back via ip_wput_nondata()
			 * later with this mblk if ipif_lookup_addr chooses
			 * to defer processing.
			 */
			*mp->b_wptr++ = (char)connp->conn_ulp;
			if ((ipif = ipif_lookup_addr(src_addr, NULL, zoneid,
			    CONNP_TO_WQ(connp), mp, ip_wput_nondata,
			    &error, ipst)) != NULL) {
				ipif_refrele(ipif);
			} else if (error == EINPROGRESS) {
				if (src_ire != NULL)
					ire_refrele(src_ire);
				return (EINPROGRESS);
			} else if (CLASSD(src_addr)) {
				error = 0;
				if (src_ire != NULL)
					ire_refrele(src_ire);
				/*
				 * (5) bind to multicast address.
				 * Fake out the IRE returned to upper
				 * layer to be a broadcast IRE.
				 */
				src_ire = ire_ctable_lookup(
				    INADDR_BROADCAST, INADDR_ANY,
				    IRE_BROADCAST, NULL, zoneid, NULL,
				    (MATCH_IRE_TYPE | MATCH_IRE_ZONEONLY),
				    ipst);
				if (src_ire == NULL || !ire_requested)
					error = EADDRNOTAVAIL;
			} else {
				/*
				 * Not a valid address for bind
				 */
				error = EADDRNOTAVAIL;
			}
			/*
			 * Just to keep it consistent with the processing in
			 * ip_bind_v4()
			 */
			mp->b_wptr--;
		}
		if (error) {
			/* Red Alert!  Attempting to be a bogon! */
			ip1dbg(("ip_bind: bad src address 0x%x\n",
			    ntohl(src_addr)));
			goto bad_addr;
		}
	}

	/*
	 * Allow setting new policies. For example, disconnects come
	 * down as ipa_t bind. As we would have set conn_policy_cached
	 * to B_TRUE before, we should set it to B_FALSE, so that policy
	 * can change after the disconnect.
	 */
	connp->conn_policy_cached = B_FALSE;

	/*
	 * If not fanout_insert this was just an address verification
	 */
	if (fanout_insert) {
		/*
		 * The addresses have been verified. Time to insert in
		 * the correct fanout list.
		 */
		IN6_IPADDR_TO_V4MAPPED(src_addr, &connp->conn_srcv6);
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &connp->conn_remv6);
		connp->conn_lport = lport;
		connp->conn_fport = 0;
		/*
		 * Do we need to add a check to reject Multicast packets
		 */
		error = ipcl_bind_insert(connp, *mp->b_wptr, src_addr, lport);
	}

	if (error == 0) {
		if (ire_requested) {
			if (!ip_bind_insert_ire(mp, src_ire, NULL, ipst)) {
				error = -1;
				/* Falls through to bad_addr */
			}
		} else if (ipsec_policy_set) {
			if (!ip_bind_ipsec_policy_set(connp, policy_mp)) {
				error = -1;
				/* Falls through to bad_addr */
			}
		}
	}
bad_addr:
	if (error != 0) {
		if (connp->conn_anon_port) {
			(void) tsol_mlp_anon(crgetzone(connp->conn_cred),
			    connp->conn_mlp_type, connp->conn_ulp, ntohs(lport),
			    B_FALSE);
		}
		connp->conn_mlp_type = mlptSingle;
	}
	if (src_ire != NULL)
		IRE_REFRELE(src_ire);
	if (ipsec_policy_set) {
		ASSERT(policy_mp == mp->b_cont);
		ASSERT(policy_mp != NULL);
		freeb(policy_mp);
		/*
		 * As of now assume that nothing else accompanies
		 * IPSEC_POLICY_SET.
		 */
		mp->b_cont = NULL;
	}
	return (error);
}

/*
 * Verify that both the source and destination addresses
 * are valid.  If verify_dst is false, then the destination address may be
 * unreachable, i.e. have no route to it.  Protocols like TCP want to verify
 * destination reachability, while tunnels do not.
 * Note that we allow connect to broadcast and multicast
 * addresses when ire_requested is set. Thus the ULP
 * has to check for IRE_BROADCAST and multicast.
 *
 * Returns zero if ok.
 * On error: returns -1 to mean TBADADDR otherwise returns an errno
 * (for use with TSYSERR reply).
 *
 * Note: lport and fport are in network byte order.
 */
int
ip_bind_connected(conn_t *connp, mblk_t *mp, ipaddr_t *src_addrp,
    uint16_t lport, ipaddr_t dst_addr, uint16_t fport,
    boolean_t ire_requested, boolean_t ipsec_policy_set,
    boolean_t fanout_insert, boolean_t verify_dst)
{
	ire_t		*src_ire;
	ire_t		*dst_ire;
	int		error = 0;
	int 		protocol;
	mblk_t		*policy_mp;
	ire_t		*sire = NULL;
	ire_t		*md_dst_ire = NULL;
	ire_t		*lso_dst_ire = NULL;
	ill_t		*ill = NULL;
	zoneid_t	zoneid;
	ipaddr_t	src_addr = *src_addrp;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	src_ire = dst_ire = NULL;
	protocol = *mp->b_wptr & 0xFF;

	/*
	 * If we never got a disconnect before, clear it now.
	 */
	connp->conn_fully_bound = B_FALSE;

	if (ipsec_policy_set) {
		policy_mp = mp->b_cont;
	}

	zoneid = IPCL_ZONEID(connp);

	if (CLASSD(dst_addr)) {
		/* Pick up an IRE_BROADCAST */
		dst_ire = ire_route_lookup(ip_g_all_ones, 0, 0, 0, NULL,
		    NULL, zoneid, MBLK_GETLABEL(mp),
		    (MATCH_IRE_RECURSIVE |
		    MATCH_IRE_DEFAULT | MATCH_IRE_RJ_BHOLE |
		    MATCH_IRE_SECATTR), ipst);
	} else {
		/*
		 * If conn_dontroute is set or if conn_nexthop_set is set,
		 * and onlink ipif is not found set ENETUNREACH error.
		 */
		if (connp->conn_dontroute || connp->conn_nexthop_set) {
			ipif_t *ipif;

			ipif = ipif_lookup_onlink_addr(connp->conn_dontroute ?
			    dst_addr : connp->conn_nexthop_v4, zoneid, ipst);
			if (ipif == NULL) {
				error = ENETUNREACH;
				goto bad_addr;
			}
			ipif_refrele(ipif);
		}

		if (connp->conn_nexthop_set) {
			dst_ire = ire_route_lookup(connp->conn_nexthop_v4, 0,
			    0, 0, NULL, NULL, zoneid, MBLK_GETLABEL(mp),
			    MATCH_IRE_SECATTR, ipst);
		} else {
			dst_ire = ire_route_lookup(dst_addr, 0, 0, 0, NULL,
			    &sire, zoneid, MBLK_GETLABEL(mp),
			    (MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
			    MATCH_IRE_PARENT | MATCH_IRE_RJ_BHOLE |
			    MATCH_IRE_SECATTR), ipst);
		}
	}
	/*
	 * dst_ire can't be a broadcast when not ire_requested.
	 * We also prevent ire's with src address INADDR_ANY to
	 * be used, which are created temporarily for
	 * sending out packets from endpoints that have
	 * conn_unspec_src set.  If verify_dst is true, the destination must be
	 * reachable.  If verify_dst is false, the destination needn't be
	 * reachable.
	 *
	 * If we match on a reject or black hole, then we've got a
	 * local failure.  May as well fail out the connect() attempt,
	 * since it's never going to succeed.
	 */
	if (dst_ire == NULL || dst_ire->ire_src_addr == INADDR_ANY ||
	    (dst_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    ((dst_ire->ire_type & IRE_BROADCAST) && !ire_requested)) {
		/*
		 * If we're verifying destination reachability, we always want
		 * to complain here.
		 *
		 * If we're not verifying destination reachability but the
		 * destination has a route, we still want to fail on the
		 * temporary address and broadcast address tests.
		 */
		if (verify_dst || (dst_ire != NULL)) {
			if (ip_debug > 2) {
				pr_addr_dbg("ip_bind_connected: bad connected "
				    "dst %s\n", AF_INET, &dst_addr);
			}
			if (dst_ire == NULL || !(dst_ire->ire_type & IRE_HOST))
				error = ENETUNREACH;
			else
				error = EHOSTUNREACH;
			goto bad_addr;
		}
	}

	/*
	 * We now know that routing will allow us to reach the destination.
	 * Check whether Trusted Solaris policy allows communication with this
	 * host, and pretend that the destination is unreachable if not.
	 *
	 * This is never a problem for TCP, since that transport is known to
	 * compute the label properly as part of the tcp_rput_other T_BIND_ACK
	 * handling.  If the remote is unreachable, it will be detected at that
	 * point, so there's no reason to check it here.
	 *
	 * Note that for sendto (and other datagram-oriented friends), this
	 * check is done as part of the data path label computation instead.
	 * The check here is just to make non-TCP connect() report the right
	 * error.
	 */
	if (dst_ire != NULL && is_system_labeled() &&
	    !IPCL_IS_TCP(connp) &&
	    tsol_compute_label(DB_CREDDEF(mp, connp->conn_cred), dst_addr, NULL,
	    connp->conn_mac_exempt, ipst) != 0) {
		error = EHOSTUNREACH;
		if (ip_debug > 2) {
			pr_addr_dbg("ip_bind_connected: no label for dst %s\n",
			    AF_INET, &dst_addr);
		}
		goto bad_addr;
	}

	/*
	 * If the app does a connect(), it means that it will most likely
	 * send more than 1 packet to the destination.  It makes sense
	 * to clear the temporary flag.
	 */
	if (dst_ire != NULL && dst_ire->ire_type == IRE_CACHE &&
	    (dst_ire->ire_marks & IRE_MARK_TEMPORARY)) {
		irb_t *irb = dst_ire->ire_bucket;

		rw_enter(&irb->irb_lock, RW_WRITER);
		/*
		 * We need to recheck for IRE_MARK_TEMPORARY after acquiring
		 * the lock to guarantee irb_tmp_ire_cnt.
		 */
		if (dst_ire->ire_marks & IRE_MARK_TEMPORARY) {
			dst_ire->ire_marks &= ~IRE_MARK_TEMPORARY;
			irb->irb_tmp_ire_cnt--;
		}
		rw_exit(&irb->irb_lock);
	}

	/*
	 * See if we should notify ULP about LSO/MDT; we do this whether or not
	 * ire_requested is TRUE, in order to handle active connects; LSO/MDT
	 * eligibility tests for passive connects are handled separately
	 * through tcp_adapt_ire().  We do this before the source address
	 * selection, because dst_ire may change after a call to
	 * ipif_select_source().  This is a best-effort check, as the
	 * packet for this connection may not actually go through
	 * dst_ire->ire_stq, and the exact IRE can only be known after
	 * calling ip_newroute().  This is why we further check on the
	 * IRE during LSO/Multidata packet transmission in
	 * tcp_lsosend()/tcp_multisend().
	 */
	if (!ipsec_policy_set && dst_ire != NULL &&
	    !(dst_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK | IRE_BROADCAST)) &&
	    (ill = ire_to_ill(dst_ire), ill != NULL)) {
		if (ipst->ips_ip_lso_outbound && ILL_LSO_CAPABLE(ill)) {
			lso_dst_ire = dst_ire;
			IRE_REFHOLD(lso_dst_ire);
		} else if (ipst->ips_ip_multidata_outbound &&
		    ILL_MDT_CAPABLE(ill)) {
			md_dst_ire = dst_ire;
			IRE_REFHOLD(md_dst_ire);
		}
	}

	if (dst_ire != NULL &&
	    dst_ire->ire_type == IRE_LOCAL &&
	    dst_ire->ire_zoneid != zoneid && dst_ire->ire_zoneid != ALL_ZONES) {
		/*
		 * If the IRE belongs to a different zone, look for a matching
		 * route in the forwarding table and use the source address from
		 * that route.
		 */
		src_ire = ire_ftable_lookup(dst_addr, 0, 0, 0, NULL, NULL,
		    zoneid, 0, NULL,
		    MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
		    MATCH_IRE_RJ_BHOLE, ipst);
		if (src_ire == NULL) {
			error = EHOSTUNREACH;
			goto bad_addr;
		} else if (src_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
			if (!(src_ire->ire_type & IRE_HOST))
				error = ENETUNREACH;
			else
				error = EHOSTUNREACH;
			goto bad_addr;
		}
		if (src_addr == INADDR_ANY)
			src_addr = src_ire->ire_src_addr;
		ire_refrele(src_ire);
		src_ire = NULL;
	} else if ((src_addr == INADDR_ANY) && (dst_ire != NULL)) {
		if ((sire != NULL) && (sire->ire_flags & RTF_SETSRC)) {
			src_addr = sire->ire_src_addr;
			ire_refrele(dst_ire);
			dst_ire = sire;
			sire = NULL;
		} else {
			/*
			 * Pick a source address so that a proper inbound
			 * load spreading would happen.
			 */
			ill_t *dst_ill = dst_ire->ire_ipif->ipif_ill;
			ipif_t *src_ipif = NULL;
			ire_t *ipif_ire;

			/*
			 * Supply a local source address such that inbound
			 * load spreading happens.
			 *
			 * Determine the best source address on this ill for
			 * the destination.
			 *
			 * 1) For broadcast, we should return a broadcast ire
			 *    found above so that upper layers know that the
			 *    destination address is a broadcast address.
			 *
			 * 2) If this is part of a group, select a better
			 *    source address so that better inbound load
			 *    balancing happens. Do the same if the ipif
			 *    is DEPRECATED.
			 *
			 * 3) If the outgoing interface is part of a usesrc
			 *    group, then try selecting a source address from
			 *    the usesrc ILL.
			 */
			if ((dst_ire->ire_zoneid != zoneid &&
			    dst_ire->ire_zoneid != ALL_ZONES) ||
			    (!(dst_ire->ire_flags & RTF_SETSRC)) &&
			    (!(dst_ire->ire_type & IRE_BROADCAST) &&
			    ((dst_ill->ill_group != NULL) ||
			    (dst_ire->ire_ipif->ipif_flags & IPIF_DEPRECATED) ||
			    (dst_ill->ill_usesrc_ifindex != 0)))) {
				/*
				 * If the destination is reachable via a
				 * given gateway, the selected source address
				 * should be in the same subnet as the gateway.
				 * Otherwise, the destination is not reachable.
				 *
				 * If there are no interfaces on the same subnet
				 * as the destination, ipif_select_source gives
				 * first non-deprecated interface which might be
				 * on a different subnet than the gateway.
				 * This is not desirable. Hence pass the dst_ire
				 * source address to ipif_select_source.
				 * It is sure that the destination is reachable
				 * with the dst_ire source address subnet.
				 * So passing dst_ire source address to
				 * ipif_select_source will make sure that the
				 * selected source will be on the same subnet
				 * as dst_ire source address.
				 */
				ipaddr_t saddr =
				    dst_ire->ire_ipif->ipif_src_addr;
				src_ipif = ipif_select_source(dst_ill,
				    saddr, zoneid);
				if (src_ipif != NULL) {
					if (IS_VNI(src_ipif->ipif_ill)) {
						/*
						 * For VNI there is no
						 * interface route
						 */
						src_addr =
						    src_ipif->ipif_src_addr;
					} else {
						ipif_ire =
						    ipif_to_ire(src_ipif);
						if (ipif_ire != NULL) {
							IRE_REFRELE(dst_ire);
							dst_ire = ipif_ire;
						}
						src_addr =
						    dst_ire->ire_src_addr;
					}
					ipif_refrele(src_ipif);
				} else {
					src_addr = dst_ire->ire_src_addr;
				}
			} else {
				src_addr = dst_ire->ire_src_addr;
			}
		}
	}

	/*
	 * We do ire_route_lookup() here (and not
	 * interface lookup as we assert that
	 * src_addr should only come from an
	 * UP interface for hard binding.
	 */
	ASSERT(src_ire == NULL);
	src_ire = ire_route_lookup(src_addr, 0, 0, 0, NULL,
	    NULL, zoneid, NULL, MATCH_IRE_ZONEONLY, ipst);
	/* src_ire must be a local|loopback */
	if (!IRE_IS_LOCAL(src_ire)) {
		if (ip_debug > 2) {
			pr_addr_dbg("ip_bind_connected: bad connected "
			    "src %s\n", AF_INET, &src_addr);
		}
		error = EADDRNOTAVAIL;
		goto bad_addr;
	}

	/*
	 * If the source address is a loopback address, the
	 * destination had best be local or multicast.
	 * The transports that can't handle multicast will reject
	 * those addresses.
	 */
	if (src_ire->ire_type == IRE_LOOPBACK &&
	    !(IRE_IS_LOCAL(dst_ire) || CLASSD(dst_addr))) {
		ip1dbg(("ip_bind_connected: bad connected loopback\n"));
		error = -1;
		goto bad_addr;
	}

	/*
	 * Allow setting new policies. For example, disconnects come
	 * down as ipa_t bind. As we would have set conn_policy_cached
	 * to B_TRUE before, we should set it to B_FALSE, so that policy
	 * can change after the disconnect.
	 */
	connp->conn_policy_cached = B_FALSE;

	/*
	 * Set the conn addresses/ports immediately, so the IPsec policy calls
	 * can handle their passed-in conn's.
	 */

	IN6_IPADDR_TO_V4MAPPED(src_addr, &connp->conn_srcv6);
	IN6_IPADDR_TO_V4MAPPED(dst_addr, &connp->conn_remv6);
	connp->conn_lport = lport;
	connp->conn_fport = fport;
	*src_addrp = src_addr;

	ASSERT(!(ipsec_policy_set && ire_requested));
	if (ire_requested) {
		iulp_t *ulp_info = NULL;

		/*
		 * Note that sire will not be NULL if this is an off-link
		 * connection and there is not cache for that dest yet.
		 *
		 * XXX Because of an existing bug, if there are multiple
		 * default routes, the IRE returned now may not be the actual
		 * default route used (default routes are chosen in a
		 * round robin fashion).  So if the metrics for different
		 * default routes are different, we may return the wrong
		 * metrics.  This will not be a problem if the existing
		 * bug is fixed.
		 */
		if (sire != NULL) {
			ulp_info = &(sire->ire_uinfo);
		}
		if (!ip_bind_insert_ire(mp, dst_ire, ulp_info, ipst)) {
			error = -1;
			goto bad_addr;
		}
	} else if (ipsec_policy_set) {
		if (!ip_bind_ipsec_policy_set(connp, policy_mp)) {
			error = -1;
			goto bad_addr;
		}
	}

	/*
	 * Cache IPsec policy in this conn.  If we have per-socket policy,
	 * we'll cache that.  If we don't, we'll inherit global policy.
	 *
	 * We can't insert until the conn reflects the policy. Note that
	 * conn_policy_cached is set by ipsec_conn_cache_policy() even for
	 * connections where we don't have a policy. This is to prevent
	 * global policy lookups in the inbound path.
	 *
	 * If we insert before we set conn_policy_cached,
	 * CONN_INBOUND_POLICY_PRESENT() check can still evaluate true
	 * because global policy cound be non-empty. We normally call
	 * ipsec_check_policy() for conn_policy_cached connections only if
	 * ipc_in_enforce_policy is set. But in this case,
	 * conn_policy_cached can get set anytime since we made the
	 * CONN_INBOUND_POLICY_PRESENT() check and ipsec_check_policy() is
	 * called, which will make the above assumption false.  Thus, we
	 * need to insert after we set conn_policy_cached.
	 */
	if ((error = ipsec_conn_cache_policy(connp, B_TRUE)) != 0)
		goto bad_addr;

	if (fanout_insert) {
		/*
		 * The addresses have been verified. Time to insert in
		 * the correct fanout list.
		 */
		error = ipcl_conn_insert(connp, protocol, src_addr,
		    dst_addr, connp->conn_ports);
	}

	if (error == 0) {
		connp->conn_fully_bound = B_TRUE;
		/*
		 * Our initial checks for LSO/MDT have passed; the IRE is not
		 * LOCAL/LOOPBACK/BROADCAST, and the link layer seems to
		 * be supporting LSO/MDT.  Pass the IRE, IPC and ILL into
		 * ip_xxinfo_return(), which performs further checks
		 * against them and upon success, returns the LSO/MDT info
		 * mblk which we will attach to the bind acknowledgment.
		 */
		if (lso_dst_ire != NULL) {
			mblk_t *lsoinfo_mp;

			ASSERT(ill->ill_lso_capab != NULL);
			if ((lsoinfo_mp = ip_lsoinfo_return(lso_dst_ire, connp,
			    ill->ill_name, ill->ill_lso_capab)) != NULL)
				linkb(mp, lsoinfo_mp);
		} else if (md_dst_ire != NULL) {
			mblk_t *mdinfo_mp;

			ASSERT(ill->ill_mdt_capab != NULL);
			if ((mdinfo_mp = ip_mdinfo_return(md_dst_ire, connp,
			    ill->ill_name, ill->ill_mdt_capab)) != NULL)
				linkb(mp, mdinfo_mp);
		}
	}
bad_addr:
	if (ipsec_policy_set) {
		ASSERT(policy_mp == mp->b_cont);
		ASSERT(policy_mp != NULL);
		freeb(policy_mp);
		/*
		 * As of now assume that nothing else accompanies
		 * IPSEC_POLICY_SET.
		 */
		mp->b_cont = NULL;
	}
	if (src_ire != NULL)
		IRE_REFRELE(src_ire);
	if (dst_ire != NULL)
		IRE_REFRELE(dst_ire);
	if (sire != NULL)
		IRE_REFRELE(sire);
	if (md_dst_ire != NULL)
		IRE_REFRELE(md_dst_ire);
	if (lso_dst_ire != NULL)
		IRE_REFRELE(lso_dst_ire);
	return (error);
}

/*
 * Insert the ire in b_cont. Returns false if it fails (due to lack of space).
 * Prefers dst_ire over src_ire.
 */
static boolean_t
ip_bind_insert_ire(mblk_t *mp, ire_t *ire, iulp_t *ulp_info, ip_stack_t *ipst)
{
	mblk_t	*mp1;
	ire_t *ret_ire = NULL;

	mp1 = mp->b_cont;
	ASSERT(mp1 != NULL);

	if (ire != NULL) {
		/*
		 * mp1 initialized above to IRE_DB_REQ_TYPE
		 * appended mblk. Its <upper protocol>'s
		 * job to make sure there is room.
		 */
		if ((mp1->b_datap->db_lim - mp1->b_rptr) < sizeof (ire_t))
			return (0);

		mp1->b_datap->db_type = IRE_DB_TYPE;
		mp1->b_wptr = mp1->b_rptr + sizeof (ire_t);
		bcopy(ire, mp1->b_rptr, sizeof (ire_t));
		ret_ire = (ire_t *)mp1->b_rptr;
		/*
		 * Pass the latest setting of the ip_path_mtu_discovery and
		 * copy the ulp info if any.
		 */
		ret_ire->ire_frag_flag |= (ipst->ips_ip_path_mtu_discovery) ?
		    IPH_DF : 0;
		if (ulp_info != NULL) {
			bcopy(ulp_info, &(ret_ire->ire_uinfo),
			    sizeof (iulp_t));
		}
		ret_ire->ire_mp = mp1;
	} else {
		/*
		 * No IRE was found. Remove IRE mblk.
		 */
		mp->b_cont = mp1->b_cont;
		freeb(mp1);
	}

	return (1);
}

/*
 * Carve "len" bytes out of an mblk chain, consuming any we empty, and duping
 * the final piece where we don't.  Return a pointer to the first mblk in the
 * result, and update the pointer to the next mblk to chew on.  If anything
 * goes wrong (i.e., dupb fails), we waste everything in sight and return a
 * NULL pointer.
 */
mblk_t *
ip_carve_mp(mblk_t **mpp, ssize_t len)
{
	mblk_t	*mp0;
	mblk_t	*mp1;
	mblk_t	*mp2;

	if (!len || !mpp || !(mp0 = *mpp))
		return (NULL);
	/* If we aren't going to consume the first mblk, we need a dup. */
	if (mp0->b_wptr - mp0->b_rptr > len) {
		mp1 = dupb(mp0);
		if (mp1) {
			/* Partition the data between the two mblks. */
			mp1->b_wptr = mp1->b_rptr + len;
			mp0->b_rptr = mp1->b_wptr;
			/*
			 * after adjustments if mblk not consumed is now
			 * unaligned, try to align it. If this fails free
			 * all messages and let upper layer recover.
			 */
			if (!OK_32PTR(mp0->b_rptr)) {
				if (!pullupmsg(mp0, -1)) {
					freemsg(mp0);
					freemsg(mp1);
					*mpp = NULL;
					return (NULL);
				}
			}
		}
		return (mp1);
	}
	/* Eat through as many mblks as we need to get len bytes. */
	len -= mp0->b_wptr - mp0->b_rptr;
	for (mp2 = mp1 = mp0; (mp2 = mp2->b_cont) != 0 && len; mp1 = mp2) {
		if (mp2->b_wptr - mp2->b_rptr > len) {
			/*
			 * We won't consume the entire last mblk.  Like
			 * above, dup and partition it.
			 */
			mp1->b_cont = dupb(mp2);
			mp1 = mp1->b_cont;
			if (!mp1) {
				/*
				 * Trouble.  Rather than go to a lot of
				 * trouble to clean up, we free the messages.
				 * This won't be any worse than losing it on
				 * the wire.
				 */
				freemsg(mp0);
				freemsg(mp2);
				*mpp = NULL;
				return (NULL);
			}
			mp1->b_wptr = mp1->b_rptr + len;
			mp2->b_rptr = mp1->b_wptr;
			/*
			 * after adjustments if mblk not consumed is now
			 * unaligned, try to align it. If this fails free
			 * all messages and let upper layer recover.
			 */
			if (!OK_32PTR(mp2->b_rptr)) {
				if (!pullupmsg(mp2, -1)) {
					freemsg(mp0);
					freemsg(mp2);
					*mpp = NULL;
					return (NULL);
				}
			}
			*mpp = mp2;
			return (mp0);
		}
		/* Decrement len by the amount we just got. */
		len -= mp2->b_wptr - mp2->b_rptr;
	}
	/*
	 * len should be reduced to zero now.  If not our caller has
	 * screwed up.
	 */
	if (len) {
		/* Shouldn't happen! */
		freemsg(mp0);
		*mpp = NULL;
		return (NULL);
	}
	/*
	 * We consumed up to exactly the end of an mblk.  Detach the part
	 * we are returning from the rest of the chain.
	 */
	mp1->b_cont = NULL;
	*mpp = mp2;
	return (mp0);
}

/* The ill stream is being unplumbed. Called from ip_close */
int
ip_modclose(ill_t *ill)
{
	boolean_t success;
	ipsq_t	*ipsq;
	ipif_t	*ipif;
	queue_t	*q = ill->ill_rq;
	ip_stack_t	*ipst = ill->ill_ipst;

	/*
	 * The punlink prior to this may have initiated a capability
	 * negotiation. But ipsq_enter will block until that finishes or
	 * times out.
	 */
	success = ipsq_enter(ill, B_FALSE, NEW_OP);

	/*
	 * Open/close/push/pop is guaranteed to be single threaded
	 * per stream by STREAMS. FS guarantees that all references
	 * from top are gone before close is called. So there can't
	 * be another close thread that has set CONDEMNED on this ill.
	 * and cause ipsq_enter to return failure.
	 */
	ASSERT(success);
	ipsq = ill->ill_phyint->phyint_ipsq;

	/*
	 * Mark it condemned. No new reference will be made to this ill.
	 * Lookup functions will return an error. Threads that try to
	 * increment the refcnt must check for ILL_CAN_LOOKUP. This ensures
	 * that the refcnt will drop down to zero.
	 */
	mutex_enter(&ill->ill_lock);
	ill->ill_state_flags |= ILL_CONDEMNED;
	for (ipif = ill->ill_ipif; ipif != NULL;
	    ipif = ipif->ipif_next) {
		ipif->ipif_state_flags |= IPIF_CONDEMNED;
	}
	/*
	 * Wake up anybody waiting to enter the ipsq. ipsq_enter
	 * returns  error if ILL_CONDEMNED is set
	 */
	cv_broadcast(&ill->ill_cv);
	mutex_exit(&ill->ill_lock);

	/*
	 * Send all the deferred DLPI messages downstream which came in
	 * during the small window right before ipsq_enter(). We do this
	 * without waiting for the ACKs because all the ACKs for M_PROTO
	 * messages are ignored in ip_rput() when ILL_CONDEMNED is set.
	 */
	ill_dlpi_send_deferred(ill);

	/*
	 * Shut down fragmentation reassembly.
	 * ill_frag_timer won't start a timer again.
	 * Now cancel any existing timer
	 */
	(void) untimeout(ill->ill_frag_timer_id);
	(void) ill_frag_timeout(ill, 0);

	/*
	 * If MOVE was in progress, clear the
	 * move_in_progress fields also.
	 */
	if (ill->ill_move_in_progress) {
		ILL_CLEAR_MOVE(ill);
	}

	/*
	 * Call ill_delete to bring down the ipifs, ilms and ill on
	 * this ill. Then wait for the refcnts to drop to zero.
	 * ill_is_freeable checks whether the ill is really quiescent.
	 * Then make sure that threads that are waiting to enter the
	 * ipsq have seen the error returned by ipsq_enter and have
	 * gone away. Then we call ill_delete_tail which does the
	 * DL_UNBIND_REQ with the driver and then qprocsoff.
	 */
	ill_delete(ill);
	mutex_enter(&ill->ill_lock);
	while (!ill_is_freeable(ill))
		cv_wait(&ill->ill_cv, &ill->ill_lock);
	while (ill->ill_waiters)
		cv_wait(&ill->ill_cv, &ill->ill_lock);

	mutex_exit(&ill->ill_lock);

	/*
	 * ill_delete_tail drops reference on ill_ipst, but we need to keep
	 * it held until the end of the function since the cleanup
	 * below needs to be able to use the ip_stack_t.
	 */
	netstack_hold(ipst->ips_netstack);

	/* qprocsoff is called in ill_delete_tail */
	ill_delete_tail(ill);
	ASSERT(ill->ill_ipst == NULL);

	/*
	 * Walk through all upper (conn) streams and qenable
	 * those that have queued data.
	 * close synchronization needs this to
	 * be done to ensure that all upper layers blocked
	 * due to flow control to the closing device
	 * get unblocked.
	 */
	ip1dbg(("ip_wsrv: walking\n"));
	conn_walk_drain(ipst);

	mutex_enter(&ipst->ips_ip_mi_lock);
	mi_close_unlink(&ipst->ips_ip_g_head, (IDP)ill);
	mutex_exit(&ipst->ips_ip_mi_lock);

	/*
	 * credp could be null if the open didn't succeed and ip_modopen
	 * itself calls ip_close.
	 */
	if (ill->ill_credp != NULL)
		crfree(ill->ill_credp);

	/*
	 * Now we are done with the module close pieces that
	 * need the netstack_t.
	 */
	netstack_rele(ipst->ips_netstack);

	mi_close_free((IDP)ill);
	q->q_ptr = WR(q)->q_ptr = NULL;

	ipsq_exit(ipsq);

	return (0);
}

/*
 * This is called as part of close() for IP, UDP, ICMP, and RTS
 * in order to quiesce the conn.
 */
void
ip_quiesce_conn(conn_t *connp)
{
	boolean_t	drain_cleanup_reqd = B_FALSE;
	boolean_t	conn_ioctl_cleanup_reqd = B_FALSE;
	boolean_t	ilg_cleanup_reqd = B_FALSE;
	ip_stack_t	*ipst;

	ASSERT(!IPCL_IS_TCP(connp));
	ipst = connp->conn_netstack->netstack_ip;

	/*
	 * Mark the conn as closing, and this conn must not be
	 * inserted in future into any list. Eg. conn_drain_insert(),
	 * won't insert this conn into the conn_drain_list.
	 * Similarly ill_pending_mp_add() will not add any mp to
	 * the pending mp list, after this conn has started closing.
	 *
	 * conn_idl, conn_pending_ill, conn_down_pending_ill, conn_ilg
	 * cannot get set henceforth.
	 */
	mutex_enter(&connp->conn_lock);
	ASSERT(!(connp->conn_state_flags & CONN_QUIESCED));
	connp->conn_state_flags |= CONN_CLOSING;
	if (connp->conn_idl != NULL)
		drain_cleanup_reqd = B_TRUE;
	if (connp->conn_oper_pending_ill != NULL)
		conn_ioctl_cleanup_reqd = B_TRUE;
	if (connp->conn_dhcpinit_ill != NULL) {
		ASSERT(connp->conn_dhcpinit_ill->ill_dhcpinit != 0);
		atomic_dec_32(&connp->conn_dhcpinit_ill->ill_dhcpinit);
		connp->conn_dhcpinit_ill = NULL;
	}
	if (connp->conn_ilg_inuse != 0)
		ilg_cleanup_reqd = B_TRUE;
	mutex_exit(&connp->conn_lock);

	if (conn_ioctl_cleanup_reqd)
		conn_ioctl_cleanup(connp);

	if (is_system_labeled() && connp->conn_anon_port) {
		(void) tsol_mlp_anon(crgetzone(connp->conn_cred),
		    connp->conn_mlp_type, connp->conn_ulp,
		    ntohs(connp->conn_lport), B_FALSE);
		connp->conn_anon_port = 0;
	}
	connp->conn_mlp_type = mlptSingle;

	/*
	 * Remove this conn from any fanout list it is on.
	 * and then wait for any threads currently operating
	 * on this endpoint to finish
	 */
	ipcl_hash_remove(connp);

	/*
	 * Remove this conn from the drain list, and do
	 * any other cleanup that may be required.
	 * (Only non-tcp streams may have a non-null conn_idl.
	 * TCP streams are never flow controlled, and
	 * conn_idl will be null)
	 */
	if (drain_cleanup_reqd)
		conn_drain_tail(connp, B_TRUE);

	if (connp == ipst->ips_ip_g_mrouter)
		(void) ip_mrouter_done(NULL, ipst);

	if (ilg_cleanup_reqd)
		ilg_delete_all(connp);

	conn_delete_ire(connp, NULL);

	/*
	 * Now conn refcnt can increase only thru CONN_INC_REF_LOCKED.
	 * callers from write side can't be there now because close
	 * is in progress. The only other caller is ipcl_walk
	 * which checks for the condemned flag.
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags |= CONN_CONDEMNED;
	while (connp->conn_ref != 1)
		cv_wait(&connp->conn_cv, &connp->conn_lock);
	connp->conn_state_flags |= CONN_QUIESCED;
	mutex_exit(&connp->conn_lock);
}

/* ARGSUSED */
int
ip_close(queue_t *q, int flags)
{
	conn_t		*connp;

	TRACE_1(TR_FAC_IP, TR_IP_CLOSE, "ip_close: q %p", q);

	/*
	 * Call the appropriate delete routine depending on whether this is
	 * a module or device.
	 */
	if (WR(q)->q_next != NULL) {
		/* This is a module close */
		return (ip_modclose((ill_t *)q->q_ptr));
	}

	connp = q->q_ptr;
	ip_quiesce_conn(connp);

	qprocsoff(q);

	/*
	 * Now we are truly single threaded on this stream, and can
	 * delete the things hanging off the connp, and finally the connp.
	 * We removed this connp from the fanout list, it cannot be
	 * accessed thru the fanouts, and we already waited for the
	 * conn_ref to drop to 0. We are already in close, so
	 * there cannot be any other thread from the top. qprocsoff
	 * has completed, and service has completed or won't run in
	 * future.
	 */
	ASSERT(connp->conn_ref == 1);

	inet_minor_free(connp->conn_minor_arena, connp->conn_dev);

	connp->conn_ref--;
	ipcl_conn_destroy(connp);

	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * Wapper around putnext() so that ip_rts_request can merely use
 * conn_recv.
 */
/*ARGSUSED2*/
static void
ip_conn_input(void *arg1, mblk_t *mp, void *arg2)
{
	conn_t *connp = (conn_t *)arg1;

	putnext(connp->conn_rq, mp);
}

/*
 * Called when the module is about to be unloaded
 */
void
ip_ddi_destroy(void)
{
	tnet_fini();

	icmp_ddi_destroy();
	rts_ddi_destroy();
	udp_ddi_destroy();
	sctp_ddi_g_destroy();
	tcp_ddi_g_destroy();
	ipsec_policy_g_destroy();
	ipcl_g_destroy();
	ip_net_g_destroy();
	ip_ire_g_fini();
	inet_minor_destroy(ip_minor_arena_sa);
#if defined(_LP64)
	inet_minor_destroy(ip_minor_arena_la);
#endif

#ifdef DEBUG
	list_destroy(&ip_thread_list);
	rw_destroy(&ip_thread_rwlock);
	tsd_destroy(&ip_thread_data);
#endif

	netstack_unregister(NS_IP);
}

/*
 * First step in cleanup.
 */
/* ARGSUSED */
static void
ip_stack_shutdown(netstackid_t stackid, void *arg)
{
	ip_stack_t *ipst = (ip_stack_t *)arg;

#ifdef NS_DEBUG
	printf("ip_stack_shutdown(%p, stack %d)\n", (void *)ipst, stackid);
#endif

	/* Get rid of loopback interfaces and their IREs */
	ip_loopback_cleanup(ipst);

	/*
	 * The *_hook_shutdown()s start the process of notifying any
	 * consumers that things are going away.... nothing is destroyed.
	 */
	ipv4_hook_shutdown(ipst);
	ipv6_hook_shutdown(ipst);

	mutex_enter(&ipst->ips_capab_taskq_lock);
	ipst->ips_capab_taskq_quit = B_TRUE;
	cv_signal(&ipst->ips_capab_taskq_cv);
	mutex_exit(&ipst->ips_capab_taskq_lock);
}

/*
 * Free the IP stack instance.
 */
static void
ip_stack_fini(netstackid_t stackid, void *arg)
{
	ip_stack_t *ipst = (ip_stack_t *)arg;
	int ret;

	/*
	 * At this point, all of the notifications that the events and
	 * protocols are going away have been run, meaning that we can
	 * now set about starting to clean things up.
	 */
	ipv4_hook_destroy(ipst);
	ipv6_hook_destroy(ipst);
	ip_net_destroy(ipst);

	mutex_destroy(&ipst->ips_capab_taskq_lock);
	cv_destroy(&ipst->ips_capab_taskq_cv);
	list_destroy(&ipst->ips_capab_taskq_list);

#ifdef NS_DEBUG
	printf("ip_stack_fini(%p, stack %d)\n", (void *)ipst, stackid);
#endif
	rw_destroy(&ipst->ips_srcid_lock);

	ip_kstat_fini(stackid, ipst->ips_ip_mibkp);
	ipst->ips_ip_mibkp = NULL;
	icmp_kstat_fini(stackid, ipst->ips_icmp_mibkp);
	ipst->ips_icmp_mibkp = NULL;
	ip_kstat2_fini(stackid, ipst->ips_ip_kstat);
	ipst->ips_ip_kstat = NULL;
	bzero(&ipst->ips_ip_statistics, sizeof (ipst->ips_ip_statistics));
	ip6_kstat_fini(stackid, ipst->ips_ip6_kstat);
	ipst->ips_ip6_kstat = NULL;
	bzero(&ipst->ips_ip6_statistics, sizeof (ipst->ips_ip6_statistics));

	nd_free(&ipst->ips_ip_g_nd);
	kmem_free(ipst->ips_param_arr, sizeof (lcl_param_arr));
	ipst->ips_param_arr = NULL;
	kmem_free(ipst->ips_ndp_arr, sizeof (lcl_ndp_arr));
	ipst->ips_ndp_arr = NULL;

	ip_mrouter_stack_destroy(ipst);

	mutex_destroy(&ipst->ips_ip_mi_lock);
	rw_destroy(&ipst->ips_ipsec_capab_ills_lock);
	rw_destroy(&ipst->ips_ill_g_usesrc_lock);
	rw_destroy(&ipst->ips_ip_g_nd_lock);

	ret = untimeout(ipst->ips_igmp_timeout_id);
	if (ret == -1) {
		ASSERT(ipst->ips_igmp_timeout_id == 0);
	} else {
		ASSERT(ipst->ips_igmp_timeout_id != 0);
		ipst->ips_igmp_timeout_id = 0;
	}
	ret = untimeout(ipst->ips_igmp_slowtimeout_id);
	if (ret == -1) {
		ASSERT(ipst->ips_igmp_slowtimeout_id == 0);
	} else {
		ASSERT(ipst->ips_igmp_slowtimeout_id != 0);
		ipst->ips_igmp_slowtimeout_id = 0;
	}
	ret = untimeout(ipst->ips_mld_timeout_id);
	if (ret == -1) {
		ASSERT(ipst->ips_mld_timeout_id == 0);
	} else {
		ASSERT(ipst->ips_mld_timeout_id != 0);
		ipst->ips_mld_timeout_id = 0;
	}
	ret = untimeout(ipst->ips_mld_slowtimeout_id);
	if (ret == -1) {
		ASSERT(ipst->ips_mld_slowtimeout_id == 0);
	} else {
		ASSERT(ipst->ips_mld_slowtimeout_id != 0);
		ipst->ips_mld_slowtimeout_id = 0;
	}
	ret = untimeout(ipst->ips_ip_ire_expire_id);
	if (ret == -1) {
		ASSERT(ipst->ips_ip_ire_expire_id == 0);
	} else {
		ASSERT(ipst->ips_ip_ire_expire_id != 0);
		ipst->ips_ip_ire_expire_id = 0;
	}

	mutex_destroy(&ipst->ips_igmp_timer_lock);
	mutex_destroy(&ipst->ips_mld_timer_lock);
	mutex_destroy(&ipst->ips_igmp_slowtimeout_lock);
	mutex_destroy(&ipst->ips_mld_slowtimeout_lock);
	mutex_destroy(&ipst->ips_ip_addr_avail_lock);
	rw_destroy(&ipst->ips_ill_g_lock);

	ipobs_fini(ipst);
	ip_ire_fini(ipst);
	ip6_asp_free(ipst);
	conn_drain_fini(ipst);
	ipcl_destroy(ipst);

	mutex_destroy(&ipst->ips_ndp4->ndp_g_lock);
	mutex_destroy(&ipst->ips_ndp6->ndp_g_lock);
	kmem_free(ipst->ips_ndp4, sizeof (ndp_g_t));
	ipst->ips_ndp4 = NULL;
	kmem_free(ipst->ips_ndp6, sizeof (ndp_g_t));
	ipst->ips_ndp6 = NULL;

	if (ipst->ips_loopback_ksp != NULL) {
		kstat_delete_netstack(ipst->ips_loopback_ksp, stackid);
		ipst->ips_loopback_ksp = NULL;
	}

	kmem_free(ipst->ips_phyint_g_list, sizeof (phyint_list_t));
	ipst->ips_phyint_g_list = NULL;
	kmem_free(ipst->ips_ill_g_heads, sizeof (ill_g_head_t) * MAX_G_HEADS);
	ipst->ips_ill_g_heads = NULL;

	kmem_free(ipst, sizeof (*ipst));
}

/*
 * This function is called from the TSD destructor, and is used to debug
 * reference count issues in IP. See block comment in <inet/ip_if.h> for
 * details.
 */
static void
ip_thread_exit(void *phash)
{
	th_hash_t *thh = phash;

	rw_enter(&ip_thread_rwlock, RW_WRITER);
	list_remove(&ip_thread_list, thh);
	rw_exit(&ip_thread_rwlock);
	mod_hash_destroy_hash(thh->thh_hash);
	kmem_free(thh, sizeof (*thh));
}

/*
 * Called when the IP kernel module is loaded into the kernel
 */
void
ip_ddi_init(void)
{
	ip_squeue_flag = ip_squeue_switch(ip_squeue_enter);

	/*
	 * For IP and TCP the minor numbers should start from 2 since we have 4
	 * initial devices: ip, ip6, tcp, tcp6.
	 */
	/*
	 * If this is a 64-bit kernel, then create two separate arenas -
	 * one for TLIs in the range of INET_MIN_DEV+2 through 2^^18-1, and the
	 * other for socket apps in the range 2^^18 through 2^^32-1.
	 */
	ip_minor_arena_la = NULL;
	ip_minor_arena_sa = NULL;
#if defined(_LP64)
	if ((ip_minor_arena_sa = inet_minor_create("ip_minor_arena_sa",
	    INET_MIN_DEV + 2, MAXMIN32, KM_SLEEP)) == NULL) {
		cmn_err(CE_PANIC,
		    "ip_ddi_init: ip_minor_arena_sa creation failed\n");
	}
	if ((ip_minor_arena_la = inet_minor_create("ip_minor_arena_la",
	    MAXMIN32 + 1, MAXMIN64, KM_SLEEP)) == NULL) {
		cmn_err(CE_PANIC,
		    "ip_ddi_init: ip_minor_arena_la creation failed\n");
	}
#else
	if ((ip_minor_arena_sa = inet_minor_create("ip_minor_arena_sa",
	    INET_MIN_DEV + 2, MAXMIN, KM_SLEEP)) == NULL) {
		cmn_err(CE_PANIC,
		    "ip_ddi_init: ip_minor_arena_sa creation failed\n");
	}
#endif
	ip_poll_normal_ticks = MSEC_TO_TICK_ROUNDUP(ip_poll_normal_ms);

	ipcl_g_init();
	ip_ire_g_init();
	ip_net_g_init();

#ifdef DEBUG
	tsd_create(&ip_thread_data, ip_thread_exit);
	rw_init(&ip_thread_rwlock, NULL, RW_DEFAULT, NULL);
	list_create(&ip_thread_list, sizeof (th_hash_t),
	    offsetof(th_hash_t, thh_link));
#endif

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of udp_stack_t's.
	 */
	netstack_register(NS_IP, ip_stack_init, ip_stack_shutdown,
	    ip_stack_fini);

	ipsec_policy_g_init();
	tcp_ddi_g_init();
	sctp_ddi_g_init();

	tnet_init();

	udp_ddi_init();
	rts_ddi_init();
	icmp_ddi_init();
}

/*
 * Initialize the IP stack instance.
 */
static void *
ip_stack_init(netstackid_t stackid, netstack_t *ns)
{
	ip_stack_t	*ipst;
	ipparam_t	*pa;
	ipndp_t		*na;

#ifdef NS_DEBUG
	printf("ip_stack_init(stack %d)\n", stackid);
#endif

	ipst = (ip_stack_t *)kmem_zalloc(sizeof (*ipst), KM_SLEEP);
	ipst->ips_netstack = ns;

	ipst->ips_ill_g_heads = kmem_zalloc(sizeof (ill_g_head_t) * MAX_G_HEADS,
	    KM_SLEEP);
	ipst->ips_phyint_g_list = kmem_zalloc(sizeof (phyint_list_t),
	    KM_SLEEP);
	ipst->ips_ndp4 = kmem_zalloc(sizeof (ndp_g_t), KM_SLEEP);
	ipst->ips_ndp6 = kmem_zalloc(sizeof (ndp_g_t), KM_SLEEP);
	mutex_init(&ipst->ips_ndp4->ndp_g_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipst->ips_ndp6->ndp_g_lock, NULL, MUTEX_DEFAULT, NULL);

	rw_init(&ipst->ips_ip_g_nd_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&ipst->ips_igmp_timer_lock, NULL, MUTEX_DEFAULT, NULL);
	ipst->ips_igmp_deferred_next = INFINITY;
	mutex_init(&ipst->ips_mld_timer_lock, NULL, MUTEX_DEFAULT, NULL);
	ipst->ips_mld_deferred_next = INFINITY;
	mutex_init(&ipst->ips_igmp_slowtimeout_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipst->ips_mld_slowtimeout_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipst->ips_ip_mi_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipst->ips_ip_addr_avail_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&ipst->ips_ill_g_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&ipst->ips_ipsec_capab_ills_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&ipst->ips_ill_g_usesrc_lock, NULL, RW_DEFAULT, NULL);

	ipcl_init(ipst);
	ip_ire_init(ipst);
	ip6_asp_init(ipst);
	ipif_init(ipst);
	conn_drain_init(ipst);
	ip_mrouter_stack_init(ipst);

	ipst->ips_ip_g_frag_timeout = IP_FRAG_TIMEOUT;
	ipst->ips_ip_g_frag_timo_ms = IP_FRAG_TIMEOUT * 1000;

	ipst->ips_ip_multirt_log_interval = 1000;

	ipst->ips_ip_g_forward = IP_FORWARD_DEFAULT;
	ipst->ips_ipv6_forward = IP_FORWARD_DEFAULT;
	ipst->ips_ill_index = 1;

	ipst->ips_saved_ip_g_forward = -1;
	ipst->ips_reg_vif_num = ALL_VIFS; 	/* Index to Register vif */

	pa = (ipparam_t *)kmem_alloc(sizeof (lcl_param_arr), KM_SLEEP);
	ipst->ips_param_arr = pa;
	bcopy(lcl_param_arr, ipst->ips_param_arr, sizeof (lcl_param_arr));

	na = (ipndp_t *)kmem_alloc(sizeof (lcl_ndp_arr), KM_SLEEP);
	ipst->ips_ndp_arr = na;
	bcopy(lcl_ndp_arr, ipst->ips_ndp_arr, sizeof (lcl_ndp_arr));
	ipst->ips_ndp_arr[IPNDP_IP_FORWARDING_OFFSET].ip_ndp_data =
	    (caddr_t)&ipst->ips_ip_g_forward;
	ipst->ips_ndp_arr[IPNDP_IP6_FORWARDING_OFFSET].ip_ndp_data =
	    (caddr_t)&ipst->ips_ipv6_forward;
	ASSERT(strcmp(ipst->ips_ndp_arr[IPNDP_CGTP_FILTER_OFFSET].ip_ndp_name,
	    "ip_cgtp_filter") == 0);
	ipst->ips_ndp_arr[IPNDP_CGTP_FILTER_OFFSET].ip_ndp_data =
	    (caddr_t)&ipst->ips_ip_cgtp_filter;
	ASSERT(strcmp(ipst->ips_ndp_arr[IPNDP_IPMP_HOOK_OFFSET].ip_ndp_name,
	    "ipmp_hook_emulation") == 0);
	ipst->ips_ndp_arr[IPNDP_IPMP_HOOK_OFFSET].ip_ndp_data =
	    (caddr_t)&ipst->ips_ipmp_hook_emulation;

	(void) ip_param_register(&ipst->ips_ip_g_nd,
	    ipst->ips_param_arr, A_CNT(lcl_param_arr),
	    ipst->ips_ndp_arr, A_CNT(lcl_ndp_arr));

	ipst->ips_ip_mibkp = ip_kstat_init(stackid, ipst);
	ipst->ips_icmp_mibkp = icmp_kstat_init(stackid);
	ipst->ips_ip_kstat = ip_kstat2_init(stackid, &ipst->ips_ip_statistics);
	ipst->ips_ip6_kstat =
	    ip6_kstat_init(stackid, &ipst->ips_ip6_statistics);

	ipst->ips_ipmp_enable_failback = B_TRUE;

	ipst->ips_ip_src_id = 1;
	rw_init(&ipst->ips_srcid_lock, NULL, RW_DEFAULT, NULL);

	ipobs_init(ipst);
	ip_net_init(ipst, ns);
	ipv4_hook_init(ipst);
	ipv6_hook_init(ipst);

	/*
	 * Create the taskq dispatcher thread and initialize related stuff.
	 */
	ipst->ips_capab_taskq_thread = thread_create(NULL, 0,
	    ill_taskq_dispatch, ipst, 0, &p0, TS_RUN, minclsyspri);
	mutex_init(&ipst->ips_capab_taskq_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ipst->ips_capab_taskq_cv, NULL, CV_DEFAULT, NULL);
	list_create(&ipst->ips_capab_taskq_list, sizeof (mblk_t),
	    offsetof(mblk_t, b_next));

	return (ipst);
}

/*
 * Allocate and initialize a DLPI template of the specified length.  (May be
 * called as writer.)
 */
mblk_t *
ip_dlpi_alloc(size_t len, t_uscalar_t prim)
{
	mblk_t	*mp;

	mp = allocb(len, BPRI_MED);
	if (!mp)
		return (NULL);

	/*
	 * DLPIv2 says that DL_INFO_REQ and DL_TOKEN_REQ (the latter
	 * of which we don't seem to use) are sent with M_PCPROTO, and
	 * that other DLPI are M_PROTO.
	 */
	if (prim == DL_INFO_REQ) {
		mp->b_datap->db_type = M_PCPROTO;
	} else {
		mp->b_datap->db_type = M_PROTO;
	}

	mp->b_wptr = mp->b_rptr + len;
	bzero(mp->b_rptr, len);
	((dl_unitdata_req_t *)mp->b_rptr)->dl_primitive = prim;
	return (mp);
}

/*
 * Debug formatting routine.  Returns a character string representation of the
 * addr in buf, of the form xxx.xxx.xxx.xxx.  This routine takes the address
 * in the form of a ipaddr_t and calls ip_dot_saddr with a pointer.
 *
 * Once the ndd table-printing interfaces are removed, this can be changed to
 * standard dotted-decimal form.
 */
char *
ip_dot_addr(ipaddr_t addr, char *buf)
{
	uint8_t *ap = (uint8_t *)&addr;

	(void) mi_sprintf(buf, "%03d.%03d.%03d.%03d",
	    ap[0] & 0xFF, ap[1] & 0xFF, ap[2] & 0xFF, ap[3] & 0xFF);
	return (buf);
}

/*
 * Write the given MAC address as a printable string in the usual colon-
 * separated format.
 */
const char *
mac_colon_addr(const uint8_t *addr, size_t alen, char *buf, size_t buflen)
{
	char *bp;

	if (alen == 0 || buflen < 4)
		return ("?");
	bp = buf;
	for (;;) {
		/*
		 * If there are more MAC address bytes available, but we won't
		 * have any room to print them, then add "..." to the string
		 * instead.  See below for the 'magic number' explanation.
		 */
		if ((alen == 2 && buflen < 6) || (alen > 2 && buflen < 7)) {
			(void) strcpy(bp, "...");
			break;
		}
		(void) sprintf(bp, "%02x", *addr++);
		bp += 2;
		if (--alen == 0)
			break;
		*bp++ = ':';
		buflen -= 3;
		/*
		 * At this point, based on the first 'if' statement above,
		 * either alen == 1 and buflen >= 3, or alen > 1 and
		 * buflen >= 4.  The first case leaves room for the final "xx"
		 * number and trailing NUL byte.  The second leaves room for at
		 * least "...".  Thus the apparently 'magic' numbers chosen for
		 * that statement.
		 */
	}
	return (buf);
}

/*
 * Send an ICMP error after patching up the packet appropriately.  Returns
 * non-zero if the appropriate MIB should be bumped; zero otherwise.
 */
static boolean_t
ip_fanout_send_icmp(queue_t *q, mblk_t *mp, uint_t flags,
    uint_t icmp_type, uint_t icmp_code, boolean_t mctl_present,
    zoneid_t zoneid, ip_stack_t *ipst)
{
	ipha_t *ipha;
	mblk_t *first_mp;
	boolean_t secure;
	unsigned char db_type;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	first_mp = mp;
	if (mctl_present) {
		mp = mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		/*
		 * If this is an ICMP error being reported - which goes
		 * up as M_CTLs, we need to convert them to M_DATA till
		 * we finish checking with global policy because
		 * ipsec_check_global_policy() assumes M_DATA as clear
		 * and M_CTL as secure.
		 */
		db_type = DB_TYPE(mp);
		DB_TYPE(mp) = M_DATA;
		secure = B_FALSE;
	}
	/*
	 * We are generating an icmp error for some inbound packet.
	 * Called from all ip_fanout_(udp, tcp, proto) functions.
	 * Before we generate an error, check with global policy
	 * to see whether this is allowed to enter the system. As
	 * there is no "conn", we are checking with global policy.
	 */
	ipha = (ipha_t *)mp->b_rptr;
	if (secure || ipss->ipsec_inbound_v4_policy_present) {
		first_mp = ipsec_check_global_policy(first_mp, NULL,
		    ipha, NULL, mctl_present, ipst->ips_netstack);
		if (first_mp == NULL)
			return (B_FALSE);
	}

	if (!mctl_present)
		DB_TYPE(mp) = db_type;

	if (flags & IP_FF_SEND_ICMP) {
		if (flags & IP_FF_HDR_COMPLETE) {
			if (ip_hdr_complete(ipha, zoneid, ipst)) {
				freemsg(first_mp);
				return (B_TRUE);
			}
		}
		if (flags & IP_FF_CKSUM) {
			/*
			 * Have to correct checksum since
			 * the packet might have been
			 * fragmented and the reassembly code in ip_rput
			 * does not restore the IP checksum.
			 */
			ipha->ipha_hdr_checksum = 0;
			ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
		}
		switch (icmp_type) {
		case ICMP_DEST_UNREACHABLE:
			icmp_unreachable(WR(q), first_mp, icmp_code, zoneid,
			    ipst);
			break;
		default:
			freemsg(first_mp);
			break;
		}
	} else {
		freemsg(first_mp);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Used to send an ICMP error message when a packet is received for
 * a protocol that is not supported. The mblk passed as argument
 * is consumed by this function.
 */
void
ip_proto_not_sup(queue_t *q, mblk_t *ipsec_mp, uint_t flags, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	mblk_t *mp;
	ipha_t *ipha;
	ill_t *ill;
	ipsec_in_t *ii;

	ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	ASSERT(ii->ipsec_in_type == IPSEC_IN);

	mp = ipsec_mp->b_cont;
	ipsec_mp->b_cont = NULL;
	ipha = (ipha_t *)mp->b_rptr;
	/* Get ill from index in ipsec_in_t. */
	ill = ill_lookup_on_ifindex(ii->ipsec_in_ill_index,
	    (IPH_HDR_VERSION(ipha) == IPV6_VERSION), NULL, NULL, NULL, NULL,
	    ipst);
	if (ill != NULL) {
		if (IPH_HDR_VERSION(ipha) == IP_VERSION) {
			if (ip_fanout_send_icmp(q, mp, flags,
			    ICMP_DEST_UNREACHABLE,
			    ICMP_PROTOCOL_UNREACHABLE, B_FALSE, zoneid, ipst)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInUnknownProtos);
			}
		} else {
			if (ip_fanout_send_icmp_v6(q, mp, flags,
			    ICMP6_PARAM_PROB, ICMP6_PARAMPROB_NEXTHEADER,
			    0, B_FALSE, zoneid, ipst)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInUnknownProtos);
			}
		}
		ill_refrele(ill);
	} else { /* re-link for the freemsg() below. */
		ipsec_mp->b_cont = mp;
	}

	/* If ICMP delivered, ipsec_mp will be a singleton (b_cont == NULL). */
	freemsg(ipsec_mp);
}

/*
 * See if the inbound datagram has had IPsec processing applied to it.
 */
boolean_t
ipsec_in_is_secure(mblk_t *ipsec_mp)
{
	ipsec_in_t *ii;

	ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	ASSERT(ii->ipsec_in_type == IPSEC_IN);

	if (ii->ipsec_in_loopback) {
		return (ii->ipsec_in_secure);
	} else {
		return (ii->ipsec_in_ah_sa != NULL ||
		    ii->ipsec_in_esp_sa != NULL ||
		    ii->ipsec_in_decaps);
	}
}

/*
 * Handle protocols with which IP is less intimate.  There
 * can be more than one stream bound to a particular
 * protocol.  When this is the case, normally each one gets a copy
 * of any incoming packets.
 *
 * IPsec NOTE :
 *
 * Don't allow a secure packet going up a non-secure connection.
 * We don't allow this because
 *
 * 1) Reply might go out in clear which will be dropped at
 *    the sending side.
 * 2) If the reply goes out in clear it will give the
 *    adversary enough information for getting the key in
 *    most of the cases.
 *
 * Moreover getting a secure packet when we expect clear
 * implies that SA's were added without checking for
 * policy on both ends. This should not happen once ISAKMP
 * is used to negotiate SAs as SAs will be added only after
 * verifying the policy.
 *
 * NOTE : If the packet was tunneled and not multicast we only send
 * to it the first match. Unlike TCP and UDP fanouts this doesn't fall
 * back to delivering packets to AF_INET6 raw sockets.
 *
 * IPQoS Notes:
 * Once we have determined the client, invoke IPPF processing.
 * Policy processing takes place only if the callout_position, IPP_LOCAL_IN,
 * is enabled. If we get here from icmp_inbound_error_fanout or ip_wput_local
 * ip_policy will be false.
 *
 * Zones notes:
 * Currently only applications in the global zone can create raw sockets for
 * protocols other than ICMP. So unlike the broadcast / multicast case of
 * ip_fanout_udp(), we only send a copy of the packet to streams in the
 * specified zone. For ICMP, this is handled by the callers of icmp_inbound().
 */
static void
ip_fanout_proto(queue_t *q, mblk_t *mp, ill_t *ill, ipha_t *ipha, uint_t flags,
    boolean_t mctl_present, boolean_t ip_policy, ill_t *recv_ill,
    zoneid_t zoneid)
{
	queue_t	*rq;
	mblk_t	*mp1, *first_mp1;
	uint_t	protocol = ipha->ipha_protocol;
	ipaddr_t dst;
	boolean_t one_only;
	mblk_t *first_mp = mp;
	boolean_t secure;
	uint32_t ill_index;
	conn_t	*connp, *first_connp, *next_connp;
	connf_t	*connfp;
	boolean_t shared_addr;
	mib2_ipIfStatsEntry_t *mibptr;
	ip_stack_t *ipst = recv_ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	mibptr = (ill != NULL) ? ill->ill_ip_mib : &ipst->ips_ip_mib;
	if (mctl_present) {
		mp = first_mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		secure = B_FALSE;
	}
	dst = ipha->ipha_dst;
	/*
	 * If the packet was tunneled and not multicast we only send to it
	 * the first match.
	 */
	one_only = ((protocol == IPPROTO_ENCAP || protocol == IPPROTO_IPV6) &&
	    !CLASSD(dst));

	shared_addr = (zoneid == ALL_ZONES);
	if (shared_addr) {
		/*
		 * We don't allow multilevel ports for raw IP, so no need to
		 * check for that here.
		 */
		zoneid = tsol_packet_to_zoneid(mp);
	}

	connfp = &ipst->ips_ipcl_proto_fanout[protocol];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		if (IPCL_PROTO_MATCH(connp, protocol, ipha, ill, flags,
		    zoneid) &&
		    (!is_system_labeled() ||
		    tsol_receive_local(mp, &dst, IPV4_VERSION, shared_addr,
		    connp))) {
			break;
		}
	}

	if (connp == NULL || connp->conn_upq == NULL) {
		/*
		 * No one bound to these addresses.  Is
		 * there a client that wants all
		 * unclaimed datagrams?
		 */
		mutex_exit(&connfp->connf_lock);
		/*
		 * Check for IPPROTO_ENCAP...
		 */
		if (protocol == IPPROTO_ENCAP && ipst->ips_ip_g_mrouter) {
			/*
			 * If an IPsec mblk is here on a multicast
			 * tunnel (using ip_mroute stuff), check policy here,
			 * THEN ship off to ip_mroute_decap().
			 *
			 * BTW,  If I match a configured IP-in-IP
			 * tunnel, this path will not be reached, and
			 * ip_mroute_decap will never be called.
			 */
			first_mp = ipsec_check_global_policy(first_mp, connp,
			    ipha, NULL, mctl_present, ipst->ips_netstack);
			if (first_mp != NULL) {
				if (mctl_present)
					freeb(first_mp);
				ip_mroute_decap(q, mp, ill);
			} /* Else we already freed everything! */
		} else {
			/*
			 * Otherwise send an ICMP protocol unreachable.
			 */
			if (ip_fanout_send_icmp(q, first_mp, flags,
			    ICMP_DEST_UNREACHABLE, ICMP_PROTOCOL_UNREACHABLE,
			    mctl_present, zoneid, ipst)) {
				BUMP_MIB(mibptr, ipIfStatsInUnknownProtos);
			}
		}
		return;
	}
	CONN_INC_REF(connp);
	first_connp = connp;

	/*
	 * Only send message to one tunnel driver by immediately
	 * terminating the loop.
	 */
	connp = one_only ? NULL : connp->conn_next;

	for (;;) {
		while (connp != NULL) {
			if (IPCL_PROTO_MATCH(connp, protocol, ipha, ill,
			    flags, zoneid) &&
			    (!is_system_labeled() ||
			    tsol_receive_local(mp, &dst, IPV4_VERSION,
			    shared_addr, connp)))
				break;
			connp = connp->conn_next;
		}

		/*
		 * Copy the packet.
		 */
		if (connp == NULL || connp->conn_upq == NULL ||
		    (((first_mp1 = dupmsg(first_mp)) == NULL) &&
		    ((first_mp1 = ip_copymsg(first_mp)) == NULL))) {
			/*
			 * No more interested clients or memory
			 * allocation failed
			 */
			connp = first_connp;
			break;
		}
		mp1 = mctl_present ? first_mp1->b_cont : first_mp1;
		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
		rq = connp->conn_rq;
		if (!canputnext(rq)) {
			if (flags & IP_FF_RAWIP) {
				BUMP_MIB(mibptr, rawipIfStatsInOverflows);
			} else {
				BUMP_MIB(&ipst->ips_icmp_mib, icmpInOverflows);
			}

			freemsg(first_mp1);
		} else {
			/*
			 * Don't enforce here if we're an actual tunnel -
			 * let "tun" do it instead.
			 */
			if (!IPCL_IS_IPTUN(connp) &&
			    (CONN_INBOUND_POLICY_PRESENT(connp, ipss) ||
			    secure)) {
				first_mp1 = ipsec_check_inbound_policy
				    (first_mp1, connp, ipha, NULL,
				    mctl_present);
			}
			if (first_mp1 != NULL) {
				int in_flags = 0;
				/*
				 * ip_fanout_proto also gets called from
				 * icmp_inbound_error_fanout, in which case
				 * the msg type is M_CTL.  Don't add info
				 * in this case for the time being. In future
				 * when there is a need for knowing the
				 * inbound iface index for ICMP error msgs,
				 * then this can be changed.
				 */
				if (connp->conn_recvif)
					in_flags = IPF_RECVIF;
				/*
				 * The ULP may support IP_RECVPKTINFO for both
				 * IP v4 and v6 so pass the appropriate argument
				 * based on conn IP version.
				 */
				if (connp->conn_ip_recvpktinfo) {
					if (connp->conn_af_isv6) {
						/*
						 * V6 only needs index
						 */
						in_flags |= IPF_RECVIF;
					} else {
						/*
						 * V4 needs index +
						 * matching address.
						 */
						in_flags |= IPF_RECVADDR;
					}
				}
				if ((in_flags != 0) &&
				    (mp->b_datap->db_type != M_CTL)) {
					/*
					 * the actual data will be
					 * contained in b_cont upon
					 * successful return of the
					 * following call else
					 * original mblk is returned
					 */
					ASSERT(recv_ill != NULL);
					mp1 = ip_add_info(mp1, recv_ill,
					    in_flags, IPCL_ZONEID(connp), ipst);
				}
				BUMP_MIB(mibptr, ipIfStatsHCInDelivers);
				if (mctl_present)
					freeb(first_mp1);
				(connp->conn_recv)(connp, mp1, NULL);
			}
		}
		mutex_enter(&connfp->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_connp = connp->conn_next;
		CONN_DEC_REF(connp);
		connp = next_connp;
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);

	/*
	 * If this packet is coming from icmp_inbound_error_fanout ip_policy
	 * will be set to false.
	 */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst) && ip_policy) {
		ill_index = ill->ill_phyint->phyint_ifindex;
		ip_process(IPP_LOCAL_IN, &mp, ill_index);
		if (mp == NULL) {
			CONN_DEC_REF(connp);
			if (mctl_present) {
				freeb(first_mp);
			}
			return;
		}
	}

	rq = connp->conn_rq;
	if (!canputnext(rq)) {
		if (flags & IP_FF_RAWIP) {
			BUMP_MIB(mibptr, rawipIfStatsInOverflows);
		} else {
			BUMP_MIB(&ipst->ips_icmp_mib, icmpInOverflows);
		}

		freemsg(first_mp);
	} else {
		if (IPCL_IS_IPTUN(connp)) {
			/*
			 * Tunneled packet.  We enforce policy in the tunnel
			 * module itself.
			 *
			 * Send the WHOLE packet up (incl. IPSEC_IN) without
			 * a policy check.
			 * FIXME to use conn_recv for tun later.
			 */
			putnext(rq, first_mp);
			CONN_DEC_REF(connp);
			return;
		}

		if ((CONN_INBOUND_POLICY_PRESENT(connp, ipss) || secure)) {
			first_mp = ipsec_check_inbound_policy(first_mp, connp,
			    ipha, NULL, mctl_present);
		}

		if (first_mp != NULL) {
			int in_flags = 0;

			/*
			 * ip_fanout_proto also gets called
			 * from icmp_inbound_error_fanout, in
			 * which case the msg type is M_CTL.
			 * Don't add info in this case for time
			 * being. In future when there is a
			 * need for knowing the inbound iface
			 * index for ICMP error msgs, then this
			 * can be changed
			 */
			if (connp->conn_recvif)
				in_flags = IPF_RECVIF;
			if (connp->conn_ip_recvpktinfo) {
				if (connp->conn_af_isv6) {
					/*
					 * V6 only needs index
					 */
					in_flags |= IPF_RECVIF;
				} else {
					/*
					 * V4 needs index +
					 * matching address.
					 */
					in_flags |= IPF_RECVADDR;
				}
			}
			if ((in_flags != 0) &&
			    (mp->b_datap->db_type != M_CTL)) {

				/*
				 * the actual data will be contained in
				 * b_cont upon successful return
				 * of the following call else original
				 * mblk is returned
				 */
				ASSERT(recv_ill != NULL);
				mp = ip_add_info(mp, recv_ill,
				    in_flags, IPCL_ZONEID(connp), ipst);
			}
			BUMP_MIB(mibptr, ipIfStatsHCInDelivers);
			(connp->conn_recv)(connp, mp, NULL);
			if (mctl_present)
				freeb(first_mp);
		}
	}
	CONN_DEC_REF(connp);
}

/*
 * Fanout for TCP packets
 * The caller puts <fport, lport> in the ports parameter.
 *
 * IPQoS Notes
 * Before sending it to the client, invoke IPPF processing.
 * Policy processing takes place only if the callout_position, IPP_LOCAL_IN,
 * is enabled. If we get here from icmp_inbound_error_fanout or ip_wput_local
 * ip_policy is false.
 */
static void
ip_fanout_tcp(queue_t *q, mblk_t *mp, ill_t *recv_ill, ipha_t *ipha,
    uint_t flags, boolean_t mctl_present, boolean_t ip_policy, zoneid_t zoneid)
{
	mblk_t  *first_mp;
	boolean_t secure;
	uint32_t ill_index;
	int	ip_hdr_len;
	tcph_t	*tcph;
	boolean_t syn_present = B_FALSE;
	conn_t	*connp;
	ip_stack_t	*ipst = recv_ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	ASSERT(recv_ill != NULL);

	first_mp = mp;
	if (mctl_present) {
		ASSERT(first_mp->b_datap->db_type == M_CTL);
		mp = first_mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		secure = B_FALSE;
	}

	ip_hdr_len = IPH_HDR_LENGTH(mp->b_rptr);

	if ((connp = ipcl_classify_v4(mp, IPPROTO_TCP, ip_hdr_len,
	    zoneid, ipst)) == NULL) {
		/*
		 * No connected connection or listener. Send a
		 * TH_RST via tcp_xmit_listeners_reset.
		 */

		/* Initiate IPPf processing, if needed. */
		if (IPP_ENABLED(IPP_LOCAL_IN, ipst)) {
			uint32_t ill_index;
			ill_index = recv_ill->ill_phyint->phyint_ifindex;
			ip_process(IPP_LOCAL_IN, &first_mp, ill_index);
			if (first_mp == NULL)
				return;
		}
		BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsHCInDelivers);
		ip2dbg(("ip_fanout_tcp: no listener; send reset to zone %d\n",
		    zoneid));
		tcp_xmit_listeners_reset(first_mp, ip_hdr_len, zoneid,
		    ipst->ips_netstack->netstack_tcp, NULL);
		return;
	}

	/*
	 * Allocate the SYN for the TCP connection here itself
	 */
	tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];
	if ((tcph->th_flags[0] & (TH_SYN|TH_ACK|TH_RST|TH_URG)) == TH_SYN) {
		if (IPCL_IS_TCP(connp)) {
			squeue_t *sqp;

			/*
			 * For fused tcp loopback, assign the eager's
			 * squeue to be that of the active connect's.
			 * Note that we don't check for IP_FF_LOOPBACK
			 * here since this routine gets called only
			 * for loopback (unlike the IPv6 counterpart).
			 */
			ASSERT(Q_TO_CONN(q) != NULL);
			if (do_tcp_fusion &&
			    !CONN_INBOUND_POLICY_PRESENT(connp, ipss) &&
			    !secure &&
			    !IPP_ENABLED(IPP_LOCAL_IN, ipst) && !ip_policy &&
			    IPCL_IS_TCP(Q_TO_CONN(q))) {
				ASSERT(Q_TO_CONN(q)->conn_sqp != NULL);
				sqp = Q_TO_CONN(q)->conn_sqp;
			} else {
				sqp = IP_SQUEUE_GET(lbolt);
			}

			mp->b_datap->db_struioflag |= STRUIO_EAGER;
			DB_CKSUMSTART(mp) = (intptr_t)sqp;
			syn_present = B_TRUE;
		}
	}

	if (IPCL_IS_TCP(connp) && IPCL_IS_BOUND(connp) && !syn_present) {
		uint_t	flags = (unsigned int)tcph->th_flags[0] & 0xFF;
		BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsHCInDelivers);
		if ((flags & TH_RST) || (flags & TH_URG)) {
			CONN_DEC_REF(connp);
			freemsg(first_mp);
			return;
		}
		if (flags & TH_ACK) {
			tcp_xmit_listeners_reset(first_mp, ip_hdr_len, zoneid,
			    ipst->ips_netstack->netstack_tcp, connp);
			CONN_DEC_REF(connp);
			return;
		}

		CONN_DEC_REF(connp);
		freemsg(first_mp);
		return;
	}

	if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) || secure) {
		first_mp = ipsec_check_inbound_policy(first_mp, connp, ipha,
		    NULL, mctl_present);
		if (first_mp == NULL) {
			BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			return;
		}
		if (IPCL_IS_TCP(connp) && IPCL_IS_BOUND(connp)) {
			ASSERT(syn_present);
			if (mctl_present) {
				ASSERT(first_mp != mp);
				first_mp->b_datap->db_struioflag |=
				    STRUIO_POLICY;
			} else {
				ASSERT(first_mp == mp);
				mp->b_datap->db_struioflag &=
				    ~STRUIO_EAGER;
				mp->b_datap->db_struioflag |=
				    STRUIO_POLICY;
			}
		} else {
			/*
			 * Discard first_mp early since we're dealing with a
			 * fully-connected conn_t and tcp doesn't do policy in
			 * this case.
			 */
			if (mctl_present) {
				freeb(first_mp);
				mctl_present = B_FALSE;
			}
			first_mp = mp;
		}
	}

	/*
	 * Initiate policy processing here if needed. If we get here from
	 * icmp_inbound_error_fanout, ip_policy is false.
	 */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst) && ip_policy) {
		ill_index = recv_ill->ill_phyint->phyint_ifindex;
		ip_process(IPP_LOCAL_IN, &mp, ill_index);
		if (mp == NULL) {
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return;
		} else if (mctl_present) {
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}



	/* Handle socket options. */
	if (!syn_present &&
	    connp->conn_ip_recvpktinfo && (flags & IP_FF_IPINFO)) {
		/* Add header */
		ASSERT(recv_ill != NULL);
		/*
		 * Since tcp does not support IP_RECVPKTINFO for V4, only pass
		 * IPF_RECVIF.
		 */
		mp = ip_add_info(mp, recv_ill, IPF_RECVIF, IPCL_ZONEID(connp),
		    ipst);
		if (mp == NULL) {
			BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return;
		} else if (mctl_present) {
			/*
			 * ip_add_info might return a new mp.
			 */
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}
	BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsHCInDelivers);
	if (IPCL_IS_TCP(connp)) {
		/* do not drain, certain use cases can blow the stack */
		SQUEUE_ENTER_ONE(connp->conn_sqp, first_mp, connp->conn_recv,
		    connp, ip_squeue_flag, SQTAG_IP_FANOUT_TCP);
	} else {
		/* Not TCP; must be SOCK_RAW, IPPROTO_TCP */
		(connp->conn_recv)(connp, first_mp, NULL);
		CONN_DEC_REF(connp);
	}
}

/*
 * If we have a IPsec NAT-Traversal packet, strip the zero-SPI or
 * pass it along to ESP if the SPI is non-zero.  Returns TRUE if the mblk
 * is not consumed.
 *
 * One of four things can happen, all of which affect the passed-in mblk:
 *
 * 1.) ICMP messages that go through here just get returned TRUE.
 *
 * 2.) The packet is stock UDP and gets its zero-SPI stripped.  Return TRUE.
 *
 * 3.) The packet is ESP-in-UDP, gets transformed into an equivalent
 *     ESP packet, and is passed along to ESP for consumption.  Return FALSE.
 *
 * 4.) The packet is an ESP-in-UDP Keepalive.  Drop it and return FALSE.
 */
static boolean_t
zero_spi_check(queue_t *q, mblk_t *mp, ire_t *ire, ill_t *recv_ill,
    ipsec_stack_t *ipss)
{
	int shift, plen, iph_len;
	ipha_t *ipha;
	udpha_t *udpha;
	uint32_t *spi;
	uint32_t esp_ports;
	uint8_t *orptr;
	boolean_t free_ire;

	if (DB_TYPE(mp) == M_CTL) {
		/*
		 * ICMP message with UDP inside.  Don't bother stripping, just
		 * send it up.
		 *
		 * NOTE: Any app with UDP_NAT_T_ENDPOINT set is probably going
		 * to ignore errors set by ICMP anyway ('cause they might be
		 * forged), but that's the app's decision, not ours.
		 */

		/* Bunch of reality checks for DEBUG kernels... */
		ASSERT(IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION);
		ASSERT(((ipha_t *)mp->b_rptr)->ipha_protocol == IPPROTO_ICMP);

		return (B_TRUE);
	}

	ipha = (ipha_t *)mp->b_rptr;
	iph_len = IPH_HDR_LENGTH(ipha);
	plen = ntohs(ipha->ipha_length);

	if (plen - iph_len - sizeof (udpha_t) < sizeof (uint32_t)) {
		/*
		 * Most likely a keepalive for the benefit of an intervening
		 * NAT.  These aren't for us, per se, so drop it.
		 *
		 * RFC 3947/8 doesn't say for sure what to do for 2-3
		 * byte packets (keepalives are 1-byte), but we'll drop them
		 * also.
		 */
		ip_drop_packet(mp, B_TRUE, recv_ill, NULL,
		    DROPPER(ipss, ipds_esp_nat_t_ka), &ipss->ipsec_dropper);
		return (B_FALSE);
	}

	if (MBLKL(mp) < iph_len + sizeof (udpha_t) + sizeof (*spi)) {
		/* might as well pull it all up - it might be ESP. */
		if (!pullupmsg(mp, -1)) {
			ip_drop_packet(mp, B_TRUE, recv_ill, NULL,
			    DROPPER(ipss, ipds_esp_nomem),
			    &ipss->ipsec_dropper);
			return (B_FALSE);
		}

		ipha = (ipha_t *)mp->b_rptr;
	}
	spi = (uint32_t *)(mp->b_rptr + iph_len + sizeof (udpha_t));
	if (*spi == 0) {
		/* UDP packet - remove 0-spi. */
		shift = sizeof (uint32_t);
	} else {
		/* ESP-in-UDP packet - reduce to ESP. */
		ipha->ipha_protocol = IPPROTO_ESP;
		shift = sizeof (udpha_t);
	}

	/* Fix IP header */
	ipha->ipha_length = htons(plen - shift);
	ipha->ipha_hdr_checksum = 0;

	orptr = mp->b_rptr;
	mp->b_rptr += shift;

	udpha = (udpha_t *)(orptr + iph_len);
	if (*spi == 0) {
		ASSERT((uint8_t *)ipha == orptr);
		udpha->uha_length = htons(plen - shift - iph_len);
		iph_len += sizeof (udpha_t);	/* For the call to ovbcopy(). */
		esp_ports = 0;
	} else {
		esp_ports = *((uint32_t *)udpha);
		ASSERT(esp_ports != 0);
	}
	ovbcopy(orptr, orptr + shift, iph_len);
	if (esp_ports != 0) /* Punt up for ESP processing. */ {
		ipha = (ipha_t *)(orptr + shift);

		free_ire = (ire == NULL);
		if (free_ire) {
			/* Re-acquire ire. */
			ire = ire_cache_lookup(ipha->ipha_dst, ALL_ZONES, NULL,
			    ipss->ipsec_netstack->netstack_ip);
			if (ire == NULL || !(ire->ire_type & IRE_LOCAL)) {
				if (ire != NULL)
					ire_refrele(ire);
				/*
				 * Do a regular freemsg(), as this is an IP
				 * error (no local route) not an IPsec one.
				 */
				freemsg(mp);
			}
		}

		ip_proto_input(q, mp, ipha, ire, recv_ill, esp_ports);
		if (free_ire)
			ire_refrele(ire);
	}

	return (esp_ports == 0);
}

/*
 * Deliver a udp packet to the given conn, possibly applying ipsec policy.
 * We are responsible for disposing of mp, such as by freemsg() or putnext()
 * Caller is responsible for dropping references to the conn, and freeing
 * first_mp.
 *
 * IPQoS Notes
 * Before sending it to the client, invoke IPPF processing. Policy processing
 * takes place only if the callout_position, IPP_LOCAL_IN, is enabled and
 * ip_policy is true. If we get here from icmp_inbound_error_fanout or
 * ip_wput_local, ip_policy is false.
 */
static void
ip_fanout_udp_conn(conn_t *connp, mblk_t *first_mp, mblk_t *mp,
    boolean_t secure, ill_t *ill, ipha_t *ipha, uint_t flags, ill_t *recv_ill,
    boolean_t ip_policy)
{
	boolean_t	mctl_present = (first_mp != NULL);
	uint32_t	in_flags = 0; /* set to IP_RECVSLLA and/or IP_RECVIF */
	uint32_t	ill_index;
	ip_stack_t	*ipst = recv_ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	ASSERT(ill != NULL);

	if (mctl_present)
		first_mp->b_cont = mp;
	else
		first_mp = mp;

	if (CONN_UDP_FLOWCTLD(connp)) {
		BUMP_MIB(ill->ill_ip_mib, udpIfStatsInOverflows);
		freemsg(first_mp);
		return;
	}

	if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) || secure) {
		first_mp = ipsec_check_inbound_policy(first_mp, connp, ipha,
		    NULL, mctl_present);
		/* Freed by ipsec_check_inbound_policy(). */
		if (first_mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return;
		}
	}
	if (mctl_present)
		freeb(first_mp);

	/* Let's hope the compilers utter "branch, predict-not-taken..." ;) */
	if (connp->conn_udp->udp_nat_t_endpoint) {
		if (mctl_present) {
			/* mctl_present *shouldn't* happen. */
			ip_drop_packet(mp, B_TRUE, NULL, NULL,
			    DROPPER(ipss, ipds_esp_nat_t_ipsec),
			    &ipss->ipsec_dropper);
			return;
		}

		if (!zero_spi_check(ill->ill_rq, mp, NULL, recv_ill, ipss))
			return;
	}

	/* Handle options. */
	if (connp->conn_recvif)
		in_flags = IPF_RECVIF;
	/*
	 * UDP supports IP_RECVPKTINFO option for both v4 and v6 so the flag
	 * passed to ip_add_info is based on IP version of connp.
	 */
	if (connp->conn_ip_recvpktinfo && (flags & IP_FF_IPINFO)) {
		if (connp->conn_af_isv6) {
			/*
			 * V6 only needs index
			 */
			in_flags |= IPF_RECVIF;
		} else {
			/*
			 * V4 needs index + matching address.
			 */
			in_flags |= IPF_RECVADDR;
		}
	}

	if (connp->conn_recvslla && !(flags & IP_FF_SEND_SLLA))
		in_flags |= IPF_RECVSLLA;

	/*
	 * Initiate IPPF processing here, if needed. Note first_mp won't be
	 * freed if the packet is dropped. The caller will do so.
	 */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst) && ip_policy) {
		ill_index = recv_ill->ill_phyint->phyint_ifindex;
		ip_process(IPP_LOCAL_IN, &mp, ill_index);
		if (mp == NULL) {
			return;
		}
	}
	if ((in_flags != 0) &&
	    (mp->b_datap->db_type != M_CTL)) {
		/*
		 * The actual data will be contained in b_cont
		 * upon successful return of the following call
		 * else original mblk is returned
		 */
		ASSERT(recv_ill != NULL);
		mp = ip_add_info(mp, recv_ill, in_flags, IPCL_ZONEID(connp),
		    ipst);
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
	/* Send it upstream */
	(connp->conn_recv)(connp, mp, NULL);
}

/*
 * Fanout for UDP packets.
 * The caller puts <fport, lport> in the ports parameter.
 *
 * If SO_REUSEADDR is set all multicast and broadcast packets
 * will be delivered to all streams bound to the same port.
 *
 * Zones notes:
 * Multicast and broadcast packets will be distributed to streams in all zones.
 * In the special case where an AF_INET socket binds to 0.0.0.0/<port> and an
 * AF_INET6 socket binds to ::/<port>, only the AF_INET socket receives the IPv4
 * packets. To maintain this behavior with multiple zones, the conns are grouped
 * by zone and the SO_REUSEADDR flag is checked for the first matching conn in
 * each zone. If unset, all the following conns in the same zone are skipped.
 */
static void
ip_fanout_udp(queue_t *q, mblk_t *mp, ill_t *ill, ipha_t *ipha,
    uint32_t ports, boolean_t broadcast, uint_t flags, boolean_t mctl_present,
    boolean_t ip_policy, ill_t *recv_ill, zoneid_t zoneid)
{
	uint32_t	dstport, srcport;
	ipaddr_t	dst;
	mblk_t		*first_mp;
	boolean_t	secure;
	in6_addr_t	v6src;
	conn_t		*connp;
	connf_t		*connfp;
	conn_t		*first_connp;
	conn_t		*next_connp;
	mblk_t		*mp1, *first_mp1;
	ipaddr_t	src;
	zoneid_t	last_zoneid;
	boolean_t	reuseaddr;
	boolean_t	shared_addr;
	boolean_t	unlabeled;
	ip_stack_t	*ipst;

	ASSERT(recv_ill != NULL);
	ipst = recv_ill->ill_ipst;

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		first_mp->b_cont = NULL;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		first_mp = NULL;
		secure = B_FALSE;
	}

	/* Extract ports in net byte order */
	dstport = htons(ntohl(ports) & 0xFFFF);
	srcport = htons(ntohl(ports) >> 16);
	dst = ipha->ipha_dst;
	src = ipha->ipha_src;

	unlabeled = B_FALSE;
	if (is_system_labeled())
		/* Cred cannot be null on IPv4 */
		unlabeled = (crgetlabel(DB_CRED(mp))->tsl_flags &
		    TSLF_UNLABELED) != 0;
	shared_addr = (zoneid == ALL_ZONES);
	if (shared_addr) {
		/*
		 * No need to handle exclusive-stack zones since ALL_ZONES
		 * only applies to the shared stack.
		 */
		zoneid = tsol_mlp_findzone(IPPROTO_UDP, dstport);
		/*
		 * If no shared MLP is found, tsol_mlp_findzone returns
		 * ALL_ZONES.  In that case, we assume it's SLP, and
		 * search for the zone based on the packet label.
		 *
		 * If there is such a zone, we prefer to find a
		 * connection in it.  Otherwise, we look for a
		 * MAC-exempt connection in any zone whose label
		 * dominates the default label on the packet.
		 */
		if (zoneid == ALL_ZONES)
			zoneid = tsol_packet_to_zoneid(mp);
		else
			unlabeled = B_FALSE;
	}

	connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(dstport, ipst)];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	if (!broadcast && !CLASSD(dst)) {
		/*
		 * Not broadcast or multicast. Send to the one (first)
		 * client we find. No need to check conn_wantpacket()
		 * since IP_BOUND_IF/conn_incoming_ill does not apply to
		 * IPv4 unicast packets.
		 */
		while ((connp != NULL) &&
		    (!IPCL_UDP_MATCH(connp, dstport, dst, srcport, src) ||
		    (!IPCL_ZONE_MATCH(connp, zoneid) &&
		    !(unlabeled && connp->conn_mac_exempt)))) {
			/*
			 * We keep searching since the conn did not match,
			 * or its zone did not match and it is not either
			 * an allzones conn or a mac exempt conn (if the
			 * sender is unlabeled.)
			 */
			connp = connp->conn_next;
		}

		if (connp == NULL || connp->conn_upq == NULL)
			goto notfound;

		if (is_system_labeled() &&
		    !tsol_receive_local(mp, &dst, IPV4_VERSION, shared_addr,
		    connp))
			goto notfound;

		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
		ip_fanout_udp_conn(connp, first_mp, mp, secure, ill, ipha,
		    flags, recv_ill, ip_policy);
		IP_STAT(ipst, ip_udp_fannorm);
		CONN_DEC_REF(connp);
		return;
	}

	/*
	 * Broadcast and multicast case
	 *
	 * Need to check conn_wantpacket().
	 * If SO_REUSEADDR has been set on the first we send the
	 * packet to all clients that have joined the group and
	 * match the port.
	 */

	while (connp != NULL) {
		if ((IPCL_UDP_MATCH(connp, dstport, dst, srcport, src)) &&
		    conn_wantpacket(connp, ill, ipha, flags, zoneid) &&
		    (!is_system_labeled() ||
		    tsol_receive_local(mp, &dst, IPV4_VERSION, shared_addr,
		    connp)))
			break;
		connp = connp->conn_next;
	}

	if (connp == NULL || connp->conn_upq == NULL)
		goto notfound;

	first_connp = connp;
	/*
	 * When SO_REUSEADDR is not set, send the packet only to the first
	 * matching connection in its zone by keeping track of the zoneid.
	 */
	reuseaddr = first_connp->conn_reuseaddr;
	last_zoneid = first_connp->conn_zoneid;

	CONN_INC_REF(connp);
	connp = connp->conn_next;
	for (;;) {
		while (connp != NULL) {
			if (IPCL_UDP_MATCH(connp, dstport, dst, srcport, src) &&
			    (reuseaddr || connp->conn_zoneid != last_zoneid) &&
			    conn_wantpacket(connp, ill, ipha, flags, zoneid) &&
			    (!is_system_labeled() ||
			    tsol_receive_local(mp, &dst, IPV4_VERSION,
			    shared_addr, connp)))
				break;
			connp = connp->conn_next;
		}
		/*
		 * Just copy the data part alone. The mctl part is
		 * needed just for verifying policy and it is never
		 * sent up.
		 */
		if (connp == NULL || (((mp1 = dupmsg(mp)) == NULL) &&
		    ((mp1 = copymsg(mp)) == NULL))) {
			/*
			 * No more interested clients or memory
			 * allocation failed
			 */
			connp = first_connp;
			break;
		}
		if (connp->conn_zoneid != last_zoneid) {
			/*
			 * Update the zoneid so that the packet isn't sent to
			 * any more conns in the same zone unless SO_REUSEADDR
			 * is set.
			 */
			reuseaddr = connp->conn_reuseaddr;
			last_zoneid = connp->conn_zoneid;
		}
		if (first_mp != NULL) {
			ASSERT(((ipsec_info_t *)first_mp->b_rptr)->
			    ipsec_info_type == IPSEC_IN);
			first_mp1 = ipsec_in_tag(first_mp, NULL,
			    ipst->ips_netstack);
			if (first_mp1 == NULL) {
				freemsg(mp1);
				connp = first_connp;
				break;
			}
		} else {
			first_mp1 = NULL;
		}
		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
		/*
		 * IPQoS notes: We don't send the packet for policy
		 * processing here, will do it for the last one (below).
		 * i.e. we do it per-packet now, but if we do policy
		 * processing per-conn, then we would need to do it
		 * here too.
		 */
		ip_fanout_udp_conn(connp, first_mp1, mp1, secure, ill,
		    ipha, flags, recv_ill, B_FALSE);
		mutex_enter(&connfp->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_connp = connp->conn_next;
		IP_STAT(ipst, ip_udp_fanmb);
		CONN_DEC_REF(connp);
		connp = next_connp;
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);
	ip_fanout_udp_conn(connp, first_mp, mp, secure, ill, ipha, flags,
	    recv_ill, ip_policy);
	IP_STAT(ipst, ip_udp_fanmb);
	CONN_DEC_REF(connp);
	return;

notfound:

	mutex_exit(&connfp->connf_lock);
	IP_STAT(ipst, ip_udp_fanothers);
	/*
	 * IPv6 endpoints bound to unicast or multicast IPv4-mapped addresses
	 * have already been matched above, since they live in the IPv4
	 * fanout tables. This implies we only need to
	 * check for IPv6 in6addr_any endpoints here.
	 * Thus we compare using ipv6_all_zeros instead of the destination
	 * address, except for the multicast group membership lookup which
	 * uses the IPv4 destination.
	 */
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &v6src);
	connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(dstport, ipst)];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	if (!broadcast && !CLASSD(dst)) {
		while (connp != NULL) {
			if (IPCL_UDP_MATCH_V6(connp, dstport, ipv6_all_zeros,
			    srcport, v6src) && IPCL_ZONE_MATCH(connp, zoneid) &&
			    conn_wantpacket(connp, ill, ipha, flags, zoneid) &&
			    !connp->conn_ipv6_v6only)
				break;
			connp = connp->conn_next;
		}

		if (connp != NULL && is_system_labeled() &&
		    !tsol_receive_local(mp, &dst, IPV4_VERSION, shared_addr,
		    connp))
			connp = NULL;

		if (connp == NULL || connp->conn_upq == NULL) {
			/*
			 * No one bound to this port.  Is
			 * there a client that wants all
			 * unclaimed datagrams?
			 */
			mutex_exit(&connfp->connf_lock);

			if (mctl_present)
				first_mp->b_cont = mp;
			else
				first_mp = mp;
			if (ipst->ips_ipcl_proto_fanout[IPPROTO_UDP].
			    connf_head != NULL) {
				ip_fanout_proto(q, first_mp, ill, ipha,
				    flags | IP_FF_RAWIP, mctl_present,
				    ip_policy, recv_ill, zoneid);
			} else {
				if (ip_fanout_send_icmp(q, first_mp, flags,
				    ICMP_DEST_UNREACHABLE,
				    ICMP_PORT_UNREACHABLE,
				    mctl_present, zoneid, ipst)) {
					BUMP_MIB(ill->ill_ip_mib,
					    udpIfStatsNoPorts);
				}
			}
			return;
		}

		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
		ip_fanout_udp_conn(connp, first_mp, mp, secure, ill, ipha,
		    flags, recv_ill, ip_policy);
		CONN_DEC_REF(connp);
		return;
	}
	/*
	 * IPv4 multicast packet being delivered to an AF_INET6
	 * in6addr_any endpoint.
	 * Need to check conn_wantpacket(). Note that we use conn_wantpacket()
	 * and not conn_wantpacket_v6() since any multicast membership is
	 * for an IPv4-mapped multicast address.
	 * The packet is sent to all clients in all zones that have joined the
	 * group and match the port.
	 */
	while (connp != NULL) {
		if (IPCL_UDP_MATCH_V6(connp, dstport, ipv6_all_zeros,
		    srcport, v6src) &&
		    conn_wantpacket(connp, ill, ipha, flags, zoneid) &&
		    (!is_system_labeled() ||
		    tsol_receive_local(mp, &dst, IPV4_VERSION, shared_addr,
		    connp)))
			break;
		connp = connp->conn_next;
	}

	if (connp == NULL || connp->conn_upq == NULL) {
		/*
		 * No one bound to this port.  Is
		 * there a client that wants all
		 * unclaimed datagrams?
		 */
		mutex_exit(&connfp->connf_lock);

		if (mctl_present)
			first_mp->b_cont = mp;
		else
			first_mp = mp;
		if (ipst->ips_ipcl_proto_fanout[IPPROTO_UDP].connf_head !=
		    NULL) {
			ip_fanout_proto(q, first_mp, ill, ipha,
			    flags | IP_FF_RAWIP, mctl_present, ip_policy,
			    recv_ill, zoneid);
		} else {
			/*
			 * We used to attempt to send an icmp error here, but
			 * since this is known to be a multicast packet
			 * and we don't send icmp errors in response to
			 * multicast, just drop the packet and give up sooner.
			 */
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsNoPorts);
			freemsg(first_mp);
		}
		return;
	}

	first_connp = connp;

	CONN_INC_REF(connp);
	connp = connp->conn_next;
	for (;;) {
		while (connp != NULL) {
			if (IPCL_UDP_MATCH_V6(connp, dstport,
			    ipv6_all_zeros, srcport, v6src) &&
			    conn_wantpacket(connp, ill, ipha, flags, zoneid) &&
			    (!is_system_labeled() ||
			    tsol_receive_local(mp, &dst, IPV4_VERSION,
			    shared_addr, connp)))
				break;
			connp = connp->conn_next;
		}
		/*
		 * Just copy the data part alone. The mctl part is
		 * needed just for verifying policy and it is never
		 * sent up.
		 */
		if (connp == NULL || (((mp1 = dupmsg(mp)) == NULL) &&
		    ((mp1 = copymsg(mp)) == NULL))) {
			/*
			 * No more intested clients or memory
			 * allocation failed
			 */
			connp = first_connp;
			break;
		}
		if (first_mp != NULL) {
			ASSERT(((ipsec_info_t *)first_mp->b_rptr)->
			    ipsec_info_type == IPSEC_IN);
			first_mp1 = ipsec_in_tag(first_mp, NULL,
			    ipst->ips_netstack);
			if (first_mp1 == NULL) {
				freemsg(mp1);
				connp = first_connp;
				break;
			}
		} else {
			first_mp1 = NULL;
		}
		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
		/*
		 * IPQoS notes: We don't send the packet for policy
		 * processing here, will do it for the last one (below).
		 * i.e. we do it per-packet now, but if we do policy
		 * processing per-conn, then we would need to do it
		 * here too.
		 */
		ip_fanout_udp_conn(connp, first_mp1, mp1, secure, ill,
		    ipha, flags, recv_ill, B_FALSE);
		mutex_enter(&connfp->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_connp = connp->conn_next;
		CONN_DEC_REF(connp);
		connp = next_connp;
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);
	ip_fanout_udp_conn(connp, first_mp, mp, secure, ill, ipha, flags,
	    recv_ill, ip_policy);
	CONN_DEC_REF(connp);
}

/*
 * Complete the ip_wput header so that it
 * is possible to generate ICMP
 * errors.
 */
int
ip_hdr_complete(ipha_t *ipha, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t *ire;

	if (ipha->ipha_src == INADDR_ANY) {
		ire = ire_lookup_local(zoneid, ipst);
		if (ire == NULL) {
			ip1dbg(("ip_hdr_complete: no source IRE\n"));
			return (1);
		}
		ipha->ipha_src = ire->ire_addr;
		ire_refrele(ire);
	}
	ipha->ipha_ttl = ipst->ips_ip_def_ttl;
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
	return (0);
}

/*
 * Nobody should be sending
 * packets up this stream
 */
static void
ip_lrput(queue_t *q, mblk_t *mp)
{
	mblk_t *mp1;

	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		/* Turn around */
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHR;
			qreply(q, mp);
			return;
		}
		break;
	}
	/* Could receive messages that passed through ar_rput */
	for (mp1 = mp; mp1; mp1 = mp1->b_cont)
		mp1->b_prev = mp1->b_next = NULL;
	freemsg(mp);
}

/* Nobody should be sending packets down this stream */
/* ARGSUSED */
void
ip_lwput(queue_t *q, mblk_t *mp)
{
	freemsg(mp);
}

/*
 * Move the first hop in any source route to ipha_dst and remove that part of
 * the source route.  Called by other protocols.  Errors in option formatting
 * are ignored - will be handled by ip_wput_options Return the final
 * destination (either ipha_dst or the last entry in a source route.)
 */
ipaddr_t
ip_massage_options(ipha_t *ipha, netstack_t *ns)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	int		i;
	ire_t		*ire;
	ip_stack_t	*ipst = ns->netstack_ip;

	ip2dbg(("ip_massage_options\n"));
	dst = ipha->ipha_dst;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		switch (optval) {
			uint8_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg(("ip_massage_options: bad src route\n"));
				break;
			}
			optlen = opts.ipoptp_len;
			off = opt[IPOPT_OFFSET];
			off--;
		redo_srr:
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* End of source route */
				ip1dbg(("ip_massage_options: end of SR\n"));
				break;
			}
			bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
			ip1dbg(("ip_massage_options: next hop 0x%x\n",
			    ntohl(dst)));
			/*
			 * Check if our address is present more than
			 * once as consecutive hops in source route.
			 * XXX verify per-interface ip_forwarding
			 * for source route?
			 */
			ire = ire_ctable_lookup(dst, 0, IRE_LOCAL, NULL,
			    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (ire != NULL) {
				ire_refrele(ire);
				off += IP_ADDR_LEN;
				goto redo_srr;
			}
			if (dst == htonl(INADDR_LOOPBACK)) {
				ip1dbg(("ip_massage_options: loopback addr in "
				    "source route!\n"));
				break;
			}
			/*
			 * Update ipha_dst to be the first hop and remove the
			 * first hop from the source route (by overwriting
			 * part of the option with NOP options).
			 */
			ipha->ipha_dst = dst;
			/* Put the last entry in dst */
			off = ((optlen - IP_ADDR_LEN - 3) & ~(IP_ADDR_LEN-1)) +
			    3;
			bcopy(&opt[off], &dst, IP_ADDR_LEN);

			ip1dbg(("ip_massage_options: last hop 0x%x\n",
			    ntohl(dst)));
			/* Move down and overwrite */
			opt[IP_ADDR_LEN] = opt[0];
			opt[IP_ADDR_LEN+1] = opt[IPOPT_OLEN] - IP_ADDR_LEN;
			opt[IP_ADDR_LEN+2] = opt[IPOPT_OFFSET];
			for (i = 0; i < IP_ADDR_LEN; i++)
				opt[i] = IPOPT_NOP;
			break;
		}
	}
	return (dst);
}

/*
 * Return the network mask
 * associated with the specified address.
 */
ipaddr_t
ip_net_mask(ipaddr_t addr)
{
	uchar_t	*up = (uchar_t *)&addr;
	ipaddr_t mask = 0;
	uchar_t	*maskp = (uchar_t *)&mask;

#if defined(__i386) || defined(__amd64)
#define	TOTALLY_BRAIN_DAMAGED_C_COMPILER
#endif
#ifdef  TOTALLY_BRAIN_DAMAGED_C_COMPILER
	maskp[0] = maskp[1] = maskp[2] = maskp[3] = 0;
#endif
	if (CLASSD(addr)) {
		maskp[0] = 0xF0;
		return (mask);
	}

	/* We assume Class E default netmask to be 32 */
	if (CLASSE(addr))
		return (0xffffffffU);

	if (addr == 0)
		return (0);
	maskp[0] = 0xFF;
	if ((up[0] & 0x80) == 0)
		return (mask);

	maskp[1] = 0xFF;
	if ((up[0] & 0xC0) == 0x80)
		return (mask);

	maskp[2] = 0xFF;
	if ((up[0] & 0xE0) == 0xC0)
		return (mask);

	/* Otherwise return no mask */
	return ((ipaddr_t)0);
}

/*
 * Select an ill for the packet by considering load spreading across
 * a different ill in the group if dst_ill is part of some group.
 */
ill_t *
ip_newroute_get_dst_ill(ill_t *dst_ill)
{
	ill_t *ill;

	/*
	 * We schedule irrespective of whether the source address is
	 * INADDR_ANY or not. illgrp_scheduler returns a held ill.
	 */
	ill = illgrp_scheduler(dst_ill);
	if (ill == NULL)
		return (NULL);

	/*
	 * For groups with names ip_sioctl_groupname ensures that all
	 * ills are of same type. For groups without names, ifgrp_insert
	 * ensures this.
	 */
	ASSERT(dst_ill->ill_type == ill->ill_type);

	return (ill);
}

/*
 * Helper function for the IPIF_NOFAILOVER/ATTACH_IF interface attachment case.
 */
ill_t *
ip_grab_attach_ill(ill_t *ill, mblk_t *first_mp, int ifindex, boolean_t isv6,
    ip_stack_t *ipst)
{
	ill_t *ret_ill;

	ASSERT(ifindex != 0);
	ret_ill = ill_lookup_on_ifindex(ifindex, isv6, NULL, NULL, NULL, NULL,
	    ipst);
	if (ret_ill == NULL ||
	    (ret_ill->ill_phyint->phyint_flags & PHYI_OFFLINE)) {
		if (isv6) {
			if (ill != NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			} else {
				BUMP_MIB(&ipst->ips_ip6_mib,
				    ipIfStatsOutDiscards);
			}
			ip1dbg(("ip_grab_attach_ill (IPv6): "
			    "bad ifindex %d.\n", ifindex));
		} else {
			if (ill != NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			} else {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsOutDiscards);
			}
			ip1dbg(("ip_grab_attach_ill (IPv4): "
			    "bad ifindex %d.\n", ifindex));
		}
		if (ret_ill != NULL)
			ill_refrele(ret_ill);
		freemsg(first_mp);
		return (NULL);
	}

	return (ret_ill);
}

/*
 * IPv4 -
 * ip_newroute is called by ip_rput or ip_wput whenever we need to send
 * out a packet to a destination address for which we do not have specific
 * (or sufficient) routing information.
 *
 * NOTE : These are the scopes of some of the variables that point at IRE,
 *	  which needs to be followed while making any future modifications
 *	  to avoid memory leaks.
 *
 *	- ire and sire are the entries looked up initially by
 *	  ire_ftable_lookup.
 *	- ipif_ire is used to hold the interface ire associated with
 *	  the new cache ire. But it's scope is limited, so we always REFRELE
 *	  it before branching out to error paths.
 *	- save_ire is initialized before ire_create, so that ire returned
 *	  by ire_create will not over-write the ire. We REFRELE save_ire
 *	  before breaking out of the switch.
 *
 *	Thus on failures, we have to REFRELE only ire and sire, if they
 *	are not NULL.
 */
void
ip_newroute(queue_t *q, mblk_t *mp, ipaddr_t dst, conn_t *connp,
    zoneid_t zoneid, ip_stack_t *ipst)
{
	areq_t	*areq;
	ipaddr_t gw = 0;
	ire_t	*ire = NULL;
	mblk_t	*res_mp;
	ipaddr_t *addrp;
	ipaddr_t nexthop_addr;
	ipif_t  *src_ipif = NULL;
	ill_t	*dst_ill = NULL;
	ipha_t  *ipha;
	ire_t	*sire = NULL;
	mblk_t	*first_mp;
	ire_t	*save_ire;
	ill_t	*attach_ill = NULL;	/* Bind to IPIF_NOFAILOVER address */
	ushort_t ire_marks = 0;
	boolean_t mctl_present;
	ipsec_out_t *io;
	mblk_t	*saved_mp;
	ire_t	*first_sire = NULL;
	mblk_t	*copy_mp = NULL;
	mblk_t	*xmit_mp = NULL;
	ipaddr_t save_dst;
	uint32_t multirt_flags =
	    MULTIRT_CACHEGW | MULTIRT_USESTAMP | MULTIRT_SETSTAMP;
	boolean_t multirt_is_resolvable;
	boolean_t multirt_resolve_next;
	boolean_t unspec_src;
	boolean_t do_attach_ill = B_FALSE;
	boolean_t ip_nexthop = B_FALSE;
	tsol_ire_gw_secattr_t *attrp = NULL;
	tsol_gcgrp_t *gcgrp = NULL;
	tsol_gcgrp_addr_t ga;

	if (ip_debug > 2) {
		/* ip1dbg */
		pr_addr_dbg("ip_newroute: dst %s\n", AF_INET, &dst);
	}

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);
	if (mctl_present) {
		io = (ipsec_out_t *)first_mp->b_rptr;
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
		ASSERT(zoneid == io->ipsec_out_zoneid);
		ASSERT(zoneid != ALL_ZONES);
	}

	ipha = (ipha_t *)mp->b_rptr;

	/* All multicast lookups come through ip_newroute_ipif() */
	if (CLASSD(dst)) {
		ip0dbg(("ip_newroute: CLASSD 0x%x (b_prev %p, b_next %p)\n",
		    ntohl(dst), (void *)mp->b_prev, (void *)mp->b_next));
		freemsg(first_mp);
		return;
	}

	if (mctl_present && io->ipsec_out_attach_if) {
		/* ip_grab_attach_ill returns a held ill */
		attach_ill = ip_grab_attach_ill(NULL, first_mp,
		    io->ipsec_out_ill_index, B_FALSE, ipst);

		/* Failure case frees things for us. */
		if (attach_ill == NULL)
			return;

		/*
		 * Check if we need an ire that will not be
		 * looked up by anybody else i.e. HIDDEN.
		 */
		if (ill_is_probeonly(attach_ill))
			ire_marks = IRE_MARK_HIDDEN;
	}
	if (mctl_present && io->ipsec_out_ip_nexthop) {
		ip_nexthop = B_TRUE;
		nexthop_addr = io->ipsec_out_nexthop_addr;
	}
	/*
	 * If this IRE is created for forwarding or it is not for
	 * traffic for congestion controlled protocols, mark it as temporary.
	 */
	if (mp->b_prev != NULL || !IP_FLOW_CONTROLLED_ULP(ipha->ipha_protocol))
		ire_marks |= IRE_MARK_TEMPORARY;

	/*
	 * Get what we can from ire_ftable_lookup which will follow an IRE
	 * chain until it gets the most specific information available.
	 * For example, we know that there is no IRE_CACHE for this dest,
	 * but there may be an IRE_OFFSUBNET which specifies a gateway.
	 * ire_ftable_lookup will look up the gateway, etc.
	 * Otherwise, given ire_ftable_lookup algorithm, only one among routes
	 * to the destination, of equal netmask length in the forward table,
	 * will be recursively explored. If no information is available
	 * for the final gateway of that route, we force the returned ire
	 * to be equal to sire using MATCH_IRE_PARENT.
	 * At least, in this case we have a starting point (in the buckets)
	 * to look for other routes to the destination in the forward table.
	 * This is actually used only for multirouting, where a list
	 * of routes has to be processed in sequence.
	 *
	 * In the process of coming up with the most specific information,
	 * ire_ftable_lookup may end up with an incomplete IRE_CACHE entry
	 * for the gateway (i.e., one for which the ire_nce->nce_state is
	 * not yet ND_REACHABLE, and is in the middle of arp resolution).
	 * Two caveats when handling incomplete ire's in ip_newroute:
	 * - we should be careful when accessing its ire_nce (specifically
	 *   the nce_res_mp) ast it might change underneath our feet, and,
	 * - not all legacy code path callers are prepared to handle
	 *   incomplete ire's, so we should not create/add incomplete
	 *   ire_cache entries here. (See discussion about temporary solution
	 *   further below).
	 *
	 * In order to minimize packet dropping, and to preserve existing
	 * behavior, we treat this case as if there were no IRE_CACHE for the
	 * gateway, and instead use the IF_RESOLVER ire to send out
	 * another request to ARP (this is achieved by passing the
	 * MATCH_IRE_COMPLETE flag to ire_ftable_lookup). When the
	 * arp response comes back in ip_wput_nondata, we will create
	 * a per-dst ire_cache that has an ND_COMPLETE ire.
	 *
	 * Note that this is a temporary solution; the correct solution is
	 * to create an incomplete  per-dst ire_cache entry, and send the
	 * packet out when the gw's nce is resolved. In order to achieve this,
	 * all packet processing must have been completed prior to calling
	 * ire_add_then_send. Some legacy code paths (e.g. cgtp) would need
	 * to be modified to accomodate this solution.
	 */
	if (ip_nexthop) {
		/*
		 * The first time we come here, we look for an IRE_INTERFACE
		 * entry for the specified nexthop, set the dst to be the
		 * nexthop address and create an IRE_CACHE entry for the
		 * nexthop. The next time around, we are able to find an
		 * IRE_CACHE entry for the nexthop, set the gateway to be the
		 * nexthop address and create an IRE_CACHE entry for the
		 * destination address via the specified nexthop.
		 */
		ire = ire_cache_lookup(nexthop_addr, zoneid,
		    MBLK_GETLABEL(mp), ipst);
		if (ire != NULL) {
			gw = nexthop_addr;
			ire_marks |= IRE_MARK_PRIVATE_ADDR;
		} else {
			ire = ire_ftable_lookup(nexthop_addr, 0, 0,
			    IRE_INTERFACE, NULL, NULL, zoneid, 0,
			    MBLK_GETLABEL(mp),
			    MATCH_IRE_TYPE | MATCH_IRE_SECATTR,
			    ipst);
			if (ire != NULL) {
				dst = nexthop_addr;
			}
		}
	} else if (attach_ill == NULL) {
		ire = ire_ftable_lookup(dst, 0, 0, 0,
		    NULL, &sire, zoneid, 0, MBLK_GETLABEL(mp),
		    MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
		    MATCH_IRE_RJ_BHOLE | MATCH_IRE_PARENT |
		    MATCH_IRE_SECATTR | MATCH_IRE_COMPLETE,
		    ipst);
	} else {
		/*
		 * attach_ill is set only for communicating with
		 * on-link hosts. So, don't look for DEFAULT.
		 */
		ipif_t	*attach_ipif;

		attach_ipif = ipif_get_next_ipif(NULL, attach_ill);
		if (attach_ipif == NULL) {
			ill_refrele(attach_ill);
			goto icmp_err_ret;
		}
		ire = ire_ftable_lookup(dst, 0, 0, 0, attach_ipif,
		    &sire, zoneid, 0, MBLK_GETLABEL(mp),
		    MATCH_IRE_RJ_BHOLE | MATCH_IRE_ILL |
		    MATCH_IRE_SECATTR, ipst);
		ipif_refrele(attach_ipif);
	}
	ip3dbg(("ip_newroute: ire_ftable_lookup() "
	    "returned ire %p, sire %p\n", (void *)ire, (void *)sire));

	/*
	 * This loop is run only once in most cases.
	 * We loop to resolve further routes only when the destination
	 * can be reached through multiple RTF_MULTIRT-flagged ires.
	 */
	do {
		/* Clear the previous iteration's values */
		if (src_ipif != NULL) {
			ipif_refrele(src_ipif);
			src_ipif = NULL;
		}
		if (dst_ill != NULL) {
			ill_refrele(dst_ill);
			dst_ill = NULL;
		}

		multirt_resolve_next = B_FALSE;
		/*
		 * We check if packets have to be multirouted.
		 * In this case, given the current <ire, sire> couple,
		 * we look for the next suitable <ire, sire>.
		 * This check is done in ire_multirt_lookup(),
		 * which applies various criteria to find the next route
		 * to resolve. ire_multirt_lookup() leaves <ire, sire>
		 * unchanged if it detects it has not been tried yet.
		 */
		if ((sire != NULL) && (sire->ire_flags & RTF_MULTIRT)) {
			ip3dbg(("ip_newroute: starting next_resolution "
			    "with first_mp %p, tag %d\n",
			    (void *)first_mp,
			    MULTIRT_DEBUG_TAGGED(first_mp)));

			ASSERT(sire != NULL);
			multirt_is_resolvable =
			    ire_multirt_lookup(&ire, &sire, multirt_flags,
			    MBLK_GETLABEL(mp), ipst);

			ip3dbg(("ip_newroute: multirt_is_resolvable %d, "
			    "ire %p, sire %p\n",
			    multirt_is_resolvable,
			    (void *)ire, (void *)sire));

			if (!multirt_is_resolvable) {
				/*
				 * No more multirt route to resolve; give up
				 * (all routes resolved or no more
				 * resolvable routes).
				 */
				if (ire != NULL) {
					ire_refrele(ire);
					ire = NULL;
				}
			} else {
				ASSERT(sire != NULL);
				ASSERT(ire != NULL);
				/*
				 * We simply use first_sire as a flag that
				 * indicates if a resolvable multirt route
				 * has already been found.
				 * If it is not the case, we may have to send
				 * an ICMP error to report that the
				 * destination is unreachable.
				 * We do not IRE_REFHOLD first_sire.
				 */
				if (first_sire == NULL) {
					first_sire = sire;
				}
			}
		}
		if (ire == NULL) {
			if (ip_debug > 3) {
				/* ip2dbg */
				pr_addr_dbg("ip_newroute: "
				    "can't resolve %s\n", AF_INET, &dst);
			}
			ip3dbg(("ip_newroute: "
			    "ire %p, sire %p, first_sire %p\n",
			    (void *)ire, (void *)sire, (void *)first_sire));

			if (sire != NULL) {
				ire_refrele(sire);
				sire = NULL;
			}

			if (first_sire != NULL) {
				/*
				 * At least one multirt route has been found
				 * in the same call to ip_newroute();
				 * there is no need to report an ICMP error.
				 * first_sire was not IRE_REFHOLDed.
				 */
				MULTIRT_DEBUG_UNTAG(first_mp);
				freemsg(first_mp);
				return;
			}
			ip_rts_change(RTM_MISS, dst, 0, 0, 0, 0, 0, 0,
			    RTA_DST, ipst);
			if (attach_ill != NULL)
				ill_refrele(attach_ill);
			goto icmp_err_ret;
		}

		/*
		 * Verify that the returned IRE does not have either
		 * the RTF_REJECT or RTF_BLACKHOLE flags set and that the IRE is
		 * either an IRE_CACHE, IRE_IF_NORESOLVER or IRE_IF_RESOLVER.
		 */
		if ((ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE)) ||
		    (ire->ire_type & (IRE_CACHE | IRE_INTERFACE)) == 0) {
			if (attach_ill != NULL)
				ill_refrele(attach_ill);
			goto icmp_err_ret;
		}
		/*
		 * Increment the ire_ob_pkt_count field for ire if it is an
		 * INTERFACE (IF_RESOLVER or IF_NORESOLVER) IRE type, and
		 * increment the same for the parent IRE, sire, if it is some
		 * sort of prefix IRE (which includes DEFAULT, PREFIX, and HOST)
		 */
		if ((ire->ire_type & IRE_INTERFACE) != 0) {
			UPDATE_OB_PKT_COUNT(ire);
			ire->ire_last_used_time = lbolt;
		}

		if (sire != NULL) {
			gw = sire->ire_gateway_addr;
			ASSERT((sire->ire_type & (IRE_CACHETABLE |
			    IRE_INTERFACE)) == 0);
			UPDATE_OB_PKT_COUNT(sire);
			sire->ire_last_used_time = lbolt;
		}
		/*
		 * We have a route to reach the destination.
		 *
		 * 1) If the interface is part of ill group, try to get a new
		 *    ill taking load spreading into account.
		 *
		 * 2) After selecting the ill, get a source address that
		 *    might create good inbound load spreading.
		 *    ipif_select_source does this for us.
		 *
		 * If the application specified the ill (ifindex), we still
		 * load spread. Only if the packets needs to go out
		 * specifically on a given ill e.g. binding to
		 * IPIF_NOFAILOVER address, then we don't try to use a
		 * different ill for load spreading.
		 */
		if (attach_ill == NULL) {
			/*
			 * Don't perform outbound load spreading in the
			 * case of an RTF_MULTIRT route, as we actually
			 * typically want to replicate outgoing packets
			 * through particular interfaces.
			 */
			if ((sire != NULL) && (sire->ire_flags & RTF_MULTIRT)) {
				dst_ill = ire->ire_ipif->ipif_ill;
				/* for uniformity */
				ill_refhold(dst_ill);
			} else {
				/*
				 * If we are here trying to create an IRE_CACHE
				 * for an offlink destination and have the
				 * IRE_CACHE for the next hop and the latter is
				 * using virtual IP source address selection i.e
				 * it's ire->ire_ipif is pointing to a virtual
				 * network interface (vni) then
				 * ip_newroute_get_dst_ll() will return the vni
				 * interface as the dst_ill. Since the vni is
				 * virtual i.e not associated with any physical
				 * interface, it cannot be the dst_ill, hence
				 * in such a case call ip_newroute_get_dst_ll()
				 * with the stq_ill instead of the ire_ipif ILL.
				 * The function returns a refheld ill.
				 */
				if ((ire->ire_type == IRE_CACHE) &&
				    IS_VNI(ire->ire_ipif->ipif_ill))
					dst_ill = ip_newroute_get_dst_ill(
					    ire->ire_stq->q_ptr);
				else
					dst_ill = ip_newroute_get_dst_ill(
					    ire->ire_ipif->ipif_ill);
			}
			if (dst_ill == NULL) {
				if (ip_debug > 2) {
					pr_addr_dbg("ip_newroute: "
					    "no dst ill for dst"
					    " %s\n", AF_INET, &dst);
				}
				goto icmp_err_ret;
			}
		} else {
			dst_ill = ire->ire_ipif->ipif_ill;
			/* for uniformity */
			ill_refhold(dst_ill);
			/*
			 * We should have found a route matching ill as we
			 * called ire_ftable_lookup with MATCH_IRE_ILL.
			 * Rather than asserting, when there is a mismatch,
			 * we just drop the packet.
			 */
			if (dst_ill != attach_ill) {
				ip0dbg(("ip_newroute: Packet dropped as "
				    "IPIF_NOFAILOVER ill is %s, "
				    "ire->ire_ipif->ipif_ill is %s\n",
				    attach_ill->ill_name,
				    dst_ill->ill_name));
				ill_refrele(attach_ill);
				goto icmp_err_ret;
			}
		}
		/* attach_ill can't go in loop. IPMP and CGTP are disjoint */
		if (attach_ill != NULL) {
			ill_refrele(attach_ill);
			attach_ill = NULL;
			do_attach_ill = B_TRUE;
		}
		ASSERT(dst_ill != NULL);
		ip2dbg(("ip_newroute: dst_ill %s\n", dst_ill->ill_name));

		/*
		 * Pick the best source address from dst_ill.
		 *
		 * 1) If it is part of a multipathing group, we would
		 *    like to spread the inbound packets across different
		 *    interfaces. ipif_select_source picks a random source
		 *    across the different ills in the group.
		 *
		 * 2) If it is not part of a multipathing group, we try
		 *    to pick the source address from the destination
		 *    route. Clustering assumes that when we have multiple
		 *    prefixes hosted on an interface, the prefix of the
		 *    source address matches the prefix of the destination
		 *    route. We do this only if the address is not
		 *    DEPRECATED.
		 *
		 * 3) If the conn is in a different zone than the ire, we
		 *    need to pick a source address from the right zone.
		 *
		 * NOTE : If we hit case (1) above, the prefix of the source
		 *	  address picked may not match the prefix of the
		 *	  destination routes prefix as ipif_select_source
		 *	  does not look at "dst" while picking a source
		 *	  address.
		 *	  If we want the same behavior as (2), we will need
		 *	  to change the behavior of ipif_select_source.
		 */
		ASSERT(src_ipif == NULL);
		if ((sire != NULL) && (sire->ire_flags & RTF_SETSRC)) {
			/*
			 * The RTF_SETSRC flag is set in the parent ire (sire).
			 * Check that the ipif matching the requested source
			 * address still exists.
			 */
			src_ipif = ipif_lookup_addr(sire->ire_src_addr, NULL,
			    zoneid, NULL, NULL, NULL, NULL, ipst);
		}

		unspec_src = (connp != NULL && connp->conn_unspec_src);

		if (src_ipif == NULL &&
		    (!unspec_src || ipha->ipha_src != INADDR_ANY)) {
			ire_marks |= IRE_MARK_USESRC_CHECK;
			if ((dst_ill->ill_group != NULL) ||
			    (ire->ire_ipif->ipif_flags & IPIF_DEPRECATED) ||
			    (connp != NULL && ire->ire_zoneid != zoneid &&
			    ire->ire_zoneid != ALL_ZONES) ||
			    (dst_ill->ill_usesrc_ifindex != 0)) {
				/*
				 * If the destination is reachable via a
				 * given gateway, the selected source address
				 * should be in the same subnet as the gateway.
				 * Otherwise, the destination is not reachable.
				 *
				 * If there are no interfaces on the same subnet
				 * as the destination, ipif_select_source gives
				 * first non-deprecated interface which might be
				 * on a different subnet than the gateway.
				 * This is not desirable. Hence pass the dst_ire
				 * source address to ipif_select_source.
				 * It is sure that the destination is reachable
				 * with the dst_ire source address subnet.
				 * So passing dst_ire source address to
				 * ipif_select_source will make sure that the
				 * selected source will be on the same subnet
				 * as dst_ire source address.
				 */
				ipaddr_t saddr = ire->ire_ipif->ipif_src_addr;
				src_ipif = ipif_select_source(dst_ill, saddr,
				    zoneid);
				if (src_ipif == NULL) {
					if (ip_debug > 2) {
						pr_addr_dbg("ip_newroute: "
						    "no src for dst %s ",
						    AF_INET, &dst);
						printf("through interface %s\n",
						    dst_ill->ill_name);
					}
					goto icmp_err_ret;
				}
			} else {
				src_ipif = ire->ire_ipif;
				ASSERT(src_ipif != NULL);
				/* hold src_ipif for uniformity */
				ipif_refhold(src_ipif);
			}
		}

		/*
		 * Assign a source address while we have the conn.
		 * We can't have ip_wput_ire pick a source address when the
		 * packet returns from arp since we need to look at
		 * conn_unspec_src and conn_zoneid, and we lose the conn when
		 * going through arp.
		 *
		 * NOTE : ip_newroute_v6 does not have this piece of code as
		 *	  it uses ip6i to store this information.
		 */
		if (ipha->ipha_src == INADDR_ANY && !unspec_src)
			ipha->ipha_src = src_ipif->ipif_src_addr;

		if (ip_debug > 3) {
			/* ip2dbg */
			pr_addr_dbg("ip_newroute: first hop %s\n",
			    AF_INET, &gw);
		}
		ip2dbg(("\tire type %s (%d)\n",
		    ip_nv_lookup(ire_nv_tbl, ire->ire_type), ire->ire_type));

		/*
		 * The TTL of multirouted packets is bounded by the
		 * ip_multirt_ttl ndd variable.
		 */
		if ((sire != NULL) && (sire->ire_flags & RTF_MULTIRT)) {
			/* Force TTL of multirouted packets */
			if ((ipst->ips_ip_multirt_ttl > 0) &&
			    (ipha->ipha_ttl > ipst->ips_ip_multirt_ttl)) {
				ip2dbg(("ip_newroute: forcing multirt TTL "
				    "to %d (was %d), dst 0x%08x\n",
				    ipst->ips_ip_multirt_ttl, ipha->ipha_ttl,
				    ntohl(sire->ire_addr)));
				ipha->ipha_ttl = ipst->ips_ip_multirt_ttl;
			}
		}
		/*
		 * At this point in ip_newroute(), ire is either the
		 * IRE_CACHE of the next-hop gateway for an off-subnet
		 * destination or an IRE_INTERFACE type that should be used
		 * to resolve an on-subnet destination or an on-subnet
		 * next-hop gateway.
		 *
		 * In the IRE_CACHE case, we have the following :
		 *
		 * 1) src_ipif - used for getting a source address.
		 *
		 * 2) dst_ill - from which we derive ire_stq/ire_rfq. This
		 *    means packets using this IRE_CACHE will go out on
		 *    dst_ill.
		 *
		 * 3) The IRE sire will point to the prefix that is the
		 *    longest  matching route for the destination. These
		 *    prefix types include IRE_DEFAULT, IRE_PREFIX, IRE_HOST.
		 *
		 *    The newly created IRE_CACHE entry for the off-subnet
		 *    destination is tied to both the prefix route and the
		 *    interface route used to resolve the next-hop gateway
		 *    via the ire_phandle and ire_ihandle fields,
		 *    respectively.
		 *
		 * In the IRE_INTERFACE case, we have the following :
		 *
		 * 1) src_ipif - used for getting a source address.
		 *
		 * 2) dst_ill - from which we derive ire_stq/ire_rfq. This
		 *    means packets using the IRE_CACHE that we will build
		 *    here will go out on dst_ill.
		 *
		 * 3) sire may or may not be NULL. But, the IRE_CACHE that is
		 *    to be created will only be tied to the IRE_INTERFACE
		 *    that was derived from the ire_ihandle field.
		 *
		 *    If sire is non-NULL, it means the destination is
		 *    off-link and we will first create the IRE_CACHE for the
		 *    gateway. Next time through ip_newroute, we will create
		 *    the IRE_CACHE for the final destination as described
		 *    above.
		 *
		 * In both cases, after the current resolution has been
		 * completed (or possibly initialised, in the IRE_INTERFACE
		 * case), the loop may be re-entered to attempt the resolution
		 * of another RTF_MULTIRT route.
		 *
		 * When an IRE_CACHE entry for the off-subnet destination is
		 * created, RTF_SETSRC and RTF_MULTIRT are inherited from sire,
		 * for further processing in emission loops.
		 */
		save_ire = ire;
		switch (ire->ire_type) {
		case IRE_CACHE: {
			ire_t	*ipif_ire;

			ASSERT(save_ire->ire_nce->nce_state == ND_REACHABLE);
			if (gw == 0)
				gw = ire->ire_gateway_addr;
			/*
			 * We need 3 ire's to create a new cache ire for an
			 * off-link destination from the cache ire of the
			 * gateway.
			 *
			 *	1. The prefix ire 'sire' (Note that this does
			 *	   not apply to the conn_nexthop_set case)
			 *	2. The cache ire of the gateway 'ire'
			 *	3. The interface ire 'ipif_ire'
			 *
			 * We have (1) and (2). We lookup (3) below.
			 *
			 * If there is no interface route to the gateway,
			 * it is a race condition, where we found the cache
			 * but the interface route has been deleted.
			 */
			if (ip_nexthop) {
				ipif_ire = ire_ihandle_lookup_onlink(ire);
			} else {
				ipif_ire =
				    ire_ihandle_lookup_offlink(ire, sire);
			}
			if (ipif_ire == NULL) {
				ip1dbg(("ip_newroute: "
				    "ire_ihandle_lookup_offlink failed\n"));
				goto icmp_err_ret;
			}

			/*
			 * Check cached gateway IRE for any security
			 * attributes; if found, associate the gateway
			 * credentials group to the destination IRE.
			 */
			if ((attrp = save_ire->ire_gw_secattr) != NULL) {
				mutex_enter(&attrp->igsa_lock);
				if ((gcgrp = attrp->igsa_gcgrp) != NULL)
					GCGRP_REFHOLD(gcgrp);
				mutex_exit(&attrp->igsa_lock);
			}

			/*
			 * XXX For the source of the resolver mp,
			 * we are using the same DL_UNITDATA_REQ
			 * (from save_ire->ire_nce->nce_res_mp)
			 * though the save_ire is not pointing at the same ill.
			 * This is incorrect. We need to send it up to the
			 * resolver to get the right res_mp. For ethernets
			 * this may be okay (ill_type == DL_ETHER).
			 */

			ire = ire_create(
			    (uchar_t *)&dst,		/* dest address */
			    (uchar_t *)&ip_g_all_ones,	/* mask */
			    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
			    (uchar_t *)&gw,		/* gateway address */
			    &save_ire->ire_max_frag,
			    save_ire->ire_nce,		/* src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,			/* IRE type */
			    src_ipif,
			    (sire != NULL) ?
			    sire->ire_mask : 0, 	/* Parent mask */
			    (sire != NULL) ?
			    sire->ire_phandle : 0,	/* Parent handle */
			    ipif_ire->ire_ihandle,	/* Interface handle */
			    (sire != NULL) ? (sire->ire_flags &
			    (RTF_SETSRC | RTF_MULTIRT)) : 0, /* flags */
			    (sire != NULL) ?
			    &(sire->ire_uinfo) : &(save_ire->ire_uinfo),
			    NULL,
			    gcgrp,
			    ipst);

			if (ire == NULL) {
				if (gcgrp != NULL) {
					GCGRP_REFRELE(gcgrp);
					gcgrp = NULL;
				}
				ire_refrele(ipif_ire);
				ire_refrele(save_ire);
				break;
			}

			/* reference now held by IRE */
			gcgrp = NULL;

			ire->ire_marks |= ire_marks;

			/*
			 * Prevent sire and ipif_ire from getting deleted.
			 * The newly created ire is tied to both of them via
			 * the phandle and ihandle respectively.
			 */
			if (sire != NULL) {
				IRB_REFHOLD(sire->ire_bucket);
				/* Has it been removed already ? */
				if (sire->ire_marks & IRE_MARK_CONDEMNED) {
					IRB_REFRELE(sire->ire_bucket);
					ire_refrele(ipif_ire);
					ire_refrele(save_ire);
					break;
				}
			}

			IRB_REFHOLD(ipif_ire->ire_bucket);
			/* Has it been removed already ? */
			if (ipif_ire->ire_marks & IRE_MARK_CONDEMNED) {
				IRB_REFRELE(ipif_ire->ire_bucket);
				if (sire != NULL)
					IRB_REFRELE(sire->ire_bucket);
				ire_refrele(ipif_ire);
				ire_refrele(save_ire);
				break;
			}

			xmit_mp = first_mp;
			/*
			 * In the case of multirouting, a copy
			 * of the packet is done before its sending.
			 * The copy is used to attempt another
			 * route resolution, in a next loop.
			 */
			if (ire->ire_flags & RTF_MULTIRT) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL) {
					xmit_mp = copy_mp;
					MULTIRT_DEBUG_TAG(first_mp);
				}
			}
			ire_add_then_send(q, ire, xmit_mp);
			ire_refrele(save_ire);

			/* Assert that sire is not deleted yet. */
			if (sire != NULL) {
				ASSERT(sire->ire_ptpn != NULL);
				IRB_REFRELE(sire->ire_bucket);
			}

			/* Assert that ipif_ire is not deleted yet. */
			ASSERT(ipif_ire->ire_ptpn != NULL);
			IRB_REFRELE(ipif_ire->ire_bucket);
			ire_refrele(ipif_ire);

			/*
			 * If copy_mp is not NULL, multirouting was
			 * requested. We loop to initiate a next
			 * route resolution attempt, starting from sire.
			 */
			if (copy_mp != NULL) {
				/*
				 * Search for the next unresolved
				 * multirt route.
				 */
				copy_mp = NULL;
				ipif_ire = NULL;
				ire = NULL;
				multirt_resolve_next = B_TRUE;
				continue;
			}
			if (sire != NULL)
				ire_refrele(sire);
			ipif_refrele(src_ipif);
			ill_refrele(dst_ill);
			return;
		}
		case IRE_IF_NORESOLVER: {
			if (dst_ill->ill_phys_addr_length != IP_ADDR_LEN &&
			    dst_ill->ill_resolver_mp == NULL) {
				ip1dbg(("ip_newroute: dst_ill %p "
				    "for IRE_IF_NORESOLVER ire %p has "
				    "no ill_resolver_mp\n",
				    (void *)dst_ill, (void *)ire));
				break;
			}

			/*
			 * TSol note: We are creating the ire cache for the
			 * destination 'dst'. If 'dst' is offlink, going
			 * through the first hop 'gw', the security attributes
			 * of 'dst' must be set to point to the gateway
			 * credentials of gateway 'gw'. If 'dst' is onlink, it
			 * is possible that 'dst' is a potential gateway that is
			 * referenced by some route that has some security
			 * attributes. Thus in the former case, we need to do a
			 * gcgrp_lookup of 'gw' while in the latter case we
			 * need to do gcgrp_lookup of 'dst' itself.
			 */
			ga.ga_af = AF_INET;
			IN6_IPADDR_TO_V4MAPPED(gw != INADDR_ANY ? gw : dst,
			    &ga.ga_addr);
			gcgrp = gcgrp_lookup(&ga, B_FALSE);

			ire = ire_create(
			    (uchar_t *)&dst,		/* dest address */
			    (uchar_t *)&ip_g_all_ones,	/* mask */
			    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
			    (uchar_t *)&gw,		/* gateway address */
			    &save_ire->ire_max_frag,
			    NULL,			/* no src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    save_ire->ire_mask,		/* Parent mask */
			    (sire != NULL) ?		/* Parent handle */
			    sire->ire_phandle : 0,
			    save_ire->ire_ihandle,	/* Interface handle */
			    (sire != NULL) ? sire->ire_flags &
			    (RTF_SETSRC | RTF_MULTIRT) : 0, /* flags */
			    &(save_ire->ire_uinfo),
			    NULL,
			    gcgrp,
			    ipst);

			if (ire == NULL) {
				if (gcgrp != NULL) {
					GCGRP_REFRELE(gcgrp);
					gcgrp = NULL;
				}
				ire_refrele(save_ire);
				break;
			}

			/* reference now held by IRE */
			gcgrp = NULL;

			ire->ire_marks |= ire_marks;

			/* Prevent save_ire from getting deleted */
			IRB_REFHOLD(save_ire->ire_bucket);
			/* Has it been removed already ? */
			if (save_ire->ire_marks & IRE_MARK_CONDEMNED) {
				IRB_REFRELE(save_ire->ire_bucket);
				ire_refrele(save_ire);
				break;
			}

			/*
			 * In the case of multirouting, a copy
			 * of the packet is made before it is sent.
			 * The copy is used in the next
			 * loop to attempt another resolution.
			 */
			xmit_mp = first_mp;
			if ((sire != NULL) &&
			    (sire->ire_flags & RTF_MULTIRT)) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL) {
					xmit_mp = copy_mp;
					MULTIRT_DEBUG_TAG(first_mp);
				}
			}
			ire_add_then_send(q, ire, xmit_mp);

			/* Assert that it is not deleted yet. */
			ASSERT(save_ire->ire_ptpn != NULL);
			IRB_REFRELE(save_ire->ire_bucket);
			ire_refrele(save_ire);

			if (copy_mp != NULL) {
				/*
				 * If we found a (no)resolver, we ignore any
				 * trailing top priority IRE_CACHE in further
				 * loops. This ensures that we do not omit any
				 * (no)resolver.
				 * This IRE_CACHE, if any, will be processed
				 * by another thread entering ip_newroute().
				 * IRE_CACHE entries, if any, will be processed
				 * by another thread entering ip_newroute(),
				 * (upon resolver response, for instance).
				 * This aims to force parallel multirt
				 * resolutions as soon as a packet must be sent.
				 * In the best case, after the tx of only one
				 * packet, all reachable routes are resolved.
				 * Otherwise, the resolution of all RTF_MULTIRT
				 * routes would require several emissions.
				 */
				multirt_flags &= ~MULTIRT_CACHEGW;

				/*
				 * Search for the next unresolved multirt
				 * route.
				 */
				copy_mp = NULL;
				save_ire = NULL;
				ire = NULL;
				multirt_resolve_next = B_TRUE;
				continue;
			}

			/*
			 * Don't need sire anymore
			 */
			if (sire != NULL)
				ire_refrele(sire);

			ipif_refrele(src_ipif);
			ill_refrele(dst_ill);
			return;
		}
		case IRE_IF_RESOLVER:
			/*
			 * We can't build an IRE_CACHE yet, but at least we
			 * found a resolver that can help.
			 */
			res_mp = dst_ill->ill_resolver_mp;
			if (!OK_RESOLVER_MP(res_mp))
				break;

			/*
			 * To be at this point in the code with a non-zero gw
			 * means that dst is reachable through a gateway that
			 * we have never resolved.  By changing dst to the gw
			 * addr we resolve the gateway first.
			 * When ire_add_then_send() tries to put the IP dg
			 * to dst, it will reenter ip_newroute() at which
			 * time we will find the IRE_CACHE for the gw and
			 * create another IRE_CACHE in case IRE_CACHE above.
			 */
			if (gw != INADDR_ANY) {
				/*
				 * The source ipif that was determined above was
				 * relative to the destination address, not the
				 * gateway's. If src_ipif was not taken out of
				 * the IRE_IF_RESOLVER entry, we'll need to call
				 * ipif_select_source() again.
				 */
				if (src_ipif != ire->ire_ipif) {
					ipif_refrele(src_ipif);
					src_ipif = ipif_select_source(dst_ill,
					    gw, zoneid);
					if (src_ipif == NULL) {
						if (ip_debug > 2) {
							pr_addr_dbg(
							    "ip_newroute: no "
							    "src for gw %s ",
							    AF_INET, &gw);
							printf("through "
							    "interface %s\n",
							    dst_ill->ill_name);
						}
						goto icmp_err_ret;
					}
				}
				save_dst = dst;
				dst = gw;
				gw = INADDR_ANY;
			}

			/*
			 * We obtain a partial IRE_CACHE which we will pass
			 * along with the resolver query.  When the response
			 * comes back it will be there ready for us to add.
			 * The ire_max_frag is atomically set under the
			 * irebucket lock in ire_add_v[46].
			 */

			ire = ire_create_mp(
			    (uchar_t *)&dst,		/* dest address */
			    (uchar_t *)&ip_g_all_ones,	/* mask */
			    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
			    (uchar_t *)&gw,		/* gateway address */
			    NULL,			/* ire_max_frag */
			    NULL,			/* no src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,			/* Interface ipif */
			    save_ire->ire_mask,		/* Parent mask */
			    0,
			    save_ire->ire_ihandle,	/* Interface handle */
			    0,				/* flags if any */
			    &(save_ire->ire_uinfo),
			    NULL,
			    NULL,
			    ipst);

			if (ire == NULL) {
				ire_refrele(save_ire);
				break;
			}

			if ((sire != NULL) &&
			    (sire->ire_flags & RTF_MULTIRT)) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL)
					MULTIRT_DEBUG_TAG(copy_mp);
			}

			ire->ire_marks |= ire_marks;

			/*
			 * Construct message chain for the resolver
			 * of the form:
			 * 	ARP_REQ_MBLK-->IRE_MBLK-->Packet
			 * Packet could contain a IPSEC_OUT mp.
			 *
			 * NOTE : ire will be added later when the response
			 * comes back from ARP. If the response does not
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
			ASSERT(ire->ire_mp != NULL);
			ire->ire_mp->b_cont = first_mp;
			/* Have saved_mp handy, for cleanup if canput fails */
			saved_mp = mp;
			mp = copyb(res_mp);
			if (mp == NULL) {
				/* Prepare for cleanup */
				mp = saved_mp; /* pkt */
				ire_delete(ire); /* ire_mp */
				ire = NULL;
				ire_refrele(save_ire);
				if (copy_mp != NULL) {
					MULTIRT_DEBUG_UNTAG(copy_mp);
					freemsg(copy_mp);
					copy_mp = NULL;
				}
				break;
			}
			linkb(mp, ire->ire_mp);

			/*
			 * Fill in the source and dest addrs for the resolver.
			 * NOTE: this depends on memory layouts imposed by
			 * ill_init().
			 */
			areq = (areq_t *)mp->b_rptr;
			addrp = (ipaddr_t *)((char *)areq +
			    areq->areq_sender_addr_offset);
			if (do_attach_ill) {
				/*
				 * This is bind to no failover case.
				 * arp packet also must go out on attach_ill.
				 */
				ASSERT(ipha->ipha_src != NULL);
				*addrp = ipha->ipha_src;
			} else {
				*addrp = save_ire->ire_src_addr;
			}

			ire_refrele(save_ire);
			addrp = (ipaddr_t *)((char *)areq +
			    areq->areq_target_addr_offset);
			*addrp = dst;
			/* Up to the resolver. */
			if (canputnext(dst_ill->ill_rq) &&
			    !(dst_ill->ill_arp_closing)) {
				putnext(dst_ill->ill_rq, mp);
				ire = NULL;
				if (copy_mp != NULL) {
					/*
					 * If we found a resolver, we ignore
					 * any trailing top priority IRE_CACHE
					 * in the further loops. This ensures
					 * that we do not omit any resolver.
					 * IRE_CACHE entries, if any, will be
					 * processed next time we enter
					 * ip_newroute().
					 */
					multirt_flags &= ~MULTIRT_CACHEGW;
					/*
					 * Search for the next unresolved
					 * multirt route.
					 */
					first_mp = copy_mp;
					copy_mp = NULL;
					/* Prepare the next resolution loop. */
					mp = first_mp;
					EXTRACT_PKT_MP(mp, first_mp,
					    mctl_present);
					if (mctl_present)
						io = (ipsec_out_t *)
						    first_mp->b_rptr;
					ipha = (ipha_t *)mp->b_rptr;

					ASSERT(sire != NULL);

					dst = save_dst;
					multirt_resolve_next = B_TRUE;
					continue;
				}

				if (sire != NULL)
					ire_refrele(sire);

				/*
				 * The response will come back in ip_wput
				 * with db_type IRE_DB_TYPE.
				 */
				ipif_refrele(src_ipif);
				ill_refrele(dst_ill);
				return;
			} else {
				/* Prepare for cleanup */
				DTRACE_PROBE1(ip__newroute__drop, mblk_t *,
				    mp);
				mp->b_cont = NULL;
				freeb(mp); /* areq */
				/*
				 * this is an ire that is not added to the
				 * cache. ire_freemblk will handle the release
				 * of any resources associated with the ire.
				 */
				ire_delete(ire); /* ire_mp */
				mp = saved_mp; /* pkt */
				ire = NULL;
				if (copy_mp != NULL) {
					MULTIRT_DEBUG_UNTAG(copy_mp);
					freemsg(copy_mp);
					copy_mp = NULL;
				}
				break;
			}
		default:
			break;
		}
	} while (multirt_resolve_next);

	ip1dbg(("ip_newroute: dropped\n"));
	/* Did this packet originate externally? */
	if (mp->b_prev) {
		mp->b_next = NULL;
		mp->b_prev = NULL;
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
	} else {
		if (dst_ill != NULL) {
			BUMP_MIB(dst_ill->ill_ip_mib, ipIfStatsOutDiscards);
		} else {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		}
	}
	ASSERT(copy_mp == NULL);
	MULTIRT_DEBUG_UNTAG(first_mp);
	freemsg(first_mp);
	if (ire != NULL)
		ire_refrele(ire);
	if (sire != NULL)
		ire_refrele(sire);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (dst_ill != NULL)
		ill_refrele(dst_ill);
	return;

icmp_err_ret:
	ip1dbg(("ip_newroute: no route\n"));
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (dst_ill != NULL)
		ill_refrele(dst_ill);
	if (sire != NULL)
		ire_refrele(sire);
	/* Did this packet originate externally? */
	if (mp->b_prev) {
		mp->b_next = NULL;
		mp->b_prev = NULL;
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInNoRoutes);
		q = WR(q);
	} else {
		/*
		 * There is no outgoing ill, so just increment the
		 * system MIB.
		 */
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutNoRoutes);
		/*
		 * Since ip_wput() isn't close to finished, we fill
		 * in enough of the header for credible error reporting.
		 */
		if (ip_hdr_complete(ipha, zoneid, ipst)) {
			/* Failed */
			MULTIRT_DEBUG_UNTAG(first_mp);
			freemsg(first_mp);
			if (ire != NULL)
				ire_refrele(ire);
			return;
		}
	}

	/*
	 * At this point we will have ire only if RTF_BLACKHOLE
	 * or RTF_REJECT flags are set on the IRE. It will not
	 * generate ICMP_HOST_UNREACHABLE if RTF_BLACKHOLE is set.
	 */
	if (ire != NULL) {
		if (ire->ire_flags & RTF_BLACKHOLE) {
			ire_refrele(ire);
			MULTIRT_DEBUG_UNTAG(first_mp);
			freemsg(first_mp);
			return;
		}
		ire_refrele(ire);
	}
	if (ip_source_routed(ipha, ipst)) {
		icmp_unreachable(q, first_mp, ICMP_SOURCE_ROUTE_FAILED,
		    zoneid, ipst);
		return;
	}
	icmp_unreachable(q, first_mp, ICMP_HOST_UNREACHABLE, zoneid, ipst);
}

ip_opt_info_t zero_info;

/*
 * IPv4 -
 * ip_newroute_ipif is called by ip_wput_multicast and
 * ip_rput_forward_multicast whenever we need to send
 * out a packet to a destination address for which we do not have specific
 * routing information. It is used when the packet will be sent out
 * on a specific interface. It is also called by ip_wput() when IP_BOUND_IF
 * socket option is set or icmp error message wants to go out on a particular
 * interface for a unicast packet.
 *
 * In most cases, the destination address is resolved thanks to the ipif
 * intrinsic resolver. However, there are some cases where the call to
 * ip_newroute_ipif must take into account the potential presence of
 * RTF_SETSRC and/or RTF_MULITRT flags in an IRE_OFFSUBNET ire
 * that uses the interface. This is specified through flags,
 * which can be a combination of:
 * - RTF_SETSRC: if an IRE_OFFSUBNET ire exists that has the RTF_SETSRC
 *   flag, the resulting ire will inherit the IRE_OFFSUBNET source address
 *   and flags. Additionally, the packet source address has to be set to
 *   the specified address. The caller is thus expected to set this flag
 *   if the packet has no specific source address yet.
 * - RTF_MULTIRT: if an IRE_OFFSUBNET ire exists that has the RTF_MULTIRT
 *   flag, the resulting ire will inherit the flag. All unresolved routes
 *   to the destination must be explored in the same call to
 *   ip_newroute_ipif().
 */
static void
ip_newroute_ipif(queue_t *q, mblk_t *mp, ipif_t *ipif, ipaddr_t dst,
    conn_t *connp, uint32_t flags, zoneid_t zoneid, ip_opt_info_t *infop)
{
	areq_t	*areq;
	ire_t	*ire = NULL;
	mblk_t	*res_mp;
	ipaddr_t *addrp;
	mblk_t *first_mp;
	ire_t	*save_ire = NULL;
	ill_t	*attach_ill = NULL;		/* Bind to IPIF_NOFAILOVER */
	ipif_t	*src_ipif = NULL;
	ushort_t ire_marks = 0;
	ill_t	*dst_ill = NULL;
	boolean_t mctl_present;
	ipsec_out_t *io;
	ipha_t *ipha;
	int	ihandle = 0;
	mblk_t	*saved_mp;
	ire_t   *fire = NULL;
	mblk_t  *copy_mp = NULL;
	boolean_t multirt_resolve_next;
	boolean_t unspec_src;
	ipaddr_t ipha_dst;
	ip_stack_t *ipst = ipif->ipif_ill->ill_ipst;

	/*
	 * CGTP goes in a loop which looks up a new ipif, do an ipif_refhold
	 * here for uniformity
	 */
	ipif_refhold(ipif);

	/*
	 * This loop is run only once in most cases.
	 * We loop to resolve further routes only when the destination
	 * can be reached through multiple RTF_MULTIRT-flagged ires.
	 */
	do {
		if (dst_ill != NULL) {
			ill_refrele(dst_ill);
			dst_ill = NULL;
		}
		if (src_ipif != NULL) {
			ipif_refrele(src_ipif);
			src_ipif = NULL;
		}
		multirt_resolve_next = B_FALSE;

		ip1dbg(("ip_newroute_ipif: dst 0x%x, if %s\n", ntohl(dst),
		    ipif->ipif_ill->ill_name));

		EXTRACT_PKT_MP(mp, first_mp, mctl_present);
		if (mctl_present)
			io = (ipsec_out_t *)first_mp->b_rptr;

		ipha = (ipha_t *)mp->b_rptr;

		/*
		 * Save the packet destination address, we may need it after
		 * the packet has been consumed.
		 */
		ipha_dst = ipha->ipha_dst;

		/*
		 * If the interface is a pt-pt interface we look for an
		 * IRE_IF_RESOLVER or IRE_IF_NORESOLVER that matches both the
		 * local_address and the pt-pt destination address. Otherwise
		 * we just match the local address.
		 * NOTE: dst could be different than ipha->ipha_dst in case
		 * of sending igmp multicast packets over a point-to-point
		 * connection.
		 * Thus we must be careful enough to check ipha_dst to be a
		 * multicast address, otherwise it will take xmit_if path for
		 * multicast packets resulting into kernel stack overflow by
		 * repeated calls to ip_newroute_ipif from ire_send().
		 */
		if (CLASSD(ipha_dst) &&
		    !(ipif->ipif_ill->ill_flags & ILLF_MULTICAST)) {
			goto err_ret;
		}

		/*
		 * We check if an IRE_OFFSUBNET for the addr that goes through
		 * ipif exists. We need it to determine if the RTF_SETSRC and/or
		 * RTF_MULTIRT flags must be honored. This IRE_OFFSUBNET ire may
		 * propagate its flags to the new ire.
		 */
		if (CLASSD(ipha_dst) && (flags & (RTF_MULTIRT | RTF_SETSRC))) {
			fire = ipif_lookup_multi_ire(ipif, ipha_dst);
			ip2dbg(("ip_newroute_ipif: "
			    "ipif_lookup_multi_ire("
			    "ipif %p, dst %08x) = fire %p\n",
			    (void *)ipif, ntohl(dst), (void *)fire));
		}

		if (mctl_present && io->ipsec_out_attach_if) {
			attach_ill = ip_grab_attach_ill(NULL, first_mp,
			    io->ipsec_out_ill_index, B_FALSE, ipst);

			/* Failure case frees things for us. */
			if (attach_ill == NULL) {
				ipif_refrele(ipif);
				if (fire != NULL)
					ire_refrele(fire);
				return;
			}

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(attach_ill)) {
				ire_marks = IRE_MARK_HIDDEN;
			}
			/*
			 * ip_wput passes the right ipif for IPIF_NOFAILOVER
			 * case.
			 */
			dst_ill = ipif->ipif_ill;
			/* attach_ill has been refheld by ip_grab_attach_ill */
			ASSERT(dst_ill == attach_ill);
		} else {
			/*
			 * If the interface belongs to an interface group,
			 * make sure the next possible interface in the group
			 * is used.  This encourages load spreading among
			 * peers in an interface group.
			 * Note: load spreading is disabled for RTF_MULTIRT
			 * routes.
			 */
			if ((flags & RTF_MULTIRT) && (fire != NULL) &&
			    (fire->ire_flags & RTF_MULTIRT)) {
				/*
				 * Don't perform outbound load spreading
				 * in the case of an RTF_MULTIRT issued route,
				 * we actually typically want to replicate
				 * outgoing packets through particular
				 * interfaces.
				 */
				dst_ill = ipif->ipif_ill;
				ill_refhold(dst_ill);
			} else {
				dst_ill = ip_newroute_get_dst_ill(
				    ipif->ipif_ill);
			}
			if (dst_ill == NULL) {
				if (ip_debug > 2) {
					pr_addr_dbg("ip_newroute_ipif: "
					    "no dst ill for dst %s\n",
					    AF_INET, &dst);
				}
				goto err_ret;
			}
		}

		/*
		 * Pick a source address preferring non-deprecated ones.
		 * Unlike ip_newroute, we don't do any source address
		 * selection here since for multicast it really does not help
		 * in inbound load spreading as in the unicast case.
		 */
		if ((flags & RTF_SETSRC) && (fire != NULL) &&
		    (fire->ire_flags & RTF_SETSRC)) {
			/*
			 * As requested by flags, an IRE_OFFSUBNET was looked up
			 * on that interface. This ire has RTF_SETSRC flag, so
			 * the source address of the packet must be changed.
			 * Check that the ipif matching the requested source
			 * address still exists.
			 */
			src_ipif = ipif_lookup_addr(fire->ire_src_addr, NULL,
			    zoneid, NULL, NULL, NULL, NULL, ipst);
		}

		unspec_src = (connp != NULL && connp->conn_unspec_src);

		if (((!ipif->ipif_isv6 && ipif->ipif_lcl_addr == INADDR_ANY) ||
		    (ipif->ipif_flags & (IPIF_DEPRECATED|IPIF_UP)) != IPIF_UP ||
		    (connp != NULL && ipif->ipif_zoneid != zoneid &&
		    ipif->ipif_zoneid != ALL_ZONES)) &&
		    (src_ipif == NULL) &&
		    (!unspec_src || ipha->ipha_src != INADDR_ANY)) {
			src_ipif = ipif_select_source(dst_ill, dst, zoneid);
			if (src_ipif == NULL) {
				if (ip_debug > 2) {
					/* ip1dbg */
					pr_addr_dbg("ip_newroute_ipif: "
					    "no src for dst %s",
					    AF_INET, &dst);
				}
				ip1dbg((" through interface %s\n",
				    dst_ill->ill_name));
				goto err_ret;
			}
			ipif_refrele(ipif);
			ipif = src_ipif;
			ipif_refhold(ipif);
		}
		if (src_ipif == NULL) {
			src_ipif = ipif;
			ipif_refhold(src_ipif);
		}

		/*
		 * Assign a source address while we have the conn.
		 * We can't have ip_wput_ire pick a source address when the
		 * packet returns from arp since conn_unspec_src might be set
		 * and we lose the conn when going through arp.
		 */
		if (ipha->ipha_src == INADDR_ANY && !unspec_src)
			ipha->ipha_src = src_ipif->ipif_src_addr;

		/*
		 * In the case of IP_BOUND_IF and IP_PKTINFO, it is possible
		 * that the outgoing interface does not have an interface ire.
		 */
		if (CLASSD(ipha_dst) && (connp == NULL ||
		    connp->conn_outgoing_ill == NULL) &&
		    infop->ip_opt_ill_index == 0) {
			/* ipif_to_ire returns an held ire */
			ire = ipif_to_ire(ipif);
			if (ire == NULL)
				goto err_ret;
			if (ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE))
				goto err_ret;
			/*
			 * ihandle is needed when the ire is added to
			 * cache table.
			 */
			save_ire = ire;
			ihandle = save_ire->ire_ihandle;

			ip2dbg(("ip_newroute_ipif: ire %p, ipif %p, "
			    "flags %04x\n",
			    (void *)ire, (void *)ipif, flags));
			if ((flags & RTF_MULTIRT) && (fire != NULL) &&
			    (fire->ire_flags & RTF_MULTIRT)) {
				/*
				 * As requested by flags, an IRE_OFFSUBNET was
				 * looked up on that interface. This ire has
				 * RTF_MULTIRT flag, so the resolution loop will
				 * be re-entered to resolve additional routes on
				 * other interfaces. For that purpose, a copy of
				 * the packet is performed at this point.
				 */
				fire->ire_last_used_time = lbolt;
				copy_mp = copymsg(first_mp);
				if (copy_mp) {
					MULTIRT_DEBUG_TAG(copy_mp);
				}
			}
			if ((flags & RTF_SETSRC) && (fire != NULL) &&
			    (fire->ire_flags & RTF_SETSRC)) {
				/*
				 * As requested by flags, an IRE_OFFSUBET was
				 * looked up on that interface. This ire has
				 * RTF_SETSRC flag, so the source address of the
				 * packet must be changed.
				 */
				ipha->ipha_src = fire->ire_src_addr;
			}
		} else {
			ASSERT((connp == NULL) ||
			    (connp->conn_outgoing_ill != NULL) ||
			    (connp->conn_dontroute) ||
			    infop->ip_opt_ill_index != 0);
			/*
			 * The only ways we can come here are:
			 * 1) IP_BOUND_IF socket option is set
			 * 2) SO_DONTROUTE socket option is set
			 * 3) IP_PKTINFO option is passed in as ancillary data.
			 * In all cases, the new ire will not be added
			 * into cache table.
			 */
			ire_marks |= IRE_MARK_NOADD;
		}

		switch (ipif->ipif_net_type) {
		case IRE_IF_NORESOLVER: {
			/* We have what we need to build an IRE_CACHE. */

			if ((dst_ill->ill_phys_addr_length != IP_ADDR_LEN) &&
			    (dst_ill->ill_resolver_mp == NULL)) {
				ip1dbg(("ip_newroute_ipif: dst_ill %p "
				    "for IRE_IF_NORESOLVER ire %p has "
				    "no ill_resolver_mp\n",
				    (void *)dst_ill, (void *)ire));
				break;
			}

			/*
			 * The new ire inherits the IRE_OFFSUBNET flags
			 * and source address, if this was requested.
			 */
			ire = ire_create(
			    (uchar_t *)&dst,		/* dest address */
			    (uchar_t *)&ip_g_all_ones,	/* mask */
			    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
			    NULL,			/* gateway address */
			    &ipif->ipif_mtu,
			    NULL,			/* no src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    (save_ire != NULL ? save_ire->ire_mask : 0),
			    (fire != NULL) ?		/* Parent handle */
			    fire->ire_phandle : 0,
			    ihandle,			/* Interface handle */
			    (fire != NULL) ?
			    (fire->ire_flags &
			    (RTF_SETSRC | RTF_MULTIRT)) : 0,
			    (save_ire == NULL ? &ire_uinfo_null :
			    &save_ire->ire_uinfo),
			    NULL,
			    NULL,
			    ipst);

			if (ire == NULL) {
				if (save_ire != NULL)
					ire_refrele(save_ire);
				break;
			}

			ire->ire_marks |= ire_marks;

			/*
			 * If IRE_MARK_NOADD is set then we need to convert
			 * the max_fragp to a useable value now. This is
			 * normally done in ire_add_v[46]. We also need to
			 * associate the ire with an nce (normally would be
			 * done in ip_wput_nondata()).
			 *
			 * Note that IRE_MARK_NOADD packets created here
			 * do not have a non-null ire_mp pointer. The null
			 * value of ire_bucket indicates that they were
			 * never added.
			 */
			if (ire->ire_marks & IRE_MARK_NOADD) {
				uint_t  max_frag;

				max_frag = *ire->ire_max_fragp;
				ire->ire_max_fragp = NULL;
				ire->ire_max_frag = max_frag;

				if ((ire->ire_nce = ndp_lookup_v4(
				    ire_to_ill(ire),
				    (ire->ire_gateway_addr != INADDR_ANY ?
				    &ire->ire_gateway_addr : &ire->ire_addr),
				    B_FALSE)) == NULL) {
					if (save_ire != NULL)
						ire_refrele(save_ire);
					break;
				}
				ASSERT(ire->ire_nce->nce_state ==
				    ND_REACHABLE);
				NCE_REFHOLD_TO_REFHOLD_NOTR(ire->ire_nce);
			}

			/* Prevent save_ire from getting deleted */
			if (save_ire != NULL) {
				IRB_REFHOLD(save_ire->ire_bucket);
				/* Has it been removed already ? */
				if (save_ire->ire_marks & IRE_MARK_CONDEMNED) {
					IRB_REFRELE(save_ire->ire_bucket);
					ire_refrele(save_ire);
					break;
				}
			}

			ire_add_then_send(q, ire, first_mp);

			/* Assert that save_ire is not deleted yet. */
			if (save_ire != NULL) {
				ASSERT(save_ire->ire_ptpn != NULL);
				IRB_REFRELE(save_ire->ire_bucket);
				ire_refrele(save_ire);
				save_ire = NULL;
			}
			if (fire != NULL) {
				ire_refrele(fire);
				fire = NULL;
			}

			/*
			 * the resolution loop is re-entered if this
			 * was requested through flags and if we
			 * actually are in a multirouting case.
			 */
			if ((flags & RTF_MULTIRT) && (copy_mp != NULL)) {
				boolean_t need_resolve =
				    ire_multirt_need_resolve(ipha_dst,
				    MBLK_GETLABEL(copy_mp), ipst);
				if (!need_resolve) {
					MULTIRT_DEBUG_UNTAG(copy_mp);
					freemsg(copy_mp);
					copy_mp = NULL;
				} else {
					/*
					 * ipif_lookup_group() calls
					 * ire_lookup_multi() that uses
					 * ire_ftable_lookup() to find
					 * an IRE_INTERFACE for the group.
					 * In the multirt case,
					 * ire_lookup_multi() then invokes
					 * ire_multirt_lookup() to find
					 * the next resolvable ire.
					 * As a result, we obtain an new
					 * interface, derived from the
					 * next ire.
					 */
					ipif_refrele(ipif);
					ipif = ipif_lookup_group(ipha_dst,
					    zoneid, ipst);
					ip2dbg(("ip_newroute_ipif: "
					    "multirt dst %08x, ipif %p\n",
					    htonl(dst), (void *)ipif));
					if (ipif != NULL) {
						mp = copy_mp;
						copy_mp = NULL;
						multirt_resolve_next = B_TRUE;
						continue;
					} else {
						freemsg(copy_mp);
					}
				}
			}
			if (ipif != NULL)
				ipif_refrele(ipif);
			ill_refrele(dst_ill);
			ipif_refrele(src_ipif);
			return;
		}
		case IRE_IF_RESOLVER:
			/*
			 * We can't build an IRE_CACHE yet, but at least
			 * we found a resolver that can help.
			 */
			res_mp = dst_ill->ill_resolver_mp;
			if (!OK_RESOLVER_MP(res_mp))
				break;

			/*
			 * We obtain a partial IRE_CACHE which we will pass
			 * along with the resolver query.  When the response
			 * comes back it will be there ready for us to add.
			 * The new ire inherits the IRE_OFFSUBNET flags
			 * and source address, if this was requested.
			 * The ire_max_frag is atomically set under the
			 * irebucket lock in ire_add_v[46]. Only in the
			 * case of IRE_MARK_NOADD, we set it here itself.
			 */
			ire = ire_create_mp(
			    (uchar_t *)&dst,		/* dest address */
			    (uchar_t *)&ip_g_all_ones,	/* mask */
			    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
			    NULL,			/* gateway address */
			    (ire_marks & IRE_MARK_NOADD) ?
			    ipif->ipif_mtu : 0,		/* max_frag */
			    NULL,			/* no src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    (save_ire != NULL ? save_ire->ire_mask : 0),
			    (fire != NULL) ?		/* Parent handle */
			    fire->ire_phandle : 0,
			    ihandle,			/* Interface handle */
			    (fire != NULL) ?		/* flags if any */
			    (fire->ire_flags &
			    (RTF_SETSRC | RTF_MULTIRT)) : 0,
			    (save_ire == NULL ? &ire_uinfo_null :
			    &save_ire->ire_uinfo),
			    NULL,
			    NULL,
			    ipst);

			if (save_ire != NULL) {
				ire_refrele(save_ire);
				save_ire = NULL;
			}
			if (ire == NULL)
				break;

			ire->ire_marks |= ire_marks;
			/*
			 * Construct message chain for the resolver of the
			 * form:
			 *	ARP_REQ_MBLK-->IRE_MBLK-->Packet
			 *
			 * NOTE : ire will be added later when the response
			 * comes back from ARP. If the response does not
			 * come back, ARP frees the packet. For this reason,
			 * we can't REFHOLD the bucket of save_ire to prevent
			 * deletions. We may not be able to REFRELE the
			 * bucket if the response never comes back.
			 * Thus, before adding the ire, ire_add_v4 will make
			 * sure that the interface route does not get deleted.
			 * This is the only case unlike ip_newroute_v6,
			 * ip_newroute_ipif_v6 where we can always prevent
			 * deletions because ire_add_then_send is called after
			 * creating the IRE.
			 * If IRE_MARK_NOADD is set, then ire_add_then_send
			 * does not add this IRE into the IRE CACHE.
			 */
			ASSERT(ire->ire_mp != NULL);
			ire->ire_mp->b_cont = first_mp;
			/* Have saved_mp handy, for cleanup if canput fails */
			saved_mp = mp;
			mp = copyb(res_mp);
			if (mp == NULL) {
				/* Prepare for cleanup */
				mp = saved_mp; /* pkt */
				ire_delete(ire); /* ire_mp */
				ire = NULL;
				if (copy_mp != NULL) {
					MULTIRT_DEBUG_UNTAG(copy_mp);
					freemsg(copy_mp);
					copy_mp = NULL;
				}
				break;
			}
			linkb(mp, ire->ire_mp);

			/*
			 * Fill in the source and dest addrs for the resolver.
			 * NOTE: this depends on memory layouts imposed by
			 * ill_init().
			 */
			areq = (areq_t *)mp->b_rptr;
			addrp = (ipaddr_t *)((char *)areq +
			    areq->areq_sender_addr_offset);
			*addrp = ire->ire_src_addr;
			addrp = (ipaddr_t *)((char *)areq +
			    areq->areq_target_addr_offset);
			*addrp = dst;
			/* Up to the resolver. */
			if (canputnext(dst_ill->ill_rq) &&
			    !(dst_ill->ill_arp_closing)) {
				putnext(dst_ill->ill_rq, mp);
				/*
				 * The response will come back in ip_wput
				 * with db_type IRE_DB_TYPE.
				 */
			} else {
				mp->b_cont = NULL;
				freeb(mp); /* areq */
				ire_delete(ire); /* ire_mp */
				saved_mp->b_next = NULL;
				saved_mp->b_prev = NULL;
				freemsg(first_mp); /* pkt */
				ip2dbg(("ip_newroute_ipif: dropped\n"));
			}

			if (fire != NULL) {
				ire_refrele(fire);
				fire = NULL;
			}


			/*
			 * The resolution loop is re-entered if this was
			 * requested through flags and we actually are
			 * in a multirouting case.
			 */
			if ((flags & RTF_MULTIRT) && (copy_mp != NULL)) {
				boolean_t need_resolve =
				    ire_multirt_need_resolve(ipha_dst,
				    MBLK_GETLABEL(copy_mp), ipst);
				if (!need_resolve) {
					MULTIRT_DEBUG_UNTAG(copy_mp);
					freemsg(copy_mp);
					copy_mp = NULL;
				} else {
					/*
					 * ipif_lookup_group() calls
					 * ire_lookup_multi() that uses
					 * ire_ftable_lookup() to find
					 * an IRE_INTERFACE for the group.
					 * In the multirt case,
					 * ire_lookup_multi() then invokes
					 * ire_multirt_lookup() to find
					 * the next resolvable ire.
					 * As a result, we obtain an new
					 * interface, derived from the
					 * next ire.
					 */
					ipif_refrele(ipif);
					ipif = ipif_lookup_group(ipha_dst,
					    zoneid, ipst);
					if (ipif != NULL) {
						mp = copy_mp;
						copy_mp = NULL;
						multirt_resolve_next = B_TRUE;
						continue;
					} else {
						freemsg(copy_mp);
					}
				}
			}
			if (ipif != NULL)
				ipif_refrele(ipif);
			ill_refrele(dst_ill);
			ipif_refrele(src_ipif);
			return;
		default:
			break;
		}
	} while (multirt_resolve_next);

err_ret:
	ip2dbg(("ip_newroute_ipif: dropped\n"));
	if (fire != NULL)
		ire_refrele(fire);
	ipif_refrele(ipif);
	/* Did this packet originate externally? */
	if (dst_ill != NULL)
		ill_refrele(dst_ill);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (mp->b_prev || mp->b_next) {
		mp->b_next = NULL;
		mp->b_prev = NULL;
	} else {
		/*
		 * Since ip_wput() isn't close to finished, we fill
		 * in enough of the header for credible error reporting.
		 */
		if (ip_hdr_complete((ipha_t *)mp->b_rptr, zoneid, ipst)) {
			/* Failed */
			freemsg(first_mp);
			if (ire != NULL)
				ire_refrele(ire);
			return;
		}
	}
	/*
	 * At this point we will have ire only if RTF_BLACKHOLE
	 * or RTF_REJECT flags are set on the IRE. It will not
	 * generate ICMP_HOST_UNREACHABLE if RTF_BLACKHOLE is set.
	 */
	if (ire != NULL) {
		if (ire->ire_flags & RTF_BLACKHOLE) {
			ire_refrele(ire);
			freemsg(first_mp);
			return;
		}
		ire_refrele(ire);
	}
	icmp_unreachable(q, first_mp, ICMP_HOST_UNREACHABLE, zoneid, ipst);
}

/* Name/Value Table Lookup Routine */
char *
ip_nv_lookup(nv_t *nv, int value)
{
	if (!nv)
		return (NULL);
	for (; nv->nv_name; nv++) {
		if (nv->nv_value == value)
			return (nv->nv_name);
	}
	return ("unknown");
}

/*
 * This is a module open, i.e. this is a control stream for access
 * to a DLPI device.  We allocate an ill_t as the instance data in
 * this case.
 */
int
ip_modopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	ill_t	*ill;
	int	err;
	zoneid_t zoneid;
	netstack_t *ns;
	ip_stack_t *ipst;

	/*
	 * Prevent unprivileged processes from pushing IP so that
	 * they can't send raw IP.
	 */
	if (secpolicy_net_rawaccess(credp) != 0)
		return (EPERM);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	ipst = ns->netstack_ip;
	ASSERT(ipst != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make IP operate as if in the global zone.
	 */
	if (ipst->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = crgetzoneid(credp);

	ill = (ill_t *)mi_open_alloc_sleep(sizeof (ill_t));
	q->q_ptr = WR(q)->q_ptr = ill;
	ill->ill_ipst = ipst;
	ill->ill_zoneid = zoneid;

	/*
	 * ill_init initializes the ill fields and then sends down
	 * down a DL_INFO_REQ after calling qprocson.
	 */
	err = ill_init(q, ill);
	if (err != 0) {
		mi_free(ill);
		netstack_rele(ipst->ips_netstack);
		q->q_ptr = NULL;
		WR(q)->q_ptr = NULL;
		return (err);
	}

	/* ill_init initializes the ipsq marking this thread as writer */
	ipsq_exit(ill->ill_phyint->phyint_ipsq);
	/* Wait for the DL_INFO_ACK */
	mutex_enter(&ill->ill_lock);
	while (ill->ill_state_flags & ILL_LL_SUBNET_PENDING) {
		/*
		 * Return value of 0 indicates a pending signal.
		 */
		err = cv_wait_sig(&ill->ill_cv, &ill->ill_lock);
		if (err == 0) {
			mutex_exit(&ill->ill_lock);
			(void) ip_close(q, 0);
			return (EINTR);
		}
	}
	mutex_exit(&ill->ill_lock);

	/*
	 * ip_rput_other could have set an error  in ill_error on
	 * receipt of M_ERROR.
	 */

	err = ill->ill_error;
	if (err != 0) {
		(void) ip_close(q, 0);
		return (err);
	}

	ill->ill_credp = credp;
	crhold(credp);

	mutex_enter(&ipst->ips_ip_mi_lock);
	err = mi_open_link(&ipst->ips_ip_g_head, (IDP)ill, devp, flag, sflag,
	    credp);
	mutex_exit(&ipst->ips_ip_mi_lock);
	if (err) {
		(void) ip_close(q, 0);
		return (err);
	}
	return (0);
}

/* For /dev/ip aka AF_INET open */
int
ip_openv4(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (ip_open(q, devp, flag, sflag, credp, B_FALSE));
}

/* For /dev/ip6 aka AF_INET6 open */
int
ip_openv6(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (ip_open(q, devp, flag, sflag, credp, B_TRUE));
}

/* IP open routine. */
int
ip_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp,
    boolean_t isv6)
{
	conn_t 		*connp;
	major_t		maj;
	zoneid_t	zoneid;
	netstack_t	*ns;
	ip_stack_t	*ipst;

	TRACE_1(TR_FAC_IP, TR_IP_OPEN, "ip_open: q %p", q);

	/* Allow reopen. */
	if (q->q_ptr != NULL)
		return (0);

	if (sflag & MODOPEN) {
		/* This is a module open */
		return (ip_modopen(q, devp, flag, sflag, credp));
	}

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	ipst = ns->netstack_ip;
	ASSERT(ipst != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make IP operate as if in the global zone.
	 */
	if (ipst->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = crgetzoneid(credp);

	/*
	 * We are opening as a device. This is an IP client stream, and we
	 * allocate an conn_t as the instance data.
	 */
	connp = ipcl_conn_create(IPCL_IPCCONN, KM_SLEEP, ipst->ips_netstack);

	/*
	 * ipcl_conn_create did a netstack_hold. Undo the hold that was
	 * done by netstack_find_by_cred()
	 */
	netstack_rele(ipst->ips_netstack);

	connp->conn_zoneid = zoneid;
	connp->conn_sqp = NULL;
	connp->conn_initial_sqp = NULL;
	connp->conn_final_sqp = NULL;

	connp->conn_upq = q;
	q->q_ptr = WR(q)->q_ptr = connp;

	if (flag & SO_SOCKSTR)
		connp->conn_flags |= IPCL_SOCKET;

	/* Minor tells us which /dev entry was opened */
	if (isv6) {
		connp->conn_flags |= IPCL_ISV6;
		connp->conn_af_isv6 = B_TRUE;
		ip_setpktversion(connp, isv6, B_FALSE, ipst);
		connp->conn_src_preferences = IPV6_PREFER_SRC_DEFAULT;
	} else {
		connp->conn_af_isv6 = B_FALSE;
		connp->conn_pkt_isv6 = B_FALSE;
	}

	if ((ip_minor_arena_la != NULL) && (flag & SO_SOCKSTR) &&
	    ((connp->conn_dev = inet_minor_alloc(ip_minor_arena_la)) != 0)) {
		connp->conn_minor_arena = ip_minor_arena_la;
	} else {
		/*
		 * Either minor numbers in the large arena were exhausted
		 * or a non socket application is doing the open.
		 * Try to allocate from the small arena.
		 */
		if ((connp->conn_dev =
		    inet_minor_alloc(ip_minor_arena_sa)) == 0) {
			/* CONN_DEC_REF takes care of netstack_rele() */
			q->q_ptr = WR(q)->q_ptr = NULL;
			CONN_DEC_REF(connp);
			return (EBUSY);
		}
		connp->conn_minor_arena = ip_minor_arena_sa;
	}

	maj = getemajor(*devp);
	*devp = makedevice(maj, (minor_t)connp->conn_dev);

	/*
	 * connp->conn_cred is crfree()ed in ipcl_conn_destroy()
	 */
	connp->conn_cred = credp;

	/*
	 * Handle IP_RTS_REQUEST and other ioctls which use conn_recv
	 */
	connp->conn_recv = ip_conn_input;

	crhold(connp->conn_cred);

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		connp->conn_mac_exempt = B_TRUE;

	connp->conn_rq = q;
	connp->conn_wq = WR(q);

	/* Non-zero default values */
	connp->conn_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;

	/*
	 * Make the conn globally visible to walkers
	 */
	ASSERT(connp->conn_ref == 1);
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);

	qprocson(q);

	return (0);
}

/*
 * Change the output format (IPv4 vs. IPv6) for a conn_t.
 * Note that there is no race since either ip_output function works - it
 * is just an optimization to enter the best ip_output routine directly.
 */
void
ip_setpktversion(conn_t *connp, boolean_t isv6, boolean_t bump_mib,
    ip_stack_t *ipst)
{
	if (isv6)  {
		if (bump_mib) {
			BUMP_MIB(&ipst->ips_ip6_mib,
			    ipIfStatsOutSwitchIPVersion);
		}
		connp->conn_send = ip_output_v6;
		connp->conn_pkt_isv6 = B_TRUE;
	} else {
		if (bump_mib) {
			BUMP_MIB(&ipst->ips_ip_mib,
			    ipIfStatsOutSwitchIPVersion);
		}
		connp->conn_send = ip_output;
		connp->conn_pkt_isv6 = B_FALSE;
	}

}

/*
 * See if IPsec needs loading because of the options in mp.
 */
static boolean_t
ipsec_opt_present(mblk_t *mp)
{
	uint8_t *optcp, *next_optcp, *opt_endcp;
	struct opthdr *opt;
	struct T_opthdr *topt;
	int opthdr_len;
	t_uscalar_t optname, optlevel;
	struct T_optmgmt_req *tor = (struct T_optmgmt_req *)mp->b_rptr;
	ipsec_req_t *ipsr;

	/*
	 * Walk through the mess, and find IP_SEC_OPT.  If it's there,
	 * return TRUE.
	 */

	optcp = mi_offset_param(mp, tor->OPT_offset, tor->OPT_length);
	opt_endcp = optcp + tor->OPT_length;
	if (tor->PRIM_type == T_OPTMGMT_REQ) {
		opthdr_len = sizeof (struct T_opthdr);
	} else {		/* O_OPTMGMT_REQ */
		ASSERT(tor->PRIM_type == T_SVR4_OPTMGMT_REQ);
		opthdr_len = sizeof (struct opthdr);
	}
	for (; optcp < opt_endcp; optcp = next_optcp) {
		if (optcp + opthdr_len > opt_endcp)
			return (B_FALSE);	/* Not enough option header. */
		if (tor->PRIM_type == T_OPTMGMT_REQ) {
			topt = (struct T_opthdr *)optcp;
			optlevel = topt->level;
			optname = topt->name;
			next_optcp = optcp + _TPI_ALIGN_TOPT(topt->len);
		} else {
			opt = (struct opthdr *)optcp;
			optlevel = opt->level;
			optname = opt->name;
			next_optcp = optcp + opthdr_len +
			    _TPI_ALIGN_OPT(opt->len);
		}
		if ((next_optcp < optcp) || /* wraparound pointer space */
		    ((next_optcp >= opt_endcp) && /* last option bad len */
		    ((next_optcp - opt_endcp) >= __TPI_ALIGN_SIZE)))
			return (B_FALSE); /* bad option buffer */
		if ((optlevel == IPPROTO_IP && optname == IP_SEC_OPT) ||
		    (optlevel == IPPROTO_IPV6 && optname == IPV6_SEC_OPT)) {
			/*
			 * Check to see if it's an all-bypass or all-zeroes
			 * IPsec request.  Don't bother loading IPsec if
			 * the socket doesn't want to use it.  (A good example
			 * is a bypass request.)
			 *
			 * Basically, if any of the non-NEVER bits are set,
			 * load IPsec.
			 */
			ipsr = (ipsec_req_t *)(optcp + opthdr_len);
			if ((ipsr->ipsr_ah_req & ~IPSEC_PREF_NEVER) != 0 ||
			    (ipsr->ipsr_esp_req & ~IPSEC_PREF_NEVER) != 0 ||
			    (ipsr->ipsr_self_encap_req & ~IPSEC_PREF_NEVER)
			    != 0)
				return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * If conn is is waiting for ipsec to finish loading, kick it.
 */
/* ARGSUSED */
static void
conn_restart_ipsec_waiter(conn_t *connp, void *arg)
{
	t_scalar_t	optreq_prim;
	mblk_t		*mp;
	cred_t		*cr;
	int		err = 0;

	/*
	 * This function is called, after ipsec loading is complete.
	 * Since IP checks exclusively and atomically (i.e it prevents
	 * ipsec load from completing until ip_optcom_req completes)
	 * whether ipsec load is complete, there cannot be a race with IP
	 * trying to set the CONN_IPSEC_LOAD_WAIT flag on any conn now.
	 */
	mutex_enter(&connp->conn_lock);
	if (connp->conn_state_flags & CONN_IPSEC_LOAD_WAIT) {
		ASSERT(connp->conn_ipsec_opt_mp != NULL);
		mp = connp->conn_ipsec_opt_mp;
		connp->conn_ipsec_opt_mp = NULL;
		connp->conn_state_flags  &= ~CONN_IPSEC_LOAD_WAIT;
		cr = DB_CREDDEF(mp, GET_QUEUE_CRED(CONNP_TO_WQ(connp)));
		mutex_exit(&connp->conn_lock);

		ASSERT(DB_TYPE(mp) == M_PROTO || DB_TYPE(mp) == M_PCPROTO);

		optreq_prim = ((union T_primitives *)mp->b_rptr)->type;
		if (optreq_prim == T_OPTMGMT_REQ) {
			err = tpi_optcom_req(CONNP_TO_WQ(connp), mp, cr,
			    &ip_opt_obj, B_FALSE);
		} else {
			ASSERT(optreq_prim == T_SVR4_OPTMGMT_REQ);
			err = svr4_optcom_req(CONNP_TO_WQ(connp), mp, cr,
			    &ip_opt_obj, B_FALSE);
		}
		if (err != EINPROGRESS)
			CONN_OPER_PENDING_DONE(connp);
		return;
	}
	mutex_exit(&connp->conn_lock);
}

/*
 * Called from the ipsec_loader thread, outside any perimeter, to tell
 * ip qenable any of the queues waiting for the ipsec loader to
 * complete.
 */
void
ip_ipsec_load_complete(ipsec_stack_t *ipss)
{
	netstack_t *ns = ipss->ipsec_netstack;

	ipcl_walk(conn_restart_ipsec_waiter, NULL, ns->netstack_ip);
}

/*
 * Can't be used. Need to call svr4* -> optset directly. the leaf routine
 * determines the grp on which it has to become exclusive, queues the mp
 * and sq draining restarts the optmgmt
 */
static boolean_t
ip_check_for_ipsec_opt(queue_t *q, mblk_t *mp)
{
	conn_t *connp = Q_TO_CONN(q);
	ipsec_stack_t *ipss = connp->conn_netstack->netstack_ipsec;

	/*
	 * Take IPsec requests and treat them special.
	 */
	if (ipsec_opt_present(mp)) {
		/* First check if IPsec is loaded. */
		mutex_enter(&ipss->ipsec_loader_lock);
		if (ipss->ipsec_loader_state != IPSEC_LOADER_WAIT) {
			mutex_exit(&ipss->ipsec_loader_lock);
			return (B_FALSE);
		}
		mutex_enter(&connp->conn_lock);
		connp->conn_state_flags |= CONN_IPSEC_LOAD_WAIT;

		ASSERT(connp->conn_ipsec_opt_mp == NULL);
		connp->conn_ipsec_opt_mp = mp;
		mutex_exit(&connp->conn_lock);
		mutex_exit(&ipss->ipsec_loader_lock);

		ipsec_loader_loadnow(ipss);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Set IPsec policy from an ipsec_req_t. If the req is not "zero" and valid,
 * all of them are copied to the conn_t. If the req is "zero", the policy is
 * zeroed out. A "zero" policy has zero ipsr_{ah,req,self_encap}_req
 * fields.
 * We keep only the latest setting of the policy and thus policy setting
 * is not incremental/cumulative.
 *
 * Requests to set policies with multiple alternative actions will
 * go through a different API.
 */
int
ipsec_set_req(cred_t *cr, conn_t *connp, ipsec_req_t *req)
{
	uint_t ah_req = 0;
	uint_t esp_req = 0;
	uint_t se_req = 0;
	ipsec_selkey_t sel;
	ipsec_act_t *actp = NULL;
	uint_t nact;
	ipsec_policy_t *pin4 = NULL, *pout4 = NULL;
	ipsec_policy_t *pin6 = NULL, *pout6 = NULL;
	ipsec_policy_root_t *pr;
	ipsec_policy_head_t *ph;
	int fam;
	boolean_t is_pol_reset;
	int error = 0;
	netstack_t	*ns = connp->conn_netstack;
	ip_stack_t	*ipst = ns->netstack_ip;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

#define	REQ_MASK (IPSEC_PREF_REQUIRED|IPSEC_PREF_NEVER)

	/*
	 * The IP_SEC_OPT option does not allow variable length parameters,
	 * hence a request cannot be NULL.
	 */
	if (req == NULL)
		return (EINVAL);

	ah_req = req->ipsr_ah_req;
	esp_req = req->ipsr_esp_req;
	se_req = req->ipsr_self_encap_req;

	/* Don't allow setting self-encap without one or more of AH/ESP. */
	if (se_req != 0 && esp_req == 0 && ah_req == 0)
		return (EINVAL);

	/*
	 * Are we dealing with a request to reset the policy (i.e.
	 * zero requests).
	 */
	is_pol_reset = ((ah_req & REQ_MASK) == 0 &&
	    (esp_req & REQ_MASK) == 0 &&
	    (se_req & REQ_MASK) == 0);

	if (!is_pol_reset) {
		/*
		 * If we couldn't load IPsec, fail with "protocol
		 * not supported".
		 * IPsec may not have been loaded for a request with zero
		 * policies, so we don't fail in this case.
		 */
		mutex_enter(&ipss->ipsec_loader_lock);
		if (ipss->ipsec_loader_state != IPSEC_LOADER_SUCCEEDED) {
			mutex_exit(&ipss->ipsec_loader_lock);
			return (EPROTONOSUPPORT);
		}
		mutex_exit(&ipss->ipsec_loader_lock);

		/*
		 * Test for valid requests. Invalid algorithms
		 * need to be tested by IPsec code because new
		 * algorithms can be added dynamically.
		 */
		if ((ah_req & ~(REQ_MASK|IPSEC_PREF_UNIQUE)) != 0 ||
		    (esp_req & ~(REQ_MASK|IPSEC_PREF_UNIQUE)) != 0 ||
		    (se_req & ~(REQ_MASK|IPSEC_PREF_UNIQUE)) != 0) {
			return (EINVAL);
		}

		/*
		 * Only privileged users can issue these
		 * requests.
		 */
		if (((ah_req & IPSEC_PREF_NEVER) ||
		    (esp_req & IPSEC_PREF_NEVER) ||
		    (se_req & IPSEC_PREF_NEVER)) &&
		    secpolicy_ip_config(cr, B_FALSE) != 0) {
			return (EPERM);
		}

		/*
		 * The IPSEC_PREF_REQUIRED and IPSEC_PREF_NEVER
		 * are mutually exclusive.
		 */
		if (((ah_req & REQ_MASK) == REQ_MASK) ||
		    ((esp_req & REQ_MASK) == REQ_MASK) ||
		    ((se_req & REQ_MASK) == REQ_MASK)) {
			/* Both of them are set */
			return (EINVAL);
		}
	}

	mutex_enter(&connp->conn_lock);

	/*
	 * If we have already cached policies in ip_bind_connected*(), don't
	 * let them change now. We cache policies for connections
	 * whose src,dst [addr, port] is known.
	 */
	if (connp->conn_policy_cached) {
		mutex_exit(&connp->conn_lock);
		return (EINVAL);
	}

	/*
	 * We have a zero policies, reset the connection policy if already
	 * set. This will cause the connection to inherit the
	 * global policy, if any.
	 */
	if (is_pol_reset) {
		if (connp->conn_policy != NULL) {
			IPPH_REFRELE(connp->conn_policy, ipst->ips_netstack);
			connp->conn_policy = NULL;
		}
		connp->conn_flags &= ~IPCL_CHECK_POLICY;
		connp->conn_in_enforce_policy = B_FALSE;
		connp->conn_out_enforce_policy = B_FALSE;
		mutex_exit(&connp->conn_lock);
		return (0);
	}

	ph = connp->conn_policy = ipsec_polhead_split(connp->conn_policy,
	    ipst->ips_netstack);
	if (ph == NULL)
		goto enomem;

	ipsec_actvec_from_req(req, &actp, &nact, ipst->ips_netstack);
	if (actp == NULL)
		goto enomem;

	/*
	 * Always allocate IPv4 policy entries, since they can also
	 * apply to ipv6 sockets being used in ipv4-compat mode.
	 */
	bzero(&sel, sizeof (sel));
	sel.ipsl_valid = IPSL_IPV4;

	pin4 = ipsec_policy_create(&sel, actp, nact, IPSEC_PRIO_SOCKET, NULL,
	    ipst->ips_netstack);
	if (pin4 == NULL)
		goto enomem;

	pout4 = ipsec_policy_create(&sel, actp, nact, IPSEC_PRIO_SOCKET, NULL,
	    ipst->ips_netstack);
	if (pout4 == NULL)
		goto enomem;

	if (connp->conn_af_isv6) {
		/*
		 * We're looking at a v6 socket, also allocate the
		 * v6-specific entries...
		 */
		sel.ipsl_valid = IPSL_IPV6;
		pin6 = ipsec_policy_create(&sel, actp, nact,
		    IPSEC_PRIO_SOCKET, NULL, ipst->ips_netstack);
		if (pin6 == NULL)
			goto enomem;

		pout6 = ipsec_policy_create(&sel, actp, nact,
		    IPSEC_PRIO_SOCKET, NULL, ipst->ips_netstack);
		if (pout6 == NULL)
			goto enomem;

		/*
		 * .. and file them away in the right place.
		 */
		fam = IPSEC_AF_V6;
		pr = &ph->iph_root[IPSEC_TYPE_INBOUND];
		HASHLIST_INSERT(pin6, ipsp_hash, pr->ipr_nonhash[fam]);
		ipsec_insert_always(&ph->iph_rulebyid, pin6);
		pr = &ph->iph_root[IPSEC_TYPE_OUTBOUND];
		HASHLIST_INSERT(pout6, ipsp_hash, pr->ipr_nonhash[fam]);
		ipsec_insert_always(&ph->iph_rulebyid, pout6);
	}

	ipsec_actvec_free(actp, nact);

	/*
	 * File the v4 policies.
	 */
	fam = IPSEC_AF_V4;
	pr = &ph->iph_root[IPSEC_TYPE_INBOUND];
	HASHLIST_INSERT(pin4, ipsp_hash, pr->ipr_nonhash[fam]);
	ipsec_insert_always(&ph->iph_rulebyid, pin4);

	pr = &ph->iph_root[IPSEC_TYPE_OUTBOUND];
	HASHLIST_INSERT(pout4, ipsp_hash, pr->ipr_nonhash[fam]);
	ipsec_insert_always(&ph->iph_rulebyid, pout4);

	/*
	 * If the requests need security, set enforce_policy.
	 * If the requests are IPSEC_PREF_NEVER, one should
	 * still set conn_out_enforce_policy so that an ipsec_out
	 * gets attached in ip_wput. This is needed so that
	 * for connections that we don't cache policy in ip_bind,
	 * if global policy matches in ip_wput_attach_policy, we
	 * don't wrongly inherit global policy. Similarly, we need
	 * to set conn_in_enforce_policy also so that we don't verify
	 * policy wrongly.
	 */
	if ((ah_req & REQ_MASK) != 0 ||
	    (esp_req & REQ_MASK) != 0 ||
	    (se_req & REQ_MASK) != 0) {
		connp->conn_in_enforce_policy = B_TRUE;
		connp->conn_out_enforce_policy = B_TRUE;
		connp->conn_flags |= IPCL_CHECK_POLICY;
	}

	mutex_exit(&connp->conn_lock);
	return (error);
#undef REQ_MASK

	/*
	 * Common memory-allocation-failure exit path.
	 */
enomem:
	mutex_exit(&connp->conn_lock);
	if (actp != NULL)
		ipsec_actvec_free(actp, nact);
	if (pin4 != NULL)
		IPPOL_REFRELE(pin4, ipst->ips_netstack);
	if (pout4 != NULL)
		IPPOL_REFRELE(pout4, ipst->ips_netstack);
	if (pin6 != NULL)
		IPPOL_REFRELE(pin6, ipst->ips_netstack);
	if (pout6 != NULL)
		IPPOL_REFRELE(pout6, ipst->ips_netstack);
	return (ENOMEM);
}

/*
 * Only for options that pass in an IP addr. Currently only V4 options
 * pass in an ipif. V6 options always pass an ifindex specifying the ill.
 * So this function assumes level is IPPROTO_IP
 */
int
ip_opt_set_ipif(conn_t *connp, ipaddr_t addr, boolean_t checkonly, int option,
    mblk_t *first_mp)
{
	ipif_t *ipif = NULL;
	int error;
	ill_t *ill;
	int zoneid;
	ip_stack_t *ipst = connp->conn_netstack->netstack_ip;

	ip2dbg(("ip_opt_set_ipif: ipaddr %X\n", addr));

	if (addr != INADDR_ANY || checkonly) {
		ASSERT(connp != NULL);
		zoneid = IPCL_ZONEID(connp);
		if (option == IP_NEXTHOP) {
			ipif = ipif_lookup_onlink_addr(addr,
			    connp->conn_zoneid, ipst);
		} else {
			ipif = ipif_lookup_addr(addr, NULL, zoneid,
			    CONNP_TO_WQ(connp), first_mp, ip_restart_optmgmt,
			    &error, ipst);
		}
		if (ipif == NULL) {
			if (error == EINPROGRESS)
				return (error);
			else if ((option == IP_MULTICAST_IF) ||
			    (option == IP_NEXTHOP))
				return (EHOSTUNREACH);
			else
				return (EINVAL);
		} else if (checkonly) {
			if (option == IP_MULTICAST_IF) {
				ill = ipif->ipif_ill;
				/* not supported by the virtual network iface */
				if (IS_VNI(ill)) {
					ipif_refrele(ipif);
					return (EINVAL);
				}
			}
			ipif_refrele(ipif);
			return (0);
		}
		ill = ipif->ipif_ill;
		mutex_enter(&connp->conn_lock);
		mutex_enter(&ill->ill_lock);
		if ((ill->ill_state_flags & ILL_CONDEMNED) ||
		    (ipif->ipif_state_flags & IPIF_CONDEMNED)) {
			mutex_exit(&ill->ill_lock);
			mutex_exit(&connp->conn_lock);
			ipif_refrele(ipif);
			return (option == IP_MULTICAST_IF ?
			    EHOSTUNREACH : EINVAL);
		}
	} else {
		mutex_enter(&connp->conn_lock);
	}

	/* None of the options below are supported on the VNI */
	if (ipif != NULL && IS_VNI(ipif->ipif_ill)) {
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		ipif_refrele(ipif);
		return (EINVAL);
	}

	switch (option) {
	case IP_DONTFAILOVER_IF:
		/*
		 * This option is used by in.mpathd to ensure
		 * that IPMP probe packets only go out on the
		 * test interfaces. in.mpathd sets this option
		 * on the non-failover interfaces.
		 * For backward compatibility, this option
		 * implicitly sets IP_MULTICAST_IF, as used
		 * be done in bind(), so that ip_wput gets
		 * this ipif to send mcast packets.
		 */
		if (ipif != NULL) {
			ASSERT(addr != INADDR_ANY);
			connp->conn_nofailover_ill = ipif->ipif_ill;
			connp->conn_multicast_ipif = ipif;
		} else {
			ASSERT(addr == INADDR_ANY);
			connp->conn_nofailover_ill = NULL;
			connp->conn_multicast_ipif = NULL;
		}
		break;

	case IP_MULTICAST_IF:
		connp->conn_multicast_ipif = ipif;
		break;
	case IP_NEXTHOP:
		connp->conn_nexthop_v4 = addr;
		connp->conn_nexthop_set = B_TRUE;
		break;
	}

	if (ipif != NULL) {
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		ipif_refrele(ipif);
		return (0);
	}
	mutex_exit(&connp->conn_lock);
	/* We succeded in cleared the option */
	return (0);
}

/*
 * For options that pass in an ifindex specifying the ill. V6 options always
 * pass in an ill. Some v4 options also pass in ifindex specifying the ill.
 */
int
ip_opt_set_ill(conn_t *connp, int ifindex, boolean_t isv6, boolean_t checkonly,
    int level, int option, mblk_t *first_mp)
{
	ill_t *ill = NULL;
	int error = 0;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	ip2dbg(("ip_opt_set_ill: ifindex %d\n", ifindex));
	if (ifindex != 0) {
		ASSERT(connp != NULL);
		ill = ill_lookup_on_ifindex(ifindex, isv6, CONNP_TO_WQ(connp),
		    first_mp, ip_restart_optmgmt, &error, ipst);
		if (ill != NULL) {
			if (checkonly) {
				/* not supported by the virtual network iface */
				if (IS_VNI(ill)) {
					ill_refrele(ill);
					return (EINVAL);
				}
				ill_refrele(ill);
				return (0);
			}
			if (!ipif_lookup_zoneid_group(ill, connp->conn_zoneid,
			    0, NULL)) {
				ill_refrele(ill);
				ill = NULL;
				mutex_enter(&connp->conn_lock);
				goto setit;
			}
			mutex_enter(&connp->conn_lock);
			mutex_enter(&ill->ill_lock);
			if (ill->ill_state_flags & ILL_CONDEMNED) {
				mutex_exit(&ill->ill_lock);
				mutex_exit(&connp->conn_lock);
				ill_refrele(ill);
				ill = NULL;
				mutex_enter(&connp->conn_lock);
			}
			goto setit;
		} else if (error == EINPROGRESS) {
			return (error);
		} else {
			error = 0;
		}
	}
	mutex_enter(&connp->conn_lock);
setit:
	ASSERT((level == IPPROTO_IP || level == IPPROTO_IPV6));

	/*
	 * The options below assume that the ILL (if any) transmits and/or
	 * receives traffic. Neither of which is true for the virtual network
	 * interface, so fail setting these on a VNI.
	 */
	if (IS_VNI(ill)) {
		ASSERT(ill != NULL);
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		ill_refrele(ill);
		return (EINVAL);
	}

	if (level == IPPROTO_IP) {
		switch (option) {
		case IP_BOUND_IF:
			connp->conn_incoming_ill = ill;
			connp->conn_outgoing_ill = ill;
			connp->conn_orig_bound_ifindex = (ill == NULL) ?
			    0 : ifindex;
			break;

		case IP_MULTICAST_IF:
			/*
			 * This option is an internal special. The socket
			 * level IP_MULTICAST_IF specifies an 'ipaddr' and
			 * is handled in ip_opt_set_ipif. IPV6_MULTICAST_IF
			 * specifies an ifindex and we try first on V6 ill's.
			 * If we don't find one, we they try using on v4 ill's
			 * intenally and we come here.
			 */
			if (!checkonly && ill != NULL) {
				ipif_t	*ipif;
				ipif = ill->ill_ipif;

				if (ipif->ipif_state_flags & IPIF_CONDEMNED) {
					mutex_exit(&ill->ill_lock);
					mutex_exit(&connp->conn_lock);
					ill_refrele(ill);
					ill = NULL;
					mutex_enter(&connp->conn_lock);
				} else {
					connp->conn_multicast_ipif = ipif;
				}
			}
			break;

		case IP_DHCPINIT_IF:
			if (connp->conn_dhcpinit_ill != NULL) {
				/*
				 * We've locked the conn so conn_cleanup_ill()
				 * cannot clear conn_dhcpinit_ill -- so it's
				 * safe to access the ill.
				 */
				ill_t *oill = connp->conn_dhcpinit_ill;

				ASSERT(oill->ill_dhcpinit != 0);
				atomic_dec_32(&oill->ill_dhcpinit);
				connp->conn_dhcpinit_ill = NULL;
			}

			if (ill != NULL) {
				connp->conn_dhcpinit_ill = ill;
				atomic_inc_32(&ill->ill_dhcpinit);
			}
			break;
		}
	} else {
		switch (option) {
		case IPV6_BOUND_IF:
			connp->conn_incoming_ill = ill;
			connp->conn_outgoing_ill = ill;
			connp->conn_orig_bound_ifindex = (ill == NULL) ?
			    0 : ifindex;
			break;

		case IPV6_BOUND_PIF:
			/*
			 * Limit all transmit to this ill.
			 * Unlike IPV6_BOUND_IF, using this option
			 * prevents load spreading and failover from
			 * happening when the interface is part of the
			 * group. That's why we don't need to remember
			 * the ifindex in orig_bound_ifindex as in
			 * IPV6_BOUND_IF.
			 */
			connp->conn_outgoing_pill = ill;
			break;

		case IPV6_DONTFAILOVER_IF:
			/*
			 * This option is used by in.mpathd to ensure
			 * that IPMP probe packets only go out on the
			 * test interfaces. in.mpathd sets this option
			 * on the non-failover interfaces.
			 */
			connp->conn_nofailover_ill = ill;
			/*
			 * For backward compatibility, this option
			 * implicitly sets ip_multicast_ill as used in
			 * IPV6_MULTICAST_IF so that ip_wput gets
			 * this ill to send mcast packets.
			 */
			connp->conn_multicast_ill = ill;
			connp->conn_orig_multicast_ifindex = (ill == NULL) ?
			    0 : ifindex;
			break;

		case IPV6_MULTICAST_IF:
			/*
			 * Set conn_multicast_ill to be the IPv6 ill.
			 * Set conn_multicast_ipif to be an IPv4 ipif
			 * for ifindex to make IPv4 mapped addresses
			 * on PF_INET6 sockets honor IPV6_MULTICAST_IF.
			 * Even if no IPv6 ill exists for the ifindex
			 * we need to check for an IPv4 ifindex in order
			 * for this to work with mapped addresses. In that
			 * case only set conn_multicast_ipif.
			 */
			if (!checkonly) {
				if (ifindex == 0) {
					connp->conn_multicast_ill = NULL;
					connp->conn_orig_multicast_ifindex = 0;
					connp->conn_multicast_ipif = NULL;
				} else if (ill != NULL) {
					connp->conn_multicast_ill = ill;
					connp->conn_orig_multicast_ifindex =
					    ifindex;
				}
			}
			break;
		}
	}

	if (ill != NULL) {
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		ill_refrele(ill);
		return (0);
	}
	mutex_exit(&connp->conn_lock);
	/*
	 * We succeeded in clearing the option (ifindex == 0) or failed to
	 * locate the ill and could not set the option (ifindex != 0)
	 */
	return (ifindex == 0 ? 0 : EINVAL);
}

/* This routine sets socket options. */
/* ARGSUSED */
int
ip_opt_set(queue_t *q, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *dummy, cred_t *cr, mblk_t *first_mp)
{
	int		*i1 = (int *)invalp;
	conn_t		*connp = Q_TO_CONN(q);
	int		error = 0;
	boolean_t	checkonly;
	ire_t		*ire;
	boolean_t	found;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	switch (optset_context) {

	case SETFN_OPTCOM_CHECKONLY:
		checkonly = B_TRUE;
		/*
		 * Note: Implies T_CHECK semantics for T_OPTCOM_REQ
		 * inlen != 0 implies value supplied and
		 * 	we have to "pretend" to set it.
		 * inlen == 0 implies that there is no
		 * 	value part in T_CHECK request and just validation
		 * done elsewhere should be enough, we just return here.
		 */
		if (inlen == 0) {
			*outlenp = 0;
			return (0);
		}
		break;
	case SETFN_OPTCOM_NEGOTIATE:
	case SETFN_UD_NEGOTIATE:
	case SETFN_CONN_NEGOTIATE:
		checkonly = B_FALSE;
		break;
	default:
		/*
		 * We should never get here
		 */
		*outlenp = 0;
		return (EINVAL);
	}

	ASSERT((optset_context != SETFN_OPTCOM_CHECKONLY) ||
	    (optset_context == SETFN_OPTCOM_CHECKONLY && inlen != 0));

	/*
	 * For fixed length options, no sanity check
	 * of passed in length is done. It is assumed *_optcom_req()
	 * routines do the right thing.
	 */

	switch (level) {
	case SOL_SOCKET:
		/*
		 * conn_lock protects the bitfields, and is used to
		 * set the fields atomically.
		 */
		switch (name) {
		case SO_BROADCAST:
			if (!checkonly) {
				/* TODO: use value someplace? */
				mutex_enter(&connp->conn_lock);
				connp->conn_broadcast = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case SO_USELOOPBACK:
			if (!checkonly) {
				/* TODO: use value someplace? */
				mutex_enter(&connp->conn_lock);
				connp->conn_loopback = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case SO_DONTROUTE:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_dontroute = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case SO_REUSEADDR:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_reuseaddr = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case SO_PROTOTYPE:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_proto = *i1;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case SO_ALLZONES:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				if (IPCL_IS_BOUND(connp)) {
					mutex_exit(&connp->conn_lock);
					return (EINVAL);
				}
				connp->conn_allzones = *i1 != 0 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case SO_ANON_MLP:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_anon_mlp = *i1 != 0 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case SO_MAC_EXEMPT:
			if (secpolicy_net_mac_aware(cr) != 0 ||
			    IPCL_IS_BOUND(connp))
				return (EACCES);
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_mac_exempt = *i1 != 0 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		default:
			/*
			 * "soft" error (negative)
			 * option not handled at this level
			 * Note: Do not modify *outlenp
			 */
			return (-EINVAL);
		}
		break;
	case IPPROTO_IP:
		switch (name) {
		case IP_NEXTHOP:
			if (secpolicy_ip_config(cr, B_FALSE) != 0)
				return (EPERM);
			/* FALLTHRU */
		case IP_MULTICAST_IF:
		case IP_DONTFAILOVER_IF: {
			ipaddr_t addr = *i1;

			error = ip_opt_set_ipif(connp, addr, checkonly, name,
			    first_mp);
			if (error != 0)
				return (error);
			break;	/* goto sizeof (int) option return */
		}

		case IP_MULTICAST_TTL:
			/* Recorded in transport above IP */
			*outvalp = *invalp;
			*outlenp = sizeof (uchar_t);
			return (0);
		case IP_MULTICAST_LOOP:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_multicast_loop = *invalp ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			*outvalp = *invalp;
			*outlenp = sizeof (uchar_t);
			return (0);
		case IP_ADD_MEMBERSHIP:
		case MCAST_JOIN_GROUP:
		case IP_DROP_MEMBERSHIP:
		case MCAST_LEAVE_GROUP: {
			struct ip_mreq *mreqp;
			struct group_req *greqp;
			ire_t *ire;
			boolean_t done = B_FALSE;
			ipaddr_t group, ifaddr;
			struct sockaddr_in *sin;
			uint32_t *ifindexp;
			boolean_t mcast_opt = B_TRUE;
			mcast_record_t fmode;
			int (*optfn)(conn_t *, boolean_t, ipaddr_t, ipaddr_t,
			    uint_t *, mcast_record_t, ipaddr_t, mblk_t *);

			switch (name) {
			case IP_ADD_MEMBERSHIP:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_JOIN_GROUP:
				fmode = MODE_IS_EXCLUDE;
				optfn = ip_opt_add_group;
				break;

			case IP_DROP_MEMBERSHIP:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_LEAVE_GROUP:
				fmode = MODE_IS_INCLUDE;
				optfn = ip_opt_delete_group;
				break;
			}

			if (mcast_opt) {
				greqp = (struct group_req *)i1;
				sin = (struct sockaddr_in *)&greqp->gr_group;
				if (sin->sin_family != AF_INET) {
					*outlenp = 0;
					return (ENOPROTOOPT);
				}
				group = (ipaddr_t)sin->sin_addr.s_addr;
				ifaddr = INADDR_ANY;
				ifindexp = &greqp->gr_interface;
			} else {
				mreqp = (struct ip_mreq *)i1;
				group = (ipaddr_t)mreqp->imr_multiaddr.s_addr;
				ifaddr = (ipaddr_t)mreqp->imr_interface.s_addr;
				ifindexp = NULL;
			}

			/*
			 * In the multirouting case, we need to replicate
			 * the request on all interfaces that will take part
			 * in replication.  We do so because multirouting is
			 * reflective, thus we will probably receive multi-
			 * casts on those interfaces.
			 * The ip_multirt_apply_membership() succeeds if the
			 * operation succeeds on at least one interface.
			 */
			ire = ire_ftable_lookup(group, IP_HOST_MASK, 0,
			    IRE_HOST, NULL, NULL, ALL_ZONES, 0, NULL,
			    MATCH_IRE_MASK | MATCH_IRE_TYPE, ipst);
			if (ire != NULL) {
				if (ire->ire_flags & RTF_MULTIRT) {
					error = ip_multirt_apply_membership(
					    optfn, ire, connp, checkonly, group,
					    fmode, INADDR_ANY, first_mp);
					done = B_TRUE;
				}
				ire_refrele(ire);
			}
			if (!done) {
				error = optfn(connp, checkonly, group, ifaddr,
				    ifindexp, fmode, INADDR_ANY, first_mp);
			}
			if (error) {
				/*
				 * EINPROGRESS is a soft error, needs retry
				 * so don't make *outlenp zero.
				 */
				if (error != EINPROGRESS)
					*outlenp = 0;
				return (error);
			}
			/* OK return - copy input buffer into output buffer */
			if (invalp != outvalp) {
				/* don't trust bcopy for identical src/dst */
				bcopy(invalp, outvalp, inlen);
			}
			*outlenp = inlen;
			return (0);
		}
		case IP_BLOCK_SOURCE:
		case IP_UNBLOCK_SOURCE:
		case IP_ADD_SOURCE_MEMBERSHIP:
		case IP_DROP_SOURCE_MEMBERSHIP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP: {
			struct ip_mreq_source *imreqp;
			struct group_source_req *gsreqp;
			in_addr_t grp, src, ifaddr = INADDR_ANY;
			uint32_t ifindex = 0;
			mcast_record_t fmode;
			struct sockaddr_in *sin;
			ire_t *ire;
			boolean_t mcast_opt = B_TRUE, done = B_FALSE;
			int (*optfn)(conn_t *, boolean_t, ipaddr_t, ipaddr_t,
			    uint_t *, mcast_record_t, ipaddr_t, mblk_t *);

			switch (name) {
			case IP_BLOCK_SOURCE:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_BLOCK_SOURCE:
				fmode = MODE_IS_EXCLUDE;
				optfn = ip_opt_add_group;
				break;

			case IP_UNBLOCK_SOURCE:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_UNBLOCK_SOURCE:
				fmode = MODE_IS_EXCLUDE;
				optfn = ip_opt_delete_group;
				break;

			case IP_ADD_SOURCE_MEMBERSHIP:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_JOIN_SOURCE_GROUP:
				fmode = MODE_IS_INCLUDE;
				optfn = ip_opt_add_group;
				break;

			case IP_DROP_SOURCE_MEMBERSHIP:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_LEAVE_SOURCE_GROUP:
				fmode = MODE_IS_INCLUDE;
				optfn = ip_opt_delete_group;
				break;
			}

			if (mcast_opt) {
				gsreqp = (struct group_source_req *)i1;
				if (gsreqp->gsr_group.ss_family != AF_INET) {
					*outlenp = 0;
					return (ENOPROTOOPT);
				}
				sin = (struct sockaddr_in *)&gsreqp->gsr_group;
				grp = (ipaddr_t)sin->sin_addr.s_addr;
				sin = (struct sockaddr_in *)&gsreqp->gsr_source;
				src = (ipaddr_t)sin->sin_addr.s_addr;
				ifindex = gsreqp->gsr_interface;
			} else {
				imreqp = (struct ip_mreq_source *)i1;
				grp = (ipaddr_t)imreqp->imr_multiaddr.s_addr;
				src = (ipaddr_t)imreqp->imr_sourceaddr.s_addr;
				ifaddr = (ipaddr_t)imreqp->imr_interface.s_addr;
			}

			/*
			 * In the multirouting case, we need to replicate
			 * the request as noted in the mcast cases above.
			 */
			ire = ire_ftable_lookup(grp, IP_HOST_MASK, 0,
			    IRE_HOST, NULL, NULL, ALL_ZONES, 0, NULL,
			    MATCH_IRE_MASK | MATCH_IRE_TYPE, ipst);
			if (ire != NULL) {
				if (ire->ire_flags & RTF_MULTIRT) {
					error = ip_multirt_apply_membership(
					    optfn, ire, connp, checkonly, grp,
					    fmode, src, first_mp);
					done = B_TRUE;
				}
				ire_refrele(ire);
			}
			if (!done) {
				error = optfn(connp, checkonly, grp, ifaddr,
				    &ifindex, fmode, src, first_mp);
			}
			if (error != 0) {
				/*
				 * EINPROGRESS is a soft error, needs retry
				 * so don't make *outlenp zero.
				 */
				if (error != EINPROGRESS)
					*outlenp = 0;
				return (error);
			}
			/* OK return - copy input buffer into output buffer */
			if (invalp != outvalp) {
				bcopy(invalp, outvalp, inlen);
			}
			*outlenp = inlen;
			return (0);
		}
		case IP_SEC_OPT:
			error = ipsec_set_req(cr, connp, (ipsec_req_t *)invalp);
			if (error != 0) {
				*outlenp = 0;
				return (error);
			}
			break;
		case IP_HDRINCL:
		case IP_OPTIONS:
		case T_IP_OPTIONS:
		case IP_TOS:
		case T_IP_TOS:
		case IP_TTL:
		case IP_RECVDSTADDR:
		case IP_RECVOPTS:
			/* OK return - copy input buffer into output buffer */
			if (invalp != outvalp) {
				/* don't trust bcopy for identical src/dst */
				bcopy(invalp, outvalp, inlen);
			}
			*outlenp = inlen;
			return (0);
		case IP_RECVIF:
			/* Retrieve the inbound interface index */
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_recvif = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IP_RECVPKTINFO:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_ip_recvpktinfo = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IP_RECVSLLA:
			/* Retrieve the source link layer address */
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_recvslla = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case MRT_INIT:
		case MRT_DONE:
		case MRT_ADD_VIF:
		case MRT_DEL_VIF:
		case MRT_ADD_MFC:
		case MRT_DEL_MFC:
		case MRT_ASSERT:
			if ((error = secpolicy_ip_config(cr, B_FALSE)) != 0) {
				*outlenp = 0;
				return (error);
			}
			error = ip_mrouter_set((int)name, q, checkonly,
			    (uchar_t *)invalp, inlen, first_mp);
			if (error) {
				*outlenp = 0;
				return (error);
			}
			/* OK return - copy input buffer into output buffer */
			if (invalp != outvalp) {
				/* don't trust bcopy for identical src/dst */
				bcopy(invalp, outvalp, inlen);
			}
			*outlenp = inlen;
			return (0);
		case IP_BOUND_IF:
		case IP_DHCPINIT_IF:
			error = ip_opt_set_ill(connp, *i1, B_FALSE, checkonly,
			    level, name, first_mp);
			if (error != 0)
				return (error);
			break; 		/* goto sizeof (int) option return */

		case IP_UNSPEC_SRC:
			/* Allow sending with a zero source address */
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_unspec_src = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		default:
			/*
			 * "soft" error (negative)
			 * option not handled at this level
			 * Note: Do not modify *outlenp
			 */
			return (-EINVAL);
		}
		break;
	case IPPROTO_IPV6:
		switch (name) {
		case IPV6_BOUND_IF:
		case IPV6_BOUND_PIF:
		case IPV6_DONTFAILOVER_IF:
			error = ip_opt_set_ill(connp, *i1, B_TRUE, checkonly,
			    level, name, first_mp);
			if (error != 0)
				return (error);
			break; 		/* goto sizeof (int) option return */

		case IPV6_MULTICAST_IF:
			/*
			 * The only possible errors are EINPROGRESS and
			 * EINVAL. EINPROGRESS will be restarted and is not
			 * a hard error. We call this option on both V4 and V6
			 * If both return EINVAL, then this call returns
			 * EINVAL. If at least one of them succeeds we
			 * return success.
			 */
			found = B_FALSE;
			error = ip_opt_set_ill(connp, *i1, B_TRUE, checkonly,
			    level, name, first_mp);
			if (error == EINPROGRESS)
				return (error);
			if (error == 0)
				found = B_TRUE;
			error = ip_opt_set_ill(connp, *i1, B_FALSE, checkonly,
			    IPPROTO_IP, IP_MULTICAST_IF, first_mp);
			if (error == 0)
				found = B_TRUE;
			if (!found)
				return (error);
			break; 		/* goto sizeof (int) option return */

		case IPV6_MULTICAST_HOPS:
			/* Recorded in transport above IP */
			break;	/* goto sizeof (int) option return */
		case IPV6_MULTICAST_LOOP:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_multicast_loop = *i1;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_JOIN_GROUP:
		case MCAST_JOIN_GROUP:
		case IPV6_LEAVE_GROUP:
		case MCAST_LEAVE_GROUP: {
			struct ipv6_mreq *ip_mreqp;
			struct group_req *greqp;
			ire_t *ire;
			boolean_t done = B_FALSE;
			in6_addr_t groupv6;
			uint32_t ifindex;
			boolean_t mcast_opt = B_TRUE;
			mcast_record_t fmode;
			int (*optfn)(conn_t *, boolean_t, const in6_addr_t *,
			    int, mcast_record_t, const in6_addr_t *, mblk_t *);

			switch (name) {
			case IPV6_JOIN_GROUP:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_JOIN_GROUP:
				fmode = MODE_IS_EXCLUDE;
				optfn = ip_opt_add_group_v6;
				break;

			case IPV6_LEAVE_GROUP:
				mcast_opt = B_FALSE;
				/* FALLTHRU */
			case MCAST_LEAVE_GROUP:
				fmode = MODE_IS_INCLUDE;
				optfn = ip_opt_delete_group_v6;
				break;
			}

			if (mcast_opt) {
				struct sockaddr_in *sin;
				struct sockaddr_in6 *sin6;
				greqp = (struct group_req *)i1;
				if (greqp->gr_group.ss_family == AF_INET) {
					sin = (struct sockaddr_in *)
					    &(greqp->gr_group);
					IN6_INADDR_TO_V4MAPPED(&sin->sin_addr,
					    &groupv6);
				} else {
					sin6 = (struct sockaddr_in6 *)
					    &(greqp->gr_group);
					groupv6 = sin6->sin6_addr;
				}
				ifindex = greqp->gr_interface;
			} else {
				ip_mreqp = (struct ipv6_mreq *)i1;
				groupv6 = ip_mreqp->ipv6mr_multiaddr;
				ifindex = ip_mreqp->ipv6mr_interface;
			}
			/*
			 * In the multirouting case, we need to replicate
			 * the request on all interfaces that will take part
			 * in replication.  We do so because multirouting is
			 * reflective, thus we will probably receive multi-
			 * casts on those interfaces.
			 * The ip_multirt_apply_membership_v6() succeeds if
			 * the operation succeeds on at least one interface.
			 */
			ire = ire_ftable_lookup_v6(&groupv6, &ipv6_all_ones, 0,
			    IRE_HOST, NULL, NULL, ALL_ZONES, 0, NULL,
			    MATCH_IRE_MASK | MATCH_IRE_TYPE, ipst);
			if (ire != NULL) {
				if (ire->ire_flags & RTF_MULTIRT) {
					error = ip_multirt_apply_membership_v6(
					    optfn, ire, connp, checkonly,
					    &groupv6, fmode, &ipv6_all_zeros,
					    first_mp);
					done = B_TRUE;
				}
				ire_refrele(ire);
			}
			if (!done) {
				error = optfn(connp, checkonly, &groupv6,
				    ifindex, fmode, &ipv6_all_zeros, first_mp);
			}
			if (error) {
				/*
				 * EINPROGRESS is a soft error, needs retry
				 * so don't make *outlenp zero.
				 */
				if (error != EINPROGRESS)
					*outlenp = 0;
				return (error);
			}
			/* OK return - copy input buffer into output buffer */
			if (invalp != outvalp) {
				/* don't trust bcopy for identical src/dst */
				bcopy(invalp, outvalp, inlen);
			}
			*outlenp = inlen;
			return (0);
		}
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP: {
			struct group_source_req *gsreqp;
			in6_addr_t v6grp, v6src;
			uint32_t ifindex;
			mcast_record_t fmode;
			ire_t *ire;
			boolean_t done = B_FALSE;
			int (*optfn)(conn_t *, boolean_t, const in6_addr_t *,
			    int, mcast_record_t, const in6_addr_t *, mblk_t *);

			switch (name) {
			case MCAST_BLOCK_SOURCE:
				fmode = MODE_IS_EXCLUDE;
				optfn = ip_opt_add_group_v6;
				break;
			case MCAST_UNBLOCK_SOURCE:
				fmode = MODE_IS_EXCLUDE;
				optfn = ip_opt_delete_group_v6;
				break;
			case MCAST_JOIN_SOURCE_GROUP:
				fmode = MODE_IS_INCLUDE;
				optfn = ip_opt_add_group_v6;
				break;
			case MCAST_LEAVE_SOURCE_GROUP:
				fmode = MODE_IS_INCLUDE;
				optfn = ip_opt_delete_group_v6;
				break;
			}

			gsreqp = (struct group_source_req *)i1;
			ifindex = gsreqp->gsr_interface;
			if (gsreqp->gsr_group.ss_family == AF_INET) {
				struct sockaddr_in *s;
				s = (struct sockaddr_in *)&gsreqp->gsr_group;
				IN6_INADDR_TO_V4MAPPED(&s->sin_addr, &v6grp);
				s = (struct sockaddr_in *)&gsreqp->gsr_source;
				IN6_INADDR_TO_V4MAPPED(&s->sin_addr, &v6src);
			} else {
				struct sockaddr_in6 *s6;
				s6 = (struct sockaddr_in6 *)&gsreqp->gsr_group;
				v6grp = s6->sin6_addr;
				s6 = (struct sockaddr_in6 *)&gsreqp->gsr_source;
				v6src = s6->sin6_addr;
			}

			/*
			 * In the multirouting case, we need to replicate
			 * the request as noted in the mcast cases above.
			 */
			ire = ire_ftable_lookup_v6(&v6grp, &ipv6_all_ones, 0,
			    IRE_HOST, NULL, NULL, ALL_ZONES, 0, NULL,
			    MATCH_IRE_MASK | MATCH_IRE_TYPE, ipst);
			if (ire != NULL) {
				if (ire->ire_flags & RTF_MULTIRT) {
					error = ip_multirt_apply_membership_v6(
					    optfn, ire, connp, checkonly,
					    &v6grp, fmode, &v6src, first_mp);
					done = B_TRUE;
				}
				ire_refrele(ire);
			}
			if (!done) {
				error = optfn(connp, checkonly, &v6grp,
				    ifindex, fmode, &v6src, first_mp);
			}
			if (error != 0) {
				/*
				 * EINPROGRESS is a soft error, needs retry
				 * so don't make *outlenp zero.
				 */
				if (error != EINPROGRESS)
					*outlenp = 0;
				return (error);
			}
			/* OK return - copy input buffer into output buffer */
			if (invalp != outvalp) {
				bcopy(invalp, outvalp, inlen);
			}
			*outlenp = inlen;
			return (0);
		}
		case IPV6_UNICAST_HOPS:
			/* Recorded in transport above IP */
			break;	/* goto sizeof (int) option return */
		case IPV6_UNSPEC_SRC:
			/* Allow sending with a zero source address */
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_unspec_src = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVPKTINFO:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_ip_recvpktinfo = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVTCLASS:
			if (!checkonly) {
				if (*i1 < 0 || *i1 > 1) {
					return (EINVAL);
				}
				mutex_enter(&connp->conn_lock);
				connp->conn_ipv6_recvtclass = *i1;
				mutex_exit(&connp->conn_lock);
			}
			break;
		case IPV6_RECVPATHMTU:
			if (!checkonly) {
				if (*i1 < 0 || *i1 > 1) {
					return (EINVAL);
				}
				mutex_enter(&connp->conn_lock);
				connp->conn_ipv6_recvpathmtu = *i1;
				mutex_exit(&connp->conn_lock);
			}
			break;
		case IPV6_RECVHOPLIMIT:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_ipv6_recvhoplimit = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPOPTS:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_ipv6_recvhopopts = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVDSTOPTS:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_ipv6_recvdstopts = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDR:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_ipv6_recvrthdr = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDRDSTOPTS:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				connp->conn_ipv6_recvrtdstopts = *i1 ? 1 : 0;
				mutex_exit(&connp->conn_lock);
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_PKTINFO:
			if (inlen == 0)
				return (-EINVAL);	/* clearing option */
			error = ip6_set_pktinfo(cr, connp,
			    (struct in6_pktinfo *)invalp, first_mp);
			if (error != 0)
				*outlenp = 0;
			else
				*outlenp = inlen;
			return (error);
		case IPV6_NEXTHOP: {
			struct sockaddr_in6 *sin6;

			/* Verify that the nexthop is reachable */
			if (inlen == 0)
				return (-EINVAL);	/* clearing option */

			sin6 = (struct sockaddr_in6 *)invalp;
			ire = ire_route_lookup_v6(&sin6->sin6_addr,
			    0, 0, 0, NULL, NULL, connp->conn_zoneid,
			    NULL, MATCH_IRE_DEFAULT, ipst);

			if (ire == NULL) {
				*outlenp = 0;
				return (EHOSTUNREACH);
			}
			ire_refrele(ire);
			return (-EINVAL);
		}
		case IPV6_SEC_OPT:
			error = ipsec_set_req(cr, connp, (ipsec_req_t *)invalp);
			if (error != 0) {
				*outlenp = 0;
				return (error);
			}
			break;
		case IPV6_SRC_PREFERENCES: {
			/*
			 * This is implemented strictly in the ip module
			 * (here and in tcp_opt_*() to accomodate tcp
			 * sockets).  Modules above ip pass this option
			 * down here since ip is the only one that needs to
			 * be aware of source address preferences.
			 *
			 * This socket option only affects connected
			 * sockets that haven't already bound to a specific
			 * IPv6 address.  In other words, sockets that
			 * don't call bind() with an address other than the
			 * unspecified address and that call connect().
			 * ip_bind_connected_v6() passes these preferences
			 * to the ipif_select_source_v6() function.
			 */
			if (inlen != sizeof (uint32_t))
				return (EINVAL);
			error = ip6_set_src_preferences(connp,
			    *(uint32_t *)invalp);
			if (error != 0) {
				*outlenp = 0;
				return (error);
			} else {
				*outlenp = sizeof (uint32_t);
			}
			break;
		}
		case IPV6_V6ONLY:
			if (*i1 < 0 || *i1 > 1) {
				return (EINVAL);
			}
			mutex_enter(&connp->conn_lock);
			connp->conn_ipv6_v6only = *i1;
			mutex_exit(&connp->conn_lock);
			break;
		default:
			return (-EINVAL);
		}
		break;
	default:
		/*
		 * "soft" error (negative)
		 * option not handled at this level
		 * Note: Do not modify *outlenp
		 */
		return (-EINVAL);
	}
	/*
	 * Common case of return from an option that is sizeof (int)
	 */
	*(int *)outvalp = *i1;
	*outlenp = sizeof (int);
	return (0);
}

/*
 * This routine gets default values of certain options whose default
 * values are maintained by protocol specific code
 */
/* ARGSUSED */
int
ip_opt_default(queue_t *q, int level, int name, uchar_t *ptr)
{
	int *i1 = (int *)ptr;
	ip_stack_t	*ipst = CONNQ_TO_IPST(q);

	switch (level) {
	case IPPROTO_IP:
		switch (name) {
		case IP_MULTICAST_TTL:
			*ptr = (uchar_t)IP_DEFAULT_MULTICAST_TTL;
			return (sizeof (uchar_t));
		case IP_MULTICAST_LOOP:
			*ptr = (uchar_t)IP_DEFAULT_MULTICAST_LOOP;
			return (sizeof (uchar_t));
		default:
			return (-1);
		}
	case IPPROTO_IPV6:
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = ipst->ips_ipv6_def_hops;
			return (sizeof (int));
		case IPV6_MULTICAST_HOPS:
			*i1 = IP_DEFAULT_MULTICAST_TTL;
			return (sizeof (int));
		case IPV6_MULTICAST_LOOP:
			*i1 = IP_DEFAULT_MULTICAST_LOOP;
			return (sizeof (int));
		case IPV6_V6ONLY:
			*i1 = 1;
			return (sizeof (int));
		default:
			return (-1);
		}
	default:
		return (-1);
	}
	/* NOTREACHED */
}

/*
 * Given a destination address and a pointer to where to put the information
 * this routine fills in the mtuinfo.
 */
int
ip_fill_mtuinfo(struct in6_addr *in6, in_port_t port,
    struct ip6_mtuinfo *mtuinfo, netstack_t *ns)
{
	ire_t *ire;
	ip_stack_t	*ipst = ns->netstack_ip;

	if (IN6_IS_ADDR_UNSPECIFIED(in6))
		return (-1);

	bzero(mtuinfo, sizeof (*mtuinfo));
	mtuinfo->ip6m_addr.sin6_family = AF_INET6;
	mtuinfo->ip6m_addr.sin6_port = port;
	mtuinfo->ip6m_addr.sin6_addr = *in6;

	ire = ire_cache_lookup_v6(in6, ALL_ZONES, NULL, ipst);
	if (ire != NULL) {
		mtuinfo->ip6m_mtu = ire->ire_max_frag;
		ire_refrele(ire);
	} else {
		mtuinfo->ip6m_mtu = IPV6_MIN_MTU;
	}
	return (sizeof (struct ip6_mtuinfo));
}

/*
 * This routine gets socket options.  For MRT_VERSION and MRT_ASSERT, error
 * checking of GET_QUEUE_CRED(q) and that ip_g_mrouter is set should be done and
 * isn't.  This doesn't matter as the error checking is done properly for the
 * other MRT options coming in through ip_opt_set.
 */
int
ip_opt_get(queue_t *q, int level, int name, uchar_t *ptr)
{
	conn_t		*connp = Q_TO_CONN(q);
	ipsec_req_t	*req = (ipsec_req_t *)ptr;

	switch (level) {
	case IPPROTO_IP:
		switch (name) {
		case MRT_VERSION:
		case MRT_ASSERT:
			(void) ip_mrouter_get(name, q, ptr);
			return (sizeof (int));
		case IP_SEC_OPT:
			return (ipsec_req_from_conn(connp, req, IPSEC_AF_V4));
		case IP_NEXTHOP:
			if (connp->conn_nexthop_set) {
				*(ipaddr_t *)ptr = connp->conn_nexthop_v4;
				return (sizeof (ipaddr_t));
			} else
				return (0);
		case IP_RECVPKTINFO:
			*(int *)ptr = connp->conn_ip_recvpktinfo ? 1: 0;
			return (sizeof (int));
		default:
			break;
		}
		break;
	case IPPROTO_IPV6:
		switch (name) {
		case IPV6_SEC_OPT:
			return (ipsec_req_from_conn(connp, req, IPSEC_AF_V6));
		case IPV6_SRC_PREFERENCES: {
			return (ip6_get_src_preferences(connp,
			    (uint32_t *)ptr));
		}
		case IPV6_V6ONLY:
			*(int *)ptr = connp->conn_ipv6_v6only ? 1 : 0;
			return (sizeof (int));
		case IPV6_PATHMTU:
			return (ip_fill_mtuinfo(&connp->conn_remv6, 0,
			    (struct ip6_mtuinfo *)ptr, connp->conn_netstack));
		default:
			break;
		}
		break;
	default:
		break;
	}
	return (-1);
}

/* Named Dispatch routine to get a current value out of our parameter table. */
/* ARGSUSED */
static int
ip_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *ioc_cr)
{
	ipparam_t *ippa = (ipparam_t *)cp;

	(void) mi_mpprintf(mp, "%d", ippa->ip_param_value);
	return (0);
}

/* ARGSUSED */
static int
ip_param_generic_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *ioc_cr)
{

	(void) mi_mpprintf(mp, "%d", *(int *)cp);
	return (0);
}

/*
 * Set ip{,6}_forwarding values.  This means walking through all of the
 * ill's and toggling their forwarding values.
 */
/* ARGSUSED */
static int
ip_forward_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *ioc_cr)
{
	long new_value;
	int *forwarding_value = (int *)cp;
	ill_t *ill;
	boolean_t isv6;
	ill_walk_context_t ctx;
	ip_stack_t *ipst = CONNQ_TO_IPST(q);

	isv6 = (forwarding_value == &ipst->ips_ipv6_forward);

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < 0 || new_value > 1) {
		return (EINVAL);
	}

	*forwarding_value = new_value;

	/*
	 * Regardless of the current value of ip_forwarding, set all per-ill
	 * values of ip_forwarding to the value being set.
	 *
	 * Bring all the ill's up to date with the new global value.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	if (isv6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_V4(&ctx, ipst);

	for (; ill != NULL; ill = ill_next(&ctx, ill))
		(void) ill_forward_set(ill, new_value != 0);

	rw_exit(&ipst->ips_ill_g_lock);
	return (0);
}

/*
 * Walk through the param array specified registering each element with the
 * Named Dispatch handler. This is called only during init. So it is ok
 * not to acquire any locks
 */
static boolean_t
ip_param_register(IDP *ndp, ipparam_t *ippa, size_t ippa_cnt,
    ipndp_t *ipnd, size_t ipnd_cnt)
{
	for (; ippa_cnt-- > 0; ippa++) {
		if (ippa->ip_param_name && ippa->ip_param_name[0]) {
			if (!nd_load(ndp, ippa->ip_param_name,
			    ip_param_get, ip_param_set, (caddr_t)ippa)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}

	for (; ipnd_cnt-- > 0; ipnd++) {
		if (ipnd->ip_ndp_name && ipnd->ip_ndp_name[0]) {
			if (!nd_load(ndp, ipnd->ip_ndp_name,
			    ipnd->ip_ndp_getf, ipnd->ip_ndp_setf,
			    ipnd->ip_ndp_data)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

/* Named Dispatch routine to negotiate a new value for one of our parameters. */
/* ARGSUSED */
static int
ip_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *ioc_cr)
{
	long		new_value;
	ipparam_t	*ippa = (ipparam_t *)cp;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < ippa->ip_param_min || new_value > ippa->ip_param_max) {
		return (EINVAL);
	}
	ippa->ip_param_value = new_value;
	return (0);
}

/*
 * Handles both IPv4 and IPv6 reassembly - doing the out-of-order cases,
 * When an ipf is passed here for the first time, if
 * we already have in-order fragments on the queue, we convert from the fast-
 * path reassembly scheme to the hard-case scheme.  From then on, additional
 * fragments are reassembled here.  We keep track of the start and end offsets
 * of each piece, and the number of holes in the chain.  When the hole count
 * goes to zero, we are done!
 *
 * The ipf_count will be updated to account for any mblk(s) added (pointed to
 * by mp) or subtracted (freeb()ed dups), upon return the caller must update
 * ipfb_count and ill_frag_count by the difference of ipf_count before and
 * after the call to ip_reassemble().
 */
int
ip_reassemble(mblk_t *mp, ipf_t *ipf, uint_t start, boolean_t more, ill_t *ill,
    size_t msg_len)
{
	uint_t	end;
	mblk_t	*next_mp;
	mblk_t	*mp1;
	uint_t	offset;
	boolean_t incr_dups = B_TRUE;
	boolean_t offset_zero_seen = B_FALSE;
	boolean_t pkt_boundary_checked = B_FALSE;

	/* If start == 0 then ipf_nf_hdr_len has to be set. */
	ASSERT(start != 0 || ipf->ipf_nf_hdr_len != 0);

	/* Add in byte count */
	ipf->ipf_count += msg_len;
	if (ipf->ipf_end) {
		/*
		 * We were part way through in-order reassembly, but now there
		 * is a hole.  We walk through messages already queued, and
		 * mark them for hard case reassembly.  We know that up till
		 * now they were in order starting from offset zero.
		 */
		offset = 0;
		for (mp1 = ipf->ipf_mp->b_cont; mp1; mp1 = mp1->b_cont) {
			IP_REASS_SET_START(mp1, offset);
			if (offset == 0) {
				ASSERT(ipf->ipf_nf_hdr_len != 0);
				offset = -ipf->ipf_nf_hdr_len;
			}
			offset += mp1->b_wptr - mp1->b_rptr;
			IP_REASS_SET_END(mp1, offset);
		}
		/* One hole at the end. */
		ipf->ipf_hole_cnt = 1;
		/* Brand it as a hard case, forever. */
		ipf->ipf_end = 0;
	}
	/* Walk through all the new pieces. */
	do {
		end = start + (mp->b_wptr - mp->b_rptr);
		/*
		 * If start is 0, decrease 'end' only for the first mblk of
		 * the fragment. Otherwise 'end' can get wrong value in the
		 * second pass of the loop if first mblk is exactly the
		 * size of ipf_nf_hdr_len.
		 */
		if (start == 0 && !offset_zero_seen) {
			/* First segment */
			ASSERT(ipf->ipf_nf_hdr_len != 0);
			end -= ipf->ipf_nf_hdr_len;
			offset_zero_seen = B_TRUE;
		}
		next_mp = mp->b_cont;
		/*
		 * We are checking to see if there is any interesing data
		 * to process.  If there isn't and the mblk isn't the
		 * one which carries the unfragmentable header then we
		 * drop it.  It's possible to have just the unfragmentable
		 * header come through without any data.  That needs to be
		 * saved.
		 *
		 * If the assert at the top of this function holds then the
		 * term "ipf->ipf_nf_hdr_len != 0" isn't needed.  This code
		 * is infrequently traveled enough that the test is left in
		 * to protect against future code changes which break that
		 * invariant.
		 */
		if (start == end && start != 0 && ipf->ipf_nf_hdr_len != 0) {
			/* Empty.  Blast it. */
			IP_REASS_SET_START(mp, 0);
			IP_REASS_SET_END(mp, 0);
			/*
			 * If the ipf points to the mblk we are about to free,
			 * update ipf to point to the next mblk (or NULL
			 * if none).
			 */
			if (ipf->ipf_mp->b_cont == mp)
				ipf->ipf_mp->b_cont = next_mp;
			freeb(mp);
			continue;
		}
		mp->b_cont = NULL;
		IP_REASS_SET_START(mp, start);
		IP_REASS_SET_END(mp, end);
		if (!ipf->ipf_tail_mp) {
			ipf->ipf_tail_mp = mp;
			ipf->ipf_mp->b_cont = mp;
			if (start == 0 || !more) {
				ipf->ipf_hole_cnt = 1;
				/*
				 * if the first fragment comes in more than one
				 * mblk, this loop will be executed for each
				 * mblk. Need to adjust hole count so exiting
				 * this routine will leave hole count at 1.
				 */
				if (next_mp)
					ipf->ipf_hole_cnt++;
			} else
				ipf->ipf_hole_cnt = 2;
			continue;
		} else if (ipf->ipf_last_frag_seen && !more &&
		    !pkt_boundary_checked) {
			/*
			 * We check datagram boundary only if this fragment
			 * claims to be the last fragment and we have seen a
			 * last fragment in the past too. We do this only
			 * once for a given fragment.
			 *
			 * start cannot be 0 here as fragments with start=0
			 * and MF=0 gets handled as a complete packet. These
			 * fragments should not reach here.
			 */

			if (start + msgdsize(mp) !=
			    IP_REASS_END(ipf->ipf_tail_mp)) {
				/*
				 * We have two fragments both of which claim
				 * to be the last fragment but gives conflicting
				 * information about the whole datagram size.
				 * Something fishy is going on. Drop the
				 * fragment and free up the reassembly list.
				 */
				return (IP_REASS_FAILED);
			}

			/*
			 * We shouldn't come to this code block again for this
			 * particular fragment.
			 */
			pkt_boundary_checked = B_TRUE;
		}

		/* New stuff at or beyond tail? */
		offset = IP_REASS_END(ipf->ipf_tail_mp);
		if (start >= offset) {
			if (ipf->ipf_last_frag_seen) {
				/* current fragment is beyond last fragment */
				return (IP_REASS_FAILED);
			}
			/* Link it on end. */
			ipf->ipf_tail_mp->b_cont = mp;
			ipf->ipf_tail_mp = mp;
			if (more) {
				if (start != offset)
					ipf->ipf_hole_cnt++;
			} else if (start == offset && next_mp == NULL)
					ipf->ipf_hole_cnt--;
			continue;
		}
		mp1 = ipf->ipf_mp->b_cont;
		offset = IP_REASS_START(mp1);
		/* New stuff at the front? */
		if (start < offset) {
			if (start == 0) {
				if (end >= offset) {
					/* Nailed the hole at the begining. */
					ipf->ipf_hole_cnt--;
				}
			} else if (end < offset) {
				/*
				 * A hole, stuff, and a hole where there used
				 * to be just a hole.
				 */
				ipf->ipf_hole_cnt++;
			}
			mp->b_cont = mp1;
			/* Check for overlap. */
			while (end > offset) {
				if (end < IP_REASS_END(mp1)) {
					mp->b_wptr -= end - offset;
					IP_REASS_SET_END(mp, offset);
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsReasmPartDups);
					break;
				}
				/* Did we cover another hole? */
				if ((mp1->b_cont &&
				    IP_REASS_END(mp1) !=
				    IP_REASS_START(mp1->b_cont) &&
				    end >= IP_REASS_START(mp1->b_cont)) ||
				    (!ipf->ipf_last_frag_seen && !more)) {
					ipf->ipf_hole_cnt--;
				}
				/* Clip out mp1. */
				if ((mp->b_cont = mp1->b_cont) == NULL) {
					/*
					 * After clipping out mp1, this guy
					 * is now hanging off the end.
					 */
					ipf->ipf_tail_mp = mp;
				}
				IP_REASS_SET_START(mp1, 0);
				IP_REASS_SET_END(mp1, 0);
				/* Subtract byte count */
				ipf->ipf_count -= mp1->b_datap->db_lim -
				    mp1->b_datap->db_base;
				freeb(mp1);
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsReasmPartDups);
				mp1 = mp->b_cont;
				if (!mp1)
					break;
				offset = IP_REASS_START(mp1);
			}
			ipf->ipf_mp->b_cont = mp;
			continue;
		}
		/*
		 * The new piece starts somewhere between the start of the head
		 * and before the end of the tail.
		 */
		for (; mp1; mp1 = mp1->b_cont) {
			offset = IP_REASS_END(mp1);
			if (start < offset) {
				if (end <= offset) {
					/* Nothing new. */
					IP_REASS_SET_START(mp, 0);
					IP_REASS_SET_END(mp, 0);
					/* Subtract byte count */
					ipf->ipf_count -= mp->b_datap->db_lim -
					    mp->b_datap->db_base;
					if (incr_dups) {
						ipf->ipf_num_dups++;
						incr_dups = B_FALSE;
					}
					freeb(mp);
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsReasmDuplicates);
					break;
				}
				/*
				 * Trim redundant stuff off beginning of new
				 * piece.
				 */
				IP_REASS_SET_START(mp, offset);
				mp->b_rptr += offset - start;
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsReasmPartDups);
				start = offset;
				if (!mp1->b_cont) {
					/*
					 * After trimming, this guy is now
					 * hanging off the end.
					 */
					mp1->b_cont = mp;
					ipf->ipf_tail_mp = mp;
					if (!more) {
						ipf->ipf_hole_cnt--;
					}
					break;
				}
			}
			if (start >= IP_REASS_START(mp1->b_cont))
				continue;
			/* Fill a hole */
			if (start > offset)
				ipf->ipf_hole_cnt++;
			mp->b_cont = mp1->b_cont;
			mp1->b_cont = mp;
			mp1 = mp->b_cont;
			offset = IP_REASS_START(mp1);
			if (end >= offset) {
				ipf->ipf_hole_cnt--;
				/* Check for overlap. */
				while (end > offset) {
					if (end < IP_REASS_END(mp1)) {
						mp->b_wptr -= end - offset;
						IP_REASS_SET_END(mp, offset);
						/*
						 * TODO we might bump
						 * this up twice if there is
						 * overlap at both ends.
						 */
						BUMP_MIB(ill->ill_ip_mib,
						    ipIfStatsReasmPartDups);
						break;
					}
					/* Did we cover another hole? */
					if ((mp1->b_cont &&
					    IP_REASS_END(mp1)
					    != IP_REASS_START(mp1->b_cont) &&
					    end >=
					    IP_REASS_START(mp1->b_cont)) ||
					    (!ipf->ipf_last_frag_seen &&
					    !more)) {
						ipf->ipf_hole_cnt--;
					}
					/* Clip out mp1. */
					if ((mp->b_cont = mp1->b_cont) ==
					    NULL) {
						/*
						 * After clipping out mp1,
						 * this guy is now hanging
						 * off the end.
						 */
						ipf->ipf_tail_mp = mp;
					}
					IP_REASS_SET_START(mp1, 0);
					IP_REASS_SET_END(mp1, 0);
					/* Subtract byte count */
					ipf->ipf_count -=
					    mp1->b_datap->db_lim -
					    mp1->b_datap->db_base;
					freeb(mp1);
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsReasmPartDups);
					mp1 = mp->b_cont;
					if (!mp1)
						break;
					offset = IP_REASS_START(mp1);
				}
			}
			break;
		}
	} while (start = end, mp = next_mp);

	/* Fragment just processed could be the last one. Remember this fact */
	if (!more)
		ipf->ipf_last_frag_seen = B_TRUE;

	/* Still got holes? */
	if (ipf->ipf_hole_cnt)
		return (IP_REASS_PARTIAL);
	/* Clean up overloaded fields to avoid upstream disasters. */
	for (mp1 = ipf->ipf_mp->b_cont; mp1; mp1 = mp1->b_cont) {
		IP_REASS_SET_START(mp1, 0);
		IP_REASS_SET_END(mp1, 0);
	}
	return (IP_REASS_COMPLETE);
}

/*
 * ipsec processing for the fast path, used for input UDP Packets
 * Returns true if ready for passup to UDP.
 * Return false if packet is not passable to UDP (e.g. it failed IPsec policy,
 * was an ESP-in-UDP packet, etc.).
 */
static boolean_t
ip_udp_check(queue_t *q, conn_t *connp, ill_t *ill, ipha_t *ipha,
    mblk_t **mpp, mblk_t **first_mpp, boolean_t mctl_present, ire_t *ire)
{
	uint32_t	ill_index;
	uint_t		in_flags;	/* IPF_RECVSLLA and/or IPF_RECVIF */
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;
	udp_t		*udp = connp->conn_udp;

	ASSERT(ipha->ipha_protocol == IPPROTO_UDP);
	/* The ill_index of the incoming ILL */
	ill_index = ((ill_t *)q->q_ptr)->ill_phyint->phyint_ifindex;

	/* pass packet up to the transport */
	if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) || mctl_present) {
		*first_mpp = ipsec_check_inbound_policy(*first_mpp, connp, ipha,
		    NULL, mctl_present);
		if (*first_mpp == NULL) {
			return (B_FALSE);
		}
	}

	/* Initiate IPPF processing for fastpath UDP */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst)) {
		ip_process(IPP_LOCAL_IN, mpp, ill_index);
		if (*mpp == NULL) {
			ip2dbg(("ip_input_ipsec_process: UDP pkt "
			    "deferred/dropped during IPPF processing\n"));
			return (B_FALSE);
		}
	}
	/*
	 * Remove 0-spi if it's 0, or move everything behind
	 * the UDP header over it and forward to ESP via
	 * ip_proto_input().
	 */
	if (udp->udp_nat_t_endpoint) {
		if (mctl_present) {
			/* mctl_present *shouldn't* happen. */
			ip_drop_packet(*first_mpp, B_TRUE, NULL,
			    NULL, DROPPER(ipss, ipds_esp_nat_t_ipsec),
			    &ipss->ipsec_dropper);
			*first_mpp = NULL;
			return (B_FALSE);
		}

		/* "ill" is "recv_ill" in actuality. */
		if (!zero_spi_check(q, *mpp, ire, ill, ipss))
			return (B_FALSE);

		/* Else continue like a normal UDP packet. */
	}

	/*
	 * We make the checks as below since we are in the fast path
	 * and want to minimize the number of checks if the IP_RECVIF and/or
	 * IP_RECVSLLA and/or IPV6_RECVPKTINFO options are not set
	 */
	if (connp->conn_recvif || connp->conn_recvslla ||
	    connp->conn_ip_recvpktinfo) {
		if (connp->conn_recvif) {
			in_flags = IPF_RECVIF;
		}
		/*
		 * UDP supports IP_RECVPKTINFO option for both v4 and v6
		 * so the flag passed to ip_add_info is based on IP version
		 * of connp.
		 */
		if (connp->conn_ip_recvpktinfo) {
			if (connp->conn_af_isv6) {
				/*
				 * V6 only needs index
				 */
				in_flags |= IPF_RECVIF;
			} else {
				/*
				 * V4 needs index + matching address.
				 */
				in_flags |= IPF_RECVADDR;
			}
		}
		if (connp->conn_recvslla) {
			in_flags |= IPF_RECVSLLA;
		}
		/*
		 * since in_flags are being set ill will be
		 * referenced in ip_add_info, so it better not
		 * be NULL.
		 */
		/*
		 * the actual data will be contained in b_cont
		 * upon successful return of the following call.
		 * If the call fails then the original mblk is
		 * returned.
		 */
		*mpp = ip_add_info(*mpp, ill, in_flags, IPCL_ZONEID(connp),
		    ipst);
	}

	return (B_TRUE);
}

/*
 * Fragmentation reassembly.  Each ILL has a hash table for
 * queuing packets undergoing reassembly for all IPIFs
 * associated with the ILL.  The hash is based on the packet
 * IP ident field.  The ILL frag hash table was allocated
 * as a timer block at the time the ILL was created.  Whenever
 * there is anything on the reassembly queue, the timer will
 * be running.  Returns B_TRUE if successful else B_FALSE;
 * frees mp on failure.
 */
static boolean_t
ip_rput_fragment(queue_t *q, mblk_t **mpp, ipha_t *ipha,
    uint32_t *cksum_val, uint16_t *cksum_flags)
{
	uint32_t	frag_offset_flags;
	ill_t		*ill = (ill_t *)q->q_ptr;
	mblk_t		*mp = *mpp;
	mblk_t		*t_mp;
	ipaddr_t	dst;
	uint8_t		proto = ipha->ipha_protocol;
	uint32_t	sum_val;
	uint16_t	sum_flags;
	ipf_t		*ipf;
	ipf_t		**ipfp;
	ipfb_t		*ipfb;
	uint16_t	ident;
	uint32_t	offset;
	ipaddr_t	src;
	uint_t		hdr_length;
	uint32_t	end;
	mblk_t		*mp1;
	mblk_t		*tail_mp;
	size_t		count;
	size_t		msg_len;
	uint8_t		ecn_info = 0;
	uint32_t	packet_size;
	boolean_t	pruned = B_FALSE;
	ip_stack_t *ipst = ill->ill_ipst;

	if (cksum_val != NULL)
		*cksum_val = 0;
	if (cksum_flags != NULL)
		*cksum_flags = 0;

	/*
	 * Drop the fragmented as early as possible, if
	 * we don't have resource(s) to re-assemble.
	 */
	if (ipst->ips_ip_reass_queue_bytes == 0) {
		freemsg(mp);
		return (B_FALSE);
	}

	/* Check for fragmentation offset; return if there's none */
	if ((frag_offset_flags = ntohs(ipha->ipha_fragment_offset_and_flags) &
	    (IPH_MF | IPH_OFFSET)) == 0)
		return (B_TRUE);

	/*
	 * We utilize hardware computed checksum info only for UDP since
	 * IP fragmentation is a normal occurence for the protocol.  In
	 * addition, checksum offload support for IP fragments carrying
	 * UDP payload is commonly implemented across network adapters.
	 */
	ASSERT(ill != NULL);
	if (proto == IPPROTO_UDP && dohwcksum && ILL_HCKSUM_CAPABLE(ill) &&
	    (DB_CKSUMFLAGS(mp) & (HCK_FULLCKSUM | HCK_PARTIALCKSUM))) {
		mblk_t *mp1 = mp->b_cont;
		int32_t len;

		/* Record checksum information from the packet */
		sum_val = (uint32_t)DB_CKSUM16(mp);
		sum_flags = DB_CKSUMFLAGS(mp);

		/* IP payload offset from beginning of mblk */
		offset = ((uchar_t *)ipha + IPH_HDR_LENGTH(ipha)) - mp->b_rptr;

		if ((sum_flags & HCK_PARTIALCKSUM) &&
		    (mp1 == NULL || mp1->b_cont == NULL) &&
		    offset >= DB_CKSUMSTART(mp) &&
		    ((len = offset - DB_CKSUMSTART(mp)) & 1) == 0) {
			uint32_t adj;
			/*
			 * Partial checksum has been calculated by hardware
			 * and attached to the packet; in addition, any
			 * prepended extraneous data is even byte aligned.
			 * If any such data exists, we adjust the checksum;
			 * this would also handle any postpended data.
			 */
			IP_ADJCKSUM_PARTIAL(mp->b_rptr + DB_CKSUMSTART(mp),
			    mp, mp1, len, adj);

			/* One's complement subtract extraneous checksum */
			if (adj >= sum_val)
				sum_val = ~(adj - sum_val) & 0xFFFF;
			else
				sum_val -= adj;
		}
	} else {
		sum_val = 0;
		sum_flags = 0;
	}

	/* Clear hardware checksumming flag */
	DB_CKSUMFLAGS(mp) = 0;

	ident = ipha->ipha_ident;
	offset = (frag_offset_flags << 3) & 0xFFFF;
	src = ipha->ipha_src;
	dst = ipha->ipha_dst;
	hdr_length = IPH_HDR_LENGTH(ipha);
	end = ntohs(ipha->ipha_length) - hdr_length;

	/* If end == 0 then we have a packet with no data, so just free it */
	if (end == 0) {
		freemsg(mp);
		return (B_FALSE);
	}

	/* Record the ECN field info. */
	ecn_info = (ipha->ipha_type_of_service & 0x3);
	if (offset != 0) {
		/*
		 * If this isn't the first piece, strip the header, and
		 * add the offset to the end value.
		 */
		mp->b_rptr += hdr_length;
		end += offset;
	}

	msg_len = MBLKSIZE(mp);
	tail_mp = mp;
	while (tail_mp->b_cont != NULL) {
		tail_mp = tail_mp->b_cont;
		msg_len += MBLKSIZE(tail_mp);
	}

	/* If the reassembly list for this ILL will get too big, prune it */
	if ((msg_len + sizeof (*ipf) + ill->ill_frag_count) >=
	    ipst->ips_ip_reass_queue_bytes) {
		ill_frag_prune(ill,
		    (ipst->ips_ip_reass_queue_bytes < msg_len) ? 0 :
		    (ipst->ips_ip_reass_queue_bytes - msg_len));
		pruned = B_TRUE;
	}

	ipfb = &ill->ill_frag_hash_tbl[ILL_FRAG_HASH(src, ident)];
	mutex_enter(&ipfb->ipfb_lock);

	ipfp = &ipfb->ipfb_ipf;
	/* Try to find an existing fragment queue for this packet. */
	for (;;) {
		ipf = ipfp[0];
		if (ipf != NULL) {
			/*
			 * It has to match on ident and src/dst address.
			 */
			if (ipf->ipf_ident == ident &&
			    ipf->ipf_src == src &&
			    ipf->ipf_dst == dst &&
			    ipf->ipf_protocol == proto) {
				/*
				 * If we have received too many
				 * duplicate fragments for this packet
				 * free it.
				 */
				if (ipf->ipf_num_dups > ip_max_frag_dups) {
					ill_frag_free_pkts(ill, ipfb, ipf, 1);
					freemsg(mp);
					mutex_exit(&ipfb->ipfb_lock);
					return (B_FALSE);
				}
				/* Found it. */
				break;
			}
			ipfp = &ipf->ipf_hash_next;
			continue;
		}

		/*
		 * If we pruned the list, do we want to store this new
		 * fragment?. We apply an optimization here based on the
		 * fact that most fragments will be received in order.
		 * So if the offset of this incoming fragment is zero,
		 * it is the first fragment of a new packet. We will
		 * keep it.  Otherwise drop the fragment, as we have
		 * probably pruned the packet already (since the
		 * packet cannot be found).
		 */
		if (pruned && offset != 0) {
			mutex_exit(&ipfb->ipfb_lock);
			freemsg(mp);
			return (B_FALSE);
		}

		if (ipfb->ipfb_frag_pkts >= MAX_FRAG_PKTS(ipst))  {
			/*
			 * Too many fragmented packets in this hash
			 * bucket. Free the oldest.
			 */
			ill_frag_free_pkts(ill, ipfb, ipfb->ipfb_ipf, 1);
		}

		/* New guy.  Allocate a frag message. */
		mp1 = allocb(sizeof (*ipf), BPRI_MED);
		if (mp1 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(mp);
reass_done:
			mutex_exit(&ipfb->ipfb_lock);
			return (B_FALSE);
		}

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmReqds);
		mp1->b_cont = mp;

		/* Initialize the fragment header. */
		ipf = (ipf_t *)mp1->b_rptr;
		ipf->ipf_mp = mp1;
		ipf->ipf_ptphn = ipfp;
		ipfp[0] = ipf;
		ipf->ipf_hash_next = NULL;
		ipf->ipf_ident = ident;
		ipf->ipf_protocol = proto;
		ipf->ipf_src = src;
		ipf->ipf_dst = dst;
		ipf->ipf_nf_hdr_len = 0;
		/* Record reassembly start time. */
		ipf->ipf_timestamp = gethrestime_sec();
		/* Record ipf generation and account for frag header */
		ipf->ipf_gen = ill->ill_ipf_gen++;
		ipf->ipf_count = MBLKSIZE(mp1);
		ipf->ipf_last_frag_seen = B_FALSE;
		ipf->ipf_ecn = ecn_info;
		ipf->ipf_num_dups = 0;
		ipfb->ipfb_frag_pkts++;
		ipf->ipf_checksum = 0;
		ipf->ipf_checksum_flags = 0;

		/* Store checksum value in fragment header */
		if (sum_flags != 0) {
			sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
			sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
			ipf->ipf_checksum = sum_val;
			ipf->ipf_checksum_flags = sum_flags;
		}

		/*
		 * We handle reassembly two ways.  In the easy case,
		 * where all the fragments show up in order, we do
		 * minimal bookkeeping, and just clip new pieces on
		 * the end.  If we ever see a hole, then we go off
		 * to ip_reassemble which has to mark the pieces and
		 * keep track of the number of holes, etc.  Obviously,
		 * the point of having both mechanisms is so we can
		 * handle the easy case as efficiently as possible.
		 */
		if (offset == 0) {
			/* Easy case, in-order reassembly so far. */
			ipf->ipf_count += msg_len;
			ipf->ipf_tail_mp = tail_mp;
			/*
			 * Keep track of next expected offset in
			 * ipf_end.
			 */
			ipf->ipf_end = end;
			ipf->ipf_nf_hdr_len = hdr_length;
		} else {
			/* Hard case, hole at the beginning. */
			ipf->ipf_tail_mp = NULL;
			/*
			 * ipf_end == 0 means that we have given up
			 * on easy reassembly.
			 */
			ipf->ipf_end = 0;

			/* Forget checksum offload from now on */
			ipf->ipf_checksum_flags = 0;

			/*
			 * ipf_hole_cnt is set by ip_reassemble.
			 * ipf_count is updated by ip_reassemble.
			 * No need to check for return value here
			 * as we don't expect reassembly to complete
			 * or fail for the first fragment itself.
			 */
			(void) ip_reassemble(mp, ipf,
			    (frag_offset_flags & IPH_OFFSET) << 3,
			    (frag_offset_flags & IPH_MF), ill, msg_len);
		}
		/* Update per ipfb and ill byte counts */
		ipfb->ipfb_count += ipf->ipf_count;
		ASSERT(ipfb->ipfb_count > 0);	/* Wraparound */
		atomic_add_32(&ill->ill_frag_count, ipf->ipf_count);
		/* If the frag timer wasn't already going, start it. */
		mutex_enter(&ill->ill_lock);
		ill_frag_timer_start(ill);
		mutex_exit(&ill->ill_lock);
		goto reass_done;
	}

	/*
	 * If the packet's flag has changed (it could be coming up
	 * from an interface different than the previous, therefore
	 * possibly different checksum capability), then forget about
	 * any stored checksum states.  Otherwise add the value to
	 * the existing one stored in the fragment header.
	 */
	if (sum_flags != 0 && sum_flags == ipf->ipf_checksum_flags) {
		sum_val += ipf->ipf_checksum;
		sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
		sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
		ipf->ipf_checksum = sum_val;
	} else if (ipf->ipf_checksum_flags != 0) {
		/* Forget checksum offload from now on */
		ipf->ipf_checksum_flags = 0;
	}

	/*
	 * We have a new piece of a datagram which is already being
	 * reassembled.  Update the ECN info if all IP fragments
	 * are ECN capable.  If there is one which is not, clear
	 * all the info.  If there is at least one which has CE
	 * code point, IP needs to report that up to transport.
	 */
	if (ecn_info != IPH_ECN_NECT && ipf->ipf_ecn != IPH_ECN_NECT) {
		if (ecn_info == IPH_ECN_CE)
			ipf->ipf_ecn = IPH_ECN_CE;
	} else {
		ipf->ipf_ecn = IPH_ECN_NECT;
	}
	if (offset && ipf->ipf_end == offset) {
		/* The new fragment fits at the end */
		ipf->ipf_tail_mp->b_cont = mp;
		/* Update the byte count */
		ipf->ipf_count += msg_len;
		/* Update per ipfb and ill byte counts */
		ipfb->ipfb_count += msg_len;
		ASSERT(ipfb->ipfb_count > 0);	/* Wraparound */
		atomic_add_32(&ill->ill_frag_count, msg_len);
		if (frag_offset_flags & IPH_MF) {
			/* More to come. */
			ipf->ipf_end = end;
			ipf->ipf_tail_mp = tail_mp;
			goto reass_done;
		}
	} else {
		/* Go do the hard cases. */
		int ret;

		if (offset == 0)
			ipf->ipf_nf_hdr_len = hdr_length;

		/* Save current byte count */
		count = ipf->ipf_count;
		ret = ip_reassemble(mp, ipf,
		    (frag_offset_flags & IPH_OFFSET) << 3,
		    (frag_offset_flags & IPH_MF), ill, msg_len);
		/* Count of bytes added and subtracted (freeb()ed) */
		count = ipf->ipf_count - count;
		if (count) {
			/* Update per ipfb and ill byte counts */
			ipfb->ipfb_count += count;
			ASSERT(ipfb->ipfb_count > 0); /* Wraparound */
			atomic_add_32(&ill->ill_frag_count, count);
		}
		if (ret == IP_REASS_PARTIAL) {
			goto reass_done;
		} else if (ret == IP_REASS_FAILED) {
			/* Reassembly failed. Free up all resources */
			ill_frag_free_pkts(ill, ipfb, ipf, 1);
			for (t_mp = mp; t_mp != NULL; t_mp = t_mp->b_cont) {
				IP_REASS_SET_START(t_mp, 0);
				IP_REASS_SET_END(t_mp, 0);
			}
			freemsg(mp);
			goto reass_done;
		}
		/* We will reach here iff 'ret' is IP_REASS_COMPLETE */
	}
	/*
	 * We have completed reassembly.  Unhook the frag header from
	 * the reassembly list.
	 *
	 * Before we free the frag header, record the ECN info
	 * to report back to the transport.
	 */
	ecn_info = ipf->ipf_ecn;
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmOKs);
	ipfp = ipf->ipf_ptphn;

	/* We need to supply these to caller */
	if ((sum_flags = ipf->ipf_checksum_flags) != 0)
		sum_val = ipf->ipf_checksum;
	else
		sum_val = 0;

	mp1 = ipf->ipf_mp;
	count = ipf->ipf_count;
	ipf = ipf->ipf_hash_next;
	if (ipf != NULL)
		ipf->ipf_ptphn = ipfp;
	ipfp[0] = ipf;
	atomic_add_32(&ill->ill_frag_count, -count);
	ASSERT(ipfb->ipfb_count >= count);
	ipfb->ipfb_count -= count;
	ipfb->ipfb_frag_pkts--;
	mutex_exit(&ipfb->ipfb_lock);
	/* Ditch the frag header. */
	mp = mp1->b_cont;

	freeb(mp1);

	/* Restore original IP length in header. */
	packet_size = (uint32_t)msgdsize(mp);
	if (packet_size > IP_MAXPACKET) {
		freemsg(mp);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		return (B_FALSE);
	}

	if (DB_REF(mp) > 1) {
		mblk_t *mp2 = copymsg(mp);

		freemsg(mp);
		if (mp2 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return (B_FALSE);
		}
		mp = mp2;
	}
	ipha = (ipha_t *)mp->b_rptr;

	ipha->ipha_length = htons((uint16_t)packet_size);
	/* We're now complete, zip the frag state */
	ipha->ipha_fragment_offset_and_flags = 0;
	/* Record the ECN info. */
	ipha->ipha_type_of_service &= 0xFC;
	ipha->ipha_type_of_service |= ecn_info;
	*mpp = mp;

	/* Reassembly is successful; return checksum information if needed */
	if (cksum_val != NULL)
		*cksum_val = sum_val;
	if (cksum_flags != NULL)
		*cksum_flags = sum_flags;

	return (B_TRUE);
}

/*
 * Perform ip header check sum update local options.
 * return B_TRUE if all is well, else return B_FALSE and release
 * the mp. caller is responsible for decrementing ire ref cnt.
 */
static boolean_t
ip_options_cksum(queue_t *q, ill_t *ill, mblk_t *mp, ipha_t *ipha, ire_t *ire,
    ip_stack_t *ipst)
{
	mblk_t		*first_mp;
	boolean_t	mctl_present;
	uint16_t	sum;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);
	/*
	 * Don't do the checksum if it has gone through AH/ESP
	 * processing.
	 */
	if (!mctl_present) {
		sum = ip_csum_hdr(ipha);
		if (sum != 0) {
			if (ill != NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
			} else {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsInCksumErrs);
			}
			freemsg(first_mp);
			return (B_FALSE);
		}
	}

	if (!ip_rput_local_options(q, mp, ipha, ire, ipst)) {
		if (mctl_present)
			freeb(first_mp);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * All udp packet are delivered to the local host via this routine.
 */
void
ip_udp_input(queue_t *q, mblk_t *mp, ipha_t *ipha, ire_t *ire,
    ill_t *recv_ill)
{
	uint32_t	sum;
	uint32_t	u1;
	boolean_t	mctl_present;
	conn_t		*connp;
	mblk_t		*first_mp;
	uint16_t	*up;
	ill_t		*ill = (ill_t *)q->q_ptr;
	uint16_t	reass_hck_flags = 0;
	ip_stack_t	*ipst;

	ASSERT(recv_ill != NULL);
	ipst = recv_ill->ill_ipst;

#define	rptr    ((uchar_t *)ipha)

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);
	ASSERT(!mctl_present || ipsec_in_is_secure(first_mp));
	ASSERT(ipha->ipha_protocol == IPPROTO_UDP);
	ASSERT(ill != NULL);

	/*
	 * FAST PATH for udp packets
	 */

	/* u1 is # words of IP options */
	u1 = ipha->ipha_version_and_hdr_length - (uchar_t)((IP_VERSION << 4) +
	    IP_SIMPLE_HDR_LENGTH_IN_WORDS);

	/* IP options present */
	if (u1 != 0)
		goto ipoptions;

	/* Check the IP header checksum.  */
	if (IS_IP_HDR_HWCKSUM(mctl_present, mp, ill)) {
		/* Clear the IP header h/w cksum flag */
		DB_CKSUMFLAGS(mp) &= ~HCK_IPV4_HDRCKSUM;
	} else if (!mctl_present) {
		/*
		 * Don't verify header checksum if this packet is coming
		 * back from AH/ESP as we already did it.
		 */
#define	uph	((uint16_t *)ipha)
		sum = uph[0] + uph[1] + uph[2] + uph[3] + uph[4] + uph[5] +
		    uph[6] + uph[7] + uph[8] + uph[9];
#undef	uph
		/* finish doing IP checksum */
		sum = (sum & 0xFFFF) + (sum >> 16);
		sum = ~(sum + (sum >> 16)) & 0xFFFF;
		if (sum != 0 && sum != 0xFFFF) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
			freemsg(first_mp);
			return;
		}
	}

	/*
	 * Count for SNMP of inbound packets for ire.
	 * if mctl is present this might be a secure packet and
	 * has already been counted for in ip_proto_input().
	 */
	if (!mctl_present) {
		UPDATE_IB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
	}

	/* packet part of fragmented IP packet? */
	u1 = ntohs(ipha->ipha_fragment_offset_and_flags);
	if (u1 & (IPH_MF | IPH_OFFSET)) {
		goto fragmented;
	}

	/* u1 = IP header length (20 bytes) */
	u1 = IP_SIMPLE_HDR_LENGTH;

	/* packet does not contain complete IP & UDP headers */
	if ((mp->b_wptr - rptr) < (IP_SIMPLE_HDR_LENGTH + UDPH_SIZE))
		goto udppullup;

	/* up points to UDP header */
	up = (uint16_t *)((uchar_t *)ipha + IP_SIMPLE_HDR_LENGTH);
#define	iphs    ((uint16_t *)ipha)

	/* if udp hdr cksum != 0, then need to checksum udp packet */
	if (up[3] != 0) {
		mblk_t *mp1 = mp->b_cont;
		boolean_t cksum_err;
		uint16_t hck_flags = 0;

		/* Pseudo-header checksum */
		u1 = IP_UDP_CSUM_COMP + iphs[6] + iphs[7] + iphs[8] +
		    iphs[9] + up[2];

		/*
		 * Revert to software checksum calculation if the interface
		 * isn't capable of checksum offload or if IPsec is present.
		 */
		if (ILL_HCKSUM_CAPABLE(ill) && !mctl_present && dohwcksum)
			hck_flags = DB_CKSUMFLAGS(mp);

		if ((hck_flags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) == 0)
			IP_STAT(ipst, ip_in_sw_cksum);

		IP_CKSUM_RECV(hck_flags, u1,
		    (uchar_t *)(rptr + DB_CKSUMSTART(mp)),
		    (int32_t)((uchar_t *)up - rptr),
		    mp, mp1, cksum_err);

		if (cksum_err) {
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsInCksumErrs);
			if (hck_flags & HCK_FULLCKSUM)
				IP_STAT(ipst, ip_udp_in_full_hw_cksum_err);
			else if (hck_flags & HCK_PARTIALCKSUM)
				IP_STAT(ipst, ip_udp_in_part_hw_cksum_err);
			else
				IP_STAT(ipst, ip_udp_in_sw_cksum_err);

			freemsg(first_mp);
			return;
		}
	}

	/* Non-fragmented broadcast or multicast packet? */
	if (ire->ire_type == IRE_BROADCAST)
		goto udpslowpath;

	if ((connp = ipcl_classify_v4(mp, IPPROTO_UDP, IP_SIMPLE_HDR_LENGTH,
	    ire->ire_zoneid, ipst)) != NULL) {
		ASSERT(connp->conn_upq != NULL);
		IP_STAT(ipst, ip_udp_fast_path);

		if (CONN_UDP_FLOWCTLD(connp)) {
			freemsg(mp);
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsInOverflows);
		} else {
			if (!mctl_present) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsHCInDelivers);
			}
			/*
			 * mp and first_mp can change.
			 */
			if (ip_udp_check(q, connp, recv_ill,
			    ipha, &mp, &first_mp, mctl_present, ire)) {
				/* Send it upstream */
				(connp->conn_recv)(connp, mp, NULL);
			}
		}
		/*
		 * freeb() cannot deal with null mblk being passed
		 * in and first_mp can be set to null in the call
		 * ipsec_input_fast_proc()->ipsec_check_inbound_policy.
		 */
		if (mctl_present && first_mp != NULL) {
			freeb(first_mp);
		}
		CONN_DEC_REF(connp);
		return;
	}

	/*
	 * if we got here we know the packet is not fragmented and
	 * has no options. The classifier could not find a conn_t and
	 * most likely its an icmp packet so send it through slow path.
	 */

	goto udpslowpath;

ipoptions:
	if (!ip_options_cksum(q, ill, mp, ipha, ire, ipst)) {
		goto slow_done;
	}

	UPDATE_IB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;
	u1 = ntohs(ipha->ipha_fragment_offset_and_flags);
	if (u1 & (IPH_MF | IPH_OFFSET)) {
fragmented:
		/*
		 * "sum" and "reass_hck_flags" are non-zero if the
		 * reassembled packet has a valid hardware computed
		 * checksum information associated with it.
		 */
		if (!ip_rput_fragment(q, &mp, ipha, &sum, &reass_hck_flags))
			goto slow_done;
		/*
		 * Make sure that first_mp points back to mp as
		 * the mp we came in with could have changed in
		 * ip_rput_fragment().
		 */
		ASSERT(!mctl_present);
		ipha = (ipha_t *)mp->b_rptr;
		first_mp = mp;
	}

	/* Now we have a complete datagram, destined for this machine. */
	u1 = IPH_HDR_LENGTH(ipha);
	/* Pull up the UDP header, if necessary. */
	if ((MBLKL(mp)) < (u1 + UDPH_SIZE)) {
udppullup:
		if (!pullupmsg(mp, u1 + UDPH_SIZE)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
			goto slow_done;
		}
		ipha = (ipha_t *)mp->b_rptr;
	}

	/*
	 * Validate the checksum for the reassembled packet; for the
	 * pullup case we calculate the payload checksum in software.
	 */
	up = (uint16_t *)((uchar_t *)ipha + u1 + UDP_PORTS_OFFSET);
	if (up[3] != 0) {
		boolean_t cksum_err;

		if ((reass_hck_flags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) == 0)
			IP_STAT(ipst, ip_in_sw_cksum);

		IP_CKSUM_RECV_REASS(reass_hck_flags,
		    (int32_t)((uchar_t *)up - (uchar_t *)ipha),
		    IP_UDP_CSUM_COMP + iphs[6] + iphs[7] + iphs[8] +
		    iphs[9] + up[2], sum, cksum_err);

		if (cksum_err) {
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsInCksumErrs);

			if (reass_hck_flags & HCK_FULLCKSUM)
				IP_STAT(ipst, ip_udp_in_full_hw_cksum_err);
			else if (reass_hck_flags & HCK_PARTIALCKSUM)
				IP_STAT(ipst, ip_udp_in_part_hw_cksum_err);
			else
				IP_STAT(ipst, ip_udp_in_sw_cksum_err);

			freemsg(first_mp);
			goto slow_done;
		}
	}
udpslowpath:

	/* Clear hardware checksum flag to be safe */
	DB_CKSUMFLAGS(mp) = 0;

	ip_fanout_udp(q, first_mp, ill, ipha, *(uint32_t *)up,
	    (ire->ire_type == IRE_BROADCAST),
	    IP_FF_SEND_ICMP | IP_FF_CKSUM | IP_FF_IPINFO,
	    mctl_present, B_TRUE, recv_ill, ire->ire_zoneid);

slow_done:
	IP_STAT(ipst, ip_udp_slow_path);
	return;

#undef  iphs
#undef  rptr
}

/* ARGSUSED */
static mblk_t *
ip_tcp_input(mblk_t *mp, ipha_t *ipha, ill_t *recv_ill, boolean_t mctl_present,
    ire_t *ire, mblk_t *first_mp, uint_t flags, queue_t *q,
    ill_rx_ring_t *ill_ring)
{
	conn_t		*connp;
	uint32_t	sum;
	uint32_t	u1;
	uint16_t	*up;
	int		offset;
	ssize_t		len;
	mblk_t		*mp1;
	boolean_t	syn_present = B_FALSE;
	tcph_t		*tcph;
	uint_t		tcph_flags;
	uint_t		ip_hdr_len;
	ill_t		*ill = (ill_t *)q->q_ptr;
	zoneid_t	zoneid = ire->ire_zoneid;
	boolean_t	cksum_err;
	uint16_t	hck_flags = 0;
	ip_stack_t	*ipst = recv_ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

#define	rptr	((uchar_t *)ipha)

	ASSERT(ipha->ipha_protocol == IPPROTO_TCP);
	ASSERT(ill != NULL);

	/*
	 * FAST PATH for tcp packets
	 */

	/* u1 is # words of IP options */
	u1 = ipha->ipha_version_and_hdr_length - (uchar_t)((IP_VERSION << 4)
	    + IP_SIMPLE_HDR_LENGTH_IN_WORDS);

	/* IP options present */
	if (u1) {
		goto ipoptions;
	} else if (!mctl_present) {
		/* Check the IP header checksum.  */
		if (IS_IP_HDR_HWCKSUM(mctl_present, mp, ill)) {
			/* Clear the IP header h/w cksum flag */
			DB_CKSUMFLAGS(mp) &= ~HCK_IPV4_HDRCKSUM;
		} else if (!mctl_present) {
			/*
			 * Don't verify header checksum if this packet
			 * is coming back from AH/ESP as we already did it.
			 */
#define	uph	((uint16_t *)ipha)
			sum = uph[0] + uph[1] + uph[2] + uph[3] + uph[4] +
			    uph[5] + uph[6] + uph[7] + uph[8] + uph[9];
#undef	uph
			/* finish doing IP checksum */
			sum = (sum & 0xFFFF) + (sum >> 16);
			sum = ~(sum + (sum >> 16)) & 0xFFFF;
			if (sum != 0 && sum != 0xFFFF) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInCksumErrs);
				goto error;
			}
		}
	}

	if (!mctl_present) {
		UPDATE_IB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
	}

	/* packet part of fragmented IP packet? */
	u1 = ntohs(ipha->ipha_fragment_offset_and_flags);
	if (u1 & (IPH_MF | IPH_OFFSET)) {
		goto fragmented;
	}

	/* u1 = IP header length (20 bytes) */
	u1 = ip_hdr_len = IP_SIMPLE_HDR_LENGTH;

	/* does packet contain IP+TCP headers? */
	len = mp->b_wptr - rptr;
	if (len < (IP_SIMPLE_HDR_LENGTH + TCP_MIN_HEADER_LENGTH)) {
		IP_STAT(ipst, ip_tcppullup);
		goto tcppullup;
	}

	/* TCP options present? */
	offset = ((uchar_t *)ipha)[IP_SIMPLE_HDR_LENGTH + 12] >> 4;

	/*
	 * If options need to be pulled up, then goto tcpoptions.
	 * otherwise we are still in the fast path
	 */
	if (len < (offset << 2) + IP_SIMPLE_HDR_LENGTH) {
		IP_STAT(ipst, ip_tcpoptions);
		goto tcpoptions;
	}

	/* multiple mblks of tcp data? */
	if ((mp1 = mp->b_cont) != NULL) {
		/* more then two? */
		if (mp1->b_cont != NULL) {
			IP_STAT(ipst, ip_multipkttcp);
			goto multipkttcp;
		}
		len += mp1->b_wptr - mp1->b_rptr;
	}

	up = (uint16_t *)(rptr + IP_SIMPLE_HDR_LENGTH + TCP_PORTS_OFFSET);

	/* part of pseudo checksum */

	/* TCP datagram length */
	u1 = len - IP_SIMPLE_HDR_LENGTH;

#define	iphs    ((uint16_t *)ipha)

#ifdef	_BIG_ENDIAN
	u1 += IPPROTO_TCP;
#else
	u1 = ((u1 >> 8) & 0xFF) + (((u1 & 0xFF) + IPPROTO_TCP) << 8);
#endif
	u1 += iphs[6] + iphs[7] + iphs[8] + iphs[9];

	/*
	 * Revert to software checksum calculation if the interface
	 * isn't capable of checksum offload or if IPsec is present.
	 */
	if (ILL_HCKSUM_CAPABLE(ill) && !mctl_present && dohwcksum)
		hck_flags = DB_CKSUMFLAGS(mp);

	if ((hck_flags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) == 0)
		IP_STAT(ipst, ip_in_sw_cksum);

	IP_CKSUM_RECV(hck_flags, u1,
	    (uchar_t *)(rptr + DB_CKSUMSTART(mp)),
	    (int32_t)((uchar_t *)up - rptr),
	    mp, mp1, cksum_err);

	if (cksum_err) {
		BUMP_MIB(ill->ill_ip_mib, tcpIfStatsInErrs);

		if (hck_flags & HCK_FULLCKSUM)
			IP_STAT(ipst, ip_tcp_in_full_hw_cksum_err);
		else if (hck_flags & HCK_PARTIALCKSUM)
			IP_STAT(ipst, ip_tcp_in_part_hw_cksum_err);
		else
			IP_STAT(ipst, ip_tcp_in_sw_cksum_err);

		goto error;
	}

try_again:

	if ((connp = ipcl_classify_v4(mp, IPPROTO_TCP, ip_hdr_len,
	    zoneid, ipst)) == NULL) {
		/* Send the TH_RST */
		goto no_conn;
	}

	tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];
	tcph_flags = tcph->th_flags[0] & (TH_SYN|TH_ACK|TH_RST|TH_URG);

	/*
	 * TCP FAST PATH for AF_INET socket.
	 *
	 * TCP fast path to avoid extra work. An AF_INET socket type
	 * does not have facility to receive extra information via
	 * ip_process or ip_add_info. Also, when the connection was
	 * established, we made a check if this connection is impacted
	 * by any global IPsec policy or per connection policy (a
	 * policy that comes in effect later will not apply to this
	 * connection). Since all this can be determined at the
	 * connection establishment time, a quick check of flags
	 * can avoid extra work.
	 */
	if (IPCL_IS_TCP4_CONNECTED_NO_POLICY(connp) && !mctl_present &&
	    !IPP_ENABLED(IPP_LOCAL_IN, ipst)) {
		ASSERT(first_mp == mp);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		if (tcph_flags != (TH_SYN | TH_ACK)) {
			SET_SQUEUE(mp, tcp_rput_data, connp);
			return (mp);
		}
		mp->b_datap->db_struioflag |= STRUIO_CONNECT;
		DB_CKSUMSTART(mp) = (intptr_t)ip_squeue_get(ill_ring);
		SET_SQUEUE(mp, tcp_input, connp);
		return (mp);
	}

	if (tcph_flags == TH_SYN) {
		if (IPCL_IS_TCP(connp)) {
			mp->b_datap->db_struioflag |= STRUIO_EAGER;
			DB_CKSUMSTART(mp) =
			    (intptr_t)ip_squeue_get(ill_ring);
			if (IPCL_IS_FULLY_BOUND(connp) && !mctl_present &&
			    !CONN_INBOUND_POLICY_PRESENT(connp, ipss)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsHCInDelivers);
				SET_SQUEUE(mp, connp->conn_recv, connp);
				return (mp);
			} else if (IPCL_IS_BOUND(connp) && !mctl_present &&
			    !CONN_INBOUND_POLICY_PRESENT(connp, ipss)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsHCInDelivers);
				ip_squeue_enter_unbound++;
				SET_SQUEUE(mp, tcp_conn_request_unbound,
				    connp);
				return (mp);
			}
			syn_present = B_TRUE;
		}
	}

	if (IPCL_IS_TCP(connp) && IPCL_IS_BOUND(connp) && !syn_present) {
		uint_t	flags = (unsigned int)tcph->th_flags[0] & 0xFF;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		/* No need to send this packet to TCP */
		if ((flags & TH_RST) || (flags & TH_URG)) {
			CONN_DEC_REF(connp);
			freemsg(first_mp);
			return (NULL);
		}
		if (flags & TH_ACK) {
			tcp_xmit_listeners_reset(first_mp, ip_hdr_len, zoneid,
			    ipst->ips_netstack->netstack_tcp, connp);
			CONN_DEC_REF(connp);
			return (NULL);
		}

		CONN_DEC_REF(connp);
		freemsg(first_mp);
		return (NULL);
	}

	if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) || mctl_present) {
		first_mp = ipsec_check_inbound_policy(first_mp, connp,
		    ipha, NULL, mctl_present);
		if (first_mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			return (NULL);
		}
		if (IPCL_IS_TCP(connp) && IPCL_IS_BOUND(connp)) {
			ASSERT(syn_present);
			if (mctl_present) {
				ASSERT(first_mp != mp);
				first_mp->b_datap->db_struioflag |=
				    STRUIO_POLICY;
			} else {
				ASSERT(first_mp == mp);
				mp->b_datap->db_struioflag &= ~STRUIO_EAGER;
				mp->b_datap->db_struioflag |= STRUIO_POLICY;
			}
		} else {
			/*
			 * Discard first_mp early since we're dealing with a
			 * fully-connected conn_t and tcp doesn't do policy in
			 * this case.
			 */
			if (mctl_present) {
				freeb(first_mp);
				mctl_present = B_FALSE;
			}
			first_mp = mp;
		}
	}

	/* Initiate IPPF processing for fastpath */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst)) {
		uint32_t	ill_index;

		ill_index = recv_ill->ill_phyint->phyint_ifindex;
		ip_process(IPP_LOCAL_IN, &mp, ill_index);
		if (mp == NULL) {
			ip2dbg(("ip_input_ipsec_process: TCP pkt "
			    "deferred/dropped during IPPF processing\n"));
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return (NULL);
		} else if (mctl_present) {
			/*
			 * ip_process might return a new mp.
			 */
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}

	}

	if (!syn_present && connp->conn_ip_recvpktinfo) {
		/*
		 * TCP does not support IP_RECVPKTINFO for v4 so lets
		 * make sure IPF_RECVIF is passed to ip_add_info.
		 */
		mp = ip_add_info(mp, recv_ill, flags|IPF_RECVIF,
		    IPCL_ZONEID(connp), ipst);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return (NULL);
		} else if (mctl_present) {
			/*
			 * ip_add_info might return a new mp.
			 */
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
	if (IPCL_IS_TCP(connp)) {
		SET_SQUEUE(first_mp, connp->conn_recv, connp);
		return (first_mp);
	} else {
		/* SOCK_RAW, IPPROTO_TCP case */
		(connp->conn_recv)(connp, first_mp, NULL);
		CONN_DEC_REF(connp);
		return (NULL);
	}

no_conn:
	/* Initiate IPPf processing, if needed. */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst)) {
		uint32_t ill_index;
		ill_index = recv_ill->ill_phyint->phyint_ifindex;
		ip_process(IPP_LOCAL_IN, &first_mp, ill_index);
		if (first_mp == NULL) {
			return (NULL);
		}
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);

	tcp_xmit_listeners_reset(first_mp, IPH_HDR_LENGTH(mp->b_rptr), zoneid,
	    ipst->ips_netstack->netstack_tcp, NULL);
	return (NULL);
ipoptions:
	if (!ip_options_cksum(q, ill, first_mp, ipha, ire, ipst)) {
		goto slow_done;
	}

	UPDATE_IB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;

	u1 = ntohs(ipha->ipha_fragment_offset_and_flags);
	if (u1 & (IPH_MF | IPH_OFFSET)) {
fragmented:
		if (!ip_rput_fragment(q, &mp, ipha, NULL, NULL)) {
			if (mctl_present)
				freeb(first_mp);
			goto slow_done;
		}
		/*
		 * Make sure that first_mp points back to mp as
		 * the mp we came in with could have changed in
		 * ip_rput_fragment().
		 */
		ASSERT(!mctl_present);
		ipha = (ipha_t *)mp->b_rptr;
		first_mp = mp;
	}

	/* Now we have a complete datagram, destined for this machine. */
	u1 = ip_hdr_len = IPH_HDR_LENGTH(ipha);

	len = mp->b_wptr - mp->b_rptr;
	/* Pull up a minimal TCP header, if necessary. */
	if (len < (u1 + 20)) {
tcppullup:
		if (!pullupmsg(mp, u1 + 20)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			goto error;
		}
		ipha = (ipha_t *)mp->b_rptr;
		len = mp->b_wptr - mp->b_rptr;
	}

	/*
	 * Extract the offset field from the TCP header.  As usual, we
	 * try to help the compiler more than the reader.
	 */
	offset = ((uchar_t *)ipha)[u1 + 12] >> 4;
	if (offset != 5) {
tcpoptions:
		if (offset < 5) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			goto error;
		}
		/*
		 * There must be TCP options.
		 * Make sure we can grab them.
		 */
		offset <<= 2;
		offset += u1;
		if (len < offset) {
			if (!pullupmsg(mp, offset)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				goto error;
			}
			ipha = (ipha_t *)mp->b_rptr;
			len = mp->b_wptr - rptr;
		}
	}

	/* Get the total packet length in len, including headers. */
	if (mp->b_cont) {
multipkttcp:
		len = msgdsize(mp);
	}

	/*
	 * Check the TCP checksum by pulling together the pseudo-
	 * header checksum, and passing it to ip_csum to be added in
	 * with the TCP datagram.
	 *
	 * Since we are not using the hwcksum if available we must
	 * clear the flag. We may come here via tcppullup or tcpoptions.
	 * If either of these fails along the way the mblk is freed.
	 * If this logic ever changes and mblk is reused to say send
	 * ICMP's back, then this flag may need to be cleared in
	 * other places as well.
	 */
	DB_CKSUMFLAGS(mp) = 0;

	up = (uint16_t *)(rptr + u1 + TCP_PORTS_OFFSET);

	u1 = (uint32_t)(len - u1);	/* TCP datagram length. */
#ifdef	_BIG_ENDIAN
	u1 += IPPROTO_TCP;
#else
	u1 = ((u1 >> 8) & 0xFF) + (((u1 & 0xFF) + IPPROTO_TCP) << 8);
#endif
	u1 += iphs[6] + iphs[7] + iphs[8] + iphs[9];
	/*
	 * Not M_DATA mblk or its a dup, so do the checksum now.
	 */
	IP_STAT(ipst, ip_in_sw_cksum);
	if (IP_CSUM(mp, (int32_t)((uchar_t *)up - rptr), u1) != 0) {
		BUMP_MIB(ill->ill_ip_mib, tcpIfStatsInErrs);
		goto error;
	}

	IP_STAT(ipst, ip_tcp_slow_path);
	goto try_again;
#undef  iphs
#undef  rptr

error:
	freemsg(first_mp);
slow_done:
	return (NULL);
}

/* ARGSUSED */
static void
ip_sctp_input(mblk_t *mp, ipha_t *ipha, ill_t *recv_ill, boolean_t mctl_present,
    ire_t *ire, mblk_t *first_mp, uint_t flags, queue_t *q, ipaddr_t dst)
{
	conn_t		*connp;
	uint32_t	sum;
	uint32_t	u1;
	ssize_t		len;
	sctp_hdr_t	*sctph;
	zoneid_t	zoneid = ire->ire_zoneid;
	uint32_t	pktsum;
	uint32_t	calcsum;
	uint32_t	ports;
	in6_addr_t	map_src, map_dst;
	ill_t		*ill = (ill_t *)q->q_ptr;
	ip_stack_t	*ipst;
	sctp_stack_t	*sctps;
	boolean_t	sctp_csum_err = B_FALSE;

	ASSERT(recv_ill != NULL);
	ipst = recv_ill->ill_ipst;
	sctps = ipst->ips_netstack->netstack_sctp;

#define	rptr	((uchar_t *)ipha)

	ASSERT(ipha->ipha_protocol == IPPROTO_SCTP);
	ASSERT(ill != NULL);

	/* u1 is # words of IP options */
	u1 = ipha->ipha_version_and_hdr_length - (uchar_t)((IP_VERSION << 4)
	    + IP_SIMPLE_HDR_LENGTH_IN_WORDS);

	/* IP options present */
	if (u1 > 0) {
		goto ipoptions;
	} else {
		/* Check the IP header checksum.  */
		if (!IS_IP_HDR_HWCKSUM(mctl_present, mp, ill) &&
		    !mctl_present) {
#define	uph	((uint16_t *)ipha)
			sum = uph[0] + uph[1] + uph[2] + uph[3] + uph[4] +
			    uph[5] + uph[6] + uph[7] + uph[8] + uph[9];
#undef	uph
			/* finish doing IP checksum */
			sum = (sum & 0xFFFF) + (sum >> 16);
			sum = ~(sum + (sum >> 16)) & 0xFFFF;
			/*
			 * Don't verify header checksum if this packet
			 * is coming back from AH/ESP as we already did it.
			 */
			if (sum != 0 && sum != 0xFFFF) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
				goto error;
			}
		}
		/*
		 * Since there is no SCTP h/w cksum support yet, just
		 * clear the flag.
		 */
		DB_CKSUMFLAGS(mp) = 0;
	}

	/*
	 * Don't verify header checksum if this packet is coming
	 * back from AH/ESP as we already did it.
	 */
	if (!mctl_present) {
		UPDATE_IB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
	}

	/* packet part of fragmented IP packet? */
	u1 = ntohs(ipha->ipha_fragment_offset_and_flags);
	if (u1 & (IPH_MF | IPH_OFFSET))
		goto fragmented;

	/* u1 = IP header length (20 bytes) */
	u1 = IP_SIMPLE_HDR_LENGTH;

find_sctp_client:
	/* Pullup if we don't have the sctp common header. */
	len = MBLKL(mp);
	if (len < (u1 + SCTP_COMMON_HDR_LENGTH)) {
		if (mp->b_cont == NULL ||
		    !pullupmsg(mp, u1 + SCTP_COMMON_HDR_LENGTH)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			goto error;
		}
		ipha = (ipha_t *)mp->b_rptr;
		len = MBLKL(mp);
	}

	sctph = (sctp_hdr_t *)(rptr + u1);
#ifdef	DEBUG
	if (!skip_sctp_cksum) {
#endif
		pktsum = sctph->sh_chksum;
		sctph->sh_chksum = 0;
		calcsum = sctp_cksum(mp, u1);
		sctph->sh_chksum = pktsum;
		if (calcsum != pktsum)
			sctp_csum_err = B_TRUE;
#ifdef	DEBUG	/* skip_sctp_cksum */
	}
#endif
	/* get the ports */
	ports = *(uint32_t *)&sctph->sh_sport;

	IRE_REFRELE(ire);
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &map_dst);
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &map_src);
	if (sctp_csum_err) {
		/*
		 * No potential sctp checksum errors go to the Sun
		 * sctp stack however they might be Adler-32 summed
		 * packets a userland stack bound to a raw IP socket
		 * could reasonably use. Note though that Adler-32 is
		 * a long deprecated algorithm and customer sctp
		 * networks should eventually migrate to CRC-32 at
		 * which time this facility should be removed.
		 */
		flags |= IP_FF_SCTP_CSUM_ERR;
		goto no_conn;
	}
	if ((connp = sctp_fanout(&map_src, &map_dst, ports, zoneid, mp,
	    sctps)) == NULL) {
		/* Check for raw socket or OOTB handling */
		goto no_conn;
	}

	/* Found a client; up it goes */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
	sctp_input(connp, ipha, mp, first_mp, recv_ill, B_TRUE, mctl_present);
	return;

no_conn:
	ip_fanout_sctp_raw(first_mp, recv_ill, ipha, B_TRUE,
	    ports, mctl_present, flags, B_TRUE, zoneid);
	return;

ipoptions:
	DB_CKSUMFLAGS(mp) = 0;
	if (!ip_options_cksum(q, ill, first_mp, ipha, ire, ipst))
		goto slow_done;

	UPDATE_IB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;

	u1 = ntohs(ipha->ipha_fragment_offset_and_flags);
	if (u1 & (IPH_MF | IPH_OFFSET)) {
fragmented:
		if (!ip_rput_fragment(q, &mp, ipha, NULL, NULL))
			goto slow_done;
		/*
		 * Make sure that first_mp points back to mp as
		 * the mp we came in with could have changed in
		 * ip_rput_fragment().
		 */
		ASSERT(!mctl_present);
		ipha = (ipha_t *)mp->b_rptr;
		first_mp = mp;
	}

	/* Now we have a complete datagram, destined for this machine. */
	u1 = IPH_HDR_LENGTH(ipha);
	goto find_sctp_client;
#undef  iphs
#undef  rptr

error:
	freemsg(first_mp);
slow_done:
	IRE_REFRELE(ire);
}

#define	VER_BITS	0xF0
#define	VERSION_6	0x60

static boolean_t
ip_rput_multimblk_ipoptions(queue_t *q, ill_t *ill, mblk_t *mp, ipha_t **iphapp,
    ipaddr_t *dstp, ip_stack_t *ipst)
{
	uint_t	opt_len;
	ipha_t *ipha;
	ssize_t len;
	uint_t	pkt_len;

	ASSERT(ill != NULL);
	IP_STAT(ipst, ip_ipoptions);
	ipha = *iphapp;

#define	rptr    ((uchar_t *)ipha)
	/* Assume no IPv6 packets arrive over the IPv4 queue */
	if (IPH_HDR_VERSION(ipha) == IPV6_VERSION) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInWrongIPVersion);
		freemsg(mp);
		return (B_FALSE);
	}

	/* multiple mblk or too short */
	pkt_len = ntohs(ipha->ipha_length);

	/* Get the number of words of IP options in the IP header. */
	opt_len = ipha->ipha_version_and_hdr_length - IP_SIMPLE_HDR_VERSION;
	if (opt_len) {
		/* IP Options present!  Validate and process. */
		if (opt_len > (15 - IP_SIMPLE_HDR_LENGTH_IN_WORDS)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			goto done;
		}
		/*
		 * Recompute complete header length and make sure we
		 * have access to all of it.
		 */
		len = ((size_t)opt_len + IP_SIMPLE_HDR_LENGTH_IN_WORDS) << 2;
		if (len > (mp->b_wptr - rptr)) {
			if (len > pkt_len) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
				goto done;
			}
			if (!pullupmsg(mp, len)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				goto done;
			}
			ipha = (ipha_t *)mp->b_rptr;
		}
		/*
		 * Go off to ip_rput_options which returns the next hop
		 * destination address, which may have been affected
		 * by source routing.
		 */
		IP_STAT(ipst, ip_opt);
		if (ip_rput_options(q, mp, ipha, dstp, ipst) == -1) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return (B_FALSE);
		}
	}
	*iphapp = ipha;
	return (B_TRUE);
done:
	/* clear b_prev - used by ip_mroute_decap */
	mp->b_prev = NULL;
	freemsg(mp);
	return (B_FALSE);
#undef  rptr
}

/*
 * Deal with the fact that there is no ire for the destination.
 */
static ire_t *
ip_rput_noire(queue_t *q, mblk_t *mp, int ll_multicast, ipaddr_t dst)
{
	ipha_t	*ipha;
	ill_t	*ill;
	ire_t	*ire;
	ip_stack_t *ipst;
	enum	ire_forward_action ret_action;

	ipha = (ipha_t *)mp->b_rptr;
	ill = (ill_t *)q->q_ptr;

	ASSERT(ill != NULL);
	ipst = ill->ill_ipst;

	/*
	 * No IRE for this destination, so it can't be for us.
	 * Unless we are forwarding, drop the packet.
	 * We have to let source routed packets through
	 * since we don't yet know if they are 'ping -l'
	 * packets i.e. if they will go out over the
	 * same interface as they came in on.
	 */
	if (ll_multicast) {
		freemsg(mp);
		return (NULL);
	}
	if (!(ill->ill_flags & ILLF_ROUTER) && !ip_source_routed(ipha, ipst)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		freemsg(mp);
		return (NULL);
	}

	/*
	 * Mark this packet as having originated externally.
	 *
	 * For non-forwarding code path, ire_send later double
	 * checks this interface to see if it is still exists
	 * post-ARP resolution.
	 *
	 * Also, IPQOS uses this to differentiate between
	 * IPP_FWD_OUT and IPP_LOCAL_OUT for post-ARP
	 * QOS packet processing in ip_wput_attach_llhdr().
	 * The QoS module can mark the b_band for a fastpath message
	 * or the dl_priority field in a unitdata_req header for
	 * CoS marking. This info can only be found in
	 * ip_wput_attach_llhdr().
	 */
	mp->b_prev = (mblk_t *)(uintptr_t)ill->ill_phyint->phyint_ifindex;
	/*
	 * Clear the indication that this may have a hardware checksum
	 * as we are not using it
	 */
	DB_CKSUMFLAGS(mp) = 0;

	ire = ire_forward(dst, &ret_action, NULL, NULL,
	    MBLK_GETLABEL(mp), ipst);

	if (ire == NULL && ret_action == Forward_check_multirt) {
		/* Let ip_newroute handle CGTP  */
		ip_newroute(q, mp, dst, NULL, GLOBAL_ZONEID, ipst);
		return (NULL);
	}

	if (ire != NULL)
		return (ire);

	mp->b_prev = mp->b_next = 0;

	if (ret_action == Forward_blackhole) {
		freemsg(mp);
		return (NULL);
	}
	/* send icmp unreachable */
	q = WR(q);
	/* Sent by forwarding path, and router is global zone */
	if (ip_source_routed(ipha, ipst)) {
		icmp_unreachable(q, mp, ICMP_SOURCE_ROUTE_FAILED,
		    GLOBAL_ZONEID, ipst);
	} else {
		icmp_unreachable(q, mp, ICMP_HOST_UNREACHABLE, GLOBAL_ZONEID,
		    ipst);
	}

	return (NULL);

}

/*
 * check ip header length and align it.
 */
static boolean_t
ip_check_and_align_header(queue_t *q, mblk_t *mp, ip_stack_t *ipst)
{
	ssize_t len;
	ill_t *ill;
	ipha_t	*ipha;

	len = MBLKL(mp);

	if (!OK_32PTR(mp->b_rptr) || len < IP_SIMPLE_HDR_LENGTH) {
		ill = (ill_t *)q->q_ptr;

		if (!OK_32PTR(mp->b_rptr))
			IP_STAT(ipst, ip_notaligned1);
		else
			IP_STAT(ipst, ip_notaligned2);
		/* Guard against bogus device drivers */
		if (len < 0) {
			/* clear b_prev - used by ip_mroute_decap */
			mp->b_prev = NULL;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			freemsg(mp);
			return (B_FALSE);
		}

		if (ip_rput_pullups++ == 0) {
			ipha = (ipha_t *)mp->b_rptr;
			(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
			    "ip_check_and_align_header: %s forced us to "
			    " pullup pkt, hdr len %ld, hdr addr %p",
			    ill->ill_name, len, (void *)ipha);
		}
		if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
			/* clear b_prev - used by ip_mroute_decap */
			mp->b_prev = NULL;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(mp);
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

ire_t *
ip_check_multihome(void *addr, ire_t *ire, ill_t *ill)
{
	ire_t		*new_ire;
	ill_t		*ire_ill;
	uint_t		ifindex;
	ip_stack_t	*ipst = ill->ill_ipst;
	boolean_t	strict_check = B_FALSE;

	/*
	 * This packet came in on an interface other than the one associated
	 * with the first ire we found for the destination address. We do
	 * another ire lookup here, using the ingress ill, to see if the
	 * interface is in an interface group.
	 * As long as the ills belong to the same group, we don't consider
	 * them to be arriving on the wrong interface. Thus, if the switch
	 * is doing inbound load spreading, we won't drop packets when the
	 * ip*_strict_dst_multihoming switch is on. Note, the same holds true
	 * for 'usesrc groups' where the destination address may belong to
	 * another interface to allow multipathing to happen.
	 * We also need to check for IPIF_UNNUMBERED point2point interfaces
	 * where the local address may not be unique. In this case we were
	 * at the mercy of the initial ire cache lookup and the IRE_LOCAL it
	 * actually returned. The new lookup, which is more specific, should
	 * only find the IRE_LOCAL associated with the ingress ill if one
	 * exists.
	 */

	if (ire->ire_ipversion == IPV4_VERSION) {
		if (ipst->ips_ip_strict_dst_multihoming)
			strict_check = B_TRUE;
		new_ire = ire_ctable_lookup(*((ipaddr_t *)addr), 0, IRE_LOCAL,
		    ill->ill_ipif, ALL_ZONES, NULL,
		    (MATCH_IRE_TYPE|MATCH_IRE_ILL_GROUP), ipst);
	} else {
		ASSERT(!IN6_IS_ADDR_MULTICAST((in6_addr_t *)addr));
		if (ipst->ips_ipv6_strict_dst_multihoming)
			strict_check = B_TRUE;
		new_ire = ire_ctable_lookup_v6((in6_addr_t *)addr, NULL,
		    IRE_LOCAL, ill->ill_ipif, ALL_ZONES, NULL,
		    (MATCH_IRE_TYPE|MATCH_IRE_ILL_GROUP), ipst);
	}
	/*
	 * If the same ire that was returned in ip_input() is found then this
	 * is an indication that interface groups are in use. The packet
	 * arrived on a different ill in the group than the one associated with
	 * the destination address.  If a different ire was found then the same
	 * IP address must be hosted on multiple ills. This is possible with
	 * unnumbered point2point interfaces. We switch to use this new ire in
	 * order to have accurate interface statistics.
	 */
	if (new_ire != NULL) {
		if ((new_ire != ire) && (new_ire->ire_rfq != NULL)) {
			ire_refrele(ire);
			ire = new_ire;
		} else {
			ire_refrele(new_ire);
		}
		return (ire);
	} else if ((ire->ire_rfq == NULL) &&
	    (ire->ire_ipversion == IPV4_VERSION)) {
		/*
		 * The best match could have been the original ire which
		 * was created against an IRE_LOCAL on lo0. In the IPv4 case
		 * the strict multihoming checks are irrelevant as we consider
		 * local addresses hosted on lo0 to be interface agnostic. We
		 * only expect a null ire_rfq on IREs which are associated with
		 * lo0 hence we can return now.
		 */
		return (ire);
	}

	/*
	 * Chase pointers once and store locally.
	 */
	ire_ill = (ire->ire_rfq == NULL) ? NULL :
	    (ill_t *)(ire->ire_rfq->q_ptr);
	ifindex = ill->ill_usesrc_ifindex;

	/*
	 * Check if it's a legal address on the 'usesrc' interface.
	 */
	if ((ifindex != 0) && (ire_ill != NULL) &&
	    (ifindex == ire_ill->ill_phyint->phyint_ifindex)) {
		return (ire);
	}

	/*
	 * If the ip*_strict_dst_multihoming switch is on then we can
	 * only accept this packet if the interface is marked as routing.
	 */
	if (!(strict_check))
		return (ire);

	if ((ill->ill_flags & ire->ire_ipif->ipif_ill->ill_flags &
	    ILLF_ROUTER) != 0) {
		return (ire);
	}

	ire_refrele(ire);
	return (NULL);
}

/*
 *
 * This is the fast forward path. If we are here, we dont need to
 * worry about RSVP, CGTP, or TSol. Furthermore the ftable lookup
 * needed to find the nexthop in this case is much simpler
 */
ire_t *
ip_fast_forward(ire_t *ire, ipaddr_t dst,  ill_t *ill, mblk_t *mp)
{
	ipha_t	*ipha;
	ire_t	*src_ire;
	ill_t	*stq_ill;
	uint_t	hlen;
	uint_t	pkt_len;
	uint32_t sum;
	queue_t	*dev_q;
	ip_stack_t *ipst = ill->ill_ipst;
	mblk_t *fpmp;
	enum	ire_forward_action ret_action;

	ipha = (ipha_t *)mp->b_rptr;

	if (ire != NULL &&
	    ire->ire_zoneid != GLOBAL_ZONEID &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * Should only use IREs that are visible to the global
		 * zone for forwarding.
		 */
		ire_refrele(ire);
		ire = ire_cache_lookup(dst, GLOBAL_ZONEID, NULL, ipst);
		/*
		 * ire_cache_lookup() can return ire of IRE_LOCAL in
		 * transient cases. In such case, just drop the packet
		 */
		if (ire->ire_type != IRE_CACHE)
			goto drop;
	}

	/*
	 * Martian Address Filtering [RFC 1812, Section 5.3.7]
	 * The loopback address check for both src and dst has already
	 * been checked in ip_input
	 */

	if (dst == INADDR_ANY || CLASSD(ipha->ipha_src)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		goto drop;
	}
	src_ire = ire_ctable_lookup(ipha->ipha_src, 0, IRE_BROADCAST, NULL,
	    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);

	if (src_ire != NULL) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ire_refrele(src_ire);
		goto drop;
	}

	/* No ire cache of nexthop. So first create one  */
	if (ire == NULL) {

		ire = ire_forward_simple(dst, &ret_action, ipst);

		/*
		 * We only come to ip_fast_forward if ip_cgtp_filter
		 * is not set. So ire_forward() should not return with
		 * Forward_check_multirt as the next action.
		 */
		ASSERT(ret_action != Forward_check_multirt);
		if (ire == NULL) {
			/* An attempt was made to forward the packet */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInForwDatagrams);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			mp->b_prev = mp->b_next = 0;
			/* send icmp unreachable */
			/* Sent by forwarding path, and router is global zone */
			if (ret_action == Forward_ret_icmp_err) {
				if (ip_source_routed(ipha, ipst)) {
					icmp_unreachable(ill->ill_wq, mp,
					    ICMP_SOURCE_ROUTE_FAILED,
					    GLOBAL_ZONEID, ipst);
				} else {
					icmp_unreachable(ill->ill_wq, mp,
					    ICMP_HOST_UNREACHABLE,
					    GLOBAL_ZONEID, ipst);
				}
			} else {
				freemsg(mp);
			}
			return (NULL);
		}
	}

	/*
	 * Forwarding fastpath exception case:
	 * If either of the follwoing case is true, we take
	 * the slowpath
	 *	o forwarding is not enabled
	 *	o incoming and outgoing interface are the same, or the same
	 *	  IPMP group
	 *	o corresponding ire is in incomplete state
	 *	o packet needs fragmentation
	 *	o ARP cache is not resolved
	 *
	 * The codeflow from here on is thus:
	 *	ip_rput_process_forward->ip_rput_forward->ip_xmit_v4
	 */
	pkt_len = ntohs(ipha->ipha_length);
	stq_ill = (ill_t *)ire->ire_stq->q_ptr;
	if (!(stq_ill->ill_flags & ILLF_ROUTER) ||
	    (ill == stq_ill) ||
	    (ill->ill_group != NULL && ill->ill_group == stq_ill->ill_group) ||
	    (ire->ire_nce == NULL) ||
	    (pkt_len > ire->ire_max_frag) ||
	    ((fpmp = ire->ire_nce->nce_fp_mp) == NULL) ||
	    ((hlen = MBLKL(fpmp)) > MBLKHEAD(mp)) ||
	    ipha->ipha_ttl <= 1) {
		ip_rput_process_forward(ill->ill_rq, mp, ire,
		    ipha, ill, B_FALSE, B_TRUE);
		return (ire);
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInForwDatagrams);

	DTRACE_PROBE4(ip4__forwarding__start,
	    ill_t *, ill, ill_t *, stq_ill, ipha_t *, ipha, mblk_t *, mp);

	FW_HOOKS(ipst->ips_ip4_forwarding_event,
	    ipst->ips_ipv4firewall_forwarding,
	    ill, stq_ill, ipha, mp, mp, 0, ipst);

	DTRACE_PROBE1(ip4__forwarding__end, mblk_t *, mp);

	if (mp == NULL)
		goto drop;

	mp->b_datap->db_struioun.cksum.flags = 0;
	/* Adjust the checksum to reflect the ttl decrement. */
	sum = (int)ipha->ipha_hdr_checksum + IP_HDR_CSUM_TTL_ADJUST;
	ipha->ipha_hdr_checksum = (uint16_t)(sum + (sum >> 16));
	ipha->ipha_ttl--;

	/*
	 * Write the link layer header.  We can do this safely here,
	 * because we have already tested to make sure that the IP
	 * policy is not set, and that we have a fast path destination
	 * header.
	 */
	mp->b_rptr -= hlen;
	bcopy(fpmp->b_rptr, mp->b_rptr, hlen);

	UPDATE_IB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;
	BUMP_MIB(stq_ill->ill_ip_mib, ipIfStatsHCOutForwDatagrams);
	BUMP_MIB(stq_ill->ill_ip_mib, ipIfStatsHCOutTransmits);
	UPDATE_MIB(stq_ill->ill_ip_mib, ipIfStatsHCOutOctets, pkt_len);

	if (!ILL_DIRECT_CAPABLE(stq_ill) || DB_TYPE(mp) != M_DATA) {
		dev_q = ire->ire_stq->q_next;
		if (DEV_Q_FLOW_BLOCKED(dev_q))
			goto indiscard;
	}

	DTRACE_PROBE4(ip4__physical__out__start,
	    ill_t *, NULL, ill_t *, stq_ill, ipha_t *, ipha, mblk_t *, mp);
	FW_HOOKS(ipst->ips_ip4_physical_out_event,
	    ipst->ips_ipv4firewall_physical_out,
	    NULL, stq_ill, ipha, mp, mp, 0, ipst);
	DTRACE_PROBE1(ip4__physical__out__end, mblk_t *, mp);
	DTRACE_IP7(send, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
	    ipha, __dtrace_ipsr_ill_t *, stq_ill, ipha_t *, ipha,
	    ip6_t *, NULL, int, 0);

	if (mp != NULL) {
		if (ipst->ips_ipobs_enabled) {
			zoneid_t szone;

			szone = ip_get_zoneid_v4(ipha->ipha_src, mp,
			    ipst, ALL_ZONES);
			ipobs_hook(mp, IPOBS_HOOK_OUTBOUND, szone,
			    ALL_ZONES, ill, IPV4_VERSION, hlen, ipst);
		}

		ILL_SEND_TX(stq_ill, ire, dst, mp, IP_DROP_ON_NO_DESC);
	}
	return (ire);

indiscard:
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
drop:
	if (mp != NULL)
		freemsg(mp);
	return (ire);

}

/*
 * This function is called in the forwarding slowpath, when
 * either the ire lacks the link-layer address, or the packet needs
 * further processing(eg. fragmentation), before transmission.
 */

static void
ip_rput_process_forward(queue_t *q, mblk_t *mp, ire_t *ire, ipha_t *ipha,
    ill_t *ill, boolean_t ll_multicast, boolean_t from_ip_fast_forward)
{
	ill_group_t	*ill_group;
	ill_group_t	*ire_group;
	queue_t		*dev_q;
	ire_t		*src_ire;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ire->ire_stq != NULL);

	mp->b_prev = NULL; /* ip_rput_noire sets incoming interface here */
	mp->b_next = NULL; /* ip_rput_noire sets dst here */

	/*
	 * If the caller of this function is ip_fast_forward() skip the
	 * next three checks as it does not apply.
	 */
	if (from_ip_fast_forward) {
		ill_group = ill->ill_group;
		ire_group = ((ill_t *)(ire->ire_rfq)->q_ptr)->ill_group;
		goto skip;
	}

	if (ll_multicast != 0) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		goto drop_pkt;
	}

	/*
	 * check if ipha_src is a broadcast address. Note that this
	 * check is redundant when we get here from ip_fast_forward()
	 * which has already done this check. However, since we can
	 * also get here from ip_rput_process_broadcast() or, for
	 * for the slow path through ip_fast_forward(), we perform
	 * the check again for code-reusability
	 */
	src_ire = ire_ctable_lookup(ipha->ipha_src, 0, IRE_BROADCAST, NULL,
	    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	if (src_ire != NULL || ipha->ipha_dst == INADDR_ANY) {
		if (src_ire != NULL)
			ire_refrele(src_ire);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip2dbg(("ip_rput_process_forward: Received packet with"
		    " bad src/dst address on %s\n", ill->ill_name));
		goto drop_pkt;
	}

	ill_group = ill->ill_group;
	ire_group = ((ill_t *)(ire->ire_rfq)->q_ptr)->ill_group;
	/*
	 * Check if we want to forward this one at this time.
	 * We allow source routed packets on a host provided that
	 * they go out the same interface or same interface group
	 * as they came in on.
	 *
	 * XXX To be quicker, we may wish to not chase pointers to
	 * get the ILLF_ROUTER flag and instead store the
	 * forwarding policy in the ire.  An unfortunate
	 * side-effect of that would be requiring an ire flush
	 * whenever the ILLF_ROUTER flag changes.
	 */
skip:
	if (((ill->ill_flags &
	    ((ill_t *)ire->ire_stq->q_ptr)->ill_flags &
	    ILLF_ROUTER) == 0) &&
	    !(ip_source_routed(ipha, ipst) && (ire->ire_rfq == q ||
	    (ill_group != NULL && ill_group == ire_group)))) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		if (ip_source_routed(ipha, ipst)) {
			q = WR(q);
			/*
			 * Clear the indication that this may have
			 * hardware checksum as we are not using it.
			 */
			DB_CKSUMFLAGS(mp) = 0;
			/* Sent by forwarding path, and router is global zone */
			icmp_unreachable(q, mp,
			    ICMP_SOURCE_ROUTE_FAILED, GLOBAL_ZONEID, ipst);
			return;
		}
		goto drop_pkt;
	}

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInForwDatagrams);

	/* Packet is being forwarded. Turning off hwcksum flag. */
	DB_CKSUMFLAGS(mp) = 0;
	if (ipst->ips_ip_g_send_redirects) {
		/*
		 * Check whether the incoming interface and outgoing
		 * interface is part of the same group. If so,
		 * send redirects.
		 *
		 * Check the source address to see if it originated
		 * on the same logical subnet it is going back out on.
		 * If so, we should be able to send it a redirect.
		 * Avoid sending a redirect if the destination
		 * is directly connected (i.e., ipha_dst is the same
		 * as ire_gateway_addr or the ire_addr of the
		 * nexthop IRE_CACHE ), or if the packet was source
		 * routed out this interface.
		 */
		ipaddr_t src, nhop;
		mblk_t	*mp1;
		ire_t	*nhop_ire = NULL;

		/*
		 * Check whether ire_rfq and q are from the same ill
		 * or if they are not same, they at least belong
		 * to the same group. If so, send redirects.
		 */
		if ((ire->ire_rfq == q ||
		    (ill_group != NULL && ill_group == ire_group)) &&
		    !ip_source_routed(ipha, ipst)) {

			nhop = (ire->ire_gateway_addr != 0 ?
			    ire->ire_gateway_addr : ire->ire_addr);

			if (ipha->ipha_dst == nhop) {
				/*
				 * We avoid sending a redirect if the
				 * destination is directly connected
				 * because it is possible that multiple
				 * IP subnets may have been configured on
				 * the link, and the source may not
				 * be on the same subnet as ip destination,
				 * even though they are on the same
				 * physical link.
				 */
				goto sendit;
			}

			src = ipha->ipha_src;

			/*
			 * We look up the interface ire for the nexthop,
			 * to see if ipha_src is in the same subnet
			 * as the nexthop.
			 *
			 * Note that, if, in the future, IRE_CACHE entries
			 * are obsoleted,  this lookup will not be needed,
			 * as the ire passed to this function will be the
			 * same as the nhop_ire computed below.
			 */
			nhop_ire = ire_ftable_lookup(nhop, 0, 0,
			    IRE_INTERFACE, NULL, NULL, ALL_ZONES,
			    0, NULL, MATCH_IRE_TYPE, ipst);

			if (nhop_ire != NULL) {
				if ((src & nhop_ire->ire_mask) ==
				    (nhop & nhop_ire->ire_mask)) {
					/*
					 * The source is directly connected.
					 * Just copy the ip header (which is
					 * in the first mblk)
					 */
					mp1 = copyb(mp);
					if (mp1 != NULL) {
						icmp_send_redirect(WR(q), mp1,
						    nhop, ipst);
					}
				}
				ire_refrele(nhop_ire);
			}
		}
	}
sendit:
	dev_q = ire->ire_stq->q_next;
	if (DEV_Q_FLOW_BLOCKED(dev_q)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		freemsg(mp);
		return;
	}

	ip_rput_forward(ire, ipha, mp, ill);
	return;

drop_pkt:
	ip2dbg(("ip_rput_process_forward: drop pkt\n"));
	freemsg(mp);
}

ire_t *
ip_rput_process_broadcast(queue_t **qp, mblk_t *mp, ire_t *ire, ipha_t *ipha,
    ill_t *ill, ipaddr_t dst, int cgtp_flt_pkt, int ll_multicast)
{
	queue_t		*q;
	uint16_t	hcksumflags;
	ip_stack_t	*ipst = ill->ill_ipst;

	q = *qp;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInBcastPkts);

	/*
	 * Clear the indication that this may have hardware
	 * checksum as we are not using it for forwarding.
	 */
	hcksumflags = DB_CKSUMFLAGS(mp);
	DB_CKSUMFLAGS(mp) = 0;

	/*
	 * Directed broadcast forwarding: if the packet came in over a
	 * different interface then it is routed out over we can forward it.
	 */
	if (ipha->ipha_protocol == IPPROTO_TCP) {
		ire_refrele(ire);
		freemsg(mp);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		return (NULL);
	}
	/*
	 * For multicast we have set dst to be INADDR_BROADCAST
	 * for delivering to all STREAMS. IRE_MARK_NORECV is really
	 * only for broadcast packets.
	 */
	if (!CLASSD(ipha->ipha_dst)) {
		ire_t *new_ire;
		ipif_t *ipif;
		/*
		 * For ill groups, as the switch duplicates broadcasts
		 * across all the ports, we need to filter out and
		 * send up only one copy. There is one copy for every
		 * broadcast address on each ill. Thus, we look for a
		 * specific IRE on this ill and look at IRE_MARK_NORECV
		 * later to see whether this ill is eligible to receive
		 * them or not. ill_nominate_bcast_rcv() nominates only
		 * one set of IREs for receiving.
		 */

		ipif = ipif_get_next_ipif(NULL, ill);
		if (ipif == NULL) {
			ire_refrele(ire);
			freemsg(mp);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return (NULL);
		}
		new_ire = ire_ctable_lookup(dst, 0, 0,
		    ipif, ALL_ZONES, NULL, MATCH_IRE_ILL, ipst);
		ipif_refrele(ipif);

		if (new_ire != NULL) {
			if (new_ire->ire_marks & IRE_MARK_NORECV) {
				ire_refrele(ire);
				ire_refrele(new_ire);
				freemsg(mp);
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				return (NULL);
			}
			/*
			 * In the special case of multirouted broadcast
			 * packets, we unconditionally need to "gateway"
			 * them to the appropriate interface here.
			 * In the normal case, this cannot happen, because
			 * there is no broadcast IRE tagged with the
			 * RTF_MULTIRT flag.
			 */
			if (new_ire->ire_flags & RTF_MULTIRT) {
				ire_refrele(new_ire);
				if (ire->ire_rfq != NULL) {
					q = ire->ire_rfq;
					*qp = q;
				}
			} else {
				ire_refrele(ire);
				ire = new_ire;
			}
		} else if (cgtp_flt_pkt == CGTP_IP_PKT_NOT_CGTP) {
			if (!ipst->ips_ip_g_forward_directed_bcast) {
				/*
				 * Free the message if
				 * ip_g_forward_directed_bcast is turned
				 * off for non-local broadcast.
				 */
				ire_refrele(ire);
				freemsg(mp);
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				return (NULL);
			}
		} else {
			/*
			 * This CGTP packet successfully passed the
			 * CGTP filter, but the related CGTP
			 * broadcast IRE has not been found,
			 * meaning that the redundant ipif is
			 * probably down. However, if we discarded
			 * this packet, its duplicate would be
			 * filtered out by the CGTP filter so none
			 * of them would get through. So we keep
			 * going with this one.
			 */
			ASSERT(cgtp_flt_pkt == CGTP_IP_PKT_PREMIUM);
			if (ire->ire_rfq != NULL) {
				q = ire->ire_rfq;
				*qp = q;
			}
		}
	}
	if (ipst->ips_ip_g_forward_directed_bcast && ll_multicast == 0) {
		/*
		 * Verify that there are not more then one
		 * IRE_BROADCAST with this broadcast address which
		 * has ire_stq set.
		 * TODO: simplify, loop over all IRE's
		 */
		ire_t	*ire1;
		int	num_stq = 0;
		mblk_t	*mp1;

		/* Find the first one with ire_stq set */
		rw_enter(&ire->ire_bucket->irb_lock, RW_READER);
		for (ire1 = ire; ire1 &&
		    !ire1->ire_stq && ire1->ire_addr == ire->ire_addr;
		    ire1 = ire1->ire_next)
			;
		if (ire1) {
			ire_refrele(ire);
			ire = ire1;
			IRE_REFHOLD(ire);
		}

		/* Check if there are additional ones with stq set */
		for (ire1 = ire; ire1; ire1 = ire1->ire_next) {
			if (ire->ire_addr != ire1->ire_addr)
				break;
			if (ire1->ire_stq) {
				num_stq++;
				break;
			}
		}
		rw_exit(&ire->ire_bucket->irb_lock);
		if (num_stq == 1 && ire->ire_stq != NULL) {
			ip1dbg(("ip_rput_process_broadcast: directed "
			    "broadcast to 0x%x\n",
			    ntohl(ire->ire_addr)));
			mp1 = copymsg(mp);
			if (mp1) {
				switch (ipha->ipha_protocol) {
				case IPPROTO_UDP:
					ip_udp_input(q, mp1, ipha, ire, ill);
					break;
				default:
					ip_proto_input(q, mp1, ipha, ire, ill,
					    0);
					break;
				}
			}
			/*
			 * Adjust ttl to 2 (1+1 - the forward engine
			 * will decrement it by one.
			 */
			if (ip_csum_hdr(ipha)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
				ip2dbg(("ip_rput_broadcast:drop pkt\n"));
				freemsg(mp);
				ire_refrele(ire);
				return (NULL);
			}
			ipha->ipha_ttl = ipst->ips_ip_broadcast_ttl + 1;
			ipha->ipha_hdr_checksum = 0;
			ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
			ip_rput_process_forward(q, mp, ire, ipha,
			    ill, ll_multicast, B_FALSE);
			ire_refrele(ire);
			return (NULL);
		}
		ip1dbg(("ip_rput: NO directed broadcast to 0x%x\n",
		    ntohl(ire->ire_addr)));
	}


	/* Restore any hardware checksum flags */
	DB_CKSUMFLAGS(mp) = hcksumflags;
	return (ire);
}

/* ARGSUSED */
static boolean_t
ip_rput_process_multicast(queue_t *q, mblk_t *mp, ill_t *ill, ipha_t *ipha,
    int *ll_multicast, ipaddr_t *dstp)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastPkts);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastOctets,
	    ntohs(ipha->ipha_length));

	/*
	 * Forward packets only if we have joined the allmulti
	 * group on this interface.
	 */
	if (ipst->ips_ip_g_mrouter && ill->ill_join_allmulti) {
		int retval;

		/*
		 * Clear the indication that this may have hardware
		 * checksum as we are not using it.
		 */
		DB_CKSUMFLAGS(mp) = 0;
		retval = ip_mforward(ill, ipha, mp);
		/* ip_mforward updates mib variables if needed */
		/* clear b_prev - used by ip_mroute_decap */
		mp->b_prev = NULL;

		switch (retval) {
		case 0:
			/*
			 * pkt is okay and arrived on phyint.
			 *
			 * If we are running as a multicast router
			 * we need to see all IGMP and/or PIM packets.
			 */
			if ((ipha->ipha_protocol == IPPROTO_IGMP) ||
			    (ipha->ipha_protocol == IPPROTO_PIM)) {
				goto done;
			}
			break;
		case -1:
			/* pkt is mal-formed, toss it */
			goto drop_pkt;
		case 1:
			/* pkt is okay and arrived on a tunnel */
			/*
			 * If we are running a multicast router
			 *  we need to see all igmp packets.
			 */
			if (ipha->ipha_protocol == IPPROTO_IGMP) {
				*dstp = INADDR_BROADCAST;
				*ll_multicast = 1;
				return (B_FALSE);
			}

			goto drop_pkt;
		}
	}

	ILM_WALKER_HOLD(ill);
	if (ilm_lookup_ill(ill, *dstp, ALL_ZONES) == NULL) {
		/*
		 * This might just be caused by the fact that
		 * multiple IP Multicast addresses map to the same
		 * link layer multicast - no need to increment counter!
		 */
		ILM_WALKER_RELE(ill);
		freemsg(mp);
		return (B_TRUE);
	}
	ILM_WALKER_RELE(ill);
done:
	ip2dbg(("ip_rput: multicast for us: 0x%x\n", ntohl(*dstp)));
	/*
	 * This assumes the we deliver to all streams for multicast
	 * and broadcast packets.
	 */
	*dstp = INADDR_BROADCAST;
	*ll_multicast = 1;
	return (B_FALSE);
drop_pkt:
	ip2dbg(("ip_rput: drop pkt\n"));
	freemsg(mp);
	return (B_TRUE);
}

/*
 * This function is used to both return an indication of whether or not
 * the packet received is a non-unicast packet (by way of the DL_UNITDATA_IND)
 * and in doing so, determine whether or not it is broadcast vs multicast.
 * For it to be a broadcast packet, we must have the appropriate mblk_t
 * hanging off the ill_t.  If this is either not present or doesn't match
 * the destination mac address in the DL_UNITDATA_IND, the packet is deemed
 * to be multicast.  Thus NICs that have no broadcast address (or no
 * capability for one, such as point to point links) cannot return as
 * the packet being broadcast.  The use of HPE_BROADCAST/HPE_MULTICAST as
 * the return values simplifies the current use of the return value of this
 * function, which is to pass through the multicast/broadcast characteristic
 * to consumers of the netinfo/pfhooks API.  While this is not cast in stone,
 * changing the return value to some other symbol demands the appropriate
 * "translation" when hpe_flags is set prior to calling hook_run() for
 * packet events.
 */
int
ip_get_dlpi_mbcast(ill_t *ill, mblk_t *mb)
{
	dl_unitdata_ind_t *ind = (dl_unitdata_ind_t *)mb->b_rptr;
	mblk_t *bmp;

	if (ind->dl_group_address) {
		if (ind->dl_dest_addr_offset > sizeof (*ind) &&
		    ind->dl_dest_addr_offset + ind->dl_dest_addr_length <
		    MBLKL(mb) &&
		    (bmp = ill->ill_bcast_mp) != NULL) {
			dl_unitdata_req_t *dlur;
			uint8_t *bphys_addr;

			dlur = (dl_unitdata_req_t *)bmp->b_rptr;
			if (ill->ill_sap_length < 0)
				bphys_addr = (uchar_t *)dlur +
				    dlur->dl_dest_addr_offset;
			else
				bphys_addr = (uchar_t *)dlur +
				    dlur->dl_dest_addr_offset +
				    ill->ill_sap_length;

			if (bcmp(mb->b_rptr + ind->dl_dest_addr_offset,
			    bphys_addr, ind->dl_dest_addr_length) == 0) {
				return (HPE_BROADCAST);
			}
			return (HPE_MULTICAST);
		}
		return (HPE_MULTICAST);
	}
	return (0);
}

static boolean_t
ip_rput_process_notdata(queue_t *q, mblk_t **first_mpp, ill_t *ill,
    int *ll_multicast, mblk_t **mpp)
{
	mblk_t *mp1, *from_mp, *to_mp, *mp, *first_mp;
	boolean_t must_copy = B_FALSE;
	struct iocblk   *iocp;
	ipha_t		*ipha;
	ip_stack_t	*ipst = ill->ill_ipst;

#define	rptr    ((uchar_t *)ipha)

	first_mp = *first_mpp;
	mp = *mpp;

	ASSERT(first_mp == mp);

	/*
	 * if db_ref > 1 then copymsg and free original. Packet may be
	 * changed and do not want other entity who has a reference to this
	 * message to trip over the changes. This is a blind change because
	 * trying to catch all places that might change packet is too
	 * difficult (since it may be a module above this one)
	 *
	 * This corresponds to the non-fast path case. We walk down the full
	 * chain in this case, and check the db_ref count of all the dblks,
	 * and do a copymsg if required. It is possible that the db_ref counts
	 * of the data blocks in the mblk chain can be different.
	 * For Example, we can get a DL_UNITDATA_IND(M_PROTO) with a db_ref
	 * count of 1, followed by a M_DATA block with a ref count of 2, if
	 * 'snoop' is running.
	 */
	for (mp1 = mp; mp1 != NULL; mp1 = mp1->b_cont) {
		if (mp1->b_datap->db_ref > 1) {
			must_copy = B_TRUE;
			break;
		}
	}

	if (must_copy) {
		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			for (mp1 = mp; mp1 != NULL;
			    mp1 = mp1->b_cont) {
				mp1->b_next = NULL;
				mp1->b_prev = NULL;
			}
			freemsg(mp);
			if (ill != NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			} else {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsInDiscards);
			}
			return (B_TRUE);
		}
		for (from_mp = mp, to_mp = mp1; from_mp != NULL;
		    from_mp = from_mp->b_cont, to_mp = to_mp->b_cont) {
			/* Copy b_prev - used by ip_mroute_decap */
			to_mp->b_prev = from_mp->b_prev;
			from_mp->b_prev = NULL;
		}
		*first_mpp = first_mp = mp1;
		freemsg(mp);
		mp = mp1;
		*mpp = mp1;
	}

	ipha = (ipha_t *)mp->b_rptr;

	/*
	 * previous code has a case for M_DATA.
	 * We want to check how that happens.
	 */
	ASSERT(first_mp->b_datap->db_type != M_DATA);
	switch (first_mp->b_datap->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		if (((dl_unitdata_ind_t *)rptr)->dl_primitive !=
		    DL_UNITDATA_IND) {
			/* Go handle anything other than data elsewhere. */
			ip_rput_dlpi(q, mp);
			return (B_TRUE);
		}

		*ll_multicast = ip_get_dlpi_mbcast(ill, mp);
		/* Ditch the DLPI header. */
		mp1 = mp->b_cont;
		ASSERT(first_mp == mp);
		*first_mpp = mp1;
		freeb(mp);
		*mpp = mp1;
		return (B_FALSE);
	case M_IOCACK:
		ip1dbg(("got iocack "));
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case DL_IOC_HDR_INFO:
			ill = (ill_t *)q->q_ptr;
			ill_fastpath_ack(ill, mp);
			return (B_TRUE);
		case SIOCSTUNPARAM:
		case OSIOCSTUNPARAM:
			/* Go through qwriter_ip */
			break;
		case SIOCGTUNPARAM:
		case OSIOCGTUNPARAM:
			ip_rput_other(NULL, q, mp, NULL);
			return (B_TRUE);
		default:
			putnext(q, mp);
			return (B_TRUE);
		}
		/* FALLTHRU */
	case M_ERROR:
	case M_HANGUP:
		/*
		 * Since this is on the ill stream we unconditionally
		 * bump up the refcount
		 */
		ill_refhold(ill);
		qwriter_ip(ill, q, mp, ip_rput_other, CUR_OP, B_FALSE);
		return (B_TRUE);
	case M_CTL:
		if ((MBLKL(first_mp) >= sizeof (da_ipsec_t)) &&
		    (((da_ipsec_t *)first_mp->b_rptr)->da_type ==
		    IPHADA_M_CTL)) {
			/*
			 * It's an IPsec accelerated packet.
			 * Make sure that the ill from which we received the
			 * packet has enabled IPsec hardware acceleration.
			 */
			if (!(ill->ill_capabilities &
			    (ILL_CAPAB_AH|ILL_CAPAB_ESP))) {
				/* IPsec kstats: bean counter */
				freemsg(mp);
				return (B_TRUE);
			}

			/*
			 * Make mp point to the mblk following the M_CTL,
			 * then process according to type of mp.
			 * After this processing, first_mp will point to
			 * the data-attributes and mp to the pkt following
			 * the M_CTL.
			 */
			mp = first_mp->b_cont;
			if (mp == NULL) {
				freemsg(first_mp);
				return (B_TRUE);
			}
			/*
			 * A Hardware Accelerated packet can only be M_DATA
			 * ESP or AH packet.
			 */
			if (mp->b_datap->db_type != M_DATA) {
				/* non-M_DATA IPsec accelerated packet */
				IPSECHW_DEBUG(IPSECHW_PKT,
				    ("non-M_DATA IPsec accelerated pkt\n"));
				freemsg(first_mp);
				return (B_TRUE);
			}
			ipha = (ipha_t *)mp->b_rptr;
			if (ipha->ipha_protocol != IPPROTO_AH &&
			    ipha->ipha_protocol != IPPROTO_ESP) {
				IPSECHW_DEBUG(IPSECHW_PKT,
				    ("non-M_DATA IPsec accelerated pkt\n"));
				freemsg(first_mp);
				return (B_TRUE);
			}
			*mpp = mp;
			return (B_FALSE);
		}
		putnext(q, mp);
		return (B_TRUE);
	case M_IOCNAK:
		ip1dbg(("got iocnak "));
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case SIOCSTUNPARAM:
		case OSIOCSTUNPARAM:
			/*
			 * Since this is on the ill stream we unconditionally
			 * bump up the refcount
			 */
			ill_refhold(ill);
			qwriter_ip(ill, q, mp, ip_rput_other, CUR_OP, B_FALSE);
			return (B_TRUE);
		case DL_IOC_HDR_INFO:
		case SIOCGTUNPARAM:
		case OSIOCGTUNPARAM:
			ip_rput_other(NULL, q, mp, NULL);
			return (B_TRUE);
		default:
			break;
		}
		/* FALLTHRU */
	default:
		putnext(q, mp);
		return (B_TRUE);
	}
}

/* Read side put procedure.  Packets coming from the wire arrive here. */
void
ip_rput(queue_t *q, mblk_t *mp)
{
	ill_t	*ill;
	union DL_primitives *dl;

	TRACE_1(TR_FAC_IP, TR_IP_RPUT_START, "ip_rput_start: q %p", q);

	ill = (ill_t *)q->q_ptr;

	if (ill->ill_state_flags & (ILL_CONDEMNED | ILL_LL_SUBNET_PENDING)) {
		/*
		 * If things are opening or closing, only accept high-priority
		 * DLPI messages.  (On open ill->ill_ipif has not yet been
		 * created; on close, things hanging off the ill may have been
		 * freed already.)
		 */
		dl = (union DL_primitives *)mp->b_rptr;
		if (DB_TYPE(mp) != M_PCPROTO ||
		    dl->dl_primitive == DL_UNITDATA_IND) {
			/*
			 * SIOC[GS]TUNPARAM ioctls can come here.
			 */
			inet_freemsg(mp);
			TRACE_2(TR_FAC_IP, TR_IP_RPUT_END,
			    "ip_rput_end: q %p (%S)", q, "uninit");
			return;
		}
	}

	TRACE_2(TR_FAC_IP, TR_IP_RPUT_END,
	    "ip_rput_end: q %p (%S)", q, "end");

	ip_input(ill, NULL, mp, NULL);
}

static mblk_t *
ip_fix_dbref(ill_t *ill, mblk_t *mp)
{
	mblk_t *mp1;
	boolean_t adjusted = B_FALSE;
	ip_stack_t *ipst = ill->ill_ipst;

	IP_STAT(ipst, ip_db_ref);
	/*
	 * The IP_RECVSLLA option depends on having the
	 * link layer header. First check that:
	 * a> the underlying device is of type ether,
	 * since this option is currently supported only
	 * over ethernet.
	 * b> there is enough room to copy over the link
	 * layer header.
	 *
	 * Once the checks are done, adjust rptr so that
	 * the link layer header will be copied via
	 * copymsg. Note that, IFT_ETHER may be returned
	 * by some non-ethernet drivers but in this case
	 * the second check will fail.
	 */
	if (ill->ill_type == IFT_ETHER &&
	    (mp->b_rptr - mp->b_datap->db_base) >=
	    sizeof (struct ether_header)) {
		mp->b_rptr -= sizeof (struct ether_header);
		adjusted = B_TRUE;
	}
	mp1 = copymsg(mp);

	if (mp1 == NULL) {
		mp->b_next = NULL;
		/* clear b_prev - used by ip_mroute_decap */
		mp->b_prev = NULL;
		freemsg(mp);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		return (NULL);
	}

	if (adjusted) {
		/*
		 * Copy is done. Restore the pointer in
		 * the _new_ mblk
		 */
		mp1->b_rptr += sizeof (struct ether_header);
	}

	/* Copy b_prev - used by ip_mroute_decap */
	mp1->b_prev = mp->b_prev;
	mp->b_prev = NULL;

	/* preserve the hardware checksum flags and data, if present */
	if (DB_CKSUMFLAGS(mp) != 0) {
		DB_CKSUMFLAGS(mp1) = DB_CKSUMFLAGS(mp);
		DB_CKSUMSTART(mp1) = DB_CKSUMSTART(mp);
		DB_CKSUMSTUFF(mp1) = DB_CKSUMSTUFF(mp);
		DB_CKSUMEND(mp1) = DB_CKSUMEND(mp);
		DB_CKSUM16(mp1) = DB_CKSUM16(mp);
	}

	freemsg(mp);
	return (mp1);
}

#define	ADD_TO_CHAIN(head, tail, cnt, mp) {    			\
	if (tail != NULL)					\
		tail->b_next = mp;				\
	else							\
		head = mp;					\
	tail = mp;						\
	cnt++;							\
}

/*
 * Direct read side procedure capable of dealing with chains. GLDv3 based
 * drivers call this function directly with mblk chains while STREAMS
 * read side procedure ip_rput() calls this for single packet with ip_ring
 * set to NULL to process one packet at a time.
 *
 * The ill will always be valid if this function is called directly from
 * the driver.
 *
 * If ip_input() is called from GLDv3:
 *
 *   - This must be a non-VLAN IP stream.
 *   - 'mp' is either an untagged or a special priority-tagged packet.
 *   - Any VLAN tag that was in the MAC header has been stripped.
 *
 * If the IP header in packet is not 32-bit aligned, every message in the
 * chain will be aligned before further operations. This is required on SPARC
 * platform.
 */
/* ARGSUSED */
void
ip_input(ill_t *ill, ill_rx_ring_t *ip_ring, mblk_t *mp_chain,
    struct mac_header_info_s *mhip)
{
	ipaddr_t		dst = NULL;
	ipaddr_t		prev_dst;
	ire_t			*ire = NULL;
	ipha_t			*ipha;
	uint_t			pkt_len;
	ssize_t			len;
	uint_t			opt_len;
	int			ll_multicast;
	int			cgtp_flt_pkt;
	queue_t			*q = ill->ill_rq;
	squeue_t		*curr_sqp = NULL;
	mblk_t 			*head = NULL;
	mblk_t			*tail = NULL;
	mblk_t			*first_mp;
	int			cnt = 0;
	ip_stack_t		*ipst = ill->ill_ipst;
	mblk_t			*mp;
	mblk_t			*dmp;
	uint8_t			tag;

	ASSERT(mp_chain != NULL);
	ASSERT(ill != NULL);

	TRACE_1(TR_FAC_IP, TR_IP_RPUT_START, "ip_input_start: q %p", q);

	tag = (ip_ring != NULL) ? SQTAG_IP_INPUT_RX_RING : SQTAG_IP_INPUT;

#define	rptr	((uchar_t *)ipha)

	while (mp_chain != NULL) {
		mp = mp_chain;
		mp_chain = mp_chain->b_next;
		mp->b_next = NULL;
		ll_multicast = 0;

		/*
		 * We do ire caching from one iteration to
		 * another. In the event the packet chain contains
		 * all packets from the same dst, this caching saves
		 * an ire_cache_lookup for each of the succeeding
		 * packets in a packet chain.
		 */
		prev_dst = dst;

		/*
		 * if db_ref > 1 then copymsg and free original. Packet
		 * may be changed and we do not want the other entity
		 * who has a reference to this message to trip over the
		 * changes. This is a blind change because trying to
		 * catch all places that might change the packet is too
		 * difficult.
		 *
		 * This corresponds to the fast path case, where we have
		 * a chain of M_DATA mblks.  We check the db_ref count
		 * of only the 1st data block in the mblk chain. There
		 * doesn't seem to be a reason why a device driver would
		 * send up data with varying db_ref counts in the mblk
		 * chain. In any case the Fast path is a private
		 * interface, and our drivers don't do such a thing.
		 * Given the above assumption, there is no need to walk
		 * down the entire mblk chain (which could have a
		 * potential performance problem)
		 *
		 * The "(DB_REF(mp) > 1)" check was moved from ip_rput()
		 * to here because of exclusive ip stacks and vnics.
		 * Packets transmitted from exclusive stack over vnic
		 * can have db_ref > 1 and when it gets looped back to
		 * another vnic in a different zone, you have ip_input()
		 * getting dblks with db_ref > 1. So if someone
		 * complains of TCP performance under this scenario,
		 * take a serious look here on the impact of copymsg().
		 */

		if (DB_REF(mp) > 1) {
			if ((mp = ip_fix_dbref(ill, mp)) == NULL)
				continue;
		}

		/*
		 * Check and align the IP header.
		 */
		first_mp = mp;
		if (DB_TYPE(mp) == M_DATA) {
			dmp = mp;
		} else if (DB_TYPE(mp) == M_PROTO &&
		    *(t_uscalar_t *)mp->b_rptr == DL_UNITDATA_IND) {
			dmp = mp->b_cont;
		} else {
			dmp = NULL;
		}
		if (dmp != NULL) {
			/*
			 * IP header ptr not aligned?
			 * OR IP header not complete in first mblk
			 */
			if (!OK_32PTR(dmp->b_rptr) ||
			    MBLKL(dmp) < IP_SIMPLE_HDR_LENGTH) {
				if (!ip_check_and_align_header(q, dmp, ipst))
					continue;
			}
		}

		/*
		 * ip_input fast path
		 */

		/* mblk type is not M_DATA */
		if (DB_TYPE(mp) != M_DATA) {
			if (ip_rput_process_notdata(q, &first_mp, ill,
			    &ll_multicast, &mp))
				continue;

			/*
			 * The only way we can get here is if we had a
			 * packet that was either a DL_UNITDATA_IND or
			 * an M_CTL for an IPsec accelerated packet.
			 *
			 * In either case, the first_mp will point to
			 * the leading M_PROTO or M_CTL.
			 */
			ASSERT(first_mp != NULL);
		} else if (mhip != NULL) {
			/*
			 * ll_multicast is set here so that it is ready
			 * for easy use with FW_HOOKS().  ip_get_dlpi_mbcast
			 * manipulates ll_multicast in the same fashion when
			 * called from ip_rput_process_notdata.
			 */
			switch (mhip->mhi_dsttype) {
			case MAC_ADDRTYPE_MULTICAST :
				ll_multicast = HPE_MULTICAST;
				break;
			case MAC_ADDRTYPE_BROADCAST :
				ll_multicast = HPE_BROADCAST;
				break;
			default :
				break;
			}
		}

		/* Only M_DATA can come here and it is always aligned */
		ASSERT(DB_TYPE(mp) == M_DATA);
		ASSERT(DB_REF(mp) == 1 && OK_32PTR(mp->b_rptr));

		ipha = (ipha_t *)mp->b_rptr;
		len = mp->b_wptr - rptr;
		pkt_len = ntohs(ipha->ipha_length);

		/*
		 * We must count all incoming packets, even if they end
		 * up being dropped later on.
		 */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInReceives);
		UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets, pkt_len);

		/* multiple mblk or too short */
		len -= pkt_len;
		if (len != 0) {
			/*
			 * Make sure we have data length consistent
			 * with the IP header.
			 */
			if (mp->b_cont == NULL) {
				if (len < 0 || pkt_len < IP_SIMPLE_HDR_LENGTH) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInHdrErrors);
					ip2dbg(("ip_input: drop pkt\n"));
					freemsg(mp);
					continue;
				}
				mp->b_wptr = rptr + pkt_len;
			} else if ((len += msgdsize(mp->b_cont)) != 0) {
				if (len < 0 || pkt_len < IP_SIMPLE_HDR_LENGTH) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInHdrErrors);
					ip2dbg(("ip_input: drop pkt\n"));
					freemsg(mp);
					continue;
				}
				(void) adjmsg(mp, -len);
				IP_STAT(ipst, ip_multimblk3);
			}
		}

		/* Obtain the dst of the current packet */
		dst = ipha->ipha_dst;

		DTRACE_IP7(receive, mblk_t *, first_mp, conn_t *, NULL,
		    void_ip_t *, ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *,
		    ipha, ip6_t *, NULL, int, 0);

		/*
		 * The following test for loopback is faster than
		 * IP_LOOPBACK_ADDR(), because it avoids any bitwise
		 * operations.
		 * Note that these addresses are always in network byte order
		 */
		if (((*(uchar_t *)&ipha->ipha_dst) == 127) ||
		    ((*(uchar_t *)&ipha->ipha_src) == 127)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			freemsg(mp);
			continue;
		}

		/*
		 * The event for packets being received from a 'physical'
		 * interface is placed after validation of the source and/or
		 * destination address as being local so that packets can be
		 * redirected to loopback addresses using ipnat.
		 */
		DTRACE_PROBE4(ip4__physical__in__start,
		    ill_t *, ill, ill_t *, NULL,
		    ipha_t *, ipha, mblk_t *, first_mp);

		FW_HOOKS(ipst->ips_ip4_physical_in_event,
		    ipst->ips_ipv4firewall_physical_in,
		    ill, NULL, ipha, first_mp, mp, ll_multicast, ipst);

		DTRACE_PROBE1(ip4__physical__in__end, mblk_t *, first_mp);

		if (first_mp == NULL) {
			continue;
		}
		dst = ipha->ipha_dst;
		/*
		 * Attach any necessary label information to
		 * this packet
		 */
		if (is_system_labeled() &&
		    !tsol_get_pkt_label(mp, IPV4_VERSION)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(mp);
			continue;
		}

		if (ipst->ips_ipobs_enabled) {
			zoneid_t dzone;

			/*
			 * On the inbound path the src zone will be unknown as
			 * this packet has come from the wire.
			 */
			dzone = ip_get_zoneid_v4(dst, mp, ipst, ALL_ZONES);
			ipobs_hook(mp, IPOBS_HOOK_INBOUND, ALL_ZONES, dzone,
			    ill, IPV4_VERSION, 0, ipst);
		}

		/*
		 * Reuse the cached ire only if the ipha_dst of the previous
		 * packet is the same as the current packet AND it is not
		 * INADDR_ANY.
		 */
		if (!(dst == prev_dst && dst != INADDR_ANY) &&
		    (ire != NULL)) {
			ire_refrele(ire);
			ire = NULL;
		}

		opt_len = ipha->ipha_version_and_hdr_length -
		    IP_SIMPLE_HDR_VERSION;

		/*
		 * Check to see if we can take the fastpath.
		 * That is possible if the following conditions are met
		 *	o Tsol disabled
		 *	o CGTP disabled
		 *	o ipp_action_count is 0
		 *	o no options in the packet
		 *	o not a RSVP packet
		 * 	o not a multicast packet
		 *	o ill not in IP_DHCPINIT_IF mode
		 */
		if (!is_system_labeled() &&
		    !ipst->ips_ip_cgtp_filter && ipp_action_count == 0 &&
		    opt_len == 0 && ipha->ipha_protocol != IPPROTO_RSVP &&
		    !ll_multicast && !CLASSD(dst) && ill->ill_dhcpinit == 0) {
			if (ire == NULL)
				ire = ire_cache_lookup_simple(dst, ipst);
			/*
			 * Unless forwarding is enabled, dont call
			 * ip_fast_forward(). Incoming packet is for forwarding
			 */
			if ((ill->ill_flags & ILLF_ROUTER) &&
			    (ire == NULL || (ire->ire_type & IRE_CACHE))) {
				ire = ip_fast_forward(ire, dst, ill, mp);
				continue;
			}
			/* incoming packet is for local consumption */
			if ((ire != NULL) && (ire->ire_type & IRE_LOCAL))
				goto local;
		}

		/*
		 * Disable ire caching for anything more complex
		 * than the simple fast path case we checked for above.
		 */
		if (ire != NULL) {
			ire_refrele(ire);
			ire = NULL;
		}

		/*
		 * Brutal hack for DHCPv4 unicast: RFC2131 allows a DHCP
		 * server to unicast DHCP packets to a DHCP client using the
		 * IP address it is offering to the client.  This can be
		 * disabled through the "broadcast bit", but not all DHCP
		 * servers honor that bit.  Therefore, to interoperate with as
		 * many DHCP servers as possible, the DHCP client allows the
		 * server to unicast, but we treat those packets as broadcast
		 * here.  Note that we don't rewrite the packet itself since
		 * (a) that would mess up the checksums and (b) the DHCP
		 * client conn is bound to INADDR_ANY so ip_fanout_udp() will
		 * hand it the packet regardless.
		 */
		if (ill->ill_dhcpinit != 0 &&
		    IS_SIMPLE_IPH(ipha) && ipha->ipha_protocol == IPPROTO_UDP &&
		    pullupmsg(mp, sizeof (ipha_t) + sizeof (udpha_t)) == 1) {
			udpha_t *udpha;

			/*
			 * Reload ipha since pullupmsg() can change b_rptr.
			 */
			ipha = (ipha_t *)mp->b_rptr;
			udpha = (udpha_t *)&ipha[1];

			if (ntohs(udpha->uha_dst_port) == IPPORT_BOOTPC) {
				DTRACE_PROBE2(ip4__dhcpinit__pkt, ill_t *, ill,
				    mblk_t *, mp);
				dst = INADDR_BROADCAST;
			}
		}

		/* Full-blown slow path */
		if (opt_len != 0) {
			if (len != 0)
				IP_STAT(ipst, ip_multimblk4);
			else
				IP_STAT(ipst, ip_ipoptions);
			if (!ip_rput_multimblk_ipoptions(q, ill, mp, &ipha,
			    &dst, ipst))
				continue;
		}

		/*
		 * Invoke the CGTP (multirouting) filtering module to process
		 * the incoming packet. Packets identified as duplicates
		 * must be discarded. Filtering is active only if the
		 * the ip_cgtp_filter ndd variable is non-zero.
		 */
		cgtp_flt_pkt = CGTP_IP_PKT_NOT_CGTP;
		if (ipst->ips_ip_cgtp_filter &&
		    ipst->ips_ip_cgtp_filter_ops != NULL) {
			netstackid_t stackid;

			stackid = ipst->ips_netstack->netstack_stackid;
			cgtp_flt_pkt =
			    ipst->ips_ip_cgtp_filter_ops->cfo_filter(stackid,
			    ill->ill_phyint->phyint_ifindex, mp);
			if (cgtp_flt_pkt == CGTP_IP_PKT_DUPLICATE) {
				freemsg(first_mp);
				continue;
			}
		}

		/*
		 * If rsvpd is running, let RSVP daemon handle its processing
		 * and forwarding of RSVP multicast/unicast packets.
		 * If rsvpd is not running but mrouted is running, RSVP
		 * multicast packets are forwarded as multicast traffic
		 * and RSVP unicast packets are forwarded by unicast router.
		 * If neither rsvpd nor mrouted is running, RSVP multicast
		 * packets are not forwarded, but the unicast packets are
		 * forwarded like unicast traffic.
		 */
		if (ipha->ipha_protocol == IPPROTO_RSVP &&
		    ipst->ips_ipcl_proto_fanout[IPPROTO_RSVP].connf_head !=
		    NULL) {
			/* RSVP packet and rsvpd running. Treat as ours */
			ip2dbg(("ip_input: RSVP for us: 0x%x\n", ntohl(dst)));
			/*
			 * This assumes that we deliver to all streams for
			 * multicast and broadcast packets.
			 * We have to force ll_multicast to 1 to handle the
			 * M_DATA messages passed in from ip_mroute_decap.
			 */
			dst = INADDR_BROADCAST;
			ll_multicast = 1;
		} else if (CLASSD(dst)) {
			/* packet is multicast */
			mp->b_next = NULL;
			if (ip_rput_process_multicast(q, mp, ill, ipha,
			    &ll_multicast, &dst))
				continue;
		}

		if (ire == NULL) {
			ire = ire_cache_lookup(dst, ALL_ZONES,
			    MBLK_GETLABEL(mp), ipst);
		}

		if (ire != NULL && ire->ire_stq != NULL &&
		    ire->ire_zoneid != GLOBAL_ZONEID &&
		    ire->ire_zoneid != ALL_ZONES) {
			/*
			 * Should only use IREs that are visible from the
			 * global zone for forwarding.
			 */
			ire_refrele(ire);
			ire = ire_cache_lookup(dst, GLOBAL_ZONEID,
			    MBLK_GETLABEL(mp), ipst);
		}

		if (ire == NULL) {
			/*
			 * No IRE for this destination, so it can't be for us.
			 * Unless we are forwarding, drop the packet.
			 * We have to let source routed packets through
			 * since we don't yet know if they are 'ping -l'
			 * packets i.e. if they will go out over the
			 * same interface as they came in on.
			 */
			ire = ip_rput_noire(q, mp, ll_multicast, dst);
			if (ire == NULL)
				continue;
		}

		/*
		 * Broadcast IRE may indicate either broadcast or
		 * multicast packet
		 */
		if (ire->ire_type == IRE_BROADCAST) {
			/*
			 * Skip broadcast checks if packet is UDP multicast;
			 * we'd rather not enter ip_rput_process_broadcast()
			 * unless the packet is broadcast for real, since
			 * that routine is a no-op for multicast.
			 */
			if (ipha->ipha_protocol != IPPROTO_UDP ||
			    !CLASSD(ipha->ipha_dst)) {
				ire = ip_rput_process_broadcast(&q, mp,
				    ire, ipha, ill, dst, cgtp_flt_pkt,
				    ll_multicast);
				if (ire == NULL)
					continue;
			}
		} else if (ire->ire_stq != NULL) {
			/* fowarding? */
			ip_rput_process_forward(q, mp, ire, ipha, ill,
			    ll_multicast, B_FALSE);
			/* ip_rput_process_forward consumed the packet */
			continue;
		}

local:
		/*
		 * If the queue in the ire is different to the ingress queue
		 * then we need to check to see if we can accept the packet.
		 * Note that for multicast packets and broadcast packets sent
		 * to a broadcast address which is shared between multiple
		 * interfaces we should not do this since we just got a random
		 * broadcast ire.
		 */
		if ((ire->ire_rfq != q) && (ire->ire_type != IRE_BROADCAST)) {
			if ((ire = ip_check_multihome(&ipha->ipha_dst, ire,
			    ill)) == NULL) {
				/* Drop packet */
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsForwProhibits);
				freemsg(mp);
				continue;
			}
			if (ire->ire_rfq != NULL)
				q = ire->ire_rfq;
		}

		switch (ipha->ipha_protocol) {
		case IPPROTO_TCP:
			ASSERT(first_mp == mp);
			if ((mp = ip_tcp_input(mp, ipha, ill, B_FALSE, ire,
			    mp, 0, q, ip_ring)) != NULL) {
				if (curr_sqp == NULL) {
					curr_sqp = GET_SQUEUE(mp);
					ASSERT(cnt == 0);
					cnt++;
					head = tail = mp;
				} else if (curr_sqp == GET_SQUEUE(mp)) {
					ASSERT(tail != NULL);
					cnt++;
					tail->b_next = mp;
					tail = mp;
				} else {
					/*
					 * A different squeue. Send the
					 * chain for the previous squeue on
					 * its way. This shouldn't happen
					 * often unless interrupt binding
					 * changes.
					 */
					IP_STAT(ipst, ip_input_multi_squeue);
					SQUEUE_ENTER(curr_sqp, head,
					    tail, cnt, SQ_PROCESS, tag);
					curr_sqp = GET_SQUEUE(mp);
					head = mp;
					tail = mp;
					cnt = 1;
				}
			}
			continue;
		case IPPROTO_UDP:
			ASSERT(first_mp == mp);
			ip_udp_input(q, mp, ipha, ire, ill);
			continue;
		case IPPROTO_SCTP:
			ASSERT(first_mp == mp);
			ip_sctp_input(mp, ipha, ill, B_FALSE, ire, mp, 0,
			    q, dst);
			/* ire has been released by ip_sctp_input */
			ire = NULL;
			continue;
		default:
			ip_proto_input(q, first_mp, ipha, ire, ill, 0);
			continue;
		}
	}

	if (ire != NULL)
		ire_refrele(ire);

	if (head != NULL)
		SQUEUE_ENTER(curr_sqp, head, tail, cnt, SQ_PROCESS, tag);

	TRACE_2(TR_FAC_IP, TR_IP_RPUT_END,
	    "ip_input_end: q %p (%S)", q, "end");
#undef  rptr
}

/*
 * ip_accept_tcp() - This function is called by the squeue when it retrieves
 * a chain of packets in the poll mode. The packets have gone through the
 * data link processing but not IP processing. For performance and latency
 * reasons, the squeue wants to process the chain in line instead of feeding
 * it back via ip_input path.
 *
 * So this is a light weight function which checks to see if the packets
 * retrived are indeed TCP packets (TCP squeue always polls TCP soft ring
 * but we still do the paranoid check) meant for local machine and we don't
 * have labels etc enabled. Packets that meet the criterion are returned to
 * the squeue and processed inline while the rest go via ip_input path.
 */
/*ARGSUSED*/
mblk_t *
ip_accept_tcp(ill_t *ill, ill_rx_ring_t *ip_ring, squeue_t *target_sqp,
    mblk_t *mp_chain, mblk_t **last, uint_t *cnt)
{
	mblk_t 		*mp;
	ipaddr_t	dst = NULL;
	ipaddr_t	prev_dst;
	ire_t		*ire = NULL;
	ipha_t		*ipha;
	uint_t		pkt_len;
	ssize_t		len;
	uint_t		opt_len;
	queue_t		*q = ill->ill_rq;
	squeue_t	*curr_sqp;
	mblk_t 		*ahead = NULL;	/* Accepted head */
	mblk_t		*atail = NULL;	/* Accepted tail */
	uint_t		acnt = 0;	/* Accepted count */
	mblk_t		*utail = NULL;	/* Unaccepted head */
	mblk_t		*uhead = NULL;	/* Unaccepted tail */
	uint_t		ucnt = 0;	/* Unaccepted cnt */
	ip_stack_t	*ipst = ill->ill_ipst;

	*cnt = 0;

	ASSERT(ill != NULL);
	ASSERT(ip_ring != NULL);

	TRACE_1(TR_FAC_IP, TR_IP_RPUT_START, "ip_accept_tcp: q %p", q);

#define	rptr	((uchar_t *)ipha)

	while (mp_chain != NULL) {
		mp = mp_chain;
		mp_chain = mp_chain->b_next;
		mp->b_next = NULL;

		/*
		 * We do ire caching from one iteration to
		 * another. In the event the packet chain contains
		 * all packets from the same dst, this caching saves
		 * an ire_cache_lookup for each of the succeeding
		 * packets in a packet chain.
		 */
		prev_dst = dst;

		ipha = (ipha_t *)mp->b_rptr;
		len = mp->b_wptr - rptr;

		ASSERT(!MBLK_RX_FANOUT_SLOWPATH(mp, ipha));

		/*
		 * If it is a non TCP packet, or doesn't have H/W cksum,
		 * or doesn't have min len, reject.
		 */
		if ((ipha->ipha_protocol != IPPROTO_TCP) || (len <
		    (IP_SIMPLE_HDR_LENGTH + TCP_MIN_HEADER_LENGTH))) {
			ADD_TO_CHAIN(uhead, utail, ucnt, mp);
			continue;
		}

		pkt_len = ntohs(ipha->ipha_length);
		if (len != pkt_len) {
			if (len > pkt_len) {
				mp->b_wptr = rptr + pkt_len;
			} else {
				ADD_TO_CHAIN(uhead, utail, ucnt, mp);
				continue;
			}
		}

		opt_len = ipha->ipha_version_and_hdr_length -
		    IP_SIMPLE_HDR_VERSION;
		dst = ipha->ipha_dst;

		/* IP version bad or there are IP options */
		if (opt_len && (!ip_rput_multimblk_ipoptions(q, ill,
		    mp, &ipha, &dst, ipst)))
			continue;

		if (is_system_labeled() || (ill->ill_dhcpinit != 0) ||
		    (ipst->ips_ip_cgtp_filter &&
		    ipst->ips_ip_cgtp_filter_ops != NULL)) {
			ADD_TO_CHAIN(uhead, utail, ucnt, mp);
			continue;
		}

		/*
		 * Reuse the cached ire only if the ipha_dst of the previous
		 * packet is the same as the current packet AND it is not
		 * INADDR_ANY.
		 */
		if (!(dst == prev_dst && dst != INADDR_ANY) &&
		    (ire != NULL)) {
			ire_refrele(ire);
			ire = NULL;
		}

		if (ire == NULL)
			ire = ire_cache_lookup_simple(dst, ipst);

		/*
		 * Unless forwarding is enabled, dont call
		 * ip_fast_forward(). Incoming packet is for forwarding
		 */
		if ((ill->ill_flags & ILLF_ROUTER) &&
		    (ire == NULL || (ire->ire_type & IRE_CACHE))) {

			DTRACE_PROBE4(ip4__physical__in__start,
			    ill_t *, ill, ill_t *, NULL,
			    ipha_t *, ipha, mblk_t *, mp);

			FW_HOOKS(ipst->ips_ip4_physical_in_event,
			    ipst->ips_ipv4firewall_physical_in,
			    ill, NULL, ipha, mp, mp, 0, ipst);

			DTRACE_PROBE1(ip4__physical__in__end, mblk_t *, mp);

			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInReceives);
			UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets,
			    pkt_len);

			ire = ip_fast_forward(ire, dst, ill, mp);
			continue;
		}

		/* incoming packet is for local consumption */
		if ((ire != NULL) && (ire->ire_type & IRE_LOCAL))
			goto local_accept;

		/*
		 * Disable ire caching for anything more complex
		 * than the simple fast path case we checked for above.
		 */
		if (ire != NULL) {
			ire_refrele(ire);
			ire = NULL;
		}

		ire = ire_cache_lookup(dst, ALL_ZONES, MBLK_GETLABEL(mp),
		    ipst);
		if (ire == NULL || ire->ire_type == IRE_BROADCAST ||
		    ire->ire_stq != NULL) {
			ADD_TO_CHAIN(uhead, utail, ucnt, mp);
			if (ire != NULL) {
				ire_refrele(ire);
				ire = NULL;
			}
			continue;
		}

local_accept:

		if (ire->ire_rfq != q) {
			ADD_TO_CHAIN(uhead, utail, ucnt, mp);
			if (ire != NULL) {
				ire_refrele(ire);
				ire = NULL;
			}
			continue;
		}

		/*
		 * The event for packets being received from a 'physical'
		 * interface is placed after validation of the source and/or
		 * destination address as being local so that packets can be
		 * redirected to loopback addresses using ipnat.
		 */
		DTRACE_PROBE4(ip4__physical__in__start,
		    ill_t *, ill, ill_t *, NULL,
		    ipha_t *, ipha, mblk_t *, mp);

		FW_HOOKS(ipst->ips_ip4_physical_in_event,
		    ipst->ips_ipv4firewall_physical_in,
		    ill, NULL, ipha, mp, mp, 0, ipst);

		DTRACE_PROBE1(ip4__physical__in__end, mblk_t *, mp);

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInReceives);
		UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets, pkt_len);

		if ((mp = ip_tcp_input(mp, ipha, ill, B_FALSE, ire, mp,
		    0, q, ip_ring)) != NULL) {
			if ((curr_sqp = GET_SQUEUE(mp)) == target_sqp) {
				ADD_TO_CHAIN(ahead, atail, acnt, mp);
			} else {
				SQUEUE_ENTER(curr_sqp, mp, mp, 1,
				    SQ_FILL, SQTAG_IP_INPUT);
			}
		}
	}

	if (ire != NULL)
		ire_refrele(ire);

	if (uhead != NULL)
		ip_input(ill, ip_ring, uhead, NULL);

	if (ahead != NULL) {
		*last = atail;
		*cnt = acnt;
		return (ahead);
	}

	return (NULL);
#undef  rptr
}

static void
ip_dlpi_error(ill_t *ill, t_uscalar_t prim, t_uscalar_t dl_err,
    t_uscalar_t err)
{
	if (dl_err == DL_SYSERR) {
		(void) mi_strlog(ill->ill_rq, 1, SL_CONSOLE|SL_ERROR|SL_TRACE,
		    "%s: %s failed: DL_SYSERR (errno %u)\n",
		    ill->ill_name, dl_primstr(prim), err);
		return;
	}

	(void) mi_strlog(ill->ill_rq, 1, SL_CONSOLE|SL_ERROR|SL_TRACE,
	    "%s: %s failed: %s\n", ill->ill_name, dl_primstr(prim),
	    dl_errstr(dl_err));
}

/*
 * ip_rput_dlpi is called by ip_rput to handle all DLPI messages other
 * than DL_UNITDATA_IND messages. If we need to process this message
 * exclusively, we call qwriter_ip, in which case we also need to call
 * ill_refhold before that, since qwriter_ip does an ill_refrele.
 */
void
ip_rput_dlpi(queue_t *q, mblk_t *mp)
{
	dl_ok_ack_t	*dloa = (dl_ok_ack_t *)mp->b_rptr;
	dl_error_ack_t	*dlea = (dl_error_ack_t *)dloa;
	ill_t		*ill = q->q_ptr;
	t_uscalar_t	prim = dloa->dl_primitive;
	t_uscalar_t	reqprim = DL_PRIM_INVAL;

	ip1dbg(("ip_rput_dlpi"));

	/*
	 * If we received an ACK but didn't send a request for it, then it
	 * can't be part of any pending operation; discard up-front.
	 */
	switch (prim) {
	case DL_ERROR_ACK:
		reqprim = dlea->dl_error_primitive;
		ip2dbg(("ip_rput_dlpi(%s): DL_ERROR_ACK for %s (0x%x): %s "
		    "(0x%x), unix %u\n", ill->ill_name, dl_primstr(reqprim),
		    reqprim, dl_errstr(dlea->dl_errno), dlea->dl_errno,
		    dlea->dl_unix_errno));
		break;
	case DL_OK_ACK:
		reqprim = dloa->dl_correct_primitive;
		break;
	case DL_INFO_ACK:
		reqprim = DL_INFO_REQ;
		break;
	case DL_BIND_ACK:
		reqprim = DL_BIND_REQ;
		break;
	case DL_PHYS_ADDR_ACK:
		reqprim = DL_PHYS_ADDR_REQ;
		break;
	case DL_NOTIFY_ACK:
		reqprim = DL_NOTIFY_REQ;
		break;
	case DL_CONTROL_ACK:
		reqprim = DL_CONTROL_REQ;
		break;
	case DL_CAPABILITY_ACK:
		reqprim = DL_CAPABILITY_REQ;
		break;
	}

	if (prim != DL_NOTIFY_IND) {
		if (reqprim == DL_PRIM_INVAL ||
		    !ill_dlpi_pending(ill, reqprim)) {
			/* Not a DLPI message we support or expected */
			freemsg(mp);
			return;
		}
		ip1dbg(("ip_rput: received %s for %s\n", dl_primstr(prim),
		    dl_primstr(reqprim)));
	}

	switch (reqprim) {
	case DL_UNBIND_REQ:
		/*
		 * NOTE: we mark the unbind as complete even if we got a
		 * DL_ERROR_ACK, since there's not much else we can do.
		 */
		mutex_enter(&ill->ill_lock);
		ill->ill_state_flags &= ~ILL_DL_UNBIND_IN_PROGRESS;
		cv_signal(&ill->ill_cv);
		mutex_exit(&ill->ill_lock);
		break;

	case DL_ENABMULTI_REQ:
		if (prim == DL_OK_ACK) {
			if (ill->ill_dlpi_multicast_state == IDS_INPROGRESS)
				ill->ill_dlpi_multicast_state = IDS_OK;
		}
		break;
	}

	/*
	 * The message is one we're waiting for (or DL_NOTIFY_IND), but we
	 * need to become writer to continue to process it.  Because an
	 * exclusive operation doesn't complete until replies to all queued
	 * DLPI messages have been received, we know we're in the middle of an
	 * exclusive operation and pass CUR_OP (except for DL_NOTIFY_IND).
	 *
	 * As required by qwriter_ip(), we refhold the ill; it will refrele.
	 * Since this is on the ill stream we unconditionally bump up the
	 * refcount without doing ILL_CAN_LOOKUP().
	 */
	ill_refhold(ill);
	if (prim == DL_NOTIFY_IND)
		qwriter_ip(ill, q, mp, ip_rput_dlpi_writer, NEW_OP, B_FALSE);
	else
		qwriter_ip(ill, q, mp, ip_rput_dlpi_writer, CUR_OP, B_FALSE);
}

/*
 * Handling of DLPI messages that require exclusive access to the ipsq.
 *
 * Need to do ill_pending_mp_release on ioctl completion, which could
 * happen here. (along with mi_copy_done)
 */
/* ARGSUSED */
static void
ip_rput_dlpi_writer(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	dl_ok_ack_t	*dloa = (dl_ok_ack_t *)mp->b_rptr;
	dl_error_ack_t	*dlea = (dl_error_ack_t *)dloa;
	int		err = 0;
	ill_t		*ill;
	ipif_t		*ipif = NULL;
	mblk_t		*mp1 = NULL;
	conn_t		*connp = NULL;
	t_uscalar_t	paddrreq;
	mblk_t		*mp_hw;
	boolean_t	success;
	boolean_t	ioctl_aborted = B_FALSE;
	boolean_t	log = B_TRUE;
	ip_stack_t		*ipst;

	ip1dbg(("ip_rput_dlpi_writer .."));
	ill = (ill_t *)q->q_ptr;
	ASSERT(ipsq == ill->ill_phyint->phyint_ipsq);

	ASSERT(IAM_WRITER_ILL(ill));

	ipst = ill->ill_ipst;

	/*
	 * ipsq_pending_mp and ipsq_pending_ipif track each other. i.e.
	 * both are null or non-null. However we can assert that only
	 * after grabbing the ipsq_lock. So we don't make any assertion
	 * here and in other places in the code.
	 */
	ipif = ipsq->ipsq_pending_ipif;
	/*
	 * The current ioctl could have been aborted by the user and a new
	 * ioctl to bring up another ill could have started. We could still
	 * get a response from the driver later.
	 */
	if (ipif != NULL && ipif->ipif_ill != ill)
		ioctl_aborted = B_TRUE;

	switch (dloa->dl_primitive) {
	case DL_ERROR_ACK:
		ip1dbg(("ip_rput_dlpi_writer: got DL_ERROR_ACK for %s\n",
		    dl_primstr(dlea->dl_error_primitive)));

		switch (dlea->dl_error_primitive) {
		case DL_DISABMULTI_REQ:
			if (!ill->ill_isv6)
				ipsq_current_finish(ipsq);
			ill_dlpi_done(ill, dlea->dl_error_primitive);
			break;
		case DL_PROMISCON_REQ:
		case DL_PROMISCOFF_REQ:
		case DL_UNBIND_REQ:
		case DL_ATTACH_REQ:
		case DL_INFO_REQ:
			ill_dlpi_done(ill, dlea->dl_error_primitive);
			break;
		case DL_NOTIFY_REQ:
			ill_dlpi_done(ill, DL_NOTIFY_REQ);
			log = B_FALSE;
			break;
		case DL_PHYS_ADDR_REQ:
			/*
			 * For IPv6 only, there are two additional
			 * phys_addr_req's sent to the driver to get the
			 * IPv6 token and lla. This allows IP to acquire
			 * the hardware address format for a given interface
			 * without having built in knowledge of the hardware
			 * address. ill_phys_addr_pend keeps track of the last
			 * DL_PAR sent so we know which response we are
			 * dealing with. ill_dlpi_done will update
			 * ill_phys_addr_pend when it sends the next req.
			 * We don't complete the IOCTL until all three DL_PARs
			 * have been attempted, so set *_len to 0 and break.
			 */
			paddrreq = ill->ill_phys_addr_pend;
			ill_dlpi_done(ill, DL_PHYS_ADDR_REQ);
			if (paddrreq == DL_IPV6_TOKEN) {
				ill->ill_token_length = 0;
				log = B_FALSE;
				break;
			} else if (paddrreq == DL_IPV6_LINK_LAYER_ADDR) {
				ill->ill_nd_lla_len = 0;
				log = B_FALSE;
				break;
			}
			/*
			 * Something went wrong with the DL_PHYS_ADDR_REQ.
			 * We presumably have an IOCTL hanging out waiting
			 * for completion. Find it and complete the IOCTL
			 * with the error noted.
			 * However, ill_dl_phys was called on an ill queue
			 * (from SIOCSLIFNAME), thus conn_pending_ill is not
			 * set. But the ioctl is known to be pending on ill_wq.
			 */
			if (!ill->ill_ifname_pending)
				break;
			ill->ill_ifname_pending = 0;
			if (!ioctl_aborted)
				mp1 = ipsq_pending_mp_get(ipsq, &connp);
			if (mp1 != NULL) {
				/*
				 * This operation (SIOCSLIFNAME) must have
				 * happened on the ill. Assert there is no conn
				 */
				ASSERT(connp == NULL);
				q = ill->ill_wq;
			}
			break;
		case DL_BIND_REQ:
			ill_dlpi_done(ill, DL_BIND_REQ);
			if (ill->ill_ifname_pending)
				break;
			/*
			 * Something went wrong with the bind.  We presumably
			 * have an IOCTL hanging out waiting for completion.
			 * Find it, take down the interface that was coming
			 * up, and complete the IOCTL with the error noted.
			 */
			if (!ioctl_aborted)
				mp1 = ipsq_pending_mp_get(ipsq, &connp);
			if (mp1 != NULL) {
				/*
				 * This operation (SIOCSLIFFLAGS) must have
				 * happened from a conn.
				 */
				ASSERT(connp != NULL);
				q = CONNP_TO_WQ(connp);
				if (ill->ill_move_in_progress) {
					ILL_CLEAR_MOVE(ill);
				}
				(void) ipif_down(ipif, NULL, NULL);
				/* error is set below the switch */
			}
			break;
		case DL_ENABMULTI_REQ:
			if (!ill->ill_isv6)
				ipsq_current_finish(ipsq);
			ill_dlpi_done(ill, DL_ENABMULTI_REQ);

			if (ill->ill_dlpi_multicast_state == IDS_INPROGRESS)
				ill->ill_dlpi_multicast_state = IDS_FAILED;
			if (ill->ill_dlpi_multicast_state == IDS_FAILED) {
				ipif_t *ipif;

				printf("ip: joining multicasts failed (%d)"
				    " on %s - will use link layer "
				    "broadcasts for multicast\n",
				    dlea->dl_errno, ill->ill_name);

				/*
				 * Set up the multicast mapping alone.
				 * writer, so ok to access ill->ill_ipif
				 * without any lock.
				 */
				ipif = ill->ill_ipif;
				mutex_enter(&ill->ill_phyint->phyint_lock);
				ill->ill_phyint->phyint_flags |=
				    PHYI_MULTI_BCAST;
				mutex_exit(&ill->ill_phyint->phyint_lock);

				if (!ill->ill_isv6) {
					(void) ipif_arp_setup_multicast(ipif,
					    NULL);
				} else {
					(void) ipif_ndp_setup_multicast(ipif,
					    NULL);
				}
			}
			freemsg(mp);	/* Don't want to pass this up */
			return;
		case DL_CONTROL_REQ:
			ip1dbg(("ip_rput_dlpi_writer: got DL_ERROR_ACK for "
			    "DL_CONTROL_REQ\n"));
			ill_dlpi_done(ill, dlea->dl_error_primitive);
			freemsg(mp);
			return;
		case DL_CAPABILITY_REQ:
			ip1dbg(("ip_rput_dlpi_writer: got DL_ERROR_ACK for "
			    "DL_CAPABILITY REQ\n"));
			if (ill->ill_dlpi_capab_state == IDCS_PROBE_SENT)
				ill->ill_dlpi_capab_state = IDCS_FAILED;
			ill_capability_done(ill);
			freemsg(mp);
			return;
		}
		/*
		 * Note the error for IOCTL completion (mp1 is set when
		 * ready to complete ioctl). If ill_ifname_pending_err is
		 * set, an error occured during plumbing (ill_ifname_pending),
		 * so we want to report that error.
		 *
		 * NOTE: there are two addtional DL_PHYS_ADDR_REQ's
		 * (DL_IPV6_TOKEN and DL_IPV6_LINK_LAYER_ADDR) that are
		 * expected to get errack'd if the driver doesn't support
		 * these flags (e.g. ethernet). log will be set to B_FALSE
		 * if these error conditions are encountered.
		 */
		if (mp1 != NULL) {
			if (ill->ill_ifname_pending_err != 0)  {
				err = ill->ill_ifname_pending_err;
				ill->ill_ifname_pending_err = 0;
			} else {
				err = dlea->dl_unix_errno ?
				    dlea->dl_unix_errno : ENXIO;
			}
		/*
		 * If we're plumbing an interface and an error hasn't already
		 * been saved, set ill_ifname_pending_err to the error passed
		 * up. Ignore the error if log is B_FALSE (see comment above).
		 */
		} else if (log && ill->ill_ifname_pending &&
		    ill->ill_ifname_pending_err == 0) {
			ill->ill_ifname_pending_err = dlea->dl_unix_errno ?
			    dlea->dl_unix_errno : ENXIO;
		}

		if (log)
			ip_dlpi_error(ill, dlea->dl_error_primitive,
			    dlea->dl_errno, dlea->dl_unix_errno);
		break;
	case DL_CAPABILITY_ACK:
		ill_capability_ack(ill, mp);
		/*
		 * The message has been handed off to ill_capability_ack
		 * and must not be freed below
		 */
		mp = NULL;
		break;

	case DL_CONTROL_ACK:
		/* We treat all of these as "fire and forget" */
		ill_dlpi_done(ill, DL_CONTROL_REQ);
		break;
	case DL_INFO_ACK:
		/* Call a routine to handle this one. */
		ill_dlpi_done(ill, DL_INFO_REQ);
		ip_ll_subnet_defaults(ill, mp);
		ASSERT(!MUTEX_HELD(&ill->ill_phyint->phyint_ipsq->ipsq_lock));
		return;
	case DL_BIND_ACK:
		/*
		 * We should have an IOCTL waiting on this unless
		 * sent by ill_dl_phys, in which case just return
		 */
		ill_dlpi_done(ill, DL_BIND_REQ);
		if (ill->ill_ifname_pending)
			break;

		if (!ioctl_aborted)
			mp1 = ipsq_pending_mp_get(ipsq, &connp);
		if (mp1 == NULL)
			break;
		/*
		 * Because mp1 was added by ill_dl_up(), and it always
		 * passes a valid connp, connp must be valid here.
		 */
		ASSERT(connp != NULL);
		q = CONNP_TO_WQ(connp);

		/*
		 * We are exclusive. So nothing can change even after
		 * we get the pending mp. If need be we can put it back
		 * and restart, as in calling ipif_arp_up()  below.
		 */
		ip1dbg(("ip_rput_dlpi: bind_ack %s\n", ill->ill_name));

		mutex_enter(&ill->ill_lock);
		ill->ill_dl_up = 1;
		ill_nic_event_dispatch(ill, 0, NE_UP, NULL, 0);
		mutex_exit(&ill->ill_lock);

		/*
		 * Now bring up the resolver; when that is complete, we'll
		 * create IREs.  Note that we intentionally mirror what
		 * ipif_up() would have done, because we got here by way of
		 * ill_dl_up(), which stopped ipif_up()'s processing.
		 */
		if (ill->ill_isv6) {
			/*
			 * v6 interfaces.
			 * Unlike ARP which has to do another bind
			 * and attach, once we get here we are
			 * done with NDP. Except in the case of
			 * ILLF_XRESOLV, in which case we send an
			 * AR_INTERFACE_UP to the external resolver.
			 * If all goes well, the ioctl will complete
			 * in ip_rput(). If there's an error, we
			 * complete it here.
			 */
			if ((err = ipif_ndp_up(ipif)) == 0) {
				if (ill->ill_flags & ILLF_XRESOLV) {
					mutex_enter(&connp->conn_lock);
					mutex_enter(&ill->ill_lock);
					success = ipsq_pending_mp_add(
					    connp, ipif, q, mp1, 0);
					mutex_exit(&ill->ill_lock);
					mutex_exit(&connp->conn_lock);
					if (success) {
						err = ipif_resolver_up(ipif,
						    Res_act_initial);
						if (err == EINPROGRESS) {
							freemsg(mp);
							return;
						}
						ASSERT(err != 0);
						mp1 = ipsq_pending_mp_get(ipsq,
						    &connp);
						ASSERT(mp1 != NULL);
					} else {
						/* conn has started closing */
						err = EINTR;
					}
				} else { /* Non XRESOLV interface */
					(void) ipif_resolver_up(ipif,
					    Res_act_initial);
					err = ipif_up_done_v6(ipif);
				}
			}
		} else if (ill->ill_net_type == IRE_IF_RESOLVER) {
			/*
			 * ARP and other v4 external resolvers.
			 * Leave the pending mblk intact so that
			 * the ioctl completes in ip_rput().
			 */
			mutex_enter(&connp->conn_lock);
			mutex_enter(&ill->ill_lock);
			success = ipsq_pending_mp_add(connp, ipif, q, mp1, 0);
			mutex_exit(&ill->ill_lock);
			mutex_exit(&connp->conn_lock);
			if (success) {
				err = ipif_resolver_up(ipif, Res_act_initial);
				if (err == EINPROGRESS) {
					freemsg(mp);
					return;
				}
				ASSERT(err != 0);
				mp1 = ipsq_pending_mp_get(ipsq, &connp);
			} else {
				/* The conn has started closing */
				err = EINTR;
			}
		} else {
			/*
			 * This one is complete. Reply to pending ioctl.
			 */
			(void) ipif_resolver_up(ipif, Res_act_initial);
			err = ipif_up_done(ipif);
		}

		if ((err == 0) && (ill->ill_up_ipifs)) {
			err = ill_up_ipifs(ill, q, mp1);
			if (err == EINPROGRESS) {
				freemsg(mp);
				return;
			}
		}

		if (ill->ill_up_ipifs) {
			ill_group_cleanup(ill);
		}

		break;
	case DL_NOTIFY_IND: {
		dl_notify_ind_t *notify = (dl_notify_ind_t *)mp->b_rptr;
		ire_t *ire;
		boolean_t need_ire_walk_v4 = B_FALSE;
		boolean_t need_ire_walk_v6 = B_FALSE;

		switch (notify->dl_notification) {
		case DL_NOTE_PHYS_ADDR:
			err = ill_set_phys_addr(ill, mp);
			break;

		case DL_NOTE_FASTPATH_FLUSH:
			ill_fastpath_flush(ill);
			break;

		case DL_NOTE_SDU_SIZE:
			/*
			 * Change the MTU size of the interface, of all
			 * attached ipif's, and of all relevant ire's.  The
			 * new value's a uint32_t at notify->dl_data.
			 * Mtu change Vs. new ire creation - protocol below.
			 *
			 * a Mark the ipif as IPIF_CHANGING.
			 * b Set the new mtu in the ipif.
			 * c Change the ire_max_frag on all affected ires
			 * d Unmark the IPIF_CHANGING
			 *
			 * To see how the protocol works, assume an interface
			 * route is also being added simultaneously by
			 * ip_rt_add and let 'ipif' be the ipif referenced by
			 * the ire. If the ire is created before step a,
			 * it will be cleaned up by step c. If the ire is
			 * created after step d, it will see the new value of
			 * ipif_mtu. Any attempt to create the ire between
			 * steps a to d will fail because of the IPIF_CHANGING
			 * flag. Note that ire_create() is passed a pointer to
			 * the ipif_mtu, and not the value. During ire_add
			 * under the bucket lock, the ire_max_frag of the
			 * new ire being created is set from the ipif/ire from
			 * which it is being derived.
			 */
			mutex_enter(&ill->ill_lock);
			ill->ill_max_frag = (uint_t)notify->dl_data;

			/*
			 * If an SIOCSLIFLNKINFO has changed the ill_max_mtu
			 * leave it alone
			 */
			if (ill->ill_mtu_userspecified) {
				mutex_exit(&ill->ill_lock);
				break;
			}
			ill->ill_max_mtu = ill->ill_max_frag;
			if (ill->ill_isv6) {
				if (ill->ill_max_mtu < IPV6_MIN_MTU)
					ill->ill_max_mtu = IPV6_MIN_MTU;
			} else {
				if (ill->ill_max_mtu < IP_MIN_MTU)
					ill->ill_max_mtu = IP_MIN_MTU;
			}
			for (ipif = ill->ill_ipif; ipif != NULL;
			    ipif = ipif->ipif_next) {
				/*
				 * Don't override the mtu if the user
				 * has explicitly set it.
				 */
				if (ipif->ipif_flags & IPIF_FIXEDMTU)
					continue;
				ipif->ipif_mtu = (uint_t)notify->dl_data;
				if (ipif->ipif_isv6)
					ire = ipif_to_ire_v6(ipif);
				else
					ire = ipif_to_ire(ipif);
				if (ire != NULL) {
					ire->ire_max_frag = ipif->ipif_mtu;
					ire_refrele(ire);
				}
				if (ipif->ipif_flags & IPIF_UP) {
					if (ill->ill_isv6)
						need_ire_walk_v6 = B_TRUE;
					else
						need_ire_walk_v4 = B_TRUE;
				}
			}
			mutex_exit(&ill->ill_lock);
			if (need_ire_walk_v4)
				ire_walk_v4(ill_mtu_change, (char *)ill,
				    ALL_ZONES, ipst);
			if (need_ire_walk_v6)
				ire_walk_v6(ill_mtu_change, (char *)ill,
				    ALL_ZONES, ipst);
			break;
		case DL_NOTE_LINK_UP:
		case DL_NOTE_LINK_DOWN: {
			/*
			 * We are writer. ill / phyint / ipsq assocs stable.
			 * The RUNNING flag reflects the state of the link.
			 */
			phyint_t *phyint = ill->ill_phyint;
			uint64_t new_phyint_flags;
			boolean_t changed = B_FALSE;
			boolean_t went_up;

			went_up = notify->dl_notification == DL_NOTE_LINK_UP;
			mutex_enter(&phyint->phyint_lock);
			new_phyint_flags = went_up ?
			    phyint->phyint_flags | PHYI_RUNNING :
			    phyint->phyint_flags & ~PHYI_RUNNING;
			if (new_phyint_flags != phyint->phyint_flags) {
				phyint->phyint_flags = new_phyint_flags;
				changed = B_TRUE;
			}
			mutex_exit(&phyint->phyint_lock);
			/*
			 * ill_restart_dad handles the DAD restart and routing
			 * socket notification logic.
			 */
			if (changed) {
				ill_restart_dad(phyint->phyint_illv4, went_up);
				ill_restart_dad(phyint->phyint_illv6, went_up);
			}
			break;
		}
		case DL_NOTE_PROMISC_ON_PHYS:
			IPSECHW_DEBUG(IPSECHW_PKT, ("ip_rput_dlpi_writer: "
			    "got a DL_NOTE_PROMISC_ON_PHYS\n"));
			mutex_enter(&ill->ill_lock);
			ill->ill_promisc_on_phys = B_TRUE;
			mutex_exit(&ill->ill_lock);
			break;
		case DL_NOTE_PROMISC_OFF_PHYS:
			IPSECHW_DEBUG(IPSECHW_PKT, ("ip_rput_dlpi_writer: "
			    "got a DL_NOTE_PROMISC_OFF_PHYS\n"));
			mutex_enter(&ill->ill_lock);
			ill->ill_promisc_on_phys = B_FALSE;
			mutex_exit(&ill->ill_lock);
			break;
		case DL_NOTE_CAPAB_RENEG:
			/*
			 * Something changed on the driver side.
			 * It wants us to renegotiate the capabilities
			 * on this ill. One possible cause is the aggregation
			 * interface under us where a port got added or
			 * went away.
			 *
			 * If the capability negotiation is already done
			 * or is in progress, reset the capabilities and
			 * mark the ill's ill_capab_reneg to be B_TRUE,
			 * so that when the ack comes back, we can start
			 * the renegotiation process.
			 *
			 * Note that if ill_capab_reneg is already B_TRUE
			 * (ill_dlpi_capab_state is IDS_UNKNOWN in this case),
			 * the capability resetting request has been sent
			 * and the renegotiation has not been started yet;
			 * nothing needs to be done in this case.
			 */
			ipsq_current_start(ipsq, ill->ill_ipif, 0);
			ill_capability_reset(ill, B_TRUE);
			ipsq_current_finish(ipsq);
			break;
		default:
			ip0dbg(("ip_rput_dlpi_writer: unknown notification "
			    "type 0x%x for DL_NOTIFY_IND\n",
			    notify->dl_notification));
			break;
		}

		/*
		 * As this is an asynchronous operation, we
		 * should not call ill_dlpi_done
		 */
		break;
	}
	case DL_NOTIFY_ACK: {
		dl_notify_ack_t *noteack = (dl_notify_ack_t *)mp->b_rptr;

		if (noteack->dl_notifications & DL_NOTE_LINK_UP)
			ill->ill_note_link = 1;
		ill_dlpi_done(ill, DL_NOTIFY_REQ);
		break;
	}
	case DL_PHYS_ADDR_ACK: {
		/*
		 * As part of plumbing the interface via SIOCSLIFNAME,
		 * ill_dl_phys() will queue a series of DL_PHYS_ADDR_REQs,
		 * whose answers we receive here.  As each answer is received,
		 * we call ill_dlpi_done() to dispatch the next request as
		 * we're processing the current one.  Once all answers have
		 * been received, we use ipsq_pending_mp_get() to dequeue the
		 * outstanding IOCTL and reply to it.  (Because ill_dl_phys()
		 * is invoked from an ill queue, conn_oper_pending_ill is not
		 * available, but we know the ioctl is pending on ill_wq.)
		 */
		uint_t paddrlen, paddroff;

		paddrreq = ill->ill_phys_addr_pend;
		paddrlen = ((dl_phys_addr_ack_t *)mp->b_rptr)->dl_addr_length;
		paddroff = ((dl_phys_addr_ack_t *)mp->b_rptr)->dl_addr_offset;

		ill_dlpi_done(ill, DL_PHYS_ADDR_REQ);
		if (paddrreq == DL_IPV6_TOKEN) {
			/*
			 * bcopy to low-order bits of ill_token
			 *
			 * XXX Temporary hack - currently, all known tokens
			 * are 64 bits, so I'll cheat for the moment.
			 */
			bcopy(mp->b_rptr + paddroff,
			    &ill->ill_token.s6_addr32[2], paddrlen);
			ill->ill_token_length = paddrlen;
			break;
		} else if (paddrreq == DL_IPV6_LINK_LAYER_ADDR) {
			ASSERT(ill->ill_nd_lla_mp == NULL);
			ill_set_ndmp(ill, mp, paddroff, paddrlen);
			mp = NULL;
			break;
		}

		ASSERT(paddrreq == DL_CURR_PHYS_ADDR);
		ASSERT(ill->ill_phys_addr_mp == NULL);
		if (!ill->ill_ifname_pending)
			break;
		ill->ill_ifname_pending = 0;
		if (!ioctl_aborted)
			mp1 = ipsq_pending_mp_get(ipsq, &connp);
		if (mp1 != NULL) {
			ASSERT(connp == NULL);
			q = ill->ill_wq;
		}
		/*
		 * If any error acks received during the plumbing sequence,
		 * ill_ifname_pending_err will be set. Break out and send up
		 * the error to the pending ioctl.
		 */
		if (ill->ill_ifname_pending_err != 0) {
			err = ill->ill_ifname_pending_err;
			ill->ill_ifname_pending_err = 0;
			break;
		}

		ill->ill_phys_addr_mp = mp;
		ill->ill_phys_addr = mp->b_rptr + paddroff;
		mp = NULL;

		/*
		 * If paddrlen is zero, the DLPI provider doesn't support
		 * physical addresses.  The other two tests were historical
		 * workarounds for bugs in our former PPP implementation, but
		 * now other things have grown dependencies on them -- e.g.,
		 * the tun module specifies a dl_addr_length of zero in its
		 * DL_BIND_ACK, but then specifies an incorrect value in its
		 * DL_PHYS_ADDR_ACK.  These bogus checks need to be removed,
		 * but only after careful testing ensures that all dependent
		 * broken DLPI providers have been fixed.
		 */
		if (paddrlen == 0 || ill->ill_phys_addr_length == 0 ||
		    ill->ill_phys_addr_length == IP_ADDR_LEN) {
			ill->ill_phys_addr = NULL;
		} else if (paddrlen != ill->ill_phys_addr_length) {
			ip0dbg(("DL_PHYS_ADDR_ACK: got addrlen %d, expected %d",
			    paddrlen, ill->ill_phys_addr_length));
			err = EINVAL;
			break;
		}

		if (ill->ill_nd_lla_mp == NULL) {
			if ((mp_hw = copyb(ill->ill_phys_addr_mp)) == NULL) {
				err = ENOMEM;
				break;
			}
			ill_set_ndmp(ill, mp_hw, paddroff, paddrlen);
		}

		/*
		 * Set the interface token.  If the zeroth interface address
		 * is unspecified, then set it to the link local address.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ill->ill_token))
			(void) ill_setdefaulttoken(ill);

		ASSERT(ill->ill_ipif->ipif_id == 0);
		if (ipif != NULL &&
		    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr)) {
			(void) ipif_setlinklocal(ipif);
		}
		break;
	}
	case DL_OK_ACK:
		ip2dbg(("DL_OK_ACK %s (0x%x)\n",
		    dl_primstr((int)dloa->dl_correct_primitive),
		    dloa->dl_correct_primitive));
		switch (dloa->dl_correct_primitive) {
		case DL_ENABMULTI_REQ:
		case DL_DISABMULTI_REQ:
			if (!ill->ill_isv6)
				ipsq_current_finish(ipsq);
			ill_dlpi_done(ill, dloa->dl_correct_primitive);
			break;
		case DL_PROMISCON_REQ:
		case DL_PROMISCOFF_REQ:
		case DL_UNBIND_REQ:
		case DL_ATTACH_REQ:
			ill_dlpi_done(ill, dloa->dl_correct_primitive);
			break;
		}
		break;
	default:
		break;
	}

	freemsg(mp);
	if (mp1 != NULL) {
		/*
		 * The operation must complete without EINPROGRESS
		 * since ipsq_pending_mp_get() has removed the mblk
		 * from ipsq_pending_mp.  Otherwise, the operation
		 * will be stuck forever in the ipsq.
		 */
		ASSERT(err != EINPROGRESS);

		switch (ipsq->ipsq_current_ioctl) {
		case 0:
			ipsq_current_finish(ipsq);
			break;

		case SIOCLIFADDIF:
		case SIOCSLIFNAME:
			ip_ioctl_finish(q, mp1, err, COPYOUT, ipsq);
			break;

		default:
			ip_ioctl_finish(q, mp1, err, NO_COPYOUT, ipsq);
			break;
		}
	}
}

/*
 * ip_rput_other is called by ip_rput to handle messages modifying the global
 * state in IP. Normally called as writer. Exception SIOCGTUNPARAM (shared)
 */
/* ARGSUSED */
void
ip_rput_other(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	ill_t		*ill;
	struct iocblk	*iocp;
	mblk_t		*mp1;
	conn_t		*connp = NULL;

	ip1dbg(("ip_rput_other "));
	ill = (ill_t *)q->q_ptr;
	/*
	 * This routine is not a writer in the case of SIOCGTUNPARAM
	 * in which case ipsq is NULL.
	 */
	if (ipsq != NULL) {
		ASSERT(IAM_WRITER_IPSQ(ipsq));
		ASSERT(ipsq == ill->ill_phyint->phyint_ipsq);
	}

	switch (mp->b_datap->db_type) {
	case M_ERROR:
	case M_HANGUP:
		/*
		 * The device has a problem.  We force the ILL down.  It can
		 * be brought up again manually using SIOCSIFFLAGS (via
		 * ifconfig or equivalent).
		 */
		ASSERT(ipsq != NULL);
		if (mp->b_rptr < mp->b_wptr)
			ill->ill_error = (int)(*mp->b_rptr & 0xFF);
		if (ill->ill_error == 0)
			ill->ill_error = ENXIO;
		if (!ill_down_start(q, mp))
			return;
		ipif_all_down_tail(ipsq, q, mp, NULL);
		break;
	case M_IOCACK:
		iocp = (struct iocblk *)mp->b_rptr;
		ASSERT(iocp->ioc_cmd != DL_IOC_HDR_INFO);
		switch (iocp->ioc_cmd) {
		case SIOCSTUNPARAM:
		case OSIOCSTUNPARAM:
			ASSERT(ipsq != NULL);
			/*
			 * Finish socket ioctl passed through to tun.
			 * We should have an IOCTL waiting on this.
			 */
			mp1 = ipsq_pending_mp_get(ipsq, &connp);
			if (ill->ill_isv6) {
				struct iftun_req *ta;

				/*
				 * if a source or destination is
				 * being set, try and set the link
				 * local address for the tunnel
				 */
				ta = (struct iftun_req *)mp->b_cont->
				    b_cont->b_rptr;
				if (ta->ifta_flags & (IFTUN_SRC | IFTUN_DST)) {
					ipif_set_tun_llink(ill, ta);
				}

			}
			if (mp1 != NULL) {
				/*
				 * Now copy back the b_next/b_prev used by
				 * mi code for the mi_copy* functions.
				 * See ip_sioctl_tunparam() for the reason.
				 * Also protect against missing b_cont.
				 */
				if (mp->b_cont != NULL) {
					mp->b_cont->b_next =
					    mp1->b_cont->b_next;
					mp->b_cont->b_prev =
					    mp1->b_cont->b_prev;
				}
				inet_freemsg(mp1);
				ASSERT(connp != NULL);
				ip_ioctl_finish(CONNP_TO_WQ(connp), mp,
				    iocp->ioc_error, NO_COPYOUT, ipsq);
			} else {
				ASSERT(connp == NULL);
				putnext(q, mp);
			}
			break;
		case SIOCGTUNPARAM:
		case OSIOCGTUNPARAM:
			/*
			 * This is really M_IOCDATA from the tunnel driver.
			 * convert back and complete the ioctl.
			 * We should have an IOCTL waiting on this.
			 */
			mp1 = ill_pending_mp_get(ill, &connp, iocp->ioc_id);
			if (mp1) {
				/*
				 * Now copy back the b_next/b_prev used by
				 * mi code for the mi_copy* functions.
				 * See ip_sioctl_tunparam() for the reason.
				 * Also protect against missing b_cont.
				 */
				if (mp->b_cont != NULL) {
					mp->b_cont->b_next =
					    mp1->b_cont->b_next;
					mp->b_cont->b_prev =
					    mp1->b_cont->b_prev;
				}
				inet_freemsg(mp1);
				if (iocp->ioc_error == 0)
					mp->b_datap->db_type = M_IOCDATA;
				ASSERT(connp != NULL);
				ip_ioctl_finish(CONNP_TO_WQ(connp), mp,
				    iocp->ioc_error, COPYOUT, NULL);
			} else {
				ASSERT(connp == NULL);
				putnext(q, mp);
			}
			break;
		default:
			break;
		}
		break;
	case M_IOCNAK:
		iocp = (struct iocblk *)mp->b_rptr;

		switch (iocp->ioc_cmd) {
			int mode;

		case DL_IOC_HDR_INFO:
			/*
			 * If this was the first attempt turn of the
			 * fastpath probing.
			 */
			mutex_enter(&ill->ill_lock);
			if (ill->ill_dlpi_fastpath_state == IDS_INPROGRESS) {
				ill->ill_dlpi_fastpath_state = IDS_FAILED;
				mutex_exit(&ill->ill_lock);
				ill_fastpath_nack(ill);
				ip1dbg(("ip_rput: DLPI fastpath off on "
				    "interface %s\n",
				    ill->ill_name));
			} else {
				mutex_exit(&ill->ill_lock);
			}
			freemsg(mp);
			break;
		case SIOCSTUNPARAM:
		case OSIOCSTUNPARAM:
			ASSERT(ipsq != NULL);
			/*
			 * Finish socket ioctl passed through to tun
			 * We should have an IOCTL waiting on this.
			 */
			/* FALLTHRU */
		case SIOCGTUNPARAM:
		case OSIOCGTUNPARAM:
			/*
			 * This is really M_IOCDATA from the tunnel driver.
			 * convert back and complete the ioctl.
			 * We should have an IOCTL waiting on this.
			 */
			if (iocp->ioc_cmd == SIOCGTUNPARAM ||
			    iocp->ioc_cmd == OSIOCGTUNPARAM) {
				mp1 = ill_pending_mp_get(ill, &connp,
				    iocp->ioc_id);
				mode = COPYOUT;
				ipsq = NULL;
			} else {
				mp1 = ipsq_pending_mp_get(ipsq, &connp);
				mode = NO_COPYOUT;
			}
			if (mp1 != NULL) {
				/*
				 * Now copy back the b_next/b_prev used by
				 * mi code for the mi_copy* functions.
				 * See ip_sioctl_tunparam() for the reason.
				 * Also protect against missing b_cont.
				 */
				if (mp->b_cont != NULL) {
					mp->b_cont->b_next =
					    mp1->b_cont->b_next;
					mp->b_cont->b_prev =
					    mp1->b_cont->b_prev;
				}
				inet_freemsg(mp1);
				if (iocp->ioc_error == 0)
					iocp->ioc_error = EINVAL;
				ASSERT(connp != NULL);
				ip_ioctl_finish(CONNP_TO_WQ(connp), mp,
				    iocp->ioc_error, mode, ipsq);
			} else {
				ASSERT(connp == NULL);
				putnext(q, mp);
			}
			break;
		default:
			break;
		}
	default:
		break;
	}
}

/*
 * NOTE : This function does not ire_refrele the ire argument passed in.
 *
 * IPQoS notes
 * IP policy is invoked twice for a forwarded packet, once on the read side
 * and again on the write side if both, IPP_FWD_IN and IPP_FWD_OUT are
 * enabled. An additional parameter, in_ill, has been added for this purpose.
 * Note that in_ill could be NULL when called from ip_rput_forward_multicast
 * because ip_mroute drops this information.
 *
 */
void
ip_rput_forward(ire_t *ire, ipha_t *ipha, mblk_t *mp, ill_t *in_ill)
{
	uint32_t	old_pkt_len;
	uint32_t	pkt_len;
	queue_t	*q;
	uint32_t	sum;
#define	rptr	((uchar_t *)ipha)
	uint32_t	max_frag;
	uint32_t	ill_index;
	ill_t		*out_ill;
	mib2_ipIfStatsEntry_t *mibptr;
	ip_stack_t	*ipst = ((ill_t *)(ire->ire_stq->q_ptr))->ill_ipst;

	/* Get the ill_index of the incoming ILL */
	ill_index = (in_ill != NULL) ? in_ill->ill_phyint->phyint_ifindex : 0;
	mibptr = (in_ill != NULL) ? in_ill->ill_ip_mib : &ipst->ips_ip_mib;

	/* Initiate Read side IPPF processing */
	if (IPP_ENABLED(IPP_FWD_IN, ipst)) {
		ip_process(IPP_FWD_IN, &mp, ill_index);
		if (mp == NULL) {
			ip2dbg(("ip_rput_forward: pkt dropped/deferred "\
			    "during IPPF processing\n"));
			return;
		}
	}

	/* Adjust the checksum to reflect the ttl decrement. */
	sum = (int)ipha->ipha_hdr_checksum + IP_HDR_CSUM_TTL_ADJUST;
	ipha->ipha_hdr_checksum = (uint16_t)(sum + (sum >> 16));

	if (ipha->ipha_ttl-- <= 1) {
		if (ip_csum_hdr(ipha)) {
			BUMP_MIB(mibptr, ipIfStatsInCksumErrs);
			goto drop_pkt;
		}
		/*
		 * Note: ire_stq this will be NULL for multicast
		 * datagrams using the long path through arp (the IRE
		 * is not an IRE_CACHE). This should not cause
		 * problems since we don't generate ICMP errors for
		 * multicast packets.
		 */
		BUMP_MIB(mibptr, ipIfStatsForwProhibits);
		q = ire->ire_stq;
		if (q != NULL) {
			/* Sent by forwarding path, and router is global zone */
			icmp_time_exceeded(q, mp, ICMP_TTL_EXCEEDED,
			    GLOBAL_ZONEID, ipst);
		} else
			freemsg(mp);
		return;
	}

	/*
	 * Don't forward if the interface is down
	 */
	if (ire->ire_ipif->ipif_ill->ill_ipif_up_count == 0) {
		BUMP_MIB(mibptr, ipIfStatsInDiscards);
		ip2dbg(("ip_rput_forward:interface is down\n"));
		goto drop_pkt;
	}

	/* Get the ill_index of the outgoing ILL */
	out_ill = ire_to_ill(ire);
	ill_index = out_ill->ill_phyint->phyint_ifindex;

	DTRACE_PROBE4(ip4__forwarding__start,
	    ill_t *, in_ill, ill_t *, out_ill, ipha_t *, ipha, mblk_t *, mp);

	FW_HOOKS(ipst->ips_ip4_forwarding_event,
	    ipst->ips_ipv4firewall_forwarding,
	    in_ill, out_ill, ipha, mp, mp, 0, ipst);

	DTRACE_PROBE1(ip4__forwarding__end, mblk_t *, mp);

	if (mp == NULL)
		return;
	old_pkt_len = pkt_len = ntohs(ipha->ipha_length);

	if (is_system_labeled()) {
		mblk_t *mp1;

		if ((mp1 = tsol_ip_forward(ire, mp)) == NULL) {
			BUMP_MIB(mibptr, ipIfStatsForwProhibits);
			goto drop_pkt;
		}
		/* Size may have changed */
		mp = mp1;
		ipha = (ipha_t *)mp->b_rptr;
		pkt_len = ntohs(ipha->ipha_length);
	}

	/* Check if there are options to update */
	if (!IS_SIMPLE_IPH(ipha)) {
		if (ip_csum_hdr(ipha)) {
			BUMP_MIB(mibptr, ipIfStatsInCksumErrs);
			goto drop_pkt;
		}
		if (ip_rput_forward_options(mp, ipha, ire, ipst)) {
			BUMP_MIB(mibptr, ipIfStatsForwProhibits);
			return;
		}

		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
	}
	max_frag = ire->ire_max_frag;
	if (pkt_len > max_frag) {
		/*
		 * It needs fragging on its way out.  We haven't
		 * verified the header checksum yet.  Since we
		 * are going to put a surely good checksum in the
		 * outgoing header, we have to make sure that it
		 * was good coming in.
		 */
		if (ip_csum_hdr(ipha)) {
			BUMP_MIB(mibptr, ipIfStatsInCksumErrs);
			goto drop_pkt;
		}
		/* Initiate Write side IPPF processing */
		if (IPP_ENABLED(IPP_FWD_OUT, ipst)) {
			ip_process(IPP_FWD_OUT, &mp, ill_index);
			if (mp == NULL) {
				ip2dbg(("ip_rput_forward: pkt dropped/deferred"\
				    " during IPPF processing\n"));
				return;
			}
		}
		/*
		 * Handle labeled packet resizing.
		 *
		 * If we have added a label, inform ip_wput_frag() of its
		 * effect on the MTU for ICMP messages.
		 */
		if (pkt_len > old_pkt_len) {
			uint32_t secopt_size;

			secopt_size = pkt_len - old_pkt_len;
			if (secopt_size < max_frag)
				max_frag -= secopt_size;
		}

		ip_wput_frag(ire, mp, IB_PKT, max_frag, 0,
		    GLOBAL_ZONEID, ipst, NULL);
		ip2dbg(("ip_rput_forward:sent to ip_wput_frag\n"));
		return;
	}

	DTRACE_PROBE4(ip4__physical__out__start, ill_t *, NULL,
	    ill_t *, out_ill, ipha_t *, ipha, mblk_t *, mp);
	FW_HOOKS(ipst->ips_ip4_physical_out_event,
	    ipst->ips_ipv4firewall_physical_out,
	    NULL, out_ill, ipha, mp, mp, 0, ipst);
	DTRACE_PROBE1(ip4__physical__out__end, mblk_t *, mp);
	if (mp == NULL)
		return;

	mp->b_prev = (mblk_t *)IPP_FWD_OUT;
	ip1dbg(("ip_rput_forward: Calling ip_xmit_v4\n"));
	(void) ip_xmit_v4(mp, ire, NULL, B_FALSE, NULL);
	/* ip_xmit_v4 always consumes the packet */
	return;

drop_pkt:;
	ip1dbg(("ip_rput_forward: drop pkt\n"));
	freemsg(mp);
#undef	rptr
}

void
ip_rput_forward_multicast(ipaddr_t dst, mblk_t *mp, ipif_t *ipif)
{
	ire_t	*ire;
	ip_stack_t *ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(!ipif->ipif_isv6);
	/*
	 * Find an IRE which matches the destination and the outgoing
	 * queue in the cache table. All we need is an IRE_CACHE which
	 * is pointing at ipif->ipif_ill. If it is part of some ill group,
	 * then it is enough to have some IRE_CACHE in the group.
	 */
	if (ipif->ipif_flags & IPIF_POINTOPOINT)
		dst = ipif->ipif_pp_dst_addr;

	ire = ire_ctable_lookup(dst, 0, 0, ipif, ALL_ZONES, MBLK_GETLABEL(mp),
	    MATCH_IRE_ILL_GROUP | MATCH_IRE_SECATTR, ipst);
	if (ire == NULL) {
		/*
		 * Mark this packet to make it be delivered to
		 * ip_rput_forward after the new ire has been
		 * created.
		 */
		mp->b_prev = NULL;
		mp->b_next = mp;
		ip_newroute_ipif(ipif->ipif_ill->ill_wq, mp, ipif, dst,
		    NULL, 0, GLOBAL_ZONEID, &zero_info);
	} else {
		ip_rput_forward(ire, (ipha_t *)mp->b_rptr, mp, NULL);
		IRE_REFRELE(ire);
	}
}

/* Update any source route, record route or timestamp options */
static int
ip_rput_forward_options(mblk_t *mp, ipha_t *ipha, ire_t *ire, ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	uint32_t	ts;
	ire_t		*dst_ire = NULL;
	ire_t		*tmp_ire = NULL;
	timestruc_t	now;

	ip2dbg(("ip_rput_forward_options\n"));
	dst = ipha->ipha_dst;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_rput_forward_options: opt %d, len %d\n",
		    optval, opts.ipoptp_len));
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			/* Check if adminstratively disabled */
			if (!ipst->ips_ip_forward_src_routed) {
				if (ire->ire_stq != NULL) {
					/*
					 * Sent by forwarding path, and router
					 * is global zone
					 */
					icmp_unreachable(ire->ire_stq, mp,
					    ICMP_SOURCE_ROUTE_FAILED,
					    GLOBAL_ZONEID, ipst);
				} else {
					ip0dbg(("ip_rput_forward_options: "
					    "unable to send unreach\n"));
					freemsg(mp);
				}
				return (-1);
			}

			dst_ire = ire_ctable_lookup(dst, 0, IRE_LOCAL,
			    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (dst_ire == NULL) {
				/*
				 * Must be partial since ip_rput_options
				 * checked for strict.
				 */
				break;
			}
			off = opt[IPOPT_OFFSET];
			off--;
		redo_srr:
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* End of source route */
				ip1dbg((
				    "ip_rput_forward_options: end of SR\n"));
				ire_refrele(dst_ire);
				break;
			}
			bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
			bcopy(&ire->ire_src_addr, (char *)opt + off,
			    IP_ADDR_LEN);
			ip1dbg(("ip_rput_forward_options: next hop 0x%x\n",
			    ntohl(dst)));

			/*
			 * Check if our address is present more than
			 * once as consecutive hops in source route.
			 */
			tmp_ire = ire_ctable_lookup(dst, 0, IRE_LOCAL,
			    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (tmp_ire != NULL) {
				ire_refrele(tmp_ire);
				off += IP_ADDR_LEN;
				opt[IPOPT_OFFSET] += IP_ADDR_LEN;
				goto redo_srr;
			}
			ipha->ipha_dst = dst;
			opt[IPOPT_OFFSET] += IP_ADDR_LEN;
			ire_refrele(dst_ire);
			break;
		case IPOPT_RR:
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* No more room - ignore */
				ip1dbg((
				    "ip_rput_forward_options: end of RR\n"));
				break;
			}
			bcopy(&ire->ire_src_addr, (char *)opt + off,
			    IP_ADDR_LEN);
			opt[IPOPT_OFFSET] += IP_ADDR_LEN;
			break;
		case IPOPT_TS:
			/* Insert timestamp if there is room */
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_TSONLY:
				off = IPOPT_TS_TIMELEN;
				break;
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
				/* Verify that the address matched */
				off = opt[IPOPT_OFFSET] - 1;
				bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
				dst_ire = ire_ctable_lookup(dst, 0,
				    IRE_LOCAL, NULL, ALL_ZONES, NULL,
				    MATCH_IRE_TYPE, ipst);
				if (dst_ire == NULL) {
					/* Not for us */
					break;
				}
				ire_refrele(dst_ire);
				/* FALLTHRU */
			case IPOPT_TS_TSANDADDR:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				/*
				 * ip_*put_options should have already
				 * dropped this packet.
				 */
				cmn_err(CE_PANIC, "ip_rput_forward_options: "
				    "unknown IT - bug in ip_rput_options?\n");
				return (0);	/* Keep "lint" happy */
			}
			if (opt[IPOPT_OFFSET] - 1 + off > optlen) {
				/* Increase overflow counter */
				off = (opt[IPOPT_POS_OV_FLG] >> 4) + 1;
				opt[IPOPT_POS_OV_FLG] =
				    (uint8_t)((opt[IPOPT_POS_OV_FLG] & 0x0F) |
				    (off << 4));
				break;
			}
			off = opt[IPOPT_OFFSET] - 1;
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
			case IPOPT_TS_TSANDADDR:
				bcopy(&ire->ire_src_addr,
				    (char *)opt + off, IP_ADDR_LEN);
				opt[IPOPT_OFFSET] += IP_ADDR_LEN;
				/* FALLTHRU */
			case IPOPT_TS_TSONLY:
				off = opt[IPOPT_OFFSET] - 1;
				/* Compute # of milliseconds since midnight */
				gethrestime(&now);
				ts = (now.tv_sec % (24 * 60 * 60)) * 1000 +
				    now.tv_nsec / (NANOSEC / MILLISEC);
				bcopy(&ts, (char *)opt + off, IPOPT_TS_TIMELEN);
				opt[IPOPT_OFFSET] += IPOPT_TS_TIMELEN;
				break;
			}
			break;
		}
	}
	return (0);
}

/*
 * This is called after processing at least one of AH/ESP headers.
 *
 * NOTE: the ill corresponding to ipsec_in_ill_index may not be
 * the actual, physical interface on which the packet was received,
 * but, when ip_strict_dst_multihoming is set to 1, could be the
 * interface which had the ipha_dst configured when the packet went
 * through ip_rput. The ill_index corresponding to the recv_ill
 * is saved in ipsec_in_rill_index
 *
 * NOTE2: The "ire" argument is only used in IPv4 cases.  This function
 * cannot assume "ire" points to valid data for any IPv6 cases.
 */
void
ip_fanout_proto_again(mblk_t *ipsec_mp, ill_t *ill, ill_t *recv_ill, ire_t *ire)
{
	mblk_t *mp;
	ipaddr_t dst;
	in6_addr_t *v6dstp;
	ipha_t *ipha;
	ip6_t *ip6h;
	ipsec_in_t *ii;
	boolean_t ill_need_rele = B_FALSE;
	boolean_t rill_need_rele = B_FALSE;
	boolean_t ire_need_rele = B_FALSE;
	netstack_t	*ns;
	ip_stack_t	*ipst;

	ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	ASSERT(ii->ipsec_in_ill_index != 0);
	ns = ii->ipsec_in_ns;
	ASSERT(ii->ipsec_in_ns != NULL);
	ipst = ns->netstack_ip;

	mp = ipsec_mp->b_cont;
	ASSERT(mp != NULL);


	if (ill == NULL) {
		ASSERT(recv_ill == NULL);
		/*
		 * We need to get the original queue on which ip_rput_local
		 * or ip_rput_data_v6 was called.
		 */
		ill = ill_lookup_on_ifindex(ii->ipsec_in_ill_index,
		    !ii->ipsec_in_v4, NULL, NULL, NULL, NULL, ipst);
		ill_need_rele = B_TRUE;

		if (ii->ipsec_in_ill_index != ii->ipsec_in_rill_index) {
			recv_ill = ill_lookup_on_ifindex(
			    ii->ipsec_in_rill_index, !ii->ipsec_in_v4,
			    NULL, NULL, NULL, NULL, ipst);
			rill_need_rele = B_TRUE;
		} else {
			recv_ill = ill;
		}

		if ((ill == NULL) || (recv_ill == NULL)) {
			ip0dbg(("ip_fanout_proto_again: interface "
			    "disappeared\n"));
			if (ill != NULL)
				ill_refrele(ill);
			if (recv_ill != NULL)
				ill_refrele(recv_ill);
			freemsg(ipsec_mp);
			return;
		}
	}

	ASSERT(ill != NULL && recv_ill != NULL);

	if (mp->b_datap->db_type == M_CTL) {
		/*
		 * AH/ESP is returning the ICMP message after
		 * removing their headers. Fanout again till
		 * it gets to the right protocol.
		 */
		if (ii->ipsec_in_v4) {
			icmph_t *icmph;
			int iph_hdr_length;
			int hdr_length;

			ipha = (ipha_t *)mp->b_rptr;
			iph_hdr_length = IPH_HDR_LENGTH(ipha);
			icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
			ipha = (ipha_t *)&icmph[1];
			hdr_length = IPH_HDR_LENGTH(ipha);
			/*
			 * icmp_inbound_error_fanout may need to do pullupmsg.
			 * Reset the type to M_DATA.
			 */
			mp->b_datap->db_type = M_DATA;
			icmp_inbound_error_fanout(ill->ill_rq, ill, ipsec_mp,
			    icmph, ipha, iph_hdr_length, hdr_length, B_TRUE,
			    B_FALSE, ill, ii->ipsec_in_zoneid);
		} else {
			icmp6_t *icmp6;
			int hdr_length;

			ip6h = (ip6_t *)mp->b_rptr;
			/* Don't call hdr_length_v6() unless you have to. */
			if (ip6h->ip6_nxt != IPPROTO_ICMPV6)
				hdr_length = ip_hdr_length_v6(mp, ip6h);
			else
				hdr_length = IPV6_HDR_LEN;

			icmp6 = (icmp6_t *)(&mp->b_rptr[hdr_length]);
			/*
			 * icmp_inbound_error_fanout_v6 may need to do
			 * pullupmsg.  Reset the type to M_DATA.
			 */
			mp->b_datap->db_type = M_DATA;
			icmp_inbound_error_fanout_v6(ill->ill_rq, ipsec_mp,
			    ip6h, icmp6, ill, B_TRUE, ii->ipsec_in_zoneid);
		}
		if (ill_need_rele)
			ill_refrele(ill);
		if (rill_need_rele)
			ill_refrele(recv_ill);
		return;
	}

	if (ii->ipsec_in_v4) {
		ipha = (ipha_t *)mp->b_rptr;
		dst = ipha->ipha_dst;
		if (CLASSD(dst)) {
			/*
			 * Multicast has to be delivered to all streams.
			 */
			dst = INADDR_BROADCAST;
		}

		if (ire == NULL) {
			ire = ire_cache_lookup(dst, ii->ipsec_in_zoneid,
			    MBLK_GETLABEL(mp), ipst);
			if (ire == NULL) {
				if (ill_need_rele)
					ill_refrele(ill);
				if (rill_need_rele)
					ill_refrele(recv_ill);
				ip1dbg(("ip_fanout_proto_again: "
				    "IRE not found"));
				freemsg(ipsec_mp);
				return;
			}
			ire_need_rele = B_TRUE;
		}

		switch (ipha->ipha_protocol) {
			case IPPROTO_UDP:
				ip_udp_input(ill->ill_rq, ipsec_mp, ipha, ire,
				    recv_ill);
				if (ire_need_rele)
					ire_refrele(ire);
				break;
			case IPPROTO_TCP:
				if (!ire_need_rele)
					IRE_REFHOLD(ire);
				mp = ip_tcp_input(mp, ipha, ill, B_TRUE,
				    ire, ipsec_mp, 0, ill->ill_rq, NULL);
				IRE_REFRELE(ire);
				if (mp != NULL) {

					SQUEUE_ENTER(GET_SQUEUE(mp), mp,
					    mp, 1, SQ_PROCESS,
					    SQTAG_IP_PROTO_AGAIN);
				}
				break;
			case IPPROTO_SCTP:
				if (!ire_need_rele)
					IRE_REFHOLD(ire);
				ip_sctp_input(mp, ipha, ill, B_TRUE, ire,
				    ipsec_mp, 0, ill->ill_rq, dst);
				break;
			default:
				ip_proto_input(ill->ill_rq, ipsec_mp, ipha, ire,
				    recv_ill, 0);
				if (ire_need_rele)
					ire_refrele(ire);
				break;
		}
	} else {
		uint32_t rput_flags = 0;

		ip6h = (ip6_t *)mp->b_rptr;
		v6dstp = &ip6h->ip6_dst;
		/*
		 * XXX Assumes ip_rput_v6 sets ll_multicast  only for multicast
		 * address.
		 *
		 * Currently, we don't store that state in the IPSEC_IN
		 * message, and we may need to.
		 */
		rput_flags |= (IN6_IS_ADDR_MULTICAST(v6dstp) ?
		    IP6_IN_LLMCAST : 0);
		ip_rput_data_v6(ill->ill_rq, ill, ipsec_mp, ip6h, rput_flags,
		    NULL, NULL);
	}
	if (ill_need_rele)
		ill_refrele(ill);
	if (rill_need_rele)
		ill_refrele(recv_ill);
}

/*
 * Call ill_frag_timeout to do garbage collection. ill_frag_timeout
 * returns 'true' if there are still fragments left on the queue, in
 * which case we restart the timer.
 */
void
ill_frag_timer(void *arg)
{
	ill_t	*ill = (ill_t *)arg;
	boolean_t frag_pending;
	ip_stack_t	*ipst = ill->ill_ipst;

	mutex_enter(&ill->ill_lock);
	ASSERT(!ill->ill_fragtimer_executing);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		ill->ill_frag_timer_id = 0;
		mutex_exit(&ill->ill_lock);
		return;
	}
	ill->ill_fragtimer_executing = 1;
	mutex_exit(&ill->ill_lock);

	frag_pending = ill_frag_timeout(ill, ipst->ips_ip_g_frag_timeout);

	/*
	 * Restart the timer, if we have fragments pending or if someone
	 * wanted us to be scheduled again.
	 */
	mutex_enter(&ill->ill_lock);
	ill->ill_fragtimer_executing = 0;
	ill->ill_frag_timer_id = 0;
	if (frag_pending || ill->ill_fragtimer_needrestart)
		ill_frag_timer_start(ill);
	mutex_exit(&ill->ill_lock);
}

void
ill_frag_timer_start(ill_t *ill)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(MUTEX_HELD(&ill->ill_lock));

	/* If the ill is closing or opening don't proceed */
	if (ill->ill_state_flags & ILL_CONDEMNED)
		return;

	if (ill->ill_fragtimer_executing) {
		/*
		 * ill_frag_timer is currently executing. Just record the
		 * the fact that we want the timer to be restarted.
		 * ill_frag_timer will post a timeout before it returns,
		 * ensuring it will be called again.
		 */
		ill->ill_fragtimer_needrestart = 1;
		return;
	}

	if (ill->ill_frag_timer_id == 0) {
		/*
		 * The timer is neither running nor is the timeout handler
		 * executing. Post a timeout so that ill_frag_timer will be
		 * called
		 */
		ill->ill_frag_timer_id = timeout(ill_frag_timer, ill,
		    MSEC_TO_TICK(ipst->ips_ip_g_frag_timo_ms >> 1));
		ill->ill_fragtimer_needrestart = 0;
	}
}

/*
 * This routine is needed for loopback when forwarding multicasts.
 *
 * IPQoS Notes:
 * IPPF processing is done in fanout routines.
 * Policy processing is done only if IPP_lOCAL_IN is enabled. Further,
 * processing for IPsec packets is done when it comes back in clear.
 * NOTE : The callers of this function need to do the ire_refrele for the
 *	  ire that is being passed in.
 */
void
ip_proto_input(queue_t *q, mblk_t *mp, ipha_t *ipha, ire_t *ire,
    ill_t *recv_ill, uint32_t esp_udp_ports)
{
	boolean_t esp_in_udp_packet = (esp_udp_ports != 0);
	ill_t	*ill = (ill_t *)q->q_ptr;
	uint32_t	sum;
	uint32_t	u1;
	uint32_t	u2;
	int		hdr_length;
	boolean_t	mctl_present;
	mblk_t		*first_mp = mp;
	mblk_t		*hada_mp = NULL;
	ipha_t		*inner_ipha;
	ip_stack_t	*ipst;

	ASSERT(recv_ill != NULL);
	ipst = recv_ill->ill_ipst;

	TRACE_1(TR_FAC_IP, TR_IP_RPUT_LOCL_START,
	    "ip_rput_locl_start: q %p", q);

	ASSERT(ire->ire_ipversion == IPV4_VERSION);
	ASSERT(ill != NULL);


#define	rptr	((uchar_t *)ipha)
#define	iphs	((uint16_t *)ipha)

	/*
	 * no UDP or TCP packet should come here anymore.
	 */
	ASSERT(ipha->ipha_protocol != IPPROTO_TCP &&
	    ipha->ipha_protocol != IPPROTO_UDP);

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);
	if (mctl_present &&
	    ((da_ipsec_t *)first_mp->b_rptr)->da_type == IPHADA_M_CTL) {
		ASSERT(MBLKL(first_mp) >= sizeof (da_ipsec_t));

		/*
		 * It's an IPsec accelerated packet.
		 * Keep a pointer to the data attributes around until
		 * we allocate the ipsec_info_t.
		 */
		IPSECHW_DEBUG(IPSECHW_PKT,
		    ("ip_rput_local: inbound HW accelerated IPsec pkt\n"));
		hada_mp = first_mp;
		hada_mp->b_cont = NULL;
		/*
		 * Since it is accelerated, it comes directly from
		 * the ill and the data attributes is followed by
		 * the packet data.
		 */
		ASSERT(mp->b_datap->db_type != M_CTL);
		first_mp = mp;
		mctl_present = B_FALSE;
	}

	/*
	 * IF M_CTL is not present, then ipsec_in_is_secure
	 * should return B_TRUE. There is a case where loopback
	 * packets has an M_CTL in the front with all the
	 * IPsec options set to IPSEC_PREF_NEVER - which means
	 * ipsec_in_is_secure will return B_FALSE. As loopback
	 * packets never comes here, it is safe to ASSERT the
	 * following.
	 */
	ASSERT(!mctl_present || ipsec_in_is_secure(first_mp));

	/*
	 * Also, we should never have an mctl_present if this is an
	 * ESP-in-UDP packet.
	 */
	ASSERT(!mctl_present || !esp_in_udp_packet);


	/* u1 is # words of IP options */
	u1 = ipha->ipha_version_and_hdr_length - (uchar_t)((IP_VERSION << 4) +
	    IP_SIMPLE_HDR_LENGTH_IN_WORDS);

	/*
	 * Don't verify header checksum if we just removed UDP header or
	 * packet is coming back from AH/ESP.
	 */
	if (!esp_in_udp_packet && !mctl_present) {
		if (u1) {
			if (!ip_options_cksum(q, ill, mp, ipha, ire, ipst)) {
				if (hada_mp != NULL)
					freemsg(hada_mp);
				return;
			}
		} else {
			/* Check the IP header checksum.  */
#define	uph	((uint16_t *)ipha)
			sum = uph[0] + uph[1] + uph[2] + uph[3] + uph[4] +
			    uph[5] + uph[6] + uph[7] + uph[8] + uph[9];
#undef  uph
			/* finish doing IP checksum */
			sum = (sum & 0xFFFF) + (sum >> 16);
			sum = ~(sum + (sum >> 16)) & 0xFFFF;
			if (sum && sum != 0xFFFF) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
				goto drop_pkt;
			}
		}
	}

	/*
	 * Count for SNMP of inbound packets for ire. As ip_proto_input
	 * might be called more than once for secure packets, count only
	 * the first time.
	 */
	if (!mctl_present) {
		UPDATE_IB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
	}

	/* Check for fragmentation offset. */
	u2 = ntohs(ipha->ipha_fragment_offset_and_flags);
	u1 = u2 & (IPH_MF | IPH_OFFSET);
	if (u1) {
		/*
		 * We re-assemble fragments before we do the AH/ESP
		 * processing. Thus, M_CTL should not be present
		 * while we are re-assembling.
		 */
		ASSERT(!mctl_present);
		ASSERT(first_mp == mp);
		if (!ip_rput_fragment(q, &mp, ipha, NULL, NULL)) {
			return;
		}
		/*
		 * Make sure that first_mp points back to mp as
		 * the mp we came in with could have changed in
		 * ip_rput_fragment().
		 */
		ipha = (ipha_t *)mp->b_rptr;
		first_mp = mp;
	}

	/*
	 * Clear hardware checksumming flag as it is currently only
	 * used by TCP and UDP.
	 */
	DB_CKSUMFLAGS(mp) = 0;

	/* Now we have a complete datagram, destined for this machine. */
	u1 = IPH_HDR_LENGTH(ipha);
	switch (ipha->ipha_protocol) {
	case IPPROTO_ICMP: {
		ire_t		*ire_zone;
		ilm_t		*ilm;
		mblk_t		*mp1;
		zoneid_t	last_zoneid;

		if (CLASSD(ipha->ipha_dst) && !IS_LOOPBACK(recv_ill)) {
			ASSERT(ire->ire_type == IRE_BROADCAST);
			/*
			 * Inactive/Failed interfaces are not supposed to
			 * respond to the multicast packets.
			 */
			if (ill_is_probeonly(ill)) {
				freemsg(first_mp);
				return;
			}

			/*
			 * In the multicast case, applications may have joined
			 * the group from different zones, so we need to deliver
			 * the packet to each of them. Loop through the
			 * multicast memberships structures (ilm) on the receive
			 * ill and send a copy of the packet up each matching
			 * one. However, we don't do this for multicasts sent on
			 * the loopback interface (PHYI_LOOPBACK flag set) as
			 * they must stay in the sender's zone.
			 *
			 * ilm_add_v6() ensures that ilms in the same zone are
			 * contiguous in the ill_ilm list. We use this property
			 * to avoid sending duplicates needed when two
			 * applications in the same zone join the same group on
			 * different logical interfaces: we ignore the ilm if
			 * its zoneid is the same as the last matching one.
			 * In addition, the sending of the packet for
			 * ire_zoneid is delayed until all of the other ilms
			 * have been exhausted.
			 */
			last_zoneid = -1;
			ILM_WALKER_HOLD(recv_ill);
			for (ilm = recv_ill->ill_ilm; ilm != NULL;
			    ilm = ilm->ilm_next) {
				if ((ilm->ilm_flags & ILM_DELETED) ||
				    ipha->ipha_dst != ilm->ilm_addr ||
				    ilm->ilm_zoneid == last_zoneid ||
				    ilm->ilm_zoneid == ire->ire_zoneid ||
				    ilm->ilm_zoneid == ALL_ZONES ||
				    !(ilm->ilm_ipif->ipif_flags & IPIF_UP))
					continue;
				mp1 = ip_copymsg(first_mp);
				if (mp1 == NULL)
					continue;
				icmp_inbound(q, mp1, B_TRUE, ill,
				    0, sum, mctl_present, B_TRUE,
				    recv_ill, ilm->ilm_zoneid);
				last_zoneid = ilm->ilm_zoneid;
			}
			ILM_WALKER_RELE(recv_ill);
		} else if (ire->ire_type == IRE_BROADCAST) {
			/*
			 * In the broadcast case, there may be many zones
			 * which need a copy of the packet delivered to them.
			 * There is one IRE_BROADCAST per broadcast address
			 * and per zone; we walk those using a helper function.
			 * In addition, the sending of the packet for ire is
			 * delayed until all of the other ires have been
			 * processed.
			 */
			IRB_REFHOLD(ire->ire_bucket);
			ire_zone = NULL;
			while ((ire_zone = ire_get_next_bcast_ire(ire_zone,
			    ire)) != NULL) {
				mp1 = ip_copymsg(first_mp);
				if (mp1 == NULL)
					continue;

				UPDATE_IB_PKT_COUNT(ire_zone);
				ire_zone->ire_last_used_time = lbolt;
				icmp_inbound(q, mp1, B_TRUE, ill,
				    0, sum, mctl_present, B_TRUE,
				    recv_ill, ire_zone->ire_zoneid);
			}
			IRB_REFRELE(ire->ire_bucket);
		}
		icmp_inbound(q, first_mp, (ire->ire_type == IRE_BROADCAST),
		    ill, 0, sum, mctl_present, B_TRUE, recv_ill,
		    ire->ire_zoneid);
		TRACE_2(TR_FAC_IP, TR_IP_RPUT_LOCL_END,
		    "ip_rput_locl_end: q %p (%S)", q, "icmp");
		return;
	}
	case IPPROTO_IGMP:
		/*
		 * If we are not willing to accept IGMP packets in clear,
		 * then check with global policy.
		 */
		if (ipst->ips_igmp_accept_clear_messages == 0) {
			first_mp = ipsec_check_global_policy(first_mp, NULL,
			    ipha, NULL, mctl_present, ipst->ips_netstack);
			if (first_mp == NULL)
				return;
		}
		if (is_system_labeled() && !tsol_can_accept_raw(mp, B_TRUE)) {
			freemsg(first_mp);
			ip1dbg(("ip_proto_input: zone all cannot accept raw"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return;
		}
		if ((mp = igmp_input(q, mp, ill)) == NULL) {
			/* Bad packet - discarded by igmp_input */
			TRACE_2(TR_FAC_IP, TR_IP_RPUT_LOCL_END,
			    "ip_rput_locl_end: q %p (%S)", q, "igmp");
			if (mctl_present)
				freeb(first_mp);
			return;
		}
		/*
		 * igmp_input() may have returned the pulled up message.
		 * So first_mp and ipha need to be reinitialized.
		 */
		ipha = (ipha_t *)mp->b_rptr;
		if (mctl_present)
			first_mp->b_cont = mp;
		else
			first_mp = mp;
		if (ipst->ips_ipcl_proto_fanout[ipha->ipha_protocol].
		    connf_head != NULL) {
			/* No user-level listener for IGMP packets */
			goto drop_pkt;
		}
		/* deliver to local raw users */
		break;
	case IPPROTO_PIM:
		/*
		 * If we are not willing to accept PIM packets in clear,
		 * then check with global policy.
		 */
		if (ipst->ips_pim_accept_clear_messages == 0) {
			first_mp = ipsec_check_global_policy(first_mp, NULL,
			    ipha, NULL, mctl_present, ipst->ips_netstack);
			if (first_mp == NULL)
				return;
		}
		if (is_system_labeled() && !tsol_can_accept_raw(mp, B_TRUE)) {
			freemsg(first_mp);
			ip1dbg(("ip_proto_input: zone all cannot accept PIM"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return;
		}
		if (pim_input(q, mp, ill) != 0) {
			/* Bad packet - discarded by pim_input */
			TRACE_2(TR_FAC_IP, TR_IP_RPUT_LOCL_END,
			    "ip_rput_locl_end: q %p (%S)", q, "pim");
			if (mctl_present)
				freeb(first_mp);
			return;
		}

		/*
		 * pim_input() may have pulled up the message so ipha needs to
		 * be reinitialized.
		 */
		ipha = (ipha_t *)mp->b_rptr;
		if (ipst->ips_ipcl_proto_fanout[ipha->ipha_protocol].
		    connf_head != NULL) {
			/* No user-level listener for PIM packets */
			goto drop_pkt;
		}
		/* deliver to local raw users */
		break;
	case IPPROTO_ENCAP:
		/*
		 * Handle self-encapsulated packets (IP-in-IP where
		 * the inner addresses == the outer addresses).
		 */
		hdr_length = IPH_HDR_LENGTH(ipha);
		if ((uchar_t *)ipha + hdr_length + sizeof (ipha_t) >
		    mp->b_wptr) {
			if (!pullupmsg(mp, (uchar_t *)ipha + hdr_length +
			    sizeof (ipha_t) - mp->b_rptr)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(first_mp);
				return;
			}
			ipha = (ipha_t *)mp->b_rptr;
		}
		inner_ipha = (ipha_t *)((uchar_t *)ipha + hdr_length);
		/*
		 * Check the sanity of the inner IP header.
		 */
		if ((IPH_HDR_VERSION(inner_ipha) != IPV4_VERSION)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
			return;
		}
		if (IPH_HDR_LENGTH(inner_ipha) < sizeof (ipha_t)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
			return;
		}
		if (inner_ipha->ipha_src == ipha->ipha_src &&
		    inner_ipha->ipha_dst == ipha->ipha_dst) {
			ipsec_in_t *ii;

			/*
			 * Self-encapsulated tunnel packet. Remove
			 * the outer IP header and fanout again.
			 * We also need to make sure that the inner
			 * header is pulled up until options.
			 */
			mp->b_rptr = (uchar_t *)inner_ipha;
			ipha = inner_ipha;
			hdr_length = IPH_HDR_LENGTH(ipha);
			if ((uchar_t *)ipha + hdr_length > mp->b_wptr) {
				if (!pullupmsg(mp, (uchar_t *)ipha +
				    + hdr_length - mp->b_rptr)) {
					freemsg(first_mp);
					return;
				}
				ipha = (ipha_t *)mp->b_rptr;
			}
			if (hdr_length > sizeof (ipha_t)) {
				/* We got options on the inner packet. */
				ipaddr_t dst = ipha->ipha_dst;

				if (ip_rput_options(q, mp, ipha, &dst, ipst) ==
				    -1) {
					/* Bad options! */
					return;
				}
				if (dst != ipha->ipha_dst) {
					/*
					 * Someone put a source-route in
					 * the inside header of a self-
					 * encapsulated packet.  Drop it
					 * with extreme prejudice and let
					 * the sender know.
					 */
					icmp_unreachable(q, first_mp,
					    ICMP_SOURCE_ROUTE_FAILED,
					    recv_ill->ill_zoneid, ipst);
					return;
				}
			}
			if (!mctl_present) {
				ASSERT(first_mp == mp);
				/*
				 * This means that somebody is sending
				 * Self-encapsualted packets without AH/ESP.
				 * If AH/ESP was present, we would have already
				 * allocated the first_mp.
				 *
				 * Send this packet to find a tunnel endpoint.
				 * if I can't find one, an ICMP
				 * PROTOCOL_UNREACHABLE will get sent.
				 */
				goto fanout;
			}
			/*
			 * We generally store the ill_index if we need to
			 * do IPsec processing as we lose the ill queue when
			 * we come back. But in this case, we never should
			 * have to store the ill_index here as it should have
			 * been stored previously when we processed the
			 * AH/ESP header in this routine or for non-ipsec
			 * cases, we still have the queue. But for some bad
			 * packets from the wire, we can get to IPsec after
			 * this and we better store the index for that case.
			 */
			ill = (ill_t *)q->q_ptr;
			ii = (ipsec_in_t *)first_mp->b_rptr;
			ii->ipsec_in_ill_index =
			    ill->ill_phyint->phyint_ifindex;
			ii->ipsec_in_rill_index =
			    recv_ill->ill_phyint->phyint_ifindex;
			if (ii->ipsec_in_decaps) {
				/*
				 * This packet is self-encapsulated multiple
				 * times. We don't want to recurse infinitely.
				 * To keep it simple, drop the packet.
				 */
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(first_mp);
				return;
			}
			ii->ipsec_in_decaps = B_TRUE;
			ip_fanout_proto_again(first_mp, recv_ill, recv_ill,
			    ire);
			return;
		}
		break;
	case IPPROTO_AH:
	case IPPROTO_ESP: {
		ipsec_stack_t *ipss = ipst->ips_netstack->netstack_ipsec;

		/*
		 * Fast path for AH/ESP. If this is the first time
		 * we are sending a datagram to AH/ESP, allocate
		 * a IPSEC_IN message and prepend it. Otherwise,
		 * just fanout.
		 */

		int ipsec_rc;
		ipsec_in_t *ii;
		netstack_t *ns = ipst->ips_netstack;

		IP_STAT(ipst, ipsec_proto_ahesp);
		if (!mctl_present) {
			ASSERT(first_mp == mp);
			first_mp = ipsec_in_alloc(B_TRUE, ns);
			if (first_mp == NULL) {
				ip1dbg(("ip_proto_input: IPSEC_IN "
				    "allocation failure.\n"));
				freemsg(hada_mp); /* okay ifnull */
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(mp);
				return;
			}
			/*
			 * Store the ill_index so that when we come back
			 * from IPsec we ride on the same queue.
			 */
			ill = (ill_t *)q->q_ptr;
			ii = (ipsec_in_t *)first_mp->b_rptr;
			ii->ipsec_in_ill_index =
			    ill->ill_phyint->phyint_ifindex;
			ii->ipsec_in_rill_index =
			    recv_ill->ill_phyint->phyint_ifindex;
			first_mp->b_cont = mp;
			/*
			 * Cache hardware acceleration info.
			 */
			if (hada_mp != NULL) {
				IPSECHW_DEBUG(IPSECHW_PKT,
				    ("ip_rput_local: caching data attr.\n"));
				ii->ipsec_in_accelerated = B_TRUE;
				ii->ipsec_in_da = hada_mp;
				hada_mp = NULL;
			}
		} else {
			ii = (ipsec_in_t *)first_mp->b_rptr;
		}

		ii->ipsec_in_esp_udp_ports = esp_udp_ports;

		if (!ipsec_loaded(ipss)) {
			ip_proto_not_sup(q, first_mp, IP_FF_SEND_ICMP,
			    ire->ire_zoneid, ipst);
			return;
		}

		ns = ipst->ips_netstack;
		/* select inbound SA and have IPsec process the pkt */
		if (ipha->ipha_protocol == IPPROTO_ESP) {
			esph_t *esph = ipsec_inbound_esp_sa(first_mp, ns);
			boolean_t esp_in_udp_sa;
			if (esph == NULL)
				return;
			ASSERT(ii->ipsec_in_esp_sa != NULL);
			ASSERT(ii->ipsec_in_esp_sa->ipsa_input_func != NULL);
			esp_in_udp_sa = ((ii->ipsec_in_esp_sa->ipsa_flags &
			    IPSA_F_NATT) != 0);
			/*
			 * The following is a fancy, but quick, way of saying:
			 * ESP-in-UDP SA and Raw ESP packet --> drop
			 *    OR
			 * ESP SA and ESP-in-UDP packet --> drop
			 */
			if (esp_in_udp_sa != esp_in_udp_packet) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_packet(first_mp, B_TRUE, ill, NULL,
				    DROPPER(ns->netstack_ipsec, ipds_esp_no_sa),
				    &ns->netstack_ipsec->ipsec_dropper);
				return;
			}
			ipsec_rc = ii->ipsec_in_esp_sa->ipsa_input_func(
			    first_mp, esph);
		} else {
			ah_t *ah = ipsec_inbound_ah_sa(first_mp, ns);
			if (ah == NULL)
				return;
			ASSERT(ii->ipsec_in_ah_sa != NULL);
			ASSERT(ii->ipsec_in_ah_sa->ipsa_input_func != NULL);
			ipsec_rc = ii->ipsec_in_ah_sa->ipsa_input_func(
			    first_mp, ah);
		}

		switch (ipsec_rc) {
		case IPSEC_STATUS_SUCCESS:
			break;
		case IPSEC_STATUS_FAILED:
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			/* FALLTHRU */
		case IPSEC_STATUS_PENDING:
			return;
		}
		/* we're done with IPsec processing, send it up */
		ip_fanout_proto_again(first_mp, ill, recv_ill, ire);
		return;
	}
	default:
		break;
	}
	if (is_system_labeled() && !tsol_can_accept_raw(mp, B_FALSE)) {
		ip1dbg(("ip_proto_input: zone %d cannot accept raw IP",
		    ire->ire_zoneid));
		goto drop_pkt;
	}
	/*
	 * Handle protocols with which IP is less intimate.  There
	 * can be more than one stream bound to a particular
	 * protocol.  When this is the case, each one gets a copy
	 * of any incoming packets.
	 */
fanout:
	ip_fanout_proto(q, first_mp, ill, ipha,
	    IP_FF_SEND_ICMP | IP_FF_CKSUM | IP_FF_RAWIP, mctl_present,
	    B_TRUE, recv_ill, ire->ire_zoneid);
	TRACE_2(TR_FAC_IP, TR_IP_RPUT_LOCL_END,
	    "ip_rput_locl_end: q %p (%S)", q, "ip_fanout_proto");
	return;

drop_pkt:
	freemsg(first_mp);
	if (hada_mp != NULL)
		freeb(hada_mp);
	TRACE_2(TR_FAC_IP, TR_IP_RPUT_LOCL_END,
	    "ip_rput_locl_end: q %p (%S)", q, "droppkt");
#undef	rptr
#undef  iphs

}

/*
 * Update any source route, record route or timestamp options.
 * Check that we are at end of strict source route.
 * The options have already been checked for sanity in ip_rput_options().
 */
static boolean_t
ip_rput_local_options(queue_t *q, mblk_t *mp, ipha_t *ipha, ire_t *ire,
    ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	uint32_t	ts;
	ire_t		*dst_ire;
	timestruc_t	now;
	zoneid_t	zoneid;
	ill_t		*ill;

	ASSERT(ire->ire_ipversion == IPV4_VERSION);

	ip2dbg(("ip_rput_local_options\n"));

	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_rput_local_options: opt %d, len %d\n",
		    optval, optlen));
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* End of source route */
				ip1dbg(("ip_rput_local_options: end of SR\n"));
				break;
			}
			/*
			 * This will only happen if two consecutive entries
			 * in the source route contains our address or if
			 * it is a packet with a loose source route which
			 * reaches us before consuming the whole source route
			 */
			ip1dbg(("ip_rput_local_options: not end of SR\n"));
			if (optval == IPOPT_SSRR) {
				goto bad_src_route;
			}
			/*
			 * Hack: instead of dropping the packet truncate the
			 * source route to what has been used by filling the
			 * rest with IPOPT_NOP.
			 */
			opt[IPOPT_OLEN] = (uint8_t)off;
			while (off < optlen) {
				opt[off++] = IPOPT_NOP;
			}
			break;
		case IPOPT_RR:
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* No more room - ignore */
				ip1dbg((
				    "ip_rput_local_options: end of RR\n"));
				break;
			}
			bcopy(&ire->ire_src_addr, (char *)opt + off,
			    IP_ADDR_LEN);
			opt[IPOPT_OFFSET] += IP_ADDR_LEN;
			break;
		case IPOPT_TS:
			/* Insert timestamp if there is romm */
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_TSONLY:
				off = IPOPT_TS_TIMELEN;
				break;
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
				/* Verify that the address matched */
				off = opt[IPOPT_OFFSET] - 1;
				bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
				dst_ire = ire_ctable_lookup(dst, 0, IRE_LOCAL,
				    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE,
				    ipst);
				if (dst_ire == NULL) {
					/* Not for us */
					break;
				}
				ire_refrele(dst_ire);
				/* FALLTHRU */
			case IPOPT_TS_TSANDADDR:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				/*
				 * ip_*put_options should have already
				 * dropped this packet.
				 */
				cmn_err(CE_PANIC, "ip_rput_local_options: "
				    "unknown IT - bug in ip_rput_options?\n");
				return (B_TRUE);	/* Keep "lint" happy */
			}
			if (opt[IPOPT_OFFSET] - 1 + off > optlen) {
				/* Increase overflow counter */
				off = (opt[IPOPT_POS_OV_FLG] >> 4) + 1;
				opt[IPOPT_POS_OV_FLG] =
				    (uint8_t)((opt[IPOPT_POS_OV_FLG] & 0x0F) |
				    (off << 4));
				break;
			}
			off = opt[IPOPT_OFFSET] - 1;
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
			case IPOPT_TS_TSANDADDR:
				bcopy(&ire->ire_src_addr, (char *)opt + off,
				    IP_ADDR_LEN);
				opt[IPOPT_OFFSET] += IP_ADDR_LEN;
				/* FALLTHRU */
			case IPOPT_TS_TSONLY:
				off = opt[IPOPT_OFFSET] - 1;
				/* Compute # of milliseconds since midnight */
				gethrestime(&now);
				ts = (now.tv_sec % (24 * 60 * 60)) * 1000 +
				    now.tv_nsec / (NANOSEC / MILLISEC);
				bcopy(&ts, (char *)opt + off, IPOPT_TS_TIMELEN);
				opt[IPOPT_OFFSET] += IPOPT_TS_TIMELEN;
				break;
			}
			break;
		}
	}
	return (B_TRUE);

bad_src_route:
	q = WR(q);
	if (q->q_next != NULL)
		ill = q->q_ptr;
	else
		ill = NULL;

	/* make sure we clear any indication of a hardware checksum */
	DB_CKSUMFLAGS(mp) = 0;
	zoneid = ipif_lookup_addr_zoneid(ipha->ipha_dst, ill, ipst);
	if (zoneid == ALL_ZONES)
		freemsg(mp);
	else
		icmp_unreachable(q, mp, ICMP_SOURCE_ROUTE_FAILED, zoneid, ipst);
	return (B_FALSE);

}

/*
 * Process IP options in an inbound packet.  If an option affects the
 * effective destination address, return the next hop address via dstp.
 * Returns -1 if something fails in which case an ICMP error has been sent
 * and mp freed.
 */
static int
ip_rput_options(queue_t *q, mblk_t *mp, ipha_t *ipha, ipaddr_t *dstp,
    ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	intptr_t	code = 0;
	ire_t		*ire = NULL;
	zoneid_t	zoneid;
	ill_t		*ill;

	ip2dbg(("ip_rput_options\n"));
	dst = ipha->ipha_dst;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_rput_options: opt %d, len %d\n",
		    optval, optlen));
		/*
		 * Note: we need to verify the checksum before we
		 * modify anything thus this routine only extracts the next
		 * hop dst from any source route.
		 */
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			ire = ire_ctable_lookup(dst, 0, IRE_LOCAL, NULL,
			    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (ire == NULL) {
				if (optval == IPOPT_SSRR) {
					ip1dbg(("ip_rput_options: not next"
					    " strict source route 0x%x\n",
					    ntohl(dst)));
					code = (char *)&ipha->ipha_dst -
					    (char *)ipha;
					goto param_prob; /* RouterReq's */
				}
				ip2dbg(("ip_rput_options: "
				    "not next source route 0x%x\n",
				    ntohl(dst)));
				break;
			}
			ire_refrele(ire);

			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_rput_options: bad option offset\n"));
				code = (char *)&opt[IPOPT_OLEN] -
				    (char *)ipha;
				goto param_prob;
			}
			off = opt[IPOPT_OFFSET];
			off--;
		redo_srr:
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* End of source route */
				ip1dbg(("ip_rput_options: end of SR\n"));
				break;
			}
			bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
			ip1dbg(("ip_rput_options: next hop 0x%x\n",
			    ntohl(dst)));

			/*
			 * Check if our address is present more than
			 * once as consecutive hops in source route.
			 * XXX verify per-interface ip_forwarding
			 * for source route?
			 */
			ire = ire_ctable_lookup(dst, 0, IRE_LOCAL, NULL,
			    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);

			if (ire != NULL) {
				ire_refrele(ire);
				off += IP_ADDR_LEN;
				goto redo_srr;
			}

			if (dst == htonl(INADDR_LOOPBACK)) {
				ip1dbg(("ip_rput_options: loopback addr in "
				    "source route!\n"));
				goto bad_src_route;
			}
			/*
			 * For strict: verify that dst is directly
			 * reachable.
			 */
			if (optval == IPOPT_SSRR) {
				ire = ire_ftable_lookup(dst, 0, 0,
				    IRE_INTERFACE, NULL, NULL, ALL_ZONES, 0,
				    MBLK_GETLABEL(mp),
				    MATCH_IRE_TYPE | MATCH_IRE_SECATTR, ipst);
				if (ire == NULL) {
					ip1dbg(("ip_rput_options: SSRR not "
					    "directly reachable: 0x%x\n",
					    ntohl(dst)));
					goto bad_src_route;
				}
				ire_refrele(ire);
			}
			/*
			 * Defer update of the offset and the record route
			 * until the packet is forwarded.
			 */
			break;
		case IPOPT_RR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_rput_options: bad option offset\n"));
				code = (char *)&opt[IPOPT_OLEN] -
				    (char *)ipha;
				goto param_prob;
			}
			break;
		case IPOPT_TS:
			/*
			 * Verify that length >= 5 and that there is either
			 * room for another timestamp or that the overflow
			 * counter is not maxed out.
			 */
			code = (char *)&opt[IPOPT_OLEN] - (char *)ipha;
			if (optlen < IPOPT_MINLEN_IT) {
				goto param_prob;
			}
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_rput_options: bad option offset\n"));
				code = (char *)&opt[IPOPT_OFFSET] -
				    (char *)ipha;
				goto param_prob;
			}
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_TSONLY:
				off = IPOPT_TS_TIMELEN;
				break;
			case IPOPT_TS_TSANDADDR:
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				code = (char *)&opt[IPOPT_POS_OV_FLG] -
				    (char *)ipha;
				goto param_prob;
			}
			if (opt[IPOPT_OFFSET] - 1 + off > optlen &&
			    (opt[IPOPT_POS_OV_FLG] & 0xF0) == 0xF0) {
				/*
				 * No room and the overflow counter is 15
				 * already.
				 */
				goto param_prob;
			}
			break;
		}
	}

	if ((opts.ipoptp_flags & IPOPTP_ERROR) == 0) {
		*dstp = dst;
		return (0);
	}

	ip1dbg(("ip_rput_options: error processing IP options."));
	code = (char *)&opt[IPOPT_OFFSET] - (char *)ipha;

param_prob:
	q = WR(q);
	if (q->q_next != NULL)
		ill = q->q_ptr;
	else
		ill = NULL;

	/* make sure we clear any indication of a hardware checksum */
	DB_CKSUMFLAGS(mp) = 0;
	/* Don't know whether this is for non-global or global/forwarding */
	zoneid = ipif_lookup_addr_zoneid(dst, ill, ipst);
	if (zoneid == ALL_ZONES)
		freemsg(mp);
	else
		icmp_param_problem(q, mp, (uint8_t)code, zoneid, ipst);
	return (-1);

bad_src_route:
	q = WR(q);
	if (q->q_next != NULL)
		ill = q->q_ptr;
	else
		ill = NULL;

	/* make sure we clear any indication of a hardware checksum */
	DB_CKSUMFLAGS(mp) = 0;
	zoneid = ipif_lookup_addr_zoneid(dst, ill, ipst);
	if (zoneid == ALL_ZONES)
		freemsg(mp);
	else
		icmp_unreachable(q, mp, ICMP_SOURCE_ROUTE_FAILED, zoneid, ipst);
	return (-1);
}

/*
 * IP & ICMP info in >=14 msg's ...
 *  - ip fixed part (mib2_ip_t)
 *  - icmp fixed part (mib2_icmp_t)
 *  - ipAddrEntryTable (ip 20)		all IPv4 ipifs
 *  - ipRouteEntryTable (ip 21)		all IPv4 IREs
 *  - ipNetToMediaEntryTable (ip 22)	[filled in by the arp module]
 *  - ipRouteAttributeTable (ip 102)	labeled routes
 *  - ip multicast membership (ip_member_t)
 *  - ip multicast source filtering (ip_grpsrc_t)
 *  - igmp fixed part (struct igmpstat)
 *  - multicast routing stats (struct mrtstat)
 *  - multicast routing vifs (array of struct vifctl)
 *  - multicast routing routes (array of struct mfcctl)
 *  - ip6 fixed part (mib2_ipv6IfStatsEntry_t)
 *					One per ill plus one generic
 *  - icmp6 fixed part (mib2_ipv6IfIcmpEntry_t)
 *					One per ill plus one generic
 *  - ipv6RouteEntry			all IPv6 IREs
 *  - ipv6RouteAttributeTable (ip6 102)	labeled routes
 *  - ipv6NetToMediaEntry		all Neighbor Cache entries
 *  - ipv6AddrEntry			all IPv6 ipifs
 *  - ipv6 multicast membership (ipv6_member_t)
 *  - ipv6 multicast source filtering (ipv6_grpsrc_t)
 *
 * MIB2_IP_MEDIA is filled in by the arp module with ARP cache entries.
 *
 * NOTE: original mpctl is copied for msg's 2..N, since its ctl part is
 * already filled in by the caller.
 * Return value of 0 indicates that no messages were sent and caller
 * should free mpctl.
 */
int
ip_snmp_get(queue_t *q, mblk_t *mpctl, int level)
{
	ip_stack_t *ipst;
	sctp_stack_t *sctps;

	if (q->q_next != NULL) {
		ipst = ILLQ_TO_IPST(q);
	} else {
		ipst = CONNQ_TO_IPST(q);
	}
	ASSERT(ipst != NULL);
	sctps = ipst->ips_netstack->netstack_sctp;

	if (mpctl == NULL || mpctl->b_cont == NULL) {
		return (0);
	}

	/*
	 * For the purposes of the (broken) packet shell use
	 * of the level we make sure MIB2_TCP/MIB2_UDP can be used
	 * to make TCP and UDP appear first in the list of mib items.
	 * TBD: We could expand this and use it in netstat so that
	 * the kernel doesn't have to produce large tables (connections,
	 * routes, etc) when netstat only wants the statistics or a particular
	 * table.
	 */
	if (!(level == MIB2_TCP || level == MIB2_UDP)) {
		if ((mpctl = icmp_snmp_get(q, mpctl)) == NULL) {
			return (1);
		}
	}

	if (level != MIB2_TCP) {
		if ((mpctl = udp_snmp_get(q, mpctl)) == NULL) {
			return (1);
		}
	}

	if (level != MIB2_UDP) {
		if ((mpctl = tcp_snmp_get(q, mpctl)) == NULL) {
			return (1);
		}
	}

	if ((mpctl = ip_snmp_get_mib2_ip_traffic_stats(q, mpctl,
	    ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip6(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_icmp(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_icmp6(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_igmp(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_multi(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip_addr(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip6_addr(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip_group_mem(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip6_group_mem(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip_group_src(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip6_group_src(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_virt_multi(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_multi_rtable(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip_route_media(q, mpctl, ipst)) == NULL) {
		return (1);
	}

	mpctl = ip_snmp_get_mib2_ip6_route_media(q, mpctl, ipst);
	if (mpctl == NULL) {
		return (1);
	}

	if ((mpctl = sctp_snmp_get_mib2(q, mpctl, sctps)) == NULL) {
		return (1);
	}
	freemsg(mpctl);
	return (1);
}


/* Get global (legacy) IPv4 statistics */
static mblk_t *
ip_snmp_get_mib2_ip(queue_t *q, mblk_t *mpctl, mib2_ipIfStatsEntry_t *ipmib,
    ip_stack_t *ipst)
{
	mib2_ip_t		old_ip_mib;
	struct opthdr		*optp;
	mblk_t			*mp2ctl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	/* fixed length IP structure... */
	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = 0;
	SET_MIB(old_ip_mib.ipForwarding,
	    (WE_ARE_FORWARDING(ipst) ? 1 : 2));
	SET_MIB(old_ip_mib.ipDefaultTTL,
	    (uint32_t)ipst->ips_ip_def_ttl);
	SET_MIB(old_ip_mib.ipReasmTimeout,
	    ipst->ips_ip_g_frag_timeout);
	SET_MIB(old_ip_mib.ipAddrEntrySize,
	    sizeof (mib2_ipAddrEntry_t));
	SET_MIB(old_ip_mib.ipRouteEntrySize,
	    sizeof (mib2_ipRouteEntry_t));
	SET_MIB(old_ip_mib.ipNetToMediaEntrySize,
	    sizeof (mib2_ipNetToMediaEntry_t));
	SET_MIB(old_ip_mib.ipMemberEntrySize, sizeof (ip_member_t));
	SET_MIB(old_ip_mib.ipGroupSourceEntrySize, sizeof (ip_grpsrc_t));
	SET_MIB(old_ip_mib.ipRouteAttributeSize,
	    sizeof (mib2_ipAttributeEntry_t));
	SET_MIB(old_ip_mib.transportMLPSize, sizeof (mib2_transportMLPEntry_t));

	/*
	 * Grab the statistics from the new IP MIB
	 */
	SET_MIB(old_ip_mib.ipInReceives,
	    (uint32_t)ipmib->ipIfStatsHCInReceives);
	SET_MIB(old_ip_mib.ipInHdrErrors, ipmib->ipIfStatsInHdrErrors);
	SET_MIB(old_ip_mib.ipInAddrErrors, ipmib->ipIfStatsInAddrErrors);
	SET_MIB(old_ip_mib.ipForwDatagrams,
	    (uint32_t)ipmib->ipIfStatsHCOutForwDatagrams);
	SET_MIB(old_ip_mib.ipInUnknownProtos,
	    ipmib->ipIfStatsInUnknownProtos);
	SET_MIB(old_ip_mib.ipInDiscards, ipmib->ipIfStatsInDiscards);
	SET_MIB(old_ip_mib.ipInDelivers,
	    (uint32_t)ipmib->ipIfStatsHCInDelivers);
	SET_MIB(old_ip_mib.ipOutRequests,
	    (uint32_t)ipmib->ipIfStatsHCOutRequests);
	SET_MIB(old_ip_mib.ipOutDiscards, ipmib->ipIfStatsOutDiscards);
	SET_MIB(old_ip_mib.ipOutNoRoutes, ipmib->ipIfStatsOutNoRoutes);
	SET_MIB(old_ip_mib.ipReasmReqds, ipmib->ipIfStatsReasmReqds);
	SET_MIB(old_ip_mib.ipReasmOKs, ipmib->ipIfStatsReasmOKs);
	SET_MIB(old_ip_mib.ipReasmFails, ipmib->ipIfStatsReasmFails);
	SET_MIB(old_ip_mib.ipFragOKs, ipmib->ipIfStatsOutFragOKs);
	SET_MIB(old_ip_mib.ipFragFails, ipmib->ipIfStatsOutFragFails);
	SET_MIB(old_ip_mib.ipFragCreates, ipmib->ipIfStatsOutFragCreates);

	/* ipRoutingDiscards is not being used */
	SET_MIB(old_ip_mib.ipRoutingDiscards, 0);
	SET_MIB(old_ip_mib.tcpInErrs, ipmib->tcpIfStatsInErrs);
	SET_MIB(old_ip_mib.udpNoPorts, ipmib->udpIfStatsNoPorts);
	SET_MIB(old_ip_mib.ipInCksumErrs, ipmib->ipIfStatsInCksumErrs);
	SET_MIB(old_ip_mib.ipReasmDuplicates,
	    ipmib->ipIfStatsReasmDuplicates);
	SET_MIB(old_ip_mib.ipReasmPartDups, ipmib->ipIfStatsReasmPartDups);
	SET_MIB(old_ip_mib.ipForwProhibits, ipmib->ipIfStatsForwProhibits);
	SET_MIB(old_ip_mib.udpInCksumErrs, ipmib->udpIfStatsInCksumErrs);
	SET_MIB(old_ip_mib.udpInOverflows, ipmib->udpIfStatsInOverflows);
	SET_MIB(old_ip_mib.rawipInOverflows,
	    ipmib->rawipIfStatsInOverflows);

	SET_MIB(old_ip_mib.ipsecInSucceeded, ipmib->ipsecIfStatsInSucceeded);
	SET_MIB(old_ip_mib.ipsecInFailed, ipmib->ipsecIfStatsInFailed);
	SET_MIB(old_ip_mib.ipInIPv6, ipmib->ipIfStatsInWrongIPVersion);
	SET_MIB(old_ip_mib.ipOutIPv6, ipmib->ipIfStatsOutWrongIPVersion);
	SET_MIB(old_ip_mib.ipOutSwitchIPv6,
	    ipmib->ipIfStatsOutSwitchIPVersion);

	if (!snmp_append_data(mpctl->b_cont, (char *)&old_ip_mib,
	    (int)sizeof (old_ip_mib))) {
		ip1dbg(("ip_snmp_get_mib2_ip: failed to allocate %u bytes\n",
		    (uint_t)sizeof (old_ip_mib)));
	}

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_ip: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* Per interface IPv4 statistics */
static mblk_t *
ip_snmp_get_mib2_ip_traffic_stats(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ill_walk_context_t	ctx;
	mblk_t			*mp_tail = NULL;
	mib2_ipIfStatsEntry_t	global_ip_mib;

	/*
	 * Make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = MIB2_IP_TRAFFIC_STATS;
	/* Include "unknown interface" ip_mib */
	ipst->ips_ip_mib.ipIfStatsIPVersion = MIB2_INETADDRESSTYPE_ipv4;
	ipst->ips_ip_mib.ipIfStatsIfIndex =
	    MIB2_UNKNOWN_INTERFACE; /* Flag to netstat */
	SET_MIB(ipst->ips_ip_mib.ipIfStatsForwarding,
	    (ipst->ips_ip_g_forward ? 1 : 2));
	SET_MIB(ipst->ips_ip_mib.ipIfStatsDefaultTTL,
	    (uint32_t)ipst->ips_ip_def_ttl);
	SET_MIB(ipst->ips_ip_mib.ipIfStatsEntrySize,
	    sizeof (mib2_ipIfStatsEntry_t));
	SET_MIB(ipst->ips_ip_mib.ipIfStatsAddrEntrySize,
	    sizeof (mib2_ipAddrEntry_t));
	SET_MIB(ipst->ips_ip_mib.ipIfStatsRouteEntrySize,
	    sizeof (mib2_ipRouteEntry_t));
	SET_MIB(ipst->ips_ip_mib.ipIfStatsNetToMediaEntrySize,
	    sizeof (mib2_ipNetToMediaEntry_t));
	SET_MIB(ipst->ips_ip_mib.ipIfStatsMemberEntrySize,
	    sizeof (ip_member_t));
	SET_MIB(ipst->ips_ip_mib.ipIfStatsGroupSourceEntrySize,
	    sizeof (ip_grpsrc_t));

	if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
	    (char *)&ipst->ips_ip_mib, (int)sizeof (ipst->ips_ip_mib))) {
		ip1dbg(("ip_snmp_get_mib2_ip_traffic_stats: "
		    "failed to allocate %u bytes\n",
		    (uint_t)sizeof (ipst->ips_ip_mib)));
	}

	bcopy(&ipst->ips_ip_mib, &global_ip_mib, sizeof (global_ip_mib));

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ill->ill_ip_mib->ipIfStatsIfIndex =
		    ill->ill_phyint->phyint_ifindex;
		SET_MIB(ill->ill_ip_mib->ipIfStatsForwarding,
		    (ipst->ips_ip_g_forward ? 1 : 2));
		SET_MIB(ill->ill_ip_mib->ipIfStatsDefaultTTL,
		    (uint32_t)ipst->ips_ip_def_ttl);

		ip_mib2_add_ip_stats(&global_ip_mib, ill->ill_ip_mib);
		if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
		    (char *)ill->ill_ip_mib,
		    (int)sizeof (*ill->ill_ip_mib))) {
			ip1dbg(("ip_snmp_get_mib2_ip_traffic_stats: "
			    "failed to allocate %u bytes\n",
			    (uint_t)sizeof (*ill->ill_ip_mib)));
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_ip_traffic_stats: "
	    "level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);

	if (mp2ctl == NULL)
		return (NULL);

	return (ip_snmp_get_mib2_ip(q, mp2ctl, &global_ip_mib, ipst));
}

/* Global IPv4 ICMP statistics */
static mblk_t *
ip_snmp_get_mib2_icmp(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;

	/*
	 * Make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_ICMP;
	optp->name = 0;
	if (!snmp_append_data(mpctl->b_cont, (char *)&ipst->ips_icmp_mib,
	    (int)sizeof (ipst->ips_icmp_mib))) {
		ip1dbg(("ip_snmp_get_mib2_icmp: failed to allocate %u bytes\n",
		    (uint_t)sizeof (ipst->ips_icmp_mib)));
	}
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_icmp: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* Global IPv4 IGMP statistics */
static mblk_t *
ip_snmp_get_mib2_igmp(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = EXPER_IGMP;
	optp->name = 0;
	if (!snmp_append_data(mpctl->b_cont, (char *)&ipst->ips_igmpstat,
	    (int)sizeof (ipst->ips_igmpstat))) {
		ip1dbg(("ip_snmp_get_mib2_igmp: failed to allocate %u bytes\n",
		    (uint_t)sizeof (ipst->ips_igmpstat)));
	}
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_igmp: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* Global IPv4 Multicast Routing statistics */
static mblk_t *
ip_snmp_get_mib2_multi(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = EXPER_DVMRP;
	optp->name = 0;
	if (!ip_mroute_stats(mpctl->b_cont, ipst)) {
		ip0dbg(("ip_mroute_stats: failed\n"));
	}
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_multi: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* IPv4 address information */
static mblk_t *
ip_snmp_get_mib2_ip_addr(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	mblk_t			*mp_tail = NULL;
	ill_t			*ill;
	ipif_t			*ipif;
	uint_t			bitval;
	mib2_ipAddrEntry_t	mae;
	zoneid_t		zoneid;
	ill_walk_context_t ctx;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	/* ipAddrEntryTable */

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = MIB2_IP_ADDR;
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			mae.ipAdEntInfo.ae_ibcnt = ipif->ipif_ib_pkt_count;
			mae.ipAdEntInfo.ae_obcnt = ipif->ipif_ob_pkt_count;
			mae.ipAdEntInfo.ae_focnt = ipif->ipif_fo_pkt_count;

			ipif_get_name(ipif, mae.ipAdEntIfIndex.o_bytes,
			    OCTET_LENGTH);
			mae.ipAdEntIfIndex.o_length =
			    mi_strlen(mae.ipAdEntIfIndex.o_bytes);
			mae.ipAdEntAddr = ipif->ipif_lcl_addr;
			mae.ipAdEntNetMask = ipif->ipif_net_mask;
			mae.ipAdEntInfo.ae_subnet = ipif->ipif_subnet;
			mae.ipAdEntInfo.ae_subnet_len =
			    ip_mask_to_plen(ipif->ipif_net_mask);
			mae.ipAdEntInfo.ae_src_addr = ipif->ipif_src_addr;
			for (bitval = 1;
			    bitval &&
			    !(bitval & ipif->ipif_brd_addr);
			    bitval <<= 1)
				noop;
			mae.ipAdEntBcastAddr = bitval;
			mae.ipAdEntReasmMaxSize = IP_MAXPACKET;
			mae.ipAdEntInfo.ae_mtu = ipif->ipif_mtu;
			mae.ipAdEntInfo.ae_metric  = ipif->ipif_metric;
			mae.ipAdEntInfo.ae_broadcast_addr =
			    ipif->ipif_brd_addr;
			mae.ipAdEntInfo.ae_pp_dst_addr =
			    ipif->ipif_pp_dst_addr;
			mae.ipAdEntInfo.ae_flags = ipif->ipif_flags |
			    ill->ill_flags | ill->ill_phyint->phyint_flags;
			mae.ipAdEntRetransmitTime = AR_EQ_DEFAULT_XMIT_INTERVAL;

			if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
			    (char *)&mae, (int)sizeof (mib2_ipAddrEntry_t))) {
				ip1dbg(("ip_snmp_get_mib2_ip_addr: failed to "
				    "allocate %u bytes\n",
				    (uint_t)sizeof (mib2_ipAddrEntry_t)));
			}
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_ip_addr: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* IPv6 address information */
static mblk_t *
ip_snmp_get_mib2_ip6_addr(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	mblk_t			*mp_tail = NULL;
	ill_t			*ill;
	ipif_t			*ipif;
	mib2_ipv6AddrEntry_t	mae6;
	zoneid_t		zoneid;
	ill_walk_context_t	ctx;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	/* ipv6AddrEntryTable */

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = MIB2_IP6_ADDR;
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			mae6.ipv6AddrInfo.ae_ibcnt = ipif->ipif_ib_pkt_count;
			mae6.ipv6AddrInfo.ae_obcnt = ipif->ipif_ob_pkt_count;
			mae6.ipv6AddrInfo.ae_focnt = ipif->ipif_fo_pkt_count;

			ipif_get_name(ipif, mae6.ipv6AddrIfIndex.o_bytes,
			    OCTET_LENGTH);
			mae6.ipv6AddrIfIndex.o_length =
			    mi_strlen(mae6.ipv6AddrIfIndex.o_bytes);
			mae6.ipv6AddrAddress = ipif->ipif_v6lcl_addr;
			mae6.ipv6AddrPfxLength =
			    ip_mask_to_plen_v6(&ipif->ipif_v6net_mask);
			mae6.ipv6AddrInfo.ae_subnet = ipif->ipif_v6subnet;
			mae6.ipv6AddrInfo.ae_subnet_len =
			    mae6.ipv6AddrPfxLength;
			mae6.ipv6AddrInfo.ae_src_addr = ipif->ipif_v6src_addr;

			/* Type: stateless(1), stateful(2), unknown(3) */
			if (ipif->ipif_flags & IPIF_ADDRCONF)
				mae6.ipv6AddrType = 1;
			else
				mae6.ipv6AddrType = 2;
			/* Anycast: true(1), false(2) */
			if (ipif->ipif_flags & IPIF_ANYCAST)
				mae6.ipv6AddrAnycastFlag = 1;
			else
				mae6.ipv6AddrAnycastFlag = 2;

			/*
			 * Address status: preferred(1), deprecated(2),
			 * invalid(3), inaccessible(4), unknown(5)
			 */
			if (ipif->ipif_flags & IPIF_NOLOCAL)
				mae6.ipv6AddrStatus = 3;
			else if (ipif->ipif_flags & IPIF_DEPRECATED)
				mae6.ipv6AddrStatus = 2;
			else
				mae6.ipv6AddrStatus = 1;
			mae6.ipv6AddrInfo.ae_mtu = ipif->ipif_mtu;
			mae6.ipv6AddrInfo.ae_metric  = ipif->ipif_metric;
			mae6.ipv6AddrInfo.ae_pp_dst_addr =
			    ipif->ipif_v6pp_dst_addr;
			mae6.ipv6AddrInfo.ae_flags = ipif->ipif_flags |
			    ill->ill_flags | ill->ill_phyint->phyint_flags;
			mae6.ipv6AddrReasmMaxSize = IP_MAXPACKET;
			mae6.ipv6AddrIdentifier = ill->ill_token;
			mae6.ipv6AddrIdentifierLen = ill->ill_token_length;
			mae6.ipv6AddrReachableTime = ill->ill_reachable_time;
			mae6.ipv6AddrRetransmitTime =
			    ill->ill_reachable_retrans_time;
			if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
			    (char *)&mae6,
			    (int)sizeof (mib2_ipv6AddrEntry_t))) {
				ip1dbg(("ip_snmp_get_mib2_ip6_addr: failed to "
				    "allocate %u bytes\n",
				    (uint_t)sizeof (mib2_ipv6AddrEntry_t)));
			}
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_ip6_addr: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* IPv4 multicast group membership. */
static mblk_t *
ip_snmp_get_mib2_ip_group_mem(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ipif_t			*ipif;
	ilm_t			*ilm;
	ip_member_t		ipm;
	mblk_t			*mp_tail = NULL;
	ill_walk_context_t	ctx;
	zoneid_t		zoneid;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/* ipGroupMember table */
	optp = (struct opthdr *)&mpctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = EXPER_IP_GROUP_MEMBERSHIP;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ILM_WALKER_HOLD(ill);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;	/* not this zone */
			ipif_get_name(ipif, ipm.ipGroupMemberIfIndex.o_bytes,
			    OCTET_LENGTH);
			ipm.ipGroupMemberIfIndex.o_length =
			    mi_strlen(ipm.ipGroupMemberIfIndex.o_bytes);
			for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
				ASSERT(ilm->ilm_ipif != NULL);
				ASSERT(ilm->ilm_ill == NULL);
				if (ilm->ilm_ipif != ipif)
					continue;
				ipm.ipGroupMemberAddress = ilm->ilm_addr;
				ipm.ipGroupMemberRefCnt = ilm->ilm_refcnt;
				ipm.ipGroupMemberFilterMode = ilm->ilm_fmode;
				if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
				    (char *)&ipm, (int)sizeof (ipm))) {
					ip1dbg(("ip_snmp_get_mib2_ip_group: "
					    "failed to allocate %u bytes\n",
					    (uint_t)sizeof (ipm)));
				}
			}
		}
		ILM_WALKER_RELE(ill);
	}
	rw_exit(&ipst->ips_ill_g_lock);
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* IPv6 multicast group membership. */
static mblk_t *
ip_snmp_get_mib2_ip6_group_mem(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ilm_t			*ilm;
	ipv6_member_t		ipm6;
	mblk_t			*mp_tail = NULL;
	ill_walk_context_t	ctx;
	zoneid_t		zoneid;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/* ip6GroupMember table */
	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = EXPER_IP6_GROUP_MEMBERSHIP;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ILM_WALKER_HOLD(ill);
		ipm6.ipv6GroupMemberIfIndex = ill->ill_phyint->phyint_ifindex;
		for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
			ASSERT(ilm->ilm_ipif == NULL);
			ASSERT(ilm->ilm_ill != NULL);
			if (ilm->ilm_zoneid != zoneid)
				continue;	/* not this zone */
			ipm6.ipv6GroupMemberAddress = ilm->ilm_v6addr;
			ipm6.ipv6GroupMemberRefCnt = ilm->ilm_refcnt;
			ipm6.ipv6GroupMemberFilterMode = ilm->ilm_fmode;
			if (!snmp_append_data2(mpctl->b_cont,
			    &mp_tail,
			    (char *)&ipm6, (int)sizeof (ipm6))) {
				ip1dbg(("ip_snmp_get_mib2_ip6_group: "
				    "failed to allocate %u bytes\n",
				    (uint_t)sizeof (ipm6)));
			}
		}
		ILM_WALKER_RELE(ill);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* IP multicast filtered sources */
static mblk_t *
ip_snmp_get_mib2_ip_group_src(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ipif_t			*ipif;
	ilm_t			*ilm;
	ip_grpsrc_t		ips;
	mblk_t			*mp_tail = NULL;
	ill_walk_context_t	ctx;
	zoneid_t		zoneid;
	int			i;
	slist_t			*sl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/* ipGroupSource table */
	optp = (struct opthdr *)&mpctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = EXPER_IP_GROUP_SOURCES;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ILM_WALKER_HOLD(ill);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (ipif->ipif_zoneid != zoneid)
				continue;	/* not this zone */
			ipif_get_name(ipif, ips.ipGroupSourceIfIndex.o_bytes,
			    OCTET_LENGTH);
			ips.ipGroupSourceIfIndex.o_length =
			    mi_strlen(ips.ipGroupSourceIfIndex.o_bytes);
			for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
				ASSERT(ilm->ilm_ipif != NULL);
				ASSERT(ilm->ilm_ill == NULL);
				sl = ilm->ilm_filter;
				if (ilm->ilm_ipif != ipif || SLIST_IS_EMPTY(sl))
					continue;
				ips.ipGroupSourceGroup = ilm->ilm_addr;
				for (i = 0; i < sl->sl_numsrc; i++) {
					if (!IN6_IS_ADDR_V4MAPPED(
					    &sl->sl_addr[i]))
						continue;
					IN6_V4MAPPED_TO_IPADDR(&sl->sl_addr[i],
					    ips.ipGroupSourceAddress);
					if (snmp_append_data2(mpctl->b_cont,
					    &mp_tail, (char *)&ips,
					    (int)sizeof (ips)) == 0) {
						ip1dbg(("ip_snmp_get_mib2_"
						    "ip_group_src: failed to "
						    "allocate %u bytes\n",
						    (uint_t)sizeof (ips)));
					}
				}
			}
		}
		ILM_WALKER_RELE(ill);
	}
	rw_exit(&ipst->ips_ill_g_lock);
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* IPv6 multicast filtered sources. */
static mblk_t *
ip_snmp_get_mib2_ip6_group_src(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ilm_t			*ilm;
	ipv6_grpsrc_t		ips6;
	mblk_t			*mp_tail = NULL;
	ill_walk_context_t	ctx;
	zoneid_t		zoneid;
	int			i;
	slist_t			*sl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/* ip6GroupMember table */
	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = EXPER_IP6_GROUP_SOURCES;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ILM_WALKER_HOLD(ill);
		ips6.ipv6GroupSourceIfIndex = ill->ill_phyint->phyint_ifindex;
		for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
			ASSERT(ilm->ilm_ipif == NULL);
			ASSERT(ilm->ilm_ill != NULL);
			sl = ilm->ilm_filter;
			if (ilm->ilm_zoneid != zoneid || SLIST_IS_EMPTY(sl))
				continue;
			ips6.ipv6GroupSourceGroup = ilm->ilm_v6addr;
			for (i = 0; i < sl->sl_numsrc; i++) {
				ips6.ipv6GroupSourceAddress = sl->sl_addr[i];
				if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
				    (char *)&ips6, (int)sizeof (ips6))) {
					ip1dbg(("ip_snmp_get_mib2_ip6_"
					    "group_src: failed to allocate "
					    "%u bytes\n",
					    (uint_t)sizeof (ips6)));
				}
			}
		}
		ILM_WALKER_RELE(ill);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* Multicast routing virtual interface table. */
static mblk_t *
ip_snmp_get_mib2_virt_multi(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = EXPER_DVMRP;
	optp->name = EXPER_DVMRP_VIF;
	if (!ip_mroute_vif(mpctl->b_cont, ipst)) {
		ip0dbg(("ip_mroute_vif: failed\n"));
	}
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_virt_multi: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/* Multicast routing table. */
static mblk_t *
ip_snmp_get_mib2_multi_rtable(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = EXPER_DVMRP;
	optp->name = EXPER_DVMRP_MRT;
	if (!ip_mroute_mrt(mpctl->b_cont, ipst)) {
		ip0dbg(("ip_mroute_mrt: failed\n"));
	}
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_multi_rtable: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/*
 * Return ipRouteEntryTable, ipNetToMediaEntryTable, and ipRouteAttributeTable
 * in one IRE walk.
 */
static mblk_t *
ip_snmp_get_mib2_ip_route_media(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr	*optp;
	mblk_t		*mp2ctl;	/* Returned */
	mblk_t		*mp3ctl;	/* nettomedia */
	mblk_t		*mp4ctl;	/* routeattrs */
	iproutedata_t	ird;
	zoneid_t	zoneid;

	/*
	 * make copies of the original message
	 *	- mp2ctl is returned unchanged to the caller for his use
	 *	- mpctl is sent upstream as ipRouteEntryTable
	 *	- mp3ctl is sent upstream as ipNetToMediaEntryTable
	 *	- mp4ctl is sent upstream as ipRouteAttributeTable
	 */
	mp2ctl = copymsg(mpctl);
	mp3ctl = copymsg(mpctl);
	mp4ctl = copymsg(mpctl);
	if (mp3ctl == NULL || mp4ctl == NULL) {
		freemsg(mp4ctl);
		freemsg(mp3ctl);
		freemsg(mp2ctl);
		freemsg(mpctl);
		return (NULL);
	}

	bzero(&ird, sizeof (ird));

	ird.ird_route.lp_head = mpctl->b_cont;
	ird.ird_netmedia.lp_head = mp3ctl->b_cont;
	ird.ird_attrs.lp_head = mp4ctl->b_cont;

	zoneid = Q_TO_CONN(q)->conn_zoneid;
	ire_walk_v4(ip_snmp_get2_v4, &ird, zoneid, ipst);

	/* ipRouteEntryTable in mpctl */
	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = MIB2_IP_ROUTE;
	optp->len = msgdsize(ird.ird_route.lp_head);
	ip3dbg(("ip_snmp_get_mib2_ip_route_media: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);

	/* ipNetToMediaEntryTable in mp3ctl */
	optp = (struct opthdr *)&mp3ctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = MIB2_IP_MEDIA;
	optp->len = msgdsize(ird.ird_netmedia.lp_head);
	ip3dbg(("ip_snmp_get_mib2_ip_route_media: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mp3ctl);

	/* ipRouteAttributeTable in mp4ctl */
	optp = (struct opthdr *)&mp4ctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = EXPER_IP_RTATTR;
	optp->len = msgdsize(ird.ird_attrs.lp_head);
	ip3dbg(("ip_snmp_get_mib2_ip_route_media: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	if (optp->len == 0)
		freemsg(mp4ctl);
	else
		qreply(q, mp4ctl);

	return (mp2ctl);
}

/*
 * Return ipv6RouteEntryTable and ipv6RouteAttributeTable in one IRE walk, and
 * ipv6NetToMediaEntryTable in an NDP walk.
 */
static mblk_t *
ip_snmp_get_mib2_ip6_route_media(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr	*optp;
	mblk_t		*mp2ctl;	/* Returned */
	mblk_t		*mp3ctl;	/* nettomedia */
	mblk_t		*mp4ctl;	/* routeattrs */
	iproutedata_t	ird;
	zoneid_t	zoneid;

	/*
	 * make copies of the original message
	 *	- mp2ctl is returned unchanged to the caller for his use
	 *	- mpctl is sent upstream as ipv6RouteEntryTable
	 *	- mp3ctl is sent upstream as ipv6NetToMediaEntryTable
	 *	- mp4ctl is sent upstream as ipv6RouteAttributeTable
	 */
	mp2ctl = copymsg(mpctl);
	mp3ctl = copymsg(mpctl);
	mp4ctl = copymsg(mpctl);
	if (mp3ctl == NULL || mp4ctl == NULL) {
		freemsg(mp4ctl);
		freemsg(mp3ctl);
		freemsg(mp2ctl);
		freemsg(mpctl);
		return (NULL);
	}

	bzero(&ird, sizeof (ird));

	ird.ird_route.lp_head = mpctl->b_cont;
	ird.ird_netmedia.lp_head = mp3ctl->b_cont;
	ird.ird_attrs.lp_head = mp4ctl->b_cont;

	zoneid = Q_TO_CONN(q)->conn_zoneid;
	ire_walk_v6(ip_snmp_get2_v6_route, &ird, zoneid, ipst);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = MIB2_IP6_ROUTE;
	optp->len = msgdsize(ird.ird_route.lp_head);
	ip3dbg(("ip_snmp_get_mib2_ip6_route_media: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);

	/* ipv6NetToMediaEntryTable in mp3ctl */
	ndp_walk(NULL, ip_snmp_get2_v6_media, &ird, ipst);

	optp = (struct opthdr *)&mp3ctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = MIB2_IP6_MEDIA;
	optp->len = msgdsize(ird.ird_netmedia.lp_head);
	ip3dbg(("ip_snmp_get_mib2_ip6_route_media: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mp3ctl);

	/* ipv6RouteAttributeTable in mp4ctl */
	optp = (struct opthdr *)&mp4ctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = EXPER_IP_RTATTR;
	optp->len = msgdsize(ird.ird_attrs.lp_head);
	ip3dbg(("ip_snmp_get_mib2_ip6_route_media: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	if (optp->len == 0)
		freemsg(mp4ctl);
	else
		qreply(q, mp4ctl);

	return (mp2ctl);
}

/*
 * IPv6 mib: One per ill
 */
static mblk_t *
ip_snmp_get_mib2_ip6(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ill_walk_context_t	ctx;
	mblk_t			*mp_tail = NULL;

	/*
	 * Make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	/* fixed length IPv6 structure ... */

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = 0;
	/* Include "unknown interface" ip6_mib */
	ipst->ips_ip6_mib.ipIfStatsIPVersion = MIB2_INETADDRESSTYPE_ipv6;
	ipst->ips_ip6_mib.ipIfStatsIfIndex =
	    MIB2_UNKNOWN_INTERFACE; /* Flag to netstat */
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsForwarding,
	    ipst->ips_ipv6_forward ? 1 : 2);
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsDefaultHopLimit,
	    ipst->ips_ipv6_def_hops);
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsEntrySize,
	    sizeof (mib2_ipIfStatsEntry_t));
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsAddrEntrySize,
	    sizeof (mib2_ipv6AddrEntry_t));
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsRouteEntrySize,
	    sizeof (mib2_ipv6RouteEntry_t));
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsNetToMediaEntrySize,
	    sizeof (mib2_ipv6NetToMediaEntry_t));
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsMemberEntrySize,
	    sizeof (ipv6_member_t));
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsGroupSourceEntrySize,
	    sizeof (ipv6_grpsrc_t));

	/*
	 * Synchronize 64- and 32-bit counters
	 */
	SYNC32_MIB(&ipst->ips_ip6_mib, ipIfStatsInReceives,
	    ipIfStatsHCInReceives);
	SYNC32_MIB(&ipst->ips_ip6_mib, ipIfStatsInDelivers,
	    ipIfStatsHCInDelivers);
	SYNC32_MIB(&ipst->ips_ip6_mib, ipIfStatsOutRequests,
	    ipIfStatsHCOutRequests);
	SYNC32_MIB(&ipst->ips_ip6_mib, ipIfStatsOutForwDatagrams,
	    ipIfStatsHCOutForwDatagrams);
	SYNC32_MIB(&ipst->ips_ip6_mib, ipIfStatsOutMcastPkts,
	    ipIfStatsHCOutMcastPkts);
	SYNC32_MIB(&ipst->ips_ip6_mib, ipIfStatsInMcastPkts,
	    ipIfStatsHCInMcastPkts);

	if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
	    (char *)&ipst->ips_ip6_mib, (int)sizeof (ipst->ips_ip6_mib))) {
		ip1dbg(("ip_snmp_get_mib2_ip6: failed to allocate %u bytes\n",
		    (uint_t)sizeof (ipst->ips_ip6_mib)));
	}

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ill->ill_ip_mib->ipIfStatsIfIndex =
		    ill->ill_phyint->phyint_ifindex;
		SET_MIB(ill->ill_ip_mib->ipIfStatsForwarding,
		    ipst->ips_ipv6_forward ? 1 : 2);
		SET_MIB(ill->ill_ip_mib->ipIfStatsDefaultHopLimit,
		    ill->ill_max_hops);

		/*
		 * Synchronize 64- and 32-bit counters
		 */
		SYNC32_MIB(ill->ill_ip_mib, ipIfStatsInReceives,
		    ipIfStatsHCInReceives);
		SYNC32_MIB(ill->ill_ip_mib, ipIfStatsInDelivers,
		    ipIfStatsHCInDelivers);
		SYNC32_MIB(ill->ill_ip_mib, ipIfStatsOutRequests,
		    ipIfStatsHCOutRequests);
		SYNC32_MIB(ill->ill_ip_mib, ipIfStatsOutForwDatagrams,
		    ipIfStatsHCOutForwDatagrams);
		SYNC32_MIB(ill->ill_ip_mib, ipIfStatsOutMcastPkts,
		    ipIfStatsHCOutMcastPkts);
		SYNC32_MIB(ill->ill_ip_mib, ipIfStatsInMcastPkts,
		    ipIfStatsHCInMcastPkts);

		if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
		    (char *)ill->ill_ip_mib,
		    (int)sizeof (*ill->ill_ip_mib))) {
			ip1dbg(("ip_snmp_get_mib2_ip6: failed to allocate "
			"%u bytes\n", (uint_t)sizeof (*ill->ill_ip_mib)));
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_ip6: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/*
 * ICMPv6 mib: One per ill
 */
static mblk_t *
ip_snmp_get_mib2_icmp6(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ill_walk_context_t	ctx;
	mblk_t			*mp_tail = NULL;
	/*
	 * Make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	/* fixed length ICMPv6 structure ... */

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_ICMP6;
	optp->name = 0;
	/* Include "unknown interface" icmp6_mib */
	ipst->ips_icmp6_mib.ipv6IfIcmpIfIndex =
	    MIB2_UNKNOWN_INTERFACE; /* netstat flag */
	ipst->ips_icmp6_mib.ipv6IfIcmpEntrySize =
	    sizeof (mib2_ipv6IfIcmpEntry_t);
	if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
	    (char *)&ipst->ips_icmp6_mib,
	    (int)sizeof (ipst->ips_icmp6_mib))) {
		ip1dbg(("ip_snmp_get_mib2_icmp6: failed to allocate %u bytes\n",
		    (uint_t)sizeof (ipst->ips_icmp6_mib)));
	}

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ill->ill_icmp6_mib->ipv6IfIcmpIfIndex =
		    ill->ill_phyint->phyint_ifindex;
		if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
		    (char *)ill->ill_icmp6_mib,
		    (int)sizeof (*ill->ill_icmp6_mib))) {
			ip1dbg(("ip_snmp_get_mib2_icmp6: failed to allocate "
			    "%u bytes\n",
			    (uint_t)sizeof (*ill->ill_icmp6_mib)));
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);

	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get_mib2_icmp6: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);
	return (mp2ctl);
}

/*
 * ire_walk routine to create both ipRouteEntryTable and
 * ipRouteAttributeTable in one IRE walk
 */
static void
ip_snmp_get2_v4(ire_t *ire, iproutedata_t *ird)
{
	ill_t				*ill;
	ipif_t				*ipif;
	mib2_ipRouteEntry_t		*re;
	mib2_ipAttributeEntry_t		*iae, *iaeptr;
	ipaddr_t			gw_addr;
	tsol_ire_gw_secattr_t		*attrp;
	tsol_gc_t			*gc = NULL;
	tsol_gcgrp_t			*gcgrp = NULL;
	uint_t				sacnt = 0;
	int				i;

	ASSERT(ire->ire_ipversion == IPV4_VERSION);

	if ((re = kmem_zalloc(sizeof (*re), KM_NOSLEEP)) == NULL)
		return;

	if ((attrp = ire->ire_gw_secattr) != NULL) {
		mutex_enter(&attrp->igsa_lock);
		if ((gc = attrp->igsa_gc) != NULL) {
			gcgrp = gc->gc_grp;
			ASSERT(gcgrp != NULL);
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
			sacnt = 1;
		} else if ((gcgrp = attrp->igsa_gcgrp) != NULL) {
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
			gc = gcgrp->gcgrp_head;
			sacnt = gcgrp->gcgrp_count;
		}
		mutex_exit(&attrp->igsa_lock);

		/* do nothing if there's no gc to report */
		if (gc == NULL) {
			ASSERT(sacnt == 0);
			if (gcgrp != NULL) {
				/* we might as well drop the lock now */
				rw_exit(&gcgrp->gcgrp_rwlock);
				gcgrp = NULL;
			}
			attrp = NULL;
		}

		ASSERT(gc == NULL || (gcgrp != NULL &&
		    RW_LOCK_HELD(&gcgrp->gcgrp_rwlock)));
	}
	ASSERT(sacnt == 0 || gc != NULL);

	if (sacnt != 0 &&
	    (iae = kmem_alloc(sacnt * sizeof (*iae), KM_NOSLEEP)) == NULL) {
		kmem_free(re, sizeof (*re));
		rw_exit(&gcgrp->gcgrp_rwlock);
		return;
	}

	/*
	 * Return all IRE types for route table... let caller pick and choose
	 */
	re->ipRouteDest = ire->ire_addr;
	ipif = ire->ire_ipif;
	re->ipRouteIfIndex.o_length = 0;
	if (ire->ire_type == IRE_CACHE) {
		ill = (ill_t *)ire->ire_stq->q_ptr;
		re->ipRouteIfIndex.o_length =
		    ill->ill_name_length == 0 ? 0 :
		    MIN(OCTET_LENGTH, ill->ill_name_length - 1);
		bcopy(ill->ill_name, re->ipRouteIfIndex.o_bytes,
		    re->ipRouteIfIndex.o_length);
	} else if (ipif != NULL) {
		ipif_get_name(ipif, re->ipRouteIfIndex.o_bytes, OCTET_LENGTH);
		re->ipRouteIfIndex.o_length =
		    mi_strlen(re->ipRouteIfIndex.o_bytes);
	}
	re->ipRouteMetric1 = -1;
	re->ipRouteMetric2 = -1;
	re->ipRouteMetric3 = -1;
	re->ipRouteMetric4 = -1;

	gw_addr = ire->ire_gateway_addr;

	if (ire->ire_type & (IRE_INTERFACE|IRE_LOOPBACK|IRE_BROADCAST))
		re->ipRouteNextHop = ire->ire_src_addr;
	else
		re->ipRouteNextHop = gw_addr;
	/* indirect(4), direct(3), or invalid(2) */
	if (ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE))
		re->ipRouteType = 2;
	else
		re->ipRouteType = (gw_addr != 0) ? 4 : 3;
	re->ipRouteProto = -1;
	re->ipRouteAge = gethrestime_sec() - ire->ire_create_time;
	re->ipRouteMask = ire->ire_mask;
	re->ipRouteMetric5 = -1;
	re->ipRouteInfo.re_max_frag	= ire->ire_max_frag;
	re->ipRouteInfo.re_frag_flag	= ire->ire_frag_flag;
	re->ipRouteInfo.re_rtt		= ire->ire_uinfo.iulp_rtt;
	re->ipRouteInfo.re_ref		= ire->ire_refcnt;
	re->ipRouteInfo.re_src_addr	= ire->ire_src_addr;
	re->ipRouteInfo.re_obpkt	= ire->ire_ob_pkt_count;
	re->ipRouteInfo.re_ibpkt	= ire->ire_ib_pkt_count;
	re->ipRouteInfo.re_flags	= ire->ire_flags;

	if (ire->ire_flags & RTF_DYNAMIC) {
		re->ipRouteInfo.re_ire_type	= IRE_HOST_REDIRECT;
	} else {
		re->ipRouteInfo.re_ire_type	= ire->ire_type;
	}

	if (!snmp_append_data2(ird->ird_route.lp_head, &ird->ird_route.lp_tail,
	    (char *)re, (int)sizeof (*re))) {
		ip1dbg(("ip_snmp_get2_v4: failed to allocate %u bytes\n",
		    (uint_t)sizeof (*re)));
	}

	for (iaeptr = iae, i = 0; i < sacnt; i++, iaeptr++, gc = gc->gc_next) {
		iaeptr->iae_routeidx = ird->ird_idx;
		iaeptr->iae_doi = gc->gc_db->gcdb_doi;
		iaeptr->iae_slrange = gc->gc_db->gcdb_slrange;
	}

	if (!snmp_append_data2(ird->ird_attrs.lp_head, &ird->ird_attrs.lp_tail,
	    (char *)iae, sacnt * sizeof (*iae))) {
		ip1dbg(("ip_snmp_get2_v4: failed to allocate %u bytes\n",
		    (unsigned)(sacnt * sizeof (*iae))));
	}

	/* bump route index for next pass */
	ird->ird_idx++;

	kmem_free(re, sizeof (*re));
	if (sacnt != 0)
		kmem_free(iae, sacnt * sizeof (*iae));

	if (gcgrp != NULL)
		rw_exit(&gcgrp->gcgrp_rwlock);
}

/*
 * ire_walk routine to create ipv6RouteEntryTable and ipRouteEntryTable.
 */
static void
ip_snmp_get2_v6_route(ire_t *ire, iproutedata_t *ird)
{
	ill_t				*ill;
	ipif_t				*ipif;
	mib2_ipv6RouteEntry_t		*re;
	mib2_ipAttributeEntry_t		*iae, *iaeptr;
	in6_addr_t			gw_addr_v6;
	tsol_ire_gw_secattr_t		*attrp;
	tsol_gc_t			*gc = NULL;
	tsol_gcgrp_t			*gcgrp = NULL;
	uint_t				sacnt = 0;
	int				i;

	ASSERT(ire->ire_ipversion == IPV6_VERSION);

	if ((re = kmem_zalloc(sizeof (*re), KM_NOSLEEP)) == NULL)
		return;

	if ((attrp = ire->ire_gw_secattr) != NULL) {
		mutex_enter(&attrp->igsa_lock);
		if ((gc = attrp->igsa_gc) != NULL) {
			gcgrp = gc->gc_grp;
			ASSERT(gcgrp != NULL);
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
			sacnt = 1;
		} else if ((gcgrp = attrp->igsa_gcgrp) != NULL) {
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
			gc = gcgrp->gcgrp_head;
			sacnt = gcgrp->gcgrp_count;
		}
		mutex_exit(&attrp->igsa_lock);

		/* do nothing if there's no gc to report */
		if (gc == NULL) {
			ASSERT(sacnt == 0);
			if (gcgrp != NULL) {
				/* we might as well drop the lock now */
				rw_exit(&gcgrp->gcgrp_rwlock);
				gcgrp = NULL;
			}
			attrp = NULL;
		}

		ASSERT(gc == NULL || (gcgrp != NULL &&
		    RW_LOCK_HELD(&gcgrp->gcgrp_rwlock)));
	}
	ASSERT(sacnt == 0 || gc != NULL);

	if (sacnt != 0 &&
	    (iae = kmem_alloc(sacnt * sizeof (*iae), KM_NOSLEEP)) == NULL) {
		kmem_free(re, sizeof (*re));
		rw_exit(&gcgrp->gcgrp_rwlock);
		return;
	}

	/*
	 * Return all IRE types for route table... let caller pick and choose
	 */
	re->ipv6RouteDest = ire->ire_addr_v6;
	re->ipv6RoutePfxLength = ip_mask_to_plen_v6(&ire->ire_mask_v6);
	re->ipv6RouteIndex = 0;	/* Unique when multiple with same dest/plen */
	re->ipv6RouteIfIndex.o_length = 0;
	ipif = ire->ire_ipif;
	if (ire->ire_type == IRE_CACHE) {
		ill = (ill_t *)ire->ire_stq->q_ptr;
		re->ipv6RouteIfIndex.o_length =
		    ill->ill_name_length == 0 ? 0 :
		    MIN(OCTET_LENGTH, ill->ill_name_length - 1);
		bcopy(ill->ill_name, re->ipv6RouteIfIndex.o_bytes,
		    re->ipv6RouteIfIndex.o_length);
	} else if (ipif != NULL) {
		ipif_get_name(ipif, re->ipv6RouteIfIndex.o_bytes, OCTET_LENGTH);
		re->ipv6RouteIfIndex.o_length =
		    mi_strlen(re->ipv6RouteIfIndex.o_bytes);
	}

	ASSERT(!(ire->ire_type & IRE_BROADCAST));

	mutex_enter(&ire->ire_lock);
	gw_addr_v6 = ire->ire_gateway_addr_v6;
	mutex_exit(&ire->ire_lock);

	if (ire->ire_type & (IRE_INTERFACE|IRE_LOOPBACK))
		re->ipv6RouteNextHop = ire->ire_src_addr_v6;
	else
		re->ipv6RouteNextHop = gw_addr_v6;

	/* remote(4), local(3), or discard(2) */
	if (ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE))
		re->ipv6RouteType = 2;
	else if (IN6_IS_ADDR_UNSPECIFIED(&gw_addr_v6))
		re->ipv6RouteType = 3;
	else
		re->ipv6RouteType = 4;

	re->ipv6RouteProtocol	= -1;
	re->ipv6RoutePolicy	= 0;
	re->ipv6RouteAge	= gethrestime_sec() - ire->ire_create_time;
	re->ipv6RouteNextHopRDI	= 0;
	re->ipv6RouteWeight	= 0;
	re->ipv6RouteMetric	= 0;
	re->ipv6RouteInfo.re_max_frag	= ire->ire_max_frag;
	re->ipv6RouteInfo.re_frag_flag	= ire->ire_frag_flag;
	re->ipv6RouteInfo.re_rtt	= ire->ire_uinfo.iulp_rtt;
	re->ipv6RouteInfo.re_src_addr	= ire->ire_src_addr_v6;
	re->ipv6RouteInfo.re_obpkt	= ire->ire_ob_pkt_count;
	re->ipv6RouteInfo.re_ibpkt	= ire->ire_ib_pkt_count;
	re->ipv6RouteInfo.re_ref	= ire->ire_refcnt;
	re->ipv6RouteInfo.re_flags	= ire->ire_flags;

	if (ire->ire_flags & RTF_DYNAMIC) {
		re->ipv6RouteInfo.re_ire_type	= IRE_HOST_REDIRECT;
	} else {
		re->ipv6RouteInfo.re_ire_type	= ire->ire_type;
	}

	if (!snmp_append_data2(ird->ird_route.lp_head, &ird->ird_route.lp_tail,
	    (char *)re, (int)sizeof (*re))) {
		ip1dbg(("ip_snmp_get2_v6: failed to allocate %u bytes\n",
		    (uint_t)sizeof (*re)));
	}

	for (iaeptr = iae, i = 0; i < sacnt; i++, iaeptr++, gc = gc->gc_next) {
		iaeptr->iae_routeidx = ird->ird_idx;
		iaeptr->iae_doi = gc->gc_db->gcdb_doi;
		iaeptr->iae_slrange = gc->gc_db->gcdb_slrange;
	}

	if (!snmp_append_data2(ird->ird_attrs.lp_head, &ird->ird_attrs.lp_tail,
	    (char *)iae, sacnt * sizeof (*iae))) {
		ip1dbg(("ip_snmp_get2_v6: failed to allocate %u bytes\n",
		    (unsigned)(sacnt * sizeof (*iae))));
	}

	/* bump route index for next pass */
	ird->ird_idx++;

	kmem_free(re, sizeof (*re));
	if (sacnt != 0)
		kmem_free(iae, sacnt * sizeof (*iae));

	if (gcgrp != NULL)
		rw_exit(&gcgrp->gcgrp_rwlock);
}

/*
 * ndp_walk routine to create ipv6NetToMediaEntryTable
 */
static int
ip_snmp_get2_v6_media(nce_t *nce, iproutedata_t *ird)
{
	ill_t				*ill;
	mib2_ipv6NetToMediaEntry_t	ntme;
	dl_unitdata_req_t		*dl;

	ill = nce->nce_ill;
	if (ill->ill_isv6 == B_FALSE) /* skip arpce entry */
		return (0);

	/*
	 * Neighbor cache entry attached to IRE with on-link
	 * destination.
	 */
	ntme.ipv6NetToMediaIfIndex = ill->ill_phyint->phyint_ifindex;
	ntme.ipv6NetToMediaNetAddress = nce->nce_addr;
	if ((ill->ill_flags & ILLF_XRESOLV) &&
	    (nce->nce_res_mp != NULL)) {
		dl = (dl_unitdata_req_t *)(nce->nce_res_mp->b_rptr);
		ntme.ipv6NetToMediaPhysAddress.o_length =
		    dl->dl_dest_addr_length;
	} else {
		ntme.ipv6NetToMediaPhysAddress.o_length =
		    ill->ill_phys_addr_length;
	}
	if (nce->nce_res_mp != NULL) {
		bcopy((char *)nce->nce_res_mp->b_rptr +
		    NCE_LL_ADDR_OFFSET(ill),
		    ntme.ipv6NetToMediaPhysAddress.o_bytes,
		    ntme.ipv6NetToMediaPhysAddress.o_length);
	} else {
		bzero(ntme.ipv6NetToMediaPhysAddress.o_bytes,
		    ill->ill_phys_addr_length);
	}
	/*
	 * Note: Returns ND_* states. Should be:
	 * reachable(1), stale(2), delay(3), probe(4),
	 * invalid(5), unknown(6)
	 */
	ntme.ipv6NetToMediaState = nce->nce_state;
	ntme.ipv6NetToMediaLastUpdated = 0;

	/* other(1), dynamic(2), static(3), local(4) */
	if (IN6_IS_ADDR_LOOPBACK(&nce->nce_addr)) {
		ntme.ipv6NetToMediaType = 4;
	} else if (IN6_IS_ADDR_MULTICAST(&nce->nce_addr)) {
		ntme.ipv6NetToMediaType = 1;
	} else {
		ntme.ipv6NetToMediaType = 2;
	}

	if (!snmp_append_data2(ird->ird_netmedia.lp_head,
	    &ird->ird_netmedia.lp_tail, (char *)&ntme, sizeof (ntme))) {
		ip1dbg(("ip_snmp_get2_v6_media: failed to allocate %u bytes\n",
		    (uint_t)sizeof (ntme)));
	}
	return (0);
}

/*
 * return (0) if invalid set request, 1 otherwise, including non-tcp requests
 */
/* ARGSUSED */
int
ip_snmp_set(queue_t *q, int level, int name, uchar_t *ptr, int len)
{
	switch (level) {
	case MIB2_IP:
	case MIB2_ICMP:
		switch (name) {
		default:
			break;
		}
		return (1);
	default:
		return (1);
	}
}

/*
 * When there exists both a 64- and 32-bit counter of a particular type
 * (i.e., InReceives), only the 64-bit counters are added.
 */
void
ip_mib2_add_ip_stats(mib2_ipIfStatsEntry_t *o1, mib2_ipIfStatsEntry_t *o2)
{
	UPDATE_MIB(o1, ipIfStatsInHdrErrors, o2->ipIfStatsInHdrErrors);
	UPDATE_MIB(o1, ipIfStatsInTooBigErrors, o2->ipIfStatsInTooBigErrors);
	UPDATE_MIB(o1, ipIfStatsInNoRoutes, o2->ipIfStatsInNoRoutes);
	UPDATE_MIB(o1, ipIfStatsInAddrErrors, o2->ipIfStatsInAddrErrors);
	UPDATE_MIB(o1, ipIfStatsInUnknownProtos, o2->ipIfStatsInUnknownProtos);
	UPDATE_MIB(o1, ipIfStatsInTruncatedPkts, o2->ipIfStatsInTruncatedPkts);
	UPDATE_MIB(o1, ipIfStatsInDiscards, o2->ipIfStatsInDiscards);
	UPDATE_MIB(o1, ipIfStatsOutDiscards, o2->ipIfStatsOutDiscards);
	UPDATE_MIB(o1, ipIfStatsOutFragOKs, o2->ipIfStatsOutFragOKs);
	UPDATE_MIB(o1, ipIfStatsOutFragFails, o2->ipIfStatsOutFragFails);
	UPDATE_MIB(o1, ipIfStatsOutFragCreates, o2->ipIfStatsOutFragCreates);
	UPDATE_MIB(o1, ipIfStatsReasmReqds, o2->ipIfStatsReasmReqds);
	UPDATE_MIB(o1, ipIfStatsReasmOKs, o2->ipIfStatsReasmOKs);
	UPDATE_MIB(o1, ipIfStatsReasmFails, o2->ipIfStatsReasmFails);
	UPDATE_MIB(o1, ipIfStatsOutNoRoutes, o2->ipIfStatsOutNoRoutes);
	UPDATE_MIB(o1, ipIfStatsReasmDuplicates, o2->ipIfStatsReasmDuplicates);
	UPDATE_MIB(o1, ipIfStatsReasmPartDups, o2->ipIfStatsReasmPartDups);
	UPDATE_MIB(o1, ipIfStatsForwProhibits, o2->ipIfStatsForwProhibits);
	UPDATE_MIB(o1, udpInCksumErrs, o2->udpInCksumErrs);
	UPDATE_MIB(o1, udpInOverflows, o2->udpInOverflows);
	UPDATE_MIB(o1, rawipInOverflows, o2->rawipInOverflows);
	UPDATE_MIB(o1, ipIfStatsInWrongIPVersion,
	    o2->ipIfStatsInWrongIPVersion);
	UPDATE_MIB(o1, ipIfStatsOutWrongIPVersion,
	    o2->ipIfStatsInWrongIPVersion);
	UPDATE_MIB(o1, ipIfStatsOutSwitchIPVersion,
	    o2->ipIfStatsOutSwitchIPVersion);
	UPDATE_MIB(o1, ipIfStatsHCInReceives, o2->ipIfStatsHCInReceives);
	UPDATE_MIB(o1, ipIfStatsHCInOctets, o2->ipIfStatsHCInOctets);
	UPDATE_MIB(o1, ipIfStatsHCInForwDatagrams,
	    o2->ipIfStatsHCInForwDatagrams);
	UPDATE_MIB(o1, ipIfStatsHCInDelivers, o2->ipIfStatsHCInDelivers);
	UPDATE_MIB(o1, ipIfStatsHCOutRequests, o2->ipIfStatsHCOutRequests);
	UPDATE_MIB(o1, ipIfStatsHCOutForwDatagrams,
	    o2->ipIfStatsHCOutForwDatagrams);
	UPDATE_MIB(o1, ipIfStatsOutFragReqds, o2->ipIfStatsOutFragReqds);
	UPDATE_MIB(o1, ipIfStatsHCOutTransmits, o2->ipIfStatsHCOutTransmits);
	UPDATE_MIB(o1, ipIfStatsHCOutOctets, o2->ipIfStatsHCOutOctets);
	UPDATE_MIB(o1, ipIfStatsHCInMcastPkts, o2->ipIfStatsHCInMcastPkts);
	UPDATE_MIB(o1, ipIfStatsHCInMcastOctets, o2->ipIfStatsHCInMcastOctets);
	UPDATE_MIB(o1, ipIfStatsHCOutMcastPkts, o2->ipIfStatsHCOutMcastPkts);
	UPDATE_MIB(o1, ipIfStatsHCOutMcastOctets,
	    o2->ipIfStatsHCOutMcastOctets);
	UPDATE_MIB(o1, ipIfStatsHCInBcastPkts, o2->ipIfStatsHCInBcastPkts);
	UPDATE_MIB(o1, ipIfStatsHCOutBcastPkts, o2->ipIfStatsHCOutBcastPkts);
	UPDATE_MIB(o1, ipsecInSucceeded, o2->ipsecInSucceeded);
	UPDATE_MIB(o1, ipsecInFailed, o2->ipsecInFailed);
	UPDATE_MIB(o1, ipInCksumErrs, o2->ipInCksumErrs);
	UPDATE_MIB(o1, tcpInErrs, o2->tcpInErrs);
	UPDATE_MIB(o1, udpNoPorts, o2->udpNoPorts);
}

void
ip_mib2_add_icmp6_stats(mib2_ipv6IfIcmpEntry_t *o1, mib2_ipv6IfIcmpEntry_t *o2)
{
	UPDATE_MIB(o1, ipv6IfIcmpInMsgs, o2->ipv6IfIcmpInMsgs);
	UPDATE_MIB(o1, ipv6IfIcmpInErrors, o2->ipv6IfIcmpInErrors);
	UPDATE_MIB(o1, ipv6IfIcmpInDestUnreachs, o2->ipv6IfIcmpInDestUnreachs);
	UPDATE_MIB(o1, ipv6IfIcmpInAdminProhibs, o2->ipv6IfIcmpInAdminProhibs);
	UPDATE_MIB(o1, ipv6IfIcmpInTimeExcds, o2->ipv6IfIcmpInTimeExcds);
	UPDATE_MIB(o1, ipv6IfIcmpInParmProblems, o2->ipv6IfIcmpInParmProblems);
	UPDATE_MIB(o1, ipv6IfIcmpInPktTooBigs, o2->ipv6IfIcmpInPktTooBigs);
	UPDATE_MIB(o1, ipv6IfIcmpInEchos, o2->ipv6IfIcmpInEchos);
	UPDATE_MIB(o1, ipv6IfIcmpInEchoReplies, o2->ipv6IfIcmpInEchoReplies);
	UPDATE_MIB(o1, ipv6IfIcmpInRouterSolicits,
	    o2->ipv6IfIcmpInRouterSolicits);
	UPDATE_MIB(o1, ipv6IfIcmpInRouterAdvertisements,
	    o2->ipv6IfIcmpInRouterAdvertisements);
	UPDATE_MIB(o1, ipv6IfIcmpInNeighborSolicits,
	    o2->ipv6IfIcmpInNeighborSolicits);
	UPDATE_MIB(o1, ipv6IfIcmpInNeighborAdvertisements,
	    o2->ipv6IfIcmpInNeighborAdvertisements);
	UPDATE_MIB(o1, ipv6IfIcmpInRedirects, o2->ipv6IfIcmpInRedirects);
	UPDATE_MIB(o1, ipv6IfIcmpInGroupMembQueries,
	    o2->ipv6IfIcmpInGroupMembQueries);
	UPDATE_MIB(o1, ipv6IfIcmpInGroupMembResponses,
	    o2->ipv6IfIcmpInGroupMembResponses);
	UPDATE_MIB(o1, ipv6IfIcmpInGroupMembReductions,
	    o2->ipv6IfIcmpInGroupMembReductions);
	UPDATE_MIB(o1, ipv6IfIcmpOutMsgs, o2->ipv6IfIcmpOutMsgs);
	UPDATE_MIB(o1, ipv6IfIcmpOutErrors, o2->ipv6IfIcmpOutErrors);
	UPDATE_MIB(o1, ipv6IfIcmpOutDestUnreachs,
	    o2->ipv6IfIcmpOutDestUnreachs);
	UPDATE_MIB(o1, ipv6IfIcmpOutAdminProhibs,
	    o2->ipv6IfIcmpOutAdminProhibs);
	UPDATE_MIB(o1, ipv6IfIcmpOutTimeExcds, o2->ipv6IfIcmpOutTimeExcds);
	UPDATE_MIB(o1, ipv6IfIcmpOutParmProblems,
	    o2->ipv6IfIcmpOutParmProblems);
	UPDATE_MIB(o1, ipv6IfIcmpOutPktTooBigs, o2->ipv6IfIcmpOutPktTooBigs);
	UPDATE_MIB(o1, ipv6IfIcmpOutEchos, o2->ipv6IfIcmpOutEchos);
	UPDATE_MIB(o1, ipv6IfIcmpOutEchoReplies, o2->ipv6IfIcmpOutEchoReplies);
	UPDATE_MIB(o1, ipv6IfIcmpOutRouterSolicits,
	    o2->ipv6IfIcmpOutRouterSolicits);
	UPDATE_MIB(o1, ipv6IfIcmpOutRouterAdvertisements,
	    o2->ipv6IfIcmpOutRouterAdvertisements);
	UPDATE_MIB(o1, ipv6IfIcmpOutNeighborSolicits,
	    o2->ipv6IfIcmpOutNeighborSolicits);
	UPDATE_MIB(o1, ipv6IfIcmpOutNeighborAdvertisements,
	    o2->ipv6IfIcmpOutNeighborAdvertisements);
	UPDATE_MIB(o1, ipv6IfIcmpOutRedirects, o2->ipv6IfIcmpOutRedirects);
	UPDATE_MIB(o1, ipv6IfIcmpOutGroupMembQueries,
	    o2->ipv6IfIcmpOutGroupMembQueries);
	UPDATE_MIB(o1, ipv6IfIcmpOutGroupMembResponses,
	    o2->ipv6IfIcmpOutGroupMembResponses);
	UPDATE_MIB(o1, ipv6IfIcmpOutGroupMembReductions,
	    o2->ipv6IfIcmpOutGroupMembReductions);
	UPDATE_MIB(o1, ipv6IfIcmpInOverflows, o2->ipv6IfIcmpInOverflows);
	UPDATE_MIB(o1, ipv6IfIcmpBadHoplimit, o2->ipv6IfIcmpBadHoplimit);
	UPDATE_MIB(o1, ipv6IfIcmpInBadNeighborAdvertisements,
	    o2->ipv6IfIcmpInBadNeighborAdvertisements);
	UPDATE_MIB(o1, ipv6IfIcmpInBadNeighborSolicitations,
	    o2->ipv6IfIcmpInBadNeighborSolicitations);
	UPDATE_MIB(o1, ipv6IfIcmpInBadRedirects, o2->ipv6IfIcmpInBadRedirects);
	UPDATE_MIB(o1, ipv6IfIcmpInGroupMembTotal,
	    o2->ipv6IfIcmpInGroupMembTotal);
	UPDATE_MIB(o1, ipv6IfIcmpInGroupMembBadQueries,
	    o2->ipv6IfIcmpInGroupMembBadQueries);
	UPDATE_MIB(o1, ipv6IfIcmpInGroupMembBadReports,
	    o2->ipv6IfIcmpInGroupMembBadReports);
	UPDATE_MIB(o1, ipv6IfIcmpInGroupMembOurReports,
	    o2->ipv6IfIcmpInGroupMembOurReports);
}

/*
 * Called before the options are updated to check if this packet will
 * be source routed from here.
 * This routine assumes that the options are well formed i.e. that they
 * have already been checked.
 */
static boolean_t
ip_source_routed(ipha_t *ipha, ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	ire_t		*ire;

	if (IS_SIMPLE_IPH(ipha)) {
		ip2dbg(("not source routed\n"));
		return (B_FALSE);
	}
	dst = ipha->ipha_dst;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_source_routed: opt %d, len %d\n",
		    optval, optlen));
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			/*
			 * If dst is one of our addresses and there are some
			 * entries left in the source route return (true).
			 */
			ire = ire_ctable_lookup(dst, 0, IRE_LOCAL, NULL,
			    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (ire == NULL) {
				ip2dbg(("ip_source_routed: not next"
				    " source route 0x%x\n",
				    ntohl(dst)));
				return (B_FALSE);
			}
			ire_refrele(ire);
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* End of source route */
				ip1dbg(("ip_source_routed: end of SR\n"));
				return (B_FALSE);
			}
			return (B_TRUE);
		}
	}
	ip2dbg(("not source routed\n"));
	return (B_FALSE);
}

/*
 * Check if the packet contains any source route.
 */
static boolean_t
ip_source_route_included(ipha_t *ipha)
{
	ipoptp_t	opts;
	uint8_t		optval;

	if (IS_SIMPLE_IPH(ipha))
		return (B_FALSE);
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		switch (optval) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * Called when the IRE expiration timer fires.
 */
void
ip_trash_timer_expire(void *args)
{
	int			flush_flag = 0;
	ire_expire_arg_t	iea;
	ip_stack_t		*ipst = (ip_stack_t *)args;

	iea.iea_ipst = ipst;	/* No netstack_hold */

	/*
	 * ip_ire_expire_id is protected by ip_trash_timer_lock.
	 * This lock makes sure that a new invocation of this function
	 * that occurs due to an almost immediate timer firing will not
	 * progress beyond this point until the current invocation is done
	 */
	mutex_enter(&ipst->ips_ip_trash_timer_lock);
	ipst->ips_ip_ire_expire_id = 0;
	mutex_exit(&ipst->ips_ip_trash_timer_lock);

	/* Periodic timer */
	if (ipst->ips_ip_ire_arp_time_elapsed >=
	    ipst->ips_ip_ire_arp_interval) {
		/*
		 * Remove all IRE_CACHE entries since they might
		 * contain arp information.
		 */
		flush_flag |= FLUSH_ARP_TIME;
		ipst->ips_ip_ire_arp_time_elapsed = 0;
		IP_STAT(ipst, ip_ire_arp_timer_expired);
	}
	if (ipst->ips_ip_ire_rd_time_elapsed >=
	    ipst->ips_ip_ire_redir_interval) {
		/* Remove all redirects */
		flush_flag |= FLUSH_REDIRECT_TIME;
		ipst->ips_ip_ire_rd_time_elapsed = 0;
		IP_STAT(ipst, ip_ire_redirect_timer_expired);
	}
	if (ipst->ips_ip_ire_pmtu_time_elapsed >=
	    ipst->ips_ip_ire_pathmtu_interval) {
		/* Increase path mtu */
		flush_flag |= FLUSH_MTU_TIME;
		ipst->ips_ip_ire_pmtu_time_elapsed = 0;
		IP_STAT(ipst, ip_ire_pmtu_timer_expired);
	}

	/*
	 * Optimize for the case when there are no redirects in the
	 * ftable, that is, no need to walk the ftable in that case.
	 */
	if (flush_flag & (FLUSH_MTU_TIME|FLUSH_ARP_TIME)) {
		iea.iea_flush_flag = flush_flag;
		ire_walk_ill_tables(MATCH_IRE_TYPE, IRE_CACHETABLE, ire_expire,
		    (char *)(uintptr_t)&iea, IP_MASK_TABLE_SIZE, 0, NULL,
		    ipst->ips_ip_cache_table_size, ipst->ips_ip_cache_table,
		    NULL, ALL_ZONES, ipst);
	}
	if ((flush_flag & FLUSH_REDIRECT_TIME) &&
	    ipst->ips_ip_redirect_cnt > 0) {
		iea.iea_flush_flag = flush_flag;
		ire_walk_ill_tables(MATCH_IRE_TYPE, IRE_FORWARDTABLE,
		    ire_expire, (char *)(uintptr_t)&iea, IP_MASK_TABLE_SIZE,
		    0, NULL, 0, NULL, NULL, ALL_ZONES, ipst);
	}
	if (flush_flag & FLUSH_MTU_TIME) {
		/*
		 * Walk all IPv6 IRE's and update them
		 * Note that ARP and redirect timers are not
		 * needed since NUD handles stale entries.
		 */
		flush_flag = FLUSH_MTU_TIME;
		iea.iea_flush_flag = flush_flag;
		ire_walk_v6(ire_expire, (char *)(uintptr_t)&iea,
		    ALL_ZONES, ipst);
	}

	ipst->ips_ip_ire_arp_time_elapsed += ipst->ips_ip_timer_interval;
	ipst->ips_ip_ire_rd_time_elapsed += ipst->ips_ip_timer_interval;
	ipst->ips_ip_ire_pmtu_time_elapsed += ipst->ips_ip_timer_interval;

	/*
	 * Hold the lock to serialize timeout calls and prevent
	 * stale values in ip_ire_expire_id. Otherwise it is possible
	 * for the timer to fire and a new invocation of this function
	 * to start before the return value of timeout has been stored
	 * in ip_ire_expire_id by the current invocation.
	 */
	mutex_enter(&ipst->ips_ip_trash_timer_lock);
	ipst->ips_ip_ire_expire_id = timeout(ip_trash_timer_expire,
	    (void *)ipst, MSEC_TO_TICK(ipst->ips_ip_timer_interval));
	mutex_exit(&ipst->ips_ip_trash_timer_lock);
}

/*
 * Called by the memory allocator subsystem directly, when the system
 * is running low on memory.
 */
/* ARGSUSED */
void
ip_trash_ire_reclaim(void *args)
{
	netstack_handle_t nh;
	netstack_t *ns;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		ip_trash_ire_reclaim_stack(ns->netstack_ip);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
}

static void
ip_trash_ire_reclaim_stack(ip_stack_t *ipst)
{
	ire_cache_count_t icc;
	ire_cache_reclaim_t icr;
	ncc_cache_count_t ncc;
	nce_cache_reclaim_t ncr;
	uint_t delete_cnt;
	/*
	 * Memory reclaim call back.
	 * Count unused, offlink, pmtu, and onlink IRE_CACHE entries.
	 * Then, with a target of freeing 1/Nth of IRE_CACHE
	 * entries, determine what fraction to free for
	 * each category of IRE_CACHE entries giving absolute priority
	 * in the order of onlink, pmtu, offlink, unused (e.g. no pmtu
	 * entry will be freed unless all offlink entries are freed).
	 */
	icc.icc_total = 0;
	icc.icc_unused = 0;
	icc.icc_offlink = 0;
	icc.icc_pmtu = 0;
	icc.icc_onlink = 0;
	ire_walk(ire_cache_count, (char *)&icc, ipst);

	/*
	 * Free NCEs for IPv6 like the onlink ires.
	 */
	ncc.ncc_total = 0;
	ncc.ncc_host = 0;
	ndp_walk(NULL, (pfi_t)ndp_cache_count, (uchar_t *)&ncc, ipst);

	ASSERT(icc.icc_total == icc.icc_unused + icc.icc_offlink +
	    icc.icc_pmtu + icc.icc_onlink);
	delete_cnt = icc.icc_total/ipst->ips_ip_ire_reclaim_fraction;
	IP_STAT(ipst, ip_trash_ire_reclaim_calls);
	if (delete_cnt == 0)
		return;
	IP_STAT(ipst, ip_trash_ire_reclaim_success);
	/* Always delete all unused offlink entries */
	icr.icr_ipst = ipst;
	icr.icr_unused = 1;
	if (delete_cnt <= icc.icc_unused) {
		/*
		 * Only need to free unused entries.  In other words,
		 * there are enough unused entries to free to meet our
		 * target number of freed ire cache entries.
		 */
		icr.icr_offlink = icr.icr_pmtu = icr.icr_onlink = 0;
		ncr.ncr_host = 0;
	} else if (delete_cnt <= icc.icc_unused + icc.icc_offlink) {
		/*
		 * Only need to free unused entries, plus a fraction of offlink
		 * entries.  It follows from the first if statement that
		 * icc_offlink is non-zero, and that delete_cnt != icc_unused.
		 */
		delete_cnt -= icc.icc_unused;
		/* Round up # deleted by truncating fraction */
		icr.icr_offlink = icc.icc_offlink / delete_cnt;
		icr.icr_pmtu = icr.icr_onlink = 0;
		ncr.ncr_host = 0;
	} else if (delete_cnt <=
	    icc.icc_unused + icc.icc_offlink + icc.icc_pmtu) {
		/*
		 * Free all unused and offlink entries, plus a fraction of
		 * pmtu entries.  It follows from the previous if statement
		 * that icc_pmtu is non-zero, and that
		 * delete_cnt != icc_unused + icc_offlink.
		 */
		icr.icr_offlink = 1;
		delete_cnt -= icc.icc_unused + icc.icc_offlink;
		/* Round up # deleted by truncating fraction */
		icr.icr_pmtu = icc.icc_pmtu / delete_cnt;
		icr.icr_onlink = 0;
		ncr.ncr_host = 0;
	} else {
		/*
		 * Free all unused, offlink, and pmtu entries, plus a fraction
		 * of onlink entries.  If we're here, then we know that
		 * icc_onlink is non-zero, and that
		 * delete_cnt != icc_unused + icc_offlink + icc_pmtu.
		 */
		icr.icr_offlink = icr.icr_pmtu = 1;
		delete_cnt -= icc.icc_unused + icc.icc_offlink +
		    icc.icc_pmtu;
		/* Round up # deleted by truncating fraction */
		icr.icr_onlink = icc.icc_onlink / delete_cnt;
		/* Using the same delete fraction as for onlink IREs */
		ncr.ncr_host = ncc.ncc_host / delete_cnt;
	}
#ifdef DEBUG
	ip1dbg(("IP reclaim: target %d out of %d current %d/%d/%d/%d "
	    "fractions %d/%d/%d/%d\n",
	    icc.icc_total/ipst->ips_ip_ire_reclaim_fraction, icc.icc_total,
	    icc.icc_unused, icc.icc_offlink,
	    icc.icc_pmtu, icc.icc_onlink,
	    icr.icr_unused, icr.icr_offlink,
	    icr.icr_pmtu, icr.icr_onlink));
#endif
	ire_walk(ire_cache_reclaim, (char *)&icr, ipst);
	if (ncr.ncr_host != 0)
		ndp_walk(NULL, (pfi_t)ndp_cache_reclaim,
		    (uchar_t *)&ncr, ipst);
#ifdef DEBUG
	icc.icc_total = 0; icc.icc_unused = 0; icc.icc_offlink = 0;
	icc.icc_pmtu = 0; icc.icc_onlink = 0;
	ire_walk(ire_cache_count, (char *)&icc, ipst);
	ip1dbg(("IP reclaim: result total %d %d/%d/%d/%d\n",
	    icc.icc_total, icc.icc_unused, icc.icc_offlink,
	    icc.icc_pmtu, icc.icc_onlink));
#endif
}

/*
 * ip_unbind is called when a copy of an unbind request is received from the
 * upper level protocol.  We remove this conn from any fanout hash list it is
 * on, and zero out the bind information.  No reply is expected up above.
 */
mblk_t *
ip_unbind(queue_t *q, mblk_t *mp)
{
	conn_t  *connp = Q_TO_CONN(q);

	ASSERT(!MUTEX_HELD(&connp->conn_lock));

	if (is_system_labeled() && connp->conn_anon_port) {
		(void) tsol_mlp_anon(crgetzone(connp->conn_cred),
		    connp->conn_mlp_type, connp->conn_ulp,
		    ntohs(connp->conn_lport), B_FALSE);
		connp->conn_anon_port = 0;
	}
	connp->conn_mlp_type = mlptSingle;

	ipcl_hash_remove(connp);

	ASSERT(mp->b_cont == NULL);
	/*
	 * Convert mp into a T_OK_ACK
	 */
	mp = mi_tpi_ok_ack_alloc(mp);

	/*
	 * should not happen in practice... T_OK_ACK is smaller than the
	 * original message.
	 */
	if (mp == NULL)
		return (NULL);

	return (mp);
}

/*
 * Write side put procedure.  Outbound data, IOCTLs, responses from
 * resolvers, etc, come down through here.
 *
 * arg2 is always a queue_t *.
 * When that queue is an ill_t (i.e. q_next != NULL), then arg must be
 * the zoneid.
 * When that queue is not an ill_t, then arg must be a conn_t pointer.
 */
void
ip_output(void *arg, mblk_t *mp, void *arg2, int caller)
{
	ip_output_options(arg, mp, arg2, caller, &zero_info);
}

void
ip_output_options(void *arg, mblk_t *mp, void *arg2, int caller,
    ip_opt_info_t *infop)
{
	conn_t		*connp = NULL;
	queue_t		*q = (queue_t *)arg2;
	ipha_t		*ipha;
#define	rptr	((uchar_t *)ipha)
	ire_t		*ire = NULL;
	ire_t		*sctp_ire = NULL;
	uint32_t	v_hlen_tos_len;
	ipaddr_t	dst;
	mblk_t		*first_mp = NULL;
	boolean_t	mctl_present;
	ipsec_out_t	*io;
	int		match_flags;
	ill_t		*attach_ill = NULL;
					/* Bind to IPIF_NOFAILOVER ill etc. */
	ill_t		*xmit_ill = NULL;	/* IP_PKTINFO etc. */
	ipif_t		*dst_ipif;
	boolean_t	multirt_need_resolve = B_FALSE;
	mblk_t		*copy_mp = NULL;
	int		err;
	zoneid_t	zoneid;
	boolean_t	need_decref = B_FALSE;
	boolean_t	ignore_dontroute = B_FALSE;
	boolean_t	ignore_nexthop = B_FALSE;
	boolean_t	ip_nexthop = B_FALSE;
	ipaddr_t	nexthop_addr;
	ip_stack_t	*ipst;

#ifdef	_BIG_ENDIAN
#define	V_HLEN	(v_hlen_tos_len >> 24)
#else
#define	V_HLEN	(v_hlen_tos_len & 0xFF)
#endif

	TRACE_1(TR_FAC_IP, TR_IP_WPUT_START,
	    "ip_wput_start: q %p", q);

	/*
	 * ip_wput fast path
	 */

	/* is packet from ARP ? */
	if (q->q_next != NULL) {
		zoneid = (zoneid_t)(uintptr_t)arg;
		goto qnext;
	}

	connp = (conn_t *)arg;
	ASSERT(connp != NULL);
	zoneid = connp->conn_zoneid;
	ipst = connp->conn_netstack->netstack_ip;

	/* is queue flow controlled? */
	if ((q->q_first != NULL || connp->conn_draining) &&
	    (caller == IP_WPUT)) {
		ASSERT(!need_decref);
		(void) putq(q, mp);
		return;
	}

	/* Multidata transmit? */
	if (DB_TYPE(mp) == M_MULTIDATA) {
		/*
		 * We should never get here, since all Multidata messages
		 * originating from tcp should have been directed over to
		 * tcp_multisend() in the first place.
		 */
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		freemsg(mp);
		return;
	} else if (DB_TYPE(mp) != M_DATA)
		goto notdata;

	if (mp->b_flag & MSGHASREF) {
		ASSERT(connp->conn_ulp == IPPROTO_SCTP);
		mp->b_flag &= ~MSGHASREF;
		SCTP_EXTRACT_IPINFO(mp, sctp_ire);
		need_decref = B_TRUE;
	}
	ipha = (ipha_t *)mp->b_rptr;

	/* is IP header non-aligned or mblk smaller than basic IP header */
#ifndef SAFETY_BEFORE_SPEED
	if (!OK_32PTR(rptr) ||
	    (mp->b_wptr - rptr) < IP_SIMPLE_HDR_LENGTH)
		goto hdrtoosmall;
#endif

	ASSERT(OK_32PTR(ipha));

	/*
	 * This function assumes that mp points to an IPv4 packet.  If it's the
	 * wrong version, we'll catch it again in ip_output_v6.
	 *
	 * Note that this is *only* locally-generated output here, and never
	 * forwarded data, and that we need to deal only with transports that
	 * don't know how to label.  (TCP, UDP, and ICMP/raw-IP all know how to
	 * label.)
	 */
	if (is_system_labeled() &&
	    (ipha->ipha_version_and_hdr_length & 0xf0) == (IPV4_VERSION << 4) &&
	    !connp->conn_ulp_labeled) {
		err = tsol_check_label(BEST_CRED(mp, connp), &mp,
		    connp->conn_mac_exempt, ipst);
		ipha = (ipha_t *)mp->b_rptr;
		if (err != 0) {
			first_mp = mp;
			if (err == EINVAL)
				goto icmp_parameter_problem;
			ip2dbg(("ip_wput: label check failed (%d)\n", err));
			goto discard_pkt;
		}
	}

	ASSERT(infop != NULL);

	if (infop->ip_opt_flags & IP_VERIFY_SRC) {
		/*
		 * IP_PKTINFO ancillary option is present.
		 * IPCL_ZONEID is used to honor IP_ALLZONES option which
		 * allows using address of any zone as the source address.
		 */
		ire = ire_ctable_lookup(ipha->ipha_src, 0,
		    (IRE_LOCAL|IRE_LOOPBACK), NULL, IPCL_ZONEID(connp),
		    NULL, MATCH_IRE_TYPE | MATCH_IRE_ZONEONLY, ipst);
		if (ire == NULL)
			goto drop_pkt;
		ire_refrele(ire);
		ire = NULL;
	}

	/*
	 * IP_DONTFAILOVER_IF and IP_BOUND_IF have precedence over ill index
	 * passed in IP_PKTINFO.
	 */
	if (infop->ip_opt_ill_index != 0 &&
	    connp->conn_outgoing_ill == NULL &&
	    connp->conn_nofailover_ill == NULL) {

		xmit_ill = ill_lookup_on_ifindex(
		    infop->ip_opt_ill_index, B_FALSE, NULL, NULL, NULL, NULL,
		    ipst);

		if (xmit_ill == NULL || IS_VNI(xmit_ill))
			goto drop_pkt;
		/*
		 * check that there is an ipif belonging
		 * to our zone. IPCL_ZONEID is not used because
		 * IP_ALLZONES option is valid only when the ill is
		 * accessible from all zones i.e has a valid ipif in
		 * all zones.
		 */
		if (!ipif_lookup_zoneid_group(xmit_ill, zoneid, 0, NULL)) {
			goto drop_pkt;
		}
	}

	/*
	 * If there is a policy, try to attach an ipsec_out in
	 * the front. At the end, first_mp either points to a
	 * M_DATA message or IPSEC_OUT message linked to a
	 * M_DATA message. We have to do it now as we might
	 * lose the "conn" if we go through ip_newroute.
	 */
	if (connp->conn_out_enforce_policy || (connp->conn_latch != NULL)) {
		if (((mp = ipsec_attach_ipsec_out(&mp, connp, NULL,
		    ipha->ipha_protocol, ipst->ips_netstack)) == NULL)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			if (need_decref)
				CONN_DEC_REF(connp);
			return;
		} else {
			ASSERT(mp->b_datap->db_type == M_CTL);
			first_mp = mp;
			mp = mp->b_cont;
			mctl_present = B_TRUE;
		}
	} else {
		first_mp = mp;
		mctl_present = B_FALSE;
	}

	v_hlen_tos_len = ((uint32_t *)ipha)[0];

	/* is wrong version or IP options present */
	if (V_HLEN != IP_SIMPLE_HDR_VERSION)
		goto version_hdrlen_check;
	dst = ipha->ipha_dst;

	if (connp->conn_nofailover_ill != NULL) {
		attach_ill = conn_get_held_ill(connp,
		    &connp->conn_nofailover_ill, &err);
		if (err == ILL_LOOKUP_FAILED) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			if (need_decref)
				CONN_DEC_REF(connp);
			freemsg(first_mp);
			return;
		}
	}

	/* If IP_BOUND_IF has been set, use that ill. */
	if (connp->conn_outgoing_ill != NULL) {
		xmit_ill = conn_get_held_ill(connp,
		    &connp->conn_outgoing_ill, &err);
		if (err == ILL_LOOKUP_FAILED)
			goto drop_pkt;

		goto send_from_ill;
	}

	/* is packet multicast? */
	if (CLASSD(dst))
		goto multicast;

	/*
	 * If xmit_ill is set above due to index passed in ip_pkt_info. It
	 * takes precedence over conn_dontroute and conn_nexthop_set
	 */
	if (xmit_ill != NULL)
		goto send_from_ill;

	if (connp->conn_dontroute || connp->conn_nexthop_set) {
		/*
		 * If the destination is a broadcast, local, or loopback
		 * address, SO_DONTROUTE and IP_NEXTHOP go through the
		 * standard path.
		 */
		ire = ire_cache_lookup(dst, zoneid, MBLK_GETLABEL(mp), ipst);
		if ((ire == NULL) || (ire->ire_type &
		    (IRE_BROADCAST | IRE_LOCAL | IRE_LOOPBACK)) == 0) {
			if (ire != NULL) {
				ire_refrele(ire);
				/* No more access to ire */
				ire = NULL;
			}
			/*
			 * bypass routing checks and go directly to interface.
			 */
			if (connp->conn_dontroute)
				goto dontroute;

			ASSERT(connp->conn_nexthop_set);
			ip_nexthop = B_TRUE;
			nexthop_addr = connp->conn_nexthop_v4;
			goto send_from_ill;
		}

		/* Must be a broadcast, a loopback or a local ire */
		ire_refrele(ire);
		/* No more access to ire */
		ire = NULL;
	}

	if (attach_ill != NULL)
		goto send_from_ill;

	/*
	 * We cache IRE_CACHEs to avoid lookups. We don't do
	 * this for the tcp global queue and listen end point
	 * as it does not really have a real destination to
	 * talk to.  This is also true for SCTP.
	 */
	if (IP_FLOW_CONTROLLED_ULP(connp->conn_ulp) &&
	    !connp->conn_fully_bound) {
		ire = ire_cache_lookup(dst, zoneid, MBLK_GETLABEL(mp), ipst);
		if (ire == NULL)
			goto noirefound;
		TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
		    "ip_wput_end: q %p (%S)", q, "end");

		/*
		 * Check if the ire has the RTF_MULTIRT flag, inherited
		 * from an IRE_OFFSUBNET ire entry in ip_newroute().
		 */
		if (ire->ire_flags & RTF_MULTIRT) {

			/*
			 * Force the TTL of multirouted packets if required.
			 * The TTL of such packets is bounded by the
			 * ip_multirt_ttl ndd variable.
			 */
			if ((ipst->ips_ip_multirt_ttl > 0) &&
			    (ipha->ipha_ttl > ipst->ips_ip_multirt_ttl)) {
				ip2dbg(("ip_wput: forcing multirt TTL to %d "
				    "(was %d), dst 0x%08x\n",
				    ipst->ips_ip_multirt_ttl, ipha->ipha_ttl,
				    ntohl(ire->ire_addr)));
				ipha->ipha_ttl = ipst->ips_ip_multirt_ttl;
			}
			/*
			 * We look at this point if there are pending
			 * unresolved routes. ire_multirt_resolvable()
			 * checks in O(n) that all IRE_OFFSUBNET ire
			 * entries for the packet's destination and
			 * flagged RTF_MULTIRT are currently resolved.
			 * If some remain unresolved, we make a copy
			 * of the current message. It will be used
			 * to initiate additional route resolutions.
			 */
			multirt_need_resolve =
			    ire_multirt_need_resolve(ire->ire_addr,
			    MBLK_GETLABEL(first_mp), ipst);
			ip2dbg(("ip_wput[TCP]: ire %p, "
			    "multirt_need_resolve %d, first_mp %p\n",
			    (void *)ire, multirt_need_resolve,
			    (void *)first_mp));
			if (multirt_need_resolve) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL) {
					MULTIRT_DEBUG_TAG(copy_mp);
				}
			}
		}

		ip_wput_ire(q, first_mp, ire, connp, caller, zoneid);

		/*
		 * Try to resolve another multiroute if
		 * ire_multirt_need_resolve() deemed it necessary.
		 */
		if (copy_mp != NULL)
			ip_newroute(q, copy_mp, dst, connp, zoneid, ipst);
		if (need_decref)
			CONN_DEC_REF(connp);
		return;
	}

	/*
	 * Access to conn_ire_cache. (protected by conn_lock)
	 *
	 * IRE_MARK_CONDEMNED is marked in ire_delete. We don't grab
	 * the ire bucket lock here to check for CONDEMNED as it is okay to
	 * send a packet or two with the IRE_CACHE that is going away.
	 * Access to the ire requires an ire refhold on the ire prior to
	 * its use since an interface unplumb thread may delete the cached
	 * ire and release the refhold at any time.
	 *
	 * Caching an ire in the conn_ire_cache
	 *
	 * o Caching an ire pointer in the conn requires a strict check for
	 * IRE_MARK_CONDEMNED. An interface unplumb thread deletes all relevant
	 * ires  before cleaning up the conns. So the caching of an ire pointer
	 * in the conn is done after making sure under the bucket lock that the
	 * ire has not yet been marked CONDEMNED. Otherwise we will end up
	 * caching an ire after the unplumb thread has cleaned up the conn.
	 * If the conn does not send a packet subsequently the unplumb thread
	 * will be hanging waiting for the ire count to drop to zero.
	 *
	 * o We also need to atomically test for a null conn_ire_cache and
	 * set the conn_ire_cache under the the protection of the conn_lock
	 * to avoid races among concurrent threads trying to simultaneously
	 * cache an ire in the conn_ire_cache.
	 */
	mutex_enter(&connp->conn_lock);
	ire = sctp_ire != NULL ? sctp_ire : connp->conn_ire_cache;

	if (ire != NULL && ire->ire_addr == dst &&
	    !(ire->ire_marks & IRE_MARK_CONDEMNED)) {

		IRE_REFHOLD(ire);
		mutex_exit(&connp->conn_lock);

	} else {
		boolean_t cached = B_FALSE;
		connp->conn_ire_cache = NULL;
		mutex_exit(&connp->conn_lock);
		/* Release the old ire */
		if (ire != NULL && sctp_ire == NULL)
			IRE_REFRELE_NOTR(ire);

		ire = ire_cache_lookup(dst, zoneid, MBLK_GETLABEL(mp), ipst);
		if (ire == NULL)
			goto noirefound;
		IRE_REFHOLD_NOTR(ire);

		mutex_enter(&connp->conn_lock);
		if (CONN_CACHE_IRE(connp) && connp->conn_ire_cache == NULL) {
			rw_enter(&ire->ire_bucket->irb_lock, RW_READER);
			if (!(ire->ire_marks & IRE_MARK_CONDEMNED)) {
				if (connp->conn_ulp == IPPROTO_TCP)
					TCP_CHECK_IREINFO(connp->conn_tcp, ire);
				connp->conn_ire_cache = ire;
				cached = B_TRUE;
			}
			rw_exit(&ire->ire_bucket->irb_lock);
		}
		mutex_exit(&connp->conn_lock);

		/*
		 * We can continue to use the ire but since it was
		 * not cached, we should drop the extra reference.
		 */
		if (!cached)
			IRE_REFRELE_NOTR(ire);
	}


	TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
	    "ip_wput_end: q %p (%S)", q, "end");

	/*
	 * Check if the ire has the RTF_MULTIRT flag, inherited
	 * from an IRE_OFFSUBNET ire entry in ip_newroute().
	 */
	if (ire->ire_flags & RTF_MULTIRT) {

		/*
		 * Force the TTL of multirouted packets if required.
		 * The TTL of such packets is bounded by the
		 * ip_multirt_ttl ndd variable.
		 */
		if ((ipst->ips_ip_multirt_ttl > 0) &&
		    (ipha->ipha_ttl > ipst->ips_ip_multirt_ttl)) {
			ip2dbg(("ip_wput: forcing multirt TTL to %d "
			    "(was %d), dst 0x%08x\n",
			    ipst->ips_ip_multirt_ttl, ipha->ipha_ttl,
			    ntohl(ire->ire_addr)));
			ipha->ipha_ttl = ipst->ips_ip_multirt_ttl;
		}

		/*
		 * At this point, we check to see if there are any pending
		 * unresolved routes. ire_multirt_resolvable()
		 * checks in O(n) that all IRE_OFFSUBNET ire
		 * entries for the packet's destination and
		 * flagged RTF_MULTIRT are currently resolved.
		 * If some remain unresolved, we make a copy
		 * of the current message. It will be used
		 * to initiate additional route resolutions.
		 */
		multirt_need_resolve = ire_multirt_need_resolve(ire->ire_addr,
		    MBLK_GETLABEL(first_mp), ipst);
		ip2dbg(("ip_wput[not TCP]: ire %p, "
		    "multirt_need_resolve %d, first_mp %p\n",
		    (void *)ire, multirt_need_resolve, (void *)first_mp));
		if (multirt_need_resolve) {
			copy_mp = copymsg(first_mp);
			if (copy_mp != NULL) {
				MULTIRT_DEBUG_TAG(copy_mp);
			}
		}
	}

	ip_wput_ire(q, first_mp, ire, connp, caller, zoneid);

	/*
	 * Try to resolve another multiroute if
	 * ire_multirt_resolvable() deemed it necessary
	 */
	if (copy_mp != NULL)
		ip_newroute(q, copy_mp, dst, connp, zoneid, ipst);
	if (need_decref)
		CONN_DEC_REF(connp);
	return;

qnext:
	/*
	 * Upper Level Protocols pass down complete IP datagrams
	 * as M_DATA messages.	Everything else is a sideshow.
	 *
	 * 1) We could be re-entering ip_wput because of ip_neworute
	 *    in which case we could have a IPSEC_OUT message. We
	 *    need to pass through ip_wput like other datagrams and
	 *    hence cannot branch to ip_wput_nondata.
	 *
	 * 2) ARP, AH, ESP, and other clients who are on the module
	 *    instance of IP stream, give us something to deal with.
	 *    We will handle AH and ESP here and rest in ip_wput_nondata.
	 *
	 * 3) ICMP replies also could come here.
	 */
	ipst = ILLQ_TO_IPST(q);

	if (DB_TYPE(mp) != M_DATA) {
notdata:
		if (DB_TYPE(mp) == M_CTL) {
			/*
			 * M_CTL messages are used by ARP, AH and ESP to
			 * communicate with IP. We deal with IPSEC_IN and
			 * IPSEC_OUT here. ip_wput_nondata handles other
			 * cases.
			 */
			ipsec_info_t *ii = (ipsec_info_t *)mp->b_rptr;
			if (mp->b_cont && (mp->b_cont->b_flag & MSGHASREF)) {
				first_mp = mp->b_cont;
				first_mp->b_flag &= ~MSGHASREF;
				ASSERT(connp->conn_ulp == IPPROTO_SCTP);
				SCTP_EXTRACT_IPINFO(first_mp, sctp_ire);
				CONN_DEC_REF(connp);
				connp = NULL;
			}
			if (ii->ipsec_info_type == IPSEC_IN) {
				/*
				 * Either this message goes back to
				 * IPsec for further processing or to
				 * ULP after policy checks.
				 */
				ip_fanout_proto_again(mp, NULL, NULL, NULL);
				return;
			} else if (ii->ipsec_info_type == IPSEC_OUT) {
				io = (ipsec_out_t *)ii;
				if (io->ipsec_out_proc_begin) {
					/*
					 * IPsec processing has already started.
					 * Complete it.
					 * IPQoS notes: We don't care what is
					 * in ipsec_out_ill_index since this
					 * won't be processed for IPQoS policies
					 * in ipsec_out_process.
					 */
					ipsec_out_process(q, mp, NULL,
					    io->ipsec_out_ill_index);
					return;
				} else {
					connp = (q->q_next != NULL) ?
					    NULL : Q_TO_CONN(q);
					first_mp = mp;
					mp = mp->b_cont;
					mctl_present = B_TRUE;
				}
				zoneid = io->ipsec_out_zoneid;
				ASSERT(zoneid != ALL_ZONES);
			} else if (ii->ipsec_info_type == IPSEC_CTL) {
				/*
				 * It's an IPsec control message requesting
				 * an SADB update to be sent to the IPsec
				 * hardware acceleration capable ills.
				 */
				ipsec_ctl_t *ipsec_ctl =
				    (ipsec_ctl_t *)mp->b_rptr;
				ipsa_t *sa = (ipsa_t *)ipsec_ctl->ipsec_ctl_sa;
				uint_t satype = ipsec_ctl->ipsec_ctl_sa_type;
				mblk_t *cmp = mp->b_cont;

				ASSERT(MBLKL(mp) >= sizeof (ipsec_ctl_t));
				ASSERT(cmp != NULL);

				freeb(mp);
				ill_ipsec_capab_send_all(satype, cmp, sa,
				    ipst->ips_netstack);
				return;
			} else {
				/*
				 * This must be ARP or special TSOL signaling.
				 */
				ip_wput_nondata(NULL, q, mp, NULL);
				TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
				    "ip_wput_end: q %p (%S)", q, "nondata");
				return;
			}
		} else {
			/*
			 * This must be non-(ARP/AH/ESP) messages.
			 */
			ASSERT(!need_decref);
			ip_wput_nondata(NULL, q, mp, NULL);
			TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
			    "ip_wput_end: q %p (%S)", q, "nondata");
			return;
		}
	} else {
		first_mp = mp;
		mctl_present = B_FALSE;
	}

	ASSERT(first_mp != NULL);
	/*
	 * ICMP echo replies attach an ipsec_out and set ipsec_out_attach_if
	 * to make sure that this packet goes out on the same interface it
	 * came in. We handle that here.
	 */
	if (mctl_present) {
		uint_t ifindex;

		io = (ipsec_out_t *)first_mp->b_rptr;
		if (io->ipsec_out_attach_if || io->ipsec_out_ip_nexthop) {
			/*
			 * We may have lost the conn context if we are
			 * coming here from ip_newroute(). Copy the
			 * nexthop information.
			 */
			if (io->ipsec_out_ip_nexthop) {
				ip_nexthop = B_TRUE;
				nexthop_addr = io->ipsec_out_nexthop_addr;

				ipha = (ipha_t *)mp->b_rptr;
				dst = ipha->ipha_dst;
				goto send_from_ill;
			} else {
				ASSERT(io->ipsec_out_ill_index != 0);
				ifindex = io->ipsec_out_ill_index;
				attach_ill = ill_lookup_on_ifindex(ifindex,
				    B_FALSE, NULL, NULL, NULL, NULL, ipst);
				if (attach_ill == NULL) {
					ASSERT(xmit_ill == NULL);
					ip1dbg(("ip_output: bad ifindex for "
					    "(BIND TO IPIF_NOFAILOVER) %d\n",
					    ifindex));
					freemsg(first_mp);
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutDiscards);
					ASSERT(!need_decref);
					return;
				}
			}
		}
	}

	ASSERT(xmit_ill == NULL);

	/* We have a complete IP datagram heading outbound. */
	ipha = (ipha_t *)mp->b_rptr;

#ifndef SPEED_BEFORE_SAFETY
	/*
	 * Make sure we have a full-word aligned message and that at least
	 * a simple IP header is accessible in the first message.  If not,
	 * try a pullup.  For labeled systems we need to always take this
	 * path as M_CTLs are "notdata" but have trailing data to process.
	 */
	if (!OK_32PTR(rptr) ||
	    (mp->b_wptr - rptr) < IP_SIMPLE_HDR_LENGTH || is_system_labeled()) {
hdrtoosmall:
		if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
			TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
			    "ip_wput_end: q %p (%S)", q, "pullupfailed");
			if (first_mp == NULL)
				first_mp = mp;
			goto discard_pkt;
		}

		/* This function assumes that mp points to an IPv4 packet. */
		if (is_system_labeled() && q->q_next == NULL &&
		    (*mp->b_rptr & 0xf0) == (IPV4_VERSION << 4) &&
		    !connp->conn_ulp_labeled) {
			err = tsol_check_label(BEST_CRED(mp, connp), &mp,
			    connp->conn_mac_exempt, ipst);
			ipha = (ipha_t *)mp->b_rptr;
			if (first_mp != NULL)
				first_mp->b_cont = mp;
			if (err != 0) {
				if (first_mp == NULL)
					first_mp = mp;
				if (err == EINVAL)
					goto icmp_parameter_problem;
				ip2dbg(("ip_wput: label check failed (%d)\n",
				    err));
				goto discard_pkt;
			}
		}

		ipha = (ipha_t *)mp->b_rptr;
		if (first_mp == NULL) {
			ASSERT(attach_ill == NULL && xmit_ill == NULL);
			/*
			 * If we got here because of "goto hdrtoosmall"
			 * We need to attach a IPSEC_OUT.
			 */
			if (connp->conn_out_enforce_policy) {
				if (((mp = ipsec_attach_ipsec_out(&mp, connp,
				    NULL, ipha->ipha_protocol,
				    ipst->ips_netstack)) == NULL)) {
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutDiscards);
					if (need_decref)
						CONN_DEC_REF(connp);
					return;
				} else {
					ASSERT(mp->b_datap->db_type == M_CTL);
					first_mp = mp;
					mp = mp->b_cont;
					mctl_present = B_TRUE;
				}
			} else {
				first_mp = mp;
				mctl_present = B_FALSE;
			}
		}
	}
#endif

	/* Most of the code below is written for speed, not readability */
	v_hlen_tos_len = ((uint32_t *)ipha)[0];

	/*
	 * If ip_newroute() fails, we're going to need a full
	 * header for the icmp wraparound.
	 */
	if (V_HLEN != IP_SIMPLE_HDR_VERSION) {
		uint_t	v_hlen;
version_hdrlen_check:
		ASSERT(first_mp != NULL);
		v_hlen = V_HLEN;
		/*
		 * siphon off IPv6 packets coming down from transport
		 * layer modules here.
		 * Note: high-order bit carries NUD reachability confirmation
		 */
		if (((v_hlen >> 4) & 0x7) == IPV6_VERSION) {
			/*
			 * FIXME: assume that callers of ip_output* call
			 * the right version?
			 */
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutWrongIPVersion);
			ASSERT(xmit_ill == NULL);
			if (attach_ill != NULL)
				ill_refrele(attach_ill);
			if (need_decref)
				mp->b_flag |= MSGHASREF;
			(void) ip_output_v6(arg, first_mp, arg2, caller);
			return;
		}

		if ((v_hlen >> 4) != IP_VERSION) {
			TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
			    "ip_wput_end: q %p (%S)", q, "badvers");
			goto discard_pkt;
		}
		/*
		 * Is the header length at least 20 bytes?
		 *
		 * Are there enough bytes accessible in the header?  If
		 * not, try a pullup.
		 */
		v_hlen &= 0xF;
		v_hlen <<= 2;
		if (v_hlen < IP_SIMPLE_HDR_LENGTH) {
			TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
			    "ip_wput_end: q %p (%S)", q, "badlen");
			goto discard_pkt;
		}
		if (v_hlen > (mp->b_wptr - rptr)) {
			if (!pullupmsg(mp, v_hlen)) {
				TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
				    "ip_wput_end: q %p (%S)", q, "badpullup2");
				goto discard_pkt;
			}
			ipha = (ipha_t *)mp->b_rptr;
		}
		/*
		 * Move first entry from any source route into ipha_dst and
		 * verify the options
		 */
		if (ip_wput_options(q, first_mp, ipha, mctl_present,
		    zoneid, ipst)) {
			ASSERT(xmit_ill == NULL);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			if (attach_ill != NULL)
				ill_refrele(attach_ill);
			TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
			    "ip_wput_end: q %p (%S)", q, "badopts");
			if (need_decref)
				CONN_DEC_REF(connp);
			return;
		}
	}
	dst = ipha->ipha_dst;

	/*
	 * Try to get an IRE_CACHE for the destination address.	 If we can't,
	 * we have to run the packet through ip_newroute which will take
	 * the appropriate action to arrange for an IRE_CACHE, such as querying
	 * a resolver, or assigning a default gateway, etc.
	 */
	if (CLASSD(dst)) {
		ipif_t	*ipif;
		uint32_t setsrc = 0;

multicast:
		ASSERT(first_mp != NULL);
		ip2dbg(("ip_wput: CLASSD\n"));
		if (connp == NULL) {
			/*
			 * Use the first good ipif on the ill.
			 * XXX Should this ever happen? (Appears
			 * to show up with just ppp and no ethernet due
			 * to in.rdisc.)
			 * However, ire_send should be able to
			 * call ip_wput_ire directly.
			 *
			 * XXX Also, this can happen for ICMP and other packets
			 * with multicast source addresses.  Perhaps we should
			 * fix things so that we drop the packet in question,
			 * but for now, just run with it.
			 */
			ill_t *ill = (ill_t *)q->q_ptr;

			/*
			 * Don't honor attach_if for this case. If ill
			 * is part of the group, ipif could belong to
			 * any ill and we cannot maintain attach_ill
			 * and ipif_ill same anymore and the assert
			 * below would fail.
			 */
			if (mctl_present && io->ipsec_out_attach_if) {
				io->ipsec_out_ill_index = 0;
				io->ipsec_out_attach_if = B_FALSE;
				ASSERT(attach_ill != NULL);
				ill_refrele(attach_ill);
				attach_ill = NULL;
			}

			ASSERT(attach_ill == NULL);
			ipif = ipif_select_source(ill, dst, GLOBAL_ZONEID);
			if (ipif == NULL) {
				if (need_decref)
					CONN_DEC_REF(connp);
				freemsg(first_mp);
				return;
			}
			ip1dbg(("ip_wput: CLASSD no CONN: dst 0x%x on %s\n",
			    ntohl(dst), ill->ill_name));
		} else {
			/*
			 * The order of precedence is IP_BOUND_IF, IP_PKTINFO
			 * and IP_MULTICAST_IF.  The block comment above this
			 * function explains the locking mechanism used here.
			 */
			if (xmit_ill == NULL) {
				xmit_ill = conn_get_held_ill(connp,
				    &connp->conn_outgoing_ill, &err);
				if (err == ILL_LOOKUP_FAILED) {
					ip1dbg(("ip_wput: No ill for "
					    "IP_BOUND_IF\n"));
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutNoRoutes);
					goto drop_pkt;
				}
			}

			if (xmit_ill == NULL) {
				ipif = conn_get_held_ipif(connp,
				    &connp->conn_multicast_ipif, &err);
				if (err == IPIF_LOOKUP_FAILED) {
					ip1dbg(("ip_wput: No ipif for "
					    "multicast\n"));
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutNoRoutes);
					goto drop_pkt;
				}
			}
			if (xmit_ill != NULL) {
				ipif = ipif_get_next_ipif(NULL, xmit_ill);
				if (ipif == NULL) {
					ip1dbg(("ip_wput: No ipif for "
					    "xmit_ill\n"));
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutNoRoutes);
					goto drop_pkt;
				}
			} else if (ipif == NULL || ipif->ipif_isv6) {
				/*
				 * We must do this ipif determination here
				 * else we could pass through ip_newroute
				 * and come back here without the conn context.
				 *
				 * Note: we do late binding i.e. we bind to
				 * the interface when the first packet is sent.
				 * For performance reasons we do not rebind on
				 * each packet but keep the binding until the
				 * next IP_MULTICAST_IF option.
				 *
				 * conn_multicast_{ipif,ill} are shared between
				 * IPv4 and IPv6 and AF_INET6 sockets can
				 * send both IPv4 and IPv6 packets. Hence
				 * we have to check that "isv6" matches above.
				 */
				if (ipif != NULL)
					ipif_refrele(ipif);
				ipif = ipif_lookup_group(dst, zoneid, ipst);
				if (ipif == NULL) {
					ip1dbg(("ip_wput: No ipif for "
					    "multicast\n"));
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutNoRoutes);
					goto drop_pkt;
				}
				err = conn_set_held_ipif(connp,
				    &connp->conn_multicast_ipif, ipif);
				if (err == IPIF_LOOKUP_FAILED) {
					ipif_refrele(ipif);
					ip1dbg(("ip_wput: No ipif for "
					    "multicast\n"));
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutNoRoutes);
					goto drop_pkt;
				}
			}
		}
		ASSERT(!ipif->ipif_isv6);
		/*
		 * As we may lose the conn by the time we reach ip_wput_ire,
		 * we copy conn_multicast_loop and conn_dontroute on to an
		 * ipsec_out. In case if this datagram goes out secure,
		 * we need the ill_index also. Copy that also into the
		 * ipsec_out.
		 */
		if (mctl_present) {
			io = (ipsec_out_t *)first_mp->b_rptr;
			ASSERT(first_mp->b_datap->db_type == M_CTL);
			ASSERT(io->ipsec_out_type == IPSEC_OUT);
		} else {
			ASSERT(mp == first_mp);
			if ((first_mp = allocb(sizeof (ipsec_info_t),
			    BPRI_HI)) == NULL) {
				ipif_refrele(ipif);
				first_mp = mp;
				goto discard_pkt;
			}
			first_mp->b_datap->db_type = M_CTL;
			first_mp->b_wptr += sizeof (ipsec_info_t);
			/* ipsec_out_secure is B_FALSE now */
			bzero(first_mp->b_rptr, sizeof (ipsec_info_t));
			io = (ipsec_out_t *)first_mp->b_rptr;
			io->ipsec_out_type = IPSEC_OUT;
			io->ipsec_out_len = sizeof (ipsec_out_t);
			io->ipsec_out_use_global_policy = B_TRUE;
			io->ipsec_out_ns = ipst->ips_netstack;
			first_mp->b_cont = mp;
			mctl_present = B_TRUE;
		}
		if (attach_ill != NULL) {
			ASSERT(attach_ill == ipif->ipif_ill);
			match_flags = MATCH_IRE_ILL | MATCH_IRE_SECATTR;

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(attach_ill)) {
				match_flags |= MATCH_IRE_MARK_HIDDEN;
			}
			io->ipsec_out_ill_index =
			    attach_ill->ill_phyint->phyint_ifindex;
			io->ipsec_out_attach_if = B_TRUE;
		} else {
			match_flags = MATCH_IRE_ILL_GROUP | MATCH_IRE_SECATTR;
			io->ipsec_out_ill_index =
			    ipif->ipif_ill->ill_phyint->phyint_ifindex;
		}
		if (connp != NULL) {
			io->ipsec_out_multicast_loop =
			    connp->conn_multicast_loop;
			io->ipsec_out_dontroute = connp->conn_dontroute;
			io->ipsec_out_zoneid = connp->conn_zoneid;
		}
		/*
		 * If the application uses IP_MULTICAST_IF with
		 * different logical addresses of the same ILL, we
		 * need to make sure that the soruce address of
		 * the packet matches the logical IP address used
		 * in the option. We do it by initializing ipha_src
		 * here. This should keep IPsec also happy as
		 * when we return from IPsec processing, we don't
		 * have to worry about getting the right address on
		 * the packet. Thus it is sufficient to look for
		 * IRE_CACHE using MATCH_IRE_ILL rathen than
		 * MATCH_IRE_IPIF.
		 *
		 * NOTE : We need to do it for non-secure case also as
		 * this might go out secure if there is a global policy
		 * match in ip_wput_ire. For bind to IPIF_NOFAILOVER
		 * address, the source should be initialized already and
		 * hence we won't be initializing here.
		 *
		 * As we do not have the ire yet, it is possible that
		 * we set the source address here and then later discover
		 * that the ire implies the source address to be assigned
		 * through the RTF_SETSRC flag.
		 * In that case, the setsrc variable will remind us
		 * that overwritting the source address by the one
		 * of the RTF_SETSRC-flagged ire is allowed.
		 */
		if (ipha->ipha_src == INADDR_ANY &&
		    (connp == NULL || !connp->conn_unspec_src)) {
			ipha->ipha_src = ipif->ipif_src_addr;
			setsrc = RTF_SETSRC;
		}
		/*
		 * Find an IRE which matches the destination and the outgoing
		 * queue (i.e. the outgoing interface.)
		 * For loopback use a unicast IP address for
		 * the ire lookup.
		 */
		if (IS_LOOPBACK(ipif->ipif_ill))
			dst = ipif->ipif_lcl_addr;

		/*
		 * If xmit_ill is set, we branch out to ip_newroute_ipif.
		 * We don't need to lookup ire in ctable as the packet
		 * needs to be sent to the destination through the specified
		 * ill irrespective of ires in the cache table.
		 */
		ire = NULL;
		if (xmit_ill == NULL) {
			ire = ire_ctable_lookup(dst, 0, 0, ipif,
			    zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
		}

		/*
		 * refrele attach_ill as its not needed anymore.
		 */
		if (attach_ill != NULL) {
			ill_refrele(attach_ill);
			attach_ill = NULL;
		}

		if (ire == NULL) {
			/*
			 * Multicast loopback and multicast forwarding is
			 * done in ip_wput_ire.
			 *
			 * Mark this packet to make it be delivered to
			 * ip_wput_ire after the new ire has been
			 * created.
			 *
			 * The call to ip_newroute_ipif takes into account
			 * the setsrc reminder. In any case, we take care
			 * of the RTF_MULTIRT flag.
			 */
			mp->b_prev = mp->b_next = NULL;
			if (xmit_ill == NULL ||
			    xmit_ill->ill_ipif_up_count > 0) {
				ip_newroute_ipif(q, first_mp, ipif, dst, connp,
				    setsrc | RTF_MULTIRT, zoneid, infop);
				TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
				    "ip_wput_end: q %p (%S)", q, "noire");
			} else {
				freemsg(first_mp);
			}
			ipif_refrele(ipif);
			if (xmit_ill != NULL)
				ill_refrele(xmit_ill);
			if (need_decref)
				CONN_DEC_REF(connp);
			return;
		}

		ipif_refrele(ipif);
		ipif = NULL;
		ASSERT(xmit_ill == NULL);

		/*
		 * Honor the RTF_SETSRC flag for multicast packets,
		 * if allowed by the setsrc reminder.
		 */
		if ((ire->ire_flags & RTF_SETSRC) && setsrc) {
			ipha->ipha_src = ire->ire_src_addr;
		}

		/*
		 * Unconditionally force the TTL to 1 for
		 * multirouted multicast packets:
		 * multirouted multicast should not cross
		 * multicast routers.
		 */
		if (ire->ire_flags & RTF_MULTIRT) {
			if (ipha->ipha_ttl > 1) {
				ip2dbg(("ip_wput: forcing multicast "
				    "multirt TTL to 1 (was %d), dst 0x%08x\n",
				    ipha->ipha_ttl, ntohl(ire->ire_addr)));
				ipha->ipha_ttl = 1;
			}
		}
	} else {
		ire = ire_cache_lookup(dst, zoneid, MBLK_GETLABEL(mp), ipst);
		if ((ire != NULL) && (ire->ire_type &
		    (IRE_BROADCAST | IRE_LOCAL | IRE_LOOPBACK))) {
			ignore_dontroute = B_TRUE;
			ignore_nexthop = B_TRUE;
		}
		if (ire != NULL) {
			ire_refrele(ire);
			ire = NULL;
		}
		/*
		 * Guard against coming in from arp in which case conn is NULL.
		 * Also guard against non M_DATA with dontroute set but
		 * destined to local, loopback or broadcast addresses.
		 */
		if (connp != NULL && connp->conn_dontroute &&
		    !ignore_dontroute) {
dontroute:
			/*
			 * Set TTL to 1 if SO_DONTROUTE is set to prevent
			 * routing protocols from seeing false direct
			 * connectivity.
			 */
			ipha->ipha_ttl = 1;

			/* If suitable ipif not found, drop packet */
			dst_ipif = ipif_lookup_onlink_addr(dst, zoneid, ipst);
			if (dst_ipif == NULL) {
noroute:
				ip1dbg(("ip_wput: no route for dst using"
				    " SO_DONTROUTE\n"));
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsOutNoRoutes);
				mp->b_prev = mp->b_next = NULL;
				if (first_mp == NULL)
					first_mp = mp;
				goto drop_pkt;
			} else {
				/*
				 * If suitable ipif has been found, set
				 * xmit_ill to the corresponding
				 * ipif_ill because we'll be using the
				 * send_from_ill logic below.
				 */
				ASSERT(xmit_ill == NULL);
				xmit_ill = dst_ipif->ipif_ill;
				mutex_enter(&xmit_ill->ill_lock);
				if (!ILL_CAN_LOOKUP(xmit_ill)) {
					mutex_exit(&xmit_ill->ill_lock);
					xmit_ill = NULL;
					ipif_refrele(dst_ipif);
					goto noroute;
				}
				ill_refhold_locked(xmit_ill);
				mutex_exit(&xmit_ill->ill_lock);
				ipif_refrele(dst_ipif);
			}
		}
		/*
		 * If we are bound to IPIF_NOFAILOVER address, look for
		 * an IRE_CACHE matching the ill.
		 */
send_from_ill:
		if (attach_ill != NULL) {
			ipif_t	*attach_ipif;

			match_flags = MATCH_IRE_ILL | MATCH_IRE_SECATTR;

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(attach_ill)) {
				match_flags |= MATCH_IRE_MARK_HIDDEN;
			}

			attach_ipif = ipif_get_next_ipif(NULL, attach_ill);
			if (attach_ipif == NULL) {
				ip1dbg(("ip_wput: No ipif for attach_ill\n"));
				goto discard_pkt;
			}
			ire = ire_ctable_lookup(dst, 0, 0, attach_ipif,
			    zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
			ipif_refrele(attach_ipif);
		} else if (xmit_ill != NULL) {
			ipif_t *ipif;

			/*
			 * Mark this packet as originated locally
			 */
			mp->b_prev = mp->b_next = NULL;

			/*
			 * Could be SO_DONTROUTE case also.
			 * Verify that at least one ipif is up on the ill.
			 */
			if (xmit_ill->ill_ipif_up_count == 0) {
				ip1dbg(("ip_output: xmit_ill %s is down\n",
				    xmit_ill->ill_name));
				goto drop_pkt;
			}

			ipif = ipif_get_next_ipif(NULL, xmit_ill);
			if (ipif == NULL) {
				ip1dbg(("ip_output: xmit_ill %s NULL ipif\n",
				    xmit_ill->ill_name));
				goto drop_pkt;
			}

			/*
			 * Look for a ire that is part of the group,
			 * if found use it else call ip_newroute_ipif.
			 * IPCL_ZONEID is not used for matching because
			 * IP_ALLZONES option is valid only when the
			 * ill is accessible from all zones i.e has a
			 * valid ipif in all zones.
			 */
			match_flags = MATCH_IRE_ILL_GROUP | MATCH_IRE_SECATTR;
			ire = ire_ctable_lookup(dst, 0, 0, ipif, zoneid,
			    MBLK_GETLABEL(mp), match_flags, ipst);
			/*
			 * If an ire exists use it or else create
			 * an ire but don't add it to the cache.
			 * Adding an ire may cause issues with
			 * asymmetric routing.
			 * In case of multiroute always act as if
			 * ire does not exist.
			 */
			if (ire == NULL || ire->ire_flags & RTF_MULTIRT) {
				if (ire != NULL)
					ire_refrele(ire);
				ip_newroute_ipif(q, first_mp, ipif,
				    dst, connp, 0, zoneid, infop);
				ipif_refrele(ipif);
				ip1dbg(("ip_output: xmit_ill via %s\n",
				    xmit_ill->ill_name));
				ill_refrele(xmit_ill);
				if (need_decref)
					CONN_DEC_REF(connp);
				return;
			}
			ipif_refrele(ipif);
		} else if (ip_nexthop || (connp != NULL &&
		    (connp->conn_nexthop_set)) && !ignore_nexthop) {
			if (!ip_nexthop) {
				ip_nexthop = B_TRUE;
				nexthop_addr = connp->conn_nexthop_v4;
			}
			match_flags = MATCH_IRE_MARK_PRIVATE_ADDR |
			    MATCH_IRE_GW;
			ire = ire_ctable_lookup(dst, nexthop_addr, 0,
			    NULL, zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
		} else {
			ire = ire_cache_lookup(dst, zoneid, MBLK_GETLABEL(mp),
			    ipst);
		}
		if (!ire) {
			/*
			 * Make sure we don't load spread if this
			 * is IPIF_NOFAILOVER case.
			 */
			if ((attach_ill != NULL) ||
			    (ip_nexthop && !ignore_nexthop)) {
				if (mctl_present) {
					io = (ipsec_out_t *)first_mp->b_rptr;
					ASSERT(first_mp->b_datap->db_type ==
					    M_CTL);
					ASSERT(io->ipsec_out_type == IPSEC_OUT);
				} else {
					ASSERT(mp == first_mp);
					first_mp = allocb(
					    sizeof (ipsec_info_t), BPRI_HI);
					if (first_mp == NULL) {
						first_mp = mp;
						goto discard_pkt;
					}
					first_mp->b_datap->db_type = M_CTL;
					first_mp->b_wptr +=
					    sizeof (ipsec_info_t);
					/* ipsec_out_secure is B_FALSE now */
					bzero(first_mp->b_rptr,
					    sizeof (ipsec_info_t));
					io = (ipsec_out_t *)first_mp->b_rptr;
					io->ipsec_out_type = IPSEC_OUT;
					io->ipsec_out_len =
					    sizeof (ipsec_out_t);
					io->ipsec_out_use_global_policy =
					    B_TRUE;
					io->ipsec_out_ns = ipst->ips_netstack;
					first_mp->b_cont = mp;
					mctl_present = B_TRUE;
				}
				if (attach_ill != NULL) {
					io->ipsec_out_ill_index = attach_ill->
					    ill_phyint->phyint_ifindex;
					io->ipsec_out_attach_if = B_TRUE;
				} else {
					io->ipsec_out_ip_nexthop = ip_nexthop;
					io->ipsec_out_nexthop_addr =
					    nexthop_addr;
				}
			}
noirefound:
			/*
			 * Mark this packet as having originated on
			 * this machine.  This will be noted in
			 * ire_add_then_send, which needs to know
			 * whether to run it back through ip_wput or
			 * ip_rput following successful resolution.
			 */
			mp->b_prev = NULL;
			mp->b_next = NULL;
			ip_newroute(q, first_mp, dst, connp, zoneid, ipst);
			TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
			    "ip_wput_end: q %p (%S)", q, "newroute");
			if (attach_ill != NULL)
				ill_refrele(attach_ill);
			if (xmit_ill != NULL)
				ill_refrele(xmit_ill);
			if (need_decref)
				CONN_DEC_REF(connp);
			return;
		}
	}

	/* We now know where we are going with it. */

	TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
	    "ip_wput_end: q %p (%S)", q, "end");

	/*
	 * Check if the ire has the RTF_MULTIRT flag, inherited
	 * from an IRE_OFFSUBNET ire entry in ip_newroute.
	 */
	if (ire->ire_flags & RTF_MULTIRT) {
		/*
		 * Force the TTL of multirouted packets if required.
		 * The TTL of such packets is bounded by the
		 * ip_multirt_ttl ndd variable.
		 */
		if ((ipst->ips_ip_multirt_ttl > 0) &&
		    (ipha->ipha_ttl > ipst->ips_ip_multirt_ttl)) {
			ip2dbg(("ip_wput: forcing multirt TTL to %d "
			    "(was %d), dst 0x%08x\n",
			    ipst->ips_ip_multirt_ttl, ipha->ipha_ttl,
			    ntohl(ire->ire_addr)));
			ipha->ipha_ttl = ipst->ips_ip_multirt_ttl;
		}
		/*
		 * At this point, we check to see if there are any pending
		 * unresolved routes. ire_multirt_resolvable()
		 * checks in O(n) that all IRE_OFFSUBNET ire
		 * entries for the packet's destination and
		 * flagged RTF_MULTIRT are currently resolved.
		 * If some remain unresolved, we make a copy
		 * of the current message. It will be used
		 * to initiate additional route resolutions.
		 */
		multirt_need_resolve = ire_multirt_need_resolve(ire->ire_addr,
		    MBLK_GETLABEL(first_mp), ipst);
		ip2dbg(("ip_wput[noirefound]: ire %p, "
		    "multirt_need_resolve %d, first_mp %p\n",
		    (void *)ire, multirt_need_resolve, (void *)first_mp));
		if (multirt_need_resolve) {
			copy_mp = copymsg(first_mp);
			if (copy_mp != NULL) {
				MULTIRT_DEBUG_TAG(copy_mp);
			}
		}
	}

	ip_wput_ire(q, first_mp, ire, connp, caller, zoneid);
	/*
	 * Try to resolve another multiroute if
	 * ire_multirt_resolvable() deemed it necessary.
	 * At this point, we need to distinguish
	 * multicasts from other packets. For multicasts,
	 * we call ip_newroute_ipif() and request that both
	 * multirouting and setsrc flags are checked.
	 */
	if (copy_mp != NULL) {
		if (CLASSD(dst)) {
			ipif_t *ipif = ipif_lookup_group(dst, zoneid, ipst);
			if (ipif) {
				ASSERT(infop->ip_opt_ill_index == 0);
				ip_newroute_ipif(q, copy_mp, ipif, dst, connp,
				    RTF_SETSRC | RTF_MULTIRT, zoneid, infop);
				ipif_refrele(ipif);
			} else {
				MULTIRT_DEBUG_UNTAG(copy_mp);
				freemsg(copy_mp);
				copy_mp = NULL;
			}
		} else {
			ip_newroute(q, copy_mp, dst, connp, zoneid, ipst);
		}
	}
	if (attach_ill != NULL)
		ill_refrele(attach_ill);
	if (xmit_ill != NULL)
		ill_refrele(xmit_ill);
	if (need_decref)
		CONN_DEC_REF(connp);
	return;

icmp_parameter_problem:
	/* could not have originated externally */
	ASSERT(mp->b_prev == NULL);
	if (ip_hdr_complete(ipha, zoneid, ipst) == 0) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutNoRoutes);
		/* it's the IP header length that's in trouble */
		icmp_param_problem(q, first_mp, 0, zoneid, ipst);
		first_mp = NULL;
	}

discard_pkt:
	BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
drop_pkt:
	ip1dbg(("ip_wput: dropped packet\n"));
	if (ire != NULL)
		ire_refrele(ire);
	if (need_decref)
		CONN_DEC_REF(connp);
	freemsg(first_mp);
	if (attach_ill != NULL)
		ill_refrele(attach_ill);
	if (xmit_ill != NULL)
		ill_refrele(xmit_ill);
	TRACE_2(TR_FAC_IP, TR_IP_WPUT_END,
	    "ip_wput_end: q %p (%S)", q, "droppkt");
}

/*
 * If this is a conn_t queue, then we pass in the conn. This includes the
 * zoneid.
 * Otherwise, this is a message coming back from ARP or for an ill_t queue,
 * in which case we use the global zoneid since those are all part of
 * the global zone.
 */
void
ip_wput(queue_t *q, mblk_t *mp)
{
	if (CONN_Q(q))
		ip_output(Q_TO_CONN(q), mp, q, IP_WPUT);
	else
		ip_output(GLOBAL_ZONEID, mp, q, IP_WPUT);
}

/*
 *
 * The following rules must be observed when accessing any ipif or ill
 * that has been cached in the conn. Typically conn_nofailover_ill,
 * conn_outgoing_ill, conn_multicast_ipif and conn_multicast_ill.
 *
 * Access: The ipif or ill pointed to from the conn can be accessed under
 * the protection of the conn_lock or after it has been refheld under the
 * protection of the conn lock. In addition the IPIF_CAN_LOOKUP or
 * ILL_CAN_LOOKUP macros must be used before actually doing the refhold.
 * The reason for this is that a concurrent unplumb could actually be
 * cleaning up these cached pointers by walking the conns and might have
 * finished cleaning up the conn in question. The macros check that an
 * unplumb has not yet started on the ipif or ill.
 *
 * Caching: An ipif or ill pointer may be cached in the conn only after
 * making sure that an unplumb has not started. So the caching is done
 * while holding both the conn_lock and the ill_lock and after using the
 * ILL_CAN_LOOKUP/IPIF_CAN_LOOKUP macro. An unplumb will set the ILL_CONDEMNED
 * flag before starting the cleanup of conns.
 *
 * The list of ipifs hanging off the ill is protected by ill_g_lock and ill_lock
 * On the other hand to access ipif->ipif_ill, we need one of either ill_g_lock
 * or a reference to the ipif or a reference to an ire that references the
 * ipif. An ipif does not change its ill except for failover/failback. Since
 * failover/failback happens only after bringing down the ipif and making sure
 * the ipif refcnt has gone to zero and holding the ill_g_lock and ill_lock
 * the above holds.
 */
ipif_t *
conn_get_held_ipif(conn_t *connp, ipif_t **ipifp, int *err)
{
	ipif_t	*ipif;
	ill_t	*ill;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	*err = 0;
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	mutex_enter(&connp->conn_lock);
	ipif = *ipifp;
	if (ipif != NULL) {
		ill = ipif->ipif_ill;
		mutex_enter(&ill->ill_lock);
		if (IPIF_CAN_LOOKUP(ipif)) {
			ipif_refhold_locked(ipif);
			mutex_exit(&ill->ill_lock);
			mutex_exit(&connp->conn_lock);
			rw_exit(&ipst->ips_ill_g_lock);
			return (ipif);
		} else {
			*err = IPIF_LOOKUP_FAILED;
		}
		mutex_exit(&ill->ill_lock);
	}
	mutex_exit(&connp->conn_lock);
	rw_exit(&ipst->ips_ill_g_lock);
	return (NULL);
}

ill_t *
conn_get_held_ill(conn_t *connp, ill_t **illp, int *err)
{
	ill_t	*ill;

	*err = 0;
	mutex_enter(&connp->conn_lock);
	ill = *illp;
	if (ill != NULL) {
		mutex_enter(&ill->ill_lock);
		if (ILL_CAN_LOOKUP(ill)) {
			ill_refhold_locked(ill);
			mutex_exit(&ill->ill_lock);
			mutex_exit(&connp->conn_lock);
			return (ill);
		} else {
			*err = ILL_LOOKUP_FAILED;
		}
		mutex_exit(&ill->ill_lock);
	}
	mutex_exit(&connp->conn_lock);
	return (NULL);
}

static int
conn_set_held_ipif(conn_t *connp, ipif_t **ipifp, ipif_t *ipif)
{
	ill_t	*ill;

	ill = ipif->ipif_ill;
	mutex_enter(&connp->conn_lock);
	mutex_enter(&ill->ill_lock);
	if (IPIF_CAN_LOOKUP(ipif)) {
		*ipifp = ipif;
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		return (0);
	}
	mutex_exit(&ill->ill_lock);
	mutex_exit(&connp->conn_lock);
	return (IPIF_LOOKUP_FAILED);
}

/*
 * This is called if the outbound datagram needs fragmentation.
 *
 * NOTE : This function does not ire_refrele the ire argument passed in.
 */
static void
ip_wput_ire_fragmentit(mblk_t *ipsec_mp, ire_t *ire, zoneid_t zoneid,
    ip_stack_t *ipst, conn_t *connp)
{
	ipha_t		*ipha;
	mblk_t		*mp;
	uint32_t	v_hlen_tos_len;
	uint32_t	max_frag;
	uint32_t	frag_flag;
	boolean_t	dont_use;

	if (ipsec_mp->b_datap->db_type == M_CTL) {
		mp = ipsec_mp->b_cont;
	} else {
		mp = ipsec_mp;
	}

	ipha = (ipha_t *)mp->b_rptr;
	v_hlen_tos_len = ((uint32_t *)ipha)[0];

#ifdef	_BIG_ENDIAN
#define	V_HLEN	(v_hlen_tos_len >> 24)
#define	LENGTH	(v_hlen_tos_len & 0xFFFF)
#else
#define	V_HLEN	(v_hlen_tos_len & 0xFF)
#define	LENGTH	((v_hlen_tos_len >> 24) | ((v_hlen_tos_len >> 8) & 0xFF00))
#endif

#ifndef SPEED_BEFORE_SAFETY
	/*
	 * Check that ipha_length is consistent with
	 * the mblk length
	 */
	if (LENGTH != (mp->b_cont ? msgdsize(mp) : mp->b_wptr - rptr)) {
		ip0dbg(("Packet length mismatch: %d, %ld\n",
		    LENGTH, msgdsize(mp)));
		freemsg(ipsec_mp);
		TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
		    "ip_wput_ire_fragmentit: mp %p (%S)", mp,
		    "packet length mismatch");
		return;
	}
#endif
	/*
	 * Don't use frag_flag if pre-built packet or source
	 * routed or if multicast (since multicast packets do not solicit
	 * ICMP "packet too big" messages). Get the values of
	 * max_frag and frag_flag atomically by acquiring the
	 * ire_lock.
	 */
	mutex_enter(&ire->ire_lock);
	max_frag = ire->ire_max_frag;
	frag_flag = ire->ire_frag_flag;
	mutex_exit(&ire->ire_lock);

	dont_use = ((ipha->ipha_ident == IP_HDR_INCLUDED) ||
	    (V_HLEN != IP_SIMPLE_HDR_VERSION &&
	    ip_source_route_included(ipha)) || CLASSD(ipha->ipha_dst));

	ip_wput_frag(ire, ipsec_mp, OB_PKT, max_frag,
	    (dont_use ? 0 : frag_flag), zoneid, ipst, connp);
}

/*
 * Used for deciding the MSS size for the upper layer. Thus
 * we need to check the outbound policy values in the conn.
 */
int
conn_ipsec_length(conn_t *connp)
{
	ipsec_latch_t *ipl;

	ipl = connp->conn_latch;
	if (ipl == NULL)
		return (0);

	if (ipl->ipl_out_policy == NULL)
		return (0);

	return (ipl->ipl_out_policy->ipsp_act->ipa_ovhd);
}

/*
 * Returns an estimate of the IPsec headers size. This is used if
 * we don't want to call into IPsec to get the exact size.
 */
int
ipsec_out_extra_length(mblk_t *ipsec_mp)
{
	ipsec_out_t *io = (ipsec_out_t *)ipsec_mp->b_rptr;
	ipsec_action_t *a;

	ASSERT(io->ipsec_out_type == IPSEC_OUT);
	if (!io->ipsec_out_secure)
		return (0);

	a = io->ipsec_out_act;

	if (a == NULL) {
		ASSERT(io->ipsec_out_policy != NULL);
		a = io->ipsec_out_policy->ipsp_act;
	}
	ASSERT(a != NULL);

	return (a->ipa_ovhd);
}

/*
 * Returns an estimate of the IPsec headers size. This is used if
 * we don't want to call into IPsec to get the exact size.
 */
int
ipsec_in_extra_length(mblk_t *ipsec_mp)
{
	ipsec_in_t *ii = (ipsec_in_t *)ipsec_mp->b_rptr;
	ipsec_action_t *a;

	ASSERT(ii->ipsec_in_type == IPSEC_IN);

	a = ii->ipsec_in_action;
	return (a == NULL ? 0 : a->ipa_ovhd);
}

/*
 * If there are any source route options, return the true final
 * destination. Otherwise, return the destination.
 */
ipaddr_t
ip_get_dst(ipha_t *ipha)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	uint32_t off;

	dst = ipha->ipha_dst;

	if (IS_SIMPLE_IPH(ipha))
		return (dst);

	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		switch (optval) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			off = opt[IPOPT_OFFSET];
			/*
			 * If one of the conditions is true, it means
			 * end of options and dst already has the right
			 * value.
			 */
			if (!(optlen < IP_ADDR_LEN || off > optlen - 3)) {
				off = optlen - IP_ADDR_LEN;
				bcopy(&opt[off], &dst, IP_ADDR_LEN);
			}
			return (dst);
		default:
			break;
		}
	}

	return (dst);
}

mblk_t *
ip_wput_ire_parse_ipsec_out(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h, ire_t *ire,
    conn_t *connp, boolean_t unspec_src, zoneid_t zoneid)
{
	ipsec_out_t	*io;
	mblk_t		*first_mp;
	boolean_t policy_present;
	ip_stack_t	*ipst;
	ipsec_stack_t	*ipss;

	ASSERT(ire != NULL);
	ipst = ire->ire_ipst;
	ipss = ipst->ips_netstack->netstack_ipsec;

	first_mp = mp;
	if (mp->b_datap->db_type == M_CTL) {
		io = (ipsec_out_t *)first_mp->b_rptr;
		/*
		 * ip_wput[_v6] attaches an IPSEC_OUT in two cases.
		 *
		 * 1) There is per-socket policy (including cached global
		 *    policy) or a policy on the IP-in-IP tunnel.
		 * 2) There is no per-socket policy, but it is
		 *    a multicast packet that needs to go out
		 *    on a specific interface. This is the case
		 *    where (ip_wput and ip_wput_multicast) attaches
		 *    an IPSEC_OUT and sets ipsec_out_secure B_FALSE.
		 *
		 * In case (2) we check with global policy to
		 * see if there is a match and set the ill_index
		 * appropriately so that we can lookup the ire
		 * properly in ip_wput_ipsec_out.
		 */

		/*
		 * ipsec_out_use_global_policy is set to B_FALSE
		 * in ipsec_in_to_out(). Refer to that function for
		 * details.
		 */
		if ((io->ipsec_out_latch == NULL) &&
		    (io->ipsec_out_use_global_policy)) {
			return (ip_wput_attach_policy(first_mp, ipha, ip6h,
			    ire, connp, unspec_src, zoneid));
		}
		if (!io->ipsec_out_secure) {
			/*
			 * If this is not a secure packet, drop
			 * the IPSEC_OUT mp and treat it as a clear
			 * packet. This happens when we are sending
			 * a ICMP reply back to a clear packet. See
			 * ipsec_in_to_out() for details.
			 */
			mp = first_mp->b_cont;
			freeb(first_mp);
		}
		return (mp);
	}
	/*
	 * See whether we need to attach a global policy here. We
	 * don't depend on the conn (as it could be null) for deciding
	 * what policy this datagram should go through because it
	 * should have happened in ip_wput if there was some
	 * policy. This normally happens for connections which are not
	 * fully bound preventing us from caching policies in
	 * ip_bind. Packets coming from the TCP listener/global queue
	 * - which are non-hard_bound - could also be affected by
	 * applying policy here.
	 *
	 * If this packet is coming from tcp global queue or listener,
	 * we will be applying policy here.  This may not be *right*
	 * if these packets are coming from the detached connection as
	 * it could have gone in clear before. This happens only if a
	 * TCP connection started when there is no policy and somebody
	 * added policy before it became detached. Thus packets of the
	 * detached connection could go out secure and the other end
	 * would drop it because it will be expecting in clear. The
	 * converse is not true i.e if somebody starts a TCP
	 * connection and deletes the policy, all the packets will
	 * still go out with the policy that existed before deleting
	 * because ip_unbind sends up policy information which is used
	 * by TCP on subsequent ip_wputs. The right solution is to fix
	 * TCP to attach a dummy IPSEC_OUT and set
	 * ipsec_out_use_global_policy to B_FALSE. As this might
	 * affect performance for normal cases, we are not doing it.
	 * Thus, set policy before starting any TCP connections.
	 *
	 * NOTE - We might apply policy even for a hard bound connection
	 * - for which we cached policy in ip_bind - if somebody added
	 * global policy after we inherited the policy in ip_bind.
	 * This means that the packets that were going out in clear
	 * previously would start going secure and hence get dropped
	 * on the other side. To fix this, TCP attaches a dummy
	 * ipsec_out and make sure that we don't apply global policy.
	 */
	if (ipha != NULL)
		policy_present = ipss->ipsec_outbound_v4_policy_present;
	else
		policy_present = ipss->ipsec_outbound_v6_policy_present;
	if (!policy_present)
		return (mp);

	return (ip_wput_attach_policy(mp, ipha, ip6h, ire, connp, unspec_src,
	    zoneid));
}

ire_t *
conn_set_outgoing_ill(conn_t *connp, ire_t *ire, ill_t **conn_outgoing_ill)
{
	ipaddr_t addr;
	ire_t *save_ire;
	irb_t *irb;
	ill_group_t *illgrp;
	int	err;

	save_ire = ire;
	addr = ire->ire_addr;

	ASSERT(ire->ire_type == IRE_BROADCAST);

	illgrp = connp->conn_outgoing_ill->ill_group;
	if (illgrp == NULL) {
		*conn_outgoing_ill = conn_get_held_ill(connp,
		    &connp->conn_outgoing_ill, &err);
		if (err == ILL_LOOKUP_FAILED) {
			ire_refrele(save_ire);
			return (NULL);
		}
		return (save_ire);
	}
	/*
	 * If IP_BOUND_IF has been done, conn_outgoing_ill will be set.
	 * If it is part of the group, we need to send on the ire
	 * that has been cleared of IRE_MARK_NORECV and that belongs
	 * to this group. This is okay as IP_BOUND_IF really means
	 * any ill in the group. We depend on the fact that the
	 * first ire in the group is always cleared of IRE_MARK_NORECV
	 * if such an ire exists. This is possible only if you have
	 * at least one ill in the group that has not failed.
	 *
	 * First get to the ire that matches the address and group.
	 *
	 * We don't look for an ire with a matching zoneid because a given zone
	 * won't always have broadcast ires on all ills in the group.
	 */
	irb = ire->ire_bucket;
	rw_enter(&irb->irb_lock, RW_READER);
	if (ire->ire_marks & IRE_MARK_NORECV) {
		/*
		 * If the current zone only has an ire broadcast for this
		 * address marked NORECV, the ire we want is ahead in the
		 * bucket, so we look it up deliberately ignoring the zoneid.
		 */
		for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
			if (ire->ire_addr != addr)
				continue;
			/* skip over deleted ires */
			if (ire->ire_marks & IRE_MARK_CONDEMNED)
				continue;
		}
	}
	while (ire != NULL) {
		/*
		 * If a new interface is coming up, we could end up
		 * seeing the loopback ire and the non-loopback ire
		 * may not have been added yet. So check for ire_stq
		 */
		if (ire->ire_stq != NULL && (ire->ire_addr != addr ||
		    ire->ire_ipif->ipif_ill->ill_group == illgrp)) {
			break;
		}
		ire = ire->ire_next;
	}
	if (ire != NULL && ire->ire_addr == addr &&
	    ire->ire_ipif->ipif_ill->ill_group == illgrp) {
		IRE_REFHOLD(ire);
		rw_exit(&irb->irb_lock);
		ire_refrele(save_ire);
		*conn_outgoing_ill = ire_to_ill(ire);
		/*
		 * Refhold the ill to make the conn_outgoing_ill
		 * independent of the ire. ip_wput_ire goes in a loop
		 * and may refrele the ire. Since we have an ire at this
		 * point we don't need to use ILL_CAN_LOOKUP on the ill.
		 */
		ill_refhold(*conn_outgoing_ill);
		return (ire);
	}
	rw_exit(&irb->irb_lock);
	ip1dbg(("conn_set_outgoing_ill: No matching ire\n"));
	/*
	 * If we can't find a suitable ire, return the original ire.
	 */
	return (save_ire);
}

/*
 * This function does the ire_refrele of the ire passed in as the
 * argument. As this function looks up more ires i.e broadcast ires,
 * it needs to REFRELE them. Currently, for simplicity we don't
 * differentiate the one passed in and looked up here. We always
 * REFRELE.
 * IPQoS Notes:
 * IP policy is invoked if IPP_LOCAL_OUT is enabled. Processing for
 * IPsec packets are done in ipsec_out_process.
 *
 */
void
ip_wput_ire(queue_t *q, mblk_t *mp, ire_t *ire, conn_t *connp, int caller,
    zoneid_t zoneid)
{
	ipha_t		*ipha;
#define	rptr	((uchar_t *)ipha)
	queue_t		*stq;
#define	Q_TO_INDEX(stq)	(((ill_t *)stq->q_ptr)->ill_phyint->phyint_ifindex)
	uint32_t	v_hlen_tos_len;
	uint32_t	ttl_protocol;
	ipaddr_t	src;
	ipaddr_t	dst;
	uint32_t	cksum;
	ipaddr_t	orig_src;
	ire_t		*ire1;
	mblk_t		*next_mp;
	uint_t		hlen;
	uint16_t	*up;
	uint32_t	max_frag = ire->ire_max_frag;
	ill_t		*ill = ire_to_ill(ire);
	int		clusterwide;
	uint16_t	ip_hdr_included; /* IP header included by ULP? */
	int		ipsec_len;
	mblk_t		*first_mp;
	ipsec_out_t	*io;
	boolean_t	conn_dontroute;		/* conn value for multicast */
	boolean_t	conn_multicast_loop;	/* conn value for multicast */
	boolean_t	multicast_forward;	/* Should we forward ? */
	boolean_t	unspec_src;
	ill_t		*conn_outgoing_ill = NULL;
	ill_t		*ire_ill;
	ill_t		*ire1_ill;
	ill_t		*out_ill;
	uint32_t 	ill_index = 0;
	boolean_t	multirt_send = B_FALSE;
	int		err;
	ipxmit_state_t	pktxmit_state;
	ip_stack_t	*ipst = ire->ire_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	TRACE_1(TR_FAC_IP, TR_IP_WPUT_IRE_START,
	    "ip_wput_ire_start: q %p", q);

	multicast_forward = B_FALSE;
	unspec_src = (connp != NULL && connp->conn_unspec_src);

	if (ire->ire_flags & RTF_MULTIRT) {
		/*
		 * Multirouting case. The bucket where ire is stored
		 * probably holds other RTF_MULTIRT flagged ire
		 * to the destination. In this call to ip_wput_ire,
		 * we attempt to send the packet through all
		 * those ires. Thus, we first ensure that ire is the
		 * first RTF_MULTIRT ire in the bucket,
		 * before walking the ire list.
		 */
		ire_t *first_ire;
		irb_t *irb = ire->ire_bucket;
		ASSERT(irb != NULL);

		/* Make sure we do not omit any multiroute ire. */
		IRB_REFHOLD(irb);
		for (first_ire = irb->irb_ire;
		    first_ire != NULL;
		    first_ire = first_ire->ire_next) {
			if ((first_ire->ire_flags & RTF_MULTIRT) &&
			    (first_ire->ire_addr == ire->ire_addr) &&
			    !(first_ire->ire_marks &
			    (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN))) {
				break;
			}
		}

		if ((first_ire != NULL) && (first_ire != ire)) {
			IRE_REFHOLD(first_ire);
			ire_refrele(ire);
			ire = first_ire;
			ill = ire_to_ill(ire);
		}
		IRB_REFRELE(irb);
	}

	/*
	 * conn_outgoing_ill variable is used only in the broadcast loop.
	 * for performance we don't grab the mutexs in the fastpath
	 */
	if ((connp != NULL) &&
	    (ire->ire_type == IRE_BROADCAST) &&
	    ((connp->conn_nofailover_ill != NULL) ||
	    (connp->conn_outgoing_ill != NULL))) {
		/*
		 * Bind to IPIF_NOFAILOVER address overrides IP_BOUND_IF
		 * option. So, see if this endpoint is bound to a
		 * IPIF_NOFAILOVER address. If so, honor it. This implies
		 * that if the interface is failed, we will still send
		 * the packet on the same ill which is what we want.
		 */
		conn_outgoing_ill = conn_get_held_ill(connp,
		    &connp->conn_nofailover_ill, &err);
		if (err == ILL_LOOKUP_FAILED) {
			ire_refrele(ire);
			freemsg(mp);
			return;
		}
		if (conn_outgoing_ill == NULL) {
			/*
			 * Choose a good ill in the group to send the
			 * packets on.
			 */
			ire = conn_set_outgoing_ill(connp, ire,
			    &conn_outgoing_ill);
			if (ire == NULL) {
				freemsg(mp);
				return;
			}
		}
	}

	if (mp->b_datap->db_type != M_CTL) {
		ipha = (ipha_t *)mp->b_rptr;
	} else {
		io = (ipsec_out_t *)mp->b_rptr;
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
		ASSERT(zoneid == io->ipsec_out_zoneid);
		ASSERT(zoneid != ALL_ZONES);
		ipha = (ipha_t *)mp->b_cont->b_rptr;
		dst = ipha->ipha_dst;
		/*
		 * For the multicast case, ipsec_out carries conn_dontroute and
		 * conn_multicast_loop as conn may not be available here. We
		 * need this for multicast loopback and forwarding which is done
		 * later in the code.
		 */
		if (CLASSD(dst)) {
			conn_dontroute = io->ipsec_out_dontroute;
			conn_multicast_loop = io->ipsec_out_multicast_loop;
			/*
			 * If conn_dontroute is not set or conn_multicast_loop
			 * is set, we need to do forwarding/loopback. For
			 * datagrams from ip_wput_multicast, conn_dontroute is
			 * set to B_TRUE and conn_multicast_loop is set to
			 * B_FALSE so that we neither do forwarding nor
			 * loopback.
			 */
			if (!conn_dontroute || conn_multicast_loop)
				multicast_forward = B_TRUE;
		}
	}

	if (ire->ire_type == IRE_LOCAL && ire->ire_zoneid != zoneid &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * When a zone sends a packet to another zone, we try to deliver
		 * the packet under the same conditions as if the destination
		 * was a real node on the network. To do so, we look for a
		 * matching route in the forwarding table.
		 * RTF_REJECT and RTF_BLACKHOLE are handled just like
		 * ip_newroute() does.
		 * Note that IRE_LOCAL are special, since they are used
		 * when the zoneid doesn't match in some cases. This means that
		 * we need to handle ipha_src differently since ire_src_addr
		 * belongs to the receiving zone instead of the sending zone.
		 * When ip_restrict_interzone_loopback is set, then
		 * ire_cache_lookup() ensures that IRE_LOCAL are only used
		 * for loopback between zones when the logical "Ethernet" would
		 * have looped them back.
		 */
		ire_t *src_ire;

		src_ire = ire_ftable_lookup(ipha->ipha_dst, 0, 0, 0,
		    NULL, NULL, zoneid, 0, NULL, (MATCH_IRE_RECURSIVE |
		    MATCH_IRE_DEFAULT | MATCH_IRE_RJ_BHOLE), ipst);
		if (src_ire != NULL &&
		    !(src_ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE)) &&
		    (!ipst->ips_ip_restrict_interzone_loopback ||
		    ire_local_same_ill_group(ire, src_ire))) {
			if (ipha->ipha_src == INADDR_ANY && !unspec_src)
				ipha->ipha_src = src_ire->ire_src_addr;
			ire_refrele(src_ire);
		} else {
			ire_refrele(ire);
			if (conn_outgoing_ill != NULL)
				ill_refrele(conn_outgoing_ill);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutNoRoutes);
			if (src_ire != NULL) {
				if (src_ire->ire_flags & RTF_BLACKHOLE) {
					ire_refrele(src_ire);
					freemsg(mp);
					return;
				}
				ire_refrele(src_ire);
			}
			if (ip_hdr_complete(ipha, zoneid, ipst)) {
				/* Failed */
				freemsg(mp);
				return;
			}
			icmp_unreachable(q, mp, ICMP_HOST_UNREACHABLE, zoneid,
			    ipst);
			return;
		}
	}

	if (mp->b_datap->db_type == M_CTL ||
	    ipss->ipsec_outbound_v4_policy_present) {
		mp = ip_wput_ire_parse_ipsec_out(mp, ipha, NULL, ire, connp,
		    unspec_src, zoneid);
		if (mp == NULL) {
			ire_refrele(ire);
			if (conn_outgoing_ill != NULL)
				ill_refrele(conn_outgoing_ill);
			return;
		}
		/*
		 * Trusted Extensions supports all-zones interfaces, so
		 * zoneid == ALL_ZONES is valid, but IPsec maps ALL_ZONES to
		 * the global zone.
		 */
		if (zoneid == ALL_ZONES && mp->b_datap->db_type == M_CTL) {
			io = (ipsec_out_t *)mp->b_rptr;
			ASSERT(io->ipsec_out_type == IPSEC_OUT);
			zoneid = io->ipsec_out_zoneid;
		}
	}

	first_mp = mp;
	ipsec_len = 0;

	if (first_mp->b_datap->db_type == M_CTL) {
		io = (ipsec_out_t *)first_mp->b_rptr;
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
		mp = first_mp->b_cont;
		ipsec_len = ipsec_out_extra_length(first_mp);
		ASSERT(ipsec_len >= 0);
		/* We already picked up the zoneid from the M_CTL above */
		ASSERT(zoneid == io->ipsec_out_zoneid);
		ASSERT(zoneid != ALL_ZONES);

		/*
		 * Drop M_CTL here if IPsec processing is not needed.
		 * (Non-IPsec use of M_CTL extracted any information it
		 * needed above).
		 */
		if (ipsec_len == 0) {
			freeb(first_mp);
			first_mp = mp;
		}
	}

	/*
	 * Fast path for ip_wput_ire
	 */

	ipha = (ipha_t *)mp->b_rptr;
	v_hlen_tos_len = ((uint32_t *)ipha)[0];
	dst = ipha->ipha_dst;

	/*
	 * ICMP(RAWIP) module should set the ipha_ident to IP_HDR_INCLUDED
	 * if the socket is a SOCK_RAW type. The transport checksum should
	 * be provided in the pre-built packet, so we don't need to compute it.
	 * Also, other application set flags, like DF, should not be altered.
	 * Other transport MUST pass down zero.
	 */
	ip_hdr_included = ipha->ipha_ident;
	ASSERT(ipha->ipha_ident == 0 || ipha->ipha_ident == IP_HDR_INCLUDED);

	if (CLASSD(dst)) {
		ip1dbg(("ip_wput_ire: to 0x%x ire %s addr 0x%x\n",
		    ntohl(dst),
		    ip_nv_lookup(ire_nv_tbl, ire->ire_type),
		    ntohl(ire->ire_addr)));
	}

/* Macros to extract header fields from data already in registers */
#ifdef	_BIG_ENDIAN
#define	V_HLEN	(v_hlen_tos_len >> 24)
#define	LENGTH	(v_hlen_tos_len & 0xFFFF)
#define	PROTO	(ttl_protocol & 0xFF)
#else
#define	V_HLEN	(v_hlen_tos_len & 0xFF)
#define	LENGTH	((v_hlen_tos_len >> 24) | ((v_hlen_tos_len >> 8) & 0xFF00))
#define	PROTO	(ttl_protocol >> 8)
#endif


	orig_src = src = ipha->ipha_src;
	/* (The loop back to "another" is explained down below.) */
another:;
	/*
	 * Assign an ident value for this packet.  We assign idents on
	 * a per destination basis out of the IRE.  There could be
	 * other threads targeting the same destination, so we have to
	 * arrange for a atomic increment.  Note that we use a 32-bit
	 * atomic add because it has better performance than its
	 * 16-bit sibling.
	 *
	 * If running in cluster mode and if the source address
	 * belongs to a replicated service then vector through
	 * cl_inet_ipident vector to allocate ip identifier
	 * NOTE: This is a contract private interface with the
	 * clustering group.
	 */
	clusterwide = 0;
	if (cl_inet_ipident) {
		ASSERT(cl_inet_isclusterwide);
		if ((*cl_inet_isclusterwide)(IPPROTO_IP,
		    AF_INET, (uint8_t *)(uintptr_t)src)) {
			ipha->ipha_ident = (*cl_inet_ipident)(IPPROTO_IP,
			    AF_INET, (uint8_t *)(uintptr_t)src,
			    (uint8_t *)(uintptr_t)dst);
			clusterwide = 1;
		}
	}
	if (!clusterwide) {
		ipha->ipha_ident =
		    (uint16_t)atomic_add_32_nv(&ire->ire_ident, 1);
	}

#ifndef _BIG_ENDIAN
	ipha->ipha_ident = (ipha->ipha_ident << 8) | (ipha->ipha_ident >> 8);
#endif

	/*
	 * Set source address unless sent on an ill or conn_unspec_src is set.
	 * This is needed to obey conn_unspec_src when packets go through
	 * ip_newroute + arp.
	 * Assumes ip_newroute{,_multi} sets the source address as well.
	 */
	if (src == INADDR_ANY && !unspec_src) {
		/*
		 * Assign the appropriate source address from the IRE if none
		 * was specified.
		 */
		ASSERT(ire->ire_ipversion == IPV4_VERSION);

		/*
		 * With IP multipathing, broadcast packets are sent on the ire
		 * that has been cleared of IRE_MARK_NORECV and that belongs to
		 * the group. However, this ire might not be in the same zone so
		 * we can't always use its source address. We look for a
		 * broadcast ire in the same group and in the right zone.
		 */
		if (ire->ire_type == IRE_BROADCAST &&
		    ire->ire_zoneid != zoneid) {
			ire_t *src_ire = ire_ctable_lookup(dst, 0,
			    IRE_BROADCAST, ire->ire_ipif, zoneid, NULL,
			    (MATCH_IRE_TYPE | MATCH_IRE_ILL_GROUP), ipst);
			if (src_ire != NULL) {
				src = src_ire->ire_src_addr;
				ire_refrele(src_ire);
			} else {
				ire_refrele(ire);
				if (conn_outgoing_ill != NULL)
					ill_refrele(conn_outgoing_ill);
				freemsg(first_mp);
				if (ill != NULL) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsOutDiscards);
				} else {
					BUMP_MIB(&ipst->ips_ip_mib,
					    ipIfStatsOutDiscards);
				}
				return;
			}
		} else {
			src = ire->ire_src_addr;
		}

		if (connp == NULL) {
			ip1dbg(("ip_wput_ire: no connp and no src "
			    "address for dst 0x%x, using src 0x%x\n",
			    ntohl(dst),
			    ntohl(src)));
		}
		ipha->ipha_src = src;
	}
	stq = ire->ire_stq;

	/*
	 * We only allow ire chains for broadcasts since there will
	 * be multiple IRE_CACHE entries for the same multicast
	 * address (one per ipif).
	 */
	next_mp = NULL;

	/* broadcast packet */
	if (ire->ire_type == IRE_BROADCAST)
		goto broadcast;

	/* loopback ? */
	if (stq == NULL)
		goto nullstq;

	/* The ill_index for outbound ILL */
	ill_index = Q_TO_INDEX(stq);

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests);
	ttl_protocol = ((uint16_t *)ipha)[4];

	/* pseudo checksum (do it in parts for IP header checksum) */
	cksum = (dst >> 16) + (dst & 0xFFFF) + (src >> 16) + (src & 0xFFFF);

	if (!IP_FLOW_CONTROLLED_ULP(PROTO)) {
		queue_t *dev_q = stq->q_next;

		/* flow controlled */
		if (DEV_Q_FLOW_BLOCKED(dev_q))
			goto blocked;

		if ((PROTO == IPPROTO_UDP) &&
		    (ip_hdr_included != IP_HDR_INCLUDED)) {
			hlen = (V_HLEN & 0xF) << 2;
			up = IPH_UDPH_CHECKSUMP(ipha, hlen);
			if (*up != 0) {
				IP_CKSUM_XMIT(ill, ire, mp, ipha, up, PROTO,
				    hlen, LENGTH, max_frag, ipsec_len, cksum);
				/* Software checksum? */
				if (DB_CKSUMFLAGS(mp) == 0) {
					IP_STAT(ipst, ip_out_sw_cksum);
					IP_STAT_UPDATE(ipst,
					    ip_udp_out_sw_cksum_bytes,
					    LENGTH - hlen);
				}
			}
		}
	} else if (ip_hdr_included != IP_HDR_INCLUDED) {
		hlen = (V_HLEN & 0xF) << 2;
		if (PROTO == IPPROTO_TCP) {
			up = IPH_TCPH_CHECKSUMP(ipha, hlen);
			/*
			 * The packet header is processed once and for all, even
			 * in the multirouting case. We disable hardware
			 * checksum if the packet is multirouted, as it will be
			 * replicated via several interfaces, and not all of
			 * them may have this capability.
			 */
			IP_CKSUM_XMIT(ill, ire, mp, ipha, up, PROTO, hlen,
			    LENGTH, max_frag, ipsec_len, cksum);
			/* Software checksum? */
			if (DB_CKSUMFLAGS(mp) == 0) {
				IP_STAT(ipst, ip_out_sw_cksum);
				IP_STAT_UPDATE(ipst, ip_tcp_out_sw_cksum_bytes,
				    LENGTH - hlen);
			}
		} else {
			sctp_hdr_t	*sctph;

			ASSERT(PROTO == IPPROTO_SCTP);
			ASSERT(MBLKL(mp) >= (hlen + sizeof (*sctph)));
			sctph = (sctp_hdr_t *)(mp->b_rptr + hlen);
			/*
			 * Zero out the checksum field to ensure proper
			 * checksum calculation.
			 */
			sctph->sh_chksum = 0;
#ifdef	DEBUG
			if (!skip_sctp_cksum)
#endif
				sctph->sh_chksum = sctp_cksum(mp, hlen);
		}
	}

	/*
	 * If this is a multicast packet and originated from ip_wput
	 * we need to do loopback and forwarding checks. If it comes
	 * from ip_wput_multicast, we SHOULD not do this.
	 */
	if (CLASSD(ipha->ipha_dst) && multicast_forward) goto multi_loopback;

	/* checksum */
	cksum += ttl_protocol;

	/* fragment the packet */
	if (max_frag < (uint_t)(LENGTH + ipsec_len))
		goto fragmentit;
	/*
	 * Don't use frag_flag if packet is pre-built or source
	 * routed or if multicast (since multicast packets do
	 * not solicit ICMP "packet too big" messages).
	 */
	if ((ip_hdr_included != IP_HDR_INCLUDED) &&
	    (V_HLEN == IP_SIMPLE_HDR_VERSION ||
	    !ip_source_route_included(ipha)) &&
	    !CLASSD(ipha->ipha_dst))
		ipha->ipha_fragment_offset_and_flags |=
		    htons(ire->ire_frag_flag);

	if (!(DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM)) {
		/* calculate IP header checksum */
		cksum += ipha->ipha_ident;
		cksum += (v_hlen_tos_len >> 16)+(v_hlen_tos_len & 0xFFFF);
		cksum += ipha->ipha_fragment_offset_and_flags;

		/* IP options present */
		hlen = (V_HLEN & 0xF) - IP_SIMPLE_HDR_LENGTH_IN_WORDS;
		if (hlen)
			goto checksumoptions;

		/* calculate hdr checksum */
		cksum = ((cksum & 0xFFFF) + (cksum >> 16));
		cksum = ~(cksum + (cksum >> 16));
		ipha->ipha_hdr_checksum = (uint16_t)cksum;
	}
	if (ipsec_len != 0) {
		/*
		 * We will do the rest of the processing after
		 * we come back from IPsec in ip_wput_ipsec_out().
		 */
		ASSERT(MBLKL(first_mp) >= sizeof (ipsec_out_t));

		io = (ipsec_out_t *)first_mp->b_rptr;
		io->ipsec_out_ill_index = ((ill_t *)stq->q_ptr)->
		    ill_phyint->phyint_ifindex;

		ipsec_out_process(q, first_mp, ire, ill_index);
		ire_refrele(ire);
		if (conn_outgoing_ill != NULL)
			ill_refrele(conn_outgoing_ill);
		return;
	}

	/*
	 * In most cases, the emission loop below is entered only
	 * once. Only in the case where the ire holds the
	 * RTF_MULTIRT flag, do we loop to process all RTF_MULTIRT
	 * flagged ires in the bucket, and send the packet
	 * through all crossed RTF_MULTIRT routes.
	 */
	if (ire->ire_flags & RTF_MULTIRT) {
		multirt_send = B_TRUE;
	}
	do {
		if (multirt_send) {
			irb_t *irb;
			/*
			 * We are in a multiple send case, need to get
			 * the next ire and make a duplicate of the packet.
			 * ire1 holds here the next ire to process in the
			 * bucket. If multirouting is expected,
			 * any non-RTF_MULTIRT ire that has the
			 * right destination address is ignored.
			 */
			irb = ire->ire_bucket;
			ASSERT(irb != NULL);

			IRB_REFHOLD(irb);
			for (ire1 = ire->ire_next;
			    ire1 != NULL;
			    ire1 = ire1->ire_next) {
				if ((ire1->ire_flags & RTF_MULTIRT) == 0)
					continue;
				if (ire1->ire_addr != ire->ire_addr)
					continue;
				if (ire1->ire_marks &
				    (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN))
					continue;

				/* Got one */
				IRE_REFHOLD(ire1);
				break;
			}
			IRB_REFRELE(irb);

			if (ire1 != NULL) {
				next_mp = copyb(mp);
				if ((next_mp == NULL) ||
				    ((mp->b_cont != NULL) &&
				    ((next_mp->b_cont =
				    dupmsg(mp->b_cont)) == NULL))) {
					freemsg(next_mp);
					next_mp = NULL;
					ire_refrele(ire1);
					ire1 = NULL;
				}
			}

			/* Last multiroute ire; don't loop anymore. */
			if (ire1 == NULL) {
				multirt_send = B_FALSE;
			}
		}

		DTRACE_PROBE4(ip4__physical__out__start, ill_t *, NULL,
		    ill_t *, ire->ire_ipif->ipif_ill, ipha_t *, ipha,
		    mblk_t *, mp);
		FW_HOOKS(ipst->ips_ip4_physical_out_event,
		    ipst->ips_ipv4firewall_physical_out,
		    NULL, ire->ire_ipif->ipif_ill, ipha, mp, mp, 0, ipst);
		DTRACE_PROBE1(ip4__physical__out__end, mblk_t *, mp);

		if (mp == NULL)
			goto release_ire_and_ill;

		if (ipst->ips_ipobs_enabled) {
			zoneid_t szone;

			/*
			 * On the outbound path the destination zone will be
			 * unknown as we're sending this packet out on the
			 * wire.
			 */
			szone = ip_get_zoneid_v4(ipha->ipha_src, mp, ipst,
			    ALL_ZONES);
			ipobs_hook(mp, IPOBS_HOOK_OUTBOUND, szone, ALL_ZONES,
			    ire->ire_ipif->ipif_ill, IPV4_VERSION, 0, ipst);
		}
		mp->b_prev = SET_BPREV_FLAG(IPP_LOCAL_OUT);
		DTRACE_PROBE2(ip__xmit__1, mblk_t *, mp, ire_t *, ire);

		pktxmit_state = ip_xmit_v4(mp, ire, NULL, B_TRUE, connp);

		if ((pktxmit_state == SEND_FAILED) ||
		    (pktxmit_state == LLHDR_RESLV_FAILED)) {
			ip2dbg(("ip_wput_ire: ip_xmit_v4 failed"
			    "- packet dropped\n"));
release_ire_and_ill:
			ire_refrele(ire);
			if (next_mp != NULL) {
				freemsg(next_mp);
				ire_refrele(ire1);
			}
			if (conn_outgoing_ill != NULL)
				ill_refrele(conn_outgoing_ill);
			return;
		}

		if (CLASSD(dst)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutMcastPkts);
			UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutMcastOctets,
			    LENGTH);
		}

		TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
		    "ip_wput_ire_end: q %p (%S)",
		    q, "last copy out");
		IRE_REFRELE(ire);

		if (multirt_send) {
			ASSERT(ire1);
			/*
			 * Proceed with the next RTF_MULTIRT ire,
			 * Also set up the send-to queue accordingly.
			 */
			ire = ire1;
			ire1 = NULL;
			stq = ire->ire_stq;
			mp = next_mp;
			next_mp = NULL;
			ipha = (ipha_t *)mp->b_rptr;
			ill_index = Q_TO_INDEX(stq);
			ill = (ill_t *)stq->q_ptr;
		}
	} while (multirt_send);
	if (conn_outgoing_ill != NULL)
		ill_refrele(conn_outgoing_ill);
	return;

	/*
	 * ire->ire_type == IRE_BROADCAST (minimize diffs)
	 */
broadcast:
	{
		/*
		 * To avoid broadcast storms, we usually set the TTL to 1 for
		 * broadcasts.  However, if SO_DONTROUTE isn't set, this value
		 * can be overridden stack-wide through the ip_broadcast_ttl
		 * ndd tunable, or on a per-connection basis through the
		 * IP_BROADCAST_TTL socket option.
		 *
		 * In the event that we are replying to incoming ICMP packets,
		 * connp could be NULL.
		 */
		ipha->ipha_ttl = ipst->ips_ip_broadcast_ttl;
		if (connp != NULL) {
			if (connp->conn_dontroute)
				ipha->ipha_ttl = 1;
			else if (connp->conn_broadcast_ttl != 0)
				ipha->ipha_ttl = connp->conn_broadcast_ttl;
		}

		/*
		 * Note that we are not doing a IRB_REFHOLD here.
		 * Actually we don't care if the list changes i.e
		 * if somebody deletes an IRE from the list while
		 * we drop the lock, the next time we come around
		 * ire_next will be NULL and hence we won't send
		 * out multiple copies which is fine.
		 */
		rw_enter(&ire->ire_bucket->irb_lock, RW_READER);
		ire1 = ire->ire_next;
		if (conn_outgoing_ill != NULL) {
			while (ire->ire_ipif->ipif_ill != conn_outgoing_ill) {
				ASSERT(ire1 == ire->ire_next);
				if (ire1 != NULL && ire1->ire_addr == dst) {
					ire_refrele(ire);
					ire = ire1;
					IRE_REFHOLD(ire);
					ire1 = ire->ire_next;
					continue;
				}
				rw_exit(&ire->ire_bucket->irb_lock);
				/* Did not find a matching ill */
				ip1dbg(("ip_wput_ire: broadcast with no "
				    "matching IP_BOUND_IF ill %s dst %x\n",
				    conn_outgoing_ill->ill_name, dst));
				freemsg(first_mp);
				if (ire != NULL)
					ire_refrele(ire);
				ill_refrele(conn_outgoing_ill);
				return;
			}
		} else if (ire1 != NULL && ire1->ire_addr == dst) {
			/*
			 * If the next IRE has the same address and is not one
			 * of the two copies that we need to send, try to see
			 * whether this copy should be sent at all. This
			 * assumes that we insert loopbacks first and then
			 * non-loopbacks. This is acheived by inserting the
			 * loopback always before non-loopback.
			 * This is used to send a single copy of a broadcast
			 * packet out all physical interfaces that have an
			 * matching IRE_BROADCAST while also looping
			 * back one copy (to ip_wput_local) for each
			 * matching physical interface. However, we avoid
			 * sending packets out different logical that match by
			 * having ipif_up/ipif_down supress duplicate
			 * IRE_BROADCASTS.
			 *
			 * This feature is currently used to get broadcasts
			 * sent to multiple interfaces, when the broadcast
			 * address being used applies to multiple interfaces.
			 * For example, a whole net broadcast will be
			 * replicated on every connected subnet of
			 * the target net.
			 *
			 * Each zone has its own set of IRE_BROADCASTs, so that
			 * we're able to distribute inbound packets to multiple
			 * zones who share a broadcast address. We avoid looping
			 * back outbound packets in different zones but on the
			 * same ill, as the application would see duplicates.
			 *
			 * If the interfaces are part of the same group,
			 * we would want to send only one copy out for
			 * whole group.
			 *
			 * This logic assumes that ire_add_v4() groups the
			 * IRE_BROADCAST entries so that those with the same
			 * ire_addr and ill_group are kept together.
			 */
			ire_ill = ire->ire_ipif->ipif_ill;
			if (ire->ire_stq == NULL && ire1->ire_stq != NULL) {
				if (ire_ill->ill_group != NULL &&
				    (ire->ire_marks & IRE_MARK_NORECV)) {
					/*
					 * If the current zone only has an ire
					 * broadcast for this address marked
					 * NORECV, the ire we want is ahead in
					 * the bucket, so we look it up
					 * deliberately ignoring the zoneid.
					 */
					for (ire1 = ire->ire_bucket->irb_ire;
					    ire1 != NULL;
					    ire1 = ire1->ire_next) {
						ire1_ill =
						    ire1->ire_ipif->ipif_ill;
						if (ire1->ire_addr != dst)
							continue;
						/* skip over the current ire */
						if (ire1 == ire)
							continue;
						/* skip over deleted ires */
						if (ire1->ire_marks &
						    IRE_MARK_CONDEMNED)
							continue;
						/*
						 * non-loopback ire in our
						 * group: use it for the next
						 * pass in the loop
						 */
						if (ire1->ire_stq != NULL &&
						    ire1_ill->ill_group ==
						    ire_ill->ill_group)
							break;
					}
				}
			} else {
				while (ire1 != NULL && ire1->ire_addr == dst) {
					ire1_ill = ire1->ire_ipif->ipif_ill;
					/*
					 * We can have two broadcast ires on the
					 * same ill in different zones; here
					 * we'll send a copy of the packet on
					 * each ill and the fanout code will
					 * call conn_wantpacket() to check that
					 * the zone has the broadcast address
					 * configured on the ill. If the two
					 * ires are in the same group we only
					 * send one copy up.
					 */
					if (ire1_ill != ire_ill &&
					    (ire1_ill->ill_group == NULL ||
					    ire_ill->ill_group == NULL ||
					    ire1_ill->ill_group !=
					    ire_ill->ill_group)) {
						break;
					}
					ire1 = ire1->ire_next;
				}
			}
		}
		ASSERT(multirt_send == B_FALSE);
		if (ire1 != NULL && ire1->ire_addr == dst) {
			if ((ire->ire_flags & RTF_MULTIRT) &&
			    (ire1->ire_flags & RTF_MULTIRT)) {
				/*
				 * We are in the multirouting case.
				 * The message must be sent at least
				 * on both ires. These ires have been
				 * inserted AFTER the standard ones
				 * in ip_rt_add(). There are thus no
				 * other ire entries for the destination
				 * address in the rest of the bucket
				 * that do not have the RTF_MULTIRT
				 * flag. We don't process a copy
				 * of the message here. This will be
				 * done in the final sending loop.
				 */
				multirt_send = B_TRUE;
			} else {
				next_mp = ip_copymsg(first_mp);
				if (next_mp != NULL)
					IRE_REFHOLD(ire1);
			}
		}
		rw_exit(&ire->ire_bucket->irb_lock);
	}

	if (stq) {
		/*
		 * A non-NULL send-to queue means this packet is going
		 * out of this machine.
		 */
		out_ill = (ill_t *)stq->q_ptr;

		BUMP_MIB(out_ill->ill_ip_mib, ipIfStatsHCOutRequests);
		ttl_protocol = ((uint16_t *)ipha)[4];
		/*
		 * We accumulate the pseudo header checksum in cksum.
		 * This is pretty hairy code, so watch close.  One
		 * thing to keep in mind is that UDP and TCP have
		 * stored their respective datagram lengths in their
		 * checksum fields.  This lines things up real nice.
		 */
		cksum = (dst >> 16) + (dst & 0xFFFF) +
		    (src >> 16) + (src & 0xFFFF);
		/*
		 * We assume the udp checksum field contains the
		 * length, so to compute the pseudo header checksum,
		 * all we need is the protocol number and src/dst.
		 */
		/* Provide the checksums for UDP and TCP. */
		if ((PROTO == IPPROTO_TCP) &&
		    (ip_hdr_included != IP_HDR_INCLUDED)) {
			/* hlen gets the number of uchar_ts in the IP header */
			hlen = (V_HLEN & 0xF) << 2;
			up = IPH_TCPH_CHECKSUMP(ipha, hlen);
			IP_STAT(ipst, ip_out_sw_cksum);
			IP_STAT_UPDATE(ipst, ip_tcp_out_sw_cksum_bytes,
			    LENGTH - hlen);
			*up = IP_CSUM(mp, hlen, cksum + IP_TCP_CSUM_COMP);
		} else if (PROTO == IPPROTO_SCTP &&
		    (ip_hdr_included != IP_HDR_INCLUDED)) {
			sctp_hdr_t	*sctph;

			hlen = (V_HLEN & 0xF) << 2;
			ASSERT(MBLKL(mp) >= (hlen + sizeof (*sctph)));
			sctph = (sctp_hdr_t *)(mp->b_rptr + hlen);
			sctph->sh_chksum = 0;
#ifdef	DEBUG
			if (!skip_sctp_cksum)
#endif
				sctph->sh_chksum = sctp_cksum(mp, hlen);
		} else {
			queue_t	*dev_q = stq->q_next;

			if (DEV_Q_FLOW_BLOCKED(dev_q)) {
blocked:
				ipha->ipha_ident = ip_hdr_included;
				/*
				 * If we don't have a conn to apply
				 * backpressure, free the message.
				 * In the ire_send path, we don't know
				 * the position to requeue the packet. Rather
				 * than reorder packets, we just drop this
				 * packet.
				 */
				if (ipst->ips_ip_output_queue &&
				    connp != NULL &&
				    caller != IRE_SEND) {
					if (caller == IP_WSRV) {
						connp->conn_did_putbq = 1;
						(void) putbq(connp->conn_wq,
						    first_mp);
						conn_drain_insert(connp);
						/*
						 * This is the service thread,
						 * and the queue is already
						 * noenabled. The check for
						 * canput and the putbq is not
						 * atomic. So we need to check
						 * again.
						 */
						if (canput(stq->q_next))
							connp->conn_did_putbq
							    = 0;
						IP_STAT(ipst, ip_conn_flputbq);
					} else {
						/*
						 * We are not the service proc.
						 * ip_wsrv will be scheduled or
						 * is already running.
						 */
						(void) putq(connp->conn_wq,
						    first_mp);
					}
				} else {
					out_ill = (ill_t *)stq->q_ptr;
					BUMP_MIB(out_ill->ill_ip_mib,
					    ipIfStatsOutDiscards);
					freemsg(first_mp);
					TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
					    "ip_wput_ire_end: q %p (%S)",
					    q, "discard");
				}
				ire_refrele(ire);
				if (next_mp) {
					ire_refrele(ire1);
					freemsg(next_mp);
				}
				if (conn_outgoing_ill != NULL)
					ill_refrele(conn_outgoing_ill);
				return;
			}
			if ((PROTO == IPPROTO_UDP) &&
			    (ip_hdr_included != IP_HDR_INCLUDED)) {
				/*
				 * hlen gets the number of uchar_ts in the
				 * IP header
				 */
				hlen = (V_HLEN & 0xF) << 2;
				up = IPH_UDPH_CHECKSUMP(ipha, hlen);
				max_frag = ire->ire_max_frag;
				if (*up != 0) {
					IP_CKSUM_XMIT(out_ill, ire, mp, ipha,
					    up, PROTO, hlen, LENGTH, max_frag,
					    ipsec_len, cksum);
					/* Software checksum? */
					if (DB_CKSUMFLAGS(mp) == 0) {
						IP_STAT(ipst, ip_out_sw_cksum);
						IP_STAT_UPDATE(ipst,
						    ip_udp_out_sw_cksum_bytes,
						    LENGTH - hlen);
					}
				}
			}
		}
		/*
		 * Need to do this even when fragmenting. The local
		 * loopback can be done without computing checksums
		 * but forwarding out other interface must be done
		 * after the IP checksum (and ULP checksums) have been
		 * computed.
		 *
		 * NOTE : multicast_forward is set only if this packet
		 * originated from ip_wput. For packets originating from
		 * ip_wput_multicast, it is not set.
		 */
		if (CLASSD(ipha->ipha_dst) && multicast_forward) {
multi_loopback:
			ip2dbg(("ip_wput: multicast, loop %d\n",
			    conn_multicast_loop));

			/*  Forget header checksum offload */
			DB_CKSUMFLAGS(mp) &= ~HCK_IPV4_HDRCKSUM;

			/*
			 * Local loopback of multicasts?  Check the
			 * ill.
			 *
			 * Note that the loopback function will not come
			 * in through ip_rput - it will only do the
			 * client fanout thus we need to do an mforward
			 * as well.  The is different from the BSD
			 * logic.
			 */
			if (ill != NULL) {
				ilm_t	*ilm;

				ILM_WALKER_HOLD(ill);
				ilm = ilm_lookup_ill(ill, ipha->ipha_dst,
				    ALL_ZONES);
				ILM_WALKER_RELE(ill);
				if (ilm != NULL) {
					/*
					 * Pass along the virtual output q.
					 * ip_wput_local() will distribute the
					 * packet to all the matching zones,
					 * except the sending zone when
					 * IP_MULTICAST_LOOP is false.
					 */
					ip_multicast_loopback(q, ill, first_mp,
					    conn_multicast_loop ? 0 :
					    IP_FF_NO_MCAST_LOOP, zoneid);
				}
			}
			if (ipha->ipha_ttl == 0) {
				/*
				 * 0 => only to this host i.e. we are
				 * done. We are also done if this was the
				 * loopback interface since it is sufficient
				 * to loopback one copy of a multicast packet.
				 */
				freemsg(first_mp);
				TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
				    "ip_wput_ire_end: q %p (%S)",
				    q, "loopback");
				ire_refrele(ire);
				if (conn_outgoing_ill != NULL)
					ill_refrele(conn_outgoing_ill);
				return;
			}
			/*
			 * ILLF_MULTICAST is checked in ip_newroute
			 * i.e. we don't need to check it here since
			 * all IRE_CACHEs come from ip_newroute.
			 * For multicast traffic, SO_DONTROUTE is interpreted
			 * to mean only send the packet out the interface
			 * (optionally specified with IP_MULTICAST_IF)
			 * and do not forward it out additional interfaces.
			 * RSVP and the rsvp daemon is an example of a
			 * protocol and user level process that
			 * handles it's own routing. Hence, it uses the
			 * SO_DONTROUTE option to accomplish this.
			 */

			if (ipst->ips_ip_g_mrouter && !conn_dontroute &&
			    ill != NULL) {
				/* Unconditionally redo the checksum */
				ipha->ipha_hdr_checksum = 0;
				ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

				/*
				 * If this needs to go out secure, we need
				 * to wait till we finish the IPsec
				 * processing.
				 */
				if (ipsec_len == 0 &&
				    ip_mforward(ill, ipha, mp)) {
					freemsg(first_mp);
					ip1dbg(("ip_wput: mforward failed\n"));
					TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
					    "ip_wput_ire_end: q %p (%S)",
					    q, "mforward failed");
					ire_refrele(ire);
					if (conn_outgoing_ill != NULL)
						ill_refrele(conn_outgoing_ill);
					return;
				}
			}
		}
		max_frag = ire->ire_max_frag;
		cksum += ttl_protocol;
		if (max_frag >= (uint_t)(LENGTH + ipsec_len)) {
			/* No fragmentation required for this one. */
			/*
			 * Don't use frag_flag if packet is pre-built or source
			 * routed or if multicast (since multicast packets do
			 * not solicit ICMP "packet too big" messages).
			 */
			if ((ip_hdr_included != IP_HDR_INCLUDED) &&
			    (V_HLEN == IP_SIMPLE_HDR_VERSION ||
			    !ip_source_route_included(ipha)) &&
			    !CLASSD(ipha->ipha_dst))
				ipha->ipha_fragment_offset_and_flags |=
				    htons(ire->ire_frag_flag);

			if (!(DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM)) {
				/* Complete the IP header checksum. */
				cksum += ipha->ipha_ident;
				cksum += (v_hlen_tos_len >> 16)+
				    (v_hlen_tos_len & 0xFFFF);
				cksum += ipha->ipha_fragment_offset_and_flags;
				hlen = (V_HLEN & 0xF) -
				    IP_SIMPLE_HDR_LENGTH_IN_WORDS;
				if (hlen) {
checksumoptions:
					/*
					 * Account for the IP Options in the IP
					 * header checksum.
					 */
					up = (uint16_t *)(rptr+
					    IP_SIMPLE_HDR_LENGTH);
					do {
						cksum += up[0];
						cksum += up[1];
						up += 2;
					} while (--hlen);
				}
				cksum = ((cksum & 0xFFFF) + (cksum >> 16));
				cksum = ~(cksum + (cksum >> 16));
				ipha->ipha_hdr_checksum = (uint16_t)cksum;
			}
			if (ipsec_len != 0) {
				ipsec_out_process(q, first_mp, ire, ill_index);
				if (!next_mp) {
					ire_refrele(ire);
					if (conn_outgoing_ill != NULL)
						ill_refrele(conn_outgoing_ill);
					return;
				}
				goto next;
			}

			/*
			 * multirt_send has already been handled
			 * for broadcast, but not yet for multicast
			 * or IP options.
			 */
			if (next_mp == NULL) {
				if (ire->ire_flags & RTF_MULTIRT) {
					multirt_send = B_TRUE;
				}
			}

			/*
			 * In most cases, the emission loop below is
			 * entered only once. Only in the case where
			 * the ire holds the RTF_MULTIRT flag, do we loop
			 * to process all RTF_MULTIRT ires in the bucket,
			 * and send the packet through all crossed
			 * RTF_MULTIRT routes.
			 */
			do {
				if (multirt_send) {
					irb_t *irb;

					irb = ire->ire_bucket;
					ASSERT(irb != NULL);
					/*
					 * We are in a multiple send case,
					 * need to get the next IRE and make
					 * a duplicate of the packet.
					 */
					IRB_REFHOLD(irb);
					for (ire1 = ire->ire_next;
					    ire1 != NULL;
					    ire1 = ire1->ire_next) {
						if (!(ire1->ire_flags &
						    RTF_MULTIRT)) {
							continue;
						}
						if (ire1->ire_addr !=
						    ire->ire_addr) {
							continue;
						}
						if (ire1->ire_marks &
						    (IRE_MARK_CONDEMNED|
						    IRE_MARK_HIDDEN)) {
							continue;
						}

						/* Got one */
						IRE_REFHOLD(ire1);
						break;
					}
					IRB_REFRELE(irb);

					if (ire1 != NULL) {
						next_mp = copyb(mp);
						if ((next_mp == NULL) ||
						    ((mp->b_cont != NULL) &&
						    ((next_mp->b_cont =
						    dupmsg(mp->b_cont))
						    == NULL))) {
							freemsg(next_mp);
							next_mp = NULL;
							ire_refrele(ire1);
							ire1 = NULL;
						}
					}

					/*
					 * Last multiroute ire; don't loop
					 * anymore. The emission is over
					 * and next_mp is NULL.
					 */
					if (ire1 == NULL) {
						multirt_send = B_FALSE;
					}
				}

				out_ill = ire_to_ill(ire);
				DTRACE_PROBE4(ip4__physical__out__start,
				    ill_t *, NULL,
				    ill_t *, out_ill,
				    ipha_t *, ipha, mblk_t *, mp);
				FW_HOOKS(ipst->ips_ip4_physical_out_event,
				    ipst->ips_ipv4firewall_physical_out,
				    NULL, out_ill, ipha, mp, mp, 0, ipst);
				DTRACE_PROBE1(ip4__physical__out__end,
				    mblk_t *, mp);
				if (mp == NULL)
					goto release_ire_and_ill_2;

				ASSERT(ipsec_len == 0);
				mp->b_prev =
				    SET_BPREV_FLAG(IPP_LOCAL_OUT);
				DTRACE_PROBE2(ip__xmit__2,
				    mblk_t *, mp, ire_t *, ire);
				pktxmit_state = ip_xmit_v4(mp, ire,
				    NULL, B_TRUE, connp);
				if ((pktxmit_state == SEND_FAILED) ||
				    (pktxmit_state == LLHDR_RESLV_FAILED)) {
release_ire_and_ill_2:
					if (next_mp) {
						freemsg(next_mp);
						ire_refrele(ire1);
					}
					ire_refrele(ire);
					TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
					    "ip_wput_ire_end: q %p (%S)",
					    q, "discard MDATA");
					if (conn_outgoing_ill != NULL)
						ill_refrele(conn_outgoing_ill);
					return;
				}

				if (CLASSD(dst)) {
					BUMP_MIB(out_ill->ill_ip_mib,
					    ipIfStatsHCOutMcastPkts);
					UPDATE_MIB(out_ill->ill_ip_mib,
					    ipIfStatsHCOutMcastOctets,
					    LENGTH);
				} else if (ire->ire_type == IRE_BROADCAST) {
					BUMP_MIB(out_ill->ill_ip_mib,
					    ipIfStatsHCOutBcastPkts);
				}

				if (multirt_send) {
					/*
					 * We are in a multiple send case,
					 * need to re-enter the sending loop
					 * using the next ire.
					 */
					ire_refrele(ire);
					ire = ire1;
					stq = ire->ire_stq;
					mp = next_mp;
					next_mp = NULL;
					ipha = (ipha_t *)mp->b_rptr;
					ill_index = Q_TO_INDEX(stq);
				}
			} while (multirt_send);

			if (!next_mp) {
				/*
				 * Last copy going out (the ultra-common
				 * case).  Note that we intentionally replicate
				 * the putnext rather than calling it before
				 * the next_mp check in hopes of a little
				 * tail-call action out of the compiler.
				 */
				TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
				    "ip_wput_ire_end: q %p (%S)",
				    q, "last copy out(1)");
				ire_refrele(ire);
				if (conn_outgoing_ill != NULL)
					ill_refrele(conn_outgoing_ill);
				return;
			}
			/* More copies going out below. */
		} else {
			int offset;
fragmentit:
			offset = ntohs(ipha->ipha_fragment_offset_and_flags);
			/*
			 * If this would generate a icmp_frag_needed message,
			 * we need to handle it before we do the IPsec
			 * processing. Otherwise, we need to strip the IPsec
			 * headers before we send up the message to the ULPs
			 * which becomes messy and difficult.
			 */
			if (ipsec_len != 0) {
				if ((max_frag < (unsigned int)(LENGTH +
				    ipsec_len)) && (offset & IPH_DF)) {
					out_ill = (ill_t *)stq->q_ptr;
					BUMP_MIB(out_ill->ill_ip_mib,
					    ipIfStatsOutFragFails);
					BUMP_MIB(out_ill->ill_ip_mib,
					    ipIfStatsOutFragReqds);
					ipha->ipha_hdr_checksum = 0;
					ipha->ipha_hdr_checksum =
					    (uint16_t)ip_csum_hdr(ipha);
					icmp_frag_needed(ire->ire_stq, first_mp,
					    max_frag, zoneid, ipst);
					if (!next_mp) {
						ire_refrele(ire);
						if (conn_outgoing_ill != NULL) {
							ill_refrele(
							    conn_outgoing_ill);
						}
						return;
					}
				} else {
					/*
					 * This won't cause a icmp_frag_needed
					 * message. to be generated. Send it on
					 * the wire. Note that this could still
					 * cause fragmentation and all we
					 * do is the generation of the message
					 * to the ULP if needed before IPsec.
					 */
					if (!next_mp) {
						ipsec_out_process(q, first_mp,
						    ire, ill_index);
						TRACE_2(TR_FAC_IP,
						    TR_IP_WPUT_IRE_END,
						    "ip_wput_ire_end: q %p "
						    "(%S)", q,
						    "last ipsec_out_process");
						ire_refrele(ire);
						if (conn_outgoing_ill != NULL) {
							ill_refrele(
							    conn_outgoing_ill);
						}
						return;
					}
					ipsec_out_process(q, first_mp,
					    ire, ill_index);
				}
			} else {
				/*
				 * Initiate IPPF processing. For
				 * fragmentable packets we finish
				 * all QOS packet processing before
				 * calling:
				 * ip_wput_ire_fragmentit->ip_wput_frag
				 */

				if (IPP_ENABLED(IPP_LOCAL_OUT, ipst)) {
					ip_process(IPP_LOCAL_OUT, &mp,
					    ill_index);
					if (mp == NULL) {
						out_ill = (ill_t *)stq->q_ptr;
						BUMP_MIB(out_ill->ill_ip_mib,
						    ipIfStatsOutDiscards);
						if (next_mp != NULL) {
							freemsg(next_mp);
							ire_refrele(ire1);
						}
						ire_refrele(ire);
						TRACE_2(TR_FAC_IP,
						    TR_IP_WPUT_IRE_END,
						    "ip_wput_ire: q %p (%S)",
						    q, "discard MDATA");
						if (conn_outgoing_ill != NULL) {
							ill_refrele(
							    conn_outgoing_ill);
						}
						return;
					}
				}
				if (!next_mp) {
					TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
					    "ip_wput_ire_end: q %p (%S)",
					    q, "last fragmentation");
					ip_wput_ire_fragmentit(mp, ire,
					    zoneid, ipst, connp);
					ire_refrele(ire);
					if (conn_outgoing_ill != NULL)
						ill_refrele(conn_outgoing_ill);
					return;
				}
				ip_wput_ire_fragmentit(mp, ire,
				    zoneid, ipst, connp);
			}
		}
	} else {
nullstq:
		/* A NULL stq means the destination address is local. */
		UPDATE_OB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
		ASSERT(ire->ire_ipif != NULL);
		if (!next_mp) {
			/*
			 * Is there an "in" and "out" for traffic local
			 * to a host (loopback)?  The code in Solaris doesn't
			 * explicitly draw a line in its code for in vs out,
			 * so we've had to draw a line in the sand: ip_wput_ire
			 * is considered to be the "output" side and
			 * ip_wput_local to be the "input" side.
			 */
			out_ill = ire_to_ill(ire);

			/*
			 * DTrace this as ip:::send.  A blocked packet will
			 * fire the send probe, but not the receive probe.
			 */
			DTRACE_IP7(send, mblk_t *, first_mp, conn_t *, NULL,
			    void_ip_t *, ipha, __dtrace_ipsr_ill_t *, out_ill,
			    ipha_t *, ipha, ip6_t *, NULL, int, 1);

			DTRACE_PROBE4(ip4__loopback__out__start,
			    ill_t *, NULL, ill_t *, out_ill,
			    ipha_t *, ipha, mblk_t *, first_mp);

			FW_HOOKS(ipst->ips_ip4_loopback_out_event,
			    ipst->ips_ipv4firewall_loopback_out,
			    NULL, out_ill, ipha, first_mp, mp, 0, ipst);

			DTRACE_PROBE1(ip4__loopback__out_end,
			    mblk_t *, first_mp);

			TRACE_2(TR_FAC_IP, TR_IP_WPUT_IRE_END,
			    "ip_wput_ire_end: q %p (%S)",
			    q, "local address");

			if (first_mp != NULL)
				ip_wput_local(q, out_ill, ipha,
				    first_mp, ire, 0, ire->ire_zoneid);
			ire_refrele(ire);
			if (conn_outgoing_ill != NULL)
				ill_refrele(conn_outgoing_ill);
			return;
		}

		out_ill = ire_to_ill(ire);

		/*
		 * DTrace this as ip:::send.  A blocked packet will fire the
		 * send probe, but not the receive probe.
		 */
		DTRACE_IP7(send, mblk_t *, first_mp, conn_t *, NULL,
		    void_ip_t *, ipha, __dtrace_ipsr_ill_t *, out_ill,
		    ipha_t *, ipha, ip6_t *, NULL, int, 1);

		DTRACE_PROBE4(ip4__loopback__out__start,
		    ill_t *, NULL, ill_t *, out_ill,
		    ipha_t *, ipha, mblk_t *, first_mp);

		FW_HOOKS(ipst->ips_ip4_loopback_out_event,
		    ipst->ips_ipv4firewall_loopback_out,
		    NULL, out_ill, ipha, first_mp, mp, 0, ipst);

		DTRACE_PROBE1(ip4__loopback__out__end, mblk_t *, first_mp);

		if (first_mp != NULL)
			ip_wput_local(q, out_ill, ipha,
			    first_mp, ire, 0, ire->ire_zoneid);
	}
next:
	/*
	 * More copies going out to additional interfaces.
	 * ire1 has already been held. We don't need the
	 * "ire" anymore.
	 */
	ire_refrele(ire);
	ire = ire1;
	ASSERT(ire != NULL && ire->ire_refcnt >= 1 && next_mp != NULL);
	mp = next_mp;
	ASSERT(ire->ire_ipversion == IPV4_VERSION);
	ill = ire_to_ill(ire);
	first_mp = mp;
	if (ipsec_len != 0) {
		ASSERT(first_mp->b_datap->db_type == M_CTL);
		mp = mp->b_cont;
	}
	dst = ire->ire_addr;
	ipha = (ipha_t *)mp->b_rptr;
	/*
	 * Restore src so that we will pick up ire->ire_src_addr if src was 0.
	 * Restore ipha_ident "no checksum" flag.
	 */
	src = orig_src;
	ipha->ipha_ident = ip_hdr_included;
	goto another;

#undef	rptr
#undef	Q_TO_INDEX
}

/*
 * Routine to allocate a message that is used to notify the ULP about MDT.
 * The caller may provide a pointer to the link-layer MDT capabilities,
 * or NULL if MDT is to be disabled on the stream.
 */
mblk_t *
ip_mdinfo_alloc(ill_mdt_capab_t *isrc)
{
	mblk_t *mp;
	ip_mdt_info_t *mdti;
	ill_mdt_capab_t *idst;

	if ((mp = allocb(sizeof (*mdti), BPRI_HI)) != NULL) {
		DB_TYPE(mp) = M_CTL;
		mp->b_wptr = mp->b_rptr + sizeof (*mdti);
		mdti = (ip_mdt_info_t *)mp->b_rptr;
		mdti->mdt_info_id = MDT_IOC_INFO_UPDATE;
		idst = &(mdti->mdt_capab);

		/*
		 * If the caller provides us with the capability, copy
		 * it over into our notification message; otherwise
		 * we zero out the capability portion.
		 */
		if (isrc != NULL)
			bcopy((caddr_t)isrc, (caddr_t)idst, sizeof (*idst));
		else
			bzero((caddr_t)idst, sizeof (*idst));
	}
	return (mp);
}

/*
 * Routine which determines whether MDT can be enabled on the destination
 * IRE and IPC combination, and if so, allocates and returns the MDT
 * notification mblk that may be used by ULP.  We also check if we need to
 * turn MDT back to 'on' when certain restrictions prohibiting us to allow
 * MDT usage in the past have been lifted.  This gets called during IP
 * and ULP binding.
 */
mblk_t *
ip_mdinfo_return(ire_t *dst_ire, conn_t *connp, char *ill_name,
    ill_mdt_capab_t *mdt_cap)
{
	mblk_t *mp;
	boolean_t rc = B_FALSE;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	ASSERT(dst_ire != NULL);
	ASSERT(connp != NULL);
	ASSERT(mdt_cap != NULL);

	/*
	 * Currently, we only support simple TCP/{IPv4,IPv6} with
	 * Multidata, which is handled in tcp_multisend().  This
	 * is the reason why we do all these checks here, to ensure
	 * that we don't enable Multidata for the cases which we
	 * can't handle at the moment.
	 */
	do {
		/* Only do TCP at the moment */
		if (connp->conn_ulp != IPPROTO_TCP)
			break;

		/*
		 * IPsec outbound policy present?  Note that we get here
		 * after calling ipsec_conn_cache_policy() where the global
		 * policy checking is performed.  conn_latch will be
		 * non-NULL as long as there's a policy defined,
		 * i.e. conn_out_enforce_policy may be NULL in such case
		 * when the connection is non-secure, and hence we check
		 * further if the latch refers to an outbound policy.
		 */
		if (CONN_IPSEC_OUT_ENCAPSULATED(connp))
			break;

		/* CGTP (multiroute) is enabled? */
		if (dst_ire->ire_flags & RTF_MULTIRT)
			break;

		/* Outbound IPQoS enabled? */
		if (IPP_ENABLED(IPP_LOCAL_OUT, ipst)) {
			/*
			 * In this case, we disable MDT for this and all
			 * future connections going over the interface.
			 */
			mdt_cap->ill_mdt_on = 0;
			break;
		}

		/* socket option(s) present? */
		if (!CONN_IS_LSO_MD_FASTPATH(connp))
			break;

		rc = B_TRUE;
	/* CONSTCOND */
	} while (0);

	/* Remember the result */
	connp->conn_mdt_ok = rc;

	if (!rc)
		return (NULL);
	else if (!mdt_cap->ill_mdt_on) {
		/*
		 * If MDT has been previously turned off in the past, and we
		 * currently can do MDT (due to IPQoS policy removal, etc.)
		 * then enable it for this interface.
		 */
		mdt_cap->ill_mdt_on = 1;
		ip1dbg(("ip_mdinfo_return: reenabling MDT for "
		    "interface %s\n", ill_name));
	}

	/* Allocate the MDT info mblk */
	if ((mp = ip_mdinfo_alloc(mdt_cap)) == NULL) {
		ip0dbg(("ip_mdinfo_return: can't enable Multidata for "
		    "conn %p on %s (ENOMEM)\n", (void *)connp, ill_name));
		return (NULL);
	}
	return (mp);
}

/*
 * Routine to allocate a message that is used to notify the ULP about LSO.
 * The caller may provide a pointer to the link-layer LSO capabilities,
 * or NULL if LSO is to be disabled on the stream.
 */
mblk_t *
ip_lsoinfo_alloc(ill_lso_capab_t *isrc)
{
	mblk_t *mp;
	ip_lso_info_t *lsoi;
	ill_lso_capab_t *idst;

	if ((mp = allocb(sizeof (*lsoi), BPRI_HI)) != NULL) {
		DB_TYPE(mp) = M_CTL;
		mp->b_wptr = mp->b_rptr + sizeof (*lsoi);
		lsoi = (ip_lso_info_t *)mp->b_rptr;
		lsoi->lso_info_id = LSO_IOC_INFO_UPDATE;
		idst = &(lsoi->lso_capab);

		/*
		 * If the caller provides us with the capability, copy
		 * it over into our notification message; otherwise
		 * we zero out the capability portion.
		 */
		if (isrc != NULL)
			bcopy((caddr_t)isrc, (caddr_t)idst, sizeof (*idst));
		else
			bzero((caddr_t)idst, sizeof (*idst));
	}
	return (mp);
}

/*
 * Routine which determines whether LSO can be enabled on the destination
 * IRE and IPC combination, and if so, allocates and returns the LSO
 * notification mblk that may be used by ULP.  We also check if we need to
 * turn LSO back to 'on' when certain restrictions prohibiting us to allow
 * LSO usage in the past have been lifted.  This gets called during IP
 * and ULP binding.
 */
mblk_t *
ip_lsoinfo_return(ire_t *dst_ire, conn_t *connp, char *ill_name,
    ill_lso_capab_t *lso_cap)
{
	mblk_t *mp;
	ip_stack_t *ipst = connp->conn_netstack->netstack_ip;

	ASSERT(dst_ire != NULL);
	ASSERT(connp != NULL);
	ASSERT(lso_cap != NULL);

	connp->conn_lso_ok = B_TRUE;

	if ((connp->conn_ulp != IPPROTO_TCP) ||
	    CONN_IPSEC_OUT_ENCAPSULATED(connp) ||
	    (dst_ire->ire_flags & RTF_MULTIRT) ||
	    !CONN_IS_LSO_MD_FASTPATH(connp) ||
	    (IPP_ENABLED(IPP_LOCAL_OUT, ipst))) {
		connp->conn_lso_ok = B_FALSE;
		if (IPP_ENABLED(IPP_LOCAL_OUT, ipst)) {
			/*
			 * Disable LSO for this and all future connections going
			 * over the interface.
			 */
			lso_cap->ill_lso_on = 0;
		}
	}

	if (!connp->conn_lso_ok)
		return (NULL);
	else if (!lso_cap->ill_lso_on) {
		/*
		 * If LSO has been previously turned off in the past, and we
		 * currently can do LSO (due to IPQoS policy removal, etc.)
		 * then enable it for this interface.
		 */
		lso_cap->ill_lso_on = 1;
		ip1dbg(("ip_mdinfo_return: reenabling LSO for interface %s\n",
		    ill_name));
	}

	/* Allocate the LSO info mblk */
	if ((mp = ip_lsoinfo_alloc(lso_cap)) == NULL)
		ip0dbg(("ip_lsoinfo_return: can't enable LSO for "
		    "conn %p on %s (ENOMEM)\n", (void *)connp, ill_name));

	return (mp);
}

/*
 * Create destination address attribute, and fill it with the physical
 * destination address and SAP taken from the template DL_UNITDATA_REQ
 * message block.
 */
boolean_t
ip_md_addr_attr(multidata_t *mmd, pdesc_t *pd, const mblk_t *dlmp)
{
	dl_unitdata_req_t *dlurp;
	pattr_t *pa;
	pattrinfo_t pa_info;
	pattr_addr_t **das = (pattr_addr_t **)&pa_info.buf;
	uint_t das_len, das_off;

	ASSERT(dlmp != NULL);

	dlurp = (dl_unitdata_req_t *)dlmp->b_rptr;
	das_len = dlurp->dl_dest_addr_length;
	das_off = dlurp->dl_dest_addr_offset;

	pa_info.type = PATTR_DSTADDRSAP;
	pa_info.len = sizeof (**das) + das_len - 1;

	/* create and associate the attribute */
	pa = mmd_addpattr(mmd, pd, &pa_info, B_TRUE, KM_NOSLEEP);
	if (pa != NULL) {
		ASSERT(*das != NULL);
		(*das)->addr_is_group = 0;
		(*das)->addr_len = (uint8_t)das_len;
		bcopy((caddr_t)dlurp + das_off, (*das)->addr, das_len);
	}

	return (pa != NULL);
}

/*
 * Create hardware checksum attribute and fill it with the values passed.
 */
boolean_t
ip_md_hcksum_attr(multidata_t *mmd, pdesc_t *pd, uint32_t start_offset,
    uint32_t stuff_offset, uint32_t end_offset, uint32_t flags)
{
	pattr_t *pa;
	pattrinfo_t pa_info;

	ASSERT(mmd != NULL);

	pa_info.type = PATTR_HCKSUM;
	pa_info.len = sizeof (pattr_hcksum_t);

	/* create and associate the attribute */
	pa = mmd_addpattr(mmd, pd, &pa_info, B_TRUE, KM_NOSLEEP);
	if (pa != NULL) {
		pattr_hcksum_t *hck = (pattr_hcksum_t *)pa_info.buf;

		hck->hcksum_start_offset = start_offset;
		hck->hcksum_stuff_offset = stuff_offset;
		hck->hcksum_end_offset = end_offset;
		hck->hcksum_flags = flags;
	}
	return (pa != NULL);
}

/*
 * Create zerocopy attribute and fill it with the specified flags
 */
boolean_t
ip_md_zcopy_attr(multidata_t *mmd, pdesc_t *pd, uint_t flags)
{
	pattr_t *pa;
	pattrinfo_t pa_info;

	ASSERT(mmd != NULL);
	pa_info.type = PATTR_ZCOPY;
	pa_info.len = sizeof (pattr_zcopy_t);

	/* create and associate the attribute */
	pa = mmd_addpattr(mmd, pd, &pa_info, B_TRUE, KM_NOSLEEP);
	if (pa != NULL) {
		pattr_zcopy_t *zcopy = (pattr_zcopy_t *)pa_info.buf;

		zcopy->zcopy_flags = flags;
	}
	return (pa != NULL);
}

/*
 * Check if ip_wput_frag_mdt() and ip_wput_frag_mdt_v6() can handle a message
 * block chain. We could rewrite to handle arbitrary message block chains but
 * that would make the code complicated and slow. Right now there three
 * restrictions:
 *
 *   1. The first message block must contain the complete IP header and
 *	at least 1 byte of payload data.
 *   2. At most MULTIDATA_MAX_PBUFS non-empty message blocks are allowed
 *	so that we can use a single Multidata message.
 *   3. No frag must be distributed over two or more message blocks so
 *	that we don't need more than two packet descriptors per frag.
 *
 * The above restrictions allow us to support userland applications (which
 * will send down a single message block) and NFS over UDP (which will
 * send down a chain of at most three message blocks).
 *
 * We also don't use MDT for payloads with less than or equal to
 * ip_wput_frag_mdt_min bytes because it would cause too much overhead.
 */
boolean_t
ip_can_frag_mdt(mblk_t *mp, ssize_t hdr_len, ssize_t len)
{
	int	blocks;
	ssize_t	total, missing, size;

	ASSERT(mp != NULL);
	ASSERT(hdr_len > 0);

	size = MBLKL(mp) - hdr_len;
	if (size <= 0)
		return (B_FALSE);

	/* The first mblk contains the header and some payload. */
	blocks = 1;
	total = size;
	size %= len;
	missing = (size == 0) ? 0 : (len - size);
	mp = mp->b_cont;

	while (mp != NULL) {
		/*
		 * Give up if we encounter a zero length message block.
		 * In practice, this should rarely happen and therefore
		 * not worth the trouble of freeing and re-linking the
		 * mblk from the chain to handle such case.
		 */
		if ((size = MBLKL(mp)) == 0)
			return (B_FALSE);

		/* Too many payload buffers for a single Multidata message? */
		if (++blocks > MULTIDATA_MAX_PBUFS)
			return (B_FALSE);

		total += size;
		/* Is a frag distributed over two or more message blocks? */
		if (missing > size)
			return (B_FALSE);
		size -= missing;

		size %= len;
		missing = (size == 0) ? 0 : (len - size);

		mp = mp->b_cont;
	}

	return (total > ip_wput_frag_mdt_min);
}

/*
 * Outbound IPv4 fragmentation routine using MDT.
 */
static void
ip_wput_frag_mdt(ire_t *ire, mblk_t *mp, ip_pkt_t pkt_type, int len,
    uint32_t frag_flag, int offset)
{
	ipha_t		*ipha_orig;
	int		i1, ip_data_end;
	uint_t		pkts, wroff, hdr_chunk_len, pbuf_idx;
	mblk_t		*hdr_mp, *md_mp = NULL;
	unsigned char	*hdr_ptr, *pld_ptr;
	multidata_t	*mmd;
	ip_pdescinfo_t	pdi;
	ill_t		*ill;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(MBLKL(mp) > sizeof (ipha_t));

	ill = ire_to_ill(ire);
	ASSERT(ill != NULL);

	ipha_orig = (ipha_t *)mp->b_rptr;
	mp->b_rptr += sizeof (ipha_t);

	/* Calculate how many packets we will send out */
	i1 = (mp->b_cont == NULL) ? MBLKL(mp) : msgsize(mp);
	pkts = (i1 + len - 1) / len;
	ASSERT(pkts > 1);

	/* Allocate a message block which will hold all the IP Headers. */
	wroff = ipst->ips_ip_wroff_extra;
	hdr_chunk_len = wroff + IP_SIMPLE_HDR_LENGTH;

	i1 = pkts * hdr_chunk_len;
	/*
	 * Create the header buffer, Multidata and destination address
	 * and SAP attribute that should be associated with it.
	 */
	if ((hdr_mp = allocb(i1, BPRI_HI)) == NULL ||
	    ((hdr_mp->b_wptr += i1),
	    (mmd = mmd_alloc(hdr_mp, &md_mp, KM_NOSLEEP)) == NULL) ||
	    !ip_md_addr_attr(mmd, NULL, ire->ire_nce->nce_res_mp)) {
		freemsg(mp);
		if (md_mp == NULL) {
			freemsg(hdr_mp);
		} else {
free_mmd:		IP_STAT(ipst, ip_frag_mdt_discarded);
			freemsg(md_mp);
		}
		IP_STAT(ipst, ip_frag_mdt_allocfail);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		return;
	}
	IP_STAT(ipst, ip_frag_mdt_allocd);

	/*
	 * Add a payload buffer to the Multidata; this operation must not
	 * fail, or otherwise our logic in this routine is broken.  There
	 * is no memory allocation done by the routine, so any returned
	 * failure simply tells us that we've done something wrong.
	 *
	 * A failure tells us that either we're adding the same payload
	 * buffer more than once, or we're trying to add more buffers than
	 * allowed.  None of the above cases should happen, and we panic
	 * because either there's horrible heap corruption, and/or
	 * programming mistake.
	 */
	if ((pbuf_idx = mmd_addpldbuf(mmd, mp)) < 0)
		goto pbuf_panic;

	hdr_ptr = hdr_mp->b_rptr;
	pld_ptr = mp->b_rptr;

	/* Establish the ending byte offset, based on the starting offset. */
	offset <<= 3;
	ip_data_end = offset + ntohs(ipha_orig->ipha_length) -
	    IP_SIMPLE_HDR_LENGTH;

	pdi.flags = PDESC_HBUF_REF | PDESC_PBUF_REF;

	while (pld_ptr < mp->b_wptr) {
		ipha_t		*ipha;
		uint16_t	offset_and_flags;
		uint16_t	ip_len;
		int		error;

		ASSERT((hdr_ptr + hdr_chunk_len) <= hdr_mp->b_wptr);
		ipha = (ipha_t *)(hdr_ptr + wroff);
		ASSERT(OK_32PTR(ipha));
		*ipha = *ipha_orig;

		if (ip_data_end - offset > len) {
			offset_and_flags = IPH_MF;
		} else {
			/*
			 * Last frag. Set len to the length of this last piece.
			 */
			len = ip_data_end - offset;
			/* A frag of a frag might have IPH_MF non-zero */
			offset_and_flags =
			    ntohs(ipha->ipha_fragment_offset_and_flags) &
			    IPH_MF;
		}
		offset_and_flags |= (uint16_t)(offset >> 3);
		offset_and_flags |= (uint16_t)frag_flag;
		/* Store the offset and flags in the IP header. */
		ipha->ipha_fragment_offset_and_flags = htons(offset_and_flags);

		/* Store the length in the IP header. */
		ip_len = (uint16_t)(len + IP_SIMPLE_HDR_LENGTH);
		ipha->ipha_length = htons(ip_len);

		/*
		 * Set the IP header checksum.  Note that mp is just
		 * the header, so this is easy to pass to ip_csum.
		 */
		ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

		DTRACE_IP7(send, mblk_t *, md_mp, conn_t *, NULL, void_ip_t *,
		    ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha, ip6_t *,
		    NULL, int, 0);

		/*
		 * Record offset and size of header and data of the next packet
		 * in the multidata message.
		 */
		PDESC_HDR_ADD(&pdi, hdr_ptr, wroff, IP_SIMPLE_HDR_LENGTH, 0);
		PDESC_PLD_INIT(&pdi);
		i1 = MIN(mp->b_wptr - pld_ptr, len);
		ASSERT(i1 > 0);
		PDESC_PLD_SPAN_ADD(&pdi, pbuf_idx, pld_ptr, i1);
		if (i1 == len) {
			pld_ptr += len;
		} else {
			i1 = len - i1;
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			ASSERT(MBLKL(mp) >= i1);
			/*
			 * Attach the next payload message block to the
			 * multidata message.
			 */
			if ((pbuf_idx = mmd_addpldbuf(mmd, mp)) < 0)
				goto pbuf_panic;
			PDESC_PLD_SPAN_ADD(&pdi, pbuf_idx, mp->b_rptr, i1);
			pld_ptr = mp->b_rptr + i1;
		}

		if ((mmd_addpdesc(mmd, (pdescinfo_t *)&pdi, &error,
		    KM_NOSLEEP)) == NULL) {
			/*
			 * Any failure other than ENOMEM indicates that we
			 * have passed in invalid pdesc info or parameters
			 * to mmd_addpdesc, which must not happen.
			 *
			 * EINVAL is a result of failure on boundary checks
			 * against the pdesc info contents.  It should not
			 * happen, and we panic because either there's
			 * horrible heap corruption, and/or programming
			 * mistake.
			 */
			if (error != ENOMEM) {
				cmn_err(CE_PANIC, "ip_wput_frag_mdt: "
				    "pdesc logic error detected for "
				    "mmd %p pinfo %p (%d)\n",
				    (void *)mmd, (void *)&pdi, error);
				/* NOTREACHED */
			}
			IP_STAT(ipst, ip_frag_mdt_addpdescfail);
			/* Free unattached payload message blocks as well */
			md_mp->b_cont = mp->b_cont;
			goto free_mmd;
		}

		/* Advance fragment offset. */
		offset += len;

		/* Advance to location for next header in the buffer. */
		hdr_ptr += hdr_chunk_len;

		/* Did we reach the next payload message block? */
		if (pld_ptr == mp->b_wptr && mp->b_cont != NULL) {
			mp = mp->b_cont;
			/*
			 * Attach the next message block with payload
			 * data to the multidata message.
			 */
			if ((pbuf_idx = mmd_addpldbuf(mmd, mp)) < 0)
				goto pbuf_panic;
			pld_ptr = mp->b_rptr;
		}
	}

	ASSERT(hdr_mp->b_wptr == hdr_ptr);
	ASSERT(mp->b_wptr == pld_ptr);

	/* Update IP statistics */
	IP_STAT_UPDATE(ipst, ip_frag_mdt_pkt_out, pkts);

	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsOutFragCreates, pkts);
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragOKs);

	len = ntohs(ipha_orig->ipha_length) + (pkts - 1) * IP_SIMPLE_HDR_LENGTH;
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutTransmits, pkts);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutOctets, len);

	if (pkt_type == OB_PKT) {
		ire->ire_ob_pkt_count += pkts;
		if (ire->ire_ipif != NULL)
			atomic_add_32(&ire->ire_ipif->ipif_ob_pkt_count, pkts);
	} else {
		/* The type is IB_PKT in the forwarding path. */
		ire->ire_ib_pkt_count += pkts;
		ASSERT(!IRE_IS_LOCAL(ire));
		if (ire->ire_type & IRE_BROADCAST) {
			atomic_add_32(&ire->ire_ipif->ipif_ib_pkt_count, pkts);
		} else {
			UPDATE_MIB(ill->ill_ip_mib,
			    ipIfStatsHCOutForwDatagrams, pkts);
			atomic_add_32(&ire->ire_ipif->ipif_fo_pkt_count, pkts);
		}
	}
	ire->ire_last_used_time = lbolt;
	/* Send it down */
	putnext(ire->ire_stq, md_mp);
	return;

pbuf_panic:
	cmn_err(CE_PANIC, "ip_wput_frag_mdt: payload buffer logic "
	    "error for mmd %p pbuf %p (%d)", (void *)mmd, (void *)mp,
	    pbuf_idx);
	/* NOTREACHED */
}

/*
 * Outbound IP fragmentation routine.
 *
 * NOTE : This routine does not ire_refrele the ire that is passed in
 * as the argument.
 */
static void
ip_wput_frag(ire_t *ire, mblk_t *mp_orig, ip_pkt_t pkt_type, uint32_t max_frag,
    uint32_t frag_flag, zoneid_t zoneid, ip_stack_t *ipst, conn_t *connp)
{
	int		i1;
	mblk_t		*ll_hdr_mp;
	int 		ll_hdr_len;
	int		hdr_len;
	mblk_t		*hdr_mp;
	ipha_t		*ipha;
	int		ip_data_end;
	int		len;
	mblk_t		*mp = mp_orig, *mp1;
	int		offset;
	queue_t		*q;
	uint32_t	v_hlen_tos_len;
	mblk_t		*first_mp;
	boolean_t	mctl_present;
	ill_t		*ill;
	ill_t		*out_ill;
	mblk_t		*xmit_mp;
	mblk_t		*carve_mp;
	ire_t		*ire1 = NULL;
	ire_t		*save_ire = NULL;
	mblk_t  	*next_mp = NULL;
	boolean_t	last_frag = B_FALSE;
	boolean_t	multirt_send = B_FALSE;
	ire_t		*first_ire = NULL;
	irb_t		*irb = NULL;
	mib2_ipIfStatsEntry_t *mibptr = NULL;

	ill = ire_to_ill(ire);
	mibptr = (ill != NULL) ? ill->ill_ip_mib : &ipst->ips_ip_mib;

	BUMP_MIB(mibptr, ipIfStatsOutFragReqds);

	if (max_frag == 0) {
		ip1dbg(("ip_wput_frag: ire frag size is 0"
		    " -  dropping packet\n"));
		BUMP_MIB(mibptr, ipIfStatsOutFragFails);
		freemsg(mp);
		return;
	}

	/*
	 * IPsec does not allow hw accelerated packets to be fragmented
	 * This check is made in ip_wput_ipsec_out prior to coming here
	 * via ip_wput_ire_fragmentit.
	 *
	 * If at this point we have an ire whose ARP request has not
	 * been sent out, we call ip_xmit_v4->ire_arpresolve to trigger
	 * sending of ARP query and change ire's state to ND_INCOMPLETE.
	 * This packet and all fragmentable packets for this ire will
	 * continue to get dropped while ire_nce->nce_state remains in
	 * ND_INCOMPLETE. Post-ARP resolution, after ire's nce_state changes to
	 * ND_REACHABLE, all subsquent large packets for this ire will
	 * get fragemented and sent out by this function.
	 */
	if (ire->ire_nce && ire->ire_nce->nce_state != ND_REACHABLE) {
		/* If nce_state is ND_INITIAL, trigger ARP query */
		(void) ip_xmit_v4(NULL, ire, NULL, B_FALSE, NULL);
		ip1dbg(("ip_wput_frag: mac address for ire is unresolved"
		    " -  dropping packet\n"));
		BUMP_MIB(mibptr, ipIfStatsOutFragFails);
		freemsg(mp);
		return;
	}

	TRACE_0(TR_FAC_IP, TR_IP_WPUT_FRAG_START,
	    "ip_wput_frag_start:");

	if (mp->b_datap->db_type == M_CTL) {
		first_mp = mp;
		mp_orig = mp = mp->b_cont;
		mctl_present = B_TRUE;
	} else {
		first_mp = mp;
		mctl_present = B_FALSE;
	}

	ASSERT(MBLKL(mp) >= sizeof (ipha_t));
	ipha = (ipha_t *)mp->b_rptr;

	/*
	 * If the Don't Fragment flag is on, generate an ICMP destination
	 * unreachable, fragmentation needed.
	 */
	offset = ntohs(ipha->ipha_fragment_offset_and_flags);
	if (offset & IPH_DF) {
		BUMP_MIB(mibptr, ipIfStatsOutFragFails);
		if (is_system_labeled()) {
			max_frag = tsol_pmtu_adjust(mp, ire->ire_max_frag,
			    ire->ire_max_frag - max_frag, AF_INET);
		}
		/*
		 * Need to compute hdr checksum if called from ip_wput_ire.
		 * Note that ip_rput_forward verifies the checksum before
		 * calling this routine so in that case this is a noop.
		 */
		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
		icmp_frag_needed(ire->ire_stq, first_mp, max_frag, zoneid,
		    ipst);
		TRACE_1(TR_FAC_IP, TR_IP_WPUT_FRAG_END,
		    "ip_wput_frag_end:(%S)",
		    "don't fragment");
		return;
	}
	/*
	 * Labeled systems adjust max_frag if they add a label
	 * to send the correct path mtu.  We need the real mtu since we
	 * are fragmenting the packet after label adjustment.
	 */
	if (is_system_labeled())
		max_frag = ire->ire_max_frag;
	if (mctl_present)
		freeb(first_mp);
	/*
	 * Establish the starting offset.  May not be zero if we are fragging
	 * a fragment that is being forwarded.
	 */
	offset = offset & IPH_OFFSET;

	/* TODO why is this test needed? */
	v_hlen_tos_len = ((uint32_t *)ipha)[0];
	if (((max_frag - LENGTH) & ~7) < 8) {
		/* TODO: notify ulp somehow */
		BUMP_MIB(mibptr, ipIfStatsOutFragFails);
		freemsg(mp);
		TRACE_1(TR_FAC_IP, TR_IP_WPUT_FRAG_END,
		    "ip_wput_frag_end:(%S)",
		    "len < 8");
		return;
	}

	hdr_len = (V_HLEN & 0xF) << 2;

	ipha->ipha_hdr_checksum = 0;

	/*
	 * Establish the number of bytes maximum per frag, after putting
	 * in the header.
	 */
	len = (max_frag - hdr_len) & ~7;

	/* Check if we can use MDT to send out the frags. */
	ASSERT(!IRE_IS_LOCAL(ire));
	if (hdr_len == IP_SIMPLE_HDR_LENGTH &&
	    ipst->ips_ip_multidata_outbound &&
	    !(ire->ire_flags & RTF_MULTIRT) &&
	    !IPP_ENABLED(IPP_LOCAL_OUT, ipst) &&
	    ill != NULL && ILL_MDT_CAPABLE(ill) &&
	    IP_CAN_FRAG_MDT(mp, IP_SIMPLE_HDR_LENGTH, len)) {
		ASSERT(ill->ill_mdt_capab != NULL);
		if (!ill->ill_mdt_capab->ill_mdt_on) {
			/*
			 * If MDT has been previously turned off in the past,
			 * and we currently can do MDT (due to IPQoS policy
			 * removal, etc.) then enable it for this interface.
			 */
			ill->ill_mdt_capab->ill_mdt_on = 1;
			ip1dbg(("ip_wput_frag: enabled MDT for interface %s\n",
			    ill->ill_name));
		}
		ip_wput_frag_mdt(ire, mp, pkt_type, len, frag_flag,
		    offset);
		return;
	}

	/* Get a copy of the header for the trailing frags */
	hdr_mp = ip_wput_frag_copyhdr((uchar_t *)ipha, hdr_len, offset, ipst);
	if (!hdr_mp) {
		BUMP_MIB(mibptr, ipIfStatsOutFragFails);
		freemsg(mp);
		TRACE_1(TR_FAC_IP, TR_IP_WPUT_FRAG_END,
		    "ip_wput_frag_end:(%S)",
		    "couldn't copy hdr");
		return;
	}
	if (DB_CRED(mp) != NULL)
		mblk_setcred(hdr_mp, DB_CRED(mp));

	/* Store the starting offset, with the MoreFrags flag. */
	i1 = offset | IPH_MF | frag_flag;
	ipha->ipha_fragment_offset_and_flags = htons((uint16_t)i1);

	/* Establish the ending byte offset, based on the starting offset. */
	offset <<= 3;
	ip_data_end = offset + ntohs(ipha->ipha_length) - hdr_len;

	/* Store the length of the first fragment in the IP header. */
	i1 = len + hdr_len;
	ASSERT(i1 <= IP_MAXPACKET);
	ipha->ipha_length = htons((uint16_t)i1);

	/*
	 * Compute the IP header checksum for the first frag.  We have to
	 * watch out that we stop at the end of the header.
	 */
	ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

	/*
	 * Now carve off the first frag.  Note that this will include the
	 * original IP header.
	 */
	if (!(mp = ip_carve_mp(&mp_orig, i1))) {
		BUMP_MIB(mibptr, ipIfStatsOutFragFails);
		freeb(hdr_mp);
		freemsg(mp_orig);
		TRACE_1(TR_FAC_IP, TR_IP_WPUT_FRAG_END,
		    "ip_wput_frag_end:(%S)",
		    "couldn't carve first");
		return;
	}

	/*
	 * Multirouting case. Each fragment is replicated
	 * via all non-condemned RTF_MULTIRT routes
	 * currently resolved.
	 * We ensure that first_ire is the first RTF_MULTIRT
	 * ire in the bucket.
	 */
	if (ire->ire_flags & RTF_MULTIRT) {
		irb = ire->ire_bucket;
		ASSERT(irb != NULL);

		multirt_send = B_TRUE;

		/* Make sure we do not omit any multiroute ire. */
		IRB_REFHOLD(irb);
		for (first_ire = irb->irb_ire;
		    first_ire != NULL;
		    first_ire = first_ire->ire_next) {
			if ((first_ire->ire_flags & RTF_MULTIRT) &&
			    (first_ire->ire_addr == ire->ire_addr) &&
			    !(first_ire->ire_marks &
			    (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN))) {
				break;
			}
		}

		if (first_ire != NULL) {
			if (first_ire != ire) {
				IRE_REFHOLD(first_ire);
				/*
				 * Do not release the ire passed in
				 * as the argument.
				 */
				ire = first_ire;
			} else {
				first_ire = NULL;
			}
		}
		IRB_REFRELE(irb);

		/*
		 * Save the first ire; we will need to restore it
		 * for the trailing frags.
		 * We REFHOLD save_ire, as each iterated ire will be
		 * REFRELEd.
		 */
		save_ire = ire;
		IRE_REFHOLD(save_ire);
	}

	/*
	 * First fragment emission loop.
	 * In most cases, the emission loop below is entered only
	 * once. Only in the case where the ire holds the RTF_MULTIRT
	 * flag, do we loop to process all RTF_MULTIRT ires in the
	 * bucket, and send the fragment through all crossed
	 * RTF_MULTIRT routes.
	 */
	do {
		if (ire->ire_flags & RTF_MULTIRT) {
			/*
			 * We are in a multiple send case, need to get
			 * the next ire and make a copy of the packet.
			 * ire1 holds here the next ire to process in the
			 * bucket. If multirouting is expected,
			 * any non-RTF_MULTIRT ire that has the
			 * right destination address is ignored.
			 *
			 * We have to take into account the MTU of
			 * each walked ire. max_frag is set by the
			 * the caller and generally refers to
			 * the primary ire entry. Here we ensure that
			 * no route with a lower MTU will be used, as
			 * fragments are carved once for all ires,
			 * then replicated.
			 */
			ASSERT(irb != NULL);
			IRB_REFHOLD(irb);
			for (ire1 = ire->ire_next;
			    ire1 != NULL;
			    ire1 = ire1->ire_next) {
				if ((ire1->ire_flags & RTF_MULTIRT) == 0)
					continue;
				if (ire1->ire_addr != ire->ire_addr)
					continue;
				if (ire1->ire_marks &
				    (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN))
					continue;
				/*
				 * Ensure we do not exceed the MTU
				 * of the next route.
				 */
				if (ire1->ire_max_frag < max_frag) {
					ip_multirt_bad_mtu(ire1, max_frag);
					continue;
				}

				/* Got one. */
				IRE_REFHOLD(ire1);
				break;
			}
			IRB_REFRELE(irb);

			if (ire1 != NULL) {
				next_mp = copyb(mp);
				if ((next_mp == NULL) ||
				    ((mp->b_cont != NULL) &&
				    ((next_mp->b_cont =
				    dupmsg(mp->b_cont)) == NULL))) {
					freemsg(next_mp);
					next_mp = NULL;
					ire_refrele(ire1);
					ire1 = NULL;
				}
			}

			/* Last multiroute ire; don't loop anymore. */
			if (ire1 == NULL) {
				multirt_send = B_FALSE;
			}
		}

		ll_hdr_len = 0;
		LOCK_IRE_FP_MP(ire);
		ll_hdr_mp = ire->ire_nce->nce_fp_mp;
		if (ll_hdr_mp != NULL) {
			ASSERT(ll_hdr_mp->b_datap->db_type == M_DATA);
			ll_hdr_len = ll_hdr_mp->b_wptr - ll_hdr_mp->b_rptr;
		} else {
			ll_hdr_mp = ire->ire_nce->nce_res_mp;
		}

		/* If there is a transmit header, get a copy for this frag. */
		/*
		 * TODO: should check db_ref before calling ip_carve_mp since
		 * it might give us a dup.
		 */
		if (!ll_hdr_mp) {
			/* No xmit header. */
			xmit_mp = mp;

		/* We have a link-layer header that can fit in our mblk. */
		} else if (mp->b_datap->db_ref == 1 &&
		    ll_hdr_len != 0 &&
		    ll_hdr_len <= mp->b_rptr - mp->b_datap->db_base) {
			/* M_DATA fastpath */
			mp->b_rptr -= ll_hdr_len;
			bcopy(ll_hdr_mp->b_rptr, mp->b_rptr, ll_hdr_len);
			xmit_mp = mp;

		/* Corner case if copyb has failed */
		} else if (!(xmit_mp = copyb(ll_hdr_mp))) {
			UNLOCK_IRE_FP_MP(ire);
			BUMP_MIB(mibptr, ipIfStatsOutFragFails);
			freeb(hdr_mp);
			freemsg(mp);
			freemsg(mp_orig);
			TRACE_1(TR_FAC_IP, TR_IP_WPUT_FRAG_END,
			    "ip_wput_frag_end:(%S)",
			    "discard");

			if (multirt_send) {
				ASSERT(ire1);
				ASSERT(next_mp);

				freemsg(next_mp);
				ire_refrele(ire1);
			}
			if (save_ire != NULL)
				IRE_REFRELE(save_ire);

			if (first_ire != NULL)
				ire_refrele(first_ire);
			return;

		/*
		 * Case of res_mp OR the fastpath mp can't fit
		 * in the mblk
		 */
		} else {
			xmit_mp->b_cont = mp;
			if (DB_CRED(mp) != NULL)
				mblk_setcred(xmit_mp, DB_CRED(mp));
			/*
			 * Get priority marking, if any.
			 * We propagate the CoS marking from the
			 * original packet that went to QoS processing
			 * in ip_wput_ire to the newly carved mp.
			 */
			if (DB_TYPE(xmit_mp) == M_DATA)
				xmit_mp->b_band = mp->b_band;
		}
		UNLOCK_IRE_FP_MP(ire);

		q = ire->ire_stq;
		out_ill = (ill_t *)q->q_ptr;

		BUMP_MIB(out_ill->ill_ip_mib, ipIfStatsOutFragCreates);

		DTRACE_PROBE4(ip4__physical__out__start,
		    ill_t *, NULL, ill_t *, out_ill,
		    ipha_t *, ipha, mblk_t *, xmit_mp);

		FW_HOOKS(ipst->ips_ip4_physical_out_event,
		    ipst->ips_ipv4firewall_physical_out,
		    NULL, out_ill, ipha, xmit_mp, mp, 0, ipst);

		DTRACE_PROBE1(ip4__physical__out__end, mblk_t *, xmit_mp);

		if (xmit_mp != NULL) {
			DTRACE_IP7(send, mblk_t *, xmit_mp, conn_t *, NULL,
			    void_ip_t *, ipha, __dtrace_ipsr_ill_t *, out_ill,
			    ipha_t *, ipha, ip6_t *, NULL, int, 0);

			ILL_SEND_TX(out_ill, ire, connp, xmit_mp, 0);

			BUMP_MIB(out_ill->ill_ip_mib, ipIfStatsHCOutTransmits);
			UPDATE_MIB(out_ill->ill_ip_mib,
			    ipIfStatsHCOutOctets, i1);

			if (pkt_type != OB_PKT) {
				/*
				 * Update the packet count and MIB stats
				 * of trailing RTF_MULTIRT ires.
				 */
				UPDATE_OB_PKT_COUNT(ire);
				BUMP_MIB(out_ill->ill_ip_mib,
				    ipIfStatsOutFragReqds);
			}
		}

		if (multirt_send) {
			/*
			 * We are in a multiple send case; look for
			 * the next ire and re-enter the loop.
			 */
			ASSERT(ire1);
			ASSERT(next_mp);
			/* REFRELE the current ire before looping */
			ire_refrele(ire);
			ire = ire1;
			ire1 = NULL;
			mp = next_mp;
			next_mp = NULL;
		}
	} while (multirt_send);

	ASSERT(ire1 == NULL);

	/* Restore the original ire; we need it for the trailing frags */
	if (save_ire != NULL) {
		/* REFRELE the last iterated ire */
		ire_refrele(ire);
		/* save_ire has been REFHOLDed */
		ire = save_ire;
		save_ire = NULL;
		q = ire->ire_stq;
	}

	if (pkt_type == OB_PKT) {
		UPDATE_OB_PKT_COUNT(ire);
	} else {
		out_ill = (ill_t *)q->q_ptr;
		BUMP_MIB(out_ill->ill_ip_mib, ipIfStatsHCOutForwDatagrams);
		UPDATE_IB_PKT_COUNT(ire);
	}

	/* Advance the offset to the second frag starting point. */
	offset += len;
	/*
	 * Update hdr_len from the copied header - there might be less options
	 * in the later fragments.
	 */
	hdr_len = IPH_HDR_LENGTH(hdr_mp->b_rptr);
	/* Loop until done. */
	for (;;) {
		uint16_t	offset_and_flags;
		uint16_t	ip_len;

		if (ip_data_end - offset > len) {
			/*
			 * Carve off the appropriate amount from the original
			 * datagram.
			 */
			if (!(carve_mp = ip_carve_mp(&mp_orig, len))) {
				mp = NULL;
				break;
			}
			/*
			 * More frags after this one.  Get another copy
			 * of the header.
			 */
			if (carve_mp->b_datap->db_ref == 1 &&
			    hdr_mp->b_wptr - hdr_mp->b_rptr <
			    carve_mp->b_rptr - carve_mp->b_datap->db_base) {
				/* Inline IP header */
				carve_mp->b_rptr -= hdr_mp->b_wptr -
				    hdr_mp->b_rptr;
				bcopy(hdr_mp->b_rptr, carve_mp->b_rptr,
				    hdr_mp->b_wptr - hdr_mp->b_rptr);
				mp = carve_mp;
			} else {
				if (!(mp = copyb(hdr_mp))) {
					freemsg(carve_mp);
					break;
				}
				/* Get priority marking, if any. */
				mp->b_band = carve_mp->b_band;
				mp->b_cont = carve_mp;
			}
			ipha = (ipha_t *)mp->b_rptr;
			offset_and_flags = IPH_MF;
		} else {
			/*
			 * Last frag.  Consume the header. Set len to
			 * the length of this last piece.
			 */
			len = ip_data_end - offset;

			/*
			 * Carve off the appropriate amount from the original
			 * datagram.
			 */
			if (!(carve_mp = ip_carve_mp(&mp_orig, len))) {
				mp = NULL;
				break;
			}
			if (carve_mp->b_datap->db_ref == 1 &&
			    hdr_mp->b_wptr - hdr_mp->b_rptr <
			    carve_mp->b_rptr - carve_mp->b_datap->db_base) {
				/* Inline IP header */
				carve_mp->b_rptr -= hdr_mp->b_wptr -
				    hdr_mp->b_rptr;
				bcopy(hdr_mp->b_rptr, carve_mp->b_rptr,
				    hdr_mp->b_wptr - hdr_mp->b_rptr);
				mp = carve_mp;
				freeb(hdr_mp);
				hdr_mp = mp;
			} else {
				mp = hdr_mp;
				/* Get priority marking, if any. */
				mp->b_band = carve_mp->b_band;
				mp->b_cont = carve_mp;
			}
			ipha = (ipha_t *)mp->b_rptr;
			/* A frag of a frag might have IPH_MF non-zero */
			offset_and_flags =
			    ntohs(ipha->ipha_fragment_offset_and_flags) &
			    IPH_MF;
		}
		offset_and_flags |= (uint16_t)(offset >> 3);
		offset_and_flags |= (uint16_t)frag_flag;
		/* Store the offset and flags in the IP header. */
		ipha->ipha_fragment_offset_and_flags = htons(offset_and_flags);

		/* Store the length in the IP header. */
		ip_len = (uint16_t)(len + hdr_len);
		ipha->ipha_length = htons(ip_len);

		/*
		 * Set the IP header checksum.	Note that mp is just
		 * the header, so this is easy to pass to ip_csum.
		 */
		ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

		/* Attach a transmit header, if any, and ship it. */
		if (pkt_type == OB_PKT) {
			UPDATE_OB_PKT_COUNT(ire);
		} else {
			out_ill = (ill_t *)q->q_ptr;
			BUMP_MIB(out_ill->ill_ip_mib,
			    ipIfStatsHCOutForwDatagrams);
			UPDATE_IB_PKT_COUNT(ire);
		}

		if (ire->ire_flags & RTF_MULTIRT) {
			irb = ire->ire_bucket;
			ASSERT(irb != NULL);

			multirt_send = B_TRUE;

			/*
			 * Save the original ire; we will need to restore it
			 * for the tailing frags.
			 */
			save_ire = ire;
			IRE_REFHOLD(save_ire);
		}
		/*
		 * Emission loop for this fragment, similar
		 * to what is done for the first fragment.
		 */
		do {
			if (multirt_send) {
				/*
				 * We are in a multiple send case, need to get
				 * the next ire and make a copy of the packet.
				 */
				ASSERT(irb != NULL);
				IRB_REFHOLD(irb);
				for (ire1 = ire->ire_next;
				    ire1 != NULL;
				    ire1 = ire1->ire_next) {
					if (!(ire1->ire_flags & RTF_MULTIRT))
						continue;
					if (ire1->ire_addr != ire->ire_addr)
						continue;
					if (ire1->ire_marks &
					    (IRE_MARK_CONDEMNED|
					    IRE_MARK_HIDDEN)) {
						continue;
					}
					/*
					 * Ensure we do not exceed the MTU
					 * of the next route.
					 */
					if (ire1->ire_max_frag < max_frag) {
						ip_multirt_bad_mtu(ire1,
						    max_frag);
						continue;
					}

					/* Got one. */
					IRE_REFHOLD(ire1);
					break;
				}
				IRB_REFRELE(irb);

				if (ire1 != NULL) {
					next_mp = copyb(mp);
					if ((next_mp == NULL) ||
					    ((mp->b_cont != NULL) &&
					    ((next_mp->b_cont =
					    dupmsg(mp->b_cont)) == NULL))) {
						freemsg(next_mp);
						next_mp = NULL;
						ire_refrele(ire1);
						ire1 = NULL;
					}
				}

				/* Last multiroute ire; don't loop anymore. */
				if (ire1 == NULL) {
					multirt_send = B_FALSE;
				}
			}

			/* Update transmit header */
			ll_hdr_len = 0;
			LOCK_IRE_FP_MP(ire);
			ll_hdr_mp = ire->ire_nce->nce_fp_mp;
			if (ll_hdr_mp != NULL) {
				ASSERT(ll_hdr_mp->b_datap->db_type == M_DATA);
				ll_hdr_len = MBLKL(ll_hdr_mp);
			} else {
				ll_hdr_mp = ire->ire_nce->nce_res_mp;
			}

			if (!ll_hdr_mp) {
				xmit_mp = mp;

			/*
			 * We have link-layer header that can fit in
			 * our mblk.
			 */
			} else if (mp->b_datap->db_ref == 1 &&
			    ll_hdr_len != 0 &&
			    ll_hdr_len <= mp->b_rptr - mp->b_datap->db_base) {
				/* M_DATA fastpath */
				mp->b_rptr -= ll_hdr_len;
				bcopy(ll_hdr_mp->b_rptr, mp->b_rptr,
				    ll_hdr_len);
				xmit_mp = mp;

			/*
			 * Case of res_mp OR the fastpath mp can't fit
			 * in the mblk
			 */
			} else if ((xmit_mp = copyb(ll_hdr_mp)) != NULL) {
				xmit_mp->b_cont = mp;
				if (DB_CRED(mp) != NULL)
					mblk_setcred(xmit_mp, DB_CRED(mp));
				/* Get priority marking, if any. */
				if (DB_TYPE(xmit_mp) == M_DATA)
					xmit_mp->b_band = mp->b_band;

			/* Corner case if copyb failed */
			} else {
				/*
				 * Exit both the replication and
				 * fragmentation loops.
				 */
				UNLOCK_IRE_FP_MP(ire);
				goto drop_pkt;
			}
			UNLOCK_IRE_FP_MP(ire);

			mp1 = mp;
			out_ill = (ill_t *)q->q_ptr;

			BUMP_MIB(out_ill->ill_ip_mib, ipIfStatsOutFragCreates);

			DTRACE_PROBE4(ip4__physical__out__start,
			    ill_t *, NULL, ill_t *, out_ill,
			    ipha_t *, ipha, mblk_t *, xmit_mp);

			FW_HOOKS(ipst->ips_ip4_physical_out_event,
			    ipst->ips_ipv4firewall_physical_out,
			    NULL, out_ill, ipha, xmit_mp, mp, 0, ipst);

			DTRACE_PROBE1(ip4__physical__out__end,
			    mblk_t *, xmit_mp);

			if (mp != mp1 && hdr_mp == mp1)
				hdr_mp = mp;
			if (mp != mp1 && mp_orig == mp1)
				mp_orig = mp;

			if (xmit_mp != NULL) {
				DTRACE_IP7(send, mblk_t *, xmit_mp, conn_t *,
				    NULL, void_ip_t *, ipha,
				    __dtrace_ipsr_ill_t *, out_ill, ipha_t *,
				    ipha, ip6_t *, NULL, int, 0);

				ILL_SEND_TX(out_ill, ire, connp, xmit_mp, 0);

				BUMP_MIB(out_ill->ill_ip_mib,
				    ipIfStatsHCOutTransmits);
				UPDATE_MIB(out_ill->ill_ip_mib,
				    ipIfStatsHCOutOctets, ip_len);

				if (pkt_type != OB_PKT) {
					/*
					 * Update the packet count of trailing
					 * RTF_MULTIRT ires.
					 */
					UPDATE_OB_PKT_COUNT(ire);
				}
			}

			/* All done if we just consumed the hdr_mp. */
			if (mp == hdr_mp) {
				last_frag = B_TRUE;
				BUMP_MIB(out_ill->ill_ip_mib,
				    ipIfStatsOutFragOKs);
			}

			if (multirt_send) {
				/*
				 * We are in a multiple send case; look for
				 * the next ire and re-enter the loop.
				 */
				ASSERT(ire1);
				ASSERT(next_mp);
				/* REFRELE the current ire before looping */
				ire_refrele(ire);
				ire = ire1;
				ire1 = NULL;
				q = ire->ire_stq;
				mp = next_mp;
				next_mp = NULL;
			}
		} while (multirt_send);
		/*
		 * Restore the original ire; we need it for the
		 * trailing frags
		 */
		if (save_ire != NULL) {
			ASSERT(ire1 == NULL);
			/* REFRELE the last iterated ire */
			ire_refrele(ire);
			/* save_ire has been REFHOLDed */
			ire = save_ire;
			q = ire->ire_stq;
			save_ire = NULL;
		}

		if (last_frag) {
			TRACE_1(TR_FAC_IP, TR_IP_WPUT_FRAG_END,
			    "ip_wput_frag_end:(%S)",
			    "consumed hdr_mp");

			if (first_ire != NULL)
				ire_refrele(first_ire);
			return;
		}
		/* Otherwise, advance and loop. */
		offset += len;
	}

drop_pkt:
	/* Clean up following allocation failure. */
	BUMP_MIB(mibptr, ipIfStatsOutFragFails);
	freemsg(mp);
	if (mp != hdr_mp)
		freeb(hdr_mp);
	if (mp != mp_orig)
		freemsg(mp_orig);

	if (save_ire != NULL)
		IRE_REFRELE(save_ire);
	if (first_ire != NULL)
		ire_refrele(first_ire);

	TRACE_1(TR_FAC_IP, TR_IP_WPUT_FRAG_END,
	    "ip_wput_frag_end:(%S)",
	    "end--alloc failure");
}

/*
 * Copy the header plus those options which have the copy bit set
 */
static mblk_t *
ip_wput_frag_copyhdr(uchar_t *rptr, int hdr_len, int offset, ip_stack_t *ipst)
{
	mblk_t	*mp;
	uchar_t	*up;

	/*
	 * Quick check if we need to look for options without the copy bit
	 * set
	 */
	mp = allocb(ipst->ips_ip_wroff_extra + hdr_len, BPRI_HI);
	if (!mp)
		return (mp);
	mp->b_rptr += ipst->ips_ip_wroff_extra;
	if (hdr_len == IP_SIMPLE_HDR_LENGTH || offset != 0) {
		bcopy(rptr, mp->b_rptr, hdr_len);
		mp->b_wptr += hdr_len + ipst->ips_ip_wroff_extra;
		return (mp);
	}
	up  = mp->b_rptr;
	bcopy(rptr, up, IP_SIMPLE_HDR_LENGTH);
	up += IP_SIMPLE_HDR_LENGTH;
	rptr += IP_SIMPLE_HDR_LENGTH;
	hdr_len -= IP_SIMPLE_HDR_LENGTH;
	while (hdr_len > 0) {
		uint32_t optval;
		uint32_t optlen;

		optval = *rptr;
		if (optval == IPOPT_EOL)
			break;
		if (optval == IPOPT_NOP)
			optlen = 1;
		else
			optlen = rptr[1];
		if (optval & IPOPT_COPY) {
			bcopy(rptr, up, optlen);
			up += optlen;
		}
		rptr += optlen;
		hdr_len -= optlen;
	}
	/*
	 * Make sure that we drop an even number of words by filling
	 * with EOL to the next word boundary.
	 */
	for (hdr_len = up - (mp->b_rptr + IP_SIMPLE_HDR_LENGTH);
	    hdr_len & 0x3; hdr_len++)
		*up++ = IPOPT_EOL;
	mp->b_wptr = up;
	/* Update header length */
	mp->b_rptr[0] = (uint8_t)((IP_VERSION << 4) | ((up - mp->b_rptr) >> 2));
	return (mp);
}

/*
 * Delivery to local recipients including fanout to multiple recipients.
 * Does not do checksumming of UDP/TCP.
 * Note: q should be the read side queue for either the ill or conn.
 * Note: rq should be the read side q for the lower (ill) stream.
 * We don't send packets to IPPF processing, thus the last argument
 * to all the fanout calls are B_FALSE.
 */
void
ip_wput_local(queue_t *q, ill_t *ill, ipha_t *ipha, mblk_t *mp, ire_t *ire,
    int fanout_flags, zoneid_t zoneid)
{
	uint32_t	protocol;
	mblk_t		*first_mp;
	boolean_t	mctl_present;
	int		ire_type;
#define	rptr	((uchar_t *)ipha)
	ip_stack_t	*ipst = ill->ill_ipst;

	TRACE_1(TR_FAC_IP, TR_IP_WPUT_LOCAL_START,
	    "ip_wput_local_start: q %p", q);

	if (ire != NULL) {
		ire_type = ire->ire_type;
	} else {
		/*
		 * Only ip_multicast_loopback() calls us with a NULL ire. If the
		 * packet is not multicast, we can't tell the ire type.
		 */
		ASSERT(CLASSD(ipha->ipha_dst));
		ire_type = IRE_BROADCAST;
	}

	first_mp = mp;
	if (first_mp->b_datap->db_type == M_CTL) {
		ipsec_out_t *io = (ipsec_out_t *)first_mp->b_rptr;
		if (!io->ipsec_out_secure) {
			/*
			 * This ipsec_out_t was allocated in ip_wput
			 * for multicast packets to store the ill_index.
			 * As this is being delivered locally, we don't
			 * need this anymore.
			 */
			mp = first_mp->b_cont;
			freeb(first_mp);
			first_mp = mp;
			mctl_present = B_FALSE;
		} else {
			/*
			 * Convert IPSEC_OUT to IPSEC_IN, preserving all
			 * security properties for the looped-back packet.
			 */
			mctl_present = B_TRUE;
			mp = first_mp->b_cont;
			ASSERT(mp != NULL);
			ipsec_out_to_in(first_mp);
		}
	} else {
		mctl_present = B_FALSE;
	}

	DTRACE_PROBE4(ip4__loopback__in__start,
	    ill_t *, ill, ill_t *, NULL,
	    ipha_t *, ipha, mblk_t *, first_mp);

	FW_HOOKS(ipst->ips_ip4_loopback_in_event,
	    ipst->ips_ipv4firewall_loopback_in,
	    ill, NULL, ipha, first_mp, mp, 0, ipst);

	DTRACE_PROBE1(ip4__loopback__in__end, mblk_t *, first_mp);

	if (first_mp == NULL)
		return;

	if (ipst->ips_ipobs_enabled) {
		zoneid_t szone, dzone, lookup_zoneid = ALL_ZONES;
		zoneid_t stackzoneid = netstackid_to_zoneid(
		    ipst->ips_netstack->netstack_stackid);

		dzone = (stackzoneid == GLOBAL_ZONEID) ? zoneid : stackzoneid;
		/*
		 * 127.0.0.1 is special, as we cannot lookup its zoneid by
		 * address.  Restrict the lookup below to the destination zone.
		 */
		if (ipha->ipha_src == ntohl(INADDR_LOOPBACK))
			lookup_zoneid = zoneid;
		szone = ip_get_zoneid_v4(ipha->ipha_src, mp, ipst,
		    lookup_zoneid);
		ipobs_hook(mp, IPOBS_HOOK_LOCAL, szone, dzone, ill,
		    IPV4_VERSION, 0, ipst);
	}

	DTRACE_IP7(receive, mblk_t *, first_mp, conn_t *, NULL, void_ip_t *,
	    ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha, ip6_t *, NULL,
	    int, 1);

	ipst->ips_loopback_packets++;

	ip2dbg(("ip_wput_local: from 0x%x to 0x%x in zone %d\n",
	    ntohl(ipha->ipha_src), ntohl(ipha->ipha_dst), zoneid));
	if (!IS_SIMPLE_IPH(ipha)) {
		ip_wput_local_options(ipha, ipst);
	}

	protocol = ipha->ipha_protocol;
	switch (protocol) {
	case IPPROTO_ICMP: {
		ire_t		*ire_zone;
		ilm_t		*ilm;
		mblk_t		*mp1;
		zoneid_t	last_zoneid;

		if (CLASSD(ipha->ipha_dst) && !IS_LOOPBACK(ill)) {
			ASSERT(ire_type == IRE_BROADCAST);
			/*
			 * In the multicast case, applications may have joined
			 * the group from different zones, so we need to deliver
			 * the packet to each of them. Loop through the
			 * multicast memberships structures (ilm) on the receive
			 * ill and send a copy of the packet up each matching
			 * one. However, we don't do this for multicasts sent on
			 * the loopback interface (PHYI_LOOPBACK flag set) as
			 * they must stay in the sender's zone.
			 *
			 * ilm_add_v6() ensures that ilms in the same zone are
			 * contiguous in the ill_ilm list. We use this property
			 * to avoid sending duplicates needed when two
			 * applications in the same zone join the same group on
			 * different logical interfaces: we ignore the ilm if
			 * it's zoneid is the same as the last matching one.
			 * In addition, the sending of the packet for
			 * ire_zoneid is delayed until all of the other ilms
			 * have been exhausted.
			 */
			last_zoneid = -1;
			ILM_WALKER_HOLD(ill);
			for (ilm = ill->ill_ilm; ilm != NULL;
			    ilm = ilm->ilm_next) {
				if ((ilm->ilm_flags & ILM_DELETED) ||
				    ipha->ipha_dst != ilm->ilm_addr ||
				    ilm->ilm_zoneid == last_zoneid ||
				    ilm->ilm_zoneid == zoneid ||
				    !(ilm->ilm_ipif->ipif_flags & IPIF_UP))
					continue;
				mp1 = ip_copymsg(first_mp);
				if (mp1 == NULL)
					continue;
				icmp_inbound(q, mp1, B_TRUE, ill, 0, 0,
				    mctl_present, B_FALSE, ill,
				    ilm->ilm_zoneid);
				last_zoneid = ilm->ilm_zoneid;
			}
			ILM_WALKER_RELE(ill);
			/*
			 * Loopback case: the sending endpoint has
			 * IP_MULTICAST_LOOP disabled, therefore we don't
			 * dispatch the multicast packet to the sending zone.
			 */
			if (fanout_flags & IP_FF_NO_MCAST_LOOP) {
				freemsg(first_mp);
				return;
			}
		} else if (ire_type == IRE_BROADCAST) {
			/*
			 * In the broadcast case, there may be many zones
			 * which need a copy of the packet delivered to them.
			 * There is one IRE_BROADCAST per broadcast address
			 * and per zone; we walk those using a helper function.
			 * In addition, the sending of the packet for zoneid is
			 * delayed until all of the other ires have been
			 * processed.
			 */
			IRB_REFHOLD(ire->ire_bucket);
			ire_zone = NULL;
			while ((ire_zone = ire_get_next_bcast_ire(ire_zone,
			    ire)) != NULL) {
				mp1 = ip_copymsg(first_mp);
				if (mp1 == NULL)
					continue;

				UPDATE_IB_PKT_COUNT(ire_zone);
				ire_zone->ire_last_used_time = lbolt;
				icmp_inbound(q, mp1, B_TRUE, ill, 0, 0,
				    mctl_present, B_FALSE, ill,
				    ire_zone->ire_zoneid);
			}
			IRB_REFRELE(ire->ire_bucket);
		}
		icmp_inbound(q, first_mp, (ire_type == IRE_BROADCAST), ill, 0,
		    0, mctl_present, B_FALSE, ill, zoneid);
		TRACE_2(TR_FAC_IP, TR_IP_WPUT_LOCAL_END,
		    "ip_wput_local_end: q %p (%S)",
		    q, "icmp");
		return;
	}
	case IPPROTO_IGMP:
		if ((mp = igmp_input(q, mp, ill)) == NULL) {
			/* Bad packet - discarded by igmp_input */
			TRACE_2(TR_FAC_IP, TR_IP_WPUT_LOCAL_END,
			    "ip_wput_local_end: q %p (%S)",
			    q, "igmp_input--bad packet");
			if (mctl_present)
				freeb(first_mp);
			return;
		}
		/*
		 * igmp_input() may have returned the pulled up message.
		 * So first_mp and ipha need to be reinitialized.
		 */
		ipha = (ipha_t *)mp->b_rptr;
		if (mctl_present)
			first_mp->b_cont = mp;
		else
			first_mp = mp;
		/* deliver to local raw users */
		break;
	case IPPROTO_ENCAP:
		/*
		 * This case is covered by either ip_fanout_proto, or by
		 * the above security processing for self-tunneled packets.
		 */
		break;
	case IPPROTO_UDP: {
		uint16_t	*up;
		uint32_t	ports;

		up = (uint16_t *)(rptr + IPH_HDR_LENGTH(ipha) +
		    UDP_PORTS_OFFSET);
		/* Force a 'valid' checksum. */
		up[3] = 0;

		ports = *(uint32_t *)up;
		ip_fanout_udp(q, first_mp, ill, ipha, ports,
		    (ire_type == IRE_BROADCAST),
		    fanout_flags | IP_FF_SEND_ICMP | IP_FF_HDR_COMPLETE |
		    IP_FF_SEND_SLLA | IP_FF_IPINFO, mctl_present, B_FALSE,
		    ill, zoneid);
		TRACE_2(TR_FAC_IP, TR_IP_WPUT_LOCAL_END,
		    "ip_wput_local_end: q %p (%S)", q, "ip_fanout_udp");
		return;
	}
	case IPPROTO_TCP: {

		/*
		 * For TCP, discard broadcast packets.
		 */
		if ((ushort_t)ire_type == IRE_BROADCAST) {
			freemsg(first_mp);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip2dbg(("ip_wput_local: discard broadcast\n"));
			return;
		}

		if (mp->b_datap->db_type == M_DATA) {
			/*
			 * M_DATA mblk, so init mblk (chain) for no struio().
			 */
			mblk_t	*mp1 = mp;

			do {
				mp1->b_datap->db_struioflag = 0;
			} while ((mp1 = mp1->b_cont) != NULL);
		}
		ASSERT((rptr + IPH_HDR_LENGTH(ipha) + TCP_PORTS_OFFSET + 4)
		    <= mp->b_wptr);
		ip_fanout_tcp(q, first_mp, ill, ipha,
		    fanout_flags | IP_FF_SEND_ICMP | IP_FF_HDR_COMPLETE |
		    IP_FF_SYN_ADDIRE | IP_FF_IPINFO,
		    mctl_present, B_FALSE, zoneid);
		TRACE_2(TR_FAC_IP, TR_IP_WPUT_LOCAL_END,
		    "ip_wput_local_end: q %p (%S)", q, "ip_fanout_tcp");
		return;
	}
	case IPPROTO_SCTP:
	{
		uint32_t	ports;

		bcopy(rptr + IPH_HDR_LENGTH(ipha), &ports, sizeof (ports));
		ip_fanout_sctp(first_mp, ill, ipha, ports,
		    fanout_flags | IP_FF_SEND_ICMP | IP_FF_HDR_COMPLETE |
		    IP_FF_IPINFO, mctl_present, B_FALSE, zoneid);
		return;
	}

	default:
		break;
	}
	/*
	 * Find a client for some other protocol.  We give
	 * copies to multiple clients, if more than one is
	 * bound.
	 */
	ip_fanout_proto(q, first_mp, ill, ipha,
	    fanout_flags | IP_FF_SEND_ICMP | IP_FF_HDR_COMPLETE | IP_FF_RAWIP,
	    mctl_present, B_FALSE, ill, zoneid);
	TRACE_2(TR_FAC_IP, TR_IP_WPUT_LOCAL_END,
	    "ip_wput_local_end: q %p (%S)", q, "ip_fanout_proto");
#undef	rptr
}

/*
 * Update any source route, record route, or timestamp options.
 * Check that we are at end of strict source route.
 * The options have been sanity checked by ip_wput_options().
 */
static void
ip_wput_local_options(ipha_t *ipha, ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	uint32_t	ts;
	ire_t		*ire;
	timestruc_t	now;

	ip2dbg(("ip_wput_local_options\n"));
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* End of source route */
				break;
			}
			/*
			 * This will only happen if two consecutive entries
			 * in the source route contains our address or if
			 * it is a packet with a loose source route which
			 * reaches us before consuming the whole source route
			 */
			ip1dbg(("ip_wput_local_options: not end of SR\n"));
			if (optval == IPOPT_SSRR) {
				return;
			}
			/*
			 * Hack: instead of dropping the packet truncate the
			 * source route to what has been used by filling the
			 * rest with IPOPT_NOP.
			 */
			opt[IPOPT_OLEN] = (uint8_t)off;
			while (off < optlen) {
				opt[off++] = IPOPT_NOP;
			}
			break;
		case IPOPT_RR:
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* No more room - ignore */
				ip1dbg((
				    "ip_wput_forward_options: end of RR\n"));
				break;
			}
			dst = htonl(INADDR_LOOPBACK);
			bcopy(&dst, (char *)opt + off, IP_ADDR_LEN);
			opt[IPOPT_OFFSET] += IP_ADDR_LEN;
			break;
		case IPOPT_TS:
			/* Insert timestamp if there is romm */
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_TSONLY:
				off = IPOPT_TS_TIMELEN;
				break;
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
				/* Verify that the address matched */
				off = opt[IPOPT_OFFSET] - 1;
				bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
				ire = ire_ctable_lookup(dst, 0, IRE_LOCAL,
				    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE,
				    ipst);
				if (ire == NULL) {
					/* Not for us */
					break;
				}
				ire_refrele(ire);
				/* FALLTHRU */
			case IPOPT_TS_TSANDADDR:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				/*
				 * ip_*put_options should have already
				 * dropped this packet.
				 */
				cmn_err(CE_PANIC, "ip_wput_local_options: "
				    "unknown IT - bug in ip_wput_options?\n");
				return;	/* Keep "lint" happy */
			}
			if (opt[IPOPT_OFFSET] - 1 + off > optlen) {
				/* Increase overflow counter */
				off = (opt[IPOPT_POS_OV_FLG] >> 4) + 1;
				opt[IPOPT_POS_OV_FLG] = (uint8_t)
				    (opt[IPOPT_POS_OV_FLG] & 0x0F) |
				    (off << 4);
				break;
			}
			off = opt[IPOPT_OFFSET] - 1;
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
			case IPOPT_TS_TSANDADDR:
				dst = htonl(INADDR_LOOPBACK);
				bcopy(&dst, (char *)opt + off, IP_ADDR_LEN);
				opt[IPOPT_OFFSET] += IP_ADDR_LEN;
				/* FALLTHRU */
			case IPOPT_TS_TSONLY:
				off = opt[IPOPT_OFFSET] - 1;
				/* Compute # of milliseconds since midnight */
				gethrestime(&now);
				ts = (now.tv_sec % (24 * 60 * 60)) * 1000 +
				    now.tv_nsec / (NANOSEC / MILLISEC);
				bcopy(&ts, (char *)opt + off, IPOPT_TS_TIMELEN);
				opt[IPOPT_OFFSET] += IPOPT_TS_TIMELEN;
				break;
			}
			break;
		}
	}
}

/*
 * Send out a multicast packet on interface ipif.
 * The sender does not have an conn.
 * Caller verifies that this isn't a PHYI_LOOPBACK.
 */
void
ip_wput_multicast(queue_t *q, mblk_t *mp, ipif_t *ipif, zoneid_t zoneid)
{
	ipha_t	*ipha;
	ire_t	*ire;
	ipaddr_t	dst;
	mblk_t		*first_mp;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	/* igmp_sendpkt always allocates a ipsec_out_t */
	ASSERT(mp->b_datap->db_type == M_CTL);
	ASSERT(!ipif->ipif_isv6);
	ASSERT(!IS_LOOPBACK(ipif->ipif_ill));

	first_mp = mp;
	mp = first_mp->b_cont;
	ASSERT(mp->b_datap->db_type == M_DATA);
	ipha = (ipha_t *)mp->b_rptr;

	/*
	 * Find an IRE which matches the destination and the outgoing
	 * queue (i.e. the outgoing interface.)
	 */
	if (ipif->ipif_flags & IPIF_POINTOPOINT)
		dst = ipif->ipif_pp_dst_addr;
	else
		dst = ipha->ipha_dst;
	/*
	 * The source address has already been initialized by the
	 * caller and hence matching on ILL (MATCH_IRE_ILL) would
	 * be sufficient rather than MATCH_IRE_IPIF.
	 *
	 * This function is used for sending IGMP packets. We need
	 * to make sure that we send the packet out of the interface
	 * (ipif->ipif_ill) where we joined the group. This is to
	 * prevent from switches doing IGMP snooping to send us multicast
	 * packets for a given group on the interface we have joined.
	 * If we can't find an ire, igmp_sendpkt has already initialized
	 * ipsec_out_attach_if so that this will not be load spread in
	 * ip_newroute_ipif.
	 */
	ire = ire_ctable_lookup(dst, 0, 0, ipif, zoneid, NULL,
	    MATCH_IRE_ILL, ipst);
	if (!ire) {
		/*
		 * Mark this packet to make it be delivered to
		 * ip_wput_ire after the new ire has been
		 * created.
		 */
		mp->b_prev = NULL;
		mp->b_next = NULL;
		ip_newroute_ipif(q, first_mp, ipif, dst, NULL, RTF_SETSRC,
		    zoneid, &zero_info);
		return;
	}

	/*
	 * Honor the RTF_SETSRC flag; this is the only case
	 * where we force this addr whatever the current src addr is,
	 * because this address is set by igmp_sendpkt(), and
	 * cannot be specified by any user.
	 */
	if (ire->ire_flags & RTF_SETSRC) {
		ipha->ipha_src = ire->ire_src_addr;
	}

	ip_wput_ire(q, first_mp, ire, NULL, B_FALSE, zoneid);
}

/*
 * NOTE : This function does not ire_refrele the ire argument passed in.
 *
 * Copy the link layer header and do IPQoS if needed. Frees the mblk on
 * failure. The nce_fp_mp can vanish any time in the case of
 * IRE_BROADCAST due to DL_NOTE_FASTPATH_FLUSH. Hence we have to hold
 * the ire_lock to access the nce_fp_mp in this case.
 * IPQoS assumes that the first M_DATA contains the IP header. So, if we are
 * prepending a fastpath message IPQoS processing must precede it, we also set
 * the b_band of the fastpath message to that of the  mblk returned by IPQoS
 * (IPQoS might have set the b_band for CoS marking).
 * However, if we are prepending DL_UNITDATA_REQ message, IPQoS processing
 * must follow it so that IPQoS can mark the dl_priority field for CoS
 * marking, if needed.
 */
static mblk_t *
ip_wput_attach_llhdr(mblk_t *mp, ire_t *ire, ip_proc_t proc,
    uint32_t ill_index, ipha_t **iphap)
{
	uint_t	hlen;
	ipha_t *ipha;
	mblk_t *mp1;
	boolean_t qos_done = B_FALSE;
	uchar_t	*ll_hdr;
	ip_stack_t	*ipst = ire->ire_ipst;

#define	rptr	((uchar_t *)ipha)

	ipha = (ipha_t *)mp->b_rptr;
	hlen = 0;
	LOCK_IRE_FP_MP(ire);
	if ((mp1 = ire->ire_nce->nce_fp_mp) != NULL) {
		ASSERT(DB_TYPE(mp1) == M_DATA);
		/* Initiate IPPF processing */
		if ((proc != 0) && IPP_ENABLED(proc, ipst)) {
			UNLOCK_IRE_FP_MP(ire);
			ip_process(proc, &mp, ill_index);
			if (mp == NULL)
				return (NULL);

			ipha = (ipha_t *)mp->b_rptr;
			LOCK_IRE_FP_MP(ire);
			if ((mp1 = ire->ire_nce->nce_fp_mp) == NULL) {
				qos_done = B_TRUE;
				goto no_fp_mp;
			}
			ASSERT(DB_TYPE(mp1) == M_DATA);
		}
		hlen = MBLKL(mp1);
		/*
		 * Check if we have enough room to prepend fastpath
		 * header
		 */
		if (hlen != 0 && (rptr - mp->b_datap->db_base) >= hlen) {
			ll_hdr = rptr - hlen;
			bcopy(mp1->b_rptr, ll_hdr, hlen);
			/*
			 * Set the b_rptr to the start of the link layer
			 * header
			 */
			mp->b_rptr = ll_hdr;
			mp1 = mp;
		} else {
			mp1 = copyb(mp1);
			if (mp1 == NULL)
				goto unlock_err;
			mp1->b_band = mp->b_band;
			mp1->b_cont = mp;
			/*
			 * certain system generated traffic may not
			 * have cred/label in ip header block. This
			 * is true even for a labeled system. But for
			 * labeled traffic, inherit the label in the
			 * new header.
			 */
			if (DB_CRED(mp) != NULL)
				mblk_setcred(mp1, DB_CRED(mp));
			/*
			 * XXX disable ICK_VALID and compute checksum
			 * here; can happen if nce_fp_mp changes and
			 * it can't be copied now due to insufficient
			 * space. (unlikely, fp mp can change, but it
			 * does not increase in length)
			 */
		}
		UNLOCK_IRE_FP_MP(ire);
	} else {
no_fp_mp:
		mp1 = copyb(ire->ire_nce->nce_res_mp);
		if (mp1 == NULL) {
unlock_err:
			UNLOCK_IRE_FP_MP(ire);
			freemsg(mp);
			return (NULL);
		}
		UNLOCK_IRE_FP_MP(ire);
		mp1->b_cont = mp;
		/*
		 * certain system generated traffic may not
		 * have cred/label in ip header block. This
		 * is true even for a labeled system. But for
		 * labeled traffic, inherit the label in the
		 * new header.
		 */
		if (DB_CRED(mp) != NULL)
			mblk_setcred(mp1, DB_CRED(mp));
		if (!qos_done && (proc != 0) && IPP_ENABLED(proc, ipst)) {
			ip_process(proc, &mp1, ill_index);
			if (mp1 == NULL)
				return (NULL);

			if (mp1->b_cont == NULL)
				ipha = NULL;
			else
				ipha = (ipha_t *)mp1->b_cont->b_rptr;
		}
	}

	*iphap = ipha;
	return (mp1);
#undef rptr
}

/*
 * Finish the outbound IPsec processing for an IPv6 packet. This function
 * is called from ipsec_out_process() if the IPsec packet was processed
 * synchronously, or from {ah,esp}_kcf_callback() if it was processed
 * asynchronously.
 */
void
ip_wput_ipsec_out_v6(queue_t *q, mblk_t *ipsec_mp, ip6_t *ip6h, ill_t *ill,
    ire_t *ire_arg)
{
	in6_addr_t *v6dstp;
	ire_t *ire;
	mblk_t *mp;
	ip6_t *ip6h1;
	uint_t	ill_index;
	ipsec_out_t *io;
	boolean_t attach_if, hwaccel;
	uint32_t flags = IP6_NO_IPPOLICY;
	int match_flags;
	zoneid_t zoneid;
	boolean_t ill_need_rele = B_FALSE;
	boolean_t ire_need_rele = B_FALSE;
	ip_stack_t	*ipst;

	mp = ipsec_mp->b_cont;
	ip6h1 = (ip6_t *)mp->b_rptr;
	io = (ipsec_out_t *)ipsec_mp->b_rptr;
	ASSERT(io->ipsec_out_ns != NULL);
	ipst = io->ipsec_out_ns->netstack_ip;
	ill_index = io->ipsec_out_ill_index;
	if (io->ipsec_out_reachable) {
		flags |= IPV6_REACHABILITY_CONFIRMATION;
	}
	attach_if = io->ipsec_out_attach_if;
	hwaccel = io->ipsec_out_accelerated;
	zoneid = io->ipsec_out_zoneid;
	ASSERT(zoneid != ALL_ZONES);
	match_flags = MATCH_IRE_ILL_GROUP | MATCH_IRE_SECATTR;
	/* Multicast addresses should have non-zero ill_index. */
	v6dstp = &ip6h->ip6_dst;
	ASSERT(ip6h->ip6_nxt != IPPROTO_RAW);
	ASSERT(!IN6_IS_ADDR_MULTICAST(v6dstp) || ill_index != 0);
	ASSERT(!attach_if || ill_index != 0);
	if (ill_index != 0) {
		if (ill == NULL) {
			ill = ip_grab_attach_ill(NULL, ipsec_mp, ill_index,
			    B_TRUE, ipst);

			/* Failure case frees things for us. */
			if (ill == NULL)
				return;

			ill_need_rele = B_TRUE;
		}
		/*
		 * If this packet needs to go out on a particular interface
		 * honor it.
		 */
		if (attach_if) {
			match_flags = MATCH_IRE_ILL;

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(ill)) {
				match_flags |= MATCH_IRE_MARK_HIDDEN;
			}
		}
	}
	ASSERT(mp != NULL);

	if (IN6_IS_ADDR_MULTICAST(v6dstp)) {
		boolean_t unspec_src;
		ipif_t	*ipif;

		/*
		 * Use the ill_index to get the right ill.
		 */
		unspec_src = io->ipsec_out_unspec_src;
		(void) ipif_lookup_zoneid(ill, zoneid, 0, &ipif);
		if (ipif == NULL) {
			if (ill_need_rele)
				ill_refrele(ill);
			freemsg(ipsec_mp);
			return;
		}

		if (ire_arg != NULL) {
			ire = ire_arg;
		} else {
			ire = ire_ctable_lookup_v6(v6dstp, 0, 0, ipif,
			    zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
			ire_need_rele = B_TRUE;
		}
		if (ire != NULL) {
			ipif_refrele(ipif);
			/*
			 * XXX Do the multicast forwarding now, as the IPsec
			 * processing has been done.
			 */
			goto send;
		}

		ip0dbg(("ip_wput_ipsec_out_v6: multicast: IRE disappeared\n"));
		mp->b_prev = NULL;
		mp->b_next = NULL;

		/*
		 * If the IPsec packet was processed asynchronously,
		 * drop it now.
		 */
		if (q == NULL) {
			if (ill_need_rele)
				ill_refrele(ill);
			freemsg(ipsec_mp);
			return;
		}

		ip_newroute_ipif_v6(q, ipsec_mp, ipif, *v6dstp,
		    unspec_src, zoneid);
		ipif_refrele(ipif);
	} else {
		if (attach_if) {
			ipif_t	*ipif;

			ipif = ipif_get_next_ipif(NULL, ill);
			if (ipif == NULL) {
				if (ill_need_rele)
					ill_refrele(ill);
				freemsg(ipsec_mp);
				return;
			}
			ire = ire_ctable_lookup_v6(v6dstp, 0, 0, ipif,
			    zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
			ire_need_rele = B_TRUE;
			ipif_refrele(ipif);
		} else {
			if (ire_arg != NULL) {
				ire = ire_arg;
			} else {
				ire = ire_cache_lookup_v6(v6dstp, zoneid, NULL,
				    ipst);
				ire_need_rele = B_TRUE;
			}
		}
		if (ire != NULL)
			goto send;
		/*
		 * ire disappeared underneath.
		 *
		 * What we need to do here is the ip_newroute
		 * logic to get the ire without doing the IPsec
		 * processing. Follow the same old path. But this
		 * time, ip_wput or ire_add_then_send will call us
		 * directly as all the IPsec operations are done.
		 */
		ip1dbg(("ip_wput_ipsec_out_v6: IRE disappeared\n"));
		mp->b_prev = NULL;
		mp->b_next = NULL;

		/*
		 * If the IPsec packet was processed asynchronously,
		 * drop it now.
		 */
		if (q == NULL) {
			if (ill_need_rele)
				ill_refrele(ill);
			freemsg(ipsec_mp);
			return;
		}

		ip_newroute_v6(q, ipsec_mp, v6dstp, &ip6h->ip6_src, ill,
		    zoneid, ipst);
	}
	if (ill != NULL && ill_need_rele)
		ill_refrele(ill);
	return;
send:
	if (ill != NULL && ill_need_rele)
		ill_refrele(ill);

	/* Local delivery */
	if (ire->ire_stq == NULL) {
		ill_t	*out_ill;
		ASSERT(q != NULL);

		/* PFHooks: LOOPBACK_OUT */
		out_ill = ire_to_ill(ire);

		/*
		 * DTrace this as ip:::send.  A blocked packet will fire the
		 * send probe, but not the receive probe.
		 */
		DTRACE_IP7(send, mblk_t *, ipsec_mp, conn_t *, NULL,
		    void_ip_t *, ip6h, __dtrace_ipsr_ill_t *, out_ill,
		    ipha_t *, NULL, ip6_t *, ip6h, int, 1);

		DTRACE_PROBE4(ip6__loopback__out__start,
		    ill_t *, NULL, ill_t *, out_ill,
		    ip6_t *, ip6h1, mblk_t *, ipsec_mp);

		FW_HOOKS6(ipst->ips_ip6_loopback_out_event,
		    ipst->ips_ipv6firewall_loopback_out,
		    NULL, out_ill, ip6h1, ipsec_mp, mp, 0, ipst);

		DTRACE_PROBE1(ip6__loopback__out__end, mblk_t *, ipsec_mp);

		if (ipsec_mp != NULL) {
			ip_wput_local_v6(RD(q), out_ill,
			    ip6h, ipsec_mp, ire, 0, zoneid);
		}
		if (ire_need_rele)
			ire_refrele(ire);
		return;
	}
	/*
	 * Everything is done. Send it out on the wire.
	 * We force the insertion of a fragment header using the
	 * IPH_FRAG_HDR flag in two cases:
	 * - after reception of an ICMPv6 "packet too big" message
	 *   with a MTU < 1280 (cf. RFC 2460 section 5)
	 * - for multirouted IPv6 packets, so that the receiver can
	 *   discard duplicates according to their fragment identifier
	 */
	/* XXX fix flow control problems. */
	if (ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN > ire->ire_max_frag ||
	    (ire->ire_frag_flag & IPH_FRAG_HDR)) {
		if (hwaccel) {
			/*
			 * hardware acceleration does not handle these
			 * "slow path" cases.
			 */
			/* IPsec KSTATS: should bump bean counter here. */
			if (ire_need_rele)
				ire_refrele(ire);
			freemsg(ipsec_mp);
			return;
		}
		if (ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN !=
		    (mp->b_cont ? msgdsize(mp) :
		    mp->b_wptr - (uchar_t *)ip6h)) {
			/* IPsec KSTATS: should bump bean counter here. */
			ip0dbg(("Packet length mismatch: %d, %ld\n",
			    ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN,
			    msgdsize(mp)));
			if (ire_need_rele)
				ire_refrele(ire);
			freemsg(ipsec_mp);
			return;
		}
		ASSERT(mp->b_prev == NULL);
		ip2dbg(("Fragmenting Size = %d, mtu = %d\n",
		    ntohs(ip6h->ip6_plen) +
		    IPV6_HDR_LEN, ire->ire_max_frag));
		ip_wput_frag_v6(mp, ire, flags, NULL, B_FALSE,
		    ire->ire_max_frag);
	} else {
		UPDATE_OB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
		ip_xmit_v6(mp, ire, flags, NULL, B_FALSE, hwaccel ? io : NULL);
	}
	if (ire_need_rele)
		ire_refrele(ire);
	freeb(ipsec_mp);
}

void
ipsec_hw_putnext(queue_t *q, mblk_t *mp)
{
	mblk_t *hada_mp;	/* attributes M_CTL mblk */
	da_ipsec_t *hada;	/* data attributes */
	ill_t *ill = (ill_t *)q->q_ptr;

	IPSECHW_DEBUG(IPSECHW_PKT, ("ipsec_hw_putnext: accelerated packet\n"));

	if ((ill->ill_capabilities & (ILL_CAPAB_AH | ILL_CAPAB_ESP)) == 0) {
		/* IPsec KSTATS: Bump lose counter here! */
		freemsg(mp);
		return;
	}

	/*
	 * It's an IPsec packet that must be
	 * accelerated by the Provider, and the
	 * outbound ill is IPsec acceleration capable.
	 * Prepends the mblk with an IPHADA_M_CTL, and ship it
	 * to the ill.
	 * IPsec KSTATS: should bump packet counter here.
	 */

	hada_mp = allocb(sizeof (da_ipsec_t), BPRI_HI);
	if (hada_mp == NULL) {
		/* IPsec KSTATS: should bump packet counter here. */
		freemsg(mp);
		return;
	}

	hada_mp->b_datap->db_type = M_CTL;
	hada_mp->b_wptr = hada_mp->b_rptr + sizeof (*hada);
	hada_mp->b_cont = mp;

	hada = (da_ipsec_t *)hada_mp->b_rptr;
	bzero(hada, sizeof (da_ipsec_t));
	hada->da_type = IPHADA_M_CTL;

	putnext(q, hada_mp);
}

/*
 * Finish the outbound IPsec processing. This function is called from
 * ipsec_out_process() if the IPsec packet was processed
 * synchronously, or from {ah,esp}_kcf_callback() if it was processed
 * asynchronously.
 */
void
ip_wput_ipsec_out(queue_t *q, mblk_t *ipsec_mp, ipha_t *ipha, ill_t *ill,
    ire_t *ire_arg)
{
	uint32_t v_hlen_tos_len;
	ipaddr_t	dst;
	ipif_t	*ipif = NULL;
	ire_t *ire;
	ire_t *ire1 = NULL;
	mblk_t *next_mp = NULL;
	uint32_t max_frag;
	boolean_t multirt_send = B_FALSE;
	mblk_t *mp;
	ipha_t *ipha1;
	uint_t	ill_index;
	ipsec_out_t *io;
	boolean_t attach_if;
	int match_flags;
	irb_t *irb = NULL;
	boolean_t ill_need_rele = B_FALSE, ire_need_rele = B_TRUE;
	zoneid_t zoneid;
	ipxmit_state_t	pktxmit_state;
	ip_stack_t	*ipst;

#ifdef	_BIG_ENDIAN
#define	LENGTH	(v_hlen_tos_len & 0xFFFF)
#else
#define	LENGTH	((v_hlen_tos_len >> 24) | ((v_hlen_tos_len >> 8) & 0xFF00))
#endif

	mp = ipsec_mp->b_cont;
	ipha1 = (ipha_t *)mp->b_rptr;
	ASSERT(mp != NULL);
	v_hlen_tos_len = ((uint32_t *)ipha)[0];
	dst = ipha->ipha_dst;

	io = (ipsec_out_t *)ipsec_mp->b_rptr;
	ill_index = io->ipsec_out_ill_index;
	attach_if = io->ipsec_out_attach_if;
	zoneid = io->ipsec_out_zoneid;
	ASSERT(zoneid != ALL_ZONES);
	ipst = io->ipsec_out_ns->netstack_ip;
	ASSERT(io->ipsec_out_ns != NULL);

	match_flags = MATCH_IRE_ILL_GROUP | MATCH_IRE_SECATTR;
	if (ill_index != 0) {
		if (ill == NULL) {
			ill = ip_grab_attach_ill(NULL, ipsec_mp,
			    ill_index, B_FALSE, ipst);

			/* Failure case frees things for us. */
			if (ill == NULL)
				return;

			ill_need_rele = B_TRUE;
		}
		/*
		 * If this packet needs to go out on a particular interface
		 * honor it.
		 */
		if (attach_if) {
			match_flags = MATCH_IRE_ILL | MATCH_IRE_SECATTR;

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(ill)) {
				match_flags |= MATCH_IRE_MARK_HIDDEN;
			}
		}
	}

	if (CLASSD(dst)) {
		boolean_t conn_dontroute;
		/*
		 * Use the ill_index to get the right ipif.
		 */
		conn_dontroute = io->ipsec_out_dontroute;
		if (ill_index == 0)
			ipif = ipif_lookup_group(dst, zoneid, ipst);
		else
			(void) ipif_lookup_zoneid(ill, zoneid, 0, &ipif);
		if (ipif == NULL) {
			ip1dbg(("ip_wput_ipsec_out: No ipif for"
			    " multicast\n"));
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutNoRoutes);
			freemsg(ipsec_mp);
			goto done;
		}
		/*
		 * ipha_src has already been intialized with the
		 * value of the ipif in ip_wput. All we need now is
		 * an ire to send this downstream.
		 */
		ire = ire_ctable_lookup(dst, 0, 0, ipif, zoneid,
		    MBLK_GETLABEL(mp), match_flags, ipst);
		if (ire != NULL) {
			ill_t *ill1;
			/*
			 * Do the multicast forwarding now, as the IPsec
			 * processing has been done.
			 */
			if (ipst->ips_ip_g_mrouter && !conn_dontroute &&
			    (ill1 = ire_to_ill(ire))) {
				if (ip_mforward(ill1, ipha, mp)) {
					freemsg(ipsec_mp);
					ip1dbg(("ip_wput_ipsec_out: mforward "
					    "failed\n"));
					ire_refrele(ire);
					goto done;
				}
			}
			goto send;
		}

		ip0dbg(("ip_wput_ipsec_out: multicast: IRE disappeared\n"));
		mp->b_prev = NULL;
		mp->b_next = NULL;

		/*
		 * If the IPsec packet was processed asynchronously,
		 * drop it now.
		 */
		if (q == NULL) {
			freemsg(ipsec_mp);
			goto done;
		}

		/*
		 * We may be using a wrong ipif to create the ire.
		 * But it is okay as the source address is assigned
		 * for the packet already. Next outbound packet would
		 * create the IRE with the right IPIF in ip_wput.
		 *
		 * Also handle RTF_MULTIRT routes.
		 */
		ip_newroute_ipif(q, ipsec_mp, ipif, dst, NULL, RTF_MULTIRT,
		    zoneid, &zero_info);
	} else {
		if (attach_if) {
			ire = ire_ctable_lookup(dst, 0, 0, ill->ill_ipif,
			    zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
		} else {
			if (ire_arg != NULL) {
				ire = ire_arg;
				ire_need_rele = B_FALSE;
			} else {
				ire = ire_cache_lookup(dst, zoneid,
				    MBLK_GETLABEL(mp), ipst);
			}
		}
		if (ire != NULL) {
			goto send;
		}

		/*
		 * ire disappeared underneath.
		 *
		 * What we need to do here is the ip_newroute
		 * logic to get the ire without doing the IPsec
		 * processing. Follow the same old path. But this
		 * time, ip_wput or ire_add_then_put will call us
		 * directly as all the IPsec operations are done.
		 */
		ip1dbg(("ip_wput_ipsec_out: IRE disappeared\n"));
		mp->b_prev = NULL;
		mp->b_next = NULL;

		/*
		 * If the IPsec packet was processed asynchronously,
		 * drop it now.
		 */
		if (q == NULL) {
			freemsg(ipsec_mp);
			goto done;
		}

		/*
		 * Since we're going through ip_newroute() again, we
		 * need to make sure we don't:
		 *
		 *	1.) Trigger the ASSERT() with the ipha_ident
		 *	    overloading.
		 *	2.) Redo transport-layer checksumming, since we've
		 *	    already done all that to get this far.
		 *
		 * The easiest way not do either of the above is to set
		 * the ipha_ident field to IP_HDR_INCLUDED.
		 */
		ipha->ipha_ident = IP_HDR_INCLUDED;
		ip_newroute(q, ipsec_mp, dst, (CONN_Q(q) ? Q_TO_CONN(q) : NULL),
		    zoneid, ipst);
	}
	goto done;
send:
	if (ire->ire_stq == NULL) {
		ill_t	*out_ill;
		/*
		 * Loopbacks go through ip_wput_local except for one case.
		 * We come here if we generate a icmp_frag_needed message
		 * after IPsec processing is over. When this function calls
		 * ip_wput_ire_fragmentit, ip_wput_frag might end up calling
		 * icmp_frag_needed. The message generated comes back here
		 * through icmp_frag_needed -> icmp_pkt -> ip_wput ->
		 * ipsec_out_process -> ip_wput_ipsec_out. We need to set the
		 * source address as it is usually set in ip_wput_ire. As
		 * ipsec_out_proc_begin is set, ip_wput calls ipsec_out_process
		 * and we end up here. We can't enter ip_wput_ire once the
		 * IPsec processing is over and hence we need to do it here.
		 */
		ASSERT(q != NULL);
		UPDATE_OB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
		if (ipha->ipha_src == 0)
			ipha->ipha_src = ire->ire_src_addr;

		/* PFHooks: LOOPBACK_OUT */
		out_ill = ire_to_ill(ire);

		/*
		 * DTrace this as ip:::send.  A blocked packet will fire the
		 * send probe, but not the receive probe.
		 */
		DTRACE_IP7(send, mblk_t *, ipsec_mp, conn_t *, NULL,
		    void_ip_t *, ipha, __dtrace_ipsr_ill_t *, out_ill,
		    ipha_t *, ipha, ip6_t *, NULL, int, 1);

		DTRACE_PROBE4(ip4__loopback__out__start,
		    ill_t *, NULL, ill_t *, out_ill,
		    ipha_t *, ipha1, mblk_t *, ipsec_mp);

		FW_HOOKS(ipst->ips_ip4_loopback_out_event,
		    ipst->ips_ipv4firewall_loopback_out,
		    NULL, out_ill, ipha1, ipsec_mp, mp, 0, ipst);

		DTRACE_PROBE1(ip4__loopback__out__end, mblk_t *, ipsec_mp);

		if (ipsec_mp != NULL)
			ip_wput_local(RD(q), out_ill,
			    ipha, ipsec_mp, ire, 0, zoneid);
		if (ire_need_rele)
			ire_refrele(ire);
		goto done;
	}

	if (ire->ire_max_frag < (unsigned int)LENGTH) {
		/*
		 * We are through with IPsec processing.
		 * Fragment this and send it on the wire.
		 */
		if (io->ipsec_out_accelerated) {
			/*
			 * The packet has been accelerated but must
			 * be fragmented. This should not happen
			 * since AH and ESP must not accelerate
			 * packets that need fragmentation, however
			 * the configuration could have changed
			 * since the AH or ESP processing.
			 * Drop packet.
			 * IPsec KSTATS: bump bean counter here.
			 */
			IPSECHW_DEBUG(IPSECHW_PKT, ("ipsec_wput_ipsec_out: "
			    "fragmented accelerated packet!\n"));
			freemsg(ipsec_mp);
		} else {
			ip_wput_ire_fragmentit(ipsec_mp, ire,
			    zoneid, ipst, NULL);
		}
		if (ire_need_rele)
			ire_refrele(ire);
		goto done;
	}

	ip2dbg(("ip_wput_ipsec_out: ipsec_mp %p, ire %p, ire_ipif %p, "
	    "ipif %p\n", (void *)ipsec_mp, (void *)ire,
	    (void *)ire->ire_ipif, (void *)ipif));

	/*
	 * Multiroute the secured packet, unless IPsec really
	 * requires the packet to go out only through a particular
	 * interface.
	 */
	if ((ire->ire_flags & RTF_MULTIRT) && !attach_if) {
		ire_t *first_ire;
		irb = ire->ire_bucket;
		ASSERT(irb != NULL);
		/*
		 * This ire has been looked up as the one that
		 * goes through the given ipif;
		 * make sure we do not omit any other multiroute ire
		 * that may be present in the bucket before this one.
		 */
		IRB_REFHOLD(irb);
		for (first_ire = irb->irb_ire;
		    first_ire != NULL;
		    first_ire = first_ire->ire_next) {
			if ((first_ire->ire_flags & RTF_MULTIRT) &&
			    (first_ire->ire_addr == ire->ire_addr) &&
			    !(first_ire->ire_marks &
			    (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN))) {
				break;
			}
		}

		if ((first_ire != NULL) && (first_ire != ire)) {
			/*
			 * Don't change the ire if the packet must
			 * be fragmented if sent via this new one.
			 */
			if (first_ire->ire_max_frag >= (unsigned int)LENGTH) {
				IRE_REFHOLD(first_ire);
				if (ire_need_rele)
					ire_refrele(ire);
				else
					ire_need_rele = B_TRUE;
				ire = first_ire;
			}
		}
		IRB_REFRELE(irb);

		multirt_send = B_TRUE;
		max_frag = ire->ire_max_frag;
	} else {
		if ((ire->ire_flags & RTF_MULTIRT) && attach_if) {
			ip1dbg(("ip_wput_ipsec_out: ignoring multirouting "
			    "flag, attach_if %d\n", attach_if));
		}
	}

	/*
	 * In most cases, the emission loop below is entered only once.
	 * Only in the case where the ire holds the RTF_MULTIRT
	 * flag, we loop to process all RTF_MULTIRT ires in the
	 * bucket, and send the packet through all crossed
	 * RTF_MULTIRT routes.
	 */
	do {
		if (multirt_send) {
			/*
			 * ire1 holds here the next ire to process in the
			 * bucket. If multirouting is expected,
			 * any non-RTF_MULTIRT ire that has the
			 * right destination address is ignored.
			 */
			ASSERT(irb != NULL);
			IRB_REFHOLD(irb);
			for (ire1 = ire->ire_next;
			    ire1 != NULL;
			    ire1 = ire1->ire_next) {
				if ((ire1->ire_flags & RTF_MULTIRT) == 0)
					continue;
				if (ire1->ire_addr != ire->ire_addr)
					continue;
				if (ire1->ire_marks &
				    (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN))
					continue;
				/* No loopback here */
				if (ire1->ire_stq == NULL)
					continue;
				/*
				 * Ensure we do not exceed the MTU
				 * of the next route.
				 */
				if (ire1->ire_max_frag < (unsigned int)LENGTH) {
					ip_multirt_bad_mtu(ire1, max_frag);
					continue;
				}

				IRE_REFHOLD(ire1);
				break;
			}
			IRB_REFRELE(irb);
			if (ire1 != NULL) {
				/*
				 * We are in a multiple send case, need to
				 * make a copy of the packet.
				 */
				next_mp = copymsg(ipsec_mp);
				if (next_mp == NULL) {
					ire_refrele(ire1);
					ire1 = NULL;
				}
			}
		}
		/*
		 * Everything is done. Send it out on the wire
		 *
		 * ip_xmit_v4 will call ip_wput_attach_llhdr and then
		 * either send it on the wire or, in the case of
		 * HW acceleration, call ipsec_hw_putnext.
		 */
		if (ire->ire_nce &&
		    ire->ire_nce->nce_state != ND_REACHABLE) {
			DTRACE_PROBE2(ip__wput__ipsec__bail,
			    (ire_t *), ire,  (mblk_t *), ipsec_mp);
			/*
			 * If ire's link-layer is unresolved (this
			 * would only happen if the incomplete ire
			 * was added to cachetable via forwarding path)
			 * don't bother going to ip_xmit_v4. Just drop the
			 * packet.
			 * There is a slight risk here, in that, if we
			 * have the forwarding path create an incomplete
			 * IRE, then until the IRE is completed, any
			 * transmitted IPsec packets will be dropped
			 * instead of being queued waiting for resolution.
			 *
			 * But the likelihood of a forwarding packet and a wput
			 * packet sending to the same dst at the same time
			 * and there not yet be an ARP entry for it is small.
			 * Furthermore, if this actually happens, it might
			 * be likely that wput would generate multiple
			 * packets (and forwarding would also have a train
			 * of packets) for that destination. If this is
			 * the case, some of them would have been dropped
			 * anyway, since ARP only queues a few packets while
			 * waiting for resolution
			 *
			 * NOTE: We should really call ip_xmit_v4,
			 * and let it queue the packet and send the
			 * ARP query and have ARP come back thus:
			 * <ARP> ip_wput->ip_output->ip-wput_nondata->
			 * ip_xmit_v4->ip_wput_attach_llhdr + ipsec
			 * hw accel work. But it's too complex to get
			 * the IPsec hw  acceleration approach to fit
			 * well with ip_xmit_v4 doing ARP without
			 * doing IPsec simplification. For now, we just
			 * poke ip_xmit_v4 to trigger the arp resolve, so
			 * that we can continue with the send on the next
			 * attempt.
			 *
			 * XXX THis should be revisited, when
			 * the IPsec/IP interaction is cleaned up
			 */
			ip1dbg(("ip_wput_ipsec_out: ire is incomplete"
			    " - dropping packet\n"));
			freemsg(ipsec_mp);
			/*
			 * Call ip_xmit_v4() to trigger ARP query
			 * in case the nce_state is ND_INITIAL
			 */
			(void) ip_xmit_v4(NULL, ire, NULL, B_FALSE, NULL);
			goto drop_pkt;
		}

		DTRACE_PROBE4(ip4__physical__out__start, ill_t *, NULL,
		    ill_t *, ire->ire_ipif->ipif_ill, ipha_t *, ipha1,
		    mblk_t *, ipsec_mp);
		FW_HOOKS(ipst->ips_ip4_physical_out_event,
		    ipst->ips_ipv4firewall_physical_out, NULL,
		    ire->ire_ipif->ipif_ill, ipha1, ipsec_mp, mp, 0, ipst);
		DTRACE_PROBE1(ip4__physical__out__end, mblk_t *, ipsec_mp);
		if (ipsec_mp == NULL)
			goto drop_pkt;

		ip1dbg(("ip_wput_ipsec_out: calling ip_xmit_v4\n"));
		pktxmit_state = ip_xmit_v4(mp, ire,
		    (io->ipsec_out_accelerated ? io : NULL), B_FALSE, NULL);

		if ((pktxmit_state ==  SEND_FAILED) ||
		    (pktxmit_state == LLHDR_RESLV_FAILED)) {

			freeb(ipsec_mp); /* ip_xmit_v4 frees the mp */
drop_pkt:
			BUMP_MIB(((ill_t *)ire->ire_stq->q_ptr)->ill_ip_mib,
			    ipIfStatsOutDiscards);
			if (ire_need_rele)
				ire_refrele(ire);
			if (ire1 != NULL) {
				ire_refrele(ire1);
				freemsg(next_mp);
			}
			goto done;
		}

		freeb(ipsec_mp);
		if (ire_need_rele)
			ire_refrele(ire);

		if (ire1 != NULL) {
			ire = ire1;
			ire_need_rele = B_TRUE;
			ASSERT(next_mp);
			ipsec_mp = next_mp;
			mp = ipsec_mp->b_cont;
			ire1 = NULL;
			next_mp = NULL;
			io = (ipsec_out_t *)ipsec_mp->b_rptr;
		} else {
			multirt_send = B_FALSE;
		}
	} while (multirt_send);
done:
	if (ill != NULL && ill_need_rele)
		ill_refrele(ill);
	if (ipif != NULL)
		ipif_refrele(ipif);
}

/*
 * Get the ill corresponding to the specified ire, and compare its
 * capabilities with the protocol and algorithms specified by the
 * the SA obtained from ipsec_out. If they match, annotate the
 * ipsec_out structure to indicate that the packet needs acceleration.
 *
 *
 * A packet is eligible for outbound hardware acceleration if the
 * following conditions are satisfied:
 *
 * 1. the packet will not be fragmented
 * 2. the provider supports the algorithm
 * 3. there is no pending control message being exchanged
 * 4. snoop is not attached
 * 5. the destination address is not a broadcast or multicast address.
 *
 * Rationale:
 *	- Hardware drivers do not support fragmentation with
 *	  the current interface.
 *	- snoop, multicast, and broadcast may result in exposure of
 *	  a cleartext datagram.
 * We check all five of these conditions here.
 *
 * XXX would like to nuke "ire_t *" parameter here; problem is that
 * IRE is only way to figure out if a v4 address is a broadcast and
 * thus ineligible for acceleration...
 */
static void
ipsec_out_is_accelerated(mblk_t *ipsec_mp, ipsa_t *sa, ill_t *ill, ire_t *ire)
{
	ipsec_out_t *io;
	mblk_t *data_mp;
	uint_t plen, overhead;
	ip_stack_t	*ipst;

	if ((sa->ipsa_flags & IPSA_F_HW) == 0)
		return;

	if (ill == NULL)
		return;
	ipst = ill->ill_ipst;
	/*
	 * Destination address is a broadcast or multicast.  Punt.
	 */
	if ((ire != NULL) && (ire->ire_type & (IRE_BROADCAST|IRE_LOOPBACK|
	    IRE_LOCAL)))
		return;

	data_mp = ipsec_mp->b_cont;

	if (ill->ill_isv6) {
		ip6_t *ip6h = (ip6_t *)data_mp->b_rptr;

		if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst))
			return;

		plen = ip6h->ip6_plen;
	} else {
		ipha_t *ipha = (ipha_t *)data_mp->b_rptr;

		if (CLASSD(ipha->ipha_dst))
			return;

		plen = ipha->ipha_length;
	}
	/*
	 * Is there a pending DLPI control message being exchanged
	 * between IP/IPsec and the DLS Provider? If there is, it
	 * could be a SADB update, and the state of the DLS Provider
	 * SADB might not be in sync with the SADB maintained by
	 * IPsec. To avoid dropping packets or using the wrong keying
	 * material, we do not accelerate this packet.
	 */
	if (ill->ill_dlpi_pending != DL_PRIM_INVAL) {
		IPSECHW_DEBUG(IPSECHW_PKT, ("ipsec_out_check_is_accelerated: "
		    "ill_dlpi_pending! don't accelerate packet\n"));
		return;
	}

	/*
	 * Is the Provider in promiscous mode? If it does, we don't
	 * accelerate the packet since it will bounce back up to the
	 * listeners in the clear.
	 */
	if (ill->ill_promisc_on_phys) {
		IPSECHW_DEBUG(IPSECHW_PKT, ("ipsec_out_check_is_accelerated: "
		    "ill in promiscous mode, don't accelerate packet\n"));
		return;
	}

	/*
	 * Will the packet require fragmentation?
	 */

	/*
	 * IPsec ESP note: this is a pessimistic estimate, but the same
	 * as is used elsewhere.
	 * SPI + sequence + MAC + IV(blocksize) + padding(blocksize-1)
	 *	+ 2-byte trailer
	 */
	overhead = (sa->ipsa_type == SADB_SATYPE_AH) ? IPSEC_MAX_AH_HDR_SIZE :
	    IPSEC_BASE_ESP_HDR_SIZE(sa);

	if ((plen + overhead) > ill->ill_max_mtu)
		return;

	io = (ipsec_out_t *)ipsec_mp->b_rptr;

	/*
	 * Can the ill accelerate this IPsec protocol and algorithm
	 * specified by the SA?
	 */
	if (!ipsec_capab_match(ill, io->ipsec_out_capab_ill_index,
	    ill->ill_isv6, sa, ipst->ips_netstack)) {
		return;
	}

	/*
	 * Tell AH or ESP that the outbound ill is capable of
	 * accelerating this packet.
	 */
	io->ipsec_out_is_capab_ill = B_TRUE;
}

/*
 * Select which AH & ESP SA's to use (if any) for the outbound packet.
 *
 * If this function returns B_TRUE, the requested SA's have been filled
 * into the ipsec_out_*_sa pointers.
 *
 * If the function returns B_FALSE, the packet has been "consumed", most
 * likely by an ACQUIRE sent up via PF_KEY to a key management daemon.
 *
 * The SA references created by the protocol-specific "select"
 * function will be released when the ipsec_mp is freed, thanks to the
 * ipsec_out_free destructor -- see spd.c.
 */
static boolean_t
ipsec_out_select_sa(mblk_t *ipsec_mp)
{
	boolean_t need_ah_acquire = B_FALSE, need_esp_acquire = B_FALSE;
	ipsec_out_t *io;
	ipsec_policy_t *pp;
	ipsec_action_t *ap;
	io = (ipsec_out_t *)ipsec_mp->b_rptr;
	ASSERT(io->ipsec_out_type == IPSEC_OUT);
	ASSERT(io->ipsec_out_len == sizeof (ipsec_out_t));

	if (!io->ipsec_out_secure) {
		/*
		 * We came here by mistake.
		 * Don't bother with ipsec processing
		 * We should "discourage" this path in the future.
		 */
		ASSERT(io->ipsec_out_proc_begin == B_FALSE);
		return (B_FALSE);
	}
	ASSERT(io->ipsec_out_need_policy == B_FALSE);
	ASSERT((io->ipsec_out_policy != NULL) ||
	    (io->ipsec_out_act != NULL));

	ASSERT(io->ipsec_out_failed == B_FALSE);

	/*
	 * IPsec processing has started.
	 */
	io->ipsec_out_proc_begin = B_TRUE;
	ap = io->ipsec_out_act;
	if (ap == NULL) {
		pp = io->ipsec_out_policy;
		ASSERT(pp != NULL);
		ap = pp->ipsp_act;
		ASSERT(ap != NULL);
	}

	/*
	 * We have an action.  now, let's select SA's.
	 * (In the future, we can cache this in the conn_t..)
	 */
	if (ap->ipa_want_esp) {
		if (io->ipsec_out_esp_sa == NULL) {
			need_esp_acquire = !ipsec_outbound_sa(ipsec_mp,
			    IPPROTO_ESP);
		}
		ASSERT(need_esp_acquire || io->ipsec_out_esp_sa != NULL);
	}

	if (ap->ipa_want_ah) {
		if (io->ipsec_out_ah_sa == NULL) {
			need_ah_acquire = !ipsec_outbound_sa(ipsec_mp,
			    IPPROTO_AH);
		}
		ASSERT(need_ah_acquire || io->ipsec_out_ah_sa != NULL);
		/*
		 * The ESP and AH processing order needs to be preserved
		 * when both protocols are required (ESP should be applied
		 * before AH for an outbound packet). Force an ESP ACQUIRE
		 * when both ESP and AH are required, and an AH ACQUIRE
		 * is needed.
		 */
		if (ap->ipa_want_esp && need_ah_acquire)
			need_esp_acquire = B_TRUE;
	}

	/*
	 * Send an ACQUIRE (extended, regular, or both) if we need one.
	 * Release SAs that got referenced, but will not be used until we
	 * acquire _all_ of the SAs we need.
	 */
	if (need_ah_acquire || need_esp_acquire) {
		if (io->ipsec_out_ah_sa != NULL) {
			IPSA_REFRELE(io->ipsec_out_ah_sa);
			io->ipsec_out_ah_sa = NULL;
		}
		if (io->ipsec_out_esp_sa != NULL) {
			IPSA_REFRELE(io->ipsec_out_esp_sa);
			io->ipsec_out_esp_sa = NULL;
		}

		sadb_acquire(ipsec_mp, io, need_ah_acquire, need_esp_acquire);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Process an IPSEC_OUT message and see what you can
 * do with it.
 * IPQoS Notes:
 * We do IPPF processing if IPP_LOCAL_OUT is enabled before processing for
 * IPsec.
 * XXX would like to nuke ire_t.
 * XXX ill_index better be "real"
 */
void
ipsec_out_process(queue_t *q, mblk_t *ipsec_mp, ire_t *ire, uint_t ill_index)
{
	ipsec_out_t *io;
	ipsec_policy_t *pp;
	ipsec_action_t *ap;
	ipha_t *ipha;
	ip6_t *ip6h;
	mblk_t *mp;
	ill_t *ill;
	zoneid_t zoneid;
	ipsec_status_t ipsec_rc;
	boolean_t ill_need_rele = B_FALSE;
	ip_stack_t	*ipst;
	ipsec_stack_t	*ipss;

	io = (ipsec_out_t *)ipsec_mp->b_rptr;
	ASSERT(io->ipsec_out_type == IPSEC_OUT);
	ASSERT(io->ipsec_out_len == sizeof (ipsec_out_t));
	ipst = io->ipsec_out_ns->netstack_ip;
	mp = ipsec_mp->b_cont;

	/*
	 * Initiate IPPF processing. We do it here to account for packets
	 * coming here that don't have any policy (i.e. !io->ipsec_out_secure).
	 * We can check for ipsec_out_proc_begin even for such packets, as
	 * they will always be false (asserted below).
	 */
	if (IPP_ENABLED(IPP_LOCAL_OUT, ipst) && !io->ipsec_out_proc_begin) {
		ip_process(IPP_LOCAL_OUT, &mp, io->ipsec_out_ill_index != 0 ?
		    io->ipsec_out_ill_index : ill_index);
		if (mp == NULL) {
			ip2dbg(("ipsec_out_process: packet dropped "\
			    "during IPPF processing\n"));
			freeb(ipsec_mp);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			return;
		}
	}

	if (!io->ipsec_out_secure) {
		/*
		 * We came here by mistake.
		 * Don't bother with ipsec processing
		 * Should "discourage" this path in the future.
		 */
		ASSERT(io->ipsec_out_proc_begin == B_FALSE);
		goto done;
	}
	ASSERT(io->ipsec_out_need_policy == B_FALSE);
	ASSERT((io->ipsec_out_policy != NULL) ||
	    (io->ipsec_out_act != NULL));
	ASSERT(io->ipsec_out_failed == B_FALSE);

	ipss = ipst->ips_netstack->netstack_ipsec;
	if (!ipsec_loaded(ipss)) {
		ipha = (ipha_t *)ipsec_mp->b_cont->b_rptr;
		if (IPH_HDR_VERSION(ipha) == IP_VERSION) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		} else {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutDiscards);
		}
		ip_drop_packet(ipsec_mp, B_FALSE, NULL, ire,
		    DROPPER(ipss, ipds_ip_ipsec_not_loaded),
		    &ipss->ipsec_dropper);
		return;
	}

	/*
	 * IPsec processing has started.
	 */
	io->ipsec_out_proc_begin = B_TRUE;
	ap = io->ipsec_out_act;
	if (ap == NULL) {
		pp = io->ipsec_out_policy;
		ASSERT(pp != NULL);
		ap = pp->ipsp_act;
		ASSERT(ap != NULL);
	}

	/*
	 * Save the outbound ill index. When the packet comes back
	 * from IPsec, we make sure the ill hasn't changed or disappeared
	 * before sending it the accelerated packet.
	 */
	if ((ire != NULL) && (io->ipsec_out_capab_ill_index == 0)) {
		int ifindex;
		ill = ire_to_ill(ire);
		ifindex = ill->ill_phyint->phyint_ifindex;
		io->ipsec_out_capab_ill_index = ifindex;
	}

	/*
	 * The order of processing is first insert a IP header if needed.
	 * Then insert the ESP header and then the AH header.
	 */
	if ((io->ipsec_out_se_done == B_FALSE) &&
	    (ap->ipa_want_se)) {
		/*
		 * First get the outer IP header before sending
		 * it to ESP.
		 */
		ipha_t *oipha, *iipha;
		mblk_t *outer_mp, *inner_mp;

		if ((outer_mp = allocb(sizeof (ipha_t), BPRI_HI)) == NULL) {
			(void) mi_strlog(q, 0, SL_ERROR|SL_TRACE|SL_CONSOLE,
			    "ipsec_out_process: "
			    "Self-Encapsulation failed: Out of memory\n");
			freemsg(ipsec_mp);
			if (ill != NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			} else {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsOutDiscards);
			}
			return;
		}
		inner_mp = ipsec_mp->b_cont;
		ASSERT(inner_mp->b_datap->db_type == M_DATA);
		oipha = (ipha_t *)outer_mp->b_rptr;
		iipha = (ipha_t *)inner_mp->b_rptr;
		*oipha = *iipha;
		outer_mp->b_wptr += sizeof (ipha_t);
		oipha->ipha_length = htons(ntohs(iipha->ipha_length) +
		    sizeof (ipha_t));
		oipha->ipha_protocol = IPPROTO_ENCAP;
		oipha->ipha_version_and_hdr_length =
		    IP_SIMPLE_HDR_VERSION;
		oipha->ipha_hdr_checksum = 0;
		oipha->ipha_hdr_checksum = ip_csum_hdr(oipha);
		outer_mp->b_cont = inner_mp;
		ipsec_mp->b_cont = outer_mp;

		io->ipsec_out_se_done = B_TRUE;
		io->ipsec_out_tunnel = B_TRUE;
	}

	if (((ap->ipa_want_ah && (io->ipsec_out_ah_sa == NULL)) ||
	    (ap->ipa_want_esp && (io->ipsec_out_esp_sa == NULL))) &&
	    !ipsec_out_select_sa(ipsec_mp))
		return;

	/*
	 * By now, we know what SA's to use.  Toss over to ESP & AH
	 * to do the heavy lifting.
	 */
	zoneid = io->ipsec_out_zoneid;
	ASSERT(zoneid != ALL_ZONES);
	if ((io->ipsec_out_esp_done == B_FALSE) && (ap->ipa_want_esp)) {
		ASSERT(io->ipsec_out_esp_sa != NULL);
		io->ipsec_out_esp_done = B_TRUE;
		/*
		 * Note that since hw accel can only apply one transform,
		 * not two, we skip hw accel for ESP if we also have AH
		 * This is an design limitation of the interface
		 * which should be revisited.
		 */
		ASSERT(ire != NULL);
		if (io->ipsec_out_ah_sa == NULL) {
			ill = (ill_t *)ire->ire_stq->q_ptr;
			ipsec_out_is_accelerated(ipsec_mp,
			    io->ipsec_out_esp_sa, ill, ire);
		}

		ipsec_rc = io->ipsec_out_esp_sa->ipsa_output_func(ipsec_mp);
		switch (ipsec_rc) {
		case IPSEC_STATUS_SUCCESS:
			break;
		case IPSEC_STATUS_FAILED:
			if (ill != NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			} else {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsOutDiscards);
			}
			/* FALLTHRU */
		case IPSEC_STATUS_PENDING:
			return;
		}
	}

	if ((io->ipsec_out_ah_done == B_FALSE) && (ap->ipa_want_ah)) {
		ASSERT(io->ipsec_out_ah_sa != NULL);
		io->ipsec_out_ah_done = B_TRUE;
		if (ire == NULL) {
			int idx = io->ipsec_out_capab_ill_index;
			ill = ill_lookup_on_ifindex(idx, B_FALSE,
			    NULL, NULL, NULL, NULL, ipst);
			ill_need_rele = B_TRUE;
		} else {
			ill = (ill_t *)ire->ire_stq->q_ptr;
		}
		ipsec_out_is_accelerated(ipsec_mp, io->ipsec_out_ah_sa, ill,
		    ire);

		ipsec_rc = io->ipsec_out_ah_sa->ipsa_output_func(ipsec_mp);
		switch (ipsec_rc) {
		case IPSEC_STATUS_SUCCESS:
			break;
		case IPSEC_STATUS_FAILED:
			if (ill != NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			} else {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsOutDiscards);
			}
			/* FALLTHRU */
		case IPSEC_STATUS_PENDING:
			if (ill != NULL && ill_need_rele)
				ill_refrele(ill);
			return;
		}
	}
	/*
	 * We are done with IPsec processing. Send it over
	 * the wire.
	 */
done:
	mp = ipsec_mp->b_cont;
	ipha = (ipha_t *)mp->b_rptr;
	if (IPH_HDR_VERSION(ipha) == IP_VERSION) {
		ip_wput_ipsec_out(q, ipsec_mp, ipha, ill, ire);
	} else {
		ip6h = (ip6_t *)ipha;
		ip_wput_ipsec_out_v6(q, ipsec_mp, ip6h, ill, ire);
	}
	if (ill != NULL && ill_need_rele)
		ill_refrele(ill);
}

/* ARGSUSED */
void
ip_restart_optmgmt(ipsq_t *dummy_sq, queue_t *q, mblk_t *first_mp, void *dummy)
{
	opt_restart_t	*or;
	int	err;
	conn_t	*connp;

	ASSERT(CONN_Q(q));
	connp = Q_TO_CONN(q);

	ASSERT(first_mp->b_datap->db_type == M_CTL);
	or = (opt_restart_t *)first_mp->b_rptr;
	/*
	 * We don't need to pass any credentials here since this is just
	 * a restart. The credentials are passed in when svr4_optcom_req
	 * is called the first time (from ip_wput_nondata).
	 */
	if (or->or_type == T_SVR4_OPTMGMT_REQ) {
		err = svr4_optcom_req(q, first_mp, NULL,
		    &ip_opt_obj, B_FALSE);
	} else {
		ASSERT(or->or_type == T_OPTMGMT_REQ);
		err = tpi_optcom_req(q, first_mp, NULL,
		    &ip_opt_obj, B_FALSE);
	}
	if (err != EINPROGRESS) {
		/* operation is done */
		CONN_OPER_PENDING_DONE(connp);
	}
}

/*
 * ioctls that go through a down/up sequence may need to wait for the down
 * to complete. This involves waiting for the ire and ipif refcnts to go down
 * to zero. Subsequently the ioctl is restarted from ipif_ill_refrele_tail.
 */
/* ARGSUSED */
void
ip_reprocess_ioctl(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	struct iocblk *iocp;
	mblk_t *mp1;
	ip_ioctl_cmd_t *ipip;
	int err;
	sin_t	*sin;
	struct lifreq *lifr;
	struct ifreq *ifr;

	iocp = (struct iocblk *)mp->b_rptr;
	ASSERT(ipsq != NULL);
	/* Existence of mp1 verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	ipip = ip_sioctl_lookup(iocp->ioc_cmd);
	if (ipip->ipi_cmd == SIOCSLIFNAME || ipip->ipi_cmd == IF_UNITSEL) {
		/*
		 * Special case where ipsq_current_ipif is not set:
		 * ill_phyint_reinit merged the v4 and v6 into a single ipsq.
		 * ill could also have become part of a ipmp group in the
		 * process, we are here as were not able to complete the
		 * operation in ipif_set_values because we could not become
		 * exclusive on the new ipsq, In such a case ipsq_current_ipif
		 * will not be set so we need to set it.
		 */
		ill_t *ill = q->q_ptr;
		ipsq_current_start(ipsq, ill->ill_ipif, ipip->ipi_cmd);
	}
	ASSERT(ipsq->ipsq_current_ipif != NULL);

	if (ipip->ipi_cmd_type == IF_CMD) {
		/* This a old style SIOC[GS]IF* command */
		ifr = (struct ifreq *)mp1->b_rptr;
		sin = (sin_t *)&ifr->ifr_addr;
	} else if (ipip->ipi_cmd_type == LIF_CMD) {
		/* This a new style SIOC[GS]LIF* command */
		lifr = (struct lifreq *)mp1->b_rptr;
		sin = (sin_t *)&lifr->lifr_addr;
	} else {
		sin = NULL;
	}

	err = (*ipip->ipi_func_restart)(ipsq->ipsq_current_ipif, sin, q, mp,
	    ipip, mp1->b_rptr);

	ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), ipsq);
}

/*
 * ioctl processing
 *
 * ioctl processing starts with ip_sioctl_copyin_setup(), which looks up
 * the ioctl command in the ioctl tables, determines the copyin data size
 * from the ipi_copyin_size field, and does an mi_copyin() of that size.
 *
 * ioctl processing then continues when the M_IOCDATA makes its way down to
 * ip_wput_nondata().  The ioctl is looked up again in the ioctl table, its
 * associated 'conn' is refheld till the end of the ioctl and the general
 * ioctl processing function ip_process_ioctl() is called to extract the
 * arguments and process the ioctl.  To simplify extraction, ioctl commands
 * are "typed" based on the arguments they take (e.g., LIF_CMD which takes a
 * `struct lifreq'), and a common extract function (e.g., ip_extract_lifreq())
 * is used to extract the ioctl's arguments.
 *
 * ip_process_ioctl determines if the ioctl needs to be serialized, and if
 * so goes thru the serialization primitive ipsq_try_enter. Then the
 * appropriate function to handle the ioctl is called based on the entry in
 * the ioctl table. ioctl completion is encapsulated in ip_ioctl_finish
 * which also refreleases the 'conn' that was refheld at the start of the
 * ioctl. Finally ipsq_exit is called if needed to exit the ipsq.
 *
 * Many exclusive ioctls go thru an internal down up sequence as part of
 * the operation. For example an attempt to change the IP address of an
 * ipif entails ipif_down, set address, ipif_up. Bringing down the interface
 * does all the cleanup such as deleting all ires that use this address.
 * Then we need to wait till all references to the interface go away.
 */
void
ip_process_ioctl(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *arg)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	ip_ioctl_cmd_t *ipip = arg;
	ip_extract_func_t *extract_funcp;
	cmd_info_t ci;
	int err;

	ip3dbg(("ip_process_ioctl: ioctl %X\n", iocp->ioc_cmd));

	if (ipip == NULL)
		ipip = ip_sioctl_lookup(iocp->ioc_cmd);

	/*
	 * SIOCLIFADDIF needs to go thru a special path since the
	 * ill may not exist yet. This happens in the case of lo0
	 * which is created using this ioctl.
	 */
	if (ipip->ipi_cmd == SIOCLIFADDIF) {
		err = ip_sioctl_addif(NULL, NULL, q, mp, NULL, NULL);
		ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), NULL);
		return;
	}

	ci.ci_ipif = NULL;
	if (ipip->ipi_cmd_type == MISC_CMD) {
		/*
		 * All MISC_CMD ioctls come in here -- e.g. SIOCGLIFCONF.
		 */
		if (ipip->ipi_cmd == IF_UNITSEL) {
			/* ioctl comes down the ill */
			ci.ci_ipif = ((ill_t *)q->q_ptr)->ill_ipif;
			ipif_refhold(ci.ci_ipif);
		}
		err = 0;
		ci.ci_sin = NULL;
		ci.ci_sin6 = NULL;
		ci.ci_lifr = NULL;
	} else {
		switch (ipip->ipi_cmd_type) {
		case IF_CMD:
		case LIF_CMD:
			extract_funcp = ip_extract_lifreq;
			break;

		case ARP_CMD:
		case XARP_CMD:
			extract_funcp = ip_extract_arpreq;
			break;

		case TUN_CMD:
			extract_funcp = ip_extract_tunreq;
			break;

		case MSFILT_CMD:
			extract_funcp = ip_extract_msfilter;
			break;

		default:
			ASSERT(0);
		}

		err = (*extract_funcp)(q, mp, ipip, &ci, ip_process_ioctl);
		if (err != 0) {
			ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), NULL);
			return;
		}

		/*
		 * All of the extraction functions return a refheld ipif.
		 */
		ASSERT(ci.ci_ipif != NULL);
	}

	if (!(ipip->ipi_flags & IPI_WR)) {
		/*
		 * A return value of EINPROGRESS means the ioctl is
		 * either queued and waiting for some reason or has
		 * already completed.
		 */
		err = (*ipip->ipi_func)(ci.ci_ipif, ci.ci_sin, q, mp, ipip,
		    ci.ci_lifr);
		if (ci.ci_ipif != NULL)
			ipif_refrele(ci.ci_ipif);
		ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), NULL);
		return;
	}

	/*
	 * If ipsq is non-null, we are already being called exclusively on an
	 * ill but in the case of a failover in progress it is the "from" ill,
	 *  rather than the "to" ill (which is the ill ptr passed in).
	 * In order to ensure we are exclusive on both ILLs we rerun
	 * ipsq_try_enter() here, ipsq's support recursive entry.
	 */
	ASSERT(ipsq == NULL || IAM_WRITER_IPSQ(ipsq));
	ASSERT(ci.ci_ipif != NULL);

	ipsq = ipsq_try_enter(ci.ci_ipif, NULL, q, mp, ip_process_ioctl,
	    NEW_OP, B_TRUE);

	/*
	 * Release the ipif so that ipif_down and friends that wait for
	 * references to go away are not misled about the current ipif_refcnt
	 * values. We are writer so we can access the ipif even after releasing
	 * the ipif.
	 */
	ipif_refrele(ci.ci_ipif);
	if (ipsq == NULL)
		return;

	ipsq_current_start(ipsq, ci.ci_ipif, ipip->ipi_cmd);

	/*
	 * For most set ioctls that come here, this serves as a single point
	 * where we set the IPIF_CHANGING flag. This ensures that there won't
	 * be any new references to the ipif. This helps functions that go
	 * through this path and end up trying to wait for the refcnts
	 * associated with the ipif to go down to zero. Some exceptions are
	 * Failover, Failback, and Groupname commands that operate on more than
	 * just the ci.ci_ipif. These commands internally determine the
	 * set of ipif's they operate on and set and clear the IPIF_CHANGING
	 * flags on that set. Another exception is the Removeif command that
	 * sets the IPIF_CONDEMNED flag internally after identifying the right
	 * ipif to operate on.
	 */
	mutex_enter(&(ci.ci_ipif)->ipif_ill->ill_lock);
	if (ipip->ipi_cmd != SIOCLIFREMOVEIF &&
	    ipip->ipi_cmd != SIOCLIFFAILOVER &&
	    ipip->ipi_cmd != SIOCLIFFAILBACK &&
	    ipip->ipi_cmd != SIOCSLIFGROUPNAME)
		(ci.ci_ipif)->ipif_state_flags |= IPIF_CHANGING;
	mutex_exit(&(ci.ci_ipif)->ipif_ill->ill_lock);

	/*
	 * A return value of EINPROGRESS means the ioctl is
	 * either queued and waiting for some reason or has
	 * already completed.
	 */
	err = (*ipip->ipi_func)(ci.ci_ipif, ci.ci_sin, q, mp, ipip, ci.ci_lifr);

	ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), ipsq);

	ipsq_exit(ipsq);
}

/*
 * Complete the ioctl. Typically ioctls use the mi package and need to
 * do mi_copyout/mi_copy_done.
 */
void
ip_ioctl_finish(queue_t *q, mblk_t *mp, int err, int mode, ipsq_t *ipsq)
{
	conn_t	*connp = NULL;

	if (err == EINPROGRESS)
		return;

	if (CONN_Q(q)) {
		connp = Q_TO_CONN(q);
		ASSERT(connp->conn_ref >= 2);
	}

	switch (mode) {
	case COPYOUT:
		if (err == 0)
			mi_copyout(q, mp);
		else
			mi_copy_done(q, mp, err);
		break;

	case NO_COPYOUT:
		mi_copy_done(q, mp, err);
		break;

	default:
		ASSERT(mode == CONN_CLOSE);	/* aborted through CONN_CLOSE */
		break;
	}

	/*
	 * The refhold placed at the start of the ioctl is released here.
	 */
	if (connp != NULL)
		CONN_OPER_PENDING_DONE(connp);

	if (ipsq != NULL)
		ipsq_current_finish(ipsq);
}

/*
 * This is called from ip_wput_nondata to resume a deferred TCP bind.
 */
/* ARGSUSED */
void
ip_resume_tcp_bind(void *arg, mblk_t *mp, void *arg2)
{
	conn_t *connp = arg;
	tcp_t	*tcp;

	ASSERT(connp != NULL && IPCL_IS_TCP(connp) && connp->conn_tcp != NULL);
	tcp = connp->conn_tcp;

	if (connp->conn_tcp->tcp_state == TCPS_CLOSED)
		freemsg(mp);
	else
		tcp_rput_other(tcp, mp);
	CONN_OPER_PENDING_DONE(connp);
}

/* Called from ip_wput for all non data messages */
/* ARGSUSED */
void
ip_wput_nondata(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	mblk_t		*mp1;
	ire_t		*ire, *fake_ire;
	ill_t		*ill;
	struct iocblk	*iocp;
	ip_ioctl_cmd_t	*ipip;
	cred_t		*cr;
	conn_t		*connp;
	int		err;
	nce_t		*nce;
	ipif_t		*ipif;
	ip_stack_t	*ipst;
	char		*proto_str;

	if (CONN_Q(q)) {
		connp = Q_TO_CONN(q);
		ipst = connp->conn_netstack->netstack_ip;
	} else {
		connp = NULL;
		ipst = ILLQ_TO_IPST(q);
	}

	cr = DB_CREDDEF(mp, GET_QUEUE_CRED(q));

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		/*
		 * IOCTL processing begins in ip_sioctl_copyin_setup which
		 * will arrange to copy in associated control structures.
		 */
		ip_sioctl_copyin_setup(q, mp);
		return;
	case M_IOCDATA:
		/*
		 * Ensure that this is associated with one of our trans-
		 * parent ioctls.  If it's not ours, discard it if we're
		 * running as a driver, or pass it on if we're a module.
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		ipip = ip_sioctl_lookup(iocp->ioc_cmd);
		if (ipip == NULL) {
			if (q->q_next == NULL) {
				goto nak;
			} else {
				putnext(q, mp);
			}
			return;
		}
		if ((q->q_next != NULL) && !(ipip->ipi_flags & IPI_MODOK)) {
			/*
			 * the ioctl is one we recognise, but is not
			 * consumed by IP as a module, pass M_IOCDATA
			 * for processing downstream, but only for
			 * common Streams ioctls.
			 */
			if (ipip->ipi_flags & IPI_PASS_DOWN) {
				putnext(q, mp);
				return;
			} else {
				goto nak;
			}
		}

		/* IOCTL continuation following copyin or copyout. */
		if (mi_copy_state(q, mp, NULL) == -1) {
			/*
			 * The copy operation failed.  mi_copy_state already
			 * cleaned up, so we're out of here.
			 */
			return;
		}
		/*
		 * If we just completed a copy in, we become writer and
		 * continue processing in ip_sioctl_copyin_done.  If it
		 * was a copy out, we call mi_copyout again.  If there is
		 * nothing more to copy out, it will complete the IOCTL.
		 */
		if (MI_COPY_DIRECTION(mp) == MI_COPY_IN) {
			if (!(mp1 = mp->b_cont) || !(mp1 = mp1->b_cont)) {
				mi_copy_done(q, mp, EPROTO);
				return;
			}
			/*
			 * Check for cases that need more copying.  A return
			 * value of 0 means a second copyin has been started,
			 * so we return; a return value of 1 means no more
			 * copying is needed, so we continue.
			 */
			if (ipip->ipi_cmd_type == MSFILT_CMD &&
			    MI_COPY_COUNT(mp) == 1) {
				if (ip_copyin_msfilter(q, mp) == 0)
					return;
			}
			/*
			 * Refhold the conn, till the ioctl completes. This is
			 * needed in case the ioctl ends up in the pending mp
			 * list. Every mp in the ill_pending_mp list and
			 * the ipsq_pending_mp must have a refhold on the conn
			 * to resume processing. The refhold is released when
			 * the ioctl completes. (normally or abnormally)
			 * In all cases ip_ioctl_finish is called to finish
			 * the ioctl.
			 */
			if (connp != NULL) {
				/* This is not a reentry */
				ASSERT(ipsq == NULL);
				CONN_INC_REF(connp);
			} else {
				if (!(ipip->ipi_flags & IPI_MODOK)) {
					mi_copy_done(q, mp, EINVAL);
					return;
				}
			}

			ip_process_ioctl(ipsq, q, mp, ipip);

		} else {
			mi_copyout(q, mp);
		}
		return;
nak:
		iocp->ioc_error = EINVAL;
		mp->b_datap->db_type = M_IOCNAK;
		iocp->ioc_count = 0;
		qreply(q, mp);
		return;

	case M_IOCNAK:
		/*
		 * The only way we could get here is if a resolver didn't like
		 * an IOCTL we sent it.	 This shouldn't happen.
		 */
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "ip_wput: unexpected M_IOCNAK, ioc_cmd 0x%x",
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd);
		freemsg(mp);
		return;
	case M_IOCACK:
		/* /dev/ip shouldn't see this */
		if (CONN_Q(q))
			goto nak;

		/* Finish socket ioctls passed through to ARP. */
		ip_sioctl_iocack(q, mp);
		return;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHALL);
		if (q->q_next) {
			putnext(q, mp);
			return;
		}
		if (*mp->b_rptr & FLUSHR) {
			*mp->b_rptr &= ~FLUSHW;
			qreply(q, mp);
			return;
		}
		freemsg(mp);
		return;
	case IRE_DB_REQ_TYPE:
		if (connp == NULL) {
			proto_str = "IRE_DB_REQ_TYPE";
			goto protonak;
		}
		/* An Upper Level Protocol wants a copy of an IRE. */
		ip_ire_req(q, mp);
		return;
	case M_CTL:
		if (mp->b_wptr - mp->b_rptr < sizeof (uint32_t))
			break;

		if (((ipsec_info_t *)mp->b_rptr)->ipsec_info_type ==
		    TUN_HELLO) {
			ASSERT(connp != NULL);
			connp->conn_flags |= IPCL_IPTUN;
			freeb(mp);
			return;
		}

		/* M_CTL messages are used by ARP to tell us things. */
		if ((mp->b_wptr - mp->b_rptr) < sizeof (arc_t))
			break;
		switch (((arc_t *)mp->b_rptr)->arc_cmd) {
		case AR_ENTRY_SQUERY:
			ip_wput_ctl(q, mp);
			return;
		case AR_CLIENT_NOTIFY:
			ip_arp_news(q, mp);
			return;
		case AR_DLPIOP_DONE:
			ASSERT(q->q_next != NULL);
			ill = (ill_t *)q->q_ptr;
			/* qwriter_ip releases the refhold */
			/* refhold on ill stream is ok without ILL_CAN_LOOKUP */
			ill_refhold(ill);
			qwriter_ip(ill, q, mp, ip_arp_done, CUR_OP, B_FALSE);
			return;
		case AR_ARP_CLOSING:
			/*
			 * ARP (above us) is closing. If no ARP bringup is
			 * currently pending, ack the message so that ARP
			 * can complete its close. Also mark ill_arp_closing
			 * so that new ARP bringups will fail. If any
			 * ARP bringup is currently in progress, we will
			 * ack this when the current ARP bringup completes.
			 */
			ASSERT(q->q_next != NULL);
			ill = (ill_t *)q->q_ptr;
			mutex_enter(&ill->ill_lock);
			ill->ill_arp_closing = 1;
			if (!ill->ill_arp_bringup_pending) {
				mutex_exit(&ill->ill_lock);
				qreply(q, mp);
			} else {
				mutex_exit(&ill->ill_lock);
				freemsg(mp);
			}
			return;
		case AR_ARP_EXTEND:
			/*
			 * The ARP module above us is capable of duplicate
			 * address detection.  Old ATM drivers will not send
			 * this message.
			 */
			ASSERT(q->q_next != NULL);
			ill = (ill_t *)q->q_ptr;
			ill->ill_arp_extend = B_TRUE;
			freemsg(mp);
			return;
		default:
			break;
		}
		break;
	case M_PROTO:
	case M_PCPROTO:
		/*
		 * The only PROTO messages we expect are ULP binds and
		 * copies of option negotiation acknowledgements.
		 */
		switch (((union T_primitives *)mp->b_rptr)->type) {
		case O_T_BIND_REQ:
		case T_BIND_REQ: {
			/* Request can get queued in bind */
			if (connp == NULL) {
				proto_str = "O_T_BIND_REQ/T_BIND_REQ";
				goto protonak;
			}
			/*
			 * The transports except SCTP call ip_bind_{v4,v6}()
			 * directly instead of a a putnext. SCTP doesn't
			 * generate any T_BIND_REQ since it has its own
			 * fanout data structures. However, ESP and AH
			 * come in for regular binds; all other cases are
			 * bind retries.
			 */
			ASSERT(!IPCL_IS_SCTP(connp));

			/* Don't increment refcnt if this is a re-entry */
			if (ipsq == NULL)
				CONN_INC_REF(connp);

			mp = connp->conn_af_isv6 ? ip_bind_v6(q, mp,
			    connp, NULL) : ip_bind_v4(q, mp, connp);
			if (mp == NULL)
				return;
			if (IPCL_IS_TCP(connp)) {
				/*
				 * In the case of TCP endpoint we
				 * come here only for bind retries
				 */
				ASSERT(ipsq != NULL);
				CONN_INC_REF(connp);
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
				    ip_resume_tcp_bind, connp,
				    SQ_FILL, SQTAG_BIND_RETRY);
			} else if (IPCL_IS_UDP(connp)) {
				/*
				 * In the case of UDP endpoint we
				 * come here only for bind retries
				 */
				ASSERT(ipsq != NULL);
				udp_resume_bind(connp, mp);
			} else if (IPCL_IS_RAWIP(connp)) {
				/*
				 * In the case of RAWIP endpoint we
				 * come here only for bind retries
				 */
				ASSERT(ipsq != NULL);
				rawip_resume_bind(connp, mp);
			} else {
				/* The case of AH and ESP */
				qreply(q, mp);
				CONN_OPER_PENDING_DONE(connp);
			}
			return;
		}
		case T_SVR4_OPTMGMT_REQ:
			ip2dbg(("ip_wput: T_SVR4_OPTMGMT_REQ flags %x\n",
			    ((struct T_optmgmt_req *)mp->b_rptr)->MGMT_flags));

			if (connp == NULL) {
				proto_str = "T_SVR4_OPTMGMT_REQ";
				goto protonak;
			}

			if (!snmpcom_req(q, mp, ip_snmp_set,
			    ip_snmp_get, cr)) {
				/*
				 * Call svr4_optcom_req so that it can
				 * generate the ack. We don't come here
				 * if this operation is being restarted.
				 * ip_restart_optmgmt will drop the conn ref.
				 * In the case of ipsec option after the ipsec
				 * load is complete conn_restart_ipsec_waiter
				 * drops the conn ref.
				 */
				ASSERT(ipsq == NULL);
				CONN_INC_REF(connp);
				if (ip_check_for_ipsec_opt(q, mp))
					return;
				err = svr4_optcom_req(q, mp, cr, &ip_opt_obj,
				    B_FALSE);
				if (err != EINPROGRESS) {
					/* Operation is done */
					CONN_OPER_PENDING_DONE(connp);
				}
			}
			return;
		case T_OPTMGMT_REQ:
			ip2dbg(("ip_wput: T_OPTMGMT_REQ\n"));
			/*
			 * Note: No snmpcom_req support through new
			 * T_OPTMGMT_REQ.
			 * Call tpi_optcom_req so that it can
			 * generate the ack.
			 */
			if (connp == NULL) {
				proto_str = "T_OPTMGMT_REQ";
				goto protonak;
			}

			ASSERT(ipsq == NULL);
			/*
			 * We don't come here for restart. ip_restart_optmgmt
			 * will drop the conn ref. In the case of ipsec option
			 * after the ipsec load is complete
			 * conn_restart_ipsec_waiter drops the conn ref.
			 */
			CONN_INC_REF(connp);
			if (ip_check_for_ipsec_opt(q, mp))
				return;
			err = tpi_optcom_req(q, mp, cr, &ip_opt_obj, B_FALSE);
			if (err != EINPROGRESS) {
				/* Operation is done */
				CONN_OPER_PENDING_DONE(connp);
			}
			return;
		case T_UNBIND_REQ:
			if (connp == NULL) {
				proto_str = "T_UNBIND_REQ";
				goto protonak;
			}
			mp = ip_unbind(q, mp);
			qreply(q, mp);
			return;
		default:
			/*
			 * Have to drop any DLPI messages coming down from
			 * arp (such as an info_req which would cause ip
			 * to receive an extra info_ack if it was passed
			 * through.
			 */
			ip1dbg(("ip_wput_nondata: dropping M_PROTO %d\n",
			    (int)*(uint_t *)mp->b_rptr));
			freemsg(mp);
			return;
		}
		/* NOTREACHED */
	case IRE_DB_TYPE: {
		nce_t		*nce;
		ill_t		*ill;
		in6_addr_t	gw_addr_v6;


		/*
		 * This is a response back from a resolver.  It
		 * consists of a message chain containing:
		 *	IRE_MBLK-->LL_HDR_MBLK->pkt
		 * The IRE_MBLK is the one we allocated in ip_newroute.
		 * The LL_HDR_MBLK is the DLPI header to use to get
		 * the attached packet, and subsequent ones for the
		 * same destination, transmitted.
		 */
		if ((mp->b_wptr - mp->b_rptr) != sizeof (ire_t))    /* ire */
			break;
		/*
		 * First, check to make sure the resolution succeeded.
		 * If it failed, the second mblk will be empty.
		 * If it is, free the chain, dropping the packet.
		 * (We must ire_delete the ire; that frees the ire mblk)
		 * We're doing this now to support PVCs for ATM; it's
		 * a partial xresolv implementation. When we fully implement
		 * xresolv interfaces, instead of freeing everything here
		 * we'll initiate neighbor discovery.
		 *
		 * For v4 (ARP and other external resolvers) the resolver
		 * frees the message, so no check is needed. This check
		 * is required, though, for a full xresolve implementation.
		 * Including this code here now both shows how external
		 * resolvers can NACK a resolution request using an
		 * existing design that has no specific provisions for NACKs,
		 * and also takes into account that the current non-ARP
		 * external resolver has been coded to use this method of
		 * NACKing for all IPv6 (xresolv) cases,
		 * whether our xresolv implementation is complete or not.
		 *
		 */
		ire = (ire_t *)mp->b_rptr;
		ill = ire_to_ill(ire);
		mp1 = mp->b_cont;		/* dl_unitdata_req */
		if (mp1->b_rptr == mp1->b_wptr) {
			if (ire->ire_ipversion == IPV6_VERSION) {
				/*
				 * XRESOLV interface.
				 */
				ASSERT(ill->ill_flags & ILLF_XRESOLV);
				mutex_enter(&ire->ire_lock);
				gw_addr_v6 = ire->ire_gateway_addr_v6;
				mutex_exit(&ire->ire_lock);
				if (IN6_IS_ADDR_UNSPECIFIED(&gw_addr_v6)) {
					nce = ndp_lookup_v6(ill,
					    &ire->ire_addr_v6, B_FALSE);
				} else {
					nce = ndp_lookup_v6(ill, &gw_addr_v6,
					    B_FALSE);
				}
				if (nce != NULL) {
					nce_resolv_failed(nce);
					ndp_delete(nce);
					NCE_REFRELE(nce);
				}
			}
			mp->b_cont = NULL;
			freemsg(mp1);		/* frees the pkt as well */
			ASSERT(ire->ire_nce == NULL);
			ire_delete((ire_t *)mp->b_rptr);
			return;
		}

		/*
		 * Split them into IRE_MBLK and pkt and feed it into
		 * ire_add_then_send. Then in ire_add_then_send
		 * the IRE will be added, and then the packet will be
		 * run back through ip_wput. This time it will make
		 * it to the wire.
		 */
		mp->b_cont = NULL;
		mp = mp1->b_cont;		/* now, mp points to pkt */
		mp1->b_cont = NULL;
		ip1dbg(("ip_wput_nondata: reply from external resolver \n"));
		if (ire->ire_ipversion == IPV6_VERSION) {
			/*
			 * XRESOLV interface. Find the nce and put a copy
			 * of the dl_unitdata_req in nce_res_mp
			 */
			ASSERT(ill->ill_flags & ILLF_XRESOLV);
			mutex_enter(&ire->ire_lock);
			gw_addr_v6 = ire->ire_gateway_addr_v6;
			mutex_exit(&ire->ire_lock);
			if (IN6_IS_ADDR_UNSPECIFIED(&gw_addr_v6)) {
				nce = ndp_lookup_v6(ill, &ire->ire_addr_v6,
				    B_FALSE);
			} else {
				nce = ndp_lookup_v6(ill, &gw_addr_v6, B_FALSE);
			}
			if (nce != NULL) {
				/*
				 * We have to protect nce_res_mp here
				 * from being accessed by other threads
				 * while we change the mblk pointer.
				 * Other functions will also lock the nce when
				 * accessing nce_res_mp.
				 *
				 * The reason we change the mblk pointer
				 * here rather than copying the resolved address
				 * into the template is that, unlike with
				 * ethernet, we have no guarantee that the
				 * resolved address length will be
				 * smaller than or equal to the lla length
				 * with which the template was allocated,
				 * (for ethernet, they're equal)
				 * so we have to use the actual resolved
				 * address mblk - which holds the real
				 * dl_unitdata_req with the resolved address.
				 *
				 * Doing this is the same behavior as was
				 * previously used in the v4 ARP case.
				 */
				mutex_enter(&nce->nce_lock);
				if (nce->nce_res_mp != NULL)
					freemsg(nce->nce_res_mp);
				nce->nce_res_mp = mp1;
				mutex_exit(&nce->nce_lock);
				/*
				 * We do a fastpath probe here because
				 * we have resolved the address without
				 * using Neighbor Discovery.
				 * In the non-XRESOLV v6 case, the fastpath
				 * probe is done right after neighbor
				 * discovery completes.
				 */
				if (nce->nce_res_mp != NULL) {
					int res;
					nce_fastpath_list_add(nce);
					res = ill_fastpath_probe(ill,
					    nce->nce_res_mp);
					if (res != 0 && res != EAGAIN)
						nce_fastpath_list_delete(nce);
				}

				ire_add_then_send(q, ire, mp);
				/*
				 * Now we have to clean out any packets
				 * that may have been queued on the nce
				 * while it was waiting for address resolution
				 * to complete.
				 */
				mutex_enter(&nce->nce_lock);
				mp1 = nce->nce_qd_mp;
				nce->nce_qd_mp = NULL;
				mutex_exit(&nce->nce_lock);
				while (mp1 != NULL) {
					mblk_t *nxt_mp;
					queue_t *fwdq = NULL;
					ill_t   *inbound_ill;
					uint_t ifindex;

					nxt_mp = mp1->b_next;
					mp1->b_next = NULL;
					/*
					 * Retrieve ifindex stored in
					 * ip_rput_data_v6()
					 */
					ifindex =
					    (uint_t)(uintptr_t)mp1->b_prev;
					inbound_ill =
					    ill_lookup_on_ifindex(ifindex,
					    B_TRUE, NULL, NULL, NULL,
					    NULL, ipst);
					mp1->b_prev = NULL;
					if (inbound_ill != NULL)
						fwdq = inbound_ill->ill_rq;

					if (fwdq != NULL) {
						put(fwdq, mp1);
						ill_refrele(inbound_ill);
					} else
						put(WR(ill->ill_rq), mp1);
					mp1 = nxt_mp;
				}
				NCE_REFRELE(nce);
			} else {	/* nce is NULL; clean up */
				ire_delete(ire);
				freemsg(mp);
				freemsg(mp1);
				return;
			}
		} else {
			nce_t *arpce;
			/*
			 * Link layer resolution succeeded. Recompute the
			 * ire_nce.
			 */
			ASSERT(ire->ire_type & (IRE_CACHE|IRE_BROADCAST));
			if ((arpce = ndp_lookup_v4(ill,
			    (ire->ire_gateway_addr != INADDR_ANY ?
			    &ire->ire_gateway_addr : &ire->ire_addr),
			    B_FALSE)) == NULL) {
				freeb(ire->ire_mp);
				freeb(mp1);
				freemsg(mp);
				return;
			}
			mutex_enter(&arpce->nce_lock);
			arpce->nce_last = TICK_TO_MSEC(lbolt64);
			if (arpce->nce_state == ND_REACHABLE) {
				/*
				 * Someone resolved this before us;
				 * cleanup the res_mp. Since ire has
				 * not been added yet, the call to ire_add_v4
				 * from ire_add_then_send (when a dup is
				 * detected) will clean up the ire.
				 */
				freeb(mp1);
			} else {
				ASSERT(arpce->nce_res_mp == NULL);
				arpce->nce_res_mp = mp1;
				arpce->nce_state = ND_REACHABLE;
			}
			mutex_exit(&arpce->nce_lock);
			if (ire->ire_marks & IRE_MARK_NOADD) {
				/*
				 * this ire will not be added to the ire
				 * cache table, so we can set the ire_nce
				 * here, as there are no atomicity constraints.
				 */
				ire->ire_nce = arpce;
				/*
				 * We are associating this nce with the ire
				 * so change the nce ref taken in
				 * ndp_lookup_v4() from
				 * NCE_REFHOLD to NCE_REFHOLD_NOTR
				 */
				NCE_REFHOLD_TO_REFHOLD_NOTR(ire->ire_nce);
			} else {
				NCE_REFRELE(arpce);
			}
			ire_add_then_send(q, ire, mp);
		}
		return;	/* All is well, the packet has been sent. */
	}
	case IRE_ARPRESOLVE_TYPE: {

		if ((mp->b_wptr - mp->b_rptr) != sizeof (ire_t)) /* fake_ire */
			break;
		mp1 = mp->b_cont;		/* dl_unitdata_req */
		mp->b_cont = NULL;
		/*
		 * First, check to make sure the resolution succeeded.
		 * If it failed, the second mblk will be empty.
		 */
		if (mp1->b_rptr == mp1->b_wptr) {
			/* cleanup  the incomplete ire, free queued packets */
			freemsg(mp); /* fake ire */
			freeb(mp1);  /* dl_unitdata response */
			return;
		}

		/*
		 * Update any incomplete nce_t found. We search the ctable
		 * and find the nce from the ire->ire_nce because we need
		 * to pass the ire to ip_xmit_v4 later, and can find both
		 * ire and nce in one lookup.
		 */
		fake_ire = (ire_t *)mp->b_rptr;

		/*
		 * By the time we come back here from ARP the incomplete ire
		 * created in ire_forward() could have been removed. We use
		 * the parameters stored in the fake_ire to specify the real
		 * ire as explicitly as possible. This avoids problems when
		 * IPMP groups are configured as an ipif can 'float'
		 * across several ill queues. We can be confident that the
		 * the inability to find an ire is because it no longer exists.
		 */
		ill = ill_lookup_on_ifindex(fake_ire->ire_ipif_ifindex, B_FALSE,
		    NULL, NULL, NULL, NULL, ipst);
		if (ill == NULL) {
			ip1dbg(("ill for incomplete ire vanished\n"));
			freemsg(mp); /* fake ire */
			freeb(mp1);  /* dl_unitdata response */
			return;
		}

		/* Get the outgoing ipif */
		mutex_enter(&ill->ill_lock);
		ipif = ipif_lookup_seqid(ill, fake_ire->ire_ipif_seqid);
		if (ipif == NULL) {
			mutex_exit(&ill->ill_lock);
			ill_refrele(ill);
			ip1dbg(("logical intrf to incomplete ire vanished\n"));
			freemsg(mp); /* fake_ire */
			freeb(mp1);  /* dl_unitdata response */
			return;
		}

		ipif_refhold_locked(ipif);
		mutex_exit(&ill->ill_lock);
		ill_refrele(ill);
		ire = ire_arpresolve_lookup(fake_ire->ire_addr,
		    fake_ire->ire_gateway_addr, ipif, fake_ire->ire_zoneid,
		    ipst, ((ill_t *)q->q_ptr)->ill_wq);
		ipif_refrele(ipif);
		if (ire == NULL) {
			/*
			 * no ire was found; check if there is an nce
			 * for this lookup; if it has no ire's pointing at it
			 * cleanup.
			 */
			if ((nce = ndp_lookup_v4(q->q_ptr,
			    (fake_ire->ire_gateway_addr != INADDR_ANY ?
			    &fake_ire->ire_gateway_addr : &fake_ire->ire_addr),
			    B_FALSE)) != NULL) {
				/*
				 * cleanup:
				 * We check for refcnt 2 (one for the nce
				 * hash list + 1 for the ref taken by
				 * ndp_lookup_v4) to check that there are
				 * no ire's pointing at the nce.
				 */
				if (nce->nce_refcnt == 2)
					ndp_delete(nce);
				NCE_REFRELE(nce);
			}
			freeb(mp1);  /* dl_unitdata response */
			freemsg(mp); /* fake ire */
			return;
		}
		nce = ire->ire_nce;
		DTRACE_PROBE2(ire__arpresolve__type,
		    ire_t *, ire, nce_t *, nce);
		ASSERT(nce->nce_state != ND_INITIAL);
		mutex_enter(&nce->nce_lock);
		nce->nce_last = TICK_TO_MSEC(lbolt64);
		if (nce->nce_state == ND_REACHABLE) {
			/*
			 * Someone resolved this before us;
			 * our response is not needed any more.
			 */
			mutex_exit(&nce->nce_lock);
			freeb(mp1);  /* dl_unitdata response */
		} else {
			ASSERT(nce->nce_res_mp == NULL);
			nce->nce_res_mp = mp1;
			nce->nce_state = ND_REACHABLE;
			mutex_exit(&nce->nce_lock);
			nce_fastpath(nce);
		}
		/*
		 * The cached nce_t has been updated to be reachable;
		 * Clear the IRE_MARK_UNCACHED flag and free the fake_ire.
		 */
		fake_ire->ire_marks &= ~IRE_MARK_UNCACHED;
		freemsg(mp);
		/*
		 * send out queued packets.
		 */
		(void) ip_xmit_v4(NULL, ire, NULL, B_FALSE, NULL);

		IRE_REFRELE(ire);
		return;
	}
	default:
		break;
	}
	if (q->q_next) {
		putnext(q, mp);
	} else
		freemsg(mp);
	return;

protonak:
	cmn_err(CE_NOTE, "IP doesn't process %s as a module", proto_str);
	if ((mp = mi_tpi_err_ack_alloc(mp, TPROTO, EINVAL)) != NULL)
		qreply(q, mp);
}

/*
 * Process IP options in an outbound packet.  Modify the destination if there
 * is a source route option.
 * Returns non-zero if something fails in which case an ICMP error has been
 * sent and mp freed.
 */
static int
ip_wput_options(queue_t *q, mblk_t *ipsec_mp, ipha_t *ipha,
    boolean_t mctl_present, zoneid_t zoneid, ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	intptr_t	code = 0;
	mblk_t		*mp;
	ire_t		*ire = NULL;

	ip2dbg(("ip_wput_options\n"));
	mp = ipsec_mp;
	if (mctl_present) {
		mp = ipsec_mp->b_cont;
	}

	dst = ipha->ipha_dst;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_wput_options: opt %d, len %d\n",
		    optval, optlen));
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_wput_options: bad option offset\n"));
				code = (char *)&opt[IPOPT_OLEN] -
				    (char *)ipha;
				goto param_prob;
			}
			off = opt[IPOPT_OFFSET];
			ip1dbg(("ip_wput_options: next hop 0x%x\n",
			    ntohl(dst)));
			/*
			 * For strict: verify that dst is directly
			 * reachable.
			 */
			if (optval == IPOPT_SSRR) {
				ire = ire_ftable_lookup(dst, 0, 0,
				    IRE_INTERFACE, NULL, NULL, ALL_ZONES, 0,
				    MBLK_GETLABEL(mp),
				    MATCH_IRE_TYPE | MATCH_IRE_SECATTR, ipst);
				if (ire == NULL) {
					ip1dbg(("ip_wput_options: SSRR not"
					    " directly reachable: 0x%x\n",
					    ntohl(dst)));
					goto bad_src_route;
				}
				ire_refrele(ire);
			}
			break;
		case IPOPT_RR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_wput_options: bad option offset\n"));
				code = (char *)&opt[IPOPT_OLEN] -
				    (char *)ipha;
				goto param_prob;
			}
			break;
		case IPOPT_TS:
			/*
			 * Verify that length >=5 and that there is either
			 * room for another timestamp or that the overflow
			 * counter is not maxed out.
			 */
			code = (char *)&opt[IPOPT_OLEN] - (char *)ipha;
			if (optlen < IPOPT_MINLEN_IT) {
				goto param_prob;
			}
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_wput_options: bad option offset\n"));
				code = (char *)&opt[IPOPT_OFFSET] -
				    (char *)ipha;
				goto param_prob;
			}
			switch (opt[IPOPT_POS_OV_FLG] & 0x0F) {
			case IPOPT_TS_TSONLY:
				off = IPOPT_TS_TIMELEN;
				break;
			case IPOPT_TS_TSANDADDR:
			case IPOPT_TS_PRESPEC:
			case IPOPT_TS_PRESPEC_RFC791:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				code = (char *)&opt[IPOPT_POS_OV_FLG] -
				    (char *)ipha;
				goto param_prob;
			}
			if (opt[IPOPT_OFFSET] - 1 + off > optlen &&
			    (opt[IPOPT_POS_OV_FLG] & 0xF0) == 0xF0) {
				/*
				 * No room and the overflow counter is 15
				 * already.
				 */
				goto param_prob;
			}
			break;
		}
	}

	if ((opts.ipoptp_flags & IPOPTP_ERROR) == 0)
		return (0);

	ip1dbg(("ip_wput_options: error processing IP options."));
	code = (char *)&opt[IPOPT_OFFSET] - (char *)ipha;

param_prob:
	/*
	 * Since ip_wput() isn't close to finished, we fill
	 * in enough of the header for credible error reporting.
	 */
	if (ip_hdr_complete((ipha_t *)mp->b_rptr, zoneid, ipst)) {
		/* Failed */
		freemsg(ipsec_mp);
		return (-1);
	}
	icmp_param_problem(q, ipsec_mp, (uint8_t)code, zoneid, ipst);
	return (-1);

bad_src_route:
	/*
	 * Since ip_wput() isn't close to finished, we fill
	 * in enough of the header for credible error reporting.
	 */
	if (ip_hdr_complete((ipha_t *)mp->b_rptr, zoneid, ipst)) {
		/* Failed */
		freemsg(ipsec_mp);
		return (-1);
	}
	icmp_unreachable(q, ipsec_mp, ICMP_SOURCE_ROUTE_FAILED, zoneid, ipst);
	return (-1);
}

/*
 * The maximum value of conn_drain_list_cnt is CONN_MAXDRAINCNT.
 * conn_drain_list_cnt can be changed by setting conn_drain_nthreads
 * thru /etc/system.
 */
#define	CONN_MAXDRAINCNT	64

static void
conn_drain_init(ip_stack_t *ipst)
{
	int i;

	ipst->ips_conn_drain_list_cnt = conn_drain_nthreads;

	if ((ipst->ips_conn_drain_list_cnt == 0) ||
	    (ipst->ips_conn_drain_list_cnt > CONN_MAXDRAINCNT)) {
		/*
		 * Default value of the number of drainers is the
		 * number of cpus, subject to maximum of 8 drainers.
		 */
		if (boot_max_ncpus != -1)
			ipst->ips_conn_drain_list_cnt = MIN(boot_max_ncpus, 8);
		else
			ipst->ips_conn_drain_list_cnt = MIN(max_ncpus, 8);
	}

	ipst->ips_conn_drain_list = kmem_zalloc(ipst->ips_conn_drain_list_cnt *
	    sizeof (idl_t), KM_SLEEP);

	for (i = 0; i < ipst->ips_conn_drain_list_cnt; i++) {
		mutex_init(&ipst->ips_conn_drain_list[i].idl_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
}

static void
conn_drain_fini(ip_stack_t *ipst)
{
	int i;

	for (i = 0; i < ipst->ips_conn_drain_list_cnt; i++)
		mutex_destroy(&ipst->ips_conn_drain_list[i].idl_lock);
	kmem_free(ipst->ips_conn_drain_list,
	    ipst->ips_conn_drain_list_cnt * sizeof (idl_t));
	ipst->ips_conn_drain_list = NULL;
}

/*
 * Note: For an overview of how flowcontrol is handled in IP please see the
 * IP Flowcontrol notes at the top of this file.
 *
 * Flow control has blocked us from proceeding. Insert the given conn in one
 * of the conn drain lists. These conn wq's will be qenabled later on when
 * STREAMS flow control does a backenable. conn_walk_drain will enable
 * the first conn in each of these drain lists. Each of these qenabled conns
 * in turn enables the next in the list, after it runs, or when it closes,
 * thus sustaining the drain process.
 *
 * The only possible calling sequence is ip_wsrv (on conn) -> ip_wput ->
 * conn_drain_insert. Thus there can be only 1 instance of conn_drain_insert
 * running at any time, on a given conn, since there can be only 1 service proc
 * running on a queue at any time.
 */
void
conn_drain_insert(conn_t *connp)
{
	idl_t	*idl;
	uint_t	index;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	mutex_enter(&connp->conn_lock);
	if (connp->conn_state_flags & CONN_CLOSING) {
		/*
		 * The conn is closing as a result of which CONN_CLOSING
		 * is set. Return.
		 */
		mutex_exit(&connp->conn_lock);
		return;
	} else if (connp->conn_idl == NULL) {
		/*
		 * Assign the next drain list round robin. We dont' use
		 * a lock, and thus it may not be strictly round robin.
		 * Atomicity of load/stores is enough to make sure that
		 * conn_drain_list_index is always within bounds.
		 */
		index = ipst->ips_conn_drain_list_index;
		ASSERT(index < ipst->ips_conn_drain_list_cnt);
		connp->conn_idl = &ipst->ips_conn_drain_list[index];
		index++;
		if (index == ipst->ips_conn_drain_list_cnt)
			index = 0;
		ipst->ips_conn_drain_list_index = index;
	}
	mutex_exit(&connp->conn_lock);

	mutex_enter(CONN_DRAIN_LIST_LOCK(connp));
	if ((connp->conn_drain_prev != NULL) ||
	    (connp->conn_state_flags & CONN_CLOSING)) {
		/*
		 * The conn is already in the drain list, OR
		 * the conn is closing. We need to check again for
		 * the closing case again since close can happen
		 * after we drop the conn_lock, and before we
		 * acquire the CONN_DRAIN_LIST_LOCK.
		 */
		mutex_exit(CONN_DRAIN_LIST_LOCK(connp));
		return;
	} else {
		idl = connp->conn_idl;
	}

	/*
	 * The conn is not in the drain list. Insert it at the
	 * tail of the drain list. The drain list is circular
	 * and doubly linked. idl_conn points to the 1st element
	 * in the list.
	 */
	if (idl->idl_conn == NULL) {
		idl->idl_conn = connp;
		connp->conn_drain_next = connp;
		connp->conn_drain_prev = connp;
	} else {
		conn_t *head = idl->idl_conn;

		connp->conn_drain_next = head;
		connp->conn_drain_prev = head->conn_drain_prev;
		head->conn_drain_prev->conn_drain_next = connp;
		head->conn_drain_prev = connp;
	}
	mutex_exit(CONN_DRAIN_LIST_LOCK(connp));
}

/*
 * This conn is closing, and we are called from ip_close. OR
 * This conn has been serviced by ip_wsrv, and we need to do the tail
 * processing.
 * If this conn is part of the drain list, we may need to sustain the drain
 * process by qenabling the next conn in the drain list. We may also need to
 * remove this conn from the list, if it is done.
 */
static void
conn_drain_tail(conn_t *connp, boolean_t closing)
{
	idl_t *idl;

	/*
	 * connp->conn_idl is stable at this point, and no lock is needed
	 * to check it. If we are called from ip_close, close has already
	 * set CONN_CLOSING, thus freezing the value of conn_idl, and
	 * called us only because conn_idl is non-null. If we are called thru
	 * service, conn_idl could be null, but it cannot change because
	 * service is single-threaded per queue, and there cannot be another
	 * instance of service trying to call conn_drain_insert on this conn
	 * now.
	 */
	ASSERT(!closing || (connp->conn_idl != NULL));

	/*
	 * If connp->conn_idl is null, the conn has not been inserted into any
	 * drain list even once since creation of the conn. Just return.
	 */
	if (connp->conn_idl == NULL)
		return;

	mutex_enter(CONN_DRAIN_LIST_LOCK(connp));

	if (connp->conn_drain_prev == NULL) {
		/* This conn is currently not in the drain list.  */
		mutex_exit(CONN_DRAIN_LIST_LOCK(connp));
		return;
	}
	idl = connp->conn_idl;
	if (idl->idl_conn_draining == connp) {
		/*
		 * This conn is the current drainer. If this is the last conn
		 * in the drain list, we need to do more checks, in the 'if'
		 * below. Otherwwise we need to just qenable the next conn,
		 * to sustain the draining, and is handled in the 'else'
		 * below.
		 */
		if (connp->conn_drain_next == idl->idl_conn) {
			/*
			 * This conn is the last in this list. This round
			 * of draining is complete. If idl_repeat is set,
			 * it means another flow enabling has happened from
			 * the driver/streams and we need to another round
			 * of draining.
			 * If there are more than 2 conns in the drain list,
			 * do a left rotate by 1, so that all conns except the
			 * conn at the head move towards the head by 1, and the
			 * the conn at the head goes to the tail. This attempts
			 * a more even share for all queues that are being
			 * drained.
			 */
			if ((connp->conn_drain_next != connp) &&
			    (idl->idl_conn->conn_drain_next != connp)) {
				idl->idl_conn = idl->idl_conn->conn_drain_next;
			}
			if (idl->idl_repeat) {
				qenable(idl->idl_conn->conn_wq);
				idl->idl_conn_draining = idl->idl_conn;
				idl->idl_repeat = 0;
			} else {
				idl->idl_conn_draining = NULL;
			}
		} else {
			/*
			 * If the next queue that we are now qenable'ing,
			 * is closing, it will remove itself from this list
			 * and qenable the subsequent queue in ip_close().
			 * Serialization is acheived thru idl_lock.
			 */
			qenable(connp->conn_drain_next->conn_wq);
			idl->idl_conn_draining = connp->conn_drain_next;
		}
	}
	if (!connp->conn_did_putbq || closing) {
		/*
		 * Remove ourself from the drain list, if we did not do
		 * a putbq, or if the conn is closing.
		 * Note: It is possible that q->q_first is non-null. It means
		 * that these messages landed after we did a enableok() in
		 * ip_wsrv. Thus STREAMS will call ip_wsrv once again to
		 * service them.
		 */
		if (connp->conn_drain_next == connp) {
			/* Singleton in the list */
			ASSERT(connp->conn_drain_prev == connp);
			idl->idl_conn = NULL;
			idl->idl_conn_draining = NULL;
		} else {
			connp->conn_drain_prev->conn_drain_next =
			    connp->conn_drain_next;
			connp->conn_drain_next->conn_drain_prev =
			    connp->conn_drain_prev;
			if (idl->idl_conn == connp)
				idl->idl_conn = connp->conn_drain_next;
			ASSERT(idl->idl_conn_draining != connp);

		}
		connp->conn_drain_next = NULL;
		connp->conn_drain_prev = NULL;
	}
	mutex_exit(CONN_DRAIN_LIST_LOCK(connp));
}

/*
 * Write service routine. Shared perimeter entry point.
 * ip_wsrv can be called in any of the following ways.
 * 1. The device queue's messages has fallen below the low water mark
 *    and STREAMS has backenabled the ill_wq. We walk thru all the
 *    the drain lists and backenable the first conn in each list.
 * 2. The above causes STREAMS to run ip_wsrv on the conn_wq of the
 *    qenabled non-tcp upper layers. We start dequeing messages and call
 *    ip_wput for each message.
 */

void
ip_wsrv(queue_t *q)
{
	conn_t	*connp;
	ill_t	*ill;
	mblk_t	*mp;

	if (q->q_next) {
		ill = (ill_t *)q->q_ptr;
		if (ill->ill_state_flags == 0) {
			/*
			 * The device flow control has opened up.
			 * Walk through conn drain lists and qenable the
			 * first conn in each list. This makes sense only
			 * if the stream is fully plumbed and setup.
			 * Hence the if check above.
			 */
			ip1dbg(("ip_wsrv: walking\n"));
			conn_walk_drain(ill->ill_ipst);
		}
		return;
	}

	connp = Q_TO_CONN(q);
	ip1dbg(("ip_wsrv: %p %p\n", (void *)q, (void *)connp));

	/*
	 * 1. Set conn_draining flag to signal that service is active.
	 *
	 * 2. ip_output determines whether it has been called from service,
	 *    based on the last parameter. If it is IP_WSRV it concludes it
	 *    has been called from service.
	 *
	 * 3. Message ordering is preserved by the following logic.
	 *    i. A directly called ip_output (i.e. not thru service) will queue
	 *    the message at the tail, if conn_draining is set (i.e. service
	 *    is running) or if q->q_first is non-null.
	 *
	 *    ii. If ip_output is called from service, and if ip_output cannot
	 *    putnext due to flow control, it does a putbq.
	 *
	 * 4. noenable the queue so that a putbq from ip_wsrv does not reenable
	 *    (causing an infinite loop).
	 */
	ASSERT(!connp->conn_did_putbq);
	while ((q->q_first != NULL) && !connp->conn_did_putbq) {
		connp->conn_draining = 1;
		noenable(q);
		while ((mp = getq(q)) != NULL) {
			ASSERT(CONN_Q(q));

			ip_output(Q_TO_CONN(q), mp, q, IP_WSRV);
			if (connp->conn_did_putbq) {
				/* ip_wput did a putbq */
				break;
			}
		}
		/*
		 * At this point, a thread coming down from top, calling
		 * ip_wput, may end up queueing the message. We have not yet
		 * enabled the queue, so ip_wsrv won't be called again.
		 * To avoid this race, check q->q_first again (in the loop)
		 * If the other thread queued the message before we call
		 * enableok(), we will catch it in the q->q_first check.
		 * If the other thread queues the message after we call
		 * enableok(), ip_wsrv will be called again by STREAMS.
		 */
		connp->conn_draining = 0;
		enableok(q);
	}

	/* Enable the next conn for draining */
	conn_drain_tail(connp, B_FALSE);

	connp->conn_did_putbq = 0;
}

/*
 * Callback to disable flow control in IP.
 *
 * This is a mac client callback added when the DLD_CAPAB_DIRECT capability
 * is enabled.
 *
 * When MAC_TX() is not able to send any more packets, dld sets its queue
 * to QFULL and enable the STREAMS flow control. Later, when the underlying
 * driver is able to continue to send packets, it calls mac_tx_(ring_)update()
 * function and wakes up corresponding mac worker threads, which in turn
 * calls this callback function, and disables flow control.
 */
/* ARGSUSED */
void
ill_flow_enable(void *ill, ip_mac_tx_cookie_t cookie)
{
	qenable(((ill_t *)ill)->ill_wq);
}

/*
 * Walk the list of all conn's calling the function provided with the
 * specified argument for each.	 Note that this only walks conn's that
 * have been bound.
 * Applies to both IPv4 and IPv6.
 */
static void
conn_walk_fanout(pfv_t func, void *arg, zoneid_t zoneid, ip_stack_t *ipst)
{
	conn_walk_fanout_table(ipst->ips_ipcl_udp_fanout,
	    ipst->ips_ipcl_udp_fanout_size,
	    func, arg, zoneid);
	conn_walk_fanout_table(ipst->ips_ipcl_conn_fanout,
	    ipst->ips_ipcl_conn_fanout_size,
	    func, arg, zoneid);
	conn_walk_fanout_table(ipst->ips_ipcl_bind_fanout,
	    ipst->ips_ipcl_bind_fanout_size,
	    func, arg, zoneid);
	conn_walk_fanout_table(ipst->ips_ipcl_proto_fanout,
	    IPPROTO_MAX, func, arg, zoneid);
	conn_walk_fanout_table(ipst->ips_ipcl_proto_fanout_v6,
	    IPPROTO_MAX, func, arg, zoneid);
}

/*
 * Flowcontrol has relieved, and STREAMS has backenabled us. For each list
 * of conns that need to be drained, check if drain is already in progress.
 * If so set the idl_repeat bit, indicating that the last conn in the list
 * needs to reinitiate the drain once again, for the list. If drain is not
 * in progress for the list, initiate the draining, by qenabling the 1st
 * conn in the list. The drain is self-sustaining, each qenabled conn will
 * in turn qenable the next conn, when it is done/blocked/closing.
 */
static void
conn_walk_drain(ip_stack_t *ipst)
{
	int i;
	idl_t *idl;

	IP_STAT(ipst, ip_conn_walk_drain);

	for (i = 0; i < ipst->ips_conn_drain_list_cnt; i++) {
		idl = &ipst->ips_conn_drain_list[i];
		mutex_enter(&idl->idl_lock);
		if (idl->idl_conn == NULL) {
			mutex_exit(&idl->idl_lock);
			continue;
		}
		/*
		 * If this list is not being drained currently by
		 * an ip_wsrv thread, start the process.
		 */
		if (idl->idl_conn_draining == NULL) {
			ASSERT(idl->idl_repeat == 0);
			qenable(idl->idl_conn->conn_wq);
			idl->idl_conn_draining = idl->idl_conn;
		} else {
			idl->idl_repeat = 1;
		}
		mutex_exit(&idl->idl_lock);
	}
}

/*
 * Walk an conn hash table of `count' buckets, calling func for each entry.
 */
static void
conn_walk_fanout_table(connf_t *connfp, uint_t count, pfv_t func, void *arg,
    zoneid_t zoneid)
{
	conn_t	*connp;

	while (count-- > 0) {
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (zoneid == GLOBAL_ZONEID ||
			    zoneid == connp->conn_zoneid) {
				CONN_INC_REF(connp);
				mutex_exit(&connfp->connf_lock);
				(*func)(connp, arg);
				mutex_enter(&connfp->connf_lock);
				CONN_DEC_REF(connp);
			}
		}
		mutex_exit(&connfp->connf_lock);
		connfp++;
	}
}

/* conn_walk_fanout routine invoked for ip_conn_report for each conn. */
static void
conn_report1(conn_t *connp, void *mp)
{
	char	buf1[INET6_ADDRSTRLEN];
	char	buf2[INET6_ADDRSTRLEN];
	uint_t	print_len, buf_len;

	ASSERT(connp != NULL);

	buf_len = ((mblk_t *)mp)->b_datap->db_lim - ((mblk_t *)mp)->b_wptr;
	if (buf_len <= 0)
		return;
	(void) inet_ntop(AF_INET6, &connp->conn_srcv6, buf1, sizeof (buf1));
	(void) inet_ntop(AF_INET6, &connp->conn_remv6, buf2, sizeof (buf2));
	print_len = snprintf((char *)((mblk_t *)mp)->b_wptr, buf_len,
	    MI_COL_PTRFMT_STR MI_COL_PTRFMT_STR MI_COL_PTRFMT_STR
	    "%5d %s/%05d %s/%05d\n",
	    (void *)connp, (void *)CONNP_TO_RQ(connp),
	    (void *)CONNP_TO_WQ(connp), connp->conn_zoneid,
	    buf1, connp->conn_lport,
	    buf2, connp->conn_fport);
	if (print_len < buf_len) {
		((mblk_t *)mp)->b_wptr += print_len;
	} else {
		((mblk_t *)mp)->b_wptr += buf_len;
	}
}

/*
 * Named Dispatch routine to produce a formatted report on all conns
 * that are listed in one of the fanout tables.
 * This report is accessed by using the ndd utility to "get" ND variable
 * "ip_conn_status".
 */
/* ARGSUSED */
static int
ip_conn_report(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *ioc_cr)
{
	conn_t *connp = Q_TO_CONN(q);

	(void) mi_mpprintf(mp,
	    "CONN      " MI_COL_HDRPAD_STR
	    "rfq      " MI_COL_HDRPAD_STR
	    "stq      " MI_COL_HDRPAD_STR
	    " zone local                 remote");

	/*
	 * Because of the ndd constraint, at most we can have 64K buffer
	 * to put in all conn info.  So to be more efficient, just
	 * allocate a 64K buffer here, assuming we need that large buffer.
	 * This should be OK as only privileged processes can do ndd /dev/ip.
	 */
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, "<< Out of buffer >>\n");
		return (0);
	}

	conn_walk_fanout(conn_report1, mp->b_cont, connp->conn_zoneid,
	    connp->conn_netstack->netstack_ip);
	return (0);
}

/*
 * Determine if the ill and multicast aspects of that packets
 * "matches" the conn.
 */
boolean_t
conn_wantpacket(conn_t *connp, ill_t *ill, ipha_t *ipha, int fanout_flags,
    zoneid_t zoneid)
{
	ill_t *in_ill;
	boolean_t found;
	ipif_t *ipif;
	ire_t *ire;
	ipaddr_t dst, src;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	dst = ipha->ipha_dst;
	src = ipha->ipha_src;

	/*
	 * conn_incoming_ill is set by IP_BOUND_IF which limits
	 * unicast, broadcast and multicast reception to
	 * conn_incoming_ill. conn_wantpacket itself is called
	 * only for BROADCAST and multicast.
	 *
	 * 1) ip_rput supresses duplicate broadcasts if the ill
	 *    is part of a group. Hence, we should be receiving
	 *    just one copy of broadcast for the whole group.
	 *    Thus, if it is part of the group the packet could
	 *    come on any ill of the group and hence we need a
	 *    match on the group. Otherwise, match on ill should
	 *    be sufficient.
	 *
	 * 2) ip_rput does not suppress duplicate multicast packets.
	 *    If there are two interfaces in a ill group and we have
	 *    2 applications (conns) joined a multicast group G on
	 *    both the interfaces, ilm_lookup_ill filter in ip_rput
	 *    will give us two packets because we join G on both the
	 *    interfaces rather than nominating just one interface
	 *    for receiving multicast like broadcast above. So,
	 *    we have to call ilg_lookup_ill to filter out duplicate
	 *    copies, if ill is part of a group.
	 */
	in_ill = connp->conn_incoming_ill;
	if (in_ill != NULL) {
		if (in_ill->ill_group == NULL) {
			if (in_ill != ill)
				return (B_FALSE);
		} else if (in_ill->ill_group != ill->ill_group) {
			return (B_FALSE);
		}
	}

	if (!CLASSD(dst)) {
		if (IPCL_ZONE_MATCH(connp, zoneid))
			return (B_TRUE);
		/*
		 * The conn is in a different zone; we need to check that this
		 * broadcast address is configured in the application's zone and
		 * on one ill in the group.
		 */
		ipif = ipif_get_next_ipif(NULL, ill);
		if (ipif == NULL)
			return (B_FALSE);
		ire = ire_ctable_lookup(dst, 0, IRE_BROADCAST, ipif,
		    connp->conn_zoneid, NULL,
		    (MATCH_IRE_TYPE | MATCH_IRE_ILL_GROUP), ipst);
		ipif_refrele(ipif);
		if (ire != NULL) {
			ire_refrele(ire);
			return (B_TRUE);
		} else {
			return (B_FALSE);
		}
	}

	if ((fanout_flags & IP_FF_NO_MCAST_LOOP) &&
	    connp->conn_zoneid == zoneid) {
		/*
		 * Loopback case: the sending endpoint has IP_MULTICAST_LOOP
		 * disabled, therefore we don't dispatch the multicast packet to
		 * the sending zone.
		 */
		return (B_FALSE);
	}

	if (IS_LOOPBACK(ill) && connp->conn_zoneid != zoneid) {
		/*
		 * Multicast packet on the loopback interface: we only match
		 * conns who joined the group in the specified zone.
		 */
		return (B_FALSE);
	}

	if (connp->conn_multi_router) {
		/* multicast packet and multicast router socket: send up */
		return (B_TRUE);
	}

	mutex_enter(&connp->conn_lock);
	found = (ilg_lookup_ill_withsrc(connp, dst, src, ill) != NULL);
	mutex_exit(&connp->conn_lock);
	return (found);
}

/*
 * Finish processing of "arp_up" when AR_DLPIOP_DONE is received from arp.
 */
/* ARGSUSED */
static void
ip_arp_done(ipsq_t *dummy_sq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	ill_t *ill = (ill_t *)q->q_ptr;
	mblk_t	*mp1, *mp2;
	ipif_t  *ipif;
	int err = 0;
	conn_t *connp = NULL;
	ipsq_t	*ipsq;
	arc_t	*arc;

	ip1dbg(("ip_arp_done(%s)\n", ill->ill_name));

	ASSERT((mp->b_wptr - mp->b_rptr) >= sizeof (arc_t));
	ASSERT(((arc_t *)mp->b_rptr)->arc_cmd == AR_DLPIOP_DONE);

	ASSERT(IAM_WRITER_ILL(ill));
	mp2 = mp->b_cont;
	mp->b_cont = NULL;

	/*
	 * We have now received the arp bringup completion message
	 * from ARP. Mark the arp bringup as done. Also if the arp
	 * stream has already started closing, send up the AR_ARP_CLOSING
	 * ack now since ARP is waiting in close for this ack.
	 */
	mutex_enter(&ill->ill_lock);
	ill->ill_arp_bringup_pending = 0;
	if (ill->ill_arp_closing) {
		mutex_exit(&ill->ill_lock);
		/* Let's reuse the mp for sending the ack */
		arc = (arc_t *)mp->b_rptr;
		mp->b_wptr = mp->b_rptr + sizeof (arc_t);
		arc->arc_cmd = AR_ARP_CLOSING;
		qreply(q, mp);
	} else {
		mutex_exit(&ill->ill_lock);
		freeb(mp);
	}

	ipsq = ill->ill_phyint->phyint_ipsq;
	ipif = ipsq->ipsq_pending_ipif;
	mp1 = ipsq_pending_mp_get(ipsq, &connp);
	ASSERT(!((mp1 != NULL) ^ (ipif != NULL)));
	if (mp1 == NULL) {
		/* bringup was aborted by the user */
		freemsg(mp2);
		return;
	}

	/*
	 * If an IOCTL is waiting on this (ipsq_current_ioctl != 0), then we
	 * must have an associated conn_t.  Otherwise, we're bringing this
	 * interface back up as part of handling an asynchronous event (e.g.,
	 * physical address change).
	 */
	if (ipsq->ipsq_current_ioctl != 0) {
		ASSERT(connp != NULL);
		q = CONNP_TO_WQ(connp);
	} else {
		ASSERT(connp == NULL);
		q = ill->ill_rq;
	}

	/*
	 * If the DL_BIND_REQ fails, it is noted
	 * in arc_name_offset.
	 */
	err = *((int *)mp2->b_rptr);
	if (err == 0) {
		if (ipif->ipif_isv6) {
			if ((err = ipif_up_done_v6(ipif)) != 0)
				ip0dbg(("ip_arp_done: init failed\n"));
		} else {
			if ((err = ipif_up_done(ipif)) != 0)
				ip0dbg(("ip_arp_done: init failed\n"));
		}
	} else {
		ip0dbg(("ip_arp_done: DL_BIND_REQ failed\n"));
	}

	freemsg(mp2);

	if ((err == 0) && (ill->ill_up_ipifs)) {
		err = ill_up_ipifs(ill, q, mp1);
		if (err == EINPROGRESS)
			return;
	}

	if (ill->ill_up_ipifs)
		ill_group_cleanup(ill);

	/*
	 * The operation must complete without EINPROGRESS since
	 * ipsq_pending_mp_get() has removed the mblk from ipsq_pending_mp.
	 * Otherwise, the operation will be stuck forever in the ipsq.
	 */
	ASSERT(err != EINPROGRESS);
	if (ipsq->ipsq_current_ioctl != 0)
		ip_ioctl_finish(q, mp1, err, NO_COPYOUT, ipsq);
	else
		ipsq_current_finish(ipsq);
}

/* Allocate the private structure */
static int
ip_priv_alloc(void **bufp)
{
	void	*buf;

	if ((buf = kmem_alloc(sizeof (ip_priv_t), KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	*bufp = buf;
	return (0);
}

/* Function to delete the private structure */
void
ip_priv_free(void *buf)
{
	ASSERT(buf != NULL);
	kmem_free(buf, sizeof (ip_priv_t));
}

/*
 * The entry point for IPPF processing.
 * If the classifier (IPGPC_CLASSIFY) is not loaded and configured, the
 * routine just returns.
 *
 * When called, ip_process generates an ipp_packet_t structure
 * which holds the state information for this packet and invokes the
 * the classifier (via ipp_packet_process). The classification, depending on
 * configured filters, results in a list of actions for this packet. Invoking
 * an action may cause the packet to be dropped, in which case the resulting
 * mblk (*mpp) is NULL. proc indicates the callout position for
 * this packet and ill_index is the interface this packet on or will leave
 * on (inbound and outbound resp.).
 */
void
ip_process(ip_proc_t proc, mblk_t **mpp, uint32_t ill_index)
{
	mblk_t		*mp;
	ip_priv_t	*priv;
	ipp_action_id_t	aid;
	int		rc = 0;
	ipp_packet_t	*pp;
#define	IP_CLASS	"ip"

	/* If the classifier is not loaded, return  */
	if ((aid = ipp_action_lookup(IPGPC_CLASSIFY)) == IPP_ACTION_INVAL) {
		return;
	}

	mp = *mpp;
	ASSERT(mp != NULL);

	/* Allocate the packet structure */
	rc = ipp_packet_alloc(&pp, IP_CLASS, aid);
	if (rc != 0) {
		*mpp = NULL;
		freemsg(mp);
		return;
	}

	/* Allocate the private structure */
	rc = ip_priv_alloc((void **)&priv);
	if (rc != 0) {
		*mpp = NULL;
		freemsg(mp);
		ipp_packet_free(pp);
		return;
	}
	priv->proc = proc;
	priv->ill_index = ill_index;
	ipp_packet_set_private(pp, priv, ip_priv_free);
	ipp_packet_set_data(pp, mp);

	/* Invoke the classifier */
	rc = ipp_packet_process(&pp);
	if (pp != NULL) {
		mp = ipp_packet_get_data(pp);
		ipp_packet_free(pp);
		if (rc != 0) {
			freemsg(mp);
			*mpp = NULL;
		}
	} else {
		*mpp = NULL;
	}
#undef	IP_CLASS
}

/*
 * Propagate a multicast group membership operation (add/drop) on
 * all the interfaces crossed by the related multirt routes.
 * The call is considered successful if the operation succeeds
 * on at least one interface.
 */
static int
ip_multirt_apply_membership(int (*fn)(conn_t *, boolean_t, ipaddr_t, ipaddr_t,
    uint_t *, mcast_record_t, ipaddr_t, mblk_t *), ire_t *ire, conn_t *connp,
    boolean_t checkonly, ipaddr_t group, mcast_record_t fmode, ipaddr_t src,
    mblk_t *first_mp)
{
	ire_t		*ire_gw;
	irb_t		*irb;
	int		error = 0;
	opt_restart_t	*or;
	ip_stack_t	*ipst = ire->ire_ipst;

	irb = ire->ire_bucket;
	ASSERT(irb != NULL);

	ASSERT(DB_TYPE(first_mp) == M_CTL);

	or = (opt_restart_t *)first_mp->b_rptr;
	IRB_REFHOLD(irb);
	for (; ire != NULL; ire = ire->ire_next) {
		if ((ire->ire_flags & RTF_MULTIRT) == 0)
			continue;
		if (ire->ire_addr != group)
			continue;

		ire_gw = ire_ftable_lookup(ire->ire_gateway_addr, 0, 0,
		    IRE_INTERFACE, NULL, NULL, ALL_ZONES, 0, NULL,
		    MATCH_IRE_RECURSIVE | MATCH_IRE_TYPE, ipst);
		/* No resolver exists for the gateway; skip this ire. */
		if (ire_gw == NULL)
			continue;

		/*
		 * This function can return EINPROGRESS. If so the operation
		 * will be restarted from ip_restart_optmgmt which will
		 * call ip_opt_set and option processing will restart for
		 * this option. So we may end up calling 'fn' more than once.
		 * This requires that 'fn' is idempotent except for the
		 * return value. The operation is considered a success if
		 * it succeeds at least once on any one interface.
		 */
		error = fn(connp, checkonly, group, ire_gw->ire_src_addr,
		    NULL, fmode, src, first_mp);
		if (error == 0)
			or->or_private = CGTP_MCAST_SUCCESS;

		if (ip_debug > 0) {
			ulong_t	off;
			char	*ksym;
			ksym = kobj_getsymname((uintptr_t)fn, &off);
			ip2dbg(("ip_multirt_apply_membership: "
			    "called %s, multirt group 0x%08x via itf 0x%08x, "
			    "error %d [success %u]\n",
			    ksym ? ksym : "?",
			    ntohl(group), ntohl(ire_gw->ire_src_addr),
			    error, or->or_private));
		}

		ire_refrele(ire_gw);
		if (error == EINPROGRESS) {
			IRB_REFRELE(irb);
			return (error);
		}
	}
	IRB_REFRELE(irb);
	/*
	 * Consider the call as successful if we succeeded on at least
	 * one interface. Otherwise, return the last encountered error.
	 */
	return (or->or_private == CGTP_MCAST_SUCCESS ? 0 : error);
}


/*
 * Issue a warning regarding a route crossing an interface with an
 * incorrect MTU. Only one message every 'ip_multirt_log_interval'
 * amount of time is logged.
 */
static void
ip_multirt_bad_mtu(ire_t *ire, uint32_t max_frag)
{
	hrtime_t	current = gethrtime();
	char		buf[INET_ADDRSTRLEN];
	ip_stack_t	*ipst = ire->ire_ipst;

	/* Convert interval in ms to hrtime in ns */
	if (ipst->ips_multirt_bad_mtu_last_time +
	    ((hrtime_t)ipst->ips_ip_multirt_log_interval * (hrtime_t)1000000) <=
	    current) {
		cmn_err(CE_WARN, "ip: ignoring multiroute "
		    "to %s, incorrect MTU %u (expected %u)\n",
		    ip_dot_addr(ire->ire_addr, buf),
		    ire->ire_max_frag, max_frag);

		ipst->ips_multirt_bad_mtu_last_time = current;
	}
}


/*
 * Get the CGTP (multirouting) filtering status.
 * If 0, the CGTP hooks are transparent.
 */
/* ARGSUSED */
static int
ip_cgtp_filter_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *ioc_cr)
{
	boolean_t	*ip_cgtp_filter_value = (boolean_t *)cp;

	(void) mi_mpprintf(mp, "%d", (int)*ip_cgtp_filter_value);
	return (0);
}


/*
 * Set the CGTP (multirouting) filtering status.
 * If the status is changed from active to transparent
 * or from transparent to active, forward the new status
 * to the filtering module (if loaded).
 */
/* ARGSUSED */
static int
ip_cgtp_filter_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *ioc_cr)
{
	long		new_value;
	boolean_t	*ip_cgtp_filter_value = (boolean_t *)cp;
	ip_stack_t	*ipst = CONNQ_TO_IPST(q);

	if (secpolicy_ip_config(ioc_cr, B_FALSE) != 0)
		return (EPERM);

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < 0 || new_value > 1) {
		return (EINVAL);
	}

	if ((!*ip_cgtp_filter_value) && new_value) {
		cmn_err(CE_NOTE, "IP: enabling CGTP filtering%s",
		    ipst->ips_ip_cgtp_filter_ops == NULL ?
		    " (module not loaded)" : "");
	}
	if (*ip_cgtp_filter_value && (!new_value)) {
		cmn_err(CE_NOTE, "IP: disabling CGTP filtering%s",
		    ipst->ips_ip_cgtp_filter_ops == NULL ?
		    " (module not loaded)" : "");
	}

	if (ipst->ips_ip_cgtp_filter_ops != NULL) {
		int	res;
		netstackid_t stackid;

		stackid = ipst->ips_netstack->netstack_stackid;
		res = ipst->ips_ip_cgtp_filter_ops->cfo_change_state(stackid,
		    new_value);
		if (res)
			return (res);
	}

	*ip_cgtp_filter_value = (boolean_t)new_value;

	return (0);
}


/*
 * Return the expected CGTP hooks version number.
 */
int
ip_cgtp_filter_supported(void)
{
	return (ip_cgtp_filter_rev);
}


/*
 * CGTP hooks can be registered by invoking this function.
 * Checks that the version number matches.
 */
int
ip_cgtp_filter_register(netstackid_t stackid, cgtp_filter_ops_t *ops)
{
	netstack_t *ns;
	ip_stack_t *ipst;

	if (ops->cfo_filter_rev != CGTP_FILTER_REV)
		return (ENOTSUP);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (EINVAL);
	ipst = ns->netstack_ip;
	ASSERT(ipst != NULL);

	if (ipst->ips_ip_cgtp_filter_ops != NULL) {
		netstack_rele(ns);
		return (EALREADY);
	}

	ipst->ips_ip_cgtp_filter_ops = ops;
	netstack_rele(ns);
	return (0);
}

/*
 * CGTP hooks can be unregistered by invoking this function.
 * Returns ENXIO if there was no registration.
 * Returns EBUSY if the ndd variable has not been turned off.
 */
int
ip_cgtp_filter_unregister(netstackid_t stackid)
{
	netstack_t *ns;
	ip_stack_t *ipst;

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (EINVAL);
	ipst = ns->netstack_ip;
	ASSERT(ipst != NULL);

	if (ipst->ips_ip_cgtp_filter) {
		netstack_rele(ns);
		return (EBUSY);
	}

	if (ipst->ips_ip_cgtp_filter_ops == NULL) {
		netstack_rele(ns);
		return (ENXIO);
	}
	ipst->ips_ip_cgtp_filter_ops = NULL;
	netstack_rele(ns);
	return (0);
}

/*
 * Check whether there is a CGTP filter registration.
 * Returns non-zero if there is a registration, otherwise returns zero.
 * Note: returns zero if bad stackid.
 */
int
ip_cgtp_filter_is_registered(netstackid_t stackid)
{
	netstack_t *ns;
	ip_stack_t *ipst;
	int ret;

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (0);
	ipst = ns->netstack_ip;
	ASSERT(ipst != NULL);

	if (ipst->ips_ip_cgtp_filter_ops != NULL)
		ret = 1;
	else
		ret = 0;

	netstack_rele(ns);
	return (ret);
}

static int
ip_squeue_switch(int val)
{
	int rval = SQ_FILL;

	switch (val) {
	case IP_SQUEUE_ENTER_NODRAIN:
		rval = SQ_NODRAIN;
		break;
	case IP_SQUEUE_ENTER:
		rval = SQ_PROCESS;
		break;
	default:
		break;
	}
	return (rval);
}

/* ARGSUSED */
static int
ip_input_proc_set(queue_t *q, mblk_t *mp, char *value,
    caddr_t addr, cred_t *cr)
{
	int *v = (int *)addr;
	long new_value;

	if (secpolicy_net_config(cr, B_FALSE) != 0)
		return (EPERM);

	if (ddi_strtol(value, NULL, 10, &new_value) != 0)
		return (EINVAL);

	ip_squeue_flag = ip_squeue_switch(new_value);
	*v = new_value;
	return (0);
}

/*
 * Handle ndd set of variables which require PRIV_SYS_NET_CONFIG such as
 * ip_debug.
 */
/* ARGSUSED */
static int
ip_int_set(queue_t *q, mblk_t *mp, char *value,
    caddr_t addr, cred_t *cr)
{
	int *v = (int *)addr;
	long new_value;

	if (secpolicy_net_config(cr, B_FALSE) != 0)
		return (EPERM);

	if (ddi_strtol(value, NULL, 10, &new_value) != 0)
		return (EINVAL);

	*v = new_value;
	return (0);
}

/*
 * Handle changes to ipmp_hook_emulation ndd variable.
 * Need to update phyint_hook_ifindex.
 * Also generate a nic plumb event should a new ifidex be assigned to a group.
 */
static void
ipmp_hook_emulation_changed(ip_stack_t *ipst)
{
	phyint_t *phyi;
	phyint_t *phyi_tmp;
	char *groupname;
	int namelen;
	ill_t	*ill;
	boolean_t new_group;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	/*
	 * Group indicies are stored in the phyint - a common structure
	 * to both IPv4 and IPv6.
	 */
	phyi = avl_first(&ipst->ips_phyint_g_list->phyint_list_avl_by_index);
	for (; phyi != NULL;
	    phyi = avl_walk(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
	    phyi, AVL_AFTER)) {
		/* Ignore the ones that do not have a group */
		if (phyi->phyint_groupname_len == 0)
			continue;

		/*
		 * Look for other phyint in group.
		 * Clear name/namelen so the lookup doesn't find ourselves.
		 */
		namelen = phyi->phyint_groupname_len;
		groupname = phyi->phyint_groupname;
		phyi->phyint_groupname_len = 0;
		phyi->phyint_groupname = NULL;

		phyi_tmp = phyint_lookup_group(groupname, B_FALSE, ipst);
		/* Restore */
		phyi->phyint_groupname_len = namelen;
		phyi->phyint_groupname = groupname;

		new_group = B_FALSE;
		if (ipst->ips_ipmp_hook_emulation) {
			/*
			 * If the group already exists and has already
			 * been assigned a group ifindex, we use the existing
			 * group_ifindex, otherwise we pick a new group_ifindex
			 * here.
			 */
			if (phyi_tmp != NULL &&
			    phyi_tmp->phyint_group_ifindex != 0) {
				phyi->phyint_group_ifindex =
				    phyi_tmp->phyint_group_ifindex;
			} else {
				/* XXX We need a recovery strategy here. */
				if (!ip_assign_ifindex(
				    &phyi->phyint_group_ifindex, ipst))
					cmn_err(CE_PANIC,
					    "ip_assign_ifindex() failed");
				new_group = B_TRUE;
			}
		} else {
			phyi->phyint_group_ifindex = 0;
		}
		if (ipst->ips_ipmp_hook_emulation)
			phyi->phyint_hook_ifindex = phyi->phyint_group_ifindex;
		else
			phyi->phyint_hook_ifindex = phyi->phyint_ifindex;

		/*
		 * For IP Filter to find out the relationship between
		 * names and interface indicies, we need to generate
		 * a NE_PLUMB event when a new group can appear.
		 * We always generate events when a new interface appears
		 * (even when ipmp_hook_emulation is set) so there
		 * is no need to generate NE_PLUMB events when
		 * ipmp_hook_emulation is turned off.
		 * And since it isn't critical for IP Filter to get
		 * the NE_UNPLUMB events we skip those here.
		 */
		if (new_group) {
			/*
			 * First phyint in group - generate group PLUMB event.
			 * Since we are not running inside the ipsq we do
			 * the dispatch immediately.
			 */
			if (phyi->phyint_illv4 != NULL)
				ill = phyi->phyint_illv4;
			else
				ill = phyi->phyint_illv6;

			if (ill != NULL)
				ill_nic_event_plumb(ill, B_TRUE);
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);
}

/* ARGSUSED */
static int
ipmp_hook_emulation_set(queue_t *q, mblk_t *mp, char *value,
    caddr_t addr, cred_t *cr)
{
	int *v = (int *)addr;
	long new_value;
	ip_stack_t	*ipst = CONNQ_TO_IPST(q);

	if (ddi_strtol(value, NULL, 10, &new_value) != 0)
		return (EINVAL);

	if (*v != new_value) {
		*v = new_value;
		ipmp_hook_emulation_changed(ipst);
	}
	return (0);
}

static void *
ip_kstat2_init(netstackid_t stackid, ip_stat_t *ip_statisticsp)
{
	kstat_t *ksp;

	ip_stat_t template = {
		{ "ipsec_fanout_proto", 	KSTAT_DATA_UINT64 },
		{ "ip_udp_fannorm", 		KSTAT_DATA_UINT64 },
		{ "ip_udp_fanmb", 		KSTAT_DATA_UINT64 },
		{ "ip_udp_fanothers", 		KSTAT_DATA_UINT64 },
		{ "ip_udp_fast_path", 		KSTAT_DATA_UINT64 },
		{ "ip_udp_slow_path", 		KSTAT_DATA_UINT64 },
		{ "ip_udp_input_err", 		KSTAT_DATA_UINT64 },
		{ "ip_tcppullup", 		KSTAT_DATA_UINT64 },
		{ "ip_tcpoptions", 		KSTAT_DATA_UINT64 },
		{ "ip_multipkttcp", 		KSTAT_DATA_UINT64 },
		{ "ip_tcp_fast_path",		KSTAT_DATA_UINT64 },
		{ "ip_tcp_slow_path",		KSTAT_DATA_UINT64 },
		{ "ip_tcp_input_error",		KSTAT_DATA_UINT64 },
		{ "ip_db_ref",			KSTAT_DATA_UINT64 },
		{ "ip_notaligned1",		KSTAT_DATA_UINT64 },
		{ "ip_notaligned2",		KSTAT_DATA_UINT64 },
		{ "ip_multimblk3",		KSTAT_DATA_UINT64 },
		{ "ip_multimblk4",		KSTAT_DATA_UINT64 },
		{ "ip_ipoptions",		KSTAT_DATA_UINT64 },
		{ "ip_classify_fail",		KSTAT_DATA_UINT64 },
		{ "ip_opt",			KSTAT_DATA_UINT64 },
		{ "ip_udp_rput_local",		KSTAT_DATA_UINT64 },
		{ "ipsec_proto_ahesp",		KSTAT_DATA_UINT64 },
		{ "ip_conn_flputbq",		KSTAT_DATA_UINT64 },
		{ "ip_conn_walk_drain",		KSTAT_DATA_UINT64 },
		{ "ip_out_sw_cksum",		KSTAT_DATA_UINT64 },
		{ "ip_in_sw_cksum",		KSTAT_DATA_UINT64 },
		{ "ip_trash_ire_reclaim_calls",	KSTAT_DATA_UINT64 },
		{ "ip_trash_ire_reclaim_success",	KSTAT_DATA_UINT64 },
		{ "ip_ire_arp_timer_expired",	KSTAT_DATA_UINT64 },
		{ "ip_ire_redirect_timer_expired",	KSTAT_DATA_UINT64 },
		{ "ip_ire_pmtu_timer_expired",	KSTAT_DATA_UINT64 },
		{ "ip_input_multi_squeue",	KSTAT_DATA_UINT64 },
		{ "ip_tcp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_tcp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_tcp_in_sw_cksum_err",		KSTAT_DATA_UINT64 },
		{ "ip_tcp_out_sw_cksum_bytes",		KSTAT_DATA_UINT64 },
		{ "ip_udp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_udp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_udp_in_sw_cksum_err",		KSTAT_DATA_UINT64 },
		{ "ip_udp_out_sw_cksum_bytes",		KSTAT_DATA_UINT64 },
		{ "ip_frag_mdt_pkt_out",		KSTAT_DATA_UINT64 },
		{ "ip_frag_mdt_discarded",		KSTAT_DATA_UINT64 },
		{ "ip_frag_mdt_allocfail",		KSTAT_DATA_UINT64 },
		{ "ip_frag_mdt_addpdescfail",		KSTAT_DATA_UINT64 },
		{ "ip_frag_mdt_allocd",			KSTAT_DATA_UINT64 },
	};

	ksp = kstat_create_netstack("ip", 0, "ipstat", "net",
	    KSTAT_TYPE_NAMED, sizeof (template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, stackid);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, ip_statisticsp, sizeof (template));
	ksp->ks_data = (void *)ip_statisticsp;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static void
ip_kstat2_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

static void *
ip_kstat_init(netstackid_t stackid, ip_stack_t *ipst)
{
	kstat_t	*ksp;

	ip_named_kstat_t template = {
		{ "forwarding",		KSTAT_DATA_UINT32, 0 },
		{ "defaultTTL",		KSTAT_DATA_UINT32, 0 },
		{ "inReceives",		KSTAT_DATA_UINT64, 0 },
		{ "inHdrErrors",	KSTAT_DATA_UINT32, 0 },
		{ "inAddrErrors",	KSTAT_DATA_UINT32, 0 },
		{ "forwDatagrams",	KSTAT_DATA_UINT64, 0 },
		{ "inUnknownProtos",	KSTAT_DATA_UINT32, 0 },
		{ "inDiscards",		KSTAT_DATA_UINT32, 0 },
		{ "inDelivers",		KSTAT_DATA_UINT64, 0 },
		{ "outRequests",	KSTAT_DATA_UINT64, 0 },
		{ "outDiscards",	KSTAT_DATA_UINT32, 0 },
		{ "outNoRoutes",	KSTAT_DATA_UINT32, 0 },
		{ "reasmTimeout",	KSTAT_DATA_UINT32, 0 },
		{ "reasmReqds",		KSTAT_DATA_UINT32, 0 },
		{ "reasmOKs",		KSTAT_DATA_UINT32, 0 },
		{ "reasmFails",		KSTAT_DATA_UINT32, 0 },
		{ "fragOKs",		KSTAT_DATA_UINT32, 0 },
		{ "fragFails",		KSTAT_DATA_UINT32, 0 },
		{ "fragCreates",	KSTAT_DATA_UINT32, 0 },
		{ "addrEntrySize",	KSTAT_DATA_INT32, 0 },
		{ "routeEntrySize",	KSTAT_DATA_INT32, 0 },
		{ "netToMediaEntrySize",	KSTAT_DATA_INT32, 0 },
		{ "routingDiscards",	KSTAT_DATA_UINT32, 0 },
		{ "inErrs",		KSTAT_DATA_UINT32, 0 },
		{ "noPorts",		KSTAT_DATA_UINT32, 0 },
		{ "inCksumErrs",	KSTAT_DATA_UINT32, 0 },
		{ "reasmDuplicates",	KSTAT_DATA_UINT32, 0 },
		{ "reasmPartDups",	KSTAT_DATA_UINT32, 0 },
		{ "forwProhibits",	KSTAT_DATA_UINT32, 0 },
		{ "udpInCksumErrs",	KSTAT_DATA_UINT32, 0 },
		{ "udpInOverflows",	KSTAT_DATA_UINT32, 0 },
		{ "rawipInOverflows",	KSTAT_DATA_UINT32, 0 },
		{ "ipsecInSucceeded",	KSTAT_DATA_UINT32, 0 },
		{ "ipsecInFailed",	KSTAT_DATA_INT32, 0 },
		{ "memberEntrySize",	KSTAT_DATA_INT32, 0 },
		{ "inIPv6",		KSTAT_DATA_UINT32, 0 },
		{ "outIPv6",		KSTAT_DATA_UINT32, 0 },
		{ "outSwitchIPv6",	KSTAT_DATA_UINT32, 0 },
	};

	ksp = kstat_create_netstack("ip", 0, "ip", "mib2", KSTAT_TYPE_NAMED,
	    NUM_OF_FIELDS(ip_named_kstat_t), 0, stackid);
	if (ksp == NULL || ksp->ks_data == NULL)
		return (NULL);

	template.forwarding.value.ui32 = WE_ARE_FORWARDING(ipst) ? 1:2;
	template.defaultTTL.value.ui32 = (uint32_t)ipst->ips_ip_def_ttl;
	template.reasmTimeout.value.ui32 = ipst->ips_ip_g_frag_timeout;
	template.addrEntrySize.value.i32 = sizeof (mib2_ipAddrEntry_t);
	template.routeEntrySize.value.i32 = sizeof (mib2_ipRouteEntry_t);

	template.netToMediaEntrySize.value.i32 =
	    sizeof (mib2_ipNetToMediaEntry_t);

	template.memberEntrySize.value.i32 = sizeof (ipv6_member_t);

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_update = ip_kstat_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static void
ip_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

static int
ip_kstat_update(kstat_t *kp, int rw)
{
	ip_named_kstat_t *ipkp;
	mib2_ipIfStatsEntry_t ipmib;
	ill_walk_context_t ctx;
	ill_t *ill;
	netstackid_t	stackid = (zoneid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	ip_stack_t	*ipst;

	if (kp == NULL || kp->ks_data == NULL)
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	ipst = ns->netstack_ip;
	if (ipst == NULL) {
		netstack_rele(ns);
		return (-1);
	}
	ipkp = (ip_named_kstat_t *)kp->ks_data;

	bcopy(&ipst->ips_ip_mib, &ipmib, sizeof (ipmib));
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill))
		ip_mib2_add_ip_stats(&ipmib, ill->ill_ip_mib);
	rw_exit(&ipst->ips_ill_g_lock);

	ipkp->forwarding.value.ui32 =		ipmib.ipIfStatsForwarding;
	ipkp->defaultTTL.value.ui32 =		ipmib.ipIfStatsDefaultTTL;
	ipkp->inReceives.value.ui64 =		ipmib.ipIfStatsHCInReceives;
	ipkp->inHdrErrors.value.ui32 =		ipmib.ipIfStatsInHdrErrors;
	ipkp->inAddrErrors.value.ui32 =		ipmib.ipIfStatsInAddrErrors;
	ipkp->forwDatagrams.value.ui64 = ipmib.ipIfStatsHCOutForwDatagrams;
	ipkp->inUnknownProtos.value.ui32 =	ipmib.ipIfStatsInUnknownProtos;
	ipkp->inDiscards.value.ui32 =		ipmib.ipIfStatsInDiscards;
	ipkp->inDelivers.value.ui64 =		ipmib.ipIfStatsHCInDelivers;
	ipkp->outRequests.value.ui64 =		ipmib.ipIfStatsHCOutRequests;
	ipkp->outDiscards.value.ui32 =		ipmib.ipIfStatsOutDiscards;
	ipkp->outNoRoutes.value.ui32 =		ipmib.ipIfStatsOutNoRoutes;
	ipkp->reasmTimeout.value.ui32 =		ipst->ips_ip_g_frag_timeout;
	ipkp->reasmReqds.value.ui32 =		ipmib.ipIfStatsReasmReqds;
	ipkp->reasmOKs.value.ui32 =		ipmib.ipIfStatsReasmOKs;
	ipkp->reasmFails.value.ui32 =		ipmib.ipIfStatsReasmFails;
	ipkp->fragOKs.value.ui32 =		ipmib.ipIfStatsOutFragOKs;
	ipkp->fragFails.value.ui32 =		ipmib.ipIfStatsOutFragFails;
	ipkp->fragCreates.value.ui32 =		ipmib.ipIfStatsOutFragCreates;

	ipkp->routingDiscards.value.ui32 =	0;
	ipkp->inErrs.value.ui32 =		ipmib.tcpIfStatsInErrs;
	ipkp->noPorts.value.ui32 =		ipmib.udpIfStatsNoPorts;
	ipkp->inCksumErrs.value.ui32 =		ipmib.ipIfStatsInCksumErrs;
	ipkp->reasmDuplicates.value.ui32 =	ipmib.ipIfStatsReasmDuplicates;
	ipkp->reasmPartDups.value.ui32 =	ipmib.ipIfStatsReasmPartDups;
	ipkp->forwProhibits.value.ui32 =	ipmib.ipIfStatsForwProhibits;
	ipkp->udpInCksumErrs.value.ui32 =	ipmib.udpIfStatsInCksumErrs;
	ipkp->udpInOverflows.value.ui32 =	ipmib.udpIfStatsInOverflows;
	ipkp->rawipInOverflows.value.ui32 =	ipmib.rawipIfStatsInOverflows;
	ipkp->ipsecInSucceeded.value.ui32 =	ipmib.ipsecIfStatsInSucceeded;
	ipkp->ipsecInFailed.value.i32 =		ipmib.ipsecIfStatsInFailed;

	ipkp->inIPv6.value.ui32 =	ipmib.ipIfStatsInWrongIPVersion;
	ipkp->outIPv6.value.ui32 =	ipmib.ipIfStatsOutWrongIPVersion;
	ipkp->outSwitchIPv6.value.ui32 = ipmib.ipIfStatsOutSwitchIPVersion;

	netstack_rele(ns);

	return (0);
}

static void *
icmp_kstat_init(netstackid_t stackid)
{
	kstat_t	*ksp;

	icmp_named_kstat_t template = {
		{ "inMsgs",		KSTAT_DATA_UINT32 },
		{ "inErrors",		KSTAT_DATA_UINT32 },
		{ "inDestUnreachs",	KSTAT_DATA_UINT32 },
		{ "inTimeExcds",	KSTAT_DATA_UINT32 },
		{ "inParmProbs",	KSTAT_DATA_UINT32 },
		{ "inSrcQuenchs",	KSTAT_DATA_UINT32 },
		{ "inRedirects",	KSTAT_DATA_UINT32 },
		{ "inEchos",		KSTAT_DATA_UINT32 },
		{ "inEchoReps",		KSTAT_DATA_UINT32 },
		{ "inTimestamps",	KSTAT_DATA_UINT32 },
		{ "inTimestampReps",	KSTAT_DATA_UINT32 },
		{ "inAddrMasks",	KSTAT_DATA_UINT32 },
		{ "inAddrMaskReps",	KSTAT_DATA_UINT32 },
		{ "outMsgs",		KSTAT_DATA_UINT32 },
		{ "outErrors",		KSTAT_DATA_UINT32 },
		{ "outDestUnreachs",	KSTAT_DATA_UINT32 },
		{ "outTimeExcds",	KSTAT_DATA_UINT32 },
		{ "outParmProbs",	KSTAT_DATA_UINT32 },
		{ "outSrcQuenchs",	KSTAT_DATA_UINT32 },
		{ "outRedirects",	KSTAT_DATA_UINT32 },
		{ "outEchos",		KSTAT_DATA_UINT32 },
		{ "outEchoReps",	KSTAT_DATA_UINT32 },
		{ "outTimestamps",	KSTAT_DATA_UINT32 },
		{ "outTimestampReps",	KSTAT_DATA_UINT32 },
		{ "outAddrMasks",	KSTAT_DATA_UINT32 },
		{ "outAddrMaskReps",	KSTAT_DATA_UINT32 },
		{ "inChksumErrs",	KSTAT_DATA_UINT32 },
		{ "inUnknowns",		KSTAT_DATA_UINT32 },
		{ "inFragNeeded",	KSTAT_DATA_UINT32 },
		{ "outFragNeeded",	KSTAT_DATA_UINT32 },
		{ "outDrops",		KSTAT_DATA_UINT32 },
		{ "inOverFlows",	KSTAT_DATA_UINT32 },
		{ "inBadRedirects",	KSTAT_DATA_UINT32 },
	};

	ksp = kstat_create_netstack("ip", 0, "icmp", "mib2", KSTAT_TYPE_NAMED,
	    NUM_OF_FIELDS(icmp_named_kstat_t), 0, stackid);
	if (ksp == NULL || ksp->ks_data == NULL)
		return (NULL);

	bcopy(&template, ksp->ks_data, sizeof (template));

	ksp->ks_update = icmp_kstat_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static void
icmp_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

static int
icmp_kstat_update(kstat_t *kp, int rw)
{
	icmp_named_kstat_t *icmpkp;
	netstackid_t	stackid = (zoneid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	ip_stack_t	*ipst;

	if ((kp == NULL) || (kp->ks_data == NULL))
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	ipst = ns->netstack_ip;
	if (ipst == NULL) {
		netstack_rele(ns);
		return (-1);
	}
	icmpkp = (icmp_named_kstat_t *)kp->ks_data;

	icmpkp->inMsgs.value.ui32 =	    ipst->ips_icmp_mib.icmpInMsgs;
	icmpkp->inErrors.value.ui32 =	    ipst->ips_icmp_mib.icmpInErrors;
	icmpkp->inDestUnreachs.value.ui32 =
	    ipst->ips_icmp_mib.icmpInDestUnreachs;
	icmpkp->inTimeExcds.value.ui32 =    ipst->ips_icmp_mib.icmpInTimeExcds;
	icmpkp->inParmProbs.value.ui32 =    ipst->ips_icmp_mib.icmpInParmProbs;
	icmpkp->inSrcQuenchs.value.ui32 =   ipst->ips_icmp_mib.icmpInSrcQuenchs;
	icmpkp->inRedirects.value.ui32 =    ipst->ips_icmp_mib.icmpInRedirects;
	icmpkp->inEchos.value.ui32 =	    ipst->ips_icmp_mib.icmpInEchos;
	icmpkp->inEchoReps.value.ui32 =	    ipst->ips_icmp_mib.icmpInEchoReps;
	icmpkp->inTimestamps.value.ui32 =   ipst->ips_icmp_mib.icmpInTimestamps;
	icmpkp->inTimestampReps.value.ui32 =
	    ipst->ips_icmp_mib.icmpInTimestampReps;
	icmpkp->inAddrMasks.value.ui32 =    ipst->ips_icmp_mib.icmpInAddrMasks;
	icmpkp->inAddrMaskReps.value.ui32 =
	    ipst->ips_icmp_mib.icmpInAddrMaskReps;
	icmpkp->outMsgs.value.ui32 =	    ipst->ips_icmp_mib.icmpOutMsgs;
	icmpkp->outErrors.value.ui32 =	    ipst->ips_icmp_mib.icmpOutErrors;
	icmpkp->outDestUnreachs.value.ui32 =
	    ipst->ips_icmp_mib.icmpOutDestUnreachs;
	icmpkp->outTimeExcds.value.ui32 =   ipst->ips_icmp_mib.icmpOutTimeExcds;
	icmpkp->outParmProbs.value.ui32 =   ipst->ips_icmp_mib.icmpOutParmProbs;
	icmpkp->outSrcQuenchs.value.ui32 =
	    ipst->ips_icmp_mib.icmpOutSrcQuenchs;
	icmpkp->outRedirects.value.ui32 =   ipst->ips_icmp_mib.icmpOutRedirects;
	icmpkp->outEchos.value.ui32 =	    ipst->ips_icmp_mib.icmpOutEchos;
	icmpkp->outEchoReps.value.ui32 =    ipst->ips_icmp_mib.icmpOutEchoReps;
	icmpkp->outTimestamps.value.ui32 =
	    ipst->ips_icmp_mib.icmpOutTimestamps;
	icmpkp->outTimestampReps.value.ui32 =
	    ipst->ips_icmp_mib.icmpOutTimestampReps;
	icmpkp->outAddrMasks.value.ui32 =
	    ipst->ips_icmp_mib.icmpOutAddrMasks;
	icmpkp->outAddrMaskReps.value.ui32 =
	    ipst->ips_icmp_mib.icmpOutAddrMaskReps;
	icmpkp->inCksumErrs.value.ui32 =    ipst->ips_icmp_mib.icmpInCksumErrs;
	icmpkp->inUnknowns.value.ui32 =	    ipst->ips_icmp_mib.icmpInUnknowns;
	icmpkp->inFragNeeded.value.ui32 =   ipst->ips_icmp_mib.icmpInFragNeeded;
	icmpkp->outFragNeeded.value.ui32 =
	    ipst->ips_icmp_mib.icmpOutFragNeeded;
	icmpkp->outDrops.value.ui32 =	    ipst->ips_icmp_mib.icmpOutDrops;
	icmpkp->inOverflows.value.ui32 =    ipst->ips_icmp_mib.icmpInOverflows;
	icmpkp->inBadRedirects.value.ui32 =
	    ipst->ips_icmp_mib.icmpInBadRedirects;

	netstack_rele(ns);
	return (0);
}

/*
 * This is the fanout function for raw socket opened for SCTP.  Note
 * that it is called after SCTP checks that there is no socket which
 * wants a packet.  Then before SCTP handles this out of the blue packet,
 * this function is called to see if there is any raw socket for SCTP.
 * If there is and it is bound to the correct address, the packet will
 * be sent to that socket.  Note that only one raw socket can be bound to
 * a port.  This is assured in ipcl_sctp_hash_insert();
 */
void
ip_fanout_sctp_raw(mblk_t *mp, ill_t *recv_ill, ipha_t *ipha, boolean_t isv4,
    uint32_t ports, boolean_t mctl_present, uint_t flags, boolean_t ip_policy,
    zoneid_t zoneid)
{
	conn_t		*connp;
	queue_t		*rq;
	mblk_t		*first_mp;
	boolean_t	secure;
	ip6_t		*ip6h;
	ip_stack_t	*ipst = recv_ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;
	sctp_stack_t	*sctps = ipst->ips_netstack->netstack_sctp;
	boolean_t	sctp_csum_err = B_FALSE;

	if (flags & IP_FF_SCTP_CSUM_ERR) {
		sctp_csum_err = B_TRUE;
		flags &= ~IP_FF_SCTP_CSUM_ERR;
	}

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		secure = B_FALSE;
	}
	ip6h = (isv4) ? NULL : (ip6_t *)ipha;

	connp = ipcl_classify_raw(mp, IPPROTO_SCTP, zoneid, ports, ipha, ipst);
	if (connp == NULL) {
		/*
		 * Although raw sctp is not summed, OOB chunks must be.
		 * Drop the packet here if the sctp checksum failed.
		 */
		if (sctp_csum_err) {
			BUMP_MIB(&sctps->sctps_mib, sctpChecksumError);
			freemsg(first_mp);
			return;
		}
		sctp_ootb_input(first_mp, recv_ill, zoneid, mctl_present);
		return;
	}
	rq = connp->conn_rq;
	if (!canputnext(rq)) {
		CONN_DEC_REF(connp);
		BUMP_MIB(recv_ill->ill_ip_mib, rawipIfStatsInOverflows);
		freemsg(first_mp);
		return;
	}
	if ((isv4 ? CONN_INBOUND_POLICY_PRESENT(connp, ipss) :
	    CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss)) || secure) {
		first_mp = ipsec_check_inbound_policy(first_mp, connp,
		    (isv4 ? ipha : NULL), ip6h, mctl_present);
		if (first_mp == NULL) {
			BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			return;
		}
	}
	/*
	 * We probably should not send M_CTL message up to
	 * raw socket.
	 */
	if (mctl_present)
		freeb(first_mp);

	/* Initiate IPPF processing here if needed. */
	if ((isv4 && IPP_ENABLED(IPP_LOCAL_IN, ipst) && ip_policy) ||
	    (!isv4 && IP6_IN_IPP(flags, ipst))) {
		ip_process(IPP_LOCAL_IN, &mp,
		    recv_ill->ill_phyint->phyint_ifindex);
		if (mp == NULL) {
			CONN_DEC_REF(connp);
			return;
		}
	}

	if (connp->conn_recvif || connp->conn_recvslla ||
	    ((connp->conn_ip_recvpktinfo ||
	    (!isv4 && IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src))) &&
	    (flags & IP_FF_IPINFO))) {
		int in_flags = 0;

		/*
		 * Since sctp does not support IP_RECVPKTINFO for v4, only pass
		 * IPF_RECVIF.
		 */
		if (connp->conn_recvif || connp->conn_ip_recvpktinfo) {
			in_flags = IPF_RECVIF;
		}
		if (connp->conn_recvslla) {
			in_flags |= IPF_RECVSLLA;
		}
		if (isv4) {
			mp = ip_add_info(mp, recv_ill, in_flags,
			    IPCL_ZONEID(connp), ipst);
		} else {
			mp = ip_add_info_v6(mp, recv_ill, &ip6h->ip6_dst);
			if (mp == NULL) {
				BUMP_MIB(recv_ill->ill_ip_mib,
				    ipIfStatsInDiscards);
				CONN_DEC_REF(connp);
				return;
			}
		}
	}

	BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsHCInDelivers);
	/*
	 * We are sending the IPSEC_IN message also up. Refer
	 * to comments above this function.
	 * This is the SOCK_RAW, IPPROTO_SCTP case.
	 */
	(connp->conn_recv)(connp, mp, NULL);
	CONN_DEC_REF(connp);
}

#define	UPDATE_IP_MIB_OB_COUNTERS(ill, len)				\
{									\
	BUMP_MIB((ill)->ill_ip_mib, ipIfStatsHCOutTransmits);		\
	UPDATE_MIB((ill)->ill_ip_mib, ipIfStatsHCOutOctets, (len));	\
}
/*
 * This function should be called only if all packet processing
 * including fragmentation is complete. Callers of this function
 * must set mp->b_prev to one of these values:
 *	{0, IPP_FWD_OUT, IPP_LOCAL_OUT}
 * prior to handing over the mp as first argument to this function.
 *
 * If the ire passed by caller is incomplete, this function
 * queues the packet and if necessary, sends ARP request and bails.
 * If the ire passed is fully resolved, we simply prepend
 * the link-layer header to the packet, do ipsec hw acceleration
 * work if necessary, and send the packet out on the wire.
 *
 * NOTE: IPsec will only call this function with fully resolved
 * ires if hw acceleration is involved.
 * TODO list :
 * 	a Handle M_MULTIDATA so that
 *	  tcp_multisend->tcp_multisend_data can
 *	  call ip_xmit_v4 directly
 *	b Handle post-ARP work for fragments so that
 *	  ip_wput_frag can call this function.
 */
ipxmit_state_t
ip_xmit_v4(mblk_t *mp, ire_t *ire, ipsec_out_t *io,
    boolean_t flow_ctl_enabled, conn_t *connp)
{
	nce_t		*arpce;
	ipha_t		*ipha;
	queue_t		*q;
	int		ill_index;
	mblk_t		*nxt_mp, *first_mp;
	boolean_t	xmit_drop = B_FALSE;
	ip_proc_t	proc;
	ill_t		*out_ill;
	int		pkt_len;

	arpce = ire->ire_nce;
	ASSERT(arpce != NULL);

	DTRACE_PROBE2(ip__xmit__v4, ire_t *, ire,  nce_t *, arpce);

	mutex_enter(&arpce->nce_lock);
	switch (arpce->nce_state) {
	case ND_REACHABLE:
		/* If there are other queued packets, queue this packet */
		if (arpce->nce_qd_mp != NULL) {
			if (mp != NULL)
				nce_queue_mp_common(arpce, mp, B_FALSE);
			mp = arpce->nce_qd_mp;
		}
		arpce->nce_qd_mp = NULL;
		mutex_exit(&arpce->nce_lock);

		/*
		 * Flush the queue.  In the common case, where the
		 * ARP is already resolved,  it will go through the
		 * while loop only once.
		 */
		while (mp != NULL) {

			nxt_mp = mp->b_next;
			mp->b_next = NULL;
			ASSERT(mp->b_datap->db_type != M_CTL);
			pkt_len = ntohs(((ipha_t *)mp->b_rptr)->ipha_length);
			/*
			 * This info is needed for IPQOS to do COS marking
			 * in ip_wput_attach_llhdr->ip_process.
			 */
			proc = (ip_proc_t)(uintptr_t)mp->b_prev;
			mp->b_prev = NULL;

			/* set up ill index for outbound qos processing */
			out_ill = ire_to_ill(ire);
			ill_index = out_ill->ill_phyint->phyint_ifindex;
			first_mp = ip_wput_attach_llhdr(mp, ire, proc,
			    ill_index, &ipha);
			if (first_mp == NULL) {
				xmit_drop = B_TRUE;
				BUMP_MIB(out_ill->ill_ip_mib,
				    ipIfStatsOutDiscards);
				goto next_mp;
			}

			/* non-ipsec hw accel case */
			if (io == NULL || !io->ipsec_out_accelerated) {
				/* send it */
				q = ire->ire_stq;
				if (proc == IPP_FWD_OUT) {
					UPDATE_IB_PKT_COUNT(ire);
				} else {
					UPDATE_OB_PKT_COUNT(ire);
				}
				ire->ire_last_used_time = lbolt;

				if (flow_ctl_enabled || canputnext(q)) {
					if (proc == IPP_FWD_OUT) {

					BUMP_MIB(out_ill->ill_ip_mib,
					    ipIfStatsHCOutForwDatagrams);

					}
					UPDATE_IP_MIB_OB_COUNTERS(out_ill,
					    pkt_len);

					DTRACE_IP7(send, mblk_t *, first_mp,
					    conn_t *, NULL, void_ip_t *, ipha,
					    __dtrace_ipsr_ill_t *, out_ill,
					    ipha_t *, ipha, ip6_t *, NULL, int,
					    0);

					ILL_SEND_TX(out_ill,
					    ire, connp, first_mp, 0);
				} else {
					BUMP_MIB(out_ill->ill_ip_mib,
					    ipIfStatsOutDiscards);
					xmit_drop = B_TRUE;
					freemsg(first_mp);
				}
			} else {
				/*
				 * Safety Pup says: make sure this
				 *  is going to the right interface!
				 */
				ill_t *ill1 =
				    (ill_t *)ire->ire_stq->q_ptr;
				int ifindex =
				    ill1->ill_phyint->phyint_ifindex;
				if (ifindex !=
				    io->ipsec_out_capab_ill_index) {
					xmit_drop = B_TRUE;
					freemsg(mp);
				} else {
					UPDATE_IP_MIB_OB_COUNTERS(ill1,
					    pkt_len);

					DTRACE_IP7(send, mblk_t *, first_mp,
					    conn_t *, NULL, void_ip_t *, ipha,
					    __dtrace_ipsr_ill_t *, ill1,
					    ipha_t *, ipha, ip6_t *, NULL,
					    int, 0);

					ipsec_hw_putnext(ire->ire_stq, mp);
				}
			}
next_mp:
			mp = nxt_mp;
		} /* while (mp != NULL) */
		if (xmit_drop)
			return (SEND_FAILED);
		else
			return (SEND_PASSED);

	case ND_INITIAL:
	case ND_INCOMPLETE:

		/*
		 * While we do send off packets to dests that
		 * use fully-resolved CGTP routes, we do not
		 * handle unresolved CGTP routes.
		 */
		ASSERT(!(ire->ire_flags & RTF_MULTIRT));
		ASSERT(io == NULL || !io->ipsec_out_accelerated);

		if (mp != NULL) {
			/* queue the packet */
			nce_queue_mp_common(arpce, mp, B_FALSE);
		}

		if (arpce->nce_state == ND_INCOMPLETE) {
			mutex_exit(&arpce->nce_lock);
			DTRACE_PROBE3(ip__xmit__incomplete,
			    (ire_t *), ire, (mblk_t *), mp,
			    (ipsec_out_t *), io);
			return (LOOKUP_IN_PROGRESS);
		}

		arpce->nce_state = ND_INCOMPLETE;
		mutex_exit(&arpce->nce_lock);
		/*
		 * Note that ire_add() (called from ire_forward())
		 * holds a ref on the ire until ARP is completed.
		 */

		ire_arpresolve(ire, ire_to_ill(ire));
		return (LOOKUP_IN_PROGRESS);
	default:
		ASSERT(0);
		mutex_exit(&arpce->nce_lock);
		return (LLHDR_RESLV_FAILED);
	}
}

#undef	UPDATE_IP_MIB_OB_COUNTERS

/*
 * Return B_TRUE if the buffers differ in length or content.
 * This is used for comparing extension header buffers.
 * Note that an extension header would be declared different
 * even if all that changed was the next header value in that header i.e.
 * what really changed is the next extension header.
 */
boolean_t
ip_cmpbuf(const void *abuf, uint_t alen, boolean_t b_valid, const void *bbuf,
    uint_t blen)
{
	if (!b_valid)
		blen = 0;

	if (alen != blen)
		return (B_TRUE);
	if (alen == 0)
		return (B_FALSE);	/* Both zero length */
	return (bcmp(abuf, bbuf, alen));
}

/*
 * Preallocate memory for ip_savebuf(). Returns B_TRUE if ok.
 * Return B_FALSE if memory allocation fails - don't change any state!
 */
boolean_t
ip_allocbuf(void **dstp, uint_t *dstlenp, boolean_t src_valid,
    const void *src, uint_t srclen)
{
	void *dst;

	if (!src_valid)
		srclen = 0;

	ASSERT(*dstlenp == 0);
	if (src != NULL && srclen != 0) {
		dst = mi_alloc(srclen, BPRI_MED);
		if (dst == NULL)
			return (B_FALSE);
	} else {
		dst = NULL;
	}
	if (*dstp != NULL)
		mi_free(*dstp);
	*dstp = dst;
	*dstlenp = dst == NULL ? 0 : srclen;
	return (B_TRUE);
}

/*
 * Replace what is in *dst, *dstlen with the source.
 * Assumes ip_allocbuf has already been called.
 */
void
ip_savebuf(void **dstp, uint_t *dstlenp, boolean_t src_valid,
    const void *src, uint_t srclen)
{
	if (!src_valid)
		srclen = 0;

	ASSERT(*dstlenp == srclen);
	if (src != NULL && srclen != 0)
		bcopy(src, *dstp, srclen);
}

/*
 * Free the storage pointed to by the members of an ip6_pkt_t.
 */
void
ip6_pkt_free(ip6_pkt_t *ipp)
{
	ASSERT(ipp->ipp_pathmtu == NULL && !(ipp->ipp_fields & IPPF_PATHMTU));

	if (ipp->ipp_fields & IPPF_HOPOPTS) {
		kmem_free(ipp->ipp_hopopts, ipp->ipp_hopoptslen);
		ipp->ipp_hopopts = NULL;
		ipp->ipp_hopoptslen = 0;
	}
	if (ipp->ipp_fields & IPPF_RTDSTOPTS) {
		kmem_free(ipp->ipp_rtdstopts, ipp->ipp_rtdstoptslen);
		ipp->ipp_rtdstopts = NULL;
		ipp->ipp_rtdstoptslen = 0;
	}
	if (ipp->ipp_fields & IPPF_DSTOPTS) {
		kmem_free(ipp->ipp_dstopts, ipp->ipp_dstoptslen);
		ipp->ipp_dstopts = NULL;
		ipp->ipp_dstoptslen = 0;
	}
	if (ipp->ipp_fields & IPPF_RTHDR) {
		kmem_free(ipp->ipp_rthdr, ipp->ipp_rthdrlen);
		ipp->ipp_rthdr = NULL;
		ipp->ipp_rthdrlen = 0;
	}
	ipp->ipp_fields &= ~(IPPF_HOPOPTS | IPPF_RTDSTOPTS | IPPF_DSTOPTS |
	    IPPF_RTHDR);
}

zoneid_t
ip_get_zoneid_v4(ipaddr_t addr, mblk_t *mp, ip_stack_t *ipst,
    zoneid_t lookup_zoneid)
{
	ire_t		*ire;
	int		ire_flags = MATCH_IRE_TYPE;
	zoneid_t	zoneid = ALL_ZONES;

	if (is_system_labeled() && !tsol_can_accept_raw(mp, B_FALSE))
		return (ALL_ZONES);

	if (lookup_zoneid != ALL_ZONES)
		ire_flags |= MATCH_IRE_ZONEONLY;
	ire = ire_ctable_lookup(addr, NULL, IRE_LOCAL | IRE_LOOPBACK, NULL,
	    lookup_zoneid, NULL, ire_flags, ipst);
	if (ire != NULL) {
		zoneid = IP_REAL_ZONEID(ire->ire_zoneid, ipst);
		ire_refrele(ire);
	}
	return (zoneid);
}

zoneid_t
ip_get_zoneid_v6(in6_addr_t *addr, mblk_t *mp, const ill_t *ill,
    ip_stack_t *ipst, zoneid_t lookup_zoneid)
{
	ire_t		*ire;
	int		ire_flags = MATCH_IRE_TYPE;
	zoneid_t	zoneid = ALL_ZONES;
	ipif_t		*ipif_arg = NULL;

	if (is_system_labeled() && !tsol_can_accept_raw(mp, B_FALSE))
		return (ALL_ZONES);

	if (IN6_IS_ADDR_LINKLOCAL(addr)) {
		ire_flags |= MATCH_IRE_ILL_GROUP;
		ipif_arg = ill->ill_ipif;
	}
	if (lookup_zoneid != ALL_ZONES)
		ire_flags |= MATCH_IRE_ZONEONLY;
	ire = ire_ctable_lookup_v6(addr, NULL, IRE_LOCAL | IRE_LOOPBACK,
	    ipif_arg, lookup_zoneid, NULL, ire_flags, ipst);
	if (ire != NULL) {
		zoneid = IP_REAL_ZONEID(ire->ire_zoneid, ipst);
		ire_refrele(ire);
	}
	return (zoneid);
}

/*
 * IP obserability hook support functions.
 */

static void
ipobs_init(ip_stack_t *ipst)
{
	ipst->ips_ipobs_enabled = B_FALSE;
	list_create(&ipst->ips_ipobs_cb_list, sizeof (ipobs_cb_t),
	    offsetof(ipobs_cb_t, ipobs_cbnext));
	mutex_init(&ipst->ips_ipobs_cb_lock, NULL, MUTEX_DEFAULT, NULL);
	ipst->ips_ipobs_cb_nwalkers = 0;
	cv_init(&ipst->ips_ipobs_cb_cv, NULL, CV_DRIVER, NULL);
}

static void
ipobs_fini(ip_stack_t *ipst)
{
	ipobs_cb_t *cb;

	mutex_enter(&ipst->ips_ipobs_cb_lock);
	while (ipst->ips_ipobs_cb_nwalkers != 0)
		cv_wait(&ipst->ips_ipobs_cb_cv, &ipst->ips_ipobs_cb_lock);

	while ((cb = list_head(&ipst->ips_ipobs_cb_list)) != NULL) {
		list_remove(&ipst->ips_ipobs_cb_list, cb);
		kmem_free(cb, sizeof (*cb));
	}
	list_destroy(&ipst->ips_ipobs_cb_list);
	mutex_exit(&ipst->ips_ipobs_cb_lock);
	mutex_destroy(&ipst->ips_ipobs_cb_lock);
	cv_destroy(&ipst->ips_ipobs_cb_cv);
}

void
ipobs_hook(mblk_t *mp, int htype, zoneid_t zsrc, zoneid_t zdst,
    const ill_t *ill, int ipver, uint32_t hlen, ip_stack_t *ipst)
{
	ipobs_cb_t *ipobs_cb;

	ASSERT(DB_TYPE(mp) == M_DATA);

	mutex_enter(&ipst->ips_ipobs_cb_lock);
	ipst->ips_ipobs_cb_nwalkers++;
	mutex_exit(&ipst->ips_ipobs_cb_lock);
	for (ipobs_cb = list_head(&ipst->ips_ipobs_cb_list); ipobs_cb != NULL;
	    ipobs_cb = list_next(&ipst->ips_ipobs_cb_list, ipobs_cb)) {
		mblk_t  *mp2 = allocb(sizeof (ipobs_hook_data_t),
		    BPRI_HI);
		if (mp2 != NULL) {
			ipobs_hook_data_t *ihd =
			    (ipobs_hook_data_t *)mp2->b_rptr;
			if (((ihd->ihd_mp = dupmsg(mp)) == NULL) &&
			    ((ihd->ihd_mp = copymsg(mp)) == NULL)) {
				freemsg(mp2);
				continue;
			}
			ihd->ihd_mp->b_rptr += hlen;
			ihd->ihd_htype = htype;
			ihd->ihd_ipver = ipver;
			ihd->ihd_zsrc = zsrc;
			ihd->ihd_zdst = zdst;
			ihd->ihd_ifindex = ill->ill_phyint->phyint_ifindex;
			ihd->ihd_stack = ipst->ips_netstack;
			mp2->b_wptr += sizeof (*ihd);
			ipobs_cb->ipobs_cbfunc(mp2);
		}
	}
	mutex_enter(&ipst->ips_ipobs_cb_lock);
	ipst->ips_ipobs_cb_nwalkers--;
	if (ipst->ips_ipobs_cb_nwalkers == 0)
		cv_broadcast(&ipst->ips_ipobs_cb_cv);
	mutex_exit(&ipst->ips_ipobs_cb_lock);
}

void
ipobs_register_hook(netstack_t *ns, pfv_t func)
{
	ipobs_cb_t   *cb;
	ip_stack_t *ipst = ns->netstack_ip;

	cb = kmem_alloc(sizeof (*cb), KM_SLEEP);

	mutex_enter(&ipst->ips_ipobs_cb_lock);
	while (ipst->ips_ipobs_cb_nwalkers != 0)
		cv_wait(&ipst->ips_ipobs_cb_cv, &ipst->ips_ipobs_cb_lock);
	ASSERT(ipst->ips_ipobs_cb_nwalkers == 0);

	cb->ipobs_cbfunc = func;
	list_insert_head(&ipst->ips_ipobs_cb_list, cb);
	ipst->ips_ipobs_enabled = B_TRUE;
	mutex_exit(&ipst->ips_ipobs_cb_lock);
}

void
ipobs_unregister_hook(netstack_t *ns, pfv_t func)
{
	ipobs_cb_t	*curcb;
	ip_stack_t	*ipst = ns->netstack_ip;

	mutex_enter(&ipst->ips_ipobs_cb_lock);
	while (ipst->ips_ipobs_cb_nwalkers != 0)
		cv_wait(&ipst->ips_ipobs_cb_cv, &ipst->ips_ipobs_cb_lock);

	for (curcb = list_head(&ipst->ips_ipobs_cb_list); curcb != NULL;
	    curcb = list_next(&ipst->ips_ipobs_cb_list, curcb)) {
		if (func == curcb->ipobs_cbfunc) {
			list_remove(&ipst->ips_ipobs_cb_list, curcb);
			kmem_free(curcb, sizeof (*curcb));
			break;
		}
	}
	if (list_is_empty(&ipst->ips_ipobs_cb_list))
		ipst->ips_ipobs_enabled = B_FALSE;
	mutex_exit(&ipst->ips_ipobs_cb_lock);
}
