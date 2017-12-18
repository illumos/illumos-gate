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
 * Copyright (c) 2017 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright (c) 2018 Joyent, Inc. All rights reserved.
 */

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
#include <sys/suntpi.h>
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
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/iptun/iptun_impl.h>
#include <inet/ipdrop.h>
#include <inet/ip_netinfo.h>
#include <inet/ilb_ip.h>

#include <sys/ethernet.h>
#include <net/if_types.h>
#include <sys/cpuvar.h>

#include <ipp/ipp.h>
#include <ipp/ipp_impl.h>
#include <ipp/ipgpc/ipgpc.h>

#include <sys/pattr.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/udp_impl.h>
#include <inet/rawip_impl.h>
#include <inet/rts_impl.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#include <sys/squeue_impl.h>
#include <inet/ip_arp.h>

#include <sys/clock_impl.h>	/* For LBOLT_FASTPATH{,64} */

/*
 * Values for squeue switch:
 * IP_SQUEUE_ENTER_NODRAIN: SQ_NODRAIN
 * IP_SQUEUE_ENTER: SQ_PROCESS
 * IP_SQUEUE_FILL: SQ_FILL
 */
int ip_squeue_enter = IP_SQUEUE_ENTER;	/* Setable in /etc/system */

int ip_squeue_flag;

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
	uint_t		ird_flags;	/* see below */
	listptr_t	ird_route;	/* ipRouteEntryTable */
	listptr_t	ird_netmedia;	/* ipNetToMediaEntryTable */
	listptr_t	ird_attrs;	/* ipRouteAttributeTable */
} iproutedata_t;

/* Include ire_testhidden and IRE_IF_CLONE routes */
#define	IRD_REPORT_ALL	0x01

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
int (*cl_inet_isclusterwide)(netstackid_t stack_id, uint8_t protocol,
    sa_family_t addr_family, uint8_t *laddrp, void *args) = NULL;

/*
 * Hook function to generate cluster wide ip fragment identifier
 */
uint32_t (*cl_inet_ipident)(netstackid_t stack_id, uint8_t protocol,
    sa_family_t addr_family, uint8_t *laddrp, uint8_t *faddrp,
    void *args) = NULL;

/*
 * Hook function to generate cluster wide SPI.
 */
void (*cl_inet_getspi)(netstackid_t, uint8_t, uint8_t *, size_t,
    void *) = NULL;

/*
 * Hook function to verify if the SPI is already utlized.
 */

int (*cl_inet_checkspi)(netstackid_t, uint8_t, uint32_t, void *) = NULL;

/*
 * Hook function to delete the SPI from the cluster wide repository.
 */

void (*cl_inet_deletespi)(netstackid_t, uint8_t, uint32_t, void *) = NULL;

/*
 * Hook function to inform the cluster when packet received on an IDLE SA
 */

void (*cl_inet_idlesa)(netstackid_t, uint8_t, uint32_t, sa_family_t,
    in6_addr_t, in6_addr_t, void *) = NULL;

/*
 * Synchronization notes:
 *
 * IP is a fully D_MP STREAMS module/driver. Thus it does not depend on any
 * MT level protection given by STREAMS. IP uses a combination of its own
 * internal serialization mechanism and standard Solaris locking techniques.
 * The internal serialization is per phyint.  This is used to serialize
 * plumbing operations, IPMP operations, most set ioctls, etc.
 *
 * Plumbing is a long sequence of operations involving message
 * exchanges between IP, ARP and device drivers. Many set ioctls are typically
 * involved in plumbing operations. A natural model is to serialize these
 * ioctls one per ill. For example plumbing of hme0 and qfe0 can go on in
 * parallel without any interference. But various set ioctls on hme0 are best
 * serialized, along with IPMP operations and processing of DLPI control
 * messages received from drivers on a per phyint basis. This serialization is
 * provided by the ipsq_t and primitives operating on this. Details can
 * be found in ip_if.c above the core primitives operating on ipsq_t.
 *
 * Lookups of an ipif or ill by a thread return a refheld ipif / ill.
 * Simiarly lookup of an ire by a thread also returns a refheld ire.
 * In addition ipif's and ill's referenced by the ire are also indirectly
 * refheld. Thus no ipif or ill can vanish as long as an ipif is refheld
 * directly or indirectly. For example an SIOCSLIFADDR ioctl that changes the
 * address of an ipif has to go through the ipsq_t. This ensures that only
 * one such exclusive operation proceeds at any time on the ipif. It then
 * waits for all refcnts
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
 * - ndp_g_lock and ncec_lock for protecting NCEs.
 *
 * - ill_lock protects fields of the ill and ipif. Details in ip.h
 *
 * - ill_g_lock: This is a global reader/writer lock. Protects the following
 *	* The AVL tree based global multi list of all ills.
 *	* The linked list of all ipifs of an ill
 *	* The <ipsq-xop> mapping
 *	* <ill-phyint> association
 *   Insertion/deletion of an ill in the system, insertion/deletion of an ipif
 *   into an ill, changing the <ipsq-xop> mapping of an ill, changing the
 *   <ill-phyint> assoc of an ill will all have to hold the ill_g_lock as
 *   writer for the actual duration of the insertion/deletion/change.
 *
 * - ill_lock:  This is a per ill mutex.
 *   It protects some members of the ill_t struct; see ip.h for details.
 *   It also protects the <ill-phyint> assoc.
 *   It also protects the list of ipifs hanging off the ill.
 *
 * - ipsq_lock: This is a per ipsq_t mutex lock.
 *   This protects some members of the ipsq_t struct; see ip.h for details.
 *   It also protects the <ipsq-ipxop> mapping
 *
 * - ipx_lock: This is a per ipxop_t mutex lock.
 *   This protects some members of the ipxop_t struct; see ip.h for details.
 *
 * - phyint_lock: This is a per phyint mutex lock. Protects just the
 *   phyint_flags
 *
 * - ip_addr_avail_lock: This is used to ensure the uniqueness of IP addresses.
 *   This lock is held in ipif_up_done and the ipif is marked IPIF_UP and the
 *   uniqueness check also done atomically.
 *
 * - ill_g_usesrc_lock: This readers/writer lock protects the usesrc
 *   group list linked by ill_usesrc_grp_next. It also protects the
 *   ill_usesrc_ifindex field. It is taken as a writer when a member of the
 *   group is being added or deleted.  This lock is taken as a reader when
 *   walking the list/group(eg: to get the number of members in a usesrc group).
 *   Note, it is only necessary to take this lock if the ill_usesrc_grp_next
 *   field is changing state i.e from NULL to non-NULL or vice-versa. For
 *   example, it is not necessary to take this lock in the initial portion
 *   of ip_sioctl_slifusesrc or at all in ip_sioctl_flags since these
 *   operations are executed exclusively and that ensures that the "usesrc
 *   group state" cannot change. The "usesrc group state" change can happen
 *   only in the latter part of ip_sioctl_slifusesrc and in ill_delete.
 *
 * Changing <ill-phyint>, <ipsq-xop> assocications:
 *
 * To change the <ill-phyint> association, the ill_g_lock must be held
 * as writer, and the ill_locks of both the v4 and v6 instance of the ill
 * must be held.
 *
 * To change the <ipsq-xop> association, the ill_g_lock must be held as
 * writer, the ipsq_lock must be held, and one must be writer on the ipsq.
 * This is only done when ills are added or removed from IPMP groups.
 *
 * To add or delete an ipif from the list of ipifs hanging off the ill,
 * ill_g_lock (writer) and ill_lock must be held and the thread must be
 * a writer on the associated ipsq.
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
 * ill_g_lock -> conn_lock -> ill_lock -> ipsq_lock -> ipx_lock
 * ill_g_lock -> ill_lock(s) -> phyint_lock
 * ill_g_lock -> ndp_g_lock -> ill_lock -> ncec_lock
 * ill_g_lock -> ip_addr_avail_lock
 * conn_lock -> irb_lock -> ill_lock -> ire_lock
 * ill_g_lock -> ip_g_nd_lock
 * ill_g_lock -> ips_ipmp_lock -> ill_lock -> nce_lock
 * ill_g_lock -> ndp_g_lock -> ill_lock -> ncec_lock -> nce_lock
 * arl_lock -> ill_lock
 * ips_ire_dep_lock -> irb_lock
 *
 * When more than 1 ill lock is needed to be held, all ill lock addresses
 * are sorted on address and locked starting from highest addressed lock
 * downward.
 *
 * Multicast scenarios
 * ips_ill_g_lock -> ill_mcast_lock
 * conn_ilg_lock -> ips_ill_g_lock -> ill_lock
 * ill_mcast_serializer -> ill_mcast_lock -> ips_ipmp_lock -> ill_lock
 * ill_mcast_serializer -> ill_mcast_lock -> connf_lock -> conn_lock
 * ill_mcast_serializer -> ill_mcast_lock -> conn_ilg_lock
 * ill_mcast_serializer -> ill_mcast_lock -> ips_igmp_timer_lock
 *
 * IPsec scenarios
 *
 * ipsa_lock -> ill_g_lock -> ill_lock
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
 * IRE dependencies - In some cases we hold ips_ire_dep_lock across ire_refrele
 * hence we will acquire irb_lock while holding ips_ire_dep_lock.
 *
 * IPsec notes :
 *
 * IP interacts with the IPsec code (AH/ESP) by storing IPsec attributes
 * in the ip_xmit_attr_t ip_recv_attr_t. For outbound datagrams, the
 * ip_xmit_attr_t has the
 * information used by the IPsec code for applying the right level of
 * protection. The information initialized by IP in the ip_xmit_attr_t
 * is determined by the per-socket policy or global policy in the system.
 * For inbound datagrams, the ip_recv_attr_t
 * starts out with nothing in it. It gets filled
 * with the right information if it goes through the AH/ESP code, which
 * happens if the incoming packet is secure. The information initialized
 * by AH/ESP, is later used by IP (during fanouts to ULP) to see whether
 * the policy requirements needed by per-socket policy or global policy
 * is met or not.
 *
 * For fully connected sockets i.e dst, src [addr, port] is known,
 * conn_policy_cached is set indicating that policy has been cached.
 * conn_in_enforce_policy may or may not be set depending on whether
 * there is a global policy match or per-socket policy match.
 * Policy inheriting happpens in ip_policy_set once the destination is known.
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
 * ---------------------
 * Non-TCP streams are flow controlled by IP. The way this is accomplished
 * differs when ILL_CAPAB_DLD_DIRECT is enabled for that IP instance. When
 * ILL_DIRECT_CAPABLE(ill) is TRUE, IP can do direct function calls into
 * GLDv3. Otherwise packets are sent down to lower layers using STREAMS
 * functions.
 *
 * Per Tx ring udp flow control:
 * This is applicable only when ILL_CAPAB_DLD_DIRECT capability is set in
 * the ill (i.e. ILL_DIRECT_CAPABLE(ill) is true).
 *
 * The underlying link can expose multiple Tx rings to the GLDv3 mac layer.
 * To achieve best performance, outgoing traffic need to be fanned out among
 * these Tx ring. mac_tx() is called (via str_mdata_fastpath_put()) to send
 * traffic out of the NIC and it takes a fanout hint. UDP connections pass
 * the address of connp as fanout hint to mac_tx(). Under flow controlled
 * condition, mac_tx() returns a non-NULL cookie (ip_mac_tx_cookie_t). This
 * cookie points to a specific Tx ring that is blocked. The cookie is used to
 * hash into an idl_tx_list[] entry in idl_tx_list[] array. Each idl_tx_list_t
 * point to drain_lists (idl_t's). These drain list will store the blocked UDP
 * connp's. The drain list is not a single list but a configurable number of
 * lists.
 *
 * The diagram below shows idl_tx_list_t's and their drain_lists. ip_stack_t
 * has an array of idl_tx_list_t. The size of the array is TX_FANOUT_SIZE
 * which is equal to 128. This array in turn contains a pointer to idl_t[],
 * the ip drain list. The idl_t[] array size is MIN(max_ncpus, 8). The drain
 * list will point to the list of connp's that are flow controlled.
 *
 *                      ---------------   -------   -------   -------
 *                   |->|drain_list[0]|-->|connp|-->|connp|-->|connp|-->
 *                   |  ---------------   -------   -------   -------
 *                   |  ---------------   -------   -------   -------
 *                   |->|drain_list[1]|-->|connp|-->|connp|-->|connp|-->
 * ----------------  |  ---------------   -------   -------   -------
 * |idl_tx_list[0]|->|  ---------------   -------   -------   -------
 * ----------------  |->|drain_list[2]|-->|connp|-->|connp|-->|connp|-->
 *                   |  ---------------   -------   -------   -------
 *                   .        .              .         .         .
 *                   |  ---------------   -------   -------   -------
 *                   |->|drain_list[n]|-->|connp|-->|connp|-->|connp|-->
 *                      ---------------   -------   -------   -------
 *                      ---------------   -------   -------   -------
 *                   |->|drain_list[0]|-->|connp|-->|connp|-->|connp|-->
 *                   |  ---------------   -------   -------   -------
 *                   |  ---------------   -------   -------   -------
 * ----------------  |->|drain_list[1]|-->|connp|-->|connp|-->|connp|-->
 * |idl_tx_list[1]|->|  ---------------   -------   -------   -------
 * ----------------  |        .              .         .         .
 *                   |  ---------------   -------   -------   -------
 *                   |->|drain_list[n]|-->|connp|-->|connp|-->|connp|-->
 *                      ---------------   -------   -------   -------
 *     .....
 * ----------------
 * |idl_tx_list[n]|-> ...
 * ----------------
 *
 * When mac_tx() returns a cookie, the cookie is hashed into an index into
 * ips_idl_tx_list[], and conn_drain_insert() is called with the idl_tx_list
 * to insert the conn onto.  conn_drain_insert() asserts flow control for the
 * sockets via su_txq_full() (non-STREAMS) or QFULL on conn_wq (STREAMS).
 * Further, conn_blocked is set to indicate that the conn is blocked.
 *
 * GLDv3 calls ill_flow_enable() when flow control is relieved.  The cookie
 * passed in the call to ill_flow_enable() identifies the blocked Tx ring and
 * is again hashed to locate the appropriate idl_tx_list, which is then
 * drained via conn_walk_drain().  conn_walk_drain() goes through each conn in
 * the drain list and calls conn_drain_remove() to clear flow control (via
 * calling su_txq_full() or clearing QFULL), and remove the conn from the
 * drain list.
 *
 * Note that the drain list is not a single list but a (configurable) array of
 * lists (8 elements by default).  Synchronization between drain insertion and
 * flow control wakeup is handled by using idl_txl->txl_lock, and only
 * conn_drain_insert() and conn_drain_remove() manipulate the drain list.
 *
 * Flow control via STREAMS is used when ILL_DIRECT_CAPABLE() returns FALSE.
 * On the send side, if the packet cannot be sent down to the driver by IP
 * (canput() fails), ip_xmit() drops the packet and returns EWOULDBLOCK to the
 * caller, who may then invoke ixa_check_drain_insert() to insert the conn on
 * the 0'th drain list.  When ip_wsrv() runs on the ill_wq because flow
 * control has been relieved, the blocked conns in the 0'th drain list are
 * drained as in the non-STREAMS case.
 *
 * In both the STREAMS and non-STREAMS cases, the sockfs upcall to set QFULL
 * is done when the conn is inserted into the drain list (conn_drain_insert())
 * and cleared when the conn is removed from the it (conn_drain_remove()).
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
 * Hooks are placed in ire_send_wire_v4 and ire_send_wire_v6.
 *
 * Inbound (local_in)
 * Hooks are placed in ip_fanout_v4 and ip_fanout_v6.
 *
 * Forwarding (in and out)
 * Hooks are placed in ire_recv_forward_v4/v6.
 *
 * IP Policy Framework processing (IPPF processing)
 * Policy processing for a packet is initiated by ip_process, which ascertains
 * that the classifier (ipgpc) is loaded and configured, failing which the
 * packet resumes normal processing in IP. If the clasifier is present, the
 * packet is acted upon by one or more IPQoS modules (action instances), per
 * filters configured in ipgpc and resumes normal IP processing thereafter.
 * An action instance can drop a packet in course of its processing.
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
 * IRE_IF_NORESOLVER (interface routes)	Exclusive
 * IRE_IF_RESOLVER (interface routes)	Exclusive
 * IRE_IF_CLONE (interface routes)	Exclusive
 * IRE_HOST (host routes)		Shared (*)
 *
 * (*) A zone can only use a default or off-subnet route if the gateway is
 * directly reachable from the zone, that is, if the gateway's address matches
 * one of the zone's logical interfaces.
 *
 * (x) IRE_LOCAL are handled a bit differently.
 * When ip_restrict_interzone_loopback is set (the default),
 * ire_route_recursive restricts loopback using an IRE_LOCAL
 * between zone to the case when L2 would have conceptually looped the packet
 * back, i.e. the loopback which is required since neither Ethernet drivers
 * nor Ethernet hardware loops them back. This is the case when the normal
 * routes (ignoring IREs with different zoneids) would send out the packet on
 * the same ill as the ill with which is IRE_LOCAL is associated.
 *
 * Multiple zones can share a common broadcast address; typically all zones
 * share the 255.255.255.255 address. Incoming as well as locally originated
 * broadcast packets must be dispatched to all the zones on the broadcast
 * network. For directed broadcasts (e.g. 10.16.72.255) this is not trivial
 * since some zones may not be on the 10.16.72/24 network. To handle this, each
 * zone has its own set of IRE_BROADCAST entries; then, broadcast packets are
 * sent to every zone that has an IRE_BROADCAST entry for the destination
 * address on the input ill, see ip_input_broadcast().
 *
 * Applications in different zones can join the same multicast group address.
 * The same logic applies for multicast as for broadcast. ip_input_multicast
 * dispatches packets to all zones that have members on the physical interface.
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

static int	ip_open(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp, boolean_t isv6);
static mblk_t	*ip_xmit_attach_llhdr(mblk_t *, nce_t *);

static boolean_t icmp_inbound_verify_v4(mblk_t *, icmph_t *, ip_recv_attr_t *);
static void	icmp_inbound_too_big_v4(icmph_t *, ip_recv_attr_t *);
static void	icmp_inbound_error_fanout_v4(mblk_t *, icmph_t *,
    ip_recv_attr_t *);
static void	icmp_options_update(ipha_t *);
static void	icmp_param_problem(mblk_t *, uint8_t,  ip_recv_attr_t *);
static void	icmp_pkt(mblk_t *, void *, size_t, ip_recv_attr_t *);
static mblk_t	*icmp_pkt_err_ok(mblk_t *, ip_recv_attr_t *);
static void	icmp_redirect_v4(mblk_t *mp, ipha_t *, icmph_t *,
    ip_recv_attr_t *);
static void	icmp_send_redirect(mblk_t *, ipaddr_t, ip_recv_attr_t *);
static void	icmp_send_reply_v4(mblk_t *, ipha_t *, icmph_t *,
    ip_recv_attr_t *);

mblk_t		*ip_dlpi_alloc(size_t, t_uscalar_t);
char		*ip_dot_addr(ipaddr_t, char *);
mblk_t		*ip_carve_mp(mblk_t **, ssize_t);
int		ip_close(queue_t *, int);
static char	*ip_dot_saddr(uchar_t *, char *);
static void	ip_lrput(queue_t *, mblk_t *);
ipaddr_t	ip_net_mask(ipaddr_t);
char		*ip_nv_lookup(nv_t *, int);
void	ip_rput(queue_t *, mblk_t *);
static void	ip_rput_dlpi_writer(ipsq_t *dummy_sq, queue_t *q, mblk_t *mp,
		    void *dummy_arg);
int		ip_snmp_get(queue_t *, mblk_t *, int, boolean_t);
static mblk_t	*ip_snmp_get_mib2_ip(queue_t *, mblk_t *,
		    mib2_ipIfStatsEntry_t *, ip_stack_t *, boolean_t);
static mblk_t	*ip_snmp_get_mib2_ip_traffic_stats(queue_t *, mblk_t *,
		    ip_stack_t *, boolean_t);
static mblk_t	*ip_snmp_get_mib2_ip6(queue_t *, mblk_t *, ip_stack_t *,
		    boolean_t);
static mblk_t	*ip_snmp_get_mib2_icmp(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_icmp6(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_igmp(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_multi(queue_t *, mblk_t *, ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip_addr(queue_t *, mblk_t *,
		    ip_stack_t *ipst, boolean_t);
static mblk_t	*ip_snmp_get_mib2_ip6_addr(queue_t *, mblk_t *,
		    ip_stack_t *ipst, boolean_t);
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
static mblk_t	*ip_snmp_get_mib2_ip_route_media(queue_t *, mblk_t *, int,
		    ip_stack_t *ipst);
static mblk_t	*ip_snmp_get_mib2_ip6_route_media(queue_t *, mblk_t *, int,
		    ip_stack_t *ipst);
static void	ip_snmp_get2_v4(ire_t *, iproutedata_t *);
static void	ip_snmp_get2_v6_route(ire_t *, iproutedata_t *);
static int	ip_snmp_get2_v4_media(ncec_t *, iproutedata_t *);
static int	ip_snmp_get2_v6_media(ncec_t *, iproutedata_t *);
int		ip_snmp_set(queue_t *, int, int, uchar_t *, int);

static mblk_t	*ip_fragment_copyhdr(uchar_t *, int, int, ip_stack_t *,
		    mblk_t *);

static void	conn_drain_init(ip_stack_t *);
static void	conn_drain_fini(ip_stack_t *);
static void	conn_drain(conn_t *connp, boolean_t closing);

static void	conn_walk_drain(ip_stack_t *, idl_tx_list_t *);
static void	conn_walk_sctp(pfv_t, void *, zoneid_t, netstack_t *);

static void	*ip_stack_init(netstackid_t stackid, netstack_t *ns);
static void	ip_stack_shutdown(netstackid_t stackid, void *arg);
static void	ip_stack_fini(netstackid_t stackid, void *arg);

static int	ip_multirt_apply_membership(int (*fn)(conn_t *, boolean_t,
    const in6_addr_t *, ipaddr_t, uint_t, mcast_record_t, const in6_addr_t *),
    ire_t *, conn_t *, boolean_t, const in6_addr_t *,  mcast_record_t,
    const in6_addr_t *);

static int	ip_squeue_switch(int);

static void	*ip_kstat_init(netstackid_t, ip_stack_t *);
static void	ip_kstat_fini(netstackid_t, kstat_t *);
static int	ip_kstat_update(kstat_t *kp, int rw);
static void	*icmp_kstat_init(netstackid_t);
static void	icmp_kstat_fini(netstackid_t, kstat_t *);
static int	icmp_kstat_update(kstat_t *kp, int rw);
static void	*ip_kstat2_init(netstackid_t, ip_stat_t *);
static void	ip_kstat2_fini(netstackid_t, kstat_t *);

static void	ipobs_init(ip_stack_t *);
static void	ipobs_fini(ip_stack_t *);

static int	ip_tp_cpu_update(cpu_setup_t, int, void *);

ipaddr_t	ip_g_all_ones = IP_HOST_MASK;

static long ip_rput_pullups;
int	dohwcksum = 1;	/* use h/w cksum if supported by the hardware */

vmem_t *ip_minor_arena_sa; /* for minor nos. from INET_MIN_DEV+2 thru 2^^18-1 */
vmem_t *ip_minor_arena_la; /* for minor nos. from 2^^18 thru 2^^32-1 */

int	ip_debug;

/*
 * Multirouting/CGTP stuff
 */
int	ip_cgtp_filter_rev = CGTP_FILTER_REV;	/* CGTP hooks version */

/*
 * IP tunables related declarations. Definitions are in ip_tunables.c
 */
extern mod_prop_info_t ip_propinfo_tbl[];
extern int ip_propinfo_count;

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
	/* 013 */ { SIOCGIFADDR, sizeof (struct ifreq), IPI_GET_CMD,
			IF_CMD, ip_sioctl_get_addr, NULL },

	/* 014 */ { SIOCSIFDSTADDR, sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_dstaddr, ip_sioctl_dstaddr_restart },
	/* 015 */ { SIOCGIFDSTADDR, sizeof (struct ifreq),
			IPI_GET_CMD, IF_CMD, ip_sioctl_get_dstaddr, NULL },

	/* 016 */ { SIOCSIFFLAGS, sizeof (struct ifreq),
			IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_flags, ip_sioctl_flags_restart },
	/* 017 */ { SIOCGIFFLAGS, sizeof (struct ifreq),
			IPI_MODOK | IPI_GET_CMD,
			IF_CMD, ip_sioctl_get_flags, NULL },

	/* 018 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 019 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* copyin size cannot be coded for SIOCGIFCONF */
	/* 020 */ { O_SIOCGIFCONF, 0, IPI_GET_CMD,
			MISC_CMD, ip_sioctl_get_ifconf, NULL },

	/* 021 */ { SIOCSIFMTU,	sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_mtu, NULL },
	/* 022 */ { SIOCGIFMTU,	sizeof (struct ifreq), IPI_GET_CMD,
			IF_CMD, ip_sioctl_get_mtu, NULL },
	/* 023 */ { SIOCGIFBRDADDR, sizeof (struct ifreq),
			IPI_GET_CMD, IF_CMD, ip_sioctl_get_brdaddr, NULL },
	/* 024 */ { SIOCSIFBRDADDR, sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_brdaddr, NULL },
	/* 025 */ { SIOCGIFNETMASK, sizeof (struct ifreq),
			IPI_GET_CMD, IF_CMD, ip_sioctl_get_netmask, NULL },
	/* 026 */ { SIOCSIFNETMASK, sizeof (struct ifreq), IPI_PRIV | IPI_WR,
			IF_CMD, ip_sioctl_netmask, ip_sioctl_netmask_restart },
	/* 027 */ { SIOCGIFMETRIC, sizeof (struct ifreq),
			IPI_GET_CMD, IF_CMD, ip_sioctl_get_metric, NULL },
	/* 028 */ { SIOCSIFMETRIC, sizeof (struct ifreq), IPI_PRIV,
			IF_CMD, ip_sioctl_metric, NULL },
	/* 029 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* See 166-168 below for extended SIOC*XARP ioctls */
	/* 030 */ { SIOCSARP, sizeof (struct arpreq), IPI_PRIV | IPI_WR,
			ARP_CMD, ip_sioctl_arp, NULL },
	/* 031 */ { SIOCGARP, sizeof (struct arpreq), IPI_GET_CMD,
			ARP_CMD, ip_sioctl_arp, NULL },
	/* 032 */ { SIOCDARP, sizeof (struct arpreq), IPI_PRIV | IPI_WR,
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

	/* 087 */ { SIOCGIFNUM, sizeof (int), IPI_GET_CMD,
			MISC_CMD, ip_sioctl_get_ifnum, NULL },
	/* 088 */ { SIOCGIFMUXID, sizeof (struct ifreq), IPI_GET_CMD,
			IF_CMD, ip_sioctl_get_muxid, NULL },
	/* 089 */ { SIOCSIFMUXID, sizeof (struct ifreq),
			IPI_PRIV | IPI_WR, IF_CMD, ip_sioctl_muxid, NULL },

	/* Both if and lif variants share same func */
	/* 090 */ { SIOCGIFINDEX, sizeof (struct ifreq), IPI_GET_CMD,
			IF_CMD, ip_sioctl_get_lifindex, NULL },
	/* Both if and lif variants share same func */
	/* 091 */ { SIOCSIFINDEX, sizeof (struct ifreq),
			IPI_PRIV | IPI_WR, IF_CMD, ip_sioctl_slifindex, NULL },

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
			IPI_PRIV | IPI_WR, LIF_CMD, ip_sioctl_removeif,
			ip_sioctl_removeif_restart },
	/* 111 */ { SIOCLIFADDIF, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_addif, NULL },
#define	SIOCLIFADDR_NDX 112
	/* 112 */ { SIOCSLIFADDR, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_addr, ip_sioctl_addr_restart },
	/* 113 */ { SIOCGLIFADDR, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_addr, NULL },
	/* 114 */ { SIOCSLIFDSTADDR, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_dstaddr, ip_sioctl_dstaddr_restart },
	/* 115 */ { SIOCGLIFDSTADDR, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_dstaddr, NULL },
	/* 116 */ { SIOCSLIFFLAGS, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_flags, ip_sioctl_flags_restart },
	/* 117 */ { SIOCGLIFFLAGS, sizeof (struct lifreq),
			IPI_GET_CMD | IPI_MODOK,
			LIF_CMD, ip_sioctl_get_flags, NULL },

	/* 118 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 119 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 120 */ { O_SIOCGLIFCONF, 0, IPI_GET_CMD, MISC_CMD,
			ip_sioctl_get_lifconf, NULL },
	/* 121 */ { SIOCSLIFMTU, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_mtu, NULL },
	/* 122 */ { SIOCGLIFMTU, sizeof (struct lifreq), IPI_GET_CMD,
			LIF_CMD, ip_sioctl_get_mtu, NULL },
	/* 123 */ { SIOCGLIFBRDADDR, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_brdaddr, NULL },
	/* 124 */ { SIOCSLIFBRDADDR, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_brdaddr, NULL },
	/* 125 */ { SIOCGLIFNETMASK, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_netmask, NULL },
	/* 126 */ { SIOCSLIFNETMASK, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_netmask, ip_sioctl_netmask_restart },
	/* 127 */ { SIOCGLIFMETRIC, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_metric, NULL },
	/* 128 */ { SIOCSLIFMETRIC, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_metric, NULL },
	/* 129 */ { SIOCSLIFNAME, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR | IPI_MODOK,
			LIF_CMD, ip_sioctl_slifname,
			ip_sioctl_slifname_restart },

	/* 130 */ { SIOCGLIFNUM, sizeof (struct lifnum), IPI_GET_CMD,
			MISC_CMD, ip_sioctl_get_lifnum, NULL },
	/* 131 */ { SIOCGLIFMUXID, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_muxid, NULL },
	/* 132 */ { SIOCSLIFMUXID, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR, LIF_CMD, ip_sioctl_muxid, NULL },
	/* 133 */ { SIOCGLIFINDEX, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_lifindex, 0 },
	/* 134 */ { SIOCSLIFINDEX, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR, LIF_CMD, ip_sioctl_slifindex, 0 },
	/* 135 */ { SIOCSLIFTOKEN, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_token, NULL },
	/* 136 */ { SIOCGLIFTOKEN, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_token, NULL },
	/* 137 */ { SIOCSLIFSUBNET, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_subnet, ip_sioctl_subnet_restart },
	/* 138 */ { SIOCGLIFSUBNET, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_subnet, NULL },
	/* 139 */ { SIOCSLIFLNKINFO, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_lnkinfo, NULL },

	/* 140 */ { SIOCGLIFLNKINFO, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_lnkinfo, NULL },
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
	/* 147 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 148 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* Old *IPSECONFIG ioctls are now deprecated, now see spdsock.c */
	/* 149 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 150 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 151 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 152 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 153 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 154 */ { SIOCGLIFBINDING, sizeof (struct lifreq), IPI_GET_CMD,
			LIF_CMD, ip_sioctl_get_binding, NULL },
	/* 155 */ { SIOCSLIFGROUPNAME, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_groupname, ip_sioctl_groupname },
	/* 156 */ { SIOCGLIFGROUPNAME, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_groupname, NULL },
	/* 157 */ { SIOCGLIFGROUPINFO, sizeof (lifgroupinfo_t),
			IPI_GET_CMD, MISC_CMD, ip_sioctl_groupinfo, NULL },

	/* Leave 158-160 unused; used to be SIOC*IFARP ioctls */
	/* 158 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 159 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* 160 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* 161 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },

	/* These are handled in ip_sioctl_copyin_setup itself */
	/* 162 */ { SIOCGIP6ADDRPOLICY, 0, IPI_NULL_BCONT,
			MISC_CMD, NULL, NULL },
	/* 163 */ { SIOCSIP6ADDRPOLICY, 0, IPI_PRIV | IPI_NULL_BCONT,
			MISC_CMD, NULL, NULL },
	/* 164 */ { SIOCGDSTINFO, 0, IPI_GET_CMD, MISC_CMD, NULL, NULL },

	/* 165 */ { SIOCGLIFCONF, 0, IPI_GET_CMD, MISC_CMD,
			ip_sioctl_get_lifconf, NULL },

	/* 166 */ { SIOCSXARP, sizeof (struct xarpreq), IPI_PRIV | IPI_WR,
			XARP_CMD, ip_sioctl_arp, NULL },
	/* 167 */ { SIOCGXARP, sizeof (struct xarpreq), IPI_GET_CMD,
			XARP_CMD, ip_sioctl_arp, NULL },
	/* 168 */ { SIOCDXARP, sizeof (struct xarpreq), IPI_PRIV | IPI_WR,
			XARP_CMD, ip_sioctl_arp, NULL },

	/* SIOCPOPSOCKFS is not handled by IP */
	/* 169 */ { IPI_DONTCARE /* SIOCPOPSOCKFS */, 0, 0, 0, NULL, NULL },

	/* 170 */ { SIOCGLIFZONE, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_lifzone, NULL },
	/* 171 */ { SIOCSLIFZONE, sizeof (struct lifreq),
			IPI_PRIV | IPI_WR, LIF_CMD, ip_sioctl_slifzone,
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
	/* 179 */ { SIOCSMSFILTER, sizeof (struct group_filter), 0,
			MSFILT_CMD, ip_sioctl_msfilter, NULL },
	/* 180 */ { SIOCGIPMSFILTER, sizeof (struct ip_msfilter), IPI_GET_CMD,
			MSFILT_CMD, ip_sioctl_msfilter, NULL },
	/* 181 */ { SIOCSIPMSFILTER, sizeof (struct ip_msfilter), 0,
			MSFILT_CMD, ip_sioctl_msfilter, NULL },
	/* 182 */ { IPI_DONTCARE, 0, 0, 0, NULL, NULL },
	/* SIOCSENABLESDP is handled by SDP */
	/* 183 */ { IPI_DONTCARE /* SIOCSENABLESDP */, 0, 0, 0, NULL, NULL },
	/* 184 */ { IPI_DONTCARE /* SIOCSQPTR */, 0, 0, 0, NULL, NULL },
	/* 185 */ { SIOCGIFHWADDR, sizeof (struct ifreq), IPI_GET_CMD,
			IF_CMD, ip_sioctl_get_ifhwaddr, NULL },
	/* 186 */ { IPI_DONTCARE /* SIOCGSTAMP */, 0, 0, 0, NULL, NULL },
	/* 187 */ { SIOCILB, 0, IPI_PRIV | IPI_GET_CMD, MISC_CMD,
			ip_sioctl_ilb_cmd, NULL },
	/* 188 */ { SIOCGETPROP, 0, IPI_GET_CMD, 0, NULL, NULL },
	/* 189 */ { SIOCSETPROP, 0, IPI_PRIV | IPI_WR, 0, NULL, NULL},
	/* 190 */ { SIOCGLIFDADSTATE, sizeof (struct lifreq),
			IPI_GET_CMD, LIF_CMD, ip_sioctl_get_dadstate, NULL },
	/* 191 */ { SIOCSLIFPREFIX, sizeof (struct lifreq), IPI_PRIV | IPI_WR,
			LIF_CMD, ip_sioctl_prefix, ip_sioctl_prefix_restart },
	/* 192 */ { SIOCGLIFHWADDR, sizeof (struct lifreq), IPI_GET_CMD,
			LIF_CMD, ip_sioctl_get_lifhwaddr, NULL }
};

int ip_ndx_ioctl_count = sizeof (ip_ndx_ioctl_table) / sizeof (ip_ioctl_cmd_t);

ip_ioctl_cmd_t ip_misc_ioctl_table[] = {
	{ I_LINK,	0, IPI_PRIV | IPI_WR, 0, NULL, NULL },
	{ I_UNLINK,	0, IPI_PRIV | IPI_WR, 0, NULL, NULL },
	{ I_PLINK,	0, IPI_PRIV | IPI_WR, 0, NULL, NULL },
	{ I_PUNLINK,	0, IPI_PRIV | IPI_WR, 0, NULL, NULL },
	{ ND_GET,	0, 0, 0, NULL, NULL },
	{ ND_SET,	0, IPI_PRIV | IPI_WR, 0, NULL, NULL },
	{ IP_IOCTL,	0, 0, 0, NULL, NULL },
	{ SIOCGETVIFCNT, sizeof (struct sioc_vif_req), IPI_GET_CMD,
		MISC_CMD, mrt_ioctl},
	{ SIOCGETSGCNT,	sizeof (struct sioc_sg_req), IPI_GET_CMD,
		MISC_CMD, mrt_ioctl},
	{ SIOCGETLSGCNT, sizeof (struct sioc_lsg_req), IPI_GET_CMD,
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
	{ IRE_DEFAULT, "DEFAULT" },
	{ IRE_PREFIX, "PREFIX" },
	{ IRE_IF_NORESOLVER, "IF_NORESOL" },
	{ IRE_IF_RESOLVER, "IF_RESOLV" },
	{ IRE_IF_CLONE, "IF_CLONE" },
	{ IRE_HOST, "HOST" },
	{ IRE_MULTICAST, "MULTICAST" },
	{ IRE_NOROUTE, "NOROUTE" },
	{ 0 }
};

nv_t	*ire_nv_tbl = ire_nv_arr;

/* Simple ICMP IP Header Template */
static ipha_t icmp_ipha = {
	IP_SIMPLE_HDR_VERSION, 0, 0, 0, 0, 0, IPPROTO_ICMP
};

struct module_info ip_mod_info = {
	IP_MOD_ID, IP_MOD_NAME, IP_MOD_MINPSZ, IP_MOD_MAXPSZ, IP_MOD_HIWAT,
	IP_MOD_LOWAT
};

/*
 * Duplicate static symbols within a module confuses mdb; so we avoid the
 * problem by making the symbols here distinct from those in udp.c.
 */

/*
 * Entry points for IP as a device and as a module.
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

static struct qinit ipwinit = {
	(pfi_t)ip_wput_nondata, (pfi_t)ip_wsrv, NULL, NULL, NULL,
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
	&iprinitv4, &ipwinit, &iplrinit, &iplwinit
};

/* For AF_INET6 aka /dev/ip6 */
struct streamtab ipinfov6 = {
	&iprinitv6, &ipwinit, &iplrinit, &iplwinit
};

#ifdef	DEBUG
boolean_t skip_sctp_cksum = B_FALSE;
#endif

/*
 * Generate an ICMP fragmentation needed message.
 * When called from ip_output side a minimal ip_recv_attr_t needs to be
 * constructed by the caller.
 */
void
icmp_frag_needed(mblk_t *mp, int mtu, ip_recv_attr_t *ira)
{
	icmph_t	icmph;
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;

	mp = icmp_pkt_err_ok(mp, ira);
	if (mp == NULL)
		return;

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_DEST_UNREACHABLE;
	icmph.icmph_code = ICMP_FRAGMENTATION_NEEDED;
	icmph.icmph_du_mtu = htons((uint16_t)mtu);
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutFragNeeded);
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDestUnreachs);

	icmp_pkt(mp, &icmph, sizeof (icmph_t), ira);
}

/*
 * icmp_inbound_v4 deals with ICMP messages that are handled by IP.
 * If the ICMP message is consumed by IP, i.e., it should not be delivered
 * to any IPPROTO_ICMP raw sockets, then it returns NULL.
 * Likewise, if the ICMP error is misformed (too short, etc), then it
 * returns NULL. The caller uses this to determine whether or not to send
 * to raw sockets.
 *
 * All error messages are passed to the matching transport stream.
 *
 * The following cases are handled by icmp_inbound:
 * 1) It needs to send a reply back and possibly delivering it
 *    to the "interested" upper clients.
 * 2) Return the mblk so that the caller can pass it to the RAW socket clients.
 * 3) It needs to change some values in IP only.
 * 4) It needs to change some values in IP and upper layers e.g TCP
 *    by delivering an error to the upper layers.
 *
 * We handle the above three cases in the context of IPsec in the
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
 *	     adjusted dce_pmtu, the next outbound datagram would
 *	     generate a local ICMP_FRAGMENTATION_NEEDED message - which
 *	     will be with the right level of protection. Thus the right
 *	     value will be communicated even if we are not able to
 *	     communicate when we get from the wire initially. But this
 *	     assumes there would be at least one outbound datagram after
 *	     IP has adjusted its dce_pmtu value. To make things
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
 */
mblk_t *
icmp_inbound_v4(mblk_t *mp, ip_recv_attr_t *ira)
{
	icmph_t		*icmph;
	ipha_t		*ipha;		/* Outer header */
	int		ip_hdr_length;	/* Outer header length */
	boolean_t	interested;
	ipif_t		*ipif;
	uint32_t	ts;
	uint32_t	*tsp;
	timestruc_t	now;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	zoneid_t	zoneid = ira->ira_zoneid;
	int		len_needed;
	mblk_t		*mp_ret = NULL;

	ipha = (ipha_t *)mp->b_rptr;

	BUMP_MIB(&ipst->ips_icmp_mib, icmpInMsgs);

	ip_hdr_length = ira->ira_ip_hdr_length;
	if ((mp->b_wptr - mp->b_rptr) < (ip_hdr_length + ICMPH_SIZE)) {
		if (ira->ira_pktlen < (ip_hdr_length + ICMPH_SIZE)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		/* Last chance to get real. */
		ipha = ip_pullup(mp, ip_hdr_length + ICMPH_SIZE, ira);
		if (ipha == NULL) {
			BUMP_MIB(&ipst->ips_icmp_mib, icmpInErrors);
			freemsg(mp);
			return (NULL);
		}
	}

	/* The IP header will always be a multiple of four bytes */
	icmph = (icmph_t *)&mp->b_rptr[ip_hdr_length];
	ip2dbg(("icmp_inbound_v4: type %d code %d\n", icmph->icmph_type,
	    icmph->icmph_code));

	/*
	 * We will set "interested" to "true" if we should pass a copy to
	 * the transport or if we handle the packet locally.
	 */
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
		if (ira->ira_flags & IRAF_MULTICAST) {
			/* multicast: respond based on tunable */
			interested = ipst->ips_ip_g_resp_to_echo_mcast;
		} else if (ira->ira_flags & IRAF_BROADCAST) {
			/* broadcast: respond based on tunable */
			interested = ipst->ips_ip_g_resp_to_echo_bcast;
		} else {
			/* unicast: always respond */
			interested = B_TRUE;
		}
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInEchos);
		if (!interested) {
			/* We never pass these to RAW sockets */
			freemsg(mp);
			return (NULL);
		}

		/* Check db_ref to make sure we can modify the packet. */
		if (mp->b_datap->db_ref > 1) {
			mblk_t	*mp1;

			mp1 = copymsg(mp);
			freemsg(mp);
			if (!mp1) {
				BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
				return (NULL);
			}
			mp = mp1;
			ipha = (ipha_t *)mp->b_rptr;
			icmph = (icmph_t *)&mp->b_rptr[ip_hdr_length];
		}
		icmph->icmph_type = ICMP_ECHO_REPLY;
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutEchoReps);
		icmp_send_reply_v4(mp, ipha, icmph, ira);
		return (NULL);

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
		if (ipst->ips_ip_g_resp_to_timestamp) {
			if (ira->ira_flags & IRAF_MULTIBROADCAST)
				interested =
				    ipst->ips_ip_g_resp_to_timestamp_bcast;
			else
				interested = B_TRUE;
		}
		if (!interested) {
			/* We never pass these to RAW sockets */
			freemsg(mp);
			return (NULL);
		}

		/* Make sure we have enough of the packet */
		len_needed = ip_hdr_length + ICMPH_SIZE +
		    3 * sizeof (uint32_t);

		if (mp->b_wptr - mp->b_rptr < len_needed) {
			ipha = ip_pullup(mp, len_needed, ira);
			if (ipha == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards - ip_pullup",
				    mp, ill);
				freemsg(mp);
				return (NULL);
			}
			/* Refresh following the pullup. */
			icmph = (icmph_t *)&mp->b_rptr[ip_hdr_length];
		}
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInTimestamps);
		/* Check db_ref to make sure we can modify the packet. */
		if (mp->b_datap->db_ref > 1) {
			mblk_t	*mp1;

			mp1 = copymsg(mp);
			freemsg(mp);
			if (!mp1) {
				BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
				return (NULL);
			}
			mp = mp1;
			ipha = (ipha_t *)mp->b_rptr;
			icmph = (icmph_t *)&mp->b_rptr[ip_hdr_length];
		}
		icmph->icmph_type = ICMP_TIME_STAMP_REPLY;
		tsp = (uint32_t *)&icmph[1];
		tsp++;		/* Skip past 'originate time' */
		/* Compute # of milliseconds since midnight */
		gethrestime(&now);
		ts = (now.tv_sec % (24 * 60 * 60)) * 1000 +
		    NSEC2MSEC(now.tv_nsec);
		*tsp++ = htonl(ts);	/* Lay in 'receive time' */
		*tsp++ = htonl(ts);	/* Lay in 'send time' */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutTimestampReps);
		icmp_send_reply_v4(mp, ipha, icmph, ira);
		return (NULL);

	case ICMP_TIME_STAMP_REPLY:
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInTimestampReps);
		break;
	case ICMP_INFO_REQUEST:
		/* Per RFC 1122 3.2.2.7, ignore this. */
	case ICMP_INFO_REPLY:
		break;
	case ICMP_ADDRESS_MASK_REQUEST:
		if (ira->ira_flags & IRAF_MULTIBROADCAST) {
			interested =
			    ipst->ips_ip_respond_to_address_mask_broadcast;
		} else {
			interested = B_TRUE;
		}
		if (!interested) {
			/* We never pass these to RAW sockets */
			freemsg(mp);
			return (NULL);
		}
		len_needed = ip_hdr_length + ICMPH_SIZE + IP_ADDR_LEN;
		if (mp->b_wptr - mp->b_rptr < len_needed) {
			ipha = ip_pullup(mp, len_needed, ira);
			if (ipha == NULL) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInTruncatedPkts);
				ip_drop_input("ipIfStatsInTruncatedPkts", mp,
				    ill);
				freemsg(mp);
				return (NULL);
			}
			/* Refresh following the pullup. */
			icmph = (icmph_t *)&mp->b_rptr[ip_hdr_length];
		}
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInAddrMasks);
		/* Check db_ref to make sure we can modify the packet. */
		if (mp->b_datap->db_ref > 1) {
			mblk_t	*mp1;

			mp1 = copymsg(mp);
			freemsg(mp);
			if (!mp1) {
				BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
				return (NULL);
			}
			mp = mp1;
			ipha = (ipha_t *)mp->b_rptr;
			icmph = (icmph_t *)&mp->b_rptr[ip_hdr_length];
		}
		/*
		 * Need the ipif with the mask be the same as the source
		 * address of the mask reply. For unicast we have a specific
		 * ipif. For multicast/broadcast we only handle onlink
		 * senders, and use the source address to pick an ipif.
		 */
		ipif = ipif_lookup_addr(ipha->ipha_dst, ill, zoneid, ipst);
		if (ipif == NULL) {
			/* Broadcast or multicast */
			ipif = ipif_lookup_remote(ill, ipha->ipha_src, zoneid);
			if (ipif == NULL) {
				freemsg(mp);
				return (NULL);
			}
		}
		icmph->icmph_type = ICMP_ADDRESS_MASK_REPLY;
		bcopy(&ipif->ipif_net_mask, &icmph[1], IP_ADDR_LEN);
		ipif_refrele(ipif);
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutAddrMaskReps);
		icmp_send_reply_v4(mp, ipha, icmph, ira);
		return (NULL);

	case ICMP_ADDRESS_MASK_REPLY:
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInAddrMaskReps);
		break;
	default:
		interested = B_TRUE;	/* Pass up to transport */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInUnknowns);
		break;
	}
	/*
	 * See if there is an ICMP client to avoid an extra copymsg/freemsg
	 * if there isn't one.
	 */
	if (ipst->ips_ipcl_proto_fanout_v4[IPPROTO_ICMP].connf_head != NULL) {
		/* If there is an ICMP client and we want one too, copy it. */

		if (!interested) {
			/* Caller will deliver to RAW sockets */
			return (mp);
		}
		mp_ret = copymsg(mp);
		if (mp_ret == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - copymsg", mp, ill);
		}
	} else if (!interested) {
		/* Neither we nor raw sockets are interested. Drop packet now */
		freemsg(mp);
		return (NULL);
	}

	/*
	 * ICMP error or redirect packet. Make sure we have enough of
	 * the header and that db_ref == 1 since we might end up modifying
	 * the packet.
	 */
	if (mp->b_cont != NULL) {
		if (ip_pullup(mp, -1, ira) == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - ip_pullup",
			    mp, ill);
			freemsg(mp);
			return (mp_ret);
		}
	}

	if (mp->b_datap->db_ref > 1) {
		mblk_t	*mp1;

		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - copymsg", mp, ill);
			freemsg(mp);
			return (mp_ret);
		}
		freemsg(mp);
		mp = mp1;
	}

	/*
	 * In case mp has changed, verify the message before any further
	 * processes.
	 */
	ipha = (ipha_t *)mp->b_rptr;
	icmph = (icmph_t *)&mp->b_rptr[ip_hdr_length];
	if (!icmp_inbound_verify_v4(mp, icmph, ira)) {
		freemsg(mp);
		return (mp_ret);
	}

	switch (icmph->icmph_type) {
	case ICMP_REDIRECT:
		icmp_redirect_v4(mp, ipha, icmph, ira);
		break;
	case ICMP_DEST_UNREACHABLE:
		if (icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED) {
			/* Update DCE and adjust MTU is icmp header if needed */
			icmp_inbound_too_big_v4(icmph, ira);
		}
		/* FALLTHRU */
	default:
		icmp_inbound_error_fanout_v4(mp, icmph, ira);
		break;
	}
	return (mp_ret);
}

/*
 * Send an ICMP echo, timestamp or address mask reply.
 * The caller has already updated the payload part of the packet.
 * We handle the ICMP checksum, IP source address selection and feed
 * the packet into ip_output_simple.
 */
static void
icmp_send_reply_v4(mblk_t *mp, ipha_t *ipha, icmph_t *icmph,
    ip_recv_attr_t *ira)
{
	uint_t		ip_hdr_length = ira->ira_ip_hdr_length;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ip_xmit_attr_t	ixas;

	/* Send out an ICMP packet */
	icmph->icmph_checksum = 0;
	icmph->icmph_checksum = IP_CSUM(mp, ip_hdr_length, 0);
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

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_BASIC_SIMPLE_V4;
	ixas.ixa_zoneid = ira->ira_zoneid;
	ixas.ixa_cred = kcred;
	ixas.ixa_cpid = NOPID;
	ixas.ixa_tsl = ira->ira_tsl;	/* Behave as a multi-level responder */
	ixas.ixa_ifindex = 0;
	ixas.ixa_ipst = ipst;
	ixas.ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	if (!(ira->ira_flags & IRAF_IPSEC_SECURE)) {
		/*
		 * This packet should go out the same way as it
		 * came in i.e in clear, independent of the IPsec policy
		 * for transmitting packets.
		 */
		ixas.ixa_flags |= IXAF_NO_IPSEC;
	} else {
		if (!ipsec_in_to_out(ira, &ixas, mp, ipha, NULL)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			/* Note: mp already consumed and ip_drop_packet done */
			return;
		}
	}
	if (ira->ira_flags & IRAF_MULTIBROADCAST) {
		/*
		 * Not one or our addresses (IRE_LOCALs), thus we let
		 * ip_output_simple pick the source.
		 */
		ipha->ipha_src = INADDR_ANY;
		ixas.ixa_flags |= IXAF_SET_SOURCE;
	}
	/* Should we send with DF and use dce_pmtu? */
	if (ipst->ips_ipv4_icmp_return_pmtu) {
		ixas.ixa_flags |= IXAF_PMTU_DISCOVERY;
		ipha->ipha_fragment_offset_and_flags |= IPH_DF_HTONS;
	}

	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutMsgs);

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);
}

/*
 * Verify the ICMP messages for either for ICMP error or redirect packet.
 * The caller should have fully pulled up the message. If it's a redirect
 * packet, only basic checks on IP header will be done; otherwise, verify
 * the packet by looking at the included ULP header.
 *
 * Called before icmp_inbound_error_fanout_v4 is called.
 */
static boolean_t
icmp_inbound_verify_v4(mblk_t *mp, icmph_t *icmph, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	int		hdr_length;
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	conn_t		*connp;
	ipha_t		*ipha;	/* Inner IP header */

	ipha = (ipha_t *)&icmph[1];
	if ((uchar_t *)ipha + IP_SIMPLE_HDR_LENGTH > mp->b_wptr)
		goto truncated;

	hdr_length = IPH_HDR_LENGTH(ipha);

	if ((IPH_HDR_VERSION(ipha) != IPV4_VERSION))
		goto discard_pkt;

	if (hdr_length < sizeof (ipha_t))
		goto truncated;

	if ((uchar_t *)ipha + hdr_length > mp->b_wptr)
		goto truncated;

	/*
	 * Stop here for ICMP_REDIRECT.
	 */
	if (icmph->icmph_type == ICMP_REDIRECT)
		return (B_TRUE);

	/*
	 * ICMP errors only.
	 */
	switch (ipha->ipha_protocol) {
	case IPPROTO_UDP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ipha + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr)
			goto truncated;
		break;
	case IPPROTO_TCP: {
		tcpha_t		*tcpha;

		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ipha + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr)
			goto truncated;

		tcpha = (tcpha_t *)((uchar_t *)ipha + hdr_length);
		connp = ipcl_tcp_lookup_reversed_ipv4(ipha, tcpha, TCPS_LISTEN,
		    ipst);
		if (connp == NULL)
			goto discard_pkt;

		if ((connp->conn_verifyicmp != NULL) &&
		    !connp->conn_verifyicmp(connp, tcpha, icmph, NULL, ira)) {
			CONN_DEC_REF(connp);
			goto discard_pkt;
		}
		CONN_DEC_REF(connp);
		break;
	}
	case IPPROTO_SCTP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ipha + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr)
			goto truncated;
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		break;
	case IPPROTO_ENCAP:
		if ((uchar_t *)ipha + hdr_length + sizeof (ipha_t) >
		    mp->b_wptr)
			goto truncated;
		break;
	default:
		break;
	}

	return (B_TRUE);

discard_pkt:
	/* Bogus ICMP error. */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
	return (B_FALSE);

truncated:
	/* We pulled up everthing already. Must be truncated */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
	ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
	return (B_FALSE);
}

/* Table from RFC 1191 */
static int icmp_frag_size_table[] =
{ 32000, 17914, 8166, 4352, 2002, 1496, 1006, 508, 296, 68 };

/*
 * Process received ICMP Packet too big.
 * Just handles the DCE create/update, including using the above table of
 * PMTU guesses. The caller is responsible for validating the packet before
 * passing it in and also to fanout the ICMP error to any matching transport
 * conns. Assumes the message has been fully pulled up and verified.
 *
 * Before getting here, the caller has called icmp_inbound_verify_v4()
 * that should have verified with ULP to prevent undoing the changes we're
 * going to make to DCE. For example, TCP might have verified that the packet
 * which generated error is in the send window.
 *
 * In some cases modified this MTU in the ICMP header packet; the caller
 * should pass to the matching ULP after this returns.
 */
static void
icmp_inbound_too_big_v4(icmph_t *icmph, ip_recv_attr_t *ira)
{
	dce_t		*dce;
	int		old_mtu;
	int		mtu, orig_mtu;
	ipaddr_t	dst;
	boolean_t	disable_pmtud;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint_t		hdr_length;
	ipha_t		*ipha;

	/* Caller already pulled up everything. */
	ipha = (ipha_t *)&icmph[1];
	ASSERT(icmph->icmph_type == ICMP_DEST_UNREACHABLE &&
	    icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED);
	ASSERT(ill != NULL);

	hdr_length = IPH_HDR_LENGTH(ipha);

	/*
	 * We handle path MTU for source routed packets since the DCE
	 * is looked up using the final destination.
	 */
	dst = ip_get_dst(ipha);

	dce = dce_lookup_and_add_v4(dst, ipst);
	if (dce == NULL) {
		/* Couldn't add a unique one - ENOMEM */
		ip1dbg(("icmp_inbound_too_big_v4: no dce for 0x%x\n",
		    ntohl(dst)));
		return;
	}

	/* Check for MTU discovery advice as described in RFC 1191 */
	mtu = ntohs(icmph->icmph_du_mtu);
	orig_mtu = mtu;
	disable_pmtud = B_FALSE;

	mutex_enter(&dce->dce_lock);
	if (dce->dce_flags & DCEF_PMTU)
		old_mtu = dce->dce_pmtu;
	else
		old_mtu = ill->ill_mtu;

	if (icmph->icmph_du_zero != 0 || mtu < ipst->ips_ip_pmtu_min) {
		uint32_t length;
		int	i;

		/*
		 * Use the table from RFC 1191 to figure out
		 * the next "plateau" based on the length in
		 * the original IP packet.
		 */
		length = ntohs(ipha->ipha_length);
		DTRACE_PROBE2(ip4__pmtu__guess, dce_t *, dce,
		    uint32_t, length);
		if (old_mtu <= length &&
		    old_mtu >= length - hdr_length) {
			/*
			 * Handle broken BSD 4.2 systems that
			 * return the wrong ipha_length in ICMP
			 * errors.
			 */
			ip1dbg(("Wrong mtu: sent %d, dce %d\n",
			    length, old_mtu));
			length -= hdr_length;
		}
		for (i = 0; i < A_CNT(icmp_frag_size_table); i++) {
			if (length > icmp_frag_size_table[i])
				break;
		}
		if (i == A_CNT(icmp_frag_size_table)) {
			/* Smaller than IP_MIN_MTU! */
			ip1dbg(("Too big for packet size %d\n",
			    length));
			disable_pmtud = B_TRUE;
			mtu = ipst->ips_ip_pmtu_min;
		} else {
			mtu = icmp_frag_size_table[i];
			ip1dbg(("Calculated mtu %d, packet size %d, "
			    "before %d\n", mtu, length, old_mtu));
			if (mtu < ipst->ips_ip_pmtu_min) {
				mtu = ipst->ips_ip_pmtu_min;
				disable_pmtud = B_TRUE;
			}
		}
	}
	if (disable_pmtud)
		dce->dce_flags |= DCEF_TOO_SMALL_PMTU;
	else
		dce->dce_flags &= ~DCEF_TOO_SMALL_PMTU;

	dce->dce_pmtu = MIN(old_mtu, mtu);
	/* Prepare to send the new max frag size for the ULP. */
	icmph->icmph_du_zero = 0;
	icmph->icmph_du_mtu =  htons((uint16_t)dce->dce_pmtu);
	DTRACE_PROBE4(ip4__pmtu__change, icmph_t *, icmph, dce_t *,
	    dce, int, orig_mtu, int, mtu);

	/* We now have a PMTU for sure */
	dce->dce_flags |= DCEF_PMTU;
	dce->dce_last_change_time = TICK_TO_SEC(ddi_get_lbolt64());
	mutex_exit(&dce->dce_lock);
	/*
	 * After dropping the lock the new value is visible to everyone.
	 * Then we bump the generation number so any cached values reinspect
	 * the dce_t.
	 */
	dce_increment_generation(dce);
	dce_refrele(dce);
}

/*
 * If the packet in error is Self-Encapsulated, icmp_inbound_error_fanout_v4
 * calls this function.
 */
static mblk_t *
icmp_inbound_self_encap_error_v4(mblk_t *mp, ipha_t *ipha, ipha_t *in_ipha)
{
	int length;

	ASSERT(mp->b_datap->db_type == M_DATA);

	/* icmp_inbound_v4 has already pulled up the whole error packet */
	ASSERT(mp->b_cont == NULL);

	/*
	 * The length that we want to overlay is the inner header
	 * and what follows it.
	 */
	length = msgdsize(mp) - ((uchar_t *)in_ipha - mp->b_rptr);

	/*
	 * Overlay the inner header and whatever follows it over the
	 * outer header.
	 */
	bcopy((uchar_t *)in_ipha, (uchar_t *)ipha, length);

	/* Adjust for what we removed */
	mp->b_wptr -= (uchar_t *)in_ipha - (uchar_t *)ipha;
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
 * For IPsec cases, we let the next-layer-up (which has access to
 * cached policy on the conn_t, or can query the SPD directly)
 * subtract out any IPsec overhead if they must.  We therefore make no
 * adjustments here for IPsec overhead.
 *
 * IFN could have been generated locally or by some router.
 *
 * LOCAL : ire_send_wire (before calling ipsec_out_process) can call
 * icmp_frag_needed/icmp_pkt2big_v6 to generated a local IFN.
 *	    This happens because IP adjusted its value of MTU on an
 *	    earlier IFN message and could not tell the upper layer,
 *	    the new adjusted value of MTU e.g. Packet was encrypted
 *	    or there was not enough information to fanout to upper
 *	    layers. Thus on the next outbound datagram, ire_send_wire
 *	    generates the IFN, where IPsec processing has *not* been
 *	    done.
 *
 *	    Note that we retain ixa_fragsize across IPsec thus once
 *	    we have picking ixa_fragsize and entered ipsec_out_process we do
 *	    no change the fragsize even if the path MTU changes before
 *	    we reach ip_output_post_ipsec.
 *
 *	    In the local case, IRAF_LOOPBACK will be set indicating
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
 *	    * NON_SECURE : If the packet in error has AH/ESP headers, we send it
 *	      up to AH/ESP for validation. AH/ESP will verify whether there is a
 *	      valid SA or not and send it back. We will fanout again if
 *	      we have more data in the packet.
 *
 *	      If the packet in error does not have AH/ESP, we handle it
 *	      like any other case.
 *
 * The caller must have called icmp_inbound_verify_v4.
 */
static void
icmp_inbound_error_fanout_v4(mblk_t *mp, icmph_t *icmph, ip_recv_attr_t *ira)
{
	uint16_t	*up;	/* Pointer to ports in ULP header */
	uint32_t	ports;	/* reversed ports for fanout */
	ipha_t		ripha;	/* With reversed addresses */
	ipha_t		*ipha;  /* Inner IP header */
	uint_t		hdr_length; /* Inner IP header length */
	tcpha_t		*tcpha;
	conn_t		*connp;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;
	ill_t		*rill = ira->ira_rill;

	/* Caller already pulled up everything. */
	ipha = (ipha_t *)&icmph[1];
	ASSERT((uchar_t *)&ipha[1] <= mp->b_wptr);
	ASSERT(mp->b_cont == NULL);

	hdr_length = IPH_HDR_LENGTH(ipha);
	ira->ira_protocol = ipha->ipha_protocol;

	/*
	 * We need a separate IP header with the source and destination
	 * addresses reversed to do fanout/classification because the ipha in
	 * the ICMP error is in the form we sent it out.
	 */
	ripha.ipha_src = ipha->ipha_dst;
	ripha.ipha_dst = ipha->ipha_src;
	ripha.ipha_protocol = ipha->ipha_protocol;
	ripha.ipha_version_and_hdr_length = ipha->ipha_version_and_hdr_length;

	ip2dbg(("icmp_inbound_error_v4: proto %d %x to %x: %d/%d\n",
	    ripha.ipha_protocol, ntohl(ipha->ipha_src),
	    ntohl(ipha->ipha_dst),
	    icmph->icmph_type, icmph->icmph_code));

	switch (ipha->ipha_protocol) {
	case IPPROTO_UDP:
		up = (uint16_t *)((uchar_t *)ipha + hdr_length);

		/* Attempt to find a client stream based on port. */
		ip2dbg(("icmp_inbound_error_v4: UDP ports %d to %d\n",
		    ntohs(up[0]), ntohs(up[1])));

		/* Note that we send error to all matches. */
		ira->ira_flags |= IRAF_ICMP_ERROR;
		ip_fanout_udp_multi_v4(mp, &ripha, up[0], up[1], ira);
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;

	case IPPROTO_TCP:
		/*
		 * Find a TCP client stream for this packet.
		 * Note that we do a reverse lookup since the header is
		 * in the form we sent it out.
		 */
		tcpha = (tcpha_t *)((uchar_t *)ipha + hdr_length);
		connp = ipcl_tcp_lookup_reversed_ipv4(ipha, tcpha, TCPS_LISTEN,
		    ipst);
		if (connp == NULL)
			goto discard_pkt;

		if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) ||
		    (ira->ira_flags & IRAF_IPSEC_SECURE)) {
			mp = ipsec_check_inbound_policy(mp, connp,
			    ipha, NULL, ira);
			if (mp == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				/* Note that mp is NULL */
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				CONN_DEC_REF(connp);
				return;
			}
		}

		ira->ira_flags |= IRAF_ICMP_ERROR;
		ira->ira_ill = ira->ira_rill = NULL;
		if (IPCL_IS_TCP(connp)) {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
			    connp->conn_recvicmp, connp, ira, SQ_FILL,
			    SQTAG_TCP_INPUT_ICMP_ERR);
		} else {
			/* Not TCP; must be SOCK_RAW, IPPROTO_TCP */
			(connp->conn_recv)(connp, mp, NULL, ira);
			CONN_DEC_REF(connp);
		}
		ira->ira_ill = ill;
		ira->ira_rill = rill;
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;

	case IPPROTO_SCTP:
		up = (uint16_t *)((uchar_t *)ipha + hdr_length);
		/* Find a SCTP client stream for this packet. */
		((uint16_t *)&ports)[0] = up[1];
		((uint16_t *)&ports)[1] = up[0];

		ira->ira_flags |= IRAF_ICMP_ERROR;
		ip_fanout_sctp(mp, &ripha, NULL, ports, ira);
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;

	case IPPROTO_ESP:
	case IPPROTO_AH:
		if (!ipsec_loaded(ipss)) {
			ip_proto_not_sup(mp, ira);
			return;
		}

		if (ipha->ipha_protocol == IPPROTO_ESP)
			mp = ipsecesp_icmp_error(mp, ira);
		else
			mp = ipsecah_icmp_error(mp, ira);
		if (mp == NULL)
			return;

		/* Just in case ipsec didn't preserve the NULL b_cont */
		if (mp->b_cont != NULL) {
			if (!pullupmsg(mp, -1))
				goto discard_pkt;
		}

		/*
		 * Note that ira_pktlen and ira_ip_hdr_length are no longer
		 * correct, but we don't use them any more here.
		 *
		 * If succesful, the mp has been modified to not include
		 * the ESP/AH header so we can fanout to the ULP's icmp
		 * error handler.
		 */
		if (mp->b_wptr - mp->b_rptr < IP_SIMPLE_HDR_LENGTH)
			goto truncated;

		/* Verify the modified message before any further processes. */
		ipha = (ipha_t *)mp->b_rptr;
		hdr_length = IPH_HDR_LENGTH(ipha);
		icmph = (icmph_t *)&mp->b_rptr[hdr_length];
		if (!icmp_inbound_verify_v4(mp, icmph, ira)) {
			freemsg(mp);
			return;
		}

		icmp_inbound_error_fanout_v4(mp, icmph, ira);
		return;

	case IPPROTO_ENCAP: {
		/* Look for self-encapsulated packets that caused an error */
		ipha_t *in_ipha;

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

			mp = icmp_inbound_self_encap_error_v4(mp, ipha,
			    in_ipha);
			if (mp == NULL)
				goto discard_pkt;

			/*
			 * Just in case self_encap didn't preserve the NULL
			 * b_cont
			 */
			if (mp->b_cont != NULL) {
				if (!pullupmsg(mp, -1))
					goto discard_pkt;
			}
			/*
			 * Note that ira_pktlen and ira_ip_hdr_length are no
			 * longer correct, but we don't use them any more here.
			 */
			if (mp->b_wptr - mp->b_rptr < IP_SIMPLE_HDR_LENGTH)
				goto truncated;

			/*
			 * Verify the modified message before any further
			 * processes.
			 */
			ipha = (ipha_t *)mp->b_rptr;
			hdr_length = IPH_HDR_LENGTH(ipha);
			icmph = (icmph_t *)&mp->b_rptr[hdr_length];
			if (!icmp_inbound_verify_v4(mp, icmph, ira)) {
				freemsg(mp);
				return;
			}

			/*
			 * The packet in error is self-encapsualted.
			 * And we are finding it further encapsulated
			 * which we could not have possibly generated.
			 */
			if (ipha->ipha_protocol == IPPROTO_ENCAP) {
				goto discard_pkt;
			}
			icmp_inbound_error_fanout_v4(mp, icmph, ira);
			return;
		}
		/* No self-encapsulated */
		/* FALLTHRU */
	}
	case IPPROTO_IPV6:
		if ((connp = ipcl_iptun_classify_v4(&ripha.ipha_src,
		    &ripha.ipha_dst, ipst)) != NULL) {
			ira->ira_flags |= IRAF_ICMP_ERROR;
			connp->conn_recvicmp(connp, mp, NULL, ira);
			CONN_DEC_REF(connp);
			ira->ira_flags &= ~IRAF_ICMP_ERROR;
			return;
		}
		/*
		 * No IP tunnel is interested, fallthrough and see
		 * if a raw socket will want it.
		 */
		/* FALLTHRU */
	default:
		ira->ira_flags |= IRAF_ICMP_ERROR;
		ip_fanout_proto_v4(mp, &ripha, ira);
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;
	}
	/* NOTREACHED */
discard_pkt:
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
	ip1dbg(("icmp_inbound_error_fanout_v4: drop pkt\n"));
	ip_drop_input("ipIfStatsInDiscards", mp, ill);
	freemsg(mp);
	return;

truncated:
	/* We pulled up everthing already. Must be truncated */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
	ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
	freemsg(mp);
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

/* Like above but without an ipha_t */
uint8_t
ipoptp_first2(ipoptp_t *optp, uint32_t totallen, uint8_t *opt)
{
	optp->ipoptp_next = opt;
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
 *
 * This is compatible with BSD in that it returns
 * the reverse source route with the final destination
 * as the last entry. The first 4 bytes of the option
 * will contain the final destination.
 */
int
ip_opt_get_user(conn_t *connp, uchar_t *buf)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	uint32_t	len = 0;
	uchar_t		*buf1 = buf;
	uint32_t	totallen;
	ipaddr_t	dst;
	ip_pkt_t	*ipp = &connp->conn_xmit_ipp;

	if (!(ipp->ipp_fields & IPPF_IPV4_OPTIONS))
		return (0);

	totallen = ipp->ipp_ipv4_options_len;
	if (totallen & 0x3)
		return (0);

	buf += IP_ADDR_LEN;	/* Leave room for final destination */
	len += IP_ADDR_LEN;
	bzero(buf1, IP_ADDR_LEN);

	dst = connp->conn_faddr_v4;

	for (optval = ipoptp_first2(&opts, totallen, ipp->ipp_ipv4_options);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		int	off;

		opt = opts.ipoptp_cur;
		if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
			break;
		}
		optlen = opts.ipoptp_len;

		switch (optval) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:

			/*
			 * Insert destination as the first entry in the source
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
			/* Last entry in source route if not already set */
			if (dst == INADDR_ANY)
				bcopy(opt + off, buf1, IP_ADDR_LEN);
			off -= IP_ADDR_LEN;

			while (off > 0) {
				bcopy(opt + off,
				    buf + off + IP_ADDR_LEN,
				    IP_ADDR_LEN);
				off -= IP_ADDR_LEN;
			}
			/* ipha_dst into first slot */
			bcopy(&dst, buf + off + IP_ADDR_LEN,
			    IP_ADDR_LEN);
			buf += optlen;
			len += optlen;
			break;

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
 * Assumes the caller has verified that the headers are in the pulled up mblk.
 * Consumes mp.
 */
static void
icmp_redirect_v4(mblk_t *mp, ipha_t *ipha, icmph_t *icmph, ip_recv_attr_t *ira)
{
	ire_t		*ire, *nire;
	ire_t		*prev_ire;
	ipaddr_t  	src, dst, gateway;
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	ipha_t		*inner_ipha;	/* Inner IP header */

	/* Caller already pulled up everything. */
	inner_ipha = (ipha_t *)&icmph[1];
	src = ipha->ipha_src;
	dst = inner_ipha->ipha_dst;
	gateway = icmph->icmph_rd_gateway;
	/* Make sure the new gateway is reachable somehow. */
	ire = ire_ftable_lookup_v4(gateway, 0, 0, IRE_ONLINK, NULL,
	    ALL_ZONES, NULL, MATCH_IRE_TYPE, 0, ipst, NULL);
	/*
	 * Make sure we had a route for the dest in question and that
	 * that route was pointing to the old gateway (the source of the
	 * redirect packet.)
	 * We do longest match and then compare ire_gateway_addr below.
	 */
	prev_ire = ire_ftable_lookup_v4(dst, 0, 0, 0, NULL, ALL_ZONES,
	    NULL, MATCH_IRE_DSTONLY, 0, ipst, NULL);
	/*
	 * Check that
	 *	the redirect was not from ourselves
	 *	the new gateway and the old gateway are directly reachable
	 */
	if (prev_ire == NULL || ire == NULL ||
	    (prev_ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK)) ||
	    (prev_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    !(ire->ire_type & IRE_IF_ALL) ||
	    prev_ire->ire_gateway_addr != src) {
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInBadRedirects);
		ip_drop_input("icmpInBadRedirects - ire", mp, ira->ira_ill);
		freemsg(mp);
		if (ire != NULL)
			ire_refrele(ire);
		if (prev_ire != NULL)
			ire_refrele(prev_ire);
		return;
	}

	ire_refrele(prev_ire);
	ire_refrele(ire);

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
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInBadRedirects);
		ip_drop_input("icmpInBadRedirects - code", mp, ira->ira_ill);
		freemsg(mp);
		return;
	}
	/*
	 * Create a Route Association.  This will allow us to remember that
	 * someone we believe told us to use the particular gateway.
	 */
	ire = ire_create(
	    (uchar_t *)&dst,			/* dest addr */
	    (uchar_t *)&ip_g_all_ones,		/* mask */
	    (uchar_t *)&gateway,		/* gateway addr */
	    IRE_HOST,
	    NULL,				/* ill */
	    ALL_ZONES,
	    (RTF_DYNAMIC | RTF_GATEWAY | RTF_HOST),
	    NULL,				/* tsol_gc_t */
	    ipst);

	if (ire == NULL) {
		freemsg(mp);
		return;
	}
	nire = ire_add(ire);
	/* Check if it was a duplicate entry */
	if (nire != NULL && nire != ire) {
		ASSERT(nire->ire_identical_ref > 1);
		ire_delete(nire);
		ire_refrele(nire);
		nire = NULL;
	}
	ire = nire;
	if (ire != NULL) {
		ire_refrele(ire);		/* Held in ire_add */

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
	prev_ire = ire_ftable_lookup_v4(dst, 0, src, IRE_HOST, NULL,
	    ALL_ZONES, NULL, (MATCH_IRE_GW | MATCH_IRE_TYPE), 0, ipst, NULL);
	if (prev_ire != NULL) {
		if (prev_ire ->ire_flags & RTF_DYNAMIC)
			ire_delete(prev_ire);
		ire_refrele(prev_ire);
	}

	freemsg(mp);
}

/*
 * Generate an ICMP parameter problem message.
 * When called from ip_output side a minimal ip_recv_attr_t needs to be
 * constructed by the caller.
 */
static void
icmp_param_problem(mblk_t *mp, uint8_t ptr, ip_recv_attr_t *ira)
{
	icmph_t	icmph;
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;

	mp = icmp_pkt_err_ok(mp, ira);
	if (mp == NULL)
		return;

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_PARAM_PROBLEM;
	icmph.icmph_pp_ptr = ptr;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutParmProbs);
	icmp_pkt(mp, &icmph, sizeof (icmph_t), ira);
}

/*
 * Build and ship an IPv4 ICMP message using the packet data in mp, and
 * the ICMP header pointed to by "stuff".  (May be called as writer.)
 * Note: assumes that icmp_pkt_err_ok has been called to verify that
 * an icmp error packet can be sent.
 * Assigns an appropriate source address to the packet. If ipha_dst is
 * one of our addresses use it for source. Otherwise let ip_output_simple
 * pick the source address.
 */
static void
icmp_pkt(mblk_t *mp, void *stuff, size_t len, ip_recv_attr_t *ira)
{
	ipaddr_t dst;
	icmph_t	*icmph;
	ipha_t	*ipha;
	uint_t	len_needed;
	size_t	msg_len;
	mblk_t	*mp1;
	ipaddr_t src;
	ire_t	*ire;
	ip_xmit_attr_t ixas;
	ip_stack_t *ipst = ira->ira_ill->ill_ipst;

	ipha = (ipha_t *)mp->b_rptr;

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_BASIC_SIMPLE_V4;
	ixas.ixa_zoneid = ira->ira_zoneid;
	ixas.ixa_ifindex = 0;
	ixas.ixa_ipst = ipst;
	ixas.ixa_cred = kcred;
	ixas.ixa_cpid = NOPID;
	ixas.ixa_tsl = ira->ira_tsl;	/* Behave as a multi-level responder */
	ixas.ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		/*
		 * Apply IPsec based on how IPsec was applied to
		 * the packet that had the error.
		 *
		 * If it was an outbound packet that caused the ICMP
		 * error, then the caller will have setup the IRA
		 * appropriately.
		 */
		if (!ipsec_in_to_out(ira, &ixas, mp, ipha, NULL)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			/* Note: mp already consumed and ip_drop_packet done */
			return;
		}
	} else {
		/*
		 * This is in clear. The icmp message we are building
		 * here should go out in clear, independent of our policy.
		 */
		ixas.ixa_flags |= IXAF_NO_IPSEC;
	}

	/* Remember our eventual destination */
	dst = ipha->ipha_src;

	/*
	 * If the packet was for one of our unicast addresses, make
	 * sure we respond with that as the source. Otherwise
	 * have ip_output_simple pick the source address.
	 */
	ire = ire_ftable_lookup_v4(ipha->ipha_dst, 0, 0,
	    (IRE_LOCAL|IRE_LOOPBACK), NULL, ira->ira_zoneid, NULL,
	    MATCH_IRE_TYPE|MATCH_IRE_ZONEONLY, 0, ipst, NULL);
	if (ire != NULL) {
		ire_refrele(ire);
		src = ipha->ipha_dst;
	} else {
		src = INADDR_ANY;
		ixas.ixa_flags |= IXAF_SET_SOURCE;
	}

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
			ip_drop_output("ipIfStatsOutDiscards", mp, NULL);
			freemsg(mp);
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
	mp1 = allocb(sizeof (icmp_ipha) + len, BPRI_MED);
	if (mp1 == NULL) {
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutErrors);
		freemsg(mp);
		return;
	}
	mp1->b_cont = mp;
	mp = mp1;

	/*
	 * Set IXAF_TRUSTED_ICMP so we can let the ICMP messages this
	 * node generates be accepted in peace by all on-host destinations.
	 * If we do NOT assume that all on-host destinations trust
	 * self-generated ICMP messages, then rework here, ip6.c, and spd.c.
	 * (Look for IXAF_TRUSTED_ICMP).
	 */
	ixas.ixa_flags |= IXAF_TRUSTED_ICMP;

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

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);
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
	clock_t now = TICK_TO_MSEC(ddi_get_lbolt());
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
icmp_pkt_err_ok(mblk_t *mp, ip_recv_attr_t *ira)
{
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	icmph_t	*icmph;
	ipha_t	*ipha;
	uint_t	len_needed;

	if (!mp)
		return (NULL);
	ipha = (ipha_t *)mp->b_rptr;
	if (ip_csum_hdr(ipha)) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInCksumErrs);
		ip_drop_input("ipIfStatsInCksumErrs", mp, NULL);
		freemsg(mp);
		return (NULL);
	}
	if (ip_type_v4(ipha->ipha_dst, ipst) == IRE_BROADCAST ||
	    ip_type_v4(ipha->ipha_src, ipst) == IRE_BROADCAST ||
	    CLASSD(ipha->ipha_dst) ||
	    CLASSD(ipha->ipha_src) ||
	    (ntohs(ipha->ipha_fragment_offset_and_flags) & IPH_OFFSET)) {
		/* Note: only errors to the fragment with offset 0 */
		BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDrops);
		freemsg(mp);
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
	if (is_system_labeled() && !tsol_can_reply_error(mp, ira)) {
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
 * Called when a packet was sent out the same link that it arrived on.
 * Check if it is ok to send a redirect and then send it.
 */
void
ip_send_potential_redirect_v4(mblk_t *mp, ipha_t *ipha, ire_t *ire,
    ip_recv_attr_t *ira)
{
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	ipaddr_t	src, nhop;
	mblk_t		*mp1;
	ire_t		*nhop_ire;

	/*
	 * Check the source address to see if it originated
	 * on the same logical subnet it is going back out on.
	 * If so, we should be able to send it a redirect.
	 * Avoid sending a redirect if the destination
	 * is directly connected (i.e., we matched an IRE_ONLINK),
	 * or if the packet was source routed out this interface.
	 *
	 * We avoid sending a redirect if the
	 * destination is directly connected
	 * because it is possible that multiple
	 * IP subnets may have been configured on
	 * the link, and the source may not
	 * be on the same subnet as ip destination,
	 * even though they are on the same
	 * physical link.
	 */
	if ((ire->ire_type & IRE_ONLINK) ||
	    ip_source_routed(ipha, ipst))
		return;

	nhop_ire = ire_nexthop(ire);
	if (nhop_ire == NULL)
		return;

	nhop = nhop_ire->ire_addr;

	if (nhop_ire->ire_type & IRE_IF_CLONE) {
		ire_t	*ire2;

		/* Follow ire_dep_parent to find non-clone IRE_INTERFACE */
		mutex_enter(&nhop_ire->ire_lock);
		ire2 = nhop_ire->ire_dep_parent;
		if (ire2 != NULL)
			ire_refhold(ire2);
		mutex_exit(&nhop_ire->ire_lock);
		ire_refrele(nhop_ire);
		nhop_ire = ire2;
	}
	if (nhop_ire == NULL)
		return;

	ASSERT(!(nhop_ire->ire_type & IRE_IF_CLONE));

	src = ipha->ipha_src;

	/*
	 * We look at the interface ire for the nexthop,
	 * to see if ipha_src is in the same subnet
	 * as the nexthop.
	 */
	if ((src & nhop_ire->ire_mask) == (nhop & nhop_ire->ire_mask)) {
		/*
		 * The source is directly connected.
		 */
		mp1 = copymsg(mp);
		if (mp1 != NULL) {
			icmp_send_redirect(mp1, nhop, ira);
		}
	}
	ire_refrele(nhop_ire);
}

/*
 * Generate an ICMP redirect message.
 */
static void
icmp_send_redirect(mblk_t *mp, ipaddr_t gateway, ip_recv_attr_t *ira)
{
	icmph_t	icmph;
	ip_stack_t *ipst = ira->ira_ill->ill_ipst;

	mp = icmp_pkt_err_ok(mp, ira);
	if (mp == NULL)
		return;

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_REDIRECT;
	icmph.icmph_code = 1;
	icmph.icmph_rd_gateway = gateway;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutRedirects);
	icmp_pkt(mp, &icmph, sizeof (icmph_t), ira);
}

/*
 * Generate an ICMP time exceeded message.
 */
void
icmp_time_exceeded(mblk_t *mp, uint8_t code, ip_recv_attr_t *ira)
{
	icmph_t	icmph;
	ip_stack_t *ipst = ira->ira_ill->ill_ipst;

	mp = icmp_pkt_err_ok(mp, ira);
	if (mp == NULL)
		return;

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_TIME_EXCEEDED;
	icmph.icmph_code = code;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutTimeExcds);
	icmp_pkt(mp, &icmph, sizeof (icmph_t), ira);
}

/*
 * Generate an ICMP unreachable message.
 * When called from ip_output side a minimal ip_recv_attr_t needs to be
 * constructed by the caller.
 */
void
icmp_unreachable(mblk_t *mp, uint8_t code, ip_recv_attr_t *ira)
{
	icmph_t	icmph;
	ip_stack_t *ipst = ira->ira_ill->ill_ipst;

	mp = icmp_pkt_err_ok(mp, ira);
	if (mp == NULL)
		return;

	bzero(&icmph, sizeof (icmph_t));
	icmph.icmph_type = ICMP_DEST_UNREACHABLE;
	icmph.icmph_code = code;
	BUMP_MIB(&ipst->ips_icmp_mib, icmpOutDestUnreachs);
	icmp_pkt(mp, &icmph, sizeof (icmph_t), ira);
}

/*
 * Latch in the IPsec state for a stream based the policy in the listener
 * and the actions in the ip_recv_attr_t.
 * Called directly from TCP and SCTP.
 */
boolean_t
ip_ipsec_policy_inherit(conn_t *connp, conn_t *lconnp, ip_recv_attr_t *ira)
{
	ASSERT(lconnp->conn_policy != NULL);
	ASSERT(connp->conn_policy == NULL);

	IPPH_REFHOLD(lconnp->conn_policy);
	connp->conn_policy = lconnp->conn_policy;

	if (ira->ira_ipsec_action != NULL) {
		if (connp->conn_latch == NULL) {
			connp->conn_latch = iplatch_create();
			if (connp->conn_latch == NULL)
				return (B_FALSE);
		}
		ipsec_latch_inbound(connp, ira);
	}
	return (B_TRUE);
}

/*
 * Verify whether or not the IP address is a valid local address.
 * Could be a unicast, including one for a down interface.
 * If allow_mcbc then a multicast or broadcast address is also
 * acceptable.
 *
 * In the case of a broadcast/multicast address, however, the
 * upper protocol is expected to reset the src address
 * to zero when we return IPVL_MCAST/IPVL_BCAST so that
 * no packets are emitted with broadcast/multicast address as
 * source address (that violates hosts requirements RFC 1122)
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
 * In all the above cases, the bound address must be valid in the current zone.
 * When the address is loopback, multicast or broadcast, there might be many
 * matching IREs so bind has to look up based on the zone.
 */
ip_laddr_t
ip_laddr_verify_v4(ipaddr_t src_addr, zoneid_t zoneid,
    ip_stack_t *ipst, boolean_t allow_mcbc)
{
	ire_t *src_ire;

	ASSERT(src_addr != INADDR_ANY);

	src_ire = ire_ftable_lookup_v4(src_addr, 0, 0, 0,
	    NULL, zoneid, NULL, MATCH_IRE_ZONEONLY, 0, ipst, NULL);

	/*
	 * If an address other than in6addr_any is requested,
	 * we verify that it is a valid address for bind
	 * Note: Following code is in if-else-if form for
	 * readability compared to a condition check.
	 */
	if (src_ire != NULL && (src_ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK))) {
		/*
		 * (2) Bind to address of local UP interface
		 */
		ire_refrele(src_ire);
		return (IPVL_UNICAST_UP);
	} else if (src_ire != NULL && src_ire->ire_type & IRE_BROADCAST) {
		/*
		 * (4) Bind to broadcast address
		 */
		ire_refrele(src_ire);
		if (allow_mcbc)
			return (IPVL_BCAST);
		else
			return (IPVL_BAD);
	} else if (CLASSD(src_addr)) {
		/* (5) bind to multicast address. */
		if (src_ire != NULL)
			ire_refrele(src_ire);

		if (allow_mcbc)
			return (IPVL_MCAST);
		else
			return (IPVL_BAD);
	} else {
		ipif_t *ipif;

		/*
		 * (3) Bind to address of local DOWN interface?
		 * (ipif_lookup_addr() looks up all interfaces
		 * but we do not get here for UP interfaces
		 * - case (2) above)
		 */
		if (src_ire != NULL)
			ire_refrele(src_ire);

		ipif = ipif_lookup_addr(src_addr, NULL, zoneid, ipst);
		if (ipif == NULL)
			return (IPVL_BAD);

		/* Not a useful source? */
		if (ipif->ipif_flags & (IPIF_NOLOCAL | IPIF_ANYCAST)) {
			ipif_refrele(ipif);
			return (IPVL_BAD);
		}
		ipif_refrele(ipif);
		return (IPVL_UNICAST_DOWN);
	}
}

/*
 * Insert in the bind fanout for IPv4 and IPv6.
 * The caller should already have used ip_laddr_verify_v*() before calling
 * this.
 */
int
ip_laddr_fanout_insert(conn_t *connp)
{
	int		error;

	/*
	 * Allow setting new policies. For example, disconnects result
	 * in us being called. As we would have set conn_policy_cached
	 * to B_TRUE before, we should set it to B_FALSE, so that policy
	 * can change after the disconnect.
	 */
	connp->conn_policy_cached = B_FALSE;

	error = ipcl_bind_insert(connp);
	if (error != 0) {
		if (connp->conn_anon_port) {
			(void) tsol_mlp_anon(crgetzone(connp->conn_cred),
			    connp->conn_mlp_type, connp->conn_proto,
			    ntohs(connp->conn_lport), B_FALSE);
		}
		connp->conn_mlp_type = mlptSingle;
	}
	return (error);
}

/*
 * Verify that both the source and destination addresses are valid. If
 * IPDF_VERIFY_DST is not set, then the destination address may be unreachable,
 * i.e. have no route to it.  Protocols like TCP want to verify destination
 * reachability, while tunnels do not.
 *
 * Determine the route, the interface, and (optionally) the source address
 * to use to reach a given destination.
 * Note that we allow connect to broadcast and multicast addresses when
 * IPDF_ALLOW_MCBC is set.
 * first_hop and dst_addr are normally the same, but if source routing
 * they will differ; in that case the first_hop is what we'll use for the
 * routing lookup but the dce and label checks will be done on dst_addr,
 *
 * If uinfo is set, then we fill in the best available information
 * we have for the destination. This is based on (in priority order) any
 * metrics and path MTU stored in a dce_t, route metrics, and finally the
 * ill_mtu/ill_mc_mtu.
 *
 * Tsol note: If we have a source route then dst_addr != firsthop. But we
 * always do the label check on dst_addr.
 */
int
ip_set_destination_v4(ipaddr_t *src_addrp, ipaddr_t dst_addr, ipaddr_t firsthop,
    ip_xmit_attr_t *ixa, iulp_t *uinfo, uint32_t flags, uint_t mac_mode)
{
	ire_t		*ire = NULL;
	int		error = 0;
	ipaddr_t	setsrc;				/* RTF_SETSRC */
	zoneid_t	zoneid = ixa->ixa_zoneid;	/* Honors SO_ALLZONES */
	ip_stack_t	*ipst = ixa->ixa_ipst;
	dce_t		*dce;
	uint_t		pmtu;
	uint_t		generation;
	nce_t		*nce;
	ill_t		*ill = NULL;
	boolean_t	multirt = B_FALSE;

	ASSERT(ixa->ixa_flags & IXAF_IS_IPV4);

	/*
	 * We never send to zero; the ULPs map it to the loopback address.
	 * We can't allow it since we use zero to mean unitialized in some
	 * places.
	 */
	ASSERT(dst_addr != INADDR_ANY);

	if (is_system_labeled()) {
		ts_label_t *tsl = NULL;

		error = tsol_check_dest(ixa->ixa_tsl, &dst_addr, IPV4_VERSION,
		    mac_mode, (flags & IPDF_ZONE_IS_GLOBAL) != 0, &tsl);
		if (error != 0)
			return (error);
		if (tsl != NULL) {
			/* Update the label */
			ip_xmit_attr_replace_tsl(ixa, tsl);
		}
	}

	setsrc = INADDR_ANY;
	/*
	 * Select a route; For IPMP interfaces, we would only select
	 * a "hidden" route (i.e., going through a specific under_ill)
	 * if ixa_ifindex has been specified.
	 */
	ire = ip_select_route_v4(firsthop, *src_addrp, ixa,
	    &generation, &setsrc, &error, &multirt);
	ASSERT(ire != NULL);	/* IRE_NOROUTE if none found */
	if (error != 0)
		goto bad_addr;

	/*
	 * ire can't be a broadcast or multicast unless IPDF_ALLOW_MCBC is set.
	 * If IPDF_VERIFY_DST is set, the destination must be reachable;
	 * Otherwise the destination needn't be reachable.
	 *
	 * If we match on a reject or black hole, then we've got a
	 * local failure.  May as well fail out the connect() attempt,
	 * since it's never going to succeed.
	 */
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		/*
		 * If we're verifying destination reachability, we always want
		 * to complain here.
		 *
		 * If we're not verifying destination reachability but the
		 * destination has a route, we still want to fail on the
		 * temporary address and broadcast address tests.
		 *
		 * In both cases do we let the code continue so some reasonable
		 * information is returned to the caller. That enables the
		 * caller to use (and even cache) the IRE. conn_ip_ouput will
		 * use the generation mismatch path to check for the unreachable
		 * case thereby avoiding any specific check in the main path.
		 */
		ASSERT(generation == IRE_GENERATION_VERIFY);
		if (flags & IPDF_VERIFY_DST) {
			/*
			 * Set errno but continue to set up ixa_ire to be
			 * the RTF_REJECT|RTF_BLACKHOLE IRE.
			 * That allows callers to use ip_output to get an
			 * ICMP error back.
			 */
			if (!(ire->ire_type & IRE_HOST))
				error = ENETUNREACH;
			else
				error = EHOSTUNREACH;
		}
	}

	if ((ire->ire_type & (IRE_BROADCAST|IRE_MULTICAST)) &&
	    !(flags & IPDF_ALLOW_MCBC)) {
		ire_refrele(ire);
		ire = ire_reject(ipst, B_FALSE);
		generation = IRE_GENERATION_VERIFY;
		error = ENETUNREACH;
	}

	/* Cache things */
	if (ixa->ixa_ire != NULL)
		ire_refrele_notr(ixa->ixa_ire);
#ifdef DEBUG
	ire_refhold_notr(ire);
	ire_refrele(ire);
#endif
	ixa->ixa_ire = ire;
	ixa->ixa_ire_generation = generation;

	/*
	 * Ensure that ixa_dce is always set any time that ixa_ire is set,
	 * since some callers will send a packet to conn_ip_output() even if
	 * there's an error.
	 */
	if (flags & IPDF_UNIQUE_DCE) {
		/* Fallback to the default dce if allocation fails */
		dce = dce_lookup_and_add_v4(dst_addr, ipst);
		if (dce != NULL)
			generation = dce->dce_generation;
		else
			dce = dce_lookup_v4(dst_addr, ipst, &generation);
	} else {
		dce = dce_lookup_v4(dst_addr, ipst, &generation);
	}
	ASSERT(dce != NULL);
	if (ixa->ixa_dce != NULL)
		dce_refrele_notr(ixa->ixa_dce);
#ifdef DEBUG
	dce_refhold_notr(dce);
	dce_refrele(dce);
#endif
	ixa->ixa_dce = dce;
	ixa->ixa_dce_generation = generation;

	/*
	 * For multicast with multirt we have a flag passed back from
	 * ire_lookup_multi_ill_v4 since we don't have an IRE for each
	 * possible multicast address.
	 * We also need a flag for multicast since we can't check
	 * whether RTF_MULTIRT is set in ixa_ire for multicast.
	 */
	if (multirt) {
		ixa->ixa_postfragfn = ip_postfrag_multirt_v4;
		ixa->ixa_flags |= IXAF_MULTIRT_MULTICAST;
	} else {
		ixa->ixa_postfragfn = ire->ire_postfragfn;
		ixa->ixa_flags &= ~IXAF_MULTIRT_MULTICAST;
	}
	if (!(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
		/* Get an nce to cache. */
		nce = ire_to_nce(ire, firsthop, NULL);
		if (nce == NULL) {
			/* Allocation failure? */
			ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
		} else {
			if (ixa->ixa_nce != NULL)
				nce_refrele(ixa->ixa_nce);
			ixa->ixa_nce = nce;
		}
	}

	/*
	 * If the source address is a loopback address, the
	 * destination had best be local or multicast.
	 * If we are sending to an IRE_LOCAL using a loopback source then
	 * it had better be the same zoneid.
	 */
	if (*src_addrp == htonl(INADDR_LOOPBACK)) {
		if ((ire->ire_type & IRE_LOCAL) && ire->ire_zoneid != zoneid) {
			ire = NULL;	/* Stored in ixa_ire */
			error = EADDRNOTAVAIL;
			goto bad_addr;
		}
		if (!(ire->ire_type & (IRE_LOOPBACK|IRE_LOCAL|IRE_MULTICAST))) {
			ire = NULL;	/* Stored in ixa_ire */
			error = EADDRNOTAVAIL;
			goto bad_addr;
		}
	}
	if (ire->ire_type & IRE_BROADCAST) {
		/*
		 * If the ULP didn't have a specified source, then we
		 * make sure we reselect the source when sending
		 * broadcasts out different interfaces.
		 */
		if (flags & IPDF_SELECT_SRC)
			ixa->ixa_flags |= IXAF_SET_SOURCE;
		else
			ixa->ixa_flags &= ~IXAF_SET_SOURCE;
	}

	/*
	 * Does the caller want us to pick a source address?
	 */
	if (flags & IPDF_SELECT_SRC) {
		ipaddr_t	src_addr;

		/*
		 * We use use ire_nexthop_ill to avoid the under ipmp
		 * interface for source address selection. Note that for ipmp
		 * probe packets, ixa_ifindex would have been specified, and
		 * the ip_select_route() invocation would have picked an ire
		 * will ire_ill pointing at an under interface.
		 */
		ill = ire_nexthop_ill(ire);

		/* If unreachable we have no ill but need some source */
		if (ill == NULL) {
			src_addr = htonl(INADDR_LOOPBACK);
			/* Make sure we look for a better source address */
			generation = SRC_GENERATION_VERIFY;
		} else {
			error = ip_select_source_v4(ill, setsrc, dst_addr,
			    ixa->ixa_multicast_ifaddr, zoneid,
			    ipst, &src_addr, &generation, NULL);
			if (error != 0) {
				ire = NULL;	/* Stored in ixa_ire */
				goto bad_addr;
			}
		}

		/*
		 * We allow the source address to to down.
		 * However, we check that we don't use the loopback address
		 * as a source when sending out on the wire.
		 */
		if ((src_addr == htonl(INADDR_LOOPBACK)) &&
		    !(ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK|IRE_MULTICAST)) &&
		    !(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
			ire = NULL;	/* Stored in ixa_ire */
			error = EADDRNOTAVAIL;
			goto bad_addr;
		}

		*src_addrp = src_addr;
		ixa->ixa_src_generation = generation;
	}

	/*
	 * Make sure we don't leave an unreachable ixa_nce in place
	 * since ip_select_route is used when we unplumb i.e., remove
	 * references on ixa_ire, ixa_nce, and ixa_dce.
	 */
	nce = ixa->ixa_nce;
	if (nce != NULL && nce->nce_is_condemned) {
		nce_refrele(nce);
		ixa->ixa_nce = NULL;
		ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	}

	/*
	 * The caller has set IXAF_PMTU_DISCOVERY if path MTU is desired.
	 * However, we can't do it for IPv4 multicast or broadcast.
	 */
	if (ire->ire_type & (IRE_BROADCAST|IRE_MULTICAST))
		ixa->ixa_flags &= ~IXAF_PMTU_DISCOVERY;

	/*
	 * Set initial value for fragmentation limit. Either conn_ip_output
	 * or ULP might updates it when there are routing changes.
	 * Handles a NULL ixa_ire->ire_ill or a NULL ixa_nce for RTF_REJECT.
	 */
	pmtu = ip_get_pmtu(ixa);
	ixa->ixa_fragsize = pmtu;
	/* Make sure ixa_fragsize and ixa_pmtu remain identical */
	if (ixa->ixa_flags & IXAF_VERIFY_PMTU)
		ixa->ixa_pmtu = pmtu;

	/*
	 * Extract information useful for some transports.
	 * First we look for DCE metrics. Then we take what we have in
	 * the metrics in the route, where the offlink is used if we have
	 * one.
	 */
	if (uinfo != NULL) {
		bzero(uinfo, sizeof (*uinfo));

		if (dce->dce_flags & DCEF_UINFO)
			*uinfo = dce->dce_uinfo;

		rts_merge_metrics(uinfo, &ire->ire_metrics);

		/* Allow ire_metrics to decrease the path MTU from above */
		if (uinfo->iulp_mtu == 0 || uinfo->iulp_mtu > pmtu)
			uinfo->iulp_mtu = pmtu;

		uinfo->iulp_localnet = (ire->ire_type & IRE_ONLINK) != 0;
		uinfo->iulp_loopback = (ire->ire_type & IRE_LOOPBACK) != 0;
		uinfo->iulp_local = (ire->ire_type & IRE_LOCAL) != 0;
	}

	if (ill != NULL)
		ill_refrele(ill);

	return (error);

bad_addr:
	if (ire != NULL)
		ire_refrele(ire);

	if (ill != NULL)
		ill_refrele(ill);

	/*
	 * Make sure we don't leave an unreachable ixa_nce in place
	 * since ip_select_route is used when we unplumb i.e., remove
	 * references on ixa_ire, ixa_nce, and ixa_dce.
	 */
	nce = ixa->ixa_nce;
	if (nce != NULL && nce->nce_is_condemned) {
		nce_refrele(nce);
		ixa->ixa_nce = NULL;
		ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	}

	return (error);
}


/*
 * Get the base MTU for the case when path MTU discovery is not used.
 * Takes the MTU of the IRE into account.
 */
uint_t
ip_get_base_mtu(ill_t *ill, ire_t *ire)
{
	uint_t mtu;
	uint_t iremtu = ire->ire_metrics.iulp_mtu;

	if (ire->ire_type & (IRE_MULTICAST|IRE_BROADCAST))
		mtu = ill->ill_mc_mtu;
	else
		mtu = ill->ill_mtu;

	if (iremtu != 0 && iremtu < mtu)
		mtu = iremtu;

	return (mtu);
}

/*
 * Get the PMTU for the attributes. Handles both IPv4 and IPv6.
 * Assumes that ixa_ire, dce, and nce have already been set up.
 *
 * The caller has set IXAF_PMTU_DISCOVERY if path MTU discovery is desired.
 * We avoid path MTU discovery if it is disabled with ndd.
 * Furtermore, if the path MTU is too small, then we don't set DF for IPv4.
 *
 * NOTE: We also used to turn it off for source routed packets. That
 * is no longer required since the dce is per final destination.
 */
uint_t
ip_get_pmtu(ip_xmit_attr_t *ixa)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;
	dce_t		*dce;
	nce_t		*nce;
	ire_t		*ire;
	uint_t		pmtu;

	ire = ixa->ixa_ire;
	dce = ixa->ixa_dce;
	nce = ixa->ixa_nce;

	/*
	 * If path MTU discovery has been turned off by ndd, then we ignore
	 * any dce_pmtu and for IPv4 we will not set DF.
	 */
	if (!ipst->ips_ip_path_mtu_discovery)
		ixa->ixa_flags &= ~IXAF_PMTU_DISCOVERY;

	pmtu = IP_MAXPACKET;
	/*
	 * Decide whether whether IPv4 sets DF
	 * For IPv6 "no DF" means to use the 1280 mtu
	 */
	if (ixa->ixa_flags & IXAF_PMTU_DISCOVERY) {
		ixa->ixa_flags |= IXAF_PMTU_IPV4_DF;
	} else {
		ixa->ixa_flags &= ~IXAF_PMTU_IPV4_DF;
		if (!(ixa->ixa_flags & IXAF_IS_IPV4))
			pmtu = IPV6_MIN_MTU;
	}

	/* Check if the PMTU is to old before we use it */
	if ((dce->dce_flags & DCEF_PMTU) &&
	    TICK_TO_SEC(ddi_get_lbolt64()) - dce->dce_last_change_time >
	    ipst->ips_ip_pathmtu_interval) {
		/*
		 * Older than 20 minutes. Drop the path MTU information.
		 */
		mutex_enter(&dce->dce_lock);
		dce->dce_flags &= ~(DCEF_PMTU|DCEF_TOO_SMALL_PMTU);
		dce->dce_last_change_time = TICK_TO_SEC(ddi_get_lbolt64());
		mutex_exit(&dce->dce_lock);
		dce_increment_generation(dce);
	}

	/* The metrics on the route can lower the path MTU */
	if (ire->ire_metrics.iulp_mtu != 0 &&
	    ire->ire_metrics.iulp_mtu < pmtu)
		pmtu = ire->ire_metrics.iulp_mtu;

	/*
	 * If the path MTU is smaller than some minimum, we still use dce_pmtu
	 * above (would be 576 for IPv4 and 1280 for IPv6), but we clear
	 * IXAF_PMTU_IPV4_DF so that we avoid setting DF for IPv4.
	 */
	if (ixa->ixa_flags & IXAF_PMTU_DISCOVERY) {
		if (dce->dce_flags & DCEF_PMTU) {
			if (dce->dce_pmtu < pmtu)
				pmtu = dce->dce_pmtu;

			if (dce->dce_flags & DCEF_TOO_SMALL_PMTU) {
				ixa->ixa_flags |= IXAF_PMTU_TOO_SMALL;
				ixa->ixa_flags &= ~IXAF_PMTU_IPV4_DF;
			} else {
				ixa->ixa_flags &= ~IXAF_PMTU_TOO_SMALL;
				ixa->ixa_flags |= IXAF_PMTU_IPV4_DF;
			}
		} else {
			ixa->ixa_flags &= ~IXAF_PMTU_TOO_SMALL;
			ixa->ixa_flags |= IXAF_PMTU_IPV4_DF;
		}
	}

	/*
	 * If we have an IRE_LOCAL we use the loopback mtu instead of
	 * the ill for going out the wire i.e., IRE_LOCAL gets the same
	 * mtu as IRE_LOOPBACK.
	 */
	if (ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK)) {
		uint_t loopback_mtu;

		loopback_mtu = (ire->ire_ipversion == IPV6_VERSION) ?
		    ip_loopback_mtu_v6plus : ip_loopback_mtuplus;

		if (loopback_mtu < pmtu)
			pmtu = loopback_mtu;
	} else if (nce != NULL) {
		/*
		 * Make sure we don't exceed the interface MTU.
		 * In the case of RTF_REJECT or RTF_BLACKHOLE we might not have
		 * an ill. We'd use the above IP_MAXPACKET in that case just
		 * to tell the transport something larger than zero.
		 */
		if (ire->ire_type & (IRE_MULTICAST|IRE_BROADCAST)) {
			if (nce->nce_common->ncec_ill->ill_mc_mtu < pmtu)
				pmtu = nce->nce_common->ncec_ill->ill_mc_mtu;
			if (nce->nce_common->ncec_ill != nce->nce_ill &&
			    nce->nce_ill->ill_mc_mtu < pmtu) {
				/*
				 * for interfaces in an IPMP group, the mtu of
				 * the nce_ill (under_ill) could be different
				 * from the mtu of the ncec_ill, so we take the
				 * min of the two.
				 */
				pmtu = nce->nce_ill->ill_mc_mtu;
			}
		} else {
			if (nce->nce_common->ncec_ill->ill_mtu < pmtu)
				pmtu = nce->nce_common->ncec_ill->ill_mtu;
			if (nce->nce_common->ncec_ill != nce->nce_ill &&
			    nce->nce_ill->ill_mtu < pmtu) {
				/*
				 * for interfaces in an IPMP group, the mtu of
				 * the nce_ill (under_ill) could be different
				 * from the mtu of the ncec_ill, so we take the
				 * min of the two.
				 */
				pmtu = nce->nce_ill->ill_mtu;
			}
		}
	}

	/*
	 * Handle the IPV6_USE_MIN_MTU socket option or ancillary data.
	 * Only applies to IPv6.
	 */
	if (!(ixa->ixa_flags & IXAF_IS_IPV4)) {
		if (ixa->ixa_flags & IXAF_USE_MIN_MTU) {
			switch (ixa->ixa_use_min_mtu) {
			case IPV6_USE_MIN_MTU_MULTICAST:
				if (ire->ire_type & IRE_MULTICAST)
					pmtu = IPV6_MIN_MTU;
				break;
			case IPV6_USE_MIN_MTU_ALWAYS:
				pmtu = IPV6_MIN_MTU;
				break;
			case IPV6_USE_MIN_MTU_NEVER:
				break;
			}
		} else {
			/* Default is IPV6_USE_MIN_MTU_MULTICAST */
			if (ire->ire_type & IRE_MULTICAST)
				pmtu = IPV6_MIN_MTU;
		}
	}

	/*
	 * For multirouted IPv6 packets, the IP layer will insert a 8-byte
	 * fragment header in every packet. We compensate for those cases by
	 * returning a smaller path MTU to the ULP.
	 *
	 * In the case of CGTP then ip_output will add a fragment header.
	 * Make sure there is room for it by telling a smaller number
	 * to the transport.
	 *
	 * When IXAF_IPV6_ADDR_FRAGHDR we subtract the frag hdr here
	 * so the ULPs consistently see a iulp_pmtu and ip_get_pmtu()
	 * which is the size of the packets it can send.
	 */
	if (!(ixa->ixa_flags & IXAF_IS_IPV4)) {
		if ((ire->ire_flags & RTF_MULTIRT) ||
		    (ixa->ixa_flags & IXAF_MULTIRT_MULTICAST)) {
			pmtu -= sizeof (ip6_frag_t);
			ixa->ixa_flags |= IXAF_IPV6_ADD_FRAGHDR;
		}
	}

	return (pmtu);
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
	int	i;
	arl_ill_common_t *ai = ill->ill_common;

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

	/* qprocsoff is done via ill_delete_tail */
	ill_delete_tail(ill);
	/*
	 * synchronously wait for arp stream to unbind. After this, we
	 * cannot get any data packets up from the driver.
	 */
	arp_unbind_complete(ill);
	ASSERT(ill->ill_ipst == NULL);

	/*
	 * Walk through all conns and qenable those that have queued data.
	 * Close synchronization needs this to
	 * be done to ensure that all upper layers blocked
	 * due to flow control to the closing device
	 * get unblocked.
	 */
	ip1dbg(("ip_wsrv: walking\n"));
	for (i = 0; i < TX_FANOUT_SIZE; i++) {
		conn_walk_drain(ipst, &ipst->ips_idl_tx_list[i]);
	}

	/*
	 * ai can be null if this is an IPv6 ill, or if the IPv4
	 * stream is being torn down before ARP was plumbed (e.g.,
	 * /sbin/ifconfig plumbing a stream twice, and encountering
	 * an error
	 */
	if (ai != NULL) {
		ASSERT(!ill->ill_isv6);
		mutex_enter(&ai->ai_lock);
		ai->ai_ill = NULL;
		if (ai->ai_arl == NULL) {
			mutex_destroy(&ai->ai_lock);
			kmem_free(ai, sizeof (*ai));
		} else {
			cv_signal(&ai->ai_ill_unplumb_done);
			mutex_exit(&ai->ai_lock);
		}
	}

	mutex_enter(&ipst->ips_ip_mi_lock);
	mi_close_unlink(&ipst->ips_ip_g_head, (IDP)ill);
	mutex_exit(&ipst->ips_ip_mi_lock);

	/*
	 * credp could be null if the open didn't succeed and ip_modopen
	 * itself calls ip_close.
	 */
	if (ill->ill_credp != NULL)
		crfree(ill->ill_credp);

	mutex_destroy(&ill->ill_saved_ire_lock);
	mutex_destroy(&ill->ill_lock);
	rw_destroy(&ill->ill_mcast_lock);
	mutex_destroy(&ill->ill_mcast_serializer);
	list_destroy(&ill->ill_nce);

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
	 *
	 * conn_idl, and conn_ilg cannot get set henceforth.
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
		ill_set_inputfn(connp->conn_dhcpinit_ill);
		connp->conn_dhcpinit_ill = NULL;
	}
	if (connp->conn_ilg != NULL)
		ilg_cleanup_reqd = B_TRUE;
	mutex_exit(&connp->conn_lock);

	if (conn_ioctl_cleanup_reqd)
		conn_ioctl_cleanup(connp);

	if (is_system_labeled() && connp->conn_anon_port) {
		(void) tsol_mlp_anon(crgetzone(connp->conn_cred),
		    connp->conn_mlp_type, connp->conn_proto,
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
	 * Remove this conn from the drain list, and do any other cleanup that
	 * may be required.  (TCP conns are never flow controlled, and
	 * conn_idl will be NULL.)
	 */
	if (drain_cleanup_reqd && connp->conn_idl != NULL) {
		idl_t *idl = connp->conn_idl;

		mutex_enter(&idl->idl_lock);
		conn_drain(connp, B_TRUE);
		mutex_exit(&idl->idl_lock);
	}

	if (connp == ipst->ips_ip_g_mrouter)
		(void) ip_mrouter_done(ipst);

	if (ilg_cleanup_reqd)
		ilg_delete_all(connp);

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
ip_conn_input(void *arg1, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t *connp = (conn_t *)arg1;

	putnext(connp->conn_rq, mp);
}

/* Dummy in case ICMP error delivery is attempted to a /dev/ip instance */
/* ARGSUSED */
static void
ip_conn_input_icmp(void *arg1, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	freemsg(mp);
}

/*
 * Called when the module is about to be unloaded
 */
void
ip_ddi_destroy(void)
{
	/* This needs to be called before destroying any transports. */
	mutex_enter(&cpu_lock);
	unregister_cpu_setup_func(ip_tp_cpu_update, NULL);
	mutex_exit(&cpu_lock);

	tnet_fini();

	icmp_ddi_g_destroy();
	rts_ddi_g_destroy();
	udp_ddi_g_destroy();
	sctp_ddi_g_destroy();
	tcp_ddi_g_destroy();
	ilb_ddi_g_destroy();
	dce_g_destroy();
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
	kt_did_t ktid;

#ifdef NS_DEBUG
	printf("ip_stack_shutdown(%p, stack %d)\n", (void *)ipst, stackid);
#endif

	/*
	 * Perform cleanup for special interfaces (loopback and IPMP).
	 */
	ip_interface_cleanup(ipst);

	/*
	 * The *_hook_shutdown()s start the process of notifying any
	 * consumers that things are going away.... nothing is destroyed.
	 */
	ipv4_hook_shutdown(ipst);
	ipv6_hook_shutdown(ipst);
	arp_hook_shutdown(ipst);

	mutex_enter(&ipst->ips_capab_taskq_lock);
	ktid = ipst->ips_capab_taskq_thread->t_did;
	ipst->ips_capab_taskq_quit = B_TRUE;
	cv_signal(&ipst->ips_capab_taskq_cv);
	mutex_exit(&ipst->ips_capab_taskq_lock);

	/*
	 * In rare occurrences, particularly on virtual hardware where CPUs can
	 * be de-scheduled, the thread that we just signaled will not run until
	 * after we have gotten through parts of ip_stack_fini. If that happens
	 * then we'll try to grab the ips_capab_taskq_lock as part of returning
	 * from cv_wait which no longer exists.
	 */
	thread_join(ktid);
}

/*
 * Free the IP stack instance.
 */
static void
ip_stack_fini(netstackid_t stackid, void *arg)
{
	ip_stack_t *ipst = (ip_stack_t *)arg;
	int ret;

#ifdef NS_DEBUG
	printf("ip_stack_fini(%p, stack %d)\n", (void *)ipst, stackid);
#endif
	/*
	 * At this point, all of the notifications that the events and
	 * protocols are going away have been run, meaning that we can
	 * now set about starting to clean things up.
	 */
	ipobs_fini(ipst);
	ipv4_hook_destroy(ipst);
	ipv6_hook_destroy(ipst);
	arp_hook_destroy(ipst);
	ip_net_destroy(ipst);

	ipmp_destroy(ipst);

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

	kmem_free(ipst->ips_propinfo_tbl,
	    ip_propinfo_count * sizeof (mod_prop_info_t));
	ipst->ips_propinfo_tbl = NULL;

	dce_stack_destroy(ipst);
	ip_mrouter_stack_destroy(ipst);

	/*
	 * Quiesce all of our timers. Note we set the quiesce flags before we
	 * call untimeout. The slowtimers may actually kick off another instance
	 * of the non-slow timers.
	 */
	mutex_enter(&ipst->ips_igmp_timer_lock);
	ipst->ips_igmp_timer_quiesce = B_TRUE;
	mutex_exit(&ipst->ips_igmp_timer_lock);

	mutex_enter(&ipst->ips_mld_timer_lock);
	ipst->ips_mld_timer_quiesce = B_TRUE;
	mutex_exit(&ipst->ips_mld_timer_lock);

	mutex_enter(&ipst->ips_igmp_slowtimeout_lock);
	ipst->ips_igmp_slowtimeout_quiesce = B_TRUE;
	mutex_exit(&ipst->ips_igmp_slowtimeout_lock);

	mutex_enter(&ipst->ips_mld_slowtimeout_lock);
	ipst->ips_mld_slowtimeout_quiesce = B_TRUE;
	mutex_exit(&ipst->ips_mld_slowtimeout_lock);

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

	mutex_destroy(&ipst->ips_capab_taskq_lock);
	cv_destroy(&ipst->ips_capab_taskq_cv);

	rw_destroy(&ipst->ips_srcid_lock);

	mutex_destroy(&ipst->ips_ip_mi_lock);
	rw_destroy(&ipst->ips_ill_g_usesrc_lock);

	mutex_destroy(&ipst->ips_igmp_timer_lock);
	mutex_destroy(&ipst->ips_mld_timer_lock);
	mutex_destroy(&ipst->ips_igmp_slowtimeout_lock);
	mutex_destroy(&ipst->ips_mld_slowtimeout_lock);
	mutex_destroy(&ipst->ips_ip_addr_avail_lock);
	rw_destroy(&ipst->ips_ill_g_lock);

	kmem_free(ipst->ips_phyint_g_list, sizeof (phyint_list_t));
	ipst->ips_phyint_g_list = NULL;
	kmem_free(ipst->ips_ill_g_heads, sizeof (ill_g_head_t) * MAX_G_HEADS);
	ipst->ips_ill_g_heads = NULL;

	ldi_ident_release(ipst->ips_ldi_ident);
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
	ipsec_policy_g_init();
	tcp_ddi_g_init();
	sctp_ddi_g_init();
	dce_g_init();

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of udp_stack_t's.
	 */
	netstack_register(NS_IP, ip_stack_init, ip_stack_shutdown,
	    ip_stack_fini);

	tnet_init();

	udp_ddi_g_init();
	rts_ddi_g_init();
	icmp_ddi_g_init();
	ilb_ddi_g_init();

	/* This needs to be called after all transports are initialized. */
	mutex_enter(&cpu_lock);
	register_cpu_setup_func(ip_tp_cpu_update, NULL);
	mutex_exit(&cpu_lock);
}

/*
 * Initialize the IP stack instance.
 */
static void *
ip_stack_init(netstackid_t stackid, netstack_t *ns)
{
	ip_stack_t	*ipst;
	size_t		arrsz;
	major_t		major;

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

	mutex_init(&ipst->ips_igmp_timer_lock, NULL, MUTEX_DEFAULT, NULL);
	ipst->ips_igmp_deferred_next = INFINITY;
	mutex_init(&ipst->ips_mld_timer_lock, NULL, MUTEX_DEFAULT, NULL);
	ipst->ips_mld_deferred_next = INFINITY;
	mutex_init(&ipst->ips_igmp_slowtimeout_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipst->ips_mld_slowtimeout_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipst->ips_ip_mi_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipst->ips_ip_addr_avail_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&ipst->ips_ill_g_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&ipst->ips_ill_g_usesrc_lock, NULL, RW_DEFAULT, NULL);

	ipcl_init(ipst);
	ip_ire_init(ipst);
	ip6_asp_init(ipst);
	ipif_init(ipst);
	conn_drain_init(ipst);
	ip_mrouter_stack_init(ipst);
	dce_stack_init(ipst);

	ipst->ips_ip_multirt_log_interval = 1000;

	ipst->ips_ill_index = 1;

	ipst->ips_saved_ip_forwarding = -1;
	ipst->ips_reg_vif_num = ALL_VIFS; 	/* Index to Register vif */

	arrsz = ip_propinfo_count * sizeof (mod_prop_info_t);
	ipst->ips_propinfo_tbl = (mod_prop_info_t *)kmem_alloc(arrsz, KM_SLEEP);
	bcopy(ip_propinfo_tbl, ipst->ips_propinfo_tbl, arrsz);

	ipst->ips_ip_mibkp = ip_kstat_init(stackid, ipst);
	ipst->ips_icmp_mibkp = icmp_kstat_init(stackid);
	ipst->ips_ip_kstat = ip_kstat2_init(stackid, &ipst->ips_ip_statistics);
	ipst->ips_ip6_kstat =
	    ip6_kstat_init(stackid, &ipst->ips_ip6_statistics);

	ipst->ips_ip_src_id = 1;
	rw_init(&ipst->ips_srcid_lock, NULL, RW_DEFAULT, NULL);

	ipst->ips_src_generation = SRC_GENERATION_INITIAL;

	ip_net_init(ipst, ns);
	ipv4_hook_init(ipst);
	ipv6_hook_init(ipst);
	arp_hook_init(ipst);
	ipmp_init(ipst);
	ipobs_init(ipst);

	/*
	 * Create the taskq dispatcher thread and initialize related stuff.
	 */
	mutex_init(&ipst->ips_capab_taskq_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ipst->ips_capab_taskq_cv, NULL, CV_DEFAULT, NULL);
	ipst->ips_capab_taskq_thread = thread_create(NULL, 0,
	    ill_taskq_dispatch, ipst, 0, &p0, TS_RUN, minclsyspri);

	major = mod_name_to_major(INET_NAME);
	(void) ldi_ident_from_major(major, &ipst->ips_ldi_ident);
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
 * Allocate and initialize a DLPI notification.  (May be called as writer.)
 */
mblk_t *
ip_dlnotify_alloc(uint_t notification, uint_t data)
{
	dl_notify_ind_t	*notifyp;
	mblk_t		*mp;

	if ((mp = ip_dlpi_alloc(DL_NOTIFY_IND_SIZE, DL_NOTIFY_IND)) == NULL)
		return (NULL);

	notifyp = (dl_notify_ind_t *)mp->b_rptr;
	notifyp->dl_notification = notification;
	notifyp->dl_data = data;
	return (mp);
}

mblk_t *
ip_dlnotify_alloc2(uint_t notification, uint_t data1, uint_t data2)
{
	dl_notify_ind_t	*notifyp;
	mblk_t		*mp;

	if ((mp = ip_dlpi_alloc(DL_NOTIFY_IND_SIZE, DL_NOTIFY_IND)) == NULL)
		return (NULL);

	notifyp = (dl_notify_ind_t *)mp->b_rptr;
	notifyp->dl_notification = notification;
	notifyp->dl_data1 = data1;
	notifyp->dl_data2 = data2;
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
 * Called when it is conceptually a ULP that would sent the packet
 * e.g., port unreachable and protocol unreachable. Check that the packet
 * would have passed the IPsec global policy before sending the error.
 *
 * Send an ICMP error after patching up the packet appropriately.
 * Uses ip_drop_input and bumps the appropriate MIB.
 */
void
ip_fanout_send_icmp_v4(mblk_t *mp, uint_t icmp_type, uint_t icmp_code,
    ip_recv_attr_t *ira)
{
	ipha_t		*ipha;
	boolean_t	secure;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	secure = ira->ira_flags & IRAF_IPSEC_SECURE;

	/*
	 * We are generating an icmp error for some inbound packet.
	 * Called from all ip_fanout_(udp, tcp, proto) functions.
	 * Before we generate an error, check with global policy
	 * to see whether this is allowed to enter the system. As
	 * there is no "conn", we are checking with global policy.
	 */
	ipha = (ipha_t *)mp->b_rptr;
	if (secure || ipss->ipsec_inbound_v4_policy_present) {
		mp = ipsec_check_global_policy(mp, NULL, ipha, NULL, ira, ns);
		if (mp == NULL)
			return;
	}

	/* We never send errors for protocols that we do implement */
	if (ira->ira_protocol == IPPROTO_ICMP ||
	    ira->ira_protocol == IPPROTO_IGMP) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ip_fanout_send_icmp_v4", mp, ill);
		freemsg(mp);
		return;
	}
	/*
	 * Have to correct checksum since
	 * the packet might have been
	 * fragmented and the reassembly code in ip_rput
	 * does not restore the IP checksum.
	 */
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

	switch (icmp_type) {
	case ICMP_DEST_UNREACHABLE:
		switch (icmp_code) {
		case ICMP_PROTOCOL_UNREACHABLE:
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInUnknownProtos);
			ip_drop_input("ipIfStatsInUnknownProtos", mp, ill);
			break;
		case ICMP_PORT_UNREACHABLE:
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsNoPorts);
			ip_drop_input("ipIfStatsNoPorts", mp, ill);
			break;
		}

		icmp_unreachable(mp, icmp_code, ira);
		break;
	default:
#ifdef DEBUG
		panic("ip_fanout_send_icmp_v4: wrong type");
		/*NOTREACHED*/
#else
		freemsg(mp);
		break;
#endif
	}
}

/*
 * Used to send an ICMP error message when a packet is received for
 * a protocol that is not supported. The mblk passed as argument
 * is consumed by this function.
 */
void
ip_proto_not_sup(mblk_t *mp, ip_recv_attr_t *ira)
{
	ipha_t		*ipha;

	ipha = (ipha_t *)mp->b_rptr;
	if (ira->ira_flags & IRAF_IS_IPV4) {
		ASSERT(IPH_HDR_VERSION(ipha) == IP_VERSION);
		ip_fanout_send_icmp_v4(mp, ICMP_DEST_UNREACHABLE,
		    ICMP_PROTOCOL_UNREACHABLE, ira);
	} else {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		ip_fanout_send_icmp_v6(mp, ICMP6_PARAM_PROB,
		    ICMP6_PARAMPROB_NEXTHEADER, ira);
	}
}

/*
 * Deliver a rawip packet to the given conn, possibly applying ipsec policy.
 * Handles IPv4 and IPv6.
 * We are responsible for disposing of mp, such as by freemsg() or putnext()
 * Caller is responsible for dropping references to the conn.
 */
void
ip_fanout_proto_conn(conn_t *connp, mblk_t *mp, ipha_t *ipha, ip6_t *ip6h,
    ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;
	boolean_t	secure;
	uint_t		protocol = ira->ira_protocol;
	iaflags_t	iraflags = ira->ira_flags;
	queue_t		*rq;

	secure = iraflags & IRAF_IPSEC_SECURE;

	rq = connp->conn_rq;
	if (IPCL_IS_NONSTR(connp) ? connp->conn_flow_cntrld : !canputnext(rq)) {
		switch (protocol) {
		case IPPROTO_ICMPV6:
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInOverflows);
			break;
		case IPPROTO_ICMP:
			BUMP_MIB(&ipst->ips_icmp_mib, icmpInOverflows);
			break;
		default:
			BUMP_MIB(ill->ill_ip_mib, rawipIfStatsInOverflows);
			break;
		}
		freemsg(mp);
		return;
	}

	ASSERT(!(IPCL_IS_IPTUN(connp)));

	if (((iraflags & IRAF_IS_IPV4) ?
	    CONN_INBOUND_POLICY_PRESENT(connp, ipss) :
	    CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss)) ||
	    secure) {
		mp = ipsec_check_inbound_policy(mp, connp, ipha,
		    ip6h, ira);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			/* Note that mp is NULL */
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			return;
		}
	}

	if (iraflags & IRAF_ICMP_ERROR) {
		(connp->conn_recvicmp)(connp, mp, NULL, ira);
	} else {
		ill_t *rill = ira->ira_rill;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		ira->ira_ill = ira->ira_rill = NULL;
		/* Send it upstream */
		(connp->conn_recv)(connp, mp, NULL, ira);
		ira->ira_ill = ill;
		ira->ira_rill = rill;
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
 * Zones notes:
 * Earlier in ip_input on a system with multiple shared-IP zones we
 * duplicate the multicast and broadcast packets and send them up
 * with each explicit zoneid that exists on that ill.
 * This means that here we can match the zoneid with SO_ALLZONES being special.
 */
void
ip_fanout_proto_v4(mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	mblk_t		*mp1;
	ipaddr_t	laddr;
	conn_t		*connp, *first_connp, *next_connp;
	connf_t		*connfp;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	laddr = ipha->ipha_dst;

	connfp = &ipst->ips_ipcl_proto_fanout_v4[ira->ira_protocol];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		/* Note: IPCL_PROTO_MATCH includes conn_wantpacket */
		if (IPCL_PROTO_MATCH(connp, ira, ipha) &&
		    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
		    tsol_receive_local(mp, &laddr, IPV4_VERSION, ira, connp))) {
			break;
		}
	}

	if (connp == NULL) {
		/*
		 * No one bound to these addresses.  Is
		 * there a client that wants all
		 * unclaimed datagrams?
		 */
		mutex_exit(&connfp->connf_lock);
		ip_fanout_send_icmp_v4(mp, ICMP_DEST_UNREACHABLE,
		    ICMP_PROTOCOL_UNREACHABLE, ira);
		return;
	}

	ASSERT(IPCL_IS_NONSTR(connp) || connp->conn_rq != NULL);

	CONN_INC_REF(connp);
	first_connp = connp;
	connp = connp->conn_next;

	for (;;) {
		while (connp != NULL) {
			/* Note: IPCL_PROTO_MATCH includes conn_wantpacket */
			if (IPCL_PROTO_MATCH(connp, ira, ipha) &&
			    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
			    tsol_receive_local(mp, &laddr, IPV4_VERSION,
			    ira, connp)))
				break;
			connp = connp->conn_next;
		}

		if (connp == NULL) {
			/* No more interested clients */
			connp = first_connp;
			break;
		}
		if (((mp1 = dupmsg(mp)) == NULL) &&
		    ((mp1 = copymsg(mp)) == NULL)) {
			/* Memory allocation failed */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			connp = first_connp;
			break;
		}

		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);

		ip_fanout_proto_conn(connp, mp1, (ipha_t *)mp1->b_rptr, NULL,
		    ira);

		mutex_enter(&connfp->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_connp = connp->conn_next;
		CONN_DEC_REF(connp);
		connp = next_connp;
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);

	ip_fanout_proto_conn(connp, mp, ipha, NULL, ira);

	CONN_DEC_REF(connp);
}

/*
 * If we have a IPsec NAT-Traversal packet, strip the zero-SPI or
 * pass it along to ESP if the SPI is non-zero.  Returns the mblk if the mblk
 * is not consumed.
 *
 * One of three things can happen, all of which affect the passed-in mblk:
 *
 * 1.) The packet is stock UDP and gets its zero-SPI stripped.  Return mblk..
 *
 * 2.) The packet is ESP-in-UDP, gets transformed into an equivalent
 *     ESP packet, and is passed along to ESP for consumption.  Return NULL.
 *
 * 3.) The packet is an ESP-in-UDP Keepalive.  Drop it and return NULL.
 */
mblk_t *
zero_spi_check(mblk_t *mp, ip_recv_attr_t *ira)
{
	int shift, plen, iph_len;
	ipha_t *ipha;
	udpha_t *udpha;
	uint32_t *spi;
	uint32_t esp_ports;
	uint8_t *orptr;
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	ipha = (ipha_t *)mp->b_rptr;
	iph_len = ira->ira_ip_hdr_length;
	plen = ira->ira_pktlen;

	if (plen - iph_len - sizeof (udpha_t) < sizeof (uint32_t)) {
		/*
		 * Most likely a keepalive for the benefit of an intervening
		 * NAT.  These aren't for us, per se, so drop it.
		 *
		 * RFC 3947/8 doesn't say for sure what to do for 2-3
		 * byte packets (keepalives are 1-byte), but we'll drop them
		 * also.
		 */
		ip_drop_packet(mp, B_TRUE, ira->ira_ill,
		    DROPPER(ipss, ipds_esp_nat_t_ka), &ipss->ipsec_dropper);
		return (NULL);
	}

	if (MBLKL(mp) < iph_len + sizeof (udpha_t) + sizeof (*spi)) {
		/* might as well pull it all up - it might be ESP. */
		if (!pullupmsg(mp, -1)) {
			ip_drop_packet(mp, B_TRUE, ira->ira_ill,
			    DROPPER(ipss, ipds_esp_nomem),
			    &ipss->ipsec_dropper);
			return (NULL);
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
	ira->ira_pktlen = (plen - shift);
	ipha->ipha_length = htons(ira->ira_pktlen);
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

		ira->ira_flags |= IRAF_ESP_UDP_PORTS;
		ira->ira_esp_udp_ports = esp_ports;
		ip_fanout_v4(mp, ipha, ira);
		return (NULL);
	}
	return (mp);
}

/*
 * Deliver a udp packet to the given conn, possibly applying ipsec policy.
 * Handles IPv4 and IPv6.
 * We are responsible for disposing of mp, such as by freemsg() or putnext()
 * Caller is responsible for dropping references to the conn.
 */
void
ip_fanout_udp_conn(conn_t *connp, mblk_t *mp, ipha_t *ipha, ip6_t *ip6h,
    ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;
	boolean_t	secure;
	iaflags_t	iraflags = ira->ira_flags;

	secure = iraflags & IRAF_IPSEC_SECURE;

	if (IPCL_IS_NONSTR(connp) ? connp->conn_flow_cntrld :
	    !canputnext(connp->conn_rq)) {
		BUMP_MIB(ill->ill_ip_mib, udpIfStatsInOverflows);
		freemsg(mp);
		return;
	}

	if (((iraflags & IRAF_IS_IPV4) ?
	    CONN_INBOUND_POLICY_PRESENT(connp, ipss) :
	    CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss)) ||
	    secure) {
		mp = ipsec_check_inbound_policy(mp, connp, ipha,
		    ip6h, ira);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			/* Note that mp is NULL */
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			return;
		}
	}

	/*
	 * Since this code is not used for UDP unicast we don't need a NAT_T
	 * check. Only ip_fanout_v4 has that check.
	 */
	if (ira->ira_flags & IRAF_ICMP_ERROR) {
		(connp->conn_recvicmp)(connp, mp, NULL, ira);
	} else {
		ill_t *rill = ira->ira_rill;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		ira->ira_ill = ira->ira_rill = NULL;
		/* Send it upstream */
		(connp->conn_recv)(connp, mp, NULL, ira);
		ira->ira_ill = ill;
		ira->ira_rill = rill;
	}
}

/*
 * Fanout for UDP packets that are multicast or broadcast, and ICMP errors.
 * (Unicast fanout is handled in ip_input_v4.)
 *
 * If SO_REUSEADDR is set all multicast and broadcast packets
 * will be delivered to all conns bound to the same port.
 *
 * If there is at least one matching AF_INET receiver, then we will
 * ignore any AF_INET6 receivers.
 * In the special case where an AF_INET socket binds to 0.0.0.0/<port> and an
 * AF_INET6 socket binds to ::/<port>, only the AF_INET socket receives the IPv4
 * packets.
 *
 * Zones notes:
 * Earlier in ip_input on a system with multiple shared-IP zones we
 * duplicate the multicast and broadcast packets and send them up
 * with each explicit zoneid that exists on that ill.
 * This means that here we can match the zoneid with SO_ALLZONES being special.
 */
void
ip_fanout_udp_multi_v4(mblk_t *mp, ipha_t *ipha, uint16_t lport, uint16_t fport,
    ip_recv_attr_t *ira)
{
	ipaddr_t	laddr;
	in6_addr_t	v6faddr;
	conn_t		*connp;
	connf_t		*connfp;
	ipaddr_t	faddr;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ira->ira_flags & (IRAF_MULTIBROADCAST|IRAF_ICMP_ERROR));

	laddr = ipha->ipha_dst;
	faddr = ipha->ipha_src;

	connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(lport, ipst)];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;

	/*
	 * If SO_REUSEADDR has been set on the first we send the
	 * packet to all clients that have joined the group and
	 * match the port.
	 */
	while (connp != NULL) {
		if ((IPCL_UDP_MATCH(connp, lport, laddr, fport, faddr)) &&
		    conn_wantpacket(connp, ira, ipha) &&
		    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
		    tsol_receive_local(mp, &laddr, IPV4_VERSION, ira, connp)))
			break;
		connp = connp->conn_next;
	}

	if (connp == NULL)
		goto notfound;

	CONN_INC_REF(connp);

	if (connp->conn_reuseaddr) {
		conn_t		*first_connp = connp;
		conn_t		*next_connp;
		mblk_t		*mp1;

		connp = connp->conn_next;
		for (;;) {
			while (connp != NULL) {
				if (IPCL_UDP_MATCH(connp, lport, laddr,
				    fport, faddr) &&
				    conn_wantpacket(connp, ira, ipha) &&
				    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
				    tsol_receive_local(mp, &laddr, IPV4_VERSION,
				    ira, connp)))
					break;
				connp = connp->conn_next;
			}
			if (connp == NULL) {
				/* No more interested clients */
				connp = first_connp;
				break;
			}
			if (((mp1 = dupmsg(mp)) == NULL) &&
			    ((mp1 = copymsg(mp)) == NULL)) {
				/* Memory allocation failed */
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				connp = first_connp;
				break;
			}
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);

			IP_STAT(ipst, ip_udp_fanmb);
			ip_fanout_udp_conn(connp, mp1, (ipha_t *)mp1->b_rptr,
			    NULL, ira);
			mutex_enter(&connfp->connf_lock);
			/* Follow the next pointer before releasing the conn */
			next_connp = connp->conn_next;
			CONN_DEC_REF(connp);
			connp = next_connp;
		}
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);
	IP_STAT(ipst, ip_udp_fanmb);
	ip_fanout_udp_conn(connp, mp, ipha, NULL, ira);
	CONN_DEC_REF(connp);
	return;

notfound:
	mutex_exit(&connfp->connf_lock);
	/*
	 * IPv6 endpoints bound to multicast IPv4-mapped addresses
	 * have already been matched above, since they live in the IPv4
	 * fanout tables. This implies we only need to
	 * check for IPv6 in6addr_any endpoints here.
	 * Thus we compare using ipv6_all_zeros instead of the destination
	 * address, except for the multicast group membership lookup which
	 * uses the IPv4 destination.
	 */
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &v6faddr);
	connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(lport, ipst)];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	/*
	 * IPv4 multicast packet being delivered to an AF_INET6
	 * in6addr_any endpoint.
	 * Need to check conn_wantpacket(). Note that we use conn_wantpacket()
	 * and not conn_wantpacket_v6() since any multicast membership is
	 * for an IPv4-mapped multicast address.
	 */
	while (connp != NULL) {
		if (IPCL_UDP_MATCH_V6(connp, lport, ipv6_all_zeros,
		    fport, v6faddr) &&
		    conn_wantpacket(connp, ira, ipha) &&
		    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
		    tsol_receive_local(mp, &laddr, IPV4_VERSION, ira, connp)))
			break;
		connp = connp->conn_next;
	}

	if (connp == NULL) {
		/*
		 * No one bound to this port.  Is
		 * there a client that wants all
		 * unclaimed datagrams?
		 */
		mutex_exit(&connfp->connf_lock);

		if (ipst->ips_ipcl_proto_fanout_v4[IPPROTO_UDP].connf_head !=
		    NULL) {
			ASSERT(ira->ira_protocol == IPPROTO_UDP);
			ip_fanout_proto_v4(mp, ipha, ira);
		} else {
			/*
			 * We used to attempt to send an icmp error here, but
			 * since this is known to be a multicast packet
			 * and we don't send icmp errors in response to
			 * multicast, just drop the packet and give up sooner.
			 */
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsNoPorts);
			freemsg(mp);
		}
		return;
	}
	CONN_INC_REF(connp);
	ASSERT(IPCL_IS_NONSTR(connp) || connp->conn_rq != NULL);

	/*
	 * If SO_REUSEADDR has been set on the first we send the
	 * packet to all clients that have joined the group and
	 * match the port.
	 */
	if (connp->conn_reuseaddr) {
		conn_t		*first_connp = connp;
		conn_t		*next_connp;
		mblk_t		*mp1;

		connp = connp->conn_next;
		for (;;) {
			while (connp != NULL) {
				if (IPCL_UDP_MATCH_V6(connp, lport,
				    ipv6_all_zeros, fport, v6faddr) &&
				    conn_wantpacket(connp, ira, ipha) &&
				    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
				    tsol_receive_local(mp, &laddr, IPV4_VERSION,
				    ira, connp)))
					break;
				connp = connp->conn_next;
			}
			if (connp == NULL) {
				/* No more interested clients */
				connp = first_connp;
				break;
			}
			if (((mp1 = dupmsg(mp)) == NULL) &&
			    ((mp1 = copymsg(mp)) == NULL)) {
				/* Memory allocation failed */
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				connp = first_connp;
				break;
			}
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);

			IP_STAT(ipst, ip_udp_fanmb);
			ip_fanout_udp_conn(connp, mp1, (ipha_t *)mp1->b_rptr,
			    NULL, ira);
			mutex_enter(&connfp->connf_lock);
			/* Follow the next pointer before releasing the conn */
			next_connp = connp->conn_next;
			CONN_DEC_REF(connp);
			connp = next_connp;
		}
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);
	IP_STAT(ipst, ip_udp_fanmb);
	ip_fanout_udp_conn(connp, mp, ipha, NULL, ira);
	CONN_DEC_REF(connp);
}

/*
 * Split an incoming packet's IPv4 options into the label and the other options.
 * If 'allocate' is set it does memory allocation for the ip_pkt_t, including
 * clearing out any leftover label or options.
 * Otherwise it just makes ipp point into the packet.
 *
 * Returns zero if ok; ENOMEM if the buffer couldn't be allocated.
 */
int
ip_find_hdr_v4(ipha_t *ipha, ip_pkt_t *ipp, boolean_t allocate)
{
	uchar_t		*opt;
	uint32_t	totallen;
	uint32_t	optval;
	uint32_t	optlen;

	ipp->ipp_fields |= IPPF_HOPLIMIT | IPPF_TCLASS | IPPF_ADDR;
	ipp->ipp_hoplimit = ipha->ipha_ttl;
	ipp->ipp_type_of_service = ipha->ipha_type_of_service;
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &ipp->ipp_addr);

	/*
	 * Get length (in 4 byte octets) of IP header options.
	 */
	totallen = ipha->ipha_version_and_hdr_length -
	    (uint8_t)((IP_VERSION << 4) + IP_SIMPLE_HDR_LENGTH_IN_WORDS);

	if (totallen == 0) {
		if (!allocate)
			return (0);

		/* Clear out anything from a previous packet */
		if (ipp->ipp_fields & IPPF_IPV4_OPTIONS) {
			kmem_free(ipp->ipp_ipv4_options,
			    ipp->ipp_ipv4_options_len);
			ipp->ipp_ipv4_options = NULL;
			ipp->ipp_ipv4_options_len = 0;
			ipp->ipp_fields &= ~IPPF_IPV4_OPTIONS;
		}
		if (ipp->ipp_fields & IPPF_LABEL_V4) {
			kmem_free(ipp->ipp_label_v4, ipp->ipp_label_len_v4);
			ipp->ipp_label_v4 = NULL;
			ipp->ipp_label_len_v4 = 0;
			ipp->ipp_fields &= ~IPPF_LABEL_V4;
		}
		return (0);
	}

	totallen <<= 2;
	opt = (uchar_t *)&ipha[1];
	if (!is_system_labeled()) {

	copyall:
		if (!allocate) {
			if (totallen != 0) {
				ipp->ipp_ipv4_options = opt;
				ipp->ipp_ipv4_options_len = totallen;
				ipp->ipp_fields |= IPPF_IPV4_OPTIONS;
			}
			return (0);
		}
		/* Just copy all of options */
		if (ipp->ipp_fields & IPPF_IPV4_OPTIONS) {
			if (totallen == ipp->ipp_ipv4_options_len) {
				bcopy(opt, ipp->ipp_ipv4_options, totallen);
				return (0);
			}
			kmem_free(ipp->ipp_ipv4_options,
			    ipp->ipp_ipv4_options_len);
			ipp->ipp_ipv4_options = NULL;
			ipp->ipp_ipv4_options_len = 0;
			ipp->ipp_fields &= ~IPPF_IPV4_OPTIONS;
		}
		if (totallen == 0)
			return (0);

		ipp->ipp_ipv4_options = kmem_alloc(totallen, KM_NOSLEEP);
		if (ipp->ipp_ipv4_options == NULL)
			return (ENOMEM);
		ipp->ipp_ipv4_options_len = totallen;
		ipp->ipp_fields |= IPPF_IPV4_OPTIONS;
		bcopy(opt, ipp->ipp_ipv4_options, totallen);
		return (0);
	}

	if (allocate && (ipp->ipp_fields & IPPF_LABEL_V4)) {
		kmem_free(ipp->ipp_label_v4, ipp->ipp_label_len_v4);
		ipp->ipp_label_v4 = NULL;
		ipp->ipp_label_len_v4 = 0;
		ipp->ipp_fields &= ~IPPF_LABEL_V4;
	}

	/*
	 * Search for CIPSO option.
	 * We assume CIPSO is first in options if it is present.
	 * If it isn't, then ipp_opt_ipv4_options will not include the options
	 * prior to the CIPSO option.
	 */
	while (totallen != 0) {
		switch (optval = opt[IPOPT_OPTVAL]) {
		case IPOPT_EOL:
			return (0);
		case IPOPT_NOP:
			optlen = 1;
			break;
		default:
			if (totallen <= IPOPT_OLEN)
				return (EINVAL);
			optlen = opt[IPOPT_OLEN];
			if (optlen < 2)
				return (EINVAL);
		}
		if (optlen > totallen)
			return (EINVAL);

		switch (optval) {
		case IPOPT_COMSEC:
			if (!allocate) {
				ipp->ipp_label_v4 = opt;
				ipp->ipp_label_len_v4 = optlen;
				ipp->ipp_fields |= IPPF_LABEL_V4;
			} else {
				ipp->ipp_label_v4 = kmem_alloc(optlen,
				    KM_NOSLEEP);
				if (ipp->ipp_label_v4 == NULL)
					return (ENOMEM);
				ipp->ipp_label_len_v4 = optlen;
				ipp->ipp_fields |= IPPF_LABEL_V4;
				bcopy(opt, ipp->ipp_label_v4, optlen);
			}
			totallen -= optlen;
			opt += optlen;

			/* Skip padding bytes until we get to a multiple of 4 */
			while ((totallen & 3) != 0 && opt[0] == IPOPT_NOP) {
				totallen--;
				opt++;
			}
			/* Remaining as ipp_ipv4_options */
			goto copyall;
		}
		totallen -= optlen;
		opt += optlen;
	}
	/* No CIPSO found; return everything as ipp_ipv4_options */
	totallen = ipha->ipha_version_and_hdr_length -
	    (uint8_t)((IP_VERSION << 4) + IP_SIMPLE_HDR_LENGTH_IN_WORDS);
	totallen <<= 2;
	opt = (uchar_t *)&ipha[1];
	goto copyall;
}

/*
 * Efficient versions of lookup for an IRE when we only
 * match the address.
 * For RTF_REJECT or BLACKHOLE we return IRE_NOROUTE.
 * Does not handle multicast addresses.
 */
uint_t
ip_type_v4(ipaddr_t addr, ip_stack_t *ipst)
{
	ire_t *ire;
	uint_t result;

	ire = ire_ftable_lookup_simple_v4(addr, 0, ipst, NULL);
	ASSERT(ire != NULL);
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))
		result = IRE_NOROUTE;
	else
		result = ire->ire_type;
	ire_refrele(ire);
	return (result);
}

/*
 * Efficient versions of lookup for an IRE when we only
 * match the address.
 * For RTF_REJECT or BLACKHOLE we return IRE_NOROUTE.
 * Does not handle multicast addresses.
 */
uint_t
ip_type_v6(const in6_addr_t *addr, ip_stack_t *ipst)
{
	ire_t *ire;
	uint_t result;

	ire = ire_ftable_lookup_simple_v6(addr, 0, ipst, NULL);
	ASSERT(ire != NULL);
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))
		result = IRE_NOROUTE;
	else
		result = ire->ire_type;
	ire_refrele(ire);
	return (result);
}

/*
 * Nobody should be sending
 * packets up this stream
 */
static void
ip_lrput(queue_t *q, mblk_t *mp)
{
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
 * are ignored - will be handled by ip_output_options. Return the final
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
			if (ip_type_v4(dst, ipst) == IRE_LOCAL) {
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

static int
ip_wait_for_info_ack(ill_t *ill)
{
	int err;

	mutex_enter(&ill->ill_lock);
	while (ill->ill_state_flags & ILL_LL_SUBNET_PENDING) {
		/*
		 * Return value of 0 indicates a pending signal.
		 */
		err = cv_wait_sig(&ill->ill_cv, &ill->ill_lock);
		if (err == 0) {
			mutex_exit(&ill->ill_lock);
			return (EINTR);
		}
	}
	mutex_exit(&ill->ill_lock);
	/*
	 * ip_rput_other could have set an error  in ill_error on
	 * receipt of M_ERROR.
	 */
	return (ill->ill_error);
}

/*
 * This is a module open, i.e. this is a control stream for access
 * to a DLPI device.  We allocate an ill_t as the instance data in
 * this case.
 */
static int
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

	/*
	 * Wait for the DL_INFO_ACK if a DL_INFO_REQ was sent.
	 *
	 * ill_init initializes the ipsq marking this thread as
	 * writer
	 */
	ipsq_exit(ill->ill_phyint->phyint_ipsq);
	err = ip_wait_for_info_ack(ill);
	if (err == 0)
		ill->ill_credp = credp;
	else
		goto fail;

	crhold(credp);

	mutex_enter(&ipst->ips_ip_mi_lock);
	err = mi_open_link(&ipst->ips_ip_g_head, (IDP)q->q_ptr, devp, flag,
	    sflag, credp);
	mutex_exit(&ipst->ips_ip_mi_lock);
fail:
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

	/* Allow reopen. */
	if (q->q_ptr != NULL)
		return (0);

	if (sflag & MODOPEN) {
		/* This is a module open */
		return (ip_modopen(q, devp, flag, sflag, credp));
	}

	if ((flag & ~(FKLYR)) == IP_HELPER_STR) {
		/*
		 * Non streams based socket looking for a stream
		 * to access IP
		 */
		return (ip_helper_stream_setup(q, devp, flag, sflag,
		    credp, isv6));
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

	connp->conn_ixa->ixa_flags |= IXAF_MULTICAST_LOOP | IXAF_SET_ULP_CKSUM;
	/* conn_allzones can not be set this early, hence no IPCL_ZONEID */
	connp->conn_ixa->ixa_zoneid = zoneid;
	connp->conn_zoneid = zoneid;

	connp->conn_rq = q;
	q->q_ptr = WR(q)->q_ptr = connp;

	/* Minor tells us which /dev entry was opened */
	if (isv6) {
		connp->conn_family = AF_INET6;
		connp->conn_ipversion = IPV6_VERSION;
		connp->conn_ixa->ixa_flags &= ~IXAF_IS_IPV4;
		connp->conn_ixa->ixa_src_preferences = IPV6_PREFER_SRC_DEFAULT;
	} else {
		connp->conn_family = AF_INET;
		connp->conn_ipversion = IPV4_VERSION;
		connp->conn_ixa->ixa_flags |= IXAF_IS_IPV4;
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
	connp->conn_cpid = curproc->p_pid;
	/* Cache things in ixa without an extra refhold */
	ASSERT(!(connp->conn_ixa->ixa_free_flags & IXA_FREE_CRED));
	connp->conn_ixa->ixa_cred = connp->conn_cred;
	connp->conn_ixa->ixa_cpid = connp->conn_cpid;
	if (is_system_labeled())
		connp->conn_ixa->ixa_tsl = crgetlabel(connp->conn_cred);

	/*
	 * Handle IP_IOC_RTS_REQUEST and other ioctls which use conn_recv
	 */
	connp->conn_recv = ip_conn_input;
	connp->conn_recvicmp = ip_conn_input_icmp;

	crhold(connp->conn_cred);

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		connp->conn_mac_mode = CONN_MAC_AWARE;

	connp->conn_zone_is_global = (crgetzoneid(credp) == GLOBAL_ZONEID);

	connp->conn_rq = q;
	connp->conn_wq = WR(q);

	/* Non-zero default values */
	connp->conn_ixa->ixa_flags |= IXAF_MULTICAST_LOOP;

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
	ipsec_act_t *actp = NULL;
	uint_t nact;
	ipsec_policy_head_t *ph;
	boolean_t is_pol_reset, is_pol_inserted = B_FALSE;
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

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	/*
	 * If we have already cached policies in conn_connect(), don't
	 * let them change now. We cache policies for connections
	 * whose src,dst [addr, port] is known.
	 */
	if (connp->conn_policy_cached) {
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
		connp->conn_in_enforce_policy = B_FALSE;
		connp->conn_out_enforce_policy = B_FALSE;
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
	 * Always insert IPv4 policy entries, since they can also apply to
	 * ipv6 sockets being used in ipv4-compat mode.
	 */
	if (!ipsec_polhead_insert(ph, actp, nact, IPSEC_AF_V4,
	    IPSEC_TYPE_INBOUND, ns))
		goto enomem;
	is_pol_inserted = B_TRUE;
	if (!ipsec_polhead_insert(ph, actp, nact, IPSEC_AF_V4,
	    IPSEC_TYPE_OUTBOUND, ns))
		goto enomem;

	/*
	 * We're looking at a v6 socket, also insert the v6-specific
	 * entries.
	 */
	if (connp->conn_family == AF_INET6) {
		if (!ipsec_polhead_insert(ph, actp, nact, IPSEC_AF_V6,
		    IPSEC_TYPE_INBOUND, ns))
			goto enomem;
		if (!ipsec_polhead_insert(ph, actp, nact, IPSEC_AF_V6,
		    IPSEC_TYPE_OUTBOUND, ns))
			goto enomem;
	}

	ipsec_actvec_free(actp, nact);

	/*
	 * If the requests need security, set enforce_policy.
	 * If the requests are IPSEC_PREF_NEVER, one should
	 * still set conn_out_enforce_policy so that ip_set_destination
	 * marks the ip_xmit_attr_t appropriatly. This is needed so that
	 * for connections that we don't cache policy in at connect time,
	 * if global policy matches in ip_output_attach_policy, we
	 * don't wrongly inherit global policy. Similarly, we need
	 * to set conn_in_enforce_policy also so that we don't verify
	 * policy wrongly.
	 */
	if ((ah_req & REQ_MASK) != 0 ||
	    (esp_req & REQ_MASK) != 0 ||
	    (se_req & REQ_MASK) != 0) {
		connp->conn_in_enforce_policy = B_TRUE;
		connp->conn_out_enforce_policy = B_TRUE;
	}

	return (error);
#undef REQ_MASK

	/*
	 * Common memory-allocation-failure exit path.
	 */
enomem:
	if (actp != NULL)
		ipsec_actvec_free(actp, nact);
	if (is_pol_inserted)
		ipsec_polhead_flush(ph, ns);
	return (ENOMEM);
}

/*
 * Set socket options for joining and leaving multicast groups.
 * Common to IPv4 and IPv6; inet6 indicates the type of socket.
 * The caller has already check that the option name is consistent with
 * the address family of the socket.
 */
int
ip_opt_set_multicast_group(conn_t *connp, t_scalar_t name,
    uchar_t *invalp, boolean_t inet6, boolean_t checkonly)
{
	int		*i1 = (int *)invalp;
	int		error = 0;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	struct ip_mreq	*v4_mreqp;
	struct ipv6_mreq *v6_mreqp;
	struct group_req *greqp;
	ire_t *ire;
	boolean_t done = B_FALSE;
	ipaddr_t ifaddr;
	in6_addr_t v6group;
	uint_t ifindex;
	boolean_t mcast_opt = B_TRUE;
	mcast_record_t fmode;
	int (*optfn)(conn_t *, boolean_t, const in6_addr_t *,
	    ipaddr_t, uint_t, mcast_record_t, const in6_addr_t *);

	switch (name) {
	case IP_ADD_MEMBERSHIP:
	case IPV6_JOIN_GROUP:
		mcast_opt = B_FALSE;
		/* FALLTHRU */
	case MCAST_JOIN_GROUP:
		fmode = MODE_IS_EXCLUDE;
		optfn = ip_opt_add_group;
		break;

	case IP_DROP_MEMBERSHIP:
	case IPV6_LEAVE_GROUP:
		mcast_opt = B_FALSE;
		/* FALLTHRU */
	case MCAST_LEAVE_GROUP:
		fmode = MODE_IS_INCLUDE;
		optfn = ip_opt_delete_group;
		break;
	default:
		ASSERT(0);
	}

	if (mcast_opt) {
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;

		greqp = (struct group_req *)i1;
		if (greqp->gr_group.ss_family == AF_INET) {
			sin = (struct sockaddr_in *)&(greqp->gr_group);
			IN6_INADDR_TO_V4MAPPED(&sin->sin_addr, &v6group);
		} else {
			if (!inet6)
				return (EINVAL);	/* Not on INET socket */

			sin6 = (struct sockaddr_in6 *)&(greqp->gr_group);
			v6group = sin6->sin6_addr;
		}
		ifaddr = INADDR_ANY;
		ifindex = greqp->gr_interface;
	} else if (inet6) {
		v6_mreqp = (struct ipv6_mreq *)i1;
		v6group = v6_mreqp->ipv6mr_multiaddr;
		ifaddr = INADDR_ANY;
		ifindex = v6_mreqp->ipv6mr_interface;
	} else {
		v4_mreqp = (struct ip_mreq *)i1;
		IN6_INADDR_TO_V4MAPPED(&v4_mreqp->imr_multiaddr, &v6group);
		ifaddr = (ipaddr_t)v4_mreqp->imr_interface.s_addr;
		ifindex = 0;
	}

	/*
	 * In the multirouting case, we need to replicate
	 * the request on all interfaces that will take part
	 * in replication.  We do so because multirouting is
	 * reflective, thus we will probably receive multi-
	 * casts on those interfaces.
	 * The ip_multirt_apply_membership() succeeds if
	 * the operation succeeds on at least one interface.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&v6group)) {
		ipaddr_t group;

		IN6_V4MAPPED_TO_IPADDR(&v6group, group);

		ire = ire_ftable_lookup_v4(group, IP_HOST_MASK, 0,
		    IRE_HOST | IRE_INTERFACE, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_MASK | MATCH_IRE_TYPE, 0, ipst, NULL);
	} else {
		ire = ire_ftable_lookup_v6(&v6group, &ipv6_all_ones, 0,
		    IRE_HOST | IRE_INTERFACE, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_MASK | MATCH_IRE_TYPE, 0, ipst, NULL);
	}
	if (ire != NULL) {
		if (ire->ire_flags & RTF_MULTIRT) {
			error = ip_multirt_apply_membership(optfn, ire, connp,
			    checkonly, &v6group, fmode, &ipv6_all_zeros);
			done = B_TRUE;
		}
		ire_refrele(ire);
	}

	if (!done) {
		error = optfn(connp, checkonly, &v6group, ifaddr, ifindex,
		    fmode, &ipv6_all_zeros);
	}
	return (error);
}

/*
 * Set socket options for joining and leaving multicast groups
 * for specific sources.
 * Common to IPv4 and IPv6; inet6 indicates the type of socket.
 * The caller has already check that the option name is consistent with
 * the address family of the socket.
 */
int
ip_opt_set_multicast_sources(conn_t *connp, t_scalar_t name,
    uchar_t *invalp, boolean_t inet6, boolean_t checkonly)
{
	int		*i1 = (int *)invalp;
	int		error = 0;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	struct ip_mreq_source *imreqp;
	struct group_source_req *gsreqp;
	in6_addr_t v6group, v6src;
	uint32_t ifindex;
	ipaddr_t ifaddr;
	boolean_t mcast_opt = B_TRUE;
	mcast_record_t fmode;
	ire_t *ire;
	boolean_t done = B_FALSE;
	int (*optfn)(conn_t *, boolean_t, const in6_addr_t *,
	    ipaddr_t, uint_t, mcast_record_t, const in6_addr_t *);

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
	default:
		ASSERT(0);
	}

	if (mcast_opt) {
		gsreqp = (struct group_source_req *)i1;
		ifindex = gsreqp->gsr_interface;
		if (gsreqp->gsr_group.ss_family == AF_INET) {
			struct sockaddr_in *s;
			s = (struct sockaddr_in *)&gsreqp->gsr_group;
			IN6_INADDR_TO_V4MAPPED(&s->sin_addr, &v6group);
			s = (struct sockaddr_in *)&gsreqp->gsr_source;
			IN6_INADDR_TO_V4MAPPED(&s->sin_addr, &v6src);
		} else {
			struct sockaddr_in6 *s6;

			if (!inet6)
				return (EINVAL);	/* Not on INET socket */

			s6 = (struct sockaddr_in6 *)&gsreqp->gsr_group;
			v6group = s6->sin6_addr;
			s6 = (struct sockaddr_in6 *)&gsreqp->gsr_source;
			v6src = s6->sin6_addr;
		}
		ifaddr = INADDR_ANY;
	} else {
		imreqp = (struct ip_mreq_source *)i1;
		IN6_INADDR_TO_V4MAPPED(&imreqp->imr_multiaddr, &v6group);
		IN6_INADDR_TO_V4MAPPED(&imreqp->imr_sourceaddr, &v6src);
		ifaddr = (ipaddr_t)imreqp->imr_interface.s_addr;
		ifindex = 0;
	}

	/*
	 * Handle src being mapped INADDR_ANY by changing it to unspecified.
	 */
	if (IN6_IS_ADDR_V4MAPPED_ANY(&v6src))
		v6src = ipv6_all_zeros;

	/*
	 * In the multirouting case, we need to replicate
	 * the request as noted in the mcast cases above.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&v6group)) {
		ipaddr_t group;

		IN6_V4MAPPED_TO_IPADDR(&v6group, group);

		ire = ire_ftable_lookup_v4(group, IP_HOST_MASK, 0,
		    IRE_HOST | IRE_INTERFACE, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_MASK | MATCH_IRE_TYPE, 0, ipst, NULL);
	} else {
		ire = ire_ftable_lookup_v6(&v6group, &ipv6_all_ones, 0,
		    IRE_HOST | IRE_INTERFACE, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_MASK | MATCH_IRE_TYPE, 0, ipst, NULL);
	}
	if (ire != NULL) {
		if (ire->ire_flags & RTF_MULTIRT) {
			error = ip_multirt_apply_membership(optfn, ire, connp,
			    checkonly, &v6group, fmode, &v6src);
			done = B_TRUE;
		}
		ire_refrele(ire);
	}
	if (!done) {
		error = optfn(connp, checkonly, &v6group, ifaddr, ifindex,
		    fmode, &v6src);
	}
	return (error);
}

/*
 * Given a destination address and a pointer to where to put the information
 * this routine fills in the mtuinfo.
 * The socket must be connected.
 * For sctp conn_faddr is the primary address.
 */
int
ip_fill_mtuinfo(conn_t *connp, ip_xmit_attr_t *ixa, struct ip6_mtuinfo *mtuinfo)
{
	uint32_t	pmtu = IP_MAXPACKET;
	uint_t		scopeid;

	if (IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6))
		return (-1);

	/* In case we never sent or called ip_set_destination_v4/v6 */
	if (ixa->ixa_ire != NULL)
		pmtu = ip_get_pmtu(ixa);

	if (ixa->ixa_flags & IXAF_SCOPEID_SET)
		scopeid = ixa->ixa_scopeid;
	else
		scopeid = 0;

	bzero(mtuinfo, sizeof (*mtuinfo));
	mtuinfo->ip6m_addr.sin6_family = AF_INET6;
	mtuinfo->ip6m_addr.sin6_port = connp->conn_fport;
	mtuinfo->ip6m_addr.sin6_addr = connp->conn_faddr_v6;
	mtuinfo->ip6m_addr.sin6_scope_id = scopeid;
	mtuinfo->ip6m_mtu = pmtu;

	return (sizeof (struct ip6_mtuinfo));
}

/*
 * When the src multihoming is changed from weak to [strong, preferred]
 * ip_ire_rebind_walker is called to walk the list of all ire_t entries
 * and identify routes that were created by user-applications in the
 * unbound state (i.e., without RTA_IFP), and for which an ire_ill is not
 * currently defined. These routes are then 'rebound', i.e., their ire_ill
 * is selected by finding an interface route for the gateway.
 */
/* ARGSUSED */
void
ip_ire_rebind_walker(ire_t *ire, void *notused)
{
	if (!ire->ire_unbound || ire->ire_ill != NULL)
		return;
	ire_rebind(ire);
	ire_delete(ire);
}

/*
 * When the src multihoming is changed from  [strong, preferred] to weak,
 * ip_ire_unbind_walker is called to walk the list of all ire_t entries, and
 * set any entries that were created by user-applications in the unbound state
 * (i.e., without RTA_IFP) back to having a NULL ire_ill.
 */
/* ARGSUSED */
void
ip_ire_unbind_walker(ire_t *ire, void *notused)
{
	ire_t *new_ire;

	if (!ire->ire_unbound || ire->ire_ill == NULL)
		return;
	if (ire->ire_ipversion == IPV6_VERSION) {
		new_ire = ire_create_v6(&ire->ire_addr_v6, &ire->ire_mask_v6,
		    &ire->ire_gateway_addr_v6, ire->ire_type, NULL,
		    ire->ire_zoneid, ire->ire_flags, NULL, ire->ire_ipst);
	} else {
		new_ire = ire_create((uchar_t *)&ire->ire_addr,
		    (uchar_t *)&ire->ire_mask,
		    (uchar_t *)&ire->ire_gateway_addr, ire->ire_type, NULL,
		    ire->ire_zoneid, ire->ire_flags, NULL, ire->ire_ipst);
	}
	if (new_ire == NULL)
		return;
	new_ire->ire_unbound = B_TRUE;
	/*
	 * The bound ire must first be deleted so that we don't return
	 * the existing one on the attempt to add the unbound new_ire.
	 */
	ire_delete(ire);
	new_ire = ire_add(new_ire);
	if (new_ire != NULL)
		ire_refrele(new_ire);
}

/*
 * When the settings of ip*_strict_src_multihoming tunables are changed,
 * all cached routes need to be recomputed. This recomputation needs to be
 * done when going from weaker to stronger modes so that the cached ire
 * for the connection does not violate the current ip*_strict_src_multihoming
 * setting. It also needs to be done when going from stronger to weaker modes,
 * so that we fall back to matching on the longest-matching-route (as opposed
 * to a shorter match that may have been selected in the strong mode
 * to satisfy src_multihoming settings).
 *
 * The cached ixa_ire entires for all conn_t entries are marked as
 * "verify" so that they will be recomputed for the next packet.
 */
void
conn_ire_revalidate(conn_t *connp, void *arg)
{
	boolean_t isv6 = (boolean_t)arg;

	if ((isv6 && connp->conn_ipversion != IPV6_VERSION) ||
	    (!isv6 && connp->conn_ipversion != IPV4_VERSION))
		return;
	connp->conn_ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
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
 * Fragmentation reassembly.  Each ILL has a hash table for
 * queuing packets undergoing reassembly for all IPIFs
 * associated with the ILL.  The hash is based on the packet
 * IP ident field.  The ILL frag hash table was allocated
 * as a timer block at the time the ILL was created.  Whenever
 * there is anything on the reassembly queue, the timer will
 * be running.  Returns the reassembled packet if reassembly completes.
 */
mblk_t *
ip_input_fragment(mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	uint32_t	frag_offset_flags;
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
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	/*
	 * Drop the fragmented as early as possible, if
	 * we don't have resource(s) to re-assemble.
	 */
	if (ipst->ips_ip_reass_queue_bytes == 0) {
		freemsg(mp);
		return (NULL);
	}

	/* Check for fragmentation offset; return if there's none */
	if ((frag_offset_flags = ntohs(ipha->ipha_fragment_offset_and_flags) &
	    (IPH_MF | IPH_OFFSET)) == 0)
		return (mp);

	/*
	 * We utilize hardware computed checksum info only for UDP since
	 * IP fragmentation is a normal occurrence for the protocol.  In
	 * addition, checksum offload support for IP fragments carrying
	 * UDP payload is commonly implemented across network adapters.
	 */
	ASSERT(ira->ira_rill != NULL);
	if (proto == IPPROTO_UDP && dohwcksum &&
	    ILL_HCKSUM_CAPABLE(ira->ira_rill) &&
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
		return (NULL);
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

	/* Handle vnic loopback of fragments */
	if (mp->b_datap->db_ref > 2)
		msg_len = 0;
	else
		msg_len = MBLKSIZE(mp);

	tail_mp = mp;
	while (tail_mp->b_cont != NULL) {
		tail_mp = tail_mp->b_cont;
		if (tail_mp->b_datap->db_ref <= 2)
			msg_len += MBLKSIZE(tail_mp);
	}

	/* If the reassembly list for this ILL will get too big, prune it */
	if ((msg_len + sizeof (*ipf) + ill->ill_frag_count) >=
	    ipst->ips_ip_reass_queue_bytes) {
		DTRACE_PROBE3(ip_reass_queue_bytes, uint_t, msg_len,
		    uint_t, ill->ill_frag_count,
		    uint_t, ipst->ips_ip_reass_queue_bytes);
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
					return (NULL);
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
			return (NULL);
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
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
reass_done:
			mutex_exit(&ipfb->ipfb_lock);
			return (NULL);
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
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		ip_drop_input("Reassembled packet too large", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	if (DB_REF(mp) > 1) {
		mblk_t *mp2 = copymsg(mp);

		if (mp2 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		freemsg(mp);
		mp = mp2;
	}
	ipha = (ipha_t *)mp->b_rptr;

	ipha->ipha_length = htons((uint16_t)packet_size);
	/* We're now complete, zip the frag state */
	ipha->ipha_fragment_offset_and_flags = 0;
	/* Record the ECN info. */
	ipha->ipha_type_of_service &= 0xFC;
	ipha->ipha_type_of_service |= ecn_info;

	/* Update the receive attributes */
	ira->ira_pktlen = packet_size;
	ira->ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);

	/* Reassembly is successful; set checksum information in packet */
	DB_CKSUM16(mp) = (uint16_t)sum_val;
	DB_CKSUMFLAGS(mp) = sum_flags;
	DB_CKSUMSTART(mp) = ira->ira_ip_hdr_length;

	return (mp);
}

/*
 * Pullup function that should be used for IP input in order to
 * ensure we do not loose the L2 source address; we need the l2 source
 * address for IP_RECVSLLA and for ndp_input.
 *
 * We return either NULL or b_rptr.
 */
void *
ip_pullup(mblk_t *mp, ssize_t len, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;

	if (ip_rput_pullups++ == 0) {
		(void) mi_strlog(ill->ill_rq, 1, SL_ERROR|SL_TRACE,
		    "ip_pullup: %s forced us to "
		    " pullup pkt, hdr len %ld, hdr addr %p",
		    ill->ill_name, len, (void *)mp->b_rptr);
	}
	if (!(ira->ira_flags & IRAF_L2SRC_SET))
		ip_setl2src(mp, ira, ira->ira_rill);
	ASSERT(ira->ira_flags & IRAF_L2SRC_SET);
	if (!pullupmsg(mp, len))
		return (NULL);
	else
		return (mp->b_rptr);
}

/*
 * Make sure ira_l2src has an address. If we don't have one fill with zeros.
 * When called from the ULP ira_rill will be NULL hence the caller has to
 * pass in the ill.
 */
/* ARGSUSED */
void
ip_setl2src(mblk_t *mp, ip_recv_attr_t *ira, ill_t *ill)
{
	const uchar_t *addr;
	int alen;

	if (ira->ira_flags & IRAF_L2SRC_SET)
		return;

	ASSERT(ill != NULL);
	alen = ill->ill_phys_addr_length;
	ASSERT(alen <= sizeof (ira->ira_l2src));
	if (ira->ira_mhip != NULL &&
	    (addr = ira->ira_mhip->mhi_saddr) != NULL) {
		bcopy(addr, ira->ira_l2src, alen);
	} else if ((ira->ira_flags & IRAF_L2SRC_LOOPBACK) &&
	    (addr = ill->ill_phys_addr) != NULL) {
		bcopy(addr, ira->ira_l2src, alen);
	} else {
		bzero(ira->ira_l2src, alen);
	}
	ira->ira_flags |= IRAF_L2SRC_SET;
}

/*
 * check ip header length and align it.
 */
mblk_t *
ip_check_and_align_header(mblk_t *mp, uint_t min_size, ip_recv_attr_t *ira)
{
	ill_t	*ill = ira->ira_ill;
	ssize_t len;

	len = MBLKL(mp);

	if (!OK_32PTR(mp->b_rptr))
		IP_STAT(ill->ill_ipst, ip_notaligned);
	else
		IP_STAT(ill->ill_ipst, ip_recv_pullup);

	/* Guard against bogus device drivers */
	if (len < 0) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	if (len == 0) {
		/* GLD sometimes sends up mblk with b_rptr == b_wptr! */
		mblk_t *mp1 = mp->b_cont;

		if (!(ira->ira_flags & IRAF_L2SRC_SET))
			ip_setl2src(mp, ira, ira->ira_rill);
		ASSERT(ira->ira_flags & IRAF_L2SRC_SET);

		freeb(mp);
		mp = mp1;
		if (mp == NULL)
			return (NULL);

		if (OK_32PTR(mp->b_rptr) && MBLKL(mp) >= min_size)
			return (mp);
	}
	if (ip_pullup(mp, min_size, ira) == NULL) {
		if (msgdsize(mp) < min_size) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
		} else {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
		}
		freemsg(mp);
		return (NULL);
	}
	return (mp);
}

/*
 * Common code for IPv4 and IPv6 to check and pullup multi-mblks
 */
mblk_t *
ip_check_length(mblk_t *mp, uchar_t *rptr, ssize_t len,	uint_t pkt_len,
    uint_t min_size, ip_recv_attr_t *ira)
{
	ill_t	*ill = ira->ira_ill;

	/*
	 * Make sure we have data length consistent
	 * with the IP header.
	 */
	if (mp->b_cont == NULL) {
		/* pkt_len is based on ipha_len, not the mblk length */
		if (pkt_len < min_size) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		if (len < 0) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		/* Drop any pad */
		mp->b_wptr = rptr + pkt_len;
	} else if ((len += msgdsize(mp->b_cont)) != 0) {
		ASSERT(pkt_len >= min_size);
		if (pkt_len < min_size) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		if (len < 0) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		/* Drop any pad */
		(void) adjmsg(mp, -len);
		/*
		 * adjmsg may have freed an mblk from the chain, hence
		 * invalidate any hw checksum here. This will force IP to
		 * calculate the checksum in sw, but only for this packet.
		 */
		DB_CKSUMFLAGS(mp) = 0;
		IP_STAT(ill->ill_ipst, ip_multimblk);
	}
	return (mp);
}

/*
 * Check that the IPv4 opt_len is consistent with the packet and pullup
 * the options.
 */
mblk_t *
ip_check_optlen(mblk_t *mp, ipha_t *ipha, uint_t opt_len, uint_t pkt_len,
    ip_recv_attr_t *ira)
{
	ill_t	*ill = ira->ira_ill;
	ssize_t len;

	/* Assume no IPv6 packets arrive over the IPv4 queue */
	if (IPH_HDR_VERSION(ipha) != IPV4_VERSION) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInWrongIPVersion);
		ip_drop_input("IPvN packet on IPv4 ill", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	if (opt_len > (15 - IP_SIMPLE_HDR_LENGTH_IN_WORDS)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
		freemsg(mp);
		return (NULL);
	}
	/*
	 * Recompute complete header length and make sure we
	 * have access to all of it.
	 */
	len = ((size_t)opt_len + IP_SIMPLE_HDR_LENGTH_IN_WORDS) << 2;
	if (len > (mp->b_wptr - mp->b_rptr)) {
		if (len > pkt_len) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		if (ip_pullup(mp, len, ira) == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return (NULL);
		}
	}
	return (mp);
}

/*
 * Returns a new ire, or the same ire, or NULL.
 * If a different IRE is returned, then it is held; the caller
 * needs to release it.
 * In no case is there any hold/release on the ire argument.
 */
ire_t *
ip_check_multihome(void *addr, ire_t *ire, ill_t *ill)
{
	ire_t		*new_ire;
	ill_t		*ire_ill;
	uint_t		ifindex;
	ip_stack_t	*ipst = ill->ill_ipst;
	boolean_t	strict_check = B_FALSE;

	/*
	 * IPMP common case: if IRE and ILL are in the same group, there's no
	 * issue (e.g. packet received on an underlying interface matched an
	 * IRE_LOCAL on its associated group interface).
	 */
	ASSERT(ire->ire_ill != NULL);
	if (IS_IN_SAME_ILLGRP(ill, ire->ire_ill))
		return (ire);

	/*
	 * Do another ire lookup here, using the ingress ill, to see if the
	 * interface is in a usesrc group.
	 * As long as the ills belong to the same group, we don't consider
	 * them to be arriving on the wrong interface. Thus, if the switch
	 * is doing inbound load spreading, we won't drop packets when the
	 * ip*_strict_dst_multihoming switch is on.
	 * We also need to check for IPIF_UNNUMBERED point2point interfaces
	 * where the local address may not be unique. In this case we were
	 * at the mercy of the initial ire lookup and the IRE_LOCAL it
	 * actually returned. The new lookup, which is more specific, should
	 * only find the IRE_LOCAL associated with the ingress ill if one
	 * exists.
	 */
	if (ire->ire_ipversion == IPV4_VERSION) {
		if (ipst->ips_ip_strict_dst_multihoming)
			strict_check = B_TRUE;
		new_ire = ire_ftable_lookup_v4(*((ipaddr_t *)addr), 0, 0,
		    IRE_LOCAL, ill, ALL_ZONES, NULL,
		    (MATCH_IRE_TYPE|MATCH_IRE_ILL), 0, ipst, NULL);
	} else {
		ASSERT(!IN6_IS_ADDR_MULTICAST((in6_addr_t *)addr));
		if (ipst->ips_ipv6_strict_dst_multihoming)
			strict_check = B_TRUE;
		new_ire = ire_ftable_lookup_v6((in6_addr_t *)addr, NULL, NULL,
		    IRE_LOCAL, ill, ALL_ZONES, NULL,
		    (MATCH_IRE_TYPE|MATCH_IRE_ILL), 0, ipst, NULL);
	}
	/*
	 * If the same ire that was returned in ip_input() is found then this
	 * is an indication that usesrc groups are in use. The packet
	 * arrived on a different ill in the group than the one associated with
	 * the destination address.  If a different ire was found then the same
	 * IP address must be hosted on multiple ills. This is possible with
	 * unnumbered point2point interfaces. We switch to use this new ire in
	 * order to have accurate interface statistics.
	 */
	if (new_ire != NULL) {
		/* Note: held in one case but not the other? Caller handles */
		if (new_ire != ire)
			return (new_ire);
		/* Unchanged */
		ire_refrele(new_ire);
		return (ire);
	}

	/*
	 * Chase pointers once and store locally.
	 */
	ASSERT(ire->ire_ill != NULL);
	ire_ill = ire->ire_ill;
	ifindex = ill->ill_usesrc_ifindex;

	/*
	 * Check if it's a legal address on the 'usesrc' interface.
	 * For IPMP data addresses the IRE_LOCAL is the upper, hence we
	 * can just check phyint_ifindex.
	 */
	if (ifindex != 0 && ifindex == ire_ill->ill_phyint->phyint_ifindex) {
		return (ire);
	}

	/*
	 * If the ip*_strict_dst_multihoming switch is on then we can
	 * only accept this packet if the interface is marked as routing.
	 */
	if (!(strict_check))
		return (ire);

	if ((ill->ill_flags & ire->ire_ill->ill_flags & ILLF_ROUTER) != 0) {
		return (ire);
	}
	return (NULL);
}

/*
 * This function is used to construct a mac_header_info_s from a
 * DL_UNITDATA_IND message.
 * The address fields in the mhi structure points into the message,
 * thus the caller can't use those fields after freeing the message.
 *
 * We determine whether the packet received is a non-unicast packet
 * and in doing so, determine whether or not it is broadcast vs multicast.
 * For it to be a broadcast packet, we must have the appropriate mblk_t
 * hanging off the ill_t.  If this is either not present or doesn't match
 * the destination mac address in the DL_UNITDATA_IND, the packet is deemed
 * to be multicast.  Thus NICs that have no broadcast address (or no
 * capability for one, such as point to point links) cannot return as
 * the packet being broadcast.
 */
void
ip_dlur_to_mhi(ill_t *ill, mblk_t *mb, struct mac_header_info_s *mhip)
{
	dl_unitdata_ind_t *ind = (dl_unitdata_ind_t *)mb->b_rptr;
	mblk_t *bmp;
	uint_t extra_offset;

	bzero(mhip, sizeof (struct mac_header_info_s));

	mhip->mhi_dsttype = MAC_ADDRTYPE_UNICAST;

	if (ill->ill_sap_length < 0)
		extra_offset = 0;
	else
		extra_offset = ill->ill_sap_length;

	mhip->mhi_daddr = (uchar_t *)ind + ind->dl_dest_addr_offset +
	    extra_offset;
	mhip->mhi_saddr = (uchar_t *)ind + ind->dl_src_addr_offset +
	    extra_offset;

	if (!ind->dl_group_address)
		return;

	/* Multicast or broadcast */
	mhip->mhi_dsttype = MAC_ADDRTYPE_MULTICAST;

	if (ind->dl_dest_addr_offset > sizeof (*ind) &&
	    ind->dl_dest_addr_offset + ind->dl_dest_addr_length < MBLKL(mb) &&
	    (bmp = ill->ill_bcast_mp) != NULL) {
		dl_unitdata_req_t *dlur;
		uint8_t *bphys_addr;

		dlur = (dl_unitdata_req_t *)bmp->b_rptr;
		bphys_addr = (uchar_t *)dlur + dlur->dl_dest_addr_offset +
		    extra_offset;

		if (bcmp(mhip->mhi_daddr, bphys_addr,
		    ind->dl_dest_addr_length) == 0)
			mhip->mhi_dsttype = MAC_ADDRTYPE_BROADCAST;
	}
}

/*
 * This function is used to construct a mac_header_info_s from a
 * M_DATA fastpath message from a DLPI driver.
 * The address fields in the mhi structure points into the message,
 * thus the caller can't use those fields after freeing the message.
 *
 * We determine whether the packet received is a non-unicast packet
 * and in doing so, determine whether or not it is broadcast vs multicast.
 * For it to be a broadcast packet, we must have the appropriate mblk_t
 * hanging off the ill_t.  If this is either not present or doesn't match
 * the destination mac address in the DL_UNITDATA_IND, the packet is deemed
 * to be multicast.  Thus NICs that have no broadcast address (or no
 * capability for one, such as point to point links) cannot return as
 * the packet being broadcast.
 */
void
ip_mdata_to_mhi(ill_t *ill, mblk_t *mp, struct mac_header_info_s *mhip)
{
	mblk_t *bmp;
	struct ether_header *pether;

	bzero(mhip, sizeof (struct mac_header_info_s));

	mhip->mhi_dsttype = MAC_ADDRTYPE_UNICAST;

	pether = (struct ether_header *)((char *)mp->b_rptr
	    - sizeof (struct ether_header));

	/*
	 * Make sure the interface is an ethernet type, since we don't
	 * know the header format for anything but Ethernet. Also make
	 * sure we are pointing correctly above db_base.
	 */
	if (ill->ill_type != IFT_ETHER)
		return;

retry:
	if ((uchar_t *)pether < mp->b_datap->db_base)
		return;

	/* Is there a VLAN tag? */
	if (ill->ill_isv6) {
		if (pether->ether_type != htons(ETHERTYPE_IPV6)) {
			pether = (struct ether_header *)((char *)pether - 4);
			goto retry;
		}
	} else {
		if (pether->ether_type != htons(ETHERTYPE_IP)) {
			pether = (struct ether_header *)((char *)pether - 4);
			goto retry;
		}
	}
	mhip->mhi_daddr = (uchar_t *)&pether->ether_dhost;
	mhip->mhi_saddr = (uchar_t *)&pether->ether_shost;

	if (!(mhip->mhi_daddr[0] & 0x01))
		return;

	/* Multicast or broadcast */
	mhip->mhi_dsttype = MAC_ADDRTYPE_MULTICAST;

	if ((bmp = ill->ill_bcast_mp) != NULL) {
		dl_unitdata_req_t *dlur;
		uint8_t *bphys_addr;
		uint_t	addrlen;

		dlur = (dl_unitdata_req_t *)bmp->b_rptr;
		addrlen = dlur->dl_dest_addr_length;
		if (ill->ill_sap_length < 0) {
			bphys_addr = (uchar_t *)dlur +
			    dlur->dl_dest_addr_offset;
			addrlen += ill->ill_sap_length;
		} else {
			bphys_addr = (uchar_t *)dlur +
			    dlur->dl_dest_addr_offset +
			    ill->ill_sap_length;
			addrlen -= ill->ill_sap_length;
		}
		if (bcmp(mhip->mhi_daddr, bphys_addr, addrlen) == 0)
			mhip->mhi_dsttype = MAC_ADDRTYPE_BROADCAST;
	}
}

/*
 * Handle anything but M_DATA messages
 * We see the DL_UNITDATA_IND which are part
 * of the data path, and also the other messages from the driver.
 */
void
ip_rput_notdata(ill_t *ill, mblk_t *mp)
{
	mblk_t		*first_mp;
	struct iocblk   *iocp;
	struct mac_header_info_s mhi;

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO: {
		if (((dl_unitdata_ind_t *)mp->b_rptr)->dl_primitive !=
		    DL_UNITDATA_IND) {
			/* Go handle anything other than data elsewhere. */
			ip_rput_dlpi(ill, mp);
			return;
		}

		first_mp = mp;
		mp = first_mp->b_cont;
		first_mp->b_cont = NULL;

		if (mp == NULL) {
			freeb(first_mp);
			return;
		}
		ip_dlur_to_mhi(ill, first_mp, &mhi);
		if (ill->ill_isv6)
			ip_input_v6(ill, NULL, mp, &mhi);
		else
			ip_input(ill, NULL, mp, &mhi);

		/* Ditch the DLPI header. */
		freeb(first_mp);
		return;
	}
	case M_IOCACK:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case DL_IOC_HDR_INFO:
			ill_fastpath_ack(ill, mp);
			return;
		default:
			putnext(ill->ill_rq, mp);
			return;
		}
		/* FALLTHRU */
	case M_ERROR:
	case M_HANGUP:
		mutex_enter(&ill->ill_lock);
		if (ill->ill_state_flags & ILL_CONDEMNED) {
			mutex_exit(&ill->ill_lock);
			freemsg(mp);
			return;
		}
		ill_refhold_locked(ill);
		mutex_exit(&ill->ill_lock);
		qwriter_ip(ill, ill->ill_rq, mp, ip_rput_other, CUR_OP,
		    B_FALSE);
		return;
	case M_CTL:
		putnext(ill->ill_rq, mp);
		return;
	case M_IOCNAK:
		ip1dbg(("got iocnak "));
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case DL_IOC_HDR_INFO:
			ip_rput_other(NULL, ill->ill_rq, mp, NULL);
			return;
		default:
			break;
		}
		/* FALLTHRU */
	default:
		putnext(ill->ill_rq, mp);
		return;
	}
}

/* Read side put procedure.  Packets coming from the wire arrive here. */
void
ip_rput(queue_t *q, mblk_t *mp)
{
	ill_t	*ill;
	union DL_primitives *dl;

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
			inet_freemsg(mp);
			return;
		}
	}
	if (DB_TYPE(mp) == M_DATA) {
		struct mac_header_info_s mhi;

		ip_mdata_to_mhi(ill, mp, &mhi);
		ip_input(ill, NULL, mp, &mhi);
	} else {
		ip_rput_notdata(ill, mp);
	}
}

/*
 * Move the information to a copy.
 */
mblk_t *
ip_fix_dbref(mblk_t *mp, ip_recv_attr_t *ira)
{
	mblk_t		*mp1;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	IP_STAT(ipst, ip_db_ref);

	/* Make sure we have ira_l2src before we loose the original mblk */
	if (!(ira->ira_flags & IRAF_L2SRC_SET))
		ip_setl2src(mp, ira, ira->ira_rill);

	mp1 = copymsg(mp);
	if (mp1 == NULL) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, ill);
		freemsg(mp);
		return (NULL);
	}
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
ip_rput_dlpi(ill_t *ill, mblk_t *mp)
{
	dl_ok_ack_t	*dloa = (dl_ok_ack_t *)mp->b_rptr;
	dl_error_ack_t	*dlea = (dl_error_ack_t *)dloa;
	queue_t		*q = ill->ill_rq;
	t_uscalar_t	prim = dloa->dl_primitive;
	t_uscalar_t	reqprim = DL_PRIM_INVAL;

	DTRACE_PROBE3(ill__dlpi, char *, "ip_rput_dlpi",
	    char *, dl_primstr(prim), ill_t *, ill);
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
 * Need to do ipsq_pending_mp_get on ioctl completion, which could
 * happen here. (along with mi_copy_done)
 */
/* ARGSUSED */
static void
ip_rput_dlpi_writer(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	dl_ok_ack_t	*dloa = (dl_ok_ack_t *)mp->b_rptr;
	dl_error_ack_t	*dlea = (dl_error_ack_t *)dloa;
	int		err = 0;
	ill_t		*ill = (ill_t *)q->q_ptr;
	ipif_t		*ipif = NULL;
	mblk_t		*mp1 = NULL;
	conn_t		*connp = NULL;
	t_uscalar_t	paddrreq;
	mblk_t		*mp_hw;
	boolean_t	success;
	boolean_t	ioctl_aborted = B_FALSE;
	boolean_t	log = B_TRUE;

	DTRACE_PROBE3(ill__dlpi, char *, "ip_rput_dlpi_writer",
	    char *, dl_primstr(dloa->dl_primitive), ill_t *, ill);

	ip1dbg(("ip_rput_dlpi_writer .."));
	ASSERT(ipsq->ipsq_xop == ill->ill_phyint->phyint_ipsq->ipsq_xop);
	ASSERT(IAM_WRITER_ILL(ill));

	ipif = ipsq->ipsq_xop->ipx_pending_ipif;
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

		DTRACE_PROBE3(ill__dlpi, char *, "ip_rput_dlpi_writer error",
		    char *, dl_primstr(dlea->dl_error_primitive),
		    ill_t *, ill);

		switch (dlea->dl_error_primitive) {
		case DL_DISABMULTI_REQ:
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
			mutex_enter(&ill->ill_lock);
			ill->ill_state_flags &= ~ILL_DOWN_IN_PROGRESS;
			mutex_exit(&ill->ill_lock);
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
				 * This might be a result of a DL_NOTE_REPLUMB
				 * notification. In that case, connp is NULL.
				 */
				if (connp != NULL)
					q = CONNP_TO_WQ(connp);

				(void) ipif_down(ipif, NULL, NULL);
				/* error is set below the switch */
			}
			break;
		case DL_ENABMULTI_REQ:
			ill_dlpi_done(ill, DL_ENABMULTI_REQ);

			if (ill->ill_dlpi_multicast_state == IDS_INPROGRESS)
				ill->ill_dlpi_multicast_state = IDS_FAILED;
			if (ill->ill_dlpi_multicast_state == IDS_FAILED) {

				printf("ip: joining multicasts failed (%d)"
				    " on %s - will use link layer "
				    "broadcasts for multicast\n",
				    dlea->dl_errno, ill->ill_name);

				/*
				 * Set up for multi_bcast; We are the
				 * writer, so ok to access ill->ill_ipif
				 * without any lock.
				 */
				mutex_enter(&ill->ill_phyint->phyint_lock);
				ill->ill_phyint->phyint_flags |=
				    PHYI_MULTI_BCAST;
				mutex_exit(&ill->ill_phyint->phyint_lock);

			}
			freemsg(mp);	/* Don't want to pass this up */
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

		if (ill->ill_ifname_pending) {
			DTRACE_PROBE2(ip__rput__dlpi__ifname__pending,
			    ill_t *, ill, mblk_t *, mp);
			break;
		}
		mutex_enter(&ill->ill_lock);
		ill->ill_dl_up = 1;
		ill->ill_state_flags &= ~ILL_DOWN_IN_PROGRESS;
		mutex_exit(&ill->ill_lock);

		if (!ioctl_aborted)
			mp1 = ipsq_pending_mp_get(ipsq, &connp);
		if (mp1 == NULL) {
			DTRACE_PROBE1(ip__rput__dlpi__no__mblk, ill_t *, ill);
			break;
		}
		/*
		 * mp1 was added by ill_dl_up(). if that is a result of
		 * a DL_NOTE_REPLUMB notification, connp could be NULL.
		 */
		if (connp != NULL)
			q = CONNP_TO_WQ(connp);
		/*
		 * We are exclusive. So nothing can change even after
		 * we get the pending mp.
		 */
		ip1dbg(("ip_rput_dlpi: bind_ack %s\n", ill->ill_name));
		DTRACE_PROBE1(ip__rput__dlpi__bind__ack, ill_t *, ill);
		ill_nic_event_dispatch(ill, 0, NE_UP, NULL, 0);

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
			 * done with NDP
			 */
			(void) ipif_resolver_up(ipif, Res_act_initial);
			if ((err = ipif_ndp_up(ipif, B_TRUE)) == 0)
				err = ipif_up_done_v6(ipif);
		} else if (ill->ill_net_type == IRE_IF_RESOLVER) {
			/*
			 * ARP and other v4 external resolvers.
			 * Leave the pending mblk intact so that
			 * the ioctl completes in ip_rput().
			 */
			if (connp != NULL)
				mutex_enter(&connp->conn_lock);
			mutex_enter(&ill->ill_lock);
			success = ipsq_pending_mp_add(connp, ipif, q, mp1, 0);
			mutex_exit(&ill->ill_lock);
			if (connp != NULL)
				mutex_exit(&connp->conn_lock);
			if (success) {
				err = ipif_resolver_up(ipif, Res_act_initial);
				if (err == EINPROGRESS) {
					freemsg(mp);
					return;
				}
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

		/*
		 * If we have a moved ipif to bring up, and everything has
		 * succeeded to this point, bring it up on the IPMP ill.
		 * Otherwise, leave it down -- the admin can try to bring it
		 * up by hand if need be.
		 */
		if (ill->ill_move_ipif != NULL) {
			if (err != 0) {
				ill->ill_move_ipif = NULL;
			} else {
				ipif = ill->ill_move_ipif;
				ill->ill_move_ipif = NULL;
				err = ipif_up(ipif, q, mp1);
				if (err == EINPROGRESS) {
					freemsg(mp);
					return;
				}
			}
		}
		break;

	case DL_NOTIFY_IND: {
		dl_notify_ind_t *notify = (dl_notify_ind_t *)mp->b_rptr;
		uint_t orig_mtu, orig_mc_mtu;

		switch (notify->dl_notification) {
		case DL_NOTE_PHYS_ADDR:
			err = ill_set_phys_addr(ill, mp);
			break;

		case DL_NOTE_REPLUMB:
			/*
			 * Directly return after calling ill_replumb().
			 * Note that we should not free mp as it is reused
			 * in the ill_replumb() function.
			 */
			err = ill_replumb(ill, mp);
			return;

		case DL_NOTE_FASTPATH_FLUSH:
			nce_flush(ill, B_FALSE);
			break;

		case DL_NOTE_SDU_SIZE:
		case DL_NOTE_SDU_SIZE2:
			/*
			 * The dce and fragmentation code can cope with
			 * this changing while packets are being sent.
			 * When packets are sent ip_output will discover
			 * a change.
			 *
			 * Change the MTU size of the interface.
			 */
			mutex_enter(&ill->ill_lock);
			orig_mtu = ill->ill_mtu;
			orig_mc_mtu = ill->ill_mc_mtu;
			switch (notify->dl_notification) {
			case DL_NOTE_SDU_SIZE:
				ill->ill_current_frag =
				    (uint_t)notify->dl_data;
				ill->ill_mc_mtu = (uint_t)notify->dl_data;
				break;
			case DL_NOTE_SDU_SIZE2:
				ill->ill_current_frag =
				    (uint_t)notify->dl_data1;
				ill->ill_mc_mtu = (uint_t)notify->dl_data2;
				break;
			}
			if (ill->ill_current_frag > ill->ill_max_frag)
				ill->ill_max_frag = ill->ill_current_frag;

			if (!(ill->ill_flags & ILLF_FIXEDMTU)) {
				ill->ill_mtu = ill->ill_current_frag;

				/*
				 * If ill_user_mtu was set (via
				 * SIOCSLIFLNKINFO), clamp ill_mtu at it.
				 */
				if (ill->ill_user_mtu != 0 &&
				    ill->ill_user_mtu < ill->ill_mtu)
					ill->ill_mtu = ill->ill_user_mtu;

				if (ill->ill_user_mtu != 0 &&
				    ill->ill_user_mtu < ill->ill_mc_mtu)
					ill->ill_mc_mtu = ill->ill_user_mtu;

				if (ill->ill_isv6) {
					if (ill->ill_mtu < IPV6_MIN_MTU)
						ill->ill_mtu = IPV6_MIN_MTU;
					if (ill->ill_mc_mtu < IPV6_MIN_MTU)
						ill->ill_mc_mtu = IPV6_MIN_MTU;
				} else {
					if (ill->ill_mtu < IP_MIN_MTU)
						ill->ill_mtu = IP_MIN_MTU;
					if (ill->ill_mc_mtu < IP_MIN_MTU)
						ill->ill_mc_mtu = IP_MIN_MTU;
				}
			} else if (ill->ill_mc_mtu > ill->ill_mtu) {
				ill->ill_mc_mtu = ill->ill_mtu;
			}

			mutex_exit(&ill->ill_lock);
			/*
			 * Make sure all dce_generation checks find out
			 * that ill_mtu/ill_mc_mtu has changed.
			 */
			if (orig_mtu != ill->ill_mtu ||
			    orig_mc_mtu != ill->ill_mc_mtu) {
				dce_increment_all_generations(ill->ill_isv6,
				    ill->ill_ipst);
			}

			/*
			 * Refresh IPMP meta-interface MTU if necessary.
			 */
			if (IS_UNDER_IPMP(ill))
				ipmp_illgrp_refresh_mtu(ill->ill_grp);
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

			if (IS_IPMP(ill)) {
				new_phyint_flags = went_up ?
				    new_phyint_flags & ~PHYI_FAILED :
				    new_phyint_flags | PHYI_FAILED;
			}

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
		case DL_NOTE_PROMISC_ON_PHYS: {
			phyint_t *phyint = ill->ill_phyint;

			mutex_enter(&phyint->phyint_lock);
			phyint->phyint_flags |= PHYI_PROMISC;
			mutex_exit(&phyint->phyint_lock);
			break;
		}
		case DL_NOTE_PROMISC_OFF_PHYS: {
			phyint_t *phyint = ill->ill_phyint;

			mutex_enter(&phyint->phyint_lock);
			phyint->phyint_flags &= ~PHYI_PROMISC;
			mutex_exit(&phyint->phyint_lock);
			break;
		}
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

		case DL_NOTE_ALLOWED_IPS:
			ill_set_allowed_ips(ill, mp);
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
		uint_t	paddrlen, paddroff;
		uint8_t	*addr;

		paddrreq = ill->ill_phys_addr_pend;
		paddrlen = ((dl_phys_addr_ack_t *)mp->b_rptr)->dl_addr_length;
		paddroff = ((dl_phys_addr_ack_t *)mp->b_rptr)->dl_addr_offset;
		addr = mp->b_rptr + paddroff;

		ill_dlpi_done(ill, DL_PHYS_ADDR_REQ);
		if (paddrreq == DL_IPV6_TOKEN) {
			/*
			 * bcopy to low-order bits of ill_token
			 *
			 * XXX Temporary hack - currently, all known tokens
			 * are 64 bits, so I'll cheat for the moment.
			 */
			bcopy(addr, &ill->ill_token.s6_addr32[2], paddrlen);
			ill->ill_token_length = paddrlen;
			break;
		} else if (paddrreq == DL_IPV6_LINK_LAYER_ADDR) {
			ASSERT(ill->ill_nd_lla_mp == NULL);
			ill_set_ndmp(ill, mp, paddroff, paddrlen);
			mp = NULL;
			break;
		} else if (paddrreq == DL_CURR_DEST_ADDR) {
			ASSERT(ill->ill_dest_addr_mp == NULL);
			ill->ill_dest_addr_mp = mp;
			ill->ill_dest_addr = addr;
			mp = NULL;
			if (ill->ill_isv6) {
				ill_setdesttoken(ill);
				ipif_setdestlinklocal(ill->ill_ipif);
			}
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
		ill->ill_phys_addr = (paddrlen == 0 ? NULL : addr);
		mp = NULL;

		/*
		 * If paddrlen or ill_phys_addr_length is zero, the DLPI
		 * provider doesn't support physical addresses.  We check both
		 * paddrlen and ill_phys_addr_length because sppp (PPP) does
		 * not have physical addresses, but historically adversises a
		 * physical address length of 0 in its DL_INFO_ACK, but 6 in
		 * its DL_PHYS_ADDR_ACK.
		 */
		if (paddrlen == 0 || ill->ill_phys_addr_length == 0) {
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

		if (ill->ill_isv6) {
			ill_setdefaulttoken(ill);
			ipif_setlinklocal(ill->ill_ipif);
		}
		break;
	}
	case DL_OK_ACK:
		ip2dbg(("DL_OK_ACK %s (0x%x)\n",
		    dl_primstr((int)dloa->dl_correct_primitive),
		    dloa->dl_correct_primitive));
		DTRACE_PROBE3(ill__dlpi, char *, "ip_rput_dlpi_writer ok",
		    char *, dl_primstr(dloa->dl_correct_primitive),
		    ill_t *, ill);

		switch (dloa->dl_correct_primitive) {
		case DL_ENABMULTI_REQ:
		case DL_DISABMULTI_REQ:
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
	if (mp1 == NULL)
		return;

	/*
	 * The operation must complete without EINPROGRESS since
	 * ipsq_pending_mp_get() has removed the mblk (mp1).  Otherwise,
	 * the operation will be stuck forever inside the IPSQ.
	 */
	ASSERT(err != EINPROGRESS);

	DTRACE_PROBE4(ipif__ioctl, char *, "ip_rput_dlpi_writer finish",
	    int, ipsq->ipsq_xop->ipx_current_ioctl, ill_t *, ill,
	    ipif_t *, NULL);

	switch (ipsq->ipsq_xop->ipx_current_ioctl) {
	case 0:
		ipsq_current_finish(ipsq);
		break;

	case SIOCSLIFNAME:
	case IF_UNITSEL: {
		ill_t *ill_other = ILL_OTHER(ill);

		/*
		 * If SIOCSLIFNAME or IF_UNITSEL is about to succeed, and the
		 * ill has a peer which is in an IPMP group, then place ill
		 * into the same group.  One catch: although ifconfig plumbs
		 * the appropriate IPMP meta-interface prior to plumbing this
		 * ill, it is possible for multiple ifconfig applications to
		 * race (or for another application to adjust plumbing), in
		 * which case the IPMP meta-interface we need will be missing.
		 * If so, kick the phyint out of the group.
		 */
		if (err == 0 && ill_other != NULL && IS_UNDER_IPMP(ill_other)) {
			ipmp_grp_t	*grp = ill->ill_phyint->phyint_grp;
			ipmp_illgrp_t	*illg;

			illg = ill->ill_isv6 ? grp->gr_v6 : grp->gr_v4;
			if (illg == NULL)
				ipmp_phyint_leave_grp(ill->ill_phyint);
			else
				ipmp_ill_join_illgrp(ill, illg);
		}

		if (ipsq->ipsq_xop->ipx_current_ioctl == IF_UNITSEL)
			ip_ioctl_finish(q, mp1, err, NO_COPYOUT, ipsq);
		else
			ip_ioctl_finish(q, mp1, err, COPYOUT, ipsq);
		break;
	}
	case SIOCLIFADDIF:
		ip_ioctl_finish(q, mp1, err, COPYOUT, ipsq);
		break;

	default:
		ip_ioctl_finish(q, mp1, err, NO_COPYOUT, ipsq);
		break;
	}
}

/*
 * ip_rput_other is called by ip_rput to handle messages modifying the global
 * state in IP.  If 'ipsq' is non-NULL, caller is writer on it.
 */
/* ARGSUSED */
void
ip_rput_other(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	ill_t		*ill = q->q_ptr;
	struct iocblk	*iocp;

	ip1dbg(("ip_rput_other "));
	if (ipsq != NULL) {
		ASSERT(IAM_WRITER_IPSQ(ipsq));
		ASSERT(ipsq->ipsq_xop ==
		    ill->ill_phyint->phyint_ipsq->ipsq_xop);
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
	case M_IOCNAK: {
		iocp = (struct iocblk *)mp->b_rptr;

		ASSERT(iocp->ioc_cmd == DL_IOC_HDR_INFO);
		/*
		 * If this was the first attempt, turn off the fastpath
		 * probing.
		 */
		mutex_enter(&ill->ill_lock);
		if (ill->ill_dlpi_fastpath_state == IDS_INPROGRESS) {
			ill->ill_dlpi_fastpath_state = IDS_FAILED;
			mutex_exit(&ill->ill_lock);
			/*
			 * don't flush the nce_t entries: we use them
			 * as an index to the ncec itself.
			 */
			ip1dbg(("ip_rput: DLPI fastpath off on interface %s\n",
			    ill->ill_name));
		} else {
			mutex_exit(&ill->ill_lock);
		}
		freemsg(mp);
		break;
	}
	default:
		ASSERT(0);
		break;
	}
}

/*
 * Update any source route, record route or timestamp options
 * When it fails it has consumed the message and BUMPed the MIB.
 */
boolean_t
ip_forward_options(mblk_t *mp, ipha_t *ipha, ill_t *dst_ill,
    ip_recv_attr_t *ira)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	ipaddr_t	ifaddr;
	uint32_t	ts;
	timestruc_t	now;
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;

	ip2dbg(("ip_forward_options\n"));
	dst = ipha->ipha_dst;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_forward_options: opt %d, len %d\n",
		    optval, opts.ipoptp_len));
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			/* Check if adminstratively disabled */
			if (!ipst->ips_ip_forward_src_routed) {
				BUMP_MIB(dst_ill->ill_ip_mib,
				    ipIfStatsForwProhibits);
				ip_drop_input("ICMP_SOURCE_ROUTE_FAILED",
				    mp, dst_ill);
				icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED,
				    ira);
				return (B_FALSE);
			}
			if (ip_type_v4(dst, ipst) != IRE_LOCAL) {
				/*
				 * Must be partial since ip_input_options
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
				    "ip_forward_options: end of SR\n"));
				break;
			}
			/* Pick a reasonable address on the outbound if */
			ASSERT(dst_ill != NULL);
			if (ip_select_source_v4(dst_ill, INADDR_ANY, dst,
			    INADDR_ANY, ALL_ZONES, ipst, &ifaddr, NULL,
			    NULL) != 0) {
				/* No source! Shouldn't happen */
				ifaddr = INADDR_ANY;
			}
			bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
			bcopy(&ifaddr, (char *)opt + off, IP_ADDR_LEN);
			ip1dbg(("ip_forward_options: next hop 0x%x\n",
			    ntohl(dst)));

			/*
			 * Check if our address is present more than
			 * once as consecutive hops in source route.
			 */
			if (ip_type_v4(dst, ipst) == IRE_LOCAL) {
				off += IP_ADDR_LEN;
				opt[IPOPT_OFFSET] += IP_ADDR_LEN;
				goto redo_srr;
			}
			ipha->ipha_dst = dst;
			opt[IPOPT_OFFSET] += IP_ADDR_LEN;
			break;
		case IPOPT_RR:
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* No more room - ignore */
				ip1dbg((
				    "ip_forward_options: end of RR\n"));
				break;
			}
			/* Pick a reasonable address on the outbound if */
			ASSERT(dst_ill != NULL);
			if (ip_select_source_v4(dst_ill, INADDR_ANY, dst,
			    INADDR_ANY, ALL_ZONES, ipst, &ifaddr, NULL,
			    NULL) != 0) {
				/* No source! Shouldn't happen */
				ifaddr = INADDR_ANY;
			}
			bcopy(&ifaddr, (char *)opt + off, IP_ADDR_LEN);
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
				if (ip_type_v4(dst, ipst) != IRE_LOCAL) {
					/* Not for us */
					break;
				}
				/* FALLTHRU */
			case IPOPT_TS_TSANDADDR:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				/*
				 * ip_*put_options should have already
				 * dropped this packet.
				 */
				cmn_err(CE_PANIC, "ip_forward_options: "
				    "unknown IT - bug in ip_input_options?\n");
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
				/* Pick a reasonable addr on the outbound if */
				ASSERT(dst_ill != NULL);
				if (ip_select_source_v4(dst_ill, INADDR_ANY,
				    dst, INADDR_ANY, ALL_ZONES, ipst, &ifaddr,
				    NULL, NULL) != 0) {
					/* No source! Shouldn't happen */
					ifaddr = INADDR_ANY;
				}
				bcopy(&ifaddr, (char *)opt + off, IP_ADDR_LEN);
				opt[IPOPT_OFFSET] += IP_ADDR_LEN;
				/* FALLTHRU */
			case IPOPT_TS_TSONLY:
				off = opt[IPOPT_OFFSET] - 1;
				/* Compute # of milliseconds since midnight */
				gethrestime(&now);
				ts = (now.tv_sec % (24 * 60 * 60)) * 1000 +
				    NSEC2MSEC(now.tv_nsec);
				bcopy(&ts, (char *)opt + off, IPOPT_TS_TIMELEN);
				opt[IPOPT_OFFSET] += IPOPT_TS_TIMELEN;
				break;
			}
			break;
		}
	}
	return (B_TRUE);
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
	ip_stack_t *ipst = ill->ill_ipst;
	time_t	timeout;

	mutex_enter(&ill->ill_lock);
	ASSERT(!ill->ill_fragtimer_executing);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		ill->ill_frag_timer_id = 0;
		mutex_exit(&ill->ill_lock);
		return;
	}
	ill->ill_fragtimer_executing = 1;
	mutex_exit(&ill->ill_lock);

	timeout = (ill->ill_isv6 ? ipst->ips_ipv6_reassembly_timeout :
	    ipst->ips_ip_reassembly_timeout);

	frag_pending = ill_frag_timeout(ill, timeout);

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
	ip_stack_t *ipst = ill->ill_ipst;
	clock_t	timeo_ms;

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
		timeo_ms = (ill->ill_isv6 ? ipst->ips_ipv6_reassembly_timeout :
		    ipst->ips_ip_reassembly_timeout) * SECONDS;

		/*
		 * The timer is neither running nor is the timeout handler
		 * executing. Post a timeout so that ill_frag_timer will be
		 * called
		 */
		ill->ill_frag_timer_id = timeout(ill_frag_timer, ill,
		    MSEC_TO_TICK(timeo_ms >> 1));
		ill->ill_fragtimer_needrestart = 0;
	}
}

/*
 * Update any source route, record route or timestamp options.
 * Check that we are at end of strict source route.
 * The options have already been checked for sanity in ip_input_options().
 */
boolean_t
ip_input_local_options(mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	ipaddr_t	ifaddr;
	uint32_t	ts;
	timestruc_t	now;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	ip2dbg(("ip_input_local_options\n"));

	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		ASSERT((opts.ipoptp_flags & IPOPTP_ERROR) == 0);
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_input_local_options: opt %d, len %d\n",
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
				ip1dbg(("ip_input_local_options: end of SR\n"));
				break;
			}
			/*
			 * This will only happen if two consecutive entries
			 * in the source route contains our address or if
			 * it is a packet with a loose source route which
			 * reaches us before consuming the whole source route
			 */
			ip1dbg(("ip_input_local_options: not end of SR\n"));
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
				    "ip_input_local_options: end of RR\n"));
				break;
			}
			/* Pick a reasonable address on the outbound if */
			if (ip_select_source_v4(ill, INADDR_ANY, ipha->ipha_dst,
			    INADDR_ANY, ALL_ZONES, ipst, &ifaddr, NULL,
			    NULL) != 0) {
				/* No source! Shouldn't happen */
				ifaddr = INADDR_ANY;
			}
			bcopy(&ifaddr, (char *)opt + off, IP_ADDR_LEN);
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
				if (ip_type_v4(dst, ipst) != IRE_LOCAL) {
					/* Not for us */
					break;
				}
				/* FALLTHRU */
			case IPOPT_TS_TSANDADDR:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				/*
				 * ip_*put_options should have already
				 * dropped this packet.
				 */
				cmn_err(CE_PANIC, "ip_input_local_options: "
				    "unknown IT - bug in ip_input_options?\n");
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
				/* Pick a reasonable addr on the outbound if */
				if (ip_select_source_v4(ill, INADDR_ANY,
				    ipha->ipha_dst, INADDR_ANY, ALL_ZONES, ipst,
				    &ifaddr, NULL, NULL) != 0) {
					/* No source! Shouldn't happen */
					ifaddr = INADDR_ANY;
				}
				bcopy(&ifaddr, (char *)opt + off, IP_ADDR_LEN);
				opt[IPOPT_OFFSET] += IP_ADDR_LEN;
				/* FALLTHRU */
			case IPOPT_TS_TSONLY:
				off = opt[IPOPT_OFFSET] - 1;
				/* Compute # of milliseconds since midnight */
				gethrestime(&now);
				ts = (now.tv_sec % (24 * 60 * 60)) * 1000 +
				    NSEC2MSEC(now.tv_nsec);
				bcopy(&ts, (char *)opt + off, IPOPT_TS_TIMELEN);
				opt[IPOPT_OFFSET] += IPOPT_TS_TIMELEN;
				break;
			}
			break;
		}
	}
	return (B_TRUE);

bad_src_route:
	/* make sure we clear any indication of a hardware checksum */
	DB_CKSUMFLAGS(mp) = 0;
	ip_drop_input("ICMP_SOURCE_ROUTE_FAILED", mp, ill);
	icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED, ira);
	return (B_FALSE);

}

/*
 * Process IP options in an inbound packet.  Always returns the nexthop.
 * Normally this is the passed in nexthop, but if there is an option
 * that effects the nexthop (such as a source route) that will be returned.
 * Sets *errorp if there is an error, in which case an ICMP error has been sent
 * and mp freed.
 */
ipaddr_t
ip_input_options(ipha_t *ipha, ipaddr_t dst, mblk_t *mp,
    ip_recv_attr_t *ira, int *errorp)
{
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	intptr_t	code = 0;
	ire_t		*ire;

	ip2dbg(("ip_input_options\n"));
	*errorp = 0;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_input_options: opt %d, len %d\n",
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
			if (ip_type_v4(dst, ipst) != IRE_LOCAL) {
				if (optval == IPOPT_SSRR) {
					ip1dbg(("ip_input_options: not next"
					    " strict source route 0x%x\n",
					    ntohl(dst)));
					code = (char *)&ipha->ipha_dst -
					    (char *)ipha;
					goto param_prob; /* RouterReq's */
				}
				ip2dbg(("ip_input_options: "
				    "not next source route 0x%x\n",
				    ntohl(dst)));
				break;
			}

			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_input_options: bad option offset\n"));
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
				ip1dbg(("ip_input_options: end of SR\n"));
				break;
			}
			bcopy((char *)opt + off, &dst, IP_ADDR_LEN);
			ip1dbg(("ip_input_options: next hop 0x%x\n",
			    ntohl(dst)));

			/*
			 * Check if our address is present more than
			 * once as consecutive hops in source route.
			 * XXX verify per-interface ip_forwarding
			 * for source route?
			 */
			if (ip_type_v4(dst, ipst) == IRE_LOCAL) {
				off += IP_ADDR_LEN;
				goto redo_srr;
			}

			if (dst == htonl(INADDR_LOOPBACK)) {
				ip1dbg(("ip_input_options: loopback addr in "
				    "source route!\n"));
				goto bad_src_route;
			}
			/*
			 * For strict: verify that dst is directly
			 * reachable.
			 */
			if (optval == IPOPT_SSRR) {
				ire = ire_ftable_lookup_v4(dst, 0, 0,
				    IRE_INTERFACE, NULL, ALL_ZONES,
				    ira->ira_tsl,
				    MATCH_IRE_TYPE | MATCH_IRE_SECATTR, 0, ipst,
				    NULL);
				if (ire == NULL) {
					ip1dbg(("ip_input_options: SSRR not "
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
				    "ip_input_options: bad option offset\n"));
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
				    "ip_input_options: bad option offset\n"));
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
		return (dst);
	}

	ip1dbg(("ip_input_options: error processing IP options."));
	code = (char *)&opt[IPOPT_OFFSET] - (char *)ipha;

param_prob:
	/* make sure we clear any indication of a hardware checksum */
	DB_CKSUMFLAGS(mp) = 0;
	ip_drop_input("ICMP_PARAM_PROBLEM", mp, ira->ira_ill);
	icmp_param_problem(mp, (uint8_t)code, ira);
	*errorp = -1;
	return (dst);

bad_src_route:
	/* make sure we clear any indication of a hardware checksum */
	DB_CKSUMFLAGS(mp) = 0;
	ip_drop_input("ICMP_SOURCE_ROUTE_FAILED", mp, ira->ira_ill);
	icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED, ira);
	*errorp = -1;
	return (dst);
}

/*
 * IP & ICMP info in >=14 msg's ...
 *  - ip fixed part (mib2_ip_t)
 *  - icmp fixed part (mib2_icmp_t)
 *  - ipAddrEntryTable (ip 20)		all IPv4 ipifs
 *  - ipRouteEntryTable (ip 21)		all IPv4 IREs
 *  - ipNetToMediaEntryTable (ip 22)	all IPv4 Neighbor Cache entries
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
 *  - ipv6NetToMediaEntry		all IPv6 Neighbor Cache entries
 *  - ipv6AddrEntry			all IPv6 ipifs
 *  - ipv6 multicast membership (ipv6_member_t)
 *  - ipv6 multicast source filtering (ipv6_grpsrc_t)
 *
 * NOTE: original mpctl is copied for msg's 2..N, since its ctl part is
 * already filled in by the caller.
 * If legacy_req is true then MIB structures needs to be truncated to their
 * legacy sizes before being returned.
 * Return value of 0 indicates that no messages were sent and caller
 * should free mpctl.
 */
int
ip_snmp_get(queue_t *q, mblk_t *mpctl, int level, boolean_t legacy_req)
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
		if ((mpctl = udp_snmp_get(q, mpctl, legacy_req)) == NULL) {
			return (1);
		}
	}

	if (level != MIB2_UDP) {
		if ((mpctl = tcp_snmp_get(q, mpctl, legacy_req)) == NULL) {
			return (1);
		}
	}

	if ((mpctl = ip_snmp_get_mib2_ip_traffic_stats(q, mpctl,
	    ipst, legacy_req)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip6(q, mpctl, ipst,
	    legacy_req)) == NULL) {
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

	if ((mpctl = ip_snmp_get_mib2_ip_addr(q, mpctl, ipst,
	    legacy_req)) == NULL) {
		return (1);
	}

	if ((mpctl = ip_snmp_get_mib2_ip6_addr(q, mpctl, ipst,
	    legacy_req)) == NULL) {
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

	mpctl = ip_snmp_get_mib2_ip_route_media(q, mpctl, level, ipst);
	if (mpctl == NULL)
		return (1);

	mpctl = ip_snmp_get_mib2_ip6_route_media(q, mpctl, level, ipst);
	if (mpctl == NULL)
		return (1);

	if ((mpctl = sctp_snmp_get_mib2(q, mpctl, sctps)) == NULL) {
		return (1);
	}
	if ((mpctl = ip_snmp_get_mib2_ip_dce(q, mpctl, ipst)) == NULL) {
		return (1);
	}
	freemsg(mpctl);
	return (1);
}

/* Get global (legacy) IPv4 statistics */
static mblk_t *
ip_snmp_get_mib2_ip(queue_t *q, mblk_t *mpctl, mib2_ipIfStatsEntry_t *ipmib,
    ip_stack_t *ipst, boolean_t legacy_req)
{
	mib2_ip_t		old_ip_mib;
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	mib2_ipAddrEntry_t	mae;

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
	    ipst->ips_ip_reassembly_timeout);
	SET_MIB(old_ip_mib.ipAddrEntrySize,
	    (legacy_req) ? LEGACY_MIB_SIZE(&mae, mib2_ipAddrEntry_t) :
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
	SET_MIB(old_ip_mib.ipDestEntrySize, sizeof (dest_cache_entry_t));

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
ip_snmp_get_mib2_ip_traffic_stats(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst,
    boolean_t legacy_req)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ill_walk_context_t	ctx;
	mblk_t			*mp_tail = NULL;
	mib2_ipIfStatsEntry_t	global_ip_mib;
	mib2_ipAddrEntry_t	mae;

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
	    (ipst->ips_ip_forwarding ? 1 : 2));
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

	bcopy(&ipst->ips_ip_mib, &global_ip_mib, sizeof (global_ip_mib));

	if (legacy_req) {
		SET_MIB(global_ip_mib.ipIfStatsAddrEntrySize,
		    LEGACY_MIB_SIZE(&mae, mib2_ipAddrEntry_t));
	}

	if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
	    (char *)&global_ip_mib, (int)sizeof (global_ip_mib))) {
		ip1dbg(("ip_snmp_get_mib2_ip_traffic_stats: "
		    "failed to allocate %u bytes\n",
		    (uint_t)sizeof (global_ip_mib)));
	}

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ill->ill_ip_mib->ipIfStatsIfIndex =
		    ill->ill_phyint->phyint_ifindex;
		SET_MIB(ill->ill_ip_mib->ipIfStatsForwarding,
		    (ipst->ips_ip_forwarding ? 1 : 2));
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

	return (ip_snmp_get_mib2_ip(q, mp2ctl, &global_ip_mib, ipst,
	    legacy_req));
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
ip_snmp_get_mib2_ip_addr(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst,
    boolean_t legacy_req)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	mblk_t			*mp_tail = NULL;
	ill_t			*ill;
	ipif_t			*ipif;
	uint_t			bitval;
	mib2_ipAddrEntry_t	mae;
	size_t			mae_size;
	zoneid_t		zoneid;
	ill_walk_context_t	ctx;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	mae_size = (legacy_req) ? LEGACY_MIB_SIZE(&mae, mib2_ipAddrEntry_t) :
	    sizeof (mib2_ipAddrEntry_t);

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
			/* Sum of count from dead IRE_LO* and our current */
			mae.ipAdEntInfo.ae_ibcnt = ipif->ipif_ib_pkt_count;
			if (ipif->ipif_ire_local != NULL) {
				mae.ipAdEntInfo.ae_ibcnt +=
				    ipif->ipif_ire_local->ire_ib_pkt_count;
			}
			mae.ipAdEntInfo.ae_obcnt = 0;
			mae.ipAdEntInfo.ae_focnt = 0;

			ipif_get_name(ipif, mae.ipAdEntIfIndex.o_bytes,
			    OCTET_LENGTH);
			mae.ipAdEntIfIndex.o_length =
			    mi_strlen(mae.ipAdEntIfIndex.o_bytes);
			mae.ipAdEntAddr = ipif->ipif_lcl_addr;
			mae.ipAdEntNetMask = ipif->ipif_net_mask;
			mae.ipAdEntInfo.ae_subnet = ipif->ipif_subnet;
			mae.ipAdEntInfo.ae_subnet_len =
			    ip_mask_to_plen(ipif->ipif_net_mask);
			mae.ipAdEntInfo.ae_src_addr = ipif->ipif_lcl_addr;
			for (bitval = 1;
			    bitval &&
			    !(bitval & ipif->ipif_brd_addr);
			    bitval <<= 1)
				noop;
			mae.ipAdEntBcastAddr = bitval;
			mae.ipAdEntReasmMaxSize = IP_MAXPACKET;
			mae.ipAdEntInfo.ae_mtu = ipif->ipif_ill->ill_mtu;
			mae.ipAdEntInfo.ae_metric  = ipif->ipif_ill->ill_metric;
			mae.ipAdEntInfo.ae_broadcast_addr =
			    ipif->ipif_brd_addr;
			mae.ipAdEntInfo.ae_pp_dst_addr =
			    ipif->ipif_pp_dst_addr;
			mae.ipAdEntInfo.ae_flags = ipif->ipif_flags |
			    ill->ill_flags | ill->ill_phyint->phyint_flags;
			mae.ipAdEntRetransmitTime =
			    ill->ill_reachable_retrans_time;

			if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
			    (char *)&mae, (int)mae_size)) {
				ip1dbg(("ip_snmp_get_mib2_ip_addr: failed to "
				    "allocate %u bytes\n", (uint_t)mae_size));
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
ip_snmp_get_mib2_ip6_addr(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst,
    boolean_t legacy_req)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	mblk_t			*mp_tail = NULL;
	ill_t			*ill;
	ipif_t			*ipif;
	mib2_ipv6AddrEntry_t	mae6;
	size_t			mae6_size;
	zoneid_t		zoneid;
	ill_walk_context_t	ctx;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	mae6_size = (legacy_req) ?
	    LEGACY_MIB_SIZE(&mae6, mib2_ipv6AddrEntry_t) :
	    sizeof (mib2_ipv6AddrEntry_t);

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
			/* Sum of count from dead IRE_LO* and our current */
			mae6.ipv6AddrInfo.ae_ibcnt = ipif->ipif_ib_pkt_count;
			if (ipif->ipif_ire_local != NULL) {
				mae6.ipv6AddrInfo.ae_ibcnt +=
				    ipif->ipif_ire_local->ire_ib_pkt_count;
			}
			mae6.ipv6AddrInfo.ae_obcnt = 0;
			mae6.ipv6AddrInfo.ae_focnt = 0;

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
			mae6.ipv6AddrInfo.ae_src_addr = ipif->ipif_v6lcl_addr;

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
			mae6.ipv6AddrInfo.ae_mtu = ipif->ipif_ill->ill_mtu;
			mae6.ipv6AddrInfo.ae_metric  =
			    ipif->ipif_ill->ill_metric;
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
			    (char *)&mae6, (int)mae6_size)) {
				ip1dbg(("ip_snmp_get_mib2_ip6_addr: failed to "
				    "allocate %u bytes\n",
				    (uint_t)mae6_size));
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
		/* Make sure the ill isn't going away. */
		if (!ill_check_and_refhold(ill))
			continue;
		rw_exit(&ipst->ips_ill_g_lock);
		rw_enter(&ill->ill_mcast_lock, RW_READER);
		for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
			if (ilm->ilm_zoneid != zoneid &&
			    ilm->ilm_zoneid != ALL_ZONES)
				continue;

			/* Is there an ipif for ilm_ifaddr? */
			for (ipif = ill->ill_ipif; ipif != NULL;
			    ipif = ipif->ipif_next) {
				if (!IPIF_IS_CONDEMNED(ipif) &&
				    ipif->ipif_lcl_addr == ilm->ilm_ifaddr &&
				    ilm->ilm_ifaddr != INADDR_ANY)
					break;
			}
			if (ipif != NULL) {
				ipif_get_name(ipif,
				    ipm.ipGroupMemberIfIndex.o_bytes,
				    OCTET_LENGTH);
			} else {
				ill_get_name(ill,
				    ipm.ipGroupMemberIfIndex.o_bytes,
				    OCTET_LENGTH);
			}
			ipm.ipGroupMemberIfIndex.o_length =
			    mi_strlen(ipm.ipGroupMemberIfIndex.o_bytes);

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
		rw_exit(&ill->ill_mcast_lock);
		ill_refrele(ill);
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
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
		/* Make sure the ill isn't going away. */
		if (!ill_check_and_refhold(ill))
			continue;
		rw_exit(&ipst->ips_ill_g_lock);
		/*
		 * Normally we don't have any members on under IPMP interfaces.
		 * We report them as a debugging aid.
		 */
		rw_enter(&ill->ill_mcast_lock, RW_READER);
		ipm6.ipv6GroupMemberIfIndex = ill->ill_phyint->phyint_ifindex;
		for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
			if (ilm->ilm_zoneid != zoneid &&
			    ilm->ilm_zoneid != ALL_ZONES)
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
		rw_exit(&ill->ill_mcast_lock);
		ill_refrele(ill);
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
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
		/* Make sure the ill isn't going away. */
		if (!ill_check_and_refhold(ill))
			continue;
		rw_exit(&ipst->ips_ill_g_lock);
		rw_enter(&ill->ill_mcast_lock, RW_READER);
		for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
			sl = ilm->ilm_filter;
			if (ilm->ilm_zoneid != zoneid &&
			    ilm->ilm_zoneid != ALL_ZONES)
				continue;
			if (SLIST_IS_EMPTY(sl))
				continue;

			/* Is there an ipif for ilm_ifaddr? */
			for (ipif = ill->ill_ipif; ipif != NULL;
			    ipif = ipif->ipif_next) {
				if (!IPIF_IS_CONDEMNED(ipif) &&
				    ipif->ipif_lcl_addr == ilm->ilm_ifaddr &&
				    ilm->ilm_ifaddr != INADDR_ANY)
					break;
			}
			if (ipif != NULL) {
				ipif_get_name(ipif,
				    ips.ipGroupSourceIfIndex.o_bytes,
				    OCTET_LENGTH);
			} else {
				ill_get_name(ill,
				    ips.ipGroupSourceIfIndex.o_bytes,
				    OCTET_LENGTH);
			}
			ips.ipGroupSourceIfIndex.o_length =
			    mi_strlen(ips.ipGroupSourceIfIndex.o_bytes);

			ips.ipGroupSourceGroup = ilm->ilm_addr;
			for (i = 0; i < sl->sl_numsrc; i++) {
				if (!IN6_IS_ADDR_V4MAPPED(&sl->sl_addr[i]))
					continue;
				IN6_V4MAPPED_TO_IPADDR(&sl->sl_addr[i],
				    ips.ipGroupSourceAddress);
				if (snmp_append_data2(mpctl->b_cont, &mp_tail,
				    (char *)&ips, (int)sizeof (ips)) == 0) {
					ip1dbg(("ip_snmp_get_mib2_ip_group_src:"
					    " failed to allocate %u bytes\n",
					    (uint_t)sizeof (ips)));
				}
			}
		}
		rw_exit(&ill->ill_mcast_lock);
		ill_refrele(ill);
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
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
		/* Make sure the ill isn't going away. */
		if (!ill_check_and_refhold(ill))
			continue;
		rw_exit(&ipst->ips_ill_g_lock);
		/*
		 * Normally we don't have any members on under IPMP interfaces.
		 * We report them as a debugging aid.
		 */
		rw_enter(&ill->ill_mcast_lock, RW_READER);
		ips6.ipv6GroupSourceIfIndex = ill->ill_phyint->phyint_ifindex;
		for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
			sl = ilm->ilm_filter;
			if (ilm->ilm_zoneid != zoneid &&
			    ilm->ilm_zoneid != ALL_ZONES)
				continue;
			if (SLIST_IS_EMPTY(sl))
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
		rw_exit(&ill->ill_mcast_lock);
		ill_refrele(ill);
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
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
ip_snmp_get_mib2_ip_route_media(queue_t *q, mblk_t *mpctl, int level,
    ip_stack_t *ipst)
{
	struct opthdr	*optp;
	mblk_t		*mp2ctl;	/* Returned */
	mblk_t		*mp3ctl;	/* nettomedia */
	mblk_t		*mp4ctl;	/* routeattrs */
	iproutedata_t	ird;
	zoneid_t	zoneid;

	/*
	 * make copies of the original message
	 *	- mp2ctl is returned unchanged to the caller for its use
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
	/*
	 * If the level has been set the special EXPER_IP_AND_ALL_IRES value,
	 * then also include ire_testhidden IREs and IRE_IF_CLONE.  This is
	 * intended a temporary solution until a proper MIB API is provided
	 * that provides complete filtering/caller-opt-in.
	 */
	if (level == EXPER_IP_AND_ALL_IRES)
		ird.ird_flags |= IRD_REPORT_ALL;

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
	ncec_walk(NULL, ip_snmp_get2_v4_media, &ird, ipst);

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
ip_snmp_get_mib2_ip6_route_media(queue_t *q, mblk_t *mpctl, int level,
    ip_stack_t *ipst)
{
	struct opthdr	*optp;
	mblk_t		*mp2ctl;	/* Returned */
	mblk_t		*mp3ctl;	/* nettomedia */
	mblk_t		*mp4ctl;	/* routeattrs */
	iproutedata_t	ird;
	zoneid_t	zoneid;

	/*
	 * make copies of the original message
	 *	- mp2ctl is returned unchanged to the caller for its use
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
	/*
	 * If the level has been set the special EXPER_IP_AND_ALL_IRES value,
	 * then also include ire_testhidden IREs and IRE_IF_CLONE.  This is
	 * intended a temporary solution until a proper MIB API is provided
	 * that provides complete filtering/caller-opt-in.
	 */
	if (level == EXPER_IP_AND_ALL_IRES)
		ird.ird_flags |= IRD_REPORT_ALL;

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
	ncec_walk(NULL, ip_snmp_get2_v6_media, &ird, ipst);

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
ip_snmp_get_mib2_ip6(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst,
    boolean_t legacy_req)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	ill_t			*ill;
	ill_walk_context_t	ctx;
	mblk_t			*mp_tail = NULL;
	mib2_ipv6AddrEntry_t	mae6;
	mib2_ipIfStatsEntry_t	*ise;
	size_t			ise_size, iae_size;

	/*
	 * Make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	/* fixed length IPv6 structure ... */

	if (legacy_req) {
		ise_size = LEGACY_MIB_SIZE(&ipst->ips_ip6_mib,
		    mib2_ipIfStatsEntry_t);
		iae_size = LEGACY_MIB_SIZE(&mae6, mib2_ipv6AddrEntry_t);
	} else {
		ise_size = sizeof (mib2_ipIfStatsEntry_t);
		iae_size = sizeof (mib2_ipv6AddrEntry_t);
	}

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = 0;
	/* Include "unknown interface" ip6_mib */
	ipst->ips_ip6_mib.ipIfStatsIPVersion = MIB2_INETADDRESSTYPE_ipv6;
	ipst->ips_ip6_mib.ipIfStatsIfIndex =
	    MIB2_UNKNOWN_INTERFACE; /* Flag to netstat */
	SET_MIB(ipst->ips_ip6_mib.ipIfStatsForwarding,
	    ipst->ips_ipv6_forwarding ? 1 : 2);
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
	    (char *)&ipst->ips_ip6_mib, (int)ise_size)) {
		ip1dbg(("ip_snmp_get_mib2_ip6: failed to allocate %u bytes\n",
		    (uint_t)ise_size));
	} else if (legacy_req) {
		/* Adjust the EntrySize fields for legacy requests. */
		ise =
		    (mib2_ipIfStatsEntry_t *)(mp_tail->b_wptr - (int)ise_size);
		SET_MIB(ise->ipIfStatsEntrySize, ise_size);
		SET_MIB(ise->ipIfStatsAddrEntrySize, iae_size);
	}

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ill->ill_ip_mib->ipIfStatsIfIndex =
		    ill->ill_phyint->phyint_ifindex;
		SET_MIB(ill->ill_ip_mib->ipIfStatsForwarding,
		    ipst->ips_ipv6_forwarding ? 1 : 2);
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
		    (char *)ill->ill_ip_mib, (int)ise_size)) {
			ip1dbg(("ip_snmp_get_mib2_ip6: failed to allocate "
			"%u bytes\n", (uint_t)ise_size));
		} else if (legacy_req) {
			/* Adjust the EntrySize fields for legacy requests. */
			ise = (mib2_ipIfStatsEntry_t *)(mp_tail->b_wptr -
			    (int)ise_size);
			SET_MIB(ise->ipIfStatsEntrySize, ise_size);
			SET_MIB(ise->ipIfStatsAddrEntrySize, iae_size);
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
	mib2_ipRouteEntry_t		*re;
	mib2_ipAttributeEntry_t		iaes;
	tsol_ire_gw_secattr_t		*attrp;
	tsol_gc_t			*gc = NULL;
	tsol_gcgrp_t			*gcgrp = NULL;
	ip_stack_t			*ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV4_VERSION);

	if (!(ird->ird_flags & IRD_REPORT_ALL)) {
		if (ire->ire_testhidden)
			return;
		if (ire->ire_type & IRE_IF_CLONE)
			return;
	}

	if ((re = kmem_zalloc(sizeof (*re), KM_NOSLEEP)) == NULL)
		return;

	if ((attrp = ire->ire_gw_secattr) != NULL) {
		mutex_enter(&attrp->igsa_lock);
		if ((gc = attrp->igsa_gc) != NULL) {
			gcgrp = gc->gc_grp;
			ASSERT(gcgrp != NULL);
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
		}
		mutex_exit(&attrp->igsa_lock);
	}
	/*
	 * Return all IRE types for route table... let caller pick and choose
	 */
	re->ipRouteDest = ire->ire_addr;
	ill = ire->ire_ill;
	re->ipRouteIfIndex.o_length = 0;
	if (ill != NULL) {
		ill_get_name(ill, re->ipRouteIfIndex.o_bytes, OCTET_LENGTH);
		re->ipRouteIfIndex.o_length =
		    mi_strlen(re->ipRouteIfIndex.o_bytes);
	}
	re->ipRouteMetric1 = -1;
	re->ipRouteMetric2 = -1;
	re->ipRouteMetric3 = -1;
	re->ipRouteMetric4 = -1;

	re->ipRouteNextHop = ire->ire_gateway_addr;
	/* indirect(4), direct(3), or invalid(2) */
	if (ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE))
		re->ipRouteType = 2;
	else if (ire->ire_type & IRE_ONLINK)
		re->ipRouteType = 3;
	else
		re->ipRouteType = 4;

	re->ipRouteProto = -1;
	re->ipRouteAge = gethrestime_sec() - ire->ire_create_time;
	re->ipRouteMask = ire->ire_mask;
	re->ipRouteMetric5 = -1;
	re->ipRouteInfo.re_max_frag = ire->ire_metrics.iulp_mtu;
	if (ire->ire_ill != NULL && re->ipRouteInfo.re_max_frag == 0)
		re->ipRouteInfo.re_max_frag = ire->ire_ill->ill_mtu;

	re->ipRouteInfo.re_frag_flag	= 0;
	re->ipRouteInfo.re_rtt		= 0;
	re->ipRouteInfo.re_src_addr	= 0;
	re->ipRouteInfo.re_ref		= ire->ire_refcnt;
	re->ipRouteInfo.re_obpkt	= ire->ire_ob_pkt_count;
	re->ipRouteInfo.re_ibpkt	= ire->ire_ib_pkt_count;
	re->ipRouteInfo.re_flags	= ire->ire_flags;

	/* Add the IRE_IF_CLONE's counters to their parent IRE_INTERFACE */
	if (ire->ire_type & IRE_INTERFACE) {
		ire_t *child;

		rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
		child = ire->ire_dep_children;
		while (child != NULL) {
			re->ipRouteInfo.re_obpkt += child->ire_ob_pkt_count;
			re->ipRouteInfo.re_ibpkt += child->ire_ib_pkt_count;
			child = child->ire_dep_sib_next;
		}
		rw_exit(&ipst->ips_ire_dep_lock);
	}

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

	if (gc != NULL) {
		iaes.iae_routeidx = ird->ird_idx;
		iaes.iae_doi = gc->gc_db->gcdb_doi;
		iaes.iae_slrange = gc->gc_db->gcdb_slrange;

		if (!snmp_append_data2(ird->ird_attrs.lp_head,
		    &ird->ird_attrs.lp_tail, (char *)&iaes, sizeof (iaes))) {
			ip1dbg(("ip_snmp_get2_v4: failed to allocate %u "
			    "bytes\n", (uint_t)sizeof (iaes)));
		}
	}

	/* bump route index for next pass */
	ird->ird_idx++;

	kmem_free(re, sizeof (*re));
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
	mib2_ipv6RouteEntry_t		*re;
	mib2_ipAttributeEntry_t		iaes;
	tsol_ire_gw_secattr_t		*attrp;
	tsol_gc_t			*gc = NULL;
	tsol_gcgrp_t			*gcgrp = NULL;
	ip_stack_t			*ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV6_VERSION);

	if (!(ird->ird_flags & IRD_REPORT_ALL)) {
		if (ire->ire_testhidden)
			return;
		if (ire->ire_type & IRE_IF_CLONE)
			return;
	}

	if ((re = kmem_zalloc(sizeof (*re), KM_NOSLEEP)) == NULL)
		return;

	if ((attrp = ire->ire_gw_secattr) != NULL) {
		mutex_enter(&attrp->igsa_lock);
		if ((gc = attrp->igsa_gc) != NULL) {
			gcgrp = gc->gc_grp;
			ASSERT(gcgrp != NULL);
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
		}
		mutex_exit(&attrp->igsa_lock);
	}
	/*
	 * Return all IRE types for route table... let caller pick and choose
	 */
	re->ipv6RouteDest = ire->ire_addr_v6;
	re->ipv6RoutePfxLength = ip_mask_to_plen_v6(&ire->ire_mask_v6);
	re->ipv6RouteIndex = 0;	/* Unique when multiple with same dest/plen */
	re->ipv6RouteIfIndex.o_length = 0;
	ill = ire->ire_ill;
	if (ill != NULL) {
		ill_get_name(ill, re->ipv6RouteIfIndex.o_bytes, OCTET_LENGTH);
		re->ipv6RouteIfIndex.o_length =
		    mi_strlen(re->ipv6RouteIfIndex.o_bytes);
	}

	ASSERT(!(ire->ire_type & IRE_BROADCAST));

	mutex_enter(&ire->ire_lock);
	re->ipv6RouteNextHop = ire->ire_gateway_addr_v6;
	mutex_exit(&ire->ire_lock);

	/* remote(4), local(3), or discard(2) */
	if (ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE))
		re->ipv6RouteType = 2;
	else if (ire->ire_type & IRE_ONLINK)
		re->ipv6RouteType = 3;
	else
		re->ipv6RouteType = 4;

	re->ipv6RouteProtocol	= -1;
	re->ipv6RoutePolicy	= 0;
	re->ipv6RouteAge	= gethrestime_sec() - ire->ire_create_time;
	re->ipv6RouteNextHopRDI	= 0;
	re->ipv6RouteWeight	= 0;
	re->ipv6RouteMetric	= 0;
	re->ipv6RouteInfo.re_max_frag = ire->ire_metrics.iulp_mtu;
	if (ire->ire_ill != NULL && re->ipv6RouteInfo.re_max_frag == 0)
		re->ipv6RouteInfo.re_max_frag = ire->ire_ill->ill_mtu;

	re->ipv6RouteInfo.re_frag_flag	= 0;
	re->ipv6RouteInfo.re_rtt	= 0;
	re->ipv6RouteInfo.re_src_addr	= ipv6_all_zeros;
	re->ipv6RouteInfo.re_obpkt	= ire->ire_ob_pkt_count;
	re->ipv6RouteInfo.re_ibpkt	= ire->ire_ib_pkt_count;
	re->ipv6RouteInfo.re_ref	= ire->ire_refcnt;
	re->ipv6RouteInfo.re_flags	= ire->ire_flags;

	/* Add the IRE_IF_CLONE's counters to their parent IRE_INTERFACE */
	if (ire->ire_type & IRE_INTERFACE) {
		ire_t *child;

		rw_enter(&ipst->ips_ire_dep_lock, RW_READER);
		child = ire->ire_dep_children;
		while (child != NULL) {
			re->ipv6RouteInfo.re_obpkt += child->ire_ob_pkt_count;
			re->ipv6RouteInfo.re_ibpkt += child->ire_ib_pkt_count;
			child = child->ire_dep_sib_next;
		}
		rw_exit(&ipst->ips_ire_dep_lock);
	}
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

	if (gc != NULL) {
		iaes.iae_routeidx = ird->ird_idx;
		iaes.iae_doi = gc->gc_db->gcdb_doi;
		iaes.iae_slrange = gc->gc_db->gcdb_slrange;

		if (!snmp_append_data2(ird->ird_attrs.lp_head,
		    &ird->ird_attrs.lp_tail, (char *)&iaes, sizeof (iaes))) {
			ip1dbg(("ip_snmp_get2_v6: failed to allocate %u "
			    "bytes\n", (uint_t)sizeof (iaes)));
		}
	}

	/* bump route index for next pass */
	ird->ird_idx++;

	kmem_free(re, sizeof (*re));
	if (gcgrp != NULL)
		rw_exit(&gcgrp->gcgrp_rwlock);
}

/*
 * ncec_walk routine to create ipv6NetToMediaEntryTable
 */
static int
ip_snmp_get2_v6_media(ncec_t *ncec, iproutedata_t *ird)
{
	ill_t				*ill;
	mib2_ipv6NetToMediaEntry_t	ntme;

	ill = ncec->ncec_ill;
	/* skip arpce entries, and loopback ncec entries */
	if (ill->ill_isv6 == B_FALSE || ill->ill_net_type == IRE_LOOPBACK)
		return (0);
	/*
	 * Neighbor cache entry attached to IRE with on-link
	 * destination.
	 * We report all IPMP groups on ncec_ill which is normally the upper.
	 */
	ntme.ipv6NetToMediaIfIndex = ill->ill_phyint->phyint_ifindex;
	ntme.ipv6NetToMediaNetAddress = ncec->ncec_addr;
	ntme.ipv6NetToMediaPhysAddress.o_length = ill->ill_phys_addr_length;
	if (ncec->ncec_lladdr != NULL) {
		bcopy(ncec->ncec_lladdr, ntme.ipv6NetToMediaPhysAddress.o_bytes,
		    ntme.ipv6NetToMediaPhysAddress.o_length);
	}
	/*
	 * Note: Returns ND_* states. Should be:
	 * reachable(1), stale(2), delay(3), probe(4),
	 * invalid(5), unknown(6)
	 */
	ntme.ipv6NetToMediaState = ncec->ncec_state;
	ntme.ipv6NetToMediaLastUpdated = 0;

	/* other(1), dynamic(2), static(3), local(4) */
	if (NCE_MYADDR(ncec)) {
		ntme.ipv6NetToMediaType = 4;
	} else if (ncec->ncec_flags & NCE_F_PUBLISH) {
		ntme.ipv6NetToMediaType = 1; /* proxy */
	} else if (ncec->ncec_flags & NCE_F_STATIC) {
		ntme.ipv6NetToMediaType = 3;
	} else if (ncec->ncec_flags & (NCE_F_MCAST|NCE_F_BCAST)) {
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

int
nce2ace(ncec_t *ncec)
{
	int flags = 0;

	if (NCE_ISREACHABLE(ncec))
		flags |= ACE_F_RESOLVED;
	if (ncec->ncec_flags & NCE_F_AUTHORITY)
		flags |= ACE_F_AUTHORITY;
	if (ncec->ncec_flags & NCE_F_PUBLISH)
		flags |= ACE_F_PUBLISH;
	if ((ncec->ncec_flags & NCE_F_NONUD) != 0)
		flags |= ACE_F_PERMANENT;
	if (NCE_MYADDR(ncec))
		flags |= (ACE_F_MYADDR | ACE_F_AUTHORITY);
	if (ncec->ncec_flags & NCE_F_UNVERIFIED)
		flags |= ACE_F_UNVERIFIED;
	if (ncec->ncec_flags & NCE_F_AUTHORITY)
		flags |= ACE_F_AUTHORITY;
	if (ncec->ncec_flags & NCE_F_DELAYED)
		flags |= ACE_F_DELAYED;
	return (flags);
}

/*
 * ncec_walk routine to create ipNetToMediaEntryTable
 */
static int
ip_snmp_get2_v4_media(ncec_t *ncec, iproutedata_t *ird)
{
	ill_t				*ill;
	mib2_ipNetToMediaEntry_t	ntme;
	const char			*name = "unknown";
	ipaddr_t			ncec_addr;

	ill = ncec->ncec_ill;
	if (ill->ill_isv6 || (ncec->ncec_flags & NCE_F_BCAST) ||
	    ill->ill_net_type == IRE_LOOPBACK)
		return (0);

	/* We report all IPMP groups on ncec_ill which is normally the upper. */
	name = ill->ill_name;
	/* Based on RFC 4293: other(1), inval(2), dyn(3), stat(4) */
	if (NCE_MYADDR(ncec)) {
		ntme.ipNetToMediaType = 4;
	} else if (ncec->ncec_flags & (NCE_F_MCAST|NCE_F_BCAST|NCE_F_PUBLISH)) {
		ntme.ipNetToMediaType = 1;
	} else {
		ntme.ipNetToMediaType = 3;
	}
	ntme.ipNetToMediaIfIndex.o_length = MIN(OCTET_LENGTH, strlen(name));
	bcopy(name, ntme.ipNetToMediaIfIndex.o_bytes,
	    ntme.ipNetToMediaIfIndex.o_length);

	IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr, ncec_addr);
	bcopy(&ncec_addr, &ntme.ipNetToMediaNetAddress, sizeof (ncec_addr));

	ntme.ipNetToMediaInfo.ntm_mask.o_length = sizeof (ipaddr_t);
	ncec_addr = INADDR_BROADCAST;
	bcopy(&ncec_addr, ntme.ipNetToMediaInfo.ntm_mask.o_bytes,
	    sizeof (ncec_addr));
	/*
	 * map all the flags to the ACE counterpart.
	 */
	ntme.ipNetToMediaInfo.ntm_flags = nce2ace(ncec);

	ntme.ipNetToMediaPhysAddress.o_length =
	    MIN(OCTET_LENGTH, ill->ill_phys_addr_length);

	if (!NCE_ISREACHABLE(ncec))
		ntme.ipNetToMediaPhysAddress.o_length = 0;
	else {
		if (ncec->ncec_lladdr != NULL) {
			bcopy(ncec->ncec_lladdr,
			    ntme.ipNetToMediaPhysAddress.o_bytes,
			    ntme.ipNetToMediaPhysAddress.o_length);
		}
	}

	if (!snmp_append_data2(ird->ird_netmedia.lp_head,
	    &ird->ird_netmedia.lp_tail, (char *)&ntme, sizeof (ntme))) {
		ip1dbg(("ip_snmp_get2_v4_media: failed to allocate %u bytes\n",
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
boolean_t
ip_source_routed(ipha_t *ipha, ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;

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
			if (ip_type_v4(dst, ipst) != IRE_LOCAL) {
				ip2dbg(("ip_source_routed: not next"
				    " source route 0x%x\n",
				    ntohl(dst)));
				return (B_FALSE);
			}
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
 * ip_unbind is called by the transports to remove a conn from
 * the fanout table.
 */
void
ip_unbind(conn_t *connp)
{

	ASSERT(!MUTEX_HELD(&connp->conn_lock));

	if (is_system_labeled() && connp->conn_anon_port) {
		(void) tsol_mlp_anon(crgetzone(connp->conn_cred),
		    connp->conn_mlp_type, connp->conn_proto,
		    ntohs(connp->conn_lport), B_FALSE);
		connp->conn_anon_port = 0;
	}
	connp->conn_mlp_type = mlptSingle;

	ipcl_hash_remove(connp);
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

	if (connp->conn_ixa->ixa_ipsec_policy == NULL)
		return (0);

	return (connp->conn_ixa->ixa_ipsec_policy->ipsp_act->ipa_ovhd);
}

/*
 * Returns an estimate of the IPsec headers size. This is used if
 * we don't want to call into IPsec to get the exact size.
 */
int
ipsec_out_extra_length(ip_xmit_attr_t *ixa)
{
	ipsec_action_t *a;

	if (!(ixa->ixa_flags & IXAF_IPSEC_SECURE))
		return (0);

	a = ixa->ixa_ipsec_action;
	if (a == NULL) {
		ASSERT(ixa->ixa_ipsec_policy != NULL);
		a = ixa->ixa_ipsec_policy->ipsp_act;
	}
	ASSERT(a != NULL);

	return (a->ipa_ovhd);
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

/*
 * Outbound IP fragmentation routine.
 * Assumes the caller has checked whether or not fragmentation should
 * be allowed. Here we copy the DF bit from the header to all the generated
 * fragments.
 */
int
ip_fragment_v4(mblk_t *mp_orig, nce_t *nce, iaflags_t ixaflags,
    uint_t pkt_len, uint32_t max_frag, uint32_t xmit_hint, zoneid_t szone,
    zoneid_t nolzid, pfirepostfrag_t postfragfn, uintptr_t *ixa_cookie)
{
	int		i1;
	int		hdr_len;
	mblk_t		*hdr_mp;
	ipha_t		*ipha;
	int		ip_data_end;
	int		len;
	mblk_t		*mp = mp_orig;
	int		offset;
	ill_t		*ill = nce->nce_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	mblk_t		*carve_mp;
	uint32_t	frag_flag;
	uint_t		priority = mp->b_band;
	int		error = 0;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragReqds);

	if (pkt_len != msgdsize(mp)) {
		ip0dbg(("Packet length mismatch: %d, %ld\n",
		    pkt_len, msgdsize(mp)));
		freemsg(mp);
		return (EINVAL);
	}

	if (max_frag == 0) {
		ip1dbg(("ip_fragment_v4: max_frag is zero. Dropping packet\n"));
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: zero max_frag", mp, ill);
		freemsg(mp);
		return (EINVAL);
	}

	ASSERT(MBLKL(mp) >= sizeof (ipha_t));
	ipha = (ipha_t *)mp->b_rptr;
	ASSERT(ntohs(ipha->ipha_length) == pkt_len);
	frag_flag = ntohs(ipha->ipha_fragment_offset_and_flags) & IPH_DF;

	/*
	 * Establish the starting offset.  May not be zero if we are fragging
	 * a fragment that is being forwarded.
	 */
	offset = ntohs(ipha->ipha_fragment_offset_and_flags) & IPH_OFFSET;

	/* TODO why is this test needed? */
	if (((max_frag - ntohs(ipha->ipha_length)) & ~7) < 8) {
		/* TODO: notify ulp somehow */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: bad starting offset", mp, ill);
		freemsg(mp);
		return (EINVAL);
	}

	hdr_len = IPH_HDR_LENGTH(ipha);
	ipha->ipha_hdr_checksum = 0;

	/*
	 * Establish the number of bytes maximum per frag, after putting
	 * in the header.
	 */
	len = (max_frag - hdr_len) & ~7;

	/* Get a copy of the header for the trailing frags */
	hdr_mp = ip_fragment_copyhdr((uchar_t *)ipha, hdr_len, offset, ipst,
	    mp);
	if (hdr_mp == NULL) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: no hdr_mp", mp, ill);
		freemsg(mp);
		return (ENOBUFS);
	}

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
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: could not carve mp", mp_orig, ill);
		freeb(hdr_mp);
		freemsg(mp_orig);
		return (ENOBUFS);
	}

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragCreates);

	error = postfragfn(mp, nce, ixaflags, i1, xmit_hint, szone, nolzid,
	    ixa_cookie);
	if (error != 0 && error != EWOULDBLOCK) {
		/* No point in sending the other fragments */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: postfragfn failed", mp_orig, ill);
		freeb(hdr_mp);
		freemsg(mp_orig);
		return (error);
	}

	/* No need to redo state machine in loop */
	ixaflags &= ~IXAF_REACH_CONF;

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
				mp->b_band = priority;
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
				mp->b_band = priority;
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

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragCreates);

		error = postfragfn(mp, nce, ixaflags, ip_len, xmit_hint, szone,
		    nolzid, ixa_cookie);
		/* All done if we just consumed the hdr_mp. */
		if (mp == hdr_mp) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragOKs);
			return (error);
		}
		if (error != 0 && error != EWOULDBLOCK) {
			DTRACE_PROBE2(ip__xmit__frag__fail, ill_t *, ill,
			    mblk_t *, hdr_mp);
			/* No point in sending the other fragments */
			break;
		}

		/* Otherwise, advance and loop. */
		offset += len;
	}
	/* Clean up following allocation failure. */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
	ip_drop_output("FragFails: loop ended", NULL, ill);
	if (mp != hdr_mp)
		freeb(hdr_mp);
	if (mp != mp_orig)
		freemsg(mp_orig);
	return (error);
}

/*
 * Copy the header plus those options which have the copy bit set
 */
static mblk_t *
ip_fragment_copyhdr(uchar_t *rptr, int hdr_len, int offset, ip_stack_t *ipst,
    mblk_t *src)
{
	mblk_t	*mp;
	uchar_t	*up;

	/*
	 * Quick check if we need to look for options without the copy bit
	 * set
	 */
	mp = allocb_tmpl(ipst->ips_ip_wroff_extra + hdr_len, src);
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
 * Update any source route, record route, or timestamp options when
 * sending a packet back to ourselves.
 * Check that we are at end of strict source route.
 * The options have been sanity checked by ip_output_options().
 */
void
ip_output_local_options(ipha_t *ipha, ip_stack_t *ipst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	uint32_t	ts;
	timestruc_t	now;

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
				    "ip_output_local_options: end of RR\n"));
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
				if (ip_type_v4(dst, ipst) != IRE_LOCAL) {
					/* Not for us */
					break;
				}
				/* FALLTHRU */
			case IPOPT_TS_TSANDADDR:
				off = IP_ADDR_LEN + IPOPT_TS_TIMELEN;
				break;
			default:
				/*
				 * ip_*put_options should have already
				 * dropped this packet.
				 */
				cmn_err(CE_PANIC, "ip_output_local_options: "
				    "unknown IT - bug in ip_output_options?\n");
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
				    NSEC2MSEC(now.tv_nsec);
				bcopy(&ts, (char *)opt + off, IPOPT_TS_TIMELEN);
				opt[IPOPT_OFFSET] += IPOPT_TS_TIMELEN;
				break;
			}
			break;
		}
	}
}

/*
 * Prepend an M_DATA fastpath header, and if none present prepend a
 * DL_UNITDATA_REQ. Frees the mblk on failure.
 *
 * nce_dlur_mp and nce_fp_mp can not disappear once they have been set.
 * If there is a change to them, the nce will be deleted (condemned) and
 * a new nce_t will be created when packets are sent. Thus we need no locks
 * to access those fields.
 *
 * We preserve b_band to support IPQoS. If a DL_UNITDATA_REQ is prepended
 * we place b_band in dl_priority.dl_max.
 */
static mblk_t *
ip_xmit_attach_llhdr(mblk_t *mp, nce_t *nce)
{
	uint_t	hlen;
	mblk_t *mp1;
	uint_t	priority;
	uchar_t *rptr;

	rptr = mp->b_rptr;

	ASSERT(DB_TYPE(mp) == M_DATA);
	priority = mp->b_band;

	ASSERT(nce != NULL);
	if ((mp1 = nce->nce_fp_mp) != NULL) {
		hlen = MBLKL(mp1);
		/*
		 * Check if we have enough room to prepend fastpath
		 * header
		 */
		if (hlen != 0 && (rptr - mp->b_datap->db_base) >= hlen) {
			rptr -= hlen;
			bcopy(mp1->b_rptr, rptr, hlen);
			/*
			 * Set the b_rptr to the start of the link layer
			 * header
			 */
			mp->b_rptr = rptr;
			return (mp);
		}
		mp1 = copyb(mp1);
		if (mp1 == NULL) {
			ill_t *ill = nce->nce_ill;

			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		mp1->b_band = priority;
		mp1->b_cont = mp;
		DB_CKSUMSTART(mp1) = DB_CKSUMSTART(mp);
		DB_CKSUMSTUFF(mp1) = DB_CKSUMSTUFF(mp);
		DB_CKSUMEND(mp1) = DB_CKSUMEND(mp);
		DB_CKSUMFLAGS(mp1) = DB_CKSUMFLAGS(mp);
		DB_LSOMSS(mp1) = DB_LSOMSS(mp);
		DTRACE_PROBE1(ip__xmit__copyb, (mblk_t *), mp1);
		/*
		 * XXX disable ICK_VALID and compute checksum
		 * here; can happen if nce_fp_mp changes and
		 * it can't be copied now due to insufficient
		 * space. (unlikely, fp mp can change, but it
		 * does not increase in length)
		 */
		return (mp1);
	}
	mp1 = copyb(nce->nce_dlur_mp);

	if (mp1 == NULL) {
		ill_t *ill = nce->nce_ill;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards", mp, ill);
		freemsg(mp);
		return (NULL);
	}
	mp1->b_cont = mp;
	if (priority != 0) {
		mp1->b_band = priority;
		((dl_unitdata_req_t *)(mp1->b_rptr))->dl_priority.dl_max =
		    priority;
	}
	return (mp1);
}

/*
 * Finish the outbound IPsec processing. This function is called from
 * ipsec_out_process() if the IPsec packet was processed
 * synchronously, or from {ah,esp}_kcf_callback_outbound() if it was processed
 * asynchronously.
 *
 * This is common to IPv4 and IPv6.
 */
int
ip_output_post_ipsec(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	iaflags_t	ixaflags = ixa->ixa_flags;
	uint_t		pktlen;


	/* AH/ESP don't update ixa_pktlen when they modify the packet */
	if (ixaflags & IXAF_IS_IPV4) {
		ipha_t		*ipha = (ipha_t *)mp->b_rptr;

		ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);
		pktlen = ntohs(ipha->ipha_length);
	} else {
		ip6_t		*ip6h = (ip6_t *)mp->b_rptr;

		ASSERT(IPH_HDR_VERSION(mp->b_rptr) == IPV6_VERSION);
		pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
	}

	/*
	 * We release any hard reference on the SAs here to make
	 * sure the SAs can be garbage collected. ipsr_sa has a soft reference
	 * on the SAs.
	 * If in the future we want the hard latching of the SAs in the
	 * ip_xmit_attr_t then we should remove this.
	 */
	if (ixa->ixa_ipsec_esp_sa != NULL) {
		IPSA_REFRELE(ixa->ixa_ipsec_esp_sa);
		ixa->ixa_ipsec_esp_sa = NULL;
	}
	if (ixa->ixa_ipsec_ah_sa != NULL) {
		IPSA_REFRELE(ixa->ixa_ipsec_ah_sa);
		ixa->ixa_ipsec_ah_sa = NULL;
	}

	/* Do we need to fragment? */
	if ((ixa->ixa_flags & IXAF_IPV6_ADD_FRAGHDR) ||
	    pktlen > ixa->ixa_fragsize) {
		if (ixaflags & IXAF_IS_IPV4) {
			ASSERT(!(ixa->ixa_flags & IXAF_IPV6_ADD_FRAGHDR));
			/*
			 * We check for the DF case in ipsec_out_process
			 * hence this only handles the non-DF case.
			 */
			return (ip_fragment_v4(mp, ixa->ixa_nce, ixa->ixa_flags,
			    pktlen, ixa->ixa_fragsize,
			    ixa->ixa_xmit_hint, ixa->ixa_zoneid,
			    ixa->ixa_no_loop_zoneid, ixa->ixa_postfragfn,
			    &ixa->ixa_cookie));
		} else {
			mp = ip_fraghdr_add_v6(mp, ixa->ixa_ident, ixa);
			if (mp == NULL) {
				/* MIB and ip_drop_output already done */
				return (ENOMEM);
			}
			pktlen += sizeof (ip6_frag_t);
			if (pktlen > ixa->ixa_fragsize) {
				return (ip_fragment_v6(mp, ixa->ixa_nce,
				    ixa->ixa_flags, pktlen,
				    ixa->ixa_fragsize, ixa->ixa_xmit_hint,
				    ixa->ixa_zoneid, ixa->ixa_no_loop_zoneid,
				    ixa->ixa_postfragfn, &ixa->ixa_cookie));
			}
		}
	}
	return ((ixa->ixa_postfragfn)(mp, ixa->ixa_nce, ixa->ixa_flags,
	    pktlen, ixa->ixa_xmit_hint, ixa->ixa_zoneid,
	    ixa->ixa_no_loop_zoneid, NULL));
}

/*
 * Finish the inbound IPsec processing. This function is called from
 * ipsec_out_process() if the IPsec packet was processed
 * synchronously, or from {ah,esp}_kcf_callback_outbound() if it was processed
 * asynchronously.
 *
 * This is common to IPv4 and IPv6.
 */
void
ip_input_post_ipsec(mblk_t *mp, ip_recv_attr_t *ira)
{
	iaflags_t	iraflags = ira->ira_flags;

	/* Length might have changed */
	if (iraflags & IRAF_IS_IPV4) {
		ipha_t		*ipha = (ipha_t *)mp->b_rptr;

		ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);
		ira->ira_pktlen = ntohs(ipha->ipha_length);
		ira->ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);
		ira->ira_protocol = ipha->ipha_protocol;

		ip_fanout_v4(mp, ipha, ira);
	} else {
		ip6_t		*ip6h = (ip6_t *)mp->b_rptr;
		uint8_t		*nexthdrp;

		ASSERT(IPH_HDR_VERSION(mp->b_rptr) == IPV6_VERSION);
		ira->ira_pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
		if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &ira->ira_ip_hdr_length,
		    &nexthdrp)) {
			/* Malformed packet */
			BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ira->ira_ill);
			freemsg(mp);
			return;
		}
		ira->ira_protocol = *nexthdrp;
		ip_fanout_v6(mp, ip6h, ira);
	}
}

/*
 * Select which AH & ESP SA's to use (if any) for the outbound packet.
 *
 * If this function returns B_TRUE, the requested SA's have been filled
 * into the ixa_ipsec_*_sa pointers.
 *
 * If the function returns B_FALSE, the packet has been "consumed", most
 * likely by an ACQUIRE sent up via PF_KEY to a key management daemon.
 *
 * The SA references created by the protocol-specific "select"
 * function will be released in ip_output_post_ipsec.
 */
static boolean_t
ipsec_out_select_sa(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	boolean_t need_ah_acquire = B_FALSE, need_esp_acquire = B_FALSE;
	ipsec_policy_t *pp;
	ipsec_action_t *ap;

	ASSERT(ixa->ixa_flags & IXAF_IPSEC_SECURE);
	ASSERT((ixa->ixa_ipsec_policy != NULL) ||
	    (ixa->ixa_ipsec_action != NULL));

	ap = ixa->ixa_ipsec_action;
	if (ap == NULL) {
		pp = ixa->ixa_ipsec_policy;
		ASSERT(pp != NULL);
		ap = pp->ipsp_act;
		ASSERT(ap != NULL);
	}

	/*
	 * We have an action.  now, let's select SA's.
	 * A side effect of setting ixa_ipsec_*_sa is that it will
	 * be cached in the conn_t.
	 */
	if (ap->ipa_want_esp) {
		if (ixa->ixa_ipsec_esp_sa == NULL) {
			need_esp_acquire = !ipsec_outbound_sa(mp, ixa,
			    IPPROTO_ESP);
		}
		ASSERT(need_esp_acquire || ixa->ixa_ipsec_esp_sa != NULL);
	}

	if (ap->ipa_want_ah) {
		if (ixa->ixa_ipsec_ah_sa == NULL) {
			need_ah_acquire = !ipsec_outbound_sa(mp, ixa,
			    IPPROTO_AH);
		}
		ASSERT(need_ah_acquire || ixa->ixa_ipsec_ah_sa != NULL);
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
		if (ixa->ixa_ipsec_ah_sa != NULL) {
			IPSA_REFRELE(ixa->ixa_ipsec_ah_sa);
			ixa->ixa_ipsec_ah_sa = NULL;
		}
		if (ixa->ixa_ipsec_esp_sa != NULL) {
			IPSA_REFRELE(ixa->ixa_ipsec_esp_sa);
			ixa->ixa_ipsec_esp_sa = NULL;
		}

		sadb_acquire(mp, ixa, need_ah_acquire, need_esp_acquire);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Handle IPsec output processing.
 * This function is only entered once for a given packet.
 * We try to do things synchronously, but if we need to have user-level
 * set up SAs, or ESP or AH uses asynchronous kEF, then the operation
 * will be completed
 *  - when the SAs are added in esp_add_sa_finish/ah_add_sa_finish
 *  - when asynchronous ESP is done it will do AH
 *
 * In all cases we come back in ip_output_post_ipsec() to fragment and
 * send out the packet.
 */
int
ipsec_out_process(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	ill_t		*ill = ixa->ixa_nce->nce_ill;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ipsec_stack_t	*ipss;
	ipsec_policy_t	*pp;
	ipsec_action_t	*ap;

	ASSERT(ixa->ixa_flags & IXAF_IPSEC_SECURE);

	ASSERT((ixa->ixa_ipsec_policy != NULL) ||
	    (ixa->ixa_ipsec_action != NULL));

	ipss = ipst->ips_netstack->netstack_ipsec;
	if (!ipsec_loaded(ipss)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_packet(mp, B_TRUE, ill,
		    DROPPER(ipss, ipds_ip_ipsec_not_loaded),
		    &ipss->ipsec_dropper);
		return (ENOTSUP);
	}

	ap = ixa->ixa_ipsec_action;
	if (ap == NULL) {
		pp = ixa->ixa_ipsec_policy;
		ASSERT(pp != NULL);
		ap = pp->ipsp_act;
		ASSERT(ap != NULL);
	}

	/* Handle explicit drop action and bypass. */
	switch (ap->ipa_act.ipa_type) {
	case IPSEC_ACT_DISCARD:
	case IPSEC_ACT_REJECT:
		ip_drop_packet(mp, B_FALSE, ill,
		    DROPPER(ipss, ipds_spd_explicit), &ipss->ipsec_spd_dropper);
		return (EHOSTUNREACH);	/* IPsec policy failure */
	case IPSEC_ACT_BYPASS:
		return (ip_output_post_ipsec(mp, ixa));
	}

	/*
	 * The order of processing is first insert a IP header if needed.
	 * Then insert the ESP header and then the AH header.
	 */
	if ((ixa->ixa_flags & IXAF_IS_IPV4) && ap->ipa_want_se) {
		/*
		 * First get the outer IP header before sending
		 * it to ESP.
		 */
		ipha_t *oipha, *iipha;
		mblk_t *outer_mp, *inner_mp;

		if ((outer_mp = allocb(sizeof (ipha_t), BPRI_HI)) == NULL) {
			(void) mi_strlog(ill->ill_rq, 0,
			    SL_ERROR|SL_TRACE|SL_CONSOLE,
			    "ipsec_out_process: "
			    "Self-Encapsulation failed: Out of memory\n");
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", mp, ill);
			freemsg(mp);
			return (ENOBUFS);
		}
		inner_mp = mp;
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
		mp = outer_mp;

		ixa->ixa_flags |= IXAF_IPSEC_TUNNEL;
	}

	/* If we need to wait for a SA then we can't return any errno */
	if (((ap->ipa_want_ah && (ixa->ixa_ipsec_ah_sa == NULL)) ||
	    (ap->ipa_want_esp && (ixa->ixa_ipsec_esp_sa == NULL))) &&
	    !ipsec_out_select_sa(mp, ixa))
		return (0);

	/*
	 * By now, we know what SA's to use.  Toss over to ESP & AH
	 * to do the heavy lifting.
	 */
	if (ap->ipa_want_esp) {
		ASSERT(ixa->ixa_ipsec_esp_sa != NULL);

		mp = ixa->ixa_ipsec_esp_sa->ipsa_output_func(mp, ixa);
		if (mp == NULL) {
			/*
			 * Either it failed or is pending. In the former case
			 * ipIfStatsInDiscards was increased.
			 */
			return (0);
		}
	}

	if (ap->ipa_want_ah) {
		ASSERT(ixa->ixa_ipsec_ah_sa != NULL);

		mp = ixa->ixa_ipsec_ah_sa->ipsa_output_func(mp, ixa);
		if (mp == NULL) {
			/*
			 * Either it failed or is pending. In the former case
			 * ipIfStatsInDiscards was increased.
			 */
			return (0);
		}
	}
	/*
	 * We are done with IPsec processing. Send it over
	 * the wire.
	 */
	return (ip_output_post_ipsec(mp, ixa));
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
		 * Special case where ipx_current_ipif is not set:
		 * ill_phyint_reinit merged the v4 and v6 into a single ipsq.
		 * We are here as were not able to complete the operation in
		 * ipif_set_values because we could not become exclusive on
		 * the new ipsq.
		 */
		ill_t *ill = q->q_ptr;
		ipsq_current_start(ipsq, ill->ill_ipif, ipip->ipi_cmd);
	}
	ASSERT(ipsq->ipsq_xop->ipx_current_ipif != NULL);

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

	err = (*ipip->ipi_func_restart)(ipsq->ipsq_xop->ipx_current_ipif, sin,
	    q, mp, ipip, mp1->b_rptr);

	DTRACE_PROBE4(ipif__ioctl, char *, "ip_reprocess_ioctl finish",
	    int, ipip->ipi_cmd,
	    ill_t *, ipsq->ipsq_xop->ipx_current_ipif->ipif_ill,
	    ipif_t *, ipsq->ipsq_xop->ipx_current_ipif);

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
	boolean_t entered_ipsq = B_FALSE;

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
		DTRACE_PROBE4(ipif__ioctl, char *, "ip_process_ioctl finish",
		    int, ipip->ipi_cmd, ill_t *, NULL, ipif_t *, NULL);
		ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), NULL);
		return;
	}

	ci.ci_ipif = NULL;
	switch (ipip->ipi_cmd_type) {
	case MISC_CMD:
	case MSFILT_CMD:
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
		extract_funcp = NULL;
		break;

	case IF_CMD:
	case LIF_CMD:
		extract_funcp = ip_extract_lifreq;
		break;

	case ARP_CMD:
	case XARP_CMD:
		extract_funcp = ip_extract_arpreq;
		break;

	default:
		ASSERT(0);
	}

	if (extract_funcp != NULL) {
		err = (*extract_funcp)(q, mp, ipip, &ci);
		if (err != 0) {
			DTRACE_PROBE4(ipif__ioctl,
			    char *, "ip_process_ioctl finish err",
			    int, ipip->ipi_cmd, ill_t *, NULL, ipif_t *, NULL);
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
		if (ci.ci_ipif != NULL) {
			DTRACE_PROBE4(ipif__ioctl,
			    char *, "ip_process_ioctl finish RD",
			    int, ipip->ipi_cmd, ill_t *, ci.ci_ipif->ipif_ill,
			    ipif_t *, ci.ci_ipif);
			ipif_refrele(ci.ci_ipif);
		} else {
			DTRACE_PROBE4(ipif__ioctl,
			    char *, "ip_process_ioctl finish RD",
			    int, ipip->ipi_cmd, ill_t *, NULL, ipif_t *, NULL);
		}
		ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), NULL);
		return;
	}

	ASSERT(ci.ci_ipif != NULL);

	/*
	 * If ipsq is non-NULL, we are already being called exclusively
	 */
	ASSERT(ipsq == NULL || IAM_WRITER_IPSQ(ipsq));
	if (ipsq == NULL) {
		ipsq = ipsq_try_enter(ci.ci_ipif, NULL, q, mp, ip_process_ioctl,
		    NEW_OP, B_TRUE);
		if (ipsq == NULL) {
			ipif_refrele(ci.ci_ipif);
			return;
		}
		entered_ipsq = B_TRUE;
	}
	/*
	 * Release the ipif so that ipif_down and friends that wait for
	 * references to go away are not misled about the current ipif_refcnt
	 * values. We are writer so we can access the ipif even after releasing
	 * the ipif.
	 */
	ipif_refrele(ci.ci_ipif);

	ipsq_current_start(ipsq, ci.ci_ipif, ipip->ipi_cmd);

	/*
	 * A return value of EINPROGRESS means the ioctl is
	 * either queued and waiting for some reason or has
	 * already completed.
	 */
	err = (*ipip->ipi_func)(ci.ci_ipif, ci.ci_sin, q, mp, ipip, ci.ci_lifr);

	DTRACE_PROBE4(ipif__ioctl, char *, "ip_process_ioctl finish WR",
	    int, ipip->ipi_cmd,
	    ill_t *, ci.ci_ipif == NULL ? NULL : ci.ci_ipif->ipif_ill,
	    ipif_t *, ci.ci_ipif);
	ip_ioctl_finish(q, mp, err, IPI2MODE(ipip), ipsq);

	if (entered_ipsq)
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
	 * The conn refhold and ioctlref placed on the conn at the start of the
	 * ioctl are released here.
	 */
	if (connp != NULL) {
		CONN_DEC_IOCTLREF(connp);
		CONN_OPER_PENDING_DONE(connp);
	}

	if (ipsq != NULL)
		ipsq_current_finish(ipsq);
}

/* Handles all non data messages */
void
ip_wput_nondata(queue_t *q, mblk_t *mp)
{
	mblk_t		*mp1;
	struct iocblk	*iocp;
	ip_ioctl_cmd_t	*ipip;
	conn_t		*connp;
	cred_t		*cr;
	char		*proto_str;

	if (CONN_Q(q))
		connp = Q_TO_CONN(q);
	else
		connp = NULL;

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
			 * The ioctl is one we recognise, but is not consumed
			 * by IP as a module and we are a module, so we drop
			 */
			goto nak;
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
			 * list. Every mp in the ipx_pending_mp list must have
			 * a refhold on the conn to resume processing. The
			 * refhold is released when the ioctl completes
			 * (whether normally or abnormally). An ioctlref is also
			 * placed on the conn to prevent TCP from removing the
			 * queue needed to send the ioctl reply back.
			 * In all cases ip_ioctl_finish is called to finish
			 * the ioctl and release the refholds.
			 */
			if (connp != NULL) {
				/* This is not a reentry */
				CONN_INC_REF(connp);
				CONN_INC_IOCTLREF(connp);
			} else {
				if (!(ipip->ipi_flags & IPI_MODOK)) {
					mi_copy_done(q, mp, EINVAL);
					return;
				}
			}

			ip_process_ioctl(NULL, q, mp, ipip);

		} else {
			mi_copyout(q, mp);
		}
		return;

	case M_IOCNAK:
		/*
		 * The only way we could get here is if a resolver didn't like
		 * an IOCTL we sent it.	 This shouldn't happen.
		 */
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "ip_wput_nondata: unexpected M_IOCNAK, ioc_cmd 0x%x",
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd);
		freemsg(mp);
		return;
	case M_IOCACK:
		/* /dev/ip shouldn't see this */
		goto nak;
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
	case M_CTL:
		break;
	case M_PROTO:
	case M_PCPROTO:
		/*
		 * The only PROTO messages we expect are SNMP-related.
		 */
		switch (((union T_primitives *)mp->b_rptr)->type) {
		case T_SVR4_OPTMGMT_REQ:
			ip2dbg(("ip_wput_nondata: T_SVR4_OPTMGMT_REQ "
			    "flags %x\n",
			    ((struct T_optmgmt_req *)mp->b_rptr)->MGMT_flags));

			if (connp == NULL) {
				proto_str = "T_SVR4_OPTMGMT_REQ";
				goto protonak;
			}

			/*
			 * All Solaris components should pass a db_credp
			 * for this TPI message, hence we ASSERT.
			 * But in case there is some other M_PROTO that looks
			 * like a TPI message sent by some other kernel
			 * component, we check and return an error.
			 */
			cr = msg_getcred(mp, NULL);
			ASSERT(cr != NULL);
			if (cr == NULL) {
				mp = mi_tpi_err_ack_alloc(mp, TSYSERR, EINVAL);
				if (mp != NULL)
					qreply(q, mp);
				return;
			}

			if (!snmpcom_req(q, mp, ip_snmp_set, ip_snmp_get, cr)) {
				proto_str = "Bad SNMPCOM request?";
				goto protonak;
			}
			return;
		default:
			ip1dbg(("ip_wput_nondata: dropping M_PROTO prim %u\n",
			    (int)*(uint_t *)mp->b_rptr));
			freemsg(mp);
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

nak:
	iocp->ioc_error = EINVAL;
	mp->b_datap->db_type = M_IOCNAK;
	iocp->ioc_count = 0;
	qreply(q, mp);
	return;

protonak:
	cmn_err(CE_NOTE, "IP doesn't process %s as a module", proto_str);
	if ((mp = mi_tpi_err_ack_alloc(mp, TPROTO, EINVAL)) != NULL)
		qreply(q, mp);
}

/*
 * Process IP options in an outbound packet.  Verify that the nexthop in a
 * strict source route is onlink.
 * Returns non-zero if something fails in which case an ICMP error has been
 * sent and mp freed.
 *
 * Assumes the ULP has called ip_massage_options to move nexthop into ipha_dst.
 */
int
ip_output_options(mblk_t *mp, ipha_t *ipha, ip_xmit_attr_t *ixa, ill_t *ill)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	ipaddr_t	dst;
	intptr_t	code = 0;
	ire_t		*ire;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ip_recv_attr_t	iras;

	ip2dbg(("ip_output_options\n"));

	dst = ipha->ipha_dst;
	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		ip2dbg(("ip_output_options: opt %d, len %d\n",
		    optval, optlen));
		switch (optval) {
			uint32_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				ip1dbg((
				    "ip_output_options: bad option offset\n"));
				code = (char *)&opt[IPOPT_OLEN] -
				    (char *)ipha;
				goto param_prob;
			}
			off = opt[IPOPT_OFFSET];
			ip1dbg(("ip_output_options: next hop 0x%x\n",
			    ntohl(dst)));
			/*
			 * For strict: verify that dst is directly
			 * reachable.
			 */
			if (optval == IPOPT_SSRR) {
				ire = ire_ftable_lookup_v4(dst, 0, 0,
				    IRE_INTERFACE, NULL, ALL_ZONES,
				    ixa->ixa_tsl,
				    MATCH_IRE_TYPE | MATCH_IRE_SECATTR, 0, ipst,
				    NULL);
				if (ire == NULL) {
					ip1dbg(("ip_output_options: SSRR not"
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
				    "ip_output_options: bad option offset\n"));
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
				    "ip_output_options: bad option offset\n"));
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

	ip1dbg(("ip_output_options: error processing IP options."));
	code = (char *)&opt[IPOPT_OFFSET] - (char *)ipha;

param_prob:
	bzero(&iras, sizeof (iras));
	iras.ira_ill = iras.ira_rill = ill;
	iras.ira_ruifindex = ill->ill_phyint->phyint_ifindex;
	iras.ira_rifindex = iras.ira_ruifindex;
	iras.ira_flags = IRAF_IS_IPV4;

	ip_drop_output("ip_output_options", mp, ill);
	icmp_param_problem(mp, (uint8_t)code, &iras);
	ASSERT(!(iras.ira_flags & IRAF_IPSEC_SECURE));
	return (-1);

bad_src_route:
	bzero(&iras, sizeof (iras));
	iras.ira_ill = iras.ira_rill = ill;
	iras.ira_ruifindex = ill->ill_phyint->phyint_ifindex;
	iras.ira_rifindex = iras.ira_ruifindex;
	iras.ira_flags = IRAF_IS_IPV4;

	ip_drop_input("ICMP_SOURCE_ROUTE_FAILED", mp, ill);
	icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED, &iras);
	ASSERT(!(iras.ira_flags & IRAF_IPSEC_SECURE));
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
	int i, j;
	idl_tx_list_t *itl_tx;

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

	ipst->ips_idl_tx_list =
	    kmem_zalloc(TX_FANOUT_SIZE * sizeof (idl_tx_list_t), KM_SLEEP);
	for (i = 0; i < TX_FANOUT_SIZE; i++) {
		itl_tx =  &ipst->ips_idl_tx_list[i];
		itl_tx->txl_drain_list =
		    kmem_zalloc(ipst->ips_conn_drain_list_cnt *
		    sizeof (idl_t), KM_SLEEP);
		mutex_init(&itl_tx->txl_lock, NULL, MUTEX_DEFAULT, NULL);
		for (j = 0; j < ipst->ips_conn_drain_list_cnt; j++) {
			mutex_init(&itl_tx->txl_drain_list[j].idl_lock, NULL,
			    MUTEX_DEFAULT, NULL);
			itl_tx->txl_drain_list[j].idl_itl = itl_tx;
		}
	}
}

static void
conn_drain_fini(ip_stack_t *ipst)
{
	int i;
	idl_tx_list_t *itl_tx;

	for (i = 0; i < TX_FANOUT_SIZE; i++) {
		itl_tx =  &ipst->ips_idl_tx_list[i];
		kmem_free(itl_tx->txl_drain_list,
		    ipst->ips_conn_drain_list_cnt * sizeof (idl_t));
	}
	kmem_free(ipst->ips_idl_tx_list,
	    TX_FANOUT_SIZE * sizeof (idl_tx_list_t));
	ipst->ips_idl_tx_list = NULL;
}

/*
 * Flow control has blocked us from proceeding.  Insert the given conn in one
 * of the conn drain lists.  When flow control is unblocked, either ip_wsrv()
 * (STREAMS) or ill_flow_enable() (direct) will be called back, which in turn
 * will call conn_walk_drain().  See the flow control notes at the top of this
 * file for more details.
 */
void
conn_drain_insert(conn_t *connp, idl_tx_list_t *tx_list)
{
	idl_t	*idl = tx_list->txl_drain_list;
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
		index = tx_list->txl_drain_index;
		ASSERT(index < ipst->ips_conn_drain_list_cnt);
		connp->conn_idl = &tx_list->txl_drain_list[index];
		index++;
		if (index == ipst->ips_conn_drain_list_cnt)
			index = 0;
		tx_list->txl_drain_index = index;
	} else {
		ASSERT(connp->conn_idl->idl_itl == tx_list);
	}
	mutex_exit(&connp->conn_lock);

	idl = connp->conn_idl;
	mutex_enter(&idl->idl_lock);
	if ((connp->conn_drain_prev != NULL) ||
	    (connp->conn_state_flags & CONN_CLOSING)) {
		/*
		 * The conn is either already in the drain list or closing.
		 * (We needed to check for CONN_CLOSING again since close can
		 * sneak in between dropping conn_lock and acquiring idl_lock.)
		 */
		mutex_exit(&idl->idl_lock);
		return;
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
	/*
	 * For non streams based sockets assert flow control.
	 */
	conn_setqfull(connp, NULL);
	mutex_exit(&idl->idl_lock);
}

static void
conn_drain_remove(conn_t *connp)
{
	idl_t *idl = connp->conn_idl;

	if (idl != NULL) {
		/*
		 * Remove ourself from the drain list.
		 */
		if (connp->conn_drain_next == connp) {
			/* Singleton in the list */
			ASSERT(connp->conn_drain_prev == connp);
			idl->idl_conn = NULL;
		} else {
			connp->conn_drain_prev->conn_drain_next =
			    connp->conn_drain_next;
			connp->conn_drain_next->conn_drain_prev =
			    connp->conn_drain_prev;
			if (idl->idl_conn == connp)
				idl->idl_conn = connp->conn_drain_next;
		}

		/*
		 * NOTE: because conn_idl is associated with a specific drain
		 * list which in turn is tied to the index the TX ring
		 * (txl_cookie) hashes to, and because the TX ring can change
		 * over the lifetime of the conn_t, we must clear conn_idl so
		 * a subsequent conn_drain_insert() will set conn_idl again
		 * based on the latest txl_cookie.
		 */
		connp->conn_idl = NULL;
	}
	connp->conn_drain_next = NULL;
	connp->conn_drain_prev = NULL;

	conn_clrqfull(connp, NULL);
	/*
	 * For streams based sockets open up flow control.
	 */
	if (!IPCL_IS_NONSTR(connp))
		enableok(connp->conn_wq);
}

/*
 * This conn is closing, and we are called from ip_close. OR
 * this conn is draining because flow-control on the ill has been relieved.
 *
 * We must also need to remove conn's on this idl from the list, and also
 * inform the sockfs upcalls about the change in flow-control.
 */
static void
conn_drain(conn_t *connp, boolean_t closing)
{
	idl_t *idl;
	conn_t *next_connp;

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
	ASSERT(!closing || connp == NULL || connp->conn_idl != NULL);

	/*
	 * If the conn doesn't exist or is not on a drain list, bail.
	 */
	if (connp == NULL || connp->conn_idl == NULL ||
	    connp->conn_drain_prev == NULL) {
		return;
	}

	idl = connp->conn_idl;
	ASSERT(MUTEX_HELD(&idl->idl_lock));

	if (!closing) {
		next_connp = connp->conn_drain_next;
		while (next_connp != connp) {
			conn_t *delconnp = next_connp;

			next_connp = next_connp->conn_drain_next;
			conn_drain_remove(delconnp);
		}
		ASSERT(connp->conn_drain_next == idl->idl_conn);
	}
	conn_drain_remove(connp);
}

/*
 * Write service routine. Shared perimeter entry point.
 * The device queue's messages has fallen below the low water mark and STREAMS
 * has backenabled the ill_wq. Send sockfs notification about flow-control on
 * each waiting conn.
 */
void
ip_wsrv(queue_t *q)
{
	ill_t	*ill;

	ill = (ill_t *)q->q_ptr;
	if (ill->ill_state_flags == 0) {
		ip_stack_t *ipst = ill->ill_ipst;

		/*
		 * The device flow control has opened up.
		 * Walk through conn drain lists and qenable the
		 * first conn in each list. This makes sense only
		 * if the stream is fully plumbed and setup.
		 * Hence the ill_state_flags check above.
		 */
		ip1dbg(("ip_wsrv: walking\n"));
		conn_walk_drain(ipst, &ipst->ips_idl_tx_list[0]);
		enableok(ill->ill_wq);
	}
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
void
ill_flow_enable(void *arg, ip_mac_tx_cookie_t cookie)
{
	ill_t *ill = (ill_t *)arg;
	ip_stack_t *ipst = ill->ill_ipst;
	idl_tx_list_t *idl_txl;

	idl_txl = &ipst->ips_idl_tx_list[IDLHASHINDEX(cookie)];
	mutex_enter(&idl_txl->txl_lock);
	/* add code to to set a flag to indicate idl_txl is enabled */
	conn_walk_drain(ipst, idl_txl);
	mutex_exit(&idl_txl->txl_lock);
}

/*
 * Flow control has been relieved and STREAMS has backenabled us; drain
 * all the conn lists on `tx_list'.
 */
static void
conn_walk_drain(ip_stack_t *ipst, idl_tx_list_t *tx_list)
{
	int i;
	idl_t *idl;

	IP_STAT(ipst, ip_conn_walk_drain);

	for (i = 0; i < ipst->ips_conn_drain_list_cnt; i++) {
		idl = &tx_list->txl_drain_list[i];
		mutex_enter(&idl->idl_lock);
		conn_drain(idl->idl_conn, B_FALSE);
		mutex_exit(&idl->idl_lock);
	}
}

/*
 * Determine if the ill and multicast aspects of that packets
 * "matches" the conn.
 */
boolean_t
conn_wantpacket(conn_t *connp, ip_recv_attr_t *ira, ipha_t *ipha)
{
	ill_t		*ill = ira->ira_rill;
	zoneid_t	zoneid = ira->ira_zoneid;
	uint_t		in_ifindex;
	ipaddr_t	dst, src;

	dst = ipha->ipha_dst;
	src = ipha->ipha_src;

	/*
	 * conn_incoming_ifindex is set by IP_BOUND_IF which limits
	 * unicast, broadcast and multicast reception to
	 * conn_incoming_ifindex.
	 * conn_wantpacket is called for unicast, broadcast and
	 * multicast packets.
	 */
	in_ifindex = connp->conn_incoming_ifindex;

	/* mpathd can bind to the under IPMP interface, which we allow */
	if (in_ifindex != 0 && in_ifindex != ill->ill_phyint->phyint_ifindex) {
		if (!IS_UNDER_IPMP(ill))
			return (B_FALSE);

		if (in_ifindex != ipmp_ill_get_ipmp_ifindex(ill))
			return (B_FALSE);
	}

	if (!IPCL_ZONE_MATCH(connp, zoneid))
		return (B_FALSE);

	if (!(ira->ira_flags & IRAF_MULTICAST))
		return (B_TRUE);

	if (connp->conn_multi_router) {
		/* multicast packet and multicast router socket: send up */
		return (B_TRUE);
	}

	if (ipha->ipha_protocol == IPPROTO_PIM ||
	    ipha->ipha_protocol == IPPROTO_RSVP)
		return (B_TRUE);

	return (conn_hasmembers_ill_withsrc_v4(connp, dst, src, ira->ira_ill));
}

void
conn_setqfull(conn_t *connp, boolean_t *flow_stopped)
{
	if (IPCL_IS_NONSTR(connp)) {
		(*connp->conn_upcalls->su_txq_full)
		    (connp->conn_upper_handle, B_TRUE);
		if (flow_stopped != NULL)
			*flow_stopped = B_TRUE;
	} else {
		queue_t *q = connp->conn_wq;

		ASSERT(q != NULL);
		if (!(q->q_flag & QFULL)) {
			mutex_enter(QLOCK(q));
			if (!(q->q_flag & QFULL)) {
				/* still need to set QFULL */
				q->q_flag |= QFULL;
				/* set flow_stopped to true under QLOCK */
				if (flow_stopped != NULL)
					*flow_stopped = B_TRUE;
				mutex_exit(QLOCK(q));
			} else {
				/* flow_stopped is left unchanged */
				mutex_exit(QLOCK(q));
			}
		}
	}
}

void
conn_clrqfull(conn_t *connp, boolean_t *flow_stopped)
{
	if (IPCL_IS_NONSTR(connp)) {
		(*connp->conn_upcalls->su_txq_full)
		    (connp->conn_upper_handle, B_FALSE);
		if (flow_stopped != NULL)
			*flow_stopped = B_FALSE;
	} else {
		queue_t *q = connp->conn_wq;

		ASSERT(q != NULL);
		if (q->q_flag & QFULL) {
			mutex_enter(QLOCK(q));
			if (q->q_flag & QFULL) {
				q->q_flag &= ~QFULL;
				/* set flow_stopped to false under QLOCK */
				if (flow_stopped != NULL)
					*flow_stopped = B_FALSE;
				mutex_exit(QLOCK(q));
				if (q->q_flag & QWANTW)
					qbackenable(q, 0);
			} else {
				/* flow_stopped is left unchanged */
				mutex_exit(QLOCK(q));
			}
		}
	}

	mutex_enter(&connp->conn_lock);
	connp->conn_blocked = B_FALSE;
	mutex_exit(&connp->conn_lock);
}

/*
 * Return the length in bytes of the IPv4 headers (base header, label, and
 * other IP options) that will be needed based on the
 * ip_pkt_t structure passed by the caller.
 *
 * The returned length does not include the length of the upper level
 * protocol (ULP) header.
 * The caller needs to check that the length doesn't exceed the max for IPv4.
 */
int
ip_total_hdrs_len_v4(const ip_pkt_t *ipp)
{
	int len;

	len = IP_SIMPLE_HDR_LENGTH;
	if (ipp->ipp_fields & IPPF_LABEL_V4) {
		ASSERT(ipp->ipp_label_len_v4 != 0);
		/* We need to round up here */
		len += (ipp->ipp_label_len_v4 + 3) & ~3;
	}

	if (ipp->ipp_fields & IPPF_IPV4_OPTIONS) {
		ASSERT(ipp->ipp_ipv4_options_len != 0);
		ASSERT((ipp->ipp_ipv4_options_len & 3) == 0);
		len += ipp->ipp_ipv4_options_len;
	}
	return (len);
}

/*
 * All-purpose routine to build an IPv4 header with options based
 * on the abstract ip_pkt_t.
 *
 * The caller has to set the source and destination address as well as
 * ipha_length. The caller has to massage any source route and compensate
 * for the ULP pseudo-header checksum due to the source route.
 */
void
ip_build_hdrs_v4(uchar_t *buf, uint_t buf_len, const ip_pkt_t *ipp,
    uint8_t protocol)
{
	ipha_t	*ipha = (ipha_t *)buf;
	uint8_t *cp;

	/* Initialize IPv4 header */
	ipha->ipha_type_of_service = ipp->ipp_type_of_service;
	ipha->ipha_length = 0;	/* Caller will set later */
	ipha->ipha_ident = 0;
	ipha->ipha_fragment_offset_and_flags = 0;
	ipha->ipha_ttl = ipp->ipp_unicast_hops;
	ipha->ipha_protocol = protocol;
	ipha->ipha_hdr_checksum = 0;

	if ((ipp->ipp_fields & IPPF_ADDR) &&
	    IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr))
		ipha->ipha_src = ipp->ipp_addr_v4;

	cp = (uint8_t *)&ipha[1];
	if (ipp->ipp_fields & IPPF_LABEL_V4) {
		ASSERT(ipp->ipp_label_len_v4 != 0);
		bcopy(ipp->ipp_label_v4, cp, ipp->ipp_label_len_v4);
		cp += ipp->ipp_label_len_v4;
		/* We need to round up here */
		while ((uintptr_t)cp & 0x3) {
			*cp++ = IPOPT_NOP;
		}
	}

	if (ipp->ipp_fields & IPPF_IPV4_OPTIONS) {
		ASSERT(ipp->ipp_ipv4_options_len != 0);
		ASSERT((ipp->ipp_ipv4_options_len & 3) == 0);
		bcopy(ipp->ipp_ipv4_options, cp, ipp->ipp_ipv4_options_len);
		cp += ipp->ipp_ipv4_options_len;
	}
	ipha->ipha_version_and_hdr_length =
	    (uint8_t)((IP_VERSION << 4) + buf_len / 4);

	ASSERT((int)(cp - buf) == buf_len);
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
 * an action may cause the packet to be dropped, in which case we return NULL.
 * proc indicates the callout position for
 * this packet and ill is the interface this packet arrived on or will leave
 * on (inbound and outbound resp.).
 *
 * We do the processing on the rill (mapped to the upper if ipmp), but MIB
 * on the ill corrsponding to the destination IP address.
 */
mblk_t *
ip_process(ip_proc_t proc, mblk_t *mp, ill_t *rill, ill_t *ill)
{
	ip_priv_t	*priv;
	ipp_action_id_t	aid;
	int		rc = 0;
	ipp_packet_t	*pp;

	/* If the classifier is not loaded, return  */
	if ((aid = ipp_action_lookup(IPGPC_CLASSIFY)) == IPP_ACTION_INVAL) {
		return (mp);
	}

	ASSERT(mp != NULL);

	/* Allocate the packet structure */
	rc = ipp_packet_alloc(&pp, "ip", aid);
	if (rc != 0)
		goto drop;

	/* Allocate the private structure */
	rc = ip_priv_alloc((void **)&priv);
	if (rc != 0) {
		ipp_packet_free(pp);
		goto drop;
	}
	priv->proc = proc;
	priv->ill_index = ill_get_upper_ifindex(rill);

	ipp_packet_set_private(pp, priv, ip_priv_free);
	ipp_packet_set_data(pp, mp);

	/* Invoke the classifier */
	rc = ipp_packet_process(&pp);
	if (pp != NULL) {
		mp = ipp_packet_get_data(pp);
		ipp_packet_free(pp);
		if (rc != 0)
			goto drop;
		return (mp);
	} else {
		/* No mp to trace in ip_drop_input/ip_drop_output  */
		mp = NULL;
	}
drop:
	if (proc == IPP_LOCAL_IN || proc == IPP_FWD_IN) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ip_process", mp, ill);
	} else {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ip_process", mp, ill);
	}
	freemsg(mp);
	return (NULL);
}

/*
 * Propagate a multicast group membership operation (add/drop) on
 * all the interfaces crossed by the related multirt routes.
 * The call is considered successful if the operation succeeds
 * on at least one interface.
 *
 * This assumes that a set of IRE_HOST/RTF_MULTIRT has been created for the
 * multicast addresses with the ire argument being the first one.
 * We walk the bucket to find all the of those.
 *
 * Common to IPv4 and IPv6.
 */
static int
ip_multirt_apply_membership(int (*fn)(conn_t *, boolean_t,
    const in6_addr_t *, ipaddr_t, uint_t, mcast_record_t, const in6_addr_t *),
    ire_t *ire, conn_t *connp, boolean_t checkonly, const in6_addr_t *v6group,
    mcast_record_t fmode, const in6_addr_t *v6src)
{
	ire_t		*ire_gw;
	irb_t		*irb;
	int		ifindex;
	int		error = 0;
	int		result;
	ip_stack_t	*ipst = ire->ire_ipst;
	ipaddr_t	group;
	boolean_t	isv6;
	int		match_flags;

	if (IN6_IS_ADDR_V4MAPPED(v6group)) {
		IN6_V4MAPPED_TO_IPADDR(v6group, group);
		isv6 = B_FALSE;
	} else {
		isv6 = B_TRUE;
	}

	irb = ire->ire_bucket;
	ASSERT(irb != NULL);

	result = 0;
	irb_refhold(irb);
	for (; ire != NULL; ire = ire->ire_next) {
		if ((ire->ire_flags & RTF_MULTIRT) == 0)
			continue;

		/* We handle -ifp routes by matching on the ill if set */
		match_flags = MATCH_IRE_TYPE;
		if (ire->ire_ill != NULL)
			match_flags |= MATCH_IRE_ILL;

		if (isv6) {
			if (!IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, v6group))
				continue;

			ire_gw = ire_ftable_lookup_v6(&ire->ire_gateway_addr_v6,
			    0, 0, IRE_INTERFACE, ire->ire_ill, ALL_ZONES, NULL,
			    match_flags, 0, ipst, NULL);
		} else {
			if (ire->ire_addr != group)
				continue;

			ire_gw = ire_ftable_lookup_v4(ire->ire_gateway_addr,
			    0, 0, IRE_INTERFACE, ire->ire_ill, ALL_ZONES, NULL,
			    match_flags, 0, ipst, NULL);
		}
		/* No interface route exists for the gateway; skip this ire. */
		if (ire_gw == NULL)
			continue;
		if (ire_gw->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
			ire_refrele(ire_gw);
			continue;
		}
		ASSERT(ire_gw->ire_ill != NULL);	/* IRE_INTERFACE */
		ifindex = ire_gw->ire_ill->ill_phyint->phyint_ifindex;

		/*
		 * The operation is considered a success if
		 * it succeeds at least once on any one interface.
		 */
		error = fn(connp, checkonly, v6group, INADDR_ANY, ifindex,
		    fmode, v6src);
		if (error == 0)
			result = CGTP_MCAST_SUCCESS;

		ire_refrele(ire_gw);
	}
	irb_refrele(irb);
	/*
	 * Consider the call as successful if we succeeded on at least
	 * one interface. Otherwise, return the last encountered error.
	 */
	return (result == CGTP_MCAST_SUCCESS ? 0 : error);
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

	ill_set_inputfn_all(ipst);

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

	ill_set_inputfn_all(ipst);

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
	int rval;

	switch (val) {
	case IP_SQUEUE_ENTER_NODRAIN:
		rval = SQ_NODRAIN;
		break;
	case IP_SQUEUE_ENTER:
		rval = SQ_PROCESS;
		break;
	case IP_SQUEUE_FILL:
	default:
		rval = SQ_FILL;
		break;
	}
	return (rval);
}

static void *
ip_kstat2_init(netstackid_t stackid, ip_stat_t *ip_statisticsp)
{
	kstat_t *ksp;

	ip_stat_t template = {
		{ "ip_udp_fannorm", 		KSTAT_DATA_UINT64 },
		{ "ip_udp_fanmb", 		KSTAT_DATA_UINT64 },
		{ "ip_recv_pullup", 		KSTAT_DATA_UINT64 },
		{ "ip_db_ref",			KSTAT_DATA_UINT64 },
		{ "ip_notaligned",		KSTAT_DATA_UINT64 },
		{ "ip_multimblk",		KSTAT_DATA_UINT64 },
		{ "ip_opt",			KSTAT_DATA_UINT64 },
		{ "ipsec_proto_ahesp",		KSTAT_DATA_UINT64 },
		{ "ip_conn_flputbq",		KSTAT_DATA_UINT64 },
		{ "ip_conn_walk_drain",		KSTAT_DATA_UINT64 },
		{ "ip_out_sw_cksum",		KSTAT_DATA_UINT64 },
		{ "ip_out_sw_cksum_bytes",	KSTAT_DATA_UINT64 },
		{ "ip_in_sw_cksum",		KSTAT_DATA_UINT64 },
		{ "ip_ire_reclaim_calls",	KSTAT_DATA_UINT64 },
		{ "ip_ire_reclaim_deleted",	KSTAT_DATA_UINT64 },
		{ "ip_nce_reclaim_calls",	KSTAT_DATA_UINT64 },
		{ "ip_nce_reclaim_deleted",	KSTAT_DATA_UINT64 },
		{ "ip_dce_reclaim_calls",	KSTAT_DATA_UINT64 },
		{ "ip_dce_reclaim_deleted",	KSTAT_DATA_UINT64 },
		{ "ip_tcp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_tcp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_tcp_in_sw_cksum_err",		KSTAT_DATA_UINT64 },
		{ "ip_udp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_udp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip_udp_in_sw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "conn_in_recvdstaddr",	KSTAT_DATA_UINT64 },
		{ "conn_in_recvopts",		KSTAT_DATA_UINT64 },
		{ "conn_in_recvif",		KSTAT_DATA_UINT64 },
		{ "conn_in_recvslla",		KSTAT_DATA_UINT64 },
		{ "conn_in_recvucred",		KSTAT_DATA_UINT64 },
		{ "conn_in_recvttl",		KSTAT_DATA_UINT64 },
		{ "conn_in_recvhopopts",	KSTAT_DATA_UINT64 },
		{ "conn_in_recvhoplimit",	KSTAT_DATA_UINT64 },
		{ "conn_in_recvdstopts",	KSTAT_DATA_UINT64 },
		{ "conn_in_recvrthdrdstopts",	KSTAT_DATA_UINT64 },
		{ "conn_in_recvrthdr",		KSTAT_DATA_UINT64 },
		{ "conn_in_recvpktinfo",	KSTAT_DATA_UINT64 },
		{ "conn_in_recvtclass",		KSTAT_DATA_UINT64 },
		{ "conn_in_timestamp",		KSTAT_DATA_UINT64 },
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
	template.reasmTimeout.value.ui32 = ipst->ips_ip_reassembly_timeout;
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
	ipkp->reasmTimeout.value.ui32 =		ipst->ips_ip_reassembly_timeout;
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
ip_fanout_sctp_raw(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h, uint32_t ports,
    ip_recv_attr_t *ira)
{
	conn_t		*connp;
	queue_t		*rq;
	boolean_t	secure;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;
	sctp_stack_t	*sctps = ipst->ips_netstack->netstack_sctp;
	iaflags_t	iraflags = ira->ira_flags;
	ill_t		*rill = ira->ira_rill;

	secure = iraflags & IRAF_IPSEC_SECURE;

	connp = ipcl_classify_raw(mp, IPPROTO_SCTP, ports, ipha, ip6h,
	    ira, ipst);
	if (connp == NULL) {
		/*
		 * Although raw sctp is not summed, OOB chunks must be.
		 * Drop the packet here if the sctp checksum failed.
		 */
		if (iraflags & IRAF_SCTP_CSUM_ERR) {
			SCTPS_BUMP_MIB(sctps, sctpChecksumError);
			freemsg(mp);
			return;
		}
		ira->ira_ill = ira->ira_rill = NULL;
		sctp_ootb_input(mp, ira, ipst);
		ira->ira_ill = ill;
		ira->ira_rill = rill;
		return;
	}
	rq = connp->conn_rq;
	if (IPCL_IS_NONSTR(connp) ? connp->conn_flow_cntrld : !canputnext(rq)) {
		CONN_DEC_REF(connp);
		BUMP_MIB(ill->ill_ip_mib, rawipIfStatsInOverflows);
		freemsg(mp);
		return;
	}
	if (((iraflags & IRAF_IS_IPV4) ?
	    CONN_INBOUND_POLICY_PRESENT(connp, ipss) :
	    CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss)) ||
	    secure) {
		mp = ipsec_check_inbound_policy(mp, connp, ipha,
		    ip6h, ira);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			/* Note that mp is NULL */
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			CONN_DEC_REF(connp);
			return;
		}
	}

	if (iraflags & IRAF_ICMP_ERROR) {
		(connp->conn_recvicmp)(connp, mp, NULL, ira);
	} else {
		ill_t *rill = ira->ira_rill;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		/* This is the SOCK_RAW, IPPROTO_SCTP case. */
		ira->ira_ill = ira->ira_rill = NULL;
		(connp->conn_recv)(connp, mp, NULL, ira);
		ira->ira_ill = ill;
		ira->ira_rill = rill;
	}
	CONN_DEC_REF(connp);
}

/*
 * Free a packet that has the link-layer dl_unitdata_req_t or fast-path
 * header before the ip payload.
 */
static void
ip_xmit_flowctl_drop(ill_t *ill, mblk_t *mp, boolean_t is_fp_mp, int fp_mp_len)
{
	int len = (mp->b_wptr - mp->b_rptr);
	mblk_t *ip_mp;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
	if (is_fp_mp || len != fp_mp_len) {
		if (len > fp_mp_len) {
			/*
			 * fastpath header and ip header in the first mblk
			 */
			mp->b_rptr += fp_mp_len;
		} else {
			/*
			 * ip_xmit_attach_llhdr had to prepend an mblk to
			 * attach the fastpath header before ip header.
			 */
			ip_mp = mp->b_cont;
			freeb(mp);
			mp = ip_mp;
			mp->b_rptr += (fp_mp_len - len);
		}
	} else {
		ip_mp = mp->b_cont;
		freeb(mp);
		mp = ip_mp;
	}
	ip_drop_output("ipIfStatsOutDiscards - flow ctl", mp, ill);
	freemsg(mp);
}

/*
 * Normal post fragmentation function.
 *
 * Send a packet using the passed in nce. This handles both IPv4 and IPv6
 * using the same state machine.
 *
 * We return an error on failure. In particular we return EWOULDBLOCK
 * when the driver flow controls. In that case this ensures that ip_wsrv runs
 * (currently by canputnext failure resulting in backenabling from GLD.)
 * This allows the callers of conn_ip_output() to use EWOULDBLOCK as an
 * indication that they can flow control until ip_wsrv() tells then to restart.
 *
 * If the nce passed by caller is incomplete, this function
 * queues the packet and if necessary, sends ARP request and bails.
 * If the Neighbor Cache passed is fully resolved, we simply prepend
 * the link-layer header to the packet, do ipsec hw acceleration
 * work if necessary, and send the packet out on the wire.
 */
/* ARGSUSED6 */
int
ip_xmit(mblk_t *mp, nce_t *nce, iaflags_t ixaflags, uint_t pkt_len,
    uint32_t xmit_hint, zoneid_t szone, zoneid_t nolzid, uintptr_t *ixacookie)
{
	queue_t		*wq;
	ill_t		*ill = nce->nce_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint64_t	delta;
	boolean_t	isv6 = ill->ill_isv6;
	boolean_t	fp_mp;
	ncec_t		*ncec = nce->nce_common;
	int64_t		now = LBOLT_FASTPATH64;
	boolean_t	is_probe;

	DTRACE_PROBE1(ip__xmit, nce_t *, nce);

	ASSERT(mp != NULL);
	ASSERT(mp->b_datap->db_type == M_DATA);
	ASSERT(pkt_len == msgdsize(mp));

	/*
	 * If we have already been here and are coming back after ARP/ND.
	 * the IXAF_NO_TRACE flag is set. We skip FW_HOOKS, DTRACE and ipobs
	 * in that case since they have seen the packet when it came here
	 * the first time.
	 */
	if (ixaflags & IXAF_NO_TRACE)
		goto sendit;

	if (ixaflags & IXAF_IS_IPV4) {
		ipha_t *ipha = (ipha_t *)mp->b_rptr;

		ASSERT(!isv6);
		ASSERT(pkt_len == ntohs(((ipha_t *)mp->b_rptr)->ipha_length));
		if (HOOKS4_INTERESTED_PHYSICAL_OUT(ipst) &&
		    !(ixaflags & IXAF_NO_PFHOOK)) {
			int	error;

			FW_HOOKS(ipst->ips_ip4_physical_out_event,
			    ipst->ips_ipv4firewall_physical_out,
			    NULL, ill, ipha, mp, mp, 0, ipst, error);
			DTRACE_PROBE1(ip4__physical__out__end,
			    mblk_t *, mp);
			if (mp == NULL)
				return (error);

			/* The length could have changed */
			pkt_len = msgdsize(mp);
		}
		if (ipst->ips_ip4_observe.he_interested) {
			/*
			 * Note that for TX the zoneid is the sending
			 * zone, whether or not MLP is in play.
			 * Since the szone argument is the IP zoneid (i.e.,
			 * zero for exclusive-IP zones) and ipobs wants
			 * the system zoneid, we map it here.
			 */
			szone = IP_REAL_ZONEID(szone, ipst);

			/*
			 * On the outbound path the destination zone will be
			 * unknown as we're sending this packet out on the
			 * wire.
			 */
			ipobs_hook(mp, IPOBS_HOOK_OUTBOUND, szone, ALL_ZONES,
			    ill, ipst);
		}
		DTRACE_IP7(send, mblk_t *, mp,  conn_t *, NULL,
		    void_ip_t *, ipha,  __dtrace_ipsr_ill_t *, ill,
		    ipha_t *, ipha, ip6_t *, NULL, int, 0);
	} else {
		ip6_t *ip6h = (ip6_t *)mp->b_rptr;

		ASSERT(isv6);
		ASSERT(pkt_len ==
		    ntohs(((ip6_t *)mp->b_rptr)->ip6_plen) + IPV6_HDR_LEN);
		if (HOOKS6_INTERESTED_PHYSICAL_OUT(ipst) &&
		    !(ixaflags & IXAF_NO_PFHOOK)) {
			int	error;

			FW_HOOKS6(ipst->ips_ip6_physical_out_event,
			    ipst->ips_ipv6firewall_physical_out,
			    NULL, ill, ip6h, mp, mp, 0, ipst, error);
			DTRACE_PROBE1(ip6__physical__out__end,
			    mblk_t *, mp);
			if (mp == NULL)
				return (error);

			/* The length could have changed */
			pkt_len = msgdsize(mp);
		}
		if (ipst->ips_ip6_observe.he_interested) {
			/* See above */
			szone = IP_REAL_ZONEID(szone, ipst);

			ipobs_hook(mp, IPOBS_HOOK_OUTBOUND, szone, ALL_ZONES,
			    ill, ipst);
		}
		DTRACE_IP7(send, mblk_t *, mp,  conn_t *, NULL,
		    void_ip_t *, ip6h,  __dtrace_ipsr_ill_t *, ill,
		    ipha_t *, NULL, ip6_t *, ip6h, int, 0);
	}

sendit:
	/*
	 * We check the state without a lock because the state can never
	 * move "backwards" to initial or incomplete.
	 */
	switch (ncec->ncec_state) {
	case ND_REACHABLE:
	case ND_STALE:
	case ND_DELAY:
	case ND_PROBE:
		mp = ip_xmit_attach_llhdr(mp, nce);
		if (mp == NULL) {
			/*
			 * ip_xmit_attach_llhdr has increased
			 * ipIfStatsOutDiscards and called ip_drop_output()
			 */
			return (ENOBUFS);
		}
		/*
		 * check if nce_fastpath completed and we tagged on a
		 * copy of nce_fp_mp in ip_xmit_attach_llhdr().
		 */
		fp_mp = (mp->b_datap->db_type == M_DATA);

		if (fp_mp &&
		    (ill->ill_capabilities & ILL_CAPAB_DLD_DIRECT)) {
			ill_dld_direct_t *idd;

			idd = &ill->ill_dld_capab->idc_direct;
			/*
			 * Send the packet directly to DLD, where it
			 * may be queued depending on the availability
			 * of transmit resources at the media layer.
			 * Return value should be taken into
			 * account and flow control the TCP.
			 */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutTransmits);
			UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutOctets,
			    pkt_len);

			if (ixaflags & IXAF_NO_DEV_FLOW_CTL) {
				(void) idd->idd_tx_df(idd->idd_tx_dh, mp,
				    (uintptr_t)xmit_hint, IP_DROP_ON_NO_DESC);
			} else {
				uintptr_t cookie;

				if ((cookie = idd->idd_tx_df(idd->idd_tx_dh,
				    mp, (uintptr_t)xmit_hint, 0)) != 0) {
					if (ixacookie != NULL)
						*ixacookie = cookie;
					return (EWOULDBLOCK);
				}
			}
		} else {
			wq = ill->ill_wq;

			if (!(ixaflags & IXAF_NO_DEV_FLOW_CTL) &&
			    !canputnext(wq)) {
				if (ixacookie != NULL)
					*ixacookie = 0;
				ip_xmit_flowctl_drop(ill, mp, fp_mp,
				    nce->nce_fp_mp != NULL ?
				    MBLKL(nce->nce_fp_mp) : 0);
				return (EWOULDBLOCK);
			}
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutTransmits);
			UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutOctets,
			    pkt_len);
			putnext(wq, mp);
		}

		/*
		 * The rest of this function implements Neighbor Unreachability
		 * detection. Determine if the ncec is eligible for NUD.
		 */
		if (ncec->ncec_flags & NCE_F_NONUD)
			return (0);

		ASSERT(ncec->ncec_state != ND_INCOMPLETE);

		/*
		 * Check for upper layer advice
		 */
		if (ixaflags & IXAF_REACH_CONF) {
			timeout_id_t tid;

			/*
			 * It should be o.k. to check the state without
			 * a lock here, at most we lose an advice.
			 */
			ncec->ncec_last = TICK_TO_MSEC(now);
			if (ncec->ncec_state != ND_REACHABLE) {
				mutex_enter(&ncec->ncec_lock);
				ncec->ncec_state = ND_REACHABLE;
				tid = ncec->ncec_timeout_id;
				ncec->ncec_timeout_id = 0;
				mutex_exit(&ncec->ncec_lock);
				(void) untimeout(tid);
				if (ip_debug > 2) {
					/* ip1dbg */
					pr_addr_dbg("ip_xmit: state"
					    " for %s changed to"
					    " REACHABLE\n", AF_INET6,
					    &ncec->ncec_addr);
				}
			}
			return (0);
		}

		delta =  TICK_TO_MSEC(now) - ncec->ncec_last;
		ip1dbg(("ip_xmit: delta = %" PRId64
		    " ill_reachable_time = %d \n", delta,
		    ill->ill_reachable_time));
		if (delta > (uint64_t)ill->ill_reachable_time) {
			mutex_enter(&ncec->ncec_lock);
			switch (ncec->ncec_state) {
			case ND_REACHABLE:
				ASSERT((ncec->ncec_flags & NCE_F_NONUD) == 0);
				/* FALLTHROUGH */
			case ND_STALE:
				/*
				 * ND_REACHABLE is identical to
				 * ND_STALE in this specific case. If
				 * reachable time has expired for this
				 * neighbor (delta is greater than
				 * reachable time), conceptually, the
				 * neighbor cache is no longer in
				 * REACHABLE state, but already in
				 * STALE state.  So the correct
				 * transition here is to ND_DELAY.
				 */
				ncec->ncec_state = ND_DELAY;
				mutex_exit(&ncec->ncec_lock);
				nce_restart_timer(ncec,
				    ipst->ips_delay_first_probe_time);
				if (ip_debug > 3) {
					/* ip2dbg */
					pr_addr_dbg("ip_xmit: state"
					    " for %s changed to"
					    " DELAY\n", AF_INET6,
					    &ncec->ncec_addr);
				}
				break;
			case ND_DELAY:
			case ND_PROBE:
				mutex_exit(&ncec->ncec_lock);
				/* Timers have already started */
				break;
			case ND_UNREACHABLE:
				/*
				 * nce_timer has detected that this ncec
				 * is unreachable and initiated deleting
				 * this ncec.
				 * This is a harmless race where we found the
				 * ncec before it was deleted and have
				 * just sent out a packet using this
				 * unreachable ncec.
				 */
				mutex_exit(&ncec->ncec_lock);
				break;
			default:
				ASSERT(0);
				mutex_exit(&ncec->ncec_lock);
			}
		}
		return (0);

	case ND_INCOMPLETE:
		/*
		 * the state could have changed since we didn't hold the lock.
		 * Re-verify state under lock.
		 */
		is_probe = ipmp_packet_is_probe(mp, nce->nce_ill);
		mutex_enter(&ncec->ncec_lock);
		if (NCE_ISREACHABLE(ncec)) {
			mutex_exit(&ncec->ncec_lock);
			goto sendit;
		}
		/* queue the packet */
		nce_queue_mp(ncec, mp, is_probe);
		mutex_exit(&ncec->ncec_lock);
		DTRACE_PROBE2(ip__xmit__incomplete,
		    (ncec_t *), ncec, (mblk_t *), mp);
		return (0);

	case ND_INITIAL:
		/*
		 * State could have changed since we didn't hold the lock, so
		 * re-verify state.
		 */
		is_probe = ipmp_packet_is_probe(mp, nce->nce_ill);
		mutex_enter(&ncec->ncec_lock);
		if (NCE_ISREACHABLE(ncec))  {
			mutex_exit(&ncec->ncec_lock);
			goto sendit;
		}
		nce_queue_mp(ncec, mp, is_probe);
		if (ncec->ncec_state == ND_INITIAL) {
			ncec->ncec_state = ND_INCOMPLETE;
			mutex_exit(&ncec->ncec_lock);
			/*
			 * figure out the source we want to use
			 * and resolve it.
			 */
			ip_ndp_resolve(ncec);
		} else  {
			mutex_exit(&ncec->ncec_lock);
		}
		return (0);

	case ND_UNREACHABLE:
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards - ND_UNREACHABLE",
		    mp, ill);
		freemsg(mp);
		return (0);

	default:
		ASSERT(0);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards - ND_other",
		    mp, ill);
		freemsg(mp);
		return (ENETUNREACH);
	}
}

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
 * Free the storage pointed to by the members of an ip_pkt_t.
 */
void
ip_pkt_free(ip_pkt_t *ipp)
{
	uint_t	fields = ipp->ipp_fields;

	if (fields & IPPF_HOPOPTS) {
		kmem_free(ipp->ipp_hopopts, ipp->ipp_hopoptslen);
		ipp->ipp_hopopts = NULL;
		ipp->ipp_hopoptslen = 0;
	}
	if (fields & IPPF_RTHDRDSTOPTS) {
		kmem_free(ipp->ipp_rthdrdstopts, ipp->ipp_rthdrdstoptslen);
		ipp->ipp_rthdrdstopts = NULL;
		ipp->ipp_rthdrdstoptslen = 0;
	}
	if (fields & IPPF_DSTOPTS) {
		kmem_free(ipp->ipp_dstopts, ipp->ipp_dstoptslen);
		ipp->ipp_dstopts = NULL;
		ipp->ipp_dstoptslen = 0;
	}
	if (fields & IPPF_RTHDR) {
		kmem_free(ipp->ipp_rthdr, ipp->ipp_rthdrlen);
		ipp->ipp_rthdr = NULL;
		ipp->ipp_rthdrlen = 0;
	}
	if (fields & IPPF_IPV4_OPTIONS) {
		kmem_free(ipp->ipp_ipv4_options, ipp->ipp_ipv4_options_len);
		ipp->ipp_ipv4_options = NULL;
		ipp->ipp_ipv4_options_len = 0;
	}
	if (fields & IPPF_LABEL_V4) {
		kmem_free(ipp->ipp_label_v4, ipp->ipp_label_len_v4);
		ipp->ipp_label_v4 = NULL;
		ipp->ipp_label_len_v4 = 0;
	}
	if (fields & IPPF_LABEL_V6) {
		kmem_free(ipp->ipp_label_v6, ipp->ipp_label_len_v6);
		ipp->ipp_label_v6 = NULL;
		ipp->ipp_label_len_v6 = 0;
	}
	ipp->ipp_fields &= ~(IPPF_HOPOPTS | IPPF_RTHDRDSTOPTS | IPPF_DSTOPTS |
	    IPPF_RTHDR | IPPF_IPV4_OPTIONS | IPPF_LABEL_V4 | IPPF_LABEL_V6);
}

/*
 * Copy from src to dst and allocate as needed.
 * Returns zero or ENOMEM.
 *
 * The caller must initialize dst to zero.
 */
int
ip_pkt_copy(ip_pkt_t *src, ip_pkt_t *dst, int kmflag)
{
	uint_t	fields = src->ipp_fields;

	/* Start with fields that don't require memory allocation */
	dst->ipp_fields = fields &
	    ~(IPPF_HOPOPTS | IPPF_RTHDRDSTOPTS | IPPF_DSTOPTS |
	    IPPF_RTHDR | IPPF_IPV4_OPTIONS | IPPF_LABEL_V4 | IPPF_LABEL_V6);

	dst->ipp_addr = src->ipp_addr;
	dst->ipp_unicast_hops = src->ipp_unicast_hops;
	dst->ipp_hoplimit = src->ipp_hoplimit;
	dst->ipp_tclass = src->ipp_tclass;
	dst->ipp_type_of_service = src->ipp_type_of_service;

	if (!(fields & (IPPF_HOPOPTS | IPPF_RTHDRDSTOPTS | IPPF_DSTOPTS |
	    IPPF_RTHDR | IPPF_IPV4_OPTIONS | IPPF_LABEL_V4 | IPPF_LABEL_V6)))
		return (0);

	if (fields & IPPF_HOPOPTS) {
		dst->ipp_hopopts = kmem_alloc(src->ipp_hopoptslen, kmflag);
		if (dst->ipp_hopopts == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_HOPOPTS;
		bcopy(src->ipp_hopopts, dst->ipp_hopopts,
		    src->ipp_hopoptslen);
		dst->ipp_hopoptslen = src->ipp_hopoptslen;
	}
	if (fields & IPPF_RTHDRDSTOPTS) {
		dst->ipp_rthdrdstopts = kmem_alloc(src->ipp_rthdrdstoptslen,
		    kmflag);
		if (dst->ipp_rthdrdstopts == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_RTHDRDSTOPTS;
		bcopy(src->ipp_rthdrdstopts, dst->ipp_rthdrdstopts,
		    src->ipp_rthdrdstoptslen);
		dst->ipp_rthdrdstoptslen = src->ipp_rthdrdstoptslen;
	}
	if (fields & IPPF_DSTOPTS) {
		dst->ipp_dstopts = kmem_alloc(src->ipp_dstoptslen, kmflag);
		if (dst->ipp_dstopts == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_DSTOPTS;
		bcopy(src->ipp_dstopts, dst->ipp_dstopts,
		    src->ipp_dstoptslen);
		dst->ipp_dstoptslen = src->ipp_dstoptslen;
	}
	if (fields & IPPF_RTHDR) {
		dst->ipp_rthdr = kmem_alloc(src->ipp_rthdrlen, kmflag);
		if (dst->ipp_rthdr == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_RTHDR;
		bcopy(src->ipp_rthdr, dst->ipp_rthdr,
		    src->ipp_rthdrlen);
		dst->ipp_rthdrlen = src->ipp_rthdrlen;
	}
	if (fields & IPPF_IPV4_OPTIONS) {
		dst->ipp_ipv4_options = kmem_alloc(src->ipp_ipv4_options_len,
		    kmflag);
		if (dst->ipp_ipv4_options == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_IPV4_OPTIONS;
		bcopy(src->ipp_ipv4_options, dst->ipp_ipv4_options,
		    src->ipp_ipv4_options_len);
		dst->ipp_ipv4_options_len = src->ipp_ipv4_options_len;
	}
	if (fields & IPPF_LABEL_V4) {
		dst->ipp_label_v4 = kmem_alloc(src->ipp_label_len_v4, kmflag);
		if (dst->ipp_label_v4 == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_LABEL_V4;
		bcopy(src->ipp_label_v4, dst->ipp_label_v4,
		    src->ipp_label_len_v4);
		dst->ipp_label_len_v4 = src->ipp_label_len_v4;
	}
	if (fields & IPPF_LABEL_V6) {
		dst->ipp_label_v6 = kmem_alloc(src->ipp_label_len_v6, kmflag);
		if (dst->ipp_label_v6 == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_LABEL_V6;
		bcopy(src->ipp_label_v6, dst->ipp_label_v6,
		    src->ipp_label_len_v6);
		dst->ipp_label_len_v6 = src->ipp_label_len_v6;
	}
	if (fields & IPPF_FRAGHDR) {
		dst->ipp_fraghdr = kmem_alloc(src->ipp_fraghdrlen, kmflag);
		if (dst->ipp_fraghdr == NULL) {
			ip_pkt_free(dst);
			return (ENOMEM);
		}
		dst->ipp_fields |= IPPF_FRAGHDR;
		bcopy(src->ipp_fraghdr, dst->ipp_fraghdr,
		    src->ipp_fraghdrlen);
		dst->ipp_fraghdrlen = src->ipp_fraghdrlen;
	}
	return (0);
}

/*
 * Returns INADDR_ANY if no source route
 */
ipaddr_t
ip_pkt_source_route_v4(const ip_pkt_t *ipp)
{
	ipaddr_t	nexthop = INADDR_ANY;
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	uint32_t	totallen;

	if (!(ipp->ipp_fields & IPPF_IPV4_OPTIONS))
		return (INADDR_ANY);

	totallen = ipp->ipp_ipv4_options_len;
	if (totallen & 0x3)
		return (INADDR_ANY);

	for (optval = ipoptp_first2(&opts, totallen, ipp->ipp_ipv4_options);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		switch (optval) {
			uint8_t off;
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				break;
			}
			optlen = opts.ipoptp_len;
			off = opt[IPOPT_OFFSET];
			off--;
			if (optlen < IP_ADDR_LEN ||
			    off > optlen - IP_ADDR_LEN) {
				/* End of source route */
				break;
			}
			bcopy((char *)opt + off, &nexthop, IP_ADDR_LEN);
			if (nexthop == htonl(INADDR_LOOPBACK)) {
				/* Ignore */
				nexthop = INADDR_ANY;
				break;
			}
			break;
		}
	}
	return (nexthop);
}

/*
 * Reverse a source route.
 */
void
ip_pkt_source_route_reverse_v4(ip_pkt_t *ipp)
{
	ipaddr_t	tmp;
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint32_t	totallen;

	if (!(ipp->ipp_fields & IPPF_IPV4_OPTIONS))
		return;

	totallen = ipp->ipp_ipv4_options_len;
	if (totallen & 0x3)
		return;

	for (optval = ipoptp_first2(&opts, totallen, ipp->ipp_ipv4_options);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		uint8_t off1, off2;

		opt = opts.ipoptp_cur;
		switch (optval) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if ((opts.ipoptp_flags & IPOPTP_ERROR) != 0) {
				break;
			}
			off1 = IPOPT_MINOFF_SR - 1;
			off2 = opt[IPOPT_OFFSET] - IP_ADDR_LEN - 1;
			while (off2 > off1) {
				bcopy(opt + off2, &tmp, IP_ADDR_LEN);
				bcopy(opt + off1, opt + off2, IP_ADDR_LEN);
				bcopy(&tmp, opt + off2, IP_ADDR_LEN);
				off2 -= IP_ADDR_LEN;
				off1 += IP_ADDR_LEN;
			}
			opt[IPOPT_OFFSET] = IPOPT_MINOFF_SR;
			break;
		}
	}
}

/*
 * Returns NULL if no routing header
 */
in6_addr_t *
ip_pkt_source_route_v6(const ip_pkt_t *ipp)
{
	in6_addr_t	*nexthop = NULL;
	ip6_rthdr0_t	*rthdr;

	if (!(ipp->ipp_fields & IPPF_RTHDR))
		return (NULL);

	rthdr = (ip6_rthdr0_t *)ipp->ipp_rthdr;
	if (rthdr->ip6r0_segleft == 0)
		return (NULL);

	nexthop = (in6_addr_t *)((char *)rthdr + sizeof (*rthdr));
	return (nexthop);
}

zoneid_t
ip_get_zoneid_v4(ipaddr_t addr, mblk_t *mp, ip_recv_attr_t *ira,
    zoneid_t lookup_zoneid)
{
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	ire_t		*ire;
	int		ire_flags = MATCH_IRE_TYPE;
	zoneid_t	zoneid = ALL_ZONES;

	if (is_system_labeled() && !tsol_can_accept_raw(mp, ira, B_FALSE))
		return (ALL_ZONES);

	if (lookup_zoneid != ALL_ZONES)
		ire_flags |= MATCH_IRE_ZONEONLY;
	ire = ire_ftable_lookup_v4(addr, NULL, NULL, IRE_LOCAL | IRE_LOOPBACK,
	    NULL, lookup_zoneid, NULL, ire_flags, 0, ipst, NULL);
	if (ire != NULL) {
		zoneid = IP_REAL_ZONEID(ire->ire_zoneid, ipst);
		ire_refrele(ire);
	}
	return (zoneid);
}

zoneid_t
ip_get_zoneid_v6(in6_addr_t *addr, mblk_t *mp, const ill_t *ill,
    ip_recv_attr_t *ira, zoneid_t lookup_zoneid)
{
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	ire_t		*ire;
	int		ire_flags = MATCH_IRE_TYPE;
	zoneid_t	zoneid = ALL_ZONES;

	if (is_system_labeled() && !tsol_can_accept_raw(mp, ira, B_FALSE))
		return (ALL_ZONES);

	if (IN6_IS_ADDR_LINKLOCAL(addr))
		ire_flags |= MATCH_IRE_ILL;

	if (lookup_zoneid != ALL_ZONES)
		ire_flags |= MATCH_IRE_ZONEONLY;
	ire = ire_ftable_lookup_v6(addr, NULL, NULL, IRE_LOCAL | IRE_LOOPBACK,
	    ill, lookup_zoneid, NULL, ire_flags, 0, ipst, NULL);
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
	netid_t id;

	id = net_getnetidbynetstackid(ipst->ips_netstack->netstack_stackid);

	ipst->ips_ip4_observe_pr = net_protocol_lookup(id, NHF_INET);
	VERIFY(ipst->ips_ip4_observe_pr != NULL);

	ipst->ips_ip6_observe_pr = net_protocol_lookup(id, NHF_INET6);
	VERIFY(ipst->ips_ip6_observe_pr != NULL);
}

static void
ipobs_fini(ip_stack_t *ipst)
{

	VERIFY(net_protocol_release(ipst->ips_ip4_observe_pr) == 0);
	VERIFY(net_protocol_release(ipst->ips_ip6_observe_pr) == 0);
}

/*
 * hook_pkt_observe_t is composed in network byte order so that the
 * entire mblk_t chain handed into hook_run can be used as-is.
 * The caveat is that use of the fields, such as the zone fields,
 * requires conversion into host byte order first.
 */
void
ipobs_hook(mblk_t *mp, int htype, zoneid_t zsrc, zoneid_t zdst,
    const ill_t *ill, ip_stack_t *ipst)
{
	hook_pkt_observe_t *hdr;
	uint64_t grifindex;
	mblk_t *imp;

	imp = allocb(sizeof (*hdr), BPRI_HI);
	if (imp == NULL)
		return;

	hdr = (hook_pkt_observe_t *)imp->b_rptr;
	/*
	 * b_wptr is set to make the apparent size of the data in the mblk_t
	 * to exclude the pointers at the end of hook_pkt_observer_t.
	 */
	imp->b_wptr = imp->b_rptr + sizeof (dl_ipnetinfo_t);
	imp->b_cont = mp;

	ASSERT(DB_TYPE(mp) == M_DATA);

	if (IS_UNDER_IPMP(ill))
		grifindex = ipmp_ill_get_ipmp_ifindex(ill);
	else
		grifindex = 0;

	hdr->hpo_version = 1;
	hdr->hpo_htype = htons(htype);
	hdr->hpo_pktlen = htonl((ulong_t)msgdsize(mp));
	hdr->hpo_ifindex = htonl(ill->ill_phyint->phyint_ifindex);
	hdr->hpo_grifindex = htonl(grifindex);
	hdr->hpo_zsrc = htonl(zsrc);
	hdr->hpo_zdst = htonl(zdst);
	hdr->hpo_pkt = imp;
	hdr->hpo_ctx = ipst->ips_netstack;

	if (ill->ill_isv6) {
		hdr->hpo_family = AF_INET6;
		(void) hook_run(ipst->ips_ipv6_net_data->netd_hooks,
		    ipst->ips_ipv6observing, (hook_data_t)hdr);
	} else {
		hdr->hpo_family = AF_INET;
		(void) hook_run(ipst->ips_ipv4_net_data->netd_hooks,
		    ipst->ips_ipv4observing, (hook_data_t)hdr);
	}

	imp->b_cont = NULL;
	freemsg(imp);
}

/*
 * Utility routine that checks if `v4srcp' is a valid address on underlying
 * interface `ill'.  If `ipifp' is non-NULL, it's set to a held ipif
 * associated with `v4srcp' on success.  NOTE: if this is not called from
 * inside the IPSQ (ill_g_lock is not held), `ill' may be removed from the
 * group during or after this lookup.
 */
boolean_t
ipif_lookup_testaddr_v4(ill_t *ill, const in_addr_t *v4srcp, ipif_t **ipifp)
{
	ipif_t *ipif;

	ipif = ipif_lookup_addr_exact(*v4srcp, ill, ill->ill_ipst);
	if (ipif != NULL) {
		if (ipifp != NULL)
			*ipifp = ipif;
		else
			ipif_refrele(ipif);
		return (B_TRUE);
	}

	ip1dbg(("ipif_lookup_testaddr_v4: cannot find ipif for src %x\n",
	    *v4srcp));
	return (B_FALSE);
}

/*
 * Transport protocol call back function for CPU state change.
 */
/* ARGSUSED */
static int
ip_tp_cpu_update(cpu_setup_t what, int id, void *arg)
{
	processorid_t cpu_seqid;
	netstack_handle_t nh;
	netstack_t *ns;

	ASSERT(MUTEX_HELD(&cpu_lock));

	switch (what) {
	case CPU_CONFIG:
	case CPU_ON:
	case CPU_INIT:
	case CPU_CPUPART_IN:
		cpu_seqid = cpu[id]->cpu_seqid;
		netstack_next_init(&nh);
		while ((ns = netstack_next(&nh)) != NULL) {
			tcp_stack_cpu_add(ns->netstack_tcp, cpu_seqid);
			sctp_stack_cpu_add(ns->netstack_sctp, cpu_seqid);
			udp_stack_cpu_add(ns->netstack_udp, cpu_seqid);
			netstack_rele(ns);
		}
		netstack_next_fini(&nh);
		break;
	case CPU_UNCONFIG:
	case CPU_OFF:
	case CPU_CPUPART_OUT:
		/*
		 * Nothing to do.  We don't remove the per CPU stats from
		 * the IP stack even when the CPU goes offline.
		 */
		break;
	default:
		break;
	}
	return (0);
}
