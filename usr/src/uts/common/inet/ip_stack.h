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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_IP_STACK_H
#define	_INET_IP_STACK_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/netstack.h>
#include <netinet/igmp_var.h>
#include <sys/modhash.h>

#ifdef _KERNEL
#include <sys/list.h>


/*
 * IP statistics.
 */
#define	IP_STAT(ipst, x)	((ipst)->ips_ip_statistics.x.value.ui64++)
#define	IP_STAT_UPDATE(ipst, x, n) \
		((ipst)->ips_ip_statistics.x.value.ui64 += (n))

typedef struct ip_stat {
	kstat_named_t	ip_udp_fannorm;
	kstat_named_t	ip_udp_fanmb;
	kstat_named_t	ip_recv_pullup;
	kstat_named_t	ip_db_ref;
	kstat_named_t	ip_notaligned;
	kstat_named_t	ip_multimblk;
	kstat_named_t	ip_opt;
	kstat_named_t	ipsec_proto_ahesp;
	kstat_named_t	ip_conn_flputbq;
	kstat_named_t	ip_conn_walk_drain;
	kstat_named_t   ip_out_sw_cksum;
	kstat_named_t	ip_out_sw_cksum_bytes;
	kstat_named_t   ip_in_sw_cksum;
	kstat_named_t   ip_ire_reclaim_calls;
	kstat_named_t   ip_ire_reclaim_deleted;
	kstat_named_t   ip_nce_reclaim_calls;
	kstat_named_t   ip_nce_reclaim_deleted;
	kstat_named_t   ip_dce_reclaim_calls;
	kstat_named_t   ip_dce_reclaim_deleted;
	kstat_named_t	ip_tcp_in_full_hw_cksum_err;
	kstat_named_t	ip_tcp_in_part_hw_cksum_err;
	kstat_named_t	ip_tcp_in_sw_cksum_err;
	kstat_named_t	ip_udp_in_full_hw_cksum_err;
	kstat_named_t	ip_udp_in_part_hw_cksum_err;
	kstat_named_t	ip_udp_in_sw_cksum_err;
	kstat_named_t	conn_in_recvdstaddr;
	kstat_named_t	conn_in_recvopts;
	kstat_named_t	conn_in_recvif;
	kstat_named_t	conn_in_recvslla;
	kstat_named_t	conn_in_recvucred;
	kstat_named_t	conn_in_recvttl;
	kstat_named_t	conn_in_recvhopopts;
	kstat_named_t	conn_in_recvhoplimit;
	kstat_named_t	conn_in_recvdstopts;
	kstat_named_t	conn_in_recvrthdrdstopts;
	kstat_named_t	conn_in_recvrthdr;
	kstat_named_t	conn_in_recvpktinfo;
	kstat_named_t	conn_in_recvtclass;
	kstat_named_t	conn_in_timestamp;
} ip_stat_t;


/*
 * IP6 statistics.
 */
#define	IP6_STAT(ipst, x)	((ipst)->ips_ip6_statistics.x.value.ui64++)
#define	IP6_STAT_UPDATE(ipst, x, n)	\
	((ipst)->ips_ip6_statistics.x.value.ui64 += (n))

typedef struct ip6_stat {
	kstat_named_t	ip6_udp_fannorm;
	kstat_named_t	ip6_udp_fanmb;
	kstat_named_t	ip6_recv_pullup;
	kstat_named_t	ip6_db_ref;
	kstat_named_t	ip6_notaligned;
	kstat_named_t	ip6_multimblk;
	kstat_named_t	ipsec_proto_ahesp;
	kstat_named_t   ip6_out_sw_cksum;
	kstat_named_t	ip6_out_sw_cksum_bytes;
	kstat_named_t   ip6_in_sw_cksum;
	kstat_named_t	ip6_tcp_in_full_hw_cksum_err;
	kstat_named_t	ip6_tcp_in_part_hw_cksum_err;
	kstat_named_t	ip6_tcp_in_sw_cksum_err;
	kstat_named_t	ip6_udp_in_full_hw_cksum_err;
	kstat_named_t	ip6_udp_in_part_hw_cksum_err;
	kstat_named_t	ip6_udp_in_sw_cksum_err;
} ip6_stat_t;

typedef struct ire_stats {
	uint64_t ire_stats_alloced;	/* # of ires alloced */
	uint64_t ire_stats_freed;	/* # of ires freed */
	uint64_t ire_stats_inserted;	/* # of ires inserted in the bucket */
	uint64_t ire_stats_deleted;	/* # of ires deleted from the bucket */
} ire_stats_t;

#define	TX_FANOUT_SIZE	128
#define	IDLHASHINDEX(X)	\
	((((uintptr_t)(X) >> 2) + ((uintptr_t)(X) >> 9)) & (TX_FANOUT_SIZE - 1))

/* Data structure to represent addresses */
typedef struct srcid_map {
	struct srcid_map	*sm_next;
	in6_addr_t		sm_addr;	/* Local address */
	uint_t			sm_srcid;	/* source id */
	uint_t			sm_refcnt;	/* > 1 ipif with same addr? */
	zoneid_t		sm_zoneid;	/* zone id */
} srcid_map_t;

/*
 * IP stack instances
 */
struct ip_stack {
	netstack_t	*ips_netstack;	/* Common netstack */

	uint_t			ips_src_generation;	/* Both IPv4 and IPv6 */

	struct mod_prop_info_s	*ips_propinfo_tbl; 	/* ip tunables table */

	mib2_ipIfStatsEntry_t	ips_ip_mib;	/* SNMP fixed size info */
	mib2_icmp_t	ips_icmp_mib;
	/*
	 * IPv6 mibs when the interface (ill) is not known.
	 * When the ill is known the per-interface mib in the ill is used.
	 */
	mib2_ipIfStatsEntry_t	ips_ip6_mib;
	mib2_ipv6IfIcmpEntry_t	ips_icmp6_mib;

	struct igmpstat		ips_igmpstat;

	kstat_t		*ips_ip_mibkp;	/* kstat exporting ip_mib data */
	kstat_t		*ips_icmp_mibkp; /* kstat exporting icmp_mib data */
	kstat_t		*ips_ip_kstat;
	ip_stat_t	ips_ip_statistics;
	kstat_t		*ips_ip6_kstat;
	ip6_stat_t	ips_ip6_statistics;

/* ip.c */
	kmutex_t	ips_igmp_timer_lock;
	kmutex_t	ips_mld_timer_lock;
	kmutex_t	ips_ip_mi_lock;
	kmutex_t	ips_ip_addr_avail_lock;
	krwlock_t	ips_ill_g_lock;

	krwlock_t	ips_ill_g_usesrc_lock;

	/* Taskq dispatcher for capability operations */
	kmutex_t	ips_capab_taskq_lock;
	kcondvar_t	ips_capab_taskq_cv;
	mblk_t		*ips_capab_taskq_head;
	mblk_t		*ips_capab_taskq_tail;
	kthread_t	*ips_capab_taskq_thread;
	boolean_t	ips_capab_taskq_quit;

/* ipclassifier.c - keep in ip_stack_t */
	/* ipclassifier hash tables */
	struct connf_s	*ips_rts_clients;
	struct connf_s	*ips_ipcl_conn_fanout;
	struct connf_s	*ips_ipcl_bind_fanout;
	struct connf_s	*ips_ipcl_proto_fanout_v4;
	struct connf_s	*ips_ipcl_proto_fanout_v6;
	struct connf_s	*ips_ipcl_udp_fanout;
	struct connf_s	*ips_ipcl_raw_fanout;		/* RAW SCTP sockets */
	struct connf_s	*ips_ipcl_iptun_fanout;
	uint_t		ips_ipcl_conn_fanout_size;
	uint_t		ips_ipcl_bind_fanout_size;
	uint_t		ips_ipcl_udp_fanout_size;
	uint_t		ips_ipcl_raw_fanout_size;
	uint_t		ips_ipcl_iptun_fanout_size;
	struct connf_s	*ips_ipcl_globalhash_fanout;
	int		ips_conn_g_index;

/* ip.c */
	/* Following protected by igmp_timer_lock */
	int 		ips_igmp_time_to_next;	/* Time since last timeout */
	int 		ips_igmp_timer_scheduled_last;
	int		ips_igmp_deferred_next;
	timeout_id_t	ips_igmp_timeout_id;
	boolean_t	ips_igmp_timer_setter_active;

	/* Following protected by mld_timer_lock */
	int 		ips_mld_time_to_next;	/* Time since last timeout */
	int 		ips_mld_timer_scheduled_last;
	int		ips_mld_deferred_next;
	timeout_id_t	ips_mld_timeout_id;
	boolean_t	ips_mld_timer_setter_active;

	/* Protected by igmp_slowtimeout_lock */
	timeout_id_t	ips_igmp_slowtimeout_id;
	kmutex_t	ips_igmp_slowtimeout_lock;

	/* Protected by mld_slowtimeout_lock */
	timeout_id_t	ips_mld_slowtimeout_id;
	kmutex_t	ips_mld_slowtimeout_lock;

	/* IPv4 forwarding table */
	struct radix_node_head *ips_ip_ftable;

#define	IPV6_ABITS		128
#define	IP6_MASK_TABLE_SIZE	(IPV6_ABITS + 1)	/* 129 ptrs */
	struct irb	*ips_ip_forwarding_table_v6[IP6_MASK_TABLE_SIZE];

	/*
	 * ire_ft_init_lock is used while initializing ip_forwarding_table
	 * dynamically in ire_add.
	 */
	kmutex_t	ips_ire_ft_init_lock;

	/*
	 * This is the IPv6 counterpart of RADIX_NODE_HEAD_LOCK. It is used
	 * to prevent adds and deletes while we are doing a ftable_lookup
	 * and extracting the ire_generation.
	 */
	krwlock_t	ips_ip6_ire_head_lock;

	uint32_t	ips_ip6_ftable_hash_size;

	ire_stats_t 	ips_ire_stats_v4;	/* IPv4 ire statistics */
	ire_stats_t 	ips_ire_stats_v6;	/* IPv6 ire statistics */

	/* Count how many condemned objects for kmem_cache callbacks */
	uint32_t	ips_num_ire_condemned;
	uint32_t	ips_num_nce_condemned;
	uint32_t	ips_num_dce_condemned;

	struct ire_s	*ips_ire_reject_v4;	/* For unreachable dests */
	struct ire_s	*ips_ire_reject_v6;	/* For unreachable dests */
	struct ire_s	*ips_ire_blackhole_v4;	/* For temporary failures */
	struct ire_s	*ips_ire_blackhole_v6;	/* For temporary failures */

	/* ips_ire_dep_lock protects ire_dep_* relationship between IREs */
	krwlock_t	ips_ire_dep_lock;

	/* Destination Cache Entries */
	struct dce_s	*ips_dce_default;
	uint_t		ips_dce_hashsize;
	struct dcb_s	*ips_dce_hash_v4;
	struct dcb_s	*ips_dce_hash_v6;
	uint_t		ips_dce_reclaim_needed;

	/* pending binds */
	mblk_t		*ips_ip6_asp_pending_ops;
	mblk_t		*ips_ip6_asp_pending_ops_tail;

	/* Synchronize updates with table usage */
	mblk_t		*ips_ip6_asp_pending_update; /* pending table updates */

	boolean_t	ips_ip6_asp_uip;	/* table update in progress */
	kmutex_t	ips_ip6_asp_lock;	/* protect all the above */
	uint32_t	ips_ip6_asp_refcnt;	/* outstanding references */

	struct ip6_asp	*ips_ip6_asp_table;
	/* The number of policy entries in the table */
	uint_t		ips_ip6_asp_table_count;

	struct conn_s	*ips_ip_g_mrouter;

	/* Time since last icmp_pkt_err */
	clock_t		ips_icmp_pkt_err_last;
	/* Number of packets sent in burst */
	uint_t		ips_icmp_pkt_err_sent;

	/* Protected by ip_mi_lock */
	void		*ips_ip_g_head;	/* IP Instance Data List Head */
	void		*ips_arp_g_head; /* ARP Instance Data List Head */

	/* Multirouting stuff */
	/* Interval (in ms) between consecutive 'bad MTU' warnings */
	hrtime_t	ips_ip_multirt_log_interval;
	/* Time since last warning issued. */
	hrtime_t	ips_multirt_bad_mtu_last_time;

	/*
	 * CGTP hooks. Enabling and disabling of hooks is controlled by an
	 * IP tunable 'ips_ip_cgtp_filter'.
	 */
	struct cgtp_filter_ops *ips_ip_cgtp_filter_ops;

	struct ipsq_s	*ips_ipsq_g_head;
	uint_t		ips_ill_index;	/* Used to assign interface indicies */
	/* When set search for unused index */
	boolean_t	ips_ill_index_wrap;

	uint_t		ips_loopback_packets;

	/* NDP/NCE structures for IPv4 and IPv6 */
	struct ndp_g_s	*ips_ndp4;
	struct ndp_g_s	*ips_ndp6;

	/* ip_mroute stuff */
	kmutex_t	ips_ip_g_mrouter_mutex;

	struct mrtstat	*ips_mrtstat;	/* Stats for netstat */
	int		ips_saved_ip_forwarding;

	/* numvifs is only a hint about the max interface being used. */
	ushort_t	ips_numvifs;
	kmutex_t	ips_numvifs_mutex;

	struct vif	*ips_vifs;
	struct mfcb	*ips_mfcs;	/* kernel routing table	*/
	struct tbf	*ips_tbfs;
	/*
	 * One-back cache used to locate a tunnel's vif,
	 * given a datagram's src ip address.
	 */
	ipaddr_t	ips_last_encap_src;
	struct vif	*ips_last_encap_vif;
	kmutex_t	ips_last_encap_lock;	/* Protects the above */

	/*
	 * reg_vif_num is protected by numvifs_mutex
	 */
	/* Whether or not special PIM assert processing is enabled. */
	ushort_t	ips_reg_vif_num; 	/* Index to Register vif */
	int		ips_pim_assert;

	union ill_g_head_u *ips_ill_g_heads;   /* ILL List Head */

	kstat_t		*ips_loopback_ksp;

	/* Array of conn drain lists */
	struct idl_tx_list_s	*ips_idl_tx_list;
	uint_t		ips_conn_drain_list_cnt; /* Count of conn_drain_list */

	/*
	 * ID used to assign next free one.
	 * Increases by one. Once it wraps we search for an unused ID.
	 */
	uint_t		ips_ip_src_id;
	boolean_t	ips_srcid_wrapped;

	struct srcid_map *ips_srcid_head;
	krwlock_t	ips_srcid_lock;

	uint64_t	ips_ipif_g_seqid;	/* Used only for sctp_addr.c */
	union phyint_list_u *ips_phyint_g_list;	/* start of phyint list */

/* ip_netinfo.c */
	hook_family_t	ips_ipv4root;
	hook_family_t	ips_ipv6root;
	hook_family_t	ips_arproot;

	net_handle_t		ips_ipv4_net_data;
	net_handle_t		ips_ipv6_net_data;
	net_handle_t		ips_arp_net_data;

	/*
	 * Hooks for firewalling
	 */
	hook_event_t		ips_ip4_physical_in_event;
	hook_event_t		ips_ip4_physical_out_event;
	hook_event_t		ips_ip4_forwarding_event;
	hook_event_t		ips_ip4_loopback_in_event;
	hook_event_t		ips_ip4_loopback_out_event;

	hook_event_t		ips_ip6_physical_in_event;
	hook_event_t		ips_ip6_physical_out_event;
	hook_event_t		ips_ip6_forwarding_event;
	hook_event_t		ips_ip6_loopback_in_event;
	hook_event_t		ips_ip6_loopback_out_event;

	hook_event_t		ips_arp_physical_in_event;
	hook_event_t		ips_arp_physical_out_event;
	hook_event_t		ips_arp_nic_events;

	hook_event_token_t	ips_ipv4firewall_physical_in;
	hook_event_token_t	ips_ipv4firewall_physical_out;
	hook_event_token_t	ips_ipv4firewall_forwarding;
	hook_event_token_t	ips_ipv4firewall_loopback_in;
	hook_event_token_t	ips_ipv4firewall_loopback_out;

	hook_event_token_t	ips_ipv6firewall_physical_in;
	hook_event_token_t	ips_ipv6firewall_physical_out;
	hook_event_token_t	ips_ipv6firewall_forwarding;
	hook_event_token_t	ips_ipv6firewall_loopback_in;
	hook_event_token_t	ips_ipv6firewall_loopback_out;

	hook_event_t		ips_ip4_nic_events;
	hook_event_t		ips_ip6_nic_events;
	hook_event_token_t	ips_ipv4nicevents;
	hook_event_token_t	ips_ipv6nicevents;

	hook_event_token_t	ips_arp_physical_in;
	hook_event_token_t	ips_arp_physical_out;
	hook_event_token_t	ips_arpnicevents;

	net_handle_t		ips_ip4_observe_pr;
	net_handle_t		ips_ip6_observe_pr;
	hook_event_t		ips_ip4_observe;
	hook_event_t		ips_ip6_observe;
	hook_event_token_t	ips_ipv4observing;
	hook_event_token_t	ips_ipv6observing;

	struct __ldi_ident	*ips_ldi_ident;

/* ipmp.c */
	krwlock_t		ips_ipmp_lock;
	mod_hash_t		*ips_ipmp_grp_hash;

};
typedef struct ip_stack ip_stack_t;

/* Finding an ip_stack_t */
#define	CONNQ_TO_IPST(_q)	(Q_TO_CONN(_q)->conn_netstack->netstack_ip)
#define	ILLQ_TO_IPST(_q)	(((ill_t *)(_q)->q_ptr)->ill_ipst)
#define	PHYINT_TO_IPST(phyi)	((phyi)->phyint_ipsq->ipsq_ipst)

#else /* _KERNEL */
typedef int ip_stack_t;
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_STACK_H */
