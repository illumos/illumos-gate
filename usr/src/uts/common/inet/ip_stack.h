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

#ifndef	_INET_IP_STACK_H
#define	_INET_IP_STACK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/netstack.h>
#include <netinet/igmp_var.h>

#ifdef _KERNEL


/*
 * IP statistics.
 */
#define	IP_STAT(ipst, x)	((ipst)->ips_ip_statistics.x.value.ui64++)
#define	IP_STAT_UPDATE(ipst, x, n) \
		((ipst)->ips_ip_statistics.x.value.ui64 += (n))

typedef struct ip_stat {
	kstat_named_t	ipsec_fanout_proto;
	kstat_named_t	ip_udp_fannorm;
	kstat_named_t	ip_udp_fanmb;
	kstat_named_t	ip_udp_fanothers;
	kstat_named_t	ip_udp_fast_path;
	kstat_named_t	ip_udp_slow_path;
	kstat_named_t	ip_udp_input_err;
	kstat_named_t	ip_tcppullup;
	kstat_named_t	ip_tcpoptions;
	kstat_named_t	ip_multipkttcp;
	kstat_named_t	ip_tcp_fast_path;
	kstat_named_t	ip_tcp_slow_path;
	kstat_named_t	ip_tcp_input_error;
	kstat_named_t	ip_db_ref;
	kstat_named_t	ip_notaligned1;
	kstat_named_t	ip_notaligned2;
	kstat_named_t	ip_multimblk3;
	kstat_named_t	ip_multimblk4;
	kstat_named_t	ip_ipoptions;
	kstat_named_t	ip_classify_fail;
	kstat_named_t	ip_opt;
	kstat_named_t	ip_udp_rput_local;
	kstat_named_t	ipsec_proto_ahesp;
	kstat_named_t	ip_conn_flputbq;
	kstat_named_t	ip_conn_walk_drain;
	kstat_named_t   ip_out_sw_cksum;
	kstat_named_t   ip_in_sw_cksum;
	kstat_named_t   ip_trash_ire_reclaim_calls;
	kstat_named_t   ip_trash_ire_reclaim_success;
	kstat_named_t   ip_ire_arp_timer_expired;
	kstat_named_t   ip_ire_redirect_timer_expired;
	kstat_named_t	ip_ire_pmtu_timer_expired;
	kstat_named_t	ip_input_multi_squeue;
	kstat_named_t	ip_tcp_in_full_hw_cksum_err;
	kstat_named_t	ip_tcp_in_part_hw_cksum_err;
	kstat_named_t	ip_tcp_in_sw_cksum_err;
	kstat_named_t	ip_tcp_out_sw_cksum_bytes;
	kstat_named_t	ip_udp_in_full_hw_cksum_err;
	kstat_named_t	ip_udp_in_part_hw_cksum_err;
	kstat_named_t	ip_udp_in_sw_cksum_err;
	kstat_named_t	ip_udp_out_sw_cksum_bytes;
	kstat_named_t	ip_frag_mdt_pkt_out;
	kstat_named_t	ip_frag_mdt_discarded;
	kstat_named_t	ip_frag_mdt_allocfail;
	kstat_named_t	ip_frag_mdt_addpdescfail;
	kstat_named_t	ip_frag_mdt_allocd;
} ip_stat_t;


/*
 * IP6 statistics.
 */
#define	IP6_STAT(ipst, x)	((ipst)->ips_ip6_statistics.x.value.ui64++)
#define	IP6_STAT_UPDATE(ipst, x, n)	\
	((ipst)->ips_ip6_statistics.x.value.ui64 += (n))

typedef struct ip6_stat {
	kstat_named_t	ip6_udp_fast_path;
	kstat_named_t	ip6_udp_slow_path;
	kstat_named_t	ip6_udp_fannorm;
	kstat_named_t	ip6_udp_fanmb;
	kstat_named_t   ip6_out_sw_cksum;
	kstat_named_t   ip6_in_sw_cksum;
	kstat_named_t	ip6_tcp_in_full_hw_cksum_err;
	kstat_named_t	ip6_tcp_in_part_hw_cksum_err;
	kstat_named_t	ip6_tcp_in_sw_cksum_err;
	kstat_named_t	ip6_tcp_out_sw_cksum_bytes;
	kstat_named_t	ip6_udp_in_full_hw_cksum_err;
	kstat_named_t	ip6_udp_in_part_hw_cksum_err;
	kstat_named_t	ip6_udp_in_sw_cksum_err;
	kstat_named_t	ip6_udp_out_sw_cksum_bytes;
	kstat_named_t	ip6_frag_mdt_pkt_out;
	kstat_named_t	ip6_frag_mdt_discarded;
	kstat_named_t	ip6_frag_mdt_allocfail;
	kstat_named_t	ip6_frag_mdt_addpdescfail;
	kstat_named_t	ip6_frag_mdt_allocd;
} ip6_stat_t;

typedef struct ire_stats {
	uint64_t ire_stats_alloced;	/* # of ires alloced */
	uint64_t ire_stats_freed;	/* # of ires freed */
	uint64_t ire_stats_inserted;	/* # of ires inserted in the bucket */
	uint64_t ire_stats_deleted;	/* # of ires deleted from the bucket */
} ire_stats_t;


/*
 * IP stack instances
 */
struct ip_stack {
	netstack_t	*ips_netstack;	/* Common netstack */

	struct ipparam_s	*ips_param_arr; 	/* ndd variable table */
	struct ipndp_s		*ips_ndp_arr;

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
	krwlock_t	ips_ip_g_nd_lock;
	kmutex_t	ips_igmp_timer_lock;
	kmutex_t	ips_mld_timer_lock;
	kmutex_t	ips_ip_mi_lock;
	kmutex_t	ips_ip_addr_avail_lock;
	krwlock_t	ips_ill_g_lock;
	krwlock_t	ips_ipsec_capab_ills_lock;
				/* protects the list of IPsec capable ills */
	struct ipsec_capab_ill_s *ips_ipsec_capab_ills_ah;
	struct ipsec_capab_ill_s *ips_ipsec_capab_ills_esp;

	krwlock_t	ips_ill_g_usesrc_lock;

	struct ill_group *ips_illgrp_head_v4;	/* Head of IPv4 ill groups */
	struct ill_group *ips_illgrp_head_v6;	/* Head of IPv6 ill groups */

/* ipclassifier.c - keep in ip_stack_t */
	/* ipclassifier hash tables */
	struct connf_s	*ips_rts_clients;
	struct connf_s	*ips_ipcl_conn_fanout;
	struct connf_s	*ips_ipcl_bind_fanout;
	struct connf_s	*ips_ipcl_proto_fanout;
	struct connf_s	*ips_ipcl_proto_fanout_v6;
	struct connf_s	*ips_ipcl_udp_fanout;
	struct connf_s	*ips_ipcl_raw_fanout;
	uint_t		ips_ipcl_conn_fanout_size;
	uint_t		ips_ipcl_bind_fanout_size;
	uint_t		ips_ipcl_udp_fanout_size;
	uint_t		ips_ipcl_raw_fanout_size;
	struct connf_s	*ips_ipcl_globalhash_fanout;
	int		ips_conn_g_index;

/* ip.c */
	/* Following protected by ips_igmp_timer_lock */
	int 		ips_igmp_time_to_next;	/* Time since last timeout */
	int 		ips_igmp_timer_scheduled_last;
	int		ips_igmp_deferred_next;
	timeout_id_t	ips_igmp_timeout_id;
	/* Protected by igmp_timer_lock */
	boolean_t	ips_igmp_timer_setter_active;

	/* Following protected by mld_timer_lock */
	int 		ips_mld_time_to_next;	/* Time since last timeout */
	int 		ips_mld_timer_scheduled_last;
	int		ips_mld_deferred_next;
	timeout_id_t	ips_mld_timeout_id;
	/* Protected by mld_timer_lock */
	boolean_t	ips_mld_timer_setter_active;

	/* Protected by igmp_slowtimeout_lock */
	timeout_id_t	ips_igmp_slowtimeout_id;
	kmutex_t	ips_igmp_slowtimeout_lock;

	/* Protected by mld_slowtimeout_lock */
	timeout_id_t	ips_mld_slowtimeout_id;
	kmutex_t	ips_mld_slowtimeout_lock;

	/* IPv4 forwarding table */
	struct radix_node_head *ips_ip_ftable;

	/* This is dynamically allocated in ip_ire_init */
	struct irb	 *ips_ip_cache_table;

#define	IPV6_ABITS		128
#define	IP6_MASK_TABLE_SIZE	(IPV6_ABITS + 1)	/* 129 ptrs */

	struct irb	*ips_ip_forwarding_table_v6[IP6_MASK_TABLE_SIZE];
	/* This is dynamically allocated in ip_ire_init */
	struct irb	*ips_ip_cache_table_v6;

	uint32_t	ips_ire_handle;
	/*
	 * ire_ft_init_lock is used while initializing ip_forwarding_table
	 * dynamically in ire_add.
	 */
	kmutex_t	ips_ire_ft_init_lock;
	kmutex_t	ips_ire_handle_lock;	/* Protects ire_handle */

	uint32_t	ips_ip_cache_table_size;
	uint32_t	ips_ip6_cache_table_size;
	uint32_t	ips_ip6_ftable_hash_size;

	ire_stats_t 	ips_ire_stats_v4;	/* IPv4 ire statistics */
	ire_stats_t 	ips_ire_stats_v6;	/* IPv6 ire statistics */

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

	int		ips_ip_g_forward;
	int		ips_ipv6_forward;

	int		ips_ipmp_hook_emulation; /* ndd variable */

	time_t		ips_ip_g_frag_timeout;
	clock_t		ips_ip_g_frag_timo_ms;

	struct conn_s	*ips_ip_g_mrouter;

	/* Time since last icmp_pkt_err */
	clock_t		ips_icmp_pkt_err_last;
	/* Number of packets sent in burst */
	uint_t		ips_icmp_pkt_err_sent;
	/* Used by icmp_send_redirect_v6 for picking random src. */
	uint_t		ips_icmp_redirect_v6_src_index;

	/* Protected by ip_mi_lock */
	void		*ips_ip_g_head;		/* Instance Data List Head */

	caddr_t		ips_ip_g_nd;		/* Named Dispatch List Head */

	/* Multirouting stuff */
	/* Interval (in ms) between consecutive 'bad MTU' warnings */
	hrtime_t	ips_ip_multirt_log_interval;
	/* Time since last warning issued. */
	hrtime_t	ips_multirt_bad_mtu_last_time;

	struct cgtp_filter_ops *ips_ip_cgtp_filter_ops;	/* CGTP hooks */
	boolean_t	ips_ip_cgtp_filter;	/* Enable/disable CGTP hooks */

	kmutex_t	ips_ip_trash_timer_lock;
	timeout_id_t	ips_ip_ire_expire_id;	/* IRE expiration timer. */
	struct ipsq_s	*ips_ipsq_g_head;
	uint_t		ips_ill_index;	/* Used to assign interface indicies */
	/* When set search for unused index */
	boolean_t	ips_ill_index_wrap;

	clock_t		ips_ip_ire_arp_time_elapsed;
			/* Time since IRE cache last flushed */
	clock_t		ips_ip_ire_rd_time_elapsed;
			/* ... redirect IREs last flushed */
	clock_t		ips_ip_ire_pmtu_time_elapsed;
			/* Time since path mtu increase */

	uint_t		ips_ip_redirect_cnt;
			/* Num of redirect routes in ftable */
	uint_t		ips_ipv6_ire_default_count;
			/* Number of IPv6 IRE_DEFAULT entries */
	uint_t		ips_ipv6_ire_default_index;
			/* Walking IPv6 index used to mod in */

	uint_t		ips_loopback_packets;

	/* NDP/NCE structures for IPv4 and IPv6 */
	struct ndp_g_s	*ips_ndp4;
	struct ndp_g_s	*ips_ndp6;

	/* ip_mroute stuff */
	kmutex_t	ips_ip_g_mrouter_mutex;

	struct mrtstat	*ips_mrtstat;	/* Stats for netstat */
	int		ips_saved_ip_g_forward;

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

	uint_t		ips_ipif_src_random;

	struct idl_s	*ips_conn_drain_list;	/* Array of conn drain lists */
	uint_t		ips_conn_drain_list_cnt; /* Count of conn_drain_list */
	int		ips_conn_drain_list_index; /* Next drain_list */

	/*
	 * ID used to assign next free one.
	 * Increases by one. Once it wraps we search for an unused ID.
	 */
	uint_t		ips_ip_src_id;
	boolean_t	ips_srcid_wrapped;

	struct srcid_map *ips_srcid_head;
	krwlock_t	ips_srcid_lock;

	uint64_t	ips_ipif_g_seqid;
	union phyint_list_u *ips_phyint_g_list;	/* start of phyint list */

	/*
	 * Reflects value of FAILBACK variable in IPMP config file
	 * /etc/default/mpathd. Default value is B_TRUE.
	 * Set to B_FALSE if user disabled failback by configuring
	 * "FAILBACK=no" in.mpathd uses SIOCSIPMPFAILBACK ioctl to pass this
	 * information to kernel.
	 */
	boolean_t ips_ipmp_enable_failback;

/* ip_neti.c */
	hook_family_t	ips_ipv4root;
	hook_family_t	ips_ipv6root;

	/*
	 * Hooks for firewalling
	 */
	hook_event_t		ips_ip4_physical_in_event;
	hook_event_t		ips_ip4_physical_out_event;
	hook_event_t		ips_ip4_forwarding_event;
	hook_event_t		ips_ip4_loopback_in_event;
	hook_event_t		ips_ip4_loopback_out_event;
	hook_event_t		ips_ip4_nic_events;
	hook_event_t		ips_ip6_physical_in_event;
	hook_event_t		ips_ip6_physical_out_event;
	hook_event_t		ips_ip6_forwarding_event;
	hook_event_t		ips_ip6_loopback_in_event;
	hook_event_t		ips_ip6_loopback_out_event;
	hook_event_t		ips_ip6_nic_events;

	hook_event_token_t	ips_ipv4firewall_physical_in;
	hook_event_token_t	ips_ipv4firewall_physical_out;
	hook_event_token_t	ips_ipv4firewall_forwarding;
	hook_event_token_t	ips_ipv4firewall_loopback_in;
	hook_event_token_t	ips_ipv4firewall_loopback_out;
	hook_event_token_t	ips_ipv4nicevents;
	hook_event_token_t	ips_ipv6firewall_physical_in;
	hook_event_token_t	ips_ipv6firewall_physical_out;
	hook_event_token_t	ips_ipv6firewall_forwarding;
	hook_event_token_t	ips_ipv6firewall_loopback_in;
	hook_event_token_t	ips_ipv6firewall_loopback_out;
	hook_event_token_t	ips_ipv6nicevents;

	net_data_t		ips_ipv4_net_data;
	net_data_t		ips_ipv6_net_data;
};
typedef struct ip_stack ip_stack_t;

/* Finding an ip_stack_t */
#define	CONNQ_TO_IPST(_q)	(Q_TO_CONN(_q)->conn_netstack->netstack_ip)
#define	ILLQ_TO_IPST(_q)	(((ill_t *)(_q)->q_ptr)->ill_ipst)

#else /* _KERNEL */
typedef int ip_stack_t;
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_STACK_H */
