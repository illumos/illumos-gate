/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef	__IPF_STACK_H__
#define	__IPF_STACK_H__

/* FIXME: appears needed for ip_proxy.h - tcpseq */
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcpip.h>

#include "ip_compat.h"
#include "ip_fil.h"
#include "ip_nat.h"
#include "ip_frag.h"
#include "ip_state.h"
#include "ip_proxy.h"
#include "ip_auth.h"
#include "ip_lookup.h"
#include "ip_pool.h"
#include "ip_htable.h"
#include <net/radix.h>
#include <sys/neti.h>
#include <sys/hook.h>

/*
 * IPF stack instances
 */
struct ipf_stack {
	struct ipf_stack	*ifs_next;
	struct ipf_stack	**ifs_pnext;
	struct ipf_stack	*ifs_gz_cont_ifs;
	netid_t			ifs_netid;
	zoneid_t		ifs_zone;
	boolean_t		ifs_gz_controlled;

	/* ipf module */
	fr_info_t		ifs_frcache[2][8];

	filterstats_t		ifs_frstats[2];
	frentry_t		*ifs_ipfilter[2][2];
	frentry_t		*ifs_ipfilter6[2][2];
	frentry_t		*ifs_ipacct6[2][2];
	frentry_t		*ifs_ipacct[2][2];
#if 0 /* not used */
	frentry_t		*ifs_ipnatrules[2][2];
#endif
	frgroup_t		*ifs_ipfgroups[IPL_LOGSIZE][2];
	int			ifs_fr_refcnt;
	/*
	 * For fr_running:
	 * 0 == loading, 1 = running, -1 = disabled, -2 = unloading
	 */
	int			ifs_fr_running;
	int			ifs_fr_flags;
	int			ifs_fr_active;
	int			ifs_fr_control_forwarding;
	int			ifs_fr_update_ipid;
#if 0
	ushort_t		ifs_fr_ip_id;
#endif
	int			ifs_fr_chksrc;
	int			ifs_fr_minttl;
	int			ifs_fr_icmpminfragmtu;
	int			ifs_fr_pass;
	ulong_t			ifs_fr_frouteok[2];
	ulong_t			ifs_fr_userifqs;
	ulong_t			ifs_fr_badcoalesces[2];
	uchar_t			ifs_ipf_iss_secret[32];
	timeout_id_t		ifs_fr_timer_id;
#if 0
	timeout_id_t		ifs_synctimeoutid;
#endif
	int			ifs_ipf_locks_done;

	ipftoken_t 		*ifs_ipftokenhead;
	ipftoken_t 		**ifs_ipftokentail;

	ipfmutex_t	ifs_ipl_mutex;
	ipfmutex_t	ifs_ipf_authmx;
	ipfmutex_t	ifs_ipf_rw;
	ipfmutex_t	ifs_ipf_timeoutlock;
	ipfrwlock_t	ifs_ipf_mutex;
	ipfrwlock_t	ifs_ipf_global;
	ipfrwlock_t	ifs_ipf_frcache;
	ipfrwlock_t	ifs_ip_poolrw;
	ipfrwlock_t	ifs_ipf_frag;
	ipfrwlock_t	ifs_ipf_state;
	ipfrwlock_t	ifs_ipf_nat;
	ipfrwlock_t	ifs_ipf_natfrag;
	ipfmutex_t	ifs_ipf_nat_new;
	ipfmutex_t	ifs_ipf_natio;
	ipfrwlock_t	ifs_ipf_auth;
	ipfmutex_t	ifs_ipf_stinsert;
	ipfrwlock_t	ifs_ipf_ipidfrag;
	ipfrwlock_t	ifs_ipf_tokens;
	kcondvar_t	ifs_iplwait;
	kcondvar_t	ifs_ipfauthwait;

	ipftuneable_t	*ifs_ipf_tuneables;
	ipftuneable_t	*ifs_ipf_tunelist;

	/* ip_fil_solaris.c */
	hook_t		*ifs_ipfhook4_in;
	hook_t		*ifs_ipfhook4_out;
	hook_t		*ifs_ipfhook4_loop_in;
	hook_t		*ifs_ipfhook4_loop_out;
	hook_t		*ifs_ipfhook4_nicevents;
	hook_t		*ifs_ipfhook6_in;
	hook_t		*ifs_ipfhook6_out;
	hook_t		*ifs_ipfhook6_loop_in;
	hook_t		*ifs_ipfhook6_loop_out;
	hook_t		*ifs_ipfhook6_nicevents;

	/* flags to indicate whether hooks are registered. */
	boolean_t	ifs_hook4_physical_in;
	boolean_t	ifs_hook4_physical_out;
	boolean_t	ifs_hook4_nic_events;
	boolean_t	ifs_hook4_loopback_in;
	boolean_t	ifs_hook4_loopback_out;
	boolean_t	ifs_hook6_physical_in;
	boolean_t	ifs_hook6_physical_out;
	boolean_t	ifs_hook6_nic_events;
	boolean_t	ifs_hook6_loopback_in;
	boolean_t	ifs_hook6_loopback_out;

	int		ifs_ipf_loopback;
	net_handle_t	ifs_ipf_ipv4;
	net_handle_t	ifs_ipf_ipv6;

	/* ip_auth.c */
	int			ifs_fr_authsize;
	int			ifs_fr_authused;
	int			ifs_fr_defaultauthage;
	int			ifs_fr_auth_lock;
	int			ifs_fr_auth_init;
	fr_authstat_t		ifs_fr_authstats;
	frauth_t		*ifs_fr_auth;
	mb_t			**ifs_fr_authpkts;
	int			ifs_fr_authstart;
	int			ifs_fr_authend;
	int			ifs_fr_authnext;
	frauthent_t		*ifs_fae_list;
	frentry_t		*ifs_ipauth;
	frentry_t		*ifs_fr_authlist;

	/* ip_frag.c */
	ipfr_t			*ifs_ipfr_list;
	ipfr_t			**ifs_ipfr_tail;
	ipfr_t			**ifs_ipfr_heads;

	ipfr_t			*ifs_ipfr_natlist;
	ipfr_t			**ifs_ipfr_nattail;
	ipfr_t			**ifs_ipfr_nattab;

	ipfr_t  		*ifs_ipfr_ipidlist;
	ipfr_t  		**ifs_ipfr_ipidtail;
	ipfr_t			**ifs_ipfr_ipidtab;

	ipfrstat_t		ifs_ipfr_stats;
	int			ifs_ipfr_inuse;
	int			ifs_ipfr_size;

	int			ifs_fr_ipfrttl;
	int			ifs_fr_frag_lock;
	int			ifs_fr_frag_init;
	ulong_t			ifs_fr_ticks;

	frentry_t		ifs_frblock;

	/* ip_htable.c */
	iphtable_t		*ifs_ipf_htables[IPL_LOGSIZE];
	ulong_t			ifs_ipht_nomem[IPL_LOGSIZE];
	ulong_t			ifs_ipf_nhtables[IPL_LOGSIZE];
	ulong_t			ifs_ipf_nhtnodes[IPL_LOGSIZE];

	/* ip_log.c */
	iplog_t			**ifs_iplh[IPL_LOGSIZE];
	iplog_t			*ifs_iplt[IPL_LOGSIZE];
	iplog_t			*ifs_ipll[IPL_LOGSIZE];
	int			ifs_iplused[IPL_LOGSIZE];
	fr_info_t		ifs_iplcrc[IPL_LOGSIZE];
	int			ifs_ipl_suppress;
	int			ifs_ipl_buffer_sz;
	int			ifs_ipl_logmax;
	int			ifs_ipl_logall;
	int			ifs_ipl_log_init;
	int			ifs_ipl_logsize;

	/* ip_lookup.c */
	ip_pool_stat_t		ifs_ippoolstat;
	int			ifs_ip_lookup_inited;

	/* ip_nat.c */
	/* nat_table[0] -> hashed list sorted by inside (ip, port) */
	/* nat_table[1] -> hashed list sorted by outside (ip, port) */
	nat_t			**ifs_nat_table[2];
	nat_t			*ifs_nat_instances;
	ipnat_t			*ifs_nat_list;
	uint_t			ifs_ipf_nattable_sz;
	uint_t			ifs_ipf_nattable_max;
	uint_t			ifs_ipf_natrules_sz;
	uint_t			ifs_ipf_rdrrules_sz;
	uint_t			ifs_ipf_hostmap_sz;
	uint_t			ifs_fr_nat_maxbucket;
	uint_t			ifs_fr_nat_maxbucket_reset;
	uint32_t		ifs_nat_masks;
	uint32_t		ifs_rdr_masks;
	uint32_t		ifs_nat6_masks[4];
	uint32_t		ifs_rdr6_masks[4];
	ipnat_t			**ifs_nat_rules;
	ipnat_t			**ifs_rdr_rules;
	hostmap_t		**ifs_maptable;
	hostmap_t		*ifs_ipf_hm_maplist;

	ipftq_t			ifs_nat_tqb[IPF_TCP_NSTATES];
	ipftq_t			ifs_nat_udptq;
	ipftq_t			ifs_nat_icmptq;
	ipftq_t			ifs_nat_iptq;
	ipftq_t			*ifs_nat_utqe;
	int			ifs_nat_logging;
	ulong_t			ifs_fr_defnatage;
	ulong_t			ifs_fr_defnatipage;
	ulong_t			ifs_fr_defnaticmpage;
	natstat_t		ifs_nat_stats;
	int			ifs_fr_nat_lock;
	int			ifs_fr_nat_init;
	uint_t			ifs_nat_flush_level_hi;
	uint_t			ifs_nat_flush_level_lo;
	ulong_t			ifs_nat_last_force_flush;
	int			ifs_nat_doflush;

	/* ip_pool.c */
	ip_pool_stat_t		ifs_ipoolstat;
	ip_pool_t		*ifs_ip_pool_list[IPL_LOGSIZE];

	/* ip_proxy.c */
	ap_session_t		*ifs_ap_sess_list;
	aproxy_t		*ifs_ap_proxylist;
	aproxy_t		*ifs_ap_proxies; /* copy of lcl_ap_proxies */

	/* ip_state.c */
	ipstate_t		**ifs_ips_table;
	ulong_t			*ifs_ips_seed;
	int			ifs_ips_num;
	ulong_t			ifs_ips_last_force_flush;
	uint_t			ifs_state_flush_level_hi;
	uint_t			ifs_state_flush_level_lo;
	ips_stat_t		ifs_ips_stats;

	ulong_t			ifs_fr_tcpidletimeout;
	ulong_t			ifs_fr_tcpclosewait;
	ulong_t			ifs_fr_tcplastack;
	ulong_t			ifs_fr_tcptimeout;
	ulong_t			ifs_fr_tcpclosed;
	ulong_t			ifs_fr_tcphalfclosed;
	ulong_t			ifs_fr_udptimeout;
	ulong_t			ifs_fr_udpacktimeout;
	ulong_t			ifs_fr_icmptimeout;
	ulong_t			ifs_fr_icmpacktimeout;
	int			ifs_fr_statemax;
	int			ifs_fr_statesize;
	int			ifs_fr_state_doflush;
	int			ifs_fr_state_lock;
	int			ifs_fr_state_maxbucket;
	int			ifs_fr_state_maxbucket_reset;
	int			ifs_fr_state_init;
	int			ifs_fr_enable_active;
	ipftq_t			ifs_ips_tqtqb[IPF_TCP_NSTATES];
	ipftq_t			ifs_ips_udptq;
	ipftq_t			ifs_ips_udpacktq;
	ipftq_t			ifs_ips_iptq;
	ipftq_t			ifs_ips_icmptq;
	ipftq_t			ifs_ips_icmpacktq;
	ipftq_t			ifs_ips_deletetq;
	ipftq_t			*ifs_ips_utqe;
	int			ifs_ipstate_logging;
	ipstate_t		*ifs_ips_list;
	ulong_t			ifs_fr_iptimeout;

	/* radix.c */
	int			ifs_max_keylen;
	struct radix_mask	*ifs_rn_mkfreelist;
	struct radix_node_head	*ifs_mask_rnhead;
	char			*ifs_addmask_key;
	char			*ifs_rn_zeros;
	char			*ifs_rn_ones;
#ifdef KERNEL
	/* kstats for inbound and outbound */
	kstat_t			*ifs_kstatp[2];
#endif
};

#endif	/* __IPF_STACK_H__ */
