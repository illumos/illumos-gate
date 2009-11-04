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

#ifndef _INET_ILB_IMPL_H
#define	_INET_ILB_IMPL_H

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/netstack.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Statistics in ILB is stored in several kstat structures.  ilb_g_kstat
 * represents the global statistics.  ilb_rule_kstat represents the statistics
 * of a rule.  ilb_server_kstat represents the statistics of a server.
 */
#define	ILB_KSTAT_MOD_NAME	"ilb"

typedef struct ilb_g_kstat_s {
	kstat_named_t	num_rules;	/* Number of rules */
	kstat_named_t	ip_frag_in;	/* Number of input fragments */
	kstat_named_t	ip_frag_dropped; /* Number of fragments dropped */
} ilb_g_kstat_t;

#define	ILB_KSTAT_UPDATE(ilbs, x, y)				\
{								\
	DTRACE_PROBE1(ilb__g__kstat__##x, ilb_stack_t *,	\
	    (ilbs));						\
	((ilbs)->ilbs_kstat->x.value.ui64 += (y));		\
}

typedef struct ilb_rule_kstat {
	kstat_named_t	num_servers;	/* Number of back end servers */
	kstat_named_t	bytes_not_processed; /* Num of bytes not processed. */
	kstat_named_t	pkt_not_processed; /* Num of packets not processed. */
	kstat_named_t	bytes_dropped;	/* Number of bytes dropped */
	kstat_named_t	pkt_dropped;	/* Number of packets dropped */
	kstat_named_t	nomem_bytes_dropped; /* Bytes dropped due to nomem */
	kstat_named_t	nomem_pkt_dropped; /* Packets dropped due to nomem */
	kstat_named_t	noport_bytes_dropped; /* No NAT sport bytes drop */
	kstat_named_t	noport_pkt_dropped; /* No NAT sport packet drop */
	kstat_named_t	icmp_echo_processed; /* No of ICMP echo processed */
	kstat_named_t	icmp_dropped;	/* No of ICMP packets dropped */
	kstat_named_t	icmp_2big_processed; /* No of ICMP 2big processed */
	kstat_named_t	icmp_2big_dropped; /* No of ICMP 2big dropped */
} ilb_rule_kstat_t;

#define	ILB_R_KSTAT(rule, x)					\
{								\
	DTRACE_PROBE1(ilb__r__kstat__##x, ilb_rule_t *,	\
	    (rule));						\
	((rule)->ir_kstat.x.value.ui64++);			\
}
#define	ILB_R_KSTAT_UPDATE(rule, x, y) 				\
{								\
	DTRACE_PROBE1(ilb__r__kstat__##x, ilb_rule_t *,	\
	    (rule));						\
	((rule)->ir_kstat.x.value.ui64 += (y));			\
}

typedef struct ilb_server_kstat {
	kstat_named_t	bytes_processed; /* Number of bytes processed */
	kstat_named_t	pkt_processed;	/* Number of packets processed */
	kstat_named_t	ip_address;	/* IP address of the server */
} ilb_server_kstat_t;

#define	ILB_S_KSTAT(host, x)					\
{								\
	DTRACE_PROBE1(ilb__s__kstat__##x, ilb_server_t *,	\
	    (host));						\
	((host)->iser_kstat.x.value.ui64++);			\
}
#define	ILB_S_KSTAT_UPDATE(host, x, y)				\
{								\
	DTRACE_PROBE1(ilb__s__kstat__##x, ilb_server_t *,	\
	    (host));						\
	((host)->iser_kstat.x.value.ui64 += (y));		\
}

/* The maximum port range, meaning all ports (65535 - 1). */
#define	ILB_ALL_PORTS_RANGE	65534

struct ilb_nat_src_s;

/*
 * This structure reprensents a server.
 */
typedef struct ilb_server_s {
	in6_addr_t		iser_addr_v6;
	in6_addr_t		iser_prefix_v6;
#define	iser_addr_v4		iser_addr_v6.s6_addr32[3]
#define	iser_prefix_v4		iser_prefix_v6.s6_addr32[3]

	boolean_t		iser_port_range;
	in_port_t		iser_min_port;	/* In host byte order */
	in_port_t		iser_max_port;

	char			iser_name[ILB_SERVER_NAMESZ];
	char			iser_ip_addr[INET6_ADDRSTRLEN];
	netstackid_t		iser_stackid;
	kstat_t			*iser_ksp;
	ilb_server_kstat_t	iser_kstat;
	struct ilb_server_s	*iser_next;

	boolean_t		iser_enabled;
	kmutex_t		iser_lock;
	kcondvar_t		iser_cv;
	uint64_t		iser_refcnt;

	int64_t			iser_die_time;

	struct ilb_nat_src_s	*iser_nat_src;
} ilb_server_t;

#define	ILB_SERVER_REFHOLD(host)	\
{					\
	mutex_enter(&(host)->iser_lock);	\
	(host)->iser_refcnt++;		\
	ASSERT((host)->iser_refcnt != 1);	\
	mutex_exit(&(host)->iser_lock);	\
}

#define	ILB_SERVER_REFRELE(host)		\
{						\
	mutex_enter(&(host)->iser_lock);		\
	(host)->iser_refcnt--;			\
	if ((host)->iser_refcnt == 1)		\
		cv_signal(&(host)->iser_cv);	\
	mutex_exit(&(host)->iser_lock);		\
}

struct ilb_rule_s;
struct ilb_hash_s;

typedef struct ilb_alg_data_s {
	boolean_t	(*ilb_alg_lb)(in6_addr_t *, in_port_t, in6_addr_t *,
			    in_port_t, void *, ilb_server_t **);
	int		(*ilb_alg_server_add)(ilb_server_t *, void *);
	int		(*ilb_alg_server_del)(ilb_server_t *, void *);
	int		(*ilb_alg_server_enable)(ilb_server_t *, void *);
	int		(*ilb_alg_server_disable)(ilb_server_t *, void *);
	void		(*ilb_alg_fini)(struct ilb_alg_data_s **);

	void		*ilb_alg_data;
} ilb_alg_data_t;

/*
 * A load balance rule has
 *
 * 1. a name
 * 2. a network protocol
 * 3. a transport protocol
 * 4. a load balance mechanism (DSR, NAT, ...)
 * 5. a target address (VIP)
 * 6. a target port (or port ranges)
 * 7. a pool of back end servers
 * 8. a load balance algorithm (round robin, hashing, ...)
 */
typedef struct ilb_rule_s {
	char			ir_name[ILB_RULE_NAMESZ];
	uint8_t			ir_ipver;
	uint8_t			ir_proto;
	ilb_topo_impl_t		ir_topo;
	zoneid_t		ir_zoneid;
	uint32_t		ir_flags;

	in6_addr_t		ir_target_v6;
#define	ir_target_v4		ir_target_v6.s6_addr32[3]
	in6_addr_t		ir_prefix_v6;
#define	ir_target_prefix_v4	ir_prefix_v6.s6_addr32[3]

	boolean_t		ir_port_range;
	in_port_t		ir_min_port;	/* In host byte order */
	in_port_t		ir_max_port;

	ilb_server_t		*ir_servers;

	uint32_t		ir_nat_expiry;
	uint32_t		ir_conn_drain_timeout;
	in6_addr_t		ir_nat_src_start;
	in6_addr_t		ir_nat_src_end;

	boolean_t		ir_sticky;
	in6_addr_t		ir_sticky_mask;
	uint32_t		ir_sticky_expiry;

	struct ilb_rule_s	*ir_next;

	struct ilb_rule_s	*ir_hash_next;
	struct ilb_rule_s	*ir_hash_prev;
	struct ilb_hash_s	*ir_hash;

	ilb_algo_impl_t		ir_alg_type;
	ilb_alg_data_t		*ir_alg;

	kstat_t			*ir_ksp;
	ilb_rule_kstat_t	ir_kstat;
	uint_t			ir_ks_instance;

	kmutex_t		ir_lock;
	kcondvar_t		ir_cv;
	uint32_t		ir_refcnt;
} ilb_rule_t;

#define	ILB_RULE_REFHOLD(rule)			\
{						\
	mutex_enter(&(rule)->ir_lock);		\
	(rule)->ir_refcnt++;			\
	ASSERT((rule)->ir_refcnt != 1);		\
	mutex_exit(&(rule)->ir_lock);		\
}

#define	ILB_RULE_REFRELE(rule)			\
{						\
	mutex_enter(&(rule)->ir_lock);		\
	ASSERT((rule)->ir_refcnt >= 2);		\
	if (--(rule)->ir_refcnt <= 2)		\
		cv_signal(&(rule)->ir_cv);	\
	mutex_exit(&(rule)->ir_lock);		\
}


typedef struct ilb_hash_s {
	ilb_rule_t	*ilb_hash_rule;
	kmutex_t	ilb_hash_lock;
#if defined(_LP64) || defined(_I32LPx)
	char		ilb_hash_pad[48];
#else
	char		ilb_hash_pad[56];
#endif
} ilb_hash_t;

struct ilb_nat_src_entry_s;

/*
 * Structure to store NAT info.
 *
 * Half NAT only uses the first 4 fields in the structure.
 */
typedef struct {
	in6_addr_t			vip;
	in6_addr_t			nat_dst;
	in_port_t			dport;
	in_port_t			nat_dport;

	in6_addr_t			src;
	in6_addr_t			nat_src;
	in_port_t			sport;
	in_port_t			nat_sport;

	struct ilb_nat_src_entry_s	*src_ent;
} ilb_nat_info_t;

extern int ilb_kmem_flags;

#ifdef __cplusplus
}
#endif

#endif /* _INET_ILB_IMPL_H */
