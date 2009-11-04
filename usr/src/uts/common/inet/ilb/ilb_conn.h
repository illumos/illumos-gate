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

#ifndef _INET_ILB_CONN_H
#define	_INET_ILB_CONN_H

#ifdef __cplusplus
extern "C" {
#endif

struct ilb_conn_s;

/*
 * Struct of the conn hash table bucket
 *
 * ilb_connp: the first conn hash entry in the bucket
 * ilb_conn_hash_lock: mutex to protect the list in the bucket
 * ilb_conn_cnt: number of conn hash entries in this bucket
 */
typedef struct ilb_conn_hash_s {
	struct ilb_conn_s	*ilb_connp;
	kmutex_t		ilb_conn_hash_lock;
	uint32_t		 ilb_conn_cnt;
#if defined(_LP64) || defined(_I32LPx)
	char			ilb_conn_hash_pad[44];
#else
	char			ilb_conn_hash_pad[52];
#endif
} ilb_conn_hash_t;

/*
 * Extracted rule/server info for faster access without holding a reference
 * to a rule or server.
 */
typedef struct ilb_rule_info_s {
	ilb_topo_impl_t		topo;
	ilb_nat_info_t		info;
} ilb_rule_info_t;

/* Info about a TCP connection for tracking */
struct ilb_tcp_track {
	uint32_t		ack;
	uint32_t		fss;
	boolean_t		fin_sent;
	boolean_t		fin_acked;
};

/*
 * Struct to store NAT info of a connection (one direction)
 *
 * conn_daddr: destination address to be matched to find this info
 * conn_saddr: source address to be matched
 * conn_dport: destination port to be matched
 * conn_sport: source port to be matched
 * conn_ip_sum: IP checksum adjustment for NAT
 * conn_tp_sum: tranport checksum adjustment for NAT
 * conn_tcp_track: TCP connection tracking info
 * conn_atime: last access time of this conn cache
 * conn_pkt_cnt: packets processed using this conn
 * conn_next: next conn info (for conn info linked list)
 * conn_prev: previous conn info (for conn info linked list)
 * conn_hash: back pointer to the conn hash table bucket
 */
struct ilb_conn_info {
	in6_addr_t		conn_daddr;
	in6_addr_t		conn_saddr;
	in_port_t		conn_dport;
	in_port_t		conn_sport;
	uint32_t		conn_ip_sum;
	uint32_t		conn_tp_sum;

	struct ilb_tcp_track	conn_tcp_track;

	/* Last access time */
	int64_t			conn_atime;
	uint64_t		conn_pkt_cnt;

	struct ilb_conn_s	*conn_next;
	struct ilb_conn_s	*conn_prev;
	ilb_conn_hash_t		*conn_hash;
};

/*
 * Struct (an entry in the conn hash table) to store a NAT info of a
 * connection (both directions, client to server and server to client)
 *
 * conn_l4: transport protocol used in this NAT connection
 * conn_expry: expiry time of this entry
 * conn_cr_time: creation time of this entry
 * conn_c2s: client to back end server info
 * conn_s2c_ back end server to client info
 * conn_server: pointer to the back end server structure
 * conn_rule_cache: rule information needed for this entry (copied from
 *                  the ilb_rule_t struct)
 * conn_sticky: pointer to the sticky info of this client, used to do
 *              reference counting on the sticky info.
 * conn_gc: indicates whether this entry needs to be garbage collected
 */
typedef struct ilb_conn_s {
	int			conn_l4;

	int64_t			conn_expiry;
	int64_t			conn_cr_time;

	/* Client to server, hash and check info */
	struct ilb_conn_info	conn_c2s;
#define	conn_c2s_daddr		conn_c2s.conn_daddr
#define	conn_c2s_saddr		conn_c2s.conn_saddr
#define	conn_c2s_dport		conn_c2s.conn_dport
#define	conn_c2s_sport		conn_c2s.conn_sport
#define	conn_c2s_next		conn_c2s.conn_next
#define	conn_c2s_prev		conn_c2s.conn_prev
#define	conn_c2s_hash		conn_c2s.conn_hash
#define	conn_c2s_atime		conn_c2s.conn_atime
#define	conn_c2s_pkt_cnt	conn_c2s.conn_pkt_cnt
#define	conn_c2s_ip_sum		conn_c2s.conn_ip_sum
#define	conn_c2s_tp_sum		conn_c2s.conn_tp_sum
#define	conn_c2s_tcp_ack	conn_c2s.conn_tcp_track.ack
#define	conn_c2s_tcp_fss	conn_c2s.conn_tcp_track.fss
#define	conn_c2s_tcp_fin_sent	conn_c2s.conn_tcp_track.fin_sent
#define	conn_c2s_tcp_fin_acked	conn_c2s.conn_tcp_track.fin_acked

	/* Server to client, hash and check info */
	struct ilb_conn_info	conn_s2c;
#define	conn_s2c_daddr		conn_s2c.conn_daddr
#define	conn_s2c_saddr		conn_s2c.conn_saddr
#define	conn_s2c_dport		conn_s2c.conn_dport
#define	conn_s2c_sport		conn_s2c.conn_sport
#define	conn_s2c_next		conn_s2c.conn_next
#define	conn_s2c_prev		conn_s2c.conn_prev
#define	conn_s2c_hash		conn_s2c.conn_hash
#define	conn_s2c_atime		conn_s2c.conn_atime
#define	conn_s2c_pkt_cnt	conn_s2c.conn_pkt_cnt
#define	conn_s2c_ip_sum		conn_s2c.conn_ip_sum
#define	conn_s2c_tp_sum		conn_s2c.conn_tp_sum
#define	conn_s2c_tcp_ack	conn_s2c.conn_tcp_track.ack
#define	conn_s2c_tcp_fss	conn_s2c.conn_tcp_track.fss
#define	conn_s2c_tcp_fin_sent	conn_s2c.conn_tcp_track.fin_sent
#define	conn_s2c_tcp_fin_acked	conn_s2c.conn_tcp_track.fin_acked

	ilb_server_t		*conn_server;
	ilb_rule_info_t		conn_rule_cache;

	/*
	 * If the rule is sticky enabled, all ilb_conn_t created from this
	 * rule will have conn_sticky set to the ilb_sticky_t entry.  Otherwise
	 * conn_sticky is NULL.
	 */
	struct ilb_sticky_s	*conn_sticky;

	boolean_t		conn_gc;
} ilb_conn_t;

/*
 * Struct of the sticky hash table bucket
 *
 * sticky_head: the sticky hash list of this bucket
 * sticky_lock: mutex to protect the list
 * sticki_cnt: number of sticky hash entries in this bucket
 */
typedef struct ilb_sticky_hash_s {
	list_t			sticky_head;
	kmutex_t		sticky_lock;
	uint32_t		sticky_cnt;
#if defined(_LP64) || defined(_I32LPx)
	char			sticky_pad[20];
#else
	char			sticky_pad[36];
#endif
} ilb_sticky_hash_t;

/*
 * Struct to store sticky info of a client.
 *
 * rule_instance: the rule instance for this entry, for look up purpose
 * rule_name: the rule name for this entry
 * server: the back end server for this client
 * src: the client source address
 * expire: the expiry time of this entry
 * atime: the last access time of this entry
 * nat_src_idx: the index to the NAT source array for this client
 * refcnt: reference count
 * list: linked list node
 * hash: back pointer to the sticky hash buckey of this entry
 */
typedef struct ilb_sticky_s {
	uint_t			rule_instance;
	char			rule_name[ILB_RULE_NAMESZ];
	ilb_server_t		*server;
	in6_addr_t		src;
	int64_t			expiry;
	int64_t			atime;
	int			nat_src_idx;

	uint32_t		refcnt;
	list_node_t		list;
	ilb_sticky_hash_t	*hash;
} ilb_sticky_t;

extern void ilb_conn_hash_init(ilb_stack_t *);
extern void ilb_conn_hash_fini(ilb_stack_t *);
extern void ilb_conn_cache_fini(void);
extern void ilb_sticky_hash_init(ilb_stack_t *);
extern void ilb_sticky_hash_fini(ilb_stack_t *);
extern void ilb_sticky_cache_fini(void);

extern boolean_t ilb_check_conn(ilb_stack_t *, int, void *, int, void *,
    in6_addr_t *, in6_addr_t *, in_port_t, in_port_t, uint32_t, in6_addr_t *);
extern boolean_t ilb_check_icmp_conn(ilb_stack_t *, mblk_t *, int, void *,
    void *, in6_addr_t *);
extern int ilb_conn_add(ilb_stack_t *, ilb_rule_t *, ilb_server_t *,
    in6_addr_t *, in_port_t, in6_addr_t *, in_port_t, ilb_nat_info_t *,
    uint32_t *, uint32_t *, struct ilb_sticky_s *);

extern ilb_server_t *ilb_sticky_find_add(ilb_stack_t *, ilb_rule_t *,
    in6_addr_t *, ilb_server_t *, struct ilb_sticky_s **, uint16_t *);
void ilb_sticky_refrele(struct ilb_sticky_s *);

#ifdef __cplusplus
}
#endif

#endif /* _INET_ILB_CONN_H */
