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

#ifndef	_INET_IPCLASSIFIER_H
#define	_INET_IPCLASSIFIER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/tcp.h>
#include <inet/ip6.h>
#include <netinet/in.h>		/* for IPPROTO_* constants */
#include <sys/sdt.h>
#include <sys/socket_proto.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>

typedef void (*edesc_spf)(void *, mblk_t *, void *, int);
typedef void (*edesc_rpf)(void *, mblk_t *, void *);

/*
 * ==============================
 * =	The CONNECTION		=
 * ==============================
 */

/*
 * The connection structure contains the common information/flags/ref needed.
 * Implementation will keep the connection struct, the layers (with their
 * respective data for event i.e. tcp_t if event was tcp_input) all in one
 * contiguous memory location.
 */

/* Conn Flags */
/* Unused			0x00020000 */
/* Unused			0x00040000 */
#define	IPCL_FULLY_BOUND	0x00080000	/* Bound to correct squeue */
#define	IPCL_CHECK_POLICY	0x00100000	/* Needs policy checking */
#define	IPCL_SOCKET		0x00200000	/* Sockfs connection */
#define	IPCL_ACCEPTOR		0x00400000	/* Sockfs priv acceptor */
#define	IPCL_CL_LISTENER	0x00800000	/* Cluster listener */
#define	IPCL_EAGER		0x01000000	/* Incoming connection */
/* Unused			0x02000000 */
#define	IPCL_TCP6		0x04000000	/* AF_INET6 TCP */
#define	IPCL_TCP4		0x08000000	/* IPv4 packet format TCP */
/* Unused			0x10000000 */
/* Unused			0x20000000 */
#define	IPCL_CONNECTED		0x40000000	/* Conn in connected table */
#define	IPCL_BOUND		0x80000000	/* Conn in bind table */

/* Flags identifying the type of conn */
#define	IPCL_TCPCONN		0x00000001	/* From tcp_conn_cache */
#define	IPCL_SCTPCONN		0x00000002	/* From sctp_conn_cache */
#define	IPCL_IPCCONN		0x00000004	/* From ip_conn_cache */
#define	IPCL_UDPCONN		0x00000008	/* From udp_conn_cache */
#define	IPCL_RAWIPCONN		0x00000010	/* From rawip_conn_cache */
#define	IPCL_RTSCONN		0x00000020	/* From rts_conn_cache */
#define	IPCL_ISV6		0x00000040	/* AF_INET6 */
#define	IPCL_IPTUN		0x00000080	/* Has "tun" plumbed above it */
#define	IPCL_NONSTR		0x00001000	/* A non-STREAMS socket */
#define	IPCL_IN_SQUEUE		0x10000000	/* Waiting squeue to finish */

/* Conn Masks */
#define	IPCL_TCP		(IPCL_TCP4|IPCL_TCP6)
#define	IPCL_REMOVED		0x00000100
#define	IPCL_REUSED		0x00000200

/* The packet format is IPv4; could be an AF_INET or AF_INET6 socket */
#define	IPCL_IS_TCP4(connp)						\
	(((connp)->conn_flags & IPCL_TCP4))

/* Connected AF_INET with no IPsec policy */
#define	IPCL_IS_TCP4_CONNECTED_NO_POLICY(connp)				\
	(((connp)->conn_flags &						\
		(IPCL_TCP4|IPCL_CONNECTED|IPCL_CHECK_POLICY|IPCL_TCP6))	\
		== (IPCL_TCP4|IPCL_CONNECTED))

#define	IPCL_IS_CONNECTED(connp)					\
	((connp)->conn_flags & IPCL_CONNECTED)

#define	IPCL_IS_BOUND(connp)						\
	((connp)->conn_flags & IPCL_BOUND)

/* AF_INET TCP that is bound */
#define	IPCL_IS_TCP4_BOUND(connp)					\
	(((connp)->conn_flags &						\
		(IPCL_TCP4|IPCL_BOUND|IPCL_TCP6)) ==			\
		(IPCL_TCP4|IPCL_BOUND))

#define	IPCL_IS_FULLY_BOUND(connp)					\
	((connp)->conn_flags & IPCL_FULLY_BOUND)

/*
 * Can't use conn_protocol since we need to tell difference
 * between a real TCP socket and a SOCK_RAW, IPPROTO_TCP.
 */
#define	IPCL_IS_TCP(connp)						\
	((connp)->conn_flags & IPCL_TCPCONN)

#define	IPCL_IS_SCTP(connp)						\
	((connp)->conn_flags & IPCL_SCTPCONN)

#define	IPCL_IS_UDP(connp)						\
	((connp)->conn_flags & IPCL_UDPCONN)

#define	IPCL_IS_RAWIP(connp)						\
	((connp)->conn_flags & IPCL_RAWIPCONN)

#define	IPCL_IS_RTS(connp)						\
	((connp)->conn_flags & IPCL_RTSCONN)

/* FIXME: Isn't it sufficient to check IPCL_IPTUN? */
#define	IPCL_IS_IPTUN(connp)						\
	(((connp)->conn_ulp == IPPROTO_ENCAP ||				\
	(connp)->conn_ulp == IPPROTO_IPV6) &&				\
	((connp)->conn_flags & IPCL_IPTUN))

#define	IPCL_IS_NONSTR(connp)	((connp)->conn_flags & IPCL_NONSTR)

typedef struct connf_s connf_t;

typedef struct
{
	int	ctb_depth;
#define	CONN_STACK_DEPTH	15
	pc_t	ctb_stack[CONN_STACK_DEPTH];
} conn_trace_t;

typedef struct ip_helper_minor_info_s {
	dev_t	ip_minfo_dev;		/* Device */
	vmem_t	*ip_minfo_arena;	/* Arena */
} ip_helper_minfo_t;

/*
 * ip helper stream info
 */
typedef struct ip_helper_stream_info_s {
	ldi_handle_t		iphs_handle;
	queue_t 		*iphs_rq;
	queue_t 		*iphs_wq;
	ip_helper_minfo_t	*iphs_minfo;
} ip_helper_stream_info_t;

/*
 * The initial fields in the conn_t are setup by the kmem_cache constructor,
 * and are preserved when it is freed. Fields after that are bzero'ed when
 * the conn_t is freed.
 */
struct conn_s {
	kmutex_t	conn_lock;
	uint32_t	conn_ref;		/* Reference counter */
	uint32_t	conn_flags;		/* Conn Flags */


	union {
		tcp_t		*cp_tcp;	/* Pointer to the tcp struct */
		struct udp_s	*cp_udp;	/* Pointer to the udp struct */
		struct icmp_s	*cp_icmp;	/* Pointer to rawip struct */
		struct rts_s	*cp_rts;	/* Pointer to rts struct */
		void		*cp_priv;
	} conn_proto_priv;
#define	conn_tcp	conn_proto_priv.cp_tcp
#define	conn_udp	conn_proto_priv.cp_udp
#define	conn_icmp	conn_proto_priv.cp_icmp
#define	conn_rts	conn_proto_priv.cp_rts
#define	conn_priv	conn_proto_priv.cp_priv

	kcondvar_t	conn_cv;
	uint8_t		conn_ulp;		/* protocol type */

	edesc_rpf	conn_recv;		/* Pointer to recv routine */

	/* Fields after this are bzero'ed when the conn_t is freed. */

	squeue_t	*conn_sqp;		/* Squeue for processing */
	uint_t		conn_state_flags;	/* IP state flags */
#define	conn_start_clr	conn_state_flags

	ire_t		*conn_ire_cache; 	/* outbound ire cache */
	unsigned int
		conn_on_sqp : 1,		/* Conn is being processed */
		conn_dontroute : 1,		/* SO_DONTROUTE state */
		conn_loopback : 1,		/* SO_LOOPBACK state */
		conn_broadcast : 1,		/* SO_BROADCAST state */

		conn_reuseaddr : 1,		/* SO_REUSEADDR state */
		conn_multicast_loop : 1,	/* IP_MULTICAST_LOOP */
		conn_multi_router : 1,		/* Wants all multicast pkts */
		conn_draining : 1,		/* ip_wsrv running */

		conn_did_putbq : 1,		/* ip_wput did a putbq */
		conn_unspec_src : 1,		/* IP_UNSPEC_SRC */
		conn_policy_cached : 1,		/* Is policy cached/latched ? */
		conn_in_enforce_policy : 1,	/* Enforce Policy on inbound */

		conn_out_enforce_policy : 1,	/* Enforce Policy on outbound */
		conn_af_isv6 : 1,		/* ip address family ver 6 */
		conn_pkt_isv6 : 1,		/* ip packet format ver 6 */
		conn_ip_recvpktinfo : 1,	/* IPV*_RECVPKTINFO option */

		conn_ipv6_recvhoplimit : 1,	/* IPV6_RECVHOPLIMIT option */
		conn_ipv6_recvhopopts : 1,	/* IPV6_RECVHOPOPTS option */
		conn_ipv6_recvdstopts : 1,	/* IPV6_RECVDSTOPTS option */
		conn_ipv6_recvrthdr : 1,	/* IPV6_RECVRTHDR option */

		conn_ipv6_recvrtdstopts : 1,	/* IPV6_RECVRTHDRDSTOPTS */
		conn_ipv6_v6only : 1,		/* IPV6_V6ONLY */
		conn_ipv6_recvtclass : 1,	/* IPV6_RECVTCLASS */
		conn_ipv6_recvpathmtu : 1,	/* IPV6_RECVPATHMTU */

		conn_pathmtu_valid : 1,		/* The cached mtu is valid. */
		conn_ipv6_dontfrag : 1,		/* IPV6_DONTFRAG */
		conn_fully_bound : 1,		/* Fully bound connection */
		conn_recvif : 1,		/* IP_RECVIF option */

		conn_recvslla : 1,		/* IP_RECVSLLA option */
		conn_mdt_ok : 1,		/* MDT is permitted */
		conn_nexthop_set : 1,
		conn_allzones : 1;		/* SO_ALLZONES */

	unsigned int
		conn_lso_ok : 1;		/* LSO is usable */

	squeue_t	*conn_initial_sqp;	/* Squeue at open time */
	squeue_t	*conn_final_sqp;	/* Squeue after connect */
	ill_t		*conn_dhcpinit_ill;	/* IP_DHCPINIT_IF */
	ipsec_latch_t	*conn_latch;		/* latched state */
	ill_t		*conn_outgoing_ill;	/* IP{,V6}_BOUND_IF */
	edesc_spf	conn_send;		/* Pointer to send routine */
	queue_t		*conn_rq;		/* Read queue */
	queue_t		*conn_wq;		/* Write queue */
	dev_t		conn_dev;		/* Minor number */
	vmem_t		*conn_minor_arena;	/* Minor arena */
	ip_helper_stream_info_t *conn_helper_info;

	cred_t		*conn_cred;		/* Credentials */
	connf_t		*conn_g_fanout;		/* Global Hash bucket head */
	struct conn_s	*conn_g_next;		/* Global Hash chain next */
	struct conn_s	*conn_g_prev;		/* Global Hash chain prev */
	struct ipsec_policy_head_s *conn_policy; /* Configured policy */
	in6_addr_t	conn_bound_source_v6;
#define	conn_bound_source	V4_PART_OF_V6(conn_bound_source_v6)

	connf_t		*conn_fanout;		/* Hash bucket we're part of */
	struct conn_s	*conn_next;		/* Hash chain next */
	struct conn_s	*conn_prev;		/* Hash chain prev */
	struct {
		in6_addr_t connua_laddr;	/* Local address */
		in6_addr_t connua_faddr;	/* Remote address */
	} connua_v6addr;
#define	conn_src	V4_PART_OF_V6(connua_v6addr.connua_laddr)
#define	conn_rem	V4_PART_OF_V6(connua_v6addr.connua_faddr)
#define	conn_srcv6	connua_v6addr.connua_laddr
#define	conn_remv6	connua_v6addr.connua_faddr
	union {
		/* Used for classifier match performance */
		uint32_t		conn_ports2;
		struct {
			in_port_t	tcpu_fport;	/* Remote port */
			in_port_t	tcpu_lport;	/* Local port */
		} tcpu_ports;
	} u_port;
#define	conn_fport	u_port.tcpu_ports.tcpu_fport
#define	conn_lport	u_port.tcpu_ports.tcpu_lport
#define	conn_ports	u_port.conn_ports2
#define	conn_upq	conn_rq
	uint8_t		conn_unused_byte;

	uint_t		conn_proto;		/* SO_PROTOTYPE state */
	ill_t		*conn_incoming_ill;	/* IP{,V6}_BOUND_IF */
	ill_t		*conn_oper_pending_ill; /* pending shared ioctl */

	ilg_t	*conn_ilg;		/* Group memberships */
	int	conn_ilg_allocated;	/* Number allocated */
	int	conn_ilg_inuse;		/* Number currently used */
	int	conn_ilg_walker_cnt;	/* No of ilg walkers */
	/* XXXX get rid of this, once ilg_delete_all is fixed */
	kcondvar_t	conn_refcv;

	struct ipif_s	*conn_multicast_ipif;	/* IP_MULTICAST_IF */
	ill_t		*conn_multicast_ill;	/* IPV6_MULTICAST_IF */
	struct	conn_s	*conn_drain_next;	/* Next conn in drain list */
	struct	conn_s	*conn_drain_prev;	/* Prev conn in drain list */
	idl_t		*conn_idl;		/* Ptr to the drain list head */
	mblk_t		*conn_ipsec_opt_mp;	/* ipsec option mblk */
	uint32_t	conn_src_preferences;	/* prefs for src addr select */
	/* mtuinfo from IPV6_PACKET_TOO_BIG conditional on conn_pathmtu_valid */
	struct ip6_mtuinfo mtuinfo;
	zoneid_t	conn_zoneid;		/* zone connection is in */
	in6_addr_t	conn_nexthop_v6;	/* nexthop IP address */
	uchar_t		conn_broadcast_ttl; 	/* IP_BROADCAST_TTL */
#define	conn_nexthop_v4	V4_PART_OF_V6(conn_nexthop_v6)
	cred_t		*conn_peercred;		/* Peer credentials, if any */
	int		conn_rtaware; 		/* RT_AWARE sockopt value */
	kcondvar_t	conn_sq_cv;		/* For non-STREAMS socket IO */
	kthread_t	*conn_sq_caller;	/* Caller of squeue sync ops */
	sock_upcalls_t	*conn_upcalls;		/* Upcalls to sockfs */
	sock_upper_handle_t conn_upper_handle;	/* Upper handle: sonode * */

	unsigned int
		conn_ulp_labeled : 1,		/* ULP label is synced */
		conn_mlp_type : 2,		/* mlp_type_t; tsol/tndb.h */
		conn_anon_mlp : 1,		/* user wants anon MLP */

		conn_anon_port : 1,		/* user bound anonymously */
		conn_mac_exempt : 1,		/* unlabeled with loose MAC */
		conn_spare : 26;

	boolean_t	conn_flow_cntrld;
	netstack_t	*conn_netstack;	/* Corresponds to a netstack_hold */
#ifdef CONN_DEBUG
#define	CONN_TRACE_MAX	10
	int		conn_trace_last;	/* ndx of last used tracebuf */
	conn_trace_t	conn_trace_buf[CONN_TRACE_MAX];
#endif
};

#define	CONN_CRED(connp) ((connp)->conn_peercred == NULL ? \
	(connp)->conn_cred : (connp)->conn_peercred)
#define	BEST_CRED(mp, connp) ((DB_CRED(mp) != NULL &&	\
	crgetlabel(DB_CRED(mp)) != NULL) ? DB_CRED(mp) : CONN_CRED(connp))

/*
 * connf_t - connection fanout data.
 *
 * The hash tables and their linkage (conn_t.{hashnextp, hashprevp} are
 * protected by the per-bucket lock. Each conn_t inserted in the list
 * points back at the connf_t that heads the bucket.
 */
struct connf_s {
	struct conn_s	*connf_head;
	kmutex_t	connf_lock;
};

#define	CONN_INC_REF(connp)	{				\
	mutex_enter(&(connp)->conn_lock);			\
	DTRACE_PROBE1(conn__inc__ref, conn_t *, connp);		\
	ASSERT(conn_trace_ref(connp));				\
	(connp)->conn_ref++;					\
	ASSERT((connp)->conn_ref != 0);				\
	mutex_exit(&(connp)->conn_lock);			\
}

#define	CONN_INC_REF_LOCKED(connp)	{			\
	DTRACE_PROBE1(conn__inc__ref, conn_t *, connp);		\
	ASSERT(MUTEX_HELD(&(connp)->conn_lock));	 	\
	ASSERT(conn_trace_ref(connp));				\
	(connp)->conn_ref++;					\
	ASSERT((connp)->conn_ref != 0);				\
}

#define	CONN_DEC_REF(connp)	{					\
	mutex_enter(&(connp)->conn_lock);				\
	DTRACE_PROBE1(conn__dec__ref, conn_t *, connp);			\
	/*								\
	 * The squeue framework always does a CONN_DEC_REF after return	\
	 * from TCP. Hence the refcnt must be at least 2 if conn_on_sqp	\
	 * is B_TRUE and conn_ref is being decremented. This is to	\
	 * account for the mblk being currently processed.		\
	 */								\
	if ((connp)->conn_ref <= 0 ||					\
	    ((connp)->conn_ref == 1 && (connp)->conn_on_sqp))		\
		cmn_err(CE_PANIC, "CONN_DEC_REF: connp(%p) has ref "	\
			"= %d\n", (void *)(connp), (connp)->conn_ref);	\
	ASSERT(conn_untrace_ref(connp));				\
	(connp)->conn_ref--;						\
	if ((connp)->conn_ref == 0) {					\
		/* Refcnt can't increase again, safe to drop lock */	\
		mutex_exit(&(connp)->conn_lock);			\
		ipcl_conn_destroy(connp);				\
	} else {							\
		cv_broadcast(&(connp)->conn_cv);			\
		mutex_exit(&(connp)->conn_lock);			\
	}								\
}

/*
 * For use with subsystems within ip which use ALL_ZONES as a wildcard
 */
#define	IPCL_ZONEID(connp)						\
	((connp)->conn_allzones ? ALL_ZONES : (connp)->conn_zoneid)

/*
 * For matching between a conn_t and a zoneid.
 */
#define	IPCL_ZONE_MATCH(connp, zoneid) 					\
	(((connp)->conn_allzones) ||					\
	    ((zoneid) == ALL_ZONES) ||					\
	    (connp)->conn_zoneid == (zoneid))


#define	_IPCL_V4_MATCH(v6addr, v4addr)	\
	(V4_PART_OF_V6((v6addr)) == (v4addr) && IN6_IS_ADDR_V4MAPPED(&(v6addr)))

#define	_IPCL_V4_MATCH_ANY(addr)	\
	(IN6_IS_ADDR_V4MAPPED_ANY(&(addr)) || IN6_IS_ADDR_UNSPECIFIED(&(addr)))


/*
 * IPCL_PROTO_MATCH() only matches conns with the specified zoneid, while
 * IPCL_PROTO_MATCH_V6() can match other conns in the multicast case, see
 * ip_fanout_proto().
 */
#define	IPCL_PROTO_MATCH(connp, protocol, ipha, ill,			\
    fanout_flags, zoneid)						\
	((((connp)->conn_src == INADDR_ANY) ||				\
	(((connp)->conn_src == ((ipha)->ipha_dst)) &&			\
	    (((connp)->conn_rem == INADDR_ANY) ||			\
	((connp)->conn_rem == ((ipha)->ipha_src))))) &&			\
	IPCL_ZONE_MATCH(connp, zoneid) &&				\
	(conn_wantpacket((connp), (ill), (ipha), (fanout_flags), 	\
	    (zoneid)) || ((protocol) == IPPROTO_PIM) ||			\
	    ((protocol) == IPPROTO_RSVP)))

#define	IPCL_PROTO_MATCH_V6(connp, protocol, ip6h, ill,			   \
    fanout_flags, zoneid)						   \
	((IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_srcv6) ||		   \
	(IN6_ARE_ADDR_EQUAL(&(connp)->conn_srcv6, &((ip6h)->ip6_dst)) &&   \
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_remv6) ||		   \
	IN6_ARE_ADDR_EQUAL(&(connp)->conn_remv6, &((ip6h)->ip6_src))))) && \
	(conn_wantpacket_v6((connp), (ill), (ip6h),			   \
	(fanout_flags), (zoneid)) || ((protocol) == IPPROTO_RSVP)))

#define	IPCL_CONN_HASH(src, ports, ipst)				\
	((unsigned)(ntohl((src)) ^ ((ports) >> 24) ^ ((ports) >> 16) ^	\
	((ports) >> 8) ^ (ports)) % (ipst)->ips_ipcl_conn_fanout_size)

#define	IPCL_CONN_HASH_V6(src, ports, ipst)				\
	IPCL_CONN_HASH(V4_PART_OF_V6((src)), (ports), (ipst))

#define	IPCL_CONN_MATCH(connp, proto, src, dst, ports)			\
	((connp)->conn_ulp == (proto) &&				\
		(connp)->conn_ports == (ports) &&      			\
		_IPCL_V4_MATCH((connp)->conn_remv6, (src)) &&		\
		_IPCL_V4_MATCH((connp)->conn_srcv6, (dst)) &&		\
		!(connp)->conn_ipv6_v6only)

#define	IPCL_CONN_MATCH_V6(connp, proto, src, dst, ports)		\
	((connp)->conn_ulp == (proto) &&				\
		(connp)->conn_ports == (ports) &&      			\
		IN6_ARE_ADDR_EQUAL(&(connp)->conn_remv6, &(src)) &&	\
		IN6_ARE_ADDR_EQUAL(&(connp)->conn_srcv6, &(dst)))

#define	IPCL_CONN_INIT(connp, protocol, src, rem, ports) {		\
	(connp)->conn_ulp = protocol;					\
	IN6_IPADDR_TO_V4MAPPED(src, &(connp)->conn_srcv6);		\
	IN6_IPADDR_TO_V4MAPPED(rem, &(connp)->conn_remv6);		\
	(connp)->conn_ports = ports;					\
}

#define	IPCL_CONN_INIT_V6(connp, protocol, src, rem, ports) {		\
	(connp)->conn_ulp = protocol;					\
	(connp)->conn_srcv6 = src;					\
	(connp)->conn_remv6 = rem;					\
	(connp)->conn_ports = ports;					\
}

#define	IPCL_PORT_HASH(port, size) \
	((((port) >> 8) ^ (port)) & ((size) - 1))

#define	IPCL_BIND_HASH(lport, ipst)					\
	((unsigned)(((lport) >> 8) ^ (lport)) % \
	    (ipst)->ips_ipcl_bind_fanout_size)

#define	IPCL_BIND_MATCH(connp, proto, laddr, lport)			\
	((connp)->conn_ulp == (proto) &&				\
		(connp)->conn_lport == (lport) &&			\
		(_IPCL_V4_MATCH_ANY((connp)->conn_srcv6) ||		\
		_IPCL_V4_MATCH((connp)->conn_srcv6, (laddr))) &&	\
		!(connp)->conn_ipv6_v6only)

#define	IPCL_BIND_MATCH_V6(connp, proto, laddr, lport)			\
	((connp)->conn_ulp == (proto) &&				\
		(connp)->conn_lport == (lport) &&			\
		(IN6_ARE_ADDR_EQUAL(&(connp)->conn_srcv6, &(laddr)) ||	\
		IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_srcv6)))

#define	IPCL_UDP_MATCH(connp, lport, laddr, fport, faddr)		\
	(((connp)->conn_lport == (lport)) &&				\
	((_IPCL_V4_MATCH_ANY((connp)->conn_srcv6) ||			\
	(_IPCL_V4_MATCH((connp)->conn_srcv6, (laddr)) &&		\
	(_IPCL_V4_MATCH_ANY((connp)->conn_remv6) ||			\
	(_IPCL_V4_MATCH((connp)->conn_remv6, (faddr)) &&		\
	(connp)->conn_fport == (fport)))))) &&				\
	!(connp)->conn_ipv6_v6only)

#define	IPCL_UDP_MATCH_V6(connp, lport, laddr, fport, faddr)	\
	(((connp)->conn_lport == (lport)) &&			\
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_srcv6) ||	\
	(IN6_ARE_ADDR_EQUAL(&(connp)->conn_srcv6, &(laddr)) &&	\
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_remv6) ||	\
	(IN6_ARE_ADDR_EQUAL(&(connp)->conn_remv6, &(faddr)) &&	\
	(connp)->conn_fport == (fport))))))

#define	IPCL_TCP_EAGER_INIT(connp, protocol, src, rem, ports) {		\
	(connp)->conn_flags |= (IPCL_TCP4|IPCL_EAGER);			\
	IN6_IPADDR_TO_V4MAPPED(src, &(connp)->conn_srcv6);		\
	IN6_IPADDR_TO_V4MAPPED(rem, &(connp)->conn_remv6);		\
	(connp)->conn_ports = ports;					\
	(connp)->conn_send = ip_output;					\
	(connp)->conn_sqp = IP_SQUEUE_GET(lbolt);			\
	(connp)->conn_initial_sqp = (connp)->conn_sqp;			\
}

#define	IPCL_TCP_EAGER_INIT_V6(connp, protocol, src, rem, ports) {	\
	(connp)->conn_flags |= (IPCL_TCP6|IPCL_EAGER|IPCL_ISV6);	\
	(connp)->conn_srcv6 = src;					\
	(connp)->conn_remv6 = rem;					\
	(connp)->conn_ports = ports;					\
	(connp)->conn_send = ip_output_v6;				\
	(connp)->conn_sqp = IP_SQUEUE_GET(lbolt);			\
	(connp)->conn_initial_sqp = (connp)->conn_sqp;			\
}

#define	IPCL_UDP_HASH(lport, ipst)	\
	IPCL_PORT_HASH(lport, (ipst)->ips_ipcl_udp_fanout_size)

#define	CONN_G_HASH_SIZE	1024

/* Raw socket hash function. */
#define	IPCL_RAW_HASH(lport, ipst)	\
	IPCL_PORT_HASH(lport, (ipst)->ips_ipcl_raw_fanout_size)

/*
 * This is similar to IPCL_BIND_MATCH except that the local port check
 * is changed to a wildcard port check.
 */
#define	IPCL_RAW_MATCH(connp, proto, laddr)			\
	((connp)->conn_ulp == (proto) &&			\
	(connp)->conn_lport == 0 &&				\
	(_IPCL_V4_MATCH_ANY((connp)->conn_srcv6) ||		\
	_IPCL_V4_MATCH((connp)->conn_srcv6, (laddr))))

#define	IPCL_RAW_MATCH_V6(connp, proto, laddr)			\
	((connp)->conn_ulp == (proto) &&			\
	(connp)->conn_lport == 0 &&				\
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_srcv6) ||	\
	IN6_ARE_ADDR_EQUAL(&(connp)->conn_srcv6, &(laddr))))

/* Function prototypes */
extern void ipcl_g_init(void);
extern void ipcl_init(ip_stack_t *);
extern void ipcl_g_destroy(void);
extern void ipcl_destroy(ip_stack_t *);
extern conn_t *ipcl_conn_create(uint32_t, int, netstack_t *);
extern void ipcl_conn_destroy(conn_t *);

void ipcl_hash_insert_wildcard(connf_t *, conn_t *);
void ipcl_hash_remove(conn_t *);
void ipcl_hash_remove_locked(conn_t *connp, connf_t *connfp);

extern int	ipcl_bind_insert(conn_t *, uint8_t, ipaddr_t, uint16_t);
extern int	ipcl_bind_insert_v6(conn_t *, uint8_t, const in6_addr_t *,
		    uint16_t);
extern int	ipcl_conn_insert(conn_t *, uint8_t, ipaddr_t, ipaddr_t,
		    uint32_t);
extern int	ipcl_conn_insert_v6(conn_t *, uint8_t, const in6_addr_t *,
		    const in6_addr_t *, uint32_t, uint_t);
extern conn_t	*ipcl_get_next_conn(connf_t *, conn_t *, uint32_t);

void ipcl_proto_insert(conn_t *, uint8_t);
void ipcl_proto_insert_v6(conn_t *, uint8_t);
conn_t *ipcl_classify_v4(mblk_t *, uint8_t, uint_t, zoneid_t, ip_stack_t *);
conn_t *ipcl_classify_v6(mblk_t *, uint8_t, uint_t, zoneid_t, ip_stack_t *);
conn_t *ipcl_classify(mblk_t *, zoneid_t, ip_stack_t *);
conn_t *ipcl_classify_raw(mblk_t *, uint8_t, zoneid_t, uint32_t, ipha_t *,
	    ip_stack_t *);
void	ipcl_globalhash_insert(conn_t *);
void	ipcl_globalhash_remove(conn_t *);
void	ipcl_walk(pfv_t, void *, ip_stack_t *);
conn_t	*ipcl_tcp_lookup_reversed_ipv4(ipha_t *, tcph_t *, int, ip_stack_t *);
conn_t	*ipcl_tcp_lookup_reversed_ipv6(ip6_t *, tcpha_t *, int, uint_t,
	    ip_stack_t *);
conn_t	*ipcl_lookup_listener_v4(uint16_t, ipaddr_t, zoneid_t, ip_stack_t *);
conn_t	*ipcl_lookup_listener_v6(uint16_t, in6_addr_t *, uint_t, zoneid_t,
	    ip_stack_t *);
int	conn_trace_ref(conn_t *);
int	conn_untrace_ref(conn_t *);
void	ipcl_conn_cleanup(conn_t *);
conn_t *ipcl_conn_tcp_lookup_reversed_ipv4(conn_t *, ipha_t *, tcph_t *,
	    ip_stack_t *);
conn_t *ipcl_conn_tcp_lookup_reversed_ipv6(conn_t *, ip6_t *, tcph_t *,
	    ip_stack_t *);

extern int ip_create_helper_stream(conn_t *connp, ldi_ident_t li);
extern void ip_free_helper_stream(conn_t *connp);

extern int ip_get_options(conn_t *, int, int, void *, t_uscalar_t *, cred_t *);
extern int ip_set_options(conn_t *, int, int, const void *, t_uscalar_t,
    cred_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPCLASSIFIER_H */
