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

typedef void (*edesc_rpf)(void *, mblk_t *, void *, ip_recv_attr_t *);
struct icmph_s;
struct icmp6_hdr;
typedef boolean_t (*edesc_vpf)(conn_t *, void *, struct icmph_s *,
    struct icmp6_hdr *, ip_recv_attr_t *);

/*
 * ==============================
 * =	The CONNECTION		=
 * ==============================
 */

/*
 * The connection structure contains the common information/flags/ref needed.
 * Implementation will keep the connection struct, the layers (with their
 * respective data for event i.e. tcp_t if event was tcp_input_data) all in one
 * contiguous memory location.
 */

/* Conn Flags */
/* Unused			0x00020000 */
/* Unused			0x00040000 */
#define	IPCL_FULLY_BOUND	0x00080000	/* Bound to correct squeue */
/* Unused			0x00100000 */
/* Unused 			0x00200000 */
/* Unused			0x00400000 */
#define	IPCL_CL_LISTENER	0x00800000	/* Cluster listener */
/* Unused			0x01000000 */
/* Unused			0x02000000 */
/* Unused			0x04000000 */
/* Unused			0x08000000 */
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
/* Unused			0x00000040 */
#define	IPCL_IPTUN		0x00000080	/* iptun module above us */

#define	IPCL_NONSTR		0x00001000	/* A non-STREAMS socket */
/* Unused			0x10000000 */

#define	IPCL_REMOVED		0x00000100
#define	IPCL_REUSED		0x00000200

#define	IPCL_IS_CONNECTED(connp)					\
	((connp)->conn_flags & IPCL_CONNECTED)

#define	IPCL_IS_BOUND(connp)						\
	((connp)->conn_flags & IPCL_BOUND)

/*
 * Can't use conn_proto since we need to tell difference
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

#define	IPCL_IS_IPTUN(connp)						\
	((connp)->conn_flags & IPCL_IPTUN)

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
 * Mandatory Access Control mode, in conn_t's conn_mac_mode field.
 * 	CONN_MAC_DEFAULT: strict enforcement of MAC.
 * 	CONN_MAC_AWARE:   allows communications between unlabeled systems
 *			  and privileged daemons
 *	CONN_MAC_IMPLICIT: allows communications without explicit labels
 *		           on the wire with privileged daemons.
 *
 * CONN_MAC_IMPLICIT is intended specifically for labeled IPsec key management
 * in networks which don't pass CIPSO-labeled packets.
 */
#define	CONN_MAC_DEFAULT 0
#define	CONN_MAC_AWARE 1
#define	CONN_MAC_IMPLICIT 2

/*
 * conn receive ancillary definition.
 *
 * These are the set of socket options that make the receive side
 * potentially pass up ancillary data items.
 * We have a union with an integer so that we can quickly check whether
 * any ancillary data items need to be added.
 */
typedef struct crb_s {
	union {
		uint32_t	crbu_all;
		struct {
			uint32_t
	crbb_recvdstaddr : 1,		/* IP_RECVDSTADDR option */
	crbb_recvopts : 1,		/* IP_RECVOPTS option */
	crbb_recvif : 1,		/* IP_RECVIF option */
	crbb_recvslla : 1,		/* IP_RECVSLLA option */

	crbb_recvttl : 1,		/* IP_RECVTTL option */
	crbb_ip_recvpktinfo : 1,	/* IP*_RECVPKTINFO option  */
	crbb_ipv6_recvhoplimit : 1,	/* IPV6_RECVHOPLIMIT option */
	crbb_ipv6_recvhopopts : 1,	/* IPV6_RECVHOPOPTS option */

	crbb_ipv6_recvdstopts : 1,	/* IPV6_RECVDSTOPTS option */
	crbb_ipv6_recvrthdr : 1,	/* IPV6_RECVRTHDR option */
	crbb_old_ipv6_recvdstopts : 1,	/* old form of IPV6_DSTOPTS */
	crbb_ipv6_recvrthdrdstopts : 1,	/* IPV6_RECVRTHDRDSTOPTS */

	crbb_ipv6_recvtclass : 1,	/* IPV6_RECVTCLASS */
	crbb_recvucred : 1,		/* IP_RECVUCRED option */
	crbb_timestamp : 1;		/* SO_TIMESTAMP "socket" option */

		} crbb;
	} crbu;
} crb_t;

#define	crb_all				crbu.crbu_all
#define	crb_recvdstaddr			crbu.crbb.crbb_recvdstaddr
#define	crb_recvopts			crbu.crbb.crbb_recvopts
#define	crb_recvif			crbu.crbb.crbb_recvif
#define	crb_recvslla			crbu.crbb.crbb_recvslla
#define	crb_recvttl			crbu.crbb.crbb_recvttl
#define	crb_ip_recvpktinfo		crbu.crbb.crbb_ip_recvpktinfo
#define	crb_ipv6_recvhoplimit		crbu.crbb.crbb_ipv6_recvhoplimit
#define	crb_ipv6_recvhopopts		crbu.crbb.crbb_ipv6_recvhopopts
#define	crb_ipv6_recvdstopts		crbu.crbb.crbb_ipv6_recvdstopts
#define	crb_ipv6_recvrthdr		crbu.crbb.crbb_ipv6_recvrthdr
#define	crb_old_ipv6_recvdstopts	crbu.crbb.crbb_old_ipv6_recvdstopts
#define	crb_ipv6_recvrthdrdstopts	crbu.crbb.crbb_ipv6_recvrthdrdstopts
#define	crb_ipv6_recvtclass		crbu.crbb.crbb_ipv6_recvtclass
#define	crb_recvucred			crbu.crbb.crbb_recvucred
#define	crb_timestamp			crbu.crbb.crbb_timestamp

/*
 * The initial fields in the conn_t are setup by the kmem_cache constructor,
 * and are preserved when it is freed. Fields after that are bzero'ed when
 * the conn_t is freed.
 *
 * Much of the conn_t is protected by conn_lock.
 *
 * conn_lock is also used by some ULPs (like UDP and RAWIP) to protect
 * their state.
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
		struct iptun_s	*cp_iptun;	/* Pointer to iptun_t */
		struct sctp_s	*cp_sctp;	/* For IPCL_SCTPCONN */
		void		*cp_priv;
	} conn_proto_priv;
#define	conn_tcp	conn_proto_priv.cp_tcp
#define	conn_udp	conn_proto_priv.cp_udp
#define	conn_icmp	conn_proto_priv.cp_icmp
#define	conn_rts	conn_proto_priv.cp_rts
#define	conn_iptun	conn_proto_priv.cp_iptun
#define	conn_sctp	conn_proto_priv.cp_sctp
#define	conn_priv	conn_proto_priv.cp_priv

	kcondvar_t	conn_cv;
	uint8_t		conn_proto;		/* protocol type */

	edesc_rpf	conn_recv;		/* Pointer to recv routine */
	edesc_rpf	conn_recvicmp;		/* For ICMP error */
	edesc_vpf	conn_verifyicmp;	/* Verify ICMP error */

	ip_xmit_attr_t	*conn_ixa;		/* Options if no ancil data */

	/* Fields after this are bzero'ed when the conn_t is freed. */
#define	conn_start_clr	conn_recv_ancillary

	/* Options for receive-side ancillary data */
	crb_t		conn_recv_ancillary;

	squeue_t	*conn_sqp;		/* Squeue for processing */
	uint_t		conn_state_flags;	/* IP state flags */

	int		conn_lingertime;	/* linger time (in seconds) */

	unsigned int
		conn_on_sqp : 1,		/* Conn is being processed */
		conn_linger : 1,		/* SO_LINGER state */
		conn_useloopback : 1,		/* SO_USELOOPBACK state */
		conn_broadcast : 1,		/* SO_BROADCAST state */

		conn_reuseaddr : 1,		/* SO_REUSEADDR state */
		conn_keepalive : 1,		/* SO_KEEPALIVE state */
		conn_multi_router : 1,		/* Wants all multicast pkts */
		conn_unspec_src : 1,		/* IP_UNSPEC_SRC */

		conn_policy_cached : 1,		/* Is policy cached/latched ? */
		conn_in_enforce_policy : 1,	/* Enforce Policy on inbound */
		conn_out_enforce_policy : 1,	/* Enforce Policy on outbound */
		conn_debug : 1,			/* SO_DEBUG */

		conn_ipv6_v6only : 1,		/* IPV6_V6ONLY */
		conn_oobinline : 1, 		/* SO_OOBINLINE state */
		conn_dgram_errind : 1,		/* SO_DGRAM_ERRIND state */
		conn_exclbind : 1,		/* SO_EXCLBIND state */

		conn_mdt_ok : 1,		/* MDT is permitted */
		conn_allzones : 1,		/* SO_ALLZONES */
		conn_ipv6_recvpathmtu : 1,	/* IPV6_RECVPATHMTU */
		conn_mcbc_bind : 1,		/* Bound to multi/broadcast */

		conn_pad_to_bit_31 : 12;

	boolean_t	conn_blocked;		/* conn is flow-controlled */

	squeue_t	*conn_initial_sqp;	/* Squeue at open time */
	squeue_t	*conn_final_sqp;	/* Squeue after connect */
	ill_t		*conn_dhcpinit_ill;	/* IP_DHCPINIT_IF */
	ipsec_latch_t	*conn_latch;		/* latched IDS */
	struct ipsec_policy_s	*conn_latch_in_policy; /* latched policy (in) */
	struct ipsec_action_s	*conn_latch_in_action; /* latched action (in) */
	uint_t		conn_bound_if;		/* IP*_BOUND_IF */
	queue_t		*conn_rq;		/* Read queue */
	queue_t		*conn_wq;		/* Write queue */
	dev_t		conn_dev;		/* Minor number */
	vmem_t		*conn_minor_arena;	/* Minor arena */
	ip_helper_stream_info_t *conn_helper_info;

	cred_t		*conn_cred;		/* Credentials */
	pid_t		conn_cpid;		/* pid from open/connect */
	uint64_t	conn_open_time;		/* time when this was opened */

	connf_t		*conn_g_fanout;		/* Global Hash bucket head */
	struct conn_s	*conn_g_next;		/* Global Hash chain next */
	struct conn_s	*conn_g_prev;		/* Global Hash chain prev */
	struct ipsec_policy_head_s *conn_policy; /* Configured policy */
	in6_addr_t	conn_bound_addr_v6;	/* Address in bind() */
#define	conn_bound_addr_v4	V4_PART_OF_V6(conn_bound_addr_v6)
	connf_t		*conn_fanout;		/* Hash bucket we're part of */
	struct conn_s	*conn_next;		/* Hash chain next */
	struct conn_s	*conn_prev;		/* Hash chain prev */

	struct {
		in6_addr_t connua_laddr;	/* Local address - match */
		in6_addr_t connua_faddr;	/* Remote address */
	} connua_v6addr;
#define	conn_laddr_v4	V4_PART_OF_V6(connua_v6addr.connua_laddr)
#define	conn_faddr_v4	V4_PART_OF_V6(connua_v6addr.connua_faddr)
#define	conn_laddr_v6	connua_v6addr.connua_laddr
#define	conn_faddr_v6	connua_v6addr.connua_faddr
	in6_addr_t	conn_saddr_v6;		/* Local address - source */
#define	conn_saddr_v4	V4_PART_OF_V6(conn_saddr_v6)

	union {
		/* Used for classifier match performance */
		uint32_t		connu_ports2;
		struct {
			in_port_t	connu_fport;	/* Remote port */
			in_port_t	connu_lport;	/* Local port */
		} connu_ports;
	} u_port;
#define	conn_fport	u_port.connu_ports.connu_fport
#define	conn_lport	u_port.connu_ports.connu_lport
#define	conn_ports	u_port.connu_ports2

	uint_t		conn_incoming_ifindex;	/* IP{,V6}_BOUND_IF, scopeid */
	ill_t		*conn_oper_pending_ill; /* pending shared ioctl */

	krwlock_t	conn_ilg_lock;		/* Protects conn_ilg_* */
	ilg_t		*conn_ilg;		/* Group memberships */

	kcondvar_t	conn_refcv;		/* For conn_oper_pending_ill */

	struct conn_s 	*conn_drain_next;	/* Next conn in drain list */
	struct conn_s	*conn_drain_prev;	/* Prev conn in drain list */
	idl_t		*conn_idl;		/* Ptr to the drain list head */
	mblk_t		*conn_ipsec_opt_mp;	/* ipsec option mblk */
	zoneid_t	conn_zoneid;		/* zone connection is in */
	int		conn_rtaware; 		/* RT_AWARE sockopt value */
	kcondvar_t	conn_sq_cv;		/* For non-STREAMS socket IO */
	sock_upcalls_t	*conn_upcalls;		/* Upcalls to sockfs */
	sock_upper_handle_t conn_upper_handle;	/* Upper handle: sonode * */

	unsigned int
		conn_mlp_type : 2,		/* mlp_type_t; tsol/tndb.h */
		conn_anon_mlp : 1,		/* user wants anon MLP */
		conn_anon_port : 1,		/* user bound anonymously */

		conn_mac_mode : 2,		/* normal/loose/implicit MAC */
		conn_anon_priv_bind : 1,	/* *_ANON_PRIV_BIND state */
		conn_zone_is_global : 1,	/* GLOBAL_ZONEID */
		conn_isvrrp : 1,		/* VRRP control socket */
		conn_spare : 23;

	boolean_t	conn_flow_cntrld;
	netstack_t	*conn_netstack;	/* Corresponds to a netstack_hold */

	/*
	 * IP format that packets received for this struct should use.
	 * Value can be IP4_VERSION or IPV6_VERSION.
	 * The sending version is encoded using IXAF_IS_IPV4.
	 */
	ushort_t	conn_ipversion;

	/* Written to only once at the time of opening the endpoint */
	sa_family_t	conn_family;		/* Family from socket() call */
	uint_t		conn_so_type;		/* Type from socket() call */

	uint_t		conn_sndbuf;		/* SO_SNDBUF state */
	uint_t		conn_rcvbuf;		/* SO_RCVBUF state */
	uint_t		conn_wroff;		/* Current write offset */

	uint_t		conn_sndlowat;		/* Send buffer low water mark */
	uint_t		conn_rcvlowat;		/* Recv buffer low water mark */

	uint8_t		conn_default_ttl;	/* Default TTL/hoplimit */

	uint32_t	conn_flowinfo;	/* Connected flow id and tclass */

	/*
	 * The most recent address for sendto. Initially set to zero
	 * which is always different than then the destination address
	 * since the send interprets zero as the loopback address.
	 */
	in6_addr_t	conn_v6lastdst;
#define	conn_v4lastdst	V4_PART_OF_V6(conn_v6lastdst)
	ushort_t	conn_lastipversion;
	in_port_t	conn_lastdstport;
	uint32_t	conn_lastflowinfo;	/* IPv6-only */
	uint_t		conn_lastscopeid;	/* IPv6-only */
	uint_t		conn_lastsrcid;		/* Only for AF_INET6 */
	/*
	 * When we are not connected conn_saddr might be unspecified.
	 * We track the source that was used with conn_v6lastdst here.
	 */
	in6_addr_t	conn_v6lastsrc;
#define	conn_v4lastsrc	V4_PART_OF_V6(conn_v6lastsrc)

	/* Templates for transmitting packets */
	ip_pkt_t	conn_xmit_ipp;		/* Options if no ancil data */

	/*
	 * Header template - conn_ht_ulp is a pointer into conn_ht_iphc.
	 * Note that ixa_ip_hdr_length indicates the offset of ht_ulp in
	 * ht_iphc
	 *
	 * The header template is maintained for connected endpoints (and
	 * updated when sticky options are changed) and also for the lastdst.
	 * There is no conflict between those usages since SOCK_DGRAM and
	 * SOCK_RAW can not be used to specify a destination address (with
	 * sendto/sendmsg) if the socket has been connected.
	 */
	uint8_t		*conn_ht_iphc;		/* Start of IP header */
	uint_t		conn_ht_iphc_allocated;	/* Allocated buffer size */
	uint_t		conn_ht_iphc_len;	/* IP+ULP size */
	uint8_t		*conn_ht_ulp;		/* Upper-layer header */
	uint_t		conn_ht_ulp_len;	/* ULP header len */

	/* Checksum to compensate for source routed packets. Host byte order */
	uint32_t	conn_sum;

	uint32_t	conn_ioctlref;		/* ioctl ref count */
#ifdef CONN_DEBUG
#define	CONN_TRACE_MAX	10
	int		conn_trace_last;	/* ndx of last used tracebuf */
	conn_trace_t	conn_trace_buf[CONN_TRACE_MAX];
#endif
};

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
	if ((connp)->conn_ref == 0 ||					\
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

/*
 * On a labeled system, we must treat bindings to ports
 * on shared IP addresses by sockets with MAC exemption
 * privilege as being in all zones, as there's
 * otherwise no way to identify the right receiver.
 */

#define	IPCL_CONNS_MAC(conn1, conn2)					\
	(((conn1)->conn_mac_mode != CONN_MAC_DEFAULT) ||		\
	((conn2)->conn_mac_mode != CONN_MAC_DEFAULT))

#define	IPCL_BIND_ZONE_MATCH(conn1, conn2)				\
	(IPCL_CONNS_MAC(conn1, conn2) ||				\
	IPCL_ZONE_MATCH(conn1, conn2->conn_zoneid) ||			\
	IPCL_ZONE_MATCH(conn2, conn1->conn_zoneid))


#define	_IPCL_V4_MATCH(v6addr, v4addr)	\
	(V4_PART_OF_V6((v6addr)) == (v4addr) && IN6_IS_ADDR_V4MAPPED(&(v6addr)))

#define	_IPCL_V4_MATCH_ANY(addr)	\
	(IN6_IS_ADDR_V4MAPPED_ANY(&(addr)) || IN6_IS_ADDR_UNSPECIFIED(&(addr)))


/*
 * IPCL_PROTO_MATCH() and IPCL_PROTO_MATCH_V6() only matches conns with
 * the specified ira_zoneid or conn_allzones by calling conn_wantpacket.
 */
#define	IPCL_PROTO_MATCH(connp, ira, ipha)				\
	((((connp)->conn_laddr_v4 == INADDR_ANY) ||			\
	(((connp)->conn_laddr_v4 == ((ipha)->ipha_dst)) &&		\
	    (((connp)->conn_faddr_v4 == INADDR_ANY) ||			\
	((connp)->conn_faddr_v4 == ((ipha)->ipha_src))))) &&		\
	conn_wantpacket((connp), (ira), (ipha)))

#define	IPCL_PROTO_MATCH_V6(connp, ira, ip6h)				\
	((IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_laddr_v6) ||		\
	(IN6_ARE_ADDR_EQUAL(&(connp)->conn_laddr_v6, &((ip6h)->ip6_dst)) &&   \
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_faddr_v6) ||		      \
	IN6_ARE_ADDR_EQUAL(&(connp)->conn_faddr_v6, &((ip6h)->ip6_src))))) && \
	(conn_wantpacket_v6((connp), (ira), (ip6h))))

#define	IPCL_CONN_HASH(src, ports, ipst)				\
	((unsigned)(ntohl((src)) ^ ((ports) >> 24) ^ ((ports) >> 16) ^	\
	((ports) >> 8) ^ (ports)) % (ipst)->ips_ipcl_conn_fanout_size)

#define	IPCL_CONN_HASH_V6(src, ports, ipst)				\
	IPCL_CONN_HASH(V4_PART_OF_V6((src)), (ports), (ipst))

#define	IPCL_CONN_MATCH(connp, proto, src, dst, ports)			\
	((connp)->conn_proto == (proto) &&				\
		(connp)->conn_ports == (ports) &&      			\
		_IPCL_V4_MATCH((connp)->conn_faddr_v6, (src)) &&	\
		_IPCL_V4_MATCH((connp)->conn_laddr_v6, (dst)) &&	\
		!(connp)->conn_ipv6_v6only)

#define	IPCL_CONN_MATCH_V6(connp, proto, src, dst, ports)		\
	((connp)->conn_proto == (proto) &&				\
		(connp)->conn_ports == (ports) &&      			\
		IN6_ARE_ADDR_EQUAL(&(connp)->conn_faddr_v6, &(src)) &&	\
		IN6_ARE_ADDR_EQUAL(&(connp)->conn_laddr_v6, &(dst)))

#define	IPCL_PORT_HASH(port, size) \
	((((port) >> 8) ^ (port)) & ((size) - 1))

#define	IPCL_BIND_HASH(lport, ipst)					\
	((unsigned)(((lport) >> 8) ^ (lport)) % \
	    (ipst)->ips_ipcl_bind_fanout_size)

#define	IPCL_BIND_MATCH(connp, proto, laddr, lport)			\
	((connp)->conn_proto == (proto) &&				\
		(connp)->conn_lport == (lport) &&			\
		(_IPCL_V4_MATCH_ANY((connp)->conn_laddr_v6) ||		\
		_IPCL_V4_MATCH((connp)->conn_laddr_v6, (laddr))) &&	\
		!(connp)->conn_ipv6_v6only)

#define	IPCL_BIND_MATCH_V6(connp, proto, laddr, lport)			\
	((connp)->conn_proto == (proto) &&				\
		(connp)->conn_lport == (lport) &&			\
		(IN6_ARE_ADDR_EQUAL(&(connp)->conn_laddr_v6, &(laddr)) || \
		IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_laddr_v6)))

/*
 * We compare conn_laddr since it captures both connected and a bind to
 * a multicast or broadcast address.
 * The caller needs to match the zoneid and also call conn_wantpacket
 * for multicast, broadcast, or when conn_incoming_ifindex is set.
 */
#define	IPCL_UDP_MATCH(connp, lport, laddr, fport, faddr)		\
	(((connp)->conn_lport == (lport)) &&				\
	((_IPCL_V4_MATCH_ANY((connp)->conn_laddr_v6) ||			\
	(_IPCL_V4_MATCH((connp)->conn_laddr_v6, (laddr)) &&		\
	(_IPCL_V4_MATCH_ANY((connp)->conn_faddr_v6) ||			\
	(_IPCL_V4_MATCH((connp)->conn_faddr_v6, (faddr)) &&		\
	(connp)->conn_fport == (fport)))))) &&				\
	!(connp)->conn_ipv6_v6only)

/*
 * We compare conn_laddr since it captures both connected and a bind to
 * a multicast or broadcast address.
 * The caller needs to match the zoneid and also call conn_wantpacket_v6
 * for multicast or when conn_incoming_ifindex is set.
 */
#define	IPCL_UDP_MATCH_V6(connp, lport, laddr, fport, faddr)	\
	(((connp)->conn_lport == (lport)) &&			\
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_laddr_v6) ||	\
	(IN6_ARE_ADDR_EQUAL(&(connp)->conn_laddr_v6, &(laddr)) &&	\
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_faddr_v6) ||	\
	(IN6_ARE_ADDR_EQUAL(&(connp)->conn_faddr_v6, &(faddr)) &&	\
	(connp)->conn_fport == (fport))))))

#define	IPCL_IPTUN_HASH(laddr, faddr)					\
	((ntohl(laddr) ^ ((ntohl(faddr) << 24) | (ntohl(faddr) >> 8))) % \
	ipcl_iptun_fanout_size)

#define	IPCL_IPTUN_HASH_V6(laddr, faddr)				\
	IPCL_IPTUN_HASH((laddr)->s6_addr32[0] ^ (laddr)->s6_addr32[1] ^	\
	    (faddr)->s6_addr32[2] ^ (faddr)->s6_addr32[3],		\
	    (faddr)->s6_addr32[0] ^ (faddr)->s6_addr32[1] ^		\
	    (laddr)->s6_addr32[2] ^ (laddr)->s6_addr32[3])

#define	IPCL_IPTUN_MATCH(connp, laddr, faddr)			\
	(_IPCL_V4_MATCH((connp)->conn_laddr_v6, (laddr)) &&	\
	_IPCL_V4_MATCH((connp)->conn_faddr_v6, (faddr)))

#define	IPCL_IPTUN_MATCH_V6(connp, laddr, faddr)		\
	(IN6_ARE_ADDR_EQUAL(&(connp)->conn_laddr_v6, (laddr)) &&	\
	IN6_ARE_ADDR_EQUAL(&(connp)->conn_faddr_v6, (faddr)))

#define	IPCL_UDP_HASH(lport, ipst)	\
	IPCL_PORT_HASH(lport, (ipst)->ips_ipcl_udp_fanout_size)

#define	CONN_G_HASH_SIZE	1024

/* Raw socket hash function. */
#define	IPCL_RAW_HASH(lport, ipst)	\
	IPCL_PORT_HASH(lport, (ipst)->ips_ipcl_raw_fanout_size)

/*
 * This is similar to IPCL_BIND_MATCH except that the local port check
 * is changed to a wildcard port check.
 * We compare conn_laddr since it captures both connected and a bind to
 * a multicast or broadcast address.
 */
#define	IPCL_RAW_MATCH(connp, proto, laddr)			\
	((connp)->conn_proto == (proto) &&			\
	(connp)->conn_lport == 0 &&				\
	(_IPCL_V4_MATCH_ANY((connp)->conn_laddr_v6) ||		\
	_IPCL_V4_MATCH((connp)->conn_laddr_v6, (laddr))))

#define	IPCL_RAW_MATCH_V6(connp, proto, laddr)			\
	((connp)->conn_proto == (proto) &&			\
	(connp)->conn_lport == 0 &&				\
	(IN6_IS_ADDR_UNSPECIFIED(&(connp)->conn_laddr_v6) ||	\
	IN6_ARE_ADDR_EQUAL(&(connp)->conn_laddr_v6, &(laddr))))

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

extern int	ipcl_bind_insert(conn_t *);
extern int	ipcl_bind_insert_v4(conn_t *);
extern int	ipcl_bind_insert_v6(conn_t *);
extern int	ipcl_conn_insert(conn_t *);
extern int	ipcl_conn_insert_v4(conn_t *);
extern int	ipcl_conn_insert_v6(conn_t *);
extern conn_t	*ipcl_get_next_conn(connf_t *, conn_t *, uint32_t);

conn_t *ipcl_classify_v4(mblk_t *, uint8_t, uint_t, ip_recv_attr_t *,
	    ip_stack_t *);
conn_t *ipcl_classify_v6(mblk_t *, uint8_t, uint_t, ip_recv_attr_t *,
	    ip_stack_t *);
conn_t *ipcl_classify(mblk_t *, ip_recv_attr_t *, ip_stack_t *);
conn_t *ipcl_classify_raw(mblk_t *, uint8_t, uint32_t, ipha_t *,
    ip6_t *, ip_recv_attr_t *, ip_stack_t *);
conn_t *ipcl_iptun_classify_v4(ipaddr_t *, ipaddr_t *, ip_stack_t *);
conn_t *ipcl_iptun_classify_v6(in6_addr_t *, in6_addr_t *, ip_stack_t *);
void	ipcl_globalhash_insert(conn_t *);
void	ipcl_globalhash_remove(conn_t *);
void	ipcl_walk(pfv_t, void *, ip_stack_t *);
conn_t	*ipcl_tcp_lookup_reversed_ipv4(ipha_t *, tcpha_t *, int, ip_stack_t *);
conn_t	*ipcl_tcp_lookup_reversed_ipv6(ip6_t *, tcpha_t *, int, uint_t,
	    ip_stack_t *);
conn_t	*ipcl_lookup_listener_v4(uint16_t, ipaddr_t, zoneid_t, ip_stack_t *);
conn_t	*ipcl_lookup_listener_v6(uint16_t, in6_addr_t *, uint_t, zoneid_t,
	    ip_stack_t *);
int	conn_trace_ref(conn_t *);
int	conn_untrace_ref(conn_t *);
void	ipcl_conn_cleanup(conn_t *);
extern uint_t	conn_recvancillary_size(conn_t *, crb_t, ip_recv_attr_t *,
    mblk_t *, ip_pkt_t *);
extern void	conn_recvancillary_add(conn_t *, crb_t, ip_recv_attr_t *,
    ip_pkt_t *, uchar_t *, uint_t);
conn_t *ipcl_conn_tcp_lookup_reversed_ipv4(conn_t *, ipha_t *, tcpha_t *,
	    ip_stack_t *);
conn_t *ipcl_conn_tcp_lookup_reversed_ipv6(conn_t *, ip6_t *, tcpha_t *,
	    ip_stack_t *);

extern int ip_create_helper_stream(conn_t *, ldi_ident_t);
extern void ip_free_helper_stream(conn_t *);
extern int	ip_helper_stream_setup(queue_t *, dev_t *, int, int,
    cred_t *, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPCLASSIFIER_H */
