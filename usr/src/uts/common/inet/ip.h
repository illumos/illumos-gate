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
 * Copyright (c) 1990 Mentat Inc.
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#ifndef	_INET_IP_H
#define	_INET_IP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/isa_defs.h>
#include <sys/types.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <sys/atomic.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <sys/neti.h>
#include <sys/hook.h>
#include <sys/hook_event.h>
#include <sys/hook_impl.h>
#include <inet/ip_stack.h>

#ifdef _KERNEL
#include <netinet/ip6.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/vmem.h>
#include <sys/squeue.h>
#include <net/route.h>
#include <sys/systm.h>
#include <net/radix.h>
#include <sys/modhash.h>

#ifdef DEBUG
#define	CONN_DEBUG
#endif

#define	IP_DEBUG
/*
 * The mt-streams(9F) flags for the IP module; put here so that other
 * "drivers" that are actually IP (e.g., ICMP, UDP) can use the same set
 * of flags.
 */
#define	IP_DEVMTFLAGS D_MP
#endif	/* _KERNEL */

#define	IP_MOD_NAME	"ip"
#define	IP_DEV_NAME	"/dev/ip"
#define	IP6_DEV_NAME	"/dev/ip6"

#define	UDP_MOD_NAME	"udp"
#define	UDP_DEV_NAME	"/dev/udp"
#define	UDP6_DEV_NAME	"/dev/udp6"

#define	TCP_MOD_NAME	"tcp"
#define	TCP_DEV_NAME	"/dev/tcp"
#define	TCP6_DEV_NAME	"/dev/tcp6"

#define	SCTP_MOD_NAME	"sctp"

#ifndef	_IPADDR_T
#define	_IPADDR_T
typedef uint32_t ipaddr_t;
#endif

/* Number of bits in an address */
#define	IP_ABITS		32
#define	IPV4_ABITS		IP_ABITS
#define	IPV6_ABITS		128
#define	IP_MAX_HW_LEN	40

#define	IP_HOST_MASK		(ipaddr_t)0xffffffffU

#define	IP_CSUM(mp, off, sum)		(~ip_cksum(mp, off, sum) & 0xFFFF)
#define	IP_CSUM_PARTIAL(mp, off, sum)	ip_cksum(mp, off, sum)
#define	IP_BCSUM_PARTIAL(bp, len, sum)	bcksum(bp, len, sum)

#define	ILL_FRAG_HASH_TBL_COUNT	((unsigned int)64)
#define	ILL_FRAG_HASH_TBL_SIZE	(ILL_FRAG_HASH_TBL_COUNT * sizeof (ipfb_t))

#define	IPV4_ADDR_LEN			4
#define	IP_ADDR_LEN			IPV4_ADDR_LEN
#define	IP_ARP_PROTO_TYPE		0x0800

#define	IPV4_VERSION			4
#define	IP_VERSION			IPV4_VERSION
#define	IP_SIMPLE_HDR_LENGTH_IN_WORDS	5
#define	IP_SIMPLE_HDR_LENGTH		20
#define	IP_MAX_HDR_LENGTH		60

#define	IP_MAX_OPT_LENGTH (IP_MAX_HDR_LENGTH-IP_SIMPLE_HDR_LENGTH)

#define	IP_MIN_MTU			(IP_MAX_HDR_LENGTH + 8)	/* 68 bytes */

/*
 * XXX IP_MAXPACKET is defined in <netinet/ip.h> as well. At some point the
 * 2 files should be cleaned up to remove all redundant definitions.
 */
#define	IP_MAXPACKET			65535
#define	IP_SIMPLE_HDR_VERSION \
	((IP_VERSION << 4) | IP_SIMPLE_HDR_LENGTH_IN_WORDS)

#define	UDPH_SIZE			8

/*
 * Constants and type definitions to support IP IOCTL commands
 */
#define	IP_IOCTL			(('i'<<8)|'p')
#define	IP_IOC_IRE_DELETE		4
#define	IP_IOC_IRE_DELETE_NO_REPLY	5
#define	IP_IOC_RTS_REQUEST		7

/* Common definitions used by IP IOCTL data structures */
typedef struct ipllcmd_s {
	uint_t	ipllc_cmd;
	uint_t	ipllc_name_offset;
	uint_t	ipllc_name_length;
} ipllc_t;

/* IP IRE Delete Command Structure. */
typedef struct ipid_s {
	ipllc_t	ipid_ipllc;
	uint_t	ipid_ire_type;
	uint_t	ipid_addr_offset;
	uint_t	ipid_addr_length;
	uint_t	ipid_mask_offset;
	uint_t	ipid_mask_length;
} ipid_t;

#define	ipid_cmd		ipid_ipllc.ipllc_cmd

#ifdef _KERNEL
/*
 * Temporary state for ip options parser.
 */
typedef struct ipoptp_s
{
	uint8_t		*ipoptp_next;	/* next option to look at */
	uint8_t		*ipoptp_end;	/* end of options */
	uint8_t		*ipoptp_cur;	/* start of current option */
	uint8_t		ipoptp_len;	/* length of current option */
	uint32_t	ipoptp_flags;
} ipoptp_t;

/*
 * Flag(s) for ipoptp_flags
 */
#define	IPOPTP_ERROR	0x00000001
#endif	/* _KERNEL */

/* Controls forwarding of IP packets, set via ipadm(1M)/ndd(1M) */
#define	IP_FORWARD_NEVER	0
#define	IP_FORWARD_ALWAYS	1

#define	WE_ARE_FORWARDING(ipst)	((ipst)->ips_ip_forwarding == IP_FORWARD_ALWAYS)

#define	IPH_HDR_LENGTH(ipha)						\
	((int)(((ipha_t *)ipha)->ipha_version_and_hdr_length & 0xF) << 2)

#define	IPH_HDR_VERSION(ipha)						\
	((int)(((ipha_t *)ipha)->ipha_version_and_hdr_length) >> 4)

#ifdef _KERNEL
/*
 * IP reassembly macros.  We hide starting and ending offsets in b_next and
 * b_prev of messages on the reassembly queue.	The messages are chained using
 * b_cont.  These macros are used in ip_reassemble() so we don't have to see
 * the ugly casts and assignments.
 * Note that the offsets are <= 64k i.e. a uint_t is sufficient to represent
 * them.
 */
#define	IP_REASS_START(mp)		((uint_t)(uintptr_t)((mp)->b_next))
#define	IP_REASS_SET_START(mp, u)	\
	((mp)->b_next = (mblk_t *)(uintptr_t)(u))
#define	IP_REASS_END(mp)		((uint_t)(uintptr_t)((mp)->b_prev))
#define	IP_REASS_SET_END(mp, u)		\
	((mp)->b_prev = (mblk_t *)(uintptr_t)(u))

#define	IP_REASS_COMPLETE	0x1
#define	IP_REASS_PARTIAL	0x2
#define	IP_REASS_FAILED		0x4

/*
 * Test to determine whether this is a module instance of IP or a
 * driver instance of IP.
 */
#define	CONN_Q(q)	(WR(q)->q_next == NULL)

#define	Q_TO_CONN(q)	((conn_t *)(q)->q_ptr)
#define	Q_TO_TCP(q)	(Q_TO_CONN((q))->conn_tcp)
#define	Q_TO_UDP(q)	(Q_TO_CONN((q))->conn_udp)
#define	Q_TO_ICMP(q)	(Q_TO_CONN((q))->conn_icmp)
#define	Q_TO_RTS(q)	(Q_TO_CONN((q))->conn_rts)

#define	CONNP_TO_WQ(connp)	((connp)->conn_wq)
#define	CONNP_TO_RQ(connp)	((connp)->conn_rq)

#define	GRAB_CONN_LOCK(q)	{				\
	if (q != NULL && CONN_Q(q))				\
		mutex_enter(&(Q_TO_CONN(q))->conn_lock);	\
}

#define	RELEASE_CONN_LOCK(q)	{				\
	if (q != NULL && CONN_Q(q))				\
		mutex_exit(&(Q_TO_CONN(q))->conn_lock);		\
}

/*
 * Ref counter macros for ioctls. This provides a guard for TCP to stop
 * tcp_close from removing the rq/wq whilst an ioctl is still in flight on the
 * stream. The ioctl could have been queued on e.g. an ipsq. tcp_close will wait
 * until the ioctlref count is zero before proceeding.
 * Ideally conn_oper_pending_ill would be used for this purpose. However, in the
 * case where an ioctl is aborted or interrupted, it can be cleared prematurely.
 * There are also some race possibilities between ip and the stream head which
 * can also end up with conn_oper_pending_ill being cleared prematurely. So, to
 * avoid these situations, we use a dedicated ref counter for ioctls which is
 * used in addition to and in parallel with the normal conn_ref count.
 */
#define	CONN_INC_IOCTLREF_LOCKED(connp)	{			\
	ASSERT(MUTEX_HELD(&(connp)->conn_lock));		\
	DTRACE_PROBE1(conn__inc__ioctlref, conn_t *, (connp));	\
	(connp)->conn_ioctlref++;				\
	mutex_exit(&(connp)->conn_lock);			\
}

#define	CONN_INC_IOCTLREF(connp)	{			\
	mutex_enter(&(connp)->conn_lock);			\
	CONN_INC_IOCTLREF_LOCKED(connp);			\
}

#define	CONN_DEC_IOCTLREF(connp)	{			\
	mutex_enter(&(connp)->conn_lock);			\
	DTRACE_PROBE1(conn__dec__ioctlref, conn_t *, (connp));	\
	/* Make sure conn_ioctlref will not underflow. */	\
	ASSERT((connp)->conn_ioctlref != 0);			\
	if ((--(connp)->conn_ioctlref == 0) &&			\
	    ((connp)->conn_state_flags & CONN_CLOSING)) {	\
		cv_broadcast(&(connp)->conn_cv);		\
	}							\
	mutex_exit(&(connp)->conn_lock);			\
}


/*
 * Complete the pending operation. Usually an ioctl. Can also
 * be a bind or option management request that got enqueued
 * in an ipsq_t. Called on completion of the operation.
 */
#define	CONN_OPER_PENDING_DONE(connp)	{			\
	mutex_enter(&(connp)->conn_lock);			\
	(connp)->conn_oper_pending_ill = NULL;			\
	cv_broadcast(&(connp)->conn_refcv);			\
	mutex_exit(&(connp)->conn_lock);			\
	CONN_DEC_REF(connp);					\
}

/*
 * Values for squeue switch:
 */
#define	IP_SQUEUE_ENTER_NODRAIN	1
#define	IP_SQUEUE_ENTER	2
#define	IP_SQUEUE_FILL 3

extern int ip_squeue_flag;

/* IP Fragmentation Reassembly Header */
typedef struct ipf_s {
	struct ipf_s	*ipf_hash_next;
	struct ipf_s	**ipf_ptphn;	/* Pointer to previous hash next. */
	uint32_t	ipf_ident;	/* Ident to match. */
	uint8_t		ipf_protocol;	/* Protocol to match. */
	uchar_t		ipf_last_frag_seen : 1;	/* Last fragment seen ? */
	time_t		ipf_timestamp;	/* Reassembly start time. */
	mblk_t		*ipf_mp;	/* mblk we live in. */
	mblk_t		*ipf_tail_mp;	/* Frag queue tail pointer. */
	int		ipf_hole_cnt;	/* Number of holes (hard-case). */
	int		ipf_end;	/* Tail end offset (0 -> hard-case). */
	uint_t		ipf_gen;	/* Frag queue generation */
	size_t		ipf_count;	/* Count of bytes used by frag */
	uint_t		ipf_nf_hdr_len; /* Length of nonfragmented header */
	in6_addr_t	ipf_v6src;	/* IPv6 source address */
	in6_addr_t	ipf_v6dst;	/* IPv6 dest address */
	uint_t		ipf_prev_nexthdr_offset; /* Offset for nexthdr value */
	uint8_t		ipf_ecn;	/* ECN info for the fragments */
	uint8_t		ipf_num_dups;	/* Number of times dup frags recvd */
	uint16_t	ipf_checksum_flags; /* Hardware checksum flags */
	uint32_t	ipf_checksum;	/* Partial checksum of fragment data */
} ipf_t;

/*
 * IPv4 Fragments
 */
#define	IS_V4_FRAGMENT(ipha_fragment_offset_and_flags)			\
	(((ntohs(ipha_fragment_offset_and_flags) & IPH_OFFSET) != 0) ||	\
	((ntohs(ipha_fragment_offset_and_flags) & IPH_MF) != 0))

#define	ipf_src	V4_PART_OF_V6(ipf_v6src)
#define	ipf_dst	V4_PART_OF_V6(ipf_v6dst)

#endif /* _KERNEL */

/* ICMP types */
#define	ICMP_ECHO_REPLY			0
#define	ICMP_DEST_UNREACHABLE		3
#define	ICMP_SOURCE_QUENCH		4
#define	ICMP_REDIRECT			5
#define	ICMP_ECHO_REQUEST		8
#define	ICMP_ROUTER_ADVERTISEMENT	9
#define	ICMP_ROUTER_SOLICITATION	10
#define	ICMP_TIME_EXCEEDED		11
#define	ICMP_PARAM_PROBLEM		12
#define	ICMP_TIME_STAMP_REQUEST		13
#define	ICMP_TIME_STAMP_REPLY		14
#define	ICMP_INFO_REQUEST		15
#define	ICMP_INFO_REPLY			16
#define	ICMP_ADDRESS_MASK_REQUEST	17
#define	ICMP_ADDRESS_MASK_REPLY		18

/* Evaluates to true if the ICMP type is an ICMP error */
#define	ICMP_IS_ERROR(type)	(		\
	(type) == ICMP_DEST_UNREACHABLE ||	\
	(type) == ICMP_SOURCE_QUENCH ||		\
	(type) == ICMP_TIME_EXCEEDED ||		\
	(type) == ICMP_PARAM_PROBLEM)

/* ICMP_TIME_EXCEEDED codes */
#define	ICMP_TTL_EXCEEDED		0
#define	ICMP_REASSEMBLY_TIME_EXCEEDED	1

/* ICMP_DEST_UNREACHABLE codes */
#define	ICMP_NET_UNREACHABLE		0
#define	ICMP_HOST_UNREACHABLE		1
#define	ICMP_PROTOCOL_UNREACHABLE	2
#define	ICMP_PORT_UNREACHABLE		3
#define	ICMP_FRAGMENTATION_NEEDED	4
#define	ICMP_SOURCE_ROUTE_FAILED	5
#define	ICMP_DEST_NET_UNKNOWN		6
#define	ICMP_DEST_HOST_UNKNOWN		7
#define	ICMP_SRC_HOST_ISOLATED		8
#define	ICMP_DEST_NET_UNREACH_ADMIN	9
#define	ICMP_DEST_HOST_UNREACH_ADMIN	10
#define	ICMP_DEST_NET_UNREACH_TOS	11
#define	ICMP_DEST_HOST_UNREACH_TOS	12

/* ICMP Header Structure */
typedef struct icmph_s {
	uint8_t		icmph_type;
	uint8_t		icmph_code;
	uint16_t	icmph_checksum;
	union {
		struct { /* ECHO request/response structure */
			uint16_t	u_echo_ident;
			uint16_t	u_echo_seqnum;
		} u_echo;
		struct { /* Destination unreachable structure */
			uint16_t	u_du_zero;
			uint16_t	u_du_mtu;
		} u_du;
		struct { /* Parameter problem structure */
			uint8_t		u_pp_ptr;
			uint8_t		u_pp_rsvd[3];
		} u_pp;
		struct { /* Redirect structure */
			ipaddr_t	u_rd_gateway;
		} u_rd;
	} icmph_u;
} icmph_t;

#define	icmph_echo_ident	icmph_u.u_echo.u_echo_ident
#define	icmph_echo_seqnum	icmph_u.u_echo.u_echo_seqnum
#define	icmph_du_zero		icmph_u.u_du.u_du_zero
#define	icmph_du_mtu		icmph_u.u_du.u_du_mtu
#define	icmph_pp_ptr		icmph_u.u_pp.u_pp_ptr
#define	icmph_rd_gateway	icmph_u.u_rd.u_rd_gateway

#define	ICMPH_SIZE	8

/*
 * Minimum length of transport layer header included in an ICMP error
 * message for it to be considered valid.
 */
#define	ICMP_MIN_TP_HDR_LEN	8

/* Aligned IP header */
typedef struct ipha_s {
	uint8_t		ipha_version_and_hdr_length;
	uint8_t		ipha_type_of_service;
	uint16_t	ipha_length;
	uint16_t	ipha_ident;
	uint16_t	ipha_fragment_offset_and_flags;
	uint8_t		ipha_ttl;
	uint8_t		ipha_protocol;
	uint16_t	ipha_hdr_checksum;
	ipaddr_t	ipha_src;
	ipaddr_t	ipha_dst;
} ipha_t;

/*
 * IP Flags
 *
 * Some of these constant names are copied for the DTrace IP provider in
 * usr/src/lib/libdtrace/common/{ip.d.in, ip.sed.in}, which should be kept
 * in sync.
 */
#define	IPH_DF		0x4000	/* Don't fragment */
#define	IPH_MF		0x2000	/* More fragments to come */
#define	IPH_OFFSET	0x1FFF	/* Where the offset lives */

/* Byte-order specific values */
#ifdef	_BIG_ENDIAN
#define	IPH_DF_HTONS	0x4000	/* Don't fragment */
#define	IPH_MF_HTONS	0x2000	/* More fragments to come */
#define	IPH_OFFSET_HTONS 0x1FFF	/* Where the offset lives */
#else
#define	IPH_DF_HTONS	0x0040	/* Don't fragment */
#define	IPH_MF_HTONS	0x0020	/* More fragments to come */
#define	IPH_OFFSET_HTONS 0xFF1F	/* Where the offset lives */
#endif

/* ECN code points for IPv4 TOS byte and IPv6 traffic class octet. */
#define	IPH_ECN_NECT	0x0	/* Not ECN-Capable Transport */
#define	IPH_ECN_ECT1	0x1	/* ECN-Capable Transport, ECT(1) */
#define	IPH_ECN_ECT0	0x2	/* ECN-Capable Transport, ECT(0) */
#define	IPH_ECN_CE	0x3	/* ECN-Congestion Experienced (CE) */

struct ill_s;

typedef	void ip_v6intfid_func_t(struct ill_s *, in6_addr_t *);
typedef void ip_v6mapinfo_func_t(struct ill_s *, uchar_t *, uchar_t *);
typedef void ip_v4mapinfo_func_t(struct ill_s *, uchar_t *, uchar_t *);

/* IP Mac info structure */
typedef struct ip_m_s {
	t_uscalar_t		ip_m_mac_type;	/* From <sys/dlpi.h> */
	int			ip_m_type;	/* From <net/if_types.h> */
	t_uscalar_t		ip_m_ipv4sap;
	t_uscalar_t		ip_m_ipv6sap;
	ip_v4mapinfo_func_t	*ip_m_v4mapping;
	ip_v6mapinfo_func_t	*ip_m_v6mapping;
	ip_v6intfid_func_t	*ip_m_v6intfid;
	ip_v6intfid_func_t	*ip_m_v6destintfid;
} ip_m_t;

/*
 * The following functions attempt to reduce the link layer dependency
 * of the IP stack. The current set of link specific operations are:
 * a. map from IPv4 class D (224.0/4) multicast address range or the
 * IPv6 multicast address range (ff00::/8) to the link layer multicast
 * address.
 * b. derive the default IPv6 interface identifier from the interface.
 * c. derive the default IPv6 destination interface identifier from
 * the interface (point-to-point only).
 */
extern	void ip_mcast_mapping(struct ill_s *, uchar_t *, uchar_t *);
/* ip_m_v6*intfid return void and are never NULL */
#define	MEDIA_V6INTFID(ip_m, ill, v6ptr) (ip_m)->ip_m_v6intfid(ill, v6ptr)
#define	MEDIA_V6DESTINTFID(ip_m, ill, v6ptr) \
	(ip_m)->ip_m_v6destintfid(ill, v6ptr)

/* Router entry types */
#define	IRE_BROADCAST		0x0001	/* Route entry for broadcast address */
#define	IRE_DEFAULT		0x0002	/* Route entry for default gateway */
#define	IRE_LOCAL		0x0004	/* Route entry for local address */
#define	IRE_LOOPBACK		0x0008	/* Route entry for loopback address */
#define	IRE_PREFIX		0x0010	/* Route entry for prefix routes */
#ifndef _KERNEL
/* Keep so user-level still compiles */
#define	IRE_CACHE		0x0020	/* Cached Route entry */
#endif
#define	IRE_IF_NORESOLVER	0x0040	/* Route entry for local interface */
					/* net without any address mapping. */
#define	IRE_IF_RESOLVER		0x0080	/* Route entry for local interface */
					/* net with resolver. */
#define	IRE_HOST		0x0100	/* Host route entry */
/* Keep so user-level still compiles */
#define	IRE_HOST_REDIRECT	0x0200	/* only used for T_SVR4_OPTMGMT_REQ */
#define	IRE_IF_CLONE		0x0400	/* Per host clone of IRE_IF */
#define	IRE_MULTICAST		0x0800	/* Special - not in table */
#define	IRE_NOROUTE		0x1000	/* Special - not in table */

#define	IRE_INTERFACE		(IRE_IF_NORESOLVER | IRE_IF_RESOLVER)

#define	IRE_IF_ALL		(IRE_IF_NORESOLVER | IRE_IF_RESOLVER | \
				    IRE_IF_CLONE)
#define	IRE_OFFSUBNET		(IRE_DEFAULT | IRE_PREFIX | IRE_HOST)
#define	IRE_OFFLINK		IRE_OFFSUBNET
/*
 * Note that we view IRE_NOROUTE as ONLINK since we can "send" to them without
 * going through a router; the result of sending will be an error/icmp error.
 */
#define	IRE_ONLINK		(IRE_IF_ALL|IRE_LOCAL|IRE_LOOPBACK| \
				    IRE_BROADCAST|IRE_MULTICAST|IRE_NOROUTE)

/* Arguments to ire_flush_cache() */
#define	IRE_FLUSH_DELETE	0
#define	IRE_FLUSH_ADD		1
#define	IRE_FLUSH_GWCHANGE	2

/*
 * Flags to ire_route_recursive
 */
#define	IRR_NONE		0
#define	IRR_ALLOCATE		1	/* OK to allocate IRE_IF_CLONE */
#define	IRR_INCOMPLETE		2	/* OK to return incomplete chain */

/*
 * Open/close synchronization flags.
 * These are kept in a separate field in the conn and the synchronization
 * depends on the atomic 32 bit access to that field.
 */
#define	CONN_CLOSING		0x01	/* ip_close waiting for ip_wsrv */
#define	CONN_CONDEMNED		0x02	/* conn is closing, no more refs */
#define	CONN_INCIPIENT		0x04	/* conn not yet visible, no refs */
#define	CONN_QUIESCED		0x08	/* conn is now quiescent */
#define	CONN_UPDATE_ILL		0x10	/* conn_update_ill in progress */

/*
 * Flags for dce_flags field. Specifies which information has been set.
 * dce_ident is always present, but the other ones are identified by the flags.
 */
#define	DCEF_DEFAULT		0x0001	/* Default DCE - no pmtu or uinfo */
#define	DCEF_PMTU		0x0002	/* Different than interface MTU */
#define	DCEF_UINFO		0x0004	/* dce_uinfo set */
#define	DCEF_TOO_SMALL_PMTU	0x0008	/* Smaller than IPv4/IPv6 MIN */

#ifdef _KERNEL
/*
 * Extra structures need for per-src-addr filtering (IGMPv3/MLDv2)
 */
#define	MAX_FILTER_SIZE	64

typedef struct slist_s {
	int		sl_numsrc;
	in6_addr_t	sl_addr[MAX_FILTER_SIZE];
} slist_t;

/*
 * Following struct is used to maintain retransmission state for
 * a multicast group.  One rtx_state_t struct is an in-line field
 * of the ilm_t struct; the slist_ts in the rtx_state_t struct are
 * alloc'd as needed.
 */
typedef struct rtx_state_s {
	uint_t		rtx_timer;	/* retrans timer */
	int		rtx_cnt;	/* retrans count */
	int		rtx_fmode_cnt;	/* retrans count for fmode change */
	slist_t		*rtx_allow;
	slist_t		*rtx_block;
} rtx_state_t;

/*
 * Used to construct list of multicast address records that will be
 * sent in a single listener report.
 */
typedef struct mrec_s {
	struct mrec_s	*mrec_next;
	uint8_t		mrec_type;
	uint8_t		mrec_auxlen;	/* currently unused */
	in6_addr_t	mrec_group;
	slist_t		mrec_srcs;
} mrec_t;

/* Group membership list per upper conn */

/*
 * We record the multicast information from the socket option in
 * ilg_ifaddr/ilg_ifindex. This allows rejoining the group in the case when
 * the ifaddr (or ifindex) disappears and later reappears, potentially on
 * a different ill. The IPv6 multicast socket options and ioctls all specify
 * the interface using an ifindex. For IPv4 some socket options/ioctls use
 * the interface address and others use the index. We record here the method
 * that was actually used (and leave the other of ilg_ifaddr or ilg_ifindex)
 * at zero so that we can rejoin the way the application intended.
 *
 * We track the ill on which we will or already have joined an ilm using
 * ilg_ill. When we have succeeded joining the ilm and have a refhold on it
 * then we set ilg_ilm. Thus intentionally there is a window where ilg_ill is
 * set and ilg_ilm is not set. This allows clearing ilg_ill as a signal that
 * the ill is being unplumbed and the ilm should be discarded.
 *
 * ilg records the state of multicast memberships of a socket end point.
 * ilm records the state of multicast memberships with the driver and is
 * maintained per interface.
 *
 * The ilg state is protected by conn_ilg_lock.
 * The ilg will not be freed until ilg_refcnt drops to zero.
 */
typedef struct ilg_s {
	struct ilg_s	*ilg_next;
	struct ilg_s	**ilg_ptpn;
	struct conn_s	*ilg_connp;	/* Back pointer to get lock */
	in6_addr_t	ilg_v6group;
	ipaddr_t	ilg_ifaddr;	/* For some IPv4 cases */
	uint_t		ilg_ifindex;	/* IPv6 and some other IPv4 cases */
	struct ill_s	*ilg_ill;	/* Where ilm is joined. No refhold */
	struct ilm_s	*ilg_ilm;	/* With ilm_refhold */
	uint_t		ilg_refcnt;
	mcast_record_t	ilg_fmode;	/* MODE_IS_INCLUDE/MODE_IS_EXCLUDE */
	slist_t		*ilg_filter;
	boolean_t	ilg_condemned;	/* Conceptually deleted */
} ilg_t;

/*
 * Multicast address list entry for ill.
 * ilm_ill is used by IPv4 and IPv6
 *
 * The ilm state (and other multicast state on the ill) is protected by
 * ill_mcast_lock. Operations that change state on both an ilg and ilm
 * in addition use ill_mcast_serializer to ensure that we can't have
 * interleaving between e.g., add and delete operations for the same conn_t,
 * group, and ill. The ill_mcast_serializer is also used to ensure that
 * multicast group joins do not occur on an interface that is in the process
 * of joining an IPMP group.
 *
 * The comment below (and for other netstack_t references) refers
 * to the fact that we only do netstack_hold in particular cases,
 * such as the references from open endpoints (ill_t and conn_t's
 * pointers). Internally within IP we rely on IP's ability to cleanup e.g.
 * ire_t's when an ill goes away.
 */
typedef struct ilm_s {
	in6_addr_t	ilm_v6addr;
	int		ilm_refcnt;
	uint_t		ilm_timer;	/* IGMP/MLD query resp timer, in msec */
	struct ilm_s	*ilm_next;	/* Linked list for each ill */
	uint_t		ilm_state;	/* state of the membership */
	struct ill_s	*ilm_ill;	/* Back pointer to ill - ill_ilm_cnt */
	zoneid_t	ilm_zoneid;
	int		ilm_no_ilg_cnt;	/* number of joins w/ no ilg */
	mcast_record_t	ilm_fmode;	/* MODE_IS_INCLUDE/MODE_IS_EXCLUDE */
	slist_t		*ilm_filter;	/* source filter list */
	slist_t		*ilm_pendsrcs;	/* relevant src addrs for pending req */
	rtx_state_t	ilm_rtx;	/* SCR retransmission state */
	ipaddr_t	ilm_ifaddr;	/* For IPv4 netstat */
	ip_stack_t	*ilm_ipst;	/* Does not have a netstack_hold */
} ilm_t;

#define	ilm_addr	V4_PART_OF_V6(ilm_v6addr)

/*
 * Soft reference to an IPsec SA.
 *
 * On relative terms, conn's can be persistent (living as long as the
 * processes which create them), while SA's are ephemeral (dying when
 * they hit their time-based or byte-based lifetimes).
 *
 * We could hold a hard reference to an SA from an ipsec_latch_t,
 * but this would cause expired SA's to linger for a potentially
 * unbounded time.
 *
 * Instead, we remember the hash bucket number and bucket generation
 * in addition to the pointer.  The bucket generation is incremented on
 * each deletion.
 */
typedef struct ipsa_ref_s
{
	struct ipsa_s	*ipsr_sa;
	struct isaf_s	*ipsr_bucket;
	uint64_t	ipsr_gen;
} ipsa_ref_t;

/*
 * IPsec "latching" state.
 *
 * In the presence of IPsec policy, fully-bound conn's bind a connection
 * to more than just the 5-tuple, but also a specific IPsec action and
 * identity-pair.
 * The identity pair is accessed from both the receive and transmit side
 * hence it is maintained in the ipsec_latch_t structure. conn_latch and
 * ixa_ipsec_latch points to it.
 * The policy and actions are stored in conn_latch_in_policy and
 * conn_latch_in_action for the inbound side, and in ixa_ipsec_policy and
 * ixa_ipsec_action for the transmit side.
 *
 * As an optimization, we also cache soft references to IPsec SA's in
 * ip_xmit_attr_t so that we can fast-path around most of the work needed for
 * outbound IPsec SA selection.
 */
typedef struct ipsec_latch_s
{
	kmutex_t	ipl_lock;
	uint32_t	ipl_refcnt;

	struct ipsid_s	*ipl_local_cid;
	struct ipsid_s	*ipl_remote_cid;
	unsigned int
			ipl_ids_latched : 1,

			ipl_pad_to_bit_31 : 31;
} ipsec_latch_t;

#define	IPLATCH_REFHOLD(ipl) { \
	atomic_add_32(&(ipl)->ipl_refcnt, 1);		\
	ASSERT((ipl)->ipl_refcnt != 0);			\
}

#define	IPLATCH_REFRELE(ipl) {				\
	ASSERT((ipl)->ipl_refcnt != 0);				\
	membar_exit();						\
	if (atomic_add_32_nv(&(ipl)->ipl_refcnt, -1) == 0)	\
		iplatch_free(ipl);				\
}

/*
 * peer identity structure.
 */
typedef struct conn_s conn_t;

/*
 * This is used to match an inbound/outbound datagram with policy.
 */
typedef	struct ipsec_selector {
	in6_addr_t	ips_local_addr_v6;
	in6_addr_t	ips_remote_addr_v6;
	uint16_t	ips_local_port;
	uint16_t	ips_remote_port;
	uint8_t		ips_icmp_type;
	uint8_t		ips_icmp_code;
	uint8_t		ips_protocol;
	uint8_t		ips_isv4 : 1,
			ips_is_icmp_inv_acq: 1;
} ipsec_selector_t;

/*
 * Note that we put v4 addresses in the *first* 32-bit word of the
 * selector rather than the last to simplify the prefix match/mask code
 * in spd.c
 */
#define	ips_local_addr_v4 ips_local_addr_v6.s6_addr32[0]
#define	ips_remote_addr_v4 ips_remote_addr_v6.s6_addr32[0]

/* Values used in IP by IPSEC Code */
#define		IPSEC_OUTBOUND		B_TRUE
#define		IPSEC_INBOUND		B_FALSE

/*
 * There are two variants in policy failures. The packet may come in
 * secure when not needed (IPSEC_POLICY_???_NOT_NEEDED) or it may not
 * have the desired level of protection (IPSEC_POLICY_MISMATCH).
 */
#define	IPSEC_POLICY_NOT_NEEDED		0
#define	IPSEC_POLICY_MISMATCH		1
#define	IPSEC_POLICY_AUTH_NOT_NEEDED	2
#define	IPSEC_POLICY_ENCR_NOT_NEEDED	3
#define	IPSEC_POLICY_SE_NOT_NEEDED	4
#define	IPSEC_POLICY_MAX		5	/* Always max + 1. */

/*
 * Check with IPSEC inbound policy if
 *
 * 1) per-socket policy is present - indicated by conn_in_enforce_policy.
 * 2) Or if we have not cached policy on the conn and the global policy is
 *    non-empty.
 */
#define	CONN_INBOUND_POLICY_PRESENT(connp, ipss)	\
	((connp)->conn_in_enforce_policy ||		\
	(!((connp)->conn_policy_cached) && 		\
	(ipss)->ipsec_inbound_v4_policy_present))

#define	CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss)	\
	((connp)->conn_in_enforce_policy ||		\
	(!(connp)->conn_policy_cached &&		\
	(ipss)->ipsec_inbound_v6_policy_present))

#define	CONN_OUTBOUND_POLICY_PRESENT(connp, ipss)	\
	((connp)->conn_out_enforce_policy ||		\
	(!((connp)->conn_policy_cached) &&		\
	(ipss)->ipsec_outbound_v4_policy_present))

#define	CONN_OUTBOUND_POLICY_PRESENT_V6(connp, ipss)	\
	((connp)->conn_out_enforce_policy ||		\
	(!(connp)->conn_policy_cached &&		\
	(ipss)->ipsec_outbound_v6_policy_present))

/*
 * Information cached in IRE for upper layer protocol (ULP).
 */
typedef struct iulp_s {
	boolean_t	iulp_set;	/* Is any metric set? */
	uint32_t	iulp_ssthresh;	/* Slow start threshold (TCP). */
	clock_t		iulp_rtt;	/* Guestimate in millisecs. */
	clock_t		iulp_rtt_sd;	/* Cached value of RTT variance. */
	uint32_t	iulp_spipe;	/* Send pipe size. */
	uint32_t	iulp_rpipe;	/* Receive pipe size. */
	uint32_t	iulp_rtomax;	/* Max round trip timeout. */
	uint32_t	iulp_sack;	/* Use SACK option (TCP)? */
	uint32_t	iulp_mtu;	/* Setable with routing sockets */

	uint32_t
		iulp_tstamp_ok : 1,	/* Use timestamp option (TCP)? */
		iulp_wscale_ok : 1,	/* Use window scale option (TCP)? */
		iulp_ecn_ok : 1,	/* Enable ECN (for TCP)? */
		iulp_pmtud_ok : 1,	/* Enable PMTUd? */

		/* These three are passed out by ip_set_destination */
		iulp_localnet: 1,	/* IRE_ONLINK */
		iulp_loopback: 1,	/* IRE_LOOPBACK */
		iulp_local: 1,		/* IRE_LOCAL */

		iulp_not_used : 25;
} iulp_t;

/*
 * The conn drain list structure (idl_t), protected by idl_lock.  Each conn_t
 * inserted in the list points back at this idl_t using conn_idl, and is
 * chained by conn_drain_next and conn_drain_prev, which are also protected by
 * idl_lock.  When flow control is relieved, either ip_wsrv() (STREAMS) or
 * ill_flow_enable() (non-STREAMS) will call conn_drain().
 *
 * The conn drain list, idl_t, itself is part of tx cookie list structure.
 * A tx cookie list points to a blocked Tx ring and contains the list of
 * all conn's that are blocked due to the flow-controlled Tx ring (via
 * the idl drain list). Note that a link can have multiple Tx rings. The
 * drain list will store the conn's blocked due to Tx ring being flow
 * controlled.
 */

typedef uintptr_t ip_mac_tx_cookie_t;
typedef	struct idl_s idl_t;
typedef	struct idl_tx_list_s idl_tx_list_t;

struct idl_tx_list_s {
	ip_mac_tx_cookie_t	txl_cookie;
	kmutex_t		txl_lock;	/* Lock for this list */
	idl_t			*txl_drain_list;
	int			txl_drain_index;
};

struct idl_s {
	conn_t		*idl_conn;		/* Head of drain list */
	kmutex_t	idl_lock;		/* Lock for this list */
	idl_tx_list_t	*idl_itl;
};

/*
 * Interface route structure which holds the necessary information to recreate
 * routes that are tied to an interface i.e. have ire_ill set.
 *
 * These routes which were initially created via a routing socket or via the
 * SIOCADDRT ioctl may be gateway routes (RTF_GATEWAY being set) or may be
 * traditional interface routes.  When an ill comes back up after being
 * down, this information will be used to recreate the routes.  These
 * are part of an mblk_t chain that hangs off of the ILL (ill_saved_ire_mp).
 */
typedef struct ifrt_s {
	ushort_t	ifrt_type;		/* Type of IRE */
	in6_addr_t	ifrt_v6addr;		/* Address IRE represents. */
	in6_addr_t	ifrt_v6gateway_addr;	/* Gateway if IRE_OFFLINK */
	in6_addr_t	ifrt_v6setsrc_addr;	/* Src addr if RTF_SETSRC */
	in6_addr_t	ifrt_v6mask;		/* Mask for matching IRE. */
	uint32_t	ifrt_flags;		/* flags related to route */
	iulp_t		ifrt_metrics;		/* Routing socket metrics */
	zoneid_t	ifrt_zoneid;		/* zoneid for route */
} ifrt_t;

#define	ifrt_addr		V4_PART_OF_V6(ifrt_v6addr)
#define	ifrt_gateway_addr	V4_PART_OF_V6(ifrt_v6gateway_addr)
#define	ifrt_mask		V4_PART_OF_V6(ifrt_v6mask)
#define	ifrt_setsrc_addr	V4_PART_OF_V6(ifrt_v6setsrc_addr)

/* Number of IP addresses that can be hosted on a physical interface */
#define	MAX_ADDRS_PER_IF	8192
/*
 * Number of Source addresses to be considered for source address
 * selection. Used by ipif_select_source_v4/v6.
 */
#define	MAX_IPIF_SELECT_SOURCE	50

#ifdef IP_DEBUG
/*
 * Trace refholds and refreles for debugging.
 */
#define	TR_STACK_DEPTH	14
typedef struct tr_buf_s {
	int	tr_depth;
	clock_t	tr_time;
	pc_t	tr_stack[TR_STACK_DEPTH];
} tr_buf_t;

typedef struct th_trace_s {
	int		th_refcnt;
	uint_t		th_trace_lastref;
	kthread_t	*th_id;
#define	TR_BUF_MAX	38
	tr_buf_t	th_trbuf[TR_BUF_MAX];
} th_trace_t;

typedef struct th_hash_s {
	list_node_t	thh_link;
	mod_hash_t	*thh_hash;
	ip_stack_t	*thh_ipst;
} th_hash_t;
#endif

/* The following are ipif_state_flags */
#define	IPIF_CONDEMNED		0x1	/* The ipif is being removed */
#define	IPIF_CHANGING		0x2	/* A critcal ipif field is changing */
#define	IPIF_SET_LINKLOCAL	0x10	/* transient flag during bringup */

/* IP interface structure, one per local address */
typedef struct ipif_s {
	struct	ipif_s	*ipif_next;
	struct	ill_s	*ipif_ill;	/* Back pointer to our ill */
	int	ipif_id;		/* Logical unit number */
	in6_addr_t ipif_v6lcl_addr;	/* Local IP address for this if. */
	in6_addr_t ipif_v6subnet;	/* Subnet prefix for this if. */
	in6_addr_t ipif_v6net_mask;	/* Net mask for this interface. */
	in6_addr_t ipif_v6brd_addr;	/* Broadcast addr for this interface. */
	in6_addr_t ipif_v6pp_dst_addr;	/* Point-to-point dest address. */
	uint64_t ipif_flags;		/* Interface flags. */
	uint_t	ipif_ire_type;		/* IRE_LOCAL or IRE_LOOPBACK */

	/*
	 * The packet count in the ipif contain the sum of the
	 * packet counts in dead IRE_LOCAL/LOOPBACK for this ipif.
	 */
	uint_t	ipif_ib_pkt_count;	/* Inbound packets for our dead IREs */

	/* Exclusive bit fields, protected by ipsq_t */
	unsigned int
		ipif_was_up : 1,	/* ipif was up before */
		ipif_addr_ready : 1,	/* DAD is done */
		ipif_was_dup : 1,	/* DAD had failed */
		ipif_added_nce : 1,	/* nce added for local address */

		ipif_pad_to_31 : 28;

	ilm_t	*ipif_allhosts_ilm;	/* For all-nodes join */
	ilm_t	*ipif_solmulti_ilm;	/* For IPv6 solicited multicast join */

	uint_t	ipif_seqid;		/* unique index across all ills */
	uint_t	ipif_state_flags;	/* See IPIF_* flag defs above */
	uint_t	ipif_refcnt;		/* active consistent reader cnt */

	zoneid_t ipif_zoneid;		/* zone ID number */
	timeout_id_t ipif_recovery_id;	/* Timer for DAD recovery */
	boolean_t ipif_trace_disable;	/* True when alloc fails */
	/*
	 * For an IPMP interface, ipif_bound_ill tracks the ill whose hardware
	 * information this ipif is associated with via ARP/NDP.  We can use
	 * an ill pointer (rather than an index) because only ills that are
	 * part of a group will be pointed to, and an ill cannot disappear
	 * while it's in a group.
	 */
	struct ill_s    *ipif_bound_ill;
	struct ipif_s   *ipif_bound_next; /* bound ipif chain */
	boolean_t	ipif_bound;	/* B_TRUE if we successfully bound */

	struct ire_s	*ipif_ire_local; /* Our IRE_LOCAL or LOOPBACK */
	struct ire_s	*ipif_ire_if;	 /* Our IRE_INTERFACE */
} ipif_t;

/*
 * The following table lists the protection levels of the various members
 * of the ipif_t. The following notation is used.
 *
 * Write once - Written to only once at the time of bringing up
 * the interface and can be safely read after the bringup without any lock.
 *
 * ipsq - Need to execute in the ipsq to perform the indicated access.
 *
 * ill_lock - Need to hold this mutex to perform the indicated access.
 *
 * ill_g_lock - Need to hold this rw lock as reader/writer for read access or
 * write access respectively.
 *
 * down ill - Written to only when the ill is down (i.e all ipifs are down)
 * up ill - Read only when the ill is up (i.e. at least 1 ipif is up)
 *
 *		 Table of ipif_t members and their protection
 *
 * ipif_next		ipsq + ill_lock +	ipsq OR ill_lock OR
 *			ill_g_lock		ill_g_lock
 * ipif_ill		ipsq + down ipif	write once
 * ipif_id		ipsq + down ipif	write once
 * ipif_v6lcl_addr	ipsq + down ipif	up ipif
 * ipif_v6subnet	ipsq + down ipif	up ipif
 * ipif_v6net_mask	ipsq + down ipif	up ipif
 *
 * ipif_v6brd_addr
 * ipif_v6pp_dst_addr
 * ipif_flags		ill_lock		ill_lock
 * ipif_ire_type	ipsq + down ill		up ill
 *
 * ipif_ib_pkt_count	Approx
 *
 * bit fields		ill_lock		ill_lock
 *
 * ipif_allhosts_ilm	ipsq			ipsq
 * ipif_solmulti_ilm	ipsq			ipsq
 *
 * ipif_seqid		ipsq			Write once
 *
 * ipif_state_flags	ill_lock		ill_lock
 * ipif_refcnt		ill_lock		ill_lock
 * ipif_bound_ill	ipsq + ipmp_lock	ipsq OR ipmp_lock
 * ipif_bound_next	ipsq			ipsq
 * ipif_bound		ipsq			ipsq
 *
 * ipif_ire_local	ipsq + ips_ill_g_lock	ipsq OR ips_ill_g_lock
 * ipif_ire_if		ipsq + ips_ill_g_lock	ipsq OR ips_ill_g_lock
 */

/*
 * Return values from ip_laddr_verify_{v4,v6}
 */
typedef enum { IPVL_UNICAST_UP, IPVL_UNICAST_DOWN, IPVL_MCAST, IPVL_BCAST,
	    IPVL_BAD} ip_laddr_t;


#define	IP_TR_HASH(tid)	((((uintptr_t)tid) >> 6) & (IP_TR_HASH_MAX - 1))

#ifdef DEBUG
#define	IPIF_TRACE_REF(ipif)	ipif_trace_ref(ipif)
#define	ILL_TRACE_REF(ill)	ill_trace_ref(ill)
#define	IPIF_UNTRACE_REF(ipif)	ipif_untrace_ref(ipif)
#define	ILL_UNTRACE_REF(ill)	ill_untrace_ref(ill)
#else
#define	IPIF_TRACE_REF(ipif)
#define	ILL_TRACE_REF(ill)
#define	IPIF_UNTRACE_REF(ipif)
#define	ILL_UNTRACE_REF(ill)
#endif

/* IPv4 compatibility macros */
#define	ipif_lcl_addr		V4_PART_OF_V6(ipif_v6lcl_addr)
#define	ipif_subnet		V4_PART_OF_V6(ipif_v6subnet)
#define	ipif_net_mask		V4_PART_OF_V6(ipif_v6net_mask)
#define	ipif_brd_addr		V4_PART_OF_V6(ipif_v6brd_addr)
#define	ipif_pp_dst_addr	V4_PART_OF_V6(ipif_v6pp_dst_addr)

/* Macros for easy backreferences to the ill. */
#define	ipif_isv6		ipif_ill->ill_isv6

#define	SIOCLIFADDR_NDX 112	/* ndx of SIOCLIFADDR in the ndx ioctl table */

/*
 * mode value for ip_ioctl_finish for finishing an ioctl
 */
#define	CONN_CLOSE	1		/* No mi_copy */
#define	COPYOUT		2		/* do an mi_copyout if needed */
#define	NO_COPYOUT	3		/* do an mi_copy_done */
#define	IPI2MODE(ipi)	((ipi)->ipi_flags & IPI_GET_CMD ? COPYOUT : NO_COPYOUT)

/*
 * The IP-MT design revolves around the serialization objects ipsq_t (IPSQ)
 * and ipxop_t (exclusive operation or "xop").  Becoming "writer" on an IPSQ
 * ensures that no other threads can become "writer" on any IPSQs sharing that
 * IPSQ's xop until the writer thread is done.
 *
 * Each phyint points to one IPSQ that remains fixed over the phyint's life.
 * Each IPSQ points to one xop that can change over the IPSQ's life.  If a
 * phyint is *not* in an IPMP group, then its IPSQ will refer to the IPSQ's
 * "own" xop (ipsq_ownxop).  If a phyint *is* part of an IPMP group, then its
 * IPSQ will refer to the "group" xop, which is shorthand for the xop of the
 * IPSQ of the IPMP meta-interface's phyint.  Thus, all phyints that are part
 * of the same IPMP group will have their IPSQ's point to the group xop, and
 * thus becoming "writer" on any phyint in the group will prevent any other
 * writer on any other phyint in the group.  All IPSQs sharing the same xop
 * are chained together through ipsq_next (in the degenerate common case,
 * ipsq_next simply refers to itself).  Note that the group xop is guaranteed
 * to exist at least as long as there are members in the group, since the IPMP
 * meta-interface can only be destroyed if the group is empty.
 *
 * Incoming exclusive operation requests are enqueued on the IPSQ they arrived
 * on rather than the xop.  This makes switching xop's (as would happen when a
 * phyint leaves an IPMP group) simple, because after the phyint leaves the
 * group, any operations enqueued on its IPSQ can be safely processed with
 * respect to its new xop, and any operations enqueued on the IPSQs of its
 * former group can be processed with respect to their existing group xop.
 * Even so, switching xops is a subtle dance; see ipsq_dq() for details.
 *
 * An IPSQ's "own" xop is embedded within the IPSQ itself since they have have
 * identical lifetimes, and because doing so simplifies pointer management.
 * While each phyint and IPSQ point to each other, it is not possible to free
 * the IPSQ when the phyint is freed, since we may still *inside* the IPSQ
 * when the phyint is being freed.  Thus, ipsq_phyint is set to NULL when the
 * phyint is freed, and the IPSQ free is later done in ipsq_exit().
 *
 * ipsq_t synchronization:	read			write
 *
 *	ipsq_xopq_mphead	ipx_lock		ipx_lock
 *	ipsq_xopq_mptail	ipx_lock		ipx_lock
 *	ipsq_xop_switch_mp	ipsq_lock		ipsq_lock
 *	ipsq_phyint		write once		write once
 *	ipsq_next		RW_READER ill_g_lock	RW_WRITER ill_g_lock
 *	ipsq_xop 		ipsq_lock or ipsq	ipsq_lock + ipsq
 *	ipsq_swxop		ipsq			ipsq
 * 	ipsq_ownxop		see ipxop_t		see ipxop_t
 *	ipsq_ipst		write once		write once
 *
 * ipxop_t synchronization:     read			write
 *
 *	ipx_writer  		ipx_lock		ipx_lock
 *	ipx_xop_queued		ipx_lock 		ipx_lock
 *	ipx_mphead		ipx_lock		ipx_lock
 *	ipx_mptail		ipx_lock		ipx_lock
 *	ipx_ipsq		write once		write once
 *	ips_ipsq_queued		ipx_lock		ipx_lock
 *	ipx_waitfor		ipsq or ipx_lock	ipsq + ipx_lock
 *	ipx_reentry_cnt		ipsq or ipx_lock	ipsq + ipx_lock
 *	ipx_current_done	ipsq			ipsq
 *	ipx_current_ioctl	ipsq			ipsq
 *	ipx_current_ipif	ipsq or ipx_lock	ipsq + ipx_lock
 *	ipx_pending_ipif	ipsq or ipx_lock	ipsq + ipx_lock
 *	ipx_pending_mp		ipsq or ipx_lock	ipsq + ipx_lock
 *	ipx_forced		ipsq			ipsq
 *	ipx_depth		ipsq			ipsq
 *	ipx_stack		ipsq			ipsq
 */
typedef struct ipxop_s {
	kmutex_t	ipx_lock;	/* see above */
	kthread_t	*ipx_writer;  	/* current owner */
	mblk_t		*ipx_mphead;	/* messages tied to this op */
	mblk_t		*ipx_mptail;
	struct ipsq_s	*ipx_ipsq;	/* associated ipsq */
	boolean_t	ipx_ipsq_queued; /* ipsq using xop has queued op */
	int		ipx_waitfor;	/* waiting; values encoded below */
	int		ipx_reentry_cnt;
	boolean_t	ipx_current_done;  /* is the current operation done? */
	int		ipx_current_ioctl; /* current ioctl, or 0 if no ioctl */
	ipif_t		*ipx_current_ipif; /* ipif for current op */
	ipif_t		*ipx_pending_ipif; /* ipif for ipx_pending_mp */
	mblk_t 		*ipx_pending_mp;   /* current ioctl mp while waiting */
	boolean_t	ipx_forced; 			/* debugging aid */
#ifdef DEBUG
	int		ipx_depth;			/* debugging aid */
#define	IPX_STACK_DEPTH	15
	pc_t		ipx_stack[IPX_STACK_DEPTH];	/* debugging aid */
#endif
} ipxop_t;

typedef struct ipsq_s {
	kmutex_t ipsq_lock;		/* see above */
	mblk_t	*ipsq_switch_mp;	/* op to handle right after switch */
	mblk_t	*ipsq_xopq_mphead;	/* list of excl ops (mostly ioctls) */
	mblk_t	*ipsq_xopq_mptail;
	struct phyint	*ipsq_phyint;	/* associated phyint */
	struct ipsq_s	*ipsq_next;	/* next ipsq sharing ipsq_xop */
	struct ipxop_s	*ipsq_xop;	/* current xop synchronization info */
	struct ipxop_s	*ipsq_swxop;	/* switch xop to on ipsq_exit() */
	struct ipxop_s	ipsq_ownxop;	/* our own xop (may not be in-use) */
	ip_stack_t	*ipsq_ipst;	/* does not have a netstack_hold */
} ipsq_t;

/*
 * ipx_waitfor values:
 */
enum {
	IPIF_DOWN = 1,	/* ipif_down() waiting for refcnts to drop */
	ILL_DOWN,	/* ill_down() waiting for refcnts to drop */
	IPIF_FREE,	/* ipif_free() waiting for refcnts to drop */
	ILL_FREE	/* ill unplumb waiting for refcnts to drop */
};

/* Operation types for ipsq_try_enter() */
#define	CUR_OP 0	/* request writer within current operation */
#define	NEW_OP 1	/* request writer for a new operation */
#define	SWITCH_OP 2	/* request writer once IPSQ XOP switches */

/*
 * Kstats tracked on each IPMP meta-interface.  Order here must match
 * ipmp_kstats[] in ip/ipmp.c.
 */
enum {
	IPMP_KSTAT_OBYTES,	IPMP_KSTAT_OBYTES64,	IPMP_KSTAT_RBYTES,
	IPMP_KSTAT_RBYTES64,	IPMP_KSTAT_OPACKETS,	IPMP_KSTAT_OPACKETS64,
	IPMP_KSTAT_OERRORS,	IPMP_KSTAT_IPACKETS,	IPMP_KSTAT_IPACKETS64,
	IPMP_KSTAT_IERRORS,	IPMP_KSTAT_MULTIRCV,	IPMP_KSTAT_MULTIXMT,
	IPMP_KSTAT_BRDCSTRCV,	IPMP_KSTAT_BRDCSTXMT,	IPMP_KSTAT_LINK_UP,
	IPMP_KSTAT_MAX		/* keep last */
};

/*
 * phyint represents state that is common to both IPv4 and IPv6 interfaces.
 * There is a separate ill_t representing IPv4 and IPv6 which has a
 * backpointer to the phyint structure for accessing common state.
 */
typedef struct phyint {
	struct ill_s	*phyint_illv4;
	struct ill_s	*phyint_illv6;
	uint_t		phyint_ifindex;		/* SIOCSLIFINDEX */
	uint64_t	phyint_flags;
	avl_node_t	phyint_avl_by_index;	/* avl tree by index */
	avl_node_t	phyint_avl_by_name;	/* avl tree by name */
	kmutex_t	phyint_lock;
	struct ipsq_s	*phyint_ipsq;		/* back pointer to ipsq */
	struct ipmp_grp_s *phyint_grp;		/* associated IPMP group */
	char		phyint_name[LIFNAMSIZ];	/* physical interface name */
	uint64_t	phyint_kstats0[IPMP_KSTAT_MAX];	/* baseline kstats */
} phyint_t;

#define	CACHE_ALIGN_SIZE 64
#define	CACHE_ALIGN(align_struct)	P2ROUNDUP(sizeof (struct align_struct),\
							CACHE_ALIGN_SIZE)
struct _phyint_list_s_ {
	avl_tree_t	phyint_list_avl_by_index;	/* avl tree by index */
	avl_tree_t	phyint_list_avl_by_name;	/* avl tree by name */
};

typedef union phyint_list_u {
	struct	_phyint_list_s_ phyint_list_s;
	char	phyint_list_filler[CACHE_ALIGN(_phyint_list_s_)];
} phyint_list_t;

#define	phyint_list_avl_by_index	phyint_list_s.phyint_list_avl_by_index
#define	phyint_list_avl_by_name		phyint_list_s.phyint_list_avl_by_name

/*
 * Fragmentation hash bucket
 */
typedef struct ipfb_s {
	struct ipf_s	*ipfb_ipf;	/* List of ... */
	size_t		ipfb_count;	/* Count of bytes used by frag(s) */
	kmutex_t	ipfb_lock;	/* Protect all ipf in list */
	uint_t		ipfb_frag_pkts; /* num of distinct fragmented pkts */
} ipfb_t;

/*
 * IRE bucket structure. Usually there is an array of such structures,
 * each pointing to a linked list of ires. irb_refcnt counts the number
 * of walkers of a given hash bucket. Usually the reference count is
 * bumped up if the walker wants no IRES to be DELETED while walking the
 * list. Bumping up does not PREVENT ADDITION. This allows walking a given
 * hash bucket without stumbling up on a free pointer.
 *
 * irb_t structures in ip_ftable are dynamically allocated and freed.
 * In order to identify the irb_t structures that can be safely kmem_free'd
 * we need to ensure that
 *  - the irb_refcnt is quiescent, indicating no other walkers,
 *  - no other threads or ire's are holding references to the irb,
 *	i.e., irb_nire == 0,
 *  - there are no active ire's in the bucket, i.e., irb_ire_cnt == 0
 */
typedef struct irb {
	struct ire_s	*irb_ire;	/* First ire in this bucket */
					/* Should be first in this struct */
	krwlock_t	irb_lock;	/* Protect this bucket */
	uint_t		irb_refcnt;	/* Protected by irb_lock */
	uchar_t		irb_marks;	/* CONDEMNED ires in this bucket ? */
#define	IRB_MARK_CONDEMNED	0x0001	/* Contains some IRE_IS_CONDEMNED */
#define	IRB_MARK_DYNAMIC	0x0002	/* Dynamically allocated */
	/* Once IPv6 uses radix then IRB_MARK_DYNAMIC will be always be set */
	uint_t		irb_ire_cnt;	/* Num of active IRE in this bucket */
	int		irb_nire;	/* Num of ftable ire's that ref irb */
	ip_stack_t	*irb_ipst;	/* Does not have a netstack_hold */
} irb_t;

/*
 * This is the structure used to store the multicast physical addresses
 * that an interface has joined.
 * The refcnt keeps track of the number of multicast IP addresses mapping
 * to a physical multicast address.
 */
typedef struct multiphysaddr_s {
	struct	multiphysaddr_s  *mpa_next;
	char	mpa_addr[IP_MAX_HW_LEN];
	int	mpa_refcnt;
} multiphysaddr_t;

#define	IRB2RT(irb)	(rt_t *)((caddr_t)(irb) - offsetof(rt_t, rt_irb))

/* Forward declarations */
struct dce_s;
typedef struct dce_s dce_t;
struct ire_s;
typedef struct ire_s ire_t;
struct ncec_s;
typedef struct ncec_s ncec_t;
struct nce_s;
typedef struct nce_s nce_t;
struct ip_recv_attr_s;
typedef struct ip_recv_attr_s ip_recv_attr_t;
struct ip_xmit_attr_s;
typedef struct ip_xmit_attr_s ip_xmit_attr_t;

struct tsol_ire_gw_secattr_s;
typedef struct tsol_ire_gw_secattr_s tsol_ire_gw_secattr_t;

/*
 * This is a structure for a one-element route cache that is passed
 * by reference between ip_input and ill_inputfn.
 */
typedef struct {
	ire_t		*rtc_ire;
	ipaddr_t	rtc_ipaddr;
	in6_addr_t	rtc_ip6addr;
} rtc_t;

/*
 * Note: Temporarily use 64 bits, and will probably go back to 32 bits after
 * more cleanup work is done.
 */
typedef uint64_t iaflags_t;

/* The ill input function pointer type */
typedef void (*pfillinput_t)(mblk_t *, void *, void *, ip_recv_attr_t *,
    rtc_t *);

/* The ire receive function pointer type */
typedef void (*pfirerecv_t)(ire_t *, mblk_t *, void *, ip_recv_attr_t *);

/* The ire send and postfrag function pointer types */
typedef int (*pfiresend_t)(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
typedef int (*pfirepostfrag_t)(mblk_t *, nce_t *, iaflags_t, uint_t, uint32_t,
    zoneid_t, zoneid_t, uintptr_t *);


#define	IP_V4_G_HEAD	0
#define	IP_V6_G_HEAD	1

#define	MAX_G_HEADS	2

/*
 * unpadded ill_if structure
 */
struct 	_ill_if_s_ {
	union ill_if_u	*illif_next;
	union ill_if_u	*illif_prev;
	avl_tree_t	illif_avl_by_ppa;	/* AVL tree sorted on ppa */
	vmem_t		*illif_ppa_arena;	/* ppa index space */
	uint16_t	illif_mcast_v1;		/* hints for		  */
	uint16_t	illif_mcast_v2;		/* [igmp|mld]_slowtimo	  */
	int		illif_name_len;		/* name length */
	char		illif_name[LIFNAMSIZ];	/* name of interface type */
};

/* cache aligned ill_if structure */
typedef union 	ill_if_u {
	struct  _ill_if_s_ ill_if_s;
	char 	illif_filler[CACHE_ALIGN(_ill_if_s_)];
} ill_if_t;

#define	illif_next		ill_if_s.illif_next
#define	illif_prev		ill_if_s.illif_prev
#define	illif_avl_by_ppa	ill_if_s.illif_avl_by_ppa
#define	illif_ppa_arena		ill_if_s.illif_ppa_arena
#define	illif_mcast_v1		ill_if_s.illif_mcast_v1
#define	illif_mcast_v2		ill_if_s.illif_mcast_v2
#define	illif_name		ill_if_s.illif_name
#define	illif_name_len		ill_if_s.illif_name_len

typedef struct ill_walk_context_s {
	int	ctx_current_list; /* current list being searched */
	int	ctx_last_list;	 /* last list to search */
} ill_walk_context_t;

/*
 * ill_g_heads structure, one for IPV4 and one for IPV6
 */
struct _ill_g_head_s_ {
	ill_if_t	*ill_g_list_head;
	ill_if_t	*ill_g_list_tail;
};

typedef union ill_g_head_u {
	struct _ill_g_head_s_ ill_g_head_s;
	char	ill_g_head_filler[CACHE_ALIGN(_ill_g_head_s_)];
} ill_g_head_t;

#define	ill_g_list_head	ill_g_head_s.ill_g_list_head
#define	ill_g_list_tail	ill_g_head_s.ill_g_list_tail

#define	IP_V4_ILL_G_LIST(ipst)	\
	(ipst)->ips_ill_g_heads[IP_V4_G_HEAD].ill_g_list_head
#define	IP_V6_ILL_G_LIST(ipst)	\
	(ipst)->ips_ill_g_heads[IP_V6_G_HEAD].ill_g_list_head
#define	IP_VX_ILL_G_LIST(i, ipst)	\
	(ipst)->ips_ill_g_heads[i].ill_g_list_head

#define	ILL_START_WALK_V4(ctx_ptr, ipst)	\
	ill_first(IP_V4_G_HEAD, IP_V4_G_HEAD, ctx_ptr, ipst)
#define	ILL_START_WALK_V6(ctx_ptr, ipst)	\
	ill_first(IP_V6_G_HEAD, IP_V6_G_HEAD, ctx_ptr, ipst)
#define	ILL_START_WALK_ALL(ctx_ptr, ipst)	\
	ill_first(MAX_G_HEADS, MAX_G_HEADS, ctx_ptr, ipst)

/*
 * Capabilities, possible flags for ill_capabilities.
 */
#define	ILL_CAPAB_LSO		0x04		/* Large Send Offload */
#define	ILL_CAPAB_HCKSUM	0x08		/* Hardware checksumming */
#define	ILL_CAPAB_ZEROCOPY	0x10		/* Zero-copy */
#define	ILL_CAPAB_DLD		0x20		/* DLD capabilities */
#define	ILL_CAPAB_DLD_POLL	0x40		/* Polling */
#define	ILL_CAPAB_DLD_DIRECT	0x80		/* Direct function call */

/*
 * Per-ill Hardware Checksumming capbilities.
 */
typedef struct ill_hcksum_capab_s ill_hcksum_capab_t;

/*
 * Per-ill Zero-copy capabilities.
 */
typedef struct ill_zerocopy_capab_s ill_zerocopy_capab_t;

/*
 * DLD capbilities.
 */
typedef struct ill_dld_capab_s ill_dld_capab_t;

/*
 * Per-ill polling resource map.
 */
typedef struct ill_rx_ring ill_rx_ring_t;

/*
 * Per-ill Large Send Offload capabilities.
 */
typedef struct ill_lso_capab_s ill_lso_capab_t;

/* The following are ill_state_flags */
#define	ILL_LL_SUBNET_PENDING	0x01	/* Waiting for DL_INFO_ACK from drv */
#define	ILL_CONDEMNED		0x02	/* No more new ref's to the ILL */
#define	ILL_DL_UNBIND_IN_PROGRESS	0x04	/* UNBIND_REQ is sent */
/*
 * ILL_DOWN_IN_PROGRESS is set to ensure the following:
 * - no packets are sent to the driver after the DL_UNBIND_REQ is sent,
 * - no longstanding references will be acquired on objects that are being
 *   brought down.
 */
#define	ILL_DOWN_IN_PROGRESS	0x08

/* Is this an ILL whose source address is used by other ILL's ? */
#define	IS_USESRC_ILL(ill)			\
	(((ill)->ill_usesrc_ifindex == 0) &&	\
	((ill)->ill_usesrc_grp_next != NULL))

/* Is this a client/consumer of the usesrc ILL ? */
#define	IS_USESRC_CLI_ILL(ill)			\
	(((ill)->ill_usesrc_ifindex != 0) &&	\
	((ill)->ill_usesrc_grp_next != NULL))

/* Is this an virtual network interface (vni) ILL ? */
#define	IS_VNI(ill)							\
	(((ill)->ill_phyint->phyint_flags & (PHYI_LOOPBACK|PHYI_VIRTUAL)) == \
	PHYI_VIRTUAL)

/* Is this a loopback ILL? */
#define	IS_LOOPBACK(ill) \
	((ill)->ill_phyint->phyint_flags & PHYI_LOOPBACK)

/* Is this an IPMP meta-interface ILL? */
#define	IS_IPMP(ill)							\
	((ill)->ill_phyint->phyint_flags & PHYI_IPMP)

/* Is this ILL under an IPMP meta-interface? (aka "in a group?") */
#define	IS_UNDER_IPMP(ill)						\
	((ill)->ill_grp != NULL && !IS_IPMP(ill))

/* Is ill1 in the same illgrp as ill2? */
#define	IS_IN_SAME_ILLGRP(ill1, ill2)					\
	((ill1)->ill_grp != NULL && ((ill1)->ill_grp == (ill2)->ill_grp))

/* Is ill1 on the same LAN as ill2? */
#define	IS_ON_SAME_LAN(ill1, ill2)					\
	((ill1) == (ill2) || IS_IN_SAME_ILLGRP(ill1, ill2))

#define	ILL_OTHER(ill)							\
	((ill)->ill_isv6 ? (ill)->ill_phyint->phyint_illv4 :		\
	    (ill)->ill_phyint->phyint_illv6)

/*
 * IPMP group ILL state structure -- up to two per IPMP group (V4 and V6).
 * Created when the V4 and/or V6 IPMP meta-interface is I_PLINK'd.  It is
 * guaranteed to persist while there are interfaces of that type in the group.
 * In general, most fields are accessed outside of the IPSQ (e.g., in the
 * datapath), and thus use locks in addition to the IPSQ for protection.
 *
 * synchronization:		read			write
 *
 *	ig_if			ipsq or ill_g_lock	ipsq and ill_g_lock
 *	ig_actif		ipsq or ipmp_lock	ipsq and ipmp_lock
 *	ig_nactif		ipsq or ipmp_lock	ipsq and ipmp_lock
 *	ig_next_ill		ipsq or ipmp_lock	ipsq and ipmp_lock
 *	ig_ipmp_ill		write once		write once
 *	ig_cast_ill		ipsq or ipmp_lock	ipsq and ipmp_lock
 *	ig_arpent		ipsq			ipsq
 *	ig_mtu			ipsq			ipsq
 *	ig_mc_mtu		ipsq			ipsq
 */
typedef struct ipmp_illgrp_s {
	list_t		ig_if; 		/* list of all interfaces */
	list_t		ig_actif;	/* list of active interfaces */
	uint_t		ig_nactif;	/* number of active interfaces */
	struct ill_s	*ig_next_ill;	/* next active interface to use */
	struct ill_s	*ig_ipmp_ill;	/* backpointer to IPMP meta-interface */
	struct ill_s	*ig_cast_ill;	/* nominated ill for multi/broadcast */
	list_t		ig_arpent;	/* list of ARP entries */
	uint_t		ig_mtu;		/* ig_ipmp_ill->ill_mtu */
	uint_t		ig_mc_mtu;	/* ig_ipmp_ill->ill_mc_mtu */
} ipmp_illgrp_t;

/*
 * IPMP group state structure -- one per IPMP group.  Created when the
 * IPMP meta-interface is plumbed; it is guaranteed to persist while there
 * are interfaces in it.
 *
 * ipmp_grp_t synchronization:		read			write
 *
 *	gr_name				ipmp_lock		ipmp_lock
 *	gr_ifname			write once		write once
 *	gr_mactype			ipmp_lock		ipmp_lock
 *	gr_phyint			write once		write once
 *	gr_nif				ipmp_lock		ipmp_lock
 *	gr_nactif			ipsq			ipsq
 *	gr_v4				ipmp_lock		ipmp_lock
 *	gr_v6				ipmp_lock		ipmp_lock
 *	gr_nv4				ipmp_lock		ipmp_lock
 *	gr_nv6				ipmp_lock		ipmp_lock
 *	gr_pendv4			ipmp_lock		ipmp_lock
 *	gr_pendv6			ipmp_lock		ipmp_lock
 *	gr_linkdownmp			ipsq			ipsq
 *	gr_ksp				ipmp_lock		ipmp_lock
 *	gr_kstats0			atomic			atomic
 */
typedef struct ipmp_grp_s {
	char		gr_name[LIFGRNAMSIZ];	/* group name */
	char		gr_ifname[LIFNAMSIZ];	/* interface name */
	t_uscalar_t	gr_mactype;	/* DLPI mactype of group */
	phyint_t	*gr_phyint;	/* IPMP group phyint */
	uint_t		gr_nif;		/* number of interfaces in group */
	uint_t		gr_nactif; 	/* number of active interfaces */
	ipmp_illgrp_t	*gr_v4;		/* V4 group information */
	ipmp_illgrp_t	*gr_v6;		/* V6 group information */
	uint_t		gr_nv4;		/* number of ills in V4 group */
	uint_t		gr_nv6;		/* number of ills in V6 group */
	uint_t		gr_pendv4; 	/* number of pending ills in V4 group */
	uint_t		gr_pendv6; 	/* number of pending ills in V6 group */
	mblk_t		*gr_linkdownmp;	/* message used to bring link down */
	kstat_t		*gr_ksp;	/* group kstat pointer */
	uint64_t	gr_kstats0[IPMP_KSTAT_MAX]; /* baseline group kstats */
} ipmp_grp_t;

/*
 * IPMP ARP entry -- one per SIOCS*ARP entry tied to the group.  Used to keep
 * ARP up-to-date as the active set of interfaces in the group changes.
 */
typedef struct ipmp_arpent_s {
	ipaddr_t	ia_ipaddr; 	/* IP address for this entry */
	boolean_t	ia_proxyarp; 	/* proxy ARP entry? */
	boolean_t	ia_notified; 	/* ARP notified about this entry? */
	list_node_t	ia_node; 	/* next ARP entry in list */
	uint16_t	ia_flags;	/* nce_flags for the address */
	size_t		ia_lladdr_len;
	uchar_t		*ia_lladdr;
} ipmp_arpent_t;

struct arl_s;

/*
 * Per-ill capabilities.
 */
struct ill_hcksum_capab_s {
	uint_t	ill_hcksum_version;	/* interface version */
	uint_t	ill_hcksum_txflags;	/* capabilities on transmit */
};

struct ill_zerocopy_capab_s {
	uint_t	ill_zerocopy_version;	/* interface version */
	uint_t	ill_zerocopy_flags;	/* capabilities */
};

struct ill_lso_capab_s {
	uint_t	ill_lso_flags;		/* capabilities */
	uint_t	ill_lso_max;		/* maximum size of payload */
};

/*
 * IP Lower level Structure.
 * Instance data structure in ip_open when there is a device below us.
 */
typedef struct ill_s {
	pfillinput_t ill_inputfn;	/* Fast input function selector */
	ill_if_t *ill_ifptr;		/* pointer to interface type */
	queue_t	*ill_rq;		/* Read queue. */
	queue_t	*ill_wq;		/* Write queue. */

	int	ill_error;		/* Error value sent up by device. */

	ipif_t	*ill_ipif;		/* Interface chain for this ILL. */

	uint_t	ill_ipif_up_count;	/* Number of IPIFs currently up. */
	uint_t	ill_max_frag;		/* Max IDU from DLPI. */
	uint_t	ill_current_frag;	/* Current IDU from DLPI. */
	uint_t	ill_mtu;		/* User-specified MTU; SIOCSLIFMTU */
	uint_t	ill_mc_mtu;		/* MTU for multi/broadcast */
	uint_t	ill_metric;		/* BSD if metric, for compatibility. */
	char	*ill_name;		/* Our name. */
	uint_t	ill_ipif_dup_count;	/* Number of duplicate addresses. */
	uint_t	ill_name_length;	/* Name length, incl. terminator. */
	uint_t	ill_net_type;		/* IRE_IF_RESOLVER/IRE_IF_NORESOLVER. */
	/*
	 * Physical Point of Attachment num.  If DLPI style 1 provider
	 * then this is derived from the devname.
	 */
	uint_t	ill_ppa;
	t_uscalar_t	ill_sap;
	t_scalar_t	ill_sap_length;	/* Including sign (for position) */
	uint_t	ill_phys_addr_length;	/* Excluding the sap. */
	uint_t	ill_bcast_addr_length;	/* Only set when the DL provider */
					/* supports broadcast. */
	t_uscalar_t	ill_mactype;
	uint8_t	*ill_frag_ptr;		/* Reassembly state. */
	timeout_id_t ill_frag_timer_id; /* timeout id for the frag timer */
	ipfb_t	*ill_frag_hash_tbl;	/* Fragment hash list head. */

	krwlock_t ill_mcast_lock;	/* Protects multicast state */
	kmutex_t ill_mcast_serializer;	/* Serialize across ilg and ilm state */
	ilm_t	*ill_ilm;		/* Multicast membership for ill */
	uint_t	ill_global_timer;	/* for IGMPv3/MLDv2 general queries */
	int	ill_mcast_type;		/* type of router which is querier */
					/* on this interface */
	uint16_t ill_mcast_v1_time;	/* # slow timeouts since last v1 qry */
	uint16_t ill_mcast_v2_time;	/* # slow timeouts since last v2 qry */
	uint8_t	ill_mcast_v1_tset;	/* 1 => timer is set; 0 => not set */
	uint8_t	ill_mcast_v2_tset;	/* 1 => timer is set; 0 => not set */

	uint8_t	ill_mcast_rv;		/* IGMPv3/MLDv2 robustness variable */
	int	ill_mcast_qi;		/* IGMPv3/MLDv2 query interval var */

	/*
	 * All non-NULL cells between 'ill_first_mp_to_free' and
	 * 'ill_last_mp_to_free' are freed in ill_delete.
	 */
#define	ill_first_mp_to_free	ill_bcast_mp
	mblk_t	*ill_bcast_mp;		/* DLPI header for broadcasts. */
	mblk_t	*ill_unbind_mp;		/* unbind mp from ill_dl_up() */
	mblk_t	*ill_promiscoff_mp;	/* for ill_leave_allmulti() */
	mblk_t	*ill_dlpi_deferred;	/* b_next chain of control messages */
	mblk_t	*ill_dest_addr_mp;	/* mblk which holds ill_dest_addr */
	mblk_t	*ill_replumb_mp;	/* replumb mp from ill_replumb() */
	mblk_t	*ill_phys_addr_mp;	/* mblk which holds ill_phys_addr */
	mblk_t	*ill_mcast_deferred;	/* b_next chain of IGMP/MLD packets */
#define	ill_last_mp_to_free	ill_mcast_deferred

	cred_t	*ill_credp;		/* opener's credentials */
	uint8_t	*ill_phys_addr;		/* ill_phys_addr_mp->b_rptr + off */
	uint8_t *ill_dest_addr;		/* ill_dest_addr_mp->b_rptr + off */

	uint_t	ill_state_flags;	/* see ILL_* flags above */

	/* Following bit fields protected by ipsq_t */
	uint_t
		ill_needs_attach : 1,
		ill_reserved : 1,
		ill_isv6 : 1,
		ill_dlpi_style_set : 1,

		ill_ifname_pending : 1,
		ill_logical_down : 1,
		ill_dl_up : 1,
		ill_up_ipifs : 1,

		ill_note_link : 1,	/* supports link-up notification */
		ill_capab_reneg : 1, /* capability renegotiation to be done */
		ill_dld_capab_inprog : 1, /* direct dld capab call in prog */
		ill_need_recover_multicast : 1,

		ill_replumbing : 1,
		ill_arl_dlpi_pending : 1,
		ill_grp_pending : 1,

		ill_pad_to_bit_31 : 17;

	/* Following bit fields protected by ill_lock */
	uint_t
		ill_fragtimer_executing : 1,
		ill_fragtimer_needrestart : 1,
		ill_manual_token : 1,	/* system won't override ill_token */
		/*
		 * ill_manual_linklocal : system will not change the
		 * linklocal whenever ill_token changes.
		 */
		ill_manual_linklocal : 1,

		ill_manual_dst_linklocal : 1, /* same for pt-pt dst linklocal */

		ill_pad_bit_31 : 27;

	/*
	 * Used in SIOCSIFMUXID and SIOCGIFMUXID for 'ifconfig unplumb'.
	 */
	int	ill_muxid;		/* muxid returned from plink */

	/* Used for IP frag reassembly throttling on a per ILL basis.  */
	uint_t	ill_ipf_gen;		/* Generation of next fragment queue */
	uint_t	ill_frag_count;		/* Count of all reassembly mblk bytes */
	uint_t	ill_frag_free_num_pkts;	 /* num of fragmented packets to free */
	clock_t	ill_last_frag_clean_time; /* time when frag's were pruned */
	int	ill_type;		/* From <net/if_types.h> */
	uint_t	ill_dlpi_multicast_state;	/* See below IDS_* */
	uint_t	ill_dlpi_fastpath_state;	/* See below IDS_* */

	/*
	 * Capabilities related fields.
	 */
	uint_t  ill_dlpi_capab_state;	/* State of capability query, IDCS_* */
	uint_t	ill_capab_pending_cnt;
	uint64_t ill_capabilities;	/* Enabled capabilities, ILL_CAPAB_* */
	ill_hcksum_capab_t *ill_hcksum_capab; /* H/W cksumming capabilities */
	ill_zerocopy_capab_t *ill_zerocopy_capab; /* Zero-copy capabilities */
	ill_dld_capab_t *ill_dld_capab; /* DLD capabilities */
	ill_lso_capab_t	*ill_lso_capab;	/* Large Segment Offload capabilities */
	mblk_t	*ill_capab_reset_mp;	/* Preallocated mblk for capab reset */

	uint8_t	ill_max_hops;	/* Maximum hops for any logical interface */
	uint_t	ill_user_mtu;	/* User-specified MTU via SIOCSLIFLNKINFO */
	uint32_t ill_reachable_time;	/* Value for ND algorithm in msec */
	uint32_t ill_reachable_retrans_time; /* Value for ND algorithm msec */
	uint_t	ill_max_buf;		/* Max # of req to buffer for ND */
	in6_addr_t	ill_token;	/* IPv6 interface id */
	in6_addr_t	ill_dest_token;	/* Destination IPv6 interface id */
	uint_t		ill_token_length;
	uint32_t	ill_xmit_count;		/* ndp max multicast xmits */
	mib2_ipIfStatsEntry_t	*ill_ip_mib;	/* ver indep. interface mib */
	mib2_ipv6IfIcmpEntry_t	*ill_icmp6_mib;	/* Per interface mib */

	phyint_t		*ill_phyint;
	uint64_t		ill_flags;

	kmutex_t	ill_lock;	/* Please see table below */
	/*
	 * The ill_nd_lla* fields handle the link layer address option
	 * from neighbor discovery. This is used for external IPv6
	 * address resolution.
	 */
	mblk_t		*ill_nd_lla_mp;	/* mblk which holds ill_nd_lla */
	uint8_t		*ill_nd_lla;	/* Link Layer Address */
	uint_t		ill_nd_lla_len;	/* Link Layer Address length */
	/*
	 * We have 4 phys_addr_req's sent down. This field keeps track
	 * of which one is pending.
	 */
	t_uscalar_t	ill_phys_addr_pend; /* which dl_phys_addr_req pending */
	/*
	 * Used to save errors that occur during plumbing
	 */
	uint_t		ill_ifname_pending_err;
	avl_node_t	ill_avl_byppa; /* avl node based on ppa */
	list_t		ill_nce; /* pointer to nce_s list */
	uint_t		ill_refcnt;	/* active refcnt by threads */
	uint_t		ill_ire_cnt;	/* ires associated with this ill */
	kcondvar_t	ill_cv;
	uint_t		ill_ncec_cnt;	/* ncecs associated with this ill */
	uint_t		ill_nce_cnt;	/* nces associated with this ill */
	uint_t		ill_waiters;	/* threads waiting in ipsq_enter */
	/*
	 * Contains the upper read queue pointer of the module immediately
	 * beneath IP.  This field allows IP to validate sub-capability
	 * acknowledgments coming up from downstream.
	 */
	queue_t		*ill_lmod_rq;	/* read queue pointer of module below */
	uint_t		ill_lmod_cnt;	/* number of modules beneath IP */
	ip_m_t		*ill_media;	/* media specific params/functions */
	t_uscalar_t	ill_dlpi_pending; /* Last DLPI primitive issued */
	uint_t		ill_usesrc_ifindex; /* use src addr from this ILL */
	struct ill_s	*ill_usesrc_grp_next; /* Next ILL in the usesrc group */
	boolean_t	ill_trace_disable;	/* True when alloc fails */
	zoneid_t	ill_zoneid;
	ip_stack_t	*ill_ipst;	/* Corresponds to a netstack_hold */
	uint32_t	ill_dhcpinit;	/* IP_DHCPINIT_IFs for ill */
	void		*ill_flownotify_mh; /* Tx flow ctl, mac cb handle */
	uint_t		ill_ilm_cnt;    /* ilms referencing this ill */
	uint_t		ill_ipallmulti_cnt; /* ip_join_allmulti() calls */
	ilm_t		*ill_ipallmulti_ilm;

	mblk_t		*ill_saved_ire_mp; /* Allocated for each extra IRE */
					/* with ire_ill set so they can */
					/* survive the ill going down and up. */
	kmutex_t	ill_saved_ire_lock; /* Protects ill_saved_ire_mp, cnt */
	uint_t		ill_saved_ire_cnt;	/* # entries */
	struct arl_ill_common_s    *ill_common;
	ire_t		*ill_ire_multicast; /* IRE_MULTICAST for ill */
	clock_t		ill_defend_start;   /* start of 1 hour period */
	uint_t		ill_defend_count;   /* # of announce/defends per ill */
	/*
	 * IPMP fields.
	 */
	ipmp_illgrp_t	*ill_grp;	/* IPMP group information */
	list_node_t	ill_actnode; 	/* next active ill in group */
	list_node_t	ill_grpnode;	/* next ill in group */
	ipif_t		*ill_src_ipif;	/* source address selection rotor */
	ipif_t		*ill_move_ipif;	/* ipif awaiting move to new ill */
	boolean_t	ill_nom_cast;	/* nominated for mcast/bcast */
	uint_t		ill_bound_cnt;	/* # of data addresses bound to ill */
	ipif_t		*ill_bound_ipif; /* ipif chain bound to ill */
	timeout_id_t	ill_refresh_tid; /* ill refresh retry timeout id */

	uint32_t	ill_mrouter_cnt; /* mrouter allmulti joins */
	uint32_t	ill_allowed_ips_cnt;
	in6_addr_t	*ill_allowed_ips;

	/* list of multicast physical addresses joined on this ill */
	multiphysaddr_t *ill_mphysaddr_list;
} ill_t;

/*
 * ILL_FREE_OK() means that there are no incoming pointer references
 * to the ill.
 */
#define	ILL_FREE_OK(ill)					\
	((ill)->ill_ire_cnt == 0 && (ill)->ill_ilm_cnt == 0 &&	\
	(ill)->ill_ncec_cnt == 0 && (ill)->ill_nce_cnt == 0)

/*
 * An ipif/ill can be marked down only when the ire and ncec references
 * to that ipif/ill goes to zero. ILL_DOWN_OK() is a necessary condition
 * quiescence checks. See comments above IPIF_DOWN_OK for details
 * on why ires and nces are selectively considered for this macro.
 */
#define	ILL_DOWN_OK(ill)					\
	(ill->ill_ire_cnt == 0 && ill->ill_ncec_cnt == 0 &&	\
	ill->ill_nce_cnt == 0)

/*
 * The following table lists the protection levels of the various members
 * of the ill_t. Same notation as that used for ipif_t above is used.
 *
 *				Write			Read
 *
 * ill_ifptr			ill_g_lock + s		Write once
 * ill_rq			ipsq			Write once
 * ill_wq			ipsq			Write once
 *
 * ill_error			ipsq			None
 * ill_ipif			ill_g_lock + ipsq	ill_g_lock OR ipsq
 * ill_ipif_up_count		ill_lock + ipsq		ill_lock OR ipsq
 * ill_max_frag			ill_lock		ill_lock
 * ill_current_frag		ill_lock		ill_lock
 *
 * ill_name			ill_g_lock + ipsq	Write once
 * ill_name_length		ill_g_lock + ipsq	Write once
 * ill_ndd_name			ipsq			Write once
 * ill_net_type			ipsq			Write once
 * ill_ppa			ill_g_lock + ipsq	Write once
 * ill_sap			ipsq + down ill		Write once
 * ill_sap_length		ipsq + down ill		Write once
 * ill_phys_addr_length		ipsq + down ill		Write once
 *
 * ill_bcast_addr_length	ipsq			ipsq
 * ill_mactype			ipsq			ipsq
 * ill_frag_ptr			ipsq			ipsq
 *
 * ill_frag_timer_id		ill_lock		ill_lock
 * ill_frag_hash_tbl		ipsq			up ill
 * ill_ilm			ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_global_timer		ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_mcast_type		ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_mcast_v1_time		ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_mcast_v2_time		ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_mcast_v1_tset		ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_mcast_v2_tset		ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_mcast_rv			ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 * ill_mcast_qi			ill_mcast_lock(WRITER)	ill_mcast_lock(READER)
 *
 * ill_down_mp			ipsq			ipsq
 * ill_dlpi_deferred		ill_lock		ill_lock
 * ill_dlpi_pending		ipsq + ill_lock		ipsq or ill_lock or
 *							absence of ipsq writer.
 * ill_phys_addr_mp		ipsq + down ill		only when ill is up
 * ill_mcast_deferred		ill_lock		ill_lock
 * ill_phys_addr		ipsq + down ill		only when ill is up
 * ill_dest_addr_mp		ipsq + down ill		only when ill is up
 * ill_dest_addr		ipsq + down ill		only when ill is up
 *
 * ill_state_flags		ill_lock		ill_lock
 * exclusive bit flags		ipsq_t			ipsq_t
 * shared bit flags		ill_lock		ill_lock
 *
 * ill_muxid			ipsq			Not atomic
 *
 * ill_ipf_gen			Not atomic
 * ill_frag_count		atomics			atomics
 * ill_type			ipsq + down ill		only when ill is up
 * ill_dlpi_multicast_state	ill_lock		ill_lock
 * ill_dlpi_fastpath_state	ill_lock		ill_lock
 * ill_dlpi_capab_state		ipsq			ipsq
 * ill_max_hops			ipsq			Not atomic
 *
 * ill_mtu			ill_lock		None
 * ill_mc_mtu			ill_lock		None
 *
 * ill_user_mtu			ipsq + ill_lock		ill_lock
 * ill_reachable_time		ipsq + ill_lock		ill_lock
 * ill_reachable_retrans_time	ipsq + ill_lock		ill_lock
 * ill_max_buf			ipsq + ill_lock		ill_lock
 *
 * Next 2 fields need ill_lock because of the get ioctls. They should not
 * report partially updated results without executing in the ipsq.
 * ill_token			ipsq + ill_lock		ill_lock
 * ill_token_length		ipsq + ill_lock		ill_lock
 * ill_dest_token		ipsq + down ill		only when ill is up
 * ill_xmit_count		ipsq + down ill		write once
 * ill_ip6_mib			ipsq + down ill		only when ill is up
 * ill_icmp6_mib		ipsq + down ill		only when ill is up
 *
 * ill_phyint			ipsq, ill_g_lock, ill_lock	Any of them
 * ill_flags			ill_lock		ill_lock
 * ill_nd_lla_mp		ipsq + down ill		only when ill is up
 * ill_nd_lla			ipsq + down ill		only when ill is up
 * ill_nd_lla_len		ipsq + down ill		only when ill is up
 * ill_phys_addr_pend		ipsq + down ill		only when ill is up
 * ill_ifname_pending_err	ipsq			ipsq
 * ill_avl_byppa		ipsq, ill_g_lock	write once
 *
 * ill_fastpath_list		ill_lock		ill_lock
 * ill_refcnt			ill_lock		ill_lock
 * ill_ire_cnt			ill_lock		ill_lock
 * ill_cv			ill_lock		ill_lock
 * ill_ncec_cnt			ill_lock		ill_lock
 * ill_nce_cnt			ill_lock		ill_lock
 * ill_ilm_cnt			ill_lock		ill_lock
 * ill_src_ipif			ill_g_lock		ill_g_lock
 * ill_trace			ill_lock		ill_lock
 * ill_usesrc_grp_next		ill_g_usesrc_lock	ill_g_usesrc_lock
 * ill_dhcpinit			atomics			atomics
 * ill_flownotify_mh		write once		write once
 * ill_capab_pending_cnt	ipsq			ipsq
 * ill_ipallmulti_cnt		ill_lock		ill_lock
 * ill_ipallmulti_ilm		ill_lock		ill_lock
 * ill_saved_ire_mp		ill_saved_ire_lock	ill_saved_ire_lock
 * ill_saved_ire_cnt		ill_saved_ire_lock	ill_saved_ire_lock
 * ill_arl			???			???
 * ill_ire_multicast		ipsq + quiescent	none
 * ill_bound_ipif		ipsq			ipsq
 * ill_actnode			ipsq + ipmp_lock	ipsq OR ipmp_lock
 * ill_grpnode			ipsq + ill_g_lock	ipsq OR ill_g_lock
 * ill_src_ipif			ill_g_lock		ill_g_lock
 * ill_move_ipif		ipsq			ipsq
 * ill_nom_cast			ipsq			ipsq OR advisory
 * ill_refresh_tid		ill_lock		ill_lock
 * ill_grp (for IPMP ill)	write once		write once
 * ill_grp (for underlying ill)	ipsq + ill_g_lock	ipsq OR ill_g_lock
 * ill_grp_pending		ill_mcast_serializer	ill_mcast_serializer
 * ill_mrouter_cnt		atomics			atomics
 * ill_mphysaddr_list	ill_lock		ill_lock
 *
 * NOTE: It's OK to make heuristic decisions on an underlying interface
 *	 by using IS_UNDER_IPMP() or comparing ill_grp's raw pointer value.
 */

/*
 * For ioctl restart mechanism see ip_reprocess_ioctl()
 */
struct ip_ioctl_cmd_s;

typedef	int (*ifunc_t)(ipif_t *, struct sockaddr_in *, queue_t *, mblk_t *,
    struct ip_ioctl_cmd_s *, void *);

typedef struct ip_ioctl_cmd_s {
	int	ipi_cmd;
	size_t	ipi_copyin_size;
	uint_t	ipi_flags;
	uint_t	ipi_cmd_type;
	ifunc_t	ipi_func;
	ifunc_t	ipi_func_restart;
} ip_ioctl_cmd_t;

/*
 * ipi_cmd_type:
 *
 * IF_CMD		1	old style ifreq cmd
 * LIF_CMD		2	new style lifreq cmd
 * ARP_CMD		3	arpreq cmd
 * XARP_CMD		4	xarpreq cmd
 * MSFILT_CMD		5	multicast source filter cmd
 * MISC_CMD		6	misc cmd (not a more specific one above)
 */

enum { IF_CMD = 1, LIF_CMD, ARP_CMD, XARP_CMD, MSFILT_CMD, MISC_CMD };

#define	IPI_DONTCARE	0	/* For ioctl encoded values that don't matter */

/* Flag values in ipi_flags */
#define	IPI_PRIV	0x1	/* Root only command */
#define	IPI_MODOK	0x2	/* Permitted on mod instance of IP */
#define	IPI_WR		0x4	/* Need to grab writer access */
#define	IPI_GET_CMD	0x8	/* branch to mi_copyout on success */
/*	unused		0x10	*/
#define	IPI_NULL_BCONT	0x20	/* ioctl has not data and hence no b_cont */

extern ip_ioctl_cmd_t	ip_ndx_ioctl_table[];
extern ip_ioctl_cmd_t	ip_misc_ioctl_table[];
extern int ip_ndx_ioctl_count;
extern int ip_misc_ioctl_count;

/* Passed down by ARP to IP during I_PLINK/I_PUNLINK */
typedef struct ipmx_s {
	char	ipmx_name[LIFNAMSIZ];		/* if name */
	uint_t
		ipmx_arpdev_stream : 1,		/* This is the arp stream */
		ipmx_notused : 31;
} ipmx_t;

/*
 * State for detecting if a driver supports certain features.
 * Support for DL_ENABMULTI_REQ uses ill_dlpi_multicast_state.
 * Support for DLPI M_DATA fastpath uses ill_dlpi_fastpath_state.
 */
#define	IDS_UNKNOWN	0	/* No DLPI request sent */
#define	IDS_INPROGRESS	1	/* DLPI request sent */
#define	IDS_OK		2	/* DLPI request completed successfully */
#define	IDS_FAILED	3	/* DLPI request failed */

/* Support for DL_CAPABILITY_REQ uses ill_dlpi_capab_state. */
enum {
	IDCS_UNKNOWN,
	IDCS_PROBE_SENT,
	IDCS_OK,
	IDCS_RESET_SENT,
	IDCS_RENEG,
	IDCS_FAILED
};

/* Extended NDP Management Structure */
typedef struct ipndp_s {
	ndgetf_t	ip_ndp_getf;
	ndsetf_t	ip_ndp_setf;
	caddr_t		ip_ndp_data;
	char		*ip_ndp_name;
} ipndp_t;

/* IXA Notification types */
typedef enum {
	IXAN_LSO,	/* LSO capability change */
	IXAN_PMTU,	/* PMTU change */
	IXAN_ZCOPY	/* ZEROCOPY capability change */
} ixa_notify_type_t;

typedef uint_t ixa_notify_arg_t;

typedef	void	(*ixa_notify_t)(void *, ip_xmit_attr_t *ixa, ixa_notify_type_t,
    ixa_notify_arg_t);

/*
 * Attribute flags that are common to the transmit and receive attributes
 */
#define	IAF_IS_IPV4		0x80000000	/* ipsec_*_v4 */
#define	IAF_TRUSTED_ICMP	0x40000000	/* ipsec_*_icmp_loopback */
#define	IAF_NO_LOOP_ZONEID_SET	0x20000000	/* Zone that shouldn't have */
						/* a copy */
#define	IAF_LOOPBACK_COPY	0x10000000	/* For multi and broadcast */

#define	IAF_MASK		0xf0000000	/* Flags that are common */

/*
 * Transmit side attributes used between the transport protocols and IP as
 * well as inside IP. It is also used to cache information in the conn_t i.e.
 * replaces conn_ire and the IPsec caching in the conn_t.
 */
struct ip_xmit_attr_s {
	iaflags_t	ixa_flags;	/* IXAF_*. See below */

	uint32_t	ixa_free_flags;	/* IXA_FREE_*. See below */
	uint32_t	ixa_refcnt;	/* Using atomics */

	/*
	 * Always initialized independently of ixa_flags settings.
	 * Used by ip_xmit so we keep them up front for cache locality.
	 */
	uint32_t	ixa_xmit_hint;	/* For ECMP and GLD TX ring fanout */
	uint_t		ixa_pktlen;	/* Always set. For frag and stats */
	zoneid_t	ixa_zoneid;	/* Assumed always set */

	/* Always set for conn_ip_output(); might be stale */
	/*
	 * Since TCP keeps the conn_t around past the process going away
	 * we need to use the "notr" (e.g, ire_refhold_notr) for ixa_ire,
	 * ixa_nce, and ixa_dce.
	 */
	ire_t		*ixa_ire;	/* Forwarding table entry */
	uint_t		ixa_ire_generation;
	nce_t		*ixa_nce;	/* Neighbor cache entry */
	dce_t		*ixa_dce;	/* Destination cache entry */
	uint_t		ixa_dce_generation;
	uint_t		ixa_src_generation;	/* If IXAF_VERIFY_SOURCE */

	uint32_t	ixa_src_preferences;	/* prefs for src addr select */
	uint32_t	ixa_pmtu;		/* IXAF_VERIFY_PMTU */

	/* Set by ULP if IXAF_VERIFY_PMTU; otherwise set by IP */
	uint32_t	ixa_fragsize;

	int8_t		ixa_use_min_mtu;	/* IXAF_USE_MIN_MTU values */

	pfirepostfrag_t	ixa_postfragfn;		/* Set internally in IP */

	in6_addr_t	ixa_nexthop_v6;		/* IXAF_NEXTHOP_SET */
#define	ixa_nexthop_v4	V4_PART_OF_V6(ixa_nexthop_v6)

	zoneid_t	ixa_no_loop_zoneid;	/* IXAF_NO_LOOP_ZONEID_SET */

	uint_t		ixa_scopeid;		/* For IPv6 link-locals */

	uint_t		ixa_broadcast_ttl;	/* IXAF_BROACAST_TTL_SET */

	uint_t		ixa_multicast_ttl;	/* Assumed set for multicast */
	uint_t		ixa_multicast_ifindex;	/* Assumed set for multicast */
	ipaddr_t	ixa_multicast_ifaddr;	/* Assumed set for multicast */

	int		ixa_raw_cksum_offset;	/* If IXAF_SET_RAW_CKSUM */

	uint32_t	ixa_ident;		/* For IPv6 fragment header */

	uint64_t	ixa_conn_id;		/* Used by DTrace */
	/*
	 * Cached LSO information.
	 */
	ill_lso_capab_t	ixa_lso_capab;		/* Valid when IXAF_LSO_CAPAB */

	uint64_t	ixa_ipsec_policy_gen;	/* Generation from iph_gen */
	/*
	 * The following IPsec fields are only initialized when
	 * IXAF_IPSEC_SECURE is set. Otherwise they contain garbage.
	 */
	ipsec_latch_t	*ixa_ipsec_latch;	/* Just the ids */
	struct ipsa_s 	*ixa_ipsec_ah_sa;	/* Hard reference SA for AH */
	struct ipsa_s 	*ixa_ipsec_esp_sa;	/* Hard reference SA for ESP */
	struct ipsec_policy_s 	*ixa_ipsec_policy; /* why are we here? */
	struct ipsec_action_s	*ixa_ipsec_action; /* For reflected packets */
	ipsa_ref_t	ixa_ipsec_ref[2];	/* Soft reference to SA */
						/* 0: ESP, 1: AH */

	/*
	 * The selectors here are potentially different than the SPD rule's
	 * selectors, and we need to have both available for IKEv2.
	 *
	 * NOTE: "Source" and "Dest" are w.r.t. outbound datagrams.  Ports can
	 *	 be zero, and the protocol number is needed to make the ports
	 *	 significant.
	 */
	uint16_t ixa_ipsec_src_port;	/* Source port number of d-gram. */
	uint16_t ixa_ipsec_dst_port;	/* Destination port number of d-gram. */
	uint8_t  ixa_ipsec_icmp_type;	/* ICMP type of d-gram */
	uint8_t  ixa_ipsec_icmp_code;	/* ICMP code of d-gram */

	sa_family_t ixa_ipsec_inaf;	/* Inner address family */
#define	IXA_MAX_ADDRLEN 4	/* Max addr len. (in 32-bit words) */
	uint32_t ixa_ipsec_insrc[IXA_MAX_ADDRLEN];	/* Inner src address */
	uint32_t ixa_ipsec_indst[IXA_MAX_ADDRLEN];	/* Inner dest address */
	uint8_t  ixa_ipsec_insrcpfx;	/* Inner source prefix */
	uint8_t  ixa_ipsec_indstpfx;	/* Inner destination prefix */

	uint8_t ixa_ipsec_proto;	/* IP protocol number for d-gram. */

	/* Always initialized independently of ixa_flags settings */
	uint_t		ixa_ifindex;	/* Assumed always set */
	uint16_t	ixa_ip_hdr_length; /* Points to ULP header */
	uint8_t		ixa_protocol;	/* Protocol number for ULP cksum */
	ts_label_t	*ixa_tsl;	/* Always set. NULL if not TX */
	ip_stack_t	*ixa_ipst;	/* Always set */
	uint32_t	ixa_extra_ident; /* Set if LSO */
	cred_t		*ixa_cred;	/* For getpeerucred */
	pid_t		ixa_cpid;	/* For getpeerucred */

#ifdef DEBUG
	kthread_t	*ixa_curthread;	/* For serialization assert */
#endif
	squeue_t	*ixa_sqp;	/* Set from conn_sqp as a hint */
	uintptr_t	ixa_cookie;	/* cookie to use for tx flow control */

	/*
	 * Must be set by ULP if any of IXAF_VERIFY_LSO, IXAF_VERIFY_PMTU,
	 * or IXAF_VERIFY_ZCOPY is set.
	 */
	ixa_notify_t	ixa_notify;	/* Registered upcall notify function */
	void		*ixa_notify_cookie; /* ULP cookie for ixa_notify */

	uint_t		ixa_tcpcleanup;	/* Used by conn_ixa_cleanup */
};

/*
 * Flags to indicate which transmit attributes are set.
 * Split into "xxx_SET" ones which indicate that the "xxx" field it set, and
 * single flags.
 */
#define	IXAF_REACH_CONF		0x00000001	/* Reachability confirmation */
#define	IXAF_BROADCAST_TTL_SET	0x00000002	/* ixa_broadcast_ttl valid */
#define	IXAF_SET_SOURCE		0x00000004	/* Replace if broadcast */
#define	IXAF_USE_MIN_MTU	0x00000008	/* IPV6_USE_MIN_MTU */

#define	IXAF_DONTFRAG		0x00000010	/* IP*_DONTFRAG */
#define	IXAF_VERIFY_PMTU	0x00000020	/* ixa_pmtu/ixa_fragsize set */
#define	IXAF_PMTU_DISCOVERY	0x00000040	/* Create/use PMTU state */
#define	IXAF_MULTICAST_LOOP	0x00000080	/* IP_MULTICAST_LOOP */

#define	IXAF_IPSEC_SECURE	0x00000100	/* Need IPsec processing */
#define	IXAF_UCRED_TSL		0x00000200	/* ixa_tsl from SCM_UCRED */
#define	IXAF_DONTROUTE		0x00000400	/* SO_DONTROUTE */
#define	IXAF_NO_IPSEC		0x00000800	/* Ignore policy */

#define	IXAF_PMTU_TOO_SMALL	0x00001000	/* PMTU too small */
#define	IXAF_SET_ULP_CKSUM	0x00002000	/* Calculate ULP checksum */
#define	IXAF_VERIFY_SOURCE	0x00004000	/* Check that source is ok */
#define	IXAF_NEXTHOP_SET	0x00008000	/* ixa_nexthop set */

#define	IXAF_PMTU_IPV4_DF	0x00010000	/* Set IPv4 DF */
#define	IXAF_NO_DEV_FLOW_CTL	0x00020000	/* Protocol needs no flow ctl */
#define	IXAF_NO_TTL_CHANGE	0x00040000	/* Internal to IP */
#define	IXAF_IPV6_ADD_FRAGHDR	0x00080000	/* Add fragment header */

#define	IXAF_IPSEC_TUNNEL	0x00100000	/* Tunnel mode */
#define	IXAF_NO_PFHOOK		0x00200000	/* Skip xmit pfhook */
#define	IXAF_NO_TRACE		0x00400000	/* When back from ARP/ND */
#define	IXAF_SCOPEID_SET	0x00800000	/* ixa_scopeid set */

#define	IXAF_MULTIRT_MULTICAST	0x01000000	/* MULTIRT for multicast */
#define	IXAF_NO_HW_CKSUM	0x02000000	/* Force software cksum */
#define	IXAF_SET_RAW_CKSUM	0x04000000	/* Use ixa_raw_cksum_offset */
#define	IXAF_IPSEC_GLOBAL_POLICY 0x08000000	/* Policy came from global */

/* Note the following uses bits 0x10000000 through 0x80000000 */
#define	IXAF_IS_IPV4		IAF_IS_IPV4
#define	IXAF_TRUSTED_ICMP	IAF_TRUSTED_ICMP
#define	IXAF_NO_LOOP_ZONEID_SET	IAF_NO_LOOP_ZONEID_SET
#define	IXAF_LOOPBACK_COPY	IAF_LOOPBACK_COPY

/* Note: use the upper 32 bits */
#define	IXAF_VERIFY_LSO		0x100000000	/* Check LSO capability */
#define	IXAF_LSO_CAPAB		0x200000000	/* Capable of LSO */
#define	IXAF_VERIFY_ZCOPY	0x400000000	/* Check Zero Copy capability */
#define	IXAF_ZCOPY_CAPAB	0x800000000	/* Capable of ZEROCOPY */

/*
 * The normal flags for sending packets e.g., icmp errors
 */
#define	IXAF_BASIC_SIMPLE_V4	\
	(IXAF_SET_ULP_CKSUM | IXAF_IS_IPV4 | IXAF_VERIFY_SOURCE)
#define	IXAF_BASIC_SIMPLE_V6	(IXAF_SET_ULP_CKSUM | IXAF_VERIFY_SOURCE)

/*
 * Normally these fields do not have a hold. But in some cases they do, for
 * instance when we've gone through ip_*_attr_to/from_mblk.
 * We use ixa_free_flags to indicate that they have a hold and need to be
 * released on cleanup.
 */
#define	IXA_FREE_CRED		0x00000001	/* ixa_cred needs to be rele */
#define	IXA_FREE_TSL		0x00000002	/* ixa_tsl needs to be rele */

/*
 * Trivial state machine used to synchronize IXA cleanup for TCP connections.
 * See conn_ixa_cleanup().
 */
#define	IXATC_IDLE		0x00000000
#define	IXATC_INPROGRESS	0x00000001
#define	IXATC_COMPLETE		0x00000002

/*
 * Simplistic way to set the ixa_xmit_hint for locally generated traffic
 * and forwarded traffic. The shift amount are based on the size of the
 * structs to discard the low order bits which don't have much if any variation
 * (coloring in kmem_cache_alloc might provide some variation).
 *
 * Basing the locally generated hint on the address of the conn_t means that
 * the packets from the same socket/connection do not get reordered.
 * Basing the hint for forwarded traffic on the ill_ring_t means that
 * packets from the same NIC+ring are likely to use the same outbound ring
 * hence we get low contention on the ring in the transmitting driver.
 */
#define	CONN_TO_XMIT_HINT(connp)	((uint32_t)(((uintptr_t)connp) >> 11))
#define	ILL_RING_TO_XMIT_HINT(ring)	((uint32_t)(((uintptr_t)ring) >> 7))

/*
 * IP set Destination Flags used by function ip_set_destination,
 * ip_attr_connect, and conn_connect.
 */
#define	IPDF_ALLOW_MCBC		0x1	/* Allow multi/broadcast */
#define	IPDF_VERIFY_DST		0x2	/* Verify destination addr */
#define	IPDF_SELECT_SRC		0x4	/* Select source address */
#define	IPDF_LSO		0x8	/* Try LSO */
#define	IPDF_IPSEC		0x10	/* Set IPsec policy */
#define	IPDF_ZONE_IS_GLOBAL	0x20	/* From conn_zone_is_global */
#define	IPDF_ZCOPY		0x40	/* Try ZEROCOPY */
#define	IPDF_UNIQUE_DCE		0x80	/* Get a per-destination DCE */

/*
 * Receive side attributes used between the transport protocols and IP as
 * well as inside IP.
 */
struct ip_recv_attr_s {
	iaflags_t	ira_flags;	/* See below */

	uint32_t	ira_free_flags;	/* IRA_FREE_*. See below */

	/*
	 * This is a hint for TCP SYN packets.
	 * Always initialized independently of ira_flags settings
	 */
	squeue_t	*ira_sqp;
	ill_rx_ring_t	*ira_ring;	/* Internal to IP */

	/* For ip_accept_tcp when IRAF_TARGET_SQP is set */
	squeue_t	*ira_target_sqp;
	mblk_t		*ira_target_sqp_mp;

	/* Always initialized independently of ira_flags settings */
	uint32_t	ira_xmit_hint;	/* For ECMP and GLD TX ring fanout */
	zoneid_t	ira_zoneid;	/* ALL_ZONES unless local delivery */
	uint_t		ira_pktlen;	/* Always set. For frag and stats */
	uint16_t	ira_ip_hdr_length; /* Points to ULP header */
	uint8_t		ira_protocol;	/* Protocol number for ULP cksum */
	uint_t		ira_rifindex;	/* Received ifindex */
	uint_t		ira_ruifindex;	/* Received upper ifindex */
	ts_label_t	*ira_tsl;	/* Always set. NULL if not TX */
	/*
	 * ira_rill and ira_ill is set inside IP, but not when conn_recv is
	 * called; ULPs should use ira_ruifindex instead.
	 */
	ill_t		*ira_rill;	/* ill where packet came */
	ill_t		*ira_ill;	/* ill where IP address hosted */
	cred_t		*ira_cred;	/* For getpeerucred */
	pid_t		ira_cpid;	/* For getpeerucred */

	/* Used when IRAF_VERIFIED_SRC is set; this source was ok */
	ipaddr_t	ira_verified_src;

	/*
	 * The following IPsec fields are only initialized when
	 * IRAF_IPSEC_SECURE is set. Otherwise they contain garbage.
	 */
	struct ipsec_action_s *ira_ipsec_action; /* how we made it in.. */
	struct ipsa_s 	*ira_ipsec_ah_sa;	/* SA for AH */
	struct ipsa_s 	*ira_ipsec_esp_sa;	/* SA for ESP */

	ipaddr_t	ira_mroute_tunnel;	/* IRAF_MROUTE_TUNNEL_SET */

	zoneid_t	ira_no_loop_zoneid;	/* IRAF_NO_LOOP_ZONEID_SET */

	uint32_t	ira_esp_udp_ports;	/* IRAF_ESP_UDP_PORTS */

	/*
	 * For IP_RECVSLLA and ip_ndp_conflict/find_solicitation.
	 * Same size as max for sockaddr_dl
	 */
#define	IRA_L2SRC_SIZE	244
	uint8_t		ira_l2src[IRA_L2SRC_SIZE];	/* If IRAF_L2SRC_SET */

	/*
	 * Local handle that we use to do lazy setting of ira_l2src.
	 * We defer setting l2src until needed but we do before any
	 * ip_input pullupmsg or copymsg.
	 */
	struct mac_header_info_s *ira_mhip;	/* Could be NULL */
};

/*
 * Flags to indicate which receive attributes are set.
 */
#define	IRAF_SYSTEM_LABELED	0x00000001	/* is_system_labeled() */
#define	IRAF_IPV4_OPTIONS	0x00000002	/* Performance */
#define	IRAF_MULTICAST		0x00000004	/* Was multicast at L3 */
#define	IRAF_BROADCAST		0x00000008	/* Was broadcast at L3 */
#define	IRAF_MULTIBROADCAST	(IRAF_MULTICAST|IRAF_BROADCAST)

#define	IRAF_LOOPBACK		0x00000010	/* Looped back by IP */
#define	IRAF_VERIFY_IP_CKSUM	0x00000020	/* Need to verify IP */
#define	IRAF_VERIFY_ULP_CKSUM	0x00000040	/* Need to verify TCP,UDP,etc */
#define	IRAF_SCTP_CSUM_ERR	0x00000080	/* sctp pkt has failed chksum */

#define	IRAF_IPSEC_SECURE	0x00000100	/* Passed AH and/or ESP */
#define	IRAF_DHCP_UNICAST	0x00000200
#define	IRAF_IPSEC_DECAPS	0x00000400	/* Was packet decapsulated */
					/* from a matching inner packet? */
#define	IRAF_TARGET_SQP		0x00000800	/* ira_target_sqp is set */
#define	IRAF_VERIFIED_SRC	0x00001000	/* ira_verified_src set */
#define	IRAF_RSVP		0x00002000	/* RSVP packet for rsvpd */
#define	IRAF_MROUTE_TUNNEL_SET	0x00004000	/* From ip_mroute_decap */
#define	IRAF_PIM_REGISTER	0x00008000	/* From register_mforward */

#define	IRAF_TX_MAC_EXEMPTABLE	0x00010000	/* Allow MAC_EXEMPT readdown */
#define	IRAF_TX_SHARED_ADDR	0x00020000	/* Arrived on ALL_ZONES addr */
#define	IRAF_ESP_UDP_PORTS	0x00040000	/* NAT-traversal packet */
#define	IRAF_NO_HW_CKSUM	0x00080000	/* Force software cksum */

#define	IRAF_ICMP_ERROR		0x00100000	/* Send to conn_recvicmp */
#define	IRAF_ROUTER_ALERT	0x00200000	/* IPv6 router alert */
#define	IRAF_L2SRC_SET		0x00400000	/* ira_l2src has been set */
#define	IRAF_L2SRC_LOOPBACK	0x00800000	/* Came from us */

#define	IRAF_L2DST_MULTICAST	0x01000000	/* Multicast at L2 */
#define	IRAF_L2DST_BROADCAST	0x02000000	/* Broadcast at L2 */
/* Unused 0x04000000 */
/* Unused 0x08000000 */

/* Below starts with 0x10000000 */
#define	IRAF_IS_IPV4		IAF_IS_IPV4
#define	IRAF_TRUSTED_ICMP	IAF_TRUSTED_ICMP
#define	IRAF_NO_LOOP_ZONEID_SET	IAF_NO_LOOP_ZONEID_SET
#define	IRAF_LOOPBACK_COPY	IAF_LOOPBACK_COPY

/*
 * Normally these fields do not have a hold. But in some cases they do, for
 * instance when we've gone through ip_*_attr_to/from_mblk.
 * We use ira_free_flags to indicate that they have a hold and need to be
 * released on cleanup.
 */
#define	IRA_FREE_CRED		0x00000001	/* ira_cred needs to be rele */
#define	IRA_FREE_TSL		0x00000002	/* ira_tsl needs to be rele */

/*
 * Optional destination cache entry for path MTU information,
 * and ULP metrics.
 */
struct dce_s {
	uint_t		dce_generation;	/* Changed since cached? */
	uint_t		dce_flags;	/* See below */
	uint_t		dce_ipversion;	/* IPv4/IPv6 version */
	uint32_t	dce_pmtu;	/* Path MTU if DCEF_PMTU */
	uint32_t	dce_ident;	/* Per destination IP ident. */
	iulp_t		dce_uinfo;	/* Metrics if DCEF_UINFO */

	struct dce_s	*dce_next;
	struct dce_s	**dce_ptpn;
	struct dcb_s	*dce_bucket;

	union {
		in6_addr_t	dceu_v6addr;
		ipaddr_t	dceu_v4addr;
	} dce_u;
#define	dce_v4addr	dce_u.dceu_v4addr
#define	dce_v6addr	dce_u.dceu_v6addr
	/* Note that for IPv6+IPMP we use the ifindex for the upper interface */
	uint_t		dce_ifindex;	/* For IPv6 link-locals */

	kmutex_t	dce_lock;
	uint_t		dce_refcnt;
	uint64_t	dce_last_change_time;	/* Path MTU. In seconds */

	ip_stack_t	*dce_ipst;	/* Does not have a netstack_hold */
};

/*
 * Values for dce_generation.
 *
 * If a DCE has DCE_GENERATION_CONDEMNED, the last dce_refrele should delete
 * it.
 *
 * DCE_GENERATION_VERIFY is never stored in dce_generation but it is
 * stored in places that cache DCE (such as ixa_dce_generation).
 * It is used as a signal that the cache is stale and needs to be reverified.
 */
#define	DCE_GENERATION_CONDEMNED	0
#define	DCE_GENERATION_VERIFY		1
#define	DCE_GENERATION_INITIAL		2
#define	DCE_IS_CONDEMNED(dce) \
	((dce)->dce_generation == DCE_GENERATION_CONDEMNED)


/*
 * Values for ips_src_generation.
 *
 * SRC_GENERATION_VERIFY is never stored in ips_src_generation but it is
 * stored in places that cache IREs (ixa_src_generation). It is used as a
 * signal that the cache is stale and needs to be reverified.
 */
#define	SRC_GENERATION_VERIFY		0
#define	SRC_GENERATION_INITIAL		1

/*
 * The kernel stores security attributes of all gateways in a database made
 * up of one or more tsol_gcdb_t elements.  Each tsol_gcdb_t contains the
 * security-related credentials of the gateway.  More than one gateways may
 * share entries in the database.
 *
 * The tsol_gc_t structure represents the gateway to credential association,
 * and refers to an entry in the database.  One or more tsol_gc_t entities are
 * grouped together to form one or more tsol_gcgrp_t, each representing the
 * list of security attributes specific to the gateway.  A gateway may be
 * associated with at most one credentials group.
 */
struct tsol_gcgrp_s;

extern uchar_t	ip6opt_ls;	/* TX IPv6 enabler */

/*
 * Gateway security credential record.
 */
typedef struct tsol_gcdb_s {
	uint_t		gcdb_refcnt;	/* reference count */
	struct rtsa_s	gcdb_attr;	/* security attributes */
#define	gcdb_mask	gcdb_attr.rtsa_mask
#define	gcdb_doi	gcdb_attr.rtsa_doi
#define	gcdb_slrange	gcdb_attr.rtsa_slrange
} tsol_gcdb_t;

/*
 * Gateway to credential association.
 */
typedef struct tsol_gc_s {
	uint_t		gc_refcnt;	/* reference count */
	struct tsol_gcgrp_s *gc_grp;	/* pointer to group */
	struct tsol_gc_s *gc_prev;	/* previous in list */
	struct tsol_gc_s *gc_next;	/* next in list */
	tsol_gcdb_t	*gc_db;		/* pointer to actual credentials */
} tsol_gc_t;

/*
 * Gateway credentials group address.
 */
typedef struct tsol_gcgrp_addr_s {
	int		ga_af;		/* address family */
	in6_addr_t	ga_addr;	/* IPv4 mapped or IPv6 address */
} tsol_gcgrp_addr_t;

/*
 * Gateway credentials group.
 */
typedef struct tsol_gcgrp_s {
	uint_t		gcgrp_refcnt;	/* reference count */
	krwlock_t	gcgrp_rwlock;	/* lock to protect following */
	uint_t		gcgrp_count;	/* number of credentials */
	tsol_gc_t	*gcgrp_head;	/* first credential in list */
	tsol_gc_t	*gcgrp_tail;	/* last credential in list */
	tsol_gcgrp_addr_t gcgrp_addr;	/* next-hop gateway address */
} tsol_gcgrp_t;

extern kmutex_t gcgrp_lock;

#define	GC_REFRELE(p) {				\
	ASSERT((p)->gc_grp != NULL);		\
	rw_enter(&(p)->gc_grp->gcgrp_rwlock, RW_WRITER); \
	ASSERT((p)->gc_refcnt > 0);		\
	if (--((p)->gc_refcnt) == 0)		\
		gc_inactive(p);			\
	else					\
		rw_exit(&(p)->gc_grp->gcgrp_rwlock); \
}

#define	GCGRP_REFHOLD(p) {			\
	mutex_enter(&gcgrp_lock);		\
	++((p)->gcgrp_refcnt);			\
	ASSERT((p)->gcgrp_refcnt != 0);		\
	mutex_exit(&gcgrp_lock);		\
}

#define	GCGRP_REFRELE(p) {			\
	mutex_enter(&gcgrp_lock);		\
	ASSERT((p)->gcgrp_refcnt > 0);		\
	if (--((p)->gcgrp_refcnt) == 0)		\
		gcgrp_inactive(p);		\
	ASSERT(MUTEX_HELD(&gcgrp_lock));	\
	mutex_exit(&gcgrp_lock);		\
}

/*
 * IRE gateway security attributes structure, pointed to by tsol_ire_gw_secattr
 */
struct tsol_tnrhc;

struct tsol_ire_gw_secattr_s {
	kmutex_t	igsa_lock;	/* lock to protect following */
	struct tsol_tnrhc *igsa_rhc;	/* host entry for gateway */
	tsol_gc_t	*igsa_gc;	/* for prefix IREs */
};

void irb_refrele_ftable(irb_t *);

extern struct kmem_cache *rt_entry_cache;

typedef struct ire4 {
	ipaddr_t ire4_mask;		/* Mask for matching this IRE. */
	ipaddr_t ire4_addr;		/* Address this IRE represents. */
	ipaddr_t ire4_gateway_addr;	/* Gateway including for IRE_ONLINK */
	ipaddr_t ire4_setsrc_addr;	/* RTF_SETSRC */
} ire4_t;

typedef struct ire6 {
	in6_addr_t ire6_mask;		/* Mask for matching this IRE. */
	in6_addr_t ire6_addr;		/* Address this IRE represents. */
	in6_addr_t ire6_gateway_addr;	/* Gateway including for IRE_ONLINK */
	in6_addr_t ire6_setsrc_addr;	/* RTF_SETSRC */
} ire6_t;

typedef union ire_addr {
	ire6_t	ire6_u;
	ire4_t	ire4_u;
} ire_addr_u_t;

/*
 * Internet Routing Entry
 * When we have multiple identical IREs we logically add them by manipulating
 * ire_identical_ref and ire_delete first decrements
 * that and when it reaches 1 we know it is the last IRE.
 * "identical" is defined as being the same for:
 * ire_addr, ire_netmask, ire_gateway, ire_ill, ire_zoneid, and ire_type
 * For instance, multiple IRE_BROADCASTs for the same subnet number are
 * viewed as identical, and so are the IRE_INTERFACEs when there are
 * multiple logical interfaces (on the same ill) with the same subnet prefix.
 */
struct ire_s {
	struct	ire_s	*ire_next;	/* The hash chain must be first. */
	struct	ire_s	**ire_ptpn;	/* Pointer to previous next. */
	uint32_t	ire_refcnt;	/* Number of references */
	ill_t		*ire_ill;
	uint32_t	ire_identical_ref; /* IRE_INTERFACE, IRE_BROADCAST */
	uchar_t		ire_ipversion;	/* IPv4/IPv6 version */
	ushort_t	ire_type;	/* Type of IRE */
	uint_t		ire_generation;	/* Generation including CONDEMNED */
	uint_t	ire_ib_pkt_count;	/* Inbound packets for ire_addr */
	uint_t	ire_ob_pkt_count;	/* Outbound packets to ire_addr */
	time_t	ire_create_time;	/* Time (in secs) IRE was created. */
	uint32_t	ire_flags;	/* flags related to route (RTF_*) */
	/*
	 * ire_testhidden is TRUE for INTERFACE IREs of IS_UNDER_IPMP(ill)
	 * interfaces
	 */
	boolean_t	ire_testhidden;
	pfirerecv_t	ire_recvfn;	/* Receive side handling */
	pfiresend_t	ire_sendfn;	/* Send side handling */
	pfirepostfrag_t	ire_postfragfn;	/* Bottom end of send handling */

	uint_t		ire_masklen;	/* # bits in ire_mask{,_v6} */
	ire_addr_u_t	ire_u;		/* IPv4/IPv6 address info. */

	irb_t		*ire_bucket;	/* Hash bucket when ire_ptphn is set */
	kmutex_t	ire_lock;
	clock_t		ire_last_used_time;	/* For IRE_LOCAL reception */
	tsol_ire_gw_secattr_t *ire_gw_secattr; /* gateway security attributes */
	zoneid_t	ire_zoneid;

	/*
	 * Cached information of where to send packets that match this route.
	 * The ire_dep_* information is used to determine when ire_nce_cache
	 * needs to be updated.
	 * ire_nce_cache is the fastpath for the Neighbor Cache Entry
	 * for IPv6; arp info for IPv4
	 * Since this is a cache setup and torn down independently of
	 * applications we need to use nce_ref{rele,hold}_notr for it.
	 */
	nce_t		*ire_nce_cache;

	/*
	 * Quick check whether the ire_type and ire_masklen indicates
	 * that the IRE can have ire_nce_cache set i.e., whether it is
	 * IRE_ONLINK and for a single destination.
	 */
	boolean_t	ire_nce_capable;

	/*
	 * Dependency tracking so we can safely cache IRE and NCE pointers
	 * in offlink and onlink IREs.
	 * These are locked under the ips_ire_dep_lock rwlock. Write held
	 * when modifying the linkage.
	 * ire_dep_parent (Also chain towards IRE for nexthop)
	 * ire_dep_parent_generation: ire_generation of ire_dep_parent
	 * ire_dep_children (From parent to first child)
	 * ire_dep_sib_next (linked list of siblings)
	 * ire_dep_sib_ptpn (linked list of siblings)
	 *
	 * The parent has a ire_refhold on each child, and each child has
	 * an ire_refhold on its parent.
	 * Since ire_dep_parent is a cache setup and torn down independently of
	 * applications we need to use ire_ref{rele,hold}_notr for it.
	 */
	ire_t		*ire_dep_parent;
	ire_t		*ire_dep_children;
	ire_t		*ire_dep_sib_next;
	ire_t		**ire_dep_sib_ptpn;	/* Pointer to previous next */
	uint_t		ire_dep_parent_generation;

	uint_t		ire_badcnt;	/* Number of times ND_UNREACHABLE */
	uint64_t	ire_last_badcnt;	/* In seconds */

	/* ire_defense* and ire_last_used_time are only used on IRE_LOCALs */
	uint_t		ire_defense_count;	/* number of ARP conflicts */
	uint_t		ire_defense_time;	/* last time defended (secs) */

	boolean_t	ire_trace_disable;	/* True when alloc fails */
	ip_stack_t	*ire_ipst;	/* Does not have a netstack_hold */
	iulp_t		ire_metrics;
	/*
	 * default and prefix routes that are added without explicitly
	 * specifying the interface are termed "unbound" routes, and will
	 * have ire_unbound set to true.
	 */
	boolean_t	ire_unbound;
};

/* IPv4 compatibility macros */
#define	ire_mask		ire_u.ire4_u.ire4_mask
#define	ire_addr		ire_u.ire4_u.ire4_addr
#define	ire_gateway_addr	ire_u.ire4_u.ire4_gateway_addr
#define	ire_setsrc_addr		ire_u.ire4_u.ire4_setsrc_addr

#define	ire_mask_v6		ire_u.ire6_u.ire6_mask
#define	ire_addr_v6		ire_u.ire6_u.ire6_addr
#define	ire_gateway_addr_v6	ire_u.ire6_u.ire6_gateway_addr
#define	ire_setsrc_addr_v6	ire_u.ire6_u.ire6_setsrc_addr

/*
 * Values for ire_generation.
 *
 * If an IRE is marked with IRE_IS_CONDEMNED, the last walker of
 * the bucket should delete this IRE from this bucket.
 *
 * IRE_GENERATION_VERIFY is never stored in ire_generation but it is
 * stored in places that cache IREs (such as ixa_ire_generation and
 * ire_dep_parent_generation). It is used as a signal that the cache is
 * stale and needs to be reverified.
 */
#define	IRE_GENERATION_CONDEMNED	0
#define	IRE_GENERATION_VERIFY		1
#define	IRE_GENERATION_INITIAL		2
#define	IRE_IS_CONDEMNED(ire) \
	((ire)->ire_generation == IRE_GENERATION_CONDEMNED)

/* Convenient typedefs for sockaddrs */
typedef	struct sockaddr_in	sin_t;
typedef	struct sockaddr_in6	sin6_t;

/* Name/Value Descriptor. */
typedef struct nv_s {
	uint64_t nv_value;
	char	*nv_name;
} nv_t;

#define	ILL_FRAG_HASH(s, i) \
	((ntohl(s) ^ ((i) ^ ((i) >> 8))) % ILL_FRAG_HASH_TBL_COUNT)

/*
 * The MAX number of allowed fragmented packets per hash bucket
 * calculation is based on the most common mtu size of 1500. This limit
 * will work well for other mtu sizes as well.
 */
#define	COMMON_IP_MTU 1500
#define	MAX_FRAG_MIN 10
#define	MAX_FRAG_PKTS(ipst)	\
	MAX(MAX_FRAG_MIN, (2 * (ipst->ips_ip_reass_queue_bytes / \
	    (COMMON_IP_MTU * ILL_FRAG_HASH_TBL_COUNT))))

/*
 * Maximum dups allowed per packet.
 */
extern uint_t ip_max_frag_dups;

/*
 * Per-packet information for received packets and transmitted.
 * Used by the transport protocols when converting between the packet
 * and ancillary data and socket options.
 *
 * Note: This private data structure and related IPPF_* constant
 * definitions are exposed to enable compilation of some debugging tools
 * like lsof which use struct tcp_t in <inet/tcp.h>. This is intended to be
 * a temporary hack and long term alternate interfaces should be defined
 * to support the needs of such tools and private definitions moved to
 * private headers.
 */
struct ip_pkt_s {
	uint_t		ipp_fields;		/* Which fields are valid */
	in6_addr_t	ipp_addr;		/* pktinfo src/dst addr */
#define	ipp_addr_v4	V4_PART_OF_V6(ipp_addr)
	uint_t		ipp_unicast_hops;	/* IPV6_UNICAST_HOPS, IP_TTL */
	uint_t		ipp_hoplimit;		/* IPV6_HOPLIMIT */
	uint_t		ipp_hopoptslen;
	uint_t		ipp_rthdrdstoptslen;
	uint_t		ipp_rthdrlen;
	uint_t		ipp_dstoptslen;
	uint_t		ipp_fraghdrlen;
	ip6_hbh_t	*ipp_hopopts;
	ip6_dest_t	*ipp_rthdrdstopts;
	ip6_rthdr_t	*ipp_rthdr;
	ip6_dest_t	*ipp_dstopts;
	ip6_frag_t	*ipp_fraghdr;
	uint8_t		ipp_tclass;		/* IPV6_TCLASS */
	uint8_t		ipp_type_of_service;	/* IP_TOS */
	uint_t		ipp_ipv4_options_len;	/* Len of IPv4 options */
	uint8_t		*ipp_ipv4_options;	/* Ptr to IPv4 options */
	uint_t		ipp_label_len_v4;	/* Len of TX label for IPv4 */
	uint8_t		*ipp_label_v4;		/* TX label for IPv4 */
	uint_t		ipp_label_len_v6;	/* Len of TX label for IPv6 */
	uint8_t		*ipp_label_v6;		/* TX label for IPv6 */
};
typedef struct ip_pkt_s ip_pkt_t;

extern void ip_pkt_free(ip_pkt_t *);	/* free storage inside ip_pkt_t */
extern ipaddr_t ip_pkt_source_route_v4(const ip_pkt_t *);
extern in6_addr_t *ip_pkt_source_route_v6(const ip_pkt_t *);
extern int ip_pkt_copy(ip_pkt_t *, ip_pkt_t *, int);
extern void ip_pkt_source_route_reverse_v4(ip_pkt_t *);

/* ipp_fields values */
#define	IPPF_ADDR		0x0001	/* Part of in6_pktinfo: src/dst addr */
#define	IPPF_HOPLIMIT		0x0002	/* Overrides unicast and multicast */
#define	IPPF_TCLASS		0x0004	/* Overrides class in sin6_flowinfo */

#define	IPPF_HOPOPTS		0x0010	/* ipp_hopopts set */
#define	IPPF_RTHDR		0x0020	/* ipp_rthdr set */
#define	IPPF_RTHDRDSTOPTS	0x0040	/* ipp_rthdrdstopts set */
#define	IPPF_DSTOPTS		0x0080	/* ipp_dstopts set */

#define	IPPF_IPV4_OPTIONS	0x0100	/* ipp_ipv4_options set */
#define	IPPF_LABEL_V4		0x0200	/* ipp_label_v4 set */
#define	IPPF_LABEL_V6		0x0400	/* ipp_label_v6 set */

#define	IPPF_FRAGHDR		0x0800	/* Used for IPsec receive side */

/*
 * Data structure which is passed to conn_opt_get/set.
 * The conn_t is included even though it can be inferred from queue_t.
 * setsockopt and getsockopt use conn_ixa and conn_xmit_ipp. However,
 * when handling ancillary data we use separate ixa and ipps.
 */
typedef struct conn_opt_arg_s {
	conn_t		*coa_connp;
	ip_xmit_attr_t	*coa_ixa;
	ip_pkt_t	*coa_ipp;
	boolean_t	coa_ancillary;	/* Ancillary data and not setsockopt */
	uint_t		coa_changed;	/* See below */
} conn_opt_arg_t;

/*
 * Flags for what changed.
 * If we want to be more efficient in the future we can have more fine
 * grained flags e.g., a flag for just IP_TOS changing.
 * For now we either call ip_set_destination (for "route changed")
 * and/or conn_build_hdr_template/conn_prepend_hdr (for "header changed").
 */
#define	COA_HEADER_CHANGED	0x0001
#define	COA_ROUTE_CHANGED	0x0002
#define	COA_RCVBUF_CHANGED	0x0004	/* SO_RCVBUF */
#define	COA_SNDBUF_CHANGED	0x0008	/* SO_SNDBUF */
#define	COA_WROFF_CHANGED	0x0010	/* Header size changed */
#define	COA_ICMP_BIND_NEEDED	0x0020
#define	COA_OOBINLINE_CHANGED	0x0040

#define	TCP_PORTS_OFFSET	0
#define	UDP_PORTS_OFFSET	0

/*
 * lookups return the ill/ipif only if the flags are clear OR Iam writer.
 * ill / ipif lookup functions increment the refcnt on the ill / ipif only
 * after calling these macros. This ensures that the refcnt on the ipif or
 * ill will eventually drop down to zero.
 */
#define	ILL_LOOKUP_FAILED	1	/* Used as error code */
#define	IPIF_LOOKUP_FAILED	2	/* Used as error code */

#define	ILL_CAN_LOOKUP(ill)						\
	(!((ill)->ill_state_flags & ILL_CONDEMNED) ||			\
	IAM_WRITER_ILL(ill))

#define	ILL_IS_CONDEMNED(ill)	\
	((ill)->ill_state_flags & ILL_CONDEMNED)

#define	IPIF_CAN_LOOKUP(ipif)	\
	(!((ipif)->ipif_state_flags & IPIF_CONDEMNED) || \
	IAM_WRITER_IPIF(ipif))

#define	IPIF_IS_CONDEMNED(ipif)	\
	((ipif)->ipif_state_flags & IPIF_CONDEMNED)

#define	IPIF_IS_CHANGING(ipif)	\
	((ipif)->ipif_state_flags & IPIF_CHANGING)

/* Macros used to assert that this thread is a writer */
#define	IAM_WRITER_IPSQ(ipsq)	((ipsq)->ipsq_xop->ipx_writer == curthread)
#define	IAM_WRITER_ILL(ill)	IAM_WRITER_IPSQ((ill)->ill_phyint->phyint_ipsq)
#define	IAM_WRITER_IPIF(ipif)	IAM_WRITER_ILL((ipif)->ipif_ill)

/*
 * Grab ill locks in the proper order. The order is highest addressed
 * ill is locked first.
 */
#define	GRAB_ILL_LOCKS(ill_1, ill_2)				\
{								\
	if ((ill_1) > (ill_2)) {				\
		if (ill_1 != NULL)				\
			mutex_enter(&(ill_1)->ill_lock);	\
		if (ill_2 != NULL)				\
			mutex_enter(&(ill_2)->ill_lock);	\
	} else {						\
		if (ill_2 != NULL)				\
			mutex_enter(&(ill_2)->ill_lock);	\
		if (ill_1 != NULL && ill_1 != ill_2)		\
			mutex_enter(&(ill_1)->ill_lock);	\
	}							\
}

#define	RELEASE_ILL_LOCKS(ill_1, ill_2)		\
{						\
	if (ill_1 != NULL)			\
		mutex_exit(&(ill_1)->ill_lock);	\
	if (ill_2 != NULL && ill_2 != ill_1)	\
		mutex_exit(&(ill_2)->ill_lock);	\
}

/* Get the other protocol instance ill */
#define	ILL_OTHER(ill)						\
	((ill)->ill_isv6 ? (ill)->ill_phyint->phyint_illv4 :	\
	    (ill)->ill_phyint->phyint_illv6)

/* ioctl command info: Ioctl properties extracted and stored in here */
typedef struct cmd_info_s
{
	ipif_t  *ci_ipif;	/* ipif associated with [l]ifreq ioctl's */
	sin_t	*ci_sin;	/* the sin struct passed down */
	sin6_t	*ci_sin6;	/* the sin6_t struct passed down */
	struct lifreq *ci_lifr;	/* the lifreq struct passed down */
} cmd_info_t;

extern struct kmem_cache *ire_cache;

extern ipaddr_t	ip_g_all_ones;

extern uint_t	ip_loopback_mtu;	/* /etc/system */
extern uint_t	ip_loopback_mtuplus;
extern uint_t	ip_loopback_mtu_v6plus;

extern vmem_t *ip_minor_arena_sa;
extern vmem_t *ip_minor_arena_la;

/*
 * ip_g_forward controls IP forwarding.  It takes two values:
 *	0: IP_FORWARD_NEVER	Don't forward packets ever.
 *	1: IP_FORWARD_ALWAYS	Forward packets for elsewhere.
 *
 * RFC1122 says there must be a configuration switch to control forwarding,
 * but that the default MUST be to not forward packets ever.  Implicit
 * control based on configuration of multiple interfaces MUST NOT be
 * implemented (Section 3.1).  SunOS 4.1 did provide the "automatic" capability
 * and, in fact, it was the default.  That capability is now provided in the
 * /etc/rc2.d/S69inet script.
 */

#define	ips_ip_respond_to_address_mask_broadcast \
					ips_propinfo_tbl[0].prop_cur_bval
#define	ips_ip_g_resp_to_echo_bcast	ips_propinfo_tbl[1].prop_cur_bval
#define	ips_ip_g_resp_to_echo_mcast	ips_propinfo_tbl[2].prop_cur_bval
#define	ips_ip_g_resp_to_timestamp	ips_propinfo_tbl[3].prop_cur_bval
#define	ips_ip_g_resp_to_timestamp_bcast ips_propinfo_tbl[4].prop_cur_bval
#define	ips_ip_g_send_redirects		ips_propinfo_tbl[5].prop_cur_bval
#define	ips_ip_g_forward_directed_bcast	ips_propinfo_tbl[6].prop_cur_bval
#define	ips_ip_mrtdebug			ips_propinfo_tbl[7].prop_cur_uval
#define	ips_ip_ire_reclaim_fraction	ips_propinfo_tbl[8].prop_cur_uval
#define	ips_ip_nce_reclaim_fraction	ips_propinfo_tbl[9].prop_cur_uval
#define	ips_ip_dce_reclaim_fraction	ips_propinfo_tbl[10].prop_cur_uval
#define	ips_ip_def_ttl			ips_propinfo_tbl[11].prop_cur_uval
#define	ips_ip_forward_src_routed	ips_propinfo_tbl[12].prop_cur_bval
#define	ips_ip_wroff_extra		ips_propinfo_tbl[13].prop_cur_uval
#define	ips_ip_pathmtu_interval		ips_propinfo_tbl[14].prop_cur_uval
#define	ips_ip_icmp_return		ips_propinfo_tbl[15].prop_cur_uval
#define	ips_ip_path_mtu_discovery	ips_propinfo_tbl[16].prop_cur_bval
#define	ips_ip_pmtu_min			ips_propinfo_tbl[17].prop_cur_uval
#define	ips_ip_ignore_redirect		ips_propinfo_tbl[18].prop_cur_bval
#define	ips_ip_arp_icmp_error		ips_propinfo_tbl[19].prop_cur_bval
#define	ips_ip_broadcast_ttl		ips_propinfo_tbl[20].prop_cur_uval
#define	ips_ip_icmp_err_interval	ips_propinfo_tbl[21].prop_cur_uval
#define	ips_ip_icmp_err_burst		ips_propinfo_tbl[22].prop_cur_uval
#define	ips_ip_reass_queue_bytes	ips_propinfo_tbl[23].prop_cur_uval
#define	ips_ip_strict_dst_multihoming	ips_propinfo_tbl[24].prop_cur_uval
#define	ips_ip_addrs_per_if		ips_propinfo_tbl[25].prop_cur_uval
#define	ips_ipsec_override_persocket_policy ips_propinfo_tbl[26].prop_cur_bval
#define	ips_icmp_accept_clear_messages	ips_propinfo_tbl[27].prop_cur_bval
#define	ips_igmp_accept_clear_messages	ips_propinfo_tbl[28].prop_cur_bval

/* IPv6 configuration knobs */
#define	ips_delay_first_probe_time	ips_propinfo_tbl[29].prop_cur_uval
#define	ips_max_unicast_solicit		ips_propinfo_tbl[30].prop_cur_uval
#define	ips_ipv6_def_hops		ips_propinfo_tbl[31].prop_cur_uval
#define	ips_ipv6_icmp_return		ips_propinfo_tbl[32].prop_cur_uval
#define	ips_ipv6_forward_src_routed	ips_propinfo_tbl[33].prop_cur_bval
#define	ips_ipv6_resp_echo_mcast	ips_propinfo_tbl[34].prop_cur_bval
#define	ips_ipv6_send_redirects		ips_propinfo_tbl[35].prop_cur_bval
#define	ips_ipv6_ignore_redirect	ips_propinfo_tbl[36].prop_cur_bval
#define	ips_ipv6_strict_dst_multihoming	ips_propinfo_tbl[37].prop_cur_uval
#define	ips_src_check			ips_propinfo_tbl[38].prop_cur_uval
#define	ips_ipsec_policy_log_interval	ips_propinfo_tbl[39].prop_cur_uval
#define	ips_pim_accept_clear_messages	ips_propinfo_tbl[40].prop_cur_bval
#define	ips_ip_ndp_unsolicit_interval	ips_propinfo_tbl[41].prop_cur_uval
#define	ips_ip_ndp_unsolicit_count	ips_propinfo_tbl[42].prop_cur_uval
#define	ips_ipv6_ignore_home_address_opt ips_propinfo_tbl[43].prop_cur_bval

/* Misc IP configuration knobs */
#define	ips_ip_policy_mask		ips_propinfo_tbl[44].prop_cur_uval
#define	ips_ip_ecmp_behavior		ips_propinfo_tbl[45].prop_cur_uval
#define	ips_ip_multirt_ttl  		ips_propinfo_tbl[46].prop_cur_uval
#define	ips_ip_ire_badcnt_lifetime	ips_propinfo_tbl[47].prop_cur_uval
#define	ips_ip_max_temp_idle		ips_propinfo_tbl[48].prop_cur_uval
#define	ips_ip_max_temp_defend		ips_propinfo_tbl[49].prop_cur_uval
#define	ips_ip_max_defend		ips_propinfo_tbl[50].prop_cur_uval
#define	ips_ip_defend_interval		ips_propinfo_tbl[51].prop_cur_uval
#define	ips_ip_dup_recovery		ips_propinfo_tbl[52].prop_cur_uval
#define	ips_ip_restrict_interzone_loopback ips_propinfo_tbl[53].prop_cur_bval
#define	ips_ip_lso_outbound		ips_propinfo_tbl[54].prop_cur_bval
#define	ips_igmp_max_version		ips_propinfo_tbl[55].prop_cur_uval
#define	ips_mld_max_version		ips_propinfo_tbl[56].prop_cur_uval
#define	ips_ip_forwarding		ips_propinfo_tbl[57].prop_cur_bval
#define	ips_ipv6_forwarding		ips_propinfo_tbl[58].prop_cur_bval
#define	ips_ip_reassembly_timeout	ips_propinfo_tbl[59].prop_cur_uval
#define	ips_ipv6_reassembly_timeout	ips_propinfo_tbl[60].prop_cur_uval
#define	ips_ip_cgtp_filter		ips_propinfo_tbl[61].prop_cur_bval
#define	ips_arp_probe_delay		ips_propinfo_tbl[62].prop_cur_uval
#define	ips_arp_fastprobe_delay		ips_propinfo_tbl[63].prop_cur_uval
#define	ips_arp_probe_interval		ips_propinfo_tbl[64].prop_cur_uval
#define	ips_arp_fastprobe_interval	ips_propinfo_tbl[65].prop_cur_uval
#define	ips_arp_probe_count		ips_propinfo_tbl[66].prop_cur_uval
#define	ips_arp_fastprobe_count		ips_propinfo_tbl[67].prop_cur_uval
#define	ips_ipv4_dad_announce_interval	ips_propinfo_tbl[68].prop_cur_uval
#define	ips_ipv6_dad_announce_interval	ips_propinfo_tbl[69].prop_cur_uval
#define	ips_arp_defend_interval		ips_propinfo_tbl[70].prop_cur_uval
#define	ips_arp_defend_rate		ips_propinfo_tbl[71].prop_cur_uval
#define	ips_ndp_defend_interval		ips_propinfo_tbl[72].prop_cur_uval
#define	ips_ndp_defend_rate		ips_propinfo_tbl[73].prop_cur_uval
#define	ips_arp_defend_period		ips_propinfo_tbl[74].prop_cur_uval
#define	ips_ndp_defend_period		ips_propinfo_tbl[75].prop_cur_uval
#define	ips_ipv4_icmp_return_pmtu	ips_propinfo_tbl[76].prop_cur_bval
#define	ips_ipv6_icmp_return_pmtu	ips_propinfo_tbl[77].prop_cur_bval
#define	ips_ip_arp_publish_count	ips_propinfo_tbl[78].prop_cur_uval
#define	ips_ip_arp_publish_interval	ips_propinfo_tbl[79].prop_cur_uval
#define	ips_ip_strict_src_multihoming	ips_propinfo_tbl[80].prop_cur_uval
#define	ips_ipv6_strict_src_multihoming	ips_propinfo_tbl[81].prop_cur_uval
#define	ips_ipv6_drop_inbound_icmpv6	ips_propinfo_tbl[82].prop_cur_bval
#define	ips_ip_dce_reclaim_threshold	ips_propinfo_tbl[83].prop_cur_uval

extern int	dohwcksum;	/* use h/w cksum if supported by the h/w */
#ifdef ZC_TEST
extern int	noswcksum;
#endif

extern char	ipif_loopback_name[];

extern nv_t	*ire_nv_tbl;

extern struct module_info ip_mod_info;

#define	HOOKS4_INTERESTED_PHYSICAL_IN(ipst)	\
	((ipst)->ips_ip4_physical_in_event.he_interested)
#define	HOOKS6_INTERESTED_PHYSICAL_IN(ipst)	\
	((ipst)->ips_ip6_physical_in_event.he_interested)
#define	HOOKS4_INTERESTED_PHYSICAL_OUT(ipst)	\
	((ipst)->ips_ip4_physical_out_event.he_interested)
#define	HOOKS6_INTERESTED_PHYSICAL_OUT(ipst)	\
	((ipst)->ips_ip6_physical_out_event.he_interested)
#define	HOOKS4_INTERESTED_FORWARDING(ipst)	\
	((ipst)->ips_ip4_forwarding_event.he_interested)
#define	HOOKS6_INTERESTED_FORWARDING(ipst)	\
	((ipst)->ips_ip6_forwarding_event.he_interested)
#define	HOOKS4_INTERESTED_LOOPBACK_IN(ipst)	\
	((ipst)->ips_ip4_loopback_in_event.he_interested)
#define	HOOKS6_INTERESTED_LOOPBACK_IN(ipst)	\
	((ipst)->ips_ip6_loopback_in_event.he_interested)
#define	HOOKS4_INTERESTED_LOOPBACK_OUT(ipst)	\
	((ipst)->ips_ip4_loopback_out_event.he_interested)
#define	HOOKS6_INTERESTED_LOOPBACK_OUT(ipst)	\
	((ipst)->ips_ip6_loopback_out_event.he_interested)
/*
 * Hooks marcos used inside of ip
 * The callers use the above INTERESTED macros first, hence
 * the he_interested check is superflous.
 */
#define	FW_HOOKS(_hook, _event, _ilp, _olp, _iph, _fm, _m, _llm, ipst, _err) \
	if ((_hook).he_interested) {					\
		hook_pkt_event_t info;					\
									\
		_NOTE(CONSTCOND)					\
		ASSERT((_ilp != NULL) || (_olp != NULL));		\
									\
		FW_SET_ILL_INDEX(info.hpe_ifp, (ill_t *)_ilp);		\
		FW_SET_ILL_INDEX(info.hpe_ofp, (ill_t *)_olp);		\
		info.hpe_protocol = ipst->ips_ipv4_net_data;		\
		info.hpe_hdr = _iph;					\
		info.hpe_mp = &(_fm);					\
		info.hpe_mb = _m;					\
		info.hpe_flags = _llm;					\
		_err = hook_run(ipst->ips_ipv4_net_data->netd_hooks,	\
		    _event, (hook_data_t)&info);			\
		if (_err != 0) {					\
			ip2dbg(("%s hook dropped mblk chain %p hdr %p\n",\
			    (_hook).he_name, (void *)_fm, (void *)_m));	\
			if (_fm != NULL) {				\
				freemsg(_fm);				\
				_fm = NULL;				\
			}						\
			_iph = NULL;					\
			_m = NULL;					\
		} else {						\
			_iph = info.hpe_hdr;				\
			_m = info.hpe_mb;				\
		}							\
	}

#define	FW_HOOKS6(_hook, _event, _ilp, _olp, _iph, _fm, _m, _llm, ipst, _err) \
	if ((_hook).he_interested) {					\
		hook_pkt_event_t info;					\
									\
		_NOTE(CONSTCOND)					\
		ASSERT((_ilp != NULL) || (_olp != NULL));		\
									\
		FW_SET_ILL_INDEX(info.hpe_ifp, (ill_t *)_ilp);		\
		FW_SET_ILL_INDEX(info.hpe_ofp, (ill_t *)_olp);		\
		info.hpe_protocol = ipst->ips_ipv6_net_data;		\
		info.hpe_hdr = _iph;					\
		info.hpe_mp = &(_fm);					\
		info.hpe_mb = _m;					\
		info.hpe_flags = _llm;					\
		_err = hook_run(ipst->ips_ipv6_net_data->netd_hooks,	\
		    _event, (hook_data_t)&info);			\
		if (_err != 0) {					\
			ip2dbg(("%s hook dropped mblk chain %p hdr %p\n",\
			    (_hook).he_name, (void *)_fm, (void *)_m));	\
			if (_fm != NULL) {				\
				freemsg(_fm);				\
				_fm = NULL;				\
			}						\
			_iph = NULL;					\
			_m = NULL;					\
		} else {						\
			_iph = info.hpe_hdr;				\
			_m = info.hpe_mb;				\
		}							\
	}

#define	FW_SET_ILL_INDEX(fp, ill)					\
	_NOTE(CONSTCOND)						\
	if ((ill) == NULL || (ill)->ill_phyint == NULL) {		\
		(fp) = 0;						\
		_NOTE(CONSTCOND)					\
	} else if (IS_UNDER_IPMP(ill)) {				\
		(fp) = ipmp_ill_get_ipmp_ifindex(ill);			\
	} else {							\
		(fp) = (ill)->ill_phyint->phyint_ifindex;		\
	}

/*
 * Network byte order macros
 */
#ifdef	_BIG_ENDIAN
#define	N_IN_CLASSA_NET		IN_CLASSA_NET
#define	N_IN_CLASSD_NET		IN_CLASSD_NET
#define	N_INADDR_UNSPEC_GROUP	INADDR_UNSPEC_GROUP
#define	N_IN_LOOPBACK_NET	(ipaddr_t)0x7f000000U
#else /* _BIG_ENDIAN */
#define	N_IN_CLASSA_NET		(ipaddr_t)0x000000ffU
#define	N_IN_CLASSD_NET		(ipaddr_t)0x000000f0U
#define	N_INADDR_UNSPEC_GROUP	(ipaddr_t)0x000000e0U
#define	N_IN_LOOPBACK_NET	(ipaddr_t)0x0000007fU
#endif /* _BIG_ENDIAN */
#define	CLASSD(addr)	(((addr) & N_IN_CLASSD_NET) == N_INADDR_UNSPEC_GROUP)
#define	CLASSE(addr)	(((addr) & N_IN_CLASSD_NET) == N_IN_CLASSD_NET)
#define	IP_LOOPBACK_ADDR(addr)			\
	(((addr) & N_IN_CLASSA_NET == N_IN_LOOPBACK_NET))

extern int	ip_debug;
extern uint_t	ip_thread_data;
extern krwlock_t ip_thread_rwlock;
extern list_t	ip_thread_list;

#ifdef IP_DEBUG
#include <sys/debug.h>
#include <sys/promif.h>

#define	ip0dbg(a)	printf a
#define	ip1dbg(a)	if (ip_debug > 2) printf a
#define	ip2dbg(a)	if (ip_debug > 3) printf a
#define	ip3dbg(a)	if (ip_debug > 4) printf a
#else
#define	ip0dbg(a)	/* */
#define	ip1dbg(a)	/* */
#define	ip2dbg(a)	/* */
#define	ip3dbg(a)	/* */
#endif	/* IP_DEBUG */

/* Default MAC-layer address string length for mac_colon_addr */
#define	MAC_STR_LEN	128

struct	mac_header_info_s;

extern void	ill_frag_timer(void *);
extern ill_t	*ill_first(int, int, ill_walk_context_t *, ip_stack_t *);
extern ill_t	*ill_next(ill_walk_context_t *, ill_t *);
extern void	ill_frag_timer_start(ill_t *);
extern void	ill_nic_event_dispatch(ill_t *, lif_if_t, nic_event_t,
    nic_event_data_t, size_t);
extern mblk_t	*ip_carve_mp(mblk_t **, ssize_t);
extern mblk_t	*ip_dlpi_alloc(size_t, t_uscalar_t);
extern mblk_t	*ip_dlnotify_alloc(uint_t, uint_t);
extern mblk_t	*ip_dlnotify_alloc2(uint_t, uint_t, uint_t);
extern char	*ip_dot_addr(ipaddr_t, char *);
extern const char *mac_colon_addr(const uint8_t *, size_t, char *, size_t);
extern void	ip_lwput(queue_t *, mblk_t *);
extern boolean_t icmp_err_rate_limit(ip_stack_t *);
extern void	icmp_frag_needed(mblk_t *, int, ip_recv_attr_t *);
extern mblk_t	*icmp_inbound_v4(mblk_t *, ip_recv_attr_t *);
extern void	icmp_time_exceeded(mblk_t *, uint8_t, ip_recv_attr_t *);
extern void	icmp_unreachable(mblk_t *, uint8_t, ip_recv_attr_t *);
extern boolean_t ip_ipsec_policy_inherit(conn_t *, conn_t *, ip_recv_attr_t *);
extern void	*ip_pullup(mblk_t *, ssize_t, ip_recv_attr_t *);
extern void	ip_setl2src(mblk_t *, ip_recv_attr_t *, ill_t *);
extern mblk_t	*ip_check_and_align_header(mblk_t *, uint_t, ip_recv_attr_t *);
extern mblk_t	*ip_check_length(mblk_t *, uchar_t *, ssize_t, uint_t, uint_t,
    ip_recv_attr_t *);
extern mblk_t	*ip_check_optlen(mblk_t *, ipha_t *, uint_t, uint_t,
    ip_recv_attr_t *);
extern mblk_t	*ip_fix_dbref(mblk_t *, ip_recv_attr_t *);
extern uint_t	ip_cksum(mblk_t *, int, uint32_t);
extern int	ip_close(queue_t *, int);
extern uint16_t	ip_csum_hdr(ipha_t *);
extern void	ip_forward_xmit_v4(nce_t *, ill_t *, mblk_t *, ipha_t *,
    ip_recv_attr_t *, uint32_t, uint32_t);
extern boolean_t ip_forward_options(mblk_t *, ipha_t *, ill_t *,
    ip_recv_attr_t *);
extern int	ip_fragment_v4(mblk_t *, nce_t *, iaflags_t, uint_t, uint32_t,
    uint32_t, zoneid_t, zoneid_t, pfirepostfrag_t postfragfn,
    uintptr_t *cookie);
extern void	ip_proto_not_sup(mblk_t *, ip_recv_attr_t *);
extern void	ip_ire_g_fini(void);
extern void	ip_ire_g_init(void);
extern void	ip_ire_fini(ip_stack_t *);
extern void	ip_ire_init(ip_stack_t *);
extern void	ip_mdata_to_mhi(ill_t *, mblk_t *, struct mac_header_info_s *);
extern int	ip_openv4(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
extern int	ip_openv6(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
extern int	ip_reassemble(mblk_t *, ipf_t *, uint_t, boolean_t, ill_t *,
    size_t);
extern void	ip_rput(queue_t *, mblk_t *);
extern void	ip_input(ill_t *, ill_rx_ring_t *, mblk_t *,
    struct mac_header_info_s *);
extern void	ip_input_v6(ill_t *, ill_rx_ring_t *, mblk_t *,
    struct mac_header_info_s *);
extern mblk_t	*ip_input_common_v4(ill_t *, ill_rx_ring_t *, mblk_t *,
    struct mac_header_info_s *, squeue_t *, mblk_t **, uint_t *);
extern mblk_t	*ip_input_common_v6(ill_t *, ill_rx_ring_t *, mblk_t *,
    struct mac_header_info_s *, squeue_t *, mblk_t **, uint_t *);
extern void	ill_input_full_v4(mblk_t *, void *, void *,
    ip_recv_attr_t *, rtc_t *);
extern void	ill_input_short_v4(mblk_t *, void *, void *,
    ip_recv_attr_t *, rtc_t *);
extern void	ill_input_full_v6(mblk_t *, void *, void *,
    ip_recv_attr_t *, rtc_t *);
extern void	ill_input_short_v6(mblk_t *, void *, void *,
    ip_recv_attr_t *, rtc_t *);
extern ipaddr_t	ip_input_options(ipha_t *, ipaddr_t, mblk_t *,
    ip_recv_attr_t *, int *);
extern boolean_t ip_input_local_options(mblk_t *, ipha_t *, ip_recv_attr_t *);
extern mblk_t	*ip_input_fragment(mblk_t *, ipha_t *, ip_recv_attr_t *);
extern mblk_t	*ip_input_fragment_v6(mblk_t *, ip6_t *, ip6_frag_t *, uint_t,
    ip_recv_attr_t *);
extern void	ip_input_post_ipsec(mblk_t *, ip_recv_attr_t *);
extern void	ip_fanout_v4(mblk_t *, ipha_t *, ip_recv_attr_t *);
extern void	ip_fanout_v6(mblk_t *, ip6_t *, ip_recv_attr_t *);
extern void	ip_fanout_proto_conn(conn_t *, mblk_t *, ipha_t *, ip6_t *,
    ip_recv_attr_t *);
extern void	ip_fanout_proto_v4(mblk_t *, ipha_t *, ip_recv_attr_t *);
extern void	ip_fanout_send_icmp_v4(mblk_t *, uint_t, uint_t,
    ip_recv_attr_t *);
extern void	ip_fanout_udp_conn(conn_t *, mblk_t *, ipha_t *, ip6_t *,
    ip_recv_attr_t *);
extern void	ip_fanout_udp_multi_v4(mblk_t *, ipha_t *, uint16_t, uint16_t,
    ip_recv_attr_t *);
extern mblk_t	*zero_spi_check(mblk_t *, ip_recv_attr_t *);
extern void	ip_build_hdrs_v4(uchar_t *, uint_t, const ip_pkt_t *, uint8_t);
extern int	ip_find_hdr_v4(ipha_t *, ip_pkt_t *, boolean_t);
extern int	ip_total_hdrs_len_v4(const ip_pkt_t *);

extern mblk_t	*ip_accept_tcp(ill_t *, ill_rx_ring_t *, squeue_t *,
    mblk_t *, mblk_t **, uint_t *cnt);
extern void	ip_rput_dlpi(ill_t *, mblk_t *);
extern void	ip_rput_notdata(ill_t *, mblk_t *);

extern void	ip_mib2_add_ip_stats(mib2_ipIfStatsEntry_t *,
		    mib2_ipIfStatsEntry_t *);
extern void	ip_mib2_add_icmp6_stats(mib2_ipv6IfIcmpEntry_t *,
		    mib2_ipv6IfIcmpEntry_t *);
extern void	ip_rput_other(ipsq_t *, queue_t *, mblk_t *, void *);
extern ire_t	*ip_check_multihome(void *, ire_t *, ill_t *);
extern void	ip_send_potential_redirect_v4(mblk_t *, ipha_t *, ire_t *,
    ip_recv_attr_t *);
extern int	ip_set_destination_v4(ipaddr_t *, ipaddr_t, ipaddr_t,
    ip_xmit_attr_t *, iulp_t *, uint32_t, uint_t);
extern int	ip_set_destination_v6(in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, ip_xmit_attr_t *, iulp_t *, uint32_t, uint_t);

extern int	ip_output_simple(mblk_t *, ip_xmit_attr_t *);
extern int	ip_output_simple_v4(mblk_t *, ip_xmit_attr_t *);
extern int	ip_output_simple_v6(mblk_t *, ip_xmit_attr_t *);
extern int	ip_output_options(mblk_t *, ipha_t *, ip_xmit_attr_t *,
    ill_t *);
extern void	ip_output_local_options(ipha_t *, ip_stack_t *);

extern ip_xmit_attr_t *conn_get_ixa(conn_t *, boolean_t);
extern ip_xmit_attr_t *conn_get_ixa_tryhard(conn_t *, boolean_t);
extern ip_xmit_attr_t *conn_replace_ixa(conn_t *, ip_xmit_attr_t *);
extern ip_xmit_attr_t *conn_get_ixa_exclusive(conn_t *);
extern ip_xmit_attr_t *ip_xmit_attr_duplicate(ip_xmit_attr_t *);
extern void	ip_xmit_attr_replace_tsl(ip_xmit_attr_t *, ts_label_t *);
extern void	ip_xmit_attr_restore_tsl(ip_xmit_attr_t *, cred_t *);
boolean_t	ip_recv_attr_replace_label(ip_recv_attr_t *, ts_label_t *);
extern void	ixa_inactive(ip_xmit_attr_t *);
extern void	ixa_refrele(ip_xmit_attr_t *);
extern boolean_t ixa_check_drain_insert(conn_t *, ip_xmit_attr_t *);
extern void	ixa_cleanup(ip_xmit_attr_t *);
extern void	ira_cleanup(ip_recv_attr_t *, boolean_t);
extern void	ixa_safe_copy(ip_xmit_attr_t *, ip_xmit_attr_t *);

extern int	conn_ip_output(mblk_t *, ip_xmit_attr_t *);
extern boolean_t ip_output_verify_local(ip_xmit_attr_t *);
extern mblk_t	*ip_output_process_local(mblk_t *, ip_xmit_attr_t *, boolean_t,
    boolean_t, conn_t *);

extern int	conn_opt_get(conn_opt_arg_t *, t_scalar_t, t_scalar_t,
    uchar_t *);
extern int	conn_opt_set(conn_opt_arg_t *, t_scalar_t, t_scalar_t, uint_t,
    uchar_t *, boolean_t, cred_t *);
extern boolean_t	conn_same_as_last_v4(conn_t *, sin_t *);
extern boolean_t	conn_same_as_last_v6(conn_t *, sin6_t *);
extern int	conn_update_label(const conn_t *, const ip_xmit_attr_t *,
    const in6_addr_t *, ip_pkt_t *);

extern int	ip_opt_set_multicast_group(conn_t *, t_scalar_t,
    uchar_t *, boolean_t, boolean_t);
extern int	ip_opt_set_multicast_sources(conn_t *, t_scalar_t,
    uchar_t *, boolean_t, boolean_t);
extern int	conn_getsockname(conn_t *, struct sockaddr *, uint_t *);
extern int	conn_getpeername(conn_t *, struct sockaddr *, uint_t *);

extern int	conn_build_hdr_template(conn_t *, uint_t, uint_t,
    const in6_addr_t *, const in6_addr_t *, uint32_t);
extern mblk_t	*conn_prepend_hdr(ip_xmit_attr_t *, const ip_pkt_t *,
    const in6_addr_t *, const in6_addr_t *, uint8_t, uint32_t, uint_t,
    mblk_t *, uint_t, uint_t, uint32_t *, int *);
extern void	ip_attr_newdst(ip_xmit_attr_t *);
extern void	ip_attr_nexthop(const ip_pkt_t *, const ip_xmit_attr_t *,
    const in6_addr_t *, in6_addr_t *);
extern int	conn_connect(conn_t *, iulp_t *, uint32_t);
extern int	ip_attr_connect(const conn_t *, ip_xmit_attr_t *,
    const in6_addr_t *, const in6_addr_t *, const in6_addr_t *, in_port_t,
    in6_addr_t *, iulp_t *, uint32_t);
extern int	conn_inherit_parent(conn_t *, conn_t *);

extern void	conn_ixa_cleanup(conn_t *connp, void *arg);

extern boolean_t conn_wantpacket(conn_t *, ip_recv_attr_t *, ipha_t *);
extern uint_t	ip_type_v4(ipaddr_t, ip_stack_t *);
extern uint_t	ip_type_v6(const in6_addr_t *, ip_stack_t *);

extern void	ip_wput_nondata(queue_t *, mblk_t *);
extern void	ip_wsrv(queue_t *);
extern char	*ip_nv_lookup(nv_t *, int);
extern boolean_t ip_local_addr_ok_v6(const in6_addr_t *, const in6_addr_t *);
extern boolean_t ip_remote_addr_ok_v6(const in6_addr_t *, const in6_addr_t *);
extern ipaddr_t ip_massage_options(ipha_t *, netstack_t *);
extern ipaddr_t ip_net_mask(ipaddr_t);
extern void	arp_bringup_done(ill_t *, int);
extern void	arp_replumb_done(ill_t *, int);

extern struct qinit iprinitv6;

extern void	ipmp_init(ip_stack_t *);
extern void	ipmp_destroy(ip_stack_t *);
extern ipmp_grp_t *ipmp_grp_create(const char *, phyint_t *);
extern void	ipmp_grp_destroy(ipmp_grp_t *);
extern void	ipmp_grp_info(const ipmp_grp_t *, lifgroupinfo_t *);
extern int	ipmp_grp_rename(ipmp_grp_t *, const char *);
extern ipmp_grp_t *ipmp_grp_lookup(const char *, ip_stack_t *);
extern int	ipmp_grp_vet_phyint(ipmp_grp_t *, phyint_t *);
extern ipmp_illgrp_t *ipmp_illgrp_create(ill_t *);
extern void	ipmp_illgrp_destroy(ipmp_illgrp_t *);
extern ill_t	*ipmp_illgrp_add_ipif(ipmp_illgrp_t *, ipif_t *);
extern void	ipmp_illgrp_del_ipif(ipmp_illgrp_t *, ipif_t *);
extern ill_t	*ipmp_illgrp_next_ill(ipmp_illgrp_t *);
extern ill_t	*ipmp_illgrp_hold_next_ill(ipmp_illgrp_t *);
extern ill_t	*ipmp_illgrp_hold_cast_ill(ipmp_illgrp_t *);
extern ill_t	*ipmp_illgrp_ipmp_ill(ipmp_illgrp_t *);
extern void	ipmp_illgrp_refresh_mtu(ipmp_illgrp_t *);
extern ipmp_arpent_t *ipmp_illgrp_create_arpent(ipmp_illgrp_t *,
    boolean_t, ipaddr_t, uchar_t *, size_t, uint16_t);
extern void	ipmp_illgrp_destroy_arpent(ipmp_illgrp_t *, ipmp_arpent_t *);
extern ipmp_arpent_t *ipmp_illgrp_lookup_arpent(ipmp_illgrp_t *, ipaddr_t *);
extern void	ipmp_illgrp_refresh_arpent(ipmp_illgrp_t *);
extern void	ipmp_illgrp_mark_arpent(ipmp_illgrp_t *, ipmp_arpent_t *);
extern ill_t	*ipmp_illgrp_find_ill(ipmp_illgrp_t *, uchar_t *, uint_t);
extern void	ipmp_illgrp_link_grp(ipmp_illgrp_t *, ipmp_grp_t *);
extern int	ipmp_illgrp_unlink_grp(ipmp_illgrp_t *);
extern uint_t	ipmp_ill_get_ipmp_ifindex(const ill_t *);
extern void	ipmp_ill_join_illgrp(ill_t *, ipmp_illgrp_t *);
extern void	ipmp_ill_leave_illgrp(ill_t *);
extern ill_t	*ipmp_ill_hold_ipmp_ill(ill_t *);
extern ill_t	*ipmp_ill_hold_xmit_ill(ill_t *, boolean_t);
extern boolean_t ipmp_ill_is_active(ill_t *);
extern void	ipmp_ill_refresh_active(ill_t *);
extern void	ipmp_phyint_join_grp(phyint_t *, ipmp_grp_t *);
extern void	ipmp_phyint_leave_grp(phyint_t *);
extern void	ipmp_phyint_refresh_active(phyint_t *);
extern ill_t	*ipmp_ipif_bound_ill(const ipif_t *);
extern ill_t	*ipmp_ipif_hold_bound_ill(const ipif_t *);
extern boolean_t ipmp_ipif_is_dataaddr(const ipif_t *);
extern boolean_t ipmp_ipif_is_stubaddr(const ipif_t *);
extern boolean_t ipmp_packet_is_probe(mblk_t *, ill_t *);
extern void	ipmp_ncec_delete_nce(ncec_t *);
extern void	ipmp_ncec_refresh_nce(ncec_t *);

extern void	conn_drain_insert(conn_t *, idl_tx_list_t *);
extern void	conn_setqfull(conn_t *, boolean_t *);
extern void	conn_clrqfull(conn_t *, boolean_t *);
extern int	conn_ipsec_length(conn_t *);
extern ipaddr_t	ip_get_dst(ipha_t *);
extern uint_t	ip_get_pmtu(ip_xmit_attr_t *);
extern uint_t	ip_get_base_mtu(ill_t *, ire_t *);
extern mblk_t *ip_output_attach_policy(mblk_t *, ipha_t *, ip6_t *,
    const conn_t *, ip_xmit_attr_t *);
extern int	ipsec_out_extra_length(ip_xmit_attr_t *);
extern int	ipsec_out_process(mblk_t *, ip_xmit_attr_t *);
extern int	ip_output_post_ipsec(mblk_t *, ip_xmit_attr_t *);
extern void	ipsec_out_to_in(ip_xmit_attr_t *, ill_t *ill,
    ip_recv_attr_t *);

extern void	ire_cleanup(ire_t *);
extern void	ire_inactive(ire_t *);
extern boolean_t irb_inactive(irb_t *);
extern ire_t	*ire_unlink(irb_t *);

#ifdef DEBUG
extern	boolean_t th_trace_ref(const void *, ip_stack_t *);
extern	void	th_trace_unref(const void *);
extern	void	th_trace_cleanup(const void *, boolean_t);
extern	void	ire_trace_ref(ire_t *);
extern	void	ire_untrace_ref(ire_t *);
#endif

extern int	ip_srcid_insert(const in6_addr_t *, zoneid_t, ip_stack_t *);
extern int	ip_srcid_remove(const in6_addr_t *, zoneid_t, ip_stack_t *);
extern boolean_t ip_srcid_find_id(uint_t, in6_addr_t *, zoneid_t, boolean_t,
    netstack_t *);
extern uint_t	ip_srcid_find_addr(const in6_addr_t *, zoneid_t, netstack_t *);

extern uint8_t	ipoptp_next(ipoptp_t *);
extern uint8_t	ipoptp_first(ipoptp_t *, ipha_t *);
extern int	ip_opt_get_user(conn_t *, uchar_t *);
extern int	ipsec_req_from_conn(conn_t *, ipsec_req_t *, int);
extern int	ip_snmp_get(queue_t *q, mblk_t *mctl, int level, boolean_t);
extern int	ip_snmp_set(queue_t *q, int, int, uchar_t *, int);
extern void	ip_process_ioctl(ipsq_t *, queue_t *, mblk_t *, void *);
extern void	ip_quiesce_conn(conn_t *);
extern  void    ip_reprocess_ioctl(ipsq_t *, queue_t *, mblk_t *, void *);
extern void	ip_ioctl_finish(queue_t *, mblk_t *, int, int, ipsq_t *);

extern boolean_t ip_cmpbuf(const void *, uint_t, boolean_t, const void *,
    uint_t);
extern boolean_t ip_allocbuf(void **, uint_t *, boolean_t, const void *,
    uint_t);
extern void	ip_savebuf(void **, uint_t *, boolean_t, const void *, uint_t);

extern boolean_t	ipsq_pending_mp_cleanup(ill_t *, conn_t *);
extern void	conn_ioctl_cleanup(conn_t *);

extern void	ip_unbind(conn_t *);

extern void tnet_init(void);
extern void tnet_fini(void);

/*
 * Hook functions to enable cluster networking
 * On non-clustered systems these vectors must always be NULL.
 */
extern int (*cl_inet_isclusterwide)(netstackid_t stack_id, uint8_t protocol,
    sa_family_t addr_family, uint8_t *laddrp, void *args);
extern uint32_t (*cl_inet_ipident)(netstackid_t stack_id, uint8_t protocol,
    sa_family_t addr_family, uint8_t *laddrp, uint8_t *faddrp,
    void *args);
extern int (*cl_inet_connect2)(netstackid_t stack_id, uint8_t protocol,
    boolean_t is_outgoing, sa_family_t addr_family, uint8_t *laddrp,
    in_port_t lport, uint8_t *faddrp, in_port_t fport, void *args);
extern void (*cl_inet_getspi)(netstackid_t, uint8_t, uint8_t *, size_t,
    void *);
extern void (*cl_inet_getspi)(netstackid_t stack_id, uint8_t protocol,
    uint8_t *ptr, size_t len, void *args);
extern int (*cl_inet_checkspi)(netstackid_t stack_id, uint8_t protocol,
    uint32_t spi, void *args);
extern void (*cl_inet_deletespi)(netstackid_t stack_id, uint8_t protocol,
    uint32_t spi, void *args);
extern void (*cl_inet_idlesa)(netstackid_t, uint8_t, uint32_t,
    sa_family_t, in6_addr_t, in6_addr_t, void *);


/* Hooks for CGTP (multirt routes) filtering module */
#define	CGTP_FILTER_REV_1	1
#define	CGTP_FILTER_REV_2	2
#define	CGTP_FILTER_REV_3	3
#define	CGTP_FILTER_REV		CGTP_FILTER_REV_3

/* cfo_filter and cfo_filter_v6 hooks return values */
#define	CGTP_IP_PKT_NOT_CGTP	0
#define	CGTP_IP_PKT_PREMIUM	1
#define	CGTP_IP_PKT_DUPLICATE	2

/* Version 3 of the filter interface */
typedef struct cgtp_filter_ops {
	int	cfo_filter_rev;			/* CGTP_FILTER_REV_3 */
	int	(*cfo_change_state)(netstackid_t, int);
	int	(*cfo_add_dest_v4)(netstackid_t, ipaddr_t, ipaddr_t,
		    ipaddr_t, ipaddr_t);
	int	(*cfo_del_dest_v4)(netstackid_t, ipaddr_t, ipaddr_t);
	int	(*cfo_add_dest_v6)(netstackid_t, in6_addr_t *, in6_addr_t *,
		    in6_addr_t *, in6_addr_t *);
	int	(*cfo_del_dest_v6)(netstackid_t, in6_addr_t *, in6_addr_t *);
	int	(*cfo_filter)(netstackid_t, uint_t, mblk_t *);
	int	(*cfo_filter_v6)(netstackid_t, uint_t, ip6_t *,
		    ip6_frag_t *);
} cgtp_filter_ops_t;

#define	CGTP_MCAST_SUCCESS	1

/*
 * The separate CGTP module needs this global symbol so that it
 * can check the version and determine whether to use the old or the new
 * version of the filtering interface.
 */
extern int	ip_cgtp_filter_rev;

extern int	ip_cgtp_filter_supported(void);
extern int	ip_cgtp_filter_register(netstackid_t, cgtp_filter_ops_t *);
extern int	ip_cgtp_filter_unregister(netstackid_t);
extern int	ip_cgtp_filter_is_registered(netstackid_t);

/*
 * rr_ring_state cycles in the order shown below from RR_FREE through
 * RR_FREE_IN_PROG and  back to RR_FREE.
 */
typedef enum {
	RR_FREE,			/* Free slot */
	RR_SQUEUE_UNBOUND,		/* Ring's squeue is unbound */
	RR_SQUEUE_BIND_INPROG,		/* Ring's squeue bind in progress */
	RR_SQUEUE_BOUND,		/* Ring's squeue bound to cpu */
	RR_FREE_INPROG			/* Ring is being freed */
} ip_ring_state_t;

#define	ILL_MAX_RINGS		256	/* Max num of rx rings we can manage */
#define	ILL_POLLING		0x01	/* Polling in use */

/*
 * These functions pointer types are exported by the mac/dls layer.
 * we need to duplicate the definitions here because we cannot
 * include mac/dls header files here.
 */
typedef boolean_t		(*ip_mac_intr_disable_t)(void *);
typedef void			(*ip_mac_intr_enable_t)(void *);
typedef ip_mac_tx_cookie_t	(*ip_dld_tx_t)(void *, mblk_t *,
    uint64_t, uint16_t);
typedef	void			(*ip_flow_enable_t)(void *, ip_mac_tx_cookie_t);
typedef void			*(*ip_dld_callb_t)(void *,
    ip_flow_enable_t, void *);
typedef boolean_t		(*ip_dld_fctl_t)(void *, ip_mac_tx_cookie_t);
typedef int			(*ip_capab_func_t)(void *, uint_t,
    void *, uint_t);

/*
 * POLLING README
 * sq_get_pkts() is called to pick packets from softring in poll mode. It
 * calls rr_rx to get the chain and process it with rr_ip_accept.
 * rr_rx = mac_soft_ring_poll() to pick packets
 * rr_ip_accept = ip_accept_tcp() to process packets
 */

/*
 * XXX: With protocol, service specific squeues, they will have
 * specific acceptor functions.
 */
typedef	mblk_t *(*ip_mac_rx_t)(void *, size_t);
typedef mblk_t *(*ip_accept_t)(ill_t *, ill_rx_ring_t *,
    squeue_t *, mblk_t *, mblk_t **, uint_t *);

/*
 * rr_intr_enable, rr_intr_disable, rr_rx_handle, rr_rx:
 * May be accessed while in the squeue AND after checking that SQS_POLL_CAPAB
 * is set.
 *
 * rr_ring_state: Protected by ill_lock.
 */
struct ill_rx_ring {
	ip_mac_intr_disable_t	rr_intr_disable; /* Interrupt disabling func */
	ip_mac_intr_enable_t	rr_intr_enable;	/* Interrupt enabling func */
	void			*rr_intr_handle; /* Handle interrupt funcs */
	ip_mac_rx_t		rr_rx;		/* Driver receive function */
	ip_accept_t		rr_ip_accept;	/* IP accept function */
	void			*rr_rx_handle;	/* Handle for Rx ring */
	squeue_t		*rr_sqp; /* Squeue the ring is bound to */
	ill_t			*rr_ill;	/* back pointer to ill */
	ip_ring_state_t		rr_ring_state;	/* State of this ring */
};

/*
 * IP - DLD direct function call capability
 * Suffixes, df - dld function, dh - dld handle,
 * cf - client (IP) function, ch - client handle
 */
typedef struct ill_dld_direct_s {		/* DLD provided driver Tx */
	ip_dld_tx_t		idd_tx_df;	/* str_mdata_fastpath_put */
	void			*idd_tx_dh;	/* dld_str_t *dsp */
	ip_dld_callb_t		idd_tx_cb_df;	/* mac_tx_srs_notify */
	void			*idd_tx_cb_dh;	/* mac_client_handle_t *mch */
	ip_dld_fctl_t		idd_tx_fctl_df;	/* mac_tx_is_flow_blocked */
	void			*idd_tx_fctl_dh;	/* mac_client_handle */
} ill_dld_direct_t;

/* IP - DLD polling capability */
typedef struct ill_dld_poll_s {
	ill_rx_ring_t		idp_ring_tbl[ILL_MAX_RINGS];
} ill_dld_poll_t;

/* Describes ill->ill_dld_capab */
struct ill_dld_capab_s {
	ip_capab_func_t		idc_capab_df;	/* dld_capab_func */
	void			*idc_capab_dh;	/* dld_str_t *dsp */
	ill_dld_direct_t	idc_direct;
	ill_dld_poll_t		idc_poll;
};

/*
 * IP squeues exports
 */
extern boolean_t 	ip_squeue_fanout;

#define	IP_SQUEUE_GET(hint) ip_squeue_random(hint)

extern void ip_squeue_init(void (*)(squeue_t *));
extern squeue_t	*ip_squeue_random(uint_t);
extern squeue_t *ip_squeue_get(ill_rx_ring_t *);
extern squeue_t *ip_squeue_getfree(pri_t);
extern int ip_squeue_cpu_move(squeue_t *, processorid_t);
extern void *ip_squeue_add_ring(ill_t *, void *);
extern void ip_squeue_bind_ring(ill_t *, ill_rx_ring_t *, processorid_t);
extern void ip_squeue_clean_ring(ill_t *, ill_rx_ring_t *);
extern void ip_squeue_quiesce_ring(ill_t *, ill_rx_ring_t *);
extern void ip_squeue_restart_ring(ill_t *, ill_rx_ring_t *);
extern void ip_squeue_clean_all(ill_t *);
extern boolean_t	ip_source_routed(ipha_t *, ip_stack_t *);

extern void tcp_wput(queue_t *, mblk_t *);

extern int	ip_fill_mtuinfo(conn_t *, ip_xmit_attr_t *,
    struct ip6_mtuinfo *);
extern hook_t *ipobs_register_hook(netstack_t *, pfv_t);
extern void ipobs_unregister_hook(netstack_t *, hook_t *);
extern void ipobs_hook(mblk_t *, int, zoneid_t, zoneid_t, const ill_t *,
    ip_stack_t *);
typedef void    (*ipsq_func_t)(ipsq_t *, queue_t *, mblk_t *, void *);

extern void	dce_g_init(void);
extern void	dce_g_destroy(void);
extern void	dce_stack_init(ip_stack_t *);
extern void	dce_stack_destroy(ip_stack_t *);
extern void	dce_cleanup(uint_t, ip_stack_t *);
extern dce_t	*dce_get_default(ip_stack_t *);
extern dce_t	*dce_lookup_pkt(mblk_t *, ip_xmit_attr_t *, uint_t *);
extern dce_t	*dce_lookup_v4(ipaddr_t, ip_stack_t *, uint_t *);
extern dce_t	*dce_lookup_v6(const in6_addr_t *, uint_t, ip_stack_t *,
    uint_t *);
extern dce_t	*dce_lookup_and_add_v4(ipaddr_t, ip_stack_t *);
extern dce_t	*dce_lookup_and_add_v6(const in6_addr_t *, uint_t,
    ip_stack_t *);
extern int	dce_update_uinfo_v4(ipaddr_t, iulp_t *, ip_stack_t *);
extern int	dce_update_uinfo_v6(const in6_addr_t *, uint_t, iulp_t *,
    ip_stack_t *);
extern int	dce_update_uinfo(const in6_addr_t *, uint_t, iulp_t *,
    ip_stack_t *);
extern void	dce_increment_generation(dce_t *);
extern void	dce_increment_all_generations(boolean_t, ip_stack_t *);
extern void	dce_refrele(dce_t *);
extern void	dce_refhold(dce_t *);
extern void	dce_refrele_notr(dce_t *);
extern void	dce_refhold_notr(dce_t *);
mblk_t		*ip_snmp_get_mib2_ip_dce(queue_t *, mblk_t *, ip_stack_t *ipst);

extern ip_laddr_t ip_laddr_verify_v4(ipaddr_t, zoneid_t,
    ip_stack_t *, boolean_t);
extern ip_laddr_t ip_laddr_verify_v6(const in6_addr_t *, zoneid_t,
    ip_stack_t *, boolean_t, uint_t);
extern int	ip_laddr_fanout_insert(conn_t *);

extern boolean_t ip_verify_src(mblk_t *, ip_xmit_attr_t *, uint_t *);
extern int	ip_verify_ire(mblk_t *, ip_xmit_attr_t *);

extern mblk_t	*ip_xmit_attr_to_mblk(ip_xmit_attr_t *);
extern boolean_t ip_xmit_attr_from_mblk(mblk_t *, ip_xmit_attr_t *);
extern mblk_t	*ip_xmit_attr_free_mblk(mblk_t *);
extern mblk_t	*ip_recv_attr_to_mblk(ip_recv_attr_t *);
extern boolean_t ip_recv_attr_from_mblk(mblk_t *, ip_recv_attr_t *);
extern mblk_t	*ip_recv_attr_free_mblk(mblk_t *);
extern boolean_t ip_recv_attr_is_mblk(mblk_t *);

#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname inet_pton _inet_pton
#else /* __PRAGMA_REDEFINE_EXTNAME */
#define	inet_pton _inet_pton
#endif /* __PRAGMA_REDEFINE_EXTNAME */

extern char	*inet_ntop(int, const void *, char *, int);
extern int	inet_pton(int, char *, void *);

/*
 * Squeue tags. Tags only need to be unique when the callback function is the
 * same to distinguish between different calls, but we use unique tags for
 * convenience anyway.
 */
#define	SQTAG_IP_INPUT			1
#define	SQTAG_TCP_INPUT_ICMP_ERR	2
#define	SQTAG_TCP6_INPUT_ICMP_ERR	3
#define	SQTAG_IP_TCP_INPUT		4
#define	SQTAG_IP6_TCP_INPUT		5
#define	SQTAG_IP_TCP_CLOSE		6
#define	SQTAG_TCP_OUTPUT		7
#define	SQTAG_TCP_TIMER			8
#define	SQTAG_TCP_TIMEWAIT		9
#define	SQTAG_TCP_ACCEPT_FINISH		10
#define	SQTAG_TCP_ACCEPT_FINISH_Q0	11
#define	SQTAG_TCP_ACCEPT_PENDING	12
#define	SQTAG_TCP_LISTEN_DISCON		13
#define	SQTAG_TCP_CONN_REQ_1		14
#define	SQTAG_TCP_EAGER_BLOWOFF		15
#define	SQTAG_TCP_EAGER_CLEANUP		16
#define	SQTAG_TCP_EAGER_CLEANUP_Q0	17
#define	SQTAG_TCP_CONN_IND		18
#define	SQTAG_TCP_RSRV			19
#define	SQTAG_TCP_ABORT_BUCKET		20
#define	SQTAG_TCP_REINPUT		21
#define	SQTAG_TCP_REINPUT_EAGER		22
#define	SQTAG_TCP_INPUT_MCTL		23
#define	SQTAG_TCP_RPUTOTHER		24
#define	SQTAG_IP_PROTO_AGAIN		25
#define	SQTAG_IP_FANOUT_TCP		26
#define	SQTAG_IPSQ_CLEAN_RING		27
#define	SQTAG_TCP_WPUT_OTHER		28
#define	SQTAG_TCP_CONN_REQ_UNBOUND	29
#define	SQTAG_TCP_SEND_PENDING		30
#define	SQTAG_BIND_RETRY		31
#define	SQTAG_UDP_FANOUT		32
#define	SQTAG_UDP_INPUT			33
#define	SQTAG_UDP_WPUT			34
#define	SQTAG_UDP_OUTPUT		35
#define	SQTAG_TCP_KSSL_INPUT		36
#define	SQTAG_TCP_DROP_Q0		37
#define	SQTAG_TCP_CONN_REQ_2		38
#define	SQTAG_IP_INPUT_RX_RING		39
#define	SQTAG_SQUEUE_CHANGE		40
#define	SQTAG_CONNECT_FINISH		41
#define	SQTAG_SYNCHRONOUS_OP		42
#define	SQTAG_TCP_SHUTDOWN_OUTPUT	43
#define	SQTAG_TCP_IXA_CLEANUP		44
#define	SQTAG_TCP_SEND_SYNACK		45

extern sin_t	sin_null;	/* Zero address for quick clears */
extern sin6_t	sin6_null;	/* Zero address for quick clears */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_H */
