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

#ifndef	_INET_IP6_H
#define	_INET_IP6_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/isa_defs.h>

#ifdef	_KERNEL
/* icmp6_t is used in the prototype of icmp_inbound_error_fanout_v6() */
#include <netinet/icmp6.h>
#endif	/* _KERNEL */

/* version number for IPv6 - hard to get this one wrong! */
#define	IPV6_VERSION		6

#define	IPV6_HDR_LEN		40

#define	IPV6_ADDR_LEN		16

/*
 * IPv6 address scopes.  The values of these enums also match the scope
 * field of multicast addresses.
 */
typedef enum {
	IP6_SCOPE_INTFLOCAL = 1,	/* Multicast addresses only */
	IP6_SCOPE_LINKLOCAL,
	IP6_SCOPE_SUBNETLOCAL,		/* Multicast addresses only */
	IP6_SCOPE_ADMINLOCAL,		/* Multicast addresses only */
	IP6_SCOPE_SITELOCAL,
	IP6_SCOPE_GLOBAL
} in6addr_scope_t;

#ifdef	_KERNEL

/*
 * Private header used between the transports and IP to carry the content
 * of the options IPV6_PKTINFO/IPV6_RECVPKTINFO (the interface index only)
 * and IPV6_NEXTHOP.
 * Also used to specify that raw sockets do not want the UDP/TCP transport
 * checksums calculated in IP (akin to IP_HDR_INCLUDED) and provide for
 * IPV6_CHECKSUM on the transmit side (using ip6i_checksum_off).
 *
 * When this header is used it must be the first header in the packet i.e.
 * before the real ip6 header. The use of a next header value of 255
 * (IPPROTO_RAW) in this header indicates its presence. Note that
 * ip6_nxt = IPPROTO_RAW indicates that "this" header is ip6_info - the
 * next header is always IPv6.
 *
 * Note that ip6i_nexthop is at the same offset as ip6_dst so that
 * this header can be kept in the packet while the it passes through
 * ip_newroute* and the ndp code. Those routines will use ip6_dst for
 * resolution.
 *
 * Implementation offset assumptions about ip6_info_t and ip6_t fields
 * and their alignments shown in figure below
 *
 * ip6_info (Private headers from transports to IP) header below
 * _______________________________________________________________ _ _ _ _ _
 * | .... | ip6i_nxt (255)| ......................|ip6i_nexthop| ...ip6_t.
 * --------------------------------------------------------------- - - - - -
 *        ^                                       ^
 * <---- >| same offset for {ip6i_nxt,ip6_nxt}    ^
 *        ^                                       ^
 * <------^-------------------------------------->| same offset for
 *        ^                                       ^ {ip6i_nxthop,ip6_dst}
 * _______________________________________________________________ _ _ _
 * | .... | ip6_nxt       | ......................|ip6_dst     | .other hdrs...
 * --------------------------------------------------------------- - - -
 * ip6_t (IPv6 protocol) header above
 */
struct ip6_info {
	union {
		struct ip6_info_ctl {
			uint32_t	ip6i_un1_flow;
			uint16_t	ip6i_un1_plen;   /* payload length */
			uint8_t		ip6i_un1_nxt;    /* next header */
			uint8_t		ip6i_un1_hlim;   /* hop limit */
		} ip6i_un1;
	} ip6i_ctlun;
	int		ip6i_flags;	/* See below */
	int		ip6i_ifindex;
	int		ip6i_checksum_off;
	int		ip6i_pad;
	in6_addr_t	ip6i_nexthop;	/* Same offset as ip6_dst */
};
typedef struct ip6_info	ip6i_t;

#define	ip6i_flow	ip6i_ctlun.ip6i_un1.ip6i_un1_flow
#define	ip6i_vcf	ip6i_flow		/* Version, class, flow */
#define	ip6i_nxt	ip6i_ctlun.ip6i_un1.ip6i_un1_nxt
#define	ip6i_hops	ip6i_ctlun.ip6i_un1.ip6i_un1_hlim

/* ip6_info flags */
#define	IP6I_IFINDEX	0x1	/* ip6i_ifindex is set (to nonzero value) */
#define	IP6I_NEXTHOP	0x2	/* ip6i_nexthop is different than ip6_dst */
#define	IP6I_NO_ULP_CKSUM	0x4
			/*
			 * Do not generate TCP/UDP/SCTP transport checksum.
			 * Used by raw sockets. Does not affect the
			 * generation of transport checksums for ICMPv6
			 * since such packets always arrive through
			 * a raw socket.
			 */
#define	IP6I_UNSPEC_SRC	0x8
			/* Used to carry conn_unspec_src through ip_newroute* */
#define	IP6I_RAW_CHECKSUM	0x10
			/* Compute checksum and stuff in ip6i_checksum_off */
#define	IP6I_VERIFY_SRC	0x20	/* Verify ip6_src. Used when IPV6_PKTINFO */
#define	IP6I_IPMP_PROBE	0x40	/* IPMP (in.mpathd) probe packet */
				/* 0x80 - 0x100 available */
#define	IP6I_DONTFRAG	0x200	/* Don't fragment this packet */
#define	IP6I_HOPLIMIT	0x400	/* hoplimit has been set by the sender */

/*
 * These constants refer to the IPV6_USE_MIN_MTU API.  The
 * actually values used in the API are these values shifted down
 * 10 bits minus 2 [-1, 1].  0 (-2 after conversion) is considered
 * the same as the default (-1).  IP6I_API_USE_MIN_MTU(f, x) returns
 * the flags field updated with min mtu.  IP6I_USE_MIN_MTU_API takes the
 * field and returns the API value (+ the -2 value).
 */
#define	IP6I_USE_MIN_MTU_UNICAST	0x400
#define	IP6I_USE_MIN_MTU_ALWAYS		0x800
#define	IP6I_USE_MIN_MTU_NEVER		0xC00
#define	IP6I_USE_MIN_MTU_API(x)		((((x) & 0xC00) >> 10) - 2)
#define	IP6I_API_USE_MIN_MTU(f, x)	(((f) & ~0xC00) &\
					((((x) + 2) & 0x3) << 11))
#define	IPV6_USE_MIN_MTU_DEFAULT	-2
#define	IPV6_USE_MIN_MTU_UNICAST	-1
#define	IPV6_USE_MIN_MTU_ALWAYS		0
#define	IPV6_USE_MIN_MTU_NEVER		1

/* Extract the scope from a multicast address */
#ifdef _BIG_ENDIAN
#define	IN6_ADDR_MC_SCOPE(addr) \
	(((addr)->s6_addr32[0] & 0x000f0000) >> 16)
#else
#define	IN6_ADDR_MC_SCOPE(addr) \
	(((addr)->s6_addr32[0] & 0x00000f00) >> 8)
#endif

/* Default IPv4 TTL for IPv6-in-IPv4 encapsulated packets */
#define	IPV6_DEFAULT_HOPS	60	/* XXX What should it be? */

/* Max IPv6 TTL */
#define	IPV6_MAX_HOPS	255

/* Minimum IPv6 MTU from rfc2460 */
#define	IPV6_MIN_MTU		1280

/* EUI-64 based token length */
#define	IPV6_TOKEN_LEN		64

/* Length of an advertised IPv6 prefix */
#define	IPV6_PREFIX_LEN		64

/* Default and maximum tunnel encapsulation limits.  See RFC 2473. */
#define	IPV6_DEFAULT_ENCAPLIMIT	4
#define	IPV6_MAX_ENCAPLIMIT	255

/*
 * Minimum and maximum extension header lengths for IPv6.  The 8-bit
 * length field of each extension header (see rfc2460) specifies the
 * number of 8 octet units of data in the header not including the
 * first 8 octets.  A value of 0 would indicate 8 bytes (0 * 8 + 8),
 * and 255 would indicate 2048 bytes (255 * 8 + 8).
 */
#define	MIN_EHDR_LEN		8
#define	MAX_EHDR_LEN		2048

/*
 * The high-order bit of the version field is used by the transports to
 * indicate a reachability confirmation to IP.
 */
#define	IP_FORWARD_PROG_BIT		0x8

#ifdef _BIG_ENDIAN
#define	IPV6_DEFAULT_VERS_AND_FLOW	0x60000000
#define	IPV6_VERS_AND_FLOW_MASK		0xF0000000
#define	IP_FORWARD_PROG			((uint32_t)IP_FORWARD_PROG_BIT << 28)
#define	V6_MCAST			0xFF000000
#define	V6_LINKLOCAL			0xFE800000

#define	IPV6_FLOW_TCLASS(x)		(((x) & IPV6_FLOWINFO_TCLASS) >> 20)
#define	IPV6_TCLASS_FLOW(f, c)		(((f) & ~IPV6_FLOWINFO_TCLASS) |\
					((c) << 20))

#else
#define	IPV6_DEFAULT_VERS_AND_FLOW	0x00000060
#define	IPV6_VERS_AND_FLOW_MASK		0x000000F0
#define	IP_FORWARD_PROG			((uint32_t)IP_FORWARD_PROG_BIT << 4)

#define	V6_MCAST			0x000000FF
#define	V6_LINKLOCAL			0x000080FE

#define	IPV6_FLOW_TCLASS(x)		((((x) & 0xf000U) >> 12) |\
					(((x) & 0xf) << 4))
#define	IPV6_TCLASS_FLOW(f, c)		(((f) & ~IPV6_FLOWINFO_TCLASS) |\
					((((c) & 0xf) << 12) |\
					(((c) & 0xf0) >> 4)))
#endif

/*
 * UTILITY MACROS FOR ADDRESSES.
 */

/*
 * Convert an IPv4 address mask to an IPv6 mask.   Pad with 1-bits.
 */
#define	V4MASK_TO_V6(v4, v6)	((v6).s6_addr32[0] = 0xffffffffUL,	\
				(v6).s6_addr32[1] = 0xffffffffUL,	\
				(v6).s6_addr32[2] = 0xffffffffUL,	\
				(v6).s6_addr32[3] = (v4))

/*
 * Convert aligned IPv4-mapped IPv6 address into an IPv4 address.
 * Note: We use "v6" here in definition of macro instead of "(v6)"
 * Not possible to use "(v6)" here since macro is used with struct
 * field names as arguments.
 */
#define	V4_PART_OF_V6(v6)	v6.s6_addr32[3]

#ifdef _BIG_ENDIAN
#define	V6_OR_V4_INADDR_ANY(a)	((a).s6_addr32[3] == 0 &&		\
				((a).s6_addr32[2] == 0xffffU ||	\
				(a).s6_addr32[2] == 0) &&		\
				(a).s6_addr32[1] == 0 &&		\
				(a).s6_addr32[0] == 0)

#else
#define	V6_OR_V4_INADDR_ANY(a)	((a).s6_addr32[3] == 0 && 		\
				((a).s6_addr32[2] == 0xffff0000U ||	\
				(a).s6_addr32[2] == 0) &&		\
				(a).s6_addr32[1] == 0 &&		\
				(a).s6_addr32[0] == 0)
#endif /* _BIG_ENDIAN */

/* IPv4-mapped CLASSD addresses */
#ifdef _BIG_ENDIAN
#define	IN6_IS_ADDR_V4MAPPED_CLASSD(addr) \
	(((addr)->_S6_un._S6_u32[2] == 0x0000ffff) && \
	(CLASSD((addr)->_S6_un._S6_u32[3])) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#else  /* _BIG_ENDIAN */
#define	IN6_IS_ADDR_V4MAPPED_CLASSD(addr) \
	(((addr)->_S6_un._S6_u32[2] == 0xffff0000U) && \
	(CLASSD((addr)->_S6_un._S6_u32[3])) && \
	((addr)->_S6_un._S6_u32[1] == 0) && \
	((addr)->_S6_un._S6_u32[0] == 0))
#endif /* _BIG_ENDIAN */

/* Clear an IPv6 addr */
#define	V6_SET_ZERO(a)		((a).s6_addr32[0] = 0,			\
				(a).s6_addr32[1] = 0,			\
				(a).s6_addr32[2] = 0,			\
				(a).s6_addr32[3] = 0)

/* Mask comparison: is IPv6 addr a, and'ed with mask m, equal to addr b? */
#define	V6_MASK_EQ(a, m, b)						\
	((((a).s6_addr32[0] & (m).s6_addr32[0]) == (b).s6_addr32[0]) &&	\
	(((a).s6_addr32[1] & (m).s6_addr32[1]) == (b).s6_addr32[1]) &&	\
	(((a).s6_addr32[2] & (m).s6_addr32[2]) == (b).s6_addr32[2]) &&	\
	(((a).s6_addr32[3] & (m).s6_addr32[3]) == (b).s6_addr32[3]))

#define	V6_MASK_EQ_2(a, m, b)						\
	((((a).s6_addr32[0] & (m).s6_addr32[0]) ==			\
	    ((b).s6_addr32[0]  & (m).s6_addr32[0])) &&			\
	(((a).s6_addr32[1] & (m).s6_addr32[1]) ==			\
	    ((b).s6_addr32[1]  & (m).s6_addr32[1])) &&			\
	(((a).s6_addr32[2] & (m).s6_addr32[2]) ==			\
	    ((b).s6_addr32[2]  & (m).s6_addr32[2])) &&			\
	(((a).s6_addr32[3] & (m).s6_addr32[3]) ==			\
	    ((b).s6_addr32[3]  & (m).s6_addr32[3])))

/* Copy IPv6 address (s), logically and'ed with mask (m), into (d) */
#define	V6_MASK_COPY(s, m, d)						\
	((d).s6_addr32[0] = (s).s6_addr32[0] & (m).s6_addr32[0],	\
	(d).s6_addr32[1] = (s).s6_addr32[1] & (m).s6_addr32[1],		\
	(d).s6_addr32[2] = (s).s6_addr32[2] & (m).s6_addr32[2],		\
	(d).s6_addr32[3] = (s).s6_addr32[3] & (m).s6_addr32[3])

#define	ILL_FRAG_HASH_V6(v6addr, i)					\
	((ntohl((v6addr).s6_addr32[3]) ^ (i ^ (i >> 8))) % 		\
						ILL_FRAG_HASH_TBL_COUNT)


/*
 * GLOBAL EXTERNALS
 */
extern const in6_addr_t	ipv6_all_ones;
extern const in6_addr_t	ipv6_all_zeros;
extern const in6_addr_t	ipv6_loopback;
extern const in6_addr_t	ipv6_all_hosts_mcast;
extern const in6_addr_t	ipv6_all_rtrs_mcast;
extern const in6_addr_t	ipv6_all_v2rtrs_mcast;
extern const in6_addr_t	ipv6_solicited_node_mcast;
extern const in6_addr_t	ipv6_unspecified_group;

/*
 * FUNCTION PROTOTYPES
 */

struct ipsec_out_s;

extern void	convert2ascii(char *buf, const in6_addr_t *addr);
extern char	*inet_ntop(int, const void *, char *, int);
extern int	inet_pton(int, char *, void *);
extern void	icmp_time_exceeded_v6(queue_t *, mblk_t *, uint8_t,
    boolean_t, boolean_t, zoneid_t, ip_stack_t *);
extern void	icmp_unreachable_v6(queue_t *, mblk_t *, uint8_t,
    boolean_t, boolean_t, zoneid_t, ip_stack_t *);
extern void	icmp_inbound_error_fanout_v6(queue_t *, mblk_t *, ip6_t *,
    icmp6_t *, ill_t *, ill_t *, boolean_t, zoneid_t);
extern boolean_t conn_wantpacket_v6(conn_t *, ill_t *, ip6_t *, int, zoneid_t);
extern mblk_t	*ip_add_info_v6(mblk_t *, ill_t *, const in6_addr_t *);
extern in6addr_scope_t	ip_addr_scope_v6(const in6_addr_t *);
extern mblk_t	*ip_bind_v6(queue_t *, mblk_t *, conn_t *, ip6_pkt_t *);
extern void	ip_build_hdrs_v6(uchar_t *, uint_t, ip6_pkt_t *, uint8_t);
extern int	ip_fanout_send_icmp_v6(queue_t *, mblk_t *, uint_t,
    uint_t, uint8_t, uint_t, boolean_t, zoneid_t, ip_stack_t *);
extern int	ip_find_hdr_v6(mblk_t *, ip6_t *, ip6_pkt_t *, uint8_t *);
extern in6_addr_t ip_get_dst_v6(ip6_t *, mblk_t *, boolean_t *);
extern ip6_rthdr_t	*ip_find_rthdr_v6(ip6_t *, uint8_t *);
extern int	ip_hdr_complete_v6(ip6_t *, zoneid_t, ip_stack_t *);
extern boolean_t	ip_hdr_length_nexthdr_v6(mblk_t *, ip6_t *,
    uint16_t *, uint8_t **);
extern int	ip_hdr_length_v6(mblk_t *, ip6_t *);
extern int	ip_check_v6_mblk(mblk_t *, ill_t *);
extern uint32_t	ip_massage_options_v6(ip6_t *, ip6_rthdr_t *, netstack_t *);
extern void	ip_wput_frag_v6(mblk_t *, ire_t *, uint_t, conn_t *, int, int);
extern void 	ip_wput_ipsec_out_v6(queue_t *, mblk_t *, ip6_t *, ill_t *,
    ire_t *);
extern int	ip_total_hdrs_len_v6(ip6_pkt_t *);
extern int	ipsec_ah_get_hdr_size_v6(mblk_t *, boolean_t);
extern void	ip_wput_v6(queue_t *, mblk_t *);
extern void	ip_wput_local_v6(queue_t *, ill_t *, ip6_t *, mblk_t *,
    ire_t *, int, zoneid_t);
extern void	ip_output_v6(void *, mblk_t *, void *, int);
extern void	ip_xmit_v6(mblk_t *, ire_t *, uint_t, conn_t *, int,
    struct ipsec_out_s *);
extern void	ip_rput_v6(queue_t *, mblk_t *);
extern void	ip_rput_data_v6(queue_t *, ill_t *, mblk_t *, ip6_t *,
    uint_t, mblk_t *, mblk_t *);
extern void	mld_input(queue_t *, mblk_t *, ill_t *);
extern void	mld_joingroup(ilm_t *);
extern void	mld_leavegroup(ilm_t *);
extern void	mld_timeout_handler(void *);

extern void	pr_addr_dbg(char *, int, const void *);
extern int	ip_multirt_apply_membership_v6(int (*fn)(conn_t *, boolean_t,
    const in6_addr_t *, int, mcast_record_t, const in6_addr_t *, mblk_t *),
    ire_t *, conn_t *, boolean_t, const in6_addr_t *, mcast_record_t,
    const in6_addr_t *, mblk_t *);
extern void	ip_newroute_ipif_v6(queue_t *, mblk_t *, ipif_t *,
    const in6_addr_t *, const in6_addr_t *, int, zoneid_t);
extern void	ip_newroute_v6(queue_t *, mblk_t *, const in6_addr_t *,
    const in6_addr_t *, ill_t *, zoneid_t, ip_stack_t *);
extern void	*ip6_kstat_init(netstackid_t, ip6_stat_t *);
extern void	ip6_kstat_fini(netstackid_t, kstat_t *);
extern size_t	ip6_get_src_preferences(conn_t *, uint32_t *);
extern int	ip6_set_src_preferences(conn_t *, uint32_t);
extern int	ip6_set_pktinfo(cred_t *, conn_t *, struct in6_pktinfo *);
extern int	ip_proto_bind_laddr_v6(conn_t *, mblk_t **, uint8_t,
    const in6_addr_t *, uint16_t, boolean_t);
extern int	ip_proto_bind_connected_v6(conn_t *, mblk_t **,
    uint8_t, in6_addr_t *, uint16_t, const in6_addr_t *, ip6_pkt_t *,
    uint16_t, boolean_t, boolean_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP6_H */
