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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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

/* From RFC 3542 - setting for IPV6_USE_MIN_MTU socket option */
#define	IPV6_USE_MIN_MTU_MULTICAST	-1	/* Default */
#define	IPV6_USE_MIN_MTU_NEVER		0
#define	IPV6_USE_MIN_MTU_ALWAYS		1

#ifdef	_KERNEL

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

#ifdef _BIG_ENDIAN
#define	IPV6_DEFAULT_VERS_AND_FLOW	0x60000000
#define	IPV6_VERS_AND_FLOW_MASK		0xF0000000
#define	V6_MCAST			0xFF000000
#define	V6_LINKLOCAL			0xFE800000

#define	IPV6_FLOW_TCLASS(x)		(((x) & IPV6_FLOWINFO_TCLASS) >> 20)
#define	IPV6_TCLASS_FLOW(f, c)		(((f) & ~IPV6_FLOWINFO_TCLASS) |\
					((c) << 20))
#else
#define	IPV6_DEFAULT_VERS_AND_FLOW	0x00000060
#define	IPV6_VERS_AND_FLOW_MASK		0x000000F0
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
extern void	icmp_param_problem_nexthdr_v6(mblk_t *, boolean_t,
    ip_recv_attr_t *);
extern void	icmp_pkt2big_v6(mblk_t *, uint32_t, boolean_t,
    ip_recv_attr_t *);
extern void	icmp_time_exceeded_v6(mblk_t *, uint8_t, boolean_t,
    ip_recv_attr_t *);
extern void	icmp_unreachable_v6(mblk_t *, uint8_t, boolean_t,
    ip_recv_attr_t *);
extern mblk_t	*icmp_inbound_v6(mblk_t *, ip_recv_attr_t *);
extern void	icmp_inbound_error_fanout_v6(mblk_t *, icmp6_t *,
    ip_recv_attr_t *);
extern void	icmp_update_out_mib_v6(ill_t *, icmp6_t *);

extern boolean_t conn_wantpacket_v6(conn_t *, ip_recv_attr_t *, ip6_t *);

extern in6addr_scope_t	ip_addr_scope_v6(const in6_addr_t *);
extern void	ip_build_hdrs_v6(uchar_t *, uint_t, const ip_pkt_t *, uint8_t,
    uint32_t);
extern void	ip_fanout_udp_multi_v6(mblk_t *, ip6_t *, uint16_t, uint16_t,
    ip_recv_attr_t *);
extern void	ip_fanout_send_icmp_v6(mblk_t *, uint_t, uint8_t,
    ip_recv_attr_t *);
extern void	ip_fanout_proto_v6(mblk_t *, ip6_t *, ip_recv_attr_t *);
extern int	ip_find_hdr_v6(mblk_t *, ip6_t *, boolean_t, ip_pkt_t *,
    uint8_t *);
extern in6_addr_t ip_get_dst_v6(ip6_t *, const mblk_t *, boolean_t *);
extern ip6_rthdr_t	*ip_find_rthdr_v6(ip6_t *, uint8_t *);
extern boolean_t	ip_hdr_length_nexthdr_v6(mblk_t *, ip6_t *,
    uint16_t *, uint8_t **);
extern int	ip_hdr_length_v6(mblk_t *, ip6_t *);
extern uint32_t	ip_massage_options_v6(ip6_t *, ip6_rthdr_t *, netstack_t *);
extern void	ip_forward_xmit_v6(nce_t *, mblk_t *, ip6_t *, ip_recv_attr_t *,
    uint32_t, uint32_t);
extern mblk_t	*ip_fraghdr_add_v6(mblk_t *, uint32_t, ip_xmit_attr_t *);
extern int	ip_fragment_v6(mblk_t *, nce_t *, iaflags_t, uint_t, uint32_t,
    uint32_t, zoneid_t, zoneid_t, pfirepostfrag_t postfragfn,
    uintptr_t *ixa_cookie);
extern int	ip_process_options_v6(mblk_t *, ip6_t *,
    uint8_t *, uint_t, uint8_t, ip_recv_attr_t *);
extern void	ip_process_rthdr(mblk_t *, ip6_t *, ip6_rthdr_t *,
    ip_recv_attr_t *);
extern int	ip_total_hdrs_len_v6(const ip_pkt_t *);
extern mblk_t	*ipsec_early_ah_v6(mblk_t *, ip_recv_attr_t *);
extern int	ipsec_ah_get_hdr_size_v6(mblk_t *, boolean_t);
extern void	ip_send_potential_redirect_v6(mblk_t *, ip6_t *, ire_t *,
    ip_recv_attr_t *);
extern void	ip_rput_v6(queue_t *, mblk_t *);
extern mblk_t	*mld_input(mblk_t *, ip_recv_attr_t *);
extern void	mld_joingroup(ilm_t *);
extern void	mld_leavegroup(ilm_t *);
extern void	mld_timeout_handler(void *);

extern void	pr_addr_dbg(char *, int, const void *);
extern void	*ip6_kstat_init(netstackid_t, ip6_stat_t *);
extern void	ip6_kstat_fini(netstackid_t, kstat_t *);
extern size_t	ip6_get_src_preferences(ip_xmit_attr_t *, uint32_t *);
extern int	ip6_set_src_preferences(ip_xmit_attr_t *, uint32_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP6_H */
