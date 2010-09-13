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

#ifndef	_INET_IP_IMPL_H
#define	_INET_IP_IMPL_H

/*
 * IP implementation private declarations.  These interfaces are
 * used to build the IP module and are not meant to be accessed
 * by any modules except IP itself.  They are undocumented and are
 * subject to change without notice.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/sdt.h>
#include <sys/dld.h>
#include <inet/tunables.h>

#define	IP_MOD_ID		5701

#define	INET_NAME	"ip"

#ifdef	_BIG_ENDIAN
#define	IP_HDR_CSUM_TTL_ADJUST	256
#define	IP_TCP_CSUM_COMP	IPPROTO_TCP
#define	IP_UDP_CSUM_COMP	IPPROTO_UDP
#define	IP_ICMPV6_CSUM_COMP	IPPROTO_ICMPV6
#else
#define	IP_HDR_CSUM_TTL_ADJUST	1
#define	IP_TCP_CSUM_COMP	(IPPROTO_TCP << 8)
#define	IP_UDP_CSUM_COMP	(IPPROTO_UDP << 8)
#define	IP_ICMPV6_CSUM_COMP	(IPPROTO_ICMPV6 << 8)
#endif

#define	TCP_CHECKSUM_OFFSET	16
#define	TCP_CHECKSUM_SIZE	2

#define	UDP_CHECKSUM_OFFSET	6
#define	UDP_CHECKSUM_SIZE	2

#define	ICMPV6_CHECKSUM_OFFSET	2
#define	ICMPV6_CHECKSUM_SIZE	2

#define	IPH_TCPH_CHECKSUMP(ipha, hlen)	\
	((uint16_t *)(((uchar_t *)(ipha)) + ((hlen) + TCP_CHECKSUM_OFFSET)))

#define	IPH_UDPH_CHECKSUMP(ipha, hlen)	\
	((uint16_t *)(((uchar_t *)(ipha)) + ((hlen) + UDP_CHECKSUM_OFFSET)))

#define	IPH_ICMPV6_CHECKSUMP(ipha, hlen)	\
	((uint16_t *)(((uchar_t *)(ipha)) + ((hlen) + ICMPV6_CHECKSUM_OFFSET)))

#define	ILL_HCKSUM_CAPABLE(ill)		\
	(((ill)->ill_capabilities & ILL_CAPAB_HCKSUM) != 0)

/*
 * Macro to adjust a given checksum value depending on any prepended
 * or postpended data on the packet.  It expects the start offset to
 * begin at an even boundary and that the packet consists of at most
 * two mblks.
 */
#define	IP_ADJCKSUM_PARTIAL(cksum_start, mp, mp1, len, adj) {		\
	/*								\
	 * Prepended extraneous data; adjust checksum.			\
	 */								\
	if ((len) > 0)							\
		(adj) = IP_BCSUM_PARTIAL(cksum_start, len, 0);		\
	else								\
		(adj) = 0;						\
	/*								\
	 * len is now the total length of mblk(s)			\
	 */								\
	(len) = MBLKL(mp);						\
	if ((mp1) == NULL)						\
		(mp1) = (mp);						\
	else								\
		(len) += MBLKL(mp1);					\
	/*								\
	 * Postpended extraneous data; adjust checksum.			\
	 */								\
	if (((len) = (DB_CKSUMEND(mp) - len)) > 0) {			\
		uint32_t _pad;						\
									\
		_pad = IP_BCSUM_PARTIAL((mp1)->b_wptr, len, 0);		\
		/*							\
		 * If the postpended extraneous data was odd		\
		 * byte aligned, swap resulting checksum bytes.		\
		 */							\
		if ((uintptr_t)(mp1)->b_wptr & 1)			\
			(adj) += ((_pad << 8) & 0xFFFF) | (_pad >> 8);	\
		else							\
			(adj) += _pad;					\
		(adj) = ((adj) & 0xFFFF) + ((int)(adj) >> 16);		\
	}								\
}

#define	IS_SIMPLE_IPH(ipha)						\
	((ipha)->ipha_version_and_hdr_length == IP_SIMPLE_HDR_VERSION)

/*
 * Currently supported flags for LSO.
 */
#define	LSO_BASIC_TCP_IPV4	DLD_LSO_BASIC_TCP_IPV4
#define	LSO_BASIC_TCP_IPV6	DLD_LSO_BASIC_TCP_IPV6

#define	ILL_LSO_CAPABLE(ill)						\
	(((ill)->ill_capabilities & ILL_CAPAB_LSO) != 0)

#define	ILL_LSO_USABLE(ill)						\
	(ILL_LSO_CAPABLE(ill) &&					\
	ill->ill_lso_capab != NULL)

#define	ILL_LSO_TCP_IPV4_USABLE(ill)					\
	(ILL_LSO_USABLE(ill) &&						\
	ill->ill_lso_capab->ill_lso_flags & LSO_BASIC_TCP_IPV4)

#define	ILL_LSO_TCP_IPV6_USABLE(ill)					\
	(ILL_LSO_USABLE(ill) &&						\
	ill->ill_lso_capab->ill_lso_flags & LSO_BASIC_TCP_IPV6)

#define	ILL_ZCOPY_CAPABLE(ill)						\
	(((ill)->ill_capabilities & ILL_CAPAB_ZEROCOPY) != 0)

#define	ILL_ZCOPY_USABLE(ill)						\
	(ILL_ZCOPY_CAPABLE(ill) && (ill->ill_zerocopy_capab != NULL) &&	\
	(ill->ill_zerocopy_capab->ill_zerocopy_flags != 0))


/* Macro that follows definitions of flags for mac_tx() (see mac_client.h) */
#define	IP_DROP_ON_NO_DESC	0x01	/* Equivalent to MAC_DROP_ON_NO_DESC */

#define	ILL_DIRECT_CAPABLE(ill)						\
	(((ill)->ill_capabilities & ILL_CAPAB_DLD_DIRECT) != 0)

/* This macro is used by the mac layer */
#define	MBLK_RX_FANOUT_SLOWPATH(mp, ipha)				\
	(DB_TYPE(mp) != M_DATA || DB_REF(mp) != 1 || !OK_32PTR(ipha) || \
	(((uchar_t *)ipha + IP_SIMPLE_HDR_LENGTH) >= (mp)->b_wptr))

/*
 * In non-global zone exclusive IP stacks, data structures such as IRE
 * entries pretend that they're in the global zone.  The following
 * macro evaluates to the real zoneid instead of a pretend
 * GLOBAL_ZONEID.
 */
#define	IP_REAL_ZONEID(zoneid, ipst)					\
	(((zoneid) == GLOBAL_ZONEID) ?					\
	    netstackid_to_zoneid((ipst)->ips_netstack->netstack_stackid) : \
	    (zoneid))

extern void ill_flow_enable(void *, ip_mac_tx_cookie_t);
extern zoneid_t	ip_get_zoneid_v4(ipaddr_t, mblk_t *, ip_recv_attr_t *,
    zoneid_t);
extern zoneid_t	ip_get_zoneid_v6(in6_addr_t *, mblk_t *, const ill_t *,
    ip_recv_attr_t *, zoneid_t);
extern void conn_ire_revalidate(conn_t *, void *);
extern void ip_ire_unbind_walker(ire_t *, void *);
extern void ip_ire_rebind_walker(ire_t *, void *);

/*
 * flag passed in by IP based protocols to get a private ip stream with
 * no conn_t. Note this flag has the same value as SO_FALLBACK
 */
#define	IP_HELPER_STR	SO_FALLBACK

#define	IP_MOD_MINPSZ	1
#define	IP_MOD_MAXPSZ	INFPSZ
#define	IP_MOD_HIWAT	65536
#define	IP_MOD_LOWAT	1024

#define	DEV_IP	"/devices/pseudo/ip@0:ip"
#define	DEV_IP6	"/devices/pseudo/ip6@0:ip6"

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_IMPL_H */
