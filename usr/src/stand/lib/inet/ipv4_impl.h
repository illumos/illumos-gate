/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Internal IPv4 implementation-specific definitions
 */

#ifndef _IPV4_IMPL_H
#define	_IPV4_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	FRAG_MAX	(40)	/* max number of IP fragments per datagram */
#define	FRAG_SUCCESS	(0)	/* datagram reassembled ok */
#define	FRAG_DUP	(1)	/* duplicate ip fragment */
#define	FRAG_NOSLOTS	(2)	/* no more ip fragment slots */
#define	FRAG_ATTEMPTS	1	/* Try twice to get all the fragments */

/*
 * IP fragmentation data structure
 */
struct ip_frag {
	int16_t		more;	/* Fragment bit (TRUE == MF, FALSE == No more */
	int16_t		offset;	/* Offset within the encapsulated datagram */
	mblk_t		*mp;	/* Fragment including IP header */
	uint16_t	ipid;	/* fragment ident */
	int16_t		iplen;	/* IP datagram's length */
	int16_t		iphlen;	/* Len of IP header */
	uint8_t		ipp;	/* IP protocol */
};

/*
 * true offset is in 8 octet units. The high order 3 bits of the IP header
 * offset field are therefore used for fragmentation flags. Shift these
 * bits off to produce the true offset. The high order flag bit is unused
 * (what would be considered the sign bit). Still, we cast the callers
 * value as an unsigned quantity to ensure it is treated as positive.
 */
#define	IPV4_OFFSET(a)	((uint16_t)(a) << 3)

#define	IPV4_VERSION	4
#define	IPH_HDR_LENGTH(iph)	(((struct ip *)(iph))->ip_hl << 2)

/* ECN code points for IPv4 TOS byte and IPv6 traffic class octet. */
#define	IPH_ECN_NECT	0x0	/* Not ECN-Capabable Transport */
#define	IPH_ECN_ECT1	0x1	/* ECN-Capable Transport, ECT(1) */
#define	IPH_ECN_ECT0	0x2	/* ECN-Capable Transport, ECT(0) */
#define	IPH_ECN_CE	0x3	/* ECN-Congestion Experienced (CE) */

#define	IPV4_VERSION			4
#define	IP_VERSION			IPV4_VERSION
#define	IP_SIMPLE_HDR_LENGTH_IN_WORDS	5
#define	IP_SIMPLE_HDR_LENGTH		20
#define	IP_MAX_HDR_LENGTH		60

#define	IP_MIN_MTU			(IP_MAX_HDR_LENGTH + 8)	/* 68 bytes */

/*
 * IP routing table. IP addresses are in network-order.
 */
struct routing {
	struct in_addr	dest;
	struct in_addr	gateway;
	uint8_t		flag;
};

extern void		ipv4_raw_socket(struct inetboot_socket *, uint8_t);
extern void		ipv4_socket_init(struct inetboot_socket *);
extern int		ipv4_header_len(struct inetgram *);
extern int		ipv4_input(int);
extern int		ipv4_output(int, struct inetgram *);
extern int		ipv4_tcp_output(int, mblk_t *);
extern struct in_addr	*ipv4_get_route(uint8_t, struct in_addr *,
			    struct in_addr *);

#ifdef	__cplusplus
}
#endif

#endif /* _IPV4_IMPL_H */
