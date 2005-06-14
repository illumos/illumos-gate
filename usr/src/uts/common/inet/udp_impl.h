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
 */

#ifndef	_UDP_IMPL_H
#define	_UDP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/int_types.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>

/* Internal udp control structure, one per open stream */
typedef	struct udp_s {
	uint32_t 	udp_state;	/* TPI state */
	in_port_t 	udp_port;	/* Port bound to this stream */
	in_port_t 	udp_dstport;	/* Connected port */
	in6_addr_t 	udp_v6src;	/* Source address of this stream */
	in6_addr_t 	udp_bound_v6src; /* Explicitly bound address */
	in6_addr_t 	udp_v6dst;	/* Connected destination */
	uint32_t	udp_flowinfo;	/* Connected flow id and tclass */
	uint32_t 	udp_max_hdr_len; /* For write offset in stream head */
	sa_family_t	udp_family;	/* Family from socket() call */
	/*
	 * IP format that packets transmitted from this struct should use.
	 * Value can be IP4_VERSION or IPV6_VERSION.
	 */
	ushort_t	udp_ipversion;
	uint32_t 	udp_ip_snd_options_len; /* Len of IPv4 options */
	uchar_t		*udp_ip_snd_options;    /* Ptr to IPv4 options */
	uint32_t 	udp_ip_rcv_options_len; /* Len of IPv4 options recvd */
	uchar_t		*udp_ip_rcv_options;    /* Ptr to IPv4 options recvd */
	cred_t		*udp_credp;		/* Credentials at open */
	uchar_t		udp_multicast_ttl;	/* IP*_MULTICAST_TTL/HOPS */
	ipaddr_t 	udp_multicast_if_addr;  /* IP_MULTICAST_IF option */
	uint_t		udp_multicast_if_index;	/* IPV6_MULTICAST_IF option */
	int		udp_bound_if;		/* IP*_BOUND_IF option */
	int		udp_xmit_if;		/* IP_XMIT_IF option */
	uint32_t
		udp_debug : 1,		/* SO_DEBUG "socket" option. */
		udp_dontroute : 1,	/* SO_DONTROUTE "socket" option. */
		udp_broadcast : 1,	/* SO_BROADCAST "socket" option. */
		udp_useloopback : 1,	/* SO_USELOOPBACK "socket" option */

		udp_reuseaddr : 1,	/* SO_REUSEADDR "socket" option. */
		udp_multicast_loop : 1,	/* IP_MULTICAST_LOOP option */
		udp_dgram_errind : 1,	/* SO_DGRAM_ERRIND option */
		udp_recvdstaddr : 1,	/* IP_RECVDSTADDR option */

		udp_recvopts : 1,	/* IP_RECVOPTS option */
		udp_discon_pending : 1,	/* T_DISCON_REQ in progress */
		udp_unspec_source : 1,	/* IP*_UNSPEC_SRC option */
		udp_ipv6_recvpktinfo : 1,	/* IPV6_RECVPKTINFO option  */

		udp_ipv6_recvhoplimit : 1,	/* IPV6_RECVHOPLIMIT option */
		udp_ipv6_recvhopopts : 1,	/* IPV6_RECVHOPOPTS option */
		udp_ipv6_recvdstopts : 1,	/* IPV6_RECVDSTOPTS option */
		udp_ipv6_recvrthdr : 1,		/* IPV6_RECVRTHDR option */

		udp_ipv6_recvtclass : 1,	/* IPV6_RECVTCLASS */
		udp_ipv6_recvpathmtu : 1,	/* IPV6_RECVPATHMTU */
		udp_anon_priv_bind : 1,
		udp_exclbind : 1,	/* ``exclusive'' binding */

		udp_recvif : 1,		/* IP_RECVIF option */
		udp_recvslla : 1,	/* IP_RECVSLLA option */
		udp_recvttl : 1,	/* IP_RECVTTL option */
		udp_recvucred : 1,	/* IP_RECVUCRED option */

		udp_old_ipv6_recvdstopts : 1,	/* old form of IPV6_DSTOPTS */
		udp_ipv6_recvrthdrdstopts : 1,	/* IPV6_RECVRTHDRDSTOPTS */

		udp_rcvhdr : 1,		/* UDP_RCVHDR option */
		udp_pad_to_bit_31 : 7;

	uint8_t		udp_type_of_service;	/* IP_TOS option */
	uint8_t		udp_ttl;		/* TTL or hoplimit */

	ip6_pkt_t	udp_sticky_ipp;		/* Sticky options */
	uint8_t		*udp_sticky_hdrs;	/* Prebuilt IPv6 hdrs */
	uint_t		udp_sticky_hdrs_len;	/* Incl. ip6h and any ip6i */
	struct udp_s	*udp_bind_hash; /* Bind hash chain */
	struct udp_s	**udp_ptpbhn; /* Pointer to previous bind hash next. */
	zoneid_t	udp_zoneid;	/* ID of owning zone */
} udp_t;

/* UDP Protocol header */
/* UDP Protocol header aligned */
typedef	struct udpahdr_s {
	in_port_t	uha_src_port;		/* Source port */
	in_port_t	uha_dst_port;		/* Destination port */
	uint16_t	uha_length;		/* UDP length */
	uint16_t	uha_checksum;		/* UDP checksum */
} udpha_t;
#define	UDPH_SIZE	8

#endif	/*  _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _UDP_IMPL_H */
