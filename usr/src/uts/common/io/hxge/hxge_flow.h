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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HXGE_HXGE_FLOW_H
#define	_SYS_HXGE_HXGE_FLOW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#define	 S6_addr32		_S6_un._S6_u32

typedef struct tcpip4_spec_s {
	in_addr_t  ip4src;
	in_addr_t  ip4dst;
	in_port_t  psrc;
	in_port_t  pdst;
} tcpip4_spec_t;

typedef struct tcpip6_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	in_port_t  psrc;
	in_port_t  pdst;
} tcpip6_spec_t;

typedef struct udpip4_spec_s {
	in_addr_t  ip4src;
	in_addr_t  ip4dst;
	in_port_t  psrc;
	in_port_t  pdst;
} udpip4_spec_t;

typedef struct udpip6_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	in_port_t  psrc;
	in_port_t  pdst;
} udpip6_spec_t;

typedef struct ahip4_spec_s {
	in_addr_t  ip4src;
	in_addr_t  ip4dst;
	uint32_t   spi;
} ahip4_spec_t;

typedef struct ahip6_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	uint32_t   spi;
} ahip6_spec_t;

typedef ahip4_spec_t espip4_spec_t;
typedef ahip6_spec_t espip6_spec_t;

typedef struct rawip4_spec_s {
	struct in6_addr ip4src;
	struct in6_addr ip4dst;
	uint8_t    hdata[64];
} rawip4_spec_t;

typedef struct rawip6_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	uint8_t    hdata[64];
} rawip6_spec_t;


typedef struct ether_spec_s {
	uint16_t   ether_type;
	uint8_t    frame_size;
	uint8_t    eframe[16];
} ether_spec_t;


typedef struct ip_user_spec_s {
	uint8_t    id;
	uint8_t    ip_ver;
	uint8_t    proto;
	uint8_t    tos_mask;
	uint8_t    tos;
} ip_user_spec_t;

typedef ether_spec_t arpip_spec_t;
typedef ether_spec_t ether_user_spec_t;

typedef struct flow_spec_s {
	uint32_t  flow_type;
	union {
		tcpip4_spec_t tcpip4spec;
		tcpip6_spec_t tcpip6spec;
		udpip4_spec_t udpip4spec;
		udpip6_spec_t udpip6spec;
		arpip_spec_t  arpipspec;
		ahip4_spec_t  ahip4spec;
		ahip6_spec_t  ahip6spec;
		espip4_spec_t espip4spec;
		espip6_spec_t espip6spec;
		rawip4_spec_t rawip4spec;
		rawip6_spec_t rawip6spec;
		ether_spec_t  etherspec;
		ip_user_spec_t  ip_usr_spec;
		uint8_t		hdata[64];
	} uh, um; /* entry, mask */
} flow_spec_t;

#define	FSPEC_TCPIP4	0x1	/* TCP/IPv4 Flow */
#define	FSPEC_TCPIP6	0x2	/* TCP/IPv6 */
#define	FSPEC_UDPIP4	0x3	/* UDP/IPv4 */
#define	FSPEC_UDPIP6	0x4	/* UDP/IPv6 */
#define	FSPEC_ARPIP	0x5	/* ARP/IPv4 */
#define	FSPEC_AHIP4	0x6	/* AH/IP4   */
#define	FSPEC_AHIP6	0x7	/* AH/IP6   */
#define	FSPEC_ESPIP4	0x8	/* ESP/IP4  */
#define	FSPEC_ESPIP6	0x9	/* ESP/IP6  */
#define	FSPEC_SCTPIP4	0xA	/* ESP/IP4  */
#define	FSPEC_SCTPIP6	0xB	/* ESP/IP6  */
#define	FSPEC_RAW4	0xC	/* RAW/IP4  */
#define	FSPEC_RAW6	0xD	/* RAW/IP6  */
#define	FSPEC_ETHER	0xE	/* ETHER Programmable  */
#define	FSPEC_IP_USR	0xF	/* IP Programmable  */
#define	FSPEC_HDATA	0x10	/* Pkt Headers eth-da,sa,etype,ip,tcp(Bitmap) */


#define	TCAM_IPV6_ADDR(m32, ip6addr) {		\
		m32[0] = ip6addr.S6_addr32[0]; \
		m32[1] = ip6addr.S6_addr32[1]; \
		m32[2] = ip6addr.S6_addr32[2]; \
		m32[3] = ip6addr.S6_addr32[3]; \
	}


#define	TCAM_IPV4_ADDR(m32, ip4addr) (m32 = ip4addr)
#define	TCAM_IP_PORTS(port32, dp, sp)	  (port32 = dp | (sp << 16))
#define	TCAM_IP_CLASS(key, mask, class)	  {		\
		key = class; \
		mask = 0x1f; \
	}

#define	TCAM_IP_PROTO(key, mask, proto) {		\
		key = proto; \
		mask = 0xff; \
	}


typedef struct flow_resource_s {
	uint64_t	channel_cookie;
	uint64_t	flow_cookie;
	uint8_t		tcam_location;
	flow_spec_t	flow_spec;
} flow_resource_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_FLOW_H */
