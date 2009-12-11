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

#ifndef	_SYS_NXGE_NXGE_FLOW_H
#define	_SYS_NXGE_NXGE_FLOW_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#define	S6_addr32	_S6_un._S6_u32

typedef struct tcpip4_spec_s {
	in_addr_t  ip4src;
	in_addr_t  ip4dst;
	in_port_t  psrc;
	in_port_t  pdst;
	uint8_t	   tos;
} tcpip4_spec_t;

typedef struct tcpip6_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	in_port_t  psrc;
	in_port_t  pdst;
	uint8_t	   tos;
} tcpip6_spec_t;

typedef struct udpip4_spec_s {
	in_addr_t  ip4src;
	in_addr_t  ip4dst;
	in_port_t  psrc;
	in_port_t  pdst;
	uint8_t	   tos;
} udpip4_spec_t;

typedef struct udpip6_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	in_port_t  psrc;
	in_port_t  pdst;
	uint8_t	   tos;
} udpip6_spec_t;

typedef struct ahip4_spec_s {
	in_addr_t  ip4src;
	in_addr_t  ip4dst;
	uint32_t   spi;
	uint8_t	   tos;
} ahip4_spec_t;

typedef struct ahip6_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	uint32_t   spi;
	uint8_t	   tos;
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


#define	FSPEC_IP4	1
#define	FSPEC_IP6	2

typedef struct ip_user_spec_s {
	uint32_t	ip4src;
	uint32_t	ip4dst;
	uint32_t	l4_4_bytes;
	uint8_t    	tos;
	uint8_t    	ip_ver;
	uint8_t    	proto;
} ip_user_spec_t;

typedef struct ip6_frag_spec_s {
	struct in6_addr ip6src;
	struct in6_addr ip6dst;
	uint32_t	l4_4_bytes;
	uint8_t    	tos;
	uint8_t    	proto;	/* should be 44 */
} ip6_frag_spec_t;


typedef ether_spec_t arpip_spec_t;
typedef ether_spec_t ether_user_spec_t;

struct flow_spec_s {
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
		ip6_frag_spec_t  ip6_frag_spec;
		uint8_t		hdata[64];
	} uh, um; /* entry, mask */
} __attribute__((packed));

typedef struct flow_spec_s flow_spec_t;

#define	FSPEC_TCPIP4	0x1	/* TCP/IPv4 Flow */
#define	FSPEC_TCPIP6	0x2	/* TCP/IPv6 */
#define	FSPEC_UDPIP4	0x3	/* UDP/IPv4 */
#define	FSPEC_UDPIP6	0x4	/* UDP/IPv6 */
#define	FSPEC_ARPIP	0x5	/* ARP/IPv4 */
#define	FSPEC_AHIP4	0x6	/* AH/IP4   */
#define	FSPEC_AHIP6	0x7	/* AH/IP6   */
#define	FSPEC_ESPIP4	0x8	/* ESP/IP4  */
#define	FSPEC_ESPIP6	0x9	/* ESP/IP6  */
#define	FSPEC_SCTPIP4	0xA	/* SCTP/IP4  */
#define	FSPEC_SCTPIP6	0xB	/* SCTP/IP6  */
#define	FSPEC_IP6FRAG	0xC	/* IPv6 Fragments */
#define	FSPEC_RAW4	0xD	/* RAW/IP4  */
#define	FSPEC_RAW6	0xE	/* RAW/IP6  */
#define	FSPEC_ETHER	0xF	/* ETHER Programmable  */
#define	FSPEC_IP_USR	0x10	/* IP Programmable  */
#define	FSPEC_HDATA	0x11	/* Pkt Headers eth-da,sa,etype,ip,tcp(Bitmap) */

#define	TCAM_IPV6_ADDR(m32, ip6addr) {		\
		m32[0] = ip6addr.S6_addr32[0]; \
		m32[1] = ip6addr.S6_addr32[1]; \
		m32[2] = ip6addr.S6_addr32[2]; \
		m32[3] = ip6addr.S6_addr32[3]; \
	}

#define	FSPEC_IPV6_ADDR(ip6addr, m32) {		\
	ip6addr.S6_addr32[0] = m32[0];		\
	ip6addr.S6_addr32[1] = m32[1];		\
	ip6addr.S6_addr32[2] = m32[2];		\
	ip6addr.S6_addr32[3] = m32[3];		\
}

#define	TCAM_IPV4_ADDR(m32, ip4addr) (m32 = ip4addr)
#define	FSPEC_IPV4_ADDR(ip4addr, m32) (ip4addr = m32)

#define	TCAM_IP_PORTS(port32, dp, sp)	  (port32 = dp | (sp << 16))
#define	FSPEC_IP_PORTS(dp, sp, port32) {	\
	dp = port32 & 0xff;			\
	sp = port32 >> 16;			\
}

#define	TCAM_IP_CLASS(key, mask, class)	  {		\
		key = class; \
		mask = 0x1f; \
	}

#define	TCAM_IP_PROTO(key, mask, proto) {		\
		key = proto; \
		mask = 0xff; \
	}

struct flow_resource_s {
	uint64_t channel_cookie;
	uint64_t flow_cookie;
	uint64_t location;
	flow_spec_t flow_spec;
} __attribute__((packed));

typedef struct flow_resource_s flow_resource_t;

/* ioctl data structure and cmd types for configuring rx classification */

#define	NXGE_RX_CLASS_GCHAN	0x01
#define	NXGE_RX_CLASS_GRULE_CNT	0x02
#define	NXGE_RX_CLASS_GRULE	0x03
#define	NXGE_RX_CLASS_GRULE_ALL	0x04
#define	NXGE_RX_CLASS_RULE_DEL	0x05
#define	NXGE_RX_CLASS_RULE_INS	0x06

#define	NXGE_PKT_DISCARD	0xffffffffffffffffULL

struct rx_class_cfg_s {
	uint32_t cmd;
	uint32_t data; /* the rule DB size or the # rx rings */
	uint64_t rule_cnt;
	uint32_t rule_locs[256];
	flow_resource_t fs;
} __attribute__((packed));

typedef struct rx_class_cfg_s rx_class_cfg_t;

/*
 * ioctl data structure and cmd types for configuring rx hash
 * for IP tunneled traffic and symmetric mode.
 */

#define	NXGE_IPTUN_CFG_ADD_CLS	0x07
#define	NXGE_IPTUN_CFG_SET_HASH	0x08
#define	NXGE_IPTUN_CFG_DEL_CLS	0x09
#define	NXGE_IPTUN_CFG_GET_CLS	0x0a
#define	NXGE_CLS_CFG_SET_SYM	0x0b
#define	NXGE_CLS_CFG_GET_SYM	0x0c

#define	IPTUN_PKT_IPV4		1
#define	IPTUN_PKT_IPV6		2
#define	IPTUN_PKT_GRE		3
#define	IPTUN_PKT_GTP		4
#define	OTHER_USR_PKT		5

#define	SEL_L4B_0_3		0x0001
#define	SEL_L4B_4_7		0x0002
#define	SEL_L4B_8_11		0x0004
#define	SEL_L4B_12_15		0x0008
#define	SEL_L4B_16_19		0x0010
#define	SEL_L4B_20_23		0x0020
#define	SEL_L4B_24_27		0x0040
#define	SEL_L4B_28_31		0x0080
#define	SEL_L4B_32_35		0x0100
#define	SEL_L4B_36_39		0x0200

#define	HASH_IFPORT		0x0001
#define	HASH_L2DA		0x0002
#define	HASH_VLAN		0x0004
#define	HASH_IPSA		0x0008
#define	HASH_IPDA		0x0010
#define	HASH_L3PROTO		0x0020

#define	CLS_TCPV4		0x08
#define	CLS_UDPV4		0x09
#define	CLS_AHESPV4		0x0A
#define	CLS_SCTPV4		0x0B
#define	CLS_TCPV6		0x0C
#define	CLS_UDPV6		0x0D
#define	CLS_AHESPV6		0x0E
#define	CLS_SCTPV6		0x0F
#define	CLS_IPV6FRAG		0x1F

struct _iptun_cfg {
	uint8_t		in_pkt_type;
	uint8_t		l4b0_val;
	uint8_t		l4b0_mask;
	uint8_t		l4b23_sel;
	uint16_t	l4b23_val;
	uint16_t	l4xor_sel;
	uint8_t		hash_flags;
} __attribute__((packed));

typedef struct _iptun_cfg iptun_cfg_t;

struct _cfg_cmd {
	uint16_t cmd;
	uint8_t sym;
	uint8_t	class_id;
	iptun_cfg_t	iptun_cfg;
} __attribute__((packed));

typedef struct _cfg_cmd cfg_cmd_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_FLOW_H */
