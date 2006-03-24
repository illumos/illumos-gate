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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ip6.h - Common structures and definitions as defined by
 * advanced BSD API.
 */

#ifndef	_NETINET_IP6_H
#define	_NETINET_IP6_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>

struct	ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t	ip6_un1_flow;   /* 4 bits version, */
							/* 8 bits tclass, and */
							/* 20 bits flow-ID */
			uint16_t	ip6_un1_plen;   /* payload length */
			uint8_t		ip6_un1_nxt;    /* next header */
			uint8_t		ip6_un1_hlim;   /* hop limit */
		} ip6_un1;
		uint8_t	ip6_un2_vfc;	/* 4 bits version and */
					/* top 4 bits of tclass */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
};
typedef struct ip6_hdr	ip6_t;

#define	ip6_vfc		ip6_ctlun.ip6_un2_vfc	/* 4 bits version and */
						/* top 4 bits of tclass */
#define	ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define	ip6_vcf		ip6_flow		/* Version, tclass, flow-ID */
#define	ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define	ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define	ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define	ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

/* Hop-by-Hop options header */
struct ip6_hbh {
	uint8_t	ip6h_nxt;	/* next header */
	uint8_t	ip6h_len;	/* length in units of 8 octets */
		/* followed by options */
};
typedef struct ip6_hbh	ip6_hbh_t;

/* Destination options header */
struct ip6_dest {
	uint8_t	ip6d_nxt;	/* next header */
	uint8_t	ip6d_len;	/* length in units of 8 octets */
		/* followed by options */
};
typedef struct ip6_dest	ip6_dest_t;

/* Routing header */
struct ip6_rthdr {
	uint8_t	ip6r_nxt;	/* next header */
	uint8_t	ip6r_len;	/* length in units of 8 octets */
	uint8_t	ip6r_type;	/* routing type */
	uint8_t	ip6r_segleft;	/* segments left */
		/* followed by routing type specific data */
};
typedef struct ip6_rthdr	ip6_rthdr_t;

/* Type 0 Routing header */
struct ip6_rthdr0 {
	uint8_t	ip6r0_nxt;		/* next header */
	uint8_t	ip6r0_len;		/* length in units of 8 octets */
	uint8_t	ip6r0_type;		/* always zero */
	uint8_t	ip6r0_segleft;		/* segments left */
	uint32_t ip6r0_reserved;	/* reserved field */
};
typedef struct ip6_rthdr0	ip6_rthdr0_t;

/* Fragment header */
struct ip6_frag {
	uint8_t		ip6f_nxt;	/* next header */
	uint8_t		ip6f_reserved;	/* reserved field */
	uint16_t	ip6f_offlg;	/* offset, reserved, and flag */
	uint32_t	ip6f_ident;	/* identification */
};
typedef struct ip6_frag	ip6_frag_t;

/* ip6f_offlg field related constants (in network byte order) */
#ifdef _BIG_ENDIAN
#define	IP6F_OFF_MASK		0xfff8	/* mask out offset from _offlg */
#define	IP6F_RESERVED_MASK	0x0006	/* reserved bits in ip6f_offlg */
#define	IP6F_MORE_FRAG		0x0001	/* more-fragments flag */
#else
#define	IP6F_OFF_MASK		0xf8ff	/* mask out offset from _offlg */
#define	IP6F_RESERVED_MASK	0x0600	/* reserved bits in ip6f_offlg */
#define	IP6F_MORE_FRAG		0x0100	/* more-fragments flag */
#endif

/* IPv6 options */
struct	ip6_opt {
	uint8_t	ip6o_type;
	uint8_t	ip6o_len;
};

/*
 * The high-order 3 bits of the option type define the behavior
 * when processing an unknown option and whether or not the option
 * content changes in flight.
 */
#define	IP6OPT_TYPE(o)		((o) & 0xc0)
#define	IP6OPT_TYPE_SKIP	0x00
#define	IP6OPT_TYPE_DISCARD	0x40
#define	IP6OPT_TYPE_FORCEICMP	0x80
#define	IP6OPT_TYPE_ICMP	0xc0
#define	IP6OPT_MUTABLE		0x20

#define	IP6OPT_PAD1			0x00	/* 00 0 00000 */
#define	IP6OPT_PADN			0x01	/* 00 0 00001 */
#define	IP6OPT_JUMBO			0xc2	/* 11 0 00010 = 194 */
#define	IP6OPT_NSAP_ADDR		0xc3	/* 11 0 00011 */
#define	IP6OPT_TUNNEL_LIMIT		0x04	/* 00 0 00100 */
#define	IP6OPT_ROUTER_ALERT		0x05	/* 00 0 00101 */
#define	IP6OPT_BINDING_UPDATE		0xc6	/* 11 0 00110 */
#define	IP6OPT_BINDING_ACK		0x07	/* 00 0 00111 */
#define	IP6OPT_BINDING_REQ		0x08	/* 00 0 01000 */
#define	IP6OPT_HOME_ADDRESS		0xc9	/* 11 0 01001 */
#define	IP6OPT_EID			0x8a	/* 10 0 01010 */

#define	IP6OPT_LS			0x0a	/* 00 0 01010 */

#define	IP6_MAX_OPT_LENGTH	255

/* Jumbo Payload Option */
struct	ip6_opt_jumbo {
	uint8_t	ip6oj_type;
	uint8_t	ip6oj_len;
	uint8_t ip6oj_jumbo_len[4];
};
#define	IP6OPT_JUMBO_LEN	6

/* NSAP Address Option */
struct	ip6_opt_nsap {
	uint8_t	ip6on_type;
	uint8_t	ip6on_len;
	uint8_t ip6on_src_nsap_len;
	uint8_t ip6on_dst_nsap_len;
	/* Followed by source NSAP */
	/* Followed by destination NSAP */
};

/* Tunnel Limit Option */
struct	ip6_opt_tunnel {
	uint8_t	ip6ot_type;
	uint8_t	ip6ot_len;
	uint8_t ip6ot_encap_limit;
};

/* Router Alert Option */
struct	ip6_opt_router {
	uint8_t	ip6or_type;
	uint8_t	ip6or_len;
	uint8_t ip6or_value[2];
};

/* Router alert values (in network byte order) */
#ifdef _BIG_ENDIAN
#define	IP6_ALERT_MLD			0x0000
#define	IP6_ALERT_RSVP			0x0001
#define	IP6_ALERT_AN			0x0002
#else
#define	IP6_ALERT_MLD			0x0000
#define	IP6_ALERT_RSVP			0x0100
#define	IP6_ALERT_AN			0x0200
#endif

/* Binding Update Option */
struct	ip6_opt_binding_update {
	uint8_t	ip6ou_type;
	uint8_t	ip6ou_len;
	uint8_t ip6ou_flags;
	uint8_t ip6ou_prefixlen;
	uint8_t ip6ou_seqno[2];
	uint8_t ip6ou_lifetime[4];
	uint8_t ip6ou_coa[16];		/* Optional based on flags */
	/* Followed by sub-options */
};

/* Binding Update Flags */
#define	IP6_BUF_ACK	0x80	/* Request a binding ack */
#define	IP6_BUF_HOME	0x40	/* Home Registration */
#define	IP6_BUF_COA	0x20	/* Care-of-address present in option */
#define	IP6_BUF_ROUTER	0x10	/* Sending mobile node is a router */

/* Binding Ack Option */
struct	ip6_opt_binding_ack {
	uint8_t	ip6oa_type;
	uint8_t	ip6oa_len;
	uint8_t ip6oa_status;
	uint8_t ip6oa_seqno[2];
	uint8_t ip6oa_lifetime[4];
	uint8_t ip6oa_refresh[4];
	/* Followed by sub-options */
};

/* Binding Request Option */
struct	ip6_opt_binding_request {
	uint8_t	ip6or_type;
	uint8_t	ip6or_len;
	/* Followed by sub-options */
};

/* Home Address Option */
struct	ip6_opt_home_address {
	uint8_t	ip6oh_type;
	uint8_t	ip6oh_len;
	uint8_t ip6oh_addr[16];		/* Home Address */
	/* Followed by sub-options */
};

/* Labeled Security Option */
struct	ip6_opt_labeled_security {
	uint8_t ip6ol_type;
	uint8_t ip6ol_len;	/* always even for defined values */
	uint8_t ip6ol_doi[4];
	/* Followed by sub-options */
};

#define	IP6LS_DOI_V4	0	/* IPv4 transition */

#define	IP6LS_TT_LEVEL	1	/* level or classification; 2-octet value */
#define	IP6LS_TT_VECTOR	2	/* compartments; bit vector (even # octets) */
#define	IP6LS_TT_ENUM	3	/* set membership; list of 2-octet values */
#define	IP6LS_TT_RANGES	4	/* set membership; pairs of 2-octet values */
#define	IP6LS_TT_V4	5	/* IPv4 compatible option */
#define	IP6LS_TT_DEST	6	/* destination-only data; per DOI */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IP6_H */
