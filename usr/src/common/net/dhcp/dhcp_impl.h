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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#ifndef	_DHCP_IMPL_H
#define	_DHCP_IMPL_H

/*
 * Common definitions used by Sun DHCP implementations
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp6.h>
#include <dhcp_symbol_common.h>
#include <sys/sunos_dhcp_class.h>

/* Packet fields */
#define	CD_PACKET_START		0
#define	CD_POPCODE		0	/* packet opcode */
#define	CD_PHTYPE		1	/* packet header type */
#define	CD_PHLEN		2	/* packet header len */
#define	CD_PHOPS		3	/* packet header len */
#define	CD_PXID			4	/* packet hops */
#define	CD_PSECS		8	/* packet xid */
#define	CD_PFLAGS		10	/* packet secs */
#define	CD_PCIADDR		12	/* packet flags */
#define	CD_YIADDR		16	/* client's ip address */
#define	CD_SIADDR		20	/* Bootserver's ip address */
#define	CD_GIADDR		24	/* BOOTP relay agent address */
#define	CD_PCHADDR		28	/* BOOTP relay agent address */
#define	CD_SNAME		44	/* Hostname of Bootserver, or opts */
#define	CD_BOOTFILE		108	/* File to boot or opts */
#define	CD_PCOOKIE		236	/* packet cookie */
#define	CD_POPTIONS		240	/* packet options */
#define	CD_PACKET_END		CD_POPTIONS

/* Internal server options */
#define	CD_INTRNL_START		1024
#define	CD_BOOL_HOSTNAME	1024	/* Entry wants hostname (Nameserv) */
#define	CD_BOOL_LEASENEG	1025	/* Entry's lease is negotiable */
#define	CD_BOOL_ECHO_VCLASS	1026	/* Echo Vendor class back to Entry */
#define	CD_BOOTPATH		1027	/* prefix path to File to boot */
#define	CD_INTRNL_END		1027

/* Error codes that could be generated while parsing packets */
#define	DHCP_ERR_OFFSET		512
#define	DHCP_GARBLED_MSG_TYPE	(DHCP_ERR_OFFSET+0)
#define	DHCP_WRONG_MSG_TYPE	(DHCP_ERR_OFFSET+1)
#define	DHCP_BAD_OPT_OVLD	(DHCP_ERR_OFFSET+2)

/*
 * Arbitrary "maximum" client ID length (in bytes), used by various bits
 * of the standalone code.  This needs to go away someday.
 */
#define	DHCP_MAX_CID_LEN	64

/*
 * Generic DHCP option structure.
 */
typedef struct {
	uint8_t    code;
	uint8_t    len;
	uint8_t    value[1];
} DHCP_OPT;

/*
 * Defines the size of DHCP_OPT code + len
 */
#define	DHCP_OPT_META_LEN	2

typedef union sockaddr46_s {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
} sockaddr46_t;

/*
 * Generic DHCP packet list. Ensure that _REENTRANT bracketed code stays at
 * bottom of this definition - the client doesn't include it. Scan.c in
 * libdhcp isn't aware of it either...
 *
 * The PKT * pointer here actually points to a dhcpv6_message_t if the packet
 * is DHCPv6.  We assume that PKT * the same or stricter alignment
 * requirements, and that the unused elements are not a significant burden.
 */
#define	MAX_PKT_LIST	5	/* maximum list size */
typedef struct  dhcp_list {
	struct dhcp_list 	*next;		/* keep first and in this */
	struct dhcp_list 	*prev;		/* order for insque/remque */

	PKT			*pkt;		/* client packet */
	uint_t			len;		/* packet len */
	int			rfc1048;	/* RFC1048 options - boolean */
	uint8_t			offset;		/* BOOTP packet offset */
	uint8_t			isv6;		/* DHCPv6 packet - boolean */
				/*
				 * standard/site options
				 */
	DHCP_OPT		*opts[DHCP_LAST_OPT + 1];

				/*
				 * Vendor specific options (client only)
				 */
	DHCP_OPT		*vs[VS_OPTION_END - VS_OPTION_START + 1];

	struct in_addr		off_ip;		/* Address OFFERed */

	uint_t			ifindex; /* received ifindex (if any) */
	sockaddr46_t		pktfrom; /* source (peer) address on input */
	sockaddr46_t		pktto;	/* destination (local) address */

} PKT_LIST;

extern int dhcp_options_scan(PKT_LIST *, boolean_t);
extern boolean_t dhcp_getinfo_pl(PKT_LIST *, uchar_t, uint16_t, uint16_t,
    void *, size_t *);
extern dhcpv6_option_t *dhcpv6_find_option(const void *, size_t,
    const dhcpv6_option_t *, uint16_t, uint_t *);
extern dhcpv6_option_t *dhcpv6_pkt_option(const PKT_LIST *,
    const dhcpv6_option_t *, uint16_t, uint_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCP_IMPL_H */
