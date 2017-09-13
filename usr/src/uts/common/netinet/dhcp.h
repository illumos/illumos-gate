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
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

/*
 * dhcp.h - Generic DHCP definitions, as per RFC's 2131 and 2132.
 */

#ifndef	_DHCP_H
#define	_DHCP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef  _REENTRANT
#include <thread.h>
#endif  /* _REENTRANT */

/*
 * DHCP option codes.
 */

#define	CD_PAD			0
#define	CD_END			255
#define	CD_SUBNETMASK		1
#define	CD_TIMEOFFSET		2
#define	CD_ROUTER		3
#define	CD_TIMESERV		4
#define	CD_IEN116_NAME_SERV	5
#define	CD_DNSSERV		6
#define	CD_LOG_SERV		7
#define	CD_COOKIE_SERV		8
#define	CD_LPR_SERV		9
#define	CD_IMPRESS_SERV		10
#define	CD_RESOURCE_SERV	11
#define	CD_HOSTNAME		12
#define	CD_BOOT_SIZE		13
#define	CD_DUMP_FILE		14
#define	CD_DNSDOMAIN		15
#define	CD_SWAP_SERV		16
#define	CD_ROOT_PATH		17
#define	CD_EXTEND_PATH		18

/* IP layer parameters */
#define	CD_IP_FORWARDING_ON	19
#define	CD_NON_LCL_ROUTE_ON	20
#define	CD_POLICY_FILTER	21
#define	CD_MAXIPSIZE		22
#define	CD_IPTTL		23
#define	CD_PATH_MTU_TIMEOUT	24
#define	CD_PATH_MTU_TABLE_SZ	25

/* IP layer parameters per interface */
#define	CD_MTU			26
#define	CD_ALL_SUBNETS_LCL_ON	27
#define	CD_BROADCASTADDR	28
#define	CD_MASK_DISCVRY_ON	29
#define	CD_MASK_SUPPLIER_ON	30
#define	CD_ROUTER_DISCVRY_ON	31
#define	CD_ROUTER_SOLICIT_SERV	32
#define	CD_STATIC_ROUTE		33

/* Link Layer Parameters per Interface */
#define	CD_TRAILER_ENCAPS_ON	34
#define	CD_ARP_TIMEOUT		35
#define	CD_ETHERNET_ENCAPS_ON	36

/* TCP Parameters */
#define	CD_TCP_TTL		37
#define	CD_TCP_KALIVE_INTVL	38
#define	CD_TCP_KALIVE_GRBG_ON	39

/* Application layer parameters */
#define	CD_NIS_DOMAIN		40
#define	CD_NIS_SERV		41
#define	CD_NTP_SERV		42
#define	CD_VENDOR_SPEC		43

/* NetBIOS parameters */
#define	CD_NETBIOS_NAME_SERV	44
#define	CD_NETBIOS_DIST_SERV	45
#define	CD_NETBIOS_NODE_TYPE	46
#define	CD_NETBIOS_SCOPE	47

/* X Window parameters */
#define	CD_XWIN_FONT_SERV	48
#define	CD_XWIN_DISP_SERV	49

/* DHCP protocol extension options */
#define	CD_REQUESTED_IP_ADDR	50
#define	CD_LEASE_TIME		51
#define	CD_OPTION_OVERLOAD	52
#define	CD_DHCP_TYPE		53
#define	CD_SERVER_ID		54
#define	CD_REQUEST_LIST		55
#define	CD_MESSAGE		56
#define	CD_MAX_DHCP_SIZE	57
#define	CD_T1_TIME		58
#define	CD_T2_TIME		59
#define	CD_CLASS_ID		60
#define	CD_CLIENT_ID		61

/* Netware options */
#define	CD_NW_IP_DOMAIN		62
#define	CD_NW_IP_OPTIONS	63

/* Nisplus options */
#define	CD_NISPLUS_DMAIN	64
#define	CD_NISPLUS_SERVS	65

/* Optional sname/bootfile options */
#define	CD_TFTP_SERV_NAME	66
#define	CD_OPT_BOOTFILE_NAME	67

/* Additional server options */
#define	CD_MOBILE_IP_AGENT	68
#define	CD_SMTP_SERVS		69
#define	CD_POP3_SERVS		70
#define	CD_NNTP_SERVS		71
#define	CD_WWW_SERVS		72
#define	CD_FINGER_SERVS		73
#define	CD_IRC_SERVS		74

/* Streettalk options */
#define	CD_STREETTALK_SERVS	75
#define	CD_STREETTALK_DA_SERVS	76

/* User class identifier */
#define	CD_USER_CLASS_ID	77

/* Newer options */

#define	CD_SLPDA		78
#define	CD_SLPSS		79
#define	CD_CLIENTFQDN		81
#define	CD_AGENTOPT		82

/*
 * Per RFC 3679, option 89 was "Never published as standard and [is] not in
 * general use". See active CD_CLIENTFQDN and RFC 4702.
 */
#define	CD_FQDN			89

#define	CD_PXEARCHi		93
#define	CD_PXENIIi		94
#define	CD_PXECID		95
#define	CD_MULTICST		107

#define	DHCP_FIRST_OPT		CD_SUBNETMASK
#define	DHCP_LAST_STD		CD_MULTICST
#define	DHCP_SITE_OPT		128		/* inclusive */
#define	DHCP_END_SITE		254
#define	DHCP_LAST_OPT		DHCP_END_SITE	/* last op code */

#define	DHCP_MAX_OPT_SIZE	255	/* maximum option size in octets */

/*
 * DHCP Packet. What will fit in a ethernet frame. We may use a smaller
 * size, based on what our transport can handle.
 */
#define	DHCP_DEF_MAX_SIZE	576	/* as spec'ed in RFC 2131 */
#define	PKT_BUFFER		1486	/* max possible size of pkt buffer */
#define	BASE_PKT_SIZE		240	/* everything but the options */
typedef struct dhcp {
	uint8_t		op;		/* message opcode */
	uint8_t		htype;		/* Hardware address type */
	uint8_t		hlen;		/* Hardware address length */
	uint8_t		hops;		/* Used by relay agents */
	uint32_t	xid;		/* transaction id */
	uint16_t	secs;		/* Secs elapsed since client boot */
	uint16_t	flags;		/* DHCP Flags field */
	struct in_addr	ciaddr;		/* client IP addr */
	struct in_addr	yiaddr;		/* 'Your' IP addr. (from server) */
	struct in_addr	siaddr;		/* Boot server IP addr */
	struct in_addr	giaddr;		/* Relay agent IP addr */
	uint8_t		chaddr[16];	/* Client hardware addr */
	uint8_t		sname[64];	/* Optl. boot server hostname */
	uint8_t		file[128];	/* boot file name (ascii path) */
	uint8_t		cookie[4];	/* Magic cookie */
	uint8_t		options[60];	/* Options */
} PKT;

typedef uint32_t	lease_t; /* DHCP lease time (32 bit quantity) */

/*
 * DHCP packet types. As per protocol.
 */
#define	DISCOVER	((uint8_t)1)
#define	OFFER		((uint8_t)2)
#define	REQUEST		((uint8_t)3)
#define	DECLINE		((uint8_t)4)
#define	ACK		((uint8_t)5)
#define	NAK		((uint8_t)6)
#define	RELEASE		((uint8_t)7)
#define	INFORM		((uint8_t)8)

/*
 * Generic DHCP protocol defines
 */
#define	DHCP_PERM	((lease_t)0xffffffff)	/* "permanent" lease time */
#define	BOOTREQUEST		(1)		/* BOOTP REQUEST opcode */
#define	BOOTREPLY		(2)		/* BOOTP REPLY opcode */
#define	BOOTMAGIC	{ 99, 130, 83, 99 }	/* rfc1048 magic cookie */
#define	BCAST_MASK	0x8000			/* BROADCAST flag */

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCP_H */
