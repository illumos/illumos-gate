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

#ifndef _DHCP6_H
#define	_DHCP6_H

/*
 * This header file describes constants and on-the-wire data structures used
 * with DHCPv6.
 *
 * Note that the data structures contained here must be used with caution.  The
 * DHCPv6 protocol generally does not maintain alignment.
 *
 * (Users may also need to include other header files to get ntohs/htons
 * definitions, if the DHCPV6_{GET,SET} macros are used.)
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>

/*
 * Message Types
 */
#define	DHCPV6_MSG_SOLICIT	1	/* Client sends */
#define	DHCPV6_MSG_ADVERTISE	2	/* Server sends */
#define	DHCPV6_MSG_REQUEST	3	/* Client sends */
#define	DHCPV6_MSG_CONFIRM	4	/* Client sends */
#define	DHCPV6_MSG_RENEW	5	/* Client sends */
#define	DHCPV6_MSG_REBIND	6	/* Client sends */
#define	DHCPV6_MSG_REPLY	7	/* Server sends */
#define	DHCPV6_MSG_RELEASE	8	/* Client sends */
#define	DHCPV6_MSG_DECLINE	9	/* Client sends */
#define	DHCPV6_MSG_RECONFIGURE	10	/* Server sends */
#define	DHCPV6_MSG_INFO_REQ	11	/* Client sends */
#define	DHCPV6_MSG_RELAY_FORW	12	/* Relay agent sends to server */
#define	DHCPV6_MSG_RELAY_REPL	13	/* Server sends to relay agent */

/*
 * Status Codes
 */
#define	DHCPV6_STAT_SUCCESS	0
#define	DHCPV6_STAT_UNSPECFAIL	1	/* Unknown reason */
#define	DHCPV6_STAT_NOADDRS	2	/* Server has no addresses available */
#define	DHCPV6_STAT_NOBINDING	3	/* Client record unavailable */
#define	DHCPV6_STAT_NOTONLINK	4	/* Prefix inappropriate for link */
#define	DHCPV6_STAT_USEMCAST	5	/* Client must use multicast */
#define	DHCPV6_STAT_NOPREFIX	6	/* No prefix available; RFC3633 */

/*
 * DHCP Unique Identifier (DUID) Types
 */
#define	DHCPV6_DUID_LLT		1	/* Link layer address plus time */
#define	DHCPV6_DUID_EN		2	/* Vendor assigned */
#define	DHCPV6_DUID_LL		3	/* Link layer address */

/*
 * DHCPv6 Option Codes
 * Note: options 10 and 35 are not assigned.
 */
#define	DHCPV6_OPT_CLIENTID	1	/* Client's DUID */
#define	DHCPV6_OPT_SERVERID	2	/* Server's DUID */
#define	DHCPV6_OPT_IA_NA	3	/* Non-temporary addrs; dhcpv6_ia_na */
#define	DHCPV6_OPT_IA_TA	4	/* Temporary addrs; dhcpv6_ia_ta */
#define	DHCPV6_OPT_IAADDR	5	/* IA Address; dhcpv6_iaaddr */
#define	DHCPV6_OPT_ORO		6	/* Option Request; uint16_t array */
#define	DHCPV6_OPT_PREFERENCE	7	/* Server preference; uint8_t */
#define	DHCPV6_OPT_ELAPSED_TIME	8	/* Client time; uint16_t; centisec */
#define	DHCPV6_OPT_RELAY_MSG	9	/* Relayed client DHCP message */
#define	DHCPV6_OPT_AUTH		11	/* Authentication; dhcpv6_auth */
#define	DHCPV6_OPT_UNICAST	12	/* Client may unicast; in6_addr_t */
#define	DHCPV6_OPT_STATUS_CODE	13	/* Status; uint16_t plus string */
#define	DHCPV6_OPT_RAPID_COMMIT	14	/* Server may do RC; boolean (len 0) */
#define	DHCPV6_OPT_USER_CLASS	15	/* Classes; {uint16_t,uint8_t...}... */
#define	DHCPV6_OPT_VENDOR_CLASS	16	/* Client vendor; uint32_t + list */
#define	DHCPV6_OPT_VENDOR_OPT	17	/* Vendor specific; uint32_t+opts */
#define	DHCPV6_OPT_INTERFACE_ID	18	/* Relay agent interface */
#define	DHCPV6_OPT_RECONF_MSG	19	/* Reconfigure; uint8_t */
#define	DHCPV6_OPT_RECONF_ACC	20	/* Reconfigure accept; boolean */
#define	DHCPV6_OPT_SIP_NAMES	21	/* SIP srv domain names (RFC3319) */
#define	DHCPV6_OPT_SIP_ADDR	22	/* SIP srv IPv6 address (RFC3319) */
#define	DHCPV6_OPT_DNS_ADDR	23	/* DNS Recur. Name Server (RFC3646) */
#define	DHCPV6_OPT_DNS_SEARCH	24	/* Domain Search List (RFC3646) */
#define	DHCPV6_OPT_IA_PD	25	/* Delegate dhcpv6_ia_na (RFC3633) */
#define	DHCPV6_OPT_IAPREFIX	26	/* Prefix dhcpv6_iaprefix (RFC3633) */
#define	DHCPV6_OPT_NIS_SERVERS	27	/* NIS in6_addr_t array (RFC3898) */
#define	DHCPV6_OPT_NIS_DOMAIN	29	/* NIS Domain string (RFC3898) */
#define	DHCPV6_OPT_SNTP_SERVERS	31	/* SNTP in6_addr_t array (RFC4075) */
#define	DHCPV6_OPT_INFO_REFTIME	32	/* Info refresh uint32_t (RFC4242) */
#define	DHCPV6_OPT_BCMCS_SRV_D	33	/* NUL-term string list (RFC4280) */
#define	DHCPV6_OPT_BCMCS_SRV_A	34	/* in6_addr_t array (RFC4280) */
#define	DHCPV6_OPT_GEOCONF_CVC	36	/* dhcpv6_civic_t plus TLVs */
#define	DHCPV6_OPT_REMOTE_ID	37	/* uint32_t plus opaque */
#define	DHCPV6_OPT_SUBSCRIBER	38	/* opaque; may be NVT ASCII */
#define	DHCPV6_OPT_CLIENT_FQDN	39	/* uint8_t plus domain */

/*
 * Reconfiguration types; used with DHCPV6_OPT_RECONF_MSG option.
 */
#define	DHCPV6_RECONF_RENEW	5	/* Renew now */
#define	DHCPV6_RECONF_INFO	11	/* Request information */

/*
 * FQDN Flags; used with DHCPV6_OPT_CLIENT_FQDN option.
 */
#define	DHCPV6_FQDNF_S	0x01	/* Server should perform AAAA RR updates */
#define	DHCPV6_FQDNF_O	0x02	/* Server override of 'S' bit */
#define	DHCPV6_FQDNF_N	0x04	/* Server should not perform any updates */

/*
 * Miscellany
 */
#define	DHCPV6_INFTIME	0xfffffffful	/* Infinity; used for timers */
#define	DHCPV6_FOREVER	0xffff		/* Used for elapsed time option */
#define	DHCPV6_SUN_ENT	42		/* Sun Microsystems enterprise ID */

/*
 * Basic DHCPv6 message header used for server/client communications.  The
 * options follow this header.
 */
struct dhcpv6_message {
	uint8_t		d6m_msg_type;
	uint8_t		d6m_transid_ho;
	uint16_t	d6m_transid_lo;
};

#define	DHCPV6_GET_TRANSID(msg) \
	(((msg)->d6m_transid_ho << 16) + ntohs((msg)->d6m_transid_lo))
#define	DHCPV6_SET_TRANSID(msg, id) \
	((msg)->d6m_transid_ho = (id) >> 16, (msg)->d6m_transid_lo = htons(id))

/*
 * DHCPv6 relay agent header used only for server/relay communications.  The
 * options follow this header, and the client message is encapsulated as an
 * option.  Note that the IPv6 addresses are not on natural word boundaries.
 */
struct dhcpv6_relay {
	uint8_t		d6r_msg_type;
	uint8_t		d6r_hop_count;
	uint8_t		d6r_linkaddr[16];
	uint8_t		d6r_peeraddr[16];
};

/*
 * DHCPv6 generic option header.  Note that options are not aligned on any
 * convenient boundary.
 */
struct dhcpv6_option {
	uint16_t	d6o_code;
	uint16_t	d6o_len;
};

/*
 * Option header for IA_NA (Non-temporary addresses) and IA_PD (Prefix
 * delegation).  Contains IA Address options for IA_NA, IA_PD Prefixes for
 * IA_PD.
 */
struct dhcpv6_ia_na {
	uint16_t	d6in_code;
	uint16_t	d6in_len;
	uint32_t	d6in_iaid;	/* Unique ID [interface] */
	uint32_t	d6in_t1;	/* Extend from same server */
	uint32_t	d6in_t2;	/* Extend from any server */
};

/*
 * Option header for IA_TA (Temporary addresses).  Contains IA Address options.
 */
struct dhcpv6_ia_ta {
	uint16_t	d6it_code;
	uint16_t	d6it_len;
	uint32_t	d6it_iaid;	/* Unique ID [interface] */
};

/*
 * Option header for IA Address.  Must be used inside of an IA_NA or IA_TA
 * option.  May contain a Status Code option.
 */
struct dhcpv6_iaaddr {
	uint16_t	d6ia_code;
	uint16_t	d6ia_len;
	in6_addr_t	d6ia_addr;	/* IPv6 address */
	uint32_t	d6ia_preflife;	/* Preferred lifetime */
	uint32_t	d6ia_vallife;	/* Valid lifetime */
};

/*
 * Option header for Authentication.  Followed by variable-length
 * authentication information field.  Warning: padding may be present.  Use
 * defined size.
 */
struct dhcpv6_auth {
	uint16_t	d6a_code;
	uint16_t	d6a_len;
	uint8_t		d6a_proto;	/* Protocol */
	uint8_t		d6a_alg;	/* Algorithm */
	uint8_t		d6a_rdm;	/* Replay Detection Method (RDM) */
	uint8_t		d6a_replay[8];	/* Information for RDM */
};
#define	DHCPV6_AUTH_SIZE	15

/* dhpv6_auth.d6a_proto values */
#define	DHCPV6_PROTO_DELAYED	2	/* Delayed Authentication mechanism */
#define	DHCPV6_PROTO_RECONFIG	3	/* Reconfigure Key mechanism */

/* dhpv6_auth.d6a_alg values */
#define	DHCPV6_ALG_HMAC_MD5	1	/* HMAC-MD5 signature */

/* dhpv6_auth.d6a_rdm values */
#define	DHCPV6_RDM_MONOCNT	0	/* Monotonic counter */

/*
 * Option header for IA_PD Prefix.  Must be used inside of an IA_PD option.
 * May contain a Status Code option.  Warning: padding may be present; use
 * defined size.
 */
struct dhcpv6_iaprefix {
	uint16_t	d6ip_code;
	uint16_t	d6ip_len;
	uint32_t	d6ip_preflife;	/* Preferred lifetime */
	uint32_t	d6ip_vallife;	/* Valid lifetime */
	uint8_t		d6ip_preflen;	/* Prefix length */
	uint8_t		d6ip_addr[16];	/* IPv6 prefix */
};
#define	DHCPV6_IAPREFIX_SIZE	29

/*
 * Option header for Civic Address information.  Followed by single octet TLV
 * encoded address elements, using CIVICADDR_* values for type.  Warning:
 * padding may be present; use defined size.
 */
struct dhcpv6_civic {
	uint16_t	d6c_code;
	uint16_t	d6c_len;
	uint8_t		d6c_what;	/* DHCPV6_CWHAT_* value */
	char		d6c_cc[2];		/* Country code; ISO 3166 */
};
#define	DHCPV6_CIVIC_SIZE	7

#define	DHCPV6_CWHAT_SERVER	0	/* Location of server */
#define	DHCPV6_CWHAT_NETWORK	1	/* Location of network */
#define	DHCPV6_CWHAT_CLIENT	2	/* Location of client */

#define	CIVICADDR_LANG	0	/* Language; RFC 2277 */
#define	CIVICADDR_A1	1	/* National division (state) */
#define	CIVICADDR_A2	2	/* County */
#define	CIVICADDR_A3	3	/* City */
#define	CIVICADDR_A4	4	/* City division */
#define	CIVICADDR_A5	5	/* Neighborhood */
#define	CIVICADDR_A6	6	/* Street group */
#define	CIVICADDR_PRD	16	/* Leading street direction */
#define	CIVICADDR_POD	17	/* Trailing street suffix */
#define	CIVICADDR_STS	18	/* Street suffix or type */
#define	CIVICADDR_HNO	19	/* House number */
#define	CIVICADDR_HNS	20	/* House number suffix */
#define	CIVICADDR_LMK	21	/* Landmark */
#define	CIVICADDR_LOC	22	/* Additional location information */
#define	CIVICADDR_NAM	23	/* Name/occupant */
#define	CIVICADDR_PC	24	/* Postal Code/ZIP */
#define	CIVICADDR_BLD	25	/* Building */
#define	CIVICADDR_UNIT	26	/* Unit/apt/suite */
#define	CIVICADDR_FLR	27	/* Floor */
#define	CIVICADDR_ROOM	28	/* Room number */
#define	CIVICADDR_TYPE	29	/* Place type */
#define	CIVICADDR_PCN	30	/* Postal community name */
#define	CIVICADDR_POBOX	31	/* Post office box */
#define	CIVICADDR_ADDL	32	/* Additional code */
#define	CIVICADDR_SEAT	33	/* Seat/desk */
#define	CIVICADDR_ROAD	34	/* Primary road or street */
#define	CIVICADDR_RSEC	35	/* Road section */
#define	CIVICADDR_RBRA	36	/* Road branch */
#define	CIVICADDR_RSBR	37	/* Road sub-branch */
#define	CIVICADDR_SPRE	38	/* Street name pre-modifier */
#define	CIVICADDR_SPOST	39	/* Street name post-modifier */
#define	CIVICADDR_SCRIPT 128	/* Script */

/*
 * DHCP Unique Identifier structures.  These represent the fixed portion of the
 * unique identifier object, and are followed by the variable-length link layer
 * address or identifier.
 */
struct duid_llt {
	uint16_t	dllt_dutype;
	uint16_t	dllt_hwtype;
	uint32_t	dllt_time;
};

/* DUID time stamps start on January 1st, 2000 UTC */
#define	DUID_TIME_BASE	946684800ul

struct duid_en {
	uint16_t	den_dutype;
	uint16_t	den_entho;
	uint16_t	den_entlo;
};

#define	DHCPV6_GET_ENTNUM(den) \
	((ntohs((den)->den_entho) << 16) + ntohs((den)->den_entlo))
#define	DHCPV6_SET_ENTNUM(den, val) \
	((den)->den_entho = htons((val) >> 16), (den)->den_entlo = htons(val))

struct duid_ll {
	uint16_t	dll_dutype;
	uint16_t	dll_hwtype;
};

/*
 * Data types
 */
typedef	struct dhcpv6_message	dhcpv6_message_t;
typedef	struct dhcpv6_relay	dhcpv6_relay_t;
typedef	struct dhcpv6_option	dhcpv6_option_t;
typedef	struct dhcpv6_ia_na	dhcpv6_ia_na_t;
typedef	struct dhcpv6_ia_ta	dhcpv6_ia_ta_t;
typedef	struct dhcpv6_iaaddr	dhcpv6_iaaddr_t;
typedef	struct dhcpv6_auth	dhcpv6_auth_t;
typedef	struct dhcpv6_iaprefix	dhcpv6_iaprefix_t;
typedef struct dhcpv6_civic	dhcpv6_civic_t;
typedef	struct duid_llt		duid_llt_t;
typedef	struct duid_en		duid_en_t;
typedef	struct duid_ll		duid_ll_t;

#ifdef __cplusplus
}
#endif

#endif /* _DHCP6_H */
