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
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_ARP_H
#define	_INET_ARP_H

#include <sys/types.h>
#include <net/if.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Warning: the interfaces described in this file are private to the
 * implementation.  They may change at any time without notice and are not
 * documented.  Do not depend on them.
 */

#define	ARP_REQUEST	1
#define	ARP_RESPONSE	2
#define	RARP_REQUEST	3
#define	RARP_RESPONSE	4

#define	AR_IOCTL		(((unsigned)'A' & 0xFF)<<8)
#define	CMD_IN_PROGRESS		0x10000

#define	AR_ENTRY_ADD		(AR_IOCTL + 1)
#define	AR_ENTRY_DELETE		(AR_IOCTL + 2)
#define	AR_ENTRY_QUERY		(AR_IOCTL + 3)
#define	AR_ENTRY_SQUERY		(AR_IOCTL + 6)
#define	AR_MAPPING_ADD		(AR_IOCTL + 7)
#define	AR_CLIENT_NOTIFY	(AR_IOCTL + 8)
#define	AR_INTERFACE_UP		(AR_IOCTL + 9)
#define	AR_INTERFACE_DOWN	(AR_IOCTL + 10)
#define	AR_INTERFACE_ON		(AR_IOCTL + 12)
#define	AR_INTERFACE_OFF	(AR_IOCTL + 13)
#define	AR_DLPIOP_DONE		(AR_IOCTL + 14)
/*
 * This is not an ARP command per se, it is used to interface between
 * ARP and IP during close.
 */
#define	AR_ARP_CLOSING		(AR_IOCTL + 16)
#define	AR_ARP_EXTEND		(AR_IOCTL + 17)
#define	AR_IPMP_ACTIVATE	(AR_IOCTL + 18)
#define	AR_IPMP_DEACTIVATE	(AR_IOCTL + 19)

/* Both ace_flags and area_flags; must also modify arp.c in mdb */
#define	ACE_F_PERMANENT		0x0001
#define	ACE_F_PUBLISH		0x0002
#define	ACE_F_DYING		0x0004
#define	ACE_F_RESOLVED		0x0008
/* Using bit mask extraction from target address */
#define	ACE_F_MAPPING		0x0010
#define	ACE_F_MYADDR		0x0020	/* IP claims to own this address */
#define	ACE_F_UNVERIFIED	0x0040	/* DAD not yet complete */
#define	ACE_F_AUTHORITY		0x0080	/* check for duplicate MACs */
#define	ACE_F_DEFEND		0x0100	/* single transmit (area_flags only) */
#define	ACE_F_OLD		0x0200	/* should revalidate when IP asks */
#define	ACE_F_FAST		0x0400	/* fast probe enabled */
#define	ACE_F_DELAYED		0x0800	/* rescheduled on arp_defend_rate */
#define	ACE_F_DAD_ABORTED	0x1000	/* DAD was aborted on link down */

/* ared_flags */
#define	ARED_F_PRESERVE_PERM	0x0001	/* preserve permanent ace */

/* ARP Command Structures */

/* arc_t - Common command overlay */
typedef struct ar_cmd_s {
	uint32_t	arc_cmd;
	uint32_t	arc_name_offset;
	uint32_t	arc_name_length;
} arc_t;

/*
 * NOTE: when using area_t for an AR_ENTRY_SQUERY, the area_hw_addr_offset
 * field isn't what you might think. See comments in ip_multi.c where
 * the routine ill_create_squery() is called, and also in the routine
 * itself, to see how this field is used *only* when the area_t holds
 * an AR_ENTRY_SQUERY.
 */
typedef	struct ar_entry_add_s {
	uint32_t	area_cmd;
	uint32_t	area_name_offset;
	uint32_t	area_name_length;
	uint32_t	area_proto;
	uint32_t	area_proto_addr_offset;
	uint32_t	area_proto_addr_length;
	uint32_t	area_proto_mask_offset;
	uint32_t	area_flags;		/* Same values as ace_flags */
	uint32_t	area_hw_addr_offset;
	uint32_t	area_hw_addr_length;
} area_t;

typedef	struct ar_entry_delete_s {
	uint32_t	ared_cmd;
	uint32_t	ared_name_offset;
	uint32_t	ared_name_length;
	uint32_t	ared_proto;
	uint32_t	ared_proto_addr_offset;
	uint32_t	ared_proto_addr_length;
	uint32_t	ared_flags;
} ared_t;

typedef	struct ar_entry_query_s {
	uint32_t	areq_cmd;
	uint32_t	areq_name_offset;
	uint32_t	areq_name_length;
	uint32_t	areq_proto;
	uint32_t	areq_target_addr_offset;
	uint32_t	areq_target_addr_length;
	uint32_t	areq_flags;
	uint32_t	areq_sender_addr_offset;
	uint32_t	areq_sender_addr_length;
	uint32_t	areq_xmit_count;	/* 0 ==> cache lookup only */
	uint32_t	areq_xmit_interval; /* # of milliseconds; 0: default */
		/* # ofquests to buffer; 0: default */
	uint32_t	areq_max_buffered;
	uchar_t	areq_sap[8];		/* to insert in returned template */
} areq_t;

#define	AR_EQ_DEFAULT_XMIT_COUNT	6
#define	AR_EQ_DEFAULT_XMIT_INTERVAL	1000
#define	AR_EQ_DEFAULT_MAX_BUFFERED	4

/*
 * Structure used with AR_ENTRY_LLAQUERY to map from the link_addr
 * (in Neighbor Discovery option format excluding the option type and
 * length) to a hardware address.
 * The response has the same format as for an AR_ENTRY_SQUERY - an M_CTL with
 * arel_hw_addr updated.
 * An IPv6 address will be passed in AR_ENTRY_LLAQUERY so that atmip
 * can send it in AR_CLIENT_NOTIFY messages.
 */
typedef	struct ar_entry_llaquery_s {
	uint32_t	arel_cmd;
	uint32_t	arel_name_offset;
	uint32_t	arel_name_length;
	uint32_t	arel_link_addr_offset;
	uint32_t	arel_link_addr_length;
	uint32_t	arel_hw_addr_offset;
	uint32_t	arel_hw_addr_length;
	uint32_t	arel_ip_addr_offset;
	uint32_t	arel_ip_addr_length;
} arel_t;

typedef	struct ar_mapping_add_s {
	uint32_t	arma_cmd;
	uint32_t	arma_name_offset;
	uint32_t	arma_name_length;
	uint32_t	arma_proto;
	uint32_t	arma_proto_addr_offset;
	uint32_t	arma_proto_addr_length;
	uint32_t	arma_proto_mask_offset;
	uint32_t	arma_proto_extract_mask_offset;
	uint32_t	arma_flags;
	uint32_t	arma_hw_addr_offset;
	uint32_t	arma_hw_addr_length;
		/* Offset were we start placing */
	uint32_t	arma_hw_mapping_start;
					/* the mask&proto_addr */
} arma_t;

/* Structure used to notify ARP of changes to IPMP group topology */
typedef	struct ar_ipmp_event_s {
	uint32_t	arie_cmd;
	uint32_t	arie_name_offset;
	uint32_t	arie_name_length;
	char		arie_grifname[LIFNAMSIZ];
} arie_t;

/* Structure used to notify clients of interesting conditions. */
typedef struct ar_client_notify_s {
	uint32_t	arcn_cmd;
	uint32_t	arcn_name_offset;
	uint32_t	arcn_name_length;
	uint32_t	arcn_code;			/* Notification code. */
} arcn_t;

/* Client Notification Codes */
#define	AR_CN_BOGON	1
#define	AR_CN_ANNOUNCE	2
#define	AR_CN_READY	3		/* DAD complete; address usable */
#define	AR_CN_FAILED	4		/* DAD failed; address unusable */

/* ARP Header */
typedef struct arh_s {
	uchar_t	arh_hardware[2];
	uchar_t	arh_proto[2];
	uchar_t	arh_hlen;
	uchar_t	arh_plen;
	uchar_t	arh_operation[2];
	/* The sender and target hw/proto pairs follow */
} arh_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_ARP_H */
