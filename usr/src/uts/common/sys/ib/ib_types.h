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
 */

#ifndef _SYS_IB_IB_TYPES_H
#define	_SYS_IB_IB_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ib_types.h
 *
 * Data definitions for all IBTA primitive data types.
 */
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Addressing types
 *	See Chapter 4 of the IBTA Volume 1 IB specification for more details.
 */
#define	IB_EUI64_COMPANYID_MASK		0x0000000000FFFFFF
#define	IB_EUI64_COMPANYID_SHIFT	40
#define	IB_EUI64_IDENTIFIER_MASK	0x000000FFFFFFFFFF

/* LID Ranges */
#define	IB_LID_UC_FIRST			0x0001
#define	IB_LID_UC_LAST			0xBFFF
#define	IB_LID_MC_FIRST			0xC000
#define	IB_LID_MC_LAST			0xFFFE
#define	IB_LID_PERMISSIVE		0xFFFF

/* Unicast GID & Multicast GID */
typedef	uint64_t	ib_guid_t;	/* EUI-64 GUID */
typedef	uint64_t	ib_sn_prefix_t;	/* Subnet Prefix */

typedef struct ib_ucast_gid_s {
	ib_sn_prefix_t	ugid_prefix;	/* GID prefix */
	ib_guid_t	ugid_guid;	/* Port GUID */
} ib_ucast_gid_t;

typedef struct ib_mcast_gid_s {
	uint32_t	mcast_gid_prefix; /* flags, scope, and signature */
	uint8_t		mcast_gid_bytes[12];
} ib_mcast_gid_t;

typedef struct ib_gid_s {
	union {
		ib_ucast_gid_t	ucast_gid;	/* unicast gid */
		ib_mcast_gid_t	mcast_gid;	/* multicast gid */
	} gid;
} ib_gid_t;

#define	gid_prefix	gid.ucast_gid.ugid_prefix
#define	gid_guid	gid.ucast_gid.ugid_guid

#define	mgid_prefix	gid.mcast_gid.mcast_gid_prefix
#define	mgid_bytes	gid.mcast_gid.mcast_gid_bytes

#define	IB_GID_DEFAULT_PREFIX		0xFE80000000000000
#define	IB_GID_SUBNET_LOCAL_PREFIX	IB_GID_DEFAULT_PREFIX
#define	IB_GID_SITE_LOCAL_PREFIX	0xFEC0000000000000
#define	IB_GID_SITE_LOCAL_SUBNET_MASK	0x000000000000FFFF

/* Multicast GID. */
#define	IB_MCGID_PREFIX			0xFF000000
#define	IB_MCGID_TRANSIENT_FLAG		0x00100000

/* Multicast Address Scope. */
#define	IB_MC_SCOPE_SUBNET_LOCAL	0x02
#define	IB_MC_SCOPE_SITE_LOCAL		0x05
#define	IB_MC_SCOPE_ORG_LOCAL		0x08
#define	IB_MC_SCOPE_GLOBAL		0x0E

/* Multicast Join State. */
#define	IB_MC_JSTATE_FULL		0x01	/* Full Member */
#define	IB_MC_JSTATE_NON		0x02	/* Non Member */
#define	IB_MC_JSTATE_SEND_ONLY_NON	0x04	/* Send Only Non Member */

#define	IB_MC_QPN			0xFFFFFF	/* Multicast QPN */

/*
 * IP-on-IB Multicast GIDs
 *
 * IPV4 gid_prefix:
 *   IB_MCGID_IPV4_PREFIX
 *   IB_MCGID_SCOPE_MASK
 *   IB_MCGID_IP_PKEY_MASK
 * IPV4 gid_guid:
 *   IB_MCGID_IPV4_LOW_GROUP_MASK
 *
 * IPV6 gid_prefix:
 *   IB_MCGID_IPV6_PREFIX
 *   IB_MCGID_SCOPE_MASK
 *   IB_MCGID_IP_PKEY_MASK
 *   IB_MCGID_IPV6_HI_GROUP_MASK
 * IPV6 gid_guid:
 *   entire gid_guid holds low part of group ID
 */
#define	IB_MCGID_IPV4_PREFIX		0xFF10401B
#define	IB_MCGID_IPV6_PREFIX		0xFF10601B
#define	IB_MCGID_SA_PREFIX		0xFF10A01B

typedef	uint16_t	ib_lid_t;	/* Port Local ID (LID) */
typedef	uint8_t		ib_path_bits_t;	/* From 0 to 7 low order bits of LID */

/*
 * PKeys and QKeys
 */
#define	IB_PKEY_DEFAULT_FULL		0xFFFF
#define	IB_PKEY_DEFAULT_LIMITED		0x7FFF
#define	IB_PKEY_INVALID_FULL		0x8000
#define	IB_PKEY_INVALID_LIMITED		0x0000
#define	IB_GSI_QKEY			0x80010000
#define	IB_PRIVILEGED_QKEY_BIT		0x80000000

typedef	uint16_t	ib_pkey_t;	/* P_Key */
typedef	uint32_t	ib_qkey_t;	/* Q_Key */
typedef	uint16_t	ib_pkey_cntr_t;
typedef	uint16_t	ib_qkey_cntr_t;

/*
 * General IBT types
 */
typedef uint64_t	ib_smkey_t;	/* subnet manager key */

typedef	uint16_t	ib_ethertype_t;	/* Ethertype */
typedef	uint32_t	ib_qpn_t;	/* 24 bit QP number */
typedef	uint32_t	ib_eecn_t;	/* 24 bit EEC number */

#define	IB_QPN_MASK	0xFFFFFF

typedef	uint32_t	ib_msglen_t;	/* message length */

typedef	uint64_t	ib_vaddr_t;	/* registered memory Virtual Address */
typedef	uint64_t	ib_memlen_t;	/* registered memory length */

typedef	uint64_t	ib_svc_id_t;	/* CM Service ID */

#define	IB_SVC_NAME_LEN	64		/* Maximum length of Service Name, */
					/* which includes a terminating NULL */
#define	IB_SVC_DATA_LEN	64		/* Length of Service Data */

/* MTU Size */
typedef enum {
	IB_MTU_NOT_SPECIFIED	= 0,
	IB_MTU_256		= 1,	/* 256 bytes */
	IB_MTU_512		= 2,	/* 512 bytes */
	IB_MTU_1K		= 3,	/* 1k bytes */
	IB_MTU_2K		= 4,	/* 2k bytes */
	IB_MTU_4K		= 5	/* 4k bytes */
} ib_mtu_t;

typedef	uint8_t			ib_time_t;	/* 6 bits of timeout exponent */
#define	IB_TIME_EXP_MASK	0x3F		/* time = 4.096us * 2 ^ exp */

/*
 * Infiniband Identifiers, based on Administration Group Number (AGN) codes
 * there are different types of Service IDs which identifies the group.
 * The first byte of the Service ID comprises of AGN field and following
 * specifies the values for AGN field.
 *
 *	0x0		- IBTA assigned Ids (WellKnown)
 *	0x1		- IETF (any category)
 *	0x2		- Locally assigned Ids with limited cacheability
 *	0x10 to 0x1f	- External Organizations assigned Ids (Well Known)
 *	others		- Reserved
 */
#define	IB_SID_MASK		0x00FFFFFFFFFFFFFF
#define	IB_SID_AGN_MASK		0xFF00000000000000

#define	IB_SID_AGN_IBTA		0x0000000000000000
#define	IB_SID_AGN_IETF		0x0100000000000000
#define	IB_SID_AGN_LOCAL	0x0200000000000000

#define	IB_SID_IPADDR_PREFIX		0x0000000001000000	/* Byte 4 */
#define	IB_SID_IPADDR_PREFIX_MASK	0xFFFFFFFFFE000000
#define	IB_SID_IPADDR_IPNUM_MASK	0x0000000000FF0000	/* Byte 5 */
#define	IB_SID_IPADDR_PORTNUM_MASK	0x000000000000FFFF	/* Byte 6 & 7 */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IB_TYPES_H */
