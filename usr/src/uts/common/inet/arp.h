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

/* Both ace_flags; must also modify arp.c in mdb */
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
