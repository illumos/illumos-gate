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

#ifndef _IPP_IPGPC_CLASSIFIER_H
#define	_IPP_IPGPC_CLASSIFIER_H

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <ipp/ipgpc/filters.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for classifier implementation for ipgpc */

#define	IPGPC_DEBUG

#ifdef IPGPC_DEBUG
#include <sys/debug.h>

#define	ipgpc0dbg(a)	printf a
#define	ipgpc1dbg(a)	if (ipgpc_debug > 2) printf a
#define	ipgpc2dbg(a)	if (ipgpc_debug > 3) printf a
#define	ipgpc3dbg(a)	if (ipgpc_debug > 4) printf a
#define	ipgpc4dbg(a)	if (ipgpc_debug > 5) printf a
#else
#define	ipgpc0dbg(a)		/*  */
#define	ipgpc1dbg(a)		/*  */
#define	ipgpc2dbg(a)		/*  */
#define	ipgpc3dbg(a)		/*  */
#define	ipgpc4dbg(a)		/*  */
#endif /* IPGPC_DEBUG */

#define	BUMP_STATS(x)		++(x)
#define	SET_STATS(x, y)		x = y
#define	UPDATE_STATS(x, y)	x += y

/* packet structure */
typedef struct ipgpc_packet_s {
	/* IP Addresses are represented as IPV6 address structures */
	in6_addr_t saddr;	/* IP source address */
	in6_addr_t daddr;	/* IP destination address */
	uint16_t sport;		/* source port */
	uint16_t dport;		/* destination port */
	uint8_t proto;		/* protocol field */
	uint8_t dsfield;	/* Traffic class/DS */
	uid_t uid;		/* user id for packet */
	projid_t projid;	/* project id for packet */
	uint_t if_index;	/* interface index */
	uint32_t direction;	/* packet direction */
	uint_t len;		/* length of packet */
} ipgpc_packet_t;

extern int ipgpc_debug;
extern boolean_t ipgpc_action_exist; /* if an ipgpc action exists */

extern ipgpc_class_t *ipgpc_classify(int, ipgpc_packet_t *);
extern void parse_packet(ipgpc_packet_t *, mblk_t *);
extern void parse_packet6(ipgpc_packet_t *, mblk_t *);
extern void print_packet(int, ipgpc_packet_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_IPGPC_CLASSIFIER_H */
