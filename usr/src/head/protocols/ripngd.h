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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Routing Information Protocol for IPv6 (RIPng)
 * as specfied by RFC 2080.
 */

#ifndef _PROTOCOLS_RIPNGD_H
#define	_PROTOCOLS_RIPNGD_H

#ifdef	__cplusplus
extern "C" {
#endif

struct netinfo6 {
	struct in6_addr	rip6_prefix;		/* destination prefix */
	uint16_t	rip6_route_tag;		/* route tag */
	uint8_t		rip6_prefix_length;	/* destination prefix length */
	uint8_t		rip6_metric;		/* cost of route */
};

struct rip6 {
	uint8_t		rip6_cmd;		/* request/response */
	uint8_t		rip6_vers;		/* protocol version # */
	uint16_t	rip6_res1;		/* pad to 32-bit boundary */
	struct netinfo6	rip6_nets[1];		/* variable length... */
};

#define	RIPVERSION6		1

/*
 * Packet types.
 */
#define	RIPCMD6_REQUEST		1	/* want info - from suppliers */
#define	RIPCMD6_RESPONSE	2	/* responding to request */

#define	IPPORT_ROUTESERVER6	521

#ifdef	__cplusplus
}
#endif

#endif	/* _PROTOCOLS_RIPNGD_H */
