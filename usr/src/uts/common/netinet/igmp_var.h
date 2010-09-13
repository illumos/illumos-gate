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

#ifndef	_NETINET_IGMP_VAR_H
#define	_NETINET_IGMP_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internet Group Management Protocol (IGMP),
 * implementation-specific definitions.
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Ajit Thyagarajan, PARC, August 1994.
 *
 * MULTICAST 3.5.1.1
 */

struct igmpstat {
	uint_t	igps_rcv_total;		/* total IGMP messages received    */
	uint_t	igps_rcv_tooshort;	/* received with too few bytes	   */
	uint_t	igps_rcv_badsum;	/* received with bad checksum	   */
	uint_t	igps_rcv_queries;	/* received membership queries	   */
	uint_t	igps_rcv_badqueries;	/* received invalid queries	   */
	uint_t	igps_rcv_reports;	/* received membership reports	   */
	uint_t	igps_rcv_badreports;	/* received invalid reports	   */
	uint_t	igps_rcv_ourreports;	/* received reports for our groups */
	uint_t	igps_snd_reports;	/* sent membership reports	   */
};

#ifdef _KERNEL
/*
 * slowtimo interval used for both IGMP and MLD
 */
#define	MCAST_SLOWTIMO_INTERVAL	10000	/* milliseconds */


/*
 * Macro to compute a random timer value between 1 and maxticks.
 * Include <sys/random.h> for random_get_pseudo_bytes() declaration.
 */
#include <sys/random.h>
#define	MCAST_RANDOM_DELAY(timer, maxticks)				      \
	/* uint_t timer; int maxticks */				      \
	(void) random_get_pseudo_bytes((uint8_t *)&(timer), sizeof (uint_t)); \
	(timer) = ((uint_t)(timer) % (maxticks)) + 1

/*
 * States for IGMPv2's leave processing
 */
#define	IGMP_OTHERMEMBER			0
#define	IGMP_IREPORTEDLAST			1

/*
 * We must remember what version the subnet's querier is.
 */
#define	IGMP_V1_ROUTER				0
#define	IGMP_V2_ROUTER				1
#define	IGMP_V3_ROUTER				2

/*
 * Map MLD versions to corresponding IGMP versions
 */
#define	MLD_V1_ROUTER				IGMP_V2_ROUTER
#define	MLD_V2_ROUTER				IGMP_V3_ROUTER

/*
 * Default values for various IGMPv3/MLDv2 values
 */
#define	MCAST_DEF_ROBUSTNESS			2
#define	MCAST_QUERY_RESP_INTERVAL		10	/* in seconds */
#define	MCAST_DEF_QUERY_INTERVAL		125	/* in seconds */
#define	MCAST_DEF_QUERY_RESP_INTERVAL		100	/* in tenths of secs */
#define	MCAST_DEF_UNSOL_RPT_INTERVAL		1	/* in seconds */

/*
 * IGMP and MLD mandate a TTL/Hop Limit of 1 for protocol messages
 */
#define	IGMP_TTL	1
#define	MLD_HOP_LIMIT	1

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IGMP_VAR_H */
