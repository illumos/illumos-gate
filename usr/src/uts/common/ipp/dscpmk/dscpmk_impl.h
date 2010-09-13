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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPP_DSCPMK_DSCPMK_IMPL_H
#define	_IPP_DSCPMK_DSCPMK_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <ipp/ipp.h>
#include <ipp/dscpmk/dscpmk.h>
#include <inet/ipp_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for implementation of DS/ToS dscp marker ipp action module */

#define	_DSCPMK_DEBUG

/* Mask out all but the Traffic class for IPv6 header */
#ifdef _BIG_ENDIAN
#define	TCLASS_MASK		0xF00FFFFF
#else
#define	TCLASS_MASK		0xFFFF0FF0
#endif

/* Array count for dscp_policed_array 0-63 */
#define	DSCPMK_ARRAY_COUNT		64
/* During modification, entries that are unchanged are signified with -1 */
#define	DSCPMK_UNCHANGED_DSCP		-1

#ifdef _DSCPMK_DEBUG
#include <sys/debug.h>
#define	dscpmk0dbg(a)		printf a
#define	dscpmk1dbg(a)		if (dscpmk_debug > 2) printf a
#define	dscpmk2dbg(a)		if (dscpmk_debug > 3) printf a
#else
#define	dscpmk0dbg(a)
#define	dscpmk1dbg(a)
#define	dscpmk2dbg(a)
#endif /* _DSCPMK_DEBUG */

/* dscpmk stats information available using kstats */
typedef struct dscpmk_stat_s {
	ipp_named_t	npackets;	/* no. of pkts seen by this instance */
	ipp_named_t	dscp_changed;	/* no. of pkts. with dscp changed */
	ipp_named_t	dscp_unchanged;	/* no. of pkts. with dscp unchanged */
	ipp_named_t	ipackets;	/* no. of pkts. not processed */
	ipp_named_t	epackets;	/* no. of pkts. in error */
} dscpmk_stat_t;

typedef struct dscpmk_dscp_stats_s {
	ipp_named_t	dscp;		/* dscp value */
	ipp_named_t	npackets;	/* no. of packets for this dscp */
} dscpmk_dscp_stats_t;

/*
 * If the above structure is changed, the count will have to be updated
 * accordingly.
 */
#define	DSCPMK_STATS_COUNT		5
#define	DSCPMK_STATS_STRING		"dscpmk_stats"

#define	DSCPMK_DSCP_STATS_COUNT		2

typedef struct dscp_stats_s {
	boolean_t	present;	/* Stats present for this DSCP */
	uint64_t	npackets;	/* no. of packets for this DSCP */
	ipp_stat_t 	*stats;		/* stats for this DSCP */
} dscp_stats_t;

/* Per-instance structure */
typedef struct dscpmk_data_s {

	ipp_action_id_t next_action; 	/* action id of next action */
	ipp_stat_t 	*stats;		/* structure for storing stats */

	/* inbound DSCP -> outbound DSCP mapping table */
	uint8_t 	dscp_map[DSCPMK_ARRAY_COUNT];

	/* Minimal stats */
	boolean_t 	summary_stats;
	uint64_t 	npackets;	/* no. of packets processed by action */
	uint64_t 	changed;	/* packets with DSCP changed */
	uint64_t 	unchanged;	/* packets with DSCP unchanged */
	uint64_t 	ipackets;	/* packets not processed */
	uint64_t 	epackets;	/* packets in error */

	/* per-DSCP stats */
	boolean_t 	detailed_stats;
	/* Stats count per DSCP value 0-63 */
	dscp_stats_t	dscp_stats[DSCPMK_ARRAY_COUNT];
} dscpmk_data_t;

#define	DSCPMK_DATA_SZ		sizeof (dscpmk_data_t)

#ifdef	_KERNEL
extern int dscpmk_process(mblk_t **, dscpmk_data_t *, ip_proc_t);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _IPP_DSCPMK_DSCPMK_IMPL_H */
