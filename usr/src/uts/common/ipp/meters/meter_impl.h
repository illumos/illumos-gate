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

#ifndef _IPP_METERS_METER_IMPL_H
#define	_IPP_METERS_METER_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/spl.h>
#include <ipp/ipp.h>
#include <inet/ipp_common.h>
#include <ipp/meters/meter.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for implementation of all the metering modules */

#ifdef	_KERNEL

/* for a colour aware meter */
enum meter_colour {
	TOKENMT_GREEN = 0x01,
	TOKENMT_YELLOW = 0x02,
	TOKENMT_RED = 0x04
};

/* If yellow action is not provided, set it to infinity */
#define	TOKENMT_NO_ACTION	0x7fffffff

#define	METER_SEC_TO_NSEC	1000000000
#define	METER_MSEC_TO_NSEC	1000000

#define	_TOKENMT_DEBUG
#define	_TSWTCL_DEBUG

#ifdef _TOKENMT_DEBUG
#define	tokenmt0dbg(a)		printf a
#define	tokenmt1dbg(a)		if (tokenmt_debug > 2) printf a
#define	tokenmt2dbg(a)		if (tokenmt_debug > 3) printf a
#else
#define	tokenmt0dbg(a)		/*  */
#define	tokenmt1dbg(a)		/*  */
#define	tokenmt2dbg(a)		/*  */
#endif /* _TOKENMT_DEBUG */

#ifdef _TSWTCL_DEBUG
#define	tswtcl0dbg(a)		printf a
#define	tswtcl1dbg(a)		if (tswtcl_debug > 2) printf a
#define	tswtcl2dbg(a)		if (tswtcl_debug > 3) printf a
#else
#define	tswtcl0dbg(a)		/*  */
#define	tswtcl1dbg(a)		/*  */
#define	tswtcl2dbg(a)		/*  */
#endif /* _TSWTCL_DEBUG */

#define	SRTCL_TOKENMT		0x01
#define	TRTCL_TOKENMT		0x02

#define	DROP_PRECD_MASK		0x07

/* Stat structure for the tokenmts */
typedef struct meter_stat_t {
	ipp_named_t red_bits;
	ipp_named_t yellow_bits;
	ipp_named_t green_bits;
	ipp_named_t red_packets;
	ipp_named_t yellow_packets;
	ipp_named_t green_packets;
	ipp_named_t epackets;
} meter_stat_t;

#define	TOKENMT_STATS_STRING	"tokenmt statistics"
#define	TSWTCL_STATS_STRING	"tswtclmtr statistics"
#define	METER_STATS_COUNT	7

/* Configuration paratokenmts for tokenmt */
typedef struct tokenmt_cfg_s {

	/* Next action for Green, Yellow and Red packets */
	ipp_action_id_t red_action;
	ipp_action_id_t yellow_action;
	ipp_action_id_t green_action;

	/* Meter type  - SRTCL_TOKENMT or TRTCL_TOKENMT */
	uint_t tokenmt_type;

	/* Committed rate in Kb/sec */
	uint32_t committed_rate;
	uint32_t peak_rate;

	/* Committed and Peak burst sizes in bits */
	uint32_t committed_burst;
	uint32_t peak_burst;

	/* Needs stats or not */
	boolean_t stats;

	/* Meter Colour aware or not */
	boolean_t colour_aware;

	/* Meter dscp to colour mapping, if colour aware */
	enum meter_colour dscp_to_colour[64];

	/* timer */
	timeout_id_t timer;
}tokenmt_cfg_t;

typedef struct tokenmt_data_s {

	/* stats for this instance */
	ipp_stat_t *stats;

	/* # packets classified as Red, Yellow and Green for this instance */
	uint64_t red_packets;
	uint64_t yellow_packets;
	uint64_t green_packets;
	uint64_t red_bits;
	uint64_t yellow_bits;
	uint64_t green_bits;
	uint64_t epackets;

	/* configured paratokenmts */
	tokenmt_cfg_t *cfg_parms;

	/* No. of tokens at the committed and peak burst */
	uint64_t committed_tokens;
	uint64_t peak_tokens;

	/* For replenishing the token buckets */
	uint64_t last_seen;

	/* Lock to protect data structures */
	kmutex_t tokenmt_lock;
} tokenmt_data_t;

typedef struct tswtcl_cfg_s {

	/* Next action for Green, Yellow and Red packets */
	ipp_action_id_t red_action;
	ipp_action_id_t yellow_action;
	ipp_action_id_t green_action;

	/* Committed and Peak rates in KB/sec */
	uint32_t committed_rate;
	uint32_t peak_rate;

	/* Window size in ms */
	uint32_t window;

	/* Need stats or not */
	boolean_t stats;

	/* For aiding computations */
	uint64_t nsecwindow;
	uint32_t pminusc;
}tswtcl_cfg_t;

typedef struct tswtcl_data_s {

	/* stats for this instance */
	ipp_stat_t *stats;

	/* Computed average rate */
	uint32_t avg_rate;

	/* Front of the sliding window */
	hrtime_t win_front;

	/* # packets classified as Red, Yellow and Green for this instance */
	uint64_t red_packets;
	uint64_t yellow_packets;
	uint64_t green_packets;
	uint64_t red_bits;
	uint64_t yellow_bits;
	uint64_t green_bits;
	uint64_t epackets;

	/* Configured paramters */
	tswtcl_cfg_t *cfg_parms;

	/* Lock to protect data structures */
	kmutex_t tswtcl_lock;
} tswtcl_data_t;

#define	TOKENMT_DATA_SZ		sizeof (tokenmt_data_t)
#define	TOKENMT_CFG_SZ		sizeof (tokenmt_cfg_t)
#define	TSWTCL_DATA_SZ		sizeof (tswtcl_data_t)
#define	TSWTCL_CFG_SZ		sizeof (tswtcl_cfg_t)

extern int tokenmt_process(mblk_t **, tokenmt_data_t *, ipp_action_id_t *);
extern int tswtcl_process(mblk_t **, tswtcl_data_t *, ipp_action_id_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _IPP_METERS_METER_IMPL_H */
