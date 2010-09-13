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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CDA_H
#define	_CDA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_api.h>

#include <sys/types.h>

#define	DP_MAX_BUF	16		/* max len of general purpose buffer */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cda {
	struct timespec cda_cpu_delay;	/* CPU offline retry interval */
	uint_t cda_cpu_tries;		/* Number of CPU offline retries */
	uint_t cda_cpu_dooffline;	/* Whether to offline CPUs */
	uint_t cda_cpu_forcedoffline;	/* Whether to do forced CPU offline */
} cda_t;

typedef struct cda_stats {
	fmd_stat_t dp_offs;		/* Successful offlines */
	fmd_stat_t dp_fails;		/* Failed offlines */
	fmd_stat_t dp_supp;		/* Suppressed offlines */
	fmd_stat_t bad_flts;		/* Malformed faults */
	fmd_stat_t nop_flts;		/* Inapplicable faults */
} cda_stats_t;

extern cda_stats_t cda_stats;
extern cda_t cda;

extern void cda_dp_retire(fmd_hdl_t *, nvlist_t *, nvlist_t *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _CDA_H */
