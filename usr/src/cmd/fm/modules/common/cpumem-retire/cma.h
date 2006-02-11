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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CMA_H
#define	_CMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_api.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cma_page {
	struct cma_page *pg_next;	/* List of page retirements for retry */
	nvlist_t *pg_fmri;		/* FMRI for this page */
	uint64_t pg_addr;		/* Address of this page */
	char *pg_uuid;			/* UUID for this page's case */
	uint_t pg_nretries;		/* Number of retries so far for page */
} cma_page_t;

typedef struct cma {
	struct timespec cma_cpu_delay;	/* CPU offline retry interval */
	uint_t cma_cpu_tries;		/* Number of CPU offline retries */
	uint_t cma_cpu_dooffline;	/* Whether to offline CPUs */
	uint_t cma_cpu_forcedoffline;	/* Whether to do forced CPU offline */
	uint_t cma_cpu_doblacklist;	/* Whether to blacklist CPUs */
	cma_page_t *cma_pages;		/* List of page retirements for retry */
	hrtime_t cma_page_curdelay;	/* Current retry sleep interval */
	hrtime_t cma_page_mindelay;	/* Minimum retry sleep interval */
	hrtime_t cma_page_maxdelay;	/* Maximum retry sleep interval */
	id_t cma_page_timerid;		/* fmd timer ID for retry sleep */
	uint_t cma_page_doretire;	/* Whether to retire pages */
	uint_t cma_page_maxretries;	/* Maximum retry on page retires */
} cma_t;

typedef struct cma_stats {
	fmd_stat_t cpu_flts;		/* Successful offlines */
	fmd_stat_t cpu_fails;		/* Failed offlines */
	fmd_stat_t cpu_blfails;		/* Failed blacklists */
	fmd_stat_t cpu_supp;		/* Suppressed offlines */
	fmd_stat_t cpu_blsupp;		/* Suppressed blacklists */
	fmd_stat_t page_flts;		/* Successful page retires */
	fmd_stat_t page_fails;		/* Failed page retires */
	fmd_stat_t page_supp;		/* Suppressed retires */
	fmd_stat_t page_nonent;		/* Retires for non-present pages */
	fmd_stat_t page_retmax;		/* Retires for page reached max */
	fmd_stat_t bad_flts;		/* Malformed faults */
	fmd_stat_t nop_flts;		/* Inapplicable faults */
	fmd_stat_t auto_flts;		/* Auto-close faults */
} cma_stats_t;

extern cma_stats_t cma_stats;
extern cma_t cma;

extern void cma_cpu_retire(fmd_hdl_t *, nvlist_t *, nvlist_t *, const char *);

extern void cma_page_retire(fmd_hdl_t *, nvlist_t *, nvlist_t *, const char *);
extern void cma_page_retry(fmd_hdl_t *);
extern void cma_page_fini(fmd_hdl_t *);

extern int cma_set_errno(int);

#ifdef __cplusplus
}
#endif

#endif /* _CMA_H */
