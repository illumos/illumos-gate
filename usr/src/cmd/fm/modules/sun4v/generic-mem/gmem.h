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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GMEM_H
#define	_GMEM_H

#include <stdarg.h>
#include <fm/fmd_api.h>
#include <sys/param.h>

#include <gmem_util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	GMEM_STAT_BUMP(name)	gmem.gm_stats->name.fmds_value.ui64++
#define	GMEM_FLTMAXCONF	95

typedef struct gmem_stat {
	fmd_stat_t bad_mem_resource;	/* # of malformed hc-scheme resource */
	fmd_stat_t bad_close;		/* # of inapplicable case closes */
	fmd_stat_t old_erpt;		/* # of erpts for removed components */
	fmd_stat_t dimm_creat;		/* # of DIMM state structs created */
	fmd_stat_t page_creat;		/* # of page state structs created */
	fmd_stat_t ce_unknown;		/* # of unknown CEs seen */
	fmd_stat_t ce_interm;		/* # of intermittent CEs seen */
	fmd_stat_t ce_clearable_persis;	/* # of clearable persistent CEs seen */
	fmd_stat_t ce_sticky;		/* # of sticky CEs seen */
} gmem_stat_t;

typedef struct gmem_serd {
	const char *cs_name;
	uint_t cs_n;
	hrtime_t cs_t;
} gmem_serd_t;

typedef struct gmem {
	gmem_list_t gm_dimms;		/* List of DIMM state structures */
	gmem_list_t gm_pages;		/* List of page state structures */
	gmem_stat_t *gm_stats;		/* Module statistics */
	size_t gm_pagesize;		/* Page size, in bytes */
	uint64_t gm_pagemask;		/* Mask for page alignments */
	uint32_t gm_max_retired_pages;  /* max num retired pages */
	uint32_t gm_ce_n;		/* serd n */
	uint64_t gm_ce_t;		/* serd t */
	uint32_t gm_filter_ratio;	/* serd filter ratio */
} gmem_t;

extern gmem_t gmem;

#ifdef __cplusplus
}
#endif

#endif /* _GMEM_H */
