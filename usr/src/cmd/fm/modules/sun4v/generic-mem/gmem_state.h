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

#ifndef _GMEM_STATE_H
#define	_GMEM_STATE_H

/*
 * Case management and saved state restoration
 */

#include <gmem_util.h>

#include <fm/fmd_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Our maximum persistent buffer name length, used to allocate fixed-size
 * arrays for name storage.
 */
/*
 * The current name DIMM_+serial number
 */
#define	GMEM_BUFNMLEN		48

/* gmem_evdisp_t, gmem_evdisp_stat_t, and gmem_evdisp_names must be in sync */
typedef enum gmem_evdisp {
	GMEM_EVD_OK,
	GMEM_EVD_BAD,
	GMEM_EVD_UNUSED,
	GMEM_EVD_REDUND
} gmem_evdisp_t;

/*
 * Each handled ereport type has four statistics, designed to indicate the
 * eventual disposition of the ereport.
 */
typedef struct gmem_evdisp_stat {
	fmd_stat_t evs_ok;		/* # of erpts processed successfully */
	fmd_stat_t evs_bad;		/* # of malformed ereports */
	fmd_stat_t evs_unused;		/* # of erpts unusable or not needed */
	fmd_stat_t evs_redund;		/* # of erpts already explained */
} gmem_evdisp_stat_t;

/* Must be in sync with gmem_case_restorers */
typedef enum gmem_nodetype {
	GMEM_NT_DIMM = 1,
	GMEM_NT_PAGE
} gmem_nodetype_t;

/*
 * Must be in sync with gmem_case_closers.  Additional types must be
 * appended to this enum otherwise interpretation of existing logs
 * and checkpoints will be confused.
 */
typedef enum gmem_ptrsubtype {
	GMEM_PTR_DIMM_CASE = 1,
	GMEM_PTR_PAGE_CASE
} gmem_ptrsubtype_t;

/*
 * There are three types of general-purpose buffers, used to track DIMMs,
 * and pages.  Created on-demand as ereports arrive, one buffer is created for
 * each thing tracked.  The general-purpose buffers are used to track common
 * state, and are used to support case-specific buffers.  Each open case has
 * a case-specific pointer buffer, used to aid in the rediscovery of the
 * associated general-purpose buffer.  When restoration begins, we iterate
 * through each of the open cases, restoring the case-specific pointer buffers
 * for each.  The pointer buffers are then used to restore the general-purpose
 * buffers.
 */

typedef	struct gmem_case_ptr {
	gmem_nodetype_t ptr_type;	/* The type of associated G.P. buffer */
	gmem_ptrsubtype_t ptr_subtype;	/* The case within the G.P. buffer */
	char ptr_name[GMEM_BUFNMLEN];	/* G.P. buffer name */
} gmem_case_ptr_t;

/*
 * All general-purpose buffers begin with a common header.  This header contains
 * identification information used in the construction of new cases.
 *
 * Note that versioned structs depend upon the size of
 * this struct remaining fixed.
 */
typedef struct gmem_header {
	gmem_list_t hdr_list;		/* List of G.P. structs of this type */
	gmem_nodetype_t hdr_nodetype;	/* Type of this G.P. struct */
	char hdr_bufname[GMEM_BUFNMLEN]; /* G.P. buffer name */
} gmem_header_t;

/*
 * Per-case-subtype case closing routines.  Stored in per-case state when the
 * case is generated, and regenerated from saved state upon restore.
 */
typedef void gmem_case_closer_f(fmd_hdl_t *, void *);
typedef void *gmem_case_restorer_f(fmd_hdl_t *, fmd_case_t *,
    gmem_case_ptr_t *);

typedef struct gmem_case_closer {
	gmem_case_closer_f *cl_func;
	void *cl_arg;
} gmem_case_closer_t;

typedef struct gmem_case {
	fmd_case_t *cc_cp;
	char *cc_serdnm;
} gmem_case_t;

/*
 * Utility functions which ease the management of cases.
 */
extern fmd_case_t *gmem_case_create(fmd_hdl_t *, gmem_header_t *,
    gmem_ptrsubtype_t, const char **);
extern void gmem_case_redirect(fmd_hdl_t *, fmd_case_t *, gmem_ptrsubtype_t);
extern void gmem_case_fini(fmd_hdl_t *, fmd_case_t *, int);
extern void gmem_case_restore(fmd_hdl_t *, gmem_case_t *, fmd_case_t *, char *);

extern int gmem_state_restore(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _GMEM_STATE_H */
