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

#ifndef _CMD_STATE_H
#define	_CMD_STATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Case management and saved state restoration
 */

#include <cmd_list.h>

#include <fm/fmd_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Our maximum persistent buffer name length, used to allocate fixed-size
 * arrays for name storage.
 */
#define	CMD_BUFNMLEN		48

/* cmd_evdisp_t, cmd_evdisp_stat_t, and cmd_evdisp_names must be in sync */
typedef enum cmd_evdisp {
	CMD_EVD_OK,
	CMD_EVD_BAD,
	CMD_EVD_UNUSED,
	CMD_EVD_REDUND
} cmd_evdisp_t;

/*
 * Each handled ereport type has four statistics, designed to indicate the
 * eventual disposition of the ereport.
 */
typedef struct cmd_evdisp_stat {
	fmd_stat_t evs_ok;		/* # of erpts processed successfully */
	fmd_stat_t evs_bad;		/* # of malformed ereports */
	fmd_stat_t evs_unused;		/* # of erpts unusable or not needed */
	fmd_stat_t evs_redund;		/* # of erpts already explained */
} cmd_evdisp_stat_t;

/* Must be in sync with cmd_case_restorers */
typedef enum cmd_nodetype {
	CMD_NT_CPU = 1,
	CMD_NT_DIMM,
	CMD_NT_BANK,
	CMD_NT_PAGE,
#ifdef sun4u
	CMD_NT_DP,
	CMD_NT_LxCACHE
#endif
#ifdef sun4v
	CMD_NT_BRANCH
#endif
} cmd_nodetype_t;

/*
 * Must be in sync with cmd_case_closers.  Additional types must be
 * appended to this enum otherwise interpretation of existing logs
 * and checkpoints will be confused.
 */
typedef enum cmd_ptrsubtype {
	CMD_PTR_CPU_ICACHE = 1,
	CMD_PTR_CPU_DCACHE,
	CMD_PTR_CPU_PCACHE,
	CMD_PTR_CPU_ITLB,
	CMD_PTR_CPU_DTLB,
	CMD_PTR_CPU_L2DATA,
	CMD_PTR_CPU_L2DATA_UERETRY,	/* no longer used */
	CMD_PTR_CPU_L2TAG,
	CMD_PTR_CPU_L3DATA,
	CMD_PTR_CPU_L3DATA_UERETRY,	/* no longer used */
	CMD_PTR_CPU_L3TAG,
	CMD_PTR_DIMM_CASE,
	CMD_PTR_BANK_CASE,
	CMD_PTR_PAGE_CASE,
	CMD_PTR_CPU_FPU,
	CMD_PTR_CPU_XR_RETRY,
	CMD_PTR_CPU_IREG,
	CMD_PTR_CPU_FREG,
	CMD_PTR_CPU_MAU,
	CMD_PTR_CPU_L2CTL,
	CMD_PTR_DP_CASE,
	CMD_PTR_DP_PAGE_DEFER,
	CMD_PTR_CPU_INV_SFSR,
	CMD_PTR_CPU_UE_DET_CPU,
	CMD_PTR_CPU_UE_DET_IO,
	CMD_PTR_CPU_MTLB,
	CMD_PTR_CPU_TLBP,
	CMD_PTR_CPU_UGESR_INV_URG,
	CMD_PTR_CPU_UGESR_CRE,
	CMD_PTR_CPU_UGESR_TSB_CTX,
	CMD_PTR_CPU_UGESR_TSBP,
	CMD_PTR_CPU_UGESR_PSTATE,
	CMD_PTR_CPU_UGESR_TSTATE,
	CMD_PTR_CPU_UGESR_IUG_F,
	CMD_PTR_CPU_UGESR_IUG_R,
	CMD_PTR_CPU_UGESR_SDC,
	CMD_PTR_CPU_UGESR_WDT,
	CMD_PTR_CPU_UGESR_DTLB,
	CMD_PTR_CPU_UGESR_ITLB,
	CMD_PTR_CPU_UGESR_CORE_ERR,
	CMD_PTR_CPU_UGESR_DAE,
	CMD_PTR_CPU_UGESR_IAE,
	CMD_PTR_CPU_UGESR_UGE,
	CMD_PTR_CPU_MISC_REGS,
	CMD_PTR_CPU_LFU,
	CMD_PTR_BRANCH_CASE,
	CMD_PTR_LxCACHE_CASE
} cmd_ptrsubtype_t;

/*
 * A change was made to the above enum that violated the ordering requirement
 * described in the comment.  As such, there exist development machines in
 * the wild that have pre-violation pointer buffers.  Attempts to run the DE
 * on those machines will cause the state-restoration code to fail, as it
 * won't know what to do with the old pointer types.  Unfortunately, the old
 * and new values overlapped for the CPU pointers, so there's not much we
 * can do there.  The memory pointers, on the other hand, changed from 6-8 to
 * 12-14, thus allowing us to make the dimm, bank, and page restoration code
 * check for both values.
 *
 * This should go away soon into the next release.
 */
typedef enum cmd_BUG_ptrsubtype {
	BUG_PTR_DIMM_CASE = 6,
	BUG_PTR_BANK_CASE = 7,
	BUG_PTR_PAGE_CASE = 8
} cmd_BUG_ptrsubtype_t;

#define	CMD_TIMERTYPE_CPU_UEC_FLUSH	1
#define	CMD_TIMERTYPE_CPU_XR_WAITER	2
#define	CMD_TIMERTYPE_MEM		3
#define	CMD_TIMERTYPE_DP		4

#define	CMD_TIMERTYPE_ISCPU(timer)	((timer) != CMD_TIMERTYPE_MEM && \
					(timer) != CMD_TIMERTYPE_DP)

/*
 * There are three types of general-purpose buffers, used to track CPUs, DIMMs,
 * and pages.  Created on-demand as ereports arrive, one buffer is created for
 * each thing tracked.  The general-purpose buffers are used to track common
 * state, and are used to support case-specific buffers.  Each open case has
 * a case-specific pointer buffer, used to aid in the rediscovery of the
 * associated general-purpose buffer.  When restoration begins, we iterate
 * through each of the open cases, restoring the case-specific pointer buffers
 * for each.  The pointer buffers are then used to restore the general-purpose
 * buffers.
 */

typedef	struct cmd_case_ptr {
	cmd_nodetype_t ptr_type;	/* The type of associated G.P. buffer */
	cmd_ptrsubtype_t ptr_subtype;	/* The case within the G.P. buffer */
	char ptr_name[CMD_BUFNMLEN];	/* G.P. buffer name */
} cmd_case_ptr_t;

/*
 * All general-purpose buffers begin with a common header.  This header contains
 * identification information used in the construction of new cases.
 *
 * Note that versioned structs (currently cmd_cpu_t) depend upon the size of
 * this struct remaining fixed.
 */
typedef struct cmd_header {
	cmd_list_t hdr_list;		/* List of G.P. structs of this type */
	cmd_nodetype_t hdr_nodetype;	/* Type of this G.P. struct */
	char hdr_bufname[CMD_BUFNMLEN]; /* G.P. buffer name */
} cmd_header_t;

/*
 * Per-case-subtype case closing routines.  Stored in per-case state when the
 * case is generated, and regenerated from saved state upon restore.
 */
typedef void cmd_case_closer_f(fmd_hdl_t *, void *);
typedef void *cmd_case_restorer_f(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);

typedef struct cmd_case_closer {
	cmd_case_closer_f *cl_func;
	void *cl_arg;
} cmd_case_closer_t;

typedef struct cmd_case {
	fmd_case_t *cc_cp;
	char *cc_serdnm;
} cmd_case_t;

/*
 * Utility functions which ease the management of cases.
 */
extern fmd_case_t *cmd_case_create(fmd_hdl_t *, cmd_header_t *,
    cmd_ptrsubtype_t, const char **);
extern void cmd_case_redirect(fmd_hdl_t *, fmd_case_t *, cmd_ptrsubtype_t);
extern void cmd_case_fini(fmd_hdl_t *, fmd_case_t *, int);
extern void cmd_case_restore(fmd_hdl_t *, cmd_case_t *, fmd_case_t *, char *);

extern int cmd_state_restore(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_STATE_H */
