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

#ifndef _CMD_H
#define	_CMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdarg.h>
#include <fm/fmd_api.h>
#include <sys/param.h>

#include <cmd_list.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Diagnosis of certain errors requires that either a) the type of ereport be
 * recorded in a persistent buffer or b) that a single value be used to
 * represent multiple ereport classes.  We start the values at 0x8 to avoid
 * collisions with an earlier class code enum.  While we have 64 bits available
 * to us, cmd_errcl_t's are saved in persistent buffers, and thus can't easily
 * grow beyond that size.  As such, ereports should only be assigned class codes
 * when needed.  NEVER CHANGE the values of these constants once assigned.
 */
#define	CMD_ERRCL_UCC		0x0000000000000008ULL
#define	CMD_ERRCL_UCU		0x0000000000000010ULL
#define	CMD_ERRCL_CPC		0x0000000000000020ULL
#define	CMD_ERRCL_CPU		0x0000000000000040ULL
#define	CMD_ERRCL_WDC		0x0000000000000080ULL
#define	CMD_ERRCL_WDU		0x0000000000000100ULL
#define	CMD_ERRCL_EDC		0x0000000000000200ULL
#define	CMD_ERRCL_EDU_ST	0x0000000000000400ULL
#define	CMD_ERRCL_EDU_BL	0x0000000000000800ULL
#define	CMD_ERRCL_L3_UCC	0x0000000000001000ULL
#define	CMD_ERRCL_L3_UCU	0x0000000000002000ULL
#define	CMD_ERRCL_L3_CPC	0x0000000000004000ULL
#define	CMD_ERRCL_L3_CPU	0x0000000000008000ULL
#define	CMD_ERRCL_L3_WDC	0x0000000000010000ULL
#define	CMD_ERRCL_L3_WDU	0x0000000000020000ULL
#define	CMD_ERRCL_L3_EDC	0x0000000000040000ULL
#define	CMD_ERRCL_L3_EDU_ST	0x0000000000080000ULL
#define	CMD_ERRCL_L3_EDU_BL	0x0000000000100000ULL
#define	CMD_ERRCL_L3_MECC	0x0000000000200000ULL
				/* hole for sequential expansion */
#define	CMD_ERRCL_RCE		0x0000040000000000ULL
#define	CMD_ERRCL_RUE		0x0000080000000000ULL
#define	CMD_ERRCL_FRC		0x0000100000000000ULL
#define	CMD_ERRCL_FRU		0x0000200000000000ULL
#define	CMD_ERRCL_IOCE		0x0000400000000000ULL
#define	CMD_ERRCL_IOUE		0x0000800000000000ULL
#define	CMD_ERRCL_DAC		0x0001000000000000ULL
#define	CMD_ERRCL_DSC		0x0002000000000000ULL
#define	CMD_ERRCL_DAU		0x0004000000000000ULL
#define	CMD_ERRCL_DSU		0x0008000000000000ULL
#define	CMD_ERRCL_LDAC		0x0010000000000000ULL
#define	CMD_ERRCL_LDWC		0x0020000000000000ULL
#define	CMD_ERRCL_LDRC		0x0040000000000000ULL
#define	CMD_ERRCL_LDSC		0x0080000000000000ULL
#define	CMD_ERRCL_LDAU		0x0100000000000000ULL
#define	CMD_ERRCL_LDWU		0x0200000000000000ULL
#define	CMD_ERRCL_LDRU		0x0400000000000000ULL
#define	CMD_ERRCL_LDSU		0x0800000000000000ULL

#define	CMD_ERRCL_SBDPC		0x1000000000000000ULL
#define	CMD_ERRCL_SBDLC		0x2000000000000000ULL
#define	CMD_ERRCL_TCCP		0x4000000000000000ULL
#define	CMD_ERRCL_TCCD		0x8000000000000000ULL

#ifdef sun4u
#define	CMD_ERRCL_ISL2XXCU(clcode) \
	((clcode) >= CMD_ERRCL_UCC && (clcode) <= CMD_ERRCL_EDU_BL)
#define	CMD_ERRCL_ISL3XXCU(clcode) \
	((clcode) >= CMD_ERRCL_L3_UCC && (clcode) <= CMD_ERRCL_L3_MECC)

#define	CMD_ERRCL_ISIOXE(clcode) \
	(((clcode) & (CMD_ERRCL_IOCE | CMD_ERRCL_IOUE)) != 0)
#else /* sun4u */
#define	CMD_ERRCL_ISL2XXCU(clcode) \
	((clcode) >= CMD_ERRCL_LDAC && (clcode) <= CMD_ERRCL_LDSU)
#define	CMD_ERRCL_ISL3XXCU(clcode) 0

#endif /* sun4u */

#define	CMD_ERRCL_ISMISCREGS(clcode) \
	((clcode) >= CMD_ERRCL_SBDPC && (clcode) <= CMD_ERRCL_TCCD)

#define	CMD_ERRCL_MATCH(clcode, mask) \
	(((clcode) & (mask)) != 0)

typedef uint64_t cmd_errcl_t;

/*
 * Use low order 2 bits of cmd_errcl_t in order to pass cpu grouping level.
 * The DE never shipped with code using low order 3 bits.
 */

#define	CMD_ERRCL_LEVEL_EXTRACT		0X0000000000000003ULL
#define	CMD_ERRCL_LEVEL_MASK		0XFFFFFFFFFFFFFFF8ULL

#define	CMD_STAT_BUMP(name)		cmd.cmd_stats->name.fmds_value.ui64++

#define	CMD_FLTMAXCONF		95	/* maximum confidence for faults */

struct cmd_xxcu_trw;

typedef struct cmd_stat {
	fmd_stat_t bad_det;		/* # of malformed detectors */
	fmd_stat_t bad_cpu_asru;	/* # of malformed cpu-scheme ASRUs */
	fmd_stat_t bad_mem_asru;	/* # of malformed mem-scheme ASRUs */
	fmd_stat_t bad_close;		/* # of inapplicable case closes */
	fmd_stat_t old_erpt;		/* # of erpts for removed components */
	fmd_stat_t cpu_creat;		/* # of CPU state structs created */
	fmd_stat_t dimm_creat;		/* # of DIMM state structs created */
	fmd_stat_t bank_creat;		/* # of bank state structs created */
	fmd_stat_t page_creat;		/* # of page state structs created */
	fmd_stat_t cache_creat;		/* # of cache state structs created */
	fmd_stat_t ce_unknown;		/* # of unknown CEs seen */
	fmd_stat_t ce_interm;		/* # of intermittent CEs seen */
	fmd_stat_t ce_ppersis;		/* # of possible persistent CEs seen */
	fmd_stat_t ce_persis;		/* # of persistent CEs seen */
	fmd_stat_t ce_leaky;		/* # of leaky CEs seen */
					/* # of possible sticky CEs: */
	fmd_stat_t ce_psticky_noptnr;		/* - no valid partner test */
	fmd_stat_t ce_psticky_ptnrnoerr;	/* - partner could not see CE */
	fmd_stat_t ce_psticky_ptnrclrd;		/* - partner could fix CE */
	fmd_stat_t ce_sticky;		/* # of sticky CEs seen */
	fmd_stat_t xxu_ue_match;	/* # of xxUs that matched in a UE $ */
	fmd_stat_t xxu_retr_flt;	/* # of xxUs unnecessary by fault */
	fmd_stat_t cpu_migrat;		/* # of CPUs migrated to new version */
	fmd_stat_t dimm_migrat;		/* # of DIMMs migrated to new version */
	fmd_stat_t bank_migrat;		/* # of banks migrated to new version */
#ifdef sun4u
	fmd_stat_t dp_ignored_ce;	/* # of CEs ignored due to DP flt/err */
	fmd_stat_t dp_ignored_ue;	/* # of UEs ignored due to DP fault */
	fmd_stat_t dp_deferred_ue;	/* # of UEs deferred due to DP error */
#endif
#ifdef sun4v
	fmd_stat_t branch_creat;	/* # of branch state structs created */
#endif
} cmd_stat_t;

typedef struct cmd_serd {
	const char *cs_name;
	uint_t cs_n;
	hrtime_t cs_t;
} cmd_serd_t;

typedef struct cmd {
	cmd_list_t cmd_cpus;		/* List of CPU state structures */
	cmd_list_t cmd_dimms;		/* List of DIMM state structures */
	cmd_list_t cmd_banks;		/* List of bank state structures */
	cmd_list_t cmd_pages;		/* List of page state structures */
	cmd_list_t cmd_iorxefrx;	/* List of IOxE/RxE/FRx correlation */
#ifdef sun4u
	cmd_list_t cmd_datapaths;	/* List of datapath state structures */
	cmd_list_t cmd_deferred_pages;	/* Pages deferred due to a DP error */
#endif
	hrtime_t cmd_iorxefrx_window;	/* Max int between IOxE/RxE/FRx pairs */
	cmd_stat_t *cmd_stats;		/* Module statistics */
	size_t cmd_pagesize;		/* Page size, in bytes */
	uint64_t cmd_pagemask;		/* Mask for page alignments */
	char cmd_ecache_dev[MAXPATHLEN]; /* Mem ctrlr drv path for E$ flush */
	struct cmd_xxcu_trw *cmd_xxcu_trw; /* Array of xxC/U train waiters */
	size_t cmd_xxcu_ntrw;		/* Number of waiters in array */
	hrtime_t cmd_xxcu_trdelay;	/* Delay for xxC/U redelivery */
	cmd_list_t cmd_xxcu_redelivs;	/* Pending xxC/U redeliveries */
	cmd_serd_t cmd_l2data_serd;	/* Params for L2$ SERD engine */
	cmd_serd_t cmd_l3data_serd;	/* Params for L3$ SERD engine */
	uint64_t cmd_thresh_tpct_sysmem; /* Pg ret warning thresh (% of mem) */
	uint64_t cmd_thresh_abs_sysmem;	/* Pg ret warning thresh (# of pages) */
	uint64_t cmd_thresh_abs_badrw;	/* Bad r/w retire thresh (# of pages) */
	cmd_serd_t cmd_miscregs_serd;   /* params for misregs serd */
	hrtime_t cmd_miscregs_trdelay;  /* delay for redelivery misregs */
#ifdef sun4u
	uint16_t cmd_dp_flag;		/* datapath error in progress if set */
#endif
#ifdef sun4v
	cmd_list_t cmd_branches;	/* List of branches state structures */
#endif
	nvlist_t *cmd_auth;		/* DE's fault authority value */
} cmd_t;

extern cmd_t cmd;

extern int cmd_set_errno(int);

extern void *cmd_buf_read(fmd_hdl_t *, fmd_case_t *, const char *, size_t);
extern void cmd_bufname(char *, size_t, const char *, ...);
extern void cmd_vbufname(char *, size_t, const char *, va_list);
extern nvlist_t *cmd_nvl_create_fault(fmd_hdl_t *,
    const char *, uint8_t, nvlist_t *, nvlist_t *, nvlist_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_H */
