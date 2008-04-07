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

#ifndef _CMD_MEM_H
#define	_CMD_MEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for managing state related to memory modules.
 *
 * Correctable errors generally cause changes to the DIMM-related state (see
 * cmd_dimm.c), whereas uncorrectable errors tend to use the bank-related
 * routines (see cmd_bank.c).  The primary exception to this division (though
 * it eventually devolves to one of the two) is the RxE/FRx pair emitted by
 * UltraSPARC-IIIi processors.  With these errors, a complete pair must be
 * received and matched before we know whether we're dealing with a CE or a UE.
 */

#include <cmd.h>
#include <cmd_state.h>
#include <cmd_fmri.h>
#include <sys/errclassify.h>
#include <cmd_cpu.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CMD_MEM_F_FAULTING	0x1

/*
 * Used to store as-yet unmatched IOxEs, RxEs, and FRxs.  When a new IOxE,
 * RxE or FRx arrives, we traverse the cmd.cmd_iorxefrx list, looking for
 * matching entries.  Matching has a cpuid-based component, as well as a
 * temporal one.  We can compare the cpuids directly, using the cmd_iorxefrx_t
 * and the newly-received event. Temporal comparison isn't performed directly.
 * Instead, we ensure that entries in the iorxefrx list are removed when they
 * expire by means of timers. This frees the matching code from the need to
 * worry about time.
 */
typedef struct cmd_iorxefrx {
	cmd_list_t rf_list;		/* List of cmd_iorxefrx_t's */
	cmd_errcl_t rf_errcl;		/* Error type (CMD_ERRCL_*) */
	uint_t rf_afsr_agentid;		/* Remote Agent ID (from AFSR) */
	uint_t rf_det_agentid;		/* Locat Agent ID (from detector) */
	id_t rf_expid;			/* Timer ID for entry expiration */
	uint64_t rf_afar;		/* Valid for RxE only */
	uint8_t rf_afar_status;		/* Valid for RxE only */
	ce_dispact_t rf_type;		/* Valid for RxE only */
	uint16_t rf_synd;		/* Valid for FRx only */
	uint8_t rf_synd_status;		/* Valid for FRx only */
	uint64_t rf_afsr;		/* Valid for FRx only */
	uint64_t rf_disp;		/* Valid for RCE only */
} cmd_iorxefrx_t;

typedef struct cmd_dimm cmd_dimm_t;
typedef struct cmd_bank cmd_bank_t;
#ifdef sun4v
typedef struct cmd_branch cmd_branch_t;
#endif

/*
 * Correctable and Uncorrectable memory errors
 *
 * CEs of "Unknown" or "Intermittent" classification are not used in diagnosis.
 *
 * "Persistent" CEs are added to per-DIMM SERD engines.  When the
 * engine for a given DIMM fires, the page corresponding to the CE that
 * caused the engine to fire is retired, and the SERD engine for that
 * DIMM is reset.
 *
 * "Possibly Persistent" CEs are at least Persistent and so are treated
 * as "Persistent" errors above, being added to the same SERD engines.
 *
 * "Leaky" CEs and "Sticky" CEs trigger immediate page retirement.
 *
 * "Possibly Sticky" CEs to which no valid partner test has been applied
 * are not used in diagnosis.  Where a valid partner test has been applied
 * but did not confirm "Sticky" status there is a _suggestion_ that the
 * original cpu may be a bad reader or writer or suffering from other
 * datapath issues.  To avoid retiring pages for such non-DIMM problems
 * these classifications are also not used in diagnosis.
 *
 * UEs immediately trigger page retirements, but do not affect the CE SERD
 * engines.  In addition, UEs are recorded in the UE caches of the detecting
 * CPUs.  When a page is to be retired, a fault.memory.page fault is
 * generated.
 *
 */

typedef cmd_evdisp_t cmd_xe_handler_f(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, uint64_t, uint8_t, uint16_t, uint8_t, ce_dispact_t, uint64_t,
    nvlist_t *);

extern ce_dispact_t cmd_mem_name2type(const char *, int);
extern int cmd_synd2upos(uint16_t);
extern int cmd_upos2dram(uint16_t);
extern cmd_evdisp_t cmd_ce(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_ue(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_ce_common(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, uint64_t, uint8_t, uint16_t, uint8_t,
    ce_dispact_t, uint64_t, nvlist_t *);
extern cmd_evdisp_t cmd_ue_common(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, uint64_t, uint8_t, uint16_t, uint8_t,
    ce_dispact_t, uint64_t, nvlist_t *);
extern cmd_evdisp_t cmd_mem_synd_check(fmd_hdl_t *, uint64_t, uint8_t,
    uint16_t, uint8_t, cmd_cpu_t *);
extern void cmd_dimm_close(fmd_hdl_t *, void *);
extern void cmd_bank_close(fmd_hdl_t *, void *);
#ifdef sun4v
extern void cmd_branch_close(fmd_hdl_t *, void *);
extern cmd_evdisp_t cmd_fb(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_fb_train(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_ue_train(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
#endif

/*
 * US-IIIi I/O, Remote and Foreign Read memory errors
 *
 * When one processor or I/O bridge attempts to read memory local to
 * another processor, one each of IOCE/IOUE/RCE/RUE and FRC/FRU will be
 * generated, depending on the type of error.  Both the IOxE/RxE and the FRx
 * are needed, as each contains data necessary to the diagnosis of the error.
 * Upon receipt of one of the errors, we wait until we receive the other.
 * When the pair has been successfully received and matched, a CE or UE,
 * as appropriate, is synthesized from the data in the matched ereports.
 * The synthesized ereports are handled by the normal CE and UE mechanisms.
 */
extern cmd_evdisp_t cmd_frx(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_rxe(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_ioxe(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_ioxe_sec(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_rxefrx_common(fmd_hdl_t *hdl, fmd_event_t *ep,
    nvlist_t *nvl, const char *class, cmd_errcl_t clcode,
    cmd_errcl_t matchmask);

/*
 * A list of received IOxE/RxE/FRx ereports is maintained for correlation
 * purposes (see above).  These two routines manage the addition of new
 * ereports, and the retrieval of existing ones.  Pruning of the list is
 * handled automatically.
 */
extern void cmd_iorxefrx_queue(fmd_hdl_t *, cmd_iorxefrx_t *);
extern void cmd_iorxefrx_free(fmd_hdl_t *, cmd_iorxefrx_t *);

extern const char *cmd_fmri_get_unum(nvlist_t *);
extern nvlist_t *cmd_mem_fmri_create(const char *);
extern nvlist_t *cmd_mem_fmri_derive(fmd_hdl_t *, uint64_t, uint64_t, uint16_t);

extern void cmd_mem_case_restore(fmd_hdl_t *, cmd_case_t *, fmd_case_t *,
    const char *, const char *);
extern char *cmd_mem_serdnm_create(fmd_hdl_t *, const char *, const char *);
extern char *cmd_page_serdnm_create(fmd_hdl_t *, const char *, uint64_t);
extern void cmd_mem_retirestat_create(fmd_hdl_t *, fmd_stat_t *, const char *,
    uint64_t, const char *);
extern int cmd_mem_thresh_check(fmd_hdl_t *, uint_t);
extern ulong_t cmd_mem_get_phys_pages(fmd_hdl_t *);

extern void cmd_mem_timeout(fmd_hdl_t *, id_t);
extern void cmd_mem_gc(fmd_hdl_t *);
extern void cmd_mem_fini(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_MEM_H */
