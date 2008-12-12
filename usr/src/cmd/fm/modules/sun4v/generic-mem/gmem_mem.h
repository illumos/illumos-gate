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

#ifndef _GMEM_MEM_H
#define	_GMEM_MEM_H

/*
 * Support routines for managing state related to memory modules.
 * Correctable errors generally cause changes to the DIMM-related state.
 */

#include <gmem.h>
#include <gmem_page.h>
#include <gmem_state.h>
#include <gmem_fmri.h>
#include <sys/errclassify.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	GMEM_ERPT_PAYLOAD_DIAGNOSE	"diagnose"
#define	GMEM_ERPT_PAYLOAD_RESOURCE	"resource"
#define	GMEM_ERPT_PAYLOAD_PHYSADDR	"phys-addr"
#define	GMEM_ERPT_PAYLOAD_OFFSET	"offset"
#define	GMEM_ERPT_PAYLOAD_SERDN		"serd_n"
#define	GMEM_ERPT_PAYLOAD_SERDT		"serd_t"
#define	GMEM_ERPT_PAYLOAD_SYMBOLPOS	"symbol-pos"
#define	GMEM_ERPT_PAYLOAD_DRAM		"dram"
#define	GMEM_ERPT_PAYLOAD_FILTER_RATIO	"filter_ratio"
#define	GMEM_ERPT_PAYLOAD_CKW		"relative-ckword"

#define	GMEM_F_FAULTING	0x1
#define	GMEM_FAULT_DIMM_PAGES	"fault.memory.dimm-page-retires-excessive"
#define	GMEM_FAULT_DIMM_4A	"fault.memory.dimm-ue-imminent"
#define	GMEM_FAULT_DIMM_4B	"fault.memory.dram-ue-imminent"
#define	GMEM_FAULT_PAGE		"fault.memory.page"
#define	INVALID_DRAM		-1

#define	DEFAULT_SERDN	0x2
#define	DEFAULT_SERDT	0xebbdb3ed0000ULL

typedef struct gmem_dimm gmem_dimm_t;

/*
 * Correctable memory errors
 * "unknown symbol" (mem-us) and "intermittent symbol" (mem-is) CEs are
 * not used in diagnosis, except for rules 4A & 4B checking.
 *
 * "clearable symbol" (mem-cs) CEs are added to the SERD engines. When the
 * engine the page corresponding to the CE that caused the engine to
 * fire is retired
 *
 * "sticky symbol" (mem-ss) CEs trigger immediate page retirement.
 *
 */

extern gmem_evdisp_t gmem_ce(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *);
extern void gmem_dimm_close(fmd_hdl_t *, void *);

extern void gmem_mem_case_restore(fmd_hdl_t *, gmem_case_t *, fmd_case_t *,
    const char *, const char *);
extern char *gmem_mem_serdnm_create(fmd_hdl_t *, const char *, const char *);
extern char *gmem_page_serdnm_create(fmd_hdl_t *, const char *, uint64_t);
extern char *gmem_mq_serdnm_create(fmd_hdl_t *, const char *, uint64_t,
    uint16_t, uint16_t);
extern void gmem_page_serd_create(fmd_hdl_t *, gmem_page_t *, nvlist_t *);
extern uint32_t gmem_get_serd_filter_ratio(nvlist_t *);
extern int gmem_serd_record(fmd_hdl_t *, const char *, uint32_t, fmd_event_t *);
extern void gmem_mem_retirestat_create(fmd_hdl_t *, fmd_stat_t *, const char *,
    uint64_t, const char *);

extern void gmem_mem_gc(fmd_hdl_t *);
extern void gmem_mem_fini(fmd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _GMEM_MEM_H */
