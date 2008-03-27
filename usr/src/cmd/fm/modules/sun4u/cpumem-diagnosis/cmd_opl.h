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

#ifndef _CMD_OPL_H
#define	_CMD_OPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cmd.h>
#include <cmd_cpu.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct opl_cpu {
	cmd_list_t oc_list;
	cmd_cpu_t *oc_cmd_cpu;
	uint32_t oc_cpuid;
} opl_cpu_t;

extern cmd_evdisp_t cmd_oplinv_urg(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplcre(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opltsb_ctx(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opltsbp(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplpstate(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opltstate(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opliug_f(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opliug_r(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplsdc(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplwdt(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opldtlb(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplitlb(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplcore_err(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opldae(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opliae(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opluge(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplmtlb(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opltlbp(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_oplinv_sfsr(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opluecpu_detcpu(fmd_hdl_t *, fmd_event_t *,
    nvlist_t *, const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opluecpu_detio(fmd_hdl_t *, fmd_event_t *,
    nvlist_t *, const char *, cmd_errcl_t);

extern cmd_evdisp_t cmd_opl_mac_common(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opl_cpu_mem(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_opl_io_mem(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern nvlist_t *opl_cpursrc_create(fmd_hdl_t *, uint32_t);
extern char *cmd_cpu_getfrustr_by_id(fmd_hdl_t *, uint32_t);
extern cmd_list_t *opl_cpulist_insert(fmd_hdl_t *, uint32_t, int);
extern void opl_cpulist_free(fmd_hdl_t *, cmd_list_t *);
extern uint8_t opl_avg(uint_t, uint_t);

extern cmd_evdisp_t cmd_opl_ue_cpu(fmd_hdl_t *, fmd_event_t *,
    const char *, const char *, cmd_ptrsubtype_t, cmd_cpu_t *, cmd_case_t *,
    uint8_t);

extern cmd_list_t *opl_cpulist_insert(fmd_hdl_t *, uint32_t, int);
extern int cmd_fmri_hc_set(fmd_hdl_t *, nvlist_t *, int, const nvlist_t *,
    nvlist_t *, int, ...);
extern nvlist_t *opl_mem_fru_create(fmd_hdl_t *, nvlist_t *);

extern cmd_list_t opl_cpu_list;

#define	OPL_CHASSIS_DEFAULT	"0"
#define	OPL_CPU_FRU_FMRI_DC	FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"=/CMU"
#define	OPL_CPU_FRU_FMRI_FF1	FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"=/MBU_A/CPUM"
#define	OPL_CPU_FRU_FMRI_FF2	FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"=/MBU_B/CPUM"
#define	OPL_CPU_FRU_FMRI_IKKAKU	FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"=/MBU_A"
#define	STR_BUFLEN		32
#define	NPAIRS			5

/*
 * Mask for getting the fault address
 * from  MARKEDID in UBC Memory UE
 * Log Register (Oberon)
 */
#define	UBC_UE_ADR_MASK		0x00007FFFFFFFFFFFULL

/*
 * To indicate if the CPU/IO handler is to be used.
 */
#define	CMD_OPL_HDLR_CPU	1
#define	CMD_OPL_HDLR_IO		2

/*
 * Macors for dealing with "core", "chip"
 * or "strand" related operations.
 */
#define	IS_STRAND		0
#define	IS_CORE			1
#define	IS_CHIP			2
#define	STRAND_UPPER_BOUND	1
#define	CORE_UPPER_BOUND	3

#define	COREID_SHIFT		1
#define	CHIPID_SHIFT		3
#define	STRAND_MASK		1
#define	CHIP_OR_CORE_MASK	3

/*
 * This is to reference the Oberon
 * UBC memory UE log register payload.
 */
#define	OBERON_UBC_MUE		"ubc-mue"

#ifdef __cplusplus
}
#endif

#endif /* _CMD_OPL_H */
