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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CPU_ACPI_H
#define	_CPU_ACPI_H

#include <sys/cpuvar.h>
#include <sys/acpi/acpi.h>
#include <sys/acpi/accommon.h>
#include <sys/acpi/acresrc.h>
#include <sys/acpica.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * P-state related macros
 */
#define	CPU_ACPI_PPC(sp)		sp->cs_ppc
#define	CPU_ACPI_PSD(sp)		sp->cs_psd
#define	CPU_ACPI_PCT(sp)		sp->cs_pct
#define	CPU_ACPI_PCT_CTRL(sp)		&sp->cs_pct[0]
#define	CPU_ACPI_PCT_STATUS(sp)		&sp->cs_pct[1]
#define	CPU_ACPI_PSTATES(sp)		sp->cs_pstates.ss_states
#define	CPU_ACPI_PSTATES_COUNT(sp)	sp->cs_pstates.ss_count

#define	CPU_ACPI_FREQ(pstate)		pstate->ps_freq
#define	CPU_ACPI_PSTATE_TRANSLAT(pstate) pstate->ps_translat
#define	CPU_ACPI_PSTATE_CTRL(pstate)	pstate->ps_ctrl

/*
 * T-state related macros
 */
#define	CPU_ACPI_TPC(sp)		sp->cs_tpc
#define	CPU_ACPI_TSD(sp)		sp->cs_tsd
#define	CPU_ACPI_PTC(sp)		sp->cs_ptc
#define	CPU_ACPI_PTC_CTRL(sp)		&sp->cs_ptc[0]
#define	CPU_ACPI_PTC_STATUS(sp)		&sp->cs_ptc[1]
#define	CPU_ACPI_TSTATES(sp)		sp->cs_tstates.ss_states
#define	CPU_ACPI_TSTATES_COUNT(sp)	sp->cs_tstates.ss_count

#define	CPU_ACPI_FREQPER(tstate)	tstate->ts_freqper
#define	CPU_ACPI_TSTATE_TRANSLAT(tstate) tstate->ts_translat
#define	CPU_ACPI_TSTATE_CTRL(tstate)	tstate->ts_ctrl
#define	CPU_ACPI_TSTATE_STAT(tstate)	tstate->ts_state

/*
 * C-state realted macros
 */
#define	CPU_ACPI_CSD(sp)		sp->cs_csd
#define	CPU_ACPI_CSTATES(sp)		sp->cs_cstates.ss_states
#define	CPU_ACPI_CSTATES_COUNT(sp)	sp->cs_cstates.ss_count

#define	CPU_ACPI_NONE_CACHED		0x0000
#define	CPU_ACPI_PCT_CACHED		0x0001
#define	CPU_ACPI_PSS_CACHED		0x0002
#define	CPU_ACPI_PSD_CACHED		0x0004
#define	CPU_ACPI_PPC_CACHED		0x0008
#define	CPU_ACPI_PTC_CACHED		0x0010
#define	CPU_ACPI_TSS_CACHED		0x0020
#define	CPU_ACPI_TSD_CACHED		0x0040
#define	CPU_ACPI_TPC_CACHED		0x0080
#define	CPU_ACPI_CST_CACHED		0x0100
#define	CPU_ACPI_CSD_CACHED		0x0200

#define	CPU_ACPI_IS_OBJ_CACHED(sp, obj)	(sp->cpu_acpi_cached & obj)
#define	CPU_ACPI_OBJ_IS_CACHED(sp, obj)	(sp->cpu_acpi_cached |= obj)
#define	CPU_ACPI_OBJ_IS_NOT_CACHED(sp, obj) (sp->cpu_acpi_cached &= ~obj)

#define	CPU_ACPI_PSTATES_SIZE(cnt) (cnt * sizeof (cpu_acpi_pstate_t))
#define	CPU_ACPI_PSS_CNT (sizeof (cpu_acpi_pstate_t) / sizeof (uint32_t))
#define	CPU_ACPI_TSTATES_SIZE(cnt) (cnt * sizeof (cpu_acpi_tstate_t))
#define	CPU_ACPI_TSS_CNT (sizeof (cpu_acpi_tstate_t) / sizeof (uint32_t))
#define	CPU_ACPI_CSTATES_SIZE(cnt) (cnt * sizeof (cpu_acpi_cstate_t))
#define	CPU_ACPI_CST_CNT (sizeof (cpu_acpi_cstate_t) / sizeof (uint32_t))
/*
 * CPU Domain Coordination Types
 */
#define	CPU_ACPI_SW_ALL	0xfc
#define	CPU_ACPI_SW_ANY	0xfd
#define	CPU_ACPI_HW_ALL	0xfe

/*
 * Container for ACPI processor state dependency information
 */
typedef struct cpu_acpi_state_dependency
{
	uint8_t sd_entries;
	uint8_t sd_revision;
	uint32_t sd_domain;
	uint32_t sd_type;
	uint32_t sd_num;
	uint32_t sd_index;
} cpu_acpi_state_dependency_t;

typedef cpu_acpi_state_dependency_t cpu_acpi_psd_t;
typedef cpu_acpi_state_dependency_t cpu_acpi_tsd_t;
typedef cpu_acpi_state_dependency_t cpu_acpi_csd_t;

/*
 * Container for ACPI processor control register information
 */
typedef struct cpu_acpi_ctrl_regs
{
	uint8_t cr_addrspace_id;
	uint8_t cr_width;
	uint8_t cr_offset;
	uint8_t cr_asize;
	ACPI_IO_ADDRESS cr_address;
} cpu_acpi_ctrl_regs_t;

typedef cpu_acpi_ctrl_regs_t cpu_acpi_pct_t;
typedef cpu_acpi_ctrl_regs_t cpu_acpi_ptc_t;

/*
 * Container for ACPI _PSS information
 */
typedef struct cpu_acpi_pstate
{
	uint32_t ps_freq;
	uint32_t ps_disp;
	uint32_t ps_translat;
	uint32_t ps_buslat;
	uint32_t ps_ctrl;
	uint32_t ps_state;
} cpu_acpi_pstate_t;

/*
 * Container for _TSS information
 */
typedef struct cpu_acpi_tstate
{
	uint32_t ts_freqper;
	uint32_t ts_disp;
	uint32_t ts_translat;
	uint32_t ts_ctrl;
	uint32_t ts_state;

} cpu_acpi_tstate_t;

/*
 * Container for _CST information
 */
typedef struct cpu_acpi_cstate
{
	uint32_t cs_addrspace_id;
	uint32_t cs_address;
	uint32_t cs_type;
	uint32_t cs_latency;
	uint32_t cs_power;
	kstat_t	*cs_ksp;
} cpu_acpi_cstate_t;

typedef struct cpu_acpi_supported_states {
	void *ss_states;
	uint32_t ss_count;
} cpu_acpi_supported_states_t;

typedef cpu_acpi_supported_states_t cpu_acpi_pstates_t;
typedef cpu_acpi_supported_states_t cpu_acpi_tstates_t;
typedef cpu_acpi_supported_states_t cpu_acpi_cstates_t;

typedef int cpu_acpi_present_capabilities_t;
typedef int cpu_acpi_ppc_t;
typedef int cpu_acpi_tpc_t;

/*
 * Container for cached ACPI data.
 */
typedef struct cpu_acpi_state {
	ACPI_HANDLE cs_handle;
	int cs_id;
	uint_t cpu_acpi_cached;
	cpu_acpi_pstates_t cs_pstates;
	cpu_acpi_pct_t cs_pct[2];
	cpu_acpi_psd_t cs_psd;
	cpu_acpi_ppc_t cs_ppc;
	cpu_acpi_tstates_t cs_tstates;
	cpu_acpi_ptc_t cs_ptc[2];
	cpu_acpi_tsd_t cs_tsd;
	cpu_acpi_tpc_t cs_tpc;
	cpu_acpi_cstates_t cs_cstates;
	cpu_acpi_csd_t cs_csd;
} cpu_acpi_state_t;

typedef cpu_acpi_state_t *cpu_acpi_handle_t;

extern void cpu_acpi_cache_ppc(cpu_acpi_handle_t);
extern void cpu_acpi_cache_tpc(cpu_acpi_handle_t);
extern int cpu_acpi_cache_pstate_data(cpu_acpi_handle_t);
extern void cpu_acpi_free_pstate_data(cpu_acpi_handle_t);
extern int cpu_acpi_cache_tstate_data(cpu_acpi_handle_t);
extern void cpu_acpi_free_tstate_data(cpu_acpi_handle_t);
extern int cpu_acpi_cache_cstate_data(cpu_acpi_handle_t);
extern void cpu_acpi_free_cstate_data(cpu_acpi_handle_t);
extern void cpu_acpi_install_notify_handler(cpu_acpi_handle_t,
    ACPI_NOTIFY_HANDLER, void *);
extern void cpu_acpi_remove_notify_handler(cpu_acpi_handle_t,
    ACPI_NOTIFY_HANDLER);
extern int cpu_acpi_write_pdc(cpu_acpi_handle_t, uint32_t, uint32_t,
    uint32_t *);
extern int cpu_acpi_write_port(ACPI_IO_ADDRESS, uint32_t, uint32_t);
extern int cpu_acpi_read_port(ACPI_IO_ADDRESS, uint32_t *, uint32_t);
extern void cpu_acpi_set_register(uint32_t, uint32_t);
extern void cpu_acpi_get_register(uint32_t, uint32_t *);
extern uint_t cpu_acpi_get_speeds(cpu_acpi_handle_t, int **);
extern uint_t cpu_acpi_get_max_cstates(cpu_acpi_handle_t);
extern void cpu_acpi_free_speeds(int *, uint_t);
extern cpu_acpi_handle_t cpu_acpi_init(cpu_t *);
extern void cpu_acpi_fini(cpu_acpi_handle_t);

#ifdef __cplusplus
}
#endif

#endif	/* _CPU_ACPI_H */
