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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CPU_ACPI_H
#define	_CPU_ACPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/acpi/acpi.h>
#include <sys/acpi/acresrc.h>
#include <sys/acpi/acglobal.h>
#include <sys/acpica.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CPU_ACPI_PPC(sp)		sp->cs_ppc
#define	CPU_ACPI_PSD(sp)		sp->cs_psd
#define	CPU_ACPI_PCT(sp)		sp->cs_pct
#define	CPU_ACPI_PCT_CTRL(sp)		&sp->cs_pct[0]
#define	CPU_ACPI_PCT_STATUS(sp)		&sp->cs_pct[1]
#define	CPU_ACPI_PSTATES(sp)		sp->cs_pstates->pss_pstates
#define	CPU_ACPI_PSTATES_COUNT(sp)	sp->cs_pstates->pss_count

#define	CPU_ACPI_PSTATE(sp, i)		&sp->cs_pstates->pss_pstates[i]
#define	CPU_ACPI_FREQ(pstate)		pstate->ps_freq
#define	CPU_ACPI_TRANSLAT(pstate)	pstate->ps_translat
#define	CPU_ACPI_CTRL(pstate)		pstate->ps_ctrl
#define	CPU_ACPI_STAT(pstate)		pstate->ps_state

#define	CPU_ACPI_NONE_CACHED		0x00
#define	CPU_ACPI_PCT_CACHED		0x01
#define	CPU_ACPI_PSS_CACHED		0x02
#define	CPU_ACPI_PSD_CACHED		0x04
#define	CPU_ACPI_PPC_CACHED		0x08

#define	CPU_ACPI_IS_OBJ_CACHED(sp, obj)	(sp->cpu_acpi_cached & obj)
#define	CPU_ACPI_OBJ_IS_CACHED(sp, obj)	(sp->cpu_acpi_cached |= obj)
#define	CPU_ACPI_OBJ_IS_NOT_CACHED(sp, obj) (sp->cpu_acpi_cached &= ~obj)

/*
 * Container for _PSD information
 */
typedef struct cpu_acpi_psd
{
	uint8_t pd_entries;
	uint8_t pd_revision;
	uint32_t pd_domain;
	uint32_t pd_type;
	uint32_t pd_num;
} cpu_acpi_psd_t;

/*
 * Container for _PCT information
 */
typedef struct cpu_acpi_pct
{
	uint8_t pc_addrspace_id;
	uint8_t pc_width;
	uint8_t pc_offset;
	uint8_t pc_asize;
	ACPI_IO_ADDRESS pc_address;
} cpu_acpi_pct_t;

/*
 * Containers for _PSS information
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

typedef struct cpu_acpi_pstates {
	cpu_acpi_pstate_t *pss_pstates;
	uint32_t pss_count;
} cpu_acpi_pstates_t;

typedef int cpu_acpi_ppc_t;

/*
 * Container for cached ACPI data.
 */
typedef struct cpu_acpi_state {
	ACPI_HANDLE cs_handle;
	dev_info_t *cs_dip;
	uint_t cpu_acpi_cached;
	cpu_acpi_pstates_t *cs_pstates;
	cpu_acpi_pct_t cs_pct[2];
	cpu_acpi_psd_t cs_psd;
	cpu_acpi_ppc_t cs_ppc;
} cpu_acpi_state_t;

typedef cpu_acpi_state_t *cpu_acpi_handle_t;

extern cpu_acpi_handle_t cpu_acpi_init(dev_info_t *);
extern void cpu_acpi_fini(cpu_acpi_handle_t);
extern int cpu_acpi_cache_pstates(cpu_acpi_handle_t);
extern int cpu_acpi_cache_pct(cpu_acpi_handle_t);
extern int cpu_acpi_cache_psd(cpu_acpi_handle_t);
extern void cpu_acpi_cache_ppc(cpu_acpi_handle_t);
extern int cpu_acpi_cache_data(cpu_acpi_handle_t);
extern void cpu_acpi_install_ppc_handler(cpu_acpi_handle_t,
    ACPI_NOTIFY_HANDLER, dev_info_t *);
extern int cpu_acpi_write_pdc(cpu_acpi_handle_t, uint32_t, uint32_t,
    uint32_t *);
extern int cpu_acpi_write_port(ACPI_IO_ADDRESS, uint32_t, uint32_t);
extern int cpu_acpi_read_port(ACPI_IO_ADDRESS, uint32_t *, uint32_t);
extern uint_t cpu_acpi_get_speeds(cpu_acpi_handle_t, int **);
extern void cpu_acpi_free_speeds(int *, uint_t);

#ifdef __cplusplus
}
#endif

#endif	/* _CPU_ACPI_H */
