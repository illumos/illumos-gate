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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2009,  Intel Corporation.
 * All Rights Reserved.
 */

#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/x_call.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/speedstep.h>
#include <sys/cpu_acpi.h>
#include <sys/cpupm.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

typedef struct turbo_kstat_s {
	struct kstat_named	turbo_supported;	/* turbo flag */
	struct kstat_named	t_mcnt;			/* IA32_MPERF_MSR */
	struct kstat_named	t_acnt;			/* IA32_APERF_MSR */
} turbo_kstat_t;

static int turbo_kstat_update(kstat_t *, int);
static void get_turbo_info(cpupm_mach_turbo_info_t *);
static void reset_turbo_info(void);
static void record_turbo_info(cpupm_mach_turbo_info_t *, uint32_t, uint32_t);
static void update_turbo_info(cpupm_mach_turbo_info_t *);

static kmutex_t turbo_mutex;

turbo_kstat_t turbo_kstat = {
	{ "turbo_supported",	KSTAT_DATA_UINT32 },
	{ "turbo_mcnt",		KSTAT_DATA_UINT64 },
	{ "turbo_acnt",		KSTAT_DATA_UINT64 },
};

#define	CPU_ACPI_P0			0
#define	CPU_IN_TURBO			1

/*
 * MSR for hardware coordination feedback mechanism
 *   - IA32_MPERF: increments in proportion to a fixed frequency
 *   - IA32_APERF: increments in proportion to actual performance
 */
#define	IA32_MPERF_MSR			0xE7
#define	IA32_APERF_MSR			0xE8

/*
 * kstat update function of the turbo mode info
 */
static int
turbo_kstat_update(kstat_t *ksp, int flag)
{
	cpupm_mach_turbo_info_t *turbo_info = ksp->ks_private;

	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	/*
	 * update the count in case CPU is in the turbo
	 * mode for a long time
	 */
	if (turbo_info->in_turbo == CPU_IN_TURBO)
		update_turbo_info(turbo_info);

	turbo_kstat.turbo_supported.value.ui32 =
	    turbo_info->turbo_supported;
	turbo_kstat.t_mcnt.value.ui64 = turbo_info->t_mcnt;
	turbo_kstat.t_acnt.value.ui64 = turbo_info->t_acnt;

	return (0);
}

/*
 * update the sum of counts and clear MSRs
 */
static void
update_turbo_info(cpupm_mach_turbo_info_t *turbo_info)
{
	ulong_t		iflag;
	uint64_t	mcnt, acnt;

	iflag = intr_clear();
	mcnt = rdmsr(IA32_MPERF_MSR);
	acnt = rdmsr(IA32_APERF_MSR);
	wrmsr(IA32_MPERF_MSR, 0);
	wrmsr(IA32_APERF_MSR, 0);
	turbo_info->t_mcnt += mcnt;
	turbo_info->t_acnt += acnt;
	intr_restore(iflag);
}

/*
 * Get count of MPERF/APERF MSR
 */
static void
get_turbo_info(cpupm_mach_turbo_info_t *turbo_info)
{
	ulong_t		iflag;
	uint64_t	mcnt, acnt;

	iflag = intr_clear();
	mcnt = rdmsr(IA32_MPERF_MSR);
	acnt = rdmsr(IA32_APERF_MSR);
	turbo_info->t_mcnt += mcnt;
	turbo_info->t_acnt += acnt;
	intr_restore(iflag);
}

/*
 * Clear MPERF/APERF MSR
 */
static void
reset_turbo_info(void)
{
	ulong_t		iflag;

	iflag = intr_clear();
	wrmsr(IA32_MPERF_MSR, 0);
	wrmsr(IA32_APERF_MSR, 0);
	intr_restore(iflag);
}

/*
 * sum up the count of one CPU_ACPI_P0 transition
 */
void
cpupm_record_turbo_info(cpupm_mach_turbo_info_t *turbo_info,
    uint32_t cur_state, uint32_t req_state)
{
	if (!turbo_info->turbo_supported)
		return;
	/*
	 * enter P0 state
	 */
	if (req_state == CPU_ACPI_P0) {
		reset_turbo_info();
		turbo_info->in_turbo = CPU_IN_TURBO;
	}
	/*
	 * Leave P0 state
	 */
	else if (cur_state == CPU_ACPI_P0) {
		turbo_info->in_turbo = 0;
		get_turbo_info(turbo_info);
	}
}

cpupm_mach_turbo_info_t *
cpupm_turbo_init(cpu_t *cp)
{
	cpupm_mach_turbo_info_t *turbo_info;

	turbo_info = kmem_zalloc(sizeof (cpupm_mach_turbo_info_t), KM_SLEEP);

	turbo_info->turbo_supported = 1;
	turbo_info->turbo_ksp = kstat_create("turbo", cp->cpu_id,
	    "turbo", "misc", KSTAT_TYPE_NAMED,
	    sizeof (turbo_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (turbo_info->turbo_ksp == NULL) {
		cmn_err(CE_NOTE, "kstat_create(turbo) fail");
	} else {
		turbo_info->turbo_ksp->ks_data = &turbo_kstat;
		turbo_info->turbo_ksp->ks_lock = &turbo_mutex;
		turbo_info->turbo_ksp->ks_update = turbo_kstat_update;
		turbo_info->turbo_ksp->ks_data_size += MAXNAMELEN;
		turbo_info->turbo_ksp->ks_private = turbo_info;

		kstat_install(turbo_info->turbo_ksp);
	}

	return (turbo_info);
}

void
cpupm_turbo_fini(cpupm_mach_turbo_info_t *turbo_info)
{
	if (turbo_info->turbo_ksp != NULL)
		kstat_delete(turbo_info->turbo_ksp);
	kmem_free(turbo_info, sizeof (cpupm_mach_turbo_info_t));
}
