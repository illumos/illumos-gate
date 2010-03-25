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

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

/*
 * Intel specific CPU power management support.
 */

#include <sys/x86_archext.h>
#include <sys/cpu_acpi.h>
#include <sys/speedstep.h>
#include <sys/cpupm_throttle.h>
#include <sys/cpu_idle.h>
#include <sys/archsystm.h>

/*
 * The Intel Processor Driver Capabilities (_PDC).
 * See Intel Processor Vendor-Specific ACPI Interface Specification
 * for details.
 */
#define	CPUPM_INTEL_PDC_REVISION	0x1
#define	CPUPM_INTEL_PDC_PS_MSR		0x0001
#define	CPUPM_INTEL_PDC_C1_HALT		0x0002
#define	CPUPM_INTEL_PDC_TS_MSR		0x0004
#define	CPUPM_INTEL_PDC_MP		0x0008
#define	CPUPM_INTEL_PDC_C2C3_MP		0x0010
#define	CPUPM_INTEL_PDC_SW_PSD		0x0020
#define	CPUPM_INTEL_PDC_TSD		0x0080
#define	CPUPM_INTEL_PDC_C1_FFH		0x0100
#define	CPUPM_INTEL_PDC_HW_PSD		0x0800

static uint32_t cpupm_intel_pdccap = 0;

/*
 * MSR for Intel ENERGY_PERF_BIAS feature.
 * The default processor power operation policy is max performance.
 * Power control unit drives to max performance at any energy cost.
 * This MSR is designed to be a power master control knob,
 * it provides 4-bit OS input to the HW for the logical CPU, based on
 * user power-policy preference(scale of 0 to 15). 0 is highest
 * performance, 15 is minimal energy consumption.
 * 7 is a good balance between performance and energy consumption.
 */
#define	IA32_ENERGY_PERF_BIAS_MSR	0x1B0
#define	EPB_MSR_MASK			0xF
#define	EPB_MAX_PERF			0
#define	EPB_BALANCE			7
#define	EPB_MAX_POWER_SAVE		15

/*
 * The value is used to initialize the user power policy preference
 * in IA32_ENERGY_PERF_BIAS_MSR. Variable is used here to allow tuning
 * from the /etc/system file.
 */
uint64_t cpupm_iepb_policy = EPB_MAX_PERF;

static void cpupm_iepb_set_policy(uint64_t power_policy);

boolean_t
cpupm_intel_init(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	uint_t family;
	uint_t model;

	if (x86_vendor != X86_VENDOR_Intel)
		return (B_FALSE);

	family = cpuid_getfamily(cp);
	model = cpuid_getmodel(cp);

	cpupm_intel_pdccap = CPUPM_INTEL_PDC_MP;

	/*
	 * If we support SpeedStep on this processor, then set the
	 * correct cma_ops for the processor and enable appropriate
	 * _PDC bits.
	 */
	if (speedstep_supported(family, model)) {
		mach_state->ms_pstate.cma_ops = &speedstep_ops;
		cpupm_intel_pdccap |= CPUPM_INTEL_PDC_PS_MSR |
		    CPUPM_INTEL_PDC_C1_HALT | CPUPM_INTEL_PDC_SW_PSD |
		    CPUPM_INTEL_PDC_HW_PSD;
	} else {
		mach_state->ms_pstate.cma_ops = NULL;
	}

	/*
	 * Set the correct tstate_ops for the processor and
	 * enable appropriate _PDC bits.
	 */
	mach_state->ms_tstate.cma_ops = &cpupm_throttle_ops;
	cpupm_intel_pdccap |= CPUPM_INTEL_PDC_TS_MSR |
	    CPUPM_INTEL_PDC_TSD;

	/*
	 * If we support deep cstates on this processor, then set the
	 * correct cstate_ops for the processor and enable appropriate
	 * _PDC bits.
	 */
	mach_state->ms_cstate.cma_ops = &cpu_idle_ops;
	cpupm_intel_pdccap |= CPUPM_INTEL_PDC_C1_HALT |
	    CPUPM_INTEL_PDC_C2C3_MP | CPUPM_INTEL_PDC_C1_FFH;

	/*
	 * _PDC support is optional and the driver should
	 * function even if the _PDC write fails.
	 */
	(void) cpu_acpi_write_pdc(mach_state->ms_acpi_handle,
	    CPUPM_INTEL_PDC_REVISION, 1, &cpupm_intel_pdccap);

	/*
	 * If Intel ENERGY PERFORMANCE BIAS feature is supported,
	 * provides input to the HW, based on user power-policy.
	 */
	if (cpuid_iepb_supported(cp)) {
		cpupm_iepb_set_policy(cpupm_iepb_policy);
	}

	return (B_TRUE);
}

/*
 * ENERGY_PERF_BIAS setting,
 * A hint to HW, based on user power-policy
 */
static void
cpupm_iepb_set_policy(uint64_t iepb_policy)
{
	ulong_t		iflag;
	uint64_t	epb_value;

	epb_value = iepb_policy & EPB_MSR_MASK;

	iflag = intr_clear();
	wrmsr(IA32_ENERGY_PERF_BIAS_MSR, epb_value);
	intr_restore(iflag);
}
