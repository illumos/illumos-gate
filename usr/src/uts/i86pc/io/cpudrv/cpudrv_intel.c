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

/*
 * Intel specific CPU power management support.
 */

#include <sys/x86_archext.h>
#include <sys/cpudrv_mach.h>
#include <sys/cpu_acpi.h>
#include <sys/speedstep.h>
#include <sys/cpudrv_throttle.h>

/*
 * The Intel Processor Driver Capabilities (_PDC).
 * See Intel Processor Vendor-Specific ACPI Interface Specification
 * for details.
 */
#define	CPUDRV_INTEL_PDC_REVISION	0x1
#define	CPUDRV_INTEL_PDC_PS_MSR		0x0001
#define	CPUDRV_INTEL_PDC_C1_HALT	0x0002
#define	CPUDRV_INTEL_PDC_TS_MSR		0x0004
#define	CPUDRV_INTEL_PDC_MP		0x0008
#define	CPUDRV_INTEL_PDC_PSD		0x0020
#define	CPUDRV_INTEL_PDC_TSD		0x0080

static uint32_t cpudrv_intel_pdccap = 0;

boolean_t
cpudrv_intel_init(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	uint_t family;
	uint_t model;

	if (x86_vendor != X86_VENDOR_Intel)
		return (B_FALSE);

	family = cpuid_getfamily(CPU);
	model = cpuid_getmodel(CPU);

	/*
	 * If we support SpeedStep on this processor, then set the
	 * correct pstate_ops for the processor and enable appropriate
	 * _PDC bits.
	 */
	if (speedstep_supported(family, model)) {
		mach_state->cpupm_pstate_ops = &speedstep_ops;
		cpudrv_intel_pdccap = CPUDRV_INTEL_PDC_PS_MSR |
		    CPUDRV_INTEL_PDC_C1_HALT | CPUDRV_INTEL_PDC_MP |
		    CPUDRV_INTEL_PDC_PSD;
	} else {
		mach_state->cpupm_pstate_ops = NULL;
	}

	/*
	 * Set the correct tstate_ops for the processor and
	 * enable appropriate _PDC bits.
	 */
	mach_state->cpupm_tstate_ops = &cpudrv_throttle_ops;
	cpudrv_intel_pdccap |= CPUDRV_INTEL_PDC_TS_MSR |
	    CPUDRV_INTEL_PDC_TSD;

	/*
	 * _PDC support is optional and the driver should
	 * function even if the _PDC write fails.
	 */
	(void) cpu_acpi_write_pdc(mach_state->acpi_handle,
	    CPUDRV_INTEL_PDC_REVISION, 1, &cpudrv_intel_pdccap);

	return (B_TRUE);
}
