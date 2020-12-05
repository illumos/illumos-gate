/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2026 RackTop Systems, Inc.
 */

#include <sys/tsc.h>
#include <sys/x86_archext.h>
#include <sys/prom_debug.h>
#include <sys/cpuvar.h>

/* The core crystal clock frequency of Denverton SoC in Hz */
#define	DENVERTON_CRYSTAL_HZ	25000000

static uint32_t
tsc_cpuid_maxleaf(void)
{
	struct cpuid_regs regs = { 0 };

	return (__cpuid_insn(&regs));
}

static boolean_t
tsc_calibrate_cpuid(uint64_t *freqp)
{
	struct cpuid_regs regs = { 0 };
	uint64_t crystal;

	PRM_POINT("Attempting to use CPUID instruction for TSC calibration...");

	if (cpuid_getvendor(CPU) != X86_VENDOR_Intel)
		return (B_FALSE);

	/* The frequency, divisor, etc are (if present) in leaf 0x15 */
	if (tsc_cpuid_maxleaf() < 0x15)
		return (B_FALSE);

	regs.cp_eax = 0x15;
	__cpuid_insn(&regs);

	crystal = regs.cp_ecx;

	/*
	 * Linux discovered that Denverton SoCs do not report their
	 * core crystal clock value (ECX) in leaf 0x15. However the
	 * value is both known and fixed for these chips, so we can utilize
	 * that knowledge and still calculate the TSC frequency.
	 */
	if (crystal == 0 && cpuid_getfamily(CPU) == 6 &&
	    cpuid_getmodel(CPU) == INTC_MODEL_DENVERTON) {
		crystal = DENVERTON_CRYSTAL_HZ;
	}

	/*
	 * Not all CPU models report all three parameters. For those
	 * that don't we fall back to other methods to calculate the
	 * TSC frequency.
	 */
	if (crystal == 0 || regs.cp_eax == 0 || regs.cp_ebx == 0)
		return (B_FALSE);

	/*
	 * Note the order to ensure the calculation is done as
	 * 64-bit to avoid overflow.
	 */
	*freqp = crystal * regs.cp_ebx / regs.cp_eax;

	return (B_TRUE);
}

static tsc_calibrate_t tsc_calibration_cpuid = {
	.tscc_source = "CPUID",
	.tscc_preference = 90,
	.tscc_calibrate = tsc_calibrate_cpuid,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_cpuid);
