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
 * Copyright 2021 Jason King
 */

#include <sys/x86_archext.h>
#include <sys/tsc.h>

/* For VMs, this leaf will contain the largest VM leaf supported in EAX */
#define	CPUID_VM_LEAF_MAX	0x40000000

/*
 * From https://lwn.net/Articles/301888/, CPUID leaf 0x40000010 (when present)
 * on VMware will contain the TSC frequency in kHz. While it would have been
 * nice to locate an official bit of documentation from VMware, implementations
 * in both Linux and FreeBSD agree with the above link, so it seems reasonable
 * to use it as well.
 */
#define	CPUID_VM_LEAF_FREQ	0x40000010

static boolean_t
tsc_calibrate_vmware(uint64_t *freqp)
{
	if (get_hwenv() != HW_VMWARE)
		return (B_FALSE);

	struct cpuid_regs regs = { 0 };

	/* First determine the largest VM leaf supported */
	regs.cp_eax = CPUID_VM_LEAF_MAX;
	__cpuid_insn(&regs);

	if (regs.cp_eax < CPUID_VM_LEAF_FREQ)
		return (B_FALSE);

	regs.cp_eax = CPUID_VM_LEAF_FREQ;
	__cpuid_insn(&regs);

	/*
	 * While not observed in the wild, as a precautionary measure,
	 * we treat a value of 0 as a failure out of an excess of caution.
	 */
	if (regs.cp_eax == 0)
		return (B_FALSE);

	/* Convert from kHz to Hz */
	*freqp = (uint64_t)regs.cp_eax * 1000;

	return (B_TRUE);
}

static tsc_calibrate_t tsc_calibration_vmware = {
	.tscc_source = "VMware",
	.tscc_preference = 100,
	.tscc_calibrate = tsc_calibrate_vmware,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_vmware);
