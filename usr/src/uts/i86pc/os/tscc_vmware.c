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
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/x86_archext.h>
#include <sys/tsc.h>

/* For VMs, this leaf will contain the largest VM leaf supported in EAX */
#define	CPUID_VM_LEAF_MAX	0x40000000

/*
 * From https://lwn.net/Articles/301888/:
 * CPUID leaf 0x40000010 (when present on supported VMMs) will contain the TSC
 * frequency in kHz.
 */
#define	CPUID_VM_LEAF_FREQ	0x40000010

/*
 * These get_hwenv() types correspond to the platforms which are known to have
 * support for exposing the TSC frequency via the aforementioned leaf.
 */
#define	HW_SUPPORTS_FREQ	(HW_VMWARE | HW_KVM | HW_VIRTUALBOX | HW_ACRN)

/*
 * Allow bypassing the platform identification step when trying to determine if
 * the host has support for the VM frequency leaf.  This allows use of the leaf
 * on hypervisors which are otherwise unknown.
 */
int tscc_vmware_match_any = 0;

static boolean_t
tsc_calibrate_vmware(uint64_t *freqp)
{
	struct cpuid_regs regs = { 0 };

	/*
	 * Are we on a platform with support?  (or has the administrator
	 * expressed their intent to bypass this check via the config option.)
	 */
	if ((get_hwenv() & HW_SUPPORTS_FREQ) == 0 &&
	    tscc_vmware_match_any == 0) {
		return (B_FALSE);
	}

	/* ... And does it expose up through the required leaf? */
	regs.cp_eax = CPUID_VM_LEAF_MAX;
	__cpuid_insn(&regs);
	if (regs.cp_eax < CPUID_VM_LEAF_FREQ) {
		return (B_FALSE);
	}

	regs.cp_eax = CPUID_VM_LEAF_FREQ;
	__cpuid_insn(&regs);

	/*
	 * While not observed in the wild, as a precautionary measure,
	 * we treat a value of 0 as a failure out of an excess of caution.
	 */
	if (regs.cp_eax == 0) {
		return (B_FALSE);
	}

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
