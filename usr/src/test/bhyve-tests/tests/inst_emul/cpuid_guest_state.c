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
 * This test verifies that CPUID emulation properly adjusts output values that
 * vary with the state of the calling processor.
 *
 * Copyright 2025 Oxide Computer Company
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <libgen.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "in_guest.h"
#include "cpuid_guest_state.h"

static const struct vcpu_cpuid_entry test_entries[] = {
	{
		.vce_function = 0,
		.vce_eax = TEST_CPUID_0_EAX,
		.vce_ebx = TEST_CPUID_0_EBX,
		.vce_ecx = TEST_CPUID_0_ECX,
		.vce_edx = TEST_CPUID_0_EDX,
	},
	/*
	 * Leaf 1 has the following variable bits:
	 *
	 * - ecx bit 27: Set only if ecx bit 26 is set and the guest has enabled
	 *   XSAVE instructions in cr4.
	 * - edx bit 9: Set only if the local APIC is enabled in
	 *   IA32_APIC_BASE MSR (0x1B).
	 *
	 * eax and ebx should be unmodified.
	 */
	{
		.vce_function = 1,
		.vce_eax = TEST_CPUID_1_EAX,
		.vce_ebx = TEST_CPUID_1_EBX,
		.vce_ecx = TEST_CPUID_1_ECX,
		.vce_edx = TEST_CPUID_1_EDX,
	},
	/*
	 * Leaf D index 0 returns supported extended processor feature state
	 * information in eax, ecx, and edx. ebx receives the size of the
	 * XSAVE feature area for the features the guest has enabled in xcr0.
	 * This value is not populated in the table; instead it is read by
	 * the host with the guest's xcr0 value still intact.
	 *
	 * Advertise support for x87, SSE, and AVX in eax. These features have
	 * well-known save area sizes (0x240 bytes for x87/SSE, 0x100 bytes
	 * for AVX).
	 */
	{
		.vce_function = 0xD,
		.vce_index = 0,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = TEST_CPUID_D_0_EAX,
		.vce_ebx = 0,
		.vce_ecx = XSAVE_AREA_SIZE_MAX,
		.vce_edx = 0,
	},
	/*
	 * Leaf D index 1 is similar to index 0, except that the required size
	 * in ebx includes the space needed to support features enabled in the
	 * IA32_XSS MSR (0xDA0).
	 *
	 * On Intel platforms, the value returned in ebx also depends on whether
	 * the appropriate state-save instructions are advertised in eax. This
	 * behavior is not directly tested here since it is host-platform
	 * dependent; instead this test value for eax advertises all extant
	 * state-save instructions.
	 */
	{
		.vce_function = 0xD,
		.vce_index = 1,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = TEST_CPUID_D_1_EAX,
		.vce_ebx = 0,
		.vce_ecx = 0,
		.vce_edx = 0,
	}
};

/*
 * Entries used to test what happens when the guest specifies an invalid CPUID
 * leaf/subleaf. In this array:
 *
 * - Exclude leaf 1 to test that accessing a missing leaf whose number is less
 *   than the maximum present leaf returns all 0s (even if a fixup would be
 *   applied had the requested leaf been present).
 * - Include leaf D to test that fallback to the maximum standard leaf still
 *   applies fixups.
 */
static const struct vcpu_cpuid_entry fallback_test_entries[] = {
	{
		.vce_function = 0,
		.vce_eax = TEST_CPUID_0_EAX,
		.vce_ebx = TEST_CPUID_0_EBX,
		.vce_ecx = TEST_CPUID_0_ECX,
		.vce_edx = TEST_CPUID_0_EDX,
	},
	{
		.vce_function = 0xD,
		.vce_index = 0,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = TEST_CPUID_D_0_EAX,
		.vce_ebx = 0,
		.vce_ecx = XSAVE_AREA_SIZE_MAX,
		.vce_edx = 0,
	},
	{
		.vce_function = 0xD,
		.vce_index = 1,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = 0x0000000F,
		.vce_ebx = 0,
		.vce_ecx = 0,
		.vce_edx = 0,
	}
};

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	ctx = test_initialize(test_suite_name);
	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };
	enum vm_exit_kind kind;

	/*
	 * Rely on legacy CPUID emulation for the first part of the test, but
	 * go ahead and grab the appropriate descriptor and set up the control
	 * structure needed for later explicit emulation.
	 */
	int vmfd = vm_get_device_fd(ctx);
	struct {
		char *name;
		bool pass_expected;
	} phases[4] = {
		{"legacy emulation mode", false},
		{"explicit mode", false},
		{"explicit mode w/Intel fallback enabled", false},
		{"fallback variations", true}
	};

	for (int i = 0; i < ARRAY_SIZE(phases); i++) {
		kind = test_run_vcpu(vcpu, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			test_fail_msg("unexpected exit in %s", phases[i].name);
			goto done;
		case VEK_TEST_PASS:
			if (phases[i].pass_expected) {
				test_pass();
			} else {
				test_fail_msg("unexpected pass from %s",
				    phases[i].name);
			}
			goto done;
		case VEK_TEST_FAIL:
			test_fail_msg("failed result in %s, %rip: %x",
			    phases[i].name, vexit.rip);
			goto done;
		case VEK_UNHANDLED: {
			uint32_t finished_phase;

			if (!vexit_match_inout(&vexit, false, IOP_TEST_VALUE, 4,
			    &finished_phase)) {
				test_fail_vmexit(&vexit);
				goto done;
			}
			if (finished_phase != i) {
				test_fail_vmexit(&vexit);
				goto done;
			}
			break;
		}
		default:
			test_fail_vmexit(&vexit);
			break;
		}

		/*
		 * The driver got past this variation. Check the phase number
		 * to see how to set up explicit CPUID for the next variation.
		 */
		struct vm_vcpu_cpuid_config cfg = {
			.vvcc_vcpuid = 0,
			.vvcc_flags = 0,
			.vvcc_nent = ARRAY_SIZE(test_entries),
			/* We trust the ioctl not to alter this const value */
			.vvcc_entries = (struct vcpu_cpuid_entry *)test_entries,
		};
		switch (i) {
		case 0:
			/* Nothing special to do for the first explicit test. */
			break;
		case 1:
			cfg.vvcc_flags = VCC_FLAG_INTEL_FALLBACK;
			break;
		case 2:
			cfg.vvcc_flags = VCC_FLAG_INTEL_FALLBACK;
			cfg.vvcc_nent = ARRAY_SIZE(fallback_test_entries);
			cfg.vvcc_entries =
			    (struct vcpu_cpuid_entry *)fallback_test_entries;
			break;
		default:
			test_fail_msg("phase %d fell through without passing",
			    i);
			goto done;
		}

		err = ioctl(vmfd, VM_SET_CPUID, &cfg);
		if (err != 0) {
			test_fail_errno(err, "ioctl(VM_SET_CPUID) failed");
		}
		ventry_fulfill_inout(&vexit, &ventry, 0);
	}

done:
	return (0);
}
