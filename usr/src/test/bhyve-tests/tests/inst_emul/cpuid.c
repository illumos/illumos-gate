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
 * Copyright 2022 Oxide Computer Company
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

static const struct vcpu_cpuid_entry test_entries[] = {
	{
		.vce_function = 0,
		.vce_eax = 5,
		.vce_ebx = 0x74737552,
		.vce_edx = 0x4f206465,
		.vce_ecx = 0x65646978,
	},
	/* basic "std" leaf */
	{
		.vce_function = 1,
		.vce_eax = 0x100,
	},

	/* skip 2 for a hole */

	/* leaf with index matching */
	{
		.vce_function = 3,
		.vce_index = 0,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = 0x300,
	},
	{
		.vce_function = 3,
		.vce_index = 1,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = 0x301,
	},

	/* leaf with index matching and a hole */
	{
		.vce_function = 4,
		.vce_index = 0,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = 0x400,
	},
	{
		.vce_function = 4,
		.vce_index = 2,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = 0x402,
	},

	/* terminal "std" leaf */
	{
		.vce_function = 5,
		.vce_eax = 5,
		.vce_ebx = 5,
		.vce_edx = 5,
		.vce_ecx = 5,
	},

	/* base "extended" leaf */
	{
		.vce_function = 0x80000000,
		.vce_eax = 0x80000001,
	},
	/* index-match "extended" leaves */
	{
		.vce_function = 0x80000001,
		.vce_index = 0x0,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = 0x8000,
	},
	{
		.vce_function = 0x80000001,
		.vce_index = 0x1,
		.vce_flags = VCE_FLAG_MATCH_INDEX,
		.vce_eax = 0x8001,
	},
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


	/* Start with test data using Intel-style fallback */
	int vmfd = vm_get_device_fd(ctx);

	struct vm_vcpu_cpuid_config cfg = {
		.vvcc_vcpuid = 0,
		.vvcc_flags = VCC_FLAG_INTEL_FALLBACK,
		.vvcc_nent = ARRAY_SIZE(test_entries),
		/* We trust the ioctl not to alter this const value */
		.vvcc_entries = (struct vcpu_cpuid_entry *)test_entries,
	};
	err = ioctl(vmfd, VM_SET_CPUID, &cfg);
	if (err != 0) {
		test_fail_errno(err, "ioctl(VM_SET_CPUID) failed");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_TEST_PASS:
			test_pass();
			break;
		case VEK_TEST_FAIL:
			test_fail_msg("failed result %rip: %x", vexit.rip);
			break;
		case VEK_UNHANDLED: {
			uint32_t val;
			if (vexit_match_inout(&vexit, false, IOP_TEST_VALUE, 4,
			    &val)) {
				/*
				 * The payload has requested switch to AMD-style
				 * fallback to run the second half of the test.
				 */
				cfg.vvcc_flags = 0;
				err = ioctl(vmfd, VM_SET_CPUID, &cfg);
				if (err != 0) {
					test_fail_errno(err,
					    "ioctl(VM_SET_CPUID) failed");
				}
				ventry_fulfill_inout(&vexit, &ventry, 0);
			} else {
				test_fail_vmexit(&vexit);
			}
			break;
		}

		default:
			test_fail_vmexit(&vexit);
			break;
		}
	} while (true);
}
