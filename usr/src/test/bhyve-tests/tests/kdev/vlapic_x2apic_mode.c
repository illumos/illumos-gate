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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Exercise guest-initiated transitions of the LAPIC between the xAPIC, x2APIC
 * and Disabled states via IA32_APIC_BASE: invalid transitions are met with #GP,
 * x2APIC mode cannot be entered unless it is advertised in CPUID, and the
 * mode-dependent registers (ID, LDR) and x2APIC MSR access rules follow each
 * transition.
 *
 * vCPU 17 is used, so that its xAPIC ID, x2APIC ID and logical x2APIC ID
 * (including the cluster) are distinct and non-zero.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <libgen.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "in_guest.h"
#include "test_defs.h"

#define	TEST_VCPUID	17

/*
 * Configure userspace-provided CPUID for the test vCPU, advertising x2APIC
 * support (or not) as requested.
 */
static void
set_cpuid(int vmfd, bool x2apic)
{
	struct vcpu_cpuid_entry entries[] = {
		{
			.vce_function = 0,
			.vce_eax = 1,
		},
		{
			.vce_function = 1,
			.vce_ecx = x2apic ? CPUID1_ECX_X2APIC : 0,
		},
	};
	struct vm_vcpu_cpuid_config cfg = {
		.vvcc_vcpuid = TEST_VCPUID,
		.vvcc_flags = 0,
		.vvcc_nent = ARRAY_SIZE(entries),
		.vvcc_entries = entries,
	};

	if (ioctl(vmfd, VM_SET_CPUID, &cfg) != 0) {
		test_fail_errno(errno, "ioctl(VM_SET_CPUID) failed");
	}
}

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	ctx = test_initialize(test_suite_name);

	if ((vcpu = vm_vcpu_open(ctx, TEST_VCPUID)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu");
	}

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu");
	}

	/* x2APIC starts out unadvertised, until the payload requests it */
	const int vmfd = vm_get_device_fd(ctx);
	set_cpuid(vmfd, false);

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
			test_fail();
			break;
		case VEK_TEST_MSG:
			test_msg_print(ctx);
			break;
		case VEK_UNHANDLED: {
			uint32_t val;

			if (vexit_match_inout(&vexit, true, IOP_TEST_PARAM, 4,
			    NULL)) {
				ventry_fulfill_inout(&vexit, &ventry,
				    TEST_VCPUID);
			} else if (vexit_match_inout(&vexit, false,
			    IOP_TEST_VALUE, 4, &val) && val == 1) {
				set_cpuid(vmfd, true);
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
