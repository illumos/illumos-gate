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

#include <stdbool.h>
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

#include "common.h"
#include "in_guest.h"

/*
 * Show that on an Intel host, legacy CPUID emulation does not allow through
 * certain AMD-specific bits.
 *
 * This test and the logic it exercises in `legacy_emulate_cpuid` does not
 * exhaustively cover all the leaves where there are potential vendor
 * differences. They instead focus on fixing misbehaviors that have been
 * observed in real configurations.
 */
int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	ctx = test_initialize(test_suite_name);

	/* Bail out early on non-Intel. */
	if (!cpu_vendor_intel()) {
		(void) fprintf(stderr, "CPU is not Intel\n");
		(void) printf("%s\tSKIP\n", test_suite_name);
		exit(EXIT_SUCCESS);
	}

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	err = vm_set_capability(vcpu, VM_CAP_PAUSE_EXIT, 1);
	if (err != 0) {
		test_fail_errno(errno, "Could not set vcpu cap");
	}

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_UNHANDLED:
			/*
			 * Expect the guest to pause after running cpuid
			 * 8000_0008.
			 */
			if (vexit.exitcode != VM_EXITCODE_PAUSE) {
				test_fail_vmexit(&vexit);
			}
			/*
			 * The masking logic for 8000_0008 does not touch EAX,
			 * so we don't assert on its value. No bits should be
			 * set in the other registers.
			 */
			if (vm_get_register(vcpu, VM_REG_GUEST_RBX,
			    &rbx) != 0) {
				test_fail_errno(errno,
				    "Could not read guest rbx");
			}
			if (vm_get_register(vcpu, VM_REG_GUEST_RCX,
			    &rcx) != 0) {
				test_fail_errno(errno,
				    "Could not read guest rcx");
			}
			if (vm_get_register(vcpu, VM_REG_GUEST_RDX,
			    &rdx) != 0) {
				test_fail_errno(errno,
				    "Could not read guest rdx");
			}
			if (rbx != 0 || rcx != 0 || rdx != 0) {
				test_fail_msg("guest sees set bits in "
				    "8000_0008 registers on Intel: "
				    "ebx=%08x ecx=%08x edx=%08x\n",
				    (uint32_t)rbx, (uint32_t)rcx,
				    (uint32_t)rdx);
			}
			test_pass();
			break;
		default:
			test_fail_vmexit(&vexit);
			break;
		}
	} while (true);
}
