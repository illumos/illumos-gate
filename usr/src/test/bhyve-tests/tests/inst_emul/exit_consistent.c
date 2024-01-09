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
 * Copyright 2023 Oxide Computer Company
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

static void
run_until_unhandled(struct vcpu *vcpu, struct vm_entry *ventry,
    struct vm_exit *vexit)
{
	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, ventry, vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_UNHANDLED:
			return;
		default:
			/*
			 * We are not expecting the payload to use any of the
			 * pass/fail/messaging facilities during this test.
			 */
			test_fail_vmexit(vexit);
			break;
		}
	} while (true);
}

static void
repeat_consistent_exit(struct vcpu *vcpu, struct vm_entry *ventry,
    struct vm_exit *vexit, uint64_t expected_rip)
{
	ventry->cmd = VEC_DEFAULT | VEC_FLAG_EXIT_CONSISTENT;
	if (vm_run(vcpu, ventry, vexit) != 0) {
		test_fail_errno(errno, "Failure during vcpu entry");
	}
	if (vexit->rip != expected_rip) {
		test_fail_msg(
		    "Unexpected forward progress when vCPU already consistent");
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

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}
	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	/*
	 * Let the payload run until it reaches the first userspace exit which
	 * requires actual handling
	 */
	run_until_unhandled(vcpu, &ventry, &vexit);
	if (vexit.exitcode != VM_EXITCODE_RDMSR) {
		test_fail_vmexit(&vexit);
	}
	uint64_t rcx = 0, rip = 0;
	if (vm_get_register(vcpu, VM_REG_GUEST_RCX, &rcx) != 0) {
		test_fail_errno(errno, "Could not read guest %rcx");
	}
	if (vm_get_register(vcpu, VM_REG_GUEST_RIP, &rip) != 0) {
		test_fail_errno(errno, "Could not read guest %rip");
	}
	/* Paranoia: confirm that in-register %rip matches vm_exit data */
	if (rip != vexit.rip) {
		test_fail_msg(
		    "vm_exit`rip does not match in-kernel %rip: %lx != %lx",
		    rip, vexit.rip);
	}

	/* Request a consistent exit */
	ventry.cmd = VEC_DEFAULT | VEC_FLAG_EXIT_CONSISTENT;
	if (vm_run(vcpu, &ventry, &vexit) != 0) {
		test_fail_errno(errno, "Failure during vcpu entry");
	}

	/*
	 * We expect the consistent exit to have completed the instruction
	 * emulation for the rdmsr (just move the %rip forward, since its left
	 * to userspace to update %rax:%rdx) and emit the BOGUS exitcode.
	 */
	if (vexit.exitcode != VM_EXITCODE_BOGUS) {
		test_fail_msg("Unexpected exitcode: %d != %d",
		    vexit.exitcode, VM_EXITCODE_BOGUS);
	}

	/*
	 * Check that the %rip moved forward only the 2 bytes expected for a
	 * rdmsr opcode.
	 */
	if (vexit.rip != (rip + 2)) {
		test_fail_msg("Exited at unexpected %rip: %lx != %lx",
		    vexit.rip, rip + 2);
	}

	/*
	 * Repeat entry with consistency request.  This should not make any
	 * forward progress since the vCPU is already in a consistent state.
	 */
	repeat_consistent_exit(vcpu, &ventry, &vexit, vexit.rip);

	/* Let the vCPU continue on to the next exit condition */
	ventry.cmd = VEC_DEFAULT;
	run_until_unhandled(vcpu, &ventry, &vexit);

	const uint64_t read_addr = 0xc0000000;
	const uint_t read_len = 4;
	if (!vexit_match_mmio(&vexit, true, read_addr, read_len, NULL)) {
		test_fail_vmexit(&vexit);
	}
	rip = vexit.rip;

	/*
	 * An attempt to push the vCPU to a consistent state without first
	 * fulfilling the MMIO should just result in the same MMIO exit.
	 */
	ventry.cmd = VEC_DEFAULT | VEC_FLAG_EXIT_CONSISTENT;
	if (vm_run(vcpu, &ventry, &vexit) != 0) {
		test_fail_errno(errno, "Failure during vcpu entry");
	}
	if (vexit.rip != rip ||
	    !vexit_match_mmio(&vexit, true, read_addr, read_len, NULL)) {
		test_fail_msg(
		    "Unexpected forward progress during MMIO emulation");
	}

	/* Fulfill the MMIO and attempt another consistent exit */
	ventry_fulfill_mmio(&vexit, &ventry, 0);
	ventry.cmd |= VEC_FLAG_EXIT_CONSISTENT;
	if (vm_run(vcpu, &ventry, &vexit) != 0) {
		test_fail_errno(errno, "Failure during vcpu entry");
	}

	/* With current payload, we expect a 3-byte mov instruction */
	if (vexit.rip != (rip + 3)) {
		test_fail_msg("Exited at unexpected %rip: %lx != %lx",
		    vexit.rip, rip + 3);
	}

	/*
	 * And again, check that vCPU remains at that %rip once its state has
	 * been made consistent.
	 */
	repeat_consistent_exit(vcpu, &ventry, &vexit, vexit.rip);

	test_pass();
}
