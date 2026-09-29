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

#include "in_guest.h"

struct rep_state {
	uint64_t rcx;
	uint64_t rsi;
	uint64_t rdi;
};

int
read_rep_state(struct vcpu *vcpu, struct rep_state *state)
{
	if (vm_get_register(vcpu, VM_REG_GUEST_RCX, &state->rcx) != 0) {
		test_fail_errno(errno, "Could not read guest %rsp");
		return (1);
	}
	if (vm_get_register(vcpu, VM_REG_GUEST_RSI, &state->rsi) != 0) {
		test_fail_errno(errno, "Could not read guest %rsi");
		return (1);
	}
	if (vm_get_register(vcpu, VM_REG_GUEST_RDI, &state->rdi) != 0) {
		test_fail_errno(errno, "Could not read guest %rdi");
		return (1);
	}

	return (0);
}

/*
 * Advance the test's guest vCPU to the next `pause`.
 */
int
advance_test(struct vcpu *vcpu)
{
	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	enum vm_exit_kind exit_kind = test_run_vcpu(vcpu, &ventry, &vexit);

	assert(exit_kind == VEK_UNHANDLED);
	if (vexit.exitcode != VM_EXITCODE_PAUSE) {
		test_fail_vmexit(&vexit);
		return (1);
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	struct rep_state state = { 0 };
	uint64_t guest_apicbase, guest_mmio_end, guest_rsp, guest_buf_end;

	ctx = test_initialize(test_suite_name);

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	if (vm_set_capability(vcpu, VM_CAP_PAUSE_EXIT, 1)) {
		perror("failed to set cap\n");
		return (1);
	}

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (vm_get_register(vcpu, VM_REG_GUEST_RSP, &guest_rsp) != 0) {
		test_fail_errno(errno, "Could not read guest %rsp");
	}
	guest_buf_end = guest_rsp + 64;

	if (vm_get_register(vcpu, VM_REG_GUEST_RAX, &guest_apicbase) != 0) {
		test_fail_errno(errno, "Could not read guest %rax");
	}
	guest_mmio_end = guest_apicbase + 64;

	/*
	 * At this point we've collected initial test state that later
	 * rep-prefixed tests will compare against.
	 */

	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (read_rep_state(vcpu, &state) != 0) {
		return (1);
	}

	if (state.rsi != guest_mmio_end) {
		test_fail_msg("rep movsl left %rsi at %p, not %p\n", state.rsi,
		    guest_mmio_end);
		return (1);
	}
	if (state.rdi != guest_buf_end) {
		test_fail_msg("rep movsl left %rdi at %p, not %p\n", state.rdi,
		    guest_buf_end);
		return (1);
	}
	if (state.rcx != 0) {
		test_fail_msg("rep movsl completed with rcx=0x%x\n", state.rcx);
		return (1);
	}

	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (read_rep_state(vcpu, &state) != 0) {
		return (1);
	}

	if (state.rdi != guest_mmio_end) {
		test_fail_msg("rep stosb left %rdi at %p, not %p\n", state.rdi,
		    guest_mmio_end);
		return (1);
	}
	if (state.rcx != 0) {
		test_fail_msg("rep stosb completed with rcx=0x%x\n", state.rcx);
		return (1);
	}

	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (read_rep_state(vcpu, &state) != 0) {
		return (1);
	}

	if (state.rdi != guest_buf_end) {
		test_fail_msg("rep insb left %rdi at %p, not %p\n", state.rdi,
		    guest_buf_end);
		return (1);
	}
	if (state.rcx != 0) {
		test_fail_msg("rep insb completed with rcx=0x%x\n", state.rcx);
		return (1);
	}

	test_pass();
	return (0);
}
