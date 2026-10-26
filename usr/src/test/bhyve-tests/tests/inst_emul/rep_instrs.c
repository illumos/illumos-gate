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
 * Copyright 2026 Edgecast Cloud LLC.
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
#include "rep_instrs.h"

#define	PT_VALID	0x01

/* #PF error code for a supervisor write to a not-present page */
#define	PF_ERR_WRITE	0x02

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

	for (;;) {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);

		switch (kind) {
		case VEK_REENTR:
			/*
			 * Spurious (BOGUS) exits, such as when emulation of a
			 * rep-prefixed instruction yields, are re-entered.
			 */
			break;
		case VEK_UNHANDLED:
			if (vexit.exitcode != VM_EXITCODE_PAUSE) {
				test_fail_vmexit(&vexit);
				return (1);
			}
			return (0);
		default:
			test_fail_msg("Unexpected exit kind %d before pause\n",
			    kind);
			return (1);
		}
	}
}

/*
 * Set or clear the valid bit in the identity-mapped 2MiB PTE covering `addr`.
 */
void
set_page_present(struct vmctx *ctx, uint64_t addr, bool present)
{
	const uint64_t pte_loc = MEM_LOC_PAGE_TABLE_2M +
	    (addr >> 21) * sizeof (uint64_t);
	uint64_t *ptep = vm_map_gpa(ctx, pte_loc, sizeof (uint64_t));

	if (ptep == NULL) {
		test_fail_msg("Could not map PTE for 0x%lx\n", addr);
	}

	if (present) {
		*ptep |= PT_VALID;
	} else {
		*ptep &= ~PT_VALID;
	}
}

/*
 * With the guest stopped in its #PF handler, check that the fault was taken
 * at `fault_addr` with the saved %rip pointing at the faulting rep-prefixed
 * instruction (as recorded by the payload in %rbx), so that returning from
 * the handler resumes the remaining iterations.
 */
int
check_page_fault(struct vmctx *ctx, struct vcpu *vcpu, const char *name,
    uint64_t fault_addr)
{
	uint64_t marker, rsp, inst_rip, cr2;
	const uint64_t *frame;

	if (vm_get_register(vcpu, VM_REG_GUEST_R8, &marker) != 0) {
		test_fail_errno(errno, "Could not read guest %r8");
		return (1);
	}
	if (marker != PF_VECTOR) {
		test_fail_msg("%s did not take #PF\n", name);
		return (1);
	}
	if (vm_get_register(vcpu, VM_REG_GUEST_RSP, &rsp) != 0) {
		test_fail_errno(errno, "Could not read guest %rsp");
		return (1);
	}
	if (vm_get_register(vcpu, VM_REG_GUEST_RBX, &inst_rip) != 0) {
		test_fail_errno(errno, "Could not read guest %rbx");
		return (1);
	}
	if (vm_get_register(vcpu, VM_REG_GUEST_CR2, &cr2) != 0) {
		test_fail_errno(errno, "Could not read guest %cr2");
		return (1);
	}

	/* The stack is identity-mapped, so %rsp is also its GPA */
	frame = vm_map_gpa(ctx, rsp, 2 * sizeof (uint64_t));
	if (frame == NULL) {
		test_fail_msg("Could not map #PF frame at 0x%lx\n", rsp);
		return (1);
	}

	if (cr2 != fault_addr) {
		test_fail_msg("%s faulted with %%cr2=0x%lx, not 0x%lx\n", name,
		    cr2, fault_addr);
		return (1);
	}
	if (frame[0] != PF_ERR_WRITE) {
		test_fail_msg("%s faulted with error code 0x%lx, not 0x%x\n",
		    name, frame[0], PF_ERR_WRITE);
		return (1);
	}
	if (frame[1] != inst_rip) {
		test_fail_msg("%s faulted with saved %%rip=0x%lx, not 0x%lx\n",
		    name, frame[1], inst_rip);
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

	set_page_present(ctx, INS_FAULT_ADDR, false);
	set_page_present(ctx, MOVS_FAULT_ADDR, false);

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

	/*
	 * rep insb of 64 bytes, starting 16 bytes before a not-present page.
	 */
	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (check_page_fault(ctx, vcpu, "rep insb", INS_FAULT_ADDR) != 0) {
		return (1);
	}

	if (read_rep_state(vcpu, &state) != 0) {
		return (1);
	}

	if (state.rdi != INS_FAULT_ADDR) {
		test_fail_msg("faulting rep insb left %%rdi at 0x%lx, "
		    "not 0x%lx\n", state.rdi, INS_FAULT_ADDR);
		return (1);
	}
	if (state.rcx != 48) {
		test_fail_msg("faulting rep insb left rcx=0x%lx, not 0x30\n",
		    state.rcx);
		return (1);
	}

	set_page_present(ctx, INS_FAULT_ADDR, true);

	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (read_rep_state(vcpu, &state) != 0) {
		return (1);
	}

	if (state.rdi != INS_FAULT_ADDR + 48) {
		test_fail_msg("resumed rep insb left %%rdi at 0x%lx, "
		    "not 0x%lx\n", state.rdi, INS_FAULT_ADDR + 48);
		return (1);
	}
	if (state.rcx != 0) {
		test_fail_msg("resumed rep insb completed with rcx=0x%lx\n",
		    state.rcx);
		return (1);
	}

	/*
	 * rep movsl of 16 dwords from the xAPIC, starting 16 bytes before a
	 * not-present page.
	 */
	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (check_page_fault(ctx, vcpu, "rep movsl", MOVS_FAULT_ADDR) != 0) {
		return (1);
	}

	if (read_rep_state(vcpu, &state) != 0) {
		return (1);
	}

	if (state.rsi != guest_apicbase + 16) {
		test_fail_msg("faulting rep movsl left %%rsi at 0x%lx, "
		    "not 0x%lx\n", state.rsi, guest_apicbase + 16);
		return (1);
	}
	if (state.rdi != MOVS_FAULT_ADDR) {
		test_fail_msg("faulting rep movsl left %%rdi at 0x%lx, "
		    "not 0x%lx\n", state.rdi, MOVS_FAULT_ADDR);
		return (1);
	}
	if (state.rcx != 12) {
		test_fail_msg("faulting rep movsl left rcx=0x%lx, not 0xc\n",
		    state.rcx);
		return (1);
	}

	set_page_present(ctx, MOVS_FAULT_ADDR, true);

	if (advance_test(vcpu) != 0) {
		return (1);
	}

	if (read_rep_state(vcpu, &state) != 0) {
		return (1);
	}

	if (state.rsi != guest_mmio_end) {
		test_fail_msg("resumed rep movsl left %%rsi at 0x%lx, "
		    "not 0x%lx\n", state.rsi, guest_mmio_end);
		return (1);
	}
	if (state.rdi != MOVS_FAULT_ADDR + 48) {
		test_fail_msg("resumed rep movsl left %%rdi at 0x%lx, "
		    "not 0x%lx\n", state.rdi, MOVS_FAULT_ADDR + 48);
		return (1);
	}
	if (state.rcx != 0) {
		test_fail_msg("resumed rep movsl completed with rcx=0x%lx\n",
		    state.rcx);
		return (1);
	}

	test_pass();
	return (0);
}
