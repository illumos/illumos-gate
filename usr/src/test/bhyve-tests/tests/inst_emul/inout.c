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
 * Copyright 2024 Oxide Computer Company
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

enum test_state {
	SEEKING_IN,
	SEEKING_OUT,
	SEEKING_END,
	DONE,
};

bool
advance_test_state(const struct vm_exit *vexit, struct vm_entry *ventry,
    struct vcpu *vcpu, enum vm_exit_kind kind, enum test_state *state,
    const bool have_decodeassist)
{
	if (*state != DONE && kind == VEK_REENTR) {
		return (true);
	}

	switch (*state) {
	case SEEKING_IN:
		if (kind != VEK_UNHANDLED) {
			break;
		}

		if (have_decodeassist) {
			if (vexit->exitcode != VM_EXITCODE_INOUT) {
				break;
			}

			const bool match_inb =
			    vexit_match_inout(vexit, true, 0x55aa, 1, NULL);
			if (!match_inb) {
				break;
			}

			ventry_fulfill_inout(vexit, ventry, 0xee);
		} else {
			if (vexit->exitcode != VM_EXITCODE_INST_EMUL) {
				break;
			}

			const bool match_inb =
			    vexit->u.inst_emul.num_valid >= 2 &&
			    vexit->u.inst_emul.inst[0] == 0xf3 &&
			    vexit->u.inst_emul.inst[1] == 0x6c;
			if (!match_inb) {
				break;
			}

			int err = vm_set_register(vcpu, 0, vexit->rip + 2);
			if (err != 0) {
				test_fail_errno(err, "failed to set %rip");
			}
		}
		*state = SEEKING_OUT;
		return (true);
	case SEEKING_OUT:
		if (kind != VEK_UNHANDLED) {
			break;
		}

		if (have_decodeassist) {
			if (vexit->exitcode != VM_EXITCODE_INOUT) {
				break;
			}

			const bool match_outb =
			    vexit_match_inout(vexit, false, 0x55aa, 1, NULL);
			if (!match_outb) {
				break;
			}

			ventry_fulfill_inout(vexit, ventry, 0);
		} else {
			if (vexit->exitcode != VM_EXITCODE_INST_EMUL) {
				break;
			}

			const bool match_outb =
			    vexit->u.inst_emul.num_valid >= 2 &&
			    vexit->u.inst_emul.inst[0] == 0xf3 &&
			    vexit->u.inst_emul.inst[1] == 0x6e;
			if (!match_outb) {
				break;
			}

			int err = vm_set_register(vcpu, 0, vexit->rip + 2);
			if (err != 0) {
				test_fail_errno(err, "failed to set %rip");
			}
		}
		*state = SEEKING_END;
		return (true);
	case SEEKING_END:
		if (kind == VEK_TEST_PASS) {
			*state = DONE;
			return (true);
		}
		break;
	case DONE:
		break;
	}

	return (false);
}

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	ctx = test_initialize(test_suite_name);

	/*
	 * Guest execution of `in` and `out` instructions (and their repeatable
	 * string versions) can have substantially different outcomes depending
	 * on available hardware support.
	 *
	 * For simple `in` or `out`, `byhve` will cause a VM exit with exit
	 * code `VM_EXITCODE_INOUT`. This is the simplest case, and not
	 * currently exercised in this test.
	 *
	 * For `ins` and `outs`, decoding the exact operation is more complex.
	 * For processors with the DecodeAssist feature, we rely on the
	 * processor to do that decoding and provide information about the
	 * trapped instruction. As a result, `ins` and `outs` on such processors
	 * result in a VM exit with code `VM_EXITCODE_INOUT`.
	 *
	 * Finally, if DecodeAssist is *not* available, we don't currently do
	 * any in-kernel disassembly to backfill the missing functionality. So
	 * instead, `ins`/`outs` on processors without DecodeAssist result in a
	 * VM exit with code `VM_EXITCODE_INST_EMUL`.
	 *
	 * Since the kernel behavior varies based on hardware features, detect
	 * DecodeAssist here as well to check for what we expect the kernel to
	 * do on this processor.
	 */
	uint_t regs[4];
	do_cpuid(0x8000000a, regs);
	const bool have_decodeassist = (regs[3] & (1 << 7)) != 0;

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	enum test_state state = SEEKING_IN;

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);

		const bool exit_ok = advance_test_state(&vexit, &ventry, vcpu,
		    kind, &state, have_decodeassist);

		if (!exit_ok) {
			test_fail_vmexit(&vexit);
			break;
		}
	} while (state != DONE);

	test_pass();
}
