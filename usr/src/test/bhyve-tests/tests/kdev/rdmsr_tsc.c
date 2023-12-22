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

/*
 * Test guest reads of the TSC via rdmsr (following a write to the TSC)
 */

#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <err.h>

#include <sys/vmm_data.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "in_guest.h"
#include "test_defs.h"

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

	struct vm_entry ventry = { 0 }; struct vm_exit vexit = { 0 };
	bool half_read = false;
	uint64_t tsc;

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);

		if (kind == VEK_REENTR) {
			continue;
		} else if (kind != VEK_UNHANDLED) {
			test_fail_vmexit(&vexit);
		}

		uint32_t val;
		if (vexit_match_inout(&vexit, false, IOP_TEST_VALUE, 4,
		    &val)) {
			if (!half_read) {
				/* low 32-bits of TSC first */
				tsc = val;
				half_read = true;
				ventry_fulfill_inout(&vexit, &ventry, 0);
			} else {
				/* high 32-bits of TSC */
				tsc |= ((uint64_t)val << 32);
				printf("tsc=%lu\n", tsc);

				/*
				 * Check that the TSC reading is at least the
				 * high value it was set to by the guest.
				 *
				 * If we wanted to be more precise about it, we
				 * could get the host frequency and calculate
				 * ppm error.
				 *
				 */
				if (tsc < TSC_TARGET_WRVAL) {
					test_fail_msg("TSC %lu < %lu", tsc,
					    TSC_TARGET_WRVAL);
				} else {
					test_pass();
				}
			}
		} else {
			test_fail_vmexit(&vexit);
		}
	} while (true);
}
