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
 * Test that adjusting the guest TSC with VMM time data interface is visible
 * in guest.
 *
 * Note: requires `vmm_allow_state_writes` to be set
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

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	int err;

	ctx = test_initialize(test_suite_name);

	err = test_setup_vcpu(ctx, 0, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	const int vmfd = vm_get_device_fd(ctx);

	/* Read time data to get baseline guest time values */
	struct vdi_time_info_v1 time_info;
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &time_info,
	};
	if (ioctl(vmfd, VM_DATA_READ, &xfer) != 0) {
		errx(EXIT_FAILURE, "VMM_DATA_READ of time info failed");
	}

	/* Change the guest TSC to a much larger value */
	uint64_t expect_tsc = 500000000000;
	time_info.vt_guest_tsc = expect_tsc;
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) != 0) {
		int error;
		error = errno;
		if (error == EPERM) {
			warn("VMM_DATA_WRITE got EPERM: is "
			    "vmm_allow_state_writes set?");
		}
		errx(EXIT_FAILURE, "VMM_DATA_WRITE of time info failed");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	bool half_read = false;
	uint64_t tsc;

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(ctx, 0, &ventry, &vexit);

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

				/*
				 * Check that the TSC reading is at least the
				 * absurdly high value it was set to.
				 */
				if (tsc >= expect_tsc) {
					(void) printf("tsc=%ld\n", tsc);
					test_pass();
				} else {
					test_fail_msg("TSC %lu < %lu\n", tsc,
					    expect_tsc);
				}
			}
		} else {
			test_fail_vmexit(&vexit);
		}
	} while (true);
}
