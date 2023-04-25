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
 * Test guest frequency control
 *
 * Note: requires `vmm_allow_state_writes` to be set, and only on AMD
 */

#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <err.h>

#include <sys/time.h>
#include <sys/vmm_data.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"
#include "in_guest.h"

#define	PPM_MARGIN	200

typedef struct tsc_reading {
	hrtime_t when;
	uint64_t tsc;
} tsc_reading_t;

static bool
check_reading(tsc_reading_t r1, tsc_reading_t r2, uint64_t guest_freq,
    uint64_t min_ticks, uint64_t tick_margin, uint32_t ppm_margin)
{
	hrtime_t time_delta = r2.when - r1.when;
	uint64_t tick_delta = r2.tsc - r1.tsc;

	/* check that number of ticks seen is valid */
	if (tick_delta < min_ticks) {
		test_fail_msg("inadequate passage of guest TSC ticks %u < %u\n",
		    tick_delta, min_ticks);
	} else if ((tick_delta - min_ticks) > tick_margin) {
		(void) printf("%u ticks outside margin %u\n", tick_delta,
		    min_ticks + tick_margin);
		return (false);
	}

	/* compute ppm error and validate */
	hrtime_t time_target = (tick_delta * NANOSEC) / guest_freq;
	hrtime_t offset;
	if (time_delta < time_target) {
		offset = time_target - time_delta;
	} else {
		offset = time_delta - time_target;
	}
	uint64_t ppm = (offset * 1000000) / time_target;
	(void) printf("%u ticks in %lu ns (error %lu ppm)\n",
	    tick_delta, time_delta, ppm);
	if (ppm > ppm_margin) {
		(void) printf("UNACCEPTABLE!\n");
		return (false);
	}
	return (true);
}

void
do_freq_test(uint64_t guest_freq, uint8_t per_sec, uint8_t seconds,
    const int vmfd, struct vmctx *ctx, struct vdi_time_info_v1 *src)
{
	/* configure the guest to have the desired frequency */
	struct vdi_time_info_v1 time_info = {
		.vt_guest_freq = guest_freq,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &time_info,
	};
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) != 0) {
		int error;
		error = errno;
		if (error == EPERM) {
			warn("VMM_DATA_WRITE got EPERM: is "
			    "vmm_allow_state_writes set?");
		}
		errx(EXIT_FAILURE, "VMM_DATA_WRITE of time info failed");
	}


	/*
	 * Run the test:
	 * - ask the guest to report the TSC every 1/per_sec seconds, in terms
	 *   of guest ticks
	 * - collect readings for `seconds` seconds, along with host hrtime
	 * - to avoid additional latency in the readings, process readings at
	 *   the end: check for error in the number of ticks reported and the
	 *   ppm based on host hrtime
	 */
	uint64_t guest_ticks = guest_freq / per_sec;
	const uint32_t nreadings = per_sec * seconds + 1;
	tsc_reading_t tsc_readings[nreadings];

	/* 5 percent margin */
	const uint32_t tick_margin = guest_ticks / 20;

	bool half_read = false;
	uint64_t cur_tsc;
	uint32_t count = 0;

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	do {
		if (count >= nreadings) {
			/* test completed: check results */
			for (int i = 1; i < nreadings; i++) {
				if (!check_reading(tsc_readings[i-1],
				    tsc_readings[i], guest_freq, guest_ticks,
				    tick_margin, PPM_MARGIN)) {
					test_fail_msg("freq test failed");
				}
			}
			break;
		}

		const enum vm_exit_kind kind =
		    test_run_vcpu(ctx, 0, &ventry, &vexit);

		if (kind == VEK_REENTR) {
			continue;
		} else if (kind != VEK_UNHANDLED) {
			test_fail_vmexit(&vexit);
		}

		uint32_t val;
		if (vexit_match_inout(&vexit, true, IOP_TEST_VALUE, 4,
		    &val)) {
			/* test setup: tell guest how often to report its tsc */
			ventry_fulfill_inout(&vexit, &ventry, guest_ticks);

		} else if (vexit_match_inout(&vexit, false, IOP_TEST_VALUE, 4,
		    &val)) {
			/*
			 * Get reported guest TSC in two 32-bit parts, with the
			 * lower bits coming in first.
			 */
			if (!half_read) {
				/* lower bits */
				cur_tsc = val;
				half_read = true;
				ventry_fulfill_inout(&vexit, &ventry, 0);
			} else {
				/* upper bits */
				cur_tsc |= ((uint64_t)val << 32);

				tsc_readings[count].when = gethrtime();
				tsc_readings[count].tsc = cur_tsc;

				half_read = false;
				cur_tsc = 0;
				count++;

				ventry_fulfill_inout(&vexit, &ventry, 0);
			}
		} else {
			test_fail_vmexit(&vexit);
		}
	} while (true);
}

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
	const bool is_svm = cpu_vendor_amd();

	if (!is_svm) {
		test_fail_msg("intel not supported\n");
	}

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
	uint64_t host_freq = time_info.vt_guest_freq;
	uint64_t guest_freq = host_freq;

	/* measure each test frequency 10x per sec, for 1 second */
	const uint8_t per_sec = 10;
	const uint8_t seconds = 1;

	/* 2x host frequency */
	guest_freq = host_freq * 2;
	(void) printf("testing 2x host_freq: guest_freq=%lu, host_freq=%lu\n",
	    guest_freq, host_freq);
	do_freq_test(guest_freq, per_sec, seconds, vmfd, ctx, &time_info);

	/* reset guest */
	test_cleanup(false);
	ctx = test_initialize(test_suite_name);
	err = test_setup_vcpu(ctx, 0, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}


	/* 0.5x host frequency */
	guest_freq = host_freq / 2;
	(void) printf("testing 0.5x host_freq: guest_freq=%lu, host_freq=%lu\n",
	    guest_freq, host_freq);
	do_freq_test(guest_freq, per_sec, seconds, vmfd, ctx, &time_info);

	/* reset guest */
	test_cleanup(false);
	ctx = test_initialize(test_suite_name);
	err = test_setup_vcpu(ctx, 0, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}


	/* 1/3 host frequency */
	guest_freq = host_freq / 3;
	(void) printf("testing 1/3 host_freq: guest_freq=%lu, host_freq=%lu\n",
	    guest_freq, host_freq);
	do_freq_test(guest_freq, per_sec, seconds, vmfd, ctx, &time_info);

	/* reset guest */
	test_cleanup(false);
	ctx = test_initialize(test_suite_name);
	err = test_setup_vcpu(ctx, 0, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}


	/* 1x host frequency */
	guest_freq = host_freq;
	(void) printf("testing 1x host_freq: guest_freq=%lu, host_freq=%lu\n",
	    guest_freq, host_freq);
	do_freq_test(guest_freq, per_sec, seconds, vmfd, ctx, &time_info);

	test_pass();
}
