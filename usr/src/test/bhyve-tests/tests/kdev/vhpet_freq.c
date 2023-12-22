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
#include "test_defs.h"

typedef struct reading {
	hrtime_t	when;
	uint32_t	value;
} reading_t;

static bool
check_reading(reading_t before, reading_t after, uint_t tick_margin,
    uint_t ppm_margin)
{
	hrtime_t time_delta = after.when - before.when;
	uint32_t tick_delta;

	if (after.value < before.value) {
		/* handle rollover */
		tick_delta = (UINT32_MAX - before.value) + after.value;
	} else {
		tick_delta = after.value - before.value;
	}

	/* is the number of ticks OK? */
	if (tick_delta < HPET_TARGET_TICKS) {
		test_fail_msg("inadequate passage of ticks %u < %u\n",
		    tick_delta, HPET_TARGET_TICKS);
	} else if ((tick_delta - HPET_TARGET_TICKS) > tick_margin) {
		(void) printf("%u ticks outside margin %u\n", tick_delta,
		    HPET_TARGET_TICKS + tick_margin);
		return (false);
	}

	hrtime_t time_target = (tick_delta * NANOSEC) / HPET_FREQ;

	hrtime_t offset;
	if (time_delta < time_target) {
		offset = time_target - time_delta;
	} else {
		offset = time_delta - time_target;
	}
	uint64_t ppm = (offset * 1000000) / time_target;
	(void) printf("margin limits: ticks=%u ppm=%lu\n",
	    tick_margin, ppm_margin);
	(void) printf("%u ticks in %lu ns (error %lu ppm)\n",
	    tick_delta, time_delta, ppm);
	if (ppm > ppm_margin) {
		(void) printf("UNACCEPTABLE!\n");
		return (false);
	}
	return (true);
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
	reading_t readings[2];
	uint_t nread = 0;
	uint_t nrepeat = 0;

	const uint_t margin_ticks = MAX(1, HPET_TARGET_TICKS / 10000);
	const uint_t margin_ppm = 400;

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);
		if (kind == VEK_REENTR) {
			continue;
		} else if (kind != VEK_UNHANDLED) {
			test_fail_vmexit(&vexit);
		}

		uint32_t v;
		if (vexit_match_inout(&vexit, false, IOP_TEST_VALUE, 4, &v)) {
			readings[nread].when = gethrtime();
			readings[nread].value = v;

			ventry_fulfill_inout(&vexit, &ventry, 0);

			nread++;
			if (nread != 2) {
				continue;
			}

			if (check_reading(readings[0], readings[1],
			    margin_ticks, margin_ppm)) {
				test_pass();
			} else {
				nrepeat++;
				if (nrepeat < 3) {
					nread = 0;
					(void) printf("retry %u\n", nrepeat);
					continue;
				}
				test_fail_msg("bad result after %u retries\n",
				    nrepeat);
			}
		} else {
			test_fail_vmexit(&vexit);
		}

	} while (true);

	return (0);
}
