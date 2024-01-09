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
check_reading(reading_t before, reading_t after, uint_t divisor, uint_t loops,
    uint_t tick_margin, uint_t ppm_margin)
{
	const hrtime_t time_delta = after.when - before.when;


	/*
	 * The ticks margin should shrink proportionally to how coarsely the
	 * timer clock is being divided.
	 */
	tick_margin /= divisor;

	/*
	 * The 'before' measurement includes the ticks which occurred between
	 * programming the timer and taking the first reading.  The 'after'
	 * measurement includes the number of loops (each consisting of the
	 * target tick count) plus however many ticks had transpired since the
	 * most recent roll-over.
	 */
	const uint32_t tick_delta =
	    loops * LAPIC_TARGET_TICKS + before.value - after.value;
	const uint32_t tick_target = loops * LAPIC_TARGET_TICKS;

	/* is the number of ticks OK? */
	if (tick_delta < tick_target) {
		if ((tick_target - tick_delta) > tick_margin) {
			(void) printf("%u ticks outside margin %u\n",
			    tick_delta, tick_target - tick_margin);
		}
	} else if ((tick_delta - tick_target) > tick_margin) {
		(void) printf("%u ticks outside margin %u\n", tick_delta,
		    tick_target + tick_margin);
		return (false);
	}

	hrtime_t time_target = (tick_delta * NANOSEC * divisor) / LAPIC_FREQ;

	hrtime_t offset;
	if (time_delta < time_target) {
		offset = time_target - time_delta;
	} else {
		offset = time_delta - time_target;
	}
	uint64_t ppm = (offset * 1000000) / time_target;
	(void) printf("params: tick_margin=%u ppm_margin=%lu divisor=%u\n",
	    tick_margin, ppm_margin, divisor);
	(void) printf("%u ticks in %lu ns (error %lu ppm)\n",
	    tick_delta, time_delta, ppm);
	if (ppm > ppm_margin) {
		(void) printf("UNACCEPTABLE!\n");
		return (false);
	}
	return (true);
}


static void
run_test(struct vcpu *vcpu, uint_t divisor, uint_t loops,
    struct vm_entry *ventry, struct vm_exit *vexit)
{
	reading_t readings[2];
	uint_t nread = 0;
	uint_t nrepeat = 0;

	const uint_t margin_ticks = MAX(1, LAPIC_TARGET_TICKS / 5000);
	const uint_t margin_ppm = 400;

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, ventry, vexit);
		if (kind == VEK_REENTR) {
			continue;
		} else if (kind != VEK_UNHANDLED) {
			test_fail_vmexit(vexit);
		}

		/* input the divisor (bits 0-15) and loop count (bits 16-31) */
		if (vexit_match_inout(vexit, true, IOP_TEST_PARAM0, 2, NULL)) {
			ventry_fulfill_inout(vexit, ventry, divisor);
			continue;
		}
		/* input the loop count */
		if (vexit_match_inout(vexit, true, IOP_TEST_PARAM1, 2, NULL)) {
			ventry_fulfill_inout(vexit, ventry, loops);
			continue;
		}

		uint32_t v;
		if (vexit_match_inout(vexit, false, IOP_TEST_VALUE, 4, &v)) {
			readings[nread].when = gethrtime();
			readings[nread].value = v;
			ventry_fulfill_inout(vexit, ventry, 0);

			nread++;
			if (nread != 2) {
				continue;
			}

			if (check_reading(readings[0], readings[1], divisor,
			    loops, margin_ticks, margin_ppm)) {
				(void) printf("good result\n");
				return;
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
			test_fail_vmexit(vexit);
		}
	} while (true);
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

	run_test(vcpu, 4, 3, &ventry, &vexit);
	run_test(vcpu, 2, 4, &ventry, &vexit);
	test_pass();
	return (0);
}
