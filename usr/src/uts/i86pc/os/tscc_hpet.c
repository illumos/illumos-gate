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
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/tsc.h>
#include <sys/prom_debug.h>
#include <sys/hpet.h>
#include <sys/clock.h>

/*
 * The amount of time (in microseconds) between tsc samples. This is
 * somewhat arbitrary, but seems reasonable. A frequency of 1GHz is
 * 1,000,000,000 ticks / sec (10^9). 100us is 10^(-6) * 10^2 => 10^(-4), so
 * 100us would represent 10^5 (100,000) ticks.
 */
#define	HPET_SAMPLE_INTERVAL_US (100)

/*
 * The same as above, but in nanoseconds (for ease in converting to HPET
 * ticks)
 */
#define	HPET_SAMPLE_INTERVAL_NS (USEC2NSEC(HPET_SAMPLE_INTERVAL_US))

/* The amount of HPET sample ticks to wait */
#define	HPET_SAMPLE_TICKS (HRTIME_TO_HPET_TICKS(HPET_SAMPLE_INTERVAL_NS))

#define	TSC_NUM_SAMPLES 10

static boolean_t
tsc_calibrate_hpet(uint64_t *freqp)
{
	uint64_t hpet_sum = 0;
	uint64_t tsc_sum = 0;
	uint_t i;

	PRM_POINT("Attempting to use HPET for TSC calibration...");

	if (hpet_early_init() != DDI_SUCCESS)
		return (B_FALSE);

	/*
	 * The expansion of HPET_SAMPLE_TICKS (specifically
	 * HRTIME_TO_HPET_TICKS) uses the HPET period to calculate the number
	 * of HPET ticks for the given time period. Therefore, we cannot
	 * set hpet_num_ticks until after the early HPET initialization has
	 * been performed by hpet_early_init() (and the HPET period is known).
	 */
	const uint64_t hpet_num_ticks = HPET_SAMPLE_TICKS;

	for (i = 0; i < TSC_NUM_SAMPLES; i++) {
		uint64_t hpet_now, hpet_end;
		uint64_t tsc_start, tsc_end;

		hpet_now = hpet_read_timer();
		hpet_end = hpet_now + hpet_num_ticks;

		tsc_start = tsc_read();
		while (hpet_now < hpet_end)
			hpet_now = hpet_read_timer();

		tsc_end = tsc_read();

		/*
		 * If our TSC isn't advancing after 100us, we're pretty much
		 * hosed.
		 */
		VERIFY3P(tsc_end, >, tsc_start);

		tsc_sum += tsc_end - tsc_start;

		/*
		 * We likely did not end exactly HPET_SAMPLE_TICKS after
		 * we started, so save the actual amount.
		 */
		hpet_sum += hpet_num_ticks + hpet_now - hpet_end;
	}

	uint64_t hpet_avg = hpet_sum / TSC_NUM_SAMPLES;
	uint64_t tsc_avg = tsc_sum / TSC_NUM_SAMPLES;
	uint64_t hpet_ns = hpet_avg * hpet_info.period / HPET_FEMTO_TO_NANO;

	PRM_POINT("HPET calibration complete");

	*freqp = tsc_avg * NANOSEC / hpet_ns;
	PRM_DEBUG(*freqp);

	return (B_TRUE);
}

static tsc_calibrate_t tsc_calibration_hpet = {
	.tscc_source = "HPET",
	.tscc_preference = 50,
	.tscc_calibrate = tsc_calibrate_hpet,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_hpet);
