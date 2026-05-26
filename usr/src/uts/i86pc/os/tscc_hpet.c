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
 * Copyright 2026 Bill Sommerfeld <sommerfeld@hamachi.org>
 */

#include <sys/tsc.h>
#include <sys/prom_debug.h>
#include <sys/hpet.h>
#include <sys/clock.h>
#include <sys/sysmacros.h>

/*
 * The amount of time (in microseconds) between tsc samples. This needs to be
 * long enough to allow the ratio between the TSC and the HPET to be
 * accurately measured.
 *
 * The HPET spec cautions that "[w]ithin any 100-microsecond period,
 * the timer is permitted to report a time that is up to 2 ticks too
 * early or too late.".  Worst case measurement error would occur when
 * it reads 2 ticks early at one end and 2 ticks late at the other.
 *
 * A 100us measurement baseline produced frequency error well in
 * excess of 200ppm with large boot-to-boot variance, which together
 * rendered the ntp.drift file useless; it could take the better part
 * of a day for ntpd to find the new frequency correction after boot.
 * A longer baseline of 10ms permits a more accurate measurement of
 * the ratio between the clocks.
 *
 * The HPET is specified to run at 10MHz or faster, so each tick is no more
 * than 100ns; over 10ms this implies a measurement error of no more than
 * 400ns/10ms or 40ppm on the HPET side.  Observed behavior is is somewhat
 * better than this.
 */
#define	HPET_SAMPLE_INTERVAL_US (10000)

/*
 * The same as above, but in nanoseconds (for ease in converting to HPET
 * ticks)
 */
#define	HPET_SAMPLE_INTERVAL_NS (USEC2NSEC(HPET_SAMPLE_INTERVAL_US))

/* The amount of HPET sample ticks to wait */
#define	HPET_SAMPLE_TICKS (HRTIME_TO_HPET_TICKS(HPET_SAMPLE_INTERVAL_NS))

static boolean_t
tsc_calibrate_hpet(uint64_t *freqp)
{
	uint_t i;

	PRM_POINT("Attempting to use HPET for TSC calibration...");

	if (hpet_early_init() != DDI_SUCCESS)
		return (B_FALSE);

	/*
	 * The expansion of HPET_SAMPLE_TICKS (specifically
	 * HRTIME_TO_HPET_TICKS) uses the HPET period to calculate the number
	 * of HPET ticks for the given time period. Therefore, we cannot set
	 * hpet_num_ticks until after the early HPET initialization has been
	 * performed by hpet_early_init() (and the HPET period is known).
	 *
	 * For safety, cap hpet_num_ticks to no more than 1<<30; we are
	 * unlikely to see this on real hardware (this would about 107 seconds
	 * at the slowest possible HPET frequency of 10MHz or about 1 second
	 * for a hypothetical fast HPET clocked at 1GHz).
	 */
	const uint64_t hpet_num_ticks = MIN(HPET_SAMPLE_TICKS, 1 << 30);

	uint32_t hpet_start, hpet_now;
	uint64_t tsc_start, tsc_end;

	/*
	 * Do a short dry run to warm up caches, then run the full 10ms
	 * duration calibration.
	 */
	for (i = 0; i < 2; i++) {
		uint64_t hpet_limit = (i == 0) ? 100 : hpet_num_ticks;

		hpet_start = hpet_read_timer_32();
		tsc_start = tsc_read();

		/*
		 * Loop until the HPET timer advances at least hpet_limit
		 * ticks.
		 *
		 * We use only the low order 32 bits of the HPET counter to
		 * avoid inconsistent read issues during calibration (see
		 * section 2.4.7 of revision 1.0a of the HPET specification).
		 *
		 * This is safe because arithmetic on uint32_t has defined
		 * behavior (results modulo 2^32) on under/overflow.  As long
		 * as the delta between two back-to-back reads of the HPET in
		 * this loop is small relative to 2^32, the difference will
		 * exceed hpet_limit before we wrap a second time.
		 */
		do {
			hpet_now = hpet_read_timer_32();
		} while ((hpet_now - hpet_start) < hpet_limit);

		tsc_end = tsc_read();

		/*
		 * If our TSC isn't advancing after 100us, we're pretty much
		 * hosed.
		 */
		VERIFY3P(tsc_end, >, tsc_start);
	}
	/*
	 * We use the actual hpet difference rather than the nominal
	 * duration of hpet_num_ticks as back-to-back reads of the hpet
	 * typically differ by more than a few ticks.
	 */
	uint64_t tsc_ticks = tsc_end - tsc_start;
	uint64_t hpet_ticks = hpet_now - hpet_start;
	uint64_t hpet_ns = hpet_ticks * hpet_info.period / HPET_FEMTO_TO_NANO;

	PRM_POINT("HPET calibration complete");

	*freqp = tsc_ticks * NANOSEC / hpet_ns;
	PRM_DEBUG(*freqp);

	cmn_err(CE_CONT, "?TSC calibration: "
	    "%lu tsc ticks, %lu hpet ticks, %lu hpet ns\n",
	    tsc_ticks, hpet_ticks, hpet_ns);
	return (B_TRUE);
}

/*
 * Reports from the field suggest that HPET calibration is currently producing
 * a substantially greater error than PIT calibration on a wide variety of
 * systems.  We are placing it last in the preference order until that can be
 * resolved.  HPET calibration cannot be disabled completely, as some systems
 * no longer emulate the PIT at all.
 */
static tsc_calibrate_t tsc_calibration_hpet = {
	.tscc_source = "HPET",
	.tscc_preference = 1,
	.tscc_calibrate = tsc_calibrate_hpet,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_hpet);
