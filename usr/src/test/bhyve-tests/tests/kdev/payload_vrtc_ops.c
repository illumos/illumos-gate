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

#include "payload_common.h"
#include "payload_utils.h"
#include "test_defs.h"

#define	IOP_RTC_ADDR	0x70
#define	IOP_RTC_DATA	0x71

/* Convenience definitions for RTC offsets */
#define	RTC_SEC		0x00
#define	RTC_MIN		0x02
#define	RTC_HOUR	0x04
#define	RTC_DAY		0x07
#define	RTC_MONTH	0x08
#define	RTC_YEAR	0x09
#define	RTC_CENTURY	0x32

#define	RTC_REGA	0x0a
#define	RTC_REGB	0x0b
#define	RTC_REGC	0x0c
#define	RTC_REGD	0x0d

#define	REGA_DIVIDER_32K	0x20
#define	REGA_DIVIDER_DIS	0x70
#define	REGA_PERIOD_512HZ	0x07
#define	REGA_PERIOD_128HZ	0x09

#define	REGB_HALT		0x80
#define	REGB_DATA_BIN		0x04
#define	REGB_24HR		0x02
#define	REGB_DST		0x01

#define	REGC_IRQ		0x80
#define	REGC_PERIODIC		0x40
#define	REGC_ALARM		0x20
#define	REGC_UPDATE		0x10

#define	PPM_THRESHOLD	500
#define	ABS(x)	((x) < 0 ? -(x) : (x))

static uint8_t rtc_last_off = 0xff;

static uint8_t
rtc_read(uint8_t off)
{
	if (off != rtc_last_off) {
		outb(IOP_RTC_ADDR, off);
		rtc_last_off = off;
	}

	return (inb(IOP_RTC_DATA));
}

static void
rtc_write(uint8_t off, uint8_t data)
{
	if (off != rtc_last_off) {
		outb(IOP_RTC_ADDR, off);
		rtc_last_off = off;
	}

	return (outb(IOP_RTC_DATA, data));
}

static uint8_t
wait_for_flag(uint8_t mask)
{
	uint8_t regc;

	do {
		regc = rtc_read(RTC_REGC);
	} while ((regc & mask) == 0);

	return (regc);
}

void
start(void)
{
	/*
	 * Initialize RTC to known state:
	 * - rega: divider and periodic timer disabled
	 * - regb: updates halted, intr disabled, 24hr time, binary fmt, no DST
	 * - regc: cleared (by read)
	 */
	rtc_write(RTC_REGA, REGA_DIVIDER_DIS);
	rtc_write(RTC_REGB, REGB_HALT | REGB_DATA_BIN | REGB_24HR);
	(void) rtc_read(RTC_REGC);

	/* Start at 1970 epoch */
	rtc_write(RTC_DAY, 1);
	rtc_write(RTC_MONTH, 1);
	rtc_write(RTC_YEAR, 70);
	rtc_write(RTC_CENTURY, 19);
	rtc_write(RTC_HOUR, 0);
	rtc_write(RTC_MIN, 0);
	rtc_write(RTC_SEC, 0);

	uint64_t start, end;
	/*
	 * After allowing the divider to run, and enabling time updates, we
	 * expect a 500ms delay until the first update to the date/time data.
	 * Measure this with the TSC, even though we do not have a calibration
	 * for its frequency.
	 */
	rtc_write(RTC_REGA, REGA_DIVIDER_32K);
	start = rdtsc();
	rtc_write(RTC_REGB, REGB_DATA_BIN | REGB_24HR);

	if (rtc_read(RTC_REGC) != 0) {
		TEST_ABORT("unexpected flags set in regC");
	}

	(void) wait_for_flag(REGC_UPDATE);
	end = rdtsc();

	const uint64_t tsc_500ms = end - start;
	start = end;

	/* Expect the clock to read 00:00:01 after the first update */
	if (rtc_read(RTC_SEC) != 1) {
		TEST_ABORT("did not find 01 in seconds field");
	}

	/* Wait for another update to pass by */
	(void) wait_for_flag(REGC_UPDATE);
	end = rdtsc();

	const uint64_t tsc_1s = end - start;

	/* Expect the clock to read 00:00:02 after the second update */
	if (rtc_read(RTC_SEC) != 2) {
		TEST_ABORT("did not find 02 in seconds field");
	}

	/*
	 * Determine ratio between the intervals which should be 500ms and
	 * 1000ms long, as measured by the TSC.
	 */
	int64_t ppm_delta = (int64_t)(tsc_500ms * 2 * 1000000) / tsc_1s;
	ppm_delta = ABS(ppm_delta - 1000000);

	if (ppm_delta > PPM_THRESHOLD) {
		TEST_ABORT("clock update timing outside threshold");
	}

	/* Put RTC in 12-hr, BCD-formatted mode */
	rtc_write(RTC_REGA, REGA_DIVIDER_DIS);
	rtc_write(RTC_REGB, REGB_HALT);

	/* Set time to 11:59:59, prepping for roll-over into noon */
	rtc_write(RTC_HOUR, 0x11);
	rtc_write(RTC_MIN, 0x59);
	rtc_write(RTC_SEC, 0x59);

	/* Release the clock to run again */
	rtc_write(RTC_REGA, REGA_DIVIDER_32K);
	rtc_write(RTC_REGB, 0);

	/* Wait for it to tick over */
	(void) wait_for_flag(REGC_UPDATE);

	if (rtc_read(RTC_SEC) != 0) {
		TEST_ABORT("invalid RTC_SEC value");
	}
	if (rtc_read(RTC_MIN) != 0) {
		TEST_ABORT("invalid RTC_MIN value");
	}
	/* Hour field should now hold 0x12 (BCD noon) | 0x80 (PM flag) */
	if (rtc_read(RTC_HOUR) != 0x92) {
		TEST_ABORT("invalid RTC_HOUR value");
	}

	/* Halt the RTC once again to prep for test of periodic timer */
	rtc_write(RTC_REGA, REGA_DIVIDER_DIS);
	rtc_write(RTC_REGB, REGB_HALT);

	/* Clear any pending event flags */
	(void) rtc_read(RTC_REGC);

	/* Release divider to run, configuring a 512Hz periodic timer */
	rtc_write(RTC_REGA, REGA_DIVIDER_32K | REGA_PERIOD_512HZ);
	rtc_write(RTC_REGB, 0);

	/* Count periodic firings until the next time update */
	uint_t periodic_fire = 0;
	uint8_t events = 0;
	do {
		events = wait_for_flag(REGC_UPDATE | REGC_PERIODIC);

		if ((events & REGC_PERIODIC) != 0) {
			periodic_fire++;
		}
	} while ((events & REGC_UPDATE) == 0);

	/*
	 * In the 500ms between releasing the divider and the first time update,
	 * we expect 256 firings of the 512Hz periodic timer.
	 */
	if (periodic_fire != 256) {
		TEST_ABORT("unexpected periodic firing count at 512Hz");
	}

	/* Change the periodic timer to 128Hz */
	rtc_write(RTC_REGA, REGA_DIVIDER_32K | REGA_PERIOD_128HZ);

	/* Count periodic firings until the next time update */
	periodic_fire = 0;
	do {
		events = wait_for_flag(REGC_UPDATE | REGC_PERIODIC);

		if ((events & REGC_PERIODIC) != 0) {
			periodic_fire++;
		}
	} while ((events & REGC_UPDATE) == 0);

	/*
	 * With 1s between time updates, we expect 128 firings for the
	 * reconfigured 128Hz periodic timer.
	 */
	if (periodic_fire != 128) {
		TEST_ABORT("unexpected periodic firing count at 128Hz");
	}

	/*
	 * TODO - Add additional tests:
	 * - alarm interrupts
	 */

	/* Happy for now */
	test_result_pass();
}
