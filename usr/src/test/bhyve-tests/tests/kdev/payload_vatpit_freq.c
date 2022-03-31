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

#include "payload_common.h"
#include "payload_utils.h"
#include "test_defs.h"


void
timer0_reset(void)
{
	/*
	 * Configure timer 0 for interrupt-on-terminal-count mode, and prepare
	 * it to be loaded with the high and low bytes.
	 */
	outb(IOP_ATPIT_CMD, 0x30);

	/* Load timer with max value (0xffff) */
	outb(IOP_ATPIT_C0, 0xff);
	outb(IOP_ATPIT_C0, 0xff);
}

uint16_t
timer0_read(void)
{
	uint16_t val;

	/* Latch timer0 */
	outb(IOP_ATPIT_CMD, 0x00);

	/* Read low and high bytes */
	val = inb(IOP_ATPIT_C0);
	val |= (uint16_t)inb(IOP_ATPIT_C0) << 8;

	return (val);
}

void
start(void)
{

	/* loop for as long as the host wants */
	for (;;) {
		uint16_t start, end;

		timer0_reset();

		start = timer0_read();
		outw(IOP_TEST_VALUE, start);

		do {
			end = timer0_read();
			/* wait for enough ticks to pass */
		} while (end > (start - ATPIT_TARGET_TICKS));
		outw(IOP_TEST_VALUE, end);
	}
}
