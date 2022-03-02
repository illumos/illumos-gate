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

#define	HPET_OFF_CONFIG			0x10
#define	HPET_OFF_MAIN_COUNT_LOW		0xf0

#define	HPET_CONFIG_ENABLE	1


static void
write_hpet(uint_t reg, uint32_t value)
{
	volatile uint32_t *ptr = (uint32_t *)(MMIO_HPET_BASE + reg);
	*ptr = value;
}

static uint32_t
read_hpet_main_low(void)
{
	volatile uint32_t *ptr =
	    (uint32_t *)(MMIO_HPET_BASE + HPET_OFF_MAIN_COUNT_LOW);
	return (*ptr);
}


void
start(void)
{
	write_hpet(HPET_OFF_CONFIG, HPET_CONFIG_ENABLE);

	/* loop for as long as the host wants */
	for (;;) {
		uint32_t start, end;

		start = read_hpet_main_low();
		outl(IOP_TEST_VALUE, start);

		do {
			end = read_hpet_main_low();
			/* wait for enough ticks to pass */
		} while (end < (start + HPET_TARGET_TICKS));
		outl(IOP_TEST_VALUE, end);
	}
}
