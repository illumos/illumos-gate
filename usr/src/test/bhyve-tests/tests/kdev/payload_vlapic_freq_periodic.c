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

#define	LAPIC_OFF_SVR	0xf0
#define	LAPIC_OFF_LVT_TIMER	0x320
#define	LAPIC_OFF_TIMER_ICR	0x380
#define	LAPIC_OFF_TIMER_CCR	0x390
#define	LAPIC_OFF_TIMER_DCR	0x3e0

#define	LAPIC_LVT_MASKED	(1 << 16)
#define	LAPIC_LVT_PERIODIC	(1 << 17)


#define	LAPIC_SVR_ENABLE	0x100

static void
write_vlapic(uint_t reg, uint32_t value)
{
	volatile uint32_t *ptr = (uint32_t *)(MMIO_LAPIC_BASE + reg);
	*ptr = value;
}

static uint32_t
read_vlapic(uint_t reg)
{
	volatile uint32_t *ptr = (uint32_t *)(MMIO_LAPIC_BASE + reg);
	return (*ptr);
}

static uint32_t
divisor_to_dcr(uint32_t inp)
{
	switch (inp) {
	case 1:
		return (0xb);
	case 2:
		return (0x0);
	case 4:
		return (0x1);
	case 8:
		return (0x2);
	case 16:
		return (0x3);
	case 32:
		return (0x8);
	case 64:
		return (0x9);
	case 128:
		return (0xa);
	default:
		/* fail immediate if divisor is out of range */
		outl(IOP_TEST_VALUE, 1);
		return (0xff);
	}
}


void
start(void)
{
	write_vlapic(LAPIC_OFF_SVR, LAPIC_SVR_ENABLE);

	/*
	 * Configure the LAPIC timer for periodic operation, but leave the
	 * interrupt itself masked.
	 */
	write_vlapic(LAPIC_OFF_LVT_TIMER,
	    LAPIC_LVT_MASKED | LAPIC_LVT_PERIODIC);

	/* loop for as long as the host wants */
	for (;;) {
		const uint16_t divisor = inw(IOP_TEST_PARAM0);
		const uint16_t loop_count = inw(IOP_TEST_PARAM1);

		write_vlapic(LAPIC_OFF_TIMER_DCR, divisor_to_dcr(divisor));
		write_vlapic(LAPIC_OFF_TIMER_ICR, LAPIC_TARGET_TICKS);

		uint32_t start, end, count = 0;
		start = read_vlapic(LAPIC_OFF_TIMER_CCR);
		outl(IOP_TEST_VALUE, start);

		uint32_t prev = start;
		do {
			end = read_vlapic(LAPIC_OFF_TIMER_CCR);

			/* timer period rolled over */
			if (end > prev) {
				count++;
			}
			prev = end;
		} while (count < loop_count);
		outl(IOP_TEST_VALUE, end);
	}
}
