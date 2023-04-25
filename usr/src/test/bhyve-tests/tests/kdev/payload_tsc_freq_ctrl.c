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

#define	UINT32_MAX	0xffffffff

void
start(void)
{
	/* read the period */
	uint32_t period = inl(IOP_TEST_VALUE);

	/* loop for as long as the host wants */
	for (;;) {
		uint64_t start, end;
		start = rdtsc();
		outl(IOP_TEST_VALUE, UINT32_MAX & start);
		outl(IOP_TEST_VALUE, UINT32_MAX & (start >> 32));

		do {
			end = rdtsc();
			/* wait for enough ticks to pass */
		} while ((end - start) < period);
	}
}
