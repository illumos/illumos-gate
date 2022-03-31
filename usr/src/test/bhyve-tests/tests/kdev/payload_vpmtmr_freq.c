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
start(void)
{
	/* loop for as long as the host wants */
	for (;;) {
		uint32_t start, end;

		start = inl(IOP_PMTMR);
		outl(IOP_TEST_VALUE, start);

		do {
			end = inl(IOP_PMTMR);
			/* wait for enough ticks to pass */
		} while (end < (start + PMTMR_TARGET_TICKS));
		outl(IOP_TEST_VALUE, end);
	}
}
