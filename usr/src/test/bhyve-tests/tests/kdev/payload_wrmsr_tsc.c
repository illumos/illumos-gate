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

#define	UINT32_MAX	0xffffffff
#define	MSR_TSC	0x10

void
start(void)
{
	/* write a value to the TSC */
	wrmsr(0x10, TSC_TARGET_WRVAL);

	/* loop for as long as the host wants */
	for (;;) {
		uint64_t tsc = rdtsc();
		outl(IOP_TEST_VALUE, UINT32_MAX & tsc);
		outl(IOP_TEST_VALUE, UINT32_MAX & (tsc >> 32));
	}
}
