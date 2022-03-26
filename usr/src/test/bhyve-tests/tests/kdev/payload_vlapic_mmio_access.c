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

#define	MSR_APICBASE	0x1b

#define	APICBASE_X2APIC	(1 << 10)


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

static void
barrier(void)
{
	asm volatile("": : :"memory");
}

void
start(void)
{
	uint64_t base = rdmsr(MSR_APICBASE);
	if ((base & APICBASE_X2APIC) != 0) {
		/* bail if the host has enabled x2apic for us */
		outb(IOP_TEST_RESULT, TEST_RESULT_FAIL);
	}

	/* Access the "normal" register offsets */
	for (uint_t reg = 0; reg < 0x1000; reg += 16) {
		uint32_t val;

		/*
		 * This ignores the fact that some register offsets are reserved
		 * (such as 0x3a0-0x3d0 and 0x3f0-0xff0) while others may be
		 * read-only or write-only.  For the time being, we know that
		 * the emulation in bhyve will not emit errors or faults for
		 * such indiscretions committed via MMIO.
		 */
		val = read_vlapic(reg);
		write_vlapic(reg, val);
	}

	/*
	 * Scan through byte-wise, even though such behavior is undefined as far
	 * as a to-specification LAPIC is concerned.
	 */
	for (uint_t off = 0; off < 0x1000; off++) {
		volatile uint8_t *ptr = (uint8_t *)(MMIO_LAPIC_BASE + off);

		uint8_t val;

		val = *ptr;
		barrier();
		*ptr = val;
	}

	/* If we made it this far without an exception, it is a win */
	outb(IOP_TEST_RESULT, TEST_RESULT_PASS);
}
