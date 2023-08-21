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

/* Arbitrary 2MB limit to keep heap away from stack */
#define	HEAP_LIMIT	0x200000

#define	MSR_APICBASE		0x01b
#define	IOP_ICU1		0x20
#define	ADDR_IOAPIC_BASE	0xfec00000

typedef struct test_data {
	uint32_t count;
	uint64_t *data;
} test_data_t;

static void
zero_data(const test_data_t *td)
{
	for (uint32_t i = 0; i < td->count; i++) {
		td->data[i] = 0;
	}
}

static void
output_data(const test_data_t *td, uint64_t tsc_start)
{
	for (uint32_t i = td->count - 1; i > 0; i--) {
		td->data[i] -= td->data[i - 1];
	}
	td->data[0] -= tsc_start;

	/*
	 * Output the low 32-bits of the data pointers, since that is adequate
	 * while the test resides wholly in lowmem.
	 */
	outl(IOP_TEST_VALUE, (uint32_t)(uintptr_t)td->data);
}

static uint32_t
mmio_read4(volatile uint32_t *ptr)
{
	return (*ptr);
}

/*
 * For a relatively cheap exit, rdmsr(APICBASE) should be suitable, since its
 * emulation is dead simple and LAPIC-related MSR operations are handled within
 * the tight confines of the SVM/VMX vmrun loop.
 */
static void
do_test_rdmsr(const test_data_t *td)
{
	zero_data(td);

	const uint64_t tsc_start = rdtsc();
	for (uint32_t i = 0; i < td->count; i++) {
		(void) rdmsr(MSR_APICBASE);
		td->data[i] = rdtsc();
	}

	output_data(td, tsc_start);
}

/*
 * For a moderately priced exit, an IO port read from the ATPIC should suffice.
 * This will take us out of the SVM/VMX vmrun loop and into the instruction
 * emulation, but the instruction fetch/decode should already be taken care of
 * by the hardware, and no further memory (guest) accesses are required.
 */
static void
do_test_inb(const test_data_t *td)
{
	zero_data(td);

	const uint64_t tsc_start = rdtsc();
	for (uint32_t i = 0; i < td->count; i++) {
		(void) inb(IOP_ICU1);
		td->data[i] = rdtsc();
	}

	output_data(td, tsc_start);
}

/*
 * For a more expensive exit, read from the selector register in the IOAPIC.
 * The device emulation is handled in-kernel, but the instruction will need to
 * (potentially) fetched and decoded.
 */
static void
do_test_mmio_cheap(const test_data_t *td)
{
	zero_data(td);
	volatile uint32_t *ioapic_regsel = (void *)(uintptr_t)ADDR_IOAPIC_BASE;

	const uint64_t tsc_start = rdtsc();
	for (uint32_t i = 0; i < td->count; i++) {
		(void) mmio_read4(ioapic_regsel);
		td->data[i] = rdtsc();
	}

	output_data(td, tsc_start);
}

void
start(void)
{

	/* Get the number of repetitions per test */
	const uint32_t count = inl(IOP_TEST_PARAM0);

	if (count * sizeof (uint64_t) > HEAP_LIMIT) {
		test_msg("excessive test count for memory sz");
		test_result_fail();
		return;
	}

	test_data_t td = {
		.count = count,
		.data = (uint64_t *)(uintptr_t)MEM_LOC_HEAP,
	};

	do_test_rdmsr(&td);
	do_test_inb(&td);
	do_test_mmio_cheap(&td);

	test_result_pass();
}
