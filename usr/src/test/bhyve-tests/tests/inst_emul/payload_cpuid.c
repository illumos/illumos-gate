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
 * Copyright 2026 Oxide Computer Company
 */

#include "payload_common.h"
#include "payload_utils.h"

int
leaf_cmp(const uint32_t *a, const uint32_t *b)
{
	return (a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]);
}

const uint32_t expected_base[] = { 5, 0x74737552, 0x65646978, 0x4f206465 };

struct test_case {
	uint32_t func;
	uint32_t idx;
	uint32_t val_eax;
	int fallback;
};

const struct test_case cases[] = {
	/* basic leaf match */
	{
		.func = 1,
		.val_eax = 0x100,
	},
	/* index matching */
	{
		.func = 3,
		.idx = 0,
		.val_eax = 0x300,
	},
	{
		.func = 3,
		.idx = 1,
		.val_eax = 0x301,
	},
	/* leaf match with hole */
	{
		.func = 4,
		.idx = 0,
		.val_eax = 0x400,
	},
	{
		.func = 4,
		.idx = 2,
		.val_eax = 0x402,
	},
	/* last std leaf */
	{
		.func = 5,
		.val_eax = 0x5,
	},

	/* invalid leaf */
	{
		.func = 2,
		.val_eax = 0,
	},
	/* invalid index */
	{
		.func = 3,
		.idx = 2,
		.val_eax = 0,
	},
	{
		.func = 4,
		.idx = 1,
		.val_eax = 0x0,
	},
	{
		.func = 4,
		.idx = 0xffff,
		.val_eax = 0x0,
	},

	/* basic extd leaf match */
	{
		.func = 0x80000000,
		.val_eax = 0x80000001,
	},
	/* basic extd index match */
	{
		.func = 0x80000001,
		.idx = 0,
		.val_eax = 0x8000,
	},
	{
		.func = 0x80000001,
		.idx = 1,
		.val_eax = 0x8001,
	},
	/* zeroed for invalid index */
	{
		.func = 0x80000001,
		.idx = 5,
		.val_eax = 0,
	},

	/* fallback beyond std leaf */
	{
		.func = 6,
		.fallback = 1,
	},
	/* fallback beyond extd leaf */
	{
		.func = 0x80000002,
		.fallback = 1,
	},
};
#define	NCASES	(sizeof (cases) / sizeof (cases[0]))

void
do_test(int intel_fallback)
{
	uint32_t regs[4];
	uint32_t expected_fallback[4] = { 0 };

	cpuid(0, 0, regs);
	if (!leaf_cmp(regs, expected_base)) {
		outb(IOP_TEST_RESULT, TEST_RESULT_FAIL);
	}

	if (intel_fallback) {
		cpuid(regs[0], 0, expected_fallback);
	}

	for (uint_t i = 0; i < NCASES; i++) {
		cpuid(cases[i].func, cases[i].idx, regs);
		if (cases[i].fallback != 0) {
			if (!leaf_cmp(regs, expected_fallback)) {
				outb(IOP_TEST_RESULT, TEST_RESULT_FAIL);
			}
		} else {
			if (regs[0] != cases[i].val_eax) {
				outb(IOP_TEST_RESULT, TEST_RESULT_FAIL);
			}
		}
	}
}

/*
 * With Intel-style fallback but no "std" leaves, there's nothing to fall back
 * on, so anything which doesn't match should get all-zeroes.
 */
void
do_nostd_test(bool have_extd)
{
	uint32_t regs[4];
	const uint32_t zero[4] = { 0 };

	cpuid(0x80000000, 0, regs);
	if (have_extd && regs[0] != 0x80000001) {
		TEST_ABORT("extd leaf did not match");
	}
	if (!have_extd && !leaf_cmp(regs, zero)) {
		TEST_ABORT("missing extd leaf not all zeroes");
	}

	/*
	 * A "std" leaf, whose search stops at the first (non-matching) entry
	 * when "extd" leaves are present.
	 */
	cpuid(0, 0, regs);
	if (!leaf_cmp(regs, zero)) {
		TEST_ABORT("leaf 0 not all zeroes");
	}
	cpuid(6, 0, regs);
	if (!leaf_cmp(regs, zero)) {
		TEST_ABORT("leaf 6 not all zeroes");
	}

	/* An "extd" leaf, beyond the last present one */
	cpuid(0x80000002, 0, regs);
	if (!leaf_cmp(regs, zero)) {
		TEST_ABORT("leaf 0x80000002 not all zeroes");
	}
}

void
start(void)
{
	/* Check results expecting Intel-style fallback */
	do_test(1);

	/* AMD-style fallback */
	outl(IOP_TEST_VALUE, 0);
	do_test(0);

	/* Intel-style fallback, with only "extd" leaves */
	outl(IOP_TEST_VALUE, 1);
	do_nostd_test(true);

	/* Intel-style fallback, with no leaves at all */
	outl(IOP_TEST_VALUE, 2);
	do_nostd_test(false);

	/* If all is well by this point, indicate success */
	outb(IOP_TEST_RESULT, TEST_RESULT_PASS);
}
