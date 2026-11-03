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
#include "cpuid_guest_state.h"

#define	CPUID_APIC		0x00000200
#define	CPUID2_XSAVE		0x04000000
#define	CPUID2_OSXSAVE		0x08000000
#define	APICBASE_ENABLED	0x00000800
#define	CR4_OSXSAVE		0x00040000

#define	XCR0_X87_SSE		0x00000003
#define	XCR0_AVX		0x00000004

#define	CPUID_D_1_XSAVEC	0x00000002
#define	CPUID_D_1_XSAVES	0x00000008

/* "GenuineIntel", as returned by leaf 0 in %ebx, %edx, %ecx */
#define	CPUID_VENDOR_INTEL_EBX	0x756e6547
#define	CPUID_VENDOR_INTEL_EDX	0x49656e69
#define	CPUID_VENDOR_INTEL_ECX	0x6c65746e

bool
vendor_is_intel(void)
{
	uint32_t regs[4];

	cpuid(0, 0, regs);
	return (regs[1] == CPUID_VENDOR_INTEL_EBX &&
	    regs[3] == CPUID_VENDOR_INTEL_EDX &&
	    regs[2] == CPUID_VENDOR_INTEL_ECX);
}

int
leaf_cmp(const uint32_t *a, const uint32_t *b)
{
	return (a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]);
}

const uint32_t expected_base[] = {
	TEST_CPUID_0_EAX,
	TEST_CPUID_0_EBX,
	TEST_CPUID_0_ECX,
	TEST_CPUID_0_EDX
};

/* Verifies that leaf 1 returns the test suite's explicitly-set values. */
void
test_leaf_1_explicit()
{
	uint32_t regs[4];

	cpuid(1, 0, regs);
	if (regs[0] != TEST_CPUID_1_EAX || regs[1] != TEST_CPUID_1_EBX ||
	    regs[3] != TEST_CPUID_1_EDX) {
		TEST_ABORT("leaf 1 eax/ebx/edx != explicit values");
	}
}

/* Verifies that leaf 1 ecx's value varies as cr4's OSXSAVE bit changes. */
void
test_leaf_1_osxsave(bool using_explicit)
{
	uint32_t regs[4];
	uint32_t orig_cr4 = getcr4();
	uint32_t ecx;

	setcr4(getcr4() & ~CR4_OSXSAVE);
	cpuid(1, 0, regs);
	ecx = regs[2];
	if ((ecx & CPUID2_OSXSAVE) != 0) {
		TEST_ABORT("leaf 1 OSXSAVE set with CR4.OSXSAVE clear");
	}
	if (using_explicit && ecx != (TEST_CPUID_1_ECX & ~CPUID2_OSXSAVE)) {
		TEST_ABORT("leaf 1 ecx != explicit value");
	}

	/* Turn OSXSAVE back on and check that it reappears in CPUID. */
	setcr4(getcr4() | CR4_OSXSAVE);
	cpuid(1, 0, regs);
	if (regs[2] != (ecx | CPUID2_OSXSAVE)) {
		TEST_ABORT("leaf 1 ecx wrong with CR4.OSXSAVE set");
	}
	setcr4(orig_cr4);
}

/* Verifies that leaf 1 edx's value varies as the APIC enable flag changes. */
void
test_leaf_1_apic(bool using_explicit)
{
	uint32_t regs[4];
	uint32_t edx;

	wrmsr(0x1B, rdmsr(0x1B) & ~APICBASE_ENABLED);
	cpuid(1, 0, regs);
	edx = regs[3];
	if ((edx & CPUID_APIC) != 0) {
		TEST_ABORT("leaf 1 APIC set with APIC disabled");
	}
	if (using_explicit && edx != (TEST_CPUID_1_EDX & ~CPUID_APIC)) {
		TEST_ABORT("leaf 1 edx != explicit value");
	}
	wrmsr(0x1B, rdmsr(0x1B) | APICBASE_ENABLED);
	cpuid(1, 0, regs);
	if (regs[3] != (edx | CPUID_APIC)) {
		TEST_ABORT("leaf 1 edx wrong with APIC enabled");
	}
}

/* Verifies that leaf D subleaf 0 ebx's value changes as XCR0 changes. */
void
test_leaf_d_index_0(bool using_explicit)
{
	uint32_t regs[4];
	uint64_t orig_cr4 = getcr4();
	uint64_t orig_xcr0;

	setcr4(getcr4() | CR4_OSXSAVE);
	orig_xcr0 = getxcr(0);
	cpuid(0xD, 0, regs);
	if (using_explicit) {
		if (regs[0] != TEST_CPUID_D_0_EAX ||
		    regs[2] != XSAVE_AREA_SIZE_MAX || regs[3] != 0) {
			TEST_ABORT("leaf D.0 eax/ecx/edx != explicit values");
		}
	}

	setxcr(0, XCR0_X87_SSE);
	cpuid(0xD, 0, regs);
	if (regs[1] != XSAVE_AREA_SIZE_BASE) {
		TEST_ABORT("leaf D.0 ebx wrong for x87/SSE");
	}

	setxcr(0, XCR0_X87_SSE | XCR0_AVX);
	cpuid(0xD, 0, regs);
	if (regs[1] != XSAVE_AREA_SIZE_BASE + XSAVE_AREA_SIZE_AVX) {
		TEST_ABORT("leaf D.0 ebx wrong for x87/SSE/AVX");
	}

	setxcr(0, orig_xcr0);
	setcr4(orig_cr4);
}

/* Verifies that leaf D subleaf 1 ebx's value changes as XCR0 changes. */
void
test_leaf_d_index_1(bool using_explicit, bool via_fallback)
{
	uint32_t leaf;
	uint32_t regs[4];
	uint64_t orig_cr4 = getcr4();
	uint64_t orig_xcr0;
	uint32_t size_base = XSAVE_AREA_SIZE_BASE;
	uint32_t size_avx = XSAVE_AREA_SIZE_BASE + XSAVE_AREA_SIZE_AVX;

	if (via_fallback) {
		leaf = 0xE;
	} else {
		leaf = 0xD;
	}

	setcr4(getcr4() | CR4_OSXSAVE);
	orig_xcr0 = getxcr(0);
	cpuid(leaf, 1, regs);
	if (using_explicit) {
		if (regs[0] != TEST_CPUID_D_1_EAX || regs[2] != 0 ||
		    regs[3] != 0) {
			TEST_ABORT("leaf D.1 eax/ecx/edx != explicit values");
		}
	}

	/*
	 * On Intel hosts, bhyve follows the SDM in reporting a size of 0 in ebx
	 * when eax advertises neither XSAVEC nor XSAVES.
	 *
	 * The explicit values (checked above) advertise both, but legacy
	 * emulation advertises only XSAVEOPT, in which case the expected size
	 * depends on the host vendor.  Legacy emulation passes that through
	 * in leaf 0, so it can be checked for here.
	 */
	if ((regs[0] & (CPUID_D_1_XSAVEC | CPUID_D_1_XSAVES)) == 0 &&
	    vendor_is_intel()) {
		size_base = 0;
		size_avx = 0;
	}

	setxcr(0, XCR0_X87_SSE);
	cpuid(leaf, 1, regs);
	if (regs[1] != size_base) {
		TEST_ABORT("leaf D.1 ebx wrong for x87/SSE");
	}

	setxcr(0, XCR0_X87_SSE | XCR0_AVX);
	cpuid(leaf, 1, regs);
	if (regs[1] != size_avx) {
		TEST_ABORT("leaf D.1 ebx wrong for x87/SSE/AVX");
	}

	setxcr(0, orig_xcr0);
	setcr4(orig_cr4);
}

/*
 * Tests that CPUID returns the expected values for leaves that are either
 * expected to be present on the host or that are explicitly supplied by the
 * test harness.
 */
void
do_basic_test(bool using_explicit)
{
	uint32_t regs[4];

	/*
	 * The specific values returned by leaves 0 and 1 are host-dependent,
	 * so only check them when explicitly overriding host CPUID.
	 */
	if (using_explicit) {
		cpuid(0, 0, regs);
		if (!leaf_cmp(regs, expected_base)) {
			TEST_ABORT("leaf 0 != explicit values");
		}

		test_leaf_1_explicit();
	}

	test_leaf_1_osxsave(using_explicit);
	test_leaf_1_apic(using_explicit);
	test_leaf_d_index_0(using_explicit);
	test_leaf_d_index_1(using_explicit, false);
}

/*
 * Tests that CPUID leaves are specialized properly when reached by the
 * "fallback" behavior described in the Intel SDM. The expected behavior is:
 *
 * - Querying a leaf that is not present but is less than the maximum
 *   supported standard leaf should return all zeroes.
 * - Querying a leaf that is greater than the maximum supported standard leaf
 *   should return the values from the maximum supported leaf.
 */
void
do_fallback_test()
{
	uint32_t regs[4];
	uint32_t zero_cpuid[4] = {0, 0, 0, 0};

	/*
	 * The fallback entries contain only leaf 0 and leaf D. Leaf 1 should
	 * return zeroes even if the OSXSAVE bit is set in cr4.
	 */
	setcr4(getcr4() | CR4_OSXSAVE);
	cpuid(1, 0, regs);
	if (!leaf_cmp(regs, zero_cpuid)) {
		TEST_ABORT("missing leaf 1 not all zeroes");
	}

	/*
	 * bhyve's fallback implementation currently falls back to the highest
	 * subleaf for a given leaf and not the guest's requested subleaf. This
	 * means that fallback can't be used to test leaf D subleaf 0 (since
	 * it resolves to subleaf 1 instead).
	 */
	test_leaf_d_index_1(true, true);
}

void
start(void)
{
	do_basic_test(false);
	outl(IOP_TEST_VALUE, 0);
	do_basic_test(true);
	outl(IOP_TEST_VALUE, 1);
	do_basic_test(true);
	outl(IOP_TEST_VALUE, 2);
	do_fallback_test();
	test_result_pass();
}
