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
#include "test_defs.h"

#define	MSR_APICBASE		0x1b
#define	MSR_X2APIC_ID		0x802
#define	MSR_X2APIC_TPR		0x808
#define	MSR_X2APIC_APR		0x809
#define	MSR_X2APIC_PPR		0x80a
#define	MSR_X2APIC_EOI		0x80b
#define	MSR_X2APIC_RRR		0x80c
#define	MSR_X2APIC_LDR		0x80d
#define	MSR_X2APIC_DFR		0x80e
#define	MSR_X2APIC_SVR		0x80f
#define	MSR_X2APIC_ICR		0x830
#define	MSR_X2APIC_ICR_HI	0x831
#define	MSR_X2APIC_SELF_IPI	0x83f

#define	APICBASE_X2APIC		(1UL << 10)
#define	APICBASE_ENABLED	(1UL << 11)
#define	APICBASE_ADDR_MASK	0xfffffffffffff000UL
#define	APICBASE_STATE_MASK	(APICBASE_ENABLED | APICBASE_X2APIC)

#define	XAPIC_OFFSET_ID		0x20

/*
 * Fixed-mode, edge-triggered, physical-destination IPI (no shorthand) of an
 * otherwise unused vector, sent to an x2APIC ID with no vCPU behind it: vCPU
 * IDs are limited to 16 bits.
 */
#define	ICR_VECTOR		0x40
#define	ICR_ABSENT_DEST		0x10000U

#define	EXPECT_OK(expr, desc)						\
	do {								\
		if ((expr) != EXC_NONE) {				\
			TEST_ABORT("unexpected exception: " desc);	\
		}							\
	} while (0)

#define	EXPECT_GP(expr, desc)						\
	do {								\
		if ((expr) != EXC_GP) {					\
			TEST_ABORT("expected #GP: " desc);		\
		}							\
	} while (0)

static uint32_t
xapic_id(void)
{
	volatile uint32_t *reg =
	    (volatile uint32_t *)(MMIO_LAPIC_BASE + XAPIC_OFFSET_ID);

	return (*reg);
}

/*
 * The logical x2APIC ID is derived from the x2APIC ID: the cluster ID in bits
 * 31:16 and a one-hot position within the cluster in bits 15:0.
 */
static uint32_t
x2apic_ldr(uint32_t id)
{
	return (((id >> 4) << 16) | (1U << (id & 0xf)));
}

static bool
cpuid_x2apic(void)
{
	uint32_t regs[4];

	cpuid(1, 0, regs);
	return ((regs[2] & CPUID1_ECX_X2APIC) != 0);
}

static void
check_x2apic_regs(uint32_t vcpuid)
{
	uint64_t val;

	EXPECT_OK(rdmsr_safe(MSR_X2APIC_ID, &val), "x2APIC ID read");
	if (val != vcpuid) {
		TEST_ABORT("x2APIC ID does not match vCPU ID");
	}
	EXPECT_OK(rdmsr_safe(MSR_X2APIC_LDR, &val), "x2APIC LDR read");
	if (val != x2apic_ldr(vcpuid)) {
		TEST_ABORT("x2APIC LDR not derived from x2APIC ID");
	}
}

void
start(void)
{
	uint64_t val;

	idt_init();

	const uint32_t vcpuid = inl(IOP_TEST_PARAM);
	const uint64_t base = rdmsr(MSR_APICBASE);

	if ((base & APICBASE_STATE_MASK) != APICBASE_ENABLED) {
		TEST_ABORT("LAPIC not in xAPIC mode at start");
	}
	if ((base & APICBASE_ADDR_MASK) != MMIO_LAPIC_BASE) {
		TEST_ABORT("unexpected LAPIC base address");
	}
	if (xapic_id() != (vcpuid << 24)) {
		TEST_ABORT("xAPIC ID does not match vCPU ID");
	}

	/* The x2APIC MSRs are inaccessible outside of x2APIC mode */
	EXPECT_GP(rdmsr_safe(MSR_X2APIC_ID, &val), "x2APIC MSR read in xAPIC");

	/* x2APIC mode cannot be entered if it is not advertised in CPUID */
	if (cpuid_x2apic()) {
		TEST_ABORT("x2APIC unexpectedly advertised in CPUID");
	}
	EXPECT_GP(wrmsr_safe(MSR_APICBASE, base | APICBASE_X2APIC),
	    "x2APIC enabled without CPUID support");
	if (rdmsr(MSR_APICBASE) != base) {
		TEST_ABORT("APICBASE altered by rejected write");
	}

	/* Have the host advertise x2APIC in CPUID */
	outl(IOP_TEST_VALUE, 1);
	if (!cpuid_x2apic()) {
		TEST_ABORT("x2APIC not advertised in CPUID");
	}

	/* The invalid state (x2APIC enabled, but LAPIC disabled) is rejected */
	EXPECT_GP(wrmsr_safe(MSR_APICBASE,
	    (base & ~APICBASE_ENABLED) | APICBASE_X2APIC),
	    "entry to invalid APICBASE state");

	/* xAPIC -> x2APIC */
	EXPECT_OK(wrmsr_safe(MSR_APICBASE, base | APICBASE_X2APIC),
	    "xAPIC -> x2APIC");
	check_x2apic_regs(vcpuid);

	/* x2APIC -> x2APIC */
	EXPECT_OK(wrmsr_safe(MSR_APICBASE, base | APICBASE_X2APIC),
	    "x2APIC -> x2APIC");
	if (rdmsr(MSR_APICBASE) != (base | APICBASE_X2APIC)) {
		TEST_ABORT("APICBASE altered by x2APIC -> x2APIC");
	}
	check_x2apic_regs(vcpuid);

	/*
	 * Registers which are read-only or absent in x2APIC mode.
	 */
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_ID, vcpuid), "ID write in x2APIC");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_LDR, 0), "LDR write in x2APIC");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_DFR, 0), "DFR write in x2APIC");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_ICR_HI, 0), "ICR_HI write in x2APIC");
	EXPECT_GP(rdmsr_safe(MSR_X2APIC_APR, &val), "APR read in x2APIC");
	EXPECT_GP(rdmsr_safe(MSR_X2APIC_RRR, &val), "RRR read in x2APIC");
	EXPECT_GP(rdmsr_safe(MSR_X2APIC_DFR, &val), "DFR read in x2APIC");
	EXPECT_OK(rdmsr_safe(MSR_X2APIC_PPR, &val), "PPR read in x2APIC");

	/*
	 * EOI accepts only a write of 0, and bits 63:32 are reserved in every
	 * register but the (64-bit) ICR.
	 */
	EXPECT_OK(wrmsr_safe(MSR_X2APIC_EOI, 0), "EOI write of 0");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_EOI, 1), "EOI write of non-zero");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_TPR, 1UL << 32),
	    "TPR write with bits 63:32 set");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_SELF_IPI, 1UL << 32),
	    "SELF_IPI write with bits 63:32 set");
	EXPECT_OK(rdmsr_safe(MSR_X2APIC_SVR, &val), "SVR read in x2APIC");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_SVR, val | (1UL << 32)),
	    "SVR write with bits 63:32 set");

	/*
	 * Only bits 7:0 of TPR and SELF_IPI are defined, and setting any of
	 * the reserved bits is met with #GP.
	 */
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_TPR, 0x100),
	    "TPR write with bits 31:8 set");
	EXPECT_GP(wrmsr_safe(MSR_X2APIC_SELF_IPI, 0x100),
	    "SELF_IPI write with bits 31:8 set");
	EXPECT_OK(wrmsr_safe(MSR_X2APIC_TPR, 0x20), "TPR write");
	EXPECT_OK(rdmsr_safe(MSR_X2APIC_TPR, &val), "TPR read");
	if (val != 0x20) {
		TEST_ABORT("TPR did not read back as written");
	}
	EXPECT_OK(wrmsr_safe(MSR_X2APIC_TPR, 0), "TPR write of 0");

	/*
	 * The ICR is a single 64-bit register in x2APIC mode and a read
	 * must return it in full including the destination in bits 63:32.
	 *
	 * The fixed-mode IPI sent by the write is addressed to a physical
	 * x2APIC ID with no vCPU behind it, so nothing is delivered.
	 */
	const uint64_t icr = ((uint64_t)ICR_ABSENT_DEST << 32) | ICR_VECTOR;
	EXPECT_OK(wrmsr_safe(MSR_X2APIC_ICR, icr), "ICR write");
	EXPECT_OK(rdmsr_safe(MSR_X2APIC_ICR, &val), "ICR read");
	if (val != icr) {
		TEST_ABORT("ICR did not read back as written");
	}

	/* x2APIC -> xAPIC is invalid without passing through Disabled */
	EXPECT_GP(wrmsr_safe(MSR_APICBASE, base), "x2APIC -> xAPIC");
	if (rdmsr(MSR_APICBASE) != (base | APICBASE_X2APIC)) {
		TEST_ABORT("APICBASE altered by rejected write");
	}

	/* x2APIC -> Disabled */
	EXPECT_OK(wrmsr_safe(MSR_APICBASE, base & ~APICBASE_ENABLED),
	    "x2APIC -> Disabled");
	EXPECT_GP(rdmsr_safe(MSR_X2APIC_ID, &val),
	    "x2APIC MSR read while disabled");

	/* Disabled -> x2APIC is invalid without passing through xAPIC */
	EXPECT_GP(wrmsr_safe(MSR_APICBASE, base | APICBASE_X2APIC),
	    "Disabled -> x2APIC");

	/* Disabled -> xAPIC, with the ID back in its xAPIC format */
	EXPECT_OK(wrmsr_safe(MSR_APICBASE, base), "Disabled -> xAPIC");
	if (xapic_id() != (vcpuid << 24)) {
		TEST_ABORT("xAPIC ID not restored after leaving x2APIC mode");
	}

	/* ... and back into x2APIC mode once more */
	EXPECT_OK(wrmsr_safe(MSR_APICBASE, base | APICBASE_X2APIC),
	    "xAPIC -> x2APIC (again)");
	check_x2apic_regs(vcpuid);

	test_result_pass();
}
