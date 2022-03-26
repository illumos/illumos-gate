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
#define	MSR_X2APIC_BASE	0x800
#define	MSR_X2APIC_MAX	0x8ff

#define	APICBASE_X2APIC	(1 << 10)

static bool
reg_readable(uint32_t reg)
{
	switch (reg) {
	case 0x802: /* ID */
	case 0x803: /* VER */

	case 0x808: /* TPR */
	case 0x809: /* APR */
	case 0x80a: /* PPR */

	case 0x80c: /* RRR */
	case 0x80d: /* LDR */
	case 0x80e: /* DFR */
	case 0x80f: /* SVR */

	case 0x810 ... 0x817: /* ISR */
	case 0x818 ... 0x81f: /* TMR */
	case 0x820 ... 0x827: /* IRR */

	case 0x828: /* ESR */

	case 0x82f: /* LVT_CMCI */
	case 0x830: /* ICR */

	case 0x832: /* LVT_TIMER */
	case 0x833: /* LVT_THERMAL */
	case 0x834: /* LVT_PERF */
	case 0x835: /* LVT_LINT0 */
	case 0x836: /* LVT_LINT1 */
	case 0x837: /* LVT_ERROR */
	case 0x838: /* TIMER_ICR */
	case 0x839: /* TIMER_CCR */

	case 0x83e: /* TIMER_DCR */
		return (true);
	default:
		return (false);
	}
}

static bool
reg_writable(uint32_t reg)
{
	switch (reg) {
	case 0x802: /* ID */

	case 0x808: /* TPR */

	case 0x80b: /* EOI */

	case 0x80d: /* LDR */
	case 0x80e: /* DFR */
	case 0x80f: /* SVR */

	case 0x828: /* ESR */

	case 0x82f: /* LVT_CMCI */
	case 0x830: /* ICR */

	case 0x832: /* LVT_TIMER */
	case 0x833: /* LVT_THERMAL */
	case 0x834: /* LVT_PERF */
	case 0x835: /* LVT_LINT0 */
	case 0x836: /* LVT_LINT1 */
	case 0x837: /* LVT_ERROR */
	case 0x838: /* TIMER_ICR */

	case 0x83e: /* TIMER_DCR */
	case 0x83f: /* SELF_IPI */
		return (true);
	default:
		return (false);
	}
}

void
start(void)
{
	uint64_t base = rdmsr(MSR_APICBASE);
	if ((base & APICBASE_X2APIC) == 0) {
		/* bail if the host has not enabled x2apic for us */
		outb(IOP_TEST_RESULT, TEST_RESULT_FAIL);
	}

	for (uint32_t msr = MSR_X2APIC_BASE; msr <= MSR_X2APIC_MAX; msr++) {
		uint64_t val = 0;

		if (reg_readable(msr)) {
			val = rdmsr(msr);
		}

		if (reg_writable(msr)) {
			if (msr == 0x828) {
				/*
				 * While the LAPIC is in x2APIC mode, writes to
				 * the ESR must carry a value of 0.
				 */
				val = 0;
			}
			wrmsr(msr, val);
		}
	}

	/* If we made it this far without a #GP, it counts as a win */
	outb(IOP_TEST_RESULT, TEST_RESULT_PASS);
}
