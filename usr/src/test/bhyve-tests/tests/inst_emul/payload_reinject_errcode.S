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

#include <sys/asm_linkage.h>

/* x2APIC ID register, inaccessible while the LAPIC is in xAPIC mode */
#define	MSR_X2APIC_ID	0x802

ENTRY(start)
	/*
	 * Reading an x2APIC MSR while the LAPIC is in xAPIC mode is met with a
	 * #GP injected by bhyve (as opposed to one raised by the CPU itself).
	 *
	 * Delivering that #GP requires reading the IDT, which this payload has
	 * never touched, so that delivery is interrupted by a VM exit (for the
	 * nested page fault on the IDT page), after which bhyve must re-inject
	 * the #GP, error code included.  The (empty) IDT then holds no handler
	 * for it, nor for the resulting #DF, so this should triple-fault.
	 */
	movl	$MSR_X2APIC_ID, %ecx
	rdmsr
	hlt
SET_SIZE(start)
