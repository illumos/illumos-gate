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
#include "payload_common.h"

# xAPIC emulation is handled in-kernel, so it is the "victim" for rep mov/stos
# tests, below. We'll pick up APICBASE from wherever it's configured to make
# sure we actually do I/O against it.
#define MSR_APICBASE $0x1b
# The PIT is handled in-kernel, so it is suitable for in-kernel rep insb
# testing. This port for TIMER_CNTR0 is registered in `vm_inout_init()`.
#define TIMER_CNTR0  $0x40

/*
 * This test is rife with dependencies on x86 UB for which we have picked *a*
 * useful behavior in bhyve. Accesses to the xAPIC registers are expected to
 * be 16-byte aligned and 4 bytes wide; anything else is strongly warned against
 * by the SDM. bhyve generally no-ops inappropriate loads/stores in this space,
 * so use that to test in-kernel rep handling.
 *
 * We use `pause` to coordinate with the test runner as `hlt` would pause the
 * vCPU thread including the test itself!
 */
ENTRY(start)
	sti
	/*
	 * The stack will do as a 64-byte scratch space for the tests below.
	 * Exit here so the test runner can capture expected rsp/APICBASE
	 * values.
	 */
	sub     $64, %rsp
	call    load_apicbase
	pause

	/* Test `rep movs` to an MMIO region.. */
	call    load_apicbase
	mov     %rax, %rsi
	lea     (%rsp), %rdi
	mov     $16, %ecx
	rep     movsl
	pause

	/* Test `rep stos` to an MMIO region.. */
	call    load_apicbase
	mov     %rax, %rdi
	mov     $0x61, %al
	mov     $64, %ecx
	rep     stosb
	pause

	/* Test `rep insb` to read repeatedly from an I/O port.. */
	mov     TIMER_CNTR0, %dx
	lea     (%rsp), %rdi
	mov     $64, %ecx
	rep     insb
	pause

	/*
	 * At this point we're through the test and all expectations have been
	 * checked by the test host.
	 */
	movw    $IOP_TEST_RESULT, %dx
	movb    $TEST_RESULT_PASS, %al
	outb    (%dx)
	pause
SET_SIZE(start)

ENTRY(load_apicbase)
	movq    MSR_APICBASE, %rcx
	rdmsr
	shl     $32, %rdx
	or      %rdx, %rax
	ret
SET_SIZE(load_apicbase)
