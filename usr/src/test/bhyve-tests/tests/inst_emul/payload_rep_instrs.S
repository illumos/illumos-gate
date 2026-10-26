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
 * Copyright 2026 Edgecast Cloud LLC.
 */

#include <sys/asm_linkage.h>
#include "payload_common.h"
#include "rep_instrs.h"

# xAPIC emulation is handled in-kernel, so it is the "victim" for rep mov/stos
# tests, below. We'll pick up APICBASE from wherever it's configured to make
# sure we actually do I/O against it.
#define MSR_APICBASE $0x1b
# The PIT is handled in-kernel, so it is suitable for in-kernel rep insb
# testing. This port for TIMER_CNTR0 is registered in `vm_inout_init()`.
#define TIMER_CNTR0  $0x40

/* Flat 64-bit code and data segment descriptors */
#define	GDT_CODE64   $0x00af9b000000ffff
#define	GDT_DATA     $0x00cf93000000ffff

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
	call    setup_pf_handler
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
	 * The remaining tests have %rdi cross into a page which the test
	 * runner has marked not-present, so the emulated instruction takes a
	 * #PF part-way through its iterations.  The fault must be delivered
	 * with the saved %rip pointing at the rep-prefixed instruction (which
	 * is kept in %rbx for the test runner to compare against), so that
	 * the remaining iterations are completed once the handler returns.
	 */

	/* Test `rep insb` faulting on its memory destination.. */
	xor     %r8d, %r8d
	mov     TIMER_CNTR0, %dx
	mov     $(INS_FAULT_ADDR - 16), %rdi
	mov     $64, %ecx
	lea     .Lins_fault(%rip), %rbx
.Lins_fault:
	rep     insb
	pause

	/* Test `rep movs` from an MMIO region faulting on its destination.. */
	xor     %r8d, %r8d
	call    load_apicbase
	mov     %rax, %rsi
	mov     $(MOVS_FAULT_ADDR - 16), %rdi
	mov     $16, %ecx
	lea     .Lmovs_fault(%rip), %rbx
.Lmovs_fault:
	rep     movsl
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

/*
 * The test harness loads the hidden segment state directly and leaves the GDT
 * empty, but both exception delivery and `iretq` consult it.  Fill in
 * descriptors for the %cs and %ss selectors in use, then install a 64-bit
 * interrupt gate for #PF.
 */
ENTRY(setup_pf_handler)
	xor     %eax, %eax
	mov     %cs, %ax
	and     $~7, %eax
	movabs  GDT_CODE64, %rdx
	mov     %rdx, MEM_LOC_GDT(%rax)

	xor     %eax, %eax
	mov     %ss, %ax
	and     $~7, %eax
	movabs  GDT_DATA, %rdx
	mov     %rdx, MEM_LOC_GDT(%rax)

	mov     $(MEM_LOC_IDT + PF_VECTOR * 16), %rdi
	lea     pf_handler(%rip), %rax
	mov     %ax, 0(%rdi)
	mov     %cs, %dx
	mov     %dx, 2(%rdi)
	movw    $0x8e00, 4(%rdi)
	shr     $16, %rax
	mov     %ax, 6(%rdi)
	shr     $16, %rax
	mov     %eax, 8(%rdi)
	movl    $0, 12(%rdi)
	ret
SET_SIZE(setup_pf_handler)

/*
 * Mark in %r8 that the fault was taken and let the test runner inspect the
 * exception frame (and make the faulting page present) before returning.
 */
ENTRY(pf_handler)
	mov     $PF_VECTOR, %r8d
	pause
	add     $8, %rsp
	iretq
SET_SIZE(pf_handler)
