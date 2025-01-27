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
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/asm_linkage.h>
#include "payload_common.h"

/* void outb(uint16_t port, uint8_t val) */
ENTRY(outb)
	movw    %di, %dx
	movb    %sil, %al
	outb    (%dx)
	ret
SET_SIZE(outb)

/* void outw(uint16_t port, uint16_t val) */
ENTRY(outw)
	movw    %di, %dx
	movw    %si, %ax
	outw    (%dx)
	ret
SET_SIZE(outb)

/* void outl(uint16_t port, uint32_t val) */
ENTRY(outl)
	movw    %di, %dx
	movl    %esi, %eax
	outl    (%dx)
	ret
SET_SIZE(outl)

/* uint8_t inb(uint16_t port) */
ENTRY(inb)
	movw    %di, %dx
	inb    (%dx)
	ret
SET_SIZE(inb)

/* uint16_t inw(uint16_t port) */
ENTRY(inw)
	movw    %di, %dx
	inw    (%dx)
	ret
SET_SIZE(inw)

/* uint32_t inl(uint16_t port) */
ENTRY(inl)
	movw    %di, %dx
	inl    (%dx)
	ret
SET_SIZE(inl)

/* uint64_t rdmsr(uint32_t msr) */
ENTRY(rdmsr)
	movl    %edi, %ecx
	rdmsr
	shlq    $32, %rdx
	orq     %rdx, %rax
	ret
SET_SIZE(rdmsr)

/* void wrmsr(uint32_t msr, uint64_t val) */
ENTRY(wrmsr)
	movq    %rsi, %rdx
	shrq    $32, %rdx
	movl    %esi, %eax
	movl    %edi, %ecx
	wrmsr
	ret
SET_SIZE(wrmsr)

/* void cpuid(uint32_t in_eax, uint32_t in_ecx, uint32_t *out_regs) */
ENTRY(cpuid)
	pushq   %rbx
	movl    %edi, %eax
	movl    %esi, %ecx
	movq    %rdx, %r8
	cpuid
	movl    %eax, (%r8)
	movl    %ebx, 4(%r8)
	movl    %ecx, 8(%r8)
	movl    %edx, 12(%r8)
	popq    %rbx
	ret
SET_SIZE(cpuid)

/* uint64_t rdtsc(void) */
ENTRY(rdtsc)
	rdtsc
	shlq    $32, %rdx
	orq     %rdx, %rax
	ret
SET_SIZE(rdtsc)

/* void ud2a(void) */
ENTRY(ud2a)
	ud2a
SET_SIZE(ud2a)

/* void setcr4(uint64_t) */
ENTRY(setcr4)
	movq    %rdi, %cr4
	ret
SET_SIZE(setcr4)

/* uint64_t getcr4(void) */
ENTRY(getcr4)
	movq    %cr4, %rax
	ret
SET_SIZE(getcr4)

/* void setxcr(uint32_t, uint64_t) */
ENTRY(setxcr)
	movq    %rsi, %rdx
	shrq    $32, %rdx
	movl    %esi, %eax
	movl    %edi, %ecx
	#xsetbv
	.byte   0x0f,0x01,0xd1
	ret
SET_SIZE(setxcr)

/* uint64_t getxcr(uint32_t) */
ENTRY(getxcr)
	movl	%edi, %ecx
	#xgetbv
	.byte 0x0f,0x01,0xd0
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
SET_SIZE(getxcr)

/* void test_result_pass(void) */
ENTRY(test_result_pass)
	movl    $IOP_TEST_RESULT, %edi
	movl    $TEST_RESULT_PASS, %esi
	call    outb
	ret
SET_SIZE(test_result_pass)

/* void test_result_fail(void) */
ENTRY(test_result_fail)
	movl    $IOP_TEST_RESULT, %edi
	movl    $TEST_RESULT_FAIL, %esi
	call    outb
	ret
SET_SIZE(test_result_fail)

/* void test_msg(const char *) */
ENTRY(test_msg)
	/*
	 * Message address is assumed to be in lower 32-bits, since that is where
	 * the payload is currently being mapped.
	 */
	movl    %edi, %esi
	movl    $IOP_TEST_MSG, %edi
	call    outl

	ret
SET_SIZE(test_msg)
