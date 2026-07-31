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

/*
 * Regression test for cases where certain combinations of SIB encodings weren't
 * getting flagged correctly.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	movq (%rax, %rbx, 2), %rsi
	movq (%rax, %r8, 4), %rsi
	movq (%rax, %r15, 8), %rsi
	movq (%rcx, %rbx, 2), %rsi
	movq (%rcx, %r8, 4), %rsi
	movq (%rcx, %r15, 8), %rsi
	movq 0x7777(%rax, %rbx, 2), %rsi
	movq 0x7777(%rax, %r8, 4), %rsi
	movq 0x7777(%rax, %r15, 8), %rsi
	movq 0x7777(%rcx, %rbx, 2), %rsi
	movq 0x7777(%rcx, %r8, 4), %rsi
	movq 0x7777(%rcx, %r15, 8), %rsi
	vmovups (%rax, %rbx, 2), %zmm20
	vmovups (%rax, %r8, 4), %zmm20
	vmovups (%rax, %r15, 8), %zmm20
	vmovups (%rcx, %rbx, 2), %zmm20
	vmovups (%rcx, %r8, 4), %zmm20
	vmovups (%rcx, %r15, 8), %zmm20
	vmovups 0x7777(%rax, %rbx, 2), %zmm20
	vmovups 0x7777(%rax, %r8, 4), %zmm20
	vmovups 0x7777(%rax, %r15, 8), %zmm20
	vmovups 0x7777(%rcx, %rbx, 2), %zmm20
	vmovups 0x7777(%rcx, %r8, 4), %zmm20
	vmovups 0x7777(%rcx, %r15, 8), %zmm20

.size libdis_test, [.-libdis_test]
