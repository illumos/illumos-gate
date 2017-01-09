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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Test bmi2 related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	bzhi	%eax, %ebx, %ecx
	bzhi	%eax, (%rbx), %ecx
	mulx	%eax, %ebx, %ecx
	mulx	(%rax), %ebx, %ecx
	pdep	%eax, %ebx, %ecx
	pdep	(%rax), %ebx, %ecx
	pext	%eax, %ebx, %ecx
	pext	(%rax), %ebx, %ecx
	rorx	$0x3, %eax, %ebx
	rorx	$0x3, (%rax), %ebx
	sarx	%eax, %ebx, %ecx
	sarx	%eax, (%rbx), %ecx
	shlx	%eax, %ebx, %ecx
	shlx	%eax, (%rbx), %ecx
	shrx	%eax, %ebx, %ecx
	shrx	%eax, (%rbx), %ecx

	bzhi	%rax, %rbx, %rcx
	bzhi	%rax, (%rbx), %rcx
	mulx	%rax, %rbx, %rcx
	mulx	(%rax), %rbx, %rcx
	pdep	%rax, %rbx, %rcx
	pdep	(%rax), %rbx, %rcx
	pext	%rax, %rbx, %rcx
	pext	(%rax), %rbx, %rcx
	rorx	$0x3, %rax, %rbx
	rorx	$0x3, (%rax), %rbx
	sarx	%rax, %rbx, %rcx
	sarx	%rax, (%rbx), %rcx
	shlx	%rax, %rbx, %rcx
	shlx	%rax, (%rbx), %rcx
	shrx	%rax, %rbx, %rcx
	shrx	%rax, (%rbx), %rcx
.size libdis_test, [.-libdis_test]
