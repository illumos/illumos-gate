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
 * Test bmi1 related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	andn	%eax, %ebx, %edx
	andn	(%rax), %ebx, %edx
	andn	0x40(%rax), %ebx, %edx
	bextr	%ebx, %eax, %edx
	bextr	%ebx, (%rax), %edx
	bextr	%ebx, 0x40(%rax), %edx
	blsi	%eax, %edx
	blsi	(%rax), %edx
	blsi	0x40(%rax), %edx
	blsmsk	%eax, %edx
	blsmsk	(%rax), %edx
	blsmsk	0x40(%rax), %edx
	blsr	%eax, %edx
	blsr	(%rax), %edx
	blsr	0x40(%rax), %edx
	tzcnt	%ax, %dx
	tzcnt	(%rax), %dx
	tzcnt	0x40(%rax), %dx
	tzcnt	%eax, %edx
	tzcnt	(%rax), %edx
	tzcnt	0x40(%rax), %edx

	andn	%rax, %rbx, %rdx
	andn	(%rax), %rbx, %rdx
	andn	0x40(%rax), %rbx, %rdx
	bextr	%rbx, %rax, %rdx
	bextr	%rbx, (%rax), %rdx
	bextr	%rbx, 0x40(%rax), %rdx
	blsi	%rax, %rdx
	blsi	(%rax), %rdx
	blsi	0x40(%rax), %rdx
	blsmsk	%rax, %rdx
	blsmsk	(%rax), %rdx
	blsmsk	0x40(%rax), %rdx
	blsr	%rax, %rdx
	blsr	(%rax), %rdx
	blsr	0x40(%rax), %rdx
	tzcnt	%rax, %rdx
	tzcnt	(%rax), %rdx
	tzcnt	0x40(%rax), %rdx
.size libdis_test, [.-libdis_test]
