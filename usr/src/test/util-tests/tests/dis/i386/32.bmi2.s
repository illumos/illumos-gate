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
	bzhi	%eax, (%ebx), %ecx
	mulx	%eax, %ebx, %ecx
	mulx	(%eax), %ebx, %ecx
	pdep	%eax, %ebx, %ecx
	pdep	(%eax), %ebx, %ecx
	pext	%eax, %ebx, %ecx
	pext	(%eax), %ebx, %ecx
	rorx	$0x3, %eax, %ebx
	rorx	$0x3, (%eax), %ebx
	sarx	%eax, %ebx, %ecx
	sarx	%eax, (%ebx), %ecx
	shlx	%eax, %ebx, %ecx
	shlx	%eax, (%ebx), %ecx
	shrx	%eax, %ebx, %ecx
	shrx	%eax, (%ebx), %ecx
.size libdis_test, [.-libdis_test]
