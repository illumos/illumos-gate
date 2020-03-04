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
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Test VAES related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vaesenc	%xmm0, %xmm1, %xmm2
	vaesenc	(%rax), %xmm1, %xmm2
	vaesenc	%ymm3, %ymm4, %ymm5
	vaesenc	(%rbx), %ymm4, %ymm5
	vaesenc	%zmm6, %zmm7, %zmm0
	vaesenc	(%rcx), %zmm7, %zmm0

	vaesenclast	%xmm0, %xmm1, %xmm2
	vaesenclast	(%rax), %xmm1, %xmm2
	vaesenclast	%ymm3, %ymm4, %ymm5
	vaesenclast	(%rbx), %ymm4, %ymm5
	vaesenclast	%zmm6, %zmm7, %zmm0
	vaesenclast	(%rcx), %zmm7, %zmm0

	vaesdec	%xmm0, %xmm1, %xmm2
	vaesdec	(%rax), %xmm1, %xmm2
	vaesdec	%ymm3, %ymm4, %ymm5
	vaesdec	(%rbx), %ymm4, %ymm5
	vaesdec	%zmm6, %zmm7, %zmm0
	vaesdec	(%rcx), %zmm7, %zmm0

	vaesdeclast	%xmm0, %xmm1, %xmm2
	vaesdeclast	(%rax), %xmm1, %xmm2
	vaesdeclast	%ymm3, %ymm4, %ymm5
	vaesdeclast	(%rbx), %ymm4, %ymm5
	vaesdeclast	%zmm6, %zmm7, %zmm0
	vaesdeclast	(%rcx), %zmm7, %zmm0
.size libdis_test, [.-libdis_test]
