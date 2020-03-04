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
 * Test AVX512 vpclmulqdq related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vpclmulqdq	$0x23, %ymm10, %ymm11, %ymm12
	vpclmulqdq	$0x42, 0x12345(%eax), %ymm13, %ymm14
	vpclmulqdq	$-0x17, 0x678(%ebx, %ecx, 4), %ymm15, %ymm16

	vpclmulqdq	$0x23, %zmm12, %zmm11, %zmm10
	vpclmulqdq	$0x42, 0x12345(%eax), %zmm8, %zmm8
	vpclmulqdq	$-0x17, 0x678(%ebx, %ecx, 4), %zmm7, %zmm6
.size libdis_test, [.-libdis_test]
