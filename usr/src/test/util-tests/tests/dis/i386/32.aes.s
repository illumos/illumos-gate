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
 * Test AES related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	aesenc		%xmm0, %xmm1
	aesenc		(%ebx), %xmm1
	aesenclast	%xmm0, %xmm1
	aesenclast	(%ebx), %xmm1
	aesdec		%xmm0, %xmm1
	aesdec		(%ebx), %xmm1
	aesdeclast	%xmm0, %xmm1
	aesdeclast	(%ebx), %xmm1
	aesimc		%xmm0, %xmm1
	aesimc		(%ebx), %xmm1
	aeskeygenassist	$0x42, %xmm0, %xmm1
	aeskeygenassist	$0x42, (%ebx), %xmm1
.size libdis_test, [.-libdis_test]
