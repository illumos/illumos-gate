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
 * Test AVX2 Gather related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vgatherdpd	%xmm0, (%eax, %xmm1, 4), %xmm2
	vgatherdpd	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vgatherdpd	%ymm0, (%eax, %xmm1, 4), %ymm2
	vgatherdpd	%ymm0, 0x42(, %xmm1, 4), %ymm2
	vgatherdps	%xmm0, (%eax, %xmm1, 4), %xmm2
	vgatherdps	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vgatherdps	%ymm0, (%eax, %ymm1, 4), %ymm2
	vgatherdps	%ymm0, 0x42(, %ymm1, 4), %ymm2
	vgatherqpd	%xmm0, (%eax, %xmm1, 4), %xmm2
	vgatherqpd	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vgatherqpd	%ymm0, (%eax, %ymm1, 4), %ymm2
	vgatherqpd	%ymm0, 0x42(, %ymm1, 4), %ymm2
	vgatherqps	%xmm0, (%eax, %xmm1, 4), %xmm2
	vgatherqps	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vgatherqps	%xmm0, (%eax, %ymm1, 4), %xmm2
	vgatherqps	%xmm0, 0x42(, %ymm1, 4), %xmm2
	vpgatherdd	%xmm0, (%eax, %xmm1, 4), %xmm2
	vpgatherdd	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vpgatherdd	%ymm0, (%eax, %ymm1, 4), %ymm2
	vpgatherdd	%ymm0, 0x42(, %ymm1, 4), %ymm2
	vpgatherdq	%xmm0, (%eax, %xmm1, 4), %xmm2
	vpgatherdq	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vpgatherdq	%ymm0, (%eax, %xmm1, 4), %ymm2
	vpgatherdq	%ymm0, 0x42(, %xmm1, 4), %ymm2
	vpgatherqd	%xmm0, (%eax, %xmm1, 4), %xmm2
	vpgatherqd	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vpgatherqd	%xmm0, (%eax, %ymm1, 4), %xmm2
	vpgatherqd	%xmm0, 0x42(, %ymm1, 4), %xmm2
	vpgatherqq	%xmm0, (%eax, %xmm1, 4), %xmm2
	vpgatherqq	%xmm0, 0x42(, %xmm1, 4), %xmm2
	vpgatherqq	%ymm0, (%eax, %ymm1, 4), %ymm2
	vpgatherqq	%ymm0, 0x42(, %ymm1, 4), %ymm2
.size libdis_test, [.-libdis_test]
