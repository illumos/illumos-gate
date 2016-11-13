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
 * Test F16C related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vcvtph2ps	%xmm0, %xmm1
	vcvtph2ps	(%rax), %xmm1
	vcvtph2ps	0x24(%rax), %xmm1
	vcvtph2ps	%xmm0, %ymm1
	vcvtph2ps	(%rax), %ymm1
	vcvtph2ps	0x24(%rax), %ymm1

	vcvtps2ph	$0x10, %xmm0, %xmm1
	vcvtps2ph	$0x10, %xmm3, (%rbx)
	vcvtps2ph	$0x10, %xmm4, 0x10(%rcx)
	vcvtps2ph	$0x10, %ymm0, %xmm1
	vcvtps2ph	$0x10, %ymm3, (%rbx)
	vcvtps2ph	$0x10, %ymm4, 0x10(%rcx)
.size libdis_test, [.-libdis_test]
