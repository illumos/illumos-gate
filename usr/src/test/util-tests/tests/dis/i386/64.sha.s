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
 * Test SHA related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	sha1rnds4	$0x1, %xmm0, %xmm1
	sha1rnds4	$0x2, (%rbx), %xmm1
	sha1rnds4	$0x3, 0x23(%rbx), %xmm1
	sha1rnds4	$0x2, (%rbx, %rcx, 4), %xmm1
	sha1nexte	%xmm0, %xmm1
	sha1nexte	(%rbx), %xmm1
	sha1nexte	0x23(%rbx), %xmm1
	sha1nexte	(%rbx, %rcx, 4), %xmm1
	sha1msg1	%xmm0, %xmm1
	sha1msg1	(%rbx), %xmm1
	sha1msg1	0x23(%rbx), %xmm1
	sha1msg1	(%rbx, %rcx, 4), %xmm1
	sha1msg2	%xmm0, %xmm1
	sha1msg2	(%rbx), %xmm1
	sha1msg2	0x23(%rbx), %xmm1
	sha1msg2	(%rbx, %rcx, 4), %xmm1
	sha256rnds2	%xmm4, %xmm5
	sha256rnds2	(%rbx), %xmm5
	sha256rnds2	0x23(%rbx), %xmm5
	sha256rnds2	(%rbx, %rcx, 4), %xmm5
	sha256msg1	%xmm0, %xmm1
	sha256msg1	(%rbx), %xmm1
	sha256msg1	0x23(%rbx), %xmm1
	sha256msg1	(%rbx, %rcx, 4), %xmm1
	sha256msg2	%xmm0, %xmm1
	sha256msg2	(%rbx), %xmm1
	sha256msg2	0x23(%rbx), %xmm1
	sha256msg2	(%rbx, %rcx, 4), %xmm1
.size libdis_test, [.-libdis_test]
