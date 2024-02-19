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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Test prefetch related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	prefetch	(%rax)
	prefetcht0	(%r10)
	prefetcht1	(%rbx)
	prefetcht2	0x4(%rcx)
	prefetchw	0x8(%rcx)
	prefetchnta	0x23(%rdx)
	prefetchit0	(%rip)
	prefetchit1	0x18(%rip)
.size libdis_test, [.-libdis_test]
