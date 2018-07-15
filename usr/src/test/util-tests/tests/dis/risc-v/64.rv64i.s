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
 * Copyright 2018, Joyent, Inc.
 */

/*
 * Test our disassembly of the RV64I instructions. Instructions are ordered per the
 * ISA manual.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	lwu	s7, 0x7ff(s1)
	lwu	s6, (s1)
	lwu	s5, -0x800(s1)
	ld	s4, 0x7ff(s1)
	ld	s3, (s1)
	ld	s2, -0x800(s1)
	sd	t0, 0x7ff(t1)
	sd	t1, (t2)
	sd	t2, -0x800(t3)
	slli	s0, s1, 2
	slli	s0, s1, 63
	srli	s0, s1, 2
	srli	s0, s1, 63
	srai	s0, s1, 2
	srai	s0, s1, 63
	addiw	ra, t0, 0x4
	addiw	ra, t0, -0x4
	slliw	t4, t5, 0x12
	srliw	t4, t5, 0x13
	sraiw	t4, t5, 0x14
	addw	s0, s1, s2
	subw	s1, s2, s3
	sllw	s3, s4, s5
	srlw	s3, s4, s5
	sraw	s3, s4, s5

.size libdis_test, [.-libdis_test]
