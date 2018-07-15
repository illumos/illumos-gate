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
 * Test common compact integer instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	c.li	ra, 0x15
	c.li	s11, -0x13
	c.lui	s1, 0x2
	c.lui	s1, 0x13

	c.addi	s1, 0x1f
	c.addi	s1, 0x3
	c.addi	s1, -0x20

	c.addi16sp	sp, 0x30
	c.addi16sp	sp, -0x40
	c.addi4spn	a1, sp, 0x10
	c.addi4spn	a1, sp, 0x2c

	c.slli	s10, 0x5
	c.slli	t4, 0x13
	c.slli	s0, 0x2
	c.srli	a2, 0x4
	c.srli	s1, 0x15
	c.srai	a3, 0x4
	c.srai	a5, 0x19
	c.andi	a4, 0x3
	c.andi	a3, -0x7
	c.mv	s1, a4
	c.mv	a0, a5
	c.add	a1, a3
	c.add	a2, a2
	c.and	a0, a1
	c.or	a1, a2
	c.xor	a2, a3
	c.sub	a3, a4

	c.nop
	c.ebreak
.size libdis_test, [.-libdis_test]
