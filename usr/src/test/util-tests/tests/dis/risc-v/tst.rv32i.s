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
 * Test our disassembly of the RV32I instructions. Instructions are ordered per
 * the ISA manual. Supervisor and CSR instructions are elsewhere.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	lui	ra, 0x00
	lui	ra, 0x23
	lui	ra, 0xfffff
	auipc	ra, 0x00
	auipc	ra, 0x23
	auipc	ra, 0xfffff
	/*
	 * Branches are not tested at this time as they basially always end up
	 * wanting to create which ends up not really lending itself to
	 * automated testing here. 
	 */
	lb	s0, 0x7ff(s1)
	lb	s1, (s1)
	lb	s2, -0x800(s1)
	lh	s3, 0x7ff(s1)
	lh	s4, (s1)
	lh	s5, -0x800(s1)
	lw	s6, 0x7ff(s1)
	lw	s7, (s1)
	lw	s8, -0x800(s1)
	lbu	s7, 0x7ff(s1)
	lbu	s6, (s1)
	lbu	s5, -0x800(s1)
	lhu	s4, 0x7ff(s1)
	lhu	s3, (s1)
	lhu	s2, -0x800(s1)
	sb	t0, 0x7ff(t1)
	sb	t1, (t2)
	sb	t2, -0x800(t3)
	sh	t3, 0x7ff(t1)
	sh	t4, (t2)
	sh	t5, -0x800(t3)
	sw	t4, 0x7ff(t1)
	sw	t3, (t2)
	sw	t2, -0x800(t3)
	addi	ra, t0, 0x4
	addi	ra, t0, -0x4
	slti	ra, t0, 0x4
	slti	ra, t0, -0x4
	sltiu	ra, t0, 0x4
	sltiu	ra, t0, -0x4
	xori	ra, t0, 0x4
	xori	ra, t0, -0x4
	ori	ra, t0, 0x4
	ori	ra, t0, -0x4
	andi	ra, t0, 0x4
	andi	ra, t0, -0x4
	slli	t4, t5, 0x12
	srli	t4, t5, 0x13
	srai	t4, t5, 0x14
	add	s0, s1, s2
	sub	s1, s2, s3
	sll	s3, s4, s5
	slt	s4, s5, s6
	sltu	a0, a1, ra
	xor	s5, s6, s7
	srl	s6, s7, s8
	sra	s7, s8, s9
	or	s8, s9, s10
	and	s9, s10, s11
	fence
	fence	ow, ir
	fence	ir, ow
	fence	ior, iorw
	fence.i
.size libdis_test, [.-libdis_test]
