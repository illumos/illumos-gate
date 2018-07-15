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
 * Test our disassembly of various supported pseudo instructions. We only
 * support disassembling a subset of the common pseudo instructions that map
 * directly to a single asm instruction. Several of the pseudo-instructions
 * transform into more than one instruction so we don't support them.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	nop
	ret
	fence
	rdinstret	t0
	rdcycle		t1
	rdtime		t2
	csrr		t1, ustatus
	csrw		ustatus, t1
	csrs		ustatus, t2
	csrc		ustatus, t3
	csrwi		uie, 0x4
	csrsi		uie, 0x5
	csrci		uie, 0x6
	frcsr		s0
	fscsr		s0, s1
	fscsr		s1
	frrm		a0
	fsrm		a0, a1
	fsrm		a1
	fsrmi		t0, 0x4
	fsrmi		0x5	
	frflags		a0
	fsflags		a0, a1
	fsflags		a1
	fsflagsi	t0, 0x4
	fsflagsi	0x5	
.size libdis_test, [.-libdis_test]
