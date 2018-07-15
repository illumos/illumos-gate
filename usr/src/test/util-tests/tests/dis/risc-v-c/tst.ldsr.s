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
 * Test common compact loads and stores.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	c.lwsp	s1,(sp)
	c.lwsp	a4,0x40(sp)
	c.lwsp	t3,0x34(sp)
	c.swsp	t4,(sp)
	c.swsp	tp,0x20(sp)
	/*
	 * gas 2.30 doesn't support using the ABI aliases. However, that's how
	 * we disassemble these.
	 */
	c.lw	x9,(x10)
	c.lw	x12,0x40(x13)
	c.fld	fs1,(a0)
	c.fld	fa3,0x40(a3)
.size libdis_test, [.-libdis_test]
