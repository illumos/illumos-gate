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
 * Test RV64C-specific integer instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	c.addiw	s1, 0x1f
	c.addiw	s1, 0x3
	c.addiw	s1, -0x20
	c.addw	a1, a2
	c.subw	s0, a3
.size libdis_test, [.-libdis_test]
