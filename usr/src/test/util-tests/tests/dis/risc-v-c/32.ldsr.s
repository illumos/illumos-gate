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
 * Test RV32C-specific loads and stores.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	c.flw	fs1,(a0)
	c.flw	fa3,0x40(a3)
	c.flwsp	fs1,(sp)
	c.flwsp	ft8,0x40(sp)
	c.flwsp	fa5,0x34(sp)
	c.fswsp	ft2,(sp)
	c.fswsp	fa3,0x20(sp)
.size libdis_test, [.-libdis_test]
