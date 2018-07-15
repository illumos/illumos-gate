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
 * Test RV64C-specific loads and stores.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	c.ldsp	s1,(sp)
	c.ldsp	a4,0x40(sp)
	c.ldsp	t3,0x38(sp)
	c.fldsp	fs1,(sp)
	c.fldsp	ft8,0x40(sp)
	c.fldsp	fa5,0x38(sp)
	c.sdsp	t4,(sp)
	c.sdsp	tp,0x20(sp)
	c.fsdsp	ft2,(sp)
	c.fsdsp	fa3,0x20(sp)
.size libdis_test, [.-libdis_test]
