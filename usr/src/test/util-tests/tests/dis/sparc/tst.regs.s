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
 * Test basic register naming
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	add %g0, %g1, %g2
	add %g1, %g2, %g3
	add %g2, %g3, %g4
	add %g3, %g4, %g5
	add %g4, %g5, %g6
	add %g5, %g6, %g7
	add %g6, %g7, %o0
	add %g7, %o0, %o1
	add %o0, %o1, %o2
	add %o1, %o2, %o3
	add %o2, %o3, %o4
	add %o3, %o4, %o5
	add %o4, %o5, %sp
	add %o5, %sp, %o7
	add %sp, %o7, %l0
	add %o7, %l0, %l1
	add %l0, %l1, %l2
	add %l1, %l2, %l3
	add %l2, %l3, %l4
	add %l3, %l4, %l5
	add %l4, %l5, %l6
	add %l5, %l6, %l7
	add %l6, %l7, %i0
	add %l7, %i0, %i1
	add %i0, %i1, %i2
	add %i1, %i2, %i3
	add %i2, %i3, %i4
	add %i3, %i4, %i5
	add %i4, %i5, %fp
	add %i5, %fp, %i7
.size libdis_test, [.-libdis_test]
