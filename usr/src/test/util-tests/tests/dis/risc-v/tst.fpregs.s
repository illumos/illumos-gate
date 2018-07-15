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
 * Test our disassembly of all of the fp register names.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:

libdifs_tefst:
	fadd.s	ft0, ft0, ft0
	fadd.s	ft1, ft1, ft1
	fadd.s	ft2, ft2, ft2
	fadd.s	ft3, ft3, ft3
	fadd.s	ft4, ft4, ft4
	fadd.s	ft5, ft5, ft5
	fadd.s	ft6, ft6, ft6
	fadd.s	ft7, ft7, ft7
	fadd.s	fs0, fs0, fs0
	fadd.s	fs1, fs1, fs1
	fadd.s	fa0, fa0, fa0
	fadd.s	fa1, fa1, fa1
	fadd.s	fa2, fa2, fa2
	fadd.s	fa3, fa3, fa3
	fadd.s	fa4, fa4, fa4
	fadd.s	fa5, fa5, fa5
	fadd.s	fa6, fa6, fa6
	fadd.s	fa7, fa7, fa7
	fadd.s	fs2, fs2, fs2
	fadd.s	fs3, fs3, fs3
	fadd.s	fs4, fs4, fs4
	fadd.s	fs5, fs5, fs5
	fadd.s	fs6, fs6, fs6
	fadd.s	fs7, fs7, fs7
	fadd.s	fs8, fs8, fs8
	fadd.s	fs9, fs9, fs9
	fadd.s	fs10, fs10, fs10
	fadd.s	fs11, fs11, fs11
	fadd.s	ft8, ft8, ft8
	fadd.s	ft9, ft9, ft9 
	fadd.s	ft10, ft10, ft10 
	fadd.s	ft11, ft11, ft11

	fadd.s	ft0, ft1, ft2
	fadd.s	ft1, ft2, ft3
	fadd.s	ft2, ft3, ft4
	fadd.s	ft3, ft4, ft5
	fadd.s	ft4, ft5, ft6
	fadd.s	ft5, ft6, ft7
	fadd.s	ft6, ft7, fs0
	fadd.s	ft7, fs0, fs1
	fadd.s	fs0, fs1, fa0
	fadd.s	fs1, fa0, fa1
	fadd.s	fa0, fa1, fa2
	fadd.s	fa1, fa2, fa3
	fadd.s	fa2, fa3, fa4
	fadd.s	fa3, fa4, fa5
	fadd.s	fa4, fa5, fa6
	fadd.s	fa5, fa6, fa7
	fadd.s	fa6, fa7, fs2
	fadd.s	fa7, fs2, fs3
	fadd.s	fs2, fs3, fs4
	fadd.s	fs3, fs4, fs5
	fadd.s	fs4, fs5, fs6
	fadd.s	fs5, fs6, fs7
	fadd.s	fs6, fs7, fs8
	fadd.s	fs7, fs8, fs9
	fadd.s	fs8, fs9, fs10
	fadd.s	fs9, fs10, fs11
	fadd.s	fs10, fs11, ft8
	fadd.s	fs11, ft8, ft9
	fadd.s	ft8, ft9, ft10
	fadd.s	ft9, ft10, ft11
	fadd.s	ft10, ft11, ft0
	fadd.s	ft11, ft0, ft1
.size libdis_test, [.-libdis_test]
