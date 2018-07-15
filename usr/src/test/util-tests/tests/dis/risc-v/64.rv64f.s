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
 * Test our disassembly of the RV64F instructions. Instructions are ordered per
 * the ISA manual.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	fcvt.l.s	t0, ft1
	fcvt.l.s	t1, ft2, rne
	fcvt.l.s	t2, ft3, rtz
	fcvt.l.s	t3, ft4, rdn
	fcvt.l.s	t4, ft5, rup
	fcvt.l.s	t5, ft6, rmm

	fcvt.lu.s	t1, ft0
	fcvt.lu.s	t2, ft1, rne
	fcvt.lu.s	t3, ft2, rtz
	fcvt.lu.s	t4, ft3, rdn
	fcvt.lu.s	t5, ft4, rup
	fcvt.lu.s	t6, ft5, rmm

	fcvt.s.l	ft1, t0
	fcvt.s.l	ft2, t1, rne
	fcvt.s.l	ft3, t2, rtz
	fcvt.s.l	ft4, t3, rdn
	fcvt.s.l	ft5, t4, rup
	fcvt.s.l	ft6, t5, rmm

	fcvt.s.lu	ft1, t0
	fcvt.s.lu	ft2, t1, rne
	fcvt.s.lu	ft3, t2, rtz
	fcvt.s.lu	ft4, t3, rdn
	fcvt.s.lu	ft5, t4, rup
	fcvt.s.lu	ft6, t5, rmm
.size libdis_test, [.-libdis_test]
