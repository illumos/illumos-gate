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
	fcvt.l.d	t0, ft1
	fcvt.l.d	t1, ft2, rne
	fcvt.l.d	t2, ft3, rtz
	fcvt.l.d	t3, ft4, rdn
	fcvt.l.d	t4, ft5, rup
	fcvt.l.d	t5, ft6, rmm

	fcvt.lu.d	t1, ft0
	fcvt.lu.d	t2, ft1, rne
	fcvt.lu.d	t3, ft2, rtz
	fcvt.lu.d	t4, ft3, rdn
	fcvt.lu.d	t5, ft4, rup
	fcvt.lu.d	t6, ft5, rmm

	fmv.x.d		t3, fa1

	fcvt.d.l	ft1, t0
	fcvt.d.l	ft2, t1, rne
	fcvt.d.l	ft3, t2, rtz
	fcvt.d.l	ft4, t3, rdn
	fcvt.d.l	ft5, t4, rup
	fcvt.d.l	ft6, t5, rmm

	fcvt.d.lu	ft1, t0
	fcvt.d.lu	ft2, t1, rne
	fcvt.d.lu	ft3, t2, rtz
	fcvt.d.lu	ft4, t3, rdn
	fcvt.d.lu	ft5, t4, rup
	fcvt.d.lu	ft6, t5, rmm

	fmv.d.x		fa2, t3
.size libdis_test, [.-libdis_test]
