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
 * Test our disassembly of the RV32A instructions. Instructions are ordered per the
 * ISA manual.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	lr.w		s0, (s1)
	lr.w.aq		s1, (s2)
	lr.w.rl		s2, (s3)
	lr.w.aqrl	s3, (s4)
	sc.w		s0, s2, (s1)
	sc.w.aq		s1, s3, (s1)
	sc.w.rl		s2, s4, (s1)
	sc.w.aqrl	s3, s5, (s1)
	amoswap.w	t0, t1, (t2)
	amoswap.w.aq	t1, t2, (t3)
	amoswap.w.rl	t2, t3, (t4)
	amoswap.w.aqrl	t3, t4, (t5)
	amoadd.w	t0, t1, (t2)
	amoadd.w.aq	t1, t2, (t3)
	amoadd.w.rl	t2, t3, (t4)
	amoadd.w.aqrl	t3, t4, (t5)
	amoxor.w	t0, t1, (t2)
	amoxor.w.aq	t1, t2, (t3)
	amoxor.w.rl	t2, t3, (t4)
	amoxor.w.aqrl	t3, t4, (t5)
	amoand.w	t0, t1, (t2)
	amoand.w.aq	t1, t2, (t3)
	amoand.w.rl	t2, t3, (t4)
	amoand.w.aqrl	t3, t4, (t5)
	amoor.w		t0, t1, (t2)
	amoor.w.aq	t1, t2, (t3)
	amoor.w.rl	t2, t3, (t4)
	amoor.w.aqrl	t3, t4, (t5)
	amomin.w	t0, t1, (t2)
	amomin.w.aq	t1, t2, (t3)
	amomin.w.rl	t2, t3, (t4)
	amomin.w.aqrl	t3, t4, (t5)
	amomax.w	t0, t1, (t2)
	amomax.w.aq	t1, t2, (t3)
	amomax.w.rl	t2, t3, (t4)
	amomax.w.aqrl	t3, t4, (t5)
	amominu.w	t0, t1, (t2)
	amominu.w.aq	t1, t2, (t3)
	amominu.w.rl	t2, t3, (t4)
	amominu.w.aqrl	t3, t4, (t5)
	amomaxu.w	t0, t1, (t2)
	amomaxu.w.aq	t1, t2, (t3)
	amomaxu.w.rl	t2, t3, (t4)
	amomaxu.w.aqrl	t3, t4, (t5)
.size libdis_test, [.-libdis_test]
