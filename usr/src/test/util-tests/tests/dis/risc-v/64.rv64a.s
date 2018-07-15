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
 * Test our disassembly of the RV64A instructions. Instructions are ordered per the
 * ISA manual.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	lr.d		s0, (s1)
	lr.d.aq		s1, (s2)
	lr.d.rl		s2, (s3)
	lr.d.aqrl	s3, (s4)
	sc.d		s0, s2, (s1)
	sc.d.aq		s1, s3, (s1)
	sc.d.rl		s2, s4, (s1)
	sc.d.aqrl	s3, s5, (s1)
	amoswap.d	t0, t1, (t2)
	amoswap.d.aq	t1, t2, (t3)
	amoswap.d.rl	t2, t3, (t4)
	amoswap.d.aqrl	t3, t4, (t5)
	amoadd.d	t0, t1, (t2)
	amoadd.d.aq	t1, t2, (t3)
	amoadd.d.rl	t2, t3, (t4)
	amoadd.d.aqrl	t3, t4, (t5)
	amoxor.d	t0, t1, (t2)
	amoxor.d.aq	t1, t2, (t3)
	amoxor.d.rl	t2, t3, (t4)
	amoxor.d.aqrl	t3, t4, (t5)
	amoand.d	t0, t1, (t2)
	amoand.d.aq	t1, t2, (t3)
	amoand.d.rl	t2, t3, (t4)
	amoand.d.aqrl	t3, t4, (t5)
	amoor.d		t0, t1, (t2)
	amoor.d.aq	t1, t2, (t3)
	amoor.d.rl	t2, t3, (t4)
	amoor.d.aqrl	t3, t4, (t5)
	amomin.d	t0, t1, (t2)
	amomin.d.aq	t1, t2, (t3)
	amomin.d.rl	t2, t3, (t4)
	amomin.d.aqrl	t3, t4, (t5)
	amomax.d	t0, t1, (t2)
	amomax.d.aq	t1, t2, (t3)
	amomax.d.rl	t2, t3, (t4)
	amomax.d.aqrl	t3, t4, (t5)
	amominu.d	t0, t1, (t2)
	amominu.d.aq	t1, t2, (t3)
	amominu.d.rl	t2, t3, (t4)
	amominu.d.aqrl	t3, t4, (t5)
	amomaxu.d	t0, t1, (t2)
	amomaxu.d.aq	t1, t2, (t3)
	amomaxu.d.rl	t2, t3, (t4)
	amomaxu.d.aqrl	t3, t4, (t5)
.size libdis_test, [.-libdis_test]
