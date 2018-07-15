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
 * Test that we properly name all registers in their place.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	add	x0, x0, x0
	add	ra, ra, ra
	add	sp, sp, sp
	add	gp, gp, gp
	add	tp, tp, tp
	add	t0, t0, t0
	add	t1, t1, t1
	add	t2, t2, t2
	add	s0, s0, s0
	add	s1, s1, s1
	add	a0, a0, a0
	add	a1, a1, a1
	add	a2, a2, a2
	add	a3, a3, a3
	add	a4, a4, a4
	add	a5, a5, a5
	add	a6, a6, a6
	add	a7, a7, a7
	add	s2, s2, s2
	add	s3, s3, s3
	add	s4, s4, s4
	add	s5, s5, s5
	add	s6, s6, s6
	add	s7, s7, s7
	add	s8, s8, s8
	add	s9, s9, s9
	add	s10, s10, s10
	add	s11, s11, s11
	add	t3, t3, t3
	add	t4, t4, t4
	add	t5, t5, t5
	add	t6, t6, t6

	add	x0, ra, sp
	add	ra, sp, gp
	add	sp, gp, tp
	add	gp, tp, t0
	add	tp, t0, t1
	add	t0, t1, t2
	add	t1, t2, s0
	add	t2, s0, s1
	add	s0, s1, a0
	add	s1, a0, a1
	add	a0, a1, a2
	add	a1, a2, a3
	add	a2, a3, a4
	add	a3, a4, a5
	add	a4, a5, a6
	add	a5, a6, a7
	add	a6, a7, s2
	add	a7, s2, s3
	add	s2, s3, s4
	add	s3, s4, s5
	add	s4, s5, s6
	add	s5, s6, s7
	add	s6, s7, s8
	add	s7, s8, s9
	add	s8, s9, s10
	add	s9, s10, s11
	add	s10, s11, t3
	add	s11, t3, t4
	add	t3, t4, t5
	add	t4, t5, t6
	add	t5, t6, x0
	add	t6, x0, ra
.size libdis_test, [.-libdis_test]
