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
 * Test our disassembly of the RV32D instructions. Instructions are ordered per
 * the ISA manual.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	fld		ft1, (s2)
	fld		ft1, -0x4(s2)
	fld		ft1, 0x42(s2)
	fsd		ft1, (s2)
	fsd		ft1, -0x4(s2)
	fsd		ft1, 0x42(s2)

	fmadd.d		ft1, ft2, ft3, ft4
	fmadd.d		ft1, ft2, ft3, ft4, rne
	fmadd.d		ft1, ft2, ft3, ft4, rtz
	fmadd.d		ft1, ft2, ft3, ft4, rdn
	fmadd.d		ft1, ft2, ft3, ft4, rup
	fmadd.d		ft1, ft2, ft3, ft4, rmm

	fmsub.d		ft1, ft2, ft3, ft4
	fmsub.d		ft1, ft2, ft3, ft4, rne
	fmsub.d		ft1, ft2, ft3, ft4, rtz
	fmsub.d		ft1, ft2, ft3, ft4, rdn
	fmsub.d		ft1, ft2, ft3, ft4, rup
	fmsub.d		ft1, ft2, ft3, ft4, rmm

	fnmsub.d	ft1, ft2, ft3, ft4
	fnmsub.d	ft1, ft2, ft3, ft4, rne
	fnmsub.d	ft1, ft2, ft3, ft4, rtz
	fnmsub.d	ft1, ft2, ft3, ft4, rdn
	fnmsub.d	ft1, ft2, ft3, ft4, rup
	fnmsub.d	ft1, ft2, ft3, ft4, rmm

	fnmadd.d	ft1, ft2, ft3, ft4
	fnmadd.d	ft1, ft2, ft3, ft4, rne
	fnmadd.d	ft1, ft2, ft3, ft4, rtz
	fnmadd.d	ft1, ft2, ft3, ft4, rdn
	fnmadd.d	ft1, ft2, ft3, ft4, rup
	fnmadd.d	ft1, ft2, ft3, ft4, rmm

	fadd.d		fs0, fs1, fs2
	fadd.d		fs1, fs2, fs3, rne
	fadd.d		fs2, fs3, fs4, rtz
	fadd.d		fs3, fs4, fs5, rdn
	fadd.d		fs4, fs5, fs6, rup
	fadd.d		fs5, fs6, fs7, rmm

	fsub.d		fs0, fs1, fs2
	fsub.d		fs1, fs2, fs3, rne
	fsub.d		fs2, fs3, fs4, rtz
	fsub.d		fs3, fs4, fs5, rdn
	fsub.d		fs4, fs5, fs6, rup
	fsub.d		fs5, fs6, fs7, rmm

	fmul.d		fs0, fs1, fs2
	fmul.d		fs1, fs2, fs3, rne
	fmul.d		fs2, fs3, fs4, rtz
	fmul.d		fs3, fs4, fs5, rdn
	fmul.d		fs4, fs5, fs6, rup
	fmul.d		fs5, fs6, fs7, rmm

	fdiv.d		fs0, fs1, fs2
	fdiv.d		fs1, fs2, fs3, rne
	fdiv.d		fs2, fs3, fs4, rtz
	fdiv.d		fs3, fs4, fs5, rdn
	fdiv.d		fs4, fs5, fs6, rup
	fdiv.d		fs5, fs6, fs7, rmm

	fsqrt.d		fs0, fs1
	fsqrt.d		fs1, fs2, rne
	fsqrt.d		fs2, fs3, rtz
	fsqrt.d		fs3, fs4, rdn
	fsqrt.d		fs4, fs5, rup
	fsqrt.d		fs5, fs6, rmm

	fsgnj.d		fa0, fa1, fa2
	fsgnjn.d	fa0, fa1, fa2
	fsgnjx.d	fa0, fa1, fa2
	fmin.d		fa0, fa1, fa2
	fmax.d		fa0, fa1, fa2

	fcvt.s.d	fs0, fs1
	fcvt.s.d	fs1, fs2, rne
	fcvt.s.d	fs2, fs3, rtz
	fcvt.s.d	fs3, fs4, rdn
	fcvt.s.d	fs4, fs5, rup
	fcvt.s.d	fs5, fs6, rmm

	fcvt.d.s	fa0, fa1

	feq.d		a0, ft8, ft7
	flt.d		a1, ft8, ft7
	fle.d		a2, ft8, ft7
	fclass.d	a3, ft8

	fcvt.w.d	t0, ft1
	fcvt.w.d	t1, ft2, rne
	fcvt.w.d	t2, ft3, rtz
	fcvt.w.d	t3, ft4, rdn
	fcvt.w.d	t4, ft5, rup
	fcvt.w.d	t5, ft6, rmm

	fcvt.wu.d	t0, ft1
	fcvt.wu.d	t1, ft2, rne
	fcvt.wu.d	t2, ft3, rtz
	fcvt.wu.d	t3, ft4, rdn
	fcvt.wu.d	t4, ft5, rup
	fcvt.wu.d	t5, ft6, rmm

	fcvt.d.w	ft1, t2
	fcvt.d.wu	ft1, t2
.size libdis_test, [.-libdis_test]
