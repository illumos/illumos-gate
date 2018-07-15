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
 * Test our disassembly of the RV32F instructions. Instructions are ordered per
 * the ISA manual.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	flw		ft1, (s2)
	flw		ft1, -0x4(s2)
	flw		ft1, 0x42(s2)
	fsw		ft1, (s2)
	fsw		ft1, -0x4(s2)
	fsw		ft1, 0x42(s2)

	fmadd.s		ft1, ft2, ft3, ft4
	fmadd.s		ft1, ft2, ft3, ft4, rne
	fmadd.s		ft1, ft2, ft3, ft4, rtz
	fmadd.s		ft1, ft2, ft3, ft4, rdn
	fmadd.s		ft1, ft2, ft3, ft4, rup
	fmadd.s		ft1, ft2, ft3, ft4, rmm

	fmsub.s		ft1, ft2, ft3, ft4
	fmsub.s		ft1, ft2, ft3, ft4, rne
	fmsub.s		ft1, ft2, ft3, ft4, rtz
	fmsub.s		ft1, ft2, ft3, ft4, rdn
	fmsub.s		ft1, ft2, ft3, ft4, rup
	fmsub.s		ft1, ft2, ft3, ft4, rmm

	fnmsub.s	ft1, ft2, ft3, ft4
	fnmsub.s	ft1, ft2, ft3, ft4, rne
	fnmsub.s	ft1, ft2, ft3, ft4, rtz
	fnmsub.s	ft1, ft2, ft3, ft4, rdn
	fnmsub.s	ft1, ft2, ft3, ft4, rup
	fnmsub.s	ft1, ft2, ft3, ft4, rmm

	fnmadd.s	ft1, ft2, ft3, ft4
	fnmadd.s	ft1, ft2, ft3, ft4, rne
	fnmadd.s	ft1, ft2, ft3, ft4, rtz
	fnmadd.s	ft1, ft2, ft3, ft4, rdn
	fnmadd.s	ft1, ft2, ft3, ft4, rup
	fnmadd.s	ft1, ft2, ft3, ft4, rmm

	fadd.s		fs0, fs1, fs2
	fadd.s		fs1, fs2, fs3, rne
	fadd.s		fs2, fs3, fs4, rtz
	fadd.s		fs3, fs4, fs5, rdn
	fadd.s		fs4, fs5, fs6, rup
	fadd.s		fs5, fs6, fs7, rmm

	fsub.s		fs0, fs1, fs2
	fsub.s		fs1, fs2, fs3, rne
	fsub.s		fs2, fs3, fs4, rtz
	fsub.s		fs3, fs4, fs5, rdn
	fsub.s		fs4, fs5, fs6, rup
	fsub.s		fs5, fs6, fs7, rmm

	fmul.s		fs0, fs1, fs2
	fmul.s		fs1, fs2, fs3, rne
	fmul.s		fs2, fs3, fs4, rtz
	fmul.s		fs3, fs4, fs5, rdn
	fmul.s		fs4, fs5, fs6, rup
	fmul.s		fs5, fs6, fs7, rmm

	fdiv.s		fs0, fs1, fs2
	fdiv.s		fs1, fs2, fs3, rne
	fdiv.s		fs2, fs3, fs4, rtz
	fdiv.s		fs3, fs4, fs5, rdn
	fdiv.s		fs4, fs5, fs6, rup
	fdiv.s		fs5, fs6, fs7, rmm

	fsqrt.s		fs0, fs1
	fsqrt.s		fs1, fs2, rne
	fsqrt.s		fs2, fs3, rtz
	fsqrt.s		fs3, fs4, rdn
	fsqrt.s		fs4, fs5, rup
	fsqrt.s		fs5, fs6, rmm

	fsgnj.s		fa0, fa1, fa2
	fsgnjn.s	fa0, fa1, fa2
	fsgnjx.s	fa0, fa1, fa2
	fmin.s		fa0, fa1, fa2
	fmax.s		fa0, fa1, fa2

	fcvt.w.s	t0, ft1
	fcvt.w.s	t1, ft2, rne
	fcvt.w.s	t2, ft3, rtz
	fcvt.w.s	t3, ft4, rdn
	fcvt.w.s	t4, ft5, rup
	fcvt.w.s	t5, ft6, rmm

	fcvt.wu.s	t0, ft1
	fcvt.wu.s	t1, ft2, rne
	fcvt.wu.s	t2, ft3, rtz
	fcvt.wu.s	t3, ft4, rdn
	fcvt.wu.s	t4, ft5, rup
	fcvt.wu.s	t5, ft6, rmm

	fmv.x.w		t0, ft1
	feq.s		a0, ft8, ft7
	flt.s		a1, ft8, ft7
	fle.s		a2, ft8, ft7
	fclass.s	a3, ft8

	fcvt.s.w	ft1, t2
	fcvt.s.w	ft2, t3, rne
	fcvt.s.w	ft3, t4, rtz
	fcvt.s.w	ft4, t5, rdn
	fcvt.s.w	ft5, t6, rup
	fcvt.s.w	ft6, t6, rmm

	fcvt.s.wu	ft1, t2
	fcvt.s.wu	ft2, t3, rne
	fcvt.s.wu	ft3, t4, rtz
	fcvt.s.wu	ft4, t5, rdn
	fcvt.s.wu	ft5, t6, rup
	fcvt.s.wu	ft6, t6, rmm

	fmv.w.x		fs10, s10
.size libdis_test, [.-libdis_test]
