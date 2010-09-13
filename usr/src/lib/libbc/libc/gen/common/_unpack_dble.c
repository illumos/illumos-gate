/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "base_conversion.h"

/* Normalize a number.  Does not affect zeros, infs, or NaNs. */
void
_fp_normalize(unpacked *pu)
{
	int             i;
	short unsigned  nlzwords, nlzbits;
	long unsigned   t;

	if ((*pu).fpclass == fp_normal) {
		for (nlzwords = 0; (pu->significand[nlzwords] == 0) && (nlzwords < UNPACKED_SIZE); nlzwords++);
		if (nlzwords >= UNPACKED_SIZE) {
			(*pu).fpclass = fp_zero;
			return;
		}
		if (nlzwords > 0) {
			for (i = 0; i < UNPACKED_SIZE - nlzwords; i++)
				pu->significand[i] = pu->significand[i + nlzwords];
			for (; i < UNPACKED_SIZE; i++)
				pu->significand[i] = 0;
			pu->exponent -= 32 * nlzwords;
		}
		for (; pu->significand[UNPACKED_SIZE - 1 - nlzwords] == 0; nlzwords++);
		/* nlzwords is now the count of trailing zero words. */

		nlzbits = 0;
		t = pu->significand[0];
		/* TESTS to determine normalize count.	 */

#define SHIFTMACRO(n) if (t <= (((unsigned long) 0xffffffff) >> n)) { t = t<<n ; nlzbits += n ; }
		SHIFTMACRO(16);
		SHIFTMACRO(8);
		SHIFTMACRO(4);
		SHIFTMACRO(2);
		SHIFTMACRO(1);
		pu->exponent -= nlzbits;
		if (nlzbits >= 1) {	/* small shift */
			unsigned long   high, low, shiftout = 0;
			for (i = UNPACKED_SIZE - 1 - nlzwords; i >= 0; i--) {
				high = pu->significand[i] << nlzbits;
				low = pu->significand[i] >> (32 - nlzbits);
				pu->significand[i] = shiftout | high;
				shiftout = low;
			}
		}
	}
}

/* Set the exception bit in the current exception register. */
void
_fp_set_exception(enum fp_exception_type ex)
{
	_fp_current_exceptions |= 1 << (int) ex;
}

enum fp_class_type
_class_double(double *x)
{
	double_equivalence kluge;

	kluge.x = *x;
	if (kluge.f.msw.exponent == 0) {	/* 0 or sub */
		if ((kluge.f.msw.significand == 0) && (kluge.f.significand2 == 0))
			return fp_zero;
		else
			return fp_subnormal;
	} else if (kluge.f.msw.exponent == 0x7ff) {	/* inf or nan */
		if ((kluge.f.msw.significand == 0) && (kluge.f.significand2 == 0))
			return fp_infinity;
		else if (kluge.f.msw.significand >= 0x40000)
			return fp_quiet;
		else
			return fp_signaling;
	} else
		return fp_normal;
}


/* Left shift significand by 11 <= n <= 16 bits.  Affect all classes.	 */
void
_fp_leftshift(unpacked *pu, unsigned n)
{
	int             i;

	unsigned long   high, low, shiftout = 0;
	for (i = UNPACKED_SIZE - 1; i >= 0; i--) {
		high = pu->significand[i] << n;
		low = pu->significand[i] >> (32 - n);
		pu->significand[i] = shiftout | high;
		shiftout = low;
	}
}


void
_unpack_double(unpacked *pu, double *px)
{
	double_equivalence x;
	int             i;

	x.x = *px;
	(*pu).sign = x.f.msw.sign;
	pu->significand[1] = x.f.significand2;
	for (i = 2; i < UNPACKED_SIZE; i++)
		pu->significand[i] = 0;
	if (x.f.msw.exponent == 0) {	/* zero or sub */
		if ((x.f.msw.significand == 0) && (x.f.significand2 == 0)) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {	/* subnormal */
			pu->fpclass = fp_normal;
			pu->exponent = 12 - DOUBLE_BIAS;
			pu->significand[0] = x.f.msw.significand;
			_fp_normalize(pu);
			return;
		}
	} else if (x.f.msw.exponent == 0x7ff) {	/* inf or nan */
		if ((x.f.msw.significand == 0) && (x.f.significand2 == 0)) {	/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {	/* nan */
			if ((x.f.msw.significand & 0x80000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {/* signaling */
				pu->fpclass = fp_quiet;
				_fp_set_exception(fp_invalid);
			}
			pu->significand[0] = 0x80000 | x.f.msw.significand;
			_fp_leftshift(pu, 11);
			return;
		}
	}
	(*pu).exponent = x.f.msw.exponent - DOUBLE_BIAS;
	(*pu).fpclass = fp_normal;
	(*pu).significand[0] = 0x100000 | x.f.msw.significand;
	_fp_leftshift(pu, 11);
}

enum fp_class_type
_class_quadruple(quadruple *x)
{
	quadruple_equivalence kluge;
	int             i;

	for (i = 0; i < 4; i++)
#ifdef __STDC__
		kluge.x = *x;
#else
		kluge.x.u[i] = x->u[i];
#endif
	if (kluge.f.msw.exponent == 0) {	/* 0 or sub */
		if ((kluge.f.msw.significand == 0) && (kluge.f.significand2 == 0) && (kluge.f.significand3 == 0) && (kluge.f.significand4 == 0))
			return fp_zero;
		else
			return fp_subnormal;
	} else if (kluge.f.msw.exponent == 0x7fff) {	/* inf or nan */
		if ((kluge.f.msw.significand == 0) && (kluge.f.significand2 == 0) && (kluge.f.significand3 == 0) && (kluge.f.significand4 == 0))
			return fp_infinity;
		else if ((kluge.f.msw.significand & 0xffff) >= 0x8000)
			return fp_quiet;
		else
			return fp_signaling;
	} else
		return fp_normal;
}

void
_unpack_quadruple(unpacked *pu, quadruple *px)
{
	quadruple_equivalence x;
	int             i;

	for (i = 0; i < 4; i++)
#ifdef __STDC__
		x.x = *px;
#else
		x.x.u[i] = px->u[i];
#endif
	(*pu).sign = x.f.msw.sign;
	pu->significand[1] = x.f.significand2;
	pu->significand[2] = x.f.significand3;
	pu->significand[3] = x.f.significand4;
	for (i = 4; i < UNPACKED_SIZE; i++)
		pu->significand[i] = 0;
	if (x.f.msw.exponent == 0) {	/* zero or sub */
		if ((x.f.msw.significand | x.f.significand2 | x.f.significand3 | x.f.significand4) == 0) {	/* zero */
			pu->fpclass = fp_zero;
			goto ret;
		} else {	/* subnormal */
			pu->fpclass = fp_normal;
			pu->exponent = 16 - QUAD_BIAS;
			pu->significand[0] = x.f.msw.significand;
			_fp_normalize(pu);
			goto ret;
		}
	} else if (x.f.msw.exponent == 0x7fff) {	/* inf or nan */
		if ((x.f.msw.significand | x.f.significand2 | x.f.significand3 | x.f.significand4) == 0) {	/* inf */
			pu->fpclass = fp_infinity;
			goto ret;
		} else {	/* nan */
			if ((x.f.msw.significand & 0x8000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {/* signaling */
				pu->fpclass = fp_quiet;
				_fp_set_exception(fp_invalid);
			}
			pu->significand[0] = 0x8000 | x.f.msw.significand;
			_fp_leftshift(pu, 16);
			goto ret;
		}
	}
	(*pu).exponent = x.f.msw.exponent - QUAD_BIAS;
	(*pu).fpclass = fp_normal;
	(*pu).significand[0] = 0x10000 | x.f.msw.significand;
	_fp_leftshift(pu, 15);
ret:
	/*
	 * printf("/n _unpack_quadruple ") ; _display_unpacked(pu);
	 */
	return;
}
