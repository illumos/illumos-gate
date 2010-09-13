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
 * Copyright (c) 1988-1995, by Sun Microsystems, Inc.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "base_conversion.h"

void
_fp_rightshift(pu, n)
	unpacked       *pu;
	int             n;

/* Right shift significand sticky by n bits.  */

{
	int             i;

	if (n >= (32 * UNPACKED_SIZE)) {	/* drastic */
		for (i = 0; (pu->significand[i] == 0) && (i < UNPACKED_SIZE); i++);
		if (i >= UNPACKED_SIZE) {
			pu->fpclass = fp_zero;
			return;
		} else {
			for (i = 0; i < (UNPACKED_SIZE - 1); i++)
				pu->significand[i] = 0;
			pu->significand[UNPACKED_SIZE - 1] = 1;
			return;
		}
	}
	while (n >= 32) {	/* big shift */
		if (pu->significand[UNPACKED_SIZE - 1] != 0)
			pu->significand[UNPACKED_SIZE - 2] |= 1;
		for (i = UNPACKED_SIZE - 2; i >= 0; i--)
			pu->significand[i + 1] = pu->significand[i];
		pu->significand[0] = 0;
		n -= 32;
	}
	if (n >= 1) {		/* small shift */
		unsigned long   high, low, shiftout = 0;
		for (i = 0; i < UNPACKED_SIZE; i++) {
			high = pu->significand[i] >> n;
			low = pu->significand[i] << (32 - n);
			pu->significand[i] = shiftout | high;
			shiftout = low;
		}
		if (shiftout != 0)
			pu->significand[UNPACKED_SIZE - 1] |= 1;
	}
}

PRIVATE int
overflow_to_infinity(sign)
	int             sign;

/* Returns 1 if overflow should go to infinity, 0 if to max finite. */

{
	int             inf;

	switch (_fp_current_direction) {
	case fp_nearest:
		inf = 1;
		break;
	case fp_tozero:
		inf = 0;
		break;
	case fp_positive:
		inf = !sign;
		break;
	case fp_negative:
		inf = sign;
		break;
	}
	return (inf);
}

PRIVATE void
round(pu, roundword)
	unpacked       *pu;

/*
 * Round according to current rounding mode. pu must be shifted to so that
 * the roundbit is pu->significand[roundword] & 0x80000000
 */

{
	int             increment;	/* boolean to indicate round up */
	int             is;
	unsigned	msw;		/* msw before increment */

	for (is = (roundword + 1); is < UNPACKED_SIZE; is++)
		if (pu->significand[is] != 0) {	/* Condense extra bits into
						 * sticky bottom of
						 * roundword. */
			pu->significand[roundword] |= 1;
			break;
		}
	if (pu->significand[roundword] == 0)
		return;
	_fp_set_exception(fp_inexact);
	switch (_fp_current_direction) {
	case fp_nearest:
		increment = pu->significand[roundword] >= 0x80000000;
		break;
	case fp_tozero:
		increment = 0;
		break;
	case fp_positive:
		increment = (pu->sign == 0) & (pu->significand[roundword] != 0);
		break;
	case fp_negative:
		increment = (pu->sign != 0) & (pu->significand[roundword] != 0);
		break;
	}
	if (increment) {
		msw=pu->significand[0];		/* save msw before round */
		is = roundword;
		do {
			is--;
			pu->significand[is]++;
		}
		while ((pu->significand[is] == 0) && (is > 0));
		if (pu->significand[0] < msw) {	/* rounding carried out */
			pu->exponent++;
			pu->significand[0] = 0x80000000;
		}
	}
	if ((_fp_current_direction == fp_nearest) && (pu->significand[roundword] == 0x80000000)) {	/* ambiguous case */
		pu->significand[roundword - 1] &= ~1;	/* force round to even */
	}
}

void
_pack_single(pu, px)
	unpacked       *pu;	/* unpacked result */
	single         *px;	/* packed single */
{
	single_equivalence kluge;

	kluge.f.msw.sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		break;
	case fp_infinity:
infinity:
		kluge.f.msw.exponent = 0xff;
		kluge.f.msw.significand = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0xff;
		kluge.f.msw.significand = 0x400000 | (0x3fffff & (pu->significand[0] >> 8));
		break;
	case fp_normal:
		_fp_rightshift(pu, 8);
		pu->exponent += SINGLE_BIAS;
		if (pu->exponent <= 0) {
			kluge.f.msw.exponent = 0;
			_fp_rightshift(pu, 1 - pu->exponent);
			round(pu, 1);
			if (pu->significand[0] == 0x800000) {	/* rounded back up to
								 * normal */
				kluge.f.msw.exponent = 1;
				kluge.f.msw.significand = 0;
				_fp_set_exception(fp_underflow);
				goto ret;
			}
			if (_fp_current_exceptions & (1 << fp_inexact))
				_fp_set_exception(fp_underflow);
			kluge.f.msw.significand = 0x7fffff & pu->significand[0];
			goto ret;
		}
		round(pu, 1);
		if (pu->significand[0] == 0x1000000) {	/* rounding overflow */
			pu->significand[0] = 0x800000;
			pu->exponent += 1;
		}
		if (pu->exponent >= 0xff) {
			_fp_set_exception(fp_overflow);
			_fp_set_exception(fp_inexact);
			if (overflow_to_infinity(pu->sign))
				goto infinity;
			kluge.f.msw.exponent = 0xfe;
			kluge.f.msw.significand = 0x7fffff;
			goto ret;
		}
		kluge.f.msw.exponent = pu->exponent;
		kluge.f.msw.significand = 0x7fffff & pu->significand[0];
	}
ret:
	*px = kluge.x;
}

void
_pack_double(pu, px)
	unpacked       *pu;	/* unpacked result */
	double         *px;	/* packed double */
{
	double_equivalence kluge;

	kluge.f.msw.sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_infinity:
infinity:
		kluge.f.msw.exponent = 0x7ff;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0x7ff;
		_fp_rightshift(pu, 11);
		kluge.f.msw.significand = 0x80000 | (0x7ffff & pu->significand[0]);
		kluge.f.significand2 = pu->significand[1];
		break;
	case fp_normal:
		_fp_rightshift(pu, 11);
		pu->exponent += DOUBLE_BIAS;
		if (pu->exponent <= 0) {	/* underflow */
			kluge.f.msw.exponent = 0;
			_fp_rightshift(pu, 1 - pu->exponent);
			round(pu, 2);
			if (pu->significand[0] == 0x100000) {	/* rounded back up to
								 * normal */
				kluge.f.msw.exponent = 1;
				kluge.f.msw.significand = 0;
				kluge.f.significand2 = 0;
				_fp_set_exception(fp_underflow);
				goto ret;
			}
			if (_fp_current_exceptions & (1 << fp_inexact))
				_fp_set_exception(fp_underflow);
			kluge.f.msw.exponent = 0;
			kluge.f.msw.significand = 0xfffff & pu->significand[0];
			kluge.f.significand2 = pu->significand[1];
			goto ret;
		}
		round(pu, 2);
		if (pu->significand[0] == 0x200000) {	/* rounding overflow */
			pu->significand[0] = 0x100000;
			pu->exponent += 1;
		}
		if (pu->exponent >= 0x7ff) {	/* overflow */
			_fp_set_exception(fp_overflow);
			_fp_set_exception(fp_inexact);
			if (overflow_to_infinity(pu->sign))
				goto infinity;
			kluge.f.msw.exponent = 0x7fe;
			kluge.f.msw.significand = 0xfffff;
			kluge.f.significand2 = 0xffffffff;
			goto ret;
		}
		kluge.f.msw.exponent = pu->exponent;
		kluge.f.msw.significand = 0xfffff & pu->significand[0];
		kluge.f.significand2 = pu->significand[1];
		break;
	}
ret:
	*px = kluge.x;
}

void
_pack_extended(pu, px)
	unpacked       *pu;	/* unpacked result */
	extended       *px;	/* packed extended */
{
	extended_equivalence kluge;

	kluge.f.msw.sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_infinity:
infinity:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.significand = 0x40000000 | (0x7fffffff & pu->significand[0]);
		kluge.f.significand2 = pu->significand[1];
		break;
	case fp_normal:
		switch (_fp_current_precision) {
		case fp_single:
			{
				single          s;
				_pack_single(pu, &s);
				_unpack_single(pu, &s);
				break;
			}
		case fp_double:
			{
				double          s;
				_pack_double(pu, &s);
				_unpack_double(pu, &s);
				break;
			}
		}
		pu->exponent += EXTENDED_BIAS;
		if (pu->exponent <= 0) {	/* underflow */
			kluge.f.msw.exponent = 0;
			_fp_rightshift(pu, -pu->exponent);
			round(pu, 2);
			if (_fp_current_exceptions & (1 << fp_inexact))
				_fp_set_exception(fp_underflow);
			kluge.f.msw.exponent = 0;
			kluge.f.significand = pu->significand[0];
			kluge.f.significand2 = pu->significand[1];
			goto ret;
		}
		round(pu, 2);
		if (pu->exponent >= 0x7fff) {	/* overflow */
			_fp_set_exception(fp_overflow);
			_fp_set_exception(fp_inexact);
			if (overflow_to_infinity(pu->sign))
				goto infinity;
			kluge.f.msw.exponent = 0x7ffe;
			kluge.f.significand = 0xffffffff;
			kluge.f.significand2 = 0xffffffff;
			goto ret;
		}
		kluge.f.msw.exponent = pu->exponent;
		kluge.f.significand = pu->significand[0];
		kluge.f.significand2 = pu->significand[1];
		break;
	}
ret:
	(*px)[0] = kluge.x[0];
	(*px)[1] = kluge.x[1];
	(*px)[2] = kluge.x[2];
}

void
_pack_quadruple(pu, px)
	unpacked       *pu;	/* unpacked result */
	quadruple      *px;	/* packed quadruple */
{
	quadruple_equivalence kluge;
	int             i;

	kluge.f.msw.sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		kluge.f.significand3 = 0;
		kluge.f.significand4 = 0;
		break;
	case fp_infinity:
infinity:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		kluge.f.significand3 = 0;
		kluge.f.significand4 = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0x7fff;
		_fp_rightshift(pu, 15);
		kluge.f.msw.significand = 0x8000 | (0xffff & pu->significand[0]);
		kluge.f.significand2 = pu->significand[1];
		kluge.f.significand3 = pu->significand[2];
		kluge.f.significand4 = pu->significand[3];
		break;
	case fp_normal:
		_fp_rightshift(pu, 15);
		pu->exponent += QUAD_BIAS;
		if (pu->exponent <= 0) {	/* underflow */
			kluge.f.msw.exponent = 0;
			_fp_rightshift(pu, 1 - pu->exponent);
			round(pu, 4);
			if (pu->significand[0] == 0x10000) {	/* rounded back up to
								 * normal */
				kluge.f.msw.exponent = 1;
				kluge.f.msw.significand = 0;
				kluge.f.significand2 = 0;
				kluge.f.significand3 = 0;
				kluge.f.significand4 = 0;
				_fp_set_exception(fp_underflow);
				goto ret;
			}
			if (_fp_current_exceptions & (1 << fp_inexact))
				_fp_set_exception(fp_underflow);
			kluge.f.msw.exponent = 0;
			kluge.f.msw.significand = 0xffff & pu->significand[0];
			kluge.f.significand2 = pu->significand[1];
			kluge.f.significand3 = pu->significand[2];
			kluge.f.significand4 = pu->significand[3];
			goto ret;
		}
		round(pu, 4);
		if (pu->significand[0] == 0x20000) {	/* rounding overflow */
			pu->significand[0] = 0x10000;
			pu->exponent += 1;
		}
		if (pu->exponent >= 0x7fff) {	/* overflow */
			_fp_set_exception(fp_overflow);
			_fp_set_exception(fp_inexact);
			if (overflow_to_infinity(pu->sign))
				goto infinity;
			kluge.f.msw.exponent = 0x7ffe;
			kluge.f.msw.significand = 0xffff;
			kluge.f.significand2 = 0xffffffff;
			kluge.f.significand3 = 0xffffffff;
			kluge.f.significand4 = 0xffffffff;
			goto ret;
		}
		kluge.f.msw.exponent = pu->exponent;
		kluge.f.msw.significand = pu->significand[0] & 0xffff;
		kluge.f.significand2 = pu->significand[1];
		kluge.f.significand3 = pu->significand[2];
		kluge.f.significand4 = pu->significand[3];
		break;
	}
ret:
#ifdef __STDC__
	*px = kluge.x;
#else
	for (i = 0; i < 4; i++)
		px->u[i] = kluge.x.u[i];
#endif
}
