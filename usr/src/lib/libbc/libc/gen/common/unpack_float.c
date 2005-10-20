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

/* IEEE function implementations.	 */

#include "base_conversion.h"

enum fp_class_type
_class_single(single *x)
{
	single_equivalence kluge;

	kluge.x = *x;
	if (kluge.f.msw.exponent == 0) {	/* 0 or sub */
		if (kluge.f.msw.significand == 0)
			return fp_zero;
		else
			return fp_subnormal;
	} else if (kluge.f.msw.exponent == 0xff) {	/* inf or nan */
		if (kluge.f.msw.significand == 0)
			return fp_infinity;
		else if (kluge.f.msw.significand >= 0x400000)
			return fp_quiet;
		else
			return fp_signaling;
	} else
		return fp_normal;
}

enum fp_class_type
_class_extended(extended *x)
{
	extended_equivalence kluge;

	kluge.x[0] = (*x)[0];
	kluge.x[1] = (*x)[1];
	kluge.x[2] = (*x)[2];
	if (kluge.f.msw.exponent == 0) {	/* 0 or sub */
		if ((kluge.f.significand == 0) && (kluge.f.significand2 == 0))
			return fp_zero;
		else
			return fp_subnormal;
	} else if (kluge.f.msw.exponent == 0x7fff) {	/* inf or nan */
		if (((kluge.f.significand & 0x7fffffff) == 0) && (kluge.f.significand2 == 0))
			return fp_infinity;
		else if ((kluge.f.significand & 0x7fffffff) >= 0x40000000)
			return fp_quiet;
		else
			return fp_signaling;
	} else
		return fp_normal;
}

void
_unpack_single(unpacked *pu, single *px)
{
	single_equivalence x;
	int             i;

	x.x = *px;
	(*pu).sign = x.f.msw.sign;
	for (i = 1; i < UNPACKED_SIZE; i++)
		pu->significand[i] = 0;
	if (x.f.msw.exponent == 0) {	/* zero or sub */
		if (x.f.msw.significand == 0) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {	/* subnormal */
			pu->fpclass = fp_normal;
			pu->exponent = -SINGLE_BIAS;
			pu->significand[0] = x.f.msw.significand << 9;
			_fp_normalize(pu);
			return;
		}
	} else if (x.f.msw.exponent == 0xff) {	/* inf or nan */
		if (x.f.msw.significand == 0) {	/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {	/* nan */
			if ((x.f.msw.significand & 0x400000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {/* signaling */
				pu->fpclass = fp_quiet;
				_fp_set_exception(fp_invalid);
			}
			pu->significand[0] = 0x40000000 | (x.f.msw.significand << 8);
			return;
		}
	}
	(*pu).exponent = x.f.msw.exponent - SINGLE_BIAS;
	(*pu).fpclass = fp_normal;
	(*pu).significand[0] = 0x80000000 | (x.f.msw.significand << 8);
}

void
_unpack_extended(unpacked *pu, extended *px)
{
	extended_equivalence x;
	int             i;

	x.x[0] = (*px)[0];
	x.x[1] = (*px)[1];
	x.x[2] = (*px)[2];
	pu->sign = x.f.msw.sign;
	pu->fpclass = fp_normal;
	pu->exponent = x.f.msw.exponent - EXTENDED_BIAS;
	pu->significand[0] = x.f.significand;
	pu->significand[1] = x.f.significand2;
	for (i = 2; i < UNPACKED_SIZE; i++)
		pu->significand[i] = 0;
	if (x.f.msw.exponent == 0x7fff) {	/* inf or nan */
		if (((x.f.significand & 0x7fffffff) == 0) && (x.f.significand2 == 0)) {	/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {	/* nan */
			if ((x.f.significand & 0x40000000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {/* signaling */
				pu->fpclass = fp_quiet;
				_fp_set_exception(fp_invalid);
			}
			return;
		}
	}
	if (x.f.significand < 0x80000000) {	/* zero or unnormal */
		if ((x.f.significand == 0) && (x.f.significand2 == 0)) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {	/* unnormal */
			pu->fpclass = fp_normal;
			_fp_normalize(pu);
			return;
		}
	}
}

void
_display_unpacked(unpacked *pu)
{
	int             i, e;

	(void) printf(" unpacked ");
	if (pu->sign == 1)
		(void) printf("-");
	else
		(void) printf("+");
	switch (pu->fpclass) {
	case fp_zero:
		(void) printf("0");
		break;
	case fp_infinity:
		(void) printf("Infinity");
		break;
	case fp_quiet:
		(void) printf("NaN(quiet)");
		break;
	case fp_signaling:
		(void) printf("NaN(signaling)");
		break;
	case fp_subnormal:
	case fp_normal:
		e = 1 + pu->exponent;
		for (i = 0; i < UNPACKED_SIZE; i++) {
			e -= 32;
			(void) printf(" %8X *2**%d + ", pu->significand[i], e);
		}
	}
	(void) printf("\n");
}
