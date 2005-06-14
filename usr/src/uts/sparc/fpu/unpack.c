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
 * Copyright 1987, 2000, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS-4.1 */

/* Unpack procedures for Sparc FPU simulator. */

#include <sys/fpu/fpu_simulator.h>
#include <sys/fpu/globals.h>

static void
unpackint32(
	unpacked	*pu,	/* unpacked result */
	int32_t		x)	/* packed int32_t */
{
	uint_t ux;

	pu->sticky = pu->rounded = 0;
	if (x == 0) {
		pu->sign = 0;
		pu->fpclass = fp_zero;
	} else {
		(*pu).sign = x < 0;
		(*pu).fpclass = fp_normal;
		(*pu).exponent = INTEGER_BIAS;
		if (x < 0) ux = -x; else ux = x;
		(*pu).significand[0] = ux>>15;
		(*pu).significand[1] = (ux&0x7fff)<<17;
		(*pu).significand[2] = 0;
		(*pu).significand[3] = 0;
		fpu_normalize(pu);
	}
}


/*
 * Workaround for bug 4287443--- we have to convince the compiler
 * that unpackint64 isn't a leaf routine.
 */
static void
subroutine(void)
{
}

static void
unpackint64(
	unpacked	*pu,	/* unpacked result */
	int64_t		x)	/* packed int64_t */
{
	union {
		uint64_t ll;
		uint32_t i[2];
	} ux;

	subroutine();

	pu->sticky = pu->rounded = 0;
	if (x == 0) {
		pu->sign = 0;
		pu->fpclass = fp_zero;
	} else {
		(*pu).sign = x < 0;
		(*pu).fpclass = fp_normal;
		(*pu).exponent = LONGLONG_BIAS;
		if (x < 0) ux.ll = -x; else ux.ll = x;
		(*pu).significand[0] = ux.i[0]>>15;
		(*pu).significand[1] = (((ux.i[0]&0x7fff)<<17) | (ux.i[1]>>15));
		(*pu).significand[2] = (ux.i[1]&0x7fff)<<17;
		(*pu).significand[3] = 0;
		fpu_normalize(pu);
	}
}

void
unpacksingle(
	fp_simd_type	*pfpsd,	/* simulator data */
	unpacked	*pu,	/* unpacked result */
	single_type	x)	/* packed single */
{
	uint_t U;

	pu->sticky = pu->rounded = 0;
	U = x.significand;
	(*pu).sign = x.sign;
	pu->significand[1] = 0;
	pu->significand[2] = 0;
	pu->significand[3] = 0;
	if (x.exponent == 0) {				/* zero or sub */
		if (x.significand == 0) {		/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {				/* subnormal */
			pu->fpclass = fp_normal;
			pu->exponent = -SINGLE_BIAS-6;
			pu->significand[0] = U;
			fpu_normalize(pu);
			return;
		}
	} else if (x.exponent == 0xff) {		/* inf or nan */
		if (x.significand == 0) {		/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {				/* nan */
			if ((U & 0x400000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {			/* signaling */
				pu->fpclass = fp_signaling;
				fpu_set_exception(pfpsd, fp_invalid);
			}
			pu->significand[0] = 0x18000 | (U >> 7);
			(*pu).significand[1] = ((U&0x7f)<<25);
			return;
		}
	}
	(*pu).exponent = x.exponent - SINGLE_BIAS;
	(*pu).fpclass = fp_normal;
	(*pu).significand[0] = 0x10000|(U>>7);
	(*pu).significand[1] = ((U&0x7f)<<25);
}

void
unpackdouble(
	fp_simd_type	*pfpsd,	/* simulator data */
	unpacked	*pu,	/* unpacked result */
	double_type	x,	/* packed double, sign/exponent/upper 20 bits */
	uint_t		y)	/* and the lower 32 bits of the significand */
{
	uint_t U;

	pu->sticky = pu->rounded = 0;
	U = x.significand;
	(*pu).sign = x.sign;
	pu->significand[1] = y;
	pu->significand[2] = 0;
	pu->significand[3] = 0;
	if (x.exponent == 0) {				/* zero or sub */
		if ((x.significand == 0) && (y == 0)) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {				/* subnormal */
			pu->fpclass = fp_normal;
			pu->exponent = -DOUBLE_BIAS-3;
			pu->significand[0] = U;
			fpu_normalize(pu);
			return;
		}
	} else if (x.exponent == 0x7ff) {		/* inf or nan */
		if ((U|y) == 0) {			/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {				/* nan */
			if ((U & 0x80000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {			/* signaling */
				pu->fpclass = fp_signaling;
				fpu_set_exception(pfpsd, fp_invalid);
			}
			pu->significand[0] = 0x18000 | (U >> 4);
			(*pu).significand[1] = ((U&0xf)<<28)|(y>>4);
			(*pu).significand[2] = ((y&0xf)<<28);
			return;
		}
	}
	(*pu).exponent = x.exponent - DOUBLE_BIAS;
	(*pu).fpclass = fp_normal;
	(*pu).significand[0] = 0x10000|(U>>4);
	(*pu).significand[1] = ((U&0xf)<<28)|(y>>4);
	(*pu).significand[2] = ((y&0xf)<<28);
}

static void
unpackextended(
	fp_simd_type	*pfpsd,	/* simulator data */
	unpacked	*pu,	/* unpacked result */
	extended_type	x,	/* packed extended, sign/exponent/16 bits */
	uint32_t	y,	/* 2nd word of extended significand */
	uint32_t	z,	/* 3rd word of extended significand */
	uint32_t	w)	/* 4th word of extended significand */
{
	uint_t U;

	pu->sticky = pu->rounded = 0;
	U = x.significand;
	(*pu).sign = x.sign;
	(*pu).fpclass = fp_normal;
	(*pu).exponent = x.exponent - EXTENDED_BIAS;
	(*pu).significand[0] = (x.exponent == 0) ? U : 0x10000|U;
	(*pu).significand[1] = y;
	(*pu).significand[2] = z;
	(*pu).significand[3] = w;
	if (x.exponent < 0x7fff) {	/* zero, normal, or subnormal */
		if ((z|y|w|pu->significand[0]) == 0) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {			/* normal or subnormal */
			if (x.exponent == 0) {
				fpu_normalize(pu);
				pu->exponent += 1;
			}
			return;
		}
	} else {					/* inf or nan */
		if ((U|z|y|w) == 0) {			/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {				/* nan */
			if ((U & 0x00008000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {			/* signaling */
				pu->fpclass = fp_signaling;
				fpu_set_exception(pfpsd, fp_invalid);
			}
			pu->significand[0] |= 0x8000;	/* make quiet */
			return;
		}
	}
}

void
_fp_unpack(
	fp_simd_type	*pfpsd,	/* simulator data */
	unpacked	*pu,	/* unpacked result */
	uint_t		n,	/* register where data starts */
	enum fp_op_type	dtype)	/* type of datum */
{
	freg_type	f;
	union {
		uint32_t	y[4];
		uint64_t	ll[2];
		freg_type	f;
	} fp;

	switch (dtype) {
	case fp_op_int32:
		pfpsd->fp_current_read_freg(&f, n, pfpsd);
		unpackint32(pu, f.int32_reg);
		break;
	case fp_op_int64:

		if ((n & 0x1) == 1)	/* fix register encoding */
			n = (n & 0x1e) | 0x20;
		pfpsd->fp_current_read_dreg(&fp.ll[0], DOUBLE(n), pfpsd);
		unpackint64(pu, fp.f.int64_reg);
		break;
	case fp_op_single:
		pfpsd->fp_current_read_freg(&f, n, pfpsd);
		unpacksingle(pfpsd, pu, f.single_reg);
		break;
	case fp_op_double:
		if ((n & 0x1) == 1)	/* fix register encoding */
			n = (n & 0x1e) | 0x20;
		pfpsd->fp_current_read_dreg(&fp.ll[0], DOUBLE(n), pfpsd);
		unpackdouble(pfpsd, pu, fp.f.double_reg, fp.y[1]);
		break;
	case fp_op_extended:
		if ((n & 0x1) == 1)	/* fix register encoding */
			n = (n & 0x1e) | 0x20;
		pfpsd->fp_current_read_dreg(&fp.ll[0], QUAD_E(n), pfpsd);
		pfpsd->fp_current_read_dreg(&fp.ll[1], QUAD_F(n), pfpsd);
		unpackextended(pfpsd, pu, fp.f.extended_reg, fp.y[1],
					fp.y[2], fp.y[3]);
		break;
	}
}

void
_fp_unpack_word(
	fp_simd_type	*pfpsd,	/* simulator data */
	uint32_t	*pu,	/* unpacked result */
	uint_t		n)	/* register where data starts */
{
	pfpsd->fp_current_read_freg(pu, n, pfpsd);
}

void
_fp_unpack_extword(
	fp_simd_type	*pfpsd,	/* simulator data */
	uint64_t	*pu,	/* unpacked result */
	uint_t		n)	/* register where data starts */
{
	if ((n & 0x1) == 1)	/* fix register encoding */
		n = (n & 0x1e) | 0x20;
	pfpsd->fp_current_read_dreg(pu, DOUBLE(n), pfpsd);
}
