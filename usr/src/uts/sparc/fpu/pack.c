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
 * Copyright 1988,1995-1996,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Pack procedures for Sparc FPU simulator. */

#include <sys/fpu/fpu_simulator.h>
#include <sys/fpu/globals.h>

/*
 * Returns 1 if overflow should go to infinity, 0 if to max finite.
 */
static int
overflow_to_infinity(
	fp_simd_type	*pfpsd,		/* Pointer to simulator data */
	int		sign)		/* negative or positive */
{
	int		inf;

	switch (pfpsd->fp_direction) {
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

/*
 * Round according to current rounding mode.
 */
static void
round(
	fp_simd_type	*pfpsd,		/* Pointer to simulator data */
	unpacked	*pu)		/* unpacked result */
{
	int		increment;	/* boolean to indicate round up */
	int		sr;

	sr = pu->sticky|pu->rounded;

	if (sr == 0)
		return;
	fpu_set_exception(pfpsd, fp_inexact);
	switch (pfpsd->fp_direction) {
	case fp_nearest:
		increment = pu->rounded;
		break;
	case fp_tozero:
		increment = 0;
		break;
	case fp_positive:
		increment = (pu->sign == 0) & (sr != 0);
		break;
	case fp_negative:
		increment = (pu->sign != 0) & (sr != 0);
		break;
	}
	if (increment) {
	    pu->significand[3]++;
	    if (pu->significand[3] == 0) {
		pu->significand[2]++;
		if (pu->significand[2] == 0) {
		    pu->significand[1]++;
		    if (pu->significand[1] == 0) {
			pu->significand[0]++;	/* rounding carried out */
			if (pu->significand[0] == 0x20000) {
			    pu->exponent++;
			    pu->significand[0] = 0x10000;
			}
		    }
		}
	    }
	}
	if ((pfpsd->fp_direction == fp_nearest) &&
	    (pu->sticky == 0) && increment != 0) {	/* ambiguous case */
		pu->significand[3] &= 0xfffffffe; /* force round to even */
	}
}

static void
packint32(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	unpacked	*pu,	/* unpacked result */
	int32_t		*px)	/* packed int32_t */
{
	switch (pu->fpclass) {
	case fp_zero:
		*px = 0;
		break;
	case fp_normal:
		if (pu->exponent >= 32)
			goto overflow;
		fpu_rightshift(pu, 112 - pu->exponent);
		round(pfpsd, pu);
		if (pu->significand[3] >= 0x80000000)
			if ((pu->sign == 0)||(pu->significand[3] > 0x80000000))
				goto overflow;
		*px = pu->significand[3];
		if (pu->sign)
			*px = -*px;
		break;
	case fp_infinity:
	case fp_quiet:
	case fp_signaling:
overflow:
		if (pu->sign)
			*px = 0x80000000;
		else
			*px = 0x7fffffff;
		pfpsd->fp_current_exceptions &= ~(1 << (int)fp_inexact);
		fpu_set_exception(pfpsd, fp_invalid);
		break;
	}
}

static void
packint64(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	unpacked	*pu,	/* unpacked result */
	int64_t		*px)	/* packed int64_t */
{
	union {
		uint64_t ll;
		uint32_t i[2];
	} x;

	switch (pu->fpclass) {
	case fp_zero:
		*px = 0;
		break;
	case fp_normal:
		if (pu->exponent >= 64)
			goto overflow;
		fpu_rightshift(pu, 112 - pu->exponent);
		round(pfpsd, pu);
		if (pu->significand[2] >= 0x80000000)
			if ((pu->sign == 0) ||
			    (pu->significand[2] > 0x80000000) ||
			    (((pu->significand[2] == 0x80000000) &&
				(pu->significand[3] > 0))))
				goto overflow;
		x.i[0] = pu->significand[2];
		x.i[1] = pu->significand[3];
		*px = x.ll;
		if (pu->sign)
			*px = -*px;
		break;
	case fp_infinity:
	case fp_quiet:
	case fp_signaling:
overflow:
		if (pu->sign)
			*px = (int64_t)0x8000000000000000;
		else
			*px = (int64_t)0x7fffffffffffffff;
		pfpsd->fp_current_exceptions &= ~(1 << (int)fp_inexact);
		fpu_set_exception(pfpsd, fp_invalid);
		break;
	}
}

static void
packsingle(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	unpacked	*pu,	/* unpacked result */
	single_type	*px)	/* packed single */
{
	px->sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		px->exponent = 0;
		px->significand = 0;
		break;
	case fp_infinity:
infinity:
		px->exponent = 0xff;
		px->significand = 0;
		break;
	case fp_quiet:
	case fp_signaling:
		fpu_rightshift(pu, 113-24);
		px->exponent = 0xff;
		px->significand = 0x400000|(0x3fffff&pu->significand[3]);
		break;
	case fp_normal:
		fpu_rightshift(pu, 113-24);
		pu->exponent += SINGLE_BIAS;
		if (pu->exponent <= 0) {
			px->exponent = 0;
			fpu_rightshift(pu, 1 - pu->exponent);
			round(pfpsd, pu);
			if (pu->significand[3] == 0x800000) {
								/*
								 * rounded
								 * back up to
								 * normal
								 */
				px->exponent = 1;
				px->significand = 0;
				fpu_set_exception(pfpsd, fp_inexact);
			} else
				px->significand = 0x7fffff & pu->significand[3];

			if (pfpsd->fp_current_exceptions & (1 << fp_inexact))
				fpu_set_exception(pfpsd, fp_underflow);
			if (pfpsd->fp_fsrtem & (1<<fp_underflow)) {
				fpu_set_exception(pfpsd, fp_underflow);
				pfpsd->fp_current_exceptions &=
						~(1 << (int)fp_inexact);
			}
			return;
		}
		round(pfpsd, pu);
		if (pu->significand[3] == 0x1000000) {	/* rounding overflow */
			pu->significand[3] = 0x800000;
			pu->exponent += 1;
		}
		if (pu->exponent >= 0xff) {
			fpu_set_exception(pfpsd, fp_overflow);
			fpu_set_exception(pfpsd, fp_inexact);
			if (pfpsd->fp_fsrtem & (1<<fp_overflow)) {
				pfpsd->fp_current_exceptions &=
						~(1 << (int)fp_inexact);
			}
			if (overflow_to_infinity(pfpsd, pu->sign))
				goto infinity;
			px->exponent = 0xfe;
			px->significand = 0x7fffff;
			return;
		}
		px->exponent = pu->exponent;
		px->significand = 0x7fffff & pu->significand[3];
	}
}

static void
packdouble(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	unpacked	*pu,	/* unpacked result */
	double_type	*px,	/* packed double, sign/exponent/upper 20 bits */
	uint_t		*py)	/* and the lower 32 bits of the significand */
{
	px->sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		px->exponent = 0;
		px->significand = 0;
		*py = 0;
		break;
	case fp_infinity:
infinity:
		px->exponent = 0x7ff;
		px->significand = 0;
		*py = 0;
		break;
	case fp_quiet:
	case fp_signaling:
		fpu_rightshift(pu, 113-53);
		px->exponent = 0x7ff;
		px->significand = 0x80000 | (0x7ffff & pu->significand[2]);
		*py = pu->significand[3];
		break;
	case fp_normal:
		fpu_rightshift(pu, 113-53);
		pu->exponent += DOUBLE_BIAS;
		if (pu->exponent <= 0) {	/* underflow */
			px->exponent = 0;
			fpu_rightshift(pu, 1 - pu->exponent);
			round(pfpsd, pu);
			if (pu->significand[2] == 0x100000) {
								/*
								 * rounded
								 * back up to
								 * normal
								 */
				px->exponent = 1;
				px->significand = 0;
				*py = 0;
				fpu_set_exception(pfpsd, fp_inexact);
			} else {
				px->exponent = 0;
				px->significand = 0xfffff & pu->significand[2];
				*py = pu->significand[3];
			}
			if (pfpsd->fp_current_exceptions & (1 << fp_inexact))
				fpu_set_exception(pfpsd, fp_underflow);
			if (pfpsd->fp_fsrtem & (1<<fp_underflow)) {
				fpu_set_exception(pfpsd, fp_underflow);
				pfpsd->fp_current_exceptions &=
						~(1 << (int)fp_inexact);
			}
			return;
		}
		round(pfpsd, pu);
		if (pu->significand[2] == 0x200000) {	/* rounding overflow */
			pu->significand[2] = 0x100000;
			pu->exponent += 1;
		}
		if (pu->exponent >= 0x7ff) {	/* overflow */
			fpu_set_exception(pfpsd, fp_overflow);
			fpu_set_exception(pfpsd, fp_inexact);
			if (pfpsd->fp_fsrtem & (1<<fp_overflow)) {
				pfpsd->fp_current_exceptions &=
						~(1 << (int)fp_inexact);
			}
			if (overflow_to_infinity(pfpsd, pu->sign))
				goto infinity;
			px->exponent = 0x7fe;
			px->significand = 0xfffff;
			*py = 0xffffffffU;
			return;
		}
		px->exponent = pu->exponent;
		px->significand = 0xfffff & pu->significand[2];
		*py = pu->significand[3];
		break;
	}
}

static void
packextended(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	unpacked	*pu,	/* unpacked result */
	extended_type	*px,	/* packed extended, sign/exponent/16 bits */
	uint_t		*py,	/* 2nd word of extended significand */
	uint_t		*pz,	/* 3rd word of extended significand */
	uint_t		*pw)	/* 4th word of extended significand */
{
	px->sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		px->exponent = 0;
		px->significand = 0;
		*pz = 0;
		*py = 0;
		*pw = 0;
		break;
	case fp_infinity:
infinity:
		px->exponent = 0x7fff;
		px->significand = 0;
		*pz = 0;
		*py = 0;
		*pw = 0;
		break;
	case fp_quiet:
	case fp_signaling:
		px->exponent = 0x7fff;
		px->significand = 0x8000 | pu->significand[0];
								/*
								 * Insure quiet
								 * nan.
								 */
		*py = pu->significand[1];
		*pz = pu->significand[2];
		*pw = pu->significand[3];
		break;
	case fp_normal:
		pu->exponent += EXTENDED_BIAS;
		if (pu->exponent <= 0) {	/* underflow */
			fpu_rightshift(pu, 1-pu->exponent);
			round(pfpsd, pu);
			if (pu->significand[0] < 0x00010000) {
								/*
								 * not rounded
								 * back up
								 * to normal
								 */
				px->exponent = 0;
			} else {
				px->exponent = 1;
				fpu_set_exception(pfpsd, fp_inexact);
			}
			if (pfpsd->fp_current_exceptions & (1 << fp_inexact))
				fpu_set_exception(pfpsd, fp_underflow);
			if (pfpsd->fp_fsrtem & (1<<fp_underflow)) {
				fpu_set_exception(pfpsd, fp_underflow);
				pfpsd->fp_current_exceptions &=
						~(1 << (int)fp_inexact);
			}
			px->significand = pu->significand[0];
			*py = pu->significand[1];
			*pz = pu->significand[2];
			*pw = pu->significand[3];
			return;
		}
		round(pfpsd, pu); /* rounding overflow handled in round() */
		if (pu->exponent >= 0x7fff) {	/* overflow */
			fpu_set_exception(pfpsd, fp_overflow);
			fpu_set_exception(pfpsd, fp_inexact);
			if (pfpsd->fp_fsrtem & (1<<fp_overflow)) {
				pfpsd->fp_current_exceptions &=
						~(1 << (int)fp_inexact);
			}
			if (overflow_to_infinity(pfpsd, pu->sign))
				goto infinity;
			px->exponent = 0x7ffe;	/* overflow to max norm */
			px->significand = 0xffff;
			*py = 0xffffffffU;
			*pz = 0xffffffffU;
			*pw = 0xffffffffU;
			return;
		}
		px->exponent = pu->exponent;
		px->significand = pu->significand[0];
		*py = pu->significand[1];
		*pz = pu->significand[2];
		*pw = pu->significand[3];
		break;
	}
}

void
_fp_pack(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	unpacked	*pu,	/* unpacked operand */
	uint_t		n,	/* register where datum starts */
	enum fp_op_type type)	/* type of datum */

{
	switch (type) {
	case fp_op_int32:
		{
			int32_t		x;

			packint32(pfpsd, pu, &x);
			if (!(pfpsd->fp_current_exceptions & pfpsd->fp_fsrtem))
				pfpsd->fp_current_write_freg(&x, n, pfpsd);
			break;
		}
	case fp_op_int64:
		{
			int64_t		x;

			packint64(pfpsd, pu, &x);
			if ((n & 0x1) == 1)	/* fix register encoding */
				n = (n & 0x1e) | 0x20;
			if (!(pfpsd->fp_current_exceptions & pfpsd->fp_fsrtem))
			    pfpsd->fp_current_write_dreg(&x, DOUBLE(n), pfpsd);
			break;
		}
	case fp_op_single:
		{
			single_type	x;

			packsingle(pfpsd, pu, &x);
			if (!(pfpsd->fp_current_exceptions & pfpsd->fp_fsrtem))
				pfpsd->fp_current_write_freg(&x, n, pfpsd);
			break;
		}
	case fp_op_double:
		{
			union {
				double_type	x[2];
				uint32_t	y[2];
				uint64_t	ll;
			} db;

			packdouble(pfpsd, pu, &db.x[0], &db.y[1]);
			if (!(pfpsd->fp_current_exceptions &
			    pfpsd->fp_fsrtem)) {
				if ((n & 0x1) == 1) /* fix register encoding */
					n = (n & 0x1e) | 0x20;
				pfpsd->fp_current_write_dreg(&db.ll, DOUBLE(n),
					pfpsd);
			}
			break;
		}
	case fp_op_extended:
		{
			union {
				extended_type	x;
				uint32_t	y[4];
				uint64_t	ll[2];
			} ex;
			unpacked	U;
			int		k;
			switch (pfpsd->fp_precision) {
							/*
							 * Implement extended
							 * rounding precision
							 * mode.
							 */
			case fp_single:
				{
					single_type	tx;

					packsingle(pfpsd, pu, &tx);
					pu = &U;
					unpacksingle(pfpsd, pu, tx);
					break;
				}
			case fp_double:
				{
					double_type	tx;
					uint_t		ty;

					packdouble(pfpsd, pu, &tx, &ty);
					pu = &U;
					unpackdouble(pfpsd, pu, tx, ty);
					break;
				}
			case fp_precision_3:	/* rounded to 64 bits */
				{
					k = pu->exponent + EXTENDED_BIAS;
					if (k >= 0) k = 113-64;
					else	k = 113-64-k;
					fpu_rightshift(pu, 113-64);
					round(pfpsd, pu);
					pu->sticky = pu->rounded = 0;
					pu->exponent += k;
					fpu_normalize(pu);
					break;
				}
			}
			packextended(pfpsd, pu, &ex.x, &ex.y[1],
						&ex.y[2], &ex.y[3]);
			if (!(pfpsd->fp_current_exceptions &
			    pfpsd->fp_fsrtem)) {
				if ((n & 0x1) == 1) /* fix register encoding */
					n = (n & 0x1e) | 0x20;
				pfpsd->fp_current_write_dreg(&ex.ll[0],
							QUAD_E(n), pfpsd);
				pfpsd->fp_current_write_dreg(&ex.ll[1],
							QUAD_F(n), pfpsd);
			}

			break;
		}
	}
}

void
_fp_pack_word(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	uint32_t	*pu,	/* unpacked operand */
	uint_t		n)	/* register where datum starts */
{
	pfpsd->fp_current_write_freg(pu, n, pfpsd);
}

void
_fp_pack_extword(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	uint64_t	*pu,	/* unpacked operand */
	uint_t		n)	/* register where datum starts */
{
	if ((n & 1) == 1)	/* fix register encoding */
		n = (n & 0x1e) | 0x20;
	pfpsd->fp_current_write_dreg(pu, DOUBLE(n), pfpsd);
}
