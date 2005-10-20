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

/*
 * Fundamental utilities of base conversion required for sprintf - but too
 * complex or too seldom used to be worth assembly language coding.
 */

/* p = x * y + c ; return (p/10000 << 16 | p%10000) */
unsigned long
_prodc_b10000(_BIG_FLOAT_DIGIT x, _BIG_FLOAT_DIGIT y, unsigned long c)
{
	unsigned long   p = x * (unsigned long) y + c;

	return ((p / 10000) << 16) | (p % 10000);
}

/* p = x * y ; return p */
unsigned long
_prod_b65536(_BIG_FLOAT_DIGIT x, _BIG_FLOAT_DIGIT y)	
{
	return (x * (unsigned long)y);
}

/* p = x * y ; return (p/10000 << 16 | p%10000) */
unsigned long
_prod_b10000(_BIG_FLOAT_DIGIT x, _BIG_FLOAT_DIGIT y)	
{
	unsigned long   p = x * (unsigned long) y;

	return ((p / 10000) << 16) | (p % 10000);
}

/* p = x << n + c ; return (p/10000 << 16 | p%10000) */
unsigned long
_lshift_b10000(_BIG_FLOAT_DIGIT x, short unsigned n, long unsigned c)	
{
	unsigned long   p = (((unsigned long) x) << n) + c;

	return ((p / 10000) << 16) | (p % 10000);
}

/* p = x * 10000 + c ; return p */
unsigned long
_prod_10000_b65536(_BIG_FLOAT_DIGIT x, long unsigned c)
{
	return (x * (unsigned long) 10000 + c);
}

/* p = x << 16 + c ; return (p/10000 << 16 | p%10000) */
unsigned long
_prod_65536_b10000(_BIG_FLOAT_DIGIT x, long unsigned c)	
{
	unsigned long   p = (((unsigned long) x) << 16) + c;

	return ((p / 10000) << 16) | (p % 10000);
}

/* p = c ; return (p/10000 << 16 | p%10000) */
unsigned long
_carry_out_b10000(unsigned long c)
{
	return ((c / 10000) << 16) | (c % 10000);
}

void
_left_shift_base_ten(_big_float *pbf, short unsigned multiplier)
{
	/*
	 * Multiply a base-10**4 significand by 2<<multiplier.  Extend length
	 * as necessary to accommodate carries.
	 */

	short unsigned  length = pbf->blength;
	int             j;
	unsigned long   carry;
	long            p;

	carry = 0;
	for (j = 0; j < length; j++) {
		p = _lshift_b10000((_BIG_FLOAT_DIGIT) pbf->bsignificand[j], multiplier, carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	while (carry != 0) {
		p = _carry_out_b10000(carry);
		pbf->bsignificand[j++] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	pbf->blength = j;
}

void
_left_shift_base_two(_big_float *pbf, short unsigned multiplier)
{
	/*
	 * Multiply a base-2**16 significand by 2<<multiplier.  Extend length
	 * as necessary to accommodate carries.
	 */

	short unsigned  length = pbf->blength;
	long unsigned   p;
	int             j;
	unsigned long   carry;

	carry = 0;
	for (j = 0; j < length; j++) {
		p = _lshift_b65536(pbf->bsignificand[j], multiplier, carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	if (carry != 0) {
		pbf->bsignificand[j++] = (_BIG_FLOAT_DIGIT) (_carry_out_b65536(carry) & 0xffff);
	}
	pbf->blength = j;
}

void
_right_shift_base_two(_big_float *pbf, short unsigned multiplier,
    _BIG_FLOAT_DIGIT *sticky)
{
	/* *pb = *pb / 2**multiplier	to normalize.	15 <= multiplier <= 1 */
	/* Any bits shifted out got to *sticky. */

	long unsigned   p;
	int             j;
	unsigned long   carry;

	carry = 0;
	for (j = pbf->blength - 1; j >= 0; j--) {
		p = _rshift_b65536(pbf->bsignificand[j], multiplier, carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p >> 16);
		carry = p & 0xffff;
	}
	*sticky = (_BIG_FLOAT_DIGIT) carry;
}

void
_multiply_base_ten(_big_float *pbf, _BIG_FLOAT_DIGIT multiplier)
{
	/*
	 * Multiply a base-10**4 significand by multiplier.  Extend length as
	 * necessary to accommodate carries.
	 */

	int             j;
	unsigned long   carry;
	long            p;

	carry = 0;
	for (j = 0; j < pbf->blength; j++) {
		p = _prodc_b10000((_BIG_FLOAT_DIGIT) pbf->bsignificand[j], multiplier, carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	while (carry != 0) {
		p = _carry_out_b10000(carry);
		pbf->bsignificand[j++] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	pbf->blength = j;
}

void
_multiply_base_two(_big_float *pbf, _BIG_FLOAT_DIGIT multiplier,
    long unsigned carry)
{
	/*
	 * Multiply a base-2**16 significand by multiplier.  Extend length as
	 * necessary to accommodate carries.
	 */

	short unsigned  length = pbf->blength;
	long unsigned   p;
	int             j;

	for (j = 0; j < length; j++) {
		p = _prodc_b65536(pbf->bsignificand[j], multiplier, carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	if (carry != 0) {
		pbf->bsignificand[j++] = (_BIG_FLOAT_DIGIT) (_carry_out_b65536(carry) & 0xffff);
	}
	pbf->blength = j;
}

void
_multiply_base_ten_by_two(_big_float *pbf, short unsigned multiplier)
{
	/*
	 * Multiply a base-10**4 significand by 2**multiplier.  Extend length
	 * as necessary to accommodate carries.
	 */

	short unsigned  length = pbf->blength;
	int             j;
	long unsigned   carry, p;

	carry = 0;
	for (j = 0; j < length; j++) {
		p = _lshift_b10000(pbf->bsignificand[j], multiplier, carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	while (carry != 0) {
		p = _carry_out_b10000(carry);
		pbf->bsignificand[j++] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	pbf->blength = j;
}

void
_unpacked_to_big_float(unpacked *pu, _big_float *pb, int *pe)
{
	/*
	 * Converts pu into a bigfloat *pb of minimal length; exponent *pe
	 * such that pu = *pb * 2 ** *pe
	 */

	int             iz, it;

	for (iz = (UNPACKED_SIZE - 2); pu->significand[iz] == 0; iz--);	/* Find lsw. */

	for (it = 0; it <= iz; it++) {
		pb->bsignificand[2 * (iz - it)] = pu->significand[it] & 0xffff;
		pb->bsignificand[2 * (iz - it) + 1] = pu->significand[it] >> 16;
	}

	pb->blength = 2 * iz + 2;
	if (pb->bsignificand[0] == 0) {
		for (it = 1; it < pb->blength; it++)
			pb->bsignificand[it - 1] = pb->bsignificand[it];
		pb->blength--;
	}
	*pe = pu->exponent + 1 - 16 * pb->blength;
	pb->bexponent = 0;

#ifdef DEBUG
	printf(" unpacked to big float 2**%d * ", *pe);
	_display_big_float(pb, 2);
#endif
}

void
_mul_65536short(_big_float *pbf, unsigned long carry)
{
	/* *pbf *= 65536 ; += carry ; */

	long unsigned   p;
	int             j;

	for (j = 0; j < pbf->blength; j++) {
		p = _prod_65536_b10000(pbf->bsignificand[j], carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	while (carry != 0) {
		p = _carry_out_b10000(carry);
		pbf->bsignificand[j++] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	pbf->blength = j;
}

void
_big_binary_to_big_decimal(_big_float *pb, _big_float *pd)
{
	/* Convert _big_float from binary form to decimal form. */

	int             i;

	pd->bsignificand[0] = pb->bsignificand[pb->blength - 1] % 10000;
	if (pd->bsignificand[0] == pb->bsignificand[pb->blength - 1]) {
		pd->blength = 1;
	} else {
		pd->blength = 2;
		pd->bsignificand[1] = pb->bsignificand[pb->blength - 1] / 10000;
	}
	for (i = pb->blength - 2; i >= 0; i--) {	/* Multiply by 2**16 and
							 * add next significand. */
		_mul_65536short(pd, (unsigned long) pb->bsignificand[i]);
	}
	for (i = 0; i <= (pb->bexponent - 16); i += 16) {	/* Multiply by 2**16 for
								 * each trailing zero. */
		_mul_65536short(pd, (unsigned long) 0);
	}
	if (pb->bexponent > i)
		_left_shift_base_ten(pd, (short unsigned) (pb->bexponent - i));
	pd->bexponent = 0;

#ifdef DEBUG
	printf(" _big_binary_to_big_decimal ");
	_display_big_float(pd, 10);
#endif
}
