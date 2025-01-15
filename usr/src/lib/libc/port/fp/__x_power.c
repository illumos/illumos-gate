/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include "base_conversion.h"
#include <sys/types.h>
#include <malloc.h>
#include <memory.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Multiply a _big_float by a power of two or ten
 */

/* see comment in double_decim.c */
static unsigned int
__quorem10000(unsigned int x, unsigned short *pr)
{
	*pr = x % 10000;
	return (x / 10000);
}

/*
 * Multiply a base-2**16 significand by multiplier.  Extend length as
 * necessary to accommodate carries.
 */
static void
__multiply_base_two(_big_float *pbf, unsigned short multiplier)
{
	unsigned int	p, carry;
	int		j, length = pbf->blength;

	carry = 0;
	for (j = 0; j < length; j++) {
		p = (unsigned int)pbf->bsignificand[j] * multiplier + carry;
		pbf->bsignificand[j] = p & 0xffff;
		carry = p >> 16;
	}
	if (carry != 0)
		pbf->bsignificand[j++] = carry;
	pbf->blength = j;
}

/*
 * Multiply a base-10**4 significand by multiplier.  Extend length as
 * necessary to accommodate carries.
 */
static void
__multiply_base_ten(_big_float *pbf, unsigned short multiplier)
{
	unsigned int	p, carry;
	int		j, length = pbf->blength;

	carry = 0;
	for (j = 0; j < length; j++) {
		p = (unsigned int)pbf->bsignificand[j] * multiplier + carry;
		carry = __quorem10000(p, &pbf->bsignificand[j]);
	}
	while (carry != 0) {
		carry = __quorem10000(carry, &pbf->bsignificand[j]);
		j++;
	}
	pbf->blength = j;
}

/*
 * Multiply a base-10**4 significand by 2**multiplier.  Extend length
 * as necessary to accommodate carries.
 */
static void
__multiply_base_ten_by_two(_big_float *pbf, unsigned short multiplier)
{
	unsigned int	p, carry;
	int		j, length = pbf->blength;

	carry = 0;
	for (j = 0; j < length; j++) {
		p = ((unsigned int)pbf->bsignificand[j] << multiplier) + carry;
		carry = __quorem10000(p, &pbf->bsignificand[j]);
	}
	while (carry != 0) {
		carry = __quorem10000(carry, &pbf->bsignificand[j]);
		j++;
	}
	pbf->blength = j;
}

/*
 * Propagate carries in a base-2**16 significand.
 */
static void
__carry_propagate_two(unsigned int carry, unsigned short *psignificand)
{
	unsigned int	p;
	int		j;

	j = 0;
	while (carry != 0) {
		p = psignificand[j] + carry;
		psignificand[j++] = p & 0xffff;
		carry = p >> 16;
	}
}

/*
 * Propagate carries in a base-10**4 significand.
 */
static void
__carry_propagate_ten(unsigned int carry, unsigned short *psignificand)
{
	unsigned int	p;
	int		j;

	j = 0;
	while (carry != 0) {
		p = psignificand[j] + carry;
		carry = __quorem10000(p, &psignificand[j]);
		j++;
	}
}

/*
 * Given x[] and y[], base-2**16 vectors of length n, compute the
 * dot product
 *
 * sum (i=0,n-1) of x[i]*y[n-1-i]
 *
 * The product may fill as many as three base-2**16 digits; product[0]
 * is the least significant, product[2] the most.
 */
static void
__multiply_base_two_vector(unsigned short n, unsigned short *px,
    unsigned short *py, unsigned short *product)
{

	unsigned int	acc, p;
	unsigned short	carry;
	int		i;

	acc = 0;
	carry = 0;
	for (i = 0; i < (int)n; i++) {
		p = px[i] * py[n - 1 - i] + acc;
		if (p < acc)
			carry++;
		acc = p;
	}
	product[0] = acc & 0xffff;
	product[1] = acc >> 16;
	product[2] = carry;
}

/*
 * Given x[] and y[], base-10**4 vectors of length n, compute the
 * dot product
 *
 * sum (i=0,n-1) of x[i]*y[n-1-i]
 *
 * The product may fill as many as three base-10**4 digits; product[0]
 * is the least significant, product[2] the most.
 */
#define	ABASE	3000000000u	/* base of accumulator */

static void
__multiply_base_ten_vector(unsigned short n, unsigned short *px,
    unsigned short *py, unsigned short *product)
{

	unsigned int	acc;
	unsigned short	carry;
	int		i;

	acc = 0;
	carry = 0;
	for (i = 0; i < (int)n; i++) {
		acc = px[i] * py[n - 1 - i] + acc;
		if (acc >= ABASE) {
			carry++;
			acc -= ABASE;
		}
	}
	product[0] = acc % 10000;
	acc = acc / 10000;
	product[1] = acc % 10000;
	acc = acc / 10000;
	product[2] = acc + (ABASE / 100000000) * carry;
}

/*
 * Multiply *pbf by the n-th power of mult, which must be two or
 * ten.  If mult is two, *pbf is assumed to be base 10**4; if mult
 * is ten, *pbf is assumed to be base 2**16.  precision specifies
 * the number of significant bits or decimal digits required in the
 * result.  (The product may have more or fewer digits than this,
 * but it will be accurate to at least this many.)
 *
 * On exit, if the product is small enough, it overwrites *pbf, and
 * *pnewbf is set to pbf.  If the product is too large to fit in *pbf,
 * this routine calls malloc(3MALLOC) to allocate storage and sets *pnewbf
 * to point to this area; it is the caller's responsibility to free
 * this storage when it is no longer needed.  Note that *pbf may be
 * modified even when the routine allocates new storage.
 *
 * If n is too large, we set errno to ERANGE and call abort(3C).
 * If an attempted malloc fails, we set errno to ENOMEM and call
 * abort(3C).
 */
void
__big_float_times_power(_big_float *pbf, int mult, int n, int precision,
    _big_float **pnewbf)
{
	int		base, needed_precision, productsize;
	int		i, j, itlast, trailing_zeros_to_delete;
	int		tablepower[3], length[3];
	int		lengthx, lengthp, istart, istop;
	int		excess_check;
	unsigned short	*pp, *table[3], canquit;
	unsigned short	multiplier, product[3];

	if (pbf->blength == 0) {
		*pnewbf = pbf;
		return;
	}

	if (mult == 2) {
		/*
		 * Handle small n cases that don't require extra
		 * storage quickly.
		 */
		if (n <= 16 && pbf->blength + 2 < pbf->bsize) {
			__multiply_base_ten_by_two(pbf, n);
			*pnewbf = pbf;
			return;
		}

		/* *pbf is base 10**4 */
		base = 10;

		/*
		 * Convert precision (base ten digits) to needed_precision
		 * (base 10**4 digits), allowing an additional digit at
		 * each end.
		 */
		needed_precision = 2 + (precision >> 2);

		/*
		 * Set up pointers to the table entries and compute their
		 * lengths.
		 */
		if (n < __TBL_2_SMALL_SIZE) {
			itlast = 0;
			tablepower[0] = n;
			tablepower[1] = tablepower[2] = 0;
		} else if (n < (__TBL_2_SMALL_SIZE * __TBL_2_BIG_SIZE)) {
			itlast = 1;
			tablepower[0] = n % __TBL_2_SMALL_SIZE;
			tablepower[1] = n / __TBL_2_SMALL_SIZE;
			tablepower[2] = 0;
		} else if (n < (__TBL_2_SMALL_SIZE * __TBL_2_BIG_SIZE *
		    __TBL_2_HUGE_SIZE)) {
			itlast = 2;
			tablepower[0] = n % __TBL_2_SMALL_SIZE;
			n /= __TBL_2_SMALL_SIZE;
			tablepower[1] = n % __TBL_2_BIG_SIZE;
			tablepower[2] = n / __TBL_2_BIG_SIZE;
		} else {
			errno = ERANGE;
			abort();
		}
		pp = (unsigned short *)__tbl_2_small_start + tablepower[0];
		table[0] = (unsigned short *)__tbl_2_small_digits + pp[0];
		length[0] = pp[1] - pp[0];
		pp = (unsigned short *)__tbl_2_big_start + tablepower[1];
		table[1] = (unsigned short *)__tbl_2_big_digits + pp[0];
		length[1] = pp[1] - pp[0];
		pp = (unsigned short *)__tbl_2_huge_start + tablepower[2];
		table[2] = (unsigned short *)__tbl_2_huge_digits + pp[0];
		length[2] = pp[1] - pp[0];
	} else {
		if (n <= 4 && pbf->blength + 1 < pbf->bsize) {
			pbf->bexponent += (short)n;
			__multiply_base_two(pbf, __tbl_10_small_digits[n]);
			*pnewbf = pbf;
			return;
		}

		/* *pbf is base 2**16 */
		base = 2;
		pbf->bexponent += (short)n; /* now need to multiply by 5**n */
		needed_precision = 2 + (precision >> 4);
		if (n < __TBL_10_SMALL_SIZE) {
			itlast = 0;
			tablepower[0] = n;
			tablepower[1] = tablepower[2] = 0;
		} else if (n < (__TBL_10_SMALL_SIZE * __TBL_10_BIG_SIZE)) {
			itlast = 1;
			tablepower[0] = n % __TBL_10_SMALL_SIZE;
			tablepower[1] = n / __TBL_10_SMALL_SIZE;
			tablepower[2] = 0;
		} else if (n < (__TBL_10_SMALL_SIZE * __TBL_10_BIG_SIZE *
		    __TBL_10_HUGE_SIZE)) {
			itlast = 2;
			tablepower[0] = n % __TBL_10_SMALL_SIZE;
			n /= __TBL_10_SMALL_SIZE;
			tablepower[1] = n % __TBL_10_BIG_SIZE;
			tablepower[2] = n / __TBL_10_BIG_SIZE;
		} else {
			errno = ERANGE;
			abort();
		}
		pp = (unsigned short *)__tbl_10_small_start + tablepower[0];
		table[0] = (unsigned short *)__tbl_10_small_digits + pp[0];
		length[0] = pp[1] - pp[0];
		pp = (unsigned short *)__tbl_10_big_start + tablepower[1];
		table[1] = (unsigned short *)__tbl_10_big_digits + pp[0];
		length[1] = pp[1] - pp[0];
		pp = (unsigned short *)__tbl_10_huge_start + tablepower[2];
		table[2] = (unsigned short *)__tbl_10_huge_digits + pp[0];
		length[2] = pp[1] - pp[0];
	}

	/* compute an upper bound on the size of the product */
	productsize = pbf->blength;
	for (i = 0; i <= itlast; i++)
		productsize += length[i];

	if (productsize < needed_precision)
		needed_precision = productsize;

	if (productsize <= pbf->bsize) {
		*pnewbf = pbf;
	} else {
		i = sizeof (_big_float) + sizeof (unsigned short) *
		    (productsize - _BIG_FLOAT_SIZE);
		if ((*pnewbf = malloc(i)) == NULL) {
			errno = ENOMEM;
			abort();
		}
		(void) memcpy((*pnewbf)->bsignificand, pbf->bsignificand,
		    pbf->blength * sizeof (unsigned short));
		(*pnewbf)->blength = pbf->blength;
		(*pnewbf)->bexponent = pbf->bexponent;
		pbf = *pnewbf;
		pbf->bsize = productsize;
	}

	/*
	 * Now pbf points to the input and the output.  Step through
	 * each level of the tables.
	 */
	for (i = 0; i <= itlast; i++) {
		if (tablepower[i] == 0)
			continue;

		lengthp = length[i];
		if (lengthp == 1) {
			/* short multiplier (<= 10**4 or 2**13) */
			if (base == 10) {
				/* left shift by tablepower[i] */
				__multiply_base_ten_by_two(pbf, tablepower[i]);
			} else {
				__multiply_base_two(pbf, (table[i])[0]);
			}
			continue;
		}

		lengthx = pbf->blength;
		if (lengthx == 1) {
			/* short multiplicand */
			multiplier = pbf->bsignificand[0];
			(void) memcpy(pbf->bsignificand, table[i],
			    lengthp * sizeof (unsigned short));
			pbf->blength = lengthp;
			if (base == 10)
				__multiply_base_ten(pbf, multiplier);
			else
				__multiply_base_two(pbf, multiplier);
			continue;
		}

		/* keep track of trailing zeroes */
		trailing_zeros_to_delete = 0;

		/* initialize for carry propagation */
		pbf->bsignificand[lengthx + lengthp - 1] = 0;

		/*
		 * General case - the result will be accumulated in *pbf
		 * from most significant digit to least significant.
		 */
		for (j = lengthx + lengthp - 2; j >= 0; j--) {
			istart = j - lengthp + 1;
			if (istart < 0)
				istart = 0;

			istop = lengthx - 1;
			if (istop > j)
				istop = j;

			pp = table[i];
			if (base == 2) {
				__multiply_base_two_vector(istop - istart + 1,
				    &(pbf->bsignificand[istart]),
				    &(pp[j - istop]), product);
				if (product[2] != 0)
					__carry_propagate_two(
					    (unsigned int)product[2],
					    &(pbf->bsignificand[j + 2]));
				if (product[1] != 0)
					__carry_propagate_two(
					    (unsigned int)product[1],
					    &(pbf->bsignificand[j + 1]));
			} else {
				__multiply_base_ten_vector(istop - istart + 1,
				    &(pbf->bsignificand[istart]),
				    &(pp[j - istop]), product);
				if (product[2] != 0)
					__carry_propagate_ten(
					    (unsigned int)product[2],
					    &(pbf->bsignificand[j + 2]));
				if (product[1] != 0)
					__carry_propagate_ten(
					    (unsigned int)product[1],
					    &(pbf->bsignificand[j + 1]));
			}
			pbf->bsignificand[j] = product[0];
			if (i < itlast || j > lengthx + lengthp - 4
			    - needed_precision)
				continue;

			/*
			 * On the last multiplication, it's not necessary
			 * to develop the entire product if further digits
			 * can't possibly affect significant digits.  But
			 * note that further digits can affect the product
			 * in one of two ways: (i) the sum of digits beyond
			 * the significant ones can cause a carry that would
			 * propagate into the significant digits, or (ii) no
			 * carry will occur, but there may be more nonzero
			 * digits that will need to be recorded in a sticky
			 * bit.
			 */
			excess_check = lengthx + lengthp;
			if (pbf->bsignificand[excess_check - 1] == 0)
				excess_check--;
			excess_check -= needed_precision + 4;
			canquit = ((base == 2)? 65535 : 9999) -
			    ((lengthx < lengthp)? lengthx : lengthp);
			/*
			 * If j <= excess_check, then we have all the
			 * significant digits.  If the (j + 1)-st digit
			 * is no larger than canquit, then the sum of the
			 * digits not yet computed can't carry into the
			 * significant digits.  If the j-th and (j + 1)-st
			 * digits are not both zero, then we know we are
			 * discarding nonzero digits.  (If both of these
			 * digits are zero, we need to keep forming more
			 * of the product to see whether or not there are
			 * any more nonzero digits.)
			 */
			if (j <= excess_check &&
			    pbf->bsignificand[j + 1] <= canquit &&
			    (pbf->bsignificand[j + 1] | pbf->bsignificand[j])
			    != 0) {
				/* can discard j+1, j, ... 0 */
				trailing_zeros_to_delete = j + 2;

				/* set sticky bit */
				pbf->bsignificand[j + 2] |= 1;
				break;
			}
		}

		/* if the product didn't carry, delete the leading zero */
		pbf->blength = lengthx + lengthp;
		if (pbf->bsignificand[pbf->blength - 1] == 0)
			pbf->blength--;

		/* look for additional trailing zeros to delete */
		for (; pbf->bsignificand[trailing_zeros_to_delete] == 0;
		    trailing_zeros_to_delete++)
			continue;

		if (trailing_zeros_to_delete > 0) {
			for (j = 0; j < (int)pbf->blength -
			    trailing_zeros_to_delete; j++) {
				pbf->bsignificand[j] = pbf->bsignificand[j
				    + trailing_zeros_to_delete];
			}
			pbf->blength -= trailing_zeros_to_delete;
			pbf->bexponent += trailing_zeros_to_delete <<
			    ((base == 2)? 4 : 2);
		}
	}
}
