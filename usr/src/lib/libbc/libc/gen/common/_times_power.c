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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "base_conversion.h"
#include <malloc.h>

void
_copy_big_float_digits(_BIG_FLOAT_DIGIT *p1, _BIG_FLOAT_DIGIT *p2,
    short unsigned n)
{				/* Copies p1[n] = p2[n] */
	short unsigned  i;

	for (i = 0; i < n; i++)
		*p1++ = *p2++;
}

void
_free_big_float(_big_float *p)
{
	/* Central routine to call free for base conversion.	 */

	char           *freearg = (char *) p;

	(void) free(freearg);
#ifdef DEBUG
	printf(" free called with %X \n", freearg);
#endif
}

void
_base_conversion_abort(int ern, char *bcastring)
{
	char            pstring[160];

	errno = ern;
	(void) sprintf(pstring, " libc base conversion file %s line %d: %s", __FILE__, __LINE__, bcastring);
	perror(pstring);
	abort();
}

/*
 * function to multiply a big_float times a positive power of two or ten.
 *
 * Arguments
 * 	pbf:		Operand x, to be replaced by the product x * mult ** n.
 *	mult:		if mult is two, x is base 10**4;
 *			if mult is ten, x is base 2**16
 *	n:
 *	precision:	Number of bits of precision ultimately required
 *			(mult=10) or number of digits of precision ultimately
 *			required (mult=2).
 *			Extra bits are allowed internally to permit correct
 *			rounding.
 *	pnewbf:		Return result *pnewbf is set to: pbf if uneventful
 *			BIG_FLOAT_TIMES_TOOBIG  if n is bigger than the tables
 *			permit ;
 *			BIG_FLOAT_TIMES_NOMEM   if pbf->blength was
 *			insufficient to hold the product, and malloc failed to
 *			produce a new block ;
 *			&newbf                  if pbf->blength was
 *			insufficient to hold the product, and a new _big_float
 *			was allocated by malloc.  newbf holds the product.
 *			It's the caller's responsibility to free this space
 *			when no longer needed.
 *
 * if precision is < 0, then -pfb->bexponent/{4 or 16} digits are discarded
 * on the last product.
 */
 void
_big_float_times_power(_big_float *pbf, int mult, int n, int precision,
    _big_float **pnewbf)
{
	short unsigned  base, sumlz = 0;
	unsigned short  productsize, trailing_zeros_to_delete, needed_precision, *pp, *table[3], max[3], *start[3], *lz[3], tablepower[3];
	int             i, j, itlast;
	_big_float     *pbfold = pbf;
	int             discard;

	if (precision >= 0)
		discard = -1;
	else {
		precision = -precision;
		discard = 0;
	}
	switch (mult) {
	case 2:		/* *pbf is in base 10**4 so multiply by a
				 * power of two */
		base = 10;
		max[0] = _max_tiny_powers_two;
		max[1] = _max_small_powers_two;
		max[2] = _max_big_powers_two;
		table[0] = _tiny_powers_two;
		table[1] = _small_powers_two;
		table[2] = _big_powers_two;
		lz[0] = 0;
		lz[1] = 0;
		lz[2] = 0;
		start[0] = _start_tiny_powers_two;
		start[1] = _start_small_powers_two;
		start[2] = _start_big_powers_two;
		needed_precision = 2 + (precision + 1) / 4;	/* Precision is in base
								 * ten; counts round and
								 * sticky. */
		break;
	case 10:		/* *pbf is in base 2**16 so multiply by a
				 * power of ten */
		base = 2;
		max[0] = _max_tiny_powers_ten;
		max[1] = _max_small_powers_ten;
		max[2] = _max_big_powers_ten;
		table[0] = _tiny_powers_ten;
		table[1] = _small_powers_ten;
		table[2] = _big_powers_ten;
		start[0] = _start_tiny_powers_ten;
		start[1] = _start_small_powers_ten;
		start[2] = _start_big_powers_ten;
		lz[0] = _leading_zeros_tiny_powers_ten;
		lz[1] = _leading_zeros_small_powers_ten;
		lz[2] = _leading_zeros_big_powers_ten;
		needed_precision = 2 + (precision + 1) / 16;	/* Precision is in base
								 * two; counts round and
								 * sticky. */
		break;
	}
	for (i = 0; i < 3; i++) {
		tablepower[i] = n % max[i];
		n = n / max[i];
	}
	for (itlast = 2; (itlast >= 0) && (tablepower[itlast] == 0); itlast--);
	/* Determine last i; could be 0, 1, or 2.	 */
	if (n > 0) {		/* The tables aren't big enough to accomodate
				 * mult**n, but it doesn't matter since the
				 * result would undoubtedly overflow even
				 * binary quadruple precision format.  Return
				 * an error code. */
		(void) printf("\n _times_power failed due to exponent %d %d %d leftover: %d \n", tablepower[0], tablepower[1], tablepower[2], n);
		*pnewbf = BIG_FLOAT_TIMES_TOOBIG;
		goto ret;
	}
	productsize = pbf->blength;
	for (i = 0; i < 3; i++)
		productsize += (start[i])[tablepower[i] + 1] - (start[i])[tablepower[i]];

	if (productsize < needed_precision)
		needed_precision = productsize;

	if (productsize <= pbf->bsize) {
		*pnewbf = pbf;	/* Work with *pnewbf from now on. */
	} else {		/* Need more significance than *pbf can hold. */
		char           *mallocresult;
		int             mallocarg;

		mallocarg = sizeof(_big_float) + sizeof(_BIG_FLOAT_DIGIT) * (productsize - _BIG_FLOAT_SIZE);
		mallocresult = malloc(mallocarg);
#ifdef DEBUG
		printf(" malloc arg %X result %X \n", mallocarg, (int) mallocresult);
#endif
		if (mallocresult == (char *) 0) {	/* Not enough memory
							 * left, bail out. */
			*pnewbf = BIG_FLOAT_TIMES_NOMEM;
			goto ret;
		}
		*pnewbf = (_big_float *) mallocresult;
		_copy_big_float_digits((*pnewbf)->bsignificand, pbf->bsignificand, pbf->blength);
		(*pnewbf)->blength = pbf->blength;
		(*pnewbf)->bexponent = pbf->bexponent;
		pbf = *pnewbf;
		pbf->bsize = productsize;
	}

	/* pbf now points to the input and the output big_floats.	 */

	for (i = 0; i <= itlast; i++)
		if (tablepower[i] != 0) {	/* Step through each of the
						 * tables. */
			unsigned        lengthx, lengthp;

			/* Powers of 10**4 have leading zeros in base 2**16. */
			lengthp = (start[i])[tablepower[i] + 1] - (start[i])[tablepower[i]];
			lengthx = pbf->blength;

			if (discard >= 0)
				switch (base) {
				case 2:
					discard = (-pbf->bexponent) / 16;
					break;
				case 10:
					discard = (-pbf->bexponent) / 4;
					break;
				}

#ifdef DEBUG
			{
				long            basexp;
				int             id;

				printf(" step %d x operand length %d \n", i, lengthx);
				_display_big_float(pbf, base);
				printf(" step %d p operand length %d power %d \n", i, lengthp, tablepower[i]);
				basexp = (base == 2) ? (lz[i])[tablepower[i]] : 0;
				for (id = 0; id < lengthp; id++) {
					printf("+ %d * ", (table[i])[id + (start[i])[tablepower[i]]]);
					if (base == 2)
						printf("2**%d", 16 * (basexp + id));
					if (base == 10)
						printf("10**%d", 4 * (basexp + id));
					if ((id % 4) == 3)
						printf("\n");
				}
				printf("\n");
			}
			if ((i == itlast) && (discard >= 0))
				printf(" alternative discard %d digits \n", discard);
#endif

			if (base == 2) {
				sumlz += (lz[i])[tablepower[i]];
				pbf->bexponent += 16 * (lz[i])[tablepower[i]];
			}
			if (lengthp == 1) {	/* Special case - multiply by
						 * <= 10**4 or 2**13 */
				switch (base) {
				case 10:
					_multiply_base_ten_by_two(pbf, tablepower[i]);
					break;
				case 2:
					_multiply_base_two(pbf, (_BIG_FLOAT_DIGIT) ((table[i])[tablepower[i]]), (unsigned long) 0);
					break;
				}
#ifdef DEBUG
				assert(pbf->blength <= pbf->bsize);
#endif
			} else if (lengthx == 1) {	/* Special case of short
							 * multiplicand. */
				_BIG_FLOAT_DIGIT multiplier = pbf->bsignificand[0];

				_copy_big_float_digits(pbf->bsignificand, (unsigned short *) &((table[i])[(start[i])[tablepower[i]]]), lengthp);
				pbf->blength = lengthp;
				switch (base) {
				case 10:
					_multiply_base_ten(pbf, multiplier);
					break;
				case 2:
					_multiply_base_two(pbf, multiplier, (unsigned long) 0);
					break;
				}
#ifdef DEBUG
				assert(pbf->blength <= pbf->bsize);
#endif
			} else {/* General case. */
				short unsigned  canquit;
				short unsigned  excess;

				/*
				 * The result will be accumulated in *pbf
				 * from most significant to least
				 * significant.
				 */

				/* Generate criterion for early termination.	 */
				switch (base) {
				case 2:
					canquit = (short unsigned)65536;
					break;
				case 10:
					canquit = 10000;
					break;
				}
				canquit -= 3 + ((lengthx < lengthp) ? lengthx : lengthp);

				pbf->bsignificand[lengthx + lengthp - 1] = 0;	/* Only gets filled by
										 * carries. */
				for (j = lengthx + lengthp - 2; j >= 0; j--) {
					int             istart = j - lengthp + 1, istop = lengthx - 1;
					short unsigned  lengthprod;
					_BIG_FLOAT_DIGIT product[3];

					pp = (unsigned short *) &((table[i])[(start[i])[tablepower[i]]]);
					if (j < istop)
						istop = j;
					if (0 > istart)
						istart = 0;

					switch (base) {
					case 2:
						_multiply_base_two_vector((short unsigned) (istop - istart + 1), &(pbf->bsignificand[istart]), &(pp[j - istop]), product);
						if (product[2] != 0)
							_carry_propagate_two((unsigned long) product[2], &(pbf->bsignificand[j + 2]));
						if (product[1] != 0)
							_carry_propagate_two((unsigned long) product[1], &(pbf->bsignificand[j + 1]));
						break;
					case 10:
						_multiply_base_ten_vector((short unsigned) (istop - istart + 1), &(pbf->bsignificand[istart]), &(pp[j - istop]), product);
						if (product[2] != 0)
							_carry_propagate_ten((unsigned long) product[2], &(pbf->bsignificand[j + 2]));
						if (product[1] != 0)
							_carry_propagate_ten((unsigned long) product[1], &(pbf->bsignificand[j + 1]));
						break;
					}
					pbf->bsignificand[j] = product[0];
					lengthprod = lengthx + lengthp;
					if (pbf->bsignificand[lengthprod - 1] == 0)
						lengthprod--;
					if (lengthprod > needed_precision)
						excess = lengthprod - needed_precision;
					else
						excess = 0;
					if ((i == itlast) && ((j + 2) <= excess) && (pbf->bsignificand[j + 1] <= canquit)
					    && ((pbf->bsignificand[j + 1] | pbf->bsignificand[j]) != 0)) {
						/*
						 * On the last
						 * multiplication, it's not
						 * necessary to develop the
						 * entire product, if further
						 * digits can't possibly
						 * affect significant digits,
						 * unless there's a chance
						 * the product might be
						 * exact!
						 */
						/*
						 * Note that the product
						 * might be exact if the j
						 * and j+1 terms are zero; if
						 * they are non-zero, then it
						 * won't be after they're
						 * discarded.
						 */

						excess = j + 2;	/* Can discard j+1, j,
								 * ... 0 */
#ifdef DEBUG
						printf(" decided to quit early at j %d since s[j+1] is %d <= %d \n", j, pbf->bsignificand[j + 1], canquit);
						printf(" s[j+2..j] are %d %d %d \n", pbf->bsignificand[j + 2], pbf->bsignificand[j + 1], pbf->bsignificand[j]);
						printf(" requested precision %d needed_precision %d big digits out of %d \n", precision, needed_precision, lengthprod);
#endif
						if ((discard >= 0) && ((j + 2) > (discard - (int) sumlz))) {
#ifdef DEBUG
							printf(" early quit rejected because j+2 = %d > %d = discard \n", j + 2, discard);
#endif
							goto pastdiscard;
						}
						pbf->bsignificand[excess] |= 1;	/* Sticky bit on. */
#ifdef DEBUG
						printf(" discard %d digits - last gets %d \n", excess, pbf->bsignificand[excess]);
#endif
						trailing_zeros_to_delete = excess;
						goto donegeneral;
					}
			pastdiscard:	;
#ifdef DEBUG
					/*
					 * else { printf(" early termination
					 * rejected at j %d since s[j+1] =
					 * %d, canquit = %d \n", j,
					 * pbf->bsignificand[j + 1],
					 * canquit); printf(" s[j+2..j] are
					 * %d %d %d \n", pbf->bsignificand[j
					 * + 2], pbf->bsignificand[j + 1],
					 * pbf->bsignificand[j]); printf("
					 * requested precision %d
					 * needed_precision %d big digits out
					 * of %d \n", precision,
					 * needed_precision, lengthprod); }
					 */
#endif
				}
				trailing_zeros_to_delete = 0;
		donegeneral:
				pbf->blength = lengthx + lengthp;
				if (pbf->bsignificand[pbf->blength - 1] == 0)
					pbf->blength--;
				for (; pbf->bsignificand[trailing_zeros_to_delete] == 0; trailing_zeros_to_delete++);
				/*
				 * Look for additional trailing zeros to
				 * delete.
				 */

				 /*
				 * fix for bug 1070565; if too many trailing
				 * zeroes are deleted, we'll violate the
				 * assertion that bexponent is in [-3,+4]
				 */
				if (base == 10) {
					int deletelimit=(1-((pbf->bexponent+3)/4));

					if ((int)trailing_zeros_to_delete > deletelimit) {
#ifdef DEBUG
	printf("\n __x_power trailing zeros delete count lowered from %d to
	%d \n", trailing_zeros_to_delete,deletelimit);
#endif

						trailing_zeros_to_delete = deletelimit;
					}
				}
				

				if (trailing_zeros_to_delete != 0) {
#ifdef DEBUG
					printf(" %d trailing zeros deleted \n", trailing_zeros_to_delete);
#endif
					_copy_big_float_digits(pbf->bsignificand, &(pbf->bsignificand[trailing_zeros_to_delete]), pbf->blength - trailing_zeros_to_delete);
					pbf->blength -= trailing_zeros_to_delete;
					switch (base) {
					case 2:
						pbf->bexponent += 16 * trailing_zeros_to_delete;
						break;
					case 10:
						pbf->bexponent += 4 * trailing_zeros_to_delete;
						break;
					}
				}
			}
		}
	if ((pbfold != pbf) && (pbf->blength <= pbfold->bsize)) {	/* Don't need that huge
									 * buffer after all! */
#ifdef DEBUG
		printf(" free called from times_power because final length %d <= %d original size \n", pbf->blength, pbfold->bsize);
#endif

		/* Copy product to original buffer. */
		pbfold->blength = pbf->blength;
		pbfold->bexponent = pbf->bexponent;
		_copy_big_float_digits(pbfold->bsignificand, pbf->bsignificand, pbf->blength);
		_free_big_float(*pnewbf);	/* Free new buffer. */
		*pnewbf = pbfold;	/* New buffer pointer now agrees with
					 * original. */
	}
ret:
	return;
}
