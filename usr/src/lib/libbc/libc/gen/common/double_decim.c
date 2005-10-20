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

/* Conversion between binary and decimal floating point. */

#include "base_conversion.h"

/* PRIVATE FUNCTIONS */

/*
 * Rounds decimal record *pd according to modes in *pm, recording exceptions
 * for inexact or overflow in *ps.  round is the round digit and sticky is 0
 * or non-zero to indicate exact or inexact. pd->ndigits is expected to be
 * correctly set.
 */
void
decimal_round(decimal_mode *pm, decimal_record *pd, fp_exception_field_type *ps,
    char round, unsigned sticky)
{
	int             lsd, i;

	if ((round == '0') && (sticky == 0)) {	/* Exact. */
		goto done;
	}
	*ps |= 1 << fp_inexact;

	switch (pm->rd) {
	case fp_nearest:
		if (round < '5')
			goto done;
		if (round > '5')
			goto roundup;
		if (sticky != 0)
			goto roundup;
		/* Now in ambiguous case; round up if lsd is odd. */
		if (pd->ndigits <= 0)
			goto done;	/* Presumed 0. */
		lsd = pd->ds[pd->ndigits - 1] - '0';
		if ((lsd % 2) == 0)
			goto done;
		goto roundup;
	case fp_positive:
		if (pd->sign != 0)
			goto done;
		goto roundup;
	case fp_negative:
		if (pd->sign == 0)
			goto done;
		goto roundup;
	case fp_tozero:
		goto done;
	}
roundup:
	for (i = (pd->ndigits - 1); (pd->ds[i] == '9') && (i >= 0); i--)
		pd->ds[i] = '0';
	if (i >= 0)
		(pd->ds[i])++;
	else {			/* Rounding carry out has occurred. */
		pd->ds[0] = '1';
		if (pm->df == floating_form) {	/* For E format, simply
						 * adjust exponent. */
			pd->exponent++;
		} else {	/* For F format, increase length of string. */
			if (pd->ndigits > 0)
				pd->ds[pd->ndigits] = '0';
			pd->ndigits++;
		}
	}
	goto ret;
done:
	if (pd->ndigits <= 0) {	/* Create zero string. */
		pd->ds[0] = '0';
		pd->ndigits = 1;
	}
ret:
	pd->ds[pd->ndigits] = 0;/* Terminate string. */
	return;
}

/*
 * Converts an unpacked integer value *pu into a decimal string in *ds, of
 * length returned in *ndigs. Inexactness is indicated by setting
 * ds[ndigs-1] odd.
 *
 * Arguments
 *	pu:		Input unpacked integer value input.
 *	nsig:		Input number of significant digits required.
 *	ds:		Output decimal integer string output
 *			must be large enough.
 *	nzeros:		Output number of implicit trailing zeros
 *			produced.
 *	ndigs:		Output number of explicit digits produced
 *			in ds.
 */
void
binary_to_decimal_integer(unpacked *pu, unsigned nsig, char ds[],
    unsigned *nzeros, unsigned *ndigs)
{

	_big_float     *pd, b, d;
	int             e, i, is;
	_BIG_FLOAT_DIGIT stickyshift;
	char            s[4];

	b.bsize = _BIG_FLOAT_SIZE;	/* Initialize sizes of big floats. */
	d.bsize = _BIG_FLOAT_SIZE;
	_unpacked_to_big_float(pu, &b, &e);
	if (e < 0) {
		_right_shift_base_two(&b, (short unsigned) -e, &stickyshift);
#ifdef DEBUG
		assert(stickyshift == 0);
#endif
	}
	_big_binary_to_big_decimal(&b, &d);
	if (e <= 0)
		pd = &d;
	else {
		_big_float_times_power(&d, 2, e, (int) nsig, &pd);
		switch ((unsigned int)pd) {
		case ((unsigned int)BIG_FLOAT_TIMES_TOOBIG):
			{
				char            bcastring[80];

				(void) sprintf(bcastring, " binary exponent %d ", e);
				_base_conversion_abort(ERANGE, bcastring);
				break;
			}
		case ((unsigned int)BIG_FLOAT_TIMES_NOMEM):
			{
				char            bcastring[80];

				(void) sprintf(bcastring, " binary exponent %d ", e);
				_base_conversion_abort(ENOMEM, bcastring);
				break;
			}
		default:
#ifdef DEBUG
			if (pd != &d)
				(void) printf(" large binary exponent %d needs heap buffer \n", e);
			printf(" product ");
			_display_big_float(pd, 10);
#endif
			break;
		}
	}
	_fourdigitsquick((short unsigned) pd->bsignificand[pd->blength - 1], s);
	for (i = 0; s[i] == '0'; i++);	/* Find first non-zero digit. */
	for (is = 0; i <= 3;)
		ds[is++] = s[i++];	/* Copy subsequent digits. */

	for (i = (pd->blength - 2); i >= 0; i--) {	/* Convert powers of
							 * 10**4 to decimal
							 * digits. */
		_fourdigitsquick((short unsigned) pd->bsignificand[i], &(ds[is]));
		is += 4;
	}

	ds[is] = 0;
	*ndigs = is;
	*nzeros = pd->bexponent;
	if (pd != &d)
		_free_big_float(pd);

#ifdef DEBUG
	printf(" binary to decimal integer result %s * 10**%d \n", ds, *nzeros);
#endif
}

/*
 * Converts an unpacked fraction value *pu into a decimal string consisting
 * of a) an implicit '.' b) *nzeros implicit leading zeros c) *ndigs explicit
 * digits in ds ds contains at least nsig significant digits. nzeros + *
 * *ndigs is at least nfrac digits after the point. Inexactness is indicated
 * by sticking to the lsb.
 *
 * Arguments
 *
 *	pu:		Input unpacked fraction value output < 1
 *			in magnitude.
 *	nsig:		Input number of significant digits
 *			required.
 *	nfrac:		Input number of digits after point
 *			required.
 *	ds:		Output decimal integer string output -
 *			must be large enough.
 *	nzeros:		Output number of implicit leading zeros
 *			produced.
 *	ndigs:		Output number of explicit digits produced
 *			in ds.
 */
 void
binary_to_decimal_fraction(unpacked *pu, unsigned nsig, unsigned nfrac,
    char ds[], int *nzeros, int *ndigs)
{
	_big_float     *pb, b, d;
	int             e, i, j, is, excess;
	char            s[4];
	int             tensig, tenpower;
	_BIG_FLOAT_DIGIT stickyshift;

	*nzeros = 0;
	if (pu->fpclass == fp_zero) {	/* Exact zero. */
		for (i = 0; i <= nfrac; i++)
			ds[i] = '0';
		for (; i <= nsig; i++)
			ds[i] = '0';
		*ndigs = i;
		return;
	}
	b.bsize = _BIG_FLOAT_SIZE;	/* Initialize sizes of big floats. */
	d.bsize = _BIG_FLOAT_SIZE;
	_unpacked_to_big_float(pu, &b, &e);
	/*
	 * e < 0 always
	 */
	b.bexponent = e;
	tenpower = nsig + (int) (((17 - e - 16 * b.blength) * (unsigned long) 19729) >> 16);
	if (tenpower < nfrac)
		tenpower = nfrac;
	tensig = nfrac;
	if (nsig > tensig)
		tensig = nsig;
	tensig = 1 + (((tensig + 2) * 217706) >> 16);
	tensig = -tensig;

#ifdef DEBUG
	printf(" binary to decimal fraction exponent 2**%d \n", e);
	printf(" binary to decimal fraction nsig %d nfrac %d tenpower %d tensig %d \n", nsig, nfrac, tenpower, tensig);
#endif
	_big_float_times_power(&b, 10, tenpower, tensig, &pb);
	switch ((unsigned int)pb) {
	case ((unsigned int)BIG_FLOAT_TIMES_TOOBIG):
		{
			char            bcastring[80];

			(void) sprintf(bcastring, " decimal exponent %d ", tenpower);
			_base_conversion_abort(ERANGE, bcastring);
			break;
		}
	case ((unsigned int)BIG_FLOAT_TIMES_NOMEM):
		{
			char            bcastring[80];

			(void) sprintf(bcastring, " decimal exponent %d ", tenpower);
			_base_conversion_abort(ENOMEM, bcastring);
			break;
		}
	default:
#ifdef DEBUG
		if (pb != &b)
			printf(" large decimal exponent %d needs heap buffer \n", tenpower);
		printf(" product ");
		_display_big_float(pb, 2);
#endif
		break;
	}

	if (pb->bexponent <= -16) {
		/* Have computed appropriate decimal part; now toss fraction. */
		excess = (-pb->bexponent) / 16;
#ifdef DEBUG
		printf(" discard %d excess fraction bits \n", 16 * excess);
#endif
		for (i = 0; (i < excess) && (pb->bsignificand[i] == 0); i++);
		if (i < excess)
			pb->bsignificand[excess] |= 1;	/* Sticky bit for
							 * discarded fraction. */
		for (i = excess; i < pb->blength; i++)
			pb->bsignificand[i - excess] = pb->bsignificand[i];

		pb->blength -= excess;
		pb->bexponent += 16 * excess;
	}
	if (pb->bexponent < 0) {
		_right_shift_base_two(pb, (short unsigned) -pb->bexponent, &stickyshift);
		if (stickyshift != 0)
			pb->bsignificand[0] |= 1;	/* Stick to lsb. */
	}
	_big_binary_to_big_decimal(pb, &d);

	i = d.blength - 1;
	while (d.bsignificand[i] == 0)
		i--;
	_fourdigitsquick((short unsigned) d.bsignificand[i], s);
	for (j = 0; s[j] == '0'; j++);	/* Find first non-zero digit. */
	for (is = 0; j <= 3;)
		ds[is++] = s[j++];	/* Copy subsequent digits. */

	for (i--; i >= 0; i--) {/* Convert powers of 10**4 to decimal digits. */
		_fourdigitsquick((short unsigned) d.bsignificand[i], &(ds[is]));
		is += 4;
	}

	ds[is] = 0;
	*ndigs = is;
#ifdef DEBUG
	assert(tenpower >= is);
#endif
	*nzeros = tenpower - is;/* There were supposed to be tenpower leading
				 * digits, and is were found. */

	if (pb != &b)
		_free_big_float(pb);

#ifdef DEBUG
	printf(" binary to decimal fraction result .%s * 10**%d \n", ds, -(*nzeros));
#endif

}

void
_unpacked_to_decimal(unpacked *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	unpacked        fx, ix;
	unsigned        fmask, imask;
	int             i, intdigs, fracdigs, fraczeros, fracsigs, ids, idsbound, lzbound;
	unsigned        nsig, nfrac, intzeros, intsigs;
	char            is[_INTEGER_SIZE], fs[DECIMAL_STRING_LENGTH];
	char            round = '0';
	unsigned        sticky = 0;

	pd->sign = px->sign;
	pd->fpclass = px->fpclass;
	if ((px->fpclass != fp_normal) && (px->fpclass != fp_subnormal))
		return;
	if ((pm->ndigits >= DECIMAL_STRING_LENGTH) ||
	    ((pm->df == floating_form) && (pm->ndigits < 1))) {	/* Gross overflow or bad
								 * spec. */
overflow:
		*ps |= 1 << fp_overflow;
		return;
	}
	/* Divide x up into integer part ix and fraction part fx.	 */

	ix = *px;
	fx = ix;
	if (ix.exponent <= -1) {/* All fraction. */
		ix.fpclass = fp_zero;
	} else if (ix.exponent >= 159) {	/* All integer. */
		fx.fpclass = fp_zero;
	} else if ((ix.exponent % 32) == 31) {	/* Integer/fraction boundary
						 * is conveniently on a word
						 * boundary. */
		imask = (ix.exponent + 1) / 32;	/* Words 0..imask-1 are
						 * integer; imask..SIZE are
						 * fraction. */
		for (i = 0; i < imask; i++)
			fx.significand[i] = 0;
		for (; i < UNPACKED_SIZE; i++)
			ix.significand[i] = 0;
		_fp_normalize(&fx);
	} else {		/* Integer/fraction boundary falls in the
				 * middle of a word. */
		imask = (ix.exponent + 1) / 32;	/* Words 0..imask-1 are
						 * integer; imask is integer
						 * and fraction ;
						 * imask+1..SIZE are
						 * fraction. */
		for (i = 0; i < imask; i++)
			fx.significand[i] = 0;
		fmask = (1 << (31 - (ix.exponent % 32))) - 1;
		fx.significand[imask] &= fmask;
		ix.significand[imask] &= ~fmask;
		for (i = (imask + 1); i < UNPACKED_SIZE; i++)
			ix.significand[i] = 0;
		_fp_normalize(&fx);
	}
	if (ix.fpclass != fp_zero) {	/* Compute integer part of result. */
		if (pm->df == floating_form)
			nsig = pm->ndigits + 1;	/* Significant digits wanted
						 * for E format, plus one for
						 * rounding. */
		else
			nsig = _INTEGER_SIZE;	/* Significant digits wanted
						 * for F format == all. */

		binary_to_decimal_integer(&ix, nsig, is, &intzeros, &intsigs);
	} else {
		intsigs = 0;
		intzeros = 0;
	}
	intdigs = intsigs + intzeros;
	fracdigs = 0;
	if (((pm->df == fixed_form) && (pm->ndigits >= 0)) ||
	    ((pm->df == floating_form) && ((pm->ndigits + 1) > intdigs))) {	/* Need to compute
										 * fraction part. */
		if (pm->df == floating_form) {	/* Need more significant
						 * digits. */
			nsig = pm->ndigits + 2 - intdigs;	/* Add two for rounding,
								 * sticky. */
			if (nsig > DECIMAL_STRING_LENGTH)
				nsig = DECIMAL_STRING_LENGTH;
			nfrac = 1;
		} else {	/* Need fraction digits. */
			nsig = 0;
			nfrac = pm->ndigits + 2;	/* Add two for rounding,
							 * sticky. */
			if (nfrac > DECIMAL_STRING_LENGTH)
				nfrac = DECIMAL_STRING_LENGTH;
		}
		binary_to_decimal_fraction(&fx, nsig, nfrac, fs, &fraczeros, &fracsigs);
		fracdigs = fraczeros + fracsigs;
	}
	if (pm->df == floating_form) {	/* Combine integer and fraction for E
					 * format. */
		idsbound = intsigs;
		if (idsbound > pm->ndigits)
			idsbound = pm->ndigits;
		for (ids = 0; ids < idsbound; ids++)
			pd->ds[ids] = is[ids];
		/* Put integer into output string. */
		idsbound = intsigs + intzeros;
		if (idsbound > pm->ndigits)
			idsbound = pm->ndigits;
		for (; ids < idsbound; ids++)
			pd->ds[ids] = '0';
		if (ids == pm->ndigits) {	/* Integer part had enough
						 * significant digits. */
			pd->ndigits = ids;
			pd->exponent = intdigs - ids;
			if (ids < intdigs) {	/* Gather rounding info. */
				if (ids < intsigs)
					round = is[ids++];
				else
					round = '0';
				for (; (is[ids] == '0') && (ids < intsigs); ids++);
				if (ids < intsigs)
					sticky = 1;
				if (fx.fpclass != fp_zero)
					sticky = 1;
			} else {/* Integer part is exact - round from
				 * fraction. */
				if (fx.fpclass != fp_zero) {
					int             stickystart;
					/* Fraction non-zero. */
					if (fraczeros > 0) {	/* Round digit is zero. */
						round = '0';
						stickystart = 0;	/* Stickies start with
									 * fs[0]. */
					} else {	/* Round digit is fs[0]. */
						round = fs[0];
						stickystart = 1;	/* Stickies start with
									 * fs[1]. */
					}
					if (sticky == 0) {	/* Search for sticky
								 * bits. */
						for (ids = stickystart; (fs[ids] == '0') && (ids < fracdigs); ids++);
						if (ids < fracdigs)
							sticky = 1;
					}
				}
			}
		} else {	/* Need more significant digits from fraction
				 * part. */
			idsbound = pm->ndigits - ids;
			if (ids == 0) {	/* No integer part - find first
					 * significant digit. */
				for (i = 0; fs[i] == '0'; i++);
				idsbound = i + idsbound + fraczeros;
				i += fraczeros;	/* Point i at first
						 * significant digit. */
			} else
				i = 0;
			if (idsbound > fracdigs)
				idsbound = fracdigs;
			pd->exponent = -idsbound;

			if (fraczeros < idsbound)	/* Compute number of
							 * leading zeros
							 * required. */
				lzbound = fraczeros;
			else
				lzbound = idsbound;
			for (; (i < lzbound); i++)
				pd->ds[ids++] = '0';
			for (; (i < idsbound); i++)
				pd->ds[ids++] = fs[i - fraczeros];
			i -= fraczeros;	/* Don't worry about leading zeros
					 * from now on, we're just rounding */
			if (i < fracsigs) {	/* Gather rounding info.  */
				if (i < 0)
					round = '0';
				else
					round = fs[i];
				i++;
				if (sticky == 0) {	/* Find out if remainder
							 * is exact. */
					if (i < 0)
						i = 0;
					for (; (fs[i] == '0') && (i < fracsigs); i++);
					if (i < fracsigs)
						sticky = 1;
				}
			} else {/* Fraction part is exact - add zero digits
				 * if required. */
				for (; ids < pm->ndigits; ids++)
					pd->ds[ids] = '0';
			}
			pd->ndigits = ids;
		}
		decimal_round(pm, pd, ps, round, sticky);
	} else {		/* Combine integer and fraction for F format. */
		if (pm->ndigits >= 0) {	/* Normal F format. */
			if ((intdigs + pm->ndigits) >= DECIMAL_STRING_LENGTH)
				goto overflow;
			for (ids = 0; ids < intsigs; ids++)
				pd->ds[ids] = is[ids];
			for (; ids < intdigs; ids++)
				pd->ds[ids] = '0';
			/* Copy integer digits. */
			idsbound = fracdigs;
			if (idsbound > pm->ndigits)
				idsbound = pm->ndigits;
			if (fraczeros < idsbound)	/* Compute number of
							 * leading zeros
							 * required. */
				lzbound = fraczeros;
			else
				lzbound = idsbound;
			for (i = 0; (i < lzbound); i++)
				pd->ds[ids++] = '0';
			for (; (i < idsbound); i++)
				pd->ds[ids++] = fs[i - fraczeros];	/* Copy fraction digits. */
			for (; i < pm->ndigits; i++)
				pd->ds[ids++] = '0';
			/* Copy trailing zeros if necessary. */
			pd->ndigits = ids;
			pd->exponent = intdigs - ids;
			i -= fraczeros;	/* Don't worry about leading zeros
					 * from now on, we're just rounding */
			if (i < fracsigs) {	/* Gather rounding info.  */
				if (i < 0)
					round = '0';
				else
					round = fs[i];
				i++;
				if (sticky == 0) {	/* Find out if remainder
							 * is exact. */
					if (i < 0)
						i = 0;
					for (; (fs[i] == '0') && (i < fracsigs); i++);
					if (i < fracsigs)
						sticky = 1;
				}
			}
			decimal_round(pm, pd, ps, round, sticky);
		} else {	/* Bizarre F format - round to left of point. */
			int             roundpos = -pm->ndigits;

			if (intdigs >= DECIMAL_STRING_LENGTH)
				goto overflow;
			if (roundpos >= DECIMAL_STRING_LENGTH)
				goto overflow;
			if (intdigs <= roundpos) {	/* Not enough integer
							 * digits. */
				if (intdigs == roundpos) {
					round = is[0];
					i = 1;
				} else {
					round = '0';
					i = 0;
				}
				for (; (is[i] == '0') && (i < intsigs); i++);
				/* Search for sticky bits. */
				if (i < intsigs)
					sticky = 1;
				pd->ndigits = 0;
			} else {/* Some integer digits do not get rounded
				 * away. */
#ifdef _NO_GOOD
				for (ids = 0; ids < (intsigs - roundpos); ids++)
					pd->ds[ids] = is[ids];
				for (ids = 0; ids < (intdigs - roundpos); ids++)
					pd->ds[ids] = '0';
#else
                                 {
                                         int             ncopy = intsigs - roundpos;
                                         if (ncopy > 0) {
                                                 /* Copy integer digits. */
                                                 (void) memcpy(&(pd->ds[0]), &(is[0]), ncopy);
                                                 ids = ncopy;
                                         }
                                 }
                                 {
                                         int             ncopy = intdigs - roundpos - ids ;
                                         if (ncopy > 0) {
                                                 (void) memset(&(pd->ds[ids]), '0', ncopy);
                                                 ids += ncopy;
                                         }
                                 }
#endif /* _NO_GOOD */
				/* Copy integer digits. */
				pd->ndigits = ids;
				if (ids < intsigs) {	/* Inexact. */
					round = is[ids++];
					for (; (is[ids] == '0') && (ids < intsigs); ids++);
					/* Search for non-zero digits. */
					if (ids < intsigs)
						sticky = 1;
				}
			}
			if (fx.fpclass != fp_zero)
				sticky = 1;
			decimal_round(pm, pd, ps, round, sticky);
			for (i = pd->ndigits; i < (pd->ndigits + roundpos); i++)
				pd->ds[i] = '0';	/* Blank out rounded
							 * away digits. */
			pd->exponent = 0;
			pd->ndigits = i;
			pd->ds[i] = 0;	/* Terminate string. */
		}
	}
}

void
double_to_decimal(double *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	double_equivalence kluge;
	unpacked        u;

	*ps = 0;		/* Initialize *ps. */
	kluge.x = *px;
	pd->sign = kluge.f.msw.sign;
	pd->fpclass = _class_double(px);
	switch (pd->fpclass) {
	case fp_zero:
		break;
	case fp_infinity:
		break;
	case fp_quiet:
		break;
	case fp_signaling:
		break;
	default:
		_unpack_double(&u, &kluge.x);
		_unpacked_to_decimal(&u, pm, pd, ps);
	}
}

void
quadruple_to_decimal(quadruple *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	quadruple_equivalence kluge;
	unpacked        u;
	int             i;

	*ps = 0;		/* Initialize *ps - no exceptions. */
	for (i = 0; i < 4; i++)
#ifdef __STDC__
		kluge.x = *px;
#else
		kluge.x.u[i] = px->u[i];
#endif
	pd->sign = kluge.f.msw.sign;
	pd->fpclass = _class_quadruple(px);
	switch (pd->fpclass) {
	case fp_zero:
		break;
	case fp_infinity:
		break;
	case fp_quiet:
		break;
	case fp_signaling:
		break;
	default:
		_unpack_quadruple(&u, px);
		_unpacked_to_decimal(&u, pm, pd, ps);
	}
}
