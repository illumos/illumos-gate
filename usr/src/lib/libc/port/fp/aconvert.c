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

/* translation table from hex values to hex chars */
static const char *hexchar = "0123456789abcdef";

/*
 * Convert arg to a hexadecimal string.
 *
 * If arg is finite and nonzero, buf is filled with ndigits hexadecimal
 * digits, representing the significand of arg, followed by a null byte
 * (so ndigits must be at least 1 and buf must be large enough to hold
 * ndigits + 1 characters).  If ndigits is large enough, the representa-
 * tion is exact; otherwise, the value is rounded according to the pre-
 * vailing rounding mode to fit the requested number of digits.  Either
 * way, the result is normalized so that the first digit is '1'.  The
 * corresponding base two exponent is passed back in *exp.
 *
 * If arg is zero, buf is filled with ndigits zeros followed by a null,
 * and *exp is set to zero.  If arg is infinite or NaN, __infnanstring
 * is called to place an appropriate string in buf, and *exp is set to
 * zero.
 *
 * Regardless of the value of arg, its sign bit is stored in *sign.
 */

#if defined(__sparc)

void
__aconvert(double arg, int ndigits, int *exp, int *sign, char *buf)
{
	union {
		unsigned int	i[2];
		long long	l;
		double		d;
	} a, c;
	int		ha, i, s;
	unsigned int	d;

	a.d = arg;
	*sign = s = a.i[0] >> 31;
	ha = a.i[0] & ~0x80000000;

	/* check for infinity or nan */
	if (ha >= 0x7ff00000) {
		*exp = 0;
		__infnanstring((ha == 0x7ff00000 && a.i[1] == 0)?
		    fp_infinity : fp_quiet, ndigits, buf);
		return;
	}

	/* check for subnormal or zero */
	if (ha < 0x00100000) {
		if ((ha | a.i[1]) == 0) {
			*exp = 0;
			for (i = 0; i < ndigits; i++)
				buf[i] = '0';
			buf[ndigits] = '\0';
			return;
		}

		/*
		 * Normalize.  It would be much simpler if we could just
		 * multiply by a power of two here, but some SPARC imple-
		 * mentations would flush the subnormal operand to zero
		 * when nonstandard mode is enabled.
		 */
		a.i[0] = ha;
		a.d = (double)a.l;
		if (s)
			a.d = -a.d;
		ha = a.i[0] & ~0x80000000;
		*exp = (ha >> 20) - 0x3ff - 1074;
	} else {
		*exp = (ha >> 20) - 0x3ff;
	}

	if (ndigits < 14) {
		/*
		 * Round the significand at the appropriate bit by adding
		 * and subtracting a power of two.  This will also raise
		 * the inexact exception if anything is rounded off.
		 */
		c.i[0] = (0x43700000 | (s << 31)) - (ndigits << 22);
		c.i[1] = 0;
		a.i[0] = (a.i[0] & 0x800fffff) | 0x3ff00000;
		a.d = (a.d + c.d) - c.d;
		ha = a.i[0] & ~0x80000000;
		if (ha >= 0x40000000)
			(*exp)++;
	}

	/* convert to hex digits */
	buf[0] = '1';
	d = ha << 12;
	for (i = 1; i < ndigits && i < 6; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	d = a.i[1];
	for (; i < ndigits && i < 14; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	for (; i < ndigits; i++)
		buf[i] = '0';
	buf[ndigits] = '\0';
}

void
__qaconvert(long double *arg, int ndigits, int *exp, int *sign, char *buf)
{
	union {
		unsigned int	i[4];
		long double	q;
	} a;
	enum fp_direction_type	rd;
	int			ha, i, s;
	unsigned int		b, r, d;

	a.q = *arg;
	*sign = a.i[0] >> 31;
	ha = a.i[0] &= ~0x80000000;

	/* check for infinity or nan */
	if (ha >= 0x7fff0000) {
		*exp = 0;
		__infnanstring((ha == 0x7fff0000 && (a.i[1] | a.i[2] | a.i[3])
		    == 0)? fp_infinity : fp_quiet, ndigits, buf);
		return;
	}

	/* check for subnormal or zero */
	if (ha < 0x00010000) {
		if ((ha | a.i[1] | a.i[2] | a.i[3]) == 0) {
			*exp = 0;
			for (i = 0; i < ndigits; i++)
				buf[i] = '0';
			buf[ndigits] = '\0';
			return;
		}

		/* normalize */
		i = 0;
		while ((a.i[0] | (a.i[1] & 0xffff0000)) == 0) {
			a.i[0] = a.i[1];
			a.i[1] = a.i[2];
			a.i[2] = a.i[3];
			a.i[3] = 0;
			i += 32;
		}
		while ((a.i[0] & 0x7fff0000) == 0) {
			a.i[0] = (a.i[0] << 1) | (a.i[1] >> 31);
			a.i[1] = (a.i[1] << 1) | (a.i[2] >> 31);
			a.i[2] = (a.i[2] << 1) | (a.i[3] >> 31);
			a.i[3] <<= 1;
			i++;
		}
		*exp = -0x3ffe - i;
	} else {
		*exp = (ha >> 16) - 0x3fff;
	}

	if (ndigits < 29) {
		/*
		 * Round the significand at the appropriate bit using
		 * integer arithmetic.  Explicitly raise the inexact
		 * exception if anything is rounded off.
		 */
		a.i[0] = (a.i[0] & 0xffff) | 0x10000;
		if (ndigits <= 5) {
			/*
			 * i and b are the index and bit position in a.i[]
			 * of the last bit to be retained.  r holds the bits
			 * to be rounded off, left-adjusted and sticky.
			 */
			i = 0;
			s = (5 - ndigits) << 2;
			b = 1 << s;
			r = ((a.i[0] << 1) << (31 - s)) | (a.i[1] >> s);
			if ((a.i[1] & (b - 1)) | a.i[2] | a.i[3])
				r |= 1;
			a.i[0] &= ~(b - 1);
			a.i[1] = a.i[2] = a.i[3] = 0;
		} else if (ndigits <= 13) {
			i = 1;
			s = (13 - ndigits) << 2;
			b = 1 << s;
			r = ((a.i[1] << 1) << (31 - s)) | (a.i[2] >> s);
			if ((a.i[2] & (b - 1)) | a.i[3])
				r |= 1;
			a.i[1] &= ~(b - 1);
			a.i[2] = a.i[3] = 0;
		} else if (ndigits <= 21) {
			i = 2;
			s = (21 - ndigits) << 2;
			b = 1 << s;
			r = ((a.i[2] << 1) << (31 - s)) | (a.i[3] >> s);
			if (a.i[3] & (b - 1))
				r |= 1;
			a.i[2] &= ~(b - 1);
			a.i[3] = 0;
		} else {
			i = 3;
			s = (29 - ndigits) << 2;
			b = 1 << s;
			r = (a.i[3] << 1) << (31 - s);
			a.i[3] &= ~(b - 1);
		}

		/* conversion is inexact if r is not zero */
		if (r) {
			__base_conversion_set_exception(
			    (fp_exception_field_type)(1 << fp_inexact));

			/* massage the rounding direction based on the sign */
			rd = _QgetRD();
			if (*sign && (rd == fp_positive || rd == fp_negative))
				rd = fp_positive + fp_negative - rd;

			/* decide whether to round up */
			if (rd == fp_positive || (rd == fp_nearest &&
			    (r > 0x80000000u || (r == 0x80000000u &&
			    (a.i[i] & b))))) {
				a.i[i] += b;
				while (a.i[i] == 0)
					a.i[--i]++;
				if (a.i[0] >= 0x20000)
					(*exp)++;
			}
		}
	}

	/* convert to hex digits */
	buf[0] = '1';
	d = a.i[0] << 16;
	for (i = 1; i < ndigits && i < 5; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	d = a.i[1];
	for (; i < ndigits && i < 13; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	d = a.i[2];
	for (; i < ndigits && i < 21; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	d = a.i[3];
	for (; i < ndigits && i < 29; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	for (; i < ndigits; i++)
		buf[i] = '0';
	buf[ndigits] = '\0';
}

#elif defined(__i386) || defined(__amd64)

/*
 * The following code assumes the rounding precision mode is set
 * to the default (round to 64 bits).
 */
void
__qaconvert(long double *arg, int ndigits, int *exp, int *sign, char *buf)
{
	union {
		unsigned int	i[3];
		long double	x;
	} a, c;
	int		ea, i, s;
	unsigned int	d;

	a.x = *arg;
	*sign = s = (a.i[2] >> 15) & 1;
	ea = a.i[2] & 0x7fff;

	/* check for infinity or nan */
	if (ea == 0x7fff) {
		*exp = 0;
		__infnanstring((((a.i[1] << 1) | a.i[0]) == 0)?
		    fp_infinity : fp_quiet, ndigits, buf);
		return;
	}

	/* check for subnormal or zero */
	if (ea == 0) {
		if ((a.i[1] | a.i[0]) == 0) {
			*exp = 0;
			for (i = 0; i < ndigits; i++)
				buf[i] = '0';
			buf[ndigits] = '\0';
			return;
		}

		/* normalize */
		a.x *= 18446744073709551616.0; /* 2^64 */
		ea = a.i[2] & 0x7fff;
		*exp = ea - 0x403f;
	} else {
		*exp = ea - 0x3fff;
	}

	if (ndigits < 17) {
		/*
		 * Round the significand at the appropriate bit by adding
		 * and subtracting a power of two.  This will also raise
		 * the inexact exception if anything is rounded off.
		 */
		c.i[2] = (0x4042 | (s << 15)) - (ndigits << 2);
		c.i[1] = 0x80000000;
		c.i[0] = 0;
		a.i[2] = 0x3fff | (s << 15);
		a.x = (a.x + c.x) - c.x;
		ea = a.i[2] & 0x7fff;
		if (ea >= 0x4000)
			(*exp)++;
	}

	/* convert to hex digits */
	buf[0] = '1';
	d = (a.i[1] << 1) | (a.i[0] >> 31);
	for (i = 1; i < ndigits && i < 9; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	d = a.i[0] << 1;
	for (; i < ndigits && i < 17; i++) {
		buf[i] = hexchar[d >> 28];
		d <<= 4;
	}
	for (; i < ndigits; i++)
		buf[i] = '0';
	buf[ndigits] = '\0';
}

void
__aconvert(double arg, int ndigits, int *exp, int *sign, char *buf)
{
	union {
		int	i[2];
		double	d;
	} a;
	long double	ldarg;
	int		ha;

	/* avoid raising invalid operation exception for signaling nan */
	a.i[0] = *(int *)&arg;
	a.i[1] = *(1+(int *)&arg);
	ha = a.i[1] & ~0x80000000;
	if (ha > 0x7ff00000 || (ha == 0x7ff00000 && a.i[0] != 0))
		a.i[1] |= 0x80000; /* make nan quiet */
	ldarg = a.d;
	__qaconvert(&ldarg, ndigits, exp, sign, buf);
}

#else
#error Unknown architecture
#endif
