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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/isa_defs.h>
#include <floatingpoint.h>
#include <limits.h>
#include "libc.h"

/*
 * Ensure that this "portable" code is only used on big-endian ISAs
 */
#if !defined(_BIG_ENDIAN) || defined(_LITTLE_ENDIAN)
#error	"big-endian only!"
#endif

/*
 * Convert a double precision floating point number into a 64-bit int.
 */
long long
__dtoll(double dval)
{
	int i0, i1;		/* bitslam */
	int exp;		/* exponent */
	int m0;			/* most significant word of mantissa */
	unsigned int m1;	/* least sig. word of mantissa */
	unsigned int _fp_current_exceptions = 0;
	union {
		int i[2];
		double d;
	} u;

	/*
	 * Extract the exponent and check boundary conditions.
	 * Notice that the exponent is equal to the bit number where
	 * we want the most significant bit to live.
	 */
	u.d = dval;
	i0 = u.i[0];
	i1 = u.i[1];

	exp = ((i0 >> 20) & 0x7ff) - 0x3ff;
	if (exp < 0) {
		return ((long long)0); /* abs(x) < 1.0, so round to 0 */
	} else if (exp > 62) {
		/*
		 * fp_invalid NOT raised if <i0,i1> == LLONG_MIN
		 */
		if (i0 >= 0 || exp != 63 || (i0 & 0xfffff) != 0 || i1 != 0) {
			/*
			 * abs(x) > MAXLLONG; return {MIN,MAX}LLONG and as
			 * overflow, Inf, NaN set fp_invalid exception
			 */
			_fp_current_exceptions |= (1 << (int)fp_invalid);
			(void) _Q_set_exception(_fp_current_exceptions);
		}
		if (i0 < 0)
			return (LLONG_MIN);
		else
			return (LLONG_MAX); /* MAXLONG */
	}

	/* Extract the mantissa. */

	m0 = 0x40000000 | ((i0 << 10) & 0x3ffffc00) | ((i1 >> 22) & 0x3ff);
	m1 = i1 << 10;

	/*
	 * The most significant bit of the mantissa is now in bit 62 of m0:m1.
	 * Shift right by (62 - exp) bits.
	 */
	switch (exp) {
	case 62:
		break;
	case 30:
		m1 = m0;
		m0 = 0;
		break;
	default:
		if (exp > 30) {
			m1 = (m0 << (exp - 30)) |
			    (m1 >> (62 - exp)) & ~(-1 << (exp - 30));
			m0 >>= 62 - exp;
		} else {
			m1 = m0 >> (30 - exp);
			m0 = 0;
		}
		break;
	}

	if (i0 < 0) {
		m0 = ~m0;
		m1 = ~m1;
		if (++m1 == 0)
			m0++;
	}

	(void) _Q_set_exception(_fp_current_exceptions);
	return ((long long)(((unsigned long long)m0 << 32) | m1));
}

/*
 * Convert a floating point number into a 64-bit int.
 */
long long
__ftoll(float fval)
{
	int i0;
	int exp;		/* exponent */
	int m0;			/* most significant word of mantissa */
	unsigned int m1;	/* least sig. word of mantissa */
	unsigned int _fp_current_exceptions = 0;
	union {
		int i;
		float f;
	} u;

	/*
	 * Extract the exponent and check boundary conditions.
	 * Notice that the exponent is equal to the bit number where
	 * we want the most significant bit to live.
	 */
	u.f = fval;
	i0 = u.i;

	exp = ((i0 >> 23) & 0xff) - 0x7f;
	if (exp < 0) {
		return ((long long) 0); /* abs(x) < 1.0, so round to 0 */
	} else if (exp > 62)  {
		/*
		 * fp_invalid NOT raised if <i0> == LLONG_MIN
		 */
		if (i0 >= 0 || exp != 63 || (i0 & 0x7fffff) != 0) {
			/*
			 * abs(x) > MAXLLONG; return {MIN,MAX}LLONG and as
			 * overflow, Inf, NaN set fp_invalid exception
			 */
			_fp_current_exceptions |= (1 << (int)fp_invalid);
			(void) _Q_set_exception(_fp_current_exceptions);
		}
		if (i0 < 0)
			return (LLONG_MIN);
		else
			return (LLONG_MAX); /* MAXLONG */
	}

	/* Extract the mantissa. */

	m0 = 0x40000000 | (i0 << 7) & 0x3fffff80;
	m1 = 0;

	/*
	 * The most significant bit of the mantissa is now in bit 62 of m0:m1.
	 * Shift right by (62 - exp) bits.
	 */
	switch (exp) {
	case 62:
		break;
	case 30:
		m1 = m0;
		m0 = 0;
		break;
	default:
		if (exp > 30) {
			m1 = m0 << (exp - 30);
			m0 >>= 62 - exp;
		} else {
			m1 = m0 >> (30 - exp);
			m0 = 0;
		}
		break;
	}

	if (i0 < 0) {
		m0 = ~m0;
		m1 = ~m1;
		if (++m1 == 0)
			m0++;
	}

	(void) _Q_set_exception(_fp_current_exceptions);
	return ((long long)(((unsigned long long)m0 << 32) | m1));
}

/*
 * Convert an extended precision floating point number into a 64-bit int.
 */
long long
_Q_qtoll(long double longdbl)
{
	int i0;
	unsigned int i1, i2;	/* a long double is 128-bit in length */
	int *plngdbl = (int *)&longdbl;
	int exp;		/* exponent */
	int m0;			/* most significant word of mantissa */
	unsigned int m1;	/* least sig. word of mantissa */
	unsigned int _fp_current_exceptions = 0;

	/*
	 * Only 96-bits of precision used
	 */
	i0 = plngdbl[0];
	i1 = plngdbl[1];
	i2 = plngdbl[2];

	/*
	 * Extract the exponent and check boundary conditions.
	 * Notice that the exponent is equal to the bit number where
	 * we want the most significant bit to live.
	 */
	exp = ((i0 >> 16) & 0x7fff) - 0x3fff;
	if (exp < 0) {
		return ((long long)0); /* abs(x) < 1.0, so round to 0 */
	} else if (exp > 62)	{
		/*
		 * fp_invalid NOT raised if <i0,i1,i2,i3> when chopped to
		 * 64 bits == LLONG_MIN
		 */
		if (i0 >= 0 || exp != 63 || (i0 & 0xffff) != 0 || i1 != 0 ||
		    (i2 & 0xfffe0000) != 0) {
			/*
			 * abs(x) > MAXLLONG; return {MIN,MAX}LLONG and as
			 * overflow, Inf, NaN set fp_invalid exception
			 */
			_fp_current_exceptions |= (1 << (int)fp_invalid);
			(void) _Q_set_exception(_fp_current_exceptions);
		}
		if (i0 < 0)
			return (LLONG_MIN);
		else
			return (LLONG_MAX); /* MAXLONG */
	}

	/* Extract the mantissa. */

	m0 = 0x40000000 | ((i0 << 14) & 0x3fffc000) | ((i1 >> 18) & 0x3fff);
	m1 = (i1 << 14) | ((i2 >> 18) & 0x3fff);

	/*
	 * The most significant bit of the mantissa is now in bit 62 of m0:m1.
	 * Shift right by (62 - exp) bits.
	 */
	switch (exp) {
	case 62:
		break;
	case 30:
		m1 = m0;
		m0 = 0;
		break;
	default:
		if (exp > 30) {
			m1 = (m0 << (exp - 30)) |
			    (m1 >> (62 - exp)) & ~(-1 << (exp - 30));
			m0 >>= 62 - exp;
		} else {
			m1 = m0 >> (30 - exp);
			m0 = 0;
		}
		break;
	}

	if (i0 < 0) {
		m0 = ~m0;
		m1 = ~m1;
		if (++m1 == 0)
			m0++;
	}

	(void) _Q_set_exception(_fp_current_exceptions);
	return ((long long)(((unsigned long long)m0 << 32) | m1));
}
