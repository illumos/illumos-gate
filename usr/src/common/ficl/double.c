/*
 * m a t h 6 4 . c
 * Forth Inspired Command Language - 64 bit math support routines
 * Authors: Michael A. Gauland (gaulandm@mdhost.cse.tek.com)
 *          Larry Hastings (larry@hastings.org)
 *          John Sadler (john_sadler@alum.mit.edu)
 * Created: 25 January 1998
 * Rev 2.03: Support for 128 bit DP math. This file really ouught to
 * be renamed!
 * $Id: double.c,v 1.2 2010/09/12 15:18:07 asau Exp $
 */
/*
 * Copyright (c) 1997-2001 John Sadler (john_sadler@alum.mit.edu)
 * All rights reserved.
 *
 * Get the latest Ficl release at http://ficl.sourceforge.net
 *
 * I am interested in hearing from anyone who uses Ficl. If you have
 * a problem, a success story, a defect, an enhancement request, or
 * if you would like to contribute to the Ficl release, please
 * contact me by email at the address above.
 *
 * L I C E N S E  and  D I S C L A I M E R
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ficl.h"

#if FICL_PLATFORM_HAS_2INTEGER
ficl2UnsignedQR
ficl2UnsignedDivide(ficl2Unsigned q, ficlUnsigned y)
{
	ficl2UnsignedQR result;

	result.quotient = q / y;
	/*
	 * Once we have the quotient, it's cheaper to calculate the
	 * remainder this way than with % (mod).  --lch
	 */
	result.remainder  = (ficlInteger)(q - (result.quotient * y));

	return (result);
}

#else  /* FICL_PLATFORM_HAS_2INTEGER */

#define	FICL_CELL_HIGH_BIT	((uintmax_t)1 << (FICL_BITS_PER_CELL-1))
#define	UMOD_SHIFT		(FICL_BITS_PER_CELL / 2)
#define	UMOD_MASK		((1L << (FICL_BITS_PER_CELL / 2)) - 1)

/*
 * ficl2IntegerIsNegative
 * Returns TRUE if the specified ficl2Unsigned has its sign bit set.
 */
int
ficl2IntegerIsNegative(ficl2Integer x)
{
	return (x.high < 0);
}

/*
 * ficl2IntegerNegate
 * Negates an ficl2Unsigned by complementing and incrementing.
 */
ficl2Integer
ficl2IntegerNegate(ficl2Integer x)
{
	x.high = ~x.high;
	x.low = ~x.low;
	x.low ++;
	if (x.low == 0)
		x.high++;

	return (x);
}

/*
 * ficl2UnsignedMultiplyAccumulate
 * Mixed precision multiply and accumulate primitive for number building.
 * Multiplies ficl2Unsigned u by ficlUnsigned mul and adds ficlUnsigned add.
 * Mul is typically the numeric base, and add represents a digit to be
 * appended to the growing number.
 * Returns the result of the operation
 */
ficl2Unsigned
ficl2UnsignedMultiplyAccumulate(ficl2Unsigned u, ficlUnsigned mul,
    ficlUnsigned add)
{
	ficl2Unsigned resultLo = ficl2UnsignedMultiply(u.low, mul);
	ficl2Unsigned resultHi = ficl2UnsignedMultiply(u.high, mul);
	resultLo.high += resultHi.low;
	resultHi.low = resultLo.low + add;

	if (resultHi.low < resultLo.low)
		resultLo.high++;

	resultLo.low = resultHi.low;

	return (resultLo);
}

/*
 * ficl2IntegerMultiply
 * Multiplies a pair of ficlIntegers and returns an ficl2Integer result.
 */
ficl2Integer
ficl2IntegerMultiply(ficlInteger x, ficlInteger y)
{
	ficl2Unsigned prod;
	ficl2Integer result;
	int sign = 1;

	if (x < 0) {
		sign = -sign;
		x = -x;
	}

	if (y < 0) {
		sign = -sign;
		y = -y;
	}

	prod = ficl2UnsignedMultiply(x, y);
	FICL_2INTEGER_SET(FICL_2UNSIGNED_GET_HIGH(prod),
	    FICL_2UNSIGNED_GET_LOW(prod), result);
	if (sign > 0)
		return (result);
	else
		return (ficl2IntegerNegate(result));
}

ficl2Integer
ficl2IntegerDecrement(ficl2Integer x)
{
	if (x.low == INTMAX_MIN)
		x.high--;
	x.low--;

	return (x);
}

ficl2Unsigned
ficl2UnsignedAdd(ficl2Unsigned x, ficl2Unsigned y)
{
	ficl2Unsigned result;

	result.high = x.high + y.high;
	result.low = x.low + y.low;

	if (result.low < y.low)
		result.high++;

	return (result);
}

/*
 * ficl2UnsignedMultiply
 * Contributed by:
 * Michael A. Gauland   gaulandm@mdhost.cse.tek.com
 */
ficl2Unsigned
ficl2UnsignedMultiply(ficlUnsigned x, ficlUnsigned y)
{
	ficl2Unsigned result = { 0, 0 };
	ficl2Unsigned addend;

	addend.low = y;
	addend.high = 0; /* No sign extension--arguments are unsigned */

	while (x != 0) {
		if (x & 1) {
			result = ficl2UnsignedAdd(result, addend);
		}
		x >>= 1;
		addend = ficl2UnsignedArithmeticShiftLeft(addend);
	}
	return (result);
}

/*
 *                      ficl2UnsignedSubtract
 */
ficl2Unsigned
ficl2UnsignedSubtract(ficl2Unsigned x, ficl2Unsigned y)
{
	ficl2Unsigned result;

	result.high = x.high - y.high;
	result.low = x.low - y.low;

	if (x.low < y.low) {
		result.high--;
	}

	return (result);
}

/*
 * ficl2UnsignedArithmeticShiftLeft
 * 64 bit left shift
 */
ficl2Unsigned
ficl2UnsignedArithmeticShiftLeft(ficl2Unsigned x)
{
	ficl2Unsigned result;

	result.high = x.high << 1;
	if (x.low & FICL_CELL_HIGH_BIT) {
		result.high++;
	}

	result.low = x.low << 1;

	return (result);
}

/*
 * ficl2UnsignedArithmeticShiftRight
 * 64 bit right shift (unsigned - no sign extend)
 */
ficl2Unsigned
ficl2UnsignedArithmeticShiftRight(ficl2Unsigned x)
{
	ficl2Unsigned result;

	result.low = x.low >> 1;
	if (x.high & 1) {
		result.low |= FICL_CELL_HIGH_BIT;
	}

	result.high = x.high >> 1;
	return (result);
}

/*
 * ficl2UnsignedOr
 * 64 bit bitwise OR
 */
ficl2Unsigned
ficl2UnsignedOr(ficl2Unsigned x, ficl2Unsigned y)
{
	ficl2Unsigned result;

	result.high = x.high | y.high;
	result.low = x.low | y.low;

	return (result);
}

/*
 * ficl2UnsignedCompare
 * Return -1 if x < y; 0 if x==y, and 1 if x > y.
 */
int
ficl2UnsignedCompare(ficl2Unsigned x, ficl2Unsigned y)
{
	if (x.high > y.high)
		return (1);
	if (x.high < y.high)
		return (-1);

	/* High parts are equal */

	if (x.low > y.low)
		return (1);
	else if (x.low < y.low)
		return (-1);

	return (0);
}

/*
 * ficl2UnsignedDivide
 * Portable versions of ficl2Multiply and ficl2Divide in C
 * Contributed by:
 * Michael A. Gauland   gaulandm@mdhost.cse.tek.com
 */
ficl2UnsignedQR
ficl2UnsignedDivide(ficl2Unsigned q, ficlUnsigned y)
{
	ficl2UnsignedQR result;
	ficl2Unsigned quotient;
	ficl2Unsigned subtrahend;
	ficl2Unsigned mask;

	quotient.low = 0;
	quotient.high = 0;

	subtrahend.low = y;
	subtrahend.high = 0;

	mask.low = 1;
	mask.high = 0;

	while ((ficl2UnsignedCompare(subtrahend, q) < 0) &&
	    (subtrahend.high & FICL_CELL_HIGH_BIT) == 0) {
		mask = ficl2UnsignedArithmeticShiftLeft(mask);
		subtrahend = ficl2UnsignedArithmeticShiftLeft(subtrahend);
	}

	while (mask.low != 0 || mask.high != 0) {
		if (ficl2UnsignedCompare(subtrahend, q) <= 0) {
			q = ficl2UnsignedSubtract(q, subtrahend);
			quotient = ficl2UnsignedOr(quotient, mask);
		}
		mask = ficl2UnsignedArithmeticShiftRight(mask);
		subtrahend = ficl2UnsignedArithmeticShiftRight(subtrahend);
	}

	result.quotient = quotient;
	result.remainder = q.low;
	return (result);
}
#endif /* !FICL_PLATFORM_HAS_2INTEGER */

/*
 * ficl2IntegerDivideFloored
 *
 * FROM THE FORTH ANS...
 * Floored division is integer division in which the remainder carries
 * the sign of the divisor or is zero, and the quotient is rounded to
 * its arithmetic floor. Symmetric division is integer division in which
 * the remainder carries the sign of the dividend or is zero and the
 * quotient is the mathematical quotient rounded towards zero or
 * truncated. Examples of each are shown in tables 3.3 and 3.4.
 *
 * Table 3.3 - Floored Division Example
 * Dividend        Divisor Remainder       Quotient
 * --------        ------- ---------       --------
 *  10                7       3                1
 * -10                7       4               -2
 *  10               -7      -4               -2
 * -10               -7      -3                1
 *
 *
 * Table 3.4 - Symmetric Division Example
 * Dividend        Divisor Remainder       Quotient
 * --------        ------- ---------       --------
 *  10                7       3                1
 * -10                7      -3               -1
 *  10               -7       3               -1
 * -10               -7      -3                1
 */
ficl2IntegerQR
ficl2IntegerDivideFloored(ficl2Integer num, ficlInteger den)
{
	ficl2IntegerQR qr;
	ficl2UnsignedQR uqr;
	ficl2Unsigned u;
	int signRem = 1;
	int signQuot = 1;

	if (ficl2IntegerIsNegative(num)) {
		num = ficl2IntegerNegate(num);
		signQuot = -signQuot;
	}

	if (den < 0) {
		den = -den;
		signRem = -signRem;
		signQuot = -signQuot;
	}

	FICL_2UNSIGNED_SET(FICL_2UNSIGNED_GET_HIGH(num),
	    FICL_2UNSIGNED_GET_LOW(num), u);
	uqr = ficl2UnsignedDivide(u, (ficlUnsigned)den);
	qr = FICL_2UNSIGNEDQR_TO_2INTEGERQR(uqr);
	if (signQuot < 0) {
		qr.quotient = ficl2IntegerNegate(qr.quotient);
		if (qr.remainder != 0) {
			qr.quotient = ficl2IntegerDecrement(qr.quotient);
			qr.remainder = den - qr.remainder;
		}
	}

	if (signRem < 0)
		qr.remainder = -qr.remainder;

	return (qr);
}

/*
 * ficl2IntegerDivideSymmetric
 * Divide an ficl2Unsigned by a ficlInteger and return a ficlInteger quotient
 * and a ficlInteger remainder. The absolute values of quotient and remainder
 * are not affected by the signs of the numerator and denominator
 * (the operation is symmetric on the number line)
 */
ficl2IntegerQR
ficl2IntegerDivideSymmetric(ficl2Integer num, ficlInteger den)
{
	ficl2IntegerQR qr;
	ficl2UnsignedQR uqr;
	ficl2Unsigned u;
	int signRem = 1;
	int signQuot = 1;

	if (ficl2IntegerIsNegative(num)) {
		num = ficl2IntegerNegate(num);
		signRem  = -signRem;
		signQuot = -signQuot;
	}

	if (den < 0) {
		den = -den;
		signQuot = -signQuot;
	}

	FICL_2UNSIGNED_SET(FICL_2UNSIGNED_GET_HIGH(num),
	    FICL_2UNSIGNED_GET_LOW(num), u);
	uqr = ficl2UnsignedDivide(u, (ficlUnsigned)den);
	qr = FICL_2UNSIGNEDQR_TO_2INTEGERQR(uqr);
	if (signRem < 0)
		qr.remainder = -qr.remainder;

	if (signQuot < 0)
		qr.quotient = ficl2IntegerNegate(qr.quotient);

	return (qr);
}
