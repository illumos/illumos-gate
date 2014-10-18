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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2011, Richard Lowe
 */

/* Functions in this file are duplicated in locallibm.il.  Keep them in sync */

#ifndef _LIBM_INLINES_H
#define	_LIBM_INLINES_H

#ifdef __GNUC__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ieeefp.h>

#define	_LO_WORD(x)	((uint32_t *)&x)[0]
#define	_HI_WORD(x)	((uint32_t *)&x)[1]
#define	_HIER_WORD(x)	((uint32_t *)&x)[2]

extern __inline__ double
__inline_sqrt(double a)
{
	double ret;

	__asm__ __volatile__("fsqrt\n\t" : "=t" (ret) : "0" (a) : "cc");
	return (ret);
}

extern __inline__ double
__ieee754_sqrt(double a)
{
	return (__inline_sqrt(a));
}

extern __inline__ float
__inline_sqrtf(float a)
{
	float ret;

	__asm__ __volatile__("fsqrt\n\t" : "=t" (ret) : "0" (a) : "cc");
	return (ret);
}

extern __inline__ double
__inline_rint(double a)
{
	__asm__ __volatile__(
	    "andl $0x7fffffff,%1\n\t"
	    "cmpl $0x43300000,%1\n\t"
	    "jae  1f\n\t"
	    "frndint\n\t"
	    "1: fwait\n\t"
	    : "+t" (a), "+&r" (_HI_WORD(a))
	    :
	    : "cc");

	return (a);
}

/*
 * 00 - 24 bits
 * 01 - reserved
 * 10 - 53 bits
 * 11 - 64 bits
 */
extern __inline__ int
__swapRP(int i)
{
	int ret;
	uint16_t cw;

	__asm__ __volatile__("fstcw %0\n\t" : "=m" (cw));

	ret = (cw >> 8) & 0x3;
	cw = (cw & 0xfcff) | ((i & 0x3) << 8);

	__asm__ __volatile__("fldcw %0\n\t" : : "m" (cw));

	return (ret);
}

/*
 * 00 - Round to nearest, with even preferred
 * 01 - Round down
 * 10 - Round up
 * 11 - Chop
 */
extern __inline__ enum fp_direction_type
__swap87RD(enum fp_direction_type i)
{
	int ret;
	uint16_t cw;

	__asm__ __volatile__("fstcw %0\n\t" : "=m" (cw));

	ret = (cw >> 10) & 0x3;
	cw = (cw & 0xf3ff) | ((i & 0x3) << 10);

	__asm__ __volatile__("fldcw %0\n\t" : : "m" (cw));

	return (ret);
}

extern __inline__ double
ceil(double d)
{
	/*
	 * Let's set a Rounding Control (RC) bits from x87 FPU Control Word
	 * to fp_positive and save old bits in rd.
	 */
	short rd = __swap87RD(fp_positive);

	/*
	 * The FRNDINT instruction returns a floating-point value that is the
	 * integral value closest to the source value in the direction of the
	 * rounding mode specified in the RC field of the x87 FPU control word.
	 *
	 * Rounds the source value in the ST(0) register to the nearest
	 * integral value, depending on the current rounding mode
	 * (setting of the RC field of the FPU control word),
	 * and stores the result in ST(0).
	 */
	__asm__ __volatile__("frndint" : "+t" (d) : : "cc");

	/* restore old RC bits */
	__swap87RD(rd);

	return (d);
}

extern __inline__ double
copysign(double d1, double d2)
{
	__asm__ __volatile__(
	    "andl $0x7fffffff,%0\n\t"	/* %0 <-- hi_32(abs(d)) */
	    "andl $0x80000000,%1\n\t"	/* %1[31] <-- sign_bit(d2) */
	    "orl  %1,%0\n\t"		/* %0 <-- hi_32(copysign(x,y)) */
	    : "+&r" (_HI_WORD(d1)), "+r" (_HI_WORD(d2))
	    :
	    : "cc");

	return (d1);
}

extern __inline__ double
fabs(double d)
{
	__asm__ __volatile__("fabs\n\t" : "+t" (d) : : "cc");
	return (d);
}

extern __inline__ float
fabsf(float d)
{
	__asm__ __volatile__("fabs\n\t" : "+t" (d) : : "cc");
	return (d);
}

extern __inline__ long double
fabsl(long double d)
{
	__asm__ __volatile__("fabs\n\t" : "+t" (d) : : "cc");
	return (d);
}

extern __inline__ int
finite(double d)
{
	int ret = _HI_WORD(d);

	__asm__ __volatile__(
	    "notl %0\n\t"
	    "andl $0x7ff00000,%0\n\t"
	    "negl %0\n\t"
	    "shrl $31,%0\n\t"
	    : "+r" (ret)
	    :
	    : "cc");
	return (ret);
}

extern __inline__ double
floor(double d)
{
	short rd = __swap87RD(fp_negative);

	__asm__ __volatile__("frndint" : "+t" (d), "+r" (rd) : : "cc");
	__swap87RD(rd);

	return (d);
}

/*
 *      branchless __isnan
 *      ((0x7ff00000-[((lx|-lx)>>31)&1]|ahx)>>31)&1 = 1 iff x is NaN
 */
extern __inline__ int
isnan(double d)
{
	int ret;

	__asm__ __volatile__(
		"movl %1,%%ecx\n\t"
		"negl %%ecx\n\t"			/* ecx <-- -lo_32(x) */
		"orl  %%ecx,%1\n\t"
		"shrl $31,%1\n\t"			/* 1 iff lx != 0 */
		"andl $0x7fffffff,%2\n\t"	/* ecx <-- hi_32(abs(x)) */
		"orl  %2,%1\n\t"
		"subl $0x7ff00000,%1\n\t"
		"negl %1\n\t"
		"shrl $31,%1\n\t"
		: "=r" (ret)
		: "0" (_HI_WORD(d)), "r" (_LO_WORD(d))
		: "ecx");

	return (ret);
}

extern __inline__ int
isnanf(float f)
{
	__asm__ __volatile__(
	    "andl $0x7fffffff,%0\n\t"
	    "negl %0\n\t"
	    "addl $0x7f800000,%0\n\t"
	    "shrl $31,%0\n\t"
	    : "+r" (f)
	    :
	    : "cc");

	return (f);
}

extern __inline__ double
rint(double a) {
    return (__inline_rint(a));
}

extern __inline__ double
scalbn(double d, int n)
{
	double dummy;

	__asm__ __volatile__(
	    "fildl %2\n\t"	/* Convert N to extended */
	    "fxch\n\t"
	    "fscale\n\t"
	    : "+t" (d), "=u" (dummy)
	    : "m" (n)
	    : "cc");

	return (d);
}

extern __inline__ int
signbit(double d)
{
	return (_HI_WORD(d) >> 31);
}

extern __inline__ int
signbitf(float f)
{
	return ((*(uint32_t *)&f) >> 31);
}

extern __inline__ double
sqrt(double d)
{
	return (__inline_sqrt(d));
}

extern __inline__ float
sqrtf(float f)
{
	return (__inline_sqrtf(f));
}

extern __inline__ long double
sqrtl(long double ld)
{
	__asm__ __volatile__("fsqrt" : "+t" (ld) : : "cc");
	return (ld);
}

extern __inline__ int
isnanl(long double ld)
{
	int ret = _HIER_WORD(ld);

	__asm__ __volatile__(
	    "andl  $0x00007fff,%0\n\t"
	    "jz	   1f\n\t"		/* jump if exp is all 0 */
	    "xorl  $0x00007fff,%0\n\t"
	    "jz	   2f\n\t"		/* jump if exp is all 1 */
	    "testl $0x80000000,%1\n\t"
	    "jz	   3f\n\t"		/* jump if leading bit is 0 */
	    "xorl  %0,%0\n\t"
	    "jmp   1f\n\t"
	    "2:\n\t"			/* note that %0 = 0 from before */
	    "cmpl  $0x80000000,%1\n\t"	/* what is first half of significand? */
	    "jnz   3f\n\t"		/* jump if not equal to 0x80000000 */
	    "testl $0xffffffff,%2\n\t"	/* is second half of significand 0? */
	    "jnz   3f\n\t"		/* jump if not equal to 0 */
	    "jmp   1f\n\t"
	    "3:\n\t"
	    "movl  $1,%0\n\t"
	    "1:\n\t"
	    : "+&r" (ret)
	    : "r" (_HI_WORD(ld)), "r" (_LO_WORD(ld))
	    : "cc");

	return (ret);
}

#ifdef __cplusplus
}
#endif

#endif  /* __GNUC__ */

#endif /* _LIBM_INLINES_H */
