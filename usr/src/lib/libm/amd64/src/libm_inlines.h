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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2011, Richard Lowe.
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

extern __inline__ float
__inline_sqrtf(float a)
{
	float ret;

	__asm__ __volatile__("sqrtss %1, %0\n\t" : "=x" (ret) : "x" (a));
	return (ret);
}

extern __inline__ double
__inline_sqrt(double a)
{
	double ret;

	__asm__ __volatile__("sqrtsd %1, %0\n\t" : "=x" (ret) : "x" (a));
	return (ret);
}

extern __inline__ double
__ieee754_sqrt(double a)
{
	return (__inline_sqrt(a));
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

extern __inline__ int
abs(int i)
{
	int ret;
	__asm__ __volatile__(
	    "movl    %1, %0\n\t"
	    "negl    %1\n\t"
	    "cmovnsl %1, %0\n\t"
	    : "=r" (ret), "+r" (i)
	    :
	    : "cc");
	return (ret);
}

extern __inline__ double
copysign(double d1, double d2)
{
	double tmpd;

	__asm__ __volatile__(
	    "movd %3, %1\n\t"
	    "andpd %1, %0\n\t"
	    "andnpd %2, %1\n\t"
	    "orpd %1, %0\n\t"
	    : "+&x" (d1), "=&x" (tmpd)
	    : "x" (d2), "r" (0x7fffffffffffffff));

	return (d1);
}

extern __inline__ double
fabs(double d)
{
	double tmp;

	__asm__ __volatile__(
	    "movd  %2, %1\n\t"
	    "andpd %1, %0"
	    : "+x" (d), "=&x" (tmp)
	    : "r" (0x7fffffffffffffff));

	return (d);
}

extern __inline__ float
fabsf(float d)
{
	__asm__ __volatile__(
	    "andpd %1, %0"
	    : "+x" (d)
	    : "x" (0x7fffffff));

	return (d);
}

extern __inline__ int
finite(double d)
{
	long ret = 0x7fffffffffffffff;
	uint64_t tmp;

	__asm__ __volatile__(
	    "movq %2, %1\n\t"
	    "andq %1, %0\n\t"
	    "movq $0x7ff0000000000000, %1\n\t"
	    "subq %1, %0\n\t"
	    "shrq $63, %0\n\t"
	    : "+r" (ret), "=r" (tmp)
	    : "x" (d)
	    : "cc");

	return (ret);
}

extern __inline__ int
signbit(double d)
{
	long ret;
	__asm__ __volatile__(
	    "movmskpd %1, %0\n\t"
	    "andq     $1, %0\n\t"
	    : "=r" (ret)
	    : "x" (d)
	    : "cc");
	return (ret);
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

#ifdef __cplusplus
}
#endif

#endif  /* __GNUC__ */

#endif /* _LIBM_INLINES_H */
