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
 * Copyright 2011, Richard Lowe.
 */

#ifndef _LIBM_INLINES_H
#define	_LIBM_INLINES_H

#ifdef __GNUC__

#include <sys/types.h>
#include <sys/ieeefp.h>

#ifdef __cplusplus
extern "C" {
#endif

extern __GNU_INLINE enum fp_class_type
fp_classf(float f)
{
	enum fp_class_type ret;
	int fint;		/* scratch for f as int */
	uint64_t tmp;

	__asm__ __volatile__(
	    "fabss  %3,%3\n\t"
	    "st	    %3,%1\n\t"
	    "ld	    %1,%0\n\t"
	    "orcc   %%g0,%0,%%g0\n\t"
	    "be,pn  %%icc,2f\n\t"
	    "nop\n\t"
	    "1:\n\t"
	    "sethi  %%hi(0x7f800000),%2\n\t"
	    "andcc  %0,%2,%%g0\n\t"
	    "bne,pt %%icc,1f\n\t"
	    "nop\n\t"
	    "or	    %%g0,1,%0\n\t"
	    "ba	    2f\n\t"	/* subnormal */
	    "nop\n\t"
	    "1:\n\t"
	    "subcc  %0,%2,%%g0\n\t"
	    "bge,pn %%icc,1f\n\t"
	    "nop\n\t"
	    "or	    %%g0,2,%0\n\t"
	    "ba	    2f\n\t"	/* normal */
	    "nop\n\t"
	    "1:\n\t"
	    "bg,pn  %%icc,1f\n\t"
	    "nop\n\t"
	    "or	    %%g0,3,%0\n\t"
	    "ba	    2f\n\t"	/* infinity */
	    "nop\n\t"
	    "1:\n\t"
	    "sethi  %%hi(0x00400000),%2\n\t"
	    "andcc  %0,%2,%%g0\n\t"
	    "or	    %%g0,4,%0\n\t"
	    "bne,pt %%icc,2f\n\t" /* quiet NaN */
	    "nop\n\t"
	    "or	    %%g0,5,%0\n\t" /* signalling NaN */
	    "2:\n\t"
	    : "=r" (ret), "=m" (fint), "=r" (tmp), "+f" (f)
	    :
	    : "cc");

	return (ret);
}

extern __GNU_INLINE enum fp_class_type
fp_class(double d)
{
	enum fp_class_type ret;
	uint64_t dint;		/* Scratch for d-as-long */
	uint64_t tmp;

	__asm__ __volatile__(
	    "fabsd  %3,%3\n\t"
	    "std    %3,%1\n\t"
	    "ldx    %1,%0\n\t"
	    "orcc   %%g0,%0,%%g0\n\t"
	    "be,pn  %%xcc,2f\n\t"
	    "nop\n\t"
	    "sethi  %%hi(0x7ff00000),%2\n\t"
	    "sllx   %2,32,%2\n\t"
	    "andcc  %0,%2,%%g0\n\t"
	    "bne,pt %%xcc,1f\n\t"
	    "nop\n\t"
	    "or	    %%g0,1,%0\n\t"
	    "ba	    2f\n\t"
	    "nop\n\t"
	    "1:\n\t"
	    "subcc  %0,%2,%%g0\n\t"
	    "bge,pn %%xcc,1f\n\t"
	    "nop\n\t"
	    "or	    %%g0,2,%0\n\t"
	    "ba	    2f\n\t"
	    "nop\n\t"
	    "1:\n\t"
	    "andncc %0,%2,%0\n\t"
	    "bne,pn %%xcc,1f\n\t"
	    "nop\n\t"
	    "or	    %%g0,3,%0\n\t"
	    "ba	    2f\n\t"
	    "nop\n\t"
	    "1:\n\t"
	    "sethi  %%hi(0x00080000),%2\n\t"
	    "sllx   %2,32,%2\n\t"
	    "andcc  %0,%2,%%g0\n\t"
	    "or	    %%g0,4,%0\n\t"
	    "bne,pt %%xcc,2f\n\t"
	    "nop\n\t"
	    "or	    %%g0,5,%0\n\t"
	    "2:\n\t"
	    : "=r" (ret), "=m" (dint), "=r" (tmp), "+e" (d)
	    :
	    : "cc");

	return (ret);
}

extern __GNU_INLINE float
__inline_sqrtf(float f)
{
	float ret;

	__asm__ __volatile__("fsqrts %1,%0\n\t" : "=f" (ret) : "f" (f));
	return (ret);
}

extern __GNU_INLINE double
__inline_sqrt(double d)
{
	double ret;

	__asm__ __volatile__("fsqrtd %1,%0\n\t" : "=f" (ret) : "f" (d));
	return (ret);
}

extern __GNU_INLINE int
__swapEX(int i)
{
	int ret;
	uint32_t fsr;
	uint64_t tmp1, tmp2;

	__asm__ __volatile__(
	    "and  %4,0x1f,%2\n\t"
	    "sll  %2,5,%2\n\t"	/* shift input to aexc bit location */
	    ".volatile\n\t"
	    "st   %%fsr,%1\n\t"
	    "ld	  %1,%0\n\t"	/* %0 = fsr */
	    "andn %0,0x3e0,%3\n\t"
	    "or   %2,%3,%2\n\t"	/* %2 = new fsr */
	    "st	  %2,%1\n\t"
	    "ld	  %1,%%fsr\n\t"
	    "srl  %0,5,%0\n\t"
	    "and  %0,0x1f,%0\n\t"
	    ".nonvolatile\n\t"
	    : "=r" (ret), "=m" (fsr), "=r" (tmp1), "=r" (tmp2)
	    : "r" (i)
	    : "cc");

	return (ret);
}

/*
 * On the SPARC, __swapRP is a no-op; always return 0 for backward
 * compatibility
 */
/* ARGSUSED */
extern __GNU_INLINE enum fp_precision_type
__swapRP(enum fp_precision_type i)
{
	return (0);
}

extern __GNU_INLINE enum fp_direction_type
__swapRD(enum fp_direction_type d)
{
	enum fp_direction_type ret;
	uint32_t fsr;
	uint64_t tmp1, tmp2, tmp3;

	__asm__ __volatile__(
	    "and   %5,0x3,%0\n\t"
	    "sll   %0,30,%2\n\t"	/* shift input to RD bit location */
	    ".volatile\n\t"
	    "st    %%fsr,%1\n\t"
	    "ld	   %1,%0\n\t"		/* %0 = fsr */
	    /* mask of rounding direction bits */
	    "sethi %%hi(0xc0000000),%4\n\t"
	    "andn  %0,%4,%3\n\t"
	    "or    %2,%3,%2\n\t"	/* %2 = new fsr */
	    "st	   %2,%1\n\t"
	    "ld	   %1,%%fsr\n\t"
	    "srl   %0,30,%0\n\t"
	    "and   %0,0x3,%0\n\t"
	    ".nonvolatile\n\t"
	    : "=r" (ret), "=m" (fsr), "=r" (tmp1), "=r" (tmp2), "=r" (tmp3)
	    : "r" (d)
	    : "cc");

	return (ret);
}

extern __GNU_INLINE int
__swapTE(int i)
{
	int ret;
	uint32_t fsr;
	uint64_t tmp1, tmp2, tmp3;

	__asm__ __volatile__(
	    "and   %5,0x1f,%0\n\t"
	    "sll   %0,23,%2\n\t"	/* shift input to TEM bit location */
	    ".volatile\n\t"
	    "st    %%fsr,%1\n\t"
	    "ld	   %1,%0\n\t"		/* %0 = fsr */
	    /* mask of TEM (Trap Enable Mode bits) */
	    "sethi %%hi(0x0f800000),%4\n\t"
	    "andn  %0,%4,%3\n\t"
	    "or    %2,%3,%2\n\t"	/* %2 = new fsr */
	    "st	   %2,%1\n\t"
	    "ld	   %1,%%fsr\n\t"
	    "srl   %0,23,%0\n\t"
	    "and   %0,0x1f,%0\n\t"
	    ".nonvolatile\n\t"
	    : "=r" (ret), "=m" (fsr), "=r" (tmp1), "=r" (tmp2), "=r" (tmp3)
	    : "r" (i)
	    : "cc");

	return (ret);
}


extern __GNU_INLINE double
sqrt(double d)
{
	return (__inline_sqrt(d));
}

extern __GNU_INLINE float
sqrtf(float f)
{
	return (__inline_sqrtf(f));
}

extern __GNU_INLINE double
fabs(double d)
{
	double ret;

	__asm__ __volatile__("fabsd %1,%0\n\t" : "=e" (ret) : "e" (d));
	return (ret);
}

extern __GNU_INLINE float
fabsf(float f)
{
	float ret;

	__asm__ __volatile__("fabss %1,%0\n\t" : "=f" (ret) : "f" (f));
	return (ret);
}

#ifdef __cplusplus
}
#endif

#endif  /* __GNUC__ */

#endif /* _LIBM_INLINES_H */
