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

/* Functions in this file are duplicated in locallibm.il.  Keep them in sync */

#ifndef _LIBM_INLINES_H
#define	_LIBM_INLINES_H

#ifdef __GNUC__

#include <sys/types.h>
#include <sys/ieeefp.h>

#ifdef __cplusplus
extern "C" {
#endif

extern __GNU_INLINE double
__inline_sqrt(double d)
{
	double ret;

	__asm__ __volatile__("fsqrtd %1,%0\n\t" : "=e" (ret) : "e" (d));
	return (ret);
}

extern __GNU_INLINE float
__inline_sqrtf(float f)
{
	float ret;

	__asm__ __volatile__("fsqrts %1,%0\n\t" : "=f" (ret) : "f" (f));
	return (ret);
}

extern __GNU_INLINE enum fp_class_type
fp_classf(float f)
{
	enum fp_class_type ret;
	uint32_t tmp;

	/* XXX: Separate input and output */
	__asm__ __volatile__(
	    "sethi  %%hi(0x80000000),%1\n\t"
	    "andncc %2,%1,%0\n\t"
	    "bne    1f\n\t"
	    "nop\n\t"
	    "mov    0,%0\n\t"
	    "ba	2f\n\t"		/* x is 0 */
	    "nop\n\t"
	    "1:\n\t"
	    "sethi  %%hi(0x7f800000),%1\n\t"
	    "andcc  %0,%1,%%g0\n\t"
	    "bne    1f\n\t"
	    "nop\n\t"
	    "mov    1,%0\n\t"
	    "ba	    2f\n\t"	/* x is subnormal */
	    "nop\n\t"
	    "1:\n\t"
	    "cmp    %0,%1\n\t"
	    "bge    1f\n\t"
	    "nop\n\t"
	    "mov    2,%0\n\t"
	    "ba	    2f\n\t"	/* x is normal */
	    "nop\n\t"
	    "1:\n\t"
	    "bg	    1f\n\t"
	    "nop\n\t"
	    "mov    3,%0\n\t"
	    "ba	    2f\n\t"	/* x is __infinity */
	    "nop\n\t"
	    "1:\n\t"
	    "sethi  %%hi(0x00400000),%1\n\t"
	    "andcc  %0,%1,%%g0\n\t"
	    "mov    4,%0\n\t"	/* x is quiet NaN */
	    "bne    2f\n\t"
	    "nop\n\t"
	    "mov    5,%0\n\t"	/* x is signaling NaN */
	    "2:\n\t"
	    : "=r" (ret), "=&r" (tmp)
	    : "r" (f)
	    : "cc");
	return (ret);
}

#define	_HI_WORD(x)	((uint32_t *)&x)[0]
#define	_LO_WORD(x)	((uint32_t *)&x)[1]

extern __GNU_INLINE enum fp_class_type
fp_class(double d)
{
	enum fp_class_type ret;
	uint32_t tmp;

	__asm__ __volatile__(
	    "sethi %%hi(0x80000000),%1\n\t"	/* %1 gets 80000000 */
	    "andn  %2,%1,%0\n\t"		/* %2-%0 gets abs(x) */
	    "orcc  %0,%3,%%g0\n\t"		/* set cc as x is zero/nonzero */
	    "bne   1f\n\t"			/* branch if x is nonzero */
	    "nop\n\t"
	    "mov   0,%0\n\t"
	    "ba	   2f\n\t"			/* x is 0 */
	    "nop\n\t"
	    "1:\n\t"
	    "sethi %%hi(0x7ff00000),%1\n\t"	/* %1 gets 7ff00000 */
	    "andcc %0,%1,%%g0\n\t"		/* cc set by __exp field of x */
	    "bne   1f\n\t"			/* branch if normal or max __exp */
	    "nop\n\t"
	    "mov   1,%0\n\t"
	    "ba	   2f\n\t"			/* x is subnormal */
	    "nop\n\t"
	    "1:\n\t"
	    "cmp   %0,%1\n\t"
	    "bge   1f\n\t"			/* branch if x is max __exp */
	    "nop\n\t"
	    "mov   2,%0\n\t"
	    "ba	   2f\n\t"			/* x is normal */
	    "nop\n\t"
	    "1:\n\t"
	    "andn  %0,%1,%0\n\t"		/* o0 gets msw __significand field */
	    "orcc  %0,%3,%%g0\n\t"		/* set cc by OR __significand */
	    "bne   1f\n\t"			/* Branch if __nan */
	    "nop\n\t"
	    "mov   3,%0\n\t"
	    "ba	   2f\n\t"			/* x is __infinity */
	    "nop\n\t"
	    "1:\n\t"
	    "sethi %%hi(0x00080000),%1\n\t"
	    "andcc %0,%1,%%g0\n\t"		/* set cc by quiet/sig bit */
	    "be	   1f\n\t"			/* Branch if signaling */
	    "nop\n\t"
	    "mov   4,%0\n\t"			/* x is quiet NaN */
	    "ba	   2f\n\t"
	    "nop\n\t"
	    "1:\n\t"
	    "mov   5,%0\n\t"			/* x is signaling NaN */
	    "2:\n\t"
	    : "=&r" (ret), "=&r" (tmp)
	    : "r" (_HI_WORD(d)), "r" (_LO_WORD(d))
	    : "cc");

	return (ret);
}

extern __GNU_INLINE int
__swapEX(int i)
{
	int ret;
	uint32_t fsr;
	uint32_t tmp1, tmp2;

	__asm__ __volatile__(
	    "and  %4,0x1f,%2\n\t" /* tmp1 = %2 = %o1 */
	    "sll  %2,5,%2\n\t"	/* shift input to aexc bit location */
	    ".volatile\n\t"
	    "st   %%fsr,%1\n\t"
	    "ld   %1,%0\n\t"	/* %0 = fsr */
	    "andn %0,0x3e0,%3\n\t" /* tmp2 = %3 = %o2 */
	    "or   %2,%3,%2\n\t"	/* %2 = new fsr */
	    "st	  %2,%1\n\t"
	    "ld	  %1,%%fsr\n\t"
	    "srl  %0,5,%0\n\t"
	    "and  %0,0x1f,%0\n\t" /* %0 = ret = %o0 */
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
	uint32_t tmp1, tmp2, tmp3;

	__asm__ __volatile__(
	    "and  %5,0x3,%0\n\t"
	    "sll  %0,30,%2\n\t"		/* shift input to RD bit location */
	    ".volatile\n\t"
	    "st   %%fsr,%1\n\t"
	    "ld	  %1,%0\n\t"		/* %0 = fsr */
	    "set  0xc0000000,%4\n\t"	/* mask of rounding direction bits */
	    "andn %0,%4,%3\n\t"
	    "or   %2,%3,%2\n\t"		/* %2 = new fsr */
	    "st	  %2,%1\n\t"
	    "ld	  %1,%%fsr\n\t"
	    "srl  %0,30,%0\n\t"
	    "and  %0,0x3,%0\n\t"
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
	uint32_t fsr, tmp1, tmp2;

	__asm__ __volatile__(
	    "and  %4,0x1f,%0\n\t"
	    "sll  %0,23,%2\n\t"		/* shift input to TEM bit location */
	    ".volatile\n\t"
	    "st   %%fsr,%1\n\t"
	    "ld	  %1,%0\n\t"		/* %0 = fsr */
	    "set  0x0f800000,%3\n\t"	/* mask of TEM (Trap Enable Mode bits) */
	    "andn %0,%3,%3\n\t"
	    "or   %2,%3,%2\n\t"		/* %2 = new fsr */
	    "st	  %2,%1\n\t"
	    "ld	  %1,%%fsr\n\t"
	    "srl  %0,23,%0\n\t"
	    "and  %0,0x1f,%0\n\t"
	    ".nonvolatile\n\t"
	    : "=r" (ret), "=m" (fsr), "=r" (tmp1), "=r" (tmp2)
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

#endif	/* __GNUC */

#endif /* _LIBM_INLINES_H */
