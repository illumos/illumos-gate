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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BASE_INLINES_H
#define	_BASE_INLINES_H

#include <sys/ccompile.h>
#include <sys/types.h>

#if !defined(__lint) && defined(__GNUC__)

/*
 * This file is intended to contain gcc-style inline assembly that corresponds
 * to base.il for all architectures.  At the moment these inlines exist only
 * for sparc and sparcv9 and these functions are implemented in C for x86.
 * They should be inlined here for gcc if a new x86 base.il is created.
 */

#if defined(__sparc)
extern __GNU_INLINE double
__mul_set(double x, double y, int *pe)
{
	double __result;
	uint32_t __fsr;
	uint32_t *__addr = &__fsr;

	__asm__ __volatile__(
	    "fmuld %4, %5, %0\n\t"
	    "st %%fsr, %3\n\t"
	    "ld %3, %2\n\t"
	    "and %2, 1, %2\n\t"
	    "st %2, %1"
	    : "=&e" (__result), "=m" (*pe), "=r" (__fsr), "=m" (*__addr)
	    : "e" (x), "e" (y));
	return (__result);
}
#endif	/* __sparc */

#if defined(__sparc)
extern __GNU_INLINE double
__div_set(double x, double y, int *pe)
{
	double __result;
	uint32_t __fsr;
	uint32_t *__addr = &__fsr;

	__asm__ __volatile__(
	    "fdivd %4, %5, %0\n\t"
	    "st %%fsr, %3\n\t"
	    "ld %3, %2\n\t"
	    "and %2, 1, %2\n\t"
	    "st %2, %1"
	    : "=&e" (__result), "=m" (*pe), "=r" (__fsr), "=m" (*__addr)
	    : "e" (x), "e" (y));
	return (__result);
}
#endif	/* __sparc */

#if defined(__sparc)
extern __GNU_INLINE double
__dabs(double *x)
{
	double __result;

	__asm__ __volatile__(
#if defined(__sparcv9)
	    "fabsd %1, %0"
#else
	    "fabss %1, %0"
#endif
	    : "=e" (__result)
	    : "0" (*x));
	return (__result);
}
#endif	/* __sparc */

#if defined(__sparc)
extern  __GNU_INLINE void
__get_ieee_flags(__ieee_flags_type *b)
{
	uint32_t __fsr;

	/*
	 * It's preferable to let the assembler insert the nops as
	 * needed; however, it warns as it does so.  Add them here for now.
	 */
	__asm__ __volatile__(
	    "st %%fsr, %0\n\t"
	    "st %%g0, %1\n\t"
	    "ld %1, %%fsr\n\t"
	    "nop; nop; nop"
	    : "=m" (*b), "=m" (__fsr));
}
#endif	/* __sparc */

#if defined(__sparc)
extern __GNU_INLINE void
__set_ieee_flags(__ieee_flags_type *b)
{
	/*
	 * It's preferable to let the assembler insert the nops as
	 * needed; however, it warns as it does so.  Add them here for now.
	 */
	__asm__ __volatile__(
	    "ld %0, %%fsr\n\t"
	    "nop; nop; nop"
	    : /* no outputs */
	    : "m" (*b));
}
#endif	/* __sparc */

#endif	/* !__lint && __GNUC__ */

#endif	/* _BASE_INLINES_H */
