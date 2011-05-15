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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ASM_BITMAP_H
#define	_ASM_BITMAP_H

#include <sys/ccompile.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

extern __GNU_INLINE int
highbit(ulong_t i)
{
	long __value = -1l;

#if defined(__amd64)
	__asm__(
	    "bsrq	%1,%0"
	    : "+r" (__value)
	    : "r" (i)
	    : "cc");
#elif defined(__i386)
	__asm__(
	    "bsrl	%1,%0"
	    : "+r" (__value)
	    : "r" (i)
	    : "cc");
#else
#error	"port me"
#endif
	return ((int)(__value + 1));
}

extern __GNU_INLINE int
lowbit(ulong_t i)
{
	long __value = -1l;

#if defined(__amd64)
	__asm__(
	    "bsfq	%1,%0"
	    : "+r" (__value)
	    : "r" (i)
	    : "cc");
#elif defined(__i386)
	__asm__(
	    "bsfl	%1,%0"
	    : "+r" (__value)
	    : "r" (i)
	    : "cc");
#else
#error	"port me"
#endif
	return ((int)(__value + 1));
}

extern __GNU_INLINE uint_t
atomic_btr32(uint32_t *memory, uint_t bitnum)
{
	uint8_t __value;

#if defined(__amd64)
	__asm__ __volatile__(
	    "lock;"
	    "btrl %2, (%0);"
	    "setc %1"
	    : "+r" (memory), "+r" (__value)
	    : "ir" (bitnum)
	    : "cc");
#elif defined(__i386)
	__asm__ __volatile__(
	    "lock;"
	    "btrl %2, (%0);"
	    "setc %1"
	    : "+r" (memory), "=r" (__value)
	    : "ir" (bitnum)
	    : "cc");
#else
#error	"port me"
#endif
	return ((uint_t)__value);
}

#endif	/* !__lint && __GNUC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM_BITMAP_H */
