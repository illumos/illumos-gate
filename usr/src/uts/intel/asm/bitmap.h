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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _ASM_BITMAP_H
#define	_ASM_BITMAP_H

#include <sys/ccompile.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

#if defined(__amd64)
#define	__SUF	"q"
#elif defined(__i386)
#define	__SUF	"l"
#else
#error "port me"
#endif

extern __GNU_INLINE int
highbit(ulong_t i)
{
	long value = -1l;

	__asm__(
	    "bsr" __SUF " %1,%0"
	    : "+r" (value)
	    : "r" (i)
	    : "cc");

	return ((int)(value + 1));
}

extern __GNU_INLINE int
lowbit(ulong_t i)
{
	long value = -1l;

	__asm__(
	    "bsf" __SUF " %1,%0"
	    : "+r" (value)
	    : "r" (i)
	    : "cc");

	return ((int)(value + 1));
}

extern __GNU_INLINE uint_t
atomic_btr32(uint32_t *memory, uint_t bitnum)
{
	uint8_t value;

	__asm__ __volatile__(
	    "lock;"
	    "btrl %2,%0;"
	    "setc %1"
	    : "+m" (*memory), "=r" (value)
	    : "ir" (bitnum)
	    : "cc");

	return ((uint_t)value);
}

#undef __SUF

#endif	/* !__lint && __GNUC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM_BITMAP_H */
