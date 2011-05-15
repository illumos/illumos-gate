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

#ifndef _ASM_ATOMIC_H
#define	_ASM_ATOMIC_H

#include <sys/ccompile.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

#if defined(__amd64)

extern __GNU_INLINE void
atomic_or_long(ulong_t *target, ulong_t bits)
{
	__asm__ __volatile__(
	    "lock; orq %1, (%0)"
	    : /* no output */
	    : "r" (target), "r" (bits));
}

extern __GNU_INLINE void
atomic_and_long(ulong_t *target, ulong_t bits)
{
	__asm__ __volatile__(
	    "lock; andq %1, (%0)"
	    : /* no output */
	    : "r" (target), "r" (bits));
}

#ifdef notdef
extern __GNU_INLINE uint64_t
cas64(uint64_t *target, uint64_t cmp,
	uint64_t newval)
{
	uint64_t retval;

	__asm__ __volatile__(
	    "movq %2, %%rax; lock; cmpxchgq %3, (%1)"
	    : "=a" (retval)
	    : "r" (target), "r" (cmp), "r" (newval));
	return (retval);
}
#endif

#elif defined(__i386)

extern __GNU_INLINE void
atomic_or_long(ulong_t *target, ulong_t bits)
{
	__asm__ __volatile__(
	    "lock; orl %1, (%0)"
	    : /* no output */
	    : "r" (target), "r" (bits));
}

extern __GNU_INLINE void
atomic_and_long(ulong_t *target, ulong_t bits)
{
	__asm__ __volatile__(
	    "lock; andl %1, (%0)"
	    : /* no output */
	    : "r" (target), "r" (bits));
}

#else
#error	"port me"
#endif

#endif /* !__lint && __GNUC__ */

#ifdef __cplusplus
}
#endif

#endif	/* _ASM_ATOMIC_H */
