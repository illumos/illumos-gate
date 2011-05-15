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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ASM_MMU_H
#define	_ASM_MMU_H

#include <sys/ccompile.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && !defined(__xpv)

#if defined(__amd64)

extern __GNU_INLINE ulong_t
getcr3(void)
{
	uint64_t value;

	__asm__ __volatile__(
	    "movq %%cr3, %0"
	    : "=r" (value));
	return (value);
}

extern __GNU_INLINE void
setcr3(ulong_t value)
{
	__asm__ __volatile__(
	    "movq %0, %%cr3"
	    : /* no output */
	    : "r" (value));
}

extern __GNU_INLINE void
reload_cr3(void)
{
	setcr3(getcr3());
}

#elif defined(__i386)

extern __GNU_INLINE ulong_t
getcr3(void)
{
	uint32_t value;

	__asm__ __volatile__(
	    "movl %%cr3, %0"
	    : "=r" (value));
	return (value);
}

extern __GNU_INLINE void
setcr3(ulong_t value)
{
	__asm__ __volatile__(
	    "movl %0, %%cr3"
	    : /* no output */
	    : "r" (value));
}

extern __GNU_INLINE void
reload_cr3(void)
{
	setcr3(getcr3());
}

#endif

#endif /* __GNUC__ && !__xpv */

#ifdef __cplusplus
}
#endif

#endif	/* _ASM_MMU_H */
