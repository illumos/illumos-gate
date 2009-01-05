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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ASM_CPU_H
#define	_ASM_CPU_H

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

#if defined(__i386) || defined(__amd64)

extern __inline__ void ht_pause(void)
{
	__asm__ __volatile__(
	    "pause");
}

#if !defined(__xpv)

extern __inline__ void cli(void)
{
	__asm__ __volatile__(
	    "cli" : : : "memory");
}

extern __inline__ void sti(void)
{
	__asm__ __volatile__(
	    "sti");
}

extern __inline__ void i86_halt(void)
{
	__asm__ __volatile__(
	    "sti; hlt");
}

#endif /* !__xpv */

#endif	/* __i386 || defined(__amd64) */

#if defined(__amd64)

extern __inline__ void __set_ds(selector_t value)
{
	__asm__ __volatile__(
	    "movw	%0, %%ds"
	    : /* no output */
	    : "r" (value));
}

extern __inline__ void __set_es(selector_t value)
{
	__asm__ __volatile__(
	    "movw	%0, %%es"
	    : /* no output */
	    : "r" (value));
}

extern __inline__ void __set_fs(selector_t value)
{
	__asm__ __volatile__(
	    "movw	%0, %%fs"
	    : /* no output */
	    : "r" (value));
}

extern __inline__ void __set_gs(selector_t value)
{
	__asm__ __volatile__(
	    "movw	%0, %%gs"
	    : /* no output */
	    : "r" (value));
}

#if !defined(__xpv)

extern __inline__ void __swapgs(void)
{
	__asm__ __volatile__(
	    "mfence; swapgs");
}

#endif /* !__xpv */

#endif	/* __amd64 */

#endif	/* !__lint && __GNUC__ */

#if !defined(__lint) && defined(__GNUC__)

#if defined(__i386) || defined(__amd64)

/*
 * prefetch 64 bytes
 * prefetch is an SSE extension which is not supported on
 * older 32-bit processors, so define this as a no-op for now
 */

extern __inline__ void prefetch64(caddr_t addr)
{
#if defined(__amd64)
	__asm__ __volatile__(
	    "prefetcht0 (%0);"
	    "prefetcht0 32(%0)"
	    : /* no output */
	    : "r" (addr));
#endif	/* __amd64 */
}

#endif	/* __i386 || __amd64 */

#endif	/* !__lint && __GNUC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM_CPU_H */
