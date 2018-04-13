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
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _ASM_MMU_H
#define	_ASM_MMU_H

#include <sys/ccompile.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__GNUC__)

#if !defined(__xpv)

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

extern __GNU_INLINE ulong_t
getcr4(void)
{
	uint64_t value;

	__asm__ __volatile__(
	    "movq %%cr4, %0"
	    : "=r" (value));
	return (value);
}

extern __GNU_INLINE void
setcr4(ulong_t value)
{
	__asm__ __volatile__(
	    "movq %0, %%cr4"
	    : /* no output */
	    : "r" (value));
}

extern __GNU_INLINE void
reload_cr3(void)
{
	setcr3(getcr3());
}

/*
 * We clobber memory: we're not writing anything, but we don't want to
 * potentially get re-ordered beyond the TLB flush.
 */
extern __GNU_INLINE void
invpcid_insn(uint64_t type, uint64_t pcid, uintptr_t addr)
{
	uint64_t pcid_desc[2] = { pcid, addr };
	__asm__ __volatile__(
	    "invpcid %0, %1"
	    : /* no output */
	    : "m" (*pcid_desc), "r" (type)
	    : "memory");
}

#endif /* !__xpv */

extern __GNU_INLINE void
mmu_invlpg(caddr_t addr)
{
	__asm__ __volatile__(
	    "invlpg %0"
	    : "=m" (*addr)
	    : "m" (*addr));
}

#endif /* __GNUC__ */

#ifdef __cplusplus
}
#endif

#endif	/* _ASM_MMU_H */
