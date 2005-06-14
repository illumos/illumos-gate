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

#ifndef	_SYS_MACHTHREAD_H
#define	_SYS_MACHTHREAD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asi.h>
#include <sys/sun4asi.h>
#include <sys/machasi.h>
#include <sys/bitmap.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_ASM

#define	THREAD_REG	%g7		/* pointer to current thread data */

/*
 * CPU_INDEX(r, scr)
 * Returns cpu id in r.
 */
#define	CPU_INDEX(r, scr)		\
	mov	SCRATCHPAD_CPUID, scr;	\
	ldxa	[scr]ASI_SCRATCHPAD, r

/*
 * Given a cpu id extract the appropriate word
 * in the cpuset mask for this cpu id.
 */
#if CPUSET_SIZE > CLONGSIZE
#define	CPU_INDEXTOSET(base, index, scr)	\
	srl	index, BT_ULSHIFT, scr;		\
	and	index, BT_ULMASK, index;	\
	sll	scr, CLONGSHIFT, scr;		\
	add	base, scr, base
#else
#define	CPU_INDEXTOSET(base, index, scr)
#endif	/* CPUSET_SIZE */


/*
 * Assembly macro to find address of the current CPU.
 * Used when coming in from a user trap - cannot use THREAD_REG.
 * Args are destination register and one scratch register.
 */
#define	CPU_ADDR(reg, scr) 		\
	.global	cpu;			\
	CPU_INDEX(scr, reg);		\
	sll	scr, CPTRSHIFT, scr;	\
	set	cpu, reg;		\
	ldn	[reg + scr], reg

#define	CINT64SHIFT	3

/*
 * Assembly macro to find the physical address of the current CPU.
 * All memory references using VA must be limited to nucleus
 * memory to avoid any MMU side effect.
 */
#define	CPU_PADDR(reg, scr)				\
	.global cpu_pa;					\
	CPU_INDEX(scr, reg);				\
	sll	scr, CINT64SHIFT, scr;			\
	set	cpu_pa, reg;				\
	ldx	[reg + scr], reg

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHTHREAD_H */
