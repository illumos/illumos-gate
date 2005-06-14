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
 * Get the processor implementation from the version register.
 */
#define	GET_CPU_IMPL(out)		\
	rdpr	%ver,	out;		\
	srlx	out, 32, out;		\
	sll	out, 16, out;		\
	srl	out, 16, out;

#ifdef	_STARFIRE
/*
 * CPU_INDEX(r, scr)
 * Returns cpu id in r.
 * On Starfire, this is read from the Port Controller's Port ID
 * register in local space.
 *
 * Need to load the 64 bit address of the PC's PortID reg
 * using only one register. Kludge the 41 bits address constant to
 * be 32bits by shifting it 12 bits to the right first.
 */
#define	LOCAL_PC_PORTID_ADDR_SRL12 0x1FFF4000
#define	PC_PORT_ID 0xD0

#define	CPU_INDEX(r, scr)			\
	rdpr	%pstate, scr;			\
	andn	scr, PSTATE_IE | PSTATE_AM, r;	\
	wrpr	r, 0, %pstate;			\
	set	LOCAL_PC_PORTID_ADDR_SRL12, r;  \
	sllx    r, 12, r;                       \
	or	r, PC_PORT_ID, r;		\
	lduwa	[r]ASI_IO, r;			\
	wrpr	scr, 0, %pstate

#else /* _STARFIRE */

/*
 * UPA supports up to 32 devices while Safari supports up to
 * 1024 devices (utilizing the SSM protocol). Based upon the
 * value of NCPU, a 5- or 10-bit mask will be needed for
 * extracting the cpu id.
 */
#if NCPU > 32
#define	CPU_MASK	0x3ff
#else
#define	CPU_MASK	0x1f
#endif	/* NCPU > 32 */

/*
 * CPU_INDEX(r, scr)
 * Returns cpu id in r.
 * For UPA based systems, the cpu id corresponds to the mid field in
 * the UPA config register. For Safari based machines, the cpu id
 * corresponds to the aid field in the Safari config register.
 *
 * XXX - scr reg is not used here.
 */
#define	CPU_INDEX(r, scr)		\
	ldxa	[%g0]ASI_UPA_CONFIG, r;	\
	srlx	r, 17, r;		\
	and	r, CPU_MASK, r

#endif	/* _STARFIRE */

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
