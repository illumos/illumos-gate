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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PISADEP_H
#define	_PISADEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internal ISA-dependent functions.
 *
 * Note that some ISA-dependent functions are exposed to applications, and found
 * in libproc.h:
 *
 * 	Ppltdest()
 * 	Pissyscall_prev()
 * 	Pstack_iter()
 */

/*
 * ISA dependent function to determine if the instruction at the given address
 * is a syscall instruction.  On x86, we have multiple system call instructions.
 * this function returns 1 if there is a system call at the given address, 2 if
 * there is a less preferred system call, and 0 if there is no system call
 * there.
 */
extern int Pissyscall(struct ps_prochandle *, uintptr_t);
/*
 * Works the same way as Pissyscall(), except operates on an in-memory buffer.
 */
extern int Pissyscall_text(struct ps_prochandle *, const void *buf,
    size_t buflen);

#if defined(__amd64)
/* amd64 stack doubleword aligned, unaligned in 32-bit mode  */
#define	PSTACK_ALIGN32(sp)	((sp) & ~(2 * sizeof (int64_t) - 1))
#define	PSTACK_ALIGN64(sp)	(sp)
#elif defined(__i386)
/* i386 stack is unaligned */
#define	PSTACK_ALIGN32(sp)	(sp)
#define	PSTACK_ALIGN64(sp)	ALIGN32(sp)
#elif defined(__sparc)
/* sparc stack is doubleword aligned for 64-bit values */
#define	PSTACK_ALIGN32(sp)	((sp) & ~(2 * sizeof (int32_t) - 1))
#define	PSTACK_ALIGN64(sp)	((sp) & ~(2 * sizeof (int64_t) - 1))
#else
#error	Unknown ISA
#endif

/*
 * Given an argument count, stack pointer, and syscall index, sets up the stack
 * and appropriate registers.  The stack pointer should be the top of the stack
 * area, after any space reserved for arguments passed by reference.  Returns a
 * pointer which is later passed to Psyscall_copyargs().
 */
extern uintptr_t Psyscall_setup(struct ps_prochandle *, int, int, uintptr_t);

/*
 * Copies all arguments out to the stack once we're stopped before the syscall.
 */
extern int Psyscall_copyinargs(struct ps_prochandle *, int, argdes_t *,
    uintptr_t);

/*
 * Copies out arguments to their original values.
 */
extern int Psyscall_copyoutargs(struct ps_prochandle *, int, argdes_t *,
    uintptr_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _PISADEP_H */
