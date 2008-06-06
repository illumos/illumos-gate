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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBC_AMD64_INC_SYS_H
#define	_LIBC_AMD64_INC_SYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines common code sequences for system calls.
 */
#include <sys/asm_linkage.h>
#include <sys/syscall.h>
#include <sys/errno.h>

#define	_fref_(name)	name@PLT
#define	_daref_(name)	name@GOTPCREL(%rip)
#define	_sref_(name)	name(%rip)

/*
 * Define the external symbol __cerror for all files.
 */
	.globl	__cerror

/*
 * __SYSCALL provides the basic trap sequence.  It assumes that
 * an entry of the form SYS_name exists (from sys/syscall.h).
 * Note that %rcx is smashed by the syscall instruction,
 * so we move it to %r10 in order to pass it to the kernel.
 */
#define	__SYSCALL(name)			\
	movq	%rcx, %r10;		\
	/* CSTYLED */			\
	movl	$SYS_/**/name, %eax;	\
	syscall

#define	SYSTRAP_RVAL1(name)	__SYSCALL(name)
#define	SYSTRAP_RVAL2(name)	__SYSCALL(name)
#define	SYSTRAP_2RVALS(name)	__SYSCALL(name)
#define	SYSTRAP_64RVAL(name)	__SYSCALL(name)

/*
 * SYSFASTTRAP provides the fast system call trap sequence.  It assumes
 * that an entry of the form T_name exists (probably from sys/trap.h).
 */
#define	SYSFASTTRAP(name)		\
	/* CSTYLED */			\
	movl	$T_/**/name, %eax;	\
	int	$T_FASTTRAP

/*
 * SYSCERROR provides the sequence to branch to __cerror if an error is
 * indicated by the carry-bit being set upon return from a trap.
 */
#define	SYSCERROR		\
	jb	__cerror

/*
 * SYSLWPERR provides the sequence to return 0 on a successful trap
 * and the error code if unsuccessful.
 * Error is indicated by the carry-bit being set upon return from a trap.
 */
#define	SYSLWPERR			\
	jae	1f;			\
	cmpl	$ERESTART, %eax;	\
	jne	2f;			\
	movl	$EINTR, %eax;		\
	jmp	2f;			\
1:					\
	xorq	%rax, %rax;		\
2:

/*
 * SYSREENTRY provides the entry sequence for restartable system calls.
 */
#define	SYSREENTRY(name)	\
	ENTRY(name);		\
1:

/*
 * SYSRESTART provides the error handling sequence for restartable
 * system calls.
 * XX64 -- Are all of the argument registers restored to their
 * original values on an ERESTART return (including %rcx)?
 */
#define	SYSRESTART(name)		\
	jae	1f;			\
	cmpl	$ERESTART, %eax;	\
	je	1b;			\
	jmp	__cerror;		\
1:

/*
 * SYSINTR_RESTART provides the error handling sequence for restartable
 * system calls in case of EINTR or ERESTART.
 */
#define	SYSINTR_RESTART(name)		\
	jae	1f;			\
	cmpl	$ERESTART, %eax;	\
	je	1b;			\
	cmpl	$EINTR, %eax;		\
	je	1b;			\
	jmp	2f;			\
1:					\
	xorq	%rax, %rax;		\
2:

/*
 * SYSCALL provides the standard (i.e.: most common) system call sequence.
 */
#define	SYSCALL(name)			\
	ENTRY(name);			\
	SYSTRAP_2RVALS(name);		\
	SYSCERROR

#define	SYSCALL_RVAL1(name)		\
	ENTRY(name);			\
	SYSTRAP_RVAL1(name);		\
	SYSCERROR

/*
 * SYSCALL64 provides the standard (i.e.: most common) system call sequence
 * for system calls that return 64-bit values.
 */
#define	SYSCALL64(name)			\
	SYSCALL(name)

/*
 * SYSCALL_RESTART provides the most common restartable system call sequence.
 */
#define	SYSCALL_RESTART(name)		\
	SYSREENTRY(name);		\
	SYSTRAP_2RVALS(name);		\
	SYSRESTART()

#define	SYSCALL_RESTART_RVAL1(name)	\
	SYSREENTRY(name);		\
	SYSTRAP_RVAL1(name);		\
	SYSRESTART()

/*
 * SYSCALL2 provides a common system call sequence when the entry name
 * is different than the trap name.
 */
#define	SYSCALL2(entryname, trapname)	\
	ENTRY(entryname);		\
	SYSTRAP_2RVALS(trapname);	\
	SYSCERROR

#define	SYSCALL2_RVAL1(entryname, trapname)	\
	ENTRY(entryname);			\
	SYSTRAP_RVAL1(trapname);		\
	SYSCERROR

/*
 * SYSCALL2_RESTART provides a common restartable system call sequence when the
 * entry name is different than the trap name.
 */
#define	SYSCALL2_RESTART(entryname, trapname)	\
	SYSREENTRY(entryname);			\
	SYSTRAP_2RVALS(trapname);		\
	SYSRESTART()

#define	SYSCALL2_RESTART_RVAL1(entryname, trapname)	\
	SYSREENTRY(entryname);				\
	SYSTRAP_RVAL1(trapname);			\
	SYSRESTART()

/*
 * SYSCALL_NOERROR provides the most common system call sequence for those
 * system calls which don't check the error reture (carry bit).
 */
#define	SYSCALL_NOERROR(name)		\
	ENTRY(name);			\
	SYSTRAP_2RVALS(name)

#define	SYSCALL_NOERROR_RVAL1(name)	\
	ENTRY(name);			\
	SYSTRAP_RVAL1(name)

/*
 * Standard syscall return sequence, return code equal to rval1.
 */
#define	RET			\
	ret

/*
 * Syscall return sequence, return code equal to rval2.
 */
#define	RET2			\
	movq	%rdx, %rax;	\
	ret

/*
 * Syscall return sequence with return code forced to zero.
 */
#define	RETC			\
	xorq	%rax, %rax;	\
	ret

#endif	/* _LIBC_AMD64_INC_SYS_H */
