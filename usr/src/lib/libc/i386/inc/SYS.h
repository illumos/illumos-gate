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

#ifndef	_LIBC_I386_INC_SYS_H
#define	_LIBC_I386_INC_SYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines common code sequences for system calls.
 */
#include <sys/asm_linkage.h>
#include <sys/syscall.h>
#include <sys/errno.h>

#define	_prologue_			\
	pushl	%ebx;			\
	call	9f;			\
9:					\
	popl	%ebx;			\
	addl	$_GLOBAL_OFFSET_TABLE_ + [. - 9b], %ebx

#define	_epilogue_			\
	popl	%ebx

#define	_fref_(name)	name@PLT
#define	_daref_(name)	name@GOT(%ebx)
#define	_sref_(name)	name@GOTOFF(%ebx)
#define	_esp_(offset)	offset+4(%esp)	/* add 4 for the saved %ebx */

/*
 * Define the external symbols __cerror and __cerror64 for all files.
 */
	.globl	__cerror
	.globl	__cerror64

/*
 * __SYSCALLINT provides the basic trap sequence.  It assumes that an entry
 * of the form SYS_name exists (probably from sys/syscall.h).
 */

#define	__SYSCALLINT(name)		\
	/* CSTYLED */			\
	movl	$SYS_/**/name, %eax;	\
	int	$T_SYSCALLINT

/*
 * __SYSENTER provides a faster variant that is only able to
 * return rval1.  Note that %ecx and %edx are ALWAYS smashed.
 */
#define	__SYSENTER(name)		\
	call	8f;			\
8:	popl	%edx;			\
	/* CSTYLED */			\
	movl	$SYS_/**/name, %eax;	\
	movl	%esp, %ecx;		\
	add	$[9f - 8b], %edx;	\
	sysenter;			\
9:

/*
 * __SYSCALL provides a faster variant on processors and kernels
 * that support it.  Note that %ecx is ALWAYS smashed.
 */
#define	__SYSCALL(name)			\
	/* CSTYLED */			\
	movl	$SYS_/**/name, %eax;	\
	.byte	0xf, 0x5	/* syscall */

#if defined(_SYSC_INSN)
#define	SYSTRAP_RVAL1(name)	__SYSCALL(name)
#define	SYSTRAP_RVAL2(name)	__SYSCALL(name)
#define	SYSTRAP_2RVALS(name)	__SYSCALL(name)
#define	SYSTRAP_64RVAL(name)	__SYSCALL(name)
#else	/* _SYSC_INSN */
#if defined(_SEP_INSN)
#define	SYSTRAP_RVAL1(name)	__SYSENTER(name)
#else	/* _SEP_INSN */
#define	SYSTRAP_RVAL1(name)	__SYSCALLINT(name)
#endif	/* _SEP_INSN */
#define	SYSTRAP_RVAL2(name)	__SYSCALLINT(name)
#define	SYSTRAP_2RVALS(name)	__SYSCALLINT(name)
#define	SYSTRAP_64RVAL(name)	__SYSCALLINT(name)
#endif	/* _SYSC_INSN */

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
 * SYSCERROR64 provides the sequence to branch to __cerror64 if an error is
 * indicated by the carry-bit being set upon return from a trap.
 */
#define	SYSCERROR64		\
	jb	__cerror64

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
	xorl	%eax, %eax;		\
2:

/*
 * SYSREENTRY provides the entry sequence for restartable system calls.
 */
#define	SYSREENTRY(name)	\
/* CSTYLED */			\
.restart_/**/name:		\
	ENTRY(name)

/*
 * SYSRESTART provides the error handling sequence for restartable
 * system calls.
 */
#define	SYSRESTART(name)		\
	jae	1f;			\
	cmpl	$ERESTART, %eax;	\
	je	name;			\
	jmp	__cerror;		\
1:

/*
 * SYSINTR_RESTART provides the error handling sequence for restartable
 * system calls in case of EINTR or ERESTART.
 */
#define	SYSINTR_RESTART(name)		\
	jae	1f;			\
	cmpl	$ERESTART, %eax;	\
	je	name;			\
	cmpl	$EINTR, %eax;		\
	je	name;			\
	jmp	2f;			\
1:					\
	xorl	%eax, %eax;		\
2:

/*
 * SYSCALL provides the standard (i.e.: most common) system call sequence.
 */
#define	SYSCALL(name)		\
	ENTRY(name);		\
	SYSTRAP_2RVALS(name);	\
	SYSCERROR

#define	SYSCALL_RVAL1(name)	\
	ENTRY(name);		\
	SYSTRAP_RVAL1(name);	\
	SYSCERROR

/*
 * SYSCALL64 provides the standard (i.e.: most common) system call sequence
 * for system calls that return 64-bit values.
 */
#define	SYSCALL64(name)		\
	ENTRY(name);		\
	SYSTRAP_64RVAL(name);	\
	SYSCERROR64

/*
 * SYSCALL_RESTART provides the most common restartable system call sequence.
 */
#define	SYSCALL_RESTART(name)	\
	SYSREENTRY(name);	\
	SYSTRAP_2RVALS(name);	\
	/* CSTYLED */		\
	SYSRESTART(.restart_/**/name)

#define	SYSCALL_RESTART_RVAL1(name)	\
	SYSREENTRY(name);		\
	SYSTRAP_RVAL1(name);		\
	/* CSTYLED */			\
	SYSRESTART(.restart_/**/name)

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
	/* CSTYLED */				\
	SYSRESTART(.restart_/**/entryname)

#define	SYSCALL2_RESTART_RVAL1(entryname, trapname)	\
	SYSREENTRY(entryname);				\
	SYSTRAP_RVAL1(trapname);			\
	/* CSTYLED */					\
	SYSRESTART(.restart_/**/entryname)

/*
 * SYSCALL_NOERROR provides the most common system call sequence for those
 * system calls which don't check the error return (carry bit).
 */
#define	SYSCALL_NOERROR(name)	\
	ENTRY(name);		\
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
	movl	%edx, %eax;	\
	ret

/*
 * Syscall return sequence with return code forced to zero.
 */
#define	RETC			\
	xorl	%eax, %eax;	\
	ret

#endif	/* _LIBC_I386_INC_SYS_H */
