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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include <sys/asm_linkage.h>

	/*
	 * weak aliases for public interfaces
	 */
	ANSI_PRAGMA_WEAK(_door_bind,function)
	ANSI_PRAGMA_WEAK(_door_call,function)
	ANSI_PRAGMA_WEAK(_door_getparam,function)
	ANSI_PRAGMA_WEAK(_door_info,function)
	ANSI_PRAGMA_WEAK(_door_revoke,function)
	ANSI_PRAGMA_WEAK(_door_setparam,function)
	ANSI_PRAGMA_WEAK(_door_unbind,function)

	ANSI_PRAGMA_WEAK(door_bind,function)
	ANSI_PRAGMA_WEAK(door_call,function)
	ANSI_PRAGMA_WEAK(door_getparam,function)
	ANSI_PRAGMA_WEAK(door_info,function)
	ANSI_PRAGMA_WEAK(door_revoke,function)
	ANSI_PRAGMA_WEAK(door_setparam,function)
	ANSI_PRAGMA_WEAK(door_unbind,function)

#include <sys/door.h>
#include "SYS.h"

/*
 * Offsets within struct door_results
 */
#define	DOOR_COOKIE	_MUL(0, CLONGSIZE)
#define	DOOR_DATA_PTR	_MUL(1, CLONGSIZE)
#define	DOOR_DATA_SIZE	_MUL(2, CLONGSIZE)
#define	DOOR_DESC_PTR	_MUL(3, CLONGSIZE)
#define	DOOR_DESC_SIZE	_MUL(4, CLONGSIZE)
#define	DOOR_PC		_MUL(5, CLONGSIZE)
#define	DOOR_SERVERS	_MUL(6, CLONGSIZE)
#define	DOOR_INFO_PTR	_MUL(7, CLONGSIZE)

/*
 * All of the syscalls except door_return() follow the same pattern.
 * The subcode goes in argument 6, which means we have to copy our
 * arguments into a new bit of stack, large enough to include the
 * subcode.  We fill the unused positions with zeros.
 */
#define	DOOR_SYSCALL(name, code, copy_args)				\
	ENTRY(name);							\
	pushl	%ebp;							\
	movl	%esp, %ebp;						\
	pushl	$code;		/* syscall subcode, arg 6 */		\
	pushl	$0;		/* dummy arg 5 */			\
	pushl	$0;		/* dummy arg 4 */			\
	copy_args;		/* args 1, 2, 3 */			\
	pushl	$0;		/* dummy return PC */			\
	SYSTRAP_RVAL1(door);						\
	jae	1f;							\
	addl	$28, %esp;						\
	leave;								\
	jmp	__cerror;						\
1:									\
	addl	$28, %esp;						\
	leave;								\
	ret;								\
	SET_SIZE(name)

#define	COPY_0								\
	pushl	$0;		/* dummy */				\
	pushl	$0;		/* dummy */				\
	pushl	$0		/* dummy */

#define	COPY_1								\
	pushl	$0;		/* dummy */				\
	pushl	$0;		/* dummy */				\
	pushl	8(%ebp)		/* 1 */

#define	COPY_2								\
	pushl	$0;		/* dummy */				\
	pushl	12(%ebp);	/* 2 */					\
	pushl	8(%ebp)		/* 1 */

#define	COPY_3								\
	pushl	16(%ebp);	/* 3 */					\
	pushl	12(%ebp);	/* 2 */					\
	pushl	8(%ebp)		/* 1 */

	DOOR_SYSCALL(__door_bind,	DOOR_BIND,	COPY_1)
	DOOR_SYSCALL(__door_call,	DOOR_CALL,	COPY_2)
	DOOR_SYSCALL(__door_create,	DOOR_CREATE,	COPY_3)
	DOOR_SYSCALL(__door_getparam,	DOOR_GETPARAM,	COPY_3)
	DOOR_SYSCALL(__door_info,	DOOR_INFO,	COPY_2)
	DOOR_SYSCALL(__door_revoke,	DOOR_REVOKE,	COPY_1)
	DOOR_SYSCALL(__door_setparam,	DOOR_SETPARAM,	COPY_3)
	DOOR_SYSCALL(__door_ucred,	DOOR_UCRED,	COPY_1)
	DOOR_SYSCALL(__door_unbind,	DOOR_UNBIND,	COPY_0)
	DOOR_SYSCALL(__door_unref,	DOOR_UNREFSYS,	COPY_0)

/*
 * int
 * __door_return(
 *	void 			*data_ptr,
 *	size_t			data_size,	(in bytes)
 *	door_return_desc_t	*door_ptr,	(holds returned desc info)
 *	caddr_t			stack_base,
 *	size_t			stack_size)
 */
	ENTRY(__door_return)
	movl	%esp, %edx		/ Save pointer to args

	pushl	%edi			/ save old %edi and %esi
	pushl	%esi			/ and use them to hold the
	movl	16(%edx), %esi		/ stack pointer and
	movl	20(%edx), %edi		/ size.

	pushl	$DOOR_RETURN		/ syscall subcode
	pushl	%edi			/ size of user stack
	pushl	%esi			/ base of user stack
	pushl	12(%edx)		/ desc arguments ptr
	pushl	8(%edx)			/ data size
	pushl	4(%edx)			/ data ptr
	pushl	0(%edx)			/ dummy return PC

door_restart:
	SYSTRAP_RVAL1(door)
	jb	3f			/* errno is set */
	/*
	 * On return, we're serving a door_call.  Our stack looks like this:
	 *
	 *		descriptors (if any)
	 *		data (if any)
	 *	 sp->	struct door_results
	 *
	 * struct door_results has the arguments in place for the server proc,
	 * so we just call it directly.
	 */
	movl	DOOR_SERVERS(%esp), %eax
	andl	%eax, %eax	/* test nservers */
	jg	1f
	/*
	 * this is the last server thread - call creation func for more
	 */
	movl	DOOR_INFO_PTR(%esp), %eax
	_prologue_
	pushl	%eax		/* door_info_t * */
	movl	_daref_(door_server_func), %eax
	movl	0(%eax), %eax
	call	*%eax		/* call create function */
	addl	$4, %esp
	_epilogue_
1:
	/* Call the door server function now */
	movl	DOOR_PC(%esp), %eax
	call	*%eax

2:
	/* Exit the thread if we return here */
	pushl	$0
	call	_thr_terminate
	/* NOTREACHED */
3:
	/*
	 * Error during door_return call.  Repark the thread in the kernel if
	 * the error code is EINTR (or ERESTART) and this lwp is still part
	 * of the same process.
	 *
	 * If the error code is EINTR or ERESTART, our stack may have been
	 * corrupted by a partial door call, so we refresh the system call
	 * arguments.
	 */
	cmpl	$EEXIST, %eax		/* exit this thread if EEXIST */
	je	2b
	cmpl	$ERESTART, %eax		/* ERESTART is same as EINTR */
	jne	4f
	movl	$EINTR, %eax
4:
	cmpl	$EINTR, %eax		/* interrupted while waiting? */
	jne	5f			/* if not, return the error */
	_prologue_
	call	_private_getpid		/* get current process id */
	movl	_daref_(door_create_pid), %edx
	movl	0(%edx), %edx
	_epilogue_
	cmpl	%eax, %edx		/* same process? */
	movl	$EINTR, %eax	/* if no, return EINTR (child of forkall) */
	jne	5f

	movl	$0, 4(%esp)		/* clear arguments and restart */
	movl	$0, 8(%esp)
	movl	$0, 12(%esp)
	movl	%esi, 16(%esp)		/* refresh sp */
	movl	%edi, 20(%esp)		/* refresh ssize */
	movl	$DOOR_RETURN, 24(%esp)	/* refresh syscall subcode */
	jmp	door_restart
5:
	/* Something bad happened during the door_return */
	addl	$28, %esp
	popl	%esi
	popl	%edi
	jmp	__cerror
	SET_SIZE(__door_return)
