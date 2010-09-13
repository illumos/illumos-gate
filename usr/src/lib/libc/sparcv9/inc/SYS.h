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

#ifndef	_LIBC_SPARCV9_INC_SYS_H
#define	_LIBC_SPARCV9_INC_SYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines common code sequences for system calls.  Note that
 * it is assumed that __cerror is within the short branch distance from
 * all the traps (so that a simple bcs can follow the trap, rather than
 * a position independent code sequence.)
 */

#include <sys/asm_linkage.h>
#include <sys/syscall.h>
#include <sys/errno.h>

/*
 * While it's tempting to imagine we could use 'rd %pc' here,
 * in fact it's a rather slow operation that consumes many
 * cycles, so we use the usual side-effect of 'call' instead.
 */
#define	PIC_SETUP(r)						\
	mov	%o7, %g1;					\
9:	call	8f;						\
	sethi	%hi(_GLOBAL_OFFSET_TABLE_ - (9b - .)), %r;	\
8:	or	%r, %lo(_GLOBAL_OFFSET_TABLE_ - (9b - .)), %r;	\
	add	%r, %o7, %r;					\
	mov	%g1, %o7

/*
 * Trap number for system calls
 */
#define	SYSCALL_TRAPNUM	64

/*
 * Define the external symbol __cerror for all files.
 */
	.global	__cerror

/*
 * __SYSTRAP provides the basic trap sequence.  It assumes that an entry
 * of the form SYS_name exists (probably from sys/syscall.h).
 */
#define	__SYSTRAP(name)			\
	/* CSTYLED */			\
	mov	SYS_/**/name, %g1;	\
	ta	SYSCALL_TRAPNUM

#define	SYSTRAP_RVAL1(name)		__SYSTRAP(name)
#define	SYSTRAP_RVAL2(name)		__SYSTRAP(name)
#define	SYSTRAP_2RVALS(name)		__SYSTRAP(name)
#define	SYSTRAP_64RVAL(name)		__SYSTRAP(name)

/*
 * SYSFASTTRAP provides the fast system call trap sequence.  It assumes
 * that an entry of the form ST_name exists (probably from sys/trap.h).
 */
#define	SYSFASTTRAP(name)		\
	/* CSTYLED */			\
	ta	ST_/**/name

/*
 * SYSCERROR provides the sequence to branch to __cerror if an error is
 * indicated by the carry-bit being set upon return from a trap.
 */
#define	SYSCERROR			\
	/* CSTYLED */			\
	bcs	__cerror;		\
	nop

/*
 * SYSLWPERR provides the sequence to return 0 on a successful trap
 * and the error code if unsuccessful.
 * Error is indicated by the carry-bit being set upon return from a trap.
 */
#define	SYSLWPERR			\
	/* CSTYLED */			\
	bcc,a,pt %icc, 1f;		\
	clr	%o0;			\
	cmp	%o0, ERESTART;		\
	move	%icc, EINTR, %o0;	\
1:

#define	SAVE_OFFSET	(STACK_BIAS + 8 * 16)

/*
 * SYSREENTRY provides the entry sequence for restartable system calls.
 */
#define	SYSREENTRY(name)			\
	ENTRY(name);				\
	stn	%o0, [%sp + SAVE_OFFSET];	\
/* CSTYLED */					\
.restart_/**/name:

/*
 * SYSRESTART provides the error handling sequence for restartable
 * system calls.
 */
#define	SYSRESTART(name)					\
	/* CSTYLED */						\
	bcc,pt	%icc, 1f;					\
	cmp	%o0, ERESTART;					\
	/* CSTYLED */						\
	be,a,pn	%icc, name;					\
	ldn	[%sp + SAVE_OFFSET], %o0;			\
	/* CSTYLED */						\
	ba,a	__cerror;					\
1:

/*
 * SYSINTR_RESTART provides the error handling sequence for restartable
 * system calls in case of EINTR or ERESTART.
 */
#define	SYSINTR_RESTART(name)					\
	/* CSTYLED */						\
	bcc,a,pt %icc, 1f;					\
	clr	%o0;						\
	cmp	%o0, ERESTART;					\
	/* CSTYLED */						\
	be,a,pn	%icc, name;					\
	ldn	[%sp + SAVE_OFFSET], %o0;			\
	cmp	%o0, EINTR;					\
	/* CSTYLED */						\
	be,a,pn	%icc, name;					\
	ldn	[%sp + SAVE_OFFSET], %o0;			\
1:

/*
 * SYSCALL provides the standard (i.e.: most common) system call sequence.
 */
#define	SYSCALL(name)						\
	ENTRY(name);						\
	SYSTRAP_2RVALS(name);					\
	SYSCERROR

#define	SYSCALL_RVAL1(name)					\
	ENTRY(name);						\
	SYSTRAP_RVAL1(name);					\
	SYSCERROR

/*
 * SYSCALL_RESTART provides the most common restartable system call sequence.
 */
#define	SYSCALL_RESTART(name)					\
	SYSREENTRY(name);					\
	SYSTRAP_2RVALS(name);					\
	/* CSTYLED */						\
	SYSRESTART(.restart_/**/name)

#define	SYSCALL_RESTART_RVAL1(name)				\
	SYSREENTRY(name);					\
	SYSTRAP_RVAL1(name);					\
	/* CSTYLED */						\
	SYSRESTART(.restart_/**/name)

/*
 * SYSCALL2 provides a common system call sequence when the entry name
 * is different than the trap name.
 */
#define	SYSCALL2(entryname, trapname)				\
	ENTRY(entryname);					\
	SYSTRAP_2RVALS(trapname);				\
	SYSCERROR

#define	SYSCALL2_RVAL1(entryname, trapname)			\
	ENTRY(entryname);					\
	SYSTRAP_RVAL1(trapname);				\
	SYSCERROR

/*
 * SYSCALL2_RESTART provides a common restartable system call sequence when the
 * entry name is different than the trap name.
 */
#define	SYSCALL2_RESTART(entryname, trapname)			\
	SYSREENTRY(entryname);					\
	SYSTRAP_2RVALS(trapname);				\
	/* CSTYLED */						\
	SYSRESTART(.restart_/**/entryname)

#define	SYSCALL2_RESTART_RVAL1(entryname, trapname)		\
	SYSREENTRY(entryname);					\
	SYSTRAP_RVAL1(trapname);				\
	/* CSTYLED */						\
	SYSRESTART(.restart_/**/entryname)

/*
 * SYSCALL_NOERROR provides the most common system call sequence for those
 * system calls which don't check the error return (carry bit).
 */
#define	SYSCALL_NOERROR(name)					\
	ENTRY(name);						\
	SYSTRAP_2RVALS(name)

#define	SYSCALL_NOERROR_RVAL1(name)				\
	ENTRY(name);						\
	SYSTRAP_RVAL1(name)

/*
 * Standard syscall return sequence, return code equal to rval1.
 */
#define	RET			\
	retl;			\
	nop

/*
 * Syscall return sequence, return code equal to rval2.
 */
#define	RET2			\
	retl;			\
	mov	%o1, %o0

/*
 * Syscall return sequence with return code forced to zero.
 */
#define	RETC			\
	retl;			\
	clr	%o0

#endif	/* _LIBC_SPARCV9_INC_SYS_H */
