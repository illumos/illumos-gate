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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/regset.h>
#include <sys/segments.h>
#include <sys/syscall.h>
#include <sys/lx_brand.h>

#if defined(_ASM)
#include <sys/lx_signal.h>
#include <sys/lx_syscall.h>
#endif	/* _ASM */

#include "assym.h"

/* 32-bit syscall numbers */
#define	LX_SYS_sigreturn	119
#define	LX_SYS_rt_sigreturn	173

#if defined(lint)

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/signal.h>

void
lx_sigreturn_tramp(void)
{}

void
lx_rt_sigreturn_tramp(void)
{}

#else	/* lint */

	ENTRY_NP(lx_swap_gs)
	push	%eax		/* save the current eax value */
	movl	0xc(%esp),%eax	/* 2nd param is a pointer */
	movw	%gs,(%eax)	/* use the pointer to save current gs */
	movl	0x8(%esp),%eax	/* first parameter is the new gs value */
	movw	%ax, %gs	/* switch to the new gs value */
	pop	%eax		/* restore eax */
	ret
	SET_SIZE(lx_swap_gs)

	/*
	 * Trampoline code is called by the return at the end of a Linux
	 * signal handler to return control to the interrupted application
	 * via the lx_sigreturn() or lx_rt_sigreturn() syscalls.
	 *
	 * (lx_sigreturn() is called for legacy signal handling, and
	 * lx_rt_sigreturn() is called for "new"-style signals.)
	 *
	 * These two routines must consist of the EXACT code sequences below
	 * as gdb looks at the sequence of instructions a routine will return
	 * to determine whether it is in a signal handler or not.
	 * See the Linux code setup_signal_stack_sc() in arch/x86/um/signal.c.
	 */
	ENTRY_NP(lx_sigreturn_tramp)
	popl	%eax
	movl	$LX_SYS_sigreturn, %eax
	int	$0x80
	SET_SIZE(lx_sigreturn_tramp)

	ENTRY_NP(lx_rt_sigreturn_tramp)
	movl	$LX_SYS_rt_sigreturn, %eax
	int	$0x80
	SET_SIZE(lx_rt_sigreturn_tramp)
#endif	/* lint */
