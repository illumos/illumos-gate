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

#if defined(__lint)

#include <sys/systm.h>

#else	/* __lint */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include "genassym.h"

#endif	/* __lint */

#ifdef	__lint

void
lx_brand_int80_callback(void)
{
}

#else	/* __lint */

#if defined(__amd64)
	/*
	 * lx brand callback for the int $0x80 trap handler.
	 *
	 * We're running on the user's %gs.
	 *
	 * We return directly to userland, bypassing the _update_sregs logic, so
	 * this	routine must NOT do anything that could cause a context switch.
	 *
	 * %rax - syscall number
	 * 
	 * When called, all general registers and %gs are as they were when
	 * the user process made the system call. The stack looks like
	 * this:
	 *  	   --------------------------------------
	 *      32 | saved stack pointer		|
	 *    | 24 | lwp brand data			|
	 *    | 16 | proc brand data			|
	 *    v  8 | user return address (*)		|
	 *       0 | caller's return addr (sys_int80)	|
	 *         -------------------------------------
	 */
	ENTRY(lx_brand_int80_callback)
	movq	24(%rsp), %r15			/* grab the lwp brand data */
	movl	%gs, BR_UGS(%r15)		/* save user %gs */

	movq	16(%rsp), %r15			/* grab the proc brand data */

.lx_brand_int80_patch_point:
	jmp	.lx_brand_int80_notrace

.lx_brand_int80_notrace:
	movq	L_HANDLER(%r15), %r15		/* load the base address */
	
0:
	/*
	 * Rather than returning to the instruction after the int 80, we
	 * transfer control into the brand library's handler table at
	 * table_addr + (16 * syscall_num) thus encoding the system
	 * call number in the instruction pointer. The original return address
	 * is passed in %eax.
	 */
	shlq	$4, %rax
	addq	%r15, %rax
	movq	32(%rsp), %rsp		/* restore user stack pointer */
	xchgq	(%rsp), %rax		/* swap %rax and return addr */
	jmp	nopop_sys_rtt_syscall32

.lx_brand_int80_trace:
	/*
	 * If tracing is active, we vector to an alternate trace-enabling
	 * handler table instead.
	 */
	movq	L_TRACEHANDLER(%r15), %r15	/* load trace handler address */
	jmp	0b
	SET_SIZE(lx_brand_int80_callback)


#define	PATCH_POINT	_CONST(.lx_brand_int80_patch_point + 1)
#define	PATCH_VAL	_CONST(.lx_brand_int80_trace - .lx_brand_int80_notrace)

	ENTRY(lx_brand_int80_enable)
	movl	$1, lx_systrace_brand_enabled(%rip)
	movq	$PATCH_POINT, %r8
	movb	$PATCH_VAL, (%r8)
	ret
	SET_SIZE(lx_brand_int80_enable)

	ENTRY(lx_brand_int80_disable)
	movq	$PATCH_POINT, %r8
	movb	$0, (%r8)
	movl	$0, lx_systrace_brand_enabled(%rip)
	ret
	SET_SIZE(lx_brand_int80_disable)


#elif defined(__i386)
	/*
	 * %eax - syscall number
	 *
	 * When called, all general registers and %gs are as they were when
	 * the user process made the system call. The stack looks like
	 * this:
	 *
	 *	   --------------------------------------
	 *    | 48 | user's %ss				|
	 *    | 44 | user's %esp			|
	 *    | 40 | EFLAGS register			|
	 *    | 36 | user's %cs				|
	 *    | 32 | user's %eip			|
	 *    | 28 | 'scratch space'			|
	 *    | 24 | user's %ebx			|
	 *    | 20 | user's %gs selector		|
	 *    | 16 | kernel's %gs selector		|
	 *    | 12 | lwp brand data			|
	 *    |  8 | proc brand data			|
	 *    v  4 | user return address		|
	 *       0 | callback wrapper return addr	|
	 *         -------------------------------------
	 */
	ENTRY(lx_brand_int80_callback)
	pushl	%ebx				/* save for use as scratch */
	movl	16(%esp), %ebx			/* grab the lwp brand data */
	movw	%gs, BR_UGS(%ebx)		/* save user %gs */

	movl	12(%esp), %ebx			/* grab the proc brand data */

.lx_brand_int80_patch_point:
	jmp	.lx_brand_int80_notrace

.lx_brand_int80_notrace:
	movl	L_HANDLER(%ebx), %ebx		/* load the base address */

0:
	/*
	 * See the corresponding comment in the amd64 version above.
	 */
	shll	$4, %eax
	addl	%ebx, %eax
	popl	%ebx				/* restore %ebx */
	addl	$32, %esp
	xchgl	(%esp), %eax			/* swap %eax and return addr */
	jmp	nopop_sys_rtt_syscall

.lx_brand_int80_trace:
	movl	L_TRACEHANDLER(%ebx), %ebx	/* load trace handler address */
	jmp	0b
	SET_SIZE(lx_brand_int80_callback)


#define	PATCH_POINT	_CONST(.lx_brand_int80_patch_point + 1)
#define	PATCH_VAL	_CONST(.lx_brand_int80_trace - .lx_brand_int80_notrace)

	ENTRY(lx_brand_int80_enable)
	pushl	%ebx
	pushl	%eax
	movl	$1, lx_systrace_brand_enabled
	movl	$PATCH_POINT, %ebx
	movl	$PATCH_VAL, %eax
	movb	%al, (%ebx)
	popl	%eax
	popl	%ebx
	ret
	SET_SIZE(lx_brand_int80_enable)

	ENTRY(lx_brand_int80_disable)
	pushl	%ebx
	movl	$PATCH_POINT, %ebx
	movb	$0, (%ebx)
	movl	$0, lx_systrace_brand_enabled
	popl	%ebx
	ret
	SET_SIZE(lx_brand_int80_disable)

#endif	/* __i386 */
#endif	/* __lint */
