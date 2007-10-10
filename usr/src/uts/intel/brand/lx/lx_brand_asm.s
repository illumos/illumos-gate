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
#include "assym.h"
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
	 *      24 | saved stack pointer		|
	 *    | 16 | lwp pointer			|
	 *    v  8 | user return address (*)		|
	 *       0 | caller's return addr (sys_int80)	|
	 *         -------------------------------------
	 */
	ENTRY(lx_brand_int80_callback)
	movq	16(%rsp), %r15			/* grab the lwp */
	movq	LWP_PROCP(%r15), %r15		/* grab the proc pointer */
	pushq	%r15				/* push the proc pointer */
	movq	P_ZONE(%r15), %r15		/* grab the zone pointer */
	movq	ZONE_BRAND_DATA(%r15), %r15	/* grab the zone brand ptr */
	pushq	%rax				/* save the syscall num */
	movl	LXZD_MAX_SYSCALL(%r15), %eax	/* load the 'max sysnum' word */
	xchgq	(%rsp), %rax			/* swap %rax and stack value */
	movq	32(%rsp), %r15			/* re-load the lwp pointer */
	movq	LWP_BRAND(%r15), %r15		/* grab the lwp brand data */
	movl	%gs, BR_UGS(%r15)		/* save user %gs */

	/* grab the 'max syscall num' for this process from 'zone brand data' */
	cmpq	(%rsp), %rax			/* is 0 <= syscall <= MAX? */
	jbe	0f				/* yes, syscall is OK */
	xorl    %eax, %eax			/* no, zero syscall number */
0:
	movq	8(%rsp), %r15			/* get the proc pointer */
	movq	P_BRAND_DATA(%r15), %r15	/* grab the proc brand data */

.lx_brand_int80_patch_point:
	jmp	.lx_brand_int80_notrace

.lx_brand_int80_notrace:
	movq	L_HANDLER(%r15), %r15		/* load the base address */
	
1:
	/*
	 * Rather than returning to the instruction after the int 80, we
	 * transfer control into the brand library's handler table at
	 * table_addr + (16 * syscall_num) thus encoding the system
	 * call number in the instruction pointer. The original return address
	 * is passed in %eax.
	 */
	shlq	$4, %rax
	addq	%r15, %rax
	movq	40(%rsp), %rsp		/* restore user stack pointer */
	xchgq	(%rsp), %rax		/* swap %rax and return addr */
	jmp	nopop_sys_rtt_syscall32

.lx_brand_int80_trace:
	/*
	 * If tracing is active, we vector to an alternate trace-enabling
	 * handler table instead.
	 */
	movq	L_TRACEHANDLER(%r15), %r15	/* load trace handler address */
	jmp	1b
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
	 *    | 44 | user's %ss				|
	 *    | 40 | user's %esp			|
	 *    | 36 | EFLAGS register			|
	 *    | 32 | user's %cs				|
	 *    | 28 | user's %eip			|
	 *    | 24 | 'scatch space'			|
	 *    | 20 | user's %ebx			|
	 *    | 16 | user's %gs selector		|
	 *    | 12 | kernel's %gs selector		|
	 *    |  8 | lwp pointer			|
	 *    v  4 | user return address		|
	 *       0 | callback wrapper return addr	|
	 *         -------------------------------------
	 */
	ENTRY(lx_brand_int80_callback)
	pushl	%ebx				/* save for use as scratch */
	movl	12(%esp), %ebx			/* grab the lwp pointer */
	movl	LWP_PROCP(%ebx), %ebx		/* grab the proc pointer */
	pushl	%ebx				/* push the proc pointer */
	movl	P_ZONE(%ebx), %ebx		/* grab the zone pointer */
	movl	ZONE_BRAND_DATA(%ebx), %ebx	/* grab the zone brand data */
	pushl	LXZD_MAX_SYSCALL(%ebx)		/* push the max sysnum */
	movl	20(%esp), %ebx			/* re-load the lwp pointer */
	movl	LWP_BRAND(%ebx), %ebx		/* grab the lwp brand data */
	movw	%gs, BR_UGS(%ebx)		/* save user %gs */

	/* grab the 'max syscall num' for this process from 'zone brand data' */
	cmpl	(%esp), %eax 			/* is 0 <= syscall <= MAX? */
	jbe	0f				/* yes, syscall is OK */
	xorl    %eax, %eax		     	/* no, zero syscall number */	
0:
	movl	4(%esp), %ebx			/* get the proc pointer */
	movl	P_BRAND_DATA(%ebx), %ebx	/* grab the proc brand data */

.lx_brand_int80_patch_point:
	jmp	.lx_brand_int80_notrace

.lx_brand_int80_notrace:
	movl	L_HANDLER(%ebx), %ebx		/* load the base address */

1:
	/*
	 * See the corresponding comment in the amd64 version above.
	 */
	shll	$4, %eax
	addl	%ebx, %eax
	movl	8(%esp), %ebx			/* restore %ebx */
	addl	$40, %esp
	xchgl	(%esp), %eax			/* swap %eax and return addr */
	jmp	nopop_sys_rtt_syscall

.lx_brand_int80_trace:
	movl	L_TRACEHANDLER(%ebx), %ebx	/* load trace handler address */
	jmp	1b
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
