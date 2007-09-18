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

#if defined(lint)

#include <sys/systm.h>

#else	/* lint */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/segments.h>

#endif	/* lint */

#ifdef	lint

void
sn1_brand_sysenter_callback(void)
{
}

void
sn1_brand_syscall_callback(void)
{
}

#if defined(__amd64)
void
sn1_brand_syscall32_callback(void)
{
}
#endif	/* amd64 */

void
sn1_brand_int91_callback(void)
{
}

#else	/* lint */

/*
 * Each of the following macros returns to the standard syscall codepath if
 * it detects that this process is not able, or intended, to emulate this
 * system call.  They all assume that the routine provides a 'bail-out'
 * label of '9'.
 */

/*
 * See if this process has a user-space handler registered for it.  For the
 * sn1 brand, the per-process brand data holds the address of the handler.
 * As shown in the stack diagrams below, the callback code leaves that data
 * at these offsets.
 */
#if defined(__amd64)
#define	CHECK_FOR_HANDLER		 \
	cmpq	$0, 24(%rsp)		;\
	je	9f		
#else
#define	CHECK_FOR_HANDLER		 \
	cmpl	$0, 12(%esp)		;\
	je	9f		
#endif	/* __amd64 */

/* 
 * If the system call number is >= 1024, then it is coming from the
 * emulation support library.  As such we should handle it natively instead
 * of sending it back to the emulation library.
 */
#define	CHECK_FOR_NATIVE(reg)		\
	cmp	$1024, reg		;\
	jl	1f			;\
	sub	$1024, reg		;\
	jmp	9f			;\
1:

/*
 * Check to see if we want to interpose on this system call.  If not, we
 * jump back into the normal syscall path and pretend nothing happened.
 */
#define CHECK_FOR_INTERPOSITION(sysr, scr, scr_low)		\
	lea	sn1_emulation_table, scr			;\
	mov	(scr), scr					;\
	add	sysr, scr					;\
	movb	(scr), scr_low					;\
	cmpb	$0, scr_low					;\
	je	9f						;\

#define	CALLBACK_PROLOGUE(call, scr, scr_low)			;\
	push	scr		/* Save scratch register */	;\
	CHECK_FOR_HANDLER					;\
	CHECK_FOR_NATIVE(call)					;\
	CHECK_FOR_INTERPOSITION(call, scr, scr_low)

/*
 * The callback routines:
 */

#if defined(__amd64)
	/* 
	 * When we get into any of these callback routines, the stack
	 * looks like this:
	 *  	   --------------------------------------
	 *      32 | saved stack pointer		|
	 *    | 24 | lwp brand data			|
	 *    | 16 | proc brand data			|
	 *    v  8 | user return address (*)		|
	 *       0 | BRAND_CALLBACK()'s return addr 	|
	 *         --------------------------------------
	 *   (*) This is actually just the bottom value from the user's
	 *       stack.  syscall puts this in %rcx instead of the stack,
	 *       so it's just garbage for that entry point.
	 */

	/*
	 * syscall handler for 32-bit user processes:
	 *
	 * %ecx contains the address of the instruction after the syscall
	 */
	ENTRY(sn1_brand_syscall32_callback)

	CALLBACK_PROLOGUE(%rax, %r15, %r15b)

	movq	%rsp, %r15	/* save our stack pointer */

	/*
	 * Adjust the user's stack so that the 'ret' from our userspace
	 * handler takes us to the post-syscall instruction instead of to
	 * the routine that called the system call.
	 */
	movq	40(%rsp), %rsp	/* restore user's stack pointer 	*/
	subq	$4, %rsp	/* save room for the post-syscall addr	*/
	movl	%ecx, (%rsp)	/* Save post-syscall addr on stack	*/

	/*
	 * To 'return' to our user-space handler, we just need to copy
	 * its address into %ecx.
	 */
	movq	24(%r15), %rcx	/* user-space handler == proc_data for sn1 */
	movq	(%r15), %r15	/* Restore scratch register */
	jmp	nopop_sys_syscall32_sysretl
9:
	popq	%r15
	retq
	SET_SIZE(sn1_brand_syscall32_callback)

	/*
	 * syscall handler for 64-bit user processes:
	 *     %rax - syscall number
	 *     %rcx - user space %rip
	 */
	ENTRY(sn1_brand_syscall_callback)

	CALLBACK_PROLOGUE(%rax, %r15, %r15b)

	movq	%rsp, %r15	/* save our stack pointer */

	movq	40(%rsp), %rsp	/* restore user's stack pointer 	*/
	subq	$8, %rsp	/* save room for the post-syscall addr	*/
	movq	%rcx, (%rsp)	/* Save post-syscall addr on stack	*/

	/*
	 * To 'return' to our user-space handler, we just need to copy
	 * its address into %ecx.
	 */
	movq	24(%r15), %rcx	/* user-space handler == proc_data for sn1 */
	movq	(%r15), %r15	/* Restore scratch register */
	jmp	nopop_sys_syscall_sysretq
9:
	popq	%r15
	retq
	
	SET_SIZE(sn1_brand_syscall_callback)

	/*
	 * %rax - syscall number
	 * %rcx - user space %esp
	 * %rdx - user space return address
	 *
	 * XXX: not tested yet.  Need a Nocona machine first.
	 */
	ENTRY(sn1_brand_sysenter_callback)

	CALLBACK_PROLOGUE(%rax, %r15, %r15b)

	subq	$4, %rcx	/* Save room for user ret addr	*/
	movq	%rdx, (%rcx)	/* Save current return addr	*/
	movq	24(%rsp), %rdx	/* user-space handler == proc_data for sn1 */
	popq	%r15
	sysexit
9:
	popq	%r15
	ret
	SET_SIZE(sn1_brand_sysenter_callback)

	/*
	 * The saved stack pointer points at the state saved when we took
	 * the interrupt:
	 *	   --------------------------------------
	 *    | 32 | user's %ss				|
	 *    | 24 | user's %esp			|
	 *    | 16 | EFLAGS register			|
	 *    v  8 | user's %cs				|
	 *       0 | user's %eip			|
	 *	   --------------------------------------
	 */
	ENTRY(sn1_brand_int91_callback)

	CALLBACK_PROLOGUE(%rax, %r15, %r15b)

	movq	24(%rsp), %r15	/* user-space handler == proc_data for sn1 */
	pushq	%rax		/* Save scratch register		*/
	movq	48(%rsp), %rax	/* Get saved %esp			*/
	movq	%r15, (%rax)	/* replace iret target address with hdlr */

	/*
	 * Adjust the caller's stack so we return to the instruction after
	 * the syscall on the next 'ret' in userspace - not to the parent
	 * routine.
	 */
	movq	24(%rax), %r15	/* Get user's %esp			*/
	subq	$4, %r15	/* Make room for new ret addr		*/
	movq	%r15, 24(%rax)	/* Replace current with updated %esp	*/
	movl	24(%rsp), %eax	/* Get post-syscall address		*/
	movl	%eax, (%r15)	/* Put it on the user's stack		*/

	popq	%rax		/* Restore scratch register		*/
	popq	%r15		/* Restore scratch register		*/
	movq	32(%rsp), %rsp	/* Remove all callback stuff from stack	*/
	jmp	nopop_sys_rtt_syscall32
9:
	popq	%r15
	retq
	SET_SIZE(sn1_brand_int91_callback)

#else	/* __amd64 */

	/*
	 * When we get into any of these callback routines, the stack
	 * looks like this:
	 *	   --------------------------------------
	 *    | 28 | 'scatch space'			|
	 *    | 24 | user's %ebx			|
	 *    | 20 | user's %gs selector		|
	 *    | 16 | kernel's %gs selector		|
	 *    | 12 | lwp brand data			|
	 *    |  8 | proc brand data			|
	 *    v  4 | user return address		|
	 *       0 | callback wrapper return addr	|
	 *         --------------------------------------
	 */

	/*
	 * lcall handler for 32-bit OS
	 *     %eax - syscall number
	 *
	 * Above the stack contents common to all callbacks is the
	 * int/lcall-specific state:
	 *	   --------------------------------------
	 *    | 48 | user's %ss				|
	 *    | 44 | user's %esp			|
	 *    | 40 | EFLAGS register			|
	 *    v 36 | user's %cs				|
	 *      32 | user's %eip			|
	 *	   --------------------------------------
	 */
	ENTRY(sn1_brand_syscall_callback)

	CALLBACK_PROLOGUE(%eax, %ebx, %bl)

	movl	12(%esp), %ebx	/* user-space handler == proc_data for sn1 */
	movl	%ebx, 36(%esp)	/* replace iret target address with hdlr */

	/*
	 * Adjust the caller's stack so we return to the instruction after
	 * the syscall on the next 'ret' in userspace - not to the parent
	 * routine.
	 */
	pushl	%eax		/* Save scratch register		*/
	movl	52(%esp), %eax	/* Get current %esp			*/
	subl	$4, %eax	/* Make room for new ret addr		*/
	movl	%eax, 52(%esp)	/* Replace current with updated %esp	*/
	movl	12(%esp), %ebx	/* Get post-syscall address		*/
	movl	%ebx, (%eax)	/* Put it on the user's stack		*/
	popl	%eax		/* Restore scratch register 		*/

	popl	%ebx		/* Restore scratch register 		*/
	addl	$32, %esp	/* Remove all callback stuff from stack	*/
	jmp	nopop_sys_rtt_syscall
9:
	popl	%ebx
	ret
	SET_SIZE(sn1_brand_syscall_callback)

	/*
	 * %eax - syscall number
	 * %ecx - user space %esp
	 * %edx - user space return address
	 */
	ENTRY(sn1_brand_sysenter_callback)

	CALLBACK_PROLOGUE(%eax, %ebx, %bl)

	subl	$4, %ecx	/* Save room for user ret addr	*/
	movl	%edx, (%ecx)	/* Save current return addr	*/
	movl	12(%esp), %edx	/* Return to user-space handler	*/
	popl	%ebx		/* Restore scratch register	*/
	sysexit
9:
	popl	%ebx
	ret
	SET_SIZE(sn1_brand_sysenter_callback)

#endif	/* __amd64 */
#endif	/* lint */

