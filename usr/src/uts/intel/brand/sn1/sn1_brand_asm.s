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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(lint)

#include <sys/systm.h>

#else	/* lint */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include "assym.h"

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

#if defined(__amd64)
/*
 * When our syscall interposition callback entry point gets invoked the
 * stack looks like this:
 *         --------------------------------------
 *      24 | saved stack pointer		|
 *    | 16 | lwp pointer			|
 *    v  8 | user return address (*)		|
 *       0 | BRAND_CALLBACK()'s return addr 	|
 *         --------------------------------------
 *   (*) This is actually just the bottom value from the user's
 *       stack.  syscall puts this in %rcx instead of the stack,
 *       so it's just garbage for that entry point.
 */

#define	V_COUNT	4
#define	V_END		(CLONGSIZE * 4)
#define	V_SSP		(CLONGSIZE * 3)
#define	V_LWP		(CLONGSIZE * 2)
#define	V_URET_ADDR	(CLONGSIZE * 1)
#define	V_CB_ADDR	(CLONGSIZE * 0)

#define	SP_REG		%rsp

#else	/* !__amd64 */
/*
 * When our syscall interposition callback entry point gets invoked the
 * stack looks like this:
 *         --------------------------------------
 *    | 24 | 'scatch space'			|
 *    | 20 | user's %ebx			|
 *    | 16 | user's %gs selector		|
 *    | 12 | kernel's %gs selector		|
 *    |  8 | lwp pointer			|
 *    v  4 | user return address		|
 *       0 | callback wrapper return addr	|
 *         --------------------------------------
 */

#define	V_COUNT	7
#define	V_END		(CLONGSIZE * 7)
#define	V_LWP		(CLONGSIZE * 2)
#define	V_URET_ADDR	(CLONGSIZE * 1)
#define	V_CB_ADDR	(CLONGSIZE * 0)

#define	SP_REG		%esp

#endif	/* !__amd64 */

/*
 * The following macros allow us to access to variables/parameters passed
 * in on the stack.  They take the following variables:
 *	sp	- a register with the current stack pointer value
 *	pcnt	- the number of words currently pushed onto the stack
 *	var	- the variable to lookup
 *	reg	- a register to read the variable into, or
 *		  a register to write to the variable
 */
#define V_OFFSET(pcnt, var)						 \
	(var + (pcnt * CLONGSIZE))

#define GET_V(sp, pcnt, var, reg)					 \
	mov	V_OFFSET(pcnt, var)(sp), reg

#define SET_V(sp, pcnt, var, reg)					 \
	mov	reg, V_OFFSET(pcnt, var)(sp)

#define GET_PROCP(sp, pcnt, reg)					 \
	GET_V(sp, pcnt, V_LWP, reg)		/* get lwp pointer */	;\
	mov	LWP_PROCP(reg), reg		/* get proc pointer */

#define GET_P_BRAND_DATA(sp, pcnt, reg)					 \
	GET_PROCP(sp, pcnt, reg)					;\
	mov	P_BRAND_DATA(reg), reg		/* get p_brand_data */

/*
 * Each of the following macros returns to the standard syscall codepath if
 * it detects that this process is not able, or intended, to emulate this
 * system call.  They all assume that the routine provides a 'bail-out'
 * label of '9'.
 */

/*
 * See if this process has a user-space hdlr registered for it.  For the
 * sn1 brand, the per-process brand data holds the address of the handler.
 * As shown in the stack diagrams above, the callback code leaves that data
 * at these offsets.
 */
#define	CHECK_FOR_HANDLER(scr)						  \
	GET_PROCP(SP_REG, 1, scr)		/* get proc pointer */   ;\
	cmp	$0, P_BRAND_DATA(scr)		/* check p_brand_data */ ;\
	je	9f

/*
 * If the system call number is >= 1024, then it is coming from the
 * emulation support library.  As such we should handle it natively instead
 * of sending it back to the emulation library.
 */
#define	CHECK_FOR_NATIVE(reg)		 \
	cmp	$1024, reg		;\
	jl	1f			;\
	sub	$1024, reg		;\
	jmp	9f			;\
1:

/*
 * Check to see if we want to interpose on this system call.  If not, we
 * jump back into the normal syscall path and pretend nothing happened.
 */
#define CHECK_FOR_INTERPOSITION(sysr, scr, scr_low)		 \
	lea	sn1_emulation_table, scr			;\
	mov	(scr), scr					;\
	add	sysr, scr					;\
	movb	(scr), scr_low					;\
	cmpb	$0, scr_low					;\
	je	9f

#define	CALLBACK_PROLOGUE(call, scr, scr_low)			 \
	push	scr		/* Save scratch register */	;\
	CHECK_FOR_HANDLER(scr)					;\
	CHECK_FOR_NATIVE(call)					;\
	CHECK_FOR_INTERPOSITION(call, scr, scr_low)

/*
 * The callback routines:
 */

#if defined(__amd64)

/*
 * syscall handler for 32-bit user processes:
 *	%rax - syscall number
 *	%ecx - the address of the instruction after the syscall
 */
ENTRY(sn1_brand_syscall32_callback)

	CALLBACK_PROLOGUE(%rax, %r15, %r15b)
	movq	%rsp, %r15	/* save our stack pointer */

	/*
	 * Adjust the user's stack so that the 'ret' from our user-space
	 * hdlr takes us to the post-syscall instruction instead of to
	 * the routine that called the system call.
	 */
	GET_V(%r15, 1, V_SSP, %rsp) /* restore user's stack pointer	*/
	subq	$4, %rsp	/* save room for the post-syscall addr	*/
	movl	%ecx, (%rsp)	/* Save post-syscall addr on stack	*/

	/*
	 * To 'return' to our user-space hdlr, we just need to copy
	 * its address into %ecx.  user-space hdlr == p_brand_data for sn1
	 */
	GET_P_BRAND_DATA(%r15, 1, %rcx);
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

	GET_V(%r15, 1, V_SSP, %rsp) /* restore user's stack pointer	*/
	subq	$8, %rsp	/* save room for the post-syscall addr	*/
	movq	%rcx, (%rsp)	/* Save post-syscall addr on stack	*/

	/*
	 * To 'return' to our user-space hdlr, we just need to copy
	 * its address into %ecx.  user-space hdlr == p_brand_data for sn1
	 */
	GET_P_BRAND_DATA(%r15, 1, %rcx);
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

	subq	$4, %rcx		/* Save room for user ret addr	*/
	movq	%rdx, (%rcx)		/* Save current return addr	*/
	GET_P_BRAND_DATA(%rsp, 1, %rdx)	/* get p_brand_data */
	popq	%r15			/* Restore scratch register	*/
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
	pushq	%rax				/* Save scratch register */

	GET_P_BRAND_DATA(%rsp, 2, %r15)		/* get p_brand_data */
	GET_V(%rsp, 2, V_SSP, %rax)		/* Get saved %esp */
	movq	%r15, (%rax)	/* replace iret target address with hdlr */

	/*
	 * Adjust the caller's stack so we return to the instruction after
	 * the syscall on the next 'ret' in userspace - not to the parent
	 * routine.
	 */
	movq	24(%rax), %r15	/* Get user's %esp			*/
	subq	$4, %r15	/* Make room for new ret addr		*/
	movq	%r15, 24(%rax)	/* Replace current with updated %esp	*/

	GET_V(%rsp, 2, V_URET_ADDR, %rax)
	movl	%eax, (%r15)	/* Put it on the user's stack		*/

	popq	%rax			/* Restore scratch register	*/
	popq	%r15			/* Restore scratch register	*/
	movq	V_SSP(%rsp), %rsp	/* Remove callback stuff from stack */
	jmp	nopop_sys_rtt_syscall32
9:
	popq	%r15
	retq
SET_SIZE(sn1_brand_int91_callback)

#else	/* !__amd64 */

/*
 * lcall handler for 32-bit OS
 *     %eax - syscall number
 *
 * Above the stack contents common to all callbacks is the
 * int/lcall-specific state:
 *	   --------------------------------------
 *    | 44 | user's %ss				|
 *    | 40 | user's %esp			|
 *    | 36 | EFLAGS register			|
 *    v 32 | user's %cs				|
 *      28 | user's %eip			|
 *	   --------------------------------------
 */
#define	V_U_SS		(V_END + (CLONGSIZE * 4))
#define	V_U_ESP		(V_END + (CLONGSIZE * 3))
#define	V_EFLAGS	(V_END + (CLONGSIZE * 2))
#define	V_U_CS		(V_END + (CLONGSIZE * 1))
#define	V_U_EIP		(V_END + (CLONGSIZE * 0))

ENTRY(sn1_brand_syscall_callback)

	CALLBACK_PROLOGUE(%eax, %ebx, %bl)
	pushl	%eax				/* Save scratch register */

	/* replace iret target address with user-space hdlr */
	GET_P_BRAND_DATA(%esp, 2, %ebx)
	SET_V(%esp, 2, V_U_EIP, %ebx)

	/*
	 * Adjust the caller's stack so we return to the instruction after
	 * the syscall on the next 'ret' in userspace - not to the parent
	 * routine.
	 */
	GET_V(%esp, 2, V_URET_ADDR, %ebx) /* Get new post-syscall ret addr  */
	GET_V(%esp, 2, V_U_ESP, %eax)	  /* Get user %esp		    */
	subl	$4, %eax		  /* Make room for new ret addr	    */
	SET_V(%esp, 2, V_U_ESP, %eax)	  /* Updated user %esp		    */
	movl	%ebx, (%eax)		  /* Put new ret addr on user stack */

	popl	%eax		/* Restore scratch register 		*/
	popl	%ebx		/* Restore scratch register 		*/
	addl	$V_END, %esp	/* Remove all callback stuff from stack	*/
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

	subl	$4, %ecx		/* Save room for user ret addr	*/
	movl	%edx, (%ecx)		/* Save current return addr	*/
	GET_P_BRAND_DATA(%esp, 1, %edx)	/* get p_brand_data */
	popl	%ebx			/* Restore scratch register	*/
	sysexit
9:
	popl	%ebx
	ret
SET_SIZE(sn1_brand_sysenter_callback)

#endif	/* !__amd64 */
#endif	/* lint */
