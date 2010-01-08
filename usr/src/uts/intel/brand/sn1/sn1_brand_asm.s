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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(lint)

#include <sys/systm.h>

#else	/* lint */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include <sn1_offsets.h>
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
 *      40 | user %gs				|
 *      32 | callback pointer			|
 *      24 | saved stack pointer		|
 *    | 16 | lwp pointer			|
 *    v  8 | user return address		|
 *       0 | BRAND_CALLBACK()'s return addr 	|
 *         --------------------------------------
 */

#define	V_COUNT	6
#define	V_END		(CLONGSIZE * 6)
#define	V_SSP		(CLONGSIZE * 3)
#define	V_LWP		(CLONGSIZE * 2)
#define	V_URET_ADDR	(CLONGSIZE * 1)
#define	V_CB_ADDR	(CLONGSIZE * 0)

#define	SP_REG		%rsp
#define	SYSCALL_REG	%rax

#else	/* !__amd64 */
/*
 * When our syscall interposition callback entry point gets invoked the
 * stack looks like this:
 *         --------------------------------------
 *    | 24 | 'scratch space'			|
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
#define	V_U_GS		(CLONGSIZE * 4)
#define	V_K_GS		(CLONGSIZE * 3)
#define	V_LWP		(CLONGSIZE * 2)
#define	V_URET_ADDR	(CLONGSIZE * 1)
#define	V_CB_ADDR	(CLONGSIZE * 0)

#define	SP_REG		%esp
#define	SYSCALL_REG	%eax

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
 * As shown in the stack diagrams below, the callback code leaves that data
 * at these offsets.  So check if sn1_proc_data_t->spd_handler is non-NULL.
 */
#define	CHECK_FOR_HANDLER(scr)						 \
	GET_P_BRAND_DATA(SP_REG, 1, scr)	/* get p_brand_data */	;\
	cmp	$0, scr							;\
	je	9f							;\
	cmp	$0, SPD_HANDLER(scr)		/* check spd_handler */ ;\
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
	cmp	$NSYSCALL, sysr	/* is 0 <= syscall <= MAX? */	;\
	ja	9f		/* no, take normal err path */	;\
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
 * Rather than returning to the instruction after the syscall, we need to
 * transfer control into the brand library's handler table at
 * table_addr + (16 * syscall_num), thus encoding the system call number in the
 * instruction pointer.  The CALC_TABLE_ADDR macro performs that calculation.
 *
 * This macro assumes the syscall number is in SYSCALL_REG and it clobbers
 * that register.  It leaves the calculated handler table return address in
 * the scratch reg.
 */
#define CALC_TABLE_ADDR(scr)						 \
	GET_P_BRAND_DATA(SP_REG, 1, scr) /* get p_brand_data ptr */	;\
	mov	SPD_HANDLER(scr), scr	/* get p_brand_data->spd_handler */ ;\
	shl	$4, SYSCALL_REG		/* syscall_num * 16 */		;\
	add	SYSCALL_REG, scr	/* leave return addr in scr reg. */

/*
 * To 'return' to our user-space handler, we just need to place its address
 * into 'retreg'.  The original return address is passed in SYSCALL_REG.
 */
#define SETUP_RET_DATA(scr, retreg)					 \
	CALC_TABLE_ADDR(scr)					 	;\
	mov	retreg, SYSCALL_REG /* save orig return addr in %rax */	;\
	mov	scr, retreg	/* save new return addr in ret reg */	;\
	pop	scr		/* restore scratch register */

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

	SETUP_RET_DATA(%r15, %rcx)
	GET_V(%rsp, 0, V_SSP, %rsp)	/* restore user's stack pointer	*/
	jmp	nopop_sys_syscall32_swapgs_sysretl
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

	SETUP_RET_DATA(%r15, %rcx)
	GET_V(%rsp, 0, V_SSP, %rsp)	/* restore user's stack pointer	*/
	jmp	nopop_sys_syscall_swapgs_sysretq
9:
	popq	%r15
	retq

SET_SIZE(sn1_brand_syscall_callback)

/*
 * %eax - syscall number
 * %ecx - user space %esp
 * %edx - user space return address
 */
ENTRY(sn1_brand_sysenter_callback)

	CALLBACK_PROLOGUE(%rax, %r15, %r15b)

	SETUP_RET_DATA(%r15, %rdx)
	jmp	sys_sysenter_swapgs_sysexit
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
#define	V_U_EIP		(CLONGSIZE * 0)

ENTRY(sn1_brand_int91_callback)

	CALLBACK_PROLOGUE(%rax, %r15, %r15b)

	/*
	 * To 'return' to our user-space handler we need to update the user's
	 * %eip pointer in the saved interrupt state.  The interrupt state was
	 * pushed onto our stack automatically when the interrupt occured; see
	 * the comments above.  The original return address is passed in %rax.
	 */
	CALC_TABLE_ADDR(%r15)
	GET_V(%rsp, 1, V_SSP, %rax)	/* get saved stack pointer */
	SET_V(%rax, 0, V_U_EIP, %r15)	/* save new return addr in %eip */ 
	GET_V(%rsp, 1, V_URET_ADDR, %rax) /* %rax has orig. return addr. */

	popq	%r15			/* Restore scratch register	*/
	movq	V_SSP(%rsp), %rsp	/* Remove callback stuff from stack */
	jmp	sys_sysint_swapgs_iret
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

	/*
  	 * To 'return' to our user-space handler, we need to replace the
	 * iret target address.
	 * The original return address is passed in %eax.
	 */
	CALC_TABLE_ADDR(%ebx)		/* new return addr is in %ebx */
	SET_V(%esp, 1, V_U_EIP, %ebx)	/* set iret target address to hdlr */
	GET_V(%esp, 1, V_URET_ADDR, %eax) /* save orig return addr in %eax */

	GET_V(%esp, 1, V_U_GS, %ebx)	/* grab the the user %gs	*/
	movw	%bx, %gs		/* restore the user %gs	*/

	popl	%ebx			/* Restore scratch register	*/
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

	/*
  	 * To 'return' to our user-space handler, we just need to place its
	 * address into %edx.
	 * The original return address is passed in %eax.
	 */
	movl    %edx, %ebx		/* save orig return addr in tmp reg */
	CALC_TABLE_ADDR(%edx)		/* new return addr is in %edx */
	movl    %ebx, %eax		/* save orig return addr in %eax */

	GET_V(%esp, 1, V_U_GS, %ebx)	/* grab the the user %gs	*/
	movw	%bx, %gs		/* restore the user %gs	*/

	popl	%ebx			/* restore scratch register	*/
	sysexit
9:
	popl	%ebx
	ret
SET_SIZE(sn1_brand_sysenter_callback)

#endif	/* !__amd64 */
#endif	/* lint */
