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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _COMMON_BRAND_ASM_H
#define	_COMMON_BRAND_ASM_H

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef	lint

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include "assym.h"

#endif	/* lint */

#ifdef _ASM	/* The remainder of this file is only for assembly files */

#if defined(__amd64)
/*
 * Common to all 64-bit callbacks:
 *
 * We're running on the kernel's %gs.
 *
 * We return directly to userland, bypassing the _update_sregs logic, so
 * the routine must NOT do anything that could cause a context switch.
 *
 * %rax - syscall number
 *
 * When called, all general registers, except for %r15, are as they were when
 * the user process made the system call.  %r15 is available to the callback as
 * a scratch register.  If the callback returns to the kernel path, %r15 does
 * not have to be restored to the user value.  If the callback returns to the
 * userlevel emulation code, the callback should restore %r15 if the emulation
 * depends on the original userlevel value.
 *
 * 64-BIT INTERPOSITION STACK
 * On entry to the callback the stack looks like this:
 *         --------------------------------------
 *      32 | callback pointer			|
 *      24 | saved stack pointer		|
 *    | 16 | lwp pointer			|
 *    v  8 | user return address		|
 *       0 | BRAND_CALLBACK()'s return addr 	|
 *         --------------------------------------
 */

#define	V_COUNT	5
#define	V_END		(CLONGSIZE * 5)
#define	V_SSP		(CLONGSIZE * 3)
#define	V_LWP		(CLONGSIZE * 2)
#define	V_URET_ADDR	(CLONGSIZE * 1)
#define	V_CB_ADDR	(CLONGSIZE * 0)

#define	SP_REG		%rsp
#define	SCR_REG		%r15
#define	SCR_REGB	%r15b
#define	SYSCALL_REG	%rax

/*
 * 64-BIT INT STACK
 * For int callbacks (e.g. int91) the saved stack pointer (V_SSP) points at
 * the state saved when we took the interrupt:
 *	   --------------------------------------
 *    | 32 | user's %ss				|
 *    | 24 | user's %esp			|
 *    | 16 | EFLAGS register			|
 *    v  8 | user's %cs				|
 *       0 | user's %eip (user return address)	|
 *	   --------------------------------------
 */
#define	V_U_EIP		(CLONGSIZE * 0)

#else	/* !__amd64 */
/*
 * 32-BIT INTERPOSITION STACK
 * When our syscall interposition callback entry point gets invoked the
 * stack looks like this:
 *         --------------------------------------
 *    | 16 | 'scratch space'			|
 *    | 12 | user's %ebx			|
 *    |  8 | user's %gs selector		|
 *    v  4 | lwp pointer			|
 *       0 | callback wrapper return addr	|
 *         --------------------------------------
 */

#define	V_COUNT	5
#define	V_END		(CLONGSIZE * 5)
#define	V_U_EBX		(CLONGSIZE * 3)
#define	V_LWP		(CLONGSIZE * 1)
#define	V_CB_ADDR	(CLONGSIZE * 0)

#define	SP_REG		%esp
#define	SCR_REG		%ebx
#define	SCR_REGB	%bl
#define	SYSCALL_REG	%eax

/*
 * 32-BIT INT STACK
 * For the lcall handler for 32-bit OS (i.e. xxx_brand_syscall_callback)
 * above the stack contents common to all callbacks is the int/lcall-specific
 * state:
 *	   --------------------------------------
 *    | 36 | user's %ss				|
 *    | 32 | user's %esp			|
 *    | 28 | EFLAGS register			|
 *    v 24 | user's %cs				|
 *      20 | user's %eip (user return address)	|
 *	   --------------------------------------
 */
#define	V_U_EIP		(V_END + (CLONGSIZE * 0))

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
#define	V_OFFSET(pcnt, var)						\
	(var + (pcnt * CLONGSIZE))

#define	GET_V(sp, pcnt, var, reg)					\
	mov	V_OFFSET(pcnt, var)(sp), reg

#define	SET_V(sp, pcnt, var, reg)					\
	mov	reg, V_OFFSET(pcnt, var)(sp)

#define	GET_PROCP(sp, pcnt, reg)					\
	GET_V(sp, pcnt, V_LWP, reg);		/* get lwp pointer */	\
	mov	LWP_PROCP(reg), reg		/* get proc pointer */

#define	GET_P_BRAND_DATA(sp, pcnt, reg)					\
	GET_PROCP(sp, pcnt, reg);					\
	mov	__P_BRAND_DATA(reg), reg	/* get p_brand_data */

/*
 * Each of the following macros returns to the standard syscall codepath if
 * it detects that this process is not able, or intended, to emulate this
 * system call.  They all assume that the routine provides a 'bail-out'
 * label of '9'.
 */

/*
 * See if this process has a user-space handler registered for it.  For the
 * brand, the per-process brand data holds the address of the handler.
 * As shown in the stack diagrams above, the callback code leaves the lwp
 * pointer at well-defined offsets, so check if proc_data_t->X_handler is
 * non-NULL.  For each brand, the handler parameter refers to the brand's
 * user-space handler variable name.
 */
#define	CHECK_FOR_HANDLER(scr, handler)					\
	GET_P_BRAND_DATA(SP_REG, 0, scr);	/* get p_brand_data */	\
	cmp	$0, scr;						\
	je	9f;							\
	cmp	$0, handler(scr);		/* check handler */	\
	je	9f

/*
 * If the system call number is >= 1024, then it is coming from the
 * emulation support library.  As such we should handle it natively instead
 * of sending it back to the emulation library.
 */
#define	CHECK_FOR_NATIVE(reg)		\
	cmp	$1024, reg;		\
	jl	1f;			\
	sub	$1024, reg;		\
	jmp	9f;			\
1:

/*
 * Check to see if we want to interpose on this system call.  If not, we
 * jump back into the normal syscall path and pretend nothing happened.
 * This macro is usable for brands which have the same number of syscalls
 * as the base OS.
 */
#define	CHECK_FOR_INTERPOSITION(emul_table, call, scr, scr_low)		\
	cmp	$NSYSCALL, call;	/* is 0 <= syscall <= MAX? */	\
	ja	9f;			/* no, take normal ret path */	\
	lea	emul_table, scr;					\
	/*CSTYLED*/							\
	mov	(scr), scr;						\
	add	call, scr;						\
	/*CSTYLED*/							\
	movb	(scr), scr_low;						\
	cmpb	$0, scr_low;						\
	je	9f			/* no, take normal ret path */

#define	CALLBACK_PROLOGUE(emul_table, handler, call, scr, scr_low)	\
	CHECK_FOR_HANDLER(scr, handler);				\
	CHECK_FOR_NATIVE(call);						\
	CHECK_FOR_INTERPOSITION(emul_table, call, scr, scr_low)

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
#define	CALC_TABLE_ADDR(scr, handler)					\
	GET_P_BRAND_DATA(SP_REG, 0, scr); /* get p_brand_data ptr */	\
	mov	handler(scr), scr;	/* get p_brand_data->XX_handler */ \
	shl	$4, SYSCALL_REG;	/* syscall_num * 16 */		\
	add	SYSCALL_REG, scr	/* leave return addr in scr reg. */

#endif	/* _ASM */

#ifdef  __cplusplus
}
#endif

#endif	/* _COMMON_BRAND_ASM_H */
