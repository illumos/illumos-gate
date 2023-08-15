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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <brand_misc.h>

/*
 * Each JMP must occupy 16 bytes
 */
#define	JMP	\
	pushq	$_CONST(. - brand_handler_table); \
	jmp	brand_handler;	\
	.align	16;

#define	JMP4	JMP; JMP; JMP; JMP
#define JMP16	JMP4; JMP4; JMP4; JMP4
#define JMP64	JMP16; JMP16; JMP16; JMP16
#define JMP256	JMP64; JMP64; JMP64; JMP64

#if defined(lint)

void
brand_handler_table(void)
{}

void
brand_handler(void)
{
}

#else	/* lint */

	/*
	 * On entry to this table, %rax will hold the return address. The
	 * location where we enter the table is a function of the system
	 * call number. The table needs the same alignment as the individual
	 * entries.
	 */
	.align	16
	ENTRY_NP(brand_handler_table)
	JMP256
	SET_SIZE(brand_handler_table)

	/*
	 * %rax - userland return address
	 * stack contains:
	 *    |    --------------------------------------
	 *    v  8 | syscall arguments			|
	 *  %rsp+0 | syscall number			|
	 *         --------------------------------------
	 */
	ENTRY_NP(brand_handler)
	pushq	%rbp			/* allocate stack frame */
	movq	%rsp, %rbp

	/* Save registers at the time of the syscall. */
	movq	$0, EH_LOCALS_GREG(REG_TRAPNO)(%rbp)
	movq	$0, EH_LOCALS_GREG(REG_ERR)(%rbp)
	movq	%r15, EH_LOCALS_GREG(REG_R15)(%rbp)
	movq	%r14, EH_LOCALS_GREG(REG_R14)(%rbp)
	movq	%r13, EH_LOCALS_GREG(REG_R13)(%rbp)
	movq	%r12, EH_LOCALS_GREG(REG_R12)(%rbp)
	movq	%r11, EH_LOCALS_GREG(REG_R11)(%rbp)
	movq	%r10, EH_LOCALS_GREG(REG_R10)(%rbp)
	movq	%r9, EH_LOCALS_GREG(REG_R9)(%rbp)
	movq	%r8, EH_LOCALS_GREG(REG_R8)(%rbp)
	movq	%rdi, EH_LOCALS_GREG(REG_RDI)(%rbp)
	movq	%rsi, EH_LOCALS_GREG(REG_RSI)(%rbp)
	movq	%rbx, EH_LOCALS_GREG(REG_RBX)(%rbp)
	movq	%rcx, EH_LOCALS_GREG(REG_RCX)(%rbp)
	movq	%rdx, EH_LOCALS_GREG(REG_RDX)(%rbp)
	xorq	%rcx, %rcx
	movw	%cs, %cx
	movq	%rcx, EH_LOCALS_GREG(REG_CS)(%rbp)
	movw	%ds, %cx
	movq	%rcx, EH_LOCALS_GREG(REG_DS)(%rbp)
	movw	%es, %cx
	movq	%rcx, EH_LOCALS_GREG(REG_ES)(%rbp)
	movw	%fs, %cx
	movq	%rcx, EH_LOCALS_GREG(REG_FS)(%rbp)
	movw	%gs, %cx
	movq	%rcx, EH_LOCALS_GREG(REG_GS)(%rbp)
	movw	%ss, %cx
	movq	%rcx, EH_LOCALS_GREG(REG_SS)(%rbp)
	pushfq					/* save syscall flags */
	popq	%r12
	movq	%r12, EH_LOCALS_GREG(REG_RFL)(%rbp)
	movq	EH_ARGS_OFFSET(0)(%rbp), %r12	/* save syscall rbp */
	movq	%r12, EH_LOCALS_GREG(REG_RBP)(%rbp)
	movq	%rbp, %r12			/* save syscall rsp */
	addq	$CPTRSIZE, %r12
	movq	%r12, EH_LOCALS_GREG(REG_RSP)(%rbp)
	movq	%fs:0, %r12			/* save syscall fsbase */
	movq	%r12, EH_LOCALS_GREG(REG_FSBASE)(%rbp)
	movq	$0, EH_LOCALS_GREG(REG_GSBASE)(%rbp)

	/*
	 * The kernel drops us into the middle of the brand_handle_table
	 * above that then pushes that table offset onto the stack, and calls
	 * into brand_handler. That offset indicates the system call number
	 * while %rax holds the return address for the system call. We replace
	 * the value on the stack with the return address, and use the value to
	 * compute the system call number by dividing by the table entry size.
	 */
	xchgq	CPTRSIZE(%rbp), %rax	/* swap JMP table offset and ret addr */
	shrq	$4, %rax		/* table_offset/size = syscall num */
	movq	%rax, EH_LOCALS_GREG(REG_RAX)(%rbp) /* save syscall num */

	/*
	 * Finish setting up our stack frame.  We would normally do this
	 * upon entry to this function, but in this case we delayed it
	 * because a "sub" operation can modify flags and we wanted to
	 * save the flags into the gregset_t above before they get modified.
	 *
	 * Our stack frame format is documented in brand_misc.h.
	 */
	subq	$EH_LOCALS_SIZE, %rsp

	/* Look up the system call's entry in the sysent table */
	movq	brand_sysent_table@GOTPCREL(%rip), %r11 /* %r11 = sysent_tbl */
	shlq	$4, %rax		/* each entry is 16 bytes */
	addq	%rax, %r11		/* %r11 = sysent entry address */

	/*
	 * Get the return value flag and the number of arguments from the
	 * sysent table.
	 */
	movq	CPTRSIZE(%r11), %r12		/* number of args + rv flag */
	andq	$RV_MASK, %r12			/* strip out number of args */
	movq	%r12, EH_LOCALS_RVFLAG(%rbp)	/* save rv flag */

	/*
	 * Setup arguments for our emulation call.  Our input arguments,
	 * 0 to N, will become emulation call arguments 1 to N+1.
	 *
	 * Note: Syscall argument passing is different from function call
	 * argument passing on amd64.  For function calls, the fourth arg
	 * is passed via %rcx, but for system calls the 4th argument is
	 * passed via %r10.  This is because in amd64, the syscall
	 * instruction puts lower 32 bit of %rflags in %r11 and puts the
	 * %rip value to %rcx.
	 */
	movq	EH_ARGS_OFFSET(4)(%rbp), %r12		/* copy 8th arg */
	movq	%r12, EH_ARGS_OFFSET(2)(%rsp)
	movq	EH_ARGS_OFFSET(3)(%rbp), %r12		/* copy 7th arg */
	movq	%r12, EH_ARGS_OFFSET(1)(%rsp)
	movq	%r9, EH_ARGS_OFFSET(0)(%rsp)
	movq	%r8, %r9
	movq	%r10, %r8
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	movq	%rdi, %rsi

	/*
	 * The first parameter to the emulation callback function is a
	 * pointer to a sysret_t structure.
	 */
	movq	%rbp, %rdi
	addq	$EH_LOCALS_SYSRET, %rdi		/* arg0 == sysret_t ptr */

	/* invoke the emulation routine */
	ALTENTRY(brand_handler_savepc)
	call	*(%r11)

	/* restore scratch and parameter registers */
	movq	EH_LOCALS_GREG(REG_R12)(%rbp), %r12	/* restore %r12 */
	movq	EH_LOCALS_GREG(REG_R11)(%rbp), %r11	/* restore %r11 */
	movq	EH_LOCALS_GREG(REG_R10)(%rbp), %r10	/* restore %r10 */
	movq	EH_LOCALS_GREG(REG_R9)(%rbp), %r9	/* restore %r9 */
	movq	EH_LOCALS_GREG(REG_R8)(%rbp), %r8	/* restore %r8 */
	movq	EH_LOCALS_GREG(REG_RCX)(%rbp), %rcx	/* restore %rcx */
	movq	EH_LOCALS_GREG(REG_RDX)(%rbp), %rdx	/* restore %rdx */
	movq	EH_LOCALS_GREG(REG_RSI)(%rbp), %rsi	/* restore %rsi */
	movq	EH_LOCALS_GREG(REG_RDI)(%rbp), %rdi	/* restore %rdi */

	/* Check for syscall emulation success or failure */
	cmpq	$0, %rax
	je	success
	stc					/* failure, set carry flag */
	jmp	return				/* return, %rax == errno */

success:
	/* There is always at least one return value. */
	movq	EH_LOCALS_SYSRET1(%rbp), %rax	/* %rax == sys_rval1 */
	cmpq	$RV_DEFAULT, EH_LOCALS_RVFLAG(%rbp) /* check rv flag */
	je	clear_carry
	mov	EH_LOCALS_SYSRET2(%rbp), %rdx	/* %rdx == sys_rval2 */
clear_carry:
	clc					/* success, clear carry flag */

return:
	movq	%rbp, %rsp			/* restore stack */
	popq	%rbp
	ret					/* ret to instr after syscall */
	SET_SIZE(brand_handler)


#endif	/* lint */
