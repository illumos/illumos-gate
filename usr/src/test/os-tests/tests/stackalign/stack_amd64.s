/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Get the stack at entry and call a function with it as an argument.
 */

	.file	"stack_amd64.s"

#include <sys/asm_linkage.h>

/*
 * void
 * get_stack_at_entry(test_ctx_t *ctx)
 *
 * ctx+0 is void (*)(uintptr_t stack, char *text),
 * and ctx+8 is the 'text' argument.
 *
 * Passes the stack pointer prior to the invoking call instruction
 * to the specified function.
 */
	ENTRY(get_stack_at_entry)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rdi, %rax
	leaq	16(%rbp), %rdi
	movq	8(%rax), %rsi
	call	*(%rax)
	popq	%rbp
	ret
	SET_SIZE(get_stack_at_entry)

/*
 * void
 * get_stack_at_init(void)
 *
 * Passes the stack pointer prior to the invoking call instruction
 * to initarray() (defined elsewhere).
 * Tests alignment in section .init_array.
 */
	ENTRY(get_stack_at_init)
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	16(%rbp), %rdi
	call	initarray@PLT
	popq	%rbp
	ret
	SET_SIZE(get_stack_at_init)

/*
 * Passes the stack pointer during init to initmain() (defined elsewhere).
 * Tests alignment in section .init.
 */
	.section ".init"
	movq	%rsp, %rdi
	call	initmain@PLT

