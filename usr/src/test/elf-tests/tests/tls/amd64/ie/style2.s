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
 * Copyright 2012, Richard Lowe.
 */

	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"foo: %p\n"
	.text
.globl main
	.type	main, @function
main:
.LFB0:
	pushq	%rbp
.LCFI0:
	movq	%rsp, %rbp
.LCFI1:
	movq	foo@GOTTPOFF(%rip), %rsi
	addq	%fs:0, %rsi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	printf
	movl	$0, %eax
	leave
	ret
.LFE0:
	.size	main, .-main
.globl foo
	.section	.rodata.str1.1
.LC1:
	.string	"foo"
	.section	.tdata,"awT",@progbits
	.align 8
	.type	foo, @object
	.size	foo, 8
foo:
	.quad	.LC1
