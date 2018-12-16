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
	.string	"foo: %p bar: %p\n"
	.text
.globl func
	.type	func, @function
func:
.LFB0:
	pushq	%rbp
.LCFI0:
	movq	%rsp, %rbp
.LCFI1:
	movq	%fs:0, %rsi
	movq	%rsi, %rdx
	addq	bar@GOTTPOFF(%rip), %rdx
	addq	foo@GOTTPOFF(%rip), %rsi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	printf
	leave
	ret
.LFE0:
	.size	func, .-func
