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
	.string	"foo: %s (%p)\n"
	.text
	.section	.tdata,"awT",@progbits
foo:
	.string	"incorrect"
        .text
.globl main
	.type	main, @function
main:
.LFB0:
	pushq	%rbp
.LCFI0:
	movq	%rsp, %rbp
        .LCFI1:
	leaq	foo@tlsld(%rip), %rdi
	call	__tls_get_addr@plt
	leaq	2+foo@dtpoff(%rax), %rsi
        movq	%rsi, %rdx
        movq	%rsi, %rsi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	printf
	movl	$0, %eax
	leave
	ret
	.size	main, .-main
