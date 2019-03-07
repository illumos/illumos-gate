/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.u
 */

/*
 * Copyright 2019, Richard Lowe.
 */

        .section .rodata.str1.1,"aMS",@progbits,1
.LC0:
        .string "foo: %s (%p)\n"
        .section .tdata,"awT",@progbits
        .align 4
	.type foo, @object
        .size foo,4
.local foo
foo:
	.string	"foo"
        .text
.globl main
        .type main, @function
main:
        pushl %ebp
        movl %esp, %ebp
	/*
         * an R_386_TLS_LDM relocation without a following
         * followed by an R_386_PLT32 relocation, rather than an
	 * R_386_TLS_LDM_PLT the call should be removed, and _not_
         * left alone unrelocated as it was prior to:
         * 10267 ld and GCC disagree about i386 local dynamic TLS
         */
        leal foo@TLSLDM(%ebx), %eax
        call ___tls_get_addr@PLT
        leal  foo@DTPOFF(%eax), %edx
        pushl %edx
        pushl %edx
        pushl $.LC0
        call printf@PLT
        movl $0x0,%eax
        leave
        ret
	.size main, .-main
