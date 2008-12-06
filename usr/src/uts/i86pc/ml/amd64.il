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


/
/ Inline functions specific to the i86pc kernel running on bare metal.
/

/
/ return value of cr3 register
/
	.inline	getcr3,0
	movq	%cr3, %rax
	.end

/
/ reload cr3 register with its current value
/
	.inline	reload_cr3,0
	movq	%cr3, %rdi
	movq	%rdi, %cr3
	.end

/
/ set cr3 register with new value
/
	.inline	setcr3,0
	movq	%rdi, %cr3
	.end

/
/ return value of cr8 register
/
	.inline	getcr8,0
	movq	%cr8, %rax
	.end

/
/ set cr8 register
/
	.inline	setcr8,0
	movq	%rdi, %cr8
	.end

/
/ enable interrupts
/
	.inline	sti,0
	sti
	.end

/
/ disable interrupts
/
	.inline cli,0
	cli
	.end

/
/ disable interrupts and return value describing if interrupts were enabled
/
	.inline	clear_int_flag,0
	pushfq
	cli
	popq	%rax
	.end

	.inline	intr_clear,0
	pushfq
	cli
	popq	%rax
	.end

/
/ return the value of the flags register
/
	.inline	getflags,0
	pushfq
	popq	%rax
	.end

/
/ restore interrupt enable flag to value returned from 'clear_int_flag' above
/
	.inline restore_int_flag,4
	testq	$0x200, %rdi
	jz	1f
	sti
1:
	.end

	.inline intr_restore,4
	testq	$0x200, %rdi
	jz	1f
	sti
1:
	.end

/
/ in and out
/
	.inline	inb,4
	movq	%rdi, %rdx
	xorq    %rax, %rax
	inb	(%dx)
	.end

	.inline	inw,4
	movq	%rdi, %rdx
	xorq    %rax, %rax
	inw	(%dx)
	.end

	.inline	inl,4
	movq	%rdi, %rdx
	xorq    %rax, %rax
	inl	(%dx)
	.end

	.inline	outb,8
	movq	%rdi, %rdx
	movq	%rsi, %rax
	outb	(%dx)
	.end

	.inline	outw,8
	movq	%rdi, %rdx
	movq	%rsi, %rax
	outw	(%dx)
	.end

	.inline	outl,8
	movq	%rdi, %rdx
	movq	%rsi, %rax
	outl	(%dx)
	.end

/*
 * Call the halt instruction. This will put the CPU to sleep until
 * it is again awoken via an interrupt.
 * This function should be called with interrupts already disabled
 * for the CPU.
 * Note that "sti" will only enable interrupts at the end of the
 * subsequent instruction...in this case: "hlt".
 */
	.inline i86_halt,0
	sti
	hlt
	.end
/
/ execute the bsrw instruction
/
	.inline bsrw_insn,4
	xorl	%eax, %eax
	bsrw	%di, %ax
	.end

/
/ prefetch 64 bytes
/
	.inline	prefetch64,8
	prefetcht0 (%rdi)
	prefetcht0 32(%rdi)
	.end

