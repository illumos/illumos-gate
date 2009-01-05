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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/
/ Inline functions specific to the i86pc kernel running on bare metal.
/

/
/ return value of cr3 register
/
	.inline	getcr3,0
	movl	%cr3, %eax
	.end

/
/ reload cr3 register with its current value
/
	.inline	reload_cr3,0
	movl	%cr3, %eax
	movl	%eax, %cr3
	.end

/*
 * Put a new value into cr3 (page table base register
 *	void setcr3(void *value)
 */
	.inline	setcr3,4
	movl	(%esp), %eax
	movl	%eax, %cr3
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
	pushfl
	cli
	popl	%eax
	.end

	.inline	intr_clear,0
	pushfl
	cli
	popl	%eax
	.end

/
/ return the flags register
/
	.inline getflags,0
	pushfl
	popl	%eax
	.end

/
/ restore interrupt enable flag to value returned from 'clear_int_flag' above
/
	.inline restore_int_flag,4
	testl	$0x200, (%esp)
	jz	1f
	sti
1:
	.end

	.inline intr_restore,4
	testl	$0x200, (%esp)
	jz	1f
	sti
1:
	.end

/
/ in and out
/
	.inline	inb,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inb	(%dx)
	.end

	.inline	inw,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inw	(%dx)
	.end

	.inline	inl,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inl	(%dx)
	.end

	.inline	outb,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outb	(%dx)
	.end

	.inline	outw,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outw	(%dx)
	.end

	.inline	outl,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outl	(%dx)
	.end

/*
 * Invalidate TLB translation to 1 page.
 *	void mmu_tlbflush_entry(void *addr)
 */
	.inline	mmu_tlbflush_entry,4
	movl	(%esp), %eax
	invlpg	(%eax)
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

/*
 * execute the bsrw instruction
 *	int bsrw_insn(uint16_t)
 */
	.inline	bsrw_insn,4
	xorl	%eax, %eax
	movw	(%esp), %cx
	bsrw	%cx, %ax
	.end

/
/ prefetch 64 bytes
/ prefetch is an SSE extension which is not supported on older 32-bit processors
/ so define this as a no-op for now
/
	.inline	prefetch64,4
/	movl  (%esp), %eax
/	prefetcht0 (%eax)
/	prefetcht0 32(%eax)
	.end

