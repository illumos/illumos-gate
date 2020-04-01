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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/segments.h>
#include <sys/controlregs.h>

/*
 * Do a call into BIOS.  This goes down to 16 bit real mode and back again.
 */

/*
 * instruction prefix to change operand size in instruction
 */
#define DATASZ	.byte 0x66;

	.globl	_start
_start:

	/*
	 * Save caller registers
	 */
	movq	%rbp, save_rbp
	movq	%rsp, save_rsp
	movq	%rbx, save_rbx
	movq	%rsi, save_rsi
	movq	%r12, save_r12
	movq	%r13, save_r13
	movq	%r14, save_r14
	movq	%r15, save_r15

	/* Switch to a low memory stack */
	movq	$_start, %rsp

	/* put interrupt number in %bl */
	movq	%rdi, %rbx

	/* allocate space for args on stack */
	subq	$18, %rsp
	movq	%rsp, %rdi

	/* copy args from high memory to stack in low memory */
	cld
	movl	$18, %ecx
	rep
	movsb

	/*
	 * Save system registers
	 */
	sidt	save_idt
	sgdt	save_gdt
	str	save_tr
	movw	%cs, save_cs
	movw	%ds, save_ds
	movw	%ss, save_ss
	movw	%es, save_es
	movw	%fs, save_fs
	movw	%gs, save_gs
	movq	%cr4, %rax
	movq	%rax, save_cr4
	movq	%cr3, %rax
	movq	%rax, save_cr3
	movq	%cr0, %rax
	movq	%rax, save_cr0

	/*
	 * save/clear the extension parts of the fs/gs base registers and cr8
	 */
	movl	$MSR_AMD_FSBASE, %ecx
	rdmsr
	movl	%eax, save_fsbase
	movl	%edx, save_fsbase + 4
	xorl	%eax, %eax
	xorl	%edx, %edx
	wrmsr

	movl	$MSR_AMD_GSBASE, %ecx
	rdmsr
	movl	%eax, save_gsbase
	movl	%edx, save_gsbase + 4
	xorl	%eax, %eax
	xorl	%edx, %edx
	wrmsr

	movl	$MSR_AMD_KGSBASE, %ecx
	rdmsr
	movl	%eax, save_kgsbase
	movl	%edx, save_kgsbase + 4
	xorl	%eax, %eax
	xorl	%edx, %edx
	wrmsr

	movq	%cr8, %rax
	movq	%rax, save_cr8

	/*
	 * set offsets in 16 bit ljmp instructions below
	 */
	leaq	enter_real, %rax
	movw	%ax, enter_real_ljmp

	leaq	enter_protected, %rax
	movw	%ax, enter_protected_ljmp

	leaq	gdt_info, %rax
	movw	%ax, gdt_info_load

	/*
	 * insert BIOS interrupt number into later instruction
	 */
	movb    %bl, int_instr+1
	jmp     1f
1:

	/*
	 * zero out all the registers to make sure they're 16 bit clean
	 */
	xorq	%r8, %r8
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14
	xorq	%r15, %r15
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebp, %ebp
	xorl	%esi, %esi
	xorl	%edi, %edi

	/*
	 * Load our own GDT/IDT
	 */
	lgdt	gdt_info
	lidt	idt_info

	/*
	 * Shut down 64 bit mode. First get into compatibility mode.
	 */
	movq	%rsp, %rax
	pushq	$B32DATA_SEL
	pushq	%rax
	pushf
	pushq	$B32CODE_SEL
	pushq	$1f
	iretq
1:
	.code32

	/*
	 * disable long mode by:
	 * - shutting down paging (bit 31 of cr0)
	 * - flushing the TLB
	 * - disabling LME (long made enable) in EFER (extended feature reg)
	 */
	movl	%cr0, %eax
	btcl	$31, %eax		/* disable paging */
	movl	%eax, %cr0
	ljmp	$B32CODE_SEL, $1f
1:

	xorl	%eax, %eax
	movl	%eax, %cr3		/* flushes TLB */

	movl	$MSR_AMD_EFER, %ecx	/* Extended Feature Enable */
	rdmsr
	btcl	$8, %eax		/* bit 8 Long Mode Enable bit */
	wrmsr

	/*
	 * ok.. now enter 16 bit mode, so we can shut down protected mode
	 *
	 * We'll have to act like we're still in a 32 bit section.
	 * So the code from this point has DATASZ in front of it to get 32 bit
	 * operands. If DATASZ is missing the operands will be 16 bit.
	 *
	 * Now shut down paging and protected (ie. segmentation) modes.
	 */
	ljmp	$B16CODE_SEL, $enter_16_bit
enter_16_bit:

	/*
	 * Make sure hidden parts of segment registers are 16 bit clean
	 */
	DATASZ	movl	$B16DATA_SEL, %eax
		movw    %ax, %ss
		movw    %ax, %ds
		movw    %ax, %es
		movw    %ax, %fs
		movw    %ax, %gs


	DATASZ	movl	$0x0, %eax	/* put us in real mode */
	DATASZ	movl	%eax, %cr0
	.byte	0xea			/* ljmp */
enter_real_ljmp:
	.value	0			/* addr (16 bit) */
	.value	0x0			/* value for %cs */
enter_real:

	/*
	 * zero out the remaining segment registers
	 */
	DATASZ	xorl	%eax, %eax
		movw    %ax, %ss
		movw    %ax, %ds
		movw    %ax, %es
		movw    %ax, %fs
		movw    %ax, %gs

	/*
	 * load the arguments to the BIOS call from the stack
	 */
	popl	%eax	/* really executes a 16 bit pop */
	popl	%ebx
	popl	%ecx
	popl	%edx
	popl	%esi
	popl	%edi
	popl	%ebp
	pop	%es
	pop	%ds

	/*
	 * do the actual BIOS call
	 */
	sti
int_instr:
	int	$0x10		/* this int number is overwritten */
	cli			/* ensure interrupts remain disabled */

	/*
	 * save results of the BIOS call
	 */
	pushf
	push	%ds
	push	%es
	pushl	%ebp		/* still executes as 16 bit */
	pushl	%edi
	pushl	%esi
	pushl	%edx
	pushl	%ecx
	pushl	%ebx
	pushl	%eax

	/*
	 * Restore protected mode and 32 bit execution
	 */
	push	$0			/* make sure %ds is zero before lgdt */
	pop	%ds
	.byte	0x0f, 0x01, 0x16	/* lgdt */
gdt_info_load:
	.value	0	/* temp GDT in currently addressible mem */

	DATASZ	movl	$0x1, %eax
	DATASZ	movl	%eax, %cr0

	.byte	0xea			/* ljmp */
enter_protected_ljmp:
	.value	0			/* addr (still in 16 bit) */
	.value	B32CODE_SEL		/* %cs value */
enter_protected:

	/*
	 * We are now back in a 32 bit code section, fix data/stack segments
	 */
	.code32
	movw	$B32DATA_SEL, %ax
	movw	%ax, %ds
	movw	%ax, %ss

	/*
	 * Re-enable paging. Note we only use 32 bit mov's to restore these
	 * control registers. That's OK as the upper 32 bits are always zero.
	 */
	movl	save_cr4, %eax
	movl	%eax, %cr4
	movl	save_cr3, %eax
	movl	%eax, %cr3

	/*
	 * re-enable long mode
	 */
	movl	$MSR_AMD_EFER, %ecx
	rdmsr
	btsl	$8, %eax
	wrmsr

	movl	save_cr0, %eax
	movl	%eax, %cr0
	jmp	enter_paging
enter_paging:


	/*
	 * transition back to 64 bit mode
	 */
	pushl	$B64CODE_SEL
	pushl	$longmode
	lret
longmode:
	.code64
	/*
	 * restore caller frame pointer and segment registers
	 */
	lgdt	save_gdt
	lidt	save_idt

	/*
	 * Before loading the task register we need to reset the busy bit
	 * in its corresponding GDT selector. The busy bit is the 2nd bit in
	 * the 5th byte of the selector.
	 */
	movzwq	save_tr, %rax
	addq	save_gdt+2, %rax
	btcl	$1, 5(%rax)
	ltr	save_tr
	movw	save_ds, %ds
	movw	save_ss, %ss
	movw	save_es, %es
	movw	save_fs, %fs
	movw	save_gs, %gs

	pushq	save_cs
	pushq	$.newcs
	lretq
.newcs:

	/*
	 * restore the hidden kernel segment base register values
	 */
	movl	save_fsbase, %eax
	movl	save_fsbase + 4, %edx
	movl	$MSR_AMD_FSBASE, %ecx
	wrmsr

	movl	save_gsbase, %eax
	movl	save_gsbase + 4, %edx
	movl	$MSR_AMD_GSBASE, %ecx
	wrmsr

	movl	save_kgsbase, %eax
	movl	save_kgsbase + 4, %edx
	movl	$MSR_AMD_KGSBASE, %ecx
	wrmsr

	movq	save_cr8, %rax
	cmpq	$0, %rax
	je	1f
	movq	%rax, %cr8
1:

	/*
	 * copy results to caller's location, then restore remaining registers
	 */
	movq    save_rsi, %rdi
	movq	%rsp, %rsi
	movq	$18, %rcx
	rep
	movsb
	movw	18(%rsp), %ax
	andq	$0xffff, %rax
	movq    save_r12, %r12
	movq    save_r13, %r13
	movq    save_r14, %r14
	movq    save_r15, %r15
	movq    save_rbx, %rbx
	movq    save_rbp, %rbp
	movq    save_rsp, %rsp
	ret


/*
 * Caller's registers to restore
 */
	.align 4
save_esi:
	.long	0
save_edi:
	.long	0
save_ebx:
	.long	0
save_ebp:
	.long	0
save_esp:
	.long	0

	.align 8
save_rsi:
	.quad	0
save_rbx:
	.quad	0
save_rbp:
	.quad	0
save_rsp:
	.quad	0
save_r12:
	.quad	0
save_r13:
	.quad	0
save_r14:
	.quad	0
save_r15:
	.quad	0
save_kgsbase:
	.quad	0
save_gsbase:
	.quad	0
save_fsbase:
	.quad	0
save_cr8:
	.quad	0

save_idt:
	.quad	0
	.quad	0

save_gdt:
	.quad	0
	.quad	0

save_cr0:
	.quad	0
save_cr3:
	.quad	0
save_cr4:
	.quad	0
save_cs:
	.quad	0
save_ss:
	.value	0
save_ds:
	.value	0
save_es:
	.value	0
save_fs:
	.value	0
save_gs:
	.value	0
save_tr:
	.value	0

idt_info:
	.value 0x3ff
	.quad 0


/*
 * We need to trampoline thru a gdt we have in low memory.
 */
#include "../boot/boot_gdt.s"
