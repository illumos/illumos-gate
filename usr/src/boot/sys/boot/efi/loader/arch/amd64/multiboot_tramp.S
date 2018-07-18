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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#include <x86/specialreg.h>

	.file	"multiboot_tramp.s"

/*
 * The current dboot in illumos kernel is running in 32bit mode
 * and expecting following 32-bit multiboot execution environment:
 *
 * EAX: MB magic
 * EBX: 32-bit physical address of MBI
 * CS: 32-bit read/execute code segment with offset 0 and limit 0xFFFFFFFF
 * DS: 32-bit read/write code segment with offset 0 and limit 0xFFFFFFFF
 * ES: 32-bit read/write code segment with offset 0 and limit 0xFFFFFFFF
 * FS: 32-bit read/write code segment with offset 0 and limit 0xFFFFFFFF
 * GS: 32-bit read/write code segment with offset 0 and limit 0xFFFFFFFF
 * SS: 32-bit read/write data segment with offset 0 and limit 0xFFFFFFFF
 * A20 enabled
 * CR0: PG cleared, PE set
 * EFLAGS: VM cleared, IF cleared
 * interrupts disabled
 */

		.set	SEL_SCODE,0x8
		.set	SEL_SDATA,0x10

		.text
		.p2align 4
		.globl	multiboot_tramp
		.type	multiboot_tramp, STT_FUNC

/*
 * void multiboot_tramp(uint32_t magic, struct relocator *relocator,
 *    uint64_t entry)
 */
multiboot_tramp:
		cli
		movq	(%rsi), %rax
		movq	%rax, %rsp		/* Switch to temporary stack. */
		movq	0x8(%rsi), %rax		/* relocator->copy */
		pushq	%rdi			/* save magic */
		pushq	%rdx			/* save entry */
		movq	%rsi, %rdi
		callq	*%rax
		movq	%rax, %rbx		/* MBI */
		popq	%rsi			/* entry to rsi */
		popq	%rdi			/* restore magic */
		lea	gdt(%rip), %rax
		lea	gdtaddr(%rip), %rdx
		movq	%rax, (%rdx)
		lea	gdtdesc(%rip), %rax
		lgdt	(%rax)

		/* record the address */
		lea	multiboot_tramp_2(%rip), %rcx
		movq	%rsp, %rax
		pushq	$SEL_SDATA
		pushq	%rax
		pushf
		pushq	$SEL_SCODE
		lea	multiboot_tramp_1(%rip), %rax
		pushq	%rax
		iretq

		.code32
multiboot_tramp_1:
		movl	$SEL_SDATA, %eax
		movw	%ax, %ss
		movw	%ax, %ds
		movw	%ax, %es
		movw	%ax, %fs
		movw	%ax, %gs

		movl	%cr0, %eax		/* disable paging */
		btrl	$31, %eax
		movl	%eax, %cr0
		jmp	*%ecx
multiboot_tramp_2:
		movl	%cr4, %eax		/* disable PAE, PGE, PSE */
		andl	$~(CR4_PGE | CR4_PAE | CR4_PSE), %eax
		movl	%eax, %cr4
		movl	$MSR_EFER, %ecx
		rdmsr				/* updates %edx:%eax */
		btcl	$8, %eax		/* clear long mode */
		wrmsr
		movl	%edi, %eax		/* magic */
		jmp	*%esi			/* jump to kernel */

/* GDT record */
		.p2align 4
gdt:
		.word	0x0, 0x0		/* NULL entry */
		.byte	0x0, 0x0, 0x0, 0x0
		.word	0xffff, 0x0		/* code segment */
		.byte	0x0, 0x9a, 0xcf, 0x0
		.word	0xffff, 0x0		/* data segment */
		.byte	0x0, 0x92, 0xcf, 0x0
gdt_end:

		.p2align 4
gdtdesc:	.word	gdt_end - gdt - 1	/* limit */
gdtaddr:	.long	0			/* base */
		.long	0

multiboot_tramp_end:
