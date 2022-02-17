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
 * dboot expects a 32-bit multiboot environment and to execute in 32-bit mode.
 *
 * EAX: MB magic
 * EBX: 32-bit physical address of MBI
 * CS: 32-bit read/execute code segment with offset 0 and limit 0xFFFFFFFF
 * DS: 32-bit read/write data segment with offset 0 and limit 0xFFFFFFFF
 * ES: 32-bit read/write data segment with offset 0 and limit 0xFFFFFFFF
 * FS: 32-bit read/write data segment with offset 0 and limit 0xFFFFFFFF
 * GS: 32-bit read/write data segment with offset 0 and limit 0xFFFFFFFF
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
 * Note as we are running in 32-bit mode, all pointers are 32-bit.
 * void multiboot_tramp(uint32_t magic, struct relocator *relocator,
 *    vm_offset_t entry)
 */
multiboot_tramp:
		cli
		pushl	%ebp		/* keep familiar stack frame */
		movl	%esp, %ebp	/* current SP */
		movl	0xc(%ebp),%eax	/* relocator */
		movl	(%eax), %eax	/* new SP */
		movl	%eax, %esp

		/* now copy arguments to new stack */
		movl	0x10(%ebp),%eax	/* entry */
		pushl	%eax
		movl	0xc(%ebp),%eax	/* relocator */
		pushl	%eax
		movl	0x8(%ebp),%eax	/* magic */
		pushl	%eax
		xorl	%eax,%eax
		pushl	%eax		/* fake IP, just to keep stack frame */
		pushl	%ebp
		movl	%esp, %ebp
		subl	$0x30, %esp	/* local mbi, gdt and gdt desc */

		movl	0xc(%ebp), %eax	/* relocator */
		pushl	%eax
		movl	0x4(%eax), %eax	/* relocator->copy */
		call	*%eax
		addl	$0x4, %esp
		movl	%eax, -0x4(%ebp)	/* save MBI */

		/* set up GDT descriptor */
		lea	-0x1c(%ebp), %eax	/* address of GDT */
		movw	$0x17, -0x22(%ebp)	/* limit */
		movl	%eax, -0x20(%ebp)	/* base */

/*
 * set up following GDT:
 *		.word	0x0, 0x0		NULL entry
 *		.byte	0x0, 0x0, 0x0, 0x0
 *		.word	0xffff, 0x0		code segment
 *		.byte	0x0, 0x9a, 0xcf, 0x0
 *		.word	0xffff, 0x0		data segment
 *		.byte	0x0, 0x92, 0xcf, 0x0
 *
 * This will create access for 4GB flat memory with
 * base = 0x00000000, segment limit = 0xffffffff
 * page granulariy 4k
 * 32-bit protected mode
 * ring 0
 * code segment is executable RW
 * data segment is not-executable RW
 */
		movw	$0x0, -0x1c(%ebp)
		movw	$0x0, -0x1a(%ebp)
		movb	$0x0, -0x18(%ebp)
		movb	$0x0, -0x17(%ebp)
		movb	$0x0, -0x16(%ebp)
		movb	$0x0, -0x15(%ebp)

		movw	$0xffff, -0x14(%ebp)
		movw	$0x0, -0x12(%ebp)
		movb	$0x0, -0x10(%ebp)
		movb	$0x9a, -0xf(%ebp)
		movb	$0xcf, -0xe(%ebp)
		movb	$0x0, -0xd(%ebp)

		movw	$0xffff, -0xc(%ebp)
		movw	$0x0, -0xa(%ebp)
		movb	$0x0, -0x8(%ebp)
		movb	$0x92, -0x7(%ebp)
		movb	$0xcf, -0x6(%ebp)
		movb	$0x0, -0x5(%ebp)

		lea	-0x22(%ebp), %eax	/* address of GDT */
		lgdt	(%eax)

		movl	0x8(%ebp), %edx		/* magic */
		movl	-0x4(%ebp), %ebx	/* MBI */
		movl	0x10(%ebp), %esi	/* entry */

		movl	$SEL_SDATA, %eax
		movw	%ax, %ss
		movw	%ax, %ds
		movw	%ax, %es
		movw	%ax, %fs
		movw	%ax, %gs

		/*
		 * We most likely don't need to push SEL_SDATA and esp
		 * because we do not expect to perform a privilege transition.
		 * However, it doesn't hurt us to push them as dboot will set
		 * up its own stack.
		 */
		movl	%esp, %eax
		pushl	$SEL_SDATA
		pushl	%eax
		pushf
		pushl	$SEL_SCODE
		pushl	%esi
		movl	%edx, %eax
		iretl

multiboot_tramp_end:
