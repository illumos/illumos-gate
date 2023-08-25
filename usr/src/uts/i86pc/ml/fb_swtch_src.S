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
 * Copyright 2018 Joyent, Inc.
 */


#include <sys/asm_linkage.h>
#include <sys/segments.h>
#include <sys/controlregs.h>
#include <sys/machparam.h>
#include <sys/multiboot.h>
#include <sys/fastboot.h>
#include "assym.h"

/*
 * This code is to switch from 64-bit or 32-bit to protected mode.
 */

/*
 * For debugging with LEDs
 */
#define	FB_OUTB_ASM(val)	\
    movb	val, %al;	\
    outb	$0x80;


#define	DISABLE_PAGING							\
	movl	%cr4, %eax						;\
	btrl	$17, %eax	/* clear PCIDE bit */			;\
	movl	%eax, %cr4						;\
	movl	%cr0, %eax						;\
	btrl	$31, %eax	/* clear PG bit */			;\
	movl	%eax, %cr0

/*
 * This macro contains common code for 64/32-bit versions of copy_sections().
 * On entry:
 *	fbf points to the fboot_file_t
 *	snum contains the number of sections
 * Registers that would be clobbered:
 *	fbs, snum, %eax, %ecx, %edi, %esi.
 * NOTE: fb_dest_pa is supposed to be in the first 1GB,
 * therefore it is safe to use 32-bit register to hold it's value
 * even for 64-bit code.
 */

#define	COPY_SECT(fbf, fbs, snum)		\
	lea	FB_SECTIONS(fbf), fbs;		\
	xorl	%eax, %eax;			\
1:	movl	FB_DEST_PA(fbf), %esi;		\
	addl	FB_SEC_OFFSET(fbs), %esi;	\
	movl	FB_SEC_PADDR(fbs), %edi;	\
	movl	FB_SEC_SIZE(fbs), %ecx;		\
	rep					\
	  movsb;				\
	/* Zero BSS */				\
	movl	FB_SEC_BSS_SIZE(fbs), %ecx;	\
	rep					\
	  stosb;				\
	add	$FB_SECTIONS_INCR, fbs;		\
	dec	snum;				\
	jnz	1b


	.globl	_start
_start:

	/* Disable interrupts */
	cli

	/* Switch to a low memory stack */
	movq	$_start, %rsp
	addq	$FASTBOOT_STACK_OFFSET, %rsp

	/*
	 * Copy from old stack to new stack
	 * If the content before fi_valid gets bigger than 0x200 bytes,
	 * the reserved stack size above will need to be changed.
	 */
	movq	%rdi, %rsi	/* source from old stack */
	movq	%rsp, %rdi	/* destination on the new stack */
	movq	$FI_VALID, %rcx	/* size to copy */
	rep
	  smovb

	xorl	%eax, %eax
	xorl	%edx, %edx

	movl	$MSR_AMD_FSBASE, %ecx
	wrmsr

	movl	$MSR_AMD_GSBASE, %ecx
	wrmsr

	movl	$MSR_AMD_KGSBASE, %ecx
	wrmsr

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

	/*
	 * Load our own GDT
	 */
	lgdt	gdt_info
	/*
	 * Load our own IDT
	 */
	lidt	idt_info

	/*
	 * Invalidate all TLB entries.
	 * Load temporary pagetables to copy kernel and boot-archive
	 */
	movq	%cr4, %rax
	andq	$_BITNOT(CR4_PGE), %rax
	movq	%rax, %cr4
	movq	FI_PAGETABLE_PA(%rsp), %rax
	movq	%rax, %cr3

	leaq	FI_FILES(%rsp), %rbx	/* offset to the files */

	/* copy unix to final destination */
	movq	FI_LAST_TABLE_PA(%rsp), %rsi	/* page table PA */
	leaq	_MUL(FASTBOOT_UNIX, FI_FILES_INCR)(%rbx), %rdi
	call	map_copy

	/* copy boot archive to final destination */
	movq	FI_LAST_TABLE_PA(%rsp), %rsi	/* page table PA */
	leaq	_MUL(FASTBOOT_BOOTARCHIVE, FI_FILES_INCR)(%rbx), %rdi
	call	map_copy

	/* Copy sections if there are any */
	leaq	_MUL(FASTBOOT_UNIX, FI_FILES_INCR)(%rbx), %rdi
	movl	FB_SECTCNT(%rdi), %esi
	cmpl	$0, %esi
	je	1f
	call	copy_sections
1:
	/*
	 * Shut down 64 bit mode. First get into compatiblity mode.
	 */
	movq	%rsp, %rax
	pushq	$B32DATA_SEL
	pushq	%rax
	pushf
	pushq	$B32CODE_SEL
	pushq	$1f
	iretq

	.code32
1:
	movl	$B32DATA_SEL, %eax
	movw	%ax, %ss
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs

	/*
	 * Disable long mode by:
	 * - shutting down paging (bit 31 of cr0).  This will flush the
	 *   TLBs.
	 * - turning off PCID in cr4
	 * - disabling LME (long mode enable) in EFER (extended feature reg)
	 */
	DISABLE_PAGING		/* clobbers %eax */

	ljmp	$B32CODE_SEL, $1f
1:

	/*
	 * Clear PGE, PAE and PSE flags as dboot expects them to be
	 * cleared.
	 */
	movl	%cr4, %eax
	andl	$_BITNOT(CR4_PGE | CR4_PAE | CR4_PSE), %eax
	movl	%eax, %cr4

	movl	$MSR_AMD_EFER, %ecx	/* Extended Feature Enable */
	rdmsr
	btcl	$8, %eax		/* bit 8 Long Mode Enable bit */
	wrmsr

dboot_jump:
	/* Jump to dboot */
	movl	$DBOOT_ENTRY_ADDRESS, %edi
	movl	FI_NEW_MBI_PA(%esp), %ebx
	movl	$MB_BOOTLOADER_MAGIC, %eax
	jmp	*%edi

	.code64
	ENTRY_NP(copy_sections)
	/*
	 * On entry
	 *	%rdi points to the fboot_file_t
	 *	%rsi contains number of sections
	 */
	movq	%rdi, %rdx
	movq	%rsi, %r9

	COPY_SECT(%rdx, %r8, %r9)
	ret
	SET_SIZE(copy_sections)

	ENTRY_NP(map_copy)
	/*
	 * On entry
	 *	%rdi points to the fboot_file_t
	 *	%rsi has FI_LAST_TABLE_PA(%rsp)
	 */

	movq	%rdi, %rdx
	movq	%rsi, %r8
	movq	FB_PTE_LIST_PA(%rdx), %rax	/* PA list of the source */
	movq	FB_DEST_PA(%rdx), %rdi		/* PA of the destination */

2:
	movq	(%rax), %rcx			/* Are we done? */
	cmpl	$FASTBOOT_TERMINATE, %ecx
	je	1f

	movq	%rcx, (%r8)
	movq	%cr3, %rsi		/* Reload cr3 */
	movq	%rsi, %cr3
	movq	FB_VA(%rdx), %rsi	/* Load from VA */
	movq	$PAGESIZE, %rcx
	shrq	$3, %rcx		/* 8-byte at a time */
	rep
	  smovq
	addq	$8, %rax 		/* Go to next PTE */
	jmp	2b
1:
	ret
	SET_SIZE(map_copy)

idt_info:
	.value	0x3ff
	.quad	0

/*
 * We need to trampoline thru a gdt we have in low memory.
 */
#include "../boot/boot_gdt.s"
