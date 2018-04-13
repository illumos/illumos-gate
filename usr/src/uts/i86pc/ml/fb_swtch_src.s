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


#if defined(__lint)

int fb_swtch_silence_lint = 0;

#else

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

#if defined(__amd64)
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

#elif defined(__i386)
	movl	0x4(%esp), %esi	/* address of fastboot info struct */

	/* Switch to a low memory stack */
	movl	$_start, %esp
	addl	$FASTBOOT_STACK_OFFSET, %esp

	/* Copy struct to stack */
	movl	%esp, %edi	/* destination on the new stack */
	movl	$FI_VALID, %ecx	/* size to copy */
	rep
	  smovb

#endif

#if defined(__amd64)

	xorl	%eax, %eax
	xorl	%edx, %edx

	movl	$MSR_AMD_FSBASE, %ecx
	wrmsr

	movl	$MSR_AMD_GSBASE, %ecx
	wrmsr

	movl	$MSR_AMD_KGSBASE, %ecx
	wrmsr

#endif
	/*
	 * zero out all the registers to make sure they're 16 bit clean
	 */
#if defined(__amd64)
	xorq	%r8, %r8
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14
	xorq	%r15, %r15
#endif
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebp, %ebp

#if defined(__amd64)
	/*
	 * Load our own GDT
	 */
	lgdt	gdt_info
#endif
	/*
	 * Load our own IDT
	 */
	lidt	idt_info

#if defined(__amd64)
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
#endif
	DISABLE_PAGING		/* clobbers %eax */

#if defined(__amd64)
	ljmp	$B32CODE_SEL, $1f
1:
#endif

	/*
	 * Clear PGE, PAE and PSE flags as dboot expects them to be
	 * cleared.
	 */
	movl	%cr4, %eax
	andl	$_BITNOT(CR4_PGE | CR4_PAE | CR4_PSE), %eax
	movl	%eax, %cr4

#if defined(__amd64)
	movl	$MSR_AMD_EFER, %ecx	/* Extended Feature Enable */
	rdmsr
	btcl	$8, %eax		/* bit 8 Long Mode Enable bit */
	wrmsr

#elif defined(__i386)
	/*
	 * If fi_has_pae is set, re-enable paging with PAE.
	 */
	leal	FI_FILES(%esp), %ebx	/* offset to the files */
	movl	FI_HAS_PAE(%esp), %edi	/* need to enable paging or not */
	cmpl	$0, %edi
	je	paging_on		/* no need to enable paging */

	movl	FI_LAST_TABLE_PA(%esp), %esi	/* page table PA */

	/*
	 * Turn on PAE
	 */
	movl	%cr4, %eax
	orl	$CR4_PAE, %eax
	movl	%eax, %cr4

	/*
	 * Load top pagetable base address into cr3
	 */
	movl	FI_PAGETABLE_PA(%esp), %eax
	movl	%eax, %cr3

	movl	%cr0, %eax
	orl	$_CONST(CR0_PG | CR0_WP | CR0_AM), %eax
	andl	$_BITNOT(CR0_NW | CR0_CD), %eax
	movl	%eax, %cr0
	jmp	paging_on
paging_on:

	/* copy unix to final destination */
	leal	_MUL(FASTBOOT_UNIX, FI_FILES_INCR)(%ebx), %edx
	call	map_copy

	/* copy boot archive to final destination */
	leal	_MUL(FASTBOOT_BOOTARCHIVE, FI_FILES_INCR)(%ebx), %edx
	call	map_copy

	/* Disable paging one more time */
	DISABLE_PAGING

	/* Copy sections if there are any */ 
	leal	_MUL(FASTBOOT_UNIX, FI_FILES_INCR)(%ebx), %edx
	movl	FB_SECTCNT(%edx), %eax
	cmpl	$0, %eax
	je	1f
	call	copy_sections
1:

	/* Whatever flags we turn on we need to turn off */
	movl	%cr4, %eax
	andl	$_BITNOT(CR4_PAE), %eax
	movl	%eax, %cr4
#endif	/* __i386 */

dboot_jump:
	/* Jump to dboot */
	movl	$DBOOT_ENTRY_ADDRESS, %edi
	movl	FI_NEW_MBI_PA(%esp), %ebx
	movl	$MB_BOOTLOADER_MAGIC, %eax
	jmp	*%edi

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY_NP(copy_sections)
	/*
	 * On entry
	 *	%edx points to the fboot_file_t
	 *	%eax contains the number of sections
	 */
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

	movl	%eax, %ebp

	COPY_SECT(%edx, %ebx, %ebp)

	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
	SET_SIZE(copy_sections)	

	ENTRY_NP(map_copy)
	/*
	 * On entry
	 *	%edx points to the fboot_file_t
	 *	%edi has FB_HAS_PAE(%esp)
	 *	%esi has FI_LAST_TABLE_PA(%esp)
	 */
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%ebp
	pushl	%esi
	pushl	%edi
	movl	%esi, %ebp	/* Save page table PA in %ebp */

	movl	FB_PTE_LIST_PA(%edx), %eax	/* PA list of the source */
	movl	FB_DEST_PA(%edx), %ebx		/* PA of the destination */

loop:
	movl	(%eax), %esi			/* Are we done? */
	cmpl	$FASTBOOT_TERMINATE, %esi
	je	done

	cmpl	$1, (%esp)			/* Is paging on? */
	jne	no_paging			/* Nope */

	movl	%ebp, %edi			/* Page table PA */
	movl	%esi, (%edi)			/* Program low 32-bit */
	movl	4(%eax), %esi			/* high bits of the table */
	movl	%esi, 4(%edi)			/* Program high 32-bit */
	movl	%cr3, %esi			/* Reload cr3 */
	movl	%esi, %cr3
	movl	FB_VA(%edx), %esi		/* Load from VA */
	jmp	do_copy
no_paging:
	andl	$_BITNOT(MMU_PAGEOFFSET), %esi	/* clear lower 12-bit */
do_copy:
	movl	%ebx, %edi
	movl	$PAGESIZE, %ecx
	shrl	$2, %ecx	/* 4-byte at a time */
	rep
	  smovl
	addl	$8, %eax /* We built the PTEs as 8-byte entries */
	addl	$PAGESIZE, %ebx
	jmp	loop
done:
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	ret
	SET_SIZE(map_copy)	
#endif	/* __i386 */


idt_info:
	.value	0x3ff
	.quad	0

/*
 * We need to trampoline thru a gdt we have in low memory.
 */
#include "../boot/boot_gdt.s"
#endif /* __lint */
