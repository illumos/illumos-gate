/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
/* Copyright 2005 Sun Microsystems, Inc.  All rights reserved. */
/* Use is subject to license terms. */
 
#if defined(lint)

#include <sys/types.h>
#include <sys/bootconf.h>

extern void printf(const char *, ...);

uint_t bpd_loc;
struct bootops *bop;

void start(void) {}
void start_paging(void) { return; }
void halt(char *msg) { printf("%s", msg); }
/*ARGSUSED*/
void exitto(int (*entrypoint)()) {}
void reset(void) {}

/* lint for inline functions in i86.il */
/*ARGSUSED*/
uint8_t inb(int port) { return (*(uint8_t *)port); }
uint16_t inw(int port) { return (*(uint16_t *)port); }
uint32_t inl(int port) { return (*(uint32_t *)port); }
void outb(int port, uint8_t v) { *(uint8_t *)port = v; }
void outw(int port, uint16_t v) { *(uint16_t *)port = v; }
void outl(int port, uint32_t v) { *(uint32_t *)port = v; }

#else

.ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/controlregs.h>
#include <sys/segment.h>
#include <assym.h>
#include "../common/multiboot.h"

.file	"asm.s"
.text

.globl  _start
_start:
       	jmp     multiboot_entry

/*
 * The following header must be present within the first 8K of
 * the binary, according to the Multiboot Specification
 */
.align  4

multiboot_header:
	.long   MB_HEADER_MAGIC		/ multiboot magic
	.long   MB_HEADER_FLAGS		/ flags
	.long   MB_HEADER_CHECKSUM	/ checksum
	.long   multiboot_header	/ header address
	.long   _start			/ load start addr
	.long   _edata			/ load end addr
	.long   _end			/ bss end
	.long   multiboot_entry		/ entry addr

/*
 * Start from where GRUB left off. The processor state is
 * as defined in the Multiboot Specification. We start with:
 *	- initialize the stack, "stack" is declared at the end of file
 *	- push register contents to stack to pass multiboot info
 *	- initialize GDT and (a dummy) IDT
 *	- call main() to load the kernel
 */
multiboot_entry:
	movl	$[stack + STACK_SIZE], %esp
	pushl   $0			/ reset flags
	popf

	push	$0 			/ terminate debugger
	push	$0
	movl	%esp, %ebp

	movl	$[multiboot_header], %ecx
	pushl	%ecx			/ multiboot header
	pushl   %ebx			/ multiboot info
	pushl   %eax			/ multiboot magic

	lgdt	gdtdesc			/ load gdt
	mov	$0x08, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss
	ljmp	$0x10, $newgdt
newgdt:

	movl	$slbidt, %eax		/ load idt
	movl	$0x7ff, %ecx
	call	munge_table
	lidt	IDTptr

	call    main			/ invoke the kernel
	hlt				/ shouldn't get here

/ help function
.globl	halt
halt:
	pushl   $halt_message	/ halt
	call    printf		/ defined in kernel
loop1:
	hlt
	jmp	loop1
 
halt_message:
	.string "Halted."

/ turn on paging
	ENTRY(start_paging)
	movl	bpd_loc, %eax
	movl	%eax, %cr3

	movl	%cr0, %eax
	orl	$[CR0_PG|CR0_PE], %eax
	movl	%eax, %cr0

	jmp	page_flush	/ flush the prefetch queue
page_flush:
	nop
	nop
	ret
	SET_SIZE(start_paging)

/ exitto 32-bit kernel
	ENTRY(exitto)
	push	%ebp		/ save stack
	mov	%esp, %ebp
	pushal			/ protect secondary boot

	movl	%esp, %eax
	movl	%eax, save_esp2

	movl	$elfbootvec, %eax
	pushl	(%eax)

	movl	$bop, %eax
	movl	(%eax), %ebx
	pushl	%ebx

	pushl	$0		/ no debug vector

	movl	$sysp, %eax
	movl	(%eax), %ecx
	pushl	%ecx

	movl	8(%ebp), %eax
	call	*%eax		/ jump to the kernel

	movl	save_esp2, %eax
	movl	%eax, %esp

	popal
	pop	%ebp		/ restore frame pointer
	ret
	SET_SIZE(exitto)

/********************************************************************** */
/**/
/*      munge_table: */
/*	      This procedure will 'munge' a descriptor table to */
/*	      change it from initialized format to runtime format. */
/**/
/*	      Assumes: */
/*		      %eax -- contains the base address of table. */
/*		      %ecx -- contains size of table. */
/**/
/* ********************************************************************* */
	ENTRY(munge_table)

	addl    %eax, %ecx      /* compute end of IDT array */
	movl    %eax, %esi      /* beginning of IDT */

moretable:
	cmpl    %esi, %ecx
	jl      donetable       /* Have we done every descriptor?? */

	movl    %esi, %ebx      /*long-vector/*short-selector/*char-rsrvd/*char-
type */

	movb    7(%ebx), %al    /* Find the byte containing the type field */
	testb   $0x10, %al      /* See if this descriptor is a segment */
	jne     notagate
	testb   $0x04, %al      /* See if this destriptor is a gate */
	je      notagate
				/* Rearrange a gate descriptor. */
	movl    4(%ebx), %edx   /* Selector, type lifted out. */
	movw    2(%ebx), %ax    /* Grab Offset 16..31 */
	movl    %edx, 2(%ebx)   /* Put back Selector, type */
	movw    %ax, 6(%ebx)    /* Offset 16..31 now in right place */
	jmp     descdone

notagate:		       /* Rearrange a non gate descriptor. */
	movw    4(%ebx), %dx    /* Limit 0..15 lifted out */
	movw    6(%ebx), %ax    /* acc1, acc2 lifted out */
	movb    %ah, 5(%ebx)    /* acc2 put back */
	movw    2(%ebx), %ax    /* 16-23, 24-31 picked up */
	movb    %al, 7(%ebx)    /* 24-31 put back */
	movb    %ah, 4(%ebx)    /* 16-23 put back */
	movw    (%ebx), %ax     /* base 0-15 picked up */
	movw    %ax, 2(%ebx)    /* base 0-15 put back */
	movw    %dx, (%ebx)     /* lim 0-15 put back */

descdone:
	addl    $8, %esi	/* Go for the next descriptor */
	jmp     moretable

donetable:
	ret
	SET_SIZE(munge_table)

/ reset machine
/ Resetting by Triple-Fault only makes emulators like VMWare warn
/ the user each time a reset is performed.  Here, we try a number
/ of techniques and only fall back on triple faulting the CPU
/ under extreme circumstances.

	ENTRY(reset)
	/
	/ Try the classic keyboard controller-triggered reset.
	/
	movw	$0x64, %dx
	movb	$0xfe, %al
	outb	(%dx)

	/ Wait up to 500 ms for the keyboard controller to pull the reset line
	pushl	$500
	call	mdelay
	addl	$4, %esp

	/
	/ Try port 0x92 fast reset
	/
	movw	$0x92, %dx
	inb	(%dx)
	cmpb	$0xff, %al	/ If port's not there, we should get back 0xFF
	je	1f
	testb	$1, %al		/ If bit 0
	jz	2f		/ is clear, jump to perform the reset
	andb	$0xfe, %al	/ otherwise,
	outb	(%dx)		/ clear bit 0 first, then
2:
	orb	$1, %al		/ Set bit 0
	outb	(%dx)		/ and reset the system
1:

	/ Wait up to 500 ms for the port 92 reset method to reset the CPU
	pushl	$500
	call	mdelay
	addl	$4, %esp

	/ Try the PCI (soft) reset vector (should work on all modern systems,
	/ but has been shown to cause problems on 450NX systems, and some newer
	/ systems (e.g. ATI IXP400-equipped systems))
	/ When resetting via this method, 2 writes are required.  The first
	/ targets bit 1 (0=hard reset without power cycle, 1=hard reset with
	/ power cycle).
	/ The reset occurs on the second write, during bit 2's transition from
	/ 0->1.
	movw	$0xcf9, %dx
	movb	$0x2, %al	/ Reset mode = hard, no power cycle
	outb	(%dx)
	movb	$0x6, %al
	outb	(%dx)

	/ Wait up to 500 ms for the port cf9 reset method to reset the CPU
	pushl	$500
	call	mdelay
	addl	$4, %esp

	/
	/ port 0xcf9 failed also.  Last-ditch effort is to
	/ triple-fault the CPU.
	/
	movw	$0, IDTlimit	/ generate faulty table
	lidt	IDTptr		/ load faulty table
	int	$10		/ trigger an interrupt

	cli
 	hlt			/ Wait forever
 	/*NOTREACHED*/
	SET_SIZE(reset)

	ENTRY(_cmntrap)
	/
	/ Stack looks like the following on entry:
	/
	/ EFLAGS		%esp + SIZEOF_i386_machregs + 16
	/ CS			%esp + SIZEOF_i386_machregs + 12
	/ EIP			%esp + SIZEOF_i386_machregs + 8
	/ ERRCODE		%esp + SIZEOF_i386_machregs + 4
	/ TRAPNO		%esp + SIZEOF_i386_machregs
	/ STRUCT MACHREGS	%esp + 0
	/
	subl	$SIZEOF_i386_machregs, %esp

	movl	%eax, i386_REG_EAX(%esp)
	movl	%ebx, i386_REG_EBX(%esp)
	movl	%ecx, i386_REG_ECX(%esp)
	movl	%edx, i386_REG_EDX(%esp)
	movl	%edi, i386_REG_EDI(%esp)
	movl	%esi, i386_REG_ESI(%esp)
	movl	%ebp, i386_REG_EBP(%esp)

	/ Copy in the saved EFLAGS
	leal	SIZEOF_i386_machregs(%esp), %eax
	addl	$16, %eax
	movl	(%eax), %eax
	movl	%eax, i386_REG_EFL(%esp)

	/ Copy in the saved CS
	leal	SIZEOF_i386_machregs(%esp), %eax
	addl	$12, %eax
	movl	(%eax), %eax
	movl	%eax, i386_REG_CS(%esp)

	/ Copy in the saved EIP
	leal	SIZEOF_i386_machregs(%esp), %eax
	addl	$8, %eax
	movl	(%eax), %eax
	movl	%eax, i386_REG_EIP(%esp)

	/ Copy in the saved ERRCODE
	leal	SIZEOF_i386_machregs(%esp), %eax
	addl	$4, %eax
	movl	(%eax), %eax
	movl	%eax, i386_REG_ERR(%esp)

	/ Copy in the saved TRAPNO
	leal	SIZEOF_i386_machregs(%esp), %eax
	movl	(%eax), %eax
	movl	%eax, i386_REG_TRAPNO(%esp)

	movl	%esp, i386_REG_ESP(%esp)
	movl	%esp, i386_REG_UESP(%esp)

	/
	/ The original %esp is +SIZEOF_i386_machregs
	/
	addl	$SIZEOF_i386_machregs, i386_REG_ESP(%esp)
	addl	$SIZEOF_i386_machregs, i386_REG_UESP(%esp)

	/ Save the segment registers
	xorl	%eax, %eax

	movw	%ss, %ax
	movw	$0, _CONST(i386_REG_SS + 2)(%esp)
	movl	%eax, i386_REG_SS(%esp)
	movw	%ds, %ax
	movw	$0, _CONST(i386_REG_DS + 2)(%esp)
	movl	%eax, i386_REG_DS(%esp)
	movw	%es, %ax
	movw	$0, _CONST(i386_REG_ES + 2)(%esp)
	movl	%eax, i386_REG_ES(%esp)
	movw	%fs, %ax
	movw	$0, _CONST(i386_REG_FS + 2)(%esp)
	movl	%eax, i386_REG_FS(%esp)
	movw	%gs, %ax
	movw	$0, _CONST(i386_REG_GS + 2)(%esp)
	movl	%eax, i386_REG_GS(%esp)

	/ Save the control registers
	movl	%cr0, %eax
	movl	%eax, i386_REG_CR0(%esp)
	movl	%cr2, %eax
	movl	%eax, i386_REG_CR2(%esp)
	movl	%cr3, %eax
	movl	%eax, i386_REG_CR3(%esp)
	movl	%cr4, %eax
	movl	%eax, i386_REG_CR4(%esp)

	/ Save the task, interrupt, gdt, ldt registers
	movw	$0, _CONST(i386_REG_TR + 2)(%esp)
	str	i386_REG_TR(%esp)
	sidt	i386_REG_IDT(%esp)
	sgdt	i386_REG_GDT(%esp)
	movw	$0, _CONST(i386_REG_LDT + 2)(%esp)
	sldt	i386_REG_LDT(%esp)

	pushl	%esp
	call	trap
	addl	$4, %esp

	addl	$SIZEOF_i386_machregs, %esp
	iret
	SET_SIZE(_cmntrap)

/ Data definitions
.align	4
.globl	bpd_loc
bpd_loc:
	.long	0
.globl	save_esp2
save_esp2:
	.long	0
.globl	save_esp
save_esp:
	.long	0
.globl	bop
bop:
	.long	0
IDTptr:
IDTlimit:
	.value	0x7ff
IDTbase:
	.long	slbidt

.align	4
gdt_start:
	.long	0
	.long	0

flatdesc:			/ offset = 0x08 (GDT_BOOTFLAT << 3)

	.value  0xFFFF		/ segment limit 0..15
	.value  0x0000		/ segment base 0..15
	.byte   0x0		/ segment base 16..23; set for 0K
	.byte   0x92		/ flags; A=0, Type=001, DPL=00, P=1
				/	Present expand down
	.byte   0xCF		/ flags; Limit (16..19)=1111, AVL=0, G=1, B=1
	.byte   0x0		/ segment base 24..32

codedesc:			/ offset = 0x10 (GDT_CODESEL << 3)

	.value	0xFFFF		/ segment limit 0..15
	.value  0x0000		/ segment base 0..15
	.byte   0x0		/ segment base 16..23; set for 0k
	.byte   0x9E		/ flags; A=0, Type=111, DPL=00, P=1
	.byte   0xCF		/ flags; Limit (16..19)=1111, AVL=0, G=1, D=1
	.byte   0x0		/ segment base 24..32

code16desc:			/ offset = 0x18

	.value  0xFFFF		/ segment limit 0..15
	.value  0x0000		/ segment base 0..15
	.byte   0x0		/ segment base 16..23; set for 0k
	.byte   0x9E		/ flags; A=0, Type=111, DPL=00, P=1
	.byte	0x0F		/ flags; Limit (16..19)=1111, AVL=0, G=0, D=0
	.byte	0x0		/ segment base 24..32

datadesc:			/ offset = 0x20

	.value  0xFFFF		/ segment limit 0..15
	.value  0x0000		/ segment base 0..15
	.byte   0x0		/ segment base 16..23; set for 0K
	.byte   0x92		/ flags; A=0, Type=001, DPL=00, P=1
				/	Present expand down
	.byte   0x4F		/ flags; Limit (16..19)=1111, AVL=0, G=1, B=1
	.byte   0x0		/ segment base 24..32

dummy_entries:
	.long	0		/ 0x28
	.long	0
	.long	0		/ 0x30
	.long	0

gsdesc:				/ 0x38 - for kmdb
	.value	0
	.value	0
	.byte	0
	.byte	0x92		/ flags; A=0, Type=001, DPL=00, P=1
	.byte	0xC0		/ flags; Limit (16..19)=0000, AVL=0, G=1, B=1
	.byte	0

gdt_end:

gdtdesc:
	.value	gdt_end - gdt_start
	.long	gdt_start

.comm stack, STACK_SIZE		/ stack area

#endif
