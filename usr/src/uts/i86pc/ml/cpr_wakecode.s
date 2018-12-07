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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/x86_archext.h>
#include <sys/cpr_wakecode.h>

#if !defined(__lint)
#include <sys/segments.h>
#include "assym.h"
#endif

#ifdef  DEBUG
#define LED     1
#define SERIAL  1
#endif	/*	DEBUG	*/

#ifdef	DEBUG
#define	COM1	0x3f8
#define	COM2	0x2f8
#define	WC_COM	COM2	/* either COM1 or COM2			*/
#define	WC_LED	0x80    /* diagnostic led port ON motherboard	*/

/*
 * defined as offsets from the data register
 */
#define	DLL	0	/* divisor latch (lsb) */
#define	DLH	1	/* divisor latch (msb) */
#define	LCR	3	/* line control register		*/
#define	MCR	4	/* modem control register		*/


#define	DLAB	0x80    /* divisor latch access bit		*/
#define	B9600L	0X0c	/* lsb bit pattern for 9600 baud	*/
#define	B9600H	0X0	/* hsb bit pattern for 9600 baud	*/
#define	DTR	0x01    /* Data Terminal Ready			*/
#define	RTS	0x02    /* Request To Send			*/
#define	STOP1	0x00	/* 1 stop bit				*/
#define	BITS8	0x03    /* 8 bits per char			*/

#endif	/*	DEBUG	*/

/*
 *	This file contains the low level routines involved in getting
 *	into and out of ACPI S3, including those needed for restarting
 *	the non-boot cpus.
 *
 *	Our assumptions:
 *
 *	Our actions:
 *
 */

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
int
wc_save_context(wc_cpu_t *pcpu)
{ return 0; }

#else	/* lint */

#if defined(__amd64)

	ENTRY_NP(wc_save_context)

	movq	(%rsp), %rdx		/ return address
	movq	%rdx, WC_RETADDR(%rdi)
	pushq	%rbp
	movq	%rsp,%rbp

	movq    %rdi, WC_VIRTADDR(%rdi)
	movq    %rdi, WC_RDI(%rdi)

	movq    %rdx, WC_RDX(%rdi)

/ stash everything else we need
	sgdt	WC_GDT(%rdi)
	sidt	WC_IDT(%rdi)
	sldt	WC_LDT(%rdi)
	str	WC_TR(%rdi)

	movq	%cr0, %rdx
	movq	%rdx, WC_CR0(%rdi)
	movq	%cr3, %rdx
	movq	%rdx, WC_CR3(%rdi)
	movq	%cr4, %rdx
	movq	%rdx, WC_CR4(%rdi)
	movq	%cr8, %rdx
	movq	%rdx, WC_CR8(%rdi)

	movq    %r8, WC_R8(%rdi)
	movq    %r9, WC_R9(%rdi)
	movq    %r10, WC_R10(%rdi)
	movq    %r11, WC_R11(%rdi)
	movq    %r12, WC_R12(%rdi)
	movq    %r13, WC_R13(%rdi)
	movq    %r14, WC_R14(%rdi)
	movq    %r15, WC_R15(%rdi)
	movq    %rax, WC_RAX(%rdi)
	movq    %rbp, WC_RBP(%rdi)
	movq    %rbx, WC_RBX(%rdi)
	movq    %rcx, WC_RCX(%rdi)
	movq    %rsi, WC_RSI(%rdi)
	movq    %rsp, WC_RSP(%rdi)

	movw	%ss, WC_SS(%rdi)
	movw	%cs, WC_CS(%rdi)
	movw	%ds, WC_DS(%rdi)
	movw	%es, WC_ES(%rdi)

	movq	$0, %rcx		/ save %fs register
	movw    %fs, %cx
	movq    %rcx, WC_FS(%rdi)

	movl    $MSR_AMD_FSBASE, %ecx
	rdmsr
	movl    %eax, WC_FSBASE(%rdi)
	movl    %edx, WC_FSBASE+4(%rdi)

	movq	$0, %rcx		/ save %gs register
	movw    %gs, %cx
	movq    %rcx, WC_GS(%rdi)

	movl    $MSR_AMD_GSBASE, %ecx	/ save gsbase msr
	rdmsr
	movl    %eax, WC_GSBASE(%rdi)
	movl    %edx, WC_GSBASE+4(%rdi)

	movl    $MSR_AMD_KGSBASE, %ecx	/ save kgsbase msr
	rdmsr
	movl    %eax, WC_KGSBASE(%rdi)
	movl    %edx, WC_KGSBASE+4(%rdi)

	movq	%gs:CPU_ID, %rax	/ save current cpu id
	movq	%rax, WC_CPU_ID(%rdi)

	pushfq
	popq	WC_EFLAGS(%rdi)

	wbinvd				/ flush the cache
	mfence

	movq	$1, %rax		/ at suspend return 1

	leave

	ret

	SET_SIZE(wc_save_context)

#elif defined(__i386)

	ENTRY_NP(wc_save_context)

	movl	4(%esp), %eax		/ wc_cpu_t *
	movl	%eax, WC_VIRTADDR(%eax)

	movl	(%esp), %edx		/ return address
	movl	%edx, WC_RETADDR(%eax)

	str	WC_TR(%eax)		/ stash everything else we need
	sgdt	WC_GDT(%eax)
	sldt	WC_LDT(%eax)
	sidt	WC_IDT(%eax)

	movl	%cr0, %edx
	movl	%edx, WC_CR0(%eax)
	movl	%cr3, %edx
	movl	%edx, WC_CR3(%eax)
	movl	%cr4, %edx
	movl	%edx, WC_CR4(%eax)

	movl	%ebx, WC_EBX(%eax)
	movl	%edi, WC_EDI(%eax)
	movl	%esi, WC_ESI(%eax)
	movl	%ebp, WC_EBP(%eax)
	movl	%esp, WC_ESP(%eax)

	movw	%ss, WC_SS(%eax)
	movw	%cs, WC_CS(%eax)
	movw	%ds, WC_DS(%eax)
	movw	%es, WC_ES(%eax)
	movw	%fs, WC_FS(%eax)
	movw	%gs, WC_GS(%eax)

	pushfl
	popl	WC_EFLAGS(%eax)

	pushl	%gs:CPU_ID		/ save current cpu id
	popl	WC_CPU_ID(%eax)

	wbinvd				/ flush the cache
	mfence

	movl	$1, %eax		/ at suspend return 1
	ret

	SET_SIZE(wc_save_context)

#endif	/* __amd64 */

#endif /* lint */


/*
 *	Our assumptions:
 *		- We are running in real mode.
 *		- Interrupts are disabled.
 *
 *	Our actions:
 *		- We start using our GDT by loading correct values in the
 *		  selector registers (cs=KCS_SEL, ds=es=ss=KDS_SEL, fs=KFS_SEL,
 *		  gs=KGS_SEL).
 *		- We change over to using our IDT.
 *		- We load the default LDT into the hardware LDT register.
 *		- We load the default TSS into the hardware task register.
 *		- We restore registers
 *		- We return to original caller (a la setjmp)
 */

#if defined(lint) || defined(__lint)

void
wc_rm_start(void)
{}

void
wc_rm_end(void)
{}

#else	/* lint */

#if defined(__amd64)

	ENTRY_NP(wc_rm_start)

	/*
	 * For the Sun Studio 10 assembler we needed to do a .code32 and
	 * mentally invert the meaning of the addr16 and data16 prefixes to
	 * get 32-bit access when generating code to be executed in 16-bit
	 * mode (sigh...)
	 *
	 * This code, despite always being built with GNU as, has inherited
	 * the conceptual damage.
	 */

	.code32

	cli
	movw		%cs, %ax
	movw		%ax, %ds		/ establish ds ...
	movw		%ax, %ss		/ ... and ss:esp
	D16 movl	$WC_STKSTART, %esp
/ using the following value blows up machines! - DO NOT USE
/	D16 movl	0xffc, %esp


#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd1, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x61, %al
	outb    (%dx)
#endif

	D16 call	cominit

	/*
	 * Enable protected-mode, write protect, and alignment mask
	 * %cr0 has already been initialsed to zero
	 */
	movl		%cr0, %eax
	D16 orl		$_CONST(CR0_PE|CR0_WP|CR0_AM), %eax
	movl		%eax, %cr0

	/*
	 * Do a jmp immediately after writing to cr0 when enabling protected
	 * mode to clear the real mode prefetch queue (per Intel's docs)
	 */
	jmp		pestart
pestart:

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd2, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x62, %al
	outb    (%dx)
#endif

	/*
	 * 16-bit protected mode is now active, so prepare to turn on long
	 * mode
	 */

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd3, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x63, %al
	outb    (%dx)
#endif

	/*
	 * Add any initial cr4 bits
	 */
	movl		%cr4, %eax
	A16 D16 orl	CR4OFF, %eax

	/*
	 * Enable PAE mode (CR4.PAE)
	 */
	D16 orl		$CR4_PAE, %eax
	movl		%eax, %cr4

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd4, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x64, %al
	outb    (%dx)
#endif

	/*
	 * Point cr3 to the 64-bit long mode page tables.
	 *
	 * Note that these MUST exist in 32-bit space, as we don't have
	 * a way to load %cr3 with a 64-bit base address for the page tables
	 * until the CPU is actually executing in 64-bit long mode.
	 */
	A16 D16 movl	CR3OFF, %eax
	movl		%eax, %cr3

	/*
	 * Set long mode enable in EFER (EFER.LME = 1)
	 */
	D16 movl	$MSR_AMD_EFER, %ecx
	rdmsr

	D16 orl		$AMD_EFER_LME, %eax
	wrmsr

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd5, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x65, %al
	outb    (%dx)
#endif

	/*
	 * Finally, turn on paging (CR0.PG = 1) to activate long mode.
	 */
	movl		%cr0, %eax
	D16 orl		$CR0_PG, %eax
	movl		%eax, %cr0

	/*
	 * The instruction after enabling paging in CR0 MUST be a branch.
	 */
	jmp		long_mode_active

long_mode_active:

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd6, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x66, %al
	outb    (%dx)
#endif

	/*
	 * Long mode is now active but since we're still running with the
	 * original 16-bit CS we're actually in 16-bit compatability mode.
	 *
	 * We have to load an intermediate GDT and IDT here that we know are
	 * in 32-bit space before we can use the kernel's GDT and IDT, which
	 * may be in the 64-bit address space, and since we're in compatability
	 * mode, we only have access to 16 and 32-bit instructions at the
	 * moment.
	 */
	A16 D16 lgdt	TEMPGDTOFF	/* load temporary GDT */
	A16 D16 lidt	TEMPIDTOFF	/* load temporary IDT */


	/*
	 * Do a far transfer to 64-bit mode.  Set the CS selector to a 64-bit
	 * long mode selector (CS.L=1) in the temporary 32-bit GDT and jump
	 * to the real mode platter address of wc_long_mode_64 as until the
	 * 64-bit CS is in place we don't have access to 64-bit instructions
	 * and thus can't reference a 64-bit %rip.
	 */

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd7, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x67, %al
	outb    (%dx)
#endif

	D16	pushl	$TEMP_CS64_SEL
	A16 D16 pushl	LM64OFF

	D16 lret


/*
 * Support routine to re-initialize VGA subsystem
 */
vgainit:
	D16 ret

/*
 * Support routine to re-initialize keyboard (which is USB - help!)
 */
kbdinit:
	D16 ret

/*
 * Support routine to re-initialize COM ports to something sane
 */
cominit:
	/ init COM1 & COM2

#if     DEBUG
/*
 * on debug kernels we need to initialize COM1 & COM2 here, so that
 * we can get debug output before the asy driver has resumed
 */

/ select COM1
	D16 movl	$_CONST(COM1+LCR), %edx
	D16 movb	$DLAB, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM1+DLL), %edx	/ divisor latch lsb
	D16 movb	$B9600L, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM1+DLH), %edx	/ divisor latch hsb
	D16 movb	$B9600H, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM1+LCR), %edx	/ select COM1
	D16 movb	$_CONST(STOP1|BITS8), %al	/ 1 stop bit, 8bit word len
	outb	(%dx)

	D16 movl	$_CONST(COM1+MCR), %edx	/ select COM1
	D16 movb	$_CONST(RTS|DTR), %al		/ data term ready & req to send
	outb	(%dx)

/ select COM2
	D16 movl	$_CONST(COM2+LCR), %edx
	D16 movb	$DLAB, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM2+DLL), %edx	/ divisor latch lsb
	D16 movb	$B9600L, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM2+DLH), %edx	/ divisor latch hsb
	D16 movb	$B9600H, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM2+LCR), %edx	/ select COM1
	D16 movb	$_CONST(STOP1|BITS8), %al	/ 1 stop bit, 8bit word len
	outb	(%dx)

	D16 movl	$_CONST(COM2+MCR), %edx	/ select COM1
	D16 movb	$_CONST(RTS|DTR), %al		/ data term ready & req to send
	outb	(%dx)
#endif	/*	DEBUG	*/

	D16 ret

	.code64

	.globl wc_long_mode_64
wc_long_mode_64:

#if     LED
	movw        $WC_LED, %dx
	movb        $0xd8, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movb        $0x68, %al
	outb    (%dx)
#endif

	/*
	 * We are now running in long mode with a 64-bit CS (EFER.LMA=1,
	 * CS.L=1) so we now have access to 64-bit instructions.
	 *
	 * First, set the 64-bit GDT base.
	 */
	.globl	rm_platter_pa
	movl	rm_platter_pa, %eax

	lgdtq	GDTROFF(%rax)		/* load 64-bit GDT */

	/*
	 * Save the CPU number in %r11; get the value here since it's saved in
	 * the real mode platter.
	 */
/ JAN
/ the following is wrong! need to figure out MP systems
/	movl	CPUNOFF(%rax), %r11d

	/*
	 * Add rm_platter_pa to %rsp to point it to the same location as seen
	 * from 64-bit mode.
	 */
	addq	%rax, %rsp

	/*
	 * Now do an lretq to load CS with the appropriate selector for the
	 * kernel's 64-bit GDT and to start executing 64-bit setup code at the
	 * virtual address where boot originally loaded this code rather than
	 * the copy in the real mode platter's rm_code array as we've been
	 * doing so far.
	 */

#if     LED
	movw        $WC_LED, %dx
	movb        $0xd9, %al
	outb    (%dx)
#endif

/ JAN this should produce 'i' but we get 'g' instead ???
#if     SERIAL
	movw        $WC_COM, %dx
	movb        $0x69, %al
	outb    (%dx)
#endif

	pushq	$KCS_SEL
	pushq	$kernel_wc_code
	lretq

	.globl kernel_wc_code
kernel_wc_code:

#if     LED
	movw        $WC_LED, %dx
	movb        $0xda, %al
	outb    (%dx)
#endif

/ JAN this should produce 'j' but we get 'g' instead ???
#if     SERIAL
	movw        $WC_COM, %dx
	movb        $0x6a, %al
	outb    (%dx)
#endif

	/*
	 * Complete the balance of the setup we need to before executing
	 * 64-bit kernel code (namely init rsp, TSS, LGDT, FS and GS).
	 */
	.globl  rm_platter_va
	movq    rm_platter_va, %rbx
	addq	$WC_CPU, %rbx

#if     LED
	movw        $WC_LED, %dx
	movb        $0xdb, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movw        $0x6b, %ax
	outb    (%dx)
#endif

	/*
	 * restore the rest of the registers
	 */

	lidtq	WC_IDT(%rbx)

#if     LED
	movw        $WC_LED, %dx
	movb        $0xdc, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movw        $0x6c, %ax
	outb    (%dx)
#endif

	/*
	 * restore the rest of the registers
	 */

	movw    $KDS_SEL, %ax
	movw    %ax, %ds
	movw    %ax, %es
	movw    %ax, %ss

	/*
	 * Before proceeding, enable usage of the page table NX bit if
	 * that's how the page tables are set up.
	 */
	bt      $X86FSET_NX, x86_featureset(%rip)
	jnc     1f
	movl    $MSR_AMD_EFER, %ecx
	rdmsr
	orl     $AMD_EFER_NXE, %eax
	wrmsr
1:

	movq	WC_CR4(%rbx), %rax	/ restore full cr4 (with Global Enable)
	movq	%rax, %cr4

	lldt	WC_LDT(%rbx)
	movzwq	WC_TR(%rbx), %rax	/ clear TSS busy bit
	addq	WC_GDT+2(%rbx), %rax
	andl	$0xfffffdff, 4(%rax)
	movq	4(%rax), %rcx
	ltr	WC_TR(%rbx)

#if     LED
	movw        $WC_LED, %dx
	movb        $0xdd, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movw        $0x6d, %ax
	outb    (%dx)
#endif

/ restore %fsbase %gsbase %kgbase registers using wrmsr instruction

	movq    WC_FS(%rbx), %rcx	/ restore fs register
	movw    %cx, %fs

	movl    $MSR_AMD_FSBASE, %ecx
	movl    WC_FSBASE(%rbx), %eax
	movl    WC_FSBASE+4(%rbx), %edx
	wrmsr

	movq    WC_GS(%rbx), %rcx	/ restore gs register
	movw    %cx, %gs

	movl    $MSR_AMD_GSBASE, %ecx	/ restore gsbase msr
	movl    WC_GSBASE(%rbx), %eax
	movl    WC_GSBASE+4(%rbx), %edx
	wrmsr

	movl    $MSR_AMD_KGSBASE, %ecx	/ restore kgsbase msr
	movl    WC_KGSBASE(%rbx), %eax
	movl    WC_KGSBASE+4(%rbx), %edx
	wrmsr

	movq	WC_CR0(%rbx), %rdx
	movq	%rdx, %cr0
	movq	WC_CR3(%rbx), %rdx
	movq	%rdx, %cr3
	movq	WC_CR8(%rbx), %rdx
	movq	%rdx, %cr8

#if     LED
	movw        $WC_LED, %dx
	movb        $0xde, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movb        $0x6e, %al
	outb    (%dx)
#endif

	/*
	 * if we are not running on the boot CPU restore stack contents by
	 * calling i_cpr_restore_stack(curthread, save_stack);
	 */
	movq    %rsp, %rbp
	call	i_cpr_bootcpuid
	cmpl	%eax, WC_CPU_ID(%rbx)
	je	2f

	movq	%gs:CPU_THREAD, %rdi
	movq	WC_SAVED_STACK(%rbx), %rsi
	call	i_cpr_restore_stack
2:

	movq    WC_RSP(%rbx), %rsp	/ restore stack pointer

	/*
	 * APIC initialization
	 */
	movq    %rsp, %rbp

	/*
	 * skip iff function pointer is NULL
	 */
	cmpq	$0, ap_mlsetup
	je	3f
	leaq	ap_mlsetup, %rax
	INDIRECT_CALL_REG(rax)
3:

	leaq	cpr_start_cpu_func, %rax
	INDIRECT_CALL_REG(rax)

/ restore %rbx to the value it ahd before we called the functions above
	movq    rm_platter_va, %rbx
	addq	$WC_CPU, %rbx

	movq    WC_R8(%rbx), %r8
	movq    WC_R9(%rbx), %r9
	movq    WC_R10(%rbx), %r10
	movq    WC_R11(%rbx), %r11
	movq    WC_R12(%rbx), %r12
	movq    WC_R13(%rbx), %r13
	movq    WC_R14(%rbx), %r14
	movq    WC_R15(%rbx), %r15
/	movq    WC_RAX(%rbx), %rax
	movq    WC_RBP(%rbx), %rbp
	movq    WC_RCX(%rbx), %rcx
/	movq    WC_RDX(%rbx), %rdx
	movq    WC_RDI(%rbx), %rdi
	movq    WC_RSI(%rbx), %rsi


/ assume that %cs does not need to be restored
/ %ds, %es & %ss are ignored in 64bit mode
	movw	WC_SS(%rbx), %ss
	movw	WC_DS(%rbx), %ds
	movw	WC_ES(%rbx), %es

#if     LED
	movw        $WC_LED, %dx
	movb        $0xdf, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movb        $0x6f, %al
	outb    (%dx)
#endif


	movq    WC_RBP(%rbx), %rbp
	movq    WC_RSP(%rbx), %rsp

#if     LED
	movw        $WC_LED, %dx
	movb        $0xe0, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movb        $0x70, %al
	outb    (%dx)
#endif


	movq    WC_RCX(%rbx), %rcx

	pushq	WC_EFLAGS(%rbx)			/ restore flags
	popfq

#if     LED
	movw        $WC_LED, %dx
	movb        $0xe1, %al
	outb    (%dx)
#endif

#if     SERIAL
	movw        $WC_COM, %dx
	movb        $0x71, %al
	outb    (%dx)
#endif

/*
 * can not use outb after this point, because doing so would mean using
 * %dx which would modify %rdx which is restored here
 */

	movq	%rbx, %rax
	movq    WC_RDX(%rax), %rdx
	movq    WC_RBX(%rax), %rbx

	leave

	movq	WC_RETADDR(%rax), %rax
	movq	%rax, (%rsp)		/ return to caller of wc_save_context

	xorl	%eax, %eax			/ at wakeup return 0
	ret


	SET_SIZE(wc_rm_start)

	ENTRY_NP(asmspin)

	movl	%edi, %ecx
A1:
	loop	A1

	SET_SIZE(asmspin)

	.globl wc_rm_end
wc_rm_end:
	nop

#elif defined(__i386)

	ENTRY_NP(wc_rm_start)

/entry:	jmp		entry			/ stop here for HDT

	cli
	movw		%cs, %ax
	movw		%ax, %ds		/ establish ds ...
	movw		%ax, %ss		/ ... and ss:esp
	D16 movl	$WC_STKSTART, %esp

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd1, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x61, %al
	outb    (%dx)
#endif


	D16 call	vgainit
	D16 call	kbdinit
	D16 call	cominit

#if     LED
	D16 movl        $WC_LED, %edx
	D16 movb        $0xd2, %al
	outb    (%dx)
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x62, %al
	outb    (%dx)
#endif

	D16 A16 movl	$WC_CPU, %ebx		/ base add of wc_cpu_t

#if     LED
	D16 movb        $0xd3, %al
	outb    $WC_LED
#endif

#if     SERIAL
	D16 movl        $WC_COM, %edx
	D16 movb        $0x63, %al
	outb    (%dx)
#endif

	D16 A16 movl	%cs:WC_DS(%ebx), %edx	/ %ds post prot/paging transit

#if     LED
	D16 movb        $0xd4, %al
	outb    $WC_LED
#endif

	D16 A16 lgdt	%cs:WC_GDT(%ebx)	/ restore gdt and idtr
	D16 A16 lidt	%cs:WC_IDT(%ebx)

#if     LED
	D16 movb        $0xd5, %al
	outb    $WC_LED
#endif

	D16 A16 movl	%cs:WC_CR4(%ebx), %eax	/ restore cr4
	D16 andl	$_BITNOT(CR4_PGE), %eax / don't set Global Enable yet
	movl		%eax, %cr4

#if     LED
	D16 movb        $0xd6, %al
	outb    $WC_LED
#endif

	D16 A16 movl	%cs:WC_CR3(%ebx), %eax	/ set PDPT
	movl		%eax, %cr3

#if     LED
	D16 movb        $0xd7, %al
	outb    $WC_LED
#endif

	D16 A16 movl	%cs:WC_CR0(%ebx), %eax	/ enable prot/paging, etc.
	movl		%eax, %cr0

#if     LED
	D16 movb        $0xd8, %al
	outb    $WC_LED
#endif

	D16 A16 movl	%cs:WC_VIRTADDR(%ebx), %ebx	/ virtaddr of wc_cpu_t

#if     LED
	D16 movb        $0xd9, %al
	outb    $WC_LED
#endif

#if     LED
	D16 movb        $0xda, %al
	outb    $WC_LED
#endif

	jmp		flush			/ flush prefetch queue
flush:
	D16 pushl	$KCS_SEL
	D16 pushl	$kernel_wc_code
	D16 lret				/ re-appear at kernel_wc_code


/*
 * Support routine to re-initialize VGA subsystem
 */
vgainit:
	D16 ret

/*
 * Support routine to re-initialize keyboard (which is USB - help!)
 */
kbdinit:
	D16 ret

/*
 * Support routine to re-initialize COM ports to something sane for debug output
 */
cominit:
#if     DEBUG
/*
 * on debug kernels we need to initialize COM1 & COM2 here, so that
 * we can get debug output before the asy driver has resumed
 */

/ select COM1
	D16 movl	$_CONST(COM1+LCR), %edx
	D16 movb	$DLAB, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM1+DLL), %edx	/ divisor latch lsb
	D16 movb	$B9600L, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM1+DLH), %edx	/ divisor latch hsb
	D16 movb	$B9600H, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM1+LCR), %edx	/ select COM1
	D16 movb	$_CONST(STOP1|BITS8), %al	/ 1 stop bit, 8bit word len
	outb	(%dx)

	D16 movl	$_CONST(COM1+MCR), %edx	/ select COM1
	D16 movb	$_CONST(RTS|DTR), %al		/ 1 stop bit, 8bit word len
	outb	(%dx)

/ select COM2
	D16 movl	$_CONST(COM2+LCR), %edx
	D16 movb	$DLAB, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM2+DLL), %edx	/ divisor latch lsb
	D16 movb	$B9600L, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM2+DLH), %edx	/ divisor latch hsb
	D16 movb	$B9600H, %al		/ divisor latch
	outb	(%dx)

	D16 movl	$_CONST(COM2+LCR), %edx	/ select COM1
	D16 movb	$_CONST(STOP1|BITS8), %al	/ 1 stop bit, 8bit word len
	outb	(%dx)

	D16 movl	$_CONST(COM2+MCR), %edx	/ select COM1
	D16 movb	$_CONST(RTS|DTR), %al		/ 1 stop bit, 8bit word len
	outb	(%dx)
#endif	/*	DEBUG	*/

	D16 ret

	.globl wc_rm_end
wc_rm_end:
	nop

	.globl	kernel_wc_code
kernel_wc_code:
	/ At this point we are with kernel's cs and proper eip.
	/ We will be executing not from the copy in real mode platter,
	/ but from the original code where boot loaded us.
	/ By this time GDT and IDT are loaded as is cr0, cr3 and cr4.
	/ %ebx is wc_cpu
	/ %dx is our ds

#if     LED
	D16 movb        $0xdb, %al
	outb	$WC_LED
#endif

/ got here OK

	movw	%dx, %ds		/ $KDS_SEL

#if     LED
	movb	$0xdc, %al
	outb	$WC_LED
#endif

	/*
	 * Before proceeding, enable usage of the page table NX bit if
	 * that's how the page tables are set up.
	 */
	bt      $X86FSET_NX, x86_featureset
	jnc     1f
	movl    $MSR_AMD_EFER, %ecx
	rdmsr
	orl     $AMD_EFER_NXE, %eax
	wrmsr
1:

	movl	WC_CR4(%ebx), %eax	/ restore full cr4 (with Global Enable)
	movl	%eax, %cr4


	lldt	WC_LDT(%ebx)		/ $LDT_SEL

	movzwl	WC_TR(%ebx), %eax	/ clear TSS busy bit
	addl	WC_GDT+2(%ebx), %eax
	andl	$_BITNOT(0x200), 4(%eax)
	ltr	WC_TR(%ebx)		/ $UTSS_SEL

	movw	WC_SS(%ebx), %ss	/ restore segment registers
	movw	WC_ES(%ebx), %es
	movw	WC_FS(%ebx), %fs
	movw	WC_GS(%ebx), %gs

	/*
	 * set the stack pointer to point into the identity mapped page
	 * temporarily, so we can make function calls
	 */
	.globl  rm_platter_va
	movl    rm_platter_va, %eax
	movl	$WC_STKSTART, %esp
	addl	%eax, %esp
	movl	%esp, %ebp

	/*
	 * if we are not running on the boot CPU restore stack contents by
	 * calling i_cpr_restore_stack(curthread, save_stack);
	 */
	call	i_cpr_bootcpuid
	cmpl	%eax, WC_CPU_ID(%ebx)
	je	2f

	pushl	WC_SAVED_STACK(%ebx)
	pushl	%gs:CPU_THREAD
	call	i_cpr_restore_stack
	addl	$0x10, %esp
2:

	movl	WC_ESP(%ebx), %esp
	movl	%esp, %ebp

	movl	WC_RETADDR(%ebx), %eax	/ return to caller of wc_save_context
	movl	%eax, (%esp)

	/*
	 * APIC initialization, skip iff function pointer is NULL
	 */
	cmpl	$0, ap_mlsetup
	je	3f
	call	*ap_mlsetup
3:

	call	*cpr_start_cpu_func

	pushl	WC_EFLAGS(%ebx)		/ restore flags
	popfl

	movl	WC_EDI(%ebx), %edi	/ restore general registers
	movl	WC_ESI(%ebx), %esi
	movl	WC_EBP(%ebx), %ebp
	movl	WC_EBX(%ebx), %ebx

/exit:	jmp	exit			/ stop here for HDT

	xorl	%eax, %eax		/ at wakeup return 0
	ret

	SET_SIZE(wc_rm_start)


#endif	/* defined(__amd64) */

#endif /* lint */

