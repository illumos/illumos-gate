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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*	  All Rights Reserved					*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/reboot.h>
#include <sys/x86_archext.h>

#if defined(__lint)

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/lgrp.h>
#include <sys/regset.h>
#include <sys/link.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>

#else	/* __lint */

#include <sys/segments.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/cmn_err.h>
#include <sys/pit.h>
#include <sys/panic.h>
#include "assym.h"

/*
 * Our assumptions:
 *	- We are running in protected-paged mode.
 *	- Interrupts are disabled.
 *	- The GDT and IDT are the callers; we need our copies.
 *	- The kernel's text, initialized data and bss are mapped.
 *
 * Our actions:
 *	- Save arguments
 *	- Initialize our stack pointer to the thread 0 stack (t0stack)
 *	  and leave room for a phony "struct regs".
 *	- Our GDT and IDT need to get munged.
 *	- Since we are using the boot's GDT descriptors, we need
 *	  to copy them into our GDT before we switch to ours.
 *	- We start using our GDT by loading correct values in the
 *	  selector registers (cs=KCS_SEL, ds=es=ss=KDS_SEL, fs=KFS_SEL,
 *	  gs=KGS_SEL).
 *	- The default LDT entry for syscall is set.
 *	- We load the default LDT into the hardware LDT register.
 *	- We load the default TSS into the hardware task register.
 *	- Check for cpu type, i.e. 486 vs. P5 vs. P6 etc.
 *	- mlsetup(%esp) gets called.
 *	- We change our appearance to look like the real thread 0.
 *	  (NOTE: making ourselves to be a real thread may be a noop)
 *	- main() gets called.  (NOTE: main() never returns).
 *
 * NOW, the real code!
 */

	/*
	 * Globals:
	 */
	.globl _start
	.globl	mlsetup
	.globl	main
	.globl	panic
	.globl	t0stack
	.globl	t0
	.globl	sysp
	.globl	edata

	/*
	 * call back into boot - sysp (bootsvcs.h) and bootops (bootconf.h)
	 */
	.globl	bootops
	.globl	bootopsp

	/*
	 * NOTE: t0stack should be the first thing in the data section so that
	 * if it ever overflows, it will fault on the last kernel text page.
	 */
	.data
	.comm	t0stack, DEFAULTSTKSZ, 32
	.comm	t0, 4094, 32

#ifdef TRAPTRACE
	/*
	 * trap_trace_ctl must agree with the structure definition in
	 * <sys/traptrace.h>
	 */	
	DGDEF3(trap_trace_bufsize, CLONGSIZE, CLONGSIZE)
	.NWORD	TRAP_TSIZE

	DGDEF3(trap_trace_freeze, 4, 4)
	.long	0

	DGDEF3(trap_trace_off, 4, 4)
	.long	0

	DGDEF3(trap_trace_ctl, _MUL(4, CLONGSIZE), 16)
	.NWORD	trap_tr0		/* next record */
	.NWORD	trap_tr0		/* first record */
	.NWORD	trap_tr0 + TRAP_TSIZE	/* limit */
	.NWORD	0			/* pad */

#if NCPU != 21
#error "NCPU != 21, Expand padding for trap_trace_ctl"
#endif

	/*
	 * Enough padding for 20 CPUs (no .skip on x86 -- grrrr).
	 */
	.NWORD	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.NWORD	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.NWORD	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.NWORD	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.NWORD	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

	/*
	 * CPU 0's preallocated TRAPTRACE buffer.
	 */
	.globl	trap_tr0
	.comm	trap_tr0, TRAP_TSIZE

	/*
	 * A dummy TRAPTRACE entry to use after death.
	 */
	.globl	trap_trace_postmort
	.comm	trap_trace_postmort, TRAP_ENT_SIZE
#endif	/* TRAPTRACE */

#endif	/* __lint */


#if defined(__amd64)

#if defined(__lint)

/* ARGSUSED */
void
_start(struct boot_syscalls *sysp, struct bootops *bop, Elf64_Boot *ebp)
{}

#else	/* __lint */

	ENTRY_NP(_start)

	/*
	 * %rdi = boot services (should die someday)
	 * %rdx = bootops
	 * end
	 */	

	leaq	edata(%rip), %rbp	/* reference edata for ksyms */
	movq	$0, (%rbp)		/* limit stack back trace */

	/*
	 * Initialize our stack pointer to the thread 0 stack (t0stack)
	 * and leave room for a "struct regs" for lwp0.  Note that the
	 * stack doesn't actually align to a 16-byte boundary until just
	 * before we call mlsetup because we want to use %rsp to point at
	 * our regs structure.
	 */
	leaq	t0stack(%rip), %rsp
	addq	$_CONST(DEFAULTSTKSZ - REGSIZE), %rsp
#if (REGSIZE & 15) == 0
	subq	$8, %rsp
#endif
	/*
	 * Save call back for special x86 boot services vector
	 */	
	movq	%rdi, sysp(%rip)

	movq	%rdx, bootops(%rip)		/* save bootops */
	movq	$bootops, bootopsp(%rip)

	/*
	 * Save arguments and flags, if only for debugging ..
	 */
	movq	%rdi, REGOFF_RDI(%rsp)
	movq	%rsi, REGOFF_RSI(%rsp)
	movq	%rdx, REGOFF_RDX(%rsp)
	movq	%rcx, REGOFF_RCX(%rsp)
	movq	%r8, REGOFF_R8(%rsp)
	movq	%r9, REGOFF_R9(%rsp)
	pushf
	popq	%r11
	movq	%r11, REGOFF_RFL(%rsp)

	DISABLE_INTR_FLAGS

	/*
	 * Enable write protect and alignment check faults.
	 */
	movq	%cr0, %rax
	orq	$_CONST(CR0_WP|CR0_AM), %rax
	andq	$_BITNOT(CR0_WT|CR0_CE), %rax
	movq	%rax, %cr0

	/*
	 * (We just assert this works by virtue of being here) 
	 */
	orl	$X86_CPUID, x86_feature(%rip)

	/*
	 * mlsetup() gets called with a struct regs as argument, while
	 * main takes no args and should never return.
	 */
	xorl	%ebp, %ebp
	movq	%rsp, %rdi
	pushq	%rbp
	/* (stack pointer now aligned on 16-byte boundary right here) */
	movq	%rsp, %rbp
	call	mlsetup
	call	main
	/* NOTREACHED */
	leaq	__return_from_main(%rip), %rdi
	xorl	%eax, %eax
	call	panic
	SET_SIZE(_start)

	/*
	 * Kernel's handler to switch stacks before invoking
	 * vmx's putchar handler.
	 *
	 * This is needed because we use the boot program for
	 * console services for a -long- time before consconfig
	 * takes them over.  In an ideal world, we'd have a console
	 * configured earlier.
	 *
	 * We use this stack to execute bsys->putchar on, because
	 * we may be asking vmx/boot to print something using a stack
	 * that only exists in the 64-bit MMU e.g. a trapping thread.
	 */
	.data
	.comm	_safe_putchar_stack, DEFAULTSTKSZ, 32

	ENTRY_NP(_stack_safe_putchar)
	.globl	_vmx_sysp
	movq	%rsp, %r11
	leaq	_safe_putchar_stack+DEFAULTSTKSZ(%rip), %rsp
	pushq	%r11
	movq	_vmx_sysp(%rip), %r10
	call	*BOOTSVCS_PUTCHAR(%r10)
	popq	%r11
	movq	%r11, %rsp
	ret
	SET_SIZE(_stack_safe_putchar)

#endif	/* __amd64 */
#endif	/* __lint */

#if !defined(__lint)

__return_from_main:
	.string	"main() returned"
__unsupported_cpu:
	.string	"486 style cpu detected - no longer supported!"

#endif	/* !__lint */

#if !defined(__amd64)

#if defined(__lint)

/*ARGSUSED*/
void
_start(struct boot_syscalls *sysp, struct bootops *bop, Elf32_Boot * ebp)
{}

#else	/* __lint */

	ENTRY_NP(_start)
	/*
	 * We jump to __start to make sure the  function
	 * enable_big_page_support does not span multiple 4K pages. This
	 * is  essential, since we need to turn paging off in
	 * enable_big_page_support
	 */
	jmp	__start

	/*
	 * It is very important that this function sit right here in the file
	 * This function should not span multiple pages. This function has
	 * to be executed from an address such that we have 1-1 mapping.
	 * First we disable paging, then we load %cr4 with %edx and then
	 * enable paging. We return to  0xe00xxxx with paging enabled.
	 */

	ENTRY_NP(enable_big_page_support)
	movl	%cr0, %eax
	and	$_BITNOT(CR0_PG), %eax
	movl	%eax, %cr0	/ disable paging
	movl	%cr3, %eax
	movl	%eax, %cr3
	movl	%cr4, %eax
	orl	%ebx, %eax
	movl	%eax, %cr4
	nop
	movl	%cr0, %eax
	orl	$CR0_PG, %eax	/ enable paging
	movl	%eax, %cr0
	jmp	enable_big_page_support_done
enable_big_page_support_done:
	xorl	%eax, %eax
	ret
	SET_SIZE(enable_big_page_support)

	/*
	 * This function enables physical address extension thereby
	 * switching from 32 bit pte's to 64 bit pte's
	 *
	 * It loads the argument that it received in %ebx into cr3
	 *
	 * XXX	is there some reason why this routine -can't- use
	 *	normal C parameter passing conventions??
	 */
	ENTRY_NP(enable_pae)
	/*
	 * disable paging
	 */
	movl	%cr0, %eax
	andl	$_BITNOT(CR0_PG), %eax
	movl	%eax, %cr0
	/*
	 * enable physical address extension
	 */
	movl	%cr4, %eax
	orl	$CR4_PAE, %eax
	movl	%eax, %cr4	
	/*
	 * set new page table base
	 */
 	movl	%ebx, %cr3
	/*
	 * restart paging
	 */
	movl	%cr0, %eax
	orl	$CR0_PG, %eax
	movl	%eax, %cr0
	jmp	enable_pae_done		/ jmp required after enabling paging
enable_pae_done:
	/*
	 * flush TLBs just in case and return
	 */
	movl	%cr3, %eax
	movl	%eax, %cr3
	orl	$CR4_PAE, cr4_value
	ret
	SET_SIZE(enable_pae)

__start:
	/*
	 *	%ecx = boot services (should die someday)
	 *	%ebx = bootops
	 */	
	mov	$edata, %ebp		/ edata needs to be defined for ksyms
	movl	$0, (%ebp)		/ limit stack back trace

	/*
	 * Initialize our stack pointer to the thread 0 stack (t0stack)
	 * and leave room for a phony "struct regs".
	 */
	movl	$t0stack + DEFAULTSTKSZ - REGSIZE, %esp

	/*
	 * Save call back for special x86 boot services vector
	 */
	mov	%ecx, sysp		/ save call back for boot services

 	mov	%ebx, bootops		/ save bootops
	movl	$bootops, bootopsp

	DISABLE_INTR_FLAGS
	/*
	 * Save all registers and flags
	 */
	pushal	
	pushfl

	/*
	 * Override bios settings and enable write protect and
	 * alignment check faults.
	 */
	movl	%cr0, %eax

	/*
	 * enable WP for detecting faults, and enable alignment checking.
	 */
	orl	$_CONST(CR0_WP|CR0_AM), %eax
	andl	$_BITNOT(CR0_WT|CR0_CE), %eax
	movl	%eax, %cr0		/ set the cr0 register correctly and
					/ override the BIOS setup
	/*
	 * If bit 21 of eflags can be flipped, then cpuid is present
	 * and enabled.
	 */
	pushfl
	popl	%ecx
	movl	%ecx, %eax
	xorl	$PS_ID, %eax		/ try complemented bit
	pushl	%eax
	popfl
	pushfl
	popl    %eax
	cmpl	%eax, %ecx
	jne	have_cpuid

	/*
	 * cpuid may be disabled on Cyrix, try to detect Cyrix by the 5/2 test
	 * div does not modify the cc flags on Cyrix, even though this may
	 * also be true for other vendors, this is generally true only for
	 * newer models from those vendors that support and do not disable
	 * cpuid (usually because cpuid cannot be disabled)
	 */

	/*
	 * clear cc flags
	 */
	xorb	%ah, %ah
	sahf

	/*
	 * perform 5/2 test
	 */
	movw	$5, %ax
	movb	$2, %bl
	divb	%bl

	lahf
	cmpb	$2, %ah
	jne	cpu_486

	/*
	 * div did not modify the cc flags, chances are the vendor is Cyrix
	 * assume the vendor is Cyrix and use the CCR's to enable cpuid
	 */
	.set	CYRIX_CRI, 0x22		/ CR Index Register
	.set	CYRIX_CRD, 0x23		/ CR Data Register

	.set	CYRIX_CCR3, 0xc3	/ Config Control Reg 3
	.set	CYRIX_CCR4, 0xe8	/ Config Control Reg 4
	.set	CYRIX_DIR0, 0xfe	/ Device Identification Reg 0
	.set	CYRIX_DIR1, 0xff	/ Device Identification Reg 1

	/*
	 * even if the cpu vendor is Cyrix and the motherboard/chipset
	 * vendor decided to ignore lines A1-A4 for I/O addresses, I/O port
	 * 0x21 corresponds with 0x23 and since 0x22 is still untouched,
	 * the reads and writes of 0x21 are guaranteed to be off-chip of
	 * the cpu
	 */

	/*
	 * enable read of ISR at I/O port 0x20
	 */
	movb	$0xb, %al
	outb	$MCMD_PORT

	/*
	 * read IMR and store in %bl
	 */
	inb	$MIMR_PORT
	movb	%al, %bl

	/*
	 * mask out all interrupts so that ISR will not change
	 */
	movb	$0xff, %al
	outb	$MIMR_PORT

	/*
	 * reads of I/O port 0x22 on Cyrix are always directed off-chip
	 * make use of I/O pull-up to test for an unknown device on 0x22
	 */
	inb	$CYRIX_CRI
	cmpb	$0xff, %al
	je	port_22_free

	/*
	 * motherboard/chipset vendor may be ignoring line A1 of I/O address
	 */
	movb	%al, %cl

	/*
	 * if the ISR and the value read from 0x22 do not match then we have
	 * detected some unknown device, probably a chipset, at 0x22
	 */
	inb	$MCMD_PORT
	cmpb	%al, %cl
	jne	restore_IMR

port_22_free:
	/*
	 * now test to see if some unknown device is using I/O port 0x23
	 *
	 * read the external I/O port at 0x23
	 */
	inb	$CYRIX_CRD

	/*
	 * Test for pull-up at 0x23 or if I/O address line A1 is being ignored.
	 * IMR is 0xff so both tests are performed simultaneously.
	 */
	cmpb	$0xff, %al
	jne	restore_IMR

	/*
	 * We are a Cyrix part. In case we are some model of Cx486 or a Cx586,
	 * record the type and fix it later if not.
	 */
	movl	$X86_VENDOR_Cyrix, x86_vendor
	movl	$X86_TYPE_CYRIX_486, x86_type

	/*
	 * Try to read CCR3. All Cyrix cpu's which support cpuid have CCR3.
	 *
	 * load CCR3 index into CCR index register
	 */

	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI

	/*
	 * If we are not a Cyrix cpu, then we have performed an external I/O
	 * cycle. If the CCR index was not valid for this Cyrix model, we may
	 * have performed an external I/O cycle as well. In these cases and
	 * if the motherboard/chipset vendor ignores I/O address line A1,
	 * then the PIC will have IRQ3 set at the lowest priority as a side	
	 * effect of the above outb. We are reasonalbly confident that there
	 * is not an unknown device on I/O port 0x22, so there should have been
	 * no unpredictable side-effect of the above outb.
	 */

	/*
	 * read CCR3
	 */
	inb	$CYRIX_CRD

	/*
	 * If we are not a Cyrix cpu the inb above produced an external I/O
	 * cycle. If we are a Cyrix model that does not support CCR3 wex
	 * produced an external I/O cycle. In all known Cyrix models 6x86 and
	 * above, bit 3 of CCR3 is reserved and cannot be set to 1. In all
	 * Cyrix models prior to the 6x86 that supported CCR3, bits 4-7 are
	 * reserved as well. It is highly unlikely that CCR3 contains the value
	 * 0xff. We test to see if I/O port 0x23 is pull-up or the IMR and
	 * deduce we are not a Cyrix with support for cpuid if so.
	 */
	cmpb	$0xff, %al
	je	restore_PIC

	/*
	 * There exist 486 ISA Cyrix chips that support CCR3 but do not support
	 * DIR0 and DIR1. If we try to read DIR0, we may generate external I/O
	 * cycles, the exact behavior is model specific and undocumented.
	 * Unfortunately these external I/O cycles may confuse some PIC's beyond
	 * recovery. Fortunatetly we can use the following undocumented trick:
	 * if bit 4 of CCR3 can be toggled, then DIR0 and DIR1 are supported.
	 * Pleasantly MAPEN contains bit 4 of CCR3, so this trick is guaranteed
	 * to work on all Cyrix cpu's which support cpuid.
	 */
	movb	%al, %dl
	xorb	$0x10, %dl
	movb	%al, %cl

	/*
	 * write back CRR3 with toggled bit 4 to CCR3
	 */
	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI

	movb	%dl, %al
	outb	$CYRIX_CRD

	/*
	 * read CCR3
	 */
	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI
	inb	$CYRIX_CRD
	movb	%al, %dl

	/*
	 * restore CCR3
	 */
	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI

	movb	%cl, %al
	outb	$CYRIX_CRD

	/*
	 * if bit 4 was not toggled DIR0 and DIR1 are not supported in which
	 * case we do not have cpuid anyway
	 */
	andb	$0x10, %al
	andb	$0x10, %dl
	cmpb	%al, %dl
	je	restore_PIC

	/*
	 * read DIR0
	 */
	movb	$CYRIX_DIR0, %al
	outb	$CYRIX_CRI
	inb	$CYRIX_CRD

	/*
	 * test for pull-up
	 */
	cmpb	$0xff, %al
	je	restore_PIC

	/*
	 * Values of 0x20-0x27 in DIR0 are currently reserved by Cyrix for
	 * future use. If Cyrix ever produces a cpu that supports cpuid with
	 * these ids, the following test will have to change. For now we remain
	 * pessimistic since the formats of the CRR's may be different then.
	 *
	 * test for at least a 6x86, to see if we support both MAPEN and CPUID
	 */
	cmpb	$0x30, %al
	jb	restore_IMR

	/*
	 * enable MAPEN
	 */
	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI

	andb	$0xf, %cl
	movb	%cl, %al
	orb	$0x10, %al
	outb	$CYRIX_CRD

	/*
	 * select CCR4
	 */
	movb	$CYRIX_CCR4, %al
	outb	$CYRIX_CRI

	/*
	 * read CCR4
	 */
	inb	$CYRIX_CRD

	/*
	 * enable cpuid
	 */
	orb	$0x80, %al
	movb	%al, %dl

	/*
	 * select CCR4
	 */
	movb	$CYRIX_CCR4, %al
	outb	$CYRIX_CRI

	/*
	 * write CCR4
	 */
	movb	%dl, %al
	outb	$CYRIX_CRD

	/*
	 * select CCR3
	 */
	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI

	/*
	 * disable MAPEN and write CCR3
	 */
	movb	%cl, %al
	outb	$CYRIX_CRD

	/*
	 * restore IMR
	 */
	movb	%bl, %al
	outb	$MIMR_PORT

	/*
	 * test to see if cpuid available
	 */
	pushfl
	popl	%ecx
	movl	%ecx, %eax
	xorl	$PS_ID, %eax		/ try complemented bit
	pushl	%eax
	popfl
	pushfl
	popl    %eax
	cmpl	%eax, %ecx
	jne	have_cpuid
	jmp	cpu_486

restore_PIC:
	/*
	 * In case the motherboard/chipset vendor is ignoring line A1 of the
	 * I/O address, we set the PIC priorities to sane values.
	 */
	movb	$0xc7, %al	/ irq 7 lowest priority
	outb	$MCMD_PORT

restore_IMR:
	movb	%bl, %al
	outb	$MIMR_PORT
	jmp	cpu_486

have_cpuid:
	/*
	 * cpuid instruction present
	 */
	orl	$X86_CPUID, x86_feature
	movl	$0, %eax
	cpuid

	movl	%ebx, cpu_vendor
	movl	%edx, cpu_vendor+4
	movl	%ecx, cpu_vendor+8

	/*
	 * early cyrix cpus are somewhat strange and need to be
	 * probed in curious ways to determine their identity
	 */

	leal	cpu_vendor, %esi
	leal	CyrixInstead, %edi
	movl	$12, %ecx
	repz
	  cmpsb
	je	vendor_is_cyrix

	/ let mlsetup()/cpuid_pass1() handle everything else in C

	jmp	cpu_done

is486:
	/*
	 * test to see if a useful cpuid
	 */
	testl	%eax, %eax
	jz	isa486

	movl	$1, %eax
	cpuid

	movl	%eax, %ebx
	andl	$0xF00, %ebx
	cmpl	$0x400, %ebx
	je	isa486

	ret
isa486:
	/*
	 * lose the return address
	 */
	popl	%eax
	jmp	cpu_486

vendor_is_cyrix:
	call	is486

	/*
	 * Processor signature and feature flags for Cyrix are insane.
	 * BIOS can play with semi-documented registers, so cpuid must be used
	 * cautiously. Since we are Cyrix that has cpuid, we have DIR0 and DIR1
	 * Keep the family in %ebx and feature flags in %edx until not needed
	 */

	/*
	 * read DIR0
	 */
	movb	$CYRIX_DIR0, %al
	outb	$CYRIX_CRI
	inb	$CYRIX_CRD

	/*
	 * First we handle the cases where we are a 6x86 or 6x86L.
	 * The 6x86 is basically a 486, the only reliable bit in the
	 * feature flags is for FPU. The 6x86L is better, unfortunately
	 * there is no really good way to distinguish between these two
	 * cpu's. We are pessimistic and when in doubt assume 6x86.
	 */

	cmpb	$0x40, %al
	jae	maybeGX

	/*
	 * We are an M1, either a 6x86 or 6x86L.
	 */
	cmpb	$0x30, %al
	je	maybe6x86L
	cmpb	$0x31, %al
	je	maybe6x86L
	cmpb	$0x34, %al
	je	maybe6x86L
	cmpb	$0x35, %al
	je	maybe6x86L

	/*
	 * although it is possible that we are a 6x86L, the cpu and
	 * documentation are so buggy, we just do not care.
	 */
	jmp	likely6x86

maybe6x86L:
	/*
	 *  read DIR1
	 */
	movb	$CYRIX_DIR1, %al
	outb	$CYRIX_CRI
	inb	$CYRIX_CRD
	cmpb	$0x22, %al
	jb	likely6x86

	/*
	 * We are a 6x86L, or at least a 6x86 with honest cpuid feature flags
	 */
	movl	$X86_TYPE_CYRIX_6x86L, x86_type
	jmp	coma_bug

likely6x86:
	/*
	 * We are likely a 6x86, or a 6x86L without a way of knowing
	 *
	 * The 6x86 has NO Pentium or Pentium Pro compatible features even
	 * though it claims to be a Pentium Pro compatible!
	 *
	 * The 6x86 core used in the 6x86 may have most of the Pentium system
	 * registers and largely conform to the Pentium System Programming
	 * Reference. Documentation on these parts is long gone. Treat it as
	 * a crippled Pentium and hope for the best.
	 */

	movl	$X86_TYPE_CYRIX_6x86, x86_type
	jmp	coma_bug

maybeGX:
	/*
	 * Now we check whether we are a MediaGX or GXm. We have particular
	 * reason for concern here. Even though most of the GXm's
	 * report having TSC in the cpuid feature flags, the TSC may be
	 * horribly broken. What is worse, is that MediaGX's are basically
	 * 486's while the good GXm's are more like Pentium Pro's!
	 */

	cmpb	$0x50, %al
	jae	maybeM2

	/*
	 * We are either a MediaGX (sometimes called a Gx86) or GXm
	 */

	cmpb	$41, %al
	je	maybeMediaGX

	cmpb	$44, %al
	jb	maybeGXm

	cmpb	$47, %al
	jbe	maybeMediaGX

	/*
	 * We do not honestly know what we are, so assume a MediaGX
	 */
	jmp	media_gx

maybeGXm:
	/*
	 * It is still possible we are either a MediaGX or GXm, trust cpuid
	 * family should be 5 on a GXm
	 */
	cmpl	$0x500, %ebx
	je	GXm

	/*
	 * BIOS/Cyrix might set family to 6 on a GXm
	 */
	cmpl	$0x600, %ebx
	jne	media_gx

GXm:
	movl	$X86_TYPE_CYRIX_GXm, x86_type
	jmp	cpu_done

maybeMediaGX:
	/*
	 * read DIR1
	 */
	movb	$CYRIX_DIR1, %al
	outb	$CYRIX_CRI
	inb	$CYRIX_CRD

	cmpb	$0x30, %al
	jae	maybeGXm

	/*
	 * we are a MediaGX for which we do not trust cpuid
	 */
media_gx:
	movl	$X86_TYPE_CYRIX_MediaGX, x86_type
	jmp	cpu_486

maybeM2:
	/*
	 * Now we check whether we are a 6x86MX or MII. These cpu's are
	 * virtually identical, but we care because for the 6x86MX, we
	 * must work around the coma bug. Also for 6x86MX prior to revision
	 * 1.4, the TSC may have serious bugs.
	 */

	cmpb	$0x60, %al
	jae	maybeM3

	/*
	 * family should be 6, but BIOS/Cyrix might set it to 5
	 */
	cmpl	$0x600, %ebx
	ja	cpu_486

	/*
	 *  read DIR1
	 */
	movb	$CYRIX_DIR1, %al
	outb	$CYRIX_CRI
	inb	$CYRIX_CRD

	cmpb	$0x8, %al
	jb	cyrix6x86MX
	cmpb	$0x80, %al
	jb	MII

cyrix6x86MX:
	/*
	 * It is altogether unclear how the revision stamped on the cpu
	 * maps to the values in DIR0 and DIR1. Just assume TSC is broken.
	 */
	movl	$X86_TYPE_CYRIX_6x86MX, x86_type
	jmp	coma_bug

MII:
	movl	$X86_TYPE_CYRIX_MII, x86_type
likeMII:
	jmp	cpu_done

maybeM3:
	/*
	 * We are some chip that we cannot identify yet, an MIII perhaps.
	 * We will be optimistic and hope that the chip is much like an MII,
	 * and that cpuid is sane. Cyrix seemed to have gotten it right in
	 * time for the MII, we can only hope it stayed that way.
	 * Maybe the BIOS or Cyrix is trying to hint at something
	 */
	cmpl	$0x500, %ebx
	je	GXm

	cmpb	$0x80, %al
	jae	likelyM3

	/*
	 * Just test for the features Cyrix is known for
	 */

	jmp	MII

likelyM3:
	/*
	 * DIR0 with values from 0x80 to 0x8f indicates a VIA Cyrix III, aka
	 * the Cyrix MIII. There may be parts later that use the same ranges
	 * for DIR0 with special values in DIR1, maybe the VIA CIII, but for
	 * now we will call anything with a DIR0 of 0x80 or higher an MIII.
	 * The MIII is supposed to support large pages, but we will believe
	 * it when we see it. For now we just enable and test for MII features.
	 */	
	movl	$X86_TYPE_VIA_CYRIX_III, x86_type
	jmp	likeMII

coma_bug:

/*
 * With NO_LOCK set to 0 in CCR1, the usual state that BIOS enforces, some
 * bus cycles are issued with LOCK# asserted. With NO_LOCK set to 1, all bus
 * cycles except page table accesses and interrupt ACK cycles do not assert
 * LOCK#. xchgl is an instruction that asserts LOCK# if NO_LOCK is set to 0.
 * Due to a bug in the cpu core involving over-optimization of branch
 * prediction, register renaming, and execution of instructions down both the
 * X and Y pipes for the xchgl instruction, short loops can be written that
 * never de-assert LOCK# from one invocation of the loop to the next, ad
 * infinitum. The undesirable effect of this situation is that interrupts are
 * not serviced. The ideal workaround to this bug would be to set NO_LOCK to
 * 1. Unfortunately bus cycles that would otherwise have asserted LOCK# no
 * longer do, unless they are page table accesses or interrupt ACK cycles.
 * With LOCK# not asserted, these bus cycles are now cached. This can cause
 * undesirable behaviour if the ARR's are not configured correctly. Solaris
 * does not configure the ARR's, nor does it provide any useful mechanism for
 * doing so, thus the ideal workaround is not viable. Fortunately, the only
 * known exploits for this bug involve the xchgl instruction specifically.
 * There is a group of undocumented registers on Cyrix 6x86, 6x86L, and
 * 6x86MX cpu's which can be used to specify one instruction as a serializing
 * instruction. With the xchgl instruction serialized, LOCK# is still
 * asserted, but it is the sole instruction for which LOCK# is asserted.
 * There is now some added penalty for the xchgl instruction, but the usual
 * bus locking is preserved. This ingenious workaround was discovered by
 * disassembling a binary provided by Cyrix as a workaround for this bug on
 * Windows, but its not documented anywhere by Cyrix, nor is the bug actually
 * mentioned in any public errata! The only concern for this workaround is
 * that there may be similar undiscovered bugs with other instructions that
 * assert LOCK# that may be leveraged to similar ends. The fact that Cyrix
 * fixed this bug sometime late in 1997 and no other exploits other than
 * xchgl have been discovered is good indication that this workaround is
 * reasonable.
 */	

	.set	CYRIX_DBR0, 0x30	/ Debug Register 0
	.set	CYRIX_DBR1, 0x31	/ Debug Register 1
	.set	CYRIX_DBR2, 0x32	/ Debug Register 2
	.set	CYRIX_DBR3, 0x33	/ Debug Register 3
	.set	CYRIX_DOR, 0x3c		/ Debug Opcode Register

	/*
 	 * What is known about DBR1, DBR2, DBR3, and DOR is that for normal
	 * cpu execution DBR1, DBR2, and DBR3 are set to 0. To obtain opcode
	 * serialization, DBR1, DBR2, and DBR3 are loaded with 0xb8, 0x7f,
	 * and 0xff. Then, DOR is loaded with the one byte opcode.
	 */

	/*
	 * select CCR3
	 */
	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI

	/*
	 * read CCR3 and mask out MAPEN
	 */
	inb	$CYRIX_CRD
	andb	$0xf, %al

	/*
	 * save masked CCR3 in %ah
	 */
	movb	%al, %ah

	/*
	 * select CCR3
	 */
	movb	$CYRIX_CCR3, %al
	outb	$CYRIX_CRI

	/*
	 * enable MAPEN
	 */
	movb	%ah, %al
	orb	$0x10, %al
	outb	$CYRIX_CRD

	/*
	 * read DBR0
	 */
	movb	$CYRIX_DBR0, %al
	outb	$CYRIX_CRI
	inb	$CYRIX_CRD

	/*
	 * disable MATCH and save in %bh
	 */
	orb	$0x80, %al
	movb	%al, %bh

	/*
	 * write DBR0
	 */
	movb	$CYRIX_DBR0, %al
	outb	$CYRIX_CRI
	movb	%bh, %al
	outb	$CYRIX_CRD

	/*
	 * write DBR1
	 */
	movb	$CYRIX_DBR1, %al 
	outb	$CYRIX_CRI
	movb	$0xf8, %al
	outb	$CYRIX_CRD

	/*
	 * write DBR2
	 */
	movb	$CYRIX_DBR2, %al
	outb	$CYRIX_CRI
	movb	$0x7f, %al
	outb	$CYRIX_CRD

	/*
	 * write DBR3
	 */
	movb	$CYRIX_DBR3, %al
	outb	$CYRIX_CRI
	xorb	%al, %al
	outb	$CYRIX_CRD

	/*
	 * write DOR
	 */
	movb	$CYRIX_DOR, %al
	outb	$CYRIX_CRI
	movb	$0x87, %al
	outb	$CYRIX_CRD

	/*
	 * enable MATCH
	 */
	movb	$CYRIX_DBR0, %al
	outb	$CYRIX_CRI
	movb	%bh, %al
	andb	$0x7f, %al
	outb	$CYRIX_CRD

	/*
	 * disable MAPEN
	 */
	movb	$0xc3, %al
	outb	$CYRIX_CRI
	movb	%ah, %al
	outb	$CYRIX_CRD

	jmp	cpu_done

cpu_done:
	popfl					/* Restore original FLAGS */
	popal					/* Restore all registers */

	/*
	 *  mlsetup(%esp) gets called.
	 */
	pushl	%esp
	call	mlsetup
	addl	$4, %esp

	/*
	 * We change our appearance to look like the real thread 0.
	 * (NOTE: making ourselves to be a real thread may be a noop)
	 * main() gets called.  (NOTE: main() never returns).
	 */
	call	main
	/* NOTREACHED */
	pushl	$__return_from_main
	call	panic

	/* NOTREACHED */
cpu_486:
	pushl	$__unsupported_cpu
	call	panic
	SET_SIZE(_start)

#endif	/* __lint */
#endif	/* !__amd64 */


/*
 *  For stack layout, see reg.h
 *  When cmntrap gets called, the error code and trap number have been pushed.
 */

#if defined(__lint)

/* ARGSUSED */
void
cmntrap()
{}

#else	/* __lint */

	.globl	trap		/* C handler called below */

#if defined(__amd64)

	ENTRY_NP2(cmntrap, _cmntrap)

	TRAP_PUSH

	/*
	 * We must first check if DTrace has set its NOFAULT bit.  This
	 * regrettably must happen before the TRAPTRACE data is recorded,
	 * because recording the TRAPTRACE data includes obtaining a stack
	 * trace -- which requires a call to getpcstack() and may induce
	 * recursion if an fbt::getpcstack: enabling is inducing the bad load.
	 */
	movl	%gs:CPU_ID, %eax
	shlq	$CPU_CORE_SHIFT, %rax
	leaq	cpu_core(%rip), %r8
	addq	%r8, %rax
	movw	CPUC_DTRACE_FLAGS(%rax), %cx
	testw	$CPU_DTRACE_NOFAULT, %cx
	jnz	.dtrace_induced

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	/*
	 * Getting a stack trace as part of TRACE_STACK() requires a call to
	 * getpcstack().  Before we can do this, we must move our stack pointer
	 * into the base pointer, and we must save the value of %cr2.  %cr2
	 * must be saved before the call because getpcstack() may be
	 * instrumented by DTrace -- and any invalid load in the DTrace
	 * enabling will clobber %cr2.
	 */
	movq	%rsp, %rbp
	movq	%cr2, %r12

	TRACE_STACK(%rdi)

/	XXX - check for NMIs????

	/ If this is a debug trap, save %dr6 in the pcb
	cmpl	$T_SGLSTP, REGOFF_TRAPNO(%rbp)
	jne	.L11
	movq	%gs:CPU_LWP, %rax
	orq	%rax, %rax
	jz	.L11		/* null lwp pointer; can't happen? */
	movq	%db6, %rcx
	movq	%rcx, LWP_PCB_DRSTAT(%rax)
	movl	$0, %ecx
	movq	%rcx, %db6	/* clear debug status register */
.L11:
	movq	%rbp, %rdi
	movq	%r12, %rsi
	movl	%gs:CPU_ID, %edx

	/
	/ We know that this isn't a DTrace non-faulting load; we can now safely
	/ reenable interrupts.  (In the case of pagefaults, we enter through an
	/ interrupt gate.)
	/
	ENABLE_INTR_FLAGS

	call	trap		/* trap(rp, addr, cpuid) handles all traps */

	jmp	_sys_rtt
.dtrace_induced:
	movq	%rsp, %rbp
	testw	$CPL_MASK, REGOFF_CS(%rbp)	/* test CS for user-mode trap */
	jnz	2f				/* if from user, panic */

	cmpl	$T_PGFLT, REGOFF_TRAPNO(%rbp)
	je	0f				/* if not a pagefault, panic */

	cmpl	$T_GPFLT, REGOFF_TRAPNO(%rbp)
	jne	3f

	/*
	 * If we've taken a GPF, we don't (unfortunately) have the address that
	 * induced the fault.  So instead of setting the fault to BADADDR,
	 * we'll set the fault to ILLOP.
	 */
	orw	$CPU_DTRACE_ILLOP, %cx
	movw	%cx, CPUC_DTRACE_FLAGS(%rax)
	jmp	1f
0:
	orw	$CPU_DTRACE_BADADDR, %cx
	movw	%cx, CPUC_DTRACE_FLAGS(%rax)	/* set fault to bad addr */
	movq	%cr2, %rcx
	movq	%rcx, CPUC_DTRACE_ILLVAL(%rax)
					    /* fault addr is illegal value */
1:
	movq	REGOFF_RIP(%rbp), %rdi
	movq	%rdi, %r12
	call	dtrace_instr_size
	addq	%rax, %r12
	movq	%r12, REGOFF_RIP(%rbp)
	INTR_POP
	iretq
2:
	leaq	dtrace_badflags(%rip), %rdi
	xorl	%eax, %eax
	call	panic
3:
	leaq	dtrace_badtrap(%rip), %rdi
	xorl	%eax, %eax
	call	panic

	SET_SIZE(cmntrap)
	SET_SIZE(_cmntrap)

#elif defined(__i386)

	ENTRY_NP2(cmntrap, _cmntrap)

	INTR_PUSH

	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%edi, %esp, %ebx, %ecx)	/* Uses label 9 */
	TRACE_STAMP(%edi)		/* Clobbers %eax, %edx, uses 9 */

	movl	%esp, %ebp

/	XXX - check for NMIs????

	/ If this is a debug trap, save %dr6 in the pcb
	cmpl	$T_SGLSTP, REGOFF_TRAPNO(%ebp)
	jne	.L11
	movl	%gs:CPU_LWP, %eax
	orl	%eax, %eax
	jz	.L11		/* null lwp pointer; can't happen? */
	movl	%db6, %ecx
	movl	%ecx, LWP_PCB_DRSTAT(%eax)
	movl	$0, %ecx
	movl	%ecx, %db6	/* clear debug status register */
.L11:
	pushl	%gs:CPU_ID
	movl	%cr2, %eax	/ fault address for PGFLTs
	pushl	%eax
	pushl	%ebp

	/*
	 * We must now check if DTrace has set its NOFAULT bit.
	 */
	movl	%gs:CPU_ID, %eax
	shll	$CPU_CORE_SHIFT, %eax
	addl	$cpu_core, %eax
	movw	CPUC_DTRACE_FLAGS(%eax), %cx
	testw	$CPU_DTRACE_NOFAULT, %cx
	jnz	0f

	/*
	 * We know that this isn't a DTrace non-faulting load; we can now safely
	 * reenable interrupts.  (In the case of pagefaults, we enter through an
	 * interrupt gate.)
	 */
	ENABLE_INTR_FLAGS

	call	trap		/* trap(rp, addr, cpuid) handles all traps */
	addl	$12, %esp	/* get argument off stack */

	jmp	_sys_rtt

0:
	testw	$CPL_MASK, REGOFF_CS(%ebp)	/* test CS for user-mode trap */
	jnz	2f				/* if from user, panic */

	cmpl	$T_PGFLT, REGOFF_TRAPNO(%ebp)
	je	0f				/* if not a pagefault, panic */

	cmpl	$T_GPFLT, REGOFF_TRAPNO(%ebp)
	jne	3f

	/*
	 * If we've taken a GPF, we don't (unfortunately) have the address that
	 * induced the fault.  So instead of setting the fault to BADADDR,
	 * we'll set the fault to ILLOP.
	 */
	orw	$CPU_DTRACE_ILLOP, %cx
	movw	%cx, CPUC_DTRACE_FLAGS(%eax)
	jmp	1f

0:
	orw	$CPU_DTRACE_BADADDR, %cx
	movw	%cx, CPUC_DTRACE_FLAGS(%eax)	/* set fault to bad addr */
	movl	%cr2, %ecx
	movl	%ecx, CPUC_DTRACE_ILLVAL(%eax)
					    /* fault addr is illegal value */
1:
	pushl	REGOFF_EIP(%ebp)
	call	dtrace_instr_size
	addl	$16, %esp
	movl	REGOFF_EIP(%ebp), %ecx
	addl	%eax, %ecx
	movl	%ecx, REGOFF_EIP(%ebp)
	INTR_POP_KERNEL
	iret
2:
	pushl	$dtrace_badflags
	call	panic

3:
	pushl	$dtrace_badtrap
	call	panic

	SET_SIZE(cmntrap)
	SET_SIZE(_cmntrap)

#endif	/* __i386 */

/*
 * Declare a uintptr_t which has the size of _cmntrap to enable stack
 * traceback code to know when a regs structure is on the stack.
 */
	.globl	_cmntrap_size
	.align	CLONGSIZE
_cmntrap_size:
	.NWORD	. - _cmntrap
	.type	_cmntrap_size, @object

dtrace_badflags:
	.string "bad DTrace flags"

dtrace_badtrap:
	.string "bad DTrace trap"

#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
void
cmninttrap()
{}

#else	/* __lint */

	.globl	trap		/* C handler called below */

#if defined(__amd64)

	ENTRY_NP(cmninttrap)

	INTR_PUSH

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	DISABLE_INTR_FLAGS

	movq	%rsp, %rbp

	movl	%gs:CPU_ID, %edx
	xorl	%esi, %esi
	movq	%rsp, %rdi
	call	trap		/* trap(rp, addr, cpuid) handles all traps */

	jmp	_sys_rtt
	SET_SIZE(cmninttrap)

#elif defined(__i386)

	ENTRY_NP(cmninttrap)

	INTR_PUSH
	DISABLE_INTR_FLAGS

	movl	%esp, %ebp

	movl	%esp, %ecx
	pushl	%gs:CPU_ID
	pushl	$0		/* fake cr2 (cmntrap is used for page faults) */
	pushl	%ecx
	call	trap		/* trap(rp, addr, cpuid) handles all traps */
	addl	$12, %esp	/* get argument off stack */

	jmp	_sys_rtt
	SET_SIZE(cmninttrap)

#endif	/* __i386 */

#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
void
dtrace_trap()
{}

#else	/* __lint */

	.globl	dtrace_user_probe

#if defined(__amd64)

	ENTRY_NP(dtrace_trap)

	INTR_PUSH

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	movq	%rsp, %rbp

	movl	%gs:CPU_ID, %edx
	movq	%cr2, %rsi
	movq	%rsp, %rdi

	ENABLE_INTR_FLAGS

	call	dtrace_user_probe /* dtrace_user_probe(rp, addr, cpuid) */
	jmp	_sys_rtt

	SET_SIZE(dtrace_trap)

#elif defined(__i386)

	ENTRY_NP(dtrace_trap)

	INTR_PUSH

	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%edi, %esp, %ebx, %ecx)	/* Uses label 9 */
	TRACE_STAMP(%edi)		/* Clobbers %eax, %edx, uses 9 */

	movl	%esp, %ebp

	pushl	%gs:CPU_ID
	movl	%cr2, %eax
	pushl	%eax
	pushl	%ebp

	pushl	$F_ON
	popfl

	call	dtrace_user_probe /* dtrace_user_probe(rp, addr, cpuid) */
	addl	$12, %esp		/* get argument off stack */

	jmp	_sys_rtt
	SET_SIZE(dtrace_trap)

#endif	/* __i386 */

#endif	/* __lint */

/*
 * Return from _sys_trap routine.
 */

#if defined(__lint)

void
lwp_rtt_initial(void)
{}

void
lwp_rtt(void)
{}

void
_sys_rtt(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(lwp_rtt_initial)
	movq	%gs:CPU_THREAD, %r15
	movq	T_STACK(%r15), %rsp	/* switch to the thread stack */
	call	__dtrace_probe___proc_start
	jmp	_lwp_rtt

	ENTRY_NP(lwp_rtt)

	/*
	 * r14	lwp
	 * rdx	lwp->lwp_procp
	 * r15	curthread
	 */

	movq	%gs:CPU_THREAD, %r15
	movq	T_STACK(%r15), %rsp	/* switch to the thread stack */
_lwp_rtt:
	call	__dtrace_probe___proc_lwp__start
	movq	%gs:CPU_LWP, %r14
	movq	LWP_PROCP(%r14), %rdx

	/*
	 * XX64	Is the stack misaligned correctly at this point?
	 *	If not, we need to do a push before calling anything ..
	 */

#if defined(DEBUG)
	/*
	 * If we were to run lwp_savectx at this point -without-
	 * RUPDATE_PENDING being set, we'd end up sampling the hardware
	 * state left by the previous running lwp, rather than setting
	 * the values requested by the lwp creator.  Bad.
	 */
	testl	$RUPDATE_PENDING, PCB_FLAGS(%r14)
	jne	1f
	leaq	_no_pending_updates(%rip), %rdi
	movl	$__LINE__, %esi
	movq	%r14, %rdx
	xorl	%eax, %eax
	call	panic
_no_pending_updates:
	.string	"%M%:%d lwp_rtt(lwp %p) but no RUPDATE_PENDING"
1:
#endif

	/*
	 * If agent lwp, clear %fs and %gs
	 */
	cmpq	%r15, P_AGENTTP(%rdx)
	jne	1f
	xorl	%ecx, %ecx
	movq	%rcx, REGOFF_FS(%rsp)
	movq	%rcx, REGOFF_GS(%rsp)
	movw	%cx, LWP_PCB_FS(%r14)
	movw	%cx, LWP_PCB_GS(%r14)
1:
	call	dtrace_systrace_rtt
	movq	REGOFF_RDX(%rsp), %rsi
	movq	REGOFF_RAX(%rsp), %rdi
	call	post_syscall		/* post_syscall(rval1, rval2) */
	movq	%cr0, %rax
	orq	$CR0_TS, %rax
	movq	%rax, %cr0		/* set up to take fault */
					/* on first use of fp */
	ALTENTRY(_sys_rtt)
	testw	$CPL_MASK, REGOFF_CS(%rsp) /* test %cs for user mode return */
	jz	sr_sup

	/*
	 * Return to user
	 */
	cmpw	$UCS_SEL, REGOFF_CS(%rsp) /* test for native (64-bit) lwp? */
	je	sys_rtt_syscall

	/*
	 * Return to 32-bit userland, checking for an AST, and (optionally)
	 * twerking any changing segment registers on the way out.
	 */
	ALTENTRY(sys_rtt_syscall32)
	movq	%gs:CPU_THREAD, %rax
	cli				/* disable interrupts */
	cmpb	$0, T_ASTFLAG(%rax)	/* test for signal or AST flag */
	jne	_handle_ast

	movq	T_LWP(%rax), %r14
	movl	PCB_FLAGS(%r14), %edx
	testl	$RUPDATE_PENDING, %edx
	jne	_update_sregs

	/*
	 * The following label is branched to by sys_syscall32 handler
	 * so if iretq below #gp faults kern_gpfault can detect and
	 * handle it.
	 */
	ALTENTRY(_set_user32_regs)
	USER32_POP
	iretq
	/*NOTREACHED*/

	/*
	 * Return to 64-bit userland, checking for an AST, and (optionally)
	 * twerking any changing segment registers on the way out.
	 */
	ALTENTRY(sys_rtt_syscall)
	movq	%gs:CPU_THREAD, %rax
	cli				/* disable interrupts */
	cmpb	$0, T_ASTFLAG(%rax)	/* test for signal or AST flag */
	jne	_handle_ast

	movq	T_LWP(%rax), %r14
	movl	PCB_FLAGS(%r14), %edx
	testl	$RUPDATE_PENDING, %edx
	jne	_update_sregs
_set_user_regs:
	USER_POP
	iretq
	/*NOTREACHED*/

	/*
	 * XX64	Don't understand why we ever come here.
	 *	If we do come here then we can probably recover by just 
	 *	branching straight to _sys_rtt
	 */
bad_set_user_regs:
	leaq	__bad_set_user_regs_msg(%rip), %rdi
	movq	%rsp, %rsi
	movq	REGOFF_CS(%rsp), %rdx
	xorl	%eax, %eax
	call	panic
__bad_set_user_regs_msg:
	.string	"bad_set_user_regs: rp=%lx rp->r_cs=%lx; how did that happen?"

	/*
	 * Update the segment registers with new values from the pcb
	 *
	 * We have to do this carefully, and in the following order,
	 * in case any of the selectors points at a bogus descriptor.
	 * If they do, we'll take a trap that will end in delivering
	 * the application a weird SIGSEGV via kern_gpfault().
	 *
	 * This is particularly tricky for %gs.
	 *
	 * Note also the slightly brittle nature of the dependencies
	 * between this code and kern_gpfault().
	 */
	ENTRY_NP(_update_sregs)
	movw	LWP_PCB_GS(%r14), %bx
	movl	$MSR_AMD_GSBASE, %ecx
	rdmsr
	movw	%bx, %gs
	/*
	 * If that instruction failed because the new %gs is a bad %gs,
	 * we'll be taking a trap but with the original %gs and %gsbase
	 * undamaged (i.e. pointing at curcpu).  Otherwise, we've just
	 * mucked up the kernel's gsbase.  Oops.  Make the newly computed
	 * gsbase be the hidden gs, and fix the kernel's gsbase back again.
	 */
#if defined(OPTERON_ERRATUM_88)
	mfence
#endif
	swapgs
	wrmsr				/* repair kernel gsbase */
	movw	%bx, REGOFF_GS(%rsp)
	/*
	 * Only override the descriptor base address if r_gs == LWPGS_SEL
	 * or if r_gs == NULL.
	 *
	 * A note on NULL descriptors -- 32-bit programs take faults if
	 * they deference NULL descriptors; however, when 64-bit programs
	 * load them into %fs or %gs, they DONT fault -- only the base
	 * address remains whatever it was from the last load.   Urk.
	 *
	 * Avoid any leakage by setting the base address to an inaccessible
	 * region.
	 */
	cmpw	$0, %bx
	jne	0f
	movl	$0x80000000, LWP_PCB_GSBASE(%r14)
	movl	$0xffffffff, LWP_PCB_GSBASE+4(%r14)
	jmp	_set_gsbase
0:	cmpw	$LWPGS_SEL, %bx
	jne	1f
_set_gsbase:
	movl	$MSR_AMD_KGSBASE, %ecx
	movl	LWP_PCB_GSBASE(%r14), %eax
	movl	LWP_PCB_GSBASE+4(%r14), %edx
	wrmsr				/* update hidden gsbase for userland */
	movl	%eax, REGOFF_GSBASE(%rsp)
	movl	%edx, REGOFF_GSBASE+4(%rsp)
1:	movw	LWP_PCB_FS(%r14), %bx
	movw	%bx, %fs
	movw	%bx, REGOFF_FS(%rsp)
	/*
	 * Only override the descriptor base address if r_fs == LWPFS_SEL
	 * or if r_fs == NULL.
	 */
	cmpw	$0, %bx
	jne	2f
	movl	$0x80000000, LWP_PCB_FSBASE(%r14)
	movl	$0xffffffff, LWP_PCB_FSBASE+4(%r14)
	jmp	_set_fsbase
2:	cmpw	$LWPFS_SEL, %bx
	jne	3f
_set_fsbase:
	movl	$MSR_AMD_FSBASE, %ecx
	movl	LWP_PCB_FSBASE(%r14), %eax
	movl	LWP_PCB_FSBASE+4(%r14), %edx
	wrmsr				/* update fsbase for userland */
	movl	%eax, REGOFF_FSBASE(%rsp)
	movl	%edx, REGOFF_FSBASE+4(%rsp)
3:
	movw	LWP_PCB_ES(%r14), %bx
	movw	%bx, %es
	movw	%bx, REGOFF_ES(%rsp)
	movw	LWP_PCB_DS(%r14), %bx
	movw	%bx, %ds
	movw	%bx, REGOFF_DS(%rsp)
	andl	$_BITNOT(RUPDATE_PENDING), PCB_FLAGS(%r14)
	jmp	_set_user_regs
	.globl	_update_sregs_done
_update_sregs_done:
	/*NOTREACHED*/
	SET_SIZE(_update_sregs)
	
_handle_ast:
	/* Let trap() handle the AST */
	sti				/* enable interrupts */
	movl	$T_AST, REGOFF_TRAPNO(%rsp) /* set trap type to AST */
	movq	%rsp, %rdi
	xorl	%esi, %esi
	movl	%gs:CPU_ID, %edx
	call	trap			/* trap(rp, 0, cpuid) */
	jmp	_sys_rtt
	/*NOTREACHED*/
	
	/*
	 * Return to supervisor
	 */
	ALTENTRY(sr_sup)

	/* Check for a kernel preemption request */
	cmpb	$0, %gs:CPU_KPRUNRUN
	jne	sr_sup_preempt		/* preemption */

	/*
	 * Restore regs before doing iretq to kernel mode
	 */
set_sup_regs:
	cmpw	$KCS_SEL, REGOFF_CS(%rsp) /* test %cs for return to user mode */
	jne	bad_set_user_regs	/* ... (this should not be necessary) */

	/*
	 * If we interrupted the mutex_exit() critical region we must
	 * reset the PC back to the beginning to prevent missed wakeups.
	 * See the comments in mutex_exit() for details.
	 */
	movq	REGOFF_PC(%rsp), %rdx
	leaq	mutex_exit_critical_start(%rip), %r8
	subq	%r8, %rdx
	cmpq	mutex_exit_critical_size(%rip), %rdx
	jae	.mutex_exit_check_done
	movq	%r8, REGOFF_PC(%rsp)
					/* restart mutex_exit() */
.mutex_exit_check_done:
	INTR_POP
	iretq

sr_sup_preempt:
	movq	%gs:CPU_THREAD, %rbx
	cmpb	$0, T_PREEMPT_LK(%rbx)	/* Already in kpreempt? */
	jne	set_sup_regs		/* if so, get out of here */
	movb	$1, T_PREEMPT_LK(%rbx)	/* otherwise, set t_preempt_lk */

	sti				/* it's now safe to unmask interrupts */

	movl	$1, %edi		/* indicate asynchronous call */
	call	kpreempt		/* kpreempt(1) */

	cli				/* re-mask interrupts */
	movb	$0, T_PREEMPT_LK(%rbx)	/* clear t_preempt_lk */

	jmp	set_sup_regs
	SET_SIZE(sr_sup)
	SET_SIZE(lwp_rtt)
	SET_SIZE(lwp_rtt_initial)
	SET_SIZE(_sys_rtt)
	SET_SIZE(sys_rtt_syscall)
	SET_SIZE(sys_rtt_syscall32)

#elif defined(__i386)

	ENTRY_NP(lwp_rtt_initial)
	movl	%gs:CPU_THREAD, %eax
	movl	T_STACK(%eax), %esp	/* switch to the thread stack */
	call	__dtrace_probe___proc_start
	jmp	_lwp_rtt

	ENTRY_NP(lwp_rtt)
	movl	%gs:CPU_THREAD, %eax
	movl	T_STACK(%eax), %esp	/* switch to the thread stack */
_lwp_rtt:
	call	__dtrace_probe___proc_lwp__start

        /*
         * If agent lwp, clear %fs and %gs.
         */
        movl    %gs:CPU_LWP, %eax
        movl    LWP_PROCP(%eax), %edx

        cmpl    %eax, P_AGENTTP(%edx)
        jne     1f
        movl    $0, REGOFF_FS(%esp)
        movl    $0, REGOFF_GS(%esp)
1:
	call	dtrace_systrace_rtt
	movl	REGOFF_EDX(%esp), %edx
	movl	REGOFF_EAX(%esp), %eax
	pushl	%edx
	pushl	%eax
	call	post_syscall		/* post_syscall(rval1, rval2) */
	addl	$8, %esp
	movl	%cr0, %eax
	orl	$CR0_TS, %eax
	movl	%eax, %cr0		/* set up to take fault */
					/* on first use of fp */

	ALTENTRY(_sys_rtt)
	testw	$CPL_MASK, REGOFF_CS(%esp) /* test CS for return to user mode */
	jz	sr_sup

	/*
	 * Return to User.
	 */

	ALTENTRY(sys_rtt_syscall)
	/* check for an AST that's posted to the lwp */
	movl	%gs:CPU_THREAD, %eax
	cli				/* disable interrupts */
	cmpb	$0, T_ASTFLAG(%eax)	/* test for signal or AST flag */
	jne	handle_ast


	/*
	 * Restore user regs before returning to user mode.
	 */
	ALTENTRY(set_user_regs)
	INTR_POP_USER
	iret
	SET_SIZE(set_user_regs)

handle_ast:
	/* Let trap() handle the AST */
	sti				/* enable interrupts */
	movl	$T_AST, REGOFF_TRAPNO(%esp) /* set trap type to AST */
	movl	%esp, %eax
	pushl	%gs:CPU_ID
	pushl	$0
	pushl	%eax
	call	trap			/* trap(rp, 0, cpuid) */
	addl	$12, %esp
	jmp	_sys_rtt

	/*
	 * Return to supervisor
	 */
	ALTENTRY(sr_sup)

	/* Check for a kernel preemption request */
	cmpb	$0, %gs:CPU_KPRUNRUN
	jne	sr_sup_preempt		/* preemption */

	/*
	 * Restore regs before doing iret to kernel mode
	 */
set_sup_regs:
	cmpw	$KGS_SEL, REGOFF_GS(%esp) /* test GS for return to user mode */
	jne	set_user_regs		/* ... (this should not be necessary) */

	/*
	 * If we interrupted the mutex_exit() critical region we must
	 * reset the PC back to the beginning to prevent missed wakeups.
	 * See the comments in mutex_exit() for details.
	 */
	movl	REGOFF_PC(%esp), %edx
	subl	$mutex_exit_critical_start, %edx
	cmpl	mutex_exit_critical_size, %edx
	jae	.mutex_exit_check_done
	movl	$mutex_exit_critical_start, REGOFF_PC(%esp)
					/* restart mutex_exit() */
.mutex_exit_check_done:
	INTR_POP_KERNEL
	iret

sr_sup_preempt:
	movl	%gs:CPU_THREAD, %ebx
	cmpb	$0, T_PREEMPT_LK(%ebx)	/* Already in kpreempt? */
	jne	set_sup_regs		/* if so, get out of here */
	movb	$1, T_PREEMPT_LK(%ebx)	/* otherwise, set t_preempt_lk */

	sti				/* it's now safe to unmask interrupts */

	pushl	$1			/* indicate asynchronous call */
	call	kpreempt		/* kpreempt(1) */
	addl	$4, %esp

	cli				/* re-mask interrupts */
	movb	$0, T_PREEMPT_LK(%ebx)	/* clear t_preempt_lk */

	jmp	set_sup_regs
	SET_SIZE(sr_sup)
	SET_SIZE(lwp_rtt)
	SET_SIZE(lwp_rtt_initial)
	SET_SIZE(_sys_rtt)
	SET_SIZE(sys_rtt_syscall)

#endif	/* __i386 */

#endif	/* __lint */

#if defined(__lint)

/*
 * So why do we have to deal with all this crud in the world of ia32?
 *
 * Basically there are four classes of ia32 implementations, those that do not
 * have a TSC, those that have a marginal TSC that is broken to the extent
 * that it is useless, those that have a marginal TSC that is not quite so
 * horribly broken and can be used with some care, and those that have a
 * reliable TSC. This crud has to be here in order to sift through all the
 * variants.
 */

/*ARGSUSED*/
uint64_t
freq_tsc(uint32_t *pit_counter)
{
	return (0);
}

#else	/* __lint */

#if defined(__amd64)

	/*
	 * XX64 quick and dirty port from the i386 version. Since we
	 * believe the amd64 tsc is more reliable, could this code be
	 * simpler?
	 */
	ENTRY_NP(freq_tsc)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rdi, %r9	/* save pit_counter */
	pushq	%rbx

	pushfq
	cli

/ We have a TSC, but we have no way in general to know how reliable it is.
/ Usually a marginal TSC behaves appropriately unless not enough time
/ elapses between reads. A reliable TSC can be read as often and as rapidly
/ as desired. The simplistic approach of reading the TSC counter and
/ correlating to the PIT counter cannot be naively followed. Instead estimates
/ have to be taken to successively refine a guess at the speed of the cpu
/ and then the TSC and PIT counter are correlated. In practice very rarely
/ is more than one quick loop required for an estimate. Measures have to be
/ taken to prevent the PIT counter from wrapping beyond its resolution and for
/ measuring the clock rate of very fast processors.
/
/ The following constant can be tuned. It should be such that the loop does
/ not take too many nor too few PIT counts to execute. If this value is too
/ large, then on slow machines the loop will take a long time, or the PIT
/ counter may even wrap. If this value is too small, then on fast machines
/ the PIT counter may count so few ticks that the resolution of the PIT
/ itself causes a bad guess. Because this code is used in machines with
/ marginal TSC's and/or IO, if this value is too small on those, it may
/ cause the calculated cpu frequency to vary slightly from boot to boot.
/
/ In all cases even if this constant is set inappropriately, the algorithm
/ will still work and the caller should be able to handle variances in the
/ calculation of cpu frequency, but the calculation will be inefficient and
/ take a disproportionate amount of time relative to a well selected value.
/ As the slowest supported cpu becomes faster, this constant should be
/ carefully increased.

	movl	$0x8000, %ecx

	/ to make sure the instruction cache has been warmed
	clc

	jmp	freq_tsc_loop

/ The following block of code up to and including the latching of the PIT
/ counter after freq_tsc_perf_loop is very critical and very carefully
/ written, it should only be modified with great care. freq_tsc_loop to
/ freq_tsc_perf_loop fits exactly in 16 bytes as do the instructions in
/ freq_tsc_perf_loop up to the unlatching of the PIT counter.

	.align	32
freq_tsc_loop:
	/ save the loop count in %ebx
	movl	%ecx, %ebx

	/ initialize the PIT counter and start a count down
	movb	$PIT_LOADMODE, %al
	outb	$PITCTL_PORT
	movb	$0xff, %al
	outb	$PITCTR0_PORT
	outb	$PITCTR0_PORT

	/ read the TSC and store the TS in %edi:%esi
	rdtsc
	movl	%eax, %esi

freq_tsc_perf_loop:
	movl	%edx, %edi
	movl	%eax, %esi
	movl	%edx, %edi
	loop	freq_tsc_perf_loop

	/ read the TSC and store the LSW in %ecx
	rdtsc
	movl	%eax, %ecx

	/ latch the PIT counter and status
	movb	$_CONST(PIT_READBACK|PIT_READBACKC0), %al
	outb	$PITCTL_PORT

	/ remember if the icache has been warmed
	setc	%ah

	/ read the PIT status
	inb	$PITCTR0_PORT
	shll	$8, %eax

	/ read PIT count
	inb	$PITCTR0_PORT
	shll	$8, %eax
	inb	$PITCTR0_PORT
	bswap	%eax

	/ check to see if the PIT count was loaded into the CE
	btw	$_CONST(PITSTAT_NULLCNT+8), %ax
	jc	freq_tsc_increase_count

	/ check to see if PIT counter wrapped
	btw	$_CONST(PITSTAT_OUTPUT+8), %ax
	jnc	freq_tsc_pit_did_not_wrap

	/ halve count
	shrl	$1, %ebx
	movl	%ebx, %ecx

	/ the instruction cache has been warmed
	stc

	jmp	freq_tsc_loop

freq_tsc_increase_count:
	shll	$1, %ebx
	jc	freq_tsc_too_fast

	movl	%ebx, %ecx

	/ the instruction cache has been warmed
	stc

	jmp	freq_tsc_loop

freq_tsc_pit_did_not_wrap:
	roll	$16, %eax

	cmpw	$0x2000, %ax
	notw	%ax
	jb	freq_tsc_sufficient_duration

freq_tsc_calculate:
	/ in mode 0, the PIT loads the count into the CE on the first CLK pulse,
	/ then on the second CLK pulse the CE is decremented, therefore mode 0
	/ is really a (count + 1) counter, ugh
	xorl	%esi, %esi
	movw	%ax, %si
	incl	%esi

	movl	$0xf000, %eax
	mull	%ebx

	/ tuck away (target_pit_count * loop_count)
	movl	%edx, %ecx
	movl	%eax, %ebx

	movl	%esi, %eax
	movl	$0xffffffff, %edx
	mull	%edx

	addl	%esi, %eax
	adcl	$0, %edx

	cmpl	%ecx, %edx
	ja	freq_tsc_div_safe
	jb	freq_tsc_too_fast

	cmpl	%ebx, %eax
	jbe	freq_tsc_too_fast

freq_tsc_div_safe:
	movl	%ecx, %edx
	movl	%ebx, %eax

	movl	%esi, %ecx
	divl	%ecx

	movl	%eax, %ecx

	/ the instruction cache has been warmed
	stc

	jmp	freq_tsc_loop

freq_tsc_sufficient_duration:
	/ test to see if the icache has been warmed
	btl	$16, %eax
	jnc	freq_tsc_calculate

	/ recall mode 0 is a (count + 1) counter
	andl	$0xffff, %eax
	incl	%eax

	/ save the number of PIT counts
	movl	%eax, (%r9)

	/ calculate the number of TS's that elapsed
	movl	%ecx, %eax
	subl	%esi, %eax
	sbbl	%edi, %edx

	jmp	freq_tsc_end

freq_tsc_too_fast:
	/ return 0 as a 64 bit quantity
	xorl	%eax, %eax
	xorl	%edx, %edx

freq_tsc_end:
	shlq	$32, %rdx
	orq	%rdx, %rax
	/ restore state of the interrupt flag
	popfq

	popq	%rbx
	leaveq
	ret
	SET_SIZE(freq_tsc)

#elif defined(__i386)

	ENTRY_NP(freq_tsc)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx

	pushfl
	cli

/ We have a TSC, but we have no way in general to know how reliable it is.
/ Usually a marginal TSC behaves appropriately unless not enough time
/ elapses between reads. A reliable TSC can be read as often and as rapidly
/ as desired. The simplistic approach of reading the TSC counter and
/ correlating to the PIT counter cannot be naively followed. Instead estimates
/ have to be taken to successively refine a guess at the speed of the cpu
/ and then the TSC and PIT counter are correlated. In practice very rarely
/ is more than one quick loop required for an estimate. Measures have to be
/ taken to prevent the PIT counter from wrapping beyond its resolution and for
/ measuring the clock rate of very fast processors.
/
/ The following constant can be tuned. It should be such that the loop does
/ not take too many nor too few PIT counts to execute. If this value is too
/ large, then on slow machines the loop will take a long time, or the PIT
/ counter may even wrap. If this value is too small, then on fast machines
/ the PIT counter may count so few ticks that the resolution of the PIT
/ itself causes a bad guess. Because this code is used in machines with
/ marginal TSC's and/or IO, if this value is too small on those, it may
/ cause the calculated cpu frequency to vary slightly from boot to boot.
/
/ In all cases even if this constant is set inappropriately, the algorithm
/ will still work and the caller should be able to handle variances in the
/ calculation of cpu frequency, but the calculation will be inefficient and
/ take a disproportionate amount of time relative to a well selected value.
/ As the slowest supported cpu becomes faster, this constant should be
/ carefully increased.

	movl	$0x8000, %ecx

	/ to make sure the instruction cache has been warmed
	clc

	jmp	freq_tsc_loop

/ The following block of code up to and including the latching of the PIT
/ counter after freq_tsc_perf_loop is very critical and very carefully
/ written, it should only be modified with great care. freq_tsc_loop to
/ freq_tsc_perf_loop fits exactly in 16 bytes as do the instructions in
/ freq_tsc_perf_loop up to the unlatching of the PIT counter.

	.align	32
freq_tsc_loop:
	/ save the loop count in %ebx
	movl	%ecx, %ebx

	/ initialize the PIT counter and start a count down
	movb	$PIT_LOADMODE, %al
	outb	$PITCTL_PORT
	movb	$0xff, %al
	outb	$PITCTR0_PORT
	outb	$PITCTR0_PORT

	/ read the TSC and store the TS in %edi:%esi
	rdtsc
	movl	%eax, %esi

freq_tsc_perf_loop:
	movl	%edx, %edi
	movl	%eax, %esi
	movl	%edx, %edi
	loop	freq_tsc_perf_loop

	/ read the TSC and store the LSW in %ecx
	rdtsc
	movl	%eax, %ecx

	/ latch the PIT counter and status
	movb	$_CONST(PIT_READBACK|PIT_READBACKC0), %al
	outb	$PITCTL_PORT

	/ remember if the icache has been warmed
	setc	%ah

	/ read the PIT status
	inb	$PITCTR0_PORT
	shll	$8, %eax

	/ read PIT count
	inb	$PITCTR0_PORT
	shll	$8, %eax
	inb	$PITCTR0_PORT
	bswap	%eax

	/ check to see if the PIT count was loaded into the CE
	btw	$_CONST(PITSTAT_NULLCNT+8), %ax
	jc	freq_tsc_increase_count

	/ check to see if PIT counter wrapped
	btw	$_CONST(PITSTAT_OUTPUT+8), %ax
	jnc	freq_tsc_pit_did_not_wrap

	/ halve count
	shrl	$1, %ebx
	movl	%ebx, %ecx

	/ the instruction cache has been warmed
	stc

	jmp	freq_tsc_loop

freq_tsc_increase_count:
	shll	$1, %ebx
	jc	freq_tsc_too_fast

	movl	%ebx, %ecx

	/ the instruction cache has been warmed
	stc

	jmp	freq_tsc_loop

freq_tsc_pit_did_not_wrap:
	roll	$16, %eax

	cmpw	$0x2000, %ax
	notw	%ax
	jb	freq_tsc_sufficient_duration

freq_tsc_calculate:
	/ in mode 0, the PIT loads the count into the CE on the first CLK pulse,
	/ then on the second CLK pulse the CE is decremented, therefore mode 0
	/ is really a (count + 1) counter, ugh
	xorl	%esi, %esi
	movw	%ax, %si
	incl	%esi

	movl	$0xf000, %eax
	mull	%ebx

	/ tuck away (target_pit_count * loop_count)
	movl	%edx, %ecx
	movl	%eax, %ebx

	movl	%esi, %eax
	movl	$0xffffffff, %edx
	mull	%edx

	addl	%esi, %eax
	adcl	$0, %edx

	cmpl	%ecx, %edx
	ja	freq_tsc_div_safe
	jb	freq_tsc_too_fast

	cmpl	%ebx, %eax
	jbe	freq_tsc_too_fast

freq_tsc_div_safe:
	movl	%ecx, %edx
	movl	%ebx, %eax

	movl	%esi, %ecx
	divl	%ecx

	movl	%eax, %ecx

	/ the instruction cache has been warmed
	stc

	jmp	freq_tsc_loop

freq_tsc_sufficient_duration:
	/ test to see if the icache has been warmed
	btl	$16, %eax
	jnc	freq_tsc_calculate

	/ recall mode 0 is a (count + 1) counter
	andl	$0xffff, %eax
	incl	%eax

	/ save the number of PIT counts
	movl	8(%ebp), %ebx
	movl	%eax, (%ebx)

	/ calculate the number of TS's that elapsed
	movl	%ecx, %eax
	subl	%esi, %eax
	sbbl	%edi, %edx

	jmp	freq_tsc_end

freq_tsc_too_fast:
	/ return 0 as a 64 bit quantity
	xorl	%eax, %eax
	xorl	%edx, %edx

freq_tsc_end:
	/ restore state of the interrupt flag
	popfl

	popl	%ebx
	popl	%esi
	popl	%edi
	popl	%ebp

	ret
	SET_SIZE(freq_tsc)

#endif	/* __i386 */
#endif	/* __lint */

#if !defined(__amd64)
#if defined(__lint)

/*
 * We do not have a TSC so we use a block of instructions with well known
 * timings.
 */

/*ARGSUSED*/
uint64_t
freq_notsc(uint32_t *pit_counter)
{
	return (0);
}

#else	/* __lint */
	ENTRY_NP(freq_notsc)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx

	pushfl
	cli

	/ initial count for the idivl loop
	movl	$0x1000, %ecx

	/ load the divisor
	movl	$1, %ebx

	jmp	freq_notsc_loop

.align	16
freq_notsc_loop:
	/ set high 32 bits of dividend to zero
	xorl	%edx, %edx

	/ save the loop count in %edi
	movl	%ecx, %edi

	/ initialize the PIT counter and start a count down
	movb	$PIT_LOADMODE, %al
	outb	$PITCTL_PORT
	movb	$0xff, %al
	outb	$PITCTR0_PORT
	outb	$PITCTR0_PORT

	/ set low 32 bits of dividend to zero
	xorl	%eax, %eax

/ It is vital that the arguments to idivl be set appropriately because on some
/ cpu's this instruction takes more or less clock ticks depending on its
/ arguments.
freq_notsc_perf_loop:
	idivl	%ebx
	idivl	%ebx
	idivl	%ebx
	idivl	%ebx
	idivl	%ebx
	loop	freq_notsc_perf_loop

	/ latch the PIT counter and status
	movb	$_CONST(PIT_READBACK|PIT_READBACKC0), %al
	outb	$PITCTL_PORT

	/ read the PIT status
	inb	$PITCTR0_PORT
	shll	$8, %eax

	/ read PIT count
	inb	$PITCTR0_PORT
	shll	$8, %eax
	inb	$PITCTR0_PORT
	bswap	%eax

	/ check to see if the PIT count was loaded into the CE
	btw	$_CONST(PITSTAT_NULLCNT+8), %ax
	jc	freq_notsc_increase_count

	/ check to see if PIT counter wrapped
	btw	$_CONST(PITSTAT_OUTPUT+8), %ax
	jnc	freq_notsc_pit_did_not_wrap

	/ halve count
	shrl	$1, %edi
	movl	%edi, %ecx

	jmp	freq_notsc_loop

freq_notsc_increase_count:
	shll	$1, %edi
	jc	freq_notsc_too_fast

	movl	%edi, %ecx

	jmp	freq_notsc_loop

freq_notsc_pit_did_not_wrap:
	shrl	$16, %eax

	cmpw	$0x2000, %ax
	notw	%ax
	jb	freq_notsc_sufficient_duration

freq_notsc_calculate:
	/ in mode 0, the PIT loads the count into the CE on the first CLK pulse,
	/ then on the second CLK pulse the CE is decremented, therefore mode 0
	/ is really a (count + 1) counter, ugh
	xorl	%esi, %esi
	movw	%ax, %si
	incl	%esi

	movl	%edi, %eax
	movl	$0xf000, %ecx
	mull	%ecx

	/ tuck away (target_pit_count * loop_count)
	movl	%edx, %edi
	movl	%eax, %ecx

	movl	%esi, %eax
	movl	$0xffffffff, %edx
	mull	%edx

	addl	%esi, %eax
	adcl	$0, %edx

	cmpl	%edi, %edx
	ja	freq_notsc_div_safe
	jb	freq_notsc_too_fast

	cmpl	%ecx, %eax
	jbe	freq_notsc_too_fast

freq_notsc_div_safe:
	movl	%edi, %edx
	movl	%ecx, %eax

	movl	%esi, %ecx
	divl	%ecx

	movl	%eax, %ecx

	jmp	freq_notsc_loop

freq_notsc_sufficient_duration:
	/ recall mode 0 is a (count + 1) counter
	incl	%eax

	/ save the number of PIT counts
	movl	8(%ebp), %ebx
	movl	%eax, (%ebx)

	/ calculate the number of cpu clock ticks that elapsed
	cmpl	$X86_VENDOR_Cyrix, x86_vendor
	jz	freq_notsc_notcyrix

	/ freq_notsc_perf_loop takes 86 clock cycles on Cyrix 6x86 cores
	movl	$86, %eax
	jmp	freq_notsc_calculate_tsc

freq_notsc_notcyrix:
	/ freq_notsc_perf_loop takes 237 clock cycles on Intel Pentiums
	movl	$237, %eax

freq_notsc_calculate_tsc:
	mull	%edi

	jmp	freq_notsc_end

freq_notsc_too_fast:
	/ return 0 as a 64 bit quantity
	xorl	%eax, %eax
	xorl	%edx, %edx

freq_notsc_end:
	/ restore state of the interrupt flag
	popfl

	popl	%ebx
	popl	%esi
	popl	%edi
	popl	%ebp

	ret
	SET_SIZE(freq_notsc)

	/
	/ setup_121_andcall(funcp, argument)
	/
	/ invokes funcp(argument) after having setup one to one mapping
	/ for the virtual address funcp to its physical address.
	/ This function cannot be invoked with PAE enabled, this could
	/ be used to enable PAE
	/
	ENTRY_NP(setup_121_andcall)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	movl	8(%ebp), %ecx		/ funcp
	movl	%ecx, %edx
	shrl	$MMU_STD_PAGESHIFT, %ecx
	andl	$MMU_L2_MASK, %ecx	/ pagetable index
	movl	%cr3, %eax
	andl	$MMU_STD_PAGEMASK, %eax	/ pagedirectory pointer
	pushl	%eax
	shrl	$MMU_STD_PAGESHIFT+NPTESHIFT, %edx
	movl	(%eax, %edx, 4), %eax	/ funcp's pagetable
	testl	$PTE_LARGEPAGE, %eax
	je	not_a_large_page
	shrl	$MMU_STD_PAGESHIFT, %eax
	addl	%eax, %ecx
	movl	%ecx, %edx
	shll	$MMU_STD_PAGESHIFT, %edx
	orl	$_CONST(PTE_SRWX|PTE_VALID), %edx
	jmp	got_pfn

not_a_large_page:
	andl	$MMU_STD_PAGEMASK, %eax		/ ignore ref and other bits
	movl	(%eax, %ecx, 4), %ecx	/ pte entry
	movl	%ecx, %edx
	shrl	$MMU_STD_PAGESHIFT, %ecx /pfnum of funcp
got_pfn:
	movl	%ecx, %ebx
	andl	$MMU_L2_MASK, %ecx
	shrl	$NPTESHIFT, %ebx
	movl	0(%esp), %eax
	leal	(%eax, %ebx, 4), %eax 	/ new pde entry  for the function
	pushl	%eax
	movl	(%eax), %eax
	testl	$PTE_VALID, %eax		/ is the pde entry valid
	jne	pagetable_isvalid
	movl	$one2one_pagetable, %ebx
	addl	$MMU_STD_PAGESIZE, %ebx	/ move to next 4k
	shrl	$MMU_STD_PAGESHIFT+NPTESHIFT, %ebx
	movl	4(%esp), %eax
	movl	(%eax, %ebx, 4), %eax
	testl	$PTE_LARGEPAGE, %eax
	je	not_a_large_page1
	shrl	$MMU_STD_PAGESHIFT, %eax
	movl	$one2one_pagetable, %ebx
	addl	$MMU_STD_PAGESIZE, %ebx	/ move to next 4k
	shrl	$MMU_STD_PAGESHIFT, %ebx
	andl	$MMU_L2_MASK, %ebx
	addl	%ebx, %eax
	shll	$MMU_STD_PAGESHIFT, %eax
	orl	$_CONST(PTE_SRWX|PTE_VALID), %eax
	jmp	got_pfn1
not_a_large_page1:
	andl	$MMU_STD_PAGEMASK, %eax		/ ignore ref and other bits
	movl	$one2one_pagetable, %ebx
	addl	$MMU_STD_PAGESIZE, %ebx	/ move to next 4k
	shrl	$MMU_STD_PAGESHIFT, %ebx
	andl	$MMU_L2_MASK, %ebx
	movl	(%eax, %ebx, 4), %eax	/ pte entry for one2one_pagetable
got_pfn1:
	movl	0(%esp), %ebx
	movl	%eax, (%ebx)		/ point pde entry at one2one_pagetable
	movl	$one2one_pagetable, %eax / load pagetable ptr
	addl	$MMU_STD_PAGESIZE, %eax		/ 4K aligned virtual address
	andl	$MMU_STD_PAGEMASK, %eax
	movl	$0, 4(%esp)		/ previous pde is invalid
	jmp	pagetable_madevalid
pagetable_isvalid:
	movl	%eax, 4(%esp)		/ save pde
pagetable_madevalid:
	andl	$MMU_STD_PAGEMASK, %eax	/ ignore lower 12 bits

	pushl	(%eax, %ecx, 4)		/ save the old pagetable entry that
					/ belongs to boot

	movl	%edx, (%eax, %ecx, 4)	/ We now have a 1-1 mapping for the
					/ function funcp
	leal	(%eax, %ecx, 4), %eax
	pushl	%eax			/ save the address of pagetable entry
					/ we patched above

	movl	8(%ebp), %eax		/ funcp
	andl	$MMU_PAGEOFFSET, %eax		/ pick the 4k offset
	andl	$MMU_STD_PAGEMASK, %edx
	addl	%edx, %eax
	movl	12(%ebp), %ebx		/ argument
	movl	%cr3, %ecx
	movl	%ecx, %cr3
	call	*%eax			/ jump to funcp(%eax)
					/ we have 1-1 mapping
					/ for this particular page, ret address
					/ still points to space in 0xe00xxxxx

	testl	 %eax, %eax
	jne	cr3_changed
	popl	%eax			/ pop the pagetable entry address
	popl	%ecx			/ pop the pagetable entry
	movl	%ecx, (%eax)		/ restore the pte that we destroyed
	popl	%eax			/ pop the pagedirectory address
	popl	%ecx			/ pop pde
	movl	%ecx, (%eax)		/ restore pde
	movl	%cr3, %eax
	movl	%eax, %cr3
	popl	%ebx
	popl	%ebp
	ret
cr3_changed:
	addl	$16, %esp		/ we had saved 4 arguments
	popl	%ebx
	popl	%ebp
	ret
	SET_SIZE(setup_121_andcall)

#endif	/* __lint */
#endif	/* !__amd64 */

#if !defined(__lint)
	.data
#if !defined(__amd64)
	.align	4
cpu_vendor:
	.long	0, 0, 0		/* Vendor ID string returned */

	.globl	CyrixInstead

	.globl	x86_feature
	.globl	x86_type
	.globl	x86_vendor
#endif
	.globl	cr4_value

	/*
	 * pagetable that would allow a one to one mapping of the
	 * first 4K of kernel text.
	 * we allocate 8K so that we have a 4K pagetable aligned
	 * across 4K boundary
	 */
	.comm	one2one_pagetable, 8192

#endif	/* __lint */
