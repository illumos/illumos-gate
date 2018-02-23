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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 *
 * Copyright 2018 Joyent, Inc.
 */
	
#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/x86_archext.h>

#if !defined(__lint)
#include <sys/segments.h>
#include "assym.h"
#endif

/*
 *	Our assumptions:
 *		- We are running in real mode.
 *		- Interrupts are disabled.
 *		- Selectors are equal (cs == ds == ss) for all real mode code
 *		- The GDT, IDT, ktss and page directory has been built for us
 *
 *	Our actions:
 *	Start CPU:
 *		- We start using our GDT by loading correct values in the
 *		  selector registers (cs=KCS_SEL, ds=es=ss=KDS_SEL, fs=KFS_SEL,
 *		  gs=KGS_SEL).
 *		- We change over to using our IDT.
 *		- We load the default LDT into the hardware LDT register.
 *		- We load the default TSS into the hardware task register.
 *		- call mp_startup(void) indirectly through the T_PC
 *	Stop CPU:
 *		- Put CPU into halted state with interrupts disabled
 *
 */

#if defined(__lint)

void
real_mode_start_cpu(void)
{}

void
real_mode_stop_cpu_stage1(void)
{}

void
real_mode_stop_cpu_stage2(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(real_mode_start_cpu)

	/*
	 * NOTE:  The GNU assembler automatically does the right thing to
	 *	  generate data size operand prefixes based on the code size
	 *	  generation mode (e.g. .code16, .code32, .code64) and as such
	 *	  prefixes need not be used on instructions EXCEPT in the case
	 *	  of address prefixes for code for which the reference is not
	 *	  automatically of the default operand size.
	 */      
	.code16
	cli
	movw		%cs, %ax
	movw		%ax, %ds	/* load cs into ds */
	movw		%ax, %ss	/* and into ss */

	/*
	 * Helps in debugging by giving us the fault address.
	 *
	 * Remember to patch a hlt (0xf4) at cmntrap to get a good stack.
	 */
	movl		$0xffc, %esp
	movl		%cr0, %eax

	/*
	 * Enable protected-mode, write protect, and alignment mask
	 */
	orl		$(CR0_PE|CR0_WP|CR0_AM), %eax
	movl		%eax, %cr0

	/*
	 * Do a jmp immediately after writing to cr0 when enabling protected
	 * mode to clear the real mode prefetch queue (per Intel's docs)
	 */
	jmp		pestart

pestart:
	/*
 	 * 16-bit protected mode is now active, so prepare to turn on long
	 * mode.
	 *
	 * Note that we currently assume that if we're attempting to run a
	 * kernel compiled with (__amd64) #defined, the target CPU has long
	 * mode support.
	 */

#if 0
	/*
	 * If there's a chance this might not be true, the following test should
	 * be done, with the no_long_mode branch then doing something
	 * appropriate:
	 */

	movl		$0x80000000, %eax	/* get largest extended CPUID */
	cpuid
	cmpl		$0x80000000, %eax	/* check if > 0x80000000 */
	jbe		no_long_mode		/* nope, no long mode */
	movl		$0x80000001, %eax	
	cpuid					/* get extended feature flags */
	btl		$29, %edx		/* check for long mode */
	jnc		no_long_mode		/* long mode not supported */
#endif

	/*
 	 * Add any initial cr4 bits
	 */
	movl		%cr4, %eax
	addr32 orl	CR4OFF, %eax

	/*
	 * Enable PAE mode (CR4.PAE)
	 */
	orl		$CR4_PAE, %eax
	movl		%eax, %cr4

	/*
	 * Point cr3 to the 64-bit long mode page tables.
	 *
	 * Note that these MUST exist in 32-bit space, as we don't have
	 * a way to load %cr3 with a 64-bit base address for the page tables
	 * until the CPU is actually executing in 64-bit long mode.
	 */
	addr32 movl	CR3OFF, %eax
	movl		%eax, %cr3

	/*
	 * Set long mode enable in EFER (EFER.LME = 1)
	 */
	movl	$MSR_AMD_EFER, %ecx
	rdmsr
	orl	$AMD_EFER_LME, %eax
	wrmsr

	/*
	 * Finally, turn on paging (CR0.PG = 1) to activate long mode.
	 */
	movl	%cr0, %eax
	orl	$CR0_PG, %eax
	movl	%eax, %cr0

	/*
	 * The instruction after enabling paging in CR0 MUST be a branch.
	 */
	jmp	long_mode_active

long_mode_active:
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
	addr32 lgdtl	TEMPGDTOFF	/* load temporary GDT */
	addr32 lidtl	TEMPIDTOFF	/* load temporary IDT */

	/*
 	 * Do a far transfer to 64-bit mode.  Set the CS selector to a 64-bit
	 * long mode selector (CS.L=1) in the temporary 32-bit GDT and jump
	 * to the real mode platter address of long_mode 64 as until the 64-bit
	 * CS is in place we don't have access to 64-bit instructions and thus
	 * can't reference a 64-bit %rip.
	 */
	pushl 		$TEMP_CS64_SEL
	addr32 pushl	LM64OFF
	lretl

	.globl	long_mode_64
long_mode_64:
	.code64
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
	movl	CPUNOFF(%rax), %r11d

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
	pushq	$KCS_SEL
	pushq	$kernel_cs_code
	lretq
	.globl real_mode_start_cpu_end
real_mode_start_cpu_end:
	nop

kernel_cs_code:
	/*
	 * Complete the balance of the setup we need to before executing
	 * 64-bit kernel code (namely init rsp, TSS, LGDT, FS and GS).
	 */
	.globl	rm_platter_va
	movq	rm_platter_va, %rax
	lidtq	IDTROFF(%rax)

	movw	$KDS_SEL, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss

	movw	$KTSS_SEL, %ax		/* setup kernel TSS */
	ltr	%ax

	xorw	%ax, %ax		/* clear LDTR */
	lldt	%ax

	/*
	 * Set GS to the address of the per-cpu structure as contained in
	 * cpu[cpu_number].
	 *
	 * Unfortunately there's no way to set the 64-bit gsbase with a mov,
	 * so we have to stuff the low 32 bits in %eax and the high 32 bits in
	 * %edx, then call wrmsr.
	 */
	leaq	cpu(%rip), %rdi
	movl	(%rdi, %r11, 8), %eax
	movl	4(%rdi, %r11, 8), %edx
	movl	$MSR_AMD_GSBASE, %ecx
	wrmsr

	/*
	 * Init FS and KernelGSBase.
	 *
	 * Based on code in mlsetup(), set them both to 8G (which shouldn't be
	 * valid until some 64-bit processes run); this will then cause an
	 * exception in any code that tries to index off them before they are
	 * properly setup.
	 */
	xorl	%eax, %eax		/* low 32 bits = 0 */
	movl	$2, %edx		/* high 32 bits = 2 */
	movl	$MSR_AMD_FSBASE, %ecx
	wrmsr

	movl	$MSR_AMD_KGSBASE, %ecx
	wrmsr

	/*
	 * Init %rsp to the exception stack set in tss_ist1 and create a legal
	 * AMD64 ABI stack frame
	 */
	movq	%gs:CPU_TSS, %rax
	movq	TSS_IST1(%rax), %rsp
	pushq	$0		/* null return address */
	pushq	$0		/* null frame pointer terminates stack trace */
	movq	%rsp, %rbp	/* stack aligned on 16-byte boundary */

	movq	%cr0, %rax
	andq    $~(CR0_TS|CR0_EM), %rax	/* clear emulate math chip bit */
	orq     $(CR0_MP|CR0_NE), %rax
	movq    %rax, %cr0		/* set machine status word */

	/*
	 * Before going any further, enable usage of page table NX bit if 
	 * that's how our page tables are set up.
	 */
	bt	$X86FSET_NX, x86_featureset(%rip)
	jnc	1f
	movl	$MSR_AMD_EFER, %ecx
	rdmsr
	orl	$AMD_EFER_NXE, %eax
	wrmsr
1:

	/*
	 * Complete the rest of the setup and call mp_startup().
	 */
	movq	%gs:CPU_THREAD, %rax	/* get thread ptr */
	call	*T_PC(%rax)		/* call mp_startup_boot */
	/* not reached */
	int	$20			/* whoops, returned somehow! */

	SET_SIZE(real_mode_start_cpu)

#elif defined(__i386)

	ENTRY_NP(real_mode_start_cpu)

#if !defined(__GNUC_AS__)

	cli
	D16 movw	%cs, %eax
	movw		%eax, %ds	/* load cs into ds */
	movw		%eax, %ss	/* and into ss */

	/*
	 * Helps in debugging by giving us the fault address.
	 *
	 * Remember to patch a hlt (0xf4) at cmntrap to get a good stack.
	 */
	D16 movl	$0xffc, %esp

 	D16 A16 lgdt	%cs:GDTROFF
 	D16 A16 lidt	%cs:IDTROFF
	D16 A16 movl	%cs:CR4OFF, %eax	/* set up CR4, if desired */
	D16 andl	%eax, %eax
	D16 A16 je	no_cr4

	D16 movl	%eax, %ecx
	D16 movl	%cr4, %eax
	D16 orl		%ecx, %eax
	D16 movl	%eax, %cr4
no_cr4:
	D16 A16 movl	%cs:CR3OFF, %eax
	A16 movl	%eax, %cr3
	movl		%cr0, %eax

	/*
	 * Enable protected-mode, paging, write protect, and alignment mask
	 */
	D16 orl		$[CR0_PG|CR0_PE|CR0_WP|CR0_AM], %eax
	movl		%eax, %cr0
	jmp		pestart

pestart:
	D16 pushl	$KCS_SEL
	D16 pushl	$kernel_cs_code
	D16 lret
	.globl real_mode_start_cpu_end
real_mode_start_cpu_end:
	nop

	.globl	kernel_cs_code
kernel_cs_code:
	/*
	 * At this point we are with kernel's cs and proper eip.
	 *
	 * We will be executing not from the copy in real mode platter,
	 * but from the original code where boot loaded us.
	 *
	 * By this time GDT and IDT are loaded as is cr3.
	 */
	movw	$KFS_SEL,%eax
	movw	%eax,%fs
	movw	$KGS_SEL,%eax
	movw	%eax,%gs
	movw	$KDS_SEL,%eax
	movw	%eax,%ds
	movw	%eax,%es
	movl	%gs:CPU_TSS,%esi
	movw	%eax,%ss
	movl	TSS_ESP0(%esi),%esp
	movw	$KTSS_SEL,%ax
	ltr	%ax
	xorw	%ax, %ax		/* clear LDTR */
	lldt	%ax
	movl	%cr0,%edx
	andl    $-1![CR0_TS|CR0_EM],%edx  /* clear emulate math chip bit */
	orl     $[CR0_MP|CR0_NE],%edx
	movl    %edx,%cr0		  /* set machine status word */

	/*
	 * Before going any further, enable usage of page table NX bit if 
	 * that's how our page tables are set up.
	 */
	bt	$X86FSET_NX, x86_featureset
	jnc	1f
	movl	%cr4, %ecx
	andl	$CR4_PAE, %ecx
	jz	1f
	movl	$MSR_AMD_EFER, %ecx
	rdmsr
	orl	$AMD_EFER_NXE, %eax
	wrmsr
1:
	movl	%gs:CPU_THREAD, %eax	/* get thread ptr */
	call	*T_PC(%eax)		/* call mp_startup */
	/* not reached */
	int	$20			/* whoops, returned somehow! */

#else

	cli
	mov		%cs, %ax
	mov		%eax, %ds	/* load cs into ds */
	mov		%eax, %ss	/* and into ss */

	/*
	 * Helps in debugging by giving us the fault address.
	 *
	 * Remember to patch a hlt (0xf4) at cmntrap to get a good stack.
	 */
	D16 mov		$0xffc, %esp

	D16 A16 lgdtl	%cs:GDTROFF
	D16 A16 lidtl	%cs:IDTROFF
	D16 A16 mov	%cs:CR4OFF, %eax	/* set up CR4, if desired */
	D16 and		%eax, %eax
	D16 A16 je	no_cr4

	D16 mov		%eax, %ecx
	D16 mov		%cr4, %eax
	D16 or		%ecx, %eax
	D16 mov		%eax, %cr4
no_cr4:
	D16 A16 mov	%cs:CR3OFF, %eax
	A16 mov		%eax, %cr3
	mov		%cr0, %eax

	/*
	 * Enable protected-mode, paging, write protect, and alignment mask
	 */
	D16 or		$(CR0_PG|CR0_PE|CR0_WP|CR0_AM), %eax
	mov		%eax, %cr0
	jmp		pestart

pestart:
	D16 pushl	$KCS_SEL
	D16 pushl	$kernel_cs_code
	D16 lret
	.globl real_mode_start_cpu_end
real_mode_start_cpu_end:
	nop
	.globl	kernel_cs_code
kernel_cs_code:
	/*
	 * At this point we are with kernel's cs and proper eip.
	 *
	 * We will be executing not from the copy in real mode platter,
	 * but from the original code where boot loaded us.
	 *
	 * By this time GDT and IDT are loaded as is cr3.
	 */
	mov	$KFS_SEL, %ax
	mov	%eax, %fs
	mov	$KGS_SEL, %ax
	mov	%eax, %gs
	mov	$KDS_SEL, %ax
	mov	%eax, %ds
	mov	%eax, %es
	mov	%gs:CPU_TSS, %esi
	mov	%eax, %ss
	mov	TSS_ESP0(%esi), %esp
	mov	$(KTSS_SEL), %ax
	ltr	%ax
	xorw	%ax, %ax		/* clear LDTR */
	lldt	%ax
	mov	%cr0, %edx
	and	$~(CR0_TS|CR0_EM), %edx	/* clear emulate math chip bit */
	or	$(CR0_MP|CR0_NE), %edx
	mov	%edx, %cr0		/* set machine status word */

	/*
	 * Before going any farther, enable usage of page table NX bit if 
	 * that's how our page tables are set up.  (PCIDE is enabled later on).
	 */
	bt	$X86FSET_NX, x86_featureset
	jnc	1f
	movl	%cr4, %ecx
	andl	$CR4_PAE, %ecx
	jz	1f
	movl	$MSR_AMD_EFER, %ecx
	rdmsr
	orl	$AMD_EFER_NXE, %eax
	wrmsr
1:
	mov	%gs:CPU_THREAD, %eax	/* get thread ptr */
	call	*T_PC(%eax)		/* call mp_startup */
	/* not reached */
	int	$20			/* whoops, returned somehow! */
#endif

	SET_SIZE(real_mode_start_cpu)

#endif	/* __amd64 */

#if defined(__amd64)

	ENTRY_NP(real_mode_stop_cpu_stage1)

#if !defined(__GNUC_AS__)

	/*
	 * For vulcan as we need to do a .code32 and mentally invert the
	 * meaning of the addr16 and data16 prefixes to get 32-bit access when
	 * generating code to be executed in 16-bit mode (sigh...)
	 */
	.code32
	cli
	movw		%cs, %ax
	movw		%ax, %ds	/* load cs into ds */
	movw		%ax, %ss	/* and into ss */

	/*
	 * Jump to the stage 2 code in the rm_platter_va->rm_cpu_halt_code
	 */
	movw		$CPUHALTCODEOFF, %ax
	.byte		0xff, 0xe0	/* jmp *%ax */

#else	/* __GNUC_AS__ */

	/*
	 * NOTE:  The GNU assembler automatically does the right thing to
	 *	  generate data size operand prefixes based on the code size
	 *	  generation mode (e.g. .code16, .code32, .code64) and as such
	 *	  prefixes need not be used on instructions EXCEPT in the case
	 *	  of address prefixes for code for which the reference is not
	 *	  automatically of the default operand size.
	 */      
	.code16
	cli
	movw		%cs, %ax
	movw		%ax, %ds	/* load cs into ds */
	movw		%ax, %ss	/* and into ss */

	/*
	 * Jump to the stage 2 code in the rm_platter_va->rm_cpu_halt_code
	 */
	movw		$CPUHALTCODEOFF, %ax
	jmp		*%ax

#endif	/* !__GNUC_AS__ */

	.globl real_mode_stop_cpu_stage1_end
real_mode_stop_cpu_stage1_end:
	nop

	SET_SIZE(real_mode_stop_cpu_stage1)

#elif defined(__i386)

	ENTRY_NP(real_mode_stop_cpu_stage1)

#if !defined(__GNUC_AS__)

	cli
	D16 movw	%cs, %eax
	movw		%eax, %ds	/* load cs into ds */
	movw		%eax, %ss	/* and into ss */

	/*
	 * Jump to the stage 2 code in the rm_platter_va->rm_cpu_halt_code
	 */
	movw		$CPUHALTCODEOFF, %ax
	.byte		0xff, 0xe0	/* jmp *%ax */

#else	/* __GNUC_AS__ */

	cli
	mov		%cs, %ax
	mov		%eax, %ds	/* load cs into ds */
	mov		%eax, %ss	/* and into ss */

	/*
	 * Jump to the stage 2 code in the rm_platter_va->rm_cpu_halt_code
	 */
	movw		$CPUHALTCODEOFF, %ax
	jmp		*%ax

#endif	/* !__GNUC_AS__ */

	.globl real_mode_stop_cpu_stage1_end
real_mode_stop_cpu_stage1_end:
	nop

	SET_SIZE(real_mode_stop_cpu_stage1)

#endif	/* __amd64 */

	ENTRY_NP(real_mode_stop_cpu_stage2)

	movw		$0xdead, %ax
	movw		%ax, CPUHALTEDOFF

real_mode_stop_cpu_loop:
	/*
	 * Put CPU into halted state.
	 * Only INIT, SMI, NMI could break the loop.
	 */
	hlt
	jmp		real_mode_stop_cpu_loop

	.globl real_mode_stop_cpu_stage2_end
real_mode_stop_cpu_stage2_end:
	nop

	SET_SIZE(real_mode_stop_cpu_stage2)

#endif	/* __lint */
