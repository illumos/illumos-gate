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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Debugger entry for both master and slave CPUs
 */

#if defined(__lint)
#include <sys/types.h>
#endif

#include <sys/segments.h>
#include <sys/asm_linkage.h>
#include <sys/controlregs.h>
#include <sys/x86_archext.h>

#include <mdb/mdb_kreg.h>
#include <kmdb/kaif.h>
#include <kmdb/kaif_asmutil.h>
#include <kmdb/kaif_regs.h>
#include <kmdb/kaif_off.h>
#include <kmdb/kmdb_dpi_isadep.h>

#if !defined(__lint)

	/* XXX implement me */
	ENTRY_NP(kaif_nmiint)
	clrq	%rcx
	movq	(%rcx), %rcx
	SET_SIZE(kaif_nmiint)

	ENTRY_NP(kaif_save_common_state)

	/*
	 * The state of the world:
	 *
	 * The stack has a complete set of saved registers and segment
	 * selectors, arranged in the order given in mdb_kreg.h.  It also has a
	 * pointer to our cpusave area.
	 *
	 * We need to save, into the cpusave area, a pointer to these saved
	 * registers.  After that, we save a few more registers, ready the
	 * machine for debugger entry, and enter the debugger.
	 */

	popq	%rax			/* the cpusave area */
	movq	%rsp, KRS_GREGS(%rax)	/* save ptr to current saved regs */

	SAVE_IDTGDT

	/* Save off %cr0, and clear write protect */
	movq	%cr0, %rcx
	movq	%rcx, KRS_CR0(%rax)
	andq	$_BITNOT(CR0_WP), %rcx
	movq	%rcx, %cr0

	/* Save the debug registers and disable any active watchpoints */
	movq	%dr7, %rcx
	movq	%rcx, KRS_DRCTL(%rax)
	andq	$_BITNOT(KREG_DRCTL_WPALLEN_MASK), %rcx
	movq	%rcx, %dr7

	movq	%dr6, %rcx
	movq	%rcx, KRS_DRSTAT(%rax)

	movq	%dr0, %rcx
	movq	%rcx, KRS_DROFF(0)(%rax)
	movq	%dr1, %rcx
	movq	%rcx, KRS_DROFF(1)(%rax)
	movq	%dr2, %rcx
	movq	%rcx, KRS_DROFF(2)(%rax)
	movq	%dr3, %rcx
	movq	%rcx, KRS_DROFF(3)(%rax)

	/*
	 * Save any requested MSRs.
	 */
	movq	KRS_MSR(%rax), %rcx
	cmpq	$0, %rcx
	je	no_msr

	pushq	%rax		/* rdmsr clobbers %eax */
	movq	%rcx, %rbx

1:
	movl	MSR_NUM(%rbx), %ecx
	cmpl	$0, %ecx
	je	msr_done

	movl	MSR_TYPE(%rbx), %edx
	cmpl	$KMDB_MSR_READ, %edx
	jne	msr_next

	rdmsr			/* addr in %ecx, value into %edx:%eax */
	movl	%eax, MSR_VAL(%rbx)
	movl	%edx, _CONST(MSR_VAL + 4)(%rbx)

msr_next:
	addq	$MSR_SIZE, %rbx
	jmp	1b

msr_done:
	popq	%rax

no_msr:
	clrq	%rbp		/* stack traces should end here */

	pushq	%rax
	movq	%rax, %rdi	/* cpusave */

	call	kaif_debugger_entry

	/* Pass cpusave and debugger return code for "call" to resume */
	popq	%rdi
	movq	%rax, %rsi

	jmp	kaif_resume

	SET_SIZE(kaif_save_common_state)

#endif	/* !__lint */

/*
 * The main entry point for master CPUs.  It also serves as the trap handler
 * for all traps and interrupts taken during single-step.
 */
#if defined(__lint)
void
kaif_cmnint(void)
{
}
#else	/* __lint */

	ENTRY_NP(kaif_cmnint)
	ALTENTRY(kaif_master_entry)

	cli

	/* Save current register state */
	subq	$REG_OFF(KREG_TRAPNO), %rsp
	KAIF_SAVE_REGS(%rsp)

	/*
	 * Switch to the kernel's GSBASE.  Neither GSBASE nor the ill-named
	 * KGSBASE can be trusted, as the kernel may or may not have already
	 * done a swapgs.  All is not lost, as the kernel can divine the correct
	 * value for us.
	 */
	movq	mdb+MDB_KDI, %rax
	movq	MKDI_GDT2GSBASE(%rax), %rax
	subq	$10, %rsp
	sgdt	(%rsp)
	movq	2(%rsp), %rdi	/* gdt base now in %rdi */
	addq	$10, %rsp
	call	*%rax		/* returns kernel's GSBASE in %rax */

	movq	%rax, %rdx
	shrq	$32, %rdx
	movl	$MSR_AMD_GSBASE, %ecx
	wrmsr

	GET_CPUSAVE_ADDR	/* %rax = cpusave, %rbx = CPU ID */

	ADVANCE_CRUMB_POINTER(%rax, %rcx, %rdx)

	ADD_CRUMB(%rax, KRM_CPU_STATE, $KAIF_CPU_STATE_MASTER, %rdx)

	movq	REG_OFF(KREG_RIP)(%rsp), %rcx
	ADD_CRUMB(%rax, KRM_PC, %rcx, %rdx)
	ADD_CRUMB(%rax, KRM_SP, %rsp, %rdx)
	movq	REG_OFF(KREG_TRAPNO)(%rsp), %rcx
	ADD_CRUMB(%rax, KRM_TRAPNO, %rcx, %rdx)

	movq	%rsp, %rbp
	pushq	%rax

	/*
	 * Were we in the debugger when we took the trap (i.e. was %esp in one
	 * of the debugger's memory ranges)?
	 */
	leaq	kaif_memranges, %rcx
	movl	kaif_nmemranges, %edx
1:	cmpq	MR_BASE(%rcx), %rsp
	jl	2f		/* below this range -- try the next one */
	cmpq	MR_LIM(%rcx), %rsp
	jg	2f		/* above this range -- try the next one */
	jmp	3f		/* matched within this range */

2:	decl	%edx
	jz	kaif_save_common_state	/* %rsp not within debugger memory */
	addq	$MR_SIZE, %rcx
	jmp	1b

3:	/*
	 * The master is still set.  That should only happen if we hit a trap
	 * while running in the debugger.  Note that it may be an intentional
	 * fault.  kmdb_dpi_handle_fault will sort it all out.
	 */

	movq	REG_OFF(KREG_TRAPNO)(%rbp), %rdi
	movq	REG_OFF(KREG_RIP)(%rbp), %rsi
	movq	REG_OFF(KREG_RSP)(%rbp), %rdx
	movq	%rbx, %rcx		/* cpuid */

	call	kmdb_dpi_handle_fault

	/*
	 * If we're here, we ran into a debugger problem, and the user
	 * elected to solve it by having the debugger debug itself.  The
	 * state we're about to save is that of the debugger when it took
	 * the fault.
	 */

	jmp	kaif_save_common_state

	SET_SIZE(kaif_master_entry)
	SET_SIZE(kaif_cmnint)

#endif	/* __lint */

/*
 * The cross-call handler for slave CPUs.
 *
 * The debugger is single-threaded, so only one CPU, called the master, may be
 * running it at any given time.  The other CPUs, known as slaves, spin in a
 * busy loop until there's something for them to do.  This is the entry point
 * for the slaves - they'll be sent here in response to a cross-call sent by the
 * master.
 */

#if defined(__lint)
char kaif_slave_entry_patch;

void
kaif_slave_entry(void)
{
}
#else /* __lint */
	.globl	kaif_slave_entry_patch;

	ENTRY_NP(kaif_slave_entry)

	/* kaif_msr_add_clrentry knows where this is */
kaif_slave_entry_patch:
	KAIF_MSR_PATCH;

	/*
	 * Cross calls are implemented as function calls, so our stack currently
	 * looks like one you'd get from a zero-argument function call.  That
	 * is, there's the return %rip at %rsp, and that's about it.  We need
	 * to make it look like an interrupt stack.  When we first save, we'll
	 * reverse the saved %ss and %rip, which we'll fix back up when we've
	 * freed up some general-purpose registers.  We'll also need to fix up
	 * the saved %rsp.
	 */

	pushq	%rsp		/* pushed value off by 8 */
	pushfq
	cli
	clrq	%rax
	movw	%cs, %ax
	pushq	%rax
	movw	%ss, %ax
	pushq	%rax		/* rip should be here */
	pushq	$-1		/* phony trap error code */
	pushq	$-1		/* phony trap number */

	subq	$REG_OFF(KREG_TRAPNO), %rsp
	KAIF_SAVE_REGS(%rsp)

	movq	REG_OFF(KREG_SS)(%rsp), %rax
	xchgq	REG_OFF(KREG_RIP)(%rsp), %rax
	movq	%rax, REG_OFF(KREG_SS)(%rsp)

	movq	REG_OFF(KREG_RSP)(%rsp), %rax
	addq	$8, %rax
	movq	%rax, REG_OFF(KREG_RSP)(%rsp)

	/* 
	 * We've saved all of the general-purpose registers, and have a stack
	 * that is irettable (after we strip down to the error code)
	 */

	GET_CPUSAVE_ADDR	/* %rax = cpusave, %rbx = CPU ID */

	ADVANCE_CRUMB_POINTER(%rax, %rcx, %rdx)

	ADD_CRUMB(%rax, KRM_CPU_STATE, $KAIF_CPU_STATE_SLAVE, %rdx)

	movq	REG_OFF(KREG_RIP)(%rsp), %rcx
	ADD_CRUMB(%rax, KRM_PC, %rcx, %rdx)

	pushq	%rax
	jmp	kaif_save_common_state

	SET_SIZE(kaif_slave_entry)

#endif	/* __lint */
