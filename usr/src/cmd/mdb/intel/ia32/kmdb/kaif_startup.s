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
	clr	%ecx
	movl	(%ecx), %ecx
	SET_SIZE(kaif_nmiint)

	ENTRY_NP(kaif_save_common_state)

	/*
	 * The state of the world:
	 *
	 * The stack has a complete set of saved registers and segment
	 * selectors, arranged in `struct regs' order (or vice-versa), up to
	 * and including EFLAGS.  It also has a pointer to our cpusave area.
	 *
	 * We need to save a pointer to these saved registers.  We also want
	 * to adjust the saved %esp - it should point just beyond the saved
	 * registers to the last frame of the thread we interrupted.  Finally,
	 * we want to clear out bits 16-31 of the saved selectors, as the
	 * selector pushls don't automatically clear them.
	 */
	popl	%eax			/* the cpusave area */

	movl	%esp, KRS_GREGS(%eax)	/* save ptr to current saved regs */

	SAVE_IDTGDT

	addl	$REG_OFF(KREG_EFLAGS - KREG_EAX), KREG_OFF(KREG_ESP)(%esp)

	andl	$0xffff, KREG_OFF(KREG_SS)(%esp)
	andl	$0xffff, KREG_OFF(KREG_GS)(%esp)
	andl	$0xffff, KREG_OFF(KREG_FS)(%esp)
	andl	$0xffff, KREG_OFF(KREG_ES)(%esp)
	andl	$0xffff, KREG_OFF(KREG_DS)(%esp)

	/* Save off %cr0, and clear write protect */
	movl	%cr0, %ecx
	movl	%ecx, KRS_CR0(%eax)
	andl	$_BITNOT(CR0_WP), %ecx
	movl	%ecx, %cr0

	/* Save the debug registers and disable any active watchpoints */
	movl	%dr7, %ecx
	movl	%ecx, KRS_DRCTL(%eax)
	andl	$_BITNOT(KREG_DRCTL_WPALLEN_MASK), %ecx
	movl	%ecx, %dr7

	movl	%dr6, %ecx
	movl	%ecx, KRS_DRSTAT(%eax)

	movl	%dr0, %ecx
	movl	%ecx, KRS_DROFF(0)(%eax)
	movl	%dr1, %ecx
	movl	%ecx, KRS_DROFF(1)(%eax)
	movl	%dr2, %ecx
	movl	%ecx, KRS_DROFF(2)(%eax)
	movl	%dr3, %ecx
	movl	%ecx, KRS_DROFF(3)(%eax)

	/*
	 * Save any requested MSRs.
	 */
	movl	KRS_MSR(%eax), %ecx
	cmpl	$0, %ecx
	je	no_msr

	pushl	%eax		/* rdmsr clobbers %eax */
	movl	%ecx, %ebx

1:
	movl	MSR_NUM(%ebx), %ecx
	cmpl	$0, %ecx
	je	msr_done

	movl	MSR_TYPE(%ebx), %edx
	cmpl	$KMDB_MSR_READ, %edx
	jne	msr_next

	rdmsr			/* addr in %ecx, value into %edx:%eax */
	movl	%eax, MSR_VAL(%ebx)
	movl	%edx, _CONST(MSR_VAL + 4)(%ebx)

msr_next:
	addl	$MSR_SIZE, %ebx
	jmp	1b

msr_done:
	popl	%eax

no_msr:
	clr	%ebp		/* stack traces should end here */

	pushl	%eax
	call	kaif_debugger_entry
	pushl	%eax		/* leave cpusave on the stack */

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

	/* Save all registers and selectors */
	pushal
	pushl	%ds
	pushl	%es
	pushl	%fs
	pushl	%gs
	pushl	%ss

	subl	$8, %esp
	movl	%ebp, REG_OFF(KREG_SAVFP)(%esp)
	movl	REG_OFF(KREG_EIP)(%esp), %eax
	movl	%eax, REG_OFF(KREG_SAVPC)(%esp)

	/*
	 * If the kernel has started using its own selectors, we should too.
	 * Update our saved selectors if they haven't been updated already.
	 */
	movw	%cs, %ax
	cmpw	$KCS_SEL, %ax
	jne	1f			/* The kernel hasn't switched yet */

	movw	$KDS_SEL, %ax
	movw	%ax, %ds
	movw	kaif_cs, %ax
	cmpw	$KCS_SEL, %ax
	je	1f			/* We already switched */

	/*
	 * The kernel switched, but we haven't.  Update our saved selectors
	 * to match the kernel's copies for use below.
	 */
	movl	$KCS_SEL, kaif_cs
	movl	$KDS_SEL, kaif_ds
	movl	$KFS_SEL, kaif_fs
	movl	$KGS_SEL, kaif_gs

1:
	/*
	 * Set the selectors to a known state.  If we come in from kmdb's IDT,
	 * we'll be on boot's %cs.  This will cause GET_CPUSAVE_ADDR to return
	 * CPU 0's cpusave, regardless of which CPU we're on, and chaos will
	 * ensue.  So, if we've got $KCSSEL in kaif_cs, switch to it.  The other
	 * selectors are restored normally.
	 */
	movw	%cs:kaif_cs, %ax
	cmpw	$KCS_SEL, %ax
	jne	1f
	ljmp	$KCS_SEL, $1f
1:
	movw	%cs:kaif_ds, %ds
	movw	kaif_ds, %es
	movw	kaif_fs, %fs
	movw	kaif_gs, %gs
	movw	kaif_ds, %ss

	GET_CPUSAVE_ADDR		/* %eax = cpusave, %ebx = CPU ID */

	ADVANCE_CRUMB_POINTER(%eax, %ecx, %edx)

	ADD_CRUMB(%eax, KRM_CPU_STATE, $KAIF_CPU_STATE_MASTER, %edx)

	movl	REG_OFF(KREG_EIP)(%esp), %ecx
	ADD_CRUMB(%eax, KRM_PC, %ecx, %edx)
	ADD_CRUMB(%eax, KRM_SP, %esp, %edx)
	movl	REG_OFF(KREG_TRAPNO)(%esp), %ecx
	ADD_CRUMB(%eax, KRM_TRAPNO, %ecx, %edx)

	movl	%esp, %ebp
	pushl	%eax

	/*
	 * Were we in the debugger when we took the trap (i.e. was %esp in one
	 * of the debugger's memory ranges)?
	 */
	leal	kaif_memranges, %ecx
	movl	kaif_nmemranges, %edx
1:	cmpl	MR_BASE(%ecx), %esp
	jl	2f		/* below this range -- try the next one */
	cmpl	MR_LIM(%ecx), %esp
	jg	2f		/* above this range -- try the next one */
	jmp	3f		/* matched within this range */

2:	decl	%edx
	jz	kaif_save_common_state	/* %esp not within debugger memory */
	addl	$MR_SIZE, %ecx
	jmp	1b

3:	/*
	 * %esp was within one of the debugger's memory ranges.  This should only
	 * happen when we take a trap while running in the debugger.
	 * kmdb_dpi_handle_fault will determine whether or not it was an expected
	 * trap, and will take the appropriate action.
	 */

	pushl	%ebx			/* cpuid */

	movl	REG_OFF(KREG_ESP)(%ebp), %ecx
	addl	$REG_OFF(KREG_EFLAGS - KREG_EAX), %ecx
	pushl	%ecx

	pushl	REG_OFF(KREG_EIP)(%ebp)
	pushl	REG_OFF(KREG_TRAPNO)(%ebp)

	call	kmdb_dpi_handle_fault
	addl	$16, %esp

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
	 * looks like one you'd get from a zero-argument function call.  There's
	 * an %eip at %esp, and that's about it.  We want to make it look like the
	 * master CPU's stack.  By doing this, we can use the same resume code for
	 * both master and slave.  We need to make our stack look like a `struct
	 * regs' before we jump into the common save routine.
	 */

	pushl	%cs
	pushfl
	cli
	pushl	$-1		/* A phony trap error code */
	pushl	$-1		/* A phony trap number */
	pushal
	pushl	%ds
	pushl	%es
	pushl	%fs
	pushl	%gs
	pushl	%ss

	subl	$8, %esp
	movl	%ebp, REG_OFF(KREG_SAVFP)(%esp)
	movl	REG_OFF(KREG_EIP)(%esp), %eax
	movl	%eax, REG_OFF(KREG_SAVPC)(%esp)

	/* Swap our saved EFLAGS and %eip.  Each is where the other should be */
	movl	REG_OFF(KREG_EFLAGS)(%esp), %eax
	xchgl	REG_OFF(KREG_EIP)(%esp), %eax
	movl	%eax, REG_OFF(KREG_EFLAGS)(%esp)

	/* Our stack now matches struct regs, and is irettable */

	/* Load sanitized segment selectors */
	movw	kaif_ds, %ds
	movw	kaif_ds, %es
	movw	kaif_fs, %fs
	movw	kaif_gs, %gs
	movw	kaif_ds, %ss

	GET_CPUSAVE_ADDR	/* %eax = cpusave, %ebx = CPU ID */

	ADVANCE_CRUMB_POINTER(%eax, %ecx, %edx)

	ADD_CRUMB(%eax, KRM_CPU_STATE, $KAIF_CPU_STATE_SLAVE, %edx)

	movl	REG_OFF(KREG_EIP)(%esp), %ecx
	ADD_CRUMB(%eax, KRM_PC, %ecx, %edx)

	pushl	%eax
	jmp	kaif_save_common_state

	SET_SIZE(kaif_slave_entry)

#endif	/* __lint */
