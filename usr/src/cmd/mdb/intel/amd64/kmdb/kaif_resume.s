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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/uadmin.h>
#include <sys/reg.h>
#include <sys/segments.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>

#include <kmdb/kaif.h>
#include <kmdb/kaif_asmutil.h>
#include <kmdb/kaif_off.h>
#include <kmdb/kmdb_dpi_isadep.h>
#include <mdb/mdb_kreg.h>

/*
 * Given the address of the current CPU's cpusave area in %rax, the following
 * macro restores the debugging state to said CPU.  Restored state includes
 * the debug registers from the global %dr variables, and debugging MSRs from
 * the CPU save area.  This code would be in a separate routine, but for the
 * fact that some of the MSRs are jump-sensitive.  As such, we need to minimize
 * the number of jumps taken subsequent to the update of said MSRs.  We can
 * remove one jump (the ret) by using a macro instead of a function for the
 * debugging state restoration code.
 *
 * Takes the cpusave area in %rdi as a parameter, clobbers %rax-%rdx
 */	
#define	KAIF_RESTORE_DEBUGGING_STATE \
	leaq	kaif_drreg, %rbx;				\
	movq	DR_CTL(%rbx), %rcx;				\
	movq	%rcx, %dr7;					\
	movq	$KREG_DRSTAT_RESERVED, %rcx;			\
	movq	%rcx, %dr6;					\
	movq	DRADDR_OFF(0)(%rbx), %rcx;			\
	movq	%rcx, %dr0;					\
	movq	DRADDR_OFF(1)(%rbx), %rcx;			\
	movq	%rcx, %dr1;					\
	movq	DRADDR_OFF(2)(%rbx), %rcx;			\
	movq	%rcx, %dr2;					\
	movq	DRADDR_OFF(3)(%rbx), %rcx;			\
	movq	%rcx, %dr3;					\
								\
	/*							\
	 * Write any requested MSRs.				\
	 */							\
	movq	KRS_MSR(%rdi), %rbx;				\
	cmpq	$0, %rbx;					\
	je	3f;						\
1:								\
	movl	MSR_NUM(%rbx), %ecx;				\
	cmpl	$0, %ecx;					\
	je	3f;						\
								\
	movl	MSR_TYPE(%rbx), %edx;				\
	cmpl	$KMDB_MSR_WRITE, %edx;				\
	jne	2f;						\
								\
	movq	MSR_VALP(%rbx), %rdx;				\
	movl	0(%rdx), %eax;					\
	movl	4(%rdx), %edx;					\
	wrmsr;							\
2:								\
	addq	$MSR_SIZE, %rbx;				\
	jmp	1b;						\
3:								\
	/*							\
	 * We must not branch after re-enabling LBR.  If	\
	 * kaif_wsr_wrexit_msr is set, it contains the number	\
	 * of the MSR that controls LBR.  kaif_wsr_wrexit_valp	\
	 * contains the value that is to be written to enable	\
	 * LBR.							\
	 */							\
	movl	kaif_msr_wrexit_msr, %ecx;			\
	cmpl	$0, %ecx;					\
	je	1f;						\
								\
	movq	kaif_msr_wrexit_valp, %rdx;			\
	movl	0(%rdx), %eax;					\
	movl	4(%rdx), %edx;					\
								\
	wrmsr;							\
1:

#if defined(__lint)
/*ARGSUSED*/
void
kaif_cpu_debug_init(kaif_cpusave_t *save)
{
}
#else	/* __lint */

	ENTRY_NP(kaif_cpu_debug_init)
	pushq	%rbp
	movq	%rsp, %rbp

	pushq	%rbx		/* macro will clobber %rbx */
	KAIF_RESTORE_DEBUGGING_STATE
	popq	%rbx

	leave
	ret

	SET_SIZE(kaif_cpu_debug_init)
#endif	/* !__lint */

	/*
	 * Resume the world.  The code that calls kaif_resume has already
	 * decided whether or not to restore the IDT.
	 */
#if defined(__lint)
void
kaif_resume(void)
{
}
#else	/* __lint */

	ENTRY_NP(kaif_resume)

	/* cpusave in %rdi, debugger command in %rsi */

	cmpq	$KAIF_CPU_CMD_PASS_TO_KERNEL, %rsi
	je	kaif_pass_to_kernel

	cmpq	$KAIF_CPU_CMD_REBOOT, %rsi
	je	kaif_reboot

	/*
	 * Send this CPU back into the world
	 */

	movq	KRS_CR0(%rdi), %rdx
	movq	%rdx, %cr0

	KAIF_RESTORE_DEBUGGING_STATE

	movq	KRS_GREGS(%rdi), %rsp
	KAIF_RESTORE_REGS(%rsp)
	addq	$REG_OFF(KREG_RIP), %rsp	/* Discard state, trapno, err */

	iretq

	SET_SIZE(kaif_resume)

#endif	/* __lint */

#if !defined(__lint)

	ENTRY_NP(kaif_pass_to_kernel)

	/* cpusave is still in %rdi */

	movq	KRS_CR0(%rdi), %rdx
	movq	%rdx, %cr0

	/*
	 * When we replaced the kernel's handlers in the IDT, we made note of
	 * the handlers being replaced, thus allowing us to pass traps directly
	 * to said handlers here.  We won't have any registers available for use
	 * after we start popping, and we know we're single-threaded here, so
	 * we have to use a global to store the handler address.
	 */
	movq	KRS_GREGS(%rdi), %rsp
	movq	REG_OFF(KREG_TRAPNO)(%rsp), %rdi
	call	kaif_kernel_trap2hdlr
	movq	%rax, kaif_kernel_handler

	/*
	 * The trap handler will expect the stack to be in trap order, with
	 * %rip being the last entry.  Our stack is currently in mdb_kreg.h
	 * order, so we'll need to pop (and restore) our way back down.
	 */
	KAIF_RESTORE_REGS(%rsp)
	addq	$REG_OFF(KREG_RIP), %rsp	/* Discard state, trapno, err */

	jmp	*%cs:kaif_kernel_handler
	/*NOTREACHED*/

	SET_SIZE(kaif_pass_to_kernel)

	/*
	 * Reboot the system.  This routine is to be called only by the master
	 * CPU.
	 */
	ENTRY_NP(kaif_reboot)

	movq	kmdb_kdi_shutdownp, %rax
	movq	(%rax), %rax
	cmpq	$0, %rax
	je	1f

	/* psm_shutdown is set in the kernel, so we'll try it */
	pushq	$AD_BOOT
	pushq	$A_SHUTDOWN
	call	*%rax
	addq	$16, %rsp

1:	/*
	 * psm_shutdown didn't work or, it wasn't set.  Let's try the time-
	 * honored method for getting things done on Intel machines --
	 * sacrifice random bits to random BIOS gods.
	 */
	ALTENTRY(reset)
	movw	$0x64, %dx
	movb	$0xfe, %al
	outb	(%dx)

	hlt
	/*NOTREACHED*/

	SET_SIZE(reset)
	SET_SIZE(kaif_reboot)

#endif	/* !__lint */
