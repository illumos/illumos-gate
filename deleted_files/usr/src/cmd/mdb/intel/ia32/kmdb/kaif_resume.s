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

#include <sys/asm_linkage.h>
#include <sys/uadmin.h>
#include <sys/reg.h>
#include <sys/segments.h>
#include <sys/x86_archext.h>

#include <kmdb/kaif.h>
#include <kmdb/kaif_asmutil.h>
#include <kmdb/kaif_off.h>
#include <kmdb/kmdb_dpi_isadep.h>
#include <mdb/mdb_kreg.h>

/*
 * Given the address of the current CPU's cpusave area in %eax, the following
 * macro restores the debugging state to said CPU.  Restored state includes
 * the debug registers from the global %dr variables, and debugging MSRs from
 * the CPU save area.  This code would be in a separate routine, but for the
 * fact that some of the MSRs are jump-sensitive.  As such, we need to minimize
 * the number of jumps taken subsequent to the update of said MSRs.  We can
 * remove one jump (the ret) by using a macro instead of a function for the
 * debugging state restoration code.
 *
 * Takes the cpusave area in %eax as a parameter, clobbers %eax-%edx
 */	
#define	KAIF_RESTORE_DEBUGGING_STATE \
	leal	kaif_drreg, %ebx;				\
	movl	DR_CTL(%ebx), %ecx;				\
	movl	%ecx, %dr7;					\
	movl	$KREG_DRSTAT_RESERVED, %ecx;			\
	movl	%ecx, %dr6;					\
	movl	DRADDR_OFF(0)(%ebx), %ecx;			\
	movl	%ecx, %dr0;					\
	movl	DRADDR_OFF(1)(%ebx), %ecx;			\
	movl	%ecx, %dr1;					\
	movl	DRADDR_OFF(2)(%ebx), %ecx;			\
	movl	%ecx, %dr2;					\
	movl	DRADDR_OFF(3)(%ebx), %ecx;			\
	movl	%ecx, %dr3;					\
								\
	/*							\
	 * Write any requested MSRs.				\
	 */							\
	movl	KRS_MSR(%eax), %ebx;				\
	cmpl	$0, %ebx;					\
	je	3f;						\
1:								\
	movl	MSR_NUM(%ebx), %ecx;				\
	cmpl	$0, %ecx;					\
	je	3f;						\
								\
	movl	MSR_TYPE(%ebx), %edx;				\
	cmpl	$KMDB_MSR_WRITE, %edx;				\
	jne	2f;						\
								\
	movl	MSR_VALP(%ebx), %edx;				\
	movl	0(%edx), %eax;					\
	movl	4(%edx), %edx;					\
	wrmsr;							\
2:								\
	addl	$MSR_SIZE, %ebx;				\
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
	movl	kaif_msr_wrexit_valp, %edx;			\
	movl	0(%edx), %eax;					\
	movl	4(%edx), %edx;					\
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
	pushl	%ebp
	movl	%esp, %ebp

	movl	8(%ebp), %eax

	pushl	%ebx
	KAIF_RESTORE_DEBUGGING_STATE
	popl	%ebx

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
	popl	%ebx		/* command */
	popl	%eax		/* cpusave */

	cmpl	$KAIF_CPU_CMD_PASS_TO_KERNEL, %ebx
	je	kaif_pass_to_kernel

	cmpl	$KAIF_CPU_CMD_REBOOT, %ebx
	je	kaif_reboot

	/*
	 * Send this CPU back into the world
	 */

	movl	KRS_CR0(%eax), %edx
	movl	%edx, %cr0

	KAIF_RESTORE_DEBUGGING_STATE

	addl	$8, %esp	/* Discard savfp and savpc */

	popl	%ss
	popl	%gs
	popl	%fs
	popl	%es
	popl	%ds
	popal

	addl	$8, %esp	/* Discard TRAPNO and ERROR */

	iret

	SET_SIZE(kaif_resume)
#endif	/* __lint */

#if !defined(__lint)

	ENTRY_NP(kaif_pass_to_kernel)

	/* cpusave is still in %eax */

	movl	KRS_CR0(%eax), %edx
	movl	%edx, %cr0

	/*
	 * When we replaced the kernel's handlers in the IDT, we made note of
	 * the handlers being replaced, thus allowing us to pass traps directly
	 * to said handlers here.  We won't have any registers available for use
	 * after we start popping, and we know we're single-threaded here, so
	 * we have to use a global to store the handler address.
	 */
	pushl	REG_OFF(KREG_TRAPNO)(%esp)
	call	kaif_kernel_trap2hdlr
	addl	$4, %esp
	movl	%eax, kaif_kernel_handler

	/*
	 * The trap handler will expect the stack to be in trap order, with
	 * %eip being the last entry.  Our stack is currently in mdb_kreg.h
	 * order, so we'll need to pop (and restore) our way back down.
	 */
	addl	$8, %esp	/* Discard savfp and savpc */
	popl	%ss
	popl	%gs
	popl	%fs
	popl	%es
	popl	%ds
	popal
	addl	$8, %esp	/* Discard trapno and err */

	ljmp	$KCS_SEL, $1f
1:	jmp	*%cs:kaif_kernel_handler
	/*NOTREACHED*/

	SET_SIZE(kaif_pass_to_kernel)

	/*
	 * Reboot the system.  This routine is to be called only by the master
	 * CPU.
	 */
	ENTRY_NP(kaif_reboot)

	movl	kmdb_kdi_shutdownp, %eax
	movl	(%eax), %eax
	cmpl	$0, %eax
	je	1f

	/* psm_shutdown is set in the kernel, so we'll try it */
	pushl	$AD_BOOT
	pushl	$A_SHUTDOWN
	call	*%eax
	addl	$8, %esp

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
