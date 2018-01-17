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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

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
#include <sys/privregs.h>
#include <sys/machprivregs.h>
#include <sys/kdi_regs.h>
#include <sys/uadmin.h>
#include <sys/psw.h>

#ifdef _ASM

#include <kdi_assym.h>
#include <assym.h>

/* clobbers %edx, %ecx, returns addr in %eax, cpu id in %ebx */
#define	GET_CPUSAVE_ADDR \
	movl	%gs:CPU_ID, %ebx;		\
	movl	%ebx, %eax;			\
	movl	$KRS_SIZE, %ecx;		\
	mull	%ecx;				\
	movl	$kdi_cpusave, %edx;		\
	/*CSTYLED*/				\
	addl	(%edx), %eax

/*
 * Save copies of the IDT and GDT descriptors.  Note that we only save the IDT
 * and GDT if the IDT isn't ours, as we may be legitimately re-entering the
 * debugger through the trap handler.  We don't want to clobber the saved IDT
 * in the process, as we'd end up resuming the world on our IDT.
 */
#define	SAVE_IDTGDT				\
	movl	%gs:CPU_IDT, %edx;		\
	cmpl	$kdi_idt, %edx;			\
	je	1f;				\
	movl	%edx, KRS_IDT(%eax);		\
	movl	%gs:CPU_GDT, %edx;		\
	movl	%edx, KRS_GDT(%eax);		\
1:

/*
 * Given the address of the current CPU's cpusave area in %edi, the following
 * macro restores the debugging state to said CPU.  Restored state includes
 * the debug registers from the global %dr variables.
 */
#define	KDI_RESTORE_DEBUGGING_STATE \
	leal	kdi_drreg, %ebx;				\
								\
	pushl	DR_CTL(%ebx);					\
	pushl	$7;						\
	call	kdi_dreg_set;					\
	addl	$8, %esp;					\
								\
	pushl	$KDIREG_DRSTAT_RESERVED;				\
	pushl	$6;						\
	call	kdi_dreg_set;					\
	addl	$8, %esp;					\
								\
	pushl	DRADDR_OFF(0)(%ebx);				\
	pushl	$0;						\
	call	kdi_dreg_set;					\
	addl	$8, %esp;					\
								\
	pushl	DRADDR_OFF(1)(%ebx);				\
	pushl	$1;						\
	call	kdi_dreg_set;			 		\
	addl	$8, %esp;					\
								\
	pushl	DRADDR_OFF(2)(%ebx);				\
	pushl	$2;						\
	call	kdi_dreg_set;					\
	addl	$8, %esp;					\
								\
	pushl	DRADDR_OFF(3)(%ebx);				\
	pushl	$3;						\
	call	kdi_dreg_set;					\
	addl	$8, %esp;

#define	KDI_RESTORE_REGS() \
	/* Discard savfp and savpc */ \
	addl	$8, %esp; \
	popl	%ss; \
	popl	%gs; \
	popl	%fs; \
	popl	%es; \
	popl	%ds; \
	popal; \
	/* Discard trapno and err */ \
	addl	$8, %esp

/*
 * Each cpusave buffer has an area set aside for a ring buffer of breadcrumbs.
 * The following macros manage the buffer.
 */

/* Advance the ring buffer */
#define	ADVANCE_CRUMB_POINTER(cpusave, tmp1, tmp2) \
	movl	KRS_CURCRUMBIDX(cpusave), tmp1;	\
	cmpl	$[KDI_NCRUMBS - 1], tmp1;	\
	jge	1f;				\
	/* Advance the pointer and index */	\
	addl	$1, tmp1;			\
	movl	tmp1, KRS_CURCRUMBIDX(cpusave);	\
	movl	KRS_CURCRUMB(cpusave), tmp1;	\
	addl	$KRM_SIZE, tmp1;		\
	jmp	2f;				\
1:	/* Reset the pointer and index */	\
	movw	$0, KRS_CURCRUMBIDX(cpusave);	\
	leal	KRS_CRUMBS(cpusave), tmp1;	\
2:	movl	tmp1, KRS_CURCRUMB(cpusave);	\
	/* Clear the new crumb */		\
	movl	$KDI_NCRUMBS, tmp2;		\
3:	movl	$0, -4(tmp1, tmp2, 4);		\
	decl	tmp2;				\
	jnz	3b

/* Set a value in the current breadcrumb buffer */
#define	ADD_CRUMB(cpusave, offset, value, tmp) \
	movl	KRS_CURCRUMB(cpusave), tmp;	\
	movl	value, offset(tmp)

#endif	/* _ASM */

/*
 * The main entry point for master CPUs.  It also serves as the trap handler
 * for all traps and interrupts taken during single-step.
 */
#if defined(__lint)
void
kdi_cmnint(void)
{
}
#else	/* __lint */

 	/* XXX implement me */
	ENTRY_NP(kdi_nmiint)
	clr	%ecx
	movl	(%ecx), %ecx
	SET_SIZE(kdi_nmiint)

	ENTRY_NP(kdi_cmnint)
	ALTENTRY(kdi_master_entry)
	
	/* Save all registers and selectors */

	pushal
	pushl	%ds
	pushl	%es
	pushl	%fs
	pushl	%gs
	pushl	%ss

	subl	$8, %esp
	movl	%ebp, REG_OFF(KDIREG_SAVFP)(%esp)
	movl	REG_OFF(KDIREG_EIP)(%esp), %eax
	movl	%eax, REG_OFF(KDIREG_SAVPC)(%esp)

	/*
	 * If the kernel has started using its own selectors, we should too.
	 * Update our saved selectors if they haven't been updated already.
	 */
	movw	%cs, %ax
	cmpw	$KCS_SEL, %ax
	jne	1f			/* The kernel hasn't switched yet */

	movw	$KDS_SEL, %ax
	movw	%ax, %ds
	movw	kdi_cs, %ax
	cmpw	$KCS_SEL, %ax
	je	1f			/* We already switched */

	/*
	 * The kernel switched, but we haven't.  Update our saved selectors
	 * to match the kernel's copies for use below.
	 */
	movl	$KCS_SEL, kdi_cs
	movl	$KDS_SEL, kdi_ds
	movl	$KFS_SEL, kdi_fs
	movl	$KGS_SEL, kdi_gs

1:
	/*
	 * Set the selectors to a known state.  If we come in from kmdb's IDT,
	 * we'll be on boot's %cs.  This will cause GET_CPUSAVE_ADDR to return
	 * CPU 0's cpusave, regardless of which CPU we're on, and chaos will
	 * ensue.  So, if we've got $KCSSEL in kdi_cs, switch to it.  The other
	 * selectors are restored normally.
	 */
	movw	%cs:kdi_cs, %ax
	cmpw	$KCS_SEL, %ax
	jne	1f
	ljmp	$KCS_SEL, $1f
1:
	movw	%cs:kdi_ds, %ds
	movw	kdi_ds, %es
	movw	kdi_fs, %fs
	movw	kdi_gs, %gs
	movw	kdi_ds, %ss

	/*
	 * This has to come after we set %gs to the kernel descriptor.  Since
	 * we've hijacked some IDT entries used in user-space such as the
	 * breakpoint handler, we can enter kdi_cmnint() with GDT_LWPGS used
	 * in %gs.  On the hypervisor, CLI() needs GDT_GS to access the machcpu.
	 */
	CLI(%eax)

#if defined(__xpv)
	/*
	 * Clear saved_upcall_mask in unused byte of cs slot on stack.
	 * It can only confuse things.
	 */
	movb    $0, REG_OFF(KDIREG_CS)+2(%esp)

#endif

	GET_CPUSAVE_ADDR		/* %eax = cpusave, %ebx = CPU ID */

	ADVANCE_CRUMB_POINTER(%eax, %ecx, %edx)

	ADD_CRUMB(%eax, KRM_CPU_STATE, $KDI_CPU_STATE_MASTER, %edx)

	movl	REG_OFF(KDIREG_EIP)(%esp), %ecx
	ADD_CRUMB(%eax, KRM_PC, %ecx, %edx)
	ADD_CRUMB(%eax, KRM_SP, %esp, %edx)
	movl	REG_OFF(KDIREG_TRAPNO)(%esp), %ecx
	ADD_CRUMB(%eax, KRM_TRAPNO, %ecx, %edx)

	movl	%esp, %ebp
	pushl	%eax

	/*
	 * Were we in the debugger when we took the trap (i.e. was %esp in one
	 * of the debugger's memory ranges)?
	 */
	leal	kdi_memranges, %ecx
	movl	kdi_nmemranges, %edx
1:	cmpl	MR_BASE(%ecx), %esp
	jl	2f		/* below this range -- try the next one */
	cmpl	MR_LIM(%ecx), %esp
	jg	2f		/* above this range -- try the next one */
	jmp	3f		/* matched within this range */

2:	decl	%edx
	jz	kdi_save_common_state	/* %esp not within debugger memory */
	addl	$MR_SIZE, %ecx
	jmp	1b

3:	/*
	 * %esp was within one of the debugger's memory ranges.  This should
	 * only happen when we take a trap while running in the debugger.
	 * kmdb_dpi_handle_fault will determine whether or not it was an
	 * expected trap, and will take the appropriate action.
	 */

	pushl	%ebx			/* cpuid */

	movl	REG_OFF(KDIREG_ESP)(%ebp), %ecx
	addl	$REG_OFF(KDIREG_EFLAGS - KDIREG_EAX), %ecx
	pushl	%ecx

	pushl	REG_OFF(KDIREG_EIP)(%ebp)
	pushl	REG_OFF(KDIREG_TRAPNO)(%ebp)

	call	kdi_dvec_handle_fault
	addl	$16, %esp

	/*
	 * If we're here, we ran into a debugger problem, and the user
	 * elected to solve it by having the debugger debug itself.  The
	 * state we're about to save is that of the debugger when it took
	 * the fault.
	 */

	jmp	kdi_save_common_state

	SET_SIZE(kdi_master_entry)
	SET_SIZE(kdi_cmnint)

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
void
kdi_slave_entry(void)
{
}
#else /* __lint */
	ENTRY_NP(kdi_slave_entry)

	/*
	 * Cross calls are implemented as function calls, so our stack
	 * currently looks like one you'd get from a zero-argument function
	 * call. There's an %eip at %esp, and that's about it.  We want to
	 * make it look like the master CPU's stack.  By doing this, we can
	 * use the same resume code for both master and slave.  We need to
	 * make our stack look like a `struct regs' before we jump into the
	 * common save routine.
	 */

	pushl	%cs
	pushfl
	pushl	$-1		/* A phony trap error code */
	pushl	$-1		/* A phony trap number */
	pushal
	pushl	%ds
	pushl	%es
	pushl	%fs
	pushl	%gs
	pushl	%ss

	subl	$8, %esp
	movl	%ebp, REG_OFF(KDIREG_SAVFP)(%esp)
	movl	REG_OFF(KDIREG_EIP)(%esp), %eax
	movl	%eax, REG_OFF(KDIREG_SAVPC)(%esp)

	/*
	 * Swap our saved EFLAGS and %eip.  Each is where the other
	 * should be.
	 */
	movl	REG_OFF(KDIREG_EFLAGS)(%esp), %eax
	xchgl	REG_OFF(KDIREG_EIP)(%esp), %eax
	movl	%eax, REG_OFF(KDIREG_EFLAGS)(%esp)

	/*
	 * Our stack now matches struct regs, and is irettable.  We don't need
	 * to do anything special for the hypervisor w.r.t. PS_IE since we
	 * iret twice anyway; the second iret back to the hypervisor
	 * will re-enable interrupts.
	 */
	CLI(%eax)

	/* Load sanitized segment selectors */
	movw	kdi_ds, %ds
	movw	kdi_ds, %es
	movw	kdi_fs, %fs
	movw	kdi_gs, %gs
	movw	kdi_ds, %ss

	GET_CPUSAVE_ADDR	/* %eax = cpusave, %ebx = CPU ID */

	ADVANCE_CRUMB_POINTER(%eax, %ecx, %edx)

	ADD_CRUMB(%eax, KRM_CPU_STATE, $KDI_CPU_STATE_SLAVE, %edx)

	movl	REG_OFF(KDIREG_EIP)(%esp), %ecx
	ADD_CRUMB(%eax, KRM_PC, %ecx, %edx)

	pushl	%eax
	jmp	kdi_save_common_state

	SET_SIZE(kdi_slave_entry)

#endif	/* __lint */

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
#if !defined(__lint)

	ENTRY_NP(kdi_save_common_state)

	popl	%eax			/* the cpusave area */

	movl	%esp, KRS_GREGS(%eax)	/* save ptr to current saved regs */

	addl	$REG_OFF(KDIREG_EFLAGS - KDIREG_EAX), KDIREG_OFF(KDIREG_ESP)(%esp)

	andl	$0xffff, KDIREG_OFF(KDIREG_SS)(%esp)
	andl	$0xffff, KDIREG_OFF(KDIREG_GS)(%esp)
	andl	$0xffff, KDIREG_OFF(KDIREG_FS)(%esp)
	andl	$0xffff, KDIREG_OFF(KDIREG_ES)(%esp)
	andl	$0xffff, KDIREG_OFF(KDIREG_DS)(%esp)

	pushl	%eax
	call	kdi_trap_pass
	cmpl	$1, %eax
	je	kdi_pass_to_kernel
	popl	%eax

	SAVE_IDTGDT

#if !defined(__xpv)
	/* Save off %cr0, and clear write protect */
	movl	%cr0, %ecx
	movl	%ecx, KRS_CR0(%eax)
	andl	$_BITNOT(CR0_WP), %ecx
	movl	%ecx, %cr0
#endif
	pushl	%edi
	movl	%eax, %edi

	/* Save the debug registers and disable any active watchpoints */
	pushl	$7
	call	kdi_dreg_get
	addl	$4, %esp

	movl	%eax, KRS_DRCTL(%edi)
	andl	$_BITNOT(KDIREG_DRCTL_WPALLEN_MASK), %eax

	pushl	%eax
	pushl	$7
	call	kdi_dreg_set
	addl	$8, %esp

	pushl	$6
	call	kdi_dreg_get
	addl	$4, %esp
	movl	%eax, KRS_DRSTAT(%edi)

	pushl	$0
	call	kdi_dreg_get
	addl	$4, %esp
	movl	%eax, KRS_DROFF(0)(%edi)

	pushl	$1
	call	kdi_dreg_get
	addl	$4, %esp
	movl	%eax, KRS_DROFF(1)(%edi)

	pushl	$2
	call	kdi_dreg_get
	addl	$4, %esp
	movl	%eax, KRS_DROFF(2)(%edi)

	pushl	$3
	call	kdi_dreg_get
	addl	$4, %esp
	movl	%eax, KRS_DROFF(3)(%edi)

	movl	%edi, %eax
	popl	%edi

	clr	%ebp		/* stack traces should end here */

	pushl	%eax
	call	kdi_debugger_entry
	popl	%eax

	jmp	kdi_resume

	SET_SIZE(kdi_save_common_state)

#endif	/* !__lint */

/*
 * Resume the world.  The code that calls kdi_resume has already
 * decided whether or not to restore the IDT.
 */
#if defined(__lint)
void
kdi_resume(void)
{
}
#else	/* __lint */

	/* cpusave in %eax */
	ENTRY_NP(kdi_resume)

	/*
	 * Send this CPU back into the world
	 */

#if !defined(__xpv)
	movl	KRS_CR0(%eax), %edx
	movl	%edx, %cr0
#endif

	pushl	%edi
	movl	%eax, %edi

	KDI_RESTORE_DEBUGGING_STATE

	popl	%edi

#if defined(__xpv)
	/*
	 * kmdb might have set PS_T in the saved eflags, so we can't use
	 * intr_restore, since that restores all of eflags; instead, just
	 * pick up PS_IE from the saved eflags.
	 */
	movl	REG_OFF(KDIREG_EFLAGS)(%esp), %eax
	testl	$PS_IE, %eax
	jz	2f
	STI
2:
#endif

	addl	$8, %esp	/* Discard savfp and savpc */

	popl	%ss
	popl	%gs
	popl	%fs
	popl	%es
	popl	%ds
	popal

	addl	$8, %esp	/* Discard TRAPNO and ERROR */

	IRET

	SET_SIZE(kdi_resume)
#endif	/* __lint */

#if !defined(__lint)

	ENTRY_NP(kdi_pass_to_kernel)

	/* pop cpusave, leaving %esp pointing to saved regs */
	popl	%eax

	movl	$KDI_CPU_STATE_NONE, KRS_CPU_STATE(%eax)

	/*
	 * Find the trap and vector off the right kernel handler.  The trap
	 * handler will expect the stack to be in trap order, with %eip being
	 * the last entry, so we'll need to restore all our regs.
	 *
	 * We're hard-coding the three cases where KMDB has installed permanent
	 * handlers, since after we restore, we don't have registers to work
	 * with; we can't use a global since other CPUs can easily pass through
	 * here at the same time.
	 *
	 * Note that we handle T_DBGENTR since userspace might have tried it.
	 */
	movl	REG_OFF(KDIREG_TRAPNO)(%esp), %eax
	cmpl	$T_SGLSTP, %eax
	je	kpass_dbgtrap
	cmpl	$T_BPTFLT, %eax
	je	kpass_brktrap
	cmpl	$T_DBGENTR, %eax
	je	kpass_invaltrap
	/*
	 * Hmm, unknown handler.  Somebody forgot to update this when they
	 * added a new trap interposition... try to drop back into kmdb.
	 */
	int	$T_DBGENTR
	
kpass_dbgtrap:
	KDI_RESTORE_REGS()
	ljmp	$KCS_SEL, $1f
1:	jmp	%cs:dbgtrap
	/*NOTREACHED*/

kpass_brktrap:
	KDI_RESTORE_REGS()
	ljmp	$KCS_SEL, $2f
2:	jmp	%cs:brktrap
	/*NOTREACHED*/

kpass_invaltrap:
	KDI_RESTORE_REGS()
	ljmp	$KCS_SEL, $3f
3:	jmp	%cs:invaltrap
	/*NOTREACHED*/

	SET_SIZE(kdi_pass_to_kernel)

	/*
	 * A minimal version of mdboot(), to be used by the master CPU only.
	 */
	ENTRY_NP(kdi_reboot)

	pushl	$AD_BOOT
	pushl	$A_SHUTDOWN
	call	*psm_shutdownf
	addl	$8, %esp

#if defined(__xpv)
	pushl	$SHUTDOWN_reboot
	call	HYPERVISOR_shutdown
#else
	call	reset
#endif
	/*NOTREACHED*/

	SET_SIZE(kdi_reboot)

#endif	/* !__lint */

#if defined(__lint)
/*ARGSUSED*/
void
kdi_cpu_debug_init(kdi_cpusave_t *save)
{
}
#else	/* __lint */

	ENTRY_NP(kdi_cpu_debug_init)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%edi
	pushl	%ebx

	movl	8(%ebp), %edi

	KDI_RESTORE_DEBUGGING_STATE

	popl	%ebx
	popl	%edi
	leave
	ret

	SET_SIZE(kdi_cpu_debug_init)
#endif	/* !__lint */

