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
 * Debugger entry and exit for both master and slave CPUs. kdi_idthdl.s contains
 * the IDT stubs that drop into here (mainly via kdi_cmnint).
 */

#if defined(__lint)
#include <sys/types.h>
#else

#include <sys/segments.h>
#include <sys/asm_linkage.h>
#include <sys/controlregs.h>
#include <sys/x86_archext.h>
#include <sys/privregs.h>
#include <sys/machprivregs.h>
#include <sys/kdi_regs.h>
#include <sys/psw.h>
#include <sys/uadmin.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#endif
#include <kdi_assym.h>
#include <assym.h>

/* clobbers %rdx, %rcx, returns addr in %rax, CPU ID in %rbx */
#define	GET_CPUSAVE_ADDR \
	movzbq	%gs:CPU_ID, %rbx;		\
	movq	%rbx, %rax;			\
	movq	$KRS_SIZE, %rcx;		\
	mulq	%rcx;				\
	movq	$kdi_cpusave, %rdx;		\
	/*CSTYLED*/				\
	addq	(%rdx), %rax

/*
 * Save copies of the IDT and GDT descriptors.  Note that we only save the IDT
 * and GDT if the IDT isn't ours, as we may be legitimately re-entering the
 * debugger through the trap handler.  We don't want to clobber the saved IDT
 * in the process, as we'd end up resuming the world on our IDT.
 */
#define	SAVE_IDTGDT				\
	movq	%gs:CPU_IDT, %r11;		\
	leaq    kdi_idt(%rip), %rsi;		\
	cmpq	%rsi, %r11;			\
	je	1f;				\
	movq	%r11, KRS_IDT(%rax);		\
	movq	%gs:CPU_GDT, %r11;		\
	movq	%r11, KRS_GDT(%rax);		\
1:

#ifdef __xpv

/*
 * Already on kernel gsbase via the hypervisor.
 */
#define	SAVE_GSBASE(reg) /* nothing */
#define	RESTORE_GSBASE(reg) /* nothing */

#else

#define	SAVE_GSBASE(base)				\
	movl	$MSR_AMD_GSBASE, %ecx;			\
	rdmsr;						\
	shlq	$32, %rdx;				\
	orq	%rax, %rdx;				\
	movq	%rdx, REG_OFF(KDIREG_GSBASE)(base);	\
	movl	$MSR_AMD_KGSBASE, %ecx;			\
	rdmsr;						\
	shlq	$32, %rdx;				\
	orq	%rax, %rdx;				\
	movq	%rdx, REG_OFF(KDIREG_KGSBASE)(base)

/*
 * We shouldn't have stomped on KGSBASE, so don't try to restore it.
 */
#define	RESTORE_GSBASE(base)				\
	movq	REG_OFF(KDIREG_GSBASE)(base), %rdx;	\
	movq	%rdx, %rax;				\
	shrq	$32, %rdx;				\
	movl	$MSR_AMD_GSBASE, %ecx;			\
	wrmsr

#endif /* __xpv */

/*
 * %ss, %rsp, %rflags, %cs, %rip, %err, %trapno are already on the stack.
 */
#define	KDI_SAVE_REGS(base) \
	movq	%rdi, REG_OFF(KDIREG_RDI)(base);	\
	movq	%rsi, REG_OFF(KDIREG_RSI)(base);	\
	movq	%rdx, REG_OFF(KDIREG_RDX)(base);	\
	movq	%rcx, REG_OFF(KDIREG_RCX)(base);	\
	movq	%r8, REG_OFF(KDIREG_R8)(base);		\
	movq	%r9, REG_OFF(KDIREG_R9)(base);		\
	movq	%rax, REG_OFF(KDIREG_RAX)(base);	\
	movq	%rbx, REG_OFF(KDIREG_RBX)(base);	\
	movq	%rbp, REG_OFF(KDIREG_RBP)(base);	\
	movq	%r10, REG_OFF(KDIREG_R10)(base);	\
	movq	%r11, REG_OFF(KDIREG_R11)(base);	\
	movq	%r12, REG_OFF(KDIREG_R12)(base);	\
	movq	%r13, REG_OFF(KDIREG_R13)(base);	\
	movq	%r14, REG_OFF(KDIREG_R14)(base);	\
	movq	%r15, REG_OFF(KDIREG_R15)(base);	\
	movq	%rbp, REG_OFF(KDIREG_SAVFP)(base);	\
	movq	REG_OFF(KDIREG_RIP)(base), %rax;	\
	movq	%rax, REG_OFF(KDIREG_SAVPC)(base);	\
	movq	%cr2, %rax;				\
	movq	%rax, REG_OFF(KDIREG_CR2)(base);	\
	clrq	%rax;					\
	movw	%ds, %ax;				\
	movq	%rax, REG_OFF(KDIREG_DS)(base);		\
	movw	%es, %ax;				\
	movq	%rax, REG_OFF(KDIREG_ES)(base);		\
	movw	%fs, %ax;				\
	movq	%rax, REG_OFF(KDIREG_FS)(base);		\
	movw	%gs, %ax;				\
	movq	%rax, REG_OFF(KDIREG_GS)(base);		\
	SAVE_GSBASE(base)

#define	KDI_RESTORE_REGS(base) \
	movq	base, %rdi;				\
	RESTORE_GSBASE(%rdi);				\
	movq	REG_OFF(KDIREG_ES)(%rdi), %rax;		\
	movw	%ax, %es;				\
	movq	REG_OFF(KDIREG_DS)(%rdi), %rax;		\
	movw	%ax, %ds;				\
	movq	REG_OFF(KDIREG_CR2)(base), %rax;	\
	movq	%rax, %cr2;				\
	movq	REG_OFF(KDIREG_R15)(%rdi), %r15;	\
	movq	REG_OFF(KDIREG_R14)(%rdi), %r14;	\
	movq	REG_OFF(KDIREG_R13)(%rdi), %r13;	\
	movq	REG_OFF(KDIREG_R12)(%rdi), %r12;	\
	movq	REG_OFF(KDIREG_R11)(%rdi), %r11;	\
	movq	REG_OFF(KDIREG_R10)(%rdi), %r10;	\
	movq	REG_OFF(KDIREG_RBP)(%rdi), %rbp;	\
	movq	REG_OFF(KDIREG_RBX)(%rdi), %rbx;	\
	movq	REG_OFF(KDIREG_RAX)(%rdi), %rax;	\
	movq	REG_OFF(KDIREG_R9)(%rdi), %r9;		\
	movq	REG_OFF(KDIREG_R8)(%rdi), %r8;		\
	movq	REG_OFF(KDIREG_RCX)(%rdi), %rcx;	\
	movq	REG_OFF(KDIREG_RDX)(%rdi), %rdx;	\
	movq	REG_OFF(KDIREG_RSI)(%rdi), %rsi;	\
	movq	REG_OFF(KDIREG_RDI)(%rdi), %rdi

/*
 * Given the address of the current CPU's cpusave area in %rax, the following
 * macro restores the debugging state to said CPU.  Restored state includes
 * the debug registers from the global %dr variables.
 *
 * Takes the cpusave area in %rdi as a parameter.
 */
#define	KDI_RESTORE_DEBUGGING_STATE \
	pushq	%rdi;						\
	leaq	kdi_drreg(%rip), %r15;				\
	movl	$7, %edi;					\
	movq	DR_CTL(%r15), %rsi;				\
	call	kdi_dreg_set;					\
								\
	movl	$6, %edi;					\
	movq	$KDIREG_DRSTAT_RESERVED, %rsi;			\
	call	kdi_dreg_set;					\
								\
	movl	$0, %edi;					\
	movq	DRADDR_OFF(0)(%r15), %rsi;			\
	call	kdi_dreg_set;					\
	movl	$1, %edi;					\
	movq	DRADDR_OFF(1)(%r15), %rsi;			\
	call	kdi_dreg_set;					\
	movl	$2, %edi;					\
	movq	DRADDR_OFF(2)(%r15), %rsi;			\
	call	kdi_dreg_set;					\
	movl	$3, %edi;					\
	movq	DRADDR_OFF(3)(%r15), %rsi;			\
	call	kdi_dreg_set;					\
	popq	%rdi;

/*
 * Each cpusave buffer has an area set aside for a ring buffer of breadcrumbs.
 * The following macros manage the buffer.
 */

/* Advance the ring buffer */
#define	ADVANCE_CRUMB_POINTER(cpusave, tmp1, tmp2) \
	movq	KRS_CURCRUMBIDX(cpusave), tmp1;	\
	cmpq	$[KDI_NCRUMBS - 1], tmp1;	\
	jge	1f;				\
	/* Advance the pointer and index */	\
	addq	$1, tmp1;			\
	movq	tmp1, KRS_CURCRUMBIDX(cpusave);	\
	movq	KRS_CURCRUMB(cpusave), tmp1;	\
	addq	$KRM_SIZE, tmp1;		\
	jmp	2f;				\
1:	/* Reset the pointer and index */	\
	movq	$0, KRS_CURCRUMBIDX(cpusave);	\
	leaq	KRS_CRUMBS(cpusave), tmp1;	\
2:	movq	tmp1, KRS_CURCRUMB(cpusave);	\
	/* Clear the new crumb */		\
	movq	$KDI_NCRUMBS, tmp2;		\
3:	movq	$0, -4(tmp1, tmp2, 4);		\
	decq	tmp2;				\
	jnz	3b

/* Set a value in the current breadcrumb buffer */
#define	ADD_CRUMB(cpusave, offset, value, tmp) \
	movq	KRS_CURCRUMB(cpusave), tmp;	\
	movq	value, offset(tmp)

	/* XXX implement me */
	ENTRY_NP(kdi_nmiint)
	clrq	%rcx
	movq	(%rcx), %rcx
	SET_SIZE(kdi_nmiint)

	/*
	 * The main entry point for master CPUs.  It also serves as the trap
	 * handler for all traps and interrupts taken during single-step.
	 */
	ENTRY_NP(kdi_cmnint)
	ALTENTRY(kdi_master_entry)

	pushq	%rax
	CLI(%rax)
	popq	%rax

	/* Save current register state */
	subq	$REG_OFF(KDIREG_TRAPNO), %rsp
	KDI_SAVE_REGS(%rsp)

#ifdef __xpv
	/*
	 * Clear saved_upcall_mask in unused byte of cs slot on stack.
	 * It can only confuse things.
	 */
	movb	$0, REG_OFF(KDIREG_CS)+4(%rsp)
#endif

#if !defined(__xpv)
	/*
	 * Switch to the kernel's GSBASE.  Neither GSBASE nor the ill-named
	 * KGSBASE can be trusted, as the kernel may or may not have already
	 * done a swapgs.  All is not lost, as the kernel can divine the correct
	 * value for us.  Note that the previous GSBASE is saved in the
	 * KDI_SAVE_REGS macro to prevent a usermode process's GSBASE from being
	 * blown away.  On the hypervisor, we don't need to do this, since it's
	 * ensured we're on our requested kernel GSBASE already.
	 */
	subq	$10, %rsp
	sgdt	(%rsp)
	movq	2(%rsp), %rdi	/* gdt base now in %rdi */
	addq	$10, %rsp
	call	kdi_gdt2gsbase	/* returns kernel's GSBASE in %rax */

	movq	%rax, %rdx
	shrq	$32, %rdx
	movl	$MSR_AMD_GSBASE, %ecx
	wrmsr

	/*
	 * In the trampoline we stashed the incoming %cr3. Copy this into
	 * the kdiregs for restoration and later use.
	 */
	mov	%gs:(CPU_KPTI_DBG+KPTI_TR_CR3), %rdx
	mov	%rdx, REG_OFF(KDIREG_CR3)(%rsp)
	/*
	 * Switch to the kernel's %cr3. From the early interrupt handler
	 * until now we've been running on the "paranoid" %cr3 (that of kas
	 * from early in boot).
	 *
	 * If we took the interrupt from somewhere already on the kas/paranoid
	 * %cr3 though, don't change it (this could happen if kcr3 is corrupt
	 * and we took a gptrap earlier from this very code).
	 */
	cmpq	%rdx, kpti_safe_cr3
	je	.no_kcr3
	mov	%gs:CPU_KPTI_KCR3, %rdx
	cmpq	$0, %rdx
	je	.no_kcr3
	mov	%rdx, %cr3
.no_kcr3:

#endif	/* __xpv */

	GET_CPUSAVE_ADDR	/* %rax = cpusave, %rbx = CPU ID */

	ADVANCE_CRUMB_POINTER(%rax, %rcx, %rdx)

	ADD_CRUMB(%rax, KRM_CPU_STATE, $KDI_CPU_STATE_MASTER, %rdx)

	movq	REG_OFF(KDIREG_RIP)(%rsp), %rcx
	ADD_CRUMB(%rax, KRM_PC, %rcx, %rdx)
	ADD_CRUMB(%rax, KRM_SP, %rsp, %rdx)
	movq	REG_OFF(KDIREG_TRAPNO)(%rsp), %rcx
	ADD_CRUMB(%rax, KRM_TRAPNO, %rcx, %rdx)

	movq	%rsp, %rbp
	pushq	%rax

	/*
	 * Were we in the debugger when we took the trap (i.e. was %esp in one
	 * of the debugger's memory ranges)?
	 */
	leaq	kdi_memranges, %rcx
	movl	kdi_nmemranges, %edx
1:
	cmpq	MR_BASE(%rcx), %rsp
	jl	2f		/* below this range -- try the next one */
	cmpq	MR_LIM(%rcx), %rsp
	jg	2f		/* above this range -- try the next one */
	jmp	3f		/* matched within this range */

2:
	decl	%edx
	jz	kdi_save_common_state	/* %rsp not within debugger memory */
	addq	$MR_SIZE, %rcx
	jmp	1b

3:	/*
	 * The master is still set.  That should only happen if we hit a trap
	 * while running in the debugger.  Note that it may be an intentional
	 * fault.  kmdb_dpi_handle_fault will sort it all out.
	 */

	movq	REG_OFF(KDIREG_TRAPNO)(%rbp), %rdi
	movq	REG_OFF(KDIREG_RIP)(%rbp), %rsi
	movq	REG_OFF(KDIREG_RSP)(%rbp), %rdx
	movq	%rbx, %rcx		/* cpuid */

	call	kdi_dvec_handle_fault

	/*
	 * If we're here, we ran into a debugger problem, and the user
	 * elected to solve it by having the debugger debug itself.  The
	 * state we're about to save is that of the debugger when it took
	 * the fault.
	 */

	jmp	kdi_save_common_state

	SET_SIZE(kdi_master_entry)
	SET_SIZE(kdi_cmnint)

/*
 * The cross-call handler for slave CPUs.
 *
 * The debugger is single-threaded, so only one CPU, called the master, may be
 * running it at any given time.  The other CPUs, known as slaves, spin in a
 * busy loop until there's something for them to do.  This is the entry point
 * for the slaves - they'll be sent here in response to a cross-call sent by the
 * master.
 */

	ENTRY_NP(kdi_slave_entry)

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
	CLI(%rax)
	pushq	$KCS_SEL
	clrq	%rax
	movw	%ss, %ax
	pushq	%rax		/* rip should be here */
	pushq	$-1		/* phony trap error code */
	pushq	$-1		/* phony trap number */

	subq	$REG_OFF(KDIREG_TRAPNO), %rsp
	KDI_SAVE_REGS(%rsp)

	movq	%cr3, %rax
	movq	%rax, REG_OFF(KDIREG_CR3)(%rsp)

	movq	REG_OFF(KDIREG_SS)(%rsp), %rax
	movq	%rax, REG_OFF(KDIREG_SAVPC)(%rsp)
	xchgq	REG_OFF(KDIREG_RIP)(%rsp), %rax
	movq	%rax, REG_OFF(KDIREG_SS)(%rsp)

	movq	REG_OFF(KDIREG_RSP)(%rsp), %rax
	addq	$8, %rax
	movq	%rax, REG_OFF(KDIREG_RSP)(%rsp)

	/*
	 * We've saved all of the general-purpose registers, and have a stack
	 * that is irettable (after we strip down to the error code)
	 */

	GET_CPUSAVE_ADDR	/* %rax = cpusave, %rbx = CPU ID */

	ADVANCE_CRUMB_POINTER(%rax, %rcx, %rdx)

	ADD_CRUMB(%rax, KRM_CPU_STATE, $KDI_CPU_STATE_SLAVE, %rdx)

	movq	REG_OFF(KDIREG_RIP)(%rsp), %rcx
	ADD_CRUMB(%rax, KRM_PC, %rcx, %rdx)
	movq	REG_OFF(KDIREG_RSP)(%rsp), %rcx
	ADD_CRUMB(%rax, KRM_SP, %rcx, %rdx)
	ADD_CRUMB(%rax, KRM_TRAPNO, $-1, %rdx)

	movq    $KDI_CPU_STATE_SLAVE, KRS_CPU_STATE(%rax)

	pushq	%rax
	jmp	kdi_save_common_state

	SET_SIZE(kdi_slave_entry)

/*
 * The state of the world:
 *
 * The stack has a complete set of saved registers and segment
 * selectors, arranged in the kdi_regs.h order.  It also has a pointer
 * to our cpusave area.
 *
 * We need to save, into the cpusave area, a pointer to these saved
 * registers.  First we check whether we should jump straight back to
 * the kernel.  If not, we save a few more registers, ready the
 * machine for debugger entry, and enter the debugger.
 */

	ENTRY_NP(kdi_save_common_state)

	popq	%rdi			/* the cpusave area */
	movq	%rsp, KRS_GREGS(%rdi)	/* save ptr to current saved regs */

	pushq	%rdi
	call	kdi_trap_pass
	testq	%rax, %rax
	jnz	kdi_pass_to_kernel
	popq	%rax /* cpusave in %rax */

	SAVE_IDTGDT

#if !defined(__xpv)
	/* Save off %cr0, and clear write protect */
	movq	%cr0, %rcx
	movq	%rcx, KRS_CR0(%rax)
	andq	$_BITNOT(CR0_WP), %rcx
	movq	%rcx, %cr0
#endif

	/* Save the debug registers and disable any active watchpoints */

	movq	%rax, %r15		/* save cpusave area ptr */
	movl	$7, %edi
	call	kdi_dreg_get
	movq	%rax, KRS_DRCTL(%r15)

	andq	$_BITNOT(KDIREG_DRCTL_WPALLEN_MASK), %rax
	movq	%rax, %rsi
	movl	$7, %edi
	call	kdi_dreg_set

	movl	$6, %edi
	call	kdi_dreg_get
	movq	%rax, KRS_DRSTAT(%r15)

	movl	$0, %edi
	call	kdi_dreg_get
	movq	%rax, KRS_DROFF(0)(%r15)

	movl	$1, %edi
	call	kdi_dreg_get
	movq	%rax, KRS_DROFF(1)(%r15)

	movl	$2, %edi
	call	kdi_dreg_get
	movq	%rax, KRS_DROFF(2)(%r15)

	movl	$3, %edi
	call	kdi_dreg_get
	movq	%rax, KRS_DROFF(3)(%r15)

	movq	%r15, %rax	/* restore cpu save area to rax */

	clrq	%rbp		/* stack traces should end here */

	pushq	%rax
	movq	%rax, %rdi	/* cpusave */

	call	kdi_debugger_entry

	/* Pass cpusave to kdi_resume */
	popq	%rdi

	jmp	kdi_resume

	SET_SIZE(kdi_save_common_state)

/*
 * Resume the world.  The code that calls kdi_resume has already
 * decided whether or not to restore the IDT.
 */
	/* cpusave in %rdi */
	ENTRY_NP(kdi_resume)

	/*
	 * Send this CPU back into the world
	 */
#if !defined(__xpv)
	movq	KRS_CR0(%rdi), %rdx
	movq	%rdx, %cr0
#endif

	KDI_RESTORE_DEBUGGING_STATE

	movq	KRS_GREGS(%rdi), %rsp

#if !defined(__xpv)
	/*
	 * If we're going back via tr_iret_kdi, then we want to copy the
	 * final %cr3 we're going to back into the kpti_dbg area now.
	 *
	 * Since the trampoline needs to find the kpti_dbg too, we enter it
	 * with %r13 set to point at that. The real %r13 (to restore before
	 * the iret) we stash in the kpti_dbg itself.
	 */
	movq	%gs:CPU_SELF, %r13	/* can't leaq %gs:*, use self-ptr */
	addq	$CPU_KPTI_DBG, %r13

	movq	REG_OFF(KDIREG_R13)(%rsp), %rdx
	movq	%rdx, KPTI_R13(%r13)

	movq	REG_OFF(KDIREG_CR3)(%rsp), %rdx
	movq	%rdx, KPTI_TR_CR3(%r13)

	/* The trampoline will undo this later. */
	movq	%r13, REG_OFF(KDIREG_R13)(%rsp)
#endif

	KDI_RESTORE_REGS(%rsp)
	addq	$REG_OFF(KDIREG_RIP), %rsp	/* Discard state, trapno, err */
	/*
	 * The common trampoline code will restore %cr3 to the right value
	 * for either kernel or userland.
	 */
#if !defined(__xpv)
	jmp	tr_iret_kdi
#else
	IRET
#endif
	/*NOTREACHED*/
	SET_SIZE(kdi_resume)


	/*
	 * We took a trap that should be handled by the kernel, not KMDB.
	 *
	 * We're hard-coding the three cases where KMDB has installed permanent
	 * handlers, since after we KDI_RESTORE_REGS(), we don't have registers
	 * to work with; we can't use a global since other CPUs can easily pass
	 * through here at the same time.
	 *
	 * Note that we handle T_DBGENTR since userspace might have tried it.
	 *
	 * The trap handler will expect the stack to be in trap order, with %rip
	 * being the last entry, so we'll need to restore all our regs.  On
	 * i86xpv we'll need to compensate for XPV_TRAP_POP.
	 *
	 * %rax on entry is either 1 or 2, which is from kdi_trap_pass().
	 * kdi_cmnint stashed the original %cr3 into KDIREG_CR3, then (probably)
	 * switched us to the CPU's kf_kernel_cr3. But we're about to call, for
	 * example:
	 *
	 * dbgtrap->trap()->tr_iret_kernel
	 *
	 * which, unlike, tr_iret_kdi, doesn't restore the original %cr3, so
	 * we'll do so here if needed.
	 *
	 * This isn't just a matter of tidiness: for example, consider:
	 *
	 * hat_switch(oldhat=kas.a_hat, newhat=prochat)
	 *  setcr3()
	 *  reset_kpti()
	 *   *brktrap* due to fbt on reset_kpti:entry
	 *
	 * Here, we have the new hat's %cr3, but we haven't yet updated
	 * kf_kernel_cr3 (so its currently kas's). So if we don't restore here,
	 * we'll stay on kas's cr3 value on returning from the trap: not good if
	 * we fault on a userspace address.
	 */
	ENTRY_NP(kdi_pass_to_kernel)

	popq	%rdi /* cpusave */
	movq	$KDI_CPU_STATE_NONE, KRS_CPU_STATE(%rdi)
	movq	KRS_GREGS(%rdi), %rsp

	cmpq	$2, %rax
	jne	no_restore_cr3
	movq	REG_OFF(KDIREG_CR3)(%rsp), %r11
	movq	%r11, %cr3

no_restore_cr3:
	movq	REG_OFF(KDIREG_TRAPNO)(%rsp), %rdi

	cmpq	$T_SGLSTP, %rdi
	je	kdi_pass_dbgtrap
	cmpq	$T_BPTFLT, %rdi
	je	kdi_pass_brktrap
	cmpq	$T_DBGENTR, %rdi
	je	kdi_pass_invaltrap
	/*
	 * Hmm, unknown handler.  Somebody forgot to update this when they
	 * added a new trap interposition... try to drop back into kmdb.
	 */
	int	$T_DBGENTR

#define	CALL_TRAP_HANDLER(name) \
	KDI_RESTORE_REGS(%rsp); \
	/* Discard state, trapno, err */ \
	addq	$REG_OFF(KDIREG_RIP), %rsp; \
	XPV_TRAP_PUSH; \
	jmp	%cs:name

kdi_pass_dbgtrap:
	CALL_TRAP_HANDLER(dbgtrap)
	/*NOTREACHED*/
kdi_pass_brktrap:
	CALL_TRAP_HANDLER(brktrap)
	/*NOTREACHED*/
kdi_pass_invaltrap:
	CALL_TRAP_HANDLER(invaltrap)
	/*NOTREACHED*/

	SET_SIZE(kdi_pass_to_kernel)

	/*
	 * A minimal version of mdboot(), to be used by the master CPU only.
	 */
	ENTRY_NP(kdi_reboot)

	movl	$AD_BOOT, %edi
	movl	$A_SHUTDOWN, %esi
	call	*psm_shutdownf
#if defined(__xpv)
	movl	$SHUTDOWN_reboot, %edi
	call	HYPERVISOR_shutdown
#else
	call	reset
#endif
	/*NOTREACHED*/

	SET_SIZE(kdi_reboot)

	ENTRY_NP(kdi_cpu_debug_init)
	pushq	%rbp
	movq	%rsp, %rbp

	pushq	%rbx		/* macro will clobber %rbx */
	KDI_RESTORE_DEBUGGING_STATE
	popq	%rbx

	leave
	ret
	SET_SIZE(kdi_cpu_debug_init)

#define	GETDREG(name, r)	\
	ENTRY_NP(name);		\
	movq	r, %rax;	\
	ret;			\
	SET_SIZE(name)

#define	SETDREG(name, r)	\
	ENTRY_NP(name);		\
	movq	%rdi, r;	\
	ret;			\
	SET_SIZE(name)

	GETDREG(kdi_getdr0, %dr0)
	GETDREG(kdi_getdr1, %dr1)
	GETDREG(kdi_getdr2, %dr2)
	GETDREG(kdi_getdr3, %dr3)
	GETDREG(kdi_getdr6, %dr6)
	GETDREG(kdi_getdr7, %dr7)

	SETDREG(kdi_setdr0, %dr0)
	SETDREG(kdi_setdr1, %dr1)
	SETDREG(kdi_setdr2, %dr2)
	SETDREG(kdi_setdr3, %dr3)
	SETDREG(kdi_setdr6, %dr6)
	SETDREG(kdi_setdr7, %dr7)

#endif /* !__lint */
