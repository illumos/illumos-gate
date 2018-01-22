/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2018 Joyent, Inc.
 */

/*
 * This file contains the trampolines that are used by KPTI in order to be
 * able to take interrupts/trap/etc while on the "user" page table.
 *
 * We don't map the full kernel text into the user page table: instead we
 * map this one small section of trampolines (which compiles to ~13 pages).
 * These trampolines are set in the IDT always (so they will run no matter
 * whether we're on the kernel or user page table), and their primary job is to
 * pivot us to the kernel %cr3 and %rsp without ruining everything.
 *
 * All of these interrupts use the amd64 IST feature when we have KPTI enabled,
 * meaning that they will execute with their %rsp set to a known location, even
 * if we take them in the kernel.
 *
 * Over in desctbls.c (for cpu0) and mp_pc.c (other cpus) we set up the IST
 * stack to point at &cpu->cpu_m.mcpu_kpti.kf_tr_rsp. You can see the mcpu_kpti
 * (a struct kpti_frame) defined in machcpuvar.h. This struct is set up to be
 * page-aligned, and we map the page it's on into both page tables. Using a
 * struct attached to the cpu_t also means that we can use %rsp-relative
 * addressing to find anything on the cpu_t, so we don't have to touch %gs or
 * GSBASE at all on incoming interrupt trampolines (which can get pretty hairy).
 *
 * This little struct is where the CPU will push the actual interrupt frame.
 * Then, in the trampoline, we change %cr3, then figure out our destination
 * stack pointer and "pivot" to it (set %rsp and re-push the CPU's interrupt
 * frame). Then we jump to the regular ISR in the kernel text and carry on as
 * normal.
 *
 * We leave the original frame and any spilled regs behind in the kpti_frame
 * lazily until we want to return to userland. Then, we clear any spilled
 * regs from it, and overwrite the rest with our iret frame. When switching
 * this cpu to a different process (in hat_switch), we bzero the whole region to
 * make sure nothing can leak between processes.
 *
 * When we're returning back to the original place we took the interrupt later
 * (especially if it was in userland), we have to jmp back to the "return
 * trampolines" here, since when we set %cr3 back to the user value, we need to
 * be executing from code here in these shared pages and not the main kernel
 * text again. Even though it should be fine to iret directly from kernel text
 * when returning to kernel code, we make things jmp to a trampoline here just
 * for consistency.
 *
 * Note that with IST, it's very important that we always must have pivoted
 * away from the IST stack before we could possibly take any other interrupt
 * on the same IST (unless it's an end-of-the-world fault and we don't care
 * about coming back from it ever).
 *
 * This is particularly relevant to the dbgtrap/brktrap trampolines, as they
 * regularly have to happen from within trampoline code (e.g. in the sysenter
 * single-step case) and then return to the world normally. As a result, these
 * two are IST'd to their own kpti_frame right above the normal one (in the same
 * page), so they don't clobber their parent interrupt.
 *
 * To aid with debugging, we also IST the page fault (#PF/pftrap), general
 * protection fault (#GP/gptrap) and stack fault (#SS/stktrap) interrupts to
 * their own separate kpti_frame. This ensures that if we take one of these
 * due to a bug in trampoline code, we preserve the original trampoline
 * state that caused the trap.
 *
 * NMI, MCE and dblfault interrupts also are taken on their own dedicated IST
 * stacks, since they can interrupt another ISR at any time. These stacks are
 * full-sized, however, and not a little kpti_frame struct. We only set %cr3 in
 * their trampolines (and do it unconditionally), and don't bother pivoting
 * away. We're either going into the panic() path, or we're going to return
 * straight away without rescheduling, so it's fine to not be on our real
 * kthread stack (and some of the state we want to go find it with might be
 * corrupt!)
 *
 * Finally, for these "special" interrupts (NMI/MCE/double fault) we use a
 * special %cr3 value we stash here in the text (kpti_safe_cr3). We set this to
 * point at the PML4 for kas early in boot and never touch it again. Hopefully
 * it survives whatever corruption brings down the rest of the kernel!
 *
 * Syscalls are different to interrupts (at least in the SYSENTER/SYSCALL64
 * cases) in that they do not push an interrupt frame (and also have some other
 * effects). In the syscall trampolines, we assume that we can only be taking
 * the call from userland and use SWAPGS and an unconditional overwrite of %cr3.
 * We do not do any stack pivoting for syscalls (and we leave SYSENTER's
 * existing %rsp pivot untouched) -- instead we spill registers into
 * %gs:CPU_KPTI_* as we need to.
 *
 * Note that the normal %cr3 values do not cause invalidations with PCIDE - see
 * hat_switch().
 */

/*
 * The macros here mostly line up with what's in kdi_idthdl.s, too, so if you
 * fix bugs here check to see if they should be fixed there as well.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/machbrand.h>
#include <sys/param.h>

#if defined(__lint)

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>

#else	/* __lint */

#include <sys/segments.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/model.h>
#include <sys/panic.h>

#if defined(__xpv)
#include <sys/hypervisor.h>
#endif

#include "assym.h"

	.data
	DGDEF3(kpti_enable, 8, 8)
	.fill	1, 8, 1

.section ".text";
.align MMU_PAGESIZE

.global kpti_tramp_start
kpti_tramp_start:
	nop

/* This will be set by mlsetup, and then double-checked later */
.global kpti_safe_cr3
kpti_safe_cr3:
	.quad 0
	SET_SIZE(kpti_safe_cr3)

/* startup_kmem() will overwrite this */
.global kpti_kbase
kpti_kbase:
	.quad KERNELBASE
	SET_SIZE(kpti_kbase)

#define	SET_KERNEL_CR3(spillreg)		\
	mov	%cr3, spillreg;			\
	mov	spillreg, %gs:CPU_KPTI_TR_CR3;	\
	mov	%gs:CPU_KPTI_KCR3, spillreg;	\
	cmp	$0, spillreg;			\
	je	2f;				\
	mov	spillreg, %cr3;			\
2:

#if DEBUG
#define	SET_USER_CR3(spillreg)			\
	mov	%cr3, spillreg;			\
	mov	spillreg, %gs:CPU_KPTI_TR_CR3;	\
	mov	%gs:CPU_KPTI_UCR3, spillreg;	\
	mov	spillreg, %cr3
#else
#define	SET_USER_CR3(spillreg)			\
	mov	%gs:CPU_KPTI_UCR3, spillreg;	\
	mov	spillreg, %cr3
#endif

#define	PIVOT_KPTI_STK(spillreg)		\
	mov	%rsp, spillreg;			\
	mov	%gs:CPU_KPTI_RET_RSP, %rsp;	\
	pushq	T_FRAMERET_SS(spillreg);	\
	pushq	T_FRAMERET_RSP(spillreg);	\
	pushq	T_FRAMERET_RFLAGS(spillreg);	\
	pushq	T_FRAMERET_CS(spillreg);	\
	pushq	T_FRAMERET_RIP(spillreg)


#define	INTERRUPT_TRAMPOLINE_P(errpush)	\
	pushq	%r13;				\
	pushq	%r14;				\
	subq	$KPTI_R14, %rsp;		\
	/* Save current %cr3. */		\
	mov	%cr3, %r14;			\
	mov	%r14, KPTI_TR_CR3(%rsp);	\
						\
	cmpw	$KCS_SEL, KPTI_CS(%rsp);	\
	je	3f;				\
1:						\
	/* Change to the "kernel" %cr3 */	\
	mov	KPTI_KCR3(%rsp), %r14;		\
	cmp	$0, %r14;			\
	je	2f;				\
	mov	%r14, %cr3;			\
2:						\
	/* Get our cpu_t in %r13 */		\
	mov	%rsp, %r13;			\
	and	$(~(MMU_PAGESIZE - 1)), %r13;	\
	subq	$CPU_KPTI_START, %r13;		\
	/* Use top of the kthread stk */	\
	mov	CPU_THREAD(%r13), %r14;		\
	mov	T_STACK(%r14), %r14;		\
	addq	$REGSIZE+MINFRAME, %r14;	\
	jmp	4f;				\
3:						\
	/* Check the %rsp in the frame. */	\
	/* Is it above kernel base? */		\
	mov	kpti_kbase, %r14;		\
	cmp	%r14, KPTI_RSP(%rsp);		\
	jb	1b;				\
	/* Use the %rsp from the trap frame */	\
	mov	KPTI_RSP(%rsp), %r14;		\
	and	$(~0xf), %r14;			\
4:						\
	mov	%rsp, %r13;			\
	/* %r14 contains our destination stk */	\
	mov	%r14, %rsp;			\
	pushq	KPTI_SS(%r13);			\
	pushq	KPTI_RSP(%r13);			\
	pushq	KPTI_RFLAGS(%r13);		\
	pushq	KPTI_CS(%r13);			\
	pushq	KPTI_RIP(%r13);			\
	errpush;				\
	mov	KPTI_R14(%r13), %r14;		\
	mov	KPTI_R13(%r13), %r13

#define	INTERRUPT_TRAMPOLINE_NOERR		\
	INTERRUPT_TRAMPOLINE_P(/**/)

#define	INTERRUPT_TRAMPOLINE			\
	INTERRUPT_TRAMPOLINE_P(pushq KPTI_ERR(%r13))

/*
 * This is used for all interrupts that can plausibly be taken inside another
 * interrupt and are using a kpti_frame stack (so #BP, #DB, #GP, #PF, #SS).
 *
 * We check for whether we took the interrupt while in another trampoline, in
 * which case we need to use the kthread stack.
 */
#define	DBG_INTERRUPT_TRAMPOLINE_P(errpush)	\
	pushq	%r13;				\
	pushq	%r14;				\
	subq	$KPTI_R14, %rsp;		\
	/* Check for clobbering */		\
	cmp	$0, KPTI_FLAG(%rsp);		\
	je	1f;				\
	/* Don't worry, this totally works */	\
	int	$8;				\
1:						\
	movq	$1, KPTI_FLAG(%rsp);		\
	/* Save current %cr3. */		\
	mov	%cr3, %r14;			\
	mov	%r14, KPTI_TR_CR3(%rsp);	\
						\
	cmpw	$KCS_SEL, KPTI_CS(%rsp);	\
	je	4f;				\
2:						\
	/* Change to the "kernel" %cr3 */	\
	mov	KPTI_KCR3(%rsp), %r14;		\
	cmp	$0, %r14;			\
	je	3f;				\
	mov	%r14, %cr3;			\
3:						\
	/* Get our cpu_t in %r13 */		\
	mov	%rsp, %r13;			\
	and	$(~(MMU_PAGESIZE - 1)), %r13;	\
	subq	$CPU_KPTI_START, %r13;		\
	/* Use top of the kthread stk */	\
	mov	CPU_THREAD(%r13), %r14;		\
	mov	T_STACK(%r14), %r14;		\
	addq	$REGSIZE+MINFRAME, %r14;	\
	jmp	6f;				\
4:						\
	/* Check the %rsp in the frame. */	\
	/* Is it above kernel base? */		\
	/* If not, treat as user. */		\
	mov	kpti_kbase, %r14;		\
	cmp	%r14, KPTI_RSP(%rsp);		\
	jb	2b;				\
	/* Is it within the kpti_frame page? */	\
	/* If it is, treat as user interrupt */	\
	mov	%rsp, %r13;			\
	and	$(~(MMU_PAGESIZE - 1)), %r13;	\
	mov	KPTI_RSP(%rsp), %r14;		\
	and	$(~(MMU_PAGESIZE - 1)), %r14;	\
	cmp	%r13, %r14;			\
	je	2b;				\
	/* Were we in trampoline code? */	\
	leaq	kpti_tramp_start, %r14;		\
	cmp	%r14, KPTI_RIP(%rsp);		\
	jb	5f;				\
	leaq	kpti_tramp_end, %r14;		\
	cmp	%r14, KPTI_RIP(%rsp);		\
	ja	5f;				\
	/* If we were, change %cr3: we might */	\
	/* have interrupted before it did. */	\
	mov	KPTI_KCR3(%rsp), %r14;		\
	mov	%r14, %cr3;			\
5:						\
	/* Use the %rsp from the trap frame */	\
	mov	KPTI_RSP(%rsp), %r14;		\
	and	$(~0xf), %r14;			\
6:						\
	mov	%rsp, %r13;			\
	/* %r14 contains our destination stk */	\
	mov	%r14, %rsp;			\
	pushq	KPTI_SS(%r13);			\
	pushq	KPTI_RSP(%r13);			\
	pushq	KPTI_RFLAGS(%r13);		\
	pushq	KPTI_CS(%r13);			\
	pushq	KPTI_RIP(%r13);			\
	errpush;				\
	mov	KPTI_R14(%r13), %r14;		\
	movq	$0, KPTI_FLAG(%r13);		\
	mov	KPTI_R13(%r13), %r13

#define	DBG_INTERRUPT_TRAMPOLINE_NOERR		\
	DBG_INTERRUPT_TRAMPOLINE_P(/**/)

#define	DBG_INTERRUPT_TRAMPOLINE		\
	DBG_INTERRUPT_TRAMPOLINE_P(pushq KPTI_ERR(%r13))

	/*
	 * These labels (_start and _end) are used by trap.c to determine if
	 * we took an interrupt like an NMI during the return process.
	 */
.global	tr_sysc_ret_start
tr_sysc_ret_start:

	/*
	 * Syscall return trampolines.
	 *
	 * These are expected to be called on the kernel %gs. tr_sysret[ql] are
	 * called after %rsp is changed back to the user value, so we have no
	 * stack to work with. tr_sysexit has a kernel stack (but has to
	 * preserve rflags, soooo).
	 */
	ENTRY_NP(tr_sysretq)
	cmpq	$1, kpti_enable
	jne	1f

	mov	%r13, %gs:CPU_KPTI_R13
	SET_USER_CR3(%r13)
	mov	%gs:CPU_KPTI_R13, %r13
	/* Zero these to make sure they didn't leak from a kernel trap */
	movq	$0, %gs:CPU_KPTI_R13
	movq	$0, %gs:CPU_KPTI_R14
1:
	swapgs
	sysretq
	SET_SIZE(tr_sysretq)

	ENTRY_NP(tr_sysretl)
	cmpq	$1, kpti_enable
	jne	1f

	mov	%r13, %gs:CPU_KPTI_R13
	SET_USER_CR3(%r13)
	mov	%gs:CPU_KPTI_R13, %r13
	/* Zero these to make sure they didn't leak from a kernel trap */
	movq	$0, %gs:CPU_KPTI_R13
	movq	$0, %gs:CPU_KPTI_R14
1:
	SWAPGS
	SYSRETL
	SET_SIZE(tr_sysretl)

	ENTRY_NP(tr_sysexit)
	/*
	 * Note: we want to preserve RFLAGS across this branch, since sysexit
	 * (unlike sysret above) does not restore RFLAGS for us.
	 *
	 * We still have the real kernel stack (sysexit does restore that), so
	 * we can use pushfq/popfq.
	 */
	pushfq

	cmpq	$1, kpti_enable
	jne	1f

	/* Have to pop it back off now before we change %cr3! */
	popfq
	mov	%r13, %gs:CPU_KPTI_R13
	SET_USER_CR3(%r13)
	mov	%gs:CPU_KPTI_R13, %r13
	/* Zero these to make sure they didn't leak from a kernel trap */
	movq	$0, %gs:CPU_KPTI_R13
	movq	$0, %gs:CPU_KPTI_R14
	jmp	2f
1:
	popfq
2:
	swapgs
	sti
	sysexit
	SET_SIZE(tr_sysexit)

.global	tr_sysc_ret_end
tr_sysc_ret_end:

	/*
	 * Syscall entry trampolines.
	 */

#if DEBUG
#define	MK_SYSCALL_TRAMPOLINE(isr)		\
	ENTRY_NP(tr_/**/isr);			\
	swapgs;					\
	mov	%r13, %gs:CPU_KPTI_R13;		\
	mov	%cr3, %r13;			\
	mov	%r13, %gs:CPU_KPTI_TR_CR3;	\
	mov	%gs:CPU_KPTI_KCR3, %r13;	\
	mov	%r13, %cr3;			\
	mov	%gs:CPU_KPTI_R13, %r13;		\
	swapgs;					\
	jmp	isr;				\
	SET_SIZE(tr_/**/isr)
#else
#define	MK_SYSCALL_TRAMPOLINE(isr)		\
	ENTRY_NP(tr_/**/isr);			\
	swapgs;					\
	mov	%r13, %gs:CPU_KPTI_R13;		\
	mov	%gs:CPU_KPTI_KCR3, %r13;	\
	mov	%r13, %cr3;			\
	mov	%gs:CPU_KPTI_R13, %r13;		\
	swapgs;					\
	jmp	isr;				\
	SET_SIZE(tr_/**/isr)
#endif

	MK_SYSCALL_TRAMPOLINE(sys_syscall)
	MK_SYSCALL_TRAMPOLINE(sys_syscall32)
	MK_SYSCALL_TRAMPOLINE(brand_sys_syscall)
	MK_SYSCALL_TRAMPOLINE(brand_sys_syscall32)

	/*
	 * SYSENTER is special. The CPU is really not very helpful when it
	 * comes to preserving and restoring state with it, and as a result
	 * we have to do all of it by hand. So, since we want to preserve
	 * RFLAGS, we have to be very careful in these trampolines to not
	 * clobber any bits in it. That means no cmpqs or branches!
	 */
	ENTRY_NP(tr_sys_sysenter)
	swapgs
	mov	%r13, %gs:CPU_KPTI_R13
#if DEBUG
	mov	%cr3, %r13
	mov	%r13, %gs:CPU_KPTI_TR_CR3
#endif
	mov	%gs:CPU_KPTI_KCR3, %r13
	mov	%r13, %cr3
	mov	%gs:CPU_KPTI_R13, %r13
	jmp	_sys_sysenter_post_swapgs
	SET_SIZE(tr_sys_sysenter)

	ENTRY_NP(tr_brand_sys_sysenter)
	swapgs
	mov	%r13, %gs:CPU_KPTI_R13
#if DEBUG
	mov	%cr3, %r13
	mov	%r13, %gs:CPU_KPTI_TR_CR3
#endif
	mov	%gs:CPU_KPTI_KCR3, %r13
	mov	%r13, %cr3
	mov	%gs:CPU_KPTI_R13, %r13
	jmp	_brand_sys_sysenter_post_swapgs
	SET_SIZE(tr_brand_sys_sysenter)

#define	MK_SYSCALL_INT_TRAMPOLINE(isr)		\
	ENTRY_NP(tr_/**/isr);			\
	swapgs;					\
	mov	%r13, %gs:CPU_KPTI_R13;		\
	SET_KERNEL_CR3(%r13);			\
	mov	%gs:CPU_THREAD, %r13;		\
	mov	T_STACK(%r13), %r13;		\
	addq	$REGSIZE+MINFRAME, %r13;	\
	mov	%r13, %rsp;			\
	pushq	%gs:CPU_KPTI_SS;		\
	pushq	%gs:CPU_KPTI_RSP;		\
	pushq	%gs:CPU_KPTI_RFLAGS;		\
	pushq	%gs:CPU_KPTI_CS;		\
	pushq	%gs:CPU_KPTI_RIP;		\
	mov	%gs:CPU_KPTI_R13, %r13;		\
	SWAPGS;					\
	jmp	isr;				\
	SET_SIZE(tr_/**/isr)

	MK_SYSCALL_INT_TRAMPOLINE(brand_sys_syscall_int)
	MK_SYSCALL_INT_TRAMPOLINE(sys_syscall_int)

	/*
	 * Interrupt/trap return trampolines
	 */

.global	tr_intr_ret_start
tr_intr_ret_start:

	ENTRY_NP(tr_iret_auto)
	cmpq	$1, kpti_enable
	jne	tr_iret_kernel
	cmpw	$KCS_SEL, T_FRAMERET_CS(%rsp)
	je	tr_iret_kernel
	jmp	tr_iret_user
	SET_SIZE(tr_iret_auto)

	ENTRY_NP(tr_iret_kernel)
	/*
	 * Yes, this does nothing extra. But this way we know if we see iret
	 * elsewhere, then we've failed to properly consider trampolines there.
	 */
	iretq
	SET_SIZE(tr_iret_kernel)

	ENTRY_NP(tr_iret_user)
	cmpq	$1, kpti_enable
	jne	1f

	swapgs
	mov	%r13, %gs:CPU_KPTI_R13
	PIVOT_KPTI_STK(%r13)
	SET_USER_CR3(%r13)
	mov	%gs:CPU_KPTI_R13, %r13
	/* Zero these to make sure they didn't leak from a kernel trap */
	movq	$0, %gs:CPU_KPTI_R13
	movq	$0, %gs:CPU_KPTI_R14
	swapgs
1:
	iretq
	SET_SIZE(tr_iret_user)

.global	tr_intr_ret_end
tr_intr_ret_end:

	/*
	 * Interrupt/trap entry trampolines
	 */

	/* CPU pushed an error code, and ISR wants one */
#define	MK_INTR_TRAMPOLINE(isr)			\
	ENTRY_NP(tr_/**/isr);			\
	INTERRUPT_TRAMPOLINE;			\
	jmp	isr;				\
	SET_SIZE(tr_/**/isr)

	/* CPU didn't push an error code, and ISR doesn't want one */
#define	MK_INTR_TRAMPOLINE_NOERR(isr)		\
	ENTRY_NP(tr_/**/isr);			\
	push	$0;				\
	INTERRUPT_TRAMPOLINE_NOERR;		\
	jmp	isr;				\
	SET_SIZE(tr_/**/isr)

	/* CPU pushed an error code, and ISR wants one */
#define	MK_DBG_INTR_TRAMPOLINE(isr)	\
	ENTRY_NP(tr_/**/isr);			\
	DBG_INTERRUPT_TRAMPOLINE;		\
	jmp	isr;				\
	SET_SIZE(tr_/**/isr)

	/* CPU didn't push an error code, and ISR doesn't want one */
#define	MK_DBG_INTR_TRAMPOLINE_NOERR(isr)	\
	ENTRY_NP(tr_/**/isr);			\
	push	$0;				\
	DBG_INTERRUPT_TRAMPOLINE_NOERR;		\
	jmp	isr;				\
	SET_SIZE(tr_/**/isr)


	MK_INTR_TRAMPOLINE_NOERR(div0trap)
	MK_DBG_INTR_TRAMPOLINE_NOERR(dbgtrap)
	MK_DBG_INTR_TRAMPOLINE_NOERR(brktrap)
	MK_INTR_TRAMPOLINE_NOERR(ovflotrap)
	MK_INTR_TRAMPOLINE_NOERR(boundstrap)
	MK_INTR_TRAMPOLINE_NOERR(invoptrap)
	MK_INTR_TRAMPOLINE_NOERR(ndptrap)
	MK_INTR_TRAMPOLINE(invtsstrap)
	MK_INTR_TRAMPOLINE(segnptrap)
	MK_DBG_INTR_TRAMPOLINE(stktrap)
	MK_DBG_INTR_TRAMPOLINE(gptrap)
	MK_DBG_INTR_TRAMPOLINE(pftrap)
	MK_INTR_TRAMPOLINE_NOERR(resvtrap)
	MK_INTR_TRAMPOLINE_NOERR(ndperr)
	MK_INTR_TRAMPOLINE(achktrap)
	MK_INTR_TRAMPOLINE_NOERR(xmtrap)
	MK_INTR_TRAMPOLINE_NOERR(invaltrap)
	MK_INTR_TRAMPOLINE_NOERR(fasttrap)
	MK_INTR_TRAMPOLINE_NOERR(dtrace_ret)

	/*
	 * These are special because they can interrupt other traps, and
	 * each other. We don't need to pivot their stacks, because they have
	 * dedicated IST stack space, but we need to change %cr3.
	 */
	ENTRY_NP(tr_nmiint)
	pushq	%r13
	mov	kpti_safe_cr3, %r13
	mov	%r13, %cr3
	popq	%r13
	jmp	nmiint
	SET_SIZE(tr_nmiint)

#if !defined(__xpv)
	ENTRY_NP(tr_syserrtrap)
	/*
	 * If we got here we should always have a zero error code pushed.
	 * The INT $0x8 instr doesn't seem to push one, though, which we use
	 * as an emergency panic in the other trampolines. So adjust things
	 * here.
	 */
	cmpq	$0, (%rsp)
	je	1f
	pushq	$0
1:
	pushq	%r13
	mov	kpti_safe_cr3, %r13
	mov	%r13, %cr3
	popq	%r13
	jmp	syserrtrap
	SET_SIZE(tr_syserrtrap)
#endif

	ENTRY_NP(tr_mcetrap)
	pushq	%r13
	mov	kpti_safe_cr3, %r13
	mov	%r13, %cr3
	popq	%r13
	jmp	mcetrap
	SET_SIZE(tr_mcetrap)

	/*
	 * Interrupts start at 32
	 */
#define MKIVCT(n)			\
	ENTRY_NP(tr_ivct/**/n)		\
	push	$0;			\
	INTERRUPT_TRAMPOLINE;		\
	push	$n - 0x20;		\
	jmp	cmnint;			\
	SET_SIZE(tr_ivct/**/n)

	MKIVCT(32);	MKIVCT(33);	MKIVCT(34);	MKIVCT(35);
	MKIVCT(36);	MKIVCT(37);	MKIVCT(38);	MKIVCT(39);
	MKIVCT(40);	MKIVCT(41);	MKIVCT(42);	MKIVCT(43);
	MKIVCT(44);	MKIVCT(45);	MKIVCT(46);	MKIVCT(47);
	MKIVCT(48);	MKIVCT(49);	MKIVCT(50);	MKIVCT(51);
	MKIVCT(52);	MKIVCT(53);	MKIVCT(54);	MKIVCT(55);
	MKIVCT(56);	MKIVCT(57);	MKIVCT(58);	MKIVCT(59);
	MKIVCT(60);	MKIVCT(61);	MKIVCT(62);	MKIVCT(63);
	MKIVCT(64);	MKIVCT(65);	MKIVCT(66);	MKIVCT(67);
	MKIVCT(68);	MKIVCT(69);	MKIVCT(70);	MKIVCT(71);
	MKIVCT(72);	MKIVCT(73);	MKIVCT(74);	MKIVCT(75);
	MKIVCT(76);	MKIVCT(77);	MKIVCT(78);	MKIVCT(79);
	MKIVCT(80);	MKIVCT(81);	MKIVCT(82);	MKIVCT(83);
	MKIVCT(84);	MKIVCT(85);	MKIVCT(86);	MKIVCT(87);
	MKIVCT(88);	MKIVCT(89);	MKIVCT(90);	MKIVCT(91);
	MKIVCT(92);	MKIVCT(93);	MKIVCT(94);	MKIVCT(95);
	MKIVCT(96);	MKIVCT(97);	MKIVCT(98);	MKIVCT(99);
	MKIVCT(100);	MKIVCT(101);	MKIVCT(102);	MKIVCT(103);
	MKIVCT(104);	MKIVCT(105);	MKIVCT(106);	MKIVCT(107);
	MKIVCT(108);	MKIVCT(109);	MKIVCT(110);	MKIVCT(111);
	MKIVCT(112);	MKIVCT(113);	MKIVCT(114);	MKIVCT(115);
	MKIVCT(116);	MKIVCT(117);	MKIVCT(118);	MKIVCT(119);
	MKIVCT(120);	MKIVCT(121);	MKIVCT(122);	MKIVCT(123);
	MKIVCT(124);	MKIVCT(125);	MKIVCT(126);	MKIVCT(127);
	MKIVCT(128);	MKIVCT(129);	MKIVCT(130);	MKIVCT(131);
	MKIVCT(132);	MKIVCT(133);	MKIVCT(134);	MKIVCT(135);
	MKIVCT(136);	MKIVCT(137);	MKIVCT(138);	MKIVCT(139);
	MKIVCT(140);	MKIVCT(141);	MKIVCT(142);	MKIVCT(143);
	MKIVCT(144);	MKIVCT(145);	MKIVCT(146);	MKIVCT(147);
	MKIVCT(148);	MKIVCT(149);	MKIVCT(150);	MKIVCT(151);
	MKIVCT(152);	MKIVCT(153);	MKIVCT(154);	MKIVCT(155);
	MKIVCT(156);	MKIVCT(157);	MKIVCT(158);	MKIVCT(159);
	MKIVCT(160);	MKIVCT(161);	MKIVCT(162);	MKIVCT(163);
	MKIVCT(164);	MKIVCT(165);	MKIVCT(166);	MKIVCT(167);
	MKIVCT(168);	MKIVCT(169);	MKIVCT(170);	MKIVCT(171);
	MKIVCT(172);	MKIVCT(173);	MKIVCT(174);	MKIVCT(175);
	MKIVCT(176);	MKIVCT(177);	MKIVCT(178);	MKIVCT(179);
	MKIVCT(180);	MKIVCT(181);	MKIVCT(182);	MKIVCT(183);
	MKIVCT(184);	MKIVCT(185);	MKIVCT(186);	MKIVCT(187);
	MKIVCT(188);	MKIVCT(189);	MKIVCT(190);	MKIVCT(191);
	MKIVCT(192);	MKIVCT(193);	MKIVCT(194);	MKIVCT(195);
	MKIVCT(196);	MKIVCT(197);	MKIVCT(198);	MKIVCT(199);
	MKIVCT(200);	MKIVCT(201);	MKIVCT(202);	MKIVCT(203);
	MKIVCT(204);	MKIVCT(205);	MKIVCT(206);	MKIVCT(207);
	MKIVCT(208);	MKIVCT(209);	MKIVCT(210);	MKIVCT(211);
	MKIVCT(212);	MKIVCT(213);	MKIVCT(214);	MKIVCT(215);
	MKIVCT(216);	MKIVCT(217);	MKIVCT(218);	MKIVCT(219);
	MKIVCT(220);	MKIVCT(221);	MKIVCT(222);	MKIVCT(223);
	MKIVCT(224);	MKIVCT(225);	MKIVCT(226);	MKIVCT(227);
	MKIVCT(228);	MKIVCT(229);	MKIVCT(230);	MKIVCT(231);
	MKIVCT(232);	MKIVCT(233);	MKIVCT(234);	MKIVCT(235);
	MKIVCT(236);	MKIVCT(237);	MKIVCT(238);	MKIVCT(239);
	MKIVCT(240);	MKIVCT(241);	MKIVCT(242);	MKIVCT(243);
	MKIVCT(244);	MKIVCT(245);	MKIVCT(246);	MKIVCT(247);
	MKIVCT(248);	MKIVCT(249);	MKIVCT(250);	MKIVCT(251);
	MKIVCT(252);	MKIVCT(253);	MKIVCT(254);	MKIVCT(255);

	/*
	 * We're PCIDE, but we don't have INVPCID.  The only way to invalidate a
	 * PCID other than the current one, then, is to load its cr3 then
	 * invlpg.  But loading kf_user_cr3 means we can longer access our
	 * caller's text mapping (or indeed, its stack).  So this little helper
	 * has to live within our trampoline text region.
	 *
	 * Called as tr_mmu_flush_user_range(addr, len, pgsz, cr3)
	 */
	ENTRY_NP(tr_mmu_flush_user_range)
	push	%rbx
	/* When we read cr3, it never has the NOINVL bit set. */
	mov	%cr3, %rax
	movq	$CR3_NOINVL_BIT, %rbx
	orq	%rbx, %rax

	mov	%rcx, %cr3
	add	%rdi, %rsi
.align	ASM_ENTRY_ALIGN
1:
	invlpg	(%rdi)
	add	%rdx, %rdi
	cmp	%rsi, %rdi
	jb	1b
	mov	%rax, %cr3
	pop	%rbx
	retq
	SET_SIZE(tr_mmu_flush_user_range)

.align MMU_PAGESIZE
.global kpti_tramp_end
kpti_tramp_end:
	nop

#endif	/* __lint */
