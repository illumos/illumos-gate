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
 * Copyright 2019 Joyent, Inc.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*	  All Rights Reserved					*/


#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/reboot.h>
#include <sys/x86_archext.h>
#include <sys/machparam.h>

#include <sys/segments.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/cmn_err.h>
#include <sys/pit.h>
#include <sys/panic.h>

#if defined(__xpv)
#include <sys/hypervisor.h>
#endif

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
	 * The very first thing in the kernel's text segment must be a jump
	 * to the os/fakebop.c startup code.
	 */
	.text
	jmp     _start

	/*
	 * Globals:
	 */
	.globl	_locore_start
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


	/*
	 * kobj_init() vectors us back to here with (note) a slightly different
	 * set of arguments than _start is given (see lint prototypes above).
	 *
	 * XXX	Make this less vile, please.
	 */
	ENTRY_NP(_locore_start)

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

#if !defined(__xpv)
	/*
	 * Enable write protect and alignment check faults.
	 */
	movq	%cr0, %rax
	orq	$_CONST(CR0_WP|CR0_AM), %rax
	andq	$_BITNOT(CR0_WT|CR0_CE), %rax
	movq	%rax, %cr0
#endif	/* __xpv */

	/*
	 * (We just assert this works by virtue of being here)
	 */
	bts	$X86FSET_CPUID, x86_featureset(%rip)

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
	SET_SIZE(_locore_start)

__return_from_main:
	.string	"main() returned"
__unsupported_cpu:
	.string	"486 style cpu detected - no longer supported!"

#if defined(DEBUG)
_no_pending_updates:
	.string	"locore.s:%d lwp_rtt(lwp %p) but pcb_rupdate != 1"
#endif

/*
 *  For stack layout, see privregs.h
 *  When cmntrap gets called, the error code and trap number have been pushed.
 *  When cmntrap_pushed gets called, the entire struct regs has been pushed.
 */

	.globl	trap		/* C handler called below */

	ENTRY_NP2(cmntrap, _cmntrap)

	INTR_PUSH

	ALTENTRY(cmntrap_pushed)

	movq	%rsp, %rbp

	/*
	 * - if this is a #pf i.e. T_PGFLT, %r15 is live
	 *   and contains the faulting address i.e. a copy of %cr2
	 *
	 * - if this is a #db i.e. T_SGLSTP, %r15 is live
	 *   and contains the value of %db6
	 */

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	/*
	 * We must first check if DTrace has set its NOFAULT bit.  This
	 * regrettably must happen before the trap stack is recorded, because
	 * this requires a call to getpcstack() and may induce recursion if an
	 * fbt::getpcstack: enabling is inducing the bad load.
	 */
	movl	%gs:CPU_ID, %eax
	shlq	$CPU_CORE_SHIFT, %rax
	leaq	cpu_core(%rip), %r8
	addq	%r8, %rax
	movw	CPUC_DTRACE_FLAGS(%rax), %cx
	testw	$CPU_DTRACE_NOFAULT, %cx
	jnz	.dtrace_induced

	TRACE_STACK(%rdi)

	movq	%rbp, %rdi
	movq	%r15, %rsi
	movl	%gs:CPU_ID, %edx

	/*
	 * We know that this isn't a DTrace non-faulting load; we can now safely
	 * reenable interrupts.  (In the case of pagefaults, we enter through an
	 * interrupt gate.)
	 */
	ENABLE_INTR_FLAGS

	call	trap		/* trap(rp, addr, cpuid) handles all traps */
	jmp	_sys_rtt

.dtrace_induced:
	cmpw	$KCS_SEL, REGOFF_CS(%rbp)	/* test CS for user-mode trap */
	jne	3f				/* if from user, panic */

	cmpl	$T_PGFLT, REGOFF_TRAPNO(%rbp)
	je	1f

	cmpl	$T_GPFLT, REGOFF_TRAPNO(%rbp)
	je	0f

	cmpl	$T_ILLINST, REGOFF_TRAPNO(%rbp)
	je	0f

	cmpl	$T_ZERODIV, REGOFF_TRAPNO(%rbp)
	jne	4f				/* if not PF/GP/UD/DE, panic */

	orw	$CPU_DTRACE_DIVZERO, %cx
	movw	%cx, CPUC_DTRACE_FLAGS(%rax)
	jmp	2f

	/*
	 * If we've taken a GPF, we don't (unfortunately) have the address that
	 * induced the fault.  So instead of setting the fault to BADADDR,
	 * we'll set the fault to ILLOP.
	 */
0:
	orw	$CPU_DTRACE_ILLOP, %cx
	movw	%cx, CPUC_DTRACE_FLAGS(%rax)
	jmp	2f
1:
	orw	$CPU_DTRACE_BADADDR, %cx
	movw	%cx, CPUC_DTRACE_FLAGS(%rax)	/* set fault to bad addr */
	movq	%r15, CPUC_DTRACE_ILLVAL(%rax)
					    /* fault addr is illegal value */
2:
	movq	REGOFF_RIP(%rbp), %rdi
	movq	%rdi, %r12
	call	dtrace_instr_size
	addq	%rax, %r12
	movq	%r12, REGOFF_RIP(%rbp)
	INTR_POP
	call	x86_md_clear
	jmp	tr_iret_auto
	/*NOTREACHED*/
3:
	leaq	dtrace_badflags(%rip), %rdi
	xorl	%eax, %eax
	call	panic
4:
	leaq	dtrace_badtrap(%rip), %rdi
	xorl	%eax, %eax
	call	panic
	SET_SIZE(cmntrap_pushed)
	SET_SIZE(cmntrap)
	SET_SIZE(_cmntrap)

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

	.globl	trap		/* C handler called below */

	ENTRY_NP(cmninttrap)

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	movq	%rsp, %rbp

	movl	%gs:CPU_ID, %edx
	xorl	%esi, %esi
	movq	%rsp, %rdi
	call	trap		/* trap(rp, addr, cpuid) handles all traps */
	jmp	_sys_rtt
	SET_SIZE(cmninttrap)

#if !defined(__xpv)
	/*
	 * Handle traps early in boot. Just revectors into C quickly as
	 * these are always fatal errors.
	 *
	 * Adjust %rsp to get same stack layout as in 32bit mode for bop_trap().
	 */
	ENTRY(bop_trap_handler)
	movq	%rsp, %rdi
	sub	$8, %rsp
	call	bop_trap
	SET_SIZE(bop_trap_handler)
#endif

	.globl	dtrace_user_probe

	ENTRY_NP(dtrace_trap)

	INTR_PUSH

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_TRAP) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	movq	%rsp, %rbp

	movl	%gs:CPU_ID, %edx
#if defined(__xpv)
	movq	%gs:CPU_VCPU_INFO, %rsi
	movq	VCPU_INFO_ARCH_CR2(%rsi), %rsi
#else
	movq	%cr2, %rsi
#endif
	movq	%rsp, %rdi

	ENABLE_INTR_FLAGS

	call	dtrace_user_probe /* dtrace_user_probe(rp, addr, cpuid) */
	jmp	_sys_rtt

	SET_SIZE(dtrace_trap)

/*
 * Return from _sys_trap routine.
 */

	ENTRY_NP(lwp_rtt_initial)
	movq	%gs:CPU_THREAD, %r15
	movq	T_STACK(%r15), %rsp	/* switch to the thread stack */
	movq	%rsp, %rbp
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
	movq	%rsp, %rbp
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
	 * pcb_rupdate being set to 1, we'd end up sampling the hardware
	 * state left by the previous running lwp, rather than setting
	 * the values requested by the lwp creator.  Bad.
	 */
	testb	$0x1, PCB_RUPDATE(%r14)
	jne	1f
	leaq	_no_pending_updates(%rip), %rdi
	movl	$__LINE__, %esi
	movq	%r14, %rdx
	xorl	%eax, %eax
	call	panic
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

	/*
	 * XXX - may want a fast path that avoids sys_rtt_common in the
	 * most common case.
	 */
	ALTENTRY(_sys_rtt)
	CLI(%rax)			/* disable interrupts */
	ALTENTRY(_sys_rtt_ints_disabled)
	movq	%rsp, %rdi		/* pass rp to sys_rtt_common */
	call	sys_rtt_common		/* do common sys_rtt tasks */
	testq	%rax, %rax		/* returning to userland? */
	jz	sr_sup

	/*
	 * Return to user
	 */
	ASSERT_UPCALL_MASK_IS_SET
	cmpw	$UCS_SEL, REGOFF_CS(%rsp) /* test for native (64-bit) lwp? */
	je	sys_rtt_syscall

	/*
	 * Return to 32-bit userland
	 */
	ALTENTRY(sys_rtt_syscall32)
	USER32_POP
	call	x86_md_clear
	jmp	tr_iret_user
	/*NOTREACHED*/

	ALTENTRY(sys_rtt_syscall)
	/*
	 * Return to 64-bit userland
	 */
	USER_POP
	ALTENTRY(nopop_sys_rtt_syscall)
	call	x86_md_clear
	jmp	tr_iret_user
	/*NOTREACHED*/
	SET_SIZE(nopop_sys_rtt_syscall)

	/*
	 * Return to supervisor
	 * NOTE: to make the check in trap() that tests if we are executing
	 * segment register fixup/restore code work properly, sr_sup MUST be
	 * after _sys_rtt .
	 */
	ALTENTRY(sr_sup)
	/*
	 * Restore regs before doing iretq to kernel mode
	 */
	INTR_POP
	jmp	tr_iret_kernel
	.globl	_sys_rtt_end
_sys_rtt_end:
	/*NOTREACHED*/
	SET_SIZE(sr_sup)
	SET_SIZE(_sys_rtt_end)
	SET_SIZE(lwp_rtt)
	SET_SIZE(lwp_rtt_initial)
	SET_SIZE(_sys_rtt_ints_disabled)
	SET_SIZE(_sys_rtt)
	SET_SIZE(sys_rtt_syscall)
	SET_SIZE(sys_rtt_syscall32)

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

	popq	%rbx
	leaveq
	ret
	SET_SIZE(freq_tsc)

