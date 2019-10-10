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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include <sys/intreg.h>
#include <sys/ivintr.h>
#include <sys/mmu.h>
#include <sys/machpcb.h>
#include <sys/machtrap.h>
#include <sys/machlock.h>
#include <sys/fdreg.h>
#include <sys/vis.h>
#include <sys/traptrace.h>
#include <sys/panic.h>
#include <sys/machasi.h>
#include <sys/clock.h>
#include <vm/hat_sfmmu.h>

#include "assym.h"


!
! REGOFF must add up to allow double word access to r_tstate.
! PCB_WBUF must also be aligned.
!
#if (REGOFF & 7) != 0
#error "struct regs not aligned"
#endif

/*
 * Absolute external symbols.
 * On the sun4u we put the panic buffer in the third and fourth pages.
 * We set things up so that the first 2 pages of KERNELBASE is illegal
 * to act as a redzone during copyin/copyout type operations. One of
 * the reasons the panic buffer is allocated in low memory to
 * prevent being overwritten during booting operations (besides
 * the fact that it is small enough to share pages with others).
 */

	.seg	".data"
	.global	panicbuf

PROM	= 0xFFE00000			! address of prom virtual area
panicbuf = SYSBASE32 + PAGESIZE		! address of panic buffer

	.type	panicbuf, #object
	.size	panicbuf, PANICBUFSIZE

/*
 * Absolute external symbol - intr_vec_table.
 *
 * With new bus structures supporting a larger number of interrupt
 * numbers, the interrupt vector table, intr_vec_table[] has been
 * moved out of kernel nucleus and allocated after panicbuf.
 */
	.global intr_vec_table

intr_vec_table = SYSBASE32 + PAGESIZE + PANICBUFSIZE ! address of interrupt table

	.type	intr_vec_table, #object
	.size	intr_vec_table, MAXIVNUM * CPTRSIZE + MAX_RSVD_IV * IV_SIZE + MAX_RSVD_IVX * (IV_SIZE + CPTRSIZE * (NCPU - 1))

/*
 * The thread 0 stack. This must be the first thing in the data
 * segment (other than an sccs string) so that we don't stomp
 * on anything important if the stack overflows. We get a
 * red zone below this stack for free when the kernel text is
 * write protected.
 */

	.global	t0stack
	.align	16
	.type	t0stack, #object
t0stack:
	.skip	T0STKSZ			! thread 0 stack
t0stacktop:
	.size	t0stack, T0STKSZ

/*
 * cpu0 and its ptl1_panic stack.  The cpu structure must be allocated
 * on a single page for ptl1_panic's physical address accesses.
 */
	.global	cpu0
	.align	MMU_PAGESIZE
cpu0:
	.type	cpu0, #object
	.skip	CPU_ALLOC_SIZE
	.size	cpu0, CPU_ALLOC_SIZE

	.global t0
	.align	PTR24_ALIGN		! alignment for mutex.
	.type	t0, #object
t0:
	.skip	THREAD_SIZE		! thread 0
	.size	t0, THREAD_SIZE

#ifdef	TRAPTRACE
	.global	trap_trace_ctl
	.global	trap_tr0
	.global trap_trace_bufsize
	.global	trap_freeze
	.global	trap_freeze_pc

	.align	4
trap_trace_bufsize:
	.word	TRAP_TSIZE		! default trap buffer size
trap_freeze:
	.word	0

	.align	64
trap_trace_ctl:
	.skip	NCPU * TRAPTR_SIZE	! NCPU control headers

	.align	16
trap_tr0:
	.skip	TRAP_TSIZE		! one buffer for the boot cpu

/*
 * When an assertion in TRACE_PTR was failed, %pc is saved in trap_freeze_pc to
 * show in which TRACE_PTR the assertion failure happened.
 */
	.align	8
trap_freeze_pc:
	.nword	0
#endif	/* TRAPTRACE */

	.align 4
	.seg	".text"

#ifdef	NOPROM
	.global availmem
availmem:
	.word	0
#endif	/* NOPROM */

	.align	8
_local_p1275cis:
	.nword	0

	.seg	".data"

	.global nwindows, nwin_minus_one, winmask
nwindows:
	.word   8
nwin_minus_one:
	.word   7
winmask:
	.word	8

	.global	afsrbuf
afsrbuf:
	.word	0,0,0,0

/*
 * System initialization
 *
 * Our contract with the boot prom specifies that the MMU is on and the
 * first 16 meg of memory is mapped with a level-1 pte.  We are called
 * with p1275cis ptr in %o0 and kdi_dvec in %o1; we start execution
 * directly from physical memory, so we need to get up into our proper 
 * addresses quickly: all code before we do this must be position 
 * independent.
 *
 * NB: Above is not true for boot/stick kernel, the only thing mapped is
 * the text+data+bss. The kernel is loaded directly into KERNELBASE.
 *
 * 	entry, the romvec pointer (romp) is the first argument;
 * 	  i.e., %o0.
 * 	the bootops vector is in the third argument (%o1)
 *
 * Our tasks are:
 * 	save parameters
 * 	construct mappings for KERNELBASE (not needed for boot/stick kernel)
 * 	hop up into high memory           (not needed for boot/stick kernel)
 * 	initialize stack pointer
 * 	initialize trap base register
 * 	initialize window invalid mask
 * 	initialize psr (with traps enabled)
 * 	figure out all the module type stuff
 * 	tear down the 1-1 mappings
 * 	dive into main()
 */
	ENTRY_NP(_start)
	!
	! Stash away our arguments in memory.
	!
	sethi	%hi(_local_p1275cis), %g1
	stn	%o4, [%g1 + %lo(_local_p1275cis)]

	!
	! Initialize CPU state registers
	!
	wrpr	%g0, PSTATE_KERN, %pstate
	wr	%g0, %g0, %fprs

	!
	! call krtld to link the world together
	!
	call	kobj_start
	mov	%o4, %o0

	CLEARTICKNPT			! allow user rdtick
	!
	! Get maxwin from %ver
	!
	rdpr	%ver, %g1
	and	%g1, VER_MAXWIN, %g1

	!
	! Stuff some memory cells related to numbers of windows.
	!
	sethi	%hi(nwin_minus_one), %g2
	st	%g1, [%g2 + %lo(nwin_minus_one)]
	inc	%g1
	sethi	%hi(nwindows), %g2
	st	%g1, [%g2 + %lo(nwindows)]
	dec	%g1
	mov	-2, %g2
	sll	%g2, %g1, %g2
	sethi	%hi(winmask), %g4
	st	%g2, [%g4 + %lo(winmask)]

	!
	! save a pointer to obp's tba for later use by kmdb
	!
	rdpr	%tba, %g1
	set	boot_tba, %g2
	stx	%g1, [%g2]

	!
	! copy obp's breakpoint trap entry to obp_bpt
	!
	rdpr	%tba, %g1
	set	T_SOFTWARE_TRAP | ST_MON_BREAKPOINT, %g2
	sll	%g2, 5, %g2
	or	%g1, %g2, %g1
	set	obp_bpt, %g2
	ldx	[%g1], %g3
	stx	%g3, [%g2]
	flush	%g2
	ldx	[%g1 + 8], %g3
	stx	%g3, [%g2 + 8]
	flush	%g2 + 8
	ldx	[%g1 + 16], %g3
	stx	%g3, [%g2 + 16]
	flush	%g2 + 16
	ldx	[%g1 + 24], %g3
	stx	%g3, [%g2 + 24]
	flush	%g2 + 24

	!
	! Initialize thread 0's stack.
	!
	set	t0stacktop, %g1		! setup kernel stack pointer
	sub	%g1, SA(KFPUSIZE+GSR_SIZE), %g2
	and	%g2, 0x3f, %g3
	sub	%g2, %g3, %o1
	sub	%o1, SA(MPCBSIZE) + STACK_BIAS, %sp

	!
	! Initialize global thread register.
	!
	set	t0, THREAD_REG

	!
	! Fill in enough of the cpu structure so that
	! the wbuf management code works. Make sure the
	! boot cpu is inserted in cpu[] based on cpuid.
	!
	CPU_INDEX(%g2, %g1)
	sll	%g2, CPTRSHIFT, %g2		! convert cpuid to cpu[] offset
	set	cpu0, %o0			! &cpu0
	set	cpu, %g1			! &cpu[]
	stn	%o0, [%g1 + %g2]		! cpu[cpuid] = &cpu0

	stn	%o0, [THREAD_REG + T_CPU]	! threadp()->t_cpu = cpu[cpuid]
	stn	THREAD_REG, [%o0 + CPU_THREAD]	! cpu[cpuid]->cpu_thread = threadp()


	!  We do NOT need to bzero our BSS...boot has already done it for us.
	!  Just need to reference edata so that we don't break /dev/ksyms
	set	edata, %g0

	!
	! Call mlsetup with address of prototype user registers.
	!
	call	mlsetup
	add	%sp, REGOFF + STACK_BIAS, %o0

#if (REGOFF != MPCB_REGS)
#error "hole in struct machpcb between frame and regs?"
#endif

	!
	! Now call main.  We will return as process 1 (init).
	!
	call	main
	nop

	!
	! Main should never return.
	!
	set	.mainretmsg, %o0
	call	panic
	nop
	SET_SIZE(_start)

.mainretmsg:
	.asciz	"main returned"
	.align	4


/*
 * Generic system trap handler.
 *
 * Some kernel trap handlers save themselves from buying a window by
 * borrowing some of sys_trap's unused locals. %l0 thru %l3 may be used
 * for this purpose, as user_rtt and priv_rtt do not depend on them.
 * %l4 thru %l7 should NOT be used this way.
 *
 * Entry Conditions:
 * 	%pstate		am:0 priv:1 ie:0
 * 			globals are either ag or ig (not mg!)
 *
 * Register Inputs:
 * 	%g1		pc of trap handler
 * 	%g2, %g3	args for handler
 * 	%g4		desired %pil (-1 means current %pil)
 * 	%g5, %g6	destroyed
 * 	%g7		saved
 *
 * Register Usage:
 * 	%l0, %l1	temps
 * 	%l3		saved %g1
 * 	%l6		curthread for user traps, %pil for priv traps
 * 	%l7		regs
 *
 * Called function prototype variants:
 *
 *	func(struct regs *rp);
 * 	func(struct regs *rp, uintptr_t arg1 [%g2], uintptr_t arg2 [%g3])
 *	func(struct regs *rp, uintptr_t arg1 [%g2],
 *	    uint32_t arg2 [%g3.l], uint32_t arg3 [%g3.h])
 *	func(struct regs *rp, uint32_t arg1 [%g2.l],
 *	    uint32_t arg2 [%g3.l], uint32_t arg3 [%g3.h], uint32_t [%g2.h])
 */

	ENTRY_NP(sys_trap)
	!
	! force tl=1, update %cwp, branch to correct handler
	!
	wrpr	%g0, 1, %tl
	rdpr	%tstate, %g5
	btst	TSTATE_PRIV, %g5
	and	%g5, TSTATE_CWP, %g6
	bnz,pn	%xcc, priv_trap
	wrpr	%g0, %g6, %cwp

	ALTENTRY(user_trap)
	!
	! user trap
	!
	! make all windows clean for kernel
	! buy a window using the current thread's stack
	!
	sethi	%hi(nwin_minus_one), %g5
	ld	[%g5 + %lo(nwin_minus_one)], %g5
	wrpr	%g0, %g5, %cleanwin
	CPU_ADDR(%g5, %g6)
	ldn	[%g5 + CPU_THREAD], %g5
	ldn	[%g5 + T_STACK], %g6
	sub	%g6, STACK_BIAS, %g6
	save	%g6, 0, %sp
	!
	! set window registers so that current windows are "other" windows
	!
	rdpr	%canrestore, %l0
	rdpr	%wstate, %l1
	wrpr	%g0, 0, %canrestore
	sllx	%l1, WSTATE_SHIFT, %l1
	wrpr	%l1, WSTATE_K64, %wstate
	wrpr	%g0, %l0, %otherwin
	!
	! set pcontext to run kernel
	!
	sethi	%hi(kcontextreg), %l0
	ldx     [%l0 + %lo(kcontextreg)], %l0
	mov	MMU_PCONTEXT, %l1	! if kcontextreg==PCONTEXT, do nothing
	ldxa	[%l1]ASI_MMU_CTX, %l2
	xor	%l0, %l2, %l2
	srlx	%l2, CTXREG_NEXT_SHIFT, %l2
	brz	%l2, 2f			! if N_pgsz0/1 changed, need demap
	sethi	%hi(FLUSH_ADDR), %l3
	mov	DEMAP_ALL_TYPE, %l2
	stxa	%g0, [%l2]ASI_DTLB_DEMAP
	stxa	%g0, [%l2]ASI_ITLB_DEMAP
2:
	stxa	%l0, [%l1]ASI_MMU_CTX
	flush	%l3			! flush required by immu
1:

	set	utl0, %g6		! bounce to utl0
have_win:
	SYSTRAP_TRACE(%o1, %o2, %o3)


	!
	! at this point we have a new window we can play in,
	! and %g6 is the label we want done to bounce to
	!
	! save needed current globals
	!
	mov	%g1, %l3	! pc
	mov	%g2, %o1	! arg #1
	mov	%g3, %o2	! arg #2
	srlx	%g3, 32, %o3	! pseudo arg #3
	srlx	%g2, 32, %o4	! pseudo arg #4
	mov	%g5, %l6	! curthread if user trap, %pil if priv trap
	!
	! save trap state on stack
	!
	add	%sp, REGOFF + STACK_BIAS, %l7
	rdpr	%tpc, %l0
	rdpr	%tnpc, %l1
	rdpr	%tstate, %l2
	stn	%l0, [%l7 + PC_OFF]
	stn	%l1, [%l7 + nPC_OFF]
	stx	%l2, [%l7 + TSTATE_OFF]
	!
	! setup pil
	!
	brlz,pt		%g4, 1f
	nop
#ifdef DEBUG
	!
	! ASSERT(%g4 >= %pil).
	!
	rdpr	%pil, %l0
	cmp	%g4, %l0
	bge,pt	%xcc, 0f
	nop				! yes, nop; to avoid anull
	set	bad_g4_called, %l3
	mov	1, %o1
	st	%o1, [%l3]
	set	bad_g4, %l3		! pc
	set	sys_trap_wrong_pil, %o1	! arg #1
	mov	%g4, %o2		! arg #2
	ba	1f			! stay at the current %pil
	mov	%l0, %o3		! arg #3
0:
#endif /* DEBUG */
	wrpr		%g0, %g4, %pil
1:
	!
	! set trap regs to execute in kernel at %g6
	! done resumes execution there
	!
	wrpr	%g0, %g6, %tnpc
	rdpr	%cwp, %l0
	set	TSTATE_KERN, %l1
	wrpr	%l1, %l0, %tstate
	done
	/* NOTREACHED */
	SET_SIZE(user_trap)
	SET_SIZE(sys_trap)


	ENTRY_NP(prom_trap)
	!
	! prom trap switches the stack to 32-bit
	! if we took a trap from a 64-bit window
	! Then buys a window on the current stack.
	!
	save	%sp, -SA64(REGOFF + REGSIZE), %sp
					/* 32 bit frame, 64 bit sized */
	set	ptl0, %g6
	ba,a,pt	%xcc, have_win
	SET_SIZE(prom_trap)

	ENTRY_NP(priv_trap)
	!
	! kernel trap
	! buy a window on the current stack
	!
	! is the trap PC in the range allocated to Open Firmware?
	rdpr	%tpc, %g5
	set	OFW_END_ADDR, %g6
	cmp	%g5, %g6
	bgu,a,pn %xcc, 1f
	  rdpr	%pil, %g5
	set	OFW_START_ADDR, %g6
	cmp	%g5, %g6
	bgeu,pn	%xcc, prom_trap
	  rdpr	%pil, %g5
1:
	!
	! check if the primary context is of kernel.
	!
	mov     MMU_PCONTEXT, %g6
	ldxa    [%g6]ASI_MMU_CTX, %g5
	sllx    %g5, CTXREG_CTX_SHIFT, %g5      ! keep just the ctx bits
	brnz,pn %g5, 2f				! assumes KCONTEXT == 0
	  rdpr  %pil, %g5
	!
	! primary context is of kernel.
	!
        set     ktl0, %g6
        save    %sp, -SA(REGOFF + REGSIZE), %sp
        ba,a,pt %xcc, have_win
2:
	!
	! primary context is of user. caller of sys_trap()
	! or priv_trap() did not set kernel context. raise
	! trap level to MAXTL-1 so that ptl1_panic() prints
	! out all levels of trap data.
	!
	rdpr	%ver, %g5
	srlx	%g5, VER_MAXTL_SHIFT, %g5
	and	%g5, VER_MAXTL_MASK, %g5	! %g5 = MAXTL
	sub	%g5, 1, %g5
	wrpr	%g0, %g5, %tl
	mov	PTL1_BAD_CTX, %g1
	ba,a,pt	%xcc, ptl1_panic
	SET_SIZE(priv_trap)

	ENTRY_NP(utl0)
	SAVE_GLOBALS(%l7)
	SAVE_OUTS(%l7)
	mov	%l6, THREAD_REG
	wrpr	%g0, PSTATE_KERN, %pstate	! enable ints
	jmpl	%l3, %o7			! call trap handler
	mov	%l7, %o0
	!
	ALTENTRY(user_rtt)
	!
	! Register inputs
	!	%l7 - regs
	!
	! disable interrupts and check for ASTs and wbuf restores
	! keep cpu_base_spl in %l4 and THREAD_REG in %l6 (needed
	! in wbuf.s when globals have already been restored).
	!
	wrpr	%g0, PIL_MAX, %pil
	ldn	[THREAD_REG + T_CPU], %l0
	ld	[%l0 + CPU_BASE_SPL], %l4

	ldub	[THREAD_REG + T_ASTFLAG], %l2
	brz,pt	%l2, 1f
	ld	[%sp + STACK_BIAS + MPCB_WBCNT], %l3
	!
	! call trap to do ast processing
	!
	wrpr	%g0, %l4, %pil			! pil = cpu_base_spl
	mov	%l7, %o0
	call	trap
	  mov	T_AST, %o2
	ba,a,pt	%xcc, user_rtt
1:
	brz,pt	%l3, 2f
	mov	THREAD_REG, %l6
	!
	! call restore_wbuf to push wbuf windows to stack
	!
	wrpr	%g0, %l4, %pil			! pil = cpu_base_spl
	mov	%l7, %o0
	call	trap
	  mov	T_FLUSH_PCB, %o2
	ba,a,pt	%xcc, user_rtt
2:
#ifdef TRAPTRACE
	TRACE_RTT(TT_SYS_RTT_USER, %l0, %l1, %l2, %l3)
#endif /* TRAPTRACE */
	ld	[%sp + STACK_BIAS + MPCB_WSTATE], %l3	! get wstate

	!
	! restore user globals and outs
	!
	rdpr	%pstate, %l1
	wrpr	%l1, PSTATE_IE, %pstate
	RESTORE_GLOBALS(%l7)
	! switch to alternate globals, saving THREAD_REG in %l6
	wrpr	%l1, PSTATE_IE | PSTATE_AG, %pstate
	mov	%sp, %g6	! remember the mpcb pointer in %g6
	RESTORE_OUTS(%l7)
	!
	! set %pil from cpu_base_spl
	!
	wrpr	%g0, %l4, %pil
	!
	! raise tl (now using nucleus context)
	!
	wrpr	%g0, 1, %tl

	! switch "other" windows back to "normal" windows.
	rdpr	%otherwin, %g1
	wrpr	%g0, 0, %otherwin
	add	%l3, WSTATE_CLEAN_OFFSET, %l3	! convert to "clean" wstate
	wrpr	%g0, %l3, %wstate
	wrpr	%g0, %g1, %canrestore

	! set pcontext to scontext for user execution
	mov	MMU_SCONTEXT, %g3
	ldxa	[%g3]ASI_MMU_CTX, %g2

	mov	MMU_PCONTEXT, %g3
	ldxa    [%g3]ASI_MMU_CTX, %g4		! need N_pgsz0/1 bits
        srlx    %g4, CTXREG_NEXT_SHIFT, %g4
        sllx    %g4, CTXREG_NEXT_SHIFT, %g4
        or      %g4, %g2, %g2                   ! Or in Nuc pgsz bits

	sethi	%hi(FLUSH_ADDR), %g4
	stxa	%g2, [%g3]ASI_MMU_CTX
	flush	%g4				! flush required by immu
	!
	! Within the code segment [rtt_ctx_start - rtt_ctx_end],
	! PCONTEXT is set to run user code. If a trap happens in this
	! window, and the trap needs to be handled at TL=0, the handler
	! must make sure to set PCONTEXT to run kernel. A convenience
	! macro, RESET_USER_RTT_REGS(scr1, scr2, label) is available to
	! TL>1 handlers for this purpose.
	!
	! %g1 = %canrestore
	! %l7 = regs
	! %g6 = mpcb
	!
	.global	rtt_ctx_start
rtt_ctx_start:
	!
	! setup trap regs
	!
	ldn	[%l7 + PC_OFF], %g3
	ldn	[%l7 + nPC_OFF], %g2
	ldx	[%l7 + TSTATE_OFF], %l0
	andn	%l0, TSTATE_CWP, %g7
	wrpr	%g3, %tpc
	wrpr	%g2, %tnpc

	!
	! Restore to window we originally trapped in.
	! First attempt to restore from the watchpoint saved register window
	!
	tst	%g1
	bne,a	1f
	  clrn	[%g6 + STACK_BIAS + MPCB_RSP0]
	tst	%fp
	be,a	1f
	  clrn	[%g6 + STACK_BIAS + MPCB_RSP0]
	! test for user return window in pcb
	ldn	[%g6 + STACK_BIAS + MPCB_RSP0], %g1
	cmp	%fp, %g1
	bne	1f
	  clrn	[%g6 + STACK_BIAS + MPCB_RSP0]
	restored
	restore
	! restore from user return window
	RESTORE_V9WINDOW(%g6 + STACK_BIAS + MPCB_RWIN0)
	!
	! Attempt to restore from the scond watchpoint saved register window
	tst	%fp
	be,a	2f
	  clrn	[%g6 + STACK_BIAS + MPCB_RSP1]
	ldn	[%g6 + STACK_BIAS + MPCB_RSP1], %g1
	cmp	%fp, %g1
	bne	2f
	  clrn	[%g6 + STACK_BIAS + MPCB_RSP1]
	restored
	restore
	RESTORE_V9WINDOW(%g6 + STACK_BIAS + MPCB_RWIN1)
	save
	b,a	2f
1:
	restore				! should not trap
2:
	!
	! set %cleanwin to %canrestore
	! set %tstate to the correct %cwp
	! retry resumes user execution
	!
	rdpr	%canrestore, %g1
	wrpr	%g0, %g1, %cleanwin
	rdpr	%cwp, %g1
	wrpr	%g1, %g7, %tstate
	retry
	.global	rtt_ctx_end
rtt_ctx_end:
	/* NOTREACHED */
	SET_SIZE(user_rtt)
	SET_SIZE(utl0)

	ENTRY_NP(ptl0)
	SAVE_GLOBALS(%l7)
	SAVE_OUTS(%l7)
	CPU_ADDR(%g5, %g6)
	ldn	[%g5 + CPU_THREAD], THREAD_REG
	wrpr	%g0, PSTATE_KERN, %pstate	! enable ints
	jmpl	%l3, %o7			! call trap handler
	mov	%l7, %o0
	!
	ALTENTRY(prom_rtt)
#ifdef TRAPTRACE
	TRACE_RTT(TT_SYS_RTT_PROM, %l0, %l1, %l2, %l3)
#endif /* TRAPTRACE */
	ba,pt	%xcc, common_rtt
	mov	THREAD_REG, %l0
	SET_SIZE(prom_rtt)
	SET_SIZE(ptl0)

	ENTRY_NP(ktl0)
	SAVE_GLOBALS(%l7)
	SAVE_OUTS(%l7)				! for the call bug workaround
	wrpr	%g0, PSTATE_KERN, %pstate	! enable ints
	jmpl	%l3, %o7			! call trap handler
	mov	%l7, %o0
	!
	ALTENTRY(priv_rtt)
#ifdef TRAPTRACE
	TRACE_RTT(TT_SYS_RTT_PRIV, %l0, %l1, %l2, %l3)
#endif /* TRAPTRACE */
	!
	! Register inputs
	!	%l7 - regs
	!	%l6 - trap %pil
	!
	! Check for a kernel preemption request
	!
	ldn	[THREAD_REG + T_CPU], %l0
	ldub	[%l0 + CPU_KPRUNRUN], %l0
	brz,pt	%l0, 1f
	nop

	!
	! Attempt to preempt
	!
	ldstub	[THREAD_REG + T_PREEMPT_LK], %l0	! load preempt lock
	brnz,pn	%l0, 1f			! can't call kpreempt if this thread is
	nop				!   already in it...

	call	kpreempt
	mov	%l6, %o0		! pass original interrupt level

	stub	%g0, [THREAD_REG + T_PREEMPT_LK]	! nuke the lock	

	rdpr	%pil, %o0		! compare old pil level
	cmp	%l6, %o0		!   with current pil level
	movg	%xcc, %o0, %l6		! if current is lower, drop old pil
1:
	!
	! If we interrupted the mutex_owner_running() critical region we
	! must reset the PC and nPC back to the beginning to prevent missed
	! wakeups. See the comments in mutex_owner_running() for details.
	!
	ldn	[%l7 + PC_OFF], %l0
	set	mutex_owner_running_critical_start, %l1
	sub	%l0, %l1, %l0
	cmp	%l0, mutex_owner_running_critical_size
	bgeu,pt	%xcc, 2f
	mov	THREAD_REG, %l0
	stn	%l1, [%l7 + PC_OFF]	! restart mutex_owner_running()
	add	%l1, 4, %l1
	ba,pt	%xcc, common_rtt
	stn	%l1, [%l7 + nPC_OFF]

2:
	!
	! If we interrupted the mutex_exit() critical region we must reset
	! the PC and nPC back to the beginning to prevent missed wakeups.
	! See the comments in mutex_exit() for details.
	!
	ldn	[%l7 + PC_OFF], %l0
	set	mutex_exit_critical_start, %l1
	sub	%l0, %l1, %l0
	cmp	%l0, mutex_exit_critical_size
	bgeu,pt	%xcc, common_rtt
	mov	THREAD_REG, %l0
	stn	%l1, [%l7 + PC_OFF]	! restart mutex_exit()
	add	%l1, 4, %l1
	stn	%l1, [%l7 + nPC_OFF]

common_rtt:
	!
	! restore globals and outs
	!
	rdpr	%pstate, %l1
	wrpr	%l1, PSTATE_IE, %pstate
	RESTORE_GLOBALS(%l7)
	! switch to alternate globals
	wrpr	%l1, PSTATE_IE | PSTATE_AG, %pstate
	RESTORE_OUTS(%l7)
	!
	! set %pil from max(old pil, cpu_base_spl)
	!
	ldn	[%l0 + T_CPU], %l0
	ld	[%l0 + CPU_BASE_SPL], %l0
	cmp	%l6, %l0
	movg	%xcc, %l6, %l0
	wrpr	%g0, %l0, %pil
	!
	! raise tl
	! setup trap regs
	! restore to window we originally trapped in
	!
	wrpr	%g0, 1, %tl
	ldn	[%l7 + PC_OFF], %g1
	ldn	[%l7 + nPC_OFF], %g2
	ldx	[%l7 + TSTATE_OFF], %l0
	andn	%l0, TSTATE_CWP, %g7
	wrpr	%g1, %tpc
	wrpr	%g2, %tnpc
	restore
	!
	! set %tstate to the correct %cwp
	! retry resumes prom execution
	!
	rdpr	%cwp, %g1
	wrpr	%g1, %g7, %tstate
	retry
	/* NOTREACHED */
	SET_SIZE(priv_rtt)
	SET_SIZE(ktl0)

#ifdef DEBUG
	.seg	".data"
	.align	4

	.global bad_g4_called
bad_g4_called:
	.word	0

sys_trap_wrong_pil:
	.asciz	"sys_trap: %g4(%d) is lower than %pil(%d)"
	.align	4
	.seg	".text"

	ENTRY_NP(bad_g4)
	mov	%o1, %o0
	mov	%o2, %o1
	call	panic
	mov	%o3, %o2
	SET_SIZE(bad_g4)
#endif /* DEBUG */

/*
 * sys_tl1_panic can be called by traps at tl1 which
 * really want to panic, but need the rearrangement of
 * the args as provided by this wrapper routine.
 */
	ENTRY_NP(sys_tl1_panic)
	mov	%o1, %o0
	mov	%o2, %o1
	call	panic
	mov	%o3, %o2
	SET_SIZE(sys_tl1_panic)

/*
 * Turn on or off bits in the auxiliary i/o register.
 *
 * set_auxioreg(bit, flag)
 *	int bit;		bit mask in aux i/o reg
 *	int flag;		0 = off, otherwise on
 *
 * This is intrinsicly ugly but is used by the floppy driver.  It is also
 * used to turn on/off the led.
 */

	.seg	".data"
	.align	4
auxio_panic:
	.asciz	"set_auxioreg: interrupts already disabled on entry"
	.align	4
	.seg	".text"

	ENTRY_NP(set_auxioreg)
	/*
	 * o0 = bit mask
	 * o1 = flag: 0 = off, otherwise on
	 *
	 * disable interrupts while updating auxioreg
	 */
	rdpr	%pstate, %o2
#ifdef	DEBUG
	andcc	%o2, PSTATE_IE, %g0	/* if interrupts already */
	bnz,a,pt %icc, 1f		/* disabled, panic */
	  nop
	sethi	%hi(auxio_panic), %o0
	call	panic
	  or	%o0, %lo(auxio_panic), %o0
1:
#endif /* DEBUG */
	wrpr	%o2, PSTATE_IE, %pstate		/* disable interrupts */
	sethi	%hi(v_auxio_addr), %o3
	ldn	[%o3 + %lo(v_auxio_addr)], %o4
	ldub	[%o4], %g1			/* read aux i/o register */
	tst	%o1
	bnz,a	2f
	 bset	%o0, %g1		/* on */
	bclr	%o0, %g1		/* off */
2:
	or	%g1, AUX_MBO, %g1	/* Must Be Ones */
	stb	%g1, [%o4]		/* write aux i/o register */
	retl
	 wrpr	%g0, %o2, %pstate	/* enable interrupt */
	SET_SIZE(set_auxioreg)

/*
 * Flush all windows to memory, except for the one we entered in.
 * We do this by doing NWINDOW-2 saves then the same number of restores.
 * This leaves the WIM immediately before window entered in.
 * This is used for context switching.
 */

	ENTRY_NP(flush_windows)
	retl
	flushw
	SET_SIZE(flush_windows)

	ENTRY_NP(debug_flush_windows)
	set	nwindows, %g1
	ld	[%g1], %g1
	mov	%g1, %g2

1:
	save	%sp, -WINDOWSIZE, %sp
	brnz	%g2, 1b
	dec	%g2

	mov	%g1, %g2
2:
	restore
	brnz	%g2, 2b
	dec	%g2

	retl
	nop

	SET_SIZE(debug_flush_windows)

/*
 * flush user windows to memory.
 */

	ENTRY_NP(flush_user_windows)
	rdpr	%otherwin, %g1
	brz	%g1, 3f
	clr	%g2
1:
	save	%sp, -WINDOWSIZE, %sp
	rdpr	%otherwin, %g1
	brnz	%g1, 1b
	add	%g2, 1, %g2
2:
	sub	%g2, 1, %g2		! restore back to orig window
	brnz	%g2, 2b
	restore
3:
	retl
	nop
	SET_SIZE(flush_user_windows)

/*
 * Throw out any user windows in the register file.
 * Used by setregs (exec) to clean out old user.
 * Used by sigcleanup to remove extraneous windows when returning from a
 * signal.
 */

	ENTRY_NP(trash_user_windows)
	rdpr	%otherwin, %g1
	brz	%g1, 3f			! no user windows?
	ldn	[THREAD_REG + T_STACK], %g5

	!
	! There are old user windows in the register file. We disable ints
	! and increment cansave so that we don't overflow on these windows.
	! Also, this sets up a nice underflow when first returning to the
	! new user.
	!
	rdpr	%pstate, %g2
	wrpr	%g2, PSTATE_IE, %pstate
	rdpr	%cansave, %g3
	rdpr	%otherwin, %g1		! re-read in case of interrupt
	add	%g3, %g1, %g3
	wrpr	%g0, 0, %otherwin
	wrpr	%g0, %g3, %cansave
	wrpr	%g0, %g2, %pstate
3:
	retl
 	clr     [%g5 + MPCB_WBCNT]       ! zero window buffer cnt
	SET_SIZE(trash_user_windows)


/*
 * Setup g7 via the CPU data structure.
 */

	ENTRY_NP(set_tbr)
	retl
	ta	72		! no tbr, stop simulation
	SET_SIZE(set_tbr)


#define	PTL1_SAVE_WINDOW(RP)						\
	stxa	%l0, [RP + RW64_LOCAL + (0 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%l1, [RP + RW64_LOCAL + (1 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%l2, [RP + RW64_LOCAL + (2 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%l3, [RP + RW64_LOCAL + (3 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%l4, [RP + RW64_LOCAL + (4 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%l5, [RP + RW64_LOCAL + (5 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%l6, [RP + RW64_LOCAL + (6 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%l7, [RP + RW64_LOCAL + (7 * RW64_LOCAL_INCR)] %asi;	\
	stxa	%i0, [RP + RW64_IN + (0 * RW64_IN_INCR)] %asi;		\
	stxa	%i1, [RP + RW64_IN + (1 * RW64_IN_INCR)] %asi;		\
	stxa	%i2, [RP + RW64_IN + (2 * RW64_IN_INCR)] %asi;		\
	stxa	%i3, [RP + RW64_IN + (3 * RW64_IN_INCR)] %asi;		\
	stxa	%i4, [RP + RW64_IN + (4 * RW64_IN_INCR)] %asi;		\
	stxa	%i5, [RP + RW64_IN + (5 * RW64_IN_INCR)] %asi;		\
	stxa	%i6, [RP + RW64_IN + (6 * RW64_IN_INCR)] %asi;		\
	stxa	%i7, [RP + RW64_IN + (7 * RW64_IN_INCR)] %asi
#define	PTL1_NEXT_WINDOW(scr)	\
	add	scr, RWIN64SIZE, scr

#define	PTL1_RESET_RWINDOWS(scr)			\
	sethi	%hi(nwin_minus_one), scr;		\
	ld	[scr + %lo(nwin_minus_one)], scr;	\
	wrpr	scr, %cleanwin;				\
	dec	scr;					\
	wrpr	scr, %cansave;				\
	wrpr	%g0, %canrestore;			\
	wrpr	%g0, %otherwin

#define	PTL1_DCACHE_LINE_SIZE	4	/* small enough for all CPUs */

/*
 * ptl1_panic is called when the kernel detects that it is in an invalid state
 * and the trap level is greater than 0.  ptl1_panic is responsible to save the
 * current CPU state, to restore the CPU state to normal, and to call panic.
 * The CPU state must be saved reliably without causing traps.  ptl1_panic saves
 * it in the ptl1_state structure, which is a member of the machcpu structure.
 * In order to access the ptl1_state structure without causing traps, physical
 * addresses are used so that we can avoid MMU miss traps.  The restriction of
 * physical memory accesses is that the ptl1_state structure must be on a single
 * physical page.  This is because (1) a single physical address for each
 * ptl1_state structure is needed and (2) it simplifies physical address
 * calculation for each member of the structure.
 * ptl1_panic is a likely spot for stack overflows to wind up; thus, the current
 * stack may not be usable.  In order to call panic reliably in such a state,
 * each CPU needs a dedicated ptl1 panic stack.
 * CPU_ALLOC_SIZE, which is defined to be MMU_PAGESIZE, is used to allocate the
 * cpu structure and a ptl1 panic stack.  They are put together on the same page
 * for memory space efficiency.  The low address part is used for the cpu
 * structure, and the high address part is for a ptl1 panic stack.
 * The cpu_pa array holds the physical addresses of the allocated cpu structures,
 * as the cpu array holds their virtual addresses.
 *
 * %g1 reason to be called
 * %g2 broken
 * %g3 broken
 */
	ENTRY_NP(ptl1_panic)
	!
	! flush D$ first, so that stale data will not be accessed later.
	! Data written via ASI_MEM bypasses D$.  If D$ contains data at the same
	! address, where data was written via ASI_MEM, a load from that address
	! using a virtual address and the default ASI still takes the old data.
	! Flushing D$ erases old data in D$, so that it will not be loaded.
	! Since we can afford only 2 registers (%g2 and %g3) for this job, we
	! flush entire D$.
	! For FJ OPL processors (IMPL values < SPITFIRE_IMPL), DC flushing
	! is not needed.
	!
	GET_CPU_IMPL(%g2)
	cmp	%g2, SPITFIRE_IMPL
	blt,pn	%icc, 1f		! Skip flushing for OPL processors
	 nop
	sethi	%hi(dcache_size), %g2
	ld	[%g2 + %lo(dcache_size)], %g2
	sethi	%hi(dcache_linesize), %g3
	ld	[%g3 + %lo(dcache_linesize)], %g3
	sub	%g2, %g3, %g2
0:	stxa	%g0, [%g2] ASI_DC_TAG
	membar	#Sync
	brnz,pt	%g2, 0b
	  sub	%g2, %g3, %g2
1:
	!
	! increment the entry counter.
	! save CPU state if this is the first entry.
	!
	CPU_PADDR(%g2, %g3);
	add	%g2, CPU_PTL1, %g2		! pstate = &CPU->mcpu.ptl1_state
	wr	%g0, ASI_MEM, %asi		! physical address access
	!
	! pstate->ptl1_entry_count++
	!
	lduwa	[%g2 + PTL1_ENTRY_COUNT] %asi, %g3
	add	%g3, 1, %g3
	stuwa	%g3, [%g2 + PTL1_ENTRY_COUNT] %asi
	! 
	! CPU state saving is skipped from the 2nd entry to ptl1_panic since we
	! do not want to clobber the state from the original failure.  panic()
	! is responsible for handling multiple or recursive panics.
	! 
	cmp	%g3, 2				! if (ptl1_entry_count >= 2)
	bge,pn	%icc, state_saved		!	goto state_saved
	  add	%g2, PTL1_REGS, %g3		! %g3 = &pstate->ptl1_regs[0]
	!
	! save CPU state
	!
save_cpu_state:
	! save current global registers
	! so that all them become available for use
	!
	stxa	%g1, [%g3 + PTL1_G1] %asi
	stxa	%g2, [%g3 + PTL1_G2] %asi
	stxa	%g3, [%g3 + PTL1_G3] %asi
	stxa	%g4, [%g3 + PTL1_G4] %asi
	stxa	%g5, [%g3 + PTL1_G5] %asi
	stxa	%g6, [%g3 + PTL1_G6] %asi
	stxa	%g7, [%g3 + PTL1_G7] %asi
	!
	! %tl, %tt, %tstate, %tpc, %tnpc for each TL
	!
	rdpr	%tl, %g1
	brz	%g1, 1f				! if(trap_level == 0) -------+
	add	%g3, PTL1_TRAP_REGS, %g4	! %g4 = &ptl1_trap_regs[0];  !
0:						! -----------<----------+    !
	stwa	%g1, [%g4 + PTL1_TL] %asi				!    !
	rdpr	%tt, %g5						!    !
	stwa	%g5, [%g4 + PTL1_TT] %asi				!    !
	rdpr	%tstate, %g5						!    !
	stxa	%g5, [%g4 + PTL1_TSTATE] %asi				!    !
	rdpr	%tpc, %g5						!    !
	stxa	%g5, [%g4 + PTL1_TPC] %asi				!    !
	rdpr	%tnpc, %g5						!    !
	stxa	%g5, [%g4 + PTL1_TNPC] %asi				!    !
	add	%g4, PTL1_TRAP_REGS_INCR, %g4				!    !
	deccc	%g1							!    !
	bnz,a,pt %icc, 0b			! if(trap_level != 0) --+    !
	  wrpr	%g1, %tl						     !
1:						! ----------<----------------+
	!
	! %pstate, %pil, SOFTINT, (S)TICK
	! Pending interrupts is also cleared in order to avoid a recursive call
	! to ptl1_panic in case the interrupt handler causes a panic.
	!
	rdpr	%pil, %g1
	stba	%g1, [%g3 + PTL1_PIL] %asi
	rdpr	%pstate, %g1
	stha	%g1, [%g3 + PTL1_PSTATE] %asi
	rd	SOFTINT, %g1
	sta	%g1, [%g3 + PTL1_SOFTINT] %asi
	wr	%g1, CLEAR_SOFTINT
	sethi   %hi(traptrace_use_stick), %g1
	ld      [%g1 + %lo(traptrace_use_stick)], %g1
	brz,a,pn %g1, 2f
	  rdpr	%tick, %g1
	rd	STICK, %g1
2:	stxa	%g1, [%g3 + PTL1_TICK] %asi

	!
	! MMU registers because ptl1_panic may be called from
	! the MMU trap handlers.
	!
	mov     MMU_SFAR, %g1
	ldxa    [%g1]ASI_DMMU, %g4
	stxa	%g4, [%g3 + PTL1_DMMU_SFAR]%asi
	mov     MMU_SFSR, %g1
	ldxa    [%g1]ASI_DMMU, %g4
	stxa	%g4, [%g3 + PTL1_DMMU_SFSR]%asi
	ldxa    [%g1]ASI_IMMU, %g4
	stxa	%g4, [%g3 + PTL1_IMMU_SFSR]%asi
	mov     MMU_TAG_ACCESS, %g1
	ldxa    [%g1]ASI_DMMU, %g4
	stxa	%g4, [%g3 + PTL1_DMMU_TAG_ACCESS]%asi
	ldxa    [%g1]ASI_IMMU, %g4
	stxa	%g4, [%g3 + PTL1_IMMU_TAG_ACCESS]%asi

	!
	! Save register window state and register windows.
	!
	rdpr	%cwp, %g1
	stba	%g1, [%g3 + PTL1_CWP] %asi
	rdpr	%wstate, %g1
	stba	%g1, [%g3 + PTL1_WSTATE] %asi
	rdpr	%otherwin, %g1
	stba	%g1, [%g3 + PTL1_OTHERWIN] %asi
	rdpr	%cleanwin, %g1
	stba	%g1, [%g3 + PTL1_CLEANWIN] %asi
	rdpr	%cansave, %g1
	stba	%g1, [%g3 + PTL1_CANSAVE] %asi
	rdpr	%canrestore, %g1
	stba	%g1, [%g3 + PTL1_CANRESTORE] %asi

	PTL1_RESET_RWINDOWS(%g1)
	clr	%g1
	wrpr	%g1, %cwp
	add	%g3, PTL1_RWINDOW, %g4		! %g4 = &ptl1_rwindow[0];

3:	PTL1_SAVE_WINDOW(%g4)	! <-------------+
	inc	%g1				!
	cmp	%g1, MAXWIN			!
	bgeu,pn	%icc, 5f			!
	wrpr	%g1, %cwp			!
	rdpr	%cwp, %g2			!
	cmp	%g1, %g2			! saturation check
	be,pt	%icc, 3b			!
	  PTL1_NEXT_WINDOW(%g4)		! ------+
5:
	!
	! most crucial CPU state was saved.
	! Proceed to go back to TL = 0.
	!
state_saved:
	wrpr	%g0, 1, %tl
	wrpr	%g0, PIL_MAX, %pil
	!
	PTL1_RESET_RWINDOWS(%g1)
	wrpr	%g0, %cwp
	wrpr	%g0, %cleanwin
	wrpr	%g0, WSTATE_KERN, %wstate
	!
	! Set pcontext to run kernel.
	!
	! For OPL, load kcontexreg instead of clearing primary
	! context register.  This is to avoid changing nucleus page
	! size bits after boot initialization.
	!
#ifdef _OPL
	sethi	%hi(kcontextreg), %g4
	ldx	[%g4 + %lo(kcontextreg)], %g4
#endif /* _OPL */

	set	DEMAP_ALL_TYPE, %g1
	sethi	%hi(FLUSH_ADDR), %g3
	set	MMU_PCONTEXT, %g2

	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP

#ifdef _OPL
	stxa	%g4, [%g2]ASI_MMU_CTX
#else /* _OPL */
	stxa	%g0, [%g2]ASI_MMU_CTX
#endif /* _OPL */

	flush	%g3

	rdpr	%cwp, %g1
	set	TSTATE_KERN, %g3
	wrpr	%g3, %g1, %tstate
	set	ptl1_panic_tl0, %g3
	wrpr	%g0, %g3, %tnpc
	done					! go to -->-+	TL:1
							    !
ptl1_panic_tl0:					! ----<-----+	TL:0
	CPU_ADDR(%l0, %l1)			! %l0 = cpu[cpuid]
	add	%l0, CPU_PTL1, %l1		! %l1 = &CPU->mcpu.ptl1_state
	!
	! prepare to call panic()
	!
	ldn	[%l0 + CPU_THREAD], THREAD_REG	! restore %g7
	ldn	[%l1 + PTL1_STKTOP], %l2	! %sp = ptl1_stktop
	sub	%l2, SA(MINFRAME) + STACK_BIAS, %sp
	clr	%fp				! no frame below this window
	clr	%i7
	!
	! enable limited interrupts
	!
	wrpr	%g0, CLOCK_LEVEL, %pil
	wrpr	%g0, PSTATE_KERN, %pstate
	!
	ba,pt	%xcc, ptl1_panic_handler
	  mov	%l1, %o0
	/*NOTREACHED*/
	SET_SIZE(ptl1_panic)

#ifdef	PTL1_PANIC_DEBUG

/*
 * ptl1_recurse() calls itself a number of times to either set up a known
 * stack or to cause a kernel stack overflow. It decrements the arguments
 * on each recursion.
 * It's called by #ifdef PTL1_PANIC_DEBUG code in startup.c to set the
 * registers to a known state to facilitate debugging.
 */
	ENTRY_NP(ptl1_recurse)
	save    %sp, -SA(MINFRAME), %sp

	set 	ptl1_recurse_call, %o7
	cmp	%o7, %i7			! if ptl1_recurse is called
	be,pt  %icc, 0f				! by itself, then skip
	  nop					! register initialization

	/* 
	 * Initialize Out Registers to Known Values 
	 */
	set	0x01000, %l0			! %i0 is the ...
						! recursion_depth_count
	sub	%i0, 1, %o0;
	sub 	%i1, 1, %o1;
	add	%l0, %o0, %o2;
	add	%l0, %o2, %o3;
	add	%l0, %o3, %o4;
	add	%l0, %o4, %o5;
	ba,a	1f
	  nop

0:	/* Outs = Ins - 1 */
	sub	%i0, 1, %o0; 
	sub	%i1, 1, %o1;
	sub	%i2, 1, %o2; 
	sub	%i3, 1, %o3;
	sub	%i4, 1, %o4; 
	sub	%i5, 1, %o5;

	/* Locals = Ins + 1 */
1:	add	%i0, 1, %l0; 	
	add	%i1, 1, %l1;
	add	%i2, 1, %l2; 
	add	%i3, 1, %l3;
	add	%i4, 1, %l4; 
	add	%i5, 1, %l5;

	set     0x0100000, %g5
	add	%g5, %g0, %g1 
	add	%g5, %g1, %g2 
	add	%g5, %g2, %g3 
	add	%g5, %g3, %g4 
	add	%g5, %g4, %g5 

	brz,pn %i1, ptl1_recurse_trap		! if trpp_count == 0) {
	  nop					!    trap to ptl1_panic
						!			
	brz,pn %i0, ptl1_recure_exit		! if(depth_count == 0) {
	  nop					!    skip recursive call
						! }
ptl1_recurse_call:
	call	ptl1_recurse
	  nop

ptl1_recure_exit:
	ret
	restore

ptl1_recurse_trap:
	ta	PTL1_DEBUG_TRAP; 		! Trap Always to ptl1_panic()
	  nop 					! NOTREACHED 
        SET_SIZE(ptl1_recurse)

	/*
	 * Asm function to handle a cross trap to call ptl1_panic()
	 */
	ENTRY_NP(ptl1_panic_xt)
	ba	ptl1_panic
	  mov	PTL1_BAD_DEBUG, %g1
        SET_SIZE(ptl1_panic_xt)

#endif	/* PTL1_PANIC_DEBUG */

#ifdef	TRAPTRACE

	ENTRY_NP(trace_ptr_panic)
	!
	! freeze the trap trace to disable the assertions.  Otherwise,
	! ptl1_panic is likely to be repeatedly called from there.
	! %g2 and %g3 are used as scratch registers in ptl1_panic.
	!
	mov	1, %g3
	sethi	%hi(trap_freeze), %g2
	st	%g3, [%g2 + %lo(trap_freeze)]
	!
	! %g1 contains the %pc address where an assertion was failed.
	! save it in trap_freeze_pc for a debugging hint if there is
	! no value saved in it.
	!
	set	trap_freeze_pc, %g2
	casn	[%g2], %g0, %g1

	ba	ptl1_panic
	mov	PTL1_BAD_TRACE_PTR, %g1
	SET_SIZE(trace_ptr_panic)

#endif	/* TRAPTRACE */
/*
 * set_kcontextreg() sets PCONTEXT to kctx
 * if PCONTEXT==kctx, do nothing
 * if N_pgsz0|N_pgsz1 differ, do demap all first
 */
        ENTRY_NP(set_kcontextreg)
	! SET_KCONTEXTREG(reg0, reg1, reg2, reg3, reg4, label1, label2, label3)
	SET_KCONTEXTREG(%o0, %o1, %o2, %o3, %o4, l1, l2, l3)
	retl
        nop
	SET_SIZE(set_kcontextreg)

/*
 * The interface for a 32-bit client program that takes over the TBA
 * calling the 64-bit romvec OBP.
 */

	ENTRY(client_handler)
	save	%sp, -SA64(MINFRAME64), %sp	! 32 bit frame, 64 bit sized
	sethi	%hi(tba_taken_over), %l2
	ld	[%l2+%lo(tba_taken_over)], %l3
	brz	%l3, 1f				! is the tba_taken_over = 1 ?
	rdpr	%wstate, %l5			! save %wstate
	andn	%l5, WSTATE_MASK, %l6
	wrpr	%l6, WSTATE_KMIX, %wstate

	!
	! switch to PCONTEXT=0
	!
#ifndef _OPL
	mov	MMU_PCONTEXT, %o2
	ldxa	[%o2]ASI_DMMU, %o2
	srlx	%o2, CTXREG_NEXT_SHIFT, %o2
	brz,pt	%o2, 1f				! nucleus pgsz is 0, no problem
	  nop
	rdpr	%pstate, %l4			! disable interrupts
	andn	%l4, PSTATE_IE, %o2
	wrpr	%g0, %o2, %pstate
	mov	DEMAP_ALL_TYPE, %o2		! set PCONTEXT=0
	stxa	%g0, [%o2]ASI_DTLB_DEMAP
	stxa	%g0, [%o2]ASI_ITLB_DEMAP
	mov	MMU_PCONTEXT, %o2
	stxa	%g0, [%o2]ASI_DMMU
        membar  #Sync
	sethi	%hi(FLUSH_ADDR), %o2
	flush	%o2				! flush required by immu
	wrpr	%g0, %l4, %pstate		! restore interrupt state
#endif /* _OPL */

1:	mov	%i1, %o0
	rdpr	%pstate, %l4			! Get the present pstate value
	andn	%l4, PSTATE_AM, %l6
	wrpr	%l6, 0, %pstate			! Set PSTATE_AM = 0
	jmpl	%i0, %o7			! Call cif handler
	nop
	wrpr	%l4, 0, %pstate			! restore pstate
	brz	%l3, 1f				! is the tba_taken_over = 1
	  nop
	wrpr	%g0, %l5, %wstate		! restore wstate

	!
	! switch to PCONTEXT=kcontexreg
	!
#ifndef _OPL
	sethi	%hi(kcontextreg), %o3
	ldx     [%o3 + %lo(kcontextreg)], %o3
	brz	%o3, 1f
	  nop
	rdpr	%pstate, %l4			! disable interrupts
	andn	%l4, PSTATE_IE, %o2
	wrpr	%g0, %o2, %pstate
	mov	DEMAP_ALL_TYPE, %o2
	stxa	%g0, [%o2]ASI_DTLB_DEMAP
	stxa	%g0, [%o2]ASI_ITLB_DEMAP
	mov	MMU_PCONTEXT, %o2
	stxa	%o3, [%o2]ASI_DMMU
        membar  #Sync
	sethi	%hi(FLUSH_ADDR), %o2
	flush	%o2				! flush required by immu
	wrpr	%g0, %l4, %pstate		! restore interrupt state
#endif /* _OPL */

1:	ret					! Return result ...
	restore	%o0, %g0, %o0			! delay; result in %o0
	SET_SIZE(client_handler)

