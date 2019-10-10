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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * General assembly language routines.
 * It is the intent of this file to contain routines that are
 * independent of the specific kernel architecture, and those that are
 * common across kernel architectures.
 * As architectures diverge, and implementations of specific
 * architecture-dependent routines change, the routines should be moved
 * from this file into the respective ../`arch -k`/subr.s file.
 * Or, if you want to be really nice, move them to a file whose
 * name has something to do with the routine you are moving.
 */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/machparam.h>	/* To get SYSBASE and PAGESIZE */
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/psr_compat.h>
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/panic.h>
#include <sys/machlock.h>
#include <sys/ontrap.h>

#include "assym.h"

	.seg	".text"
	.align	4

/*
 * Macro to raise processor priority level.
 * Avoid dropping processor priority if already at high level.
 * Also avoid going below CPU->cpu_base_spl, which could've just been set by
 * a higher-level interrupt thread that just blocked.
 *
 * level can be %o0 (not other regs used here) or a constant.
 */
#define	RAISE(level) \
	rdpr	%pil, %o1;		/* get current PIL */		\
	cmp	%o1, level;		/* is PIL high enough? */	\
	bge	1f;			/* yes, return */		\
	nop;								\
	wrpr	%g0, PIL_MAX, %pil;	/* freeze CPU_BASE_SPL */	\
	ldn	[THREAD_REG + T_CPU], %o2;				\
	ld	[%o2 + CPU_BASE_SPL], %o2;				\
	cmp	%o2, level;		/* compare new to base */	\
	movl	%xcc, level, %o2;	/* use new if base lower */	\
	wrpr	%g0, %o2, %pil;						\
1:									\
	retl;								\
	mov	%o1, %o0		/* return old PIL */

/*
 * Macro to raise processor priority level to level >= DISP_LEVEL.
 * Doesn't require comparison to CPU->cpu_base_spl.
 *
 * newpil can be %o0 (not other regs used here) or a constant.
 */
#define	RAISE_HIGH(level) \
	rdpr	%pil, %o1;		/* get current PIL */		\
	cmp	%o1, level;		/* is PIL high enough? */	\
	bge	1f;			/* yes, return */		\
	nop;								\
	wrpr	%g0, level, %pil;	/* use chose value */		\
1:									\
	retl;								\
	mov	%o1, %o0		/* return old PIL */
	
/*
 * Macro to set the priority to a specified level.
 * Avoid dropping the priority below CPU->cpu_base_spl.
 *
 * newpil can be %o0 (not other regs used here) or a constant with
 * the new PIL in the PSR_PIL field of the level arg.
 */
#define SETPRI(level) \
	rdpr	%pil, %o1;		/* get current PIL */		\
	wrpr	%g0, PIL_MAX, %pil;	/* freeze CPU_BASE_SPL */	\
	ldn	[THREAD_REG + T_CPU], %o2;				\
	ld	[%o2 + CPU_BASE_SPL], %o2;				\
	cmp	%o2, level;		/* compare new to base */	\
	movl	%xcc, level, %o2;	/* use new if base lower */	\
	wrpr	%g0, %o2, %pil;						\
	retl;								\
	mov	%o1, %o0		/* return old PIL */

/*
 * Macro to set the priority to a specified level at or above LOCK_LEVEL.
 * Doesn't require comparison to CPU->cpu_base_spl.
 *
 * newpil can be %o0 (not other regs used here) or a constant with
 * the new PIL in the PSR_PIL field of the level arg.
 */
#define	SETPRI_HIGH(level) \
	rdpr	%pil, %o1;		/* get current PIL */		\
	wrpr	%g0, level, %pil;					\
	retl;								\
	mov	%o1, %o0		/* return old PIL */

	/*
	 * Berkley 4.3 introduced symbolically named interrupt levels
	 * as a way deal with priority in a machine independent fashion.
	 * Numbered priorities are machine specific, and should be
	 * discouraged where possible.
	 *
	 * Note, for the machine specific priorities there are
	 * examples listed for devices that use a particular priority.
	 * It should not be construed that all devices of that
	 * type should be at that priority.  It is currently were
	 * the current devices fit into the priority scheme based
	 * upon time criticalness.
	 *
	 * The underlying assumption of these assignments is that
	 * SPARC9 IPL 10 is the highest level from which a device
	 * routine can call wakeup.  Devices that interrupt from higher
	 * levels are restricted in what they can do.  If they need
	 * kernels services they should schedule a routine at a lower
	 * level (via software interrupt) to do the required
	 * processing.
	 *
	 * Examples of this higher usage:
	 *	Level	Usage
	 *	15	Asynchronous memory exceptions
	 *	14	Profiling clock (and PROM uart polling clock)
	 *	13	Audio device
	 *	12	Serial ports
	 *	11	Floppy controller
	 *
	 * The serial ports request lower level processing on level 6.
	 * Audio and floppy request lower level processing on level 4.
	 *
	 * Also, almost all splN routines (where N is a number or a
	 * mnemonic) will do a RAISE(), on the assumption that they are
	 * never used to lower our priority.
	 * The exceptions are:
	 *	spl8()		Because you can't be above 15 to begin with!
	 *	splzs()		Because this is used at boot time to lower our
	 *			priority, to allow the PROM to poll the uart.
	 *	spl0()		Used to lower priority to 0.
	 */

	/* locks out all interrupts, including memory errors */
	ENTRY(spl8)
	SETPRI_HIGH(15)
	SET_SIZE(spl8)

	/* just below the level that profiling runs */
	ENTRY(spl7)
	RAISE_HIGH(13)
	SET_SIZE(spl7)

	/* sun specific - highest priority onboard serial i/o zs ports */
	ENTRY(splzs)
	SETPRI_HIGH(12)	/* Can't be a RAISE, as it's used to lower us */
	SET_SIZE(splzs)

	/*
	 * should lock out clocks and all interrupts,
	 * as you can see, there are exceptions
	 */
	ENTRY(splhi)
	ALTENTRY(splhigh)
	ALTENTRY(spl6)
	ALTENTRY(i_ddi_splhigh)
	RAISE_HIGH(DISP_LEVEL)
	SET_SIZE(i_ddi_splhigh)
	SET_SIZE(spl6)
	SET_SIZE(splhigh)
	SET_SIZE(splhi)

	/* allow all interrupts */
	ENTRY(spl0)
	SETPRI(0)
	SET_SIZE(spl0)

/*
 * splx - set PIL back to that indicated by the old %pil passed as an argument,
 * or to the CPU's base priority, whichever is higher.
 */

	ENTRY(splx)
	ALTENTRY(i_ddi_splx)
	SETPRI(%o0)		/* set PIL */
	SET_SIZE(i_ddi_splx)
	SET_SIZE(splx)

/*
 * splr()
 *
 * splr is like splx but will only raise the priority and never drop it
 * Be careful not to set priority lower than CPU->cpu_base_pri,
 * even though it seems we're raising the priority, it could be set higher
 * at any time by an interrupt routine, so we must block interrupts and
 * look at CPU->cpu_base_pri.
 */

	ENTRY(splr)
	RAISE(%o0)
	SET_SIZE(splr)

/*
 * on_fault()
 * Catch lofault faults. Like setjmp except it returns one
 * if code following causes uncorrectable fault. Turned off
 * by calling no_fault().
 */

	ENTRY(on_fault)
	membar	#Sync			! sync error barrier (see copy.s)
	stn	%o0, [THREAD_REG + T_ONFAULT]
	set	catch_fault, %o1
	b	setjmp			! let setjmp do the rest
	stn	%o1, [THREAD_REG + T_LOFAULT]	! put catch_fault in t_lofault

catch_fault:
	save	%sp, -SA(WINDOWSIZE), %sp ! goto next window so that we can rtn
	ldn	[THREAD_REG + T_ONFAULT], %o0
	membar	#Sync				! sync error barrier
	stn	%g0, [THREAD_REG + T_ONFAULT]	! turn off onfault
	b	longjmp			! let longjmp do the rest
	stn	%g0, [THREAD_REG + T_LOFAULT]	! turn off lofault
	SET_SIZE(on_fault)

/*
 * no_fault()
 * turn off fault catching.
 */

	ENTRY(no_fault)
	membar	#Sync				! sync error barrier
	stn	%g0, [THREAD_REG + T_ONFAULT]
	retl
	stn	%g0, [THREAD_REG + T_LOFAULT]	! turn off lofault
	SET_SIZE(no_fault)

/*
 * Default trampoline code for on_trap() (see <sys/ontrap.h>).  On sparcv9,
 * the trap code will complete trap processing but reset the return %pc to
 * ot_trampoline, which will by default be set to the address of this code.
 * We longjmp(&curthread->t_ontrap->ot_jmpbuf) to return back to on_trap().
 */

	ENTRY(on_trap_trampoline)
	ldn	[THREAD_REG + T_ONTRAP], %o0    
	b	longjmp                 
	add	%o0, OT_JMPBUF, %o0
	SET_SIZE(on_trap_trampoline)

/*
 * Push a new element on to the t_ontrap stack.  Refer to <sys/ontrap.h> for
 * more information about the on_trap() mechanism.  If the on_trap_data is the
 * same as the topmost stack element, we just modify that element.
 * On UltraSPARC, we need to issue a membar #Sync before modifying t_ontrap.
 * The issue barrier is defined to force all deferred errors to complete before
 * we go any further.  We want these errors to be processed before we modify
 * our current error protection.
 */

	ENTRY(on_trap)
	membar	#Sync				! force error barrier
	sth	%o1, [%o0 + OT_PROT]		! ot_prot = prot
	sth	%g0, [%o0 + OT_TRAP]		! ot_trap = 0
	set	on_trap_trampoline, %o2		! %o2 = &on_trap_trampoline
	stn	%o2, [%o0 + OT_TRAMPOLINE]	! ot_trampoline = %o2
	stn	%g0, [%o0 + OT_HANDLE]		! ot_handle = NULL
	ldn	[THREAD_REG + T_ONTRAP], %o2	! %o2 = curthread->t_ontrap
	cmp	%o0, %o2			! if (otp == %o2)
	be	0f				!    don't modify t_ontrap
	stn	%g0, [%o0 + OT_PAD1]		! delay - ot_pad1 = NULL

	stn	%o2, [%o0 + OT_PREV]		! ot_prev = t_ontrap
	membar	#Sync				! force error barrier
	stn	%o0, [THREAD_REG + T_ONTRAP]	! t_ontrap = otp

0:	b	setjmp				! let setjmp do the rest
	add	%o0, OT_JMPBUF, %o0		! %o0 = &ot_jmpbuf
	SET_SIZE(on_trap)

/*
 * Setjmp and longjmp implement non-local gotos using state vectors
 * type label_t.
 */

	ENTRY(setjmp)
	stn	%o7, [%o0 + L_PC]	! save return address
	stn	%sp, [%o0 + L_SP]	! save stack ptr
	retl
	clr	%o0			! return 0
	SET_SIZE(setjmp)


	ENTRY(longjmp)
	!
        ! The following save is required so that an extra register
        ! window is flushed.  Flushw flushes nwindows-2
        ! register windows.  If setjmp and longjmp are called from
        ! within the same window, that window will not get pushed
        ! out onto the stack without the extra save below.  Tail call
        ! optimization can lead to callers of longjmp executing
        ! from a window that could be the same as the setjmp,
        ! thus the need for the following save.
        !
	save    %sp, -SA(MINFRAME), %sp
	flushw				! flush all but this window
	ldn	[%i0 + L_PC], %i7	! restore return addr
	ldn	[%i0 + L_SP], %fp	! restore sp for dest on foreign stack
	ret				! return 1
	restore	%g0, 1, %o0		! takes underflow, switches stacks
	SET_SIZE(longjmp)

/*
 * movtuc(length, from, to, table)
 *
 * VAX movtuc instruction (sort of).
 */

	ENTRY(movtuc)
	tst     %o0
	ble,pn	%ncc, 2f		! check length
	clr     %o4

	ldub    [%o1 + %o4], %g1        ! get next byte in string
0:
	ldub    [%o3 + %g1], %g1        ! get corresponding table entry
	tst     %g1                     ! escape char?
	bnz     1f
	stb     %g1, [%o2 + %o4]        ! delay slot, store it

	retl                            ! return (bytes moved)
	mov     %o4, %o0
1:
	inc     %o4                     ! increment index
	cmp     %o4, %o0                ! index < length ?
	bl,a,pt	%ncc, 0b
	ldub    [%o1 + %o4], %g1        ! delay slot, get next byte in string
2:
	retl                            ! return (bytes moved)
	mov     %o4, %o0
	SET_SIZE(movtuc)

/*
 * scanc(length, string, table, mask)
 *
 * VAX scanc instruction.
 */

	ENTRY(scanc)
	tst	%o0	
	ble,pn	%ncc, 1f		! check length
	clr	%o4
0:
	ldub	[%o1 + %o4], %g1	! get next byte in string
	cmp	%o4, %o0		! interlock slot, index < length ?
	ldub	[%o2 + %g1], %g1	! get corresponding table entry
	bge,pn	%ncc, 1f		! interlock slot
	btst	%o3, %g1		! apply the mask
	bz,a	0b
	inc	%o4			! delay slot, increment index
1:
	retl				! return(length - index)
	sub	%o0, %o4, %o0
	SET_SIZE(scanc)

/*
 * if a() calls b() calls caller(),
 * caller() returns return address in a().
 */

	ENTRY(caller)
	retl
	mov	%i7, %o0
	SET_SIZE(caller)

/*
 * if a() calls callee(), callee() returns the
 * return address in a();
 */

	ENTRY(callee)
	retl
	mov	%o7, %o0
	SET_SIZE(callee)

/*
 * return the current frame pointer
 */

	ENTRY(getfp)
	retl
	mov	%fp, %o0
	SET_SIZE(getfp)

/*
 * Get vector base register
 */

	ENTRY(gettbr)
	retl
	mov     %tbr, %o0
	SET_SIZE(gettbr)

/*
 * Get processor state register, V9 faked to look like V8.
 * Note: does not provide ccr.xcc and provides FPRS.FEF instead of
 * PSTATE.PEF, because PSTATE.PEF is always on in order to allow the
 * libc_psr memcpy routines to run without hitting the fp_disabled trap.
 */

	ENTRY(getpsr)
	rd	%ccr, %o1			! get ccr
        sll	%o1, PSR_ICC_SHIFT, %o0		! move icc to V8 psr.icc
	rd	%fprs, %o1			! get fprs
	and	%o1, FPRS_FEF, %o1		! mask out dirty upper/lower
	sllx	%o1, PSR_FPRS_FEF_SHIFT, %o1	! shift fef to V8 psr.ef
        or	%o0, %o1, %o0			! or into psr.ef
        set	V9_PSR_IMPLVER, %o1		! SI assigned impl/ver: 0xef
        retl
        or	%o0, %o1, %o0			! or into psr.impl/ver
	SET_SIZE(getpsr)

/*
 * Get current processor interrupt level
 */

	ENTRY(getpil)
	retl
	rdpr	%pil, %o0
	SET_SIZE(getpil)

	ENTRY(setpil)
	retl
	wrpr	%g0, %o0, %pil
	SET_SIZE(setpil)


/*
 * _insque(entryp, predp)
 *
 * Insert entryp after predp in a doubly linked list.
 */

	ENTRY(_insque)
	ldn	[%o1], %g1		! predp->forw
	stn	%o1, [%o0 + CPTRSIZE]	! entryp->back = predp
	stn	%g1, [%o0]		! entryp->forw = predp->forw
	stn	%o0, [%o1]		! predp->forw = entryp
	retl
	stn	%o0, [%g1 + CPTRSIZE]	! predp->forw->back = entryp
	SET_SIZE(_insque)

/*
 * _remque(entryp)
 *
 * Remove entryp from a doubly linked list
 */

	ENTRY(_remque)
	ldn	[%o0], %g1		! entryp->forw
	ldn	[%o0 + CPTRSIZE], %g2	! entryp->back
	stn	%g1, [%g2]		! entryp->back->forw = entryp->forw
	retl
	stn	%g2, [%g1 + CPTRSIZE]	! entryp->forw->back = entryp->back
	SET_SIZE(_remque)


/*
 * strlen(str)
 *
 * Returns the number of non-NULL bytes in string argument.
 *
 * XXX -  why is this here, rather than the traditional file?
 *	  why does it have local labels which don't start with a `.'?
 */

	ENTRY(strlen)
	mov	%o0, %o1
	andcc	%o1, 3, %o3		! is src word aligned
	bz	$nowalgnd
	clr	%o0			! length of non-zero bytes
	cmp	%o3, 2			! is src half-word aligned
	be	$s2algn
	cmp	%o3, 3			! src is byte aligned
	ldub	[%o1], %o3		! move 1 or 3 bytes to align it
	inc	1, %o1			! in either case, safe to do a byte
	be	$s3algn
	tst	%o3
$s1algn:
	bnz,a	$s2algn			! now go align dest
	inc	1, %o0
	b,a	$done

$s2algn:
	lduh	[%o1], %o3		! know src is half-byte aligned
	inc	2, %o1
	srl	%o3, 8, %o4
	tst	%o4			! is the first byte zero
	bnz,a	1f
	inc	%o0
	b,a	$done
1:	andcc	%o3, 0xff, %o3		! is the second byte zero
	bnz,a	$nowalgnd
	inc	%o0
	b,a	$done
$s3algn:
	bnz,a	$nowalgnd
	inc	1, %o0
	b,a	$done

$nowalgnd:
	! use trick to check if any read bytes of a word are zero
	! the following two constants will generate "byte carries"
	! and check if any bit in a byte is set, if all characters
	! are 7bits (unsigned) this allways works, otherwise
	! there is a specil case that rarely happens, see below

	set	0x7efefeff, %o3
	set	0x81010100, %o4

3:	ld	[%o1], %o2		! main loop
	inc	4, %o1
	add	%o2, %o3, %o5		! generate byte-carries
	xor	%o5, %o2, %o5		! see if orignal bits set
	and	%o5, %o4, %o5
	cmp	%o5, %o4		! if ==,  no zero bytes
	be,a	3b
	inc	4, %o0

	! check for the zero byte and increment the count appropriately
	! some information (the carry bit) is lost if bit 31
	! was set (very rare), if this is the rare condition,
	! return to the main loop again

	sethi	%hi(0xff000000), %o5	! mask used to test for terminator
	andcc	%o2, %o5, %g0		! check if first byte was zero
	bnz	1f
	srl	%o5, 8, %o5
$done:
	retl
	nop
1:	andcc	%o2, %o5, %g0		! check if second byte was zero
	bnz	1f
	srl	%o5, 8, %o5
$done1:
	retl
	inc	%o0
1:	andcc 	%o2, %o5, %g0		! check if third byte was zero
	bnz	1f
	andcc	%o2, 0xff, %g0		! check if last byte is zero
$done2:
	retl
	inc	2, %o0
1:	bnz,a	3b
	inc	4, %o0			! count of bytes
$done3:
	retl
	inc	3, %o0
	SET_SIZE(strlen)

/*
 * Provide a C callable interface to the membar instruction.
 */

	ENTRY(membar_ldld)
	retl
	membar	#LoadLoad
	SET_SIZE(membar_ldld)

	ENTRY(membar_stld)
	retl
	membar	#StoreLoad
	SET_SIZE(membar_stld)

	ENTRY(membar_ldst)
	retl
	membar	#LoadStore
	SET_SIZE(membar_ldst)

	ENTRY(membar_stst)
	retl
	membar	#StoreStore
	SET_SIZE(membar_stst)

	ENTRY(membar_ldld_stld)
	ALTENTRY(membar_stld_ldld)
	retl
	membar	#LoadLoad|#StoreLoad
	SET_SIZE(membar_stld_ldld)
	SET_SIZE(membar_ldld_stld)

	ENTRY(membar_ldld_ldst)
	ALTENTRY(membar_ldst_ldld)
	retl
	membar	#LoadLoad|#LoadStore
	SET_SIZE(membar_ldst_ldld)
	SET_SIZE(membar_ldld_ldst)

	ENTRY(membar_ldld_stst)
	ALTENTRY(membar_stst_ldld)
	retl
	membar	#LoadLoad|#StoreStore
	SET_SIZE(membar_stst_ldld)
	SET_SIZE(membar_ldld_stst)

	ENTRY(membar_stld_ldst)
	ALTENTRY(membar_ldst_stld)
	retl
	membar	#StoreLoad|#LoadStore
	SET_SIZE(membar_ldst_stld)
	SET_SIZE(membar_stld_ldst)

	ENTRY(membar_stld_stst)
	ALTENTRY(membar_stst_stld)
	retl
	membar	#StoreLoad|#StoreStore
	SET_SIZE(membar_stst_stld)
	SET_SIZE(membar_stld_stst)

	ENTRY(membar_ldst_stst)
	ALTENTRY(membar_stst_ldst)
	retl
	membar	#LoadStore|#StoreStore
	SET_SIZE(membar_stst_ldst)
	SET_SIZE(membar_ldst_stst)

	ENTRY(membar_lookaside)
	retl
	membar	#Lookaside
	SET_SIZE(membar_lookaside)

	ENTRY(membar_memissue)
	retl
	membar	#MemIssue
	SET_SIZE(membar_memissue)

	ENTRY(membar_sync)
	retl
	membar	#Sync
	SET_SIZE(membar_sync)


/*
 * Since all of the fuword() variants are so similar, we have a macro to spit
 * them out.
 */

#define	FUWORD(NAME, LOAD, STORE, COPYOP)	\
	ENTRY(NAME);				\
	sethi	%hi(1f), %o5;			\
	ldn	[THREAD_REG + T_LOFAULT], %o3;	\
	or	%o5, %lo(1f), %o5;		\
	membar	#Sync;				\
	stn	%o5, [THREAD_REG + T_LOFAULT];	\
	LOAD	[%o0]ASI_USER, %o2;		\
	membar	#Sync;				\
	stn	%o3, [THREAD_REG + T_LOFAULT];	\
	mov	0, %o0;				\
	retl;					\
	STORE	%o2, [%o1];			\
1:						\
	membar	#Sync;				\
	stn	%o3, [THREAD_REG + T_LOFAULT];	\
	ldn	[THREAD_REG + T_COPYOPS], %o2;	\
	brz	%o2, 2f;			\
	nop;					\
	ldn	[%o2 + COPYOP], %g1;		\
	jmp	%g1;				\
	nop;					\
2:						\
	retl;					\
	mov	-1, %o0;			\
	SET_SIZE(NAME)

	FUWORD(fuword64, ldxa, stx, CP_FUWORD64)
	FUWORD(fuword32, lda, st, CP_FUWORD32)
	FUWORD(fuword16, lduha, sth, CP_FUWORD16)
	FUWORD(fuword8, lduba, stb, CP_FUWORD8)


/*
 * Since all of the suword() variants are so similar, we have a macro to spit
 * them out.
 */

#define	SUWORD(NAME, STORE, COPYOP)		\
	ENTRY(NAME)				\
	sethi	%hi(1f), %o5;			\
	ldn	[THREAD_REG + T_LOFAULT], %o3;	\
	or	%o5, %lo(1f), %o5;		\
	membar	#Sync;				\
	stn	%o5, [THREAD_REG + T_LOFAULT];	\
	STORE	%o1, [%o0]ASI_USER;		\
	membar	#Sync;				\
	stn	%o3, [THREAD_REG + T_LOFAULT];	\
	retl;					\
	clr	%o0;				\
1:						\
	membar	#Sync;				\
	stn	%o3, [THREAD_REG + T_LOFAULT];	\
	ldn	[THREAD_REG + T_COPYOPS], %o2;	\
	brz	%o2, 2f;			\
	nop;					\
	ldn	[%o2 + COPYOP], %g1;		\
	jmp	%g1;				\
	nop;					\
2:						\
	retl;					\
	mov	-1, %o0;			\
	SET_SIZE(NAME)

	SUWORD(suword64, stxa, CP_SUWORD64)
	SUWORD(suword32, sta, CP_SUWORD32)
	SUWORD(suword16, stha, CP_SUWORD16)
	SUWORD(suword8, stba, CP_SUWORD8)

	ENTRY(fuword8_noerr)
	lduba	[%o0]ASI_USER, %o0	
	retl
	stb	%o0, [%o1]
	SET_SIZE(fuword8_noerr)

	ENTRY(fuword16_noerr)
	lduha	[%o0]ASI_USER, %o0
	retl
	sth	%o0, [%o1]
	SET_SIZE(fuword16_noerr)

	ENTRY(fuword32_noerr)
	lda	[%o0]ASI_USER, %o0
	retl
	st	%o0, [%o1]
	SET_SIZE(fuword32_noerr)

	ENTRY(fuword64_noerr)
	ldxa	[%o0]ASI_USER, %o0
	retl
	stx	%o0, [%o1]
	SET_SIZE(fuword64_noerr)

	ENTRY(suword8_noerr)
	retl
	stba	%o1, [%o0]ASI_USER
	SET_SIZE(suword8_noerr)

	ENTRY(suword16_noerr)
	retl
	stha	%o1, [%o0]ASI_USER
	SET_SIZE(suword16_noerr)

	ENTRY(suword32_noerr)
	retl
	sta	%o1, [%o0]ASI_USER
	SET_SIZE(suword32_noerr)

	ENTRY(suword64_noerr)
	retl
	stxa	%o1, [%o0]ASI_USER
	SET_SIZE(suword64_noerr)

	.weak	subyte
	subyte=suword8
	.weak	subyte_noerr
	subyte_noerr=suword8_noerr
#ifdef _LP64
	.weak	fulword
	fulword=fuword64
	.weak	fulword_noerr
	fulword_noerr=fuword64_noerr
	.weak	sulword
	sulword=suword64
	.weak	sulword_noerr
	sulword_noerr=suword64_noerr
#else
	.weak	fulword
	fulword=fuword32
	.weak	fulword_noerr
	fulword_noerr=fuword32_noerr
	.weak	sulword
	sulword=suword32
	.weak	sulword_noerr
	sulword_noerr=suword32_noerr
#endif	/* LP64 */

/*
 * We define rdtick here, but not for sun4v. On sun4v systems, the %tick
 * and %stick should not be read directly without considering the tick
 * and stick offset kernel variables introduced to support sun4v OS
 * suspension.
 */
#if !defined (sun4v)

	ENTRY(rdtick)
	retl
	rd	%tick, %o0
        SET_SIZE(rdtick)

#endif /* !sun4v */

/*
 * Set tba to given address, no side effects.
 */

	ENTRY(set_tba)
	mov	%o0, %o1
	rdpr	%tba, %o0
	wrpr	%o1, %tba
	retl
	nop
	SET_SIZE(set_tba)

	ENTRY(get_tba)
	retl
	rdpr	%tba, %o0
	SET_SIZE(get_tba)

	ENTRY_NP(setpstate)
	retl
	wrpr	%g0, %o0, %pstate
	SET_SIZE(setpstate)

	ENTRY_NP(getpstate)
	retl
	rdpr	%pstate, %o0
	SET_SIZE(getpstate)

	ENTRY_NP(dtrace_interrupt_disable)
	rdpr	%pstate, %o0
	andn	%o0, PSTATE_IE, %o1
	retl
	wrpr	%g0, %o1, %pstate
	SET_SIZE(dtrace_interrupt_disable)

	ENTRY_NP(dtrace_interrupt_enable)
	retl
	wrpr	%g0, %o0, %pstate 
	SET_SIZE(dtrace_interrupt_enable)

#ifdef SF_ERRATA_51
	.align 32
	ENTRY(dtrace_membar_return)
	retl
	nop
	SET_SIZE(dtrace_membar_return)
#define	DTRACE_MEMBAR_RETURN	ba,pt %icc, dtrace_membar_return
#else
#define	DTRACE_MEMBAR_RETURN	retl
#endif

	ENTRY(dtrace_membar_producer)
	DTRACE_MEMBAR_RETURN
	membar	#StoreStore
	SET_SIZE(dtrace_membar_producer)

	ENTRY(dtrace_membar_consumer)
	DTRACE_MEMBAR_RETURN
	membar	#LoadLoad
	SET_SIZE(dtrace_membar_consumer)

	ENTRY_NP(dtrace_flush_windows)
	retl
	flushw
	SET_SIZE(dtrace_flush_windows)

	/*
	 * %g1	pcstack
	 * %g2	iteration count
	 * %g3	final %fp
	 * %g4	final %i7
	 * %g5	saved %cwp (so we can get back to the original window)
	 *
	 * %o0	pcstack / return value (iteration count)
	 * %o1	limit / saved %cansave
	 * %o2	lastfp
	 * %o3	lastpc
	 * %o4	saved %canrestore
	 * %o5	saved %pstate (to restore interrupts)
	 *
	 * Note:  The frame pointer returned via lastfp is safe to use as
	 *	long as getpcstack_top() returns either (0) or a value less
	 *	than (limit).
	 */
	ENTRY_NP(getpcstack_top)

	rdpr	%pstate, %o5
	andn	%o5, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate	! disable interrupts

	mov	%o0, %g1		! we need the pcstack pointer while
					! we're visiting other windows

	rdpr	%canrestore, %g2	! number of available windows
	sub	%g2, 1, %g2		! account for skipped frame
	cmp	%g2, %o1		! compare with limit
	movg	%icc, %o1, %g2		! %g2 = min(%canrestore-1, limit)

	brlez,a,pn %g2, 3f		! Use slow path if count <= 0 --
	clr	%o0			! return zero.

	mov	%g2, %o0		! set up return value

	rdpr	%cwp, %g5		! remember the register window state
	rdpr	%cansave, %o1		! 'restore' changes, so we can undo
	rdpr	%canrestore, %o4	! its effects when we finish.

	restore				! skip caller's frame
1:
	st	%i7, [%g1]		! stash return address in pcstack
	restore				! go to the next frame
	subcc	%g2, 1, %g2		! decrement the count
	bnz,pt	%icc, 1b		! loop until count reaches 0
	add	%g1, 4, %g1		! increment pcstack

	mov	%i6, %g3		! copy the final %fp and return PC
	mov	%i7, %g4		! aside so we can return them to our
					! caller

	wrpr	%g0, %g5, %cwp		! jump back to the original window
	wrpr	%g0, %o1, %cansave	! and restore the original register
	wrpr	%g0, %o4, %canrestore	! window state.
2:
	stn	%g3, [%o2]		! store the frame pointer and pc
	st	%g4, [%o3]		! so our caller can continue the trace

	retl				! return to caller
	wrpr	%g0, %o5, %pstate	! restore interrupts

3:
	flushw				! flush register windows, then
	ldn	[%fp + STACK_BIAS + 14*CLONGSIZE], %g3	! load initial fp
	ba	2b
	ldn	[%fp + STACK_BIAS + 15*CLONGSIZE], %g4	! and pc
	SET_SIZE(getpcstack_top)

	ENTRY_NP(setwstate)
	retl
	wrpr	%g0, %o0, %wstate
	SET_SIZE(setwstate)


	ENTRY_NP(getwstate)
	retl
	rdpr	%wstate, %o0
	SET_SIZE(getwstate)


/*
 * int panic_trigger(int *tp)
 *
 * A panic trigger is a word which is updated atomically and can only be set
 * once.  We atomically store 0xFF into the high byte and load the old value.
 * If the byte was 0xFF, the trigger has already been activated and we fail.
 * If the previous value was 0 or not 0xFF, we succeed.  This allows a
 * partially corrupt trigger to still trigger correctly.  DTrace has its own
 * version of this function to allow it to panic correctly from probe context.
 */

	ENTRY_NP(panic_trigger)
	ldstub	[%o0], %o0		! store 0xFF, load byte into %o0
	cmp	%o0, 0xFF		! compare %o0 to 0xFF
	set	1, %o1			! %o1 = 1
	be,a	0f			! if (%o0 == 0xFF) goto 0f (else annul)
	set	0, %o1			! delay - %o1 = 0
0:	retl
	mov	%o1, %o0		! return (%o1);
	SET_SIZE(panic_trigger)

	ENTRY_NP(dtrace_panic_trigger)
	ldstub	[%o0], %o0		! store 0xFF, load byte into %o0
	cmp	%o0, 0xFF		! compare %o0 to 0xFF
	set	1, %o1			! %o1 = 1
	be,a	0f			! if (%o0 == 0xFF) goto 0f (else annul)
	set	0, %o1			! delay - %o1 = 0
0:	retl
	mov	%o1, %o0		! return (%o1);
	SET_SIZE(dtrace_panic_trigger)

/*
 * void vpanic(const char *format, va_list alist)
 *
 * The panic() and cmn_err() functions invoke vpanic() as a common entry point
 * into the panic code implemented in panicsys().  vpanic() is responsible
 * for passing through the format string and arguments, and constructing a
 * regs structure on the stack into which it saves the current register
 * values.  If we are not dying due to a fatal trap, these registers will
 * then be preserved in panicbuf as the current processor state.  Before
 * invoking panicsys(), vpanic() activates the first panic trigger (see
 * common/os/panic.c) and switches to the panic_stack if successful.  Note that
 * DTrace takes a slightly different panic path if it must panic from probe
 * context.  Instead of calling panic, it calls into dtrace_vpanic(), which
 * sets up the initial stack as vpanic does, calls dtrace_panic_trigger(), and
 * branches back into vpanic().
 */

	ENTRY_NP(vpanic)

	save	%sp, -SA(MINFRAME + REGSIZE), %sp	! save and allocate regs

	!
	! The v9 struct regs has a 64-bit r_tstate field, which we use here
	! to store the %ccr, %asi, %pstate, and %cwp as they would appear
	! in %tstate if a trap occurred.  We leave it up to the debugger to
	! realize what happened and extract the register values.
	!
	rd	%ccr, %l0				! %l0 = %ccr
	sllx	%l0, TSTATE_CCR_SHIFT, %l0		! %l0 <<= CCR_SHIFT
	rd	%asi, %l1				! %l1 = %asi
	sllx	%l1, TSTATE_ASI_SHIFT, %l1		! %l1 <<= ASI_SHIFT
	or	%l0, %l1, %l0				! %l0 |= %l1
	rdpr	%pstate, %l1				! %l1 = %pstate
	sllx	%l1, TSTATE_PSTATE_SHIFT, %l1		! %l1 <<= PSTATE_SHIFT
	or	%l0, %l1, %l0				! %l0 |= %l1
	rdpr	%cwp, %l1				! %l1 = %cwp
	sllx	%l1, TSTATE_CWP_SHIFT, %l1		! %l1 <<= CWP_SHIFT
	or	%l0, %l1, %l0				! %l0 |= %l1

	set	vpanic, %l1				! %l1 = %pc (vpanic)
	add	%l1, 4, %l2				! %l2 = %npc (vpanic+4)
	rd	%y, %l3					! %l3 = %y
	!
	! Flush register windows before panic_trigger() in order to avoid a
	! problem that a dump hangs if flush_windows() causes another panic.
	!
	call	flush_windows
	nop

	sethi	%hi(panic_quiesce), %o0
	call	panic_trigger
	or	%o0, %lo(panic_quiesce), %o0		! if (!panic_trigger(

vpanic_common:
	tst	%o0					!     &panic_quiesce))
	be	0f					!   goto 0f;
	mov	%o0, %l4				!   delay - %l4 = %o0

	!
	! If panic_trigger() was successful, we are the first to initiate a
	! panic: switch to the panic_stack.
	!
	set	panic_stack, %o0			! %o0 = panic_stack
	set	PANICSTKSIZE, %o1			! %o1 = size of stack
	add	%o0, %o1, %o0				! %o0 = top of stack

	sub	%o0, SA(MINFRAME + REGSIZE) + STACK_BIAS, %sp

	!
	! Now that we've got everything set up, store each register to its
	! designated location in the regs structure allocated on the stack.
	! The register set we store is the equivalent of the registers at
	! the time the %pc was pointing to vpanic, thus the %i's now contain
	! what the %o's contained prior to the save instruction.
	!
0:	stx	%l0, [%sp + STACK_BIAS + SA(MINFRAME) + TSTATE_OFF]
	stx	%g1, [%sp + STACK_BIAS + SA(MINFRAME) + G1_OFF]
	stx	%g2, [%sp + STACK_BIAS + SA(MINFRAME) + G2_OFF]
	stx	%g3, [%sp + STACK_BIAS + SA(MINFRAME) + G3_OFF]
	stx	%g4, [%sp + STACK_BIAS + SA(MINFRAME) + G4_OFF]
	stx	%g5, [%sp + STACK_BIAS + SA(MINFRAME) + G5_OFF]
	stx	%g6, [%sp + STACK_BIAS + SA(MINFRAME) + G6_OFF]
	stx	%g7, [%sp + STACK_BIAS + SA(MINFRAME) + G7_OFF]
	stx	%i0, [%sp + STACK_BIAS + SA(MINFRAME) + O0_OFF]
	stx	%i1, [%sp + STACK_BIAS + SA(MINFRAME) + O1_OFF]
	stx	%i2, [%sp + STACK_BIAS + SA(MINFRAME) + O2_OFF]
	stx	%i3, [%sp + STACK_BIAS + SA(MINFRAME) + O3_OFF]
	stx	%i4, [%sp + STACK_BIAS + SA(MINFRAME) + O4_OFF]
	stx	%i5, [%sp + STACK_BIAS + SA(MINFRAME) + O5_OFF]
	stx	%i6, [%sp + STACK_BIAS + SA(MINFRAME) + O6_OFF]
	stx	%i7, [%sp + STACK_BIAS + SA(MINFRAME) + O7_OFF]
	stn	%l1, [%sp + STACK_BIAS + SA(MINFRAME) + PC_OFF]
	stn	%l2, [%sp + STACK_BIAS + SA(MINFRAME) + NPC_OFF]
	st	%l3, [%sp + STACK_BIAS + SA(MINFRAME) + Y_OFF]

	mov	%l4, %o3				! %o3 = on_panic_stack
	add	%sp, STACK_BIAS + SA(MINFRAME), %o2	! %o2 = &regs
	mov	%i1, %o1				! %o1 = alist
	call	panicsys				! panicsys();
	mov	%i0, %o0				! %o0 = format
	ret
	restore

	SET_SIZE(vpanic)

	ENTRY_NP(dtrace_vpanic)

	save	%sp, -SA(MINFRAME + REGSIZE), %sp	! save and allocate regs

	!
	! The v9 struct regs has a 64-bit r_tstate field, which we use here
	! to store the %ccr, %asi, %pstate, and %cwp as they would appear
	! in %tstate if a trap occurred.  We leave it up to the debugger to
	! realize what happened and extract the register values.
	!
	rd	%ccr, %l0				! %l0 = %ccr
	sllx	%l0, TSTATE_CCR_SHIFT, %l0		! %l0 <<= CCR_SHIFT
	rd	%asi, %l1				! %l1 = %asi
	sllx	%l1, TSTATE_ASI_SHIFT, %l1		! %l1 <<= ASI_SHIFT
	or	%l0, %l1, %l0				! %l0 |= %l1
	rdpr	%pstate, %l1				! %l1 = %pstate
	sllx	%l1, TSTATE_PSTATE_SHIFT, %l1		! %l1 <<= PSTATE_SHIFT
	or	%l0, %l1, %l0				! %l0 |= %l1
	rdpr	%cwp, %l1				! %l1 = %cwp
	sllx	%l1, TSTATE_CWP_SHIFT, %l1		! %l1 <<= CWP_SHIFT
	or	%l0, %l1, %l0				! %l0 |= %l1

	set	dtrace_vpanic, %l1			! %l1 = %pc (vpanic)
	add	%l1, 4, %l2				! %l2 = %npc (vpanic+4)
	rd	%y, %l3					! %l3 = %y
	!
	! Flush register windows before panic_trigger() in order to avoid a
	! problem that a dump hangs if flush_windows() causes another panic.
	!
	call	dtrace_flush_windows
	nop

	sethi	%hi(panic_quiesce), %o0
	call	dtrace_panic_trigger
	or	%o0, %lo(panic_quiesce), %o0		! if (!panic_trigger(

	ba,a	vpanic_common
	SET_SIZE(dtrace_vpanic)
	
	ENTRY(get_subcc_ccr)
	wr	%g0, %ccr	! clear condition codes
	subcc	%o0, %o1, %g0
	retl
	rd	%ccr, %o0	! return condition codes
	SET_SIZE(get_subcc_ccr)

	ENTRY_NP(ftrace_interrupt_disable)
	rdpr	%pstate, %o0
	andn	%o0, PSTATE_IE, %o1
	retl
	wrpr	%g0, %o1, %pstate
	SET_SIZE(ftrace_interrupt_disable)

	ENTRY_NP(ftrace_interrupt_enable)
	retl
	wrpr	%g0, %o0, %pstate 
	SET_SIZE(ftrace_interrupt_enable)

