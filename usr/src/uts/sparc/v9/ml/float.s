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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/machpcb.h>
#include <sys/machtrap.h>
#include <sys/machsig.h>
#include <sys/machthread.h>

#include "assym.h"

/*
 * Floating point trap handling.
 *
 *	The FPU is always in a V9 current configuration.
 *
 *	When a user process is first started via exec,
 *	floating point operations will be disabled by default.
 *	Upon execution of the first floating point instruction,
 *	a fp_disabled trap will be generated; then a word in
 *	the uarea is written signifying use of the floating point
 *	registers so that subsequent context switches will save
 *	and restore the floating point them. The trapped instruction
 *	will be restarted and processing will continue as normal.
 *
 *	When a operation occurs that the hardware cannot properly
 *	handle, an unfinshed fp_op exception will be generated.
 *	Software routines in the kernel will be	executed to
 *	simulate proper handling of such conditions.
 *
 *	Exception handling will emulate all instructions
 *	in the floating point address queue. Note that there
 *	is no %fq in sun4u, because it has precise FP traps.
 *
 *	Floating point queues are now machine dependent, and std %fq
 *	is an illegal V9 instruction. The fp_exception code has been
 *	moved to sun4u/ml/machfloat.s.
 *
 *	NOTE: This code DOES NOT SUPPORT KERNEL (DEVICE DRIVER)
 *		USE OF THE FPU
 *
 *	Instructions for running without the hardware fpu:
 *	1. Setting fpu_exists to 0 now only works on a DEBUG kernel.
 *	2. adb -w unix and set fpu_exists, use_hw_bcopy, use_hw_copyio, and
 *		use_hw_bzero to 0 and rename libc_psr.so.1 in
 *		/usr/platform/sun4u/lib so that it will not get used by
 *		the libc bcopy routines. Then reboot the system and you
 *		should see the bootup message "FPU not in use".
 *	3. To run kaos, you must comment out the code which sets the
 *		version number of the fsr to 7, in fldst: stfsr/stxfsr
 *		(unless you are running against a comparison system that
 *		has the same fsr version number).
 *	4. The stqf{a}/ldqf{a} instructions cause kaos errors, for reasons
 *		that appear to be a kaos bug, so don't use them!
 */

	.section ".data"
	.align	8
fsrholder:
	.word	0			! dummy place to write fsr
	.word	0

	DGDEF(fpu_exists)		! always exists for V9
#ifdef FP_DISABLED
	.word	0
#else
	.word	1			! sundiag (gack) uses this variable
#endif

	DGDEF(fpu_version)
	.word	-1

/*
 * FPU probe - read the %fsr and get fpu_version.
 * Called from autoconf. If a %fq is created for
 * future cpu versions, a fq_exists variable
 * could be created by this function.
 */

	ENTRY_NP(fpu_probe)
	wr	%g0, FPRS_FEF, %fprs	! enable fpu in fprs
	rdpr	%pstate, %g2		! read pstate, save value in %g2
	or	%g2, PSTATE_PEF, %g1	! new pstate with fpu enabled
	wrpr	%g1, %g0, %pstate	! write pstate

	sethi	%hi(fsrholder), %g2
	stx	%fsr, [%g2 + %lo(fsrholder)]
	ldx	[%g2 + %lo(fsrholder)], %g2	! snarf the FSR
	set	FSR_VER, %g1
	and	%g2, %g1, %g2			! get version
	srl	%g2, FSR_VER_SHIFT, %g2		! and shift it down
	sethi	%hi(fpu_version), %g3		! save the FPU version
	st	%g2, [%g3 + %lo(fpu_version)]

	ba	fp_kstat_init		! initialize the fpu_kstat
	wr	%g0, %g0, %fprs		! disable fpu and clear fprs
	SET_SIZE(fpu_probe)

/*
 * fp_clearregs(fp)
 *	struct v9_fpu *fp;
 *
 * Initialization for the hardware fpu.
 * Clear the fsr and initialize registers to NaN (-1)
 * The caller (fp_disabled) is supposed to update the fprs
 * so when the return to userland is made, the fpu is enabled.
 */

	ENTRY_NP(fp_clearregs)
	ldx	[%o0 + FPU_FSR], %fsr		! load fsr

	mov	-1, %g2				! -1 is NaN
	stx	%g2, [%o0]			! initialize %f0
	ldd	[%o0], %d0
	ldd	[%o0], %d2
	ldd	[%o0], %d4
	ldd	[%o0], %d6
	ldd	[%o0], %d8
	ldd	[%o0], %d10
	ldd	[%o0], %d12
	ldd	[%o0], %d14
	ldd	[%o0], %d16
	ldd	[%o0], %d18
	ldd	[%o0], %d20
	ldd	[%o0], %d22
	ldd	[%o0], %d24
	ldd	[%o0], %d26
	ldd	[%o0], %d28
	ldd	[%o0], %d30
	ldd	[%o0], %d32
	ldd	[%o0], %d34
	ldd	[%o0], %d36
	ldd	[%o0], %d38
	ldd	[%o0], %d40
	ldd	[%o0], %d42
	ldd	[%o0], %d44
	ldd	[%o0], %d46
	ldd	[%o0], %d48
	ldd	[%o0], %d50
	ldd	[%o0], %d52
	ldd	[%o0], %d54
	ldd	[%o0], %d56
	ldd	[%o0], %d58
	ldd	[%o0], %d60
	retl
	ldd	[%o0], %d62
	SET_SIZE(fp_clearregs)

/*
 * void _fp_read_pfreg(pf, n)
 *	uint32_t	*pf;	Old freg value.
 *	unsigned	n;	Want to read register n
 *
 * {
 *	*pf = %f[n];
 * }
 *
 * void
 * _fp_write_pfreg(pf, n)
 *	uint32_t	*pf;	New freg value.
 *	unsigned	n;	Want to write register n.
 *
 * {
 *	%f[n] = *pf;
 * }
 */

	ENTRY_NP(_fp_read_pfreg)
	sll	%o1, 3, %o1		! Table entries are 8 bytes each.
	set	.stable, %g1		! g1 gets base of table.
	jmp	%g1 + %o1		! Jump into table
	nop				! Can't follow CTI by CTI.

	ENTRY_NP(_fp_write_pfreg)
	sll	%o1, 3, %o1		! Table entries are 8 bytes each.
	set	.ltable, %g1		! g1 gets base of table.
	jmp	%g1 + %o1		! Jump into table
	nop				! Can't follow CTI by CTI.

#define STOREFP(n) jmp %o7+8 ; st %f/**/n, [%o0]

.stable:
	STOREFP(0)
	STOREFP(1)
	STOREFP(2)
	STOREFP(3)
	STOREFP(4)
	STOREFP(5)
	STOREFP(6)
	STOREFP(7)
	STOREFP(8)
	STOREFP(9)
	STOREFP(10)
	STOREFP(11)
	STOREFP(12)
	STOREFP(13)
	STOREFP(14)
	STOREFP(15)
	STOREFP(16)
	STOREFP(17)
	STOREFP(18)
	STOREFP(19)
	STOREFP(20)
	STOREFP(21)
	STOREFP(22)
	STOREFP(23)
	STOREFP(24)
	STOREFP(25)
	STOREFP(26)
	STOREFP(27)
	STOREFP(28)
	STOREFP(29)
	STOREFP(30)
	STOREFP(31)

#define LOADFP(n) jmp %o7+8 ; ld [%o0],%f/**/n

.ltable:
	LOADFP(0)
	LOADFP(1)
	LOADFP(2)
	LOADFP(3)
	LOADFP(4)
	LOADFP(5)
	LOADFP(6)
	LOADFP(7)
	LOADFP(8)
	LOADFP(9)
	LOADFP(10)
	LOADFP(11)
	LOADFP(12)
	LOADFP(13)
	LOADFP(14)
	LOADFP(15)
	LOADFP(16)
	LOADFP(17)
	LOADFP(18)
	LOADFP(19)
	LOADFP(20)
	LOADFP(21)
	LOADFP(22)
	LOADFP(23)
	LOADFP(24)
	LOADFP(25)
	LOADFP(26)
	LOADFP(27)
	LOADFP(28)
	LOADFP(29)
	LOADFP(30)
	LOADFP(31)
	SET_SIZE(_fp_read_pfreg)
	SET_SIZE(_fp_write_pfreg)

/*
 * void _fp_read_pdreg(
 *	uint64_t	*pd,	Old dreg value.
 *	u_int	n)		Want to read register n
 *
 * {
 *	*pd = %d[n];
 * }
 *
 * void
 * _fp_write_pdreg(
 *	uint64_t	*pd,	New dreg value.
 *	u_int	n)		Want to write register n.
 *
 * {
 *	%d[n] = *pd;
 * }
 */

	ENTRY_NP(_fp_read_pdreg)
	sll	%o1, 3, %o1		! Table entries are 8 bytes each.
	set	.dstable, %g1		! g1 gets base of table.
	jmp	%g1 + %o1		! Jump into table
	nop				! Can't follow CTI by CTI.

	ENTRY_NP(_fp_write_pdreg)
	sll	%o1, 3, %o1		! Table entries are 8 bytes each.
	set	.dltable, %g1		! g1 gets base of table.
	jmp	%g1 + %o1		! Jump into table
	nop				! Can't follow CTI by CTI.

#define STOREDP(n) jmp %o7+8 ; std %d/**/n, [%o0]

.dstable:
	STOREDP(0)
	STOREDP(2)
	STOREDP(4)
	STOREDP(6)
	STOREDP(8)
	STOREDP(10)
	STOREDP(12)
	STOREDP(14)
	STOREDP(16)
	STOREDP(18)
	STOREDP(20)
	STOREDP(22)
	STOREDP(24)
	STOREDP(26)
	STOREDP(28)
	STOREDP(30)
	STOREDP(32)
	STOREDP(34)
	STOREDP(36)
	STOREDP(38)
	STOREDP(40)
	STOREDP(42)
	STOREDP(44)
	STOREDP(46)
	STOREDP(48)
	STOREDP(50)
	STOREDP(52)
	STOREDP(54)
	STOREDP(56)
	STOREDP(58)
	STOREDP(60)
	STOREDP(62)

#define LOADDP(n) jmp %o7+8 ; ldd [%o0],%d/**/n

.dltable:
	LOADDP(0)
	LOADDP(2)
	LOADDP(4)
	LOADDP(6)
	LOADDP(8)
	LOADDP(10)
	LOADDP(12)
	LOADDP(14)
	LOADDP(16)
	LOADDP(18)
	LOADDP(20)
	LOADDP(22)
	LOADDP(24)
	LOADDP(26)
	LOADDP(28)
	LOADDP(30)
	LOADDP(32)
	LOADDP(34)
	LOADDP(36)
	LOADDP(38)
	LOADDP(40)
	LOADDP(42)
	LOADDP(44)
	LOADDP(46)
	LOADDP(48)
	LOADDP(50)
	LOADDP(52)
	LOADDP(54)
	LOADDP(56)
	LOADDP(58)
	LOADDP(60)
	LOADDP(62)
	SET_SIZE(_fp_read_pdreg)
	SET_SIZE(_fp_write_pdreg)

	ENTRY_NP(_fp_write_pfsr)
	retl
	ldx	[%o0], %fsr
	SET_SIZE(_fp_write_pfsr)

	ENTRY_NP(_fp_read_pfsr)
	retl
	stx	%fsr, [%o0]
	SET_SIZE(_fp_read_pfsr)

	ENTRY_NP(_fp_write_fprs)
	retl
	wr	%o0, %g0, %fprs			! write fprs
	SET_SIZE(_fp_write_fprs)

	ENTRY_NP(_fp_read_fprs)
	retl
	rd	%fprs, %o0			! save fprs
	SET_SIZE(_fp_read_fprs)

	ENTRY_NP(_fp_subcc_ccr)
	subcc	%o0, %o1, %g0
	retl
	rd	%ccr, %o0			! save ccr
	SET_SIZE(_fp_subcc_ccr)

/*
 * Floating Point Exceptions handled according to type:
 *	2) unfinished_fpop
 *		re-execute the faulty instruction(s) using
 *		software emulation (must do every instruction in FQ)
 *	3) unimplemented_fpop
 *		an unimplemented instruction, if it is legal,
 *		will cause emulation of the instruction (and all
 *		other instuctions in the FQ)
 *	4) sequence_error
 *		panic, this should not happen, and if it does it
 *		it is the result of a kernel bug
 *
 * This code assumes the trap preamble has set up the window environment
 * for execution of kernel code.
 * Note: this code could be changed to be part of the cpu-specific
 * (ie, Spitfire-specific) module code before final release.
 */

	ENTRY_NP(_fp_exception)
	mov	%o7, %l0		! saved return address
	mov	%o0, %l1		! saved *rp
	set     FSR_FTT, %o4		! put FSR_FTT in %o4
	xor	%o4, 0xffffffffffffffff, %o3 ! xor FSR_FTT to get
	and     %o1, %o3, %o2		! an fsr with a zero'd ftt
	ldn	[THREAD_REG + T_LWP], %o3 ! get lwp
	ldn	[%o3 + LWP_FPU], %l3	! get lwp_fpu
	stx	%o2, [%l3 + FPU_FSR]	! save floating point status
	and	%o1, %o4, %g2		! get the ftt trap type
#ifdef  DEBUG
	brnz,a,pt %g2, fttok
	  nop
	set	.badfpfttmsg, %o0	! panic message
	call	panic			! %o1 has the fsr w/ftt value
	nop
fttok:
#endif  /* DEBUG */
	srl	%g2, FSR_FTT_SHIFT, %o4	! check ftt
	cmp	%o4, FTT_SEQ		! sanity check for bogus exceptions
	!
	! traps are already enabled to allow other
	! interrupts while emulating floating point instructions
	!
	blt,a,pt %xcc, fpeok
	nop
	!
	! Sequence error or unknown ftt exception.
	!
seq_error:
	set	.badfpexcpmsg, %o0	! panic if bad ftt
	call	panic
	sra	%o4, 0, %o1		! mov ftt to o1 for panic message

fpeok:
	call	fp_kstat_update		! fp_kstat_update(ftt)
	mov	%o4, %o0		! ftt
	!
	! Get the floating point instruction, and run the floating
	! point simulator. There is no floating point queue, so we fake one.
	!
	call	fp_precise		! fp_precise(&regs)
	mov	%l1, %o0		! saved *rp

fp_ret:
	rd	%fprs, %g1		! read fprs, save value in %g1
	st	%g1, [%l3 + FPU_FPRS]	! save fprs
	jmp	%l0 + 8			! jump to saved return address
	stx	%fsr, [%l3 + FPU_FSR]	! save fsr
	SET_SIZE(_fp_exception)

.badfpexcpmsg:
	.asciz	"unexpected floating point exception %x"

#ifdef	DEBUG
.badfpfttmsg:
	.asciz	"No floating point ftt, fsr %llx"
#endif	/* DEBUG */

/*
 * Floating Point Exceptions.
 * handled according to type:
 *	1) IEEE_exception
 *		re-execute the faulty instruction(s) using
 *		software emulation (must do every instruction in FQ)
 *
 * This code assumes the trap preamble has set up the window environment
 * for execution of kernel code.
 */

	ENTRY_NP(_fp_ieee_exception)
	mov	%o7, %l0		! saved return address
	mov	%o0, %l1		! saved *rp
	mov	%o1, %l2		! saved fsr
	set	FSR_FTT, %o4		! put FSR_FTT in %o4
	xor	%o4, 0xffffffffffffffff, %o3 ! ! xor FSR_FTT to get
	and	%o1, %o3, %o2		! an fsr with a zero'd ftt
	ldn	[THREAD_REG + T_LWP], %o3 ! get lwp
	ldn	[%o3 + LWP_FPU], %l3	! get lwp_fpu
	stx	%o2, [%l3 + FPU_FSR]	! save floating point status
	stub	%g0, [%l3 + FPU_QCNT]	! clear fpu_qcnt
	and	%o1, %o4, %g2		! mask out trap type
#ifdef  DEBUG
	brnz,a,pt %g2, fttgd
	  nop
	set	.badfpfttmsg, %o0	! panic message
	call	panic			! %o1 has the fsr w/ftt value
	nop
fttgd:
#endif	/* DEBUG */
	srl	%g2, FSR_FTT_SHIFT, %o4	! check ftt
	cmp	%o4, FTT_SEQ		! sanity check for bogus exceptions
	!
	! traps are already enabled to allow other
	! interrupts while emulating floating point instructions
	!
	blt,a,pt %xcc, fpegd
	nop
	!
	! Sequence error or unknown ftt exception.
	!
seq_err:
	set	.badfpexcpmsg, %o0	! panic if bad ftt
	call	panic
	sra	%o4, 0, %o1		! mov ftt to o1 for panic message

fpegd:
	call	fp_kstat_update		! fp_kstat_update(ftt)
	mov	%o4, %o0		! ftt
	!
	! Call fpu_trap directly, don't bother to run the fp simulator.
	! The *rp is already in %o0. Clear fpu_qcnt.
	!
	set	(T_FP_EXCEPTION_IEEE), %o2	! trap type

	set	FSR_CEXC, %o3
	and	%l2, %o3, %g2		! mask out cexc

	andcc	%g2, FSR_CEXC_NX, %g0	! check for inexact
	bnz,a,pt %xcc, fpok
	or	%g0, FPE_FLTRES, %o3	! fp inexact code

	andcc	%g2, FSR_CEXC_DZ, %g0	! check for divide-by-zero
	bnz,a,pt %xcc, fpok
	or	%g0, FPE_FLTDIV, %o3	! fp divide by zero code

	andcc	%g2, FSR_CEXC_UF, %g0	! check for underflow
	bnz,a,pt %xcc, fpok
	or	%g0, FPE_FLTUND, %o3	! fp underflow code

	andcc	%g2, FSR_CEXC_OF, %g0	! check for overflow
	bnz,a,pt %xcc, fpok
	or	%g0, FPE_FLTOVF, %o3	! fp overflow code

	andcc	%g2, FSR_CEXC_NV, %g0	! check for invalid
	bnz,a,pn %xcc, fpok
	or	%g0, FPE_FLTINV, %o3	! fp invalid code

cexec_err:
	set	.badfpcexcmsg, %o0	! panic message
	call	panic			! panic if no cexc bit set
	mov	%g1, %o1
fpok:
	mov	%l1, %o0		! saved *rp
	call	fpu_trap		! fpu_trap(&regs, addr, type, code)
	ldn	[%o0 + PC_OFF], %o1 	! address of trapping instruction

	rd	%fprs, %g1		! read fprs, save value in %g1
	st	%g1, [%l3 + FPU_FPRS]	! save fprs
	jmp	%l0 + 8			! jump to saved return address
	stx	%fsr, [%l3 + FPU_FSR]	! save fsr
	SET_SIZE(_fp_ieee_exception)

.badfpcexcmsg:
	.asciz	"No floating point exception, fsr %llx"

