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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * General machine architecture & implementation specific
 * assembly language routines.
 */
#include "assym.h"

#define CPU_MODULE /* need it for NSEC_SHIFT used by NATIVE_TIME_TO_NSEC() */

#include <sys/asm_linkage.h>
#include <sys/machsystm.h>
#include <sys/machthread.h>
#include <sys/machclock.h>
#include <sys/privregs.h>
#include <sys/cmpregs.h>
#include <sys/clock.h>
#include <sys/fpras.h>
#include <sys/soft_state.h>

/*
 * This isn't the routine you're looking for.
 *
 * The routine simply returns the value of %tick on the *current* processor.
 * Most of the time, gettick() [which in turn maps to %stick on platforms
 * that have different CPU %tick rates] is what you want.
 */

	ENTRY(ultra_gettick)
	RD_TICK(%o0,%o1,%o2,__LINE__)
	retl
	nop
	SET_SIZE(ultra_gettick)

	ENTRY(set_mmfsa_scratchpad)
	stxa	%o0, [%g0]ASI_SCRATCHPAD 
	retl
	nop
	SET_SIZE(set_mmfsa_scratchpad)

	ENTRY(get_mmfsa_scratchpad)
	ldxa	[%g0]ASI_SCRATCHPAD, %o0 
	retl
	nop
	SET_SIZE(get_mmfsa_scratchpad)



/*
 * Called from a x-trap at tl1 must use %g1 as arg
 * and save/restore %o0-%o5 after hypervisor calls
 */

	ENTRY(cpu_intrq_unregister_powerdown)

	CPU_ADDR(%g2, %g3)
	add %g2, CPU_MCPU, %g2 
	/*
	 * Save %o regs
	 */
	mov %o0, %g3
	mov %o1, %g4
	mov %o2, %g5
	mov %o5, %g6

	ldx [%g2 + MCPU_CPU_Q_BASE], %o1
	mov INTR_CPU_Q, %o0
	call hv_cpu_qconf
	mov %g0, %o2

	ldx [%g2 + MCPU_DEV_Q_BASE], %o1
	mov INTR_DEV_Q, %o0
	call hv_cpu_qconf
	mov %g0, %o2

	ldx [%g2 + MCPU_RQ_BASE], %o1
	mov CPU_RQ, %o0
	call hv_cpu_qconf
	mov %g0, %o2

	ldx [%g2 + MCPU_NRQ_BASE], %o1
	mov CPU_NRQ, %o0
	call hv_cpu_qconf
	mov %g0, %o2

	/*
	 * set done flag to 0
	 */
	stub %g0, [%g1]

	/*
	 * Restore %o regs
	 */
	mov %g3, %o0
	mov %g4, %o1
	mov %g5, %o2
	mov %g6, %o5

	/*
	 * This CPU is on its way out. Spin here
	 * until the DR unconfigure code stops it.
	 * Returning would put it back in the OS
	 * where it might grab resources like locks,
	 * causing some nastiness to occur.
	 */
0:
	ba,a	0b

	SET_SIZE(cpu_intrq_unregister_powerdown)


/*
 * Get the processor ID.
 * === MID reg as specified in 15dec89 sun4u spec, sec 5.4.3
 */

	ENTRY(getprocessorid)
	CPU_INDEX(%o0, %o1)
	retl
	nop
	SET_SIZE(getprocessorid)

	ENTRY_NP(tick2ns)
	!
	! Use nsec_scale for sun4v which is based on %stick
	!
	NATIVE_TIME_TO_NSEC(%o0, %o2, %o3)
	retl
	nop
	SET_SIZE(tick2ns)

	ENTRY(set_cmp_error_steering)
	retl
	nop
	SET_SIZE(set_cmp_error_steering)

	ENTRY(ultra_getver)
	retl
	mov	-1, %o0		! XXXQ no version available
	SET_SIZE(ultra_getver)

	/*
	 * Check instructions using just the AX pipelines, designed by
	 * C.B. Liaw of PNP.
	 *
	 * This function must match a struct fpras_chkfn and must be
	 * block aligned.  A zero return means all was well.  These
	 * instructions are chosen to be sensitive to bit corruptions
	 * on the fpras rewrite, so if a bit corruption still produces
	 * a valid instruction we should still get an incorrect result
	 * here.  This function is never called directly - it is copied
	 * into per-cpu and per-operation buffers;  it must therefore
	 * be absolutely position independent.  If an illegal instruction
	 * is encountered then the trap handler trampolines to the final
	 * three instructions of this function.
	 *
	 * We want two instructions that are complements of one another,
	 * and which can perform a calculation with a known result.
	 *
	 * SETHI:
	 *
	 * | 0 0 |  rd   | 1 0 0 |	imm22				|
	 *  31 30 29   25 24   22 21				       0
	 *
	 * ADDCCC with two source registers:
	 *
	 * | 1 0 |  rd   | 0 1 1   0 0 0 |  rs1  | 0 |	   -	|  rs2  |
	 *  31 30 29   25 24           19 18   14 13  12       5 4     0
	 *
	 * We can choose rd and imm2 of the SETHI and rd, rs1 and rs2 of
	 * the ADDCCC to obtain instructions that are complements in all but
	 * bit 30.
	 *
	 * Registers are numbered as follows:
	 *
	 * r[31]	%i7
	 * r[30]	%i6
	 * r[29]	%i5
	 * r[28]	%i4
	 * r[27]	%i3
	 * r[26]	%i2
	 * r[25]	%i1
	 * r[24]	%i0
	 * r[23]	%l7
	 * r[22]	%l6
	 * r[21]	%l5
	 * r[20]	%l4
	 * r[19]	%l3
	 * r[18]	%l2
	 * r[17]	%l1
	 * r[16]	%l0
	 * r[15]	%o7
	 * r[14]	%o6
	 * r[13]	%o5
	 * r[12]	%o4
	 * r[11]	%o3
	 * r[10]	%o2
	 * r[9]		%o1
	 * r[8]		%o0	
	 * r[7]		%g7
	 * r[6]		%g6
	 * r[5]		%g5
	 * r[4]		%g4
	 * r[3]		%g3
	 * r[2]		%g2
	 * r[1]		%g1
	 * r[0]		%g0
	 *
	 * For register r[n], register r[31-n] is the complement.  We must
	 * avoid use of %i6/%i7 and %o6/%o7 as well as %g7.  Clearly we need
	 * to use a local or input register as one half of the pair, which
	 * requires us to obtain our own register window or take steps
	 * to preserve any local or input we choose to use.  We choose
	 * %o1 as rd for the SETHI, so rd of the ADDCCC must be %l6.
	 * We'll use %o1 as rs1 and %l6 as rs2 of the ADDCCC, which then
	 * requires that imm22 be 0b111 10110 1 11111111 01001 or 0x3dbfe9,
	 * or %hi(0xf6ffa400).  This determines the value of the constant
	 * CBV2 below.
	 *
	 * The constant CBV1 is chosen such that an initial subcc %g0, CBV1
	 * will set the carry bit and every addccc thereafter will continue
	 * to generate a carry.  Other values are possible for CBV1 - this
	 * is just one that works this way.
	 *
	 * Finally CBV3 is the expected answer when we perform our repeated
	 * calculations on CBV1 and CBV2 - it is not otherwise specially
	 * derived.  If this result is not obtained then a corruption has
	 * occured during the FPRAS_REWRITE of one of the two blocks of
	 * 16 instructions.  A corruption could also result in an illegal
	 * instruction or other unexpected trap - we catch illegal
	 * instruction traps in the PC range and trampoline to the
	 * last instructions of the function to return a failure indication.
	 *
	 */

#define	CBV1		0xc11
#define	CBV2		0xf6ffa400
#define	CBV3		0x66f9d800
#define	CBR1		%o1
#define	CBR2		%l6
#define	CBO2		%o2
#define	SETHI_CBV2_CBR1		sethi %hi(CBV2), CBR1
#define	ADDCCC_CBR1_CBR2_CBR2	addccc CBR1, CBR2, CBR2

	.align	64
	ENTRY_NP(fpras_chkfn_type1)
	mov	CBR2, CBO2		! 1, preserve CBR2 of (callers) window
	mov	FPRAS_OK, %o0		! 2, default return value
	ba,pt	%icc, 1f		! 3
	  subcc %g0, CBV1, CBR2		! 4
					! 5 - 16
	.align	64
1:	SETHI_CBV2_CBR1			! 1
	ADDCCC_CBR1_CBR2_CBR2		! 2
	SETHI_CBV2_CBR1			! 3
	ADDCCC_CBR1_CBR2_CBR2		! 4
	SETHI_CBV2_CBR1			! 5
	ADDCCC_CBR1_CBR2_CBR2		! 6
	SETHI_CBV2_CBR1			! 7
	ADDCCC_CBR1_CBR2_CBR2		! 8
	SETHI_CBV2_CBR1			! 9
	ADDCCC_CBR1_CBR2_CBR2		! 10
	SETHI_CBV2_CBR1			! 11
	ADDCCC_CBR1_CBR2_CBR2		! 12
	SETHI_CBV2_CBR1			! 13
	ADDCCC_CBR1_CBR2_CBR2		! 14
	SETHI_CBV2_CBR1			! 15
	ADDCCC_CBR1_CBR2_CBR2		! 16

	ADDCCC_CBR1_CBR2_CBR2		! 1
	SETHI_CBV2_CBR1			! 2
	ADDCCC_CBR1_CBR2_CBR2		! 3
	SETHI_CBV2_CBR1			! 4
	ADDCCC_CBR1_CBR2_CBR2		! 5
	SETHI_CBV2_CBR1			! 6
	ADDCCC_CBR1_CBR2_CBR2		! 7
	SETHI_CBV2_CBR1			! 8
	ADDCCC_CBR1_CBR2_CBR2		! 9
	SETHI_CBV2_CBR1			! 10
	ADDCCC_CBR1_CBR2_CBR2		! 11
	SETHI_CBV2_CBR1			! 12
	ADDCCC_CBR1_CBR2_CBR2		! 13
	SETHI_CBV2_CBR1			! 14
	ADDCCC_CBR1_CBR2_CBR2		! 15
	SETHI_CBV2_CBR1			! 16

	addc	CBR1, CBR2, CBR2	! 1
	sethi	%hi(CBV3), CBR1		! 2
	cmp	CBR1, CBR2		! 3
	movnz	%icc, FPRAS_BADCALC, %o0! 4, how detected
	retl				! 5
	  mov	CBO2, CBR2		! 6, restore borrowed register
	.skip 4*(13-7+1)		! 7 - 13
					!
					! illegal instr'n trap comes here
					!
	mov	CBO2, CBR2		! 14, restore borrowed register
	retl				! 15
	  mov	FPRAS_BADTRAP, %o0	! 16, how detected
	SET_SIZE(fpras_chkfn_type1)

	.seg	".data"
	.global soft_state_message_strings

	.align	SSM_SIZE
soft_state_message_strings:
	.asciz	SOLARIS_SOFT_STATE_BOOT_MSG_STR
	.align	SSM_SIZE
	.asciz	SOLARIS_SOFT_STATE_RUN_MSG_STR
	.align	SSM_SIZE
	.asciz	SOLARIS_SOFT_STATE_HALT_MSG_STR
	.align	SSM_SIZE
	.asciz	SOLARIS_SOFT_STATE_POWER_MSG_STR
	.align	SSM_SIZE
	.asciz	SOLARIS_SOFT_STATE_PANIC_MSG_STR
	.align	SSM_SIZE
	.asciz	SOLARIS_SOFT_STATE_REBOOT_MSG_STR
	.align	SSM_SIZE
	.asciz	SOLARIS_SOFT_STATE_DEBUG_MSG_STR
	.align	SSM_SIZE
	.skip	SSM_SIZE			/* saved message */
	.nword	0

	.seg	".text"
