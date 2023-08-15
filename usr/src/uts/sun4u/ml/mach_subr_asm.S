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
 * General machine architecture & implementation specific
 * assembly language routines.
 */
#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/machsystm.h>
#include <sys/machthread.h>
#include <sys/privregs.h>
#include <sys/cmpregs.h>
#include <sys/clock.h>
#include <sys/fpras.h>

/*
 * This isn't the routine you're looking for.
 *
 * The routine simply returns the value of %tick on the *current* processor.
 * Most of the time, gettick() [which in turn maps to %stick on platforms
 * that have different CPU %tick rates] is what you want.
 */

	ENTRY(ultra_gettick)
	retl
	rdpr	%tick, %o0
	SET_SIZE(ultra_gettick)

/*
 * Get the processor ID.
 * === MID reg as specified in 15dec89 sun4u spec, sec 5.4.3
 */

	ENTRY(getprocessorid)
	CPU_INDEX(%o0, %o1)
	retl
	nop
	SET_SIZE(getprocessorid)

	ENTRY(set_error_enable_tl1)
	cmp	%g2, EER_SET_ABSOLUTE
	be	%xcc, 1f
	  nop
	ldxa	[%g0]ASI_ESTATE_ERR, %g3
	membar	#Sync
	cmp	%g2, EER_SET_SETBITS
	be,a	%xcc, 1f
	  or	%g3, %g1, %g1
	andn	%g3, %g1, %g1			/* EER_SET_CLRBITS */
1:
	stxa	%g1, [%g0]ASI_ESTATE_ERR	/* ecache error enable reg */
	membar	#Sync
	retry
	SET_SIZE(set_error_enable_tl1)

	ENTRY(set_error_enable)
	stxa	%o0, [%g0]ASI_ESTATE_ERR	/* ecache error enable reg */
	membar	#Sync
	retl
	nop
	SET_SIZE(set_error_enable)

	ENTRY(get_error_enable)
	retl
	ldxa	[%g0]ASI_ESTATE_ERR, %o0	/* ecache error enable reg */
	SET_SIZE(get_error_enable)

	ENTRY(get_asyncflt)
	ldxa	[%g0]ASI_AFSR, %o1		! afsr reg
	retl
	stx	%o1, [%o0]
	SET_SIZE(get_asyncflt)

	ENTRY(set_asyncflt)
	stxa	%o0, [%g0]ASI_AFSR		! afsr reg
	membar	#Sync
	retl
	nop
	SET_SIZE(set_asyncflt)

	ENTRY(get_asyncaddr)
	ldxa	[%g0]ASI_AFAR, %o1		! afar reg
	retl
	stx	%o1, [%o0]
	SET_SIZE(get_asyncaddr)

	ENTRY_NP(tick2ns)
	sethi	%hi(cpunodes), %o4
	or	%o4, %lo(cpunodes), %o4		! %o4 = &cpunodes
	! Register usage:
	!
	! o0 = timestamp
	! o2 = byte offset into cpunodes for tick_nsec_scale of this CPU
	! o4 = &cpunodes
	!
	mulx	%o1, CPU_NODE_SIZE, %o2	! %o2 = byte offset into cpunodes
	add	%o2, TICK_NSEC_SCALE, %o2
	ld	[%o4 + %o2], %o2	! %o2 = cpunodes[cpuid].tick_nsec_scale
	NATIVE_TIME_TO_NSEC_SCALE(%o0, %o2, %o3, TICK_NSEC_SHIFT)
	retl
	nop
	SET_SIZE(tick2ns)

	ENTRY(set_cmp_error_steering)
	membar	#Sync
	set	ASI_CORE_ID, %o0		! %o0 = ASI_CORE_ID
	ldxa	[%o0]ASI_CMP_PER_CORE, %o0	! get ASI_CORE_ID
	and	%o0, COREID_MASK, %o0
	set	ASI_CMP_ERROR_STEERING, %o1	! %o1 = ERROR_STEERING_REG
	stxa	%o0, [%o1]ASI_CMP_SHARED	! this core now hadles
	membar	#Sync				!  non-core specific errors
	retl
	nop
	SET_SIZE(set_cmp_error_steering)

	ENTRY(ultra_getver)
	retl
	rdpr	%ver, %o0
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

/*
 * fp_zero() - clear all fp data registers and the fsr
 */

	ENTRY_NP(fp_zero)
	std	%g0, [%sp + ARGPUSH + STACK_BIAS]
	fzero	%f0
	fzero	%f2
	ldd	[%sp + ARGPUSH + STACK_BIAS], %fsr
	faddd	%f0, %f2, %f4
	fmuld	%f0, %f2, %f6
	faddd	%f0, %f2, %f8
	fmuld	%f0, %f2, %f10
	faddd	%f0, %f2, %f12
	fmuld	%f0, %f2, %f14
	faddd	%f0, %f2, %f16
	fmuld	%f0, %f2, %f18
	faddd	%f0, %f2, %f20
	fmuld	%f0, %f2, %f22
	faddd	%f0, %f2, %f24
	fmuld	%f0, %f2, %f26
	faddd	%f0, %f2, %f28
	fmuld	%f0, %f2, %f30
	faddd	%f0, %f2, %f32
	fmuld	%f0, %f2, %f34
	faddd	%f0, %f2, %f36
	fmuld	%f0, %f2, %f38
	faddd	%f0, %f2, %f40
	fmuld	%f0, %f2, %f42
	faddd	%f0, %f2, %f44
	fmuld	%f0, %f2, %f46
	faddd	%f0, %f2, %f48
	fmuld	%f0, %f2, %f50
	faddd	%f0, %f2, %f52
	fmuld	%f0, %f2, %f54
	faddd	%f0, %f2, %f56
	fmuld	%f0, %f2, %f58
	faddd	%f0, %f2, %f60
	retl
	fmuld	%f0, %f2, %f62
	SET_SIZE(fp_zero)

