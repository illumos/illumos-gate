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

/* Integer Unit simulator for Sparc FPU simulator. */

#include <sys/fpu/fpu_simulator.h>
#include <sys/fpu/globals.h>

#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/vis_simulator.h>

/*
 * fbcc_sim() also handles V9 fbpcc, and ignores the prediction bit.
 */
static enum ftt_type
fbcc_sim(
	fp_inst_type    pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	kfpu_t		*pfpu)	/* Pointer to FPU register block. */

{
	fsr_type	fsr;
	int fbpcc = 0;
	union {
		fp_inst_type	fi;
		int32_t		i;	/* for sign_ext(disp22) */
	} fp;
	enum fcc_type	fcc;
	enum icc_type {
		fbn, fbne, fblg, fbul, fbl, fbug, fbg, fbu,
		fba, fbe, fbue, fbge, fbuge, fble, fbule, fbo
	} icc;

	uint_t	annul, takeit;

	if (((pinst.op3 >> 3) & 0xf) == 5)
		fbpcc = 1;
	fsr.ll = pfpu->fpu_fsr;
	if (fbpcc) {
		uint_t nfcc = (pinst.op3 >> 1) & 0x3;
		switch (nfcc) {
			case fcc_0:
				fcc = fsr.fcc0;
				break;
			case fcc_1:
				fcc = fsr.fcc1;
				break;
			case fcc_2:
				fcc = fsr.fcc2;
				break;
			case fcc_3:
				fcc = fsr.fcc3;
				break;
			}
	} else {
		fcc = fsr.fcc0;
	}
	icc = (enum icc_type) (pinst.rd & 0xf);
	annul = pinst.rd & 0x10;

	switch (icc) {
	case fbn:
		takeit = 0;
		break;
	case fbl:
		takeit = fcc == fcc_less;
		break;
	case fbg:
		takeit = fcc == fcc_greater;
		break;
	case fbu:
		takeit = fcc == fcc_unordered;
		break;
	case fbe:
		takeit = fcc == fcc_equal;
		break;
	case fblg:
		takeit = (fcc == fcc_less) || (fcc == fcc_greater);
		break;
	case fbul:
		takeit = (fcc == fcc_unordered) || (fcc == fcc_less);
		break;
	case fbug:
		takeit = (fcc == fcc_unordered) || (fcc == fcc_greater);
		break;
	case fbue:
		takeit = (fcc == fcc_unordered) || (fcc == fcc_equal);
		break;
	case fbge:
		takeit = (fcc == fcc_greater) || (fcc == fcc_equal);
		break;
	case fble:
		takeit = (fcc == fcc_less) || (fcc == fcc_equal);
		break;
	case fbne:
		takeit = fcc != fcc_equal;
		break;
	case fbuge:
		takeit = fcc != fcc_less;
		break;
	case fbule:
		takeit = fcc != fcc_greater;
		break;
	case fbo:
		takeit = fcc != fcc_unordered;
		break;
	case fba:
		takeit = 1;
		break;
	}
	if (takeit) {		/* Branch taken. */
		uintptr_t	tpc;

		fp.fi = pinst;
		tpc = pregs->r_pc;
		if (annul && (icc == fba)) {	/* fba,a is wierd */
			if (fbpcc) {
				pregs->r_pc = tpc +
					(int)((fp.i << 13) >> 11);
			} else {
				pregs->r_pc = tpc +
					(int)((fp.i << 10) >> 8);
			}
			pregs->r_npc = pregs->r_pc + 4;
		} else {
			pregs->r_pc = pregs->r_npc;
			if (fbpcc) {
				pregs->r_npc = tpc +
					(int)((fp.i << 13) >> 11);
			} else {
				pregs->r_npc = tpc +
					(int)((fp.i << 10) >> 8);
			}
		}
	} else {		/* Branch not taken. */
		if (annul) {	/* Annul next instruction. */
			pregs->r_pc = pregs->r_npc + 4;
			pregs->r_npc += 8;
		} else {	/* Execute next instruction. */
			pregs->r_pc = pregs->r_npc;
			pregs->r_npc += 4;
		}
	}
	return (ftt_none);
}

/* PUBLIC FUNCTIONS */

enum ftt_type
_fp_iu_simulator(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*pfpu)	/* Pointer to FPU register block. */
{
	switch (pinst.hibits) {
	case 0:				/* fbcc and V9 fbpcc */
		return (fbcc_sim(pinst, pregs, pfpu));
	case 2:
		switch (pinst.op3) {
		case 0x28:
			if (pinst.rs1 == 0x13)
				return (vis_rdgsr(pfpsd, pinst, pregs,
					prw, pfpu));
			else
				return (ftt_unimplemented);
		case 0x30:
			if (pinst.rd == 0x13)
				return (vis_wrgsr(pfpsd, pinst, pregs,
					prw, pfpu));
			else
				return (ftt_unimplemented);
		case 0x2C:
			return (movcc(pfpsd, pinst, pregs, prw, pfpu));
		default:
			return (ftt_unimplemented);
	}
	case 3:
		return (fldst(pfpsd, pinst, pregs, prw));
	default:
		return (ftt_unimplemented);
	}
}
