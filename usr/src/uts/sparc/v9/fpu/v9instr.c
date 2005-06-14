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

#include <sys/privregs.h>
#include <sys/vis_simulator.h>
#include <sys/asi.h>
#include <sys/simulate.h>
#include <sys/model.h>

#define	FPU_REG_FIELD uint32_reg	/* Coordinate with FPU_REGS_TYPE. */
#define	FPU_DREG_FIELD uint64_reg	/* Coordinate with FPU_DREGS_TYPE. */
#define	FPU_FSR_FIELD uint64_reg	/* Coordinate with V9_FPU_FSR_TYPE. */

/*
 * Simulator for loads and stores between floating-point unit and memory.
 */
enum ftt_type
fldst(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw)	/* Pointer to locals and ins. */
{
	uint32_t sz_bits, asi = 0;
	uint64_t fea, tea;
	uint64_t *ea;
	enum ftt_type   ftt;
	char *badaddr = (caddr_t)(-1);
	union {
		fp_inst_type	inst;
		int32_t		i;
	} fp;

	fp.inst = pinst;
	if ((pinst.op3 >> 4) & 1) {
		if (pinst.ibit) {
			asi = (uint32_t)((pregs->r_tstate >> TSTATE_ASI_SHIFT) &
			    TSTATE_ASI_MASK);
		} else {
			asi = (fp.i >> 5) & 0xff;
		}
		/* check for ld/st alternate and highest defined V9 asi */
		if (((pinst.op3 & 0x30) == 0x30) && (asi > ASI_SNFL))
			return (vis_fldst(pfpsd, pinst, pregs, prw, asi));
	}

	if (pinst.ibit == 0) {	/* effective address = rs1 + rs2 */
		ftt = read_iureg(pfpsd, pinst.rs1, pregs, prw, &fea);
		if (ftt != ftt_none)
			return (ftt);
		ftt = read_iureg(pfpsd, pinst.rs2, pregs, prw, &tea);
		if (ftt != ftt_none)
			return (ftt);
		ea = (uint64_t *)(fea + tea);
	} else {		/* effective address = rs1 + imm13 */
				/* Extract simm13 field. */
		fea = (uint64_t)((fp.i << 19) >> 19);
		ftt = read_iureg(pfpsd, pinst.rs1, pregs, prw, &tea);
		if (ftt != ftt_none)
			return (ftt);
		ea = (uint64_t *)(fea + tea);
	}
	sz_bits = pinst.op3 & 0x3;
	switch (sz_bits) {		/* map size bits to a number */
	case 0:					/* ldf{a}/stf{a} */
		/* Must be word-aligned. */
		if (((uintptr_t)ea & 0x3) != 0)
			return (ftt_alignment);
		break;
	case 1: if (pinst.rd == 0) {		/* ldfsr/stfsr */
			/* Must be word-aligned. */
			if (((uintptr_t)ea & 0x3) != 0)
				return (ftt_alignment);
		} else {			/* ldxfsr/stxfsr */
			/* Must be extword-aligned. */
			if (((uintptr_t)ea & 0x7) != 0)
				return (ftt_alignment);
		}
		break;
	case 2:					/* ldqf{a}/stqf{a} */
		/* Require only word alignment. */
		if (((uintptr_t)ea & 0x3) != 0)
			return (ftt_alignment);
		break;
	case 3:					/* lddf{a}/stdf{a} */
		if (get_udatamodel() == DATAMODEL_ILP32) {
			/* Require 64 bit-alignment. */
			if (((uintptr_t)ea & 0x7) != 0)
				return (ftt_alignment);
		} else {
			if (((uintptr_t)ea & 0x3) != 0)
				return (ftt_alignment);
		}
	}

	pfpsd->fp_trapaddr = (caddr_t)ea; /* setup bad addr in case we trap */
	if ((pinst.op3 >> 2) & 1)	/* store */
		pfpsd->fp_traprw = S_READ;
	else
		pfpsd->fp_traprw = S_WRITE;

	switch (do_unaligned(pregs, &badaddr)) {
	case SIMU_FAULT:
		return (ftt_fault);
	case SIMU_ILLEGAL:
		return (ftt_unimplemented);
	case SIMU_SUCCESS:
		break;
	}
	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt_none);
}

/*
 * Floating-point conditional moves between floating point unit registers.
 */
static enum ftt_type
fmovcc_fcc(
	fp_simd_type	*pfpsd,	/* Pointer to fpu simulator data */
	fp_inst_type	inst,	/* FPU instruction to simulate. */
	fsr_type	*pfsr,	/* Pointer to image of FSR to read and write. */
	enum cc_type	cc)	/* FSR condition code field from fcc[0-3] */
{
	uint32_t	moveit;
	fsr_type	fsr;
	enum fcc_type	fcc;
	enum icc_type {
		fmovn, fmovne, fmovlg, fmovul, fmovl, fmovug, fmovg, fmovu,
		fmova, fmove, fmovue, fmovge, fmovuge, fmovle, fmovule, fmovo
	} cond;

	fsr = *pfsr;
	switch (cc) {
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
	default:
		return (ftt_unimplemented);
	}

	cond = (enum icc_type) (inst.rs1 & 0xf);
	switch (cond) {
	case fmovn:
		moveit = 0;
		break;
	case fmovl:
		moveit = fcc == fcc_less;
		break;
	case fmovg:
		moveit = fcc == fcc_greater;
		break;
	case fmovu:
		moveit = fcc == fcc_unordered;
		break;
	case fmove:
		moveit = fcc == fcc_equal;
		break;
	case fmovlg:
		moveit = (fcc == fcc_less) || (fcc == fcc_greater);
		break;
	case fmovul:
		moveit = (fcc == fcc_unordered) || (fcc == fcc_less);
		break;
	case fmovug:
		moveit = (fcc == fcc_unordered) || (fcc == fcc_greater);
		break;
	case fmovue:
		moveit = (fcc == fcc_unordered) || (fcc == fcc_equal);
		break;
	case fmovge:
		moveit = (fcc == fcc_greater) || (fcc == fcc_equal);
		break;
	case fmovle:
		moveit = (fcc == fcc_less) || (fcc == fcc_equal);
		break;
	case fmovne:
		moveit = fcc != fcc_equal;
		break;
	case fmovuge:
		moveit = fcc != fcc_less;
		break;
	case fmovule:
		moveit = fcc != fcc_greater;
		break;
	case fmovo:
		moveit = fcc != fcc_unordered;
		break;
	case fmova:
		moveit = 1;
		break;
	default:
		return (ftt_unimplemented);
	}
	if (moveit) {		/* Move fpu register. */
		uint32_t nrs2, nrd;
		uint32_t usr;
		uint64_t lusr;

		nrs2 = inst.rs2;
		nrd = inst.rd;
		if (inst.prec < 2) {	/* fmovs */
			_fp_unpack_word(pfpsd, &usr, nrs2);
			_fp_pack_word(pfpsd, &usr, nrd);
		} else {		/* fmovd */
			/* fix register encoding */
			if ((nrs2 & 1) == 1)
				nrs2 = (nrs2 & 0x1e) | 0x20;
			_fp_unpack_extword(pfpsd, &lusr, nrs2);
			if ((nrd & 1) == 1)
				nrd = (nrd & 0x1e) | 0x20;
			_fp_pack_extword(pfpsd, &lusr, nrd);
			if (inst.prec > 2) {		/* fmovq */
				_fp_unpack_extword(pfpsd, &lusr, nrs2+2);
				_fp_pack_extword(pfpsd, &lusr, nrd+2);
			}
		}
	}
	return (ftt_none);
}

/*
 * Integer conditional moves between floating point unit registers.
 */
static enum ftt_type
fmovcc_icc(
	fp_simd_type	*pfpsd,	/* Pointer to fpu simulator data */
	fp_inst_type	inst,	/* FPU instruction to simulate. */
	enum cc_type	cc)	/* CCR condition code field from tstate */
{
	int 	moveit;
	enum icc_type {
		fmovn, fmove, fmovle, fmovl, fmovleu, fmovcs, fmovneg, fmovvs,
		fmova, fmovne, fmovg, fmovge, fmovgu, fmovcc, fmovpos, fmovvc
	} cond;

	struct regs *pregs;
	uint64_t tstate;
	union {
		uint32_t	i;
		ccr_type	cc;
	} ccr;

	pregs = lwptoregs(curthread->t_lwp);
	tstate = pregs->r_tstate;
	switch (cc) {
	case icc:
		ccr.i = (uint32_t)((tstate >> TSTATE_CCR_SHIFT) & 0xf);
		break;
	case xcc:
		ccr.i = (uint32_t)(((tstate >> TSTATE_CCR_SHIFT) & 0xf0) >> 4);
		break;
	}

	cond = (enum icc_type) (inst.rs1 & 0xf);
	switch (cond) {
	case fmovn:
		moveit = 0;
		break;
	case fmove:
		moveit = (int)(ccr.cc.z);
		break;
	case fmovle:
		moveit = (int)(ccr.cc.z | (ccr.cc.n ^ ccr.cc.v));
		break;
	case fmovl:
		moveit = (int)(ccr.cc.n ^ ccr.cc.v);
		break;
	case fmovleu:
		moveit = (int)(ccr.cc.c | ccr.cc.z);
		break;
	case fmovcs:
		moveit = (int)(ccr.cc.c);
		break;
	case fmovneg:
		moveit = (int)(ccr.cc.n);
		break;
	case fmovvs:
		moveit = (int)(ccr.cc.v);
		break;
	case fmova:
		moveit = 1;
		break;
	case fmovne:
		moveit = (int)(ccr.cc.z == 0);
		break;
	case fmovg:
		moveit = (int)((ccr.cc.z | (ccr.cc.n ^ ccr.cc.v)) == 0);
		break;
	case fmovge:
		moveit = (int)((ccr.cc.n ^ ccr.cc.v) == 0);
		break;
	case fmovgu:
		moveit = (int)((ccr.cc.c | ccr.cc.z) == 0);
		break;
	case fmovcc:
		moveit = (int)(ccr.cc.c == 0);
		break;
	case fmovpos:
		moveit = (int)(ccr.cc.n == 0);
		break;
	case fmovvc:
		moveit = (int)(ccr.cc.v == 0);
		break;
	default:
		return (ftt_unimplemented);
	}
	if (moveit) {		/* Move fpu register. */
		uint32_t nrs2, nrd;
		uint32_t usr;
		uint64_t lusr;

		nrs2 = inst.rs2;
		nrd = inst.rd;
		if (inst.prec < 2) {	/* fmovs */
			_fp_unpack_word(pfpsd, &usr, nrs2);
			_fp_pack_word(pfpsd, &usr, nrd);
		} else {		/* fmovd */
			/* fix register encoding */
			if ((nrs2 & 1) == 1)
				nrs2 = (nrs2 & 0x1e) | 0x20;
			_fp_unpack_extword(pfpsd, &lusr, nrs2);
			if ((nrd & 1) == 1)
				nrd = (nrd & 0x1e) | 0x20;
			_fp_pack_extword(pfpsd, &lusr, nrd);
			if (inst.prec > 2) {		/* fmovq */
				_fp_unpack_extword(pfpsd, &lusr, nrs2+2);
				_fp_pack_extword(pfpsd, &lusr, nrd+2);
			}
		}
	}
	return (ftt_none);
}

/*
 * Simulator for moving fp register on condition (FMOVcc).
 * FMOVccq (Quad version of instruction) not supported by Ultra-1, so this
 * code must always be present.
 */
enum ftt_type
fmovcc(
	fp_simd_type	*pfpsd,	/* Pointer to fpu simulator data */
	fp_inst_type	inst,	/* FPU instruction to simulate. */
	fsr_type	*pfsr)	/* Pointer to image of FSR to read and write. */
{
	enum cc_type	opf_cc;

	opf_cc = (enum cc_type) ((inst.ibit << 2) | (inst.opcode >> 4));
	if ((opf_cc == icc) || (opf_cc == xcc)) {
		return (fmovcc_icc(pfpsd, inst, opf_cc));
	} else {
		return (fmovcc_fcc(pfpsd, inst, pfsr, opf_cc));
	}
}

/*
 * Simulator for moving fp register on integer register condition (FMOVr).
 * FMOVrq (Quad version of instruction) not supported by Ultra-1, so this
 * code must always be present.
 */
enum ftt_type
fmovr(
	fp_simd_type	*pfpsd,	/* Pointer to fpu simulator data */
	fp_inst_type	inst)	/* FPU instruction to simulate. */
{
	struct regs	*pregs;
	ulong_t		*prw;
	uint32_t	nrs1;
	enum ftt_type	ftt;
	enum rcond_type {
		none, fmovre, fmovrlez, fmovrlz,
		nnone, fmovrne, fmovrgz, fmovrgez
	} rcond;
	int64_t moveit, r;

	nrs1 = inst.rs1;
	if (nrs1 > 15)		/* rs1 must be a global register */
		return (ftt_unimplemented);
	if (inst.ibit)		/* ibit must be unused */
		return (ftt_unimplemented);
	pregs = lwptoregs(curthread->t_lwp);
	prw = (ulong_t *)pregs->r_sp;
	ftt = read_iureg(pfpsd, nrs1, pregs, prw, (uint64_t *)&r);
	if (ftt != ftt_none)
		return (ftt);
	rcond = (enum rcond_type) (inst.opcode >> 3) & 7;
	switch (rcond) {
	case fmovre:
		moveit = r == 0;
		break;
	case fmovrlez:
		moveit = r <= 0;
		break;
	case fmovrlz:
		moveit = r < 0;
		break;
	case fmovrne:
		moveit = r != 0;
		break;
	case fmovrgz:
		moveit = r > 0;
		break;
	case fmovrgez:
		moveit = r >= 0;
		break;
	default:
		return (ftt_unimplemented);
	}
	if (moveit) {		/* Move fpu register. */
		uint32_t nrs2, nrd;
		uint32_t usr;
		uint64_t lusr;

		nrs2 = inst.rs2;
		nrd = inst.rd;
		if (inst.prec < 2) {	/* fmovs */
			_fp_unpack_word(pfpsd, &usr, nrs2);
			_fp_pack_word(pfpsd, &usr, nrd);
		} else {		/* fmovd */
			_fp_unpack_extword(pfpsd, &lusr, nrs2);
			_fp_pack_extword(pfpsd, &lusr, nrd);
			if (inst.prec > 2) {		/* fmovq */
				_fp_unpack_extword(pfpsd, &lusr, nrs2+2);
				_fp_pack_extword(pfpsd, &lusr, nrd+2);
			}
		}
	}
	return (ftt_none);
}

/*
 * Move integer register on condition (MOVcc).
 */
enum ftt_type
movcc(
	fp_simd_type	*pfpsd, /* Pointer to fpu simulator data */
	fp_inst_type    pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*pfpu)	/* Pointer to FPU register block. */

{
	fsr_type	fsr;
	enum cc_type	cc;
	enum fcc_type	fcc;
	enum icc_type {
		fmovn, fmovne, fmovlg, fmovul, fmovl, fmovug, fmovg, fmovu,
		fmova, fmove, fmovue, fmovge, fmovuge, fmovle, fmovule, fmovo
	} cond;
	uint32_t moveit;
	enum ftt_type ftt = ftt_none;

	cc = (enum cc_type) (pinst.opcode >> 0x4) & 3;
	fsr.ll = pfpu->fpu_fsr;
	cond = (enum icc_type) (pinst.rs1 & 0xf);
	switch (cc) {
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
	default:
		return (ftt_unimplemented);
	}

	switch (cond) {
	case fmovn:
		moveit = 0;
		break;
	case fmovl:
		moveit = fcc == fcc_less;
		break;
	case fmovg:
		moveit = fcc == fcc_greater;
		break;
	case fmovu:
		moveit = fcc == fcc_unordered;
		break;
	case fmove:
		moveit = fcc == fcc_equal;
		break;
	case fmovlg:
		moveit = (fcc == fcc_less) || (fcc == fcc_greater);
		break;
	case fmovul:
		moveit = (fcc == fcc_unordered) || (fcc == fcc_less);
		break;
	case fmovug:
		moveit = (fcc == fcc_unordered) || (fcc == fcc_greater);
		break;
	case fmovue:
		moveit = (fcc == fcc_unordered) || (fcc == fcc_equal);
		break;
	case fmovge:
		moveit = (fcc == fcc_greater) || (fcc == fcc_equal);
		break;
	case fmovle:
		moveit = (fcc == fcc_less) || (fcc == fcc_equal);
		break;
	case fmovne:
		moveit = fcc != fcc_equal;
		break;
	case fmovuge:
		moveit = fcc != fcc_less;
		break;
	case fmovule:
		moveit = fcc != fcc_greater;
		break;
	case fmovo:
		moveit = fcc != fcc_unordered;
		break;
	case fmova:
		moveit = 1;
		break;
	default:
		return (ftt_unimplemented);
	}
	if (moveit) {		/* Move fpu register. */
		uint32_t nrd;
		uint64_t r;

		nrd = pinst.rd;
		if (pinst.ibit == 0) {	/* copy the value in r[rs2] */
			uint32_t nrs2;

			nrs2 = pinst.rs2;
			ftt = read_iureg(pfpsd, nrs2, pregs, prw, &r);
			if (ftt != ftt_none)
				return (ftt);
			ftt = write_iureg(pfpsd, nrd, pregs, prw, &r);
		} else {		/* use sign_ext(simm11) */
			union {
				fp_inst_type	inst;
				int32_t		i;
			} fp;

			fp.inst = pinst;	/* Extract simm11 field */
			r = (fp.i << 21) >> 21;
			ftt = write_iureg(pfpsd, nrd, pregs, prw, &r);
		}
	}
	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt);
}
