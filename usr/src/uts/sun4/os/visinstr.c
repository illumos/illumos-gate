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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* VIS floating point instruction simulator for Sparc FPU simulator. */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/fpu/fpu_simulator.h>
#include <sys/vis_simulator.h>
#include <sys/fpu/globals.h>
#include <sys/privregs.h>
#include <sys/sun4asi.h>
#include <sys/machasi.h>
#include <sys/debug.h>
#include <sys/cpu_module.h>
#include <sys/systm.h>

#define	FPU_REG_FIELD uint32_reg	/* Coordinate with FPU_REGS_TYPE. */
#define	FPU_DREG_FIELD uint64_reg	/* Coordinate with FPU_DREGS_TYPE. */
#define	FPU_FSR_FIELD uint64_reg	/* Coordinate with V9_FPU_FSR_TYPE. */

extern	uint_t	get_subcc_ccr(uint64_t, uint64_t);

static enum ftt_type vis_array(fp_simd_type *, vis_inst_type, struct regs *,
				void *);
static enum ftt_type vis_alignaddr(fp_simd_type *, vis_inst_type,
				struct regs *, void *, kfpu_t *);
static enum ftt_type vis_edge(fp_simd_type *, vis_inst_type, struct regs *,
				void *);
static enum ftt_type vis_faligndata(fp_simd_type *, fp_inst_type,
				kfpu_t *);
static enum ftt_type vis_bmask(fp_simd_type *, vis_inst_type, struct regs *,
				void *, kfpu_t *);
static enum ftt_type vis_bshuffle(fp_simd_type *, fp_inst_type,
				kfpu_t *);
static enum ftt_type vis_siam(fp_simd_type *, vis_inst_type, kfpu_t *);
static enum ftt_type vis_fcmp(fp_simd_type *, vis_inst_type, struct regs *,
				void *);
static enum ftt_type vis_fmul(fp_simd_type *, vis_inst_type);
static enum ftt_type vis_fpixel(fp_simd_type *, vis_inst_type, kfpu_t *);
static enum ftt_type vis_fpaddsub(fp_simd_type *, vis_inst_type);
static enum ftt_type vis_pdist(fp_simd_type *, fp_inst_type);
static enum ftt_type vis_prtl_fst(fp_simd_type *, vis_inst_type, struct regs *,
				void *, uint_t);
static enum ftt_type vis_short_fls(fp_simd_type *, vis_inst_type,
				struct regs *, void *, uint_t);
static enum ftt_type vis_blk_fldst(fp_simd_type *, vis_inst_type,
				struct regs *, void *, uint_t);

/*
 * Simulator for VIS instructions with op3 == 0x36 that get fp_disabled
 * traps.
 */
enum ftt_type
vis_fpu_simulator(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	uint_t	us1, us2, usr;
	uint64_t lus1, lus2, lusr;
	enum ftt_type ftt = ftt_none;
	union {
		vis_inst_type	inst;
		fp_inst_type	pinst;
	} f;

	ASSERT(USERMODE(pregs->r_tstate));
	nrs1 = pinst.rs1;
	nrs2 = pinst.rs2;
	nrd = pinst.rd;
	f.pinst = pinst;
	if ((f.inst.opf & 1) == 0) {		/* double precision */
		if ((nrs1 & 1) == 1) 		/* fix register encoding */
			nrs1 = (nrs1 & 0x1e) | 0x20;
		if ((nrs2 & 1) == 1)
			nrs2 = (nrs2 & 0x1e) | 0x20;
		if ((nrd & 1) == 1)
			nrd = (nrd & 0x1e) | 0x20;
	}

	switch (f.inst.opf) {
		/* these instr's do not use fp regs */
	case edge8:
	case edge8l:
	case edge8n:
	case edge8ln:
	case edge16:
	case edge16l:
	case edge16n:
	case edge16ln:
	case edge32:
	case edge32l:
	case edge32n:
	case edge32ln:
		ftt = vis_edge(pfpsd, f.inst, pregs, prw);
		break;
	case array8:
	case array16:
	case array32:
		ftt = vis_array(pfpsd, f.inst, pregs, prw);
		break;
	case alignaddr:
	case alignaddrl:
		ftt = vis_alignaddr(pfpsd, f.inst, pregs, prw, fp);
		break;
	case bmask:
		ftt = vis_bmask(pfpsd, f.inst, pregs, prw, fp);
		break;
	case fcmple16:
	case fcmpne16:
	case fcmpgt16:
	case fcmpeq16:
	case fcmple32:
	case fcmpne32:
	case fcmpgt32:
	case fcmpeq32:
		ftt = vis_fcmp(pfpsd, f.inst, pregs, prw);
		break;
	case fmul8x16:
	case fmul8x16au:
	case fmul8x16al:
	case fmul8sux16:
	case fmul8ulx16:
	case fmuld8sux16:
	case fmuld8ulx16:
		ftt = vis_fmul(pfpsd, f.inst);
		break;
	case fpack16:
	case fpack32:
	case fpackfix:
	case fexpand:
	case fpmerge:
		ftt = vis_fpixel(pfpsd, f.inst, fp);
		break;
	case pdist:
		ftt = vis_pdist(pfpsd, pinst);
		break;
	case faligndata:
		ftt = vis_faligndata(pfpsd, pinst, fp);
		break;
	case bshuffle:
		ftt = vis_bshuffle(pfpsd, pinst, fp);
		break;
	case fpadd16:
	case fpadd16s:
	case fpadd32:
	case fpadd32s:
	case fpsub16:
	case fpsub16s:
	case fpsub32:
	case fpsub32s:
		ftt = vis_fpaddsub(pfpsd, f.inst);
		break;
	case fzero:
		lusr = 0;
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fzeros:
		usr = 0;
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fnor:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = ~(lus1 | lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fnors:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = ~(us1 | us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fandnot2:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = (lus1 & ~lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fandnot2s:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = (us1 & ~us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fnot2:
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = ~lus2;
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fnot2s:
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = ~us2;
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fandnot1:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = (~lus1 & lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fandnot1s:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = (~us1 & us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fnot1:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		lusr = ~lus1;
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fnot1s:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		usr = ~us1;
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fxor:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = (lus1 ^ lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fxors:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = (us1 ^ us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fnand:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = ~(lus1 & lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fnands:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = ~(us1 & us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fand:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = (lus1 & lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fands:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = (us1 & us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fxnor:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = ~(lus1 ^ lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fxnors:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = ~(us1 ^ us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fsrc1:
		_fp_unpack_extword(pfpsd, &lusr, nrs1);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fsrc1s:
		_fp_unpack_word(pfpsd, &usr, nrs1);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fornot2:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = (lus1 | ~lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fornot2s:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = (us1 | ~us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fsrc2:
		_fp_unpack_extword(pfpsd, &lusr, nrs2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fsrc2s:
		_fp_unpack_word(pfpsd, &usr, nrs2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fornot1:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = (~lus1 | lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fornot1s:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = (~us1 | us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case for_op:
		_fp_unpack_extword(pfpsd, &lus1, nrs1);
		_fp_unpack_extword(pfpsd, &lus2, nrs2);
		lusr = (lus1 | lus2);
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fors_op:
		_fp_unpack_word(pfpsd, &us1, nrs1);
		_fp_unpack_word(pfpsd, &us2, nrs2);
		usr = (us1 | us2);
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case fone:
		lusr = 0xffffffffffffffff;
		_fp_pack_extword(pfpsd, &lusr, nrd);
		break;
	case fones:
		usr = 0xffffffffUL;
		_fp_pack_word(pfpsd, &usr, nrd);
		break;
	case siam:
		ftt = vis_siam(pfpsd, f.inst, fp);
		break;
	default:
		return (ftt_unimplemented);
	}

	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt);
}

/*
 * Simulator for edge instructions
 */
static enum ftt_type
vis_edge(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw)	/* Pointer to locals and ins. */

{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	enum ftt_type ftt;
	uint64_t addrl, addrr, mask;
	uint64_t ah61l, ah61r;		/* Higher 61 bits of address */
	int al3l, al3r;			/* Lower 3 bits of address */
	uint_t	ccr;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;

	ftt = read_iureg(pfpsd, nrs1, pregs, prw, &addrl);
	if (ftt != ftt_none)
		return (ftt);
	ftt = read_iureg(pfpsd, nrs2, pregs, prw, &addrr);
	if (ftt != ftt_none)
		return (ftt);

	/* Test PSTATE.AM to determine 32-bit vs 64-bit addressing */
	if ((pregs->r_tstate & TSTATE_AM) != 0) {
		ah61l = addrl & 0xfffffff8;
		ah61r = addrr & 0xfffffff8;
	} else {
		ah61l = addrl & ~0x7;
		ah61r = addrr & ~0x7;
	}


	switch (inst.opf) {
	case edge8:
	case edge8n:
	case edge8l:
	case edge8ln:
		al3l = addrl & 0x7;
		switch (inst.opf) {
		case edge8:
		case edge8n:
			if (inst.opf == edge8) {
				VISINFO_KSTAT(vis_edge8);
			} else {
				VISINFO_KSTAT(vis_edge8n);
			}
			mask = 0xff >> al3l;
			if (ah61l == ah61r) {
				al3r = addrr & 0x7;
				mask &= (0xff << (0x7 - al3r)) & 0xff;
			}
			break;
		case edge8l:
		case edge8ln:
			if (inst.opf == edge8l) {
				VISINFO_KSTAT(vis_edge8l);
			} else {
				VISINFO_KSTAT(vis_edge8ln);
			}
			mask = (0xff << al3l) & 0xff;
			if (ah61l == ah61r) {
				al3r = addrr & 0x7;
				mask &= 0xff >> (0x7 - al3r);
			}
			break;
		}
		break;
	case edge16:
	case edge16l:
	case edge16n:
	case edge16ln:
		al3l = addrl & 0x6;
		al3l >>= 0x1;
		switch (inst.opf) {
		case edge16:
		case edge16n:
			if (inst.opf == edge16) {
				VISINFO_KSTAT(vis_edge16);

			} else {
				VISINFO_KSTAT(vis_edge16n);
			}
			mask = 0xf >> al3l;
			if (ah61l == ah61r) {
				al3r = addrr & 0x6;
				al3r >>= 0x1;
				mask &= (0xf << (0x3 - al3r)) & 0xf;
			}
			break;
		case edge16l:
		case edge16ln:
			if (inst.opf == edge16l) {
				VISINFO_KSTAT(vis_edge16l);

			} else {
				VISINFO_KSTAT(vis_edge16ln);
			}

			mask = (0xf << al3l) & 0xf;
			if (ah61l == ah61r) {
				al3r = addrr & 0x6;
				al3r >>= 0x1;
				mask &= 0xf >> (0x3 - al3r);
			}
			break;
		}
		break;
	case edge32:
	case edge32l:
	case edge32n:
	case edge32ln:
		al3l = addrl & 0x4;
		al3l >>= 0x2;

		switch (inst.opf) {
		case edge32:
		case edge32n:
			if (inst.opf == edge32) {
				VISINFO_KSTAT(vis_edge32);

			} else {
				VISINFO_KSTAT(vis_edge32n);
			}
			mask = 0x3 >> al3l;
			if (ah61l == ah61r) {
				al3r = addrr & 0x4;
				al3r >>= 0x2;
				mask &= (0x3 << (0x1 - al3r)) & 0x3;
			}
			break;
		case edge32l:
		case edge32ln:
			if (inst.opf == edge32l) {
				VISINFO_KSTAT(vis_edge32l);

			} else {
				VISINFO_KSTAT(vis_edge32ln);
			}
			mask = (0x3 << al3l) & 0x3;
			if (ah61l == ah61r) {
				al3r = addrr & 0x4;
				al3r >>= 0x2;
				mask &= 0x3 >> (0x1 - al3r);
			}
			break;
		}
		break;
	}

	ftt = write_iureg(pfpsd, nrd, pregs, prw, &mask);

	switch (inst.opf) {
	case edge8:
	case edge8l:
	case edge16:
	case edge16l:
	case edge32:
	case edge32l:

		/* Update flags per SUBcc outcome */
		pregs->r_tstate &= ~((uint64_t)TSTATE_CCR_MASK
					<< TSTATE_CCR_SHIFT);
		ccr = get_subcc_ccr(addrl, addrr);  /* get subcc cond. codes */
		pregs->r_tstate |= ((uint64_t)ccr << TSTATE_CCR_SHIFT);

		break;
	}
	return (ftt);
}

/*
 * Simulator for three dimentional array addressing instructions.
 */
static enum ftt_type
vis_array(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw)	/* Pointer to locals and ins. */

{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	enum ftt_type ftt;
	uint64_t laddr, bsize, baddr;
	uint64_t nbit;
	int oy, oz;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;

	ftt = read_iureg(pfpsd, nrs1, pregs, prw, &laddr);
	if (ftt != ftt_none)
		return (ftt);
	ftt = read_iureg(pfpsd, nrs2, pregs, prw, &bsize);
	if (ftt != ftt_none)
		return (ftt);

	if (bsize > 5) {
		bsize = 5;
	}
	nbit = (1 << bsize) - 1;	/* Number of bits for XY<6+n-1:6> */
	oy = 17 + bsize;		/* Offset of Y<6+n-1:6> */
	oz = 17 + 2 * bsize;		/* Offset of Z<8:5> */

	baddr = 0;
	baddr |= (laddr >> (11 -  0)) & (0x03 <<  0);	/* X_integer<1:0> */
	baddr |= (laddr >> (33 -  2)) & (0x03 <<  2);	/* Y_integer<1:0> */
	baddr |= (laddr >> (55 -  4)) & (0x01 <<  4);	/* Z_integer<0>   */
	baddr |= (laddr >> (13 -  5)) & (0x0f <<  5);	/* X_integer<5:2> */
	baddr |= (laddr >> (35 -  9)) & (0x0f <<  9);	/* Y_integer<5:2> */
	baddr |= (laddr >> (56 - 13)) & (0x0f << 13);	/* Z_integer<4:1> */
	baddr |= (laddr >> (17 - 17)) & (nbit << 17);	/* X_integer<6+n-1:6> */
	baddr |= (laddr >> (39 - oy)) & (nbit << oy);	/* Y_integer<6+n-1:6> */
	baddr |= (laddr >> (60 - oz)) & (0x0f << oz);	/* Z_integer<8:5> */

	switch (inst.opf) {
	case array8:
		VISINFO_KSTAT(vis_array8);
		break;
	case array16:
		VISINFO_KSTAT(vis_array16);
		baddr <<= 1;
		break;
	case array32:
		VISINFO_KSTAT(vis_array32);
		baddr <<= 2;
		break;
	}

	ftt = write_iureg(pfpsd, nrd, pregs, prw, &baddr);

	return (ftt);
}

/*
 * Simulator for alignaddr and alignaddrl instructions.
 */
static enum ftt_type
vis_alignaddr(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	enum ftt_type ftt;
	uint64_t ea, tea, g, r;
	short s;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;

	ftt = read_iureg(pfpsd, nrs1, pregs, prw, &ea);
	if (ftt != ftt_none)
		return (ftt);
	ftt = read_iureg(pfpsd, nrs2, pregs, prw, &tea);
	if (ftt != ftt_none)
		return (ftt);
	ea += tea;
	r = ea & ~0x7;	/* zero least 3 significant bits */
	ftt = write_iureg(pfpsd, nrd, pregs, prw, &r);


	g = pfpsd->fp_current_read_gsr(fp);
	g &= ~(GSR_ALIGN_MASK);		/* zero the align offset */
	r = ea & 0x7;
	if (inst.opf == alignaddrl) {
		s = (short)(~r);	/* 2's complement for alignaddrl */
		if (s < 0)
			r = (uint64_t)((s + 1) & 0x7);
		else
			r = (uint64_t)(s & 0x7);
	}
	g |= (r << GSR_ALIGN_SHIFT) & GSR_ALIGN_MASK;
	pfpsd->fp_current_write_gsr(g, fp);

	return (ftt);
}

/*
 * Simulator for bmask instruction.
 */
static enum ftt_type
vis_bmask(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	enum ftt_type ftt;
	uint64_t ea, tea, g;

	VISINFO_KSTAT(vis_bmask);
	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;

	ftt = read_iureg(pfpsd, nrs1, pregs, prw, &ea);
	if (ftt != ftt_none)
		return (ftt);
	ftt = read_iureg(pfpsd, nrs2, pregs, prw, &tea);
	if (ftt != ftt_none)
		return (ftt);
	ea += tea;
	ftt = write_iureg(pfpsd, nrd, pregs, prw, &ea);

	g = pfpsd->fp_current_read_gsr(fp);
	g &= ~(GSR_MASK_MASK);		/* zero the mask offset */

	/* Put the least significant 32 bits of ea in GSR.mask */
	g |= (ea << GSR_MASK_SHIFT) & GSR_MASK_MASK;
	pfpsd->fp_current_write_gsr(g, fp);
	return (ftt);
}

/*
 * Simulator for fp[add|sub]* instruction.
 */
static enum ftt_type
vis_fpaddsub(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst)	/* FPU instruction to simulate. */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	union {
		uint64_t	ll;
		uint32_t	i[2];
		uint16_t	s[4];
	} lrs1, lrs2, lrd;
	union {
		uint32_t	i;
		uint16_t	s[2];
	} krs1, krs2, krd;
	int i;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	if ((inst.opf & 1) == 0) {	/* double precision */
		if ((nrs1 & 1) == 1) 	/* fix register encoding */
			nrs1 = (nrs1 & 0x1e) | 0x20;
		if ((nrs2 & 1) == 1)
			nrs2 = (nrs2 & 0x1e) | 0x20;
		if ((nrd & 1) == 1)
			nrd = (nrd & 0x1e) | 0x20;
	}
	switch (inst.opf) {
	case fpadd16:
		_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		for (i = 0; i <= 3; i++) {
			lrd.s[i] = lrs1.s[i] + lrs2.s[i];
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fpadd16s:
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0; i <= 1; i++) {
			krd.s[i] = krs1.s[i] + krs2.s[i];
		}
		_fp_pack_word(pfpsd, &krd.i, nrd);
		break;
	case fpadd32:
		_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		for (i = 0; i <= 1; i++) {
			lrd.i[i] = lrs1.i[i] + lrs2.i[i];
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fpadd32s:
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		krd.i = krs1.i + krs2.i;
		_fp_pack_word(pfpsd, &krd.i, nrd);
		break;
	case fpsub16:
		_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		for (i = 0; i <= 3; i++) {
			lrd.s[i] = lrs1.s[i] - lrs2.s[i];
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fpsub16s:
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0; i <= 1; i++) {
			krd.s[i] = krs1.s[i] - krs2.s[i];
		}
		_fp_pack_word(pfpsd, &krd.i, nrd);
		break;
	case fpsub32:
		_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		for (i = 0; i <= 1; i++) {
			lrd.i[i] = lrs1.i[i] - lrs2.i[i];
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fpsub32s:
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		krd.i = krs1.i - krs2.i;
		_fp_pack_word(pfpsd, &krd.i, nrd);
		break;
	}
	return (ftt_none);
}

/*
 * Simulator for fcmp* instruction.
 */
static enum ftt_type
vis_fcmp(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw)	/* Pointer to locals and ins. */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	union {
		uint64_t	ll;
		uint32_t	i[2];
		uint16_t	s[4];
	} krs1, krs2, krd;
	enum ftt_type ftt;
	short sr1, sr2;
	int i, ir1, ir2;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	krd.ll = 0;
	if ((nrs1 & 1) == 1) 	/* fix register encoding */
		nrs1 = (nrs1 & 0x1e) | 0x20;
	if ((nrs2 & 1) == 1)
		nrs2 = (nrs2 & 0x1e) | 0x20;

	_fp_unpack_extword(pfpsd, &krs1.ll, nrs1);
	_fp_unpack_extword(pfpsd, &krs2.ll, nrs2);
	switch (inst.opf) {
	case fcmple16:
		VISINFO_KSTAT(vis_fcmple16);
		for (i = 0; i <= 3; i++) {
			sr1 = (short)krs1.s[i];
			sr2 = (short)krs2.s[i];
			if (sr1 <= sr2)
				krd.ll += (0x8 >> i);
		}
		break;
	case fcmpne16:
		VISINFO_KSTAT(vis_fcmpne16);
		for (i = 0; i <= 3; i++) {
			sr1 = (short)krs1.s[i];
			sr2 = (short)krs2.s[i];
			if (sr1 != sr2)
				krd.ll += (0x8 >> i);
		}
		break;
	case fcmpgt16:
		VISINFO_KSTAT(vis_fcmpgt16);
		for (i = 0; i <= 3; i++) {
			sr1 = (short)krs1.s[i];
			sr2 = (short)krs2.s[i];
			if (sr1 > sr2)
				krd.ll += (0x8 >> i);
		}
		break;
	case fcmpeq16:
		VISINFO_KSTAT(vis_fcmpeq16);
		for (i = 0; i <= 3; i++) {
			sr1 = (short)krs1.s[i];
			sr2 = (short)krs2.s[i];
			if (sr1 == sr2)
				krd.ll += (0x8 >> i);
		}
		break;
	case fcmple32:
		VISINFO_KSTAT(vis_fcmple32);
		for (i = 0; i <= 1; i++) {
			ir1 = (int)krs1.i[i];
			ir2 = (int)krs2.i[i];
			if (ir1 <= ir2)
				krd.ll += (0x2 >> i);
		}
		break;
	case fcmpne32:
		VISINFO_KSTAT(vis_fcmpne32);
		for (i = 0; i <= 1; i++) {
			ir1 = (int)krs1.i[i];
			ir2 = (int)krs2.i[i];
			if (ir1 != ir2)
				krd.ll += (0x2 >> i);
		}
		break;
	case fcmpgt32:
		VISINFO_KSTAT(vis_fcmpgt32);
		for (i = 0; i <= 1; i++) {
			ir1 = (int)krs1.i[i];
			ir2 = (int)krs2.i[i];
			if (ir1 > ir2)
				krd.ll += (0x2 >> i);
		}
		break;
	case fcmpeq32:
		VISINFO_KSTAT(vis_fcmpeq32);
		for (i = 0; i <= 1; i++) {
			ir1 = (int)krs1.i[i];
			ir2 = (int)krs2.i[i];
			if (ir1 == ir2)
				krd.ll += (0x2 >> i);
		}
		break;
	}
	ftt = write_iureg(pfpsd, nrd, pregs, prw, &krd.ll);
	return (ftt);
}

/*
 * Simulator for fmul* instruction.
 */
static enum ftt_type
vis_fmul(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst)	/* FPU instruction to simulate. */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	union {
		uint64_t	ll;
		uint32_t	i[2];
		uint16_t	s[4];
		uint8_t		c[8];
	} lrs1, lrs2, lrd;
	union {
		uint32_t	i;
		uint16_t	s[2];
		uint8_t		c[4];
	} krs1, krs2, kres;
	short s1, s2, sres;
	ushort_t us1;
	char c1;
	int i;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	if ((inst.opf & 1) == 0) {	/* double precision */
		if ((nrd & 1) == 1) 	/* fix register encoding */
			nrd = (nrd & 0x1e) | 0x20;
	}

	switch (inst.opf) {
	case fmul8x16:
		VISINFO_KSTAT(vis_fmul8x16);
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		if ((nrs2 & 1) == 1)
			nrs2 = (nrs2 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		for (i = 0; i <= 3; i++) {
			us1 = (ushort_t)krs1.c[i];
			s2 = (short)lrs2.s[i];
			kres.i = us1 * s2;
			sres = (short)((kres.c[1] << 8) | kres.c[2]);
			if (kres.c[3] >= 0x80)
				sres++;
			lrd.s[i] = sres;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fmul8x16au:
		VISINFO_KSTAT(vis_fmul8x16au);
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0; i <= 3; i++) {
			us1 = (ushort_t)krs1.c[i];
			s2 = (short)krs2.s[0];
			kres.i = us1 * s2;
			sres = (short)((kres.c[1] << 8) | kres.c[2]);
			if (kres.c[3] >= 0x80)
				sres++;
			lrd.s[i] = sres;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fmul8x16al:
		VISINFO_KSTAT(vis_fmul8x16al);
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0; i <= 3; i++) {
			us1 = (ushort_t)krs1.c[i];
			s2 = (short)krs2.s[1];
			kres.i = us1 * s2;
			sres = (short)((kres.c[1] << 8) | kres.c[2]);
			if (kres.c[3] >= 0x80)
				sres++;
			lrd.s[i] = sres;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fmul8sux16:
		VISINFO_KSTAT(vis_fmul8sux16);
		if ((nrs1 & 1) == 1) 	/* fix register encoding */
			nrs1 = (nrs1 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
		if ((nrs2 & 1) == 1)
			nrs2 = (nrs2 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		for (i = 0; i <= 3; i++) {
			c1 = lrs1.c[(i*2)];
			s1 = (short)c1;		/* keeps the sign alive */
			s2 = (short)lrs2.s[i];
			kres.i = s1 * s2;
			sres = (short)((kres.c[1] << 8) | kres.c[2]);
			if (kres.c[3] >= 0x80)
				sres++;
			if (sres < 0)
				lrd.s[i] = (sres & 0xFFFF);
			else
				lrd.s[i] = sres;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fmul8ulx16:
		VISINFO_KSTAT(vis_fmul8ulx16);
		if ((nrs1 & 1) == 1) 	/* fix register encoding */
			nrs1 = (nrs1 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
		if ((nrs2 & 1) == 1)
			nrs2 = (nrs2 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		for (i = 0; i <= 3; i++) {
			us1 = (ushort_t)lrs1.c[(i*2)+1];
			s2 = (short)lrs2.s[i];
			kres.i = us1 * s2;
			sres = (short)kres.s[0];
			if (kres.s[1] >= 0x8000)
				sres++;
			lrd.s[i] = sres;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fmuld8sux16:
		VISINFO_KSTAT(vis_fmuld8sux16);
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0; i <= 1; i++) {
			c1 = krs1.c[(i*2)];
			s1 = (short)c1;		/* keeps the sign alive */
			s2 = (short)krs2.s[i];
			kres.i = s1 * s2;
			lrd.i[i] = kres.i << 8;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fmuld8ulx16:
		VISINFO_KSTAT(vis_fmuld8ulx16);
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0; i <= 1; i++) {
			us1 = (ushort_t)krs1.c[(i*2)+1];
			s2 = (short)krs2.s[i];
			lrd.i[i] = us1 * s2;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	}
	return (ftt_none);
}

/*
 * Simulator for fpixel formatting instructions.
 */
static enum ftt_type
vis_fpixel(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* FPU instruction to simulate. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	int	i, j, k, sf;
	union {
		uint64_t	ll;
		uint32_t	i[2];
		uint16_t	s[4];
		uint8_t		c[8];
	} lrs1, lrs2, lrd;
	union {
		uint32_t	i;
		uint16_t	s[2];
		uint8_t		c[4];
	} krs1, krs2, krd;
	uint64_t r;
	int64_t l, m;
	short s;
	uchar_t uc;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	if ((inst.opf != fpack16) && (inst.opf != fpackfix)) {
		if ((nrd & 1) == 1) 	/* fix register encoding */
			nrd = (nrd & 0x1e) | 0x20;
	}

	switch (inst.opf) {
	case fpack16:
		VISINFO_KSTAT(vis_fpack16);
		if ((nrs2 & 1) == 1) 	/* fix register encoding */
			nrs2 = (nrs2 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
		r = pfpsd->fp_current_read_gsr(fp);
		/* fpack16 ignores GSR.scale msb */
		sf = (int)(GSR_SCALE(r) & 0xf);
		for (i = 0; i <= 3; i++) {
			s = (short)lrs2.s[i];	/* preserve the sign */
			j = ((int)s << sf);
			k = j >> 7;
			if (k < 0) {
				uc = 0;
			} else if (k > 255) {
				uc = 255;
			} else {
				uc = (uchar_t)k;
			}
			krd.c[i] = uc;
		}
		_fp_pack_word(pfpsd, &krd.i, nrd);
		break;
	case fpack32:
		VISINFO_KSTAT(vis_fpack32);
		if ((nrs1 & 1) == 1) 	/* fix register encoding */
			nrs1 = (nrs1 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
		if ((nrs2 & 1) == 1)
			nrs2 = (nrs2 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);

		r = pfpsd->fp_current_read_gsr(fp);
		sf = (int)GSR_SCALE(r);
		lrd.ll = lrs1.ll << 8;
		for (i = 0, k = 3; i <= 1; i++, k += 4) {
			j = (int)lrs2.i[i];	/* preserve the sign */
			l = ((int64_t)j << sf);
			m = l >> 23;
			if (m < 0) {
				uc = 0;
			} else if (m > 255) {
				uc = 255;
			} else {
				uc = (uchar_t)m;
			}
			lrd.c[k] = uc;
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fpackfix:
		VISINFO_KSTAT(vis_fpackfix);
		if ((nrs2 & 1) == 1)
			nrs2 = (nrs2 & 0x1e) | 0x20;
		_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);

		r = pfpsd->fp_current_read_gsr(fp);
		sf = (int)GSR_SCALE(r);
		for (i = 0; i <= 1; i++) {
			j = (int)lrs2.i[i];	/* preserve the sign */
			l = ((int64_t)j << sf);
			m = l >> 16;
			if (m < -32768) {
				s = -32768;
			} else if (m > 32767) {
				s = 32767;
			} else {
				s = (short)m;
			}
			krd.s[i] = s;
		}
		_fp_pack_word(pfpsd, &krd.i, nrd);
		break;
	case fexpand:
		VISINFO_KSTAT(vis_fexpand);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0; i <= 3; i++) {
			uc = krs2.c[i];
			lrd.s[i] = (ushort_t)(uc << 4);
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	case fpmerge:
		VISINFO_KSTAT(vis_fpmerge);
		_fp_unpack_word(pfpsd, &krs1.i, nrs1);
		_fp_unpack_word(pfpsd, &krs2.i, nrs2);
		for (i = 0, j = 0; i <= 3; i++, j += 2) {
			lrd.c[j] = krs1.c[i];
			lrd.c[j+1] = krs2.c[i];
		}
		_fp_pack_extword(pfpsd, &lrd.ll, nrd);
		break;
	}
	return (ftt_none);
}

/*
 * Simulator for pdist instruction.
 */
enum ftt_type
vis_pdist(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst)	/* FPU instruction to simulate. */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	int	i;
	short	s;
	union {
		uint64_t	ll;
		uint8_t		c[8];
	} lrs1, lrs2, lrd;

	nrs1 = pinst.rs1;
	nrs2 = pinst.rs2;
	nrd = pinst.rd;
	VISINFO_KSTAT(vis_pdist);
	if ((nrs1 & 1) == 1) 		/* fix register encoding */
		nrs1 = (nrs1 & 0x1e) | 0x20;
	if ((nrs2 & 1) == 1)
		nrs2 = (nrs2 & 0x1e) | 0x20;
	if ((nrd & 1) == 1)
		nrd = (nrd & 0x1e) | 0x20;

	_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
	_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);
	_fp_unpack_extword(pfpsd, &lrd.ll, nrd);

	for (i = 0; i <= 7; i++) {
		s = (short)(lrs1.c[i] - lrs2.c[i]);
		if (s < 0)
			s = ~s + 1;
		lrd.ll += s;
	}

	_fp_pack_extword(pfpsd, &lrd.ll, nrd);
	return (ftt_none);
}

/*
 * Simulator for faligndata instruction.
 */
static enum ftt_type
vis_faligndata(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	int	i, j, k, ao;
	union {
		uint64_t	ll;
		uint8_t		c[8];
	} lrs1, lrs2, lrd;
	uint64_t r;

	nrs1 = pinst.rs1;
	nrs2 = pinst.rs2;
	nrd = pinst.rd;
	if ((nrs1 & 1) == 1) 		/* fix register encoding */
		nrs1 = (nrs1 & 0x1e) | 0x20;
	if ((nrs2 & 1) == 1)
		nrs2 = (nrs2 & 0x1e) | 0x20;
	if ((nrd & 1) == 1)
		nrd = (nrd & 0x1e) | 0x20;

	_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
	_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);

	r = pfpsd->fp_current_read_gsr(fp);
	ao = (int)GSR_ALIGN(r);

	for (i = 0, j = ao, k = 0; i <= 7; i++)
		if (j <= 7) {
			lrd.c[i] = lrs1.c[j++];
		} else {
			lrd.c[i] = lrs2.c[k++];
		}
	_fp_pack_extword(pfpsd, &lrd.ll, nrd);

	return (ftt_none);
}

/*
 * Simulator for bshuffle instruction.
 */
static enum ftt_type
vis_bshuffle(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	int	i, j, ao;
	union {
		uint64_t	ll;
		uint8_t		c[8];
	} lrs1, lrs2, lrd;
	uint64_t r;

	VISINFO_KSTAT(vis_bshuffle);
	nrs1 = pinst.rs1;
	nrs2 = pinst.rs2;
	nrd = pinst.rd;
	if ((nrs1 & 1) == 1) 		/* fix register encoding */
		nrs1 = (nrs1 & 0x1e) | 0x20;
	if ((nrs2 & 1) == 1)
		nrs2 = (nrs2 & 0x1e) | 0x20;
	if ((nrd & 1) == 1)
		nrd = (nrd & 0x1e) | 0x20;

	_fp_unpack_extword(pfpsd, &lrs1.ll, nrs1);
	_fp_unpack_extword(pfpsd, &lrs2.ll, nrs2);

	r = pfpsd->fp_current_read_gsr(fp);
	ao = (int)GSR_MASK(r);

	/*
	 * BSHUFFLE Destination Byte Selection
	 * rd Byte	Source
	 * 0		rs byte[GSR.mask<31..28>]
	 * 1		rs byte[GSR.mask<27..24>]
	 * 2		rs byte[GSR.mask<23..20>]
	 * 3		rs byte[GSR.mask<19..16>]
	 * 4		rs byte[GSR.mask<15..12>]
	 * 5		rs byte[GSR.mask<11..8>]
	 * 6		rs byte[GSR.mask<7..4>]
	 * 7		rs byte[GSR.mask<3..0>]
	 * P.S. rs1 is the upper half and rs2 is the lower half
	 * Bytes in the source value are numbered from most to
	 * least significant
	 */
	for (i = 7; i >= 0; i--, ao = (ao >> 4)) {
		j = ao & 0xf;		/* get byte number */
		if (j < 8) {
			lrd.c[i] = lrs1.c[j];
		} else {
			lrd.c[i] = lrs2.c[j - 8];
		}
	}
	_fp_pack_extword(pfpsd, &lrd.ll, nrd);

	return (ftt_none);
}

/*
 * Simulator for siam instruction.
 */
static enum ftt_type
vis_siam(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* FPU instruction to simulate. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t	nrs2;			/* Register number fields. */
	uint64_t g, r;
	nrs2 = inst.rs2;

	g = pfpsd->fp_current_read_gsr(fp);
	g &= ~(GSR_IM_IRND_MASK);	/* zero the IM and IRND fields */
	r = nrs2 & 0x7;			/* get mode(3 bit) */
	g |= (r << GSR_IRND_SHIFT);
	pfpsd->fp_current_write_gsr(g, fp);
	return (ftt_none);
}

/*
 * Simulator for VIS loads and stores between floating-point unit and memory.
 */
enum ftt_type
vis_fldst(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	uint_t		asi)	/* asi to emulate! */
{
	union {
		vis_inst_type	inst;
		fp_inst_type	pinst;
	} i;

	ASSERT(USERMODE(pregs->r_tstate));
	i.pinst = pinst;
	switch (asi) {
		case ASI_PST8_P:
		case ASI_PST8_S:
		case ASI_PST16_P:
		case ASI_PST16_S:
		case ASI_PST32_P:
		case ASI_PST32_S:
		case ASI_PST8_PL:
		case ASI_PST8_SL:
		case ASI_PST16_PL:
		case ASI_PST16_SL:
		case ASI_PST32_PL:
		case ASI_PST32_SL:
			return (vis_prtl_fst(pfpsd, i.inst, pregs,
			    prw, asi));
		case ASI_FL8_P:
		case ASI_FL8_S:
		case ASI_FL8_PL:
		case ASI_FL8_SL:
		case ASI_FL16_P:
		case ASI_FL16_S:
		case ASI_FL16_PL:
		case ASI_FL16_SL:
			return (vis_short_fls(pfpsd, i.inst, pregs,
			    prw, asi));
		case ASI_BLK_AIUP:
		case ASI_BLK_AIUS:
		case ASI_BLK_AIUPL:
		case ASI_BLK_AIUSL:
		case ASI_BLK_P:
		case ASI_BLK_S:
		case ASI_BLK_PL:
		case ASI_BLK_SL:
		case ASI_BLK_COMMIT_P:
		case ASI_BLK_COMMIT_S:
			return (vis_blk_fldst(pfpsd, i.inst, pregs,
			    prw, asi));
		default:
			return (ftt_unimplemented);
	}
}

/*
 * Simulator for partial stores between floating-point unit and memory.
 */
static enum ftt_type
vis_prtl_fst(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* ISE instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	uint_t		asi)	/* asi to emulate! */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	uint_t	opf, msk;
	int	h, i, j;
	uint64_t ea, tmsk;
	union {
		freg_type	f;
		uint64_t	ll;
		uint32_t	i[2];
		uint16_t	s[4];
		uint8_t		c[8];
	} k, l, res;
	enum ftt_type   ftt;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	if ((nrd & 1) == 1) 		/* fix register encoding */
		nrd = (nrd & 0x1e) | 0x20;
	opf = inst.opf;
	res.ll = 0;
	if ((opf & 0x100) == 0) {	/* effective address = rs1  */
		ftt = read_iureg(pfpsd, nrs1, pregs, prw, &ea);
		if (ftt != ftt_none)
			return (ftt);
		ftt = read_iureg(pfpsd, nrs2, pregs, prw, &tmsk);
		if (ftt != ftt_none)
			return (ftt);
		msk = (uint_t)tmsk;
	} else {
		pfpsd->fp_trapaddr = (caddr_t)pregs->r_pc;
		return (ftt_unimplemented);
	}

	pfpsd->fp_trapaddr = (caddr_t)ea; /* setup bad addr in case we trap */
	if ((ea & 0x3) != 0)
		return (ftt_alignment);	/* Require 32 bit-alignment. */

	switch (asi) {
	case ASI_PST8_P:
	case ASI_PST8_S:
		ftt = _fp_read_extword((uint64_t *)ea, &l.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		for (i = 0, j = 0x80; i <= 7; i++, j >>= 1) {
			if ((msk & j) == j)
				res.c[i] = k.c[i];
			else
				res.c[i] = l.c[i];
		}
		ftt = _fp_write_extword((uint64_t *)ea, res.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		break;
	case ASI_PST8_PL:	/* little-endian */
	case ASI_PST8_SL:
		ftt = _fp_read_extword((uint64_t *)ea, &l.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		for (h = 7, i = 0, j = 1; i <= 7; h--, i++, j <<= 1) {
			if ((msk & j) == j)
				res.c[i] = k.c[h];
			else
				res.c[i] = l.c[i];
		}
		ftt = _fp_write_extword((uint64_t *)ea, res.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		break;
	case ASI_PST16_P:
	case ASI_PST16_S:
		ftt = _fp_read_extword((uint64_t *)ea, &l.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		for (i = 0, j = 0x8; i <= 3; i++, j >>= 1) {
			if ((msk & j) == j)
				res.s[i] = k.s[i];
			else
				res.s[i] = l.s[i];
		}
		ftt = _fp_write_extword((uint64_t *)ea, res.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		break;
	case ASI_PST16_PL:
	case ASI_PST16_SL:
		ftt = _fp_read_extword((uint64_t *)ea, &l.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		for (h = 7, i = 0, j = 1; i <= 6; h -= 2, i += 2, j <<= 1) {
			if ((msk & j) == j) {
				res.c[i] = k.c[h];
				res.c[i+1] = k.c[h-1];
			} else {
				res.c[i] = l.c[i];
				res.c[i+1] = l.c[i+1];
			}
		}
		ftt = _fp_write_extword((uint64_t *)ea, res.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		break;
	case ASI_PST32_P:
	case ASI_PST32_S:
		ftt = _fp_read_extword((uint64_t *)ea, &l.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		for (i = 0, j = 0x2; i <= 1; i++, j >>= 1) {
			if ((msk & j) == j)
				res.i[i] = k.i[i];
			else
				res.i[i] = l.i[i];
		}
		ftt = _fp_write_extword((uint64_t *)ea, res.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		break;
	case ASI_PST32_PL:
	case ASI_PST32_SL:
		ftt = _fp_read_extword((uint64_t *)ea, &l.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		for (h = 7, i = 0, j = 1; i <= 4; h -= 4, i += 4, j <<= 1) {
			if ((msk & j) == j) {
				res.c[i] = k.c[h];
				res.c[i+1] = k.c[h-1];
				res.c[i+2] = k.c[h-2];
				res.c[i+3] = k.c[h-3];
			} else {
				res.c[i] = l.c[i];
				res.c[i+1] = l.c[i+1];
				res.c[i+2] = l.c[i+2];
				res.c[i+3] = l.c[i+3];
			}
		}
		ftt = _fp_write_extword((uint64_t *)ea, res.ll, pfpsd);
		if (ftt != ftt_none)
			return (ftt);
		break;
	}

	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt_none);
}

/*
 * Simulator for short load/stores between floating-point unit and memory.
 */
static enum ftt_type
vis_short_fls(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* ISE instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	uint_t		asi)	/* asi to emulate! */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	uint_t	opf;
	uint64_t ea, tea;
	union {
		freg_type	f;
		uint64_t	ll;
		uint32_t	i[2];
		uint16_t	s[4];
		uint8_t		c[8];
	} k;
	union {
		vis_inst_type	inst;
		int		i;
	} fp;
	enum ftt_type   ftt = ftt_none;
	ushort_t us;
	uchar_t uc;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	if ((nrd & 1) == 1) 		/* fix register encoding */
		nrd = (nrd & 0x1e) | 0x20;
	opf = inst.opf;
	fp.inst = inst;
	if ((opf & 0x100) == 0) { /* effective address = rs1 + rs2 */
		ftt = read_iureg(pfpsd, nrs1, pregs, prw, &ea);
		if (ftt != ftt_none)
			return (ftt);
		ftt = read_iureg(pfpsd, nrs2, pregs, prw, &tea);
		if (ftt != ftt_none)
			return (ftt);
		ea += tea;
	} else {	/* effective address = rs1 + imm13 */
		fp.inst = inst;
		ea = (fp.i << 19) >> 19;	/* Extract simm13 field. */
		ftt = read_iureg(pfpsd, nrs1, pregs, prw, &tea);
		if (ftt != ftt_none)
			return (ftt);
		ea += tea;
	}
	if (get_udatamodel() == DATAMODEL_ILP32)
		ea = (uint64_t)(caddr32_t)ea;

	pfpsd->fp_trapaddr = (caddr_t)ea; /* setup bad addr in case we trap */
	switch (asi) {
	case ASI_FL8_P:
	case ASI_FL8_S:
	case ASI_FL8_PL:		/* little-endian */
	case ASI_FL8_SL:
		if ((inst.op3 & 7) == 3) {	/* load byte */
			if (fuword8((void *)ea, &uc) == -1)
				return (ftt_fault);
			k.ll = 0;
			k.c[7] = uc;
			_fp_pack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		} else {			/* store byte */
			_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
			uc = k.c[7];
			if (subyte((caddr_t)ea, uc) == -1)
				return (ftt_fault);
		}
		break;
	case ASI_FL16_P:
	case ASI_FL16_S:
		if ((ea & 1) == 1)
			return (ftt_alignment);
		if ((inst.op3 & 7) == 3) {	/* load short */
			if (fuword16((void *)ea, &us) == -1)
				return (ftt_fault);
			k.ll = 0;
			k.s[3] = us;
			_fp_pack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		} else {			/* store short */
			_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
			us = k.s[3];
			if (suword16((caddr_t)ea, us) == -1)
				return (ftt_fault);
		}
		break;
	case ASI_FL16_PL:		/* little-endian */
	case ASI_FL16_SL:
		if ((ea & 1) == 1)
			return (ftt_alignment);
		if ((inst.op3 & 7) == 3) {	/* load short */
			if (fuword16((void *)ea, &us) == -1)
				return (ftt_fault);
			k.ll = 0;
			k.c[6] = (uchar_t)us;
			k.c[7] = (uchar_t)((us & 0xff00) >> 8);
			_fp_pack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
		} else {			/* store short */
			_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD, nrd);
			uc = k.c[7];
			us = (ushort_t)((uc << 8) | k.c[6]);
			if (suword16((void *)ea, us) == -1)
				return (ftt_fault);
		}
		break;
	}

	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt_none);
}

/*
 * Simulator for block loads and stores between floating-point unit and memory.
 * We pass the addrees of ea to sync_data_memory() to flush the Ecache.
 * Sync_data_memory() calls platform dependent code to flush the Ecache.
 */
static enum ftt_type
vis_blk_fldst(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	vis_inst_type	inst,	/* ISE instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	uint_t		asi)	/* asi to emulate! */
{
	uint_t	nrs1, nrs2, nrd;	/* Register number fields. */
	uint_t	opf, h, i, j;
	uint64_t ea, tea;
	union {
		freg_type	f;
		uint64_t	ll;
		uint8_t		c[8];
	} k, l;
	union {
		vis_inst_type	inst;
		int32_t		i;
	} fp;
	enum ftt_type   ftt;
	boolean_t little_endian = B_FALSE;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	if ((nrd & 1) == 1) 		/* fix register encoding */
		nrd = (nrd & 0x1e) | 0x20;

	/* ensure register is 8-double precision aligned */
	if ((nrd & 0xf) != 0)
		return (ftt_unimplemented);

	opf = inst.opf;
	if ((opf & 0x100) == 0) { 	/* effective address = rs1 + rs2 */
		ftt = read_iureg(pfpsd, nrs1, pregs, prw, &ea);
		if (ftt != ftt_none)
			return (ftt);
		ftt = read_iureg(pfpsd, nrs2, pregs, prw, &tea);
		if (ftt != ftt_none)
			return (ftt);
		ea += tea;
	} else {			/* effective address = rs1 + imm13 */
		fp.inst = inst;
		ea = (fp.i << 19) >> 19;	/* Extract simm13 field. */
		ftt = read_iureg(pfpsd, nrs1, pregs, prw, &tea);
		if (ftt != ftt_none)
			return (ftt);
		ea += tea;
	}
	if ((ea & 0x3F) != 0)		/* Require 64 byte-alignment. */
		return (ftt_alignment);

	pfpsd->fp_trapaddr = (caddr_t)ea; /* setup bad addr in case we trap */
	switch (asi) {
	case ASI_BLK_AIUPL:
	case ASI_BLK_AIUSL:
	case ASI_BLK_PL:
	case ASI_BLK_SL:
		little_endian = B_TRUE;
		/* FALLTHROUGH */
	case ASI_BLK_AIUP:
	case ASI_BLK_AIUS:
	case ASI_BLK_P:
	case ASI_BLK_S:
	case ASI_BLK_COMMIT_P:
	case ASI_BLK_COMMIT_S:
		if ((inst.op3 & 7) == 3) {	/* lddf */
			for (i = 0; i < 8; i++, nrd += 2) {
				ftt = _fp_read_extword((uint64_t *)ea, &k.ll,
				    pfpsd);
				if (ftt != ftt_none)
					return (ftt);
				if (little_endian) {
					for (j = 0, h = 7; j < 8; j++, h--)
						l.c[h] = k.c[j];
					k.ll = l.ll;
				}
				_fp_pack_extword(pfpsd, &k.f.FPU_DREG_FIELD,
				    nrd);
				ea += 8;
			}
		} else {			/* stdf */
			for (i = 0; i < 8; i++, nrd += 2) {
				_fp_unpack_extword(pfpsd, &k.f.FPU_DREG_FIELD,
				    nrd);
				if (little_endian) {
					for (j = 0, h = 7; j < 8; j++, h--)
						l.c[h] = k.c[j];
					k.ll = l.ll;
				}
				ftt = _fp_write_extword((uint64_t *)ea, k.ll,
				    pfpsd);
				if (ftt != ftt_none)
					return (ftt);
				ea += 8;
			}
		}
		if ((asi == ASI_BLK_COMMIT_P) || (asi == ASI_BLK_COMMIT_S))
			sync_data_memory((caddr_t)(ea - 64), 64);
		break;
	default:
		/* addr of unimp inst */
		pfpsd->fp_trapaddr = (caddr_t)pregs->r_pc;
		return (ftt_unimplemented);
	}

	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt_none);
}

/*
 * Simulator for rd %gsr instruction.
 */
enum ftt_type
vis_rdgsr(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t nrd;
	uint64_t r;
	enum ftt_type ftt = ftt_none;

	nrd = pinst.rd;

	r = pfpsd->fp_current_read_gsr(fp);
	ftt = write_iureg(pfpsd, nrd, pregs, prw, &r);
	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt);
}

/*
 * Simulator for wr %gsr instruction.
 */
enum ftt_type
vis_wrgsr(
	fp_simd_type	*pfpsd,	/* FPU simulator data. */
	fp_inst_type	pinst,	/* FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*fp)	/* Need to fp to access gsr reg */
{
	uint_t nrs1;
	uint64_t r, r1, r2;
	enum ftt_type ftt = ftt_none;

	nrs1 = pinst.rs1;
	ftt = read_iureg(pfpsd, nrs1, pregs, prw, &r1);
	if (ftt != ftt_none)
		return (ftt);
	if (pinst.ibit == 0) {	/* copy the value in r[rs2] */
		uint_t nrs2;

		nrs2 = pinst.rs2;
		ftt = read_iureg(pfpsd, nrs2, pregs, prw, &r2);
		if (ftt != ftt_none)
			return (ftt);
	} else {	/* use sign_ext(simm13) */
		union {
			fp_inst_type	inst;
			uint32_t	i;
		} fp;

		fp.inst = pinst;		/* Extract simm13 field */
		r2 = (fp.i << 19) >> 19;
	}
	r = r1 ^ r2;
	pfpsd->fp_current_write_gsr(r, fp);
	pregs->r_pc = pregs->r_npc;	/* Do not retry emulated instruction. */
	pregs->r_npc += 4;
	return (ftt);
}

/*
 * This is the loadable module wrapper.
 */
#include <sys/errno.h>
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"vis fp simulation",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
