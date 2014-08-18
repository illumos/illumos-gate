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

/* Main procedures for sparc FPU simulator. */

#include <sys/fpu/fpu_simulator.h>
#include <sys/fpu/globals.h>
#include <sys/fpu/fpusystm.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/privregs.h>
#include <sys/vis_simulator.h>

#define	FPUINFO_KSTAT(opcode)	{					\
	extern void __dtrace_probe___fpuinfo_##opcode(uint64_t *);	\
	uint64_t *stataddr = &fpuinfo.opcode.value.ui64;		\
	__dtrace_probe___fpuinfo_##opcode(stataddr);			\
	atomic_inc_64(&fpuinfo.opcode.value.ui64);			\
}

#define	FPUINFO_KSTAT_PREC(prec, kstat_s, kstat_d, kstat_q)		\
	if (prec < 2) {							\
		FPUINFO_KSTAT(kstat_s);					\
	} else if (prec == 2) {						\
		FPUINFO_KSTAT(kstat_d);					\
	} else {							\
		FPUINFO_KSTAT(kstat_q);					\
	}

/*
 * FPU simulator global kstat data
 */
struct fpuinfo_kstat fpuinfo = {
	{ "fpu_sim_fmovs",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmovd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmovq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fnegs",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fnegd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fnegq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fabss",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fabsd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fabsq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fsqrts",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fsqrtd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fsqrtq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fadds",		KSTAT_DATA_UINT64},
	{ "fpu_sim_faddd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_faddq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fsubs",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fsubd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fsubq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmuls",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmuld",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmulq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fdivs",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fdivd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fdivq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fcmps",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fcmpd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fcmpq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fcmpes",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fcmped",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fcmpeq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fsmuld",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fdmulx",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fstox",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fdtox",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fqtox",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fxtos",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fxtod",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fxtoq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fitos",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fitod",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fitoq",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fstoi",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fdtoi",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fqtoi",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmovcc",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmovr",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmadds",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmaddd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmsubs",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fmsubd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fnmadds",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fnmaddd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fnmsubs",		KSTAT_DATA_UINT64},
	{ "fpu_sim_fnmsubd",		KSTAT_DATA_UINT64},
	{ "fpu_sim_invalid",		KSTAT_DATA_UINT64},
};

struct visinfo_kstat visinfo = {
	{ "vis_edge8",		KSTAT_DATA_UINT64},
	{ "vis_edge8n",		KSTAT_DATA_UINT64},
	{ "vis_edge8l",		KSTAT_DATA_UINT64},
	{ "vis_edge8ln",	KSTAT_DATA_UINT64},
	{ "vis_edge16",		KSTAT_DATA_UINT64},
	{ "vis_edge16n",	KSTAT_DATA_UINT64},
	{ "vis_edge16l",	KSTAT_DATA_UINT64},
	{ "vis_edge16ln",	KSTAT_DATA_UINT64},
	{ "vis_edge32",		KSTAT_DATA_UINT64},
	{ "vis_edge32n",	KSTAT_DATA_UINT64},
	{ "vis_edge32l",	KSTAT_DATA_UINT64},
	{ "vis_edge32ln",	KSTAT_DATA_UINT64},
	{ "vis_array8",		KSTAT_DATA_UINT64},
	{ "vis_array16",	KSTAT_DATA_UINT64},
	{ "vis_array32",	KSTAT_DATA_UINT64},
	{ "vis_bmask",		KSTAT_DATA_UINT64},
	{ "vis_fcmple16",	KSTAT_DATA_UINT64},
	{ "vis_fcmpne16",	KSTAT_DATA_UINT64},
	{ "vis_fcmpgt16",	KSTAT_DATA_UINT64},
	{ "vis_fcmpeq16",	KSTAT_DATA_UINT64},
	{ "vis_fcmple32",	KSTAT_DATA_UINT64},
	{ "vis_fcmpne32",	KSTAT_DATA_UINT64},
	{ "vis_fcmpgt32",	KSTAT_DATA_UINT64},
	{ "vis_fcmpeq32",	KSTAT_DATA_UINT64},
	{ "vis_fmul8x16",	KSTAT_DATA_UINT64},
	{ "vis_fmul8x16au",	KSTAT_DATA_UINT64},
	{ "vis_fmul8x16al",	KSTAT_DATA_UINT64},
	{ "vis_fmul8sux16",	KSTAT_DATA_UINT64},
	{ "vis_fmul8ulx16",	KSTAT_DATA_UINT64},
	{ "vis_fmuld8sux16",	KSTAT_DATA_UINT64},
	{ "vis_fmuld8ulx16",	KSTAT_DATA_UINT64},
	{ "vis_fpack16",	KSTAT_DATA_UINT64},
	{ "vis_fpack32",	KSTAT_DATA_UINT64},
	{ "vis_fpackfix",	KSTAT_DATA_UINT64},
	{ "vis_fexpand",	KSTAT_DATA_UINT64},
	{ "vis_fpmerge",	KSTAT_DATA_UINT64},
	{ "vis_pdist",		KSTAT_DATA_UINT64},
	{ "vis_pdistn",		KSTAT_DATA_UINT64},
	{ "vis_bshuffle",	KSTAT_DATA_UINT64},

};

/* PUBLIC FUNCTIONS */

int fp_notp = 1;	/* fp checking not a problem */

/* ARGSUSED */
static enum ftt_type
_fp_fpu_simulator(
	fp_simd_type	*pfpsd,	/* Pointer to fpu simulator data */
	fp_inst_type	inst,	/* FPU instruction to simulate. */
	fsr_type	*pfsr,	/* Pointer to image of FSR to read and write. */
	uint64_t	gsr)	/* Image of GSR to read */
{
	unpacked	us1, us2, ud;	/* Unpacked operands and result. */
	uint32_t	nrs1, nrs2, nrd; /* Register number fields. */
	uint32_t	usr, andexcep;
	fsr_type	fsr;
	enum fcc_type	cc;
	uint32_t	nfcc;		/* fcc number field. */
	uint64_t	lusr;

	nrs1 = inst.rs1;
	nrs2 = inst.rs2;
	nrd = inst.rd;
	fsr = *pfsr;
	pfpsd->fp_current_exceptions = 0;	/* Init current exceptions. */
	pfpsd->fp_fsrtem    = fsr.tem;		/* Obtain fsr's tem */
	/*
	 * Obtain rounding direction and precision
	 */
	pfpsd->fp_direction = GSR_IM(gsr) ? GSR_IRND(gsr) : fsr.rnd;
	pfpsd->fp_precision = fsr.rnp;

	if (inst.op3 == 0x37) { /* IMPDEP2B FMA-fused opcode */
		fp_fma_inst_type *fma_inst;
		uint32_t	nrs3;
		unpacked	us3;
		unpacked	ust;
		fma_inst = (fp_fma_inst_type *) &inst;
		nrs2 = fma_inst->rs2;
		nrs3 = fma_inst->rs3;
		switch (fma_inst->var) {
		case fmadd:
			_fp_unpack(pfpsd, &us1, nrs1, fma_inst->sz);
			_fp_unpack(pfpsd, &us2, nrs2, fma_inst->sz);
			_fp_mul(pfpsd, &us1, &us2, &ust);
			if ((pfpsd->fp_current_exceptions & fsr.tem) == 0) {
				_fp_unpack(pfpsd, &us3, nrs3, fma_inst->sz);
				_fp_add(pfpsd, &ust, &us3, &ud);
				_fp_pack(pfpsd, &ud, nrd, fma_inst->sz);
			}
			FPUINFO_KSTAT_PREC(fma_inst->sz, fpu_sim_fmadds,
			    fpu_sim_fmaddd, fpu_sim_invalid);
			break;
		case fmsub:
			_fp_unpack(pfpsd, &us1, nrs1, fma_inst->sz);
			_fp_unpack(pfpsd, &us2, nrs2, fma_inst->sz);
			_fp_mul(pfpsd, &us1, &us2, &ust);
			if ((pfpsd->fp_current_exceptions & fsr.tem) == 0) {
				_fp_unpack(pfpsd, &us3, nrs3, fma_inst->sz);
				_fp_sub(pfpsd, &ust, &us3, &ud);
				_fp_pack(pfpsd, &ud, nrd, fma_inst->sz);
			}
			FPUINFO_KSTAT_PREC(fma_inst->sz, fpu_sim_fmsubs,
			    fpu_sim_fmsubd, fpu_sim_invalid);
			break;
		case fnmadd:
			_fp_unpack(pfpsd, &us1, nrs1, fma_inst->sz);
			_fp_unpack(pfpsd, &us2, nrs2, fma_inst->sz);
			_fp_mul(pfpsd, &us1, &us2, &ust);
			if ((pfpsd->fp_current_exceptions & fsr.tem) == 0) {
				_fp_unpack(pfpsd, &us3, nrs3, fma_inst->sz);
				if (ust.fpclass != fp_quiet &&
				    ust.fpclass != fp_signaling)
					ust.sign ^= 1;
				_fp_sub(pfpsd, &ust, &us3, &ud);
				_fp_pack(pfpsd, &ud, nrd, fma_inst->sz);
			}
			FPUINFO_KSTAT_PREC(fma_inst->sz, fpu_sim_fnmadds,
			    fpu_sim_fnmaddd, fpu_sim_invalid);
			break;
		case fnmsub:
			_fp_unpack(pfpsd, &us1, nrs1, fma_inst->sz);
			_fp_unpack(pfpsd, &us2, nrs2, fma_inst->sz);
			_fp_mul(pfpsd, &us1, &us2, &ust);
			if ((pfpsd->fp_current_exceptions & fsr.tem) == 0) {
				_fp_unpack(pfpsd, &us3, nrs3, fma_inst->sz);
				if (ust.fpclass != fp_quiet &&
				    ust.fpclass != fp_signaling)
					ust.sign ^= 1;
				_fp_add(pfpsd, &ust, &us3, &ud);
				_fp_pack(pfpsd, &ud, nrd, fma_inst->sz);
			}
			FPUINFO_KSTAT_PREC(fma_inst->sz, fpu_sim_fnmsubs,
			    fpu_sim_fnmsubd, fpu_sim_invalid);
		}
	} else {
		nfcc = nrd & 0x3;
		if (inst.op3 == 0x35) {		/* fpop2 */
			fsr.cexc = 0;
			*pfsr = fsr;
			if ((inst.opcode & 0xf) == 0) {
				if ((fp_notp) && (inst.prec == 0))
					return (ftt_unimplemented);
				FPUINFO_KSTAT(fpu_sim_fmovcc);
				return (fmovcc(pfpsd, inst, pfsr)); /* fmovcc */
			} else if ((inst.opcode & 0x7) == 1) {
				if ((fp_notp) && (inst.prec == 0))
					return (ftt_unimplemented);
				FPUINFO_KSTAT(fpu_sim_fmovr);
				return (fmovr(pfpsd, inst));	/* fmovr */
			}
		}
		/* ibit not valid for fpop1 instructions */
		if ((fp_notp) && (inst.ibit != 0))
			return (ftt_unimplemented);
		if ((fp_notp) && (inst.prec == 0)) { /* fxto[sdq], fito[sdq] */
			if ((inst.opcode != flltos) &&
			    (inst.opcode != flltod) &&
			    (inst.opcode != flltox) &&
			    (inst.opcode != fitos) &&
			    (inst.opcode != fitod) &&
			    (inst.opcode != fitox)) {
				return (ftt_unimplemented);
			}
		}
		switch (inst.opcode) {
		case fmovs:		/* also covers fmovd, fmovq */
			if (inst.prec < 2) {	/* fmovs */
				_fp_unpack_word(pfpsd, &usr, nrs2);
				_fp_pack_word(pfpsd, &usr, nrd);
				FPUINFO_KSTAT(fpu_sim_fmovs);
			} else {		/* fmovd */
				_fp_unpack_extword(pfpsd, &lusr, nrs2);
				_fp_pack_extword(pfpsd, &lusr, nrd);
				if (inst.prec > 2) {		/* fmovq */
					_fp_unpack_extword(pfpsd, &lusr,
					    nrs2+2);
					_fp_pack_extword(pfpsd, &lusr, nrd+2);
					FPUINFO_KSTAT(fpu_sim_fmovq);
				} else {
					FPUINFO_KSTAT(fpu_sim_fmovd);
				}
			}
			break;
		case fabss:		/* also covers fabsd, fabsq */
			if (inst.prec < 2) {	/* fabss */
				_fp_unpack_word(pfpsd, &usr, nrs2);
				usr &= 0x7fffffff;
				_fp_pack_word(pfpsd, &usr, nrd);
				FPUINFO_KSTAT(fpu_sim_fabss);
			} else {		/* fabsd */
				_fp_unpack_extword(pfpsd, &lusr, nrs2);
				lusr &= 0x7fffffffffffffff;
				_fp_pack_extword(pfpsd, &lusr, nrd);
				if (inst.prec > 2) {		/* fabsq */
					_fp_unpack_extword(pfpsd, &lusr,
					    nrs2+2);
					_fp_pack_extword(pfpsd, &lusr, nrd+2);
					FPUINFO_KSTAT(fpu_sim_fabsq);
				} else {
					FPUINFO_KSTAT(fpu_sim_fabsd);
				}
			}
			break;
		case fnegs:		/* also covers fnegd, fnegq */
			if (inst.prec < 2) {	/* fnegs */
				_fp_unpack_word(pfpsd, &usr, nrs2);
				usr ^= 0x80000000;
				_fp_pack_word(pfpsd, &usr, nrd);
				FPUINFO_KSTAT(fpu_sim_fnegs);
			} else {		/* fnegd */
				_fp_unpack_extword(pfpsd, &lusr, nrs2);
				lusr ^= 0x8000000000000000;
				_fp_pack_extword(pfpsd, &lusr, nrd);
				if (inst.prec > 2) {		/* fnegq */
					_fp_unpack_extword(pfpsd, &lusr,
					    nrs2+2);
					lusr ^= 0x0000000000000000;
					_fp_pack_extword(pfpsd, &lusr, nrd+2);
					FPUINFO_KSTAT(fpu_sim_fnegq);
				} else {
					FPUINFO_KSTAT(fpu_sim_fnegd);
				}
			}
			break;
		case fadd:
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			_fp_add(pfpsd, &us1, &us2, &ud);
			_fp_pack(pfpsd, &ud, nrd, inst.prec);
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fadds,
			    fpu_sim_faddd, fpu_sim_faddq);
			break;
		case fsub:
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			_fp_sub(pfpsd, &us1, &us2, &ud);
			_fp_pack(pfpsd, &ud, nrd, inst.prec);
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fsubs,
			    fpu_sim_fsubd, fpu_sim_fsubq);
			break;
		case fmul:
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			_fp_mul(pfpsd, &us1, &us2, &ud);
			_fp_pack(pfpsd, &ud, nrd, inst.prec);
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fmuls,
			    fpu_sim_fmuld, fpu_sim_fmulq);
			break;
		case fsmuld:
			if ((fp_notp) && (inst.prec != 1))
				return (ftt_unimplemented);
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			_fp_mul(pfpsd, &us1, &us2, &ud);
			_fp_pack(pfpsd, &ud, nrd,
			    (enum fp_op_type) ((int)inst.prec+1));
			FPUINFO_KSTAT(fpu_sim_fsmuld);
			break;
		case fdmulx:
			if ((fp_notp) && (inst.prec != 2))
				return (ftt_unimplemented);
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			_fp_mul(pfpsd, &us1, &us2, &ud);
			_fp_pack(pfpsd, &ud, nrd,
			    (enum fp_op_type) ((int)inst.prec+1));
			FPUINFO_KSTAT(fpu_sim_fdmulx);
			break;
		case fdiv:
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			_fp_div(pfpsd, &us1, &us2, &ud);
			_fp_pack(pfpsd, &ud, nrd, inst.prec);
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fdivs,
			    fpu_sim_fdivd, fpu_sim_fdivq);
			break;
		case fcmp:
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			cc = _fp_compare(pfpsd, &us1, &us2, 0);
			if (!(pfpsd->fp_current_exceptions & pfpsd->fp_fsrtem))
				switch (nfcc) {
				case fcc_0:
					fsr.fcc0 = cc;
					break;
				case fcc_1:
					fsr.fcc1 = cc;
					break;
				case fcc_2:
					fsr.fcc2 = cc;
					break;
				case fcc_3:
					fsr.fcc3 = cc;
					break;
				}
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fcmps,
			    fpu_sim_fcmpd, fpu_sim_fcmpq);
			break;
		case fcmpe:
			_fp_unpack(pfpsd, &us1, nrs1, inst.prec);
			_fp_unpack(pfpsd, &us2, nrs2, inst.prec);
			cc = _fp_compare(pfpsd, &us1, &us2, 1);
			if (!(pfpsd->fp_current_exceptions & pfpsd->fp_fsrtem))
				switch (nfcc) {
				case fcc_0:
					fsr.fcc0 = cc;
					break;
				case fcc_1:
					fsr.fcc1 = cc;
					break;
				case fcc_2:
					fsr.fcc2 = cc;
					break;
				case fcc_3:
					fsr.fcc3 = cc;
					break;
				}
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fcmpes,
			    fpu_sim_fcmped, fpu_sim_fcmpeq);
			break;
		case fsqrt:
			_fp_unpack(pfpsd, &us1, nrs2, inst.prec);
			_fp_sqrt(pfpsd, &us1, &ud);
			_fp_pack(pfpsd, &ud, nrd, inst.prec);
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fsqrts,
			    fpu_sim_fsqrtd, fpu_sim_fsqrtq);
			break;
		case ftoi:
			_fp_unpack(pfpsd, &us1, nrs2, inst.prec);
			pfpsd->fp_direction = fp_tozero;
			/* Force rounding toward zero. */
			_fp_pack(pfpsd, &us1, nrd, fp_op_int32);
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fstoi,
			    fpu_sim_fdtoi, fpu_sim_fqtoi);
			break;
		case ftoll:
			_fp_unpack(pfpsd, &us1, nrs2, inst.prec);
			pfpsd->fp_direction = fp_tozero;
			/* Force rounding toward zero. */
			_fp_pack(pfpsd, &us1, nrd, fp_op_int64);
			FPUINFO_KSTAT_PREC(inst.prec, fpu_sim_fstox,
			    fpu_sim_fdtox, fpu_sim_fqtox);
			break;
		case flltos:
			_fp_unpack(pfpsd, &us1, nrs2, fp_op_int64);
			_fp_pack(pfpsd, &us1, nrd, fp_op_single);
			FPUINFO_KSTAT(fpu_sim_fxtos);
			break;
		case flltod:
			_fp_unpack(pfpsd, &us1, nrs2, fp_op_int64);
			_fp_pack(pfpsd, &us1, nrd, fp_op_double);
			FPUINFO_KSTAT(fpu_sim_fxtod);
			break;
		case flltox:
			_fp_unpack(pfpsd, &us1, nrs2, fp_op_int64);
			_fp_pack(pfpsd, &us1, nrd, fp_op_extended);
			FPUINFO_KSTAT(fpu_sim_fxtoq);
			break;
		case fitos:
			_fp_unpack(pfpsd, &us1, nrs2, inst.prec);
			_fp_pack(pfpsd, &us1, nrd, fp_op_single);
			FPUINFO_KSTAT(fpu_sim_fitos);
			break;
		case fitod:
			_fp_unpack(pfpsd, &us1, nrs2, inst.prec);
			_fp_pack(pfpsd, &us1, nrd, fp_op_double);
			FPUINFO_KSTAT(fpu_sim_fitod);
			break;
		case fitox:
			_fp_unpack(pfpsd, &us1, nrs2, inst.prec);
			_fp_pack(pfpsd, &us1, nrd, fp_op_extended);
			FPUINFO_KSTAT(fpu_sim_fitoq);
			break;
		default:
			return (ftt_unimplemented);
		}
	}
	fsr.cexc = pfpsd->fp_current_exceptions;
	andexcep = pfpsd->fp_current_exceptions & fsr.tem;
	if (andexcep != 0) {	/* Signal an IEEE SIGFPE here. */
		if (andexcep & (1 << fp_invalid)) {
			pfpsd->fp_trapcode = FPE_FLTINV;
			fsr.cexc = FSR_CEXC_NV;
		} else if (andexcep & (1 << fp_overflow)) {
			pfpsd->fp_trapcode = FPE_FLTOVF;
			fsr.cexc = FSR_CEXC_OF;
		} else if (andexcep & (1 << fp_underflow)) {
			pfpsd->fp_trapcode = FPE_FLTUND;
			fsr.cexc = FSR_CEXC_UF;
		} else if (andexcep & (1 << fp_division)) {
			pfpsd->fp_trapcode = FPE_FLTDIV;
			fsr.cexc = FSR_CEXC_DZ;
		} else if (andexcep & (1 << fp_inexact)) {
			pfpsd->fp_trapcode = FPE_FLTRES;
			fsr.cexc = FSR_CEXC_NX;
		} else {
			pfpsd->fp_trapcode = 0;
		}
		*pfsr = fsr;
		return (ftt_ieee);
	} else {	/* Just set accrued exception field. */
		fsr.aexc |= pfpsd->fp_current_exceptions;
	}
	*pfsr = fsr;
	return (ftt_none);
}

/*
 * fpu_vis_sim simulates fpu and vis instructions;
 * It can work with both real and pcb image registers.
 */
enum ftt_type
fpu_vis_sim(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	fp_inst_type	*pinst,	/* Address of FPU instruction to simulate */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	fsr_type	*pfsr,	/* Pointer to image of FSR to read and write */
	uint64_t	gsr,	/* Image of GSR to read */
	uint32_t	inst)	/* The FPU instruction to simulate */
{
	klwp_id_t lwp = ttolwp(curthread);
	union {
		uint32_t	i;
		fp_inst_type	inst;
	} fp;
	kfpu_t *pfp = lwptofpu(lwp);
	enum ftt_type ftt;

	fp.i = inst;
	pfpsd->fp_trapaddr = (caddr_t)pinst;
	if (fpu_exists) {
		pfpsd->fp_current_read_freg = _fp_read_pfreg;
		pfpsd->fp_current_write_freg = _fp_write_pfreg;
		pfpsd->fp_current_read_dreg = _fp_read_pdreg;
		pfpsd->fp_current_write_dreg = _fp_write_pdreg;
		pfpsd->fp_current_read_gsr = _fp_read_pgsr;
		pfpsd->fp_current_write_gsr = _fp_write_pgsr;
	} else {
		pfpsd->fp_current_pfregs = pfp;
		pfpsd->fp_current_read_freg = _fp_read_vfreg;
		pfpsd->fp_current_write_freg = _fp_write_vfreg;
		pfpsd->fp_current_read_dreg = _fp_read_vdreg;
		pfpsd->fp_current_write_dreg = _fp_write_vdreg;
		pfpsd->fp_current_read_gsr = get_gsr;
		pfpsd->fp_current_write_gsr = set_gsr;
	}

	if ((fp.inst.hibits == 2) && (fp.inst.op3 == 0x36)) {
			ftt = vis_fpu_simulator(pfpsd, fp.inst,
			    pregs, (ulong_t *)pregs->r_sp, pfp);
			return (ftt);
	} else if ((fp.inst.hibits == 2) &&
	    ((fp.inst.op3 == 0x34) || (fp.inst.op3 == 0x35) ||
	    (fp.inst.op3 == 0x37))) {
		ftt =  _fp_fpu_simulator(pfpsd, fp.inst, pfsr, gsr);
		if (ftt == ftt_none || ftt == ftt_ieee) {
			pregs->r_pc = pregs->r_npc;
			pregs->r_npc += 4;
		}
		return (ftt);
	} else {
		ftt = _fp_iu_simulator(pfpsd, fp.inst, pregs,
		    (ulong_t *)pregs->r_sp, pfp);
		return (ftt);
	}
}

/*
 * fpu_simulator simulates FPU instructions only;
 * reads and writes FPU data registers directly.
 */
enum ftt_type
fpu_simulator(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	fp_inst_type	*pinst,	/* Address of FPU instruction to simulate */
	fsr_type	*pfsr,	/* Pointer to image of FSR to read and write */
	uint64_t	gsr,	/* Image of GSR to read */
	uint32_t	inst)	/* The FPU instruction to simulate */
{
	union {
		uint32_t	i;
		fp_inst_type	inst;
	} fp;

	fp.i = inst;
	pfpsd->fp_trapaddr = (caddr_t)pinst;
	pfpsd->fp_current_read_freg = _fp_read_pfreg;
	pfpsd->fp_current_write_freg = _fp_write_pfreg;
	pfpsd->fp_current_read_dreg = _fp_read_pdreg;
	pfpsd->fp_current_write_dreg = _fp_write_pdreg;
	pfpsd->fp_current_read_gsr = _fp_read_pgsr;
	pfpsd->fp_current_write_gsr = _fp_write_pgsr;
	return (_fp_fpu_simulator(pfpsd, fp.inst, pfsr, gsr));
}

/*
 * fp_emulator simulates FPU and CPU-FPU instructions; reads and writes FPU
 * data registers from image in pfpu.
 */
enum ftt_type
fp_emulator(
	fp_simd_type	*pfpsd,	/* Pointer to simulator data */
	fp_inst_type	*pinst,	/* Pointer to FPU instruction to simulate. */
	struct regs	*pregs,	/* Pointer to PCB image of registers. */
	void		*prw,	/* Pointer to locals and ins. */
	kfpu_t		*pfpu)	/* Pointer to FPU register block. */
{
	klwp_id_t lwp = ttolwp(curthread);
	union {
		uint32_t	i;
		fp_inst_type	inst;
	} fp;
	enum ftt_type	ftt;
	uint64_t gsr = get_gsr(pfpu);
	kfpu_t *pfp = lwptofpu(lwp);
	uint64_t	tfsr;

	tfsr = pfpu->fpu_fsr;
	pfpsd->fp_current_pfregs = pfpu;
	pfpsd->fp_current_read_freg = _fp_read_vfreg;
	pfpsd->fp_current_write_freg = _fp_write_vfreg;
	pfpsd->fp_current_read_dreg = _fp_read_vdreg;
	pfpsd->fp_current_write_dreg = _fp_write_vdreg;
	pfpsd->fp_current_read_gsr = get_gsr;
	pfpsd->fp_current_write_gsr = set_gsr;
	pfpsd->fp_trapaddr = (caddr_t)pinst; /* bad inst addr in case we trap */
	ftt = _fp_read_inst((uint32_t *)pinst, &(fp.i), pfpsd);
	if (ftt != ftt_none)
		return (ftt);

	if ((fp.inst.hibits == 2) &&
	    ((fp.inst.op3 == 0x34) || (fp.inst.op3 == 0x35) ||
	    (fp.inst.op3 == 0x37))) {
		ftt = _fp_fpu_simulator(pfpsd, fp.inst, (fsr_type *)&tfsr, gsr);
		/* Do not retry emulated instruction. */
		pregs->r_pc = pregs->r_npc;
		pregs->r_npc += 4;
		pfpu->fpu_fsr = tfsr;
		if (ftt != ftt_none) {
			/*
			 * Simulation generated an exception of some kind,
			 * simulate the fp queue for a signal.
			 */
			pfpu->fpu_q->FQu.fpq.fpq_addr = (uint32_t *)pinst;
			pfpu->fpu_q->FQu.fpq.fpq_instr = fp.i;
			pfpu->fpu_qcnt = 1;
		}
	} else if ((fp.inst.hibits == 2) && (fp.inst.op3 == 0x36)) {
			ftt = vis_fpu_simulator(pfpsd, fp.inst,
			    pregs, prw, pfp);
	} else
		ftt = _fp_iu_simulator(pfpsd, fp.inst, pregs, prw, pfpu);

	if (ftt != ftt_none)
		return (ftt);

	/*
	 * If we are single-stepping, don't emulate any more instructions.
	 */
	if (lwp->lwp_pcb.pcb_step != STEP_NONE)
		return (ftt);
again:
	/*
	 * now read next instruction and see if it can be emulated
	 */
	pinst = (fp_inst_type *)pregs->r_pc;
	pfpsd->fp_trapaddr = (caddr_t)pinst; /* bad inst addr in case we trap */
	ftt = _fp_read_inst((uint32_t *)pinst, &(fp.i), pfpsd);
	if (ftt != ftt_none)
		return (ftt);
	if ((fp.inst.hibits == 2) &&		/* fpops */
	    ((fp.inst.op3 == 0x34) || (fp.inst.op3 == 0x35) ||
	    (fp.inst.op3 == 0x37))) {
		ftt = _fp_fpu_simulator(pfpsd, fp.inst, (fsr_type *)&tfsr, gsr);
		/* Do not retry emulated instruction. */
		pfpu->fpu_fsr = tfsr;
		pregs->r_pc = pregs->r_npc;
		pregs->r_npc += 4;
		if (ftt != ftt_none) {
			/*
			 * Simulation generated an exception of some kind,
			 * simulate the fp queue for a signal.
			 */
			pfpu->fpu_q->FQu.fpq.fpq_addr = (uint32_t *)pinst;
			pfpu->fpu_q->FQu.fpq.fpq_instr = fp.i;
			pfpu->fpu_qcnt = 1;
		}
	} else if ((fp.inst.hibits == 2) && (fp.inst.op3 == 0x36)) {
			ftt = vis_fpu_simulator(pfpsd, fp.inst,
			    pregs, prw, pfp);
	} else if (
						/* rd %gsr */
	    ((fp.inst.hibits == 2) && ((fp.inst.op3 & 0x3f) == 0x28) &&
	    (fp.inst.rs1 == 0x13)) ||
						/* wr %gsr */
	    ((fp.inst.hibits == 2) && ((fp.inst.op3 & 0x3f) == 0x30) &&
	    (fp.inst.rd == 0x13)) ||
						/* movcc */
	    ((fp.inst.hibits == 2) && ((fp.inst.op3 & 0x3f) == 0x2c) &&
	    (((fp.i>>18) & 0x1) == 0)) ||
						/* fbpcc */
	    ((fp.inst.hibits == 0) && (((fp.i>>22) & 0x7) == 5)) ||
						/* fldst */
	    ((fp.inst.hibits == 3) && ((fp.inst.op3 & 0x38) == 0x20)) ||
						/* fbcc */
	    ((fp.inst.hibits == 0) && (((fp.i>>22) & 0x7) == 6))) {
		ftt = _fp_iu_simulator(pfpsd, fp.inst, pregs, prw, pfpu);
	} else
		return (ftt);

	if (ftt != ftt_none)
		return (ftt);
	else
		goto again;
}

/*
 * FPU simulator global kstat data
 */
struct fpustat_kstat fpustat = {
	{ "fpu_ieee_traps",		KSTAT_DATA_UINT64 },
	{ "fpu_unfinished_traps",	KSTAT_DATA_UINT64 },
	{ "fpu_unimplemented",		KSTAT_DATA_UINT64 },
};

kstat_t *fpu_kstat = NULL;
kstat_t *fpuinfo_kstat = NULL;
kstat_t *visinfo_kstat = NULL;

void
fp_kstat_init(void)
{
	const uint_t fpustat_ndata = sizeof (fpustat) / sizeof (kstat_named_t);
	const uint_t fpuinfo_ndata = sizeof (fpuinfo) / sizeof (kstat_named_t);
	const uint_t visinfo_ndata = sizeof (visinfo) /sizeof (kstat_named_t);

	ASSERT(fpu_kstat == NULL);
	if ((fpu_kstat = kstat_create("unix", 0, "fpu_traps", "misc",
	    KSTAT_TYPE_NAMED, fpustat_ndata, KSTAT_FLAG_VIRTUAL)) == NULL) {
		cmn_err(CE_WARN, "CPU%d: kstat_create for fpu_traps failed",
		    CPU->cpu_id);
	} else {
		fpu_kstat->ks_data = (void *)&fpustat;
		kstat_install(fpu_kstat);
	}

	ASSERT(fpuinfo_kstat == NULL);
	if ((fpuinfo_kstat = kstat_create("unix", 0, "fpu_info", "misc",
	    KSTAT_TYPE_NAMED, fpuinfo_ndata, KSTAT_FLAG_VIRTUAL)) == NULL) {
		cmn_err(CE_WARN, "CPU%d: kstat_create for fpu_info failed",
		    CPU->cpu_id);
	} else {
		fpuinfo_kstat->ks_data = (void *)&fpuinfo;
		kstat_install(fpuinfo_kstat);
	}
	ASSERT(visinfo_kstat == NULL);
	if ((visinfo_kstat = kstat_create("unix", 0, "vis_info", "misc",
	    KSTAT_TYPE_NAMED, visinfo_ndata, KSTAT_FLAG_VIRTUAL)) == NULL) {
		cmn_err(CE_WARN, "CPU%d: kstat_create for vis_info failed",
		    CPU->cpu_id);
	} else {
		visinfo_kstat->ks_data = (void *)&visinfo;
		kstat_install(visinfo_kstat);
	}
}

void
fp_kstat_update(enum ftt_type ftt)
{
	ASSERT((ftt == ftt_ieee) || (ftt == ftt_unfinished) ||
	    (ftt == ftt_unimplemented));
	if (ftt == ftt_ieee)
		atomic_inc_64(&fpustat.fpu_ieee_traps.value.ui64);
	else if (ftt == ftt_unfinished)
		atomic_inc_64(&fpustat.fpu_unfinished_traps.value.ui64);
	else if (ftt == ftt_unimplemented)
		atomic_inc_64(&fpustat.fpu_unimplemented_traps.value.ui64);
}
