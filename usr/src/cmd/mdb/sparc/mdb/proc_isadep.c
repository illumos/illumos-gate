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

/*
 * User Process Target SPARC v7 and v9 component
 *
 * This file provides the ISA-dependent portion of the user process target
 * for both the sparcv7 and sparcv9 ISAs.  For more details on the
 * implementation refer to mdb_proc.c.
 */

#ifdef __sparcv9
#define	__sparcv9cpu
#endif

#include <mdb/mdb_proc.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb.h>

#include <sys/elf_SPARC.h>
#include <sys/stack.h>
#include <libproc.h>

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

const mdb_tgt_regdesc_t pt_regdesc[] = {
	{ "g0", R_G0, MDB_TGT_R_EXPORT },
	{ "g1", R_G1, MDB_TGT_R_EXPORT },
	{ "g2", R_G2, MDB_TGT_R_EXPORT },
	{ "g3", R_G3, MDB_TGT_R_EXPORT },
	{ "g4", R_G4, MDB_TGT_R_EXPORT },
	{ "g5", R_G5, MDB_TGT_R_EXPORT },
	{ "g6", R_G6, MDB_TGT_R_EXPORT },
	{ "g7", R_G7, MDB_TGT_R_EXPORT },
	{ "o0", R_O0, MDB_TGT_R_EXPORT },
	{ "o1", R_O1, MDB_TGT_R_EXPORT },
	{ "o2", R_O2, MDB_TGT_R_EXPORT },
	{ "o3", R_O3, MDB_TGT_R_EXPORT },
	{ "o4", R_O4, MDB_TGT_R_EXPORT },
	{ "o5", R_O5, MDB_TGT_R_EXPORT },
	{ "o6", R_O6, MDB_TGT_R_EXPORT },
	{ "o7", R_O7, MDB_TGT_R_EXPORT },
	{ "l0", R_L0, MDB_TGT_R_EXPORT },
	{ "l1", R_L1, MDB_TGT_R_EXPORT },
	{ "l2", R_L2, MDB_TGT_R_EXPORT },
	{ "l3", R_L3, MDB_TGT_R_EXPORT },
	{ "l4", R_L4, MDB_TGT_R_EXPORT },
	{ "l5", R_L5, MDB_TGT_R_EXPORT },
	{ "l6", R_L6, MDB_TGT_R_EXPORT },
	{ "l7", R_L7, MDB_TGT_R_EXPORT },
	{ "i0", R_I0, MDB_TGT_R_EXPORT },
	{ "i1", R_I1, MDB_TGT_R_EXPORT },
	{ "i2", R_I2, MDB_TGT_R_EXPORT },
	{ "i3", R_I3, MDB_TGT_R_EXPORT },
	{ "i4", R_I4, MDB_TGT_R_EXPORT },
	{ "i5", R_I5, MDB_TGT_R_EXPORT },
	{ "i6", R_I6, MDB_TGT_R_EXPORT },
	{ "i7", R_I7, MDB_TGT_R_EXPORT },
#ifdef __sparcv9
	{ "ccr", R_CCR, MDB_TGT_R_EXPORT },
#else
	{ "psr", R_PSR, MDB_TGT_R_EXPORT },
#endif
	{ "pc", R_PC, MDB_TGT_R_EXPORT },
	{ "npc", R_nPC, MDB_TGT_R_EXPORT },
	{ "y", R_Y, 0 },
#ifdef __sparcv9
	{ "asi", R_ASI, MDB_TGT_R_EXPORT },
	{ "fprs", R_FPRS, MDB_TGT_R_EXPORT },
#else
	{ "wim", R_WIM, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "tbr", R_TBR, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
#endif
	{ "sp", R_SP, MDB_TGT_R_EXPORT | MDB_TGT_R_ALIAS },
	{ "fp", R_FP, MDB_TGT_R_EXPORT | MDB_TGT_R_ALIAS },
	{ NULL, 0, 0 }
};

#define	FPU_FSR		0	/* fake register number for %fsr */
#define	FPU_FPRS	1	/* fake register number for %fprs */

/*
 * We cannot rely on pr_instr, because if we hit a breakpoint or the user has
 * artifically modified memory, it will no longer be correct.
 */
static uint32_t
pt_read_instr(mdb_tgt_t *t)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	uint32_t ret = 0;

	(void) mdb_tgt_vread(t, &ret, sizeof (ret), psp->pr_reg[R_PC]);

	return (ret);
}

/*ARGSUSED*/
int
pt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	prgregset_t grs;
	uint64_t xgregs[8];
	uint64_t xoregs[8];
	int rwidth, i;

#if defined(__sparc) && defined(_ILP32)
	static const uint32_t zero[8] = { 0 };
	prxregset_t xrs;
#endif

#define	GETREG2(x) ((uintptr_t)grs[(x)]), ((uintptr_t)grs[(x)])

	if (argc != 0)
		return (DCMD_USAGE);

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_UNDEAD) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	if (Pstate(t->t_pshandle) == PS_LOST) {
		mdb_warn("debugger has lost control of process\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC)
		tid = (mdb_tgt_tid_t)addr;
	else
		tid = PTL_TID(t);

	if (PTL_GETREGS(t, tid, grs) != 0) {
		mdb_warn("failed to get current register set");
		return (DCMD_ERR);
	}

	for (i = 0; i < 8; i++) {
		xgregs[i] = (ulong_t)grs[R_G0 + i];
		xoregs[i] = (ulong_t)grs[R_O0 + i];
	}

	if (Pstatus(t->t_pshandle)->pr_dmodel == PR_MODEL_LP64)
		rwidth = 16;
	else
		rwidth = 8;

#if defined(__sparc) && defined(_ILP32)
	/*
	 * If we are debugging a 32-bit SPARC process on an UltraSPARC CPU,
	 * the globals and outs can have 32 upper bits hiding in the xregs.
	 */
	if (PTL_GETXREGS(t, tid, &xrs) == 0 && xrs.pr_type == XR_TYPE_V8P) {
		for (i = 0; i < 8; i++) {
			xgregs[i] |= (uint64_t)
			    xrs.pr_un.pr_v8p.pr_xg[XR_G0 + i] << 32;
			xoregs[i] |= (uint64_t)
			    xrs.pr_un.pr_v8p.pr_xo[XR_O0 + i] << 32;
		}

		if (bcmp(xrs.pr_un.pr_v8p.pr_xg, zero, sizeof (zero)) ||
		    bcmp(xrs.pr_un.pr_v8p.pr_xo, zero, sizeof (zero)))
			rwidth = 16; /* one or more have upper bits set */
	}
#endif	/* __sparc && _ILP32 */

	for (i = 0; i < 8; i++) {
		mdb_printf("%%g%d = 0x%0*llx %15llA %%l%d = 0x%0?p %A\n",
		    i, rwidth, xgregs[i], xgregs[i], i, GETREG2(R_L0 + i));
	}

	for (i = 0; i < 8; i++) {
		mdb_printf("%%o%d = 0x%0*llx %15llA %%i%d = 0x%0?p %A\n",
		    i, rwidth, xoregs[i], xoregs[i], i, GETREG2(R_I0 + i));
	}

	mdb_printf("\n");

#ifdef __sparcv9
	mdb_printf(" %%ccr = 0x%02x xcc=%c%c%c%c icc=%c%c%c%c\n", grs[R_CCR],
	    (grs[R_CCR] & KREG_CCR_XCC_N_MASK) ? 'N' : 'n',
	    (grs[R_CCR] & KREG_CCR_XCC_Z_MASK) ? 'Z' : 'z',
	    (grs[R_CCR] & KREG_CCR_XCC_V_MASK) ? 'V' : 'v',
	    (grs[R_CCR] & KREG_CCR_XCC_C_MASK) ? 'C' : 'c',
	    (grs[R_CCR] & KREG_CCR_ICC_N_MASK) ? 'N' : 'n',
	    (grs[R_CCR] & KREG_CCR_ICC_Z_MASK) ? 'Z' : 'z',
	    (grs[R_CCR] & KREG_CCR_ICC_V_MASK) ? 'V' : 'v',
	    (grs[R_CCR] & KREG_CCR_ICC_C_MASK) ? 'C' : 'c');
#else	/* __sparcv9 */
	mdb_printf(" %%psr = 0x%08x impl=0x%x ver=0x%x icc=%c%c%c%c\n"
	    "                   ec=%u ef=%u pil=%u s=%u ps=%u et=%u cwp=0x%x\n",
	    grs[R_PSR],
	    (grs[R_PSR] & KREG_PSR_IMPL_MASK) >> KREG_PSR_IMPL_SHIFT,
	    (grs[R_PSR] & KREG_PSR_VER_MASK) >> KREG_PSR_VER_SHIFT,
	    (grs[R_PSR] & KREG_PSR_ICC_N_MASK) ? 'N' : 'n',
	    (grs[R_PSR] & KREG_PSR_ICC_Z_MASK) ? 'Z' : 'z',
	    (grs[R_PSR] & KREG_PSR_ICC_V_MASK) ? 'V' : 'v',
	    (grs[R_PSR] & KREG_PSR_ICC_C_MASK) ? 'C' : 'c',
	    grs[R_PSR] & KREG_PSR_EC_MASK, grs[R_PSR] & KREG_PSR_EF_MASK,
	    (grs[R_PSR] & KREG_PSR_PIL_MASK) >> KREG_PSR_PIL_SHIFT,
	    grs[R_PSR] & KREG_PSR_S_MASK, grs[R_PSR] & KREG_PSR_PS_MASK,
	    grs[R_PSR] & KREG_PSR_ET_MASK,
	    (grs[R_PSR] & KREG_PSR_CWP_MASK) >> KREG_PSR_CWP_SHIFT);
#endif	/* __sparcv9 */

	mdb_printf("   %%y = 0x%0?p\n", grs[R_Y]);

	mdb_printf("  %%pc = 0x%0?p %A\n", GETREG2(R_PC));
	mdb_printf(" %%npc = 0x%0?p %A\n", GETREG2(R_nPC));

	mdb_printf("  %%sp = 0x%0?p\n", grs[R_SP]);
	mdb_printf("  %%fp = 0x%0?p\n\n", grs[R_FP]);

#ifdef __sparcv9
	mdb_printf(" %%asi = 0x%02lx\n", grs[R_ASI]);
	mdb_printf("%%fprs = 0x%02lx\n", grs[R_FPRS]);
#else	/* __sparcv9 */
	mdb_printf(" %%wim = 0x%08x\n", grs[R_WIM]);
	mdb_printf(" %%tbr = 0x%08x\n", grs[R_TBR]);
#endif	/* __sparcv9 */

	return (DCMD_OK);
}

/*ARGSUSED*/
int
pt_fpregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	int is_v8plus, is_v9, i;
#ifdef	__sparcv9
	prgregset_t grs;
#endif
	prfpregset_t fprs;
	prxregset_t xrs;
	uint32_t *regs;
	int ns, nd, nq;

	enum {
		FPR_MIXED	= 0x0, /* show single, double, and status */
		FPR_SINGLE	= 0x1, /* show single-precision only */
		FPR_DOUBLE	= 0x2, /* show double-precision only */
		FPR_QUAD	= 0x4  /* show quad-precision only */
	};

	uint_t opts = FPR_MIXED;

	/*
	 * The prfpregset structure only provides us with the FPU in the form
	 * of 32-bit integers, doubles, or quads.  We use this union of the
	 * various types to display floats, doubles, and long doubles.
	 */
	union {
		struct {
			uint32_t i1;
			uint32_t i2;
			uint32_t i3;
			uint32_t i4;
		} ip;
		float f;
		double d;
		long double ld;
	} fpu;

	if (mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, FPR_SINGLE, &opts,
	    'd', MDB_OPT_SETBITS, FPR_DOUBLE, &opts,
	    'q', MDB_OPT_SETBITS, FPR_QUAD, &opts, NULL) != argc)
		return (DCMD_USAGE);

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_UNDEAD) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	if (Pstate(t->t_pshandle) == PS_LOST) {
		mdb_warn("debugger has lost control of process\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC)
		tid = (mdb_tgt_tid_t)addr;
	else
		tid = PTL_TID(t);

	is_v9 = Pstatus(t->t_pshandle)->pr_dmodel == PR_MODEL_LP64;
	is_v8plus = is_v9 == 0 && PTL_GETXREGS(t, tid, &xrs) == 0 &&
	    xrs.pr_type == XR_TYPE_V8P;

#ifdef	__sparcv9
	if (is_v9 && opts == FPR_MIXED) {
		if (PTL_GETREGS(t, tid, grs) == 0)
			mdb_printf("fprs %lx\n", grs[R_FPRS]);
		else
			mdb_warn("failed to read fprs register");
	}
#endif
	if (is_v8plus && opts == FPR_MIXED)
		mdb_printf("fprs %x\n", xrs.pr_un.pr_v8p.pr_fprs);

	if (PTL_GETFPREGS(t, tid, &fprs) != 0) {
		mdb_warn("failed to get floating point registers");
		return (DCMD_ERR);
	}

	if (opts == FPR_MIXED) {
		uint64_t fsr = fprs.pr_fsr;
		if (is_v8plus)
			fsr |= (uint64_t)xrs.pr_un.pr_v8p.pr_xfsr << 32;
		mdb_printf("fsr  %llx\n", fsr);
	}

	/*
	 * Set up the regs pointer to be a pointer to a contiguous chunk of
	 * memory containing all the floating pointer register data.  Set
	 * ns, nd, and nq to indicate the number of registers of each type.
	 */
	if (is_v9) {
		regs = fprs.pr_fr.pr_regs;
		ns = 64;
		nd = 32;
		nq = 16;
	} else if (is_v8plus) {
		regs = mdb_alloc(sizeof (uint32_t) * 64, UM_SLEEP | UM_GC);
		bcopy(fprs.pr_fr.pr_regs, regs, sizeof (uint32_t) * 32);
		bcopy(xrs.pr_un.pr_v8p.pr_xfr.pr_regs, regs + 32,
		    sizeof (uint32_t) * 32);
		ns = 64;
		nd = 32;
		nq = 16;
	} else {
		regs = fprs.pr_fr.pr_regs;
		ns = 32;
		nd = 16;
		nq = 0;
	}

	if (opts == FPR_MIXED) {
		for (i = 0; i < ns; i++) {
			fpu.ip.i1 = regs[i];
			mdb_printf("f%-3d %08x   %e", i, fpu.ip.i1, fpu.f);
			if (i & 1) {
				fpu.ip.i1 = regs[i - 1];
				fpu.ip.i2 = regs[i];
				mdb_printf("   %g", fpu.d);
			}
			mdb_printf("\n");
		}
	}

	if (opts & FPR_SINGLE) {
		for (i = 0; i < ns; i++) {
			fpu.ip.i1 = regs[i];
			mdb_printf("f%-3d %08x   %e\n", i, fpu.ip.i1, fpu.f);
		}
	}

	if (opts & FPR_DOUBLE) {
		for (i = 0; i < nd; i++) {
			fpu.ip.i1 = regs[i * 2 + 0];
			fpu.ip.i2 = regs[i * 2 + 1];
			mdb_printf("f%-3d %08x.%08x   %g\n", i * 2,
			    fpu.ip.i1, fpu.ip.i2, fpu.d);
		}
	}

	if (opts & FPR_QUAD) {
		for (i = 0; i < nq; i++) {
			fpu.ip.i1 = regs[i * 4 + 0];
			fpu.ip.i2 = regs[i * 4 + 1];
			fpu.ip.i3 = regs[i * 4 + 2];
			fpu.ip.i4 = regs[i * 4 + 3];
			mdb_printf("f%-3d %08x.%08x.%08x.%08x   %s\n", i * 4,
			    fpu.ip.i1, fpu.ip.i2, fpu.ip.i3, fpu.ip.i4,
			    longdoubletos(&fpu.ld, 16, 'e'));
		}
	}

	return (DCMD_OK);
}

/*
 * Read a single floating-point register.  If it's a v8 or v9 register, then
 * we get its value from prfpregset_t.  If it's a v8+ register, look in xregs.
 */
int
pt_getfpreg(mdb_tgt_t *t, mdb_tgt_tid_t tid, ushort_t rd_num,
    ushort_t rd_flags, mdb_tgt_reg_t *rp)
{
	mdb_tgt_reg_t rval;
	prfpregset_t fprs;
	prxregset_t xrs;

	if (PTL_GETFPREGS(t, tid, &fprs) != 0)
		return (-1); /* errno is set for us */

	if ((rd_flags & MDB_TGT_R_XREG) && PTL_GETXREGS(t, tid, &xrs) != 0)
		return (-1); /* errno is set for us */

	if (rd_flags & MDB_TGT_R_FPU) {
		switch (rd_num) {
		case FPU_FSR:
			rval = fprs.pr_fsr;
			if (rd_flags & MDB_TGT_R_XREG)
				rval |= (uint64_t)
				    xrs.pr_un.pr_v8p.pr_xfsr << 32;
			break;
		case FPU_FPRS:
			if (rd_flags & MDB_TGT_R_XREG)
				rval = xrs.pr_un.pr_v8p.pr_fprs;
			break;
		}

	} else if (rd_flags & MDB_TGT_R_FPS) {
		if (rd_flags & MDB_TGT_R_XREG)
			rval = xrs.pr_un.pr_v8p.pr_xfr.pr_regs[rd_num - 32];
		else
			rval = fprs.pr_fr.pr_regs[rd_num];

	} else if (rd_flags & MDB_TGT_R_FPD) {
		if (rd_flags & MDB_TGT_R_XREG)
			rval = ((uint64_t *)
			    xrs.pr_un.pr_v8p.pr_xfr.pr_dregs)[rd_num - 16];
		else
			rval = ((uint64_t *)fprs.pr_fr.pr_dregs)[rd_num];
	}

	*rp = rval;
	return (0);
}

/*
 * Write a single floating-point register.  If it's a v8 or v9 register, then
 * we set its value in prfpregset_t.  If it's a v8+ register, modify the xregs.
 */
int
pt_putfpreg(mdb_tgt_t *t, mdb_tgt_tid_t tid, ushort_t rd_num,
    ushort_t rd_flags, mdb_tgt_reg_t rval)
{
	prfpregset_t fprs;
	prxregset_t xrs;

	if (PTL_GETFPREGS(t, tid, &fprs) != 0)
		return (-1); /* errno is set for us */

	if ((rd_flags & MDB_TGT_R_XREG) && PTL_GETXREGS(t, tid, &xrs) != 0)
		return (-1); /* errno is set for us */

	if (rd_flags & MDB_TGT_R_FPU) {
		switch (rd_num) {
		case FPU_FSR:
			fprs.pr_fsr = (uint32_t)rval;
			if (rd_flags & MDB_TGT_R_XREG)
				xrs.pr_un.pr_v8p.pr_xfsr = rval >> 32;
			break;
		case FPU_FPRS:
			if (rd_flags & MDB_TGT_R_XREG)
				xrs.pr_un.pr_v8p.pr_fprs = rval;
			break;
		}

	} else if (rd_flags & MDB_TGT_R_FPS) {
		if (rd_flags & MDB_TGT_R_XREG)
			xrs.pr_un.pr_v8p.pr_xfr.pr_regs[rd_num - 32] = rval;
		else
			fprs.pr_fr.pr_regs[rd_num] = rval;

	} else if (rd_flags & MDB_TGT_R_FPD) {
		if (rd_flags & MDB_TGT_R_XREG)
			((uint64_t *)xrs.pr_un.pr_v8p.pr_xfr.pr_dregs)
			    [rd_num - 16] = rval;
		else
			((uint64_t *)fprs.pr_fr.pr_dregs)[rd_num] = rval;
	}

	if (PTL_SETFPREGS(t, tid, &fprs) != 0)
		return (-1); /* errno is set for us */

	if ((rd_flags & MDB_TGT_R_XREG) && PTL_SETXREGS(t, tid, &xrs) != 0)
		return (-1); /* errno is set for us */

	return (0);
}

/*
 * Utility function for inserting a floating-point register description into
 * the p_regs hash table of register descriptions.
 */
static void
pt_addfpreg(mdb_nv_t *nvp, uint_t rnum, uint_t rnam, char pref, ushort_t flags)
{
	uintmax_t nval = MDB_TGT_R_NVAL(rnum, flags | MDB_TGT_R_EXPORT);
	char name[8]; /* enough for "[fdq][0-9][0-9]\0" */

	(void) mdb_iob_snprintf(name, sizeof (name), "%c%u", pref, rnam);
	(void) mdb_nv_insert(nvp, name, NULL, nval, MDB_NV_RDONLY);
}

/*
 * Determine the ISA of the target and then insert the appropriate register
 * description entries into p_regs.  If the target is v8plus or v9, add the
 * entire v9 floating-point model; otherwise just add the v8 registers.
 */
void
pt_addfpregs(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;
	struct ps_prochandle *P = t->t_pshandle;
	prxregset_t xrs;
	uint_t i;

	uint_t fpuflag = MDB_TGT_R_FPU | MDB_TGT_R_EXPORT;
	uint_t e_mach = pt->p_file ? pt->p_file->gf_ehdr.e_machine : EM_NONE;
	uint_t model = P ? Pstatus(P)->pr_dmodel : PR_MODEL_UNKNOWN;

	/*
	 * If the ELF file is SPARCv9 or the process or core is 64-bit, then
	 * add the SPARCv9 floating-point descriptions.  Otherwise use v7/v8.
	 */
	if (e_mach == EM_SPARCV9 || model == PR_MODEL_LP64) {
		for (i = 0; i < 64; i++)
			pt_addfpreg(&pt->p_regs, i, i, 'f', MDB_TGT_R_FPS);
		for (i = 0; i < 32; i++)
			pt_addfpreg(&pt->p_regs, i, i * 2, 'd', MDB_TGT_R_FPD);
	} else {
		for (i = 0; i < 32; i++)
			pt_addfpreg(&pt->p_regs, i, i, 'f', MDB_TGT_R_FPS);
		for (i = 0; i < 16; i++)
			pt_addfpreg(&pt->p_regs, i, i * 2, 'd', MDB_TGT_R_FPD);
	}

	/*
	 * If the ELF file is SPARCv8+ or the process or core has v8+ xregs,
	 * then include the additional v8plus register descriptions.
	 */
	if (e_mach == EM_SPARC32PLUS || (P != NULL && PTL_GETXREGS(t,
	    PTL_TID(t), &xrs) == 0 && xrs.pr_type == XR_TYPE_V8P)) {

		for (i = 32; i < 64; i++) {
			pt_addfpreg(&pt->p_regs, i, i, 'f',
			    MDB_TGT_R_FPS | MDB_TGT_R_XREG);
		}

		for (i = 16; i < 32; i++) {
			pt_addfpreg(&pt->p_regs, i, i * 2, 'd',
			    MDB_TGT_R_FPD | MDB_TGT_R_XREG);
		}

		fpuflag |= MDB_TGT_R_XREG; /* fpu status regs are in xregs */

		(void) mdb_nv_insert(&pt->p_regs, "fsr", NULL,
		    MDB_TGT_R_NVAL(FPU_FSR, fpuflag), MDB_NV_RDONLY);

		(void) mdb_nv_insert(&pt->p_regs, "fprs", NULL,
		    MDB_TGT_R_NVAL(FPU_FPRS, fpuflag), MDB_NV_RDONLY);

	} else {
		(void) mdb_nv_insert(&pt->p_regs, "fsr", NULL,
		    MDB_TGT_R_NVAL(FPU_FSR, fpuflag), MDB_NV_RDONLY);
	}
}

int
pt_frameregs(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs, boolean_t pc_faked)
{
	char buf[BUFSIZ];
	const prgreg_t *pregs = &gregs->gregs[0];

	argc = MIN(argc, (uint_t)(uintptr_t)arglim);

	if (pc_faked)
		mdb_printf("%<b>%0?lr %s%</b>(", pregs[R_SP], "?");
	else
		mdb_printf("%<b>%0?lr %a%</b>(", pregs[R_SP], pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");

	(void) mdb_inc_indent(2);

	mdb_printf("%%l0-%%l3: %?lr %?lr %?lr %?lr\n",
	    pregs[R_L0], pregs[R_L1], pregs[R_L2], pregs[R_L3]);

	mdb_printf("%%l4-%%l7: %?lr %?lr %?lr %?lr\n",
	    pregs[R_L4], pregs[R_L5], pregs[R_L6], pregs[R_L7]);

	if (pregs[R_FP] != 0 && (pregs[R_FP] + STACK_BIAS) != 0)
		if (mdb_dis_ins2str(mdb.m_disasm, mdb.m_target, MDB_TGT_AS_VIRT,
		    buf, sizeof (buf), pregs[R_I7]) != pregs[R_I7])
			mdb_printf("%-#25a%s\n", pregs[R_I7], buf);

	(void) mdb_dec_indent(2);
	mdb_printf("\n");

	return (0);
}

const char *
pt_disasm(const GElf_Ehdr *ehp)
{
#ifdef __sparcv9
	const char *disname = "v9plus";
#else
	const char *disname = "v8";
#endif
	/*
	 * If e_machine is SPARC32+, the program has been compiled v8plus or
	 * v8plusa and we need to allow v9 and potentially VIS opcodes.
	 */
	if (ehp != NULL && ehp->e_machine == EM_SPARC32PLUS) {
		if (ehp->e_flags & (EF_SPARC_SUN_US1 | EF_SPARC_SUN_US3))
			disname = "v9plus";
		else
			disname = "v9";
	}

	return (disname);
}

/*
 * Macros and #defines for extracting and interpreting SPARC instruction set,
 * used in pt_step_out() and pt_next() below.
 */
#define	OP(machcode)	((machcode) >> 30)
#define	OP2(machcode)	(((machcode) >> 22) & 0x07)
#define	OP3(machcode)	(((machcode) >> 19) & 0x3f)
#define	RD(machcode)	(((machcode) >> 25) & 0x1f)
#define	RS1(machcode)	(((machcode) >> 14) & 0x1f)
#define	RS2(machcode)	((machcode) & 0x1f)

#define	OP_BRANCH	0x0
#define	OP_ARITH	0x2

#define	OP2_ILLTRAP	0x0

#define	OP3_OR		0x02
#define	OP3_SAVE	0x3c
#define	OP3_RESTORE	0x3d

/*
 * If we are stopped on a save instruction or at the first instruction of a
 * known function, return %o7 as the step-out address; otherwise return the
 * current frame's return address (%i7).  Significantly better handling of
 * step out in leaf routines could be accomplished by implementing more
 * complex decoding of the current function and our current state.
 */
int
pt_step_out(mdb_tgt_t *t, uintptr_t *p)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	uintptr_t pc = psp->pr_reg[R_PC];
	uint32_t instr;

	char buf[1];
	GElf_Sym s;

	if (Pstate(t->t_pshandle) != PS_STOP)
		return (set_errno(EMDB_TGTBUSY));

	instr = pt_read_instr(t);

	if (mdb_tgt_lookup_by_addr(t, pc, MDB_TGT_SYM_FUZZY,
	    buf, sizeof (buf), &s, NULL) == 0 && s.st_value == pc)
		*p = psp->pr_reg[R_O7] + 2 * sizeof (instr_t);
	else if (OP(instr) == OP_ARITH &&
	    OP3(instr) == OP3_SAVE)
		*p = psp->pr_reg[R_O7] + 2 * sizeof (instr_t);
	else
		*p = psp->pr_reg[R_I7] + 2 * sizeof (instr_t);

	return (0);
}

/*
 * Step over call and jmpl by returning the address of the position where a
 * temporary breakpoint can be set to catch return from the control transfer.
 * This function does not currently provide advancing decoding of DCTI
 * couples or any other complex special case; we just fall back to single-step.
 */
int
pt_next(mdb_tgt_t *t, uintptr_t *p)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	uintptr_t pc;
	uintptr_t npc;
	GElf_Sym func;
	char name[1];
	instr_t instr;

	if (Pstate(t->t_pshandle) != PS_STOP)
		return (set_errno(EMDB_TGTBUSY));

	pc = psp->pr_reg[R_PC];
	npc = psp->pr_reg[R_nPC];
	instr = pt_read_instr(t);

	if (mdb_tgt_lookup_by_addr(t, pc, MDB_TGT_SYM_FUZZY,
	    name, sizeof (name), &func, NULL) != 0)
		return (-1);

	if (npc < func.st_value || func.st_value + func.st_size <= npc) {
		uint_t reg;

		/*
		 * We're about to transfer control outside this function,
		 * so we want to stop when control returns from the other
		 * function. Normally the return address will be in %o7,
		 * tail-calls being the exception. We try to discover
		 * if this is a tail-call and compute the return address
		 * in that case.
		 */
		if (OP(instr) == OP_ARITH &&
		    OP3(instr) == OP3_RESTORE) {
			reg = R_I7;

		} else if (OP(instr) == OP_ARITH &&
		    OP3(instr) == OP3_OR &&
		    RD(instr) == R_O7) {

			if (RS1(instr) != R_G0)
				return (set_errno(EAGAIN));
			reg = RS2(instr);

		} else {
			reg = R_O7;
		}

		*p = psp->pr_reg[reg] + 2 * sizeof (instr_t);

		/*
		 * If a function returns a structure, the caller may place
		 * an illtrap whose const22 field represents the size of
		 * the structure immediately after the delay slot of the
		 * call (or jmpl) instruction. To handle this case, we
		 * check the instruction that we think we're going to
		 * return to, and advance past it if it's an illtrap
		 * instruction. Note that this applies to SPARC v7 and v8,
		 * but not v9.
		 */
		if (mdb_tgt_vread(t, &instr, sizeof (instr_t), *p) ==
		    sizeof (instr_t) &&
		    OP(instr) == OP_BRANCH && OP2(instr) == OP2_ILLTRAP)
			*p += sizeof (instr_t);

		return (0);
	}

	return (set_errno(EAGAIN));
}
