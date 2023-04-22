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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2019 Doma Gergő Mihály <doma.gergo.mihaly@gmail.com>
 * Copyright 2023 Oxide Computer Company
 */

/*
 * User Process Target Intel 64-bit component
 *
 * This file provides the ISA-dependent portion of the user process target.
 * For more details on the implementation refer to mdb_proc.c.
 */

#include <mdb/mdb_proc.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_amd64util.h>
#include <mdb/proc_x86util.h>
#include <mdb/mdb.h>

#include <sys/ucontext.h>
#include <sys/frame.h>
#include <libproc.h>
#include <sys/fp.h>
#include <ieeefp.h>
#include <sys/sysmacros.h>

#include <stddef.h>

const mdb_tgt_regdesc_t pt_regdesc[] = {
	{ "r15",	REG_R15,	MDB_TGT_R_EXPORT },
	{ "r15d",	REG_R15,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r15w",	REG_R15,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r15l",	REG_R15,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r14",	REG_R14,	MDB_TGT_R_EXPORT },
	{ "r14d",	REG_R14,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r14w",	REG_R14,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r14l",	REG_R14,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r13",	REG_R13,	MDB_TGT_R_EXPORT },
	{ "r13d",	REG_R13,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r13w",	REG_R13,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r13l",	REG_R13,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r12",	REG_R12,	MDB_TGT_R_EXPORT },
	{ "r12d",	REG_R12,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r12w",	REG_R12,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r12l",	REG_R12,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r11",	REG_R11,	MDB_TGT_R_EXPORT },
	{ "r11d",	REG_R11,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r11w",	REG_R11,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r11l",	REG_R11,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r10",	REG_R10,	MDB_TGT_R_EXPORT },
	{ "r10d",	REG_R10,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r10w",	REG_R10,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r10l",	REG_R10,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r9",		REG_R9,		MDB_TGT_R_EXPORT },
	{ "r9d",	REG_R9,		MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r9w",	REG_R9,		MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r9l",	REG_R9,		MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r8",		REG_R8,		MDB_TGT_R_EXPORT },
	{ "r8d",	REG_R8,		MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r8w",	REG_R8,		MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r8l",	REG_R8,		MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rdi",	REG_RDI,	MDB_TGT_R_EXPORT },
	{ "edi",	REG_RDI,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "di",		REG_RDI,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dil",	REG_RDI,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rsi",	REG_RSI,	MDB_TGT_R_EXPORT },
	{ "esi",	REG_RSI,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "si",		REG_RSI,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "sil",	REG_RSI,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rbp",	REG_RBP,	MDB_TGT_R_EXPORT },
	{ "ebp",	REG_RBP,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "bp",		REG_RBP,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bpl",	REG_RBP,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rbx",	REG_RBX,	MDB_TGT_R_EXPORT },
	{ "ebx",	REG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "bx",		REG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bh",		REG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "bl",		REG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rdx",	REG_RDX,	MDB_TGT_R_EXPORT },
	{ "edx",	REG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "dx",		REG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dh",		REG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "dl",		REG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rcx",	REG_RCX,	MDB_TGT_R_EXPORT },
	{ "ecx",	REG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "cx",		REG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ch",		REG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "cl",		REG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rax",	REG_RAX,	MDB_TGT_R_EXPORT },
	{ "eax",	REG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "ax",		REG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ah",		REG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "al",		REG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "trapno",	REG_TRAPNO,	MDB_TGT_R_EXPORT },
	{ "err",	REG_ERR,	MDB_TGT_R_EXPORT },
	{ "rip",	REG_RIP,	MDB_TGT_R_EXPORT },
	{ "cs",		REG_CS,		MDB_TGT_R_EXPORT },
	{ "rflags",	REG_RFL,	MDB_TGT_R_EXPORT },
	{ "eflags",	REG_RFL,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "rsp",	REG_RSP,	MDB_TGT_R_EXPORT },
	{ "esp",	REG_RSP,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "sp",		REG_RSP,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "spl",	REG_RSP,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "ss",		REG_SS,		MDB_TGT_R_EXPORT },
	{ "fs",		REG_FS,		MDB_TGT_R_EXPORT },
	{ "gs",		REG_GS,		MDB_TGT_R_EXPORT },
	{ "es",		REG_ES,		MDB_TGT_R_EXPORT },
	{ "ds",		REG_DS,		MDB_TGT_R_EXPORT },
	{ "fsbase",	REG_FSBASE,	MDB_TGT_R_EXPORT },
	{ "gsbase",	REG_GSBASE,	MDB_TGT_R_EXPORT },
	{ NULL, 0, 0 }
};

/*
 * We cannot rely on pr_instr, because if we hit a breakpoint or the user has
 * artifically modified memory, it will no longer be correct.
 */
static uint8_t
pt_read_instr(mdb_tgt_t *t)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	uint8_t ret = 0;

	(void) mdb_tgt_aread(t, MDB_TGT_AS_VIRT_I, &ret, sizeof (ret),
	    psp->pr_reg[REG_RIP]);

	return (ret);
}

/*ARGSUSED*/
int
pt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	prgregset_t grs;
	prgreg_t rflags;
	boolean_t from_ucontext = B_FALSE;

	if (mdb_getopts(argc, argv,
	    'u', MDB_OPT_SETBITS, B_TRUE, &from_ucontext, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (from_ucontext) {
		int off;
		int o0, o1;

		if (!(flags & DCMD_ADDRSPEC)) {
			mdb_warn("-u requires a ucontext_t address\n");
			return (DCMD_ERR);
		}

		o0 = mdb_ctf_offsetof_by_name("ucontext_t", "uc_mcontext");
		o1 = mdb_ctf_offsetof_by_name("mcontext_t", "gregs");
		if (o0 == -1 || o1 == -1) {
			off = offsetof(ucontext_t, uc_mcontext) +
			    offsetof(mcontext_t, gregs);
		} else {
			off = o0 + o1;
		}

		if (mdb_vread(&grs, sizeof (grs), addr + off) != sizeof (grs)) {
			mdb_warn("failed to read from ucontext_t %p", addr);
			return (DCMD_ERR);
		}
		goto print_regs;
	}

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

print_regs:
	rflags = grs[REG_RFL];

	mdb_printf("%%rax = 0x%0?p\t%%r8  = 0x%0?p\n",
	    grs[REG_RAX], grs[REG_R8]);
	mdb_printf("%%rbx = 0x%0?p\t%%r9  = 0x%0?p\n",
	    grs[REG_RBX], grs[REG_R9]);
	mdb_printf("%%rcx = 0x%0?p\t%%r10 = 0x%0?p\n",
	    grs[REG_RCX], grs[REG_R10]);
	mdb_printf("%%rdx = 0x%0?p\t%%r11 = 0x%0?p\n",
	    grs[REG_RDX], grs[REG_R11]);
	mdb_printf("%%rsi = 0x%0?p\t%%r12 = 0x%0?p\n",
	    grs[REG_RSI], grs[REG_R12]);
	mdb_printf("%%rdi = 0x%0?p\t%%r13 = 0x%0?p\n",
	    grs[REG_RDI], grs[REG_R13]);
	mdb_printf("         %?s\t%%r14 = 0x%0?p\n",
	    "", grs[REG_R14]);
	mdb_printf("         %?s\t%%r15 = 0x%0?p\n",
	    "", grs[REG_R15]);

	mdb_printf("\n");

	mdb_printf("%%cs = 0x%04x\t%%fs = 0x%04x\t%%gs = 0x%04x\n",
	    grs[REG_CS], grs[REG_FS], grs[REG_GS]);
	mdb_printf("%%ds = 0x%04x\t%%es = 0x%04x\t%%ss = 0x%04x\n",
	    grs[REG_DS], grs[REG_ES], grs[REG_SS]);

	mdb_printf("\n");

	mdb_printf("%%rip = 0x%0?p %A\n", grs[REG_RIP], grs[REG_RIP]);
	mdb_printf("%%rbp = 0x%0?p\n", grs[REG_RBP], grs[REG_RBP]);
	mdb_printf("%%rsp = 0x%0?p\n", grs[REG_RSP], grs[REG_RSP]);

	mdb_printf("\n");

	mdb_printf("%%rflags = 0x%08x\n", rflags);

	mdb_printf("  id=%u vip=%u vif=%u ac=%u vm=%u rf=%u nt=%u iopl=0x%x\n",
	    (rflags & KREG_EFLAGS_ID_MASK) >> KREG_EFLAGS_ID_SHIFT,
	    (rflags & KREG_EFLAGS_VIP_MASK) >> KREG_EFLAGS_VIP_SHIFT,
	    (rflags & KREG_EFLAGS_VIF_MASK) >> KREG_EFLAGS_VIF_SHIFT,
	    (rflags & KREG_EFLAGS_AC_MASK) >> KREG_EFLAGS_AC_SHIFT,
	    (rflags & KREG_EFLAGS_VM_MASK) >> KREG_EFLAGS_VM_SHIFT,
	    (rflags & KREG_EFLAGS_RF_MASK) >> KREG_EFLAGS_RF_SHIFT,
	    (rflags & KREG_EFLAGS_NT_MASK) >> KREG_EFLAGS_NT_SHIFT,
	    (rflags & KREG_EFLAGS_IOPL_MASK) >> KREG_EFLAGS_IOPL_SHIFT);

	mdb_printf("  status=<%s,%s,%s,%s,%s,%s,%s,%s,%s>\n",
	    (rflags & KREG_EFLAGS_OF_MASK) ? "OF" : "of",
	    (rflags & KREG_EFLAGS_DF_MASK) ? "DF" : "df",
	    (rflags & KREG_EFLAGS_IF_MASK) ? "IF" : "if",
	    (rflags & KREG_EFLAGS_TF_MASK) ? "TF" : "tf",
	    (rflags & KREG_EFLAGS_SF_MASK) ? "SF" : "sf",
	    (rflags & KREG_EFLAGS_ZF_MASK) ? "ZF" : "zf",
	    (rflags & KREG_EFLAGS_AF_MASK) ? "AF" : "af",
	    (rflags & KREG_EFLAGS_PF_MASK) ? "PF" : "pf",
	    (rflags & KREG_EFLAGS_CF_MASK) ? "CF" : "cf");

	mdb_printf("\n");

	mdb_printf("%%gsbase = 0x%0?p\n", grs[REG_GSBASE]);
	mdb_printf("%%fsbase = 0x%0?p\n", grs[REG_FSBASE]);
	mdb_printf("%%trapno = 0x%x\n", grs[REG_TRAPNO]);
	mdb_printf("   %%err = 0x%x\n", grs[REG_ERR]);

	return (set_errno(ENOTSUP));
}

int
pt_fpregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int ret;
	prfpregset_t fprs;
	struct _fpchip_state fps;
	char buf[256];
	uint_t top;
	size_t i;

	/*
	 * Union for overlaying _fpreg structure on to quad-precision
	 * floating-point value (long double).
	 */
	union {
		struct _fpreg reg;
		long double ld;
	} fpru;

	/*
	 * We use common code between 32-bit and 64-bit x86 to capture and print
	 * the extended vector state. The remaining classic 387 state is
	 * finicky and different enough that it is left to be dealt with on its
	 * own.
	 */
	if ((ret = x86_pt_fpregs_common(addr, flags, argc, &fprs)) != DCMD_OK)
		return (ret);

	bcopy(&fprs.fp_reg_set.fpchip_state, &fps, sizeof (fps));
	mdb_printf("387 and FP Control State\n");

	fps.status &= 0xffff;	/* saved status word is really 16 bits */

	mdb_printf("cw     0x%04x (%s)\n", fps.cw,
	    fpcw2str(fps.cw, buf, sizeof (buf)));

	top = (fps.sw & FPS_TOP) >> 11;
	mdb_printf("sw     0x%04x (TOP=0t%u) (%s)\n", fps.sw,
	    top, fpsw2str(fps.sw, buf, sizeof (buf)));

	mdb_printf("xcp sw 0x%04x (%s)\n\n", fps.status,
	    fpsw2str(fps.status, buf, sizeof (buf)));

	mdb_printf("fop    0x%x\n", fps.fop);
	mdb_printf("rip    0x%x\n", fps.rip);
	mdb_printf("rdp    0x%x\n\n", fps.rdp);

	for (i = 0; i < ARRAY_SIZE(fps.st); i++) {
		/*
		 * Recall that we need to use the current TOP-of-stack value to
		 * associate the _st[] index back to a physical register number,
		 * since tag word indices are physical register numbers.  Then
		 * to get the tag value, we shift over two bits for each tag
		 * index, and then grab the bottom two bits.
		 */
		uint_t tag_index = (i + top) & 7;
		uint_t tag_fctw = (fps.fctw >> tag_index) & 1;
		uint_t tag_value;
		uint_t exp;

		/*
		 * AMD64 stores the tag in a compressed form. It is
		 * necessary to extract the original 2-bit tag value.
		 * See AMD64 Architecture Programmer's Manual Volume 2:
		 * System Programming, Chapter 11.
		 */

		fpru.ld = fps.st[i].__fpr_pad._q;
		exp = fpru.reg.exponent & 0x7fff;

		if (tag_fctw == 0) {
			tag_value = 3; /* empty */
		} else if (exp == 0) {
			if (fpru.reg.significand[0] == 0 &&
			    fpru.reg.significand[1] == 0 &&
			    fpru.reg.significand[2] == 0 &&
			    fpru.reg.significand[3] == 0)
				tag_value = 1; /* zero */
			else
				tag_value = 2; /* special: denormal */
		} else if (exp == 0x7fff) {
			tag_value = 2; /* special: infinity or NaN */
		} else if (fpru.reg.significand[3] & 0x8000) {
			tag_value = 0; /* valid */
		} else {
			tag_value = 2; /* special: unnormal */
		}

		mdb_printf("%%st%d   0x%04x.%04x%04x%04x%04x = %lg %s\n",
		    i, fpru.reg.exponent,
		    fpru.reg.significand[3], fpru.reg.significand[2],
		    fpru.reg.significand[1], fpru.reg.significand[0],
		    fpru.ld, fptag2str(tag_value));
	}

	x86_pt_fpregs_sse_ctl(fps.mxcsr, fps.xstatus, buf, sizeof (buf));

	return (DCMD_OK);
}

/*ARGSUSED*/
int
pt_getfpreg(mdb_tgt_t *t, mdb_tgt_tid_t tid, ushort_t rd_num,
    ushort_t rd_flags, mdb_tgt_reg_t *rp)
{
	return (set_errno(ENOTSUP));
}

/*ARGSUSED*/
int
pt_putfpreg(mdb_tgt_t *t, mdb_tgt_tid_t tid, ushort_t rd_num,
    ushort_t rd_flags, mdb_tgt_reg_t rval)
{
	return (set_errno(ENOTSUP));
}

/*ARGSUSED*/
void
pt_addfpregs(mdb_tgt_t *t)
{
	/* not implemented */
}

/*ARGSUSED*/
int
pt_frameregs(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs, boolean_t pc_faked)
{
	return (set_errno(ENOTSUP));
}

/*ARGSUSED*/
const char *
pt_disasm(const GElf_Ehdr *ehp)
{
	return ("amd64");
}

/*
 * Determine the return address for the current frame.
 */
int
pt_step_out(mdb_tgt_t *t, uintptr_t *p)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;

	if (Pstate(t->t_pshandle) != PS_STOP)
		return (set_errno(EMDB_TGTBUSY));

	return (mdb_amd64_step_out(t, p, psp->pr_reg[REG_RIP],
	    psp->pr_reg[REG_RBP], psp->pr_reg[REG_RSP], psp->pr_instr));
}

/*
 * Return the address of the next instruction following a call, or return -1
 * and set errno to EAGAIN if the target should just single-step.
 */
int
pt_next(mdb_tgt_t *t, uintptr_t *p)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;

	if (Pstate(t->t_pshandle) != PS_STOP)
		return (set_errno(EMDB_TGTBUSY));

	return (mdb_amd64_next(t, p, psp->pr_reg[REG_RIP], pt_read_instr(t)));
}
