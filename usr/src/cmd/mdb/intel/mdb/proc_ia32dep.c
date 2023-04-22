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
 * Copyright 2019 Doma Gergő Mihály <doma.gergo.mihaly@gmail.com>
 * Copyright 2018 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

/*
 * User Process Target Intel 32-bit component
 *
 * This file provides the ISA-dependent portion of the user process target.
 * For more details on the implementation refer to mdb_proc.c.
 */

#include <mdb/mdb_proc.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_ia32util.h>
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
	{ "gs", GS, MDB_TGT_R_EXPORT },
	{ "fs", FS, MDB_TGT_R_EXPORT },
	{ "es", ES, MDB_TGT_R_EXPORT },
	{ "ds", DS, MDB_TGT_R_EXPORT },
	{ "edi", EDI, MDB_TGT_R_EXPORT },
	{ "di",	EDI, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "esi", ESI, MDB_TGT_R_EXPORT },
	{ "si", ESI, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ebp", EBP, MDB_TGT_R_EXPORT },
	{ "bp", EBP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "kesp", ESP, MDB_TGT_R_EXPORT },
	{ "ksp", ESP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ebx", EBX, MDB_TGT_R_EXPORT },
	{ "bx", EBX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bh", EBX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "bl", EBX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "edx", EDX, MDB_TGT_R_EXPORT },
	{ "dx", EDX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dh", EDX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "dl", EDX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "ecx", ECX, MDB_TGT_R_EXPORT },
	{ "cx", ECX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ch", ECX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "cl", ECX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "eax", EAX, MDB_TGT_R_EXPORT },
	{ "ax", EAX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ah", EAX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "al", EAX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "trapno", TRAPNO, MDB_TGT_R_EXPORT },
	{ "err", ERR, MDB_TGT_R_EXPORT },
	{ "eip", EIP, MDB_TGT_R_EXPORT },
	{ "cs", CS, MDB_TGT_R_EXPORT },
	{ "eflags", EFL, MDB_TGT_R_EXPORT },
	{ "esp", UESP, MDB_TGT_R_EXPORT },
	{ "sp", UESP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ss", SS, MDB_TGT_R_EXPORT },
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
	    psp->pr_reg[EIP]);

	return (ret);
}

/*ARGSUSED*/
int
pt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	prgregset_t grs;
	prgreg_t eflags;
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
	eflags = grs[EFL];

	mdb_printf("%%cs = 0x%04x\t\t%%eax = 0x%0?p %A\n",
	    grs[CS], grs[EAX], grs[EAX]);

	mdb_printf("%%ds = 0x%04x\t\t%%ebx = 0x%0?p %A\n",
	    grs[DS], grs[EBX], grs[EBX]);

	mdb_printf("%%ss = 0x%04x\t\t%%ecx = 0x%0?p %A\n",
	    grs[SS], grs[ECX], grs[ECX]);

	mdb_printf("%%es = 0x%04x\t\t%%edx = 0x%0?p %A\n",
	    grs[ES], grs[EDX], grs[EDX]);

	mdb_printf("%%fs = 0x%04x\t\t%%esi = 0x%0?p %A\n",
	    grs[FS], grs[ESI], grs[ESI]);

	mdb_printf("%%gs = 0x%04x\t\t%%edi = 0x%0?p %A\n\n",
	    grs[GS], grs[EDI], grs[EDI]);

	mdb_printf(" %%eip = 0x%0?p %A\n", grs[EIP], grs[EIP]);
	mdb_printf(" %%ebp = 0x%0?p\n", grs[EBP]);
	mdb_printf("%%kesp = 0x%0?p\n\n", grs[ESP]);
	mdb_printf("%%eflags = 0x%08x\n", eflags);

	mdb_printf("  id=%u vip=%u vif=%u ac=%u vm=%u rf=%u nt=%u iopl=0x%x\n",
	    (eflags & KREG_EFLAGS_ID_MASK) >> KREG_EFLAGS_ID_SHIFT,
	    (eflags & KREG_EFLAGS_VIP_MASK) >> KREG_EFLAGS_VIP_SHIFT,
	    (eflags & KREG_EFLAGS_VIF_MASK) >> KREG_EFLAGS_VIF_SHIFT,
	    (eflags & KREG_EFLAGS_AC_MASK) >> KREG_EFLAGS_AC_SHIFT,
	    (eflags & KREG_EFLAGS_VM_MASK) >> KREG_EFLAGS_VM_SHIFT,
	    (eflags & KREG_EFLAGS_RF_MASK) >> KREG_EFLAGS_RF_SHIFT,
	    (eflags & KREG_EFLAGS_NT_MASK) >> KREG_EFLAGS_NT_SHIFT,
	    (eflags & KREG_EFLAGS_IOPL_MASK) >> KREG_EFLAGS_IOPL_SHIFT);

	mdb_printf("  status=<%s,%s,%s,%s,%s,%s,%s,%s,%s>\n\n",
	    (eflags & KREG_EFLAGS_OF_MASK) ? "OF" : "of",
	    (eflags & KREG_EFLAGS_DF_MASK) ? "DF" : "df",
	    (eflags & KREG_EFLAGS_IF_MASK) ? "IF" : "if",
	    (eflags & KREG_EFLAGS_TF_MASK) ? "TF" : "tf",
	    (eflags & KREG_EFLAGS_SF_MASK) ? "SF" : "sf",
	    (eflags & KREG_EFLAGS_ZF_MASK) ? "ZF" : "zf",
	    (eflags & KREG_EFLAGS_AF_MASK) ? "AF" : "af",
	    (eflags & KREG_EFLAGS_PF_MASK) ? "PF" : "pf",
	    (eflags & KREG_EFLAGS_CF_MASK) ? "CF" : "cf");

	mdb_printf("   %%esp = 0x%0?x\n", grs[UESP]);
	mdb_printf("%%trapno = 0x%x\n", grs[TRAPNO]);
	mdb_printf("   %%err = 0x%x\n", grs[ERR]);

	return (DCMD_OK);
}

int
pt_fpregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int ret;
	prfpregset_t fprs;
	struct _fpstate fps;
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

	fps.cw &= 0xffff;	/* control word is really 16 bits */
	fps.sw &= 0xffff;	/* status word is really 16 bits */
	fps.status &= 0xffff;	/* saved status word is really 16 bits */
	fps.cssel &= 0xffff;	/* %cs is really 16-bits */
	fps.datasel &= 0xffff;	/* %ds is really 16-bits too */

	mdb_printf("cw     0x%04x (%s)\n", fps.cw,
	    fpcw2str(fps.cw, buf, sizeof (buf)));

	top = (fps.sw & FPS_TOP) >> 11;
	mdb_printf("sw     0x%04x (TOP=0t%u) (%s)\n", fps.sw,
	    top, fpsw2str(fps.sw, buf, sizeof (buf)));

	mdb_printf("xcp sw 0x%04x (%s)\n\n", fps.status,
	    fpsw2str(fps.status, buf, sizeof (buf)));

	mdb_printf("ipoff  %a\n", fps.ipoff);
	mdb_printf("cssel  0x%x\n", fps.cssel);
	mdb_printf("dtoff  %a\n", fps.dataoff);
	mdb_printf("dtsel  0x%x\n\n", fps.datasel);

	for (i = 0; i < ARRAY_SIZE(fps._st); i++) {
		/*
		 * Recall that we need to use the current TOP-of-stack value to
		 * associate the _st[] index back to a physical register number,
		 * since tag word indices are physical register numbers.  Then
		 * to get the tag value, we shift over two bits for each tag
		 * index, and then grab the bottom two bits.
		 */
		uint_t tag_index = (i + top) & 7;
		uint_t tag_value = (fps.tag >> (tag_index * 2)) & 3;

		fpru.reg = fps._st[i];
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
	return ("ia32");
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

	return (mdb_ia32_step_out(t, p, psp->pr_reg[EIP], psp->pr_reg[EBP],
	    psp->pr_reg[UESP], pt_read_instr(t)));
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

	return (mdb_ia32_next(t, p, psp->pr_reg[EIP], pt_read_instr(t)));
}
