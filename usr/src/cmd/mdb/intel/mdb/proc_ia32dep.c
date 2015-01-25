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
 * Copyright 2015 Joyent, Inc.
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
#include <mdb/mdb_ia32util.h>
#include <mdb/mdb.h>

#include <sys/ucontext.h>
#include <sys/frame.h>
#include <libproc.h>
#include <sys/fp.h>
#include <ieeefp.h>

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

	(void) mdb_tgt_vread(t, &ret, sizeof (ret), psp->pr_reg[EIP]);

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

static const char *
fpcw2str(uint32_t cw, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	/*
	 * Decode all masks in the 80387 control word.
	 */
	if (cw & FPIM)
		p += mdb_snprintf(p, (size_t)(end - p), "|IM");
	if (cw & FPDM)
		p += mdb_snprintf(p, (size_t)(end - p), "|DM");
	if (cw & FPZM)
		p += mdb_snprintf(p, (size_t)(end - p), "|ZM");
	if (cw & FPOM)
		p += mdb_snprintf(p, (size_t)(end - p), "|OM");
	if (cw & FPUM)
		p += mdb_snprintf(p, (size_t)(end - p), "|UM");
	if (cw & FPPM)
		p += mdb_snprintf(p, (size_t)(end - p), "|PM");
	if (cw & FPPC)
		p += mdb_snprintf(p, (size_t)(end - p), "|PC");
	if (cw & FPRC)
		p += mdb_snprintf(p, (size_t)(end - p), "|RC");
	if (cw & FPIC)
		p += mdb_snprintf(p, (size_t)(end - p), "|IC");

	/*
	 * Decode precision, rounding, and infinity options in control word.
	 */
	if (cw & FPSIG24)
		p += mdb_snprintf(p, (size_t)(end - p), "|SIG24");
	if (cw & FPSIG53)
		p += mdb_snprintf(p, (size_t)(end - p), "|SIG53");
	if (cw & FPSIG64)
		p += mdb_snprintf(p, (size_t)(end - p), "|SIG64");

	if ((cw & FPRC) == (FPRD|FPRU))
		p += mdb_snprintf(p, (size_t)(end - p), "|RTZ");
	else if (cw & FPRD)
		p += mdb_snprintf(p, (size_t)(end - p), "|RD");
	else if (cw & FPRU)
		p += mdb_snprintf(p, (size_t)(end - p), "|RU");
	else
		p += mdb_snprintf(p, (size_t)(end - p), "|RTN");

	if (cw & FPA)
		p += mdb_snprintf(p, (size_t)(end - p), "|A");
	else
		p += mdb_snprintf(p, (size_t)(end - p), "|P");
	if (cw & WFPB17)
		p += mdb_snprintf(p, (size_t)(end - p), "|WFPB17");
	if (cw & WFPB24)
		p += mdb_snprintf(p, (size_t)(end - p), "|WFPB24");

	if (buf[0] == '|')
		return (buf + 1);

	return ("0");
}

static const char *
fpsw2str(uint32_t cw, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	/*
	 * Decode all masks in the 80387 status word.
	 */
	if (cw & FPS_IE)
		p += mdb_snprintf(p, (size_t)(end - p), "|IE");
	if (cw & FPS_DE)
		p += mdb_snprintf(p, (size_t)(end - p), "|DE");
	if (cw & FPS_ZE)
		p += mdb_snprintf(p, (size_t)(end - p), "|ZE");
	if (cw & FPS_OE)
		p += mdb_snprintf(p, (size_t)(end - p), "|OE");
	if (cw & FPS_UE)
		p += mdb_snprintf(p, (size_t)(end - p), "|UE");
	if (cw & FPS_PE)
		p += mdb_snprintf(p, (size_t)(end - p), "|PE");
	if (cw & FPS_SF)
		p += mdb_snprintf(p, (size_t)(end - p), "|SF");
	if (cw & FPS_ES)
		p += mdb_snprintf(p, (size_t)(end - p), "|ES");
	if (cw & FPS_C0)
		p += mdb_snprintf(p, (size_t)(end - p), "|C0");
	if (cw & FPS_C1)
		p += mdb_snprintf(p, (size_t)(end - p), "|C1");
	if (cw & FPS_C2)
		p += mdb_snprintf(p, (size_t)(end - p), "|C2");
	if (cw & FPS_C3)
		p += mdb_snprintf(p, (size_t)(end - p), "|C3");
	if (cw & FPS_B)
		p += mdb_snprintf(p, (size_t)(end - p), "|B");

	if (buf[0] == '|')
		return (buf + 1);

	return ("0");
}

static const char *
fpmxcsr2str(uint32_t mxcsr, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	/*
	 * Decode the MXCSR word
	 */
	if (mxcsr & SSE_IE)
		p += mdb_snprintf(p, (size_t)(end - p), "|IE");
	if (mxcsr & SSE_DE)
		p += mdb_snprintf(p, (size_t)(end - p), "|DE");
	if (mxcsr & SSE_ZE)
		p += mdb_snprintf(p, (size_t)(end - p), "|ZE");
	if (mxcsr & SSE_OE)
		p += mdb_snprintf(p, (size_t)(end - p), "|OE");
	if (mxcsr & SSE_UE)
		p += mdb_snprintf(p, (size_t)(end - p), "|UE");
	if (mxcsr & SSE_PE)
		p += mdb_snprintf(p, (size_t)(end - p), "|PE");

	if (mxcsr & SSE_DAZ)
		p += mdb_snprintf(p, (size_t)(end - p), "|DAZ");

	if (mxcsr & SSE_IM)
		p += mdb_snprintf(p, (size_t)(end - p), "|IM");
	if (mxcsr & SSE_DM)
		p += mdb_snprintf(p, (size_t)(end - p), "|DM");
	if (mxcsr & SSE_ZM)
		p += mdb_snprintf(p, (size_t)(end - p), "|ZM");
	if (mxcsr & SSE_OM)
		p += mdb_snprintf(p, (size_t)(end - p), "|OM");
	if (mxcsr & SSE_UM)
		p += mdb_snprintf(p, (size_t)(end - p), "|UM");
	if (mxcsr & SSE_PM)
		p += mdb_snprintf(p, (size_t)(end - p), "|PM");

	if ((mxcsr & SSE_RC) == (SSE_RD|SSE_RU))
		p += mdb_snprintf(p, (size_t)(end - p), "|RTZ");
	else if (mxcsr & SSE_RD)
		p += mdb_snprintf(p, (size_t)(end - p), "|RD");
	else if (mxcsr & SSE_RU)
		p += mdb_snprintf(p, (size_t)(end - p), "|RU");
	else
		p += mdb_snprintf(p, (size_t)(end - p), "|RTN");

	if (mxcsr & SSE_FZ)
		p += mdb_snprintf(p, (size_t)(end - p), "|FZ");

	if (buf[0] == '|')
		return (buf + 1);
	return ("0");
}

/*ARGSUSED*/
int
pt_fpregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	uint32_t hw = FP_NO;
	uint_t sse = 0;
	prfpregset_t fprs;
	struct _fpstate fps;
	char buf[256];
	uint_t top;
	int i;

	/*
	 * Union for overlaying _fpreg structure on to quad-precision
	 * floating-point value (long double).
	 */
	union {
		struct _fpreg reg;
		long double ld;
	} fpru;

	/*
	 * Array of strings corresponding to FPU tag word values (see
	 * section 7.3.6 of the Intel Programmer's Reference Manual).
	 */
	const char *tag_strings[] = { "valid", "zero", "special", "empty" };

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

	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &hw,
	    sizeof (hw), "libc.so", "_fp_hw") < 0 &&
	    mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &hw,
	    sizeof (hw), MDB_TGT_OBJ_EXEC, "_fp_hw") < 0)
		mdb_warn("failed to read _fp_hw value");

	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &sse,
	    sizeof (sse), "libc.so", "_sse_hw") < 0 &&
	    mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &sse,
	    sizeof (sse), MDB_TGT_OBJ_EXEC, "_sse_hw") < 0)
		mdb_warn("failed to read _sse_hw value");

	mdb_printf("_fp_hw 0x%02x (", hw);
	switch (hw) {
	case FP_SW:
		mdb_printf("80387 software emulator");
		break;
	case FP_287:
		mdb_printf("80287 chip");
		break;
	case FP_387:
		mdb_printf("80387 chip");
		break;
	case FP_486:
		mdb_printf("80486 chip");
		break;
	default:
		mdb_printf("no floating point support");
		break;
	}
	if (sse)
		mdb_printf(" with SSE");
	mdb_printf(")\n");

	if (!(hw & FP_HW))
		return (DCMD_OK); /* just abort if no hardware present */

	if (PTL_GETFPREGS(t, tid, &fprs) != 0) {
		mdb_warn("failed to get floating point registers");
		return (DCMD_ERR);
	}

	bcopy(&fprs.fp_reg_set.fpchip_state, &fps, sizeof (fps));

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

	for (i = 0; i < 8; i++) {
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
		    fpru.ld, tag_strings[tag_value]);
	}

	if (!sse)
		return (DCMD_OK);

	mdb_printf("\nmxcsr  0x%04x (%s)\n", fps.mxcsr,
	    fpmxcsr2str(fps.mxcsr, buf, sizeof (buf)));
	mdb_printf("xcp    0x%04x (%s)\n\n", fps.xstatus,
	    fpmxcsr2str(fps.xstatus, buf, sizeof (buf)));

	for (i = 0; i < 8; i++)
		mdb_printf("%%xmm%d  0x%08x%08x%08x%08x\n", i,
		    fps.xmm[i][3], fps.xmm[i][2],
		    fps.xmm[i][1], fps.xmm[i][0]);

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
