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

#include <sys/types.h>
#include <sys/reg.h>
#include <sys/privregs.h>
#include <sys/stack.h>
#include <sys/frame.h>

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_amd64util.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

/*
 * This array is used by the getareg and putareg entry points, and also by our
 * register variable discipline.
 */

const mdb_tgt_regdesc_t mdb_amd64_kregs[] = {
	{ "savfp", KREG_SAVFP, MDB_TGT_R_EXPORT },
	{ "savpc", KREG_SAVPC, MDB_TGT_R_EXPORT },
	{ "rdi", KREG_RDI, MDB_TGT_R_EXPORT },
	{ "rsi", KREG_RSI, MDB_TGT_R_EXPORT },
	{ "rdx", KREG_RDX, MDB_TGT_R_EXPORT },
	{ "rcx", KREG_RCX, MDB_TGT_R_EXPORT },
	{ "r8", KREG_R8, MDB_TGT_R_EXPORT },
	{ "r9", KREG_R9, MDB_TGT_R_EXPORT },
	{ "rax", KREG_RAX, MDB_TGT_R_EXPORT },
	{ "rbx", KREG_RBX, MDB_TGT_R_EXPORT },
	{ "rbp", KREG_RBP, MDB_TGT_R_EXPORT },
	{ "r10", KREG_R10, MDB_TGT_R_EXPORT },
	{ "r11", KREG_R11, MDB_TGT_R_EXPORT },
	{ "r12", KREG_R12, MDB_TGT_R_EXPORT },
	{ "r13", KREG_R13, MDB_TGT_R_EXPORT },
	{ "r14", KREG_R14, MDB_TGT_R_EXPORT },
	{ "r15", KREG_R15, MDB_TGT_R_EXPORT },
	{ "fsbase", KREG_FSBASE, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "gsbase", KREG_GSBASE, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "kgsbase", KREG_KGSBASE, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "ds", KREG_DS, MDB_TGT_R_EXPORT },
	{ "es", KREG_ES, MDB_TGT_R_EXPORT },
	{ "fs", KREG_FS, MDB_TGT_R_EXPORT },
	{ "gs", KREG_GS, MDB_TGT_R_EXPORT },
	{ "trapno", KREG_TRAPNO, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "err", KREG_ERR, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "rip", KREG_RIP, MDB_TGT_R_EXPORT },
	{ "cs", KREG_CS, MDB_TGT_R_EXPORT },
	{ "rflags", KREG_RFLAGS, MDB_TGT_R_EXPORT },
	{ "rsp", KREG_RSP, MDB_TGT_R_EXPORT },
	{ "ss", KREG_SS, MDB_TGT_R_EXPORT },
	{ NULL, 0, 0 }
};

void
mdb_amd64_printregs(const mdb_tgt_gregset_t *gregs)
{
	const kreg_t *kregs = &gregs->kregs[0];
	kreg_t rflags = kregs[KREG_RFLAGS];

#define	GETREG2(x) ((uintptr_t)kregs[(x)]), ((uintptr_t)kregs[(x)])

	mdb_printf("%%rax = 0x%0?p %15A %%r9  = 0x%0?p %A\n",
	    GETREG2(KREG_RAX), GETREG2(KREG_R9));
	mdb_printf("%%rbx = 0x%0?p %15A %%r10 = 0x%0?p %A\n",
	    GETREG2(KREG_RBX), GETREG2(KREG_R10));
	mdb_printf("%%rcx = 0x%0?p %15A %%r11 = 0x%0?p %A\n",
	    GETREG2(KREG_RCX), GETREG2(KREG_R11));
	mdb_printf("%%rdx = 0x%0?p %15A %%r12 = 0x%0?p %A\n",
	    GETREG2(KREG_RDX), GETREG2(KREG_R12));
	mdb_printf("%%rsi = 0x%0?p %15A %%r13 = 0x%0?p %A\n",
	    GETREG2(KREG_RSI), GETREG2(KREG_R13));
	mdb_printf("%%rdi = 0x%0?p %15A %%r14 = 0x%0?p %A\n",
	    GETREG2(KREG_RDI), GETREG2(KREG_R14));
	mdb_printf("%%r8  = 0x%0?p %15A %%r15 = 0x%0?p %A\n\n",
	    GETREG2(KREG_R8), GETREG2(KREG_R15));

	mdb_printf("%%rip = 0x%0?p %A\n", GETREG2(KREG_RIP));
	mdb_printf("%%rbp = 0x%0?p\n", kregs[KREG_RBP]);
	mdb_printf("%%rsp = 0x%0?p\n", kregs[KREG_RSP]);

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

	mdb_printf("  status=<%s,%s,%s,%s,%s,%s,%s,%s,%s>\n\n",
	    (rflags & KREG_EFLAGS_OF_MASK) ? "OF" : "of",
	    (rflags & KREG_EFLAGS_DF_MASK) ? "DF" : "df",
	    (rflags & KREG_EFLAGS_IF_MASK) ? "IF" : "if",
	    (rflags & KREG_EFLAGS_TF_MASK) ? "TF" : "tf",
	    (rflags & KREG_EFLAGS_SF_MASK) ? "SF" : "sf",
	    (rflags & KREG_EFLAGS_ZF_MASK) ? "ZF" : "zf",
	    (rflags & KREG_EFLAGS_AF_MASK) ? "AF" : "af",
	    (rflags & KREG_EFLAGS_PF_MASK) ? "PF" : "pf",
	    (rflags & KREG_EFLAGS_CF_MASK) ? "CF" : "cf");

	mdb_printf("%24s%%cs = 0x%04x\t%%ds = 0x%04x\t%%es = 0x%04x\n",
	    " ", kregs[KREG_CS], kregs[KREG_DS], kregs[KREG_ES]);

	mdb_printf("%%trapno = 0x%x\t\t%%fs = 0x%04x\tfsbase = 0x%0?p\n",
	    kregs[KREG_TRAPNO], (kregs[KREG_FS] & 0xffff), kregs[KREG_FSBASE]);
	mdb_printf("   %%err = 0x%x\t\t%%gs = 0x%04x\tgsbase = 0x%0?p\n",
	    kregs[KREG_ERR], (kregs[KREG_GS] & 0xffff), kregs[KREG_GSBASE]);
}

int
mdb_amd64_kvm_stack_iter(mdb_tgt_t *t, const mdb_tgt_gregset_t *gsp,
    mdb_tgt_stack_f *func, void *arg)
{
	mdb_tgt_gregset_t gregs;
	kreg_t *kregs = &gregs.kregs[0];
	int got_pc = (gsp->kregs[KREG_RIP] != 0);

	struct {
		uintptr_t fr_savfp;
		uintptr_t fr_savpc;
	} fr;

	uintptr_t fp = gsp->kregs[KREG_RBP];
	uintptr_t pc = gsp->kregs[KREG_RIP];

	bcopy(gsp, &gregs, sizeof (gregs));

	while (fp != 0) {

		if (fp & (STACK_ALIGN - 1))
			return (set_errno(EMDB_STKALIGN));

		bzero(&fr, sizeof (fr));
		(void) mdb_tgt_vread(t, &fr, sizeof (fr), fp);

		if (got_pc && func(arg, pc, 0, NULL, &gregs) != 0)
			break;

		kregs[KREG_RSP] = kregs[KREG_RBP];

		kregs[KREG_RBP] = fp = fr.fr_savfp;
		kregs[KREG_RIP] = pc = fr.fr_savpc;

		got_pc = (pc != 0);
	}

	return (0);
}

/*
 * Determine the return address for the current frame.  Typically this is the
 * fr_savpc value from the current frame, but we also perform some special
 * handling to see if we are stopped on one of the first two instructions of
 * a typical function prologue, in which case %rbp will not be set up yet.
 */
int
mdb_amd64_step_out(mdb_tgt_t *t, uintptr_t *p, kreg_t pc, kreg_t fp, kreg_t sp,
    mdb_instr_t curinstr)
{
	struct frame fr;
	GElf_Sym s;
	char buf[1];

	enum {
		M_PUSHQ_RBP	= 0x55,	/* pushq %rbp */
		M_REX_W		= 0x48, /* REX prefix with only W set */
		M_MOVL_RBP	= 0x8b	/* movq %rsp, %rbp with prefix */
	};

	if (mdb_tgt_lookup_by_addr(t, pc, MDB_TGT_SYM_FUZZY,
	    buf, 0, &s, NULL) == 0) {
		if (pc == s.st_value && curinstr == M_PUSHQ_RBP)
			fp = sp - 8;
		else if (pc == s.st_value + 1 && curinstr == M_REX_W) {
			if (mdb_tgt_vread(t, &curinstr, sizeof (curinstr),
			    pc + 1) == sizeof (curinstr) && curinstr ==
			    M_MOVL_RBP)
				fp = sp;
		}
	}

	if (mdb_tgt_vread(t, &fr, sizeof (fr), fp) == sizeof (fr)) {
		*p = fr.fr_savpc;
		return (0);
	}

	return (-1); /* errno is set for us */
}

/*ARGSUSED*/
int
mdb_amd64_next(mdb_tgt_t *t, uintptr_t *p, kreg_t pc, mdb_instr_t curinstr)
{
	mdb_tgt_addr_t npc;

	enum {
		M_CALL_REL = 0xe8, /* call near with relative displacement */
		M_CALL_REG = 0xff, /* call near indirect or call far register */

		M_REX_LO = 0x40,
		M_REX_HI = 0x4f
	};

	/*
	 * If the opcode is a near call with relative displacement, assume the
	 * displacement is a rel32 from the next instruction.
	 */
	if (curinstr == M_CALL_REL) {
		*p = pc + sizeof (mdb_instr_t) + sizeof (uint32_t);
		return (0);
	}

	/* Skip the rex prefix, if any */
	if (curinstr >= M_REX_LO && curinstr <= M_REX_HI &&
	    mdb_tgt_vread(t, &curinstr, sizeof (curinstr), pc) !=
	    sizeof (curinstr))
		return (-1); /* errno is set for us */

	if (curinstr != M_CALL_REG) {
		/* It's not a call */
		return (set_errno(EAGAIN));
	}

	if ((npc = mdb_dis_nextins(mdb.m_disasm, t, MDB_TGT_AS_VIRT, pc)) == pc)
		return (-1); /* errno is set for us */

	*p = npc;
	return (0);
}

/*ARGSUSED*/
int
mdb_amd64_kvm_frame(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uintptr_t)arglim);
	mdb_printf("%a(", pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}

int
mdb_amd64_kvm_framev(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uintptr_t)arglim);
	mdb_printf("%0?lr %a(", gregs->kregs[KREG_RBP], pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}
