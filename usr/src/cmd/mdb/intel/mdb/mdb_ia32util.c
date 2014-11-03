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
/*
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/reg.h>
#include <sys/privregs.h>
#include <sys/stack.h>
#include <sys/frame.h>

#include <mdb/mdb_ia32util.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

/*
 * We also define an array of register names and their corresponding
 * array indices.  This is used by the getareg and putareg entry points,
 * and also by our register variable discipline.
 */
const mdb_tgt_regdesc_t mdb_ia32_kregs[] = {
	{ "savfp", KREG_SAVFP, MDB_TGT_R_EXPORT },
	{ "savpc", KREG_SAVPC, MDB_TGT_R_EXPORT },
	{ "eax", KREG_EAX, MDB_TGT_R_EXPORT },
	{ "ax", KREG_EAX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ah", KREG_EAX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "al", KREG_EAX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "ebx", KREG_EBX, MDB_TGT_R_EXPORT },
	{ "bx", KREG_EBX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bh", KREG_EBX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "bl", KREG_EBX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "ecx", KREG_ECX, MDB_TGT_R_EXPORT },
	{ "cx", KREG_ECX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ch", KREG_ECX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "cl", KREG_ECX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "edx", KREG_EDX, MDB_TGT_R_EXPORT },
	{ "dx", KREG_EDX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dh", KREG_EDX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "dl", KREG_EDX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "esi", KREG_ESI, MDB_TGT_R_EXPORT },
	{ "si", KREG_ESI, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "edi", KREG_EDI, MDB_TGT_R_EXPORT },
	{ "di",	EDI, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ebp", KREG_EBP, MDB_TGT_R_EXPORT },
	{ "bp", KREG_EBP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "esp", KREG_ESP, MDB_TGT_R_EXPORT },
	{ "sp", KREG_ESP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "cs", KREG_CS, MDB_TGT_R_EXPORT },
	{ "ds", KREG_DS, MDB_TGT_R_EXPORT },
	{ "ss", KREG_SS, MDB_TGT_R_EXPORT },
	{ "es", KREG_ES, MDB_TGT_R_EXPORT },
	{ "fs", KREG_FS, MDB_TGT_R_EXPORT },
	{ "gs", KREG_GS, MDB_TGT_R_EXPORT },
	{ "eflags", KREG_EFLAGS, MDB_TGT_R_EXPORT },
	{ "eip", KREG_EIP, MDB_TGT_R_EXPORT },
	{ "uesp", KREG_UESP, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "usp", KREG_UESP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "trapno", KREG_TRAPNO, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "err", KREG_ERR, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ NULL, 0, 0 }
};

void
mdb_ia32_printregs(const mdb_tgt_gregset_t *gregs)
{
	const kreg_t *kregs = &gregs->kregs[0];
	kreg_t eflags = kregs[KREG_EFLAGS];

	mdb_printf("%%cs = 0x%04x\t\t%%eax = 0x%0?p %A\n",
	    kregs[KREG_CS], kregs[KREG_EAX], kregs[KREG_EAX]);

	mdb_printf("%%ds = 0x%04x\t\t%%ebx = 0x%0?p %A\n",
	    kregs[KREG_DS], kregs[KREG_EBX], kregs[KREG_EBX]);

	mdb_printf("%%ss = 0x%04x\t\t%%ecx = 0x%0?p %A\n",
	    kregs[KREG_SS], kregs[KREG_ECX], kregs[KREG_ECX]);

	mdb_printf("%%es = 0x%04x\t\t%%edx = 0x%0?p %A\n",
	    kregs[KREG_ES], kregs[KREG_EDX], kregs[KREG_EDX]);

	mdb_printf("%%fs = 0x%04x\t\t%%esi = 0x%0?p %A\n",
	    kregs[KREG_FS], kregs[KREG_ESI], kregs[KREG_ESI]);

	mdb_printf("%%gs = 0x%04x\t\t%%edi = 0x%0?p %A\n\n",
	    kregs[KREG_GS], kregs[KREG_EDI], kregs[KREG_EDI]);

	mdb_printf("%%eip = 0x%0?p %A\n", kregs[KREG_EIP], kregs[KREG_EIP]);
	mdb_printf("%%ebp = 0x%0?p\n", kregs[KREG_EBP]);
	mdb_printf("%%esp = 0x%0?p\n\n", kregs[KREG_ESP]);
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

#ifndef _KMDB
	mdb_printf("  %%uesp = 0x%0?x\n", kregs[KREG_UESP]);
#endif
	mdb_printf("%%trapno = 0x%x\n", kregs[KREG_TRAPNO]);
	mdb_printf("   %%err = 0x%x\n", kregs[KREG_ERR]);
}

/*
 * Given a return address (%eip), determine the likely number of arguments
 * that were pushed on the stack prior to its execution.  We do this by
 * expecting that a typical call sequence consists of pushing arguments on
 * the stack, executing a call instruction, and then performing an add
 * on %esp to restore it to the value prior to pushing the arguments for
 * the call.  We attempt to detect such an add, and divide the addend
 * by the size of a word to determine the number of pushed arguments.
 */
static uint_t
kvm_argcount(mdb_tgt_t *t, uintptr_t eip, ssize_t size)
{
	uint8_t ins[6];
	ulong_t n;

	enum {
		M_MODRM_ESP = 0xc4,	/* Mod/RM byte indicates %esp */
		M_ADD_IMM32 = 0x81,	/* ADD imm32 to r/m32 */
		M_ADD_IMM8  = 0x83	/* ADD imm8 to r/m32 */
	};

	if (mdb_tgt_vread(t, ins, sizeof (ins), eip) != sizeof (ins))
		return (0);

	if (ins[1] != M_MODRM_ESP)
		return (0);

	switch (ins[0]) {
	case M_ADD_IMM32:
		n = ins[2] + (ins[3] << 8) + (ins[4] << 16) + (ins[5] << 24);
		break;

	case M_ADD_IMM8:
		n = ins[2];
		break;

	default:
		n = 0;
	}

	return (MIN((ssize_t)n, size) / sizeof (long));
}

int
mdb_ia32_kvm_stack_iter(mdb_tgt_t *t, const mdb_tgt_gregset_t *gsp,
    mdb_tgt_stack_f *func, void *arg)
{
	mdb_tgt_gregset_t gregs;
	kreg_t *kregs = &gregs.kregs[0];
	int got_pc = (gsp->kregs[KREG_EIP] != 0);
	int err;

	struct {
		uintptr_t fr_savfp;
		uintptr_t fr_savpc;
		long fr_argv[32];
	} fr;

	uintptr_t fp = gsp->kregs[KREG_EBP];
	uintptr_t pc = gsp->kregs[KREG_EIP];
	uintptr_t lastfp = 0;

	ssize_t size;
	uint_t argc;
	int detect_exception_frames = 0;
#ifndef	_KMDB
	int xp;

	if ((mdb_readsym(&xp, sizeof (xp), "xpv_panicking") != -1) && (xp > 0))
		detect_exception_frames = 1;
#endif

	bcopy(gsp, &gregs, sizeof (gregs));

	while (fp != 0) {

		/*
		 * Ensure progress (increasing fp), and prevent
		 * endless loop with the same FP.
		 */
		if (fp <= lastfp) {
			err = EMDB_STKFRAME;
			goto badfp;
		}
		if (fp & (STACK_ALIGN - 1)) {
			err = EMDB_STKALIGN;
			goto badfp;
		}
		if ((size = mdb_tgt_vread(t, &fr, sizeof (fr), fp)) >=
		    (ssize_t)(2 * sizeof (uintptr_t))) {
			size -= (ssize_t)(2 * sizeof (uintptr_t));
			argc = kvm_argcount(t, fr.fr_savpc, size);
		} else {
			err = EMDB_NOMAP;
			goto badfp;
		}

		if (got_pc && func(arg, pc, argc, fr.fr_argv, &gregs) != 0)
			break;

		kregs[KREG_ESP] = kregs[KREG_EBP];

		lastfp = fp;
		fp = fr.fr_savfp;
		/*
		 * The Xen hypervisor marks a stack frame as belonging to
		 * an exception by inverting the bits of the pointer to
		 * that frame.  We attempt to identify these frames by
		 * inverting the pointer and seeing if it is within 0xfff
		 * bytes of the last frame.
		 */
		if (detect_exception_frames)
			if ((fp != 0) && (fp < lastfp) &&
			    ((lastfp ^ ~fp) < 0xfff))
				fp = ~fp;

		kregs[KREG_EBP] = fp;
		kregs[KREG_EIP] = pc = fr.fr_savpc;

		got_pc = (pc != 0);
	}

	return (0);

badfp:
	mdb_printf("%p [%s]", fp, mdb_strerror(err));
	return (set_errno(err));
}

/*
 * Determine the return address for the current frame.  Typically this is the
 * fr_savpc value from the current frame, but we also perform some special
 * handling to see if we are stopped on one of the first two instructions of a
 * typical function prologue, in which case %ebp will not be set up yet.
 */
int
mdb_ia32_step_out(mdb_tgt_t *t, uintptr_t *p, kreg_t pc, kreg_t fp, kreg_t sp,
    mdb_instr_t curinstr)
{
	struct frame fr;
	GElf_Sym s;
	char buf[1];

	enum {
		M_PUSHL_EBP	= 0x55, /* pushl %ebp */
		M_MOVL_EBP	= 0x8b  /* movl %esp, %ebp */
	};

	if (mdb_tgt_lookup_by_addr(t, pc, MDB_TGT_SYM_FUZZY,
	    buf, 0, &s, NULL) == 0) {
		if (pc == s.st_value && curinstr == M_PUSHL_EBP)
			fp = sp - 4;
		else if (pc == s.st_value + 1 && curinstr == M_MOVL_EBP)
			fp = sp;
	}

	if (mdb_tgt_vread(t, &fr, sizeof (fr), fp) == sizeof (fr)) {
		*p = fr.fr_savpc;
		return (0);
	}

	return (-1); /* errno is set for us */
}

/*
 * Return the address of the next instruction following a call, or return -1
 * and set errno to EAGAIN if the target should just single-step.  We perform
 * a bit of disassembly on the current instruction in order to determine if it
 * is a call and how many bytes should be skipped, depending on the exact form
 * of the call instruction that is being used.
 */
int
mdb_ia32_next(mdb_tgt_t *t, uintptr_t *p, kreg_t pc, mdb_instr_t curinstr)
{
	uint8_t m;

	enum {
		M_CALL_REL = 0xe8, /* call near with relative displacement */
		M_CALL_REG = 0xff, /* call near indirect or call far register */

		M_MODRM_MD = 0xc0, /* mask for Mod/RM byte Mod field */
		M_MODRM_OP = 0x38, /* mask for Mod/RM byte opcode field */
		M_MODRM_RM = 0x07, /* mask for Mod/RM byte R/M field */

		M_MD_IND   = 0x00, /* Mod code for [REG] */
		M_MD_DSP8  = 0x40, /* Mod code for disp8[REG] */
		M_MD_DSP32 = 0x80, /* Mod code for disp32[REG] */
		M_MD_REG   = 0xc0, /* Mod code for REG */

		M_OP_IND   = 0x10, /* Opcode for call near indirect */
		M_RM_DSP32 = 0x05  /* R/M code for disp32 */
	};

	/*
	 * If the opcode is a near call with relative displacement, assume the
	 * displacement is a rel32 from the next instruction.
	 */
	if (curinstr == M_CALL_REL) {
		*p = pc + sizeof (mdb_instr_t) + sizeof (uint32_t);
		return (0);
	}

	/*
	 * If the opcode is a call near indirect or call far register opcode,
	 * read the subsequent Mod/RM byte to perform additional decoding.
	 */
	if (curinstr == M_CALL_REG) {
		if (mdb_tgt_vread(t, &m, sizeof (m), pc + 1) != sizeof (m))
			return (-1); /* errno is set for us */

		/*
		 * If the Mod/RM opcode extension indicates a near indirect
		 * call, then skip the appropriate number of additional
		 * bytes depending on the addressing form that is used.
		 */
		if ((m & M_MODRM_OP) == M_OP_IND) {
			switch (m & M_MODRM_MD) {
			case M_MD_DSP8:
				*p = pc + 3; /* skip pr_instr, m, disp8 */
				break;
			case M_MD_DSP32:
				*p = pc + 6; /* skip pr_instr, m, disp32 */
				break;
			case M_MD_IND:
				if ((m & M_MODRM_RM) == M_RM_DSP32) {
					*p = pc + 6;
					break; /* skip pr_instr, m, disp32 */
				}
				/* FALLTHRU */
			case M_MD_REG:
				*p = pc + 2; /* skip pr_instr, m */
				break;
			}
			return (0);
		}
	}

	return (set_errno(EAGAIN));
}

/*ARGSUSED*/
int
mdb_ia32_kvm_frame(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uint_t)arglim);
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
mdb_ia32_kvm_framev(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uint_t)arglim);
	mdb_printf("%0?lr %a(", gregs->kregs[KREG_EBP], pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}
