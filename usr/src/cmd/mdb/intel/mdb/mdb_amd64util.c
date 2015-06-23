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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

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
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <saveargs.h>

/*
 * This array is used by the getareg and putareg entry points, and also by our
 * register variable discipline.
 */

const mdb_tgt_regdesc_t mdb_amd64_kregs[] = {
	{ "savfp", KREG_SAVFP, MDB_TGT_R_EXPORT },
	{ "savpc", KREG_SAVPC, MDB_TGT_R_EXPORT },
	{ "rdi", KREG_RDI, MDB_TGT_R_EXPORT },
	{ "edi", KREG_RDI, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "di",  KREG_RDI, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dil", KREG_RDI, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rsi", KREG_RSI, MDB_TGT_R_EXPORT },
	{ "esi", KREG_RSI, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "si",  KREG_RSI, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "sil", KREG_RSI, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rdx", KREG_RDX, MDB_TGT_R_EXPORT },
	{ "edx", KREG_RDX, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "dx",  KREG_RDX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dh",  KREG_RDX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "dl",  KREG_RDX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rcx", KREG_RCX, MDB_TGT_R_EXPORT },
	{ "ecx", KREG_RCX, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "cx",  KREG_RCX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ch",  KREG_RCX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "cl",  KREG_RCX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r8", KREG_R8, MDB_TGT_R_EXPORT },
	{ "r8d", KREG_R8,  MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r8w", KREG_R8,  MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r8l", KREG_R8,  MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r9", KREG_R9, MDB_TGT_R_EXPORT },
	{ "r9d", KREG_R8,  MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r9w", KREG_R8,  MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r9l", KREG_R8,  MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rax", KREG_RAX, MDB_TGT_R_EXPORT },
	{ "eax", KREG_RAX, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "ax",  KREG_RAX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ah",  KREG_RAX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "al",  KREG_RAX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rbx", KREG_RBX, MDB_TGT_R_EXPORT },
	{ "ebx", KREG_RBX, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "bx",  KREG_RBX, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bh",  KREG_RBX, MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "bl",  KREG_RBX, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rbp", KREG_RBP, MDB_TGT_R_EXPORT },
	{ "ebp", KREG_RBP, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "bp",  KREG_RBP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bpl", KREG_RBP, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r10", KREG_R10, MDB_TGT_R_EXPORT },
	{ "r10d", KREG_R10, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r10w", KREG_R10, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r10l", KREG_R10, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r11", KREG_R11, MDB_TGT_R_EXPORT },
	{ "r11d", KREG_R11, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r11w", KREG_R11, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r11l", KREG_R11, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r12", KREG_R12, MDB_TGT_R_EXPORT },
	{ "r12d", KREG_R12, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r12w", KREG_R12, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r12l", KREG_R12, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r13", KREG_R13, MDB_TGT_R_EXPORT },
	{ "r13d", KREG_R13, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r13w", KREG_R13, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r13l", KREG_R13, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r14", KREG_R14, MDB_TGT_R_EXPORT },
	{ "r14d", KREG_R14, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r14w", KREG_R14, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r14l", KREG_R14, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r15", KREG_R15, MDB_TGT_R_EXPORT },
	{ "r15d", KREG_R15, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r15w", KREG_R15, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r15l", KREG_R15, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "ds", KREG_DS, MDB_TGT_R_EXPORT },
	{ "es", KREG_ES, MDB_TGT_R_EXPORT },
	{ "fs", KREG_FS, MDB_TGT_R_EXPORT },
	{ "gs", KREG_GS, MDB_TGT_R_EXPORT },
	{ "trapno", KREG_TRAPNO, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "err", KREG_ERR, MDB_TGT_R_EXPORT | MDB_TGT_R_PRIV },
	{ "rip", KREG_RIP, MDB_TGT_R_EXPORT },
	{ "cs", KREG_CS, MDB_TGT_R_EXPORT },
	{ "rflags", KREG_RFLAGS, MDB_TGT_R_EXPORT },
	{ "eflags", KREG_RFLAGS, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "rsp", KREG_RSP, MDB_TGT_R_EXPORT },
	{ "esp", KREG_RSP, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "sp",  KREG_RSP, MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "spl", KREG_RSP, MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
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

	mdb_printf("%%trapno = 0x%x\t\t%%fs = 0x%04x\t%%gs = 0x%04x\n",
	    kregs[KREG_TRAPNO], (kregs[KREG_FS] & 0xffff),
	    (kregs[KREG_GS] & 0xffff));
	mdb_printf("   %%err = 0x%x\n", kregs[KREG_ERR]);
}

int
mdb_amd64_kvm_stack_iter(mdb_tgt_t *t, const mdb_tgt_gregset_t *gsp,
    mdb_tgt_stack_f *func, void *arg)
{
	mdb_tgt_gregset_t gregs;
	kreg_t *kregs = &gregs.kregs[0];
	int got_pc = (gsp->kregs[KREG_RIP] != 0);
	uint_t argc, reg_argc;
	long fr_argv[32];
	int start_index; /* index to save_instr where to start comparison */
	int err;
	int i;

	struct fr {
		uintptr_t fr_savfp;
		uintptr_t fr_savpc;
	} fr;

	uintptr_t fp = gsp->kregs[KREG_RBP];
	uintptr_t pc = gsp->kregs[KREG_RIP];
	uintptr_t lastfp = 0;

	ssize_t size;
	ssize_t insnsize;
	uint8_t ins[SAVEARGS_INSN_SEQ_LEN];

	GElf_Sym s;
	mdb_syminfo_t sip;
	mdb_ctf_funcinfo_t mfp;
	int xpv_panic = 0;
	int advance_tortoise = 1;
	uintptr_t tortoise_fp = 0;
#ifndef	_KMDB
	int xp;

	if ((mdb_readsym(&xp, sizeof (xp), "xpv_panicking") != -1) && (xp > 0))
		xpv_panic = 1;
#endif

	bcopy(gsp, &gregs, sizeof (gregs));

	while (fp != 0) {
		int args_style = 0;

		if (mdb_tgt_vread(t, &fr, sizeof (fr), fp) != sizeof (fr)) {
			err = EMDB_NOMAP;
			goto badfp;
		}

		if (tortoise_fp == 0) {
			tortoise_fp = fp;
		} else {
			/*
			 * Advance tortoise_fp every other frame, so we detect
			 * cycles with Floyd's tortoise/hare.
			 */
			if (advance_tortoise != 0) {
				struct fr tfr;

				if (mdb_tgt_vread(t, &tfr, sizeof (tfr),
				    tortoise_fp) != sizeof (tfr)) {
					err = EMDB_NOMAP;
					goto badfp;
				}

				tortoise_fp = tfr.fr_savfp;
			}

			if (fp == tortoise_fp) {
				err = EMDB_STKFRAME;
				goto badfp;
			}
		}

		advance_tortoise = !advance_tortoise;

		if ((mdb_tgt_lookup_by_addr(t, pc, MDB_TGT_SYM_FUZZY,
		    NULL, 0, &s, &sip) == 0) &&
		    (mdb_ctf_func_info(&s, &sip, &mfp) == 0)) {
			int return_type = mdb_ctf_type_kind(mfp.mtf_return);
			mdb_ctf_id_t args_types[5];

			argc = mfp.mtf_argc;

			/*
			 * If the function returns a structure or union
			 * greater than 16 bytes in size %rdi contains the
			 * address in which to store the return value rather
			 * than for an argument.
			 */
			if ((return_type == CTF_K_STRUCT ||
			    return_type == CTF_K_UNION) &&
			    mdb_ctf_type_size(mfp.mtf_return) > 16)
				start_index = 1;
			else
				start_index = 0;

			/*
			 * If any of the first 5 arguments are a structure
			 * less than 16 bytes in size, it will be passed
			 * spread across two argument registers, and we will
			 * not cope.
			 */
			if (mdb_ctf_func_args(&mfp, 5, args_types) == CTF_ERR)
				argc = 0;

			for (i = 0; i < MIN(5, argc); i++) {
				int t = mdb_ctf_type_kind(args_types[i]);

				if (((t == CTF_K_STRUCT) ||
				    (t == CTF_K_UNION)) &&
				    mdb_ctf_type_size(args_types[i]) <= 16) {
					argc = 0;
					break;
				}
			}
		} else {
			argc = 0;
		}

		/*
		 * The number of instructions to search for argument saving is
		 * limited such that only instructions prior to %pc are
		 * considered such that we never read arguments from a
		 * function where the saving code has not in fact yet
		 * executed.
		 */
		insnsize = MIN(MIN(s.st_size, SAVEARGS_INSN_SEQ_LEN),
		    pc - s.st_value);

		if (mdb_tgt_vread(t, ins, insnsize, s.st_value) != insnsize)
			argc = 0;

		if ((argc != 0) &&
		    ((args_style = saveargs_has_args(ins, insnsize, argc,
		    start_index)) != SAVEARGS_NO_ARGS)) {
			/* Up to 6 arguments are passed via registers */
			reg_argc = MIN((6 - start_index), mfp.mtf_argc);
			size = reg_argc * sizeof (long);

			/*
			 * If Studio pushed a structure return address as an
			 * argument, we need to read one more argument than
			 * actually exists (the addr) to make everything line
			 * up.
			 */
			if (args_style == SAVEARGS_STRUCT_ARGS)
				size += sizeof (long);

			if (mdb_tgt_vread(t, fr_argv, size, (fp - size))
			    != size)
				return (-1);	/* errno has been set for us */

			/*
			 * Arrange the arguments in the right order for
			 * printing.
			 */
			for (i = 0; i < (reg_argc / 2); i++) {
				long t = fr_argv[i];

				fr_argv[i] = fr_argv[reg_argc - i - 1];
				fr_argv[reg_argc - i - 1] = t;
			}

			if (argc > reg_argc) {
				size = MIN((argc - reg_argc) * sizeof (long),
				    sizeof (fr_argv) -
				    (reg_argc * sizeof (long)));

				if (mdb_tgt_vread(t, &fr_argv[reg_argc], size,
				    fp + sizeof (fr)) != size)
					return (-1); /* errno has been set */
			}
		} else {
			argc = 0;
		}

		if (got_pc && func(arg, pc, argc, fr_argv, &gregs) != 0)
			break;

		kregs[KREG_RSP] = kregs[KREG_RBP];

		lastfp = fp;
		fp = fr.fr_savfp;
		/*
		 * The Xen hypervisor marks a stack frame as belonging to
		 * an exception by inverting the bits of the pointer to
		 * that frame.  We attempt to identify these frames by
		 * inverting the pointer and seeing if it is within 0xfff
		 * bytes of the last frame.
		 */
		if (xpv_panic)
			if ((fp != 0) && (fp < lastfp) &&
			    ((lastfp ^ ~fp) < 0xfff))
				fp = ~fp;

		kregs[KREG_RBP] = fp;
		kregs[KREG_RIP] = pc = fr.fr_savpc;

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
	mdb_tgt_addr_t callpc;

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
	callpc = pc;
	while (curinstr >= M_REX_LO && curinstr <= M_REX_HI) {
		if (mdb_tgt_vread(t, &curinstr, sizeof (curinstr), ++callpc) !=
		    sizeof (curinstr))
			return (-1); /* errno is set for us */
	}

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
	/*
	 * Historically adb limited stack trace argument display to a fixed-
	 * size number of arguments since no symbolic debugging info existed.
	 * On amd64 we can detect the true number of saved arguments so only
	 * respect an arglim of zero; otherwise display the entire argv[].
	 */
	if (arglim == 0)
		argc = 0;

	mdb_printf("%0?lr %a(", gregs->kregs[KREG_RBP], pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}
