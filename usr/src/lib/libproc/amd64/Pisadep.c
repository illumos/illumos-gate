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
 * Copyright 2018, Joyent, Inc.
 */

#include <sys/stack.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/sysmacros.h>
#include <sys/trap.h>
#include <sys/machelf.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include <saveargs.h>
#include "Pcontrol.h"
#include "Pstack.h"

static uchar_t int_syscall_instr[] = { 0xCD, T_SYSCALLINT };
static uchar_t syscall_instr[] = { 0x0f, 0x05 };

const char *
Ppltdest(struct ps_prochandle *P, uintptr_t pltaddr)
{
	map_info_t *mp = Paddr2mptr(P, pltaddr);
	file_info_t *fp;
	size_t i;
	uintptr_t r_addr;

	if (mp == NULL || (fp = mp->map_file) == NULL ||
	    fp->file_plt_base == 0 ||
	    pltaddr - fp->file_plt_base >= fp->file_plt_size) {
		errno = EINVAL;
		return (NULL);
	}

	i = (pltaddr - fp->file_plt_base) / M_PLT_ENTSIZE - M_PLT_XNumber;

	if (P->status.pr_dmodel == PR_MODEL_LP64) {
		Elf64_Rela r;

		r_addr = fp->file_jmp_rel + i * sizeof (r);

		if (Pread(P, &r, sizeof (r), r_addr) == sizeof (r) &&
		    (i = ELF64_R_SYM(r.r_info)) < fp->file_dynsym.sym_symn) {
			Elf_Data *data = fp->file_dynsym.sym_data_pri;
			Elf64_Sym *symp = &(((Elf64_Sym *)data->d_buf)[i]);

			return (fp->file_dynsym.sym_strs + symp->st_name);
		}
	} else {
		Elf32_Rel r;

		r_addr = fp->file_jmp_rel + i * sizeof (r);

		if (Pread(P, &r, sizeof (r), r_addr) == sizeof (r) &&
		    (i = ELF32_R_SYM(r.r_info)) < fp->file_dynsym.sym_symn) {
			Elf_Data *data = fp->file_dynsym.sym_data_pri;
			Elf32_Sym *symp = &(((Elf32_Sym *)data->d_buf)[i]);

			return (fp->file_dynsym.sym_strs + symp->st_name);
		}
	}

	return (NULL);
}

int
Pissyscall(struct ps_prochandle *P, uintptr_t addr)
{
	uchar_t instr[16];

	if (P->status.pr_dmodel == PR_MODEL_LP64) {
		if (Pread(P, instr, sizeof (syscall_instr), addr) !=
		    sizeof (syscall_instr) ||
		    memcmp(instr, syscall_instr, sizeof (syscall_instr)) != 0)
			return (0);
		else
			return (1);
	}

	if (Pread(P, instr, sizeof (int_syscall_instr), addr) !=
	    sizeof (int_syscall_instr))
		return (0);

	if (memcmp(instr, int_syscall_instr, sizeof (int_syscall_instr)) == 0)
		return (1);

	return (0);
}

int
Pissyscall_prev(struct ps_prochandle *P, uintptr_t addr, uintptr_t *dst)
{
	int ret;

	if (P->status.pr_dmodel == PR_MODEL_LP64) {
		if (Pissyscall(P, addr - sizeof (syscall_instr))) {
			if (dst)
				*dst = addr - sizeof (syscall_instr);
			return (1);
		}
		return (0);
	}

	if ((ret = Pissyscall(P, addr - sizeof (int_syscall_instr))) != 0) {
		if (dst)
			*dst = addr - sizeof (int_syscall_instr);
		return (ret);
	}

	return (0);
}

int
Pissyscall_text(struct ps_prochandle *P, const void *buf, size_t buflen)
{
	if (P->status.pr_dmodel == PR_MODEL_LP64) {
		if (buflen >= sizeof (syscall_instr) &&
		    memcmp(buf, syscall_instr, sizeof (syscall_instr)) == 0)
			return (1);
		else
			return (0);
	}

	if (buflen < sizeof (int_syscall_instr))
		return (0);

	if (memcmp(buf, int_syscall_instr, sizeof (int_syscall_instr)) == 0)
		return (1);

	return (0);
}

#define	TR_ARG_MAX 6	/* Max args to print, same as SPARC */

static boolean_t
argcount_ctf(struct ps_prochandle *P, uint32_t pc, uint_t *countp)
{
	GElf_Sym sym;
	ctf_file_t *ctfp;
	ctf_funcinfo_t finfo;
	prsyminfo_t si = { 0 };

	if (Pxlookup_by_addr(P, pc, NULL, 0, &sym, &si) != 0)
		return (B_FALSE);

	if ((ctfp = Paddr_to_ctf(P, pc)) == NULL)
		return (B_FALSE);

	if (ctf_func_info(ctfp, si.prs_id, &finfo) == CTF_ERR)
		return (B_FALSE);

	*countp = finfo.ctc_argc;

	return (B_TRUE);
}

/*
 * Given a return address, determine the likely number of arguments
 * that were pushed on the stack prior to its execution.  We do this by
 * expecting that a typical call sequence consists of pushing arguments on
 * the stack, executing a call instruction, and then performing an add
 * on %esp to restore it to the value prior to pushing the arguments for
 * the call.  We attempt to detect such an add, and divide the addend
 * by the size of a word to determine the number of pushed arguments.
 *
 * If we do not find such an add, this does not necessarily imply that the
 * function took no arguments. It is not possible to reliably detect such a
 * void function because hand-coded assembler does not always perform an add
 * to %esp immediately after the "call" instruction (eg. _sys_call()).
 * Because of this, we default to returning MIN(sz, TR_ARG_MAX) instead of 0
 * in the absence of an add to %esp.
 */
static ulong_t
argcount(struct ps_prochandle *P, uint32_t pc, ssize_t sz)
{
	uchar_t instr[6];
	ulong_t count, max;

	max = MIN(sz / sizeof (uint32_t), TR_ARG_MAX);

	/*
	 * Read the instruction at the return location.
	 */
	if (Pread(P, instr, sizeof (instr), (uintptr_t)pc) != sizeof (instr))
		return (max);

	if (instr[1] != 0xc4)
		return (max);

	switch (instr[0]) {
	case 0x81:	/* count is a longword */
		count = instr[2]+(instr[3]<<8)+(instr[4]<<16)+(instr[5]<<24);
		break;
	case 0x83:	/* count is a byte */
		count = instr[2];
		break;
	default:
		return (max);
	}

	count /= sizeof (uint32_t);
	return (MIN(count, max));
}

static void
ucontext_32_to_prgregs(const ucontext32_t *uc, prgregset_t dst)
{
	const greg32_t *src = &uc->uc_mcontext.gregs[0];

	dst[REG_DS] = (uint16_t)src[DS];
	dst[REG_ES] = (uint16_t)src[ES];

	dst[REG_GS] = (uint16_t)src[GS];
	dst[REG_FS] = (uint16_t)src[FS];
	dst[REG_SS] = (uint16_t)src[SS];
	dst[REG_RSP] = (uint32_t)src[UESP];
	dst[REG_RFL] = src[EFL];
	dst[REG_CS] = (uint16_t)src[CS];
	dst[REG_RIP] = (uint32_t)src[EIP];
	dst[REG_ERR] = (uint32_t)src[ERR];
	dst[REG_TRAPNO] = (uint32_t)src[TRAPNO];
	dst[REG_RAX] = (uint32_t)src[EAX];
	dst[REG_RCX] = (uint32_t)src[ECX];
	dst[REG_RDX] = (uint32_t)src[EDX];
	dst[REG_RBX] = (uint32_t)src[EBX];
	dst[REG_RBP] = (uint32_t)src[EBP];
	dst[REG_RSI] = (uint32_t)src[ESI];
	dst[REG_RDI] = (uint32_t)src[EDI];
}

static int
Pstack_iter32(struct ps_prochandle *P, const prgregset_t regs,
    proc_stack_f *func, void *arg)
{
	prgreg_t *prevfp = NULL;
	uint_t pfpsize = 0;
	int nfp = 0;
	struct {
		prgreg32_t fp;
		prgreg32_t pc;
		prgreg32_t args[32];
	} frame;
	uint_t argc;
	ssize_t sz;
	prgregset_t gregs;
	uint32_t fp, pfp, pc, ctf_pc;
	long args[32];
	int rv;
	int i;

	/*
	 * Type definition for a structure corresponding to an IA32
	 * signal frame.  Refer to the comments in Pstack.c for more info
	 */
	typedef struct {
		prgreg32_t fp;
		prgreg32_t pc;
		int signo;
		caddr32_t ucp;
		caddr32_t sip;
	} sf_t;

	uclist_t ucl;
	ucontext32_t uc;
	uintptr_t uc_addr;

	init_uclist(&ucl, P);
	(void) memcpy(gregs, regs, sizeof (gregs));

	fp = regs[R_FP];
	ctf_pc = pc = regs[R_PC];

	while (fp != 0 || pc != 0) {
		if (stack_loop(fp, &prevfp, &nfp, &pfpsize))
			break;

		if (fp != 0 &&
		    (sz = Pread(P, &frame, sizeof (frame), (uintptr_t)fp)
		    >= (ssize_t)(2* sizeof (uint32_t)))) {
			/*
			 * One more trick for signal frames: the kernel sets
			 * the return pc of the signal frame to 0xffffffff on
			 * Intel IA32, so argcount won't work.
			 */
			if (frame.pc != -1L) {
				sz -= 2* sizeof (uint32_t);
				if (argcount_ctf(P, ctf_pc, &argc)) {
					argc = MIN(argc, 32);
				} else {
					argc = argcount(P, (uint32_t)frame.pc,
					    sz);
				}
			} else
				argc = 3; /* sighandler(signo, sip, ucp) */
		} else {
			(void) memset(&frame, 0, sizeof (frame));
			argc = 0;
		}

		ctf_pc = frame.pc;
		gregs[R_FP] = fp;
		gregs[R_PC] = pc;

		for (i = 0; i < argc; i++)
			args[i] = (uint32_t)frame.args[i];

		if ((rv = func(arg, gregs, argc, args)) != 0)
			break;

		/*
		 * In order to allow iteration over java frames (which can have
		 * their own frame pointers), we allow the iterator to change
		 * the contents of gregs.  If we detect a change, then we assume
		 * that the new values point to the next frame.
		 */
		if (gregs[R_FP] != fp || gregs[R_PC] != pc) {
			fp = gregs[R_FP];
			pc = gregs[R_PC];
			continue;
		}

		pfp = fp;
		fp = frame.fp;
		pc = frame.pc;

		if (find_uclink(&ucl, pfp + sizeof (sf_t)))
			uc_addr = pfp + sizeof (sf_t);
		else
			uc_addr = (uintptr_t)NULL;

		if (uc_addr != (uintptr_t)NULL &&
		    Pread(P, &uc, sizeof (uc), uc_addr) == sizeof (uc)) {
			ucontext_32_to_prgregs(&uc, gregs);
			fp = gregs[R_FP];
			pc = gregs[R_PC];
		}
	}

	if (prevfp)
		free(prevfp);

	free_uclist(&ucl);
	return (rv);
}

static void
ucontext_n_to_prgregs(const ucontext_t *src, prgregset_t dst)
{
	(void) memcpy(dst, src->uc_mcontext.gregs, sizeof (gregset_t));
}

/*
 * Read arguments from the frame indicated by regs into args, return the
 * number of arguments successfully read
 */
static int
read_args(struct ps_prochandle *P, uintptr_t fp, uintptr_t pc, prgreg_t *args,
    size_t argsize)
{
	GElf_Sym sym;
	ctf_file_t *ctfp = NULL;
	ctf_funcinfo_t finfo;
	prsyminfo_t si = {0};
	uint8_t ins[SAVEARGS_INSN_SEQ_LEN];
	size_t insnsize;
	int argc = 0;
	int rettype = 0;
	int start_index = 0;
	int args_style = 0;
	int i;
	ctf_id_t args_types[5];

	if (Pxlookup_by_addr(P, pc, NULL, 0, &sym, &si) != 0)
		return (0);

	if ((ctfp = Paddr_to_ctf(P, pc)) == NULL)
		return (0);

	if (ctf_func_info(ctfp, si.prs_id, &finfo) == CTF_ERR)
		return (0);

	argc = finfo.ctc_argc;

	if (argc == 0)
		return (0);

	rettype = ctf_type_kind(ctfp, finfo.ctc_return);

	/*
	 * If the function returns a structure or union greater than 16 bytes
	 * in size %rdi contains the address in which to store the return
	 * value rather than for an argument.
	 */
	if (((rettype == CTF_K_STRUCT) || (rettype == CTF_K_UNION)) &&
	    ctf_type_size(ctfp, finfo.ctc_return) > 16)
		start_index = 1;
	else
		start_index = 0;

	/*
	 * If any of the first 5 arguments are a structure less than 16 bytes
	 * in size, it will be passed spread across two argument registers,
	 * and we will not cope.
	 */
	if (ctf_func_args(ctfp, si.prs_id, 5, args_types) == CTF_ERR)
		return (0);

	for (i = 0; i < MIN(5, finfo.ctc_argc); i++) {
		int t = ctf_type_kind(ctfp, args_types[i]);

		if (((t == CTF_K_STRUCT) || (t == CTF_K_UNION)) &&
		    ctf_type_size(ctfp, args_types[i]) <= 16)
			return (0);
	}

	/*
	 * The number of instructions to search for argument saving is limited
	 * such that only instructions prior to %pc are considered and we
	 * never read arguments from a function where the saving code has not
	 * in fact yet executed.
	 */
	insnsize = MIN(MIN(sym.st_size, SAVEARGS_INSN_SEQ_LEN),
	    pc - sym.st_value);

	if (Pread(P, ins, insnsize, sym.st_value) != insnsize)
		return (0);

	if ((argc != 0) &&
	    ((args_style = saveargs_has_args(ins, insnsize, argc,
	    start_index)) != SAVEARGS_NO_ARGS)) {
		int regargs = MIN((6 - start_index), argc);
		size_t size = regargs * sizeof (long);
		int i;

		/*
		 * If Studio pushed a structure return address as an argument,
		 * we need to read one more argument than actually exists (the
		 * addr) to make everything line up.
		 */
		if (args_style == SAVEARGS_STRUCT_ARGS)
			size += sizeof (long);

		if (Pread(P, args, size, (fp - size)) != size)
			return (0);

		for (i = 0; i < (regargs / 2); i++) {
			prgreg_t t = args[i];

			args[i] = args[regargs - i - 1];
			args[regargs - i - 1] = t;
		}

		if (argc > regargs) {
			size = MIN((argc - regargs) * sizeof (long),
			    argsize - (regargs * sizeof (long)));

			if (Pread(P, &args[regargs], size, fp +
			    (sizeof (uintptr_t) * 2)) != size)
				return (6);
		}

		return (argc);
	} else {
		return (0);
	}
}

int
Pstack_iter(struct ps_prochandle *P, const prgregset_t regs,
    proc_stack_f *func, void *arg)
{
	struct {
		uintptr_t fp;
		uintptr_t pc;
	} frame;

	uint_t pfpsize = 0;
	prgreg_t *prevfp = NULL;
	prgreg_t fp, pfp;
	prgreg_t pc;

	prgregset_t gregs;
	int nfp = 0;

	uclist_t ucl;
	int rv = 0;
	int argc;

	uintptr_t uc_addr;
	ucontext_t uc;

	/*
	 * Type definition for a structure corresponding to an IA32
	 * signal frame.  Refer to the comments in Pstack.c for more info
	 */
	typedef struct {
		prgreg_t fp;
		prgreg_t pc;
		prgreg_t signo;
		siginfo_t *sip;
	} sigframe_t;
	prgreg_t args[32] = {0};

	if (P->status.pr_dmodel != PR_MODEL_LP64)
		return (Pstack_iter32(P, regs, func, arg));

	init_uclist(&ucl, P);
	(void) memcpy(gregs, regs, sizeof (gregs));

	fp = gregs[R_FP];
	pc = gregs[R_PC];

	while (fp != 0 || pc != 0) {

		if (stack_loop(fp, &prevfp, &nfp, &pfpsize))
			break;

		if (fp != 0 &&
		    Pread(P, &frame, sizeof (frame), (uintptr_t)fp) ==
		    sizeof (frame)) {
			if (frame.pc == -1) {
				argc = 3;
				args[2] = fp + sizeof (sigframe_t);
				if (Pread(P, &args, 2 * sizeof (prgreg_t),
				    fp + 2 * sizeof (prgreg_t)) !=
				    2 * sizeof (prgreg_t))
					argc = 0;
			} else {
				argc = read_args(P, fp, pc, args,
				    sizeof (args));
			}
		} else {
			(void) memset(&frame, 0, sizeof (frame));
			argc = 0;
		}

		gregs[R_FP] = fp;
		gregs[R_PC] = pc;

		if ((rv = func(arg, gregs, argc, args)) != 0)
			break;

		pfp = fp;
		fp = frame.fp;
		pc = frame.pc;

		if (pc == -1 && find_uclink(&ucl, pfp + sizeof (sigframe_t))) {
			uc_addr = pfp + sizeof (sigframe_t);

			if (Pread(P, &uc, sizeof (uc), uc_addr)
			    == sizeof (uc)) {
				ucontext_n_to_prgregs(&uc, gregs);
				fp = gregs[R_FP];
				pc = gregs[R_PC];
			}
		}
	}

	if (prevfp)
		free(prevfp);

	free_uclist(&ucl);

	return (rv);
}

uintptr_t
Psyscall_setup(struct ps_prochandle *P, int nargs, int sysindex, uintptr_t sp)
{
	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		sp -= sizeof (int) * (nargs+2);

		P->status.pr_lwp.pr_reg[REG_RAX] = sysindex;
		P->status.pr_lwp.pr_reg[REG_RSP] = sp;
		P->status.pr_lwp.pr_reg[REG_RIP] = P->sysaddr;
	} else {
		int pusharg = (nargs > 6) ? nargs - 6: 0;

		sp -= sizeof (int64_t) * (pusharg+2);

		P->status.pr_lwp.pr_reg[REG_RAX] = sysindex;
		P->status.pr_lwp.pr_reg[REG_RSP] = sp;
		P->status.pr_lwp.pr_reg[REG_RIP] = P->sysaddr;
	}

	return (sp);
}

int
Psyscall_copyinargs(struct ps_prochandle *P, int nargs, argdes_t *argp,
    uintptr_t ap)
{
	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		int32_t arglist[MAXARGS+2];
		int i;
		argdes_t *adp;

		for (i = 0, adp = argp; i < nargs; i++, adp++)
			arglist[1 + i] = (int32_t)adp->arg_value;

		arglist[0] = P->status.pr_lwp.pr_reg[REG_RIP];
		if (Pwrite(P, &arglist[0], sizeof (int) * (nargs+1),
		    (uintptr_t)ap) != sizeof (int) * (nargs+1))
			return (-1);
	} else {
		int64_t arglist[MAXARGS+2];
		int i;
		argdes_t *adp;
		int pusharg = (nargs > 6) ? nargs - 6: 0;

		for (i = 0, adp = argp; i < nargs; i++, adp++) {
			switch (i) {
			case 0:
				(void) Pputareg(P, REG_RDI, adp->arg_value);
				break;
			case 1:
				(void) Pputareg(P, REG_RSI, adp->arg_value);
				break;
			case 2:
				(void) Pputareg(P, REG_RDX, adp->arg_value);
				break;
			case 3:
				(void) Pputareg(P, REG_RCX, adp->arg_value);
				break;
			case 4:
				(void) Pputareg(P, REG_R8, adp->arg_value);
				break;
			case 5:
				(void) Pputareg(P, REG_R9, adp->arg_value);
				break;
			default:
				arglist[i - 5] = (uint64_t)adp->arg_value;
				break;
			}
		}

		arglist[0] = P->status.pr_lwp.pr_reg[REG_RIP];

		if (Pwrite(P, &arglist[0],
		    sizeof (int64_t) * (pusharg + 1), ap) !=
		    sizeof (int64_t) * (pusharg + 1))
			return (-1);
	}

	return (0);
}

int
Psyscall_copyoutargs(struct ps_prochandle *P, int nargs, argdes_t *argp,
    uintptr_t ap)
{
	if (P->status.pr_dmodel == PR_MODEL_ILP32) {
		uint32_t arglist[MAXARGS + 2];
		int i;
		argdes_t *adp;

		if (Pread(P, &arglist[0], sizeof (int) * (nargs+1),
		    (uintptr_t)ap) != sizeof (int) * (nargs+1))
			return (-1);

		for (i = 0, adp = argp; i < nargs; i++, adp++)
			adp->arg_value = arglist[i];
	} else {
		int pusharg = (nargs > 6) ? nargs - 6: 0;
		int64_t arglist[MAXARGS+2];
		int i;
		argdes_t *adp;

		if (pusharg  > 0 &&
		    Pread(P, &arglist[0], sizeof (int64_t) * (pusharg + 1),
		    ap) != sizeof (int64_t) * (pusharg + 1))
			return (-1);

		for (i = 0, adp = argp; i < nargs; i++, adp++) {
			switch (i) {
			case 0:
				adp->arg_value =
				    P->status.pr_lwp.pr_reg[REG_RDI];
				break;
			case 1:
				adp->arg_value =
				    P->status.pr_lwp.pr_reg[REG_RSI];
				break;
			case 2:
				adp->arg_value =
				    P->status.pr_lwp.pr_reg[REG_RDX];
				break;
			case 3:
				adp->arg_value =
				    P->status.pr_lwp.pr_reg[REG_RCX];
				break;
			case 4:
				adp->arg_value =
				    P->status.pr_lwp.pr_reg[REG_R8];
				break;
			case 5:
				adp->arg_value =
				    P->status.pr_lwp.pr_reg[REG_R9];
				break;
			default:
				adp->arg_value = arglist[i - 6];
				break;
			}
		}

		return (0);
	}

	return (0);
}
