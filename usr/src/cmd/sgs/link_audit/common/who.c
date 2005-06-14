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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcntl.h>
#include <link.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <signal.h>

#include "env.h"
#include "mach.h"
#include "who.h"


static int		detail_syms = 0; /* display detail symbol information */
static Objinfo *	objhead = 0;	/* head of object list */
static Elist *		funclist = 0;
static sigset_t		iset;


static void
add_object(Objinfo ** objlist, Link_map * lmp)
{
	Objinfo *	op, * cur, * prev;
	Elf_Ehdr *	ehdr;
	Elf_Phdr *	phdr;
	caddr_t		lpc, hpc;
	int		i;

	if ((op = calloc(1, sizeof (Objinfo))) == 0) {
		(void) fprintf(stderr, "who.so.1: calloc failed\n");
		exit(1);
	}

	lpc = hpc = (caddr_t)lmp->l_addr;
	/* LINTED */
	ehdr = (Elf_Ehdr *)lpc;

	/* LINTED */
	for (i = 0, phdr = (Elf_Phdr *)(ehdr->e_phoff + lpc);
	    i < ehdr->e_phnum; i++, phdr++) {
		caddr_t		_hpc;
		if ((phdr->p_type == PT_LOAD) &&
		    ((_hpc = phdr->p_vaddr + phdr->p_memsz + lpc) > hpc))
			hpc = _hpc;
	}
	op->o_lpc = lpc;
	op->o_hpc = hpc;
	op->o_lmp = lmp;


	if (ehdr->e_type == ET_EXEC)
		op->o_flags |= FLG_OB_FIXED;

	if (*objlist == 0) {
		*objlist = op;
		return;
	}
	/*
	 * Do an insertion sort to maintain the list
	 * in order.
	 */
	if ((*objlist)->o_lmp->l_addr > lmp->l_addr) {
		op->o_next = *objlist;
		*objlist = op;
		return;
	}

	for (prev = 0, cur = *objlist; cur; prev = cur, cur = cur->o_next) {
		if (lpc < cur->o_lpc)
			break;
	}
	if (prev == 0) {
		op->o_next = *objlist;
		*objlist = op;
		return;
	}
	prev->o_next = op;
	op->o_next = cur;
}

static void
remove_object(Objinfo ** objlist, Link_map * lmp)
{
	Objinfo *	cur, * prev;

	for (prev = 0, cur = *objlist; cur; prev = cur, cur = cur->o_next) {
		if (cur->o_lmp == lmp)
			break;
	}
	/*
	 * Did we find it?
	 */
	if (!cur)
		return;

	if (!prev)
		*objlist = cur->o_next;
	else
		prev->o_next = cur->o_next;

	if (cur->o_elf) {
		(void) elf_end(cur->o_elf);
		(void) close(cur->o_fd);
	}
	free(cur);
}

static void
print_simple_address(void * pc)
{
	Dl_info		info;

	if (dladdr(pc, &info) == 0) {
		(void) fprintf(stderr,
			"\t<unknown>: 0x%lx\n", (unsigned long)pc);
		return;
	}

	(void) fprintf(stderr, "\t%s:%s+0x%lx\n",
		info.dli_fname, info.dli_sname,
		(ulong_t)((uintptr_t)pc - (uintptr_t)info.dli_saddr));
}

static void
load_syms(Objinfo * op)
{
	int		fd;
	Elf *		elf;
	Elf_Scn *	scn;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		op->o_flags |= FLG_OB_NOSYMS;
		return;
	}

	if ((fd = open(op->o_lmp->l_name, O_RDONLY)) == -1) {
		op->o_flags |= FLG_OB_NOSYMS;
		return;
	}

	if ((elf = elf_begin(fd, ELF_C_READ, 0)) == 0) {
		op->o_flags |= FLG_OB_NOSYMS;
		(void) close(fd);
		return;
	}
	scn = 0;
	while ((scn = elf_nextscn(elf, scn)) != 0) {
		Elf_Shdr *	shdr;
		Elf_Data *	data;
		shdr = elf_getshdr(scn);
		if (shdr->sh_type != SHT_SYMTAB)
			continue;
		data = elf_getdata(scn, 0);
		op->o_syms = (Elf_Sym *)data->d_buf;
		/* LINTED */
		op->o_symcnt = (uint_t)(shdr->sh_size / shdr->sh_entsize);
		scn = elf_getscn(elf, shdr->sh_link);
		data = elf_getdata(scn, 0);
		op->o_strs = (const char *)data->d_buf;
	}
	if (!op->o_syms) {
		(void) elf_end(elf);
		(void) close(fd);
		op->o_flags |= FLG_OB_NOSYMS;
	}
}


static void
print_address(caddr_t pc)
{
	Elf_Sym *	sym, * _sym;
	Objinfo *	op;
	int		i;

	if (!detail_syms) {
		print_simple_address(pc);
		return;
	}
	for (op = objhead; op; op = op->o_next) {
		if ((pc >= op->o_lpc) && (pc <= op->o_hpc))
			break;
	}
	if (op && (op->o_syms == 0))
		load_syms(op);

	if (!op || (op->o_flags & FLG_OB_NOSYMS)) {
		print_simple_address(pc);
		return;
	}

	sym = op->o_syms;
	if ((op->o_flags & FLG_OB_FIXED) == 0)
		pc = (caddr_t)((uintptr_t)pc - (uintptr_t)op->o_lpc);
	for (i = 0, _sym = op->o_syms; i < op->o_symcnt; i++, _sym++) {
		if (((uintptr_t)_sym->st_value < (uintptr_t)pc) &&
		    (_sym->st_value > sym->st_value))
			sym = _sym;
	}
	(void) fprintf(stderr, "\t%s:%s+0x%lx\n",
		op->o_lmp->l_name, sym->st_name + op->o_strs,
		(ulong_t)((uintptr_t)pc - (uintptr_t)sym->st_value));
}

static void
print_stack(struct frame *sp)
{
	FLUSHWIN();

	while (sp && sp->fr_savpc) {
		print_address((caddr_t)sp->fr_savpc);
		sp = (struct frame *)((ulong_t)sp->fr_savfp + STACK_BIAS);
	}
}

uint_t
la_version(uint_t version)
{
	if (version > LAV_CURRENT)
		(void) fprintf(stderr, "who.so: unexpected version: %d\n",
			version);

	if (checkenv((const char *)"WHO_DETAIL"))
		detail_syms++;

	build_env_list(&funclist, (const char *)"WHOCALLS");

	/*
	 * Initalize iset to the full set of signals to be masked durring
	 * pltenter/pltexit
	 */
	(void) sigfillset(&iset);

	return (LAV_CURRENT);
}

/* ARGSUSED1 */
uint_t
la_objopen(Link_map *lmp, Lmid_t lmid, uintptr_t *cookie)
{
	add_object(&objhead, lmp);
	return (LA_FLG_BINDTO | LA_FLG_BINDFROM);
}


uint_t
la_objclose(uintptr_t *cookie)
{
	remove_object(&objhead, (Link_map *)(*cookie));
	return (1);
}


/* ARGSUSED1 */
#if	defined(__sparcv9)
uintptr_t
la_sparcv9_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv9_regs *regset, uint_t *sb_flags,
	const char *sym_name)
#elif	defined(__sparc)
uintptr_t
la_sparcv8_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv8_regs *regset, uint_t *sb_flags)
#elif   defined(__amd64)
uintptr_t
la_amd64_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_amd64_regs *regset, uint_t *sb_flags,
	const char *sym_name)
#elif   defined(__i386)
uintptr_t
la_i86_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcooke,
	uintptr_t *defcook, La_i86_regs *regset, uint_t *sb_flags)
#endif
{
	sigset_t	oset;
#if	!defined(_LP64)
	const char	*sym_name = (const char *)symp->st_name;
#endif

	(void) sigprocmask(SIG_BLOCK, &iset, &oset);
	if (check_list(funclist, sym_name)) {
		struct frame	*frame_p;

		(void) fprintf(stderr, "%s(0x%lx, 0x%lx, 0x%lx)\n", sym_name,
			(long)GETARG0(regset), (long)GETARG1(regset),
			(long)GETARG2(regset));

		print_address((caddr_t)GETPREVPC(regset));

		frame_p = (struct frame *)((ulong_t)GETFRAME(regset)
		    + STACK_BIAS);

		print_stack(frame_p);
		(void) fflush(stdout);
	}
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	return (symp->st_value);
}
