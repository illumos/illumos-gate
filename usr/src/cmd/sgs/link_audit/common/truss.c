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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <link.h>
#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "env.h"
#include "mach.h"

static Elist		*bindto_list = NULL;
static Elist		*bindfrom_list = NULL;

static uint_t		pidout = 0;
static pid_t		pid;
static FILE		*outfile = stderr;
static uint_t		indent = 1;
static uint_t		indent_level = 1;
static uint_t		trussall = 0;
static uint_t		noexit = 0;
static sigset_t		iset;

/*
 * It's not possible to gather the return code on routines
 * which actually have a dependence on the 'stack frame structure'.
 * Below is a list of known symbols which have this dependency,
 * truss.so will disable the la_pltexit() entry point for these
 * routines, which will remove the requirement for the extra
 * stackframe that the link_auditing interface creates.
 *
 * NOTE: this list *must* be mainted in alphabetical order.
 *	 if this list ever became to long a faster search mechanism
 *	 should be considered.
 */
static char	*spec_sym[] = {
#if	defined(__sparc)
	".stret1",
	".stret2",
	".stret4",
	".stret8",
#endif
	"__getcontext",
	"_getcontext",
	"_getsp",
	"_longjmp",
	"_setcontext",
	"_setjmp",
	"_siglongjmp",
	"_sigsetjmp",
	"_vfork",
	"getcontext",
	"getsp",
	"longjmp",
	"setcontext",
	"setjmp",
	"siglongjmp",
	"sigsetjmp",
	"vfork",
	(char *)0
};

uint_t
la_version(uint_t version)
{
	char	*str;

	if (version > LAV_CURRENT)
		(void) fprintf(stderr, "truss.so: unexpected version: %d\n",
		    version);

	build_env_list(&bindto_list, (const char *)"TRUSS_BINDTO");
	build_env_list(&bindfrom_list, (const char *)"TRUSS_BINDFROM");

	if (checkenv((const char *)"TRUSS_PID")) {
		pidout = 1;
		pid = getpid();
	} else {
		char	*str = "LD_AUDIT=";
		/*
		 * This disables truss output in subsequent fork()/exec
		 * processes.
		 */
		(void) putenv(str);
	}

	if (checkenv((const char *)"TRUSS_NOEXIT")) {
		noexit++;
		indent = 0;
	}

	if (checkenv((const char *)"TRUSS_NOINDENT"))
		indent = 0;

	if (checkenv((const char *)"TRUSS_ALL"))
		trussall++;

	str = checkenv((const char *)"TRUSS_OUTPUT");
	if (str != NULL) {
		FILE	*fp;
		char	fname[MAXPATHLEN];

		if (pidout)
			(void) snprintf(fname, MAXPATHLEN, "%s.%d", str,
			    (int)pid);
		else
			(void) strncpy(fname, str, MAXPATHLEN);

		fp = fopen(fname, (const char *)"w");
		if (fp != NULL) {
			outfile = fp;
		} else {
			(void) fprintf(stderr,
			    "truss.so: unable to open file=`%s': %s\n",
			    fname, strerror(errno));
		}
	}

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
	uint_t	flags;
	char	*basename;
	static int	first = 1;

	if ((bindto_list == NULL) || (trussall))
		flags = LA_FLG_BINDTO;
	else if (check_list(bindto_list, lmp->l_name))
		flags = LA_FLG_BINDTO;
	else
		flags = 0;

	if (((bindfrom_list == NULL) && first) || trussall ||
	    (check_list(bindfrom_list, lmp->l_name)))
		flags |= LA_FLG_BINDFROM;

	first = 0;

	if (flags) {
		if ((basename = strrchr(lmp->l_name, '/')) != NULL)
			basename++;
		else
			basename = lmp->l_name;
		*cookie = (uintptr_t)basename;
	}

	return (flags);
}

/* ARGSUSED1 */
#if	defined(_LP64)
uintptr_t
la_symbind64(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcook,
    uintptr_t *defcook, uint_t *sb_flags, const char *sym_name)
#else
uintptr_t
la_symbind32(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcook,
    uintptr_t *defcook, uint_t *sb_flags)
#endif
{
#if	!defined(_LP64)
	const char	*sym_name = (const char *)symp->st_name;
#endif


	if (noexit)
		*sb_flags |= LA_SYMB_NOPLTEXIT;

	/*
	 * Check to see if this symbol is one of the 'special' symbols.
	 * If so we disable PLTEXIT calls for that symbol.
	 */
	if ((*sb_flags & LA_SYMB_NOPLTEXIT) == 0) {
		uint_t	ndx;
		char	*str;
		for (ndx = 0; (str = spec_sym[ndx]) != NULL; ndx++) {
			int	cmpval;
			cmpval = strcmp(sym_name, str);
			if (cmpval < 0)
				break;
			if (cmpval == 0) {
				*sb_flags |= LA_SYMB_NOPLTEXIT;
				break;
			}
		}
	}
	return (symp->st_value);
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
la_i86_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
    uintptr_t *defcookie, La_i86_regs *regset, uint_t *sb_flags)
#endif
{
	char		*istr;
	char		*defname = (char *)(*defcookie);
	char		*refname = (char *)(*refcookie);
#if	!defined(_LP64)
	const char	*sym_name = (const char *)symp->st_name;
#endif
	sigset_t	oset;

	(void) sigprocmask(SIG_BLOCK, &iset, &oset);

	if (pidout)
		(void) fprintf(outfile, "%5d:", (int)getpid());

	if ((*sb_flags & LA_SYMB_NOPLTEXIT) == 0)
		istr = "";
	else
		istr = "*";

	(void) fprintf(outfile, "%-15s -> %15s:%-*s%s(0x%lx, 0x%lx, 0x%lx)\n",
	    refname, defname, indent_level, istr, sym_name,
	    (long)GETARG0(regset), (long)GETARG1(regset),
	    (long)GETARG2(regset));

	(void) fflush(outfile);
	if (indent && ((*sb_flags & LA_SYMB_NOPLTEXIT) == 0))
		indent_level++;
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	return (symp->st_value);
}

/* ARGSUSED1 */
#if	defined(_LP64)
/* ARGSUSED */
uintptr_t
la_pltexit64(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
    uintptr_t *defcookie, uintptr_t retval, const char *sym_name)
#else
uintptr_t
la_pltexit(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
    uintptr_t *defcookie, uintptr_t retval)
#endif
{
	char		*defname = (char *)(*defcookie);
	char		*refname = (char *)(*refcookie);
	sigset_t	oset;
#if	!defined(_LP64)
	const char	*sym_name = (const char *)symp->st_name;
#endif

	(void) sigprocmask(SIG_BLOCK, &iset, &oset);

	if (pidout)
		(void) fprintf(outfile, "%5d:", (int)pid);
	if (indent)
		indent_level--;
	(void) fprintf(outfile, "%-15s -> %15s:%*s%s - 0x%lx\n", refname,
	    defname, indent_level, "", sym_name, (ulong_t)retval);
	(void) fflush(outfile);
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	return (retval);
}
