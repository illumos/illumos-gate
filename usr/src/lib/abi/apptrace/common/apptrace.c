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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <link.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <signal.h>
#include <synch.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <apptrace.h>
#include <libintl.h>
#include <locale.h>
#include <limits.h>
#include <sys/sysmacros.h>
#include "abienv.h"
#include "mach.h"

#include <libproc.h>
#include <libctf.h>

#define	NUM_ARGS 40

extern const char	*type_name(ctf_file_t *, ctf_id_t, char *, size_t);
extern void		print_value(ctf_file_t *, ctf_id_t, ulong_t);

static struct ps_prochandle	*proc_hdl = NULL;

static Liblist	*bindto_list;
static Liblist	*bindto_excl;
static Liblist	*bindfrom_list;
static Liblist	*bindfrom_excl;
static Liblist	*intlib_list;
static uint_t	pidout;
static Intlist	*trace_list;
static Intlist	*trace_excl;
static Intlist	*verbose_list;
static Intlist	*verbose_excl;

/*
 * Required for calls to build_env_list1 where
 * things are added to the end of the list (preserving
 * search order implied by the setting of env variables
 * in apptracecmd.c)
 */
static Liblist	*intlib_listend;

/*
 * These globals are sought and used by interceptlib.c
 * which goes into all interceptor objects.
 */
FILE		*ABISTREAM = stderr;
sigset_t	abisigset;

/*
 * Strings are printed with "%.*s", abi_strpsz, string
 */
int		abi_strpsz = 20;

/*
 * Special function pointers that'll be set up to point at the
 * libc/libthread versions in the _application's_ link map (as opposed
 * to our own).
 *
 * Additionally, it is impossible to generalize the programmatic
 * creation of interceptor functions for variable argument list
 * functions.  However, in the case of the printf family, there is a
 * vprintf equivalent.  The interceptors for the printf family live in
 * interceptor.c and they call the appropriate vprintf interface
 * instead of the printf interface that they're intercepting.  The
 * link map issue remains, however, so function pointers for the
 * vprintf family in the application's link map are set up here.
 *
 * The interceptors also need to examine errno which also needs to be
 * extracted from the base link map.
 *
 * All of these pointers are initialized in la_preinit().
 */

thread_t (*abi_thr_self)(void);
int (*abi_thr_main)(void);

int (*ABI_VFPRINTF)(FILE *, char const *, va_list);
int (*ABI_VFWPRINTF)(FILE *, const wchar_t *, va_list);
int (*ABI_VPRINTF)(char const *, va_list);
int (*ABI_VSNPRINTF)(char *, size_t, char const *, va_list);
int (*ABI_VSPRINTF)(char *, char const *, va_list);
int (*ABI_VSWPRINTF)(wchar_t *, size_t, const wchar_t *, va_list);
int (*ABI_VWPRINTF)(const wchar_t *, va_list);
int *(*__abi_real_errno)(void);

#if defined(__sparcv9)
static char const *libcpath		= "/lib/sparcv9/libc.so.1";
#elif defined(__amd64)
static char const *libcpath		= "/lib/amd64/libc.so.1";
#else
static char const *libcpath		= "/lib/libc.so.1";
#endif

/* Used as arguments later to dlsym */
static char const *thr_main_sym		= "thr_main";
static char const *thr_self_sym		= "thr_self";
static char const *vfprintf_sym		= "vfprintf";
static char const *vfwprintf_sym	= "vfwprintf";
static char const *vprintf_sym		= "vprintf";
static char const *vsnprintf_sym	= "vsnprintf";
static char const *vsprintf_sym		= "vsprintf";
static char const *vswprintf_sym	= "vswprintf";
static char const *vwprintf_sym		= "vwprintf";
static char const *errno_sym		= "___errno";

/*
 * The list of functions below are functions for which
 * apptrace.so will not perform any tracing.
 *
 * The user visible failure of tracing these functions
 * is a core dump of the application under observation.
 *
 * This list was originally discovered during sotruss
 * development.  Attempts lacking sufficient determination
 * to shrink this list have failed.
 *
 * There are a number of different kinds of issues here.
 *
 * The .stretX functions have to do with the relationship
 * that the caller and callee has with functions that
 * return structures and the altered calling convention
 * that results.
 *
 * We cannot trace *setjmp because the caller of these routines
 * is not allow to return which is exactly what an interceptor
 * function is going to do.
 *
 * The *context functions are on the list because we cannot trace
 * netscape without them on the list, but the exact mechanics of the
 * failure are not known at this time.
 *
 * The leaf functions *getsp can probably be removed given the
 * presence of an interceptor but that experiment has not been
 * conducted.
 *
 * NOTE: this list *must* be maintained in alphabetical order.
 *	 if this list ever became too long a faster search mechanism
 *	 should be considered.
 */
static char *spec_sym[] = {
#if defined(sparc)
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
	NULL
};

uint_t
la_version(uint_t version)
{
	char		*str;
	FILE		*fp;

	if (version > LAV_CURRENT)
		(void) fprintf(stderr,
				dgettext(TEXT_DOMAIN,
					"apptrace: unexpected version: %u\n"),
				version);

	build_env_list(&bindto_list, "APPTRACE_BINDTO");
	build_env_list(&bindto_excl, "APPTRACE_BINDTO_EXCLUDE");

	build_env_list(&bindfrom_list, "APPTRACE_BINDFROM");
	build_env_list(&bindfrom_excl, "APPTRACE_BINDFROM_EXCLUDE");

	if (checkenv("APPTRACE_PID") != NULL) {
		pidout = 1;
	} else {
		char *str = "LD_AUDIT=";
		char *str2 = "LD_AUDIT64=";
		/*
		 * This disables apptrace output in subsequent exec'ed
		 * processes.
		 */
		(void) putenv(str);
		(void) putenv(str2);
	}

	if ((str = checkenv("APPTRACE_OUTPUT")) != NULL) {
		int fd, newfd, targetfd, lowerlimit;
		struct rlimit rl;

		if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
			(void) fprintf(stderr,
					dgettext(TEXT_DOMAIN,
						"apptrace: getrlimit: %s\n"),
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		fd = open(str, O_WRONLY|O_CREAT|O_TRUNC, 0666);
		if (fd == -1) {
			(void) fprintf(stderr,
					dgettext(TEXT_DOMAIN,
						"apptrace: %s: %s\n"),
					str,
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		/*
		 * Those fans of dup2 should note that dup2 cannot
		 * be used below because dup2 closes the target file
		 * descriptor.  Thus, if we're apptracing say, ksh
		 * we'd have closed the fd it uses for the history
		 * file (63 on my box).
		 *
		 * fcntl with F_DUPFD returns first available >= arg3
		 * so we iterate from the top until we find a available
		 * fd.
		 *
		 * Not finding an fd after 10 tries is a failure.
		 *
		 * Since the _file member of the FILE structure is an
		 * unsigned char, we must clamp our fd request to
		 * UCHAR_MAX
		 */
		lowerlimit = ((rl.rlim_cur >
		    UCHAR_MAX) ? UCHAR_MAX : rl.rlim_cur) - 10;

		for (targetfd = lowerlimit + 10;
		    targetfd > lowerlimit; targetfd--) {
			if ((newfd = fcntl(fd, F_DUPFD, targetfd)) != -1)
				break;
		}

		if (newfd == -1) {
			(void) fprintf(stderr,
					dgettext(TEXT_DOMAIN,
						"apptrace: F_DUPFD: %s\n"),
					strerror(errno));
			exit(EXIT_FAILURE);
		}
		(void) close(fd);

		if (fcntl(newfd, F_SETFD, FD_CLOEXEC) == -1) {
			(void) fprintf(stderr,
					dgettext(TEXT_DOMAIN,
					"apptrace: fcntl FD_CLOEXEC: %s\n"),
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		if ((fp = fdopen(newfd, "wF")) != NULL) {
			ABISTREAM = fp;
		} else {
			(void) fprintf(stderr,
					dgettext(TEXT_DOMAIN,
						"apptrace: fdopen: %s\n"),
					strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

#if defined(_LP64)
	build_env_list1(&intlib_list, &intlib_listend,
	    "APPTRACE_INTERCEPTORS64");
#else
	build_env_list1(&intlib_list, &intlib_listend,
	    "APPTRACE_INTERCEPTORS");
#endif

	/* Set up lists interfaces to trace or ignore */
	env_to_intlist(&trace_list, "APPTRACE_INTERFACES");
	env_to_intlist(&trace_excl, "APPTRACE_INTERFACES_EXCLUDE");
	env_to_intlist(&verbose_list, "APPTRACE_VERBOSE");
	env_to_intlist(&verbose_excl, "APPTRACE_VERBOSE_EXCLUDE");

	return (LAV_CURRENT);
}

/* ARGSUSED1 */
uint_t
la_objopen(Link_map *lmp, Lmid_t lmid, uintptr_t *cookie)
{
	uint_t		flags;
	static int	first = 1;
	int		perr;

	/*
	 * If this is the first time in, then l_name is the app
	 * and unless the user gave an explict from list
	 * we will trace calls from it.
	 */
	if (first && bindfrom_list == NULL) {
		flags = LA_FLG_BINDFROM | LA_FLG_BINDTO;
		first = 0;
		goto work;
	}

	/*
	 * If we have no bindto_list, then we assume that we
	 * bindto everything (apptrace -T \*)
	 *
	 * Otherwise we make sure that l_name is on the list.
	 */
	flags = 0;
	if (bindto_list == NULL) {
		flags = LA_FLG_BINDTO;
	} else if (check_list(bindto_list, lmp->l_name) != NULL) {
		flags |= LA_FLG_BINDTO;
	}

	/*
	 * If l_name is on the exclusion list, zero the bit.
	 */
	if ((bindto_excl != NULL) &&
	    check_list(bindto_excl, lmp->l_name) != NULL) {
		flags &= ~LA_FLG_BINDTO;
	}

	/*
	 * If l_name is on the bindfrom list then trace
	 */
	if (check_list(bindfrom_list, lmp->l_name) != NULL) {
		flags |= LA_FLG_BINDFROM;
	}

	/*
	 * If l_name is on the exclusion list, zero the bit
	 * else trace, (this allows "-F !foo" to imply
	 * "-F '*' -F !foo")
	 */
	if (check_list(bindfrom_excl, lmp->l_name) != NULL) {
		flags &= ~LA_FLG_BINDFROM;
	} else if (bindfrom_excl != NULL && bindfrom_list == NULL) {
		flags |= LA_FLG_BINDFROM;
	}

work:
	if (flags) {
		*cookie = (uintptr_t)abibasename(lmp->l_name);

		/*
		 * only call Pgrab() once to get the ps_prochandle
		 */
		if (proc_hdl == NULL)
			proc_hdl = Pgrab(getpid(), PGRAB_RDONLY, &perr);
	}

	return (flags);
}

static void
apptrace_preinit_fail(void)
{
	(void) fprintf(stderr,
			dgettext(TEXT_DOMAIN, "apptrace: la_preinit: %s\n"),
			dlerror());
	exit(EXIT_FAILURE);
}

/* ARGSUSED */
void
la_preinit(uintptr_t *cookie)
{
	void	*h = NULL;

	(void) sigfillset(&abisigset);

	h = dlmopen(LM_ID_BASE, libcpath, RTLD_LAZY | RTLD_NOLOAD);
	if (h == NULL)
		apptrace_preinit_fail();

	if ((abi_thr_self =
	    (thread_t (*)(void)) dlsym(h, thr_self_sym)) == NULL)
		apptrace_preinit_fail();
	if ((abi_thr_main =
	    (int (*)(void)) dlsym(h, thr_main_sym)) == NULL)
		apptrace_preinit_fail();

	/* Do printf style pointers */
	if ((ABI_VFPRINTF =
	    (int (*)(FILE *, char const *, va_list))
	    dlsym(h, vfprintf_sym)) == NULL)
		apptrace_preinit_fail();

	if ((ABI_VFWPRINTF =
	    (int (*)(FILE *, const wchar_t *, va_list))
	    dlsym(h, vfwprintf_sym)) == NULL)
		apptrace_preinit_fail();

	if ((ABI_VPRINTF =
	    (int (*)(char const *, va_list))
	    dlsym(h, vprintf_sym)) == NULL)
		apptrace_preinit_fail();

	if ((ABI_VSNPRINTF =
	    (int (*)(char *, size_t, char const *, va_list))
	    dlsym(h, vsnprintf_sym)) == NULL)
		apptrace_preinit_fail();

	if ((ABI_VSPRINTF =
	    (int (*)(char *, char const *, va_list))
	    dlsym(h, vsprintf_sym)) == NULL)
		apptrace_preinit_fail();

	if ((ABI_VSWPRINTF =
	    (int (*)(wchar_t *, size_t, const wchar_t *, va_list))
	    dlsym(h, vswprintf_sym)) == NULL)
		apptrace_preinit_fail();

	if ((ABI_VWPRINTF =
	    (int (*)(const wchar_t *, va_list))
	    dlsym(h, vwprintf_sym)) == NULL)
		apptrace_preinit_fail();

	if ((__abi_real_errno =
	    (int *(*)(void))
	    dlsym(h, errno_sym)) == NULL)
		apptrace_preinit_fail();

	(void) dlclose(h);
}

/* ARGSUSED1 */
#if defined(_LP64)
uintptr_t
la_symbind64(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcook,
    uintptr_t *defcook, uint_t *sb_flags, char const *sym_name)
#else
uintptr_t
la_symbind32(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcook,
    uintptr_t *defcook, uint_t *sb_flags)
#endif
{
#if !defined(_LP64)
	char const *sym_name = (char const *) symp->st_name;
#endif
	int intercept = 0, verbose = 0;
	uintptr_t ret = symp->st_value;
	uint_t ndx;
	char *str;

#if defined(_LP64)
	if (ELF64_ST_TYPE(symp->st_info) != STT_FUNC)
		goto end;
#else
	/* If we're not looking at a function, bug out */
	if (ELF32_ST_TYPE(symp->st_info) != STT_FUNC)
		goto end;
#endif

	if (verbose_list != NULL) {
		/* apptrace ... -v verbose_list ... cmd */
		if (check_intlist(verbose_list, sym_name))
			verbose = 1;
	}
	if (verbose_excl != NULL) {
		/* apptrace ... -v !verbose_excl ... cmd */
		if (check_intlist(verbose_excl, sym_name))
			verbose = 0;
		else if (verbose_list == NULL && trace_list == NULL &&
		    trace_excl == NULL)
			/* apptrace -v !verbose_excl cmd */
			intercept = 1;
	}
	if (trace_list != NULL) {
		/* apptrace ... -t trace_list ... cmd */
		if (check_intlist(trace_list, sym_name))
			intercept = 1;
	} else if (verbose_list == NULL && verbose_excl == NULL)
		/* default (implies -t '*'):  apptrace cmd */
		intercept = 1;

	if (trace_excl != NULL) {
		/* apptrace ... -t !trace_excl ... cmd */
		if (check_intlist(trace_excl, sym_name))
			intercept = 0;
	}

	if (verbose == 0 && intercept == 0) {
		*sb_flags |= (LA_SYMB_NOPLTEXIT | LA_SYMB_NOPLTENTER);
		goto end;
	}

	/*
	 * Check to see if this symbol is one of the 'special' symbols.
	 * If so we disable calls for that symbol.
	 */
	for (ndx = 0; (str = spec_sym[ndx]) != NULL; ndx++) {
		int	cmpval;
		cmpval = strcmp(sym_name, str);
		if (cmpval < 0)
			break;
		if (cmpval == 0) {
			intercept = verbose = 0;
			*sb_flags |= (LA_SYMB_NOPLTEXIT | LA_SYMB_NOPLTENTER);
			break;
		}
	}

end:
	return (ret);
}

/* ARGSUSED1 */
#if	defined(__sparcv9)
uintptr_t
la_sparcv9_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv9_regs *regset, uint_t *sb_flags,
	char const *sym_name)
#elif	defined(__sparc)
uintptr_t
la_sparcv8_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv8_regs *regset, uint_t *sb_flags)
#elif   defined(__amd64)
uintptr_t
la_amd64_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_amd64_regs *regset, uint_t *sb_flags,
	char const *sym_name)
#elif   defined(__i386)
uintptr_t
la_i86_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_i86_regs *regset, uint_t *sb_flags)
#endif
{
	char		*defname = (char *)(*defcookie);
	char		*refname = (char *)(*refcookie);
	sigset_t	omask;
#if	!defined(_LP64)
	char const	*sym_name = (char const *)symp->st_name;
#endif

	char		buf[256];
	GElf_Sym	sym;
	prsyminfo_t	si;
	ctf_file_t	*ctfp;
	ctf_funcinfo_t	finfo;
	int		argc;
	ctf_id_t	argt[NUM_ARGS];
	ulong_t		argv[NUM_ARGS];
	int		i;
	char		*sep = "";
	ctf_id_t	type, rtype;
	int		kind;

	abilock(&omask);

	if (pidout)
		(void) fprintf(ABISTREAM, "%7u:", (unsigned int)getpid());

	if ((ctfp = Pname_to_ctf(proc_hdl, defname)) == NULL)
		goto fail;

	if (Pxlookup_by_name(proc_hdl, PR_LMID_EVERY, defname, sym_name,
	    &sym, &si) != 0)
		goto fail;

	if (ctf_func_info(ctfp, si.prs_id, &finfo) == CTF_ERR)
		goto fail;

	(void) type_name(ctfp, finfo.ctc_return, buf, sizeof (buf));
	(void) fprintf(ABISTREAM, "-> %-8s -> %8s:%s %s(",
	    refname, defname, buf, sym_name);

	/*
	 * According to bug in la_pltexit(), it can't return
	 * if the type is just a struct/union.  So, if the return
	 * type is a struct/union, la_pltexit() should be off.
	 */
	rtype = ctf_type_resolve(ctfp, finfo.ctc_return);
	type = ctf_type_reference(ctfp, rtype);
	rtype = ctf_type_resolve(ctfp, type);
	kind = ctf_type_kind(ctfp, rtype);
	if ((kind == CTF_K_STRUCT || kind == CTF_K_UNION) &&
	    strpbrk(buf, "*") == NULL)
		*sb_flags |= LA_SYMB_NOPLTEXIT;

	argc = MIN(sizeof (argt) / sizeof (argt[0]), finfo.ctc_argc);
	(void) ctf_func_args(ctfp, si.prs_id, argc, argt);

	argv[0] = GETARG0(regset);
	if (argc > 1)
		argv[1] = GETARG1(regset);
	if (argc > 2)
		argv[2] = GETARG2(regset);
	if (argc > 3)
		argv[3] = GETARG3(regset);
	if (argc > 4)
		argv[4] = GETARG4(regset);
	if (argc > 5)
		argv[5] = GETARG5(regset);
	if (argc > 6) {
		for (i = 6; i < argc; i++)
			argv[i] = GETARG_6NUP(i, regset);
	}

	for (i = 0; i < argc; i++) {
		(void) type_name(ctfp, argt[i], buf, sizeof (buf));
		(void) fprintf(ABISTREAM, "%s%s = ", sep, buf);
		rtype = ctf_type_resolve(ctfp, argt[i]);
		type = ctf_type_reference(ctfp, rtype);
		rtype = ctf_type_resolve(ctfp, type);
		kind = ctf_type_kind(ctfp, rtype);
		if (kind == CTF_K_STRUCT || kind == CTF_K_UNION)
			(void) fprintf(ABISTREAM, "0x%p", (void *)argv[i]);
		else
			print_value(ctfp, argt[i], argv[i]);
		sep = ", ";
	}

	if (finfo.ctc_flags & CTF_FUNC_VARARG)
		(void) fprintf(ABISTREAM, "%s...", sep);
	else if (argc == 0)
		(void) fprintf(ABISTREAM, "void");

	if ((*sb_flags & LA_SYMB_NOPLTEXIT) != 0)
		(void) fprintf(ABISTREAM, ") ** ST\n");
	else
		(void) fprintf(ABISTREAM, ")\n");

	if (verbose_list != NULL &&
	    check_intlist(verbose_list, sym_name) != 0) {
		for (i = 0; i < argc; i++) {
			(void) type_name(ctfp, argt[i], buf, sizeof (buf));
			(void) fprintf(ABISTREAM, "\targ%d = (%s) ", i, buf);
			print_value(ctfp, argt[i], argv[i]);
			(void) fprintf(ABISTREAM, "\n");
		}
		if ((*sb_flags & LA_SYMB_NOPLTEXIT) != 0) {
			if (kind == CTF_K_STRUCT)
				(void) fprintf(ABISTREAM,
				    "\treturn = (struct), apptrace "
				    "will not trace the return\n");
			else
				(void) fprintf(ABISTREAM,
				    "\treturn = (union), apptrace "
				    "will not trace the return\n");
		}
	}

	(void) fflush(ABISTREAM);
	abiunlock(&omask);
	return (symp->st_value);

fail:
	(void) fprintf(ABISTREAM,
	    "-> %-8s -> %8s:%s(0x%lx, 0x%lx, 0x%lx) ** NR\n",
	    refname, defname, sym_name,
	    (ulong_t)GETARG0(regset),
	    (ulong_t)GETARG1(regset),
	    (ulong_t)GETARG2(regset));

	*sb_flags |= LA_SYMB_NOPLTEXIT;
	(void) fflush(ABISTREAM);
	abiunlock(&omask);
	return (symp->st_value);
}

/* ARGSUSED */
#if	defined(_LP64)
uintptr_t
la_pltexit64(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, uintptr_t retval, const char *sym_name)
#else
uintptr_t
la_pltexit(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, uintptr_t retval)
#endif
{
#if	!defined(_LP64)
	const char	*sym_name = (const char *)symp->st_name;
#endif
	sigset_t	omask;
	char		buf[256];
	GElf_Sym	sym;
	prsyminfo_t	si;
	ctf_file_t	*ctfp;
	ctf_funcinfo_t	finfo;
	char		*defname = (char *)(*defcookie);
	char		*refname = (char *)(*refcookie);

	abilock(&omask);

	if (pidout)
		(void) fprintf(ABISTREAM, "%7u:", (unsigned int)getpid());

	if (retval == 0) {
		if (verbose_list == NULL) {
			(void) fprintf(ABISTREAM, "<- %-8s -> %8s:%s()\n",
			    refname, defname, sym_name);
			(void) fflush(ABISTREAM);
		}
		abiunlock(&omask);
		return (retval);
	}

	if ((ctfp = Pname_to_ctf(proc_hdl, defname)) == NULL)
		goto fail;

	if (Pxlookup_by_name(proc_hdl, PR_LMID_EVERY, defname,
	    sym_name, &sym, &si) != 0)
		goto fail;

	if (ctf_func_info(ctfp, si.prs_id, &finfo) == CTF_ERR)
		goto fail;

	if (verbose_list != NULL) {
		if (check_intlist(verbose_list, sym_name) != 0) {
			(void) type_name(ctfp, finfo.ctc_return, buf,
			    sizeof (buf));
			(void) fprintf(ABISTREAM, "\treturn = (%s) ", buf);
			print_value(ctfp, finfo.ctc_return, retval);
			(void) fprintf(ABISTREAM, "\n");
			(void) fprintf(ABISTREAM, "<- %-8s -> %8s:%s()",
			    refname, defname, sym_name);
			(void) fprintf(ABISTREAM, " = 0x%p\n", (void *)retval);
		}
	} else {
		(void) fprintf(ABISTREAM, "<- %-8s -> %8s:%s()",
		    refname, defname, sym_name);
		(void) fprintf(ABISTREAM, " = 0x%p\n", (void *)retval);
	}

	(void) fflush(ABISTREAM);
	abiunlock(&omask);
	return (retval);

fail:
	if (verbose_list != NULL) {
		if (check_intlist(verbose_list, sym_name) != 0) {
			(void) fprintf(ABISTREAM,
			    "\treturn = 0x%p\n", (void *)retval);
			(void) fprintf(ABISTREAM, "<- %-8s -> %8s:%s()",
			    refname, defname, sym_name);
			(void) fprintf(ABISTREAM, " = 0x%p\n", (void *)retval);
		}
	} else {
		(void) fprintf(ABISTREAM, "<- %-8s -> %8s:%s()",
		    refname, defname, sym_name);
		(void) fprintf(ABISTREAM, " = 0x%p\n", (void *)retval);
	}

	(void) fflush(ABISTREAM);
	abiunlock(&omask);
	return (retval);
}
