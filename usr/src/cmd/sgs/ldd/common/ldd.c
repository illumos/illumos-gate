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
 *
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Print the list of shared objects required by a dynamic executable or shared
 * object.
 *
 * usage is: ldd [-d | -r] [-c] [-D] [-e envar] [-i] [-f] [-L] [-l] [-p] [-s]
 *		[-U | -u] [-v] [-w] file(s)
 *
 * ldd opens the file and verifies the information in the elf header.
 * If the file is a dynamic executable, we set up some environment variables
 * and exec(2) the file.  If the file is a shared object, we preload the
 * file with a dynamic executable stub. The runtime linker (ld.so.1) actually
 * provides the diagnostic output, according to the environment variables set.
 *
 * If neither -d nor -r is specified, we set only LD_TRACE_LOADED_OBJECTS_[AE].
 * The runtime linker will print the pathnames of all dynamic objects it
 * loads, and then exit.  Note that we distiguish between ELF and AOUT objects
 * when setting this environment variable - AOUT executables cause the mapping
 * of sbcp, the dependencies of which the user isn't interested in.
 *
 * If -d or -r is specified, we also set LD_WARN=1; the runtime linker will
 * perform its normal relocations and issue warning messages for unresolved
 * references. It will then exit.
 * If -r is specified, we set LD_BIND_NOW=1, so that the runtime linker
 * will perform all relocations, otherwise (under -d) the runtime linker
 * will not perform PLT (function) type relocations.
 *
 * If -c is specified we also set LD_NOCONFIG=1, thus disabling any
 * configuration file use.
 *
 * If -D is specified we skip deferred dependency processing.  By default,
 * ldd loads all deferred dependencies.  However, during normal process
 * execution, deferred dependencies are only loaded when an explicit binding
 * to an individual deferred reference is made.  As no user code is executed
 * under ldd, explicit references to deferred symbols can't be triggered.
 *
 * If -e is specified the associated environment variable is set for the
 * child process that will produce ldd's diagnostics.
 *
 * If -i is specified, we set LD_INIT=1. The order of inititialization
 * sections to be executed is printed. We also set LD_WARN=1.
 *
 * If -f is specified, we will run ldd as root on executables that have
 * an unsercure runtime linker that does not live under the "/usr/lib"
 * directory.  By default we will not let this happen.
 *
 * If -l is specified it generates a warning for any auxiliary filter not found.
 * Prior to 2.8 this forced any filters to load (all) their filtees.  This is
 * now the default, however missing auxiliary filters don't generate any error
 * diagniostic.  See also -L.
 *
 * If -L is specified we revert to lazy loading, thus any filtee or lazy
 * dependency loading is deferred until relocations cause loading.  Without
 * this option we set LD_LOADFLTR=1, thus forcing any filters to load (all)
 * their filtees, and LD_NOLAZYLOAD=1 thus forcing immediate processing of
 * any lazy loaded dependencies.
 *
 * If -s is specified we also set LD_TRACE_SEARCH_PATH=1, thus enabling
 * the runtime linker to indicate the search algorithm used.
 *
 * If -v is specified we also set LD_VERBOSE=1, thus enabling the runtime
 * linker to indicate all object dependencies (not just the first object
 * loaded) together with any versioning requirements.
 *
 * If -U or -u is specified unused dependencies are detected.  -u causes
 * LD_UNUSED=1 to be set, which causes dependencies that are unused within the
 * process to be detected.  -U causes LD_UNREF=1 to be set, which causes
 * unreferenced objects, and unreferenced cyclic dependencies to be detected.
 * These options assert that at least -d is set as relocation references are
 * what determine an objects use.
 *
 * If -w is specified, no unresolved weak references are allowed.  -w causes
 * LD_NOUNRESWEAK=1 to be set.  By default, an unresolved weak reference is
 * allowed, and a "0" is written to the relocation offset.  The -w option
 * disables this default.  Any weak references that can not be resolved result
 * in relocation error messages.  This option has no use without -r or -d.
 *
 * If the -p option is specified, no unresolved PARENT or EXTERN references are
 * allowed.  -p causes LD_NOPAREXT=1 to be set.  By default, PARENT and EXTERN
 * references, which have been explicitly assigned via a mapfile when a shared
 * object was built, imply that a caller will provide the symbols, and hence
 * these are not reported as relocation errors.  Note, the -p option is asserted
 * by default when either the -r or -d options are used to inspect a dynamic
 * executable.  This option has no use with a shared object without -r or -d.
 */
#include	<fcntl.h>
#include	<stdio.h>
#include	<string.h>
#include	<_libelf.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<wait.h>
#include	<locale.h>
#include	<errno.h>
#include	<signal.h>
#include	"machdep.h"
#include	"sgs.h"
#include	"conv.h"
#include	"a.out.h"
#include	"msg.h"

static int	elf_check(int, char *, char *, Elf *, int);
static int	aout_check(int, char *, char *, int, int);
static int	run(int, char *, char *, const char *, int);


/*
 * Define all environment variable strings.  The character following the "="
 * will be written to, to disable or enable the associated feature.
 */
static char	bind[] =	"LD_BIND_NOW= ",
		load_elf[] =	"LD_TRACE_LOADED_OBJECTS_E= ",
		load_aout[] =	"LD_TRACE_LOADED_OBJECTS_A= ",
		path[] =	"LD_TRACE_SEARCH_PATHS= ",
		verb[] =	"LD_VERBOSE= ",
		warn[] =	"LD_WARN= ",
		conf[] =	"LD_NOCONFIG= ",
		fltr[] =	"LD_LOADFLTR= ",
		lazy[] =	"LD_NOLAZYLOAD=1",
		init[] =	"LD_INIT= ",
		uref[] =	"LD_UNREF= ",
		used[] =	"LD_UNUSED= ",
		weak[] =	"LD_NOUNRESWEAK= ",
		nope[] =	"LD_NOPAREXT= ",
		defr[] =	"LD_DEFERRED= ";
static char	*load;

static const char	*prefile_32, *prefile_64, *prefile;
static APlist		*eopts = NULL;

int
main(int argc, char **argv, char **envp)
{
	char	*str, *cname = argv[0];

	Elf	*elf;
	int	cflag = 0, dflag = 0, fflag = 0, iflag = 0, Lflag = 0;
	int	lflag = 0, rflag = 0, sflag = 0, Uflag = 0, uflag = 0;
	int	Dflag = 0, pflag = 0, vflag = 0, wflag = 0;
	int	nfile, var, error = 0;
	Aliste	idx;

	/*
	 * If we're on a 64-bit kernel, try to exec a full 64-bit version of
	 * the binary.  If successful, conv_check_native() won't return.
	 *
	 * This is done to ensure that ldd can handle objects >2GB.
	 * ldd uses libelf, which is not large file capable. The
	 * 64-bit ldd can handle any sized object.
	 */
	(void) conv_check_native(argv, envp);

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	/*
	 * verify command line syntax and process arguments
	 */
	opterr = 0;				/* disable getopt error mesg */

	while ((var = getopt(argc, argv, MSG_ORIG(MSG_STR_GETOPT))) != EOF) {
		switch (var) {
		case 'c' :			/* enable config search */
			cflag = 1;
			break;
		case 'D' :			/* skip deferred dependencies */
			Dflag = 1;
			break;
		case 'd' :			/* perform data relocations */
			dflag = 1;
			if (rflag)
				error++;
			break;
		case 'e' :
			if (aplist_append(&eopts, optarg, 10) == NULL) {
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC),
				    cname);
				exit(1);
			}
			break;
		case 'f' :
			fflag = 1;
			break;
		case 'L' :
			Lflag = 1;
			break;
		case 'l' :
			lflag = 1;
			break;
		case 'i' :			/* print the order of .init */
			iflag = 1;
			break;
		case 'p' :
			pflag = 1;		/* expose unreferenced */
			break;			/*	parent or externals */
		case 'r' :			/* perform all relocations */
			rflag = 1;
			if (dflag)
				error++;
			break;
		case 's' :			/* enable search path output */
			sflag = 1;
			break;
		case 'U' :			/* list unreferenced */
			Uflag = 1;		/*	dependencies */
			if (uflag)
				error++;
			break;
		case 'u' :			/* list unused dependencies */
			uflag = 1;
			if (Uflag)
				error++;
			break;
		case 'v' :			/* enable verbose output */
			vflag = 1;
			break;
		case 'w' :			/* expose unresolved weak */
			wflag = 1;		/*	references */
			break;
		default :
			error++;
			break;
		}
		if (error)
			break;
	}
	if (error) {
		(void) fprintf(stderr, MSG_INTL(MSG_ARG_USAGE), cname);
		exit(1);
	}

	/*
	 * Determine if any of the LD_PRELOAD family is already set in the
	 * environment, if so we'll continue to analyze each object with the
	 * appropriate setting.
	 */
	if (((prefile_32 = getenv(MSG_ORIG(MSG_LD_PRELOAD_32))) == NULL) ||
	    (*prefile_32 == '\0')) {
		prefile_32 = MSG_ORIG(MSG_STR_EMPTY);
	}
	if (((prefile_64 = getenv(MSG_ORIG(MSG_LD_PRELOAD_64))) == NULL) ||
	    (*prefile_64 == '\0')) {
		prefile_64 = MSG_ORIG(MSG_STR_EMPTY);
	}
	if (((prefile = getenv(MSG_ORIG(MSG_LD_PRELOAD))) == NULL) ||
	    (*prefile == '\0')) {
		prefile = MSG_ORIG(MSG_STR_EMPTY);
	}

	/*
	 * Determine if any environment requests are for the LD_PRELOAD family,
	 * and if so override any environment settings we've established above.
	 */
	for (APLIST_TRAVERSE(eopts, idx, str)) {
		if ((strncmp(str, MSG_ORIG(MSG_LD_PRELOAD_32),
		    MSG_LD_PRELOAD_32_SIZE)) == 0) {
			str += MSG_LD_PRELOAD_32_SIZE;
			if ((*str++ == '=') && (*str != '\0'))
				prefile_32 = str;
			continue;
		}
		if ((strncmp(str, MSG_ORIG(MSG_LD_PRELOAD_64),
		    MSG_LD_PRELOAD_64_SIZE)) == 0) {
			str += MSG_LD_PRELOAD_64_SIZE;
			if ((*str++ == '=') && (*str != '\0'))
				prefile_64 = str;
			continue;
		}
		if ((strncmp(str, MSG_ORIG(MSG_LD_PRELOAD),
		    MSG_LD_PRELOAD_SIZE)) == 0) {
			str += MSG_LD_PRELOAD_SIZE;
			if ((*str++ == '=') && (*str != '\0'))
				prefile = str;
			continue;
		}
	}

	/*
	 * Set the appropriate relocation environment variables (Note unsetting
	 * the environment variables is done just in case the user already
	 * has these in their environment ... sort of thing the test folks
	 * would do :-)
	 */
	warn[sizeof (warn) - 2] = (dflag || rflag || Uflag || uflag) ? '1' :
	    '\0';
	bind[sizeof (bind) - 2] = (rflag) ? '1' : '\0';
	path[sizeof (path) - 2] = (sflag) ? '1' : '\0';
	verb[sizeof (verb) - 2] = (vflag) ? '1' : '\0';
	fltr[sizeof (fltr) - 2] = (Lflag) ? '\0' : (lflag) ? '2' : '1';
	init[sizeof (init) - 2] = (iflag) ? '1' : '\0';
	conf[sizeof (conf) - 2] = (cflag) ? '1' : '\0';
	lazy[sizeof (lazy) - 2] = (Lflag) ? '\0' : '1';
	uref[sizeof (uref) - 2] = (Uflag) ? '1' : '\0';
	used[sizeof (used) - 2] = (uflag) ? '1' : '\0';
	weak[sizeof (weak) - 2] = (wflag) ? '1' : '\0';
	nope[sizeof (nope) - 2] = (pflag) ? '1' : '\0';
	defr[sizeof (defr) - 2] = (Dflag) ? '\0' : '1';

	/*
	 * coordinate libelf's version information
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_LIBELF), cname,
		    EV_CURRENT);
		exit(1);
	}

	/*
	 * Loop through remaining arguments.  Note that from here on there
	 * are no exit conditions so that we can process a list of files,
	 * any error condition is retained for a final exit status.
	 */
	nfile = argc - optind;
	for (; optind < argc; optind++) {
		char	*fname = argv[optind];

		/*
		 * Open file (do this before checking access so that we can
		 * provide the user with better diagnostics).
		 */
		if ((var = open(fname, O_RDONLY)) == -1) {
			int	err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN), cname,
			    fname, strerror(err));
			error = 1;
			continue;
		}

		/*
		 * Get the files elf descriptor and process it as an elf or
		 * a.out (4.x) file.
		 */
		elf = elf_begin(var, ELF_C_READ, (Elf *)0);
		switch (elf_kind(elf)) {
		case ELF_K_AR :
			(void) fprintf(stderr, MSG_INTL(MSG_USP_NODYNORSO),
			    cname, fname);
			error = 1;
			break;
		case ELF_K_COFF:
			(void) fprintf(stderr, MSG_INTL(MSG_USP_UNKNOWN),
			    cname, fname);
			error = 1;
			break;
		case ELF_K_ELF:
			if (elf_check(nfile, fname, cname, elf, fflag) != 0)
				error = 1;
			break;
		default:
			/*
			 * This is either an unknown file or an aout format
			 */
			if (aout_check(nfile, fname, cname, var, fflag) != 0)
				error = 1;
			break;
		}
		(void) elf_end(elf);
		(void) close(var);
	}
	return (error);
}



static int
elf_check(int nfile, char *fname, char *cname, Elf *elf, int fflag)
{
	Conv_inv_buf_t	inv_buf;
	GElf_Ehdr	ehdr;
	GElf_Phdr	phdr;
	int		dynamic = 0, interp = 0, cnt, class;

	/*
	 * verify information in file header
	 */
	if (gelf_getehdr(elf, &ehdr) == NULL) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETEHDR),
		    cname, fname, elf_errmsg(-1));
		return (1);
	}

	/*
	 * Compatible machine
	 */
	if ((ehdr.e_machine != M_MACH_32) && (ehdr.e_machine != M_MACH_64) &&
	    (ehdr.e_machine != M_MACHPLUS)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_MACHTYPE), cname, fname,
		    conv_ehdr_mach(ehdr.e_machine, 0, &inv_buf));
		return (1);
	}

	/*
	 * Compatible encoding (byte order)
	 */
	if (ehdr.e_ident[EI_DATA] != M_DATA) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_DATA), cname, fname,
		    conv_ehdr_data(ehdr.e_ident[EI_DATA], 0, &inv_buf));
		return (1);
	}

	/*
	 * Compatible class
	 */
	switch (class = ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		/*
		 * If M_MACH is not the same thing as M_MACHPLUS and this
		 * is an M_MACHPLUS object, then the corresponding header
		 * flag must be set.
		 */
		if ((ehdr.e_machine != M_MACH) &&
		    ((ehdr.e_flags & M_FLAGSPLUS) == 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_MACHFLAGS),
			    cname, fname);
			return (1);
		}
		break;
	case ELFCLASS64:
		/* Requires 64-bit kernel */
		if (conv_sys_eclass() == ELFCLASS32) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_KCLASS32),
			    cname, fname, conv_ehdr_class(class, 0, &inv_buf));
			return (1);
		}
		break;
	default:
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_CLASS), cname, fname,
		    conv_ehdr_class(class, 0, &inv_buf));
		return (1);
	}

	/*
	 * Object type
	 */
	if ((ehdr.e_type != ET_EXEC) && (ehdr.e_type != ET_DYN) &&
	    (ehdr.e_type != ET_REL)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_BADMAGIC),
		    cname, fname);
		return (1);
	}

	/*
	 * Check that the file is executable.  Dynamic executables must be
	 * executable to be exec'ed.  Shared objects need not be executable to
	 * be mapped with a dynamic executable, however, by convention they're
	 * supposed to be executable.
	 */
	if (access(fname, X_OK) != 0) {
		if (ehdr.e_type == ET_EXEC) {
			(void) fprintf(stderr, MSG_INTL(MSG_USP_NOTEXEC_1),
			    cname, fname);
			return (1);
		}
		(void) fprintf(stderr, MSG_INTL(MSG_USP_NOTEXEC_2), cname,
		    fname);
	}

	/*
	 * Determine whether we have a dynamic section or interpretor.
	 */
	for (cnt = 0; cnt < (int)ehdr.e_phnum; cnt++) {
		if (dynamic && interp)
			break;

		if (gelf_getphdr(elf, cnt, &phdr) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETPHDR),
			    cname, fname, elf_errmsg(-1));
			return (1);
		}

		if (phdr.p_type == PT_DYNAMIC) {
			dynamic = 1;
			continue;
		}

		if (phdr.p_type != PT_INTERP)
			continue;

		interp = 1;

		/*
		 * If fflag is not set, and euid == root, and the interpreter
		 * does not live under /lib, /usr/lib or /etc/lib then don't
		 * allow ldd to execute the image.  This prevents someone
		 * creating a `trojan horse' by substituting their own
		 * interpreter that could preform privileged operations
		 * when ldd is against it.
		 */
		if ((fflag == 0) && (geteuid() == 0) &&
		    (strcmp(fname, conv_lddstub(class)) != 0)) {
			char	*interpreter;

			/*
			 * Does the interpreter live under a trusted directory.
			 */
			interpreter = elf_getident(elf, 0) + phdr.p_offset;

			if ((strncmp(interpreter, MSG_ORIG(MSG_PTH_USRLIB),
			    MSG_PTH_USRLIB_SIZE) != 0) &&
			    (strncmp(interpreter, MSG_ORIG(MSG_PTH_LIB),
			    MSG_PTH_LIB_SIZE) != 0) &&
			    (strncmp(interpreter, MSG_ORIG(MSG_PTH_ETCLIB),
			    MSG_PTH_ETCLIB_SIZE) != 0)) {
				(void) fprintf(stderr, MSG_INTL(MSG_USP_ELFINS),
				    cname, fname, interpreter);
				return (1);
			}
		}
	}

	/*
	 * Catch the case of a static executable (ie, an ET_EXEC that has a set
	 * of program headers but no PT_DYNAMIC).
	 */
	if (ehdr.e_phnum && !dynamic) {
		(void) fprintf(stderr, MSG_INTL(MSG_USP_NODYNORSO), cname,
		    fname);
		return (1);
	}

	/*
	 * If there is a dynamic section, then check for the DF_1_NOHDR
	 * flag, and bail if it is present. Such objects are created using
	 * a mapfile option (?N in the version 1 syntax, or HDR_NOALLOC
	 * otherwise). The ELF header and program headers are
	 * not mapped as part of the first segment, and virtual addresses
	 * are computed without them. If ldd tries to interpret such
	 * a file, it will become confused and generate bad output or
	 * crash. Such objects are always special purpose files (like an OS
	 * kernel) --- files for which the ldd operation doesn't make sense.
	 */
	if (dynamic && (_gelf_getdyndtflags_1(elf) & DF_1_NOHDR)) {
		(void) fprintf(stderr, MSG_INTL(MSG_USP_NOHDR), cname,
		    fname);
		return (1);
	}

	load = load_elf;

	/*
	 * Run the required program (shared and relocatable objects require the
	 * use of lddstub).
	 */
	if ((ehdr.e_type == ET_EXEC) && interp)
		return (run(nfile, cname, fname, (const char *)fname, class));
	else
		return (run(nfile, cname, fname, conv_lddstub(class), class));
}

static int
aout_check(int nfile, char *fname, char *cname, int fd, int fflag)
{
	struct exec32	aout;
	int		err;

	if (lseek(fd, 0, SEEK_SET) != 0) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_LSEEK), cname, fname,
		    strerror(err));
		return (1);
	}
	if (read(fd, (char *)&aout, sizeof (aout)) != sizeof (aout)) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_READ), cname, fname,
		    strerror(err));
		return (1);
	}
	if (aout.a_machtype != M_SPARC) {
		(void) fprintf(stderr, MSG_INTL(MSG_USP_UNKNOWN), cname, fname);
		return (1);
	}
	if (N_BADMAG(aout) || !aout.a_dynamic) {
		(void) fprintf(stderr, MSG_INTL(MSG_USP_NODYNORSO), cname,
		    fname);
		return (1);
	}
	if (!fflag && (geteuid() == 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_USP_AOUTINS), cname, fname);
		return (1);
	}

	/*
	 * Run the required program.
	 */
	if ((aout.a_magic == ZMAGIC) && (aout.a_entry <= sizeof (aout))) {
		load = load_elf;
		return (run(nfile, cname, fname, conv_lddstub(ELFCLASS32),
		    ELFCLASS32));
	} else {
		load = load_aout;
		return (run(nfile, cname, fname, (const char *)fname,
		    ELFCLASS32));
	}
}


/*
 * Run the required program, setting the preload and trace environment
 * variables accordingly.
 */
static int
run(int nfile, char *cname, char *fname, const char *ename, int class)
{
	const char	*preload = 0;
	int		pid, status;

	if ((pid = fork()) == -1) {
		int	err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_FORK), cname,
		    strerror(err));
		return (1);
	}

	if (pid) {				/* parent */
		while (wait(&status) != pid)
			;
		if (WIFSIGNALED(status) && ((WSIGMASK & status) != SIGPIPE)) {
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_EXEC), cname,
			    fname);
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_EXEC_SIG),
			    (WSIGMASK & status), ((status & WCOREFLG) ?
			    MSG_INTL(MSG_SYS_EXEC_CORE) :
			    MSG_ORIG(MSG_STR_EMPTY)));
			status = 1;
		} else if (WHIBYTE(status)) {
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_EXEC), cname,
			    fname);
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_EXEC_STAT),
			    WHIBYTE(status));
			status = 1;
		}
	} else {				/* child */
		Aliste	idx;
		char	*str;
		size_t	size;

		/*
		 * When using ldd(1) to analyze a shared object we preload the
		 * shared object with lddstub.  Any additional preload
		 * requirements are added after the object being analyzed, this
		 * allows us to skip the first object but produce diagnostics
		 * for each other preloaded object.
		 */
		if (fname != ename) {
			char		*str;
			const char	*files = prefile;
			const char	*format = MSG_ORIG(MSG_STR_FMT1);

			for (str = fname; *str; str++)
				if (*str == '/') {
					format = MSG_ORIG(MSG_STR_FMT2);
					break;
			}

			preload = MSG_ORIG(MSG_LD_PRELOAD);

			/*
			 * Determine which preload files and preload environment
			 * variable to use.
			 */
			if (class == ELFCLASS64) {
				if (prefile_64 != MSG_ORIG(MSG_STR_EMPTY)) {
					files = prefile_64;
					preload = MSG_ORIG(MSG_LD_PRELOAD_64);
				}
			} else {
				if (prefile_32 != MSG_ORIG(MSG_STR_EMPTY)) {
					files = prefile_32;
					preload = MSG_ORIG(MSG_LD_PRELOAD_32);
				}
			}

			if ((str = (char *)malloc(strlen(preload) +
			    strlen(fname) + strlen(files) + 5)) == 0) {
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC),
				    cname);
				exit(1);
			}

			(void) sprintf(str, format, preload, fname, files);
			if (putenv(str) != 0) {
				(void) fprintf(stderr, MSG_INTL(MSG_ENV_FAILED),
				    cname);
				exit(1);
			}

			/*
			 * The pointer "load" has be assigned to load_elf[] or
			 * load_aout[].  Use the size of load_elf[] as the size
			 * of load_aout[] is the same.
			 */
			load[sizeof (load_elf) - 2] = '2';
		} else
			load[sizeof (load_elf) - 2] = '1';


		/*
		 * Establish new environment variables to affect the child
		 * process.
		 */
		if ((putenv(warn) != 0) || (putenv(bind) != 0) ||
		    (putenv(path) != 0) || (putenv(verb) != 0) ||
		    (putenv(fltr) != 0) || (putenv(conf) != 0) ||
		    (putenv(init) != 0) || (putenv(lazy) != 0) ||
		    (putenv(uref) != 0) || (putenv(used) != 0) ||
		    (putenv(weak) != 0) || (putenv(load) != 0) ||
		    (putenv(nope) != 0) || (putenv(defr) != 0)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ENV_FAILED), cname);
			exit(1);
		}

		/*
		 * Establish explicit environment requires (but don't override
		 * any preload request established to process a shared object).
		 */
		size = 0;
		for (APLIST_TRAVERSE(eopts, idx, str)) {
			if (preload) {
				if (size == 0)
					size = strlen(preload);
				if ((strncmp(preload, str, size) == 0) &&
				    (str[size] == '=')) {
					continue;
				}
			}
			if (putenv(str) != 0) {
				(void) fprintf(stderr, MSG_INTL(MSG_ENV_FAILED),
				    cname);
				exit(1);
			}
		}

		/*
		 * Execute the object and let ld.so.1 do the rest.
		 */
		if (nfile > 1)
			(void) printf(MSG_ORIG(MSG_STR_FMT3), fname);
		(void) fflush(stdout);
		if ((execl(ename, ename, (char *)0)) == -1) {
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_EXEC), cname,
			    fname);
			perror(ename);
			_exit(0);
			/* NOTREACHED */
		}
	}
	return (status);
}

const char *
_ldd_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}
