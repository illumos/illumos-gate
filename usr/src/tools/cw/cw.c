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

/*
 * Wrapper for the GNU C compiler to make it accept the Sun C compiler
 * arguments where possible.
 *
 * Since the translation is inexact, this is something of a work-in-progress.
 */

/*
 * -#		Verbose mode
 * -###		Show compiler commands built by driver, no compilation
 * -A<name[(tokens)]>	Preprocessor predicate assertion
 * -B<[static|dynamic]>	Specify dynamic or static binding
 * -C		Prevent preprocessor from removing comments
 * -c		Compile only - produce .o files, suppress linking
 * -cg92	Alias for -xtarget=ss1000
 * -D<name[=token]>	Associate name with token as if by #define
 * -d[y|n]	dynamic [-dy] or static [-dn] option to linker
 * -E		Compile source through preprocessor only, output to stdout
 * -erroff=<t>	Suppress warnings specified by tags t(%none, %all, <tag list>)
 * -errtags=<a>	Display messages with tags a(no, yes)
 * -errwarn=<t>	Treats warnings specified by tags t(%none, %all, <tag list>)
 *		as errors
 * -fast	Optimize using a selection of options
 * -fd		Report old-style function definitions and declarations
 * -flags	Show this summary of compiler options
 * -fnonstd	Initialize floating-point hardware to non-standard preferences
 * -fns[=<yes|no>] Select non-standard floating point mode
 * -fprecision=<p> Set FP rounding precision mode p(single, double, extended)
 * -fround=<r>	Select the IEEE rounding mode in effect at startup
 * -fsimple[=<n>] Select floating-point optimization preferences <n>
 * -fsingle	Use single-precision arithmetic (-Xt and -Xs modes only)
 * -ftrap=<t>	Select floating-point trapping mode in effect at startup
 * -fstore	force floating pt. values to target precision on assignment
 * -G		Build a dynamic shared library
 * -g		Compile for debugging
 * -H		Print path name of each file included during compilation
 * -h <name>	Assign <name> to generated dynamic shared library
 * -I<dir>	Add <dir> to preprocessor #include file search path
 * -i		Passed to linker to ignore any LD_LIBRARY_PATH setting
 * -keeptmp	Keep temporary files created during compilation
 * -KPIC	Compile position independent code with 32-bit addresses
 * -Kpic	Compile position independent code
 * -L<dir>	Pass to linker to add <dir> to the library search path
 * -l<name>	Link with library lib<name>.a or lib<name>.so
 * -mc		Remove duplicate strings from .comment section of output files
 * -mr		Remove all strings from .comment section of output files
 * -mr,"string"	Remove all strings and append "string" to .comment section
 * -mt		Specify options needed when compiling multi-threaded code
 * -native	Find available processor, generate code accordingly
 * -nofstore	Do not force floating pt. values to target precision
 *		on assignment
 * -nolib	Same as -xnolib
 * -noqueue	Disable queuing of compiler license requests
 * -norunpath	Do not build in a runtime path for shared libraries
 * -O		Use default optimization level (-xO2)
 * -o <outputfile> Set name of output file to <outputfile>
 * -P		Compile source through preprocessor only, output to .i  file
 * -PIC		Alias for -KPIC or -xcode=pic32
 * -p		Compile for profiling with prof
 * -pic		Alias for -Kpic or -xcode=pic13
 * -Q[y|n]	Emit/don't emit identification info to output file
 * -qp		Compile for profiling with prof
 * -R<dir[:dir]> Build runtime search path list into executable
 * -S		Compile and only generate assembly code (.s)
 * -s		Strip symbol table from the executable file
 * -U<name>	Delete initial definition of preprocessor symbol <name>
 * -V		Report version number of each compilation phase
 * -v		Do stricter semantic checking
 * -W<c>,<arg>	Pass <arg> to specified component <c> (a,l,m,p,0,2,h,i,u)
 * -w		Suppress compiler warning messages
 * -Xa		Compile assuming ANSI C conformance, allow K & R extensions
 *		(default mode)
 * -Xc		Compile assuming strict ANSI C conformance
 * -Xs		Compile assuming (pre-ANSI) K & R C style code
 * -Xt		Compile assuming K & R conformance, allow ANSI C
 * -x386	Generate code for the 80386 processor
 * -x486	Generate code for the 80486 processor
 * -xarch=<a>	Specify target architecture instruction set
 * -xbuiltin[=<b>] When profitable inline, or substitute intrinisic functions
 *		for system functions, b={%all,%none}
 * -xCC		Accept C++ style comments
 * -xchar_byte_order=<o> Specify multi-char byte order <o> (default, high, low)
 * -xchip=<c>	Specify the target processor for use by the optimizer
 * -xcode=<c>	Generate different code for forming addresses
 * -xcrossfile[=<n>] Enable optimization and inlining across source files,
 *		n={0|1}
 * -xe		Perform only syntax/semantic checking, no code generation
 * -xF		Compile for later mapfile reordering
 * -xhelp=<f>	Display on-line help information f(flags, readme, errors)
 * -xildoff	Cancel -xildon
 * -xildon	Enable use of the incremental linker, ild
 * -xinline=[<a>,...,<a>]  Attempt inlining of specified user routines,
 *		<a>={%auto,func,no%func}
 * -xlibmieee	Force IEEE 754 return values for math routines in
 *		exceptional cases
 * -xlibmil	Inline selected libm math routines for optimization
 * -xlic_lib=sunperf	Link in the Sun supplied performance libraries
 * -xlicinfo	Show license server information
 * -xM		Generate makefile dependencies
 * -xM1		Generate makefile dependencies, but exclude /usr/include
 * -xmaxopt=[off,1,2,3,4,5] maximum optimization level allowed on #pragma opt
 * -xnolib	Do not link with default system libraries
 * -xnolibmil	Cancel -xlibmil on command line
 * -xO<n>	Generate optimized code (n={1|2|3|4|5})
 * -xP		Print prototypes for function definitions
 * -xpentium	Generate code for the pentium processor
 * -xpg		Compile for profiling with gprof
 * -xprofile=<p> Collect data for a profile or use a profile to optimize
 *		<p>={{collect,use}[:<path>],tcov}
 * -xregs=<r>	Control register allocation
 * -xs		Allow debugging without object (.o) files
 * -xsb		Compile for use with the WorkShop source browser
 * -xsbfast	Generate only WorkShop source browser info, no compilation
 * -xsfpconst	Represent unsuffixed floating point constants as single
 *		precision
 * -xspace	Do not do optimizations that increase code size
 * -xstrconst	Place string literals into read-only data segment
 * -xtarget=<t>	Specify target system for optimization
 * -xtemp=<dir>	Set directory for temporary files to <dir>
 * -xtime	Report the execution time for each compilation phase
 * -xtransition	Emit warnings for differences between K&R C and ANSI C
 * -xtrigraphs[=<yes|no>] Enable|disable trigraph translation
 * -xunroll=n	Enable unrolling loops n times where possible
 * -Y<c>,<dir>	Specify <dir> for location of component <c> (a,l,m,p,0,h,i,u)
 * -YA,<dir>	Change default directory searched for components
 * -YI,<dir>	Change default directory searched for include files
 * -YP,<dir>	Change default directory for finding libraries files
 * -YS,<dir>	Change default directory for startup object files
 */

/*
 * Translation table:
 */
/*
 * -#				-v
 * -###				error
 * -A<name[(tokens)]>		pass-thru
 * -B<[static|dynamic]>		pass-thru (syntax error for anything else)
 * -C				pass-thru
 * -c				pass-thru
 * -cg92			-m32 -mcpu=v8 -mtune=supersparc (SPARC only)
 * -D<name[=token]>		pass-thru
 * -dy or -dn			-Wl,-dy or -Wl,-dn
 * -E				pass-thru
 * -erroff=E_EMPTY_TRANSLATION_UNIT ignore
 * -errtags=%all		-Wall
 * -errwarn=%all		-Werror else -Wno-error
 * -fast			error
 * -fd				error
 * -flags			--help
 * -fnonstd			error
 * -fns[=<yes|no>]		error
 * -fprecision=<p>		error
 * -fround=<r>			error
 * -fsimple[=<n>]		error
 * -fsingle[=<n>]		error
 * -ftrap=<t>			error
 * -fstore			error
 * -G				pass-thru
 * -g				pass-thru
 * -H				pass-thru
 * -h <name>			pass-thru
 * -I<dir>			pass-thru
 * -i				pass-thru
 * -keeptmp			-save-temps
 * -KPIC			-fPIC
 * -Kpic			-fpic
 * -L<dir>			pass-thru
 * -l<name>			pass-thru
 * -mc				error
 * -mr				error
 * -mr,"string"			error
 * -mt				-D_REENTRANT
 * -native			error
 * -nofstore			error
 * -nolib			-nodefaultlibs
 * -noqueue			ignore
 * -norunpath			ignore
 * -O				-O2
 * -o <outputfile>		pass-thru
 * -P				-E -o filename.i (or error)
 * -PIC				-fPIC (C++ only)
 * -p				pass-thru
 * -pic				-fpic (C++ only)
 * -Q[y|n]			error
 * -qp				-p
 * -R<dir[:dir]>		pass-thru
 * -S				pass-thru
 * -s				-Wl,-s
 * -U<name>			pass-thru
 * -V				--version
 * -v				-Wall
 * -Wa,<arg>			pass-thru
 * -Wp,<arg>			pass-thru except -xc99=<a>
 * -Wl,<arg>			pass-thru
 * -W{m,0,2,h,i,u>		error/ignore
 * -Wu,-xmodel=kernel		-ffreestanding -mcmodel=kernel -mno-red-zone
 * -w				pass-thru
 * -Xa				-std=iso9899:199409 or -ansi
 * -Xc				-ansi -pedantic
 * -Xt				error
 * -Xs				-traditional -std=c89
 * -x386			-march=i386 (x86 only)
 * -x486			-march=i486 (x86 only)
 * -xarch=<a>			table
 * -xbuiltin[=<b>]		error
 * -xCC				ignore
 * -xchar_byte_order=<o>	error
 * -xchip=<c>			table
 * -xcode=<c>			table
 * -xcrossfile[=<n>]		error
 * -xe				error
 * -xF				error
 * -xhelp=<f>			error
 * -xildoff			ignore
 * -xildon			ignore
 * -xinline			ignore
 * -xlibmieee			error
 * -xlibmil			error
 * -xlic_lib=sunperf		error
 * -xM				-M
 * -xM1				-MM
 * -xmaxopt=[...]		error
 * -xnolib			-nodefaultlibs
 * -xnolibmil			error
 * -xO<n>			-O<n>
 * -xP				error
 * -xpentium			-march=pentium (x86 only)
 * -xpg				error
 * -xprofile=<p>		error
 * -xregs=<r>			table
 * -xs				error
 * -xsb				error
 * -xsbfast			error
 * -xsfpconst			error
 * -xspace			ignore (-not -Os)
 * -xstrconst			ignore
 * -xtarget=<t>			table
 * -xtemp=<dir>			error
 * -xtime			error
 * -xtransition			-Wtransition
 * -xtrigraphs=<yes|no>		-trigraphs -notrigraphs
 * -xunroll=n			error
 * -Y<c>,<dir>			error
 * -YA,<dir>			error
 * -YI,<dir>			-nostdinc -I<dir>
 * -YP,<dir>			error
 * -YS,<dir>			error
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/isa_defs.h>

static int echo = 1;
static int newargc;
static const char *progname;

static char *default_cc_dir;
static char *default_gcc_dir;

static char *default_cplusplus_dir;
static char *default_gplusplus_dir;

static const char *xarch_tbl[] = {
#if defined(__x86)
	"generic",	NULL,
	"generic64",	"-m64", "-mtune=opteron", NULL,
	"amd64",	"-m64", "-mtune=opteron", NULL,
	"386",		"-march=i386", NULL,
	"pentium_pro",	"-march=pentiumpro", NULL,
#elif defined(__sparc)
	"generic",	"-m32", "-mcpu=v8", NULL,
	"generic64",	"-m64", "-mcpu=v9", NULL,
	"v8",		"-m32", "-mcpu=v8", "-mno-v8plus", NULL,
	"v8plus",	"-m32", "-mcpu=v9", "-mv8plus", NULL,
	"v8plusa",	"-m32", "-mcpu=ultrasparc", "-mv8plus", "-mvis", NULL,
	"v8plusb",	"-m32", "-mcpu=ultrasparc3", "-mv8plus", "-mvis", NULL,
	"v9",		"-m64", "-mcpu=v9", NULL,
	"v9a",		"-m64", "-mcpu=ultrasparc", "-mvis", NULL,
	"v9b",		"-m64", "-mcpu=ultrasparc3", "-mvis", NULL,
#endif
	NULL,		NULL
};

static const char *xchip_tbl[] = {
#if defined(__x86)
	"386",		"-mtune=i386", NULL,
	"486",		"-mtune=i486", NULL,
	"pentium",	"-mtune=pentium", NULL,
	"pentium_pro",  "-mtune=pentiumpro", NULL,
#elif defined(__sparc)
	"super",	"-mtune=supersparc", NULL,
	"ultra",	"-mtune=ultrasparc", NULL,
	"ultra3",	"-mtune=ultrasparc3", NULL,
#endif
	NULL,		NULL
};

static const char *xcode_tbl[] = {
#if defined(__sparc)
	"abs32",	"-fno-pic", "-mcmodel=medlow", NULL,
	"abs44",	"-fno-pic", "-mcmodel=medmid", NULL,
	"abs64",	"-fno-pic", "-mcmodel=medany", NULL,
	"pic13",	"-fpic", NULL,
	"pic32",	"-fPIC", NULL,
#endif
	NULL,		NULL
};

static const char *xtarget_tbl[] = {
#if defined(__x86)
	"pentium_pro",	"-march=pentiumpro", NULL,
#endif	/* __x86 */
	NULL,		NULL
};

static const char *xregs_tbl[] = {
#if defined(__sparc)
	"appl",		"-mapp-regs", NULL,
	"no%appl",	"-mno-app-regs", NULL,
	"float",	"-mfpu", NULL,
	"no%float",	"-mno-fpu", NULL,
#endif	/* __sparc */
	NULL,		NULL
};

struct aelist {
	struct ae {
		struct ae *ae_next;
		char *ae_arg;
	} *ael_head, *ael_tail;
};

static struct aelist *
newael(void)
{
	return (calloc(sizeof (struct aelist), 1));
}

static void
newae(struct aelist *ael, const char *arg)
{
	struct ae *ae;

	ae = calloc(sizeof (*ae), 1);
	ae->ae_arg = strdup(arg);
	if (ael->ael_tail == NULL)
		ael->ael_head = ae;
	else
		ael->ael_tail->ae_next = ae;
	ael->ael_tail = ae;
	newargc++;
}

static void
error(const char *arg)
{
	(void) fprintf(stderr,
	    "%s: mapping failed at or near arg '%s'\n", progname, arg);
	exit(2);
}

/*
 * Add the current favourite set of warnings to the gcc invocation.
 */
static void
warnings(struct aelist *h)
{
	static int warningsonce;

	if (warningsonce++)
		return;

	newae(h, "-Wall");
	newae(h, "-Wno-unknown-pragmas");
	newae(h, "-Wno-missing-braces");
	newae(h, "-Wno-sign-compare");
	newae(h, "-Wno-parentheses");
	newae(h, "-Wno-uninitialized");
	newae(h, "-Wno-implicit-function-declaration");
	newae(h, "-Wno-unused");
	newae(h, "-Wno-trigraphs");
	newae(h, "-Wno-char-subscripts");
	newae(h, "-Wno-switch");
}

static void
optim_disable(struct aelist *h, int level)
{
	if (level >= 2) {
		newae(h, "-fno-strict-aliasing");
		newae(h, "-fno-unit-at-a-time");
		newae(h, "-fno-optimize-sibling-calls");
	}
}

/* ARGSUSED */
static void
Xamode(struct aelist *h)
{
}

static void
Xcmode(struct aelist *h)
{
	static int xconce;

	if (xconce++)
		return;

	newae(h, "-ansi");
	newae(h, "-pedantic-errors");
}

static void
Xsmode(struct aelist *h)
{
	static int xsonce;

	if (xsonce++)
		return;

	newae(h, "-traditional");
	newae(h, "-traditional-cpp");
}

static void
usage()
{
	(void) fprintf(stderr,
	    "usage: %s { -_cc | -_gcc | -_CC | -_g++ } [ -_compiler | ... ]\n",
	    progname);
	exit(2);
}

static void
xlate(struct aelist *h, const char *xarg, const char **table)
{
	while (*table != NULL && strcmp(xarg, *table) != 0) {
		while (*table != NULL)
			table++;
		table++;
	}

	if (*table == NULL)
		error(xarg);

	table++;

	while (*table != NULL) {
		newae(h, *table);
		table++;
	}
}

static void
do_gcc(const char *dir, const char *cmd, int argc, char **argv,
    struct aelist *h, int cplusplus)
{
	int c;
	int pic = 0;
	int nolibc = 0;
	char *model = NULL;
	char *program;
	size_t len = strlen(dir) + strlen(cmd) + 2;

	program = malloc(len);
	(void) snprintf(program, len, "%s/%s", dir, cmd);

	/*
	 * Basic defaults for ON compilation
	 */
	newae(h, program);

	newae(h, "-fident");
	newae(h, "-finline");
	newae(h, "-fno-inline-functions");
	newae(h, "-fno-builtin");
	newae(h, "-fno-asm");
	newae(h, "-nodefaultlibs");

	/*
	 * This is needed because 'u' is defined
	 * under a conditional on 'sun'.  Should
	 * probably just remove the conditional,
	 * or make it be dependent on '__sun'.
	 *
	 * -Dunix is also missing in enhanced ANSI mode
	 */
	newae(h, "-D__sun");

	/*
	 * Walk the argument list, translating as we go ..
	 */

	while (--argc > 0) {
		char *arg = *++argv;
		size_t arglen = strlen(arg);

		if (*arg == '-')
			arglen--;
		else {
			/*
			 * Discard inline files that gcc doesn't grok
			 */
			if (arglen > 3 &&
			    strcmp(arg + arglen - 3, ".il") == 0)
				continue;

			/*
			 * Otherwise, filenames, and partial arguments
			 * are simply passed through for gcc to chew on.
			 */
			newae(h, arg);
			continue;
		}

		if (cplusplus) {
			if (strncmp(arg, "-compat=", 8) == 0) {
				/* discard -compat=4 and -compat=5 */
				continue;
			}
			if (strcmp(arg, "-Qoption") == 0) {
				/* discard -Qoption and its two arguments */
				if (argc < 3)
					error(arg);
				argc -= 2;
				argv += 2;
				continue;
			}
			if (strcmp(arg, "-xwe") == 0) {
				/* turn warnings into errors */
				/* newae(h, "-Werror"); */
				continue;
			}
			if (strcmp(arg, "-noex") == 0) {
				/* no exceptions */
				newae(h, "-fno-exceptions");
				/* no run time type descriptor information */
				newae(h, "-fno-rtti");
				continue;
			}
			if (strcmp(arg, "-pic") == 0) {
				newae(h, "-fpic");
				pic = 1;
				continue;
			}
			if (strcmp(arg, "-PIC") == 0) {
				newae(h, "-fPIC");
				pic = 1;
				continue;
			}
			if (strcmp(arg, "-norunpath") == 0) {
				/* gcc has no corresponding option */
				continue;
			}
			if (strcmp(arg, "-nolib") == 0) {
				/* -nodefaultlibs is on by default */
				nolibc = 1;
				continue;
			}
#if defined(__sparc)
			if (strcmp(arg, "-cg92") == 0) {
				xlate(h, "v8", xarch_tbl);
				xlate(h, "super", xchip_tbl);
				continue;
			}
#endif	/* __sparc */
		}

		switch ((c = arg[1])) {
		case '_':
			if (strcmp(arg, "-_noecho") == 0)
				echo = 0;
			else if (strncmp(arg, "-_cc=", 5) == 0 ||
			    strncmp(arg, "-_CC=", 5) == 0)
				/* EMPTY */;
			else if (strncmp(arg, "-_gcc=", 6) == 0 ||
			    strncmp(arg, "-_g++=", 6) == 0)
				newae(h, arg + 6);
			else if (strcmp(arg, "-_compiler") == 0) {
				(void) printf("%s\n", program);
				exit(0);
			} else
				error(arg);
			break;
		case '#':
			if (arglen == 1) {
				newae(h, "-v");
				break;
			}
			error(arg);
			break;
		case 'g':
			newae(h, "-gdwarf-2");
			break;
		case 'E':
			if (arglen == 1) {
				newae(h, "-xc");
				newae(h, arg);
				nolibc = 1;
				break;
			}
			error(arg);
			break;
		case 'c':
		case 'S':
			if (arglen == 1)
				nolibc = 1;
			/* FALLTHROUGH */
		case 'C':
		case 'H':
		case 'p':
			if (arglen == 1) {
				newae(h, arg);
				break;
			}
			error(arg);
			break;
		case 'A':
		case 'h':
		case 'I':
		case 'i':
		case 'L':
		case 'l':
		case 'o':
		case 'R':
		case 'U':
		case 'u':
		case 'w':
			newae(h, arg);
			break;
		case 'D':
			newae(h, arg);
			/*
			 * XXX	Clearly a hack ... do we need _KADB too?
			 */
			if (strcmp(arg, "-D_KERNEL") == 0 ||
			    strcmp(arg, "-D_BOOT") == 0)
				newae(h, "-ffreestanding");
			break;
		case 'd':
			if (arglen == 2) {
				if (strcmp(arg, "-dy") == 0) {
					newae(h, "-Wl,-dy");
					break;
				}
				if (strcmp(arg, "-dn") == 0) {
					newae(h, "-Wl,-dn");
					break;
				}
			}
			if (strcmp(arg, "-dalign") == 0) {
				/*
				 * -dalign forces alignment in some cases;
				 * gcc does not need any flag to do this.
				 */
				break;
			}
			error(arg);
			break;
		case 'e':
			if (strcmp(arg,
			    "-erroff=E_EMPTY_TRANSLATION_UNIT") == 0) {
				/*
				 * Accept but ignore this -- gcc doesn't
				 * seem to complain about empty translation
				 * units
				 */
				break;
			}
			/* XX64 -- ignore all -erroff= options, for now */
			if (strncmp(arg, "-erroff=", 8) == 0)
				break;
			if (strcmp(arg, "-errtags=yes") == 0) {
				warnings(h);
				break;
			}
			if (strcmp(arg, "-errwarn=%all") == 0) {
				newae(h, "-Werror");
				break;
			}
			error(arg);
			break;
		case 'f':
			if (strcmp(arg, "-flags") == 0) {
				newae(h, "--help");
				break;
			}
			error(arg);
			break;
		case 'G':
			newae(h, "-shared");
			nolibc = 1;
			break;
		case 'k':
			if (strcmp(arg, "-keeptmp") == 0) {
				newae(h, "-save-temps");
				break;
			}
			error(arg);
			break;
		case 'K':
			if (arglen == 1) {
				if ((arg = *++argv) == NULL || *arg == '\0')
					error("-K");
				argc--;
			} else {
				arg += 2;
			}
			if (strcmp(arg, "pic") == 0) {
				newae(h, "-fpic");
				pic = 1;
				break;
			}
			if (strcmp(arg, "PIC") == 0) {
				newae(h, "-fPIC");
				pic = 1;
				break;
			}
			error("-K");
			break;
		case 'm':
			if (strcmp(arg, "-mt") == 0) {
				newae(h, "-D_REENTRANT");
				break;
			}
			error(arg);
			break;
		case 'B':	/* linker options */
		case 'M':
		case 'z':
			{
				char *opt;
				size_t len;
				char *s;

				if (arglen == 1) {
					opt = *++argv;
					if (opt == NULL || *opt == '\0')
						error(arg);
					argc--;
				} else {
					opt = arg + 2;
				}
				len = strlen(opt) + 7;
				s = malloc(len);
				(void) snprintf(s, len, "-Wl,-%c%s", c, opt);
				newae(h, s);
				free(s);
			}
			break;
		case 'n':
			if (strcmp(arg, "-noqueue") == 0) {
				/*
				 * Horrid license server stuff - n/a
				 */
				break;
			}
			error(arg);
			break;
		case 'O':
			if (arglen == 1) {
				newae(h, "-O");
				break;
			}
			error(arg);
			break;
		case 'P':
			/*
			 * We could do '-E -o filename.i', but that's hard,
			 * and we don't need it for the case that's triggering
			 * this addition.  We'll require the user to specify
			 * -o in the Makefile.  If they don't they'll find out
			 * in a hurry.
			 */
			newae(h, "-E");
			nolibc = 1;
			break;
		case 'q':
			if (strcmp(arg, "-qp") == 0) {
				newae(h, "-p");
				break;
			}
			error(arg);
			break;
		case 's':
			if (arglen == 1) {
				newae(h, "-Wl,-s");
				break;
			}
			error(arg);
			break;
		case 'V':
			if (arglen == 1) {
				echo = 0;
				newae(h, "--version");
				break;
			}
			error(arg);
			break;
		case 'v':
			if (arglen == 1) {
				warnings(h);
				break;
			}
			error(arg);
			break;
		case 'W':
			if (strncmp(arg, "-Wp,-xc99", 9) == 0) {
				/*
				 * gcc's preprocessor will accept c99
				 * regardless, so accept and ignore.
				 */
				break;
			}
			if (strncmp(arg, "-Wa,", 4) == 0 ||
			    strncmp(arg, "-Wp,", 4) == 0 ||
			    strncmp(arg, "-Wl,", 4) == 0) {
				newae(h, arg);
				break;
			}
			if (strcmp(arg, "-W0,-xc99=pragma") == 0) {
				/* (undocumented) enables _Pragma */
				break;
			}
			if (strcmp(arg, "-W0,-xc99=%none") == 0) {
				/*
				 * This is a polite way of saying
				 * "no c99 constructs allowed!"
				 * For now, just accept and ignore this.
				 */
				break;
			}
			if (strcmp(arg, "-W0,-noglobal") == 0) {
				/*
				 * gcc doesn't prefix local symbols
				 * in debug mode, so this is not needed.
				 */
				break;
			}
			if (strcmp(arg, "-W0,-Lt") == 0) {
				/*
				 * Generate tests at the top of loops.
				 * There is no direct gcc equivalent, ignore.
				 */
				break;
			}
			if (strcmp(arg, "-W2,-Rcond_elim") == 0) {
				/*
				 * Elimination and expansion of conditionals;
				 * gcc has no direct equivalent.
				 */
				break;
			}
			if (strcmp(arg, "-Wd,-xsafe=unboundsym") == 0) {
				/*
				 * Prevents optimizing away checks for
				 * unbound weak symbol addresses.  gcc does
				 * not do this, so it's not needed.
				 */
				break;
			}
			if (strncmp(arg, "-Wc,-xcode=", 11) == 0) {
				xlate(h, arg + 11, xcode_tbl);
				if (strncmp(arg + 11, "pic", 3) == 0)
					pic = 1;
				break;
			}
			if (strncmp(arg, "-Wc,-Qiselect", 13) == 0) {
				/*
				 * Prevents insertion of register symbols.
				 * gcc doesn't do this, so ignore it.
				 */
				break;
			}
#if defined(__x86)
			if (strcmp(arg, "-Wu,-no_got_reloc") == 0) {
				/*
				 * Don't create any GOT relocations?
				 * Well, gcc doesn't have this degree
				 * of control over its pic code ...
				 */
				break;
			}
			if (strcmp(arg, "-Wu,-xmodel=kernel") == 0) {
				newae(h, "-ffreestanding");
				newae(h, "-mno-red-zone");
				model = "-mcmodel=kernel";
				nolibc = 1;
				break;
			}
#endif	/* __x86 */
			error(arg);
			break;
		case 'X':
			if (strcmp(arg, "-Xa") == 0 ||
			    strcmp(arg, "-Xt") == 0) {
				Xamode(h);
				break;
			}
			if (strcmp(arg, "-Xc") == 0) {
				Xcmode(h);
				break;
			}
			if (strcmp(arg, "-Xs") == 0) {
				Xsmode(h);
				break;
			}
			error(arg);
			break;
		case 'x':
			if (arglen == 1)
				error(arg);
			switch (arg[2]) {
#if defined(__x86)
			case '3':
				if (strcmp(arg, "-x386") == 0) {
					newae(h, "-march=i386");
					break;
				}
				error(arg);
				break;
			case '4':
				if (strcmp(arg, "-x486") == 0) {
					newae(h, "-march=i486");
					break;
				}
				error(arg);
				break;
#endif	/* __x86 */
			case 'a':
				if (strncmp(arg, "-xarch=", 7) == 0) {
					xlate(h, arg + 7, xarch_tbl);
					break;
				}
				error(arg);
				break;
			case 'C':
				/* Accept C++ style comments -- ignore */
				if (strcmp(arg, "-xCC") == 0)
					break;
				error(arg);
				break;
			case 'c':
				if (strncmp(arg, "-xc99=%all", 10) == 0) {
					newae(h, "-std=gnu99");
					break;
				}
				if (strncmp(arg, "-xc99=%none", 11) == 0) {
					newae(h, "-std=gnu89");
					break;
				}
				if (strncmp(arg, "-xchip=", 7) == 0) {
					xlate(h, arg + 7, xchip_tbl);
					break;
				}
				if (strncmp(arg, "-xcode=", 7) == 0) {
					xlate(h, arg + 7, xcode_tbl);
					if (strncmp(arg + 7, "pic", 3) == 0)
						pic = 1;
					break;
				}
				if (strncmp(arg, "-xcache=", 8) == 0)
					break;
				error(arg);
				break;
			case 'd':
				if (strcmp(arg, "-xdepend") == 0)
					break;
				error(arg);
				break;
			case 'F':
				/* compile for mapfile reordering -- ignore */
				if (strcmp(arg, "-xF") == 0)
					break;
				error(arg);
				break;
			case 'i':
				if (strncmp(arg, "-xinline", 8) == 0)
					/* No inlining; ignore */
					break;
				if (strcmp(arg, "-xildon") == 0 ||
				    strcmp(arg, "-xildoff") == 0)
					/* No incremental linking; ignore */
					break;
				error(arg);
				break;
			case 'M':
				if (strcmp(arg, "-xM") == 0) {
					newae(h, "-M");
					break;
				}
				if (strcmp(arg, "-xM1") == 0) {
					newae(h, "-MM");
					break;
				}
				error(arg);
				break;
			case 'n':
				if (strcmp(arg, "-xnolib") == 0) {
					nolibc = 1;
					break;
				}
				error(arg);
				break;
			case 'O':
				if (strncmp(arg, "-xO", 3) == 0) {
					size_t len = strlen(arg);
					char *s = malloc(len);
					int c = *(arg + 3);
					int level;

					if (len != 4 || !isdigit(c))
						error(arg);

					level = atoi(arg + 3);
					if (level > 5)
						error(arg);
					if (level >= 2) {
						/*
						 * For gcc-3.4.x at -O2 we
						 * need to disable optimizations
						 * that break ON.
						 */
						optim_disable(h, level);
						/*
						 * limit -xO3 to -O2 as well.
						 */
						level = 2;
					}
					(void) snprintf(s, len, "-O%d", level);
					newae(h, s);
					free(s);
					break;
				}
				error(arg);
				break;
			case 'p':
				if (strcmp(arg, "-xpentium") == 0) {
					newae(h, "-march=pentium");
					break;
				}
				if (strcmp(arg, "-xpg") == 0) {
					newae(h, "-pg");
					break;
				}
				error(arg);
				break;
			case 'r':
				if (strncmp(arg, "-xregs=", 7) == 0) {
					xlate(h, arg + 7, xregs_tbl);
					break;
				}
				error(arg);
				break;
			case 's':
				if (strcmp(arg, "-xs") == 0 ||
				    strcmp(arg, "-xspace") == 0 ||
				    strcmp(arg, "-xstrconst") == 0)
					break;
				error(arg);
				break;
			case 't':
				if (strcmp(arg, "-xtransition") == 0) {
					newae(h, "-Wtransition");
					break;
				}
				if (strcmp(arg, "-xtrigraphs=yes") == 0) {
					newae(h, "-trigraphs");
					break;
				}
				if (strcmp(arg, "-xtrigraphs=no") == 0) {
					newae(h, "-notrigraphs");
					break;
				}
				if (strncmp(arg, "-xtarget=", 9) == 0) {
					xlate(h, arg + 9, xtarget_tbl);
					break;
				}
				error(arg);
				break;
			case 'b':
			case 'e':
			case 'h':
			case 'l':
			default:
				error(arg);
				break;
			}
			break;
		case 'Y':
			if (arglen == 1) {
				if ((arg = *++argv) == NULL || *arg == '\0')
					error("-Y");
				argc--;
				arglen = strlen(arg + 1);
			} else {
				arg += 2;
			}
			/* Just ignore -YS,... for now */
			if (strncmp(arg, "S,", 2) == 0)
				break;
			if (strncmp(arg, "l,", 2) == 0) {
				char *s = strdup(arg);
				s[0] = '-';
				s[1] = 'B';
				newae(h, s);
				free(s);
				break;
			}
			if (strncmp(arg, "I,", 2) == 0) {
				char *s = strdup(arg);
				s[0] = '-';
				s[1] = 'I';
				newae(h, "-nostdinc");
				newae(h, s);
				free(s);
				break;
			}
			error(arg);
			break;
		case 'Q':
			/*
			 * We could map -Qy into -Wl,-Qy etc.
			 */
		default:
			error(arg);
			break;
		}
	}

	if (model && !pic)
		newae(h, model);
	if (!nolibc)
		newae(h, "-lc");
}

/* ARGSUSED4 */
static void
do_cc(const char *dir, const char *cmd, int argc, char **argv,
    struct aelist *h, int cplusplus)
{
	char *program;
	size_t len = strlen(dir) + strlen(cmd) + 2;

	program = malloc(len);
	(void) snprintf(program, len, "%s/%s", dir, cmd);

	/*
	 * This is pretty simple.
	 * We just have to recognize -V, -_noecho, -_compiler, -_cc= and -_gcc=
	 */
	newae(h, program);

	while (--argc > 0) {
		char *arg = *++argv;

		if (*arg != '-') {
			newae(h, arg);
		} else if (*(arg + 1) != '_') {
			if (strcmp(arg, "-V") == 0)
				echo = 0;
			newae(h, arg);
		} else if (strcmp(arg, "-_noecho") == 0) {
			echo = 0;
		} else if (strcmp(arg, "-_compiler") == 0) {
			(void) printf("%s\n", program);
			exit(0);
		} else if (strncmp(arg, "-_cc=", 5) == 0 ||
		    strncmp(arg, "-_CC=", 5) == 0) {
			newae(h, arg + 5);
		} else if (strncmp(arg, "-_gcc=", 6) != 0 &&
		    strncmp(arg, "-_g++=", 6) != 0) {
			(void) fprintf(stderr,
			    "%s: invalid argument '%s'\n", progname, arg);
			exit(2);
		}
	}
}

int
main(int argc, char **argv)
{
	struct aelist *h = newael();
	const char *dir;
	int ac;
	char **newargv;
	struct ae *a;
	char cc_buf[MAXPATHLEN], gcc_buf[MAXPATHLEN];

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	default_cc_dir = DEFAULT_CC_DIR;
	default_gcc_dir = DEFAULT_GCC_DIR;
	default_cplusplus_dir = DEFAULT_CPLUSPLUS_DIR;
	default_gplusplus_dir = DEFAULT_GPLUSPLUS_DIR;

	/*
	 * Figure out where to get our tools from.  This depends on
	 * the environment variables set at run time.
	 */
	if ((dir = getenv("SPRO_VROOT")) != NULL) {
		(void) snprintf(cc_buf, MAXPATHLEN, "%s/bin", dir);
	} else if ((dir = getenv("SPRO_ROOT")) != NULL) {
		(void) snprintf(cc_buf, MAXPATHLEN, "%s/SOS8/bin", dir);
	} else if ((dir = getenv("BUILD_TOOLS")) != NULL) {
		(void) snprintf(cc_buf, MAXPATHLEN,
		    "%s/SUNWspro/SOS8/bin", dir);
	}
	if (dir != NULL)
		default_cc_dir = (char *)cc_buf;

	if ((dir = getenv("GNU_ROOT")) != NULL) {
		(void) snprintf(gcc_buf, MAXPATHLEN, "%s/bin", dir);
		default_gcc_dir = (char *)gcc_buf;
	}

	default_cplusplus_dir = default_cc_dir;
	default_gplusplus_dir = default_gcc_dir;

	/*
	 * The first argument must be one of "-_cc", "-_gcc", "-_CC", or "-_g++"
	 */
	if (argc == 1)
		usage();
	argc--;
	argv++;
	if (strcmp(argv[0], "-_cc") == 0) {
		if ((dir = getenv("CW_CC_DIR")) == NULL)
			dir = default_cc_dir;
		do_cc(dir, "cc", argc, argv, h, 0);
	} else if (strcmp(argv[0], "-_gcc") == 0) {
		if ((dir = getenv("CW_GCC_DIR")) == NULL)
			dir = default_gcc_dir;
		do_gcc(dir, "gcc", argc, argv, h, 0);
	} else if (strcmp(argv[0], "-_CC") == 0) {
		if ((dir = getenv("CW_CPLUSPLUS_DIR")) == NULL)
			dir = default_cplusplus_dir;
		do_cc(dir, "CC", argc, argv, h, 1);
	} else if (strcmp(argv[0], "-_g++") == 0) {
		if ((dir = getenv("CW_GPLUSPLUS_DIR")) == NULL)
			dir = default_gplusplus_dir;
		do_gcc(dir, "g++", argc, argv, h, 1);
	} else {
		/* assume "-_gcc" by default */
		argc++;
		argv--;
		if ((dir = getenv("CW_GCC_DIR")) == NULL)
			dir = default_gcc_dir;
		do_gcc(dir, "gcc", argc, argv, h, 0);
	}

	newargv = calloc(sizeof (*newargv), newargc + 1);

	if (echo)
		(void) printf("+ ");

	for (ac = 0, a = h->ael_head; a; a = a->ae_next, ac++) {
		newargv[ac] = a->ae_arg;
		if (echo)
			(void) printf("%s ", a->ae_arg);
		if (a == h->ael_tail)
			break;
	}

	if (echo) {
		(void) printf("\n");
		(void) fflush(stdout);
	}

	/*
	 * Here goes ..
	 */
	(void) execvp(newargv[0], newargv);

	/*
	 * execvp() returns only on error.
	 */
	perror("execvp");
	(void) fprintf(stderr, "%s: couldn't run %s\n",
	    progname, newargv[0]);
	return (4);
}
