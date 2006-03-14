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


#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<stdarg.h>
#include	<string.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<libintl.h>
#include	<locale.h>
#include	<fcntl.h>
#include	"conv.h"
#include	"libld.h"
#include	"msg.h"

/*
 * The following prevent us from having to include ctype.h which defines these
 * functions as macros which reference the __ctype[] array.  Go through .plt's
 * to get to these functions in libc rather than have every invocation of ld
 * have to suffer the R_SPARC_COPY overhead of the __ctype[] array.
 */
extern int	isspace(int);

/*
 * Print a message to stdout
 */
/* VARARGS3 */
void
eprintf(Lm_list *lml, Error error, const char *format, ...)
{
	va_list			args;
	static const char	*strings[ERR_NUM] = { MSG_ORIG(MSG_STR_EMPTY) };

#if	defined(lint)
	/*
	 * The lml argument is only meaningful for diagnostics sent to ld.so.1.
	 * Supress the lint error by making a dummy assignment.
	 */
	lml = 0;
#endif
	if (error > ERR_NONE) {
		if (error == ERR_WARNING) {
			if (strings[ERR_WARNING] == 0)
			    strings[ERR_WARNING] = MSG_INTL(MSG_ERR_WARNING);
		} else if (error == ERR_FATAL) {
			if (strings[ERR_FATAL] == 0)
			    strings[ERR_FATAL] = MSG_INTL(MSG_ERR_FATAL);
		} else if (error == ERR_ELF) {
			if (strings[ERR_ELF] == 0)
			    strings[ERR_ELF] = MSG_INTL(MSG_ERR_ELF);
		}
		(void) fputs(MSG_ORIG(MSG_STR_LDDIAG), stderr);
	}
	(void) fputs(strings[error], stderr);

	va_start(args, format);
	(void) vfprintf(stderr, format, args);
	if (error == ERR_ELF) {
		int	elferr;

		if ((elferr = elf_errno()) != 0)
			(void) fprintf(stderr, MSG_ORIG(MSG_STR_ELFDIAG),
			    elf_errmsg(elferr));
	}
	(void) fprintf(stderr, MSG_ORIG(MSG_STR_NL));
	(void) fflush(stderr);
	va_end(args);
}


/*
 * Determine whether we need the Elf32 or Elf64 libld.
 */
static int
determine_class(int argc, char ** argv)
{
	unsigned char	class = 0;
	int		c;

getmore:
	/*
	 * Skip options.
	 *
	 * The only option we're interested in is -64, which enforces a 64-bit
	 * link-edit.  This option is used when the only input to ld() is a
	 * mapfile and a 64-bit object is required.  If we've already processed
	 * a 32-bit object and we find -64, we have an error condition, but let
	 * this fall through to libld to obtain the default error message.
	 */
	opterr = 0;
	while ((c = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != -1) {
		switch (c) {
			case '6':
				return (ELFCLASS64);
			default:
				break;
		}
	}

	/*
	 * Otherwise look for the first ELF object to determine the class of
	 * objects to operate on.
	 */
	for (; optind < argc; optind++) {
		int		fd;
		unsigned char	ident[EI_NIDENT];

		/*
		 * If we've already analyzed the initial object, continue.
		 * We're only interested in skipping all files to check for
		 * more options, and specifically if the -64 option is set.
		 */
		if (class)
			continue;

		/*
		 * If we detect some more options return to getopt().
		 * Checking argv[optind][1] against null prevents a forever
		 * loop if an unadorned `-' argument is passed to us.
		 */
		if (argv[optind][0] == '-') {
			if (argv[optind][1] == '\0')
				continue;
			else
				goto getmore;
		}

		if ((fd = open(argv[optind], O_RDONLY)) == -1) {
			int err = errno;

			eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN),
			    argv[optind], strerror(err));
			return (0);
		}

		/*
		 * Determine the files ELF class.
		 */
		if ((read(fd, ident, EI_NIDENT) == EI_NIDENT) &&
		    (ident[EI_MAG0] == ELFMAG0) &&
		    (ident[EI_MAG1] == ELFMAG1) &&
		    (ident[EI_MAG2] == ELFMAG2) &&
		    (ident[EI_MAG3] == ELFMAG3)) {
			if (((class = ident[EI_CLASS]) != ELFCLASS32) &&
			    (class != ELFCLASS64))
				class = 0;
		}
		(void) close(fd);
	}

	/*
	 * If we couldn't establish a class default to 32-bit.
	 */
	if (class)
		return (class);

	return (ELFCLASS32);
}

/*
 * Prepend environment string as a series of options to the argv array.
 */
static int
prepend_ldoptions(char *ld_options, int *argcp, char ***argvp)
{
	int	nargc;			/* new argc */
	char	**nargv;		/* new argv */
	char	*arg, *string;
	int	count;

	/*
	 * Get rid of leading white space, and make sure the string has size.
	 */
	while (isspace(*ld_options))
		ld_options++;
	if (*ld_options == '\0')
		return (1);

	nargc = 0;
	arg = string = ld_options;

	/*
	 * Walk the environment string counting any arguments that are
	 * separated by white space.
	 */
	while (*string != '\0') {
		if (isspace(*string)) {
			nargc++;
			while (isspace(*string))
				string++;
			arg = string;
		} else
			string++;
	}
	if (arg != string)
		nargc++;

	/*
	 * Allocate a new argv array big enough to hold the new options from
	 * the environment string and the old argv options.
	 */
	if ((nargv = calloc(nargc + *argcp, sizeof (char *))) == 0) {
		int	err = errno;
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_ALLOC), strerror(err));
		return (0);
	}

	/*
	 * Initialize first element of new argv array to be the first element
	 * of the old argv array (ie. calling programs name).  Then add the new
	 * args obtained from the environment.
	 */
	nargv[0] = (*argvp)[0];
	nargc = 0;
	arg = string = ld_options;
	while (*string != '\0') {
		if (isspace(*string)) {
			nargc++;
			*string++ = '\0';
			nargv[nargc] = arg;
			while (isspace(*string))
				string++;
			arg = string;
		} else
			string++;
	}
	if (arg != string) {
		nargc++;
		nargv[nargc] = arg;
	}

	/*
	 * Now add the original argv array (skipping argv[0]) to the end of the
	 * new argv array, and overwrite the old argc and argv.
	 */
	for (count = 1; count < *argcp; count++) {
		nargc++;
		nargv[nargc] = (*argvp)[count];
	}
	*argcp = ++nargc;
	*argvp = nargv;

	return (1);
}

/*
 * Check to see if there is a LD_ALTEXEC=<path to alternate ld> in the
 * environment.  If so, first null the environment variable out, and then
 * exec() the binary pointed to by the environment variable, passing the same
 * arguments as the originating process.  This mechanism permits using
 * alternate link-editors (debugging/developer copies) even in complex build
 * environments.
 *
 * If LD_ALTEXEC= isn't set, or the exec() fails, silently return and allow the
 * current link-editor to execute.
 */
void
ld_altexec(char **argv, char **envp)
{
	char	*execstr;
	char	**str;
	for (str = envp; *str; str++) {
		if (strncmp(*str, MSG_ORIG(MSG_LD_ALTEXEC),
		    MSG_LD_ALTEXEC_SIZE) == 0) {
			break;
		}
	}
	if (*str == 0)
		return;

	/*
	 * get a pointer to the actual string - if it's
	 * a null entry - we return.
	 */
	execstr = strdup(*str + MSG_LD_ALTEXEC_SIZE);
	if (*execstr == '\0')
		return;
	/*
	 * Null out the LD_ALTEXEC= environment entry.
	 */
	(*str)[MSG_LD_ALTEXEC_SIZE] = '\0';

	/*
	 * Set argv[0] to point to our new linker
	 */
	argv[0] = execstr;

	/*
	 * And attempt to execute it.
	 */
	(void) execve(execstr, argv, envp);

	/*
	 * If the exec() fails, silently fall through and continue execution of
	 * the current link-editor.
	 */
}

int
main(int argc, char **argv, char **envp)
{
	char		*ld_options, **oargv = argv;
	uchar_t 	class;

	/*
	 * XX64 -- Strip "-Wl," from the head of each argument.  This is to
	 * accommodate awkwardness in passing ld arguments to gcc while
	 * maintaining the structure of the OSNet build environment's Makefiles.
	 */
	{
		int i;
		char *p;

		for (i = 0; i < argc; i++) {
			p = argv[i];
			while (*(p + 1) == 'W' && strncmp(p, "-Wl,-", 5) == 0)
				argv[i] = (p += 4);
		}
	}

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	/*
	 * Execute alternate linker if LD_ALTEXEC environment variable is set.
	 */
	ld_altexec(argv, envp);

	/*
	 * Check the LD_OPTIONS environment variable, and if present prepend
	 * the arguments specified to the command line argument list.
	 */
	if ((ld_options = getenv(MSG_ORIG(MSG_LD_OPTIONS))) != NULL) {
		/*
		 * Prevent modification of actual environment strings.
		 */
		if (((ld_options = strdup(ld_options)) == NULL) ||
		    (prepend_ldoptions(ld_options, &argc, &argv) == 0))
			return (1);
	}

	/*
	 * Locate the first input file and from this file determine the class of
	 * objects we're going to process.  If the class is ELFCLASS64 we'll
	 * call the ELF64 class of interfaces, else the ELF32 class.  Note that
	 * if the option -64 is encountered a 64-bit link is explicitly being
	 * requested.
	 */
	if ((class = determine_class(argc, argv)) == 0)
		return (1);

	/*
	 * If we're on a 64-bit kernel, try to exec a full 64-bit version of ld.
	 */
	if (class == ELFCLASS64)
		conv_check_native(oargv, envp);

	/*
	 * Reset the getopt(3c) error message flag, and call the generic entry
	 * point using the appropriate class.
	 */
	optind = opterr = 1;
	if (class == ELFCLASS64)
		return (ld64_main(argc, argv));
	else
		return (ld32_main(argc, argv));
}

/*
 * Exported interfaces required by our dependencies.  libld and friends bind to
 * the different implementations of these provided by either ld or ld.so.1.
 */
const char *
_ld_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}
